<?php
/**
 * Reverse proxy for IPMI/BMC web UIs.
 * Routes: /ipmi_proxy.php/{token}/{bmc_path...}
 * - HTTP requests are proxied via cURL with session cookies.
 * - WebSocket upgrade requests are diverted to ipmi_ws_relay.php.
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/ipmi_web_session.php';
require_once __DIR__ . '/lib/ipmi_proxy_debug.php';
require_once __DIR__ . '/lib/ipmi_bmc_curl.php';

require_once __DIR__ . '/lib/ipmi_proxy/bootstrap.php';

if (PHP_SAPI === 'cli' && ($p = getenv('IPMI_DUMP_ILO_DOM_JS_PATH')) !== false && $p !== '') {
    $domonly = '(function(){' . ipmiProxyBuildKvmAutoLaunchIloDomHelpersJs() . '})();';
    file_put_contents($p, $domonly . "\n");
    exit(0);
}

if (PHP_SAPI === 'cli' && getenv('IPMI_VALIDATE_KVM_JS_DOM') === '1') {
    $domonly = '(function(){' . ipmiProxyBuildKvmAutoLaunchIloDomHelpersJs() . '})();';
    $bd = ipmiProxyValidateGeneratedJsBraceBalance($domonly);
    fwrite(STDERR, "ilo_dom_wrapped\t" . json_encode($bd, JSON_UNESCAPED_UNICODE) . "\n");
    $tmp = rtrim(sys_get_temp_dir(), '/') . '/ipmi_kvm_dom_validate_' . bin2hex(random_bytes(4)) . '.js';
    if (@file_put_contents($tmp, $domonly) !== false) {
        passthru('node --check ' . escapeshellarg($tmp) . ' 2>&1', $nodeDom);
        @unlink($tmp);
        fwrite(STDERR, "ilo_dom_node_check\t" . ($nodeDom === 0 ? "ok" : "fail") . "\n");
    }
    exit(($bd['ok'] && (int) $bd['depth'] === 0) ? 0 : 1);
}

if (PHP_SAPI === 'cli' && getenv('IPMI_VALIDATE_KVM_JS') === '1') {
    $je = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES;
    $familyJs = json_encode('ilo', $je);
    $planJs = json_encode([
        'vendor_family'                => 'ilo',
        'speculative_shell_autolaunch'   => false,
        'console_ready_timeout_ms'       => 45000,
        'should_attempt_proxy_autolaunch'=> true,
        'kvm_entry_path'                => '/html/application.html',
        'launch_strategy'               => 'ilo_application_force_html5',
    ], $je);
    $pxJs = json_encode('/ipmi_proxy.php/' . str_repeat('a', 64), $je);
    $dbgLit = 'true';
    $segments = [
        'preamble' => ipmiProxyBuildKvmAutoLaunchPreambleJs($familyJs, $planJs, $pxJs, 'false', $dbgLit),
        'ilo_dom'    => ipmiProxyBuildKvmAutoLaunchIloDomHelpersJs(),
        'progress'   => ipmiProxyBuildKvmRuntimeProgressHelpersJs(),
        'launch_gate'=> ipmiProxyBuildKvmAutoLaunchLaunchGateJs(),
        'ilo_tick'   => ipmiProxyBuildIloKvmScript(),
        'idrac'      => ipmiProxyBuildIdracKvmScript(),
        'supermicro' => ipmiProxyBuildSupermicroKvmScript(),
        'closer'     => '})();',
    ];
    $acc = '';
    foreach ($segments as $name => $chunk) {
        $acc .= $chunk;
        $b = ipmiProxyValidateGeneratedJsBraceBalance($acc);
        if (!$b['ok'] || (int) $b['depth'] !== 0) {
            fwrite(STDERR, "brace_after_segment\t" . $name . "\t" . json_encode($b, JSON_UNESCAPED_UNICODE) . "\n");
        }
    }
    $body = $acc;
    $v = ipmiProxyValidateGeneratedIloJs($body);
    fwrite(STDERR, json_encode($v, JSON_UNESCAPED_UNICODE) . "\n");
    if (!$v['ok']) {
        exit(1);
    }
    $tmp = rtrim(sys_get_temp_dir(), '/') . '/ipmi_kvm_runtime_validate_' . bin2hex(random_bytes(4)) . '.js';
    if (@file_put_contents($tmp, $body) === false) {
        exit(0);
    }
    passthru('node --check ' . escapeshellarg($tmp) . ' 2>/dev/null', $nodeCode);
    @unlink($tmp);
    exit($nodeCode === 0 ? 0 : 1);
}

set_time_limit(300);
ignore_user_abort(true);

ipmiProxyDebugMaybeSetCookie();

  header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
  header('Pragma: no-cache');
header('Referrer-Policy: same-origin');

// /ipmi_proxy.php/{token} without trailing slash makes relative URLs resolve to /ipmi_proxy.php/{file} (broken).
$reqPath = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
if (preg_match('#^/ipmi_proxy\.php/([a-f0-9]{64})$#i', $reqPath)) {
    $qs = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_QUERY);
    header('Location: ' . $reqPath . '/' . ($qs !== '' ? ('?' . $qs) : ''), true, 302);
    exit;
}

$pathInfo = $_SERVER['PATH_INFO'] ?? '';
$pathInfo = is_string($pathInfo) ? $pathInfo : '';
// Some vendor JS requests assets without the token prefix (e.g. images/login.png).
// If the Referer contains the session token, redirect to the tokenized path so assets resolve.
// Important: only do this when the current request path itself is NOT already tokenized,
// otherwise we can generate token/token URLs and trigger redirect loops.
$reqPathHasToken = (bool) preg_match('#^/ipmi_proxy\.php/[a-f0-9]{64}(?:/|$)#i', $reqPath);
if (!$reqPathHasToken && !preg_match('#^/([a-f0-9]{64})(/|$)#i', $pathInfo)) {
    $ref = (string) ($_SERVER['HTTP_REFERER'] ?? '');
    if ($ref !== '' && preg_match('#/ipmi_proxy\.php/([a-f0-9]{64})/#i', $ref, $mRef)) {
        $refToken = $mRef[1];
        if (preg_match('#^/ipmi_proxy\.php(/.+)$#i', $reqPath, $mPath)) {
            $suffix = $mPath[1];
            if (!preg_match('#^/[a-f0-9]{64}(?:/|$)#i', $suffix)) {
                $qs = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_QUERY);
                header('Location: /ipmi_proxy.php/' . $refToken . $suffix . ($qs !== '' ? ('?' . $qs) : ''), true, 302);
                exit;
            }
        }
    }
}

$pathAfterPrefixFromUri = '';
if (isset($_SERVER['REQUEST_URI'])) {
    $uriPathOnly = (string) parse_url((string) $_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $prefix = '/ipmi_proxy.php';
    $pos = strpos($uriPathOnly, $prefix);
    if ($pos !== false) {
        $pathAfterPrefixFromUri = (string) substr($uriPathOnly, $pos + strlen($prefix));
    }
}
if ($pathInfo === '' && $pathAfterPrefixFromUri !== '') {
    $pathInfo = $pathAfterPrefixFromUri;
}

$pathInfo = '/' . ltrim((string)$pathInfo, '/');
$parts = explode('/', ltrim($pathInfo, '/'), 2);
$token = strtolower(trim((string)($parts[0] ?? '')));
$bmcPath = '/' . ltrim((string)($parts[1] ?? ''), '/');

// Some vendor UIs resolve assets to /ipmi_proxy.php/images/... (missing token).
// Recover the token from same-origin Referer when possible.
$tokenRecoveredFromReferer = false;
$tokenRecoveredFromCookie = false;
if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    $ref = (string)($_SERVER['HTTP_REFERER'] ?? '');
    if ($ref !== '') {
        $refParts = parse_url($ref);
        $refHost = strtolower((string)($refParts['host'] ?? ''));
        $selfHost = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
        if ($refHost !== '' && $selfHost !== '' && $refHost === $selfHost) {
            $refPath = (string)($refParts['path'] ?? '');
            if (preg_match('#/ipmi_proxy\.php/([a-f0-9]{64})#i', $refPath, $m)) {
                $token = strtolower($m[1]);
                $tokenRecoveredFromReferer = true;
            }
        }
    }
}
if (!$tokenRecoveredFromReferer && !preg_match('/^[a-f0-9]{64}$/', $token)) {
    $cookieToken = (string)($_COOKIE['IPMI_PROXY_TOKEN'] ?? '');
    if (preg_match('/^[a-f0-9]{64}$/', $cookieToken)) {
        $token = strtolower($cookieToken);
        $tokenRecoveredFromCookie = true;
    }
}
if ($tokenRecoveredFromReferer || $tokenRecoveredFromCookie) {
    // When request URL is like /ipmi_proxy.php/js/... (missing token), don't drop the first segment ("js").
    // Keep the full path after /ipmi_proxy.php as BMC path.
    $rawCandidate = $pathAfterPrefixFromUri !== '' ? $pathAfterPrefixFromUri : $pathInfo;
    $rawCandidate = '/' . ltrim((string) $rawCandidate, '/');
    if ($rawCandidate !== '/' && !preg_match('#^/[a-f0-9]{64}(?:/|$)#i', $rawCandidate)) {
        $bmcPath = $rawCandidate;
    } elseif ($bmcPath === '/' && $pathInfo !== '/' && $pathInfo !== '') {
        $bmcPath = '/' . ltrim((string) $pathInfo, '/');
    }
}

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    http_response_code(400);
    echo 'Invalid session token';
    exit;
}

$session = ipmiWebLoadSession($mysqli, $token);
if (!$session) {
    http_response_code(403);
    echo 'Session expired or invalid';
    exit;
}

// Retry auto-login here if the session was created but has no usable auth yet.
$autoLoginBootstrapError = '';
if (ipmiWebNeedsAutoLogin($session)) {
    $origType = (string) ($session['bmc_type'] ?? 'generic');
    if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
        ipmiWebSaveSessionCookies(
            $mysqli,
            $token,
            $session['cookies'],
            $session['forward_headers'] ?? [],
            (string)($session['bmc_scheme'] ?? 'https')
        );
        $newType = (string) ($session['bmc_type'] ?? $origType);
        if ($newType !== '' && $newType !== $origType) {
            $upd = $mysqli->prepare('UPDATE ipmi_web_sessions SET bmc_type = ? WHERE token = ? LIMIT 1');
            if ($upd) {
                $upd->bind_param('ss', $newType, $token);
                $upd->execute();
                $upd->close();
            }
        }
        ipmiWebPersistDetectedServerType(
            $mysqli,
            (int) ($session['server_id'] ?? 0),
            $origType,
            $newType
        );
    } else {
        $autoLoginBootstrapError = (string) ($session['auto_login_error'] ?? '');
    }
}

// Remember last active proxy token for asset requests that miss the token segment.
$secureTokenCookie = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);
setcookie('IPMI_PROXY_TOKEN', $token, [
    'expires'  => time() + 7200,
    'path'     => '/ipmi_proxy.php',
    'secure'   => $secureTokenCookie,
    'httponly' => true,
    'samesite' => 'Lax',
]);

$kvmCookiePath = '/ipmi_proxy.php/' . rawurlencode($token);
if ((string) ($_GET['ipmi_kvm_auto'] ?? '') === '1') {
    setcookie('IPMI_KVM_AUTO', '1', [
        'expires'  => time() + 600,
        'path'     => $kvmCookiePath,
        'secure'   => $secureTokenCookie,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}
if ((string) ($_GET['ipmi_kvm_legacy'] ?? '') === '1') {
    setcookie('IPMI_KVM_LEGACY', '1', [
        'expires'  => time() + 1200,
        'path'     => $kvmCookiePath,
        'secure'   => $secureTokenCookie,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

$panelUserId = null;
// Avoid overwriting the main panel session cookie when the browser opens the proxy
// without a valid PHPSESSID (e.g. different scheme or new tab).
if (isset($_COOKIE[session_name()])) {
    session_start(['read_and_close' => true]);
    $panelUserId = $_SESSION['user_id'] ?? null;
}
if (!$panelUserId) {
    $createdIp = (string)($session['created_ip'] ?? '');
    $createdUa = (string)($session['user_agent'] ?? '');
    $remoteIp = (string)($_SERVER['REMOTE_ADDR'] ?? '');
    $currentUa = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
    $allowTokenOnly = false;

    if ($createdIp !== '' && $remoteIp !== '' && $createdIp === $remoteIp) {
        if ($createdUa === '' || $currentUa === '') {
            $allowTokenOnly = true;
        } else {
            $allowTokenOnly = (strncmp($currentUa, $createdUa, strlen($createdUa)) === 0)
                || (strncmp($createdUa, $currentUa, strlen($currentUa)) === 0);
        }
    }

    if (!$allowTokenOnly) {
        http_response_code(401);
        echo 'Authentication required';
        exit;
    }
}

// Release session lock immediately: the browser loads HTML + /js/iLO.js + CSS in parallel; holding
// the lock here blocks those requests until the BMC response finishes → failed script load, iLO undefined.
if (session_status() === PHP_SESSION_ACTIVE) {
    session_write_close();
}

$ipmiTraceId = '';
if (ipmiProxyDebugEnabled()) {
    $ipmiTraceId = ipmiProxyDebugSendTraceHeaders();
}

if (isset($_GET['ipmi_kvm_replan']) && (string) $_GET['ipmi_kvm_replan'] === '1') {
    $GLOBALS['__ipmi_kvm_force_replan_for_token'] = $token;
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('kvm_plan_replan_query', ['trace' => $ipmiTraceId]);
    }
}

$bmcIp = $session['ipmi_ip'];
$tokenPrefix = '/ipmi_proxy.php/' . rawurlencode($token);

// Supermicro has both legacy (topmenu) and SPA UIs. Some models loop if we force topmenu.
// Only force topmenu when explicitly requested.
$typeNorm = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
$pathLowerForBootstrap = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
if ($autoLoginBootstrapError !== '' && $typeNorm === 'idrac') {
    if ($autoLoginBootstrapError === 'session_limit') {
        ipmiProxyEmitSessionExpiredPage(
            'iDRAC rejected auto-login because the maximum number of user sessions has been reached. '
            . 'Please wait for old iDRAC sessions to expire (or clear sessions on iDRAC), then open a new session.'
        );
        exit;
    }
    if (in_array($pathLowerForBootstrap, ['/', '/start.html', '/index.html', '/login.html', '/restgui/start.html', '/restgui/launch'], true)) {
        ipmiProxyEmitSessionExpiredPage(
            'Could not establish an iDRAC session automatically. Please open a new session from the panel.'
        );
        exit;
    }
}
if ($autoLoginBootstrapError !== '' && $typeNorm === 'ami') {
    if ($autoLoginBootstrapError === 'session_limit') {
        ipmiProxyEmitSessionExpiredPage(
            'AMI BMC rejected auto-login because the maximum number of user sessions has been reached. '
            . 'Please wait for old BMC sessions to expire (or clear sessions on the BMC), then open a new session.'
        );
        exit;
    }
    if (in_array($pathLowerForBootstrap, ['/', '/index.html', '/login', '/login.html'], true)) {
        ipmiProxyEmitSessionExpiredPage(
            'Could not establish an AMI BMC session automatically. Please open a new session from the panel.'
        );
        exit;
    }
}
if ($autoLoginBootstrapError !== '' && !in_array($typeNorm, ['idrac', 'ami'], true)) {
    if ($autoLoginBootstrapError === 'session_limit' && in_array($pathLowerForBootstrap, ['/', '/index.html', '/login', '/login.html'], true)) {
        ipmiProxyEmitSessionExpiredPage(
            'BMC rejected auto-login because the maximum number of sessions has been reached. '
            . 'Please wait for old sessions to expire, then open a new session.'
        );
        exit;
    }
}
$earlyQuery = ipmiProxyDebugStripFromQuery((string) ($_SERVER['QUERY_STRING'] ?? ''));
$earlyBmcScheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
// Some Supermicro builds fire /cgi/logout.cgi from stale client-side state right after open.
// If we proxy that literally, the BMC can bounce between logout/login/topmenu and create browser redirect storms.
// Keep the panel session stable by neutralizing implicit logout unless an explicit force flag is present.
$earlyPath = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
$methodEarly = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
if (
    $typeNorm === 'supermicro'
    && in_array($methodEarly, ['GET', 'POST'], true)
    && $earlyPath === '/cgi/logout.cgi'
    && !isset($_GET['force_logout'])
) {
    $baseUrlForSm = $earlyBmcScheme . '://' . $bmcIp;
    $smValid = ipmiWebSupermicroVerifyAuthed(
        $baseUrlForSm,
        $bmcIp,
        is_array($session['cookies'] ?? null) ? $session['cookies'] : []
    );
    if (!$smValid) {
        $session['cookies'] = [];
        $session['forward_headers'] = [];
        if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
            ipmiWebSaveSessionCookies(
                $mysqli,
                $token,
                $session['cookies'],
                is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
                (string)($session['bmc_scheme'] ?? 'https')
            );
            if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
                ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
            }
        } else {
            ipmiProxyEmitSessionExpiredPage('Your BMC web session became invalid. Open a new session from the panel.');
        }
    }
    // Do not redirect here (redirect can recurse if BMC repeatedly calls logout).
    // Return a lightweight successful response so the browser flow stays on the current page.
    http_response_code(204);
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Content-Type: text/plain; charset=UTF-8');
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('supermicro_logout_neutralized', [
            'trace' => $ipmiTraceId,
            'bmcPath' => $bmcPath,
        ]);
        ipmiProxyDebugEmitLogHeader([
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'phase'   => 'logout_neutralized',
        ]);
    }
    exit;
}
if ($typeNorm === 'supermicro' && isset($_GET['sm_topmenu'])) {
    $rootPath = trim($bmcPath) === '' ? '/' : $bmcPath;
    if ($methodEarly === 'GET' && $rootPath === '/') {
        $redir = $tokenPrefix . ipmiWebPostLoginLandingPath((string) ($session['bmc_type'] ?? 'generic'));
        if ($earlyQuery !== '') {
            $redir .= '&' . $earlyQuery;
        }
        header('Location: ' . $redir, true, 302);
        exit;
    }
}

$bmcScheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';

$isWsUpgrade = (
    isset($_SERVER['HTTP_UPGRADE'])
    && stripos((string)$_SERVER['HTTP_UPGRADE'], 'websocket') !== false
    && isset($_SERVER['HTTP_CONNECTION'])
    && stripos((string)$_SERVER['HTTP_CONNECTION'], 'upgrade') !== false
);

if ($isWsUpgrade) {
    $wsProto = ($bmcScheme === 'http') ? 'ws' : 'wss';
    $wsTarget = $wsProto . '://' . $bmcIp . $bmcPath;
    if (!empty($_SERVER['QUERY_STRING'])) {
        $wsTarget .= '?' . $_SERVER['QUERY_STRING'];
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ws_redirect', [
            'trace'  => $ipmiTraceId,
            'path'   => $bmcPath,
            'target' => $wsProto . '://' . $bmcIp . '/*',
        ]);
    }
    $relayUrl = '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=' . rawurlencode($wsTarget);
    header('Location: ' . $relayUrl, true, 307);
    exit;
}

$queryString = ipmiProxyDebugStripFromQuery((string) ($_SERVER['QUERY_STRING'] ?? ''));
$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
$currentBmcTarget = $bmcPath . ($queryString !== '' ? ('?' . $queryString) : '');

// BMC often has no /favicon.ico or is slow; proxying it yields 502 in DevTools.
if ($method === 'GET' && basename($bmcPath) === 'favicon.ico') {
    header('Location: /favicon.php' . ($queryString !== '' ? ('?' . $queryString) : ''), true, 302);
    exit;
}

$bmcUrl = $bmcScheme . '://' . $bmcIp . $bmcPath;
if ($queryString !== '') {
    $bmcUrl .= '?' . $queryString;
}

$postBody = ($method === 'POST') ? file_get_contents('php://input') : null;
$fwdContentType = $_SERVER['CONTENT_TYPE'] ?? $_SERVER['HTTP_CONTENT_TYPE'] ?? '';

if (ipmiProxyDebugEnabled()) {
    ipmiProxyDebugLog('request', [
        'trace'     => $ipmiTraceId,
        'token'     => ipmiProxyDebugRedactToken($token),
        'method'    => $method,
        'bmcPath'   => $bmcPath,
        'bmcHost'   => $bmcIp,
        'bmcType'   => (string) ($session['bmc_type'] ?? ''),
        'bmcScheme' => $bmcScheme,
        'hasQuery'  => $queryString !== '',
        'kvmAuto'   => ((string) ($_GET['ipmi_kvm_auto'] ?? '') === '1') ? 1 : 0,
        'kvmLegacy' => ((string) ($_GET['ipmi_kvm_legacy'] ?? '') === '1') ? 1 : 0,
        'referer'   => substr((string) ($_SERVER['HTTP_REFERER'] ?? ''), 0, 180),
        'cookies'   => ipmiProxyDebugCookieMeta(is_array($session['cookies'] ?? null) ? $session['cookies'] : []),
    ]);
}


if (is_array($session['cookies'])) {
    $session['cookies'] = ipmiProxyMergeClientBmcCookies($session['cookies'], (string) ($session['bmc_type'] ?? ''));
    if (ipmiWebIsIloFamilyType((string)($session['bmc_type'] ?? ''))) {
        ipmiWebSyncIloSessionAndSessionKeyCookies($session['cookies']);
    }
}

$bmcTypeNorm = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
$bmcPathOnlyLower = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
$GLOBALS['__ipmi_ilo_runtime_recover_attempted'] = false;

if ($method === 'GET' && ipmiWebIsNormalizedIloType($bmcTypeNorm) && ipmiProxyIsIloSpaShellEntryPath($bmcPath)) {
    ipmiProxyMaybeIloRuntimePreflight($mysqli, $token, $session, $bmcIp, $bmcPath, $ipmiTraceId);
}

$fwdHdr = $session['forward_headers'] ?? [];
$fwdHdr = ipmiProxyMergeClientBmcForwardHeaders(
    is_array($fwdHdr) ? $fwdHdr : [],
    $bmcScheme,
    $bmcIp,
    is_array($session['cookies'] ?? null) ? $session['cookies'] : []
);
// iLO JSON endpoints are sensitive to missing AJAX-style headers.
// Keep these defaults at the proxy edge so browser/runtime differences do not break auth.
if (ipmiWebIsNormalizedIloType($bmcTypeNorm) && ($method === 'GET' || $method === 'POST')) {
    $isIloJsonLike = str_starts_with($bmcPathOnlyLower, '/json/')
        || str_starts_with($bmcPathOnlyLower, '/api/')
        || str_starts_with($bmcPathOnlyLower, '/rest/');
    if ($isIloJsonLike) {
        if (!ipmiProxyForwardHeadersHasHeader((array) $fwdHdr, 'X-Requested-With')) {
            $fwdHdr['X-Requested-With'] = 'XMLHttpRequest';
        }
        if (!ipmiProxyForwardHeadersHasHeader((array) $fwdHdr, 'Accept')) {
            $fwdHdr['Accept'] = 'application/json, text/javascript, */*';
        }
    }
}
if ($method === 'GET' && ipmiProxyShouldStreamBmcRequest($method, $bmcPath)) {
    if (ipmiWebNeedsAutoLogin($session)) {
        http_response_code(403);
        echo 'BMC session not available. Open this server from the panel again so the panel can sign in to the BMC.';
        exit;
    }
    // Long polls / SSE must not inherit the generic 300s cap; Apache may still enforce its own limit.
    set_time_limit(0);
    ignore_user_abort(true);
    ipmiProxyRecoverBmcAuthBeforeSse($session, $mysqli, $token, $bmcIp, $bmcScheme, $fwdHdr, $ipmiTraceId);
    $bmcUrl = $bmcScheme . '://' . $bmcIp . $bmcPath;
    if ($queryString !== '') {
        $bmcUrl .= '?' . $queryString;
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('stream_sse', [
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'accept'  => substr((string) ($_SERVER['HTTP_ACCEPT'] ?? ''), 0, 120),
        ]);
        ipmiProxyDebugEmitLogHeader([
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'phase'   => 'pre_stream',
        ]);
    }
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }

    $streamUrl = $bmcUrl;
    $r = ipmiProxyStreamGetBmcResponse(
        $streamUrl,
        $session['cookies'],
        is_array($fwdHdr) ? $fwdHdr : [],
        $bmcIp,
        false
    );

    if (!$r['ok'] && !empty($r['applied_resolve'])) {
        $r = ipmiProxyStreamGetBmcResponse(
            $streamUrl,
            $session['cookies'],
            is_array($fwdHdr) ? $fwdHdr : [],
            $bmcIp,
            true
        );
    }

    $iloSseRetried = false;
    if (!$r['ok']) {
        if (ipmiWebIsNormalizedIloType($bmcTypeNorm) && ipmiProxyIsIloEventStreamPath($bmcPath)) {
            $canSseRecover = ipmiProxyIloSseLooksRecoverable($r);
            if ($canSseRecover) {
                $sseRetryState = ipmiProxyIloBootstrapStateLoad($session);
                $sseRetryDecision = ['kind' => 'hard', 'reason' => 'sse_stream_failed'];
                if (!ipmiProxyIloCanAttemptAnotherRefresh($sseRetryState, $sseRetryDecision)) {
                    if (ipmiProxyDebugEnabled()) {
                        ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                            'trace'  => $ipmiTraceId,
                            'gate'   => 'sse_stream_retry',
                            'reason' => 'refresh_budget',
                        ]);
                    }
                } else {
                    $sseRetryState = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $sseRetryState, $ipmiTraceId);
                    if (ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $ipmiTraceId, 'sse_stream_failed')) {
                        if (ipmiProxyDebugEnabled()) {
                            ipmiProxyDebugLog('ilo_runtime_sse_retry', [
                                'trace'   => $ipmiTraceId,
                                'bmcPath' => $bmcPath,
                            ]);
                        }
                        ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $ipmiTraceId);
                        $freshSse = ipmiProxyRebuildFreshIloRequestState($session, $bmcScheme, $bmcIp, $bmcPathOnlyLower, $ipmiTraceId);
                        $fwdHdr = $freshSse['fwdHdr'];
                        ipmiProxyRecoverBmcAuthBeforeSse($session, $mysqli, $token, $bmcIp, $bmcScheme, $fwdHdr, $ipmiTraceId);
                        $r = ipmiProxyStreamGetBmcResponse(
                            $streamUrl,
                            $freshSse['cookies'],
                            is_array($fwdHdr) ? $fwdHdr : [],
                            $bmcIp,
                            false
                        );
                        if (!$r['ok'] && !empty($r['applied_resolve'])) {
                            $r = ipmiProxyStreamGetBmcResponse(
                                $streamUrl,
                                $freshSse['cookies'],
                                is_array($fwdHdr) ? $fwdHdr : [],
                                $bmcIp,
                                true
                            );
                        }
                        $iloSseRetried = true;
                    }
                }
            }
        }
        if (!$r['ok']) {
            if (ipmiWebIsNormalizedIloType($bmcTypeNorm) && ipmiProxyIsIloEventStreamPath($bmcPath)) {
                ipmiProxyIloBootstrapNoteSse($mysqli, $token, $session, false, $iloSseRetried, $r, $ipmiTraceId);
            }
            if (ipmiProxyDebugEnabled()) {
                $sseAxis = 'sse_transport';
                if (!empty($r['auth_rejected'])) {
                    $sseAxis = 'sse_auth_drift';
                } elseif (!empty($r['sse_recoverable_http'])
                    || (isset($r['curl_errno']) && (int) $r['curl_errno'] !== 0)) {
                    $sseAxis = 'upstream_transport';
                }
                ipmiProxyDebugLog('stream_sse_failed', [
                    'trace'           => $ipmiTraceId,
                    'bmcPath'         => $bmcPath,
                    'auth_rejected'   => !empty($r['auth_rejected']),
                    'sse_recover_http' => !empty($r['sse_recoverable_http']) ? (int) ($r['sse_recover_http_code'] ?? 0) : 0,
                    'applied_resolve' => !empty($r['applied_resolve']),
                    'curl_errno'      => $r['curl_errno'] ?? null,
                    'curl_error'      => isset($r['curl_error']) ? substr((string) $r['curl_error'], 0, 240) : null,
                    'ilo_sse_retried' => $iloSseRetried ? 1 : 0,
                    'failure_axis'    => $sseAxis,
                    'blank_ui_cause'  => ipmiProxyIloBlankUiCause($bmcPath, 'sse_final', [
                        'auth_rejected'        => !empty($r['auth_rejected']),
                        'curl_errno'           => (int) ($r['curl_errno'] ?? 0),
                        'sse_recoverable_http' => !empty($r['sse_recoverable_http']),
                    ]),
                ]);
                ipmiProxyDebugEmitLogHeader(array_merge([
                    'trace'   => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                    'phase'   => 'stream_failed',
                ], ipmiWebIsNormalizedIloType($bmcTypeNorm) ? [
                    'ilo_bootstrap' => ipmiProxyIloBootstrapDebugSnapshot($session),
                ] : []));
            }
            if (ipmiProxyDebugEnabled()
                && ipmiWebIsNormalizedIloType($bmcTypeNorm)
                && ipmiProxyIsIloEventStreamPath($bmcPath)) {
                $sseFinalAxis = !empty($r['auth_rejected']) ? 'sse_auth_drift' : 'upstream_transport';
                ipmiProxyDebugLog('ilo_runtime_final_failure', [
                    'trace'          => $ipmiTraceId,
                    'bmcPath'        => $bmcPath,
                    'kind'           => 'sse',
                    'auth'           => !empty($r['auth_rejected']) ? 'rejected' : 'transport',
                    'failure_axis'   => $sseFinalAxis,
                    'blank_ui_cause' => ipmiProxyIloBlankUiCause($bmcPath, 'sse_final', [
                        'auth_rejected'        => !empty($r['auth_rejected']),
                        'curl_errno'           => (int) ($r['curl_errno'] ?? 0),
                        'sse_recoverable_http' => !empty($r['sse_recoverable_http']),
                    ]),
                    'sse_recover_http' => !empty($r['sse_recoverable_http']) ? (int) ($r['sse_recover_http_code'] ?? 0) : 0,
                ]);
            }
            if (!empty($r['auth_rejected'])) {
                ipmiProxyEmitSessionExpiredPage('BMC denied this request because the session expired. Open a new session from the panel.');
            } elseif (ipmiProxyIsHealthPollPath($bmcPath)) {
                ipmiProxyEmitHealthPollFallbackJson();
            } elseif (str_starts_with(strtolower($bmcPath), '/sse/')) {
                ipmiProxyEmitSseRetryHint();
            } else {
                http_response_code(502);
                echo 'BMC unreachable';
            }
        }
    }
    if (!empty($r['ok']) && ipmiWebIsNormalizedIloType($bmcTypeNorm) && ipmiProxyIsIloEventStreamPath($bmcPath)) {
        ipmiProxyIloBootstrapNoteSse($mysqli, $token, $session, true, $iloSseRetried, null, $ipmiTraceId);
        if ($iloSseRetried && ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_sse_recovered_after_refresh', ['trace' => $ipmiTraceId, 'bmcPath' => $bmcPath]);
        }
    }
    exit;
}

if (
    $method === 'GET'
    && ipmiWebIsNormalizedIloType($typeNorm)
    && in_array(strtolower((string) parse_url($bmcPath, PHP_URL_PATH)), ['/html/application.html', '/html/rc_info.html'], true)
    && (string) ($_GET['ipmi_kvm_auto'] ?? '') === '1'
    && (string) ($_GET['ipmi_kvm_legacy'] ?? '') !== '1'
) {
    // Do not pre-block by jnlp_template heuristics.
    // Real HTML5 capability must be decided by runtime launch path.
    $forceHtml5 = ((string) ($_GET['ipmi_kvm_force_html5'] ?? '') === '1');
    if (ipmiProxyDebugEnabled() && $forceHtml5) {
        ipmiProxyDebugLog('ilo_kvm_force_html5', [
            'trace' => $ipmiTraceId,
            'from' => $bmcPath,
        ]);
    }
}

$result = ipmiProxyExecute($bmcUrl, $method, $postBody, $fwdContentType, $session['cookies'], is_array($fwdHdr) ? $fwdHdr : [], $bmcIp);

ipmiProxyIloMaybeRecoverBufferedRuntime(
    $mysqli,
    $token,
    $session,
    $bmcScheme,
    $bmcIp,
    $bmcPath,
    $bmcPathOnlyLower,
    $method,
    $bmcUrl,
    $postBody,
    $fwdContentType,
    $result,
    $ipmiTraceId
);
if (!empty($GLOBALS['__ipmi_ilo_runtime_recover_attempted'])) {
    $fwdHdr = ipmiProxyRebuildIloForwardHeadersFromSession(
        $session,
        $bmcScheme,
        $bmcIp,
        $bmcPathOnlyLower
    );
}

// Core JS/CSS/image assets must be resilient. If transport failed, retry once.
if ($result['raw'] === false && $method === 'GET' && ipmiProxyIsBmcStaticAssetPath($bmcPath)) {
        $retryAsset = ipmiProxyExecute(
        $bmcUrl,
        $method,
        $postBody,
        $fwdContentType,
        $session['cookies'],
        is_array($fwdHdr) ? $fwdHdr : [],
        $bmcIp,
        20
    );
    if ($retryAsset['raw'] !== false) {
        $result = $retryAsset;
    }
}

if ($result['raw'] === false) {
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('curl_failed', ['trace' => $ipmiTraceId, 'bmcPath' => $bmcPath, 'method' => $method]);
        ipmiProxyDebugEmitLogHeader([
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'phase'   => 'curl_failed',
        ]);
    }
    if ($method === 'GET' && ipmiProxyIsBmcStaticAssetPath($bmcPath)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('static_asset_fallback', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'reason'  => 'curl_failed',
            ]);
            ipmiProxyDebugEmitLogHeader([
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'phase'   => 'static_fallback',
            ]);
        }
        if (ipmiProxyTryEmitStaticFallback($bmcPath)) {
            exit;
        }
    }
    if (ipmiProxyIsHealthPollPath($bmcPath)) {
        ipmiProxyEmitHealthPollFallbackJson();
        exit;
    }
    if (ipmiProxyDebugEnabled()
        && ipmiWebIsNormalizedIloType($bmcTypeNorm)
        && ipmiProxyIsIloRecoverableRuntimePath($bmcPath)
        && !empty($GLOBALS['__ipmi_ilo_runtime_recover_attempted'])) {
        ipmiProxyDebugLog('ilo_runtime_final_failure', [
            'trace'          => $ipmiTraceId,
            'bmcPath'        => $bmcPath,
            'kind'           => 'upstream_transport',
            'method'         => $method,
            'path_class'     => ipmiProxyIloRuntimePathDebugClass($bmcPath),
            'failure_axis'   => 'upstream_transport',
            'blank_ui_cause' => ipmiProxyIloBlankUiCause($bmcPath, 'curl_after_recover'),
            'curl_errno'     => (int) ($result['curl_errno'] ?? 0),
        ]);
    }
    http_response_code(502);
    echo 'BMC unreachable';
    exit;
}

$rawResponse = $result['raw'];
$httpCode = $result['http_code'];
$contentTypeResp = $result['content_type'];

[, $responseBody] = ipmiWebCurlExtractFinalHeadersAndBody($rawResponse);
$newCookies = ipmiWebCurlMergeSetCookiesFromChain($rawResponse, []);

if (!empty($newCookies)) {
    $session['cookies'] = array_merge($session['cookies'], $newCookies);
    ipmiWebSaveSessionCookies(
        $mysqli,
        $token,
        $session['cookies'],
        is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
        (string)($session['bmc_scheme'] ?? 'https')
    );
    if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
        ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
    }
}

// ASRockRack/Supermicro UI sometimes references banner images with relative paths that resolve to
// /cgi/*.png (404). Retry known asset directories when a small image returns 404.
if ($method === 'GET' && ($httpCode === 404 || $httpCode === 400) && ipmiProxyIsBmcStaticAssetPath($bmcPath)) {
    $pathOnly = (string) parse_url($bmcPath, PHP_URL_PATH);
    $file = basename($pathOnly);
    $dir = dirname(str_replace('\\', '/', $pathOnly));
    $dir = $dir === '.' ? '/' : $dir;
    $typeNormAsset = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));

    // iLO login shells may incorrectly reference /html/css|js|images paths.
    // If those 404, retry same asset from root to keep UI from breaking to white screen.
    if (ipmiWebIsNormalizedIloType($typeNormAsset) && preg_match('#^/html/(.+)$#i', $pathOnly, $mHtmlAsset)) {
        $altPath = '/' . ltrim((string) ($mHtmlAsset[1] ?? ''), '/');
        if (
            $altPath !== '/'
            && preg_match('#^/(?:css|js|img|images|fonts|themes|alt/css|alt/js|favicon\.ico)(?:/|$)#i', $altPath)
        ) {
            $altUrl = $bmcScheme . '://' . $bmcIp . $altPath;
            $alt = ipmiProxyExecute(
                $altUrl,
                $method,
                $postBody,
                $fwdContentType,
                $session['cookies'],
                is_array($fwdHdr) ? $fwdHdr : [],
                $bmcIp,
                15
            );
            if ($alt['raw'] !== false && $alt['http_code'] >= 200 && $alt['http_code'] < 400) {
                $rawResponse = $alt['raw'];
                $httpCode = $alt['http_code'];
                $contentTypeResp = $alt['content_type'];
                [, $responseBody] = ipmiWebCurlExtractFinalHeadersAndBody($rawResponse);
            }
        }
    }

    $isH5Banner = (bool)preg_match('/^h5banner_(left|right)\\.png$/i', $file);
    if ($isH5Banner
        || ($dir === '/' && preg_match('/\\.(?:png|jpg|jpeg|gif|svg)$/i', $file))
        || (preg_match('/\\/(?:res|resources|assets)(?:\\/oem)?\\/?$/i', $dir) && preg_match('/\\.(?:png|jpg|jpeg|gif|svg)$/i', $file))) {
        $candidates = [
            '/images/' . $file,
            '/img/' . $file,
            '/resources/' . $file,
            '/res/' . $file,
            '/res/oem/' . $file,
            '/oem/' . $file,
            '/assets/' . $file,
            '/static/' . $file,
        ];
        foreach ($candidates as $altPath) {
            $altUrl = $bmcScheme . '://' . $bmcIp . $altPath;
            $alt = ipmiProxyExecute(
                $altUrl,
                $method,
                $postBody,
                $fwdContentType,
                $session['cookies'],
                is_array($fwdHdr) ? $fwdHdr : [],
                $bmcIp,
                12
            );
            if ($alt['raw'] === false && $bmcScheme === 'https') {
                $altUrl = 'http://' . $bmcIp . $altPath;
                $alt = ipmiProxyExecute(
                    $altUrl,
                    $method,
                    $postBody,
                    $fwdContentType,
                    $session['cookies'],
                    is_array($fwdHdr) ? $fwdHdr : [],
                    $bmcIp,
                    12
                );
            }
            if ($alt['raw'] !== false && $alt['http_code'] >= 200 && $alt['http_code'] < 400) {
                $rawResponse = $alt['raw'];
                $httpCode = $alt['http_code'];
                $contentTypeResp = $alt['content_type'];
                [, $responseBody] = ipmiWebCurlExtractFinalHeadersAndBody($rawResponse);
                $altCookies = ipmiWebCurlMergeSetCookiesFromChain($rawResponse, []);
                if (!empty($altCookies)) {
                    $session['cookies'] = array_merge($session['cookies'], $altCookies);
                    ipmiWebSaveSessionCookies(
                        $mysqli,
                        $token,
                        $session['cookies'],
                        is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
                        (string)($session['bmc_scheme'] ?? 'https')
                    );
                    if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
                        ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
                    }
                }
                break;
            }
        }
        // If the BMC does not provide these banners anywhere, return a tiny transparent PNG
        // to avoid repeated 404s and JS layout retries.
        if ($isH5Banner && ($httpCode === 404 || $httpCode === 400)) {
            http_response_code(200);
            header('Content-Type: image/png');
            header('Cache-Control: private, max-age=300');
            echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=');
            exit;
        }
    }
}

if (ipmiWebIsNormalizedIloType($bmcTypeNorm)) {
    $pathRoleTrack = ipmiProxyClassifyIloPathRoleForSession($mysqli, $token, $session, $bmcPath, $method, $ipmiTraceId);
    if (ipmiProxyDebugEnabled()) {
        $pathRoleLog = [
            'trace'              => $ipmiTraceId,
            'bmcPath'            => $bmcPath,
            'path_role'          => $pathRoleTrack['role'],
            'path_role_base'     => (string) ($pathRoleTrack['base_role'] ?? $pathRoleTrack['role']),
            'bootstrap_critical' => !empty($pathRoleTrack['bootstrap_critical']) ? 1 : 0,
            'gate'               => 'post_upstream',
        ];
        if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
            $ctxP = ipmiProxyIloActiveNativeConsoleContextDetail($session, ipmiProxyIloBootstrapStateLoad($session));
            $pathRoleLog['native_console_context'] = $ctxP['active'] ? 1 : 0;
            $pathRoleLog['native_ctx_match'] = (string) ($ctxP['match'] ?? '');
            $pathRoleLog['secondary_promotion'] = (($pathRoleTrack['role'] ?? '') === 'secondary_console_helper')
                ? 'promoted' : 'not_promoted';
        }
        ipmiProxyDebugLog('ilo_path_role_classified', $pathRoleLog);
        if (!empty($pathRoleTrack['bootstrap_critical'])) {
            ipmiProxyDebugLog('ilo_bootstrap_critical_path_detected', [
                'trace'     => $ipmiTraceId,
                'bmcPath'   => $bmcPath,
                'path_role' => $pathRoleTrack['role'],
                'gate'      => 'post_upstream',
            ]);
        }
    }
    ipmiProxyIloBootstrapTrackBufferedResponse(
        $mysqli,
        $token,
        $session,
        $bmcPath,
        $method,
        (int) $httpCode,
        (string) $contentTypeResp,
        (string) $responseBody,
        $pathRoleTrack,
        !empty($GLOBALS['__ipmi_ilo_runtime_recover_attempted']),
        $ipmiTraceId
    );
}

// Determine content type early for login/timeout detection.
$ct = strtolower(trim(explode(';', $contentTypeResp)[0] ?? ''));
$isHtml = ($ct === '' || $ct === 'text/html' || strpos($ct, 'html') !== false || strpos($ct, 'text/plain') !== false);
$isJs = in_array($ct, ['application/javascript', 'text/javascript', 'application/x-javascript'], true);
$isCss = ($ct === 'text/css');
$isJson = (strpos($ct, 'json') !== false);

if (
    $method === 'GET'
    && $httpCode === 200
    && $isHtml
    && ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))
    && strtolower((string) parse_url($bmcPath, PHP_URL_PATH)) === '/html/java_irc.html'
    && ipmiProxyBodyLooksLikeJavaOnlyIloConsole($responseBody)
) {
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_java_irc_detected', [
            'trace' => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'kvmAutoFlow' => ipmiProxyIsKvmAutoFlowRequest() ? 1 : 0,
        ]);
    }
}

if (
    $method === 'GET'
    && $httpCode === 200
    && $isHtml
    && ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))
    && strtolower((string) parse_url($bmcPath, PHP_URL_PATH)) === '/html/jnlp_template.html'
) {
    $iloBoot = ipmiProxyIloBootstrapStateLoad($session);
    $nativeCtxSnap = ipmiProxyIloActiveNativeConsoleContextDetail($session, $iloBoot);
    $nativeCtx = $nativeCtxSnap['active'];
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_jnlp_template_detected', [
            'trace' => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'fromKvmAutoFlow' => ipmiProxyIsKvmAutoFlowRequest() ? 1 : 0,
            'looksUnavailable' => ipmiProxyBodyLooksLikeIloHtml5ConsoleUnavailable($responseBody) ? 1 : 0,
            'native_console_context' => $nativeCtx ? 1 : 0,
            'native_ctx_match' => (string) ($nativeCtxSnap['match'] ?? ''),
        ]);
        if ($nativeCtx) {
            ipmiProxyDebugLog('ilo_legacy_named_helper_seen_in_html5_flow', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
            ]);
            ipmiProxyDebugLog('ilo_secondary_helper_not_treated_as_legacy_fallback', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
            ]);
        }
    }
}

// HTML/login/timeout shell: session cookie is stale or session create-time login failed.
$looksLikeLoginPage = ipmiWebResponseLooksLikeBmcLoginPage($responseBody, $contentTypeResp);
$hasTimeoutText = ipmiProxyBodyHasSessionTimeout($responseBody);
$looksLikeSmTimeoutShell = ipmiProxyBodyLooksLikeSupermicroTimeoutShell($responseBody);
$isAssetPath = ipmiProxyIsBmcStaticAssetPath($bmcPath);
// If an asset request returned HTML, treat it as a login/timeout shell.
if ($isAssetPath && $isHtml && $httpCode >= 200 && $httpCode < 400) {
    $looksLikeLoginPage = true;
}
// AMI/ASRock SPA can render a login shell without password fields (so generic login detection fails).
if ($method === 'GET' && $httpCode === 200) {
    $typeNorm = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
    if ($typeNorm === 'ami' && $isHtml) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ami_verify_start', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
            ]);
        }
        $baseUrl = (string) ($session['bmc_scheme'] ?? 'https') . '://' . $bmcIp;
        $hasAuth = ipmiWebAmiVerifyAuthed(
            $baseUrl,
            $bmcIp,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : [],
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : []
        );
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ami_verify_result', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'authed'  => $hasAuth ? 1 : 0,
            ]);
        }
        if (!$hasAuth) {
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ami_spa_login_detected', [
                    'trace'   => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                ]);
            }
            $session['cookies'] = [];
            $session['forward_headers'] = [];
            if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
                ipmiWebSaveSessionCookies(
                    $mysqli,
                    $token,
                    $session['cookies'],
                    is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
                    (string)($session['bmc_scheme'] ?? 'https')
                );
                if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
                    ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
                }
                $landingPath = ipmiProxyPostAuthLandingPath((string) ($session['bmc_type'] ?? 'generic'));
                if ($landingPath !== '' && !ipmiProxyIsSameRelativeTarget($landingPath, $currentBmcTarget)) {
                    header('Location: ' . $tokenPrefix . $landingPath, true, 302);
                    exit;
                }
            }
        }
    }
    if (ipmiWebIsNormalizedIloType($typeNorm) && $isHtml) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_verify_start', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
            ]);
        }
        $baseUrl = (string) ($session['bmc_scheme'] ?? 'https') . '://' . $bmcIp;
        $hasAuth = ipmiWebIloVerifyAuthed(
            $baseUrl,
            $bmcIp,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : [],
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : []
        );
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_verify_result', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'authed'  => $hasAuth ? 1 : 0,
            ]);
        }
        if ($hasAuth) {
            $landingPath = ipmiProxyPostAuthLandingPath((string) ($session['bmc_type'] ?? 'generic'));
            $curPathOnly = strtolower((string) parse_url($currentBmcTarget, PHP_URL_PATH));
            if ($curPathOnly === '' || $curPathOnly === '/') {
                if ($landingPath !== '' && !ipmiProxyIsSameRelativeTarget($landingPath, $currentBmcTarget)) {
                    if (ipmiProxyDebugEnabled()) {
                        ipmiProxyDebugLog('ilo_root_redirect', [
                            'trace' => $ipmiTraceId,
                            'from'  => $currentBmcTarget,
                            'to'    => $landingPath,
                        ]);
                    }
                    header('Location: ' . $tokenPrefix . $landingPath, true, 302);
                    exit;
                }
            }
            // Some iLO builds transiently route authenticated users through login.html.
            // Avoid white-screen/login-shell fallback by forcing the authenticated landing page.
            $isIloLoginShell = in_array($curPathOnly, ['/login.html', '/html/login.html'], true);
            if ($isIloLoginShell && $landingPath !== '' && !ipmiProxyIsSameRelativeTarget($landingPath, $currentBmcTarget)) {
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_login_redirect', [
                        'trace' => $ipmiTraceId,
                        'from'  => $currentBmcTarget,
                        'to'    => $landingPath,
                    ]);
                }
                header('Location: ' . $tokenPrefix . $landingPath, true, 302);
                exit;
            }
        }
        if (!$hasAuth) {
            $session['cookies'] = [];
            $session['forward_headers'] = [];
            if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
                ipmiWebSaveSessionCookies(
                    $mysqli,
                    $token,
                    $session['cookies'],
                    is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
                    (string)($session['bmc_scheme'] ?? 'https')
                );
                if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
                    ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
                }
                $landingPath = ipmiProxyPostAuthLandingPath((string) ($session['bmc_type'] ?? 'generic'));
                if ($landingPath !== '' && !ipmiProxyIsSameRelativeTarget($landingPath, $currentBmcTarget)) {
                    header('Location: ' . $tokenPrefix . $landingPath, true, 302);
                    exit;
                }
            }
        }
    }
    if ($typeNorm === 'idrac' && $isHtml) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('idrac_verify_start', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
            ]);
        }
        $baseUrl = (string) ($session['bmc_scheme'] ?? 'https') . '://' . $bmcIp;
        $hasAuth = ipmiWebIdracVerifyAuthed(
            $baseUrl,
            $bmcIp,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : []
        );
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('idrac_verify_result', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'authed'  => $hasAuth ? 1 : 0,
            ]);
        }
        if ($hasAuth) {
            $landingPath = ipmiProxyPostAuthLandingPath((string) ($session['bmc_type'] ?? 'generic'));
            $curPathOnly = strtolower((string) parse_url($currentBmcTarget, PHP_URL_PATH));
            // If auth is valid and browser is on launcher/login-like endpoints, move to app entry.
            $isLoginLikePath = in_array($curPathOnly, ['/login', '/login.html', '/start.html', '/restgui/start.html', '/restgui/launch'], true);
            if ($isLoginLikePath && $landingPath !== '' && !ipmiProxyIsSameRelativeTarget($landingPath, $currentBmcTarget)) {
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('idrac_login_redirect', [
                        'trace' => $ipmiTraceId,
                        'from'  => $currentBmcTarget,
                        'to'    => $landingPath,
                    ]);
                }
                header('Location: ' . $tokenPrefix . $landingPath, true, 302);
                exit;
            }
        } else {
            // Do not force iDRAC relogin for every HTML page when verify is uncertain.
            // We only relogin on clear auth-shell signals, otherwise we can cause loops/session churn.
            $shouldRelogin = $looksLikeLoginPage
                || $hasTimeoutText
                || ipmiProxyBodyLooksLikeIdracLauncherShell($responseBody)
                || ipmiProxyLooksLikeLoginPath($bmcPath);
            if ($shouldRelogin) {
                $session['cookies'] = [];
                $session['forward_headers'] = [];
                if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
                    ipmiWebSaveSessionCookies(
                        $mysqli,
                        $token,
                        $session['cookies'],
                        is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
                        (string)($session['bmc_scheme'] ?? 'https')
                    );
                    if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
                        ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
                    }
                    $landingPath = ipmiProxyPostAuthLandingPath((string) ($session['bmc_type'] ?? 'generic'));
                    if ($landingPath !== '' && !ipmiProxyIsSameRelativeTarget($landingPath, $currentBmcTarget)) {
                        header('Location: ' . $tokenPrefix . $landingPath, true, 302);
                        exit;
                    }
                } else {
                    // Failed to establish an authenticated iDRAC session; avoid endless launcher/login spinner loops.
                    if (ipmiProxyBodyLooksLikeIdracLauncherShell($responseBody) || ipmiProxyLooksLikeLoginPath($bmcPath)) {
                        ipmiProxyEmitSessionExpiredPage('Could not establish an iDRAC session. Open a new session from the panel.');
                        exit;
                    }
                }
            } elseif (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('idrac_relogin_skipped_uncertain_verify', [
                    'trace'   => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                ]);
            }
        }
    }
}
if ($method === 'GET' && $httpCode === 200 && $isHtml && $isAssetPath
    && ($looksLikeLoginPage || $hasTimeoutText || $looksLikeSmTimeoutShell)) {
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('asset_auth_recover', [
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'reason'  => ($looksLikeLoginPage ? 'login_page' : ($hasTimeoutText ? 'timeout_text' : 'sm_timeout_shell')),
        ]);
    }
    $session['cookies'] = [];
    $session['forward_headers'] = [];
    if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
        ipmiWebSaveSessionCookies(
            $mysqli,
            $token,
            $session['cookies'],
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
            (string)($session['bmc_scheme'] ?? 'https')
        );
        if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
            ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
        }
        $retryHdrAsset = is_array($fwdHdr) ? $fwdHdr : [];
        $iloAssetHdr = ipmiProxyIloFreshForwardHeadersAfterRelogin($session, $bmcScheme, $bmcIp, $bmcPath, $mysqli, $token, $ipmiTraceId);
        if ($iloAssetHdr !== null) {
            $retryHdrAsset = $iloAssetHdr;
        }
        $retryAsset = ipmiProxyExecute(
            $bmcUrl,
            $method,
            $postBody,
            $fwdContentType,
            $session['cookies'],
            $retryHdrAsset,
            $bmcIp,
            20
        );
        if ($retryAsset['raw'] !== false) {
            $rawResponse = $retryAsset['raw'];
            $httpCode = $retryAsset['http_code'];
            $contentTypeResp = $retryAsset['content_type'];
            [, $responseBody] = ipmiWebCurlExtractFinalHeadersAndBody($rawResponse);
            $looksLikeLoginPage = ipmiWebResponseLooksLikeBmcLoginPage($responseBody, $contentTypeResp);
            $hasTimeoutText = ipmiProxyBodyHasSessionTimeout($responseBody);
            $looksLikeSmTimeoutShell = ipmiProxyBodyLooksLikeSupermicroTimeoutShell($responseBody);
        }
    }
    if ($looksLikeLoginPage || $hasTimeoutText || $looksLikeSmTimeoutShell) {
        if (ipmiProxyTryEmitStaticFallback($bmcPath)) {
            exit;
        }
        http_response_code(204);
        if ($isJs) {
            header('Content-Type: application/javascript; charset=utf-8');
        } elseif ($isCss) {
            header('Content-Type: text/css; charset=utf-8');
        }
        exit;
    }
}

if ($method === 'GET' && $httpCode === 200 && $isHtml && !$isAssetPath
    && ($looksLikeLoginPage || $hasTimeoutText || $looksLikeSmTimeoutShell)) {
    $hasAuth = ipmiWebHasUsableBmcAuth(
        is_array($session['cookies'] ?? null) ? $session['cookies'] : [],
        is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : []
    );
    if ($hasAuth) {
        // A non-empty cookie jar is not enough on some BMCs (especially Supermicro timeout shells).
        // Verify auth before suppressing timeout/login-page handling.
        $verifiedAuth = true;
        $typeForVerify = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
        if ($typeForVerify === 'supermicro') {
            $baseUrlForVerify = (string) ($session['bmc_scheme'] ?? 'https') . '://' . $bmcIp;
            $verifiedAuth = ipmiWebSupermicroVerifyAuthed(
                $baseUrlForVerify,
                $bmcIp,
                is_array($session['cookies'] ?? null) ? $session['cookies'] : []
            );
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('supermicro_verify_before_suppress', [
                    'trace'    => $ipmiTraceId,
                    'bmcPath'  => $bmcPath,
                    'verified' => $verifiedAuth ? 1 : 0,
                ]);
            }
        }
        if ($verifiedAuth) {
        $landingPath = ipmiProxyPostAuthLandingPath((string) ($session['bmc_type'] ?? 'generic'));
        $skipIdracLandingRedirect = ipmiProxyShouldSuppressIdracLandingRedirect(
            (string) ($session['bmc_type'] ?? ''),
            $currentBmcTarget,
            $landingPath
        );
        if ($skipIdracLandingRedirect && ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('idrac_landing_redirect_suppressed', [
                'trace' => $ipmiTraceId,
                'from'  => $currentBmcTarget,
                'to'    => $landingPath,
            ]);
        }
        if (!$skipIdracLandingRedirect && $landingPath !== '' && !ipmiProxyIsSameRelativeTarget($landingPath, $currentBmcTarget)) {
            header('Location: ' . $tokenPrefix . $landingPath, true, 302);
            exit;
        }
        // Auth is present and we're already on the landing page; don't override with a timeout page.
        // Some vendors embed "session timeout" strings in JS even when the session is valid.
        $looksLikeLoginPage = false;
        $hasTimeoutText = false;
        $looksLikeSmTimeoutShell = false;
        } else {
            $hasAuth = false;
        }
    }
    if ($looksLikeLoginPage || $hasTimeoutText || $looksLikeSmTimeoutShell) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('relogin_attempt', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'reason'  => ($looksLikeLoginPage ? 'login_page' : ($hasTimeoutText ? 'timeout_text' : 'sm_timeout_shell')),
            ]);
        }
        $session['cookies'] = [];
        $session['forward_headers'] = [];
        if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
            ipmiWebSaveSessionCookies(
                $mysqli,
                $token,
                $session['cookies'],
                is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
                (string)($session['bmc_scheme'] ?? 'https')
            );
            if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
                ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
            }
            $landingPath = ipmiProxyPostAuthLandingPath((string) ($session['bmc_type'] ?? 'generic'));
            $skipIdracLandingRedirect = ipmiProxyShouldSuppressIdracLandingRedirect(
                (string) ($session['bmc_type'] ?? ''),
                $currentBmcTarget,
                $landingPath
            );
            if ($skipIdracLandingRedirect && ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('idrac_landing_redirect_suppressed', [
                    'trace' => $ipmiTraceId,
                    'from'  => $currentBmcTarget,
                    'to'    => $landingPath,
                ]);
            }
            if (!$skipIdracLandingRedirect && $landingPath !== '' && !ipmiProxyIsSameRelativeTarget($landingPath, $currentBmcTarget)) {
                header('Location: ' . $tokenPrefix . $landingPath, true, 302);
                exit;
            }
            // Same target (already on landing path): retry this request with fresh cookies instead
            // of emitting timeout page from stale response.
            $retryHdrRelogin = is_array($fwdHdr) ? $fwdHdr : [];
            $iloReloginHdr = ipmiProxyIloFreshForwardHeadersAfterRelogin($session, $bmcScheme, $bmcIp, $bmcPath, $mysqli, $token, $ipmiTraceId);
            if ($iloReloginHdr !== null) {
                $retryHdrRelogin = $iloReloginHdr;
            }
            $retryAfterLogin = ipmiProxyExecute(
                $bmcUrl,
                $method,
                $postBody,
                $fwdContentType,
                $session['cookies'],
                $retryHdrRelogin,
                $bmcIp,
                20
            );
            if ($retryAfterLogin['raw'] !== false) {
                $rawResponse = $retryAfterLogin['raw'];
                $httpCode = $retryAfterLogin['http_code'];
                $contentTypeResp = $retryAfterLogin['content_type'];
                [, $responseBody] = ipmiWebCurlExtractFinalHeadersAndBody($rawResponse);
                $looksLikeLoginPage = ipmiWebResponseLooksLikeBmcLoginPage($responseBody, $contentTypeResp);
                $hasTimeoutText = ipmiProxyBodyHasSessionTimeout($responseBody);
                $looksLikeSmTimeoutShell = ipmiProxyBodyLooksLikeSupermicroTimeoutShell($responseBody);
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('relogin_retry_result', [
                        'trace' => $ipmiTraceId,
                        'http' => $httpCode,
                        'loginPage' => $looksLikeLoginPage ? 1 : 0,
                        'timeoutText' => $hasTimeoutText ? 1 : 0,
                        'smTimeoutShell' => $looksLikeSmTimeoutShell ? 1 : 0,
                    ]);
                }
            }
        }
    }
    if ($looksLikeLoginPage || $hasTimeoutText || $looksLikeSmTimeoutShell) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('login_page_detected', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'loginPage' => $looksLikeLoginPage ? 1 : 0,
                'timeoutText' => $hasTimeoutText ? 1 : 0,
                'smTimeoutShell' => $looksLikeSmTimeoutShell ? 1 : 0,
            ]);
        }
        if (ipmiProxyDebugEnabled() && ($hasTimeoutText || $looksLikeSmTimeoutShell)) {
            ipmiProxyDebugLog('session_timeout_detected', [
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'timeoutText' => $hasTimeoutText ? 1 : 0,
                'smTimeoutShell' => $looksLikeSmTimeoutShell ? 1 : 0,
            ]);
        }
        ipmiWebKvmLaunchPlanCacheInvalidate($mysqli, $token);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('kvm_plan_recomputed_after_auth_drift', [
                'trace' => $ipmiTraceId,
                'bmcPath' => $bmcPath,
            ]);
        }
        ipmiProxyEmitSessionExpiredPage('Your session has timed out. You will need to open a new session.');
        exit;
    }
}

// Supermicro dashboard/status APIs are served from CGI endpoints and can sporadically return
// either 401/403 OR a timeout/login shell with HTTP 200 while the topmenu shell still looks valid.
// Retry once after refreshing auth so widgets don't stay blank.
$supermicroRuntimeBodyAuthFail = false;
if (
    ($method === 'GET' || $method === 'POST')
    && ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')) === 'supermicro'
    && ipmiProxyIsSupermicroRuntimeApiPath($bmcPath)
) {
    if ($httpCode === 200) {
        $supermicroRuntimeBodyAuthFail = ipmiProxyBodyLooksLikeSupermicroApiAuthFailure((string) $responseBody)
            || ipmiWebResponseLooksLikeBmcLoginPage((string) $responseBody, (string) $contentTypeResp);
    }
}
if (
    ($httpCode === 401 || $httpCode === 403 || $supermicroRuntimeBodyAuthFail)
    && ($method === 'GET' || $method === 'POST')
    && ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')) === 'supermicro'
    && ipmiProxyIsSupermicroRuntimeApiPath($bmcPath)
) {
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('supermicro_runtime_auth_recover_start', [
            'trace' => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'http' => $httpCode,
            'bodyAuthFail' => $supermicroRuntimeBodyAuthFail ? 1 : 0,
        ]);
    }
    $session['cookies'] = [];
    $session['forward_headers'] = [];
    if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
        ipmiWebSaveSessionCookies(
            $mysqli,
            $token,
            $session['cookies'],
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
            (string)($session['bmc_scheme'] ?? 'https')
        );
        if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
            ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
        }
        $retryHdr = ipmiProxyMergeClientBmcForwardHeaders(
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
            (string) ($session['bmc_scheme'] ?? 'https'),
            $bmcIp,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : []
        );
        if (!ipmiProxyForwardHeadersHasHeader($retryHdr, 'X-Requested-With')) {
            $retryHdr['X-Requested-With'] = 'XMLHttpRequest';
        }
        $retryApi = ipmiProxyExecute(
            $bmcUrl,
            $method,
            $postBody,
            $fwdContentType,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : [],
            $retryHdr,
            $bmcIp,
            20
        );
        if ($retryApi['raw'] !== false) {
            $rawResponse = $retryApi['raw'];
            $httpCode = (int) ($retryApi['http_code'] ?? 0);
            $contentTypeResp = (string) ($retryApi['content_type'] ?? '');
            [, $responseBody] = ipmiWebCurlExtractFinalHeadersAndBody($rawResponse);
            $ct = strtolower(trim(explode(';', $contentTypeResp)[0] ?? ''));
            $isHtml = ($ct === '' || $ct === 'text/html' || strpos($ct, 'html') !== false || strpos($ct, 'text/plain') !== false);
            $isJs = in_array($ct, ['application/javascript', 'text/javascript', 'application/x-javascript'], true);
            $isCss = ($ct === 'text/css');
            $isJson = (strpos($ct, 'json') !== false);
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('supermicro_runtime_auth_recover_result', [
                    'trace' => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                    'http' => $httpCode,
                    'contentType' => $contentTypeResp,
                ]);
            }
        }
    } elseif (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('supermicro_runtime_auth_recover_failed', [
            'trace' => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'error' => (string) ($session['auto_login_error'] ?? ''),
        ]);
    }
}

// AMI runtime APIs can return 401/403 while shell HTML still renders.
// Retry once after refreshing auth so UI does not bounce between #login and dashboard.
if (
    ($httpCode === 401 || $httpCode === 403)
    && ($method === 'GET' || $method === 'POST')
    && ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')) === 'ami'
    && ipmiProxyIsAmiRuntimeApiPath($bmcPath)
) {
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ami_runtime_auth_recover_start', [
            'trace' => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'http' => $httpCode,
        ]);
    }
    $session['cookies'] = [];
    $session['forward_headers'] = [];
    if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
        ipmiWebSaveSessionCookies(
            $mysqli,
            $token,
            $session['cookies'],
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
            (string)($session['bmc_scheme'] ?? 'https')
        );
        if (ipmiWebHasUsableBmcAuth($session['cookies'], is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [])) {
            ipmiWebEmitMirroredBmcCookiesForProxy($token, $session['cookies']);
        }
        $retryHdr = ipmiProxyMergeClientBmcForwardHeaders(
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [],
            (string) ($session['bmc_scheme'] ?? 'https'),
            $bmcIp,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : []
        );
        if (!ipmiProxyForwardHeadersHasHeader($retryHdr, 'X-Requested-With')) {
            $retryHdr['X-Requested-With'] = 'XMLHttpRequest';
        }
        if (!ipmiProxyForwardHeadersHasHeader($retryHdr, 'Accept')) {
            $retryHdr['Accept'] = 'application/json, text/javascript, */*';
        }
        $retryApi = ipmiProxyExecute(
            $bmcUrl,
            $method,
            $postBody,
            $fwdContentType,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : [],
            $retryHdr,
            $bmcIp,
            20
        );
        if ($retryApi['raw'] !== false) {
            $rawResponse = $retryApi['raw'];
            $httpCode = (int) ($retryApi['http_code'] ?? 0);
            $contentTypeResp = (string) ($retryApi['content_type'] ?? '');
            [, $responseBody] = ipmiWebCurlExtractFinalHeadersAndBody($rawResponse);
            $ct = strtolower(trim(explode(';', $contentTypeResp)[0] ?? ''));
            $isHtml = ($ct === '' || $ct === 'text/html' || strpos($ct, 'html') !== false || strpos($ct, 'text/plain') !== false);
            $isJs = in_array($ct, ['application/javascript', 'text/javascript', 'application/x-javascript'], true);
            $isCss = ($ct === 'text/css');
            $isJson = (strpos($ct, 'json') !== false);
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ami_runtime_auth_recover_result', [
                    'trace' => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                    'http' => $httpCode,
                    'contentType' => $contentTypeResp,
                ]);
            }
        }
    } elseif (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ami_runtime_auth_recover_failed', [
            'trace' => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'error' => (string) ($session['auto_login_error'] ?? ''),
        ]);
    }
}

if (ipmiProxyIsHealthPollPath($bmcPath) && ($httpCode === 401 || $httpCode === 403 || $httpCode >= 500)) {
    ipmiProxyEmitHealthPollFallbackJson();
    exit;
}

http_response_code($httpCode ?: 502);

// Some AMI/ASRockRack firmwares return 404 for /html/application.html.
// iLO4 can also return 404 for /html/application.html on top-level open links on certain builds.
// For iLO, only fallback for top-level document navigations (not iframe sub-loads).
$typeNormFor404 = ipmiWebNormalizeBmcType((string)($session['bmc_type'] ?? 'generic'));
if ($isHtml && ($typeNormFor404 === 'ami' || ipmiWebIsNormalizedIloType($typeNormFor404))) {
    $pathLower = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($httpCode === 404 && ($pathLower === '/html/application.html' || $pathLower === '/html/application.html/')) {
        if ($typeNormFor404 === 'ami') {
            header('Location: ' . $tokenPrefix . '/', true, 302);
            exit;
        }
        $fetchDest = strtolower((string) ($_SERVER['HTTP_SEC_FETCH_DEST'] ?? ''));
        $isTopLevelDocument = ($fetchDest === '' || $fetchDest === 'document');
        if ($isTopLevelDocument) {
            header('Location: ' . $tokenPrefix . '/index.html', true, 302);
            exit;
        }
    }
}

if ($contentTypeResp !== '') {
    header('Content-Type: ' . $contentTypeResp);
}
if ($method === 'GET' && ipmiProxyIsBmcStaticAssetPath($bmcPath) && $httpCode >= 200 && $httpCode < 400) {
    header('Cache-Control: private, max-age=300');
    if (function_exists('header_remove')) {
        @header_remove('Pragma');
    }
}

// iLO SPA checks document.cookie; without mirrored cookies it stays on #/login while the proxy
// is already authenticated server-side.
$scMirror = is_array($session['cookies'] ?? null) ? $session['cookies'] : [];
$shMirror = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
if ($isHtml && $httpCode >= 200 && $httpCode < 400 && ipmiWebHasUsableBmcAuth($scMirror, [])) {
    ipmiWebEmitMirroredBmcCookiesForProxy($token, $scMirror);
}

$rewriteBody = $isHtml || $isJs || $isCss || $isJson;
$bmcTypeStr = (string)($session['bmc_type'] ?? '');
$injectIloPatch = false;

if ($rewriteBody) {
    $responseBody = ipmiProxyRewriteBmcResponseBody(
        $responseBody,
        $bmcIp,
        $token,
        $tokenPrefix,
        $bmcTypeStr,
        $isHtml
    );
    if ($isCss) {
        $responseBody = ipmiProxyRewriteCssResponseBody($responseBody, $bmcPath, $tokenPrefix, $bmcIp);
    }
    if ($isJs && ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType($bmcTypeStr))) {
        $responseBody = ipmiProxyRewriteIloSocketJs($responseBody, $bmcPath, $token, $bmcIp, $bmcScheme);
    }
    if ($isHtml) {
        $responseBody = ipmiProxyStripMetaCsp($responseBody);
        foreach (ipmiProxyGetBmcHostAliases($bmcIp) as $host) {
            $responseBody = ipmiWebRewriteHtml($responseBody, $tokenPrefix, $host);
        }
        $responseBody = ipmiWebRewriteHtmlRelativeToDocument($responseBody, $tokenPrefix, $bmcPath);
        if (ipmiWebNormalizeBmcType($bmcTypeStr) === 'ami') {
            $responseBody = ipmiProxyInjectAmiLocalStorageBridge($responseBody);
        }
        // Inject iLO-specific path/fetch/EventSource fixes only for iLO-family HTML (or iLO SSE paths).
        // Avoid patching other vendors to reduce UI side-effects.
        $authOkHtml = ipmiWebHasUsableBmcAuth($scMirror, $shMirror);
        $shouldInjectIloPatch = $httpCode >= 200 && $httpCode < 400
            && (
                ipmiProxyIsIloFamily($bmcTypeStr)
                || stripos($responseBody, '/sse/') !== false
            );
        if ($shouldInjectIloPatch) {
            $xAuthForPatch = $authOkHtml ? ipmiProxyExtractIloAuthToken($scMirror, $shMirror) : '';
            if ($xAuthForPatch === '') {
                $xAuthForPatch = null;
            }
            $responseBody = ipmiProxyInjectIloHeadFixes(
                $responseBody,
                $token,
                $xAuthForPatch,
                $bmcIp
            );
        } else {
            $shouldInjectGenericPatch = $httpCode >= 200 && $httpCode < 400
                && ($authOkHtml || in_array($typeNorm, ['supermicro', 'ami', 'idrac'], true));
            if ($shouldInjectGenericPatch) {
            $genericAuth = ipmiProxyExtractIloAuthToken($scMirror, $shMirror);
            $csrfHeader = '';
            foreach (['X-CSRFTOKEN', 'X-CSRF-Token', 'X-Csrf-Token', 'X-CSRFToken'] as $hk) {
                if (!empty($shMirror[$hk])) {
                    $csrfHeader = (string) $shMirror[$hk];
                    break;
                }
            }
            $responseBody = ipmiProxyInjectGenericHeadFixes(
                $responseBody,
                $token,
                $bmcIp,
                $genericAuth !== '' ? $genericAuth : null,
                $csrfHeader !== '' ? $csrfHeader : null,
                $typeNorm === 'supermicro',
                $typeNorm === 'ami'
            );
            }
        }
        $kvmAutoPath = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
        $kvmAutoFlow = ipmiProxyIsKvmAutoFlowRequest();
        $kvmFam = ipmiWebBmcFamily($bmcTypeStr);
        $injectKvmPathOk = false;
        if ($kvmFam === 'ilo' && in_array($kvmAutoPath, ['/', '/index.html', '/html/application.html', '/html/summary.html', '/html/rc_info.html'], true)) {
            $injectKvmPathOk = true;
        }
        if ($kvmFam === 'idrac' && in_array($kvmAutoPath, ['/', '/index.html', '/start.html', '/login.html', '/viewer.html', '/console.html', '/restgui/start.html', '/restgui/launch'], true)) {
            $injectKvmPathOk = true;
        }
        if ($kvmFam === 'supermicro' && ($kvmAutoPath === '/cgi/url_redirect.cgi' || str_contains(strtolower($bmcPath), 'url_name=topmenu'))) {
            $injectKvmPathOk = true;
        }
        $shouldInjectKvmAutoPatch = ($httpCode >= 200 && $httpCode < 400) && $injectKvmPathOk;
        if ($shouldInjectKvmAutoPatch) {
            $launchPlanForPatch = ipmiWebResolveKvmLaunchPlan($session, $mysqli);
            $kvmAutolaunchInjectMeta = [];
            $responseBody = ipmiProxyInjectKvmAutoLaunchPatch(
                $responseBody,
                $token,
                $session,
                $kvmAutoFlow,
                $launchPlanForPatch,
                $mysqli,
                $kvmAutolaunchInjectMeta
            );
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('kvm_launch_plan_selected', array_merge(
                    ['trace' => $ipmiTraceId, 'bmcPath' => $bmcPath],
                    ipmiWebKvmPlanLogSummary($launchPlanForPatch)
                ));
                $kvmInjMode = (string) ($kvmAutolaunchInjectMeta['mode'] ?? '');
                if ($kvmInjMode === 'full') {
                    ipmiProxyDebugLog('kvm_autolaunch_patch_injected', [
                        'trace' => $ipmiTraceId,
                        'bmcPath' => $bmcPath,
                        'bmcType' => $bmcTypeStr,
                        'vendor_family' => $launchPlanForPatch['vendor_family'] ?? '',
                        'kvm_entry_path' => $launchPlanForPatch['kvm_entry_path'] ?? '',
                        'kvmAutoFlow' => $kvmAutoFlow ? 1 : 0,
                    ]);
                } elseif ($kvmInjMode === 'safe_fallback') {
                    ipmiProxyDebugLog('kvm_autolaunch_patch_injection_safe_fallback_only', [
                        'trace' => $ipmiTraceId,
                        'bmcPath' => $bmcPath,
                        'bmcType' => $bmcTypeStr,
                        'vendor_family' => $launchPlanForPatch['vendor_family'] ?? '',
                        'js_reason' => $kvmAutolaunchInjectMeta['js_reason'] ?? '',
                        'js_depth' => $kvmAutolaunchInjectMeta['js_depth'] ?? 0,
                    ]);
                }
                $injPath = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
                ipmiProxyDebugLog('kvm_autolaunch_inject_summary', [
                    'trace' => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                    'inject_mode' => $kvmInjMode,
                    'runtime_js_valid' => ($kvmAutolaunchInjectMeta['js_ok'] ?? null) === true ? 1 : (($kvmAutolaunchInjectMeta['js_ok'] ?? null) === false ? 0 : null),
                    'js_syntactically_valid' => ($kvmAutolaunchInjectMeta['js_ok'] ?? null) === true ? 'yes' : (($kvmAutolaunchInjectMeta['js_ok'] ?? null) === false ? 'no' : 'unknown'),
                    'runtime_patch_injected' => $kvmInjMode === 'full' ? 'yes' : 'no',
                    'runtime_patch_injected_full' => $kvmInjMode === 'full' ? 1 : 0,
                    'runtime_patch_stub_only' => $kvmInjMode === 'safe_fallback' ? 1 : 0,
                    'inject_target_application_path' => str_contains($injPath, '/html/application.html') ? 'yes' : 'no',
                    'inject_target_shell_index' => ($injPath === '' || $injPath === '/' || str_contains($injPath, '/index.html') || str_contains($injPath, '/restgui/')) ? 'yes' : 'no',
                    'js_reason' => (string) ($kvmAutolaunchInjectMeta['js_reason'] ?? ''),
                ]);
            }
        }
        // Inject this helper on all iLO HTML pages:
        // it shows the unavailable banner only when query flag exists,
        // and also removes stale banners left by in-page route changes.
        $kvmHintPath = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
        $shouldInjectKvmUnavailableHint = ($httpCode >= 200 && $httpCode < 400)
            && ipmiWebBmcFamily($bmcTypeStr) === 'ilo'
            && in_array($kvmHintPath, ['/', '/index.html', '/html/application.html', '/html/summary.html'], true);
        if ($shouldInjectKvmUnavailableHint) {
            $responseBody = ipmiProxyInjectKvmUnavailableHint($responseBody);
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('kvm_unavailable_hint_injected', [
                    'trace' => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                    'bmcType' => $bmcTypeStr,
                ]);
            }
        }
        $shouldInjectKvmPanelControlled = ($httpCode >= 200 && $httpCode < 400)
            && ipmiWebBmcFamily($bmcTypeStr) === 'ilo'
            && in_array($kvmHintPath, ['/', '/index.html', '/html/application.html', '/html/summary.html'], true)
            && (string) ($_GET['ipmi_kvm_delivery'] ?? '') === 'panel_controlled';
        if ($shouldInjectKvmPanelControlled) {
            $responseBody = ipmiProxyInjectKvmPanelControlledBanner($responseBody);
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('kvm_panel_controlled_banner_injected', [
                    'trace' => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                ]);
            }
        }
        $injectIloPatch = $shouldInjectIloPatch;
    }
}

if (ipmiProxyDebugEnabled()) {
    $docDir = dirname(str_replace('\\', '/', $bmcPath));
    if ($docDir === '.' || $docDir === '') {
        $docDir = '/';
    }
    ipmiProxyDebugLog('response', [
        'trace'          => $ipmiTraceId,
        'http'           => $httpCode,
        'contentType'    => substr($contentTypeResp, 0, 96),
        'bodyBytes'      => strlen($responseBody),
        'rewritten'      => $rewriteBody,
        'injectIloPatch' => $injectIloPatch,
        'htmlDocDir'     => $isHtml ? $docDir : null,
    ]);
    // KVM delivery snapshot: merge cached plan with live session meta (tier fields are not persisted in kvm_plan).
    $kvmDelDbg = [
        'kvm_delivery_tier'              => '',
        'kvm_native_route_confirmed'     => 0,
        'kvm_fallback_session_available' => 0,
        'kvm_user_facing_mode'           => '',
        'kvm_client_diagnostic'          => '',
        'kvm_blocked_by_suspend'         => 0,
    ];
    $kvmPlanSnapAll = is_array($session['session_meta']['kvm_plan']['plan'] ?? null)
        ? $session['session_meta']['kvm_plan']['plan'] : null;
    if (is_array($kvmPlanSnapAll)) {
        $pDbg = $kvmPlanSnapAll;
        unset($pDbg['_kvm_delivery_merged_v1']);
        $mPlan = ipmiWebKvmLaunchPlanMergeDelivery($pDbg, $session);
        $kvmDelDbg['kvm_delivery_tier'] = (string) ($mPlan['delivery_tier'] ?? '');
        $kvmDelDbg['kvm_native_route_confirmed'] = !empty($mPlan['native_route_confirmed']) ? 1 : 0;
        $kvmDelDbg['kvm_fallback_session_available'] = !empty($mPlan['fallback_session_available']) ? 1 : 0;
        $kvmDelDbg['kvm_user_facing_mode'] = (string) ($mPlan['user_facing_kvm_mode'] ?? '');
        $kvmDelDbg['kvm_client_diagnostic'] = (string) ($mPlan['client_visible_kvm_state'] ?? '');
    }
    $sidDbg = (int) ($session['server_id'] ?? 0);
    if ($sidDbg > 0) {
        $stS = $mysqli->prepare('SELECT COALESCE(suspended, 0) AS s FROM server_suspension WHERE server_id = ? LIMIT 1');
        if ($stS) {
            $stS->bind_param('i', $sidDbg);
            $stS->execute();
            $resS = $stS->get_result();
            $rs = $resS ? $resS->fetch_assoc() : null;
            $stS->close();
            if ($rs && (int) ($rs['s'] ?? 0) === 1) {
                $kvmDelDbg['kvm_blocked_by_suspend'] = 1;
            }
        }
    }
    $iloDbgExtra = [];
    if (ipmiWebIsNormalizedIloType($bmcTypeNorm)) {
        $iloDbgExtra['ilo_bootstrap'] = ipmiProxyIloBootstrapDebugSnapshot($session);
        $iloDbgExtra['ilo_console_readiness_server'] = ipmiProxyIloConsoleReadinessDebugSnapshot($session);
        $ncDbg = is_array($session['session_meta']['ilo_native_console_confirmation'] ?? null)
            ? $session['session_meta']['ilo_native_console_confirmation'] : null;
        if (is_array($ncDbg)) {
            $brDbg = is_array($ncDbg['browser'] ?? null) ? $ncDbg['browser'] : [];
        $iloNcRow = [
                'tier' => (string) ($ncDbg['tier'] ?? ''),
                'final_debug_verdict'    => (string) ($ncDbg['final_debug_verdict'] ?? ''),
                'final_strong_native_console' => ((string) ($ncDbg['final_debug_verdict'] ?? '') === 'native_console_strongly_confirmed') ? 'yes' : 'no',
                'confidence'             => (int) ($ncDbg['confidence'] ?? 0),
                'transport_started'      => !empty($ncDbg['transport_started']) ? 1 : 0,
                'session_ready'          => !empty($ncDbg['session_ready']) ? 1 : 0,
                'live_display_confirmed' => !empty($ncDbg['live_display_confirmed']) ? 1 : 0,
                'shell_only_signal'      => !empty($ncDbg['shell_only_signal']) ? 1 : 0,
                'browser_overlay_persisted' => $brDbg !== [] ? 'yes' : 'no',
            ];
        if ($brDbg !== []) {
            $iloNcRow['browser_application_path_loaded'] = !empty($brDbg['application_path_loaded']) ? 'yes' : 'no';
            $iloNcRow['browser_shell_only_ui'] = !empty($brDbg['shell_only_ui']) ? 'yes' : 'no';
            $iloNcRow['browser_overview_shell'] = !empty($brDbg['overview_shell']) ? 'yes' : 'no';
            $iloNcRow['browser_helper_activity'] = !empty($brDbg['helper_activity']) ? 'yes' : 'no';
            $iloNcRow['browser_live_display'] = (!empty($brDbg['live_display']) || !empty($brDbg['live_display_confirmed'])) ? 'yes' : 'no';
        }
        $iloDbgExtra['ilo_native_console_confirmation'] = $iloNcRow;
        }
        $iloPrFinal = ipmiProxyClassifyIloPathRoleForSession($mysqli, $token, $session, $bmcPath, $method, $ipmiTraceId);
        $iloDbgExtra['ilo_path_role'] = (string) ($iloPrFinal['role'] ?? '');
        $iloDbgExtra['ilo_path_role_base'] = (string) ($iloPrFinal['base_role'] ?? $iloDbgExtra['ilo_path_role']);
        $iloDbgExtra['ilo_path_bootstrap_critical'] = !empty($iloPrFinal['bootstrap_critical']) ? 1 : 0;
        $iloDbgExtra['ilo_path_role_flags'] = $iloPrFinal['flags'] ?? [];
        $iloDbgExtra['ilo_path_heuristic_score'] = (int) ($iloPrFinal['heuristic_score'] ?? 0);
        $kvmPlanSnap = $kvmPlanSnapAll;
        if (is_array($kvmPlanSnap) && (($kvmPlanSnap['vendor_family'] ?? '') === 'ilo')) {
            $iloDbgExtra['ilo_native_console_verdict'] = (string) ($kvmPlanSnap['ilo_native_console_verdict'] ?? '');
            $iloDbgExtra['ilo_console_capability'] = (string) ($kvmPlanSnap['console_capability'] ?? '');
            $iloDbgExtra['ilo_should_attempt_autolaunch'] = !empty($kvmPlanSnap['should_attempt_proxy_autolaunch']) ? 1 : 0;
            $iloDbgExtra['ilo_native_launch_blockers'] = array_slice((array) ($kvmPlanSnap['native_launch_blockers'] ?? []), 0, 8);
            $iloDbgExtra['ilo_native_launch_reason'] = substr((string) ($kvmPlanSnap['native_launch_reason'] ?? ''), 0, 220);
            $iloDbgExtra['ilo_shell_auth_vs_native'] = [
                'shell_authenticated_hint' => (int) ($kvmPlanSnap['shell_authenticated_hint'] ?? 0),
                'native_launch_viable'     => !empty($kvmPlanSnap['native_launch_viable']) ? 1 : 0,
                'bootstrap_healthy_hint'   => (int) ($kvmPlanSnap['shell_bootstrap_healthy_hint'] ?? 0),
            ];
        }
        $capSnap = is_array($session['session_meta']['ilo_console_capability']['data'] ?? null)
            ? $session['session_meta']['ilo_console_capability']['data'] : null;
        if (is_array($capSnap) && ($iloDbgExtra['ilo_native_console_verdict'] ?? '') === '') {
            $iloDbgExtra['ilo_native_console_verdict'] = (string) ($capSnap['ilo_native_console_verdict'] ?? '');
            $iloDbgExtra['ilo_console_capability'] = (string) ($capSnap['capability'] ?? '');
        }
    }
    ipmiProxyDebugEmitLogHeader(array_merge([
        'trace'   => $ipmiTraceId,
        'bmcPath' => $bmcPath,
        'phase'   => 'response',
    ], $kvmDelDbg, $iloDbgExtra));
    if ($isHtml && $httpCode >= 200 && $httpCode < 500) {
        ipmiProxyDebugAppendConsoleScript($responseBody, $ipmiTraceId, $bmcPath);
    }
}

echo $responseBody;
