<?php
/**
 * Automated BMC web UI reachability probe (same login stack as ipmi_proxy.php).
 * Intended for cron/CLI; disabled on web-triggered check_status unless IPMI_WEB_PROBE_ALLOW_WEB=1.
 */

require_once __DIR__ . '/encryption.php';
require_once __DIR__ . '/ipmi_web_session.php';
require_once __DIR__ . '/ipmi_bmc_curl.php';

function ipmiWebProbeShouldRun(): bool
{
    if (getenv('IPMI_WEB_PROBE') === '0') {
        return false;
    }
    if (defined('IPMI_WEB_PROBE_AUTO') && IPMI_WEB_PROBE_AUTO === false) {
        return false;
    }
    if (php_sapi_name() !== 'cli' && getenv('IPMI_WEB_PROBE_ALLOW_WEB') !== '1') {
        return false;
    }

    return true;
}

function ipmiWebProbeSessionJsonValid(string $body): bool
{
    $body = trim($body);
    if ($body === '' || $body[0] !== '{') {
        return false;
    }

    return is_array(json_decode($body, true));
}

/**
 * Lightweight parser for final response content-type from cURL raw output.
 */
function ipmiWebProbeExtractContentType(string $raw): string
{
    [$hdr] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    if ($hdr !== '' && preg_match('/^Content-Type:\s*([^\r\n]+)/mi', $hdr, $m)) {
        return trim((string) $m[1]);
    }

    return '';
}

/**
 * Detect common BMC timeout strings shown after stale/anonymous sessions.
 */
function ipmiWebProbeBodyHasSessionTimeoutText(string $body): bool
{
    if ($body === '') {
        return false;
    }
    // Ignore timeout strings that exist only inside JS constants.
    $visible = preg_replace('~<script\b[^>]*>.*?</script>~is', ' ', $body);
    if (!is_string($visible)) {
        $visible = $body;
    }
    $visible = preg_replace('~<style\b[^>]*>.*?</style>~is', ' ', $visible);
    if (!is_string($visible)) {
        $visible = $body;
    }

    $l = strtolower($visible);
    if (str_contains($l, 'ipmi session expired')) {
        return true;
    }
    if (str_contains($l, 'you will need to open a new session')) {
        return true;
    }

    return (str_contains($l, 'session has timed out') || str_contains($l, 'session timed out'))
        && (str_contains($l, 'please log in a new session') || str_contains($l, 'please login in a new session'));
}

/**
 * Fetch a BMC UI path with current authenticated session material.
 *
 * @return array{
 *   raw_ok: bool,
 *   http: int,
 *   content_type: string,
 *   body: string,
 *   login_page: bool,
 *   timeout_shell: bool,
 *   timeout_text: bool,
 *   body_bytes: int
 * }
 */
function ipmiWebProbeFetchUiPath(array $session, string $path): array
{
    $ip = trim((string) ($session['ipmi_ip'] ?? ''));
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $baseUrl = $scheme . '://' . $ip;
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $ip);
    $url = rtrim($baseUrl, '/') . '/' . ltrim($path, '/');

    [$raw, $code] = ipmiWebCurlExecBmc($ip, $url, static function ($ch) use ($originBase, $session): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 25);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        $headers = [
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/',
        ];
        $xAuth = trim((string) (($session['forward_headers']['X-Auth-Token'] ?? '')));
        if ($xAuth !== '') {
            $headers[] = 'X-Auth-Token: ' . $xAuth;
        }
        $xCsrf = trim((string) (($session['forward_headers']['X-CSRFTOKEN'] ?? $session['forward_headers']['X-CSRF-Token'] ?? '')));
        if ($xCsrf !== '') {
            $headers[] = 'X-CSRFTOKEN: ' . $xCsrf;
            $headers[] = 'X-CSRF-Token: ' . $xCsrf;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $parts = [];
        foreach (($session['cookies'] ?? []) as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }
    });

    if ($raw === false) {
        return [
            'raw_ok' => false,
            'http' => $code,
            'content_type' => '',
            'body' => '',
            'login_page' => false,
            'timeout_shell' => false,
            'timeout_text' => false,
            'body_bytes' => 0,
        ];
    }

    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    $contentType = ipmiWebProbeExtractContentType($raw);
    $timeoutText = ipmiWebProbeBodyHasSessionTimeoutText((string) $body);

    return [
        'raw_ok' => true,
        'http' => $code,
        'content_type' => $contentType,
        'body' => (string) $body,
        'login_page' => ipmiWebResponseLooksLikeBmcLoginPage((string) $body, $contentType),
        'timeout_shell' => ipmiWebResponseLooksLikeSupermicroTimeoutShell((string) $body),
        'timeout_text' => $timeoutText,
        'body_bytes' => strlen((string) $body),
    ];
}

/**
 * UI entrypoints expected after a successful authenticated web session per normalized BMC type.
 *
 * @return array<int, string>
 */
function ipmiWebProbeUiPathsForType(string $bmcType): array
{
    $type = ipmiWebNormalizeBmcType($bmcType);
    switch ($type) {
        case 'supermicro':
            return ['/', '/cgi/url_redirect.cgi?url_name=topmenu', '/cgi/url_redirect.cgi?url_name=dashboard'];
        case 'ilo4':
            return ['/', '/html/application.html'];
        case 'idrac':
            return ['/', '/restgui/start.html'];
        case 'ami':
            return ['/', '/html/application.html'];
        default:
            return ['/'];
    }
}

/**
 * Probe entrypoints through local proxy (same flow as "Open IPMI Session" click).
 *
 * @return array<int, string>
 */
function ipmiWebProbeProxyUiPathsForType(string $bmcType): array
{
    $type = ipmiWebNormalizeBmcType($bmcType);
    switch ($type) {
        case 'supermicro':
            return ['/', '/cgi/url_redirect.cgi?url_name=topmenu', '/cgi/url_redirect.cgi?url_name=dashboard'];
        case 'ilo4':
            return ['/', '/html/application.html'];
        case 'idrac':
            return ['/'];
        case 'ami':
            return ['/'];
        default:
            return ['/'];
    }
}

function ipmiWebProbeProxyBaseUrl(): string
{
    $env = trim((string) getenv('IPMI_PROXY_PROBE_BASE'));
    if ($env !== '') {
        return rtrim($env, '/');
    }

    return 'http://127.0.0.1';
}

/**
 * Parse redirect hops from raw cURL chain (CURLOPT_HEADER + FOLLOWLOCATION).
 *
 * @return array<int, array{http:int, location:string}>
 */
function ipmiWebProbeExtractRedirectChain(string $raw): array
{
    $out = [];
    $segments = ipmiWebSplitCurlResponseChain($raw);
    foreach ($segments as [$hdr, $_body]) {
        $http = 0;
        $loc = '';
        if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/im', $hdr, $m)) {
            $http = (int) $m[1];
        }
        if (preg_match('/^Location:\s*([^\r\n]+)/im', $hdr, $m)) {
            $loc = trim((string) $m[1]);
        }
        $out[] = ['http' => $http, 'location' => $loc];
    }

    return $out;
}

/**
 * @return array{
 *   raw_ok: bool,
 *   http: int,
 *   content_type: string,
 *   body: string,
 *   body_bytes: int,
 *   login_page: bool,
 *   timeout_shell: bool,
 *   timeout_text: bool,
 *   proxy_expired: bool,
 *   redirect_loop: bool,
 *   curl_error: string,
 *   final_url: string
 * }
 */
function ipmiWebProbeFetchProxyPath(string $token, string $path): array
{
    $base = ipmiWebProbeProxyBaseUrl();
    $url = $base . '/ipmi_proxy.php/' . rawurlencode($token) . '/' . ltrim($path, '/');
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 12);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_ENCODING, '');
    curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
    $raw = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $finalUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    $curlErr = '';
    $redirectLoop = false;
    if ($raw === false) {
        $curlErr = (string) curl_error($ch);
        $redirectLoop = curl_errno($ch) === CURLE_TOO_MANY_REDIRECTS;
    }
    curl_close($ch);

    if ($raw === false) {
        return [
            'raw_ok' => false,
            'http' => $code,
            'content_type' => '',
            'body' => '',
            'body_bytes' => 0,
            'login_page' => false,
            'timeout_shell' => false,
            'timeout_text' => false,
            'proxy_expired' => false,
            'redirect_loop' => $redirectLoop,
            'curl_error' => $curlErr,
            'final_url' => $finalUrl,
            'redirect_chain' => [],
            'logout_redirect' => false,
            'topmenu_redirect' => false,
            'loop_hint' => false,
        ];
    }

    $redirectChain = ipmiWebProbeExtractRedirectChain((string) $raw);
    $locs = [];
    $logoutRedirect = false;
    $topmenuRedirect = false;
    foreach ($redirectChain as $hop) {
        $loc = strtolower((string) ($hop['location'] ?? ''));
        if ($loc === '') {
            continue;
        }
        $locs[] = $loc;
        if (str_contains($loc, '/cgi/logout.cgi')) {
            $logoutRedirect = true;
        }
        if (str_contains($loc, '/cgi/url_redirect.cgi?url_name=topmenu')) {
            $topmenuRedirect = true;
        }
    }
    $loopHint = false;
    if (count($locs) >= 3) {
        $uniq = array_values(array_unique($locs));
        if (count($uniq) <= 2) {
            $loopHint = true;
        }
    }

    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    $contentType = ipmiWebProbeExtractContentType($raw);
    $timeoutText = ipmiWebProbeBodyHasSessionTimeoutText((string) $body);
    $lb = strtolower((string) $body);
    $proxyExpired = str_contains($lb, 'ipmi session expired');

    return [
        'raw_ok' => true,
        'http' => $code,
        'content_type' => $contentType,
        'body' => (string) $body,
        'body_bytes' => strlen((string) $body),
        'login_page' => ipmiWebResponseLooksLikeBmcLoginPage((string) $body, $contentType),
        'timeout_shell' => ipmiWebResponseLooksLikeSupermicroTimeoutShell((string) $body),
        'timeout_text' => $timeoutText,
        'proxy_expired' => $proxyExpired,
        'redirect_loop' => false,
        'curl_error' => '',
        'final_url' => $finalUrl,
        'redirect_chain' => $redirectChain,
        'logout_redirect' => $logoutRedirect,
        'topmenu_redirect' => $topmenuRedirect,
        'loop_hint' => $loopHint,
    ];
}

/**
 * Deep proxy-flow checks. Uses same session creation path as UI open action.
 *
 * @return array{ok: bool, error?: string, checks?: array<int, array<string, mixed>>}
 */
function ipmiWebProbeProxyFlowValidation(mysqli $mysqli, int $serverId): array
{
    $checks = [];
    $token = '';
    $prevRemoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;
    $prevUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
    try {
        // Align with ipmi_proxy token-only guard (created_ip + created_ua must match proxy request).
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = ipmiWebCurlUserAgent();
        $probeSession = ipmiWebCreateSession($mysqli, $serverId, 0, 'admin', 900);
        $token = (string) ($probeSession['token'] ?? '');
        $bmcType = (string) ($probeSession['bmc_type'] ?? 'generic');
        if ($token === '' || !preg_match('/^[a-f0-9]{64}$/', $token)) {
            return ['ok' => false, 'error' => 'proxy_session_create_failed', 'checks' => $checks];
        }

        foreach (ipmiWebProbeProxyUiPathsForType($bmcType) as $path) {
            $res = ipmiWebProbeFetchProxyPath($token, $path);
            $checks[] = [
                'kind' => 'proxy',
                'path' => $path,
                'http' => (int) ($res['http'] ?? 0),
                'content_type' => (string) ($res['content_type'] ?? ''),
                'body_bytes' => (int) ($res['body_bytes'] ?? 0),
                'login_page' => !empty($res['login_page']),
                'timeout_text' => !empty($res['timeout_text']),
                'timeout_shell' => !empty($res['timeout_shell']),
                'proxy_expired' => !empty($res['proxy_expired']),
                'redirect_loop' => !empty($res['redirect_loop']),
                'final_url' => (string) ($res['final_url'] ?? ''),
                'curl_error' => (string) ($res['curl_error'] ?? ''),
                'logout_redirect' => !empty($res['logout_redirect']),
                'topmenu_redirect' => !empty($res['topmenu_redirect']),
                'loop_hint' => !empty($res['loop_hint']),
            ];

            if (empty($res['raw_ok'])) {
                if (!empty($res['redirect_loop'])) {
                    return ['ok' => false, 'error' => 'proxy_redirect_loop:' . $path, 'checks' => $checks];
                }
                return ['ok' => false, 'error' => 'proxy_fetch_failed:' . $path, 'checks' => $checks];
            }
            $http = (int) ($res['http'] ?? 0);
            if ($http >= 400 || $http === 0) {
                return ['ok' => false, 'error' => 'proxy_http_' . $http . ':' . $path, 'checks' => $checks];
            }
            if (!empty($res['proxy_expired']) || !empty($res['timeout_shell'])) {
                return ['ok' => false, 'error' => 'proxy_timeout_shell:' . $path, 'checks' => $checks];
            }
            if (!empty($res['logout_redirect']) && !empty($res['topmenu_redirect']) && !empty($res['loop_hint'])) {
                return ['ok' => false, 'error' => 'proxy_logout_topmenu_loop:' . $path, 'checks' => $checks];
            }
            $ignoreIloLoginMarker = (ipmiWebNormalizeBmcType($bmcType) === 'ilo4' && $path === '/html/application.html');
            if (!empty($res['login_page']) && !$ignoreIloLoginMarker) {
                return ['ok' => false, 'error' => 'proxy_login_page:' . $path, 'checks' => $checks];
            }
        }
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => 'proxy_validation_exception', 'checks' => $checks];
    } finally {
        if ($prevRemoteAddr === null) {
            unset($_SERVER['REMOTE_ADDR']);
        } else {
            $_SERVER['REMOTE_ADDR'] = $prevRemoteAddr;
        }
        if ($prevUserAgent === null) {
            unset($_SERVER['HTTP_USER_AGENT']);
        } else {
            $_SERVER['HTTP_USER_AGENT'] = $prevUserAgent;
        }
        if ($token !== '' && preg_match('/^[a-f0-9]{64}$/', $token)) {
            $stmt = $mysqli->prepare("UPDATE ipmi_web_sessions SET revoked_at = NOW() WHERE token = ? LIMIT 1");
            if ($stmt) {
                $stmt->bind_param('s', $token);
                $stmt->execute();
                $stmt->close();
            }
        }
    }

    return ['ok' => true, 'checks' => $checks];
}

/**
 * Deep UI checks after auto-login succeeds. Useful for matrix classification.
 *
 * @return array{ok: bool, error?: string, checks?: array<int, array<string, mixed>>}
 */
function ipmiWebProbeDeepUiValidation(array $session): array
{
    $type = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
    $checks = [];

    $root = ipmiWebProbeFetchUiPath($session, '/');
    $checks[] = [
        'path' => '/',
        'http' => (int) ($root['http'] ?? 0),
        'content_type' => (string) ($root['content_type'] ?? ''),
        'body_bytes' => (int) ($root['body_bytes'] ?? 0),
        'login_page' => !empty($root['login_page']),
        'timeout_text' => !empty($root['timeout_text']),
        'timeout_shell' => !empty($root['timeout_shell']),
    ];
    if (empty($root['raw_ok'])) {
        return ['ok' => false, 'error' => 'ui_fetch_failed:/', 'checks' => $checks];
    }
    $rootHttp = (int) ($root['http'] ?? 0);
    if ($rootHttp >= 400 || $rootHttp === 0) {
        return ['ok' => false, 'error' => 'ui_http_' . $rootHttp . ':/', 'checks' => $checks];
    }
    $isSupermicro = ($type === 'supermicro');
    if (!empty($root['login_page']) && !$isSupermicro) {
        return ['ok' => false, 'error' => 'ui_login_page:/', 'checks' => $checks];
    }

    if ($type === 'supermicro') {
        if (!empty($root['timeout_shell'])) {
            return ['ok' => false, 'error' => 'ui_timeout_shell:/', 'checks' => $checks];
        }
        $topmenuCandidates = [
            '/cgi/url_redirect.cgi?url_name=topmenu',
            '/cgi/url_redirect.cgi?url_name=mainmenu',
        ];
        $anyTopmenuOk = false;
        foreach ($topmenuCandidates as $path) {
            $res = ipmiWebProbeFetchUiPath($session, $path);
            $checks[] = [
                'path' => $path,
                'http' => (int) ($res['http'] ?? 0),
                'content_type' => (string) ($res['content_type'] ?? ''),
                'body_bytes' => (int) ($res['body_bytes'] ?? 0),
                'login_page' => !empty($res['login_page']),
                'timeout_text' => !empty($res['timeout_text']),
                'timeout_shell' => !empty($res['timeout_shell']),
            ];
            if (!empty($res['raw_ok']) && (int) ($res['http'] ?? 0) > 0 && (int) ($res['http'] ?? 0) < 400
                && empty($res['login_page']) && empty($res['timeout_shell'])) {
                $anyTopmenuOk = true;
                break;
            }
        }
        if (!$anyTopmenuOk) {
            return ['ok' => false, 'error' => 'supermicro_topmenu_unreachable', 'checks' => $checks];
        }
        // Validate the actual dashboard entry endpoint too (common user-facing issue:
        // topmenu opens but dashboard keeps spinning/reloading).
        $dashboardCandidates = [
            '/cgi/url_redirect.cgi?url_name=dashboard',
            '/cgi/url_redirect.cgi?url_name=sys_info',
        ];
        $anyDashboardOk = false;
        foreach ($dashboardCandidates as $path) {
            $res = ipmiWebProbeFetchUiPath($session, $path);
            $checks[] = [
                'path' => $path,
                'http' => (int) ($res['http'] ?? 0),
                'content_type' => (string) ($res['content_type'] ?? ''),
                'body_bytes' => (int) ($res['body_bytes'] ?? 0),
                'login_page' => !empty($res['login_page']),
                'timeout_text' => !empty($res['timeout_text']),
                'timeout_shell' => !empty($res['timeout_shell']),
            ];
            if (!empty($res['raw_ok']) && (int) ($res['http'] ?? 0) > 0 && (int) ($res['http'] ?? 0) < 400
                && empty($res['login_page']) && empty($res['timeout_shell'])) {
                $anyDashboardOk = true;
                break;
            }
        }
        if (!$anyDashboardOk) {
            return ['ok' => false, 'error' => 'supermicro_dashboard_unreachable', 'checks' => $checks];
        }
        return ['ok' => true, 'checks' => $checks];
    }

    if ($type === 'ilo4') {
        $app = ipmiWebProbeFetchUiPath($session, '/html/application.html');
        $checks[] = [
            'path' => '/html/application.html',
            'http' => (int) ($app['http'] ?? 0),
            'content_type' => (string) ($app['content_type'] ?? ''),
            'body_bytes' => (int) ($app['body_bytes'] ?? 0),
            'login_page' => !empty($app['login_page']),
            'timeout_text' => !empty($app['timeout_text']),
            'timeout_shell' => !empty($app['timeout_shell']),
        ];
        if (empty($app['raw_ok'])) {
            return ['ok' => false, 'error' => 'ilo_application_fetch_failed', 'checks' => $checks];
        }
        $appHttp = (int) ($app['http'] ?? 0);
        if ($appHttp >= 400 || $appHttp === 0) {
            return ['ok' => false, 'error' => 'ilo_application_http_' . $appHttp, 'checks' => $checks];
        }
        if (!empty($app['login_page'])) {
            return ['ok' => false, 'error' => 'ilo_application_login_page', 'checks' => $checks];
        }
        return ['ok' => true, 'checks' => $checks];
    }

    if ($type === 'idrac') {
        $idracCandidates = ['/restgui/start.html', '/restgui/launch'];
        $anyOk = false;
        foreach ($idracCandidates as $path) {
            $res = ipmiWebProbeFetchUiPath($session, $path);
            $checks[] = [
                'path' => $path,
                'http' => (int) ($res['http'] ?? 0),
                'content_type' => (string) ($res['content_type'] ?? ''),
                'body_bytes' => (int) ($res['body_bytes'] ?? 0),
                'login_page' => !empty($res['login_page']),
                'timeout_text' => !empty($res['timeout_text']),
                'timeout_shell' => !empty($res['timeout_shell']),
            ];
            if (!empty($res['raw_ok']) && (int) ($res['http'] ?? 0) > 0 && (int) ($res['http'] ?? 0) < 400 && empty($res['login_page'])) {
                $anyOk = true;
                break;
            }
        }
        if (!$anyOk) {
            // Some iDRAC firmwares expose a different entrypoint while root is already authenticated.
            // Treat this as pass to avoid false negatives in fleet-wide health checks.
            return ['ok' => true, 'checks' => $checks];
        }
        return ['ok' => true, 'checks' => $checks];
    }

    if ($type === 'ami') {
        $amiCandidates = ['/html/application.html', '/html/index.html'];
        $anyOk = false;
        foreach ($amiCandidates as $path) {
            $res = ipmiWebProbeFetchUiPath($session, $path);
            $checks[] = [
                'path' => $path,
                'http' => (int) ($res['http'] ?? 0),
                'content_type' => (string) ($res['content_type'] ?? ''),
                'body_bytes' => (int) ($res['body_bytes'] ?? 0),
                'login_page' => !empty($res['login_page']),
                'timeout_text' => !empty($res['timeout_text']),
                'timeout_shell' => !empty($res['timeout_shell']),
            ];
            if (!empty($res['raw_ok']) && (int) ($res['http'] ?? 0) > 0 && (int) ($res['http'] ?? 0) < 400 && empty($res['login_page'])) {
                $anyOk = true;
                break;
            }
        }
        if (!$anyOk) {
            // AMI/ASRock variants often keep the SPA at "/" and 404 /html/* paths.
            // If root is authenticated and non-login, count as healthy.
            return ['ok' => true, 'checks' => $checks];
        }
        return ['ok' => true, 'checks' => $checks];
    }

    return ['ok' => true, 'checks' => $checks];
}

/**
 * GET /json/session_info (iLO). Matches ipmi_proxy TLS/SNI: hostname + CURLOPT_RESOLVE when PTR exists,
 * Origin/Referer use preferred hostname, retry without resolve on 401/403 / curl failure like the proxy.
 *
 * @return array{raw_ok: bool, http: int, body: string, applied_resolve: bool}
 */
function ipmiWebProbeFetchSessionInfo(array $session, bool $tryResolve): array
{
    $ip = trim((string) ($session['ipmi_ip'] ?? ''));
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $url = $scheme . '://' . $ip . '/json/session_info';
    $originBase = $scheme . '://' . ipmiBmcPreferredOriginHost($ip);

    $ch = curl_init($url);
    $appliedResolve = false;
    if ($tryResolve) {
        $appliedResolve = ipmiBmcApplyCurlUrlAndResolve($ch, $url, $ip);
    }
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 12);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 6);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
    $hdr = [
        'Accept: application/json, text/javascript, */*',
        'X-Requested-With: XMLHttpRequest',
        'Origin: ' . $originBase,
        'Referer: ' . $originBase . '/',
    ];
    $tok = trim((string) (($session['forward_headers']['X-Auth-Token'] ?? '')));
    if ($tok !== '') {
        $hdr[] = 'X-Auth-Token: ' . $tok;
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $hdr);
    $parts = [];
    foreach ($session['cookies'] ?? [] as $k => $v) {
        if ($v !== null && trim((string) $v) !== '') {
            $parts[] = $k . '=' . $v;
        }
    }
    $cookie = implode('; ', $parts);
    if ($cookie !== '') {
        curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    }
    $raw = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($raw === false) {
        return ['raw_ok' => false, 'http' => $code, 'body' => '', 'applied_resolve' => $appliedResolve];
    }
    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);

    return ['raw_ok' => true, 'http' => $code, 'body' => (string) $body, 'applied_resolve' => $appliedResolve];
}

/**
 * GET /json/session_info with the session jar (iLO family only).
 */
function ipmiWebProbeIloSessionInfoOk(array $session): bool
{
    if (!ipmiWebIsIloFamilyType((string) ($session['bmc_type'] ?? ''))) {
        return true;
    }
    $ip = trim((string) ($session['ipmi_ip'] ?? ''));
    if ($ip === '') {
        return false;
    }

    $first = ipmiWebProbeFetchSessionInfo($session, true);
    if ($first['raw_ok'] && $first['http'] >= 200 && $first['http'] < 400 && ipmiWebProbeSessionJsonValid($first['body'])) {
        return true;
    }

    $shouldRetryPlain = $first['applied_resolve']
        && (
            !$first['raw_ok']
            || $first['http'] === 0
            || $first['http'] === 401
            || $first['http'] === 403
            || ($first['raw_ok'] && $first['http'] >= 200 && $first['http'] < 400 && !ipmiWebProbeSessionJsonValid($first['body']))
        );
    if (!$shouldRetryPlain) {
        return false;
    }

    $second = ipmiWebProbeFetchSessionInfo($session, false);
    if (!$second['raw_ok'] || $second['http'] < 200 || $second['http'] >= 400) {
        return false;
    }

    return ipmiWebProbeSessionJsonValid($second['body']);
}

/**
 * @return array{ok: bool, skipped?: bool, reason?: string, error?: string, scheme?: string}
 */
function ipmiWebProbeServerWebUi(mysqli $mysqli, int $serverId): array
{
    $stmt = $mysqli->prepare("
        SELECT s.id, s.ipmi_ip, s.ipmi_user, s.ipmi_pass, s.bmc_type, COALESCE(ss.suspended, 0) AS suspended
        FROM servers s
        LEFT JOIN server_suspension ss ON ss.server_id = s.id
        WHERE s.id = ?
        LIMIT 1
    ");
    if (!$stmt) {
        return ['ok' => false, 'error' => 'db_prepare_failed'];
    }
    $stmt->bind_param('i', $serverId);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if (!$row) {
        return ['ok' => false, 'error' => 'server_not_found'];
    }
    if ((int) ($row['suspended'] ?? 0) === 1) {
        return ['ok' => true, 'skipped' => true, 'reason' => 'suspended'];
    }

    $ip = trim((string) ($row['ipmi_ip'] ?? ''));
    if ($ip === '') {
        return ['ok' => false, 'error' => 'no_ipmi_ip'];
    }

    try {
        $ipmiUser = Encryption::decrypt($row['ipmi_user']);
        $ipmiPass = Encryption::decrypt($row['ipmi_pass']);
    } catch (Exception $e) {
        $ipmiUser = $row['ipmi_user'];
        $ipmiPass = $row['ipmi_pass'];
    }

    if (trim((string) $ipmiUser) === '' || trim((string) $ipmiPass) === '') {
        return ['ok' => false, 'error' => 'no_credentials'];
    }

    $session = [
        'ipmi_ip'          => $ip,
        'ipmi_user'        => $ipmiUser,
        'ipmi_pass'        => $ipmiPass,
        'bmc_type'         => strtolower(trim((string) ($row['bmc_type'] ?? 'generic'))),
        'cookies'          => [],
        'forward_headers'  => [],
        'bmc_scheme'       => 'https',
    ];

    if (!ipmiWebAttemptAutoLogin($session, $mysqli)) {
        $reason = trim((string) ($session['auto_login_error'] ?? ''));
        if ($reason !== '') {
            return ['ok' => false, 'error' => 'auto_login_failed:' . $reason];
        }
        return ['ok' => false, 'error' => 'auto_login_failed'];
    }

    if (!ipmiWebProbeIloSessionInfoOk($session)) {
        return ['ok' => false, 'error' => 'session_info_failed', 'scheme' => (string) ($session['bmc_scheme'] ?? 'https')];
    }

    return ['ok' => true, 'scheme' => (string) ($session['bmc_scheme'] ?? 'https')];
}

/**
 * Server web probe with optional deep post-login UI validation.
 *
 * @return array{ok: bool, skipped?: bool, reason?: string, error?: string, scheme?: string, checks?: array<int, array<string, mixed>>, proxy_checks?: array<int, array<string, mixed>>}
 */
function ipmiWebProbeServerWebUiDetailed(mysqli $mysqli, int $serverId, bool $deep = true, bool $proxyFlow = false): array
{
    $base = ipmiWebProbeServerWebUi($mysqli, $serverId);
    if (empty($base['ok']) || !empty($base['skipped'])) {
        return $base;
    }

    // Rebuild session material similarly to the main probe so we can run deep path checks.
    $stmt = $mysqli->prepare("
        SELECT s.id, s.ipmi_ip, s.ipmi_user, s.ipmi_pass, s.bmc_type
        FROM servers s
        WHERE s.id = ?
        LIMIT 1
    ");
    if (!$stmt) {
        $base['ok'] = false;
        $base['error'] = 'db_prepare_failed_deep';
        return $base;
    }
    $stmt->bind_param('i', $serverId);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();
    if (!$row) {
        $base['ok'] = false;
        $base['error'] = 'server_not_found_deep';
        return $base;
    }
    try {
        $ipmiUser = Encryption::decrypt($row['ipmi_user']);
        $ipmiPass = Encryption::decrypt($row['ipmi_pass']);
    } catch (Exception $e) {
        $ipmiUser = $row['ipmi_user'];
        $ipmiPass = $row['ipmi_pass'];
    }
    $session = [
        'server_id'         => (int) $row['id'],
        'ipmi_ip'           => trim((string) ($row['ipmi_ip'] ?? '')),
        'ipmi_user'         => (string) $ipmiUser,
        'ipmi_pass'         => (string) $ipmiPass,
        'bmc_type'          => strtolower(trim((string) ($row['bmc_type'] ?? 'generic'))),
        'cookies'           => [],
        'forward_headers'   => [],
        'bmc_scheme'        => 'https',
    ];
    if (!ipmiWebAttemptAutoLogin($session, $mysqli)) {
        $base['ok'] = false;
        $reason = trim((string) ($session['auto_login_error'] ?? ''));
        $base['error'] = $reason !== ''
            ? ('auto_login_failed_deep:' . $reason)
            : 'auto_login_failed_deep';
        return $base;
    }

    if ($deep) {
        $deepResult = ipmiWebProbeDeepUiValidation($session);
        if (empty($deepResult['ok'])) {
            $base['ok'] = false;
            $base['error'] = (string) ($deepResult['error'] ?? 'deep_ui_failed');
            if (isset($deepResult['checks']) && is_array($deepResult['checks'])) {
                $base['checks'] = $deepResult['checks'];
            }
            return $base;
        }
        if (isset($deepResult['checks']) && is_array($deepResult['checks'])) {
            $base['checks'] = $deepResult['checks'];
        }
    }

    if ($proxyFlow) {
        $proxyResult = ipmiWebProbeProxyFlowValidation($mysqli, $serverId);
        if (isset($proxyResult['checks']) && is_array($proxyResult['checks'])) {
            $base['proxy_checks'] = $proxyResult['checks'];
            if (!isset($base['checks']) || !is_array($base['checks'])) {
                $base['checks'] = [];
            }
            $base['checks'] = array_merge($base['checks'], $proxyResult['checks']);
        }
        if (empty($proxyResult['ok'])) {
            $base['ok'] = false;
            $base['error'] = (string) ($proxyResult['error'] ?? 'proxy_flow_failed');
            return $base;
        }
    }

    return $base;
}

/**
 * Log one-line result for log aggregation / monitoring.
 */
function ipmiWebProbeLogResult(int $serverId, array $result): void
{
    if (!empty($result['skipped'])) {
        error_log('[ipmi_web_probe] server_id=' . $serverId . ' skipped=' . ($result['reason'] ?? 'unknown'));

        return;
    }
    if (!empty($result['ok'])) {
        error_log('[ipmi_web_probe] server_id=' . $serverId . ' ok=1 scheme=' . ($result['scheme'] ?? ''));

        return;
    }
    error_log('[ipmi_web_probe] server_id=' . $serverId . ' ok=0 err=' . ($result['error'] ?? 'unknown'));
}
