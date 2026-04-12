<?php
/**
 * IPMI Web Session management — creation, loading, auto-login,
 * HTML rewriting helpers, and vendor-specific KVM console routing.
 *
 * DB table: ipmi_web_sessions
 *   id, token, user_id, server_id, ipmi_ip, ipmi_user, ipmi_pass,
 *   bmc_type, bmc_cookies (JSON: flat cookie map, or {"_c":{...},"_h":{...},"_s":"http","_m":{...}}),
 *   _m holds small opaque session metadata (KVM plan cache, iLO preflight TTL, iLO SPA bootstrap state) — not secrets.
 *   _m.ilo_bootstrap (v1): phase, rolling event window, SSE health, refresh_ts budget, shell_ts (last successful shell_entry),
 *   window.roles_ok (distinct critical roles that succeeded in the short window), and observed.paths — bounded per-session
 *   hints (hit counts, promotion flags, ~600s TTL) for firmware-specific helper routes; no secrets.
 *   ilo_console_capability (v1, TTL ~280s): classified native HTML5 vs legacy/shell-only evidence from path probes + /index.html shell sample.
 *   ilo_ui_blockers: masthead_fragment_ok from preflight (auth vs SPA assembly).
 *   ilo_native_launch_failures: bounded client/server launch failure reasons (no secrets).
 *   created_ip, user_agent,
 *   created_at, expires_at, last_access_at, revoked_at
 */

require_once __DIR__ . '/encryption.php';
require_once __DIR__ . '/ipmi_bmc_curl.php';

/** Browser-like UA so BMCs (iLO, iDRAC) do not reject PHP-curl defaults. */
function ipmiWebCurlUserAgent(): string
{
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
}

/**
 * Origin/Referer base for BMC requests: when connecting to https://&lt;IP&gt;/… use the certificate hostname (PTR) like the proxy does.
 */
function ipmiWebBmcOriginBaseFromConnectUrl(string $connectBaseUrl, string $bmcIp): string
{
    $p = parse_url($connectBaseUrl);
    $scheme = strtolower((string) ($p['scheme'] ?? 'https'));
    $host = (string) ($p['host'] ?? '');
    if ($host !== '' && filter_var($host, FILTER_VALIDATE_IP)) {
        return $scheme . '://' . ipmiBmcPreferredOriginHost($bmcIp);
    }

    return rtrim($connectBaseUrl, '/');
}

/**
 * cURL to BMC with optional hostname+CURLOPT_RESOLVE; retry once without resolve on transport failure / 403 (parity with ipmi_proxy.php).
 *
 * @param callable(\CurlHandle|resource): void $configure
 * @return array{0: mixed, 1: int} raw response (false on failure) and HTTP status
 */
function ipmiWebCurlExecBmc(string $bmcIp, string $url, callable $configure): array
{
    $run = static function (bool $useResolve) use ($bmcIp, $url, $configure): array {
        $ch = curl_init($url);
        $applied = false;
        if ($useResolve) {
            $applied = ipmiBmcApplyCurlUrlAndResolve($ch, $url, $bmcIp);
        }
        // BMC web UIs often gzip HTML/JS. We must decode for reliable login-page fingerprinting.
        curl_setopt($ch, CURLOPT_ENCODING, '');
        $configure($ch);
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return [$raw, $code, $applied];
    };

    [$raw, $code, $applied] = $run(true);
    if (($raw === false || $code === 0 || $code === 403) && $applied) {
        [$raw, $code] = $run(false);

        return [$raw, $code];
    }

    return [$raw, $code];
}

/**
 * Strip risky keys from session metadata before JSON persistence (defense in depth).
 *
 * @param array<string, mixed> $meta
 * @return array<string, mixed>
 */
function ipmiWebSanitizeSessionMetaForStorage(array $meta): array
{
    $out = [];
    foreach ($meta as $k => $v) {
        if (!is_string($k) || $k === '' || str_starts_with($k, '_')) {
            continue;
        }
        if (in_array(strtolower($k), ['password', 'ipmi_pass', 'token', 'csrf'], true)) {
            continue;
        }
        $out[$k] = $v;
    }

    return $out;
}

/**
 * Persist cookie jar + optional BMC auth headers (e.g. Redfish X-Auth-Token) in bmc_cookies JSON.
 * Legacy rows are a flat object of name => value cookies only.
 * Optional _m holds cross-request metadata (KVM plan cache, iLO preflight, ilo_bootstrap lifecycle) — small TTL-bounded blobs only.
 *
 * @param array<string, mixed> $sessionMeta
 */
function ipmiWebPackStoredAuth(array $cookies, array $forwardHeaders, string $bmcScheme = 'https', array $sessionMeta = []): string
{
    $forwardHeaders = array_filter($forwardHeaders, static function ($v) {
        return $v !== null && $v !== '';
    });
    $bmcScheme = ($bmcScheme === 'http') ? 'http' : 'https';
    $sessionMeta = ipmiWebSanitizeSessionMetaForStorage($sessionMeta);
    $needsWrapper = $forwardHeaders !== [] || $bmcScheme === 'http' || $sessionMeta !== [];
    if (!$needsWrapper) {
        return json_encode($cookies, JSON_UNESCAPED_SLASHES);
    }

    $payload = ['_c' => $cookies, '_h' => $forwardHeaders];
    if ($bmcScheme === 'http') {
        $payload['_s'] = 'http';
    }
    if ($sessionMeta !== []) {
        $payload['_m'] = $sessionMeta;
    }

    return json_encode($payload, JSON_UNESCAPED_SLASHES);
}

/**
 * @return array{0: array<string, string>, 1: array<string, string>, 2: string, 3: array<string, mixed>}
 */
function ipmiWebUnpackStoredAuth(string $raw): array
{
    $d = json_decode($raw, true);
    if (!is_array($d)) {
        return [[], [], 'https', []];
    }
    $meta = [];
    if (isset($d['_m']) && is_array($d['_m'])) {
        $meta = $d['_m'];
    }
    if (isset($d['_c']) && is_array($d['_c'])) {
        $h = $d['_h'] ?? [];
        $s = (isset($d['_s']) && $d['_s'] === 'http') ? 'http' : 'https';

        return [$d['_c'], is_array($h) ? $h : [], $s, $meta];
    }

    return [$d, [], 'https', $meta];
}

/**
 * Read current bmc_cookies JSON, let $mutator edit session meta only, write back preserving cookies/headers.
 *
 * @param callable(array<string, mixed>): void $mutator
 */
function ipmiWebSessionMetaMutate(mysqli $mysqli, string $token, callable $mutator): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $stmt = $mysqli->prepare('SELECT bmc_cookies FROM ipmi_web_sessions WHERE token = ? LIMIT 1');
    if (!$stmt) {
        return;
    }
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();
    $raw = trim((string) ($row['bmc_cookies'] ?? ''));
    [$cookies, $fwd, $scheme, $meta] = $raw !== '' ? ipmiWebUnpackStoredAuth($raw) : [[], [], 'https', []];
    if (!is_array($meta)) {
        $meta = [];
    }
    $mutator($meta);
    $meta = ipmiWebSanitizeSessionMetaForStorage($meta);
    $json = ipmiWebPackStoredAuth($cookies, $fwd, $scheme, $meta);
    $upd = $mysqli->prepare('UPDATE ipmi_web_sessions SET bmc_cookies = ? WHERE token = ? LIMIT 1');
    if ($upd) {
        $upd->bind_param('ss', $json, $token);
        $upd->execute();
        $upd->close();
    }
}

/**
 * @return array{kvm_plan?: array<string, mixed>, ilo_preflight?: array<string, mixed>, ilo_bootstrap?: array<string, mixed>}|array<string, mixed>
 */
function ipmiWebLoadSessionMetaFromRow(string $rawCookies): array
{
    $raw = trim($rawCookies);
    if ($raw === '') {
        return [];
    }
    [, , , $meta] = ipmiWebUnpackStoredAuth($raw);

    return is_array($meta) ? $meta : [];
}

/**
 * Cheap bootstrap viability view from session metadata only (no BMC I/O).
 * Live probes and auth refresh live in ipmi_proxy.php (ipmiProxyMaybeIloRuntimePreflight).
 *
 * @param array<string, mixed> $sessionMeta
 * @return array{phase: string, preflight_age_sec: int|null, preflight_bootstrap_ok: bool|null}
 */
function ipmiWebIloBootstrapViabilityPreflightSummary(array $sessionMeta): array
{
    $now = time();
    $pf = $sessionMeta['ilo_preflight'] ?? null;
    $age = (is_array($pf) && isset($pf['t'])) ? $now - (int) $pf['t'] : null;
    $bs = $sessionMeta['ilo_bootstrap'] ?? null;
    $phase = (is_array($bs) && (int) ($bs['v'] ?? 0) === 1)
        ? (string) ($bs['phase'] ?? 'fresh')
        : 'fresh';

    return [
        'phase'                  => $phase,
        'preflight_age_sec'     => $age,
        'preflight_bootstrap_ok' => is_array($pf) ? (isset($pf['bootstrap_ok']) ? (bool) $pf['bootstrap_ok'] : null) : null,
    ];
}

/**
 * @param array<string, mixed> $sessionMeta
 * @return array{phase: string, preflight_age_sec: int|null, preflight_bootstrap_ok: bool|null}
 */
function ipmiWebIloBootstrapViabilityPreflight(array $sessionMeta): array
{
    return ipmiWebIloBootstrapViabilityPreflightSummary($sessionMeta);
}

/**
 * Split raw cURL output (HEADER + CURLOPT_FOLLOWLOCATION chain) into per-response segments.
 * A middle hop may include a non-empty body (e.g. 302 + HTML); we must not stop before later hops.
 *
 * @return list<array{0: string, 1: string}> [headers, body] per HTTP message in order
 */
function ipmiWebSplitCurlResponseChain(string $raw): array
{
    $raw = (string) $raw;
    if ($raw === '') {
        return [];
    }

    $chunks = preg_split('/\r\n(?=HTTP\/\d)/', $raw);
    if ($chunks === false || count($chunks) <= 1) {
        $chunks2 = preg_split('/\n(?=HTTP\/\d)/', $raw);
        if (is_array($chunks2) && count($chunks2) > 1) {
            $chunks = $chunks2;
        }
    }
    if (!is_array($chunks) || $chunks === []) {
        return [];
    }

    $segments = [];
    foreach ($chunks as $chunk) {
        $chunk = ltrim($chunk, "\r\n");
        if ($chunk === '' || !preg_match('/^HTTP\/\d/i', $chunk)) {
            continue;
        }
        $hs = strpos($chunk, "\r\n\r\n");
        $sepLen = 4;
        if ($hs === false) {
            $hs = strpos($chunk, "\n\n");
            $sepLen = 2;
        }
        if ($hs === false) {
            continue;
        }
        $hdr = substr($chunk, 0, $hs);
        $body = substr($chunk, $hs + $sepLen);
        $segments[] = [$hdr, $body];
    }

    return $segments;
}

/**
 * With CURLOPT_HEADER + CURLOPT_FOLLOWLOCATION, PHP cURL concatenates each redirect hop.
 * Prefer the last response in the chain (cookies / JSON session data often appear on the final hop).
 *
 * @return array{0: string, 1: string} Final header block (no trailing blank line), response body
 */
function ipmiWebCurlExtractFinalHeadersAndBody(string $raw): array
{
    $segments = ipmiWebSplitCurlResponseChain($raw);
    if ($segments !== []) {
        $last = $segments[count($segments) - 1];

        return [$last[0], $last[1]];
    }

    $work = (string) $raw;
    $hs = strpos($work, "\r\n\r\n");
    if ($hs === false) {
        return ['', $work];
    }
    $hdr = substr($work, 0, $hs);
    $rest = substr($work, $hs + 4);
    if (str_starts_with($rest, 'HTTP/')) {
        return ipmiWebCurlExtractFinalHeadersAndBody($rest);
    }

    return [$hdr, $rest];
}

/**
 * Merge Set-Cookie name=value pairs from every hop in a followed redirect chain.
 */
function ipmiWebCurlMergeSetCookiesFromChain(string $raw, array $existing): array
{
    $jar = $existing;
    $segments = ipmiWebSplitCurlResponseChain($raw);
    if ($segments === []) {
        $work = (string) $raw;
        while (true) {
            $hs = strpos($work, "\r\n\r\n");
            if ($hs === false) {
                break;
            }
            $hdr = substr($work, 0, $hs);
            $rest = substr($work, $hs + 4);
            if (preg_match_all('/^Set-Cookie:\s*([^;\r\n]+)/mi', $hdr, $matches)) {
                foreach ($matches[1] as $c) {
                    $eqPos = strpos($c, '=');
                    if ($eqPos !== false) {
                        $ck = trim(substr($c, 0, $eqPos));
                        $cv = trim(substr($c, $eqPos + 1));
                        if ($ck !== '' && strtolower($cv) !== 'deleted' && trim($cv) !== '') {
                            $jar[$ck] = $cv;
                        }
                    }
                }
            }
            if (str_starts_with($rest, 'HTTP/')) {
                $work = $rest;
                continue;
            }
            break;
        }

        return $jar;
    }

    foreach ($segments as [$hdr, $_body]) {
        if (preg_match_all('/^Set-Cookie:\s*([^;\r\n]+)/mi', $hdr, $matches)) {
            foreach ($matches[1] as $c) {
                $eqPos = strpos($c, '=');
                if ($eqPos !== false) {
                    $ck = trim(substr($c, 0, $eqPos));
                    $cv = trim(substr($c, $eqPos + 1));
                    if ($ck !== '' && strtolower($cv) !== 'deleted' && trim($cv) !== '') {
                        $jar[$ck] = $cv;
                    }
                }
            }
        }
    }

    return $jar;
}

function ipmiWebMergeAuthFromHeaderBlock(string $hdr, array &$cookieJar, array &$forwardHeaders): void
{
    if (preg_match_all('/^Set-Cookie:\s*([^;\r\n]+)/mi', $hdr, $matches)) {
        foreach ($matches[1] as $c) {
            $eqPos = strpos($c, '=');
            if ($eqPos !== false) {
                $ck = trim(substr($c, 0, $eqPos));
                $cv = trim(substr($c, $eqPos + 1));
                if ($ck !== '' && strtolower($cv) !== 'deleted' && trim($cv) !== '') {
                    $cookieJar[$ck] = $cv;
                }
            }
        }
    }

    foreach ((preg_split('/\r\n/', $hdr) ?: []) as $line) {
        if (stripos($line, 'X-Auth-Token:') === 0) {
            $tok = trim(substr($line, strlen('X-Auth-Token:')));
            if ($tok !== '') {
                $forwardHeaders['X-Auth-Token'] = $tok;
            }
        }
        if (stripos($line, 'X-Auth-Token :') === 0) {
            $tok = trim(substr($line, strlen('X-Auth-Token :')));
            if ($tok !== '') {
                $forwardHeaders['X-Auth-Token'] = $tok;
            }
        }
    }

    if (preg_match('/^Location:\s*([^\r\n]+)/mi', $hdr, $lm)) {
        $loc = trim($lm[1]);
        if (preg_match('~/Sessions/([^/?\s#]+)~i', $loc, $sid)) {
            $forwardHeaders['X-Auth-Token'] = rawurldecode($sid[1]);
        }
    }
}

/**
 * iLO 4 classic UI calls /json/session_info with both cookies; session alone returns JS_ERR_LOST_SESSION.
 */
function ipmiWebSyncIloSessionAndSessionKeyCookies(array &$cookies): void
{
    $s = trim((string)($cookies['session'] ?? ''));
    $k = trim((string)($cookies['sessionKey'] ?? ''));
    if ($s !== '' && $k === '') {
        $cookies['sessionKey'] = $s;
    } elseif ($k !== '' && $s === '') {
        $cookies['session'] = $k;
    }
}

function ipmiWebIsIloFamilyType(string $bmcType): bool
{
    return ipmiWebBmcFamily($bmcType) === 'ilo';
}

function ipmiWebApplyJsonAuthHints(array $json, array &$cookieJar, array &$forwardHeaders, int $depth = 0): void
{
    if ($depth > 6) {
        return;
    }
    // iLO JSON-RPC wraps session fields under "output" (e.g. output.session_key).
    if (isset($json['output']) && is_array($json['output'])) {
        ipmiWebApplyJsonAuthHints($json['output'], $cookieJar, $forwardHeaders, $depth + 1);
    }

    // AMI/ASRock API login returns CSRFToken in JSON and expects it on subsequent API calls.
    foreach (['CSRFToken', 'csrfToken', 'csrf_token', 'csrf'] as $k) {
        if (!empty($json[$k]) && is_string($json[$k])) {
            $v = trim((string) $json[$k]);
            if ($v !== '') {
                $forwardHeaders['X-CSRFTOKEN'] = $v;
                // Frontend JS reads garc cookie and pushes it into X-CSRFTOKEN for AJAX.
                $cookieJar['garc'] = $v;
                // Mirror the login flow cookies the AMI SPA sets on success.
                if (!isset($cookieJar['refresh_disable'])) {
                    $cookieJar['refresh_disable'] = '1';
                }
            }
            break;
        }
    }

    // AMI SPA also stores TFA-related flags as cookies after login success.
    foreach (['TFAStatus', 'tfaStatus', 'tfa_status'] as $k) {
        if (isset($json[$k]) && $json[$k] !== null) {
            $cookieJar['TFAStatus'] = (string) $json[$k];
            break;
        }
    }
    foreach (['TFAEnabled', 'tfaEnabled', 'tfa_enabled'] as $k) {
        if (isset($json[$k]) && $json[$k] !== null) {
            $cookieJar['TFAEnabled'] = (string) $json[$k];
            break;
        }
    }

    // iDRAC /data/login JSON (session id for REST; cookies may also be Set-Cookie on same hop).
    if (!empty($json['authToken']) && is_string($json['authToken'])) {
        $v = trim((string) $json['authToken']);
        if ($v !== '') {
            $forwardHeaders['X-Auth-Token'] = $v;

            return;
        }
    }

    foreach (['session_key', 'sessionKey', 'SessionKey', 'auth_key', 'authKey'] as $k) {
        if (!empty($json[$k]) && is_string($json[$k])) {
            $v = trim((string)$json[$k]);
            if ($v !== '') {
                $cookieJar['session'] = $v;
                $cookieJar['sessionKey'] = $v;

                return;
            }
        }
    }

    if (isset($json['Oem']['Hpe']['SessionKey']) && is_string($json['Oem']['Hpe']['SessionKey'])) {
        $v = trim((string)$json['Oem']['Hpe']['SessionKey']);
        if ($v !== '') {
            $forwardHeaders['X-Auth-Token'] = $v;

            return;
        }
    }
    if (!empty($json['Oem']['Hpe']['SessionToken']) && is_string($json['Oem']['Hpe']['SessionToken'])) {
        $v = trim((string)$json['Oem']['Hpe']['SessionToken']);
        if ($v !== '') {
            $forwardHeaders['X-Auth-Token'] = $v;

            return;
        }
    }

    foreach (['Token', 'SessionToken', 'token', 'session_token', 'sessionId', 'SessionId'] as $k) {
        if (!empty($json[$k]) && is_string($json[$k])) {
            $v = trim((string)$json[$k]);
            if ($v !== '') {
                $forwardHeaders['X-Auth-Token'] = $v;

                return;
            }
        }
    }

    $odataType = isset($json['@odata.type']) ? (string)$json['@odata.type'] : '';
    if ($odataType !== '' && stripos($odataType, 'Session') !== false && !empty($json['Id']) && is_string($json['Id'])) {
        $v = trim((string)$json['Id']);
        if ($v !== '' && ($forwardHeaders['X-Auth-Token'] ?? '') === '') {
            $forwardHeaders['X-Auth-Token'] = $v;
        }
    }
}

function ipmiWebCollectAuthFromLoginResponse(string $raw, array &$cookieJar, array &$forwardHeaders): void
{
    $segments = ipmiWebSplitCurlResponseChain($raw);
    if ($segments === []) {
        // Non-standard output: merge at least the first hop and parse JSON if present.
        $work = (string) $raw;
        while (true) {
            $hs = strpos($work, "\r\n\r\n");
            if ($hs === false) {
                break;
            }
            $hdr = substr($work, 0, $hs);
            $rest = substr($work, $hs + 4);
            ipmiWebMergeAuthFromHeaderBlock($hdr, $cookieJar, $forwardHeaders);
            if (str_starts_with($rest, 'HTTP/')) {
                $work = $rest;
                continue;
            }
            $trim = ltrim($rest);
            if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[')) {
                $j = json_decode($rest, true);
                if (is_array($j)) {
                    ipmiWebApplyJsonAuthHints($j, $cookieJar, $forwardHeaders);
                }
            }
            break;
        }

        return;
    }

    foreach ($segments as [$hdr, $_body]) {
        ipmiWebMergeAuthFromHeaderBlock($hdr, $cookieJar, $forwardHeaders);
    }

    $finalBody = $segments[count($segments) - 1][1];
    $trim = ltrim($finalBody);
    if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[')) {
        $j = json_decode($finalBody, true);
        if (!is_array($j)) {
            $j = json_decode(trim((string) preg_replace('/^[^{[]+/', '', $finalBody)), true);
        }
        if (is_array($j)) {
            ipmiWebApplyJsonAuthHints($j, $cookieJar, $forwardHeaders);
        }
    }
}

/**
 * True if the cookie jar or forwarded headers contain a non-empty BMC auth value.
 * Empty keys (e.g. session=) must not count as logged in.
 */
function ipmiWebIsAuthValueUsable($v): bool
{
    if ($v === null) {
        return false;
    }
    $s = trim((string) $v);
    if ($s === '') {
        return false;
    }
    $ls = strtolower($s);
    return !in_array($ls, ['0', 'null', 'undefined', 'none'], true);
}

/**
 * Lightweight debug logger that only emits when ipmi_proxy debug is enabled.
 * Safe to call from any context (no-op if debug helpers are not loaded).
 *
 * @param array<string, mixed> $context
 */
function ipmiWebDebugLog(string $event, array $context = []): void
{
    if (!function_exists('ipmiProxyDebugEnabled') || !function_exists('ipmiProxyDebugLog')) {
        return;
    }
    try {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog($event, $context);
        }
    } catch (Throwable $e) {
        // ignore debug errors
    }
}

function ipmiWebHasUsableBmcAuth(array $cookieJar, array $forwardHeaders): bool
{
    foreach ($cookieJar as $v) {
        if (ipmiWebIsAuthValueUsable($v)) {
            return true;
        }
    }
    foreach ($forwardHeaders as $v) {
        if (ipmiWebIsAuthValueUsable($v)) {
            return true;
        }
    }

    return false;
}

function ipmiWebHasSupermicroAuthCookie(array $cookieJar): bool
{
    foreach (['SID', 'sid', 'SessionId', 'session_id', 'session', 'sessionid'] as $k) {
        if (isset($cookieJar[$k]) && ipmiWebIsAuthValueUsable($cookieJar[$k])) {
            return true;
        }
    }
    return false;
}

function ipmiWebLoginResponseLooksAuthed(int $httpCode, array $cookieJar, array $forwardHeaders): bool
{
    if ($httpCode < 200 || $httpCode >= 400) {
        return false;
    }

    return ipmiWebHasUsableBmcAuth($cookieJar, $forwardHeaders);
}

/**
 * Detect JSON login failure so we do not treat error pages with stray cookies as success.
 * Covers iLO /json/login_session error messages and Redfish error objects.
 */
function ipmiWebLoginResponseBodyIsFailure(string $raw): bool
{
    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    $trim = ltrim($body);
    if ($trim === '' || ($trim[0] !== '{' && $trim[0] !== '[')) {
        // iDRAC /data/login often responds with XML, e.g.:
        // <authResult>5</authResult><errorMsg>The maximum number of user sessions has been reached!</errorMsg>
        if (preg_match('~<authResult>\s*([^<]+)\s*</authResult>~i', $body, $m)) {
            $authResult = trim((string) ($m[1] ?? ''));
            $status = '';
            if (preg_match('~<status>\s*([^<]+)\s*</status>~i', $body, $sm)) {
                $status = strtolower(trim((string) ($sm[1] ?? '')));
            }
            $errorMsg = '';
            if (preg_match('~<errorMsg>\s*([^<]*)\s*</errorMsg>~i', $body, $em)) {
                $errorMsg = strtolower(trim((string) ($em[1] ?? '')));
            }
            $forwardUrl = '';
            if (preg_match('~<forwardUrl>\s*([^<]+)\s*</forwardUrl>~i', $body, $fm)) {
                $forwardUrl = trim((string) ($fm[1] ?? ''));
            }
            // Some iDRAC builds return authResult=99 with status=ok and a forwardUrl for an already-valid session.
            // Treat this as success, otherwise we incorrectly mark valid auto-login as failed.
            $isIdracAlreadyAuthed = ($authResult === '99')
                && ($status === 'ok' || $forwardUrl !== '')
                && $errorMsg === '';

            if ($authResult !== '' && $authResult !== '0' && !$isIdracAlreadyAuthed) {
                return true;
            }
        }
        return false;
    }
    $j = json_decode($body, true);
    if (!is_array($j)) {
        return false;
    }
    if (!empty($j['messages']) && is_array($j['messages'])) {
        foreach ($j['messages'] as $m) {
            if (is_array($m) && isset($m['type']) && strcasecmp((string)$m['type'], 'Error') === 0) {
                return true;
            }
        }
    }
    if (isset($j['error']) && is_array($j['error'])) {
        if (!empty($j['error']['code']) || !empty($j['error']['message'])) {
            return true;
        }
    }
    // Avoid treating arbitrary top-level "code" as failure (many APIs use it for non-login fields).
    // iLO JSON-RPC failures pair non-zero code with method/user_login-style payloads.
    if (isset($j['code']) && is_numeric($j['code']) && (int)$j['code'] !== 0) {
        if (isset($j['user_login']) || isset($j['method']) || (isset($j['output']) && is_array($j['output']))) {
            return true;
        }
    }
    // AMI/ASRock session limit error (code 15000) should be treated as failure.
    if (isset($j['code']) && is_numeric($j['code']) && (int)$j['code'] === 15000) {
        return true;
    }
    if (!empty($j['error']) && is_string($j['error']) && stripos($j['error'], 'maximum number of sessions') !== false) {
        return true;
    }

    return false;
}

/**
 * Best-effort reason classifier for failed login responses.
 * Used for faster fail paths and clearer probe diagnostics.
 */
function ipmiWebLoginResponseFailureReason(string $raw, int $httpCode, string $bmcType): string
{
    $typeNorm = ipmiWebNormalizeBmcType($bmcType);
    $j = ipmiWebDecodeJsonBody($raw);
    if (is_array($j)) {
        $jsonText = strtolower((string) json_encode($j, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        if (isset($j['code']) && is_numeric($j['code']) && (int) $j['code'] === 15000) {
            return 'session_limit';
        }
        if (str_contains($jsonText, 'maximum number of sessions')) {
            return 'session_limit';
        }
        if (str_contains($jsonText, 'js_err_no_priv')
            || str_contains($jsonText, 'invalid login attempt')
            || str_contains($jsonText, 'could not login')
            || str_contains($jsonText, 'invalid user')
            || str_contains($jsonText, 'unauthorized name')
            || str_contains($jsonText, 'access denied')
            || str_contains($jsonText, 'invalid username')
            || str_contains($jsonText, 'invalid password')) {
            return 'invalid_credentials';
        }
    }

    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    if (preg_match('~<authResult>\s*([^<]+)\s*</authResult>~i', $body, $m)) {
        $authResult = trim((string) ($m[1] ?? ''));
        if ($authResult !== '' && $authResult !== '0') {
            $status = '';
            if (preg_match('~<status>\s*([^<]+)\s*</status>~i', $body, $sm)) {
                $status = strtolower(trim((string) ($sm[1] ?? '')));
            }
            $errorMsg = '';
            if (preg_match('~<errorMsg>\s*([^<]*)\s*</errorMsg>~i', $body, $em)) {
                $errorMsg = strtolower(trim((string) ($em[1] ?? '')));
            }
            $forwardUrl = '';
            if (preg_match('~<forwardUrl>\s*([^<]+)\s*</forwardUrl>~i', $body, $fm)) {
                $forwardUrl = trim((string) ($fm[1] ?? ''));
            }
            // Some iDRAC builds signal "already authenticated" with authResult=99.
            if ($authResult === '99' && ($status === 'ok' || $forwardUrl !== '') && $errorMsg === '') {
                return '';
            }
            if ($authResult === '5' || str_contains($errorMsg, 'maximum number of user sessions')) {
                return 'session_limit';
            }
            if (str_contains($errorMsg, 'invalid')
                || str_contains($errorMsg, 'wrong')
                || str_contains($errorMsg, 'incorrect')
                || str_contains($errorMsg, 'authentication')) {
                return 'invalid_credentials';
            }
            return 'auth_rejected';
        }
    }

    $lb = strtolower(substr((string) $body, 0, 240000));
    if ($lb !== '') {
        if (str_contains($lb, 'lang_event_sensor_specific_event_str42_2')
            || str_contains($lb, 'invalid login')
            || str_contains($lb, 'invalid user')
            || str_contains($lb, 'invalid password')
            || str_contains($lb, 'access denied')
            || str_contains($lb, 'unauthorized name')
            || str_contains($lb, 'authentication failed')) {
            return 'invalid_credentials';
        }
        if (str_contains($lb, 'maximum number of sessions')) {
            return 'session_limit';
        }
    }

    if ($httpCode === 401 || $httpCode === 403) {
        if (ipmiWebIsNormalizedIloType($typeNorm) || $typeNorm === 'idrac' || $typeNorm === 'ami' || $typeNorm === 'supermicro') {
            return 'invalid_credentials';
        }
        return 'auth_rejected';
    }
    if ($httpCode === 0) {
        return 'connect_failed';
    }

    return '';
}

/**
 * Parse JSON from a BMC response (if present).
 *
 * @return array<string, mixed>|null
 */
function ipmiWebDecodeJsonBody(string $raw): ?array
{
    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    $trim = ltrim($body);
    if ($trim === '' || ($trim[0] !== '{' && $trim[0] !== '[')) {
        return null;
    }
    $j = json_decode($body, true);
    if (!is_array($j)) {
        return null;
    }

    return $j;
}

function ipmiWebAmiSessionLimitDetected(string $raw): bool
{
    $j = ipmiWebDecodeJsonBody($raw);
    if ($j === null) {
        return false;
    }
    if (isset($j['code']) && is_numeric($j['code']) && (int)$j['code'] === 15000) {
        return true;
    }
    if (!empty($j['error']) && is_string($j['error']) && stripos($j['error'], 'maximum number of sessions') !== false) {
        return true;
    }

    return false;
}

function ipmiWebExtractCsrfTokenForAmi(array $cookieJar, array $forwardHeaders): string
{
    foreach (['X-CSRFTOKEN', 'X-CSRF-Token', 'csrf', 'csrfToken', 'CSRFToken'] as $k) {
        if (!empty($forwardHeaders[$k]) && is_string($forwardHeaders[$k])) {
            $v = trim((string) $forwardHeaders[$k]);
            if ($v !== '') {
                return $v;
            }
        }
    }
    foreach (['garc', 'CSRFToken', 'csrfToken', 'csrf', 'csrftoken'] as $k) {
        if (!empty($cookieJar[$k]) && is_string($cookieJar[$k])) {
            $v = trim((string) $cookieJar[$k]);
            if ($v !== '') {
                return $v;
            }
        }
    }

    return '';
}

function ipmiWebAmiAttemptLogout(string $baseUrl, string $bmcIp, array $cookieJar, array $forwardHeaders): bool
{
    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    // Try to prefetch a CSRF token for logout calls (some AMI builds require it).
    foreach (['/api/session', '/api/status/uptime'] as $prefetchPath) {
        [$prefRaw, $prefCode] = ipmiWebCurlExecBmc($bmcIp, $baseUrl . $prefetchPath, static function ($ch) use ($originBase, $cookieJar): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 6);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            curl_setopt($ch, CURLOPT_HTTPGET, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Accept: application/json, text/javascript, */*',
                'X-Requested-With: XMLHttpRequest',
                'Origin: ' . $originBase,
                'Referer: ' . $originBase . '/',
            ]);
            $parts = [];
            foreach ($cookieJar as $k => $v) {
                if ($v !== null && trim((string) $v) !== '') {
                    $parts[] = $k . '=' . $v;
                }
            }
            if ($parts !== []) {
                curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
            }
        });
        if ($prefRaw !== false && $prefCode >= 200 && $prefCode < 500) {
            $j = ipmiWebDecodeJsonBody($prefRaw);
            if (is_array($j)) {
                ipmiWebApplyJsonAuthHints($j, $cookieJar, $forwardHeaders);
            }
        }
    }

    $csrf = ipmiWebExtractCsrfTokenForAmi($cookieJar, $forwardHeaders);
    $cookieParts = [];
    foreach ($cookieJar as $k => $v) {
        if ($v !== null && trim((string) $v) !== '') {
            $cookieParts[] = $k . '=' . $v;
        }
    }
    $cookieHeader = $cookieParts !== [] ? implode('; ', $cookieParts) : '';
    $headers = [
        'Accept: application/json, text/javascript, */*',
        'X-Requested-With: XMLHttpRequest',
        'Origin: ' . $originBase,
        'Referer: ' . $originBase . '/',
    ];
    if ($csrf !== '') {
        $headers[] = 'X-CSRFTOKEN: ' . $csrf;
        $headers[] = 'X-CSRF-Token: ' . $csrf;
    }

    $logoutUrls = [
        ['url' => $baseUrl . '/api/session', 'method' => 'DELETE'],
        ['url' => $baseUrl . '/api/logout', 'method' => 'POST'],
        ['url' => $baseUrl . '/api/session/logout', 'method' => 'POST'],
    ];

    foreach ($logoutUrls as $target) {
        [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $target['url'], static function ($ch) use ($headers, $cookieHeader, $target): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 20);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            if ($target['method'] === 'DELETE') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
            } else {
                curl_setopt($ch, CURLOPT_POST, true);
            }
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            if ($cookieHeader !== '') {
                curl_setopt($ch, CURLOPT_COOKIE, $cookieHeader);
            }
        });

        ipmiWebDebugLog('ami_logout_http', [
            'path' => $target['url'],
            'method' => $target['method'],
            'http' => $code,
        ]);

        if ($raw !== false && $code >= 200 && $code < 300) {
            return true;
        }
    }

    return false;
}

function ipmiWebAmiCleanupSessionsFromDb(?mysqli $mysqli, int $serverId, string $currentToken, string $baseUrl, string $bmcIp, int $limit = 5): bool
{
    if (!$mysqli || $serverId <= 0) {
        return false;
    }
    $sql = "
        SELECT token, bmc_cookies
        FROM ipmi_web_sessions
        WHERE server_id = ? AND revoked_at IS NULL AND expires_at > NOW() AND token <> ?
        ORDER BY COALESCE(last_access_at, created_at) DESC
        LIMIT ?
    ";
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) {
        return false;
    }
    $stmt->bind_param("isi", $serverId, $currentToken, $limit);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
    $stmt->close();

    $freed = 0;
    foreach ($rows as $row) {
        $rawCookies = (string) ($row['bmc_cookies'] ?? '');
        if ($rawCookies === '') {
            continue;
        }
        [$cookies, $forwardHeaders] = ipmiWebUnpackStoredAuth($rawCookies);
        if (!ipmiWebHasUsableBmcAuth($cookies, $forwardHeaders)) {
            continue;
        }
        if (ipmiWebAmiAttemptLogout($baseUrl, $bmcIp, $cookies, $forwardHeaders)) {
            $freed++;
            $upd = $mysqli->prepare("UPDATE ipmi_web_sessions SET revoked_at = NOW() WHERE token = ? LIMIT 1");
            if ($upd) {
                $tok = (string) ($row['token'] ?? '');
                $upd->bind_param("s", $tok);
                $upd->execute();
                $upd->close();
            }
        }
    }

    ipmiWebDebugLog('ami_logout_db_cleanup', [
        'server_id' => $serverId,
        'freed' => $freed,
    ]);

    return $freed > 0;
}

function ipmiWebSupermicroAttemptLogout(string $baseUrl, string $bmcIp, array $cookieJar): bool
{
    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    $cookieParts = [];
    foreach ($cookieJar as $k => $v) {
        if ($v !== null && trim((string) $v) !== '') {
            $cookieParts[] = $k . '=' . $v;
        }
    }
    $cookieHeader = $cookieParts !== [] ? implode('; ', $cookieParts) : '';

    [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $baseUrl . '/cgi/logout.cgi', static function ($ch) use ($originBase, $cookieHeader): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/',
        ]);
        if ($cookieHeader !== '') {
            curl_setopt($ch, CURLOPT_COOKIE, $cookieHeader);
        }
    });

    ipmiWebDebugLog('supermicro_logout_http', [
        'path' => '/cgi/logout.cgi',
        'http' => $code,
    ]);

    return $raw !== false && $code >= 200 && $code < 400;
}

function ipmiWebSupermicroCleanupSessionsFromDb(?mysqli $mysqli, int $serverId, string $currentToken, string $baseUrl, string $bmcIp, int $limit = 5): bool
{
    if (!$mysqli || $serverId <= 0) {
        return false;
    }
    $sql = "
        SELECT token, bmc_cookies
        FROM ipmi_web_sessions
        WHERE server_id = ? AND revoked_at IS NULL AND expires_at > NOW() AND token <> ?
        ORDER BY COALESCE(last_access_at, created_at) DESC
        LIMIT ?
    ";
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) {
        return false;
    }
    $stmt->bind_param('isi', $serverId, $currentToken, $limit);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
    $stmt->close();

    $freed = 0;
    foreach ($rows as $row) {
        $rawCookies = (string) ($row['bmc_cookies'] ?? '');
        if ($rawCookies === '') {
            continue;
        }
        [$cookies, $forwardHeaders] = ipmiWebUnpackStoredAuth($rawCookies);
        if (!ipmiWebHasUsableBmcAuth($cookies, $forwardHeaders) || !ipmiWebHasSupermicroAuthCookie($cookies)) {
            continue;
        }
        if (ipmiWebSupermicroAttemptLogout($baseUrl, $bmcIp, $cookies)) {
            $freed++;
            $upd = $mysqli->prepare("UPDATE ipmi_web_sessions SET revoked_at = NOW() WHERE token = ? LIMIT 1");
            if ($upd) {
                $tok = (string) ($row['token'] ?? '');
                $upd->bind_param('s', $tok);
                $upd->execute();
                $upd->close();
            }
        }
    }

    ipmiWebDebugLog('supermicro_logout_db_cleanup', [
        'server_id' => $serverId,
        'freed' => $freed,
    ]);

    return $freed > 0;
}

function ipmiWebIdracAttemptLogout(string $baseUrl, string $bmcIp, array $cookieJar): bool
{
    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    $cookieParts = [];
    foreach ($cookieJar as $k => $v) {
        if ($v !== null && trim((string) $v) !== '') {
            $cookieParts[] = $k . '=' . $v;
        }
    }
    $cookieHeader = $cookieParts !== [] ? implode('; ', $cookieParts) : '';

    $targets = [
        ['path' => '/data/logout', 'method' => 'GET', 'xhr' => true],
        ['path' => '/data/logout', 'method' => 'POST', 'xhr' => true, 'body' => ''],
        ['path' => '/logout', 'method' => 'GET', 'xhr' => false],
        ['path' => '/logout.html', 'method' => 'GET', 'xhr' => false],
        ['path' => '/restgui/logout', 'method' => 'GET', 'xhr' => false],
    ];

    foreach ($targets as $t) {
        $path = (string) ($t['path'] ?? '/data/logout');
        $method = strtoupper((string) ($t['method'] ?? 'GET'));
        $xhr = !empty($t['xhr']);
        $body = (string) ($t['body'] ?? '');
        [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $baseUrl . $path, static function ($ch) use ($originBase, $cookieHeader, $method, $xhr, $body): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 20);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            $headers = [
                'Accept: */*',
                'Origin: ' . $originBase,
                'Referer: ' . $originBase . '/login.html',
            ];
            if ($xhr) {
                $headers[] = 'X-Requested-With: XMLHttpRequest';
            }
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            if ($method === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            } else {
                curl_setopt($ch, CURLOPT_HTTPGET, true);
            }
            if ($cookieHeader !== '') {
                curl_setopt($ch, CURLOPT_COOKIE, $cookieHeader);
            }
        });

        ipmiWebDebugLog('idrac_logout_http', [
            'path' => $path,
            'method' => $method,
            'http' => $code,
        ]);

        if ($raw !== false && $code >= 200 && $code < 500) {
            return true;
        }
    }

    return false;
}

/**
 * Try to clear stale iDRAC sessions via Redfish using account Basic auth.
 * This is used only as a fallback when normal auto-login reports session_limit.
 */
function ipmiWebIdracCleanupSessionsViaRedfish(string $baseUrl, string $bmcIp, string $user, string $pass, int $maxDeletes = 20): bool
{
    $baseUrl = rtrim($baseUrl, '/');
    if ($baseUrl === '' || $bmcIp === '' || $user === '' || $pass === '') {
        return false;
    }

    $request = static function (string $path, string $method = 'GET', string $body = '') use ($baseUrl, $bmcIp, $user, $pass): array {
        $url = $baseUrl . $path;
        return ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($method, $body, $user, $pass): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 20);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
            curl_setopt($ch, CURLOPT_USERPWD, $user . ':' . $pass);
            $headers = [
                'Accept: application/json',
            ];
            $m = strtoupper($method);
            if ($m === 'POST') {
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                $headers[] = 'Content-Type: application/json';
            } elseif ($m === 'DELETE') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                if ($body !== '') {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                    $headers[] = 'Content-Type: application/json';
                }
            } else {
                curl_setopt($ch, CURLOPT_HTTPGET, true);
            }
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        });
    };

    $listPaths = [
        '/redfish/v1/Sessions',
        '/redfish/v1/Sessions/',
        '/redfish/v1/SessionService/Sessions',
        '/redfish/v1/SessionService/Sessions/',
    ];

    foreach ($listPaths as $listPath) {
        [$raw, $code] = $request($listPath, 'GET');
        if ($raw === false || $code < 200 || $code >= 400) {
            ipmiWebDebugLog('idrac_redfish_list_failed', [
                'path' => $listPath,
                'http' => $code,
            ]);
            continue;
        }

        [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
        $json = json_decode((string) $body, true);
        if (!is_array($json) || empty($json['Members']) || !is_array($json['Members'])) {
            ipmiWebDebugLog('idrac_redfish_list_empty', [
                'path' => $listPath,
                'http' => $code,
            ]);
            continue;
        }

        $deleted = 0;
        $attempted = 0;
        foreach ($json['Members'] as $member) {
            if (!is_array($member)) {
                continue;
            }
            $odata = trim((string) ($member['@odata.id'] ?? ''));
            if ($odata === '' || !str_starts_with($odata, '/')) {
                continue;
            }
            $attempted++;
            [$dRaw, $dCode] = $request($odata, 'DELETE');
            ipmiWebDebugLog('idrac_redfish_delete', [
                'path' => $odata,
                'http' => $dCode,
            ]);
            if ($dRaw !== false && in_array((int) $dCode, [200, 202, 204, 404], true)) {
                $deleted++;
            }
            if ($deleted >= max(1, $maxDeletes)) {
                break;
            }
        }

        ipmiWebDebugLog('idrac_redfish_cleanup', [
            'list_path' => $listPath,
            'attempted' => $attempted,
            'deleted' => $deleted,
        ]);

        if ($deleted > 0) {
            return true;
        }
    }

    return false;
}

function ipmiWebIdracCleanupSessionsFromDb(?mysqli $mysqli, int $serverId, string $currentToken, string $baseUrl, string $bmcIp, int $limit = 5): bool
{
    if (!$mysqli || $serverId <= 0) {
        return false;
    }
    $sql = "
        SELECT token, bmc_cookies
        FROM ipmi_web_sessions
        WHERE server_id = ? AND revoked_at IS NULL AND expires_at > NOW() AND token <> ?
        ORDER BY COALESCE(last_access_at, created_at) DESC
        LIMIT ?
    ";
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) {
        return false;
    }
    $stmt->bind_param('isi', $serverId, $currentToken, $limit);
    $stmt->execute();
    $res = $stmt->get_result();
    $rows = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
    $stmt->close();

    $freed = 0;
    foreach ($rows as $row) {
        $rawCookies = (string) ($row['bmc_cookies'] ?? '');
        if ($rawCookies === '') {
            continue;
        }
        [$cookies, $forwardHeaders] = ipmiWebUnpackStoredAuth($rawCookies);
        if (!ipmiWebHasUsableBmcAuth($cookies, $forwardHeaders)) {
            continue;
        }
        if (ipmiWebIdracAttemptLogout($baseUrl, $bmcIp, $cookies)) {
            $freed++;
            $upd = $mysqli->prepare("UPDATE ipmi_web_sessions SET revoked_at = NOW() WHERE token = ? LIMIT 1");
            if ($upd) {
                $tok = (string) ($row['token'] ?? '');
                $upd->bind_param('s', $tok);
                $upd->execute();
                $upd->close();
            }
        }
    }

    ipmiWebDebugLog('idrac_logout_db_cleanup', [
        'server_id' => $serverId,
        'freed' => $freed,
    ]);

    return $freed > 0;
}

function ipmiWebResponseLooksLikeIdracLauncherShell(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $lb = strtolower(substr($body, 0, 120000));
    if ($lb === '') {
        return false;
    }

    return strpos($lb, '/session?aimgetintprop=scl_int_enabled') !== false
        && strpos($lb, 'aimgetboolprop=pam_bool_sso_enabled') !== false
        && strpos($lb, 'top.document.location.href') !== false
        && strpos($lb, '/login.html') !== false;
}

function ipmiWebTryReuseExistingSession(mysqli $mysqli, int $serverId, int $userId, int $ttlSeconds): ?array
{
    $sql = "
        SELECT token
        FROM ipmi_web_sessions
        WHERE server_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > NOW()
        ORDER BY COALESCE(last_access_at, created_at) DESC
        LIMIT 1
    ";
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) {
        return null;
    }
    $stmt->bind_param("ii", $serverId, $userId);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();
    if (!$row || empty($row['token'])) {
        return null;
    }
    $session = ipmiWebLoadSession($mysqli, (string) $row['token']);
    if (!$session) {
        return null;
    }
    // Extend expiry so frequent opens reuse same BMC session.
    $newExpires = date('Y-m-d H:i:s', time() + max(300, $ttlSeconds));
    $upd = $mysqli->prepare("UPDATE ipmi_web_sessions SET expires_at = ? WHERE token = ? LIMIT 1");
    if ($upd) {
        $upd->bind_param("ss", $newExpires, $row['token']);
        $upd->execute();
        $upd->close();
    }

    return $session;
}

/**
 * When Redfish/JSON already established auth (token or JSON body), do not reject success because
 * the response chain included an HTML fragment that looks like a login page (false positive on some UIs).
 */
function ipmiWebLoginShouldRejectAsLoginHtml(string $raw, array $cookieJar, array $forwardHeaders, string $bmcType): bool
{
    $typeNorm = ipmiWebNormalizeBmcType($bmcType);
    // X-Auth-Token is reliable for iLO/iDRAC web auth bootstrap.
    // For Supermicro/AMI flows it can appear in non-auth contexts; do not bypass login-page checks there.
    $fam = ipmiWebBmcFamily($bmcType);
    if (trim((string)($forwardHeaders['X-Auth-Token'] ?? '')) !== '' && ($fam === 'ilo' || $fam === 'idrac')) {
        return false;
    }
    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    $trim = ltrim($body);
    if ($trim !== '' && ($trim[0] === '{' || $trim[0] === '[')) {
        return false;
    }
    // iLO classic session cookies (not Supermicro SID): trust over title/password HTML heuristics.
    if (ipmiWebIsIloFamilyType($bmcType)) {
        foreach (['session', 'sessionKey'] as $ck) {
            if (!empty($cookieJar[$ck]) && trim((string)$cookieJar[$ck]) !== '') {
                return false;
            }
        }
    }

    return ipmiWebLoginResponseHtmlIsLoginPage($raw);
}

/**
 * After a login POST, the final HTML may still be a sign-in page (wrong password, etc.) while
 * Set-Cookie left a session id from the anonymous login form (e.g. Supermicro/ATEN "SID").
 * Treat that as login failure so we do not store a useless jar and redirect users to the proxy
 * unauthenticated.
 */
function ipmiWebLoginResponseHtmlIsLoginPage(string $raw): bool
{
    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    $t = ltrim($body);
    if ($t === '' || $t[0] !== '<') {
        return false;
    }
    $l = strtolower(substr($body, 0, 200000));
    if (strpos($l, 'session has timed out') !== false || strpos($l, 'session timed out') !== false) {
        return true;
    }
    $hasPw = strpos($l, 'type="password"') !== false
        || strpos($l, "type='password'") !== false
        || strpos($l, 'type=password') !== false;
    // Some Supermicro/ATEN login shells render password as plain text input initially
    // (then switch by JS), so type=password can be absent in raw HTML.
    if (!$hasPw) {
        $smTextPwdMarkers = (
            (strpos($l, 'supermicro bmc login') !== false || strpos($l, 'aten international') !== false)
            && (strpos($l, '/cgi/login.cgi') !== false || strpos($l, 'action="/cgi/login.cgi"') !== false)
            && (
                strpos($l, 'name="pwd"') !== false
                || strpos($l, "name='pwd'") !== false
                || strpos($l, 'id="pwd"') !== false
                || strpos($l, "id='pwd'") !== false
            )
        );
        if ($smTextPwdMarkers) {
            return true;
        }
        return false;
    }
    if (strpos($l, 'supermicro bmc login') !== false) {
        return true;
    }
    if (strpos($l, 'aten international') !== false && strpos($l, 'login') !== false) {
        return true;
    }
    if (preg_match('/<title>[^<]*(log\\s*in|sign\\s*in|login)[^<]*<\\/title>/i', substr($body, 0, 80000))) {
        return true;
    }

    return false;
}

/**
 * True when the proxied HTML looks like a BMC sign-in page (session missing or stale).
 */
function ipmiWebResponseLooksLikeBmcLoginPage(string $body, string $contentType): bool
{
    $ct = strtolower($contentType);
    // Ignore JS/CSS payload text when detecting login pages; proxy-injected scripts can contain
    // strings like input[type=password] and login keywords that would create false positives.
    $visible = preg_replace('~<script\b[^>]*>.*?</script>~is', ' ', $body);
    if (!is_string($visible)) {
        $visible = $body;
    }
    $visible = preg_replace('~<style\b[^>]*>.*?</style>~is', ' ', $visible);
    if (!is_string($visible)) {
        $visible = $body;
    }

    $l = strtolower(substr($visible, 0, 200000));
    if (ipmiWebResponseLooksLikeSupermicroAuthedShell($body)) {
        return false;
    }
    if (ipmiWebResponseLooksLikeIloAuthedShell($body)) {
        return false;
    }
    if (ipmiWebResponseLooksLikeIdracAuthedShell($body)) {
        return false;
    }
    if (ipmiWebResponseLooksLikeAmiSpaLogin($body)) {
        return false;
    }
    $maybeHtml = strpos($ct, 'html') !== false
        || strpos($ct, 'text/plain') !== false
        || strpos($l, '<html') !== false
        || strpos($l, '<form') !== false
        || strpos($l, 'type=\"password\"') !== false
        || strpos($l, "type='password'") !== false
        || strpos($l, 'type=password') !== false;
    if (!$maybeHtml) {
        return false;
    }
    if (strpos($l, 'session has timed out') !== false || strpos($l, 'session timed out') !== false) {
        // Vendor shells ship timeout strings in JS/help text; do not treat as login if shell markers match full body.
        if (ipmiWebResponseLooksLikeIloAuthedShell($body)
            || ipmiWebResponseLooksLikeIdracAuthedShell($body)
            || ipmiWebResponseLooksLikeSupermicroAuthedShell($body)) {
            return false;
        }

        return true;
    }
    $hasPw = strpos($l, 'type="password"') !== false
        || strpos($l, "type='password'") !== false
        || strpos($l, 'type=password') !== false;
    if (!$hasPw) {
        // Supermicro/ATEN can ship login page with text password field and JS-driven masking.
        $smTextPwdMarkers = (
            (strpos($l, 'supermicro bmc login') !== false || strpos($l, 'aten international') !== false)
            && (strpos($l, '/cgi/login.cgi') !== false || strpos($l, 'action="/cgi/login.cgi"') !== false)
            && (
                strpos($l, 'name="pwd"') !== false
                || strpos($l, "name='pwd'") !== false
                || strpos($l, 'id="pwd"') !== false
                || strpos($l, "id='pwd'") !== false
            )
        );
        if ($smTextPwdMarkers) {
            return true;
        }
        return false;
    }
    if (strpos($l, 'login') !== false
        || strpos($l, 'sign in') !== false
        || strpos($l, 'sign-in') !== false
        || strpos($l, 'signin') !== false
        || strpos($l, 'user_login') !== false
        || strpos($l, 'username') !== false
        || strpos($l, 'name="username"') !== false
        || strpos($l, "name='username'") !== false) {
        return true;
    }

    return false;
}

/**
 * Supermicro/ASRock authenticated topmenu shell often contains login-related words
 * and timeout string constants, but it is not a login or timeout page.
 */
function ipmiWebResponseLooksLikeSupermicroAuthedShell(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $l = strtolower(substr($body, 0, 200000));
    if ($l === '') {
        return false;
    }

    $hits = 0;
    if (strpos($l, 'lang_topmenu_greeting') !== false) {
        $hits++;
    }
    if (strpos($l, 'id="refreshid"') !== false || strpos($l, "id='refreshid'") !== false) {
        $hits++;
    }
    if (strpos($l, "sessionstorage.setitem ('_x_auth'") !== false
        || strpos($l, 'sessionstorage.setitem("_x_auth"') !== false) {
        $hits++;
    }
    if (strpos($l, 'new redfish (null, session_id)') !== false) {
        $hits++;
    }

    return $hits >= 2;
}

/**
 * iLO authenticated shell includes login-related strings in JS, which should not be treated as login page.
 */
function ipmiWebResponseLooksLikeIloAuthedShell(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $l = strtolower(substr($body, 0, 260000));
    if ($l === '') {
        return false;
    }

    $hits = 0;
    if (strpos($l, 'function starteventwatchdog') !== false) {
        $hits++;
    }
    if (strpos($l, '/json/session_info') !== false) {
        $hits++;
    }
    if (strpos($l, 'id=modalframe') !== false || strpos($l, 'id="modalframe"') !== false || strpos($l, "id='modalframe'") !== false) {
        $hits++;
    }
    if (strpos($l, 'showapplication()') !== false || strpos($l, 'showlogin()') !== false) {
        $hits++;
    }
    // iLO 5/6 SPA shell
    if (strpos($l, 'iloglobal') !== false || strpos($l, 'html/application') !== false) {
        $hits++;
    }
    if (strpos($l, 'id="appframe"') !== false || strpos($l, "id='appframe'") !== false || strpos($l, 'id=appframe') !== false) {
        $hits++;
    }
    if (strpos($l, 'starthtml5irc') !== false || strpos($l, 'start_html5_irc') !== false) {
        $hits++;
    }
    if (strpos($l, 'framecontent') !== false || strpos($l, 'framedirectory') !== false) {
        $hits++;
    }
    if (str_contains($l, 'rc_info.html') || str_contains($l, '/html/rc_info')) {
        $hits++;
    }
    if (str_contains($l, 'hpe') && str_contains($l, 'integrated remote console')) {
        $hits++;
    }
    if (str_contains($l, '/js/ilo.js') || str_contains($l, 'ilo.js')) {
        $hits++;
    }
    if (str_contains($l, 'id="ircwindow"') || str_contains($l, 'id=ircwindow')) {
        $hits++;
    }
    if (str_contains($l, 'content.html') && str_contains($l, 'framecontent')) {
        $hits++;
    }

    return $hits >= 2;
}

/**
 * iDRAC authenticated GUI shell (not the bare /login.html form).
 */
function ipmiWebResponseLooksLikeIdracAuthedShell(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $l = strtolower(substr($body, 0, 260000));
    if ($l === '') {
        return false;
    }
    $hits = 0;
    if (str_contains($l, 'idrac') && (str_contains($l, 'restgui') || str_contains($l, '/restgui/'))) {
        $hits += 2;
    }
    if (str_contains($l, 'ext-all') && str_contains($l, 'dell')) {
        $hits++;
    }
    if (str_contains($l, 'virtual console') || str_contains($l, 'launch console')) {
        $hits++;
    }
    if (str_contains($l, 'qsessionid') || str_contains($l, 'sessionid')) {
        $hits++;
    }

    return $hits >= 2;
}

/**
 * Some Supermicro/ASRock timeout shells don't include the timeout sentence directly.
 * They execute sessionTimeout() via logout_alert() on DOM ready.
 */
function ipmiWebResponseLooksLikeSupermicroTimeoutShell(string $body): bool
{
    if ($body === '') {
        return false;
    }
    if (ipmiWebResponseLooksLikeSupermicroAuthedShell($body)) {
        return false;
    }
    $l = strtolower(substr($body, 0, 120000));
    if ($l === '') {
        return false;
    }
    $hasLogoutFn = strpos($l, 'logout_alert') !== false;
    $hasSessionTimeoutCall = strpos($l, 'sessiontimeout()') !== false
        || strpos($l, 'sessiontimeout ();') !== false;
    $hasReadyHook = strpos($l, 'document).ready') !== false || strpos($l, 'jquery(document).ready') !== false;

    return $hasLogoutFn && $hasSessionTimeoutCall && $hasReadyHook;
}

/**
 * AMI/ASRock newer BMC UI shell fingerprint.
 */
function ipmiWebResponseLooksLikeAmiSpaLogin(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $l = strtolower(substr($body, 0, 200000));
    if ($l === '') {
        return false;
    }

    $hasShell = strpos($l, 'source.min.js') !== false && strpos($l, 'styles.min.css') !== false;
    if (!$hasShell) {
        return false;
    }

    if (strpos($l, 'id="ami_logo"') !== false
        || strpos($l, "id='ami_logo'") !== false
        || strpos($l, '/api/session') !== false
        || strpos($l, 'id="main"') !== false
        || strpos($l, '<main role="main"') !== false) {
        return true;
    }

    return false;
}

/**
 * No stored BMC cookies or Redfish token — need auto-login before proxying.
 */
function ipmiWebNeedsAutoLogin(array $session): bool
{
    $c = $session['cookies'] ?? [];
    $h = $session['forward_headers'] ?? [];
    if (!is_array($c)) {
        $c = [];
    }
    if (!is_array($h)) {
        $h = [];
    }

    return !ipmiWebHasUsableBmcAuth($c, $h);
}

/**
 * Validate that a previously stored BMC auth jar still represents a live authenticated session.
 * This prevents reusing stale cookies that immediately bounce to login/timeout loops.
 */
function ipmiWebStoredSessionAuthStillValid(array $session): bool
{
    $ip = trim((string) ($session['ipmi_ip'] ?? ''));
    if ($ip === '') {
        return false;
    }
    $cookies = is_array($session['cookies'] ?? null) ? $session['cookies'] : [];
    $forwardHeaders = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
    if (!ipmiWebHasUsableBmcAuth($cookies, $forwardHeaders)) {
        return false;
    }

    $storedType = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
    $storedScheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $bases = [$storedScheme . '://' . $ip];
    $altScheme = ($storedScheme === 'https') ? 'http' : 'https';
    $bases[] = $altScheme . '://' . $ip;

    $verifyByType = static function (string $type, string $baseUrl) use ($ip, $cookies, $forwardHeaders): bool {
        if (ipmiWebIsNormalizedIloType($type)) {
            return ipmiWebIloVerifyAuthed($baseUrl, $ip, $cookies, $forwardHeaders);
        }
        switch ($type) {
            case 'supermicro':
                return ipmiWebSupermicroVerifyAuthed($baseUrl, $ip, $cookies);
            case 'idrac':
                return ipmiWebIdracVerifyAuthed($baseUrl, $ip, $cookies);
            case 'ami':
                return ipmiWebAmiVerifyAuthed($baseUrl, $ip, $cookies, $forwardHeaders);
            default:
                return false;
        }
    };

    if ($storedType !== 'generic') {
        foreach ($bases as $baseUrl) {
            if ($verifyByType($storedType, $baseUrl)) {
                return true;
            }
        }

        return false;
    }

    $candidates = [];
    if (ipmiWebHasSupermicroAuthCookie($cookies)) {
        $candidates[] = 'supermicro';
    }
    if (isset($cookies['QSESSIONID']) || isset($cookies['garc'])
        || isset($forwardHeaders['X-CSRFTOKEN']) || isset($forwardHeaders['X-CSRF-Token'])) {
        $candidates[] = 'ami';
    }
    if (isset($cookies['session']) || isset($cookies['sessionKey'])) {
        // Any ilo[0-9]+ label routes through ipmiWebIsNormalizedIloType → ipmiWebIloVerifyAuthed (gen-agnostic).
        $candidates[] = 'ilo5';
    }
    if (isset($cookies['-http-session-']) || isset($cookies['ST2']) || isset($cookies['sid']) || isset($cookies['sessionid'])) {
        $candidates[] = 'idrac';
    }
    $candidates = array_values(array_unique($candidates));
    if ($candidates === []) {
        return false;
    }

    foreach ($candidates as $type) {
        foreach ($bases as $baseUrl) {
            if ($verifyByType($type, $baseUrl)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Keep up to $maxKeep newest active web sessions per user+server; revoke older rows.
 * Avoids invalidating other browser tabs while still bounding session table growth.
 */
function ipmiWebPruneExcessWebSessions(mysqli $mysqli, int $serverId, int $userId, string $keepToken, int $maxKeep = 8): void
{
    if ($maxKeep < 2) {
        $maxKeep = 2;
    }
    $stmt = $mysqli->prepare(
        'SELECT token FROM ipmi_web_sessions WHERE server_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > NOW() ORDER BY id DESC'
    );
    if (!$stmt) {
        return;
    }
    $stmt->bind_param('ii', $serverId, $userId);
    $stmt->execute();
    $res = $stmt->get_result();
    $tokens = [];
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $t = (string)($row['token'] ?? '');
            if ($t !== '') {
                $tokens[] = $t;
            }
        }
    }
    $stmt->close();
    if (count($tokens) <= $maxKeep) {
        return;
    }
    $keep = array_slice($tokens, 0, $maxKeep);
    if (!in_array($keepToken, $keep, true)) {
        array_pop($keep);
        $keep[] = $keepToken;
    }
    $keepFlip = array_fill_keys($keep, true);
    $rev = $mysqli->prepare('UPDATE ipmi_web_sessions SET revoked_at = NOW() WHERE server_id = ? AND user_id = ? AND token = ? AND revoked_at IS NULL LIMIT 1');
    if (!$rev) {
        return;
    }
    foreach ($tokens as $t) {
        if (isset($keepFlip[$t])) {
            continue;
        }
        $rev->bind_param('iis', $serverId, $userId, $t);
        $rev->execute();
    }
    $rev->close();
}

function ipmiWebCreateSession(mysqli $mysqli, int $serverId, int $userId, string $role, int $ttlSeconds = 7200): array
{
    $isAdmin = ($role === 'admin');

    if ($isAdmin || $role === 'reseller') {
        $stmt = $mysqli->prepare("
            SELECT s.*, COALESCE(ss.suspended, 0) AS suspended
            FROM servers s
            LEFT JOIN server_suspension ss ON ss.server_id = s.id
            WHERE s.id = ?
            LIMIT 1
        ");
        $stmt->bind_param("i", $serverId);
    } else {
        $stmt = $mysqli->prepare("
            SELECT s.*, COALESCE(ss.suspended, 0) AS suspended
            FROM servers s
            INNER JOIN user_servers us ON us.server_id = s.id
            LEFT JOIN server_suspension ss ON ss.server_id = s.id
            WHERE s.id = ? AND us.user_id = ?
            LIMIT 1
        ");
        $stmt->bind_param("ii", $serverId, $userId);
    }

    $stmt->execute();
    $res = $stmt->get_result();
    $server = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if (!$server) {
        throw new Exception('Server not found or no permission');
    }

    $isSuspended = ((int)($server['suspended'] ?? 0) === 1);
    if ($isSuspended && !$isAdmin) {
        throw new Exception('Server is suspended');
    }

    try {
        $ipmiUser = Encryption::decrypt($server['ipmi_user']);
        $ipmiPass = Encryption::decrypt($server['ipmi_pass']);
    } catch (Exception $e) {
        $ipmiUser = $server['ipmi_user'];
        $ipmiPass = $server['ipmi_pass'];
    }

    $ipmiIp = trim((string)($server['ipmi_ip'] ?? ''));
    if ($ipmiIp === '') {
        throw new Exception('Server has no IPMI IP configured');
    }

    // Always create a new session for this user/server and revoke any prior ones.
    // Carry forward the most recent valid BMC auth so we don't force a fresh login.
    $carryCookies = [];
    $carryHeaders = [];
    $carryScheme = '';
    $carryType = '';
    $carry = $mysqli->prepare("
        SELECT token
        FROM ipmi_web_sessions
        WHERE server_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > NOW()
        ORDER BY COALESCE(last_access_at, created_at) DESC
        LIMIT 1
    ");
    if ($carry) {
        $carry->bind_param("ii", $serverId, $userId);
        $carry->execute();
        $resCarry = $carry->get_result();
        $rowCarry = $resCarry ? $resCarry->fetch_assoc() : null;
        $carry->close();
        if ($rowCarry && !empty($rowCarry['token'])) {
            $oldSession = ipmiWebLoadSession($mysqli, (string) $rowCarry['token']);
            if ($oldSession) {
                $cc = is_array($oldSession['cookies'] ?? null) ? $oldSession['cookies'] : [];
                $ch = is_array($oldSession['forward_headers'] ?? null) ? $oldSession['forward_headers'] : [];
                if (ipmiWebHasUsableBmcAuth($cc, $ch) && ipmiWebStoredSessionAuthStillValid($oldSession)) {
                    $carryCookies = $cc;
                    $carryHeaders = $ch;
                    $carryScheme = (string)($oldSession['bmc_scheme'] ?? '');
                    $carryType = (string)($oldSession['bmc_type'] ?? '');
                } else {
                    $oldToken = (string) $rowCarry['token'];
                    $redacted = (strlen($oldToken) >= 8) ? ('…' . substr($oldToken, -8)) : '…';
                    ipmiWebDebugLog('carry_session_rejected', [
                        'server_id' => $serverId,
                        'user_id' => $userId,
                        'token' => $redacted,
                    ]);
                }
            }
        }
    }
    $token = bin2hex(random_bytes(32));
    $expiresAt = date('Y-m-d H:i:s', time() + max(300, $ttlSeconds));
    $bmcType = strtolower(trim((string)($server['bmc_type'] ?? 'generic')));

    $encUser = Encryption::encrypt($ipmiUser);
    $encPass = Encryption::encrypt($ipmiPass);
    $createdIp = $_SERVER['REMOTE_ADDR'] ?? null;
    $userAgent = isset($_SERVER['HTTP_USER_AGENT']) ? substr((string)$_SERVER['HTTP_USER_AGENT'], 0, 255) : null;

    $ins = $mysqli->prepare("
        INSERT INTO ipmi_web_sessions
            (token, server_id, user_id, ipmi_ip, ipmi_user, ipmi_pass, bmc_type, created_ip, user_agent, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)
    ");
    $ins->bind_param(
        "siissssss" . "s",
        $token, $serverId, $userId, $ipmiIp, $encUser, $encPass, $bmcType, $createdIp, $userAgent, $expiresAt
    );
    if (!$ins->execute()) {
        $err = $ins->error;
        $ins->close();
        throw new Exception('Failed to create IPMI web session: ' . $err);
    }
    $ins->close();

    $session = [
        'token'            => $token,
        'server_id'        => $serverId,
        'user_id'          => $userId,
        'ipmi_ip'          => $ipmiIp,
        'ipmi_user'        => $ipmiUser,
        'ipmi_pass'        => $ipmiPass,
        'bmc_type'         => $bmcType,
        'expires_at'       => $expiresAt,
        'cookies'          => [],
        'forward_headers'  => [],
        'bmc_scheme'       => 'https',
    ];

    if (!empty($carryCookies)) {
        $session['cookies'] = $carryCookies;
        $session['forward_headers'] = $carryHeaders;
        if ($carryScheme !== '') {
            $session['bmc_scheme'] = $carryScheme;
        }
        if ($carryType !== '' && $carryType !== $session['bmc_type']) {
            $session['bmc_type'] = $carryType;
        }
    } else {
        ipmiWebAttemptAutoLogin($session, $mysqli);
    }

    // Persist upgraded detected vendor type (e.g. generic -> supermicro) so
    // subsequent proxy requests use the right vendor-specific behavior.
    $detectedType = strtolower(trim((string)($session['bmc_type'] ?? $bmcType)));
    if ($detectedType !== '' && $detectedType !== $bmcType) {
        $upd = $mysqli->prepare('UPDATE ipmi_web_sessions SET bmc_type = ? WHERE token = ? LIMIT 1');
        if ($upd) {
            $upd->bind_param('ss', $detectedType, $token);
            $upd->execute();
            $upd->close();
        }
    }

    // Wrong bmc_type (e.g. supermicro vs iLO) skips whole vendor endpoint lists — retry with generic.
    // Important: never permanently downgrade the session type to generic on failed fallback.
    // Otherwise iDRAC/iLO vendor-specific recovery logic is skipped on first open.
    if (ipmiWebNeedsAutoLogin($session) && ipmiWebNormalizeBmcType($bmcType) !== 'generic') {
        $restoreType = ipmiWebNormalizeBmcType((string)($session['bmc_type'] ?? $bmcType));
        if ($restoreType === '') {
            $restoreType = ipmiWebNormalizeBmcType($bmcType);
        }

        $session['bmc_type'] = 'generic';
        $session['cookies'] = [];
        $session['forward_headers'] = [];
        $session['bmc_scheme'] = 'https';
        if (ipmiWebAttemptAutoLogin($session, $mysqli)) {
            $fallbackDetectedType = ipmiWebNormalizeBmcType((string)($session['bmc_type'] ?? 'generic'));
            if ($fallbackDetectedType === '') {
                $fallbackDetectedType = 'generic';
            }
            $upd = $mysqli->prepare('UPDATE ipmi_web_sessions SET bmc_type = ? WHERE token = ? LIMIT 1');
            if ($upd) {
                $upd->bind_param('ss', $fallbackDetectedType, $token);
                $upd->execute();
                $upd->close();
            }
            $session['bmc_type'] = $fallbackDetectedType;
        } else {
            // Keep the vendor hint when fallback auth fails so proxy-side type-specific
            // verification/relogin can still run on the first browser request.
            $session['bmc_type'] = $restoreType;
        }
    }

    if (ipmiWebNeedsAutoLogin($session)) {
        // Keep the session so the proxy can retry auto-login on first request.
        // This prevents immediate hard-failure when a transient login hiccup occurs.
        $session['auto_login_failed'] = true;
    }

    ipmiWebSaveSessionCookies(
        $mysqli,
        $token,
        $session['cookies'],
        $session['forward_headers'] ?? [],
        (string)($session['bmc_scheme'] ?? 'https')
    );

    $finalType = strtolower(trim((string)($session['bmc_type'] ?? $bmcType)));
    if ($finalType === '') {
        $finalType = $bmcType;
    }
    if ($finalType !== $bmcType) {
        $upd = $mysqli->prepare('UPDATE ipmi_web_sessions SET bmc_type = ? WHERE token = ? LIMIT 1');
        if ($upd) {
            $upd->bind_param('ss', $finalType, $token);
            $upd->execute();
            $upd->close();
        }
    }

    // If server row is still generic but runtime detection identified a concrete vendor,
    // persist it so next sessions/probes follow vendor-specific paths from the start.
    ipmiWebPersistDetectedServerType($mysqli, $serverId, $bmcType, $finalType);

    ipmiWebPruneExcessWebSessions($mysqli, $serverId, $userId, $token, 8);

    return $session;
}

function ipmiWebLoadSession(mysqli $mysqli, string $token): ?array
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return null;
    }

    $stmt = $mysqli->prepare("
        SELECT ws.*, s.bmc_type AS server_bmc_type
        FROM ipmi_web_sessions ws
        LEFT JOIN servers s ON s.id = ws.server_id
        WHERE ws.token = ? AND ws.expires_at > NOW() AND ws.revoked_at IS NULL
        LIMIT 1
    ");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $res = $stmt->get_result();
    $row = $res ? $res->fetch_assoc() : null;
    $stmt->close();

    if (!$row) {
        return null;
    }

    $upd = $mysqli->prepare("UPDATE ipmi_web_sessions SET last_access_at = NOW() WHERE id = ?");
    if ($upd) {
        $rowId = (int)$row['id'];
        $upd->bind_param("i", $rowId);
        $upd->execute();
        $upd->close();
    }

    try {
        $ipmiUser = Encryption::decrypt($row['ipmi_user']);
        $ipmiPass = Encryption::decrypt($row['ipmi_pass']);
    } catch (Exception $e) {
        $ipmiUser = $row['ipmi_user'];
        $ipmiPass = $row['ipmi_pass'];
    }

    $cookies = [];
    $forwardHeaders = [];
    $bmcScheme = 'https';
    $rawCookies = trim((string)($row['bmc_cookies'] ?? ''));
    $sessionMeta = [];
    if ($rawCookies !== '') {
        [$cookies, $forwardHeaders, $bmcScheme, $sessionMeta] = ipmiWebUnpackStoredAuth($rawCookies);
    }

    $bmcType = strtolower(trim((string)($row['bmc_type'] ?? 'generic')));
    $serverType = ipmiWebNormalizeBmcType((string)($row['server_bmc_type'] ?? 'generic'));
    // Legacy/bad fallback tokens may be downgraded to generic; recover iDRAC behavior from server metadata.
    if (ipmiWebNormalizeBmcType($bmcType) === 'generic' && $serverType === 'idrac') {
        $bmcType = 'idrac';
        $fix = $mysqli->prepare('UPDATE ipmi_web_sessions SET bmc_type = ? WHERE id = ? LIMIT 1');
        if ($fix) {
            $rowId = (int)$row['id'];
            $fix->bind_param('si', $bmcType, $rowId);
            $fix->execute();
            $fix->close();
        }
    }
    if (ipmiWebIsIloFamilyType($bmcType)) {
        ipmiWebSyncIloSessionAndSessionKeyCookies($cookies);
    }

    return [
        'token'             => $row['token'],
        'server_id'         => (int)$row['server_id'],
        'user_id'           => (int)$row['user_id'],
        'ipmi_ip'           => $row['ipmi_ip'],
        'ipmi_user'         => $ipmiUser,
        'ipmi_pass'         => $ipmiPass,
        'bmc_type'          => $bmcType,
        'created_ip'        => $row['created_ip'] ?? null,
        'user_agent'        => $row['user_agent'] ?? null,
        'expires_at'        => $row['expires_at'],
        'cookies'           => $cookies,
        'forward_headers'   => $forwardHeaders,
        'bmc_scheme'        => $bmcScheme,
        'session_meta'      => is_array($sessionMeta) ? $sessionMeta : [],
    ];
}

function ipmiWebCleanupExpiredSessions(mysqli $mysqli): void
{
    $mysqli->query("DELETE FROM ipmi_web_sessions WHERE expires_at < NOW()");
}

/**
 * Persist BMC cookie jar + forward headers after a runtime auth refresh (iLO/iDRAC JSON, SSE, etc.).
 */
function ipmiWebPersistRefreshedRuntimeAuth(mysqli $mysqli, string $token, array $session): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $cookies = is_array($session['cookies'] ?? null) ? $session['cookies'] : [];
    $forwardHeaders = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
    $bmcScheme = (string) ($session['bmc_scheme'] ?? 'https');
    ipmiWebSaveSessionCookies($mysqli, $token, $cookies, $forwardHeaders, $bmcScheme);
    if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        $tokHint = strlen($token) >= 8 ? ('…' . substr($token, -8)) : '…';
        $xAuth = trim((string) ($forwardHeaders['X-Auth-Token'] ?? ''));
        ipmiProxyDebugLog('ilo_runtime_auth_persisted', [
            'token'        => $tokHint,
            'cookie_names' => array_slice(array_keys($cookies), 0, 12),
            'has_x_auth'   => $xAuth !== '' ? 1 : 0,
        ]);
    }
    if (ipmiWebHasUsableBmcAuth($cookies, $forwardHeaders)) {
        ipmiWebEmitMirroredBmcCookiesForProxy($token, $cookies);
    }
}

function ipmiWebSaveSessionCookies(mysqli $mysqli, string $token, array $cookies, array $forwardHeaders = [], string $bmcScheme = 'https'): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $meta = [];
    $sel = $mysqli->prepare('SELECT bmc_cookies FROM ipmi_web_sessions WHERE token = ? LIMIT 1');
    if ($sel) {
        $sel->bind_param('s', $token);
        $sel->execute();
        $r = $sel->get_result();
        $prev = $r ? $r->fetch_assoc() : null;
        $sel->close();
        if ($prev && trim((string) ($prev['bmc_cookies'] ?? '')) !== '') {
            [, , , $meta] = ipmiWebUnpackStoredAuth((string) $prev['bmc_cookies']);
        }
    }
    if (!is_array($meta)) {
        $meta = [];
    }
    $json = ipmiWebPackStoredAuth($cookies, $forwardHeaders, $bmcScheme, $meta);
    $stmt = $mysqli->prepare("UPDATE ipmi_web_sessions SET bmc_cookies = ? WHERE token = ?");
    if ($stmt) {
        $stmt->bind_param("ss", $json, $token);
        $stmt->execute();
        $stmt->close();
    }
}

function ipmiWebBuildProxyUrl(string $token, string $bmcPath = '/'): string
{
    return '/ipmi_proxy.php/' . rawurlencode($token) . '/' . ltrim($bmcPath, '/');
}

/**
 * Redfish login often yields X-Auth-Token only; the iLO HTML/JS UI still expects the legacy
 * session cookie from POST /json/login_session. Without it, the proxy loads the sign-in page.
 */
function ipmiWebIloEnsureSessionCookieForWebUi(string $baseUrl, string $bmcIp, string $user, string $pass, array &$cookieJar, array &$forwardHeaders): void
{
    ipmiWebSyncIloSessionAndSessionKeyCookies($cookieJar);
    if (isset($cookieJar['session']) && trim((string)$cookieJar['session']) !== '') {
        return;
    }

    $url = $baseUrl . '/json/login_session';
    $bmcIp = trim($bmcIp);
    if ($bmcIp === '') {
        $h = parse_url($baseUrl, PHP_URL_HOST);
        $bmcIp = is_string($h) ? $h : '';
    }
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    $jsonBody = json_encode(['method' => 'login', 'user_login' => $user, 'password' => $pass], JSON_UNESCAPED_SLASHES);

    [$raw] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($jsonBody, $forwardHeaders, $originBase, $cookieJar): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 45);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonBody);
        $jsonHeaders = [
            'Content-Type: application/json',
            'Accept: application/json, text/javascript, */*',
            'X-Requested-With: XMLHttpRequest',
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/',
        ];
        $tok = trim((string) ($forwardHeaders['X-Auth-Token'] ?? ''));
        if ($tok !== '') {
            $jsonHeaders[] = 'X-Auth-Token: ' . $tok;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $jsonHeaders);
        $parts = [];
        foreach ($cookieJar as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }
    });

    if ($raw === false || ipmiWebLoginResponseBodyIsFailure($raw)) {
        return;
    }

    ipmiWebCollectAuthFromLoginResponse($raw, $cookieJar, $forwardHeaders);
    ipmiWebSyncIloSessionAndSessionKeyCookies($cookieJar);
}

/**
 * Supermicro/ASRockRack often finalizes the web UI session after login by hitting
 * /cgi/url_redirect.cgi?url_name=topmenu. Fetch it once to refresh cookies so
 * the UI doesn't immediately bounce back to the login page.
 */
function ipmiWebSupermicroBootstrap(string $baseUrl, string $bmcIp, array &$cookieJar, array &$forwardHeaders): void
{
    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    $url = $baseUrl . '/cgi/url_redirect.cgi?url_name=topmenu';

    [$raw] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($originBase, $cookieJar): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        $reqHeaders = [
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/',
        ];
        curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);
        $parts = [];
        foreach ($cookieJar as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }
    });

    if ($raw === false) {
        return;
    }

    ipmiWebCollectAuthFromLoginResponse($raw, $cookieJar, $forwardHeaders);
}

/**
 * Validate that Supermicro/ASRock web session is actually authenticated.
 * A plain SID cookie can still represent an anonymous/expired session.
 */
function ipmiWebSupermicroVerifyAuthed(string $baseUrl, string $bmcIp, array $cookieJar): bool
{
    if (!ipmiWebHasSupermicroAuthCookie($cookieJar)) {
        return false;
    }

    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    $url = $baseUrl . '/cgi/url_redirect.cgi?url_name=topmenu';

    [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($originBase, $cookieJar): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/',
        ]);
        $parts = [];
        foreach ($cookieJar as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }
    });

    if ($raw === false || $code < 200 || $code >= 400) {
        return false;
    }

    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    if (ipmiWebResponseLooksLikeSupermicroTimeoutShell($body)) {
        return false;
    }
    if (ipmiWebResponseLooksLikeBmcLoginPage($body, 'text/html')) {
        return false;
    }

    return true;
}

/**
 * Validate iDRAC web session by opening a known authenticated UI entrypoint.
 * A plain -http-session- cookie can be anonymous on some builds.
 */
function ipmiWebIdracVerifyAuthed(string $baseUrl, string $bmcIp, array $cookieJar): bool
{
    if (!ipmiWebHasUsableBmcAuth($cookieJar, [])) {
        return false;
    }

    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    $targets = ['/index.html', '/start.html', '/', '/restgui/start.html', '/restgui/launch'];
    $hasAuthedUi = false;
    foreach ($targets as $path) {
        $url = $baseUrl . $path;
        [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($originBase, $cookieJar): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 20);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            curl_setopt($ch, CURLOPT_HTTPGET, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Origin: ' . $originBase,
                'Referer: ' . $originBase . '/',
            ]);
            $parts = [];
            foreach ($cookieJar as $k => $v) {
                if ($v !== null && trim((string) $v) !== '') {
                    $parts[] = $k . '=' . $v;
                }
            }
            if ($parts !== []) {
                curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
            }
        });

        if ($raw === false || $code < 200 || $code >= 400) {
            continue;
        }

        [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
        if (ipmiWebResponseLooksLikeBmcLoginPage($body, 'text/html')) {
            continue;
        }
        if (ipmiWebResponseLooksLikeIdracLauncherShell($body)) {
            continue;
        }

        $hasAuthedUi = true;
        break;
    }

    if (!$hasAuthedUi) {
        return false;
    }

    // Extra guard: if explicit login page still renders a login shell, the cookie is not authenticated.
    [$rawLogin, $codeLogin] = ipmiWebCurlExecBmc($bmcIp, $baseUrl . '/login.html', static function ($ch) use ($originBase, $cookieJar): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/',
        ]);
        $parts = [];
        foreach ($cookieJar as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }
    });
    if ($rawLogin !== false && $codeLogin >= 200 && $codeLogin < 400) {
        [, $loginBody] = ipmiWebCurlExtractFinalHeadersAndBody($rawLogin);
        if (ipmiWebResponseLooksLikeBmcLoginPage($loginBody, 'text/html')) {
            return false;
        }
    }

    return true;
}

function ipmiWebIloVerifyAuthed(string $baseUrl, string $bmcIp, array $cookieJar, array $forwardHeaders): bool
{
    if (!ipmiWebHasUsableBmcAuth($cookieJar, $forwardHeaders)) {
        return false;
    }

    ipmiWebSyncIloSessionAndSessionKeyCookies($cookieJar);
    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);

    // Primary verification endpoint for iLO web UI auth.
    $url = $baseUrl . '/json/session_info';
    [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($originBase, $cookieJar, $forwardHeaders): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        $headers = [
            'Accept: application/json, text/javascript, */*',
            'X-Requested-With: XMLHttpRequest',
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/',
        ];
        $tok = trim((string) ($forwardHeaders['X-Auth-Token'] ?? ''));
        if ($tok !== '') {
            $headers[] = 'X-Auth-Token: ' . $tok;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $parts = [];
        foreach ($cookieJar as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }
    });

    if ($raw !== false && $code >= 200 && $code < 400) {
        [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
        $json = json_decode(trim((string) $body), true);
        if (is_array($json)) {
            $msg = strtolower((string) ($json['message'] ?? $json['error'] ?? ''));
            $details = strtolower((string) ($json['details'] ?? ''));
            if (str_contains($msg, 'lost_session') || str_contains($details, 'invalid session')) {
                return false;
            }
            return true;
        }
    }

    // Fallback check: if root is not a login shell, treat as authenticated.
    $rootUrl = $baseUrl . '/';
    [$rootRaw, $rootCode] = ipmiWebCurlExecBmc($bmcIp, $rootUrl, static function ($ch) use ($originBase, $cookieJar, $forwardHeaders): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 20);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        $headers = [
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/',
        ];
        $tok = trim((string) ($forwardHeaders['X-Auth-Token'] ?? ''));
        if ($tok !== '') {
            $headers[] = 'X-Auth-Token: ' . $tok;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $parts = [];
        foreach ($cookieJar as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }
    });

    if ($rootRaw === false || $rootCode < 200 || $rootCode >= 400) {
        return false;
    }

    [, $rootBody] = ipmiWebCurlExtractFinalHeadersAndBody($rootRaw);
    if (ipmiWebResponseLooksLikeBmcLoginPage($rootBody, 'text/html')) {
        return false;
    }

    return true;
}

/**
 * True when iLO returns an authenticated SPA masthead fragment (not login shell).
 */
function ipmiWebIloBootstrapFragmentProbe(string $baseUrl, string $bmcIp, array $cookieJar, array $forwardHeaders): bool
{
    if (!ipmiWebHasUsableBmcAuth($cookieJar, $forwardHeaders)) {
        return false;
    }

    ipmiWebSyncIloSessionAndSessionKeyCookies($cookieJar);
    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    $url = $baseUrl . '/html/masthead.html';
    [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($originBase, $cookieJar, $forwardHeaders): void {
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 12);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 6);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        $headers = [
            'Accept: text/html, */*;q=0.8',
            'X-Requested-With: XMLHttpRequest',
            'Origin: ' . $originBase,
            'Referer: ' . $originBase . '/html/application.html',
        ];
        $tok = trim((string) ($forwardHeaders['X-Auth-Token'] ?? ''));
        if ($tok !== '') {
            $headers[] = 'X-Auth-Token: ' . $tok;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $parts = [];
        foreach ($cookieJar as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }
    });

    if ($raw === false || $code < 200 || $code >= 400) {
        return false;
    }

    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
    if (ipmiWebResponseLooksLikeBmcLoginPage($body, 'text/html')) {
        return false;
    }
    $lb = strtolower(substr((string) $body, 0, 48000));
    if ($lb === '') {
        return false;
    }
    if (str_contains($lb, 'ipmi session expired')
        || (str_contains($lb, 'session has timed out') && str_contains($lb, 'log in'))) {
        return false;
    }

    return strlen($body) > 80
        && (str_contains($lb, 'masthead')
            || str_contains($lb, 'hp.common')
            || str_contains($lb, 'ilo-navigation')
            || str_contains($lb, 'fwk-masthead'));
}

function ipmiWebAmiVerifyAuthed(string $baseUrl, string $bmcIp, array $cookieJar, array $forwardHeaders): bool
{
    if (!ipmiWebHasUsableBmcAuth($cookieJar, $forwardHeaders)) {
        return false;
    }

    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    // First, try an API endpoint that requires auth (more reliable than HTML shell).
    $apiTargets = [
        '/api/status/uptime',
        '/api/status',
    ];
    foreach ($apiTargets as $path) {
        $url = $baseUrl . $path;
        [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($originBase, $cookieJar, $forwardHeaders): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 6);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            curl_setopt($ch, CURLOPT_HTTPGET, true);
            $headers = [
                'Accept: application/json, text/javascript, */*',
                'X-Requested-With: XMLHttpRequest',
                'Origin: ' . $originBase,
                'Referer: ' . $originBase . '/',
            ];
            $tok = trim((string) ($forwardHeaders['X-CSRFTOKEN'] ?? $forwardHeaders['X-CSRF-Token'] ?? ''));
            if ($tok !== '') {
                $headers[] = 'X-CSRFTOKEN: ' . $tok;
                $headers[] = 'X-CSRF-Token: ' . $tok;
            }
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            $parts = [];
            foreach ($cookieJar as $k => $v) {
                if ($v !== null && trim((string) $v) !== '') {
                    $parts[] = $k . '=' . $v;
                }
            }
            if ($parts !== []) {
                curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
            }
        });
        if ($raw === false) {
            continue;
        }
        if ($code === 401 || $code === 403) {
            ipmiWebDebugLog('ami_verify_api', [
                'path' => $path,
                'http' => $code,
                'result' => 'unauthorized',
            ]);
            return false;
        }
        if ($code >= 200 && $code < 300) {
            $json = ipmiWebDecodeJsonBody($raw);
            if (is_array($json)) {
                ipmiWebDebugLog('ami_verify_api', [
                    'path' => $path,
                    'http' => $code,
                    'result' => 'ok',
                ]);
                return true;
            }
        }
    }
    $targets = [
        '/html/application.html',
        '/html/index.html',
        '/',
    ];

    foreach ($targets as $path) {
        $url = $baseUrl . $path;
        [$raw, $code] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($originBase, $cookieJar, $forwardHeaders): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 20);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            curl_setopt($ch, CURLOPT_HTTPGET, true);
            $headers = [
                'Origin: ' . $originBase,
                'Referer: ' . $originBase . '/',
            ];
            $tok = trim((string) ($forwardHeaders['X-Auth-Token'] ?? ''));
            if ($tok !== '') {
                $headers[] = 'X-Auth-Token: ' . $tok;
            }
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            $parts = [];
            foreach ($cookieJar as $k => $v) {
                if ($v !== null && trim((string) $v) !== '') {
                    $parts[] = $k . '=' . $v;
                }
            }
            if ($parts !== []) {
                curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
            }
        });

        if ($raw === false || $code < 200 || $code >= 400) {
            continue;
        }

        [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
        if (ipmiWebResponseLooksLikeBmcLoginPage($body, 'text/html')) {
            continue;
        }
        $lb = strtolower(substr((string) $body, 0, 120000));
        if (strpos($lb, 'commonutil.js') !== false
            || strpos($lb, 'source.min.js') !== false
            || strpos($lb, '/html/application.html') !== false) {
            return true;
        }
        if (trim((string) $body) !== '') {
            return true;
        }
    }

    return false;
}

function ipmiWebInferBmcTypeFromAutologin(string $currentTypeNorm, string $pathUsed, string $rawResponse): string
{
    if ($currentTypeNorm !== 'generic') {
        return $currentTypeNorm;
    }

    $path = strtolower(trim($pathUsed));
    if ($path === '/json/login_session') {
        return 'ilo5';
    }
    if ($path === '/data/login' || $path === '/login.html' || str_starts_with($path, '/restgui/')) {
        return 'idrac';
    }
    if ($path === '/api/session') {
        return 'ami';
    }
    if ($path === '/cgi/login.cgi') {
        return 'supermicro';
    }

    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody($rawResponse);
    $lb = strtolower(substr((string) $body, 0, 120000));
    if (strpos($lb, 'supermicro') !== false || strpos($lb, 'asrockrack') !== false || strpos($lb, 'aten') !== false) {
        return 'supermicro';
    }
    // Classic iLO 4 HTML UI (no iLO 5/6 SPA shell markers).
    if ((strpos($lb, 'login.htm') !== false || strpos($lb, 'cpqlogin') !== false || strpos($lb, 'javascript/cpq') !== false)
        && strpos($lb, 'iloglobal') === false
        && strpos($lb, '/html/application.html') === false
        && strpos($lb, 'starthtml5irc') === false) {
        return 'ilo4';
    }
    if (strpos($lb, 'integrated lights-out') !== false || strpos($lb, 'hewlett') !== false || strpos($lb, 'hpe') !== false || strpos($lb, ' ilo') !== false) {
        return 'ilo5';
    }
    if (strpos($lb, 'idrac') !== false || strpos($lb, 'dell') !== false || strpos($lb, '/restgui/') !== false) {
        return 'idrac';
    }
    // iLO 5/6 SPA bundles (do not classify as AMI — ASRock uses different entry fingerprints).
    if (strpos($lb, '/html/application.html') !== false
        || strpos($lb, 'iloglobal') !== false
        || strpos($lb, 'starthtml5irc') !== false
        || strpos($lb, 'framecontent') !== false) {
        return 'ilo5';
    }
    if (strpos($lb, 'commonutil.js') !== false || strpos($lb, 'source.min.js') !== false) {
        return 'ilo5';
    }
    if (strpos($lb, 'id="ami_logo"') !== false || strpos($lb, "id='ami_logo'") !== false || strpos($lb, '/api/session') !== false) {
        return 'ami';
    }

    return 'generic';
}

/**
 * Supermicro/ASRockRack login often includes hidden fields or CSRF tokens.
 * Fetch the login page and return hidden input fields + updated cookies + form action + user/pass field names.
 *
 * @return array{fields: array<string,string>, cookies: array<string,string>, action: string, userField: string, passField: string, isSupermicro: bool}
 */
function ipmiWebSupermicroFetchLoginFields(string $baseUrl, string $bmcIp, array $cookieJar): array
{
    $baseUrl = rtrim($baseUrl, '/');
    $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $bmcIp);
    $targets = [
        $baseUrl . '/',
        $baseUrl . '/cgi/login.cgi',
        $baseUrl . '/login.html',
    ];

    foreach ($targets as $url) {
        [$raw] = ipmiWebCurlExecBmc($bmcIp, $url, static function ($ch) use ($originBase, $cookieJar): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 20);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            curl_setopt($ch, CURLOPT_HTTPGET, true);
            $reqHeaders = [
                'Origin: ' . $originBase,
                'Referer: ' . $originBase . '/',
            ];
            curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);
            $parts = [];
            foreach ($cookieJar as $k => $v) {
                if ($v !== null && trim((string) $v) !== '') {
                    $parts[] = $k . '=' . $v;
                }
            }
            if ($parts !== []) {
                curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
            }
        });

        if ($raw === false) {
            continue;
        }

        [$hdrs, $body] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
        $newCookies = ipmiWebCurlMergeSetCookiesFromChain($raw, []);
        if ($newCookies !== []) {
            $cookieJar = array_merge($cookieJar, $newCookies);
        }

        $fields = [];
        $action = '';
        $userField = '';
        $passField = '';
        $isSupermicro = false;

        if ($body !== '' && stripos($body, '<form') !== false) {
            if (preg_match('/<form[^>]+action\\s*=\\s*["\\\']([^"\\\']+)["\\\']/i', $body, $fm)) {
                $action = trim((string) $fm[1]);
            }
        }
        if ($body !== '') {
            $lb = strtolower($body);
            if (strpos($lb, 'supermicro') !== false || strpos($lb, 'asrockrack') !== false || strpos($lb, 'aten') !== false) {
                $isSupermicro = true;
            }
        }

        if ($body !== '' && stripos($body, '<input') !== false) {
            if (preg_match_all('/<input[^>]+>/i', $body, $m)) {
                foreach ($m[0] as $tag) {
                    if (!preg_match('/name\\s*=\\s*["\\\']?([^"\\\'\\s>]+)/i', $tag, $nm)) {
                        continue;
                    }
                    $name = trim((string) $nm[1]);
                    if ($name === '') {
                        continue;
                    }
                    $type = '';
                    if (preg_match('/type\\s*=\\s*["\\\']?([^"\\\'\\s>]+)/i', $tag, $tm)) {
                        $type = strtolower(trim((string) $tm[1]));
                    }
                    $val = '';
                    if (preg_match('/value\\s*=\\s*["\\\']([^"\\\']*)/i', $tag, $vm)) {
                        $val = (string) $vm[1];
                    }
                    if ($type === 'password' && $passField === '') {
                        $passField = $name;
                    } elseif (($type === 'text' || $type === '' || $type === 'email') && $userField === '' && $name !== $passField) {
                        $userField = $name;
                    }
                    if ($type === '' || $type === 'hidden' || $type === 'submit' || $type === 'button') {
                        $fields[$name] = $val;
                    }
                }
            }
        }

        if ($fields !== [] || $action !== '' || $userField !== '' || $passField !== '' || $isSupermicro) {
            return [
                'fields'    => $fields,
                'cookies'   => $cookieJar,
                'action'    => $action,
                'userField' => $userField,
                'passField' => $passField,
                'isSupermicro' => $isSupermicro,
            ];
        }
    }

    return [
        'fields'    => [],
        'cookies'   => $cookieJar,
        'action'    => '',
        'userField' => '',
        'passField' => '',
        'isSupermicro' => false,
    ];
}

/**
 * Auto-login to BMC web UI via cURL, storing cookies and/or Redfish-style auth headers.
 */
function ipmiWebAttemptAutoLogin(array &$session, ?mysqli $mysqli = null): bool
{
    $ip   = $session['ipmi_ip'] ?? '';
    $user = $session['ipmi_user'] ?? '';
    $pass = $session['ipmi_pass'] ?? '';
    $bmcType = strtolower(trim((string)($session['bmc_type'] ?? 'generic')));

    if ($ip === '' || $user === '' || $pass === '') {
        return false;
    }

    $sc = $session['cookies'] ?? [];
    $sh = $session['forward_headers'] ?? [];
    if (!is_array($sc)) {
        $sc = [];
    }
    if (!is_array($sh)) {
        $sh = [];
    }
    if (!ipmiWebHasUsableBmcAuth($sc, $sh)) {
        $session['cookies'] = [];
        $session['forward_headers'] = [];
    }

    $prevCookies = $session['cookies'] ?? [];
    $prevHeaders = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
    $prevScheme = (string)($session['bmc_scheme'] ?? 'https');
    if (!isset($session['forward_headers']) || !is_array($session['forward_headers'])) {
        $session['forward_headers'] = [];
    }

    // Quick reachability preflight keeps unreachable hosts from spending minutes in endpoint retries.
    $quickReach = static function (string $host): array {
        foreach (['https', 'http'] as $scheme) {
            $url = $scheme . '://' . $host . '/';
            [$raw, $code] = ipmiWebCurlExecBmc($host, $url, static function ($ch): void {
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 6);
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
                curl_setopt($ch, CURLOPT_HEADER, true);
                curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
                curl_setopt($ch, CURLOPT_HTTPGET, true);
            });
            if ($raw !== false && $code > 0 && $code < 500) {
                return ['ok' => true, 'scheme' => $scheme, 'http' => $code];
            }
        }

        return ['ok' => false, 'scheme' => '', 'http' => 0];
    };
    $pre = $quickReach($ip);
    if (empty($pre['ok'])) {
        $session['auto_login_error'] = 'connect_failed';
        ipmiWebDebugLog('autologin_unreachable', [
            'ip' => $ip,
            'type' => $bmcType,
        ]);
        return false;
    }

    // Prefer preflight scheme first, then fallback to the other scheme.
    $bases = [];
    $firstScheme = (($pre['scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $bases[] = $firstScheme . '://' . $ip;
    $bases[] = ($firstScheme === 'https' ? 'http' : 'https') . '://' . $ip;
    $firstFailureReason = '';

    foreach ($bases as $baseUrl) {
        $baseUrl = rtrim($baseUrl, '/');
        ipmiWebDebugLog('autologin_base', [
            'base' => $baseUrl,
            'ip' => $ip,
            'type' => $bmcType,
        ]);
        $amiRetryCount = 0;
        $primeJar = [];
        $primeHdr = [];
        [$praw] = ipmiWebCurlExecBmc($ip, $baseUrl . '/', static function ($ch): void {
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 25);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 12);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
            curl_setopt($ch, CURLOPT_HTTPGET, true);
        });
        if ($praw !== false) {
            ipmiWebCollectAuthFromLoginResponse($praw, $primeJar, $primeHdr);
        }

        $smLoginMeta = null;
        $smCookieJar = $primeJar;
        $typeNorm = ipmiWebNormalizeBmcType($bmcType);
        $primeBody = '';
        if ($praw !== false) {
            [, $primeBody] = ipmiWebCurlExtractFinalHeadersAndBody($praw);
        }
        // AMI/ASRockRack SPA can be mis-classified as supermicro by IPMI detection.
        // If the login page matches AMI, force AMI flow regardless of stored bmc_type.
        if (ipmiWebResponseLooksLikeAmiSpaLogin($primeBody)) {
            $typeNorm = 'ami';
            $session['bmc_type'] = 'ami';
        } elseif ($typeNorm === 'generic') {
            $smLoginMeta = ipmiWebSupermicroFetchLoginFields($baseUrl, $ip, $primeJar);
            $smCookieJar = $smLoginMeta['cookies'] ?? $primeJar;
            if (!empty($smLoginMeta['isSupermicro'])) {
                $typeNorm = 'supermicro';
                $session['bmc_type'] = 'supermicro';
            }
        }

        $retryAmi = true;
        $retrySmCount = 0;
        $retryIdracCount = 0;
        while ($retryAmi) {
            $retryAmi = false;
            $loginEndpoints = ipmiWebLoginEndpoints($typeNorm, $user, $pass);
            foreach ($loginEndpoints as $endpoint) {
            $cookieJar = $smCookieJar;
            $forwardHeaders = [];

            $url = $baseUrl . $endpoint['path'];
            $originBase = ipmiWebBmcOriginBaseFromConnectUrl($baseUrl, $ip);

            $postPayload = $endpoint['post'] ?? null;
            $isSmType = ($typeNorm === 'supermicro');
            if ($isSmType && is_array($postPayload)) {
                if ($smLoginMeta === null) {
                    $smLoginMeta = ipmiWebSupermicroFetchLoginFields($baseUrl, $ip, $cookieJar);
                    $smCookieJar = $smLoginMeta['cookies'] ?? $cookieJar;
                }
                if (is_array($smLoginMeta) && !empty($smLoginMeta['fields'])) {
                    $postPayload = array_merge($smLoginMeta['fields'], $postPayload);
                }
                if (is_array($smLoginMeta)) {
                    $uf = trim((string)($smLoginMeta['userField'] ?? ''));
                    $pf = trim((string)($smLoginMeta['passField'] ?? ''));
                    if ($uf !== '' && (!array_key_exists($uf, $postPayload) || $postPayload[$uf] === '')) {
                        $postPayload[$uf] = $user;
                    }
                    if ($pf !== '' && (!array_key_exists($pf, $postPayload) || $postPayload[$pf] === '')) {
                        $postPayload[$pf] = $pass;
                    }
                    $act = trim((string)($smLoginMeta['action'] ?? ''));
                    if ($act !== '') {
                        if (str_starts_with($act, 'http://') || str_starts_with($act, 'https://')) {
                            $pu = parse_url($act, PHP_URL_PATH);
                            if (is_string($pu) && $pu !== '') {
                                $url = $baseUrl . $pu;
                            }
                        } elseif (str_starts_with($act, '/')) {
                            $url = $baseUrl . $act;
                        } else {
                            $url = $baseUrl . '/' . ltrim($act, '/');
                        }
                    }
                }
                $cookieJar = $smCookieJar;
            }

            [$raw, $code] = ipmiWebCurlExecBmc($ip, $url, static function ($ch) use ($endpoint, $originBase, $postPayload): void {
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 25);
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_HEADER, true);
                curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());

                if ($postPayload !== null) {
                    curl_setopt($ch, CURLOPT_POST, true);
                    if (is_array($postPayload)) {
                        $body = http_build_query($postPayload);
                        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                        $reqHeaders = [
                            'Content-Type: application/x-www-form-urlencoded',
                            'Origin: ' . $originBase,
                            'Referer: ' . $originBase . '/',
                        ];
                        if (!empty($endpoint['accept'])) {
                            $reqHeaders[] = 'Accept: ' . (string) $endpoint['accept'];
                        }
                        if (!empty($endpoint['redfish'])) {
                            $reqHeaders[] = 'OData-Version: 4.0';
                        }
                        if (!empty($endpoint['xhr'])) {
                            $reqHeaders[] = 'X-Requested-With: XMLHttpRequest';
                        }
                        curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);
                    } else {
                        curl_setopt($ch, CURLOPT_POSTFIELDS, (string) $postPayload);
                        $jsonHeaders = [
                            'Content-Type: application/json',
                            'Origin: ' . $originBase,
                            'Referer: ' . $originBase . '/',
                        ];
                        if (!empty($endpoint['accept'])) {
                            $jsonHeaders[] = 'Accept: ' . (string) $endpoint['accept'];
                        }
                        if (!empty($endpoint['redfish'])) {
                            $jsonHeaders[] = 'OData-Version: 4.0';
                        }
                        if (!empty($endpoint['xhr'])) {
                            $jsonHeaders[] = 'X-Requested-With: XMLHttpRequest';
                        }
                        curl_setopt($ch, CURLOPT_HTTPHEADER, $jsonHeaders);
                    }
                }
            });

            if ($raw === false) {
                ipmiWebDebugLog('autologin_attempt', [
                    'path' => (string) ($endpoint['path'] ?? ''),
                    'http' => 0,
                    'result' => 'curl_failed',
                ]);
                if ($firstFailureReason === '') {
                    $firstFailureReason = 'connect_failed';
                }
                continue;
            }

            ipmiWebCollectAuthFromLoginResponse($raw, $cookieJar, $forwardHeaders);

            $isSupermicro = $isSmType || (!empty($smLoginMeta['isSupermicro']));
            if ($isSupermicro && !ipmiWebHasSupermicroAuthCookie($cookieJar)) {
                $forwardHeaders = []; // ignore misleading X-Auth-Token for Supermicro
            }

            $loginHtml = ipmiWebLoginResponseHtmlIsLoginPage($raw);
            $loginJsonFail = ipmiWebLoginResponseBodyIsFailure($raw);
            $failureReason = ipmiWebLoginResponseFailureReason($raw, (int) $code, (string) ($session['bmc_type'] ?? $bmcType));
            if ($typeNorm === 'ami' && $amiRetryCount < 1 && ipmiWebAmiSessionLimitDetected($raw)) {
                ipmiWebDebugLog('ami_session_limit_detected', [
                    'path' => (string) ($endpoint['path'] ?? ''),
                    'http' => $code,
                ]);
                $logoutOk = ipmiWebAmiAttemptLogout($baseUrl, $ip, $cookieJar, $forwardHeaders);
                ipmiWebDebugLog('ami_logout_attempt', [
                    'ok' => $logoutOk ? 1 : 0,
                ]);
                $dbCleanupOk = false;
                if (!$logoutOk && $mysqli) {
                    $dbCleanupOk = ipmiWebAmiCleanupSessionsFromDb($mysqli, (int)($session['server_id'] ?? 0), (string)($session['token'] ?? ''), $baseUrl, $ip, 5);
                }
                if ($logoutOk || $dbCleanupOk) {
                    $amiRetryCount++;
                    $retryAmi = true;
                    break;
                }
            }
            if ($typeNorm === 'supermicro' && $retrySmCount < 1 && $failureReason === 'session_limit') {
                ipmiWebDebugLog('supermicro_session_limit_detected', [
                    'path' => (string) ($endpoint['path'] ?? ''),
                    'http' => $code,
                ]);
                $smLogoutOk = ipmiWebSupermicroAttemptLogout($baseUrl, $ip, $cookieJar);
                ipmiWebDebugLog('supermicro_logout_attempt', [
                    'ok' => $smLogoutOk ? 1 : 0,
                ]);
                $smDbCleanupOk = false;
                if (!$smLogoutOk && $mysqli) {
                    $smDbCleanupOk = ipmiWebSupermicroCleanupSessionsFromDb(
                        $mysqli,
                        (int)($session['server_id'] ?? 0),
                        (string)($session['token'] ?? ''),
                        $baseUrl,
                        $ip,
                        5
                    );
                }
                if ($smLogoutOk || $smDbCleanupOk) {
                    $retrySmCount++;
                    $retryAmi = true;
                    break;
                }
            }
            if ($typeNorm === 'idrac' && $retryIdracCount < 1
                && ($failureReason === 'session_limit'
                    || stripos($raw, 'maximum number of user sessions') !== false
                    || stripos($raw, 'maximum number of sessions') !== false)) {
                ipmiWebDebugLog('idrac_session_limit_detected', [
                    'path' => (string) ($endpoint['path'] ?? ''),
                    'http' => $code,
                ]);
                $idracLogoutOk = ipmiWebIdracAttemptLogout($baseUrl, $ip, $cookieJar);
                ipmiWebDebugLog('idrac_logout_attempt', [
                    'ok' => $idracLogoutOk ? 1 : 0,
                ]);
                $idracDbCleanupOk = false;
                if (!$idracLogoutOk && $mysqli) {
                    $idracDbCleanupOk = ipmiWebIdracCleanupSessionsFromDb(
                        $mysqli,
                        (int)($session['server_id'] ?? 0),
                        (string)($session['token'] ?? ''),
                        $baseUrl,
                        $ip,
                        20
                    );
                }
                $idracRedfishCleanupOk = false;
                if (!$idracLogoutOk && !$idracDbCleanupOk) {
                    $idracRedfishCleanupOk = ipmiWebIdracCleanupSessionsViaRedfish(
                        $baseUrl,
                        $ip,
                        (string) $user,
                        (string) $pass,
                        20
                    );
                }
                if ($idracLogoutOk || $idracDbCleanupOk || $idracRedfishCleanupOk) {
                    $retryIdracCount++;
                    $retryAmi = true;
                    break;
                }
            }
            ipmiWebDebugLog('autologin_attempt', [
                'path' => (string) ($endpoint['path'] ?? ''),
                'http' => $code,
                'isSupermicro' => $isSupermicro ? 1 : 0,
                'cookies' => array_keys(array_filter($cookieJar, 'ipmiWebIsAuthValueUsable')),
                'headers' => array_keys(array_filter($forwardHeaders, 'ipmiWebIsAuthValueUsable')),
                'loginHtml' => $loginHtml ? 1 : 0,
                'loginJsonFail' => $loginJsonFail ? 1 : 0,
                'failureReason' => $failureReason,
            ]);
            if ($failureReason !== '' && $firstFailureReason === '') {
                $firstFailureReason = $failureReason;
            }

            if (ipmiWebLoginResponseLooksAuthed($code, $cookieJar, $forwardHeaders)
                && !$loginJsonFail
                && !ipmiWebLoginShouldRejectAsLoginHtml($raw, $cookieJar, $forwardHeaders, $bmcType)) {
                if ($isSupermicro && !ipmiWebHasSupermicroAuthCookie($cookieJar)) {
                    continue;
                }
                if (ipmiWebNormalizeBmcType($bmcType) === 'supermicro') {
                    ipmiWebSupermicroBootstrap($baseUrl, $ip, $cookieJar, $forwardHeaders);
                }
                $pathUsed = (string) ($endpoint['path'] ?? '');
                $effectiveType = ipmiWebInferBmcTypeFromAutologin($typeNorm, $pathUsed, $raw);
                if ($effectiveType !== 'generic') {
                    $session['bmc_type'] = $effectiveType;
                }

                $needIloBridge = ipmiWebIsNormalizedIloType($effectiveType)
                    || ($effectiveType === 'generic'
                        && ($pathUsed === '/json/login_session' || str_contains($pathUsed, 'SessionService/Sessions')));
                if ($needIloBridge) {
                    ipmiWebIloEnsureSessionCookieForWebUi($baseUrl, $ip, $user, $pass, $cookieJar, $forwardHeaders);
                }
                if (!ipmiWebHasUsableBmcAuth($cookieJar, $forwardHeaders)) {
                    continue;
                }
                if (ipmiWebIsNormalizedIloType($effectiveType)) {
                    ipmiWebSyncIloSessionAndSessionKeyCookies($cookieJar);
                }
                if ($effectiveType === 'supermicro' && !ipmiWebSupermicroVerifyAuthed($baseUrl, $ip, $cookieJar)) {
                    ipmiWebDebugLog('autologin_attempt', [
                        'path' => (string) ($endpoint['path'] ?? ''),
                        'http' => $code,
                        'result' => 'supermicro_verify_failed',
                    ]);
                    continue;
                }
                if ($effectiveType === 'idrac' && !ipmiWebIdracVerifyAuthed($baseUrl, $ip, $cookieJar)) {
                    // iDRAC can still allocate a web session cookie even when our post-login page checks fail.
                    // Best effort logout here avoids leaking sessions and hitting iDRAC session-limit quickly.
                    $logoutOk = ipmiWebIdracAttemptLogout($baseUrl, $ip, $cookieJar);
                    $redfishCleanupOk = ipmiWebIdracCleanupSessionsViaRedfish(
                        $baseUrl,
                        $ip,
                        (string) $user,
                        (string) $pass,
                        20
                    );
                    $cleanupOk = $logoutOk || $redfishCleanupOk;
                    ipmiWebDebugLog('autologin_attempt', [
                        'path' => (string) ($endpoint['path'] ?? ''),
                        'http' => $code,
                        'result' => 'idrac_verify_failed',
                        'logout_ok' => $logoutOk ? 1 : 0,
                        'redfish_cleanup_ok' => $redfishCleanupOk ? 1 : 0,
                        'cleanup_ok' => $cleanupOk ? 1 : 0,
                    ]);
                    continue;
                }
                if (ipmiWebIsNormalizedIloType($effectiveType) && !ipmiWebIloVerifyAuthed($baseUrl, $ip, $cookieJar, $forwardHeaders)) {
                    ipmiWebDebugLog('autologin_attempt', [
                        'path' => (string) ($endpoint['path'] ?? ''),
                        'http' => $code,
                        'result' => 'ilo_verify_failed',
                    ]);
                    continue;
                }
                if ($effectiveType === 'ami' && !ipmiWebAmiVerifyAuthed($baseUrl, $ip, $cookieJar, $forwardHeaders)) {
                    ipmiWebDebugLog('autologin_attempt', [
                        'path' => (string) ($endpoint['path'] ?? ''),
                        'http' => $code,
                        'result' => 'ami_verify_failed',
                    ]);
                    continue;
                }
                $session['cookies'] = $cookieJar;
                $session['forward_headers'] = $forwardHeaders;
                $session['bmc_scheme'] = (strncasecmp($baseUrl, 'http://', 7) === 0) ? 'http' : 'https';

                ipmiWebDebugLog('autologin_success', [
                    'path' => (string) ($endpoint['path'] ?? ''),
                    'base' => $baseUrl,
                    'cookies' => array_keys(array_filter($cookieJar, 'ipmiWebIsAuthValueUsable')),
                ]);
                unset($session['auto_login_error']);
                return true;
            }

            // Credential failures are definitive for current endpoint family; avoid long retry storms.
            if ($failureReason === 'invalid_credentials') {
                $session['auto_login_error'] = 'invalid_credentials';
                ipmiWebDebugLog('autologin_failed_fast', [
                    'ip' => $ip,
                    'type' => $bmcType,
                    'reason' => 'invalid_credentials',
                ]);
                return false;
            }
        }
        }
    }

    $session['cookies'] = $prevCookies;
    $session['forward_headers'] = $prevHeaders;
    $session['bmc_scheme'] = $prevScheme;
    $session['auto_login_error'] = $firstFailureReason !== '' ? $firstFailureReason : 'unknown';

    ipmiWebDebugLog('autologin_failed', [
        'ip' => $ip,
        'type' => $bmcType,
        'reason' => $session['auto_login_error'],
    ]);
    return false;
}

function ipmiWebLoginEndpoints(string $bmcType, string $user, string $pass): array
{
    $type = ipmiWebNormalizeBmcType($bmcType);

    if (ipmiWebIsNormalizedIloType($type)) {
        $redfishBody = json_encode(['UserName' => $user, 'Password' => $pass], JSON_UNESCAPED_SLASHES);
        $redfishBodyHpe = json_encode([
            'UserName' => $user,
            'Password' => $pass,
            'Oem'      => ['Hpe' => ['LoginName' => $user]],
        ], JSON_UNESCAPED_SLASHES);
        $iloJsonLogin = [
            'path'   => '/json/login_session',
            'post'   => json_encode(['method' => 'login', 'user_login' => $user, 'password' => $pass]),
            'accept' => 'application/json, text/javascript, */*',
            'xhr'    => true,
        ];

        return [
            $iloJsonLogin,
            ['path' => '/redfish/v1/SessionService/Sessions', 'post' => $redfishBody, 'accept' => 'application/json', 'redfish' => true],
            ['path' => '/redfish/v1/SessionService/Sessions/', 'post' => $redfishBody, 'accept' => 'application/json', 'redfish' => true],
            ['path' => '/redfish/v1/SessionService/Sessions', 'post' => $redfishBodyHpe, 'accept' => 'application/json', 'redfish' => true],
        ];
    }

    switch ($type) {
        case 'supermicro':
            $smUser = base64_encode($user);
            $smPass = base64_encode(str_replace('\\', '\\\\', $pass));
            return [
                ['path' => '/cgi/login.cgi', 'post' => ['name' => $smUser, 'pwd' => $smPass, 'check' => '00']],
                ['path' => '/cgi/login.cgi', 'post' => ['name' => $user, 'pwd' => $pass]],
                ['path' => '/cgi/login.cgi', 'post' => ['username' => $user, 'password' => $pass]],
            ];
        case 'idrac':
            $redfishBody = json_encode(['UserName' => $user, 'Password' => $pass], JSON_UNESCAPED_SLASHES);

            return [
                ['path' => '/data/login', 'post' => ['user' => $user, 'password' => $pass]],
                ['path' => '/login.html', 'post' => ['user' => $user, 'password' => $pass]],
                ['path' => '/redfish/v1/SessionService/Sessions', 'post' => $redfishBody, 'accept' => 'application/json', 'redfish' => true],
                ['path' => '/redfish/v1/SessionService/Sessions/', 'post' => $redfishBody, 'accept' => 'application/json', 'redfish' => true],
            ];
        case 'ami':
            return [
                [
                    'path'   => '/api/session',
                    'post'   => ['username' => $user, 'password' => $pass],
                    'accept' => 'application/json, text/javascript, */*; q=0.01',
                    'xhr'    => true,
                ],
            ];
        default:
            $redfishBody = json_encode(['UserName' => $user, 'Password' => $pass], JSON_UNESCAPED_SLASHES);
            $iloJsonLogin = [
                'path'   => '/json/login_session',
                'post'   => json_encode(['method' => 'login', 'user_login' => $user, 'password' => $pass]),
                'accept' => 'application/json, text/javascript, */*',
                'xhr'    => true,
            ];

            return [
                $iloJsonLogin,
                ['path' => '/data/login', 'post' => ['user' => $user, 'password' => $pass]],
                [
                    'path'   => '/api/session',
                    'post'   => ['username' => $user, 'password' => $pass],
                    'accept' => 'application/json, text/javascript, */*; q=0.01',
                    'xhr'    => true,
                ],
                ['path' => '/redfish/v1/SessionService/Sessions', 'post' => $redfishBody, 'accept' => 'application/json', 'redfish' => true],
                ['path' => '/redfish/v1/SessionService/Sessions/', 'post' => $redfishBody, 'accept' => 'application/json', 'redfish' => true],
                ['path' => '/cgi/login.cgi', 'post' => ['name' => $user, 'pwd' => $pass]],
                ['path' => '/cgi/login.cgi', 'post' => ['username' => $user, 'password' => $pass]],
            ];
    }
}

/**
 * True when normalized type is a numbered iLO generation (ilo4, ilo5, ilo6, …).
 * Used instead of hardcoding === 'ilo4' across proxy/KVM paths.
 */
function ipmiWebIsNormalizedIloType(string $norm): bool
{
    return (bool) preg_match('/^ilo[0-9]+$/i', trim($norm));
}

/**
 * High-level vendor bucket for shared login/KVM logic (ilo, idrac, supermicro, ami, generic).
 * Prefer this over comparing a single flattened normalize() label for iLO generations.
 */
function ipmiWebBmcFamily(string $bmcType): string
{
    $raw = strtolower(trim(preg_replace('/\s+/', ' ', $bmcType)));
    if ($raw === '' || $raw === 'generic') {
        return 'generic';
    }
    $norm = ipmiWebNormalizeBmcType($bmcType);
    if (ipmiWebIsNormalizedIloType($norm) || $raw === 'ilo' || $raw === 'hpe' || $raw === 'hp' || str_contains($raw, 'integrated lights-out')) {
        return 'ilo';
    }
    if ($norm === 'idrac' || str_contains($raw, 'idrac') || $raw === 'dell' || str_contains($raw, 'poweredge')) {
        return 'idrac';
    }
    if ($norm === 'supermicro' || str_contains($raw, 'supermicro') || str_contains($raw, 'super micro') || str_contains($raw, 'supermiscro')) {
        return 'supermicro';
    }
    if ($norm === 'ami' || str_contains($raw, 'asrock') || str_contains($raw, 'ami-bmc') || $raw === 'ami') {
        return 'ami';
    }

    return 'generic';
}

/**
 * Best-effort firmware line (ilo5, ilo6, idrac9, …) for planner/debug; not always known from DB alone.
 */
function ipmiWebBmcVariant(string $bmcType): string
{
    $raw = strtolower(trim(preg_replace('/\s+/', ' ', $bmcType)));
    $norm = ipmiWebNormalizeBmcType($bmcType);
    if (ipmiWebIsNormalizedIloType($norm)) {
        return strtolower($norm);
    }
    if (preg_match('/ilo\s*([0-9]{1,2})\b/i', $raw, $m)) {
        return 'ilo' . (int) $m[1];
    }
    if (preg_match('/\bilo([0-9]{1,2})\b/i', $raw, $m)) {
        return 'ilo' . (int) $m[1];
    }
    if ($raw === 'ilo' || $raw === 'hpe' || $raw === 'hp') {
        // Unknown generation: prefer ilo5 for HTML5/Redfish-first behavior; explicit ilo4/ilo6 still come from DB.
        return 'ilo5';
    }
    if (preg_match('/idrac\s*([0-9]{1,2})\b/i', $raw, $m)) {
        return 'idrac' . (int) $m[1];
    }
    if (str_contains($raw, 'idrac')) {
        return 'idrac';
    }
    if ($norm === 'idrac') {
        return 'idrac';
    }
    if ($norm === 'supermicro') {
        return 'supermicro';
    }
    if ($norm === 'ami') {
        return 'ami';
    }

    return $norm !== '' && $norm !== 'generic' ? $norm : 'generic';
}

/**
 * Normalize BMC type for DB/session compatibility.
 * iLO generations are preserved (ilo5 ≠ ilo4). iDRAC stays a single normalized idrac; use ipmiWebBmcVariant() for idrac8/9 hints.
 */
function ipmiWebNormalizeBmcType(string $bmcType): string
{
    $type = strtolower(trim(preg_replace('/\s+/', ' ', str_replace('_', '-', $bmcType))));
    $aliases = [
        'supermiscro' => 'supermicro',
        'super micro' => 'supermicro',
        'asrockrack'  => 'ami',
        'asrock'      => 'ami',
        'ami'         => 'ami',
        'ami-bmc'     => 'ami',
        'dell'        => 'idrac',
        'idrac'       => 'idrac',
    ];
    if (isset($aliases[$type])) {
        return $aliases[$type];
    }
    if (in_array($type, ['supermicro', 'idrac', 'ami'], true)) {
        return $type;
    }
    // Numbered iLO: ilo5, ilo 5, ilo5-gen10, hpe-ilo6, …
    if (preg_match('/(?:^|[^a-z0-9])ilo\s*([0-9]{1,2})\b/i', $type, $m)) {
        return 'ilo' . (int) $m[1];
    }
    if (preg_match('/^ilo([0-9]{1,2})\b/i', $type, $m)) {
        return 'ilo' . (int) $m[1];
    }
    if ($type === 'ilo' || $type === 'hpe' || $type === 'hp') {
        return 'ilo5';
    }
    // Unnumbered "ilo" substring in free-text labels (e.g. vendor strings): default to ilo5, not legacy ilo4.
    if (str_contains($type, 'ilo')) {
        return 'ilo5';
    }

    return 'generic';
}

function ipmiWebCanPersistDetectedType(string $currentType, string $detectedType): bool
{
    $current = ipmiWebNormalizeBmcType($currentType);
    $detected = ipmiWebNormalizeBmcType($detectedType);
    if ($current !== 'generic') {
        return false;
    }

    return in_array($detected, ['supermicro', 'idrac', 'ami'], true)
        || ipmiWebIsNormalizedIloType($detected);
}

function ipmiWebPersistDetectedServerType(mysqli $mysqli, int $serverId, string $currentType, string $detectedType): void
{
    if ($serverId <= 0 || !ipmiWebCanPersistDetectedType($currentType, $detectedType)) {
        return;
    }
    $detected = ipmiWebNormalizeBmcType($detectedType);
    $stmt = $mysqli->prepare('UPDATE servers SET bmc_type = ? WHERE id = ? AND bmc_type = ? LIMIT 1');
    if ($stmt) {
        $generic = 'generic';
        $stmt->bind_param('sis', $detected, $serverId, $generic);
        $stmt->execute();
        $stmt->close();
    }
}

function ipmiWebPostLoginLandingPath(string $bmcType): string
{
    $fam = ipmiWebBmcFamily($bmcType);
    if ($fam === 'supermicro') {
        // Supermicro post-login container route.
        // Inner content is loaded from this shell; direct dashboard route can render as a broken subframe.
        return '/cgi/url_redirect.cgi?url_name=topmenu';
    }
    if ($fam === 'ilo') {
        // Some iLO builds return 404 on /html/application.html for top-level navigation.
        // /index.html is a safer authenticated entry and still loads the full UI shell.
        return '/index.html';
    }
    if ($fam === 'idrac') {
        // /start.html is often a pre-login launcher and can bounce to /login.html.
        // Use authenticated app entry to avoid login/start loops in proxy mode.
        return '/index.html';
    }
    if ($fam === 'ami') {
        return '/';
    }

    return '/';
}

/**
 * Structured vendor identity for KVM launch planning (family vs variant).
 *
 * @return array{raw_bmc_type: string, normalized_type: string, vendor_family: string, vendor_variant: string}
 */
function ipmiWebVendorProfile(array $session): array
{
    $raw = trim((string) ($session['bmc_type'] ?? 'generic'));

    return [
        'raw_bmc_type' => $raw,
        'normalized_type' => ipmiWebNormalizeBmcType($raw),
        'vendor_family'   => ipmiWebBmcFamily($raw),
        'vendor_variant'  => ipmiWebBmcVariant($raw),
    ];
}

/**
 * Rank candidate KVM paths using ipmiWebProbeKvmPath (for diagnostics / planner debug).
 *
 * @param list<string> $candidatePaths
 * @return array{ranked: list<array{path: string, probe: array<string, mixed>}>, best: ?array{path: string, probe: array<string, mixed>}}
 */
function ipmiWebProbeVendorNativeKvm(array $session, array $candidatePaths, array $options = []): array
{
    unset($options);
    $ranked = [];
    foreach ($candidatePaths as $p) {
        $p = (string) $p;
        if ($p === '') {
            continue;
        }
        $probe = ipmiWebProbeKvmPath($session, $p);
        $ranked[] = ['path' => $p, 'probe' => $probe];
    }
    usort($ranked, static function (array $a, array $b): int {
        $sa = (int) ($a['probe']['score'] ?? -999999);
        $sb = (int) ($b['probe']['score'] ?? -999999);

        return $sb <=> $sa;
    });
    $best = $ranked[0] ?? null;

    return ['ranked' => $ranked, 'best' => $best];
}

/**
 * Per-request cache for KVM launch plan (invalidated when BMC cookies are saved for the token).
 */
function ipmiWebKvmLaunchPlanCacheKey(array $session): string
{
    $tok = (string) ($session['token'] ?? '');
    $fam = ipmiWebBmcFamily((string) ($session['bmc_type'] ?? 'generic'));
    $ck = '0';
    if (!empty($session['cookies']) && is_array($session['cookies'])) {
        $parts = [];
        foreach ($session['cookies'] as $name => $value) {
            $n = strtolower(trim((string) $name));
            if ($n === '') {
                continue;
            }
            $parts[] = $n . '=' . hash('sha256', (string) $value);
        }
        sort($parts);
        $ck = (string) count($parts) . '|' . hash('sha256', implode("\n", $parts));
    }

    return $tok . "\t" . $fam . "\t" . $ck;
}

function ipmiWebKvmLaunchPlanCacheInvalidate(?mysqli $mysqli, string $token): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    if ($mysqli) {
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta): void {
            unset($meta['kvm_plan'], $meta['ilo_console_capability']);
        });
    }
    $g = &$GLOBALS['__ipmi_kvm_launch_plan_cache'];
    if (!is_array($g)) {
        return;
    }
    $prefix = $token . "\t";
    foreach (array_keys($g) as $k) {
        if (is_string($k) && str_starts_with($k, $prefix)) {
            unset($g[$k]);
        }
    }
}

/**
 * @param array<string, array{t: int, plan: array<string, mixed>}> $g
 */
function ipmiWebKvmLaunchPlanCachePut(array &$g, string $cacheKey, array $plan, ?mysqli $mysqli, string $token): void
{
    $g[$cacheKey] = ['t' => time(), 'plan' => $plan];
    if ($mysqli && preg_match('/^[a-f0-9]{64}$/', $token)) {
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($cacheKey, $plan): void {
            $meta['kvm_plan'] = [
                't'  => time(),
                'ck' => $cacheKey,
                'plan' => $plan,
            ];
        });
    }
}

/**
 * Vendor-native KVM launch plan: entry path, delivery mode, proxy patch/WS/cookie hints, debug trace.
 *
 * @return array{
 *   raw_bmc_type: string,
 *   vendor_family: string,
 *   vendor_variant: string,
 *   post_login_path: string,
 *   kvm_entry_path: string,
 *   mode: string,
 *   needs_ws_relay: bool,
 *   needs_cookie_mirror: bool,
 *   needs_runtime_patch: bool,
 *   fallback_path: string,
 *   debug: array<string, mixed>
 * }
 */
function ipmiWebResolveKvmLaunchPlan(array $session, ?mysqli $persistMetaMysqli = null): array
{
    $g = &$GLOBALS['__ipmi_kvm_launch_plan_cache'];
    if (!is_array($g)) {
        $g = [];
    }
    $cacheKey = ipmiWebKvmLaunchPlanCacheKey($session);
    $tok = (string) ($session['token'] ?? '');
    $forceReplan = $tok !== ''
        && isset($GLOBALS['__ipmi_kvm_force_replan_for_token'])
        && is_string($GLOBALS['__ipmi_kvm_force_replan_for_token'])
        && hash_equals($tok, $GLOBALS['__ipmi_kvm_force_replan_for_token']);
    if ($forceReplan) {
        unset($GLOBALS['__ipmi_kvm_force_replan_for_token']);
        if (function_exists('ipmiProxyDebugLog') && function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('kvm_plan_recomputed_after_stall', [
                'vendor_family' => ipmiWebBmcFamily((string) ($session['bmc_type'] ?? 'generic')),
            ]);
        }
    } elseif (!$forceReplan) {
        $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
        $kp = $meta['kvm_plan'] ?? null;
        if (is_array($kp) && isset($kp['plan'], $kp['ck'], $kp['t']) && (string) $kp['ck'] === $cacheKey && is_array($kp['plan'])) {
            $ageDb = time() - (int) $kp['t'];
            if ($ageDb >= 0 && $ageDb < 120) {
                $cachedPlan = $kp['plan'];
                $cachedPlan['debug']['plan_source'] = 'cache_hit_db';
                $cachedPlan['debug']['plan_cache_age_sec'] = $ageDb;
                if (function_exists('ipmiProxyDebugLog') && function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('kvm_plan_cache_hit', [
                        'scope'          => 'db',
                        'age_sec'        => $ageDb,
                        'vendor_family'  => (string) ($cachedPlan['vendor_family'] ?? ''),
                        'vendor_variant' => (string) ($cachedPlan['vendor_variant'] ?? ''),
                    ]);
                }

                return $cachedPlan;
            }
            if (function_exists('ipmiProxyDebugLog') && function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled() && $ageDb >= 120) {
                ipmiProxyDebugLog('kvm_plan_cache_expired', [
                    'scope'   => 'db',
                    'age_sec' => $ageDb,
                ]);
            }
        } elseif (function_exists('ipmiProxyDebugLog') && function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()
            && is_array($kp) && isset($kp['ck']) && (string) $kp['ck'] !== $cacheKey) {
            ipmiProxyDebugLog('kvm_plan_cache_miss', [
                'reason' => 'cookie_key_mismatch',
                'scope'  => 'db',
            ]);
        }
    }
    if (!$forceReplan && isset($g[$cacheKey]) && is_array($g[$cacheKey])) {
        $age = time() - (int) ($g[$cacheKey]['t'] ?? 0);
        if ($age >= 0 && $age < 120 && is_array($g[$cacheKey]['plan'] ?? null)) {
            $cachedPlan = $g[$cacheKey]['plan'];
            $cachedPlan['debug']['plan_source'] = 'request_memo_hit';
            $cachedPlan['debug']['plan_cache_age_sec'] = $age;
            if (function_exists('ipmiProxyDebugLog') && function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('kvm_plan_cache_hit', [
                    'scope'          => 'request',
                    'age_sec'        => $age,
                    'vendor_family'  => (string) ($cachedPlan['vendor_family'] ?? ''),
                    'vendor_variant' => (string) ($cachedPlan['vendor_variant'] ?? ''),
                ]);
            }

            return $cachedPlan;
        }
    }
    if (function_exists('ipmiProxyDebugLog') && function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
        $reason = 'no_entry';
        if (isset($g[$cacheKey]) && is_array($g[$cacheKey])) {
            $staleAge = time() - (int) ($g[$cacheKey]['t'] ?? 0);
            $reason = ($staleAge >= 120) ? 'expired' : 'invalid_shape';
        }
        $fam = ipmiWebBmcFamily((string) ($session['bmc_type'] ?? 'generic'));
        if ($forceReplan) {
            // Already logged kvm_plan_recomputed_after_stall
        } elseif ($reason === 'expired') {
            ipmiProxyDebugLog('kvm_plan_recomputed', ['reason' => $reason, 'vendor_family' => $fam]);
        } else {
            ipmiProxyDebugLog('kvm_plan_cache_miss', ['reason' => $reason, 'vendor_family' => $fam, 'scope' => 'compute']);
        }
    }

    $profile = ipmiWebVendorProfile($session);
    $family = $profile['vendor_family'];
    $variant = $profile['vendor_variant'];
    $postLogin = ipmiWebPostLoginLandingPath((string) ($session['bmc_type'] ?? 'generic'));
    $debug = [
        'profile'        => $profile,
        'candidates'     => [],
        'selection_note' => '',
        'plan_source'    => 'computed',
    ];
    $plan = [
        'raw_bmc_type'        => $profile['raw_bmc_type'],
        'vendor_family'       => $family,
        'vendor_variant'      => $variant,
        'post_login_path'     => $postLogin,
        'kvm_entry_path'      => '/',
        'mode'                => 'fallback',
        'needs_ws_relay'      => false,
        'needs_cookie_mirror' => true,
        'needs_runtime_patch' => false,
        'fallback_path'       => '/',
        'launch_strategy'     => '',
        'shell_entry_path'    => '',
        'console_bootstrap_path' => '',
        'renderer_direct_possible' => false,
        'html5_markers'       => false,
        'requires_client_bootstrap' => false,
        'console_ready_timeout_ms' => 45000,
        'interactive_success_markers' => ['renderer_connected', 'visible_canvas', 'ws_relay_seen'],
        'bootstrap_markers'   => [],
        'transport_markers'   => ['ipmi_ws_relay', 'websocket'],
        'stall_markers'       => ['no_transport', 'no_interactive', 'known_error_text'],
        'debug'               => $debug,
    ];

    if ($family === 'ilo') {
        $candidates = [
            '/html/application.html?ipmi_kvm_auto=1&ipmi_kvm_force_html5=1',
            '/html/application.html?ipmi_kvm_auto=1',
            '/index.html?ipmi_kvm_auto=1',
            '/html/rc_info.html',
            '/html/irc.html',
            '/index.html',
        ];
        $ranked = ipmiWebProbeVendorNativeKvm($session, $candidates);
        $plan['debug']['ranked'] = $ranked['ranked'];
        $iloHtml5 = ipmiWebIloSupportsStandaloneHtml5Kvm($session);
        $plan['html5_markers'] = $iloHtml5;
        $bestRow = $ranked['ranked'][0] ?? null;
        $bestProbe = is_array($bestRow) ? ($bestRow['probe'] ?? []) : [];
        $bestPath = is_array($bestRow) ? (string) ($bestRow['path'] ?? '') : '';

        $shellPackForCap = ipmiWebIloAnalyzeShellForConsoleCapability($session, '/index.html');
        $cap = ipmiWebIloConsoleCapability($session, $persistMetaMysqli, [
            'ranked_rows' => $ranked['ranked'],
            'ilo_html5'   => $iloHtml5,
            'shell_pack'  => $shellPackForCap,
        ]);
        $plan['console_capability'] = (string) ($cap['capability'] ?? 'unknown');
        $plan['console_capability_confidence'] = (int) ($cap['confidence'] ?? 0);
        $plan['native_launch_viable'] = !empty($cap['should_attempt_proxy_autolaunch']);
        $plan['native_launch_reason'] = implode(';', array_slice((array) ($cap['reasons'] ?? []), 0, 8));
        $plan['native_launch_blockers'] = array_slice((array) ($cap['blockers'] ?? []), 0, 12);
        $plan['ilo_native_console_verdict'] = (string) ($cap['ilo_native_console_verdict'] ?? 'native_html5_unconfirmed');
        $plan['autolaunch_suppression_detail'] = (string) ($cap['autolaunch_suppression_detail'] ?? '');
        $plan['shell_authenticated_hint'] = !empty($cap['shell_authenticated']) ? 1 : 0;
        $plan['shell_bootstrap_healthy_hint'] = !empty($cap['shell_bootstrap_healthy']) ? 1 : 0;
        $plan['should_attempt_proxy_autolaunch'] = !empty($cap['should_attempt_proxy_autolaunch']);
        $plan['should_fallback_to_shell_only'] = !empty($cap['should_fallback_to_shell_only']);
        $plan['should_offer_legacy_or_alt_fallback'] = !empty($cap['should_offer_legacy_or_alt_fallback']);
        $plan['debug']['ilo_console_capability'] = [
            'capability'   => $plan['console_capability'],
            'verdict'      => $plan['ilo_native_console_verdict'],
            'confidence'   => $plan['console_capability_confidence'],
            'attempt_auto' => $plan['should_attempt_proxy_autolaunch'] ? 1 : 0,
        ];

        $strategy = 'ilo_application_autolaunch';
        $kvmPath = '/html/application.html?ipmi_kvm_auto=1';
        if ($iloHtml5) {
            $kvmPath = '/html/application.html?ipmi_kvm_auto=1&ipmi_kvm_force_html5=1';
            $strategy = 'ilo_application_force_html5';
        } elseif ($bestPath !== ''
            && str_contains($bestPath, 'irc.html')
            && !empty($bestProbe['browser_native_like'])
            && empty($bestProbe['login_like'])
            && empty($bestProbe['unavailable'])
        ) {
            $kvmPath = '/html/irc.html';
            $strategy = 'ilo_irc_bootstrap';
        } elseif ($bestPath !== ''
            && str_contains($bestPath, 'rc_info')
            && !empty($bestProbe['vendor_shell_like'])
            && empty($bestProbe['login_like'])
            && (int) ($bestProbe['score'] ?? 0) >= 40
        ) {
            $kvmPath = '/html/rc_info.html';
            $strategy = 'ilo_rc_info_first';
        }

        if (!$plan['should_attempt_proxy_autolaunch']) {
            if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_console_capability_declined_native', [
                    'capability' => $plan['console_capability'],
                    'verdict'    => $plan['ilo_native_console_verdict'],
                ]);
                ipmiProxyDebugLog('ilo_autolaunch_suppressed', [
                    'reason' => 'capability_not_proven',
                    'verdict'=> $plan['ilo_native_console_verdict'],
                ]);
            }
            $strategy = (string) ($cap['recommended_strategy'] ?? 'ilo_shell_only');
            if ($strategy === 'ilo_shell_degraded_wait'
                || $strategy === 'ilo_shell_only'
                || $strategy === 'ilo_shell_only_legacy_fallback'
                || $strategy === 'ilo_license_or_feature_gate') {
                $kvmPath = '/index.html?ipmi_kvm_auto=1';
            } elseif ($strategy === 'ilo_shell_explore' || $strategy === 'ilo_manual_navigation') {
                $kvmPath = '/index.html';
            }
            $plan['requires_client_bootstrap'] = false;
            $plan['console_ready_timeout_ms'] = 14000;
            $plan['renderer_direct_possible'] = false;
        } elseif ($plan['console_capability'] === 'html5_native_possible_but_unconfirmed') {
            $strategy = 'ilo_speculative_shell_autolaunch';
            $kvmPath = '/index.html?ipmi_kvm_auto=1';
            $plan['console_ready_timeout_ms'] = 34000;
            $plan['renderer_direct_possible'] = $iloHtml5 || !empty($bestProbe['browser_native_like']);
        } else {
            $plan['console_ready_timeout_ms'] = 52000;
            $plan['renderer_direct_possible'] = $iloHtml5 || !empty($bestProbe['browser_native_like']);
        }

        $plan['kvm_entry_path'] = $kvmPath;
        $plan['shell_entry_path'] = '/index.html';
        $plan['console_bootstrap_path'] = '/html/rc_info.html';
        $plan['launch_strategy'] = $strategy;
        if ($plan['should_attempt_proxy_autolaunch']) {
            $plan['requires_client_bootstrap'] = !str_contains($kvmPath, 'irc.html');
        }
        $plan['mode'] = 'proxy_autolaunch';
        $plan['needs_runtime_patch'] = true;
        $plan['needs_ws_relay'] = true;
        $plan['fallback_path'] = '/index.html';
        $plan['debug']['selection_note'] = 'iLO: strategy=' . $strategy . '; ranked_top=' . $bestPath
            . '; html5=' . ($iloHtml5 ? '1' : '0') . '; score=' . (int) ($bestProbe['score'] ?? 0)
            . '; cap=' . $plan['console_capability'] . '; verdict=' . $plan['ilo_native_console_verdict'];
        $plan['debug']['ilo_html5_probe'] = $iloHtml5 ? 1 : 0;
        $plan['bootstrap_markers'] = ['ilo_shell', 'ilo_rc_bootstrap', 'ilo_html5_markers'];
        $plan['transport_markers'] = ['ipmi_ws_relay', 'websocket', 'renderer_connected'];
        $plan['interactive_success_markers'] = ['console_visible', 'irc_window', 'canvas'];

        if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_native_console_verdict', [
                'verdict' => $plan['ilo_native_console_verdict'],
                'capability' => $plan['console_capability'],
                'strategy'   => $strategy,
            ]);
        }

        ipmiWebKvmLaunchPlanCachePut($g, $cacheKey, $plan, $persistMetaMysqli, $tok);

        return $plan;
    }

    if ($family === 'idrac') {
        $candidates = [
            '/index.html',
            '/restgui/start.html',
            '/viewer.html',
            '/console.html',
            '/restgui/launch',
            '/start.html',
        ];
        $rankedIdrac = ipmiWebProbeVendorNativeKvm($session, $candidates);
        $plan['debug']['ranked'] = $rankedIdrac['ranked'];
        $picked = ipmiWebPickReachablePath($session, $candidates, '/index.html', true);
        $pr = null;
        foreach ($rankedIdrac['ranked'] as $row) {
            if (($row['path'] ?? '') === $picked && isset($row['probe'])) {
                $pr = $row['probe'];
                break;
            }
        }
        if (!is_array($pr)) {
            $pr = ipmiWebProbeKvmPath($session, $picked);
        }
        $plan['debug']['picked'] = ['path' => $picked, 'probe' => $pr];
        $plan['kvm_entry_path'] = $picked;
        if (!empty($pr['browser_native_like'])) {
            $plan['mode'] = 'browser_html5';
            $plan['debug']['selection_note'] = 'iDRAC: browser-native markers on picked path.';
        } elseif (!empty($pr['vendor_shell_like']) && empty($pr['login_like'])) {
            $plan['mode'] = 'proxy_autolaunch';
            $plan['needs_runtime_patch'] = true;
            $plan['debug']['selection_note'] = 'iDRAC: authenticated launcher/shell; client navigation may be required.';
        } else {
            $plan['mode'] = 'proxy_autolaunch';
            $plan['needs_runtime_patch'] = true;
            $plan['debug']['selection_note'] = 'iDRAC: default autolaunch path (probe ambiguous or shell pending).';
        }
        $plan['needs_ws_relay'] = !empty($pr['ws_like']);
        $plan['fallback_path'] = '/index.html?ipmi_kvm_unavailable=1';
        $plan['shell_entry_path'] = '/index.html';
        $plan['console_bootstrap_path'] = '/viewer.html';
        $plan['launch_strategy'] = 'idrac_' . preg_replace('#[^a-z0-9]+#i', '_', $picked);
        $plan['renderer_direct_possible'] = !empty($pr['browser_native_like']);
        $plan['requires_client_bootstrap'] = !empty($plan['needs_runtime_patch']);
        $plan['console_ready_timeout_ms'] = 48000;
        $plan['bootstrap_markers'] = ['idrac_shell', 'idrac_viewer_markers', 'idrac_launcher'];
        $plan['transport_markers'] = ['ipmi_ws_relay', 'websocket', 'avct'];
        $plan['interactive_success_markers'] = ['canvas', 'viewer_active'];

        ipmiWebKvmLaunchPlanCachePut($g, $cacheKey, $plan, $persistMetaMysqli, $tok);

        return $plan;
    }

    if ($family === 'supermicro') {
        $candidates = [
            '/cgi/url_redirect.cgi?url_name=ikvm&url_type=html5',
            '/cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk',
            '/cgi/url_redirect.cgi?url_name=ikvm',
        ];
        $rankedSm = ipmiWebProbeVendorNativeKvm($session, $candidates);
        $plan['debug']['ranked'] = $rankedSm['ranked'];
        $picked = ipmiWebPickReachablePath($session, $candidates, '/cgi/url_redirect.cgi?url_name=topmenu&ipmi_kvm_unavailable=1', true);
        $pr = null;
        foreach ($rankedSm['ranked'] as $row) {
            if (($row['path'] ?? '') === $picked && isset($row['probe'])) {
                $pr = $row['probe'];
                break;
            }
        }
        if (!is_array($pr)) {
            $pr = ipmiWebProbeKvmPath($session, $picked);
        }
        $plan['debug']['picked'] = ['path' => $picked, 'probe' => $pr];
        $plan['kvm_entry_path'] = $picked;
        if (!empty($pr['browser_native_like'])) {
            $plan['mode'] = 'browser_html5';
        } else {
            $plan['mode'] = 'proxy_autolaunch';
        }
        $plan['needs_runtime_patch'] = !empty($pr['vendor_shell_like']) && empty($pr['browser_native_like']);
        $plan['fallback_path'] = '/cgi/url_redirect.cgi?url_name=topmenu&ipmi_kvm_unavailable=1';
        $plan['debug']['selection_note'] = 'Supermicro: prefer html5 IKVM redirect when reachable.';
        $plan['shell_entry_path'] = '/cgi/url_redirect.cgi?url_name=topmenu';
        $plan['console_bootstrap_path'] = $picked;
        $plan['launch_strategy'] = 'supermicro_ikvm';
        $plan['renderer_direct_possible'] = !empty($pr['browser_native_like']);
        $plan['requires_client_bootstrap'] = !empty($plan['needs_runtime_patch']);
        $plan['console_ready_timeout_ms'] = 50000;
        $plan['bootstrap_markers'] = ['supermicro_shell', 'supermicro_html5', 'ikvm_route'];
        $plan['transport_markers'] = ['ipmi_ws_relay', 'websocket'];
        $plan['interactive_success_markers'] = ['canvas', 'ikvm_active'];

        ipmiWebKvmLaunchPlanCachePut($g, $cacheKey, $plan, $persistMetaMysqli, $tok);

        return $plan;
    }

    if ($family === 'ami') {
        $plan['kvm_entry_path'] = '/';
        $plan['mode'] = 'browser_html5';
        $plan['needs_runtime_patch'] = true;
        $plan['debug']['selection_note'] = 'AMI/ASRock: SPA entry at /.';
        $plan['launch_strategy'] = 'ami_spa';

        ipmiWebKvmLaunchPlanCachePut($g, $cacheKey, $plan, $persistMetaMysqli, $tok);

        return $plan;
    }

    $plan['kvm_entry_path'] = '/';
    $plan['debug']['selection_note'] = 'generic: no vendor-specific KVM plan.';
    $plan['launch_strategy'] = 'generic';

    ipmiWebKvmLaunchPlanCachePut($g, $cacheKey, $plan, $persistMetaMysqli, $tok);

    return $plan;
}

/**
 * Compact plan summary for debug logs (no cookies, tokens, or full HTML).
 *
 * @return array<string, mixed>
 */
function ipmiWebKvmPlanLogSummary(array $plan): array
{
    $dbg = $plan['debug'] ?? [];
    $ranked = $dbg['ranked'] ?? [];
    if (!is_array($ranked)) {
        $ranked = [];
    }
    $rows = [];
    foreach (array_slice($ranked, 0, 8) as $entry) {
        $p = (string) ($entry['path'] ?? '');
        $pr = $entry['probe'] ?? [];
        if (!is_array($pr)) {
            $pr = [];
        }
        $rows[] = [
            'path'   => $p,
            'score'  => $pr['score'] ?? null,
            'http'   => $pr['code'] ?? null,
            'login'  => !empty($pr['login'] ?? $pr['login_like'] ?? false),
            'native' => !empty($pr['browser_native_like'] ?? false),
            'shell'  => !empty($pr['vendor_shell_like'] ?? false),
            'markers'=> array_slice($pr['markers'] ?? [], 0, 5),
        ];
    }
    $picked = $dbg['picked'] ?? null;
    $pickedRow = null;
    if (is_array($picked)) {
        $ppr = $picked['probe'] ?? [];
        $pickedRow = [
            'path' => (string) ($picked['path'] ?? ''),
            'score' => is_array($ppr) ? ($ppr['score'] ?? null) : null,
        ];
    }

    return [
        'raw_bmc_type'   => (string) ($plan['raw_bmc_type'] ?? ''),
        'vendor_family'  => (string) ($plan['vendor_family'] ?? ''),
        'vendor_variant' => (string) ($plan['vendor_variant'] ?? ''),
        'kvm_entry_path' => (string) ($plan['kvm_entry_path'] ?? ''),
        'launch_strategy'=> (string) ($plan['launch_strategy'] ?? ''),
        'plan_source'    => (string) ($dbg['plan_source'] ?? ''),
        'plan_cache_age_sec' => $dbg['plan_cache_age_sec'] ?? null,
        'mode'           => (string) ($plan['mode'] ?? ''),
        'note'           => (string) ($dbg['selection_note'] ?? ''),
        'ranked'         => $rows,
        'picked'         => $pickedRow,
        'shell_entry'    => (string) ($plan['shell_entry_path'] ?? ''),
        'console_boot'   => (string) ($plan['console_bootstrap_path'] ?? ''),
        'console_ready_timeout_ms' => (int) ($plan['console_ready_timeout_ms'] ?? 45000),
        'bootstrap_markers' => is_array($plan['bootstrap_markers'] ?? null) ? array_slice($plan['bootstrap_markers'], 0, 12) : [],
        'transport_markers' => is_array($plan['transport_markers'] ?? null) ? array_slice($plan['transport_markers'], 0, 12) : [],
        'interactive_success_markers' => is_array($plan['interactive_success_markers'] ?? null) ? array_slice($plan['interactive_success_markers'], 0, 12) : [],
        'console_capability' => (string) ($plan['console_capability'] ?? ''),
        'ilo_native_console_verdict' => (string) ($plan['ilo_native_console_verdict'] ?? ''),
        'native_launch_viable' => !empty($plan['native_launch_viable']) ? 1 : 0,
        'should_attempt_proxy_autolaunch' => !empty($plan['should_attempt_proxy_autolaunch']) ? 1 : 0,
        'shell_authenticated_hint' => (int) ($plan['shell_authenticated_hint'] ?? 0),
        'shell_bootstrap_healthy_hint' => (int) ($plan['shell_bootstrap_healthy_hint'] ?? 0),
    ];
}

function ipmiWebKvmConsolePath(array $session): string
{
    $plan = ipmiWebResolveKvmLaunchPlan($session);

    return (string) ($plan['kvm_entry_path'] ?? '/');
}

function ipmiWebKvmConsoleUrl(array $session): string
{
    $path = ipmiWebKvmConsolePath($session);

    return ipmiWebBuildProxyUrl($session['token'], $path);
}

function ipmiWebKvmPathLooksConsoleLike(string $path, string $body): bool
{
    if (str_contains(strtolower($path), 'ipmi_kvm_auto=1')) {
        return true;
    }
    $p = strtolower((string) parse_url($path, PHP_URL_PATH));
    if ($p === '') {
        $p = strtolower($path);
    }
    if (str_contains($p, 'ikvm')
        || str_contains($p, 'viewer')
        || str_contains($p, 'console')
        || str_contains($p, 'irc')
        || str_contains($p, 'intgapp')
    ) {
        return true;
    }

    $sample = strtolower(substr((string) $body, 0, 200000));
    if ($sample === '') {
        return false;
    }

    return str_contains($sample, 'remote console')
        || str_contains($sample, 'ikvm')
        || str_contains($sample, 'jviewer')
        || str_contains($sample, 'avct')
        || str_contains($sample, 'novnc')
        || str_contains($sample, 'launch console')
        || str_contains($sample, 'launch kvm');
}

function ipmiWebKvmDeliveryMode(string $path, string $contentType, string $body): string
{
    $p = strtolower((string) $path);
    $ct = strtolower((string) $contentType);
    $sample = strtolower(substr((string) $body, 0, 200000));
    if (str_contains($p, 'ipmi_kvm_auto=1')) {
        return 'proxy_autolaunch';
    }
    if (str_contains($ct, 'application/x-ms-application')) {
        return 'clickonce';
    }
    if (str_contains($ct, 'application/x-java-jnlp-file')) {
        return 'jnlp';
    }
    if (str_contains($p, 'java_irc') || str_contains($sample, 'applet-based console')) {
        return 'java_applet';
    }
    if (str_contains($ct, 'text/html')) {
        return 'html';
    }

    return 'other';
}

function ipmiWebIloSupportsStandaloneHtml5Kvm(array $session): bool
{
    // Prefer content-aware probes: some builds return 200 on /html/irc.html with a shell or
    // redirect to HTML5 paths; others expose markers only on application.html.
    $paths = ['/html/irc.html', '/html/application.html', '/index.html'];
    foreach ($paths as $p) {
        $probe = ipmiWebProbeKvmPath($session, $p);
        if (!empty($probe['browser_native_like']) && empty($probe['login_like']) && empty($probe['unavailable'])) {
            return true;
        }
        $code = (int) ($probe['code'] ?? 0);
        if ($code >= 200 && $code < 400 && empty($probe['login_like']) && empty($probe['unavailable']) && empty($probe['unavailable_like'])) {
            $markers = $probe['markers'] ?? [];
            if (is_array($markers) && (in_array('ilo_html5_markers', $markers, true) || in_array('ilo_renderer', $markers, true))) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Fetch HTML from BMC for iLO shell/console analysis (bounded body).
 *
 * @return array{code: int, body: string, login_like: bool}
 */
function ipmiWebIloProbePathBodySample(array $session, string $path, int $maxBytes = 240000): array
{
    $ip = trim((string) ($session['ipmi_ip'] ?? ''));
    if ($ip === '') {
        return ['code' => 0, 'body' => '', 'login_like' => true];
    }
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $url = $scheme . '://' . $ip . '/' . ltrim($path, '/');
    $cookieHeader = ipmiWebBuildCookieString($session);
    $ch = curl_init($url);
    $appliedResolve = ipmiBmcApplyCurlUrlAndResolve($ch, $url, $ip);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 8);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_ENCODING, '');
    curl_setopt($ch, CURLOPT_HTTPGET, true);
    curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
    if ($cookieHeader !== '') {
        curl_setopt($ch, CURLOPT_COOKIE, $cookieHeader);
    }
    $reqHeaders = [];
    $fh = $session['forward_headers'] ?? [];
    if (is_array($fh)) {
        foreach ($fh as $hn => $hv) {
            $hn = trim((string) $hn);
            if ($hn === '' || strcasecmp($hn, 'Cookie') === 0) {
                continue;
            }
            $reqHeaders[] = $hn . ': ' . $hv;
        }
    }
    if ($reqHeaders !== []) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);
    }
    $raw = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (($raw === false || $code === 0) && $appliedResolve) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 8);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        if ($cookieHeader !== '') {
            curl_setopt($ch, CURLOPT_COOKIE, $cookieHeader);
        }
        if ($reqHeaders !== []) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);
        }
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
    }
    $body = '';
    if (is_string($raw) && $raw !== '') {
        [, $respBody] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
        $body = (string) $respBody;
        if (strlen($body) > $maxBytes) {
            $body = substr($body, 0, $maxBytes);
        }
    }
    $loginLike = ipmiWebResponseLooksLikeBmcLoginPage($body, 'text/html');
    if ($loginLike && ipmiWebResponseLooksLikeIloAuthedShell($body)) {
        $loginLike = false;
    }

    return ['code' => $code, 'body' => $body, 'login_like' => $loginLike];
}

/**
 * @return array<string, mixed>
 */
function ipmiWebIloAnalyzeDocumentForLaunchSurface(string $html): array
{
    $s = strtolower(substr($html, 0, 220000));
    $reasons = [];
    $evidence = [];
    $html5 = false;
    $legacy = false;
    $license = false;
    $rcRef = false;
    if ($s === '') {
        return [
            'has_launch_surface'       => false,
            'html5_native_markers'     => false,
            'legacy_java_markers'      => false,
            'license_gated_markers'    => false,
            'remote_console_refs'      => false,
            'iframe_console_refs'      => false,
            'reasons'                  => ['empty_body'],
            'evidence'               => [],
        ];
    }
    if (str_contains($s, 'starthtml5irc')
        || str_contains($s, 'start_html5_irc')
        || str_contains($s, 'ilo.starthtml5')
        || (str_contains($s, 'html5') && str_contains($s, 'integrated remote console'))
        || str_contains($s, 'html5 irc')
        || str_contains($s, 'ircwindow')
        || str_contains($s, 'hrcbutton')
        || (str_contains($s, 'new renderer') && str_contains($s, 'irc'))
        || str_contains($s, 'htmlircwindowmode')) {
        $html5 = true;
        $reasons[] = 'html5_marker';
        $evidence[] = 'html5_console_marker';
    }
    if (str_contains($s, 'remote console') || str_contains($s, 'remote control') || str_contains($s, 'virtual media')
        || str_contains($s, 'launch console') || str_contains($s, 'kvm')) {
        $rcRef = true;
        $reasons[] = 'remote_console_text';
    }
    $iframeConsoleSignal = (str_contains($s, '<iframe') || str_contains($s, 'framecontent'))
        && (str_contains($s, 'irc') || str_contains($s, 'rc_info') || str_contains($s, 'console'));
    if ($iframeConsoleSignal) {
        $reasons[] = 'iframe_console';
        $evidence[] = 'iframe_console_pattern';
    }
    if (str_contains($s, 'java integrated remote console')
        || str_contains($s, 'applet-based console')
        || str_contains($s, '.net integrated remote console')
        || (str_contains($s, 'java') && str_contains($s, 'jnlp') && str_contains($s, 'console'))) {
        $legacy = true;
        $reasons[] = 'legacy_java_net';
        $evidence[] = 'legacy_console_marker';
    }
    if (str_contains($s, 'license') && (str_contains($s, 'remote') || str_contains($s, 'ilo advanced') || str_contains($s, 'not available'))
        || str_contains($s, 'evaluation license')
        || str_contains($s, 'requires an advanced license')) {
        $license = true;
        $reasons[] = 'license_language';
        $evidence[] = 'license_gated_text';
    }
    $hasSurface = $html5
        || $iframeConsoleSignal
        || (($rcRef || str_contains($s, 'ilo.')) && (str_contains($s, 'framecontent') || str_contains($s, 'html/application') || str_contains($s, 'rc_info')));

    return [
        'has_launch_surface'    => $hasSurface,
        'html5_native_markers'  => $html5,
        'legacy_java_markers'   => $legacy,
        'license_gated_markers' => $license,
        'remote_console_refs'   => $rcRef,
        'iframe_console_refs'   => str_contains($s, 'iframe') && (str_contains($s, 'irc') || str_contains($s, 'console')),
        'reasons'               => $reasons,
        'evidence'              => array_slice(array_unique($evidence), 0, 12),
    ];
}

function ipmiWebIloLooksLegacyOnlyFromAnalysis(array $analysis): bool
{
    return !empty($analysis['legacy_java_markers']) && empty($analysis['html5_native_markers']);
}

function ipmiWebIloLooksLicenseGatedFromAnalysis(array $analysis): bool
{
    return !empty($analysis['license_gated_markers']);
}

/**
 * Score current shell HTML for native-console launch surface (0–100). Higher = stronger live evidence.
 *
 * @param array<string, mixed> $surface from ipmiWebIloAnalyzeDocumentForLaunchSurface
 */
function ipmiWebIloCurrentSurfaceEvidenceScore(array $surface): int
{
    $score = 0;
    if (!empty($surface['html5_native_markers'])) {
        $score += 48;
    }
    if (!empty($surface['iframe_console_refs'])) {
        $score += 38;
    }
    $reasons = is_array($surface['reasons'] ?? null) ? $surface['reasons'] : [];
    foreach ($reasons as $r) {
        if ($r === 'iframe_console') {
            $score += 34;
        } elseif ($r === 'html5_marker') {
            $score += 40;
        } elseif ($r === 'remote_console_text') {
            $score += 22;
        }
    }
    if (!empty($surface['has_launch_surface'])) {
        $score += 18;
    }

    return min(100, $score);
}

/**
 * Weight stale pessimistic session signals (0–100). Used only for confidence / logging — not to veto surface alone.
 *
 * @param array<string, mixed> $bootstrapMeta from ipmiWebIloBootstrapMetaFromSession
 */
function ipmiWebIloHistoricalFailureWeight(array $bootstrapMeta): int
{
    $w = 0;
    $phase = (string) ($bootstrapMeta['phase'] ?? '');
    if ($phase === 'stalled') {
        $w += 40;
    } elseif (in_array($phase, ['degraded', 'bootstrapping'], true)) {
        $w += 18;
    }
    $streak = (int) ($bootstrapMeta['sse_fail_streak'] ?? 0);
    $w += min(36, $streak * 10);
    if (!empty($bootstrapMeta['runtime_stall_signal'])) {
        $w += 22;
    }
    if (($bootstrapMeta['masthead_fragment_ok'] ?? null) === false) {
        $w += 12;
    }
    if (($bootstrapMeta['preflight_bootstrap_ok'] ?? null) === false) {
        $w += 10;
    }

    return min(100, $w);
}

/**
 * @return array{v: int, spent: int, max: int}
 */
function ipmiWebIloBoundedLaunchBudgetFromSession(array $session): array
{
    $m = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $b = is_array($m['ilo_bounded_native_launch'] ?? null) ? $m['ilo_bounded_native_launch'] : [];
    if ((int) ($b['v'] ?? 0) !== 1) {
        return ['v' => 1, 'spent' => 0, 'max' => 1];
    }

    return [
        'v'     => 1,
        'spent' => min(1, (int) ($b['spent'] ?? 0)),
        'max'   => 1,
    ];
}

function ipmiWebIloBoundedLaunchCanSpend(array $session): bool
{
    $b = ipmiWebIloBoundedLaunchBudgetFromSession($session);

    return $b['spent'] < $b['max'];
}

/**
 * Record one bounded native autolaunch attempt (server-side budget). Pair with capability “surface present” path.
 */
function ipmiWebIloBoundedLaunchBudgetRecordSpend(?mysqli $mysqli, string $token, array &$session): void
{
    if (!$mysqli || !preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta): void {
        $b = is_array($meta['ilo_bounded_native_launch'] ?? null) ? $meta['ilo_bounded_native_launch'] : [];
        if ((int) ($b['v'] ?? 0) !== 1) {
            $b = ['v' => 1, 'spent' => 0];
        }
        $b['spent'] = min(1, (int) ($b['spent'] ?? 0) + 1);
        $b['t'] = time();
        $meta['ilo_bounded_native_launch'] = $b;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $cur = ipmiWebIloBoundedLaunchBudgetFromSession($session);
    $session['session_meta']['ilo_bounded_native_launch'] = [
        'v'     => 1,
        'spent' => min(1, $cur['spent'] + 1),
        't'     => time(),
    ];
}

/**
 * SSE instability must not veto the first bounded launch when the current shell shows a launch surface.
 * When $shellAuthed && $hasLaunchSurface, always returns false (policy); kept for explicit reuse / tooling.
 */
function ipmiWebIloSseFailureShouldBlockInitialLaunch(array $bootstrapMeta, bool $shellAuthed, bool $hasLaunchSurface): bool
{
    if ($shellAuthed && $hasLaunchSurface) {
        return false;
    }

    return (int) ($bootstrapMeta['sse_fail_streak'] ?? 0) >= 3;
}

function ipmiWebIloSseFailureShouldBlockRepeatedLaunch(array $bootstrapMeta, bool $budgetCanSpend): bool
{
    if ($budgetCanSpend) {
        return false;
    }

    return (int) ($bootstrapMeta['sse_fail_streak'] ?? 0) >= 2;
}

/**
 * When stalled SSE/phase should be softened for a fresh authenticated shell with measurable surface evidence.
 *
 * @param array<string, mixed> $surface launch_surface from shell analysis
 */
function ipmiWebIloShouldSoftResetStallState(array $bootstrapMeta, array $shellPack, array $surface): bool
{
    if (empty($shellPack['shell_authenticated']) || empty($shellPack['has_launch_surface'])) {
        return false;
    }
    if (ipmiWebIloLooksLicenseGatedFromAnalysis($surface)) {
        return false;
    }
    if (ipmiWebIloCurrentSurfaceEvidenceScore($surface) < 28) {
        return false;
    }
    $phase = (string) ($bootstrapMeta['phase'] ?? '');
    $streak = (int) ($bootstrapMeta['sse_fail_streak'] ?? 0);

    return $phase === 'stalled' || ($streak >= 2 && in_array($phase, ['degraded', 'stalled'], true));
}

/**
 * @param array<string, mixed> $surface
 */
function ipmiWebIloMaybeSoftResetBootstrapStallForSurface(
    ?mysqli $mysqli,
    string $token,
    array &$session,
    array $shellPack,
    array $bootstrapMeta,
    array $surface
): bool {
    if (!$mysqli || !preg_match('/^[a-f0-9]{64}$/', $token)) {
        return false;
    }
    if (!ipmiWebIloShouldSoftResetStallState($bootstrapMeta, $shellPack, $surface)) {
        if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
            $phase = (string) ($bootstrapMeta['phase'] ?? '');
            $streak = (int) ($bootstrapMeta['sse_fail_streak'] ?? 0);
            if (($phase === 'stalled' || $streak >= 2) && !empty($shellPack['shell_authenticated'])) {
                ipmiProxyDebugLog('ilo_stall_state_retained_due_to_strong_negative_evidence', [
                    'phase'           => $phase,
                    'sse_fail_streak' => $streak,
                    'surface_score'   => ipmiWebIloCurrentSurfaceEvidenceScore($surface),
                ]);
            }
        }

        return false;
    }
    $patched = null;
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use (&$patched): void {
        $ib = is_array($meta['ilo_bootstrap'] ?? null) ? $meta['ilo_bootstrap'] : [];
        if ((int) ($ib['v'] ?? 0) !== 1) {
            return;
        }
        $sse = is_array($ib['sse'] ?? null) ? $ib['sse'] : ['last' => '', 'fail_streak' => 0, 'last_ts' => 0, 'ok_after_refresh' => 0];
        $streak = (int) ($sse['fail_streak'] ?? 0);
        if (($ib['phase'] ?? '') === 'stalled') {
            $ib['phase'] = 'degraded';
        }
        $sse['fail_streak'] = min($streak, 1);
        $ib['sse'] = $sse;
        $ib['updated_at'] = time();
        $meta['ilo_bootstrap'] = $ib;
        $patched = $ib;
    });
    if (!is_array($patched)) {
        return false;
    }
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_bootstrap'] = $patched;
    if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_stall_state_soft_reset', [
            'phase_now'       => (string) ($patched['phase'] ?? ''),
            'sse_fail_streak' => (int) (($patched['sse'] ?? [])['fail_streak'] ?? 0),
        ]);
        ipmiProxyDebugLog('ilo_state_soft_reset_decision', ['applied' => 1]);
        ipmiProxyDebugLog('ilo_fresh_shell_attempt_window_active', ['surface_score' => ipmiWebIloCurrentSurfaceEvidenceScore($surface)]);
    }

    return true;
}

/**
 * @param array<string, mixed> $session
 * @param array<string, mixed> $surface
 * @param array<string, mixed> $bootstrapMeta
 * @return array{allow: bool, reason: string}
 */
function ipmiWebIloShouldAllowBoundedLaunchAttempt(
    ?array $session,
    array $surface,
    array $bootstrapMeta,
    bool $shellAuthed,
    bool $hasSurface,
    bool $runtimeStall,
    bool $provenHtml5
): array {
    if ($session === null || !$shellAuthed || !$hasSurface || $provenHtml5) {
        return ['allow' => false, 'reason' => 'preconditions_not_met'];
    }
    if (!$runtimeStall) {
        return ['allow' => false, 'reason' => 'no_runtime_stall'];
    }
    if (ipmiWebIloLooksLicenseGatedFromAnalysis($surface)) {
        return ['allow' => false, 'reason' => 'license_gate'];
    }
    $score = ipmiWebIloCurrentSurfaceEvidenceScore($surface);
    if ($score < 32) {
        return ['allow' => false, 'reason' => 'surface_evidence_too_weak'];
    }
    if (!ipmiWebIloBoundedLaunchCanSpend($session)) {
        return ['allow' => false, 'reason' => 'bounded_launch_budget_exhausted'];
    }
    // When shellAuthed && hasSurface, SseFailureShouldBlockInitialLaunch is always false — SSE is not an absolute veto.
    return ['allow' => true, 'reason' => 'surface_outweighs_stale_stall'];
}

/**
 * @param bool $attemptAutolaunch
 * @param array<string, mixed> $surface
 * @param array<string, mixed> $bootstrapMeta
 * @param string $boundedDenyReason reason from ipmiWebIloShouldAllowBoundedLaunchAttempt when stall gate denied override
 */
function ipmiWebIloSurfaceAwareSuppressionDetail(
    bool $attemptAutolaunch,
    string $verdict,
    bool $hasSurface,
    array $surface,
    array $bootstrapMeta,
    ?array $session,
    string $boundedDenyReason = ''
): string {
    if ($attemptAutolaunch) {
        return '';
    }
    if (ipmiWebIloLooksLicenseGatedFromAnalysis($surface)) {
        return 'hard_blocker_license_or_feature';
    }
    if (!$hasSurface) {
        return 'no_launch_surface';
    }
    if ($boundedDenyReason === 'bounded_launch_budget_exhausted'
        || ($session !== null && !ipmiWebIloBoundedLaunchCanSpend($session))) {
        return 'bounded_launch_budget_exhausted';
    }
    if ($boundedDenyReason === 'surface_evidence_too_weak') {
        return 'surface_evidence_below_bounded_threshold';
    }
    if ($boundedDenyReason === 'license_gate') {
        return 'hard_blocker_license_or_feature';
    }
    if ($verdict === 'native_html5_possible_but_session_degraded') {
        return 'session_bootstrap_unhealthy';
    }
    if ((int) ($bootstrapMeta['sse_fail_streak'] ?? 0) >= 3 && empty($surface['html5_native_markers'])) {
        return 'repeated_transport_or_sse_failure';
    }
    if (in_array((string) ($bootstrapMeta['phase'] ?? ''), ['stalled', 'degraded'], true)
        && !empty($bootstrapMeta['runtime_stall_signal'])) {
        return 'session_bootstrap_unhealthy';
    }

    return 'capability_or_transport_unavailable';
}

/**
 * @return array<string, mixed>
 */
function ipmiWebIloBootstrapMetaFromSession(array $session): array
{
    $m = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $ib = is_array($m['ilo_bootstrap'] ?? null) ? $m['ilo_bootstrap'] : [];
    $pf = is_array($m['ilo_preflight'] ?? null) ? $m['ilo_preflight'] : [];
    $bl = is_array($m['ilo_ui_blockers'] ?? null) ? $m['ilo_ui_blockers'] : [];
    $sse = is_array($ib['sse'] ?? null) ? $ib['sse'] : [];
    $sseStreak = (int) ($sse['fail_streak'] ?? 0);
    $phase = (string) ($ib['phase'] ?? 'fresh');
    $runtimeStallSignal = ($phase === 'stalled') || ($sseStreak >= 2);

    return [
        'phase'                 => $phase,
        'preflight_bootstrap_ok'=> $pf['bootstrap_ok'] ?? null,
        'masthead_fragment_ok'  => $bl['masthead_fragment_ok'] ?? null,
        'sse_fail_streak'       => $sseStreak,
        'runtime_stall_signal'  => $runtimeStallSignal,
    ];
}

/**
 * @return array<string, mixed>
 */
function ipmiWebIloAnalyzeShellForConsoleCapability(array $session, string $shellPath = '/index.html'): array
{
    if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_shell_console_capability_analysis_started', ['shellPath' => $shellPath]);
    }
    $fetch = ipmiWebIloProbePathBodySample($session, $shellPath);
    $code = (int) $fetch['code'];
    $body = (string) $fetch['body'];
    $loginLike = !empty($fetch['login_like']);
    $shellAuthed = $code >= 200 && $code < 400 && !$loginLike && $body !== '';
    $surface = ipmiWebIloAnalyzeDocumentForLaunchSurface($body);
    if (!empty($surface['html5_native_markers']) && function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_shell_console_capability_html5_marker_found', ['shellPath' => $shellPath]);
    }
    if (!empty($surface['legacy_java_markers']) && function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_shell_console_capability_legacy_marker_found', ['shellPath' => $shellPath]);
    }
    if (!empty($surface['license_gated_markers']) && function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_shell_console_capability_license_marker_found', ['shellPath' => $shellPath]);
    }
    if (!empty($surface['has_launch_surface']) && function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_launch_surface_found', ['shellPath' => $shellPath, 'reasons' => $surface['reasons'] ?? []]);
    } elseif ($shellAuthed && function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_launch_surface_missing', ['shellPath' => $shellPath]);
    }

    return [
        'shell_path'           => $shellPath,
        'http_code'            => $code,
        'shell_authenticated'  => $shellAuthed,
        'login_like'           => $loginLike,
        'launch_surface'       => $surface,
        'has_launch_surface'   => !empty($surface['has_launch_surface']),
    ];
}

/**
 * @param list<array{path: string, probe: array<string, mixed>}> $ranked
 * @param array<string, mixed> $shellPack from ipmiWebIloAnalyzeShellForConsoleCapability
 * @param array<string, mixed> $bootstrapMeta
 * @param array<string, mixed>|null $session for bounded native-launch budget (optional)
 * @return array<string, mixed>
 */
function ipmiWebIloConsoleCapabilityFromProbe(array $ranked, array $shellPack, array $bootstrapMeta, string $variant, bool $iloHtml5StandaloneProbe, ?array $session = null): array
{
    $pathCodes = [];
    foreach ($ranked as $row) {
        $full = (string) ($row['path'] ?? '');
        $pr = is_array($row['probe'] ?? null) ? $row['probe'] : [];
        $c = (int) ($pr['code'] ?? 0);
        if (stripos($full, 'application.html') !== false) {
            $pathCodes['application'] = $c;
        }
        if (stripos($full, 'rc_info') !== false) {
            $pathCodes['rc_info'] = $c;
        }
        if (stripos($full, 'irc.html') !== false) {
            $pathCodes['irc'] = $c;
        }
        if (stripos($full, 'index.html') !== false || preg_match('#(^|/)index\\.html#i', $full)) {
            $pathCodes['index'] = $c;
        }
    }
    $app404 = isset($pathCodes['application']) && $pathCodes['application'] === 404;
    $rc404 = isset($pathCodes['rc_info']) && $pathCodes['rc_info'] === 404;
    $irc404 = isset($pathCodes['irc']) && $pathCodes['irc'] === 404;
    $indexOk = isset($pathCodes['index']) && $pathCodes['index'] >= 200 && $pathCodes['index'] < 400;
    $tripleConsole404 = $app404 && $rc404 && $irc404;
    $ilo4ish = stripos($variant, 'ilo4') !== false || str_contains(strtolower($variant), 'ilo4');
    $ilo4ProbeHtml5NeedsShellProof = $ilo4ish && $tripleConsole404;

    $surface = is_array($shellPack['launch_surface'] ?? null) ? $shellPack['launch_surface'] : [];
    $hasSurface = !empty($shellPack['has_launch_surface']);
    $shellAuthed = !empty($shellPack['shell_authenticated']);

    $phase = (string) ($bootstrapMeta['phase'] ?? 'fresh');
    $mastheadOk = $bootstrapMeta['masthead_fragment_ok'];
    $preflightBootOk = $bootstrapMeta['preflight_bootstrap_ok'];
    $bootstrapIncomplete = ($mastheadOk === false)
        || in_array($phase, ['degraded', 'stalled'], true)
        || ($preflightBootOk === false);

    $blockers = [];
    $reasons = [];
    $cap = 'unknown';
    $confidence = 30;
    $verdict = 'native_html5_unconfirmed';
    $recStrategy = 'ilo_shell_explore';
    $attemptAutolaunch = true;
    $fallbackShell = true;
    $offerLegacy = false;

    if (ipmiWebIloLooksLicenseGatedFromAnalysis($surface)) {
        $cap = 'license_gated_or_disabled';
        $confidence = 72;
        $verdict = 'native_html5_likely_license_gated';
        $blockers[] = 'license_gated';
        $reasons[] = 'license_text_in_shell';
        $attemptAutolaunch = false;
        $recStrategy = 'ilo_license_or_feature_gate';
    } elseif ($iloHtml5StandaloneProbe && $shellAuthed && $ilo4ProbeHtml5NeedsShellProof && empty($surface['html5_native_markers'])) {
        $cap = 'html5_native_possible_but_unconfirmed';
        $confidence = 42;
        $verdict = 'native_html5_unconfirmed';
        $reasons[] = 'ilo4_console_routes_404_probe_only_index';
        $blockers[] = 'ilo4_requires_shell_html5_proof';
        $attemptAutolaunch = $hasSurface;
        $recStrategy = $hasSurface ? 'ilo_speculative_shell_autolaunch' : 'ilo_shell_only';
    } elseif ($iloHtml5StandaloneProbe && $shellAuthed) {
        $cap = 'html5_native_available';
        $confidence = 88;
        $verdict = 'native_html5_available';
        $reasons[] = 'probe_html5_confirmed';
        $attemptAutolaunch = true;
        $recStrategy = 'ilo_application_autolaunch';
    } elseif (!empty($surface['html5_native_markers']) && $shellAuthed) {
        $cap = 'html5_native_available';
        $confidence = 78;
        $verdict = 'native_html5_available';
        $reasons[] = 'shell_html5_markers';
        $attemptAutolaunch = true;
        $recStrategy = 'ilo_application_autolaunch';
    } elseif ($hasSurface && $shellAuthed) {
        $cap = 'html5_native_possible_but_unconfirmed';
        $confidence = 55;
        $verdict = 'native_html5_unconfirmed';
        $reasons[] = 'launch_surface_heuristic';
        $attemptAutolaunch = true;
        $recStrategy = 'ilo_speculative_shell_autolaunch';
    } elseif ($bootstrapIncomplete && $shellAuthed) {
        $cap = 'shell_bootstrap_incomplete';
        $confidence = 68;
        $verdict = 'native_html5_blocked_by_shell_degradation';
        $blockers[] = 'fragment_failure_blocks_native_launch';
        $blockers[] = 'missing_bootstrap_fragment';
        $reasons[] = 'bootstrap_phase_or_masthead';
        $attemptAutolaunch = false;
        $recStrategy = 'ilo_shell_degraded_wait';
    } elseif ((stripos($variant, 'ilo4') !== false || str_contains(strtolower($variant), 'ilo4'))
        && $app404 && $rc404 && $irc404 && $indexOk && $shellAuthed) {
        $cap = 'legacy_only';
        $confidence = 62;
        $verdict = 'native_html5_likely_legacy_only';
        $blockers[] = 'console_routes_404';
        $reasons[] = 'ilo4_routes_missing';
        $attemptAutolaunch = false;
        $offerLegacy = true;
        $recStrategy = 'ilo_shell_only_legacy_fallback';
    } elseif ($app404 && $rc404 && $irc404 && $indexOk && $shellAuthed && !$hasSurface) {
        $cap = 'legacy_only';
        $confidence = 58;
        $verdict = 'native_html5_not_detected';
        $blockers[] = 'no_launch_surface';
        $blockers[] = 'console_routes_404';
        $reasons[] = 'typical_html5_paths_absent';
        $attemptAutolaunch = false;
        $offerLegacy = true;
        $recStrategy = 'ilo_shell_only';
    } elseif (!$shellAuthed) {
        $cap = 'unknown';
        $confidence = 25;
        $verdict = 'native_html5_unconfirmed';
        $blockers[] = 'shell_not_authenticated';
        $attemptAutolaunch = false;
        $recStrategy = 'ilo_auth_first';
    } elseif (!$hasSurface) {
        $cap = 'unknown';
        $confidence = 40;
        $verdict = 'native_html5_not_detected';
        $blockers[] = 'no_launch_surface';
        $reasons[] = 'shell_missing_console_markers';
        $attemptAutolaunch = false;
        $recStrategy = 'ilo_manual_navigation';
    }

    $surfaceEvidenceScore = ipmiWebIloCurrentSurfaceEvidenceScore($surface);
    $historicalFailureW = ipmiWebIloHistoricalFailureWeight($bootstrapMeta);
    $boundedConsumed = false;
    $boundedDenyReason = '';

    $runtimeStall = !empty($bootstrapMeta['runtime_stall_signal']);
    $stallEvidence = [];
    if ($runtimeStall && $shellAuthed && empty($surface['html5_native_markers'])) {
        $provenHtml5 = ($cap === 'html5_native_available')
            || !empty($surface['html5_native_markers'])
            || ($iloHtml5StandaloneProbe && !$ilo4ProbeHtml5NeedsShellProof);
        $stallEvidence['runtime_stall_signal'] = 1;
        $stallEvidence['sse_fail_streak'] = (int) ($bootstrapMeta['sse_fail_streak'] ?? 0);

        if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_native_transport_evidence_applied', [
                'sse_fail_streak' => (int) ($bootstrapMeta['sse_fail_streak'] ?? 0),
                'phase'           => $phase,
            ]);
        }

        if ($attemptAutolaunch && !$provenHtml5) {
            $bounded = ipmiWebIloShouldAllowBoundedLaunchAttempt(
                $session,
                $surface,
                $bootstrapMeta,
                $shellAuthed,
                $hasSurface,
                true,
                $provenHtml5
            );
            if ($bounded['allow']) {
                $verdict = 'native_html5_surface_present_launch_allowed_once';
                $cap = 'html5_native_possible_but_unconfirmed';
                $recStrategy = 'ilo_speculative_shell_autolaunch';
                $confidence = min(58, max($confidence, 50));
                $reasons[] = 'bounded_launch_surface_overrides_stale_stall';
                $blockers[] = 'historical_stall_softened_for_bounded_native_attempt';
                $boundedConsumed = true;
                if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_bounded_launch_allowed_due_to_surface', [
                        'surface_evidence_score' => $surfaceEvidenceScore,
                        'historical_weight'      => $historicalFailureW,
                        'reason'                 => $bounded['reason'],
                    ]);
                    ipmiProxyDebugLog('ilo_current_surface_evidence_applied', ['score' => $surfaceEvidenceScore]);
                    ipmiProxyDebugLog('ilo_historical_failure_weight_applied', ['weight' => $historicalFailureW]);
                    ipmiProxyDebugLog('ilo_sse_failures_softened_for_initial_launch', [
                        'sse_fail_streak' => (int) ($bootstrapMeta['sse_fail_streak'] ?? 0),
                    ]);
                    ipmiProxyDebugLog('ilo_sse_failures_not_used_as_absolute_block', ['surface' => 1]);
                    ipmiProxyDebugLog('ilo_surface_vs_history_decision', [
                        'winner' => 'current_surface',
                        'bounded'=> 1,
                    ]);
                    ipmiProxyDebugLog('ilo_capability_health_separated', [
                        'surface_present'  => $hasSurface ? 1 : 0,
                        'session_degraded'   => in_array($phase, ['stalled', 'degraded'], true) ? 1 : 0,
                    ]);
                    ipmiProxyDebugLog('ilo_launch_attempt_allowed_despite_degraded_state', [
                        'masthead_ok' => $mastheadOk === null ? 'null' : (int) (bool) $mastheadOk,
                    ]);
                    ipmiProxyDebugLog('ilo_launch_budget_decision', [
                        'can_spend' => ipmiWebIloBoundedLaunchCanSpend($session ?? []) ? 1 : 0,
                        'will_spend'=> 1,
                    ]);
                }
            } else {
                $boundedDenyReason = (string) ($bounded['reason'] ?? '');
                $blockers[] = 'bootstrap_stalled_or_sse_unstable';
                $reasons[] = 'server_session_suggests_no_reliable_html5_transport';
                $attemptAutolaunch = false;
                if ($verdict === 'native_html5_unconfirmed' || $cap === 'html5_native_possible_but_unconfirmed' || $cap === 'unknown') {
                    if ($hasSurface) {
                        $verdict = 'native_html5_possible_but_session_degraded';
                        $cap = 'html5_native_possible_but_unconfirmed';
                    } else {
                        $verdict = 'native_html5_not_detected';
                        $cap = 'unknown';
                    }
                }
                $recStrategy = 'ilo_shell_only';
                if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_bounded_launch_denied_due_to_gate', [
                        'reason'                 => $bounded['reason'],
                        'surface_evidence_score' => $surfaceEvidenceScore,
                    ]);
                    ipmiProxyDebugLog('ilo_surface_vs_history_decision', [
                        'winner' => 'stale_session_signals',
                        'bounded'=> 0,
                    ]);
                    if ($bounded['reason'] === 'bounded_launch_budget_exhausted') {
                        ipmiProxyDebugLog('ilo_sse_failures_block_repeated_launch', [
                            'sse_fail_streak' => (int) ($bootstrapMeta['sse_fail_streak'] ?? 0),
                        ]);
                    }
                }
            }
        }
    }

    $suppressionDetail = ipmiWebIloSurfaceAwareSuppressionDetail(
        $attemptAutolaunch,
        $verdict,
        $hasSurface,
        $surface,
        $bootstrapMeta,
        $session,
        $boundedDenyReason
    );
    if ($hasSurface && !$attemptAutolaunch && function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_surface_present_but_suppressed_reason', [
            'detail' => $suppressionDetail,
            'verdict'=> $verdict,
        ]);
    }

    $evidence = array_merge(
        [
            'path_codes'              => $pathCodes,
            'shell_http'              => (int) ($shellPack['http_code'] ?? 0),
            'variant'                 => $variant,
            'bootstrap_phase'         => $phase,
            'surface_evidence_score'  => $surfaceEvidenceScore,
            'historical_failure_weight'=> $historicalFailureW,
        ],
        $stallEvidence,
        is_array($surface['evidence'] ?? null) ? ['surface' => $surface['evidence']] : []
    );

    if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_shell_console_capability_result', [
            'capability' => $cap,
            'verdict'    => $verdict,
            'confidence' => $confidence,
            'attempt'    => $attemptAutolaunch ? 1 : 0,
        ]);
        ipmiProxyDebugLog('ilo_native_console_evidence_summary', [
            'capability' => $cap,
            'verdict'    => $verdict,
            'blockers'   => $blockers,
            'reasons'    => $reasons,
        ]);
        ipmiProxyDebugLog('ilo_native_console_verdict_finalized', [
            'verdict'       => $verdict,
            'capability'    => $cap,
            'shell_authed'  => $shellAuthed ? 1 : 0,
            'attempt_auto'  => $attemptAutolaunch ? 1 : 0,
            'reasons_csv'   => implode(',', array_slice($reasons, 0, 10)),
            'blockers_csv'  => implode(',', array_slice($blockers, 0, 10)),
            'suppression'   => $suppressionDetail,
            'bounded_deny'  => $boundedDenyReason !== '' ? $boundedDenyReason : null,
        ]);
    }

    return [
        'capability'                         => $cap,
        'confidence'                         => $confidence,
        'reasons'                            => $reasons,
        'evidence'                           => $evidence,
        'recommended_strategy'               => $recStrategy,
        'should_attempt_proxy_autolaunch'    => $attemptAutolaunch,
        'should_fallback_to_shell_only'      => $fallbackShell,
        'should_offer_legacy_or_alt_fallback'=> $offerLegacy,
        'ilo_native_console_verdict'         => $verdict,
        'shell_authenticated'                => $shellAuthed,
        'shell_bootstrap_healthy'            => $shellAuthed && !$bootstrapIncomplete,
        'native_console_available'           => $cap === 'html5_native_available',
        'native_console_transport_started'   => false,
        'blockers'                           => $blockers,
        'launch_surface'                     => $surface,
        'native_console_surface_present'     => $hasSurface,
        'native_console_capability_possible' => $hasSurface && $shellAuthed && !ipmiWebIloLooksLicenseGatedFromAnalysis($surface),
        'current_session_launch_allowed'     => $attemptAutolaunch,
        'current_session_launch_suppressed'  => !$attemptAutolaunch,
        'autolaunch_suppression_detail'      => $suppressionDetail,
        'bounded_native_launch_consumed'     => $boundedConsumed,
        'surface_evidence_score'             => $surfaceEvidenceScore,
        'historical_failure_weight'          => $historicalFailureW,
    ];
}

/**
 * Cached console capability (session meta TTL). Recomputes when stale or missing.
 *
 * @param array<string, mixed> $options ranked_rows?: list, ilo_html5?: bool, force?: bool, shell_pack?: array
 * @return array<string, mixed>
 */
function ipmiWebIloConsoleCapability(array $session, ?mysqli $mysqli, array $options = []): array
{
    $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $cached = $meta['ilo_console_capability'] ?? null;
    $ttl = 280;
    $bootstrapQuick = ipmiWebIloBootstrapMetaFromSession($session);
    $stallMayHeal = !empty($bootstrapQuick['runtime_stall_signal']);
    if (empty($options['force'])
        && !$stallMayHeal
        && is_array($cached)
        && (int) ($cached['v'] ?? 0) === 1
        && time() - (int) ($cached['t'] ?? 0) < $ttl
        && is_array($cached['data'] ?? null)) {
        return $cached['data'];
    }
    $rankedRows = $options['ranked_rows'] ?? null;
    if (!is_array($rankedRows)) {
        $candidates = [
            '/html/application.html?ipmi_kvm_auto=1&ipmi_kvm_force_html5=1',
            '/html/application.html?ipmi_kvm_auto=1',
            '/index.html?ipmi_kvm_auto=1',
            '/html/rc_info.html',
            '/html/irc.html',
            '/index.html',
        ];
        $rankedRows = ipmiWebProbeVendorNativeKvm($session, $candidates)['ranked'];
    }
    $iloH5 = array_key_exists('ilo_html5', $options)
        ? (bool) $options['ilo_html5']
        : ipmiWebIloSupportsStandaloneHtml5Kvm($session);
    $shellPack = $options['shell_pack'] ?? null;
    if (!is_array($shellPack)) {
        $shellPack = ipmiWebIloAnalyzeShellForConsoleCapability($session, '/index.html');
    }
    $variant = ipmiWebBmcVariant((string) ($session['bmc_type'] ?? 'generic'));
    $tok = (string) ($session['token'] ?? '');
    $surfForReset = is_array($shellPack['launch_surface'] ?? null) ? $shellPack['launch_surface'] : [];
    $bm0 = ipmiWebIloBootstrapMetaFromSession($session);
    ipmiWebIloMaybeSoftResetBootstrapStallForSurface($mysqli, $tok, $session, $shellPack, $bm0, $surfForReset);
    $bootstrapMeta = ipmiWebIloBootstrapMetaFromSession($session);
    $data = ipmiWebIloConsoleCapabilityFromProbe($rankedRows, $shellPack, $bootstrapMeta, $variant, $iloH5, $session);
    if (!empty($data['bounded_native_launch_consumed']) && $mysqli && preg_match('/^[a-f0-9]{64}$/', $tok)) {
        ipmiWebIloBoundedLaunchBudgetRecordSpend($mysqli, $tok, $session);
        if (function_exists('ipmiProxyDebugEnabled') && function_exists('ipmiProxyDebugLog') && ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_launch_budget_spent', [
                'budget' => ipmiWebIloBoundedLaunchBudgetFromSession($session),
            ]);
        }
    }
    if ($mysqli && preg_match('/^[a-f0-9]{64}$/', $tok)) {
        ipmiWebSessionMetaMutate($mysqli, $tok, static function (array &$m) use ($data): void {
            $m['ilo_console_capability'] = ['v' => 1, 't' => time(), 'data' => $data];
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_console_capability'] = ['v' => 1, 't' => time(), 'data' => $data];
    }

    return $data;
}

function ipmiWebIloInvalidateConsoleCapabilityMeta(?mysqli $mysqli, string $token, array &$session): void
{
    if ($mysqli && preg_match('/^[a-f0-9]{64}$/', $token)) {
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta): void {
            unset($meta['ilo_console_capability']);
        });
    }
    if (isset($session['session_meta']) && is_array($session['session_meta'])) {
        unset($session['session_meta']['ilo_console_capability']);
    }
}

/**
 * Record masthead/fragment preflight outcome for planner (separate from auth).
 */
function ipmiWebIloRecordMastheadPreflightOutcome(?mysqli $mysqli, string $token, array &$session, bool $mastheadOk): void
{
    if ($mysqli && preg_match('/^[a-f0-9]{64}$/', $token)) {
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($mastheadOk): void {
            $meta['ilo_ui_blockers'] = [
                'v' => 1,
                't'                    => time(),
                'masthead_fragment_ok' => $mastheadOk,
            ];
        });
    }
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_ui_blockers'] = [
        'v'                    => 1,
        't'                    => time(),
        'masthead_fragment_ok' => $mastheadOk,
    ];
    ipmiWebIloInvalidateConsoleCapabilityMeta($mysqli, $token, $session);
    if (!$mastheadOk) {
        ipmiWebKvmLaunchPlanCacheInvalidate($mysqli, $token);
    }
}

function ipmiWebKvmPathLooksUnavailable(string $body): bool
{
    $sample = strtolower(substr((string) $body, 0, 200000));
    if ($sample === '') {
        return false;
    }

    $looksLikeIloChooser = str_contains($sample, 'html5 integrated remote console')
        || (
            str_contains($sample, 'html5 console')
            && (
                str_contains($sample, '.net integrated remote console')
                || str_contains($sample, 'java integrated remote console')
                || str_contains($sample, 'web start')
            )
        );
    if ($looksLikeIloChooser) {
        return false;
    }

    return str_contains($sample, 'can not open remote control page')
        || str_contains($sample, 'cannot open remote control page')
        || str_contains($sample, 'ikvm server port')
        || str_contains($sample, 'remote control is disabled')
        || str_contains($sample, 'console is disabled')
        || str_contains($sample, 'applet-based console')
        || str_contains($sample, 'requiring the availability of java')
        || str_contains($sample, 'java integrated remote console')
        || str_contains($sample, 'keep the current window open');
}

function ipmiWebKvmBodyHasTimeoutText(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $sample = strtolower(substr((string) $body, 0, 200000));

    return str_contains($sample, 'ipmi session expired')
        || str_contains($sample, 'session has timed out')
        || str_contains($sample, 'session timed out')
        || str_contains($sample, 'please log in a new session')
        || str_contains($sample, 'please login in a new session');
}

/**
 * Lightweight KVM path probe against current authenticated BMC session.
 *
 * @return array<string, mixed>
 */
function ipmiWebProbeKvmPath(array $session, string $path): array
{
    $ip = trim((string) ($session['ipmi_ip'] ?? ''));
    if ($ip === '') {
        return [
            'ok' => false, 'score' => -1000, 'code' => 0, 'http_code' => 0,
            'login' => false, 'login_like' => false,
            'timeout' => false, 'timeout_like' => false,
            'unavailable' => false, 'unavailable_like' => false,
            'mode' => 'other', 'delivery_mode' => 'other',
            'final_url' => '', 'content_type' => '',
            'vendor_shell_like' => false, 'console_like' => false,
            'browser_native_like' => false, 'ws_like' => false,
            'markers' => [],
        ];
    }

    $vendorFamily = ipmiWebBmcFamily((string) ($session['bmc_type'] ?? 'generic'));
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $url = $scheme . '://' . $ip . '/' . ltrim($path, '/');
    $cookieHeader = ipmiWebBuildCookieString($session);
    $ch = curl_init($url);
    $appliedResolve = ipmiBmcApplyCurlUrlAndResolve($ch, $url, $ip);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 7);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_ENCODING, '');
    curl_setopt($ch, CURLOPT_HTTPGET, true);
    curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
    if ($cookieHeader !== '') {
        curl_setopt($ch, CURLOPT_COOKIE, $cookieHeader);
    }
    $reqHeaders = [];
    $fh = $session['forward_headers'] ?? [];
    if (is_array($fh)) {
        foreach ($fh as $hn => $hv) {
            $hn = trim((string) $hn);
            if ($hn === '' || strcasecmp($hn, 'Cookie') === 0) {
                continue;
            }
            $reqHeaders[] = $hn . ': ' . $hv;
        }
    }
    if ($reqHeaders !== []) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);
    }
    $raw = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $finalUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);

    if (($raw === false || $code === 0) && $appliedResolve) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 7);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_HTTPGET, true);
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        if ($cookieHeader !== '') {
            curl_setopt($ch, CURLOPT_COOKIE, $cookieHeader);
        }
        if ($reqHeaders !== []) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);
        }
        $raw = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $finalUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);
    }

    $contentType = '';
    $body = '';
    if (is_string($raw) && $raw !== '') {
        [$hdr, $respBody] = ipmiWebCurlExtractFinalHeadersAndBody($raw);
        $body = (string) $respBody;
        if ($hdr !== '' && preg_match('/^Content-Type:\s*([^\r\n]+)/mi', $hdr, $mCt)) {
            $contentType = trim((string) ($mCt[1] ?? ''));
        }
    }

    $deliveryMode = ipmiWebKvmDeliveryMode($path, $contentType, $body);

    $sample = strtolower(substr((string) $body, 0, 200000));
    $pathLower = strtolower($path);
    $markers = [];
    $loginLike = ipmiWebResponseLooksLikeBmcLoginPage($body, $contentType);
    if ($loginLike && ipmiWebResponseLooksLikeIloAuthedShell($body)) {
        $loginLike = false;
    }
    if ($loginLike && ipmiWebResponseLooksLikeIdracAuthedShell($body)) {
        $loginLike = false;
    }
    $timeoutLike = ipmiWebKvmBodyHasTimeoutText($body);
    $unavailableLike = ipmiWebKvmPathLooksUnavailable($body);
    $vendorShell = false;
    $browserNative = false;
    $wsLike = (bool) preg_match('/\bws[s]?:\/\//i', $body)
        || str_contains($sample, 'new websocket(')
        || str_contains($sample, 'new websocket (')
        || str_contains($sample, '.websocket');
    if (!$loginLike && $sample !== '') {
        if (
            str_contains($sample, 'iloglobal')
            || str_contains($sample, 'framecontent')
            || str_contains($sample, 'framedirectory')
            || str_contains($sample, 'html/application')
            || str_contains($sample, 'ilo.start')
        ) {
            $vendorShell = true;
            $markers[] = 'ilo_shell';
        }
        if (
            str_contains($sample, 'idrac')
            || str_contains($sample, 'restgui')
            || str_contains($sample, '/restgui/')
            || str_contains($sample, 'oem/inventory')
            || (str_contains($sample, 'angular.min.js') && str_contains($sample, 'dell'))
        ) {
            $vendorShell = true;
            $markers[] = 'idrac_shell';
        }
        if (
            str_contains($sample, 'supermicro')
            || str_contains($sample, 'url_redirect.cgi')
            || str_contains($sample, 'smc')
            || str_contains($sample, 'ikvm')
        ) {
            $vendorShell = true;
            $markers[] = 'supermicro_shell';
        }
        if (str_contains($sample, 'asrock') || (str_contains($sample, 'csrftoken') && str_contains($sample, 'bmc'))) {
            $vendorShell = true;
            $markers[] = 'ami_shell';
        }
    }
    if ($sample !== '' && !$unavailableLike) {
        if (
            str_contains($sample, 'starthtml5irc')
            || str_contains($sample, 'start_html5_irc')
            || (str_contains($sample, 'html5') && str_contains($sample, 'integrated remote console'))
            || str_contains($sample, 'html5 irc')
            || str_contains($sample, 'ircwindow')
            || str_contains($sample, 'html/irc')
            || (str_contains($sample, 'renderer') && str_contains($sample, 'irc'))
        ) {
            $browserNative = true;
            $markers[] = 'ilo_html5_markers';
        }
        if (str_contains($sample, 'new renderer') || str_contains($sample, 'htmlircwindowmode')) {
            $browserNative = true;
            $markers[] = 'ilo_renderer';
        }
        if (
            str_contains($sample, 'virtual console')
            || str_contains($sample, 'html5 console')
            || str_contains($sample, 'vmrc')
            || str_contains($sample, 'avctkvm')
            || str_contains($sample, 'viewer.html')
            || str_contains($sample, 'console.html')
            || str_contains($pathLower, 'viewer.html')
            || str_contains($pathLower, 'console.html')
        ) {
            $browserNative = true;
            $markers[] = 'idrac_viewer_markers';
        }
        if (
            str_contains($pathLower, 'url_type=html5')
            || (str_contains($pathLower, 'ikvm') && str_contains($sample, 'html5'))
            || (str_contains($sample, 'ikvm') && str_contains($sample, 'websocket'))
        ) {
            $browserNative = true;
            $markers[] = 'supermicro_html5';
        }
    }
    if ($vendorFamily === 'idrac' && !$loginLike && str_contains($sample, 'launch') && str_contains($sample, 'console')) {
        $vendorShell = true;
        $markers[] = 'idrac_launcher';
    }
    if ($vendorFamily === 'ilo' && str_contains($pathLower, 'rc_info') && $vendorShell) {
        $markers[] = 'ilo_rc_bootstrap';
    }
    $consoleLike = ipmiWebKvmPathLooksConsoleLike($path, $body);
    if ($consoleLike) {
        $markers[] = 'console_route_or_copy';
    }
    $markers = array_values(array_unique($markers));
    $cls = [
        'markers'             => $markers,
        'login_like'          => $loginLike,
        'timeout_like'        => $timeoutLike,
        'unavailable_like'    => $unavailableLike,
        'vendor_shell_like'   => $vendorShell,
        'console_like'        => $consoleLike,
        'browser_native_like' => $browserNative,
        'ws_like'             => $wsLike,
    ];
    $login = $loginLike;
    $timeout = $timeoutLike;
    $unavailable = $unavailableLike;

    $ok = ($code >= 200 && $code < 400) && !$login && !$timeout;

    $score = 0;
    if ($ok) {
        $score += 20;
    }
    if (!empty($cls['vendor_shell_like'])) {
        $score += 30;
    }
    if (!empty($cls['console_like'])) {
        $score += 24;
    }
    if (!empty($cls['browser_native_like'])) {
        $score += 65;
    }
    if (!empty($cls['ws_like'])) {
        $score += 14;
    }
    if ($deliveryMode === 'proxy_autolaunch') {
        $score += 52;
    }
    if ($deliveryMode === 'html') {
        $score += 8;
    }
    if ($deliveryMode === 'clickonce' || $deliveryMode === 'jnlp' || $deliveryMode === 'java_applet') {
        $score -= 68;
    }
    if ($unavailable) {
        $score -= 145;
    }
    if ($code >= 400 || $code === 0) {
        $score -= 82;
    }
    if ($login) {
        $score -= 48;
    }
    if ($timeout) {
        $score -= 48;
    }
    if (!empty($cls['vendor_shell_like']) && !$login && $deliveryMode === 'html' && !$unavailable) {
        $score += 12;
    }
    if (in_array('ilo_rc_bootstrap', $markers, true) && !$login) {
        $score += 24;
    }
    if ($vendorFamily === 'idrac'
        && !$login
        && (str_contains($pathLower, 'viewer') || str_contains($pathLower, 'console'))
        && !empty($cls['browser_native_like'])) {
        $score += 20;
    }

    return [
        'ok'                  => $ok,
        'score'               => $score,
        'code'                => $code,
        'http_code'           => $code,
        'login'               => $login,
        'login_like'          => $login,
        'timeout'             => $timeout,
        'timeout_like'        => $timeout,
        'unavailable'         => $unavailable,
        'unavailable_like'    => $unavailable,
        'mode'                => $deliveryMode,
        'delivery_mode'       => $deliveryMode,
        'final_url'           => $finalUrl,
        'content_type'        => $contentType,
        'vendor_shell_like'   => $cls['vendor_shell_like'],
        'console_like'        => $cls['console_like'],
        'browser_native_like' => $cls['browser_native_like'],
        'ws_like'             => $cls['ws_like'],
        'markers'             => $cls['markers'],
    ];
}

/**
 * True when probe result is suitable for browser-first KVM (HTML5 shell, SPA entry, or autolaunch URL).
 */
function ipmiWebKvmProbeIsBrowserOriented(array $probe): bool
{
    $mode = (string) ($probe['delivery_mode'] ?? $probe['mode'] ?? 'other');
    if (in_array($mode, ['proxy_autolaunch', 'html'], true)) {
        return true;
    }
    if (!empty($probe['browser_native_like'])) {
        return true;
    }
    if (!empty($probe['vendor_shell_like']) && $mode === 'html' && empty($probe['login_like']) && empty($probe['login'])) {
        return true;
    }

    return false;
}

function ipmiWebKvmModeIsBrowserNative(string $mode): bool
{
    return in_array($mode, ['proxy_autolaunch', 'html'], true);
}

function ipmiWebPickReachablePath(array $session, array $candidates, string $fallback, bool $browserOnly = false): string
{
    $bestAny = ['path' => $fallback, 'score' => -100000];
    $bestBrowser = ['path' => '', 'score' => -100000];

    foreach ($candidates as $path) {
        $probe = ipmiWebProbeKvmPath($session, $path);
        $score = (int) ($probe['score'] ?? -1000);
        if ($score > $bestAny['score']) {
            $bestAny = ['path' => $path, 'score' => $score];
        }
        $bad = !empty($probe['unavailable']) || !empty($probe['unavailable_like']);
        if (!$bad && ipmiWebKvmProbeIsBrowserOriented($probe) && $score > $bestBrowser['score']) {
            $bestBrowser = ['path' => $path, 'score' => $score];
        }
        if (!$browserOnly && !empty($probe['ok']) && !$bad && $score >= 32) {
            return $path;
        }
    }

    if ($browserOnly && $bestBrowser['path'] !== '') {
        return $bestBrowser['path'];
    }
    if ($browserOnly) {
        return $fallback;
    }

    return $bestAny['path'];
}

function ipmiWebBuildCookieString(array $session): string
{
    if (empty($session['cookies'])) {
        return '';
    }
    $parts = [];
    foreach ($session['cookies'] as $k => $v) {
        if (ipmiWebIsAuthValueUsable($v)) {
            $parts[] = $k . '=' . $v;
        }
    }
    return implode('; ', $parts);
}

/**
 * Mirror BMC cookie jar to the browser under the proxy URL path.
 * iLO (and similar SPAs) often inspect document.cookie and route to #/login when the session
 * cookie is missing, even though the server-side proxy already authenticates with cURL.
 * HttpOnly is off so client scripts can read the cookie if the vendor UI expects it.
 */
function ipmiWebEmitMirroredBmcCookiesForProxy(string $token, array $cookies): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    // No trailing slash: matches /ipmi_proxy.php/{token} and /ipmi_proxy.php/{token}/… in all browsers.
    $path = '/ipmi_proxy.php/' . $token;
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int)($_SERVER['SERVER_PORT'] ?? 0) === 443);
    $expires = time() + 7200;
    $opts = [
        'expires'  => $expires,
        'path'     => $path,
        'secure'   => $secure,
        'httponly' => false,
        'samesite' => 'Lax',
    ];
    $maxCookies = 48;
    $maxTotalBytes = 24576;
    $totalBytes = 0;
    $n = 0;
    foreach ($cookies as $name => $value) {
        if ($n >= $maxCookies) {
            break;
        }
        if (!ipmiWebIsAuthValueUsable($value)) {
            continue;
        }
        $name = (string)$name;
        if (!preg_match('/^[A-Za-z0-9_-]+$/', $name)) {
            continue;
        }
        if (strlen($name) > 128) {
            continue;
        }
        $val = (string)$value;
        if (strlen($val) > 3800) {
            continue;
        }
        $pairBytes = strlen($name) + strlen($val) + 8;
        if ($totalBytes + $pairBytes > $maxTotalBytes) {
            continue;
        }
        if (PHP_VERSION_ID >= 70300) {
            setcookie($name, $val, $opts);
        } else {
            setcookie($name, $val, $expires, $path, '', $secure, false);
        }
        $totalBytes += $pairBytes;
        ++$n;
    }
}

function ipmiWsBuildCookieHeader(array $session): string
{
    $str = ipmiWebBuildCookieString($session);
    if ($str === '') {
        return '';
    }
    return 'Cookie: ' . $str . "\r\n";
}

/**
 * Extra BMC headers for WebSocket upgrade (e.g. Redfish X-Auth-Token after auto-login).
 */
function ipmiWsBuildForwardHeaderLines(array $session): string
{
    $h = $session['forward_headers'] ?? [];
    if (!is_array($h) || $h === []) {
        return '';
    }
    $out = '';
    foreach ($h as $name => $value) {
        $name = trim((string)$name);
        if ($name === '' || strcasecmp($name, 'Cookie') === 0) {
            continue;
        }
        $out .= $name . ': ' . str_replace(["\r", "\n"], '', (string)$value) . "\r\n";
    }

    return $out;
}

function ipmiWebRewriteHtml(string $html, string $tokenPrefix, string $bmcIp): string
{
    if ($tokenPrefix !== '') {
        $baseHref = rtrim($tokenPrefix, '/') . '/';
        $html = preg_replace_callback(
            '#<base\\s+href=(["\'])([^"\']*)\\1#i',
            static function (array $m) use ($baseHref): string {
                $href = trim((string) $m[2]);
                if ($href === '' || $href === '/' || str_starts_with($href, '/')) {
                    if (str_starts_with($href, '/ipmi_proxy.php/')) {
                        return $m[0];
                    }

                    return '<base href="' . $baseHref . '"';
                }

                return $m[0];
            },
            $html
        ) ?? $html;
    }

    $html = preg_replace_callback(
        '#((?:src|href|action)\s*=\s*["\'])(/[^"\']*["\'])#i',
        static function (array $m) use ($tokenPrefix): string {
            $quotedPath = $m[2];
            $path = substr($quotedPath, 0, -1);
            if (str_starts_with($path, '/ipmi_proxy.php/')) {
                return $m[1] . $quotedPath;
            }
            if ($tokenPrefix !== '' && str_starts_with($path, $tokenPrefix)) {
                return $m[1] . $quotedPath;
            }

            return $m[1] . $tokenPrefix . $quotedPath;
        },
        $html
    );

    $html = preg_replace_callback(
        '#((?:src|href|action)\s*=\s*["\'])https?://' . preg_quote($bmcIp, '#') . '(/[^"\']*["\'])#i',
        static function (array $m) use ($tokenPrefix): string {
            $quotedPath = $m[2];
            $path = substr($quotedPath, 0, -1);
            if (str_starts_with($path, '/ipmi_proxy.php/') || ($tokenPrefix !== '' && str_starts_with($path, $tokenPrefix))) {
                return $m[1] . $quotedPath;
            }

            return $m[1] . $tokenPrefix . $quotedPath;
        },
        $html
    );

    return $html;
}

/**
 * Resolve a relative URL segment against a directory path (result always starts with '/').
 *
 * @param string $dir e.g. "/html/app" (dirname of the proxied document)
 */
function ipmiWebResolveRelativePathFromDir(string $dir, string $rel): string
{
    $rel = trim($rel);
    if ($rel === '') {
        return '';
    }
    $dir = str_replace('\\', '/', $dir);
    $parts = [];
    $trimDir = trim($dir, '/');
    if ($trimDir !== '') {
        $parts = explode('/', $trimDir);
    }
    foreach (explode('/', $rel) as $seg) {
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($seg === '..') {
            array_pop($parts);
        } else {
            $parts[] = $seg;
        }
    }

    return '/' . implode('/', $parts);
}

/**
 * application.html often uses sibling-relative assets (href="css/foo.css"). The browser resolves
 * those against the current document URL; in a proxied SPA the shell URL may not match the HTML
 * file's directory → stylesheets 404. Rewrite non-root-relative src/href using this response path.
 */
function ipmiWebRewriteHtmlRelativeToDocument(string $html, string $tokenPrefix, string $bmcPath): string
{
    $tokenPrefix = rtrim((string) $tokenPrefix, '/');
    if ($tokenPrefix === '') {
        return $html;
    }

    $bmcPath = str_replace('\\', '/', (string) $bmcPath);
    $dir = dirname($bmcPath);
    if ($dir === '.' || $dir === '') {
        $dir = '/';
    }

    return preg_replace_callback(
        '#\b((?:src|href)\s*=\s*["\'])([^"\']+)#i',
        static function (array $m) use ($tokenPrefix, $dir): string {
            $attr = $m[1];
            $path = trim($m[2]);
            if ($path === '' || $path === '#' || $path[0] === '?') {
                return $m[0];
            }
            $lower = strtolower($path);
            if (str_starts_with($path, '/')
                || str_starts_with($lower, 'http://')
                || str_starts_with($lower, 'https://')
                || str_starts_with($lower, 'data:')
                || str_starts_with($lower, 'javascript:')
                || str_starts_with($lower, 'mailto:')
            ) {
                return $m[0];
            }
            if (stripos($path, 'ipmi_proxy.php') !== false) {
                return $m[0];
            }
            // For vendor UIs (Supermicro/ASRock), relative assets often live at root (js/, css/, img/).
            // Treat these as root-relative to avoid /cgi/js/... rewrites.
            if (preg_match('#^(js|css|img|images|fonts|res|resources|static)/#i', $path)) {
                return $attr . $tokenPrefix . '/' . ltrim($path, '/');
            }
            $resolved = ipmiWebResolveRelativePathFromDir($dir, $path);
            if ($resolved === '') {
                return $m[0];
            }

            return $attr . $tokenPrefix . $resolved;
        },
        $html
    ) ?? $html;
}
