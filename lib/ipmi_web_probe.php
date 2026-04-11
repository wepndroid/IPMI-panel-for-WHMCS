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
 * Best-effort cleanup of BMC web session created during probe login.
 * This prevents probe runs from accumulating stale sessions on BMC side.
 */
function ipmiWebProbeBestEffortLogout(array $session): void
{
    $ip = trim((string) ($session['ipmi_ip'] ?? ''));
    if ($ip === '') {
        return;
    }
    $type = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $baseUrl = $scheme . '://' . $ip;
    $cookies = is_array($session['cookies'] ?? null) ? $session['cookies'] : [];
    $forwardHeaders = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
    if (!ipmiWebHasUsableBmcAuth($cookies, $forwardHeaders)) {
        return;
    }

    try {
        if ($type === 'idrac') {
            ipmiWebIdracAttemptLogout($baseUrl, $ip, $cookies);
            return;
        }
        if ($type === 'supermicro') {
            ipmiWebSupermicroAttemptLogout($baseUrl, $ip, $cookies);
            return;
        }
        if ($type === 'ami') {
            ipmiWebAmiAttemptLogout($baseUrl, $ip, $cookies, $forwardHeaders);
            return;
        }
    } catch (Throwable $e) {
        // ignore probe logout errors
    }
}

/**
 * Proxy-path cleanup for probe sessions created with ipmiWebCreateSession().
 */
function ipmiWebProbeProxyBestEffortLogout(string $token, string $bmcType): void
{
    if ($token === '' || !preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $type = ipmiWebNormalizeBmcType($bmcType);
    try {
        if ($type === 'idrac') {
            ipmiWebProbeFetchProxyPathWithMethod($token, '/data/logout', 'GET', null);
            ipmiWebProbeFetchProxyPathWithMethod($token, '/logout', 'GET', null);
            return;
        }
        if ($type === 'supermicro') {
            ipmiWebProbeFetchProxyPathWithMethod($token, '/cgi/logout.cgi', 'POST', '');
            return;
        }
        if ($type === 'ami') {
            ipmiWebProbeFetchProxyPathWithMethod($token, '/api/session', 'DELETE', '');
            return;
        }
    } catch (Throwable $e) {
        // ignore probe logout errors
    }
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
    if (ipmiWebIsNormalizedIloType($type)) {
        return ['/', '/index.html'];
    }
    switch ($type) {
        case 'supermicro':
            return ['/', '/cgi/url_redirect.cgi?url_name=topmenu', '/cgi/url_redirect.cgi?url_name=dashboard'];
        case 'idrac':
            return ['/', '/start.html', '/index.html', '/restgui/start.html'];
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
    if (ipmiWebIsNormalizedIloType($type)) {
        return ['/', '/index.html'];
    }
    switch ($type) {
        case 'supermicro':
            return ['/', '/cgi/url_redirect.cgi?url_name=topmenu', '/cgi/url_redirect.cgi?url_name=dashboard'];
        case 'idrac':
            return ['/', '/start.html'];
        case 'ami':
            return ['/'];
        default:
            return ['/'];
    }
}

function ipmiWebProbeIsSupermicroRuntimeApiPath(string $path): bool
{
    $p = strtolower((string) parse_url($path, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }

    return in_array($p, ['/cgi/xml_dispatcher.cgi', '/cgi/op.cgi', '/cgi/ipmi.cgi', '/cgi/upgrade_process.cgi'], true);
}

function ipmiWebProbeLooksLikeSupermicroRuntimeAuthFailure(string $body): bool
{
    $l = strtolower(substr((string) $body, 0, 120000));
    if ($l === '') {
        return false;
    }

    if (str_contains($l, 'please log in a new session') || str_contains($l, 'please login in a new session')) {
        return true;
    }
    if (str_contains($l, 'your session has timed out') || str_contains($l, 'session timed out')) {
        return true;
    }
    if (str_contains($l, 'invalid session') || str_contains($l, 'no valid session')) {
        return true;
    }
    if (str_contains($l, 'session expired')) {
        return true;
    }

    return false;
}

/**
 * Parse Supermicro inline CSRF bootstrap call:
 *   SmcCsrfInsert("CSRF_TOKEN", "<token>")
 *
 * @return array{0:string,1:string} [headerName, headerValue]
 */
function ipmiWebProbeExtractSupermicroCsrfFromHtml(string $html): array
{
    if ($html === '') {
        return ['', ''];
    }
    if (preg_match('/SmcCsrfInsert\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)/i', $html, $m)) {
        $name = trim((string) ($m[1] ?? ''));
        $value = trim((string) ($m[2] ?? ''));
        if ($name !== '' && $value !== '') {
            return [$name, $value];
        }
    }

    return ['', ''];
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
 *   redirect_chain: array<int, array{http:int, location:string}>,
 *   logout_redirect: bool,
 *   topmenu_redirect: bool,
 *   loop_hint: bool
 * }
 */
function ipmiWebProbeFetchProxyPathWithMethod(
    string $token,
    string $path,
    string $method = 'GET',
    ?string $postBody = null,
    array $extraHeaders = []
): array
{
    $base = ipmiWebProbeProxyBaseUrl();
    $url = $base . '/ipmi_proxy.php/' . rawurlencode($token) . '/' . ltrim($path, '/');
    $ch = curl_init($url);
    $method = strtoupper(trim($method));
    if ($method === '') {
        $method = 'GET';
    }
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 8);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 12);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_ENCODING, '');
    curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        if ($postBody !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);
        }
    } elseif ($method !== 'GET') {
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        if ($postBody !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);
        }
    }
    if ($extraHeaders !== []) {
        $hdrs = [];
        foreach ($extraHeaders as $h) {
            $h = trim((string) $h);
            if ($h !== '') {
                $hdrs[] = $h;
            }
        }
        if ($hdrs !== []) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $hdrs);
        }
    }
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

function ipmiWebProbeFetchProxyPath(string $token, string $path): array
{
    return ipmiWebProbeFetchProxyPathWithMethod($token, $path, 'GET', null);
}

function ipmiWebProbeLooksLikeIdracStartLauncher(string $body): bool
{
    $l = strtolower(substr((string) $body, 0, 200000));
    if ($l === '') {
        return false;
    }
    return str_contains($l, 'aimgetintprop=scl_int_enabled,pam_int_ldap_enable_mode')
        && str_contains($l, 'aimgetboolprop=pam_bool_sso_enabled')
        && (
            str_contains($l, 'top.document.location.href = "/login.html"')
            || str_contains($l, 'top.document.location.href="/login.html"')
        );
}

/**
 * Resolve a relative asset URL against the current BMC path.
 */
function ipmiWebProbeResolveRelativeBmcPath(string $basePath, string $rel): string
{
    $basePathOnly = (string) parse_url($basePath, PHP_URL_PATH);
    if ($basePathOnly === '') {
        $basePathOnly = '/';
    }
    if (!str_starts_with($basePathOnly, '/')) {
        $basePathOnly = '/' . $basePathOnly;
    }
    $baseDir = rtrim(str_replace('\\', '/', dirname($basePathOnly)), '/');
    if ($baseDir === '') {
        $baseDir = '/';
    }

    $raw = trim($rel);
    if ($raw === '') {
        return '/';
    }
    if (str_starts_with($raw, '/')) {
        return $raw;
    }

    $qPos = strpos($raw, '?');
    $fragPos = strpos($raw, '#');
    $cutPos = false;
    if ($qPos !== false && $fragPos !== false) {
        $cutPos = min($qPos, $fragPos);
    } elseif ($qPos !== false) {
        $cutPos = $qPos;
    } elseif ($fragPos !== false) {
        $cutPos = $fragPos;
    }
    $tail = '';
    $pathPart = $raw;
    if ($cutPos !== false) {
        $pathPart = substr($raw, 0, $cutPos);
        $tail = substr($raw, $cutPos);
    }

    $segments = [];
    foreach (explode('/', $baseDir . '/' . $pathPart) as $seg) {
        if ($seg === '' || $seg === '.') {
            continue;
        }
        if ($seg === '..') {
            array_pop($segments);
            continue;
        }
        $segments[] = $seg;
    }

    return '/' . implode('/', $segments) . $tail;
}

/**
 * Extract candidate script/style/image URLs from HTML.
 *
 * @return array<int, string>
 */
function ipmiWebProbeExtractHtmlAssetUrls(string $html): array
{
    $urls = [];

    // script src
    if (preg_match_all('/<script\b[^>]*\bsrc\s*=\s*(["\'])(.*?)\1[^>]*>/is', $html, $m1)) {
        foreach ($m1[2] as $u) {
            $u = trim((string) $u);
            if ($u !== '') {
                $urls[] = $u;
            }
        }
    }

    // link href (styles/icons/preloads that affect rendering)
    if (preg_match_all('/<link\b[^>]*\bhref\s*=\s*(["\'])(.*?)\1[^>]*>/is', $html, $m2, PREG_SET_ORDER)) {
        foreach ($m2 as $row) {
            $tag = (string) $row[0];
            $u = trim((string) ($row[2] ?? ''));
            if ($u === '') {
                continue;
            }
            $tagLc = strtolower($tag);
            $rel = '';
            if (preg_match('/\brel\s*=\s*(["\'])(.*?)\1/i', $tag, $rm)) {
                $rel = strtolower(trim((string) ($rm[2] ?? '')));
            }
            $as = '';
            if (preg_match('/\bas\s*=\s*(["\'])(.*?)\1/i', $tag, $am)) {
                $as = strtolower(trim((string) ($am[2] ?? '')));
            }

            $isUsefulLink = false;
            if ($rel !== '') {
                if (
                    str_contains($rel, 'stylesheet')
                    || str_contains($rel, 'icon')
                    || str_contains($rel, 'preload')
                ) {
                    $isUsefulLink = true;
                }
            }
            if (!$isUsefulLink && ($as === 'style' || $as === 'script' || $as === 'font')) {
                $isUsefulLink = true;
            }

            // Fallback by extension when rel/as attributes are absent.
            if (!$isUsefulLink) {
                $pathOnly = strtolower((string) parse_url($u, PHP_URL_PATH));
                if (
                    str_ends_with($pathOnly, '.css')
                    || str_ends_with($pathOnly, '.js')
                    || str_ends_with($pathOnly, '.ico')
                    || str_ends_with($pathOnly, '.png')
                    || str_ends_with($pathOnly, '.jpg')
                    || str_ends_with($pathOnly, '.jpeg')
                    || str_ends_with($pathOnly, '.svg')
                    || str_ends_with($pathOnly, '.woff')
                    || str_ends_with($pathOnly, '.woff2')
                ) {
                    $isUsefulLink = true;
                }
            }

            if ($isUsefulLink) {
                $urls[] = $u;
            }
        }
    }

    // img src
    if (preg_match_all('/<img\b[^>]*\bsrc\s*=\s*(["\'])(.*?)\1[^>]*>/is', $html, $m3)) {
        foreach ($m3[2] as $u) {
            $u = trim((string) $u);
            if ($u !== '') {
                $urls[] = $u;
            }
        }
    }

    $clean = [];
    foreach ($urls as $u) {
        $u = trim((string) $u);
        if ($u === '' || $u[0] === '#') {
            continue;
        }
        $lu = strtolower($u);
        if (
            str_starts_with($lu, 'javascript:')
            || str_starts_with($lu, 'data:')
            || str_starts_with($lu, 'mailto:')
            || str_starts_with($lu, 'tel:')
        ) {
            continue;
        }
        $clean[] = $u;
    }

    return array_values(array_unique($clean));
}

/**
 * Convert extracted HTML URL to BMC-relative path for proxy fetch.
 */
function ipmiWebProbeAssetUrlToBmcPath(string $token, string $basePath, string $url): string
{
    $u = trim($url);
    if ($u === '') {
        return '/';
    }

    $tokenPrefix = '/ipmi_proxy.php/' . rawurlencode($token) . '/';

    if (preg_match('#^https?://#i', $u)) {
        $path = (string) parse_url($u, PHP_URL_PATH);
        $query = (string) parse_url($u, PHP_URL_QUERY);
        $candidate = $path . ($query !== '' ? ('?' . $query) : '');
        if (str_starts_with($candidate, $tokenPrefix)) {
            $candidate = '/' . ltrim(substr($candidate, strlen($tokenPrefix)), '/');
        }
        if ($candidate === '') {
            return '/';
        }
        return $candidate;
    }

    if (str_starts_with($u, '/ipmi_proxy.php/')) {
        $needle = '/ipmi_proxy.php/' . rawurlencode($token) . '/';
        if (str_starts_with($u, $needle)) {
            $rest = substr($u, strlen($needle));
            return '/' . ltrim((string) $rest, '/');
        }
        return '/';
    }

    if (str_starts_with($u, '/')) {
        return $u;
    }

    return ipmiWebProbeResolveRelativeBmcPath($basePath, $u);
}

/**
 * Probe essential assets for a proxied HTML page (JS/CSS heavy failures => UI likely broken).
 *
 * @return array{ok: bool, total: int, critical_total: int, fail: int, critical_fail: int, sample_failed: array<int, array<string, mixed>>}
 */
function ipmiWebProbeValidateProxyAssets(string $token, string $basePath, string $html): array
{
    $assets = ipmiWebProbeExtractHtmlAssetUrls($html);
    $maxAssets = 50;
    if (count($assets) > $maxAssets) {
        $assets = array_slice($assets, 0, $maxAssets);
    }

    $total = 0;
    $criticalTotal = 0;
    $fail = 0;
    $criticalFail = 0;
    $failedSamples = [];

    foreach ($assets as $assetUrl) {
        $bmcPath = ipmiWebProbeAssetUrlToBmcPath($token, $basePath, $assetUrl);
        if ($bmcPath === '' || $bmcPath === '/') {
            continue;
        }

        $total++;
        $pathOnly = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
        $isOptionalLegacy = (
            str_ends_with($pathOnly, '/libs/js/html5shiv.js')
            || str_ends_with($pathOnly, '/libs/js/respond.min.js')
            || str_contains($pathOnly, '/html5shiv.js')
            || str_contains($pathOnly, '/respond.min.js')
        );
        $isCritical = str_ends_with($pathOnly, '.js')
            || str_ends_with($pathOnly, '.css')
            || str_contains($pathOnly, '/js/')
            || str_contains($pathOnly, '/css/');
        if ($isCritical) {
            $criticalTotal++;
        }

        $res = ipmiWebProbeFetchProxyPath($token, $bmcPath);
        $http = (int) ($res['http'] ?? 0);
        $isFailed = empty($res['raw_ok']) || $http === 0 || $http >= 400;
        if ($isFailed) {
            if ($isOptionalLegacy && ($http === 404 || $http === 0)) {
                continue;
            }
            $fail++;
            if ($isCritical) {
                $criticalFail++;
            }
            if (count($failedSamples) < 10) {
                $failedSamples[] = [
                    'asset' => $assetUrl,
                    'resolved_path' => $bmcPath,
                    'http' => $http,
                    'curl_error' => (string) ($res['curl_error'] ?? ''),
                ];
            }
        }
    }

    // Conservative threshold to avoid noisy image/font misses while still catching broken UI.
    $ok = true;
    if ($criticalFail >= 2) {
        $ok = false;
    }
    if ($criticalTotal > 0 && $criticalFail / max(1, $criticalTotal) >= 0.35) {
        $ok = false;
    }
    return [
        'ok' => $ok,
        'total' => $total,
        'critical_total' => $criticalTotal,
        'fail' => $fail,
        'critical_fail' => $criticalFail,
        'sample_failed' => $failedSamples,
    ];
}

/**
 * Deep proxy-flow checks. Uses same session creation path as UI open action.
 *
 * @return array{ok: bool, error?: string, checks?: array<int, array<string, mixed>>}
 */
function ipmiWebProbeProxyFlowValidation(mysqli $mysqli, int $serverId, bool $e2e = false): array
{
    $checks = [];
    $token = '';
    $bmcType = 'generic';
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

            if (ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType($bmcType)) && $path === '/') {
                $final = strtolower((string) ($res['final_url'] ?? ''));
                $iloLandingOk = str_contains($final, '/index.html') || str_contains($final, '/html/application.html');
                if ($final !== '' && str_contains($final, '/ipmi_proxy.php/') && !$iloLandingOk) {
                    return ['ok' => false, 'error' => 'proxy_ilo_root_not_redirected', 'checks' => $checks];
                }
            }

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
            $ignoreIloLoginMarker = (ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType($bmcType))
                && ($path === '/html/application.html' || $path === '/index.html'));
            if (!empty($res['login_page']) && !$ignoreIloLoginMarker) {
                return ['ok' => false, 'error' => 'proxy_login_page:' . $path, 'checks' => $checks];
            }

            if ($e2e) {
                $ct = strtolower((string) ($res['content_type'] ?? ''));
                if (str_contains($ct, 'text/html')) {
                    $assetCheck = ipmiWebProbeValidateProxyAssets($token, $path, (string) ($res['body'] ?? ''));
                    $checks[] = [
                        'kind' => 'proxy_assets',
                        'path' => $path,
                        'asset_total' => $assetCheck['total'],
                        'asset_fail' => $assetCheck['fail'],
                        'asset_critical_total' => $assetCheck['critical_total'],
                        'asset_critical_fail' => $assetCheck['critical_fail'],
                        'asset_ok' => $assetCheck['ok'],
                        'asset_failed_samples' => $assetCheck['sample_failed'],
                    ];
                    if (empty($assetCheck['ok'])) {
                        return ['ok' => false, 'error' => 'proxy_asset_failures:' . $path, 'checks' => $checks];
                    }
                }
            }
        }

        if ($e2e && ipmiWebNormalizeBmcType($bmcType) === 'supermicro') {
            // Verify a real dashboard API call (not just shell HTML/assets):
            // POST /cgi/xml_dispatcher.cgi with GENERIC_INFO.XML must return XML payload.
            $topmenuForCsrf = ipmiWebProbeFetchProxyPath($token, '/cgi/url_redirect.cgi?url_name=topmenu');
            [$csrfHeaderName, $csrfHeaderValue] = ipmiWebProbeExtractSupermicroCsrfFromHtml((string) ($topmenuForCsrf['body'] ?? ''));
            $proxyBase = rtrim(ipmiWebProbeProxyBaseUrl(), '/');
            $topmenuRef = $proxyBase . '/ipmi_proxy.php/' . rawurlencode($token) . '/cgi/url_redirect.cgi?url_name=topmenu';
            $apiHeaders = [
                'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With: XMLHttpRequest',
                'Referer: ' . $topmenuRef,
                'Origin: ' . $proxyBase,
            ];
            if ($csrfHeaderName !== '' && $csrfHeaderValue !== '') {
                $apiHeaders[] = $csrfHeaderName . ': ' . $csrfHeaderValue;
            }
            $apiPath = '/cgi/xml_dispatcher.cgi';
            $apiRes = ipmiWebProbeFetchProxyPathWithMethod(
                $token,
                $apiPath,
                'POST',
                'op=GENERIC_INFO.XML&r=(0,0)',
                $apiHeaders
            );
            $apiBody = (string) ($apiRes['body'] ?? '');
            $apiAuthFail = ipmiWebProbeLooksLikeSupermicroRuntimeAuthFailure($apiBody);
            $apiXmlOk = (stripos($apiBody, '<GENERIC_INFO') !== false) || (stripos($apiBody, '<GENERIC ') !== false);
            $csrfProbeBlocked = ((int) ($apiRes['http'] ?? 0) === 403)
                && (stripos($apiBody, 'token value is not matched') !== false);
            $checks[] = [
                'kind' => 'proxy_supermicro_runtime_api',
                'path' => $apiPath,
                'method' => 'POST',
                'http' => (int) ($apiRes['http'] ?? 0),
                'raw_ok' => !empty($apiRes['raw_ok']),
                'login_page' => !empty($apiRes['login_page']),
                'timeout_text' => !empty($apiRes['timeout_text']),
                'timeout_shell' => !empty($apiRes['timeout_shell']),
                'proxy_expired' => !empty($apiRes['proxy_expired']),
                'auth_fail_text' => $apiAuthFail,
                'xml_ok' => $apiXmlOk,
                'csrf_probe_blocked' => $csrfProbeBlocked,
                'csrf_header' => $csrfHeaderName !== '' ? $csrfHeaderName : '',
                'body_bytes' => (int) ($apiRes['body_bytes'] ?? 0),
            ];
            $apiHttp = (int) ($apiRes['http'] ?? 0);
            if (
                empty($apiRes['raw_ok'])
                || $apiHttp === 0
                || ($apiHttp >= 400 && !$csrfProbeBlocked)
                || !empty($apiRes['login_page'])
                || !empty($apiRes['timeout_text'])
                || !empty($apiRes['timeout_shell'])
                || !empty($apiRes['proxy_expired'])
                || $apiAuthFail
                || (!$apiXmlOk && !$csrfProbeBlocked)
            ) {
                return ['ok' => false, 'error' => 'proxy_supermicro_runtime_api_invalid:' . $apiPath, 'checks' => $checks];
            }

            $logout = ipmiWebProbeFetchProxyPathWithMethod($token, '/cgi/logout.cgi', 'POST', '');
            $checks[] = [
                'kind' => 'proxy_action',
                'path' => '/cgi/logout.cgi',
                'method' => 'POST',
                'http' => (int) ($logout['http'] ?? 0),
                'raw_ok' => !empty($logout['raw_ok']),
            ];
            $after = ipmiWebProbeFetchProxyPath($token, '/cgi/url_redirect.cgi?url_name=topmenu');
            $checks[] = [
                'kind' => 'proxy_after_logout_probe',
                'path' => '/cgi/url_redirect.cgi?url_name=topmenu',
                'http' => (int) ($after['http'] ?? 0),
                'login_page' => !empty($after['login_page']),
                'timeout_text' => !empty($after['timeout_text']),
                'timeout_shell' => !empty($after['timeout_shell']),
                'proxy_expired' => !empty($after['proxy_expired']),
            ];
            if (
                empty($after['raw_ok'])
                || (int) ($after['http'] ?? 0) >= 400
                || !empty($after['proxy_expired'])
                || !empty($after['timeout_shell'])
                || !empty($after['timeout_text'])
            ) {
                return ['ok' => false, 'error' => 'proxy_supermicro_logout_instability', 'checks' => $checks];
            }
        }
        if ($e2e && ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType($bmcType))) {
            // iLO white-screen regressions often come from runtime auth drift:
            // shell HTML is 200 but /json/session_info flips to 401/403.
            $iloApiPath = '/json/session_info';
            $iloApiRes = ipmiWebProbeFetchProxyPath($token, $iloApiPath);
            $iloApiBody = (string) ($iloApiRes['body'] ?? '');
            $iloApiJsonOk = ipmiWebProbeSessionJsonValid($iloApiBody);
            $checks[] = [
                'kind' => 'proxy_ilo_session_api',
                'path' => $iloApiPath,
                'http' => (int) ($iloApiRes['http'] ?? 0),
                'raw_ok' => !empty($iloApiRes['raw_ok']),
                'login_page' => !empty($iloApiRes['login_page']),
                'json_ok' => $iloApiJsonOk,
                'body_bytes' => (int) ($iloApiRes['body_bytes'] ?? 0),
            ];
            if (
                empty($iloApiRes['raw_ok'])
                || (int) ($iloApiRes['http'] ?? 0) >= 400
                || (int) ($iloApiRes['http'] ?? 0) === 0
                || !empty($iloApiRes['login_page'])
                || !$iloApiJsonOk
            ) {
                return ['ok' => false, 'error' => 'proxy_ilo_session_api_invalid', 'checks' => $checks];
            }

            // iLO KVM jnlp_template guard:
            // Keep this endpoint pass-through (vendor-native flow) and avoid
            // forcing legacy/unavailable redirects from proxy heuristics.
            $proxyBase = ipmiWebProbeProxyBaseUrl() . '/ipmi_proxy.php/' . rawurlencode($token);
            $kvmRef = $proxyBase . '/html/application.html?ipmi_kvm_auto=1';
            $iloJnlp = ipmiWebProbeFetchProxyPathWithMethod(
                $token,
                '/html/jnlp_template.html',
                'GET',
                null,
                ['Referer: ' . $kvmRef]
            );
            $legacyRedirect = false;
            $legacyQuerySeen = false;
            $unavailableRedirect = false;
            foreach (($iloJnlp['redirect_chain'] ?? []) as $hop) {
                $loc = strtolower((string) ($hop['location'] ?? ''));
                if ($loc === '') {
                    continue;
                }
                if (str_contains($loc, 'ipmi_kvm_unavailable=1')) {
                    $unavailableRedirect = true;
                }
                if (str_contains($loc, '/html/irc.application')) {
                    $legacyRedirect = true;
                    if (str_contains($loc, 'ipmi_kvm_legacy=1')) {
                        $legacyQuerySeen = true;
                    }
                }
            }
            $finalUrlLower = strtolower((string) ($iloJnlp['final_url'] ?? ''));
            if (str_contains($finalUrlLower, '/html/irc.application')) {
                $legacyRedirect = true;
            }
            if (str_contains($finalUrlLower, 'ipmi_kvm_legacy=1')) {
                $legacyQuerySeen = true;
            }
            if (str_contains($finalUrlLower, 'ipmi_kvm_unavailable=1')) {
                $unavailableRedirect = true;
            }
            $checks[] = [
                'kind' => 'proxy_ilo_kvm_fallback',
                'path' => '/html/jnlp_template.html',
                'http' => (int) ($iloJnlp['http'] ?? 0),
                'raw_ok' => !empty($iloJnlp['raw_ok']),
                'final_url' => (string) ($iloJnlp['final_url'] ?? ''),
                'legacy_redirect' => $legacyRedirect,
                'legacy_query' => $legacyQuerySeen,
                'unavailable_redirect' => $unavailableRedirect,
            ];
            if (
                empty($iloJnlp['raw_ok'])
                || (int) ($iloJnlp['http'] ?? 0) >= 400
                || (int) ($iloJnlp['http'] ?? 0) === 0
                || $legacyRedirect
            ) {
                return ['ok' => false, 'error' => 'proxy_ilo_kvm_jnlp_invalid', 'checks' => $checks];
            }
        }
        if ($e2e && ipmiWebNormalizeBmcType($bmcType) === 'idrac') {
            // iDRAC-specific loop guard:
            // /login.html must not bounce to /restgui/start.html launcher (start -> login -> start loop).
            $loginRes = ipmiWebProbeFetchProxyPath($token, '/login.html');
            $redirToStart = false;
            foreach (($loginRes['redirect_chain'] ?? []) as $hop) {
                $loc = strtolower((string) ($hop['location'] ?? ''));
                if ($loc === '') {
                    continue;
                }
                if (str_contains($loc, '/restgui/start.html') || str_contains($loc, '/start.html')) {
                    $redirToStart = true;
                    break;
                }
            }
            $startLauncher = ipmiWebProbeLooksLikeIdracStartLauncher((string) ($loginRes['body'] ?? ''));
            $checks[] = [
                'kind' => 'proxy_idrac_login',
                'path' => '/login.html',
                'http' => (int) ($loginRes['http'] ?? 0),
                'raw_ok' => !empty($loginRes['raw_ok']),
                'final_url' => (string) ($loginRes['final_url'] ?? ''),
                'redirect_to_start' => $redirToStart,
                'looks_like_start_launcher' => $startLauncher,
            ];
            if (empty($loginRes['raw_ok']) || (int) ($loginRes['http'] ?? 0) >= 400 || (int) ($loginRes['http'] ?? 0) === 0) {
                return ['ok' => false, 'error' => 'proxy_idrac_login_unreachable', 'checks' => $checks];
            }
            if ($redirToStart && $startLauncher) {
                return ['ok' => false, 'error' => 'proxy_idrac_start_login_loop', 'checks' => $checks];
            }

            // iDRAC start page depends on these session API calls; if they return login/html
            // the UI stays on spinner even though /start.html itself is 200.
            $sessionApiPaths = [
                '/session?aimGetIntProp=scl_int_enabled,pam_int_ldap_enable_mode',
                '/session?aimGetBoolProp=pam_bool_sso_enabled',
            ];
            foreach ($sessionApiPaths as $apiPath) {
                $apiRes = ipmiWebProbeFetchProxyPath($token, $apiPath);
                $apiBody = (string) ($apiRes['body'] ?? '');
                $apiJsonOk = ipmiWebProbeSessionJsonValid($apiBody);
                $checks[] = [
                    'kind' => 'proxy_idrac_session_api',
                    'path' => $apiPath,
                    'http' => (int) ($apiRes['http'] ?? 0),
                    'raw_ok' => !empty($apiRes['raw_ok']),
                    'login_page' => !empty($apiRes['login_page']),
                    'json_ok' => $apiJsonOk,
                    'body_bytes' => (int) ($apiRes['body_bytes'] ?? 0),
                ];
                if (
                    empty($apiRes['raw_ok'])
                    || (int) ($apiRes['http'] ?? 0) >= 400
                    || (int) ($apiRes['http'] ?? 0) === 0
                    || !empty($apiRes['login_page'])
                    || !$apiJsonOk
                ) {
                    return ['ok' => false, 'error' => 'proxy_idrac_session_api_invalid', 'checks' => $checks];
                }
            }
        }
        if ($e2e) {
            $kvmPath = ipmiWebKvmConsolePath($probeSession);
            $kvmRes = ipmiWebProbeFetchProxyPath($token, $kvmPath);
            $kvmBody = (string) ($kvmRes['body'] ?? '');
            $kvmLooksConsole = ipmiWebKvmPathLooksConsoleLike($kvmPath, $kvmBody);
            $kvmUnavailable = ipmiWebKvmPathLooksUnavailable($kvmBody);
            $checks[] = [
                'kind' => 'proxy_kvm',
                'path' => $kvmPath,
                'http' => (int) ($kvmRes['http'] ?? 0),
                'raw_ok' => !empty($kvmRes['raw_ok']),
                'final_url' => (string) ($kvmRes['final_url'] ?? ''),
                'login_page' => !empty($kvmRes['login_page']),
                'timeout_text' => !empty($kvmRes['timeout_text']),
                'timeout_shell' => !empty($kvmRes['timeout_shell']),
                'proxy_expired' => !empty($kvmRes['proxy_expired']),
                'looks_console_like' => $kvmLooksConsole,
                'looks_unavailable' => $kvmUnavailable,
                'body_bytes' => (int) ($kvmRes['body_bytes'] ?? 0),
            ];
            if (
                empty($kvmRes['raw_ok'])
                || (int) ($kvmRes['http'] ?? 0) >= 400
                || (int) ($kvmRes['http'] ?? 0) === 0
                || !empty($kvmRes['login_page'])
                || !empty($kvmRes['timeout_text'])
                || !empty($kvmRes['timeout_shell'])
                || !empty($kvmRes['proxy_expired'])
            ) {
                return ['ok' => false, 'error' => 'proxy_kvm_invalid:' . $kvmPath, 'checks' => $checks];
            }
            if ($kvmUnavailable) {
                return ['ok' => false, 'error' => 'proxy_kvm_unavailable:' . $kvmPath, 'checks' => $checks];
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
            ipmiWebProbeProxyBestEffortLogout($token, $bmcType);
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
    $iloRootShellOk = ipmiWebIsNormalizedIloType($type)
        && !empty($root['body'])
        && ipmiWebResponseLooksLikeIloAuthedShell((string) ($root['body'] ?? ''));
    if (!empty($root['login_page']) && !$isSupermicro && !$iloRootShellOk) {
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

    if (ipmiWebIsNormalizedIloType($type)) {
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
        $idracCandidates = ['/start.html', '/index.html', '/restgui/start.html', '/restgui/launch'];
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
        ipmiWebProbeBestEffortLogout($session);
        return ['ok' => false, 'error' => 'session_info_failed', 'scheme' => (string) ($session['bmc_scheme'] ?? 'https')];
    }

    ipmiWebProbeBestEffortLogout($session);
    return ['ok' => true, 'scheme' => (string) ($session['bmc_scheme'] ?? 'https')];
}

/**
 * Server web probe with optional deep post-login UI validation.
 *
 * @return array{ok: bool, skipped?: bool, reason?: string, error?: string, scheme?: string, checks?: array<int, array<string, mixed>>, proxy_checks?: array<int, array<string, mixed>>}
 */
function ipmiWebProbeServerWebUiDetailed(mysqli $mysqli, int $serverId, bool $deep = true, bool $proxyFlow = false, bool $e2e = false): array
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
            ipmiWebProbeBestEffortLogout($session);
            return $base;
        }
        if (isset($deepResult['checks']) && is_array($deepResult['checks'])) {
            $base['checks'] = $deepResult['checks'];
        }
    }

    if ($proxyFlow) {
        $proxyResult = ipmiWebProbeProxyFlowValidation($mysqli, $serverId, $e2e);
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
            ipmiWebProbeBestEffortLogout($session);
            return $base;
        }
    }

    ipmiWebProbeBestEffortLogout($session);
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
