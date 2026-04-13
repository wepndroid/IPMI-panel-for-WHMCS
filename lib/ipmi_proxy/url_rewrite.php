<?php

function ipmiProxyWsRelayPath(string $scheme, string $bmcHost, string $path, string $token): string
{
    $fullTarget = strtolower($scheme) . '://' . $bmcHost . $path;
    return '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=' . rawurlencode($fullTarget);
}

/** @return list<string> */
function ipmiProxyGetBmcHostAliases(string $bmcIp): array
{
    return ipmiBmcGetHostAliases($bmcIp);
}

function ipmiProxyBmcPreferredOriginHost(string $bmcIp): string
{
    return ipmiBmcPreferredOriginHost($bmcIp);
}

/**
 * @param \CurlHandle|resource $ch
 */
function ipmiProxyApplyCurlBmcUrlAndResolve($ch, string $bmcUrl, string $bmcIp): bool
{
    return ipmiBmcApplyCurlUrlAndResolve($ch, $bmcUrl, $bmcIp);
}

/**
 * Escaped slashes as in JSON or minified JS: wss:\/\/host\/path
 */
function ipmiProxyRewriteEscapedWebSocketUrls(string $body, string $bmcHost, string $token): string
{
    $q = preg_quote($bmcHost, '#');
    $cb = static function (array $m) use ($bmcHost, $token): string {
        $scheme = strtolower($m[1]);
        $pathJson = $m[2] ?? '';
        $path = str_replace('\/', '/', $pathJson);
        if ($path === '' || $path[0] !== '/') {
            $path = '/' . ltrim($path, '/');
        }
        return ipmiProxyWsRelayPath($scheme, $bmcHost, $path, $token);
    };
    $patterns = [
        '#\b(wss|ws):\\\\/\\\\/' . $q . '(?::\\d+)?((?:\\\\/[^"\\\\]*)*)#i',
        // Single-quoted / alternate escaping in minified JSON-ish fragments
        "#\\b(wss|ws):\\\\/\\\\/" . $q . '(?::\\d+)?((?:\\\\/[^\'\\\\]*)*)#i',
    ];
    foreach ($patterns as $re) {
        $tmp = preg_replace_callback($re, $cb, $body);
        if (is_string($tmp)) {
            $body = $tmp;
        }
    }

    return $body;
}

/**
 * Rewrite wss/ws URLs that point at the BMC so the browser opens WebSockets on this host
 * (ipmi_ws_relay.php). Direct wss:// to the BMC IP is unreachable from user browsers;
 * routing via ipmi_proxy.php + 307 is unreliable because many browsers skip redirects on WS.
 */
function ipmiProxyRewriteWebSocketUrls(string $body, string $bmcHost, string $token): string
{
    $q = preg_quote($bmcHost, '#');
    $cb = static function (array $m) use ($bmcHost, $token): string {
        $scheme = strtolower($m[1]);
        $path = (isset($m[2]) && $m[2] !== '') ? $m[2] : '/';
        $fullTarget = $scheme . '://' . $bmcHost . $path;

        return '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=' . rawurlencode($fullTarget);
    };
    $orig = $body;
    $out = $orig;
    $patterns = [
        // Optional whitespace after scheme; path may end at ) or , (minified call sites).
        '#\b(wss|ws)\s*:\s*//' . $q . '(?::\d+)?(/[^\s"\'<>\),]*)?#i',
        // new WebSocket("wss://host/path")
        '#new\s+WebSocket\s*\(\s*["\'](wss|ws)\s*:\s*//' . $q . '(?::\d+)?(/[^\s"\']*)?#i',
    ];
    foreach ($patterns as $re) {
        $tmp = preg_replace_callback($re, $cb, $out);
        if (is_string($tmp)) {
            $out = $tmp;
        }
    }
    // Template literals: `wss://${host}/path` — rewrite when host token matches BMC (minified bundles).
    $tplCb = static function (array $m) use ($bmcHost, $token): string {
        $scheme = strtolower($m[1]);
        $rest = (string) ($m[2] ?? '');
        $fullTarget = $scheme . '://' . $bmcHost . ($rest !== '' ? $rest : '/');

        return '`' . '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=' . rawurlencode($fullTarget) . '`';
    };
    $tplRe = '#`(wss|ws)\s*:\s*/\s*/\s*' . $q . '(?::\d+)?(/[^`$]*)?`#i';
    $tmpTpl = preg_replace_callback($tplRe, $tplCb, $out);
    if (is_string($tmpTpl)) {
        $out = $tmpTpl;
    }
    // String concat: "wss://"+host+"/path" (common in obfuscated viewers)
    $concatRe = '#(["\'])(wss|ws)\1\s*\+\s*["\']' . $q . '(?::\d+)?["\']\s*\+\s*(["\'])(/[^"\']*)?\3#i';
    $tmpCo = preg_replace_callback($concatRe, static function (array $m) use ($bmcHost, $token): string {
        $scheme = strtolower($m[2]);
        $path = isset($m[4]) && $m[4] !== '' ? $m[4] : '/';
        $fullTarget = $scheme . '://' . $bmcHost . $path;
        $relay = '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=' . rawurlencode($fullTarget);

        return json_encode($relay, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    }, $out);
    if (is_string($tmpCo)) {
        $out = $tmpCo;
    }

    return $out;
}

/**
 * Rewrite http(s) BMC URLs to the proxy path, including JSON-style escaped slashes.
 * iLO/Redfish often returns URLs only inside JSON; minified JS may use https:\/\/ as well.
 */
function ipmiProxyRewriteHttpBmcUrls(string $body, string $bmcHost, string $tokenPrefix): string
{
    $tpJson = str_replace('/', '\\/', $tokenPrefix);
    $pairs = [
        ['https://' . $bmcHost, $tokenPrefix],
        ['https:\\/\\/' . $bmcHost, $tpJson],
        ['http://' . $bmcHost, $tokenPrefix],
        ['http:\\/\\/' . $bmcHost, $tpJson],
    ];
    foreach ($pairs as [$from, $to]) {
        $body = str_replace($from, $to, $body);
    }
    return $body;
}

/**
 * iLO 5/6 SPA uses root-relative API and asset paths. From a proxied page, /js/... hits the
 * panel origin (wrong). Longer prefixes first so /redfish/v1/ is not broken by /redfish/.
 */
function ipmiProxyRewriteIloRootRelative(string $body, string $token): string
{
    $px = '/ipmi_proxy.php/' . rawurlencode($token);
    $pxj = str_replace('/', '\\/', $px);
    $roots = [
        '/cgi/',
        '/res/',
        '/resources/',
        '/static/',
        '/redfish/v1/',
        '/redfish/',
        '/rest/v1/',
        '/rest/',
        '/restapi/',
        '/js/',
        '/css/',
        '/fonts/',
        '/img/',
        '/images/',
        '/json/',
        '/api/',
        '/html/',
        '/themes/', // iLO 4 classic UI CSS bundles (e.g. /themes/hpe/css/...)
        '/sse/', // iLO 5/6 UI event stream (e.g. /sse/ui)
        '/java/', // legacy Java console payloads
        '/Java/', // Supermicro/older BMC java payloads are often uppercase path
        '/viewer/', // iDRAC console route family
        '/console/', // vendor console routes
        '/kvm/', // vendor kvm assets
        '/avct/', // iDRAC console assets
        '/favicon.ico', // often requested at site root; must route through proxy
    ];
    $pairs = [];
    foreach ($roots as $r) {
        $ej = str_replace('/', '\\/', $r);
        $pairs[] = ['"' . $r, '"' . $px . $r];
        $pairs[] = ["'" . $r, "'" . $px . $r];
        $pairs[] = ['+"' . $r, '+"' . $px . $r];
        $pairs[] = ['"' . $ej, '"' . $pxj . $ej];
    }
    foreach ($pairs as [$from, $to]) {
        $body = str_replace($from, $to, $body);
    }
    return $body;
}
