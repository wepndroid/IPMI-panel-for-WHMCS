<?php

function ipmiProxyRewriteBmcResponseBody(string $body, string $bmcIp, string $token, string $tokenPrefix, string $bmcType, bool $isHtml = false): string
{
    $aliases = ipmiProxyGetBmcHostAliases($bmcIp);
    $mentionsHost = false;
    foreach ($aliases as $host) {
        $h = trim((string) $host);
        if ($h !== '' && strpos($body, $h) !== false) {
            $mentionsHost = true;
            break;
        }
    }
    // Avoid regex scans over 200KB+ vendor bundles (jquery, etc.) when the BMC hostname never appears.
    if ($mentionsHost) {
        $preAliasRewrite = $body;
        foreach ($aliases as $host) {
            $body = ipmiProxyRewriteEscapedWebSocketUrls($body, $host, $token);
            $body = ipmiProxyRewriteWebSocketUrls($body, $host, $token);
            $body = ipmiProxyRewriteHttpBmcUrls($body, $host, $tokenPrefix);
        }
        if ($body !== $preAliasRewrite) {
            ipmiProxyDebugLog('bmc_response_host_rewrite', [
                'delta_len'            => strlen($body) - strlen($preAliasRewrite),
                'ws_relay_path_present' => str_contains($body, '/ipmi_ws_relay.php') ? 1 : 0,
            ]);
        }
    }

    // Root-relative rewrites: do NOT key off '"/js/' for JS bundles — jquery.min.js often contains that
    // substring. iLO HTML pages are small: always rewrite root-relative paths when vendor is iLO.
    // Supermicro/ASRockRack also depend on root-relative /cgi/ and /res/ assets.
    $typeNorm = ipmiWebNormalizeBmcType((string) $bmcType);
    $needsIloRoot = ($isHtml && (ipmiProxyIsIloFamily($bmcType) || $typeNorm === 'supermicro'))
        || strpos($body, '"/redfish/') !== false
        || strpos($body, "'/redfish/") !== false
        || strpos($body, '"/rest/') !== false
        || strpos($body, '"\\/redfish\\/') !== false
        || strpos($body, '"\\/rest\\/') !== false
        || strpos($body, '"/restapi/') !== false
        || strpos($body, "'/restapi/") !== false
        || strpos($body, '"\\/restapi\\/') !== false
        || strpos($body, '"/sse/') !== false
        || strpos($body, '"\\/sse\\/') !== false
        || strpos($body, '"/cgi/') !== false
        || strpos($body, "'/cgi/") !== false
        || strpos($body, '"\\/cgi\\/') !== false
        || strpos($body, '"/res/') !== false
        || strpos($body, "'/res/") !== false
        || strpos($body, '"\\/res\\/') !== false
        || strpos($body, '"/json/') !== false
        || strpos($body, '"\\/json\\/') !== false
        || strpos($body, '"/api/') !== false
        || strpos($body, '"\\/api\\/') !== false
        || strpos($body, '"/html/') !== false
        || strpos($body, '"\\/html\\/') !== false
        || strpos($body, '"/java/') !== false
        || strpos($body, '"\\/java\\/') !== false
        || strpos($body, '"/Java/') !== false
        || strpos($body, '"\\/Java\\/') !== false
        || strpos($body, '"/viewer/') !== false
        || strpos($body, '"\\/viewer\\/') !== false
        || strpos($body, '"/console/') !== false
        || strpos($body, '"\\/console\\/') !== false
        || strpos($body, '"/kvm/') !== false
        || strpos($body, '"\\/kvm\\/') !== false
        || strpos($body, '"/avct/') !== false
        || strpos($body, '"\\/avct\\/') !== false
        || strpos($body, '"/favicon.ico') !== false
        || strpos($body, '"\\/favicon.ico') !== false
        || strpos($body, '"/themes/') !== false
        || strpos($body, '"\\/themes\\/') !== false;

    if ($needsIloRoot) {
        $body = ipmiProxyRewriteIloRootRelative($body, $token);
    }

    return $body;
}

function ipmiProxyRewriteIloSocketJs(string $body, string $bmcPath, string $token, string $bmcIp, string $bmcScheme): string
{
    $path = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (!in_array($path, ['/js/socket.js', '/html/js/socket.js'], true)) {
        return $body;
    }

    $targetWs = (($bmcScheme === 'http') ? 'ws' : 'wss') . '://' . $bmcIp . '/wss/ircport';
    $replacement = 'this.sessionKey = options.sessionKey, this.sockaddr = (function(){var S=false;try{if(typeof window!=="undefined"&&window.top&&window.top.location&&window.top.location.protocol==="https:")S=true;}catch(e1){}try{if(!S&&self.location&&self.location.protocol==="https:")S=true;}catch(e2){}return S?"wss://":"ws://";})()+((function(){try{if(typeof window!=="undefined"&&window.top&&window.top.location&&window.top.location.host)return window.top.location.host;}catch(e3){}try{if(self.location&&self.location.host)return self.location.host;}catch(e4){}return options.host;})())+"/ipmi_ws_relay.php?token='
        . rawurlencode($token)
        . '&target=" + encodeURIComponent('
        . json_encode($targetWs, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES)
        . '),';

    $needle = 'this.sessionKey = options.sessionKey, this.sockaddr = "wss://" + options.host + "/wss/ircport",';
    if (strpos($body, $needle) !== false) {
        return str_replace($needle, $replacement, $body);
    }

    $updated = preg_replace(
        '/this\.sessionKey\s*=\s*options\.sessionKey,\s*this\.sockaddr\s*=\s*"wss:\/\/"\s*\+\s*options\.host\s*\+\s*"\/wss\/ircport",/s',
        $replacement,
        $body,
        1
    );
    if (is_string($updated)) {
        $body = $updated;
    }

    $needleSq = "this.sessionKey = options.sessionKey, this.sockaddr = 'wss://' + options.host + '/wss/ircport',";
    if (strpos($body, $needleSq) !== false) {
        return str_replace($needleSq, $replacement, $body);
    }

    $updated2 = preg_replace(
        '/this\.sessionKey\s*=\s*options\.sessionKey,\s*this\.sockaddr\s*=\s*[\'"]wss:\/\/[\'"]\s*\.\s*options\.host\s*\.\s*[\'"]\/wss\/ircport[\'"],/s',
        $replacement,
        $body,
        1
    );
    if (is_string($updated2)) {
        $body = $updated2;
    }

    $needleTight = 'this.sessionKey = options.sessionKey,this.sockaddr="wss://"+options.host+"/wss/ircport",';
    if (strpos($body, $needleTight) !== false) {
        return str_replace($needleTight, $replacement, $body);
    }
    $updated3 = preg_replace(
        '/this\.sessionKey\s*=\s*options\.sessionKey\s*,\s*this\.sockaddr\s*=\s*"wss:\/\/"\s*\+\s*options\.host\s*\+\s*"\/wss\/ircport"\s*,/s',
        $replacement,
        $body,
        1
    );

    return is_string($updated3) ? $updated3 : $body;
}

/**
 * Stylesheets often use url(/fonts/...) or url(../fonts/...). Those must point at the proxy prefix
 * or the browser requests the panel origin and DevTools reports failed stylesheet/font loads.
 */
function ipmiProxyRewriteCssResponseBody(string $body, string $bmcPath, string $tokenPrefix, string $bmcIp): string
{
    $tp = rtrim($tokenPrefix, '/');
    $dir = dirname(str_replace('\\', '/', $bmcPath));
    if ($dir === '.' || $dir === '') {
        $dir = '/';
    }

    foreach (ipmiProxyGetBmcHostAliases($bmcIp) as $host) {
        $body = str_replace('https://' . $host, $tp, $body);
        $body = str_replace('http://' . $host, $tp, $body);
    }

    $body = str_replace('@import "/', '@import "' . $tp . '/', $body);
    $body = str_replace("@import '/", "@import '" . $tp . '/', $body);
    $body = str_replace('@import url("/', '@import url("' . $tp . '/', $body);
    $body = str_replace("@import url('/", "@import url('" . $tp . '/', $body);

    return preg_replace_callback(
        '#\burl\s*\(\s*(["\']?)([^)]+)\1\s*\)#i',
        static function (array $m) use ($tp, $dir): string {
            $path = trim($m[2]);
            $q = $m[1];
            if ($path === '') {
                return $m[0];
            }
            $lower = strtolower($path);
            if (str_starts_with($lower, 'data:') || str_starts_with($lower, 'blob:') || preg_match('#^(https?:)?//#i', $path)) {
                return $m[0];
            }
            if (str_starts_with($path, '/ipmi_proxy.php/')) {
                return $m[0];
            }
            if (str_starts_with($path, '/')) {
                return 'url(' . $q . $tp . $path . $q . ')';
            }
            $resolved = ipmiWebResolveRelativePathFromDir($dir, $path);

            return 'url(' . $q . $tp . $resolved . $q . ')';
        },
        $body
    ) ?? $body;
}

/**
 * AMI/ASRock SPA uses localStorage "garc" to decide dashboard vs login.
 * Mirror cookie garc into localStorage so SPA skips login when server-side auth exists.
 */
function ipmiProxyInjectAmiLocalStorageBridge(string $html): string
{
    $script = '<script data-ami-bridge="1">(function(){try{'
        . 'try{var _a=window.alert;window.alert=function(msg){try{var s=String(msg||"").toLowerCase();'
        . 'if(s.indexOf("session is running")>=0||s.indexOf("already a session")>=0){return;}'
        . '}catch(e){}return _a.apply(this,arguments);};}catch(e){}'
        . 'var m=document.cookie.match(/(?:^|; )garc=([^;]+)/);'
        . 'if(m&&m[1]){var v=decodeURIComponent(m[1]);'
        . 'if(!localStorage.getItem("garc")){localStorage.setItem("garc",v);} '
        . 'var h=(location.hash||"");'
        . 'if(h===""||h==="#"||h==="#login"||h==="#/login"){location.hash="#/dashboard";}'
        . '}'
        . '}catch(e){}})();</script>';
    if (stripos($html, '<head') !== false) {
        $html = preg_replace('~<head[^>]*>~i', '$0' . $script, $html, 1) ?? $html;
        return $html;
    }
    if (stripos($html, '</body>') !== false) {
        return preg_replace('~</body>~i', $script . '</body>', $html, 1) ?? ($html . $script);
    }

    return $html . $script;
}

/**
 * Remove CSP meta tags to allow proxy-injected scripts to run.
 */
function ipmiProxyStripMetaCsp(string $html): string
{
    return preg_replace(
        '~<meta[^>]+http-equiv\\s*=\\s*[\"\\\']?content-security-policy[\"\\\']?[^>]*>~i',
        '',
        $html
    ) ?? $html;
}
