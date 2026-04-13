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

function ipmiProxyInjectIntoHtmlHeadOrBody(string $html, string $snippet): string
{
    if (stripos($html, '<head') !== false) {
        return preg_replace('/<head(\s[^>]*)?>/i', '$0' . $snippet, $html, 1) ?? $html;
    }
    if (stripos($html, '</body>') !== false) {
        return preg_replace('~</body>~i', $snippet . '</body>', $html, 1) ?? ($html . $snippet);
    }

    return $html . $snippet;
}

/**
 * iLO pages embed the BMC DNS name in JSON or absolute URLs. PTR from the panel may not match
 * that name; harvesting hints lets the injected script rewrite client calls to the real hostname.
 *
 * @return list<string>
 */
function ipmiProxyExtractIloHostnameHintsFromHtml(string $html, string $panelHostLower): array
{
    $panelHostLower = strtolower(trim($panelHostLower));
    $colon = strrpos($panelHostLower, ':');
    if ($colon !== false && strpos($panelHostLower, ']') === false) {
        $panelHostLower = substr($panelHostLower, 0, $colon);
    }

    $found = [];
    $patterns = [
        '/"(?:hostName|hostname|HostName|dns_hostname|iLOFQDN|DnsName|DNSName)"\s*:\s*"([^"]+)"/',
        '#https?://([a-z0-9][a-z0-9.-]*\.[a-z]{2,})/(?:redfish|json|rest|sse|js|html|api)(?:/|[\s"\'\\\\])#i',
    ];
    foreach ($patterns as $re) {
        if (preg_match_all($re, $html, $m)) {
            foreach ($m[1] as $h) {
                $h = strtolower(trim((string) $h));
                if ($h === '' || $h === 'localhost' || $h === $panelHostLower) {
                    continue;
                }
                if (!str_contains($h, '.')) {
                    continue;
                }
                $found[$h] = true;
            }
        }
    }

    return array_keys($found);
}

/**
 * iLO SPAs often call fetch(location.origin + "/redfish/..."), which never appears as a static
 * string we can rewrite. Patch fetch/XHR/WebSocket at runtime + optional &lt;base href&gt;.
 *
 * Also rewrites absolute https://&lt;BMC host or IP&gt;/... so the browser does not call the BMC
 * directly (only the panel can reach it).
 */
function ipmiProxyInjectIloHeadFixes(string $html, string $token, ?string $redfishXAuthToken = null, string $bmcIp = ''): string
{
    if (stripos($html, 'data-ipmi-proxy-ilo-patch') !== false) {
        return $html;
    }

    $px = '/ipmi_proxy.php/' . rawurlencode($token);
    $pxJs = json_encode($px, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $wsRelay = '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=';
    $wsRelayJs = json_encode($wsRelay, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $wsRelay = '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=';
    $wsRelayJs = json_encode($wsRelay, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $xTok = $redfishXAuthToken !== null ? trim($redfishXAuthToken) : '';
    $xJs = json_encode($xTok, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    $bmcHosts = [];
    if ($bmcIp !== '') {
        foreach (ipmiProxyGetBmcHostAliases($bmcIp) as $h) {
            $h = trim((string) $h);
            if ($h !== '') {
                $bmcHosts[] = $h;
            }
        }
    }

    $panelHint = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
    foreach (ipmiProxyExtractIloHostnameHintsFromHtml($html, $panelHint) as $hint) {
        $bmcHosts[] = $hint;
    }

    $bmcHosts = array_values(array_unique(array_map(static function ($v) {
        return strtolower(trim((string) $v));
    }, $bmcHosts)));
    $hostsJs = json_encode($bmcHosts, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

    $iconHref = htmlspecialchars($px . '/favicon.ico', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $patch = '<link rel="icon" href="' . $iconHref . '" data-ipmi-proxy-icon="1">'
        . '<script data-ipmi-proxy-ilo-patch="1">'
        . '(function(){try{var _a=window.alert;window.alert=function(msg){try{var s=String(msg||"").toLowerCase();'
        . 'if(s.indexOf("session has timed out")>=0||s.indexOf("session timed out")>=0||s.indexOf("session is running")>=0||s.indexOf("already a session")>=0){return;}'
        . '}catch(e){}return _a.apply(this,arguments);};}catch(e){}'
        . 'var P=' . $pxJs . ';var W=' . $wsRelayJs . ';var A=' . $xJs . ';var H=' . $hostsJs . ';'
        . 'var R=["/redfish/v1/","/redfish/","/rest/v1/","/rest/","/restapi/","/js/","/css/","/fonts/","/img/","/images/","/json/","/api/","/html/","/themes/","/sse/","/cgi/","/java/","/Java/","/viewer/","/console/","/kvm/","/avct/","/favicon.ico"];'
        . 'var L=location;var po=L.protocol+"//"+L.host;var wo=(L.protocol==="https:"?"wss:":"ws:")+"//"+L.host;'
        . 'function iH(h){if(!h)return false;h=String(h).toLowerCase();for(var i=0;i<H.length;i++){if(H[i]&&String(H[i]).toLowerCase()===h)return true;}return false;}'
        . 'function sp(s){if(typeof s!=="string"||s.indexOf(P)===0)return false;for(var i=0;i<R.length;i++){if(s.indexOf(R[i])===0)return true;}return false;}'
        . 'function fu(s){if(typeof s!=="string")return s;if(s.indexOf(po+P)===0)return s;try{var u=new URL(s,po);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());if(sh&&u.pathname.indexOf(P)===0)return po+u.pathname+u.search+u.hash;if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname)))return po+P+u.pathname+u.search+u.hash;}catch(e){}return sp(s)?po+P+s:s;}'
        . 'function wru(s){if(typeof s!=="string")return s;try{var u=new URL(s,L.href);if((u.origin===po)&&u.pathname.indexOf("/ipmi_ws_relay.php")===0)return wo+u.pathname+u.search+u.hash;var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());var wsScheme=String(u.protocol||"").toLowerCase();if(wsScheme!=="ws:"&&wsScheme!=="wss:"){wsScheme=(L.protocol==="https:"?"wss:":"ws:");}var targetHost=u.host;if((sh&&sp(u.pathname))&&H.length>0){targetHost=String(H[0]);}if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname))){var target=wsScheme.replace(":","")+"://"+targetHost+u.pathname+u.search;return wo+W+encodeURIComponent(target);}}catch(e){}return s;}'
        . 'function fx(n){if(typeof A!=="string"||!A)return n;n=n||{};try{var Hd=new Headers(n.headers||{});if(!Hd.has("X-Auth-Token"))Hd.set("X-Auth-Token",A);n.headers=Hd;}catch(e){}return n;}'
        . 'if(window.fetch){var of=window.fetch;window.fetch=function(i,n){try{n=fx(n||{});'
        . 'if(typeof i==="string")return of.call(this,fu(i),n);'
        . 'if(window.Request&&i instanceof Request){if(i.url.indexOf(po+P)===0)return of.call(this,i,n);var u=new URL(i.url,L.href);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());'
        . 'var ru="";if(sh&&u.pathname.indexOf(P)===0){ru=po+u.pathname+u.search+u.hash;}else if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname))){ru=po+P+u.pathname+u.search+u.hash;}'
        . 'if(ru){var Rq=new Request(ru,i);try{var H2=new Headers(Rq.headers);if(typeof A==="string"&&A&&!H2.has("X-Auth-Token"))H2.set("X-Auth-Token",A);Rq=new Request(Rq,{headers:H2});}catch(e2){}return of.call(this,Rq,n);}}'
        . '}catch(e){}return of.call(this,i,n);};}'
        . 'var xp=XMLHttpRequest&&XMLHttpRequest.prototype;if(xp&&xp.open){var oo=xp.open;xp.open=function(m,u,a3,a4,a5){try{if(typeof u==="string")u=fu(u);}catch(e){}return oo.call(this,m,u,a3,a4,a5);};}'
        . 'if(xp&&xp.send){var xs=xp.send;xp.send=function(b){try{if(typeof A==="string"&&A){try{this.setRequestHeader("X-Auth-Token",A);}catch(e3){}}}catch(e4){}return xs.call(this,b);};}'
        . 'if(window.WebSocket){var OW=WebSocket;window.WebSocket=function(u,p){try{if(typeof u==="string")u=wru(u);}catch(e){}return new OW(u,p);};}'
        . 'if(window.EventSource){var OES=EventSource;window.EventSource=function(u,c){try{if(typeof u==="string")u=fu(u);}catch(e6){}return new OES(u,c);};'
        . 'try{window.EventSource.prototype=OES.prototype;}catch(e7){}}'
        . 'try{if(typeof A==="string"){var dc=String(document.cookie||"");'
        . 'var hasAuth=/(?:^|;\\s*)(session|sessionKey|QSESSIONID)=/i.test(dc);'
        . 'if(hasAuth&&String(location.hash||"").toLowerCase()==="#login"){location.hash="#/dashboard";}}}catch(e8){}'
        . '})();</script>'
        . '<script data-ipmi-proxy-ilo-patch="1">'
        . '(function(){'
        . 'function sens(u){u=String(u||"");return u.indexOf("health_summary")>=0||u.indexOf("/json/health")>=0||u.indexOf("/sse/")>=0;}'
        . 'function key(u){try{return String(u).split("?")[0];}catch(e){return"";}}'
        . 'function install(){var jq=window.jQuery||window.$;if(!jq||!jq.ajax||jq.ajax.__ipmiProxyAjaxBackoff)return;'
        . 'var oa=jq.ajax;var st={};'
        . 'var w=function(a,b){var callArgs=arguments;'
        . 'var opts=(typeof a==="object"&&a!==null)?a:(b||{url:a});'
        . 'var u=(opts&&opts.url)||"";if(!sens(u))return oa.apply(this,callArgs);'
        . 'var k=key(u)||String(u||"");var slot=st[k]||(st[k]={cf:0,next:0});var now=Date.now();var wait=slot.next>now?slot.next-now:0;'
        . 'function arm(xhr){if(!xhr||!xhr.done||!xhr.fail)return;'
        . 'xhr.done(function(){slot.cf=0;slot.next=0;});'
        . 'xhr.fail(function(xhrObj,ts){if(ts==="abort")return;'
        . 'var bad=!xhrObj||xhrObj.status>=400||ts==="error"||ts==="timeout";'
        . 'if(bad){slot.cf=slot.cf<8?slot.cf+1:8;slot.next=Date.now()+Math.min(3e4,1e3*Math.pow(2,slot.cf));}});}'
        . 'if(wait>0){var d=jq.Deferred();var self=this;var tid=setTimeout(function(){var x=oa.apply(self,callArgs);arm(x);if(x&&x.done)x.done(d.resolve).fail(d.reject);else try{d.reject();}catch(e){}},wait);'
        . 'var p=d.promise();try{p.abort=function(){clearTimeout(tid);};}catch(e){}return p;}'
        . 'var x=oa.apply(this,callArgs);arm(x);return x;};w.__ipmiProxyAjaxBackoff=true;jq.ajax=w;}'
        . 'install();var n=0;var t=setInterval(function(){install();if(++n>=40)clearInterval(t);},250);'
        . '})();</script>';

    // Do not inject <base href>: iLO pages mix root-relative (/js/...) and sibling-relative
    // (jquery.translate.js) URLs; a single base breaks the latter into /TOKEN/jquery... (400).

    return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
}

function ipmiProxyIsIloFamily(string $bmcType): bool
{
    return ipmiWebBmcFamily($bmcType) === 'ilo';
}

function ipmiProxyInjectBmcAuthHeaderPatch(string $html, string $token, ?string $authToken = null): string
{
    if ($authToken === null || trim($authToken) === '') {
        return $html;
    }
    if (stripos($html, 'data-ipmi-proxy-auth-patch') !== false) {
        return $html;
    }
    $px = '/ipmi_proxy.php/' . rawurlencode($token);
    $authJs = json_encode(trim((string)$authToken), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $patch = '<script data-ipmi-proxy-auth-patch="1">'
        . '(function(){var A=' . $authJs . ';if(!A)return;'
        . 'if(window.fetch){var of=window.fetch;window.fetch=function(i,n){try{n=n||{};var H=new Headers(n.headers||{});'
        . 'if(!H.has("X-Auth-Token"))H.set("X-Auth-Token",A);n.headers=H;}catch(e){}return of.call(this,i,n);};}'
        . 'var xp=XMLHttpRequest&&XMLHttpRequest.prototype;if(xp&&xp.send){var os=xp.send;xp.send=function(b){try{this.setRequestHeader("X-Auth-Token",A);}catch(e){}return os.call(this,b);};}'
        . '})();</script>';
    return preg_replace('/<head(\s[^>]*)?>/i', '$0' . $patch, $html, 1) ?? $html;
}

function ipmiProxyInjectGenericHeadFixes(
    string $html,
    string $token,
    string $bmcIp,
    ?string $authToken = null,
    ?string $csrfToken = null,
    bool $forceSupermicroLegacy = false,
    bool $disableLoginHashRedirect = false
): string {
    if (stripos($html, 'data-ipmi-proxy-generic-patch') !== false) {
        return $html;
    }

    $px = '/ipmi_proxy.php/' . rawurlencode($token);
    $pxJs = json_encode($px, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $authJs = json_encode(trim((string)($authToken ?? '')), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $csrfJs = json_encode(trim((string)($csrfToken ?? '')), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

    $bmcHosts = [];
    if ($bmcIp !== '') {
        foreach (ipmiProxyGetBmcHostAliases($bmcIp) as $h) {
            $h = trim((string) $h);
            if ($h !== '') {
                $bmcHosts[] = $h;
            }
        }
    }
    $bmcHosts = array_values(array_unique(array_map(static function ($v) {
        return strtolower(trim((string) $v));
    }, $bmcHosts)));
    $hostsJs = json_encode($bmcHosts, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

    $forceSm = $forceSupermicroLegacy ? '1' : '0';
    $disableHashRedirect = $disableLoginHashRedirect ? '1' : '0';
    $patch = '<script data-ipmi-proxy-generic-patch="1">'
        . '(function(){'
        . 'try{var _a=window.alert;window.alert=function(msg){try{var s=String(msg||"").toLowerCase();'
        . 'if(s.indexOf("session has timed out")>=0||s.indexOf("session timed out")>=0||s.indexOf("session is running")>=0||s.indexOf("already a session")>=0){return;}'
        . '}catch(e){}return _a.apply(this,arguments);};}catch(e){}'
        . 'var P=' . $pxJs . ';var W=' . $wsRelayJs . ';var A=' . $authJs . ';var C=' . $csrfJs . ';var H=' . $hostsJs . ';'
        . 'var R=["/redfish/v1/","/redfish/","/rest/v1/","/rest/","/restapi/","/session","/data/","/rpc/","/js/","/css/","/fonts/","/img/","/images/","/json/","/api/","/html/","/themes/","/sse/","/cgi/","/res/","/java/","/Java/","/viewer/","/console/","/kvm/","/avct/","/favicon.ico"];'
        . 'var L=location;var po=L.protocol+"//"+L.host;var wo=(L.protocol==="https:"?"wss:":"ws:")+"//"+L.host;'
        . 'var F=' . $forceSm . ';'
        . 'var D=' . $disableHashRedirect . ';'
        . 'if(F){try{if(window.sessionStorage&&!sessionStorage.getItem("_x_auth")){sessionStorage.setItem("_x_auth","ipmi_proxy");}}catch(e0){}}'
        . 'function iH(h){if(!h)return false;h=String(h).toLowerCase();for(var i=0;i<H.length;i++){if(H[i]&&String(H[i]).toLowerCase()===h)return true;}return false;}'
        . 'function sp(s){if(typeof s!=="string"||s.indexOf(P)===0)return false;for(var i=0;i<R.length;i++){if(s.indexOf(R[i])===0)return true;}return false;}'
        . 'function fu(s){if(typeof s!=="string")return s;if(s.indexOf(po+P)===0)return s;try{var u=new URL(s,po);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());if(sh&&u.pathname.indexOf(P)===0)return po+u.pathname+u.search+u.hash;if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname)))return po+P+u.pathname+u.search+u.hash;}catch(e){}return sp(s)?po+P+s:s;}'
        . 'function wru(s){if(typeof s!=="string")return s;try{var u=new URL(s,L.href);if((u.origin===po)&&u.pathname.indexOf("/ipmi_ws_relay.php")===0)return wo+u.pathname+u.search+u.hash;var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());var wsScheme=String(u.protocol||"").toLowerCase();if(wsScheme!=="ws:"&&wsScheme!=="wss:"){wsScheme=(L.protocol==="https:"?"wss:":"ws:");}var targetHost=u.host;if((sh&&sp(u.pathname))&&H.length>0){targetHost=String(H[0]);}if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname))){var target=wsScheme.replace(":","")+"://"+targetHost+u.pathname+u.search;return wo+W+encodeURIComponent(target);}}catch(e){}return s;}'
        . 'function isLogoutUrl(s){try{var u=new URL(String(s||""),po);var p=String(u.pathname||"").toLowerCase();if(p.indexOf("/cgi/logout.cgi")===0)return true;}catch(e){}try{return String(s||"").toLowerCase().indexOf("/cgi/logout.cgi")>=0;}catch(e2){return false;}}'
        . 'function gc(n){try{var m=document.cookie.match(new RegExp("(?:^|;\\\\s*)"+n+"=([^;]+)"));return m?decodeURIComponent(m[1]):"";}catch(e){return"";}}'
        . 'function csrf(){var v="";if(typeof C==="string"&&C)v=C;var g=gc("garc");if(g)v=g;var t=gc("CSRFToken");if(t)v=t;return v;}'
        . 'function addAuth(n){n=n||{};try{var Hd=new Headers(n.headers||{});'
        . 'if(typeof A==="string"&&A&&!Hd.has("X-Auth-Token"))Hd.set("X-Auth-Token",A);'
        . 'var cv=csrf();if(cv){if(!Hd.has("X-CSRFTOKEN"))Hd.set("X-CSRFTOKEN",cv);if(!Hd.has("X-CSRF-Token"))Hd.set("X-CSRF-Token",cv);}n.headers=Hd;}catch(e){}return n;}'
        . 'if(window.fetch){var of=window.fetch;window.fetch=function(i,n){try{n=addAuth(n||{});'
        . 'if(F&&((typeof i==="string"&&isLogoutUrl(i))||(i&&i.url&&isLogoutUrl(i.url)))){return Promise.reject(new Error("ipmi_proxy_logout_blocked"));}'
        . 'if(typeof i==="string")return of.call(this,fu(i),n);'
        . 'if(window.Request&&i instanceof Request){if(i.url.indexOf(po+P)===0)return of.call(this,i,n);var u=new URL(i.url,L.href);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());'
        . 'var ru="";if(sh&&u.pathname.indexOf(P)===0){ru=po+u.pathname+u.search+u.hash;}else if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname))){ru=po+P+u.pathname+u.search+u.hash;}'
        . 'if(ru){var Rq=new Request(ru,i);'
        . 'try{var H2=new Headers(Rq.headers);if(typeof A==="string"&&A&&!H2.has("X-Auth-Token"))H2.set("X-Auth-Token",A);Rq=new Request(Rq,{headers:H2});}catch(e2){}return of.call(this,Rq,n);} }'
        . '}catch(e){}return of.call(this,i,n);};}'
        . 'var xp=XMLHttpRequest&&XMLHttpRequest.prototype;if(xp&&xp.open){var oo=xp.open;xp.open=function(m,u,a3,a4,a5){try{this.__ipmi_proxy_url=u;if(typeof u==="string")u=fu(u);this.__ipmi_proxy_url=u;}catch(e){}return oo.call(this,m,u,a3,a4,a5);};}'
        . 'if(xp&&xp.send){var os=xp.send;xp.send=function(b){try{if(F&&isLogoutUrl(this.__ipmi_proxy_url)){try{this.abort();}catch(e0){}return;}if(typeof A==="string"&&A){try{this.setRequestHeader("X-Auth-Token",A);}catch(e3){}}'
        . 'var cv=csrf();if(cv){try{this.setRequestHeader("X-CSRFTOKEN",cv);}catch(e5){}try{this.setRequestHeader("X-CSRF-Token",cv);}catch(e6){}}}catch(e4){}return os.call(this,b);};}'
        . 'if(window.WebSocket){var OW=WebSocket;window.WebSocket=function(u,p){try{if(typeof u==="string")u=wru(u);}catch(e){}return new OW(u,p);};}'
        . 'if(window.EventSource){var OES=EventSource;window.EventSource=function(u,c){try{if(typeof u==="string")u=fu(u);}catch(e6){}return new OES(u,c);};'
        . 'try{window.EventSource.prototype=OES.prototype;}catch(e7){}}'
        . 'if(F){try{'
        . 'if(window.navigator&&typeof navigator.sendBeacon==="function"){var osb=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){try{if(isLogoutUrl(u)){return true;}}catch(e13){}return osb(u,d);};}'
        . 'if(window.HTMLFormElement&&HTMLFormElement.prototype&&HTMLFormElement.prototype.submit){var sf=HTMLFormElement.prototype.submit;HTMLFormElement.prototype.submit=function(){try{var a=this.getAttribute("action")||this.action||"";if(isLogoutUrl(a)){return false;}}catch(e10){}return sf.call(this);};}'
        . 'document.addEventListener("click",function(ev){try{var n=ev.target;var a=(n&&n.closest)?n.closest("a[href]"):null;if(a&&isLogoutUrl(a.getAttribute("href")||a.href)){ev.preventDefault();ev.stopPropagation();return false;}}catch(e11){}},true);'
        . 'if(typeof window.logout_alert==="function"){window.logout_alert=function(){return false;};}'
        . 'if(typeof window.sessiontimeout==="function"){window.sessiontimeout=function(){return false;};}'
        . 'if(typeof window.sessionTimeout==="function"){window.sessionTimeout=function(){return false;};}'
        . '}catch(e12){}}'
        . 'try{var dc=String(document.cookie||"");'
        . 'var h=(location.hash||"").toLowerCase();'
        . 'var sidLike=/(?:^|;\\s*)(sid|sessionid|session_id|session)=/i.test(dc);'
        . 'var isLoginHash=((h==="#login")||(h==="#/login"));'
        . 'var isLoginDoc=false;'
        . 'try{var t=String(document.title||"").toLowerCase();'
        . 'var hasPw=!!(document.querySelector&&document.querySelector("input[type=password]"));'
        . 'if(hasPw&&(t.indexOf("login")>=0||t.indexOf("supermicro")>=0||t.indexOf("asrock")>=0)){isLoginDoc=true;}'
        . '}catch(e9){}'
        . 'if(F&&sidLike&&(isLoginHash||isLoginDoc)){'
        . ' if(!sessionStorage.getItem("ipmi_sm_legacy")){sessionStorage.setItem("ipmi_sm_legacy","1");location.href=P+"/cgi/url_redirect.cgi?url_name=topmenu";return;}'
        . '}'
        . 'if(!F&&!D&&sidLike&&isLoginHash){location.hash="#/dashboard";}'
        . '}catch(e8){}'
        . '})();</script>';

    return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
}

/**
 * Vendor-agnostic KVM autolaunch preamble (FAMILY, PLAN, flow control, navigation helpers).
 */
function ipmiProxyBuildKvmAutoLaunchPreambleJs(string $familyJs, string $planJs, string $pxJs, string $autoJs, string $dbgLit): string
{
    return '(function(){'
        . 'var FAMILY=' . $familyJs . ';var PLAN=' . $planJs . ';var P=' . $pxJs . ';var AUTO=' . $autoJs . ';var DBG=' . $dbgLit . ';'
        . 'function _kvmDbg(ev,extra){try{if(!DBG)return;}catch(e0){return;}try{if(window.console&&console.info)console.info("[ipmi-kvm]",ev,extra!=null?extra:"");}catch(e1){}}'
        . 'var q=null;try{q=new URLSearchParams(location.search||"");}catch(e){q=null;}'
        . 'var queryAuto=(q&&q.get("ipmi_kvm_auto")==="1");'
        . 'try{if(queryAuto&&window.sessionStorage){sessionStorage.setItem("_ipmi_kvm_auto_flow","1");sessionStorage.removeItem("_ipmi_kvm_autolaunch_done");sessionStorage.removeItem("_ipmi_kvm_app_redirected");}}catch(_e0){}'
        . 'var flowActive=false;'
        . 'try{flowActive=queryAuto||AUTO||(window.sessionStorage&&sessionStorage.getItem("_ipmi_kvm_auto_flow")==="1");}catch(_e1){flowActive=queryAuto||AUTO;}'
        . 'if(!flowActive){return;}'
        . 'if(FAMILY==="ilo"&&PLAN&&PLAN.should_attempt_proxy_autolaunch===false){'
        . 'try{_kvmDbg("ilo_autolaunch_suppressed",{verdict:String(PLAN.ilo_native_console_verdict||""),cap:String(PLAN.console_capability||""),suppression:String(PLAN.autolaunch_suppression_detail||"")});}catch(_eSup){}'
        . 'try{_kvmDbg("ilo_no_transport_after_shell_launch",{suppressed:1,suppression:String(PLAN.autolaunch_suppression_detail||"")});}catch(_eNt){}'
        . 'return;}'
        . 'var launchDone=false;'
        . 'try{launchDone=!!(window.sessionStorage&&sessionStorage.getItem("_ipmi_kvm_autolaunch_done")==="1");}catch(_e2){launchDone=false;}'
        . 'function go(p){try{location.href=P+p;}catch(e){}}'
        . 'function pathLower(){try{return String(location.pathname||"").toLowerCase();}catch(e){return"";}}'
        . 'function markDone(){try{if(window.sessionStorage){sessionStorage.setItem("_ipmi_kvm_autolaunch_done","1");}}catch(e){}}'
        . 'function markAppRedirected(){try{if(window.sessionStorage){sessionStorage.setItem("_ipmi_kvm_app_redirected","1");}}catch(e){}}'
        . 'function wasAppRedirected(){try{return !!(window.sessionStorage&&sessionStorage.getItem("_ipmi_kvm_app_redirected")==="1");}catch(e){return false;}}'
        . 'try{var _cs0=document.currentScript;if(_cs0){var _pm=_cs0.getAttribute("data-ipmi-kvm-patch-mode")||"";_kvmDbg("ilo_kvm_runtime_debug_matrix",{js_syntactically_valid:_cs0.getAttribute("data-ipmi-kvm-js-valid")==="1"?"yes":"no",runtime_patch_injected:_pm==="safe_fallback"?"no":"yes",application_path_loaded_now:pathLower().indexOf("/html/application.html")>=0?"yes":"no",note:"dynamic_shell_helper_live_final_in_il_confirmation_signals_collected_and_il_console_readiness_verdict"});}}catch(_eM0){}'
        . 'function forceSameTabOpen(ctx){try{'
        . 'if(!ctx||!ctx.open||ctx.__ipmi_kvm_open_patched)return;'
        . 'var ow=ctx.open.bind(ctx);'
        . 'ctx.open=function(u,n,f){try{if(typeof u==="string"&&u!==""){ctx.location.href=u;return ctx;}}catch(_e0){}return ow(u,n,f);};'
        . 'ctx.__ipmi_kvm_open_patched=true;'
        . '}catch(e){}}';
}

/**
 * iLO-only DOM / renderer helpers (collectContexts, startHtml5Irc shims).
 */
function ipmiProxyBuildKvmAutoLaunchIloDomHelpersJs(): string
{
    return ''
        . 'function fnSrc(fn){try{return Function.prototype.toString.call(fn);}catch(e){return"";}}'
        . 'function isRendererStartFn(fn){var s=fnSrc(fn);if(!s)return false;return s.indexOf("new Renderer")!==-1||s.indexOf("renderer = new Renderer")!==-1||s.indexOf("htmlIrcWindowMode")!==-1;}'
        . 'function isWrapperStartFn(fn){var s=fnSrc(fn);if(!s)return false;return s.indexOf("iLO.startHtml5Irc")!==-1&&s.indexOf("new Renderer")===-1;}'
        . 'function getIloDirectTopRenderer(ctx){try{var t=(ctx&&ctx.top)?ctx.top:window.top;if(t&&isRendererStartFn(t.startHtml5Irc))return t;}catch(e){}return null;}'
        . 'function hasIloRendererHost(ctx){try{'
        . 'if(!ctx)return false;'
        . 'if(isRendererStartFn(ctx.startHtml5Irc))return true;'
        . 'if(ctx.document&&ctx.document.getElementById&&ctx.document.getElementById("ircWindow"))return true;'
        . '}catch(e){}return false;}'
        . 'function findIloRendererHost(ctx){'
        . 'var out=[];'
        . 'function add(c){if(!c)return;for(var i=0;i<out.length;i++){if(out[i]===c)return;}out.push(c);}'
        . 'try{add(ctx);}catch(e0){}'
        . 'try{if(ctx&&ctx.parent&&ctx.parent!==ctx)add(ctx.parent);}catch(e1){}'
        . 'try{if(ctx&&ctx.parent&&ctx.parent.parent&&ctx.parent.parent!==ctx.parent)add(ctx.parent.parent);}catch(e2){}'
        . 'try{if(ctx&&ctx.top&&ctx.top!==ctx)add(ctx.top);}catch(e3){}'
        . 'try{if(ctx&&ctx.top&&ctx.top.frames&&ctx.top.frames.appFrame)add(ctx.top.frames.appFrame);}catch(e4){}'
        . 'for(var j=0;j<out.length;j++){if(hasIloRendererHost(out[j]))return out[j];}'
        . 'for(var k=0;k<out.length;k++){try{if(out[k]&&out[k].frameDirectory&&out[k].frameContent){return out[k];}}catch(_e5){}}'
        . 'return ctx||null;'
        . '}'
        . 'function bindIloTopPage(ctx){try{'
        . 'if(!ctx)return null;'
        . 'var host=findIloRendererHost(ctx)||ctx;'
        . 'if(ctx.iLOGlobal){ctx.iLOGlobal.topPage=host;}'
        . 'if(host&&host.iLOGlobal){host.iLOGlobal.topPage=host;}'
        . 'if(ctx.iLOGlobal&&ctx.iLOGlobal.topPage){ctx.iLOGlobal.topPage.appFrame=host;}'
        . 'if(host&&host.iLOGlobal&&host.iLOGlobal.topPage){host.iLOGlobal.topPage.appFrame=host;}'
        . 'return host;'
        . '}catch(e){return ctx||null;}}'
        . 'function ensureIloStartPatched(ctx){try{'
        . 'if(!ctx||!ctx.iLO||typeof ctx.iLO.startHtml5Irc!=="function"||ctx.iLO.__ipmi_start_patched){return;}'
        . 'ctx.iLO.__ipmi_start_orig=ctx.iLO.startHtml5Irc;'
        . 'ctx.iLO.startHtml5Irc=function(){try{'
        . 'try{if(ctx.iLO&&typeof ctx.iLO.setCookie==="function"){ctx.iLO.setCookie("irc",["last","html5"]);}}catch(_c0){}'
        . 'var directTop=getIloDirectTopRenderer(ctx);'
        . 'if(directTop){forceSameTabOpen(directTop);ensureIloFrameResizeShim(directTop);clearIloStaleRenderer(directTop);try{directTop.startHtml5Irc({mode:"WINDOW"});return;}catch(_dt1){}try{directTop.startHtml5Irc();return;}catch(_dt2){}}'
        . 'var host=bindIloTopPage(ctx)||findIloRendererHost(ctx)||ctx;'
        . 'ensureIloFrameResizeShim(host);clearIloStaleRenderer(host);clearIloStaleRenderer(ctx);'
        . 'if(host){forceSameTabOpen(host);'
        . 'if(isRendererStartFn(host.startHtml5Irc)){try{host.startHtml5Irc({mode:"WINDOW"});return;}catch(_e1){}try{host.startHtml5Irc();return;}catch(_e2){}}'
        . '}'
        . 'var orig=ctx.iLO.__ipmi_start_orig;'
        . 'if(orig&&orig!==ctx.iLO.startHtml5Irc){try{return orig.apply(ctx.iLO,arguments);}catch(_e3){}}'
        . '}catch(_e0){}'
        . '};'
        . 'ctx.iLO.__ipmi_start_patched=true;'
        . '}catch(e){}}'
        . 'function isShown(node){try{return !!(node&&node.offsetParent!==null);}catch(e){return false;}}'
        . 'function hasIloShellHost(ctx){try{return !!(ctx&&ctx.document&&ctx.document.getElementById&&ctx.document.getElementById("frameContent"));}catch(e){return false;}}'
        . 'function getIloShellHost(ctx){var out=[];function add(c){if(!c)return;for(var i=0;i<out.length;i++){if(out[i]===c)return;}out.push(c);}try{add(ctx);}catch(e0){}try{if(ctx&&ctx.parent&&ctx.parent!==ctx)add(ctx.parent);}catch(e1){}try{if(ctx&&ctx.parent&&ctx.parent.parent&&ctx.parent.parent!==ctx.parent)add(ctx.parent.parent);}catch(e2){}try{if(ctx&&ctx.top&&ctx.top!==ctx)add(ctx.top);}catch(e3){}for(var j=0;j<out.length;j++){if(hasIloShellHost(out[j]))return out[j];}return null;}'
        . 'function getIloFrameContent(ctx){try{var sh=getIloShellHost(ctx)||ctx;if(sh&&sh.frames&&sh.frames.frameContent)return sh.frames.frameContent;}catch(e){}return null;}'
        . 'function getIloIframeContent(ctx){try{var fc=getIloFrameContent(ctx);if(fc&&fc.frames&&fc.frames.iframeContent)return fc.frames.iframeContent;}catch(e){}return null;}'
        . 'function getIloIframeContentEl(ctx){try{var fc=getIloFrameContent(ctx);if(fc&&fc.document&&fc.document.getElementById){return fc.document.getElementById("iframeContent");}}catch(e){}return null;}'
        . 'function ensureIloIndexAppLoaded(ctx){try{'
        . 'if(!ctx||!ctx.document||!ctx.document.getElementById)return false;'
        . 'var app=ctx.document.getElementById("appFrame");'
        . 'if(!app)return false;'
        . 'var src=String(app.getAttribute("src")||"").toLowerCase();'
        . 'if(src.indexOf("html/application.html")!==-1)return false;'
        . 'if(typeof ctx.showApplication==="function"){ctx.showApplication();return true;}'
        . 'if(src===""||src==="about:blank"){app.setAttribute("src","html/application.html");return true;}'
        . 'return false;'
        . '}catch(e){return false;}}'
        . 'function ensureIloFrameResizeShim(ctx){try{var host=getIloShellHost(ctx)||findIloRendererHost(ctx)||ctx;if(!host||!host.document||!host.document.getElementById)return;var fd=host.document.getElementById("frameDirectory");if(fd&&fd.contentWindow&&typeof fd.contentWindow.frameResize!=="function"){fd.contentWindow.frameResize=function(){};}}catch(e){}}'
        . 'function hasIloRcPage(ctx){try{var ic=getIloIframeContent(ctx);var p=String((ic&&ic.location&&ic.location.pathname)||"").toLowerCase();var ok=(p.indexOf("/html/rc_info.html")!==-1);if(ok){try{var shell=getIloShellHost(ctx)||findIloRendererHost(ctx)||ctx;if(shell){shell.__ipmi_rc_info_loading_ts=0;}}catch(_e0){}}return ok;}catch(e){return false;}}'
        . 'function ensureIloShellLoaded(ctx){try{'
        . 'var host=getIloShellHost(ctx);'
        . 'if(!host||ctx!==host||!host.document)return false;'
        . 'try{if(host.iLOGlobal){host.iLOGlobal.initialLink="rc_info.html";host.iLOGlobal.content="rc_info.html";host.iLOGlobal.initialTab=0;}}catch(_e0){}'
        . 'var frameEl=host.document.getElementById("frameContent");'
        . 'if(!frameEl)return false;'
        . 'var src=String(frameEl.getAttribute("src")||"").toLowerCase();'
        . 'if(src===""||src==="about:blank"){frameEl.setAttribute("src","content.html");return true;}'
        . 'return false;'
        . '}catch(e){return false;}}'
        . 'function rcWindowVisible(ctx){try{'
        . 'if(!ctx||!ctx.document)return false;'
        . 'var w=ctx.document.getElementById("ircWindow");'
        . 'if(!w)return false;'
        . 'try{if(typeof ctx.jQuery==="function"&&ctx.jQuery("#ircWindow").dialog("instance"))return true;}catch(_e0){}'
        . 'return !!(w.offsetParent!==null||String((w.style&&w.style.display)||"").toLowerCase()!=="none");'
        . '}catch(e){return false;}}'
        . 'function clearIloStaleRenderer(ctx){try{'
        . 'var host=findIloRendererHost(ctx)||ctx;if(!host)return false;'
        . 'var target=host,stale=false;'
        . 'try{stale=!!(host.renderer&&host.renderer.connected&&!rcWindowVisible(host));}catch(_e0){}'
        . 'if(!stale&&ctx&&ctx!==host){try{if(ctx.renderer&&ctx.renderer.connected&&!rcWindowVisible(ctx)){target=ctx;stale=true;}}catch(_e1){}}'
        . 'if(!stale||!target)return false;'
        . 'try{if(target.renderer&&target.renderer.worker&&typeof target.renderer.worker.close==="function"){target.renderer.worker.close();}}catch(_e2){}'
        . 'try{if(target.renderer&&target.renderer.decoder&&typeof target.renderer.decoder.terminate==="function"){target.renderer.decoder.terminate();}}catch(_e3){}'
        . 'try{if(target.renderer&&typeof target.renderer.close==="function"){target.renderer.close();}}catch(_e4){}'
        . 'try{if(target.renderer){target.renderer.connected=false;}}catch(_e5){}'
        . 'try{target.renderer=null;}catch(_e6){}'
        . 'try{var w=target.document&&target.document.getElementById?target.document.getElementById("ircWindow"):null;if(w){w.style.display="none";}}catch(_e7){}'
        . 'return true;'
        . '}catch(e){return false;}}'
        . 'function rendererConnected(ctx){try{return !!(ctx&&ctx.renderer&&ctx.renderer.connected);}catch(e){return false;}}'
        . 'function consoleVisible(ctx){try{'
        . 'if(!ctx)return false;'
        . 'if(rendererConnected(ctx))return true;'
        . 'var host=findIloRendererHost(ctx)||ctx;'
        . 'if(host&&host!==ctx&&rendererConnected(host))return true;'
        . '}catch(e){}return false;}'
        . 'function findIloHtml5Button(ctx){try{'
        . 'if(!ctx||!ctx.document)return null;'
        . 'return ctx.document.getElementById("HRCButton")||ctx.document.querySelector("button[data-localize=\'rc_info.html5Console\']")||null;'
        . '}catch(e){return null;}}'
        . 'function iloKvText(s){s=String(s||"").toLowerCase();return(s.indexOf("html5")>=0&&(s.indexOf("console")>=0||s.indexOf("remote")>=0||s.indexOf("irc")>=0))||(s.indexOf("integrated")>=0&&s.indexOf("remote")>=0)||(s.indexOf("launch")>=0&&s.indexOf("console")>=0);}'
        . 'function iloConsoleKeyword(s){s=String(s||"").toLowerCase();if(iloKvText(s))return true;if(s.indexOf("remote console")>=0)return true;if(s.indexOf("integrated remote console")>=0)return true;if(s.indexOf("launch console")>=0)return true;if(s.indexOf("html5 console")>=0)return true;if(s.indexOf("virtual console")>=0)return true;if(s.indexOf("kvm")>=0&&(s.indexOf("console")>=0||s.indexOf("launch")>=0||s.indexOf("remote")>=0))return true;if(s.indexOf("irc")>=0&&s.indexOf("console")>=0)return true;if(s==="console"||s.indexOf(" console")>=0)return true;return false;}'
        . 'function ipmiProxyIloFrameCandidateScore(el){try{var s=0,src=String(el.getAttribute("src")||"").toLowerCase(),nm=String(el.getAttribute("name")||"").toLowerCase(),id=String(el.getAttribute("id")||"").toLowerCase(),cl=String(el.getAttribute("class")||"").toLowerCase(),ti=String(el.getAttribute("title")||"").toLowerCase();if(src.indexOf("rc_info")>=0||src.indexOf("irc.html")>=0)s+=62;if(src.indexOf("application.html")>=0)s+=55;if(src.indexOf("jnlp")>=0||src.indexOf("jnlp_template")>=0)s+=38;if(src.indexOf("html/irc")>=0)s+=45;if(nm.indexOf("appframe")>=0||id.indexOf("appframe")>=0||id==="appframe")s+=28;if(cl.indexOf("console")>=0||ti.indexOf("console")>=0)s+=18;if(nm.indexOf("frame")>=0&&src.indexOf("html/")>=0)s+=12;if(id==="framecontent"||nm==="framecontent"||id==="framedirectory")s+=8;if(src.indexOf("content.html")>=0||src.indexOf("masthead")>=0)s+=6;return s;}catch(e){return 0;}}'
        . 'function ipmiProxyIloFrameCandidateClassify(el,sc){try{var src=String(el.getAttribute("src")||"").toLowerCase(),id=String(el.getAttribute("id")||"").toLowerCase(),nm=String(el.getAttribute("name")||"").toLowerCase();if(id==="framecontent"||nm==="framecontent"||src.indexOf("content.html")>=0)return"shell_frame";if(sc>=40||(src.indexOf("rc_info")>=0||src.indexOf("application.html")>=0||src.indexOf("irc")>=0))return"console_frame_candidate";if(sc>=22||src.indexOf("html/")>=0)return"launcher_frame";return"unrelated";}catch(e){return"unrelated";}}'
        . 'function ipmiProxyIloFindConsoleFrameCandidate(doc){try{if(!doc||!doc.querySelectorAll)return null;var F=doc.querySelectorAll("iframe,frame");var best=null,bs=0;for(var i=0;i<F.length&&i<48;i++){var sc=ipmiProxyIloFrameCandidateScore(F[i]);if(sc>bs){bs=sc;best=F[i];}}if(bs>=22)return {el:best,score:bs,kind:ipmiProxyIloFrameCandidateClassify(best,bs)};}catch(e2){}return null;}'
        . 'function ipmiProxyIloFindNavigableFrame(doc){try{if(!doc||!doc.querySelectorAll)return null;var F=doc.querySelectorAll("iframe,frame");var best=null,bs=0;for(var j=0;j<F.length&&j<48;j++){var sc2=ipmiProxyIloFrameCandidateScore(F[j]);if(sc2>bs){bs=sc2;best=F[j];}}if(bs>=14&&best)return {el:best,score:bs,kind:ipmiProxyIloFrameCandidateClassify(best,bs)};}catch(e3){}return null;}'
        . 'function ipmiProxyIloFindConsoleModuleInApplication(doc){try{if(!doc||!doc.querySelectorAll)return null;var L=doc.querySelectorAll("a[href],button,[role=button],[role=tab],[role=menuitem],.hp-menu-item,.gwt-MenuItem,.nav-item,.tree_view a,li.gwt-MenuItem,[class*=console],[id*=console],[class*=remote],[id*=irc]");for(var i=0;i<L.length&&i<220;i++){var e=L[i],tx=String(e.textContent||e.innerText||"");if(iloConsoleKeyword(tx))return e;var h=String(e.getAttribute("href")||"").toLowerCase();if(h.indexOf("rc_info")>=0||h.indexOf("irc")>=0||h.indexOf("html5")>=0)return e;}return null;}catch(e){return null;}}'
        . 'function ipmiProxyIloFindConsoleLaunchActionInApplication(doc){try{var d0=ipmiProxyIloFindConsoleModuleInApplication(doc);if(d0)return d0;var d1=findIloDeepLaunch({document:doc});if(d1)return d1;var d2=findIloHeuristicLaunch({document:doc});if(d2)return d2;return findIloBestConsoleHrefClickable(doc);}catch(e2){return null;}}'
        . 'function ipmiProxyIloFollowConsoleFrameTransition(doc,st){try{if(!doc||!st||st.reported.consoleFrameFollowed)return false;var fc=ipmiProxyIloFindConsoleFrameCandidate(doc);if(!fc||!fc.el)return false;var src=String(fc.el.getAttribute("src")||"").toLowerCase();var shellish=(fc.kind==="shell_frame")||(src.indexOf("content.html")>=0||src.indexOf("masthead")>=0||src===""||src==="about:blank");if(fc.score>=16&&shellish&&src.indexOf("rc_info")<0&&src.indexOf("irc")<0){try{fc.el.setAttribute("src","html/rc_info.html");st.reported.consoleFrameFollowed=true;_kvmDbg("ilo_console_content_frame_followed",{score:fc.score,kind:fc.kind||""});return true;}catch(_ff){}}return false;}catch(e){return false;}}'
        . 'function ipmiProxyIloCaptureLaunchSnapshotDoc(d){try{var out={path:"",hash:"",title:"",iframeN:0,iframeSrcSig:"",bodyLen:0,aLen:0};if(!d||!d.documentElement)return out;try{out.path=String(location.pathname||"").toLowerCase();out.hash=String(location.hash||"").toLowerCase();}catch(_p){}try{out.title=String(d.title||"").substring(0,120);}catch(_t){}try{out.bodyLen=String((d.body&&d.body.innerText)||"").length;}catch(_b){}try{out.aLen=d.querySelectorAll?d.querySelectorAll("a[href]").length:0;}catch(_a){}try{var F=d.querySelectorAll("iframe,frame"),sig=[],i;for(i=0;i<F.length&&i<36;i++){sig.push(String(F[i].getAttribute("src")||"").substring(0,96));}out.iframeN=F.length;out.iframeSrcSig=sig.join("|");}catch(_f){}return out;}catch(e){return{path:"",hash:"",title:"",iframeN:0,iframeSrcSig:"",bodyLen:0,aLen:0};}}'
        . 'function ipmiProxyIloCapturePreLaunchSnapshot(){try{return ipmiProxyIloCaptureLaunchSnapshotDoc(document);}catch(e){return{path:"",hash:"",title:"",iframeN:0,iframeSrcSig:"",bodyLen:0,aLen:0};}}'
        . 'function ipmiProxyIloCapturePostLaunchSnapshot(){return ipmiProxyIloCapturePreLaunchSnapshot();}'
        . 'function ipmiProxyIloDiffLaunchSnapshots(a,b){try{a=a||{};b=b||{};var ch=[],meaning=false;if(String(a.path||"")!==String(b.path||"")){ch.push("path");meaning=true;}if(String(a.hash||"")!==String(b.hash||"")){ch.push("hash");meaning=true;}if((a.iframeN|0)!==(b.iframeN|0)){ch.push("iframe_count");meaning=true;}if(String(a.iframeSrcSig||"")!==String(b.iframeSrcSig||"")){ch.push("iframe_src");meaning=true;}if(Math.abs((a.bodyLen|0)-(b.bodyLen|0))>80){ch.push("body_text_len");meaning=true;}if((a.aLen|0)!==(b.aLen|0)){ch.push("anchor_count");meaning=true;}return{changed:ch,meaningful:meaning};}catch(e){return{changed:[],meaningful:false};}}'
        . 'function ipmiProxyIloLaunchFunctionContextFingerprint(){try{var s=ipmiProxyIloCapturePreLaunchSnapshot();return String(s.path||"")+"#"+String(s.hash||"")+":"+String(s.iframeN||0)+":"+String(s.iframeSrcSig||"").substring(0,200);}catch(e){return"";}}'
        . 'function ipmiProxyIloRecordLaunchFunctionFound(st,src,ctxIdx){try{if(st)st.launchFunctionFound=true;try{_kvmDbg("ilo_launch_function_found",{src:String(src||""),ctx:ctxIdx});}catch(_x){}}catch(e){}}'
        . 'function ipmiProxyIloLaunchFunctionPreconditions(w,il){try{var o={iLO_present:!!il,startHtml5Irc_type:typeof(il&&il.startHtml5Irc),argLength:-1,hasAppFrame:false,appFrameSrc:""};try{if(il&&il.startHtml5Irc)o.argLength=il.startHtml5Irc.length;}catch(_l){}try{if(w&&w.document&&w.document.getElementById){var af=w.document.getElementById("appFrame");if(af){o.hasAppFrame=true;o.appFrameSrc=String(af.getAttribute("src")||"").substring(0,120);}}}catch(_a){}try{_kvmDbg("ilo_launch_function_context_checked",o);}catch(_c){}var inc=!o.hasAppFrame||!o.appFrameSrc||o.appFrameSrc.toLowerCase().indexOf("application")<0;if(inc&&o.startHtml5Irc_type==="function"){try{_kvmDbg("ilo_launch_function_present_but_context_incomplete",{reason:"appframe_not_application",appFrameSrc:o.appFrameSrc});}catch(_p){}}return o;}catch(e){return{iLO_present:false};}}'
        . 'function ipmiProxyIloCanInvokeLaunchFunction(st){try{if(!st)return true;if(st.shellLaunchProbeExhausted)return false;if((st.launchFnBudgetSpent|0)>=(st.launchFnBudgetMax|0))return false;if(st.shellLaunchNoEffectLocked&&!st.launchFnContextChanged)return false;return true;}catch(e){return true;}}'
        . 'function ipmiProxyIloRecordLaunchFunctionBudgetSpend(st,label){try{if(!st)return;st.launchFnBudgetSpent=(st.launchFnBudgetSpent|0)+1;try{_kvmDbg("ilo_launch_function_budget_spent",{spent:st.launchFnBudgetSpent,max:st.launchFnBudgetMax||2,label:String(label||"")});}catch(_b){}if((st.launchFnBudgetSpent|0)>=(st.launchFnBudgetMax|0)){try{_kvmDbg("ilo_launch_function_budget_exhausted",{spent:st.launchFnBudgetSpent});}catch(_e){}st.shellLaunchProbeExhausted=true;}}catch(e){}}'
        . 'function ipmiProxyIloShouldRetryLaunchFunction(st){try{if(!st)return false;if(!st.shellLaunchNoEffectLocked)return ipmiProxyIloCanInvokeLaunchFunction(st);return !!st.launchFnContextChanged;}catch(e){return false;}}'
        . 'function ipmiProxyIloInvokeILOStartHtml5Once(il,w,gi,st){try{var pre=ipmiProxyIloCapturePreLaunchSnapshot();try{_kvmDbg("ilo_launch_pre_snapshot",pre);}catch(_ps){}try{_kvmDbg("ilo_launch_function_invocation_attempted",{fn:"iLO.startHtml5Irc",ctx:gi});}catch(_ia){}var threw=false,retOk=false;try{if(il&&typeof il.startHtml5Irc==="function"){il.startHtml5Irc.call(il,{mode:"WINDOW"});retOk=true;}}catch(e1){threw=true;try{if(il&&typeof il.startHtml5Irc==="function"){il.startHtml5Irc.call(il);retOk=true;threw=false;}}catch(e2){threw=true;}}try{_kvmDbg("ilo_launch_function_invocation_returned",{ctx:gi,threw:threw?1:0});}catch(_ir){}if(threw){try{_kvmDbg("ilo_launch_function_invocation_failed",{fn:"iLO.startHtml5Irc",ctx:gi});}catch(_if){}return"threw";}var post=ipmiProxyIloCapturePostLaunchSnapshot();try{_kvmDbg("ilo_launch_post_snapshot",post);}catch(_po){}var df=ipmiProxyIloDiffLaunchSnapshots(pre,post);try{_kvmDbg("ilo_launch_snapshot_diff",{changed:df.changed.join(","),meaningful:df.meaningful?1:0});}catch(_sd){}if(df.meaningful){try{_kvmDbg("ilo_launch_function_effective",{fn:"iLO.startHtml5Irc",via:"state_change"});if(df.changed.indexOf("path")>=0)_kvmDbg("ilo_launch_action_changed_url",{});if(df.changed.indexOf("iframe_src")>=0||df.changed.indexOf("iframe_count")>=0)_kvmDbg("ilo_launch_action_changed_frame_state",{});}catch(_ef){}st.launchFunctionEffective=true;return"ilo_startHtml5Irc_effective";}try{_kvmDbg("ilo_launch_function_no_effect",{fn:"iLO.startHtml5Irc",ctx:gi});try{_kvmDbg("ilo_launch_action_no_effect",{phase:"immediate_diff",ctx:gi});}catch(_ne){}}catch(_nf){}st.launchFunctionNoEffectObserved=true;try{st.shellLaunchProvenIneffective=true;}catch(_spi){}return"ilo_startHtml5Irc_no_effect";}catch(e){try{_kvmDbg("ilo_launch_function_invocation_failed",{fn:"iLO.startHtml5Irc",err:String(e)});}catch(_e2){}return"threw";}}'
        . 'function ipmiProxyIloTryNamedFn(w,fn,ctxIdx,label,st){try{if(st&&!ipmiProxyIloCanInvokeLaunchFunction(st))return"";if(!w||typeof w[fn]!=="function")return"";ipmiProxyIloRecordLaunchFunctionFound(st||{},label||fn,ctxIdx);try{_kvmDbg("ilo_launch_function_invocation_attempted",{fn:fn,ctx:ctxIdx});}catch(_ia){}var modes=[function(){w[fn].call(w,{mode:"WINDOW"});},function(){w[fn].call(w);},function(){w[fn]();}];for(var mi=0;mi<modes.length;mi++){try{modes[mi]();try{_kvmDbg("ilo_launch_function_invocation_succeeded",{fn:fn,ctx:ctxIdx});}catch(_is){}if(st)ipmiProxyIloRecordLaunchFunctionBudgetSpend(st,fn);return"fn_"+fn;}catch(_fx){}}try{_kvmDbg("ilo_launch_function_invocation_failed",{fn:fn,ctx:ctxIdx});}catch(_if){}if(st)ipmiProxyIloRecordLaunchFunctionBudgetSpend(st,fn);}catch(_e){}return"";}'
        . 'function tryProbeIloLaunchGlobals(ctxArr,st){try{var nm=["openHtml5Irc","launchHtml5Irc","openIntegratedRemoteConsole","openRemoteConsole","launchRemoteConsole","startIntegratedRemoteConsole","showRemoteConsole","openHtmlConsole","launchHtmlConsole","openIRC","startIRC","openVirtualConsole","launchVirtualConsole"];if(!st||st.shellLaunchProbeExhausted)return"";if(!ipmiProxyIloCanInvokeLaunchFunction(st))return"";for(var gi=0;gi<ctxArr.length;gi++){var w=ctxArr[gi];if(!w)continue;var il=null;try{il=w.iLO;}catch(_il0){il=null;}if(il&&typeof il.startHtml5Irc==="function"){ipmiProxyIloLaunchFunctionPreconditions(w,il);ipmiProxyIloRecordLaunchFunctionFound(st,"iLO.startHtml5Irc",gi);var inv=ipmiProxyIloInvokeILOStartHtml5Once(il,w,gi,st);ipmiProxyIloRecordLaunchFunctionBudgetSpend(st,"iLO.startHtml5Irc");if(inv&&inv.indexOf("effective")>=0)return inv;if(inv==="ilo_startHtml5Irc_no_effect"||inv==="threw")return"";}var r0=ipmiProxyIloTryNamedFn(w,"startHtml5Irc",gi,"global_startHtml5Irc",st);if(r0)return r0;if(il){for(var ni=0;ni<nm.length;ni++){var fn=nm[ni],hit="";try{if(typeof il[fn]==="function"){ipmiProxyIloRecordLaunchFunctionFound(st,"iLO."+fn,gi);try{_kvmDbg("ilo_launch_function_invocation_attempted",{fn:"iLO."+fn,ctx:gi});}catch(_ia2){}try{il[fn].call(il,{mode:"WINDOW"});hit="ilo_"+fn;}catch(_i0){try{il[fn].call(il);hit="ilo_"+fn;}catch(_i1){try{il[fn]();hit="ilo_"+fn;}catch(_i2){}}}}}catch(_i3){}if(hit){ipmiProxyIloRecordLaunchFunctionBudgetSpend(st,fn);return hit;}}}for(var gj=0;gj<nm.length;gj++){var r1=ipmiProxyIloTryNamedFn(w,nm[gj],gi,"global_"+nm[gj],st);if(r1)return r1;}}}catch(gp){}return"";}'
        . 'function tryNavigateLauncherFrameOnce(doc,st){try{if(!doc||!st||st.frameNavDone)return false;var fc=ipmiProxyIloFindNavigableFrame(doc);if(!fc||!fc.el)return false;if(fc.score>=10&&fc.score<14)_kvmDbg("ilo_console_frame_candidate_rejected",{score:fc.score,kind:fc.kind||"",reason:"below_nav_threshold"});var el=fc.el,src=String(el.getAttribute("src")||"").toLowerCase(),fid=String(el.getAttribute("id")||"").toLowerCase(),fnm=String(el.getAttribute("name")||"").toLowerCase();if(src.indexOf("rc_info")>=0||src.indexOf("application")>=0)return false;var shellMain=(fc.kind==="shell_frame")&&(fid==="framecontent"||fnm==="framecontent"||src.indexOf("content.html")>=0||src===""||src==="about:blank");var consoleEmpty=(fc.kind==="console_frame_candidate")&&(src===""||src==="about:blank"||src.indexOf("content.html")>=0);if(shellMain&&fc.score>=14){st.frameNavDone=true;_kvmDbg("ilo_console_frame_candidate_followed",{action:"set_src_rc_info",score:fc.score,kind:fc.kind,reason:"shell_main_frame"});try{el.setAttribute("src","html/rc_info.html");return true;}catch(sn0){}}if(fc.kind==="shell_frame")return false;if(fc.score<32)return false;if(consoleEmpty){st.frameNavDone=true;_kvmDbg("ilo_console_frame_candidate_followed",{action:"set_src_rc_info",score:fc.score,kind:fc.kind,reason:"launcher_empty"});try{el.setAttribute("src","html/rc_info.html");return true;}catch(sn1){}}}catch(nf){}return false;}'
        . 'function ipmiProxyIloInspectSameOriginFrameForLaunch(fw){try{if(!fw||!fw.document)return null;var ifs=fw.document.querySelectorAll("iframe,frame");for(var ii=0;ii<ifs.length&&ii<28;ii++){try{var w=ifs[ii].contentWindow;if(!w||!w.document)continue;var el=findIloDeepLaunch({document:w.document})||findIloHeuristicLaunch({document:w.document})||findIloBestConsoleHrefClickable(w.document);if(el){_kvmDbg("ilo_frame_subdocument_launch_control",{iframe_index:ii});return el;}}catch(e2){}}}catch(e){}return null;}'
        . 'function ipmiProxyIloHrefConsoleScore(href){try{var h=String(href||"").toLowerCase();if(!h||h.indexOf("javascript:")===0||h.indexOf("#")===0)return-100;if(h.indexOf("logout")>=0||h.indexOf("log_out")>=0)return-80;var s=0;if(h.indexOf("rc_info")>=0)s+=70;if(h.indexOf("irc")>=0&&h.indexOf(".html")>=0)s+=55;if(h.indexOf("application.html")>=0)s+=50;if(h.indexOf("remote")>=0&&h.indexOf("console")>=0)s+=48;if(h.indexOf("html5")>=0)s+=40;if(h.indexOf("kvm")>=0)s+=35;if(h.indexOf("jnlp")>=0)s+=28;if(h.indexOf("java")>=0&&h.indexOf("irc")>=0)s+=22;if(h.indexOf("console")>=0)s+=18;if(h.indexOf("virtual")>=0&&h.indexOf("console")>=0)s+=20;return s;}catch(e){return 0;}}'
        . 'function findIloBestConsoleHrefClickable(doc){try{if(!doc||!doc.querySelectorAll)return null;var A=doc.querySelectorAll("a[href]"),best=null,bs=-999;for(var ai=0;ai<A.length&&ai<420;ai++){var a=A[ai],href=a.getAttribute("href")||"",sc=ipmiProxyIloHrefConsoleScore(href),tx=String(a.textContent||a.innerText||"");if(iloConsoleKeyword(tx))sc+=25;if(sc>bs){bs=sc;best=a;}}if(best&&bs>=12)return best;}catch(e){}return null;}'
        . 'function findIloDeepLaunchRecursive(ctx,depth){try{if(!ctx||!ctx.document||depth>4)return null;var d0=findIloDeepLaunch(ctx)||findIloHeuristicLaunch(ctx)||findIloBestConsoleHrefClickable(ctx.document);if(d0)return d0;var ifs=ctx.document.querySelectorAll("iframe,frame");for(var fi=0;fi<ifs.length&&fi<18;fi++){try{var w=ifs[fi].contentWindow;if(!w)continue;var hit=findIloDeepLaunchRecursive(w,depth+1);if(hit)return hit;}catch(fr){}}}catch(e2){}return null;}'
        . 'function tryFollowBoundedConsoleHref(ctxArr,st){try{if(!st)return false;var pl=pathLower();var onShell=(pl.indexOf("/index.html")>=0||pl.indexOf("/restgui/")>=0||pl==="/"||pl==="");if(!onShell&&!ipmiProxyIloPathIsManagementShellish())return false;var best=null,bDoc=null,bSc=-999;for(var ci=0;ci<ctxArr.length;ci++){var c=ctxArr[ci];if(!c||!c.document)continue;var a=findIloBestConsoleHrefClickable(c.document);if(!a)continue;var href=String(a.getAttribute("href")||""),sc=ipmiProxyIloHrefConsoleScore(href)+10;if(sc>bSc){bSc=sc;best=a;bDoc=c.document;}}if(!best||bSc<14)return false;_kvmDbg("ilo_launch_discovery_escalation_attempted",{kind:"bounded_console_href",score:bSc});_kvmDbg("ilo_launch_navigation_triggered",{target:String(best.getAttribute("href")||"").substring(0,120)});try{if(typeof best.click==="function"){best.click();return true;}}catch(_c0){}try{if(bDoc&&bDoc.createEvent){var ev=bDoc.createEvent("MouseEvents");ev.initEvent("click",true,true);best.dispatchEvent(ev);return true;}}catch(_c1){}}catch(_bf){}return false;}'
        . 'function tryShellDiscoveryEscalationOnce(ctxArr,st){try{if(!st||st.shellEscalationConsumed)return"";if(kvmIloWsTransportEvidence())return"";st.shellEscalationConsumed=true;try{_kvmDbg("ilo_launch_discovery_escalation_allowed",{reason:"shell_index_no_transport"});}catch(_ea){}if(tryFollowBoundedConsoleHref(ctxArr,st)){st.discNavTriggered=true;st.anyLaunchAction=true;st.discoveryEscalationKind="console_href";try{st.appNavPendingSince=kvmNow();}catch(_an0){}try{_kvmDbg("ilo_launch_discovery_escalation_attempted",{kind:"console_href_ok"});}catch(_ok){}return"href";}try{if(st&&st.shellLaunchProvenIneffective){try{_kvmDbg("ilo_shell_launch_proven_ineffective",{note:"authoritative_spa_escalation"});}catch(_s1){}}try{_kvmDbg("ilo_application_path_promotion_allowed",{target:"html/application.html"});}catch(_ap0){}try{if(st){st.applicationPathPromotionActive=true;st.shellPathAbandoned=true;}try{_kvmDbg("ilo_shell_path_abandoned_for_application",{});}catch(_sp){}}catch(_ap1){}try{_kvmDbg("ilo_launch_discovery_escalation_attempted",{kind:"spa_bootstrap_fallback",target:"html/application.html"});}catch(_e0){}try{if(st){st.appNavPendingSince=kvmNow();st.appNavCommitted=false;}}catch(_an1){}try{_kvmDbg("ilo_application_path_promotion_triggered",{});}catch(_pt){}go("/html/application.html?ipmi_kvm_auto=1");st.discNavTriggered=true;st.anyLaunchAction=true;st.discoveryEscalationKind="spa_bootstrap";try{_kvmDbg("ilo_application_navigation_triggered",{target:"html/application.html"});}catch(_nt){}markAppRedirected();return"spa";}catch(_ge){try{_kvmDbg("ilo_launch_discovery_escalation_failed",{err:String(_ge)});}catch(_ef){}}return"";}catch(_se){return"";}}'
        . 'function findIloDeepLaunch(ctx){try{var d=ctx.document;if(!d||!d.querySelectorAll)return null;var L=d.querySelectorAll("a[href],button,[role=button],[role=menuitem],input[type=button],input[type=submit],label,.btn,.hpJump,.menuItem,.nav-item,a[class*=nav],a[class*=menu],[data-action],[data-url],[data-href],[data-target],.tree_view a,.gwt-Anchor,td[onclick],div[onclick],span[onclick],li[onclick]");for(var i=0;i<L.length&&i<520;i++){var e=L[i],t=String(e.textContent||e.innerText||""),h=String(e.getAttribute("href")||"").toLowerCase(),oc=String(e.getAttribute("onclick")||"").toLowerCase(),da=String(e.getAttribute("data-action")||"").toLowerCase(),du=String(e.getAttribute("data-url")||"").toLowerCase(),dh=String(e.getAttribute("data-href")||"").toLowerCase(),dt=String(e.getAttribute("data-target")||"").toLowerCase(),ti=String(e.getAttribute("title")||"").toLowerCase(),ar=String(e.getAttribute("aria-label")||"").toLowerCase();if(iloConsoleKeyword(t)||iloConsoleKeyword(h)||iloConsoleKeyword(oc)||iloConsoleKeyword(da)||iloConsoleKeyword(du)||iloConsoleKeyword(dh)||iloConsoleKeyword(dt)||iloConsoleKeyword(ti)||iloConsoleKeyword(ar)||h.indexOf("rc_info")>=0||h.indexOf("application.html")>=0||h.indexOf("irc")>=0||h.indexOf("jnlp")>=0||h.indexOf("html5")>=0||h.indexOf("remote-console")>=0||h.indexOf("remote_console")>=0||h.indexOf("kvm")>=0&&h.indexOf("console")>=0)return e;}}catch(e2){}return null;}'
        . 'function findIloHeuristicLaunch(ctx){try{var d=ctx.document;if(!d||!d.querySelectorAll)return null;var L=d.querySelectorAll("a[href],button,[role=button],input[type=button],input[type=submit],label,.btn");for(var i=0;i<L.length&&i<140;i++){var e=L[i],t=String(e.textContent||""),h=String(e.getAttribute("href")||"").toLowerCase(),oc=String(e.getAttribute("onclick")||"").toLowerCase(),dt=String(e.getAttribute("data-localize")||"").toLowerCase();if(iloKvText(t)||iloKvText(h)||iloConsoleKeyword(t)||iloConsoleKeyword(h)||iloKvText(oc)||iloKvText(dt)||h.indexOf("irc")>=0||h.indexOf("html5")>=0||h.indexOf("remote")>=0&&h.indexOf("console")>=0){return e;}}}catch(e2){}return null;}'
        . 'function wireIloAppFrame(ctx){try{'
        . 'if(!ctx)return;'
        . 'var host=bindIloTopPage(ctx)||ctx;'
        . 'if(host&&host.iLOGlobal&&host.iLOGlobal.topPage){host.iLOGlobal.topPage.appFrame=host;}'
        . '}catch(e){}}'
        . 'function ensureIloRcPageLoaded(ctx){try{'
        . 'var host=getIloShellHost(ctx);'
        . 'if(!host||ctx!==host)return false;'
        . 'var fc=getIloFrameContent(host);'
        . 'if(!fc||typeof fc.loadContent!=="function")return false;'
        . 'if(hasIloRcPage(host))return false;'
        . 'var pendingTs=0;'
        . 'try{pendingTs=Number(host.__ipmi_rc_info_loading_ts||0);}catch(_e2pre){pendingTs=0;}'
        . 'if(pendingTs>0&&(Date.now()-pendingTs)<15000){return false;}'
        . 'var iframeEl=getIloIframeContentEl(host);'
        . 'if(iframeEl&&!iframeEl.__ipmi_rc_load_bound){try{iframeEl.addEventListener("load",function(){try{host.__ipmi_rc_info_loading_ts=0;}catch(_eL){}},true);iframeEl.__ipmi_rc_load_bound=true;}catch(_eLb){}}'
        . 'var iframeSrc="";'
        . 'try{iframeSrc=String((iframeEl&&iframeEl.getAttribute&&iframeEl.getAttribute("src"))||"").toLowerCase();}catch(_e2a){}'
        . 'if(iframeSrc.indexOf("rc_info.html")!==-1){'
        . 'try{'
        . 'if(pendingTs<=0){host.__ipmi_rc_info_loading_ts=Date.now();return false;}'
        . 'if((Date.now()-pendingTs)<15000){return false;}'
        . '}catch(_e2b){return false;}'
        . '}'
        . 'try{if(host.iLOGlobal){host.iLOGlobal.initialLink="rc_info.html";host.iLOGlobal.content="rc_info.html";host.iLOGlobal.initialTab=0;}}catch(_e3){}'
        . 'try{if(fc.iLOGlobal){fc.iLOGlobal.initialLink="rc_info.html";fc.iLOGlobal.initialTab=0;}}catch(_e3b){}'
        . 'try{_kvmDbg("ilo_rc_info_navigation","loadContent");host.__ipmi_rc_info_loading_ts=Date.now();fc.loadContent("rc_info.html");return true;}catch(_e4){}'
        . 'return false;'
        . '}catch(e){return false;}}'
        . 'function ensureIloGlobalStartPatched(ctx){try{'
        . 'if(!ctx||typeof ctx.startHtml5Irc!=="function"||ctx.__ipmi_global_start_patched||!isWrapperStartFn(ctx.startHtml5Irc)){return;}'
        . 'var orig=ctx.startHtml5Irc;'
        . 'ctx.startHtml5Irc=function(){'
        . 'var started=false,cc=collectContexts();'
        . 'for(var i=0;i<cc.length;i++){if(callStart(cc[i])||callIloStart(cc[i])){started=true;break;}}'
        . 'if(started){return false;}'
        . 'try{return orig.apply(this,arguments);}catch(e){return false;}'
        . '};'
        . 'ctx.__ipmi_global_start_patched=true;'
        . '}catch(e){}}'
        . 'function ensureIloRcButtonPatched(ctx){try{'
        . 'var btn=findIloHtml5Button(ctx);'
        . 'if(!btn||btn.__ipmi_kvm_bound)return;'
        . 'btn.__ipmi_kvm_bound=true;'
        . 'try{btn.setAttribute("data-ipmi-kvm-ready","1");}catch(_e0){}'
        . '}catch(e){}}'
        . 'function callIloStart(ctx){'
        . 'if(!ctx)return false;'
        . 'var host=bindIloTopPage(ctx)||findIloRendererHost(ctx)||ctx;'
        . 'ensureIloStartPatched(ctx);'
        . 'if(host&&host!==ctx){ensureIloStartPatched(host);}'
        . 'clearIloStaleRenderer(host);clearIloStaleRenderer(ctx);'
        . 'wireIloAppFrame(host||ctx);'
        . 'var fired=false;'
        . 'try{if(host&&host.iLO&&typeof host.iLO.startHtml5Irc==="function"){host.iLO.startHtml5Irc();fired=true;}}catch(e0){}'
        . 'try{if(!fired&&ctx.iLO&&typeof ctx.iLO.startHtml5Irc==="function"){ctx.iLO.startHtml5Irc();fired=true;}}catch(e1){}'
        . 'if(!fired)return false;'
        . 'return consoleVisible(host)||consoleVisible(ctx);}'
        . 'function callStart(ctx){'
        . 'if(!ctx)return false;'
        . 'var directTop=getIloDirectTopRenderer(ctx);'
        . 'if(directTop){ensureIloFrameResizeShim(directTop);clearIloStaleRenderer(directTop);try{directTop.startHtml5Irc({mode:"WINDOW"});}catch(_dt1){}try{if(!consoleVisible(directTop)){directTop.startHtml5Irc();}}catch(_dt2){}if(consoleVisible(directTop))return true;}'
        . 'var host=findIloRendererHost(ctx)||bindIloTopPage(ctx)||ctx;'
        . 'ensureIloFrameResizeShim(host);clearIloStaleRenderer(host);clearIloStaleRenderer(ctx);'
        . 'if(host&&isRendererStartFn(host.startHtml5Irc)){'
        . 'try{host.startHtml5Irc({mode:"WINDOW"});}catch(e1){}'
        . 'try{if(!consoleVisible(host)&&!consoleVisible(ctx)){host.startHtml5Irc();}}catch(e2){}'
        . 'if(consoleVisible(host)||consoleVisible(ctx))return true;'
        . '}'
        . 'return false;}'
        . 'function clickHtml5Anchor(ctx,skipButton){try{'
        . 'if(!ctx||!ctx.document||!ctx.document.querySelector)return false;'
        . 'var btn=findIloHtml5Button(ctx);'
        . 'if(!skipButton&&btn){if(typeof btn.click==="function"){btn.click();return true;}'
        . 'if(ctx.document.createEvent){var bev=ctx.document.createEvent("MouseEvents");bev.initEvent("click",true,true);btn.dispatchEvent(bev);return true;}}'
        . 'var a=ctx.document.querySelector("#html5_irc_label a");'
        . 'if(!a){var heur=findIloHeuristicLaunch(ctx);if(heur){_kvmDbg("ilo_click_candidate_found","heuristic");if(typeof heur.click==="function"){heur.click();return true;}if(ctx.document.createEvent){var evh=ctx.document.createEvent("MouseEvents");evh.initEvent("click",true,true);heur.dispatchEvent(evh);return true;}}return false;}'
        . 'if(typeof a.click==="function"){a.click();return true;}'
        . 'if(ctx.document.createEvent){var ev=ctx.document.createEvent("MouseEvents");ev.initEvent("click",true,true);a.dispatchEvent(ev);return true;}'
        . '}catch(e){}return false;}'
        . 'function tryExpandIloHiddenMenus(doc,tag){try{if(!doc||!doc.querySelectorAll)return false;var M=doc.querySelectorAll(".menu-toggle,.nav-toggle,.gwt-MenuBar,.hp-menu-button,.hp-menu,.nav-item button,[class*=expand]");for(var i=0;i<M.length&&i<16;i++){var e=M[i];try{if(e&&e.offsetParent!==null){if(typeof e.click==="function"){e.click();return true;}}}catch(_me){}}}catch(e){}return false;}'
        . 'function tryClickIloDiscoveryLaunch(ctxArr,tag,st){try{var gp="";if(!st||!st.shellLaunchProbeExhausted){gp=tryProbeIloLaunchGlobals(ctxArr,st);}else{try{_kvmDbg("ilo_launch_function_retry_denied",{reason:"budget_exhausted"});}catch(_rd0){}}if(gp)return gp;for(var qi=0;qi<ctxArr.length;qi++){var c=ctxArr[qi];if(!c||!c.document)continue;if(st&&tryNavigateLauncherFrameOnce(c.document,st))return"frame_nav_rc_info";var dl=findIloDeepLaunch(c)||findIloDeepLaunchRecursive(c,0);if(!dl){var ah=findIloBestConsoleHrefClickable(c.document);if(ah){_kvmDbg("ilo_launch_control_found",{src:"console_href",tag:tag||""});dl=ah;}}if(dl){_kvmDbg("ilo_launch_control_found",{src:"deep_scan",tag:tag||""});if(typeof dl.click==="function"){dl.click();return"deep";}if(c.document.createEvent){var ev=c.document.createEvent("MouseEvents");ev.initEvent("click",true,true);dl.dispatchEvent(ev);return"deep";}}var ins=ipmiProxyIloInspectSameOriginFrameForLaunch(c);if(ins){_kvmDbg("ilo_frame_contains_launch_surface",{tag:tag||""});if(typeof ins.click==="function"){ins.click();return"frame_inspect";}if(c.document&&c.document.createEvent){var ev2=c.document.createEvent("MouseEvents");ev2.initEvent("click",true,true);ins.dispatchEvent(ev2);return"frame_inspect";}}var fc=ipmiProxyIloFindConsoleFrameCandidate(c.document);if(fc&&fc.el){_kvmDbg("ilo_launch_frame_candidate_found",{score:fc.score,kind:fc.kind||"",tag:tag||""});if(fc.score>=24){_kvmDbg("ilo_console_frame_candidate_detected",{score:fc.score,kind:fc.kind||"",tag:tag||""});try{if(fc.el.focus)fc.el.focus();}catch(_fe){}}else if(fc.score>=10){_kvmDbg("ilo_console_frame_candidate_rejected",{score:fc.score,kind:fc.kind||"",reason:"below_action_threshold"});}}}}catch(_q){}return"";}'
        . 'function collectContexts(){'
        . 'var out=[];'
        . 'function add(c){if(!c)return;for(var i=0;i<out.length;i++){if(out[i]===c)return;}out.push(c);}'
        . 'try{add(window);}catch(e0){}'
        . 'try{if(window.parent&&window.parent!==window)add(window.parent);}catch(e1){}'
        . 'try{if(window.parent&&window.parent.parent&&window.parent.parent!==window.parent)add(window.parent.parent);}catch(e1b){}'
        . 'try{if(window.top&&window.top!==window)add(window.top);}catch(e2){}'
        . 'try{if(window.top&&window.top.frames&&window.top.frames.appFrame)add(window.top.frames.appFrame);}catch(e2b){}'
        . 'try{if(window.frames&&window.frames.frameContent)add(window.frames.frameContent);}catch(e3){}'
        . 'try{if(window.frames&&window.frames.frameContent&&window.frames.frameContent.frames&&window.frames.frameContent.frames.iframeContent){add(window.frames.frameContent.frames.iframeContent);}}catch(e4){}'
        . 'try{if(window.parent&&window.parent.frames&&window.parent.frames.frameContent)add(window.parent.frames.frameContent);}catch(e5){}'
        . 'try{if(window.parent&&window.parent.frames&&window.parent.frames.frameContent&&window.parent.frames.frameContent.frames&&window.parent.frames.frameContent.frames.iframeContent){add(window.parent.frames.frameContent.frames.iframeContent);}}catch(e6){}'
        . 'try{if(window.frames){for(var fi=0;fi<window.frames.length&&fi<36;fi++){try{add(window.frames[fi]);}catch(fx){}}}}catch(f0){}'
        . 'try{if(window.top&&window.top.frames){for(var fi2=0;fi2<window.top.frames.length&&fi2<36;fi2++){try{add(window.top.frames[fi2]);}catch(fx2){}}}}catch(f1){}'
        . 'return out;}';
}

function ipmiProxyBuildKvmAutoLaunchLaunchGateJs(): string
{
    return 'if(launchDone&&!queryAuto){'
        . 'if(FAMILY==="ilo"){'
        . 'var c0=collectContexts(),ok0=false;'
        . 'for(var z=0;z<c0.length;z++){if(consoleVisible(c0[z])){ok0=true;break;}}'
        . 'if(!ok0){try{if(window.sessionStorage){sessionStorage.removeItem("_ipmi_kvm_autolaunch_done");}}catch(_e2b){} launchDone=false;}'
        . 'if(launchDone){return;}'
        . '}else{'
        . 'try{if(window.sessionStorage){sessionStorage.removeItem("_ipmi_kvm_autolaunch_done");}}catch(_e2c){}'
        . 'launchDone=false;'
        . '}'
        . '}';
}

/**
 * Shared runtime signals: WebSocket relay usage, canvas-like nodes, stall bookkeeping (vendor ticks use this).
 */
function ipmiProxyBuildKvmRuntimeProgressHelpersJs(): string
{
    return ''
        . 'var KVM_TMO=45000;try{KVM_TMO=parseInt(String((PLAN&&PLAN.console_ready_timeout_ms)||45000),10)||45000;}catch(_kt){KVM_TMO=45000;}'
        . 'function kvmNow(){try{return Date.now();}catch(e){return 0;}}'
        . 'function kvmTouchProgress(st){try{st.lastProgress=kvmNow();}catch(e){}}'
        . 'function kvmWsRelaySeen(){try{var e=performance.getEntriesByType("resource"),i;for(i=0;i<e.length;i++){var n=String(e[i].name||"");if(n.indexOf("ipmi_ws_relay.php")>=0)return true;}}catch(e0){}'
        . 'try{if(window.__ipmi_kvm_ws_relay_ts&&(kvmNow()-window.__ipmi_kvm_ws_relay_ts)<180000)return true;}catch(e1){}return false;}'
        . 'function kvmVisibleCanvasLike(doc){try{'
        . 'if(!doc||!doc.querySelectorAll)return false;'
        . 'var C=doc.querySelectorAll("canvas");for(var i=0;i<C.length&&i<24;i++){var c=C[i];if(c&&c.width>80&&c.height>60)return true;}'
        . 'var V=doc.querySelectorAll("video");if(V&&V.length)return true;'
        . '}catch(e){}return false;}'
        . 'function kvmAnyFrameCanvas(ctx){try{'
        . 'var L=collectContexts();for(var i=0;i<L.length;i++){try{var d=L[i].document;if(d&&kvmVisibleCanvasLike(d))return true;}catch(e2){}}'
        . '}catch(e3){}return false;}'
        . 'function kvmIloRendererDetected(ctx){try{return !!(consoleVisible(ctx)||(ctx&&ctx.renderer&&ctx.renderer.connected));}catch(e){return false;}}'
        . 'function kvmIloWsTransportEvidence(){return kvmWsRelaySeen();}'
        . 'function kvmIloTransportDetected(){return kvmIloWsTransportEvidence();}'
        . 'function kvmIloRendererOrContainerPresent(ctx){try{'
        . 'if(kvmIloRendererDetected(ctx))return true;'
        . 'var L=collectContexts();for(var i=0;i<L.length;i++){try{'
        . 'if(rcWindowVisible(L[i]))return true;'
        . 'if(L[i].document&&L[i].document.getElementById&&L[i].document.getElementById("ircWindow"))return true;'
        . '}catch(e0){}}'
        . '}catch(e){}return false;}'
        . 'function kvmIloLoadingPleaseWaitAny(){try{'
        . 'var L=collectContexts();'
        . 'for(var i=0;i<L.length;i++){try{'
        . 'var d=L[i].document;if(!d||!d.body)continue;'
        . 'var t=String((d.body.innerText||d.body.textContent||"")).toLowerCase();'
        . 'if(t.indexOf("please wait")>=0&&t.indexOf("loading")>=0)return true;'
        . 'if(t.indexOf("loading, please wait")>=0)return true;'
        . 'if(t.indexOf("loading")>=0&&t.indexOf("wait")>=0&&t.length<4200)return true;'
        . '}catch(e1){}}'
        . '}catch(e){}return false;}'
        . 'function kvmIloRcWindowAny(){try{var L=collectContexts();for(var i=0;i<L.length;i++){try{if(rcWindowVisible(L[i]))return true;}catch(e2){}}}catch(e){}return false;}'
        . 'function ipmiProxyIloPathIsManagementShellish(){try{var pl=pathLower();if(pl.indexOf("/html/application.html")>=0)return false;if(pl.indexOf("/html/rc_info")>=0||pl.indexOf("/html/irc")>=0)return false;if(pl.indexOf("/index.html")>=0||pl==="/"||pl===""||pl.indexOf("/restgui/")>=0)return true;}catch(e){}return false;}'
        . 'function ipmiProxyIloConsoleRouteReached(){try{var pl=pathLower();return pl.indexOf("/html/application.html")>=0||pl.indexOf("/html/rc_info")>=0||pl.indexOf("/html/irc")>=0;}catch(e){return false;}}'
        . 'function ipmiProxyIloApplicationPathLoaded(){try{return pathLower().indexOf("/html/application.html")>=0;}catch(e){return false;}}'
        . 'function ipmiProxyIloCanvasLooksActive(doc){try{'
        . 'if(!doc||!doc.querySelectorAll)return false;'
        . 'var C=doc.querySelectorAll("canvas");for(var i=0;i<C.length&&i<32;i++){var c=C[i];if(!c||c.width<80||c.height<60)continue;try{var st=window.getComputedStyle?window.getComputedStyle(c):null;if(st&&st.display==="none")continue;var r=c.getBoundingClientRect();if(r.width>=48&&r.height>=36)return true;}catch(_ce){}}'
        . 'var V=doc.querySelectorAll("video");for(var j=0;j<V.length&&j<8;j++){var v=V[j];if(!v)continue;try{var r2=v.getBoundingClientRect();if(r2.width>=64&&r2.height>=48)return true;}catch(_ve){}}'
        . '}catch(e){}return false;}'
        . 'function ipmiProxyIloConsoleContentFrameVisible(doc){try{if(!doc||!doc.querySelectorAll)return false;var F=doc.querySelectorAll("iframe,frame");for(var fi=0;fi<F.length&&fi<40;fi++){var el=F[fi],src=String(el.getAttribute("src")||"").toLowerCase();if(src.indexOf("jnlp")>=0)continue;if(src.indexOf("irc")>=0||src.indexOf("rc_info")>=0){var r=el.getBoundingClientRect();if(r.width>48&&r.height>48)return true;}}}catch(e){}return false;}'
        . 'function ipmiProxyIloHasLiveDisplayEvidence(ctx){try{'
        . 'var L=collectContexts();for(var x=0;x<L.length;x++){try{var d=L[x].document;if(d&&(ipmiProxyIloCanvasLooksActive(d)||ipmiProxyIloConsoleContentFrameVisible(d)))return true;}catch(e1){}}'
        . 'for(var y=0;y<L.length;y++){try{if(rcWindowVisible(L[y]))return true;}catch(e2){}}'
        . '}catch(e){}'
        . 'try{if(ipmiProxyIloCanvasLooksActive(document)||ipmiProxyIloConsoleContentFrameVisible(document))return true;}catch(e3){}'
        . 'return false;}'
        . 'function ipmiProxyIloLooksLikeLiveConsoleSurface(ctx){return ipmiProxyIloHasLiveDisplayEvidence(ctx);}'
        . 'function ipmiProxyIloConsoleViewportLooksReal(ctx){return ipmiProxyIloHasLiveDisplayEvidence(ctx);}'
        . 'function ipmiProxyIloHasVisibleLiveConsole(ctx){return ipmiProxyIloHasLiveDisplayEvidence(ctx);}'
        . 'function ipmiProxyIloLoadingOnlyStatePresent(){return kvmIloLoadingPleaseWaitAny();}'
        . 'function ipmiProxyIloLooksLikeOverviewShell(doc){try{'
        . 'if(!doc||!doc.body)return false;'
        . 'var t=String(doc.title||"").toLowerCase();'
        . 'if((t.indexOf("overview")>=0&&(t.indexOf("ilo")>=0||t.indexOf("hpe")>=0))||(t.indexOf("ilo")>=0&&t.indexOf("overview")>=0))return true;'
        . 'var b=String(doc.body.innerText||doc.body.textContent||"").toLowerCase();'
        . 'if(b.indexOf("ilo overview")>=0)return true;'
        . 'if(b.indexOf("remote console")>=0&&b.indexOf("integrated")>=0&&ipmiProxyIloCanvasLooksActive(doc))return false;'
        . 'if(b.indexOf("system information")>=0&&b.indexOf("firmware")>=0&&b.indexOf("serial number")>=0&&!ipmiProxyIloCanvasLooksActive(doc))return true;'
        . 'var nav=doc.querySelectorAll("[class*=nav],[class*=menu],.tree_view,#tabber");'
        . 'if(nav.length>=2&&b.indexOf("overview")>=0&&!ipmiProxyIloCanvasLooksActive(doc)&&!doc.getElementById("ircWindow"))return true;'
        . 'return false;}catch(e){return false;}}'
        . 'function ipmiProxyIloApplicationLoadedButConsoleNotReached(ctx){try{if(!ipmiProxyIloApplicationPathLoaded())return false;if(ipmiProxyIloHasLiveDisplayEvidence(ctx)||kvmIloRcWindowAny())return false;return true;}catch(e){return false;}}'
        . 'function ipmiProxyIloApplicationLoadedShellOnly(ctx){try{if(!ipmiProxyIloApplicationPathLoaded())return false;if(ipmiProxyIloHasLiveDisplayEvidence(ctx)||kvmIloRcWindowAny())return false;var doc=(ctx&&ctx.document)?ctx.document:document;if(!doc||!doc.body)return true;if(ipmiProxyIloLooksLikeOverviewShell(doc))return true;var b=String(doc.body.innerText||doc.body.textContent||"").toLowerCase();if(b.indexOf("ilo overview")>=0)return true;if(!ipmiProxyIloCanvasLooksActive(doc)&&!doc.getElementById("ircWindow")){if(b.indexOf("overview")>=0&&(b.indexOf("firmware")>=0||b.indexOf("serial")>=0||b.indexOf("health")>=0))return true;var T=doc.querySelectorAll("table");if(T&&T.length>=4&&(b.indexOf("power")>=0||b.indexOf("temperature")>=0))return true;}return false;}catch(e){return false;}}'
        . 'function ipmiProxyIloHelperActivitySupportsButDoesNotConfirm(ctx){try{return ipmiProxyIloHelperActivityPresent()&&!ipmiProxyIloHasLiveDisplayEvidence(ctx)&&!kvmIloRcWindowAny()&&(ipmiProxyIloApplicationLoadedShellOnly(ctx)||ipmiProxyIloLooksLikeOverviewShell((ctx&&ctx.document)?ctx.document:document));}catch(e){return false;}}'
        . 'function ipmiProxyIloShellVsConsoleStateStore(o){try{window.__ipmi_ilo_shell_vs_console=o||{};}catch(e){}}'
        . 'function ipmiProxyIloShellVsConsoleStateLoad(){try{return window.__ipmi_ilo_shell_vs_console||null;}catch(e){return null;}}'
        . 'function ipmiProxyIloShellVsConsoleVerdict(){try{var o=ipmiProxyIloShellVsConsoleStateLoad();return o&&o.final_verdict?String(o.final_verdict):"";}catch(e){return"";}}'
        . 'function ipmiProxyIloManagementShellStillVisible(ctx){try{'
        . 'if(ipmiProxyIloHasLiveDisplayEvidence(ctx))return false;'
        . 'if(kvmIloRcWindowAny())return false;'
        . 'if(kvmIloLoadingPleaseWaitAny())return false;'
        . 'if(typeof hasIloRendererHost==="function"&&ctx&&hasIloRendererHost(ctx))return false;'
        . 'var doc=null;try{doc=(ctx&&ctx.document)?ctx.document:document;}catch(_d0){doc=document;}'
        . 'if(!doc)return false;'
        . 'if(ipmiProxyIloLooksLikeOverviewShell(doc))return true;'
        . 'if(ipmiProxyIloApplicationLoadedShellOnly(ctx))return true;'
        . 'if(ipmiProxyIloPathIsManagementShellish()&&!ipmiProxyIloConsoleRouteReached())return true;'
        . 'return false;}catch(e){return false;}}'
        . 'function ipmiProxyIloLiveConsoleNotYetReached(ctx){try{return !ipmiProxyIloHasLiveDisplayEvidence(ctx)&&!kvmIloRcWindowAny();}catch(e){return true;}}'
        . 'function ipmiProxyIloHelperActivityPresent(){try{var e=performance.getEntriesByType("resource"),i,u;for(i=0;i<e.length;i++){u=String(e[i].name||"").toLowerCase();if(u.indexOf("jnlp_template")>=0||u.indexOf("jnlp")>=0&&u.indexOf(".html")>=0)return true;if(u.indexOf("/html/irc")>=0||u.indexOf("irc.html")>=0)return true;if(u.indexOf("rc_info")>=0)return true;}}catch(e0){}return false;}'
        . 'function ipmiProxyIloHelperActivityCorrelatesWithConsoleReach(ctx){try{return ipmiProxyIloHelperActivityPresent()&&ipmiProxyIloHasLiveDisplayEvidence(ctx)&&!ipmiProxyIloApplicationLoadedShellOnly(ctx);}catch(e){return false;}}'
        . 'function ipmiProxyIloHelperActivityWithoutConsoleTransition(ctx){return ipmiProxyIloHelperActivityPresent()&&ipmiProxyIloManagementShellStillVisible(ctx);}'
        . 'function ipmiProxyIloHelperSupportsVisibleTransition(ctx){try{return ipmiProxyIloHelperActivityCorrelatesWithConsoleReach(ctx);}catch(e){return false;}}'
        . 'function ipmiProxyIloHelperSeenWithoutVisibleProgress(ctx){try{return ipmiProxyIloHelperActivityPresent()&&!ipmiProxyIloHasLiveDisplayEvidence(ctx)&&!kvmIloRcWindowAny();}catch(e){return false;}}'
        . 'function ipmiProxyIloDomSnapshotSig(w){try{var d=(w&&w.document)?w.document:document;if(!d||!d.body)return"e";var t=String(d.body.innerText||d.body.textContent||"").replace(/\\s+/g," ").trim();var la=0,lif=0;try{la=d.querySelectorAll("a[href]").length;}catch(_a){}try{lif=d.querySelectorAll("iframe,frame").length;}catch(_f){}return String(t.length)+":"+String(la)+":"+String(lif);}catch(e){return"e";}}'
        . 'function ipmiProxyIloLooksLikeShellOnlyUi(ctx){return ipmiProxyIloManagementShellStillVisible(ctx);}'
        . 'function ipmiProxyIloLooksLikeWhiteScreenStall(tick,st){try{var d=document;if(!d||!d.body)return false;var t=String(d.body.innerText||d.body.textContent||"").replace(/\\s+/g," ").trim();var L=t.length;var ch=d.body.children?d.body.children.length:0;var ifc=0;try{var F=d.querySelectorAll("iframe,frame");if(F)ifc=F.length;}catch(_e){}var bg="";try{bg=String(d.body.style&&d.body.style.backgroundColor||"").toLowerCase();}catch(_b){}if(L<32&&ch<=3&&ifc<=1)return true;if(L<95&&ifc<=1&&ch<=2&&!ipmiProxyIloHasLiveDisplayEvidence(window)&&tick>16)return true;if(st&&st.discNavTriggered&&(L<40||bg==="rgb(255, 255, 255)"||bg==="#ffffff")&&tick>20&&!ipmiProxyIloHasLiveDisplayEvidence(window))return true;return false;}catch(e){return false;}}'
        . 'function ipmiProxyIloLaunchDiscoveryStateStore(o){try{window.__ipmi_ilo_launch_discovery=o||{};}catch(e){}}'
        . 'function ipmiProxyIloLaunchDiscoveryStateLoadBr(){try{return window.__ipmi_ilo_launch_discovery||null;}catch(e){return null;}}'
        . 'function ipmiProxyIloRegisterLaunchHelperSignal(st){try{if(!st)return;var h=ipmiProxyIloHelperActivityPresent();if(!h||st.helperReg)return;st.helperReg=true;if(st.launchSurfaceFound||st.discTriggered||st.discNavTriggered){st.helperAidedDiscovery=true;try{_kvmDbg("ilo_launch_helper_aided_discovery",{});}catch(_h1){}}else{try{_kvmDbg("ilo_launch_helper_seen",{phase:"discovery"});}catch(_h2){}}}catch(e){}}'
        . 'function ipmiProxyIloHelperAidedDiscovery(st){return !!(st&&st.helperAidedDiscovery);}'
        . 'function ipmiProxyIloArmLaunchOutcomeProbe(st,n,sig,ws,live){try{if(!st)return;st.pendingOutcomeCheck=n+5;st.launchSigBefore=sig||"";st.__wsBefore=!!ws;st.__liveBefore=!!live;try{st.__wideSnapBefore=JSON.stringify(typeof ipmiProxyIloCapturePreLaunchSnapshot==="function"?ipmiProxyIloCapturePreLaunchSnapshot():{});}catch(_w1){st.__wideSnapBefore="";}}catch(e){}}'
        . 'function ipmiProxyIloRecordLaunchAttemptOutcome(st,sigBefore,wsBefore,liveBefore,tick){try{if(!st)return{effective:false,domChanged:false,wsUp:false,liveUp:false,wideMeaningful:false};var sig=ipmiProxyIloDomSnapshotSig(window);var ws=kvmIloWsTransportEvidence();var live=ipmiProxyIloHasLiveDisplayEvidence(window);var domChanged=(sigBefore&&sig&&sig!==sigBefore);var wsUp=(!wsBefore&&ws);var liveUp=(!liveBefore&&live);var wideMeaningful=false;try{var pre=JSON.parse(st.__wideSnapBefore||"{}");var post=(typeof ipmiProxyIloCapturePostLaunchSnapshot==="function")?ipmiProxyIloCapturePostLaunchSnapshot():{};var wdiff=(typeof ipmiProxyIloDiffLaunchSnapshots==="function")?ipmiProxyIloDiffLaunchSnapshots(pre,post):{meaningful:false,changed:[]};wideMeaningful=!!(wdiff&&wdiff.meaningful);try{_kvmDbg("ilo_launch_snapshot_diff",{narrow_sig_change:domChanged?1:0,wide_fields:(wdiff&&wdiff.changed)?wdiff.changed.join(","):"",wide_meaningful:wideMeaningful?1:0});}catch(_wd){}}catch(_we){}var effective=domChanged||wsUp||liveUp||wideMeaningful;if(effective&&wideMeaningful){try{_kvmDbg("ilo_launch_action_changed_shell_state",{via:"wide_snapshot"});}catch(_ss2){}}try{ipmiProxyIloLaunchDiscoveryStateStore({sig_before:sigBefore||"",sig_after:sig,dom_changed:domChanged?1:0,ws_before:wsBefore?1:0,ws_after:ws?1:0,live_before:liveBefore?1:0,live_after:live?1:0,effective:effective?1:0,wide_meaningful:wideMeaningful?1:0,tick:tick||0,ts:Date.now()});}catch(_ss){}if(!effective){try{_kvmDbg("ilo_launch_action_no_effect",{tick:tick,dom_changed:domChanged?1:0,ws:ws?1:0,live:live?1:0,wide:wideMeaningful?1:0});}catch(_ne){}}else{try{_kvmDbg("ilo_launch_function_effective",{tick:tick,source:"deferred_probe"});}catch(_ef){}}return {effective:effective,domChanged:domChanged,wsUp:wsUp,liveUp:liveUp,wideMeaningful:wideMeaningful};}catch(e){return{effective:false,domChanged:false,wsUp:false,liveUp:false,wideMeaningful:false};}}'
        . 'function ipmiProxyIloConsoleReadinessVerdict(p){try{p=p||{};if(p.fin)return"native_console_strongly_confirmed";if(p.launchFailed)return"launch_discovery_failed";if(p.noEffect)return"launch_action_no_effect";if(p.whiteStall)return"launch_discovery_failed";if(p.specShell&&!p.discoveryStarted)return"shell_autolaunch_allowed";if(p.specShell&&p.discoveryStarted&&!p.transport&&!p.live&&p.shellEscalationConsumed&&p.mgmtVisible)return"console_start_failed_no_transport";if(p.specShell&&p.discoveryStarted&&!p.transport&&!p.live&&p.sessReady===false&&p.launchTried)return"console_start_failed_no_session_ready";return p.inProgress||"launch_discovery_in_progress";}catch(e){return"unknown";}}'
        . 'function ipmiProxyIloFinalizeReadinessFromDiscovery(st,verdict,detail){try{if(!st)return;st.finalDiscoveryVerdict=String(verdict||"");try{ipmiProxyIloLaunchDiscoveryStateStore({final_discovery_verdict:st.finalDiscoveryVerdict,detail:String(detail||""),ts:Date.now()});}catch(_fs){}try{_kvmDbg("ilo_console_readiness_verdict",{verdict:st.finalDiscoveryVerdict,detail:String(detail||""),discovery:1});}catch(_fd){}}catch(e){}}'
        . 'function ipmiProxyIloLooksLikeManagementShellOnly(ctx){return ipmiProxyIloManagementShellStillVisible(ctx);}'
        . 'function ipmiProxyIloHasOnlyShellUi(ctx){return ipmiProxyIloManagementShellStillVisible(ctx);}'
        . 'function ipmiProxyIloShouldRejectShellAsConsoleSuccess(ctx,st){return ipmiProxyIloManagementShellStillVisible(ctx)&&!kvmIloWsTransportEvidence();}'
        . 'function ipmiProxyIloShouldRejectShellOnlyAsStrongConfirmation(ctx){var live=ipmiProxyIloHasLiveDisplayEvidence(ctx);return ipmiProxyIloManagementShellStillVisible(ctx)||(ipmiProxyIloHelperActivityPresent()&&!live);}'
        . 'function ipmiProxyIloCanStronglyConfirmLiveConsole(ctx,st){var probe={finStable:st?st.finStable||0:0};var r=kvmIloReadyToFinalize(ctx,probe);return !!(r&&r.ok);}'
        . 'function ipmiProxyIloFinalizeStrongConfirmationFromVisibleUi(ctx,st,rf){var v=(rf&&rf.ok)?"native_console_strongly_confirmed":(rf&&rf.why?String(rf.why):"console_not_ready");try{ipmiProxyIloShellVsConsoleStateStore({final_verdict:v,finalize:rf||{},live_console_visible:rf&&rf.ok?1:0,native_console_strongly_confirmed:rf&&rf.ok?1:0,ts:Date.now()});}catch(e){}return rf;}'
        . 'function kvmIloSessionReadyEvidence(ctx){'
        . 'try{'
        . 'if(ipmiProxyIloHasLiveDisplayEvidence(ctx))return true;'
        . 'if(kvmIloRcWindowAny()&&!kvmIloLoadingPleaseWaitAny())return true;'
        . '}catch(e){}return false;}'
        . 'function kvmIloInteractiveLikely(ctx){'
        . 'if(kvmIloRendererDetected(ctx))return true;'
        . 'try{if(rcWindowVisible(ctx))return true;}catch(e0){}'
        . 'return kvmAnyFrameCanvas(ctx);'
        . '}'
        . 'function kvmIloReadyToFinalize(ctx,st){'
        . 'var ws=kvmIloWsTransportEvidence();'
        . 'var load=kvmIloLoadingPleaseWaitAny();'
        . 'var live=ipmiProxyIloHasLiveDisplayEvidence(ctx);'
        . 'var mgmt=ipmiProxyIloManagementShellStillVisible(ctx);'
        . 'var ov=false;try{var _d=(ctx&&ctx.document)?ctx.document:document;ov=ipmiProxyIloLooksLikeOverviewShell(_d);}catch(_ov){}'
        . 'var appPl=ipmiProxyIloApplicationPathLoaded();'
        . 'var tk=st?st.__lastTick||0:0;'
        . 'if(load)return {ok:false,why:"loading_only_state",loading_only:1};'
        . 'if(appPl&&!live&&tk>20&&ipmiProxyIloLooksLikeWhiteScreenStall(tk,st)){try{_kvmDbg("ilo_white_screen_failure_finalized",{tick:tk,path:"application"});_kvmDbg("ilo_application_loaded_white_screen",{tick:tk});}catch(_wsf){}return {ok:false,why:"application_loaded_white_screen",white_screen:1,app_path:1};}'
        . 'if(mgmt&&!live){var why="shell_only_management_ui",app=ipmiProxyIloApplicationPathLoaded();if(app&&ov)why="native_console_route_reached_but_shell_only";else if(app)why="application_loaded_console_not_reached";else if(ov)why="shell_only_management_ui";return {ok:false,why:why,shell_only:1,management_shell_still_visible:1,app_path:app?1:0,overview_shell:ov?1:0,native_route_not_ready:app&&!live?1:0};}'
        . 'if(!ws)return {ok:false,why:"no_relay_transport"};'
        . 'if(!live)return {ok:false,why:"transport_without_live_display"};'
        . 'st.finStable=(st.finStable||0)+1;'
        . 'if(st.finStable>=3)return {ok:true,why:"user_visible_console_success"};'
        . 'return {ok:false,why:"stabilizing"};}'
        . 'function kvmHookWsRelayProbe(){try{'
        . 'if(!window.WebSocket||window.__ipmi_kvm_ws_progress_hook)return;'
        . 'window.__ipmi_kvm_ws_progress_hook=true;var W0=window.WebSocket;'
        . 'window.WebSocket=function(u,p){try{if(typeof u==="string"&&u.indexOf("ipmi_ws_relay.php")>=0){window.__ipmi_kvm_ws_relay_ts=kvmNow();try{_kvmDbg("ipmi_ws_relay_client_open",String(u).substring(0,96));}catch(e1){}}}catch(e2){}'
        . 'return new W0(u,p);};window.WebSocket.prototype=W0.prototype;'
        . '}catch(e3){}}'
        . 'kvmHookWsRelayProbe();'
        . 'function kvmIdracViewerBootstrap(){try{'
        . 'var p=pathLower();if(p.indexOf("viewer")>=0||p.indexOf("console")>=0)return true;'
        . 'var b=String(document.body&&document.body.innerHTML||"").toLowerCase();'
        . 'return b.indexOf("avct")>=0||b.indexOf("vmrc")>=0||b.indexOf("websocket")>=0;'
        . '}catch(e){return false;}}'
        . 'function kvmIdracTransportLikely(){return kvmWsRelaySeen()||kvmIdracViewerBootstrap();}'
        . 'function kvmIdracInteractiveLikely(){try{return kvmVisibleCanvasLike(document)||kvmAnyFrameCanvas(window);}catch(e){return false;}}'
        . 'function kvmSupermicroInteractiveLikely(){try{'
        . 'if(kvmVisibleCanvasLike(document))return true;'
        . 'var b=String(document.body&&document.body.innerHTML||"").toLowerCase();'
        . 'return b.indexOf("ikvm")>=0&&b.indexOf("canvas")>=0;'
        . '}catch(e){return false;}}'
        . 'function ipmiProxyIloDetectRemoteConsolePrivilegeBlock(doc){try{if(!doc||!doc.body)return false;var t=String(doc.body.innerText||doc.body.textContent||"").toLowerCase();if(t.indexOf("remote console privilege")>=0&&t.indexOf("required")>=0)return true;if(t.indexOf("insufficient privilege")>=0&&t.indexOf("console")>=0)return true;if(t.indexOf("you do not have")>=0&&t.indexOf("remote console")>=0)return true;var L=doc.querySelectorAll?doc.querySelectorAll(".hpWarning,.hp-warning,.warning-text,[class*=warning],[class*=error],[class*=privilege]"):[];for(var i=0;i<L.length&&i<32;i++){var lt=String(L[i].textContent||"").toLowerCase();if(lt.indexOf("privilege")>=0&&lt.indexOf("remote console")>=0)return true;}return false;}catch(e){return false;}}'
        . 'function ipmiProxyIloDetectRemoteConsolePrivilegePresent(doc){try{if(ipmiProxyIloDetectRemoteConsolePrivilegeBlock(doc))return false;if(!doc||!doc.body)return false;var btn=doc.getElementById?doc.getElementById("HRCButton"):null;if(!btn)btn=doc.querySelector?doc.querySelector("button[data-localize=\\x27rc_info.html5Console\\x27]"):null;if(!btn)btn=doc.querySelector?doc.querySelector("#html5_irc_label a"):null;if(btn){var dis=btn.disabled||btn.getAttribute("disabled")==="disabled"||String(btn.getAttribute("class")||"").indexOf("disabled")>=0;if(dis)return false;return true;}var t=String(doc.body.innerText||"").toLowerCase();if(t.indexOf("html5 console")>=0||t.indexOf("launch console")>=0||t.indexOf("integrated remote console")>=0){if(t.indexOf("privilege")>=0&&t.indexOf("required")>=0)return false;return true;}return false;}catch(e){return false;}}'
        . 'function ipmiProxyIloDetectVisibleUserState(doc){try{if(!doc||!doc.body)return"unknown";var t=String(doc.body.innerText||doc.body.textContent||"");var m=t.match(/User:\\s*([^\\n\\r]{1,60})/i);if(!m)return"unknown";var u=String(m[1]).trim();if(!u||u.toLowerCase()==="unknown"||u==="-"||u==="")return"unknown";return u;}catch(e){return"unknown";}}'
        . 'function ipmiProxyIloRemoteConsolePrivilegeVerdict(doc){try{if(ipmiProxyIloDetectRemoteConsolePrivilegeBlock(doc))return"privilege_missing";if(ipmiProxyIloDetectRemoteConsolePrivilegePresent(doc))return"privilege_present";return"privilege_unknown";}catch(e){return"privilege_unknown";}}'
        . 'function ipmiProxyIloFindHtml5ConsoleLaunchControl(doc){try{if(!doc)return null;var btn=doc.getElementById?doc.getElementById("HRCButton"):null;if(btn&&!btn.disabled)return btn;var btn2=doc.querySelector?doc.querySelector("button[data-localize=\\x27rc_info.html5Console\\x27]"):null;if(btn2&&!btn2.disabled)return btn2;var a=doc.querySelector?doc.querySelector("#html5_irc_label a"):null;if(a)return a;var links=doc.querySelectorAll?doc.querySelectorAll("a[href],button"):[];for(var i=0;i<links.length&&i<200;i++){var tx=String(links[i].textContent||"").toLowerCase();if((tx.indexOf("html5")>=0&&tx.indexOf("console")>=0)||(tx.indexOf("launch")>=0&&tx.indexOf("html5")>=0))return links[i];}return null;}catch(e){return null;}}';
}

function ipmiProxyBuildIloKvmScript(): string
{
    return 'if(FAMILY==="ilo"){'
        . 'var pl=pathLower();'
        . 'if(pl.indexOf("/html/rc_info.html")!==-1&&!hasIloRendererHost(window)&&(!window.parent||window.parent===window)){go("/html/application.html?ipmi_kvm_auto=1");return;}'
        . 'var n=0,max=Math.max(220,Math.ceil(KVM_TMO/220));'
        . 'var iloSt={phase:0,lastProgress:kvmNow(),clicks:0,phaseClickRounds:0,navAttempts:0,reported:{boot:false,launch:false,trans:false,inter:false,rContainer:false,rDetected:false,wsEv:false,sessR:false,bootstrap:false,fin:false,stuck:false,noTrans:false,noSess:false,stuckEsc:false,stuckFin:false,interWhileLoad:false,liveDispEv:false,loadingClearedEv:false,appPath:false,overview:false,helperSeen:false,helperNoTx:false,helperCorr:false,consoleFrameFollowed:false},finStable:0,ldSince:0,ldDbg:false,ldPerDbg:false,esc:0,stall:false,lastVerdict:"console_starting",prevVerdict:"",corrDbg:false,specShell:false,discoveryStarted:false,menuExpanded:false,discEsc:0,discNavTriggered:false,anyLaunchAction:false,launchDiscoveryFailed:false,discTriggered:false,funcFound:false,frameNavDone:false,delayedRescanDone:false,earlyDiscDone:false,prevLd:false,shellFailDbg:false,loadFailDbg:false,shellEscalationConsumed:false,discoveryEscalationKind:"",finalDiscoveryVerdict:"",launchSurfaceFound:false,whiteStallReported:false,helperReg:false,helperAidedDiscovery:false,launchNoEffectReported:false,pendingOutcomeCheck:-1,launchSigBefore:"",__wsBefore:false,__liveBefore:false,discoveryOutcomeLogged:false,helperNoTargetDbg:false,shellOnlyUiDbg:false,helperNoConfirmDbg:false,consoleModDbg:false,contentFrameVisDbg:false,appConsoleLaunchTried:false,launchFnBudgetSpent:0,launchFnBudgetMax:2,shellLaunchProbeExhausted:false,shellLaunchNoEffectLocked:false,shellLaunchProvenIneffective:false,launchFnContextChanged:false,lastCtxFp:"",shellPathAbandoned:false,applicationPathPromotionActive:false,appNavPendingSince:0,appNavCommitted:false,appNavFailed:false,launchFunctionFound:false,launchFunctionEffective:false,launchFunctionNoEffectObserved:false,__lastTick:0,privilegeVerdict:"unknown",privilegeBlockDetected:false,privilegeBlockDbg:false,privilegePresentDbg:false,privilegeUserState:"unknown",privilegeUserDbg:false,html5LaunchControlFound:false,html5LaunchAttempted:false,html5LaunchEffective:false,privilegeBlockFinalized:false};'
        . '(function tick(){'
        . 'n++;'
        . 'if(iloSt.pendingOutcomeCheck>0&&n>=iloSt.pendingOutcomeCheck){iloSt.pendingOutcomeCheck=-1;var _or=ipmiProxyIloRecordLaunchAttemptOutcome(iloSt,iloSt.launchSigBefore,iloSt.__wsBefore,iloSt.__liveBefore,n);if(_or&&_or.effective){try{_kvmDbg("ilo_launch_function_effective",{source:"deferred_probe"});}catch(_efp){}iloSt.launchFunctionEffective=true;iloSt.shellLaunchNoEffectLocked=false;}else if(iloSt.specShell&&!iloSt.launchNoEffectReported){iloSt.launchNoEffectReported=true;iloSt.shellLaunchProvenIneffective=true;iloSt.shellLaunchNoEffectLocked=true;iloSt.shellLaunchProbeExhausted=true;try{_kvmDbg("ilo_shell_launch_proven_ineffective",{source:"deferred_probe"});_kvmDbg("ilo_launch_function_no_effect",{phase:"deferred_probe"});_kvmDbg("ilo_launch_discovery_failed",{reason:"launch_action_no_effect"});ipmiProxyIloFinalizeReadinessFromDiscovery(iloSt,"launch_action_no_effect","post_click_no_dom_ws_live_change");}catch(_of){}}}'
        . 'var ctx=collectContexts();'
        . 'iloSt.__lastTick=n;'
        . 'try{var _cfpPrev=iloSt.lastCtxFp||"";var _cfpNow=(typeof ipmiProxyIloLaunchFunctionContextFingerprint==="function")?ipmiProxyIloLaunchFunctionContextFingerprint():"";if(_cfpPrev&&_cfpNow!==_cfpPrev&&iloSt.shellLaunchNoEffectLocked){iloSt.launchFnContextChanged=true;iloSt.shellLaunchNoEffectLocked=false;iloSt.shellLaunchProbeExhausted=false;iloSt.launchFnBudgetSpent=0;try{_kvmDbg("ilo_launch_function_retry_allowed",{reason:"context_fingerprint_changed"});}catch(_cr){}}iloSt.lastCtxFp=_cfpNow;}catch(_cf){}'
        . 'var wsEarly=kvmIloWsTransportEvidence();var liveEarly=ipmiProxyIloHasLiveDisplayEvidence(window);var sigEarly=ipmiProxyIloDomSnapshotSig(window);'
        . 'if(iloSt.appNavPendingSince>0&&!iloSt.appNavCommitted&&!iloSt.appNavFailed){var plNav=pathLower();if(plNav.indexOf("/html/application.html")>=0){iloSt.appNavCommitted=true;iloSt.appNavPendingSince=0;try{_kvmDbg("ilo_application_navigation_committed",{path:plNav});_kvmDbg("ilo_application_document_loaded",{path:plNav});_kvmDbg("ilo_application_path_active",{path:plNav});}catch(_ac){}}else if(kvmNow()-iloSt.appNavPendingSince>9500){iloSt.appNavFailed=true;try{_kvmDbg("ilo_application_navigation_not_committed",{ms:kvmNow()-iloSt.appNavPendingSince});_kvmDbg("ilo_application_navigation_failed",{reason:"timeout_not_on_application"});_kvmDbg("ilo_application_navigation_no_effect",{reason:"location_unchanged"});}catch(_af){}}}'
        . 'iloSt.specShell=!!(PLAN&&PLAN.speculative_shell_autolaunch);'
        . 'if(iloSt.specShell&&!iloSt.discoveryStarted){iloSt.discoveryStarted=true;try{_kvmDbg("ilo_shell_autolaunch_allowed",{entry:String(PLAN.kvm_entry_path||""),strategy:String(PLAN.launch_strategy||"")});_kvmDbg("ilo_launch_discovery_started",{path:pathLower()});}catch(_ds0){}}'
        . 'var shell=getIloShellHost(window);'
        . 'var rootCtx=null;'
        . 'try{rootCtx=(window.top&&window.top.document&&window.top.document.getElementById&&window.top.document.getElementById("appFrame"))?window.top:window;}catch(_eroot){rootCtx=window;}'
        . 'if(rootCtx){if(ensureIloIndexAppLoaded(rootCtx)){kvmTouchProgress(iloSt);}}'
        . 'if(shell){if(!shell.__ipmi_dbg_shell){try{shell.__ipmi_dbg_shell=1;kvmTouchProgress(iloSt);_kvmDbg("ilo_shell_detected",1);}catch(ds){}}forceSameTabOpen(shell);ensureIloFrameResizeShim(shell);ensureIloStartPatched(shell);ensureIloGlobalStartPatched(shell);wireIloAppFrame(shell);ensureIloShellLoaded(shell);ensureIloRcPageLoaded(shell);if((n%8)===0){clearIloStaleRenderer(shell);}}'
        . 'var rcPage=false,btnFound=false;'
        . 'for(var ri=0;ri<ctx.length;ri++){if(hasIloRcPage(ctx[ri])){rcPage=true;}if(findIloHtml5Button(ctx[ri])){btnFound=true;}}'
        . 'if(rcPage||btnFound){iloSt.anyLaunchAction=true;if(!iloSt.launchSurfaceFound){iloSt.launchSurfaceFound=true;try{_kvmDbg("ilo_launch_surface_found",{rc_page:rcPage?1:0,html5_button:btnFound?1:0});}catch(_lsf){}}}'
        . 'if(rcPage&&!iloSt.reported.boot){iloSt.reported.boot=true;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_bootstrap_route_ready",1);_kvmDbg("ilo_console_bootstrap_started",1);}catch(eb){}}'
        . 'if(btnFound&&!iloSt.reported.launch){iloSt.reported.launch=true;iloSt.anyLaunchAction=true;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_control_found",1);}catch(el){}}'
        . 'if(iloSt.specShell&&(n===10||n===11)&&!iloSt.menuExpanded){iloSt.menuExpanded=true;for(var mx=0;mx<ctx.length;mx++){try{if(ctx[mx].document&&tryExpandIloHiddenMenus(ctx[mx].document,"shell")){_kvmDbg("ilo_launch_menu_expanded",{n:n});break;}}catch(_mex){}}}'
        . 'if(iloSt.specShell&&n===5&&!iloSt.earlyDiscDone){iloSt.earlyDiscDone=true;var edr=tryClickIloDiscoveryLaunch(ctx,"early",iloSt);if(edr){iloSt.discTriggered=true;iloSt.anyLaunchAction=true;iloSt.clicks++;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_triggered",{how:edr,clicks:iloSt.clicks,tag:"early"});ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(_ed0){}}}'
        . 'if(iloSt.specShell&&iloSt.menuExpanded&&n===12&&!iloSt.delayedRescanDone){iloSt.delayedRescanDone=true;var ddr=tryClickIloDiscoveryLaunch(ctx,"delayed_rescan",iloSt);if(ddr){iloSt.discTriggered=true;iloSt.anyLaunchAction=true;iloSt.clicks++;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_triggered",{how:ddr,clicks:iloSt.clicks,tag:"delayed_rescan"});ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(_dd0){}}}'
        . 'if(iloSt.specShell&&(n%5===2)&&n>3){var dlr=tryClickIloDiscoveryLaunch(ctx,"scan",iloSt);if(dlr){iloSt.discTriggered=true;iloSt.anyLaunchAction=true;iloSt.clicks++;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_triggered",{how:dlr,clicks:iloSt.clicks});ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(_dlt){}}}'
        . 'for(var i=0;i<ctx.length;i++){forceSameTabOpen(ctx[i]);ensureIloFrameResizeShim(ctx[i]);ensureIloStartPatched(ctx[i]);ensureIloGlobalStartPatched(ctx[i]);wireIloAppFrame(ctx[i]);ensureIloRcButtonPatched(ctx[i]);if((n%8)===0){clearIloStaleRenderer(ctx[i]);}'
        . 'try{'
        . 'if(kvmIloRendererOrContainerPresent(ctx[i])&&!iloSt.reported.rContainer){iloSt.reported.rContainer=true;kvmTouchProgress(iloSt);_kvmDbg("ilo_renderer_container_detected",1);}'
        . 'if(kvmIloRendererDetected(ctx[i])&&!iloSt.reported.rDetected){iloSt.reported.rDetected=true;kvmTouchProgress(iloSt);try{var _ldR=kvmIloLoadingPleaseWaitAny();_kvmDbg("ilo_renderer_detected",{loading:_ldR?1:0,hint:_ldR?"not_console_success":""});}catch(edr){_kvmDbg("ilo_renderer_detected",1);}}'
        . 'if(kvmIloInteractiveLikely(ctx[i])){if(!iloSt.reported.inter){iloSt.reported.inter=true;try{var _ldH=kvmIloLoadingPleaseWaitAny();_kvmDbg("ilo_console_interactive_likely",{loading:_ldH?1:0,hint:_ldH?"not_final_success":""});if(_ldH&&!iloSt.reported.interWhileLoad){iloSt.reported.interWhileLoad=true;_kvmDbg("ilo_console_interactive_likely_while_loading",{note:"shell_only_not_interactive_ready"});}}catch(eilh){_kvmDbg("ilo_console_interactive_likely",1);}}kvmTouchProgress(iloSt);}'
        . '}catch(eic){}'
        . '}'
        . 'var wsNow=kvmIloWsTransportEvidence();'
        . 'if(wsNow){kvmTouchProgress(iloSt);if(!iloSt.reported.wsEv){iloSt.reported.wsEv=true;iloSt.reported.trans=true;try{_kvmDbg("ilo_transport_evidence_detected",1);_kvmDbg("ilo_console_transport_started",1);_kvmDbg("ilo_transport_detected",1);}catch(et0){}}}'
        . 'var plx2=pathLower();var onShellPath=(plx2.indexOf("/index.html")>=0||plx2.indexOf("/restgui/")>=0||plx2==="/"||plx2==="");var escEarly=(iloSt.specShell&&iloSt.shellLaunchProvenIneffective&&onShellPath&&!rcPage&&n>=10);var escLate=(iloSt.specShell&&n>=24&&onShellPath&&!rcPage);if(iloSt.specShell&&!iloSt.shellEscalationConsumed&&!wsNow&&(escEarly||escLate)){var _ek=tryShellDiscoveryEscalationOnce(ctx,iloSt);if(_ek==="href"){ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}if(_ek==="spa"){return;}}'
        . 'if(iloSt.specShell&&n===33&&!iloSt.discNavTriggered&&!iloSt.shellEscalationConsumed){try{var plxSk=pathLower();var _esk=plxSk.indexOf("/html/application.html")>=0?"already_in_spa":"still_on_shell_within_window";_kvmDbg("ilo_launch_discovery_escalation_skipped",{reason:_esk});}catch(_skp){}}'
        . 'if(kvmIloSessionReadyEvidence(window)&&!iloSt.reported.sessR){iloSt.reported.sessR=true;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_session_ready_evidence_detected",1);_kvmDbg("ilo_console_session_ready",1);}catch(es0){}}'
        . 'var ldNow=kvmIloLoadingPleaseWaitAny(),rAny=iloSt.reported.rContainer,ldMs=iloSt.ldSince?(kvmNow()-iloSt.ldSince):0;'
        . 'if(ldNow){if(!iloSt.ldSince)iloSt.ldSince=kvmNow();ldMs=kvmNow()-iloSt.ldSince;if(!iloSt.ldDbg&&ldMs>6000){iloSt.ldDbg=true;try{_kvmDbg("ilo_loading_state_detected",{ms:ldMs});}catch(eld0){}}if(ldMs>12000&&!iloSt.ldPerDbg){iloSt.ldPerDbg=true;try{_kvmDbg("ilo_loading_state_persisted",{ms:ldMs});_kvmDbg("ilo_loading_spinner_persisted",{ms:ldMs});}catch(eld1){}}}'
        . 'else{iloSt.ldSince=0;iloSt.ldDbg=false;iloSt.ldPerDbg=false;}'
        . 'var liveNow=ipmiProxyIloHasLiveDisplayEvidence(window),shellOnlyNow=ipmiProxyIloLooksLikeManagementShellOnly(window),routeNow=ipmiProxyIloConsoleRouteReached(),mgmtNow=ipmiProxyIloManagementShellStillVisible(window),appPathNow=ipmiProxyIloApplicationPathLoaded(),overviewNow=false;try{overviewNow=ipmiProxyIloLooksLikeOverviewShell(document);}catch(_ovn){overviewNow=false;}var helperNow=ipmiProxyIloHelperActivityPresent();'
        . 'if(appPathNow&&!iloSt.reported.appPath){iloSt.reported.appPath=true;try{_kvmDbg("ilo_application_path_loaded",{path:pathLower()});var _b0=ipmiProxyIloShellVsConsoleStateLoad()||{};_b0.application_path_loaded=1;_b0.app_tick=n;ipmiProxyIloShellVsConsoleStateStore(_b0);}catch(_ap0){}}'
        . 'if(overviewNow&&!iloSt.reported.overview){iloSt.reported.overview=true;try{_kvmDbg("ilo_overview_shell_detected",1);_kvmDbg("ilo_management_shell_detected",1);var _b1=ipmiProxyIloShellVsConsoleStateLoad()||{};_b1.overview_shell_detected=1;ipmiProxyIloShellVsConsoleStateStore(_b1);}catch(_ov1){}}'
        . 'if(mgmtNow&&!liveNow&&(n%12)===0){try{_kvmDbg("ilo_management_shell_still_visible",{tick:n,app_path:appPathNow?1:0,overview:overviewNow?1:0});}catch(_msv){}}'
        . 'if(appPathNow&&(n%3)===1){try{var _pvDoc=null;for(var _pvi=0;_pvi<ctx.length;_pvi++){try{if(ctx[_pvi]&&ctx[_pvi].document&&ctx[_pvi].document.body){_pvDoc=ctx[_pvi].document;break;}}catch(_pvE){}}if(_pvDoc){var _pvV=ipmiProxyIloRemoteConsolePrivilegeVerdict(_pvDoc);iloSt.privilegeVerdict=_pvV;if(_pvV==="privilege_missing"&&!iloSt.privilegeBlockDetected){iloSt.privilegeBlockDetected=true;iloSt.privilegeBlockFinalized=false;}if(_pvV==="privilege_missing"&&!iloSt.privilegeBlockDbg){iloSt.privilegeBlockDbg=true;try{_kvmDbg("ilo_remote_console_privilege_message_detected",{});_kvmDbg("ilo_remote_console_privilege_block_detected",{});_kvmDbg("ilo_remote_console_privilege_missing",{verdict:_pvV});}catch(_pvD){}}if(_pvV==="privilege_present"&&!iloSt.privilegePresentDbg){iloSt.privilegePresentDbg=true;iloSt.privilegeBlockDetected=false;try{_kvmDbg("ilo_remote_console_privilege_present",{});}catch(_pvP){}}var _pvU=ipmiProxyIloDetectVisibleUserState(_pvDoc);iloSt.privilegeUserState=_pvU;if(_pvU==="unknown"&&!iloSt.privilegeUserDbg){iloSt.privilegeUserDbg=true;try{_kvmDbg("ilo_visible_user_unknown",{});}catch(_pvU2){}}else if(_pvU!=="unknown"&&iloSt.privilegeUserDbg){iloSt.privilegeUserDbg=false;try{_kvmDbg("ilo_visible_user_detected",{user:String(_pvU).substring(0,60)});}catch(_pvU3){}}var _h5Btn=ipmiProxyIloFindHtml5ConsoleLaunchControl(_pvDoc);if(_h5Btn&&!iloSt.html5LaunchControlFound){iloSt.html5LaunchControlFound=true;try{_kvmDbg("ilo_html5_console_button_found",{});}catch(_h5D){}}}}catch(_pvOuter){}}'
        . 'if(iloSt.privilegeBlockDetected&&!iloSt.privilegeBlockFinalized&&n>16&&!liveNow&&!wsNow){iloSt.privilegeBlockFinalized=true;iloSt.stall=true;try{_kvmDbg("ilo_remote_console_privilege_block_finalized",{tick:n,user:String(iloSt.privilegeUserState||"unknown").substring(0,60)});_kvmDbg("ilo_console_readiness_verdict",{verdict:"remote_console_privilege_missing",detail:"privilege_required_message_on_page",user_state:String(iloSt.privilegeUserState||"")});}catch(_pvFin){}}'
        . 'if(helperNow&&!iloSt.reported.helperSeen){iloSt.reported.helperSeen=true;try{_kvmDbg("ilo_helper_activity_seen",1);}catch(_hs){}}'
        . 'if(helperNow){ipmiProxyIloRegisterLaunchHelperSignal(iloSt);}'
        . 'if(appPathNow&&!liveNow&&ipmiProxyIloApplicationLoadedShellOnly(window)&&(n%6)===2){try{_kvmDbg("ilo_application_loaded_shell_only",{tick:n,overview:overviewNow?1:0,helper:helperNow?1:0});}catch(_aso){}}'
        . 'if(appPathNow&&overviewNow&&!liveNow&&(n%8)===4){try{_kvmDbg("ilo_console_not_reached_after_application_load",{tick:n,helper:helperNow?1:0,transport:wsNow?1:0});}catch(_cnr){}}'
        . 'if(appPathNow&&!liveNow&&(n%7)===3){for(var _aft=0;_aft<ctx.length;_aft++){try{if(ctx[_aft].document&&ipmiProxyIloFollowConsoleFrameTransition(ctx[_aft].document,iloSt))break;}catch(_fe){}}}'
        . 'if(appPathNow&&!liveNow&&n>6&&(n%5)===0&&!iloSt.appConsoleLaunchTried){for(var _bi=0;_bi<ctx.length;_bi++){try{var _doc2=ctx[_bi].document;if(!_doc2)continue;var _mod=ipmiProxyIloFindConsoleModuleInApplication(_doc2);if(_mod&&!iloSt.consoleModDbg){iloSt.consoleModDbg=true;_kvmDbg("ilo_console_module_detected",{tick:n});}var _act=ipmiProxyIloFindConsoleLaunchActionInApplication(_doc2);if(_act){_kvmDbg("ilo_console_launch_action_found",{tick:n});try{var _didA=false;if(typeof _act.click==="function"){_act.click();_didA=true;}else if(_doc2.createEvent){var _evx=_doc2.createEvent("MouseEvents");_evx.initEvent("click",true,true);_act.dispatchEvent(_evx);_didA=true;}if(_didA){iloSt.appConsoleLaunchTried=true;iloSt.discTriggered=true;iloSt.anyLaunchAction=true;kvmTouchProgress(iloSt);_kvmDbg("ilo_console_launch_action_triggered",{});ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);break;}}catch(_acl){}}}catch(_lp){}}}'
        . 'try{var _rootd=document;if(_rootd&&ipmiProxyIloConsoleContentFrameVisible(_rootd)&&!iloSt.contentFrameVisDbg){iloSt.contentFrameVisDbg=true;_kvmDbg("ilo_console_content_frame_visible",{where:"root"});}for(var _ci=0;_ci<ctx.length;_ci++){try{var _d3=ctx[_ci].document;if(_d3&&ipmiProxyIloConsoleContentFrameVisible(_d3)&&!iloSt.contentFrameVisDbg){iloSt.contentFrameVisDbg=true;_kvmDbg("ilo_console_content_frame_visible",{where:"ctx",idx:_ci});break;}}catch(_cfv){}}}catch(_cfv0){}'
        . 'if(helperNow&&mgmtNow&&!liveNow&&!iloSt.helperNoConfirmDbg&&n>18){iloSt.helperNoConfirmDbg=true;try{if(ipmiProxyIloHelperActivitySupportsButDoesNotConfirm(window))_kvmDbg("ilo_helper_success_not_counted_as_console_success",{helper:1,management_shell:mgmtNow?1:0,app_path:appPathNow?1:0,overview:overviewNow?1:0});if(ipmiProxyIloHelperSeenWithoutVisibleProgress(window))_kvmDbg("ilo_helper_activity_without_visible_progress",{app_path:appPathNow?1:0});if(ipmiProxyIloHelperSupportsVisibleTransition(window))_kvmDbg("ilo_helper_activity_correlated_with_console_frame",{});}catch(_hnc){}}'
        . 'if(helperNow&&iloSt.specShell&&n>22&&!iloSt.launchSurfaceFound&&!iloSt.discTriggered&&!iloSt.helperNoTargetDbg){iloSt.helperNoTargetDbg=true;try{_kvmDbg("ilo_launch_helper_seen_but_no_target_found",{tick:n});_kvmDbg("ilo_no_launch_target_found",{reason:"helper_without_surface",tick:n});}catch(_hnt0){}}'
        . 'if(helperNow&&mgmtNow&&!liveNow&&!iloSt.reported.helperNoTx){iloSt.reported.helperNoTx=true;try{_kvmDbg("ilo_helper_activity_without_console_transition",{overview:overviewNow?1:0});_kvmDbg("ilo_console_not_reached",1);}catch(_hnt){}}'
        . 'if(helperNow&&liveNow&&!iloSt.reported.helperCorr){iloSt.reported.helperCorr=true;try{_kvmDbg("ilo_helper_activity_correlated_with_console_reach",1);}catch(_hc){}}'
        . 'if(liveNow&&!iloSt.reported.liveDispEv){iloSt.reported.liveDispEv=true;try{_kvmDbg("ilo_live_display_evidence_detected",{route:routeNow?1:0});_kvmDbg("ilo_live_console_visible",1);_kvmDbg("ilo_live_console_display_visible",{route:routeNow?1:0,overview_still:overviewNow?1:0});_kvmDbg("ilo_console_viewport_active",1);var _cd=document;var _anyCv=false;try{if(_cd&&ipmiProxyIloCanvasLooksActive(_cd))_anyCv=true;}catch(_c0){}if(_anyCv)_kvmDbg("ilo_console_canvas_active",1);var _b2=ipmiProxyIloShellVsConsoleStateLoad()||{};_b2.live_console_visible=1;_b2.live_console_display_visible=1;ipmiProxyIloShellVsConsoleStateStore(_b2);}catch(_lde){}}'
        . 'if(mgmtNow&&!liveNow&&!ldNow&&(n%16)===0){try{_kvmDbg("ilo_shell_only_visible",{app_path:appPathNow?1:0,overview:overviewNow?1:0});}catch(_sov){}}'
        . 'if(iloSt.specShell&&shellOnlyNow&&!liveNow&&!wsNow&&n>10&&!iloSt.shellOnlyUiDbg){iloSt.shellOnlyUiDbg=true;try{_kvmDbg("ilo_shell_only_ui_detected",{tick:n,transport:wsNow?1:0});}catch(_sui){}}'
        . 'if(iloSt.specShell&&ipmiProxyIloLooksLikeWhiteScreenStall(n,iloSt)&&!iloSt.whiteStallReported){iloSt.whiteStallReported=true;try{_kvmDbg("ilo_white_screen_stall_detected",{tick:n,disc_nav:iloSt.discNavTriggered?1:0});_kvmDbg("ilo_stalled_before_transport",{white_screen:1});ipmiProxyIloFinalizeReadinessFromDiscovery(iloSt,"launch_discovery_failed","white_screen_stall");}catch(_wss){}}'
        . 'if(iloSt.prevLd&&!ldNow&&liveNow&&!iloSt.reported.loadingClearedEv){iloSt.reported.loadingClearedEv=true;try{_kvmDbg("ilo_loading_only_state_cleared",{live_display:1});}catch(_lc){}}'
        . 'iloSt.prevLd=!!ldNow;'
        . 'if(ldNow&&!liveNow&&(n%6)===0){try{_kvmDbg("ilo_loading_only_state_present",{tick:n,ms:ldMs});}catch(_lop){}}'
        . 'if((n%4)===0){try{var _cs={shell_only_ui:shellOnlyNow?1:0,management_shell_visible:mgmtNow?1:0,overview_shell:overviewNow?1:0,application_path_loaded:appPathNow?1:0,helper_activity:helperNow?1:0,native_route_reached:routeNow?1:0,transport_started:wsNow?1:0,session_ready:iloSt.reported.sessR?1:0,live_display:liveNow?1:0,loading_only:ldNow?1:0,loading_persisted:(ldNow&&ldMs>12000)?1:0,launch_surface:(rcPage||btnFound)?1:0,launch_surface_found:iloSt.launchSurfaceFound?1:0,renderer_container:rAny?1:0,weak_interactive_likely:iloSt.reported.inter?1:0,launch_action:(iloSt.discTriggered||iloSt.discNavTriggered)?1:0,launch_action_effective:(iloSt.launchNoEffectReported?0:1),shell_escalation_consumed:iloSt.shellEscalationConsumed?1:0,discovery_escalation_kind:String(iloSt.discoveryEscalationKind||""),white_screen_stall:iloSt.whiteStallReported?1:0,helper_aided_discovery:iloSt.helperAidedDiscovery?1:0,launch_outcome_probe_pending:(iloSt.pendingOutcomeCheck>0)?1:0,launch_fn_found:iloSt.launchFunctionFound?1:0,launch_fn_effective:iloSt.launchFunctionEffective?1:0,shell_path_abandoned:iloSt.shellPathAbandoned?1:0,app_nav_committed:iloSt.appNavCommitted?1:0,app_nav_failed:iloSt.appNavFailed?1:0,privilege_verdict:String(iloSt.privilegeVerdict||"unknown"),privilege_block:iloSt.privilegeBlockDetected?1:0,html5_launch_attempted:iloSt.html5LaunchAttempted?1:0,html5_launch_effective:iloSt.html5LaunchEffective?1:0,visible_user:String(iloSt.privilegeUserState||"unknown").substring(0,40)};_kvmDbg("ilo_confirmation_signals_collected",_cs);var _w=_cs.launch_surface||_cs.renderer_container||_cs.weak_interactive_likely;var _m=_cs.native_route_reached||_cs.launch_action;var _reach=_m||_cs.launch_surface;var _str=_cs.transport_started&&_cs.live_display&&!_cs.loading_only&&!mgmtNow&&!overviewNow;if(_str)_kvmDbg("ilo_confirmation_strong",{note:"browser_signal_bundle_visible_console"});else if(_reach&&!_str)_kvmDbg("ilo_confirmation_reached_not_ready",_cs);else if(_w&&!_reach)_kvmDbg("ilo_confirmation_weak_only",_cs);if((mgmtNow||overviewNow)&&n>20&&!liveNow&&!iloSt.shellFailDbg){iloSt.shellFailDbg=true;_kvmDbg("ilo_strong_confirmation_rejected_shell_only",_cs);_kvmDbg("ilo_confirmation_failed_shell_only",_cs);}if(shellOnlyNow&&n>24&&!wsNow&&!liveNow&&!iloSt.shellFailDbg){iloSt.shellFailDbg=true;_kvmDbg("ilo_confirmation_failed_shell_only",_cs);}if(ldNow&&ldMs>15000&&!liveNow&&!iloSt.loadFailDbg){iloSt.loadFailDbg=true;_kvmDbg("ilo_confirmation_failed_loading_only",_cs);}}catch(_cef){}}'
        . 'if(rAny&&ldNow&&!wsNow&&ldMs>14000&&!iloSt.reported.noTrans){iloSt.reported.noTrans=true;try{_kvmDbg("ilo_renderer_without_transport",{ms:ldMs});}catch(et1){}}'
        . 'if(rAny&&ldNow&&!iloSt.reported.sessR&&ldMs>18000&&!iloSt.reported.noSess){iloSt.reported.noSess=true;try{_kvmDbg("ilo_renderer_without_session_ready",{ms:ldMs});}catch(es1){}}'
        . 'if(rAny&&ldNow&&!wsNow&&iloSt.ldSince&&(ldMs)>26000&&iloSt.esc===0){iloSt.esc=1;try{_kvmDbg("ilo_stuck_loading_escalation_allowed",{reason:"no_ws_long_loading"});if(shell){clearIloStaleRenderer(shell);forceSameTabOpen(shell);}for(var ei=0;ei<ctx.length;ei++){try{clearIloStaleRenderer(ctx[ei]);}catch(ec0){}}_kvmDbg("ilo_stuck_loading_escalation_attempted",{n:1});}catch(eesc){}}'
        . 'else if(rAny&&ldNow&&!wsNow&&iloSt.ldSince&&(ldMs)>26000&&iloSt.esc>0&&!iloSt.reported.stuckEsc){iloSt.reported.stuckEsc=true;try{_kvmDbg("ilo_stuck_loading_escalation_skipped",{reason:"already_escalated_once"});}catch(eskip){}}'
        . 'if(rAny&&ldNow&&!wsNow&&iloSt.ldSince&&(ldMs)>36000&&!iloSt.corrDbg){iloSt.corrDbg=true;try{_kvmDbg("ilo_console_startup_stall_correlated",{reason:"prolonged_loading_no_transport",ms:ldMs});}catch(ec2){}}'
        . 'if(rAny&&ldNow&&iloSt.ldSince&&(ldMs)>40000&&!iloSt.reported.stuck){iloSt.reported.stuck=true;iloSt.lastVerdict="console_stuck_loading";try{if(!wsNow){_kvmDbg("ilo_console_stuck_loading",{reason:"prolonged_loading_no_transport",ms:ldMs});_kvmDbg("ilo_console_readiness_verdict",{verdict:"console_start_failed_no_transport",detail:"no_ws_after_renderer",ms:ldMs});}else{_kvmDbg("ilo_console_stuck_loading",{reason:"prolonged_loading_with_transport",ms:ldMs,session_ready:iloSt.reported.sessR?1:0});_kvmDbg("ilo_console_readiness_verdict",{verdict:"console_stuck_loading",detail:"loading_with_ws_or_session_stall",ms:ldMs});}_kvmDbg("ilo_loading_state_escalated",{ms:ldMs,esc:iloSt.esc});if(iloSt.esc>=1){_kvmDbg("ilo_stuck_loading_finalized",{esc:iloSt.esc,verdict:"console_stuck_loading"});}}catch(est){}}'
        . 'var rf=kvmIloReadyToFinalize(window,iloSt);'
        . 'if((n%4)===0){try{var _mxTk=iloSt.__lastTick||0;var _mxWs=!!kvmIloWsTransportEvidence();var _mxLive=!!ipmiProxyIloHasLiveDisplayEvidence(window);var _mxApp=ipmiProxyIloApplicationPathLoaded();_kvmDbg("ilo_kvm_debug_matrix",{launch_function_found:iloSt.launchFunctionFound?1:0,launch_function_effective:iloSt.launchFunctionEffective?1:0,shell_path_abandoned:iloSt.shellPathAbandoned?1:0,application_navigation_committed:iloSt.appNavCommitted?1:0,application_navigation_failed:iloSt.appNavFailed?1:0,white_screen_stall:iloSt.whiteStallReported?1:0,live_display_visible:_mxLive?1:0,transport_started:_mxWs?1:0,strong_confirmation_ready:rf.ok?1:0,strong_confirmation_why:String(rf.why||""),privilege_verdict:String(iloSt.privilegeVerdict||"unknown"),privilege_block:iloSt.privilegeBlockDetected?1:0,privilege_block_finalized:iloSt.privilegeBlockFinalized?1:0,visible_user:String(iloSt.privilegeUserState||"unknown").substring(0,40),html5_button_found:iloSt.html5LaunchControlFound?1:0,html5_launch_attempted:iloSt.html5LaunchAttempted?1:0,html5_launch_effective:iloSt.html5LaunchEffective?1:0,shell_launch_probe_exhausted:iloSt.shellLaunchProbeExhausted?1:0});}catch(_mx){}}'
        . 'if(rf.ok&&!iloSt.reported.fin){iloSt.reported.fin=true;iloSt.lastVerdict="console_interactive_confirmed";try{ipmiProxyIloFinalizeStrongConfirmationFromVisibleUi(window,iloSt,rf);_kvmDbg("ilo_strong_confirmation_achieved",{why:rf.why||""});_kvmDbg("ilo_user_visible_console_success",{why:rf.why||"",strong_confirmation:1,live_display:liveNow?1:0,transport:wsNow?1:0});_kvmDbg("ilo_confirmation_strong",{tier:"native_console_strongly_confirmed",source:"finalize"});_kvmDbg("ilo_console_interactive_confirmed",rf);_kvmDbg("ilo_console_readiness_verdict",{verdict:"native_console_strongly_confirmed",why:rf.why||"",native_console_confirmation:"native_console_strongly_confirmed",live_display:liveNow?1:0,management_shell_visible:mgmtNow?1:0,overview_shell:overviewNow?1:0});markDone();return;}catch(emf){}}'
        . 'var started=false,rcReady=rcPage||btnFound;'
        . 'var _blkPrivilege=iloSt.privilegeBlockDetected&&!liveNow&&!wsNow;'
        . 'var _blkShellDup=iloSt.specShell&&iloSt.shellLaunchProbeExhausted&&iloSt.shellLaunchNoEffectLocked&&!iloSt.launchFnContextChanged;if(_blkShellDup&&(n%12)===0){try{_kvmDbg("ilo_launch_function_blocked_by_context",{reason:"no_effect_budget_exhausted"});}catch(_bc){}}'
        . 'if(appPathNow&&!iloSt.html5LaunchAttempted&&!_blkPrivilege&&iloSt.privilegeVerdict==="privilege_present"&&n>4){try{var _h5Doc=null;for(var _h5i=0;_h5i<ctx.length;_h5i++){try{if(ctx[_h5i]&&ctx[_h5i].document&&ctx[_h5i].document.body){_h5Doc=ctx[_h5i].document;break;}}catch(_h5e){}}if(_h5Doc){var _h5Ctrl=ipmiProxyIloFindHtml5ConsoleLaunchControl(_h5Doc);if(_h5Ctrl){var _h5Pre=ipmiProxyIloCapturePreLaunchSnapshot();try{_kvmDbg("ilo_html5_console_launch_attempted",{tick:n});}catch(_h5la){}try{if(typeof _h5Ctrl.click==="function")_h5Ctrl.click();else if(_h5Doc.createEvent){var _h5ev=_h5Doc.createEvent("MouseEvents");_h5ev.initEvent("click",true,true);_h5Ctrl.dispatchEvent(_h5ev);}}catch(_h5cl){}iloSt.html5LaunchAttempted=true;iloSt.anyLaunchAction=true;iloSt.discTriggered=true;kvmTouchProgress(iloSt);ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);try{var _h5Post=ipmiProxyIloCapturePostLaunchSnapshot();var _h5Diff=ipmiProxyIloDiffLaunchSnapshots(_h5Pre,_h5Post);if(_h5Diff&&_h5Diff.meaningful){iloSt.html5LaunchEffective=true;_kvmDbg("ilo_html5_console_launch_effective",{changed:_h5Diff.changed.join(",")});}else{_kvmDbg("ilo_html5_console_launch_no_effect",{tick:n});}}catch(_h5d){}}}}catch(_h5outer){}}'
        . 'if(_blkPrivilege&&(n%8)===0&&n>8){try{_kvmDbg("ilo_launch_blocked_by_privilege",{tick:n,verdict:iloSt.privilegeVerdict,user:String(iloSt.privilegeUserState||"").substring(0,60)});}catch(_lbp){}}'
        . 'if((rcReady||iloSt.specShell)&&!_blkPrivilege){'
        . 'if(iloSt.phase===0){var directTop=getIloDirectTopRenderer(window);if(directTop&&!_blkShellDup){if(!iloSt.funcFound){iloSt.funcFound=true;iloSt.launchFunctionFound=true;try{_kvmDbg("ilo_launch_function_found",{src:"directTop"});}catch(_ff0){}}_kvmDbg("ilo_direct_renderer_attempt",1);if(callStart(directTop)){started=true;iloSt.anyLaunchAction=true;iloSt.discTriggered=true;iloSt.clicks++;iloSt.phase=1;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_function_invoked","direct");_kvmDbg("ilo_launch_triggered",{how:"callStart_direct",clicks:iloSt.clicks});if(iloSt.specShell)ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(e0){}}}}'
        . 'if(!started&&iloSt.phase<=1&&!_blkShellDup){for(var b=0;b<ctx.length;b++){if(callStart(ctx[b])){started=true;iloSt.anyLaunchAction=true;iloSt.discTriggered=true;iloSt.clicks++;iloSt.phase=2;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_function_invoked","renderer_ctx");_kvmDbg("ilo_launch_triggered",{how:"callStart_ctx",clicks:iloSt.clicks});if(iloSt.specShell)ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(e1){}break;}}}'
        . 'if(!started&&iloSt.phase<=2&&!_blkShellDup){for(var h=0;h<ctx.length;h++){if(callIloStart(ctx[h])){started=true;iloSt.anyLaunchAction=true;iloSt.discTriggered=true;iloSt.clicks++;iloSt.phase=3;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_function_invoked","ilo_start");_kvmDbg("ilo_launch_triggered",{how:"callIloStart",clicks:iloSt.clicks});if(iloSt.specShell)ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(e2){}break;}}}'
        . 'if(!started&&iloSt.phase<=3&&(n%6===0)){iloSt.phaseClickRounds++;if(iloSt.phaseClickRounds<=12){for(var k=0;k<ctx.length;k++){if(clickHtml5Anchor(ctx[k],false)){started=true;iloSt.anyLaunchAction=true;iloSt.clicks++;iloSt.discTriggered=true;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_function_invoked","click");if(iloSt.specShell)ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(e3){}break;}}}}'
        . 'if(!started&&iloSt.phase<=4&&shell&&(n%10===0)&&iloSt.navAttempts<3){iloSt.navAttempts++;if(ensureIloRcPageLoaded(shell)){iloSt.phase=4;iloSt.anyLaunchAction=true;iloSt.discTriggered=true;iloSt.clicks++;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_rc_info_navigation","phase");_kvmDbg("ilo_launch_triggered",{how:"loadContent_rc_info",clicks:iloSt.clicks});if(iloSt.specShell)ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(e4){}}}}'
        . 'if(!rcReady&&iloSt.phase===0&&n<=16&&!_blkShellDup){var dtEarly=getIloDirectTopRenderer(window);if(dtEarly){iloSt.launchFunctionFound=true;_kvmDbg("ilo_direct_renderer_attempt",1);if(callStart(dtEarly)){iloSt.phase=1;iloSt.anyLaunchAction=true;iloSt.discTriggered=true;iloSt.clicks++;kvmTouchProgress(iloSt);try{_kvmDbg("ilo_launch_function_invoked","direct_early");_kvmDbg("ilo_launch_triggered",{how:"callStart_early",clicks:iloSt.clicks});if(iloSt.specShell)ipmiProxyIloArmLaunchOutcomeProbe(iloSt,n,sigEarly,wsEarly,liveEarly);}catch(e5){}}}}'
        . 'var hitMax=(n>=max);'
        . 'if(!iloSt.stall&&(kvmNow()-iloSt.lastProgress)>KVM_TMO){iloSt.stall=true;var _discFail=iloSt.specShell&&!iloSt.reported.trans&&((iloSt.clicks===0&&!iloSt.discNavTriggered&&!iloSt.discTriggered&&!rcPage)||iloSt.launchNoEffectReported||iloSt.whiteStallReported);if(_discFail){iloSt.launchDiscoveryFailed=true;try{_kvmDbg("ilo_no_launch_target_found",{ticks:n,clicks:iloSt.clicks,no_effect:iloSt.launchNoEffectReported?1:0,white_screen:iloSt.whiteStallReported?1:0});_kvmDbg("ilo_launch_discovery_failed",{reason:iloSt.launchNoEffectReported?"stall_after_no_effect":(iloSt.whiteStallReported?"stall_white_screen":"stall_timeout_shell_no_surface")});_kvmDbg("ilo_stalled_before_transport",{discovery:1});_kvmDbg("ilo_console_readiness_reclassified",{to:"launch_discovery_failed"});_kvmDbg("ilo_console_start_failed_no_launch_target",1);}catch(_sfd){}}try{_kvmDbg("ilo_console_stalled",{ticks:n,phase:iloSt.phase,clicks:iloSt.clicks,no_transport:!iloSt.reported.trans,speculative_shell:iloSt.specShell?1:0,launch_discovery_failed:iloSt.launchDiscoveryFailed?1:0});}catch(es){}}'
        . 'if(hitMax&&iloSt.specShell&&!iloSt.reported.trans&&(iloSt.launchNoEffectReported||iloSt.whiteStallReported||(iloSt.clicks===0&&!iloSt.discNavTriggered&&!iloSt.discTriggered&&!rcPage))){iloSt.launchDiscoveryFailed=true;try{_kvmDbg("ilo_no_launch_target_found",{reason:"max_ticks"});_kvmDbg("ilo_launch_discovery_failed",{reason:iloSt.launchNoEffectReported?"max_ticks_no_effect":"max_ticks_no_launch"});if(iloSt.shellEscalationConsumed&&!liveNow&&!wsNow){_kvmDbg("ilo_console_readiness_verdict",{verdict:"console_start_failed_no_transport",discovery:1,shell_escalation:1});}}catch(_mxd){}}'
        . 'var vNext="console_starting";'
        . 'if(iloSt.reported.stuck)vNext="console_stuck_loading";'
        . 'else if(iloSt.reported.fin)vNext="console_interactive_confirmed";'
        . 'else if(iloSt.privilegeBlockFinalized&&!liveNow)vNext="remote_console_privilege_missing";'
        . 'else if(iloSt.privilegeBlockDetected&&!liveNow&&!wsNow&&n>12)vNext="remote_console_privilege_missing";'
        . 'else if(iloSt.launchDiscoveryFailed)vNext="launch_discovery_failed";'
        . 'else if(iloSt.html5LaunchAttempted&&!iloSt.html5LaunchEffective&&!wsNow&&!liveNow&&n>20)vNext="remote_console_launch_attempted_no_effect";'
        . 'else if(iloSt.launchNoEffectReported&&!wsNow&&!liveNow)vNext="launch_action_no_effect";'
        . 'else if(iloSt.whiteStallReported&&!wsNow)vNext="launch_discovery_failed";'
        . 'else if(iloSt.specShell&&iloSt.shellEscalationConsumed&&!wsNow&&!liveNow&&n>28&&mgmtNow)vNext="console_start_failed_no_transport";'
        . 'else if(shellOnlyNow&&!liveNow&&!wsNow&&n>8)vNext="shell_only";'
        . 'else if(iloSt.specShell&&iloSt.discNavTriggered&&!wsNow)vNext="launch_triggered_waiting_transport";'
        . 'else if(iloSt.specShell&&!iloSt.anyLaunchAction&&!wsNow&&!iloSt.launchDiscoveryFailed&&n<6&&!iloSt.discNavTriggered)vNext="shell_autolaunch_allowed";'
        . 'else if(iloSt.specShell&&!iloSt.anyLaunchAction&&n>=6&&!wsNow&&!iloSt.discNavTriggered)vNext="launch_discovery_in_progress";'
        . 'else if(rAny&&!liveNow&&!wsNow&&n>10)vNext="renderer_only";'
        . 'else if(ldNow&&!liveNow&&n>12)vNext="loading_only";'
        . 'else if(rAny&&ldNow&&!wsNow)vNext="console_transport_pending";'
        . 'else if(wsNow&&!iloSt.reported.sessR)vNext="console_transport_pending";'
        . 'else if(iloSt.reported.sessR&&!iloSt.reported.fin)vNext="console_session_ready";'
        . 'else if(rAny&&wsNow)vNext="console_transport_pending";'
        . 'if(vNext==="console_starting"&&iloSt.specShell&&!iloSt.anyLaunchAction&&!wsNow&&!iloSt.launchDiscoveryFailed&&n>4)vNext="launch_discovery_in_progress";'
        . 'iloSt.lastVerdict=vNext;'
        . 'if(iloSt.lastVerdict!==iloSt.prevVerdict){iloSt.prevVerdict=iloSt.lastVerdict;try{var _ltf=(iloSt.anyLaunchAction||rcPage||btnFound||iloSt.launchSurfaceFound)?1:0;var _lat=(iloSt.discTriggered||iloSt.discNavTriggered)?1:0;var _lae=iloSt.launchNoEffectReported?0:1;var _tHint=(wsNow&&liveNow&&!ldNow&&!mgmtNow&&!overviewNow)?"native_console_strongly_confirmed":(routeNow&&!liveNow?"application_loaded_console_not_reached":"native_console_not_confirmed");if(appPathNow&&!liveNow&&overviewNow)_tHint="native_console_route_reached_but_shell_only";else if(appPathNow&&!liveNow&&!overviewNow)_tHint="application_loaded_console_not_reached";if(overviewNow&&!liveNow&&!appPathNow)_tHint="shell_only_management_ui";if(routeNow&&!liveNow&&!mgmtNow)_tHint="native_console_route_reached_not_ready";_kvmDbg("ilo_console_readiness_verdict",{verdict:iloSt.lastVerdict,ws:wsNow?1:0,transport_evidence:wsNow?1:0,transport_started:wsNow?1:0,session_ready:iloSt.reported.sessR?1:0,load:ldNow?1:0,loading_persisted:(ldNow&&ldMs>12000)?1:0,loading_ms:ldNow?ldMs:0,rContainer:rAny?1:0,renderer_container:rAny?1:0,session_ready_evidence:iloSt.reported.sessR?1:0,sess:iloSt.reported.sessR?1:0,speculative_shell:iloSt.specShell?1:0,shell_autolaunch_initial_phase:(iloSt.lastVerdict==="shell_autolaunch_allowed")?1:0,launch_discovery_started:iloSt.discoveryStarted?1:0,launch_surface_found:iloSt.launchSurfaceFound?1:0,launch_target_found:_ltf,launch_action_triggered:_lat,launch_action_effective:_lae,launch_outcome_probe_pending:(iloSt.pendingOutcomeCheck>0)?1:0,launch_discovery:iloSt.discoveryStarted?1:0,any_launch_action:iloSt.anyLaunchAction?1:0,clicks:iloSt.clicks,disc_nav:iloSt.discNavTriggered?1:0,shell_escalation_consumed:iloSt.shellEscalationConsumed?1:0,white_screen_stall:iloSt.whiteStallReported?1:0,final_discovery_verdict:iloSt.lastVerdict,shell_only_ui:shellOnlyNow?1:0,management_shell_visible:mgmtNow?1:0,overview_shell:overviewNow?1:0,application_path_loaded:appPathNow?1:0,application_loaded_shell_only:ipmiProxyIloApplicationLoadedShellOnly(window)?1:0,helper_activity:helperNow?1:0,helper_aided_discovery:iloSt.helperAidedDiscovery?1:0,helper_correlated_with_visible_console:ipmiProxyIloHelperActivityCorrelatesWithConsoleReach(window)?1:0,live_display_evidence:liveNow?1:0,native_route_reached:routeNow?1:0,native_console_tier_hint:_tHint});}catch(ev){}}'
        . 'if(iloSt.stall){return;}'
        . 'if(hitMax){try{_kvmDbg("ilo_console_stalled",{ticks:n,reason:"max_ticks",launch_discovery_failed:iloSt.launchDiscoveryFailed?1:0,no_transport:!iloSt.reported.trans?1:0});if(iloSt.launchDiscoveryFailed){_kvmDbg("ilo_console_readiness_verdict",{verdict:"launch_discovery_failed",reason:"max_ticks",transport_started:wsNow?1:0,launch_target_found:(iloSt.anyLaunchAction||rcPage||btnFound)?1:0,launch_action_triggered:(iloSt.discTriggered||iloSt.discNavTriggered)?1:0});}}catch(em){}return;}'
        . 'setTimeout(tick,250);'
        . '})();'
        . 'return;'
        . '}';
}

function ipmiProxyBuildIdracKvmScript(): string
{
    return 'if(FAMILY==="idrac"){'
        . 'var wantDr=(PLAN&&PLAN.kvm_entry_path)?String(PLAN.kvm_entry_path):"/index.html";'
        . 'var bootDr=(PLAN&&PLAN.console_bootstrap_path)?String(PLAN.console_bootstrap_path):"/viewer.html";'
        . 'var _idrN=0,_idrBooted=false,_idrSt={lastProgress:kvmNow(),clicks:0,navs:0,reported:{boot:false,launch:false,trans:false},stall:false};'
        . '_kvmDbg("idrac_shell_detected",pathLower());'
        . 'kvmTouchProgress(_idrSt);'
        . 'try{'
        . 'if(window.sessionStorage&&!sessionStorage.getItem("_ipmi_idrac_autonav")){'
        . 'sessionStorage.setItem("_ipmi_idrac_autonav","1");'
        . 'var cur=String(location.pathname||"").toLowerCase();'
        . 'if(cur.indexOf("/viewer.html")<0&&cur.indexOf("/console.html")<0&&wantDr){'
        . 'if(wantDr.charAt(0)!=="/")wantDr="/"+wantDr;'
        . 'var curFullDr=location.pathname+(location.search||"");'
        . 'if(wantDr!==curFullDr){_kvmDbg("idrac_console_navigation",wantDr);go(wantDr);}'
        . '}'
        . '}'
        . '}catch(_idr0){}'
        . '(function _idrTick(){_idrN++;'
        . 'try{'
        . 'var _b=String(document.body&&document.body.innerText||"").toLowerCase();'
        . 'if(_b.indexOf("virtual")>=0&&_b.indexOf("console")>=0){kvmTouchProgress(_idrSt);if(!_idrSt.reported.boot){_idrSt.reported.boot=true;_kvmDbg("idrac_viewer_bootstrap_detected",1);}}'
        . 'if(kvmIdracViewerBootstrap()){kvmTouchProgress(_idrSt);}'
        . 'if(kvmIdracTransportLikely()&&!_idrSt.reported.trans){_idrSt.reported.trans=true;kvmTouchProgress(_idrSt);_kvmDbg("idrac_transport_detected",1);}'
        . 'if(kvmIdracInteractiveLikely()){_kvmDbg("idrac_console_interactive_likely",1);markDone();return;}'
        . 'var _L=document.querySelectorAll("a[href],button,[role=button],input[type=button]");'
        . 'for(var _i=0;_i<_L.length;_i++){'
        . 'var _e=_L[_i],_h=String(_e.getAttribute("href")||"").toLowerCase(),_x=String(_e.textContent||"").toLowerCase();'
        . 'if(_h.indexOf("viewer")>=0||_h.indexOf("console")>=0||(_x.indexOf("virtual")>=0&&_x.indexOf("console")>=0)||(_x.indexOf("launch")>=0&&_x.indexOf("console")>=0)||(_x.indexOf("kvm")>=0&&_x.indexOf("launch")>=0)){'
        . 'if(!_idrSt.reported.launch){_idrSt.reported.launch=true;_kvmDbg("idrac_launch_control_found",_h||_x);}'
        . 'if(_idrN%4===0&&_idrSt.clicks<6){_idrSt.clicks++;kvmTouchProgress(_idrSt);try{_e.click();}catch(ec){}}'
        . '}'
        . '}'
        . '}catch(_idr1){}'
        . 'if(!_idrBooted&&_idrN>=26&&bootDr&&pathLower().indexOf("viewer")<0&&pathLower().indexOf("console")<0&&_idrN%12===0){_idrBooted=true;_idrSt.navs++;if(_idrSt.navs<=2){_kvmDbg("idrac_console_navigation",bootDr);try{go(bootDr);return;}catch(eb){}}}'
        . 'if(!_idrSt.stall&&(kvmNow()-_idrSt.lastProgress)>KVM_TMO){_idrSt.stall=true;_kvmDbg("idrac_console_stalled",{ticks:_idrN,clicks:_idrSt.clicks,no_transport:!_idrSt.reported.trans});return;}'
        . 'if(_idrN>=120){_kvmDbg("idrac_console_stalled",{ticks:_idrN,reason:"max_ticks"});return;}'
        . 'setTimeout(_idrTick,380);'
        . '})();'
        . 'return;}';
}

function ipmiProxyBuildSupermicroKvmScript(): string
{
    return 'if(FAMILY==="supermicro"){'
        . 'var wantSm=(PLAN&&PLAN.kvm_entry_path)?String(PLAN.kvm_entry_path):"/cgi/url_redirect.cgi?url_name=ikvm&url_type=html5";'
        . 'var _smN=0,_smSt={lastProgress:kvmNow(),clicks:0,reported:{boot:false,trans:false},stall:false};'
        . 'try{'
        . 'var _smBody=String(document.body&&document.body.innerText||"").toLowerCase();'
        . 'if(_smBody.indexOf("supermicro")>=0||_smBody.indexOf("topmenu")>=0||location.href.indexOf("topmenu")>=0){'
        . 'if(!window.__ipmi_sm_shell_tp){window.__ipmi_sm_shell_tp=1;kvmTouchProgress(_smSt);}'
        . '_kvmDbg("supermicro_shell_detected",1);}'
        . '_kvmDbg("supermicro_html5_route_selected",wantSm);'
        . 'if(window.sessionStorage&&!sessionStorage.getItem("_ipmi_sm_autonav")){'
        . 'sessionStorage.setItem("_ipmi_sm_autonav","1");'
        . 'var _p=String(location.pathname||"").toLowerCase(),_q=String(location.search||"").toLowerCase();'
        . 'if(_p.indexOf("ikvm")<0&&_q.indexOf("ikvm")<0&&wantSm){if(wantSm.charAt(0)!=="/")wantSm="/"+wantSm;'
        . 'var curFullSm=location.pathname+(location.search||"");'
        . 'if(wantSm!==curFullSm){go(wantSm);}'
        . '}'
        . '}'
        . '}catch(_sm0){}'
        . '(function _smTick(){_smN++;'
        . 'try{'
        . 'if(String(location.search||"").toLowerCase().indexOf("html5")>=0||String(location.pathname||"").toLowerCase().indexOf("ikvm")>=0){if(!_smSt.reported.boot){_smSt.reported.boot=true;kvmTouchProgress(_smSt);_kvmDbg("supermicro_bootstrap_detected",1);}}'
        . 'if(kvmWsRelaySeen()&&!_smSt.reported.trans){_smSt.reported.trans=true;kvmTouchProgress(_smSt);_kvmDbg("supermicro_transport_detected",1);}'
        . 'if(kvmSupermicroInteractiveLikely()){_kvmDbg("supermicro_console_interactive_likely",1);markDone();return;}'
        . 'var _L2=document.querySelectorAll("a[href],button,[role=button],input[type=button],area[href]");'
        . 'for(var _j=0;_j<_L2.length;_j++){'
        . 'var _e2=_L2[_j],_h2=String(_e2.getAttribute("href")||"").toLowerCase(),_x2=String(_e2.textContent||"").toLowerCase();'
        . 'if(_h2.indexOf("ikvm")>=0||_h2.indexOf("kvm")>=0||_x2.indexOf("ikvm")>=0||(_x2.indexOf("kvm")>=0&&(_x2.indexOf("launch")>=0||_x2.indexOf("remote")>=0))){'
        . 'if(_smN%5===0&&_smSt.clicks<7){_smSt.clicks++;kvmTouchProgress(_smSt);_kvmDbg("supermicro_click_candidate_found",_h2||_x2);try{_e2.click();}catch(ec2){}}'
        . '}'
        . '}'
        . '}catch(_sm1){}'
        . 'if(!_smSt.stall&&(kvmNow()-_smSt.lastProgress)>KVM_TMO){_smSt.stall=true;_kvmDbg("supermicro_console_stalled",{ticks:_smN,clicks:_smSt.clicks});return;}'
        . 'if(_smN>=110){_kvmDbg("supermicro_console_stalled",{ticks:_smN,reason:"max_ticks"});return;}'
        . 'setTimeout(_smTick,420);'
        . '})();'
        . 'return;}';
}

/**
 * Best-effort brace balance check for generated autolaunch JS (strings/comments aware).
 *
 * @return array{ok: bool, reason: string, depth: int}
 */
function ipmiProxyValidateGeneratedJsBraceBalance(string $js): array
{
    $depth = 0;
    $n = strlen($js);
    $inStr = false;
    $strCh = '';
    $esc = false;
    $inLineComment = false;
    $inBlockComment = false;
    for ($i = 0; $i < $n; $i++) {
        $c = $js[$i];
        $next = ($i + 1 < $n) ? $js[$i + 1] : '';
        if ($inLineComment) {
            if ($c === "\n") {
                $inLineComment = false;
            }
            continue;
        }
        if ($inBlockComment) {
            if ($c === '*' && $next === '/') {
                $inBlockComment = false;
                $i++;
            }
            continue;
        }
        if ($inStr) {
            if ($esc) {
                $esc = false;
                continue;
            }
            if ($c === '\\' && ($strCh === '"' || $strCh === '\'' || $strCh === '`')) {
                $esc = true;
                continue;
            }
            if ($c === $strCh) {
                $inStr = false;
            }
            continue;
        }
        if ($c === '/' && $next === '/') {
            $inLineComment = true;
            $i++;
            continue;
        }
        if ($c === '/' && $next === '*') {
            $inBlockComment = true;
            $i++;
            continue;
        }
        if ($c === '"' || $c === '\'' || $c === '`') {
            $inStr = true;
            $strCh = $c;
            continue;
        }
        if ($c === '{') {
            $depth++;
        } elseif ($c === '}') {
            $depth--;
            if ($depth < 0) {
                return ['ok' => false, 'reason' => 'negative_brace_depth', 'depth' => $depth];
            }
        }
    }
    if ($inStr) {
        return ['ok' => false, 'reason' => 'unterminated_string', 'depth' => $depth];
    }
    if ($inBlockComment) {
        return ['ok' => false, 'reason' => 'unterminated_block_comment', 'depth' => $depth];
    }

    return [
        'ok'     => $depth === 0,
        'reason' => $depth === 0 ? '' : 'unbalanced_braces',
        'depth'  => $depth,
    ];
}

/**
 * @return array{ok: bool, reason: string, depth: int, bytes: int}
 */
function ipmiProxyValidateGeneratedIloJs(string $fullPatchJs): array
{
    $bal = ipmiProxyValidateGeneratedJsBraceBalance($fullPatchJs);
    $out = [
        'ok'     => $bal['ok'],
        'reason' => (string) $bal['reason'],
        'depth'  => (int) $bal['depth'],
        'bytes'  => strlen($fullPatchJs),
    ];
    if ($out['ok'] && stripos($fullPatchJs, 'function tryClickIloDiscoveryLaunch') !== false) {
        if (preg_match('/catch\s*\(\s*_q\s*\)\s*\{\s*\}\s*return""\s*;\s*\}\s*function\s+collectContexts\s*\(/', $fullPatchJs) !== 1) {
            $out['ok'] = false;
            $out['reason'] = 'tryClickIloDiscoveryLaunch_tail_pattern_mismatch';
        }
    }

    return $out;
}

/** @return array{ok: bool, reason: string, depth: int, bytes: int} */
function ipmiProxyValidateGeneratedJs(string $fullPatchJs): array
{
    return ipmiProxyValidateGeneratedIloJs($fullPatchJs);
}

/**
 * Remove proxy token and similar material from generated JS before writing debug artifacts.
 */
function ipmiProxyRedactSensitiveFromGeneratedJs(string $js, string $token): string
{
    if ($token !== '' && preg_match('/^[a-f0-9]{64}$/', $token)) {
        $js = str_replace($token, '<redacted-token>', $js);
    }

    return (string) preg_replace('#/ipmi_proxy\\.php/[a-f0-9]{64}#i', '/ipmi_proxy.php/<redacted-token>', $js);
}

/**
 * When validation fails, persist a redacted excerpt for offline inspection (debug only).
 */
function ipmiProxyDumpInvalidGeneratedJsContext(string $js, string $reason, int $depth, string $token): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    $redacted = ipmiProxyRedactSensitiveFromGeneratedJs($js, $token);
    $hash = substr(sha1($redacted), 0, 8);
    $path = rtrim(sys_get_temp_dir(), '/') . '/ipmi_ilo_runtime_js_invalid_' . gmdate('Ymd_His') . '_' . $hash . '.log';
    $head = substr($redacted, 0, 6000);
    $tail = strlen($redacted) > 12000 ? substr($redacted, -6000) : '';
    $payload = 'reason=' . $reason . "\ndepth=" . (string) $depth . "\nbytes=" . (string) strlen($js) . "\n--- head ---\n"
        . $head . "\n--- tail ---\n" . $tail . "\n";
    if (@file_put_contents($path, $payload) !== false) {
        ipmiProxyDebugLog('ilo_runtime_js_invalid_dump_written', [
            'path'   => $path,
            'reason' => $reason,
            'depth'  => $depth,
        ]);
    }
}

/**
 * Full autolaunch runtime body (preamble + shared helpers + vendor branches + IIFE closer).
 */
function ipmiProxyBuildIloRuntimeJs(string $familyJs, string $planJs, string $pxJs, string $autoJs, string $dbgLit): string
{
    return ipmiProxyBuildKvmAutoLaunchPreambleJs($familyJs, $planJs, $pxJs, $autoJs, $dbgLit)
        . ipmiProxyBuildKvmAutoLaunchIloDomHelpersJs()
        . ipmiProxyBuildKvmRuntimeProgressHelpersJs()
        . ipmiProxyBuildKvmAutoLaunchLaunchGateJs()
        . ipmiProxyBuildIloKvmScript()
        . ipmiProxyBuildIdracKvmScript()
        . ipmiProxyBuildSupermicroKvmScript()
        . '})();';
}

/**
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyIloShellVsConsoleStateLoad(array $session): array
{
    $m = $session['session_meta']['ilo_shell_vs_console'] ?? null;

    return is_array($m) ? $m : [];
}

/**
 * @param array<string, mixed> $state
 */
function ipmiProxyIloShellVsConsoleStateStore(mysqli $mysqli, string $token, array $state): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state = array_slice(array_merge(['v' => 1, 'ts' => time()], $state), 0, 48);
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $meta['ilo_shell_vs_console'] = $state;
    });
}

/**
 * @param array<string, mixed> $session
 * @param array<string, mixed> $browserSnapshot optional fields from client */
function ipmiProxyIloShellVsConsoleVerdict(array $session, array $browserSnapshot = []): string
{
    $a = array_merge(ipmiProxyIloShellVsConsoleStateLoad($session), $browserSnapshot);
    $v = (string) ($a['final_verdict'] ?? '');

    return $v !== '' ? $v : 'unknown';
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloShouldRejectShellOnlyAsStrongConfirmation(array $session, array $browserSnapshot = []): bool
{
    $a = array_merge(ipmiProxyIloShellVsConsoleStateLoad($session), $browserSnapshot);
    if (!empty($a['management_shell_still_visible']) && empty($a['live_console_visible'])) {
        return true;
    }
    if (!empty($a['overview_shell_detected']) && empty($a['live_console_visible'])) {
        return true;
    }
    if (!empty($a['helper_activity']) && empty($a['live_console_visible']) && !empty($a['management_shell_still_visible'])) {
        return true;
    }

    return false;
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloCanStronglyConfirmLiveConsole(array $session, array $browserSnapshot = []): bool
{
    if (ipmiProxyIloShouldRejectShellOnlyAsStrongConfirmation($session, $browserSnapshot)) {
        return false;
    }
    $a = array_merge(ipmiProxyIloShellVsConsoleStateLoad($session), $browserSnapshot);

    return !empty($a['live_console_visible']) && !empty($a['transport_started']);
}

/**
 * Persist a terminal shell-discovery failure into session _m.ilo_launch_discovery (merges with existing state).
 *
 * @param array<string, mixed> $failure keys: reason, detail (optional)
 */
function ipmiProxyIloFinalizeShellDiscoveryFailure(mysqli $mysqli, string $token, array &$session, array $failure, string $traceId = ''): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $reason = substr((string) ($failure['reason'] ?? 'launch_discovery_failed'), 0, 96);
    $ld['final_discovery_verdict'] = $reason;
    $ld['discovery_failed_at'] = time();
    if (isset($failure['detail'])) {
        $ld['discovery_failure_detail'] = substr((string) $failure['detail'], 0, 160);
    }
    ipmiProxyIloLaunchDiscoveryStateStore($mysqli, $token, $session, $ld, $traceId);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_launch_discovery_server_finalized', [
            'verdict' => $reason,
            'detail'  => substr((string) ($failure['detail'] ?? ''), 0, 160),
        ]);
    }
}

/**
 * Combined shell autolaunch discovery readiness (session + optional browser beacon overlay).
 * Distinct from ipmiProxyIloConsoleReadinessVerdict() (startup helper HTTP state).
 *
 * @param array<string, mixed> $session
 * @param array<string, mixed> $browserSnapshot
 */
function ipmiProxyIloLaunchDiscoveryReadinessVerdict(array $session, array $browserSnapshot = []): string
{
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $a = array_merge($ld, $browserSnapshot);
    $v = (string) ($a['final_discovery_verdict'] ?? '');
    if ($v !== '') {
        return $v;
    }
    if (!empty($a['white_screen_stall'])) {
        return 'launch_discovery_failed';
    }
    if (!empty($a['launch_action_no_effect'])) {
        return 'launch_action_no_effect';
    }

    $h = ipmiProxyIloLaunchDiscoveryVerdict($a);
    if ($h !== 'launch_discovery_unknown') {
        return $h;
    }

    return 'launch_discovery_in_progress';
}

/**
 * Classify an iLO HTML document for patch-mode selection.
 *
 * @return string One of: ilo_main_application_page, ilo_shell_page, ilo_helper_page,
 *                ilo_secondary_console_helper_page, ilo_frame_candidate_page, ilo_unknown_html_page.
 */
function ipmiProxyClassifyIloHtmlDocument(string $bmcPath, string $html = ''): string
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (str_contains($p, '/html/application.html')) {
        return 'ilo_main_application_page';
    }
    if (str_contains($p, '/html/rc_info.html') || str_contains($p, '/html/irc.html')) {
        return 'ilo_frame_candidate_page';
    }
    if (str_contains($p, '/html/jnlp_template.html') || str_contains($p, '/html/jnlp')) {
        return 'ilo_secondary_console_helper_page';
    }
    if (str_contains($p, '/html/summary.html') || str_contains($p, '/html/overview')) {
        return 'ilo_helper_page';
    }
    if ($p === '/' || $p === '' || $p === '/index.html' || str_contains($p, '/restgui/')) {
        return 'ilo_shell_page';
    }
    if (str_contains($p, '/html/')) {
        $lc = strtolower($html);
        if (str_contains($lc, 'jnlp') || str_contains($lc, 'launch') || str_contains($lc, 'applet')) {
            return 'ilo_secondary_console_helper_page';
        }
        return 'ilo_helper_page';
    }
    return 'ilo_unknown_html_page';
}

/**
 * Determine the patch mode for a classified iLO HTML document.
 *
 * @return string One of: main_runtime, shell_runtime, helper_runtime_minimal, no_runtime, debug_stub_only.
 */
function ipmiProxyDetermineIloPatchMode(string $pageType, ?array $plan = null): string
{
    $strategy = (string) ($plan['launch_strategy'] ?? '');
    switch ($pageType) {
        case 'ilo_main_application_page':
            return 'main_runtime';
        case 'ilo_shell_page':
            return 'shell_runtime';
        case 'ilo_frame_candidate_page':
            return 'main_runtime';
        case 'ilo_secondary_console_helper_page':
            return 'helper_runtime_minimal';
        case 'ilo_helper_page':
            return 'helper_runtime_minimal';
        case 'ilo_unknown_html_page':
            return 'helper_runtime_minimal';
        default:
            return 'helper_runtime_minimal';
    }
}

function ipmiProxyShouldInjectMainRuntime(string $patchMode): bool
{
    return $patchMode === 'main_runtime' || $patchMode === 'shell_runtime';
}

function ipmiProxyShouldInjectHelperRuntime(string $patchMode): bool
{
    return $patchMode === 'helper_runtime_minimal';
}

function ipmiProxyShouldInjectNoRuntime(string $patchMode): bool
{
    return $patchMode === 'no_runtime';
}

/**
 * Build a tiny helper-safe runtime for secondary/helper iLO pages.
 * Records bounded helper signals but never drives readiness or strong confirmation.
 */
function ipmiProxyBuildIloHelperRuntimeJs(string $pxJs, string $dbgLit): string
{
    return '(function(){'
        . 'var DBG=' . $dbgLit . ';'
        . 'function _kvmDbg(ev,extra){try{if(!DBG)return;if(window.console&&console.info)console.info("[ipmi-kvm]",ev,extra!=null?extra:"");}catch(e){}}'
        . 'try{_kvmDbg("ilo_helper_page_loaded",{path:String(location.pathname||"").toLowerCase()});}catch(e){}'
        . 'try{if(window.sessionStorage&&sessionStorage.getItem("_ipmi_kvm_auto_flow")==="1"){'
        . '_kvmDbg("ilo_helper_activity_seen",{page:String(location.pathname||"").substring(0,120),title:String(document.title||"").substring(0,80)});'
        . '}}catch(e){}'
        . '})();';
}

/**
 * @param array<string, mixed>|string $sessionOrLegacyBmcType Full web session array, or legacy BMC type string (limited plan quality).
 * @param array<string, mixed>|null $injectOut Optional; receives inject outcome: mode full|safe_fallback|skipped_duplicate|helper_minimal, js_ok, js_reason, js_depth.
 */
function ipmiProxyInjectKvmAutoLaunchPatch(string $html, string $token, $sessionOrLegacyBmcType, bool $kvmAutoFlow = false, ?array $launchPlan = null, ?mysqli $persistKvmPlanMysqli = null, ?array &$injectOut = null, string $bmcPath = ''): string
{
    $injectMeta = ['mode' => 'pending', 'js_ok' => null, 'js_reason' => '', 'js_depth' => 0];
    if (stripos($html, 'data-ipmi-proxy-kvm-autolaunch') !== false) {
        $injectMeta = ['mode' => 'skipped_duplicate', 'js_ok' => null, 'js_reason' => '', 'js_depth' => 0];
        if ($injectOut !== null) {
            $injectOut = $injectMeta;
        }

        return $html;
    }
    if (!is_array($sessionOrLegacyBmcType)) {
        $session = [
            'bmc_type'        => (string) $sessionOrLegacyBmcType,
            'ipmi_ip'         => '',
            'bmc_scheme'      => 'https',
            'cookies'         => [],
            'forward_headers' => [],
        ];
    } else {
        $session = $sessionOrLegacyBmcType;
    }
    $plan = $launchPlan ?? ipmiWebResolveKvmLaunchPlan($session, $persistKvmPlanMysqli);
    // Recompute delivery/abandonment against the latest session meta (same request as discovery updates).
    unset($plan['_kvm_delivery_merged_v1']);
    $plan = ipmiWebKvmLaunchPlanMergeDelivery($plan, $session);
    $planSrc = (string) ($plan['debug']['plan_source'] ?? '');
    if (
        ipmiProxyDebugEnabled()
        && ($planSrc === 'cache_hit_db' || $planSrc === 'request_memo_hit' || str_starts_with($planSrc, 'cache_hit'))
    ) {
        ipmiProxyDebugLog('kvm_plan_reused_after_shell_success', [
            'vendor_family'  => (string) ($plan['vendor_family'] ?? ''),
            'launch_strategy' => (string) ($plan['launch_strategy'] ?? ''),
        ]);
    }
    $planLite = [
        'kvm_entry_path' => (string) ($plan['kvm_entry_path'] ?? '/'),
        'fallback_path'  => (string) ($plan['fallback_path'] ?? '/'),
        'mode'           => (string) ($plan['mode'] ?? 'fallback'),
        'launch_strategy' => (string) ($plan['launch_strategy'] ?? ''),
        'shell_entry_path' => (string) ($plan['shell_entry_path'] ?? ''),
        'console_bootstrap_path' => (string) ($plan['console_bootstrap_path'] ?? ''),
        'requires_client_bootstrap' => !empty($plan['requires_client_bootstrap']),
        'console_ready_timeout_ms' => (int) ($plan['console_ready_timeout_ms'] ?? 45000),
        'bootstrap_markers' => is_array($plan['bootstrap_markers'] ?? null) ? $plan['bootstrap_markers'] : [],
        'transport_markers' => is_array($plan['transport_markers'] ?? null) ? $plan['transport_markers'] : [],
        'interactive_success_markers' => is_array($plan['interactive_success_markers'] ?? null) ? $plan['interactive_success_markers'] : [],
        'should_attempt_proxy_autolaunch' => !empty($plan['effective_should_attempt_proxy_autolaunch'])
            ? true
            : (!isset($plan['should_attempt_proxy_autolaunch']) || !empty($plan['should_attempt_proxy_autolaunch'])),
        'ilo_native_console_verdict' => (string) ($plan['ilo_native_console_verdict'] ?? ''),
        'console_capability' => (string) ($plan['console_capability'] ?? ''),
        'native_launch_viable' => !empty($plan['native_launch_viable']),
        'autolaunch_suppression_detail' => (string) ($plan['autolaunch_suppression_detail'] ?? ''),
        'speculative_shell_autolaunch' => ((string) ($plan['launch_strategy'] ?? '')) === 'ilo_speculative_shell_autolaunch',
        'delivery_tier' => (string) ($plan['delivery_tier'] ?? ''),
        'user_facing_kvm_mode' => (string) ($plan['user_facing_kvm_mode'] ?? ''),
        'client_visible_kvm_state' => (string) ($plan['client_visible_kvm_state'] ?? ''),
        'speculative_shell_abandoned' => !empty($plan['speculative_shell_abandoned']) ? 1 : 0,
        'preferred_native_path' => (string) ($plan['preferred_native_path'] ?? ''),
    ];
    $familyJs = json_encode((string) ($plan['vendor_family'] ?? 'generic'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $planJs = json_encode($planLite, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $px = '/ipmi_proxy.php/' . rawurlencode($token);
    $pxJs = json_encode($px, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $autoJs = $kvmAutoFlow ? 'true' : 'false';
    $dbgLit = ipmiProxyDebugEnabled() ? 'true' : 'false';
    if (
        ipmiProxyDebugEnabled()
        && (($plan['vendor_family'] ?? '') === 'ilo')
        && empty($plan['should_attempt_proxy_autolaunch'])
    ) {
        $sup = (string) ($plan['autolaunch_suppression_detail'] ?? '');
        $capDbg = (string) ($plan['console_capability'] ?? '');
        $evt = 'ilo_autolaunch_suppressed';
        $ctx = [
            'verdict'    => (string) ($plan['ilo_native_console_verdict'] ?? ''),
            'capability' => $capDbg,
            'strategy'   => (string) ($plan['launch_strategy'] ?? ''),
            'suppression' => $sup,
        ];
        if ($sup === 'no_launch_surface' || ($sup === '' && str_contains((string) ($plan['ilo_native_console_verdict'] ?? ''), 'not_detected'))) {
            $evt = 'ilo_autolaunch_suppressed_due_to_no_surface';
        } elseif ($sup === 'bounded_launch_budget_exhausted') {
            $evt = 'ilo_autolaunch_suppressed_due_to_budget_exhausted';
        } elseif ($sup === 'hard_blocker_license_or_feature') {
            $evt = 'ilo_autolaunch_suppressed_due_to_hard_blocker';
        } elseif ($sup === 'repeated_transport_or_sse_failure') {
            $evt = 'ilo_autolaunch_suppressed_due_to_repeated_transport_failure';
        } elseif ($sup === 'session_bootstrap_unhealthy') {
            $evt = 'ilo_autolaunch_suppressed_due_to_session_bootstrap_unhealthy';
        } elseif ($sup === 'surface_evidence_below_bounded_threshold') {
            $evt = 'ilo_autolaunch_suppressed_due_to_weak_surface_evidence';
        } elseif ($sup !== '') {
            $evt = 'ilo_autolaunch_suppressed_due_to_capability_gate';
        }
        ipmiProxyDebugLog($evt, $ctx);
        ipmiProxyDebugLog('ilo_native_launch_marked_unavailable_for_session', [
            'verdict' => (string) ($plan['ilo_native_console_verdict'] ?? ''),
            'suppression' => $sup,
        ]);
    }
    // Page-type-aware patch mode selection
    $pageType = ($plan['vendor_family'] ?? '') === 'ilo'
        ? ipmiProxyClassifyIloHtmlDocument($bmcPath, $html)
        : 'ilo_unknown_html_page';
    $patchMode = ($plan['vendor_family'] ?? '') === 'ilo'
        ? ipmiProxyDetermineIloPatchMode($pageType, $plan)
        : 'main_runtime';
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_patch_mode_selected', [
            'page_type' => $pageType,
            'patch_mode' => $patchMode,
            'bmcPath' => $bmcPath,
        ]);
    }

    // Helper pages get only the minimal helper runtime (never the full main runtime)
    if (ipmiProxyShouldInjectHelperRuntime($patchMode)) {
        $helperBody = ipmiProxyBuildIloHelperRuntimeJs($pxJs, $dbgLit);
        $injectMeta = [
            'mode'      => 'helper_minimal',
            'js_ok'     => true,
            'js_reason' => '',
            'js_depth'  => 0,
            'page_type' => $pageType,
            'patch_mode' => $patchMode,
        ];
        $scriptOpen = '<script data-ipmi-proxy-kvm-autolaunch="1" data-ipmi-kvm-js-valid="1" data-ipmi-kvm-patch-mode="helper_minimal">';
        $patch = $scriptOpen . $helperBody . '</script>';
        if ($injectOut !== null) {
            $injectOut = $injectMeta;
        }
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_js_injected', [
                'mode' => 'helper_minimal',
                'page_type' => $pageType,
                'bytes' => strlen($helperBody),
            ]);
        }
        return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
    }

    $autoLaunchBody = ipmiProxyBuildIloRuntimeJs($familyJs, $planJs, $pxJs, $autoJs, $dbgLit);

    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_js_generation_started', [
            'vendor_family' => (string) ($plan['vendor_family'] ?? ''),
            'bytes'         => strlen($autoLaunchBody),
            'page_type'     => $pageType,
            'patch_mode'    => $patchMode,
        ]);
    }
    $jsVal = ipmiProxyValidateGeneratedIloJs($autoLaunchBody);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog($jsVal['ok'] ? 'ilo_runtime_js_generation_validated' : 'ilo_runtime_js_generation_invalid', [
            'ok'     => $jsVal['ok'] ? 1 : 0,
            'reason' => $jsVal['reason'],
            'depth'  => $jsVal['depth'],
            'bytes'  => $jsVal['bytes'],
        ]);
        if ($jsVal['ok']) {
            ipmiProxyDebugLog('ilo_runtime_js_generation_fixed', [
                'inject_builder' => 'for_try_scope_application_shell_v2',
                'bytes'          => $jsVal['bytes'],
            ]);
        }
    }

    if (!$jsVal['ok']) {
        ipmiProxyDumpInvalidGeneratedJsContext($autoLaunchBody, (string) $jsVal['reason'], (int) $jsVal['depth'], $token);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_js_injection_aborted', [
                'reason' => $jsVal['reason'],
                'depth'  => $jsVal['depth'],
                'bytes'  => $jsVal['bytes'],
            ]);
            ipmiProxyDebugLog('ilo_runtime_js_safe_fallback_used', [
                'reason' => $jsVal['reason'],
            ]);
        }
        $injectMeta = [
            'mode'       => 'safe_fallback',
            'js_ok'      => false,
            'js_reason'  => (string) $jsVal['reason'],
            'js_depth'   => (int) $jsVal['depth'],
        ];
        $scriptOpen = '<script data-ipmi-proxy-kvm-autolaunch="1" data-ipmi-kvm-js-valid="0" data-ipmi-kvm-patch-mode="safe_fallback"'
            . (ipmiProxyDebugEnabled()
                ? (' data-ipmi-kvm-js-reason="' . htmlspecialchars((string) $jsVal['reason'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"')
                : '')
            . '>';
        $stubBody = '(function(){try{if(typeof console!=="undefined"&&console.warn)console.warn("ilo_runtime_patch_disabled_due_to_invalid_js");}catch(e){}})();';
        $patch = $scriptOpen . $stubBody . '</script>';

        if ($injectOut !== null) {
            $injectOut = $injectMeta;
        }

        return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
    }

    $injectMeta = [
        'mode'       => 'full',
        'js_ok'      => true,
        'js_reason'  => '',
        'js_depth'   => 0,
        'page_type'  => $pageType,
        'patch_mode' => $patchMode,
    ];
    $scriptOpen = '<script data-ipmi-proxy-kvm-autolaunch="1" data-ipmi-kvm-js-valid="1" data-ipmi-kvm-patch-mode="' . htmlspecialchars($patchMode, ENT_QUOTES, 'UTF-8') . '">';
    $patch = $scriptOpen . $autoLaunchBody . '</script>';
    if ($injectOut !== null) {
        $injectOut = $injectMeta;
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_js_injected', [
            'mode'       => 'full',
            'page_type'  => $pageType,
            'patch_mode' => $patchMode,
            'bytes'      => strlen($autoLaunchBody),
        ]);
    }

    return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
}

/**
 * @param array<string, mixed> $analysis from ipmiWebIloAnalyzeDocumentForLaunchSurface
 */
function ipmiProxyIloHasLaunchSurface(array $analysis): bool
{
    return !empty($analysis['has_launch_surface']);
}

/** @return array<string, mixed> */
function ipmiProxyIloLaunchSurfaceAnalysisFromHtml(string $html): array
{
    return ipmiWebIloAnalyzeDocumentForLaunchSurface($html);
}

/**
 * @param array<string, mixed> $plan  KVM launch plan
 * @param array<string, mixed> $cap   Console capability blob (optional)
 * @param array<string, mixed> $state Bootstrap or session state (optional, unused)
 */
function ipmiProxyIloShouldAttemptAutolaunch(array $plan, array $cap = [], array $state = []): bool
{
    unset($cap, $state);
    if (isset($plan['should_attempt_proxy_autolaunch'])) {
        return !empty($plan['should_attempt_proxy_autolaunch']);
    }

    return !empty($plan['native_launch_viable']);
}

function ipmiProxyIloRecordNativeLaunchFailureReason(mysqli $mysqli, string $token, array &$session, string $reason): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $reason = substr($reason, 0, 160);
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($reason): void {
        $log = is_array($meta['ilo_native_launch_failures'] ?? null) ? $meta['ilo_native_launch_failures'] : ['v' => 1, 'items' => []];
        if ((int) ($log['v'] ?? 0) !== 1) {
            $log = ['v' => 1, 'items' => []];
        }
        $items = is_array($log['items'] ?? null) ? $log['items'] : [];
        $items[] = ['t' => time(), 'r' => $reason];
        $log['items'] = array_slice($items, -8);
        $meta['ilo_native_launch_failures'] = $log;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_native_launch_failures'] = $session['session_meta']['ilo_native_launch_failures'] ?? ['v' => 1, 'items' => []];
}

/**
 * @param array<string, mixed> $plan
 * @param array<string, mixed> $session
 */
function ipmiProxyIloShouldSuppressFurtherAutolaunch(array $plan, array $session): bool
{
    if (empty($plan['should_attempt_proxy_autolaunch'])) {
        return true;
    }
    $fail = is_array($session['session_meta']['ilo_native_launch_failures']['items'] ?? null)
        ? $session['session_meta']['ilo_native_launch_failures']['items'] : [];
    $recent = 0;
    $now = time();
    foreach ($fail as $row) {
        if (is_array($row) && ($now - (int) ($row['t'] ?? 0)) < 600) {
            $recent++;
        }
    }

    return $recent >= 5;
}

/**
 * @param array<string, mixed> $plan
 * @param array<string, mixed> $session
 */
function ipmiProxyShouldAbandonSpeculativeShellLaunch(array $session, array $plan): bool
{
    return function_exists('ipmiWebShouldAbandonIloSpeculativeShellLaunch')
        && ipmiWebShouldAbandonIloSpeculativeShellLaunch($session, $plan);
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyDetermineKvmDeliveryTier(array $plan, array $session = []): string
{
    unset($session);

    return (string) ($plan['delivery_tier'] ?? 'panel_controlled_proxy_session');
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyCanOfferControlledFallback(array $plan): bool
{
    return !empty($plan['fallback_session_available'])
        && (string) ($plan['delivery_tier'] ?? '') !== 'kvm_unavailable';
}

/**
 * @param array<string, mixed> $plan
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyFinalizeKvmDeliveryVerdict(array $plan, array $session): array
{
    unset($plan['_kvm_delivery_merged_v1']);

    return ipmiWebKvmLaunchPlanMergeDelivery($plan, $session);
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyShouldUseNativePreferredPath(array $plan): bool
{
    if ((string) ($plan['vendor_family'] ?? '') !== 'ilo') {
        return true;
    }
    $s = (string) ($plan['launch_strategy'] ?? '');

    return $s === 'ilo_application_force_html5' || $s === 'ilo_application_autolaunch' || $s === 'ilo_irc_bootstrap' || $s === 'ilo_rc_info_first';
}

/**
 * @param array<string, mixed> $confirmation from ipmiWebIloNativeConsoleConfirmation
 */
function ipmiProxyStrongNativeConfirmation(array $confirmation): bool
{
    return (string) ($confirmation['final_debug_verdict'] ?? '') === 'native_console_strongly_confirmed';
}

/**
 * @param array<string, mixed> $confirmation
 */
function ipmiProxyRejectWeakShellEvidence(array $confirmation): bool
{
    return !empty($confirmation['shell_only_signal'])
        && (string) ($confirmation['final_debug_verdict'] ?? '') !== 'native_console_strongly_confirmed';
}

/**
 * @param array<string, mixed> $confirmation
 */
function ipmiProxyLooksLikeLiveServerDisplay(array $confirmation): bool
{
    return !empty($confirmation['live_display_confirmed']);
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloLooksLikeShellOnlyStall(array $session): bool
{
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $fv = strtolower((string) ($ld['final_discovery_verdict'] ?? ''));

    return str_contains($fv, 'shell') || str_contains($fv, 'no_effect') || str_contains($fv, 'no_launch');
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloLooksLikeWhiteScreenStall(array $session): bool
{
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $fv = strtolower((string) ($ld['final_discovery_verdict'] ?? ''));
    $det = strtolower((string) ($ld['discovery_failure_detail'] ?? ''));

    return str_contains($fv, 'white_screen') || str_contains($det, 'white_screen');
}

/**
 * @return array{reason: string, detail: string}
 */
function ipmiProxyFinalizeNativeLaunchFailure(array $session, string $fallbackDetail = ''): array
{
    if (ipmiProxyIloLooksLikeWhiteScreenStall($session)) {
        return ['reason' => 'white_screen_stall', 'detail' => $fallbackDetail];
    }
    if (ipmiProxyIloLooksLikeShellOnlyStall($session)) {
        return ['reason' => 'shell_only_stall', 'detail' => $fallbackDetail];
    }
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $fv = strtolower((string) ($ld['final_discovery_verdict'] ?? ''));
    if (str_contains($fv, 'no_launch') || str_contains($fv, 'no_effect')) {
        return ['reason' => 'no_launch_target_found', 'detail' => $fallbackDetail];
    }
    $conf = ipmiWebIloNativeConsoleConfirmation($session, []);
    if (empty($conf['transport_started']) && !empty($conf['shell_only_signal'])) {
        return ['reason' => 'transport_never_started', 'detail' => $fallbackDetail];
    }
    if (empty($conf['session_ready']) && !empty($conf['shell_only_signal'])) {
        return ['reason' => 'session_never_ready', 'detail' => $fallbackDetail];
    }

    return ['reason' => 'native_route_missing', 'detail' => $fallbackDetail];
}

/**
 * @param array<string, mixed> $plan
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyBuildFallbackSessionPlan(array $plan, array $session): array
{
    unset($session);
    $out = $plan;
    $out['user_facing_kvm_mode'] = 'panel_fallback_console';
    $out['delivery_tier'] = 'panel_controlled_proxy_session';
    $out['client_visible_kvm_state'] = 'panel_fallback_console_available';

    return $out;
}

function ipmiProxyCanUseNoVncFallback(): bool
{
    $p = realpath(__DIR__ . '/novnc/vnc_lite.html');

    return $p !== false && is_file($p);
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyCanUsePanelHostedSessionFallback(array $session): bool
{
    return isset($session['token']) && preg_match('/^[a-f0-9]{64}$/', (string) $session['token']);
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyFallbackSessionUrl(string $token, string $bmcPath, array $plan): string
{
    $fp = ipmiProxyBuildFallbackSessionPlan($plan, []);

    return ipmiWebBuildProxyUrlWithDelivery($token, $bmcPath, $fp);
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyDetermineVendorKvmOptions(array $plan): array
{
    return [
        'vendor_family'        => (string) ($plan['vendor_family'] ?? ''),
        'console_capability'   => (string) ($plan['console_capability'] ?? ''),
        'native_launch_viable' => !empty($plan['native_launch_viable']),
        'launch_strategy'      => (string) ($plan['launch_strategy'] ?? ''),
    ];
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyDetermineFinalUserFacingKvmMode(array $plan): string
{
    return (string) ($plan['user_facing_kvm_mode'] ?? 'panel_fallback_console');
}

/**
 * Non-blocking banner: session is panel-proxied (Tier B) — native console not strongly confirmed yet.
 */
function ipmiProxyInjectKvmPanelControlledBanner(string $html): string
{
    if (stripos($html, 'data-ipmi-proxy-kvm-panel-controlled') !== false) {
        return $html;
    }
    $patch = '<script data-ipmi-proxy-kvm-panel-controlled="1">'
        . '(function(){try{'
        . 'if(!document||!document.body)return;'
        . 'var q=new URLSearchParams(location.search||"");'
        . 'if(q.get("ipmi_kvm_delivery")!=="panel_controlled")return;'
        . 'var existing=document.getElementById("ipmi-kvm-panel-controlled-banner");'
        . 'if(existing)return;'
        . 'var d=document.createElement("div");d.id="ipmi-kvm-panel-controlled-banner";'
        . 'd.style.cssText="position:fixed;z-index:2147483646;left:14px;top:14px;max-width:520px;background:#142a4a;color:#e2f0ff;border:1px solid #3d6aaa;border-radius:10px;padding:10px 14px;font:12px/1.45 Arial,sans-serif;box-shadow:0 6px 18px rgba(0,0,0,.35)";'
        . 'd.textContent="Panel-proxied BMC session: live vendor KVM is still establishing. If the console stalls, use Debug from ipmi_kvm or open with ipmi_kvm_replan=1. Access stays on the panel; BMC credentials are not exposed.";'
        . 'document.body.appendChild(d);'
        . 'setTimeout(function(){try{d.style.opacity="0";setTimeout(function(){if(d&&d.parentNode){d.parentNode.removeChild(d);}},260);}catch(_e){}},14000);'
        . '}catch(e){}})();</script>';

    return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
}

function ipmiProxyInjectKvmUnavailableHint(string $html): string
{
    if (stripos($html, 'data-ipmi-proxy-kvm-unavailable') !== false) {
        return $html;
    }
    $patch = '<script data-ipmi-proxy-kvm-unavailable="1">'
        . '(function(){try{'
        . 'if(!document||!document.body)return;'
        . 'var q=new URLSearchParams(location.search||"");'
        . 'var hasFlag=(q.get("ipmi_kvm_unavailable")==="1");'
        . 'var existing=document.getElementById("ipmi-kvm-unavailable-banner");'
        . 'if(!hasFlag){if(existing&&existing.parentNode){existing.parentNode.removeChild(existing);}return;}'
        . 'if(existing)return;'
        . 'var d=document.createElement("div");d.id="ipmi-kvm-unavailable-banner";'
        . 'd.style.cssText="position:fixed;z-index:2147483647;right:14px;top:14px;max-width:540px;background:#102546;color:#d8e9ff;border:1px solid #2a4a76;border-radius:10px;padding:12px 14px;font:13px/1.45 Arial,sans-serif;box-shadow:0 8px 22px rgba(0,0,0,.35);opacity:1;transition:opacity .22s ease";'
        . 'd.textContent="KVM is currently unavailable in browser-native mode for this server/firmware. You can still use regular IPMI session features from this page.";'
        . 'document.body.appendChild(d);'
        . 'setTimeout(function(){try{d.style.opacity="0";setTimeout(function(){if(d&&d.parentNode){d.parentNode.removeChild(d);}},260);}catch(_e){}},9000);'
        . '}catch(e){}})();</script>';

    return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
}

function ipmiProxyExtractIloAuthToken(array $cookies, array $forwardHeaders): string
{
    $hdr = trim((string)($forwardHeaders['X-Auth-Token'] ?? ''));
    if ($hdr !== '') {
        return $hdr;
    }
    foreach ($cookies as $name => $value) {
        $n = strtolower((string)$name);
        if ($n === 'sessionkey' || $n === 'x-auth-token') {
            $val = trim((string)$value);
            if ($val !== '') {
                return $val;
            }
        }
    }
    return '';
}

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
    $replacement = 'this.sessionKey = options.sessionKey, this.sockaddr = ((self.location && self.location.protocol === "https:") ? "wss://" : "ws://") + ((self.location && self.location.host) ? self.location.host : options.host) + "/ipmi_ws_relay.php?token='
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

    return is_string($updated2) ? $updated2 : $body;
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
        'should_attempt_proxy_autolaunch' => true,
        'kvm_entry_path'                => '/html/application.html',
        'launch_strategy'               => 'ilo_application_force_html5',
    ], $je);
    $pxJs = json_encode('/ipmi_proxy.php/' . str_repeat('a', 64), $je);
    $dbgLit = 'true';
    $segments = [
        'preamble' => ipmiProxyBuildKvmAutoLaunchPreambleJs($familyJs, $planJs, $pxJs, 'false', $dbgLit),
        'ilo_dom'    => ipmiProxyBuildKvmAutoLaunchIloDomHelpersJs(),
        'progress'   => ipmiProxyBuildKvmRuntimeProgressHelpersJs(),
        'launch_gate' => ipmiProxyBuildKvmAutoLaunchLaunchGateJs(),
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

// Default 30s max_execution_time kills mid-response after headers → Chrome ERR_CONNECTION_RESET + "200 (OK)".
// Large BMC assets + URL rewrites can exceed 30s on slow links; SSE uses set_time_limit(0) below.
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

function ipmiProxyIsHealthPollPath(string $bmcPath): bool
{
    $p = strtolower($bmcPath);

    return str_contains($p, '/json/health') || str_contains($p, 'health_summary');
}

function ipmiProxyIsIloRuntimeApiPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }

    return str_starts_with($p, '/json/')
        || str_starts_with($p, '/api/')
        || str_starts_with($p, '/rest/')
        || str_starts_with($p, '/sse/');
}

function ipmiProxyIsIloEventStreamPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));

    return $p !== '' && str_starts_with($p, '/sse/');
}

/**
 * Named HTML fragments (legacy allowlist — broader detection uses heuristics + context).
 */
function ipmiProxyIloRuntimeFragmentPathNamed(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }
    $fragments = [
        '/html/masthead.html',
        '/html/sidebar.html',
        '/html/footer.html',
        '/html/login_message.html',
        '/html/session_timeout.html',
    ];
    if (in_array($p, $fragments, true)) {
        return true;
    }

    return str_contains($p, 'masthead') && str_ends_with($p, '.html');
}

/**
 * Full application / heavy HTML pages — never treat as small bootstrap fragments.
 */
function ipmiProxyIloHtmlFragmentPathStrictExclude(string $pLower): bool
{
    if ($pLower === '' || !str_starts_with($pLower, '/html/') || !str_ends_with($pLower, '.html')) {
        return true;
    }
    $bn = basename($pLower);
    if (preg_match('/^(application|index|login|summary|redirect|health|kvm|console)\\b/i', $bn)) {
        return true;
    }
    if (preg_match('/java_irc|jnlp|rc_info|remote_console|virtual_media|video|license|legal|help(_|\\.|$)|about\\./i', $pLower)) {
        return true;
    }

    return false;
}

/**
 * @param array<string, mixed> $context bootstrap_state?, observed?, shell_ts?, trace?
 * @return array{score: int, reasons: list<string>}
 */
function ipmiProxyIloHtmlFragmentHeuristicScore(string $bmcPath, array $context): array
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $reasons = [];
    $score = 0;
    if ($p === '' || ipmiProxyIloHtmlFragmentPathStrictExclude($p)) {
        return ['score' => 0, 'reasons' => ['excluded_or_invalid']];
    }
    if (!str_starts_with($p, '/html/') || !str_ends_with($p, '.html')) {
        return ['score' => 0, 'reasons' => ['not_html_fragment_path']];
    }
    $bn = basename($p, '.html');
    $score += 22;
    $reasons[] = 'under_html';
    if (strlen($bn) <= 36 && preg_match('/(?:^|_)(?:nav|bar|head|pane|frag|partial|widget|menu|tile|card|drawer|panel|snippet|include|toolbar|breadcrumb|masthead|sidebar|footer|header)(?:_|$)/i', $bn)) {
        $score += 28;
        $reasons[] = 'fragment_like_name';
    } elseif (preg_match('/(?:fragment|partial|widget|snippet|include|masthead|sidebar|navbar|statusbar)/i', $bn)) {
        $score += 24;
        $reasons[] = 'bootstrap_keyword';
    } elseif (strlen($bn) <= 24 && !str_contains($bn, '_') && $bn !== 'page' && $bn !== 'main') {
        $score += 8;
        $reasons[] = 'short_basename';
    }
    $st = is_array($context['bootstrap_state'] ?? null) ? $context['bootstrap_state'] : [];
    $shellTs = (int) ($st['shell_ts'] ?? $context['shell_ts'] ?? 0);
    $now = time();
    if ($shellTs > 0 && $now - $shellTs < 120) {
        $score += 18;
        $reasons[] = 'post_shell_window';
    }
    if (ipmiProxyIloIsWithinBootstrapWindow($st)) {
        $score += 12;
        $reasons[] = 'bootstrap_window';
    }
    $obs = is_array($st['observed'] ?? null) ? $st['observed'] : [];
    $paths = is_array($obs['paths'] ?? null) ? $obs['paths'] : [];
    if (!empty($paths[$p]['promoted'])) {
        $score += 35;
        $reasons[] = 'observed_promoted';
    } elseif (isset($paths[$p]) && (int) ($paths[$p]['hits'] ?? 0) >= 2) {
        $score += 15;
        $reasons[] = 'observed_repeat';
    }
    $phase = (string) ($st['phase'] ?? '');
    if (in_array($phase, ['bootstrapping', 'degraded', 'stalled'], true)) {
        $score += 8;
        $reasons[] = 'phase_not_healthy';
    }

    return ['score' => min(100, $score), 'reasons' => $reasons];
}

/**
 * Reasons that indicate the path shape is fragment-like or session-learned, not merely "any /html/*.html soon after shell".
 *
 * @param list<string> $reasons
 */
function ipmiProxyIloHtmlFragmentHeuristicHasStructuralSignal(array $reasons): bool
{
    static $sig = [
        'fragment_like_name',
        'bootstrap_keyword',
        'short_basename',
        'observed_repeat',
        'observed_promoted',
    ];
    foreach ($reasons as $r) {
        if (in_array($r, $sig, true)) {
            return true;
        }
    }

    return false;
}

function ipmiProxyIloShouldTreatHtmlFragmentAsBootstrapCritical(string $bmcPath, array $context): bool
{
    if (ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)) {
        return true;
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (ipmiProxyIloHtmlFragmentPathStrictExclude($p)) {
        return false;
    }
    $h = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, $context);
    if ($h['score'] < 52) {
        return false;
    }

    return ipmiProxyIloHtmlFragmentHeuristicHasStructuralSignal($h['reasons']);
}

/**
 * Path-only recoverability hint for /html/*.html (no session). Bounded; excludes heavy pages.
 */
function ipmiProxyIloHtmlFragmentRecoverableHeuristic(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (ipmiProxyIloHtmlFragmentPathStrictExclude($p)) {
        return false;
    }
    if (!str_starts_with($p, '/html/') || !str_ends_with($p, '.html')) {
        return false;
    }
    $h = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, []);

    return $h['score'] >= 36;
}

function ipmiProxyIloLooksLikeBootstrapHtmlFragment(string $bmcPath, array $context = []): bool
{
    return ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)
        || ipmiProxyIloShouldTreatHtmlFragmentAsBootstrapCritical($bmcPath, $context);
}

function ipmiProxyIloLooksLikeBootstrapApi(string $bmcPath, array $context = []): bool
{
    unset($context);
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '' || ipmiProxyIsHealthPollPath($bmcPath)) {
        return false;
    }

    return str_starts_with($p, '/json/') || str_starts_with($p, '/api/') || str_starts_with($p, '/rest/');
}

function ipmiProxyIloIsWithinBootstrapWindow(array $state): bool
{
    $shellTs = (int) ($state['shell_ts'] ?? 0);
    if ($shellTs <= 0) {
        return false;
    }
    $age = time() - $shellTs;
    if ($age < 120) {
        return true;
    }
    $phase = (string) ($state['phase'] ?? '');

    return $age < 300 && in_array($phase, ['bootstrapping', 'degraded', 'stalled'], true);
}

/** @param array<string, mixed> $session */
function ipmiProxyIloPathContextFromSession(array $session): array
{
    $state = ipmiProxyIloBootstrapStateLoad($session);

    return [
        'bootstrap_state' => $state,
        'shell_ts'        => (int) ($state['shell_ts'] ?? 0),
    ];
}

/**
 * Cached KVM launch plan from session DB metadata (if present).
 *
 * @return array<string, mixed>
 */
function ipmiProxyIloKvmPlanFromSession(array $session): array
{
    $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $kp = $meta['kvm_plan'] ?? null;

    return is_array($kp) && is_array($kp['plan'] ?? null) ? $kp['plan'] : [];
}

/**
 * Narrow allowlist: HTML routes that are not primary bootstrap fragments but travel with native HTML5 console.
 */
function ipmiProxyIloLooksLikeSecondaryConsoleHelper(string $path): bool
{
    $p = strtolower((string) parse_url($path, PHP_URL_PATH));
    static $helpers = [
        '/html/jnlp_template.html',
    ];

    return in_array($p, $helpers, true);
}

/**
 * Relative weight for secondary-helper health signals (kept small vs masthead/session_info).
 */
function ipmiProxyIloSecondaryHelperWeight(string $path): float
{
    $p = strtolower((string) parse_url($path, PHP_URL_PATH));
    if ($p === '/html/jnlp_template.html') {
        return 0.22;
    }

    return 0.0;
}

/**
 * Inspect KVM plan + bootstrap phase for proven HTML5-native console (strict gate for secondary-helper promotion).
 *
 * @param array<string, mixed> $bootstrapState from ipmiProxyIloBootstrapStateLoad
 * @return array{active: bool, match: string, verdict: string, strategy: string, vendor_family: string, phase: string}
 */
function ipmiProxyIloActiveNativeConsoleContextDetail(array $session, array $bootstrapState = []): array
{
    $plan = ipmiProxyIloKvmPlanFromSession($session);
    $verdict = (string) ($plan['ilo_native_console_verdict'] ?? '');
    $strategy = (string) ($plan['launch_strategy'] ?? '');
    $fam = (string) ($plan['vendor_family'] ?? '');
    $phase = (string) ($bootstrapState['phase'] ?? '');
    $match = '';
    if ($verdict === 'native_html5_available') {
        $match = 'verdict_native_html5_available';
    } elseif ($strategy === 'ilo_application_force_html5') {
        $match = 'strategy_ilo_application_force_html5';
    }
    $active = $match !== '' && $phase !== 'stalled';
    if ($fam !== '' && $fam !== 'ilo') {
        $active = false;
        $match = $match !== '' ? 'blocked_non_ilo_plan_family' : '';
    }

    return [
        'active' => $active,
        'match'          => $match,
        'verdict'        => $verdict,
        'strategy'       => $strategy,
        'vendor_family'  => $fam,
        'phase'          => $phase,
    ];
}

/**
 * True when the session model already shows proven/native HTML5 console intent and bootstrap is not stalled.
 *
 * @param array<string, mixed> $bootstrapState from ipmiProxyIloBootstrapStateLoad
 */
function ipmiProxyIloHasActiveNativeConsoleContext(array $session, array $bootstrapState = []): bool
{
    return ipmiProxyIloActiveNativeConsoleContextDetail($session, $bootstrapState)['active'];
}

/**
 * Gated promotion: known secondary helpers only, and only with active native-console context.
 *
 * @param array<string, mixed> $bootstrapState
 * @param array<string, mixed>|null $plan unused; reserved for callers that already loaded the plan
 */
function ipmiProxyIloShouldPromoteSecondaryConsoleHelper(
    string $bmcPath,
    array $session,
    array $bootstrapState,
    ?array $plan = null
): bool {
    unset($plan);
    if (!ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        return false;
    }
    if (ipmiProxyIloSecondaryHelperWeight($bmcPath) <= 0.0) {
        return false;
    }

    return ipmiProxyIloHasActiveNativeConsoleContext($session, $bootstrapState);
}

/**
 * Increment lightweight secondary-helper counters in the bootstrap window (does not affect phase classification).
 *
 * @param array<string, mixed> $window
 * @return array<string, mixed>
 */
function ipmiProxyIloBootstrapRegisterSecondarySignal(array $window, string $outcome): array
{
    $w = $window;
    if ($outcome === 'ok') {
        $w['sec_helper_ok'] = min(8, (int) ($w['sec_helper_ok'] ?? 0) + 1);
    } elseif (str_starts_with($outcome, 'fail')) {
        $w['sec_helper_fail'] = min(5, (int) ($w['sec_helper_fail'] ?? 0) + 1);
    }

    return $w;
}

/**
 * Default iLO final-stage console readiness bucket (server-side proxy observations only; browser is authoritative for transport).
 *
 * @return array<string, mixed>
 */
function ipmiProxyIloConsoleReadinessDefaults(): array
{
    return [
        'v'                       => 1,
        'updated_ts'              => 0,
        'helper_seen'             => 0,
        'helper_ok'               => 0,
        'helper_fail'             => 0,
        'helper_last_path'        => '',
        'helper_last_outcome'     => '',
        'application_html_ok'     => 0,
        'stuck_escalation_count'  => 0,
        'stuck_escalation_ts'     => 0,
        'proxy_transport_hint'    => 0,
        'proxy_session_hint'      => 0,
    ];
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloConsoleReadinessStateLoad(array $session): array
{
    $raw = $session['session_meta']['ilo_console_readiness'] ?? null;
    if (!is_array($raw) || (int) ($raw['v'] ?? 0) < 1) {
        return ipmiProxyIloConsoleReadinessDefaults();
    }

    return array_merge(ipmiProxyIloConsoleReadinessDefaults(), $raw);
}

function ipmiProxyIloConsoleReadinessStateStore(mysqli $mysqli, string $token, array &$session, array $state, string $traceId): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state['updated_ts'] = time();
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $meta['ilo_console_readiness'] = $state;
        $prevBrowser = is_array($meta['ilo_native_console_confirmation']['browser'] ?? null)
            ? $meta['ilo_native_console_confirmation']['browser'] : [];
        $wrap = ['session_meta' => $meta];
        $newConf = ipmiWebIloNativeConsoleConfirmation($wrap, []);
        if ($prevBrowser !== []) {
            $newConf['browser'] = $prevBrowser;
        }
        $meta['ilo_native_console_confirmation'] = $newConf;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_console_readiness'] = $state;
    $prevBrowserMem = is_array($session['session_meta']['ilo_native_console_confirmation']['browser'] ?? null)
        ? $session['session_meta']['ilo_native_console_confirmation']['browser'] : [];
    $session['session_meta']['ilo_native_console_confirmation'] = ipmiWebIloNativeConsoleConfirmation($session, []);
    if ($prevBrowserMem !== []) {
        $session['session_meta']['ilo_native_console_confirmation']['browser'] = $prevBrowserMem;
    }
    if (ipmiProxyDebugEnabled() && $traceId !== '') {
        $conf = is_array($session['session_meta']['ilo_native_console_confirmation'] ?? null)
            ? $session['session_meta']['ilo_native_console_confirmation'] : [];
        ipmiProxyDebugLog('ilo_console_readiness_server_updated', [
            'trace'                       => $traceId,
            'verdict'                     => ipmiProxyIloConsoleReadinessVerdict($state),
            'native_console_debug_verdict' => (string) ($conf['final_debug_verdict'] ?? ''),
        ]);
    }
}

/**
 * @param array<string, mixed> $event types: startup_helper, application_html
 * @return array<string, mixed>
 */
function ipmiProxyIloConsoleReadinessUpdate(array $state, array $event): array
{
    $s = $state;
    $t = (string) ($event['type'] ?? '');
    if ($t === 'startup_helper') {
        $s['helper_seen'] = (int) ($s['helper_seen'] ?? 0) + 1;
        $s['helper_last_path'] = (string) ($event['path'] ?? '');
        $s['helper_last_outcome'] = (string) ($event['outcome'] ?? '');
        if (!empty($event['ok'])) {
            $s['helper_ok'] = (int) ($s['helper_ok'] ?? 0) + 1;
            $s['proxy_session_hint'] = 1;
        } else {
            $s['helper_fail'] = (int) ($s['helper_fail'] ?? 0) + 1;
        }
    }
    if ($t === 'application_html') {
        $s['application_html_ok'] = !empty($event['ok']) ? 1 : 0;
    }

    return $s;
}

function ipmiProxyIloConsoleReadinessVerdict(array $state): string
{
    $hok = (int) ($state['helper_ok'] ?? 0);
    $hfail = (int) ($state['helper_fail'] ?? 0);
    $seen = (int) ($state['helper_seen'] ?? 0);
    if ($hfail >= 1 && $hok === 0 && $seen >= 1) {
        return 'console_start_failed_no_session_ready';
    }
    if ($hok >= 1) {
        return 'startup_helper_http_ok';
    }

    return 'console_starting';
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloConsoleReadinessDebugSnapshot(array $session): array
{
    $st = ipmiProxyIloConsoleReadinessStateLoad($session);
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $conf = ipmiWebIloNativeConsoleConfirmation($session, []);
    $capSnap = is_array($session['session_meta']['ilo_console_capability']['data'] ?? null)
        ? $session['session_meta']['ilo_console_capability']['data'] : [];

    return [
        'verdict_server'           => ipmiProxyIloFinalizeConsoleStartupStatus($st),
        'helper_seen'            => (int) ($st['helper_seen'] ?? 0),
        'helper_ok'              => (int) ($st['helper_ok'] ?? 0),
        'helper_fail'            => (int) ($st['helper_fail'] ?? 0),
        'helper_last'            => (string) ($st['helper_last_path'] ?? ''),
        'transport_proxy_hint'   => ipmiProxyIloHasTransportEvidence($st) ? 1 : 0,
        'session_ready_proxy_hint' => ipmiProxyIloHasSessionReadyEvidence($st) ? 1 : 0,
        'launch_discovery_verdict' => ipmiProxyIloLaunchDiscoveryVerdict($ld),
        'launch_discovery_readiness' => ipmiProxyIloLaunchDiscoveryReadinessVerdict($session, []),
        'launch_helper_seen'     => (int) ($ld['helper_seen'] ?? 0),
        'launch_helper_ok'       => (int) ($ld['helper_ok'] ?? 0),
        'speculative_shell_hint' => (int) ($ld['speculative_shell_hint'] ?? 0),
        'native_console_tier'    => (string) ($conf['tier'] ?? ''),
        'native_console_debug_verdict' => (string) ($conf['final_debug_verdict'] ?? ''),
        'native_console_confidence' => (int) ($conf['confidence'] ?? 0),
        'capability_server_hint' => (string) ($capSnap['capability'] ?? ''),
        'live_display_note'      => 'browser_authoritative; server snapshot excludes live canvas',
    ];
}

/**
 * Evaluate strict native-console confirmation from a flat signal map (browser overlay and/or server hints).
 *
 * @param array<string, mixed> $signals
 * @return array<string, mixed>
 */
function ipmiProxyIloNativeConsoleConfirmationFromSignals(array $signals): array
{
    return ipmiWebIloNativeConsoleTierEvaluate($signals);
}

/**
 * @param array<string, mixed> $confirmation from ipmiWebIloNativeConsoleTierEvaluate / ipmiProxyIloNativeConsoleConfirmationFromSignals
 */
function ipmiProxyIloNativeConsoleVerdict(array $confirmation): string
{
    return (string) ($confirmation['final_debug_verdict'] ?? 'native_console_not_confirmed');
}

/**
 * @param array<string, mixed> $readiness ipmi_console_readiness state
 * @param array<string, mixed> $discovery ilo_launch_discovery state
 * @return array<string, mixed>
 */
function ipmiProxyIloFinalizeConfirmationFromReadiness(array $readiness, array $discovery): array
{
    $signals = [
        'transport_started_server'   => !empty($readiness['proxy_transport_hint']),
        'session_ready_server'       => ((int) ($readiness['helper_ok'] ?? 0) >= 1) || !empty($readiness['proxy_session_hint']),
        'launch_path_reached_server' => (int) ($readiness['application_html_ok'] ?? 0) >= 1,
        'bootstrap_helper_ok'        => ((int) ($readiness['helper_ok'] ?? 0) >= 1),
        'launch_action_triggered'    => ((int) ($discovery['launch_discovery_esc'] ?? 0) >= 1)
            || !empty($discovery['helper_seen']),
    ];

    return ipmiWebIloNativeConsoleTierEvaluate($signals);
}

/**
 * @param array<string, mixed> $confirmation
 */
function ipmiProxyIloCanUpgradeToStrongConfirmation(array $confirmation): bool
{
    $final = (string) ($confirmation['final_debug_verdict'] ?? '');

    return $final === 'native_console_strongly_confirmed';
}

/**
 * Read capability blob only (feature existence — not per-attempt confirmation).
 *
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyIloCapabilityStateLoad(array $session): array
{
    $raw = $session['session_meta']['ilo_console_capability'] ?? null;
    if (!is_array($raw)) {
        return ['v' => 0, 'data' => []];
    }

    return $raw;
}

/**
 * @param array<string, mixed> $session
 * @param array<string, mixed> $capState ilo_console_capability wrapper
 */
function ipmiProxyIloCapabilityStateStore(mysqli $mysqli, string $token, array &$session, array $capState): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($capState): void {
        $meta['ilo_console_capability'] = $capState;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_console_capability'] = $capState;
}

/**
 * Persist strict confirmation snapshot (does not replace capability state).
 *
 * @param array<string, mixed> $confirmation full tier array
 */
function ipmiProxyIloConfirmationStateStore(mysqli $mysqli, string $token, array &$session, array $confirmation): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $confirmation['updated_ts'] = time();
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($confirmation): void {
        $meta['ilo_native_console_confirmation'] = $confirmation;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_native_console_confirmation'] = $confirmation;
}

/** Thin alias for ipmiProxyIloConsoleReadinessStateStore (readiness separate from capability/confirmation). */
function ipmiProxyIloReadinessStateStore(mysqli $mysqli, string $token, array &$session, array $state, string $traceId): void
{
    ipmiProxyIloConsoleReadinessStateStore($mysqli, $token, $session, $state, $traceId);
}

function ipmiProxyIloShouldRejectShellAsConsoleSuccess(string $bmcPath, array $confirmation): bool
{
    if (!ipmiWebIloLooksLikeManagementShellPath($bmcPath)) {
        return false;
    }

    return ($confirmation['final_debug_verdict'] ?? '') !== 'native_console_strongly_confirmed';
}

/**
 * Server cannot see the BMC framebuffer; use browser-reported signals when available.
 *
 * @param array<string, mixed> $browserSignals
 */
function ipmiProxyIloLooksLikeLiveConsoleSurface(array $browserSignals): bool
{
    return !empty($browserSignals['live_display']) || !empty($browserSignals['live_display_confirmed']);
}

function ipmiProxyIloConsoleStartupRequestRole(string $bmcPath): string
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '/html/jnlp_template.html') {
        return 'console_startup_helper';
    }

    return 'other';
}

/**
 * Server-side hints only (browser WebSocket / canvas signals are authoritative).
 *
 * @param array<string, mixed> $readinessState
 */
function ipmiProxyIloHasTransportEvidence(array $readinessState): bool
{
    return !empty($readinessState['proxy_transport_hint']);
}

/**
 * @param array<string, mixed> $readinessState
 */
function ipmiProxyIloHasSessionReadyEvidence(array $readinessState): bool
{
    return (int) ($readinessState['helper_ok'] ?? 0) >= 1
        || !empty($readinessState['proxy_session_hint']);
}

function ipmiProxyIloFinalizeConsoleStartupStatus(array $state): string
{
    return ipmiProxyIloConsoleReadinessVerdict($state);
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloRegisterConsoleStartupSignal(array $state, string $bmcPath, bool $ok, string $outcome): array
{
    if (ipmiProxyIloConsoleStartupRequestRole($bmcPath) !== 'console_startup_helper') {
        return $state;
    }

    return ipmiProxyIloConsoleReadinessUpdate($state, [
        'type'    => 'startup_helper',
        'path'    => $bmcPath,
        'ok'      => $ok,
        'outcome' => $outcome,
    ]);
}

/** @param array<string, mixed> $browserReport */
function ipmiProxyIloLoadingStateDetected(array $browserReport): bool
{
    return !empty($browserReport['loading_text'])
        || !empty($browserReport['loading_spinner'])
        || !empty($browserReport['loading_dom']);
}

function ipmiProxyIloLoadingStateTooLong(int $sinceMs, int $thresholdMs = 12000): bool
{
    return $sinceMs >= $thresholdMs;
}

/**
 * @param array<string, mixed> $readinessState
 */
function ipmiProxyIloShouldEscalateStuckLoading(array $readinessState, bool $rendererSeen, bool $transportSeen, int $loadingMs): bool
{
    return $rendererSeen
        && !$transportSeen
        && $loadingMs >= 28000
        && ipmiProxyIloCanEscalateStuckLoading($readinessState);
}

/**
 * @param array<string, mixed> $readinessState
 */
function ipmiProxyIloCanEscalateStuckLoading(array $readinessState): bool
{
    return (int) ($readinessState['stuck_escalation_count'] ?? 0) < 1;
}

/**
 * @param array<string, mixed> $readinessState
 * @return array<string, mixed>
 */
function ipmiProxyIloEscalateStuckLoadingOnce(array $readinessState): array
{
    if (!ipmiProxyIloCanEscalateStuckLoading($readinessState)) {
        return $readinessState;
    }
    $readinessState['stuck_escalation_count'] = 1;
    $readinessState['stuck_escalation_ts'] = time();

    return $readinessState;
}

/**
 * @param array<string, mixed> $readinessState
 * @return array<string, mixed>
 */
function ipmiProxyIloRecordStuckLoadingEscalation(array $readinessState): array
{
    return ipmiProxyIloEscalateStuckLoadingOnce($readinessState);
}

/**
 * Shell→console launch discovery (server-side correlation; browser events are authoritative).
 *
 * @return array<string, mixed>
 */
function ipmiProxyIloLaunchDiscoveryDefaults(): array
{
    return [
        'v' => 1,
        'updated_ts'                => 0,
        'helper_seen'               => 0,
        'helper_ok'                 => 0,
        'helper_fail'               => 0,
        'helper_last_path'          => '',
        'launch_discovery_esc'      => 0,
        'speculative_shell_hint'    => 0,
        'final_discovery_verdict'   => '',
        'discovery_failed_at'       => 0,
        'discovery_failure_detail'  => '',
    ];
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloLaunchDiscoveryStateLoad(array $session): array
{
    $raw = $session['session_meta']['ilo_launch_discovery'] ?? null;
    if (!is_array($raw) || (int) ($raw['v'] ?? 0) < 1) {
        return ipmiProxyIloLaunchDiscoveryDefaults();
    }

    return array_merge(ipmiProxyIloLaunchDiscoveryDefaults(), $raw);
}

function ipmiProxyIloLaunchDiscoveryStateStore(mysqli $mysqli, string $token, array &$session, array $state, string $traceId): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state['updated_ts'] = time();
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $meta['ilo_launch_discovery'] = $state;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_launch_discovery'] = $state;
    if (ipmiProxyDebugEnabled() && $traceId !== '') {
        ipmiProxyDebugLog('ilo_launch_discovery_server_updated', [
            'trace'   => $traceId,
            'verdict' => ipmiProxyIloLaunchDiscoveryVerdict($state),
        ]);
    }
}

/**
 * @param array<string, mixed> $event
 * @return array<string, mixed>
 */
function ipmiProxyIloLaunchDiscoveryUpdate(array $state, array $event): array
{
    $s = $state;
    $t = (string) ($event['type'] ?? '');
    if ($t === 'launch_helper') {
        $s['helper_seen'] = (int) ($s['helper_seen'] ?? 0) + 1;
        $s['helper_last_path'] = (string) ($event['path'] ?? '');
        if (!empty($event['ok'])) {
            $s['helper_ok'] = (int) ($s['helper_ok'] ?? 0) + 1;
        } else {
            $s['helper_fail'] = (int) ($s['helper_fail'] ?? 0) + 1;
        }
    }

    return $s;
}

function ipmiProxyIloLaunchDiscoveryVerdict(array $state): string
{
    $fv = (string) ($state['final_discovery_verdict'] ?? '');
    if ($fv !== '') {
        return $fv;
    }
    $seen = (int) ($state['helper_seen'] ?? 0);
    $ok = (int) ($state['helper_ok'] ?? 0);
    $fail = (int) ($state['helper_fail'] ?? 0);
    if ($seen >= 1 && $ok === 0 && $fail >= 1) {
        return 'launch_helper_seen_but_no_http_ok';
    }
    if ($ok >= 1) {
        return 'launch_helper_http_observed';
    }

    return 'launch_discovery_unknown';
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloRegisterLaunchHelperSignal(array $state, string $bmcPath, bool $ok, string $outcome): array
{
    if (!ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        return $state;
    }

    return ipmiProxyIloLaunchDiscoveryUpdate($state, [
        'type'    => 'launch_helper',
        'path'    => $bmcPath,
        'ok'      => $ok,
        'outcome' => $outcome,
    ]);
}

function ipmiProxyIloNoLaunchTargetFound(array $browserHints): bool
{
    return !empty($browserHints['launch_discovery_failed']) || !empty($browserHints['no_launch_target']);
}

function ipmiProxyIloFinalizeDiscoveryFailure(string $reason, array $browserHints = []): array
{
    return [
        'verdict'       => 'launch_discovery_failed',
        'reason'        => $reason,
        'browser_hints' => $browserHints,
    ];
}

function ipmiProxyIloCanEscalateLaunchDiscovery(array $state): bool
{
    return (int) ($state['launch_discovery_esc'] ?? 0) < 1;
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloEscalateLaunchDiscoveryOnce(array $state): array
{
    if (!ipmiProxyIloCanEscalateLaunchDiscovery($state)) {
        return $state;
    }
    $state['launch_discovery_esc'] = 1;

    return $state;
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloRecordLaunchDiscoveryEscalation(array $state): array
{
    return ipmiProxyIloEscalateLaunchDiscoveryOnce($state);
}

function ipmiProxyIloHelperPathAidedLaunchDiscovery(array $session): bool
{
    $s = ipmiProxyIloLaunchDiscoveryStateLoad($session);

    return (int) ($s['helper_ok'] ?? 0) >= 1;
}

/**
 * @param array<string, mixed> $readiness
 * @param array<string, mixed> $discovery
 */
function ipmiProxyIloFinalizeReadinessFromDiscovery(array $readiness, array $discovery): string
{
    $d = ipmiProxyIloLaunchDiscoveryVerdict($discovery);
    if ($d === 'launch_helper_seen_but_no_http_ok') {
        return 'launch_helper_seen_but_no_target_found';
    }
    if ($d === 'launch_helper_http_observed') {
        return 'launch_helper_aided_pending_browser';
    }

    return ipmiProxyIloConsoleReadinessVerdict($readiness);
}

/**
 * Promote a narrow set of transport-shaped /html routes when native HTML5 is already proven — not bootstrap-critical.
 *
 * @param array<string, mixed> $final role row from ipmiProxyClassifyIloPathRole + contextualize
 * @param array<string, mixed> $bootstrapState
 * @return array<string, mixed>
 */
function ipmiProxyIloApplySecondaryConsoleHelperPathRole(
    array $final,
    string $bmcPath,
    array $session,
    array $bootstrapState,
    string $traceId
): array {
    $baseRole = (string) ($final['base_role'] ?? '');
    $curRole = (string) ($final['role'] ?? '');
    if ($curRole !== 'transport_related' || $baseRole !== 'transport_related') {
        return $final;
    }
    if (!ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        return $final;
    }

    $ctxDetail = ipmiProxyIloActiveNativeConsoleContextDetail($session, $bootstrapState);
    $ctxActive = $ctxDetail['active'];
    if (ipmiProxyDebugEnabled() && $traceId !== '') {
        ipmiProxyDebugLog('ilo_secondary_helper_context_check', [
            'trace'          => $traceId,
            'bmcPath'        => $bmcPath,
            'context_active' => $ctxActive ? 1 : 0,
            'ctx_match'      => (string) ($ctxDetail['match'] ?? ''),
            'verdict'        => (string) ($ctxDetail['verdict'] ?? ''),
            'strategy'       => (string) ($ctxDetail['strategy'] ?? ''),
            'vendor_family'  => (string) ($ctxDetail['vendor_family'] ?? ''),
            'phase'          => (string) ($ctxDetail['phase'] ?? ''),
        ]);
    }

    if (!$ctxActive) {
        if (ipmiProxyDebugEnabled() && $traceId !== '') {
            $skipReason = 'native_console_context_not_active';
            if ((string) ($ctxDetail['match'] ?? '') === 'blocked_non_ilo_plan_family') {
                $skipReason = 'plan_vendor_family_not_ilo';
            } elseif ((string) ($ctxDetail['phase'] ?? '') === 'stalled') {
                $skipReason = 'bootstrap_phase_stalled';
            } elseif ($ctxDetail['match'] === '' && ipmiProxyIloKvmPlanFromSession($session) === []) {
                $skipReason = 'kvm_plan_missing_in_session';
            } elseif ($ctxDetail['match'] === '') {
                $skipReason = 'no_verdict_or_force_html5_strategy';
            }
            ipmiProxyDebugLog('ilo_secondary_helper_promotion_skipped', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
                'reason'  => $skipReason,
            ]);
        }

        return $final;
    }

    $w = ipmiProxyIloSecondaryHelperWeight($bmcPath);
    if ($w <= 0.0) {
        if (ipmiProxyDebugEnabled() && $traceId !== '') {
            ipmiProxyDebugLog('ilo_secondary_helper_guardrail_applied', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
                'reason'  => 'zero_weight',
            ]);
        }

        return $final;
    }

    $out = $final;
    $out['role'] = 'secondary_console_helper';
    $out['bootstrap_critical'] = false;
    $out['recoverable'] = false;
    $out['debug_class'] = 'secondary_native_console_helper';
    $out['flags'] = is_array($out['flags'] ?? null) ? $out['flags'] : [];
    $out['flags']['secondary_native_console_helper'] = true;
    $out['flags']['legacy_named_helper_in_html5_flow'] = true;
    $out['secondary_helper_weight'] = $w;

    if (ipmiProxyDebugEnabled() && $traceId !== '') {
        ipmiProxyDebugLog('ilo_secondary_helper_context_active', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
        ]);
        ipmiProxyDebugLog('ilo_secondary_console_helper_detected', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
            'weight'  => $w,
        ]);
        if (strtolower((string) parse_url($bmcPath, PHP_URL_PATH)) === '/html/jnlp_template.html') {
            ipmiProxyDebugLog('ilo_jnlp_template_promoted', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
            ]);
        }
        ipmiProxyDebugLog('ilo_secondary_helper_role_finalized', [
            'trace'            => $traceId,
            'bmcPath'          => $bmcPath,
            'from_base'        => $baseRole,
            'final_role'       => $out['role'],
            'weight'           => $w,
            'promotion_reason' => 'active_native_console_context',
            'ctx_match'        => (string) ($ctxDetail['match'] ?? ''),
        ]);
    }

    return $out;
}

/**
 * @param array<string, mixed> $baseRole from ipmiProxyClassifyIloPathRole inner
 * @param array<string, mixed> $state
 * @param array<string, mixed> $requestContext path, heuristic breakdown, trace
 * @return array<string, mixed>
 */
function ipmiProxyIloContextualizePathRole(array $baseRole, array $state, array $requestContext): array
{
    $out = $baseRole;
    $out['base_role'] = (string) ($baseRole['role'] ?? '');
    $out['flags'] = is_array($baseRole['flags'] ?? null) ? $baseRole['flags'] : [];
    $out['flags']['context_elevated'] = false;
    $bmcPath = (string) ($requestContext['bmcPath'] ?? '');
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $trace = (string) ($requestContext['trace'] ?? '');
    if (($baseRole['role'] ?? '') !== 'transport_related' || !str_starts_with($p, '/html/') || !str_ends_with($p, '.html')) {
        return $out;
    }
    $ctx = [
        'bootstrap_state' => $state,
        'shell_ts'        => (int) ($state['shell_ts'] ?? 0),
    ];
    $h = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, $ctx);
    $out['heuristic_score'] = $h['score'];
    $out['heuristic_reasons'] = $h['reasons'];
    $promoted = false;
    $obs = is_array($state['observed'] ?? null) ? $state['observed'] : [];
    $paths = is_array($obs['paths'] ?? null) ? $obs['paths'] : [];
    if (!empty($paths[$p]['promoted'])) {
        $promoted = true;
    }
    $structural = ipmiProxyIloHtmlFragmentHeuristicHasStructuralSignal($h['reasons']);
    $elevate = $promoted
        || ($structural && ($h['score'] >= 52 || ($h['score'] >= 44 && ipmiProxyIloIsWithinBootstrapWindow($state))));
    if (!$elevate) {
        if (ipmiProxyDebugEnabled() && $trace !== '') {
            ipmiProxyDebugLog('ilo_html_fragment_heuristic_negative', [
                'trace'   => $trace,
                'bmcPath' => $bmcPath,
                'score'   => $h['score'],
            ]);
            ipmiProxyDebugLog('ilo_path_role_not_elevated_after_context_check', [
                'trace'   => $trace,
                'bmcPath' => $bmcPath,
                'score'   => $h['score'],
            ]);
        }

        return $out;
    }
    $out['role'] = $h['score'] >= 58 || $promoted ? 'bootstrap_critical' : 'runtime_fragment';
    $out['bootstrap_critical'] = true;
    $out['recoverable'] = true;
    $out['debug_class'] = 'helper_fragment';
    $out['flags']['html_heuristic'] = true;
    $out['flags']['context_elevated'] = true;
    if ($promoted) {
        $out['flags']['promoted_observed'] = true;
    }
    if (ipmiProxyDebugEnabled() && $trace !== '') {
        ipmiProxyDebugLog('ilo_html_fragment_heuristic_positive', [
            'trace'   => $trace,
            'bmcPath' => $bmcPath,
            'score'   => $h['score'],
            'reasons' => $h['reasons'],
        ]);
        ipmiProxyDebugLog('ilo_path_role_elevated_by_context', [
            'trace' => $trace,
            'bmcPath'  => $bmcPath,
            'score'    => $h['score'],
            'promoted' => $promoted ? 1 : 0,
            'role'     => $out['role'],
        ]);
        ipmiProxyDebugLog('ilo_bootstrap_html_fragment_detected', [
            'trace'   => $trace,
            'bmcPath' => $bmcPath,
            'score'   => $h['score'],
        ]);
        if ($out['role'] === 'bootstrap_critical') {
            ipmiProxyDebugLog('ilo_html_fragment_promoted_to_bootstrap_critical', [
                'trace'   => $trace,
                'bmcPath' => $bmcPath,
                'via'     => $promoted ? 'observed' : 'heuristic',
            ]);
        }
    }

    return $out;
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloObservedPathsNormalize(array $obs, int $now = 0): array
{
    if (!is_array($obs) || (int) ($obs['v'] ?? 0) !== 1) {
        return ['v' => 1, 'paths' => []];
    }
    if ($now <= 0) {
        $now = time();
    }
    $paths = is_array($obs['paths'] ?? null) ? $obs['paths'] : [];
    foreach ($paths as $k => $row) {
        if (!is_array($row)) {
            unset($paths[$k]);
            continue;
        }
        if ($now - (int) ($row['last'] ?? 0) > 600) {
            unset($paths[$k]);
        }
    }
    if (count($paths) > 12) {
        $paths = array_slice($paths, -12, 12, true);
    }

    return ['v' => 1, 'paths' => $paths];
}

/**
 * @param array<string, mixed> $state
 * @return array<string, mixed>
 */
function ipmiProxyIloRecordObservedBootstrapPath(array $state, string $pathKey, bool $wasCritical, bool $outcomeOk): array
{
    $now = time();
    $state['observed'] = ipmiProxyIloObservedPathsNormalize($state['observed'] ?? [], $now);
    $paths = &$state['observed']['paths'];
    if (!isset($paths[$pathKey])) {
        $paths[$pathKey] = ['first' => $now, 'hits' => 0, 'promoted' => 0, 'last' => $now, 'ok' => 0, 'fail' => 0];
    }
    $paths[$pathKey]['hits'] = (int) ($paths[$pathKey]['hits'] ?? 0) + 1;
    $paths[$pathKey]['last'] = $now;
    if ($outcomeOk) {
        $paths[$pathKey]['ok'] = (int) ($paths[$pathKey]['ok'] ?? 0) + 1;
    } else {
        $paths[$pathKey]['fail'] = (int) ($paths[$pathKey]['fail'] ?? 0) + 1;
    }
    if ($wasCritical && (int) $paths[$pathKey]['hits'] >= 2 && ipmiProxyIloIsWithinBootstrapWindow($state)) {
        if (empty($paths[$pathKey]['promoted'])) {
            $promoCount = 0;
            foreach ($paths as $row) {
                if (is_array($row) && !empty($row['promoted'])) {
                    $promoCount++;
                }
            }
            if ($promoCount >= 8) {
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_observed_path_promotion_skipped', [
                        'path' => $pathKey,
                        'reason' => 'max_promoted_paths',
                    ]);
                    ipmiProxyDebugLog('ilo_bootstrap_recovery_guardrail_applied', [
                        'rule' => 'observed_promotion_cap',
                    ]);
                }
            } else {
                $paths[$pathKey]['promoted'] = 1;
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_observed_path_promoted', ['path' => $pathKey, 'hits' => (int) $paths[$pathKey]['hits']]);
                    ipmiProxyDebugLog('ilo_path_promoted_by_observation', ['path' => $pathKey]);
                }
            }
        }
    }
    foreach ($paths as $k => $row) {
        if (!is_array($row)) {
            unset($paths[$k]);
            continue;
        }
        if ($now - (int) ($row['last'] ?? 0) > 600) {
            unset($paths[$k]);
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_observed_path_expired', ['path' => $k]);
            }
        }
    }
    if (count($paths) > 12) {
        $paths = array_slice($paths, -12, 12, true);
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_observed_path_recorded', [
            'path'    => $pathKey,
            'critical' => $wasCritical ? 1 : 0,
            'ok'      => $outcomeOk ? 1 : 0,
        ]);
    }

    return $state;
}

/**
 * Small HTML fragments the iLO SPA loads during bootstrap (not full application pages).
 * With optional $context (bootstrap_state), includes heuristic/promoted HTML helpers.
 */
function ipmiProxyIsIloRuntimeFragmentPath(string $bmcPath, array $context = []): bool
{
    if (ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)) {
        return true;
    }
    if ($context !== [] && ipmiProxyIloShouldTreatHtmlFragmentAsBootstrapCritical($bmcPath, $context)) {
        return true;
    }

    return false;
}

/**
 * Use for semantic HTML checks when session context is unavailable (path-only heuristic).
 */
function ipmiProxyIloIsHtmlFragmentForSemanticCheck(string $bmcPath): bool
{
    if (ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)) {
        return true;
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (ipmiProxyIloHtmlFragmentPathStrictExclude($p)) {
        return false;
    }

    return str_starts_with($p, '/html/') && str_ends_with($p, '.html')
        && ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, [])['score'] >= 40;
}

function ipmiProxyIsIloBootstrapPath(string $bmcPath): bool
{
    return ipmiProxyIsIloRuntimeApiPath($bmcPath) || ipmiProxyIsIloRuntimeFragmentPath($bmcPath);
}

/**
 * Paths where a failed transport or 401/403/502 likely indicates stale iLO session — safe to try one auth refresh + retry.
 */
function ipmiProxyIsIloRecoverableRuntimePath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }
    if (
        str_starts_with($p, '/json/')
        || str_starts_with($p, '/sse/')
        || str_starts_with($p, '/api/')
        || str_starts_with($p, '/rest/')
    ) {
        return true;
    }

    return ipmiProxyIsIloRuntimeFragmentPath($bmcPath)
        || ipmiProxyIloHtmlFragmentRecoverableHeuristic($bmcPath);
}

function ipmiProxyIsIloSpaShellEntryPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));

    return in_array($p, ['/index.html', '/html/application.html', '/html/index.html'], true);
}

/**
 * Authoritative iLO path roles for bootstrap / recovery / debug (normalized iLO only at call sites).
 *
 * $context may include bootstrap_state, shell_ts, trace (for debug), accept_header (reserved).
 * Narrow "secondary_console_helper" roles (legacy-named helpers during proven HTML5 flow) are applied
 * only in ipmiProxyClassifyIloPathRoleForSession via ipmiProxyIloApplySecondaryConsoleHelperPathRole.
 *
 * @param array<string, mixed> $context
 * @return array<string, mixed>
 */
function ipmiProxyClassifyIloPathRole(string $bmcPath, string $method = 'GET', array $context = []): array
{
    unset($method);
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $pathKey = $p !== '' ? $p : '/';
    $trace = (string) ($context['trace'] ?? '');
    $fragCtx = $context;
    if (isset($context['bootstrap_state']) && is_array($context['bootstrap_state'])) {
        $fragCtx = array_merge($context, [
            'bootstrap_state' => $context['bootstrap_state'],
            'shell_ts'        => (int) ($context['bootstrap_state']['shell_ts'] ?? 0),
        ]);
    }
    $base = [
        'role'               => 'noncritical',
        'bootstrap_critical' => false,
        'recoverable'        => false,
        'debug_class'        => 'other',
        'path_key'           => $pathKey,
        'flags'              => [
            'html_heuristic'     => false,
            'promoted_observed'  => false,
            'context_elevated'   => false,
            'api_bootstrap'      => false,
        ],
        'heuristic_score'      => 0,
        'heuristic_reasons'  => [],
        'base_role'          => 'noncritical',
    ];
    if ($p === '') {
        return $base;
    }
    if (ipmiProxyIsBmcStaticAssetPath($bmcPath)) {
        if (ipmiProxyDebugEnabled() && $trace !== '') {
            ipmiProxyDebugLog('ilo_path_excluded_as_static_asset', ['trace' => $trace, 'bmcPath' => $bmcPath]);
        }
        $base['role'] = 'static_asset';
        $base['base_role'] = 'static_asset';

        return $base;
    }
    if (ipmiProxyIsIloSpaShellEntryPath($bmcPath)) {
        $base['role'] = 'shell_entry';
        $base['base_role'] = 'shell_entry';
        $base['bootstrap_critical'] = true;

        return $base;
    }
    if (ipmiProxyIsIloEventStreamPath($bmcPath)) {
        $base['role'] = 'event_stream';
        $base['base_role'] = 'event_stream';
        $base['bootstrap_critical'] = true;
        $base['recoverable'] = true;
        $base['debug_class'] = 'event_stream';

        return $base;
    }
    if (ipmiProxyIsIloRuntimeFragmentPath($bmcPath, $fragCtx)) {
        $h = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, $fragCtx);
        $base['role'] = 'runtime_fragment';
        $base['base_role'] = 'runtime_fragment';
        $base['bootstrap_critical'] = true;
        $base['recoverable'] = true;
        $base['debug_class'] = 'helper_fragment';
        $base['heuristic_score'] = $h['score'];
        $base['heuristic_reasons'] = $h['reasons'];
        if ($h['score'] >= 40 && !ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)) {
            $base['flags']['html_heuristic'] = true;
        }

        return $base;
    }
    if (str_starts_with($p, '/json/') || str_starts_with($p, '/api/') || str_starts_with($p, '/rest/')) {
        if (ipmiProxyIsHealthPollPath($bmcPath)) {
            $base['role'] = 'noncritical';
            $base['base_role'] = 'noncritical';
            $base['debug_class'] = 'runtime_api';

            return $base;
        }
        $base['role'] = 'runtime_api';
        $base['base_role'] = 'runtime_api';
        $base['bootstrap_critical'] = true;
        $base['recoverable'] = true;
        $base['debug_class'] = 'runtime_api';
        $base['flags']['api_bootstrap'] = true;
        if (ipmiProxyDebugEnabled() && $trace !== '') {
            ipmiProxyDebugLog('ilo_bootstrap_api_detected', ['trace' => $trace, 'bmcPath' => $bmcPath]);
        }

        return $base;
    }
    if (str_starts_with($p, '/html/') && str_ends_with($p, '.html')) {
        $base['role'] = 'transport_related';
        $base['base_role'] = 'transport_related';

        return $base;
    }
    $base['base_role'] = 'noncritical';

    return $base;
}

/**
 * Classify with session bootstrap state + contextual elevation + debug summary.
 *
 * @return array<string, mixed>
 */
function ipmiProxyClassifyIloPathRoleForSession(
    mysqli $mysqli,
    string $token,
    array &$session,
    string $bmcPath,
    string $method,
    string $traceId
): array {
    if (!ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))) {
        return ipmiProxyClassifyIloPathRole($bmcPath, $method, []);
    }
    $ctx = ipmiProxyIloPathContextFromSession($session);
    $ctx['trace'] = $traceId;
    $state = is_array($ctx['bootstrap_state'] ?? null) ? $ctx['bootstrap_state'] : [];
    if (ipmiProxyIloIsWithinBootstrapWindow($state) && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_context_window_active', [
            'trace'    => $traceId,
            'shell_ts' => (int) ($state['shell_ts'] ?? 0),
            'phase'    => (string) ($state['phase'] ?? ''),
        ]);
    }
    $base = ipmiProxyClassifyIloPathRole($bmcPath, $method, $ctx);
    $base['base_role'] = (string) ($base['base_role'] ?? $base['role']);
    $final = $base;
    if ($state !== []) {
        $final = ipmiProxyIloContextualizePathRole($base, $state, [
            'bmcPath' => $bmcPath,
            'trace'   => $traceId,
        ]);
    }
    $final = ipmiProxyIloApplySecondaryConsoleHelperPathRole($final, $bmcPath, $session, $state, $traceId);
    if (ipmiProxyDebugEnabled()) {
        $ctxSnap = ipmiProxyIloActiveNativeConsoleContextDetail($session, $state);
        $secPromo = 'n/a';
        if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
            if (($final['role'] ?? '') === 'secondary_console_helper') {
                $secPromo = 'promoted';
            } elseif (($final['base_role'] ?? '') === 'transport_related' && ($final['role'] ?? '') === 'transport_related') {
                $secPromo = $ctxSnap['active'] ? 'invariant_transport_despite_active_ctx' : 'skipped_no_native_context';
            } else {
                $secPromo = 'skipped_role_not_transport';
            }
        }
        ipmiProxyDebugLog('ilo_role_heuristic_summary', [
            'trace'                 => $traceId,
            'bmcPath'               => $bmcPath,
            'base_role'             => (string) ($final['base_role'] ?? ''),
            'final_role'            => (string) ($final['role'] ?? ''),
            'bootstrap_crit'        => !empty($final['bootstrap_critical']) ? 1 : 0,
            'heuristic_score'       => (int) ($final['heuristic_score'] ?? 0),
            'heuristic_reasons'     => $final['heuristic_reasons'] ?? [],
            'flags'                 => $final['flags'] ?? [],
            'secondary_w'           => (float) ($final['secondary_helper_weight'] ?? 0.0),
            'native_console_context' => $ctxSnap['active'] ? 1 : 0,
            'native_ctx_match'      => (string) ($ctxSnap['match'] ?? ''),
            'secondary_promotion'   => $secPromo,
        ]);
        ipmiProxyDebugLog('ilo_bootstrap_role_finalized', [
            'trace'      => $traceId,
            'bmcPath'    => $bmcPath,
            'final_role' => (string) ($final['role'] ?? ''),
        ]);
    }
    if (
        ($final['base_role'] ?? '') === 'transport_related'
        && ($final['role'] ?? '') === 'transport_related'
        && str_starts_with(strtolower((string) parse_url($bmcPath, PHP_URL_PATH)), '/html/')
        && !ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)
        && ipmiProxyIloIsWithinBootstrapWindow($state)
        && ipmiProxyDebugEnabled()
    ) {
        $hs = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, [
            'bootstrap_state' => $state,
            'shell_ts'        => (int) ($state['shell_ts'] ?? 0),
        ]);
        ipmiProxyDebugLog('ilo_path_missed_as_bootstrap_critical', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
            'score'   => $hs['score'],
        ]);
    }

    return $final;
}

/** @return array<string, mixed> */
function ipmiProxyIloBootstrapStateLoad(array $session): array
{
    $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $raw = $meta['ilo_bootstrap'] ?? null;
    if (!is_array($raw) || ($raw['v'] ?? 0) !== 1) {
        return ipmiProxyIloBootstrapStateDefaults();
    }
    $now = time();
    if (($raw['updated_at'] ?? 0) > 0 && $now - (int) $raw['updated_at'] > 3600) {
        return ipmiProxyIloBootstrapStateDefaults();
    }
    $raw['events'] = is_array($raw['events'] ?? null) ? array_slice($raw['events'], -24) : [];
    $raw['refresh_ts'] = is_array($raw['refresh_ts'] ?? null) ? $raw['refresh_ts'] : [];
    $raw['sse'] = is_array($raw['sse'] ?? null) ? $raw['sse'] : ipmiProxyIloBootstrapStateDefaults()['sse'];
    if (!isset($raw['shell_ts'])) {
        $raw['shell_ts'] = 0;
    }
    $raw['observed'] = ipmiProxyIloObservedPathsNormalize($raw['observed'] ?? [], $now);
    $raw['phase'] = ipmiProxyIloBootstrapStateClassify($raw);

    return $raw;
}

/** @return array<string, mixed> */
function ipmiProxyIloBootstrapStateDefaults(): array
{
    return [
        'v'          => 1,
        'updated_at' => 0,
        'phase'      => 'fresh',
        'events'     => [],
        'sse'        => ['last' => '', 'fail_streak' => 0, 'last_ts' => 0, 'ok_after_refresh' => 0],
        'refresh_ts' => [],
        'window'     => ['t0' => time(), 'crit_ok' => 0, 'crit_fail' => 0, 'soft_fail' => 0, 'shell_ok' => 0, 'roles_ok' => '', 'sec_helper_ok' => 0, 'sec_helper_fail' => 0],
        'shell_ts'   => 0,
        'observed'   => ['v' => 1, 'paths' => []],
    ];
}

function ipmiProxyIloBootstrapStateClassify(array $state): string
{
    $sse = is_array($state['sse'] ?? null) ? $state['sse'] : [];
    $failStreak = (int) ($sse['fail_streak'] ?? 0);
    $w = is_array($state['window'] ?? null) ? $state['window'] : [];
    $critOk = (int) ($w['crit_ok'] ?? 0);
    $critFail = (int) ($w['crit_fail'] ?? 0);
    $softFail = (int) ($w['soft_fail'] ?? 0);
    $shellOk = (int) ($w['shell_ok'] ?? 0);
    $rolesCsv = (string) ($w['roles_ok'] ?? '');
    $distinctRoles = count(array_filter(array_unique(array_filter(explode(',', $rolesCsv)))));

    if (
        $shellOk > 0 && $critOk >= 2 && $failStreak < 2 && $critFail <= 1 && $softFail <= 2
        && ($distinctRoles >= 2 || $critOk >= 3)
    ) {
        return 'healthy';
    }
    if ($shellOk > 0 && ($critFail >= 3 || $failStreak >= 2 || ($softFail >= 3 && $critOk < 2))) {
        return 'stalled';
    }
    if ($critFail >= 1 || $softFail >= 2 || $failStreak >= 1) {
        return 'degraded';
    }
    if ($shellOk > 0 || $critOk > 0) {
        return 'bootstrapping';
    }

    return 'fresh';
}

function ipmiProxyIloBootstrapLooksStalled(array $state): bool
{
    return ($state['phase'] ?? '') === 'stalled';
}

function ipmiProxyIloBootstrapLooksHealthy(array $state): bool
{
    return ($state['phase'] ?? '') === 'healthy';
}

/** @return array<string, mixed> */
function ipmiProxyIloBootstrapDebugSnapshot(array $session): array
{
    $s = ipmiProxyIloBootstrapStateLoad($session);
    $sse = is_array($s['sse'] ?? null) ? $s['sse'] : [];
    $rts = is_array($s['refresh_ts'] ?? null) ? $s['refresh_ts'] : [];
    $now = time();

    $evs = is_array($s['events'] ?? null) ? $s['events'] : [];
    $lastEv = $evs !== [] ? $evs[count($evs) - 1] : [];

    $w = is_array($s['window'] ?? null) ? $s['window'] : [];

    return [
        'phase'            => (string) ($s['phase'] ?? ''),
        'sse_last'         => (string) ($sse['last'] ?? ''),
        'sse_fail_streak'  => (int) ($sse['fail_streak'] ?? 0),
        'refresh_60s'      => count(array_filter($rts, static fn($t) => $t > $now - 60)),
        'sec_helper_ok'    => (int) ($w['sec_helper_ok'] ?? 0),
        'sec_helper_fail'  => (int) ($w['sec_helper_fail'] ?? 0),
        'blank_ui_hypothesis' => ipmiProxyIloBootstrapBlankUiHypothesis($s),
        'last_event_outcome'  => is_array($lastEv) ? (string) ($lastEv['outcome'] ?? '') : '',
        'last_event_path'     => is_array($lastEv) ? (string) ($lastEv['path'] ?? '') : '',
    ];
}

/** @param array<string, mixed> $state */
function ipmiProxyIloBootstrapLastCriticalHint(array $state): string
{
    $evs = is_array($state['events'] ?? null) ? $state['events'] : [];
    for ($i = count($evs) - 1; $i >= 0; $i--) {
        $e = $evs[$i];
        if (!is_array($e) || empty($e['critical'])) {
            continue;
        }
        $out = (string) ($e['outcome'] ?? '');
        $path = (string) ($e['path'] ?? '');
        $role = (string) ($e['role'] ?? '');
        if ($out === 'fail_soft_auth' || str_starts_with($out, 'fail_soft')) {
            if ($role === 'runtime_fragment' || str_contains($path, 'masthead')) {
                return 'fragment_mismatch';
            }

            return 'soft_auth_response';
        }
        if ($out === 'fail_hard_auth') {
            return 'auth_drift';
        }
        if ($out === 'fail_http' || $out === 'fail_transport' || $out === 'fail_hard_transport') {
            return 'transport_failure';
        }
    }

    return '';
}

function ipmiProxyIloBootstrapBlankUiHypothesis(array $state): string
{
    $phase = (string) ($state['phase'] ?? '');
    $sse = is_array($state['sse'] ?? null) ? $state['sse'] : [];
    if (($sse['fail_streak'] ?? 0) >= 2 && $phase !== 'healthy') {
        return 'sse_instability';
    }
    if ($phase === 'stalled') {
        return 'bootstrap_stall';
    }
    if ($phase === 'degraded') {
        return 'bootstrap_degraded';
    }
    if (($sse['last'] ?? '') === 'fail_auth') {
        return 'auth_drift';
    }
    $hint = ipmiProxyIloBootstrapLastCriticalHint($state);
    if ($hint !== '') {
        return $hint;
    }

    return 'unknown_or_transient';
}

/**
 * @param array<string, mixed> $event
 * @return array<string, mixed>
 */
function ipmiProxyIloBootstrapStateUpdate(array $state, array $event): array
{
    $now = time();
    $state['updated_at'] = $now;
    $evs = is_array($state['events'] ?? null) ? $state['events'] : [];
    $event['t'] = $now;
    $evs[] = $event;
    $state['events'] = array_slice($evs, -24);

    $w = is_array($state['window'] ?? null) ? $state['window'] : ['t0' => $now, 'crit_ok' => 0, 'crit_fail' => 0, 'soft_fail' => 0, 'shell_ok' => 0, 'roles_ok' => '', 'sec_helper_ok' => 0, 'sec_helper_fail' => 0];
    if ($now - (int) ($w['t0'] ?? $now) > 75) {
        $w = ['t0' => $now, 'crit_ok' => 0, 'crit_fail' => 0, 'soft_fail' => 0, 'shell_ok' => 0, 'roles_ok' => '', 'sec_helper_ok' => 0, 'sec_helper_fail' => 0];
    }
    $role = (string) ($event['role'] ?? '');
    $critical = !empty($event['critical']);
    $outcome = (string) ($event['outcome'] ?? '');
    if ($role === 'shell_entry' && $outcome === 'ok') {
        $w['shell_ok'] = (int) $w['shell_ok'] + 1;
        $state['shell_ts'] = $now;
    }
    if ($critical) {
        if ($outcome === 'ok') {
            $w['crit_ok'] = (int) $w['crit_ok'] + 1;
            if ($role !== '' && $role !== 'shell_entry') {
                $rlist = array_values(array_filter(explode(',', (string) ($w['roles_ok'] ?? ''))));
                if (!in_array($role, $rlist, true)) {
                    $rlist[] = $role;
                    $w['roles_ok'] = implode(',', array_slice($rlist, -6));
                }
            }
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_bootstrap_positive_signal_registered', [
                    'role' => $role,
                    'path' => (string) ($event['path'] ?? ''),
                ]);
            }
        } elseif (str_starts_with($outcome, 'fail_soft') || str_contains($outcome, 'soft')) {
            $w['crit_fail'] = (int) $w['crit_fail'] + 1;
            $w['soft_fail'] = (int) $w['soft_fail'] + 1;
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_bootstrap_negative_signal_registered', [
                    'role'   => $role,
                    'path'   => (string) ($event['path'] ?? ''),
                    'outcome' => $outcome,
                ]);
            }
        } elseif (str_starts_with($outcome, 'fail')) {
            $w['crit_fail'] = (int) $w['crit_fail'] + 1;
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_bootstrap_negative_signal_registered', [
                    'role'   => $role,
                    'path'   => (string) ($event['path'] ?? ''),
                    'outcome' => $outcome,
                ]);
            }
        }
    }
    if ($role === 'secondary_console_helper') {
        $w = ipmiProxyIloBootstrapRegisterSecondarySignal($w, $outcome);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_secondary_helper_health_signal', [
                'role'            => $role,
                'path'            => (string) ($event['path'] ?? ''),
                'outcome'         => $outcome,
                'sec_helper_ok'   => (int) ($w['sec_helper_ok'] ?? 0),
                'sec_helper_fail' => (int) ($w['sec_helper_fail'] ?? 0),
            ]);
        }
    }
    $state['window'] = $w;
    $prevPhase = (string) ($state['phase'] ?? '');
    $state['phase'] = ipmiProxyIloBootstrapStateClassify($state);
    if (ipmiProxyDebugEnabled() && (string) ($state['phase'] ?? '') !== $prevPhase) {
        ipmiProxyDebugLog('ilo_bootstrap_health_recomputed', [
            'phase'      => (string) ($state['phase'] ?? ''),
            'phase_prev' => $prevPhase,
        ]);
    }

    return $state;
}

function ipmiProxyIloBootstrapStateStore(mysqli $mysqli, string $token, array &$session, array $state, string $traceId, string $logEvent = 'ilo_bootstrap_state_updated'): void
{
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, $logEvent);
}

function ipmiProxyIloBootstrapStatePersist(mysqli $mysqli, string $token, array &$session, array $state, string $traceId, string $logEvent): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $prevPhase = is_array($session['session_meta']['ilo_bootstrap'] ?? null)
        ? (string) ($session['session_meta']['ilo_bootstrap']['phase'] ?? '') : '';
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $meta['ilo_bootstrap'] = $state;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_bootstrap'] = $state;
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog($logEvent, [
            'trace' => $traceId,
            'phase'       => (string) ($state['phase'] ?? ''),
            'phase_prev'  => $prevPhase,
        ]);
        $ph = (string) ($state['phase'] ?? '');
        if ($ph === 'healthy') {
            ipmiProxyDebugLog('ilo_bootstrap_state_healthy', ['trace' => $traceId]);
        } elseif ($ph === 'stalled') {
            ipmiProxyDebugLog('ilo_bootstrap_state_stalled', ['trace' => $traceId]);
        } elseif ($ph === 'degraded') {
            ipmiProxyDebugLog('ilo_bootstrap_state_degraded', ['trace' => $traceId]);
        }
    }
}

/**
 * @param array{kind: string, reason: string} $decision
 */
function ipmiProxyIloBootstrapCanRefresh(array $state, array $decision): bool
{
    $now = time();
    $ts = is_array($state['refresh_ts'] ?? null) ? $state['refresh_ts'] : [];
    $ts = array_values(array_filter($ts, static fn($t) => $t > $now - 60));
    if (count($ts) >= 3) {
        $kind = (string) ($decision['kind'] ?? '');
        $reason = (string) ($decision['reason'] ?? '');
        if ($kind !== 'hard') {
            return false;
        }

        return str_contains($reason, 'http_401')
            || str_contains($reason, 'sse_')
            || str_contains($reason, 'sse_precheck')
            || str_contains($reason, 'bootstrap_preflight')
            || str_contains($reason, 'shell_preflight');
    }
    if (
        count($ts) >= 2 && ($decision['kind'] ?? '') === 'soft'
        && (($state['phase'] ?? '') === 'stalled' || ($state['phase'] ?? '') === 'degraded')
    ) {
        return false;
    }

    return true;
}

/**
 * @param array<string, mixed> $state
 * @return array<string, mixed>
 */
function ipmiProxyIloBootstrapRegisterRefresh(array $state): array
{
    $now = time();
    $ts = is_array($state['refresh_ts'] ?? null) ? $state['refresh_ts'] : [];
    $ts[] = $now;
    $state['refresh_ts'] = array_values(array_filter($ts, static fn($t) => $t > $now - 90));

    return $state;
}

/** @param array{kind: string, reason: string} $decision */
function ipmiProxyIloCanAttemptAnotherRefresh(array $state, array $decision): bool
{
    return ipmiProxyIloBootstrapCanRefresh($state, $decision);
}

/**
 * Reserve a refresh slot in bootstrap metadata before calling the BMC relogin (parallel SPA bursts).
 *
 * @param array<string, mixed> $state
 * @return array<string, mixed>
 */
function ipmiProxyIloBootstrapBeginRefreshBudget(
    mysqli $mysqli,
    string $token,
    array &$session,
    array $state,
    string $traceId
): array {
    $state = ipmiProxyIloBootstrapRegisterRefresh($state);
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, 'ilo_refresh_attempt_recorded');

    return $state;
}

/**
 * Record whether a refresh attempt actually fixed auth state (after BeginRefreshBudget).
 *
 * @param array<string, mixed> $state
 * @return array<string, mixed>
 */
function ipmiProxyIloRecordRefreshAttempt(
    mysqli $mysqli,
    string $token,
    array &$session,
    array $state,
    bool $refreshSucceeded,
    string $traceId
): array {
    $state = ipmiProxyIloBootstrapStateUpdate($state, [
        'role'     => 'auth_refresh',
        'critical' => false,
        'outcome'  => $refreshSucceeded ? 'ok_refresh' : 'fail_refresh',
        'path'     => '/_ilo_refresh/',
    ]);
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, 'ilo_bootstrap_state_updated');

    return $state;
}

/**
 * @param array<string, mixed> $requestContext path_role, shell_entry (bool)
 * @param array<string, mixed> $responseContext soft_auth (bool), http (int)
 */
function ipmiProxyIloBootstrapShouldRefreshAuth(array $state, array $requestContext, array $responseContext): bool
{
    $phase = (string) ($state['phase'] ?? '');
    if (!empty($requestContext['shell_entry']) && in_array($phase, ['stalled', 'degraded'], true)) {
        return true;
    }
    if (!empty($responseContext['soft_auth']) && $phase === 'degraded') {
        return true;
    }
    if (!empty($responseContext['soft_auth']) && $phase === 'stalled') {
        return true;
    }

    return false;
}

/** @param array<string, mixed>|null $sseFailure */
function ipmiProxyIloSseLooksRecoverable(array $sseFailure): bool
{
    if ($sseFailure === null || $sseFailure === []) {
        return false;
    }

    return !empty($sseFailure['auth_rejected'])
        || (isset($sseFailure['curl_errno']) && (int) $sseFailure['curl_errno'] !== 0)
        || !empty($sseFailure['sse_recoverable_http']);
}

function ipmiProxyIloRuntimeJsonLooksSemanticallyBroken(string $bmcPath, string $body): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (!str_starts_with($p, '/json/')) {
        return false;
    }
    $t = trim($body);
    if ($t === '' || ($t[0] !== '{' && $t[0] !== '[')) {
        return str_starts_with($p, '/json/session_info');
    }
    $j = json_decode($t, true);
    if (!is_array($j)) {
        return true;
    }
    if (str_contains($p, 'session_info')) {
        $keys = array_map('strtolower', array_keys($j));
        $hints = ['session', 'user', 'username', 'lang', 'mpmodel', 'build', 'serial', 'oh_type', 'features'];
        foreach ($hints as $h) {
            foreach ($keys as $k) {
                if (str_contains($k, $h)) {
                    return false;
                }
            }
        }

        return count($j) <= 2;
    }

    return false;
}

function ipmiProxyIloApiJsonPlaceholderBroken(string $body, string $pLower): bool
{
    $t = trim($body);
    if ($t === '{}' || $t === '[]' || strcasecmp($t, 'null') === 0) {
        return str_contains($pLower, 'session') || str_contains($pLower, 'login')
            || str_contains($pLower, 'masthead') || str_contains($pLower, 'host_power');
    }

    return false;
}

function ipmiProxyIloApiResponseLooksBootstrapBroken(string $bmcPath, string $contentType, string $body): bool
{
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    if (!str_contains($ct, 'json')) {
        return false;
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (ipmiProxyIsHealthPollPath($bmcPath)) {
        return false;
    }
    if (!str_starts_with($p, '/json/') && !str_starts_with($p, '/api/') && !str_starts_with($p, '/rest/')) {
        return false;
    }
    if (ipmiProxyIloRuntimeJsonLooksSemanticallyBroken($bmcPath, $body)) {
        return true;
    }

    return ipmiProxyIloApiJsonPlaceholderBroken($body, $p);
}

function ipmiProxyIloResponseLooksLikeUnexpectedFullShell(string $bmcPath, string $contentType, string $body): bool
{
    if (!ipmiProxyIloIsHtmlFragmentForSemanticCheck($bmcPath)) {
        return false;
    }
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    if (!str_contains($ct, 'html')) {
        return false;
    }
    if (strlen($body) < 65000) {
        return false;
    }
    $head = strtolower(substr($body, 0, 14000));
    if (
        str_contains($head, 'masthead') || str_contains($head, 'sidebar')
        || str_contains($head, 'nav-container') || str_contains($head, 'fragment')
        || str_contains($head, 'widget-pane')
    ) {
        return false;
    }

    return str_contains($head, '<html');
}

function ipmiProxyIloFragmentLooksWrong(string $bmcPath, string $contentType, string $body): bool
{
    return ipmiProxyIloIsHtmlFragmentForSemanticCheck($bmcPath)
        && ipmiProxyIloBootstrapResponseLooksWrong($bmcPath, $contentType, $body);
}

function ipmiProxyIloResponseLooksBootstrapBroken(string $bmcPath, string $contentType, string $body): bool
{
    if (ipmiProxyIloBootstrapResponseLooksWrong($bmcPath, $contentType, $body)) {
        return true;
    }
    if (ipmiProxyIloResponseLooksLikeUnexpectedFullShell($bmcPath, $contentType, $body)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_fragment_returned_full_shell', [
                'bmcPath' => $bmcPath,
            ]);
        }

        return true;
    }
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    if (str_contains($ct, 'json') && ipmiProxyIloApiResponseLooksBootstrapBroken($bmcPath, $contentType, $body)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_api_response_bootstrap_broken', [
                'bmcPath' => $bmcPath,
            ]);
        }

        return true;
    }

    return false;
}

/**
 * @param array<string, mixed>|null $sseResult
 */
function ipmiProxyIloBootstrapNoteSse(
    mysqli $mysqli,
    string $token,
    array &$session,
    bool $ok,
    bool $retriedAfterRefresh,
    ?array $sseResult,
    string $traceId
): void {
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state = ipmiProxyIloBootstrapStateLoad($session);
    $sse = is_array($state['sse'] ?? null) ? $state['sse'] : [];
    $now = time();
    if ($ok) {
        $sse['last'] = 'ok';
        $sse['fail_streak'] = 0;
        $sse['last_ts'] = $now;
        if ($retriedAfterRefresh) {
            $sse['ok_after_refresh'] = (int) ($sse['ok_after_refresh'] ?? 0) + 1;
        }
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_sse_health_positive', ['trace' => $traceId, 'retried' => $retriedAfterRefresh ? 1 : 0]);
            ipmiProxyDebugLog('ilo_bootstrap_health_positive_signal', ['trace' => $traceId, 'channel' => 'sse']);
        }
    } else {
        $auth = is_array($sseResult) && !empty($sseResult['auth_rejected']);
        $sse['last'] = $auth ? 'fail_auth' : 'fail_transport';
        $sse['fail_streak'] = (int) ($sse['fail_streak'] ?? 0) + 1;
        $sse['last_ts'] = $now;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_sse_health_negative', [
                'trace'    => $traceId,
                'auth'     => $auth ? 1 : 0,
                'retried'  => $retriedAfterRefresh ? 1 : 0,
            ]);
            ipmiProxyDebugLog('ilo_bootstrap_health_negative_signal', ['trace' => $traceId, 'channel' => 'sse']);
            if ($retriedAfterRefresh) {
                ipmiProxyDebugLog('ilo_sse_still_failing_after_refresh', ['trace' => $traceId]);
            }
        }
    }
    $state['sse'] = $sse;
    $failAuth = !$ok && is_array($sseResult) && !empty($sseResult['auth_rejected']);
    $state = ipmiProxyIloBootstrapStateUpdate($state, [
        'role'     => 'event_stream',
        'critical' => true,
        'outcome'  => $ok ? 'ok' : ($failAuth ? 'fail_soft_auth' : 'fail_hard_transport'),
        'path'     => '/sse/',
    ]);
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, 'ilo_bootstrap_state_updated');
}

/** @param array<string, mixed>|null $sseResult */
function ipmiProxyIloSseHealthUpdate(
    mysqli $mysqli,
    string $token,
    array &$session,
    bool $ok,
    bool $retriedAfterRefresh,
    ?array $sseResult,
    string $traceId
): void {
    ipmiProxyIloBootstrapNoteSse($mysqli, $token, $session, $ok, $retriedAfterRefresh, $sseResult, $traceId);
}

/**
 * @param array<string, mixed> $pathRole final role from ipmiProxyClassifyIloPathRoleForSession (or equivalent)
 */
function ipmiProxyIloBootstrapTrackBufferedResponse(
    mysqli $mysqli,
    string $token,
    array &$session,
    string $bmcPath,
    string $method,
    int $httpCode,
    string $contentType,
    string $body,
    array $pathRole,
    bool $recoveryWasAttempted,
    string $traceId
): void {
    if (!ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))) {
        return;
    }
    if (in_array($pathRole['role'], ['static_asset', 'noncritical'], true)) {
        return;
    }
    $state = ipmiProxyIloBootstrapStateLoad($session);
    $critical = !empty($pathRole['bootstrap_critical']);
    $shellLoginLike = $pathRole['role'] === 'shell_entry'
        && $httpCode >= 200 && $httpCode < 400
        && (ipmiWebResponseLooksLikeBmcLoginPage($body, $contentType) || ipmiProxyBodyHasSessionTimeout($body));
    $softFail = ipmiProxyIloIsSoftAuthFailure($bmcPath, $httpCode, $contentType, $body) || $shellLoginLike;
    $ok = $httpCode >= 200 && $httpCode < 400        && !$softFail
        && !ipmiProxyIloResponseLooksBootstrapBroken($bmcPath, $contentType, $body);
    $semanticBroken = $httpCode >= 200 && $httpCode < 400
        && $critical
        && ipmiProxyIloResponseLooksBootstrapBroken($bmcPath, $contentType, $body);
    if ($semanticBroken && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_semantic_failure_detected', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
        ]);
        if (ipmiProxyIloFragmentLooksWrong($bmcPath, $contentType, $body)) {
            ipmiProxyDebugLog('ilo_fragment_shape_unexpected', ['trace' => $traceId, 'bmcPath' => $bmcPath]);
        }
        if (ipmiProxyIloRuntimeJsonLooksSemanticallyBroken($bmcPath, $body)) {
            ipmiProxyDebugLog('ilo_runtime_json_semantically_broken', ['trace' => $traceId, 'bmcPath' => $bmcPath]);
        }
    }
    $outcome = 'ok';
    if (!$ok) {
        if ($httpCode === 401 || $httpCode === 403) {
            $outcome = 'fail_hard_auth';
        } elseif ($semanticBroken || ipmiProxyIloIsSoftAuthFailure($bmcPath, $httpCode, $contentType, $body)) {
            $outcome = 'fail_soft_auth';
        } elseif ($httpCode >= 400) {
            $outcome = 'fail_http';
        } else {
            $outcome = 'fail_transport';
        }
    }
    $state = ipmiProxyIloBootstrapStateUpdate($state, [
        'role'     => (string) $pathRole['role'],
        'critical' => $critical,
        'outcome'  => $outcome,
        'path'     => (string) $pathRole['path_key'],
        'recovery' => $recoveryWasAttempted ? 1 : 0,
    ]);
    $pathKey = (string) ($pathRole['path_key'] ?? '');
    if ($pathKey !== '') {
        $state = ipmiProxyIloRecordObservedBootstrapPath($state, $pathKey, $critical, $ok);
    }
    $phase = (string) ($state['phase'] ?? '');
    if (ipmiProxyIloBootstrapLooksStalled($state) && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_shell_loaded_spa_stalled', [
            'trace'      => $traceId,
            'bmcPath'    => $bmcPath,
            'last_event' => $outcome,
        ]);
    }
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, 'ilo_bootstrap_state_updated_from_role');
    $csr = ipmiProxyIloConsoleReadinessStateLoad($session);
    $csrChanged = false;
    $pathOnly = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (str_contains($pathOnly, 'application.html') && $httpCode >= 200 && $httpCode < 400 && $ok) {
        $csr = ipmiProxyIloConsoleReadinessUpdate($csr, [
            'type' => 'application_html',
            'ok'   => true,
        ]);
        $csrChanged = true;
    }
    if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        $csr = ipmiProxyIloRegisterConsoleStartupSignal($csr, $bmcPath, $ok, $outcome);
        $csrChanged = true;
        if (ipmiProxyDebugEnabled() && $traceId !== '') {
            ipmiProxyDebugLog('ilo_console_startup_helper_seen', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
                'role'    => (string) ($pathRole['role'] ?? ''),
                'ok'      => $ok ? 1 : 0,
            ]);
            if ($ok) {
                ipmiProxyDebugLog('ilo_console_startup_helper_ok', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                ]);
            } else {
                ipmiProxyDebugLog('ilo_console_startup_helper_failed', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                    'outcome' => $outcome,
                ]);
            }
        }
    }
    if ($csrChanged) {
        ipmiProxyIloConsoleReadinessStateStore($mysqli, $token, $session, $csr, $traceId);
    }
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $ldChanged = false;
    if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        $ld = ipmiProxyIloRegisterLaunchHelperSignal($ld, $bmcPath, $ok, $outcome);
        $ldChanged = true;
        $planStrat = (string) (ipmiProxyIloKvmPlanFromSession($session)['launch_strategy'] ?? '');
        if ($planStrat === 'ilo_speculative_shell_autolaunch') {
            $ld['speculative_shell_hint'] = 1;
        }
        if (ipmiProxyDebugEnabled() && $traceId !== '') {
            ipmiProxyDebugLog('ilo_launch_helper_seen', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
                'ok'      => $ok ? 1 : 0,
                'strategy' => $planStrat,
            ]);
            if ($ok) {
                ipmiProxyDebugLog('ilo_launch_helper_aided_discovery', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                ]);
            } elseif ($planStrat === 'ilo_speculative_shell_autolaunch') {
                ipmiProxyDebugLog('ilo_launch_helper_seen_but_no_target_found', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                    'outcome' => $outcome,
                    'hint'    => 'http_failed_or_soft_auth_shell_discovery_may_still_fail',
                ]);
            }
        }
    }
    if ($ldChanged) {
        ipmiProxyIloLaunchDiscoveryStateStore($mysqli, $token, $session, $ld, $traceId);
    }
    if (ipmiProxyDebugEnabled()) {
        if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
            $ctxDetail = ipmiProxyIloActiveNativeConsoleContextDetail($session, $state);
            if (!$ok && $ctxDetail['active'] && (string) ($state['phase'] ?? '') !== 'stalled') {
                ipmiProxyDebugLog('ilo_console_startup_stall_correlated', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                    'reason'  => 'helper_failed_while_native_flow_active',
                    'outcome' => $outcome,
                ]);
            }
        }
        if (($pathRole['role'] ?? '') === 'secondary_console_helper') {
            ipmiProxyDebugLog('ilo_secondary_console_helper_contributed', [
                'trace'    => $traceId,
                'bmcPath'  => $bmcPath,
                'weight'   => (float) ($pathRole['secondary_helper_weight'] ?? 0.0),
                'positive' => $ok ? 1 : 0,
                'outcome'  => $outcome,
                'sec_snap' => [
                    'sec_helper_ok'   => (int) ($state['window']['sec_helper_ok'] ?? 0),
                    'sec_helper_fail' => (int) ($state['window']['sec_helper_fail'] ?? 0),
                ],
            ]);
        }
        if ($critical) {
            ipmiProxyDebugLog('ilo_path_contributed_to_bootstrap_health', [
                'trace'    => $traceId,
                'bmcPath'  => $bmcPath,
                'role'     => (string) $pathRole['role'],
                'outcome'  => $outcome,
                'positive' => $ok ? 1 : 0,
                'flags'    => $pathRole['flags'] ?? [],
            ]);
        }
        if ($recoveryWasAttempted) {
            ipmiProxyDebugLog('ilo_bootstrap_recovery_role_used', [
                'trace'              => $traceId,
                'bmcPath'            => $bmcPath,
                'role'               => (string) $pathRole['role'],
                'bootstrap_critical' => $critical ? 1 : 0,
                'outcome'            => $outcome,
            ]);
        }
        ipmiProxyDebugLog('ilo_bootstrap_finalized', [
            'trace'     => $traceId,
            'bmcPath'   => $bmcPath,
            'phase'     => $phase,
            'outcome'   => $outcome,
            'role'      => (string) $pathRole['role'],
        ]);
    }
}

/**
 * @return 'event_stream'|'runtime_api'|'helper_fragment'|'other'
 */
function ipmiProxyIloRuntimePathDebugClass(string $bmcPath): string
{
    if (ipmiProxyIsIloEventStreamPath($bmcPath)) {
        return 'event_stream';
    }
    if (ipmiProxyIloIsHtmlFragmentForSemanticCheck($bmcPath)) {
        return 'helper_fragment';
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (str_starts_with($p, '/json/') || str_starts_with($p, '/api/') || str_starts_with($p, '/rest/')) {
        return 'runtime_api';
    }

    return 'other';
}

/**
 * Single field for correlating blank iLO SPA shells with server-side logs.
 *
 * @param 'auth_refresh_failed'|'sse_final'|'post_retry_http'|'curl_after_recover' $mode
 * @param array{http?: int, auth_rejected?: bool, curl_errno?: int, sse_recoverable_http?: bool} $ctx
 */
function ipmiProxyIloBlankUiCause(string $bmcPath, string $mode, array $ctx = []): string
{
    $class = ipmiProxyIloRuntimePathDebugClass($bmcPath);
    if ($mode === 'auth_refresh_failed') {
        return 'auth_drift';
    }
    if ($mode === 'sse_final') {
        if (!empty($ctx['auth_rejected'])) {
            return 'auth_drift';
        }
        if (!empty($ctx['curl_errno'])) {
            return 'upstream_transport';
        }
        if (!empty($ctx['sse_recoverable_http'])) {
            return 'upstream_transport';
        }

        return 'sse_failure';
    }
    if ($mode === 'post_retry_http') {
        $http = (int) ($ctx['http'] ?? 0);
        if (in_array($http, [401, 403], true)) {
            return 'auth_drift';
        }
        if ($http === 502 || $http === 503) {
            return 'upstream_transport';
        }
        if ($class === 'helper_fragment') {
            return 'fragment_bootstrap';
        }
        if ($class === 'runtime_api') {
            return $http >= 500 ? 'upstream_transport' : 'unknown';
        }

        return 'unknown';
    }
    if ($mode === 'curl_after_recover') {
        return 'upstream_transport';
    }

    return 'unknown';
}

function ipmiProxyIloRuntimeAuthRefresh(mysqli $mysqli, string $token, array &$session, string $bmcIp, string $traceId, string $reason): bool
{
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_auth_refresh_attempt', [
            'trace'  => $traceId,
            'reason' => $reason,
        ]);
    }
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $baseUrl = $scheme . '://' . $bmcIp;
    $user = trim((string) ($session['ipmi_user'] ?? ''));
    $pass = (string) ($session['ipmi_pass'] ?? '');
    $cookies = is_array($session['cookies'] ?? null) ? $session['cookies'] : [];
    $fwd = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
    ipmiWebSyncIloSessionAndSessionKeyCookies($cookies);
    if ($user !== '' && $pass !== '') {
        ipmiWebIloEnsureSessionCookieForWebUi($baseUrl, $bmcIp, $user, $pass, $cookies, $fwd);
    }
    $session['cookies'] = $cookies;
    $session['forward_headers'] = $fwd;
    if (ipmiWebIloVerifyAuthed($baseUrl, $bmcIp, $session['cookies'], is_array($session['forward_headers']) ? $session['forward_headers'] : [])) {
        ipmiWebPersistRefreshedRuntimeAuth($mysqli, $token, $session);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_auth_refresh_success', [
                'trace' => $traceId,
                'via'   => 'session_cookie_repair',
            ]);
        }

        return true;
    }
    $session['cookies'] = [];
    $session['forward_headers'] = [];
    if (!ipmiWebAttemptAutoLogin($session, $mysqli)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_auth_refresh_failed', [
                'trace' => $traceId,
                'error' => (string) ($session['auto_login_error'] ?? ''),
            ]);
        }

        return false;
    }
    ipmiWebPersistRefreshedRuntimeAuth($mysqli, $token, $session);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_auth_refresh_success', [
            'trace' => $traceId,
            'via'   => 'full_auto_login',
        ]);
    }

    return true;
}

/**
 * Reload cookies, forward headers, scheme, and session_meta from DB after a refresh wrote them.
 */
function ipmiProxyReloadSessionRowInto(array &$session, mysqli $mysqli, string $token, string $traceId): bool
{
    $row = ipmiWebLoadSession($mysqli, $token);
    if (!$row) {
        return false;
    }
    $session['cookies'] = is_array($row['cookies'] ?? null) ? $row['cookies'] : [];
    $session['forward_headers'] = is_array($row['forward_headers'] ?? null) ? $row['forward_headers'] : [];
    $session['bmc_scheme'] = (string) ($row['bmc_scheme'] ?? 'https');
    $session['session_meta'] = is_array($row['session_meta'] ?? null) ? $row['session_meta'] : [];
    if (ipmiWebIsIloFamilyType((string) ($session['bmc_type'] ?? ''))) {
        $session['cookies'] = ipmiProxyMergeClientBmcCookies($session['cookies'], (string) ($session['bmc_type'] ?? ''));
        ipmiWebSyncIloSessionAndSessionKeyCookies($session['cookies']);
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_session_reloaded_after_refresh', ['trace' => $traceId]);
    }

    return true;
}

function ipmiProxyRebuildIloForwardHeadersFromSession(array $session, string $bmcScheme, string $bmcIp, string $bmcPathOnlyLower): array
{
    $hdr = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
    $hdr = ipmiProxyMergeClientBmcForwardHeaders(
        $hdr,
        $bmcScheme,
        $bmcIp,
        is_array($session['cookies'] ?? null) ? $session['cookies'] : []
    );
    if (
        str_starts_with($bmcPathOnlyLower, '/json/')
        || str_starts_with($bmcPathOnlyLower, '/api/')
        || str_starts_with($bmcPathOnlyLower, '/rest/')
    ) {
        if (!ipmiProxyForwardHeadersHasHeader($hdr, 'X-Requested-With')) {
            $hdr['X-Requested-With'] = 'XMLHttpRequest';
        }
        if (!ipmiProxyForwardHeadersHasHeader($hdr, 'Accept')) {
            $hdr['Accept'] = 'application/json, text/javascript, */*';
        }
    }

    return $hdr;
}

/**
 * @return array{fwdHdr: array<string, string>, cookies: array<string, string>}
 */
function ipmiProxyRebuildFreshIloRequestState(array &$session, string &$bmcScheme, string $bmcIp, string $bmcPathOnlyLower, string $traceId): array
{
    $bmcScheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $cookies = is_array($session['cookies'] ?? null) ? $session['cookies'] : [];
    $fwdHdr = ipmiProxyRebuildIloForwardHeadersFromSession($session, $bmcScheme, $bmcIp, $bmcPathOnlyLower);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_retry_request_state_rebuilt', [
            'trace'               => $traceId,
            'bmcScheme'           => $bmcScheme,
            'forward_header_keys' => array_slice(array_keys($fwdHdr), 0, 14),
            'cookie_key_count'    => count($cookies),
            'mitigates_stale_retry_headers' => 1,
            'session_row_source'  => 'db_reload_before_rebuild',
        ]);
        ipmiProxyDebugLog('ilo_retry_using_fresh_forward_headers', [
            'trace'      => $traceId,
            'has_x_auth' => (trim((string) ($fwdHdr['X-Auth-Token'] ?? '')) !== '') ? 1 : 0,
        ]);
        ipmiProxyDebugLog('ilo_retry_using_fresh_cookies', [
            'trace' => $traceId,
            'names' => array_slice(array_keys($cookies), 0, 14),
        ]);
    }

    return ['fwdHdr' => $fwdHdr, 'cookies' => $cookies];
}

/**
 * After HTML/asset relogin mutates the session, iLO needs the same DB-reload + header merge as runtime recovery (avoids stale X-Auth-Token on immediate retry).
 *
 * @return array<string, string>|null Forward headers to use, or null if vendor is not normalized iLO
 */
function ipmiProxyIloFreshForwardHeadersAfterRelogin(
    array &$session,
    string &$bmcScheme,
    string $bmcIp,
    string $bmcPath,
    mysqli $mysqli,
    string $token,
    string $traceId
): ?array {
    if (!ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))) {
        return null;
    }
    ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $traceId);
    $pl = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $st = ipmiProxyRebuildFreshIloRequestState($session, $bmcScheme, $bmcIp, $pl, $traceId);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_relogin_retry_fresh_headers', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
            'mitigates_stale_retry_headers' => 1,
        ]);
    }

    return $st['fwdHdr'];
}

function ipmiProxyMaybeIloRuntimePreflight(mysqli $mysqli, string $token, array &$session, string $bmcIp, string $bmcPath, string $traceId): void
{
    $now = time();
    $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $pf = $meta['ilo_preflight'] ?? null;
    $bootstrapState = ipmiProxyIloBootstrapStateLoad($session);
    $bootstrapPhase = (string) ($bootstrapState['phase'] ?? 'fresh');
    $shellPathRole = ipmiProxyClassifyIloPathRoleForSession($mysqli, $token, $session, $bmcPath, 'GET', $traceId);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_preflight_started', [
            'trace'           => $traceId,
            'bootstrap_phase' => $bootstrapPhase,
            'path_role'       => $shellPathRole['role'],
            'path_role_base'  => (string) ($shellPathRole['base_role'] ?? $shellPathRole['role']),
            'bootstrap_critical' => !empty($shellPathRole['bootstrap_critical']) ? 1 : 0,
        ]);
        ipmiProxyDebugLog('ilo_path_role_classified', [
            'trace'              => $traceId,
            'bmcPath'            => $bmcPath,
            'path_role'          => $shellPathRole['role'],
            'path_role_base'     => (string) ($shellPathRole['base_role'] ?? $shellPathRole['role']),
            'bootstrap_critical' => !empty($shellPathRole['bootstrap_critical']) ? 1 : 0,
            'gate'               => 'preflight',
        ]);
    }
    if (in_array($bootstrapPhase, ['stalled', 'degraded'], true) && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_preflight_degraded', [
            'trace' => $traceId,
            'phase' => $bootstrapPhase,
        ]);
    }
    $cacheFresh = is_array($pf) && isset($pf['t']) && (int) $pf['t'] > $now - 25;
    $cacheViable = $cacheFresh
        && !empty($pf['bootstrap_ok'])
        && !in_array($bootstrapPhase, ['stalled', 'degraded'], true);
    if ($cacheViable && ipmiProxyIloBootstrapLooksHealthy($bootstrapState)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_bootstrap_preflight_cache_hit', [
                'trace'           => $traceId,
                'bootstrap_phase' => $bootstrapPhase,
            ]);
            ipmiProxyDebugLog('ilo_runtime_preflight_cache_hit', [
                'trace'         => $traceId,
                'age_sec'       => $now - (int) $pf['t'],
                'session_ok'    => !empty($pf['session_ok']) ? 1 : 0,
                'bootstrap_ok'  => !empty($pf['bootstrap_ok']) ? 1 : 0,
            ]);
        }

        return;
    }
    if ($cacheFresh && !in_array($bootstrapPhase, ['stalled', 'degraded'], true)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_preflight_cache_hit', [
                'trace'         => $traceId,
                'age_sec'       => $now - (int) $pf['t'],
                'session_ok'    => !empty($pf['session_ok']) ? 1 : 0,
                'bootstrap_ok'  => !empty($pf['bootstrap_ok']) ? 1 : 0,
            ]);
        }

        return;
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_preflight_cache_miss', ['trace' => $traceId]);
        ipmiProxyDebugLog('ilo_runtime_preflight_started', ['trace' => $traceId]);
    }
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $baseUrl = $scheme . '://' . $bmcIp;
    $cookies = is_array($session['cookies']) ? $session['cookies'] : [];
    $fwd = is_array($session['forward_headers']) ? $session['forward_headers'] : [];
    $sessionOk = ipmiWebIloVerifyAuthed($baseUrl, $bmcIp, $cookies, $fwd);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog($sessionOk ? 'ilo_runtime_preflight_session_info_ok' : 'ilo_runtime_preflight_failed', [
            'trace'  => $traceId,
            'phase'  => 'session_info',
        ]);
        if ($sessionOk) {
            ipmiProxyDebugLog('ilo_bootstrap_preflight_auth_ok', ['trace' => $traceId]);
        }
    }
    $bootstrapOk = $sessionOk && ipmiWebIloBootstrapFragmentProbe($baseUrl, $bmcIp, $cookies, $fwd);
    if ($sessionOk) {
        ipmiWebIloRecordMastheadPreflightOutcome($mysqli, $token, $session, $bootstrapOk);
    }
    if (ipmiProxyDebugEnabled() && $sessionOk) {
        ipmiProxyDebugLog($bootstrapOk ? 'ilo_runtime_preflight_bootstrap_ok' : 'ilo_runtime_preflight_failed', [
            'trace'  => $traceId,
            'phase'  => 'masthead_fragment',
        ]);
        if ($bootstrapOk) {
            ipmiProxyDebugLog('ilo_bootstrap_preflight_fragment_ok', ['trace' => $traceId]);
        }
    }
    if ($sessionOk && $bootstrapOk) {
        $payload = ['t' => $now, 'session_ok' => true, 'bootstrap_ok' => true];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_preflight_passed', ['trace' => $traceId]);
        }

        return;
    }
    $preRefreshPhase = (string) ($bootstrapState['phase'] ?? '');
    $shouldEarlyRefresh = in_array($preRefreshPhase, ['stalled', 'degraded'], true);
    $didPreflightAuthRefresh = false;
    if ($shouldEarlyRefresh) {
        $earlyDecision = ['kind' => 'hard', 'reason' => 'bootstrap_preflight_stalled'];
        if (!ipmiProxyIloCanAttemptAnotherRefresh($bootstrapState, $earlyDecision)) {
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                    'trace'   => $traceId,
                    'gate'    => 'preflight_stalled',
                    'reason'  => 'refresh_budget',
                ]);
            }
        } else {
            $bootstrapState = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $bootstrapState, $traceId);
            if (ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $traceId, 'bootstrap_preflight_stalled')) {
                $didPreflightAuthRefresh = true;
                ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $traceId);
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_bootstrap_preflight_refreshed_auth', [
                        'trace'  => $traceId,
                        'reason' => 'stalled_or_degraded_phase',
                    ]);
                }
                $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
                $baseUrl = $scheme . '://' . $bmcIp;
                $cookies = is_array($session['cookies']) ? $session['cookies'] : [];
                $fwd = is_array($session['forward_headers']) ? $session['forward_headers'] : [];
                $sessionOk = ipmiWebIloVerifyAuthed($baseUrl, $bmcIp, $cookies, $fwd);
                $bootstrapOk = $sessionOk && ipmiWebIloBootstrapFragmentProbe($baseUrl, $bmcIp, $cookies, $fwd);
                if ($sessionOk) {
                    ipmiWebIloRecordMastheadPreflightOutcome($mysqli, $token, $session, $bootstrapOk);
                }
            }
        }
    }
    if ($sessionOk && $bootstrapOk) {
        $payload = ['t' => time(), 'session_ok' => true, 'bootstrap_ok' => true];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_preflight_passed', ['trace' => $traceId]);
        }

        return;
    }
    if ($didPreflightAuthRefresh) {
        $payload = ['t' => time(), 'session_ok' => $sessionOk, 'bootstrap_ok' => $bootstrapOk];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_bootstrap_preflight_skip_second_refresh', [
                'trace'        => $traceId,
                'session_ok'   => $sessionOk ? 1 : 0,
                'bootstrap_ok' => $bootstrapOk ? 1 : 0,
            ]);
        }

        return;
    }
    $bootstrapStateShell = ipmiProxyIloBootstrapStateLoad($session);
    $shellDecision = ['kind' => 'hard', 'reason' => 'shell_preflight'];
    if (!ipmiProxyIloCanAttemptAnotherRefresh($bootstrapStateShell, $shellDecision)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                'trace'  => $traceId,
                'gate'   => 'shell_preflight',
                'reason' => 'refresh_budget',
            ]);
        }
        $payload = ['t' => $now, 'session_ok' => false, 'bootstrap_ok' => false];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;

        return;
    }
    $bootstrapStateShell = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $bootstrapStateShell, $traceId);
    if (ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $traceId, 'shell_preflight')) {
        ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $traceId);
        $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
        $baseUrl = $scheme . '://' . $bmcIp;
        $cookies = is_array($session['cookies']) ? $session['cookies'] : [];
        $fwd = is_array($session['forward_headers']) ? $session['forward_headers'] : [];
        $sessionOk2 = ipmiWebIloVerifyAuthed($baseUrl, $bmcIp, $cookies, $fwd);
        $bootstrapOk2 = $sessionOk2 && ipmiWebIloBootstrapFragmentProbe($baseUrl, $bmcIp, $cookies, $fwd);
        if ($sessionOk2) {
            ipmiWebIloRecordMastheadPreflightOutcome($mysqli, $token, $session, $bootstrapOk2);
        }
        $payload = ['t' => time(), 'session_ok' => $sessionOk2, 'bootstrap_ok' => $bootstrapOk2];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_preflight_auth_refreshed', [
                'trace'        => $traceId,
                'session_ok'   => $sessionOk2 ? 1 : 0,
                'bootstrap_ok' => $bootstrapOk2 ? 1 : 0,
            ]);
            ipmiProxyDebugLog('ilo_bootstrap_preflight_refreshed_auth', [
                'trace'  => $traceId,
                'reason' => 'shell_preflight',
            ]);
        }
    } else {
        $payload = ['t' => $now, 'session_ok' => false, 'bootstrap_ok' => false];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
    }
}

/**
 * Paths where HTTP 200 may still mean stale session (soft auth). Matches recoverable runtime set so any endpoint eligible for hard retry is also checked for soft 200 failures.
 */
function ipmiProxyIloBootstrapSensitivePath(string $bmcPath): bool
{
    return ipmiProxyIsIloRecoverableRuntimePath($bmcPath);
}

function ipmiProxyIloJsonLooksUnauthed(string $body): bool
{
    $t = trim($body);
    if ($t === '' || ($t[0] !== '{' && $t[0] !== '[')) {
        return false;
    }
    $j = json_decode($t, true);
    if (!is_array($j)) {
        return true;
    }
    $msg = strtolower((string) ($j['message'] ?? $j['error'] ?? ''));
    if (is_string($j['error'] ?? null)) {
        $msg .= ' ' . strtolower((string) $j['error']);
    }
    $details = strtolower((string) ($j['details'] ?? ''));
    if (str_contains($msg, 'lost_session') || str_contains($details, 'invalid session')) {
        return true;
    }
    if (str_contains($msg, 'unauthorized') || str_contains($msg, 'forbidden')) {
        return true;
    }
    if (str_contains($msg, 'authentication') && (str_contains($msg, 'fail') || str_contains($msg, 'required'))) {
        return true;
    }
    if (isset($j['code']) && (int) $j['code'] === 401) {
        return true;
    }
    $ext = $j['error'] ?? null;
    if (is_array($ext)) {
        $ek = strtolower((string) ($ext['key'] ?? $ext['code'] ?? ''));

        return str_contains($ek, 'session') || str_contains($ek, 'auth');
    }

    return false;
}

function ipmiProxyIloHtmlLooksUnauthed(string $body): bool
{
    if (ipmiWebResponseLooksLikeBmcLoginPage($body, 'text/html')) {
        return true;
    }
    if (ipmiProxyBodyHasSessionTimeout($body)) {
        return true;
    }

    return false;
}

function ipmiProxyIloBootstrapResponseLooksWrong(string $bmcPath, string $contentType, string $body): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    if (ipmiProxyIloIsHtmlFragmentForSemanticCheck($bmcPath)) {
        if (str_contains($ct, 'json')) {
            return true;
        }
        $lb = strtolower(substr($body, 0, 24000));
        if (strlen($body) < 40) {
            return true;
        }
        if (
            $lb !== '' && str_contains($lb, '<html') && !str_contains($lb, 'masthead')
            && str_contains($lb, 'password') && str_contains($lb, 'login')
        ) {
            return true;
        }
    }
    if (str_starts_with($p, '/json/') && (str_contains($ct, 'html') || ($ct === 'text/plain' && ipmiProxyIloHtmlLooksUnauthed($body)))) {
        return ipmiProxyIloHtmlLooksUnauthed($body);
    }

    return false;
}

function ipmiProxyIloIsSoftAuthFailure(string $bmcPath, int $httpCode, string $contentType, string $body): bool
{
    if ($httpCode < 200 || $httpCode >= 400) {
        return false;
    }
    if (!ipmiProxyIloBootstrapSensitivePath($bmcPath)) {
        return false;
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    $jsonish = str_starts_with($p, '/json/') || str_contains($ct, 'json');
    if ($jsonish && ipmiProxyIloJsonLooksUnauthed($body)) {
        return true;
    }
    if (str_contains($ct, 'html') && ipmiProxyIloHtmlLooksUnauthed($body)) {
        return true;
    }
    if (ipmiProxyIloBootstrapResponseLooksWrong($bmcPath, $contentType, $body)) {
        return true;
    }

    return false;
}

/**
 * @return array{recover: bool, reason: string, kind: 'none'|'hard'|'soft', soft_detail?: string}
 */
function ipmiProxyIloClassifyBufferedRecovery(
    mysqli $mysqli,
    string $token,
    array &$session,
    array $result,
    string $bmcPath,
    string $method,
    string $traceId
): array {
    if (!ipmiProxyIsIloRecoverableRuntimePath($bmcPath)) {
        return ['recover' => false, 'reason' => 'not_recoverable_path', 'kind' => 'none'];
    }
    $http0 = (int) ($result['http_code'] ?? 0);
    if (($result['raw'] ?? false) === false) {
        return [
            'recover' => true,
            'reason'  => 'curl_failed:' . (int) ($result['curl_errno'] ?? 0),
            'kind'    => 'hard',
        ];
    }
    if (in_array($http0, [401, 403, 502, 503], true)) {
        return ['recover' => true, 'reason' => 'http_' . $http0, 'kind' => 'hard'];
    }
    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody((string) $result['raw']);
    $ct = (string) ($result['content_type'] ?? '');
    $pathRole = ipmiProxyClassifyIloPathRoleForSession($mysqli, $token, $session, $bmcPath, $method, $traceId);
    if (!empty($pathRole['bootstrap_critical']) && $http0 >= 200 && $http0 < 400) {
        if (ipmiProxyIloResponseLooksBootstrapBroken($bmcPath, $ct, $body)) {
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_bootstrap_semantic_failure_detected', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                    'gate'    => 'classify_recovery',
                ]);
            }

            return [
                'recover'     => true,
                'reason'      => 'soft_auth:semantic_bootstrap',
                'kind'        => 'soft',
                'soft_detail' => 'semantic_bootstrap',
            ];
        }
    }
    if (ipmiProxyIloIsSoftAuthFailure($bmcPath, $http0, $ct, $body)) {
        $detail = 'json_unauth';
        if (ipmiProxyIloBootstrapResponseLooksWrong($bmcPath, $ct, $body)) {
            $detail = 'bootstrap_mismatch';
        } elseif (str_contains(strtolower(trim(explode(';', $ct)[0] ?? '')), 'html') && ipmiProxyIloHtmlLooksUnauthed($body)) {
            $detail = 'html_login_like';
        }

        return [
            'recover'      => true,
            'reason'       => 'soft_auth:' . $detail,
            'kind'         => 'soft',
            'soft_detail'  => $detail,
        ];
    }

    return ['recover' => false, 'reason' => 'ok_or_not_actionable', 'kind' => 'none'];
}

/**
 * Normalized debug bucket for blank-iLO triage (see ipmi_proxy_debug.php).
 */
function ipmiProxyIloDebugFailureAxisFromReason(string $kind, string $reason): string
{
    if ($kind === 'soft' && str_contains($reason, 'semantic_bootstrap')) {
        return 'bootstrap_semantic';
    }
    if ($kind === 'soft') {
        return 'soft_auth';
    }
    if (str_starts_with($reason, 'curl_failed')) {
        return 'upstream_transport';
    }
    if (preg_match('/^http_/', $reason)) {
        return 'hard_http_auth';
    }

    return 'hard_failure';
}

/**
 * Single authoritative iLO buffered (non-SSE) recovery: refresh → reload DB row → rebuild headers → one retry.
 *
 * @param array<string, mixed> $result
 */
function ipmiProxyIloMaybeRecoverBufferedRuntime(
    mysqli $mysqli,
    string $token,
    array &$session,
    string &$bmcScheme,
    string $bmcIp,
    string $bmcPath,
    string $bmcPathOnlyLower,
    string $method,
    string $bmcUrl,
    ?string $postBody,
    string $fwdContentType,
    array &$result,
    string $ipmiTraceId
): void {
    if (!ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))) {
        return;
    }
    if (!empty($GLOBALS['__ipmi_ilo_runtime_recover_attempted'])) {
        return;
    }
    $pathRole = ipmiProxyClassifyIloPathRoleForSession($mysqli, $token, $session, $bmcPath, $method, $ipmiTraceId);
    $class = (string) ($pathRole['debug_class'] ?? 'other');
    $bootstrapCritical = !empty($pathRole['bootstrap_critical']) ? 1 : 0;
    $bootstrapState = ipmiProxyIloBootstrapStateLoad($session);
    $httpPre = (int) ($result['http_code'] ?? 0);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_state_loaded', [
            'trace'         => $ipmiTraceId,
            'bootstrap_pre' => (string) ($bootstrapState['phase'] ?? ''),
            'gate'          => 'buffered_recovery',
        ]);
        ipmiProxyDebugLog('ilo_path_role_classified', [
            'trace'              => $ipmiTraceId,
            'bmcPath'            => $bmcPath,
            'method'             => $method,
            'path_role'          => $pathRole['role'],
            'path_role_base'     => (string) ($pathRole['base_role'] ?? $pathRole['role']),
            'bootstrap_critical' => $bootstrapCritical,
            'recoverable'        => !empty($pathRole['recoverable']) ? 1 : 0,
        ]);
        if ($bootstrapCritical) {
            ipmiProxyDebugLog('ilo_bootstrap_critical_path_detected', [
                'trace'     => $ipmiTraceId,
                'bmcPath'   => $bmcPath,
                'path_role' => $pathRole['role'],
            ]);
        }
        ipmiProxyDebugLog('ilo_bootstrap_request_executed', [
            'trace'         => $ipmiTraceId,
            'bmcPath'       => $bmcPath,
            'http'          => $httpPre,
            'bootstrap_pre' => (string) ($bootstrapState['phase'] ?? ''),
            'path_role'     => $pathRole['role'],
        ]);
    }
    $decision = ipmiProxyIloClassifyBufferedRecovery($mysqli, $token, $session, $result, $bmcPath, $method, $ipmiTraceId);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_request_classified', [
            'trace'              => $ipmiTraceId,
            'bmcPath'            => $bmcPath,
            'method'             => $method,
            'path_class'         => $class,
            'path_role'          => $pathRole['role'],
            'bootstrap_critical' => $bootstrapCritical,
            'recover'            => $decision['recover'] ? 1 : 0,
            'reason'             => $decision['reason'],
            'kind'               => $decision['kind'],
        ]);
    }
    if (!$decision['recover']) {
        return;
    }
    if (!ipmiProxyIloCanAttemptAnotherRefresh($bootstrapState, $decision)) {
        $rts = is_array($bootstrapState['refresh_ts'] ?? null) ? $bootstrapState['refresh_ts'] : [];
        $recent = count(array_filter($rts, static fn($t) => $t > time() - 60));
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                'trace'          => $ipmiTraceId,
                'bmcPath'        => $bmcPath,
                'reason'         => $decision['reason'],
                'recent_refresh' => $recent,
                'bootstrap_phase' => (string) ($bootstrapState['phase'] ?? ''),
            ]);
            if ($recent >= 3) {
                ipmiProxyDebugLog('ilo_refresh_budget_exhausted', [
                    'trace'   => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                ]);
            }
            ipmiProxyDebugLog('ilo_bootstrap_recovery_decision', [
                'trace'        => $ipmiTraceId,
                'will_recover' => 0,
                'reason'       => 'refresh_budget',
                'kind'         => $decision['kind'],
            ]);
        }

        return;
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_recovery_decision', [
            'trace'          => $ipmiTraceId,
            'will_recover'   => 1,
            'reason'         => $decision['reason'],
            'kind'           => $decision['kind'],
            'failure_axis'   => ipmiProxyIloDebugFailureAxisFromReason((string) $decision['kind'], (string) $decision['reason']),
        ]);
        ipmiProxyDebugLog('ilo_bootstrap_recovery_decision', [
            'trace'          => $ipmiTraceId,
            'will_recover'   => 1,
            'bootstrap_pre'  => (string) ($bootstrapState['phase'] ?? ''),
            'reason'         => $decision['reason'],
            'failure_axis'   => ipmiProxyIloDebugFailureAxisFromReason((string) $decision['kind'], (string) $decision['reason']),
        ]);
        if ($decision['kind'] === 'soft') {
            ipmiProxyDebugLog('ilo_soft_auth_failure_detected', [
                'trace'          => $ipmiTraceId,
                'bmcPath'        => $bmcPath,
                'detail'         => (string) ($decision['soft_detail'] ?? ''),
                'failure_axis'   => ipmiProxyIloDebugFailureAxisFromReason('soft', (string) ($decision['reason'] ?? '')),
            ]);
        }
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_recovery_attempt', ['trace' => $ipmiTraceId, 'reason' => $decision['reason']]);
    }
    $bootstrapState = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $bootstrapState, $ipmiTraceId);
    if (!ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $ipmiTraceId, $decision['reason'])) {
        $bootstrapState = ipmiProxyIloRecordRefreshAttempt($mysqli, $token, $session, $bootstrapState, false, $ipmiTraceId);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_final_failure', [
                'trace'          => $ipmiTraceId,
                'bmcPath'        => $bmcPath,
                'phase'          => 'auth_refresh_failed',
                'reason'         => $decision['reason'],
                'path_class'     => $class,
                'failure_axis'   => 'auth_refresh_exhausted',
                'blank_ui_cause' => ipmiProxyIloBlankUiCause($bmcPath, 'auth_refresh_failed'),
            ]);
            ipmiProxyDebugLog('ilo_runtime_final_result', [
                'trace' => $ipmiTraceId,
                'outcome'  => 'auth_refresh_failed',
                'bmcPath'  => $bmcPath,
            ]);
        }

        return;
    }
    $bootstrapState = ipmiProxyIloRecordRefreshAttempt($mysqli, $token, $session, $bootstrapState, true, $ipmiTraceId);
    ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $ipmiTraceId);
    $fresh = ipmiProxyRebuildFreshIloRequestState($session, $bmcScheme, $bmcIp, $bmcPathOnlyLower, $ipmiTraceId);
    $GLOBALS['__ipmi_ilo_runtime_recover_attempted'] = true;
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_retry_executed', [
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'method'  => $method,
        ]);
        ipmiProxyDebugLog('ilo_bootstrap_retry_executed', [
            'trace'       => $ipmiTraceId,
            'bmcPath'     => $bmcPath,
            'fresh_state' => 1,
        ]);
    }
    $result = ipmiProxyExecute(
        $bmcUrl,
        $method,
        $postBody,
        $fwdContentType,
        $fresh['cookies'],
        $fresh['fwdHdr'],
        $bmcIp
    );
    $http1 = (int) ($result['http_code'] ?? 0);
    $okTransport = (($result['raw'] ?? false) !== false);
    $body1 = '';
    $ct1 = (string) ($result['content_type'] ?? '');
    if ($okTransport) {
        [, $body1] = ipmiWebCurlExtractFinalHeadersAndBody((string) $result['raw']);
    }
    $stillSoft = $okTransport && ipmiProxyIloIsSoftAuthFailure($bmcPath, $http1, $ct1, $body1);
    $hardBad = $okTransport && in_array($http1, [401, 403, 502, 503], true);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_final_result', [
            'trace'        => $ipmiTraceId,
            'bmcPath'      => $bmcPath,
            'http'         => $http1,
            'transport_ok' => $okTransport ? 1 : 0,
            'still_soft'   => $stillSoft ? 1 : 0,
            'hard_bad'     => $hardBad ? 1 : 0,
        ]);
    }
    if ($okTransport && $http1 >= 200 && $http1 < 400 && !$stillSoft && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_fragment_recovered', [
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
        ]);
    } elseif (ipmiProxyDebugEnabled() && $okTransport && ($hardBad || $stillSoft)) {
        $axisPost = 'hard_http_auth';
        if ($stillSoft) {
            $axisPost = ($class === 'helper_fragment') ? 'fragment_bootstrap_soft' : 'soft_auth';
        } elseif ($http1 >= 500) {
            $axisPost = 'upstream_transport';
        }
        ipmiProxyDebugLog('ilo_runtime_final_failure', [
            'trace'          => $ipmiTraceId,
            'bmcPath'        => $bmcPath,
            'phase'          => 'post_auth_retry_bad_http',
            'http'           => $http1,
            'path_class'     => $class,
            'still_soft_auth' => $stillSoft ? 1 : 0,
            'failure_axis'   => $axisPost,
            'blank_ui_cause' => $stillSoft ? 'soft_auth_failure' : ipmiProxyIloBlankUiCause($bmcPath, 'post_retry_http', ['http' => $http1]),
        ]);
    }
}

function ipmiProxyIsSupermicroRuntimeApiPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }

    return in_array($p, ['/cgi/xml_dispatcher.cgi', '/cgi/op.cgi', '/cgi/ipmi.cgi'], true);
}

function ipmiProxyIsAmiRuntimeApiPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }

    return str_starts_with($p, '/api/')
        || str_starts_with($p, '/rest/')
        || str_starts_with($p, '/rpc/')
        || $p === '/session'
        || str_starts_with($p, '/session/');
}

/**
 * Normalize proxy-relative targets so we can safely avoid self-redirect loops.
 */
function ipmiProxyCanonicalRelativeTarget(string $target): string
{
    $target = trim($target);
    if ($target === '') {
        return '/';
    }
    if (preg_match('#^https?://#i', $target)) {
        $p = parse_url($target, PHP_URL_PATH);
        $q = parse_url($target, PHP_URL_QUERY);
        $target = (string)($p ?? '/');
        if ($target === '') {
            $target = '/';
        }
        if (is_string($q) && $q !== '') {
            $target .= '?' . $q;
        }
    }

    $path = (string)parse_url($target, PHP_URL_PATH);
    if ($path === '') {
        $path = '/';
    }
    $query = (string)parse_url($target, PHP_URL_QUERY);
    return $query !== '' ? ($path . '?' . $query) : $path;
}

function ipmiProxyIsSameRelativeTarget(string $a, string $b): bool
{
    return ipmiProxyCanonicalRelativeTarget($a) === ipmiProxyCanonicalRelativeTarget($b);
}

/**
 * iDRAC quirk:
 * /restgui/start.html is a launcher page that usually redirects to /login.html.
 * If proxy forcibly redirects /login.html back to /restgui/start.html, browser loops forever.
 */
function ipmiProxyShouldSuppressIdracLandingRedirect(string $bmcType, string $currentTarget, string $landingPath): bool
{
    if (ipmiWebNormalizeBmcType($bmcType) !== 'idrac') {
        return false;
    }
    $landing = ipmiProxyCanonicalRelativeTarget($landingPath);
    $isIdracLauncherLanding = ipmiProxyIsSameRelativeTarget($landing, '/restgui/start.html')
        || ipmiProxyIsSameRelativeTarget($landing, '/start.html')
        || ipmiProxyIsSameRelativeTarget($landing, '/restgui/launch');
    if (!$isIdracLauncherLanding) {
        return false;
    }
    $cur = strtolower((string) parse_url(ipmiProxyCanonicalRelativeTarget($currentTarget), PHP_URL_PATH));
    return $cur === '/login.html'
        || $cur === '/login'
        || $cur === '/start.html'
        || $cur === '/restgui/start.html'
        || $cur === '/restgui/launch';
}

function ipmiProxyBodyHasSessionTimeout(string $body): bool
{
    if ($body === '') {
        return false;
    }
    if (ipmiProxyBodyLooksLikeSupermicroTopmenuAuthed($body)) {
        return false;
    }
    if (ipmiWebResponseLooksLikeIloAuthedShell($body)) {
        return false;
    }
    // Ignore timeout strings embedded in JS constants; only inspect visible HTML text.
    $visible = preg_replace('~<script\b[^>]*>.*?</script>~is', ' ', $body);
    if (!is_string($visible)) {
        $visible = $body;
    }
    $visible = preg_replace('~<style\b[^>]*>.*?</style>~is', ' ', $visible);
    if (!is_string($visible)) {
        $visible = $body;
    }
    $snippet = strtolower(substr($visible, 0, 200000));
    if (strpos($snippet, 'ipmi session expired') !== false) {
        return true;
    }
    if (strpos($snippet, 'you will need to open a new session') !== false) {
        return true;
    }

    return (strpos($snippet, 'session has timed out') !== false || strpos($snippet, 'session timed out') !== false)
        && (strpos($snippet, 'please log in a new session') !== false || strpos($snippet, 'please login in a new session') !== false);
}

function ipmiProxyBodyLooksLikeIdracLauncherShell(string $body): bool
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

function ipmiProxyBodyLooksLikeSupermicroTopmenuAuthed(string $body): bool
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
    if (
        strpos($l, "sessionstorage.setitem ('_x_auth'") !== false
        || strpos($l, 'sessionstorage.setitem("_x_auth"') !== false
    ) {
        $hits++;
    }
    if (strpos($l, 'new redfish (null, session_id)') !== false) {
        $hits++;
    }

    return $hits >= 2;
}

function ipmiProxyBodyLooksLikeSupermicroTimeoutShell(string $body): bool
{
    if ($body === '') {
        return false;
    }
    if (ipmiProxyBodyLooksLikeSupermicroTopmenuAuthed($body)) {
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

function ipmiProxyBodyLooksLikeSupermicroApiAuthFailure(string $body): bool
{
    if ($body === '') {
        return false;
    }
    if (ipmiProxyBodyHasSessionTimeout($body) || ipmiProxyBodyLooksLikeSupermicroTimeoutShell($body)) {
        return true;
    }

    $l = strtolower(substr($body, 0, 120000));
    if ($l === '') {
        return false;
    }

    if (strpos($l, 'please log in a new session') !== false || strpos($l, 'please login in a new session') !== false) {
        return true;
    }
    if (strpos($l, 'your session has timed out') !== false || strpos($l, 'session timed out') !== false) {
        return true;
    }
    if (strpos($l, 'invalid session') !== false || strpos($l, 'no valid session') !== false) {
        return true;
    }
    if (strpos($l, 'session expired') !== false) {
        return true;
    }

    return false;
}

function ipmiProxyBodyLooksLikeJavaOnlyIloConsole(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $sample = strtolower(substr((string) $body, 0, 200000));
    if ($sample === '') {
        return false;
    }

    return str_contains($sample, 'java integrated remote console')
        && str_contains($sample, 'applet-based console')
        && str_contains($sample, 'requiring the availability of java');
}

function ipmiProxyBodyLooksLikeIloHtml5ConsoleUnavailable(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $sample = strtolower(substr((string) $body, 0, 200000));
    if ($sample === '') {
        return false;
    }

    return str_contains($sample, 'standalone html5 console not yet available')
        || (str_contains($sample, 'html5 console') && str_contains($sample, 'not yet available'));
}

function ipmiProxyIsKvmAutoFlowRequest(): bool
{
    $autoQuery = ((string) ($_GET['ipmi_kvm_auto'] ?? '') === '1');
    $legacyQuery = ((string) ($_GET['ipmi_kvm_legacy'] ?? '') === '1');
    $autoCookie = ((string) ($_COOKIE['IPMI_KVM_AUTO'] ?? '') === '1');
    $legacyCookie = ((string) ($_COOKIE['IPMI_KVM_LEGACY'] ?? '') === '1');
    $ref = strtolower((string) ($_SERVER['HTTP_REFERER'] ?? ''));
    $autoRef = str_contains($ref, 'ipmi_kvm_auto=1');
    $legacyRef = str_contains($ref, 'ipmi_kvm_legacy=1');

    $auto = $autoQuery || $autoCookie || $autoRef;
    $legacy = $legacyQuery || $legacyCookie || $legacyRef;

    return $auto && !$legacy;
}

function ipmiProxyLooksLikeLoginPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    return $p === '/login' || $p === '/login.html' || $p === '/signin' || $p === '/signin.html';
}

function ipmiProxyPostAuthLandingPath(string $bmcType): string
{
    return ipmiWebPostLoginLandingPath((string) $bmcType);
}

function ipmiProxyEmitSessionExpiredPage(string $message = ''): void
{
    $msg = trim($message) !== '' ? $message : 'Your BMC web session has timed out. Open a new session from the panel.';
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    $safeMsg = htmlspecialchars($msg, ENT_QUOTES, 'UTF-8');
    $back = htmlspecialchars('/index.php', ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>IPMI Session Expired</title>'
        . '<style>body{font-family:Arial,sans-serif;background:#0b1630;color:#dce6ff;margin:0;padding:28px}'
        . '.card{max-width:760px;margin:30px auto;background:#1b2a47;border-radius:10px;padding:24px;border:1px solid #2b3d60}'
        . 'a{color:#7fc0ff} .btn{display:inline-block;margin-right:10px;margin-top:14px;padding:10px 14px;'
        . 'border-radius:7px;background:#22477a;color:#fff;text-decoration:none}</style></head><body>'
        . '<div class="card"><h2 style="margin-top:0">IPMI Session Expired</h2><p>' . $safeMsg . '</p>'
        . '<a class="btn" href="' . $back . '">Back to panel</a></div></body></html>';
    exit;
}

function ipmiProxyEmitKvmModeChoicePage(string $tokenPrefix, string $title, string $message): void
{
    http_response_code(200);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    $safeTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $safeMsg = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    $browserUrl = htmlspecialchars($tokenPrefix . '/html/application.html?ipmi_kvm_auto=1&ipmi_kvm_force_html5=1', ENT_QUOTES, 'UTF-8');
    $dashUrl = htmlspecialchars($tokenPrefix . '/index.html', ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>' . $safeTitle . '</title>'
        . '<style>body{font-family:Arial,sans-serif;background:#0b1630;color:#dce6ff;margin:0;padding:28px}'
        . '.card{max-width:860px;margin:28px auto;background:#1b2a47;border-radius:10px;padding:24px;border:1px solid #2b3d60}'
        . '.btn{display:inline-block;margin:10px 10px 0 0;padding:10px 14px;border-radius:7px;background:#22477a;color:#fff;text-decoration:none}'
        . '.btn-alt{background:#2f5f2f}.btn-low{background:#3b3f58}</style></head><body>'
        . '<div class="card"><h2 style="margin-top:0">' . $safeTitle . '</h2><p>' . $safeMsg . '</p>'
        . '<a class="btn btn-alt" href="' . $browserUrl . '">Try Browser HTML5 Console</a>'
        . '<a class="btn btn-low" href="' . $dashUrl . '">Back to iLO Dashboard</a>'
        . '</div></body></html>';
    exit;
}

function ipmiProxyIsBmcStaticAssetPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }
    foreach (['/js/', '/css/', '/fonts/', '/themes/', '/img/', '/images/'] as $prefix) {
        if (str_contains($p, $prefix)) {
            return true;
        }
    }

    return (bool) preg_match('/\.(?:js|css|png|svg|jpg|jpeg|gif|webp|ico|woff2?|ttf|eot|map|jar|jnlp|class|cab)$/', $p);
}

/**
 * Per-URL cURL total timeout for buffered ipmiProxyExecute (non-streaming GET/POST).
 */
function ipmiProxyCurlTimeoutForBmcUrl(string $bmcUrl): int
{
    $path = strtolower((string) (parse_url($bmcUrl, PHP_URL_PATH) ?? ''));
    // Health poll endpoints are very chatty on iLO; keep timeout bounded to avoid worker starvation.
    if (str_contains($path, '/json/health') || str_contains($path, 'health_summary')) {
        return 25;
    }
    // Keep static assets under common FastCGI/proxy timeouts to avoid 502 before PHP responds.
    if (ipmiProxyIsBmcStaticAssetPath($path)) {
        return 20;
    }

    return 60;
}

/**
 * Paths that must be streamed (bytes forwarded as they arrive), not buffered in PHP.
 * Only true SSE/event-stream endpoints are streamed.
 */
function ipmiProxyIsBmcLongPollOrStreamPath(string $bmcPath): bool
{
    $p = strtolower($bmcPath);
    if (str_starts_with($p, '/sse/') || str_contains($p, 'event_stream') || str_contains($p, 'eventstream')) {
        return true;
    }
    $acc = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));

    return str_contains($acc, 'text/event-stream');
}

/**
 * Execute the proxy request. Extracted so we can retry after auth recovery.
 * Retries once without CURLOPT_RESOLVE if the first attempt fails (bad PTR / libcurl quirk).
 *
 * @param int|null $timeoutOverride Total cURL timeout in seconds; null = ipmiProxyCurlTimeoutForBmcUrl($bmcUrl).
 */
function ipmiProxyExecute(string $bmcUrl, string $method, ?string $postBody, string $fwdContentType, array $cookies, array $forwardHeaders = [], string $bmcIp = '', ?int $timeoutOverride = null): array
{
    $bmcIpEff = $bmcIp !== '' ? $bmcIp : (string) (parse_url($bmcUrl, PHP_URL_HOST) ?? '');

    $attemptResolve = function (bool $tryResolve) use ($bmcUrl, $method, $postBody, $fwdContentType, $cookies, $forwardHeaders, $bmcIpEff, $timeoutOverride): array {
        $ch = curl_init($bmcUrl);
        $appliedResolve = false;
        if ($tryResolve) {
            $appliedResolve = ipmiProxyApplyCurlBmcUrlAndResolve($ch, $bmcUrl, $bmcIpEff);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $effTimeout = $timeoutOverride !== null ? $timeoutOverride : ipmiProxyCurlTimeoutForBmcUrl($bmcUrl);
        curl_setopt($ch, CURLOPT_TIMEOUT, $effTimeout);
        if ($effTimeout > 0) {
            curl_setopt($ch, CURLOPT_NOSIGNAL, true);
        }
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        ipmiProxyApplyCurlBmcReferer($ch, $bmcUrl, $forwardHeaders, $bmcIpEff);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($postBody !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);
            }
        }

        $parts = [];
        foreach ($cookies as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }

        $headers = [];
        if ($fwdContentType !== '') {
            $headers[] = 'Content-Type: ' . $fwdContentType;
        }
        foreach ($forwardHeaders as $hn => $hv) {
            $hn = trim((string) $hn);
            if ($hn === '' || strcasecmp($hn, 'Content-Type') === 0) {
                continue;
            }
            if ($hv === null || trim((string) $hv) === '') {
                continue;
            }
            $headers[] = $hn . ': ' . $hv;
        }
        if ($headers !== []) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $rawResponse = curl_exec($ch);
        $curlErrNo = ($rawResponse === false) ? curl_errno($ch) : 0;
        $curlErrStr = ($rawResponse === false) ? (string) curl_error($ch) : '';
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentTypeResp = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        return [
            'raw'             => $rawResponse,
            'http_code'       => $httpCode,
            'content_type'    => $contentTypeResp,
            'applied_resolve' => $appliedResolve,
            'curl_errno'      => $curlErrNo,
            'curl_error'      => $curlErrStr,
        ];
    };

    $out = $attemptResolve(true);
    if (($out['raw'] === false || $out['http_code'] === 0) && $out['applied_resolve']) {
        $out = $attemptResolve(false);
    }
    // Some iLO builds return 403 on API when SNI uses PTR hostname but accept the same session over https://&lt;IP&gt;/...
    if ($out['raw'] !== false && (int) $out['http_code'] === 403 && !empty($out['applied_resolve'])) {
        $out2 = $attemptResolve(false);
        if ($out2['raw'] !== false) {
            $out = $out2;
        }
    }

    return [
        'raw'          => $out['raw'],
        'http_code'    => $out['http_code'],
        'content_type' => $out['content_type'],
        'curl_errno'   => (int) ($out['curl_errno'] ?? 0),
        'curl_error'   => (string) ($out['curl_error'] ?? ''),
    ];
}

function ipmiProxyForwardHeadersHasHeader(array $forwardHeaders, string $needleName): bool
{
    $n = strtolower($needleName);
    foreach ($forwardHeaders as $k => $_v) {
        if (strtolower(trim((string) $k)) === $n) {
            return true;
        }
    }

    return false;
}

/**
 * Some BMCs reject API/SSE requests without a Referer from the BMC origin.
 */
function ipmiProxyApplyCurlBmcReferer($ch, string $bmcUrl, array $forwardHeaders, string $bmcIp): void
{
    if (ipmiProxyForwardHeadersHasHeader($forwardHeaders, 'Referer')) {
        return;
    }
    $p = parse_url($bmcUrl);
    if (!is_array($p) || empty($p['scheme'])) {
        return;
    }
    if ($bmcIp === '') {
        $bmcIp = (string) ($p['host'] ?? '');
    }
    $host = ipmiProxyBmcPreferredOriginHost($bmcIp);
    $port = isset($p['port']) ? ':' . (int) $p['port'] : '';
    curl_setopt($ch, CURLOPT_REFERER, $p['scheme'] . '://' . $host . $port . '/');
}

function ipmiProxyGetClientXAuthToken(): string
{
    $t = trim((string) ($_SERVER['HTTP_X_AUTH_TOKEN'] ?? ''));
    if ($t !== '') {
        return $t;
    }
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $name => $value) {
            if (strcasecmp((string) $name, 'X-Auth-Token') === 0) {
                return trim((string) $value);
            }
        }
    }

    return '';
}

/**
 * Browser sends Origin: https://panel-host; many BMCs reject that and return 403 on API/SSE/CSS.
 * The SPA may also hold a fresher X-Auth-Token than the DB after client-side login.
 *
 * @param array<string, string> $forwardHeaders
 * @return array<string, string>
 */
function ipmiProxyMergeClientBmcForwardHeaders(array $forwardHeaders, string $bmcScheme, string $bmcIp, array $cookieJar = []): array
{
    $out = $forwardHeaders;
    $xAuth = ipmiProxyGetClientXAuthToken();
    if ($xAuth === '') {
        foreach (['sessionKey', 'session', 'X-Auth-Token', 'x-auth-token'] as $k) {
            $v = trim((string) ($cookieJar[$k] ?? ''));
            if ($v !== '') {
                $xAuth = $v;
                break;
            }
        }
    }
    if ($xAuth !== '') {
        $out['X-Auth-Token'] = $xAuth;
    }
    $bmcScheme = ($bmcScheme === 'http') ? 'http' : 'https';
    $out['Origin'] = $bmcScheme . '://' . ipmiProxyBmcPreferredOriginHost($bmcIp);

    return $out;
}

/**
 * Sync Origin / X-Auth-Token for streamed BMC requests; for iLO, verify / repair JSON session before SSE.
 */
function ipmiProxyRecoverBmcAuthBeforeSse(array &$session, mysqli $mysqli, string $token, string $bmcIp, string &$bmcScheme, array &$fwdHdr, string $traceId = ''): void
{
    $bmcScheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $typeNorm = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
    if (ipmiWebIsNormalizedIloType($typeNorm)) {
        $baseUrl = $bmcScheme . '://' . $bmcIp;
        $v = ipmiWebIloVerifyAuthed(
            $baseUrl,
            $bmcIp,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : [],
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : []
        );
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_sse_precheck', [
                'trace'    => $traceId,
                'verified' => $v ? 1 : 0,
            ]);
        }
        if (!$v) {
            $ssePreState = ipmiProxyIloBootstrapStateLoad($session);
            $ssePreDecision = ['kind' => 'hard', 'reason' => 'sse_precheck_failed'];
            if (!ipmiProxyIloCanAttemptAnotherRefresh($ssePreState, $ssePreDecision)) {
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                        'trace'  => $traceId,
                        'gate'   => 'sse_precheck',
                        'reason' => 'refresh_budget',
                    ]);
                }
            } else {
                $ssePreState = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $ssePreState, $traceId);
                ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $traceId, 'sse_precheck_failed');
            }
        }
    }
    $fwdHdr = ipmiProxyMergeClientBmcForwardHeaders(
        is_array($fwdHdr) ? $fwdHdr : [],
        $bmcScheme,
        $bmcIp,
        is_array($session['cookies'] ?? null) ? $session['cookies'] : []
    );
}

/**
 * Long-lived Server-Sent Events (and similar) must be streamed. Buffering the full response
 * in PHP (CURLOPT_RETURNTRANSFER) blocks until the BMC closes the stream → endless "loading".
 */
function ipmiProxyShouldStreamBmcRequest(string $method, string $bmcPath): bool
{
    if ($method !== 'GET') {
        return false;
    }

    return ipmiProxyIsBmcLongPollOrStreamPath($bmcPath);
}

function ipmiProxyEmitHealthPollFallbackJson(): void
{
    http_response_code(200);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    echo '{}';
}

function ipmiProxyEmitSseRetryHint(): void
{
    http_response_code(200);
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');
    echo "retry: 5000\n\n";
    if (ob_get_level() > 0) {
        @ob_flush();
    }
    flush();
}

/**
 * For static asset transport failures, avoid hard 502 responses that break the whole BMC UI shell.
 * We only provide safe fallbacks for non-executable assets (css/fonts/images), never JS.
 */
function ipmiProxyTryEmitStaticFallback(string $bmcPath): bool
{
    $path = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($path === '') {
        return false;
    }
    $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
    if ($ext === '') {
        return false;
    }

    // Fonts/maps: no-content is acceptable and avoids noisy 502s.
    if (in_array($ext, ['woff', 'woff2', 'ttf', 'eot', 'otf', 'map'], true)) {
        http_response_code(204);
        header('Cache-Control: private, max-age=120');
        return true;
    }

    if ($ext === 'css') {
        http_response_code(200);
        header('Content-Type: text/css; charset=utf-8');
        header('Cache-Control: private, max-age=120');
        echo "/* ipmi-proxy fallback css: upstream asset unavailable */\n";
        return true;
    }

    if ($ext === 'svg') {
        http_response_code(200);
        header('Content-Type: image/svg+xml; charset=utf-8');
        header('Cache-Control: private, max-age=120');
        echo '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>';
        return true;
    }

    if (in_array($ext, ['png', 'gif', 'webp'], true)) {
        http_response_code(200);
        header('Content-Type: image/png');
        header('Cache-Control: private, max-age=120');
        // 1x1 transparent PNG
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=');
        return true;
    }

    if (in_array($ext, ['jpg', 'jpeg'], true)) {
        http_response_code(200);
        header('Content-Type: image/jpeg');
        header('Cache-Control: private, max-age=120');
        // 1x1 white JPEG
        echo base64_decode('/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxAQEBAQEA8PEA8QDw8PDw8PDw8QEA8QFREWFhURFRUYHSggGBolGxUVITEhJSkrLi4uFx8zODMsNygtLisBCgoKDQ0NFQ8PFSsdFR0rKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK//AABEIAAEAAQMBIgACEQEDEQH/xAAXAAEBAQEAAAAAAAAAAAAAAAAAAQID/8QAFhEBAQEAAAAAAAAAAAAAAAAAAAER/9oADAMBAAIQAxAAAAHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/Z');
        return true;
    }

    if ($ext === 'ico') {
        http_response_code(204);
        header('Cache-Control: private, max-age=120');
        return true;
    }

    return false;
}

/**
 * Stream SSE or long-poll JSON from the BMC. Aborts before sending bytes if status is 401/403/502/503 (502/503: recoverable upstream — proxy may refresh auth and retry once).
 *
 * @return array{ok: bool, auth_rejected: bool, applied_resolve: bool, curl_errno?: int, curl_error?: string, sse_recoverable_http?: bool, sse_recover_http_code?: int}
 */
function ipmiProxyStreamGetBmcResponse(string $bmcUrl, array $cookies, array $forwardHeaders, string $bmcIp, bool $skipHostnameResolve = false): array
{
    $streamPath = strtolower((string) (parse_url($bmcUrl, PHP_URL_PATH) ?? ''));
    $defaultStreamCt = (str_contains($streamPath, '/json/health') || str_contains($streamPath, 'health_summary'))
        ? 'application/json; charset=utf-8'
        : 'text/event-stream';

    $ch = curl_init($bmcUrl);
    $appliedResolve = false;
    if (!$skipHostnameResolve) {
        $appliedResolve = ipmiProxyApplyCurlBmcUrlAndResolve($ch, $bmcUrl, $bmcIp);
    }
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 0);
    // SSE and some BMC long-polls are unreliable over HTTP/2 with libcurl; iLO uses HTTP/1.1 in practice.
    if (defined('CURL_HTTP_VERSION_1_1')) {
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    }
    curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
    curl_setopt($ch, CURLOPT_HTTPGET, true);
    ipmiProxyApplyCurlBmcReferer($ch, $bmcUrl, $forwardHeaders, $bmcIp);

    $parts = [];
    foreach ($cookies as $k => $v) {
        if ($v !== null && trim((string) $v) !== '') {
            $parts[] = $k . '=' . $v;
        }
    }
    $reqH = ['Accept-Encoding: identity'];
    $acc = (string) ($_SERVER['HTTP_ACCEPT'] ?? '');
    if ($acc !== '') {
        $reqH[] = 'Accept: ' . $acc;
    }
    foreach ($forwardHeaders as $hn => $hv) {
        $hn = trim((string) $hn);
        if ($hn === '' || strcasecmp($hn, 'Content-Type') === 0) {
            continue;
        }
        if ($hv === null || trim((string) $hv) === '') {
            continue;
        }
        $reqH[] = $hn . ': ' . $hv;
    }
    if ($parts !== []) {
        $reqH[] = 'Cookie: ' . implode('; ', $parts);
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $reqH);

    $lines = [];
    $headersSent = false;
    $authRejected = false;
    $sseRecoverableHttp = false;
    $sseRecoverableHttpCode = 0;
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($curl, $headerLine) use (&$lines, &$headersSent, &$authRejected, &$sseRecoverableHttp, &$sseRecoverableHttpCode, $defaultStreamCt): int {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $headerLine, $hm)) {
            $code = (int) $hm[1];
            if ($code === 401 || $code === 403) {
                $authRejected = true;

                return 0;
            }
            if ($code === 502 || $code === 503) {
                $sseRecoverableHttp = true;
                $sseRecoverableHttpCode = $code;

                return 0;
            }
        }
        // HTTP/2 pseudo-header from libcurl
        if (preg_match('/^:\s*status:\s*(\d{3})\b/i', trim((string) $headerLine), $hm)) {
            $code = (int) $hm[1];
            if ($code === 401 || $code === 403) {
                $authRejected = true;

                return 0;
            }
            if ($code === 502 || $code === 503) {
                $sseRecoverableHttp = true;
                $sseRecoverableHttpCode = $code;

                return 0;
            }
        }
        if ($headerLine === "\r\n" || $headerLine === "\n") {
            if (!$headersSent && $lines !== []) {
                $block = implode('', $lines);
                $lines = [];
                $code = 200;
                if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/m', $block, $m)) {
                    $code = (int) $m[1];
                } elseif (preg_match('/^:\s*status:\s*(\d{3})\b/im', $block, $m)) {
                    $code = (int) $m[1];
                }
                http_response_code($code);
                $ct = $defaultStreamCt;
                if (preg_match('/^Content-Type:\s*([^\r\n]+)/mi', $block, $cm)) {
                    $ct = trim($cm[1]);
                }
                header('Content-Type: ' . $ct);
                header('Cache-Control: no-cache');
                header('X-Accel-Buffering: no');
                if (function_exists('apache_setenv')) {
                    @apache_setenv('no-gzip', '1');
                }
                $headersSent = true;
            } else {
                $lines = [];
            }

            return strlen($headerLine);
        }
        $lines[] = $headerLine;

        return strlen($headerLine);
    });

    curl_setopt($ch, CURLOPT_WRITEFUNCTION, static function ($curl, $data): int {
        echo $data;
        if (ob_get_level() > 0) {
            @ob_flush();
        }
        flush();

        return strlen($data);
    });

    $ok = curl_exec($ch);
    $curlErr = ($ok === false);
    $curlErrNo = $curlErr ? curl_errno($ch) : 0;
    $curlErrStr = $curlErr ? curl_error($ch) : '';
    curl_close($ch);

    if ($authRejected) {
        return ['ok' => false, 'auth_rejected' => true, 'applied_resolve' => $appliedResolve];
    }
    if ($sseRecoverableHttp) {
        return [
            'ok'                   => false,
            'auth_rejected'        => false,
            'applied_resolve'      => $appliedResolve,
            'sse_recoverable_http' => true,
            'sse_recover_http_code' => $sseRecoverableHttpCode,
        ];
    }
    if ($curlErr) {
        return [
            'ok'               => false,
            'auth_rejected'    => false,
            'applied_resolve'  => $appliedResolve,
            'curl_errno'       => $curlErrNo,
            'curl_error'       => $curlErrStr,
        ];
    }

    return ['ok' => true, 'auth_rejected' => false, 'applied_resolve' => $appliedResolve];
}

/**
 * Overlay Cookie header from the browser for keys we already store (mirrored BMC cookies).
 * Keeps client and server jars aligned after Set-Cookie mirror.
 */
function ipmiProxyMergeClientBmcCookies(array $dbCookies, string $bmcType = ''): array
{
    if ($dbCookies === []) {
        return $dbCookies;
    }
    $typeNorm = ipmiWebNormalizeBmcType((string) $bmcType);
    $raw = (string)($_SERVER['HTTP_COOKIE'] ?? '');
    if ($raw === '') {
        return $dbCookies;
    }
    $out = $dbCookies;
    $blockOverride = [];
    if ($typeNorm === 'supermicro' || $typeNorm === 'ami') {
        // Keep critical auth cookies from being overwritten, but allow JS-set cookies (e.g. QSESSIONID)
        // to be added so the SPA doesn't logout immediately.
        $blockOverride = ['sid' => true, 'sessionid' => true, 'session_id' => true, 'session' => true];
    }
    foreach (explode(';', $raw) as $chunk) {
        $chunk = trim($chunk);
        if ($chunk === '') {
            continue;
        }
        $eq = strpos($chunk, '=');
        if ($eq === false) {
            continue;
        }
        $name = trim(substr($chunk, 0, $eq));
        $value = trim(substr($chunk, $eq + 1));
        if ($name === '' || $value === '') {
            continue;
        }
        if (strcasecmp($name, 'PHPSESSID') === 0) {
            continue;
        }
        if ($typeNorm === 'supermicro' || $typeNorm === 'ami') {
            $lname = strtolower($name);
            if (isset($blockOverride[$lname])) {
                continue;
            }
        }
        if (array_key_exists($name, $out)) {
            if ($typeNorm === 'ami') {
                $out[$name] = $value;
                continue;
            }
            // Only override if server-side cookie is missing/invalid.
            if (!ipmiWebIsAuthValueUsable($out[$name])) {
                $out[$name] = $value;
            }
        } elseif ($typeNorm === 'supermicro' || $typeNorm === 'ami') {
            // Allow adding new cookies for Supermicro/ASRockRack/AMI SPA flows.
            $out[$name] = $value;
        }
    }

    return $out;
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
                } elseif (
                    !empty($r['sse_recoverable_http'])
                    || (isset($r['curl_errno']) && (int) $r['curl_errno'] !== 0)
                ) {
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
            if (
                ipmiProxyDebugEnabled()
                && ipmiWebIsNormalizedIloType($bmcTypeNorm)
                && ipmiProxyIsIloEventStreamPath($bmcPath)
            ) {
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
    if (
        ipmiProxyDebugEnabled()
        && ipmiWebIsNormalizedIloType($bmcTypeNorm)
        && ipmiProxyIsIloRecoverableRuntimePath($bmcPath)
        && !empty($GLOBALS['__ipmi_ilo_runtime_recover_attempted'])
    ) {
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
    if (
        $isH5Banner
        || ($dir === '/' && preg_match('/\\.(?:png|jpg|jpeg|gif|svg)$/i', $file))
        || (preg_match('/\\/(?:res|resources|assets)(?:\\/oem)?\\/?$/i', $dir) && preg_match('/\\.(?:png|jpg|jpeg|gif|svg)$/i', $file))
    ) {
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
if (
    $method === 'GET' && $httpCode === 200 && $isHtml && $isAssetPath
    && ($looksLikeLoginPage || $hasTimeoutText || $looksLikeSmTimeoutShell)
) {
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

if (
    $method === 'GET' && $httpCode === 200 && $isHtml && !$isAssetPath
    && ($looksLikeLoginPage || $hasTimeoutText || $looksLikeSmTimeoutShell)
) {
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
        if ($kvmFam === 'ilo' && in_array($kvmAutoPath, ['/', '/index.html', '/html/application.html', '/html/summary.html', '/html/rc_info.html', '/html/jnlp_template.html'], true)) {
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
                $kvmAutolaunchInjectMeta,
                $bmcPath
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
