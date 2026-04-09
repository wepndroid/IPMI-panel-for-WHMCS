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
    $body = preg_replace_callback(
        '#\b(wss|ws):\\\\/\\\\/' . $q . '(?::\\d+)?((?:\\\\/[^"\\\\]*)*)#i',
        $cb,
        $body
    );
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
    return preg_replace_callback(
        '#\b(wss|ws)://' . $q . '(?::\d+)?(/[^"\'\\\\s\)\]\},;]*)?#i',
        static function (array $m) use ($bmcHost, $token): string {
            $scheme = strtolower($m[1]);
            $path = (isset($m[2]) && $m[2] !== '') ? $m[2] : '/';
            $fullTarget = $scheme . '://' . $bmcHost . $path;
            return '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=' . rawurlencode($fullTarget);
        },
        $body
    );
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
        . 'var P=' . $pxJs . ';var A=' . $xJs . ';var H=' . $hostsJs . ';'
        . 'var R=["/redfish/v1/","/redfish/","/rest/v1/","/rest/","/js/","/css/","/fonts/","/img/","/images/","/json/","/api/","/html/","/themes/","/sse/","/cgi/","/favicon.ico"];'
        . 'var L=location;var po=L.protocol+"//"+L.host;'
        . 'function iH(h){if(!h)return false;h=String(h).toLowerCase();for(var i=0;i<H.length;i++){if(H[i]&&String(H[i]).toLowerCase()===h)return true;}return false;}'
        . 'function sp(s){if(typeof s!=="string"||s.indexOf(P)===0)return false;for(var i=0;i<R.length;i++){if(s.indexOf(R[i])===0)return true;}return false;}'
        . 'function fu(s){if(typeof s!=="string")return s;if(s.indexOf(po+P)===0)return s;try{var u=new URL(s,po);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());if(sh&&u.pathname.indexOf(P)===0)return po+u.pathname+u.search+u.hash;if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname)))return po+P+u.pathname+u.search+u.hash;}catch(e){}return sp(s)?po+P+s:s;}'
        . 'function fx(n){if(typeof A!=="string"||!A)return n;n=n||{};try{var Hd=new Headers(n.headers||{});if(!Hd.has("X-Auth-Token"))Hd.set("X-Auth-Token",A);n.headers=Hd;}catch(e){}return n;}'
        . 'if(window.fetch){var of=window.fetch;window.fetch=function(i,n){try{n=fx(n||{});'
        . 'if(typeof i==="string")return of.call(this,fu(i),n);'
        . 'if(window.Request&&i instanceof Request){if(i.url.indexOf(po+P)===0)return of.call(this,i,n);var u=new URL(i.url,L.href);'
        . 'if(iH(u.hostname)||(u.origin===po&&sp(u.pathname))){var nu=po+P+u.pathname+u.search+u.hash;var Rq=new Request(nu,i);try{var H2=new Headers(Rq.headers);if(typeof A==="string"&&A&&!H2.has("X-Auth-Token"))H2.set("X-Auth-Token",A);Rq=new Request(Rq,{headers:H2});}catch(e2){}return of.call(this,Rq,n);}}'
        . '}catch(e){}return of.call(this,i,n);};}'
        . 'var xp=XMLHttpRequest&&XMLHttpRequest.prototype;if(xp&&xp.open){var oo=xp.open;xp.open=function(m,u,a3,a4,a5){try{if(typeof u==="string")u=fu(u);}catch(e){}return oo.call(this,m,u,a3,a4,a5);};}'
        . 'if(xp&&xp.send){var xs=xp.send;xp.send=function(b){try{if(typeof A==="string"&&A){try{this.setRequestHeader("X-Auth-Token",A);}catch(e3){}}}catch(e4){}return xs.call(this,b);};}'
        . 'if(window.WebSocket){var OW=WebSocket;window.WebSocket=function(u,p){try{'
        . 'if(typeof u==="string"){var wu=new URL(u,L.href);if(iH(wu.hostname)||sp(wu.pathname)||(wu.origin===po&&sp(wu.pathname)))'
        . 'u=(L.protocol==="https:"?"wss:":"ws:")+"//"+L.host+P+wu.pathname+wu.search;}'
        . '}catch(e){}return new OW(u,p);};}'
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

    return preg_replace('/<head(\s[^>]*)?>/i', '$0' . $patch, $html, 1) ?? $html;
}

function ipmiProxyIsIloFamily(string $bmcType): bool
{
    $t = strtolower(trim($bmcType));
    return $t === 'ilo4' || str_starts_with($t, 'ilo') || str_contains($t, 'ilo');
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
    bool $forceSupermicroLegacy = false
): string
{
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
    $patch = '<script data-ipmi-proxy-generic-patch="1">'
        . '(function(){'
        . 'try{var _a=window.alert;window.alert=function(msg){try{var s=String(msg||"").toLowerCase();'
        . 'if(s.indexOf("session has timed out")>=0||s.indexOf("session timed out")>=0||s.indexOf("session is running")>=0||s.indexOf("already a session")>=0){return;}'
        . '}catch(e){}return _a.apply(this,arguments);};}catch(e){}'
        . 'var P=' . $pxJs . ';var A=' . $authJs . ';var C=' . $csrfJs . ';var H=' . $hostsJs . ';'
        . 'var R=["/redfish/v1/","/redfish/","/rest/v1/","/rest/","/session","/data/","/rpc/","/js/","/css/","/fonts/","/img/","/images/","/json/","/api/","/html/","/themes/","/sse/","/cgi/","/res/","/favicon.ico"];'
        . 'var L=location;var po=L.protocol+"//"+L.host;'
        . 'var F=' . $forceSm . ';'
        . 'if(F){try{if(window.sessionStorage&&!sessionStorage.getItem("_x_auth")){sessionStorage.setItem("_x_auth","ipmi_proxy");}}catch(e0){}}'
        . 'function iH(h){if(!h)return false;h=String(h).toLowerCase();for(var i=0;i<H.length;i++){if(H[i]&&String(H[i]).toLowerCase()===h)return true;}return false;}'
        . 'function sp(s){if(typeof s!=="string"||s.indexOf(P)===0)return false;for(var i=0;i<R.length;i++){if(s.indexOf(R[i])===0)return true;}return false;}'
        . 'function fu(s){if(typeof s!=="string")return s;if(s.indexOf(po+P)===0)return s;try{var u=new URL(s,po);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());if(sh&&u.pathname.indexOf(P)===0)return po+u.pathname+u.search+u.hash;if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname)))return po+P+u.pathname+u.search+u.hash;}catch(e){}return sp(s)?po+P+s:s;}'
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
        . 'if(window.WebSocket){var OW=WebSocket;window.WebSocket=function(u,p){try{if(typeof u==="string"){var wu=new URL(u,L.href);'
        . 'if(iH(wu.hostname)||sp(wu.pathname)||(wu.origin===po&&sp(wu.pathname)))u=(L.protocol==="https:"?"wss:":"ws:")+"//"+L.host+P+wu.pathname+wu.search;}'
        . '}catch(e){}return new OW(u,p);};}'
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
        . 'if(!F&&sidLike&&isLoginHash){location.hash="#/dashboard";}'
        . '}catch(e8){}'
        . '})();</script>';

    return preg_replace('/<head(\s[^>]*)?>/i', '$0' . $patch, $html, 1) ?? $html;
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
        foreach ($aliases as $host) {
            $body = ipmiProxyRewriteEscapedWebSocketUrls($body, $host, $token);
            $body = ipmiProxyRewriteWebSocketUrls($body, $host, $token);
            $body = ipmiProxyRewriteHttpBmcUrls($body, $host, $tokenPrefix);
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
        || strpos($body, '"/favicon.ico') !== false
        || strpos($body, '"\\/favicon.ico') !== false
        || strpos($body, '"/themes/') !== false
        || strpos($body, '"\\/themes\\/') !== false;

    if ($needsIloRoot) {
        $body = ipmiProxyRewriteIloRootRelative($body, $token);
    }

    return $body;
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

function ipmiProxyIsSupermicroRuntimeApiPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }

    return in_array($p, ['/cgi/xml_dispatcher.cgi', '/cgi/op.cgi', '/cgi/ipmi.cgi'], true);
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
    if (strpos($l, "sessionstorage.setitem ('_x_auth'") !== false
        || strpos($l, 'sessionstorage.setitem("_x_auth"') !== false) {
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

    return (bool) preg_match('/\.(?:js|css|png|svg|jpg|jpeg|gif|webp|ico|woff2?|ttf|eot|map)$/', $p);
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
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentTypeResp = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        return [
            'raw'             => $rawResponse,
            'http_code'       => $httpCode,
            'content_type'    => $contentTypeResp,
            'applied_resolve' => $appliedResolve,
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
 * Sync Origin / X-Auth-Token for streamed BMC requests.
 *
 * We intentionally do not perform runtime re-login in the proxy request path.
 * If BMC auth is stale, caller returns a session-expired response and user opens a new session.
 */
function ipmiProxyRecoverBmcAuthBeforeSse(array &$session, string $bmcIp, string &$bmcScheme, array &$fwdHdr): void
{
    $bmcScheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
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
 * Stream SSE or long-poll JSON from the BMC. Aborts before sending bytes if status is 401/403.
 *
 * @return array{ok: bool, auth_rejected: bool, applied_resolve: bool, curl_errno?: int, curl_error?: string}
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
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($curl, $headerLine) use (&$lines, &$headersSent, &$authRejected, $defaultStreamCt): int {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $headerLine, $hm)) {
            $code = (int) $hm[1];
            if ($code === 401 || $code === 403) {
                $authRejected = true;

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

$fwdHdr = $session['forward_headers'] ?? [];
$fwdHdr = ipmiProxyMergeClientBmcForwardHeaders(
    is_array($fwdHdr) ? $fwdHdr : [],
    $bmcScheme,
    $bmcIp,
    is_array($session['cookies'] ?? null) ? $session['cookies'] : []
);
// iLO JSON endpoints are sensitive to missing AJAX-style headers.
// Keep these defaults at the proxy edge so browser/runtime differences do not break auth.
$bmcTypeNorm = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
$bmcPathOnlyLower = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
if ($bmcTypeNorm === 'ilo4' && ($method === 'GET' || $method === 'POST')) {
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
    ipmiProxyRecoverBmcAuthBeforeSse($session, $bmcIp, $bmcScheme, $fwdHdr);
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

    if (!$r['ok']) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('stream_sse_failed', [
                'trace'           => $ipmiTraceId,
                'bmcPath'         => $bmcPath,
                'auth_rejected'   => !empty($r['auth_rejected']),
                'applied_resolve' => !empty($r['applied_resolve']),
                'curl_errno'      => $r['curl_errno'] ?? null,
                'curl_error'      => isset($r['curl_error']) ? substr((string) $r['curl_error'], 0, 240) : null,
            ]);
            ipmiProxyDebugEmitLogHeader([
                'trace'   => $ipmiTraceId,
                'bmcPath' => $bmcPath,
                'phase'   => 'stream_failed',
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
    exit;
}

$result = ipmiProxyExecute($bmcUrl, $method, $postBody, $fwdContentType, $session['cookies'], is_array($fwdHdr) ? $fwdHdr : [], $bmcIp);

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
    if ($typeNormAsset === 'ilo4' && preg_match('#^/html/(.+)$#i', $pathOnly, $mHtmlAsset)) {
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

// Determine content type early for login/timeout detection.
$ct = strtolower(trim(explode(';', $contentTypeResp)[0] ?? ''));
$isHtml = ($ct === '' || $ct === 'text/html' || strpos($ct, 'html') !== false || strpos($ct, 'text/plain') !== false);
$isJs = ($ct === 'application/javascript' || $ct === 'text/javascript');
$isCss = ($ct === 'text/css');
$isJson = (strpos($ct, 'json') !== false);

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
    if ($typeNorm === 'ilo4' && $isHtml) {
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
            // iDRAC can show spinner shell without explicit timeout/login markers when cookie is stale.
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
            $retryAfterLogin = ipmiProxyExecute(
                $bmcUrl,
                $method,
                $postBody,
                $fwdContentType,
                $session['cookies'],
                is_array($fwdHdr) ? $fwdHdr : [],
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
        ipmiProxyEmitSessionExpiredPage('Your session has timed out. You will need to open a new session.');
        exit;
    }
}

// iLO runtime APIs can return 401/403 even while shell HTML is still cached/rendered.
// Retry once after a fresh auto-login so UI does not fall into a white/login shell loop.
if (
    ($httpCode === 401 || $httpCode === 403)
    && $method === 'GET'
    && ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')) === 'ilo4'
    && ipmiProxyIsIloRuntimeApiPath($bmcPath)
) {
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_auth_recover_start', [
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
            $isJs = ($ct === 'application/javascript' || $ct === 'text/javascript');
            $isCss = ($ct === 'text/css');
            $isJson = (strpos($ct, 'json') !== false);
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_runtime_auth_recover_result', [
                    'trace' => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                    'http' => $httpCode,
                    'contentType' => $contentTypeResp,
                ]);
            }
        }
    } elseif (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_auth_recover_failed', [
            'trace' => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'error' => (string) ($session['auto_login_error'] ?? ''),
        ]);
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
            $isJs = ($ct === 'application/javascript' || $ct === 'text/javascript');
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

if (ipmiProxyIsHealthPollPath($bmcPath) && ($httpCode === 401 || $httpCode === 403 || $httpCode >= 500)) {
    ipmiProxyEmitHealthPollFallbackJson();
    exit;
}

http_response_code($httpCode ?: 502);

// Some AMI/ASRockRack firmwares return 404 for /html/application.html.
// iLO4 can also return 404 for /html/application.html on top-level open links on certain builds.
// For iLO, only fallback for top-level document navigations (not iframe sub-loads).
$typeNormFor404 = ipmiWebNormalizeBmcType((string)($session['bmc_type'] ?? 'generic'));
if ($isHtml && ($typeNormFor404 === 'ami' || $typeNormFor404 === 'ilo4')) {
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
        } elseif ($authOkHtml && $httpCode >= 200 && $httpCode < 400) {
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
                $typeNorm === 'supermicro'
            );
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
    ipmiProxyDebugEmitLogHeader([
        'trace'   => $ipmiTraceId,
        'bmcPath' => $bmcPath,
        'phase'   => 'response',
    ]);
    if ($isHtml && $httpCode >= 200 && $httpCode < 500) {
        ipmiProxyDebugAppendConsoleScript($responseBody, $ipmiTraceId, $bmcPath);
    }
}

echo $responseBody;
