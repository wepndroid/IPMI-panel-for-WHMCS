<?php

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
        . 'var L=location;var po=L.protocol+"//"+L.host;var _ipmiSecWs=function(){try{if(window.top&&window.top.location&&window.top.location.protocol==="https:")return true;}catch(e){}return L.protocol==="https:";}();var wo=(_ipmiSecWs?"wss:":"ws:")+"//"+L.host;'
        . 'function iH(h){if(!h)return false;h=String(h).toLowerCase();for(var i=0;i<H.length;i++){if(H[i]&&String(H[i]).toLowerCase()===h)return true;}return false;}'
        . 'function sp(s){if(typeof s!=="string"||s.indexOf(P)===0)return false;for(var i=0;i<R.length;i++){if(s.indexOf(R[i])===0)return true;}return false;}'
        . 'function fu(s){if(typeof s!=="string")return s;if(s.indexOf(po+P)===0)return s;try{var u=new URL(s,po);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());if(sh&&u.pathname.indexOf(P)===0)return po+u.pathname+u.search+u.hash;if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname)))return po+P+u.pathname+u.search+u.hash;}catch(e){}return sp(s)?po+P+s:s;}'
        . 'function wru(s){if(typeof s!=="string")return s;try{var u=new URL(s,L.href);if((u.origin===po)&&u.pathname.indexOf("/ipmi_ws_relay.php")===0)return wo+u.pathname+u.search+u.hash;var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());var wsScheme=String(u.protocol||"").toLowerCase();if(wsScheme!=="ws:"&&wsScheme!=="wss:"){wsScheme=(_ipmiSecWs?"wss:":"ws:");}var targetHost=u.host;if((sh&&sp(u.pathname))&&H.length>0){targetHost=String(H[0]);}if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname))){var target=wsScheme.replace(":","")+"://"+targetHost+u.pathname+u.search;return wo+W+encodeURIComponent(target);}}catch(e){}return s;}'
        . 'function _ipmiWssFix(u){try{var s=String(u||"");if(s.indexOf("ws://")!==0)return u;var t=false;try{t=!!(window.top&&window.top.location&&window.top.location.protocol==="https:");}catch(e1){}if(!t&&L.protocol==="https:")t=true;return t?("wss://"+s.substring(6)):u;}catch(e){return u;}}'
        . 'function fx(n){if(typeof A!=="string"||!A)return n;n=n||{};try{var Hd=new Headers(n.headers||{});if(!Hd.has("X-Auth-Token"))Hd.set("X-Auth-Token",A);n.headers=Hd;}catch(e){}return n;}'
        . 'if(window.fetch){var of=window.fetch;window.fetch=function(i,n){try{n=fx(n||{});'
        . 'if(typeof i==="string")return of.call(this,fu(i),n);'
        . 'if(window.Request&&i instanceof Request){if(i.url.indexOf(po+P)===0)return of.call(this,i,n);var u=new URL(i.url,L.href);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());'
        . 'var ru="";if(sh&&u.pathname.indexOf(P)===0){ru=po+u.pathname+u.search+u.hash;}else if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname))){ru=po+P+u.pathname+u.search+u.hash;}'
        . 'if(ru){var Rq=new Request(ru,i);try{var H2=new Headers(Rq.headers);if(typeof A==="string"&&A&&!H2.has("X-Auth-Token"))H2.set("X-Auth-Token",A);Rq=new Request(Rq,{headers:H2});}catch(e2){}return of.call(this,Rq,n);}}'
        . '}catch(e){}return of.call(this,i,n);};}'
        . 'var xp=XMLHttpRequest&&XMLHttpRequest.prototype;if(xp&&xp.open){var oo=xp.open;xp.open=function(m,u,a3,a4,a5){try{if(typeof u==="string")u=fu(u);}catch(e){}return oo.call(this,m,u,a3,a4,a5);};}'
        . 'if(xp&&xp.send){var xs=xp.send;xp.send=function(b){try{if(typeof A==="string"&&A){try{this.setRequestHeader("X-Auth-Token",A);}catch(e3){}}}catch(e4){}return xs.call(this,b);};}'
        . 'if(window.WebSocket){var OW=WebSocket;window.WebSocket=function(u,p){try{if(typeof u==="string"){u=wru(u);u=_ipmiWssFix(u);}}catch(e){}return new OW(u,p);};}'
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
    $wsRelay = '/ipmi_ws_relay.php?token=' . rawurlencode($token) . '&target=';
    $wsRelayJs = json_encode($wsRelay, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);

    $forceSm = $forceSupermicroLegacy ? '1' : '0';
    $disableHashRedirect = $disableLoginHashRedirect ? '1' : '0';
    $patch = '<script data-ipmi-proxy-generic-patch="1">'
        . '(function(){'
        . 'try{var _a=window.alert;window.alert=function(msg){try{var s=String(msg||"").toLowerCase();'
        . 'if(s.indexOf("session has timed out")>=0||s.indexOf("session timed out")>=0||s.indexOf("session is running")>=0||s.indexOf("already a session")>=0){return;}'
        . '}catch(e){}return _a.apply(this,arguments);};}catch(e){}'
        . 'var P=' . $pxJs . ';var W=' . $wsRelayJs . ';var A=' . $authJs . ';var C=' . $csrfJs . ';var H=' . $hostsJs . ';'
        . 'var R=["/redfish/v1/","/redfish/","/rest/v1/","/rest/","/restapi/","/session","/data/","/rpc/","/js/","/css/","/fonts/","/img/","/images/","/json/","/api/","/html/","/themes/","/sse/","/cgi/","/res/","/java/","/Java/","/viewer/","/console/","/kvm/","/avct/","/favicon.ico"];'
        . 'var L=location;var po=L.protocol+"//"+L.host;var _ipmiSecWs=function(){try{if(window.top&&window.top.location&&window.top.location.protocol==="https:")return true;}catch(e){}return L.protocol==="https:";}();var wo=(_ipmiSecWs?"wss:":"ws:")+"//"+L.host;'
        . 'var F=' . $forceSm . ';'
        . 'var D=' . $disableHashRedirect . ';'
        . 'if(F){try{if(window.sessionStorage&&!sessionStorage.getItem("_x_auth")){sessionStorage.setItem("_x_auth","ipmi_proxy");}}catch(e0){}}'
        . 'function iH(h){if(!h)return false;h=String(h).toLowerCase();for(var i=0;i<H.length;i++){if(H[i]&&String(H[i]).toLowerCase()===h)return true;}return false;}'
        . 'function sp(s){if(typeof s!=="string"||s.indexOf(P)===0)return false;for(var i=0;i<R.length;i++){if(s.indexOf(R[i])===0)return true;}return false;}'
        . 'function fu(s){if(typeof s!=="string")return s;if(s.indexOf(po+P)===0)return s;try{var u=new URL(s,po);var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());if(sh&&u.pathname.indexOf(P)===0)return po+u.pathname+u.search+u.hash;if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname)))return po+P+u.pathname+u.search+u.hash;}catch(e){}return sp(s)?po+P+s:s;}'
        . 'function wru(s){if(typeof s!=="string")return s;try{var u=new URL(s,L.href);if((u.origin===po)&&u.pathname.indexOf("/ipmi_ws_relay.php")===0)return wo+u.pathname+u.search+u.hash;var sh=(String(u.hostname||"").toLowerCase()===String(L.hostname||"").toLowerCase());var wsScheme=String(u.protocol||"").toLowerCase();if(wsScheme!=="ws:"&&wsScheme!=="wss:"){wsScheme=(_ipmiSecWs?"wss:":"ws:");}var targetHost=u.host;if((sh&&sp(u.pathname))&&H.length>0){targetHost=String(H[0]);}if(iH(u.hostname)||(sh&&sp(u.pathname))||(u.origin===po&&sp(u.pathname))){var target=wsScheme.replace(":","")+"://"+targetHost+u.pathname+u.search;return wo+W+encodeURIComponent(target);}}catch(e){}return s;}'
        . 'function _ipmiWssFix(u){try{var s=String(u||"");if(s.indexOf("ws://")!==0)return u;var t=false;try{t=!!(window.top&&window.top.location&&window.top.location.protocol==="https:");}catch(e1){}if(!t&&L.protocol==="https:")t=true;return t?("wss://"+s.substring(6)):u;}catch(e){return u;}}'
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
        . 'if(window.WebSocket){var OW=WebSocket;window.WebSocket=function(u,p){try{if(typeof u==="string"){u=wru(u);u=_ipmiWssFix(u);}}catch(e){}return new OW(u,p);};}'
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
