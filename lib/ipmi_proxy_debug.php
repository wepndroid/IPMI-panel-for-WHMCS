<?php
/**
 * Opt-in debug for ipmi_proxy.php.
 *
 * Enable via any of:
 * - config: define('IPMI_PROXY_DEBUG', true);
 * - env: IPMI_PROXY_DEBUG=1
 * - cookie: ipmi_proxy_debug=1 (set automatically for 24h when you open with ?ipmi_proxy_debug=1)
 * - query: ?ipmi_proxy_debug=1 on the proxied URL (stripped before forwarding to the BMC)
 *
 * Logs to PHP error_log; sends X-IPMI-Proxy-Trace for correlation.
 * Browser: console.group on HTML pages; X-IPMI-Proxy-Debug-Log (base64 JSON) on all responses where headers are still mutable.
 * Does not log cookie values or full proxy tokens.
 */

/** @var list<array{ts: float, event: string, context: array<string, mixed>}>|null */
$GLOBALS['ipmi_proxy_debug_buffer'] = null;

function ipmiProxyDebugEnabled(): bool
{
    if (defined('IPMI_PROXY_DEBUG') && IPMI_PROXY_DEBUG) {
        return true;
    }
    $e = getenv('IPMI_PROXY_DEBUG');
    if ($e === '1' || strcasecmp((string) $e, 'true') === 0) {
        return true;
    }
    if (isset($_COOKIE['ipmi_proxy_debug']) && (string) $_COOKIE['ipmi_proxy_debug'] === '1') {
        return true;
    }
    if (isset($_GET['ipmi_proxy_debug']) && (string) $_GET['ipmi_proxy_debug'] === '1') {
        return true;
    }

    return false;
}

/**
 * Remove debug-only query keys so they are not forwarded to the BMC.
 */
function ipmiProxyDebugStripFromQuery(string $queryString): string
{
    if ($queryString === '') {
        return '';
    }
    parse_str($queryString, $params);
    if (!is_array($params)) {
        return $queryString;
    }
    unset($params['ipmi_proxy_debug'], $params['ipmi_proxy_console']);

    return http_build_query($params);
}

/**
 * Set a 24h cookie when ?ipmi_proxy_debug=1 so subrequests (JS/CSS/json) keep logging without the query param.
 */
function ipmiProxyDebugMaybeSetCookie(): void
{
    if (!isset($_GET['ipmi_proxy_debug'])) {
        return;
    }
    $val = (string) $_GET['ipmi_proxy_debug'];
    if ($val !== '1' && $val !== '0' && strcasecmp($val, 'off') !== 0) {
        return;
    }
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443);
    $expires = ($val === '1') ? (time() + 86400) : (time() - 3600);
    $path = '/';
    if (PHP_VERSION_ID >= 70300) {
        setcookie('ipmi_proxy_debug', $val === '1' ? '1' : '0', [
            'expires'  => $expires,
            'path'     => $path,
            'secure'   => $secure,
            'httponly' => false,
            'samesite' => 'Lax',
        ]);
    } else {
        setcookie('ipmi_proxy_debug', $val === '1' ? '1' : '0', $expires, $path, '', $secure, false);
    }
}

function ipmiProxyDebugBufferInit(): void
{
    if ($GLOBALS['ipmi_proxy_debug_buffer'] === null) {
        $GLOBALS['ipmi_proxy_debug_buffer'] = [];
    }
}

/**
 * @param array<string, mixed> $context
 */
function ipmiProxyDebugBufferAppend(string $event, array $context): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    ipmiProxyDebugBufferInit();
    $GLOBALS['ipmi_proxy_debug_buffer'][] = [
        'ts'      => round(microtime(true), 4),
        'event'   => $event,
        'context' => $context,
    ];
}

function ipmiProxyDebugRedactToken(string $token): string
{
    $t = strtolower(trim($token));
    if (strlen($t) <= 8) {
        return '***';
    }

    return '…' . substr($t, -8);
}

/** @param array<string, mixed> $cookies */
function ipmiProxyDebugCookieMeta(array $cookies): array
{
    $names = [];
    foreach ($cookies as $k => $v) {
        if ($v !== null && trim((string) $v) !== '') {
            $names[] = (string) $k;
        }
    }
    sort($names);

    return ['count' => count($names), 'keys' => $names];
}

/**
 * @param array<string, mixed> $context
 */
function ipmiProxyDebugLog(string $event, array $context = []): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    ipmiProxyDebugBufferAppend($event, $context);
    $line = date('c') . ' [ipmi_proxy] ' . $event;
    if ($context !== []) {
        $line .= ' ' . json_encode($context, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
    error_log($line);
}

function ipmiProxyDebugSendTraceHeaders(): string
{
    $id = bin2hex(random_bytes(8));
    header('X-IPMI-Proxy-Debug-Active: 1', false);
    header('X-IPMI-Proxy-Trace: ' . $id, false);

    return $id;
}

/**
 * @return list<array{ts: float, event: string, context: array<string, mixed>}>
 */
function ipmiProxyDebugGetBuffer(): array
{
    if ($GLOBALS['ipmi_proxy_debug_buffer'] === null) {
        return [];
    }

    return $GLOBALS['ipmi_proxy_debug_buffer'];
}

/**
 * Emit X-IPMI-Proxy-Debug-Log (base64 JSON). Call before any response body bytes.
 * Safe to call before SSE (partial log) and again before HTML/JSON (full log) — later call replaces the header.
 *
 * @param array<string, mixed> $extra e.g. ['trace' => $id, 'bmcPath' => $path, 'phase' => 'pre_stream']
 */
function ipmiProxyDebugEmitLogHeader(array $extra = []): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    $buf = ipmiProxyDebugGetBuffer();
    $payload = array_merge([
        'v'      => 1,
        'events' => $buf,
    ], $extra);
    $payload['events'] = $buf;

    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) {
        return;
    }
    $max = 12000;
    if (strlen($json) > $max) {
        $payload['truncated'] = true;
        $payload['events'] = array_slice($buf, 0, 40);
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false || strlen($json) > $max) {
            $json = json_encode([
                'v'         => 1,
                'truncated' => true,
                'error'     => 'payload_too_large',
                'trace'     => $extra['trace'] ?? null,
            ], JSON_UNESCAPED_SLASHES);
        }
    }
    header('X-IPMI-Proxy-Debug-Log: ' . base64_encode((string) $json), true);
}

/**
 * Append a script to HTML so DevTools Console shows the same payload (copy from console or from Network → response headers).
 */
function ipmiProxyDebugAppendConsoleScript(string &$html, string $traceId, string $bmcPath): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    $buf = ipmiProxyDebugGetBuffer();
    $payload = [
        'v'         => 1,
        'trace'     => $traceId,
        'bmcPath'   => $bmcPath,
        'hint'      => 'Copy this object from the console or copy the X-IPMI-Proxy-Debug-Log header (base64) from Network.',
        'events'    => $buf,
    ];
    $json = json_encode($payload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return;
    }
    $script = '<script data-ipmi-proxy-debug="1">'
        . '(function(){try{var P=' . $json . ';'
        . 'console.groupCollapsed("%cIPMI Proxy debug","font-weight:bold;color:#063;background:#dfefff;padding:2px 8px;border-radius:3px");'
        . 'console.log(P);console.groupEnd();'
        . 'if(typeof window.IPMI_PROXY_DEBUG==="undefined")window.IPMI_PROXY_DEBUG=P;'
        . 'try{if(window.top!==window.self){return;}'
        . 'var txt="";try{txt=JSON.stringify(P,null,2);}catch(e1){txt=String(P);} '
        . 'var box=document.getElementById("ipmi-proxy-debug-box");'
        . 'if(!box){box=document.createElement("div");box.id="ipmi-proxy-debug-box";'
        . 'box.style.cssText="position:fixed;right:12px;bottom:12px;z-index:2147483647;'
        . 'width:520px;max-width:90vw;background:#0b1630;color:#dce6ff;border:1px solid #2b3d60;'
        . 'border-radius:8px;box-shadow:0 10px 30px rgba(0,0,0,.35);padding:10px;font-family:monospace;font-size:12px;";'
        . 'var title=document.createElement("div");title.textContent="IPMI Proxy Debug (copy text)";'
        . 'title.style.cssText="font-weight:bold;margin-bottom:6px;";'
        . 'var btn=document.createElement("button");btn.textContent="Copy";'
        . 'btn.style.cssText="float:right;margin-top:-2px;background:#22477a;color:#fff;border:0;border-radius:6px;padding:4px 10px;cursor:pointer;";'
        . 'btn.onclick=function(){try{var ta=document.getElementById(\'ipmi-proxy-debug-text\');ta.select();document.execCommand(\'copy\');}catch(e){}};'
        . 'var ta=document.createElement("textarea");ta.id="ipmi-proxy-debug-text";ta.readOnly=true;'
        . 'ta.style.cssText="width:100%;height:240px;resize:vertical;background:#0f1d3a;color:#dce6ff;border:1px solid #2b3d60;border-radius:6px;padding:6px;";'
        . 'box.appendChild(title);box.appendChild(btn);box.appendChild(ta);document.body.appendChild(box);} '
        . 'var ta2=document.getElementById("ipmi-proxy-debug-text");if(ta2&&ta2.value!==txt){ta2.value=txt;}'
        . '}catch(e2){}'
        . '}catch(e){console.warn("IPMI Proxy debug",e);}})();'
        . '</script>';
    if (stripos($html, '</body>') !== false) {
        $html = preg_replace('~</body>~i', $script . '</body>', $html, 1) ?? ($html . $script);
    } else {
        $html .= $script;
    }
}
