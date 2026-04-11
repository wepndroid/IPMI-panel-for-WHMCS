<?php
/**
 * WebSocket relay validation endpoint.
 *
 * Real WebSocket proxying cannot be done reliably in PHP under Apache.
 * This script validates the session token and returns connection details
 * that the client-side JavaScript can use to establish a direct WebSocket
 * connection where possible, or falls back to a simple PHP stream relay
 * for environments where mod_proxy_wstunnel dynamic routing is not available.
 *
 * For most BMC KVM consoles (especially Java-based or HTML5 consoles served
 * via the HTTP proxy), WebSocket is not required — the HTTP proxy handles
 * the console page delivery. This endpoint exists as a fallback.
 */
session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/ipmi_web_session.php';
require_once __DIR__ . '/lib/ipmi_proxy_debug.php';

$token = strtolower(trim((string)($_GET['token'] ?? '')));

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid token']);
    exit;
}

$session = ipmiWebLoadSession($mysqli, $token);
if (!$session) {
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Session expired or invalid']);
    exit;
}

$panelUserId = $_SESSION['user_id'] ?? null;
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
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Authentication required']);
        exit;
    }
}

$isWsUpgrade = (
    isset($_SERVER['HTTP_UPGRADE'])
    && stripos((string)$_SERVER['HTTP_UPGRADE'], 'websocket') !== false
);

if (!$isWsUpgrade) {
    header('Content-Type: application/json');
    echo json_encode([
        'status'  => 'ok',
        'message' => 'WebSocket relay endpoint. Connect with Upgrade: websocket header.',
        'bmc_ip'  => $session['ipmi_ip'],
    ]);
    exit;
}

$bmcIp   = $session['ipmi_ip'];
$target  = trim((string)($_GET['target'] ?? ''));

$parsedTarget = parse_url($target);
$wsPath  = ($parsedTarget['path'] ?? '/');
$wsQuery = ($parsedTarget['query'] ?? '');
if ($wsQuery !== '') {
    $wsPath .= '?' . $wsQuery;
}

$tScheme = strtolower((string)($parsedTarget['scheme'] ?? 'wss'));
$useTls = ($tScheme === 'wss');
$bmcPort = (int)($parsedTarget['port'] ?? ($useTls ? 443 : 80));

$wsKey = base64_encode(random_bytes(16));
$cookieHeader = ipmiWsBuildCookieHeader($session);
$extraHeaders = ipmiWsBuildForwardHeaderLines($session);

$originScheme = $useTls ? 'https' : 'http';
$handshake = "GET {$wsPath} HTTP/1.1\r\n"
    . "Host: {$bmcIp}\r\n"
    . "Upgrade: websocket\r\n"
    . "Connection: Upgrade\r\n"
    . "Sec-WebSocket-Key: {$wsKey}\r\n"
    . "Sec-WebSocket-Version: 13\r\n"
    . "Origin: {$originScheme}://{$bmcIp}\r\n"
    . $cookieHeader
    . $extraHeaders
    . "\r\n";

$ctx = stream_context_create([
    'ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    ],
]);

$connectSpec = $useTls
    ? 'ssl://' . $bmcIp . ':' . $bmcPort
    : 'tcp://' . $bmcIp . ':' . $bmcPort;

if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    $cookiePresent = $cookieHeader !== '' ? 1 : 0;
    $extraHdrLines = $extraHeaders !== '' ? substr_count(trim($extraHeaders), "\n") : 0;
    error_log('ipmi_ws_relay: pre_connect scheme=' . $tScheme . ' port=' . $bmcPort
        . ' pathLen=' . strlen($wsPath) . ' cookieHeader=' . $cookiePresent
        . ' forwardHdrLines=' . $extraHdrLines);
}

$remote = @stream_socket_client(
    $connectSpec,
    $errno,
    $errstr,
    10,
    STREAM_CLIENT_CONNECT,
    $useTls ? $ctx : null
);

if (!$remote) {
    if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
        error_log('ipmi_ws_relay: tcp_connect_failed errno=' . (string) $errno . ' err=' . substr((string) $errstr, 0, 200));
    }
    http_response_code(502);
    echo 'Cannot connect to BMC WebSocket: ' . $errstr;
    exit;
}

fwrite($remote, $handshake);

$responseHeader = '';
while (!feof($remote)) {
    $line = fgets($remote, 4096);
    if ($line === false) {
        break;
    }
    $responseHeader .= $line;
    if (trim($line) === '') {
        break;
    }
}

if (stripos($responseHeader, '101') === false) {
    if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
        $first = strtok($responseHeader, "\n");
        error_log('ipmi_ws_relay: handshake_no_101 firstLine=' . trim((string) $first));
    }
    fclose($remote);
    http_response_code(502);
    echo 'BMC WebSocket handshake failed';
    exit;
}

if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    error_log('ipmi_ws_relay: handshake_ok scheme=' . $tScheme);
}

$expectedAccept = base64_encode(sha1($wsKey . '258EAFA5-E914-47DA-95CA-5AB5DC11653B', true));

header('HTTP/1.1 101 Switching Protocols');
header('Upgrade: websocket');
header('Connection: Upgrade');
header('Sec-WebSocket-Accept: ' . $expectedAccept);

if (function_exists('ob_end_flush')) {
    while (ob_get_level()) {
        ob_end_flush();
    }
}
flush();

set_time_limit(0);
stream_set_blocking($remote, false);

$clientIn  = fopen('php://input', 'rb');
$clientOut = fopen('php://output', 'wb');

if (!$clientIn || !$clientOut) {
    fclose($remote);
    exit;
}

stream_set_blocking($clientIn, false);

$deadline = time() + 7200;
while (!feof($remote) && time() < $deadline) {
    $read = [$remote, $clientIn];
    $write = null;
    $except = null;

    $changed = @stream_select($read, $write, $except, 1, 0);
    if ($changed === false) {
        break;
    }
    if ($changed === 0) {
        continue;
    }

    foreach ($read as $stream) {
        $data = @fread($stream, 65536);
        if ($data === false || $data === '') {
            if (feof($stream)) {
                break 2;
            }
            continue;
        }

        if ($stream === $remote) {
            @fwrite($clientOut, $data);
            @fflush($clientOut);
        } else {
            @fwrite($remote, $data);
        }
    }
}

@fclose($clientIn);
@fclose($clientOut);
@fclose($remote);
