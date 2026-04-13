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

// Release PHP session lock immediately — the relay loop can run for hours and
// a held session file lock blocks every other request sharing the same PHPSESSID
// (including parallel WebSocket connections the iLO console needs for video/input/control).
session_write_close();

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

// Align with panel/KVM policy: clients must not open new relay paths while suspended (admins may).
$serverIdRelay = (int) ($session['server_id'] ?? 0);
if ($serverIdRelay > 0) {
    $susRow = null;
    $stSus = $mysqli->prepare('SELECT COALESCE(suspended, 0) AS s FROM server_suspension WHERE server_id = ? LIMIT 1');
    if ($stSus) {
        $stSus->bind_param('i', $serverIdRelay);
        $stSus->execute();
        $rSus = $stSus->get_result();
        $susRow = $rSus ? $rSus->fetch_assoc() : null;
        $stSus->close();
    }
    if ($susRow && (int) ($susRow['s'] ?? 0) === 1) {
        $webUserId = (int) ($session['user_id'] ?? 0);
        $roleRow = null;
        if ($webUserId > 0) {
            $stR = $mysqli->prepare("SELECT role FROM users WHERE id = ? LIMIT 1");
            if ($stR) {
                $stR->bind_param('i', $webUserId);
                $stR->execute();
                $rr = $stR->get_result();
                $roleRow = $rr ? $rr->fetch_assoc() : null;
                $stR->close();
            }
        }
        $isAdminRelay = is_array($roleRow) && (string) ($roleRow['role'] ?? '') === 'admin';
        if (!$isAdminRelay) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Server is suspended', 'suspended' => 1]);
            exit;
        }
    }
}

$isWsUpgrade = (
    isset($_SERVER['HTTP_UPGRADE'])
    && stripos((string)$_SERVER['HTTP_UPGRADE'], 'websocket') !== false
);

if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    error_log('ipmi_ws_relay: request_received'
        . ' method=' . ($_SERVER['REQUEST_METHOD'] ?? 'unknown')
        . ' upgrade=' . ($_SERVER['HTTP_UPGRADE'] ?? 'none')
        . ' connection=' . ($_SERVER['HTTP_CONNECTION'] ?? 'none')
        . ' is_ws_upgrade=' . ($isWsUpgrade ? '1' : '0')
        . ' sapi=' . PHP_SAPI
        . ' target_present=' . (isset($_GET['target']) && $_GET['target'] !== '' ? '1' : '0'));
}

if (!$isWsUpgrade) {
    header('Content-Type: application/json');
    echo json_encode([
        'status'  => 'ok',
        'message' => 'WebSocket relay endpoint. Connect with Upgrade: websocket header.',
        'bmc_ip'  => $session['ipmi_ip'],
        'sapi'    => PHP_SAPI,
        'note'    => 'If WebSocket connections fail, check: 1) Apache mod_proxy_wstunnel or mod_headers allows Upgrade pass-through, 2) PHP runs as CGI/FPM not mod_php for raw socket relay, 3) BMC IP is reachable from this server.',
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

$preferredHost = ipmiBmcPreferredOriginHost($bmcIp);
$defaultPort = $useTls ? 443 : 80;
$hostLine = $preferredHost . (($bmcPort !== $defaultPort) ? (':' . $bmcPort) : '');
$originScheme = $useTls ? 'https' : 'http';
$originLine = $originScheme . '://' . $preferredHost;
if ($bmcPort !== $defaultPort) {
    $originLine .= ':' . $bmcPort;
}
$clientProto = trim((string) ($_SERVER['HTTP_SEC_WEBSOCKET_PROTOCOL'] ?? ''));
$protoLine = '';
if ($clientProto !== '' && strlen($clientProto) <= 512 && preg_match('/^[A-Za-z0-9\\s,;\\.\\-_]+$/', $clientProto)) {
    $protoLine = 'Sec-WebSocket-Protocol: ' . $clientProto . "\r\n";
    if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
        error_log('ipmi_ws_relay: client_protocol_fwd=1');
    }
}

$handshake = "GET {$wsPath} HTTP/1.1\r\n"
    . "Host: {$hostLine}\r\n"
    . "Upgrade: websocket\r\n"
    . "Connection: Upgrade\r\n"
    . "Sec-WebSocket-Key: {$wsKey}\r\n"
    . "Sec-WebSocket-Version: 13\r\n"
    . "Origin: {$originLine}\r\n"
    . $protoLine
    . $cookieHeader
    . $extraHeaders
    . "\r\n";

$ctx = stream_context_create([
    'ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
        'security_level'    => 0,
        'ciphers'           => 'DEFAULT:@SECLEVEL=0',
    ],
]);

$connectSpec = $useTls
    ? 'ssl://' . $bmcIp . ':' . $bmcPort
    : 'tcp://' . $bmcIp . ':' . $bmcPort;

// All DB work is done — close MySQL before the potentially hours-long relay loop
// to avoid holding a connection from the pool.
if (isset($mysqli) && $mysqli instanceof mysqli) {
    @$mysqli->close();
    unset($mysqli);
}

if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    $cookiePresent = $cookieHeader !== '' ? 1 : 0;
    $extraHdrLines = $extraHeaders !== '' ? substr_count(trim($extraHeaders), "\n") : 0;
    $pathHasWs = (stripos($wsPath, 'ws') !== false || stripos($wsPath, 'irc') !== false || stripos($wsPath, 'kvm') !== false) ? 1 : 0;
    $protoFwd = ($protoLine !== '') ? 1 : 0;
    $pathFp = substr(hash('sha256', $wsPath), 0, 16);
    error_log('ipmi_ws_relay: pre_connect scheme=' . $tScheme . ' port=' . $bmcPort
        . ' pathLen=' . strlen($wsPath) . ' path_ws_hint=' . $pathHasWs
        . ' path_fp=' . $pathFp
        . ' cookieHeader=' . $cookiePresent
        . ' forwardHdrLines=' . $extraHdrLines
        . ' sec_ws_proto_fwd=' . $protoFwd
        . ' tls_to_bmc=' . ($useTls ? '1' : '0')
        . ' host_fwd=1 origin_fwd=1 host_kind=' . (filter_var($preferredHost, FILTER_VALIDATE_IP) ? 'ip' : 'name'));
}

if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    error_log('ipmi_ws_relay: connecting to ' . $connectSpec
        . ' tls=' . ($useTls ? '1' : '0')
        . ' bmc_ip=' . $bmcIp
        . ' port=' . $bmcPort
        . ' ws_path_len=' . strlen($wsPath));
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
        error_log('ipmi_ws_relay: tcp_connect_failed errno=' . (string) $errno . ' err=' . substr((string) $errstr, 0, 200)
            . ' connect_spec=' . $connectSpec);
    }
    http_response_code(502);
    header('Content-Type: text/plain');
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
        $hl = strtolower($responseHeader);
        $upHttp = 0;
        if (preg_match('/HTTP\/\S+\s+(\d{3})\b/', (string) $responseHeader, $hm)) {
            $upHttp = (int) $hm[1];
        }
        error_log('ipmi_ws_relay: handshake_no_101 firstLine=' . trim((string) $first)
            . ' upstream_http=' . (string) $upHttp
            . ' hdrBytes=' . strlen($responseHeader)
            . ' path_fp=' . substr(hash('sha256', $wsPath), 0, 16)
            . ' www_authenticate=' . (str_contains($hl, 'www-authenticate') ? '1' : '0')
            . ' has_location=' . (preg_match('/^location:\s/im', $responseHeader) ? '1' : '0')
            . ' has_set_cookie=' . (preg_match('/^set-cookie:\s/im', $responseHeader) ? '1' : '0'));
    }
    fclose($remote);
    http_response_code(502);
    echo 'BMC WebSocket handshake failed';
    exit;
}

if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    error_log('ipmi_ws_relay: handshake_ok scheme=' . $tScheme
        . ' host_kind=' . (filter_var($preferredHost, FILTER_VALIDATE_IP) ? 'ip' : 'name')
        . ' pathLen=' . strlen($wsPath)
        . ' cookie_fwd=' . ($cookieHeader !== '' ? '1' : '0'));
}

$expectedAccept = base64_encode(sha1($wsKey . '258EAFA5-E914-47DA-95CA-5AB5DC11653B', true));

$serverProto = (string) ($_SERVER['HTTP_SEC_WEBSOCKET_VERSION'] ?? '');
$bmcProto = '';
if (preg_match('/Sec-WebSocket-Protocol:\s*([^\r\n]+)/i', $responseHeader, $spMatch)) {
    $bmcProto = trim($spMatch[1]);
}

if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    error_log('ipmi_ws_relay: sending_101 sapi=' . PHP_SAPI
        . ' bmc_proto=' . ($bmcProto !== '' ? $bmcProto : 'none')
        . ' client_proto=' . ($clientProto !== '' ? $clientProto : 'none'));
}

header('HTTP/1.1 101 Switching Protocols');
header('Upgrade: websocket');
header('Connection: Upgrade');
header('Sec-WebSocket-Accept: ' . $expectedAccept);
if ($bmcProto !== '') {
    header('Sec-WebSocket-Protocol: ' . $bmcProto);
}

if (function_exists('ob_end_flush')) {
    while (ob_get_level()) {
        ob_end_flush();
    }
}
flush();

if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', '1');
}
@ini_set('zlib.output_compression', '0');
@ini_set('implicit_flush', '1');

set_time_limit(0);
stream_set_blocking($remote, false);

$clientIn  = fopen('php://input', 'rb');
$clientOut = fopen('php://output', 'wb');

if (!$clientIn || !$clientOut) {
    if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
        error_log('ipmi_ws_relay: failed_to_open_client_streams clientIn=' . ($clientIn ? '1' : '0') . ' clientOut=' . ($clientOut ? '1' : '0'));
    }
    fclose($remote);
    exit;
}

stream_set_blocking($clientIn, false);

$deadline = time() + 7200;
$bytesFromBmc = 0;
$bytesFromClient = 0;
$relayStartTs = microtime(true);

if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    error_log('ipmi_ws_relay: relay_loop_started sapi=' . PHP_SAPI);
}

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
            $bytesFromBmc += strlen($data);
            @fwrite($clientOut, $data);
            @fflush($clientOut);
        } else {
            $bytesFromClient += strlen($data);
            @fwrite($remote, $data);
        }
    }
}

$elapsed = round(microtime(true) - $relayStartTs, 2);
if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
    error_log('ipmi_ws_relay: relay_ended elapsed=' . $elapsed . 's'
        . ' bytes_from_bmc=' . $bytesFromBmc
        . ' bytes_from_client=' . $bytesFromClient
        . ' sapi=' . PHP_SAPI);
}

@fclose($clientIn);
@fclose($clientOut);
@fclose($remote);
