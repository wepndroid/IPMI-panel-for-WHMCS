<?php
/**
 * WebSocket relay for KVM console transport.
 *
 * Accepts a browser WebSocket upgrade, validates the session token,
 * opens an upstream TLS/WSS connection to the BMC, and pumps frames
 * bidirectionally. Returns structured diagnostic JSON on every failure
 * path so the browser-side runtime can report precise transport-health
 * verdicts instead of generic "handshake failed."
 */
session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/ipmi_web_session.php';
require_once __DIR__ . '/lib/ipmi_proxy_debug.php';
require_once __DIR__ . '/lib/ipmi_kvm_buglog.php';

// ---------------------------------------------------------------------------
// Sustained frame-flow thresholds (must match bugs.txt aggregate semantics).
// ---------------------------------------------------------------------------
/** @return array{min_bmc_bytes: int, min_bmc_frames: int} */
function ipmiWsRelaySustainedFlowThresholds(): array
{
    return ['min_bmc_bytes' => 4096, 'min_bmc_frames' => 12];
}

/**
 * True once BMC→browser bytes/frames cross bounded sustained-flow thresholds.
 */
function ipmiWsRelayObserveSustainedFrameFlow(int $bytesFromBmc, int $framesBmc, bool $alreadyObserved): bool
{
    if ($alreadyObserved) {
        return true;
    }
    $t = ipmiWsRelaySustainedFlowThresholds();

    return $bytesFromBmc >= $t['min_bmc_bytes'] && $framesBmc >= $t['min_bmc_frames'];
}

// ---------------------------------------------------------------------------
// Helper: structured debug log
// ---------------------------------------------------------------------------
function ipmiWsRelayDebugEvent(string $event, array $detail = []): void
{
    if (function_exists('ipmiProxyDebugEnabled') && ipmiProxyDebugEnabled()) {
        $parts = [$event];
        foreach ($detail as $k => $v) {
            if (is_bool($v)) {
                $v = $v ? '1' : '0';
            }
            $parts[] = $k . '=' . (string) $v;
        }
        error_log(implode(' ', $parts));
    }
    $tok = $GLOBALS['__ipmi_ws_relay_buglog_token'] ?? null;
    global $mysqli;
    if (is_string($tok) && preg_match('/^[a-f0-9]{64}$/', $tok) && function_exists('ipmiKvmBugLogRelayDebugEvent')) {
        ipmiKvmBugLogRelayDebugEvent($tok, $event, $detail, $mysqli instanceof mysqli ? $mysqli : null);
    }
}

// ---------------------------------------------------------------------------
// Helper: environment support verdict
// ---------------------------------------------------------------------------
function ipmiWsRelayEnvironmentSupportsUpgrade(): array
{
    $sapi = PHP_SAPI;
    $canFlush = function_exists('ob_end_flush');
    $canInput = is_readable('php://input');
    $outputWritable = true;
    $verdict = 'supported';
    $notes = [];

    if ($sapi === 'cli') {
        $verdict = 'unsupported';
        $notes[] = 'CLI SAPI cannot serve HTTP upgrades';
    }

    if (stripos($sapi, 'apache') !== false) {
        $notes[] = 'Apache SAPI: if frame pump shows 0 bytes in ipmi_ws_relay_closed while browser shows open, inspect output buffering / mod_php raw stream support';
    }

    if (!$canFlush) {
        $notes[] = 'ob_end_flush not available';
    }

    return [
        'sapi'           => $sapi,
        'verdict'        => $verdict,
        'can_flush'      => $canFlush,
        'can_input'      => $canInput,
        'output_writable' => $outputWritable,
        'notes'          => $notes,
    ];
}

// ---------------------------------------------------------------------------
// Helper: parse and validate the target URL
// ---------------------------------------------------------------------------
/**
 * Validate browser WebSocket upgrade headers and compute Sec-WebSocket-Accept
 * from the *client's* Sec-WebSocket-Key (RFC 6455). Upstream BMC uses a separate key.
 *
 * @return array{accept: string, key: string}
 */
function ipmiWsRelayValidateBrowserUpgrade(): array
{
    $key = trim((string) ($_SERVER['HTTP_SEC_WEBSOCKET_KEY'] ?? ''));
    $ver = trim((string) ($_SERVER['HTTP_SEC_WEBSOCKET_VERSION'] ?? ''));

    if ($key === '') {
        ipmiWsRelayDebugEvent('ipmi_ws_relay_browser_handshake_failed', [
            'reason' => 'missing_sec_websocket_key',
        ]);
        ipmiWsRelayErrorResponse(400, 'relay_browser_handshake_failed', 'Missing Sec-WebSocket-Key');
    }

    $raw = base64_decode($key, true);
    if ($raw === false || strlen($raw) !== 16) {
        ipmiWsRelayDebugEvent('ipmi_ws_relay_browser_handshake_failed', [
            'reason' => 'invalid_sec_websocket_key',
        ]);
        ipmiWsRelayErrorResponse(400, 'relay_browser_handshake_failed', 'Invalid Sec-WebSocket-Key');
    }

    if ($ver !== '13') {
        ipmiWsRelayDebugEvent('ipmi_ws_relay_browser_handshake_failed', [
            'reason' => 'unsupported_version',
            'version' => $ver,
        ]);
        ipmiWsRelayErrorResponse(426, 'relay_browser_handshake_failed', 'Sec-WebSocket-Version 13 required', [
            'sec_websocket_version' => $ver,
        ]);
    }

    $accept = base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-5AB5DC11653B', true));

    return ['key' => $key, 'accept' => $accept];
}

function ipmiWsRelayParseTarget(string $raw): ?array
{
    if ($raw === '') {
        return null;
    }
    $p = parse_url($raw);
    if (!is_array($p)) {
        return null;
    }
    $scheme = strtolower((string) ($p['scheme'] ?? 'wss'));
    $host   = (string) ($p['host'] ?? '');
    $path   = (string) ($p['path'] ?? '/');
    $query  = (string) ($p['query'] ?? '');
    if ($query !== '') {
        $path .= '?' . $query;
    }
    $useTls = ($scheme === 'wss');
    $port   = (int) ($p['port'] ?? ($useTls ? 443 : 80));

    if ($host === '' || $port < 1 || $port > 65535) {
        return null;
    }

    return [
        'scheme'  => $scheme,
        'host'    => $host,
        'port'    => $port,
        'path'    => $path,
        'use_tls' => $useTls,
        'raw'     => $raw,
    ];
}

// ---------------------------------------------------------------------------
// Helper: JSON error response with relay diagnostic stage
// ---------------------------------------------------------------------------
function ipmiWsRelayErrorResponse(int $httpCode, string $stage, string $message, array $extra = []): never
{
    ipmiWsRelayDebugEvent('ipmi_ws_relay_http_error_exit', [
        'http_code' => $httpCode,
        'stage'     => $stage,
        'message'   => substr($message, 0, 220),
    ]);
    http_response_code($httpCode);
    header('Content-Type: application/json');
    $body = array_merge([
        'error'   => $message,
        'stage'   => $stage,
        'sapi'    => PHP_SAPI,
    ], $extra);
    echo json_encode($body);
    exit;
}

// ---------------------------------------------------------------------------
// 1. Token validation
// ---------------------------------------------------------------------------
$token = strtolower(trim((string) ($_GET['token'] ?? '')));

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    ipmiWsRelayErrorResponse(400, 'token_validation', 'Invalid token');
}

$GLOBALS['__ipmi_ws_relay_buglog_token'] = $token;

$session = ipmiWebLoadSession($mysqli, $token);
if (!$session) {
    ipmiWsRelayErrorResponse(403, 'session_load', 'Session expired or invalid');
}

// Read panel user then release session lock immediately.
$panelUserId = $_SESSION['user_id'] ?? null;
session_write_close();

if (!$panelUserId) {
    $createdIp = (string) ($session['created_ip'] ?? '');
    $createdUa = (string) ($session['user_agent'] ?? '');
    $remoteIp  = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $currentUa = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
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
        ipmiWsRelayErrorResponse(401, 'auth', 'Authentication required');
    }
}

// ---------------------------------------------------------------------------
// 2. Suspension check
// ---------------------------------------------------------------------------
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
            ipmiWsRelayErrorResponse(403, 'suspension', 'Server is suspended', ['suspended' => 1]);
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Detect upgrade request
// ---------------------------------------------------------------------------
$isWsUpgrade = (
    isset($_SERVER['HTTP_UPGRADE'])
    && stripos((string) $_SERVER['HTTP_UPGRADE'], 'websocket') !== false
);

ipmiWsRelayDebugEvent('ipmi_ws_relay_request_received', [
    'method'         => ($_SERVER['REQUEST_METHOD'] ?? 'unknown'),
    'upgrade'        => ($_SERVER['HTTP_UPGRADE'] ?? 'none'),
    'connection'     => ($_SERVER['HTTP_CONNECTION'] ?? 'none'),
    'is_ws_upgrade'  => $isWsUpgrade,
    'sapi'           => PHP_SAPI,
    'target_present' => (isset($_GET['target']) && $_GET['target'] !== ''),
]);

if (!$isWsUpgrade) {
    $env = ipmiWsRelayEnvironmentSupportsUpgrade();
    header('Content-Type: application/json');
    echo json_encode([
        'status'        => 'ok',
        'message'       => 'WebSocket relay endpoint. Connect with Upgrade: websocket header.',
        'bmc_ip'        => $session['ipmi_ip'],
        'sapi'          => PHP_SAPI,
        'environment'   => $env['verdict'],
        'environment_notes' => $env['notes'],
        'note'          => 'Send a real WebSocket upgrade to use this relay. Upstream BMC WS success/failure is logged server-side (ipmi_ws_relay_upstream_ws_*), not returned in this JSON.',
    ]);
    exit;
}

// ---------------------------------------------------------------------------
// 4. Environment pre-check
// ---------------------------------------------------------------------------
$envCheck = ipmiWsRelayEnvironmentSupportsUpgrade();
if ($envCheck['verdict'] === 'unsupported') {
    ipmiWsRelayDebugEvent('ipmi_ws_relay_relay_environment_unsupported', $envCheck);
    ipmiWsRelayErrorResponse(503, 'environment_check', 'Runtime does not support WebSocket relay', [
        'environment' => $envCheck,
    ]);
}

ipmiWsRelayDebugEvent('ipmi_ws_relay_environment_evaluated', [
    'sapi'        => (string) ($envCheck['sapi'] ?? ''),
    'verdict'     => (string) ($envCheck['verdict'] ?? ''),
    'can_flush'   => !empty($envCheck['can_flush']) ? '1' : '0',
    'can_input'   => !empty($envCheck['can_input']) ? '1' : '0',
    'notes_join'  => implode('|', $envCheck['notes'] ?? []),
]);

ipmiWsRelayDebugEvent('ipmi_ws_relay_browser_handshake_started', [
    'sapi' => PHP_SAPI,
    'ws_key_present' => isset($_SERVER['HTTP_SEC_WEBSOCKET_KEY']),
    'ws_version' => ($_SERVER['HTTP_SEC_WEBSOCKET_VERSION'] ?? 'missing'),
]);

$browserWs = ipmiWsRelayValidateBrowserUpgrade();

// ---------------------------------------------------------------------------
// 5. Parse and validate target
// ---------------------------------------------------------------------------
$targetRaw = trim((string) ($_GET['target'] ?? ''));
$target = ipmiWsRelayParseTarget($targetRaw);

if (!$target) {
    ipmiWsRelayDebugEvent('ipmi_ws_relay_target_invalid', ['raw_len' => strlen($targetRaw)]);
    ipmiWsRelayErrorResponse(400, 'target_validation', 'Invalid or missing target WebSocket URL');
}

$bmcIp  = $session['ipmi_ip'];
$useTls = $target['use_tls'];
$bmcPort = $target['port'];
$wsPath  = $target['path'];

// ---------------------------------------------------------------------------
// 6. Build upstream handshake (separate Sec-WebSocket-Key from browser)
// ---------------------------------------------------------------------------
$upstreamWsKey = base64_encode(random_bytes(16));
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
if ($clientProto !== '' && strlen($clientProto) <= 512 && preg_match('/^[A-Za-z0-9\s,;\.\-_]+$/', $clientProto)) {
    $protoLine = 'Sec-WebSocket-Protocol: ' . $clientProto . "\r\n";
}

$handshake = "GET {$wsPath} HTTP/1.1\r\n"
    . "Host: {$hostLine}\r\n"
    . "Upgrade: websocket\r\n"
    . "Connection: Upgrade\r\n"
    . "Sec-WebSocket-Key: {$upstreamWsKey}\r\n"
    . "Sec-WebSocket-Version: 13\r\n"
    . "Origin: {$originLine}\r\n"
    . $protoLine
    . $cookieHeader
    . $extraHeaders
    . "\r\n";

// ---------------------------------------------------------------------------
// 7. Close DB before long-lived relay
// ---------------------------------------------------------------------------
if (isset($mysqli) && $mysqli instanceof mysqli) {
    @$mysqli->close();
    unset($mysqli);
}

// ---------------------------------------------------------------------------
// 8. Open upstream TCP/TLS connection to BMC
// ---------------------------------------------------------------------------
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

ipmiWsRelayDebugEvent('ipmi_ws_relay_upstream_connect_started', [
    'spec'    => $connectSpec,
    'tls'     => $useTls,
    'bmc_ip'  => $bmcIp,
    'port'    => $bmcPort,
    'path_len' => strlen($wsPath),
]);

$connectStart = microtime(true);
$remote = @stream_socket_client(
    $connectSpec,
    $errno,
    $errstr,
    10,
    STREAM_CLIENT_CONNECT,
    $useTls ? $ctx : null
);
$connectMs = round((microtime(true) - $connectStart) * 1000);

if (!$remote) {
    $stage = $useTls ? 'upstream_tls_failed' : 'upstream_tcp_failed';
    ipmiWsRelayDebugEvent('ipmi_ws_relay_' . $stage, [
        'errno'       => $errno,
        'err'         => substr((string) $errstr, 0, 200),
        'connect_ms'  => $connectMs,
        'connect_spec' => $connectSpec,
    ]);
    ipmiWsRelayErrorResponse(502, $stage, 'Cannot connect to BMC: ' . $errstr, [
        'connect_ms' => $connectMs,
        'tls'        => $useTls,
    ]);
}

ipmiWsRelayDebugEvent($useTls ? 'ipmi_ws_relay_upstream_tls_connected' : 'ipmi_ws_relay_upstream_tcp_connected', [
    'connect_ms' => $connectMs,
    'bmc_ip'     => $bmcIp,
    'port'       => $bmcPort,
]);

// ---------------------------------------------------------------------------
// 9. Upstream WebSocket handshake
// ---------------------------------------------------------------------------
fwrite($remote, $handshake);

$responseHeader = '';
$headerReadStart = microtime(true);
while (!feof($remote)) {
    $line = fgets($remote, 4096);
    if ($line === false) {
        break;
    }
    $responseHeader .= $line;
    if (trim($line) === '') {
        break;
    }
    if (strlen($responseHeader) > 16384) {
        break;
    }
}
$headerReadMs = round((microtime(true) - $headerReadStart) * 1000);

$upstreamHttpCode = 0;
if (preg_match('/HTTP\/\S+\s+(\d{3})\b/', $responseHeader, $hm)) {
    $upstreamHttpCode = (int) $hm[1];
}

if ($upstreamHttpCode !== 101) {
    $firstLine = trim((string) strtok($responseHeader, "\n"));
    $hl = strtolower($responseHeader);
    ipmiWsRelayDebugEvent('ipmi_ws_relay_upstream_ws_handshake_failed', [
        'upstream_http'    => $upstreamHttpCode,
        'first_line'       => substr($firstLine, 0, 120),
        'header_bytes'     => strlen($responseHeader),
        'header_read_ms'   => $headerReadMs,
        'www_authenticate' => str_contains($hl, 'www-authenticate'),
        'has_location'     => (bool) preg_match('/^location:\s/im', $responseHeader),
        'has_set_cookie'   => (bool) preg_match('/^set-cookie:\s/im', $responseHeader),
    ]);
    fclose($remote);
    ipmiWsRelayErrorResponse(502, 'upstream_ws_handshake_failed', 'BMC WebSocket handshake failed', [
        'upstream_http' => $upstreamHttpCode,
        'header_read_ms' => $headerReadMs,
    ]);
}

ipmiWsRelayDebugEvent('ipmi_ws_relay_upstream_ws_handshake_succeeded', [
    'upstream_http' => 101,
    'header_bytes'  => strlen($responseHeader),
    'header_read_ms' => $headerReadMs,
    'cookie_fwd'    => ($cookieHeader !== ''),
    'proto_fwd'     => ($protoLine !== ''),
]);

// ---------------------------------------------------------------------------
// 10. Send 101 Switching Protocols to browser (Accept from *client* key, RFC 6455)
// ---------------------------------------------------------------------------
$browserAccept = $browserWs['accept'];

$bmcProto = '';
if (preg_match('/Sec-WebSocket-Protocol:\s*([^\r\n]+)/i', $responseHeader, $spMatch)) {
    $bmcProto = trim($spMatch[1]);
}

ipmiWsRelayDebugEvent('ipmi_ws_relay_browser_handshake_accepting', [
    'sapi'         => PHP_SAPI,
    'bmc_proto'    => ($bmcProto !== '' ? $bmcProto : 'none'),
    'client_proto' => ($clientProto !== '' ? $clientProto : 'none'),
]);

header('HTTP/1.1 101 Switching Protocols');
header('Upgrade: websocket');
header('Connection: Upgrade');
header('Sec-WebSocket-Accept: ' . $browserAccept);
if ($bmcProto !== '') {
    header('Sec-WebSocket-Protocol: ' . $bmcProto);
}

while (ob_get_level()) {
    ob_end_flush();
}
flush();

if (function_exists('apache_setenv')) {
    @apache_setenv('no-gzip', '1');
}
@ini_set('zlib.output_compression', '0');
@ini_set('implicit_flush', '1');

ipmiWsRelayDebugEvent('ipmi_ws_relay_browser_handshake_succeeded', ['sapi' => PHP_SAPI]);

// ---------------------------------------------------------------------------
// 11. Frame pump
// ---------------------------------------------------------------------------
set_time_limit(0);
stream_set_blocking($remote, false);

$clientIn  = fopen('php://input', 'rb');
$clientOut = fopen('php://output', 'wb');

if (!$clientIn || !$clientOut) {
    ipmiWsRelayDebugEvent('ipmi_ws_relay_client_streams_failed', [
        'clientIn'  => (bool) $clientIn,
        'clientOut' => (bool) $clientOut,
    ]);
    fclose($remote);
    exit;
}

stream_set_blocking($clientIn, false);

$deadline        = time() + 7200;
$bytesFromBmc    = 0;
$bytesFromClient = 0;
$framesBmc       = 0;
$framesClient    = 0;
$relayStartTs    = microtime(true);
$lastActivityTs  = microtime(true);
$idleTimeoutSec  = 300;
$pumpErrors      = 0;
$firstFrameSeen  = false;
$idleExit        = false;
$sustainedFlowObserved = false;
$sustainedThresholds = ipmiWsRelaySustainedFlowThresholds();
$sustainedMinBmcBytes = $sustainedThresholds['min_bmc_bytes'];
$sustainedMinBmcFrames = $sustainedThresholds['min_bmc_frames'];

ipmiWsRelayDebugEvent('ipmi_ws_relay_frame_pump_started', [
    'sapi'                      => PHP_SAPI,
    'deadline_sec'              => 7200,
    'idle_timeout'              => $idleTimeoutSec,
    'sustained_min_bmc_bytes'   => $sustainedMinBmcBytes,
    'sustained_min_bmc_frames'  => $sustainedMinBmcFrames,
]);

while (!feof($remote) && time() < $deadline) {
    $read   = [$remote, $clientIn];
    $write  = null;
    $except = null;

    $changed = @stream_select($read, $write, $except, 1, 0);
    if ($changed === false) {
        $pumpErrors++;
        ipmiWsRelayDebugEvent('ipmi_ws_relay_frame_pump_error', ['kind' => 'select', 'errors' => $pumpErrors]);
        if ($pumpErrors > 10) {
            break;
        }
        continue;
    }

    if ($changed === 0) {
        if ((microtime(true) - $lastActivityTs) > $idleTimeoutSec) {
            $idleExit = true;
            ipmiWsRelayDebugEvent('ipmi_ws_relay_frame_pump_idle_timeout', [
                'idle_sec' => round(microtime(true) - $lastActivityTs),
                'bmc_bytes' => $bytesFromBmc,
                'bmc_frames' => $framesBmc,
                'sustained_prior' => $sustainedFlowObserved ? '1' : '0',
            ]);
            break;
        }
        continue;
    }

    foreach ($read as $stream) {
        $data = @fread($stream, 65536);
        if ($data === false || $data === '') {
            if (feof($stream)) {
                $who = ($stream === $remote) ? 'bmc' : 'client';
                ipmiWsRelayDebugEvent('ipmi_ws_relay_frame_pump_eof', ['side' => $who]);
                break 2;
            }
            continue;
        }

        $lastActivityTs = microtime(true);

        if ($stream === $remote) {
            $bytesFromBmc += strlen($data);
            $framesBmc++;
            if (!$firstFrameSeen && strlen($data) > 0) {
                $firstFrameSeen = true;
                ipmiWsRelayDebugEvent('ipmi_ws_relay_first_frame_observed', [
                    'from'  => 'bmc',
                    'bytes' => strlen($data),
                ]);
            }
            if (!$sustainedFlowObserved && ipmiWsRelayObserveSustainedFrameFlow($bytesFromBmc, $framesBmc, false)) {
                $sustainedFlowObserved = true;
                ipmiWsRelayDebugEvent('ipmi_ws_relay_sustained_frame_flow_observed', [
                    'bytes_from_bmc' => $bytesFromBmc,
                    'frames_bmc'     => $framesBmc,
                    'elapsed_sec'    => round(microtime(true) - $relayStartTs, 2),
                ]);
            }
            $written = @fwrite($clientOut, $data);
            if ($written === false) {
                ipmiWsRelayDebugEvent('ipmi_ws_relay_frame_pump_error', [
                    'kind' => 'client_write_failed',
                    'bytes_attempted' => strlen($data),
                ]);
                break 2;
            }
            @fflush($clientOut);
        } else {
            $bytesFromClient += strlen($data);
            $framesClient++;
            $written = @fwrite($remote, $data);
            if ($written === false) {
                ipmiWsRelayDebugEvent('ipmi_ws_relay_frame_pump_error', [
                    'kind' => 'upstream_write_failed',
                    'bytes_attempted' => strlen($data),
                ]);
                break 2;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 12. Cleanup and final log
// ---------------------------------------------------------------------------
$elapsed = round(microtime(true) - $relayStartTs, 2);
$healthy = $sustainedFlowObserved && ($bytesFromBmc > 0 && $bytesFromClient > 0) && !$idleExit;

ipmiWsRelayDebugEvent('ipmi_ws_relay_closed', [
    'elapsed_sec'               => $elapsed,
    'bytes_from_bmc'            => $bytesFromBmc,
    'bytes_from_client'         => $bytesFromClient,
    'frames_bmc'                => $framesBmc,
    'frames_client'             => $framesClient,
    'pump_errors'               => $pumpErrors,
    'idle_exit'                 => $idleExit ? '1' : '0',
    'first_frame_seen'          => $firstFrameSeen ? '1' : '0',
    'sustained_flow_observed'   => $sustainedFlowObserved ? '1' : '0',
    'transport_healthy_session' => $healthy ? '1' : '0',
    'sapi'                      => PHP_SAPI,
]);

@fclose($clientIn);
@fclose($clientOut);
@fclose($remote);
