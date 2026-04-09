#!/usr/bin/env php
<?php
/**
 * Standalone sweep: probe BMC web UI (auto-login + iLO /json/session_info) for every non-suspended server.
 * Cron example (daily): 0 3 * * * php /var/www/html/jobs/ipmi_web_probe.php --limit=200
 * Optional deep checks: --deep=1
 * Optional proxy-flow checks (same path as Open IPMI Session): --proxy=1
 * Optional deeper E2E checks (asset/load/logout stability): --e2e=1
 *
 * Disable all web probes: env IPMI_WEB_PROBE=0 or define IPMI_WEB_PROBE_AUTO false in config.php
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('CLI only');
}

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../lib/ipmi_web_probe.php';

if (!ipmiWebProbeShouldRun()) {
    fwrite(STDERR, "Web probe disabled (IPMI_WEB_PROBE=0 or IPMI_WEB_PROBE_AUTO=false or not CLI).\n");
    exit(0);
}

$limit = 500;
$targetId = 0;
$deep = false;
$proxyFlow = false;
$e2e = false;
foreach ($_SERVER['argv'] ?? [] as $arg) {
    if (strpos($arg, '--limit=') === 0) {
        $limit = max(1, (int) substr($arg, 8));
    }
    if (strpos($arg, '--id=') === 0) {
        $targetId = (int) substr($arg, 5);
    }
    if (strpos($arg, '--deep=') === 0) {
        $deep = substr($arg, 7) === '1';
    }
    if (strpos($arg, '--proxy=') === 0) {
        $proxyFlow = substr($arg, 8) === '1';
    }
    if (strpos($arg, '--e2e=') === 0) {
        $e2e = substr($arg, 6) === '1';
    }
}

$lockFile = sys_get_temp_dir() . '/ipmi_web_probe.lock';
$lockFp = fopen($lockFile, 'c');
if (!$lockFp || !flock($lockFp, LOCK_EX | LOCK_NB)) {
    fwrite(STDERR, "Another ipmi_web_probe instance is running.\n");
    exit(0);
}

$ok = 0;
$fail = 0;
$skip = 0;

if ($targetId > 0) {
    $probe = ipmiWebProbeServerWebUiDetailed($mysqli, $targetId, $deep, $proxyFlow, $e2e);
    ipmiWebProbeLogResult($targetId, $probe);
    if (!empty($probe['skipped'])) {
        $skip++;
    } elseif (!empty($probe['ok'])) {
        $ok++;
    } else {
        $fail++;
    }
    echo json_encode([
        'server_id' => $targetId,
        'deep' => $deep ? 1 : 0,
        'proxy' => $proxyFlow ? 1 : 0,
        'e2e' => $e2e ? 1 : 0,
        'result' => $probe
    ], JSON_UNESCAPED_SLASHES) . "\n";
} else {
    $stmt = $mysqli->prepare("
        SELECT s.id
        FROM servers s
        LEFT JOIN server_suspension ss ON ss.server_id = s.id
        WHERE COALESCE(ss.suspended, 0) = 0
        ORDER BY s.id ASC
        LIMIT ?
    ");
    if (!$stmt) {
        fwrite(STDERR, 'DB error: ' . $mysqli->error . "\n");
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
        exit(1);
    }
    $stmt->bind_param('i', $limit);
    $stmt->execute();
    $res = $stmt->get_result();
    while ($res && ($row = $res->fetch_assoc())) {
        $sid = (int) $row['id'];
        $probe = ipmiWebProbeServerWebUiDetailed($mysqli, $sid, $deep, $proxyFlow, $e2e);
        ipmiWebProbeLogResult($sid, $probe);
        if (!empty($probe['skipped'])) {
            $skip++;
        } elseif (!empty($probe['ok'])) {
            $ok++;
        } else {
            $fail++;
        }
    }
    $stmt->close();
    echo json_encode([
        'ok' => $ok,
        'fail' => $fail,
        'skipped' => $skip,
        'limit' => $limit,
        'deep' => $deep ? 1 : 0,
        'proxy' => $proxyFlow ? 1 : 0,
        'e2e' => $e2e ? 1 : 0
    ], JSON_UNESCAPED_SLASHES) . "\n";
}

flock($lockFp, LOCK_UN);
fclose($lockFp);
exit($fail > 0 ? 1 : 0);
