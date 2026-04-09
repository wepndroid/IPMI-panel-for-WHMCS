#!/usr/bin/env php
<?php
/**
 * Full matrix web probe across servers, grouped by failure pattern.
 *
 * Usage:
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --limit=200
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --type=ilo4
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --ids=281,282,385
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --include-suspended=1
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --samples=3
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --deep=1
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --proxy=1
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --e2e=1 --proxy=1
 *   php /var/www/html/jobs/ipmi_web_probe_matrix.php --json=/tmp/ipmi_probe_matrix.json
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit("CLI only\n");
}

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../lib/ipmi_web_probe.php';

if (!ipmiWebProbeShouldRun()) {
    fwrite(STDERR, "Web probe disabled (IPMI_WEB_PROBE=0 or IPMI_WEB_PROBE_AUTO=false).\n");
    exit(0);
}

function ipmiProbeMatrixArg(string $prefix, array $argv): ?string
{
    foreach ($argv as $arg) {
        if (strpos($arg, $prefix) === 0) {
            return substr($arg, strlen($prefix));
        }
    }

    return null;
}

function ipmiProbeMatrixNormalizeType(string $type): string
{
    $t = strtolower(trim($type));
    if ($t === '') {
        return 'generic';
    }

    return $t;
}

$argv = $_SERVER['argv'] ?? [];
$limitArg = ipmiProbeMatrixArg('--limit=', $argv);
$typeArg = ipmiProbeMatrixArg('--type=', $argv);
$idsArg = ipmiProbeMatrixArg('--ids=', $argv);
$includeSuspendedArg = ipmiProbeMatrixArg('--include-suspended=', $argv);
$samplesArg = ipmiProbeMatrixArg('--samples=', $argv);
$deepArg = ipmiProbeMatrixArg('--deep=', $argv);
$proxyArg = ipmiProbeMatrixArg('--proxy=', $argv);
$e2eArg = ipmiProbeMatrixArg('--e2e=', $argv);
$jsonPath = ipmiProbeMatrixArg('--json=', $argv);

$limit = $limitArg !== null ? max(0, (int) $limitArg) : 0;
$filterType = $typeArg !== null ? ipmiProbeMatrixNormalizeType($typeArg) : '';
$includeSuspended = $includeSuspendedArg === '1';
$samplePerGroup = $samplesArg !== null ? max(1, min(10, (int) $samplesArg)) : 2;
$deep = ($deepArg === null) ? true : ($deepArg === '1');
$proxyFlow = ($proxyArg === '1');
$e2e = ($e2eArg === '1');

$ids = [];
if ($idsArg !== null) {
    foreach (explode(',', $idsArg) as $raw) {
        $id = (int) trim($raw);
        if ($id > 0) {
            $ids[$id] = true;
        }
    }
    $ids = array_keys($ids);
}

$lockFile = sys_get_temp_dir() . '/ipmi_web_probe_matrix.lock';
$lockFp = fopen($lockFile, 'c');
if (!$lockFp || !flock($lockFp, LOCK_EX | LOCK_NB)) {
    fwrite(STDERR, "Another ipmi_web_probe_matrix instance is running.\n");
    exit(0);
}

$start = microtime(true);

$sql = "
    SELECT s.id, s.server_name, s.ipmi_ip, s.bmc_type, COALESCE(ss.suspended, 0) AS suspended
    FROM servers s
    LEFT JOIN server_suspension ss ON ss.server_id = s.id
";

$where = [];
if (!$includeSuspended) {
    $where[] = "COALESCE(ss.suspended, 0) = 0";
}
if ($filterType !== '') {
    $where[] = "s.bmc_type = ?";
}
if (!empty($ids)) {
    $idList = implode(',', array_map('intval', $ids));
    $where[] = "s.id IN (" . $idList . ")";
}
if (!empty($where)) {
    $sql .= " WHERE " . implode(' AND ', $where);
}
$sql .= " ORDER BY s.id ASC";
if ($limit > 0) {
    $sql .= " LIMIT " . (int) $limit;
}

$stmt = $mysqli->prepare($sql);
if (!$stmt) {
    fwrite(STDERR, "DB prepare failed: " . $mysqli->error . "\n");
    flock($lockFp, LOCK_UN);
    fclose($lockFp);
    exit(1);
}
if ($filterType !== '') {
    $stmt->bind_param('s', $filterType);
}
$stmt->execute();
$res = $stmt->get_result();

$rows = [];
while ($res && ($row = $res->fetch_assoc())) {
    $rows[] = [
        'id'        => (int) $row['id'],
        'server'    => (string) $row['server_name'],
        'ip'        => (string) $row['ipmi_ip'],
        'type'      => ipmiProbeMatrixNormalizeType((string) $row['bmc_type']),
        'suspended' => (int) ($row['suspended'] ?? 0),
    ];
}
$stmt->close();

$totals = [
    'scanned' => 0,
    'ok' => 0,
    'fail' => 0,
    'skipped' => 0,
];

$byType = [];
$failureGroups = [];

foreach ($rows as $row) {
    $sid = $row['id'];
    $stype = $row['type'];
    $totals['scanned']++;
    if (!isset($byType[$stype])) {
        $byType[$stype] = ['total' => 0, 'ok' => 0, 'fail' => 0, 'skipped' => 0];
    }
    $byType[$stype]['total']++;

    $result = ipmiWebProbeServerWebUiDetailed($mysqli, $sid, $deep, $proxyFlow, $e2e);
    ipmiWebProbeLogResult($sid, $result);

    if (!empty($result['skipped'])) {
        $totals['skipped']++;
        $byType[$stype]['skipped']++;
        continue;
    }

    if (!empty($result['ok'])) {
        $totals['ok']++;
        $byType[$stype]['ok']++;
        continue;
    }

    $totals['fail']++;
    $byType[$stype]['fail']++;
    $err = (string) ($result['error'] ?? 'unknown');
    $key = $stype . '|' . $err;
    if (!isset($failureGroups[$key])) {
        $failureGroups[$key] = [
            'type' => $stype,
            'error' => $err,
            'count' => 0,
            'samples' => [],
        ];
    }
    $failureGroups[$key]['count']++;
    if (count($failureGroups[$key]['samples']) < $samplePerGroup) {
        $sample = [
            'id' => $row['id'],
            'server' => $row['server'],
            'ip' => $row['ip'],
        ];
        if (!empty($result['checks']) && is_array($result['checks'])) {
            $sample['checks'] = $result['checks'];
        }
        $failureGroups[$key]['samples'][] = $sample;
    }
}

uasort($failureGroups, static function (array $a, array $b): int {
    if ($a['count'] === $b['count']) {
        return strcmp($a['type'] . '|' . $a['error'], $b['type'] . '|' . $b['error']);
    }

    return $b['count'] <=> $a['count'];
});
ksort($byType);

$durationSec = round(microtime(true) - $start, 3);

echo "IPMI Web Probe Matrix\n";
echo "Scanned: {$totals['scanned']}  OK: {$totals['ok']}  FAIL: {$totals['fail']}  SKIPPED: {$totals['skipped']}  Duration: {$durationSec}s  Deep=" . ($deep ? '1' : '0') . "  Proxy=" . ($proxyFlow ? '1' : '0') . "  E2E=" . ($e2e ? '1' : '0') . "\n";
echo "\nBy BMC type:\n";
foreach ($byType as $type => $stats) {
    echo "  {$type}: total={$stats['total']} ok={$stats['ok']} fail={$stats['fail']} skipped={$stats['skipped']}\n";
}

echo "\nFailure groups:\n";
if (empty($failureGroups)) {
    echo "  none\n";
} else {
    $idx = 1;
    foreach ($failureGroups as $group) {
        echo "  {$idx}. type={$group['type']} error={$group['error']} count={$group['count']}\n";
        foreach ($group['samples'] as $sample) {
            echo "     - id={$sample['id']} server={$sample['server']} ip={$sample['ip']}\n";
            if (!empty($sample['checks']) && is_array($sample['checks'])) {
                foreach ($sample['checks'] as $chk) {
                    $kind = (string) ($chk['kind'] ?? 'direct');
                    $path = (string) ($chk['path'] ?? '');
                    if ($kind === 'proxy_assets') {
                        $aTotal = (int) ($chk['asset_total'] ?? 0);
                        $aFail = (int) ($chk['asset_fail'] ?? 0);
                        $aCritTotal = (int) ($chk['asset_critical_total'] ?? 0);
                        $aCritFail = (int) ($chk['asset_critical_fail'] ?? 0);
                        $aOk = !empty($chk['asset_ok']) ? 1 : 0;
                        echo "       · check kind={$kind} path={$path} assets={$aTotal} fail={$aFail} critical={$aCritFail}/{$aCritTotal} ok={$aOk}\n";
                        if (!empty($chk['asset_failed_samples']) && is_array($chk['asset_failed_samples'])) {
                            $sampleIdx = 0;
                            foreach ($chk['asset_failed_samples'] as $af) {
                                $sampleIdx++;
                                if ($sampleIdx > 3) {
                                    break;
                                }
                                $asset = (string) ($af['asset'] ?? '');
                                $resolved = (string) ($af['resolved_path'] ?? '');
                                $aHttp = (int) ($af['http'] ?? 0);
                                echo "         · asset http={$aHttp} src={$asset} resolved={$resolved}\n";
                            }
                        }
                        continue;
                    }
                    $http = (int) ($chk['http'] ?? 0);
                    $bytes = (int) ($chk['body_bytes'] ?? 0);
                    $lp = !empty($chk['login_page']) ? 1 : 0;
                    $tt = !empty($chk['timeout_text']) ? 1 : 0;
                    $ts = !empty($chk['timeout_shell']) ? 1 : 0;
                    $px = !empty($chk['proxy_expired']) ? 1 : 0;
                    $rl = !empty($chk['redirect_loop']) ? 1 : 0;
                    $fu = trim((string) ($chk['final_url'] ?? ''));
                    $ce = trim((string) ($chk['curl_error'] ?? ''));
                    $line = "       · check kind={$kind} path={$path} http={$http} bytes={$bytes} login={$lp} timeoutText={$tt} timeoutShell={$ts}";
                    if ($kind === 'proxy') {
                        $line .= " proxyExpired={$px} redirectLoop={$rl}";
                        if ($fu !== '') {
                            $line .= " finalUrl={$fu}";
                        }
                        if ($ce !== '') {
                            $line .= " curlErr={$ce}";
                        }
                    }
                    echo $line . "\n";
                }
            }
        }
        $idx++;
    }
}

$report = [
    'generated_at_utc' => gmdate('Y-m-d H:i:s'),
    'duration_sec' => $durationSec,
    'args' => [
        'limit' => $limit,
        'type' => $filterType,
        'include_suspended' => $includeSuspended,
        'sample_per_group' => $samplePerGroup,
        'deep' => $deep,
        'proxy' => $proxyFlow,
        'e2e' => $e2e,
        'ids' => $ids,
    ],
    'totals' => $totals,
    'by_type' => $byType,
    'failure_groups' => array_values($failureGroups),
];

if ($jsonPath !== null && trim($jsonPath) !== '') {
    $encoded = json_encode($report, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    if ($encoded === false) {
        fwrite(STDERR, "\nFailed to encode JSON report.\n");
    } else {
        $okWrite = @file_put_contents($jsonPath, $encoded . "\n");
        if ($okWrite === false) {
            fwrite(STDERR, "\nFailed to write JSON report to: {$jsonPath}\n");
        } else {
            echo "\nJSON report: {$jsonPath}\n";
        }
    }
}

flock($lockFp, LOCK_UN);
fclose($lockFp);

exit($totals['fail'] > 0 ? 1 : 0);
