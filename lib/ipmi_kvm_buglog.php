<?php
/**
 * Project-local KVM run diagnostic log (bugs.txt in project root).
 * One canonical file: reset on each KVM button click, append with LOCK_EX for the active run.
 */

declare(strict_types=1);

require_once __DIR__ . '/ipmi_web_session.php';

/**
 * Absolute path to bugs.txt (project root).
 */
function ipmiKvmBugLogRootPath(): string
{
    return dirname(__DIR__) . DIRECTORY_SEPARATOR . 'bugs.txt';
}

/**
 * Mask a secret for logging: keep last 8 chars when long enough.
 */
function ipmiKvmBugLogMaskSecrets(?string $s, int $tailKeep = 8): string
{
    $s = trim((string) $s);
    if ($s === '') {
        return '';
    }
    $len = strlen($s);
    if ($len <= $tailKeep) {
        return '****';
    }

    return '****' . substr($s, -$tailKeep);
}

/**
 * Truncate bugs.txt (used internally by start run).
 */
function ipmiKvmBugLogResetFile(): void
{
    $path = ipmiKvmBugLogRootPath();
    $fp = @fopen($path, 'cb');
    if ($fp === false) {
        return;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);

        return;
    }
    ftruncate($fp, 0);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
}

/**
 * Reset bugs.txt at the start of every panel KVM attempt (after session row exists).
 * Replaced entirely by ipmiKvmBugLogStartRun() when the launch plan succeeds.
 */
function ipmiKvmBugLogBeginPanelAttempt(int $serverId): void
{
    $path = ipmiKvmBugLogRootPath();
    $fp = @fopen($path, 'cb');
    if ($fp === false) {
        return;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);

        return;
    }
    ftruncate($fp, 0);
    $t = gmdate('c') . 'Z';
    $body = "==================================================\n"
        . "KVM PANEL ATTEMPT\n"
        . 'started_at_utc: ' . $t . "\n"
        . 'service_id: ' . max(0, $serverId) . "\n"
        . "note: one reset per KVM click; KVM RUN START overwrites this after launch plan ok\n"
        . "==================================================\n\n";
    fwrite($fp, $body);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
}

/**
 * Append one UTF-8 line (caller supplies trailing \n if needed).
 */
function ipmiKvmBugLogAppend(string $line): void
{
    $path = ipmiKvmBugLogRootPath();
    $line = str_replace(["\r", "\n"], ' ', $line);
    $line = rtrim($line) . "\n";
    $fp = @fopen($path, 'ab');
    if ($fp === false) {
        return;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);

        return;
    }
    fwrite($fp, $line);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
}

/**
 * Read active run_id from bugs.txt header (LOCK_SH).
 */
function ipmiKvmBugLogCurrentRunId(): ?string
{
    $path = ipmiKvmBugLogRootPath();
    if (!is_readable($path)) {
        return null;
    }
    $fp = @fopen($path, 'rb');
    if ($fp === false) {
        return null;
    }
    flock($fp, LOCK_SH);
    $head = '';
    for ($i = 0; $i < 48 && !feof($fp); $i++) {
        $head .= (string) fgets($fp, 4096);
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    if (preg_match('/^run_id:\s*(\S+)/m', $head, $m)) {
        return trim($m[1]);
    }

    return null;
}

/**
 * Read token_suffix from header for relay/ingest correlation.
 */
function ipmiKvmBugLogReadTokenSuffixFromHeader(): ?string
{
    $path = ipmiKvmBugLogRootPath();
    if (!is_readable($path)) {
        return null;
    }
    $fp = @fopen($path, 'rb');
    if ($fp === false) {
        return null;
    }
    flock($fp, LOCK_SH);
    $head = '';
    for ($i = 0; $i < 48 && !feof($fp); $i++) {
        $head .= (string) fgets($fp, 4096);
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    if (preg_match('/^token_suffix:\s*(\S+)/m', $head, $m)) {
        return strtolower(trim($m[1]));
    }

    return null;
}

/**
 * Start a new KVM run: reset file, write header + plan block, return run_id.
 *
 * @param array<string, mixed> $ctx
 */
function ipmiKvmBugLogStartRun(array $ctx): string
{
    $runId = bin2hex(random_bytes(8));
    $started = gmdate('c') . 'Z';
    $token = strtolower(trim((string) ($ctx['token'] ?? '')));
    $suffix = (strlen($token) === 64) ? substr($token, -8) : '';
    $path = ipmiKvmBugLogRootPath();

    $fp = @fopen($path, 'cb');
    if ($fp === false) {
        return $runId;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);

        return $runId;
    }
    ftruncate($fp, 0);

    $bmcHostMasked = ipmiKvmBugLogMaskSecrets((string) ($ctx['bmc_host'] ?? ''), 12);
    $tokenMasked = ipmiKvmBugLogMaskSecrets($token, 8);

    $lines = [
        '==================================================',
        'KVM RUN START',
        'run_id: ' . $runId,
        'started_at_utc: ' . $started,
        'panel_entry: ' . trim((string) ($ctx['panel_entry'] ?? 'ipmi_kvm.php')),
        'service_id: ' . trim((string) ($ctx['service_id'] ?? '')),
        'bmc_type: ' . trim((string) ($ctx['bmc_type'] ?? '')),
        'vendor_family: ' . trim((string) ($ctx['vendor_family'] ?? '')),
        'bmc_host_masked: ' . $bmcHostMasked,
        'token_masked: ' . $tokenMasked,
        'token_suffix: ' . $suffix,
        '======================',
        '',
        '[PLAN]',
        'selected_path: ' . trim((string) ($ctx['selected_path'] ?? '')),
        'strategy: ' . trim((string) ($ctx['strategy'] ?? '')),
        'capability: ' . trim((string) ($ctx['capability'] ?? '')),
        'native_verdict: ' . trim((string) ($ctx['native_verdict'] ?? '')),
        'delivery_tier: ' . trim((string) ($ctx['delivery_tier'] ?? '')),
        'user_facing_mode: ' . trim((string) ($ctx['user_facing_mode'] ?? '')),
        '',
        '[SERVER]',
        'event: kvm_run_log_initialized',
        '',
        '[BROWSER]',
        '',
        '[HELPER]',
        '',
        '[TRANSPORT]',
        '',
        '[BUG]',
        '',
        '[NOTE]',
        'event: final_summary_deferred | note: [FINAL] after relay terminal / pagehide kvm_run_finalize / server mark closed; kvm_final_summary only snapshots session until then',
        '',
        '==================================================',
        'KVM RUN END (in progress)',
        '===========',
        '',
    ];
    fwrite($fp, implode("\n", $lines));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return $runId;
}

function ipmiKvmBugLogAppendSection(string $section, string $bodyLine): void
{
    $section = strtoupper(trim($section));
    if ($section === '') {
        $section = 'NOTE';
    }
    ipmiKvmBugLogAppend('[' . $section . '] ' . $bodyLine);
}

function ipmiKvmBugLogAppendBug(string $code, string $summary, string $detail = ''): void
{
    $detail = trim($detail);
    if ($detail !== '') {
        $detail = ' | detail: ' . ipmiKvmBugLogMaskSecrets($detail, 24);
    }
    ipmiKvmBugLogAppend('[BUG] code: ' . trim($code) . ' | summary: ' . trim($summary) . $detail);
}

/**
 * Verify token belongs to active run (suffix match against bugs.txt header).
 */
function ipmiKvmBugLogTokenMatchesActiveRun(string $token): bool
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return false;
    }
    $want = strtolower(substr($token, -8));
    $got = ipmiKvmBugLogReadTokenSuffixFromHeader();

    return $got !== null && $got !== '' && hash_equals($got, $want);
}

/**
 * True when bugs.txt represents an in-progress KVM run (header present, file non-empty).
 */
function ipmiKvmBugLogHasOpenRun(): bool
{
    $id = ipmiKvmBugLogCurrentRunId();

    return $id !== null && $id !== '';
}

/**
 * Whether a [FINAL] block may be written (active run + token matches when provided).
 */
function ipmiKvmBugLogCanFinalizeRun(string $token): bool
{
    if (!ipmiKvmBugLogHasOpenRun()) {
        return false;
    }
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return true;
    }

    return ipmiKvmBugLogTokenMatchesActiveRun($token);
}

/**
 * Persist last browser kvm_final_summary payload so [FINAL] can be recomputed after later relay events.
 *
 * @param array<string, mixed> $payload
 */
function ipmiKvmBugLogPersistLastFinalPayload(mysqli $mysqli, string $token, array $payload): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $snap = [
        'token'   => strtolower($token),
        'run_id'  => (string) ($payload['run_id'] ?? ''),
        'section' => (string) ($payload['section'] ?? 'FINAL'),
        'event'   => (string) ($payload['event'] ?? ''),
        'detail'  => is_array($payload['detail'] ?? null) ? array_slice($payload['detail'], 0, 96, true) : [],
    ];
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($snap): void {
        $meta['kvm_buglog_last_final_payload'] = $snap;
    });
}

/**
 * Priority for rewriting [FINAL] after a relay log line (higher = refresh sooner).
 */
function ipmiKvmBugLogRelayEventFinalRefreshPriority(string $event): int
{
    return match (true) {
        $event === 'ipmi_ws_relay_closed' => 3,
        $event === 'ipmi_ws_relay_http_error_exit' => 3,
        $event === 'ipmi_ws_relay_frame_pump_idle_timeout' => 3,
        str_contains($event, 'ipmi_ws_relay_upstream_ws_handshake_failed') => 3,
        str_contains($event, 'ipmi_ws_relay_upstream_tls_failed') => 3,
        str_contains($event, 'ipmi_ws_relay_upstream_tcp_failed') => 3,
        $event === 'ipmi_ws_relay_sustained_frame_flow_observed' => 2,
        $event === 'ipmi_ws_relay_first_frame_observed' => 1,
        str_contains($event, 'ipmi_ws_relay_frame_pump_error') => 2,
        // Success-path lines that often land after an early [FINAL]: refresh so TRANSPORT does not trail a stale block.
        $event === 'ipmi_ws_relay_frame_pump_started' => 1,
        $event === 'ipmi_ws_relay_browser_handshake_succeeded' => 1,
        $event === 'ipmi_ws_relay_browser_handshake_accepting' => 1,
        $event === 'ipmi_ws_relay_upstream_ws_handshake_succeeded' => 1,
        $event === 'ipmi_ws_relay_upstream_tls_connected' => 1,
        $event === 'ipmi_ws_relay_upstream_tcp_connected' => 1,
        default => 0,
    };
}

/**
 * After relay logs a meaningful transport line, write or rewrite [FINAL] at EOF.
 *
 * Terminal relay events (close / idle / hard errors) always flush a deferred final so browser snapshots
 * are not written to bugs.txt before transport settles. Mid-run events only rewrite when [FINAL] exists.
 */
function ipmiKvmBugLogMaybeRefreshFinalAfterRelayEvent(mysqli $mysqli, string $token, string $event): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    $pri = ipmiKvmBugLogRelayEventFinalRefreshPriority($event);
    if ($pri < 1) {
        return;
    }
    $path = ipmiKvmBugLogRootPath();
    if (!is_readable($path)) {
        return;
    }
    $raw = @file_get_contents($path);
    if ($raw === false) {
        return;
    }
    $hasFinal = str_contains($raw, '[FINAL]');
    $session = ipmiWebLoadSession($mysqli, $token);
    if (!$session) {
        return;
    }
    $stored = $session['session_meta']['kvm_buglog_last_final_payload'] ?? null;
    $hasStored = is_array($stored) && !empty($stored['detail']);
    $now = time();
    $lastTs = (int) ($session['session_meta']['kvm_buglog_final_refresh_ts'] ?? 0);

    if ($pri >= 3) {
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($now): void {
            $meta['kvm_buglog_final_refresh_ts'] = $now;
            $meta['kvm_buglog_final_refresh_count'] = (int) ($meta['kvm_buglog_final_refresh_count'] ?? 0) + 1;
        });
        ipmiKvmBugLogPatchFinalFromSessionOrMinimal($mysqli, $token);

        return;
    }

    if ($pri >= 1 && $hasFinal && $hasStored) {
        if (($now - $lastTs) < (($pri >= 2) ? 2 : 5)) {
            return;
        }
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($now): void {
            $meta['kvm_buglog_final_refresh_ts'] = $now;
            $meta['kvm_buglog_final_refresh_count'] = (int) ($meta['kvm_buglog_final_refresh_count'] ?? 0) + 1;
        });
        $payload = $stored;
        $payload['token'] = strtolower($token);
        $rid = ipmiKvmBugLogCurrentRunId();
        if ($rid !== null && $rid !== '') {
            $payload['run_id'] = $rid;
        }
        ipmiKvmBugLogPatchFinalBlock($payload, $mysqli);
    }
}

/**
 * Public entry: rewrite [FINAL] from last browser snapshot + current bugs.txt (e.g. true run end).
 *
 * @param array<string, mixed> $payload
 */
function ipmiKvmBugLogFinalizeRun(mysqli $mysqli, string $token, array $payload): void
{
    ipmiKvmBugLogPersistLastFinalPayload($mysqli, $token, $payload);
    ipmiKvmBugLogPatchFinalBlock($payload, $mysqli);
}

/**
 * Append transport line if token matches active KVM run (relay path).
 */
function ipmiKvmBugLogRelayDebugEvent(string $token, string $event, array $detail = [], ?mysqli $mysqli = null): void
{
    if (!ipmiKvmBugLogTokenMatchesActiveRun($token)) {
        return;
    }
    $parts = [$event];
    foreach ($detail as $k => $v) {
        if (is_bool($v)) {
            $v = $v ? '1' : '0';
        }
        if (is_float($v)) {
            $v = (string) $v;
        }
        if (is_int($v)) {
            $v = (string) $v;
        }
        if (!is_string($v)) {
            $v = json_encode($v, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        }
        if (strlen($v) > 220) {
            $v = substr($v, 0, 220) . '…';
        }
        $parts[] = $k . '=' . $v;
    }
    ipmiKvmBugLogAppendSection('TRANSPORT', 'event: ' . implode(' ', $parts));
    if ($mysqli instanceof mysqli) {
        ipmiKvmBugLogMaybeRefreshFinalAfterRelayEvent($mysqli, $token, $event);
    }
}

/**
 * Hash selected detail keys for per-run browser/transport noise dedupe.
 *
 * @param array<string, mixed> $detail
 * @param list<string> $materialKeys
 */
function ipmiKvmBrowserLogDedupeMaterialHash(array $detail, array $materialKeys): string
{
    if ($materialKeys === []) {
        return '';
    }
    $slice = [];
    foreach ($materialKeys as $k) {
        if (array_key_exists($k, $detail)) {
            $slice[$k] = $detail[$k];
        }
    }
    $j = json_encode($slice, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);

    return substr(hash('sha256', (string) $j), 0, 12);
}

/**
 * Whether this ingest should collapse duplicate bugs.txt lines (first line kept; repeats counted in meta).
 *
 * @param array<string, mixed> $detail
 * @return array{noise: bool, key: string}
 */
function ipmiKvmBrowserLogNoiseDedupeInfo(string $section, string $event, array $detail): array
{
    $ev = strtolower(trim($event));
    $sec = strtoupper(trim($section));
    /** @var array<string, array{sec: list<string>, mat: list<string>}> $rules */
    $rules = [
        'shell_launch_no_effect'                           => ['sec' => ['BROWSER'], 'mat' => []],
        'ilo_starthtml5irc_no_effect'                     => ['sec' => ['BROWSER'], 'mat' => []],
        'strong_confirmation_rejected_transport_unhealthy' => ['sec' => ['BROWSER'], 'mat' => ['transport_verdict']],
        'transport_failed'                                 => ['sec' => ['TRANSPORT'], 'mat' => ['verdict']],
        'transport_healthy'                                => ['sec' => ['TRANSPORT'], 'mat' => []],
        'browser_ws_handshake_failed_event'                => ['sec' => ['TRANSPORT'], 'mat' => []],
    ];
    if (!isset($rules[$ev])) {
        return ['noise' => false, 'key' => ''];
    }
    if (!in_array($sec, $rules[$ev]['sec'], true)) {
        return ['noise' => false, 'key' => ''];
    }
    $h = ipmiKvmBrowserLogDedupeMaterialHash($detail, $rules[$ev]['mat']);
    $key = ipmiKvmBugLogCanonicalEventKey($sec, $ev, $h);

    return ['noise' => true, 'key' => $key];
}

/**
 * Track collapsed browser noise (total deliveries vs first-line appends) for [FINAL] summary.
 */
function ipmiKvmBrowserLogRecordNoiseStats(mysqli $mysqli, string $token, string $dedupeKey, bool $suppressedLine, array $detail): void
{
    if ($dedupeKey === '' || !preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    $preview = '';
    $enc = json_encode($detail, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if (is_string($enc)) {
        $preview = substr($enc, 0, 140);
    }
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($dedupeKey, $suppressedLine, $preview): void {
        $st = is_array($meta['kvm_buglog_browser_noise_stats'] ?? null) ? $meta['kvm_buglog_browser_noise_stats'] : [];
        if (!isset($st[$dedupeKey])) {
            $st[$dedupeKey] = [
                'total'                 => 0,
                'first_ts'              => time(),
                'last_ts'               => time(),
                'suppressed_after_first'=> 0,
                'last_preview'          => $preview,
            ];
        }
        $st[$dedupeKey]['total'] = (int) ($st[$dedupeKey]['total'] ?? 0) + 1;
        $st[$dedupeKey]['last_ts'] = time();
        if ($suppressedLine) {
            $st[$dedupeKey]['suppressed_after_first'] = (int) ($st[$dedupeKey]['suppressed_after_first'] ?? 0) + 1;
        }
        if ($preview !== '') {
            $st[$dedupeKey]['last_preview'] = $preview;
        }
        $meta['kvm_buglog_browser_noise_stats'] = array_slice($st, -48, null, true);
    });
}

/**
 * @param array<string, mixed>|null $noiseStats
 */
function ipmiKvmBrowserFormatNoiseSummaryForFinal(?array $noiseStats): string
{
    if ($noiseStats === null || $noiseStats === []) {
        return 'none';
    }
    $parts = [];
    foreach (array_slice($noiseStats, -20, null, true) as $k => $row) {
        if (!is_array($row)) {
            continue;
        }
        $t = (int) ($row['total'] ?? 0);
        $s = (int) ($row['suppressed_after_first'] ?? 0);
        $parts[] = $k . ':n=' . $t . ',collapsed=' . $s;
    }

    return $parts !== [] ? implode(' | ', $parts) : 'none';
}

/**
 * Flush deferred [FINAL] using last kvm_final_summary snapshot (session) or aggregate-only pending block.
 */
function ipmiKvmBugLogPatchFinalFromSessionOrMinimal(mysqli $mysqli, string $token): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    $session = ipmiWebLoadSession($mysqli, $token);
    if (!$session) {
        return;
    }
    $stored = $session['session_meta']['kvm_buglog_last_final_payload'] ?? null;
    $runId = (string) (ipmiKvmBugLogCurrentRunId() ?? '');
    if (!is_array($stored) || empty($stored['detail'])) {
        $payload = [
            'token'   => strtolower($token),
            'run_id'  => $runId,
            'section' => 'FINAL',
            'event'   => 'kvm_final_summary',
            'detail'  => [
                'verdict'              => 'pending',
                'final_failure_reason' => '',
            ],
        ];
    } else {
        $payload = $stored;
        $payload['token'] = strtolower($token);
        if ($runId !== '') {
            $payload['run_id'] = $runId;
        }
    }
    ipmiKvmBugLogPatchFinalBlock($payload, $mysqli);
}

/**
 * Mark run closed from server/panel and write [FINAL] (same as browser kvm_run_finalize).
 */
function ipmiKvmBugLogMarkRunClosed(mysqli $mysqli, string $token): void
{
    if (!ipmiKvmBugLogCanFinalizeRun($token)) {
        return;
    }
    ipmiKvmBugLogAppendSection('NOTE', 'event: kvm_run_closed | note: server_marked_run_closed_flush_final');
    ipmiKvmBugLogPatchFinalFromSessionOrMinimal($mysqli, $token);
}

/**
 * Normalize browser ingest payload to a log line.
 *
 * @param array<string, mixed> $row
 */
function ipmiKvmBugLogNormalizeBrowserEvent(array $row): string
{
    $section = strtoupper(trim((string) ($row['section'] ?? 'BROWSER')));
    $event = trim((string) ($row['event'] ?? ''));
    if ($event === '') {
        $event = 'unknown';
    }
    $detail = $row['detail'] ?? null;
    $extra = '';
    if (is_array($detail)) {
        $enc = json_encode($detail, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if (is_string($enc) && strlen($enc) > 400) {
            $enc = substr($enc, 0, 400) . '…';
        }
        $extra = $enc !== false && $enc !== '' ? ' | detail: ' . $enc : '';
    } elseif (is_string($detail) && trim($detail) !== '') {
        $extra = ' | detail: ' . substr(trim($detail), 0, 400);
    }

    return 'event: ' . $event . $extra;
}

/**
 * Ingest a browser event: validate run_id + token suffix, append, optional meta side effects.
 *
 * @param array<string, mixed> $payload
 * @return array{ok: bool, error?: string}
 */
function ipmiKvmBugLogIngestBrowserEvent(mysqli $mysqli, array $payload): array
{
    $token = strtolower(trim((string) ($payload['token'] ?? '')));
    $runId = trim((string) ($payload['run_id'] ?? ''));
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return ['ok' => false, 'error' => 'invalid_token'];
    }
    $session = ipmiWebLoadSession($mysqli, $token);
    if (!$session) {
        return ['ok' => false, 'error' => 'session_invalid'];
    }
    $active = ipmiKvmBugLogCurrentRunId();
    if ($active === null || $active === '' || !hash_equals($active, $runId)) {
        return ['ok' => false, 'error' => 'run_mismatch'];
    }
    if (!ipmiKvmBugLogTokenMatchesActiveRun($token)) {
        return ['ok' => false, 'error' => 'token_suffix_mismatch'];
    }
    $section = (string) ($payload['section'] ?? 'BROWSER');
    $ev = strtolower((string) ($payload['event'] ?? ''));
    $detail = is_array($payload['detail'] ?? null) ? $payload['detail'] : [];

    if ($ev === 'kvm_final_summary') {
        ipmiKvmBugLogPersistLastFinalPayload($mysqli, $token, $payload);

        return ['ok' => true];
    }

    if ($ev === 'kvm_run_finalize') {
        ipmiKvmBugLogAppendSection('NOTE', 'event: kvm_run_finalize_received | note: flush deferred [FINAL] (browser unload or explicit finalize)');
        ipmiKvmBugLogPatchFinalFromSessionOrMinimal($mysqli, $token);

        return ['ok' => true];
    }

    $line = ipmiKvmBugLogNormalizeBrowserEvent([
        'section' => $section,
        'event'   => (string) ($payload['event'] ?? ''),
        'detail'  => $payload['detail'] ?? null,
    ]);
    $noise = ipmiKvmBrowserLogNoiseDedupeInfo($section, $ev, $detail);
    $me = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $evDedupe = is_array($me['kvm_buglog_dedupe']['events'] ?? null) ? $me['kvm_buglog_dedupe']['events'] : [];
    $dedupeKey = $noise['noise'] ? $noise['key'] : '';
    $skipLine = $dedupeKey !== '' && isset($evDedupe[$dedupeKey]);
    if (!$skipLine) {
        ipmiKvmBugLogAppendSection($section, $line);
    }
    if ($dedupeKey !== '') {
        ipmiKvmBrowserLogRecordNoiseStats($mysqli, $token, $dedupeKey, $skipLine, $detail);
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($dedupeKey): void {
            $d = is_array($meta['kvm_buglog_dedupe'] ?? null) ? $meta['kvm_buglog_dedupe'] : ['v' => 1, 'events' => []];
            $evMap = is_array($d['events'] ?? null) ? $d['events'] : [];
            if (!isset($evMap[$dedupeKey])) {
                $evMap[$dedupeKey] = ['first_ts' => time(), 'last_ts' => time(), 'count' => 1];
            } else {
                $evMap[$dedupeKey]['count'] = (int) ($evMap[$dedupeKey]['count'] ?? 0) + 1;
                $evMap[$dedupeKey]['last_ts'] = time();
            }
            $d['events'] = array_slice($evMap, -64, null, true);
            $d['v'] = 1;
            $meta['kvm_buglog_dedupe'] = $d;
        });
    }

    if ($ev === 'shell_launch_no_effect' || $ev === 'ilo_starthtml5irc_no_effect') {
        ipmiKvmRecordShellAbandonReason($mysqli, $token, 'SHELL_LAUNCH_NO_EFFECT', '');
    }
    if ($ev === 'application_path_loaded') {
        ipmiKvmRunStateStore($mysqli, $token, [
            'path_state' => 'application_path_active',
            'ts'         => time(),
        ]);
    }

    return ['ok' => true];
}

/**
 * Scan full bugs.txt for relay/browser signals (aggregate over the whole run, not first snapshot).
 *
 * @return array<string, mixed>
 */
function ipmiKvmBugLogComputeAggregateFromRaw(string $raw): array
{
    $agg = [
        'browser_ws_handshake_ok'         => false,
        'browser_ws_attempted'            => false,
        'browser_ws_handshake_fail_count' => 0,
        'browser_ws_error_count'          => 0,
        'browser_ws_close_count'          => 0,
        'upstream_connect_attempted'     => false,
        'upstream_tls_ok'                 => false,
        'upstream_ws_ok'                  => false,
        'frame_pump_started'              => false,
        'first_frame_observed'            => false,
        'sustained_frame_flow_observed'   => false,
        'idle_timeout_observed'           => false,
        'upstream_ws_fail_count'          => 0,
        'upstream_tls_fail_count'         => 0,
        'relay_pump_starts'               => 0,
        'relay_closed_events'             => 0,
        'relay_http_error_exit_count'     => 0,
        'transport_attempted'             => false,
        'application_path_signal'         => false,
        'shell_abandon_signal'            => false,
        'launch_attempt_signal'           => false,
        'live_display_heuristic_signal'   => false,
        'browser_transport_verdict_last'  => '',
    ];
    if ($raw === '') {
        return $agg;
    }
    $agg['browser_ws_handshake_ok'] = str_contains($raw, 'ipmi_ws_relay_browser_handshake_succeeded')
        || (bool) preg_match('/\[BROWSER\][^\n]*browser_ws_handshake_succeeded/', $raw)
        || (bool) preg_match('/\[TRANSPORT\][^\n]*browser_ws_handshake_succeeded/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_handshake_succeeded\b/', $raw);
    $agg['upstream_tls_ok'] = str_contains($raw, 'ipmi_ws_relay_upstream_tls_connected')
        || str_contains($raw, 'ipmi_ws_relay_upstream_tcp_connected');
    $agg['upstream_ws_ok'] = str_contains($raw, 'ipmi_ws_relay_upstream_ws_handshake_succeeded');
    $agg['frame_pump_started'] = str_contains($raw, 'ipmi_ws_relay_frame_pump_started');
    $agg['first_frame_observed'] = str_contains($raw, 'ipmi_ws_relay_first_frame_observed')
        || (bool) preg_match('/event:\s*browser_ws_first_application_frame\b/', $raw);
    $agg['sustained_frame_flow_observed'] = str_contains($raw, 'ipmi_ws_relay_sustained_frame_flow_observed');
    $agg['idle_timeout_observed'] = str_contains($raw, 'ipmi_ws_relay_frame_pump_idle_timeout');
    $agg['upstream_ws_fail_count'] = substr_count($raw, 'ipmi_ws_relay_upstream_ws_handshake_failed');
    $agg['upstream_tls_fail_count'] = substr_count($raw, 'ipmi_ws_relay_upstream_tls_failed')
        + substr_count($raw, 'ipmi_ws_relay_upstream_tcp_failed');
    $agg['relay_pump_starts'] = substr_count($raw, 'ipmi_ws_relay_frame_pump_started');
    $agg['relay_closed_events'] = substr_count($raw, 'ipmi_ws_relay_closed');
    $agg['application_path_signal'] = (bool) preg_match('/event:\s*application_path_loaded\b/', $raw)
        || (bool) preg_match('/event:\s*application_path_html_served_committed\b/', $raw);
    $agg['shell_abandon_signal'] = str_contains($raw, 'shell_path_abandoned_for_application')
        || str_contains($raw, 'SHELL_SSE_403')
        || str_contains($raw, 'SHELL_SESSION_INFO_403')
        || str_contains($raw, 'code: SHELL_LAUNCH_NO_EFFECT');
    $agg['shell_runtime_inject_count'] = (int) preg_match_all('/ilo_main_runtime_injected[^\n]*patch_mode:\s*shell_runtime\b/', $raw);
    $agg['shell_exit_stub_inject_count'] = (int) preg_match_all('/ilo_main_runtime_injected[^\n]*patch_mode:\s*shell_exit_stub\b/', $raw);
    $agg['shell_abandon_server_events_count'] = substr_count($raw, 'shell_path_abandoned_for_application');
    $agg['launch_attempt_signal'] = (bool) preg_match(
        '/event:\s*(ilo_launch_triggered|ilo_html5_console_launch_attempted|shell_escalation_console_href|application_path_loaded|shell_launch_no_effect|shell_path_abandon_flag_loaded|launch_action_no_effect|launch_surface_observed|ilo_launch_attempted_browser)\b/',
        $raw
    );
    $agg['session_ready_signal'] = (bool) preg_match('/event:\s*session_ready_heuristic\b/', $raw);
    $agg['live_display_heuristic_signal'] = (bool) preg_match('/event:\s*live_display_heuristic\b/', $raw);

    if (preg_match_all('/"transport_verdict"\s*:\s*"([^"]{1,80})"/', $raw, $vm) && $vm[1] !== []) {
        $agg['browser_transport_verdict_last'] = (string) end($vm[1]);
    }

    $agg['browser_ws_attempted'] = str_contains($raw, 'ipmi_ws_relay_request_received')
        || str_contains($raw, 'ipmi_ws_relay_browser_handshake_started')
        || str_contains($raw, 'ipmi_ws_relay_browser_handshake_failed')
        || str_contains($raw, 'ipmi_ws_relay_browser_handshake_succeeded')
        || str_contains($raw, 'ipmi_ws_relay_browser_handshake_accepting')
        || (bool) preg_match('/event:\s*browser_ws_relay_connect_attempted\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_construct_failed\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_handshake_succeeded\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_handshake_failed_event\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_closed\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_first_application_frame\b/', $raw)
        // Ingested browser-side transport verdict lines (post-WebSocket; collapse-only duplicates but first line proves WS path ran).
        || (bool) preg_match('/event:\s*transport_healthy\b/', $raw)
        || (bool) preg_match('/event:\s*transport_failed\b/', $raw);
    $agg['browser_ws_handshake_fail_count'] = substr_count($raw, 'ipmi_ws_relay_browser_handshake_failed');
    $agg['browser_ws_error_count'] = substr_count($raw, 'browser_ws_construct_failed')
        + substr_count($raw, 'browser_ws_handshake_failed_event')
        + (int) $agg['browser_ws_handshake_fail_count'];
    $agg['browser_ws_close_count'] = substr_count($raw, 'browser_ws_closed');
    $agg['upstream_connect_attempted'] = str_contains($raw, 'ipmi_ws_relay_upstream_connect_started');
    $agg['relay_http_error_exit_count'] = substr_count($raw, 'ipmi_ws_relay_http_error_exit');
    $agg['transport_attempted'] = !empty($agg['browser_ws_attempted'])
        || !empty($agg['upstream_connect_attempted'])
        || ((int) ($agg['relay_pump_starts'] ?? 0) > 0);

    return $agg;
}

/**
 * Full-run transport aggregate with derived unstable/failed flags (bugs.txt scan).
 *
 * @return array<string, mixed>
 */
function ipmiKvmTransportAggregateLoad(string $raw): array
{
    return ipmiKvmTransportAggregateFinalize(ipmiKvmBugLogComputeAggregateFromRaw($raw));
}

/**
 * Streaming merge hook (full-file scan remains authoritative for bugs.txt).
 *
 * @param array<string, mixed> $agg
 * @return array<string, mixed>
 */
function ipmiKvmTransportAggregateMergeEvent(array $agg, string $event, array $detail = []): array
{
    $e = strtolower(trim($event));
    if (str_contains($e, 'ipmi_ws_relay_browser_handshake_succeeded') || str_contains($e, 'browser_ws_handshake_succeeded')) {
        $agg['browser_ws_handshake_ok'] = true;
    }
    if (str_contains($e, 'ipmi_ws_relay_first_frame_observed') || str_contains($e, 'browser_ws_first_application_frame')) {
        $agg['first_frame_observed'] = true;
    }
    if (str_contains($e, 'ipmi_ws_relay_sustained_frame_flow_observed')) {
        $agg['sustained_frame_flow_observed'] = true;
    }
    if (str_contains($e, 'ipmi_ws_relay_frame_pump_started')) {
        $agg['frame_pump_started'] = true;
    }
    unset($detail);

    return $agg;
}

/**
 * Optional: mirror last computed transport aggregate into session meta (debug / panel reads).
 *
 * @param array<string, mixed> $agg Output of ipmiKvmTransportAggregateLoad()
 */
function ipmiKvmTransportAggregateStore(mysqli $mysqli, string $token, array $agg): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    $slice = array_intersect_key($agg, array_flip([
        'transport_attempted', 'transport_unstable', 'transport_failed',
        'browser_ws_attempted', 'browser_ws_handshake_ok', 'browser_ws_handshake_fail_count',
        'browser_ws_error_count', 'browser_ws_close_count',
        'upstream_connect_attempted', 'upstream_tls_ok', 'upstream_ws_ok',
        'frame_pump_started', 'first_frame_observed', 'sustained_frame_flow_observed',
        'idle_timeout_observed', 'upstream_ws_fail_count', 'upstream_tls_fail_count',
        'relay_pump_starts', 'relay_http_error_exit_count',
        'live_display_heuristic_signal', 'browser_transport_verdict_last',
    ]));
    $slice['v'] = 1;
    $slice['ts'] = time();
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($slice): void {
        $meta['kvm_transport_aggregate'] = $slice;
    });
}

/**
 * @param array<string, mixed> $agg
 * @return array<string, mixed>
 */
function ipmiKvmTransportAggregateFinalize(array $agg): array
{
    $out = $agg;
    $sust = !empty($agg['sustained_frame_flow_observed']);
    $first = !empty($agg['first_frame_observed']);
    $pump = !empty($agg['frame_pump_started']);
    $bOk = !empty($agg['browser_ws_handshake_ok']);
    $tlsOk = !empty($agg['upstream_tls_ok']);
    $wsOk = !empty($agg['upstream_ws_ok']);
    $upWsFail = (int) ($agg['upstream_ws_fail_count'] ?? 0);
    $upTlsFail = (int) ($agg['upstream_tls_fail_count'] ?? 0);
    $httpErr = (int) ($agg['relay_http_error_exit_count'] ?? 0);
    $idle = !empty($agg['idle_timeout_observed']);
    $pumps = (int) ($agg['relay_pump_starts'] ?? 0);

    $partial = $bOk && ($tlsOk || $wsOk || $first);
    $out['transport_unstable'] = false;
    if (!$sust) {
        if ($partial && ($upWsFail >= 1 || $upTlsFail >= 1 || $httpErr >= 1)) {
            $out['transport_unstable'] = true;
        }
        if ($first && $idle) {
            $out['transport_unstable'] = true;
        }
        if ($pumps >= 2 && ($upWsFail >= 1 || $idle || $httpErr >= 1)) {
            $out['transport_unstable'] = true;
        }
    }

    $out['transport_failed'] = false;
    $bErrT = (int) ($agg['browser_ws_error_count'] ?? 0);
    if (!empty($agg['transport_attempted']) && !$bOk && $bErrT >= 1) {
        $out['transport_failed'] = true;
    }
    if (!empty($agg['transport_attempted']) && !$bOk && $httpErr >= 2) {
        $out['transport_failed'] = true;
    }

    return $out;
}

/**
 * @param array<string, mixed> $agg  Output of ipmiKvmTransportAggregateLoad()
 * @param array<string, mixed> $merged
 */
function ipmiKvmTransportFinalFailureReason(array $agg, array $merged, bool $transportHealthy, string $verdict): string
{
    $shellPathVerdicts = [
        'shell_abandonment_loop',
        'shell_runtime_reinjected_after_abandon',
        'shell_path_failed_not_promoted',
        'application_promotion_not_committed',
    ];
    if (in_array($verdict, $shellPathVerdicts, true)) {
        return '';
    }
    if ($transportHealthy) {
        return '';
    }
    if (empty($agg['transport_attempted'])) {
        return 'transport_not_attempted';
    }

    $bOk = ($merged['browser_ws_handshake_ok'] ?? '') === 'yes' || !empty($agg['browser_ws_handshake_ok']);
    $bErr = (int) ($agg['browser_ws_error_count'] ?? 0);
    if (!$bOk && $bErr >= 1) {
        return 'browser_ws_handshake_failed';
    }

    $tlsOk = ($merged['upstream_tls_ok'] ?? '') === 'yes' || !empty($agg['upstream_tls_ok']);
    $wsOk = ($merged['upstream_ws_ok'] ?? '') === 'yes' || !empty($agg['upstream_ws_ok']);
    $upTlsFail = (int) ($agg['upstream_tls_fail_count'] ?? 0);
    $upWsFail = (int) ($agg['upstream_ws_fail_count'] ?? 0);
    $httpErr = (int) ($agg['relay_http_error_exit_count'] ?? 0);
    $pump = !empty($agg['frame_pump_started']);
    $first = !empty($agg['first_frame_observed']);
    $sust = !empty($agg['sustained_frame_flow_observed']);
    $idle = !empty($agg['idle_timeout_observed']);
    $pumps = (int) ($agg['relay_pump_starts'] ?? 0);

    $partialUpstream = $bOk && ($tlsOk || $wsOk || $first);

    if (!$tlsOk && $upTlsFail >= 1 && !$wsOk && $upWsFail === 0 && !$first) {
        return 'upstream_tls_failed';
    }
    if (!$wsOk && $upWsFail >= 1 && $bOk && ($tlsOk || !empty($agg['upstream_connect_attempted']))) {
        if ($partialUpstream && ($upTlsFail >= 1 || $httpErr >= 1 || $pumps >= 2)) {
            return 'transport_unstable_after_partial_success';
        }

        return 'upstream_ws_handshake_failed';
    }

    if ($pump && !$first) {
        return 'frame_pump_started_but_no_first_frame';
    }

    if ($first && !$sust) {
        if ($idle) {
            return 'idle_timeout_without_sustained_flow';
        }
        if ($partialUpstream && ($upWsFail >= 1 || $upTlsFail >= 1 || $httpErr >= 1)) {
            return 'transport_unstable_after_partial_success';
        }

        return 'first_frame_only_no_sustained_flow';
    }

    if (!empty($agg['transport_unstable'])) {
        return 'transport_unstable_after_partial_success';
    }

    return 'transport_attempted_but_console_not_confirmed';
}

/** @deprecated Use ipmiKvmTransportAggregateLoad */
function ipmiKvmBugLogComputeAggregateFinalState(string $raw): array
{
    return ipmiKvmTransportAggregateLoad($raw);
}

/**
 * Remove all [FINAL] sections (legacy mid-file or trailing).
 */
function ipmiKvmBugLogStripFinalSections(string $raw): string
{
    // New-format [FINAL] blocks end with a fixed footer so relay lines appended after the run marker are not swallowed.
    $footClosed = '#\n\[FINAL\]\n[\s\S]*?\n==================================================\nKVM RUN END\s*\n#';
    for ($i = 0; $i < 8; $i++) {
        $next = preg_replace($footClosed, "\n", $raw, 1);
        if (!is_string($next) || $next === $raw) {
            break;
        }
        $raw = $next;
    }
    for ($i = 0; $i < 8; $i++) {
        $next = preg_replace('#\n\[FINAL\][\s\S]*?\n==================================================\nKVM RUN END#', "\n==================================================\nKVM RUN END", $raw, 1);
        if (!is_string($next) || $next === $raw) {
            break;
        }
        $raw = $next;
    }
    // Legacy: [FINAL] with no footer — removes to EOF (may drop relay lines that were appended after an old final).
    $raw = preg_replace('#\n\[FINAL\][\s\S]*$#', '', $raw);

    return is_string($raw) ? (rtrim($raw) . "\n") : '';
}

/**
 * Merge browser snapshot with file aggregates (OR for "ever true" positives).
 *
 * @param array<string, mixed> $agg
 * @param array<string, mixed> $detail
 * @return array<string, mixed>
 */
function ipmiKvmBugLogMergeFinalDetailWithAggregate(array $agg, array $detail): array
{
    $pickYes = static function (bool $fileSig, $d): string {
        $detTrue = ($d === true || $d === 1 || $d === '1' || $d === 'yes');
        $detFalse = ($d === false || $d === 0 || $d === '0' || $d === 'no');
        if ($fileSig || $detTrue) {
            return 'yes';
        }
        if ($detFalse) {
            return 'no';
        }

        return 'unknown';
    };

    $merged = $detail;
    $merged['application_path_loaded'] = $pickYes($agg['application_path_signal'], $detail['application_path_loaded'] ?? null);
    $merged['shell_path_abandoned'] = $pickYes($agg['shell_abandon_signal'], $detail['shell_path_abandoned'] ?? null);
    $merged['launch_attempted'] = $pickYes($agg['launch_attempt_signal'], $detail['launch_attempted'] ?? null);
    $merged['browser_ws_handshake_ok'] = $pickYes($agg['browser_ws_handshake_ok'], $detail['browser_ws_handshake_ok'] ?? null);
    $merged['upstream_tls_ok'] = $pickYes($agg['upstream_tls_ok'], $detail['upstream_tls_ok'] ?? null);
    $merged['upstream_ws_ok'] = $pickYes($agg['upstream_ws_ok'], $detail['upstream_ws_ok'] ?? null);
    $merged['frame_pump_started'] = $pickYes($agg['frame_pump_started'], $detail['frame_pump_started'] ?? null);
    $merged['first_frame_observed'] = $pickYes($agg['first_frame_observed'], $detail['first_frame_observed'] ?? null);
    $merged['sustained_frame_flow_observed'] = $pickYes($agg['sustained_frame_flow_observed'], $detail['sustained_frame_flow_observed'] ?? null);
    $merged['frame_pump_active'] = $pickYes(
        $agg['frame_pump_started'] || $agg['first_frame_observed'],
        $detail['frame_pump_active'] ?? null
    );
    $merged['session_ready_merged'] = $pickYes($agg['session_ready_signal'], $detail['session_ready'] ?? null);

    $clientBrowserWsAttempt = $detail['browser_ws_attempted'] ?? $detail['ws_connect_attempted'] ?? null;
    $merged['browser_ws_attempted'] = $pickYes(!empty($agg['browser_ws_attempted']), $clientBrowserWsAttempt);

    $clientTransportAttempted = $detail['transport_attempted'] ?? null;
    if ($clientTransportAttempted === null) {
        $clientTransportAttempted = $detail['ws_connect_attempted'] ?? $detail['transport_started'] ?? null;
    }
    $merged['transport_attempted'] = $pickYes(!empty($agg['transport_attempted']), $clientTransportAttempted);
    if (($merged['browser_ws_attempted'] ?? '') === 'yes') {
        $merged['transport_attempted'] = 'yes';
    }

    $merged['upstream_connect_attempted'] = $pickYes(
        !empty($agg['upstream_connect_attempted']),
        $detail['upstream_connect_attempted'] ?? null
    );
    $merged['live_display'] = $pickYes(!empty($agg['live_display_heuristic_signal']), $detail['live_display'] ?? null);
    $merged['transport_verdict_snapshot'] = trim((string) ($detail['transport_verdict'] ?? ''));
    if ($merged['transport_verdict_snapshot'] === '' && !empty($agg['browser_transport_verdict_last'])) {
        $merged['transport_verdict_snapshot'] = (string) $agg['browser_transport_verdict_last'];
    }

    return $merged;
}

/**
 * Strict transport health for [FINAL]: sustained flow wins; idle / repeat upstream failures degrade.
 *
 * @param array<string, mixed> $agg
 * @param array<string, mixed> $merged
 */
function ipmiKvmBugLogDeriveFinalTransportHealthy(array $agg, array $merged, string $verdict): bool
{
    $shellPathVerdicts = [
        'shell_abandonment_loop',
        'shell_runtime_reinjected_after_abandon',
        'shell_path_failed_not_promoted',
        'application_promotion_not_committed',
    ];
    if (in_array($verdict, $shellPathVerdicts, true)) {
        return false;
    }
    if (!empty($agg['transport_unstable'])) {
        return false;
    }
    $badVerdict = in_array($verdict, [
        'transport_unhealthy_console_not_confirmed',
        'transport_unstable_console_not_confirmed',
        'console_transport_healthy',
        'relay_browser_handshake_failed',
        'relay_upstream_tls_failed',
        'relay_upstream_ws_failed',
        'launch_discovery_failed',
        'launch_action_no_effect',
        'launch_reached_renderer_only',
    ], true);
    if ($badVerdict) {
        return false;
    }
    $sustAgg = !empty($agg['sustained_frame_flow_observed']);
    // Green path: relay/server must observe sustained meaningful frame flow in bugs.txt scan.
    // Browser `sustained_transport_ok` / snapshot fields inform verdicts and noise, not transport_healthy.
    $sust = $sustAgg;
    $idle = !empty($agg['idle_timeout_observed']);
    $pumps = (int) ($agg['relay_pump_starts'] ?? 0);
    $upFails = (int) ($agg['upstream_ws_fail_count'] ?? 0);

    if (!$sust) {
        return false;
    }
    $tlsFails = (int) ($agg['upstream_tls_fail_count'] ?? 0);
    if ($tlsFails >= 2) {
        return false;
    }
    if ($tlsFails >= 1 && empty($agg['upstream_tls_ok'])) {
        return false;
    }
    if ($idle) {
        return false;
    }
    if ($pumps >= 2 && $upFails >= 1) {
        return false;
    }
    if ($upFails >= 2) {
        return false;
    }

    return true;
}

/**
 * Parse bugs.txt [PLAN] selected_path (initial KVM route at run start).
 */
function ipmiKvmBugLogParseInitialPlanSelectedPath(string $raw): string
{
    if (preg_match('/\[PLAN\][\s\S]*?\nselected_path:\s*([^\n]+)/', $raw, $m)) {
        return trim($m[1]);
    }
    if (preg_match('/^selected_path:\s*([^\n]+)/m', $raw, $m)) {
        return trim($m[1]);
    }

    return '';
}

/**
 * First server or BUG shell-abandon code in the run log.
 */
function ipmiKvmBugLogParseFirstShellAbandonCode(string $raw): string
{
    if (preg_match('/shell_path_abandoned_for_application\s*\|\s*code:\s*(\S+)/i', $raw, $m)) {
        return trim($m[1]);
    }
    if (preg_match('/\[BUG\]\s*code:\s*(SHELL_[A-Z0-9_]+)/', $raw, $m)) {
        return trim($m[1]);
    }

    return '';
}

/**
 * Append one bugs.txt line per run (session meta gate) — e.g. server-side application.html commit.
 */
function ipmiKvmBugLogAppendOncePerRun(mysqli $mysqli, string $token, string $onceKey, string $section, string $lineBody): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $onceKey = substr(preg_replace('/[^a-z0-9_]/i', '_', $onceKey), 0, 64);
    $ref = ['go' => false];
    ipmiWebSessionMetaMutate($mysqli, $token, function (array &$meta) use ($onceKey, &$ref): void {
        $once = is_array($meta['kvm_buglog_once'] ?? null) ? $meta['kvm_buglog_once'] : [];
        if (!empty($once[$onceKey])) {
            return;
        }
        $once[$onceKey] = time();
        $meta['kvm_buglog_once'] = array_slice($once, -24, null, true);
        $ref['go'] = true;
    });
    if (!empty($ref['go'])) {
        ipmiKvmBugLogAppendSection($section, $lineBody);
    }
}

/**
 * Stable key for per-run bugs.txt dedupe (category + code + optional material hash).
 */
function ipmiKvmBugLogCanonicalEventKey(string $category, string $code, string $detailMaterialHash = ''): string
{
    return strtolower(trim($category)) . '|' . trim($code) . '|' . trim($detailMaterialHash);
}

/**
 * Merge kvm_run_path_state (bounded) in session meta.
 */
function ipmiKvmRunStateStore(mysqli $mysqli, string $token, array $patch): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $patch = array_slice($patch, 0, 24);
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($patch): void {
        $prev = is_array($meta['kvm_run_path_state'] ?? null) ? $meta['kvm_run_path_state'] : [];
        $meta['kvm_run_path_state'] = array_merge($prev, $patch + ['v' => 1]);
    });
}

/**
 * Persist shell abandon + run path state + optional first-seen BUG line (deduped per run in session meta).
 */
function ipmiKvmRecordShellAbandonReason(mysqli $mysqli, string $token, string $reasonCode, string $detailMaterial = ''): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $mat = $detailMaterial !== '' ? substr(hash('sha256', $detailMaterial), 0, 12) : '';
    $bugKey = ipmiKvmBugLogCanonicalEventKey('BUG', $reasonCode, $mat);
    $session = ipmiWebLoadSession($mysqli, $token);
    $me = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $ev0 = is_array($me['kvm_buglog_dedupe']['events'] ?? null) ? $me['kvm_buglog_dedupe']['events'] : [];
    if (!isset($ev0[$bugKey])) {
        if ($reasonCode === 'SHELL_LAUNCH_NO_EFFECT') {
            ipmiKvmBugLogAppendBug('SHELL_LAUNCH_NO_EFFECT', 'Shell HTML5 launch left DOM/transport unchanged', $detailMaterial);
        } else {
            ipmiKvmBugLogAppendBug($reasonCode, 'Shell abandon reason recorded', $detailMaterial);
        }
    }
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($bugKey): void {
        $d = is_array($meta['kvm_buglog_dedupe'] ?? null) ? $meta['kvm_buglog_dedupe'] : ['v' => 1, 'events' => []];
        $ev = is_array($d['events'] ?? null) ? $d['events'] : [];
        if (!isset($ev[$bugKey])) {
            $ev[$bugKey] = ['first_ts' => time(), 'last_ts' => time(), 'count' => 1];
        } else {
            $ev[$bugKey]['count'] = (int) ($ev[$bugKey]['count'] ?? 0) + 1;
            $ev[$bugKey]['last_ts'] = time();
        }
        $d['events'] = array_slice($ev, -64, null, true);
        $d['v'] = 1;
        $meta['kvm_buglog_dedupe'] = $d;
    });
    ipmiKvmShellAbandonPersist($mysqli, $token, $reasonCode, '');
}

/**
 * Force effective application-path plan for this run (browser/server promotion).
 */
function ipmiKvmPlanForceApplicationOverride(mysqli $mysqli, string $token): void
{
    ipmiKvmShellAbandonPersist($mysqli, $token, 'APPLICATION_PROMOTION_TRIGGERED', '');
    ipmiKvmRunStateStore($mysqli, $token, [
        'path_state'   => 'application_path_promoting',
        'promotion_ts' => time(),
    ]);
}

/**
 * Override browser verdict when file aggregates show shell-path loop / failed promotion.
 *
 * @param array<string, mixed> $agg
 * @param array<string, mixed> $merged
 * @return array{verdict: string, source: string, shell_loop_metrics: string}
 */
function ipmiKvmComputeFinalVerdict(array $agg, array $merged, string $browserVerdict): array
{
    $app = (string) ($merged['application_path_loaded'] ?? 'unknown');
    $sr = (int) ($agg['shell_runtime_inject_count'] ?? 0);
    $stub = (int) ($agg['shell_exit_stub_inject_count'] ?? 0);
    $abandonN = (int) ($agg['shell_abandon_server_events_count'] ?? 0);
    $shellSig = !empty($agg['shell_abandon_signal']);
    $metrics = 'shell_runtime_injections=' . $sr
        . ' shell_exit_stub_injections=' . $stub
        . ' shell_abandon_server_events=' . $abandonN
        . ' application_path_loaded=' . $app;

    if ($shellSig && $sr >= 2 && $stub === 0 && ($app === 'no' || $app === 'unknown')) {
        return ['verdict' => 'shell_runtime_reinjected_after_abandon', 'source' => 'aggregate_file', 'shell_loop_metrics' => $metrics];
    }
    if ($abandonN >= 2 && $sr >= 2 && ($app === 'no' || $app === 'unknown')) {
        return ['verdict' => 'shell_abandonment_loop', 'source' => 'aggregate_file', 'shell_loop_metrics' => $metrics];
    }
    if ($shellSig && ($app === 'no' || $app === 'unknown') && $sr >= 1 && $stub === 0) {
        return ['verdict' => 'shell_path_failed_not_promoted', 'source' => 'aggregate_file', 'shell_loop_metrics' => $metrics];
    }
    if ($shellSig && ($app === 'no' || $app === 'unknown') && $stub >= 3) {
        return ['verdict' => 'application_promotion_not_committed', 'source' => 'aggregate_file', 'shell_loop_metrics' => $metrics];
    }

    return ['verdict' => $browserVerdict, 'source' => 'browser', 'shell_loop_metrics' => $metrics];
}

/**
 * @param array<string, mixed> $payload
 */
function ipmiKvmFinalizeRunSummary(array $payload, ?mysqli $mysqli = null): void
{
    ipmiKvmBugLogPatchFinalBlock($payload, $mysqli);
}

/**
 * Write [FINAL] at end of bugs.txt from browser payload + full-file aggregates (authoritative).
 *
 * @param array<string, mixed> $payload
 */
function ipmiKvmBugLogUpdateFinalSummary(array $payload, ?mysqli $mysqli = null): void
{
    ipmiKvmBugLogPatchFinalBlock($payload, $mysqli);
}

/**
 * Alias: recompute and move [FINAL] to EOF (includes all transport lines appended since last write).
 *
 * @param array<string, mixed> $payload
 */
function ipmiKvmBugLogRewriteFinalSection(array $payload, ?mysqli $mysqli = null): void
{
    ipmiKvmBugLogPatchFinalBlock($payload, $mysqli);
}

/**
 * @param array<string, mixed> $payload
 */
function ipmiKvmBugLogPatchFinalBlock(array $payload, ?mysqli $mysqli = null): void
{
    $detail = is_array($payload['detail'] ?? null) ? $payload['detail'] : [];
    $verdict = trim((string) ($detail['verdict'] ?? 'pending'));
    $path = ipmiKvmBugLogRootPath();
    if (!is_readable($path)) {
        return;
    }
    $raw = file_get_contents($path);
    if ($raw === false || $raw === '') {
        return;
    }
    $agg = ipmiKvmTransportAggregateLoad($raw);
    $merged = ipmiKvmBugLogMergeFinalDetailWithAggregate($agg, $detail);
    $resolved = ipmiKvmComputeFinalVerdict($agg, $merged, $verdict !== '' ? $verdict : 'pending');
    if (($resolved['source'] ?? '') === 'aggregate_file' && ($resolved['verdict'] ?? '') !== '') {
        $verdict = (string) $resolved['verdict'];
    }
    $transportHealthy = ipmiKvmBugLogDeriveFinalTransportHealthy($agg, $merged, $verdict);
    $transportDerived = ipmiKvmTransportFinalFailureReason($agg, $merged, $transportHealthy, $verdict);
    $ended = gmdate('c') . 'Z';
    $failureReason = trim((string) ($detail['final_failure_reason'] ?? $detail['reason'] ?? $detail['transport_why'] ?? ''));
    $shellPathVerdicts = [
        'shell_abandonment_loop',
        'shell_runtime_reinjected_after_abandon',
        'shell_path_failed_not_promoted',
        'application_promotion_not_committed',
    ];
    $staleTransportReasons = [
        '',
        'none',
        'not_attempted',
        'transport_not_attempted',
        'relay_ws_not_attempted',
        'no_sustained_relay_frame_flow_or_transport_unstable',
    ];
    $frNorm = strtolower($failureReason);
    if (in_array($verdict, $shellPathVerdicts, true)) {
        if ($failureReason === '' || in_array($frNorm, $staleTransportReasons, true)) {
            $failureReason = 'kvm_shell_path_not_resolved_before_end:' . $verdict;
        }
    } elseif ($failureReason === '') {
        if (!$transportHealthy && $verdict === 'transport_unhealthy_console_not_confirmed') {
            $failureReason = 'no_sustained_relay_frame_flow_or_transport_unstable';
        }
    }
    $frNorm = strtolower($failureReason);
    if (!in_array($verdict, $shellPathVerdicts, true) && $transportDerived !== '') {
        if (in_array($frNorm, $staleTransportReasons, true)) {
            $failureReason = $transportDerived;
        }
    }
    if (($failureReason === '' || strtolower($failureReason) === 'none') && $transportDerived !== '' && !in_array($verdict, $shellPathVerdicts, true)) {
        $failureReason = $transportDerived;
    }
    $failureReason = substr($failureReason, 0, 400);

    $refreshCount = 0;
    $noiseSummary = 'none';
    $tok = strtolower(trim((string) ($payload['token'] ?? '')));
    if ($mysqli instanceof mysqli && preg_match('/^[a-f0-9]{64}$/', $tok)) {
        $sess = ipmiWebLoadSession($mysqli, $tok);
        if ($sess) {
            $refreshCount = (int) ($sess['session_meta']['kvm_buglog_final_refresh_count'] ?? 0);
            $ns = $sess['session_meta']['kvm_buglog_browser_noise_stats'] ?? null;
            $noiseSummary = ipmiKvmBrowserFormatNoiseSummaryForFinal(is_array($ns) ? $ns : null);
        }
    }

    $line = static function (string $k, string $v): string {
        return $k . ': ' . $v . "\n";
    };

    $srCount = (int) ($agg['shell_runtime_inject_count'] ?? 0);
    $stubCount = (int) ($agg['shell_exit_stub_inject_count'] ?? 0);
    $appLoaded = (string) ($merged['application_path_loaded'] ?? 'unknown');
    $shellAbandonMerged = (string) ($merged['shell_path_abandoned'] ?? 'unknown');
    $abandonCode = ipmiKvmBugLogParseFirstShellAbandonCode($raw);
    $initialPlanPath = ipmiKvmBugLogParseInitialPlanSelectedPath($raw);
    $specShellRuntimeUsed = $srCount > 0 ? 'yes' : 'no';
    $shellActiveSignal = ($srCount > 0 || $stubCount > 0) ? 'yes' : 'no';
    $reinjectAfterAbandon = in_array($verdict, ['shell_runtime_reinjected_after_abandon', 'shell_abandonment_loop'], true)
        || (!empty($agg['shell_abandon_signal']) && $srCount >= 2 && $stubCount === 0)
        ? 'yes'
        : 'no';
    $promotionCommitted = ($appLoaded === 'yes') ? 'yes' : 'no';
    $transportUnstable = !empty($agg['transport_unstable']) ? 'yes' : 'no';
    $transportFailed = !empty($agg['transport_failed']) ? 'yes' : 'no';

    $finalBody = '[FINAL]' . "\n"
        . $line('verdict', $verdict !== '' ? $verdict : 'pending')
        . $line('verdict_source', (string) ($resolved['source'] ?? 'browser'))
        . $line('shell_loop_metrics', (string) ($resolved['shell_loop_metrics'] ?? ''))
        . $line('plan_initial_selected_path', $initialPlanPath !== '' ? $initialPlanPath : 'unknown')
        . $line('effective_kvm_path_note', '/html/application.html after shell abandon (session plan override; not re-logged each request)')
        . $line('kvm_speculative_shell_active_signal', $shellActiveSignal)
        . $line('speculative_shell_full_runtime_used', $specShellRuntimeUsed)
        . $line('shell_path_abandoned', $shellAbandonMerged)
        . $line('shell_abandon_reason_code', $abandonCode !== '' ? $abandonCode : 'unknown')
        . $line('application_promotion_committed', $promotionCommitted)
        . $line('shell_runtime_reinjected_after_abandon', $reinjectAfterAbandon)
        . $line('strong_confirmation', !empty($detail['strong_confirmation']) ? 'yes' : 'no')
        . $line('application_path_loaded', $appLoaded)
        . $line('launch_attempted', (string) ($merged['launch_attempted'] ?? 'unknown'))
        . $line('transport_attempted', (string) ($merged['transport_attempted'] ?? 'unknown'))
        . $line('browser_ws_attempted', (string) ($merged['browser_ws_attempted'] ?? 'unknown'))
        . $line('browser_ws_handshake_ok', (string) ($merged['browser_ws_handshake_ok'] ?? 'unknown'))
        . $line('browser_ws_handshake_fail_count', (string) ((int) ($agg['browser_ws_handshake_fail_count'] ?? 0)))
        . $line('browser_ws_error_count', (string) ((int) ($agg['browser_ws_error_count'] ?? 0)))
        . $line('browser_ws_close_count', (string) ((int) ($agg['browser_ws_close_count'] ?? 0)))
        . $line('browser_noise_collapsed_summary', $noiseSummary)
        . $line('upstream_connect_attempted', (string) ($merged['upstream_connect_attempted'] ?? 'unknown'))
        . $line('upstream_tls_ok', (string) ($merged['upstream_tls_ok'] ?? 'unknown'))
        . $line('upstream_ws_ok', (string) ($merged['upstream_ws_ok'] ?? 'unknown'))
        . $line('frame_pump_started', (string) ($merged['frame_pump_started'] ?? 'unknown'))
        . $line('first_frame_observed', (string) ($merged['first_frame_observed'] ?? 'unknown'))
        . $line('sustained_frame_flow_observed', (string) ($merged['sustained_frame_flow_observed'] ?? 'unknown'))
        . $line('idle_timeout_observed', !empty($agg['idle_timeout_observed']) ? 'yes' : 'no')
        . $line('upstream_ws_handshake_failures', (string) ((int) ($agg['upstream_ws_fail_count'] ?? 0)))
        . $line('upstream_tls_failures', (string) ((int) ($agg['upstream_tls_fail_count'] ?? 0)))
        . $line('relay_http_error_exits', (string) ((int) ($agg['relay_http_error_exit_count'] ?? 0)))
        . $line('relay_pump_sessions', (string) ((int) ($agg['relay_pump_starts'] ?? 0)))
        . $line('frame_pump_active', (string) ($merged['frame_pump_active'] ?? 'unknown'))
        . $line('transport_unstable', $transportUnstable)
        . $line('transport_failed', $transportFailed)
        . $line('transport_healthy', $transportHealthy ? 'yes' : 'no')
        . $line('session_ready', (string) ($merged['session_ready_merged'] ?? 'unknown'))
        . $line('live_display', (string) ($merged['live_display'] ?? 'unknown'))
        . $line('transport_verdict_snapshot', ($merged['transport_verdict_snapshot'] ?? '') !== '' ? (string) $merged['transport_verdict_snapshot'] : 'unknown')
        . $line('final_failure_reason', $failureReason !== '' ? $failureReason : 'none')
        . $line('ended_at_utc', $ended)
        . $line('aggregate_source', 'full_bugs_txt_scan_relay_transport_browser_helper_server_plus_last_kvm_final_summary_snapshot | final_refresh_count=' . (string) $refreshCount)
        . "==================================================\n"
        . "KVM RUN END\n";

    if (
        function_exists('ipmiProxyDebugEnabled')
        && function_exists('ipmiProxyDebugLog')
        && ipmiProxyDebugEnabled()
    ) {
        ipmiProxyDebugLog('kvm_buglog_final_transport_matrix', [
            'token_suffix'                  => strlen($tok) >= 8 ? substr($tok, -8) : '',
            'transport_attempted'           => (string) ($merged['transport_attempted'] ?? ''),
            'browser_ws_attempted'          => (string) ($merged['browser_ws_attempted'] ?? ''),
            'browser_ws_handshake_ok'       => (string) ($merged['browser_ws_handshake_ok'] ?? ''),
            'browser_ws_error_count'        => (string) ((int) ($agg['browser_ws_error_count'] ?? 0)),
            'browser_ws_close_count'        => (string) ((int) ($agg['browser_ws_close_count'] ?? 0)),
            'upstream_connect_attempted'    => (string) ($merged['upstream_connect_attempted'] ?? ''),
            'upstream_tls_ok'               => (string) ($merged['upstream_tls_ok'] ?? ''),
            'upstream_ws_ok'                => (string) ($merged['upstream_ws_ok'] ?? ''),
            'frame_pump_started'            => (string) ($merged['frame_pump_started'] ?? ''),
            'first_frame_observed'          => (string) ($merged['first_frame_observed'] ?? ''),
            'sustained_frame_flow_observed' => (string) ($merged['sustained_frame_flow_observed'] ?? ''),
            'transport_unstable'            => $transportUnstable,
            'transport_failed'              => $transportFailed,
            'transport_healthy'             => $transportHealthy ? 'yes' : 'no',
            'final_failure_reason'          => $failureReason !== '' ? substr($failureReason, 0, 240) : 'none',
        ]);
    }

    $stripped = ipmiKvmBugLogStripFinalSections($raw);
    $out = rtrim($stripped) . "\n\n" . $finalBody;

    $fp = @fopen($path, 'cb');
    if ($fp === false) {
        return;
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);

        return;
    }
    ftruncate($fp, 0);
    fwrite($fp, $out);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    if ($mysqli instanceof mysqli && preg_match('/^[a-f0-9]{64}$/', $tok)) {
        ipmiKvmTransportAggregateStore($mysqli, $tok, $agg);
    }
}

/**
 * Persist shell abandonment reason for next injected PLAN (iLO) + run-scoped path state (one-way).
 *
 * @param string $snapshotBmcPath Optional BMC path when abandon first observed (for diagnostics).
 */
function ipmiKvmShellAbandonPersist(mysqli $mysqli, string $token, string $reason, string $snapshotBmcPath = ''): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($reason, $snapshotBmcPath): void {
        $meta['kvm_shell_abandon'] = [
            'v'      => 1,
            'reason' => $reason,
            'ts'     => time(),
        ];
        $prev = is_array($meta['kvm_run_path_state'] ?? null) ? $meta['kvm_run_path_state'] : [];
        $reasons = is_array($prev['abandon_reasons'] ?? null) ? $prev['abandon_reasons'] : [];
        if (!in_array($reason, $reasons, true)) {
            $reasons[] = $reason;
        }
        if ($snapshotBmcPath !== '' && empty($prev['initial_kvm_entry_path'])) {
            $prev['initial_kvm_entry_path'] = substr($snapshotBmcPath, 0, 240);
        }
        $prevPs = (string) ($prev['path_state'] ?? '');
        $keepAppPath = in_array($prevPs, ['application_path_active', 'application_path_confirmed'], true);
        $nextPathState = $keepAppPath ? $prevPs : 'shell_path_abandoned';
        $meta['kvm_run_path_state'] = array_merge($prev, [
            'v'                       => 1,
            'path_state'              => $nextPathState,
            'abandon_reasons'         => array_slice($reasons, 0, 16),
            'primary_abandon_reason'  => $reason,
            'ts'                      => time(),
        ]);
    });
}

// --- Transport health (session meta; browser + ingest may update) ---

/** @param array<string, mixed> $session */
function ipmiProxyIloTransportHealthStateLoad(array $session): array
{
    $m = $session['session_meta']['kvm_transport_health'] ?? null;

    return is_array($m) ? $m : [];
}

/** @param array<string, mixed> $state */
function ipmiProxyIloTransportHealthStateStore(mysqli $mysqli, string $token, array $state): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state = array_slice($state, 0, 32);
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $prev = isset($meta['kvm_transport_health']) && is_array($meta['kvm_transport_health'])
            ? $meta['kvm_transport_health'] : [];
        $meta['kvm_transport_health'] = array_merge($prev, $state + ['ts' => time()]);
    });
}

/** @param array<string, mixed> $state */
function ipmiProxyIloTransportHealthVerdict(array $state): string
{
    if (!empty($state['transport_failed'])) {
        return 'transport_failed';
    }
    if (!empty($state['transport_healthy'])) {
        if (!empty($state['sustained_frame_flow_observed'])) {
            return 'transport_healthy';
        }

        return 'transport_provisional_no_sustained_flow';
    }
    if (!empty($state['browser_ws_handshake_failed'])) {
        return 'browser_ws_handshake_failed';
    }
    if (!empty($state['upstream_ws_failed'])) {
        return 'upstream_ws_failed';
    }

    return (string) ($state['phase'] ?? 'unknown');
}

function ipmiProxyIloObserveRelayTransportState(mysqli $mysqli, string $token, string $phase, array $extra = []): void
{
    ipmiProxyIloTransportHealthStateStore($mysqli, $token, array_merge(['relay_phase' => $phase], $extra));
}

function ipmiProxyIloObserveBrowserWsState(mysqli $mysqli, string $token, string $phase, array $extra = []): void
{
    $map = [
        'handshake_ok'   => ['browser_ws_handshake_ok' => 1],
        'handshake_fail' => ['browser_ws_handshake_failed' => 1],
        'connect'        => ['browser_ws_connect_attempted' => 1],
    ];
    $patch = $map[$phase] ?? ['browser_ws_phase' => $phase];
    ipmiProxyIloTransportHealthStateStore($mysqli, $token, array_merge($patch, $extra));
}

function ipmiProxyIloObserveUpstreamWsState(mysqli $mysqli, string $token, string $phase, array $extra = []): void
{
    $patch = match ($phase) {
        'tls_ok'    => ['upstream_tls_ok' => 1],
        'tls_fail'  => ['upstream_tls_failed' => 1, 'transport_failed' => 1],
        'ws_ok'     => ['upstream_ws_ok' => 1],
        'ws_fail'   => ['upstream_ws_failed' => 1, 'transport_failed' => 1],
        default     => ['upstream_phase' => $phase],
    };
    ipmiProxyIloTransportHealthStateStore($mysqli, $token, array_merge($patch, $extra));
}

function ipmiProxyIloObserveFrameFlowState(mysqli $mysqli, string $token, bool $active, bool $observed = false): void
{
    $patch = ['frame_pump_active' => $active ? 1 : 0];
    if ($observed) {
        $patch['frame_flow_observed'] = 1;
    }
    ipmiProxyIloTransportHealthStateStore($mysqli, $token, $patch);
}

/** Relay / browser: record bounded sustained frame-flow observation (session meta; complements bugs.txt). */
function ipmiProxyIloObserveSustainedTransport(mysqli $mysqli, string $token, bool $sustained): void
{
    ipmiProxyIloTransportHealthStateStore($mysqli, $token, [
        'sustained_frame_flow_observed' => $sustained ? 1 : 0,
    ]);
}

/**
 * iLO: record server-side shell path abandonment + BUG lines + session meta.
 */
function ipmiProxyIloAbandonShellPath(mysqli $mysqli, string $token, string $bugCode, string $bmcPath = ''): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $bugKey = ipmiKvmBugLogCanonicalEventKey('BUG', $bugCode, '');
    $srvKey = ipmiKvmBugLogCanonicalEventKey('SERVER', 'shell_path_abandon', $bugCode);
    $session = ipmiWebLoadSession($mysqli, $token);
    $me = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $ev0 = is_array($me['kvm_buglog_dedupe']['events'] ?? null) ? $me['kvm_buglog_dedupe']['events'] : [];
    if (!isset($ev0[$bugKey])) {
        ipmiKvmBugLogAppendBug($bugCode, 'Shell KVM path abandoned', $bmcPath);
    }
    if (!isset($ev0[$srvKey])) {
        ipmiKvmBugLogAppendSection(
            'SERVER',
            'event: shell_path_abandoned_for_application | code: ' . $bugCode
                . ($bmcPath !== '' ? ' | bmc_path: ' . substr($bmcPath, 0, 120) : '')
        );
    }
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($bugKey, $srvKey): void {
        $d = is_array($meta['kvm_buglog_dedupe'] ?? null) ? $meta['kvm_buglog_dedupe'] : ['v' => 1, 'events' => []];
        $ev = is_array($d['events'] ?? null) ? $d['events'] : [];
        foreach ([$bugKey, $srvKey] as $k) {
            if (!isset($ev[$k])) {
                $ev[$k] = ['first_ts' => time(), 'last_ts' => time(), 'count' => 1];
            } else {
                $ev[$k]['count'] = (int) ($ev[$k]['count'] ?? 0) + 1;
                $ev[$k]['last_ts'] = time();
            }
        }
        $d['events'] = array_slice($ev, -64, null, true);
        $d['v'] = 1;
        $meta['kvm_buglog_dedupe'] = $d;
    });
    ipmiKvmShellAbandonPersist($mysqli, $token, $bugCode, $bmcPath);
}

function ipmiProxyIloShouldAbandonShellPath(array $session): bool
{
    return ipmiKvmIsShellAbandonedForRun($session);
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloForceApplicationPathForRun(mysqli $mysqli, string $token): void
{
    ipmiKvmPlanForceApplicationOverride($mysqli, $token);
}

function ipmiKvmBugLogBrowserBeaconEndpoint(): string
{
    return '/ipmi_kvm_buglog_ingest.php';
}

/** @param array<string, mixed> $row */
function ipmiKvmBrowserLogNormalize(array $row): string
{
    return ipmiKvmBugLogNormalizeBrowserEvent($row);
}

function ipmiKvmBrowserLogAppend(string $section, string $event, $detail = null): void
{
    ipmiKvmBugLogAppendSection(
        $section,
        ipmiKvmBrowserLogNormalize([
            'section' => $section,
            'event'   => $event,
            'detail'  => $detail,
        ])
    );
}

/**
 * @param array<string, mixed> $payload
 * @return array{ok: bool, error?: string}
 */
function ipmiKvmBrowserLogIngest(mysqli $mysqli, array $payload): array
{
    return ipmiKvmBugLogIngestBrowserEvent($mysqli, $payload);
}

/**
 * @return array{noise: bool, key: string}
 */
function ipmiKvmBrowserLogDeduplicate(string $section, string $event, array $detail): array
{
    return ipmiKvmBrowserLogNoiseDedupeInfo($section, $event, $detail);
}

/**
 * Browser-visible slice of full-run aggregate (from bugs.txt raw scan).
 *
 * @return array<string, mixed>
 */
function ipmiKvmBrowserLogAggregateState(string $raw): array
{
    $agg = ipmiKvmBugLogComputeAggregateFromRaw($raw);
    $keys = [
        'application_path_signal', 'launch_attempt_signal', 'session_ready_signal',
        'live_display_heuristic_signal', 'browser_transport_verdict_last',
        'browser_ws_attempted', 'browser_ws_handshake_ok', 'browser_ws_handshake_fail_count',
        'browser_ws_error_count', 'browser_ws_close_count',
        'transport_attempted', 'upstream_connect_attempted', 'upstream_tls_ok', 'upstream_ws_ok',
        'frame_pump_started', 'first_frame_observed', 'sustained_frame_flow_observed',
        'idle_timeout_observed', 'transport_unstable', 'transport_failed',
    ];
    $agg = ipmiKvmTransportAggregateFinalize($agg);

    return array_intersect_key($agg, array_flip($keys));
}

/**
 * @param array<string, mixed> $session
 * @param array<string, mixed> $browserSnapshot
 */
function ipmiProxyIloCanFinalizeStrongConfirmation(array $session, array $browserSnapshot = []): bool
{
    $t = ipmiProxyIloTransportHealthStateLoad($session);
    $th = !empty($t['transport_healthy']) || !empty($browserSnapshot['transport_healthy']);

    return $th && !empty($browserSnapshot['live_display']);
}

/** @param array<string, mixed> $browserSnapshot */
function ipmiProxyIloRejectHeuristicOnlySuccess(array $browserSnapshot): bool
{
    if (!empty($browserSnapshot['transport_healthy'])) {
        return false;
    }

    return !empty($browserSnapshot['session_ready'])
        || !empty($browserSnapshot['live_display'])
        || !empty($browserSnapshot['renderer_only']);
}

function ipmiProxyIloFinalizeStrongConfirmation(string $verdict): void
{
    ipmiKvmBugLogAppendSection('FINAL', 'event: finalize_marker | verdict: ' . substr(trim($verdict), 0, 120));
}

function ipmiProxyIloStopShellPollingAfterPromotion(mysqli $mysqli, string $token): void
{
    ipmiKvmShellAbandonPersist($mysqli, $token, 'SHELL_POLL_STOP_AFTER_PROMOTION');
}
