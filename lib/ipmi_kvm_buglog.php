<?php
/**
 * Project-local KVM run diagnostic logs under bugs/bugsN.txt (monotonic per click).
 * Each panel KVM launch creates a new file; historical runs are never truncated or reused.
 */

declare(strict_types=1);

require_once __DIR__ . '/ipmi_web_session.php';

/** Project root (parent of lib/). */
function ipmiKvmBugProjectRoot(): string
{
    return dirname(__DIR__);
}

/** Absolute path to bugs/ directory. */
function ipmiKvmBugFolderPath(): string
{
    return ipmiKvmBugProjectRoot() . DIRECTORY_SEPARATOR . 'bugs';
}

/**
 * Ensure bugs/ exists (0755).
 */
function ipmiKvmBugFolderEnsureExists(): bool
{
    $dir = ipmiKvmBugFolderPath();
    if (is_dir($dir)) {
        return true;
    }

    return @mkdir($dir, 0755, true);
}

/**
 * Sorted list of numeric indexes N for existing bugsN.txt files.
 *
 * @return list<int>
 */
function ipmiKvmBugFileListExisting(): array
{
    $dir = ipmiKvmBugFolderPath();
    $out = [];
    if (!is_dir($dir)) {
        return $out;
    }
    foreach (scandir($dir) ?: [] as $fn) {
        if (preg_match('/^bugs(\d+)\.txt$/i', $fn, $m)) {
            $out[] = (int) $m[1];
        }
    }
    sort($out, SORT_NUMERIC);

    return $out;
}

/**
 * Next file index: max(existing) + 1, or 1 if none (gaps are not reused).
 */
function ipmiKvmBugFileNextIndex(): int
{
    $list = ipmiKvmBugFileListExisting();
    if ($list === []) {
        return 1;
    }

    return max($list) + 1;
}

/** Absolute path for bugs/bugs{N}.txt */
function ipmiKvmBugFilePathForIndex(int $index): string
{
    return ipmiKvmBugFolderPath() . DIRECTORY_SEPARATOR . 'bugs' . max(1, $index) . '.txt';
}

/** Relative path from project root: bugs/bugs{N}.txt */
function ipmiKvmBugFileRelForIndex(int $index): string
{
    return 'bugs/bugs' . max(1, $index) . '.txt';
}

/**
 * Create a new empty run file and write the initial template. Does not touch other files.
 *
 * @param array<string, mixed> $ctx Same context as ipmiKvmBugLogStartRun
 * @return array{run_id: string, bug_file_rel: string, bug_file_index: int, abs_path: string}
 */
function ipmiKvmBugFileCreateForRun(array $ctx): array
{
    $runId = bin2hex(random_bytes(8));
    $started = gmdate('c') . 'Z';
    $token = strtolower(trim((string) ($ctx['token'] ?? '')));
    $suffix = (strlen($token) === 64) ? substr($token, -8) : '';

    if (!ipmiKvmBugFolderEnsureExists()) {
        return [
            'run_id'         => $runId,
            'bug_file_rel'   => '',
            'bug_file_index' => 0,
            'abs_path'       => '',
        ];
    }

    $idx = ipmiKvmBugFileNextIndex();
    $path = ipmiKvmBugFilePathForIndex($idx);
    while (is_file($path) && @filesize($path) > 0) {
        $idx++;
        $path = ipmiKvmBugFilePathForIndex($idx);
    }
    $rel = ipmiKvmBugFileRelForIndex($idx);

    $bmcHostMasked = ipmiKvmBugLogMaskSecrets((string) ($ctx['bmc_host'] ?? ''), 12);
    $tokenMasked = ipmiKvmBugLogMaskSecrets($token, 8);

    $lines = [
        '==================================================',
        'KVM RUN START',
        'run_id: ' . $runId,
        'bug_file_rel: ' . $rel,
        'bug_file_index: ' . (string) $idx,
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
        '[BROWSER_CONSOLE]',
        'note: ordered_transcript_appended_during_run_via_browser_ingest',
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
    $body = implode("\n", $lines);
    $fp = @fopen($path, 'cb');
    if ($fp === false) {
        return [
            'run_id'         => $runId,
            'bug_file_rel'   => '',
            'bug_file_index' => 0,
            'abs_path'       => '',
        ];
    }
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);

        return [
            'run_id'         => $runId,
            'bug_file_rel'   => '',
            'bug_file_index' => 0,
            'abs_path'       => '',
        ];
    }
    ftruncate($fp, 0);
    fwrite($fp, $body);
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    return [
        'run_id'         => $runId,
        'bug_file_rel'   => $rel,
        'bug_file_index' => $idx,
        'abs_path'       => $path,
    ];
}

/**
 * Absolute path for the active run file from session meta (token-bound).
 */
function ipmiKvmBugFilePathForRun(mysqli $mysqli, string $token): ?string
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return null;
    }
    $session = ipmiWebLoadSession($mysqli, strtolower($token));
    if (!$session) {
        return null;
    }
    $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $br = is_array($meta['kvm_buglog_run'] ?? null) ? $meta['kvm_buglog_run'] : [];
    $rel = trim((string) ($br['bug_file_rel'] ?? ''));
    if ($rel === '' || str_contains($rel, '..') || str_starts_with($rel, '/')) {
        return null;
    }
    $abs = ipmiKvmBugProjectRoot() . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);

    return $abs;
}

/**
 * @deprecated Legacy singleton bugs.txt path; do not use for writes. Kept for one-off tooling only.
 */
function ipmiKvmBugLogRootPath(): string
{
    return ipmiKvmBugProjectRoot() . DIRECTORY_SEPARATOR . 'bugs.txt';
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
 * @deprecated Per-run files: nothing to reset globally.
 */
function ipmiKvmBugLogResetFile(): void
{
}

/**
 * Historical: previously reset singleton bugs.txt. Per-run logs use bugs/bugsN.txt only.
 */
function ipmiKvmBugLogBeginPanelAttempt(int $serverId): void
{
    unset($serverId);
}

/**
 * Append one UTF-8 line to the token-bound run file only.
 */
function ipmiKvmBugLogAppend(string $line, mysqli $mysqli, string $token): void
{
    $path = ipmiKvmBugFilePathForRun($mysqli, $token);
    if ($path === null || $path === '') {
        return;
    }
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
 * Active run_id for this token (session meta; authoritative for ingest).
 */
function ipmiKvmBugLogCurrentRunIdForToken(mysqli $mysqli, string $token): ?string
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return null;
    }
    $session = ipmiWebLoadSession($mysqli, strtolower($token));
    if (!$session) {
        return null;
    }
    $br = is_array($session['session_meta']['kvm_buglog_run'] ?? null) ? $session['session_meta']['kvm_buglog_run'] : [];
    $rid = trim((string) ($br['run_id'] ?? ''));

    return $rid !== '' ? $rid : null;
}

/** @deprecated Use ipmiKvmBugLogCurrentRunIdForToken($mysqli, $token) */
function ipmiKvmBugLogCurrentRunId(): ?string
{
    return null;
}

function ipmiKvmBugLogTokenSuffixFromSession(array $session): ?string
{
    $br = is_array($session['session_meta']['kvm_buglog_run'] ?? null) ? $session['session_meta']['kvm_buglog_run'] : [];
    $s = strtolower(trim((string) ($br['token_suffix'] ?? '')));

    return $s !== '' ? $s : null;
}

/**
 * Read token_suffix from session (replaces legacy header read from singleton file).
 */
function ipmiKvmBugLogReadTokenSuffixFromHeader(): ?string
{
    return null;
}

/**
 * Start a new KVM run: create bugs/bugsN.txt only; return run_id and file metadata.
 *
 * @param array<string, mixed> $ctx
 * @return array{run_id: string, bug_file_rel: string, bug_file_index: int}
 */
function ipmiKvmBugLogStartRun(array $ctx): array
{
    $created = ipmiKvmBugFileCreateForRun($ctx);

    return [
        'run_id'         => $created['run_id'],
        'bug_file_rel'   => $created['bug_file_rel'],
        'bug_file_index' => (int) ($created['bug_file_index'] ?? 0),
    ];
}

function ipmiKvmBugLogAppendSection(string $section, string $bodyLine, mysqli $mysqli, string $token): void
{
    $section = strtoupper(trim($section));
    if ($section === '') {
        $section = 'NOTE';
    }
    ipmiKvmBugLogAppend('[' . $section . '] ' . $bodyLine, $mysqli, strtolower($token));
}

function ipmiKvmBugLogAppendBug(string $code, string $summary, mysqli $mysqli, string $token, string $detail = ''): void
{
    $detail = trim($detail);
    if ($detail !== '') {
        $detail = ' | detail: ' . ipmiKvmBugLogMaskSecrets($detail, 24);
    }
    ipmiKvmBugLogAppend('[BUG] code: ' . trim($code) . ' | summary: ' . trim($summary) . $detail, $mysqli, strtolower($token));
}

/**
 * Verify token belongs to active KVM buglog run for this session row.
 */
function ipmiKvmBugLogTokenMatchesActiveRun(string $token, mysqli $mysqli): bool
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return false;
    }
    $tok = strtolower($token);
    $session = ipmiWebLoadSession($mysqli, $tok);
    if (!$session) {
        return false;
    }
    $want = substr($tok, -8);
    $got = ipmiKvmBugLogTokenSuffixFromSession($session);

    return $got !== null && $got !== '' && hash_equals($got, $want);
}

/**
 * True when this token has an open bug run file binding and the run is not marked closed in session.
 */
function ipmiKvmBugLogHasOpenRun(mysqli $mysqli, string $token): bool
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return false;
    }
    $session = ipmiWebLoadSession($mysqli, strtolower($token));
    if (!$session) {
        return false;
    }
    $br = is_array($session['session_meta']['kvm_buglog_run'] ?? null) ? $session['session_meta']['kvm_buglog_run'] : [];
    $rid = trim((string) ($br['run_id'] ?? ''));
    $rel = trim((string) ($br['bug_file_rel'] ?? ''));

    return $rid !== '' && $rel !== '';
}

/**
 * Whether a [FINAL] block may be written (active run + token matches when provided).
 */
function ipmiKvmBugLogCanFinalizeRun(mysqli $mysqli, string $token): bool
{
    if (!ipmiKvmBugLogHasOpenRun($mysqli, $token)) {
        return false;
    }
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return true;
    }

    return ipmiKvmBugLogTokenMatchesActiveRun($token, $mysqli);
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
        // Every relay HTTP hit should be able to move [FINAL] forward (browser may have logged errors first).
        $event === 'ipmi_ws_relay_request_received' => 2,
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
    $path = ipmiKvmBugFilePathForRun($mysqli, $token);
    if ($path === null || $path === '' || !is_readable($path)) {
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
        if (!ipmiKvmBugLogSettleWindowPassed($mysqli, $token, 12)) {
            return;
        }
        if (($now - $lastTs) < (($pri >= 2) ? 2 : 5)) {
            return;
        }
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($now): void {
            $meta['kvm_buglog_final_refresh_ts'] = $now;
            $meta['kvm_buglog_final_refresh_count'] = (int) ($meta['kvm_buglog_final_refresh_count'] ?? 0) + 1;
        });
        $payload = $stored;
        $payload['token'] = strtolower($token);
        $rid = ipmiKvmBugLogCurrentRunIdForToken($mysqli, $token);
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
    if (!$mysqli instanceof mysqli || !ipmiKvmBugLogTokenMatchesActiveRun($token, $mysqli)) {
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
    ipmiKvmBugLogAppendSection('TRANSPORT', 'event: ' . implode(' ', $parts), $mysqli, $token);
    if ($mysqli instanceof mysqli) {
        ipmiKvmBugLogTouchMeaningfulEvent($mysqli, $token);
        ipmiKvmBugLogMaybeRefreshFinalAfterRelayEvent($mysqli, $token, $event);
    }
}

/**
 * Update session timestamp for settle-window finalization (browser + relay + console).
 */
function ipmiKvmBugLogTouchMeaningfulEvent(?mysqli $mysqli, string $token): void
{
    if (!$mysqli instanceof mysqli || !preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    $tok = strtolower($token);
    ipmiWebSessionMetaMutate($mysqli, $tok, static function (array &$meta): void {
        $meta['kvm_buglog_last_meaningful_event_ts'] = time();
    });
}

/**
 * Next monotonic seq for [BROWSER_CONSOLE] lines (server-assigned when client sends 0).
 */
function ipmiKvmBugLogNextBrowserConsoleSeq(mysqli $mysqli, string $token): int
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return 0;
    }
    $tok = strtolower($token);
    $seq = 0;
    ipmiWebSessionMetaMutate($mysqli, $tok, static function (array &$meta) use (&$seq): void {
        $seq = (int) ($meta['kvm_buglog_console_seq'] ?? 0) + 1;
        $meta['kvm_buglog_console_seq'] = $seq;
    });

    return $seq;
}

/**
 * Append one ordered console transcript line (no noise dedupe — full stream).
 *
 * @param array<string, mixed>|string|null $detailMsg
 */
function ipmiKvmBugLogAppendBrowserConsoleLine(
    ?mysqli $mysqli,
    string $token,
    int $clientSeq,
    string $level,
    string $source,
    string $eventText,
    $detailMsg
): void {
    if (!$mysqli instanceof mysqli || !ipmiKvmBugLogTokenMatchesActiveRun($token, $mysqli)) {
        return;
    }
    $level = strtolower(preg_replace('/[^a-z]/', '', $level) ?? '');
    if ($level === '') {
        $level = 'log';
    }
    $level = substr($level, 0, 12);
    $source = str_replace(["\r", "\n"], ' ', substr(trim($source), 0, 160));
    $eventText = str_replace(["\r", "\n"], ' ', substr(trim($eventText), 0, 220));
    if ($detailMsg !== null && !is_string($detailMsg)) {
        $detailMsg = json_encode($detailMsg, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
    $detailStr = is_string($detailMsg) ? trim($detailMsg) : '';
    $detailStr = str_replace(["\r", "\n"], ' ', $detailStr);
    $detailStr = ipmiKvmBugLogMaskSecrets($detailStr, 12);
    if (strlen($detailStr) > 900) {
        $detailStr = substr($detailStr, 0, 900) . '…';
    }
    $seq = $clientSeq > 0 ? $clientSeq : 0;
    if ($seq <= 0 && $mysqli instanceof mysqli) {
        $seq = ipmiKvmBugLogNextBrowserConsoleSeq($mysqli, $token);
    }
    if ($seq <= 0) {
        $seq = 1;
    }
    $line = 'seq: ' . $seq
        . ' | level: ' . $level
        . ' | source: ' . ($source !== '' ? $source : 'browser')
        . ' | event: ' . ($eventText !== '' ? $eventText : 'line')
        . ' | detail: ' . ($detailStr !== '' ? $detailStr : '-');
    ipmiKvmBugLogAppendSection('BROWSER_CONSOLE', $line, $mysqli, $token);
    if ($mysqli instanceof mysqli) {
        ipmiKvmBugLogTouchMeaningfulEvent($mysqli, $token);
    }
}

/**
 * Remove prior [BROWSER_SUMMARY] block before rewriting at [FINAL] time.
 */
function ipmiKvmBugLogStripBrowserSummarySection(string $raw): string
{
    $next = preg_replace('#(?:\n\[BROWSER_SUMMARY\][^\n]*)+#', "\n", $raw);
    $next = is_string($next) ? preg_replace('#(?:\n\[BROWSER\] norm_summary \|[^\n]*)+#', "\n", $next) : $raw;

    return is_string($next) ? $next : $raw;
}

/**
 * Regenerated normalized browser summary (counts from aggregate scan).
 *
 * @param array<string, mixed> $agg
 */
function ipmiKvmBugLogFormatBrowserSummarySection(array $agg): string
{
    $pfx = '[BROWSER] norm_summary | ';
    $lines = [
        $pfx . 'note: recomputed_when_[FINAL]_refreshed_from_full_bugs_txt_scan',
    ];
    $lines[] = $pfx . 'event: browser_console_entry_count | count: ' . (string) ((int) ($agg['browser_console_entry_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_console_error_count | count: ' . (string) ((int) ($agg['browser_console_error_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_console_warn_count | count: ' . (string) ((int) ($agg['browser_console_warn_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_ws_attempted | signal: ' . (!empty($agg['browser_ws_attempted']) ? 'yes' : 'no');
    $lines[] = $pfx . 'event: browser_ws_failed_connect | count: ' . (string) ((int) ($agg['browser_ws_failed_connect_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_ws_error | count: ' . (string) ((int) ($agg['browser_ws_socket_error_events'] ?? 0));
    $lines[] = $pfx . 'event: browser_ws_handshake_fail_lines | count: ' . (string) ((int) ($agg['browser_ws_error_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_ws_close | count: ' . (string) ((int) ($agg['browser_ws_close_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_dom_exception | count: ' . (string) ((int) ($agg['browser_dom_exception_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_mutation_observer_invalid_target | count: ' . (string) ((int) ($agg['browser_mutation_observer_invalid_target_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_null_children_access | count: ' . (string) ((int) ($agg['browser_null_children_access_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_unhandled_exception | count: ' . (string) ((int) ($agg['browser_unhandled_exception_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_unhandled_rejection | count: ' . (string) ((int) ($agg['browser_unhandled_rejection_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_fetch_http_error | count: ' . (string) ((int) ($agg['browser_fetch_http_error_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_fetch_502 | count: ' . (string) ((int) ($agg['browser_fetch_502_count'] ?? 0));
    $lines[] = $pfx . 'event: browser_transport_verdict_tick | latest: ' . (trim((string) ($agg['browser_transport_verdict_last'] ?? '')) !== ''
        ? substr(trim((string) $agg['browser_transport_verdict_last']), 0, 80)
        : 'unknown');
    $lines[] = $pfx . 'event: relay_request_count | count: ' . (string) ((int) ($agg['relay_request_count'] ?? 0));
    $lines[] = $pfx . 'event: relay_browser_attempt_correlated | count: ' . (string) ((int) ($agg['relay_browser_attempt_correlated_count'] ?? 0));
    $lines[] = $pfx . 'event: relay_browser_attempt_none | count: ' . (string) ((int) ($agg['relay_browser_attempt_none_count'] ?? 0));
    $ids = trim((string) ($agg['browser_attempt_ids_seen_csv'] ?? ''));
    $noneN = (int) ($agg['relay_browser_attempt_none_count'] ?? 0);
    $corrN = (int) ($agg['relay_browser_attempt_correlated_count'] ?? 0);
    $mismatch = $ids !== '' && $noneN > 0 && $corrN === 0;
    $lines[] = $pfx . 'event: relay_correlation_mismatch_suspected | signal: ' . ($mismatch ? 'yes' : 'no');
    $lines[] = $pfx . 'event: browser_attempt_ids_seen | ids: ' . ($ids !== '' ? $ids : 'none');
    $lines[] = $pfx . 'event: browser_stalled_max_ticks | count: ' . (string) ((int) ($agg['browser_stalled_max_ticks_count'] ?? 0));
    $lines[] = $pfx . 'event: session_ready_heuristic | signal: ' . (!empty($agg['session_ready_signal']) ? 'yes' : 'no');
    $lines[] = $pfx . 'event: live_display_heuristic | signal: ' . (!empty($agg['live_display_heuristic_signal']) ? 'yes' : 'no');

    return implode("\n", $lines);
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
        'browser_ws_error'                                 => ['sec' => ['BROWSER'], 'mat' => ['relay_url_norm']],
        'browser_ws_failed_connect'                        => ['sec' => ['BROWSER'], 'mat' => ['relay_url_norm', 'phase']],
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
    $runId = (string) (ipmiKvmBugLogCurrentRunIdForToken($mysqli, $token) ?? '');
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
    if (!ipmiKvmBugLogCanFinalizeRun($mysqli, $token)) {
        return;
    }
    ipmiKvmBugLogAppendSection('NOTE', 'event: kvm_run_closed | note: server_marked_run_closed_flush_final', $mysqli, $token);
    ipmiKvmBugLogPatchFinalFromSessionOrMinimal($mysqli, $token);
}

/**
 * Normalize browser ingest payload to a log line.
 *
 * @param array<string, mixed> $row
 */
function ipmiKvmBugLogNormalizeBrowserEvent(array $row): string
{
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
    $active = ipmiKvmBugLogCurrentRunIdForToken($mysqli, $token);
    if ($active === null || $active === '' || !hash_equals($active, $runId)) {
        return ['ok' => false, 'error' => 'run_mismatch'];
    }
    if (!ipmiKvmBugLogTokenMatchesActiveRun($token, $mysqli)) {
        return ['ok' => false, 'error' => 'token_suffix_mismatch'];
    }
    $section = (string) ($payload['section'] ?? 'BROWSER');
    $ev = strtolower((string) ($payload['event'] ?? ''));
    $detail = is_array($payload['detail'] ?? null) ? $payload['detail'] : [];

    if ($ev === 'kvm_final_summary') {
        ipmiKvmBugLogPersistLastFinalPayload($mysqli, $token, $payload);
        ipmiKvmBugLogTouchMeaningfulEvent($mysqli, $token);

        return ['ok' => true];
    }

    if ($ev === 'browser_console_line' && strtoupper(trim($section)) === 'BROWSER_CONSOLE') {
        $d = is_array($detail) ? $detail : [];
        $evName = strtolower(trim((string) ($d['event'] ?? '')));
        ipmiKvmBugLogAppendBrowserConsoleLine(
            $mysqli,
            $token,
            (int) ($d['seq'] ?? 0),
            (string) ($d['level'] ?? 'log'),
            (string) ($d['source'] ?? ''),
            (string) ($d['event'] ?? 'line'),
            $d['detail'] ?? ($d['message'] ?? null)
        );
        if ($evName === 'browser_mutation_observer_invalid_target') {
            ipmiKvmBugLogAppendOncePerRun($mysqli, $token, 'b_mo_inv', 'BUG', 'code: BROWSER_MUTATION_OBSERVER_INVALID_TARGET | summary: MutationObserver.observe skipped non-Node target');
        }
        if ($evName === 'browser_null_children_access') {
            ipmiKvmBugLogAppendOncePerRun($mysqli, $token, 'b_null_ch', 'BUG', 'code: BROWSER_NULL_CHILDREN_ACCESS | summary: Safe-guarded null/undefined .children access in patched code path');
        }

        return ['ok' => true];
    }

    if ($ev === 'kvm_run_finalize') {
        $fd = is_array($payload['detail'] ?? null) ? $payload['detail'] : [];
        $force = !empty($fd['force_finalize']) || !empty($fd['force']);
        $reason = strtolower(trim((string) ($fd['reason'] ?? '')));
        $bypassSettle = $force
            || $reason === 'pagehide'
            || $reason === 'helper_pagehide'
            || $reason === 'unload'
            || $reason === 'max_ticks'
            || str_contains($reason, 'mark_run_closed');
        if (!$bypassSettle && !ipmiKvmRunStateCanFinalize($mysqli, $token, ['quiet_seconds' => 12])) {
            ipmiKvmBugLogAppendSection('NOTE', 'event: kvm_run_finalize_deferred | note: settle_window_not_quiet_since_last_meaningful_browser_relay_or_console_event', $mysqli, $token);

            return ['ok' => true];
        }
        ipmiKvmBugLogAppendSection('NOTE', 'event: kvm_run_finalize_received | note: flush deferred [FINAL] (browser unload, settle passed, or force_finalize)', $mysqli, $token);
        ipmiKvmBugLogPatchFinalFromSessionOrMinimal($mysqli, $token);
        ipmiKvmRunStateAdvance($mysqli, $token, 'run_finalized', []);

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
        ipmiKvmBugLogAppendSection($section, $line, $mysqli, $token);
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

    $browserFinalPri = [
        'browser_ws_failed_connect' => 'ipmi_ws_relay_http_error_exit',
        'browser_ws_error'        => 'ipmi_ws_relay_frame_pump_error',
        'browser_ws_close'        => 'ipmi_ws_relay_first_frame_observed',
        'browser_ws_attempted'    => 'ipmi_ws_relay_request_received',
    ];
    if ($mysqli instanceof mysqli && isset($browserFinalPri[$ev])) {
        ipmiKvmBugLogMaybeRefreshFinalAfterRelayEvent($mysqli, $token, $browserFinalPri[$ev]);
    }
    if ($mysqli instanceof mysqli && $ev === 'browser_ws_attempted' && $detail !== []) {
        ipmiKvmBrowserRelayCorrelationStore($mysqli, $token, $detail);
    }

    ipmiKvmBugLogTouchMeaningfulEvent($mysqli, $token);

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
        'relay_request_count'             => 0,
        'browser_ws_failed_connect_count' => 0,
        'browser_ws_socket_error_events'  => 0,
    ];
    if ($raw === '') {
        return ipmiKvmBugLogAugmentAggregateFromTranscript('', $agg);
    }
    $agg['relay_request_count'] = substr_count($raw, 'ipmi_ws_relay_request_received');
    $agg['browser_ws_failed_connect_count'] = (int) preg_match_all('/event:\s*browser_ws_failed_connect\b/', $raw);
    $agg['browser_ws_socket_error_events'] = (int) preg_match_all('/event:\s*browser_ws_error\b/', $raw);
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
        || (bool) preg_match('/event:\s*browser_ws_attempted\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_relay_connect_attempted\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_construct_failed\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_handshake_succeeded\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_handshake_failed_event\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_closed\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_error\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_failed_connect\b/', $raw)
        || (bool) preg_match('/event:\s*browser_ws_first_application_frame\b/', $raw)
        // Ingested browser-side transport verdict lines (post-WebSocket; collapse-only duplicates but first line proves WS path ran).
        || (bool) preg_match('/event:\s*transport_healthy\b/', $raw)
        || (bool) preg_match('/event:\s*transport_failed\b/', $raw);
    $agg['browser_ws_handshake_fail_count'] = substr_count($raw, 'ipmi_ws_relay_browser_handshake_failed');
    $agg['browser_ws_error_count'] = substr_count($raw, 'browser_ws_construct_failed')
        + substr_count($raw, 'browser_ws_handshake_failed_event')
        + (int) $agg['browser_ws_handshake_fail_count']
        + (int) ($agg['browser_ws_socket_error_events'] ?? 0);
    $agg['browser_ws_close_count'] = (int) preg_match_all('/event:\s*browser_ws_close\b/', $raw)
        + (int) preg_match_all('/event:\s*browser_ws_closed\b/', $raw);
    $agg['upstream_connect_attempted'] = str_contains($raw, 'ipmi_ws_relay_upstream_connect_started');
    $agg['relay_http_error_exit_count'] = substr_count($raw, 'ipmi_ws_relay_http_error_exit');
    $agg['transport_attempted'] = !empty($agg['browser_ws_attempted'])
        || !empty($agg['upstream_connect_attempted'])
        || ((int) ($agg['relay_pump_starts'] ?? 0) > 0)
        || ((int) ($agg['relay_request_count'] ?? 0) > 0);

    return ipmiKvmBugLogAugmentAggregateFromTranscript($raw, $agg);
}

/**
 * Derive browser-console transcript metrics + relay/browser_attempt correlation from full bugs.txt.
 *
 * @param array<string, mixed> $agg
 * @return array<string, mixed>
 */
function ipmiKvmBugLogAugmentAggregateFromTranscript(string $raw, array $agg): array
{
    if ($raw === '') {
        return $agg;
    }
    $agg['browser_console_entry_count'] = 0;
    $agg['browser_console_error_count'] = 0;
    $agg['browser_console_warn_count'] = 0;
    $agg['browser_console_log_count'] = 0;
    $agg['browser_console_info_count'] = 0;
    $agg['browser_console_debug_count'] = 0;
    $agg['browser_dom_exception_count'] = 0;
    $agg['browser_mutation_observer_invalid_target_count'] = 0;
    $agg['browser_null_children_access_count'] = 0;
    $agg['browser_unhandled_exception_count'] = 0;
    $agg['browser_unhandled_rejection_count'] = 0;
    $agg['browser_fetch_http_error_count'] = 0;
    $agg['browser_fetch_502_count'] = 0;
    $agg['browser_transport_verdict_tick_count'] = (int) preg_match_all('/event:\s*browser_transport_verdict_tick\b/', $raw);
    $agg['browser_stalled_max_ticks_count'] = 0;
    $agg['browser_console_socket_error_lines'] = 0;
    $agg['relay_browser_attempt_correlated_count'] = 0;
    $agg['relay_browser_attempt_none_count'] = 0;
    $agg['relay_requests_correlated_to_browser_attempts'] = 0;
    $agg['browser_attempt_ids_seen_csv'] = '';

    if (preg_match_all('/^\[BROWSER_CONSOLE\]\s+(.+)$/m', $raw, $cm)) {
        $agg['browser_console_entry_count'] = count($cm[1]);
        foreach ($cm[1] as $line) {
            if (preg_match('/\|\s*level:\s*(\w+)\s*\|/', $line, $lm)) {
                $lv = strtolower($lm[1]);
                if ($lv === 'error') {
                    $agg['browser_console_error_count']++;
                } elseif ($lv === 'warn') {
                    $agg['browser_console_warn_count']++;
                } elseif ($lv === 'info') {
                    $agg['browser_console_info_count']++;
                } elseif ($lv === 'debug') {
                    $agg['browser_console_debug_count']++;
                } else {
                    $agg['browser_console_log_count']++;
                }
            }
            if (preg_match('/\|\s*event:\s*([^|]+)\s*\|/', $line, $em)) {
                $enet = trim($em[1]);
                $el = strtolower($enet);
                if ($el === 'browser_unhandled_exception' || str_contains($el, 'uncaught')) {
                    $agg['browser_unhandled_exception_count']++;
                }
                if ($el === 'browser_unhandled_rejection') {
                    $agg['browser_unhandled_rejection_count']++;
                }
                if ($el === 'browser_mutation_observer_invalid_target') {
                    $agg['browser_mutation_observer_invalid_target_count']++;
                }
                if ($el === 'browser_null_children_access') {
                    $agg['browser_null_children_access_count']++;
                }
                if (preg_match('/^browser_fetch_(\d+)$/', $enet, $fm)) {
                    $agg['browser_fetch_http_error_count']++;
                    if ($fm[1] === '502') {
                        $agg['browser_fetch_502_count']++;
                    }
                }
            }
            $low = strtolower($line);
            if (str_contains($low, 'domexception')
                || (str_contains($low, 'mutationobserver') && str_contains($low, "not of type 'node'"))
                || str_contains($low, 'not of type "node"')) {
                $agg['browser_dom_exception_count']++;
            }
            if (str_contains($low, 'socket.js') && str_contains($low, 'level: error')) {
                $agg['browser_console_socket_error_lines']++;
            }
            if (str_contains($low, 'ilo_console_stalled') || (str_contains($low, 'max_ticks') && str_contains($low, 'reason'))) {
                $agg['browser_stalled_max_ticks_count']++;
            }
            if (str_contains($low, "reading 'children'") || str_contains($low, 'reading "children"') || str_contains($low, "cannot read properties of null")) {
                $agg['browser_null_children_access_count']++;
            }
        }
    }

    $attemptIds = [];
    if (preg_match_all('/browser_attempt=([^\s&]+)/', $raw, $am)) {
        foreach ($am[1] as $aid) {
            $aid = trim($aid, ',');
            if ($aid !== '' && strcasecmp($aid, 'none') !== 0) {
                $attemptIds[$aid] = true;
            }
        }
    }
    if (preg_match_all('/"attempt_id"\s*:\s*"([^"]+)"/', $raw, $jm)) {
        foreach ($jm[1] as $aid) {
            if ($aid !== '' && strcasecmp($aid, 'none') !== 0) {
                $attemptIds[$aid] = true;
            }
        }
    }
    $ids = array_keys($attemptIds);
    sort($ids);
    $agg['browser_attempt_ids_seen_csv'] = $ids !== [] ? implode(',', array_slice($ids, 0, 24)) : '';

    if (preg_match_all('/ipmi_ws_relay_request_received[^\n]*browser_attempt=([^\s&]+)/', $raw, $rm)) {
        foreach ($rm[1] as $ba) {
            $ba = trim($ba, ',');
            if ($ba === '' || strcasecmp($ba, 'none') === 0) {
                $agg['relay_browser_attempt_none_count']++;
            } else {
                $agg['relay_browser_attempt_correlated_count']++;
            }
        }
    }
    $agg['relay_requests_correlated_to_browser_attempts'] = (int) $agg['relay_browser_attempt_correlated_count'];

    $wsConsoleEv = (int) preg_match_all('/\|\s*event:\s*browser_ws_(failed_connect|error)\b/', $raw);
    if (((int) ($agg['browser_console_socket_error_lines'] ?? 0)) >= 1 || $wsConsoleEv >= 1) {
        $agg['browser_ws_attempted'] = true;
    }

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
        'browser_ws_error_count', 'browser_ws_close_count', 'browser_ws_failed_connect_count',
        'relay_request_count', 'browser_ws_socket_error_events',
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

    $bSockLines = (int) ($agg['browser_console_socket_error_lines'] ?? 0);
    if ($bSockLines >= 2 && $partial) {
        $out['transport_unstable'] = true;
    }
    $relN = (int) ($agg['relay_request_count'] ?? 0);
    if ($bSockLines >= 3 && $relN >= 1) {
        $out['transport_unstable'] = true;
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
    $relays = (int) ($agg['relay_request_count'] ?? 0);
    $bFailConn = (int) ($agg['browser_ws_failed_connect_count'] ?? 0);
    $sockErrOnly = (int) ($agg['browser_ws_socket_error_events'] ?? 0);

    if (!$bOk && $relays === 0 && ($bFailConn >= 1 || $sockErrOnly >= 1)) {
        return 'browser_ws_failed_before_relay_confirmed';
    }
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

    if ($partialUpstream && !$sust && ($sockErrOnly >= 2 || $bFailConn >= 2 || ($bFailConn >= 1 && $sockErrOnly >= 1))) {
        return 'browser_ws_errors_after_partial_relay_success';
    }

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
        'native_console_strongly_rejected_incomplete_evidence',
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
        ipmiKvmBugLogAppendSection($section, $lineBody, $mysqli, $token);
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
 * Bump shell exit-stub injection counter (bounded promotion loop breaker).
 */
function ipmiKvmRunStateBumpShellExitStub(mysqli $mysqli, string $token): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    $tok = strtolower($token);
    ipmiWebSessionMetaMutate($mysqli, $tok, static function (array &$meta): void {
        $st = is_array($meta['kvm_run_path_state'] ?? null) ? $meta['kvm_run_path_state'] : [];
        $st['shell_exit_stub_inject_count'] = (int) ($st['shell_exit_stub_inject_count'] ?? 0) + 1;
        $st['v'] = 1;
        $meta['kvm_run_path_state'] = $st;
    });
}

/**
 * Advance run-scoped KVM lifecycle / FSM markers (session meta).
 *
 * @param array<string, mixed> $extra Merged into kvm_run_path_state
 */
function ipmiKvmRunStateAdvance(mysqli $mysqli, string $token, string $phase, array $extra = []): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    $phase = substr(preg_replace('/[^a-z0-9_]/i', '_', $phase), 0, 48);
    if ($phase === '') {
        return;
    }
    ipmiKvmRunStateStore($mysqli, strtolower($token), array_merge([
        'lifecycle_current' => $phase,
        'lifecycle_ts'      => time(),
    ], $extra));
}

/**
 * Finalize allowed: active run + token + optional settle window (or force / bypass).
 *
 * @param array<string, mixed> $opts force|bypass_settle|quiet_seconds
 */
function ipmiKvmRunStateCanFinalize(mysqli $mysqli, string $token, array $opts = []): bool
{
    if (!ipmiKvmBugLogCanFinalizeRun($mysqli, $token)) {
        return false;
    }
    if (!empty($opts['force']) || !empty($opts['bypass_settle'])) {
        return true;
    }

    return ipmiKvmBugLogSettleWindowPassed($mysqli, $token, (int) ($opts['quiet_seconds'] ?? 12));
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
            ipmiKvmBugLogAppendBug('SHELL_LAUNCH_NO_EFFECT', 'Shell HTML5 launch left DOM/transport unchanged', $mysqli, $token, $detailMaterial);
        } else {
            ipmiKvmBugLogAppendBug($reasonCode, 'Shell abandon reason recorded', $mysqli, $token, $detailMaterial);
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
    $tok = strtolower(trim((string) ($payload['token'] ?? '')));
    $path = null;
    if ($mysqli instanceof mysqli && preg_match('/^[a-f0-9]{64}$/', $tok)) {
        $path = ipmiKvmBugFilePathForRun($mysqli, $tok);
    }
    if ($path === null || $path === '' || !is_readable($path)) {
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

    if ($verdict === 'native_console_strongly_confirmed') {
        if ($appLoaded !== 'yes'
            || $promotionCommitted !== 'yes'
            || !$transportHealthy
            || $reinjectAfterAbandon === 'yes'
            || $transportUnstable === 'yes') {
            $verdict = 'native_console_strongly_rejected_incomplete_evidence';
            $resolved['source'] = 'aggregate_transport_gate';
            if ($failureReason === '' || strtolower($failureReason) === 'none') {
                $failureReason = 'strong_confirmation_rejected_missing_application_transport_or_unstable';
            }
        }
    }

    $finalBody = '[FINAL]' . "\n"
        . $line('verdict', $verdict !== '' ? $verdict : 'pending')
        . $line('final_verdict', $verdict !== '' ? $verdict : 'pending')
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
        . $line('browser_ws_failed_connect_count', (string) ((int) ($agg['browser_ws_failed_connect_count'] ?? 0)))
        . $line('browser_console_entry_count', (string) ((int) ($agg['browser_console_entry_count'] ?? 0)))
        . $line('browser_console_error_count', (string) ((int) ($agg['browser_console_error_count'] ?? 0)))
        . $line('browser_console_warn_count', (string) ((int) ($agg['browser_console_warn_count'] ?? 0)))
        . $line('browser_console_log_count', (string) ((int) ($agg['browser_console_log_count'] ?? 0)))
        . $line('browser_console_info_count', (string) ((int) ($agg['browser_console_info_count'] ?? 0)))
        . $line('browser_console_debug_count', (string) ((int) ($agg['browser_console_debug_count'] ?? 0)))
        . $line('browser_dom_exception_count', (string) ((int) ($agg['browser_dom_exception_count'] ?? 0)))
        . $line('browser_null_children_access_count', (string) ((int) ($agg['browser_null_children_access_count'] ?? 0)))
        . $line('browser_fetch_502_count', (string) ((int) ($agg['browser_fetch_502_count'] ?? 0)))
        . $line('browser_unhandled_exception_count', (string) ((int) ($agg['browser_unhandled_exception_count'] ?? 0)))
        . $line('browser_unhandled_rejection_count', (string) ((int) ($agg['browser_unhandled_rejection_count'] ?? 0)))
        . $line('browser_transport_verdict_tick_count', (string) ((int) ($agg['browser_transport_verdict_tick_count'] ?? 0)))
        . $line('browser_stalled_max_ticks_count', (string) ((int) ($agg['browser_stalled_max_ticks_count'] ?? 0)))
        . $line('browser_attempt_ids_seen', (string) ($agg['browser_attempt_ids_seen_csv'] ?? 'none'))
        . $line('relay_requests_correlated_to_browser_attempts', (string) ((int) ($agg['relay_requests_correlated_to_browser_attempts'] ?? 0)))
        . $line('browser_attempt_none_count', (string) ((int) ($agg['relay_browser_attempt_none_count'] ?? 0)))
        . $line('relay_request_count', (string) ((int) ($agg['relay_request_count'] ?? 0)))
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
        . $line('aggregate_source', 'per_run_bug_file_full_scan_relay_transport_browser_console_transcript_helper_server_plus_last_kvm_final_summary_snapshot | final_refresh_count=' . (string) $refreshCount)
        . "==================================================\n"
        . "KVM RUN END\n";

    if (
        function_exists('ipmiProxyDebugEnabled')
        && function_exists('ipmiProxyDebugLog')
        && ipmiProxyDebugEnabled()
    ) {
        ipmiProxyDebugLog('kvm_buglog_final_transport_matrix', [
            'token_suffix'                  => strlen($tok) >= 8 ? substr($tok, -8) : '',
            'verdict'                       => $verdict !== '' ? $verdict : 'pending',
            'verdict_source'                => (string) ($resolved['source'] ?? 'browser'),
            'transport_attempted'           => (string) ($merged['transport_attempted'] ?? ''),
            'browser_ws_attempted'          => (string) ($merged['browser_ws_attempted'] ?? ''),
            'browser_ws_handshake_ok'       => (string) ($merged['browser_ws_handshake_ok'] ?? ''),
            'browser_ws_error_count'        => (string) ((int) ($agg['browser_ws_error_count'] ?? 0)),
            'browser_ws_close_count'        => (string) ((int) ($agg['browser_ws_close_count'] ?? 0)),
            'browser_ws_failed_connect_count' => (string) ((int) ($agg['browser_ws_failed_connect_count'] ?? 0)),
            'browser_console_entry_count'   => (string) ((int) ($agg['browser_console_entry_count'] ?? 0)),
            'browser_console_error_count'   => (string) ((int) ($agg['browser_console_error_count'] ?? 0)),
            'browser_console_warn_count'    => (string) ((int) ($agg['browser_console_warn_count'] ?? 0)),
            'browser_dom_exception_count'   => (string) ((int) ($agg['browser_dom_exception_count'] ?? 0)),
            'relay_request_count'           => (string) ((int) ($agg['relay_request_count'] ?? 0)),
            'relay_correlated_browser_attempt' => (string) ((int) ($agg['relay_requests_correlated_to_browser_attempts'] ?? 0)),
            'relay_browser_attempt_none'    => (string) ((int) ($agg['relay_browser_attempt_none_count'] ?? 0)),
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
    $stripped = ipmiKvmBugLogStripBrowserSummarySection($stripped);
    $summaryBlock = ipmiKvmBugLogFormatBrowserSummarySection($agg);
    $out = rtrim($stripped) . "\n\n" . $summaryBlock . "\n\n" . $finalBody;

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
        ipmiKvmBugLogAppendBug($bugCode, 'Shell KVM path abandoned', $mysqli, $token, $bmcPath);
    }
    if (!isset($ev0[$srvKey])) {
        ipmiKvmBugLogAppendSection(
            'SERVER',
            'event: shell_path_abandoned_for_application | code: ' . $bugCode
                . ($bmcPath !== '' ? ' | bmc_path: ' . substr($bmcPath, 0, 120) : ''),
            $mysqli,
            $token
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

function ipmiKvmBrowserLogAppend(mysqli $mysqli, string $token, string $section, string $event, $detail = null): void
{
    ipmiKvmBugLogAppendSection(
        $section,
        ipmiKvmBrowserLogNormalize([
            'section' => $section,
            'event'   => $event,
            'detail'  => $detail,
        ]),
        $mysqli,
        strtolower($token)
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
        'browser_ws_error_count', 'browser_ws_close_count', 'browser_ws_failed_connect_count', 'relay_request_count',
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

function ipmiProxyIloFinalizeStrongConfirmation(mysqli $mysqli, string $token, string $verdict): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    ipmiKvmBugLogAppendSection(
        'FINAL',
        'event: finalize_marker | verdict: ' . substr(trim($verdict), 0, 120),
        $mysqli,
        strtolower($token)
    );
}

function ipmiProxyIloStopShellPollingAfterPromotion(mysqli $mysqli, string $token): void
{
    ipmiKvmShellAbandonPersist($mysqli, $token, 'SHELL_POLL_STOP_AFTER_PROMOTION');
}

/**
 * Server-side attempt id for non-browser callers (browser uses ipmiKvmTransportAttemptIdCreate in injected JS).
 */
function ipmiKvmTransportAttemptIdCreate(): string
{
    try {
        return 'srv_' . bin2hex(random_bytes(4));
    } catch (Throwable $e) {
        return 'srv_t' . (string) time();
    }
}

function ipmiKvmTransportAttemptIdPropagate(string $attemptId): string
{
    $s = trim(preg_replace('/[^a-zA-Z0-9_.-]/', '', $attemptId));

    return $s !== '' ? substr($s, 0, 64) : ipmiKvmTransportAttemptIdCreate();
}

/**
 * Optional hook for future session-backed correlation; full-run truth remains bugs.txt scan.
 *
 * @param array<string, mixed> $row
 */
function ipmiKvmBrowserRelayCorrelationStore(mysqli $mysqli, string $token, array $row): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return;
    }
    $tok = strtolower($token);
    $aid = trim((string) ($row['attempt_id'] ?? ''));
    if ($aid === '' || strcasecmp($aid, 'none') === 0) {
        return;
    }
    $aid = substr(preg_replace('/[^a-zA-Z0-9_.-]/', '', $aid), 0, 64);
    if ($aid === '') {
        return;
    }
    ipmiWebSessionMetaMutate($mysqli, $tok, static function (array &$meta) use ($aid): void {
        $ids = is_array($meta['kvm_browser_ws_attempt_ids'] ?? null) ? $meta['kvm_browser_ws_attempt_ids'] : [];
        $ids[] = $aid;
        $meta['kvm_browser_ws_attempt_ids'] = array_slice(array_values(array_unique($ids)), -32);
    });
}

/**
 * @param array<string, mixed> $a
 * @param array<string, mixed> $b
 * @return array<string, mixed>
 */
function ipmiKvmBrowserRelayCorrelationMerge(array $a, array $b): array
{
    return array_merge($a, $b);
}

/**
 * True when no meaningful browser/relay/console event for quietSeconds (session meta).
 */
function ipmiKvmBugLogSettleWindowPassed(mysqli $mysqli, string $token, int $quietSeconds = 12): bool
{
    if (!preg_match('/^[a-f0-9]{64}$/', strtolower($token))) {
        return true;
    }
    $tok = strtolower($token);
    $session = ipmiWebLoadSession($mysqli, $tok);
    if (!$session) {
        return true;
    }
    $meta = $session['session_meta'] ?? [];
    $last = (int) ($meta['kvm_buglog_last_meaningful_event_ts'] ?? 0);
    if ($last <= 0) {
        return true;
    }
    $quietSeconds = max(3, min(120, $quietSeconds));

    return (time() - $last) >= $quietSeconds;
}

/**
 * Streaming merge for browser file lines (authoritative aggregate still from ipmiKvmBugLogComputeAggregateFromRaw).
 *
 * @param array<string, mixed> $agg
 * @param array<string, mixed> $detail
 * @return array<string, mixed>
 */
function ipmiKvmTransportAggregateMergeBrowserEvent(array $agg, string $event, array $detail = []): array
{
    $e = strtolower(trim($event));
    if (str_contains($e, 'browser_ws_attempted')
        || str_contains($e, 'browser_ws_failed_connect')
        || str_contains($e, 'browser_ws_error')
        || str_contains($e, 'browser_ws_relay_connect_attempted')) {
        $agg['browser_ws_attempted'] = true;
    }
    unset($detail);

    return $agg;
}
