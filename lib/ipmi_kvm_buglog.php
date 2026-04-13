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
        'event: final_summary_written_only_at_run_end | note: [FINAL] appended after aggregate merge; not provisional',
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
 * Append transport line if token matches active KVM run (relay path).
 */
function ipmiKvmBugLogRelayDebugEvent(string $token, string $event, array $detail = []): void
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
    $line = ipmiKvmBugLogNormalizeBrowserEvent([
        'section' => $section,
        'event'   => (string) ($payload['event'] ?? ''),
        'detail'  => $payload['detail'] ?? null,
    ]);
    ipmiKvmBugLogAppendSection($section, $line);

    $ev = strtolower((string) ($payload['event'] ?? ''));
    if ($ev === 'shell_launch_no_effect' || $ev === 'ilo_starthtml5irc_no_effect') {
        ipmiKvmBugLogAppendBug('SHELL_LAUNCH_NO_EFFECT', 'Shell HTML5 launch left DOM/transport unchanged', '');
        ipmiKvmShellAbandonPersist($mysqli, $token, 'SHELL_LAUNCH_NO_EFFECT');
    }
    if ($ev === 'kvm_final_summary') {
        ipmiKvmBugLogUpdateFinalSummary($payload);
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
        'browser_ws_handshake_ok'       => false,
        'upstream_tls_ok'               => false,
        'upstream_ws_ok'                => false,
        'frame_pump_started'            => false,
        'first_frame_observed'          => false,
        'sustained_frame_flow_observed' => false,
        'idle_timeout_observed'         => false,
        'upstream_ws_fail_count'        => 0,
        'upstream_tls_fail_count'         => 0,
        'relay_pump_starts'             => 0,
        'relay_closed_events'           => 0,
        'application_path_signal'       => false,
        'shell_abandon_signal'          => false,
        'launch_attempt_signal'         => false,
    ];
    if ($raw === '') {
        return $agg;
    }
    $agg['browser_ws_handshake_ok'] = str_contains($raw, 'ipmi_ws_relay_browser_handshake_succeeded')
        || (bool) preg_match('/\[BROWSER\][^\n]*browser_ws_handshake_succeeded/', $raw)
        || (bool) preg_match('/\[TRANSPORT\][^\n]*browser_ws_handshake_succeeded/', $raw);
    $agg['upstream_tls_ok'] = str_contains($raw, 'ipmi_ws_relay_upstream_tls_connected')
        || str_contains($raw, 'ipmi_ws_relay_upstream_tcp_connected');
    $agg['upstream_ws_ok'] = str_contains($raw, 'ipmi_ws_relay_upstream_ws_handshake_succeeded');
    $agg['frame_pump_started'] = str_contains($raw, 'ipmi_ws_relay_frame_pump_started');
    $agg['first_frame_observed'] = str_contains($raw, 'ipmi_ws_relay_first_frame_observed');
    $agg['sustained_frame_flow_observed'] = str_contains($raw, 'ipmi_ws_relay_sustained_frame_flow_observed');
    $agg['idle_timeout_observed'] = str_contains($raw, 'ipmi_ws_relay_frame_pump_idle_timeout');
    $agg['upstream_ws_fail_count'] = substr_count($raw, 'ipmi_ws_relay_upstream_ws_handshake_failed');
    $agg['upstream_tls_fail_count'] = substr_count($raw, 'ipmi_ws_relay_upstream_tls_failed')
        + substr_count($raw, 'ipmi_ws_relay_upstream_tcp_failed');
    $agg['relay_pump_starts'] = substr_count($raw, 'ipmi_ws_relay_frame_pump_started');
    $agg['relay_closed_events'] = substr_count($raw, 'ipmi_ws_relay_closed');
    $agg['application_path_signal'] = (bool) preg_match('/event:\s*application_path_loaded\b/', $raw);
    $agg['shell_abandon_signal'] = str_contains($raw, 'shell_path_abandoned_for_application')
        || str_contains($raw, 'SHELL_SSE_403')
        || str_contains($raw, 'SHELL_SESSION_INFO_403')
        || str_contains($raw, 'code: SHELL_LAUNCH_NO_EFFECT');
    $agg['launch_attempt_signal'] = (bool) preg_match(
        '/event:\s*(ilo_launch_triggered|ilo_html5_console_launch_attempted|shell_escalation_console_href|application_path_loaded|shell_launch_no_effect|shell_path_abandon_flag_loaded)\b/',
        $raw
    );
    $agg['session_ready_signal'] = (bool) preg_match('/event:\s*session_ready_heuristic\b/', $raw);

    return $agg;
}

/** @return array<string, mixed> */
function ipmiKvmBugLogComputeAggregateFinalState(string $raw): array
{
    return ipmiKvmBugLogComputeAggregateFromRaw($raw);
}

/**
 * Remove all [FINAL] sections (legacy mid-file or trailing).
 */
function ipmiKvmBugLogStripFinalSections(string $raw): string
{
    for ($i = 0; $i < 8; $i++) {
        $next = preg_replace('#\n\[FINAL\][\s\S]*?\n==================================================\nKVM RUN END#', "\n==================================================\nKVM RUN END", $raw, 1);
        if (!is_string($next) || $next === $raw) {
            break;
        }
        $raw = $next;
    }
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
    $sustBrowser = !empty($merged['sustained_transport_ok'])
        || ($merged['sustained_frame_flow_observed'] ?? '') === 'yes';
    $sust = $sustAgg || $sustBrowser;
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
 * Write [FINAL] at end of bugs.txt from browser payload + full-file aggregates (authoritative).
 *
 * @param array<string, mixed> $payload
 */
function ipmiKvmBugLogUpdateFinalSummary(array $payload): void
{
    ipmiKvmBugLogPatchFinalBlock($payload);
}

/**
 * @param array<string, mixed> $payload
 */
function ipmiKvmBugLogPatchFinalBlock(array $payload): void
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
    $agg = ipmiKvmBugLogComputeAggregateFromRaw($raw);
    $merged = ipmiKvmBugLogMergeFinalDetailWithAggregate($agg, $detail);
    $transportHealthy = ipmiKvmBugLogDeriveFinalTransportHealthy($agg, $merged, $verdict);
    $ended = gmdate('c') . 'Z';
    $failureReason = trim((string) ($detail['final_failure_reason'] ?? $detail['reason'] ?? $detail['transport_why'] ?? ''));
    if ($failureReason === '') {
        if (!$transportHealthy && $verdict === 'transport_unhealthy_console_not_confirmed') {
            $failureReason = 'no_sustained_relay_frame_flow_or_transport_unstable';
        }
    }
    $failureReason = substr($failureReason, 0, 400);

    $line = static function (string $k, string $v): string {
        return $k . ': ' . $v . "\n";
    };

    $finalBody = '[FINAL]' . "\n"
        . $line('verdict', $verdict !== '' ? $verdict : 'pending')
        . $line('strong_confirmation', !empty($detail['strong_confirmation']) ? 'yes' : 'no')
        . $line('application_path_loaded', (string) ($merged['application_path_loaded'] ?? 'unknown'))
        . $line('shell_path_abandoned', (string) ($merged['shell_path_abandoned'] ?? 'unknown'))
        . $line('launch_attempted', (string) ($merged['launch_attempted'] ?? 'unknown'))
        . $line('browser_ws_handshake_ok', (string) ($merged['browser_ws_handshake_ok'] ?? 'unknown'))
        . $line('upstream_tls_ok', (string) ($merged['upstream_tls_ok'] ?? 'unknown'))
        . $line('upstream_ws_ok', (string) ($merged['upstream_ws_ok'] ?? 'unknown'))
        . $line('frame_pump_started', (string) ($merged['frame_pump_started'] ?? 'unknown'))
        . $line('first_frame_observed', (string) ($merged['first_frame_observed'] ?? 'unknown'))
        . $line('sustained_frame_flow_observed', (string) ($merged['sustained_frame_flow_observed'] ?? 'unknown'))
        . $line('idle_timeout_observed', !empty($agg['idle_timeout_observed']) ? 'yes' : 'no')
        . $line('upstream_ws_handshake_failures', (string) ((int) ($agg['upstream_ws_fail_count'] ?? 0)))
        . $line('relay_pump_sessions', (string) ((int) ($agg['relay_pump_starts'] ?? 0)))
        . $line('frame_pump_active', (string) ($merged['frame_pump_active'] ?? 'unknown'))
        . $line('transport_healthy', $transportHealthy ? 'yes' : 'no')
        . $line('session_ready', (string) ($merged['session_ready_merged'] ?? 'unknown'))
        . $line('live_display', !empty($detail['live_display']) ? 'yes' : 'no')
        . $line('final_failure_reason', $failureReason !== '' ? $failureReason : 'none')
        . $line('ended_at_utc', $ended)
        . $line('aggregate_source', 'full_file_scan_plus_last_browser_snapshot');

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
}

/**
 * Persist shell abandonment reason for next injected PLAN (iLO).
 */
function ipmiKvmShellAbandonPersist(mysqli $mysqli, string $token, string $reason): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($reason): void {
        $meta['kvm_shell_abandon'] = [
            'v'      => 1,
            'reason' => $reason,
            'ts'     => time(),
        ];
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
        return 'transport_healthy';
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

/**
 * iLO: record server-side shell path abandonment + BUG lines + session meta.
 */
function ipmiProxyIloAbandonShellPath(mysqli $mysqli, string $token, string $bugCode, string $bmcPath = ''): void
{
    ipmiKvmBugLogAppendBug($bugCode, 'Shell KVM path abandoned', $bmcPath);
    ipmiKvmBugLogAppendSection('SERVER', 'event: shell_path_abandoned_for_application | code: ' . $bugCode);
    ipmiKvmShellAbandonPersist($mysqli, $token, $bugCode);
}

function ipmiProxyIloShouldAbandonShellPath(array $session): bool
{
    $m = $session['session_meta']['kvm_shell_abandon'] ?? null;

    return is_array($m) && !empty($m['reason']);
}

function ipmiKvmBugLogBrowserBeaconEndpoint(): string
{
    return '/ipmi_kvm_buglog_ingest.php';
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
