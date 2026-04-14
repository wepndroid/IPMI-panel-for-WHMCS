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
    $ev = strtolower((string) ($payload['event'] ?? ''));
    $noisyBrowser = in_array($ev, ['shell_launch_no_effect', 'ilo_starthtml5irc_no_effect'], true);
    $browserDedupeKey = $noisyBrowser ? ipmiKvmBugLogCanonicalEventKey('BROWSER', $ev, '') : '';
    $me = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $evDedupe = is_array($me['kvm_buglog_dedupe']['events'] ?? null) ? $me['kvm_buglog_dedupe']['events'] : [];
    $skipBrowserLine = $browserDedupeKey !== '' && isset($evDedupe[$browserDedupeKey]);
    if (!$skipBrowserLine) {
        ipmiKvmBugLogAppendSection($section, $line);
    }
    if ($browserDedupeKey !== '') {
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($browserDedupeKey): void {
            $d = is_array($meta['kvm_buglog_dedupe'] ?? null) ? $meta['kvm_buglog_dedupe'] : ['v' => 1, 'events' => []];
            $evMap = is_array($d['events'] ?? null) ? $d['events'] : [];
            if (!isset($evMap[$browserDedupeKey])) {
                $evMap[$browserDedupeKey] = ['first_ts' => time(), 'last_ts' => time(), 'count' => 1];
            } else {
                $evMap[$browserDedupeKey]['count'] = (int) ($evMap[$browserDedupeKey]['count'] ?? 0) + 1;
                $evMap[$browserDedupeKey]['last_ts'] = time();
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
    $shellPathVerdicts = [
        'shell_abandonment_loop',
        'shell_runtime_reinjected_after_abandon',
        'shell_path_failed_not_promoted',
        'application_promotion_not_committed',
    ];
    if (in_array($verdict, $shellPathVerdicts, true)) {
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
function ipmiKvmFinalizeRunSummary(array $payload): void
{
    ipmiKvmBugLogPatchFinalBlock($payload);
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
    $resolved = ipmiKvmComputeFinalVerdict($agg, $merged, $verdict !== '' ? $verdict : 'pending');
    if (($resolved['source'] ?? '') === 'aggregate_file' && ($resolved['verdict'] ?? '') !== '') {
        $verdict = (string) $resolved['verdict'];
    }
    $transportHealthy = ipmiKvmBugLogDeriveFinalTransportHealthy($agg, $merged, $verdict);
    $ended = gmdate('c') . 'Z';
    $failureReason = trim((string) ($detail['final_failure_reason'] ?? $detail['reason'] ?? $detail['transport_why'] ?? ''));
    $shellPathVerdicts = [
        'shell_abandonment_loop',
        'shell_runtime_reinjected_after_abandon',
        'shell_path_failed_not_promoted',
        'application_promotion_not_committed',
    ];
    if ($failureReason === '') {
        if (!$transportHealthy && $verdict === 'transport_unhealthy_console_not_confirmed') {
            $failureReason = 'no_sustained_relay_frame_flow_or_transport_unstable';
        } elseif (in_array($verdict, $shellPathVerdicts, true)) {
            $failureReason = 'kvm_shell_path_not_resolved_before_end:' . $verdict;
        }
    }
    $failureReason = substr($failureReason, 0, 400);

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
