<?php

function ipmiProxyIsHealthPollPath(string $bmcPath): bool
{
    $p = strtolower($bmcPath);

    return str_contains($p, '/json/health') || str_contains($p, 'health_summary');
}

function ipmiProxyIsIloRuntimeApiPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }

    return str_starts_with($p, '/json/')
        || str_starts_with($p, '/api/')
        || str_starts_with($p, '/rest/')
        || str_starts_with($p, '/sse/');
}

function ipmiProxyIsIloEventStreamPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));

    return $p !== '' && str_starts_with($p, '/sse/');
}

/**
 * Named HTML fragments (legacy allowlist — broader detection uses heuristics + context).
 */
function ipmiProxyIloRuntimeFragmentPathNamed(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }
    $fragments = [
        '/html/masthead.html',
        '/html/sidebar.html',
        '/html/footer.html',
        '/html/login_message.html',
        '/html/session_timeout.html',
    ];
    if (in_array($p, $fragments, true)) {
        return true;
    }

    return str_contains($p, 'masthead') && str_ends_with($p, '.html');
}

/**
 * Full application / heavy HTML pages — never treat as small bootstrap fragments.
 */
function ipmiProxyIloHtmlFragmentPathStrictExclude(string $pLower): bool
{
    if ($pLower === '' || !str_starts_with($pLower, '/html/') || !str_ends_with($pLower, '.html')) {
        return true;
    }
    $bn = basename($pLower);
    if (preg_match('/^(application|index|login|summary|redirect|health|kvm|console)\\b/i', $bn)) {
        return true;
    }
    if (preg_match('/java_irc|jnlp|rc_info|remote_console|virtual_media|video|license|legal|help(_|\\.|$)|about\\./i', $pLower)) {
        return true;
    }

    return false;
}

/**
 * @param array<string, mixed> $context bootstrap_state?, observed?, shell_ts?, trace?
 * @return array{score: int, reasons: list<string>}
 */
function ipmiProxyIloHtmlFragmentHeuristicScore(string $bmcPath, array $context): array
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $reasons = [];
    $score = 0;
    if ($p === '' || ipmiProxyIloHtmlFragmentPathStrictExclude($p)) {
        return ['score' => 0, 'reasons' => ['excluded_or_invalid']];
    }
    if (!str_starts_with($p, '/html/') || !str_ends_with($p, '.html')) {
        return ['score' => 0, 'reasons' => ['not_html_fragment_path']];
    }
    $bn = basename($p, '.html');
    $score += 22;
    $reasons[] = 'under_html';
    if (strlen($bn) <= 36 && preg_match('/(?:^|_)(?:nav|bar|head|pane|frag|partial|widget|menu|tile|card|drawer|panel|snippet|include|toolbar|breadcrumb|masthead|sidebar|footer|header)(?:_|$)/i', $bn)) {
        $score += 28;
        $reasons[] = 'fragment_like_name';
    } elseif (preg_match('/(?:fragment|partial|widget|snippet|include|masthead|sidebar|navbar|statusbar)/i', $bn)) {
        $score += 24;
        $reasons[] = 'bootstrap_keyword';
    } elseif (strlen($bn) <= 24 && !str_contains($bn, '_') && $bn !== 'page' && $bn !== 'main') {
        $score += 8;
        $reasons[] = 'short_basename';
    }
    $st = is_array($context['bootstrap_state'] ?? null) ? $context['bootstrap_state'] : [];
    $shellTs = (int) ($st['shell_ts'] ?? $context['shell_ts'] ?? 0);
    $now = time();
    if ($shellTs > 0 && $now - $shellTs < 120) {
        $score += 18;
        $reasons[] = 'post_shell_window';
    }
    if (ipmiProxyIloIsWithinBootstrapWindow($st)) {
        $score += 12;
        $reasons[] = 'bootstrap_window';
    }
    $obs = is_array($st['observed'] ?? null) ? $st['observed'] : [];
    $paths = is_array($obs['paths'] ?? null) ? $obs['paths'] : [];
    if (!empty($paths[$p]['promoted'])) {
        $score += 35;
        $reasons[] = 'observed_promoted';
    } elseif (isset($paths[$p]) && (int) ($paths[$p]['hits'] ?? 0) >= 2) {
        $score += 15;
        $reasons[] = 'observed_repeat';
    }
    $phase = (string) ($st['phase'] ?? '');
    if (in_array($phase, ['bootstrapping', 'degraded', 'stalled'], true)) {
        $score += 8;
        $reasons[] = 'phase_not_healthy';
    }

    return ['score' => min(100, $score), 'reasons' => $reasons];
}

/**
 * Reasons that indicate the path shape is fragment-like or session-learned, not merely "any /html/*.html soon after shell".
 *
 * @param list<string> $reasons
 */
function ipmiProxyIloHtmlFragmentHeuristicHasStructuralSignal(array $reasons): bool
{
    static $sig = [
        'fragment_like_name',
        'bootstrap_keyword',
        'short_basename',
        'observed_repeat',
        'observed_promoted',
    ];
    foreach ($reasons as $r) {
        if (in_array($r, $sig, true)) {
            return true;
        }
    }

    return false;
}

function ipmiProxyIloShouldTreatHtmlFragmentAsBootstrapCritical(string $bmcPath, array $context): bool
{
    if (ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)) {
        return true;
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (ipmiProxyIloHtmlFragmentPathStrictExclude($p)) {
        return false;
    }
    $h = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, $context);
    if ($h['score'] < 52) {
        return false;
    }

    return ipmiProxyIloHtmlFragmentHeuristicHasStructuralSignal($h['reasons']);
}

/**
 * Path-only recoverability hint for /html/*.html (no session). Bounded; excludes heavy pages.
 */
function ipmiProxyIloHtmlFragmentRecoverableHeuristic(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (ipmiProxyIloHtmlFragmentPathStrictExclude($p)) {
        return false;
    }
    if (!str_starts_with($p, '/html/') || !str_ends_with($p, '.html')) {
        return false;
    }
    $h = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, []);

    return $h['score'] >= 36;
}

function ipmiProxyIloLooksLikeBootstrapHtmlFragment(string $bmcPath, array $context = []): bool
{
    return ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)
        || ipmiProxyIloShouldTreatHtmlFragmentAsBootstrapCritical($bmcPath, $context);
}

function ipmiProxyIloLooksLikeBootstrapApi(string $bmcPath, array $context = []): bool
{
    unset($context);
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '' || ipmiProxyIsHealthPollPath($bmcPath)) {
        return false;
    }

    return str_starts_with($p, '/json/') || str_starts_with($p, '/api/') || str_starts_with($p, '/rest/');
}

function ipmiProxyIloIsWithinBootstrapWindow(array $state): bool
{
    $shellTs = (int) ($state['shell_ts'] ?? 0);
    if ($shellTs <= 0) {
        return false;
    }
    $age = time() - $shellTs;
    if ($age < 120) {
        return true;
    }
    $phase = (string) ($state['phase'] ?? '');

    return $age < 300 && in_array($phase, ['bootstrapping', 'degraded', 'stalled'], true);
}

/** @param array<string, mixed> $session */
function ipmiProxyIloPathContextFromSession(array $session): array
{
    $state = ipmiProxyIloBootstrapStateLoad($session);

    return [
        'bootstrap_state' => $state,
        'shell_ts'        => (int) ($state['shell_ts'] ?? 0),
    ];
}

/**
 * Cached KVM launch plan from session DB metadata (if present).
 *
 * @return array<string, mixed>
 */
function ipmiProxyIloKvmPlanFromSession(array $session): array
{
    $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $kp = $meta['kvm_plan'] ?? null;

    return is_array($kp) && is_array($kp['plan'] ?? null) ? $kp['plan'] : [];
}

/**
 * Narrow allowlist: HTML routes that are not primary bootstrap fragments but travel with native HTML5 console.
 */
function ipmiProxyIloLooksLikeSecondaryConsoleHelper(string $path): bool
{
    $p = strtolower((string) parse_url($path, PHP_URL_PATH));
    static $helpers = [
        '/html/jnlp_template.html',
    ];

    return in_array($p, $helpers, true);
}

/**
 * Relative weight for secondary-helper health signals (kept small vs masthead/session_info).
 */
function ipmiProxyIloSecondaryHelperWeight(string $path): float
{
    $p = strtolower((string) parse_url($path, PHP_URL_PATH));
    if ($p === '/html/jnlp_template.html') {
        return 0.22;
    }

    return 0.0;
}

/**
 * Inspect KVM plan + bootstrap phase for proven HTML5-native console (strict gate for secondary-helper promotion).
 *
 * @param array<string, mixed> $bootstrapState from ipmiProxyIloBootstrapStateLoad
 * @return array{active: bool, match: string, verdict: string, strategy: string, vendor_family: string, phase: string}
 */
function ipmiProxyIloActiveNativeConsoleContextDetail(array $session, array $bootstrapState = []): array
{
    $plan = ipmiProxyIloKvmPlanFromSession($session);
    $verdict = (string) ($plan['ilo_native_console_verdict'] ?? '');
    $strategy = (string) ($plan['launch_strategy'] ?? '');
    $fam = (string) ($plan['vendor_family'] ?? '');
    $phase = (string) ($bootstrapState['phase'] ?? '');
    $match = '';
    if ($verdict === 'native_html5_available') {
        $match = 'verdict_native_html5_available';
    } elseif ($strategy === 'ilo_application_force_html5') {
        $match = 'strategy_ilo_application_force_html5';
    }
    $active = $match !== '' && $phase !== 'stalled';
    if ($fam !== '' && $fam !== 'ilo') {
        $active = false;
        $match = $match !== '' ? 'blocked_non_ilo_plan_family' : '';
    }

    return [
        'active' => $active,
        'match'          => $match,
        'verdict'        => $verdict,
        'strategy'       => $strategy,
        'vendor_family'  => $fam,
        'phase'          => $phase,
    ];
}

/**
 * True when the session model already shows proven/native HTML5 console intent and bootstrap is not stalled.
 *
 * @param array<string, mixed> $bootstrapState from ipmiProxyIloBootstrapStateLoad
 */
function ipmiProxyIloHasActiveNativeConsoleContext(array $session, array $bootstrapState = []): bool
{
    return ipmiProxyIloActiveNativeConsoleContextDetail($session, $bootstrapState)['active'];
}

/**
 * Gated promotion: known secondary helpers only, and only with active native-console context.
 *
 * @param array<string, mixed> $bootstrapState
 * @param array<string, mixed>|null $plan unused; reserved for callers that already loaded the plan
 */
function ipmiProxyIloShouldPromoteSecondaryConsoleHelper(
    string $bmcPath,
    array $session,
    array $bootstrapState,
    ?array $plan = null
): bool {
    unset($plan);
    if (!ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        return false;
    }
    if (ipmiProxyIloSecondaryHelperWeight($bmcPath) <= 0.0) {
        return false;
    }

    return ipmiProxyIloHasActiveNativeConsoleContext($session, $bootstrapState);
}

/**
 * Increment lightweight secondary-helper counters in the bootstrap window (does not affect phase classification).
 *
 * @param array<string, mixed> $window
 * @return array<string, mixed>
 */
function ipmiProxyIloBootstrapRegisterSecondarySignal(array $window, string $outcome): array
{
    $w = $window;
    if ($outcome === 'ok') {
        $w['sec_helper_ok'] = min(8, (int) ($w['sec_helper_ok'] ?? 0) + 1);
    } elseif (str_starts_with($outcome, 'fail')) {
        $w['sec_helper_fail'] = min(5, (int) ($w['sec_helper_fail'] ?? 0) + 1);
    }

    return $w;
}

/**
 * Default iLO final-stage console readiness bucket (server-side proxy observations only; browser is authoritative for transport).
 *
 * @return array<string, mixed>
 */
function ipmiProxyIloConsoleReadinessDefaults(): array
{
    return [
        'v'                       => 1,
        'updated_ts'              => 0,
        'helper_seen'             => 0,
        'helper_ok'               => 0,
        'helper_fail'             => 0,
        'helper_last_path'        => '',
        'helper_last_outcome'     => '',
        'application_html_ok'     => 0,
        'stuck_escalation_count'  => 0,
        'stuck_escalation_ts'     => 0,
        'proxy_transport_hint'    => 0,
        'proxy_session_hint'      => 0,
    ];
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloConsoleReadinessStateLoad(array $session): array
{
    $raw = $session['session_meta']['ilo_console_readiness'] ?? null;
    if (!is_array($raw) || (int) ($raw['v'] ?? 0) < 1) {
        return ipmiProxyIloConsoleReadinessDefaults();
    }

    return array_merge(ipmiProxyIloConsoleReadinessDefaults(), $raw);
}

function ipmiProxyIloConsoleReadinessStateStore(mysqli $mysqli, string $token, array &$session, array $state, string $traceId): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state['updated_ts'] = time();
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $meta['ilo_console_readiness'] = $state;
        $prevBrowser = is_array($meta['ilo_native_console_confirmation']['browser'] ?? null)
            ? $meta['ilo_native_console_confirmation']['browser'] : [];
        $wrap = ['session_meta' => $meta];
        $newConf = ipmiWebIloNativeConsoleConfirmation($wrap, []);
        if ($prevBrowser !== []) {
            $newConf['browser'] = $prevBrowser;
        }
        $meta['ilo_native_console_confirmation'] = $newConf;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_console_readiness'] = $state;
    $prevBrowserMem = is_array($session['session_meta']['ilo_native_console_confirmation']['browser'] ?? null)
        ? $session['session_meta']['ilo_native_console_confirmation']['browser'] : [];
    $session['session_meta']['ilo_native_console_confirmation'] = ipmiWebIloNativeConsoleConfirmation($session, []);
    if ($prevBrowserMem !== []) {
        $session['session_meta']['ilo_native_console_confirmation']['browser'] = $prevBrowserMem;
    }
    if (ipmiProxyDebugEnabled() && $traceId !== '') {
        $conf = is_array($session['session_meta']['ilo_native_console_confirmation'] ?? null)
            ? $session['session_meta']['ilo_native_console_confirmation'] : [];
        ipmiProxyDebugLog('ilo_console_readiness_server_updated', [
            'trace'                       => $traceId,
            'verdict'                     => ipmiProxyIloConsoleReadinessVerdict($state),
            'native_console_debug_verdict'=> (string) ($conf['final_debug_verdict'] ?? ''),
        ]);
    }
}

/**
 * @param array<string, mixed> $event types: startup_helper, application_html
 * @return array<string, mixed>
 */
function ipmiProxyIloConsoleReadinessUpdate(array $state, array $event): array
{
    $s = $state;
    $t = (string) ($event['type'] ?? '');
    if ($t === 'startup_helper') {
        $s['helper_seen'] = (int) ($s['helper_seen'] ?? 0) + 1;
        $s['helper_last_path'] = (string) ($event['path'] ?? '');
        $s['helper_last_outcome'] = (string) ($event['outcome'] ?? '');
        if (!empty($event['ok'])) {
            $s['helper_ok'] = (int) ($s['helper_ok'] ?? 0) + 1;
            $s['proxy_session_hint'] = 1;
        } else {
            $s['helper_fail'] = (int) ($s['helper_fail'] ?? 0) + 1;
        }
    }
    if ($t === 'application_html') {
        $s['application_html_ok'] = !empty($event['ok']) ? 1 : 0;
    }

    return $s;
}

function ipmiProxyIloConsoleReadinessVerdict(array $state): string
{
    $hok = (int) ($state['helper_ok'] ?? 0);
    $hfail = (int) ($state['helper_fail'] ?? 0);
    $seen = (int) ($state['helper_seen'] ?? 0);
    if ($hfail >= 1 && $hok === 0 && $seen >= 1) {
        return 'console_start_failed_no_session_ready';
    }
    if ($hok >= 1) {
        return 'startup_helper_http_ok';
    }

    return 'console_starting';
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloConsoleReadinessDebugSnapshot(array $session): array
{
    $st = ipmiProxyIloConsoleReadinessStateLoad($session);
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $conf = ipmiWebIloNativeConsoleConfirmation($session, []);
    $capSnap = is_array($session['session_meta']['ilo_console_capability']['data'] ?? null)
        ? $session['session_meta']['ilo_console_capability']['data'] : [];

    return [
        'verdict_server'           => ipmiProxyIloFinalizeConsoleStartupStatus($st),
        'helper_seen'            => (int) ($st['helper_seen'] ?? 0),
        'helper_ok'              => (int) ($st['helper_ok'] ?? 0),
        'helper_fail'            => (int) ($st['helper_fail'] ?? 0),
        'helper_last'            => (string) ($st['helper_last_path'] ?? ''),
        'transport_proxy_hint'   => ipmiProxyIloHasTransportEvidence($st) ? 1 : 0,
        'session_ready_proxy_hint' => ipmiProxyIloHasSessionReadyEvidence($st) ? 1 : 0,
        'launch_discovery_verdict' => ipmiProxyIloLaunchDiscoveryVerdict($ld),
        'launch_discovery_readiness' => ipmiProxyIloLaunchDiscoveryReadinessVerdict($session, []),
        'launch_helper_seen'     => (int) ($ld['helper_seen'] ?? 0),
        'launch_helper_ok'       => (int) ($ld['helper_ok'] ?? 0),
        'speculative_shell_hint' => (int) ($ld['speculative_shell_hint'] ?? 0),
        'native_console_tier'    => (string) ($conf['tier'] ?? ''),
        'native_console_debug_verdict' => (string) ($conf['final_debug_verdict'] ?? ''),
        'native_console_confidence' => (int) ($conf['confidence'] ?? 0),
        'capability_server_hint' => (string) ($capSnap['capability'] ?? ''),
        'live_display_note'      => 'browser_authoritative; server snapshot excludes live canvas',
    ];
}

/**
 * Evaluate strict native-console confirmation from a flat signal map (browser overlay and/or server hints).
 *
 * @param array<string, mixed> $signals
 * @return array<string, mixed>
 */
function ipmiProxyIloNativeConsoleConfirmationFromSignals(array $signals): array
{
    return ipmiWebIloNativeConsoleTierEvaluate($signals);
}

/**
 * @param array<string, mixed> $confirmation from ipmiWebIloNativeConsoleTierEvaluate / ipmiProxyIloNativeConsoleConfirmationFromSignals
 */
function ipmiProxyIloNativeConsoleVerdict(array $confirmation): string
{
    return (string) ($confirmation['final_debug_verdict'] ?? 'native_console_not_confirmed');
}

/**
 * @param array<string, mixed> $readiness ipmi_console_readiness state
 * @param array<string, mixed> $discovery ilo_launch_discovery state
 * @return array<string, mixed>
 */
function ipmiProxyIloFinalizeConfirmationFromReadiness(array $readiness, array $discovery): array
{
    $signals = [
        'transport_started_server'   => !empty($readiness['proxy_transport_hint']),
        'session_ready_server'       => ((int) ($readiness['helper_ok'] ?? 0) >= 1) || !empty($readiness['proxy_session_hint']),
        'launch_path_reached_server' => (int) ($readiness['application_html_ok'] ?? 0) >= 1,
        'bootstrap_helper_ok'        => ((int) ($readiness['helper_ok'] ?? 0) >= 1),
        'launch_action_triggered'    => ((int) ($discovery['launch_discovery_esc'] ?? 0) >= 1)
            || !empty($discovery['helper_seen']),
    ];

    return ipmiWebIloNativeConsoleTierEvaluate($signals);
}

/**
 * @param array<string, mixed> $confirmation
 */
function ipmiProxyIloCanUpgradeToStrongConfirmation(array $confirmation): bool
{
    $final = (string) ($confirmation['final_debug_verdict'] ?? '');

    return $final === 'native_console_strongly_confirmed';
}

/**
 * Read capability blob only (feature existence — not per-attempt confirmation).
 *
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyIloCapabilityStateLoad(array $session): array
{
    $raw = $session['session_meta']['ilo_console_capability'] ?? null;
    if (!is_array($raw)) {
        return ['v' => 0, 'data' => []];
    }

    return $raw;
}

/**
 * @param array<string, mixed> $session
 * @param array<string, mixed> $capState ilo_console_capability wrapper
 */
function ipmiProxyIloCapabilityStateStore(mysqli $mysqli, string $token, array &$session, array $capState): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($capState): void {
        $meta['ilo_console_capability'] = $capState;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_console_capability'] = $capState;
}

/**
 * Persist strict confirmation snapshot (does not replace capability state).
 *
 * @param array<string, mixed> $confirmation full tier array
 */
function ipmiProxyIloConfirmationStateStore(mysqli $mysqli, string $token, array &$session, array $confirmation): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $confirmation['updated_ts'] = time();
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($confirmation): void {
        $meta['ilo_native_console_confirmation'] = $confirmation;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_native_console_confirmation'] = $confirmation;
}

/** Thin alias for ipmiProxyIloConsoleReadinessStateStore (readiness separate from capability/confirmation). */
function ipmiProxyIloReadinessStateStore(mysqli $mysqli, string $token, array &$session, array $state, string $traceId): void
{
    ipmiProxyIloConsoleReadinessStateStore($mysqli, $token, $session, $state, $traceId);
}

function ipmiProxyIloShouldRejectShellAsConsoleSuccess(string $bmcPath, array $confirmation): bool
{
    if (!ipmiWebIloLooksLikeManagementShellPath($bmcPath)) {
        return false;
    }

    return ($confirmation['final_debug_verdict'] ?? '') !== 'native_console_strongly_confirmed';
}

/**
 * Server cannot see the BMC framebuffer; use browser-reported signals when available.
 *
 * @param array<string, mixed> $browserSignals
 */
function ipmiProxyIloLooksLikeLiveConsoleSurface(array $browserSignals): bool
{
    return !empty($browserSignals['live_display']) || !empty($browserSignals['live_display_confirmed']);
}

function ipmiProxyIloConsoleStartupRequestRole(string $bmcPath): string
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '/html/jnlp_template.html') {
        return 'console_startup_helper';
    }

    return 'other';
}

/**
 * Server-side hints only (browser WebSocket / canvas signals are authoritative).
 *
 * @param array<string, mixed> $readinessState
 */
function ipmiProxyIloHasTransportEvidence(array $readinessState): bool
{
    return !empty($readinessState['proxy_transport_hint']);
}

/**
 * @param array<string, mixed> $readinessState
 */
function ipmiProxyIloHasSessionReadyEvidence(array $readinessState): bool
{
    return (int) ($readinessState['helper_ok'] ?? 0) >= 1
        || !empty($readinessState['proxy_session_hint']);
}

function ipmiProxyIloFinalizeConsoleStartupStatus(array $state): string
{
    return ipmiProxyIloConsoleReadinessVerdict($state);
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloRegisterConsoleStartupSignal(array $state, string $bmcPath, bool $ok, string $outcome): array
{
    if (ipmiProxyIloConsoleStartupRequestRole($bmcPath) !== 'console_startup_helper') {
        return $state;
    }

    return ipmiProxyIloConsoleReadinessUpdate($state, [
        'type'    => 'startup_helper',
        'path'    => $bmcPath,
        'ok'      => $ok,
        'outcome' => $outcome,
    ]);
}

/** @param array<string, mixed> $browserReport */
function ipmiProxyIloLoadingStateDetected(array $browserReport): bool
{
    return !empty($browserReport['loading_text'])
        || !empty($browserReport['loading_spinner'])
        || !empty($browserReport['loading_dom']);
}

function ipmiProxyIloLoadingStateTooLong(int $sinceMs, int $thresholdMs = 12000): bool
{
    return $sinceMs >= $thresholdMs;
}

/**
 * @param array<string, mixed> $readinessState
 */
function ipmiProxyIloShouldEscalateStuckLoading(array $readinessState, bool $rendererSeen, bool $transportSeen, int $loadingMs): bool
{
    return $rendererSeen
        && !$transportSeen
        && $loadingMs >= 28000
        && ipmiProxyIloCanEscalateStuckLoading($readinessState);
}

/**
 * @param array<string, mixed> $readinessState
 */
function ipmiProxyIloCanEscalateStuckLoading(array $readinessState): bool
{
    return (int) ($readinessState['stuck_escalation_count'] ?? 0) < 1;
}

/**
 * @param array<string, mixed> $readinessState
 * @return array<string, mixed>
 */
function ipmiProxyIloEscalateStuckLoadingOnce(array $readinessState): array
{
    if (!ipmiProxyIloCanEscalateStuckLoading($readinessState)) {
        return $readinessState;
    }
    $readinessState['stuck_escalation_count'] = 1;
    $readinessState['stuck_escalation_ts'] = time();

    return $readinessState;
}

/**
 * @param array<string, mixed> $readinessState
 * @return array<string, mixed>
 */
function ipmiProxyIloRecordStuckLoadingEscalation(array $readinessState): array
{
    return ipmiProxyIloEscalateStuckLoadingOnce($readinessState);
}

/**
 * Shell→console launch discovery (server-side correlation; browser events are authoritative).
 *
 * @return array<string, mixed>
 */
function ipmiProxyIloLaunchDiscoveryDefaults(): array
{
    return [
        'v' => 1,
        'updated_ts'                => 0,
        'helper_seen'               => 0,
        'helper_ok'                 => 0,
        'helper_fail'               => 0,
        'helper_last_path'          => '',
        'launch_discovery_esc'      => 0,
        'speculative_shell_hint'    => 0,
        'final_discovery_verdict'   => '',
        'discovery_failed_at'       => 0,
        'discovery_failure_detail'  => '',
    ];
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloLaunchDiscoveryStateLoad(array $session): array
{
    $raw = $session['session_meta']['ilo_launch_discovery'] ?? null;
    if (!is_array($raw) || (int) ($raw['v'] ?? 0) < 1) {
        return ipmiProxyIloLaunchDiscoveryDefaults();
    }

    return array_merge(ipmiProxyIloLaunchDiscoveryDefaults(), $raw);
}

function ipmiProxyIloLaunchDiscoveryStateStore(mysqli $mysqli, string $token, array &$session, array $state, string $traceId): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state['updated_ts'] = time();
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $meta['ilo_launch_discovery'] = $state;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_launch_discovery'] = $state;
    if (ipmiProxyDebugEnabled() && $traceId !== '') {
        ipmiProxyDebugLog('ilo_launch_discovery_server_updated', [
            'trace'   => $traceId,
            'verdict' => ipmiProxyIloLaunchDiscoveryVerdict($state),
        ]);
    }
}

/**
 * @param array<string, mixed> $event
 * @return array<string, mixed>
 */
function ipmiProxyIloLaunchDiscoveryUpdate(array $state, array $event): array
{
    $s = $state;
    $t = (string) ($event['type'] ?? '');
    if ($t === 'launch_helper') {
        $s['helper_seen'] = (int) ($s['helper_seen'] ?? 0) + 1;
        $s['helper_last_path'] = (string) ($event['path'] ?? '');
        if (!empty($event['ok'])) {
            $s['helper_ok'] = (int) ($s['helper_ok'] ?? 0) + 1;
        } else {
            $s['helper_fail'] = (int) ($s['helper_fail'] ?? 0) + 1;
        }
    }

    return $s;
}

function ipmiProxyIloLaunchDiscoveryVerdict(array $state): string
{
    $fv = (string) ($state['final_discovery_verdict'] ?? '');
    if ($fv !== '') {
        return $fv;
    }
    $seen = (int) ($state['helper_seen'] ?? 0);
    $ok = (int) ($state['helper_ok'] ?? 0);
    $fail = (int) ($state['helper_fail'] ?? 0);
    if ($seen >= 1 && $ok === 0 && $fail >= 1) {
        return 'launch_helper_seen_but_no_http_ok';
    }
    if ($ok >= 1) {
        return 'launch_helper_http_observed';
    }

    return 'launch_discovery_unknown';
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloRegisterLaunchHelperSignal(array $state, string $bmcPath, bool $ok, string $outcome): array
{
    if (!ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        return $state;
    }

    return ipmiProxyIloLaunchDiscoveryUpdate($state, [
        'type'    => 'launch_helper',
        'path'    => $bmcPath,
        'ok'      => $ok,
        'outcome' => $outcome,
    ]);
}

function ipmiProxyIloNoLaunchTargetFound(array $browserHints): bool
{
    return !empty($browserHints['launch_discovery_failed']) || !empty($browserHints['no_launch_target']);
}

function ipmiProxyIloFinalizeDiscoveryFailure(string $reason, array $browserHints = []): array
{
    return [
        'verdict'       => 'launch_discovery_failed',
        'reason'        => $reason,
        'browser_hints' => $browserHints,
    ];
}

function ipmiProxyIloCanEscalateLaunchDiscovery(array $state): bool
{
    return (int) ($state['launch_discovery_esc'] ?? 0) < 1;
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloEscalateLaunchDiscoveryOnce(array $state): array
{
    if (!ipmiProxyIloCanEscalateLaunchDiscovery($state)) {
        return $state;
    }
    $state['launch_discovery_esc'] = 1;

    return $state;
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloRecordLaunchDiscoveryEscalation(array $state): array
{
    return ipmiProxyIloEscalateLaunchDiscoveryOnce($state);
}

function ipmiProxyIloHelperPathAidedLaunchDiscovery(array $session): bool
{
    $s = ipmiProxyIloLaunchDiscoveryStateLoad($session);

    return (int) ($s['helper_ok'] ?? 0) >= 1;
}

/**
 * @param array<string, mixed> $readiness
 * @param array<string, mixed> $discovery
 */
function ipmiProxyIloFinalizeReadinessFromDiscovery(array $readiness, array $discovery): string
{
    $d = ipmiProxyIloLaunchDiscoveryVerdict($discovery);
    if ($d === 'launch_helper_seen_but_no_http_ok') {
        return 'launch_helper_seen_but_no_target_found';
    }
    if ($d === 'launch_helper_http_observed') {
        return 'launch_helper_aided_pending_browser';
    }

    return ipmiProxyIloConsoleReadinessVerdict($readiness);
}

/**
 * Promote a narrow set of transport-shaped /html routes when native HTML5 is already proven — not bootstrap-critical.
 *
 * @param array<string, mixed> $final role row from ipmiProxyClassifyIloPathRole + contextualize
 * @param array<string, mixed> $bootstrapState
 * @return array<string, mixed>
 */
function ipmiProxyIloApplySecondaryConsoleHelperPathRole(
    array $final,
    string $bmcPath,
    array $session,
    array $bootstrapState,
    string $traceId
): array {
    $baseRole = (string) ($final['base_role'] ?? '');
    $curRole = (string) ($final['role'] ?? '');
    if ($curRole !== 'transport_related' || $baseRole !== 'transport_related') {
        return $final;
    }
    if (!ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        return $final;
    }

    $ctxDetail = ipmiProxyIloActiveNativeConsoleContextDetail($session, $bootstrapState);
    $ctxActive = $ctxDetail['active'];
    if (ipmiProxyDebugEnabled() && $traceId !== '') {
        ipmiProxyDebugLog('ilo_secondary_helper_context_check', [
            'trace'          => $traceId,
            'bmcPath'        => $bmcPath,
            'context_active' => $ctxActive ? 1 : 0,
            'ctx_match'      => (string) ($ctxDetail['match'] ?? ''),
            'verdict'        => (string) ($ctxDetail['verdict'] ?? ''),
            'strategy'       => (string) ($ctxDetail['strategy'] ?? ''),
            'vendor_family'  => (string) ($ctxDetail['vendor_family'] ?? ''),
            'phase'          => (string) ($ctxDetail['phase'] ?? ''),
        ]);
    }

    if (!$ctxActive) {
        if (ipmiProxyDebugEnabled() && $traceId !== '') {
            $skipReason = 'native_console_context_not_active';
            if ((string) ($ctxDetail['match'] ?? '') === 'blocked_non_ilo_plan_family') {
                $skipReason = 'plan_vendor_family_not_ilo';
            } elseif ((string) ($ctxDetail['phase'] ?? '') === 'stalled') {
                $skipReason = 'bootstrap_phase_stalled';
            } elseif ($ctxDetail['match'] === '' && ipmiProxyIloKvmPlanFromSession($session) === []) {
                $skipReason = 'kvm_plan_missing_in_session';
            } elseif ($ctxDetail['match'] === '') {
                $skipReason = 'no_verdict_or_force_html5_strategy';
            }
            ipmiProxyDebugLog('ilo_secondary_helper_promotion_skipped', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
                'reason'  => $skipReason,
            ]);
        }

        return $final;
    }

    $w = ipmiProxyIloSecondaryHelperWeight($bmcPath);
    if ($w <= 0.0) {
        if (ipmiProxyDebugEnabled() && $traceId !== '') {
            ipmiProxyDebugLog('ilo_secondary_helper_guardrail_applied', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
                'reason'  => 'zero_weight',
            ]);
        }

        return $final;
    }

    $out = $final;
    $out['role'] = 'secondary_console_helper';
    $out['bootstrap_critical'] = false;
    $out['recoverable'] = false;
    $out['debug_class'] = 'secondary_native_console_helper';
    $out['flags'] = is_array($out['flags'] ?? null) ? $out['flags'] : [];
    $out['flags']['secondary_native_console_helper'] = true;
    $out['flags']['legacy_named_helper_in_html5_flow'] = true;
    $out['secondary_helper_weight'] = $w;

    if (ipmiProxyDebugEnabled() && $traceId !== '') {
        ipmiProxyDebugLog('ilo_secondary_helper_context_active', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
        ]);
        ipmiProxyDebugLog('ilo_secondary_console_helper_detected', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
            'weight'  => $w,
        ]);
        if (strtolower((string) parse_url($bmcPath, PHP_URL_PATH)) === '/html/jnlp_template.html') {
            ipmiProxyDebugLog('ilo_jnlp_template_promoted', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
            ]);
        }
        ipmiProxyDebugLog('ilo_secondary_helper_role_finalized', [
            'trace'            => $traceId,
            'bmcPath'          => $bmcPath,
            'from_base'        => $baseRole,
            'final_role'       => $out['role'],
            'weight'           => $w,
            'promotion_reason' => 'active_native_console_context',
            'ctx_match'        => (string) ($ctxDetail['match'] ?? ''),
        ]);
    }

    return $out;
}

/**
 * @param array<string, mixed> $baseRole from ipmiProxyClassifyIloPathRole inner
 * @param array<string, mixed> $state
 * @param array<string, mixed> $requestContext path, heuristic breakdown, trace
 * @return array<string, mixed>
 */
function ipmiProxyIloContextualizePathRole(array $baseRole, array $state, array $requestContext): array
{
    $out = $baseRole;
    $out['base_role'] = (string) ($baseRole['role'] ?? '');
    $out['flags'] = is_array($baseRole['flags'] ?? null) ? $baseRole['flags'] : [];
    $out['flags']['context_elevated'] = false;
    $bmcPath = (string) ($requestContext['bmcPath'] ?? '');
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $trace = (string) ($requestContext['trace'] ?? '');
    if (($baseRole['role'] ?? '') !== 'transport_related' || !str_starts_with($p, '/html/') || !str_ends_with($p, '.html')) {
        return $out;
    }
    $ctx = [
        'bootstrap_state' => $state,
        'shell_ts'        => (int) ($state['shell_ts'] ?? 0),
    ];
    $h = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, $ctx);
    $out['heuristic_score'] = $h['score'];
    $out['heuristic_reasons'] = $h['reasons'];
    $promoted = false;
    $obs = is_array($state['observed'] ?? null) ? $state['observed'] : [];
    $paths = is_array($obs['paths'] ?? null) ? $obs['paths'] : [];
    if (!empty($paths[$p]['promoted'])) {
        $promoted = true;
    }
    $structural = ipmiProxyIloHtmlFragmentHeuristicHasStructuralSignal($h['reasons']);
    $elevate = $promoted
        || ($structural && ($h['score'] >= 52 || ($h['score'] >= 44 && ipmiProxyIloIsWithinBootstrapWindow($state))));
    if (!$elevate) {
        if (ipmiProxyDebugEnabled() && $trace !== '') {
            ipmiProxyDebugLog('ilo_html_fragment_heuristic_negative', [
                'trace'   => $trace,
                'bmcPath' => $bmcPath,
                'score'   => $h['score'],
            ]);
            ipmiProxyDebugLog('ilo_path_role_not_elevated_after_context_check', [
                'trace'   => $trace,
                'bmcPath' => $bmcPath,
                'score'   => $h['score'],
            ]);
        }

        return $out;
    }
    $out['role'] = $h['score'] >= 58 || $promoted ? 'bootstrap_critical' : 'runtime_fragment';
    $out['bootstrap_critical'] = true;
    $out['recoverable'] = true;
    $out['debug_class'] = 'helper_fragment';
    $out['flags']['html_heuristic'] = true;
    $out['flags']['context_elevated'] = true;
    if ($promoted) {
        $out['flags']['promoted_observed'] = true;
    }
    if (ipmiProxyDebugEnabled() && $trace !== '') {
        ipmiProxyDebugLog('ilo_html_fragment_heuristic_positive', [
            'trace'   => $trace,
            'bmcPath' => $bmcPath,
            'score'   => $h['score'],
            'reasons' => $h['reasons'],
        ]);
        ipmiProxyDebugLog('ilo_path_role_elevated_by_context', [
            'trace' => $trace,
            'bmcPath'  => $bmcPath,
            'score'    => $h['score'],
            'promoted' => $promoted ? 1 : 0,
            'role'     => $out['role'],
        ]);
        ipmiProxyDebugLog('ilo_bootstrap_html_fragment_detected', [
            'trace'   => $trace,
            'bmcPath' => $bmcPath,
            'score'   => $h['score'],
        ]);
        if ($out['role'] === 'bootstrap_critical') {
            ipmiProxyDebugLog('ilo_html_fragment_promoted_to_bootstrap_critical', [
                'trace'   => $trace,
                'bmcPath' => $bmcPath,
                'via'     => $promoted ? 'observed' : 'heuristic',
            ]);
        }
    }

    return $out;
}

/**
 * @return array<string, mixed>
 */
function ipmiProxyIloObservedPathsNormalize(array $obs, int $now = 0): array
{
    if (!is_array($obs) || (int) ($obs['v'] ?? 0) !== 1) {
        return ['v' => 1, 'paths' => []];
    }
    if ($now <= 0) {
        $now = time();
    }
    $paths = is_array($obs['paths'] ?? null) ? $obs['paths'] : [];
    foreach ($paths as $k => $row) {
        if (!is_array($row)) {
            unset($paths[$k]);
            continue;
        }
        if ($now - (int) ($row['last'] ?? 0) > 600) {
            unset($paths[$k]);
        }
    }
    if (count($paths) > 12) {
        $paths = array_slice($paths, -12, 12, true);
    }

    return ['v' => 1, 'paths' => $paths];
}

/**
 * @param array<string, mixed> $state
 * @return array<string, mixed>
 */
function ipmiProxyIloRecordObservedBootstrapPath(array $state, string $pathKey, bool $wasCritical, bool $outcomeOk): array
{
    $now = time();
    $state['observed'] = ipmiProxyIloObservedPathsNormalize($state['observed'] ?? [], $now);
    $paths = &$state['observed']['paths'];
    if (!isset($paths[$pathKey])) {
        $paths[$pathKey] = ['first' => $now, 'hits' => 0, 'promoted' => 0, 'last' => $now, 'ok' => 0, 'fail' => 0];
    }
    $paths[$pathKey]['hits'] = (int) ($paths[$pathKey]['hits'] ?? 0) + 1;
    $paths[$pathKey]['last'] = $now;
    if ($outcomeOk) {
        $paths[$pathKey]['ok'] = (int) ($paths[$pathKey]['ok'] ?? 0) + 1;
    } else {
        $paths[$pathKey]['fail'] = (int) ($paths[$pathKey]['fail'] ?? 0) + 1;
    }
    if ($wasCritical && (int) $paths[$pathKey]['hits'] >= 2 && ipmiProxyIloIsWithinBootstrapWindow($state)) {
        if (empty($paths[$pathKey]['promoted'])) {
            $promoCount = 0;
            foreach ($paths as $row) {
                if (is_array($row) && !empty($row['promoted'])) {
                    $promoCount++;
                }
            }
            if ($promoCount >= 8) {
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_observed_path_promotion_skipped', [
                        'path' => $pathKey,
                        'reason'=> 'max_promoted_paths',
                    ]);
                    ipmiProxyDebugLog('ilo_bootstrap_recovery_guardrail_applied', [
                        'rule' => 'observed_promotion_cap',
                    ]);
                }
            } else {
                $paths[$pathKey]['promoted'] = 1;
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_observed_path_promoted', ['path' => $pathKey, 'hits' => (int) $paths[$pathKey]['hits']]);
                    ipmiProxyDebugLog('ilo_path_promoted_by_observation', ['path' => $pathKey]);
                }
            }
        }
    }
    foreach ($paths as $k => $row) {
        if (!is_array($row)) {
            unset($paths[$k]);
            continue;
        }
        if ($now - (int) ($row['last'] ?? 0) > 600) {
            unset($paths[$k]);
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_observed_path_expired', ['path' => $k]);
            }
        }
    }
    if (count($paths) > 12) {
        $paths = array_slice($paths, -12, 12, true);
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_observed_path_recorded', [
            'path'    => $pathKey,
            'critical'=> $wasCritical ? 1 : 0,
            'ok'      => $outcomeOk ? 1 : 0,
        ]);
    }

    return $state;
}

/**
 * Small HTML fragments the iLO SPA loads during bootstrap (not full application pages).
 * With optional $context (bootstrap_state), includes heuristic/promoted HTML helpers.
 */
function ipmiProxyIsIloRuntimeFragmentPath(string $bmcPath, array $context = []): bool
{
    if (ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)) {
        return true;
    }
    if ($context !== [] && ipmiProxyIloShouldTreatHtmlFragmentAsBootstrapCritical($bmcPath, $context)) {
        return true;
    }

    return false;
}

/**
 * Use for semantic HTML checks when session context is unavailable (path-only heuristic).
 */
function ipmiProxyIloIsHtmlFragmentForSemanticCheck(string $bmcPath): bool
{
    if (ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)) {
        return true;
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (ipmiProxyIloHtmlFragmentPathStrictExclude($p)) {
        return false;
    }

    return str_starts_with($p, '/html/') && str_ends_with($p, '.html')
        && ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, [])['score'] >= 40;
}

function ipmiProxyIsIloBootstrapPath(string $bmcPath): bool
{
    return ipmiProxyIsIloRuntimeApiPath($bmcPath) || ipmiProxyIsIloRuntimeFragmentPath($bmcPath);
}

/**
 * Paths where a failed transport or 401/403/502 likely indicates stale iLO session — safe to try one auth refresh + retry.
 */
function ipmiProxyIsIloRecoverableRuntimePath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }
    if (str_starts_with($p, '/json/')
        || str_starts_with($p, '/sse/')
        || str_starts_with($p, '/api/')
        || str_starts_with($p, '/rest/')) {
        return true;
    }

    return ipmiProxyIsIloRuntimeFragmentPath($bmcPath)
        || ipmiProxyIloHtmlFragmentRecoverableHeuristic($bmcPath);
}

function ipmiProxyIsIloSpaShellEntryPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));

    return in_array($p, ['/index.html', '/html/application.html', '/html/index.html'], true);
}

/**
 * Authoritative iLO path roles for bootstrap / recovery / debug (normalized iLO only at call sites).
 *
 * $context may include bootstrap_state, shell_ts, trace (for debug), accept_header (reserved).
 * Narrow "secondary_console_helper" roles (legacy-named helpers during proven HTML5 flow) are applied
 * only in ipmiProxyClassifyIloPathRoleForSession via ipmiProxyIloApplySecondaryConsoleHelperPathRole.
 *
 * @param array<string, mixed> $context
 * @return array<string, mixed>
 */
function ipmiProxyClassifyIloPathRole(string $bmcPath, string $method = 'GET', array $context = []): array
{
    unset($method);
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $pathKey = $p !== '' ? $p : '/';
    $trace = (string) ($context['trace'] ?? '');
    $fragCtx = $context;
    if (isset($context['bootstrap_state']) && is_array($context['bootstrap_state'])) {
        $fragCtx = array_merge($context, [
            'bootstrap_state' => $context['bootstrap_state'],
            'shell_ts'        => (int) ($context['bootstrap_state']['shell_ts'] ?? 0),
        ]);
    }
    $base = [
        'role'               => 'noncritical',
        'bootstrap_critical' => false,
        'recoverable'        => false,
        'debug_class'        => 'other',
        'path_key'           => $pathKey,
        'flags'              => [
            'html_heuristic'     => false,
            'promoted_observed'  => false,
            'context_elevated'   => false,
            'api_bootstrap'      => false,
        ],
        'heuristic_score'      => 0,
        'heuristic_reasons'  => [],
        'base_role'          => 'noncritical',
    ];
    if ($p === '') {
        return $base;
    }
    if (ipmiProxyIsBmcStaticAssetPath($bmcPath)) {
        if (ipmiProxyDebugEnabled() && $trace !== '') {
            ipmiProxyDebugLog('ilo_path_excluded_as_static_asset', ['trace' => $trace, 'bmcPath' => $bmcPath]);
        }
        $base['role'] = 'static_asset';
        $base['base_role'] = 'static_asset';

        return $base;
    }
    if (ipmiProxyIsIloSpaShellEntryPath($bmcPath)) {
        $base['role'] = 'shell_entry';
        $base['base_role'] = 'shell_entry';
        $base['bootstrap_critical'] = true;

        return $base;
    }
    if (ipmiProxyIsIloEventStreamPath($bmcPath)) {
        $base['role'] = 'event_stream';
        $base['base_role'] = 'event_stream';
        $base['bootstrap_critical'] = true;
        $base['recoverable'] = true;
        $base['debug_class'] = 'event_stream';

        return $base;
    }
    if (ipmiProxyIsIloRuntimeFragmentPath($bmcPath, $fragCtx)) {
        $h = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, $fragCtx);
        $base['role'] = 'runtime_fragment';
        $base['base_role'] = 'runtime_fragment';
        $base['bootstrap_critical'] = true;
        $base['recoverable'] = true;
        $base['debug_class'] = 'helper_fragment';
        $base['heuristic_score'] = $h['score'];
        $base['heuristic_reasons'] = $h['reasons'];
        if ($h['score'] >= 40 && !ipmiProxyIloRuntimeFragmentPathNamed($bmcPath)) {
            $base['flags']['html_heuristic'] = true;
        }

        return $base;
    }
    if (str_starts_with($p, '/json/') || str_starts_with($p, '/api/') || str_starts_with($p, '/rest/')) {
        if (ipmiProxyIsHealthPollPath($bmcPath)) {
            $base['role'] = 'noncritical';
            $base['base_role'] = 'noncritical';
            $base['debug_class'] = 'runtime_api';

            return $base;
        }
        $base['role'] = 'runtime_api';
        $base['base_role'] = 'runtime_api';
        $base['bootstrap_critical'] = true;
        $base['recoverable'] = true;
        $base['debug_class'] = 'runtime_api';
        $base['flags']['api_bootstrap'] = true;
        if (ipmiProxyDebugEnabled() && $trace !== '') {
            ipmiProxyDebugLog('ilo_bootstrap_api_detected', ['trace' => $trace, 'bmcPath' => $bmcPath]);
        }

        return $base;
    }
    if (str_starts_with($p, '/html/') && str_ends_with($p, '.html')) {
        $base['role'] = 'transport_related';
        $base['base_role'] = 'transport_related';

        return $base;
    }
    $base['base_role'] = 'noncritical';

    return $base;
}

/**
 * Classify with session bootstrap state + contextual elevation + debug summary.
 *
 * @return array<string, mixed>
 */
function ipmiProxyClassifyIloPathRoleForSession(
    mysqli $mysqli,
    string $token,
    array &$session,
    string $bmcPath,
    string $method,
    string $traceId
): array {
    if (!ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))) {
        return ipmiProxyClassifyIloPathRole($bmcPath, $method, []);
    }
    $ctx = ipmiProxyIloPathContextFromSession($session);
    $ctx['trace'] = $traceId;
    $state = is_array($ctx['bootstrap_state'] ?? null) ? $ctx['bootstrap_state'] : [];
    if (ipmiProxyIloIsWithinBootstrapWindow($state) && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_context_window_active', [
            'trace'    => $traceId,
            'shell_ts' => (int) ($state['shell_ts'] ?? 0),
            'phase'    => (string) ($state['phase'] ?? ''),
        ]);
    }
    $base = ipmiProxyClassifyIloPathRole($bmcPath, $method, $ctx);
    $base['base_role'] = (string) ($base['base_role'] ?? $base['role']);
    $final = $base;
    if ($state !== []) {
        $final = ipmiProxyIloContextualizePathRole($base, $state, [
            'bmcPath' => $bmcPath,
            'trace'   => $traceId,
        ]);
    }
    $final = ipmiProxyIloApplySecondaryConsoleHelperPathRole($final, $bmcPath, $session, $state, $traceId);
    if (ipmiProxyDebugEnabled()) {
        $ctxSnap = ipmiProxyIloActiveNativeConsoleContextDetail($session, $state);
        $secPromo = 'n/a';
        if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
            if (($final['role'] ?? '') === 'secondary_console_helper') {
                $secPromo = 'promoted';
            } elseif (($final['base_role'] ?? '') === 'transport_related' && ($final['role'] ?? '') === 'transport_related') {
                $secPromo = $ctxSnap['active'] ? 'invariant_transport_despite_active_ctx' : 'skipped_no_native_context';
            } else {
                $secPromo = 'skipped_role_not_transport';
            }
        }
        ipmiProxyDebugLog('ilo_role_heuristic_summary', [
            'trace'                 => $traceId,
            'bmcPath'               => $bmcPath,
            'base_role'             => (string) ($final['base_role'] ?? ''),
            'final_role'            => (string) ($final['role'] ?? ''),
            'bootstrap_crit'        => !empty($final['bootstrap_critical']) ? 1 : 0,
            'heuristic_score'       => (int) ($final['heuristic_score'] ?? 0),
            'heuristic_reasons'     => $final['heuristic_reasons'] ?? [],
            'flags'                 => $final['flags'] ?? [],
            'secondary_w'           => (float) ($final['secondary_helper_weight'] ?? 0.0),
            'native_console_context'=> $ctxSnap['active'] ? 1 : 0,
            'native_ctx_match'      => (string) ($ctxSnap['match'] ?? ''),
            'secondary_promotion'   => $secPromo,
        ]);
        ipmiProxyDebugLog('ilo_bootstrap_role_finalized', [
            'trace'      => $traceId,
            'bmcPath'    => $bmcPath,
            'final_role' => (string) ($final['role'] ?? ''),
        ]);
    }
    if (
        ($final['base_role'] ?? '') === 'transport_related'
        && ($final['role'] ?? '') === 'transport_related'
        && str_starts_with(strtolower((string) parse_url($bmcPath, PHP_URL_PATH)), '/html/')
        && !ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)
        && ipmiProxyIloIsWithinBootstrapWindow($state)
        && ipmiProxyDebugEnabled()
    ) {
        $hs = ipmiProxyIloHtmlFragmentHeuristicScore($bmcPath, [
            'bootstrap_state' => $state,
            'shell_ts'        => (int) ($state['shell_ts'] ?? 0),
        ]);
        ipmiProxyDebugLog('ilo_path_missed_as_bootstrap_critical', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
            'score'   => $hs['score'],
        ]);
    }

    return $final;
}

/** @return array<string, mixed> */
function ipmiProxyIloBootstrapStateLoad(array $session): array
{
    $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $raw = $meta['ilo_bootstrap'] ?? null;
    if (!is_array($raw) || ($raw['v'] ?? 0) !== 1) {
        return ipmiProxyIloBootstrapStateDefaults();
    }
    $now = time();
    if (($raw['updated_at'] ?? 0) > 0 && $now - (int) $raw['updated_at'] > 3600) {
        return ipmiProxyIloBootstrapStateDefaults();
    }
    $raw['events'] = is_array($raw['events'] ?? null) ? array_slice($raw['events'], -24) : [];
    $raw['refresh_ts'] = is_array($raw['refresh_ts'] ?? null) ? $raw['refresh_ts'] : [];
    $raw['sse'] = is_array($raw['sse'] ?? null) ? $raw['sse'] : ipmiProxyIloBootstrapStateDefaults()['sse'];
    if (!isset($raw['shell_ts'])) {
        $raw['shell_ts'] = 0;
    }
    $raw['observed'] = ipmiProxyIloObservedPathsNormalize($raw['observed'] ?? [], $now);
    $raw['phase'] = ipmiProxyIloBootstrapStateClassify($raw);

    return $raw;
}

/** @return array<string, mixed> */
function ipmiProxyIloBootstrapStateDefaults(): array
{
    return [
        'v'          => 1,
        'updated_at' => 0,
        'phase'      => 'fresh',
        'events'     => [],
        'sse'        => ['last' => '', 'fail_streak' => 0, 'last_ts' => 0, 'ok_after_refresh' => 0],
        'refresh_ts' => [],
        'window'     => ['t0' => time(), 'crit_ok' => 0, 'crit_fail' => 0, 'soft_fail' => 0, 'shell_ok' => 0, 'roles_ok' => '', 'sec_helper_ok' => 0, 'sec_helper_fail' => 0],
        'shell_ts'   => 0,
        'observed'   => ['v' => 1, 'paths' => []],
    ];
}

function ipmiProxyIloBootstrapStateClassify(array $state): string
{
    $sse = is_array($state['sse'] ?? null) ? $state['sse'] : [];
    $failStreak = (int) ($sse['fail_streak'] ?? 0);
    $w = is_array($state['window'] ?? null) ? $state['window'] : [];
    $critOk = (int) ($w['crit_ok'] ?? 0);
    $critFail = (int) ($w['crit_fail'] ?? 0);
    $softFail = (int) ($w['soft_fail'] ?? 0);
    $shellOk = (int) ($w['shell_ok'] ?? 0);
    $rolesCsv = (string) ($w['roles_ok'] ?? '');
    $distinctRoles = count(array_filter(array_unique(array_filter(explode(',', $rolesCsv)))));

    if ($shellOk > 0 && $critOk >= 2 && $failStreak < 2 && $critFail <= 1 && $softFail <= 2
        && ($distinctRoles >= 2 || $critOk >= 3)) {
        return 'healthy';
    }
    if ($shellOk > 0 && ($critFail >= 3 || $failStreak >= 2 || ($softFail >= 3 && $critOk < 2))) {
        return 'stalled';
    }
    if ($critFail >= 1 || $softFail >= 2 || $failStreak >= 1) {
        return 'degraded';
    }
    if ($shellOk > 0 || $critOk > 0) {
        return 'bootstrapping';
    }

    return 'fresh';
}

function ipmiProxyIloBootstrapLooksStalled(array $state): bool
{
    return ($state['phase'] ?? '') === 'stalled';
}

function ipmiProxyIloBootstrapLooksHealthy(array $state): bool
{
    return ($state['phase'] ?? '') === 'healthy';
}

/** @return array<string, mixed> */
function ipmiProxyIloBootstrapDebugSnapshot(array $session): array
{
    $s = ipmiProxyIloBootstrapStateLoad($session);
    $sse = is_array($s['sse'] ?? null) ? $s['sse'] : [];
    $rts = is_array($s['refresh_ts'] ?? null) ? $s['refresh_ts'] : [];
    $now = time();

    $evs = is_array($s['events'] ?? null) ? $s['events'] : [];
    $lastEv = $evs !== [] ? $evs[count($evs) - 1] : [];

    $w = is_array($s['window'] ?? null) ? $s['window'] : [];

    return [
        'phase'            => (string) ($s['phase'] ?? ''),
        'sse_last'         => (string) ($sse['last'] ?? ''),
        'sse_fail_streak'  => (int) ($sse['fail_streak'] ?? 0),
        'refresh_60s'      => count(array_filter($rts, static fn ($t) => $t > $now - 60)),
        'sec_helper_ok'    => (int) ($w['sec_helper_ok'] ?? 0),
        'sec_helper_fail'  => (int) ($w['sec_helper_fail'] ?? 0),
        'blank_ui_hypothesis' => ipmiProxyIloBootstrapBlankUiHypothesis($s),
        'last_event_outcome'  => is_array($lastEv) ? (string) ($lastEv['outcome'] ?? '') : '',
        'last_event_path'     => is_array($lastEv) ? (string) ($lastEv['path'] ?? '') : '',
    ];
}

/** @param array<string, mixed> $state */
function ipmiProxyIloBootstrapLastCriticalHint(array $state): string
{
    $evs = is_array($state['events'] ?? null) ? $state['events'] : [];
    for ($i = count($evs) - 1; $i >= 0; $i--) {
        $e = $evs[$i];
        if (!is_array($e) || empty($e['critical'])) {
            continue;
        }
        $out = (string) ($e['outcome'] ?? '');
        $path = (string) ($e['path'] ?? '');
        $role = (string) ($e['role'] ?? '');
        if ($out === 'fail_soft_auth' || str_starts_with($out, 'fail_soft')) {
            if ($role === 'runtime_fragment' || str_contains($path, 'masthead')) {
                return 'fragment_mismatch';
            }

            return 'soft_auth_response';
        }
        if ($out === 'fail_hard_auth') {
            return 'auth_drift';
        }
        if ($out === 'fail_http' || $out === 'fail_transport' || $out === 'fail_hard_transport') {
            return 'transport_failure';
        }
    }

    return '';
}

function ipmiProxyIloBootstrapBlankUiHypothesis(array $state): string
{
    $phase = (string) ($state['phase'] ?? '');
    $sse = is_array($state['sse'] ?? null) ? $state['sse'] : [];
    if (($sse['fail_streak'] ?? 0) >= 2 && $phase !== 'healthy') {
        return 'sse_instability';
    }
    if ($phase === 'stalled') {
        return 'bootstrap_stall';
    }
    if ($phase === 'degraded') {
        return 'bootstrap_degraded';
    }
    if (($sse['last'] ?? '') === 'fail_auth') {
        return 'auth_drift';
    }
    $hint = ipmiProxyIloBootstrapLastCriticalHint($state);
    if ($hint !== '') {
        return $hint;
    }

    return 'unknown_or_transient';
}

/**
 * @param array<string, mixed> $event
 * @return array<string, mixed>
 */
function ipmiProxyIloBootstrapStateUpdate(array $state, array $event): array
{
    $now = time();
    $state['updated_at'] = $now;
    $evs = is_array($state['events'] ?? null) ? $state['events'] : [];
    $event['t'] = $now;
    $evs[] = $event;
    $state['events'] = array_slice($evs, -24);

    $w = is_array($state['window'] ?? null) ? $state['window'] : ['t0' => $now, 'crit_ok' => 0, 'crit_fail' => 0, 'soft_fail' => 0, 'shell_ok' => 0, 'roles_ok' => '', 'sec_helper_ok' => 0, 'sec_helper_fail' => 0];
    if ($now - (int) ($w['t0'] ?? $now) > 75) {
        $w = ['t0' => $now, 'crit_ok' => 0, 'crit_fail' => 0, 'soft_fail' => 0, 'shell_ok' => 0, 'roles_ok' => '', 'sec_helper_ok' => 0, 'sec_helper_fail' => 0];
    }
    $role = (string) ($event['role'] ?? '');
    $critical = !empty($event['critical']);
    $outcome = (string) ($event['outcome'] ?? '');
    if ($role === 'shell_entry' && $outcome === 'ok') {
        $w['shell_ok'] = (int) $w['shell_ok'] + 1;
        $state['shell_ts'] = $now;
    }
    if ($critical) {
        if ($outcome === 'ok') {
            $w['crit_ok'] = (int) $w['crit_ok'] + 1;
            if ($role !== '' && $role !== 'shell_entry') {
                $rlist = array_values(array_filter(explode(',', (string) ($w['roles_ok'] ?? ''))));
                if (!in_array($role, $rlist, true)) {
                    $rlist[] = $role;
                    $w['roles_ok'] = implode(',', array_slice($rlist, -6));
                }
            }
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_bootstrap_positive_signal_registered', [
                    'role' => $role,
                    'path' => (string) ($event['path'] ?? ''),
                ]);
            }
        } elseif (str_starts_with($outcome, 'fail_soft') || str_contains($outcome, 'soft')) {
            $w['crit_fail'] = (int) $w['crit_fail'] + 1;
            $w['soft_fail'] = (int) $w['soft_fail'] + 1;
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_bootstrap_negative_signal_registered', [
                    'role'   => $role,
                    'path'   => (string) ($event['path'] ?? ''),
                    'outcome'=> $outcome,
                ]);
            }
        } elseif (str_starts_with($outcome, 'fail')) {
            $w['crit_fail'] = (int) $w['crit_fail'] + 1;
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_bootstrap_negative_signal_registered', [
                    'role'   => $role,
                    'path'   => (string) ($event['path'] ?? ''),
                    'outcome'=> $outcome,
                ]);
            }
        }
    }
    if ($role === 'secondary_console_helper') {
        $w = ipmiProxyIloBootstrapRegisterSecondarySignal($w, $outcome);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_secondary_helper_health_signal', [
                'role'            => $role,
                'path'            => (string) ($event['path'] ?? ''),
                'outcome'         => $outcome,
                'sec_helper_ok'   => (int) ($w['sec_helper_ok'] ?? 0),
                'sec_helper_fail' => (int) ($w['sec_helper_fail'] ?? 0),
            ]);
        }
    }
    $state['window'] = $w;
    $prevPhase = (string) ($state['phase'] ?? '');
    $state['phase'] = ipmiProxyIloBootstrapStateClassify($state);
    if (ipmiProxyDebugEnabled() && (string) ($state['phase'] ?? '') !== $prevPhase) {
        ipmiProxyDebugLog('ilo_bootstrap_health_recomputed', [
            'phase'      => (string) ($state['phase'] ?? ''),
            'phase_prev' => $prevPhase,
        ]);
    }

    return $state;
}

function ipmiProxyIloBootstrapStateStore(mysqli $mysqli, string $token, array &$session, array $state, string $traceId, string $logEvent = 'ilo_bootstrap_state_updated'): void
{
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, $logEvent);
}

function ipmiProxyIloBootstrapStatePersist(mysqli $mysqli, string $token, array &$session, array $state, string $traceId, string $logEvent): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $prevPhase = is_array($session['session_meta']['ilo_bootstrap'] ?? null)
        ? (string) ($session['session_meta']['ilo_bootstrap']['phase'] ?? '') : '';
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $meta['ilo_bootstrap'] = $state;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_bootstrap'] = $state;
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog($logEvent, [
            'trace' => $traceId,
            'phase'       => (string) ($state['phase'] ?? ''),
            'phase_prev'  => $prevPhase,
        ]);
        $ph = (string) ($state['phase'] ?? '');
        if ($ph === 'healthy') {
            ipmiProxyDebugLog('ilo_bootstrap_state_healthy', ['trace' => $traceId]);
        } elseif ($ph === 'stalled') {
            ipmiProxyDebugLog('ilo_bootstrap_state_stalled', ['trace' => $traceId]);
        } elseif ($ph === 'degraded') {
            ipmiProxyDebugLog('ilo_bootstrap_state_degraded', ['trace' => $traceId]);
        }
    }
}

/**
 * @param array{kind: string, reason: string} $decision
 */
function ipmiProxyIloBootstrapCanRefresh(array $state, array $decision): bool
{
    $now = time();
    $ts = is_array($state['refresh_ts'] ?? null) ? $state['refresh_ts'] : [];
    $ts = array_values(array_filter($ts, static fn ($t) => $t > $now - 60));
    if (count($ts) >= 3) {
        $kind = (string) ($decision['kind'] ?? '');
        $reason = (string) ($decision['reason'] ?? '');
        if ($kind !== 'hard') {
            return false;
        }

        return str_contains($reason, 'http_401')
            || str_contains($reason, 'sse_')
            || str_contains($reason, 'sse_precheck')
            || str_contains($reason, 'bootstrap_preflight')
            || str_contains($reason, 'shell_preflight');
    }
    if (count($ts) >= 2 && ($decision['kind'] ?? '') === 'soft'
        && (($state['phase'] ?? '') === 'stalled' || ($state['phase'] ?? '') === 'degraded')) {
        return false;
    }

    return true;
}

/**
 * @param array<string, mixed> $state
 * @return array<string, mixed>
 */
function ipmiProxyIloBootstrapRegisterRefresh(array $state): array
{
    $now = time();
    $ts = is_array($state['refresh_ts'] ?? null) ? $state['refresh_ts'] : [];
    $ts[] = $now;
    $state['refresh_ts'] = array_values(array_filter($ts, static fn ($t) => $t > $now - 90));

    return $state;
}

/** @param array{kind: string, reason: string} $decision */
function ipmiProxyIloCanAttemptAnotherRefresh(array $state, array $decision): bool
{
    return ipmiProxyIloBootstrapCanRefresh($state, $decision);
}

/**
 * Reserve a refresh slot in bootstrap metadata before calling the BMC relogin (parallel SPA bursts).
 *
 * @param array<string, mixed> $state
 * @return array<string, mixed>
 */
function ipmiProxyIloBootstrapBeginRefreshBudget(
    mysqli $mysqli,
    string $token,
    array &$session,
    array $state,
    string $traceId
): array {
    $state = ipmiProxyIloBootstrapRegisterRefresh($state);
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, 'ilo_refresh_attempt_recorded');

    return $state;
}

/**
 * Record whether a refresh attempt actually fixed auth state (after BeginRefreshBudget).
 *
 * @param array<string, mixed> $state
 * @return array<string, mixed>
 */
function ipmiProxyIloRecordRefreshAttempt(
    mysqli $mysqli,
    string $token,
    array &$session,
    array $state,
    bool $refreshSucceeded,
    string $traceId
): array {
    $state = ipmiProxyIloBootstrapStateUpdate($state, [
        'role'     => 'auth_refresh',
        'critical' => false,
        'outcome'  => $refreshSucceeded ? 'ok_refresh' : 'fail_refresh',
        'path'     => '/_ilo_refresh/',
    ]);
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, 'ilo_bootstrap_state_updated');

    return $state;
}

/**
 * @param array<string, mixed> $requestContext path_role, shell_entry (bool)
 * @param array<string, mixed> $responseContext soft_auth (bool), http (int)
 */
function ipmiProxyIloBootstrapShouldRefreshAuth(array $state, array $requestContext, array $responseContext): bool
{
    $phase = (string) ($state['phase'] ?? '');
    if (!empty($requestContext['shell_entry']) && in_array($phase, ['stalled', 'degraded'], true)) {
        return true;
    }
    if (!empty($responseContext['soft_auth']) && $phase === 'degraded') {
        return true;
    }
    if (!empty($responseContext['soft_auth']) && $phase === 'stalled') {
        return true;
    }

    return false;
}

/** @param array<string, mixed>|null $sseFailure */
function ipmiProxyIloSseLooksRecoverable(array $sseFailure): bool
{
    if ($sseFailure === null || $sseFailure === []) {
        return false;
    }

    return !empty($sseFailure['auth_rejected'])
        || (isset($sseFailure['curl_errno']) && (int) $sseFailure['curl_errno'] !== 0)
        || !empty($sseFailure['sse_recoverable_http']);
}

function ipmiProxyIloRuntimeJsonLooksSemanticallyBroken(string $bmcPath, string $body): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (!str_starts_with($p, '/json/')) {
        return false;
    }
    $t = trim($body);
    if ($t === '' || ($t[0] !== '{' && $t[0] !== '[')) {
        return str_starts_with($p, '/json/session_info');
    }
    $j = json_decode($t, true);
    if (!is_array($j)) {
        return true;
    }
    if (str_contains($p, 'session_info')) {
        $keys = array_map('strtolower', array_keys($j));
        $hints = ['session', 'user', 'username', 'lang', 'mpmodel', 'build', 'serial', 'oh_type', 'features'];
        foreach ($hints as $h) {
            foreach ($keys as $k) {
                if (str_contains($k, $h)) {
                    return false;
                }
            }
        }

        return count($j) <= 2;
    }

    return false;
}

function ipmiProxyIloApiJsonPlaceholderBroken(string $body, string $pLower): bool
{
    $t = trim($body);
    if ($t === '{}' || $t === '[]' || strcasecmp($t, 'null') === 0) {
        return str_contains($pLower, 'session') || str_contains($pLower, 'login')
            || str_contains($pLower, 'masthead') || str_contains($pLower, 'host_power');
    }

    return false;
}

function ipmiProxyIloApiResponseLooksBootstrapBroken(string $bmcPath, string $contentType, string $body): bool
{
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    if (!str_contains($ct, 'json')) {
        return false;
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (ipmiProxyIsHealthPollPath($bmcPath)) {
        return false;
    }
    if (!str_starts_with($p, '/json/') && !str_starts_with($p, '/api/') && !str_starts_with($p, '/rest/')) {
        return false;
    }
    if (ipmiProxyIloRuntimeJsonLooksSemanticallyBroken($bmcPath, $body)) {
        return true;
    }

    return ipmiProxyIloApiJsonPlaceholderBroken($body, $p);
}

function ipmiProxyIloResponseLooksLikeUnexpectedFullShell(string $bmcPath, string $contentType, string $body): bool
{
    if (!ipmiProxyIloIsHtmlFragmentForSemanticCheck($bmcPath)) {
        return false;
    }
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    if (!str_contains($ct, 'html')) {
        return false;
    }
    if (strlen($body) < 65000) {
        return false;
    }
    $head = strtolower(substr($body, 0, 14000));
    if (str_contains($head, 'masthead') || str_contains($head, 'sidebar')
        || str_contains($head, 'nav-container') || str_contains($head, 'fragment')
        || str_contains($head, 'widget-pane')) {
        return false;
    }

    return str_contains($head, '<html');
}

function ipmiProxyIloFragmentLooksWrong(string $bmcPath, string $contentType, string $body): bool
{
    return ipmiProxyIloIsHtmlFragmentForSemanticCheck($bmcPath)
        && ipmiProxyIloBootstrapResponseLooksWrong($bmcPath, $contentType, $body);
}

function ipmiProxyIloResponseLooksBootstrapBroken(string $bmcPath, string $contentType, string $body): bool
{
    if (ipmiProxyIloBootstrapResponseLooksWrong($bmcPath, $contentType, $body)) {
        return true;
    }
    if (ipmiProxyIloResponseLooksLikeUnexpectedFullShell($bmcPath, $contentType, $body)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_fragment_returned_full_shell', [
                'bmcPath' => $bmcPath,
            ]);
        }

        return true;
    }
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    if (str_contains($ct, 'json') && ipmiProxyIloApiResponseLooksBootstrapBroken($bmcPath, $contentType, $body)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_api_response_bootstrap_broken', [
                'bmcPath' => $bmcPath,
            ]);
        }

        return true;
    }

    return false;
}

/**
 * @param array<string, mixed>|null $sseResult
 */
function ipmiProxyIloBootstrapNoteSse(
    mysqli $mysqli,
    string $token,
    array &$session,
    bool $ok,
    bool $retriedAfterRefresh,
    ?array $sseResult,
    string $traceId
): void {
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state = ipmiProxyIloBootstrapStateLoad($session);
    $sse = is_array($state['sse'] ?? null) ? $state['sse'] : [];
    $now = time();
    if ($ok) {
        $sse['last'] = 'ok';
        $sse['fail_streak'] = 0;
        $sse['last_ts'] = $now;
        if ($retriedAfterRefresh) {
            $sse['ok_after_refresh'] = (int) ($sse['ok_after_refresh'] ?? 0) + 1;
        }
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_sse_health_positive', ['trace' => $traceId, 'retried' => $retriedAfterRefresh ? 1 : 0]);
            ipmiProxyDebugLog('ilo_bootstrap_health_positive_signal', ['trace' => $traceId, 'channel' => 'sse']);
        }
    } else {
        $auth = is_array($sseResult) && !empty($sseResult['auth_rejected']);
        $sse['last'] = $auth ? 'fail_auth' : 'fail_transport';
        $sse['fail_streak'] = (int) ($sse['fail_streak'] ?? 0) + 1;
        $sse['last_ts'] = $now;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_sse_health_negative', [
                'trace'    => $traceId,
                'auth'     => $auth ? 1 : 0,
                'retried'  => $retriedAfterRefresh ? 1 : 0,
            ]);
            ipmiProxyDebugLog('ilo_bootstrap_health_negative_signal', ['trace' => $traceId, 'channel' => 'sse']);
            if ($retriedAfterRefresh) {
                ipmiProxyDebugLog('ilo_sse_still_failing_after_refresh', ['trace' => $traceId]);
            }
        }
    }
    $state['sse'] = $sse;
    $failAuth = !$ok && is_array($sseResult) && !empty($sseResult['auth_rejected']);
    $state = ipmiProxyIloBootstrapStateUpdate($state, [
        'role'     => 'event_stream',
        'critical' => true,
        'outcome'  => $ok ? 'ok' : ($failAuth ? 'fail_soft_auth' : 'fail_hard_transport'),
        'path'     => '/sse/',
    ]);
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, 'ilo_bootstrap_state_updated');
}

/** @param array<string, mixed>|null $sseResult */
function ipmiProxyIloSseHealthUpdate(
    mysqli $mysqli,
    string $token,
    array &$session,
    bool $ok,
    bool $retriedAfterRefresh,
    ?array $sseResult,
    string $traceId
): void {
    ipmiProxyIloBootstrapNoteSse($mysqli, $token, $session, $ok, $retriedAfterRefresh, $sseResult, $traceId);
}

/**
 * @param array<string, mixed> $pathRole final role from ipmiProxyClassifyIloPathRoleForSession (or equivalent)
 */
function ipmiProxyIloBootstrapTrackBufferedResponse(
    mysqli $mysqli,
    string $token,
    array &$session,
    string $bmcPath,
    string $method,
    int $httpCode,
    string $contentType,
    string $body,
    array $pathRole,
    bool $recoveryWasAttempted,
    string $traceId
): void {
    if (!ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))) {
        return;
    }
    if (in_array($pathRole['role'], ['static_asset', 'noncritical'], true)) {
        return;
    }
    $state = ipmiProxyIloBootstrapStateLoad($session);
    $critical = !empty($pathRole['bootstrap_critical']);
    $shellLoginLike = $pathRole['role'] === 'shell_entry'
        && $httpCode >= 200 && $httpCode < 400
        && (ipmiWebResponseLooksLikeBmcLoginPage($body, $contentType) || ipmiProxyBodyHasSessionTimeout($body));
    $softFail = ipmiProxyIloIsSoftAuthFailure($bmcPath, $httpCode, $contentType, $body) || $shellLoginLike;
    $ok = $httpCode >= 200 && $httpCode < 400        && !$softFail
        && !ipmiProxyIloResponseLooksBootstrapBroken($bmcPath, $contentType, $body);
    $semanticBroken = $httpCode >= 200 && $httpCode < 400
        && $critical
        && ipmiProxyIloResponseLooksBootstrapBroken($bmcPath, $contentType, $body);
    if ($semanticBroken && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_semantic_failure_detected', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
        ]);
        if (ipmiProxyIloFragmentLooksWrong($bmcPath, $contentType, $body)) {
            ipmiProxyDebugLog('ilo_fragment_shape_unexpected', ['trace' => $traceId, 'bmcPath' => $bmcPath]);
        }
        if (ipmiProxyIloRuntimeJsonLooksSemanticallyBroken($bmcPath, $body)) {
            ipmiProxyDebugLog('ilo_runtime_json_semantically_broken', ['trace' => $traceId, 'bmcPath' => $bmcPath]);
        }
    }
    $outcome = 'ok';
    if (!$ok) {
        if ($httpCode === 401 || $httpCode === 403) {
            $outcome = 'fail_hard_auth';
        } elseif ($semanticBroken || ipmiProxyIloIsSoftAuthFailure($bmcPath, $httpCode, $contentType, $body)) {
            $outcome = 'fail_soft_auth';
        } elseif ($httpCode >= 400) {
            $outcome = 'fail_http';
        } else {
            $outcome = 'fail_transport';
        }
    }
    $state = ipmiProxyIloBootstrapStateUpdate($state, [
        'role'     => (string) $pathRole['role'],
        'critical' => $critical,
        'outcome'  => $outcome,
        'path'     => (string) $pathRole['path_key'],
        'recovery' => $recoveryWasAttempted ? 1 : 0,
    ]);
    $pathKey = (string) ($pathRole['path_key'] ?? '');
    if ($pathKey !== '') {
        $state = ipmiProxyIloRecordObservedBootstrapPath($state, $pathKey, $critical, $ok);
    }
    $phase = (string) ($state['phase'] ?? '');
    if (ipmiProxyIloBootstrapLooksStalled($state) && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_shell_loaded_spa_stalled', [
            'trace'      => $traceId,
            'bmcPath'    => $bmcPath,
            'last_event' => $outcome,
        ]);
    }
    ipmiProxyIloBootstrapStatePersist($mysqli, $token, $session, $state, $traceId, 'ilo_bootstrap_state_updated_from_role');
    $csr = ipmiProxyIloConsoleReadinessStateLoad($session);
    $csrChanged = false;
    $pathOnly = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (str_contains($pathOnly, 'application.html') && $httpCode >= 200 && $httpCode < 400 && $ok) {
        $csr = ipmiProxyIloConsoleReadinessUpdate($csr, [
            'type' => 'application_html',
            'ok'   => true,
        ]);
        $csrChanged = true;
    }
    if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        $csr = ipmiProxyIloRegisterConsoleStartupSignal($csr, $bmcPath, $ok, $outcome);
        $csrChanged = true;
        if (ipmiProxyDebugEnabled() && $traceId !== '') {
            ipmiProxyDebugLog('ilo_console_startup_helper_seen', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
                'role'    => (string) ($pathRole['role'] ?? ''),
                'ok'      => $ok ? 1 : 0,
            ]);
            if ($ok) {
                ipmiProxyDebugLog('ilo_console_startup_helper_ok', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                ]);
            } else {
                ipmiProxyDebugLog('ilo_console_startup_helper_failed', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                    'outcome' => $outcome,
                ]);
            }
        }
    }
    if ($csrChanged) {
        ipmiProxyIloConsoleReadinessStateStore($mysqli, $token, $session, $csr, $traceId);
    }
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $ldChanged = false;
    if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
        $ld = ipmiProxyIloRegisterLaunchHelperSignal($ld, $bmcPath, $ok, $outcome);
        $ldChanged = true;
        $planStrat = (string) (ipmiProxyIloKvmPlanFromSession($session)['launch_strategy'] ?? '');
        if ($planStrat === 'ilo_speculative_shell_autolaunch') {
            $ld['speculative_shell_hint'] = 1;
        }
        if (ipmiProxyDebugEnabled() && $traceId !== '') {
            ipmiProxyDebugLog('ilo_launch_helper_seen', [
                'trace'   => $traceId,
                'bmcPath' => $bmcPath,
                'ok'      => $ok ? 1 : 0,
                'strategy'=> $planStrat,
            ]);
            if ($ok) {
                ipmiProxyDebugLog('ilo_launch_helper_aided_discovery', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                ]);
            } elseif ($planStrat === 'ilo_speculative_shell_autolaunch') {
                ipmiProxyDebugLog('ilo_launch_helper_seen_but_no_target_found', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                    'outcome' => $outcome,
                    'hint'    => 'http_failed_or_soft_auth_shell_discovery_may_still_fail',
                ]);
            }
        }
    }
    if ($ldChanged) {
        ipmiProxyIloLaunchDiscoveryStateStore($mysqli, $token, $session, $ld, $traceId);
    }
    if (ipmiProxyDebugEnabled()) {
        if (ipmiProxyIloLooksLikeSecondaryConsoleHelper($bmcPath)) {
            $ctxDetail = ipmiProxyIloActiveNativeConsoleContextDetail($session, $state);
            if (!$ok && $ctxDetail['active'] && (string) ($state['phase'] ?? '') !== 'stalled') {
                ipmiProxyDebugLog('ilo_console_startup_stall_correlated', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                    'reason'  => 'helper_failed_while_native_flow_active',
                    'outcome' => $outcome,
                ]);
            }
        }
        if (($pathRole['role'] ?? '') === 'secondary_console_helper') {
            ipmiProxyDebugLog('ilo_secondary_console_helper_contributed', [
                'trace'    => $traceId,
                'bmcPath'  => $bmcPath,
                'weight'   => (float) ($pathRole['secondary_helper_weight'] ?? 0.0),
                'positive' => $ok ? 1 : 0,
                'outcome'  => $outcome,
                'sec_snap' => [
                    'sec_helper_ok'   => (int) ($state['window']['sec_helper_ok'] ?? 0),
                    'sec_helper_fail' => (int) ($state['window']['sec_helper_fail'] ?? 0),
                ],
            ]);
        }
        if ($critical) {
            ipmiProxyDebugLog('ilo_path_contributed_to_bootstrap_health', [
                'trace'    => $traceId,
                'bmcPath'  => $bmcPath,
                'role'     => (string) $pathRole['role'],
                'outcome'  => $outcome,
                'positive' => $ok ? 1 : 0,
                'flags'    => $pathRole['flags'] ?? [],
            ]);
        }
        if ($recoveryWasAttempted) {
            ipmiProxyDebugLog('ilo_bootstrap_recovery_role_used', [
                'trace'              => $traceId,
                'bmcPath'            => $bmcPath,
                'role'               => (string) $pathRole['role'],
                'bootstrap_critical' => $critical ? 1 : 0,
                'outcome'            => $outcome,
            ]);
        }
        ipmiProxyDebugLog('ilo_bootstrap_finalized', [
            'trace'     => $traceId,
            'bmcPath'   => $bmcPath,
            'phase'     => $phase,
            'outcome'   => $outcome,
            'role'      => (string) $pathRole['role'],
        ]);
    }
}

/**
 * @return 'event_stream'|'runtime_api'|'helper_fragment'|'other'
 */
function ipmiProxyIloRuntimePathDebugClass(string $bmcPath): string
{
    if (ipmiProxyIsIloEventStreamPath($bmcPath)) {
        return 'event_stream';
    }
    if (ipmiProxyIloIsHtmlFragmentForSemanticCheck($bmcPath)) {
        return 'helper_fragment';
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if (str_starts_with($p, '/json/') || str_starts_with($p, '/api/') || str_starts_with($p, '/rest/')) {
        return 'runtime_api';
    }

    return 'other';
}

/**
 * Single field for correlating blank iLO SPA shells with server-side logs.
 *
 * @param 'auth_refresh_failed'|'sse_final'|'post_retry_http'|'curl_after_recover' $mode
 * @param array{http?: int, auth_rejected?: bool, curl_errno?: int, sse_recoverable_http?: bool} $ctx
 */
function ipmiProxyIloBlankUiCause(string $bmcPath, string $mode, array $ctx = []): string
{
    $class = ipmiProxyIloRuntimePathDebugClass($bmcPath);
    if ($mode === 'auth_refresh_failed') {
        return 'auth_drift';
    }
    if ($mode === 'sse_final') {
        if (!empty($ctx['auth_rejected'])) {
            return 'auth_drift';
        }
        if (!empty($ctx['curl_errno'])) {
            return 'upstream_transport';
        }
        if (!empty($ctx['sse_recoverable_http'])) {
            return 'upstream_transport';
        }

        return 'sse_failure';
    }
    if ($mode === 'post_retry_http') {
        $http = (int) ($ctx['http'] ?? 0);
        if (in_array($http, [401, 403], true)) {
            return 'auth_drift';
        }
        if ($http === 502 || $http === 503) {
            return 'upstream_transport';
        }
        if ($class === 'helper_fragment') {
            return 'fragment_bootstrap';
        }
        if ($class === 'runtime_api') {
            return $http >= 500 ? 'upstream_transport' : 'unknown';
        }

        return 'unknown';
    }
    if ($mode === 'curl_after_recover') {
        return 'upstream_transport';
    }

    return 'unknown';
}

function ipmiProxyIloRuntimeAuthRefresh(mysqli $mysqli, string $token, array &$session, string $bmcIp, string $traceId, string $reason): bool
{
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_auth_refresh_attempt', [
            'trace'  => $traceId,
            'reason' => $reason,
        ]);
    }
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $baseUrl = $scheme . '://' . $bmcIp;
    $user = trim((string) ($session['ipmi_user'] ?? ''));
    $pass = (string) ($session['ipmi_pass'] ?? '');
    $cookies = is_array($session['cookies'] ?? null) ? $session['cookies'] : [];
    $fwd = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
    ipmiWebSyncIloSessionAndSessionKeyCookies($cookies);
    if ($user !== '' && $pass !== '') {
        ipmiWebIloEnsureSessionCookieForWebUi($baseUrl, $bmcIp, $user, $pass, $cookies, $fwd);
    }
    $session['cookies'] = $cookies;
    $session['forward_headers'] = $fwd;
    if (ipmiWebIloVerifyAuthed($baseUrl, $bmcIp, $session['cookies'], is_array($session['forward_headers']) ? $session['forward_headers'] : [])) {
        ipmiWebPersistRefreshedRuntimeAuth($mysqli, $token, $session);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_auth_refresh_success', [
                'trace' => $traceId,
                'via'   => 'session_cookie_repair',
            ]);
        }

        return true;
    }
    $session['cookies'] = [];
    $session['forward_headers'] = [];
    if (!ipmiWebAttemptAutoLogin($session, $mysqli)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_auth_refresh_failed', [
                'trace' => $traceId,
                'error' => (string) ($session['auto_login_error'] ?? ''),
            ]);
        }

        return false;
    }
    ipmiWebPersistRefreshedRuntimeAuth($mysqli, $token, $session);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_auth_refresh_success', [
            'trace' => $traceId,
            'via'   => 'full_auto_login',
        ]);
    }

    return true;
}

/**
 * Reload cookies, forward headers, scheme, and session_meta from DB after a refresh wrote them.
 */
function ipmiProxyReloadSessionRowInto(array &$session, mysqli $mysqli, string $token, string $traceId): bool
{
    $row = ipmiWebLoadSession($mysqli, $token);
    if (!$row) {
        return false;
    }
    $session['cookies'] = is_array($row['cookies'] ?? null) ? $row['cookies'] : [];
    $session['forward_headers'] = is_array($row['forward_headers'] ?? null) ? $row['forward_headers'] : [];
    $session['bmc_scheme'] = (string) ($row['bmc_scheme'] ?? 'https');
    $session['session_meta'] = is_array($row['session_meta'] ?? null) ? $row['session_meta'] : [];
    if (ipmiWebIsIloFamilyType((string) ($session['bmc_type'] ?? ''))) {
        $session['cookies'] = ipmiProxyMergeClientBmcCookies($session['cookies'], (string) ($session['bmc_type'] ?? ''));
        ipmiWebSyncIloSessionAndSessionKeyCookies($session['cookies']);
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_session_reloaded_after_refresh', ['trace' => $traceId]);
    }

    return true;
}

function ipmiProxyRebuildIloForwardHeadersFromSession(array $session, string $bmcScheme, string $bmcIp, string $bmcPathOnlyLower): array
{
    $hdr = is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : [];
    $hdr = ipmiProxyMergeClientBmcForwardHeaders(
        $hdr,
        $bmcScheme,
        $bmcIp,
        is_array($session['cookies'] ?? null) ? $session['cookies'] : []
    );
    if (str_starts_with($bmcPathOnlyLower, '/json/')
        || str_starts_with($bmcPathOnlyLower, '/api/')
        || str_starts_with($bmcPathOnlyLower, '/rest/')) {
        if (!ipmiProxyForwardHeadersHasHeader($hdr, 'X-Requested-With')) {
            $hdr['X-Requested-With'] = 'XMLHttpRequest';
        }
        if (!ipmiProxyForwardHeadersHasHeader($hdr, 'Accept')) {
            $hdr['Accept'] = 'application/json, text/javascript, */*';
        }
    }

    return $hdr;
}

/**
 * @return array{fwdHdr: array<string, string>, cookies: array<string, string>}
 */
function ipmiProxyRebuildFreshIloRequestState(array &$session, string &$bmcScheme, string $bmcIp, string $bmcPathOnlyLower, string $traceId): array
{
    $bmcScheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $cookies = is_array($session['cookies'] ?? null) ? $session['cookies'] : [];
    $fwdHdr = ipmiProxyRebuildIloForwardHeadersFromSession($session, $bmcScheme, $bmcIp, $bmcPathOnlyLower);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_retry_request_state_rebuilt', [
            'trace'               => $traceId,
            'bmcScheme'           => $bmcScheme,
            'forward_header_keys' => array_slice(array_keys($fwdHdr), 0, 14),
            'cookie_key_count'    => count($cookies),
            'mitigates_stale_retry_headers' => 1,
            'session_row_source'  => 'db_reload_before_rebuild',
        ]);
        ipmiProxyDebugLog('ilo_retry_using_fresh_forward_headers', [
            'trace'      => $traceId,
            'has_x_auth' => (trim((string) ($fwdHdr['X-Auth-Token'] ?? '')) !== '') ? 1 : 0,
        ]);
        ipmiProxyDebugLog('ilo_retry_using_fresh_cookies', [
            'trace' => $traceId,
            'names' => array_slice(array_keys($cookies), 0, 14),
        ]);
    }

    return ['fwdHdr' => $fwdHdr, 'cookies' => $cookies];
}

/**
 * After HTML/asset relogin mutates the session, iLO needs the same DB-reload + header merge as runtime recovery (avoids stale X-Auth-Token on immediate retry).
 *
 * @return array<string, string>|null Forward headers to use, or null if vendor is not normalized iLO
 */
function ipmiProxyIloFreshForwardHeadersAfterRelogin(
    array &$session,
    string &$bmcScheme,
    string $bmcIp,
    string $bmcPath,
    mysqli $mysqli,
    string $token,
    string $traceId
): ?array {
    if (!ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))) {
        return null;
    }
    ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $traceId);
    $pl = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $st = ipmiProxyRebuildFreshIloRequestState($session, $bmcScheme, $bmcIp, $pl, $traceId);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_relogin_retry_fresh_headers', [
            'trace'   => $traceId,
            'bmcPath' => $bmcPath,
            'mitigates_stale_retry_headers' => 1,
        ]);
    }

    return $st['fwdHdr'];
}

function ipmiProxyMaybeIloRuntimePreflight(mysqli $mysqli, string $token, array &$session, string $bmcIp, string $bmcPath, string $traceId): void
{
    $now = time();
    $meta = is_array($session['session_meta'] ?? null) ? $session['session_meta'] : [];
    $pf = $meta['ilo_preflight'] ?? null;
    $bootstrapState = ipmiProxyIloBootstrapStateLoad($session);
    $bootstrapPhase = (string) ($bootstrapState['phase'] ?? 'fresh');
    $shellPathRole = ipmiProxyClassifyIloPathRoleForSession($mysqli, $token, $session, $bmcPath, 'GET', $traceId);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_preflight_started', [
            'trace'           => $traceId,
            'bootstrap_phase' => $bootstrapPhase,
            'path_role'       => $shellPathRole['role'],
            'path_role_base'  => (string) ($shellPathRole['base_role'] ?? $shellPathRole['role']),
            'bootstrap_critical' => !empty($shellPathRole['bootstrap_critical']) ? 1 : 0,
        ]);
        ipmiProxyDebugLog('ilo_path_role_classified', [
            'trace'              => $traceId,
            'bmcPath'            => $bmcPath,
            'path_role'          => $shellPathRole['role'],
            'path_role_base'     => (string) ($shellPathRole['base_role'] ?? $shellPathRole['role']),
            'bootstrap_critical' => !empty($shellPathRole['bootstrap_critical']) ? 1 : 0,
            'gate'               => 'preflight',
        ]);
    }
    if (in_array($bootstrapPhase, ['stalled', 'degraded'], true) && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_preflight_degraded', [
            'trace' => $traceId,
            'phase' => $bootstrapPhase,
        ]);
    }
    $cacheFresh = is_array($pf) && isset($pf['t']) && (int) $pf['t'] > $now - 25;
    $cacheViable = $cacheFresh
        && !empty($pf['bootstrap_ok'])
        && !in_array($bootstrapPhase, ['stalled', 'degraded'], true);
    if ($cacheViable && ipmiProxyIloBootstrapLooksHealthy($bootstrapState)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_bootstrap_preflight_cache_hit', [
                'trace'           => $traceId,
                'bootstrap_phase' => $bootstrapPhase,
            ]);
            ipmiProxyDebugLog('ilo_runtime_preflight_cache_hit', [
                'trace'         => $traceId,
                'age_sec'       => $now - (int) $pf['t'],
                'session_ok'    => !empty($pf['session_ok']) ? 1 : 0,
                'bootstrap_ok'  => !empty($pf['bootstrap_ok']) ? 1 : 0,
            ]);
        }

        return;
    }
    if ($cacheFresh && !in_array($bootstrapPhase, ['stalled', 'degraded'], true)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_preflight_cache_hit', [
                'trace'         => $traceId,
                'age_sec'       => $now - (int) $pf['t'],
                'session_ok'    => !empty($pf['session_ok']) ? 1 : 0,
                'bootstrap_ok'  => !empty($pf['bootstrap_ok']) ? 1 : 0,
            ]);
        }

        return;
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_preflight_cache_miss', ['trace' => $traceId]);
        ipmiProxyDebugLog('ilo_runtime_preflight_started', ['trace' => $traceId]);
    }
    $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $baseUrl = $scheme . '://' . $bmcIp;
    $cookies = is_array($session['cookies']) ? $session['cookies'] : [];
    $fwd = is_array($session['forward_headers']) ? $session['forward_headers'] : [];
    $sessionOk = ipmiWebIloVerifyAuthed($baseUrl, $bmcIp, $cookies, $fwd);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog($sessionOk ? 'ilo_runtime_preflight_session_info_ok' : 'ilo_runtime_preflight_failed', [
            'trace'  => $traceId,
            'phase'  => 'session_info',
        ]);
        if ($sessionOk) {
            ipmiProxyDebugLog('ilo_bootstrap_preflight_auth_ok', ['trace' => $traceId]);
        }
    }
    $bootstrapOk = $sessionOk && ipmiWebIloBootstrapFragmentProbe($baseUrl, $bmcIp, $cookies, $fwd);
    if ($sessionOk) {
        ipmiWebIloRecordMastheadPreflightOutcome($mysqli, $token, $session, $bootstrapOk);
    }
    if (ipmiProxyDebugEnabled() && $sessionOk) {
        ipmiProxyDebugLog($bootstrapOk ? 'ilo_runtime_preflight_bootstrap_ok' : 'ilo_runtime_preflight_failed', [
            'trace'  => $traceId,
            'phase'  => 'masthead_fragment',
        ]);
        if ($bootstrapOk) {
            ipmiProxyDebugLog('ilo_bootstrap_preflight_fragment_ok', ['trace' => $traceId]);
        }
    }
    if ($sessionOk && $bootstrapOk) {
        $payload = ['t' => $now, 'session_ok' => true, 'bootstrap_ok' => true];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_preflight_passed', ['trace' => $traceId]);
        }

        return;
    }
    $preRefreshPhase = (string) ($bootstrapState['phase'] ?? '');
    $shouldEarlyRefresh = in_array($preRefreshPhase, ['stalled', 'degraded'], true);
    $didPreflightAuthRefresh = false;
    if ($shouldEarlyRefresh) {
        $earlyDecision = ['kind' => 'hard', 'reason' => 'bootstrap_preflight_stalled'];
        if (!ipmiProxyIloCanAttemptAnotherRefresh($bootstrapState, $earlyDecision)) {
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                    'trace'   => $traceId,
                    'gate'    => 'preflight_stalled',
                    'reason'  => 'refresh_budget',
                ]);
            }
        } else {
            $bootstrapState = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $bootstrapState, $traceId);
            if (ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $traceId, 'bootstrap_preflight_stalled')) {
                $didPreflightAuthRefresh = true;
                ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $traceId);
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_bootstrap_preflight_refreshed_auth', [
                        'trace'  => $traceId,
                        'reason' => 'stalled_or_degraded_phase',
                    ]);
                }
                $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
                $baseUrl = $scheme . '://' . $bmcIp;
                $cookies = is_array($session['cookies']) ? $session['cookies'] : [];
                $fwd = is_array($session['forward_headers']) ? $session['forward_headers'] : [];
                $sessionOk = ipmiWebIloVerifyAuthed($baseUrl, $bmcIp, $cookies, $fwd);
                $bootstrapOk = $sessionOk && ipmiWebIloBootstrapFragmentProbe($baseUrl, $bmcIp, $cookies, $fwd);
                if ($sessionOk) {
                    ipmiWebIloRecordMastheadPreflightOutcome($mysqli, $token, $session, $bootstrapOk);
                }
            }
        }
    }
    if ($sessionOk && $bootstrapOk) {
        $payload = ['t' => time(), 'session_ok' => true, 'bootstrap_ok' => true];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_preflight_passed', ['trace' => $traceId]);
        }

        return;
    }
    if ($didPreflightAuthRefresh) {
        $payload = ['t' => time(), 'session_ok' => $sessionOk, 'bootstrap_ok' => $bootstrapOk];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_bootstrap_preflight_skip_second_refresh', [
                'trace'        => $traceId,
                'session_ok'   => $sessionOk ? 1 : 0,
                'bootstrap_ok' => $bootstrapOk ? 1 : 0,
            ]);
        }

        return;
    }
    $bootstrapStateShell = ipmiProxyIloBootstrapStateLoad($session);
    $shellDecision = ['kind' => 'hard', 'reason' => 'shell_preflight'];
    if (!ipmiProxyIloCanAttemptAnotherRefresh($bootstrapStateShell, $shellDecision)) {
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                'trace'  => $traceId,
                'gate'   => 'shell_preflight',
                'reason' => 'refresh_budget',
            ]);
        }
        $payload = ['t' => $now, 'session_ok' => false, 'bootstrap_ok' => false];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;

        return;
    }
    $bootstrapStateShell = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $bootstrapStateShell, $traceId);
    if (ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $traceId, 'shell_preflight')) {
        ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $traceId);
        $scheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
        $baseUrl = $scheme . '://' . $bmcIp;
        $cookies = is_array($session['cookies']) ? $session['cookies'] : [];
        $fwd = is_array($session['forward_headers']) ? $session['forward_headers'] : [];
        $sessionOk2 = ipmiWebIloVerifyAuthed($baseUrl, $bmcIp, $cookies, $fwd);
        $bootstrapOk2 = $sessionOk2 && ipmiWebIloBootstrapFragmentProbe($baseUrl, $bmcIp, $cookies, $fwd);
        if ($sessionOk2) {
            ipmiWebIloRecordMastheadPreflightOutcome($mysqli, $token, $session, $bootstrapOk2);
        }
        $payload = ['t' => time(), 'session_ok' => $sessionOk2, 'bootstrap_ok' => $bootstrapOk2];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_preflight_auth_refreshed', [
                'trace'        => $traceId,
                'session_ok'   => $sessionOk2 ? 1 : 0,
                'bootstrap_ok' => $bootstrapOk2 ? 1 : 0,
            ]);
            ipmiProxyDebugLog('ilo_bootstrap_preflight_refreshed_auth', [
                'trace'  => $traceId,
                'reason' => 'shell_preflight',
            ]);
        }
    } else {
        $payload = ['t' => $now, 'session_ok' => false, 'bootstrap_ok' => false];
        ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($payload): void {
            $meta['ilo_preflight'] = $payload;
        });
        if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
            $session['session_meta'] = [];
        }
        $session['session_meta']['ilo_preflight'] = $payload;
    }
}

/**
 * Paths where HTTP 200 may still mean stale session (soft auth). Matches recoverable runtime set so any endpoint eligible for hard retry is also checked for soft 200 failures.
 */
function ipmiProxyIloBootstrapSensitivePath(string $bmcPath): bool
{
    return ipmiProxyIsIloRecoverableRuntimePath($bmcPath);
}

function ipmiProxyIloJsonLooksUnauthed(string $body): bool
{
    $t = trim($body);
    if ($t === '' || ($t[0] !== '{' && $t[0] !== '[')) {
        return false;
    }
    $j = json_decode($t, true);
    if (!is_array($j)) {
        return true;
    }
    $msg = strtolower((string) ($j['message'] ?? $j['error'] ?? ''));
    if (is_string($j['error'] ?? null)) {
        $msg .= ' ' . strtolower((string) $j['error']);
    }
    $details = strtolower((string) ($j['details'] ?? ''));
    if (str_contains($msg, 'lost_session') || str_contains($details, 'invalid session')) {
        return true;
    }
    if (str_contains($msg, 'unauthorized') || str_contains($msg, 'forbidden')) {
        return true;
    }
    if (str_contains($msg, 'authentication') && (str_contains($msg, 'fail') || str_contains($msg, 'required'))) {
        return true;
    }
    if (isset($j['code']) && (int) $j['code'] === 401) {
        return true;
    }
    $ext = $j['error'] ?? null;
    if (is_array($ext)) {
        $ek = strtolower((string) ($ext['key'] ?? $ext['code'] ?? ''));

        return str_contains($ek, 'session') || str_contains($ek, 'auth');
    }

    return false;
}

function ipmiProxyIloHtmlLooksUnauthed(string $body): bool
{
    if (ipmiWebResponseLooksLikeBmcLoginPage($body, 'text/html')) {
        return true;
    }
    if (ipmiProxyBodyHasSessionTimeout($body)) {
        return true;
    }

    return false;
}

function ipmiProxyIloBootstrapResponseLooksWrong(string $bmcPath, string $contentType, string $body): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    if (ipmiProxyIloIsHtmlFragmentForSemanticCheck($bmcPath)) {
        if (str_contains($ct, 'json')) {
            return true;
        }
        $lb = strtolower(substr($body, 0, 24000));
        if (strlen($body) < 40) {
            return true;
        }
        if ($lb !== '' && str_contains($lb, '<html') && !str_contains($lb, 'masthead')
            && str_contains($lb, 'password') && str_contains($lb, 'login')) {
            return true;
        }
    }
    if (str_starts_with($p, '/json/') && (str_contains($ct, 'html') || ($ct === 'text/plain' && ipmiProxyIloHtmlLooksUnauthed($body)))) {
        return ipmiProxyIloHtmlLooksUnauthed($body);
    }

    return false;
}

function ipmiProxyIloIsSoftAuthFailure(string $bmcPath, int $httpCode, string $contentType, string $body): bool
{
    if ($httpCode < 200 || $httpCode >= 400) {
        return false;
    }
    if (!ipmiProxyIloBootstrapSensitivePath($bmcPath)) {
        return false;
    }
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    $ct = strtolower(trim(explode(';', $contentType)[0] ?? ''));
    $jsonish = str_starts_with($p, '/json/') || str_contains($ct, 'json');
    if ($jsonish && ipmiProxyIloJsonLooksUnauthed($body)) {
        return true;
    }
    if (str_contains($ct, 'html') && ipmiProxyIloHtmlLooksUnauthed($body)) {
        return true;
    }
    if (ipmiProxyIloBootstrapResponseLooksWrong($bmcPath, $contentType, $body)) {
        return true;
    }

    return false;
}

/**
 * @return array{recover: bool, reason: string, kind: 'none'|'hard'|'soft', soft_detail?: string}
 */
function ipmiProxyIloClassifyBufferedRecovery(
    mysqli $mysqli,
    string $token,
    array &$session,
    array $result,
    string $bmcPath,
    string $method,
    string $traceId
): array {
    if (!ipmiProxyIsIloRecoverableRuntimePath($bmcPath)) {
        return ['recover' => false, 'reason' => 'not_recoverable_path', 'kind' => 'none'];
    }
    $http0 = (int) ($result['http_code'] ?? 0);
    if (($result['raw'] ?? false) === false) {
        return [
            'recover' => true,
            'reason'  => 'curl_failed:' . (int) ($result['curl_errno'] ?? 0),
            'kind'    => 'hard',
        ];
    }
    if (in_array($http0, [401, 403, 502, 503], true)) {
        return ['recover' => true, 'reason' => 'http_' . $http0, 'kind' => 'hard'];
    }
    [, $body] = ipmiWebCurlExtractFinalHeadersAndBody((string) $result['raw']);
    $ct = (string) ($result['content_type'] ?? '');
    $pathRole = ipmiProxyClassifyIloPathRoleForSession($mysqli, $token, $session, $bmcPath, $method, $traceId);
    if (!empty($pathRole['bootstrap_critical']) && $http0 >= 200 && $http0 < 400) {
        if (ipmiProxyIloResponseLooksBootstrapBroken($bmcPath, $ct, $body)) {
            if (ipmiProxyDebugEnabled()) {
                ipmiProxyDebugLog('ilo_bootstrap_semantic_failure_detected', [
                    'trace'   => $traceId,
                    'bmcPath' => $bmcPath,
                    'gate'    => 'classify_recovery',
                ]);
            }

            return [
                'recover'     => true,
                'reason'      => 'soft_auth:semantic_bootstrap',
                'kind'        => 'soft',
                'soft_detail' => 'semantic_bootstrap',
            ];
        }
    }
    if (ipmiProxyIloIsSoftAuthFailure($bmcPath, $http0, $ct, $body)) {
        $detail = 'json_unauth';
        if (ipmiProxyIloBootstrapResponseLooksWrong($bmcPath, $ct, $body)) {
            $detail = 'bootstrap_mismatch';
        } elseif (str_contains(strtolower(trim(explode(';', $ct)[0] ?? '')), 'html') && ipmiProxyIloHtmlLooksUnauthed($body)) {
            $detail = 'html_login_like';
        }

        return [
            'recover'      => true,
            'reason'       => 'soft_auth:' . $detail,
            'kind'         => 'soft',
            'soft_detail'  => $detail,
        ];
    }

    return ['recover' => false, 'reason' => 'ok_or_not_actionable', 'kind' => 'none'];
}

/**
 * Normalized debug bucket for blank-iLO triage (see ipmi_proxy_debug.php).
 */
function ipmiProxyIloDebugFailureAxisFromReason(string $kind, string $reason): string
{
    if ($kind === 'soft' && str_contains($reason, 'semantic_bootstrap')) {
        return 'bootstrap_semantic';
    }
    if ($kind === 'soft') {
        return 'soft_auth';
    }
    if (str_starts_with($reason, 'curl_failed')) {
        return 'upstream_transport';
    }
    if (preg_match('/^http_/', $reason)) {
        return 'hard_http_auth';
    }

    return 'hard_failure';
}

/**
 * Single authoritative iLO buffered (non-SSE) recovery: refresh → reload DB row → rebuild headers → one retry.
 *
 * @param array<string, mixed> $result
 */
function ipmiProxyIloMaybeRecoverBufferedRuntime(
    mysqli $mysqli,
    string $token,
    array &$session,
    string &$bmcScheme,
    string $bmcIp,
    string $bmcPath,
    string $bmcPathOnlyLower,
    string $method,
    string $bmcUrl,
    ?string $postBody,
    string $fwdContentType,
    array &$result,
    string $ipmiTraceId
): void {
    if (!ipmiWebIsNormalizedIloType(ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic')))) {
        return;
    }
    if (!empty($GLOBALS['__ipmi_ilo_runtime_recover_attempted'])) {
        return;
    }
    $pathRole = ipmiProxyClassifyIloPathRoleForSession($mysqli, $token, $session, $bmcPath, $method, $ipmiTraceId);
    $class = (string) ($pathRole['debug_class'] ?? 'other');
    $bootstrapCritical = !empty($pathRole['bootstrap_critical']) ? 1 : 0;
    $bootstrapState = ipmiProxyIloBootstrapStateLoad($session);
    $httpPre = (int) ($result['http_code'] ?? 0);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_bootstrap_state_loaded', [
            'trace'         => $ipmiTraceId,
            'bootstrap_pre' => (string) ($bootstrapState['phase'] ?? ''),
            'gate'          => 'buffered_recovery',
        ]);
        ipmiProxyDebugLog('ilo_path_role_classified', [
            'trace'              => $ipmiTraceId,
            'bmcPath'            => $bmcPath,
            'method'             => $method,
            'path_role'          => $pathRole['role'],
            'path_role_base'     => (string) ($pathRole['base_role'] ?? $pathRole['role']),
            'bootstrap_critical' => $bootstrapCritical,
            'recoverable'        => !empty($pathRole['recoverable']) ? 1 : 0,
        ]);
        if ($bootstrapCritical) {
            ipmiProxyDebugLog('ilo_bootstrap_critical_path_detected', [
                'trace'     => $ipmiTraceId,
                'bmcPath'   => $bmcPath,
                'path_role' => $pathRole['role'],
            ]);
        }
        ipmiProxyDebugLog('ilo_bootstrap_request_executed', [
            'trace'         => $ipmiTraceId,
            'bmcPath'       => $bmcPath,
            'http'          => $httpPre,
            'bootstrap_pre' => (string) ($bootstrapState['phase'] ?? ''),
            'path_role'     => $pathRole['role'],
        ]);
    }
    $decision = ipmiProxyIloClassifyBufferedRecovery($mysqli, $token, $session, $result, $bmcPath, $method, $ipmiTraceId);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_request_classified', [
            'trace'              => $ipmiTraceId,
            'bmcPath'            => $bmcPath,
            'method'             => $method,
            'path_class'         => $class,
            'path_role'          => $pathRole['role'],
            'bootstrap_critical' => $bootstrapCritical,
            'recover'            => $decision['recover'] ? 1 : 0,
            'reason'             => $decision['reason'],
            'kind'               => $decision['kind'],
        ]);
    }
    if (!$decision['recover']) {
        return;
    }
    if (!ipmiProxyIloCanAttemptAnotherRefresh($bootstrapState, $decision)) {
        $rts = is_array($bootstrapState['refresh_ts'] ?? null) ? $bootstrapState['refresh_ts'] : [];
        $recent = count(array_filter($rts, static fn ($t) => $t > time() - 60));
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                'trace'          => $ipmiTraceId,
                'bmcPath'        => $bmcPath,
                'reason'         => $decision['reason'],
                'recent_refresh' => $recent,
                'bootstrap_phase'=> (string) ($bootstrapState['phase'] ?? ''),
            ]);
            if ($recent >= 3) {
                ipmiProxyDebugLog('ilo_refresh_budget_exhausted', [
                    'trace'   => $ipmiTraceId,
                    'bmcPath' => $bmcPath,
                ]);
            }
            ipmiProxyDebugLog('ilo_bootstrap_recovery_decision', [
                'trace'        => $ipmiTraceId,
                'will_recover' => 0,
                'reason'       => 'refresh_budget',
                'kind'         => $decision['kind'],
            ]);
        }

        return;
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_recovery_decision', [
            'trace'          => $ipmiTraceId,
            'will_recover'   => 1,
            'reason'         => $decision['reason'],
            'kind'           => $decision['kind'],
            'failure_axis'   => ipmiProxyIloDebugFailureAxisFromReason((string) $decision['kind'], (string) $decision['reason']),
        ]);
        ipmiProxyDebugLog('ilo_bootstrap_recovery_decision', [
            'trace'          => $ipmiTraceId,
            'will_recover'   => 1,
            'bootstrap_pre'  => (string) ($bootstrapState['phase'] ?? ''),
            'reason'         => $decision['reason'],
            'failure_axis'   => ipmiProxyIloDebugFailureAxisFromReason((string) $decision['kind'], (string) $decision['reason']),
        ]);
        if ($decision['kind'] === 'soft') {
            ipmiProxyDebugLog('ilo_soft_auth_failure_detected', [
                'trace'          => $ipmiTraceId,
                'bmcPath'        => $bmcPath,
                'detail'         => (string) ($decision['soft_detail'] ?? ''),
                'failure_axis'   => ipmiProxyIloDebugFailureAxisFromReason('soft', (string) ($decision['reason'] ?? '')),
            ]);
        }
    }
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_recovery_attempt', ['trace' => $ipmiTraceId, 'reason' => $decision['reason']]);
    }
    $bootstrapState = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $bootstrapState, $ipmiTraceId);
    if (!ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $ipmiTraceId, $decision['reason'])) {
        $bootstrapState = ipmiProxyIloRecordRefreshAttempt($mysqli, $token, $session, $bootstrapState, false, $ipmiTraceId);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_final_failure', [
                'trace'          => $ipmiTraceId,
                'bmcPath'        => $bmcPath,
                'phase'          => 'auth_refresh_failed',
                'reason'         => $decision['reason'],
                'path_class'     => $class,
                'failure_axis'   => 'auth_refresh_exhausted',
                'blank_ui_cause' => ipmiProxyIloBlankUiCause($bmcPath, 'auth_refresh_failed'),
            ]);
            ipmiProxyDebugLog('ilo_runtime_final_result', [
                'trace' => $ipmiTraceId,
                'outcome'  => 'auth_refresh_failed',
                'bmcPath'  => $bmcPath,
            ]);
        }

        return;
    }
    $bootstrapState = ipmiProxyIloRecordRefreshAttempt($mysqli, $token, $session, $bootstrapState, true, $ipmiTraceId);
    ipmiProxyReloadSessionRowInto($session, $mysqli, $token, $ipmiTraceId);
    $fresh = ipmiProxyRebuildFreshIloRequestState($session, $bmcScheme, $bmcIp, $bmcPathOnlyLower, $ipmiTraceId);
    $GLOBALS['__ipmi_ilo_runtime_recover_attempted'] = true;
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_retry_executed', [
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
            'method'  => $method,
        ]);
        ipmiProxyDebugLog('ilo_bootstrap_retry_executed', [
            'trace'       => $ipmiTraceId,
            'bmcPath'     => $bmcPath,
            'fresh_state' => 1,
        ]);
    }
    $result = ipmiProxyExecute(
        $bmcUrl,
        $method,
        $postBody,
        $fwdContentType,
        $fresh['cookies'],
        $fresh['fwdHdr'],
        $bmcIp
    );
    $http1 = (int) ($result['http_code'] ?? 0);
    $okTransport = (($result['raw'] ?? false) !== false);
    $body1 = '';
    $ct1 = (string) ($result['content_type'] ?? '');
    if ($okTransport) {
        [, $body1] = ipmiWebCurlExtractFinalHeadersAndBody((string) $result['raw']);
    }
    $stillSoft = $okTransport && ipmiProxyIloIsSoftAuthFailure($bmcPath, $http1, $ct1, $body1);
    $hardBad = $okTransport && in_array($http1, [401, 403, 502, 503], true);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_final_result', [
            'trace'        => $ipmiTraceId,
            'bmcPath'      => $bmcPath,
            'http'         => $http1,
            'transport_ok' => $okTransport ? 1 : 0,
            'still_soft'   => $stillSoft ? 1 : 0,
            'hard_bad'     => $hardBad ? 1 : 0,
        ]);
    }
    if ($okTransport && $http1 >= 200 && $http1 < 400 && !$stillSoft && ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_fragment_recovered', [
            'trace'   => $ipmiTraceId,
            'bmcPath' => $bmcPath,
        ]);
    } elseif (ipmiProxyDebugEnabled() && $okTransport && ($hardBad || $stillSoft)) {
        $axisPost = 'hard_http_auth';
        if ($stillSoft) {
            $axisPost = ($class === 'helper_fragment') ? 'fragment_bootstrap_soft' : 'soft_auth';
        } elseif ($http1 >= 500) {
            $axisPost = 'upstream_transport';
        }
        ipmiProxyDebugLog('ilo_runtime_final_failure', [
            'trace'          => $ipmiTraceId,
            'bmcPath'        => $bmcPath,
            'phase'          => 'post_auth_retry_bad_http',
            'http'           => $http1,
            'path_class'     => $class,
            'still_soft_auth'=> $stillSoft ? 1 : 0,
            'failure_axis'   => $axisPost,
            'blank_ui_cause' => $stillSoft ? 'soft_auth_failure' : ipmiProxyIloBlankUiCause($bmcPath, 'post_retry_http', ['http' => $http1]),
        ]);
    }
}

function ipmiProxyIsSupermicroRuntimeApiPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }

    return in_array($p, ['/cgi/xml_dispatcher.cgi', '/cgi/op.cgi', '/cgi/ipmi.cgi'], true);
}

function ipmiProxyIsAmiRuntimeApiPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }

    return str_starts_with($p, '/api/')
        || str_starts_with($p, '/rest/')
        || str_starts_with($p, '/rpc/')
        || $p === '/session'
        || str_starts_with($p, '/session/');
}

/**
 * Normalize proxy-relative targets so we can safely avoid self-redirect loops.
 */
function ipmiProxyCanonicalRelativeTarget(string $target): string
{
    $target = trim($target);
    if ($target === '') {
        return '/';
    }
    if (preg_match('#^https?://#i', $target)) {
        $p = parse_url($target, PHP_URL_PATH);
        $q = parse_url($target, PHP_URL_QUERY);
        $target = (string)($p ?? '/');
        if ($target === '') {
            $target = '/';
        }
        if (is_string($q) && $q !== '') {
            $target .= '?' . $q;
        }
    }

    $path = (string)parse_url($target, PHP_URL_PATH);
    if ($path === '') {
        $path = '/';
    }
    $query = (string)parse_url($target, PHP_URL_QUERY);
    return $query !== '' ? ($path . '?' . $query) : $path;
}

function ipmiProxyIsSameRelativeTarget(string $a, string $b): bool
{
    return ipmiProxyCanonicalRelativeTarget($a) === ipmiProxyCanonicalRelativeTarget($b);
}

/**
 * iDRAC quirk:
 * /restgui/start.html is a launcher page that usually redirects to /login.html.
 * If proxy forcibly redirects /login.html back to /restgui/start.html, browser loops forever.
 */
function ipmiProxyShouldSuppressIdracLandingRedirect(string $bmcType, string $currentTarget, string $landingPath): bool
{
    if (ipmiWebNormalizeBmcType($bmcType) !== 'idrac') {
        return false;
    }
    $landing = ipmiProxyCanonicalRelativeTarget($landingPath);
    $isIdracLauncherLanding = ipmiProxyIsSameRelativeTarget($landing, '/restgui/start.html')
        || ipmiProxyIsSameRelativeTarget($landing, '/start.html')
        || ipmiProxyIsSameRelativeTarget($landing, '/restgui/launch');
    if (!$isIdracLauncherLanding) {
        return false;
    }
    $cur = strtolower((string) parse_url(ipmiProxyCanonicalRelativeTarget($currentTarget), PHP_URL_PATH));
    return $cur === '/login.html'
        || $cur === '/login'
        || $cur === '/start.html'
        || $cur === '/restgui/start.html'
        || $cur === '/restgui/launch';
}

function ipmiProxyBodyHasSessionTimeout(string $body): bool
{
    if ($body === '') {
        return false;
    }
    if (ipmiProxyBodyLooksLikeSupermicroTopmenuAuthed($body)) {
        return false;
    }
    if (ipmiWebResponseLooksLikeIloAuthedShell($body)) {
        return false;
    }
    // Ignore timeout strings embedded in JS constants; only inspect visible HTML text.
    $visible = preg_replace('~<script\b[^>]*>.*?</script>~is', ' ', $body);
    if (!is_string($visible)) {
        $visible = $body;
    }
    $visible = preg_replace('~<style\b[^>]*>.*?</style>~is', ' ', $visible);
    if (!is_string($visible)) {
        $visible = $body;
    }
    $snippet = strtolower(substr($visible, 0, 200000));
    if (strpos($snippet, 'ipmi session expired') !== false) {
        return true;
    }
    if (strpos($snippet, 'you will need to open a new session') !== false) {
        return true;
    }

    return (strpos($snippet, 'session has timed out') !== false || strpos($snippet, 'session timed out') !== false)
        && (strpos($snippet, 'please log in a new session') !== false || strpos($snippet, 'please login in a new session') !== false);
}

function ipmiProxyBodyLooksLikeIdracLauncherShell(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $lb = strtolower(substr($body, 0, 120000));
    if ($lb === '') {
        return false;
    }

    return strpos($lb, '/session?aimgetintprop=scl_int_enabled') !== false
        && strpos($lb, 'aimgetboolprop=pam_bool_sso_enabled') !== false
        && strpos($lb, 'top.document.location.href') !== false
        && strpos($lb, '/login.html') !== false;
}

function ipmiProxyBodyLooksLikeSupermicroTopmenuAuthed(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $l = strtolower(substr($body, 0, 200000));
    if ($l === '') {
        return false;
    }

    $hits = 0;
    if (strpos($l, 'lang_topmenu_greeting') !== false) {
        $hits++;
    }
    if (strpos($l, 'id="refreshid"') !== false || strpos($l, "id='refreshid'") !== false) {
        $hits++;
    }
    if (strpos($l, "sessionstorage.setitem ('_x_auth'") !== false
        || strpos($l, 'sessionstorage.setitem("_x_auth"') !== false) {
        $hits++;
    }
    if (strpos($l, 'new redfish (null, session_id)') !== false) {
        $hits++;
    }

    return $hits >= 2;
}

function ipmiProxyBodyLooksLikeSupermicroTimeoutShell(string $body): bool
{
    if ($body === '') {
        return false;
    }
    if (ipmiProxyBodyLooksLikeSupermicroTopmenuAuthed($body)) {
        return false;
    }
    $l = strtolower(substr($body, 0, 120000));
    if ($l === '') {
        return false;
    }
    $hasLogoutFn = strpos($l, 'logout_alert') !== false;
    $hasSessionTimeoutCall = strpos($l, 'sessiontimeout()') !== false
        || strpos($l, 'sessiontimeout ();') !== false;
    $hasReadyHook = strpos($l, 'document).ready') !== false || strpos($l, 'jquery(document).ready') !== false;

    return $hasLogoutFn && $hasSessionTimeoutCall && $hasReadyHook;
}

function ipmiProxyBodyLooksLikeSupermicroApiAuthFailure(string $body): bool
{
    if ($body === '') {
        return false;
    }
    if (ipmiProxyBodyHasSessionTimeout($body) || ipmiProxyBodyLooksLikeSupermicroTimeoutShell($body)) {
        return true;
    }

    $l = strtolower(substr($body, 0, 120000));
    if ($l === '') {
        return false;
    }

    if (strpos($l, 'please log in a new session') !== false || strpos($l, 'please login in a new session') !== false) {
        return true;
    }
    if (strpos($l, 'your session has timed out') !== false || strpos($l, 'session timed out') !== false) {
        return true;
    }
    if (strpos($l, 'invalid session') !== false || strpos($l, 'no valid session') !== false) {
        return true;
    }
    if (strpos($l, 'session expired') !== false) {
        return true;
    }

    return false;
}

function ipmiProxyBodyLooksLikeJavaOnlyIloConsole(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $sample = strtolower(substr((string) $body, 0, 200000));
    if ($sample === '') {
        return false;
    }

    return str_contains($sample, 'java integrated remote console')
        && str_contains($sample, 'applet-based console')
        && str_contains($sample, 'requiring the availability of java');
}

function ipmiProxyBodyLooksLikeIloHtml5ConsoleUnavailable(string $body): bool
{
    if ($body === '') {
        return false;
    }
    $sample = strtolower(substr((string) $body, 0, 200000));
    if ($sample === '') {
        return false;
    }

    return str_contains($sample, 'standalone html5 console not yet available')
        || (str_contains($sample, 'html5 console') && str_contains($sample, 'not yet available'));
}

function ipmiProxyIsKvmAutoFlowRequest(): bool
{
    $autoQuery = ((string) ($_GET['ipmi_kvm_auto'] ?? '') === '1');
    $legacyQuery = ((string) ($_GET['ipmi_kvm_legacy'] ?? '') === '1');
    $autoCookie = ((string) ($_COOKIE['IPMI_KVM_AUTO'] ?? '') === '1');
    $legacyCookie = ((string) ($_COOKIE['IPMI_KVM_LEGACY'] ?? '') === '1');
    $ref = strtolower((string) ($_SERVER['HTTP_REFERER'] ?? ''));
    $autoRef = str_contains($ref, 'ipmi_kvm_auto=1');
    $legacyRef = str_contains($ref, 'ipmi_kvm_legacy=1');

    $auto = $autoQuery || $autoCookie || $autoRef;
    $legacy = $legacyQuery || $legacyCookie || $legacyRef;

    return $auto && !$legacy;
}

function ipmiProxyLooksLikeLoginPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    return $p === '/login' || $p === '/login.html' || $p === '/signin' || $p === '/signin.html';
}

function ipmiProxyPostAuthLandingPath(string $bmcType): string
{
    return ipmiWebPostLoginLandingPath((string) $bmcType);
}

function ipmiProxyEmitSessionExpiredPage(string $message = ''): void
{
    $msg = trim($message) !== '' ? $message : 'Your BMC web session has timed out. Open a new session from the panel.';
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    $safeMsg = htmlspecialchars($msg, ENT_QUOTES, 'UTF-8');
    $back = htmlspecialchars('/index.php', ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>IPMI Session Expired</title>'
        . '<style>body{font-family:Arial,sans-serif;background:#0b1630;color:#dce6ff;margin:0;padding:28px}'
        . '.card{max-width:760px;margin:30px auto;background:#1b2a47;border-radius:10px;padding:24px;border:1px solid #2b3d60}'
        . 'a{color:#7fc0ff} .btn{display:inline-block;margin-right:10px;margin-top:14px;padding:10px 14px;'
        . 'border-radius:7px;background:#22477a;color:#fff;text-decoration:none}</style></head><body>'
        . '<div class="card"><h2 style="margin-top:0">IPMI Session Expired</h2><p>' . $safeMsg . '</p>'
        . '<a class="btn" href="' . $back . '">Back to panel</a></div></body></html>';
    exit;
}

function ipmiProxyEmitKvmModeChoicePage(string $tokenPrefix, string $title, string $message): void
{
    http_response_code(200);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    $safeTitle = htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
    $safeMsg = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    $browserUrl = htmlspecialchars($tokenPrefix . '/html/application.html?ipmi_kvm_auto=1&ipmi_kvm_force_html5=1', ENT_QUOTES, 'UTF-8');
    $dashUrl = htmlspecialchars($tokenPrefix . '/index.html', ENT_QUOTES, 'UTF-8');
    echo '<!doctype html><html><head><meta charset="utf-8"><title>' . $safeTitle . '</title>'
        . '<style>body{font-family:Arial,sans-serif;background:#0b1630;color:#dce6ff;margin:0;padding:28px}'
        . '.card{max-width:860px;margin:28px auto;background:#1b2a47;border-radius:10px;padding:24px;border:1px solid #2b3d60}'
        . '.btn{display:inline-block;margin:10px 10px 0 0;padding:10px 14px;border-radius:7px;background:#22477a;color:#fff;text-decoration:none}'
        . '.btn-alt{background:#2f5f2f}.btn-low{background:#3b3f58}</style></head><body>'
        . '<div class="card"><h2 style="margin-top:0">' . $safeTitle . '</h2><p>' . $safeMsg . '</p>'
        . '<a class="btn btn-alt" href="' . $browserUrl . '">Try Browser HTML5 Console</a>'
        . '<a class="btn btn-low" href="' . $dashUrl . '">Back to iLO Dashboard</a>'
        . '</div></body></html>';
    exit;
}

function ipmiProxyIsBmcStaticAssetPath(string $bmcPath): bool
{
    $p = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($p === '') {
        return false;
    }
    foreach (['/js/', '/css/', '/fonts/', '/themes/', '/img/', '/images/'] as $prefix) {
        if (str_contains($p, $prefix)) {
            return true;
        }
    }

    return (bool) preg_match('/\.(?:js|css|png|svg|jpg|jpeg|gif|webp|ico|woff2?|ttf|eot|map|jar|jnlp|class|cab)$/', $p);
}

/**
 * Per-URL cURL total timeout for buffered ipmiProxyExecute (non-streaming GET/POST).
 */
function ipmiProxyCurlTimeoutForBmcUrl(string $bmcUrl): int
{
    $path = strtolower((string) (parse_url($bmcUrl, PHP_URL_PATH) ?? ''));
    // Health poll endpoints are very chatty on iLO; keep timeout bounded to avoid worker starvation.
    if (str_contains($path, '/json/health') || str_contains($path, 'health_summary')) {
        return 25;
    }
    // Keep static assets under common FastCGI/proxy timeouts to avoid 502 before PHP responds.
    if (ipmiProxyIsBmcStaticAssetPath($path)) {
        return 20;
    }

    return 60;
}

/**
 * Paths that must be streamed (bytes forwarded as they arrive), not buffered in PHP.
 * Only true SSE/event-stream endpoints are streamed.
 */
function ipmiProxyIsBmcLongPollOrStreamPath(string $bmcPath): bool
{
    $p = strtolower($bmcPath);
    if (str_starts_with($p, '/sse/') || str_contains($p, 'event_stream') || str_contains($p, 'eventstream')) {
        return true;
    }
    $acc = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));

    return str_contains($acc, 'text/event-stream');
}

/**
 * Execute the proxy request. Extracted so we can retry after auth recovery.
 * Retries once without CURLOPT_RESOLVE if the first attempt fails (bad PTR / libcurl quirk).
 *
 * @param int|null $timeoutOverride Total cURL timeout in seconds; null = ipmiProxyCurlTimeoutForBmcUrl($bmcUrl).
 */
function ipmiProxyExecute(string $bmcUrl, string $method, ?string $postBody, string $fwdContentType, array $cookies, array $forwardHeaders = [], string $bmcIp = '', ?int $timeoutOverride = null): array
{
    $bmcIpEff = $bmcIp !== '' ? $bmcIp : (string) (parse_url($bmcUrl, PHP_URL_HOST) ?? '');

    $attemptResolve = function (bool $tryResolve) use ($bmcUrl, $method, $postBody, $fwdContentType, $cookies, $forwardHeaders, $bmcIpEff, $timeoutOverride): array {
        $ch = curl_init($bmcUrl);
        $appliedResolve = false;
        if ($tryResolve) {
            $appliedResolve = ipmiProxyApplyCurlBmcUrlAndResolve($ch, $bmcUrl, $bmcIpEff);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $effTimeout = $timeoutOverride !== null ? $timeoutOverride : ipmiProxyCurlTimeoutForBmcUrl($bmcUrl);
        curl_setopt($ch, CURLOPT_TIMEOUT, $effTimeout);
        if ($effTimeout > 0) {
            curl_setopt($ch, CURLOPT_NOSIGNAL, true);
        }
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_ENCODING, '');
        curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
        ipmiProxyApplyCurlBmcReferer($ch, $bmcUrl, $forwardHeaders, $bmcIpEff);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($postBody !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postBody);
            }
        }

        $parts = [];
        foreach ($cookies as $k => $v) {
            if ($v !== null && trim((string) $v) !== '') {
                $parts[] = $k . '=' . $v;
            }
        }
        if ($parts !== []) {
            curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $parts));
        }

        $headers = [];
        if ($fwdContentType !== '') {
            $headers[] = 'Content-Type: ' . $fwdContentType;
        }
        foreach ($forwardHeaders as $hn => $hv) {
            $hn = trim((string) $hn);
            if ($hn === '' || strcasecmp($hn, 'Content-Type') === 0) {
                continue;
            }
            if ($hv === null || trim((string) $hv) === '') {
                continue;
            }
            $headers[] = $hn . ': ' . $hv;
        }
        if ($headers !== []) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        }

        $rawResponse = curl_exec($ch);
        $curlErrNo = ($rawResponse === false) ? curl_errno($ch) : 0;
        $curlErrStr = ($rawResponse === false) ? (string) curl_error($ch) : '';
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $contentTypeResp = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        return [
            'raw'             => $rawResponse,
            'http_code'       => $httpCode,
            'content_type'    => $contentTypeResp,
            'applied_resolve' => $appliedResolve,
            'curl_errno'      => $curlErrNo,
            'curl_error'      => $curlErrStr,
        ];
    };

    $out = $attemptResolve(true);
    if (($out['raw'] === false || $out['http_code'] === 0) && $out['applied_resolve']) {
        $out = $attemptResolve(false);
    }
    // Some iLO builds return 403 on API when SNI uses PTR hostname but accept the same session over https://&lt;IP&gt;/...
    if ($out['raw'] !== false && (int) $out['http_code'] === 403 && !empty($out['applied_resolve'])) {
        $out2 = $attemptResolve(false);
        if ($out2['raw'] !== false) {
            $out = $out2;
        }
    }

    return [
        'raw'          => $out['raw'],
        'http_code'    => $out['http_code'],
        'content_type' => $out['content_type'],
        'curl_errno'   => (int) ($out['curl_errno'] ?? 0),
        'curl_error'   => (string) ($out['curl_error'] ?? ''),
    ];
}

function ipmiProxyForwardHeadersHasHeader(array $forwardHeaders, string $needleName): bool
{
    $n = strtolower($needleName);
    foreach ($forwardHeaders as $k => $_v) {
        if (strtolower(trim((string) $k)) === $n) {
            return true;
        }
    }

    return false;
}

/**
 * Some BMCs reject API/SSE requests without a Referer from the BMC origin.
 */
function ipmiProxyApplyCurlBmcReferer($ch, string $bmcUrl, array $forwardHeaders, string $bmcIp): void
{
    if (ipmiProxyForwardHeadersHasHeader($forwardHeaders, 'Referer')) {
        return;
    }
    $p = parse_url($bmcUrl);
    if (!is_array($p) || empty($p['scheme'])) {
        return;
    }
    if ($bmcIp === '') {
        $bmcIp = (string) ($p['host'] ?? '');
    }
    $host = ipmiProxyBmcPreferredOriginHost($bmcIp);
    $port = isset($p['port']) ? ':' . (int) $p['port'] : '';
    curl_setopt($ch, CURLOPT_REFERER, $p['scheme'] . '://' . $host . $port . '/');
}

function ipmiProxyGetClientXAuthToken(): string
{
    $t = trim((string) ($_SERVER['HTTP_X_AUTH_TOKEN'] ?? ''));
    if ($t !== '') {
        return $t;
    }
    if (function_exists('getallheaders')) {
        foreach (getallheaders() as $name => $value) {
            if (strcasecmp((string) $name, 'X-Auth-Token') === 0) {
                return trim((string) $value);
            }
        }
    }

    return '';
}

/**
 * Browser sends Origin: https://panel-host; many BMCs reject that and return 403 on API/SSE/CSS.
 * The SPA may also hold a fresher X-Auth-Token than the DB after client-side login.
 *
 * @param array<string, string> $forwardHeaders
 * @return array<string, string>
 */
function ipmiProxyMergeClientBmcForwardHeaders(array $forwardHeaders, string $bmcScheme, string $bmcIp, array $cookieJar = []): array
{
    $out = $forwardHeaders;
    $xAuth = ipmiProxyGetClientXAuthToken();
    if ($xAuth === '') {
        foreach (['sessionKey', 'session', 'X-Auth-Token', 'x-auth-token'] as $k) {
            $v = trim((string) ($cookieJar[$k] ?? ''));
            if ($v !== '') {
                $xAuth = $v;
                break;
            }
        }
    }
    if ($xAuth !== '') {
        $out['X-Auth-Token'] = $xAuth;
    }
    $bmcScheme = ($bmcScheme === 'http') ? 'http' : 'https';
    $out['Origin'] = $bmcScheme . '://' . ipmiProxyBmcPreferredOriginHost($bmcIp);

    return $out;
}

/**
 * Sync Origin / X-Auth-Token for streamed BMC requests; for iLO, verify / repair JSON session before SSE.
 */
function ipmiProxyRecoverBmcAuthBeforeSse(array &$session, mysqli $mysqli, string $token, string $bmcIp, string &$bmcScheme, array &$fwdHdr, string $traceId = ''): void
{
    $bmcScheme = (($session['bmc_scheme'] ?? 'https') === 'http') ? 'http' : 'https';
    $typeNorm = ipmiWebNormalizeBmcType((string) ($session['bmc_type'] ?? 'generic'));
    if (ipmiWebIsNormalizedIloType($typeNorm)) {
        $baseUrl = $bmcScheme . '://' . $bmcIp;
        $v = ipmiWebIloVerifyAuthed(
            $baseUrl,
            $bmcIp,
            is_array($session['cookies'] ?? null) ? $session['cookies'] : [],
            is_array($session['forward_headers'] ?? null) ? $session['forward_headers'] : []
        );
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_sse_precheck', [
                'trace'    => $traceId,
                'verified' => $v ? 1 : 0,
            ]);
        }
        if (!$v) {
            $ssePreState = ipmiProxyIloBootstrapStateLoad($session);
            $ssePreDecision = ['kind' => 'hard', 'reason' => 'sse_precheck_failed'];
            if (!ipmiProxyIloCanAttemptAnotherRefresh($ssePreState, $ssePreDecision)) {
                if (ipmiProxyDebugEnabled()) {
                    ipmiProxyDebugLog('ilo_refresh_attempt_suppressed_due_to_recent_failure', [
                        'trace'  => $traceId,
                        'gate'   => 'sse_precheck',
                        'reason' => 'refresh_budget',
                    ]);
                }
            } else {
                $ssePreState = ipmiProxyIloBootstrapBeginRefreshBudget($mysqli, $token, $session, $ssePreState, $traceId);
                ipmiProxyIloRuntimeAuthRefresh($mysqli, $token, $session, $bmcIp, $traceId, 'sse_precheck_failed');
            }
        }
    }
    $fwdHdr = ipmiProxyMergeClientBmcForwardHeaders(
        is_array($fwdHdr) ? $fwdHdr : [],
        $bmcScheme,
        $bmcIp,
        is_array($session['cookies'] ?? null) ? $session['cookies'] : []
    );
}

/**
 * Long-lived Server-Sent Events (and similar) must be streamed. Buffering the full response
 * in PHP (CURLOPT_RETURNTRANSFER) blocks until the BMC closes the stream → endless "loading".
 */
function ipmiProxyShouldStreamBmcRequest(string $method, string $bmcPath): bool
{
    if ($method !== 'GET') {
        return false;
    }

    return ipmiProxyIsBmcLongPollOrStreamPath($bmcPath);
}

function ipmiProxyEmitHealthPollFallbackJson(): void
{
    http_response_code(200);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    echo '{}';
}

function ipmiProxyEmitSseRetryHint(): void
{
    http_response_code(200);
    header('Content-Type: text/event-stream');
    header('Cache-Control: no-cache');
    header('X-Accel-Buffering: no');
    echo "retry: 5000\n\n";
    if (ob_get_level() > 0) {
        @ob_flush();
    }
    flush();
}

/**
 * For static asset transport failures, avoid hard 502 responses that break the whole BMC UI shell.
 * We only provide safe fallbacks for non-executable assets (css/fonts/images), never JS.
 */
function ipmiProxyTryEmitStaticFallback(string $bmcPath): bool
{
    $path = strtolower((string) parse_url($bmcPath, PHP_URL_PATH));
    if ($path === '') {
        return false;
    }
    $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
    if ($ext === '') {
        return false;
    }

    // Fonts/maps: no-content is acceptable and avoids noisy 502s.
    if (in_array($ext, ['woff', 'woff2', 'ttf', 'eot', 'otf', 'map'], true)) {
        http_response_code(204);
        header('Cache-Control: private, max-age=120');
        return true;
    }

    if ($ext === 'css') {
        http_response_code(200);
        header('Content-Type: text/css; charset=utf-8');
        header('Cache-Control: private, max-age=120');
        echo "/* ipmi-proxy fallback css: upstream asset unavailable */\n";
        return true;
    }

    if ($ext === 'svg') {
        http_response_code(200);
        header('Content-Type: image/svg+xml; charset=utf-8');
        header('Cache-Control: private, max-age=120');
        echo '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>';
        return true;
    }

    if (in_array($ext, ['png', 'gif', 'webp'], true)) {
        http_response_code(200);
        header('Content-Type: image/png');
        header('Cache-Control: private, max-age=120');
        // 1x1 transparent PNG
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=');
        return true;
    }

    if (in_array($ext, ['jpg', 'jpeg'], true)) {
        http_response_code(200);
        header('Content-Type: image/jpeg');
        header('Cache-Control: private, max-age=120');
        // 1x1 white JPEG
        echo base64_decode('/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBxAQEBAQEA8PEA8QDw8PDw8PDw8QEA8QFREWFhURFRUYHSggGBolGxUVITEhJSkrLi4uFx8zODMsNygtLisBCgoKDQ0NFQ8PFSsdFR0rKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrK//AABEIAAEAAQMBIgACEQEDEQH/xAAXAAEBAQEAAAAAAAAAAAAAAAAAAQID/8QAFhEBAQEAAAAAAAAAAAAAAAAAAAER/9oADAMBAAIQAxAAAAHkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/Z');
        return true;
    }

    if ($ext === 'ico') {
        http_response_code(204);
        header('Cache-Control: private, max-age=120');
        return true;
    }

    return false;
}

/**
 * Stream SSE or long-poll JSON from the BMC. Aborts before sending bytes if status is 401/403/502/503 (502/503: recoverable upstream — proxy may refresh auth and retry once).
 *
 * @return array{ok: bool, auth_rejected: bool, applied_resolve: bool, curl_errno?: int, curl_error?: string, sse_recoverable_http?: bool, sse_recover_http_code?: int}
 */
function ipmiProxyStreamGetBmcResponse(string $bmcUrl, array $cookies, array $forwardHeaders, string $bmcIp, bool $skipHostnameResolve = false): array
{
    $streamPath = strtolower((string) (parse_url($bmcUrl, PHP_URL_PATH) ?? ''));
    $defaultStreamCt = (str_contains($streamPath, '/json/health') || str_contains($streamPath, 'health_summary'))
        ? 'application/json; charset=utf-8'
        : 'text/event-stream';

    $ch = curl_init($bmcUrl);
    $appliedResolve = false;
    if (!$skipHostnameResolve) {
        $appliedResolve = ipmiProxyApplyCurlBmcUrlAndResolve($ch, $bmcUrl, $bmcIp);
    }
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
    curl_setopt($ch, CURLOPT_TIMEOUT, 0);
    // SSE and some BMC long-polls are unreliable over HTTP/2 with libcurl; iLO uses HTTP/1.1 in practice.
    if (defined('CURL_HTTP_VERSION_1_1')) {
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    }
    curl_setopt($ch, CURLOPT_USERAGENT, ipmiWebCurlUserAgent());
    curl_setopt($ch, CURLOPT_HTTPGET, true);
    ipmiProxyApplyCurlBmcReferer($ch, $bmcUrl, $forwardHeaders, $bmcIp);

    $parts = [];
    foreach ($cookies as $k => $v) {
        if ($v !== null && trim((string) $v) !== '') {
            $parts[] = $k . '=' . $v;
        }
    }
    $reqH = ['Accept-Encoding: identity'];
    $acc = (string) ($_SERVER['HTTP_ACCEPT'] ?? '');
    if ($acc !== '') {
        $reqH[] = 'Accept: ' . $acc;
    }
    foreach ($forwardHeaders as $hn => $hv) {
        $hn = trim((string) $hn);
        if ($hn === '' || strcasecmp($hn, 'Content-Type') === 0) {
            continue;
        }
        if ($hv === null || trim((string) $hv) === '') {
            continue;
        }
        $reqH[] = $hn . ': ' . $hv;
    }
    if ($parts !== []) {
        $reqH[] = 'Cookie: ' . implode('; ', $parts);
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $reqH);

    $lines = [];
    $headersSent = false;
    $authRejected = false;
    $sseRecoverableHttp = false;
    $sseRecoverableHttpCode = 0;
    curl_setopt($ch, CURLOPT_HEADERFUNCTION, function ($curl, $headerLine) use (&$lines, &$headersSent, &$authRejected, &$sseRecoverableHttp, &$sseRecoverableHttpCode, $defaultStreamCt): int {
        if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/', $headerLine, $hm)) {
            $code = (int) $hm[1];
            if ($code === 401 || $code === 403) {
                $authRejected = true;

                return 0;
            }
            if ($code === 502 || $code === 503) {
                $sseRecoverableHttp = true;
                $sseRecoverableHttpCode = $code;

                return 0;
            }
        }
        // HTTP/2 pseudo-header from libcurl
        if (preg_match('/^:\s*status:\s*(\d{3})\b/i', trim((string) $headerLine), $hm)) {
            $code = (int) $hm[1];
            if ($code === 401 || $code === 403) {
                $authRejected = true;

                return 0;
            }
            if ($code === 502 || $code === 503) {
                $sseRecoverableHttp = true;
                $sseRecoverableHttpCode = $code;

                return 0;
            }
        }
        if ($headerLine === "\r\n" || $headerLine === "\n") {
            if (!$headersSent && $lines !== []) {
                $block = implode('', $lines);
                $lines = [];
                $code = 200;
                if (preg_match('/^HTTP\/\S+\s+(\d{3})\b/m', $block, $m)) {
                    $code = (int) $m[1];
                } elseif (preg_match('/^:\s*status:\s*(\d{3})\b/im', $block, $m)) {
                    $code = (int) $m[1];
                }
                http_response_code($code);
                $ct = $defaultStreamCt;
                if (preg_match('/^Content-Type:\s*([^\r\n]+)/mi', $block, $cm)) {
                    $ct = trim($cm[1]);
                }
                header('Content-Type: ' . $ct);
                header('Cache-Control: no-cache');
                header('X-Accel-Buffering: no');
                if (function_exists('apache_setenv')) {
                    @apache_setenv('no-gzip', '1');
                }
                $headersSent = true;
            } else {
                $lines = [];
            }

            return strlen($headerLine);
        }
        $lines[] = $headerLine;

        return strlen($headerLine);
    });

    curl_setopt($ch, CURLOPT_WRITEFUNCTION, static function ($curl, $data): int {
        echo $data;
        if (ob_get_level() > 0) {
            @ob_flush();
        }
        flush();

        return strlen($data);
    });

    $ok = curl_exec($ch);
    $curlErr = ($ok === false);
    $curlErrNo = $curlErr ? curl_errno($ch) : 0;
    $curlErrStr = $curlErr ? curl_error($ch) : '';
    curl_close($ch);

    if ($authRejected) {
        return ['ok' => false, 'auth_rejected' => true, 'applied_resolve' => $appliedResolve];
    }
    if ($sseRecoverableHttp) {
        return [
            'ok'                   => false,
            'auth_rejected'        => false,
            'applied_resolve'      => $appliedResolve,
            'sse_recoverable_http' => true,
            'sse_recover_http_code' => $sseRecoverableHttpCode,
        ];
    }
    if ($curlErr) {
        return [
            'ok'               => false,
            'auth_rejected'    => false,
            'applied_resolve'  => $appliedResolve,
            'curl_errno'       => $curlErrNo,
            'curl_error'       => $curlErrStr,
        ];
    }

    return ['ok' => true, 'auth_rejected' => false, 'applied_resolve' => $appliedResolve];
}

/**
 * Overlay Cookie header from the browser for keys we already store (mirrored BMC cookies).
 * Keeps client and server jars aligned after Set-Cookie mirror.
 */
function ipmiProxyMergeClientBmcCookies(array $dbCookies, string $bmcType = ''): array
{
    if ($dbCookies === []) {
        return $dbCookies;
    }
    $typeNorm = ipmiWebNormalizeBmcType((string) $bmcType);
    $raw = (string)($_SERVER['HTTP_COOKIE'] ?? '');
    if ($raw === '') {
        return $dbCookies;
    }
    $out = $dbCookies;
    $blockOverride = [];
    if ($typeNorm === 'supermicro' || $typeNorm === 'ami') {
        // Keep critical auth cookies from being overwritten, but allow JS-set cookies (e.g. QSESSIONID)
        // to be added so the SPA doesn't logout immediately.
        $blockOverride = ['sid' => true, 'sessionid' => true, 'session_id' => true, 'session' => true];
    }
    foreach (explode(';', $raw) as $chunk) {
        $chunk = trim($chunk);
        if ($chunk === '') {
            continue;
        }
        $eq = strpos($chunk, '=');
        if ($eq === false) {
            continue;
        }
        $name = trim(substr($chunk, 0, $eq));
        $value = trim(substr($chunk, $eq + 1));
        if ($name === '' || $value === '') {
            continue;
        }
        if (strcasecmp($name, 'PHPSESSID') === 0) {
            continue;
        }
        if ($typeNorm === 'supermicro' || $typeNorm === 'ami') {
            $lname = strtolower($name);
            if (isset($blockOverride[$lname])) {
                continue;
            }
        }
        if (array_key_exists($name, $out)) {
            if ($typeNorm === 'ami') {
                $out[$name] = $value;
                continue;
            }
            // Only override if server-side cookie is missing/invalid.
            if (!ipmiWebIsAuthValueUsable($out[$name])) {
                $out[$name] = $value;
            }
        } elseif ($typeNorm === 'supermicro' || $typeNorm === 'ami') {
            // Allow adding new cookies for Supermicro/ASRockRack/AMI SPA flows.
            $out[$name] = $value;
        }
    }

    return $out;
}
