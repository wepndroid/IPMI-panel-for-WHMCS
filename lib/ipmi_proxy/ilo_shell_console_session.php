<?php

/**
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyIloShellVsConsoleStateLoad(array $session): array
{
    $m = $session['session_meta']['ilo_shell_vs_console'] ?? null;

    return is_array($m) ? $m : [];
}

/**
 * @param array<string, mixed> $state
 */
function ipmiProxyIloShellVsConsoleStateStore(mysqli $mysqli, string $token, array $state): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $state = array_slice(array_merge(['v' => 1, 'ts' => time()], $state), 0, 48);
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($state): void {
        $meta['ilo_shell_vs_console'] = $state;
    });
}

/**
 * @param array<string, mixed> $session
 * @param array<string, mixed> $browserSnapshot optional fields from client */
function ipmiProxyIloShellVsConsoleVerdict(array $session, array $browserSnapshot = []): string
{
    $a = array_merge(ipmiProxyIloShellVsConsoleStateLoad($session), $browserSnapshot);
    $v = (string) ($a['final_verdict'] ?? '');

    return $v !== '' ? $v : 'unknown';
}

/**
 * Application-path / shell-vs-console session bucket (alias of ilo_shell_vs_console meta).
 *
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyIloApplicationStateLoad(array $session): array
{
    return ipmiProxyIloShellVsConsoleStateLoad($session);
}

/**
 * @param array<string, mixed> $state
 */
function ipmiProxyIloApplicationStateStore(mysqli $mysqli, string $token, array $state): void
{
    ipmiProxyIloShellVsConsoleStateStore($mysqli, $token, $state);
}

/**
 * Merge patch into stored application/shell-vs-console state (session meta).
 *
 * @param array<string, mixed> $patch
 */
function ipmiProxyIloApplicationStateUpdate(mysqli $mysqli, string $token, array $patch): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $patch = array_slice($patch, 0, 40);
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($patch): void {
        $prev = (isset($meta['ilo_shell_vs_console']) && is_array($meta['ilo_shell_vs_console']))
            ? $meta['ilo_shell_vs_console'] : [];
        $meta['ilo_shell_vs_console'] = array_slice(array_merge(['v' => 1, 'ts' => time()], $prev, $patch), 0, 48);
    });
}

/**
 * @param array<string, mixed> $session
 * @param array<string, mixed> $browserSnapshot
 */
function ipmiProxyIloApplicationStateVerdict(array $session, array $browserSnapshot = []): string
{
    return ipmiProxyIloShellVsConsoleVerdict($session, $browserSnapshot);
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloShouldRejectShellOnlyAsStrongConfirmation(array $session, array $browserSnapshot = []): bool
{
    $a = array_merge(ipmiProxyIloShellVsConsoleStateLoad($session), $browserSnapshot);
    if (!empty($a['live_console_visible'])) {
        return false;
    }
    if (!empty($a['management_shell_still_visible'])) {
        return true;
    }
    if (!empty($a['overview_shell_detected'])) {
        return true;
    }
    if (!empty($a['helper_activity']) && !empty($a['application_loaded_shell_only'])) {
        return true;
    }

    return false;
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloCanStronglyConfirmLiveConsole(array $session, array $browserSnapshot = []): bool
{
    if (ipmiProxyIloShouldRejectShellOnlyAsStrongConfirmation($session, $browserSnapshot)) {
        return false;
    }
    $a = array_merge(ipmiProxyIloShellVsConsoleStateLoad($session), $browserSnapshot);

    return !empty($a['live_console_visible']) && !empty($a['transport_started']);
}

/**
 * Persist a terminal shell-discovery failure into session _m.ilo_launch_discovery (merges with existing state).
 *
 * @param array<string, mixed> $failure keys: reason, detail (optional)
 */
function ipmiProxyIloFinalizeShellDiscoveryFailure(mysqli $mysqli, string $token, array &$session, array $failure, string $traceId = ''): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $reason = substr((string) ($failure['reason'] ?? 'launch_discovery_failed'), 0, 96);
    $ld['final_discovery_verdict'] = $reason;
    $ld['discovery_failed_at'] = time();
    if (isset($failure['detail'])) {
        $ld['discovery_failure_detail'] = substr((string) $failure['detail'], 0, 160);
    }
    ipmiProxyIloLaunchDiscoveryStateStore($mysqli, $token, $session, $ld, $traceId);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_launch_discovery_server_finalized', [
            'verdict' => $reason,
            'detail'  => substr((string) ($failure['detail'] ?? ''), 0, 160),
        ]);
    }
}

/**
 * Combined shell autolaunch discovery readiness (session + optional browser beacon overlay).
 * Distinct from ipmiProxyIloConsoleReadinessVerdict() (startup helper HTTP state).
 *
 * @param array<string, mixed> $session
 * @param array<string, mixed> $browserSnapshot
 */
function ipmiProxyIloLaunchDiscoveryReadinessVerdict(array $session, array $browserSnapshot = []): string
{
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $a = array_merge($ld, $browserSnapshot);
    $v = (string) ($a['final_discovery_verdict'] ?? '');
    if ($v !== '') {
        return $v;
    }
    if (!empty($a['white_screen_stall'])) {
        return 'launch_discovery_failed';
    }
    if (!empty($a['launch_action_no_effect'])) {
        return 'launch_action_no_effect';
    }

    $h = ipmiProxyIloLaunchDiscoveryVerdict($a);
    if ($h !== 'launch_discovery_unknown') {
        return $h;
    }

    return 'launch_discovery_in_progress';
}
