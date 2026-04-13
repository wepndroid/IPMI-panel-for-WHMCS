<?php

/**
 * @param array<string, mixed> $analysis from ipmiWebIloAnalyzeDocumentForLaunchSurface
 */
function ipmiProxyIloHasLaunchSurface(array $analysis): bool
{
    return !empty($analysis['has_launch_surface']);
}

/** @return array<string, mixed> */
function ipmiProxyIloLaunchSurfaceAnalysisFromHtml(string $html): array
{
    return ipmiWebIloAnalyzeDocumentForLaunchSurface($html);
}

/**
 * @param array<string, mixed> $plan  KVM launch plan
 * @param array<string, mixed> $cap   Console capability blob (optional)
 * @param array<string, mixed> $state Bootstrap or session state (optional, unused)
 */
function ipmiProxyIloShouldAttemptAutolaunch(array $plan, array $cap = [], array $state = []): bool
{
    unset($cap, $state);
    if (isset($plan['should_attempt_proxy_autolaunch'])) {
        return !empty($plan['should_attempt_proxy_autolaunch']);
    }

    return !empty($plan['native_launch_viable']);
}

function ipmiProxyIloRecordNativeLaunchFailureReason(mysqli $mysqli, string $token, array &$session, string $reason): void
{
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
        return;
    }
    $reason = substr($reason, 0, 160);
    ipmiWebSessionMetaMutate($mysqli, $token, static function (array &$meta) use ($reason): void {
        $log = is_array($meta['ilo_native_launch_failures'] ?? null) ? $meta['ilo_native_launch_failures'] : ['v' => 1, 'items' => []];
        if ((int) ($log['v'] ?? 0) !== 1) {
            $log = ['v' => 1, 'items' => []];
        }
        $items = is_array($log['items'] ?? null) ? $log['items'] : [];
        $items[] = ['t' => time(), 'r' => $reason];
        $log['items'] = array_slice($items, -8);
        $meta['ilo_native_launch_failures'] = $log;
    });
    if (!isset($session['session_meta']) || !is_array($session['session_meta'])) {
        $session['session_meta'] = [];
    }
    $session['session_meta']['ilo_native_launch_failures'] = $session['session_meta']['ilo_native_launch_failures'] ?? ['v' => 1, 'items' => []];
}

/**
 * @param array<string, mixed> $plan
 * @param array<string, mixed> $session
 */
function ipmiProxyIloShouldSuppressFurtherAutolaunch(array $plan, array $session): bool
{
    if (empty($plan['should_attempt_proxy_autolaunch'])) {
        return true;
    }
    $fail = is_array($session['session_meta']['ilo_native_launch_failures']['items'] ?? null)
        ? $session['session_meta']['ilo_native_launch_failures']['items'] : [];
    $recent = 0;
    $now = time();
    foreach ($fail as $row) {
        if (is_array($row) && ($now - (int) ($row['t'] ?? 0)) < 600) {
            $recent++;
        }
    }

    return $recent >= 5;
}

/**
 * @param array<string, mixed> $plan
 * @param array<string, mixed> $session
 */
function ipmiProxyShouldAbandonSpeculativeShellLaunch(array $session, array $plan): bool
{
    return function_exists('ipmiWebShouldAbandonIloSpeculativeShellLaunch')
        && ipmiWebShouldAbandonIloSpeculativeShellLaunch($session, $plan);
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyDetermineKvmDeliveryTier(array $plan, array $session = []): string
{
    unset($session);

    return (string) ($plan['delivery_tier'] ?? 'panel_controlled_proxy_session');
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyCanOfferControlledFallback(array $plan): bool
{
    return !empty($plan['fallback_session_available'])
        && (string) ($plan['delivery_tier'] ?? '') !== 'kvm_unavailable';
}

/**
 * @param array<string, mixed> $plan
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyFinalizeKvmDeliveryVerdict(array $plan, array $session): array
{
    unset($plan['_kvm_delivery_merged_v1']);

    return ipmiWebKvmLaunchPlanMergeDelivery($plan, $session);
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyShouldUseNativePreferredPath(array $plan): bool
{
    if ((string) ($plan['vendor_family'] ?? '') !== 'ilo') {
        return true;
    }
    $s = (string) ($plan['launch_strategy'] ?? '');

    return $s === 'ilo_application_force_html5' || $s === 'ilo_application_autolaunch' || $s === 'ilo_irc_bootstrap' || $s === 'ilo_rc_info_first';
}

/**
 * @param array<string, mixed> $confirmation from ipmiWebIloNativeConsoleConfirmation
 */
function ipmiProxyStrongNativeConfirmation(array $confirmation): bool
{
    return (string) ($confirmation['final_debug_verdict'] ?? '') === 'native_console_strongly_confirmed';
}

/**
 * @param array<string, mixed> $confirmation
 */
function ipmiProxyRejectWeakShellEvidence(array $confirmation): bool
{
    return !empty($confirmation['shell_only_signal'])
        && (string) ($confirmation['final_debug_verdict'] ?? '') !== 'native_console_strongly_confirmed';
}

/**
 * @param array<string, mixed> $confirmation
 */
function ipmiProxyLooksLikeLiveServerDisplay(array $confirmation): bool
{
    return !empty($confirmation['live_display_confirmed']);
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloLooksLikeShellOnlyStall(array $session): bool
{
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $fv = strtolower((string) ($ld['final_discovery_verdict'] ?? ''));

    return str_contains($fv, 'shell') || str_contains($fv, 'no_effect') || str_contains($fv, 'no_launch');
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyIloLooksLikeWhiteScreenStall(array $session): bool
{
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $fv = strtolower((string) ($ld['final_discovery_verdict'] ?? ''));
    $det = strtolower((string) ($ld['discovery_failure_detail'] ?? ''));

    return str_contains($fv, 'white_screen') || str_contains($det, 'white_screen');
}

/**
 * @return array{reason: string, detail: string}
 */
function ipmiProxyFinalizeNativeLaunchFailure(array $session, string $fallbackDetail = ''): array
{
    if (ipmiProxyIloLooksLikeWhiteScreenStall($session)) {
        return ['reason' => 'white_screen_stall', 'detail' => $fallbackDetail];
    }
    if (ipmiProxyIloLooksLikeShellOnlyStall($session)) {
        return ['reason' => 'shell_only_stall', 'detail' => $fallbackDetail];
    }
    $ld = ipmiProxyIloLaunchDiscoveryStateLoad($session);
    $fv = strtolower((string) ($ld['final_discovery_verdict'] ?? ''));
    if (str_contains($fv, 'no_launch') || str_contains($fv, 'no_effect')) {
        return ['reason' => 'no_launch_target_found', 'detail' => $fallbackDetail];
    }
    $conf = ipmiWebIloNativeConsoleConfirmation($session, []);
    if (empty($conf['transport_started']) && !empty($conf['shell_only_signal'])) {
        return ['reason' => 'transport_never_started', 'detail' => $fallbackDetail];
    }
    if (empty($conf['session_ready']) && !empty($conf['shell_only_signal'])) {
        return ['reason' => 'session_never_ready', 'detail' => $fallbackDetail];
    }

    return ['reason' => 'native_route_missing', 'detail' => $fallbackDetail];
}

/**
 * @param array<string, mixed> $plan
 * @param array<string, mixed> $session
 * @return array<string, mixed>
 */
function ipmiProxyBuildFallbackSessionPlan(array $plan, array $session): array
{
    unset($session);
    $out = $plan;
    $out['user_facing_kvm_mode'] = 'panel_fallback_console';
    $out['delivery_tier'] = 'panel_controlled_proxy_session';
    $out['client_visible_kvm_state'] = 'panel_fallback_console_available';

    return $out;
}

function ipmiProxyCanUseNoVncFallback(): bool
{
    $p = realpath(__DIR__ . '/novnc/vnc_lite.html');

    return $p !== false && is_file($p);
}

/**
 * @param array<string, mixed> $session
 */
function ipmiProxyCanUsePanelHostedSessionFallback(array $session): bool
{
    return isset($session['token']) && preg_match('/^[a-f0-9]{64}$/', (string) $session['token']);
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyFallbackSessionUrl(string $token, string $bmcPath, array $plan): string
{
    $fp = ipmiProxyBuildFallbackSessionPlan($plan, []);

    return ipmiWebBuildProxyUrlWithDelivery($token, $bmcPath, $fp);
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyDetermineVendorKvmOptions(array $plan): array
{
    return [
        'vendor_family'        => (string) ($plan['vendor_family'] ?? ''),
        'console_capability'   => (string) ($plan['console_capability'] ?? ''),
        'native_launch_viable' => !empty($plan['native_launch_viable']),
        'launch_strategy'      => (string) ($plan['launch_strategy'] ?? ''),
    ];
}

/**
 * @param array<string, mixed> $plan
 */
function ipmiProxyDetermineFinalUserFacingKvmMode(array $plan): string
{
    return (string) ($plan['user_facing_kvm_mode'] ?? 'panel_fallback_console');
}

/**
 * Non-blocking banner: session is panel-proxied (Tier B) — native console not strongly confirmed yet.
 */
function ipmiProxyInjectKvmPanelControlledBanner(string $html): string
{
    if (stripos($html, 'data-ipmi-proxy-kvm-panel-controlled') !== false) {
        return $html;
    }
    $patch = '<script data-ipmi-proxy-kvm-panel-controlled="1">'
        . '(function(){try{'
        . 'if(!document||!document.body)return;'
        . 'var q=new URLSearchParams(location.search||"");'
        . 'if(q.get("ipmi_kvm_delivery")!=="panel_controlled")return;'
        . 'var existing=document.getElementById("ipmi-kvm-panel-controlled-banner");'
        . 'if(existing)return;'
        . 'var d=document.createElement("div");d.id="ipmi-kvm-panel-controlled-banner";'
        . 'd.style.cssText="position:fixed;z-index:2147483646;left:14px;top:14px;max-width:520px;background:#142a4a;color:#e2f0ff;border:1px solid #3d6aaa;border-radius:10px;padding:10px 14px;font:12px/1.45 Arial,sans-serif;box-shadow:0 6px 18px rgba(0,0,0,.35)";'
        . 'd.textContent="Panel-proxied BMC session: live vendor KVM is still establishing. If the console stalls, use Debug from ipmi_kvm or open with ipmi_kvm_replan=1. Access stays on the panel; BMC credentials are not exposed.";'
        . 'document.body.appendChild(d);'
        . 'setTimeout(function(){try{d.style.opacity="0";setTimeout(function(){if(d&&d.parentNode){d.parentNode.removeChild(d);}},260);}catch(_e){}},14000);'
        . '}catch(e){}})();</script>';

    return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
}

function ipmiProxyInjectKvmUnavailableHint(string $html): string
{
    if (stripos($html, 'data-ipmi-proxy-kvm-unavailable') !== false) {
        return $html;
    }
    $patch = '<script data-ipmi-proxy-kvm-unavailable="1">'
        . '(function(){try{'
        . 'if(!document||!document.body)return;'
        . 'var q=new URLSearchParams(location.search||"");'
        . 'var hasFlag=(q.get("ipmi_kvm_unavailable")==="1");'
        . 'var existing=document.getElementById("ipmi-kvm-unavailable-banner");'
        . 'if(!hasFlag){if(existing&&existing.parentNode){existing.parentNode.removeChild(existing);}return;}'
        . 'if(existing)return;'
        . 'var d=document.createElement("div");d.id="ipmi-kvm-unavailable-banner";'
        . 'd.style.cssText="position:fixed;z-index:2147483647;right:14px;top:14px;max-width:540px;background:#102546;color:#d8e9ff;border:1px solid #2a4a76;border-radius:10px;padding:12px 14px;font:13px/1.45 Arial,sans-serif;box-shadow:0 8px 22px rgba(0,0,0,.35);opacity:1;transition:opacity .22s ease";'
        . 'd.textContent="KVM is currently unavailable in browser-native mode for this server/firmware. You can still use regular IPMI session features from this page.";'
        . 'document.body.appendChild(d);'
        . 'setTimeout(function(){try{d.style.opacity="0";setTimeout(function(){if(d&&d.parentNode){d.parentNode.removeChild(d);}},260);}catch(_e){}},9000);'
        . '}catch(e){}})();</script>';

    return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
}

function ipmiProxyExtractIloAuthToken(array $cookies, array $forwardHeaders): string
{
    $hdr = trim((string)($forwardHeaders['X-Auth-Token'] ?? ''));
    if ($hdr !== '') {
        return $hdr;
    }
    foreach ($cookies as $name => $value) {
        $n = strtolower((string)$name);
        if ($n === 'sessionkey' || $n === 'x-auth-token') {
            $val = trim((string)$value);
            if ($val !== '') {
                return $val;
            }
        }
    }
    return '';
}
