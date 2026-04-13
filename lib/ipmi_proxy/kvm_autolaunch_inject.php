<?php

/**
 * @param array<string, mixed>|string $sessionOrLegacyBmcType Full web session array, or legacy BMC type string (limited plan quality).
 * @param array<string, mixed>|null $injectOut Optional; receives inject outcome: mode full|safe_fallback|skipped_duplicate, js_ok, js_reason, js_depth.
 */
function ipmiProxyInjectKvmAutoLaunchPatch(string $html, string $token, $sessionOrLegacyBmcType, bool $kvmAutoFlow = false, ?array $launchPlan = null, ?mysqli $persistKvmPlanMysqli = null, ?array &$injectOut = null): string
{
    $injectMeta = ['mode' => 'pending', 'js_ok' => null, 'js_reason' => '', 'js_depth' => 0];
    if (stripos($html, 'data-ipmi-proxy-kvm-autolaunch') !== false) {
        $injectMeta = ['mode' => 'skipped_duplicate', 'js_ok' => null, 'js_reason' => '', 'js_depth' => 0];
        if ($injectOut !== null) {
            $injectOut = $injectMeta;
        }

        return $html;
    }
    if (!is_array($sessionOrLegacyBmcType)) {
        $session = [
            'bmc_type'        => (string) $sessionOrLegacyBmcType,
            'ipmi_ip'         => '',
            'bmc_scheme'      => 'https',
            'cookies'         => [],
            'forward_headers' => [],
        ];
    } else {
        $session = $sessionOrLegacyBmcType;
    }
    $plan = $launchPlan ?? ipmiWebResolveKvmLaunchPlan($session, $persistKvmPlanMysqli);
    // Recompute delivery/abandonment against the latest session meta (same request as discovery updates).
    unset($plan['_kvm_delivery_merged_v1']);
    $plan = ipmiWebKvmLaunchPlanMergeDelivery($plan, $session);
    $planSrc = (string) ($plan['debug']['plan_source'] ?? '');
    if (ipmiProxyDebugEnabled()
        && ($planSrc === 'cache_hit_db' || $planSrc === 'request_memo_hit' || str_starts_with($planSrc, 'cache_hit'))) {
        ipmiProxyDebugLog('kvm_plan_reused_after_shell_success', [
            'vendor_family'  => (string) ($plan['vendor_family'] ?? ''),
            'launch_strategy'=> (string) ($plan['launch_strategy'] ?? ''),
        ]);
    }
    $planLite = [
        'kvm_entry_path' => (string) ($plan['kvm_entry_path'] ?? '/'),
        'fallback_path'  => (string) ($plan['fallback_path'] ?? '/'),
        'mode'           => (string) ($plan['mode'] ?? 'fallback'),
        'launch_strategy' => (string) ($plan['launch_strategy'] ?? ''),
        'shell_entry_path' => (string) ($plan['shell_entry_path'] ?? ''),
        'console_bootstrap_path' => (string) ($plan['console_bootstrap_path'] ?? ''),
        'requires_client_bootstrap' => !empty($plan['requires_client_bootstrap']),
        'console_ready_timeout_ms' => (int) ($plan['console_ready_timeout_ms'] ?? 45000),
        'bootstrap_markers' => is_array($plan['bootstrap_markers'] ?? null) ? $plan['bootstrap_markers'] : [],
        'transport_markers' => is_array($plan['transport_markers'] ?? null) ? $plan['transport_markers'] : [],
        'interactive_success_markers' => is_array($plan['interactive_success_markers'] ?? null) ? $plan['interactive_success_markers'] : [],
        'should_attempt_proxy_autolaunch' => !empty($plan['effective_should_attempt_proxy_autolaunch'])
            ? true
            : (!isset($plan['should_attempt_proxy_autolaunch']) || !empty($plan['should_attempt_proxy_autolaunch'])),
        'ilo_native_console_verdict' => (string) ($plan['ilo_native_console_verdict'] ?? ''),
        'console_capability' => (string) ($plan['console_capability'] ?? ''),
        'native_launch_viable' => !empty($plan['native_launch_viable']),
        'autolaunch_suppression_detail' => (string) ($plan['autolaunch_suppression_detail'] ?? ''),
        'speculative_shell_autolaunch' => ((string) ($plan['launch_strategy'] ?? '')) === 'ilo_speculative_shell_autolaunch',
        'delivery_tier' => (string) ($plan['delivery_tier'] ?? ''),
        'user_facing_kvm_mode' => (string) ($plan['user_facing_kvm_mode'] ?? ''),
        'client_visible_kvm_state' => (string) ($plan['client_visible_kvm_state'] ?? ''),
        'speculative_shell_abandoned' => !empty($plan['speculative_shell_abandoned']) ? 1 : 0,
        'preferred_native_path' => (string) ($plan['preferred_native_path'] ?? ''),
    ];
    $familyJs = json_encode((string) ($plan['vendor_family'] ?? 'generic'), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $planJs = json_encode($planLite, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $px = '/ipmi_proxy.php/' . rawurlencode($token);
    $pxJs = json_encode($px, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    $autoJs = $kvmAutoFlow ? 'true' : 'false';
    $dbgLit = ipmiProxyDebugEnabled() ? 'true' : 'false';
    if (ipmiProxyDebugEnabled()
        && (($plan['vendor_family'] ?? '') === 'ilo')
        && empty($plan['should_attempt_proxy_autolaunch'])) {
        $sup = (string) ($plan['autolaunch_suppression_detail'] ?? '');
        $capDbg = (string) ($plan['console_capability'] ?? '');
        $evt = 'ilo_autolaunch_suppressed';
        $ctx = [
            'verdict'    => (string) ($plan['ilo_native_console_verdict'] ?? ''),
            'capability' => $capDbg,
            'strategy'   => (string) ($plan['launch_strategy'] ?? ''),
            'suppression'=> $sup,
        ];
        if ($sup === 'no_launch_surface' || ($sup === '' && str_contains((string) ($plan['ilo_native_console_verdict'] ?? ''), 'not_detected'))) {
            $evt = 'ilo_autolaunch_suppressed_due_to_no_surface';
        } elseif ($sup === 'bounded_launch_budget_exhausted') {
            $evt = 'ilo_autolaunch_suppressed_due_to_budget_exhausted';
        } elseif ($sup === 'hard_blocker_license_or_feature') {
            $evt = 'ilo_autolaunch_suppressed_due_to_hard_blocker';
        } elseif ($sup === 'repeated_transport_or_sse_failure') {
            $evt = 'ilo_autolaunch_suppressed_due_to_repeated_transport_failure';
        } elseif ($sup === 'session_bootstrap_unhealthy') {
            $evt = 'ilo_autolaunch_suppressed_due_to_session_bootstrap_unhealthy';
        } elseif ($sup === 'surface_evidence_below_bounded_threshold') {
            $evt = 'ilo_autolaunch_suppressed_due_to_weak_surface_evidence';
        } elseif ($sup !== '') {
            $evt = 'ilo_autolaunch_suppressed_due_to_capability_gate';
        }
        ipmiProxyDebugLog($evt, $ctx);
        ipmiProxyDebugLog('ilo_native_launch_marked_unavailable_for_session', [
            'verdict' => (string) ($plan['ilo_native_console_verdict'] ?? ''),
            'suppression' => $sup,
        ]);
    }
    $autoLaunchBody = ipmiProxyBuildIloRuntimeJs($familyJs, $planJs, $pxJs, $autoJs, $dbgLit);

    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_js_generation_started', [
            'vendor_family' => (string) ($plan['vendor_family'] ?? ''),
            'bytes'         => strlen($autoLaunchBody),
        ]);
    }
    $jsVal = ipmiProxyValidateGeneratedIloJs($autoLaunchBody);
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog($jsVal['ok'] ? 'ilo_runtime_js_generation_validated' : 'ilo_runtime_js_generation_invalid', [
            'ok'     => $jsVal['ok'] ? 1 : 0,
            'reason' => $jsVal['reason'],
            'depth'  => $jsVal['depth'],
            'bytes'  => $jsVal['bytes'],
        ]);
        if ($jsVal['ok']) {
            ipmiProxyDebugLog('ilo_runtime_js_ready_for_injection', [
                'inject_builder' => 'ilo_runtime_bundle_v1',
                'bytes'          => $jsVal['bytes'],
            ]);
        }
    }

    if (!$jsVal['ok']) {
        ipmiProxyDumpInvalidGeneratedJsContext($autoLaunchBody, (string) $jsVal['reason'], (int) $jsVal['depth'], $token);
        if (ipmiProxyDebugEnabled()) {
            ipmiProxyDebugLog('ilo_runtime_js_injection_aborted', [
                'reason' => $jsVal['reason'],
                'depth'  => $jsVal['depth'],
                'bytes'  => $jsVal['bytes'],
            ]);
            ipmiProxyDebugLog('ilo_runtime_js_safe_fallback_used', [
                'reason' => $jsVal['reason'],
            ]);
        }
        $injectMeta = [
            'mode'       => 'safe_fallback',
            'js_ok'      => false,
            'js_reason'  => (string) $jsVal['reason'],
            'js_depth'   => (int) $jsVal['depth'],
        ];
        $scriptOpen = '<script data-ipmi-proxy-kvm-autolaunch="1" data-ipmi-kvm-js-valid="0" data-ipmi-kvm-patch-mode="safe_fallback"'
            . (ipmiProxyDebugEnabled()
                ? (' data-ipmi-kvm-js-reason="' . htmlspecialchars((string) $jsVal['reason'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"')
                : '')
            . '>';
        $stubBody = '(function(){try{if(typeof console!=="undefined"&&console.warn)console.warn("ilo_runtime_patch_disabled_due_to_invalid_js");}catch(e){}})();';
        $patch = $scriptOpen . $stubBody . '</script>';

        if ($injectOut !== null) {
            $injectOut = $injectMeta;
        }

        return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
    }

    $injectMeta = [
        'mode'      => 'full',
        'js_ok'     => true,
        'js_reason' => '',
        'js_depth'  => 0,
    ];
    if (ipmiProxyDebugEnabled()) {
        ipmiProxyDebugLog('ilo_runtime_js_injected', [
            'vendor_family' => (string) ($plan['vendor_family'] ?? ''),
            'launch_strategy' => (string) ($plan['launch_strategy'] ?? ''),
            'bytes'           => strlen($autoLaunchBody),
        ]);
    }
    $scriptOpen = '<script data-ipmi-proxy-kvm-autolaunch="1" data-ipmi-kvm-js-valid="1" data-ipmi-kvm-patch-mode="full">';
    $patch = $scriptOpen . $autoLaunchBody . '</script>';
    if ($injectOut !== null) {
        $injectOut = $injectMeta;
    }

    return ipmiProxyInjectIntoHtmlHeadOrBody($html, $patch);
}
