<?php
/**
 * Opt-in debug for ipmi_proxy.php.
 *
 * Enable via any of:
 * - config: define('IPMI_PROXY_DEBUG', true);
 * - env: IPMI_PROXY_DEBUG=1
 * - cookie: ipmi_proxy_debug=1 (set automatically for 24h when you open with ?ipmi_proxy_debug=1)
 * - query: ?ipmi_proxy_debug=1 on the proxied URL (stripped before forwarding to the BMC)
 *
 * Logs to PHP error_log; sends X-IPMI-Proxy-Trace for correlation.
 * Browser: console.group on HTML pages; X-IPMI-Proxy-Debug-Log (base64 JSON) on all responses where headers are still mutable.
 * Does not log cookie values or full proxy tokens.
 *
 * KVM / WebSocket oriented events include: kvm_plan_cache_hit, kvm_plan_cache_miss,
 * kvm_plan_recomputed, kvm_plan_recomputed_after_stall (via ?ipmi_kvm_replan=1 on proxy URL),
 * kvm_plan_recomputed_after_auth_drift, kvm_plan_reused_after_shell_success,
 * kvm_launch_plan_selected, bmc_response_host_rewrite, ilo_/idrac_/supermicro_ console
 * progression events, ipmi_ws_relay_client_open / ipmi_ws_relay:* error_log lines when relay debug is on.
 * iLO SPA/runtime continuity: ilo_runtime_request_classified, ilo_runtime_recovery_decision,
 * ilo_runtime_recovery_attempt, ilo_runtime_retry_executed, ilo_runtime_final_result,
 * ilo_runtime_preflight_* (cache_hit / cache_miss / session_info_ok / bootstrap_ok / auth_refreshed),
 * ilo_runtime_sse_precheck, ilo_runtime_auth_refresh_*, ilo_runtime_sse_retry, ilo_runtime_final_failure,
 * ilo_retry_request_state_rebuilt, ilo_retry_using_fresh_forward_headers, ilo_retry_using_fresh_cookies,
 * ilo_runtime_session_reloaded_after_refresh, ilo_runtime_auth_persisted, ilo_soft_auth_failure_detected.
 * KVM plan: kvm_plan_cache_hit (scope db|request), kvm_plan_cache_miss, kvm_plan_cache_expired — DB-backed TTL cache in session _m metadata.
 * Blank-SPA diagnosis: blank_ui_cause / precheck_blank_ui / still_soft_auth — see ipmiProxyIloBlankUiCause in ipmi_proxy.php.
 * failure_axis (unified bucket): soft_auth | hard_http_auth | upstream_transport | auth_refresh_exhausted |
 * fragment_bootstrap_soft | sse_auth_drift | sse_transport | hard_failure | bootstrap_semantic —
 * plus mitigates_stale_retry_headers on rebuild logs.
 * iLO SPA bootstrap lifecycle (session _m.ilo_bootstrap): ilo_bootstrap_state_loaded, ilo_bootstrap_state_updated,
 * ilo_bootstrap_state_{healthy,degraded,stalled}, ilo_path_role_classified, ilo_bootstrap_critical_path_detected,
 * ilo_bootstrap_request_executed | ilo_bootstrap_recovery_decision | ilo_bootstrap_retry_executed | ilo_bootstrap_finalized,
 * ilo_shell_loaded_spa_stalled, ilo_bootstrap_health_{positive,negative}_signal, ilo_bootstrap_semantic_failure_detected,
 * ilo_fragment_shape_unexpected, ilo_runtime_json_semantically_broken,
 * ilo_bootstrap_preflight_{started,cache_hit,auth_ok,fragment_ok,degraded,refreshed_auth},
 * ilo_sse_health_{positive,negative}, ilo_sse_recovered_after_refresh, ilo_sse_still_failing_after_refresh,
 * ilo_refresh_attempt_suppressed_due_to_recent_failure, ilo_refresh_attempt_recorded, ilo_refresh_budget_exhausted.
 * iLO path roles (session-aware): HTML elevation requires a structural heuristic signal (name/keyword/repeat/promoted), not time-only;
 * ilo_bootstrap_context_window_active, ilo_role_heuristic_summary (native_console_context, native_ctx_match, secondary_promotion on helper paths), ilo_bootstrap_role_finalized,
 * ilo_html_fragment_heuristic_{positive,negative}, ilo_path_role_{elevated_by_context,not_elevated_after_context_check},
 * ilo_bootstrap_html_fragment_detected, ilo_html_fragment_promoted_to_bootstrap_critical, ilo_path_missed_as_bootstrap_critical,
 * ilo_path_excluded_as_static_asset, ilo_bootstrap_api_detected, ilo_observed_path_{recorded,promoted,expired},
 * ilo_observed_path_promotion_skipped, ilo_path_promoted_by_observation, ilo_bootstrap_recovery_guardrail_applied,
 * ilo_fragment_{shape_unexpected,returned_full_shell}, ilo_api_response_bootstrap_broken,
 * ilo_bootstrap_state_updated_from_role, ilo_path_contributed_to_bootstrap_health, ilo_bootstrap_recovery_role_used.
 * iLO final-stage console readiness (browser + server correlation): ilo_console_readiness_verdict, ilo_console_readiness_server_updated,
 * ilo_transport_evidence_detected, ilo_console_transport_started, ilo_session_ready_evidence_detected, ilo_console_session_ready,
 * ilo_renderer_container_detected (vs renderer_detected), ilo_loading_state_{detected,persisted}, ilo_loading_spinner_persisted,
 * ilo_renderer_without_{transport,session_ready}, ilo_console_stuck_loading, ilo_console_startup_stall_correlated,
 * ilo_stuck_loading_escalation_{allowed,attempted,skipped}, ilo_stuck_loading_finalized, ilo_console_interactive_confirmed,
 * ilo_console_interactive_likely_while_loading (heuristic only, not success),
 * ilo_console_startup_helper_{seen,ok,failed}.
 * iLO /index.html speculative shell launch discovery: speculative_shell_autolaunch in PLAN, ilo_shell_autolaunch_allowed,
 * ilo_launch_discovery_started, ilo_launch_menu_expanded, ilo_launch_surface_found, ilo_launch_function_found,
 * ilo_launch_function_invocation_{attempted,succeeded,failed}, ilo_launch_control_found (deep_scan / console_href),
 * ilo_launch_triggered, ilo_launch_navigation_triggered, ilo_launch_discovery_escalation_{allowed,attempted,failed,skipped},
 * ilo_launch_frame_candidate_found, ilo_console_frame_candidate_{detected,followed,rejected}, ilo_frame_contains_launch_surface,
 * ilo_frame_subdocument_launch_control (clickable control found inside same-origin iframe),
 * ilo_shell_only_ui_detected, ilo_white_screen_stall_detected, ilo_launch_action_no_effect,
 * ilo_launch_{pre_snapshot,post_snapshot,snapshot_diff}, ilo_launch_function_{budget_available,budget_spent,budget_exhausted,retry_allowed,retry_denied},
 * ilo_launch_function_{effective,no_effect,invocation_returned,context_checked}, ilo_launch_function_present_but_context_incomplete,
 * ilo_shell_launch_proven_ineffective, ilo_application_path_promotion_{allowed,triggered}, ilo_shell_path_abandoned_for_application,
 * ilo_application_navigation_{triggered,committed,not_committed,failed,no_effect}, ilo_application_{document_loaded,path_active,loaded_white_screen},
 * ilo_application_navigation_no_effect, ilo_white_screen_failure_finalized, ilo_launch_function_blocked_by_context,
 * ilo_helper_activity_{without_visible_progress,correlated_with_console_frame},
 * ilo_remote_console_privilege_{message_detected,block_detected,missing,present,block_finalized},
 * ilo_visible_user_{unknown,detected}, ilo_html5_console_{button_found,launch_attempted,launch_no_effect,launch_effective},
 * ilo_launch_blocked_by_privilege, ilo_console_session_continuity_checked,
 * ilo_kvm_debug_matrix (every 4th tick on speculative shell: launch_fn found/effective, shell abandoned, app nav committed/failed, white_screen stall, live display, transport, privilege_verdict/block/user, html5_button/launch/effective, strong_confirmation_ready + why),
 * ilo_no_launch_target_found, ilo_launch_discovery_failed, ilo_stalled_before_transport (discovery:1 / white_screen:1),
 * ilo_console_readiness_reclassified, ilo_console_start_failed_no_launch_target, ilo_launch_discovery_server_finalized,
 * session _m.ilo_launch_discovery (ipmiProxyIloLaunchDiscoveryState* / ipmiProxyIloLaunchDiscoveryReadinessVerdict),
 * ilo_launch_helper_{seen,aided_discovery,seen_but_no_target_found}, ilo_launch_discovery_server_updated.
 * WebSocket relay (server error_log, when IPMI_PROXY_DEBUG): ipmi_ws_relay_request_received, ipmi_ws_relay_browser_handshake_{started,succeeded,failed,accepting},
 * ipmi_ws_relay_upstream_{connect_started,tls_connected,tls_failed,tcp_connected,upstream_ws_handshake_succeeded,upstream_ws_handshake_failed},
 * ipmi_ws_relay_frame_pump_{started,error,idle_timeout,eof}, ipmi_ws_relay_closed, ipmi_ws_relay_relay_environment_unsupported.
 * Browser KVM transport health: ipmi_ws_relay_client_open, ipmi_ws_relay_handshake_ok, ipmi_ws_relay_handshake_error, ipmi_ws_relay_first_frame,
 * ilo_transport_health_{provisional,confirmed,failed}, ilo_transport_{handshake_ok,handshake_failed,frame_flow_started},
 * ilo_strong_confirmation_rejected_transport_unhealthy, ilo_native_console_strongly_confirmed (strong success only after relay frame flow).
 * KVM bugs.txt [FINAL] rewrite: kvm_buglog_final_transport_matrix (aggregate + merged browser snapshot; mirrors transport_* lines when proxy debug on).
 * iLO strict native-console confirmation (capability vs reach vs session vs live display): ilo_confirmation_signals_collected,
 * ilo_confirmation_{weak_only,reached_not_ready,strong}, ilo_confirmation_failed_{shell_only,loading_only},
 * ilo_runtime_js_generation_{started,validated,invalid,fixed} (brace / tail sanity on injected autolaunch; fixed emitted when validation passes;
 *   ilo_runtime_js_invalid_dump_written, ilo_runtime_js_injection_aborted, ilo_runtime_js_safe_fallback_used on stub path;
 *   kvm_autolaunch_inject_summary (inject path flags, js_syntactically_valid yes/no, runtime_patch_injected yes/no, stub vs application.html target),
 *   ilo_kvm_runtime_debug_matrix (browser: js_valid / patch injected / application_path_loaded_now from currentScript + pathLower),
 *   with proxy debug, injected &lt;script&gt; also carries data-ipmi-kvm-js-valid, data-ipmi-kvm-patch-mode, data-ipmi-kvm-js-reason on stub),
 * ilo_application_path_loaded, ilo_application_loaded_shell_only, ilo_console_not_reached_after_application_load,
 * ilo_overview_shell_detected, ilo_management_shell_{detected,still_visible}, ilo_shell_only_visible,
 * ilo_console_module_detected, ilo_console_launch_action_{found,triggered}, ilo_console_content_frame_{visible,followed},
 * ilo_live_console_{visible,display_visible}, ilo_helper_activity_{seen,without_console_transition,correlated_with_console_reach},
 * ilo_helper_success_not_counted_as_console_success, ilo_console_not_reached,
 * ilo_strong_confirmation_{rejected_shell_only,achieved} (visible live console + relay transport required; Overview shell excluded),
 * ilo_live_display_evidence_detected, ilo_console_{canvas_active,viewport_active},
 * ilo_loading_only_state_{present,cleared}, ilo_user_visible_console_success (strong confirmation only).
 * Session _m.ilo_native_console_confirmation: tier, final_debug_verdict, confidence, evidence buckets (server; live display browser-authoritative until optional beacon).
 * KVM delivery (X-IPMI-Proxy-Debug-Log on proxy responses when debug on): kvm_delivery_tier, kvm_native_route_confirmed,
 * kvm_fallback_session_available, kvm_user_facing_mode, kvm_client_diagnostic, kvm_blocked_by_suspend (merged plan + DB; not forwarded to BMC).
 * iLO secondary native-console helpers (e.g. jnlp_template during proven HTML5): ilo_secondary_helper_context_check (verdict/strategy/family/phase),
 * ilo_secondary_helper_context_active, ilo_secondary_console_helper_detected, ilo_jnlp_template_promoted (incl. native_ctx_match),
 * ilo_path_role_classified adds native_console_context for helper paths post-upstream,
 * ilo_secondary_helper_role_finalized, ilo_secondary_helper_promotion_skipped, ilo_secondary_helper_guardrail_applied,
 * ilo_secondary_helper_health_signal, ilo_secondary_console_helper_contributed, ilo_legacy_named_helper_seen_in_html5_flow,
 * ilo_secondary_helper_not_treated_as_legacy_fallback.
 * iLO native console vs auth: ilo_shell_console_capability_analysis_started, ilo_shell_console_capability_html5_marker_found,
 * ilo_shell_console_capability_legacy_marker_found, ilo_shell_console_capability_license_marker_found,
 * ilo_shell_console_capability_result, ilo_launch_surface_found, ilo_launch_surface_missing, ilo_native_console_evidence_summary,
 * ilo_native_console_verdict, ilo_console_capability_declined_native, ilo_autolaunch_suppressed,
 * ilo_autolaunch_suppressed_due_to_no_surface, ilo_autolaunch_suppressed_due_to_budget_exhausted,
 * ilo_autolaunch_suppressed_due_to_hard_blocker, ilo_autolaunch_suppressed_due_to_repeated_transport_failure,
 * ilo_autolaunch_suppressed_due_to_session_bootstrap_unhealthy, ilo_autolaunch_suppressed_due_to_weak_surface_evidence,
 * ilo_autolaunch_suppressed_due_to_capability_gate,
 * ilo_native_launch_marked_unavailable_for_session, ilo_no_transport_after_shell_launch,
 * Surface vs stale bootstrap/SSE: ilo_bounded_launch_allowed_due_to_surface, ilo_bounded_launch_denied_due_to_gate,
 * ilo_current_surface_evidence_applied, ilo_historical_failure_weight_applied, ilo_surface_vs_history_decision,
 * ilo_sse_failures_softened_for_initial_launch, ilo_sse_failures_not_used_as_absolute_block, ilo_sse_failures_block_repeated_launch,
 * ilo_stall_state_soft_reset, ilo_stall_state_retained_due_to_strong_negative_evidence, ilo_state_soft_reset_decision,
 * ilo_fresh_shell_attempt_window_active, ilo_capability_health_separated, ilo_launch_attempt_allowed_despite_degraded_state,
 * ilo_launch_budget_decision, ilo_launch_budget_spent, ilo_surface_present_but_suppressed_reason,
 * ilo_native_transport_evidence_applied,
 * ilo_native_console_verdict_finalized (reasons_csv / blockers_csv / suppression after gates).
 * Debug response header/console: ilo_bootstrap snapshot (phase, sse_fail_streak, refresh_60s, sec_helper_ok/fail, blank_ui_hypothesis,
 * last_event_outcome/path) + ilo_path_role, ilo_path_role_base, ilo_path_bootstrap_critical, ilo_path_role_flags,
 * ilo_path_heuristic_score on final emit. Preflight: ilo_bootstrap_preflight_skip_second_refresh when stall/degraded relogin already ran once in the same preflight.
 */

/** @var list<array{ts: float, event: string, context: array<string, mixed>}>|null */
$GLOBALS['ipmi_proxy_debug_buffer'] = null;

function ipmiProxyDebugEnabled(): bool
{
    if (defined('IPMI_PROXY_DEBUG') && IPMI_PROXY_DEBUG) {
        return true;
    }
    $e = getenv('IPMI_PROXY_DEBUG');
    if ($e === '1' || strcasecmp((string) $e, 'true') === 0) {
        return true;
    }
    if (isset($_COOKIE['ipmi_proxy_debug']) && (string) $_COOKIE['ipmi_proxy_debug'] === '1') {
        return true;
    }
    if (isset($_GET['ipmi_proxy_debug']) && (string) $_GET['ipmi_proxy_debug'] === '1') {
        return true;
    }
    if (isset($_GET['debug']) && (string) $_GET['debug'] === '1') {
        return true;
    }

    return false;
}

/**
 * Remove proxy-only query keys so they are not forwarded to the BMC.
 */
function ipmiProxyDebugStripFromQuery(string $queryString): string
{
    if ($queryString === '') {
        return '';
    }
    parse_str($queryString, $params);
    if (!is_array($params)) {
        return $queryString;
    }
    unset(
        $params['ipmi_proxy_debug'],
        $params['debug'],
        $params['ipmi_proxy_console'],
        $params['ipmi_kvm_auto'],
        $params['ipmi_kvm_legacy'],
        $params['ipmi_kvm_force_html5'],
        $params['ipmi_kvm_stage'],
        $params['ipmi_kvm_unavailable'],
        $params['ipmi_kvm_replan'],
        $params['ipmi_kvm_delivery'],
        $params['ipmi_kvm_native_speculative'],
        $params['ipmi_kvm_fallback']
    );

    return http_build_query($params);
}

/**
 * Set a 24h cookie when ?ipmi_proxy_debug=1 so subrequests (JS/CSS/json) keep logging without the query param.
 */
function ipmiProxyDebugMaybeSetCookie(): void
{
    if (!isset($_GET['ipmi_proxy_debug'])) {
        return;
    }
    $val = (string) $_GET['ipmi_proxy_debug'];
    if ($val !== '1' && $val !== '0' && strcasecmp($val, 'off') !== 0) {
        return;
    }
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443);
    $expires = ($val === '1') ? (time() + 86400) : (time() - 3600);
    $path = '/';
    if (PHP_VERSION_ID >= 70300) {
        setcookie('ipmi_proxy_debug', $val === '1' ? '1' : '0', [
            'expires'  => $expires,
            'path'     => $path,
            'secure'   => $secure,
            'httponly' => false,
            'samesite' => 'Lax',
        ]);
    } else {
        setcookie('ipmi_proxy_debug', $val === '1' ? '1' : '0', $expires, $path, '', $secure, false);
    }
}

function ipmiProxyDebugBufferInit(): void
{
    if ($GLOBALS['ipmi_proxy_debug_buffer'] === null) {
        $GLOBALS['ipmi_proxy_debug_buffer'] = [];
    }
}

/**
 * @param array<string, mixed> $context
 */
function ipmiProxyDebugBufferAppend(string $event, array $context): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    ipmiProxyDebugBufferInit();
    $GLOBALS['ipmi_proxy_debug_buffer'][] = [
        'ts'      => round(microtime(true), 4),
        'event'   => $event,
        'context' => $context,
    ];
}

function ipmiProxyDebugRedactToken(string $token): string
{
    $t = strtolower(trim($token));
    if (strlen($t) <= 8) {
        return '***';
    }

    return '…' . substr($t, -8);
}

/** @param array<string, mixed> $cookies */
function ipmiProxyDebugCookieMeta(array $cookies): array
{
    $names = [];
    foreach ($cookies as $k => $v) {
        if ($v !== null && trim((string) $v) !== '') {
            $names[] = (string) $k;
        }
    }
    sort($names);

    return ['count' => count($names), 'keys' => $names];
}

/**
 * @param array<string, mixed> $context
 */
function ipmiProxyDebugLog(string $event, array $context = []): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    ipmiProxyDebugBufferAppend($event, $context);
    $line = date('c') . ' [ipmi_proxy] ' . $event;
    if ($context !== []) {
        $line .= ' ' . json_encode($context, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
    error_log($line);
}

function ipmiProxyDebugSendTraceHeaders(): string
{
    $id = bin2hex(random_bytes(8));
    header('X-IPMI-Proxy-Debug-Active: 1', false);
    header('X-IPMI-Proxy-Trace: ' . $id, false);

    return $id;
}

/**
 * @return list<array{ts: float, event: string, context: array<string, mixed>}>
 */
function ipmiProxyDebugGetBuffer(): array
{
    if ($GLOBALS['ipmi_proxy_debug_buffer'] === null) {
        return [];
    }

    return $GLOBALS['ipmi_proxy_debug_buffer'];
}

/**
 * Emit X-IPMI-Proxy-Debug-Log (base64 JSON). Call before any response body bytes.
 * Safe to call before SSE (partial log) and again before HTML/JSON (full log) — later call replaces the header.
 *
 * @param array<string, mixed> $extra e.g. ['trace' => $id, 'bmcPath' => $path, 'phase' => 'pre_stream']
 */
function ipmiProxyDebugEmitLogHeader(array $extra = []): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    $buf = ipmiProxyDebugGetBuffer();
    $payload = array_merge([
        'v'      => 1,
        'events' => $buf,
    ], $extra);
    $payload['events'] = $buf;

    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) {
        return;
    }
    $max = 12000;
    if (strlen($json) > $max) {
        $payload['truncated'] = true;
        $payload['events'] = array_slice($buf, 0, 40);
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false || strlen($json) > $max) {
            $json = json_encode([
                'v'         => 1,
                'truncated' => true,
                'error'     => 'payload_too_large',
                'trace'     => $extra['trace'] ?? null,
            ], JSON_UNESCAPED_SLASHES);
        }
    }
    header('X-IPMI-Proxy-Debug-Log: ' . base64_encode((string) $json), true);
}

/**
 * Append a script to HTML so DevTools Console shows the same payload (copy from console or from Network → response headers).
 */
function ipmiProxyDebugAppendConsoleScript(string &$html, string $traceId, string $bmcPath): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    $buf = ipmiProxyDebugGetBuffer();
    $payload = [
        'v'         => 1,
        'trace'     => $traceId,
        'bmcPath'   => $bmcPath,
        'hint'      => 'Copy this object from the console or copy the X-IPMI-Proxy-Debug-Log header (base64) from Network.',
        'events'    => $buf,
    ];
    $json = json_encode($payload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return;
    }
    $script = '<script data-ipmi-proxy-debug="1">'
        . '(function(){try{var P=' . $json . ';'
        . 'console.groupCollapsed("%cIPMI Proxy debug","font-weight:bold;color:#063;background:#dfefff;padding:2px 8px;border-radius:3px");'
        . 'console.log(P);console.groupEnd();'
        . 'if(typeof window.IPMI_PROXY_DEBUG==="undefined")window.IPMI_PROXY_DEBUG=P;'
        . 'try{if(window.top!==window.self){return;}'
        . 'var txt="";try{txt=JSON.stringify(P,null,2);}catch(e1){txt=String(P);} '
        . 'var box=document.getElementById("ipmi-proxy-debug-box");'
        . 'if(!box){box=document.createElement("div");box.id="ipmi-proxy-debug-box";'
        . 'box.style.cssText="position:fixed;right:12px;bottom:12px;z-index:2147483647;'
        . 'width:520px;max-width:90vw;background:#0b1630;color:#dce6ff;border:1px solid #2b3d60;'
        . 'border-radius:8px;box-shadow:0 10px 30px rgba(0,0,0,.35);padding:10px;font-family:monospace;font-size:12px;";'
        . 'var title=document.createElement("div");title.textContent="IPMI Proxy Debug (copy text)";'
        . 'title.style.cssText="font-weight:bold;margin-bottom:6px;";'
        . 'var btn=document.createElement("button");btn.textContent="Copy";'
        . 'btn.style.cssText="float:right;margin-top:-2px;background:#22477a;color:#fff;border:0;border-radius:6px;padding:4px 10px;cursor:pointer;";'
        . 'btn.onclick=function(){try{var ta=document.getElementById(\'ipmi-proxy-debug-text\');ta.select();document.execCommand(\'copy\');}catch(e){}};'
        . 'var ta=document.createElement("textarea");ta.id="ipmi-proxy-debug-text";ta.readOnly=true;'
        . 'ta.style.cssText="width:100%;height:240px;resize:vertical;background:#0f1d3a;color:#dce6ff;border:1px solid #2b3d60;border-radius:6px;padding:6px;";'
        . 'box.appendChild(title);box.appendChild(btn);box.appendChild(ta);document.body.appendChild(box);} '
        . 'var ta2=document.getElementById("ipmi-proxy-debug-text");if(ta2&&ta2.value!==txt){ta2.value=txt;}'
        . '}catch(e2){}'
        . '}catch(e){console.warn("IPMI Proxy debug",e);}})();'
        . '</script>';
    if (stripos($html, '</body>') !== false) {
        $html = preg_replace('~</body>~i', $script . '</body>', $html, 1) ?? ($html . $script);
    } else {
        $html .= $script;
    }
}
