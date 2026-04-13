<?php

/**
 * Loads split ipmi_proxy implementation (function definitions only).
 * Keep require order stable for readability; PHP resolves calls at runtime after all units load.
 */
require_once __DIR__ . '/url_rewrite.php';
require_once __DIR__ . '/html_injection.php';
require_once __DIR__ . '/kvm_js_preamble.php';
require_once __DIR__ . '/kvm_js_ilo_dom.php';
require_once __DIR__ . '/kvm_js_launch_gate.php';
require_once __DIR__ . '/kvm_js_progress.php';
require_once __DIR__ . '/kvm_js_vendor_ilo.php';
require_once __DIR__ . '/kvm_js_vendor_idrac.php';
require_once __DIR__ . '/kvm_js_vendor_supermicro.php';
require_once __DIR__ . '/kvm_js_validate.php';
require_once __DIR__ . '/kvm_js_runtime_assemble.php';
require_once __DIR__ . '/ilo_shell_console_session.php';
require_once __DIR__ . '/kvm_autolaunch_inject.php';
require_once __DIR__ . '/kvm_delivery.php';
require_once __DIR__ . '/response_rewrite.php';
require_once __DIR__ . '/ilo_bootstrap_and_http.php';

