<?php
/**
 * KVM Console launcher.
 * Creates an IPMI web session and redirects to the vendor-specific
 * KVM console path through the reverse proxy.
 */
session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/login_redirect.php';
require_once __DIR__ . '/lib/ipmi_web_session.php';
require_once __DIR__ . '/lib/ipmi_proxy_debug.php';

if (!isset($_SESSION['user_id'])) {
    ipmiRedirectUnauthenticatedToLogin();
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Referrer-Policy: same-origin');

$userId = (int)($_SESSION['user_id'] ?? 0);
$role = (string)($_SESSION['role'] ?? 'user');
$serverId = (int)($_GET['id'] ?? 0);
$requestCsrf = (string)($_GET['csrf_token'] ?? '');
$sessionCsrf = (string)($_SESSION['csrf_token'] ?? '');
$debugProxy = (string)($_GET['ipmi_proxy_debug'] ?? '') === '1'
    || (string)($_GET['debug'] ?? '') === '1';
$error = '';
$launchUrl = null;
$launchPath = null;
$launchPlan = null;

try {
    if ($serverId <= 0) {
        throw new Exception('Missing server ID');
    }
    if ($requestCsrf !== '' && $sessionCsrf !== '' && !hash_equals($sessionCsrf, $requestCsrf)) {
        throw new Exception('Invalid session request token');
    }

    ipmiWebCleanupExpiredSessions($mysqli);
    $sessionData = ipmiWebCreateSession($mysqli, $serverId, $userId, $role, 7200);

    $launchPlan = ipmiWebResolveKvmLaunchPlan($sessionData, $mysqli);
    $launchPath = (string) ($launchPlan['kvm_entry_path'] ?? '/');
    $launchUrl = ipmiWebBuildProxyUrl((string) $sessionData['token'], $launchPath);
    if ($debugProxy) {
      $launchUrl .= (str_contains($launchUrl, '?') ? '&' : '?') . 'ipmi_proxy_debug=1';
      $summary = ipmiWebKvmPlanLogSummary($launchPlan);
      error_log('ipmi_kvm kvm_launch_plan_selected ' . json_encode($summary, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
      ipmiProxyDebugLog('kvm_launch_plan_selected', $summary);
    }
    if (!$debugProxy) {
      header('Location: ' . $launchUrl, true, 302);
      exit();
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

$title = 'KVM Console';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= htmlspecialchars($title, ENT_QUOTES, 'UTF-8') ?></title>
  <link rel="stylesheet" href="assets/panel.css">
</head>
<body class="ipmi-login">
  <main class="ipmi-login-main" style="max-width:780px;margin:40px auto;">
    <section class="ipmi-card" style="padding:28px;">
      <h1 class="ipmi-login-form-title" style="margin-bottom:12px;">KVM Console</h1>
      <?php if ($error !== ''): ?>
      <p class="ipmi-login-error" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
      <?php elseif ($launchUrl): ?>
      <p style="margin:0 0 12px;">Debug mode is enabled. Open the KVM URL below.</p>
      <?php
        $launchUrlReplan = $launchUrl . (str_contains((string) $launchUrl, '?') ? '&' : '?') . 'ipmi_kvm_replan=1';
      ?>
      <p style="margin:0 0 16px;">
        <a href="<?= htmlspecialchars((string) $launchUrl, ENT_QUOTES, 'UTF-8') ?>" class="ipmi-btn ipmi-btn-power" target="_blank" rel="noopener">Open KVM (Debug ON)</a>
      </p>
      <p style="margin:0 0 12px;font-size:13px;opacity:.85;">If native KVM stayed on the vendor shell or stalled, try recomputing the cached launch plan:
        <a href="<?= htmlspecialchars((string) $launchUrlReplan, ENT_QUOTES, 'UTF-8') ?>" target="_blank" rel="noopener">Open with <code>ipmi_kvm_replan=1</code></a>
      </p>
      <p style="margin:0 0 8px;font-size:13px;opacity:.75;">Selected KVM path:</p>
      <input type="text" readonly style="width:100%;padding:8px;border-radius:8px;border:1px solid #1f3550;background:#0f1b2b;color:#cfe6ff;margin-bottom:10px;" value="<?= htmlspecialchars((string) $launchPath, ENT_QUOTES, 'UTF-8') ?>">
      <p style="margin:0 0 8px;font-size:13px;opacity:.75;">Direct debug URL:</p>
      <input type="text" readonly style="width:100%;padding:8px;border-radius:8px;border:1px solid #1f3550;background:#0f1b2b;color:#cfe6ff;" value="<?= htmlspecialchars((string) $launchUrl, ENT_QUOTES, 'UTF-8') ?>">
      <?php if (is_array($launchPlan)): ?>
      <?php $planSum = ipmiWebKvmPlanLogSummary($launchPlan); ?>
      <p style="margin:16px 0 8px;font-size:13px;opacity:.75;">Launch decision (summary):</p>
      <dl style="font-size:13px;line-height:1.5;margin:0 0 14px;padding:12px;border-radius:8px;border:1px solid #1f3550;background:#0a1522;color:#cfe6ff;">
        <dt style="opacity:.75;margin:0;">Raw BMC type</dt><dd style="margin:0 0 8px 0;"><?= htmlspecialchars((string) ($planSum['raw_bmc_type'] ?? ''), ENT_QUOTES, 'UTF-8') ?></dd>
        <dt style="opacity:.75;margin:0;">Vendor family / variant</dt><dd style="margin:0 0 8px 0;"><?= htmlspecialchars((string) ($planSum['vendor_family'] ?? '') . ' / ' . (string) ($planSum['vendor_variant'] ?? ''), ENT_QUOTES, 'UTF-8') ?></dd>
        <dt style="opacity:.75;margin:0;">Plan source</dt><dd style="margin:0 0 8px 0;"><?= htmlspecialchars((string) ($planSum['plan_source'] ?? '') . (isset($planSum['plan_cache_age_sec']) ? ' (cache age ' . (int) $planSum['plan_cache_age_sec'] . 's)' : ''), ENT_QUOTES, 'UTF-8') ?></dd>
        <dt style="opacity:.75;margin:0;">Strategy / mode</dt><dd style="margin:0 0 8px 0;"><?= htmlspecialchars((string) ($planSum['launch_strategy'] ?? '') . ' — ' . (string) ($planSum['mode'] ?? ''), ENT_QUOTES, 'UTF-8') ?></dd>
        <dt style="opacity:.75;margin:0;">Entry / shell / bootstrap paths</dt><dd style="margin:0 0 8px 0;word-break:break-all;"><?= htmlspecialchars((string) ($planSum['kvm_entry_path'] ?? '') . ' | shell: ' . (string) ($planSum['shell_entry'] ?? '') . ' | boot: ' . (string) ($planSum['console_boot'] ?? ''), ENT_QUOTES, 'UTF-8') ?></dd>
        <dt style="opacity:.75;margin:0;">Console ready timeout (ms)</dt><dd style="margin:0 0 8px 0;"><?= (int) ($planSum['console_ready_timeout_ms'] ?? 0) ?></dd>
        <dt style="opacity:.75;margin:0;">Plan markers (bootstrap / transport / interactive)</dt><dd style="margin:0 0 8px 0;word-break:break-word;font-size:12px;"><?= htmlspecialchars(json_encode([
 'bootstrap' => $planSum['bootstrap_markers'] ?? [],
          'transport' => $planSum['transport_markers'] ?? [],
          'interactive' => $planSum['interactive_success_markers'] ?? [],
        ], JSON_UNESCAPED_SLASHES), ENT_QUOTES, 'UTF-8') ?></dd>
        <dt style="opacity:.75;margin:0;">Runtime debug</dt><dd style="margin:0 0 8px 0;font-size:12px;">Open the KVM link with <code>?ipmi_proxy_debug=1</code> (or <code>?debug=1</code>). Browser console: <code>[ipmi-kvm]</code> vendor progression. Server <code>error_log</code>: iLO blank-SPA diagnosis via <code>ilo_runtime_preflight_*</code>, <code>ilo_runtime_auth_refresh_*</code>, <code>ilo_runtime_request_retry</code>, <code>ilo_runtime_sse_retry</code>, <code>ilo_runtime_final_failure</code> (no secrets).</dd>
        <dt style="opacity:.75;margin:0;">Selection note</dt><dd style="margin:0 0 0 0;word-break:break-word;"><?= htmlspecialchars((string) ($planSum['note'] ?? ''), ENT_QUOTES, 'UTF-8') ?></dd>
      </dl>
      <p style="margin:16px 0 8px;font-size:13px;opacity:.75;">Full launch plan JSON:</p>
      <pre style="white-space:pre-wrap;word-break:break-word;font-size:12px;line-height:1.45;padding:12px;border-radius:8px;border:1px solid #1f3550;background:#0a1522;color:#cfe6ff;max-height:420px;overflow:auto;"><?= htmlspecialchars(json_encode($launchPlan, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES, 'UTF-8') ?></pre>
      <?php endif; ?>
      <?php else: ?>
      <p class="ipmi-login-error" role="alert">KVM URL could not be created.</p>
      <?php endif; ?>
      <p style="margin-top:14px;"><a href="index.php" class="ipmi-btn ipmi-btn-refresh">Back to panel</a></p>
    </section>
  </main>
</body>
</html>
