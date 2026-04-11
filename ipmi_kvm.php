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

    $launchPlan = ipmiWebResolveKvmLaunchPlan($sessionData);
    $launchPath = (string) ($launchPlan['kvm_entry_path'] ?? '/');
    $launchUrl = ipmiWebBuildProxyUrl((string) $sessionData['token'], $launchPath);
    if ($debugProxy) {
      $launchUrl .= (str_contains($launchUrl, '?') ? '&' : '?') . 'ipmi_proxy_debug=1';
      error_log('ipmi_kvm kvm_launch_plan_selected ' . json_encode(ipmiWebKvmPlanLogSummary($launchPlan), JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE));
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
      <p style="margin:0 0 16px;">
        <a href="<?= htmlspecialchars((string) $launchUrl, ENT_QUOTES, 'UTF-8') ?>" class="ipmi-btn ipmi-btn-power" target="_blank" rel="noopener">Open KVM (Debug ON)</a>
      </p>
      <p style="margin:0 0 8px;font-size:13px;opacity:.75;">Selected KVM path:</p>
      <input type="text" readonly style="width:100%;padding:8px;border-radius:8px;border:1px solid #1f3550;background:#0f1b2b;color:#cfe6ff;margin-bottom:10px;" value="<?= htmlspecialchars((string) $launchPath, ENT_QUOTES, 'UTF-8') ?>">
      <p style="margin:0 0 8px;font-size:13px;opacity:.75;">Direct debug URL:</p>
      <input type="text" readonly style="width:100%;padding:8px;border-radius:8px;border:1px solid #1f3550;background:#0f1b2b;color:#cfe6ff;" value="<?= htmlspecialchars((string) $launchUrl, ENT_QUOTES, 'UTF-8') ?>">
      <?php if (is_array($launchPlan)): ?>
      <p style="margin:16px 0 8px;font-size:13px;opacity:.75;">Launch plan (vendor_family / mode / flags):</p>
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
