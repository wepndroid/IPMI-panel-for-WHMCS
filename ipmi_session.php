<?php
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
$sessionData = null;

try {
  if ($serverId <= 0) {
    throw new Exception('Missing server ID');
  }
  if ($requestCsrf !== '' && $sessionCsrf !== '' && !hash_equals($sessionCsrf, $requestCsrf)) {
    throw new Exception('Invalid session request token');
  }

  ipmiWebCleanupExpiredSessions($mysqli);
  $sessionData = ipmiWebCreateSession($mysqli, $serverId, $userId, $role, 7200);
} catch (Throwable $e) {
  $error = $e->getMessage();
}

$launchUrl = null;
if ($error === '' && $sessionData) {
  // Launch to vendor-appropriate post-login entry (same class of page as manual login flow).
  $launchPath = ipmiWebPostLoginLandingPath((string) ($sessionData['bmc_type'] ?? 'generic'));
  if (!is_string($launchPath) || $launchPath === '') {
    $launchPath = '/';
  }
  $launchUrl = ipmiWebBuildProxyUrl($sessionData['token'], $launchPath);
  if ($debugProxy) {
    $launchUrl .= (str_contains($launchUrl, '?') ? '&' : '?') . 'ipmi_proxy_debug=1';
  }
  if (!$debugProxy) {
    header('Location: ' . $launchUrl, true, 302);
    exit();
  }
}

$title = 'IPMI Session';
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
      <h1 class="ipmi-login-form-title" style="margin-bottom:12px;">IPMI Session</h1>
      <?php if ($error !== ''): ?>
        <p class="ipmi-login-error" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
        <p>
          <a href="index.php" class="ipmi-btn ipmi-btn-refresh">Back to panel</a>
        </p>
      <?php elseif ($debugProxy && $launchUrl): ?>
        <p style="margin:0 0 12px;">
          Debug mode is enabled. Click below to open the IPMI session with debug logging.
        </p>
        <p style="margin:0 0 16px;">
          <a href="<?= htmlspecialchars($launchUrl, ENT_QUOTES, 'UTF-8') ?>" class="ipmi-btn ipmi-btn-power" target="_blank" rel="noopener">Open IPMI Session (Debug ON)</a>
        </p>
        <div style="background:#0f1b2b;border:1px solid #1f3550;border-radius:10px;padding:12px;margin-bottom:16px;">
          <p style="margin:0 0 8px;font-size:14px;opacity:.9;">After it opens:</p>
          <ol style="margin:0 0 0 18px;padding:0;font-size:14px;opacity:.85;">
            <li>Open DevTools → Console.</li>
            <li>Look for a group named <strong>IPMI Proxy debug</strong>.</li>
            <li>Copy the object (or run <code>copy(window.IPMI_PROXY_DEBUG)</code>).</li>
          </ol>
        </div>
        <p style="margin:0 0 8px;font-size:13px;opacity:.75;">Direct debug URL:</p>
        <input type="text" readonly style="width:100%;padding:8px;border-radius:8px;border:1px solid #1f3550;background:#0f1b2b;color:#cfe6ff;" value="<?= htmlspecialchars($launchUrl, ENT_QUOTES, 'UTF-8') ?>">
        <p style="margin-top:12px;">
          <a href="index.php" class="ipmi-btn ipmi-btn-refresh">Back to panel</a>
        </p>
      <?php else: ?>
        <p class="ipmi-login-error" role="alert">Session could not be created.</p>
        <p><a href="index.php" class="ipmi-btn ipmi-btn-refresh">Back to panel</a></p>
      <?php endif; ?>
    </section>
  </main>
</body>
</html>
