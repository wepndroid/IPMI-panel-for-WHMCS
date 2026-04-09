<?php
session_start();
include 'config.php';
require_once __DIR__ . '/lib/login_redirect.php';

// If this request came from an active IPMI proxy session, keep navigation
// inside that proxy token path instead of falling back to panel login page.
$proxyRef = trim((string)($_SERVER['HTTP_REFERER'] ?? ''));
if ($proxyRef !== '' && preg_match('#/ipmi_proxy\.php/([a-f0-9]{64})(?:/|$)#i', $proxyRef, $m)) {
    $proxyToken = strtolower((string)$m[1]);
    if (preg_match('/^[a-f0-9]{64}$/', $proxyToken)) {
        $query = trim((string)($_SERVER['QUERY_STRING'] ?? ''));
        $target = '/ipmi_proxy.php/' . rawurlencode($proxyToken) . '/login.php';
        if ($query !== '') {
            $target .= '?' . $query;
        }
        header('Location: ' . $target, true, 302);
        exit();
    }
}

if (isset($_SESSION['user_id'])) {
    if (isset($_GET['next'])) {
        header('Location: ' . ipmiSafePostLoginNext((string)$_GET['next']), true, 302);
        exit();
    }
    header('Location: index.php');
    exit();
}

if (isset($_GET['next'])) {
    $_SESSION['post_login_redirect'] = ipmiSafePostLoginNext((string)$_GET['next']);
} elseif (!isset($_POST['login'])) {
    unset($_SESSION['post_login_redirect']);
}

$error = '';

if (isset($_POST['login'])) {
    $username = trim((string)($_POST['username'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    $stmt = $mysqli->prepare("SELECT id, username, role, password FROM users WHERE username = ? OR LOWER(email) = LOWER(?) LIMIT 1");
    $stmt->bind_param("ss", $username, $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result ? $result->fetch_assoc() : null;
    $stmt->close();

    if ($row) {
        if (password_verify($password, $row['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $row['username'];
            $_SESSION['role'] = $row['role'];
            $redirect = 'index.php';
            if (!empty($_SESSION['post_login_redirect'])) {
                $redirect = ipmiSafePostLoginNext((string)$_SESSION['post_login_redirect']);
            }
            unset($_SESSION['post_login_redirect']);
            header('Location: ' . $redirect, true, 302);
            exit();
        } else {
            $error = "Invalid username or password.";
        }
    } else {
        $error = "Invalid username or password.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in — Dedicated Server Panel</title>
    <link rel="stylesheet" href="assets/panel.css">
</head>
<body class="ipmi-login">
  <div class="ipmi-login-split">
    <aside class="ipmi-login-brand">
      <div class="ipmi-login-brand-top">
        <span class="ipmi-login-brand-badge">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5" opacity="0.6"/>
            <path d="M2 12h20M12 2a15 15 0 0 0 0 20M12 2a15 15 0 0 1 0 20" stroke="currentColor" stroke-width="1.5" opacity="0.4"/>
          </svg>
          Dedicated Server Panel
        </span>
      </div>
      <div class="ipmi-login-brand-center">
        <div class="ipmi-login-brand-logo">
          <img src="logo.png" width="300" height="120" alt="IPMI Panel Logo">
        </div>
      </div>
    </aside>

    <main class="ipmi-login-main">
      <form method="post" class="ipmi-login-form" autocomplete="on" id="ipmiLoginForm">
        <header class="ipmi-login-form-head">
          <h1 class="ipmi-login-form-title">Sign in</h1>
          <p class="ipmi-login-form-lead">Welcome back</p>
        </header>

        <?php if ($error !== ''): ?>
          <p class="ipmi-login-error" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
        <?php endif; ?>

        <div class="ipmi-login-field">
          <label for="login-username">Email or Username</label>
          <input id="login-username" type="text" name="username" placeholder="Email or Username" required autofocus autocomplete="username">
        </div>

        <div class="ipmi-login-field">
          <label for="login-password">Password</label>
          <div class="ipmi-login-password-wrap">
            <input id="login-password" type="password" name="password" placeholder="Password" required autocomplete="current-password">
            <button type="button" class="ipmi-login-pw-toggle" id="ipmiPwToggle" aria-label="Show password" aria-pressed="false">
              <span class="ipmi-pw-icon ipmi-pw-icon--show" aria-hidden="true">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                  <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z" stroke="currentColor" stroke-width="2"/>
                  <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/>
                </svg>
              </span>
              <span class="ipmi-pw-icon ipmi-pw-icon--hide" aria-hidden="true">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                  <path d="M17.94 17.94A10 10 0 0 1 12 20c-7 0-11-8-11-8a21 21 0 0 1 4.09-5M9.9 4.24A9 9 0 0 1 12 4c7 0 11 8 11 8a21 21 0 0 1-2.16 3.19M14.12 14.12a3 3 0 1 1-4.24-4.24M1 1l22 22" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                </svg>
              </span>
            </button>
          </div>
        </div>

        <input type="submit" name="login" value="Sign in" class="ipmi-login-submit">

        <footer class="ipmi-login-footer">
          <p class="ipmi-login-footnote">Need access? Ask your administrator to create an account.</p>
        </footer>
      </form>
    </main>
  </div>
  <script>
  (function () {
    var input = document.getElementById('login-password');
    var btn = document.getElementById('ipmiPwToggle');
    if (!input || !btn) return;
    btn.addEventListener('click', function () {
      var willReveal = input.type === 'password';
      input.type = willReveal ? 'text' : 'password';
      btn.classList.toggle('is-revealed', willReveal);
      btn.setAttribute('aria-pressed', willReveal ? 'true' : 'false');
      btn.setAttribute('aria-label', willReveal ? 'Hide password' : 'Show password');
    });
  })();
  </script>
</body>
</html>
