<?php
/**
 * API endpoints for WHMCS integration
 * Supports:
 * - status/suspend/unsuspend/power actions
 * - hostname-based server resolution
 * - Accept-Order provisioning (create/reuse user + create/reuse server + assignment)
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../lib/ipmi_service.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-API-Key');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  exit(0);
}

function respond($payload, $statusCode = 200)
{
  http_response_code((int)$statusCode);
  echo json_encode($payload);
  exit;
}

function requestValue($key, $default = '')
{
  if (isset($_POST[$key])) {
    return trim((string)$_POST[$key]);
  }
  if (isset($_GET[$key])) {
    return trim((string)$_GET[$key]);
  }
  return $default;
}

function requestValueRaw($key, $default = '')
{
  if (isset($_POST[$key])) {
    return (string)$_POST[$key];
  }
  if (isset($_GET[$key])) {
    return (string)$_GET[$key];
  }
  return $default;
}

function randomPassword($length = 16)
{
  $length = max(12, (int)$length);
  $raw = bin2hex(random_bytes((int)ceil($length / 2)));
  return substr($raw, 0, $length);
}

function normalizeUsernameFromEmail($email)
{
  $email = strtolower(trim((string)$email));
  if ($email === '') {
    return '';
  }
  // Keep username deterministic and close to email.
  if (strlen($email) > 50) {
    $email = substr($email, 0, 50);
  }
  return $email;
}

function queueBackgroundPowerAction($serverId, $action)
{
  $serverId = (int)$serverId;
  $allowed = ['off', 'on', 'reset'];
  if ($serverId <= 0 || !in_array($action, $allowed, true)) {
    return false;
  }

  $jobPath = realpath(__DIR__ . '/../jobs/power_action.php');
  if (!$jobPath) {
    return false;
  }

  $phpBin = 'php';
  if (defined('PHP_BINARY') && PHP_BINARY) {
    $binName = strtolower(basename((string)PHP_BINARY));
    if (strpos($binName, 'php') !== false) {
      $phpBin = (string)PHP_BINARY;
    }
  }

  $cmd = escapeshellarg($phpBin) . " " . escapeshellarg($jobPath)
    . " --id=" . $serverId
    . " --action=" . escapeshellarg($action)
    . " > /dev/null 2>&1 &";

  shell_exec($cmd);
  return true;
}

function queueBackgroundStatusCheck($serverId, $delaySeconds = 0)
{
  $serverId = (int)$serverId;
  if ($serverId <= 0) {
    return false;
  }

  $jobPath = realpath(__DIR__ . '/../jobs/check_status.php');
  if (!$jobPath) {
    return false;
  }

  $phpBin = 'php';
  if (defined('PHP_BINARY') && PHP_BINARY) {
    $binName = strtolower(basename((string)PHP_BINARY));
    if (strpos($binName, 'php') !== false) {
      $phpBin = (string)PHP_BINARY;
    }
  }

  // Debounce per-server queue bursts (WHMCS can call status multiple times per page flow).
  $kickFile = sys_get_temp_dir() . '/ipmi_status_bg_' . $serverId . '.lastkick';
  $lastKick = is_file($kickFile) ? (int)@file_get_contents($kickFile) : 0;
  if ((time() - $lastKick) < 12) {
    return true;
  }
  @file_put_contents($kickFile, (string)time(), LOCK_EX);

  $delay = max(0, (int)$delaySeconds);
  if ($delay > 0) {
    $cmd = "(sleep " . $delay . "; " . escapeshellarg($phpBin) . " " . escapeshellarg($jobPath)
      . " --id=" . $serverId
      . ") > /dev/null 2>&1 &";
  } else {
    $cmd = escapeshellarg($phpBin) . " " . escapeshellarg($jobPath)
      . " --id=" . $serverId
      . " > /dev/null 2>&1 &";
  }
  shell_exec($cmd);
  return true;
}

function getServerSuspendedFlag($mysqli, $serverId)
{
  $serverId = (int)$serverId;
  if ($serverId <= 0) {
    return 0;
  }
  $stmt = $mysqli->prepare("SELECT suspended FROM server_suspension WHERE server_id = ?");
  if (!$stmt) {
    return 0;
  }
  $stmt->bind_param("i", $serverId);
  $stmt->execute();
  $res = $stmt->get_result();
  $suspended = 0;
  if ($res && $res->num_rows > 0) {
    $suspended = (int)($res->fetch_assoc()['suspended'] ?? 0);
  }
  $stmt->close();
  return $suspended;
}

function getCachedServerStatusRow($mysqli, $serverId)
{
  $serverId = (int)$serverId;
  if ($serverId <= 0) {
    return null;
  }
  $stmt = $mysqli->prepare("
    SELECT power_state, reachable, last_checked, last_error
    FROM server_status
    WHERE server_id = ?
    LIMIT 1
  ");
  if (!$stmt) {
    return null;
  }
  $stmt->bind_param("i", $serverId);
  $stmt->execute();
  $res = $stmt->get_result();
  $row = ($res && $res->num_rows > 0) ? $res->fetch_assoc() : null;
  $stmt->close();
  return $row ?: null;
}

function isCachedStatusStale($lastChecked, $maxAgeSeconds = 45)
{
  $ts = strtotime((string)$lastChecked);
  if ($ts === false || $ts <= 0) {
    return true;
  }
  return (time() - $ts) > max(5, (int)$maxAgeSeconds);
}

function queueBackgroundBmcDetect($serverId)
{
  $serverId = (int)$serverId;
  if ($serverId <= 0) {
    return false;
  }

  $jobPath = realpath(__DIR__ . '/../jobs/detect_bmc_types.php');
  if (!$jobPath) {
    return false;
  }

  $phpBin = 'php';
  if (defined('PHP_BINARY') && PHP_BINARY) {
    $binName = strtolower(basename((string)PHP_BINARY));
    if (strpos($binName, 'php') !== false) {
      $phpBin = (string)PHP_BINARY;
    }
  }

  $cmd = escapeshellarg($phpBin) . ' ' . escapeshellarg($jobPath)
    . ' --ids=' . escapeshellarg((string)$serverId)
    . ' > /dev/null 2>&1 &';

  shell_exec($cmd);
  return true;
}

function upsertServerStatusCache($mysqli, $serverId, $powerState, $reachable = 1, $lastError = '')
{
  $serverId = (int)$serverId;
  $powerState = (string)$powerState;
  $reachable = (int)$reachable;
  $lastError = (string)$lastError;

  $stmt = $mysqli->prepare("
    INSERT INTO server_status (server_id, power_state, reachable, last_checked, last_error)
    VALUES (?, ?, ?, NOW(), ?)
    ON DUPLICATE KEY UPDATE
      power_state = VALUES(power_state),
      reachable = VALUES(reachable),
      last_checked = NOW(),
      last_error = VALUES(last_error)
  ");
  if (!$stmt) {
    return false;
  }
  $stmt->bind_param("isis", $serverId, $powerState, $reachable, $lastError);
  $ok = $stmt->execute();
  $stmt->close();
  return $ok;
}

function authenticateAPI($mysqli)
{
  $apiKey = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['api_key'] ?? null;

  if (!$apiKey) {
    return ['error' => 'API key required', 'code' => 401];
  }

  $stmt = $mysqli->prepare("SELECT * FROM api_keys WHERE api_key = ? AND active = 1");
  $stmt->bind_param("s", $apiKey);
  $stmt->execute();
  $result = $stmt->get_result();
  if ($result->num_rows === 0) {
    $stmt->close();
    return ['error' => 'Invalid API key', 'code' => 401];
  }

  $apiKeyData = $result->fetch_assoc();
  $stmt->close();

  if (!empty($apiKeyData['allowed_ips'])) {
    $allowedIPs = explode(',', $apiKeyData['allowed_ips']);
    $clientIP = $_SERVER['REMOTE_ADDR'] ?? '';
    $allowed = false;

    foreach ($allowedIPs as $ip) {
      $ip = trim((string)$ip);
      if ($ip === '*' || $ip === $clientIP) {
        $allowed = true;
        break;
      }
    }

    if (!$allowed) {
      return ['error' => 'IP address not allowed', 'code' => 403];
    }
  }

  $stmt = $mysqli->prepare("UPDATE api_keys SET last_used = NOW() WHERE id = ?");
  if ($stmt) {
    $stmt->bind_param("i", $apiKeyData['id']);
    $stmt->execute();
    $stmt->close();
  }

  return ['success' => true, 'api_key_data' => $apiKeyData];
}

function resolveServerIdByHostname($mysqli, $hostname, &$error = '', &$statusCode = 400)
{
  $hostname = trim((string)$hostname);
  if ($hostname === '') {
    $error = 'Hostname is required';
    $statusCode = 400;
    return 0;
  }

  $stmt = $mysqli->prepare("SELECT id FROM servers WHERE server_name = ?");
  if (!$stmt) {
    $error = 'Database error';
    $statusCode = 500;
    return 0;
  }
  $stmt->bind_param("s", $hostname);
  $stmt->execute();
  $res = $stmt->get_result();
  $count = $res ? $res->num_rows : 0;

  if ($count === 0) {
    $stmt->close();
    $error = 'Server not found for hostname';
    $statusCode = 404;
    return 0;
  }

  if ($count > 1) {
    $stmt->close();
    $error = 'Duplicate hostname in panel';
    $statusCode = 409;
    return 0;
  }

  $row = $res->fetch_assoc();
  $stmt->close();
  return (int)$row['id'];
}

function ensurePanelUser($mysqli, $email, &$createdUser, &$generatedPassword, &$username)
{
  $createdUser = false;
  $generatedPassword = '';
  $username = '';
  $email = strtolower(trim((string)$email));
  if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    throw new Exception('Valid client email is required');
  }

  $stmt = $mysqli->prepare("SELECT id, username, email FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1");
  if (!$stmt) {
    throw new Exception('Database error while checking user');
  }
  $stmt->bind_param("s", $email);
  $stmt->execute();
  $res = $stmt->get_result();
  if ($res && $res->num_rows > 0) {
    $row = $res->fetch_assoc();
    $stmt->close();
    $existingUserId = (int)$row['id'];
    $currentUsername = trim((string)$row['username']);
    $desiredUsername = $email;
    $username = $currentUsername;

    // Align username with email for consistent client login display/use.
    if ($desiredUsername !== '' && strcasecmp($currentUsername, $desiredUsername) !== 0) {
      $collision = $mysqli->prepare("SELECT id FROM users WHERE username = ? AND id <> ? LIMIT 1");
      if ($collision) {
        $collision->bind_param("si", $desiredUsername, $existingUserId);
        $collision->execute();
        $colRes = $collision->get_result();
        $hasCollision = $colRes && $colRes->num_rows > 0;
        $collision->close();

        if (!$hasCollision) {
          $updUser = $mysqli->prepare("UPDATE users SET username = ? WHERE id = ?");
          if ($updUser) {
            $updUser->bind_param("si", $desiredUsername, $existingUserId);
            if ($updUser->execute()) {
              $username = $desiredUsername;
            }
            $updUser->close();
          }
        }
      }
    }

    return $existingUserId;
  }
  $stmt->close();

  // New users: keep username equal to email (client expectation).
  $candidate = normalizeUsernameFromEmail($email);
  if ($candidate === '') {
    throw new Exception('Unable to derive username from email');
  }
  $check = $mysqli->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
  if (!$check) {
    throw new Exception('Database error while checking username');
  }
  $check->bind_param("s", $candidate);
  $check->execute();
  $checkRes = $check->get_result();
  $exists = $checkRes && $checkRes->num_rows > 0;
  $check->close();
  if ($exists) {
    throw new Exception('Panel username conflict for client email. Please rename existing panel user and retry provisioning.');
  }

  $generatedPassword = randomPassword(16);
  $passwordHash = password_hash($generatedPassword, PASSWORD_DEFAULT);

  $ins = $mysqli->prepare("
    INSERT INTO users (username, email, password, role, created_by)
    VALUES (?, ?, ?, 'user', NULL)
  ");
  if (!$ins) {
    throw new Exception('Database error while creating user');
  }
  $ins->bind_param("sss", $candidate, $email, $passwordHash);
  if (!$ins->execute()) {
    $ins->close();
    throw new Exception('Unable to create panel user');
  }
  $newUserId = (int)$ins->insert_id;
  $ins->close();

  $createdUser = true;
  $username = $candidate;
  return $newUserId;
}

function ensureServerAndAssignment($mysqli, $userId, $hostname, $serverIp, $ipmiIp, $ipmiUser, $ipmiPass, $notes, &$createdServer)
{
  $createdServer = false;
  $hostname = trim((string)$hostname);
  $serverIp = trim((string)$serverIp);
  $ipmiIp = trim((string)$ipmiIp);
  $ipmiUser = trim((string)$ipmiUser);
  // Keep exact password bytes (no trim) to avoid corrupting credentials.
  $ipmiPass = (string)$ipmiPass;
  $notes = trim((string)$notes);

  if ($hostname === '') {
    throw new Exception('Hostname is required');
  }
  if ($ipmiIp === '' || $ipmiUser === '' || $ipmiPass === '') {
    throw new Exception('IPMI IP/User/Password are required');
  }

  $stmt = $mysqli->prepare("SELECT id FROM servers WHERE server_name = ?");
  if (!$stmt) {
    throw new Exception('Database error while checking server hostname');
  }
  $stmt->bind_param("s", $hostname);
  $stmt->execute();
  $res = $stmt->get_result();
  $count = $res ? $res->num_rows : 0;

  if ($count > 1) {
    $stmt->close();
    throw new Exception('Duplicate hostname in panel');
  }

  $encryptedUser = Encryption::normalizeForStorage($ipmiUser, 'ipmi_user');
  $encryptedPass = Encryption::normalizeForStorage($ipmiPass, 'ipmi_pass');

  if ($count === 1) {
    $row = $res->fetch_assoc();
    $serverId = (int)$row['id'];
    $stmt->close();

    $upd = $mysqli->prepare("
      UPDATE servers
      SET server_ip = ?, ipmi_ip = ?, ipmi_user = ?, ipmi_pass = ?, notes = ?
      WHERE id = ?
    ");
    if (!$upd) {
      throw new Exception('Database error while updating server');
    }
    $upd->bind_param("sssssi", $serverIp, $ipmiIp, $encryptedUser, $encryptedPass, $notes, $serverId);
    if (!$upd->execute()) {
      $upd->close();
      throw new Exception('Unable to update existing server');
    }
    $upd->close();
  } else {
    $stmt->close();
    // Hostname not found. Reuse by IPMI IP if already present (prevents duplicate physical targets).
    $byIp = $mysqli->prepare("SELECT id FROM servers WHERE ipmi_ip = ?");
    if (!$byIp) {
      throw new Exception('Database error while checking existing IPMI IP');
    }
    $byIp->bind_param("s", $ipmiIp);
    $byIp->execute();
    $ipRes = $byIp->get_result();
    $ipCount = $ipRes ? $ipRes->num_rows : 0;

    if ($ipCount > 1) {
      $byIp->close();
      throw new Exception('Duplicate IPMI IP already exists in panel');
    }

    if ($ipCount === 1) {
      $row = $ipRes->fetch_assoc();
      $serverId = (int)$row['id'];
      $byIp->close();

      $upd = $mysqli->prepare("
        UPDATE servers
        SET server_name = ?, server_ip = ?, ipmi_ip = ?, ipmi_user = ?, ipmi_pass = ?, notes = ?
        WHERE id = ?
      ");
      if (!$upd) {
        throw new Exception('Database error while updating server by IPMI IP');
      }
      $upd->bind_param("ssssssi", $hostname, $serverIp, $ipmiIp, $encryptedUser, $encryptedPass, $notes, $serverId);
      if (!$upd->execute()) {
        $upd->close();
        throw new Exception('Unable to update existing server by IPMI IP');
      }
      $upd->close();
    } else {
      $byIp->close();
      $ins = $mysqli->prepare("
        INSERT INTO servers (server_name, server_ip, ipmi_ip, ipmi_user, ipmi_pass, status, bmc_type, notes)
        VALUES (?, ?, ?, ?, ?, 'unknown', 'generic', ?)
      ");
      if (!$ins) {
        throw new Exception('Database error while creating server');
      }
      $ins->bind_param("ssssss", $hostname, $serverIp, $ipmiIp, $encryptedUser, $encryptedPass, $notes);
      if (!$ins->execute()) {
        $ins->close();
        throw new Exception('Unable to create server');
      }
      $serverId = (int)$ins->insert_id;
      $ins->close();
      $createdServer = true;
    }
  }

  // Keep dedicated-server ownership unambiguous: reassign server to target user.
  $cleanupAssign = $mysqli->prepare("DELETE FROM user_servers WHERE server_id = ? AND user_id <> ?");
  if ($cleanupAssign) {
    $cleanupAssign->bind_param("ii", $serverId, $userId);
    $cleanupAssign->execute();
    $cleanupAssign->close();
  }

  $assign = $mysqli->prepare("INSERT IGNORE INTO user_servers (user_id, server_id) VALUES (?, ?)");
  if (!$assign) {
    throw new Exception('Database error while assigning server');
  }
  $assign->bind_param("ii", $userId, $serverId);
  if (!$assign->execute()) {
    $assign->close();
    throw new Exception('Unable to assign server to user');
  }
  $assign->close();

  $sus = $mysqli->prepare("
    INSERT INTO server_suspension (server_id, suspended, unsuspended_at, suspension_reason)
    VALUES (?, 0, NOW(), 'Activated via WHMCS')
    ON DUPLICATE KEY UPDATE
      suspended = 0,
      unsuspended_at = NOW(),
      suspension_reason = 'Activated via WHMCS'
  ");
  if ($sus) {
    $sus->bind_param("i", $serverId);
    $sus->execute();
    $sus->close();
  }

  return $serverId;
}

$auth = authenticateAPI($mysqli);
if (isset($auth['error'])) {
  respond($auth, $auth['code'] ?? 401);
}

$ipmiService = new IPMIService($mysqli);

$path = $_SERVER['PATH_INFO'] ?? $_SERVER['REQUEST_URI'] ?? '';
$path = preg_replace('/\?.*$/', '', $path);
$path = preg_replace('#^/api/api\.php#', '', $path);

$serverId = 0;
$action = '';
$hostname = '';

if (preg_match('#/server/(\d+)/([a-zA-Z_]+)#', $path, $matches)) {
  $serverId = (int)$matches[1];
  $action = strtolower((string)$matches[2]);
} elseif (preg_match('#/server/hostname/([^/]+)/([a-zA-Z_]+)#', $path, $matches)) {
  $hostname = urldecode((string)$matches[1]);
  $action = strtolower((string)$matches[2]);
} elseif (preg_match('#^/([a-zA-Z_]+)$#', $path, $matches)) {
  $action = strtolower((string)$matches[1]);
}

if (isset($_GET['server_id'])) {
  $serverId = (int)$_GET['server_id'];
}
if (isset($_GET['hostname'])) {
  $hostname = trim((string)$_GET['hostname']);
}
if (isset($_GET['action'])) {
  $action = strtolower(trim((string)$_GET['action']));
}

$aliases = [
  'power_on' => 'poweron',
  'power_off' => 'poweroff',
  'reset' => 'reboot',
  'resolve_server' => 'resolve',
];
if (isset($aliases[$action])) {
  $action = $aliases[$action];
}

if ($action === '') {
  respond(['error' => 'Action is required'], 400);
}

$postOnlyActions = ['provision', 'suspend', 'unsuspend', 'poweron', 'poweroff', 'reboot'];
if (in_array($action, $postOnlyActions, true) && strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
  respond(['error' => 'This action requires POST method'], 405);
}

// Actions that do not require server_id beforehand.
$noServerIdActions = ['provision', 'resolve'];
if (!in_array($action, $noServerIdActions, true)) {
  if ($serverId <= 0 && $hostname !== '') {
    $resolveError = '';
    $resolveCode = 400;
    $serverId = resolveServerIdByHostname($mysqli, $hostname, $resolveError, $resolveCode);
    if ($serverId <= 0) {
      respond(['error' => $resolveError], $resolveCode);
    }
  }

  if ($serverId <= 0) {
    respond(['error' => 'Invalid server ID'], 400);
  }

  $stmt = $mysqli->prepare("SELECT id FROM servers WHERE id = ?");
  $stmt->bind_param("i", $serverId);
  $stmt->execute();
  $result = $stmt->get_result();
  if ($result->num_rows === 0) {
    $stmt->close();
    respond(['error' => 'Server not found'], 404);
  }
  $stmt->close();
}

try {
  switch ($action) {
    case 'resolve':
      $resolveHost = requestValue('hostname', $hostname);
      $resolveError = '';
      $resolveCode = 400;
      $resolvedId = resolveServerIdByHostname($mysqli, $resolveHost, $resolveError, $resolveCode);
      if ($resolvedId <= 0) {
        respond(['error' => $resolveError], $resolveCode);
      }

      $stmt = $mysqli->prepare("
        SELECT s.id, s.server_name, s.server_ip, s.ipmi_ip, COALESCE(ss.suspended, 0) AS suspended
        FROM servers s
        LEFT JOIN server_suspension ss ON ss.server_id = s.id
        WHERE s.id = ?
      ");
      $stmt->bind_param("i", $resolvedId);
      $stmt->execute();
      $row = $stmt->get_result()->fetch_assoc();
      $stmt->close();

      respond([
        'success' => true,
        'server_id' => (int)$row['id'],
        'server_name' => $row['server_name'],
        'server_ip' => $row['server_ip'],
        'ipmi_ip' => $row['ipmi_ip'],
        'suspended' => (int)$row['suspended'],
      ]);
      break;

    case 'provision':
      if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        respond(['error' => 'Provision requires POST'], 405);
      }

      $email = requestValue('email', requestValue('client_email', ''));
      $hostnameInput = requestValue('hostname', requestValue('server_name', ''));
      $serverIp = requestValue('server_ip', requestValue('dedicated_ip', ''));
      $ipmiIp = requestValue('ipmi_ip', '');
      $ipmiUser = requestValue('ipmi_user', '');
      $ipmiPass = requestValueRaw('ipmi_pass', '');
      $notes = requestValue('notes', 'Provisioned via WHMCS');

      if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        respond(['error' => 'Valid email is required'], 400);
      }
      if ($hostnameInput === '') {
        respond(['error' => 'Hostname is required'], 400);
      }
      if ($ipmiIp === '' || $ipmiUser === '' || $ipmiPass === '') {
        respond(['error' => 'ipmi_ip, ipmi_user and ipmi_pass are required'], 400);
      }

      $createdUser = false;
      $generatedPassword = '';
      $panelUsername = '';
      $createdServer = false;
      $serverId = 0;
      $userId = 0;

      $mysqli->begin_transaction();
      try {
        $userId = ensurePanelUser($mysqli, $email, $createdUser, $generatedPassword, $panelUsername);
        $serverId = ensureServerAndAssignment(
          $mysqli,
          $userId,
          $hostnameInput,
          $serverIp,
          $ipmiIp,
          $ipmiUser,
          $ipmiPass,
          $notes,
          $createdServer
        );
        $mysqli->commit();
      } catch (Exception $e) {
        $mysqli->rollback();
        throw $e;
      }

      // Fast refresh without blocking response.
      queueBackgroundStatusCheck($serverId, 1);
      // Keep bmc_type accurate for vendor-specific runtime command strategy.
      queueBackgroundBmcDetect($serverId);

      respond([
        'success' => true,
        'message' => 'Provision completed',
        'user_id' => $userId,
        'user_created' => $createdUser,
        'panel_username' => $panelUsername,
        'panel_password' => $createdUser ? $generatedPassword : null,
        'server_id' => $serverId,
        'server_created' => $createdServer,
        'hostname' => $hostnameInput,
      ]);
      break;

    case 'status':
      $quick = requestValue('quick', '0') === '1';
      $suspended = getServerSuspendedFlag($mysqli, $serverId);

      if ($quick) {
        $cached = getCachedServerStatusRow($mysqli, $serverId);
        if ($cached) {
          if (isCachedStatusStale($cached['last_checked'] ?? null, 35)) {
            queueBackgroundStatusCheck($serverId, 0);
          }
          respond([
            'success' => true,
            'server_id' => $serverId,
            'power_state' => (string)($cached['power_state'] ?? 'unknown'),
            'reachable' => (int)($cached['reachable'] ?? 0),
            'suspended' => $suspended,
            'last_error' => (string)($cached['last_error'] ?? ''),
            'last_checked' => (string)($cached['last_checked'] ?? ''),
            'cached' => true,
          ]);
        }

        // No cache yet: schedule async check and return immediate placeholder.
        queueBackgroundStatusCheck($serverId, 0);
        respond([
          'success' => true,
          'server_id' => $serverId,
          'power_state' => 'unknown',
          'reachable' => 0,
          'suspended' => $suspended,
          'last_error' => 'Status refresh queued',
          'last_checked' => '',
          'cached' => true,
        ]);
      }

      $status = $ipmiService->checkStatus($serverId);
      respond([
        'success' => true,
        'server_id' => $serverId,
        'power_state' => (string)($status['power_state'] ?? 'unknown'),
        'reachable' => (int)($status['reachable'] ?? 0),
        'suspended' => $suspended,
        'last_error' => (string)($status['last_error'] ?? ''),
        'last_checked' => gmdate('Y-m-d H:i:s'),
        'cached' => false,
      ]);
      break;

    case 'suspend':
      $reason = requestValue('reason', 'Suspended via API');
      $stmt = $mysqli->prepare("
        INSERT INTO server_suspension (server_id, suspended, suspended_at, suspension_reason)
        VALUES (?, 1, NOW(), ?)
        ON DUPLICATE KEY UPDATE
          suspended = 1,
          suspended_at = NOW(),
          suspension_reason = ?,
          unsuspended_at = NULL,
          unsuspended_by = NULL
      ");
      $stmt->bind_param("iss", $serverId, $reason, $reason);
      $stmt->execute();
      $stmt->close();

      $async = !isset($_POST['async']) || $_POST['async'] !== '0';
      if ($async) {
        $queued = queueBackgroundPowerAction($serverId, 'off');
        $powerResult = $queued ? 'queued' : 'queue_failed';
      } else {
        $powerResult = $ipmiService->powerOff($serverId, null);
      }

      respond([
        'success' => true,
        'server_id' => $serverId,
        'message' => 'Server suspended successfully',
        'async' => $async,
        'power_off_result' => $powerResult,
      ]);
      break;

    case 'unsuspend':
      $stmt = $mysqli->prepare("
        INSERT INTO server_suspension (server_id, suspended, unsuspended_at, suspension_reason)
        VALUES (?, 0, NOW(), 'Unsuspended via API')
        ON DUPLICATE KEY UPDATE
          suspended = 0,
          unsuspended_at = NOW(),
          unsuspended_by = NULL
      ");
      $stmt->bind_param("i", $serverId);
      $stmt->execute();
      $stmt->close();

      $powerOn = isset($_POST['power_on']) && $_POST['power_on'] == '1';
      $powerResult = null;
      $async = !isset($_POST['async']) || $_POST['async'] !== '0';
      if ($powerOn) {
        if ($async) {
          $queued = queueBackgroundPowerAction($serverId, 'on');
          $powerResult = $queued ? 'queued' : 'queue_failed';
        } else {
          try {
            $powerResult = $ipmiService->powerOn($serverId, null);
          } catch (Exception $e) {
            $powerResult = 'Error: ' . $e->getMessage();
          }
        }
      }

      respond([
        'success' => true,
        'server_id' => $serverId,
        'message' => 'Server unsuspended successfully',
        'power_on' => $powerOn,
        'async' => $async,
        'power_on_result' => $powerResult,
      ]);
      break;

    case 'poweron':
      $async = !isset($_POST['async']) || $_POST['async'] !== '0';
      if ($async) {
        $queued = queueBackgroundPowerAction($serverId, 'on');
        if (!$queued) {
          respond([
            'error' => 'Failed to queue power on action',
            'server_id' => $serverId,
            'action' => 'power_on',
          ], 500);
        }
        upsertServerStatusCache($mysqli, $serverId, 'unknown', 1, '');
        queueBackgroundStatusCheck($serverId, 2);
        respond([
          'success' => true,
          'server_id' => $serverId,
          'action' => 'power_on',
          'queued' => true,
        ]);
      }

      $result = $ipmiService->powerOn($serverId, null);
      upsertServerStatusCache($mysqli, $serverId, 'on', 1, '');
      queueBackgroundStatusCheck($serverId, 1);
      respond([
        'success' => true,
        'server_id' => $serverId,
        'action' => 'power_on',
        'queued' => false,
        'result' => $result,
      ]);
      break;

    case 'poweroff':
      $async = !isset($_POST['async']) || $_POST['async'] !== '0';
      if ($async) {
        $queued = queueBackgroundPowerAction($serverId, 'off');
        if (!$queued) {
          respond([
            'error' => 'Failed to queue power off action',
            'server_id' => $serverId,
            'action' => 'power_off',
          ], 500);
        }
        upsertServerStatusCache($mysqli, $serverId, 'unknown', 1, '');
        queueBackgroundStatusCheck($serverId, 2);
        respond([
          'success' => true,
          'server_id' => $serverId,
          'action' => 'power_off',
          'queued' => true,
        ]);
      }

      $result = $ipmiService->powerOff($serverId, null);
      upsertServerStatusCache($mysqli, $serverId, 'off', 1, '');
      queueBackgroundStatusCheck($serverId, 1);
      respond([
        'success' => true,
        'server_id' => $serverId,
        'action' => 'power_off',
        'queued' => false,
        'result' => $result,
      ]);
      break;

    case 'reboot':
      $async = !isset($_POST['async']) || $_POST['async'] !== '0';
      if ($async) {
        $queued = queueBackgroundPowerAction($serverId, 'reset');
        if (!$queued) {
          respond([
            'error' => 'Failed to queue reboot action',
            'server_id' => $serverId,
            'action' => 'reboot',
          ], 500);
        }
        upsertServerStatusCache($mysqli, $serverId, 'unknown', 1, '');
        queueBackgroundStatusCheck($serverId, 3);
        respond([
          'success' => true,
          'server_id' => $serverId,
          'action' => 'reboot',
          'queued' => true,
        ]);
      }

      $result = $ipmiService->reboot($serverId, null);
      upsertServerStatusCache($mysqli, $serverId, 'unknown', 1, '');
      queueBackgroundStatusCheck($serverId, 2);
      respond([
        'success' => true,
        'server_id' => $serverId,
        'action' => 'reboot',
        'queued' => false,
        'result' => $result,
      ]);
      break;

    default:
      respond([
        'error' => 'Invalid action',
        'available_actions' => ['resolve', 'provision', 'status', 'suspend', 'unsuspend', 'poweron', 'poweroff', 'reboot'],
      ], 400);
  }
} catch (Exception $e) {
  respond([
    'error' => $e->getMessage(),
    'server_id' => $serverId,
    'hostname' => $hostname,
    'action' => $action,
  ], 500);
}
