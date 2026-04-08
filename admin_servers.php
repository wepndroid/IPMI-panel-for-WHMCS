<?php
session_start();
include 'config.php';
require_once __DIR__ . '/lib/ipmi_service.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'admin') {
  header('Location: login.php');
  exit();
}

$user_id = $_SESSION['user_id'];
$is_admin = ($_SESSION['role'] === 'admin');
$is_reseller = ($_SESSION['role'] === 'reseller');
$ipmiService = new IPMIService($mysqli);

if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = (string)$_SESSION['csrf_token'];

function isValidServersCsrf($token) {
  return isset($_SESSION['csrf_token']) && is_string($token) && $token !== '' && hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Detect BMC type using IPMI mc info.
 * Returns array: ['type' => supermicro|ilo4|idrac|generic, 'vendor' => string].
 */
function detectBmcType($ip, $user, $pass)
{
  $ip = trim((string)$ip);
  $user = trim((string)$user);
  $pass = (string)$pass;

  if ($ip === '' || $user === '' || $pass === '') {
    return ['type' => 'generic', 'vendor' => 'Unknown'];
  }

  $timeoutCmd = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? '' : 'timeout 10 ';
  $attempts = [];
  $attempts[] = ['interface' => 'lanplus', 'cipher' => null];
  foreach ([17, 3, 8, 7, 1, 0] as $cipher) {
    $attempts[] = ['interface' => 'lanplus', 'cipher' => $cipher];
  }
  $attempts[] = ['interface' => 'lan', 'cipher' => null];
  $privilegeLevels = ['ADMINISTRATOR', 'OPERATOR', 'USER'];

  $output = '';
  $success = false;
  foreach ($attempts as $attempt) {
    $iface = $attempt['interface'];
    $cipher = $attempt['cipher'];
    foreach ($privilegeLevels as $privilege) {
      $cmd = $timeoutCmd
        . "ipmitool -I " . $iface
        . " -L " . $privilege
        . " -H " . escapeshellarg($ip)
        . " -U " . escapeshellarg($user)
        . " -P " . escapeshellarg($pass);

      if ($iface === 'lanplus' && $cipher !== null) {
        $cmd .= " -C " . (int)$cipher;
      }

      $cmd .= " mc info 2>&1";
      $output = (string)shell_exec($cmd);
      $normalized = strtolower(trim($output));

      $isFailure = (
        $normalized === '' ||
        strpos($normalized, 'error') !== false ||
        strpos($normalized, 'unable') !== false ||
        strpos($normalized, 'invalid') !== false
      );

      if (!$isFailure) {
        $success = true;
        break;
      }
    }
    if ($success) {
      break;
    }
  }

  // Fallback probe for vendor strings on some controllers.
  if (!$success) {
    foreach ($attempts as $attempt) {
      $iface = $attempt['interface'];
      $cipher = $attempt['cipher'];
      foreach ($privilegeLevels as $privilege) {
        $cmd = $timeoutCmd
          . "ipmitool -I " . $iface
          . " -L " . $privilege
          . " -H " . escapeshellarg($ip)
          . " -U " . escapeshellarg($user)
          . " -P " . escapeshellarg($pass);

        if ($iface === 'lanplus' && $cipher !== null) {
          $cmd .= " -C " . (int)$cipher;
        }

        $cmd .= " fru print 0 2>&1";
        $fallbackOutput = (string)shell_exec($cmd);
        $fallbackNormalized = strtolower(trim($fallbackOutput));

        $isFailure = (
          $fallbackNormalized === '' ||
          strpos($fallbackNormalized, 'error') !== false ||
          strpos($fallbackNormalized, 'unable') !== false ||
          strpos($fallbackNormalized, 'invalid') !== false
        );

        if (!$isFailure) {
          $output = $fallbackOutput;
          $success = true;
          break;
        }
      }
      if ($success) {
        break;
      }
    }
  }

  $normalized = strtolower((string)$output);

  $genericVendors = [
    'lenovo' => 'Lenovo',
    'ibm' => 'IBM',
    'xclarity' => 'Lenovo XClarity',
    'asrock' => 'ASRock',
    'gigabyte' => 'Gigabyte',
    'quanta' => 'Quanta',
    'intel' => 'Intel',
    'american megatrends' => 'AMI',
    'ami' => 'AMI',
    'openbmc' => 'OpenBMC',
  ];

  if (
    strpos($normalized, 'integrated lights-out') !== false ||
    strpos($normalized, 'hewlett') !== false ||
    strpos($normalized, 'hpe') !== false ||
    strpos($normalized, ' ilo') !== false
  ) {
    return ['type' => 'ilo4', 'vendor' => 'HPE'];
  }

  if (
    strpos($normalized, 'idrac') !== false ||
    strpos($normalized, 'dell') !== false
  ) {
    return ['type' => 'idrac', 'vendor' => 'Dell'];
  }

  if (strpos($normalized, 'supermicro') !== false) {
    return ['type' => 'supermicro', 'vendor' => 'Supermicro'];
  }

  if (strpos($normalized, 'asrockrack') !== false || strpos($normalized, 'asrock') !== false) {
    return ['type' => 'ami', 'vendor' => 'ASRockRack'];
  }

  foreach ($genericVendors as $needle => $label) {
    if (strpos($normalized, $needle) !== false) {
      return ['type' => 'generic', 'vendor' => $label];
    }
  }

  if ($success) {
    return ['type' => 'generic', 'vendor' => 'Unknown'];
  }

  return ['type' => 'generic', 'vendor' => 'Unreachable'];
}

/**
 * Normalize bmc_type input to allowed values.
 */
function normalizeBmcType($bmcType)
{
  $type = strtolower(trim((string)$bmcType));
  if ($type === '') {
    return 'auto';
  }
  $aliases = [
    'super misc' => 'supermicro',
    'super micro' => 'supermicro',
    'supermiscro' => 'supermicro',
    'ilo' => 'ilo4',
    'i lo' => 'ilo4',
    'dell' => 'idrac',
    'ami' => 'ami',
    'asrockrack' => 'ami',
    'asrock' => 'ami',
  ];
  if (isset($aliases[$type])) {
    $type = $aliases[$type];
  }
  if (in_array($type, ['auto', 'supermicro', 'ilo4', 'idrac', 'ami', 'generic'], true)) {
    return $type;
  }
  return '';
}

/**
 * Launch background BMC detection for specific server IDs.
 */
function triggerBackgroundBmcDetection(array $serverIds)
{
  $ids = array_values(array_unique(array_map('intval', $serverIds)));
  $ids = array_values(array_filter($ids, function ($id) {
    return $id > 0;
  }));

  if (empty($ids)) {
    return;
  }

  $phpBin = 'php';
  if (php_sapi_name() === 'cli' && defined('PHP_BINARY') && PHP_BINARY) {
    $binName = strtolower(basename((string)PHP_BINARY));
    if (strpos($binName, 'php') !== false) {
      $phpBin = (string)PHP_BINARY;
    }
  }
  $script = __DIR__ . '/jobs/detect_bmc_types.php';
  if (!is_file($script)) {
    return;
  }

  $idsArg = implode(',', $ids);

  if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
    $cmd = 'start /B "" ' . escapeshellarg($phpBin) . ' ' . escapeshellarg($script) . ' --ids=' . escapeshellarg($idsArg);
  } else {
    $cmd = escapeshellarg($phpBin) . ' ' . escapeshellarg($script) . ' --ids=' . escapeshellarg($idsArg) . ' > /dev/null 2>&1 &';
  }

  @shell_exec($cmd);
}

// Handle delete
if (isset($_GET['delete'])) {
  if (!isValidServersCsrf($_GET['csrf'] ?? '')) {
    $_SESSION['message'] = "Invalid CSRF token";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }
  $id = intval($_GET['delete']);
  $cleanupSql = [
    "DELETE FROM server_status WHERE server_id = ?",
    "DELETE FROM server_suspension WHERE server_id = ?",
    "DELETE FROM user_servers WHERE server_id = ?",
  ];
  foreach ($cleanupSql as $sql) {
    $stmtCleanup = $mysqli->prepare($sql);
    if ($stmtCleanup) {
      $stmtCleanup->bind_param("i", $id);
      $stmtCleanup->execute();
      $stmtCleanup->close();
    }
  }

  $stmt = $mysqli->prepare("DELETE FROM servers WHERE id = ?");
  if ($stmt) {
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->close();
  }
  $_SESSION['message'] = "Server deleted successfully";
  $_SESSION['messageType'] = "success";
  header('Location: admin_servers.php');
  exit();
}

// Handle suspend
if (isset($_GET['suspend'])) {
  if (!isValidServersCsrf($_GET['csrf'] ?? '')) {
    $_SESSION['message'] = "Invalid CSRF token";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }
  $id = intval($_GET['suspend']);
  $reason = $_GET['reason'] ?? 'Suspended by admin';

  // Power off the server
  try {
    $ipmiService->powerOff($id, $user_id);
  } catch (Exception $e) {
    // Continue even if power off fails
  }

  // Mark as suspended
  $stmt = $mysqli->prepare("
    INSERT INTO server_suspension (server_id, suspended, suspended_at, suspended_by, suspension_reason)
    VALUES (?, 1, NOW(), ?, ?)
    ON DUPLICATE KEY UPDATE
      suspended = 1,
      suspended_at = NOW(),
      suspended_by = ?,
      suspension_reason = ?,
      unsuspended_at = NULL,
      unsuspended_by = NULL
  ");
  $stmt->bind_param("iisis", $id, $user_id, $reason, $user_id, $reason);
  $stmt->execute();
  $stmt->close();

  $_SESSION['message'] = "Server suspended successfully";
  $_SESSION['messageType'] = "success";
  header('Location: admin_servers.php');
  exit();
}

// Handle unsuspend
if (isset($_GET['unsuspend'])) {
  if (!isValidServersCsrf($_GET['csrf'] ?? '')) {
    $_SESSION['message'] = "Invalid CSRF token";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }
  $id = intval($_GET['unsuspend']);

  $stmt = $mysqli->prepare("
    UPDATE server_suspension 
    SET suspended = 0, unsuspended_at = NOW(), unsuspended_by = ?
    WHERE server_id = ?
  ");
  $stmt->bind_param("ii", $user_id, $id);
  $stmt->execute();
  $stmt->close();

  $_SESSION['message'] = "Server unsuspended successfully";
  $_SESSION['messageType'] = "success";
  header('Location: admin_servers.php');
  exit();
}

// Handle bulk CSV upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['bulk_upload'])) {
  require_once __DIR__ . '/lib/encryption.php';

  $inserted = 0;
  $updated = 0;
  $failed = 0;
  $queuedAutoDetect = 0;
  $autoDetectServerIds = [];
  $errors = [];
  $maxErrorsToShow = 10;

  if (!isset($_FILES['bulk_csv']) || !is_array($_FILES['bulk_csv'])) {
    $_SESSION['message'] = "Bulk import failed: file upload missing.";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }

  $file = $_FILES['bulk_csv'];
  if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
    $_SESSION['message'] = "Bulk import failed: upload error code " . (int)($file['error'] ?? -1) . ".";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }

  $originalName = (string)($file['name'] ?? '');
  $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
  if ($ext !== 'csv') {
    $_SESSION['message'] = "Bulk import failed: only .csv files are accepted.";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }

  $tmpName = (string)($file['tmp_name'] ?? '');
  $fp = @fopen($tmpName, 'r');
  if (!$fp) {
    $_SESSION['message'] = "Bulk import failed: unable to read uploaded file.";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }

  $header = fgetcsv($fp);
  if ($header === false) {
    fclose($fp);
    $_SESSION['message'] = "Bulk import failed: CSV is empty.";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }

  $headerMap = [];
  foreach ($header as $idx => $colName) {
    $normalized = strtolower(trim((string)$colName));
    if ($normalized !== '') {
      $headerMap[$normalized] = $idx;
    }
  }

  $requiredHeaders = ['server_name', 'ipmi_ip', 'ipmi_user', 'ipmi_pass'];
  $missingHeaders = [];
  foreach ($requiredHeaders as $requiredHeader) {
    if (!array_key_exists($requiredHeader, $headerMap)) {
      $missingHeaders[] = $requiredHeader;
    }
  }

  if (!empty($missingHeaders)) {
    fclose($fp);
    $_SESSION['message'] = "Bulk import failed: missing required CSV headers: " . implode(', ', $missingHeaders);
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }

  $updateStmt = $mysqli->prepare("
    UPDATE servers
    SET server_name = ?, server_ip = ?, ipmi_user = ?, ipmi_pass = ?, bmc_type = ?, notes = ?
    WHERE id = ?
  ");
  $insertStmt = $mysqli->prepare("
    INSERT INTO servers (server_name, server_ip, ipmi_ip, ipmi_user, ipmi_pass, bmc_type, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  ");

  if (!$updateStmt || !$insertStmt) {
    fclose($fp);
    $_SESSION['message'] = "Bulk import failed: SQL prepare error.";
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php');
    exit();
  }

  // Build existing IPMI IP -> server_id map once to avoid a SELECT for every CSV row.
  $existingMap = [];
  $existingRes = $mysqli->query("SELECT id, ipmi_ip FROM servers");
  if ($existingRes) {
    while ($existingRow = $existingRes->fetch_assoc()) {
      $existingIp = trim((string)($existingRow['ipmi_ip'] ?? ''));
      $existingId = (int)($existingRow['id'] ?? 0);
      if ($existingIp !== '' && $existingId > 0) {
        $existingMap[$existingIp] = $existingId;
      }
    }
  }

  $inTransaction = false;
  try {
    $mysqli->begin_transaction();
    $inTransaction = true;
  } catch (Throwable $e) {
    // Continue without transaction if unavailable.
  }

  $lineNumber = 1; // header line
  while (($row = fgetcsv($fp)) !== false) {
    $lineNumber++;

    $allEmpty = true;
    foreach ($row as $cell) {
      if (trim((string)$cell) !== '') {
        $allEmpty = false;
        break;
      }
    }
    if ($allEmpty) {
      continue;
    }

    $serverName = trim((string)($row[$headerMap['server_name']] ?? ''));
    $serverIp = trim((string)($row[$headerMap['server_ip']] ?? ''));
    $ipmiIp = trim((string)($row[$headerMap['ipmi_ip']] ?? ''));
    $ipmiUser = trim((string)($row[$headerMap['ipmi_user']] ?? ''));
    $ipmiPass = (string)($row[$headerMap['ipmi_pass']] ?? '');
    $bmcRaw = trim((string)($row[$headerMap['bmc_type']] ?? 'auto'));
    $notes = trim((string)($row[$headerMap['notes']] ?? ''));

    if ($serverName === '' || $ipmiIp === '' || $ipmiUser === '' || $ipmiPass === '') {
      $failed++;
      if (count($errors) < $maxErrorsToShow) {
        $errors[] = "Line {$lineNumber}: missing required values.";
      }
      continue;
    }

    $bmcType = normalizeBmcType($bmcRaw);
    if ($bmcType === '') {
      $failed++;
      if (count($errors) < $maxErrorsToShow) {
        $errors[] = "Line {$lineNumber}: invalid bmc_type '{$bmcRaw}'.";
      }
      continue;
    }

    if ($bmcType === 'auto') {
      // Keep import fast: insert/update first, then detect in background.
      $bmcType = 'generic';
    }

    try {
      $encryptedUser = Encryption::normalizeForStorage($ipmiUser, 'ipmi_user');
      $encryptedPass = Encryption::normalizeForStorage($ipmiPass, 'ipmi_pass');
    } catch (Exception $e) {
      $failed++;
      if (count($errors) < $maxErrorsToShow) {
        $errors[] = "Line {$lineNumber}: credential processing failed ({$e->getMessage()}).";
      }
      continue;
    }

    if (isset($existingMap[$ipmiIp]) && (int)$existingMap[$ipmiIp] > 0) {
      $existingId = (int)$existingMap[$ipmiIp];
      try {
        $updateStmt->bind_param("ssssssi", $serverName, $serverIp, $encryptedUser, $encryptedPass, $bmcType, $notes, $existingId);
        $updateStmt->execute();
        $updated++;
        if ($bmcRaw === '' || strtolower($bmcRaw) === 'auto') {
          $autoDetectServerIds[] = $existingId;
          $queuedAutoDetect++;
        }
      } catch (Throwable $e) {
        $failed++;
        if (count($errors) < $maxErrorsToShow) {
          $errors[] = "Line {$lineNumber}: update failed for IPMI IP {$ipmiIp}.";
        }
      }
    } else {
      try {
        $insertStmt->bind_param("sssssss", $serverName, $serverIp, $ipmiIp, $encryptedUser, $encryptedPass, $bmcType, $notes);
        $insertStmt->execute();
        $inserted++;
        $newId = (int)$insertStmt->insert_id;
        if ($newId > 0) {
          $existingMap[$ipmiIp] = $newId;
        }
        if ($bmcRaw === '' || strtolower($bmcRaw) === 'auto') {
          if ($newId > 0) {
            $autoDetectServerIds[] = $newId;
            $queuedAutoDetect++;
          }
        }
      } catch (Throwable $e) {
        $failed++;
        if (count($errors) < $maxErrorsToShow) {
          $errors[] = "Line {$lineNumber}: insert failed for IPMI IP {$ipmiIp}.";
        }
      }
    }
  }
  fclose($fp);
  $updateStmt->close();
  $insertStmt->close();

  if ($inTransaction) {
    try {
      $mysqli->commit();
    } catch (Throwable $e) {
      try {
        $mysqli->rollback();
      } catch (Throwable $rollbackError) {
      }
      $_SESSION['message'] = "Bulk import failed: transaction commit error.";
      $_SESSION['messageType'] = "error";
      header('Location: admin_servers.php');
      exit();
    }
  }

  if (!empty($autoDetectServerIds)) {
    triggerBackgroundBmcDetection($autoDetectServerIds);
  }

  $summary = "Bulk import completed.\nInserted: {$inserted}\nUpdated: {$updated}\nFailed: {$failed}";
  if ($queuedAutoDetect > 0) {
    $summary .= "\nAuto-detect queued in background: {$queuedAutoDetect}";
  }
  if (!empty($errors)) {
    $summary .= "\n\nErrors:\n- " . implode("\n- ", $errors);
    if ($failed > count($errors)) {
      $summary .= "\n- ...and " . ($failed - count($errors)) . " more";
    }
  }

  $_SESSION['message'] = $summary;
  $_SESSION['messageType'] = ($inserted === 0 && $updated === 0) ? "error" : "success";
  header('Location: admin_servers.php');
  exit();
}

// Handle form submission (add/edit)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['bulk_upload'])) {
  $id = isset($_POST['id']) ? intval($_POST['id']) : 0;
  $server_name = trim((string)($_POST['server_name'] ?? ''));
  $server_ip = trim((string)($_POST['server_ip'] ?? ''));
  $ipmi_ip = trim((string)($_POST['ipmi_ip'] ?? ''));
  $ipmi_user = trim((string)($_POST['ipmi_user'] ?? ''));
  $ipmi_pass = (string)($_POST['ipmi_pass'] ?? '');
  $bmc_type = trim((string)($_POST['bmc_type'] ?? 'auto'));
  $notes = trim((string)($_POST['notes'] ?? ''));
  $autoDetectSuffix = '';

  if ($bmc_type === 'auto') {
    $detected = detectBmcType($ipmi_ip, $ipmi_user, $ipmi_pass);
    $bmc_type = $detected['type'];
    $autoDetectSuffix = " (BMC auto-detected: " . strtoupper($detected['type']) . " / vendor: " . $detected['vendor'] . ")";
  }

  // Encrypt credentials safely (plaintext -> encrypted; already-encrypted value preserved).
  require_once __DIR__ . '/lib/encryption.php';
  try {
    $encrypted_user = Encryption::normalizeForStorage($ipmi_user, 'ipmi_user');
    $encrypted_pass = Encryption::normalizeForStorage($ipmi_pass, 'ipmi_pass');
  } catch (Exception $e) {
    $_SESSION['message'] = 'Credential save failed: ' . $e->getMessage();
    $_SESSION['messageType'] = "error";
    header('Location: admin_servers.php' . ($id > 0 ? '?edit=' . $id : ''));
    exit();
  }

  if ($id > 0) {
    // Update
    $stmt = $mysqli->prepare("
      UPDATE servers 
      SET server_name = ?, server_ip = ?, ipmi_ip = ?, ipmi_user = ?, ipmi_pass = ?, bmc_type = ?, notes = ?
      WHERE id = ?
    ");
    $stmt->bind_param("sssssssi", $server_name, $server_ip, $ipmi_ip, $encrypted_user, $encrypted_pass, $bmc_type, $notes, $id);
    $stmt->execute();
    $stmt->close();
    $_SESSION['message'] = "Server updated successfully" . $autoDetectSuffix;
  } else {
    // Insert
    $stmt = $mysqli->prepare("
      INSERT INTO servers (server_name, server_ip, ipmi_ip, ipmi_user, ipmi_pass, bmc_type, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    ");
    $stmt->bind_param("sssssss", $server_name, $server_ip, $ipmi_ip, $encrypted_user, $encrypted_pass, $bmc_type, $notes);
    $stmt->execute();
    $stmt->close();
    $_SESSION['message'] = "Server added successfully" . $autoDetectSuffix;
  }
  $_SESSION['messageType'] = "success";
  header('Location: admin_servers.php');
  exit();
}

// Get message from session and clear it
$message = '';
$messageType = '';
if (isset($_SESSION['message'])) {
  $message = $_SESSION['message'];
  $messageType = $_SESSION['messageType'];
  unset($_SESSION['message']);
  unset($_SESSION['messageType']);
}

$sampleCsv = "server_name,server_ip,ipmi_ip,ipmi_user,ipmi_pass,bmc_type,notes\n"
  . "server-1,,10.0.0.100,ADMIN,ExamplePass123,auto,Example server\n"
  . "server-2,172.16.0.10,10.0.0.101,ADMIN,ExamplePass456,supermicro,Imported in bulk\n"
  . "server-3,172.16.0.11,10.0.0.102,ADMIN,ExamplePass789,ami,ASRockRack / AMI example";
$sampleCsvDataUrl = 'data:text/csv;charset=utf-8,' . rawurlencode($sampleCsv);

// Get servers list
$servers = $mysqli->query("
  SELECT s.*, COALESCE(ss.suspended, 0) as suspended
  FROM servers s
  LEFT JOIN server_suspension ss ON s.id = ss.server_id
  ORDER BY s.id ASC
");

// Get server for editing
$editServer = null;
if (isset($_GET['edit'])) {
  $editId = intval($_GET['edit']);
  $result = $mysqli->query("SELECT * FROM servers WHERE id=$editId");
  if ($result && $result->num_rows > 0) {
    $editServer = $result->fetch_assoc();
    // Decrypt for editing
    try {
      require_once __DIR__ . '/lib/encryption.php';
      $editServer['ipmi_user'] = Encryption::decrypt($editServer['ipmi_user']);
      $editServer['ipmi_pass'] = Encryption::decrypt($editServer['ipmi_pass']);
    } catch (Exception $e) {
      // If decryption fails, use as-is (might be plaintext from migration)
    }
  }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Server Management - IPMI Panel</title>
  <link rel="stylesheet" href="assets/panel.css">
  <script>
    function toggleMobileMenu() {
      const mobileNav = document.getElementById('mobileNav');
      mobileNav.classList.toggle('active');
    }

    function closeMobileMenu() {
      const mobileNav = document.getElementById('mobileNav');
      mobileNav.classList.remove('active');
    }

    document.addEventListener('click', function(event) {
      const mobileNav = document.getElementById('mobileNav');
      const menuToggle = document.querySelector('.mobile-menu-toggle');
      
      if (mobileNav && menuToggle && 
          !mobileNav.contains(event.target) && 
          !menuToggle.contains(event.target) &&
          mobileNav.classList.contains('active')) {
        mobileNav.classList.remove('active');
      }
    });

    // Preserve scroll position on form submission and link clicks
    document.addEventListener('DOMContentLoaded', function() {
      // Restore scroll position if available
      const savedScroll = sessionStorage.getItem('scrollPos_admin_servers');
      if (savedScroll !== null) {
        window.scrollTo(0, parseInt(savedScroll));
        sessionStorage.removeItem('scrollPos_admin_servers');
      }

      // Save scroll position before form submission
      document.querySelectorAll('form[method="POST"]').forEach(function(form) {
        form.addEventListener('submit', function() {
          sessionStorage.setItem('scrollPos_admin_servers', window.pageYOffset || document.documentElement.scrollTop);
        });
      });

      // Save scroll position before clicking redirect links
      document.querySelectorAll('a[href*="?delete="], a[href*="?suspend="], a[href*="?unsuspend="]').forEach(function(link) {
        link.addEventListener('click', function() {
          sessionStorage.setItem('scrollPos_admin_servers', window.pageYOffset || document.documentElement.scrollTop);
        });
      });

      var bulkCsvDrop = document.getElementById('bulkCsvDrop');
      var bulkCsvFile = document.getElementById('bulkCsvFile');
      var bulkCsvFileName = document.getElementById('bulkCsvFileName');
      if (bulkCsvDrop && bulkCsvFile && bulkCsvFileName) {
        function updateBulkFileName() {
          var f = bulkCsvFile.files && bulkCsvFile.files[0];
          bulkCsvFileName.textContent = f ? f.name : 'No file selected';
        }
        bulkCsvFile.addEventListener('change', updateBulkFileName);

        var dragDepth = 0;
        bulkCsvDrop.addEventListener('dragenter', function (e) {
          e.preventDefault();
          e.stopPropagation();
          dragDepth++;
          bulkCsvDrop.classList.add('ipmi-file-drop--active');
        });
        bulkCsvDrop.addEventListener('dragleave', function (e) {
          e.preventDefault();
          e.stopPropagation();
          dragDepth--;
          if (dragDepth <= 0) {
            dragDepth = 0;
            bulkCsvDrop.classList.remove('ipmi-file-drop--active');
          }
        });
        bulkCsvDrop.addEventListener('dragover', function (e) {
          e.preventDefault();
          e.stopPropagation();
        });
        bulkCsvDrop.addEventListener('drop', function (e) {
          e.preventDefault();
          e.stopPropagation();
          dragDepth = 0;
          bulkCsvDrop.classList.remove('ipmi-file-drop--active');
          var files = e.dataTransfer && e.dataTransfer.files;
          if (!files || !files.length) return;
          try {
            var dt = new DataTransfer();
            dt.items.add(files[0]);
            bulkCsvFile.files = dt.files;
            updateBulkFileName();
          } catch (err) {}
        });
      }
    });
  </script>
  <script src="assets/ipmi-row-actions.js" defer></script>
</head>

<body>
  <?php
  $ipmiActiveNav = 'servers';
  $ipmiPageTitle = 'Server management';
  $ipmiPageDescription = 'Import CSV, add or edit BMC credentials, detect vendor types, and remove servers.';
  require __DIR__ . '/inc/panel_header.php';
  ?>

  <div class="container">
    <?php if ($message): ?>
      <div class="message <?= $messageType ?>" id="alertMessage" onclick="this.remove()"><?= htmlspecialchars($message) ?></div>
      <script>
        document.addEventListener('click', function(e) {
          const alert = document.getElementById('alertMessage');
          if (alert && !alert.contains(e.target)) {
            alert.remove();
          }
        });
        setTimeout(function() {
          const alert = document.getElementById('alertMessage');
          if (alert) alert.remove();
        }, 5000);
      </script>
    <?php endif; ?>

    <h2>Bulk upload (CSV)</h2>
    <form method="POST" enctype="multipart/form-data" class="bulk-form ipmi-bulk-upload-form">
      <input type="hidden" name="bulk_upload" value="1">
      <p class="bulk-hint ipmi-bulk-upload-hint" id="bulkCsvColumnsHint">
        Required columns: <code>server_name</code>, <code>server_ip</code>, <code>ipmi_ip</code>, <code>ipmi_user</code>, <code>ipmi_pass</code>, <code>bmc_type</code>, <code>notes</code>
      </p>
      <div class="ipmi-file-drop" id="bulkCsvDrop">
        <input type="file" name="bulk_csv" id="bulkCsvFile" class="ipmi-file-input-overlay" accept=".csv,text/csv" required
          aria-describedby="bulkCsvColumnsHint" aria-label="CSV file to import">
        <div class="ipmi-file-drop-inner">
          <span class="ipmi-file-drop-icon" aria-hidden="true">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 3v12m0 0l4-4m-4 4l-4-4M4 15v4a2 2 0 002 2h12a2 2 0 002-2v-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </span>
          <p class="ipmi-file-drop-title">Drop your CSV here or click to browse</p>
          <p class="ipmi-file-drop-sub">One file · .csv</p>
          <p class="ipmi-file-drop-name" id="bulkCsvFileName" aria-live="polite">No file selected</p>
        </div>
      </div>
      <div class="ipmi-bulk-upload-footer">
        <a class="sample-link" href="<?= htmlspecialchars($sampleCsvDataUrl) ?>" download="servers_sample.csv">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
            <path d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M8 12l4 4m0 0l4-4m-4 4V4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Download sample CSV
        </a>
        <button type="submit">Import CSV</button>
      </div>
    </form>

    <h2><?= $editServer ? 'Edit Server' : 'Add New Server' ?></h2>
    <form method="POST">
      <?php if ($editServer): ?>
        <input type="hidden" name="id" value="<?= $editServer['id'] ?>">
      <?php endif; ?>
      <label>Server Name:</label>
      <input type="text" name="server_name" value="<?= htmlspecialchars($editServer['server_name'] ?? '') ?>" required>

      <label>Server IP:</label>
      <input type="text" name="server_ip" value="<?= htmlspecialchars($editServer['server_ip'] ?? '') ?>" placeholder="Optional">

      <label>IPMI IP:</label>
      <input type="text" name="ipmi_ip" value="<?= htmlspecialchars($editServer['ipmi_ip'] ?? '') ?>" required>

      <label>IPMI Username:</label>
      <input type="text" name="ipmi_user" value="<?= htmlspecialchars($editServer['ipmi_user'] ?? 'ADMIN') ?>" required>

      <label>IPMI Password:</label>
      <input type="password" name="ipmi_pass" value="<?= htmlspecialchars($editServer['ipmi_pass'] ?? '') ?>" required>

      <label>BMC Type:</label>
      <select name="bmc_type">
        <option value="auto" <?= ($editServer['bmc_type'] ?? 'auto') === 'auto' ? 'selected' : '' ?>>Auto Detect</option>
        <option value="supermicro" <?= ($editServer['bmc_type'] ?? '') === 'supermicro' ? 'selected' : '' ?>>Supermicro</option>
        <option value="ami" <?= ($editServer['bmc_type'] ?? '') === 'ami' ? 'selected' : '' ?>>AMI / ASRockRack</option>
        <option value="ilo4" <?= ($editServer['bmc_type'] ?? '') === 'ilo4' ? 'selected' : '' ?>>iLO4</option>
        <option value="idrac" <?= ($editServer['bmc_type'] ?? '') === 'idrac' ? 'selected' : '' ?>>iDRAC</option>
        <option value="generic" <?= ($editServer['bmc_type'] ?? '') === 'generic' ? 'selected' : '' ?>>Generic / Other</option>
      </select>

      <label>Notes:</label>
      <textarea name="notes" rows="3"><?= htmlspecialchars($editServer['notes'] ?? '') ?></textarea>

      <button type="submit"><?= $editServer ? 'Update Server' : 'Add Server' ?></button>
      <?php if ($editServer): ?>
        <a href="admin_servers.php" class="ipmi-link-action">Cancel</a>
      <?php endif; ?>
    </form>

    <h2>Servers List</h2>
    <div class="table-container">
    <table>
      <thead>
      <tr>
        <th>ID</th>
        <th>Name</th>
        <th>Server IP</th>
        <th>IPMI IP</th>
        <th>Status</th>
        <th>Actions</th>
      </tr>
      </thead>
      <tbody>
      <?php while ($s = $servers->fetch_assoc()): ?>
        <tr>
          <td><?= $s['id'] ?></td>
          <td><?= htmlspecialchars($s['server_name']) ?></td>
          <td><?= htmlspecialchars($s['server_ip'] ?? '-') ?></td>
          <td><?= htmlspecialchars($s['ipmi_ip']) ?></td>
          <td>
            <?php if ((int)$s['suspended'] === 1): ?>
              <span class="suspended">SUSPENDED</span>
            <?php else: ?>
              Active
            <?php endif; ?>
          </td>
          <?php
            $sid = (int) $s['id'];
            $sName = htmlspecialchars($s['server_name'], ENT_QUOTES, 'UTF-8');
            $menuId = 'ipmi-actions-menu-' . $sid;
            $btnId = 'ipmi-actions-btn-' . $sid;
          ?>
          <td class="ipmi-actions-cell">
            <div class="ipmi-row-actions">
              <button type="button" class="ipmi-actions-trigger" id="<?= $btnId ?>"
                aria-haspopup="true" aria-expanded="false" aria-controls="<?= $menuId ?>">
                <span class="ipmi-sr-only">Actions for <?= $sName ?></span>
                <svg class="ipmi-actions-icon" width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                  <circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/>
                </svg>
              </button>
              <div class="ipmi-actions-menu" id="<?= $menuId ?>" role="menu" aria-labelledby="<?= $btnId ?>" hidden>
                <a href="?edit=<?= $sid ?>" role="menuitem" class="ipmi-actions-menu-link">Edit</a>
                <a href="?delete=<?= $sid ?>&csrf=<?= urlencode($csrfToken) ?>" role="menuitem" class="ipmi-actions-menu-link ipmi-actions-menu-link--danger"
                  onclick="return confirm('Delete server?')">Delete</a>
                <?php if ((int)$s['suspended'] === 1): ?>
                  <a href="?unsuspend=<?= $sid ?>&csrf=<?= urlencode($csrfToken) ?>" role="menuitem" class="ipmi-actions-menu-link ipmi-actions-menu-link--success">Unsuspend</a>
                <?php else: ?>
                  <a href="?suspend=<?= $sid ?>&csrf=<?= urlencode($csrfToken) ?>" role="menuitem" class="ipmi-actions-menu-link ipmi-actions-menu-link--warn"
                    onclick="return confirm('Suspend server? This will power it off.')">Suspend</a>
                <?php endif; ?>
              </div>
            </div>
          </td>
        </tr>
      <?php endwhile; ?>
      </tbody>
    </table>
    </div>
  </div>
</body>

</html>
