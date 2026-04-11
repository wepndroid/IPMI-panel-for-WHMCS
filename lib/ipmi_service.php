<?php

/**
 * Centralized IPMI service
 * Handles all IPMI commands with encryption, logging, and error handling
 */

require_once __DIR__ . '/encryption.php';

class IPMIService
{
  private $mysqli;
  private $debugEnabled = false;

  public function __construct($mysqli)
  {
    $this->mysqli = $mysqli;
    $this->debugEnabled = (getenv('IPMI_DEBUG') === '1');
  }

  /**
   * Execute IPMI command
   */
  private static $allowedCommands = [
    'chassis power on',
    'chassis power off',
    'chassis power reset',
    'chassis power status',
    'chassis power soft',
    'chassis power cycle',
    'mc info',
    'fru print 0',
  ];

  public function runIPMI($serverId, $command, $userId = null)
  {
    $command = trim((string)$command);
    if (!in_array($command, self::$allowedCommands, true)) {
      throw new Exception('Invalid IPMI command');
    }

    $stmt = $this->mysqli->prepare("
      SELECT s.*, ss.suspended 
      FROM servers s 
      LEFT JOIN server_suspension ss ON s.id = ss.server_id 
      WHERE s.id = ?
    ");
    $stmt->bind_param("i", $serverId);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
      throw new Exception("Server not found");
    }

    $server = $result->fetch_assoc();

    // Decrypt credentials
    try {
      $ipmiUser = Encryption::decrypt($server['ipmi_user']);
      $ipmiPass = Encryption::decrypt($server['ipmi_pass']);
    } catch (Exception $e) {
      // If decryption fails, try plaintext (for migration)
      $ipmiUser = $server['ipmi_user'];
      $ipmiPass = $server['ipmi_pass'];
    }

    $ip = $server['ipmi_ip'];

    // Check suspension for power-on commands
    if (isset($server['suspended']) && (int)$server['suspended'] === 1) {
      $powerCommands = ['chassis power on', 'power on'];
      $cmdLower = strtolower($command);
      foreach ($powerCommands as $pcmd) {
        if (strpos($cmdLower, $pcmd) !== false) {
          throw new Exception("Server is suspended. Power-on is not allowed.");
        }
      }
    }

    // Execute IPMI command.
    // Use BMC-aware attempt plan to reduce failures and long waits.
    $isPowerCommand = $this->isPowerCommand($command);
    $output = "";
    $success = false;
    $bmcType = $this->normalizeBmcType((string)($server['bmc_type'] ?? 'generic'));
    $attempts = $this->buildAttemptsForBmcType($bmcType, $isPowerCommand);
    $extendedPowerAttempts = $isPowerCommand ? $this->buildExtendedPowerAttemptsForBmcType($bmcType) : [];
    // Keep a no-privilege attempt first for compatibility with older BMCs.
    // Some environments work in legacy panels without explicit -L.
    $privilegeLevels = $isPowerCommand
      ? ['', 'ADMINISTRATOR', 'OPERATOR']
      : ['', 'OPERATOR'];

    // Add timeout for Linux compatibility.
    // Keep per-attempt timeout short, and enforce total-budget below.
    $timeoutSeconds = $isPowerCommand ? (($bmcType === 'supermicro') ? 10 : 8) : 4;
    $timeoutCmd = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? '' : ('timeout ' . $timeoutSeconds . ' ');
    $totalBudgetSeconds = $isPowerCommand ? 28 : 14;
    $deadlineAt = microtime(true) + $totalBudgetSeconds;

    foreach ($attempts as $attempt) {
      if (microtime(true) >= $deadlineAt) {
        break;
      }
      $iface = $attempt['interface'];
      $cipher = $attempt['cipher'];
      foreach ($privilegeLevels as $privilege) {
        if (microtime(true) >= $deadlineAt) {
          break;
        }
        $run = $this->executeIpmiAttempt($timeoutCmd, $iface, $cipher, $privilege, $ip, $ipmiUser, $ipmiPass, $command);
        $output = $run['output'];
        if (!$run['is_failure']) {
          $success = true;
          break;
        }
      }
      if ($success) {
        break;
      }
    }

    // Compatibility fallback for controllers that require less-common cipher suites
    // for power actions (reported on some ASRockRack/Supermicro-like implementations).
    if (!$success && $isPowerCommand && !empty($extendedPowerAttempts)) {
      foreach ($extendedPowerAttempts as $attempt) {
        if (microtime(true) >= $deadlineAt) {
          break;
        }
        $iface = $attempt['interface'];
        $cipher = $attempt['cipher'];
        foreach (['', 'ADMINISTRATOR'] as $privilege) {
          if (microtime(true) >= $deadlineAt) {
            break;
          }
          $run = $this->executeIpmiAttempt($timeoutCmd, $iface, $cipher, $privilege, $ip, $ipmiUser, $ipmiPass, $command);
          $output = $run['output'];
          if (!$run['is_failure']) {
            $success = true;
            break;
          }
        }
        if ($success) {
          break;
        }
      }
    }

    if (!$success) {
      $remaining = (int)max(0, floor($deadlineAt - microtime(true)));
      $rfResult = $this->runRedfishFallback($ip, $ipmiUser, $ipmiPass, $command, $remaining);
      if ($rfResult['success']) {
        $success = true;
        $output = $rfResult['output'];
      } else {
        $output = "Error: Unable to connect - " . ($output ?: "No output");
      }
    }

    // Log the action
    $this->logAction($userId, $serverId, $command, $output, $success);

    return $output;
  }

  /**
   * Build BMC-aware ipmitool attempt order.
   */
  private function buildAttemptsForBmcType($bmcType, $isPowerCommand)
  {
    $type = $this->normalizeBmcType($bmcType);

    // Keep attempts compact to avoid long blocking requests.
    if ($type === 'supermicro') {
      // Supermicro legacy flows often work with default lanplus first,
      // then -C 3 fallback.
      return [
        ['interface' => 'lanplus', 'cipher' => null],
        ['interface' => 'lanplus', 'cipher' => 3],
        ['interface' => 'lanplus', 'cipher' => 17],
        ['interface' => 'lan', 'cipher' => null],
      ];
    }

    if (preg_match('/^ilo[0-9]+$/', $type)) {
      return [
        ['interface' => 'lanplus', 'cipher' => 3],
        ['interface' => 'lanplus', 'cipher' => null],
        ['interface' => 'lanplus', 'cipher' => 17],
        ['interface' => 'lan', 'cipher' => null],
      ];
    }

    if ($type === 'idrac') {
      return [
        ['interface' => 'lanplus', 'cipher' => null],
        ['interface' => 'lanplus', 'cipher' => 17],
        ['interface' => 'lanplus', 'cipher' => 3],
        ['interface' => 'lan', 'cipher' => null],
      ];
    }

    // Generic fallback.
    if ($isPowerCommand) {
      return [
        ['interface' => 'lanplus', 'cipher' => null],
        ['interface' => 'lanplus', 'cipher' => 3],
        ['interface' => 'lanplus', 'cipher' => 17],
        ['interface' => 'lan', 'cipher' => null],
      ];
    }

    // For status checks, keep a wider list for compatibility.
    return [
      ['interface' => 'lanplus', 'cipher' => null],
      ['interface' => 'lanplus', 'cipher' => 3],
      ['interface' => 'lanplus', 'cipher' => 17],
      ['interface' => 'lanplus', 'cipher' => 8],
      ['interface' => 'lanplus', 'cipher' => 7],
      ['interface' => 'lanplus', 'cipher' => 1],
      ['interface' => 'lanplus', 'cipher' => 0],
      ['interface' => 'lan', 'cipher' => null],
    ];
  }

  /**
   * Additional power-command attempts for endpoints that reject common ciphers.
   * Kept separate to avoid slowing down normal paths unless needed.
   */
  private function buildExtendedPowerAttemptsForBmcType($bmcType)
  {
    $type = $this->normalizeBmcType($bmcType);
    $ciphers = [8, 7, 1, 0];

    // Useful on many "generic" and ASRockRack/Supermicro-like targets.
    if (in_array($type, ['generic', 'supermicro', 'idrac'], true) || preg_match('/^ilo[0-9]+$/', $type)) {
      $out = [];
      foreach ($ciphers as $c) {
        $out[] = ['interface' => 'lanplus', 'cipher' => $c];
      }
      $out[] = ['interface' => 'lan', 'cipher' => null];
      return $out;
    }

    return [];
  }

  private function isPowerCommand($command)
  {
    $cmd = strtolower(trim((string)$command));
    return (
      strpos($cmd, 'chassis power on') !== false ||
      strpos($cmd, 'chassis power off') !== false ||
      strpos($cmd, 'chassis power reset') !== false ||
      strpos($cmd, 'chassis power soft') !== false ||
      strpos($cmd, 'chassis power cycle') !== false
    );
  }

  private function isOutputFailure($output)
  {
    $output = trim((string)$output);
    $normalized = strtolower($output);
    if ($normalized === '') {
      return true;
    }

    // Positive signals first to avoid false negatives on verbose ipmitool output.
    $successSignals = [
      'chassis power is on',
      'chassis power is off',
      'chassis power control: up',
      'chassis power control: down',
      'chassis power control: cycle',
      'chassis power control: reset',
      'chassis power control: soft',
      'set chassis power control to up',
      'set chassis power control to down',
      'set chassis power control to cycle',
      'set chassis power control to reset',
      'set chassis power control to soft',
      'power on command sent via redfish',
      'power off command sent via redfish',
      'reset command sent via redfish',
    ];
    foreach ($successSignals as $signal) {
      if (strpos($normalized, $signal) !== false) {
        return false;
      }
    }

    // Failure signals.
    return (
      strpos($normalized, 'error') !== false ||
      strpos($normalized, 'unable') !== false ||
      strpos($normalized, 'invalid') !== false ||
      strpos($normalized, 'failed') !== false ||
      strpos($normalized, 'timeout') !== false ||
      strpos($normalized, 'unauthorized') !== false ||
      strpos($normalized, 'not allowed') !== false ||
      strpos($normalized, 'permission denied') !== false
    );
  }

  private function normalizeBmcType($bmcType)
  {
    $type = strtolower(trim((string)$bmcType));
    $aliases = [
      'supermiscro' => 'supermicro',
      'super micro' => 'supermicro',
      'super misc' => 'supermicro',
      'asrockrack' => 'ami',
      'asrock rack' => 'ami',
      'asrock' => 'ami',
      'ami' => 'ami',
      // Ambiguous panel label "ilo": prefer ilo5 (HTML5/Redfish); explicit ilo4/ilo6 still stored as-is.
      'ilo' => 'ilo5',
      'dell' => 'idrac',
    ];
    if (isset($aliases[$type])) {
      $type = $aliases[$type];
    }
    if (preg_match('/^ilo[0-9]+$/', $type)) {
      return $type;
    }
    if (preg_match('/^ilo[0-9]+$/', $type) || in_array($type, ['supermicro', 'idrac', 'ami', 'generic'], true)) {
      return $type;
    }
    return 'generic';
  }

  private function executeIpmiAttempt($timeoutCmd, $iface, $cipher, $privilege, $ip, $ipmiUser, $ipmiPass, $command)
  {
    $cmd = $timeoutCmd . "ipmitool -I " . $iface
      . " -H " . escapeshellarg($ip)
      . " -U " . escapeshellarg($ipmiUser)
      . " -P " . escapeshellarg($ipmiPass);

    if ($privilege !== '') {
      $cmd .= " -L " . $privilege;
    }

    if ($iface === 'lanplus' && $cipher !== null) {
      $cmd .= " -C " . (int)$cipher;
    }

    $cmd .= " " . $command . " 2>&1";
    $output = (string)shell_exec($cmd);
    $isFailure = $this->isOutputFailure(trim($output));

    return [
      'output' => $output,
      'is_failure' => $isFailure
    ];
  }

  /**
   * Try Redfish fallback when ipmitool fails.
   * Supports status/on/off/reset semantics used by this panel.
   */
  private function runRedfishFallback($ip, $user, $pass, $command, $maxRemainingSeconds = 0)
  {
    if ((int)$maxRemainingSeconds <= 1) {
      return ['success' => false, 'output' => ''];
    }

    $cmd = strtolower(trim((string)$command));
    $op = null;
    if (strpos($cmd, 'chassis power status') !== false) {
      $op = 'status';
    } elseif (strpos($cmd, 'chassis power on') !== false) {
      $op = 'on';
    } elseif (strpos($cmd, 'chassis power off') !== false) {
      $op = 'off';
    } elseif (strpos($cmd, 'chassis power reset') !== false) {
      $op = 'reset';
    }

    if ($op === null) {
      return ['success' => false, 'output' => ''];
    }

    $rfConnectTimeout = (int)max(2, min(4, (int)$maxRemainingSeconds));
    $rfTimeout = (int)max(3, min(6, (int)$maxRemainingSeconds));

    $systemPath = $this->redfishDiscoverSystemPath($ip, $user, $pass, $rfTimeout, $rfConnectTimeout);
    if ($systemPath === '') {
      return ['success' => false, 'output' => ''];
    }

    if ($op === 'status') {
      $res = $this->redfishRequest($ip, $user, $pass, 'GET', $systemPath, null, $rfTimeout, $rfConnectTimeout);
      if (!$res['success']) {
        return ['success' => false, 'output' => ''];
      }
      $power = strtolower((string)($res['json']['PowerState'] ?? ''));
      if ($power === 'on') {
        return ['success' => true, 'output' => 'Chassis Power is on'];
      }
      if ($power === 'off') {
        return ['success' => true, 'output' => 'Chassis Power is off'];
      }
      return ['success' => true, 'output' => 'Chassis Power is ' . ($power !== '' ? $power : 'unknown')];
    }

    $resetPath = rtrim($systemPath, '/') . '/Actions/ComputerSystem.Reset/';
    $resetType = 'ForceRestart';
    if ($op === 'on') {
      $resetType = 'On';
    } elseif ($op === 'off') {
      $resetType = 'ForceOff';
    }

    $res = $this->redfishRequest($ip, $user, $pass, 'POST', $resetPath, ['ResetType' => $resetType], $rfTimeout, $rfConnectTimeout);
    if (!$res['success']) {
      return ['success' => false, 'output' => ''];
    }

    if ($op === 'on') {
      return ['success' => true, 'output' => 'Power on command sent via Redfish'];
    }
    if ($op === 'off') {
      return ['success' => true, 'output' => 'Power off command sent via Redfish'];
    }
    return ['success' => true, 'output' => 'Reset command sent via Redfish'];
  }

  /**
   * Discover a Redfish System path (e.g. /redfish/v1/Systems/1/).
   */
  private function redfishDiscoverSystemPath($ip, $user, $pass, $timeout = 6, $connectTimeout = 4)
  {
    $res = $this->redfishRequest($ip, $user, $pass, 'GET', '/redfish/v1/Systems', null, $timeout, $connectTimeout);
    if (!$res['success'] || !is_array($res['json'])) {
      $res = $this->redfishRequest($ip, $user, $pass, 'GET', '/redfish/v1/Systems/', null, $timeout, $connectTimeout);
      if (!$res['success'] || !is_array($res['json'])) {
        return '';
      }
    }

    $json = $res['json'];
    if (isset($json['Members'][0]['@odata.id'])) {
      return (string)$json['Members'][0]['@odata.id'];
    }
    if (isset($json['links']['Member'][0]['href'])) {
      return (string)$json['links']['Member'][0]['href'];
    }

    // Conservative fallback used by most Redfish implementations.
    return '/redfish/v1/Systems/1/';
  }

  /**
   * Basic Redfish HTTP helper.
   */
  private function redfishRequest($ip, $user, $pass, $method, $path, $payload = null, $timeout = 8, $connectTimeout = 4)
  {
    $url = 'https://' . $ip . '/' . ltrim((string)$path, '/');
    $ch = curl_init($url);
    if ($ch === false) {
      return ['success' => false, 'json' => null];
    }

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, max(2, (int)$timeout));
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, max(1, (int)$connectTimeout));
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_setopt($ch, CURLOPT_USERPWD, $user . ':' . $pass);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json', 'Content-Type: application/json']);

    $method = strtoupper((string)$method);
    if ($method === 'POST') {
      curl_setopt($ch, CURLOPT_POST, true);
      $body = is_array($payload) ? json_encode($payload) : (string)$payload;
      curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    } else {
      curl_setopt($ch, CURLOPT_HTTPGET, true);
    }

    $raw = curl_exec($ch);
    $err = curl_error($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($err) {
      return ['success' => false, 'json' => null, 'http_code' => $code];
    }

    $json = null;
    if (is_string($raw) && $raw !== '') {
      $decoded = json_decode($raw, true);
      if (is_array($decoded)) {
        $json = $decoded;
      }
    }

    $okCodes = [200, 201, 202, 204];
    if (!in_array($code, $okCodes, true)) {
      return ['success' => false, 'json' => $json, 'http_code' => $code];
    }

    return ['success' => true, 'json' => $json, 'http_code' => $code];
  }

  /**
   * Check server power status
   */
  public function checkStatus($serverId)
  {
    // Check if server is suspended - don't update status for suspended servers
    $stmt = $this->mysqli->prepare("
      SELECT suspended FROM server_suspension WHERE server_id = ? AND suspended = 1
    ");
    $stmt->bind_param("i", $serverId);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
      // Server is suspended, return current status without checking IPMI
      $stmt->close();
      $stmt = $this->mysqli->prepare("
        SELECT power_state, reachable, last_checked, last_error 
        FROM server_status 
        WHERE server_id = ?
      ");
      $stmt->bind_param("i", $serverId);
      $stmt->execute();
      $statusResult = $stmt->get_result();
      $status = $statusResult->fetch_assoc();
      $stmt->close();

      // Return existing status or default if not found
      if ($status) {
        return [
          'power_state' => $status['power_state'] ?? 'unknown',
          'reachable' => $status['reachable'] ?? 0,
          'last_error' => $status['last_error'] ?? 'Server is suspended'
        ];
      }

      return [
        'power_state' => 'unknown',
        'reachable' => 0,
        'last_error' => 'Server is suspended'
      ];
    }
    $stmt->close();

    // Backoff for recently unreachable endpoints to avoid repeated long ipmitool timeouts
    // that can slow both panel and WHMCS integrations.
    $stmt = $this->mysqli->prepare("
      SELECT power_state, reachable, last_checked, last_error
      FROM server_status
      WHERE server_id = ?
      LIMIT 1
    ");
    if ($stmt) {
      $stmt->bind_param("i", $serverId);
      $stmt->execute();
      $cachedRes = $stmt->get_result();
      $cached = ($cachedRes && $cachedRes->num_rows > 0) ? $cachedRes->fetch_assoc() : null;
      $stmt->close();

      if ($cached) {
        $cachedReachable = (int)($cached['reachable'] ?? 0);
        $cachedError = trim((string)($cached['last_error'] ?? ''));
        $cachedChecked = strtotime((string)($cached['last_checked'] ?? ''));
        $isFreshFailure = ($cachedChecked !== false && $cachedChecked > 0 && (time() - $cachedChecked) < 90);
        if ($cachedReachable === 0 && $cachedError !== '' && $isFreshFailure) {
          $cachedPowerState = trim((string)($cached['power_state'] ?? 'unknown'));
          if ($cachedPowerState === '') {
            $cachedPowerState = 'unknown';
          }
          $this->saveServerStatusRow($serverId, $cachedPowerState, 0, $cachedError);
          return [
            'power_state' => $cachedPowerState,
            'reachable' => 0,
            'last_error' => $cachedError,
          ];
        }
      }
    }

    try {
      $output = $this->runIPMI($serverId, 'chassis power status');
      $status_lower = strtolower(trim((string)$output));

      $powerState = "unknown";
      $reachable = 0;
      $lastError = null;

      if (strpos($status_lower, 'chassis power is on') !== false || strpos($status_lower, 'is on') !== false) {
        $powerState = "on";
        $reachable = 1;
      } elseif (strpos($status_lower, 'chassis power is off') !== false || strpos($status_lower, 'is off') !== false) {
        $powerState = "off";
        $reachable = 1;
      } else {
        $lastError = substr($output, 0, 250);
      }

      if ($this->debugEnabled) {
        $debugLastError = $lastError ?? 'NULL';
        if (php_sapi_name() === 'cli') {
          echo "[IPMI DEBUG] server {$serverId}: power_state={$powerState}, reachable={$reachable}, last_error={$debugLastError}" . PHP_EOL;
        }
        error_log("[IPMI DEBUG] server {$serverId}: power_state={$powerState}, reachable={$reachable}, last_error={$debugLastError}");
      }

      $this->saveServerStatusRow($serverId, $powerState, $reachable, (string)($lastError ?? ''));

      return [
        'power_state' => $powerState,
        'reachable' => $reachable,
        'last_error' => $lastError
      ];
    } catch (Exception $e) {
      $errorMessage = (string)$e->getMessage();
      $this->saveServerStatusRow($serverId, 'unknown', 0, $errorMessage);
      return [
        'power_state' => 'unknown',
        'reachable' => 0,
        'last_error' => $errorMessage
      ];
    }
  }

  private function saveServerStatusRow($serverId, $powerState, $reachable, $lastError)
  {
    $serverId = (int)$serverId;
    $powerState = (string)$powerState;
    $reachable = (int)$reachable;
    $lastError = (string)$lastError;

    $stmt = $this->mysqli->prepare("
      INSERT INTO server_status (server_id, power_state, reachable, last_checked, last_error)
      VALUES (?, ?, ?, NOW(), ?)
      ON DUPLICATE KEY UPDATE
        power_state = ?,
        reachable = ?,
        last_checked = NOW(),
        last_error = ?
    ");
    if (!$stmt) {
      if ($this->debugEnabled) {
        error_log("[IPMI DEBUG] SQL prepare error updating server_status for server {$serverId}: " . $this->mysqli->error);
      }
      return;
    }

    $stmt->bind_param(
      "isissis",
      $serverId,
      $powerState,
      $reachable,
      $lastError,
      $powerState,
      $reachable,
      $lastError
    );

    if (!$stmt->execute() && $this->debugEnabled) {
      error_log("[IPMI DEBUG] SQL execute error updating server_status for server {$serverId}: " . $stmt->error);
    }
    $stmt->close();
  }

  /**
   * Log action to database
   */
  private function logAction($userId, $serverId, $action, $result, $success)
  {
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? null;
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
    $resultText = $success ? 'Success' : substr($result, 0, 500);

    $stmt = $this->mysqli->prepare("
      INSERT INTO action_logs (user_id, server_id, action, ip_address, user_agent, result)
      VALUES (?, ?, ?, ?, ?, ?)
    ");
    $stmt->bind_param("iissss", $userId, $serverId, $action, $ipAddress, $userAgent, $resultText);
    $stmt->execute();
    $stmt->close();
  }

  /**
   * Power on server
   */
  public function powerOn($serverId, $userId = null)
  {
    $result = $this->runIPMI($serverId, 'chassis power on', $userId);

    // Verify real state transition, not only command acknowledgement.
    if ($this->waitForExpectedPowerState($serverId, 'on', 6, 1200)) {
      return 'Power on command applied';
    }

    // One retry for endpoints that acknowledge first command but apply slowly.
    $retry = $this->runIPMI($serverId, 'chassis power on', $userId);
    if (!$this->isOutputFailure($retry) && $this->waitForExpectedPowerState($serverId, 'on', 6, 1200)) {
      return 'Power on command applied (retry)';
    }

    $current = $this->readCurrentPowerState($serverId);
    throw new Exception('Power on command sent but server still reports ' . strtoupper($current));
  }

  /**
   * Power off server
   */
  public function powerOff($serverId, $userId = null)
  {
    $result = $this->runIPMI($serverId, 'chassis power off', $userId);

    // Verify real state transition, not only command acknowledgement.
    if ($this->waitForExpectedPowerState($serverId, 'off', 6, 1200)) {
      return 'Power off command applied';
    }

    // Fallback for hardware that applies OFF reliably with SOFT.
    $soft = $this->runIPMI($serverId, 'chassis power soft', $userId);
    if (!$this->isOutputFailure($soft) && $this->waitForExpectedPowerState($serverId, 'off', 8, 1200)) {
      return 'Power off command applied (soft)';
    }

    // Final retry with hard off.
    $retry = $this->runIPMI($serverId, 'chassis power off', $userId);
    if (!$this->isOutputFailure($retry) && $this->waitForExpectedPowerState($serverId, 'off', 8, 1200)) {
      return 'Power off command applied (retry)';
    }

    $current = $this->readCurrentPowerState($serverId);
    throw new Exception('Power off command sent but server still reports ' . strtoupper($current));
  }

  /**
   * Reboot server
   */
  public function reboot($serverId, $userId = null)
  {
    $result = $this->runIPMI($serverId, 'chassis power reset', $userId);
    if (!$this->isOutputFailure($result)) {
      return $result;
    }

    // Fallback for BMCs that use "cycle" instead of "reset".
    $cycle = $this->runIPMI($serverId, 'chassis power cycle', $userId);
    if (!$this->isOutputFailure($cycle)) {
      return $cycle;
    }

    throw new Exception($result !== '' ? $result : 'Reboot failed');
  }

  private function readCurrentPowerState($serverId)
  {
    try {
      $out = (string)$this->runIPMI($serverId, 'chassis power status');
    } catch (Exception $e) {
      return 'unknown';
    }

    $s = strtolower(trim($out));
    if (strpos($s, 'chassis power is on') !== false || strpos($s, 'is on') !== false) {
      return 'on';
    }
    if (strpos($s, 'chassis power is off') !== false || strpos($s, 'is off') !== false) {
      return 'off';
    }
    return 'unknown';
  }

  private function waitForExpectedPowerState($serverId, $expectedState, $attempts = 6, $sleepMs = 1200)
  {
    $expected = strtolower(trim((string)$expectedState));
    if (!in_array($expected, ['on', 'off'], true)) {
      return false;
    }

    $tries = max(1, (int)$attempts);
    $sleepUs = max(200000, ((int)$sleepMs) * 1000);

    for ($i = 0; $i < $tries; $i++) {
      $current = $this->readCurrentPowerState($serverId);
      if ($current === $expected) {
        return true;
      }
      if ($i < $tries - 1) {
        usleep($sleepUs);
      }
    }
    return false;
  }
}
