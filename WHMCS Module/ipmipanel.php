<?php
/**
 * WHMCS Server Module — IPMI Panel Integration
 *
 * Supports: CreateAccount, SuspendAccount, UnsuspendAccount,
 * TerminateAccount, power actions, and client area controls.
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

function ipmipanel_MetaData()
{
    return [
        'DisplayName' => 'IPMI Panel',
        'APIVersion'  => '1.1',
    ];
}

function ipmipanel_ConfigOptions()
{
    return [
        'Panel URL' => [
            'Type'        => 'text',
            'Size'        => 80,
            'Description' => 'Full URL to your IPMI panel, e.g. https://panel.example.com',
        ],
        'API Key' => [
            'Type'        => 'password',
            'Size'        => 80,
            'Description' => 'API key for the IPMI panel',
        ],
    ];
}

function ipmipanel_CustomFields()
{
    return [
        [
            'Name'     => 'IPMI IP',
            'Type'     => 'text',
            'Size'     => 40,
            'Required' => true,
            'AdminOnly' => true,
        ],
        [
            'Name'     => 'IPMI User',
            'Type'     => 'text',
            'Size'     => 40,
            'Required' => true,
            'AdminOnly' => true,
        ],
        [
            'Name'     => 'IPMI Password',
            'Type'     => 'password',
            'Size'     => 40,
            'Required' => true,
            'AdminOnly' => true,
        ],
    ];
}

function ipmipanel_apiCall($params, $action, $extraData = [])
{
    $panelUrl = rtrim(trim((string)($params['configoption1'] ?? '')), '/');
    $apiKey = trim((string)($params['configoption2'] ?? ''));

    if ($panelUrl === '' || $apiKey === '') {
        return ['error' => 'Panel URL or API key not configured'];
    }

    $url = $panelUrl . '/api/api.php';

    $postData = array_merge([
        'action' => $action,
    ], $extraData);

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postData));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'X-API-Key: ' . $apiKey,
        'Content-Type: application/x-www-form-urlencoded',
    ]);

    $raw = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($raw === false) {
        return ['error' => 'cURL error: ' . $err];
    }

    $json = json_decode($raw, true);
    if (!is_array($json)) {
        return ['error' => 'Invalid JSON response (HTTP ' . $code . ')'];
    }

    return $json;
}

function ipmipanel_getCustomField($params, $fieldName, $trim = true)
{
    $customFields = $params['customfields'] ?? [];
    foreach ($customFields as $key => $value) {
        if (strcasecmp($key, $fieldName) === 0) {
            $v = (string)$value;
            return $trim ? trim($v) : $v;
        }
    }
    return '';
}

function ipmipanel_CreateAccount(array $params)
{
    $email = trim((string)($params['clientsdetails']['email'] ?? ''));
    $hostname = trim((string)($params['domain'] ?? ''));
    $serverIp = trim((string)($params['dedicatedip'] ?? ''));
    $ipmiIp = ipmipanel_getCustomField($params, 'IPMI IP');
    $ipmiUser = ipmipanel_getCustomField($params, 'IPMI User');
    // Keep exact password value from custom field; do not trim spaces.
    $ipmiPass = ipmipanel_getCustomField($params, 'IPMI Password', false);

    if ($email === '') {
        return 'Client email is required';
    }
    if ($hostname === '') {
        return 'Hostname (domain field) is required';
    }
    if ($ipmiIp === '' || $ipmiUser === '' || $ipmiPass === '') {
        return 'IPMI IP, User, and Password custom fields are required';
    }

    $result = ipmipanel_apiCall($params, 'provision', [
        'email'     => $email,
        'hostname'  => $hostname,
        'server_ip' => $serverIp,
        'ipmi_ip'   => $ipmiIp,
        'ipmi_user' => $ipmiUser,
        'ipmi_pass' => $ipmiPass,
        'notes'     => 'Provisioned via WHMCS service #' . (int)($params['serviceid'] ?? 0),
    ]);

    if (isset($result['error'])) {
        return 'Provision failed: ' . $result['error'];
    }

    $serviceId = (int)($params['serviceid'] ?? 0);
    $panelUsername = trim((string)($result['panel_username'] ?? ''));
    $panelPassword = trim((string)($result['panel_password'] ?? ''));

    if ($serviceId > 0 && $panelUsername !== '') {
        $updateFields = ['username' => $panelUsername];
        if ($panelPassword !== '') {
            $updateFields['password'] = $panelPassword;
        }

        try {
            $command = 'UpdateClientProduct';
            $postData = [
                'serviceid' => $serviceId,
            ];
            foreach ($updateFields as $k => $v) {
                $postData[$k] = $v;
            }
            localAPI($command, $postData);
        } catch (\Exception $e) {
            // non-fatal: credentials still returned in provision response
        }
    }

    return 'success';
}

function ipmipanel_SuspendAccount(array $params)
{
    $hostname = trim((string)($params['domain'] ?? ''));
    $serverId = 0;

    if ($hostname !== '') {
        $resolve = ipmipanel_apiCall($params, 'resolve', ['hostname' => $hostname]);
        if (isset($resolve['server_id'])) {
            $serverId = (int)$resolve['server_id'];
        }
    }

    if ($serverId <= 0) {
        return 'Cannot resolve server for hostname: ' . $hostname;
    }

    $result = ipmipanel_apiCall($params, 'suspend', [
        'server_id' => $serverId,
        'reason'    => 'Suspended via WHMCS',
    ]);

    if (isset($result['error'])) {
        return 'Suspend failed: ' . $result['error'];
    }

    return 'success';
}

function ipmipanel_UnsuspendAccount(array $params)
{
    $hostname = trim((string)($params['domain'] ?? ''));
    $serverId = 0;

    if ($hostname !== '') {
        $resolve = ipmipanel_apiCall($params, 'resolve', ['hostname' => $hostname]);
        if (isset($resolve['server_id'])) {
            $serverId = (int)$resolve['server_id'];
        }
    }

    if ($serverId <= 0) {
        return 'Cannot resolve server for hostname: ' . $hostname;
    }

    $result = ipmipanel_apiCall($params, 'unsuspend', [
        'server_id' => $serverId,
        'power_on'  => '1',
    ]);

    if (isset($result['error'])) {
        return 'Unsuspend failed: ' . $result['error'];
    }

    return 'success';
}

function ipmipanel_TerminateAccount(array $params)
{
    $hostname = trim((string)($params['domain'] ?? ''));
    $serverId = 0;

    if ($hostname !== '') {
        $resolve = ipmipanel_apiCall($params, 'resolve', ['hostname' => $hostname]);
        if (isset($resolve['server_id'])) {
            $serverId = (int)$resolve['server_id'];
        }
    }

    if ($serverId <= 0) {
        return 'success';
    }

    ipmipanel_apiCall($params, 'suspend', [
        'server_id' => $serverId,
        'reason'    => 'Terminated via WHMCS',
    ]);

    return 'success';
}

function ipmipanel_ServiceSingleSignOn(array $params)
{
    return [];
}

function ipmipanel_AdminCustomButtonArray()
{
    return [
        'Power On'  => 'poweron',
        'Power Off' => 'poweroff',
        'Reboot'    => 'reboot',
    ];
}

function ipmipanel_ClientAreaCustomButtonArray()
{
    return [
        'Power On'  => 'poweron',
        'Power Off' => 'poweroff',
        'Reboot'    => 'reboot',
    ];
}

function ipmipanel_poweron(array $params)
{
    $hostname = trim((string)($params['domain'] ?? ''));
    $serverId = ipmipanel_resolveServerId($params, $hostname);
    if ($serverId <= 0) {
        return 'Cannot resolve server for hostname: ' . $hostname;
    }
    $result = ipmipanel_apiCall($params, 'poweron', ['server_id' => $serverId]);
    if (isset($result['error'])) {
        return 'Power On failed: ' . $result['error'];
    }
    return 'success';
}

function ipmipanel_poweroff(array $params)
{
    $hostname = trim((string)($params['domain'] ?? ''));
    $serverId = ipmipanel_resolveServerId($params, $hostname);
    if ($serverId <= 0) {
        return 'Cannot resolve server for hostname: ' . $hostname;
    }
    $result = ipmipanel_apiCall($params, 'poweroff', ['server_id' => $serverId]);
    if (isset($result['error'])) {
        return 'Power Off failed: ' . $result['error'];
    }
    return 'success';
}

function ipmipanel_reboot(array $params)
{
    $hostname = trim((string)($params['domain'] ?? ''));
    $serverId = ipmipanel_resolveServerId($params, $hostname);
    if ($serverId <= 0) {
        return 'Cannot resolve server for hostname: ' . $hostname;
    }
    $result = ipmipanel_apiCall($params, 'reboot', ['server_id' => $serverId]);
    if (isset($result['error'])) {
        return 'Reboot failed: ' . $result['error'];
    }
    return 'success';
}

function ipmipanel_resolveServerId(array $params, string $hostname): int
{
    if ($hostname === '') {
        return 0;
    }
    $resolve = ipmipanel_apiCall($params, 'resolve', ['hostname' => $hostname]);
    return (int)($resolve['server_id'] ?? 0);
}

function ipmipanel_ClientArea(array $params)
{
    $panelUrl = rtrim(trim((string)($params['configoption1'] ?? '')), '/');
    $hostname = trim((string)($params['domain'] ?? ''));

    $serverId = 0;
    $isSuspended = false;
    $powerState = 'unknown';

    if ($hostname !== '') {
        $resolve = ipmipanel_apiCall($params, 'resolve', ['hostname' => $hostname]);
        if (isset($resolve['server_id'])) {
            $serverId = (int)$resolve['server_id'];
            $isSuspended = ((int)($resolve['suspended'] ?? 0) === 1);
        }
    }

    if ($serverId > 0 && !$isSuspended) {
        $status = ipmipanel_apiCall($params, 'status', [
            'server_id' => $serverId,
            'quick'     => '1',
        ]);
        if (isset($status['power_state'])) {
            $powerState = strtolower((string)$status['power_state']);
        }
    }

    $ipmiSessionUrl = '';
    $kvmConsoleUrl = '';
    $panelLoginUrl = '';
    if ($serverId > 0 && $panelUrl !== '') {
        $ipmiSessionUrl = $panelUrl . '/ipmi_session.php?id=' . $serverId;
        $kvmConsoleUrl = $panelUrl . '/ipmi_kvm.php?id=' . $serverId;
        $panelLoginUrl = $panelUrl . '/login.php';
    }

    $panelUsername = trim((string)($params['username'] ?? ''));
    $panelPassword = trim((string)($params['password'] ?? ''));

    return [
        'tabOverviewReplacementTemplate' => 'templates/clientarea-controls.tpl',
        'templateVariables' => [
            'ipmipanelPanelUrl'       => $panelUrl,
            'ipmipanelServerId'       => $serverId,
            'ipmipanelHostname'       => $hostname,
            'ipmipanelIpmiSessionUrl' => $ipmiSessionUrl,
            'ipmipanelKvmConsoleUrl'  => $kvmConsoleUrl,
            'ipmipanelIsSuspended'    => $isSuspended,
            'ipmipanelPowerState'     => $powerState,
            'ipmipanelPanelLoginUrl'  => $panelLoginUrl,
            'ipmipanelPanelUsername'  => $panelUsername,
            'ipmipanelPanelPassword'  => $panelPassword,
        ],
    ];
}
