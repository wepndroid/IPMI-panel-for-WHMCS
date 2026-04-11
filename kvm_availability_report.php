<?php
require __DIR__ . '/config.php';
require __DIR__ . '/lib/ipmi_web_session.php';

function csvCell(string $value): string
{
    return '"' . str_replace('"', '""', $value) . '"';
}

/**
 * @return array<int, string>
 */
function kvmCandidates(string $bmcType): array
{
    $type = ipmiWebNormalizeBmcType($bmcType);
    if (ipmiWebIsNormalizedIloType($type)) {
        return [
            '/html/application.html?ipmi_kvm_auto=1',
            '/html/rc_info.html?ipmi_kvm_auto=1',
            '/html/irc.html',
            '/html/jnlp_template.html',
            '/html/java_irc.html',
            '/html/IRC.application?cofc_goback=false',
        ];
    }
    switch ($type) {
        case 'idrac':
            return [
                '/viewer.html',
                '/console.html',
                '/start.html',
                '/index.html',
                '/restgui/start.html',
            ];
        case 'supermicro':
            return [
                '/cgi/url_redirect.cgi?url_name=ikvm&url_type=html5',
                '/cgi/url_redirect.cgi?url_name=ikvm&url_type=jwsk',
                '/cgi/url_redirect.cgi?url_name=ikvm&url_type=java',
                '/cgi/url_redirect.cgi?url_name=ikvm',
            ];
        case 'ami':
            return [
                '/kvm',
                '/console',
                '/html/application.html',
                '/',
            ];
        default:
            return ['/'];
    }
}

function classifyLoginFailure(string $msg): string
{
    $m = strtolower($msg);
    if (str_contains($m, 'session_limit') || str_contains($m, 'maximum number of user sessions')) {
        return 'LOGIN_SESSION_LIMIT';
    }
    if (str_contains($m, 'invalid_credentials')) {
        return 'LOGIN_INVALID_CREDENTIALS';
    }
    if (str_contains($m, 'connect_failed') || str_contains($m, 'bmc unreachable')) {
        return 'LOGIN_CONNECT_FAILED';
    }

    return 'LOGIN_FAILED';
}

echo "server_id,server_name,bmc_type,result,best_path,best_mode,best_http,best_score,best_unavailable,error\n";

$q = $mysqli->query("SELECT id, server_name, bmc_type FROM servers ORDER BY id ASC");
if (!$q) {
    fwrite(STDERR, "Failed to read servers table.\n");
    exit(1);
}

while ($row = $q->fetch_assoc()) {
    $serverId = (int) ($row['id'] ?? 0);
    $serverName = (string) ($row['server_name'] ?? '');
    $bmcType = (string) ($row['bmc_type'] ?? 'generic');

    $result = 'NO_WORKING_ENDPOINT';
    $bestPath = '';
    $bestMode = '';
    $bestHttp = 0;
    $bestScore = -100000;
    $bestUnavailable = 0;
    $error = '';

    try {
        $session = ipmiWebCreateSession($mysqli, $serverId, 1, 'admin', 300);
        $candidates = kvmCandidates($bmcType);

        $hasBrowserNative = false;
        $hasLegacy = false;
        $hasUnavailable = false;

        foreach ($candidates as $path) {
            $probe = ipmiWebProbeKvmPath($session, $path);
            $score = (int) ($probe['score'] ?? -1000);
            $mode = (string) ($probe['mode'] ?? 'other');
            $ok = !empty($probe['ok']) && empty($probe['unavailable']);

            if ($score > $bestScore) {
                $bestScore = $score;
                $bestPath = $path;
                $bestMode = $mode;
                $bestHttp = (int) ($probe['code'] ?? 0);
                $bestUnavailable = !empty($probe['unavailable']) ? 1 : 0;
            }

            if ($ok && (ipmiWebKvmProbeIsBrowserOriented($probe) || in_array($mode, ['proxy_autolaunch', 'html'], true))) {
                $hasBrowserNative = true;
            }
            if ($ok && in_array($mode, ['clickonce', 'jnlp', 'java_applet'], true)) {
                $hasLegacy = true;
            }
            if (!empty($probe['unavailable'])) {
                $hasUnavailable = true;
            }
        }

        if ($hasBrowserNative) {
            $result = 'HTML5_READY';
        } elseif ($hasLegacy) {
            $result = 'LEGACY_ONLY';
        } elseif ($hasUnavailable) {
            $result = 'KVM_UNAVAILABLE_LICENSE_OR_CONFIG';
        }

        $token = (string) ($session['token'] ?? '');
        if ($token !== '') {
            $st = $mysqli->prepare("UPDATE ipmi_web_sessions SET revoked_at = NOW() WHERE token = ? LIMIT 1");
            if ($st) {
                $st->bind_param('s', $token);
                $st->execute();
                $st->close();
            }
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
        $result = classifyLoginFailure($error);
    }

    echo implode(',', [
        (string) $serverId,
        csvCell($serverName),
        csvCell($bmcType),
        csvCell($result),
        csvCell($bestPath),
        csvCell($bestMode),
        (string) $bestHttp,
        (string) $bestScore,
        (string) $bestUnavailable,
        csvCell($error),
    ]) . "\n";
}
