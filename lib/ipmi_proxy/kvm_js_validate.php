<?php

/**
 * Best-effort brace balance check for generated autolaunch JS (strings/comments aware).
 *
 * @return array{ok: bool, reason: string, depth: int}
 */
function ipmiProxyValidateGeneratedJsBraceBalance(string $js): array
{
    $depth = 0;
    $n = strlen($js);
    $inStr = false;
    $strCh = '';
    $esc = false;
    $inLineComment = false;
    $inBlockComment = false;
    for ($i = 0; $i < $n; $i++) {
        $c = $js[$i];
        $next = ($i + 1 < $n) ? $js[$i + 1] : '';
        if ($inLineComment) {
            if ($c === "\n") {
                $inLineComment = false;
            }
            continue;
        }
        if ($inBlockComment) {
            if ($c === '*' && $next === '/') {
                $inBlockComment = false;
                $i++;
            }
            continue;
        }
        if ($inStr) {
            if ($esc) {
                $esc = false;
                continue;
            }
            if ($c === '\\' && ($strCh === '"' || $strCh === '\'' || $strCh === '`')) {
                $esc = true;
                continue;
            }
            if ($c === $strCh) {
                $inStr = false;
            }
            continue;
        }
        if ($c === '/' && $next === '/') {
            $inLineComment = true;
            $i++;
            continue;
        }
        if ($c === '/' && $next === '*') {
            $inBlockComment = true;
            $i++;
            continue;
        }
        if ($c === '"' || $c === '\'' || $c === '`') {
            $inStr = true;
            $strCh = $c;
            continue;
        }
        if ($c === '{') {
            $depth++;
        } elseif ($c === '}') {
            $depth--;
            if ($depth < 0) {
                return ['ok' => false, 'reason' => 'negative_brace_depth', 'depth' => $depth];
            }
        }
    }
    if ($inStr) {
        return ['ok' => false, 'reason' => 'unterminated_string', 'depth' => $depth];
    }
    if ($inBlockComment) {
        return ['ok' => false, 'reason' => 'unterminated_block_comment', 'depth' => $depth];
    }

    return [
        'ok'     => $depth === 0,
        'reason' => $depth === 0 ? '' : 'unbalanced_braces',
        'depth'  => $depth,
    ];
}

/**
 * Replace strings/comments with whitespace for lightweight token analysis.
 */
function ipmiProxyGeneratedJsTokenView(string $js): string
{
    $n = strlen($js);
    $out = '';
    $inStr = false;
    $strCh = '';
    $esc = false;
    $inLineComment = false;
    $inBlockComment = false;
    for ($i = 0; $i < $n; $i++) {
        $c = $js[$i];
        $next = ($i + 1 < $n) ? $js[$i + 1] : '';
        if ($inLineComment) {
            if ($c === "\n") {
                $inLineComment = false;
                $out .= "\n";
            } else {
                $out .= ' ';
            }
            continue;
        }
        if ($inBlockComment) {
            if ($c === '*' && $next === '/') {
                $inBlockComment = false;
                $out .= '  ';
                $i++;
            } else {
                $out .= ($c === "\n" ? "\n" : ' ');
            }
            continue;
        }
        if ($inStr) {
            $out .= ($c === "\n" ? "\n" : ' ');
            if ($esc) {
                $esc = false;
                continue;
            }
            if ($c === '\\' && ($strCh === '"' || $strCh === '\'' || $strCh === '`')) {
                $esc = true;
                continue;
            }
            if ($c === $strCh) {
                $inStr = false;
            }
            continue;
        }
        if ($c === '/' && $next === '/') {
            $inLineComment = true;
            $out .= '  ';
            $i++;
            continue;
        }
        if ($c === '/' && $next === '*') {
            $inBlockComment = true;
            $out .= '  ';
            $i++;
            continue;
        }
        if ($c === '"' || $c === '\'' || $c === '`') {
            $inStr = true;
            $strCh = $c;
            $out .= ' ';
            continue;
        }
        $out .= $c;
    }

    return $out;
}

/**
 * Parser-like checks to catch malformed concatenation boundaries not covered by brace depth.
 *
 * @return array{ok: bool, reason: string}
 */
function ipmiProxyValidateGeneratedJsWithParserLikeChecks(string $js): array
{
    $tv = ipmiProxyGeneratedJsTokenView($js);
    if (preg_match('/(^|[;{}\\s])catch\\s*\\(/m', $tv) === 1 && preg_match('/\\btry\\b/', $tv) !== 1) {
        return ['ok' => false, 'reason' => 'catch_without_try_token'];
    }
    if (preg_match('/\\}\\s*catch\\s*\\(/', $tv) === 1 && preg_match('/\\btry\\s*\\{[\\s\\S]{0,400}\\}\\s*catch\\s*\\(/', $tv) !== 1) {
        return ['ok' => false, 'reason' => 'suspicious_try_catch_boundary'];
    }
    if (preg_match('/catch\\s*\\([^)]*$/m', $tv) === 1) {
        return ['ok' => false, 'reason' => 'unterminated_catch_clause'];
    }
    if (preg_match('/\\btry\\b(?![\\s\\S]{0,40}\\{)/', $tv) === 1) {
        return ['ok' => false, 'reason' => 'try_without_block_open'];
    }

    return ['ok' => true, 'reason' => ''];
}

/**
 * Optional JS parser check via node --check.
 *
 * @return array{ok: bool, reason: string}
 */
function ipmiProxyValidateGeneratedJsWithNodeCheck(string $js): array
{
    if (stripos(PHP_OS_FAMILY, 'Windows') === false && stripos(PHP_OS_FAMILY, 'Linux') === false && stripos(PHP_OS_FAMILY, 'Darwin') === false) {
        return ['ok' => true, 'reason' => 'node_check_skipped_platform'];
    }
    if (!function_exists('shell_exec') || !function_exists('sys_get_temp_dir')) {
        return ['ok' => true, 'reason' => 'node_check_unavailable'];
    }
    $tmp = rtrim((string) sys_get_temp_dir(), "/\\") . DIRECTORY_SEPARATOR . 'ipmi_kvm_js_check_' . bin2hex(random_bytes(5)) . '.js';
    if (@file_put_contents($tmp, $js) === false) {
        return ['ok' => true, 'reason' => 'node_check_temp_write_failed'];
    }
    $cmd = 'node --check ' . escapeshellarg($tmp) . ' 2>&1';
    $out = shell_exec($cmd);
    @unlink($tmp);
    if (!is_string($out)) {
        return ['ok' => true, 'reason' => 'node_check_not_available'];
    }
    $low = strtolower($out);
    if ($low === '' || str_contains($low, 'syntaxerror') === false) {
        return ['ok' => true, 'reason' => ''];
    }
    if (str_contains($low, "unexpected token 'catch'")) {
        return ['ok' => false, 'reason' => 'node_syntax_unexpected_catch'];
    }

    return ['ok' => false, 'reason' => 'node_syntax_error'];
}

/**
 * @return array{ok: bool, reason: string, depth: int, bytes: int}
 */
function ipmiProxyValidateGeneratedIloJs(string $fullPatchJs): array
{
    $bal = ipmiProxyValidateGeneratedJsBraceBalance($fullPatchJs);
    $out = [
        'ok'     => $bal['ok'],
        'reason' => (string) $bal['reason'],
        'depth'  => (int) $bal['depth'],
        'bytes'  => strlen($fullPatchJs),
    ];
    if ($out['ok']) {
        $p = ipmiProxyValidateGeneratedJsWithParserLikeChecks($fullPatchJs);
        if (!$p['ok']) {
            $out['ok'] = false;
            $out['reason'] = $p['reason'];
        }
    }
    if ($out['ok'] && strlen($fullPatchJs) <= 1600000) {
        $n = ipmiProxyValidateGeneratedJsWithNodeCheck($fullPatchJs);
        if (!$n['ok']) {
            $out['ok'] = false;
            $out['reason'] = $n['reason'];
        }
    }
    if ($out['ok'] && stripos($fullPatchJs, 'function tryClickIloDiscoveryLaunch') !== false) {
        if (preg_match('/catch\s*\(\s*_q\s*\)\s*\{\s*\}\s*return""\s*;\s*\}\s*function\s+collectContexts\s*\(/', $fullPatchJs) !== 1) {
            $out['ok'] = false;
            $out['reason'] = 'tryClickIloDiscoveryLaunch_tail_pattern_mismatch';
        }
    }

    return $out;
}

/** @return array{ok: bool, reason: string, depth: int, bytes: int} */
function ipmiProxyValidateGeneratedJs(string $fullPatchJs): array
{
    return ipmiProxyValidateGeneratedIloJs($fullPatchJs);
}

/**
 * Remove proxy token and similar material from generated JS before writing debug artifacts.
 */
function ipmiProxyRedactSensitiveFromGeneratedJs(string $js, string $token): string
{
    if ($token !== '' && preg_match('/^[a-f0-9]{64}$/', $token)) {
        $js = str_replace($token, '<redacted-token>', $js);
    }

    return (string) preg_replace('#/ipmi_proxy\\.php/[a-f0-9]{64}#i', '/ipmi_proxy.php/<redacted-token>', $js);
}

/**
 * When validation fails, persist a redacted excerpt for offline inspection (debug only).
 */
function ipmiProxyDumpInvalidGeneratedJsContext(string $js, string $reason, int $depth, string $token): void
{
    if (!ipmiProxyDebugEnabled()) {
        return;
    }
    $redacted = ipmiProxyRedactSensitiveFromGeneratedJs($js, $token);
    $hash = substr(sha1($redacted), 0, 8);
    $path = rtrim(sys_get_temp_dir(), '/') . '/ipmi_ilo_runtime_js_invalid_' . gmdate('Ymd_His') . '_' . $hash . '.log';
    $head = substr($redacted, 0, 6000);
    $tail = strlen($redacted) > 12000 ? substr($redacted, -6000) : '';
    $payload = 'reason=' . $reason . "\ndepth=" . (string) $depth . "\nbytes=" . (string) strlen($js) . "\n--- head ---\n"
        . $head . "\n--- tail ---\n" . $tail . "\n";
    if (@file_put_contents($path, $payload) !== false) {
        ipmiProxyDebugLog('ilo_runtime_js_invalid_dump_written', [
            'path'   => $path,
            'reason' => $reason,
            'depth'  => $depth,
        ]);
    }
}
