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
