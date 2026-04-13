<?php

/**
 * Full autolaunch runtime body (preamble + shared helpers + vendor branches + IIFE closer).
 */
function ipmiProxyBuildIloRuntimeJs(string $familyJs, string $planJs, string $pxJs, string $autoJs, string $dbgLit): string
{
    return ipmiProxyBuildKvmAutoLaunchPreambleJs($familyJs, $planJs, $pxJs, $autoJs, $dbgLit)
        . ipmiProxyBuildKvmAutoLaunchIloDomHelpersJs()
        . ipmiProxyBuildKvmRuntimeProgressHelpersJs()
        . ipmiProxyBuildKvmAutoLaunchLaunchGateJs()
        . ipmiProxyBuildIloKvmScript()
        . ipmiProxyBuildIdracKvmScript()
        . ipmiProxyBuildSupermicroKvmScript()
        . '})();';
}
