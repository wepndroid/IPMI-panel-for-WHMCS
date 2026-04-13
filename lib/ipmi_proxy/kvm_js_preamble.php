<?php

/**
 * Vendor-agnostic KVM autolaunch preamble (FAMILY, PLAN, flow control, navigation helpers).
 */
function ipmiProxyBuildKvmAutoLaunchPreambleJs(string $familyJs, string $planJs, string $pxJs, string $autoJs, string $dbgLit): string
{
    return '(function(){'
        . 'var FAMILY=' . $familyJs . ';var PLAN=' . $planJs . ';var P=' . $pxJs . ';var AUTO=' . $autoJs . ';var DBG=' . $dbgLit . ';'
        . 'function _kvmDbg(ev,extra){try{if(!DBG)return;}catch(e0){return;}try{if(window.console&&console.info)console.info("[ipmi-kvm]",ev,extra!=null?extra:"");}catch(e1){}}'
        . 'var q=null;try{q=new URLSearchParams(location.search||"");}catch(e){q=null;}'
        . 'var queryAuto=(q&&q.get("ipmi_kvm_auto")==="1");'
        . 'try{if(queryAuto&&window.sessionStorage){sessionStorage.setItem("_ipmi_kvm_auto_flow","1");sessionStorage.removeItem("_ipmi_kvm_autolaunch_done");sessionStorage.removeItem("_ipmi_kvm_app_redirected");}}catch(_e0){}'
        . 'var flowActive=false;'
        . 'try{flowActive=queryAuto||AUTO||(window.sessionStorage&&sessionStorage.getItem("_ipmi_kvm_auto_flow")==="1");}catch(_e1){flowActive=queryAuto||AUTO;}'
        . 'if(!flowActive){return;}'
        . 'if(FAMILY==="ilo"&&PLAN&&PLAN.should_attempt_proxy_autolaunch===false){'
        . 'try{_kvmDbg("ilo_autolaunch_suppressed",{verdict:String(PLAN.ilo_native_console_verdict||""),cap:String(PLAN.console_capability||""),suppression:String(PLAN.autolaunch_suppression_detail||"")});}catch(_eSup){}'
        . 'try{_kvmDbg("ilo_no_transport_after_shell_launch",{suppressed:1,suppression:String(PLAN.autolaunch_suppression_detail||"")});}catch(_eNt){}'
        . 'return;}'
        . 'var launchDone=false;'
        . 'try{launchDone=!!(window.sessionStorage&&sessionStorage.getItem("_ipmi_kvm_autolaunch_done")==="1");}catch(_e2){launchDone=false;}'
        . 'function go(p){try{location.href=P+p;}catch(e){}}'
        . 'function pathLower(){try{return String(location.pathname||"").toLowerCase();}catch(e){return"";}}'
        . 'function markDone(){try{if(window.sessionStorage){sessionStorage.setItem("_ipmi_kvm_autolaunch_done","1");}}catch(e){}}'
        . 'function markAppRedirected(){try{if(window.sessionStorage){sessionStorage.setItem("_ipmi_kvm_app_redirected","1");}}catch(e){}}'
        . 'function wasAppRedirected(){try{return !!(window.sessionStorage&&sessionStorage.getItem("_ipmi_kvm_app_redirected")==="1");}catch(e){return false;}}'
        . 'try{var _cs0=document.currentScript;if(_cs0){var _pm=_cs0.getAttribute("data-ipmi-kvm-patch-mode")||"";var _ov="unknown",_hp="unknown",_lv="unknown",_ws0="unknown";try{_ov=ipmiProxyIloLooksLikeOverviewShell(document)?"yes":"no";}catch(_eOv){}try{_hp=ipmiProxyIloHelperActivityPresent()?"yes":"no";}catch(_eHp){}try{_lv=ipmiProxyIloHasLiveDisplayEvidence(window)?"yes":"no";}catch(_eLv){}try{var _ap0=pathLower().indexOf("/html/application.html")>=0;_ws0=ipmiProxyIloLooksLikeWhiteScreenStall(_ap0?14:2,{discNavTriggered:_ap0?1:0})?"yes":"no";}catch(_eWs){}_kvmDbg("ilo_kvm_runtime_debug_matrix",{js_syntactically_valid:_cs0.getAttribute("data-ipmi-kvm-js-valid")==="1"?"yes":"no",runtime_patch_injected:_pm==="safe_fallback"?"no":"yes",application_path_loaded_now:pathLower().indexOf("/html/application.html")>=0?"yes":"no",overview_shell_visible:_ov,management_shell_hint:_ov,helper_activity_seen:_hp,white_screen_coarse:_ws0,live_display_visible:_lv,note:"initial_snapshot_then_see_il_confirmation_signals_collected"});}}catch(_eM0){}'
        . 'function forceSameTabOpen(ctx){try{'
        . 'if(!ctx||!ctx.open||ctx.__ipmi_kvm_open_patched)return;'
        . 'var ow=ctx.open.bind(ctx);'
        . 'ctx.open=function(u,n,f){try{if(typeof u==="string"&&u!==""){ctx.location.href=u;return ctx;}}catch(_e0){}return ow(u,n,f);};'
        . 'ctx.__ipmi_kvm_open_patched=true;'
        . '}catch(e){}}';

}
