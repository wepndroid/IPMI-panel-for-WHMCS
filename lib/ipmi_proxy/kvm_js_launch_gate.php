<?php

function ipmiProxyBuildKvmAutoLaunchLaunchGateJs(): string
{
    return 'if(launchDone&&!queryAuto){'
        . 'if(FAMILY==="ilo"){'
        . 'var c0=collectContexts(),ok0=false;'
        . 'for(var z=0;z<c0.length;z++){if(consoleVisible(c0[z])){ok0=true;break;}}'
        . 'if(!ok0){try{if(window.sessionStorage){sessionStorage.removeItem("_ipmi_kvm_autolaunch_done");}}catch(_e2b){} launchDone=false;}'
        . 'if(launchDone){return;}'
        . '}else{'
        . 'try{if(window.sessionStorage){sessionStorage.removeItem("_ipmi_kvm_autolaunch_done");}}catch(_e2c){}'
        . 'launchDone=false;'
        . '}'
        . '}';

}
