// Forensic YARA rules for privilege-escalation tooling and UAC bypass artifacts.
// Loaded by yara_scan through forensic_yara_rules_dir / EDR_YARA_RULES_DIR.

rule Privilege_Potato_PrintSpoofer_Family {
    meta:
        severity = "HIGH"
        description = "Potato/PrintSpoofer/EfsPotato SeImpersonate privilege escalation tooling"
        mitre = "T1068,T1134.001"
        confidence = "0.75"
    strings:
        $tool1 = "JuicyPotato" ascii wide nocase
        $tool2 = "RoguePotato" ascii wide nocase
        $tool3 = "SweetPotato" ascii wide nocase
        $tool4 = "GodPotato" ascii wide nocase
        $tool5 = "EfsPotato" ascii wide nocase
        $tool6 = "PrintSpoofer" ascii wide nocase
        $priv1 = "SeImpersonatePrivilege" ascii wide
        $priv2 = "ImpersonateNamedPipeClient" ascii wide
        $priv3 = "RpcImpersonateClient" ascii wide
        $pipe1 = "\\pipe\\spoolss" ascii wide nocase
        $pipe2 = "\\pipe\\efsrpc" ascii wide nocase
        $clsid1 = "{4991d34b-80a1-4291-83b6-3328366b9097}" ascii wide nocase
    condition:
        filesize < 30MB and ((any of ($tool*) and (any of ($priv*) or any of ($pipe*) or any of ($clsid*))) or (2 of ($priv*) and (any of ($pipe*) or any of ($clsid*))))
}

rule Privilege_UAC_Bypass_LOLBIN_Artifacts {
    meta:
        severity = "MEDIUM"
        description = "UAC bypass LOLBIN and registry hijack artifact strings"
        mitre = "T1548.002"
        confidence = "0.65"
    strings:
        $bin1 = "fodhelper.exe" ascii wide nocase
        $bin2 = "ComputerDefaults.exe" ascii wide nocase
        $bin3 = "eventvwr.exe" ascii wide nocase
        $bin4 = "cmstp.exe" ascii wide nocase
        $bin5 = "sdclt.exe" ascii wide nocase
        $bin6 = "SilentCleanup" ascii wide nocase
        $reg1 = "ms-settings\\Shell\\Open\\command" ascii wide nocase
        $reg2 = "mscfile\\shell\\open\\command" ascii wide nocase
        $reg3 = "App Paths\\control.exe" ascii wide nocase
        $verb1 = "DelegateExecute" ascii wide nocase
        $verb2 = "autoElevate" ascii wide nocase
    condition:
        filesize < 20MB and (any of ($bin*) and (any of ($reg*) and any of ($verb*)))
}

rule Privilege_Token_Impersonation_Tooling {
    meta:
        severity = "MEDIUM"
        description = "Token impersonation and make-token tooling strings"
        mitre = "T1134"
        confidence = "0.65"
    strings:
        $api1 = "DuplicateTokenEx" ascii wide
        $api2 = "ImpersonateLoggedOnUser" ascii wide
        $api3 = "SetThreadToken" ascii wide
        $api4 = "CreateProcessWithTokenW" ascii wide
        $cmd1 = "token::elevate" ascii wide nocase
        $cmd2 = "token::run" ascii wide nocase
        $cmd3 = "make_token" ascii wide nocase
        $cmd4 = "steal_token" ascii wide nocase
    condition:
        filesize < 25MB and (2 of ($api*) and any of ($cmd*) or 3 of ($api*))
}
