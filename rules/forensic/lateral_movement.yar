// Forensic YARA rules for lateral-movement tooling and artifacts.
// Loaded by yara_scan through forensic_yara_rules_dir / EDR_YARA_RULES_DIR.

rule Lateral_PsExec_PAExec_Artifacts {
    meta:
        severity = "HIGH"
        description = "PsExec/PAExec remote service execution artifacts"
        mitre = "T1021.002,T1569.002"
        confidence = "0.75"
    strings:
        $svc1 = "PSEXESVC" ascii wide nocase
        $svc2 = "PAExec" ascii wide nocase
        $tool1 = "PsExec" ascii wide nocase
        $share1 = "ADMIN$" ascii wide nocase
        $share2 = "\\svcctl" ascii wide nocase
        $api1 = "OpenSCManager" ascii wide
        $api2 = "CreateService" ascii wide
        $api3 = "StartService" ascii wide
    condition:
        filesize < 25MB and (((any of ($svc*) or any of ($tool*)) and any of ($share*) and any of ($api*)) or ((any of ($svc*) and any of ($tool*)) and 2 of ($api*)))
}

rule Lateral_Impacket_Exec_Family {
    meta:
        severity = "HIGH"
        description = "Impacket wmiexec/smbexec/atexec/dcomexec lateral execution string cluster"
        mitre = "T1021.002,T1021.003,T1047,T1053.005"
        confidence = "0.75"
    strings:
        $tool1 = "wmiexec.py" ascii wide nocase
        $tool2 = "smbexec.py" ascii wide nocase
        $tool3 = "atexec.py" ascii wide nocase
        $tool4 = "dcomexec.py" ascii wide nocase
        $lib1 = "impacket" ascii wide nocase
        $svc1 = "__output" ascii wide nocase
        $svc2 = "\\ADMIN$\\" ascii wide nocase
        $svc3 = "RemComSvc" ascii wide nocase
        $cmd1 = "cmd.exe /Q /c" ascii wide nocase
        $cmd2 = "Windows Management Instrumentation" ascii wide nocase
        $cmd3 = "Win32_Process" ascii wide nocase
    condition:
        filesize < 30MB and (($lib1 and any of ($tool*) and (any of ($svc*) or any of ($cmd*))) or (2 of ($tool*) and (any of ($svc*) or any of ($cmd*))) or ($cmd1 and 2 of ($svc*)))
}

rule Lateral_CME_NetExec_InvokeExec {
    meta:
        severity = "MEDIUM"
        description = "CrackMapExec/NetExec/Invoke-SMBExec/Invoke-WMIExec lateral movement tooling"
        mitre = "T1021.002,T1047,T1550.002"
        confidence = "0.65"
    strings:
        $tool1 = "CrackMapExec" ascii wide nocase
        $tool2 = "NetExec" ascii wide nocase
        $tool3 = "Invoke-SMBExec" ascii wide nocase
        $tool4 = "Invoke-WMIExec" ascii wide nocase
        $arg1 = "--hashes" ascii wide nocase
        $arg2 = "-H " ascii wide
        $proto1 = "smb://" ascii wide nocase
        $proto2 = "wmiexec" ascii wide nocase
        $proto3 = "psexec" ascii wide nocase
    condition:
        filesize < 25MB and (any of ($tool*) and (any of ($arg*) and any of ($proto*)))
}
