// Forensic YARA rules for credential-theft tooling and artifacts.
// Loaded by yara_scan through forensic_yara_rules_dir / EDR_YARA_RULES_DIR.

rule Credential_Mimikatz_Family_Strings {
    meta:
        severity = "HIGH"
        description = "Mimikatz/Kiwi/SafetyKatz/SharpKatz credential theft string cluster"
        mitre = "T1003.001,T1558"
        confidence = "0.8"
    strings:
        $tool1 = "mimikatz" ascii wide nocase
        $tool2 = "kiwi" ascii wide nocase
        $tool3 = "SafetyKatz" ascii wide nocase
        $tool4 = "SharpKatz" ascii wide nocase
        $cmd1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd2 = "sekurlsa::ekeys" ascii wide nocase
        $cmd3 = "lsadump::sam" ascii wide nocase
        $cmd4 = "lsadump::dcsync" ascii wide nocase
        $cmd5 = "privilege::debug" ascii wide nocase
        $cmd6 = "kerberos::golden" ascii wide nocase
    condition:
        filesize < 20MB and (any of ($tool*) and 2 of ($cmd*) or 3 of ($cmd*))
}

rule Credential_LSASS_Dump_Tooling {
    meta:
        severity = "HIGH"
        description = "LSASS dump tooling/API strings including nanodump, dumpert and MiniDumpWriteDump"
        mitre = "T1003.001"
        confidence = "0.75"
    strings:
        $target1 = "lsass.exe" ascii wide nocase
        $target2 = "lsass.dmp" ascii wide nocase
        $api1 = "MiniDumpWriteDump" ascii wide
        $api2 = "PssCaptureSnapshot" ascii wide
        $api3 = "Dbghelp.dll" ascii wide nocase
        $tool1 = "nanodump" ascii wide nocase
        $tool2 = "Dumpert" ascii wide nocase
        $tool3 = "comsvcs.dll" ascii wide nocase
        $arg1 = "-ma lsass" ascii wide nocase
        $arg2 = "sekurlsa::minidump" ascii wide nocase
    condition:
        filesize < 30MB and ((any of ($target*) and any of ($api*) and (any of ($tool*) or any of ($arg*))) or (2 of ($tool*) and any of ($api*)))
}

rule Credential_LaZagne_Browser_Secrets {
    meta:
        severity = "MEDIUM"
        description = "LaZagne/browser credential harvesting string cluster"
        mitre = "T1555.003,T1555"
        confidence = "0.65"
    strings:
        $tool1 = "LaZagne" ascii wide nocase
        $path1 = "Login Data" ascii wide nocase
        $path2 = "logins.json" ascii wide nocase
        $path3 = "key4.db" ascii wide nocase
        $path4 = "Cookies" ascii wide nocase
        $kw1 = "browser passwords" ascii wide nocase
        $kw2 = "dpapi" ascii wide nocase
        $kw3 = "Windows Vault" ascii wide nocase
    condition:
        filesize < 20MB and (($tool1 and (any of ($path*) and any of ($kw*))) or (3 of ($path*) and any of ($kw*)))
}
