// 取证 YARA 起始规则集 — 进程注入 / 远控相关。
// 由 yara_scan 命令通过 forensic_yara_rules_dir / EDR_YARA_RULES_DIR 加载。
// 规则名即回流到 YARA_HIT rules=[...] 的标识。

rule Injection_API_Combo {
    meta:
        severity    = "HIGH"
        description = "经典远程线程注入 API 组合"
        mitre       = "T1055"
        confidence  = "0.7"
    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "NtCreateThreadEx" ascii wide
        $a5 = "QueueUserAPC" ascii wide
        $a6 = "SetThreadContext" ascii wide
    condition:
        2 of ($a*)
}

rule Process_Hollowing_Indicators {
    meta:
        severity    = "HIGH"
        description = "进程镂空 / 替换映像常见 API"
        mitre       = "T1055.012"
        confidence  = "0.7"
    strings:
        $h1 = "NtUnmapViewOfSection" ascii wide
        $h2 = "ZwUnmapViewOfSection" ascii wide
        $h3 = "NtMapViewOfSection" ascii wide
        $h4 = "ResumeThread" ascii wide
        $h5 = "CreateProcessW" ascii wide
    condition:
        ($h1 or $h2 or $h3) and $h4 and $h5
}

rule Reflective_Loader_String {
    meta:
        severity    = "MEDIUM"
        description = "反射式 DLL 加载特征字符串"
        mitre       = "T1620"
        confidence  = "0.6"
    strings:
        $r1 = "ReflectiveLoader" ascii wide
        $r2 = "_ReflectiveLoader@4" ascii
    condition:
        any of ($r*)
}
