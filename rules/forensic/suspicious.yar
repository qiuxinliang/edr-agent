// 取证 YARA 起始规则集 — 脚本混淆 / C2 / webshell 通用特征。

rule Suspicious_PowerShell_Obfuscation {
    meta:
        severity    = "HIGH"
        description = "PowerShell 编码下载 / 混淆执行"
        mitre       = "T1059.001"
        confidence  = "0.7"
    strings:
        $p1 = "FromBase64String" ascii wide nocase
        $p2 = "-EncodedCommand" ascii wide nocase
        $p3 = "-enc " ascii wide nocase
        $p4 = "DownloadString" ascii wide nocase
        $p5 = "IEX" ascii wide
        $p6 = "Invoke-Expression" ascii wide nocase
        $p7 = "-WindowStyle Hidden" ascii wide nocase
    condition:
        2 of ($p*)
}

rule Suspicious_Webshell_Eval {
    meta:
        severity    = "HIGH"
        description = "脚本 webshell 动态执行特征"
        mitre       = "T1505.003"
        confidence  = "0.6"
    strings:
        $w1 = "eval(" ascii nocase
        $w2 = "base64_decode" ascii nocase
        $w3 = "system(" ascii nocase
        $w4 = "shell_exec" ascii nocase
        $w5 = "passthru(" ascii nocase
        $w6 = "Runtime.getRuntime().exec" ascii
    condition:
        2 of ($w*)
}

rule Suspicious_CobaltStrike_Markers {
    meta:
        severity    = "CRITICAL"
        description = "Cobalt Strike beacon / 默认配置标记"
        mitre       = "T1071"
        confidence  = "0.6"
    strings:
        $c1 = "%%IMPORT%%" ascii
        $c2 = "beacon.dll" ascii nocase
        $c3 = "ReflectiveLoader" ascii
        $c4 = { 69 68 69 68 69 6b 2e 2e 2e }   // 常见 sleep mask/解码桩字节
        $ua = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" ascii
    condition:
        2 of them
}

rule Suspicious_C2_Network_Strings {
    meta:
        severity    = "MEDIUM"
        description = "可疑外联 / 隐蔽通道字符串"
        mitre       = "T1071"
        confidence  = "0.4"
    strings:
        $n1 = ".onion" ascii nocase
        $n2 = "/gate.php" ascii nocase
        $n3 = "/submit.php" ascii nocase
        $n4 = "User-Agent: curl" ascii nocase
    condition:
        any of ($n*)
}
