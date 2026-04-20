rule PHP_Webshell_OneLiners {
    meta:
        description = "PHP one-liner webshell patterns"
        severity = "CRITICAL"
        confidence = "0.95"
    strings:
        $eval_post = /@?eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $assert_post = /@?assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\s*\[/ nocase
        $b64_eval = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $gz_eval = /eval\s*\(\s*gz(inflate|uncompress|decode)\s*\(/ nocase
        $var_func = /\$[a-zA-Z_]\w*\s*=\s*['"]assert['"]\s*;/ nocase
    condition:
        filesize < 1MB and any of ($eval_post, $assert_post, $b64_eval, $gz_eval, $var_func)
}

rule PHP_Webshell_ChinaChopper {
    meta:
        description = "ChinaChopper/Behinder/AntSword common patterns"
        severity = "CRITICAL"
        confidence = "1.0"
    strings:
        $chopper = "eval(base64_decode($_POST" nocase
        $chopper2 = "@eval(base64_decode($_POST" nocase
        $behinder_v3 = { 40 65 76 61 6C 28 67 7A 69 6E 66 6C 61 74 65 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 28 }
        $antsword = "@ini_set(\"display_errors\",\"0\");@set_time_limit(0);"
    condition:
        filesize < 500KB and any of them
}

rule PHP_Webshell_FunctionObfuscation {
    meta:
        description = "PHP function name obfuscation webshell"
        severity = "HIGH"
        confidence = "0.80"
    strings:
        $rot13 = /\bstr_rot13\s*\(\s*['"][a-zA-Z]+['"]\s*\)/ nocase
        $hex2bin = /\bhex2bin\s*\(\s*['"][0-9a-fA-F]+['"]\s*\)/ nocase
        $chr_concat = /chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)/
        $strrev = /\bstrrev\s*\(\s*['"][a-zA-Z]{4,}['"]\s*\)/ nocase
    condition:
        filesize < 2MB and 2 of ($rot13, $hex2bin, $chr_concat, $strrev)
}

rule PHP_Webshell_SystemCommand {
    meta:
        description = "PHP system command with external input"
        severity = "HIGH"
        confidence = "0.75"
    strings:
        $system = /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/ nocase
        $user_input = /\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[/
    condition:
        filesize < 5MB and $system and $user_input
}

rule PHP_Webshell_FilesystemWrite {
    meta:
        description = "PHP writes executable script content"
        severity = "HIGH"
        confidence = "0.70"
    strings:
        $fwrite = /fwrite\s*\(/ nocase
        $file_put = /file_put_contents\s*\(/ nocase
        $php_tag = "<?php"
        $php_tag2 = "<?="
        $user_input = /\$_(GET|POST|REQUEST|COOKIE)\s*\[/
    condition:
        filesize < 10MB and ($fwrite or $file_put) and ($php_tag or $php_tag2) and $user_input
}
