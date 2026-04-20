rule JSP_Webshell_Runtime_Exec {
    meta:
        description = "JSP Runtime.exec command execution"
        severity = "CRITICAL"
        confidence = "0.90"
    strings:
        $runtime = "Runtime.getRuntime().exec(" nocase
        $proc_builder = "ProcessBuilder" nocase
        $req_param = /request\.(getParameter|getAttribute)\s*\(/ nocase
        $mixed = /new\s+String\s*\(\s*request\.getParameter/ nocase
    condition:
        filesize < 2MB and ($runtime or $proc_builder) and ($req_param or $mixed)
}

rule JSP_Webshell_ClassLoader {
    meta:
        description = "JSP memory shell and class-loader behavior"
        severity = "CRITICAL"
        confidence = "0.95"
    strings:
        $classloader = "defineClass" nocase
        $urlclassloader = "URLClassLoader" nocase
        $add_filter = "addFilter" nocase
        $add_servlet = "addServlet" nocase
        $b64_class = /Base64\.getDecoder\(\)\.decode\s*\(/ nocase
    condition:
        filesize < 5MB and ($classloader or $urlclassloader) and ($b64_class or $add_filter or $add_servlet)
}

rule ASPX_Webshell_Eval {
    meta:
        description = "ASPX dynamic code compile and execute"
        severity = "CRITICAL"
        confidence = "0.90"
    strings:
        $csharp = "CSharpCodeProvider" nocase
        $compile = "CompileAssemblyFromSource" nocase
        $assembly = "Assembly.Load(" nocase
        $req_form = /Request\.(Form|QueryString|Params)\s*\[/ nocase
        $req_input = "Request.InputStream" nocase
    condition:
        filesize < 5MB and ($csharp or $compile or $assembly) and ($req_form or $req_input)
}

rule ASPX_Webshell_CommandExec {
    meta:
        description = "ASPX Process.Start command execution"
        severity = "HIGH"
        confidence = "0.85"
    strings:
        $proc_start = "Process.Start(" nocase
        $proc_obj = "new Process()" nocase
        $cmd_line = "StartInfo.FileName" nocase
        $req_input = /Request\.(Form|QueryString|Params)\s*\[/ nocase
    condition:
        filesize < 2MB and ($proc_start or ($proc_obj and $cmd_line)) and $req_input
}

rule Generic_Webshell_Encoding_Layering {
    meta:
        description = "Multi-layer encoding obfuscation patterns"
        severity = "MEDIUM"
        confidence = "0.65"
    strings:
        $triple_b64 = /base64_decode\s*\(\s*base64_decode\s*\(\s*base64_decode/
        $gz_b64 = /gzinflate\s*\(\s*base64_decode\s*\(/
        $str_replace = /str_replace\s*\(\s*['"][ ]?['"]\s*,\s*['"]['"]\s*,/
    condition:
        filesize < 5MB and any of them
}
