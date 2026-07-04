// 取证 YARA 起始规则集 — 加壳 / 打包器特征。

import "pe"

rule Packer_UPX {
    meta:
        severity    = "MEDIUM"
        description = "UPX 加壳特征"
        mitre       = "T1027.002"
        confidence  = "0.7"
    strings:
        $u1 = "UPX0" ascii
        $u2 = "UPX1" ascii
        $u3 = "UPX!" ascii
    condition:
        2 of ($u*)
}

rule Packer_Section_Anomaly {
    meta:
        severity    = "LOW"
        description = "PE 节区可写可执行 / 命名异常（加壳常见）"
        mitre       = "T1027.002"
        confidence  = "0.5"
    condition:
        pe.is_pe and
        for any i in (0..pe.number_of_sections - 1): (
            (pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) and
            (pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE)
        )
}
