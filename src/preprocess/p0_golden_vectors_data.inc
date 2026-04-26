/* 由 edr-agent/scripts/gen_p0_golden_vectors_inc.py 自 p0_golden_vectors.json 生成，勿手改。 */
#ifndef P0_GOLDEN_VECTORS_DATA_INC
#define P0_GOLDEN_VECTORS_DATA_INC
#define P0_GOLDEN_N 7
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
static const char *p0_golden_rule_id[] = {
p0_gv_r0, p0_gv_r1, p0_gv_r2, p0_gv_r3, p0_gv_r4, p0_gv_r5, p0_gv_r6, };
static const char *p0_golden_process_name[] = {
p0_gv_p0, p0_gv_p1, p0_gv_p2, p0_gv_p3, p0_gv_p4, p0_gv_p5, p0_gv_p6, };
static const char *p0_golden_cmdline[] = {
p0_gv_c0, p0_gv_c1, p0_gv_c2, p0_gv_c3, p0_gv_c4, p0_gv_c5, p0_gv_c6, };
static const int p0_golden_expect[] = {
1, 0, 1, 1, 0, 0, 0, };
#endif

