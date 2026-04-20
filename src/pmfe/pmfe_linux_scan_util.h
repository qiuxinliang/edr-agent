/* Linux PMFE：/proc/maps 解析与候选打分（供 pmfe_engine 与单元测试共用） */

#ifndef PMFE_LINUX_SCAN_UTIL_H
#define PMFE_LINUX_SCAN_UTIL_H

#include <stddef.h>
#include <stdint.h>

const char *edr_pmfe_linux_skip_ws(const char *p);

/**
 * 解析 /proc/pid/maps 单行：地址范围、perms、pathname（含空格时取余下整段）。
 * @param perms 至少 5 字节（4 字符 + NUL）
 */
int edr_pmfe_linux_parse_maps_line(const char *line, uint64_t *lo, uint64_t *hi, char perms[5], char *path,
                                   size_t path_cap);

/**
 * 私有可执行映射候选打分。anon_exec_only!=0 时仅匿名/[vdso] 等路径（无 '/' 或以 '[' 开头）参与。
 */
float edr_pmfe_linux_map_candidate_score(const char *perms, uint64_t lo, uint64_t hi, const char *path,
                                         int anon_exec_only);

#endif
