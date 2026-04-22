/**
 * SQLite 规则库元数据（版本号、行数），供 AVE_GetStatus 与平台热更新观测。
 */
#ifndef EDR_AVE_RULES_META_H
#define EDR_AVE_RULES_META_H

#include <stddef.h>

/** 读取 `ave_db_meta` 表：`SELECT value FROM ave_db_meta WHERE key=?` */
int edr_ave_db_meta_get(const char *db_path, const char *key, char *out, size_t out_cap);

/** 统计 `ioc_file_hash` 中 `is_active=1` 行数（失败返回 -1） */
int edr_ave_db_count_ioc_rows(const char *db_path);

/** 统计 `file_hash_whitelist` 中 `is_active=1` 行数 */
int edr_ave_db_count_file_whitelist_rows(const char *db_path);

#endif
