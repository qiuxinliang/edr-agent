-- =============================================================================
-- 按终端 IP 汇总「冒烟相关」endpoint_events：每 10 分钟 + 表字段 type
--
-- 用途: 从库中取出某 IP 在最近时间窗内、与 edr_platform_stack_smoke.ps1
-- 关键词可匹配 的行，按 10 分钟桶与 event type 做统计，便于对采集/匹配做验收。
-- 时区: bucket 使用 MySQL 对 `ts` 的数值截断，与 `endpoint_events.ts` 存储的时区一致
--        （若 ts 为 UTC，则以下 period_start 理解为 UTC 对齐的整 10 分钟界）。
--
-- 修改 @ip 与 @hours_ago 后执行:
--   mysql -h ... -p edr < qa_smoke_stats_by_10m_ip.sql
-- 或导出为 UTF-8 文件（自动注入 @ip / @hours_ago）: qa_smoke_stats_export.ps1、.cmd、.sh
-- =============================================================================
SET NAMES utf8mb4;

-- >>> 按你的环境改
SET @ip = '192.168.64.2';
-- 回溯时间（小时），「刚才」冒烟可设 1～3
SET @hours_ago = 4;

-- ---------------------------------------------------------------------------
-- 0) 解析该 IP 当前应使用的终端（同 IP 多行时取 last_seen 最新一条）
-- ---------------------------------------------------------------------------
SELECT
  e.tenant_id,
  e.id        AS endpoint_id,
  e.hostname,
  e.ip,
  e.last_seen,
  e.status
FROM endpoints e
INNER JOIN (
  SELECT id
  FROM endpoints
  WHERE ip = @ip
  ORDER BY last_seen DESC
  LIMIT 1
) pick ON e.id = pick.id
WHERE e.ip = @ip;

-- ---------------------------------------------------------------------------
-- 1) 主表: 每 10 分钟 × event.type 计数（仅「冒烟相关」行）
-- ---------------------------------------------------------------------------
SELECT
  FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(m.ts) / 600) * 600) AS period_start,
  m.type,
  COUNT(*) AS event_count
FROM (
  SELECT
    e.ts,
    e.type,
    LOWER(CONCAT(' ', IFNULL(e.payload_json, ''), ' ', IFNULL(e.summary, ''), ' ')) AS lx
  FROM endpoint_events e
  INNER JOIN (
    SELECT tenant_id, id AS endpoint_id
    FROM endpoints
    WHERE ip = @ip
    ORDER BY last_seen DESC
    LIMIT 1
  ) ep ON e.tenant_id = ep.tenant_id AND e.endpoint_id = ep.endpoint_id
  WHERE e.ts >= DATE_SUB(NOW(), INTERVAL @hours_ago HOUR)
) m
WHERE
  m.lx LIKE '%encodedcommand%'
  OR m.lx LIKE '%frombase64string%'
  OR ((m.lx LIKE '%-windowstyle%' OR m.lx LIKE '% -w %' OR m.lx LIKE '% -w  %') AND m.lx LIKE '%hidden%')
  OR m.lx LIKE '%noprofile%'
  OR m.lx LIKE '%invoke-webrequest%'
  OR m.lx LIKE '%iwr %'
  OR m.lx LIKE 'iwr %'
  OR m.lx LIKE '%invoke-restmethod%'
  OR m.lx LIKE '%irm %'
  OR m.lx LIKE 'irm %'
  OR m.lx LIKE '%httpbin%'
  OR m.lx LIKE '%example.com%'
  OR m.lx LIKE '%iex(%'
  OR m.lx LIKE '% iex %'
  OR m.lx LIKE '%invoke-expression%'
  OR m.lx LIKE '%whoami%'
  OR m.lx LIKE '%systeminfo%'
  OR m.lx LIKE '%tasklist%'
  OR m.lx LIKE '%ipconfig%'
  OR m.lx LIKE '%certutil%'
  OR m.lx LIKE '%mshta%'
  OR m.lx LIKE '%rundll32%'
  OR m.lx LIKE '%regsvr32%'
  OR m.lx LIKE '%.sct%'
  OR m.lx LIKE '%wmic%'
  OR m.lx LIKE '%bitsadmin%'
  OR m.lx LIKE '%msiexec%'
  OR m.lx LIKE '%cmdkey%'
  OR m.lx LIKE '%\admin$%'
  OR m.lx LIKE '%/admin$%'
  OR m.lx LIKE '%\\admin$%'
  OR m.lx LIKE '%psexec%'
  OR m.lx LIKE '%bcdedit%'
GROUP BY
  FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(m.ts) / 600) * 600),
  m.type
ORDER BY
  period_start,
  m.type;

-- ---------------------------------------------------------------------------
-- 2) 仅按 10 分钟: 总行数（冒烟相关，不按 type 拆分）
-- ---------------------------------------------------------------------------
SELECT
  FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(m.ts) / 600) * 600) AS period_start,
  COUNT(*) AS smoke_related_rows
FROM (
  SELECT e.ts, LOWER(
    CONCAT(' ', IFNULL(e.payload_json, ''), ' ', IFNULL(e.summary, ''), ' ')
  ) AS lx
  FROM endpoint_events e
  INNER JOIN (
    SELECT tenant_id, id AS endpoint_id
    FROM endpoints
    WHERE ip = @ip
    ORDER BY last_seen DESC
    LIMIT 1
  ) ep ON e.tenant_id = ep.tenant_id AND e.endpoint_id = ep.endpoint_id
  WHERE e.ts >= DATE_SUB(NOW(), INTERVAL @hours_ago HOUR)
) m
WHERE
  m.lx LIKE '%encodedcommand%'
  OR m.lx LIKE '%frombase64string%'
  OR ((m.lx LIKE '%-windowstyle%' OR m.lx LIKE '% -w %' OR m.lx LIKE '% -w  %') AND m.lx LIKE '%hidden%')
  OR m.lx LIKE '%noprofile%'
  OR m.lx LIKE '%invoke-webrequest%'
  OR m.lx LIKE '%iwr %'
  OR m.lx LIKE 'iwr %'
  OR m.lx LIKE '%invoke-restmethod%'
  OR m.lx LIKE '%irm %'
  OR m.lx LIKE 'irm %'
  OR m.lx LIKE '%httpbin%'
  OR m.lx LIKE '%example.com%'
  OR m.lx LIKE '%iex(%'
  OR m.lx LIKE '% iex %'
  OR m.lx LIKE '%invoke-expression%'
  OR m.lx LIKE '%whoami%'
  OR m.lx LIKE '%systeminfo%'
  OR m.lx LIKE '%tasklist%'
  OR m.lx LIKE '%ipconfig%'
  OR m.lx LIKE '%certutil%'
  OR m.lx LIKE '%mshta%'
  OR m.lx LIKE '%rundll32%'
  OR m.lx LIKE '%regsvr32%'
  OR m.lx LIKE '%.sct%'
  OR m.lx LIKE '%wmic%'
  OR m.lx LIKE '%bitsadmin%'
  OR m.lx LIKE '%msiexec%'
  OR m.lx LIKE '%cmdkey%'
  OR m.lx LIKE '%\admin$%'
  OR m.lx LIKE '%/admin$%'
  OR m.lx LIKE '%\\admin$%'
  OR m.lx LIKE '%psexec%'
  OR m.lx LIKE '%bcdedit%'
GROUP BY
  FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(m.ts) / 600) * 600)
ORDER BY period_start;

-- ---------------------------------------------------------------------------
-- 3) 每 10 分钟: 按「粗分类」计数（与烟测 R-* 成组，便于和脚本步骤对照）
--    行可能命中多类，各列可单独大于 period 内总数（按「命中次数」理解）
-- ---------------------------------------------------------------------------
SELECT
  FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(m.ts) / 600) * 600) AS period_start,
  COUNT(*) AS rows_in_period,
  SUM(
    (m.lx LIKE '%encodedcommand%' OR m.lx LIKE '% -encodedcommand%' OR m.lx LIKE '%frombase64string%')
  ) AS cat_r_exec_encode_b64,
  SUM(
    ((m.lx LIKE '%-windowstyle%' OR m.lx LIKE '% -w %') AND m.lx LIKE '%hidden%') OR m.lx LIKE '%noprofile%'
  ) AS cat_r_exec_002_style,
  SUM(
    m.lx LIKE '%invoke-webrequest%' OR m.lx LIKE '%iwr %' OR m.lx LIKE 'iwr %' OR m.lx LIKE '%invoke-restmethod%'
     OR m.lx LIKE '%irm %' OR m.lx LIKE 'irm %' OR m.lx LIKE '%httpbin%' OR m.lx LIKE '%example.com%'
  ) AS cat_r_exec_005_iwr_irm,
  SUM(m.lx LIKE '%iex(%' OR m.lx LIKE '% iex %' OR m.lx LIKE '%invoke-expression%') AS cat_r_fileless_iex,
  SUM(
    m.lx LIKE '%whoami%' OR m.lx LIKE '%systeminfo%' OR m.lx LIKE '%tasklist%' OR m.lx LIKE '%ipconfig%'
  ) AS cat_r_disc_001,
  SUM(m.lx LIKE '%certutil%' OR m.lx LIKE '%mshta%') AS cat_lolbin_certutil_mshta,
  SUM(
    m.lx LIKE '%rundll32%' OR (m.lx LIKE '%regsvr32%' OR m.lx LIKE '%.sct%')
  ) AS cat_lolbin_rundll32_regsvr,
  SUM(m.lx LIKE '%wmic%') AS cat_lolbin_wmic,
  SUM(m.lx LIKE '%bitsadmin%' OR m.lx LIKE '%msiexec%') AS cat_lolbin_bits_msi,
  SUM(m.lx LIKE '%cmdkey%') AS cat_r_cred_005,
  SUM(m.lx LIKE '%\admin$%' OR m.lx LIKE '%/admin$%' OR m.lx LIKE '%\\admin$%' OR m.lx LIKE '%psexec%') AS cat_r_lmove_admin,
  SUM(m.lx LIKE '%bcdedit%') AS cat_bcdedit
FROM (
  SELECT
    e.ts,
    LOWER(
      CONCAT(' ', IFNULL(e.payload_json, ''), ' ', IFNULL(e.summary, ''), ' ')
    ) AS lx
  FROM endpoint_events e
  INNER JOIN (
    SELECT tenant_id, id AS endpoint_id
    FROM endpoints
    WHERE ip = @ip
    ORDER BY last_seen DESC
    LIMIT 1
  ) ep ON e.tenant_id = ep.tenant_id AND e.endpoint_id = ep.endpoint_id
  WHERE e.ts >= DATE_SUB(NOW(), INTERVAL @hours_ago HOUR)
) m
WHERE
  m.lx LIKE '%encodedcommand%'
  OR m.lx LIKE '%frombase64string%'
  OR ((m.lx LIKE '%-windowstyle%' OR m.lx LIKE '% -w %' OR m.lx LIKE '% -w  %') AND m.lx LIKE '%hidden%')
  OR m.lx LIKE '%noprofile%'
  OR m.lx LIKE '%invoke-webrequest%'
  OR m.lx LIKE '%iwr %'
  OR m.lx LIKE 'iwr %'
  OR m.lx LIKE '%invoke-restmethod%'
  OR m.lx LIKE '%irm %'
  OR m.lx LIKE 'irm %'
  OR m.lx LIKE '%httpbin%'
  OR m.lx LIKE '%example.com%'
  OR m.lx LIKE '%iex(%'
  OR m.lx LIKE '% iex %'
  OR m.lx LIKE '%invoke-expression%'
  OR m.lx LIKE '%whoami%'
  OR m.lx LIKE '%systeminfo%'
  OR m.lx LIKE '%tasklist%'
  OR m.lx LIKE '%ipconfig%'
  OR m.lx LIKE '%certutil%'
  OR m.lx LIKE '%mshta%'
  OR m.lx LIKE '%rundll32%'
  OR m.lx LIKE '%regsvr32%'
  OR m.lx LIKE '%.sct%'
  OR m.lx LIKE '%wmic%'
  OR m.lx LIKE '%bitsadmin%'
  OR m.lx LIKE '%msiexec%'
  OR m.lx LIKE '%cmdkey%'
  OR m.lx LIKE '%\admin$%'
  OR m.lx LIKE '%/admin$%'
  OR m.lx LIKE '%\\admin$%'
  OR m.lx LIKE '%psexec%'
  OR m.lx LIKE '%bcdedit%'
GROUP BY
  FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(m.ts) / 600) * 600)
ORDER BY period_start;

-- ---------------------------------------------------------------------------
-- 4) 同窗内对照: 该终端「全部」事件数 / 10 分钟（不限冒烟），便于看占比
-- ---------------------------------------------------------------------------
SELECT
  FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(e.ts) / 600) * 600) AS period_start,
  COUNT(*) AS all_event_rows
FROM endpoint_events e
INNER JOIN (
  SELECT tenant_id, id AS endpoint_id
  FROM endpoints
  WHERE ip = @ip
  ORDER BY last_seen DESC
  LIMIT 1
) ep ON e.tenant_id = ep.tenant_id AND e.endpoint_id = ep.endpoint_id
WHERE e.ts >= DATE_SUB(NOW(), INTERVAL @hours_ago HOUR)
GROUP BY
  FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(e.ts) / 600) * 600)
ORDER BY period_start;
