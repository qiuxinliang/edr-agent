-- =============================================================================
-- 专查 edr_platform_stack_smoke 相关痕迹（endpoint_events）
--
-- 用途: 在 MySQL / TiDB 上检查「客户端是否采到、平台是否落库、字段是否可匹配
-- 动态规则 / dynamicrules」的原始材料（summary + payload_json 全文检索）。
-- 与脚本 edr_platform_stack_smoke.ps1 中的 R-* 说明对齐，便于回归对照。
--
-- 使用步骤:
--   1) 在下方 SET 中填入 tenant_id、endpoint_id、时间窗（小时）。
--   2) mysql:  mysql -h <host> -u <u> -p <db> < qa_smoke_traces_endpoint_events.sql
--   3) 若无命中: 先确认 endpoint 的 id 与 tenant、ingest；再放大 @hours_ago；或
--      将主查询中 AND ( ... 至少一类 ... ) 整段改为 1=1 仅看时间窗内样本。
-- =============================================================================
SET NAMES utf8mb4;

-- >>> 必改: 与 agent.toml 及 endpoints 表一致
SET @tenant_id   = 'demo-tenant';
SET @endpoint_id = 'ep-1034b1b3efa151f827915be41eba37b3';

-- 回溯时间（小时），冒烟刚跑完可设 1～3
SET @hours_ago   = 6;

-- ---------------------------------------------------------------------------
-- 主查询: 仅列出「与烟测任一类关键词相关」的行，并打标签 smoke_tags
-- lx = LOWER( payload_json + summary )，覆盖 JSON 内 cmdline 等子串
-- ---------------------------------------------------------------------------
SELECT
  t.id,
  t.ts,
  t.type,
  t.pid,
  t.severity,
  t.summary,
  TRIM(
    CONCAT(
      IF(t.lx LIKE '%encodedcommand%' OR t.lx LIKE '% -encodedcommand%', ' R-EXEC-001-enc;', ''),
      IF(t.lx LIKE '%frombase64string%', ' R-EXEC-001-b64;', ''),
      IF((t.lx LIKE '%-windowstyle%' OR t.lx LIKE '% -w %') AND t.lx LIKE '%hidden%', ' R-EXEC-002-hidprof;', ''),
      IF(t.lx LIKE '%noprofile%', ' R-EXEC-002-noprof;', ''),
      IF(t.lx LIKE '%invoke-webrequest%' OR t.lx LIKE '%iwr %' OR t.lx LIKE 'iwr %', ' R-EXEC-005-iwr;', ''),
      IF(t.lx LIKE '%invoke-restmethod%' OR t.lx LIKE '%irm %' OR t.lx LIKE 'irm %', ' R-EXEC-005-irm;', ''),
      IF(t.lx LIKE '%httpbin%', ' R-EXEC-005-httpbin;', ''),
      IF(t.lx LIKE '%example.com%', ' R-LOLBIN-example.com;', ''),
      IF(t.lx LIKE '%iex(%' OR t.lx LIKE '% iex %' OR t.lx LIKE '%invoke-expression%', ' R-FILELESS-001-iex;', ''),
      IF(t.lx LIKE '%whoami%', ' R-DISC-whoami;', ''),
      IF(t.lx LIKE '%systeminfo%' OR t.lx LIKE '%tasklist%' OR t.lx LIKE '%ipconfig%', ' R-DISC-sys-net;', ''),
      IF(t.lx LIKE '%certutil%' OR t.lx LIKE '%urlcache%', ' R-LOLBIN-003-certutil;', ''),
      IF(t.lx LIKE '%mshta%', ' R-LOLBIN-004-mshta;', ''),
      IF(t.lx LIKE '%rundll32%' AND (t.lx LIKE '%fileprotocolhandler%' OR t.lx LIKE '%url.dll%'), ' R-LOLBIN-002-rundll32;', ''),
      IF(t.lx LIKE '%regsvr32%' OR t.lx LIKE '%scrobj.dll%' OR t.lx LIKE '%.sct%', ' R-LOLBIN-001-regsvr32-sct;', ''),
      IF(t.lx LIKE '%wmic%' AND t.lx LIKE '%/node:%', ' R-LOLBIN-005-wmic-node;', ''),
      IF(t.lx LIKE '%bitsadmin%' OR t.lx LIKE '%/transfer %', ' R-LOLBIN-009-bitsadmin;', ''),
      IF(t.lx LIKE '%msiexec%' AND (t.lx LIKE '%.msi%' OR t.lx LIKE '%https:%'), ' R-LOLBIN-006-msiexec-https;', ''),
      IF(t.lx LIKE '%cmdkey%' AND t.lx LIKE '%list%', ' R-CRED-005-cmdkey;', ''),
      IF(t.lx LIKE '%psexec%' OR t.lx LIKE '%\admin$%' OR t.lx LIKE '%/admin$%' OR t.lx LIKE '%\\admin$%', ' R-LMOVE-admin;', ''),
      IF(t.lx LIKE '%bcdedit%' AND t.lx LIKE '%enum%', ' bcdedit-enum;', '')
    )
  ) AS smoke_tags,
  LEFT(t.payload_json, 4000) AS payload_json_head
FROM (
  SELECT
    e.id,
    e.ts,
    e.type,
    e.pid,
    e.severity,
    e.summary,
    e.payload_json,
    LOWER(CONCAT(' ', IFNULL(e.payload_json, ''), ' ', IFNULL(e.summary, ''), ' ')) AS lx
  FROM endpoint_events e
  WHERE e.tenant_id = @tenant_id
    AND e.endpoint_id = @endpoint_id
    AND e.ts >= DATE_SUB(NOW(), INTERVAL @hours_ago HOUR)
) t
WHERE
  t.lx LIKE '%encodedcommand%'
  OR t.lx LIKE '%frombase64string%'
  OR (t.lx LIKE '%-windowstyle%' OR t.lx LIKE '% -w %' OR t.lx LIKE '% -w  %') AND t.lx LIKE '%hidden%'
  OR t.lx LIKE '%-noprofile%'
  OR t.lx LIKE '%invoke-webrequest%'
  OR t.lx LIKE '%iwr %'
  OR t.lx LIKE 'iwr %'
  OR t.lx LIKE '%invoke-restmethod%'
  OR t.lx LIKE '%irm %'
  OR t.lx LIKE 'irm %'
  OR t.lx LIKE '%httpbin%'
  OR t.lx LIKE '%example.com%'
  OR t.lx LIKE '%iex(%'
  OR t.lx LIKE '% iex %'
  OR t.lx LIKE '%invoke-expression%'
  OR t.lx LIKE '%whoami%'
  OR t.lx LIKE '%systeminfo%'
  OR t.lx LIKE '%tasklist%'
  OR t.lx LIKE '%ipconfig%'
  OR t.lx LIKE '%certutil%'
  OR t.lx LIKE '%mshta%'
  OR t.lx LIKE '%rundll32%'
  OR t.lx LIKE '%regsvr32%'
  OR t.lx LIKE '%.sct%'
  OR t.lx LIKE '%wmic%'
  OR t.lx LIKE '%bitsadmin%'
  OR t.lx LIKE '%msiexec%'
  OR t.lx LIKE '%cmdkey%'
  OR t.lx LIKE '%\admin$%'
  OR t.lx LIKE '%/admin$%'
  OR t.lx LIKE '%\\admin$%'
  OR t.lx LIKE '%psexec%'
  OR t.lx LIKE '%bcdedit%'
ORDER BY t.ts DESC
LIMIT 500;

-- ---------------------------------------------------------------------------
-- 汇总: 时间窗内总事件行数 + 与「进程类 LOLBin/PS」粗略相关的行数
-- ---------------------------------------------------------------------------
SELECT
  (SELECT COUNT(*)
   FROM endpoint_events
   WHERE tenant_id = @tenant_id
     AND endpoint_id = @endpoint_id
     AND ts >= DATE_SUB(NOW(), INTERVAL @hours_ago HOUR)) AS events_in_window,
  (SELECT COUNT(*)
   FROM (
     SELECT
       e2.id,
       LOWER(CONCAT(' ', IFNULL(e2.payload_json, ''), ' ', IFNULL(e2.summary, ''), ' ')) AS bx
     FROM endpoint_events e2
     WHERE e2.tenant_id = @tenant_id
       AND e2.endpoint_id = @endpoint_id
       AND e2.ts >= DATE_SUB(NOW(), INTERVAL @hours_ago HOUR)
   ) s
   WHERE
     s.bx LIKE '%certutil%'
     OR s.bx LIKE '%encodedcommand%'
     OR s.bx LIKE '%powershell%'
     OR s.bx LIKE '%mshta%'
     OR s.bx LIKE '%rundll32%'
     OR s.bx LIKE '%iwr %'
  ) AS rough_lolbin_like_hits;
