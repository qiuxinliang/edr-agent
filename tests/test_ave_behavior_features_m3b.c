/**
 * 《11》M3b：§5.2–5.4 编码（与管线快照字段一致）。
 */
#include "edr/ave_behavior_features.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int expect_near(const char *name, float a, float b, float eps) {
  if (fabsf(a - b) > eps) {
    fprintf(stderr, "FAIL %s: got %f want %f\n", name, (double)a, (double)b);
    return -1;
  }
  return 0;
}

int main(void) {
  float feat[64];
  AVEBehaviorEvent e;
  memset(&e, 0, sizeof(e));
  EdrAveBehaviorFeatExtra ex;
  memset(&ex, 0, sizeof(ex));
  ex.static_max_conf = 0.4f;
  ex.static_verdict_norm = 2.f / 9.f;

  EdrAveBehaviorPidSnapshot s;
  memset(&s, 0, sizeof(s));
  s.total_events_incl_current = 100;
  s.file_write_count = 50;
  s.net_connect_count = 10;
  s.reg_write_count = 5;
  s.dll_load_count = 25;
  s.has_injected_memory = 1.f;
  s.has_accessed_lsass = 0.f;
  s.has_loaded_suspicious_dll = 1.f;
  s.has_ioc_connection = 0.f;
  s.parent_chain_depth_norm = 0.1f;
  s.is_system_account = 0.f;
  s.time_since_birth_norm = 0.5f;
  s.unique_ip_count = 10;
  s.is_high_value_host = 1.f;
  s.prev_event_ns = 1000000000LL;
  s.now_ns = 2000000000LL;
  s.burst_1s_count = 50;
  s.events_last_1min = 30;
  s.events_last_5min = 80;
  s.is_first_event_of_proc = 0;
  s.events_after_net_connect = 3;

  e.event_type = AVE_EVT_FILE_WRITE;
  snprintf(e.target_path, sizeof(e.target_path), "C:\\Windows\\Temp\\a.exe");

  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (feat[24] < 0.01f) {
    fprintf(stderr, "FAIL C24 path entropy (file write) too low: %f\n", (double)feat[24]);
    return 1;
  }

  if (expect_near("B8 total", feat[8], 0.1f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("B9 file", feat[9], 0.5f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("D36 gap log", feat[36], (float)(log10(1000.0 + 1.0) / 6.0), 0.02f) != 0) {
    return 1;
  }
  if (expect_near("D37 burst", feat[37], 0.5f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("D43 after net", feat[43], 0.3f, 0.001f) != 0) {
    return 1;
  }
  if (feat[2] < 0.99f) {
    fprintf(stderr, "FAIL A file_write one-hot\n");
    return 1;
  }
  if (expect_near("E57 is_real_event real step", feat[57], 1.f, 0.001f) != 0) {
    return 1;
  }

  e.target_has_motw = 1u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C35 target_has_motw", feat[35], 1.f, 0.001f) != 0) {
    return 1;
  }

  /* C25–C28：路径启发式（《11》§5.3 C 组） */
  memset(&e, 0, sizeof(e));
  e.event_type = AVE_EVT_FILE_WRITE;
  snprintf(e.target_path, sizeof(e.target_path), "C:\\Windows\\System32\\calc.exe");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C25 system path", feat[25], 1.f, 0.001f) != 0) {
    return 1;
  }
  snprintf(e.target_path, sizeof(e.target_path), "C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C26 temp path", feat[26], 1.f, 0.001f) != 0) {
    return 1;
  }
  snprintf(e.target_path, sizeof(e.target_path), "\\\\fileserver\\share\\a.exe");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C27 unc path", feat[27], 1.f, 0.001f) != 0) {
    return 1;
  }
  snprintf(e.target_path, sizeof(e.target_path), "C:\\tools\\x.ps1");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C28 ext ps1", feat[28], 1.f, 0.001f) != 0) {
    return 1;
  }
  snprintf(e.target_path, sizeof(e.target_path), "C:\\w\\m.dll");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C28 ext dll", feat[28], 0.5f, 0.001f) != 0) {
    return 1;
  }

  e.event_type = AVE_EVT_REG_WRITE;
  snprintf(e.target_path, sizeof(e.target_path),
           "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C32 reg run risk", feat[32], 0.9f, 0.001f) != 0) {
    return 1;
  }

  memset(&e, 0, sizeof(e));
  e.event_type = AVE_EVT_NET_DNS;
  snprintf(e.target_domain, sizeof(e.target_domain), "abcdefghijklmnopqrstuvwxyz.example.com");
  e.ioc_domain_hit = 1u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (feat[33] < 0.01f) {
    fprintf(stderr, "FAIL C33 dns entropy low got %f\n", (double)feat[33]);
    return 1;
  }
  if (expect_near("C34 ioc domain", feat[34], 1.f, 0.001f) != 0) {
    return 1;
  }

  /* C24：固定路径 Shannon /16 数值对拍（T16，《11》§5.3） */
  memset(&e, 0, sizeof(e));
  e.event_type = AVE_EVT_FILE_WRITE;
  snprintf(e.target_path, sizeof(e.target_path), "abab");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C24 golden abab", feat[24], 0.0625f, 0.0001f) != 0) {
    return 1;
  }
  snprintf(e.target_path, sizeof(e.target_path), "a");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C24 zero entropy single char path", feat[24], 0.f, 0.0001f) != 0) {
    return 1;
  }

  /* FILE_EXECUTE / DLL_LOAD 走同一 path_evt 分支 */
  e.event_type = AVE_EVT_FILE_EXECUTE;
  snprintf(e.target_path, sizeof(e.target_path), "C:\\Windows\\notepad.exe");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C25 FILE_EXECUTE system", feat[25], 1.f, 0.001f) != 0) {
    return 1;
  }
  e.event_type = AVE_EVT_DLL_LOAD;
  snprintf(e.target_path, sizeof(e.target_path), "C:\\Users\\x\\AppData\\Local\\Temp\\x.dll");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C26 DLL_LOAD temp", feat[26], 1.f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("C28 DLL_LOAD ext dll", feat[28], 0.5f, 0.001f) != 0) {
    return 1;
  }

  /* C28：bat / cmd 与 ps1 同为高风险扩展名 */
  e.event_type = AVE_EVT_FILE_WRITE;
  snprintf(e.target_path, sizeof(e.target_path), "C:\\x.bat");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C28 ext bat", feat[28], 1.f, 0.001f) != 0) {
    return 1;
  }
  snprintf(e.target_path, sizeof(e.target_path), "C:\\x.cmd");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C28 ext cmd", feat[28], 1.f, 0.001f) != 0) {
    return 1;
  }

  /* C29–C31：私网 / 公网 × 端口档位 */
  memset(&e, 0, sizeof(e));
  e.event_type = AVE_EVT_NET_CONNECT;
  snprintf(e.target_ip, sizeof(e.target_ip), "10.0.0.1");
  e.target_port = 443u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C29 private 10.x", feat[29], 0.f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("C30 low when private", feat[30], 0.1f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("C31 well-known 443", feat[31], 0.2f, 0.001f) != 0) {
    return 1;
  }
  snprintf(e.target_ip, sizeof(e.target_ip), "192.168.0.1");
  e.target_port = 445u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C29 private 192.168", feat[29], 0.f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("C31 smb 445 private", feat[31], 0.9f, 0.001f) != 0) {
    return 1;
  }
  snprintf(e.target_ip, sizeof(e.target_ip), "172.31.255.254");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C29 private 172.16-31", feat[29], 0.f, 0.001f) != 0) {
    return 1;
  }
  snprintf(e.target_ip, sizeof(e.target_ip), "8.8.8.8");
  e.target_port = 445u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C29 public", feat[29], 1.f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("C30 high when public", feat[30], 0.6f, 0.001f) != 0) {
    return 1;
  }
  if (expect_near("C31 smb 445 public", feat[31], 0.9f, 0.001f) != 0) {
    return 1;
  }
  e.target_port = 0u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C31 port zero", feat[31], 0.f, 0.001f) != 0) {
    return 1;
  }
  e.target_port = 1337u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C31 odd port default", feat[31], 0.5f, 0.001f) != 0) {
    return 1;
  }

  /* C32：非 Run 键默认 0.3 */
  e.event_type = AVE_EVT_REG_WRITE;
  e.target_port = 0u;
  e.target_ip[0] = '\0';
  snprintf(e.target_path, sizeof(e.target_path), "HKLM\\SOFTWARE\\Vendor\\App");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("C32 reg default risk", feat[32], 0.3f, 0.001f) != 0) {
    return 1;
  }

  /* C33：固定短域 Shannon /8 */
  memset(&e, 0, sizeof(e));
  e.event_type = AVE_EVT_NET_DNS;
  snprintf(e.target_domain, sizeof(e.target_domain), "abc");
  e.ioc_domain_hit = 0u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  {
    float want33 = (logf(3.f) / logf(2.f)) / 8.f;
    if (expect_near("C33 dns entropy abc", feat[33], want33, 0.0002f) != 0) {
      return 1;
    }
  }
  if (expect_near("C34 no ioc", feat[34], 0.f, 0.001f) != 0) {
    return 1;
  }

  memset(&ex, 0, sizeof(ex));
  ex.static_max_conf = 0.4f;
  ex.static_verdict_norm = 2.f / 9.f;
  ex.cert_revoked_ancestor = 1.f;
  memset(&e, 0, sizeof(e));
  e.event_type = AVE_EVT_FILE_WRITE;
  e.target_has_motw = 1u;
  snprintf(e.target_path, sizeof(e.target_path), "C:\\Windows\\Temp\\a.exe");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("E56 cert_revoked_ancestor", feat[56], 1.f, 0.001f) != 0) {
    return 1;
  }

  memset(&ex, 0, sizeof(ex));
  ex.static_max_conf = 0.4f;
  ex.static_verdict_norm = 2.f / 9.f;
  ex.cert_revoked_ancestor = 0.f;
  memset(&e, 0, sizeof(e));
  e.event_type = AVE_EVT_FILE_WRITE;
  e.target_has_motw = 1u;
  e.cert_revoked_ancestor = 1u;
  snprintf(e.target_path, sizeof(e.target_path), "C:\\Windows\\Temp\\a.exe");
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (expect_near("E56 cert_revoked_ancestor event-only", feat[56], 1.f, 0.001f) != 0) {
    return 1;
  }

  /* C 组：非路径类事件应接近 0 */
  memset(&ex, 0, sizeof(ex));
  ex.static_max_conf = 0.4f;
  ex.static_verdict_norm = 2.f / 9.f;
  memset(&e, 0, sizeof(e));
  e.event_type = AVE_EVT_NET_CONNECT;
  snprintf(e.target_ip, sizeof(e.target_ip), "8.8.8.8");
  e.target_port = 443u;
  edr_ave_behavior_encode_m3b(&e, &ex, &s, feat, 64u);
  if (feat[24] > 0.01f) {
    fprintf(stderr, "FAIL C24 path entropy for net evt\n");
    return 1;
  }
  if (feat[29] < 0.99f) {
    fprintf(stderr, "FAIL C29 public ip\n");
    return 1;
  }
  if (expect_near("E57 is_real_event after net encode", feat[57], 1.f, 0.001f) != 0) {
    return 1;
  }

  {
    float pad_step[64];
    memset(pad_step, 0, sizeof(pad_step));
    if (pad_step[57] > 0.001f) {
      fprintf(stderr, "FAIL PAD step dim57 must be 0 (§5.6)\n");
      return 1;
    }
  }

  return 0;
}
