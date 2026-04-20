#include "edr/grpc_client.h"

#include "edr/command.h"
#include "edr/config.h"

#include <cstring>

#include <grpc/grpc.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>

#include "edr/v1/ingest.grpc.pb.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

#ifndef EDR_AGENT_VERSION_STRING
#define EDR_AGENT_VERSION_STRING "0.3.0"
#endif

static std::mutex s_mu;
static std::shared_ptr<grpc::Channel> s_channel;
static std::unique_ptr<edr::v1::EventIngest::Stub> s_stub;
static std::string s_endpoint_id;
static std::string s_target;
static int s_timeout_s = 10;
static int s_keepalive_s = 30;
static std::string s_ca;
static std::string s_cert;
static std::string s_key;
static bool s_insecure = false;

static std::atomic<unsigned long> s_rpc_ok{0};
static std::atomic<unsigned long> s_rpc_fail{0};
static std::atomic<int> s_report_fail_streak{0};
static std::atomic<unsigned long> s_upload_seq{0};

/** ReportEvents 上传带宽（TOML upload.max_upload_mbps）；0 表示不节流 */
static uint32_t s_max_upload_mbps;
static double s_upload_token_bytes;
static std::chrono::steady_clock::time_point s_upload_last_tp;
static bool s_upload_tb_inited;

static std::atomic<bool> s_sub_stop{true};
static std::thread s_sub_thr;
static std::shared_ptr<grpc::ClientContext> s_sub_ctx;

static void subscribe_thread_main(std::string endpoint_id);

static bool grpc_client_connect_locked(const std::string &target) {
  std::shared_ptr<grpc::ChannelCredentials> creds;
  if (s_insecure) {
    fprintf(stderr, "[grpc] 警告: EDR_GRPC_INSECURE=1，使用非加密通道\n");
    creds = grpc::InsecureChannelCredentials();
  } else if (!s_ca.empty() && !s_cert.empty() && !s_key.empty()) {
    grpc::SslCredentialsOptions ssl;
    ssl.pem_root_certs = s_ca;
    ssl.pem_cert_chain = s_cert;
    ssl.pem_private_key = s_key;
    creds = grpc::SslCredentials(ssl);
  } else if (!s_ca.empty()) {
    grpc::SslCredentialsOptions ssl;
    ssl.pem_root_certs = s_ca;
    creds = grpc::SslCredentials(ssl);
  } else {
    fprintf(stderr,
            "[grpc] 未找到 CA/客户端证书（server.ca_cert 等），且未设置 EDR_GRPC_INSECURE=1，"
            "跳过 gRPC。开发可: export EDR_GRPC_INSECURE=1\n");
    return false;
  }

  grpc::ChannelArguments args;
  args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, s_keepalive_s * 1000);
  args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);
  args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
  args.SetInt(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS, 200);
  args.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS, 5000);

  s_target = target;
  s_channel = grpc::CreateCustomChannel(target, creds, args);
  s_stub = edr::v1::EventIngest::NewStub(s_channel);
  s_report_fail_streak = 0;
  s_upload_tb_inited = false;
  s_upload_token_bytes = 0.0;

  fprintf(stderr, "[grpc] mTLS 通道: %s (ReportEvents + Subscribe", target.c_str());
  if (s_max_upload_mbps > 0u) {
    fprintf(stderr, "；上传节流 max_upload_mbps=%u", (unsigned)s_max_upload_mbps);
  } else {
    fprintf(stderr, "；上传节流关闭（max_upload_mbps=0）");
  }
  fprintf(stderr, ")\n");

  s_sub_stop = false;
  s_sub_thr = std::thread(subscribe_thread_main, s_endpoint_id);
  return true;
}

static void pb_to_soar_meta(const edr::v1::CommandEnvelope &cmd, EdrSoarCommandMeta *out) {
  std::memset(out, 0, sizeof(*out));
  auto cp = [](char *dst, size_t cap, const std::string &s) {
    if (cap == 0) {
      return;
    }
    size_t n = std::min(cap - 1u, s.size());
    if (n > 0u) {
      std::memcpy(dst, s.data(), n);
    }
    dst[n] = 0;
  };
  cp(out->soar_correlation_id, sizeof(out->soar_correlation_id), cmd.soar_correlation_id());
  cp(out->playbook_run_id, sizeof(out->playbook_run_id), cmd.playbook_run_id());
  cp(out->playbook_step_id, sizeof(out->playbook_step_id), cmd.playbook_step_id());
  cp(out->idempotency_key, sizeof(out->idempotency_key), cmd.idempotency_key());
  out->issued_at_unix_ms = cmd.issued_at_unix_ms();
  out->deadline_ms = cmd.deadline_ms();
}

static edr::v1::CommandExecutionStatus map_exec_status(int s) {
  switch (s) {
    case EdrCmdExecOk:
      return edr::v1::COMMAND_EXECUTION_STATUS_OK;
    case EdrCmdExecRejected:
      return edr::v1::COMMAND_EXECUTION_STATUS_REJECTED;
    case EdrCmdExecFailed:
      return edr::v1::COMMAND_EXECUTION_STATUS_FAILED;
    case EdrCmdExecUnknownType:
      return edr::v1::COMMAND_EXECUTION_STATUS_UNKNOWN_TYPE;
    default:
      return edr::v1::COMMAND_EXECUTION_STATUS_UNSPECIFIED;
  }
}

static std::string read_pem_file(const char *path) {
  if (!path || !path[0]) {
    return "";
  }
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    return "";
  }
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

static void subscribe_thread_main(std::string endpoint_id) {
  unsigned backoff_ms = 500;
  while (!s_sub_stop.load()) {
    if (!s_channel) {
      break;
    }
    {
      auto stub = edr::v1::EventIngest::NewStub(s_channel);
      auto ctx = std::make_shared<grpc::ClientContext>();
      s_sub_ctx = ctx;
      edr::v1::SubscribeRequest req;
      req.set_endpoint_id(endpoint_id);

      std::unique_ptr<grpc::ClientReader<edr::v1::CommandEnvelope>> reader(
          stub->Subscribe(ctx.get(), req));
      if (!reader) {
        fprintf(stderr, "[grpc] Subscribe reader 为空\n");
        s_sub_ctx.reset();
      } else {
        edr::v1::CommandEnvelope cmd;
        while (!s_sub_stop.load() && reader->Read(&cmd)) {
          EdrSoarCommandMeta sm{};
          pb_to_soar_meta(cmd, &sm);
          edr_command_on_envelope(cmd.command_id().c_str(), cmd.command_type().c_str(),
                                  reinterpret_cast<const uint8_t *>(cmd.payload().data()),
                                  cmd.payload().size(), &sm);
        }
        grpc::Status st = reader->Finish();
        if (!st.ok() && st.error_code() != grpc::StatusCode::CANCELLED) {
          fprintf(stderr, "[grpc] Subscribe 流结束: %d %s\n", (int)st.error_code(),
                  st.error_message().c_str());
        }
      }
      s_sub_ctx.reset();
    }
    if (s_sub_stop.load()) {
      break;
    }
    fprintf(stderr, "[grpc] Subscribe %u ms 后重连…\n", backoff_ms);
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
    backoff_ms = std::min<unsigned>(backoff_ms * 2, 60000u);
  }
}

extern "C" void edr_grpc_client_init(const EdrConfig *cfg) {
  if (!cfg) {
    return;
  }
  edr_grpc_client_shutdown();

  std::string target(cfg->server.address);
  if (target.empty()) {
    fprintf(stderr, "[grpc] server.address 为空，跳过 gRPC\n");
    return;
  }

  s_endpoint_id = cfg->agent.endpoint_id;
  s_timeout_s = cfg->server.connect_timeout_s > 0 ? cfg->server.connect_timeout_s : 10;
  s_keepalive_s =
      cfg->server.keepalive_interval_s > 0 ? cfg->server.keepalive_interval_s : 30;

  s_ca = read_pem_file(cfg->server.ca_cert);
  s_cert = read_pem_file(cfg->server.client_cert);
  s_key = read_pem_file(cfg->server.client_key);
  const char *insec = std::getenv("EDR_GRPC_INSECURE");
  s_insecure = (insec && insec[0] == '1');
  s_max_upload_mbps = cfg->upload.max_upload_mbps;
  (void)grpc_client_connect_locked(target);
}

extern "C" void edr_grpc_client_shutdown(void) {
  s_sub_stop = true;
  if (s_sub_ctx) {
    s_sub_ctx->TryCancel();
  }
  if (s_sub_thr.joinable()) {
    s_sub_thr.join();
  }
  s_stub.reset();
  s_channel.reset();
  s_upload_tb_inited = false;
}

extern "C" int edr_grpc_client_ready(void) {
  std::lock_guard<std::mutex> lock(s_mu);
  return s_stub ? 1 : 0;
}

extern "C" int edr_grpc_client_reconnect_to_target(const char *target) {
  std::string next = target ? target : "";
  if (next.empty()) {
    return -1;
  }
  std::lock_guard<std::mutex> lock(s_mu);
  if (s_endpoint_id.empty()) {
    return -1;
  }
  if (s_target == next && s_stub) {
    return 0;
  }
  s_sub_stop = true;
  if (s_sub_ctx) {
    s_sub_ctx->TryCancel();
  }
  if (s_sub_thr.joinable()) {
    s_sub_thr.join();
  }
  s_stub.reset();
  s_channel.reset();
  if (!grpc_client_connect_locked(next)) {
    return -1;
  }
  return 0;
}

extern "C" int edr_grpc_client_send_batch(const char *batch_id, const uint8_t *header12,
                                          size_t header_len, const uint8_t *payload,
                                          size_t payload_len) {
  std::lock_guard<std::mutex> lock(s_mu);
  if (!s_stub || !header12 || header_len < 12u || !payload || payload_len == 0u) {
    return -1;
  }

  int streak = s_report_fail_streak.load();
  if (streak > 0) {
    unsigned shift = (unsigned)std::min(streak, 8);
    unsigned delay_ms = 50u * (1u << shift);
    if (delay_ms > 5000u) {
      delay_ms = 5000u;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
  }

  const size_t wire_bytes = header_len + payload_len;
  if (s_max_upload_mbps > 0u && wire_bytes > 0u) {
    const double rate_bps = (double)s_max_upload_mbps * 125000.0;
    auto now = std::chrono::steady_clock::now();
    if (!s_upload_tb_inited) {
      s_upload_last_tp = now;
      s_upload_token_bytes = rate_bps;
      s_upload_tb_inited = true;
    } else {
      double dt = std::chrono::duration<double>(now - s_upload_last_tp).count();
      s_upload_last_tp = now;
      s_upload_token_bytes =
          std::min(rate_bps * 30.0, s_upload_token_bytes + dt * rate_bps);
    }
    while (s_upload_token_bytes + 1e-9 < (double)wire_bytes) {
      double deficit = (double)wire_bytes - s_upload_token_bytes;
      double sleep_s = deficit / rate_bps;
      std::this_thread::sleep_for(std::chrono::duration<double>(sleep_s));
      now = std::chrono::steady_clock::now();
      double dt = std::chrono::duration<double>(now - s_upload_last_tp).count();
      s_upload_last_tp = now;
      s_upload_token_bytes =
          std::min(rate_bps * 30.0, s_upload_token_bytes + dt * rate_bps);
    }
    s_upload_token_bytes -= (double)wire_bytes;
  }

  edr::v1::ReportEventsRequest req;
  req.set_endpoint_id(s_endpoint_id);
  req.set_batch_id(batch_id ? batch_id : "");
  req.set_agent_version(EDR_AGENT_VERSION_STRING);
  std::string blob(reinterpret_cast<const char *>(header12), header_len);
  blob.append(reinterpret_cast<const char *>(payload), payload_len);
  req.set_payload(blob);

  grpc::ClientContext ctx;
  ctx.set_deadline(std::chrono::system_clock::now() +
                   std::chrono::seconds(s_timeout_s));
  edr::v1::ReportEventsResponse resp;
  grpc::Status st = s_stub->ReportEvents(&ctx, req, &resp);
  if (!st.ok()) {
    s_rpc_fail++;
    s_report_fail_streak++;
    fprintf(stderr, "[grpc] ReportEvents 失败: %d %s\n", (int)st.error_code(),
            st.error_message().c_str());
    return -1;
  }
  if (!resp.accepted()) {
    s_rpc_fail++;
    s_report_fail_streak++;
    return -1;
  }
  s_report_fail_streak = 0;
  s_rpc_ok++;
  return 0;
}

extern "C" int edr_grpc_client_report_command_result(const char *command_id,
                                                     const EdrSoarCommandMeta *meta,
                                                     int execution_status, int exit_code,
                                                     const char *detail_utf8) {
  std::lock_guard<std::mutex> lock(s_mu);
  if (!s_stub) {
    return -1;
  }
  edr::v1::ReportCommandResultRequest req;
  req.set_endpoint_id(s_endpoint_id);
  edr::v1::CommandExecutionResult *r = req.mutable_result();
  r->set_command_id(command_id ? command_id : "");
  r->set_endpoint_id(s_endpoint_id);
  r->set_agent_version(EDR_AGENT_VERSION_STRING);
  if (meta) {
    r->set_soar_correlation_id(meta->soar_correlation_id);
    r->set_playbook_run_id(meta->playbook_run_id);
    r->set_playbook_step_id(meta->playbook_step_id);
  }
  r->set_status(map_exec_status(execution_status));
  r->set_exit_code(exit_code);
  r->set_detail_utf8(detail_utf8 ? detail_utf8 : "");
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
  r->set_finished_unix_ms(ms);

  grpc::ClientContext ctx;
  ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(s_timeout_s));
  edr::v1::ReportCommandResultResponse resp;
  grpc::Status st = s_stub->ReportCommandResult(&ctx, req, &resp);
  if (!st.ok()) {
    s_rpc_fail++;
    fprintf(stderr, "[grpc] ReportCommandResult 失败: %d %s\n", (int)st.error_code(),
            st.error_message().c_str());
    return -1;
  }
  if (!resp.accepted()) {
    s_rpc_fail++;
    return -1;
  }
  s_rpc_ok++;
  return 0;
}

extern "C" unsigned long edr_grpc_client_rpc_ok(void) { return s_rpc_ok.load(); }

extern "C" unsigned long edr_grpc_client_rpc_fail(void) { return s_rpc_fail.load(); }

extern "C" int edr_grpc_client_upload_file(const char *alert_id, const char *file_path, const char *sha256_hex,
                                           char *out_minio_key, size_t out_minio_key_cap) {
  std::lock_guard<std::mutex> lock(s_mu);
  if (out_minio_key && out_minio_key_cap > 0u) {
    out_minio_key[0] = '\0';
  }
  if (!s_stub || !file_path || !file_path[0]) {
    return -1;
  }
  std::ifstream f(file_path, std::ios::binary);
  if (!f) {
    return -1;
  }
  f.seekg(0, std::ios::end);
  std::streamoff sz = f.tellg();
  if (sz <= 0) {
    return -1;
  }
  f.seekg(0, std::ios::beg);

  grpc::ClientContext ctx;
  ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(s_timeout_s));
  edr::v1::UploadResult resp;
  std::unique_ptr<grpc::ClientWriter<edr::v1::FileChunk>> wr = s_stub->UploadFile(&ctx, &resp);
  if (!wr) {
    return -1;
  }

  std::string name = file_path;
  size_t p = name.find_last_of("/\\");
  if (p != std::string::npos) {
    name = name.substr(p + 1);
  }
  unsigned long seq = ++s_upload_seq;
  auto now_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
          .count();
  std::string upload_id = "up-" + std::to_string((long long)now_ms) + "-" + std::to_string(seq);

  static const size_t kChunk = 256u * 1024u;
  std::string chunk;
  chunk.resize(kChunk);
  uint64_t offset = 0;
  while (f) {
    f.read(&chunk[0], (std::streamsize)kChunk);
    std::streamsize n = f.gcount();
    if (n <= 0) {
      break;
    }
    bool is_last = (offset + (uint64_t)n >= (uint64_t)sz);
    edr::v1::FileChunk c;
    c.set_upload_id(upload_id);
    c.set_alert_id(alert_id ? alert_id : "");
    c.set_filename(name);
    if (offset == 0u) {
      c.set_sha256(sha256_hex ? sha256_hex : "");
      c.set_file_size((uint64_t)sz);
    }
    c.set_data(chunk.data(), (size_t)n);
    c.set_offset(offset);
    c.set_is_last(is_last);
    if (!wr->Write(c)) {
      (void)wr->WritesDone();
      grpc::Status st = wr->Finish();
      (void)st;
      s_rpc_fail++;
      return -1;
    }
    offset += (uint64_t)n;
  }
  (void)wr->WritesDone();
  grpc::Status st = wr->Finish();
  if (!st.ok() || !resp.success()) {
    s_rpc_fail++;
    return -1;
  }
  if (out_minio_key && out_minio_key_cap > 0u) {
    snprintf(out_minio_key, out_minio_key_cap, "%s", resp.minio_key().c_str());
  }
  s_rpc_ok++;
  return 0;
}
