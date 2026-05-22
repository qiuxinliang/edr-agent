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
static std::atomic<long long> s_last_success_ms{0};
static std::atomic<long long> s_last_failure_ms{0};
static std::mutex s_runtime_mu;
static std::string s_last_error;

/** ReportEvents 上传带宽（TOML upload.max_upload_mbps）；0 表示不节流 */
static uint32_t s_max_upload_mbps;
static double s_upload_token_bytes;
static std::chrono::steady_clock::time_point s_upload_last_tp;
static bool s_upload_tb_inited;

static std::atomic<bool> s_sub_stop{true};
static std::thread s_sub_thr;
static std::shared_ptr<grpc::ClientContext> s_sub_ctx;
static std::atomic<bool> s_control_ready{false};
static std::mutex s_control_mu;
static std::mutex s_control_write_mu;
static grpc::ClientReaderWriter<edr::v1::CommandEnvelope, edr::v1::CommandEnvelope> *s_control_stream =
    nullptr;

static void subscribe_thread_main(std::string endpoint_id);
static void control_stream_thread_main(std::string endpoint_id);

static long long unix_ms_now(void) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

static void runtime_success(void) {
  s_last_success_ms = unix_ms_now();
  std::lock_guard<std::mutex> lock(s_runtime_mu);
  s_last_error.clear();
}

static void runtime_failure(const std::string &err) {
  s_last_failure_ms = unix_ms_now();
  std::lock_guard<std::mutex> lock(s_runtime_mu);
  s_last_error = err.substr(0, 150);
}

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
    runtime_failure("missing grpc tls credentials");
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

  fprintf(stderr, "[grpc] mTLS 通道: %s (ReportEvents + ControlStream", target.c_str());
  if (s_max_upload_mbps > 0u) {
    fprintf(stderr, "；上传节流 max_upload_mbps=%u", (unsigned)s_max_upload_mbps);
  } else {
    fprintf(stderr, "；上传节流关闭（max_upload_mbps=0）");
  }
  fprintf(stderr, ")\n");

  s_sub_stop = false;
  s_sub_thr = std::thread(control_stream_thread_main, s_endpoint_id);
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

static void json_escape_append(std::string &out, const std::string &s) {
  out.push_back('"');
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back((char)c);
    } else if (c == '\n') {
      out += "\\n";
    } else if (c == '\r') {
      out += "\\r";
    } else if (c == '\t') {
      out += "\\t";
    } else if (c < 0x20u) {
      out.push_back(' ');
    } else {
      out.push_back((char)c);
    }
  }
  out.push_back('"');
}

static std::string json_quoted(const std::string &s) {
  std::string out;
  out.reserve(s.size() + 8u);
  json_escape_append(out, s);
  return out;
}

static std::string build_result_chunk_detail(const std::string &chunk_id, size_t index,
                                             size_t count, size_t total_bytes,
                                             const std::string &data) {
  std::ostringstream os;
  os << "{\"chunked\":true,\"chunk_protocol\":\"edr-result-chunk-v1\","
     << "\"chunk_id\":" << json_quoted(chunk_id) << ","
     << "\"chunk_index\":" << index << ",\"chunk_count\":" << count << ","
     << "\"total_bytes\":" << total_bytes << ",\"data\":" << json_quoted(data) << "}";
  return os.str();
}

static std::string build_control_result_payload(const char *command_id,
                                                const EdrSoarCommandMeta *meta,
                                                int execution_status, int exit_code,
                                                const std::string &detail,
                                                long long finished_ms, bool chunked,
                                                const std::string &chunk_id, size_t chunk_index,
                                                size_t chunk_count, size_t total_bytes,
                                                const std::string &chunk_data) {
  std::ostringstream os;
  os << "{\"command_id\":" << json_quoted(command_id ? command_id : "")
     << ",\"status\":" << (int)map_exec_status(execution_status)
     << ",\"exit_code\":" << exit_code
     << ",\"finished_unix_ms\":" << finished_ms
     << ",\"agent_version\":\"" << EDR_AGENT_VERSION_STRING << "\"";
  if (meta) {
    os << ",\"soar_correlation_id\":" << json_quoted(meta->soar_correlation_id)
       << ",\"playbook_run_id\":" << json_quoted(meta->playbook_run_id)
       << ",\"playbook_step_id\":" << json_quoted(meta->playbook_step_id);
  }
  if (chunked) {
    os << ",\"chunked\":true,\"chunk_protocol\":\"edr-result-chunk-v1\""
       << ",\"chunk_id\":" << json_quoted(chunk_id)
       << ",\"chunk_index\":" << chunk_index << ",\"chunk_count\":" << chunk_count
       << ",\"total_bytes\":" << total_bytes << ",\"data\":" << json_quoted(chunk_data);
  } else {
    os << ",\"detail_utf8\":" << json_quoted(detail);
  }
  os << "}";
  return os.str();
}

static bool control_stream_write(const edr::v1::CommandEnvelope &msg) {
  std::lock_guard<std::mutex> lock(s_control_mu);
  if (!s_control_ready.load() || !s_control_stream) {
    return false;
  }
  std::lock_guard<std::mutex> wlock(s_control_write_mu);
  return s_control_stream->Write(msg);
}

static bool control_stream_send_result(const char *command_id, const EdrSoarCommandMeta *meta,
                                       int execution_status, int exit_code,
                                       const std::string &detail, long long finished_ms) {
  if (!s_control_ready.load()) {
    return false;
  }
  static const size_t kResultChunk = 24u * 1024u;
  const size_t n = detail.size();
  const size_t count = std::max<size_t>(1u, (n + kResultChunk - 1u) / kResultChunk);
  std::string chunk_id;
  if (count > 1u) {
    chunk_id = std::string(command_id ? command_id : "cmd") + "-" + std::to_string(finished_ms);
  }
  for (size_t i = 0; i < count; i++) {
    const size_t off = i * kResultChunk;
    const std::string part =
        count > 1u ? detail.substr(off, std::min(kResultChunk, n - off)) : std::string();
    edr::v1::CommandEnvelope msg;
    msg.set_command_id(command_id ? command_id : "");
    msg.set_command_type(count > 1u ? "command_result_chunk" : "command_result");
    if (meta) {
      msg.set_soar_correlation_id(meta->soar_correlation_id);
      msg.set_playbook_run_id(meta->playbook_run_id);
      msg.set_playbook_step_id(meta->playbook_step_id);
      msg.set_idempotency_key(meta->idempotency_key);
    }
    msg.set_issued_at_unix_ms(finished_ms);
    std::string payload = build_control_result_payload(
        command_id, meta, execution_status, exit_code, detail, finished_ms, count > 1u, chunk_id, i,
        count, n, part);
    msg.set_payload(payload);
    if (!control_stream_write(msg)) {
      return false;
    }
  }
  return true;
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
          runtime_failure("subscribe: " + st.error_message());
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

static void control_stream_thread_main(std::string endpoint_id) {
  unsigned backoff_ms = 500;
  while (!s_sub_stop.load()) {
    if (!s_channel) {
      break;
    }
    auto stub = edr::v1::EventIngest::NewStub(s_channel);
    auto ctx = std::make_shared<grpc::ClientContext>();
    s_sub_ctx = ctx;
    std::unique_ptr<grpc::ClientReaderWriter<edr::v1::CommandEnvelope, edr::v1::CommandEnvelope>>
        stream(stub->ControlStream(ctx.get()));
    if (!stream) {
      runtime_failure("ControlStream: stream is null");
      s_sub_ctx.reset();
      std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
      backoff_ms = std::min<unsigned>(backoff_ms * 2, 60000u);
      continue;
    }
    {
      std::lock_guard<std::mutex> lock(s_control_mu);
      s_control_stream = stream.get();
      s_control_ready = true;
    }

    edr::v1::CommandEnvelope hello;
    hello.set_command_id("agent-hello");
    hello.set_command_type("agent_hello");
    hello.set_issued_at_unix_ms(unix_ms_now());
    std::string payload = std::string("{\"endpoint_id\":") + json_quoted(endpoint_id) +
                          ",\"agent_version\":\"" EDR_AGENT_VERSION_STRING "\"}";
    hello.set_payload(payload);
    if (!control_stream_write(hello)) {
      runtime_failure("ControlStream: hello write failed");
    } else {
      runtime_success();
      backoff_ms = 500;
      fprintf(stderr, "[grpc] ControlStream 已建立 endpoint=%s\n", endpoint_id.c_str());
    }

    edr::v1::CommandEnvelope cmd;
    while (!s_sub_stop.load() && stream->Read(&cmd)) {
      EdrSoarCommandMeta sm{};
      pb_to_soar_meta(cmd, &sm);
      edr_command_on_envelope(cmd.command_id().c_str(), cmd.command_type().c_str(),
                              reinterpret_cast<const uint8_t *>(cmd.payload().data()),
                              cmd.payload().size(), &sm);
    }
    {
      std::lock_guard<std::mutex> lock(s_control_mu);
      s_control_ready = false;
      s_control_stream = nullptr;
    }
    grpc::Status st = stream->Finish();
    s_sub_ctx.reset();
    if (st.error_code() == grpc::StatusCode::UNIMPLEMENTED) {
      fprintf(stderr, "[grpc] ControlStream 未实现，回退 Subscribe 服务端流\n");
      subscribe_thread_main(endpoint_id);
      return;
    }
    if (!st.ok() && st.error_code() != grpc::StatusCode::CANCELLED) {
      fprintf(stderr, "[grpc] ControlStream 流结束: %d %s\n", (int)st.error_code(),
              st.error_message().c_str());
      runtime_failure("ControlStream: " + st.error_message());
    }
    if (s_sub_stop.load()) {
      break;
    }
    fprintf(stderr, "[grpc] ControlStream %u ms 后重连…\n", backoff_ms);
    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
    backoff_ms = std::min<unsigned>(backoff_ms * 2, 60000u);
  }
  {
    std::lock_guard<std::mutex> lock(s_control_mu);
    s_control_ready = false;
    s_control_stream = nullptr;
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
  s_insecure = cfg->server.grpc_insecure || (insec && insec[0] == '1');
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
  {
    std::lock_guard<std::mutex> lock(s_control_mu);
    s_control_ready = false;
    s_control_stream = nullptr;
  }
  s_stub.reset();
  s_channel.reset();
  s_upload_tb_inited = false;
}

extern "C" int edr_grpc_client_ready(void) {
  std::lock_guard<std::mutex> lock(s_mu);
  return s_stub ? 1 : 0;
}

extern "C" void edr_grpc_client_get_runtime(EdrGrpcClientRuntime *out) {
  if (!out) {
    return;
  }
  std::memset(out, 0, sizeof(*out));
  {
    std::lock_guard<std::mutex> lock(s_mu);
    out->ready = s_stub ? 1 : 0;
  }
  out->insecure = s_insecure ? 1 : 0;
  out->report_fail_streak = s_report_fail_streak.load();
  out->rpc_ok = s_rpc_ok.load();
  out->rpc_fail = s_rpc_fail.load();
  out->last_success_unix_ms = s_last_success_ms.load();
  out->last_failure_unix_ms = s_last_failure_ms.load();
  {
    std::lock_guard<std::mutex> lock(s_runtime_mu);
    std::snprintf(out->last_error, sizeof(out->last_error), "%s", s_last_error.c_str());
  }
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
  {
    std::lock_guard<std::mutex> lock(s_control_mu);
    s_control_ready = false;
    s_control_stream = nullptr;
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
    runtime_failure("ReportEvents: " + st.error_message());
    fprintf(stderr, "[grpc] ReportEvents 失败: %d %s\n", (int)st.error_code(),
            st.error_message().c_str());
    return -1;
  }
  if (!resp.accepted()) {
    s_rpc_fail++;
    s_report_fail_streak++;
    runtime_failure("ReportEvents: rejected");
    return -1;
  }
  s_report_fail_streak = 0;
  s_rpc_ok++;
  runtime_success();
  return 0;
}

static int report_command_result_unary_locked(const char *command_id,
                                              const EdrSoarCommandMeta *meta,
                                              int execution_status, int exit_code,
                                              const char *detail_utf8, long long finished_ms) {
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
  r->set_finished_unix_ms(finished_ms);

  grpc::ClientContext ctx;
  ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(s_timeout_s));
  edr::v1::ReportCommandResultResponse resp;
  grpc::Status st = s_stub->ReportCommandResult(&ctx, req, &resp);
  if (!st.ok()) {
    s_rpc_fail++;
    runtime_failure("ReportCommandResult: " + st.error_message());
    fprintf(stderr, "[grpc] ReportCommandResult 失败: %d %s\n", (int)st.error_code(),
            st.error_message().c_str());
    return -1;
  }
  if (!resp.accepted()) {
    s_rpc_fail++;
    runtime_failure("ReportCommandResult: rejected");
    return -1;
  }
  s_rpc_ok++;
  runtime_success();
  return 0;
}

extern "C" int edr_grpc_client_report_command_result(const char *command_id,
                                                     const EdrSoarCommandMeta *meta,
                                                     int execution_status, int exit_code,
                                                     const char *detail_utf8) {
  std::lock_guard<std::mutex> lock(s_mu);
  if (!s_stub && !s_control_ready.load()) {
    return -1;
  }
  std::string detail(detail_utf8 ? detail_utf8 : "");
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();

  if (control_stream_send_result(command_id, meta, execution_status, exit_code, detail, ms)) {
    s_rpc_ok++;
    runtime_success();
    return 0;
  }

  static const size_t kUnaryChunk = 24u * 1024u;
  if (detail.size() <= kUnaryChunk) {
    return report_command_result_unary_locked(command_id, meta, execution_status, exit_code,
                                              detail.c_str(), ms);
  }

  std::string chunk_id = std::string(command_id ? command_id : "cmd") + "-" + std::to_string(ms);
  const size_t count = (detail.size() + kUnaryChunk - 1u) / kUnaryChunk;
  for (size_t i = 0; i < count; i++) {
    const size_t off = i * kUnaryChunk;
    std::string part = detail.substr(off, std::min(kUnaryChunk, detail.size() - off));
    std::string chunk_detail = build_result_chunk_detail(chunk_id, i, count, detail.size(), part);
    int rc = report_command_result_unary_locked(command_id, meta, execution_status, exit_code,
                                                chunk_detail.c_str(), ms);
    if (rc != 0) {
      return rc;
    }
  }
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
      runtime_failure("UploadFile: write failed");
      return -1;
    }
    offset += (uint64_t)n;
  }
  (void)wr->WritesDone();
  grpc::Status st = wr->Finish();
  if (!st.ok() || !resp.success()) {
    s_rpc_fail++;
    runtime_failure(st.ok() ? "UploadFile: rejected" : ("UploadFile: " + st.error_message()));
    return -1;
  }
  if (out_minio_key && out_minio_key_cap > 0u) {
    snprintf(out_minio_key, out_minio_key_cap, "%s", resp.minio_key().c_str());
  }
  s_rpc_ok++;
  runtime_success();
  return 0;
}
