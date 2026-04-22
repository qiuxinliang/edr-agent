/**
 * FL UploadGradients unary gRPC client — no generated fl.pb.cc (avoids protobuf gencode
 * version clash with checked-in ingest.pb). Request body matches fl_pb_wire.c; response
 * is minimal protobuf wire parse (UploadGradientsResponse: accepted, message).
 */
#include <grpc/grpc.h>
#include <grpc/support/time.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/completion_queue.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/generic/generic_stub.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/support/byte_buffer.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string read_pem_file(const char *path) {
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

static bool read_varint(const uint8_t *data, size_t len, size_t *pos, uint64_t *out) {
  *out = 0;
  int shift = 0;
  while (*pos < len && shift <= 63) {
    uint8_t b = data[(*pos)++];
    *out |= static_cast<uint64_t>(b & 0x7Fu) << shift;
    if ((b & 0x80u) == 0u) {
      return true;
    }
    shift += 7;
  }
  return false;
}

/** Best-effort parse of edr.v1.UploadGradientsResponse (fields 1 bool, 2 string). */
static void parse_upload_response(const uint8_t *data, size_t len, char *err_detail, size_t errcap) {
  if (!err_detail || errcap == 0u) {
    return;
  }
  err_detail[0] = '\0';
  size_t i = 0;
  while (i < len) {
    uint64_t tag_u64 = 0;
    if (!read_varint(data, len, &i, &tag_u64)) {
      break;
    }
    uint32_t tag = static_cast<uint32_t>(tag_u64);
    uint32_t field = tag >> 3;
    uint32_t wtype = tag & 7u;
    if (field == 1u && wtype == 0u) {
      uint64_t v = 0;
      if (!read_varint(data, len, &i, &v)) {
        break;
      }
      (void)v;
      continue;
    }
    if (field == 2u && wtype == 2u) {
      uint64_t slen = 0;
      if (!read_varint(data, len, &i, &slen)) {
        break;
      }
      if (slen > static_cast<uint64_t>(len - i)) {
        break;
      }
      size_t n = static_cast<size_t>(slen);
      if (n > 0u && errcap > 1u) {
        size_t copy = n < errcap - 1u ? n : errcap - 1u;
        memcpy(err_detail, data + i, copy);
        err_detail[copy] = '\0';
      }
      i += n;
      continue;
    }
    /* skip unknown */
    if (wtype == 0u) {
      uint64_t skip = 0;
      if (!read_varint(data, len, &i, &skip)) {
        break;
      }
    } else if (wtype == 1u) {
      if (i + 8u > len) {
        break;
      }
      i += 8u;
    } else if (wtype == 2u) {
      uint64_t slen = 0;
      if (!read_varint(data, len, &i, &slen)) {
        break;
      }
      if (slen > static_cast<uint64_t>(len - i)) {
        break;
      }
      i += static_cast<size_t>(slen);
    } else if (wtype == 5u) {
      if (i + 4u > len) {
        break;
      }
      i += 4u;
    } else {
      break;
    }
  }
}

static std::shared_ptr<grpc::ChannelCredentials> make_creds(int insecure, char *errbuf, size_t errcap) {
  if (insecure) {
    return grpc::InsecureChannelCredentials();
  }
  const char *ca_path = getenv("EDR_FL_GRPC_CA_PEM");
  std::string ca = read_pem_file(ca_path);
  if (ca.empty()) {
    if (errbuf && errcap) {
      snprintf(errbuf, errcap, "TLS: set EDR_FL_GRPC_CA_PEM to PEM file or use EDR_FL_GRPC_INSECURE=1");
    }
    return nullptr;
  }
  grpc::SslCredentialsOptions ssl;
  ssl.pem_root_certs = ca;
  return grpc::SslCredentials(ssl);
}

}  // namespace

extern "C" int fl_grpc_upload_gradient_call(const char *target, int insecure, const uint8_t *wire_body,
                                            size_t wire_len, char *errbuf, size_t errcap) {
  if (!target || !target[0] || !wire_body || wire_len == 0u) {
    if (errbuf && errcap) {
      snprintf(errbuf, errcap, "invalid args");
    }
    return -1;
  }

  auto creds = make_creds(insecure, errbuf, errcap);
  if (!creds) {
    return -1;
  }

  grpc::ChannelArguments args;
  const char *to_env = getenv("EDR_FL_GRPC_TIMEOUT_MS");
  int timeout_ms = 30000;
  if (to_env && to_env[0]) {
    int v = atoi(to_env);
    if (v > 100 && v < 600000) {
      timeout_ms = v;
    }
  }

  std::shared_ptr<grpc::Channel> channel = grpc::CreateCustomChannel(target, creds, args);

  grpc::ByteBuffer request;
  request.Append(grpc::Slice(wire_body, wire_len));

  grpc::ClientContext context;
  context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(timeout_ms));

  grpc::CompletionQueue cq;
  grpc::GenericStub stub(channel);

  std::unique_ptr<grpc::ClientAsyncResponseReader<grpc::ByteBuffer>> rpc(
      stub.PrepareUnaryCall(&context, "/edr.v1.FLService/UploadGradients", request, &cq));
  if (!rpc) {
    if (errbuf && errcap) {
      snprintf(errbuf, errcap, "PrepareUnaryCall failed");
    }
    return -1;
  }

  grpc::ByteBuffer response;
  grpc::Status status;
  void *tag = reinterpret_cast<void *>(static_cast<uintptr_t>(0xed01u));
  rpc->StartCall();
  rpc->Finish(&response, &status, tag);

  void *got_tag = nullptr;
  bool ok = false;
  const gpr_timespec deadline =
      gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_millis(timeout_ms, GPR_TIMESPAN));
  grpc::CompletionQueue::NextStatus ns = cq.AsyncNext(&got_tag, &ok, deadline);
  if (ns != grpc::CompletionQueue::GOT_EVENT || got_tag != tag || !ok) {
    if (errbuf && errcap) {
      snprintf(errbuf, errcap, "async wait failed or timeout");
    }
    return -1;
  }

  if (!status.ok()) {
    if (errbuf && errcap) {
      snprintf(errbuf, errcap, "%d %s", static_cast<int>(status.error_code()), status.error_message().c_str());
    }
    return -1;
  }

  std::vector<grpc::Slice> slices;
  response.Dump(&slices);
  std::string resp_bytes;
  for (const auto &sl : slices) {
    resp_bytes.append(reinterpret_cast<const char *>(sl.begin()), sl.size());
  }

  char detail[256];
  detail[0] = '\0';
  parse_upload_response(reinterpret_cast<const uint8_t *>(resp_bytes.data()), resp_bytes.size(), detail,
                        sizeof(detail));
  if (detail[0] && errbuf && errcap) {
    snprintf(errbuf, errcap, "ok: %s", detail);
  } else if (errbuf && errcap) {
    snprintf(errbuf, errcap, "ok");
  }
  return 0;
}
