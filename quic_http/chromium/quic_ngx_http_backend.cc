
/*
 * Copyright (C) sunlei
 */

#include "quic_ngx_http_backend.h"

#include <utility>

#include "net/third_party/quiche/src/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_file_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_map_util.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_text_utils.h"
#include "quic_ngx_http_stream.h"


using spdy::kV3LowestPriority;
using spdy::SpdyHeaderBlock;

namespace quic {

QuicNgxHttpBackend::QuicNgxHttpBackend() : cache_initialized_(false) {}

QuicNgxHttpBackend::~QuicNgxHttpBackend() {}

bool QuicNgxHttpBackend::InitializeBackend(const std::string& cache_directory) {
  cache_initialized_ = true;
  return true;
}

bool QuicNgxHttpBackend::IsBackendInitialized() const {
  return cache_initialized_;
}

void QuicNgxHttpBackend::FetchResponseFromBackend(
    const SpdyHeaderBlock& request_headers,
    const std::string& request_body,
    QuicSimpleServerBackend::RequestHandler* quic_stream) {

  // for (auto it = request_headers.begin(); it != request_headers.end(); ++it) {
  //   std::string v = it->first.as_string() + ": " + it->second.as_string();
  //   LOG(INFO) << it->first.as_string() << ": " << it->second.as_string();
  // }

  std::ostringstream ngx_request_header;
  auto it = request_headers.find(":method");
  if (it == request_headers.end()) {
    return;
  }
  ngx_request_header << it->second.as_string() << " ";

  it = request_headers.find(":path");
  if (it == request_headers.end()) {
    return;
  }
  ngx_request_header << it->second.as_string() << " HTTP/3.0\r\n";

  it = request_headers.find(":authority");
  if (it == request_headers.end()) {
    return;
  }
  ngx_request_header << "Host: " << it->second.as_string() << "\r\n";

  for (auto it = request_headers.begin(); it != request_headers.end(); ++it) {
    std::string k = it->first.as_string();
    std::string v = it->second.as_string();
    if (k[0] == ':') {
      continue;
    }
    ngx_request_header << k << ": " << v << "\r\n";
  }
  ngx_request_header << "\r\n";

  std::string nr = ngx_request_header.str();
  // printf("%s\n", nr.c_str());

  QuicNgxHttpStream* ngx_stream = reinterpret_cast<QuicNgxHttpStream*>(
                              static_cast<QuicSimpleServerStream*>(quic_stream));

  struct sockaddr_storage self_addr = ngx_stream->get_self_address();
  struct sockaddr_storage peer_addr = ngx_stream->get_peer_address();
  request_quic_2_ngx_(cur_ngx_connection_,
                      ngx_stream,
                      &self_addr,
                      &peer_addr,
                      nr.c_str(), nr.length(),
                      request_body.c_str(), request_body.length());
}

// The memory cache does not have a per-stream handler
void QuicNgxHttpBackend::CloseBackendResponseStream(
    QuicSimpleServerBackend::RequestHandler* quic_stream) {
  QuicNgxHttpStream* ngx_stream = reinterpret_cast<QuicNgxHttpStream*>(
                              static_cast<QuicSimpleServerStream*>(quic_stream));

  if (ngx_stream->get_ngx_connection()) {
    set_stream_for_ngx_(ngx_stream->get_ngx_connection(), nullptr);
    ngx_stream->set_ngx_connection(nullptr);
  }
}





}  // namespace quic
