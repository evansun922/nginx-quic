
/*
 * Copyright (C) sunlei
 */


#ifndef QUIC_NGX_RTMP_SERVER_H_
#define QUIC_NGX_RTMP_SERVER_H_

#include "base/memory/weak_ptr.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/core/quic_version_manager.h"
#include "net/third_party/quiche/src/quic/tools/quic_transport_simple_server_dispatcher.h"
#include "net/third_party/quiche/src/quic/tools/quic_transport_simple_server_session.h"
#include "url/origin.h"
#include "quic_ngx_rtmp_interface.h"

namespace quic {

// Server for rtmp
class QuicNgxRtmpServer {
 public:
  QuicNgxRtmpServer(int fd, int port);
  ~QuicNgxRtmpServer();

  // Initialize the internal state of the server.
  void Initialize(void* ngx_module_context,
                  CreateNgxTimer create_ngx_timer,
                  AddNgxTimer add_ngx_timer,
                  DelNgxTimer del_ngx_timer,
                  FreeNgxTimer free_ngx_timer,
                  std::vector<url::Origin> &accepted_origins);
  

 private:


  int fd_; // unowned.
  int port_;

  quic::QuicVersionManager version_manager_;
  quic::QuicChromiumClock* clock_;  // Not owned.
  quic::QuicConfig config_;
  quic::QuicCryptoServerConfig crypto_config_;

  std::unique_ptr<quic::QuicDispatcher> dispatcher_;

};

}  // namespace net

#endif  // QUIC_NGX_RTMP_SERVER_H_
