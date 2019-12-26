
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
#include "quic_ngx_rtmp_interface.h"

namespace quic {

class QuicPacketReader;
class QuicDispatcher;
  
// Server for rtmp
class QuicNgxRtmpServer {
 public:
  QuicNgxRtmpServer(int fd, int port,
                    std::unique_ptr<ProofSource> proof_source);
  ~QuicNgxRtmpServer();

  // Initialize the internal state of the server.
  void Initialize(void* ngx_module_context,
                  int address_family,
                  CreateNgxTimer create_ngx_timer,
                  AddNgxTimer add_ngx_timer,
                  DelNgxTimer del_ngx_timer,
                  FreeNgxTimer free_ngx_timer);

  void ReadAndDispatchPackets(void* ngx_connection);

 private:


  int fd_; // unowned.
  int port_;

  quic::QuicVersionManager version_manager_;
  quic::QuicChromiumClock* clock_;  // Not owned.
  quic::QuicConfig config_;
  quic::QuicCryptoServerConfig crypto_config_;

  std::unique_ptr<QuicDispatcher> dispatcher_;
  std::unique_ptr<QuicPacketReader> packet_reader_;

  QuicPacketCount packets_dropped_;
  bool overflow_supported_;
};

}  // namespace net

#endif  // QUIC_NGX_RTMP_SERVER_H_
