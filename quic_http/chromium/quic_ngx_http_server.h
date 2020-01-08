
/*
 * Copyright (C) sunlei
 */

#ifndef QUIC_NGX_HTTP_SERVER_H_
#define QUIC_NGX_HTTP_SERVER_H_

#include <memory>

#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/core/quic_framer.h"
#include "net/third_party/quiche/src/quic/core/quic_version_manager.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "quic_ngx_http_interface.h"


namespace quic {

class QuicDispatcher;
class QuicPacketReader;
class QuicNgxHttpStream;
class QuicNgxHttpBackend;  
class QuicNgxPacketWriter;
  
class QuicNgxHttpServer {
 public:
  QuicNgxHttpServer(std::unique_ptr<ProofSource> proof_source,
                QuicNgxHttpBackend* quic_ngx_server_backend,
                int idle_network_timeout);
  QuicNgxHttpServer(std::unique_ptr<ProofSource> proof_source,
                const QuicConfig& config,
                const ParsedQuicVersionVector& supported_versions,
                QuicNgxHttpBackend* quic_ngx_server_backend,
                int idle_network_timeout);
  QuicNgxHttpServer(std::unique_ptr<ProofSource> proof_source,
                const QuicConfig& config,
                const QuicCryptoServerConfig::ConfigOptions& server_config_options,
                const ParsedQuicVersionVector& supported_versions,
                QuicNgxHttpBackend* quic_ngx_server_backend,
                int idle_network_timeout,
                uint8_t expected_connection_id_length);
  QuicNgxHttpServer(const QuicNgxHttpServer&) = delete;
  QuicNgxHttpServer& operator=(const QuicNgxHttpServer&) = delete;

  ~QuicNgxHttpServer();

  // Initialize the internal state of the server.
  void Initialize(void* ngx_module_context,
                  int listen_fd,
                  int port,
                  int address_family,
                  CreateNgxTimer create_ngx_timer,
                  AddNgxTimer add_ngx_timer,
                  DelNgxTimer del_ngx_timer,
                  FreeNgxTimer free_ngx_timer,
                  SetEPOLLOUT set_epoll_out);

  void ReadAndDispatchPackets(void* ngx_connection);

  // retrun true, need to add epoll event of writing
  bool FlushWriteCache();

  // retrun true, need to keep epoll event of writing
  bool CanWrite();
  
  void Shutdown();

  void OnWriteBlocked();

  void SetChloMultiplier(size_t multiplier) {
    crypto_config_.set_chlo_multiplier(multiplier);
  }

  void SetPreSharedKey(quiche::QuicheStringPiece key) {
    crypto_config_.set_pre_shared_key(key);
  }

  QuicNgxHttpBackend* server_backend() {
    return quic_ngx_server_backend_;
  }

 protected:
  QuicPacketWriter* CreateWriter(int fd);

  QuicDispatcher* CreateQuicDispatcher(
                     void* ngx_module_context,
                     CreateNgxTimer create_ngx_timer,
                     AddNgxTimer add_ngx_timer,
                     DelNgxTimer del_ngx_timer,
                     FreeNgxTimer free_ngx_timer);

  const QuicConfig& config() const { return config_; }
  const QuicCryptoServerConfig& crypto_config() const { return crypto_config_; }

  QuicDispatcher* dispatcher() { return dispatcher_.get(); }

  QuicVersionManager* version_manager() { return &version_manager_; }



  void set_silent_close(bool value) { silent_close_ = value; }

  uint8_t expected_connection_id_length() {
    return expected_connection_id_length_;
  }

 private:

  // Accepts data from the framer and demuxes clients to sessions.
  std::unique_ptr<QuicDispatcher> dispatcher_;

  // The port the server is listening on.
  int port_;
  
  // Listening connection.  Also used for outbound client communication.
  int fd_; // unowned.


  // If overflow_supported_ is true this will be the number of packets dropped
  // during the lifetime of the server.  This may overflow if enough packets
  // are dropped.
  QuicPacketCount packets_dropped_;

  // True if the kernel supports SO_RXQ_OVFL, the number of packets dropped
  // because the socket would otherwise overflow.
  bool overflow_supported_;

  // If true, do not call Shutdown on the dispatcher.  Connections will close
  // without sending a final connection close.
  bool silent_close_;

  // config_ contains non-crypto parameters that are negotiated in the crypto
  // handshake.
  QuicConfig config_;
  // crypto_config_ contains crypto parameters for the handshake.
  QuicCryptoServerConfig crypto_config_;
  // crypto_config_options_ contains crypto parameters for the handshake.
  QuicCryptoServerConfig::ConfigOptions crypto_config_options_;

  // Used to generate current supported versions.
  QuicVersionManager version_manager_;

  // Point to a QuicPacketReader object on the heap. The reader allocates more
  // space than allowed on the stack.
  std::unique_ptr<QuicPacketReader> packet_reader_;

  QuicNgxHttpBackend* quic_ngx_server_backend_;  // unowned.

  // Connection ID length expected to be read on incoming IETF short headers.
  uint8_t expected_connection_id_length_;

  // Used by the helper_ to time alarms.
  quic::QuicChromiumClock clock_;
  
  // Used to manage the message loop. Owned by dispatcher_.
  net::QuicChromiumConnectionHelper* helper_;

  // unowned
  QuicNgxPacketWriter* writer_;

  // Owned by nginx.
  void* ngx_module_context_;

  // set EPOLLOUT in nginx
  SetEPOLLOUT set_epoll_out_;
};

}  // namespace quic

#endif  // QUIC_NGX_HTTP_SERVER_H_
