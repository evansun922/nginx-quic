
/*
 * Copyright (C) sunlei
 */

#ifndef QUICHE_QUIC_QUIC_NGX_SERVER_H_
#define QUICHE_QUIC_QUIC_NGX_SERVER_H_

#include <memory>

#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/core/quic_framer.h"
#include "net/third_party/quiche/src/quic/core/quic_packet_writer.h"
#include "net/third_party/quiche/src/quic/core/quic_version_manager.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "quic_ngx_interface.h"


namespace quic {

class QuicDispatcher;
class QuicPacketReader;
class QuicNgxStream;
class QuicNgxBackend;  
class QuicNgxPacketWriter;
  
class QuicNgxServer {
 public:
  QuicNgxServer(std::unique_ptr<ProofSource> proof_source,
                QuicNgxBackend* quic_ngx_server_backend,
                int idle_network_timeout);
  QuicNgxServer(std::unique_ptr<ProofSource> proof_source,
                const QuicConfig& config,
                const QuicCryptoServerConfig::ConfigOptions& server_config_options,
                const ParsedQuicVersionVector& supported_versions,
                QuicNgxBackend* quic_ngx_server_backend,
                int idle_network_timeout,
                uint8_t expected_connection_id_length);
  QuicNgxServer(const QuicNgxServer&) = delete;
  QuicNgxServer& operator=(const QuicNgxServer&) = delete;

  ~QuicNgxServer();

  // Initialize the internal state of the server.
  void Initialize(void* ngx_module_context,
                  int listen_fd,
                  int port,
                  int address_family,
                  CreateNgxTimer create_ngx_timer,
                  AddNgxTimer add_ngx_timer,
                  DelNgxTimer del_ngx_timer,
                  FreeNgxTimer free_ngx_timer);

  void ReadAndDispatchPackets(void* ngx_connection);

  // retrun true, need to add epoll event of writing
  bool FlushWriteCache();

  // retrun true, need to keep epoll event of writing
  bool CanWrite();
  
  void Shutdown();

  void SetChloMultiplier(size_t multiplier) {
    crypto_config_.set_chlo_multiplier(multiplier);
  }

  void SetPreSharedKey(QuicStringPiece key) {
    crypto_config_.set_pre_shared_key(key);
  }

  QuicNgxBackend* server_backend() {
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

  QuicNgxBackend* quic_ngx_server_backend_;  // unowned.

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
};

}  // namespace quic

#endif  // QUICHE_QUIC_QUIC_NGX_SERVER_H_
