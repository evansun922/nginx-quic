
/*
 * Copyright (C) sunlei
 */

#ifndef QUIC_NGX_HTTP_DISPATCHER_H_
#define QUIC_NGX_HTTP_DISPATCHER_H_

#include "net/third_party/quiche/src/quic/tools/quic_simple_dispatcher.h"

namespace quic {

class QuicNgxHttpDispatcher : public QuicSimpleDispatcher {
 public:
  QuicNgxHttpDispatcher(
      const QuicConfig* config,
      const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      QuicSimpleServerBackend* quic_simple_server_backend,
      uint8_t expected_connection_id_length);

  ~QuicNgxHttpDispatcher() override;

 protected:
  std::unique_ptr<QuicSession> CreateQuicSession(
      QuicConnectionId connection_id,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& peer_address,
      quiche::QuicheStringPiece alpn,
      const ParsedQuicVersion& version) override;

};

}  // namespace quic

#endif  // QUIC_NGX_HTTP_DISPATCHER_H_
