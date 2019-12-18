
/*
 * Copyright (C) sunlei
 */

#include "quic_ngx_dispatcher.h"
#include "quic_ngx_session.h"
#include "quic_ngx_server.h"
#include "quic_ngx_backend.h"

namespace quic {

QuicNgxDispatcher::QuicNgxDispatcher(
    const QuicConfig* config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    QuicSimpleServerBackend* quic_simple_server_backend,
    uint8_t expected_connection_id_length)
    : QuicSimpleDispatcher(config,
                           crypto_config,
                           version_manager,
                           std::move(helper),
                           std::move(session_helper),
                           std::move(alarm_factory),
                           quic_simple_server_backend,
                           expected_connection_id_length) {
}

QuicNgxDispatcher::~QuicNgxDispatcher() = default;

void QuicNgxDispatcher::OnWriteBlocked(QuicBlockedWriterInterface* blocked_writer) {
  QuicSimpleDispatcher::OnWriteBlocked(blocked_writer);

  QuicNgxBackend *backend = reinterpret_cast<QuicNgxBackend*>(server_backend());
  QuicNgxServer *server = backend->get_server();
  server->OnWriteBlocked();
}
  
std::unique_ptr<QuicSession> QuicNgxDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const QuicSocketAddress& client_address,
    quiche::QuicheStringPiece /*alpn*/,
    const ParsedQuicVersion& version) {
  // The QuicServerSessionBase takes ownership of |connection| below.
  QuicConnection* connection = new QuicConnection(
      connection_id, client_address, helper(), alarm_factory(), writer(),
      /* owns_writer= */ false, Perspective::IS_SERVER,
      ParsedQuicVersionVector{version});

  auto session = std::make_unique<QuicNgxSession>(
      config(), GetSupportedVersions(), connection, this, session_helper(),
      crypto_config(), compressed_certs_cache(), server_backend());
  session->Initialize();
  return session;
}

}  // namespace quic
