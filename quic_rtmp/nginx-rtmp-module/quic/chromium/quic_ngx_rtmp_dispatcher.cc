
#include "quic_ngx_rtmp_dispatcher.h"

#include <memory>

#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_dispatcher.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"

#include "quic_ngx_rtmp_session.h"

namespace quic {

QuicNgxRtmpDispatcher::QuicNgxRtmpDispatcher(
    const QuicConfig* config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    uint8_t expected_server_connection_id_length,
    ProcessRtmpData process_rtmp_data,
    SetVisitorForNgx set_visitor_for_ngx,
    void* ngx_module_context)
    : QuicDispatcher(config,
                     crypto_config,
                     version_manager,
                     std::move(helper),
                     std::move(session_helper),
                     std::move(alarm_factory),
                     expected_server_connection_id_length),
      process_rtmp_data_(process_rtmp_data),
      set_visitor_for_ngx_(set_visitor_for_ngx),
      ngx_module_context_(ngx_module_context) {}


std::unique_ptr<QuicSession>
QuicNgxRtmpDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const QuicSocketAddress& /*self_address*/,
    const QuicSocketAddress& peer_address,
    quiche::QuicheStringPiece /*alpn*/,
    const ParsedQuicVersion& version) {
  auto connection = std::make_unique<QuicConnection>(
      connection_id, peer_address, helper(), alarm_factory(), writer(),
      /*owns_writer=*/false, Perspective::IS_SERVER,
      ParsedQuicVersionVector{version});
  auto session = std::make_unique<QuicNgxRtmpSession>(
      connection.release(), /*owns_connection=*/true, this, config(),
      GetSupportedVersions(), crypto_config(), compressed_certs_cache(),
      this);
  session->Initialize();
  return session;
}

}  // namespace quic
