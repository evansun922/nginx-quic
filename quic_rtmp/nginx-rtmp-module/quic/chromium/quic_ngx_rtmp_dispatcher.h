
/*
 * Copyright (C) sunlei
 */

#ifndef QUIC_NGX_RTMP_DISPATCHER_H_
#define QUIC_NGX_RTMP_DISPATCHER_H_

#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/quic_dispatcher.h"
#include "net/third_party/quiche/src/quic/tools/quic_transport_simple_server_session.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"
#include "quic_ngx_rtmp_interface.h"

namespace quic {

// Dispatcher that creates a QuicNgxRtmpDispatcher for every incoming
// connection.
class QuicNgxRtmpDispatcher : public QuicDispatcher {
 public:
  QuicNgxRtmpDispatcher(
      const QuicConfig* config,
      const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStreamBase::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      uint8_t expected_server_connection_id_length,
      ProcessRtmpData process_rtmp_data,
      SetVisitorForNgx set_visitor_for_ngx,
      void* ngx_module_context);
  

  ProcessRtmpData GetProcessRtmpData() { return process_rtmp_data_; }
  SetVisitorForNgx GetSetVisitorForNgx() { return set_visitor_for_ngx_; }
  void* GetNgxContext() {return ngx_module_context_;}
 protected:
  std::unique_ptr<QuicSession> CreateQuicSession(
      QuicConnectionId connection_id,
      const QuicSocketAddress& self_address,
      const QuicSocketAddress& peer_address,
      quiche::QuicheStringPiece alpn,
      const ParsedQuicVersion& version) override;

 private:
  ProcessRtmpData process_rtmp_data_;
  SetVisitorForNgx set_visitor_for_ngx_;
  void *ngx_module_context_;
};

}  // namespace quic

#endif  // QUIC_NGX_RTMP_DISPATCHER_H_
