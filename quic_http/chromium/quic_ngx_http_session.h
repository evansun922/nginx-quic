
/*
 * Copyright (C) sunlei
 */

#ifndef QUIC_NGX_HTTP_SESSION_H_
#define QUIC_NGX_HTTP_SESSION_H_

#include "net/third_party/quiche/src/quic/tools/quic_simple_server_session.h"

namespace quic {


class QuicNgxHttpSession : public QuicSimpleServerSession {
 public:
  QuicNgxHttpSession(const QuicConfig& config,
                   const ParsedQuicVersionVector& supported_versions,
                   QuicConnection* connection,
                   QuicSession::Visitor* visitor,
                   QuicCryptoServerStreamBase::Helper* helper,
                   const QuicCryptoServerConfig* crypto_config,
                   QuicCompressedCertsCache* compressed_certs_cache,
                   QuicSimpleServerBackend* quic_simple_server_backend);
  QuicNgxHttpSession(const QuicNgxHttpSession&) = delete;
  QuicNgxHttpSession& operator=(const QuicNgxHttpSession&) = delete;

  ~QuicNgxHttpSession() override;

 protected:
  // QuicSession methods:
  QuicSpdyStream* CreateIncomingStream(QuicStreamId id) override;
  QuicSpdyStream* CreateIncomingStream(PendingStream* pending) override;
  QuicSimpleServerStream* CreateOutgoingBidirectionalStream() override;
  QuicSimpleServerStream* CreateOutgoingUnidirectionalStream() override;

};

}  // namespace quic

#endif  // QUIC_NGX_HTTP_SESSION_H_
