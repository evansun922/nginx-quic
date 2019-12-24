
/*
 * Copyright (C) sunlei
 */

#include "quic_ngx_http_session.h"
#include "quic_ngx_http_stream.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"

namespace quic {

QuicNgxHttpSession::QuicNgxHttpSession(
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection,
    QuicSession::Visitor* visitor,
    QuicCryptoServerStream::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    QuicSimpleServerBackend* quic_simple_server_backend)
    : QuicSimpleServerSession(config,
                              supported_versions,
                              connection,
                              visitor,
                              helper,
                              crypto_config,
                              compressed_certs_cache,
                              quic_simple_server_backend) {
}

QuicNgxHttpSession::~QuicNgxHttpSession() = default;

QuicSpdyStream* QuicNgxHttpSession::CreateIncomingStream(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicSpdyStream* stream = new QuicNgxHttpStream(
                id, this, BIDIRECTIONAL, server_backend());
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

QuicSpdyStream* QuicNgxHttpSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicSpdyStream* stream = new QuicNgxHttpStream(
                pending, this, BIDIRECTIONAL, server_backend());
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

QuicSimpleServerStream*
QuicNgxHttpSession::CreateOutgoingBidirectionalStream() {
  DCHECK(false);
  return nullptr;
}

QuicSimpleServerStream*
QuicNgxHttpSession::CreateOutgoingUnidirectionalStream() {
  if (!ShouldCreateOutgoingUnidirectionalStream()) {
    return nullptr;
  }

  QuicSimpleServerStream* stream = new QuicNgxHttpStream(
      GetNextOutgoingUnidirectionalStreamId(), this, WRITE_UNIDIRECTIONAL,
      server_backend());
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

}  // namespace quic
