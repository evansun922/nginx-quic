
/*
 * Copyright (C) sunlei
 */

#include "quic_ngx_session.h"
#include "quic_ngx_stream.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"

namespace quic {

QuicNgxSession::QuicNgxSession(
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

QuicNgxSession::~QuicNgxSession() = default;

QuicSpdyStream* QuicNgxSession::CreateIncomingStream(QuicStreamId id) {
  if (!ShouldCreateIncomingStream(id)) {
    return nullptr;
  }

  QuicSpdyStream* stream = new QuicNgxStream(
                id, this, BIDIRECTIONAL, server_backend());
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

QuicSpdyStream* QuicNgxSession::CreateIncomingStream(
    PendingStream* pending) {
  QuicSpdyStream* stream = new QuicNgxStream(
                pending, this, BIDIRECTIONAL, server_backend());
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

QuicSimpleServerStream*
QuicNgxSession::CreateOutgoingBidirectionalStream() {
  DCHECK(false);
  return nullptr;
}

QuicSimpleServerStream*
QuicNgxSession::CreateOutgoingUnidirectionalStream() {
  if (!ShouldCreateOutgoingUnidirectionalStream()) {
    return nullptr;
  }

  QuicSimpleServerStream* stream = new QuicNgxStream(
      GetNextOutgoingUnidirectionalStreamId(), this, WRITE_UNIDIRECTIONAL,
      server_backend());
  ActivateStream(QuicWrapUnique(stream));
  return stream;
}

}  // namespace quic
