
/*
 * Copyright (C) sunlei
 */


#ifndef QUIC_NGX_RTMP_SESSION_H_
#define QUIC_NGX_RTMP_SESSION_H_

#include <memory>
#include <vector>

#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_containers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_server_session.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"

namespace quic {


class QuicNgxRtmpSession
    : public QuicTransportServerSession,
      QuicTransportServerSession::ServerVisitor {
 public:


  QuicNgxRtmpSession(
      QuicConnection* connection,
      bool owns_connection,
      Visitor* owner,
      const QuicConfig& config,
      const ParsedQuicVersionVector& supported_versions,
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* compressed_certs_cache);
  ~QuicNgxRtmpSession() override;

  void OnIncomingDataStream(QuicTransportStream* stream) override;
  void OnCanCreateNewOutgoingStream(bool unidirectional) override;
  bool CheckOrigin(url::Origin origin) override;
  bool ProcessPath(const GURL& url) override;



 private:

  const bool owns_connection_;
};

}  // namespace quic

#endif  // QUIC_NGX_RTMP_SESSION_H_
