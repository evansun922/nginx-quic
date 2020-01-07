
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
#include "quic_ngx_rtmp_interface.h"

namespace quic {

class QuicNgxRtmpDispatcher;
  
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
      QuicCompressedCertsCache* compressed_certs_cache,
      QuicNgxRtmpDispatcher* dispatcher);
  ~QuicNgxRtmpSession() override;

  void OnIncomingDataStream(QuicTransportStream* stream) override;
  void OnCanCreateNewOutgoingStream(bool unidirectional) override;
  bool CheckOrigin(url::Origin origin) override;
  bool ProcessPath(const GURL& url) override;

  QuicNgxRtmpDispatcher* GetRtmpDispatcher() { return dispatcher_; }

 private:

  const bool owns_connection_;
  QuicNgxRtmpDispatcher* dispatcher_;
};



class QuicNgxRtmpVisitor : public QuicTransportStream::Visitor {
 public:
  QuicNgxRtmpVisitor(QuicNgxRtmpSession* session,
                     QuicTransportStream* stream);
  ~QuicNgxRtmpVisitor() override;

  void OnCanRead() override;
  void OnFinRead() override;
  void OnCanWrite() override;

  bool Write(const char* data, int len);
  void SendFin();

  void SetNc(void* nc) { nc_ = nc; had_rtmp_handshake_ = true; }
  void* GetNc() { return nc_; }
  
 private:
  QuicNgxRtmpSession* session_; // unowned
  QuicTransportStream* stream_; // unowned
  void* nc_; // unowned ngx_connection
  std::string buffer_;
  bool had_rtmp_handshake_;
};
  

}  // namespace quic

#endif  // QUIC_NGX_RTMP_SESSION_H_
