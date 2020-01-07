

#include "quic_ngx_rtmp_session.h"

#include <memory>

#include "url/gurl.h"
#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_protocol.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_stream.h"
#include "quic_ngx_rtmp_dispatcher.h"


namespace quic {


QuicNgxRtmpVisitor::QuicNgxRtmpVisitor(
                QuicNgxRtmpSession* session,
                QuicTransportStream* stream)
  : session_(session),stream_(stream),nc_(nullptr),
    had_rtmp_handshake_(false){}

QuicNgxRtmpVisitor::~QuicNgxRtmpVisitor() {
  if (nc_) {
    session_->GetRtmpDispatcher()->
      GetSetVisitorForNgx()(nc_, nullptr);
    nc_ = nullptr;
  }
}

void QuicNgxRtmpVisitor::OnCanRead() {
  // stream_->Read(&buffer_);
  // OnCanWrite();

  std::string buffer;
  stream_->Read(&buffer);
  if (nc_ == nullptr) {
    if (had_rtmp_handshake_ == true) {
      // this connection had handshaked and closed,
      // so close this visitor
      OnFinRead();
      return;
    }

    struct sockaddr_storage self_addr =
      session_->self_address().generic_address();
    struct sockaddr_storage peer_addr =
      session_->peer_address().generic_address();
    session_->GetRtmpDispatcher()->GetProcessRtmpData()(
               session_->GetRtmpDispatcher()->GetNgxContext(),
               nc_,
               this,
               &self_addr,
               &peer_addr,
               buffer.data(),
               buffer.length());
    return;
  }
  
  session_->GetRtmpDispatcher()->GetProcessRtmpData()(
            session_->GetRtmpDispatcher()->GetNgxContext(),
            nc_,
            this,
            nullptr,
            nullptr,
            buffer.data(),
            buffer.length());
}

void QuicNgxRtmpVisitor::OnFinRead() {
  bool success = stream_->SendFin();
  DCHECK(success);
}

void QuicNgxRtmpVisitor::OnCanWrite() {
  if (buffer_.empty()) {
    return;
  }

  bool success = stream_->Write(buffer_);
  if (success) {
    buffer_ = "";
  }
}

bool QuicNgxRtmpVisitor::Write(const char* data, int len) {
  quiche::QuicheStringPiece d(data, len);
  return stream_->Write(d);
}

void QuicNgxRtmpVisitor::SendFin() {
  OnFinRead();
}



QuicNgxRtmpSession::QuicNgxRtmpSession(
    QuicConnection* connection,
    bool owns_connection,
    Visitor* owner,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    QuicNgxRtmpDispatcher* dispatcher)
    : QuicTransportServerSession(connection,
                                 owner,
                                 config,
                                 supported_versions,
                                 crypto_config,
                                 compressed_certs_cache,
                                 this),
      owns_connection_(owns_connection),
      dispatcher_(dispatcher){}

QuicNgxRtmpSession::~QuicNgxRtmpSession() {
  if (owns_connection_) {
    DeleteConnection();
  }
}

void QuicNgxRtmpSession::OnIncomingDataStream(
    QuicTransportStream* stream) {
  stream->set_visitor(
    std::make_unique<QuicNgxRtmpVisitor>(this, stream));
}

void QuicNgxRtmpSession::OnCanCreateNewOutgoingStream(
    bool unidirectional) {}

bool QuicNgxRtmpSession::CheckOrigin(url::Origin origin) {
  return true;
}

bool QuicNgxRtmpSession::ProcessPath(const GURL& url) {
  return true;
}



}  // namespace quic
