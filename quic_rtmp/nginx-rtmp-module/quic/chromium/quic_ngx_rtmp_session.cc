

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

namespace quic {

namespace {


class QuicNgxRtmpVisitor : public QuicTransportStream::Visitor {
 public:
  QuicNgxRtmpVisitor(QuicTransportStream* stream) : stream_(stream) {}

  void OnCanRead() override {
    stream_->Read(&buffer_);
    OnCanWrite();
  }

  void OnFinRead() override {
    bool success = stream_->SendFin();
    DCHECK(success);
  }

  void OnCanWrite() override {
    if (buffer_.empty()) {
      return;
    }

    bool success = stream_->Write(buffer_);
    if (success) {
      buffer_ = "";
    }
  }

 private:
  QuicTransportStream* stream_;
  std::string buffer_;
};




}  // namespace

QuicNgxRtmpSession::QuicNgxRtmpSession(
    QuicConnection* connection,
    bool owns_connection,
    Visitor* owner,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache)
    : QuicTransportServerSession(connection,
                                 owner,
                                 config,
                                 supported_versions,
                                 crypto_config,
                                 compressed_certs_cache,
                                 this),
      owns_connection_(owns_connection) {}

QuicNgxRtmpSession::~QuicNgxRtmpSession() {
  if (owns_connection_) {
    DeleteConnection();
  }
}

void QuicNgxRtmpSession::OnIncomingDataStream(
    QuicTransportStream* stream) {
  stream->set_visitor(
        std::make_unique<QuicNgxRtmpVisitor>(stream));
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
