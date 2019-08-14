#include "quic_ngx_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h" 

namespace quic {

QuicNgxStream::QuicNgxStream(
    QuicStreamId id,
    QuicSpdySession* session,
    StreamType type,
    QuicSimpleServerBackend* quic_simple_server_backend)
    : QuicSimpleServerStream(id, session, type, quic_simple_server_backend),
      ngx_connection_(nullptr),
      content_length_(-1), had_send_length_(0), is_http_chunked_(false),
      http_chunked_step_(0), fin_(false) {}

QuicNgxStream::QuicNgxStream(
    PendingStream* pending,
    QuicSpdySession* session,
    StreamType type,
    QuicSimpleServerBackend* quic_simple_server_backend)
    : QuicSimpleServerStream(pending, session,
                             type, quic_simple_server_backend),
      ngx_connection_(nullptr),
      content_length_(-1), had_send_length_(0), is_http_chunked_(false),
      http_chunked_step_(0), fin_(false) {}

QuicNgxStream::~QuicNgxStream() = default;

bool QuicNgxStream::SendHttpHeaders(const char* data, int len) {
  spdy::SpdyHeaderBlock spdy_headers;
  int i, start = 0;
  
  for (i = 0; i < len; i++) {
    if (data[i] == '\r') {
      if (start == i) {
        break;
      }
      
      QuicStringPiece line(data + start, i - start);
      if (line.substr(0, 4) == "HTTP") {
        size_t pos = line.find(" ");
        if (pos == std::string::npos) {
          LOG(DFATAL) << "Headers invalid or empty, ignoring";
          return false;
        }
    
        spdy_headers[":status"] = line.substr(pos + 1, 3);
        continue;
      }

      // Headers are "key: value".
      size_t pos = line.find(": ");
      if (pos == std::string::npos) {
        LOG(DFATAL) << "Headers invalid or empty, ignoring";
        return false;
      }
      spdy_headers.AppendValueOrAddHeader(
           QuicTextUtils::ToLower(line.substr(0, pos)), line.substr(pos + 2));
      continue;
    }

    if (data[i] == '\n') {
      start = i + 1;
    }
  }

  
  if (i+2 != len) {
    return false;
  }


  auto content_length = spdy_headers.find("content-length");
  if (content_length != spdy_headers.end()) {
      QuicTextUtils::StringToInt(content_length->second,
                                   &content_length_);
  }
  std::string http_status("");
  auto it_status = spdy_headers.find(":status");
  if (it_status != spdy_headers.end()) {
    http_status = it_status->second.as_string();
  }
  // std::string http_ver("");
  // auto it_ver = proxy->spdy_headers_.find(":ver");
  // if (it_ver != proxy->spdy_headers_.end()) {
  //   http_ver = it_ver->second.as_string();
  //   proxy->spdy_headers_.erase(":ver");
  // }
  std::string transfer_encoding("");
  auto it_transfer_encoding = spdy_headers.find("transfer-encoding");
  if (it_transfer_encoding != spdy_headers.end()) {
    transfer_encoding = it_transfer_encoding->second.as_string();
  }

  if (transfer_encoding == "chunked") {
    fin_ = false;
    is_http_chunked_ = true;
    spdy_headers.erase("transfer-encoding");
    spdy_headers.erase("connection");
  } else if (content_length_ == -1) {
    fin_ = true;
    if (http_status == "200" ||
        http_status == "100") {
      fin_ = false;
    }    
  } else if (content_length_ == 0) {
    fin_ = true;
  }
        
  // LOG(INFO) << "send request header " << proxy->quic_stream_->id()
  //           << " content-length " << proxy->content_length_
  //           << " fin " << fin;
  WriteHeaders(std::move(spdy_headers), fin_, nullptr);
  
  return true;
}

void QuicNgxStream::SendHttpbody(const char*data, int len) {
  if (fin_) {
    return;
  }
  
  had_send_length_ += len;

  if (is_http_chunked_) {
    while (len > 0) {

      if (http_chunked_step_ == 0) {
        http_chunked_step_ = 1;
        char *endptr = nullptr;
        content_length_ = (size_t)::strtol(data, &endptr, 16);
        if (content_length_ == 0) {
          fin_ = true;
          WriteOrBufferBody("", true);
          return;
        }
        
        int use_len = endptr - data + 2;
        data += use_len;
        len -= use_len;

      } else if (http_chunked_step_ == 1) {
        
        int send_len = (int)content_length_;
        if (send_len > len) {
          send_len = len;
        }
      
        QuicStringPiece body(data, send_len);
        WriteOrBufferBody(body, false);
        content_length_ -= send_len;
        data += send_len;
        len -= send_len;

        if (content_length_ == 0) {
          http_chunked_step_ = 2;
          content_length_ = 2;
        }

      } else if (http_chunked_step_ == 2) {
        if (len >= (int)content_length_) {
          data += content_length_;
          len -= content_length_;
          content_length_ = 0;
          http_chunked_step_ = 0;
        } else {
          content_length_ -= len;
          len = 0;
        }
      }
    }

  } else {
    QuicStringPiece body(data, len);
    fin_ = had_send_length_ == content_length_;
    WriteOrBufferBody(body, fin_);
  }
}
  
std::string QuicNgxStream::get_peer_ip() {
  return session()->peer_address().host().Normalized().ToString();
}

struct sockaddr_storage QuicNgxStream::get_peer_address() {
  return session()->peer_address().generic_address();
}
  
// bool QuicNgxStream::OnStreamFrameAcked(QuicStreamOffset offset,
//                                          QuicByteCount data_length,
//                                          bool fin_acked,
//                                          QuicTime::Delta ack_delay_time,
//                                          QuicByteCount* newly_acked_length) {
//   bool rs = QuicSimpleServerStream::OnStreamFrameAcked(offset,
//                                                        data_length,
//                                                        fin_acked,
//                                                        ack_delay_time,
//                                                        newly_acked_length);
//   if (quic_ngx_curl_) {
//     quic_ngx_curl_->ContinueDownload(BufferedDataBytes());
//   } else if (false == fin_sent() &&
//              BufferedDataBytes() == 0) {
//     // quic_ngx_curl_ is nullptr and close this stream
//     set_fin_sent(true);
//     CloseWriteSide();
//   }
//   return rs;
// }



}  // namespace quic
