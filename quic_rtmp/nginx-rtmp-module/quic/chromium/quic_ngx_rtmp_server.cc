
/*
 * Copyright (C) sunlei
 */

#include "quic_ngx_rtmp_server.h"

#include <stdlib.h>


#include "net/base/net_errors.h"
#include "net/quic/address_utils.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/core/quic_default_packet_writer.h"

#include "quic_ngx_alarm_factory.h"
#include "quic_ngx_packet_reader.h"
#include "quic_ngx_packet_writer.h"
#include "quic_ngx_rtmp_dispatcher.h"
#include "quic_ngx_packet_writer.h"

namespace quic {
namespace {

using quic::CryptoHandshakeMessage;
using quic::ParsedQuicVersion;
using quic::PROTOCOL_TLS1_3;
using quic::QUIC_VERSION_99;
using quic::QuicChromiumClock;
using quic::QuicCryptoServerStream;
using quic::QuicSocketAddress;
using quic::QuicTransportSimpleServerSession;

constexpr char kSourceAddressTokenSecret[] = "test";
// constexpr size_t kMaxReadsPerEvent = 32;
constexpr size_t kMaxNewConnectionsPerEvent = 32;
// constexpr int kReadBufferSize = 2 * quic::kMaxIncomingPacketSize;

}  // namespace

class QuicNgxRtmpSessionHelper
    : public QuicCryptoServerStream::Helper {
 public:
  bool CanAcceptClientHello(const CryptoHandshakeMessage& /*message*/,
                            const QuicSocketAddress& /*client_address*/,
                            const QuicSocketAddress& /*peer_address*/,
                            const QuicSocketAddress& /*self_address*/,
                            std::string* /*error_details*/) const override {
    return true;
  }
};

QuicNgxRtmpServer::QuicNgxRtmpServer(int fd, int port,
                  std::unique_ptr<quic::ProofSource> proof_source)
  : fd_(fd),
    port_(port),
    version_manager_({ParsedQuicVersion{PROTOCOL_TLS1_3, QUIC_VERSION_99}}),
    clock_(QuicChromiumClock::GetInstance()),
    crypto_config_(kSourceAddressTokenSecret,
                   quic::QuicRandom::GetInstance(),
                   std::move(proof_source),
                   quic::KeyExchangeSource::Default()),
    packet_reader_(new QuicNgxPacketReader()),
    writer_(nullptr),
    packets_dropped_(0),
    overflow_supported_(false) {}

QuicNgxRtmpServer::~QuicNgxRtmpServer() {}

void QuicNgxRtmpServer::Initialize(
                   void* ngx_module_context,
                   int address_family,
                   CreateNgxTimer create_ngx_timer,
                   AddNgxTimer add_ngx_timer,
                   DelNgxTimer del_ngx_timer,
                   FreeNgxTimer free_ngx_timer,
                   ProcessRtmpData process_rtmp_data,
                   SetVisitorForNgx set_visitor_for_ngx,
                   SetEPOLLOUT set_epoll_out) {
  
  int get_overflow = 1;
  int rc = setsockopt(fd_, SOL_SOCKET, SO_RXQ_OVFL, &get_overflow,
                      sizeof(get_overflow));
  if (rc < 0) {
    QUIC_DLOG(WARNING) << "Socket overflow detection not supported";
  } else {
    overflow_supported_ = true;
  }

  rc = QuicSocketUtils::SetGetAddressInfo(fd_, address_family);
  if (rc < 0) {
    LOG(ERROR) << "IP detection not supported" << strerror(errno);
    exit(0);
  }

  rc = QuicSocketUtils::SetGetSoftwareReceiveTimestamp(fd_);
  if (rc < 0) {
    QUIC_LOG(WARNING) << "SO_TIMESTAMPING not supported; using fallback: "
                      << strerror(errno);
  }
  
  dispatcher_.reset(new quic::QuicNgxRtmpDispatcher(
                &config_,
                &crypto_config_,
                &version_manager_,
                std::make_unique<net::QuicChromiumConnectionHelper>(
                    clock_,
                    quic::QuicRandom::GetInstance()),
                std::make_unique<QuicNgxRtmpSessionHelper>(),
                std::make_unique<QuicNgxAlarmFactory>(
                    ngx_module_context,
                    create_ngx_timer,
                    add_ngx_timer,
                    del_ngx_timer,
                    free_ngx_timer),
                quic::kQuicDefaultConnectionIdLength,
                process_rtmp_data,
                set_visitor_for_ngx,
                ngx_module_context));

  writer_ = new QuicNgxPacketWriter(fd_,
                                    set_epoll_out,
                                    ngx_module_context);
  dispatcher_->InitializeWithWriter(writer_);
}

void QuicNgxRtmpServer::Shutdown() {
  dispatcher_->Shutdown();
}

bool QuicNgxRtmpServer::FlushWriteCache() {
  if (writer_ == nullptr) {
    return false;
  }

  WriteResult r = writer_->Flush();
  return r.status == WRITE_STATUS_BLOCKED;
}

bool QuicNgxRtmpServer::CanWrite() {
  dispatcher_->OnCanWrite();
  if (dispatcher_->HasPendingWrites()) {
    return true;
  }

  return FlushWriteCache();
}

void QuicNgxRtmpServer::ReadAndDispatchPackets(void* ngx_connection) {
  
  dispatcher_->ProcessBufferedChlos(kMaxNewConnectionsPerEvent);

  bool more_to_read = true;
  while (more_to_read) {
    more_to_read = packet_reader_->ReadAndDispatchPackets(
               fd_, port_, *clock_, dispatcher_.get(),
               overflow_supported_ ? &packets_dropped_ : nullptr);
  }

  if (dispatcher_->HasChlosBuffered()) {
    dispatcher_->ProcessBufferedChlos(kMaxNewConnectionsPerEvent);
  }
}


}  // namespace net
