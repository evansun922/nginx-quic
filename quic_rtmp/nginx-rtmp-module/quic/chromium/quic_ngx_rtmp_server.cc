
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
#include "net/socket/udp_server_socket.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/tools/quic_transport_simple_server_dispatcher.h"
#include "net/third_party/quiche/src/quic/core/quic_default_packet_writer.h"

#include "quic_ngx_alarm_factory.h"

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
// constexpr size_t kMaxNewConnectionsPerEvent = 32;
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

QuicNgxRtmpServer::QuicNgxRtmpServer(int fd, int port)
  : fd_(fd),
    port_(port),
    version_manager_({ParsedQuicVersion{PROTOCOL_TLS1_3, QUIC_VERSION_99}}),
    clock_(QuicChromiumClock::GetInstance()),
    crypto_config_(kSourceAddressTokenSecret,
                   quic::QuicRandom::GetInstance(),
                   quic::CreateDefaultProofSource(),
                   quic::KeyExchangeSource::Default()) {}

QuicNgxRtmpServer::~QuicNgxRtmpServer() {}

void QuicNgxRtmpServer::Initialize(void* ngx_module_context,
                                CreateNgxTimer create_ngx_timer,
                                AddNgxTimer add_ngx_timer,
                                DelNgxTimer del_ngx_timer,
                                FreeNgxTimer free_ngx_timer,
                                std::vector<url::Origin> &accepted_origins) {
  dispatcher_.reset(new quic::QuicTransportSimpleServerDispatcher(
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
                std::move(accepted_origins)));

  dispatcher_->InitializeWithWriter(new QuicDefaultPacketWriter(fd_));

  printf("AAAA %d\n", port_);
}




}  // namespace net
