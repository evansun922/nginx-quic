
#include "quic_ngx_server.h"

#include <errno.h>
#include <features.h>
#include <string.h>
#include <cstdint>
#include <memory>

#include "net/third_party/quiche/src/quic/core/crypto/crypto_handshake.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_data_reader.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/tls_server_handshaker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/tools/quic_simple_crypto_server_stream_helper.h"
#include "quic_ngx_alarm_factory.h"
#include "quic_ngx_stream.h"
#include "quic_ngx_dispatcher.h"
#include "quic_ngx_backend.h"
#include "quic_ngx_packet_reader.h"
#include "quic_ngx_packet_writer.h"


namespace quic {


namespace {
  
const char kSourceAddressTokenSecret[] = "secret";

}  // namespace
  

const size_t kNumSessionsToCreatePerSocketEvent = 16;

QuicNgxServer::QuicNgxServer(std::unique_ptr<ProofSource> proof_source,
                             QuicNgxBackend* quic_ngx_server_backend,
                             int idle_network_timeout)
  : QuicNgxServer(std::move(proof_source),
                  QuicConfig(),
                  QuicCryptoServerConfig::ConfigOptions(),
                  AllSupportedVersions(),
                  quic_ngx_server_backend,
                  idle_network_timeout,
                  kQuicDefaultConnectionIdLength) {}

QuicNgxServer::QuicNgxServer(
    std::unique_ptr<ProofSource> proof_source,
    const QuicConfig& config,
    const QuicCryptoServerConfig::ConfigOptions& crypto_config_options,
    const ParsedQuicVersionVector& supported_versions,
    QuicNgxBackend* quic_ngx_server_backend,
    int idle_network_timeout,
    uint8_t expected_connection_id_length)
  : port_(0),
    fd_(-1),
    packets_dropped_(0),
    overflow_supported_(false),
    silent_close_(false),
    config_(config),
    crypto_config_(kSourceAddressTokenSecret,
                   QuicRandom::GetInstance(),
                   std::move(proof_source),
                   KeyExchangeSource::Default()),
    crypto_config_options_(crypto_config_options),
    version_manager_(supported_versions),
    packet_reader_(new QuicNgxPacketReader()),
    quic_ngx_server_backend_(quic_ngx_server_backend),
    expected_connection_id_length_(expected_connection_id_length),
    helper_(new net::QuicChromiumConnectionHelper(&clock_,
            quic::QuicRandom::GetInstance())),
    writer_(nullptr),
    ngx_module_context_(nullptr) {
  if (-1 != idle_network_timeout) {
    config_.SetIdleNetworkTimeout(QuicTime::Delta::FromSeconds(idle_network_timeout),
                                  QuicTime::Delta::FromSeconds(idle_network_timeout/2));
  }
}

QuicNgxServer::~QuicNgxServer() = default;

void QuicNgxServer::Initialize(void* ngx_module_context,
                               int listen_fd,
                               int port,
                               int address_family,
                               CreateNgxTimer create_ngx_timer,
                               AddNgxTimer add_ngx_timer,
                               DelNgxTimer del_ngx_timer,
                               FreeNgxTimer free_ngx_timer) {
  // If an initial flow control window has not explicitly been set, then use a
  // sensible value for a server: 1 MB for session, 64 KB for each stream.
  const uint32_t kInitialSessionFlowControlWindow = 1 * 1024 * 1024;  // 1 MB
  const uint32_t kInitialStreamFlowControlWindow = 64 * 1024;         // 64 KB
  if (config_.GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config_.SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindow);
  }
  if (config_.GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config_.SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindow);
  }

  ngx_module_context_ = ngx_module_context;
  fd_ = listen_fd;
  port_ = port;


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

  
  do {
    std::unique_ptr<CryptoHandshakeMessage> scfg(
      crypto_config_.AddDefaultConfig(helper_->GetRandomGenerator(),
                                      helper_->GetClock(),
                                      crypto_config_options_));
  } while(false);

  dispatcher_.reset(CreateQuicDispatcher(ngx_module_context,
                                         create_ngx_timer,
                                         add_ngx_timer,
                                         del_ngx_timer,
                                         free_ngx_timer));
  dispatcher_->InitializeWithWriter(CreateWriter(fd_));
}

QuicPacketWriter* QuicNgxServer::CreateWriter(int fd) {
  // return new QuicDefaultPacketWriter(fd);
  writer_ = new QuicNgxPacketWriter(fd);
  return writer_;
}

QuicDispatcher* QuicNgxServer::CreateQuicDispatcher(void* ngx_module_context,
                                                    CreateNgxTimer create_ngx_timer,
                                                    AddNgxTimer add_ngx_timer,
                                                    DelNgxTimer del_ngx_timer,
                                                    FreeNgxTimer free_ngx_timer) {
  return new QuicNgxDispatcher(
      &config_, &crypto_config_, &version_manager_,
      std::unique_ptr<quic::QuicConnectionHelperInterface>(helper_),
      std::unique_ptr<QuicCryptoServerStream::Helper>(
          new QuicSimpleCryptoServerStreamHelper(QuicRandom::GetInstance())),
      std::unique_ptr<QuicAlarmFactory>(
         new QuicNgxAlarmFactory(ngx_module_context,
                                 create_ngx_timer,
                                 add_ngx_timer,
                                 del_ngx_timer,
                                 free_ngx_timer)),
      quic_ngx_server_backend_, expected_connection_id_length_);
}

void QuicNgxServer::ReadAndDispatchPackets(void* ngx_connection) {
  quic_ngx_server_backend_->set_ngx_connection(ngx_connection);
  
  dispatcher_->ProcessBufferedChlos(kNumSessionsToCreatePerSocketEvent);

  bool more_to_read = true;
  while (more_to_read) {
    more_to_read = packet_reader_->ReadAndDispatchPackets(
               fd_, port_, clock_, dispatcher_.get(),
               overflow_supported_ ? &packets_dropped_ : nullptr);
  }
}

bool QuicNgxServer::FlushWriteCache() {
  if (writer_ == nullptr) {
    return false;
  }

  WriteResult r = writer_->Flush();
  return r.status == WRITE_STATUS_BLOCKED;
}

bool QuicNgxServer::CanWrite() {
  dispatcher_->OnCanWrite();
  if (dispatcher_->HasPendingWrites()) {
    return true;
  }

  return FlushWriteCache();
}

void QuicNgxServer::Shutdown() {
  writer_ = nullptr;
  if (!silent_close_) {
    // Before we shut down the epoll server, give all active sessions a chance
    // to notify clients that they're closing.
    dispatcher_->Shutdown();
  }
}

// void QuicNgxServer::OnEvent(int fd, QuicEpollEvent* event) {
//   DCHECK_EQ(fd, fd_);
//   event->out_ready_mask = 0;

//   if (event->in_events & EPOLLIN) {
//     QUIC_DVLOG(1) << "EPOLLIN";

//     dispatcher_->ProcessBufferedChlos(kNumSessionsToCreatePerSocketEvent);

//     bool more_to_read = true;
//     while (more_to_read) {
//       more_to_read = packet_reader_->ReadAndDispatchPackets(
//           fd_, port_, QuicEpollClock(&epoll_server_), dispatcher_.get(),
//           overflow_supported_ ? &packets_dropped_ : nullptr);
//     }

//     if (dispatcher_->HasChlosBuffered()) {
//       // Register EPOLLIN event to consume buffered CHLO(s).
//       event->out_ready_mask |= EPOLLIN;
//     }
//   }

//   if (event->in_events & EPOLLERR) {
//   }
// }

}  // namespace quic
