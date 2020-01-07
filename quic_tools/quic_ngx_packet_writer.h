
/*
 * Copyright (C) sunlei
 */

#ifndef QUICHE_QUIC_CORE_QUIC_NGX_PACKET_WRITER_H_
#define QUICHE_QUIC_CORE_QUIC_NGX_PACKET_WRITER_H_

#include "net/third_party/quiche/src/quic/core/quic_default_packet_writer.h"
#include "net/quic/platform/impl/quic_linux_socket_utils.h"
#include "quic_ngx_tools_interface.h"


namespace quic {

constexpr size_t kMaxWritesCacheCount = 16;
constexpr size_t kMaxWritesCacheSize = 2 * kMaxOutgoingPacketSize;
  
// Ngx packet writer which wraps QuicLinuxSocketUtils WritePacket.
class QUIC_EXPORT_PRIVATE QuicNgxPacketWriter : public QuicDefaultPacketWriter {
 public:
  explicit QuicNgxPacketWriter(int fd,
                               SetEPOLLOUT set_epoll_out,
                               void *module_context);
  QuicNgxPacketWriter(const QuicNgxPacketWriter&) = delete;
  QuicNgxPacketWriter& operator=(const QuicNgxPacketWriter&) = delete;
  ~QuicNgxPacketWriter() override;

  // QuicPacketWriter
  WriteResult WritePacket(const char* buffer,
                          size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* options) override;
  WriteResult Flush() override;


 private:

  void SetSendValue(struct mmsghdr *mhdr,
                    struct iovec *iov,
                    char *buf,
                    int len,
                    struct sockaddr_storage *peer_address);
  
  struct NgxPacket {    
    char buf[kMaxWritesCacheSize];
    int len;
    struct sockaddr_storage peer_address;
  };

  std::list<NgxPacket*> free_packet_list_;
  std::list<NgxPacket*> use_packet_list_;

  struct mmsghdr mmsghdr_[kMaxWritesCacheCount];
  struct iovec iovec_[kMaxWritesCacheCount];
  int sendmmsg_len_;

  SetEPOLLOUT set_epoll_out_;
  void *module_context_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_NGX_PACKET_WRITER_H_
