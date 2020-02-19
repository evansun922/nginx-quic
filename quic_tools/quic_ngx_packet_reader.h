
/*
 * Copyright (C) sunlei
 */

#ifndef QUICHE_QUIC_NGX_PACKET_READER_H_
#define QUICHE_QUIC_NGX_PACKET_READER_H_

#include "net/third_party/quiche/src/quic/core/quic_packet_reader.h"


namespace quic {

#ifndef MMSG_MORE
#define MMSG_MORE 0
#endif

#ifndef MMSG_MORE_NO_ANDROID
#define MMSG_MORE_NO_ANDROID 0
#endif
  
// #if !MMSG_MORE
// // Read in larger batches to minimize recvmmsg overhead.
// constexpr int kNumPacketsPerReadMmsgCall = 16;
// #endif

class QuicNgxPacketReader : public QuicPacketReader {
 public:
  explicit QuicNgxPacketReader();
  QuicNgxPacketReader(const QuicNgxPacketReader&) = delete;
  QuicNgxPacketReader& operator=(const QuicNgxPacketReader&) = delete;

  ~QuicNgxPacketReader() override;

  // Reads a number of packets from the given fd, and then passes them off to
  // the PacketProcessInterface.  Returns true if there may be additional
  // packets available on the socket.
  // Populates |packets_dropped| if it is non-null and the socket is configured
  // to track dropped packets and some packets are read.
  // If the socket has timestamping enabled, the per packet timestamps will be
  // passed to the processor. Otherwise, |clock| will be used.
  bool ReadAndDispatchPackets(int fd,
                              int port,
                              const QuicClock& clock,
                              ProcessPacketInterface* processor,
                              QuicPacketCount* packets_dropped) override;
  
 private:
#if !MMSG_MORE
  // Storage only used when recvmmsg is available.
  // TODO(danzh): change it to be a pointer to avoid the allocation on the stack
  // from exceeding maximum allowed frame size.
  // packets_ and mmsg_hdr_ are used to supply cbuf and buf to the recvmmsg
  // call.
  struct PacketData {
    iovec iov;
    // raw_address is used for address information provided by the recvmmsg
    // call on the packets.
    struct sockaddr_storage raw_address;
    // cbuf is used for ancillary data from the kernel on recvmmsg.
    char cbuf[kCmsgSpaceForReadPacket];
    // buf is used for the data read from the kernel on recvmmsg.
    char buf[2*kMaxIncomingPacketSize];
  };
  PacketData packets_[kNumPacketsPerReadMmsgCall];
  mmsghdr mmsg_hdr_[kNumPacketsPerReadMmsgCall];
#endif
};

}  // namespace quic

#endif  // QUICHE_QUIC_NGX_PACKET_READER_H_
