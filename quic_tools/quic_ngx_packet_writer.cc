
/*
 * Copyright (C) sunlei
 */

#include "quic_ngx_packet_writer.h"

namespace quic {

QuicNgxPacketWriter::QuicNgxPacketWriter(int fd)
  : QuicDefaultPacketWriter(fd),writes_cache_pos_(0) {}

QuicNgxPacketWriter::~QuicNgxPacketWriter() = default;

WriteResult QuicNgxPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const QuicIpAddress& self_address,
    const QuicSocketAddress& peer_address,
    PerPacketOptions* options) {
  DCHECK(!IsWriteBlocked());
  DCHECK(nullptr == options)
      << "QuicNgxPacketWriter does not accept any options.";

  if (buffered_writes_.size() >= kMaxWritesCacheCount) {
    Flush();
    if (buffered_writes_.size() >= kMaxWritesCacheCount) {
      set_write_blocked(true);
      return WriteResult(WRITE_STATUS_BLOCKED, EAGAIN);
    }    
  }
  
  char *cpy_buffer = writes_cache_[writes_cache_pos_%kMaxWritesCacheCount];
  memcpy(cpy_buffer, buffer, buf_len);
  writes_cache_pos_++;
  buffered_writes_.emplace_back(cpy_buffer, buf_len, self_address, peer_address);
  if (buffered_writes_.size() >= kMaxWritesCacheCount) {
    // send
    WriteResult result = Flush();
    if (IsWriteBlockedStatus(result.status)) {
      set_write_blocked(true);
      return result;
    }
  }

  return WriteResult(WRITE_STATUS_OK, buf_len);
}

WriteResult QuicNgxPacketWriter::Flush() {
  if (buffered_writes_.empty())
    return WriteResult(WRITE_STATUS_OK, 0);
  
  QuicMMsgHdr mhdr(
      buffered_writes_.begin(), buffered_writes_.end(), kCmsgSpaceForIp,
      [](QuicMMsgHdr* mhdr, int i, const BufferedWrite& buffered_write) {
        mhdr->SetIpInNextCmsg(i, buffered_write.self_address);
      });
  int num_packets_sent = 0;
  WriteResult result = QuicLinuxSocketUtils::WriteMultiplePackets(
              fd(), &mhdr, &num_packets_sent);
  if (num_packets_sent > 0) {
    buffered_writes_.erase(buffered_writes_.begin(),
                           buffered_writes_.begin() + num_packets_sent);
  }
  return result;
}


}  // namespace quic
