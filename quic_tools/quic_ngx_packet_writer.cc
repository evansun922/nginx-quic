
/*
 * Copyright (C) sunlei
 */

#include "quic_ngx_packet_writer.h"

namespace quic {

QuicNgxPacketWriter::QuicNgxPacketWriter(int fd,
                                         SetEPOLLOUT set_epoll_out,
                                         void *module_context)
  : QuicDefaultPacketWriter(fd),
    sendmmsg_len_(0),
    set_epoll_out_(set_epoll_out),
    module_context_(module_context) {
  for (size_t i = 0; i < kMaxWritesCacheCount; i++) {
    NgxPacket *p = new NgxPacket();
    free_packet_list_.push_back(p);
  }
}

QuicNgxPacketWriter::~QuicNgxPacketWriter() {
  for (auto it = free_packet_list_.begin();
       it != free_packet_list_.end();
       ++it) {
    delete *it;
  }
  free_packet_list_.clear();

  for (auto it = use_packet_list_.begin();
       it != use_packet_list_.end();
       ++it) {
    delete *it;
  }
  use_packet_list_.clear();
}

WriteResult QuicNgxPacketWriter::WritePacket(
    const char* buffer,
    size_t buf_len,
    const QuicIpAddress& self_address,
    const QuicSocketAddress& peer_address,
    PerPacketOptions* options) {
  DCHECK(!IsWriteBlocked());
  DCHECK(nullptr == options)
      << "QuicNgxPacketWriter does not accept any options.";

  
  if (!free_packet_list_.empty()) {
    auto it = free_packet_list_.begin();

    memcpy((*it)->buf, buffer, buf_len);
    (*it)->len = buf_len;
    (*it)->peer_address = peer_address.generic_address();

    SetSendValue(&mmsghdr_[sendmmsg_len_],
                 &iovec_[sendmmsg_len_],
                 (*it)->buf,
                 (*it)->len,
                 &(*it)->peer_address);
    sendmmsg_len_++;    
    
    use_packet_list_.push_back(*it);
    free_packet_list_.erase(it);

    if (free_packet_list_.empty()) {
      Flush();
    }
    
    return WriteResult(WRITE_STATUS_OK, buf_len);
  }

  Flush();
  if (free_packet_list_.empty()) {
    set_epoll_out_(module_context_);
    set_write_blocked(true);
    return WriteResult(WRITE_STATUS_BLOCKED, EAGAIN);
  }

  

  auto it = free_packet_list_.begin();

  memcpy((*it)->buf, buffer, buf_len);
  (*it)->len = buf_len;
  (*it)->peer_address = peer_address.generic_address();

  SetSendValue(&mmsghdr_[sendmmsg_len_],
               &iovec_[sendmmsg_len_],
               (*it)->buf,
               (*it)->len,
               &(*it)->peer_address);
  sendmmsg_len_++;    
    
  use_packet_list_.push_back(*it);
  free_packet_list_.erase(it);

  if (free_packet_list_.empty()) {
    Flush();
  }
    
  return WriteResult(WRITE_STATUS_OK, buf_len);
  

  // if (buffered_writes_.size() >= kMaxWritesCacheCount) {
  //   Flush();
  //   if (buffered_writes_.size() >= kMaxWritesCacheCount) {
  //     set_write_blocked(true);
  //     return WriteResult(WRITE_STATUS_BLOCKED, EAGAIN);
  //   }    
  // }
  
  // char *cpy_buffer = writes_cache_[writes_cache_pos_%kMaxWritesCacheCount];
  // memcpy(cpy_buffer, buffer, buf_len);
  // writes_cache_pos_++;
  // buffered_writes_.emplace_back(cpy_buffer, buf_len, self_address, peer_address);
  // if (buffered_writes_.size() >= kMaxWritesCacheCount) {
  //   // send
  //   WriteResult result = Flush();
  //   if (IsWriteBlockedStatus(result.status)) {
  //     set_write_blocked(true);
  //     return result;
  //   }
  // }

  // return WriteResult(WRITE_STATUS_OK, buf_len);
}

WriteResult QuicNgxPacketWriter::Flush() {
  if (sendmmsg_len_ == 0)
    return WriteResult(WRITE_STATUS_OK, 0);


  int rc;
  do {
    rc = ::sendmmsg(fd(), mmsghdr_, sendmmsg_len_, 0);
  } while (rc < 0 && errno == EINTR);



  if (rc > 0) {
    int total_send_len = 0;
    auto it = use_packet_list_.begin();
    int j = 0;
    sendmmsg_len_ = 0;
    while (it != use_packet_list_.end()) {
      if (j < rc) {
        total_send_len += (*it)->len;
        free_packet_list_.push_front(*it);
        j++;
        it = use_packet_list_.erase(it);
        continue;
      }

      SetSendValue(&mmsghdr_[sendmmsg_len_],
                   &iovec_[sendmmsg_len_],
                   (*it)->buf,
                   (*it)->len,
                   &(*it)->peer_address);
      sendmmsg_len_++;
      ++it;
    }

    return WriteResult(WRITE_STATUS_OK, total_send_len);
  } else if (rc == 0) {
    QUIC_BUG << "sendmmsg returned 0, returning WRITE_STATUS_ERROR. errno: "
             << errno;
    errno = EIO;
  }

  return WriteResult((errno == EAGAIN || errno == EWOULDBLOCK)
                     ? WRITE_STATUS_BLOCKED
                     : WRITE_STATUS_ERROR,
                     errno);

  
  
  
  // QuicMMsgHdr mhdr(
  //     buffered_writes_.begin(), buffered_writes_.end(), kCmsgSpaceForIp,
  //     [](QuicMMsgHdr* mhdr, int i, const BufferedWrite& buffered_write) {
  //       mhdr->SetIpInNextCmsg(i, buffered_write.self_address);
  //     });
  // int num_packets_sent = 0;
  // WriteResult result = QuicLinuxSocketUtils::WriteMultiplePackets(
  //             fd(), &mhdr, &num_packets_sent);
  // if (num_packets_sent > 0) {
  //   buffered_writes_.erase(buffered_writes_.begin(),
  //                          buffered_writes_.begin() + num_packets_sent);
  // }
  // return result;
}

void QuicNgxPacketWriter::SetSendValue(struct mmsghdr *mhdr,
                                       struct iovec *iov,
                                       char *buf,
                                       int len,
                                       struct sockaddr_storage *peer_address) {
  memset(iov, 0, sizeof(struct iovec));
  iov->iov_base = buf;
  iov->iov_len = len;

  memset(mhdr, 0, sizeof(struct mmsghdr));
  struct msghdr* hdr = &mhdr->msg_hdr;
  hdr->msg_iov = iov;
  hdr->msg_iovlen = 1;
  // hdr->msg_control = nullptr;
  // hdr->msg_controllen = 0;

  hdr->msg_name = peer_address;
  hdr->msg_namelen = peer_address->ss_family == AF_INET
    ? sizeof(sockaddr_in)
    : sizeof(sockaddr_in6);
}


}  // namespace quic
