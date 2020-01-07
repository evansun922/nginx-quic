
/*
 * Copyright (C) sunlei
 */

#ifndef NET_QUIC_QUIC_RTMP_INTERFACE_H_
#define NET_QUIC_QUIC_RTMP_INTERFACE_H_

#include "quic_ngx_tools_interface.h"

#ifdef __cplusplus
extern "C"  {
#endif

/*
 *  call in nginx
 */
typedef void(*SetVisitorForNgx)(void *ngx_nc,
                                void *quic_visitor);

  
/*
 *  call in quic
 */
typedef void(*ProcessRtmpData)(void *module_context,
                               void *nc,
                               void *quic_visitor,
                               struct sockaddr_storage* self_addr,
                               struct sockaddr_storage* peer_addr,
                               const char *data,
                               int data_len);



  
void* ngx_rtmp_init_quic(void* ngx_module_context,
                         int listen_fd,
                         int port,
                         int address_family,
                         CreateNgxTimer create_ngx_timer,
                         AddNgxTimer add_ngx_timer,
                         DelNgxTimer del_ngx_timer,
                         FreeNgxTimer free_ngx_timer,
                         char **certificate_list,
                         char **certificate_key_list,
                         ProcessRtmpData process_rtmp_data,
                         SetVisitorForNgx set_visitor_for_ngx,
                         SetEPOLLOUT set_epoll_out);

void ngx_rtmp_free_quic(void* chromium_server);

void ngx_rtmp_shutdown_quic(void* chromium_server);

void ngx_rtmp_read_dispatch_packets(void* chromium_server,
                                    void* ngx_connection);

int ngx_rtmp_flush_cache_packets(void* chromium_server);

int ngx_rtmp_can_write(void* chromium_server);

void ngx_rtmp_set_nc_for_quic_visitor(
                      void* quic_visitor,
                      void* ngx_connection);

ssize_t ngx_rtmp_send_quic_packets(
                          void* quic_visitor,
                          const char*data,
                          int len);

void ngx_rtmp_sendfin(void* quic_visitor);


#ifdef __cplusplus
}
#endif

#endif  // NET_QUIC_QUIC_RTMP_INTERFACE_H_
