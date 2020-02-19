
/*
 * Copyright (C) sunlei
 */

#ifndef QUIC_NGX_HTTP_INTERFACE_H_
#define QUIC_NGX_HTTP_INTERFACE_H_

#include "quic_ngx_tools_interface.h"

#ifdef __cplusplus
extern "C"  {
#endif

/*
 *  call in nginx
 */


  
/*
 *  call in quic
 */
  
typedef void(*RequestHttpQuic2Ngx)(void* ngx_connection,
                                   void* quic_stream,
                                   struct sockaddr_storage* self_addr,
                                   struct sockaddr_storage* peer_addr,
                                   const char *header,
                                   int header_len,
                                   const char *body,
                                   int body_len);

typedef void(*SetStreamForNgx)(void* ngx_request, /*ngx_http_request_t*/
                               void* quic_stream);



  
void* ngx_http_init_quic(void* ngx_module_context,
                         int listen_fd,
                         int port,
                         int address_family,
                         CreateNgxTimer create_ngx_timer,
                         AddNgxTimer add_ngx_timer,
                         DelNgxTimer del_ngx_timer,
                         FreeNgxTimer free_ngx_timer,
                         RequestHttpQuic2Ngx req_quic_2_ngx,
                         SetStreamForNgx set_stream_for_ngx,
                         SetEPOLLOUT set_epoll_out,
                         char **certificate_list,
                         char **certificate_key_list,
                         int bbr,
                         int ietf_draft,
                         int idle_network_timeout,
                         uintptr_t ngx_log_level);

void ngx_http_free_quic(void* chromium_server);

void ngx_http_shutdown_quic(void* chromium_server);

void ngx_http_read_dispatch_packets(void* chromium_server,
                                    void* ngx_connection);

ssize_t ngx_http_send_quic_packets(void* quic_stream,
                                   const char*data, int len);

size_t ngx_http_stream_buffered_size(void* quic_stream);

int ngx_http_flush_cache_packets(void* chromium_server);

int ngx_http_can_write(void* chromium_server);

void ngx_http_set_nc_for_quic_stream(void* quic_stream,
                                void* ngx_connection/*ngx_connection_t*/);
  

#ifdef __cplusplus
}
#endif

#endif  // QUIC_NGX_HTTP_INTERFACE_H_
