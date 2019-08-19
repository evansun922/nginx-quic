
#ifndef NET_QUIC_QUIC_NGX_INTERFACE_H_
#define NET_QUIC_QUIC_NGX_INTERFACE_H_

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"  {
#endif

/*
 *  call in nginx
 */
typedef void(*OnChromiumAlarm)(void *chromium_alarm);

  
/*
 *  call in quic
 */
typedef void*(*CreateNgxTimer)(void *module_context,
                              void *chromium_alarm,
                              OnChromiumAlarm onChromiumAlarm);
  
typedef void(*AddNgxTimer)(void *module_context,
                           void *ngx_timer,
                           int64_t delay);
  
typedef void(*DelNgxTimer)(void *module_context, void *ngx_timer);

typedef void(*FreeNgxTimer)(void *ngx_timer);
  
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


  
void* ngx_init_quic(void* ngx_module_context,
                    int listen_fd,
                    int port,
                    int address_family,
                    CreateNgxTimer create_ngx_timer,
                    AddNgxTimer add_ngx_timer,
                    DelNgxTimer del_ngx_timer,
                    FreeNgxTimer free_ngx_timer,
                    RequestHttpQuic2Ngx req_quic_2_ngx,
                    SetStreamForNgx set_stream_for_ngx,
                    const char* certificate_file,
                    const char* key_file,
                    int bbr,
                    int idle_network_timeout);

void ngx_free_quic(void* chromium_server);

void ngx_shutdown_quic(void* chromium_server);

void ngx_read_dispatch_packets(void* chromium_server, void* ngx_connection);

ssize_t ngx_send_quic_packets(void* quic_stream,
                              const char*data, int len);

int ngx_flush_cache_packets(void* chromium_server);

int ngx_can_write(void* chromium_server);

void ngx_set_nc_for_quic_stream(void* quic_stream,
                                void* ngx_connection/*ngx_connection_t*/);
  

#ifdef __cplusplus
}
#endif

#endif  // NET_QUIC_QUIC_NGX_INTERFACE_H_
