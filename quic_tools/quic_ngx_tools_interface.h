
/*
 * Copyright (C) sunlei
 */

#ifndef NET_QUIC_QUIC_NGX_TOOLS_INTERFACE_H_
#define NET_QUIC_QUIC_NGX_TOOLS_INTERFACE_H_

#include <stdint.h>
#include <stdio.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#ifdef __cplusplus
extern "C"  {
#endif

typedef struct {
  ngx_pool_t       *pool;
  ngx_connection_t *lc;
  ngx_event_t       ngx_quic_interval_event;
  size_t            flush_interval;
  void             *chromium_server;
  size_t            stream_buffered_size;
} ngx_quic_context_t;

  
/*
 *  call in nginx
 */
typedef void(*OnChromiumAlarm)(void *chromium_alarm);

typedef struct {
  ngx_event_t ev;
  void *chromium_alarm;
  OnChromiumAlarm onChromiumAlarm;
} chromium_alarm_t;
  
  
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

typedef void(*SetEPOLLOUT)(void* module_context);


  
void* ngx_quic_CreateNgxTimer(void *module_context,
                                          void *chromium_alarm,
                                          OnChromiumAlarm onChromiumAlarm);
void ngx_quic_AddNgxTimer(void *module_context,
                                      void *ngx_timer,
                                      int64_t delay);
void ngx_quic_DelNgxTimer(void *module_context, void *ngx_timer);
void ngx_quic_FreeNgxTimer(void *ngx_timer);


void ngx_quic_close_accepted_udp_connection(ngx_connection_t *c);
ngx_connection_t *
ngx_create_connection_for_quic(ngx_connection_t *lc,
                               struct sockaddr_storage* self_addr,
                               struct sockaddr_storage* peer_addr,
                               ngx_recv_pt recv,
                               ngx_send_pt send,
                               ngx_send_chain_pt send_chain,
                               ngx_pool_cleanup_pt pool_cleanup_handler);

void ngx_quic_set_epoll_out(void *module_context);
  
#ifdef __cplusplus
}
#endif

#endif // NET_QUIC_QUIC_NGX_TOOLS_INTERFACE_H_

