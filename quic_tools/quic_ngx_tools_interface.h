
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



  
void* ngx_quic_CreateNgxTimer(void *module_context,
                                          void *chromium_alarm,
                                          OnChromiumAlarm onChromiumAlarm);
void ngx_quic_AddNgxTimer(void *module_context,
                                      void *ngx_timer,
                                      int64_t delay);
void ngx_quic_DelNgxTimer(void *module_context, void *ngx_timer);
void ngx_quic_FreeNgxTimer(void *ngx_timer);

  
  
#ifdef __cplusplus
}
#endif

#endif // NET_QUIC_QUIC_NGX_TOOLS_INTERFACE_H_

