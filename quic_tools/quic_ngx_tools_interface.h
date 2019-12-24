
/*
 * Copyright (C) sunlei
 */

#ifndef NET_QUIC_QUIC_NGX_TOOLS_INTERFACE_H_
#define NET_QUIC_QUIC_NGX_TOOLS_INTERFACE_H_

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




  
#ifdef __cplusplus
}
#endif

#endif // NET_QUIC_QUIC_NGX_TOOLS_INTERFACE_H_

