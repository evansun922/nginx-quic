
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


  
/*
 *  call in quic
 */
  



  
void* ngx_rtmp_init_quic(void* ngx_module_context,
                         int listen_fd,
                         int port,
                         CreateNgxTimer create_ngx_timer,
                         AddNgxTimer add_ngx_timer,
                         DelNgxTimer del_ngx_timer,
                         FreeNgxTimer free_ngx_timer);



#ifdef __cplusplus
}
#endif

#endif  // NET_QUIC_QUIC_RTMP_INTERFACE_H_
