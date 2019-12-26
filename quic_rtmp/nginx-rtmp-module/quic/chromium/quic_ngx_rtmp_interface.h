
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
                         int address_family,
                         CreateNgxTimer create_ngx_timer,
                         AddNgxTimer add_ngx_timer,
                         DelNgxTimer del_ngx_timer,
                         FreeNgxTimer free_ngx_timer,
                         char **certificate_list,
                         char **certificate_key_list);

void ngx_rtmp_read_dispatch_packets(void* chromium_server,
                                    void* ngx_connection);



#ifdef __cplusplus
}
#endif

#endif  // NET_QUIC_QUIC_RTMP_INTERFACE_H_
