
/*
 * Copyright (C) sunlei
 */


#include "ngx_rtmp_quic_chromium.h"
#include "ngx_rtmp_quic_module.h"







void
ngx_rtmp_quic_handler_buf_by_quic(ngx_connection_t *c)
{
  ngx_rtmp_init_connection(c);
}


void*
ngx_rtmp_quic_init_chromium(ngx_rtmp_quic_context_t *module_context,
                            int listen_fd,
                            int port,
                            int address_family,
                            char **certificate_list,
                            char **certificate_key_list)
{  
  return ngx_rtmp_init_quic(module_context,
                            listen_fd,
                            port,
                            address_family,
                            ngx_quic_CreateNgxTimer,
                            ngx_quic_AddNgxTimer,
                            ngx_quic_DelNgxTimer,
                            ngx_quic_FreeNgxTimer,
                            certificate_list,
                            certificate_key_list);
}


void
ngx_rtmp_event_quic_recvmsg(ngx_event_t *ev)
{

  ngx_listening_t                 *ls;
  ngx_connection_t                *lc;
  ngx_rtmp_quic_context_t         *quic_ctx;


  if (ev->timedout) {
    ev->timedout = 0;
  }

  lc = ev->data;
  ls = lc->listening;
  ev->ready = 0;
  quic_ctx = lc->data;
    
  ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                 "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

  ngx_rtmp_read_dispatch_packets(quic_ctx->chromium_server, lc);
}



