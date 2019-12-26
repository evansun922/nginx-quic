/*
 * Copyright (C) sunlei
 */

#ifndef _NGX_RTMP_QUIC_CHROMIUM_H_INCLUDED_
#define _NGX_RTMP_QUIC_CHROMIUM_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "ngx_rtmp_quic_module.h"





void ngx_rtmp_quic_handler_buf_by_quic(ngx_connection_t *c);
void* ngx_rtmp_quic_init_chromium(
                 ngx_rtmp_quic_context_t *module_context,
                 int listen_fd,
                 int port,
                 int address_family,
                 char **certificate_list,
                 char **certificate_key_list);
void ngx_rtmp_event_quic_recvmsg(ngx_event_t *ev);



#endif // _NGX_RTMP_QUIC_CHROMIUM_H_INCLUDED_
