/*
 * Copyright (C) sunlei
 */


#ifndef _NGX_HTTP_QUIC_CHROMIUM_H_INCLUDED_
#define _NGX_HTTP_QUIC_CHROMIUM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_quic_module.h"




/*
 *  chromium interface
 */
void* ngx_http_quic_init_chromium(ngx_http_quic_context_t *module_context,
                                  int listen_fd,
                                  int port,
                                  int address_family,
                                  char **certificate_list,
                                  char **certificate_key_list,
                                  int bbr,
                                  int ietf_draft,
                                  int idle_network_timeout);

void ngx_http_quic_handler_buf_by_quic(ngx_connection_t *c);

void ngx_http_event_quic_recvmsg(ngx_event_t *ev);

void ngx_event_quic_can_sendmsg(ngx_event_t *ev);

#endif /* _NGX_HTTP_QUIC_CHROMIUM_H_INCLUDED_ */
