
/*
 * Copyright (C) sunlei
 */


#ifndef _NGX_HTTP_QUIC_MODULE_H_INCLUDED_
#define _NGX_HTTP_QUIC_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



typedef struct {
  ngx_str_t                 certificate;
  ngx_str_t                 certificate_key;
  ngx_flag_t                bbr;
  ngx_flag_t                ietf_draft;
  size_t                    flush_interval;  // millisecond
  time_t                    idle_network_timeout; // seconds
} ngx_http_quic_srv_conf_t;


typedef struct {
  ngx_pool_t       *pool;
  ngx_connection_t *lc;
  ngx_event_t      ngx_quic_interval_event;
  size_t           flush_interval;
  void             *chromium_server;
} ngx_http_quic_context_t;


extern ngx_module_t  ngx_http_quic_module;


#endif /* _NGX_HTTP_QUIC_MODULE_H_INCLUDED_ */
