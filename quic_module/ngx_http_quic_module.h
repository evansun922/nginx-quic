
/*
 * Copyright (C) sunlei
 */


#ifndef _NGX_HTTP_QUIC_MODULE_H_INCLUDED_
#define _NGX_HTTP_QUIC_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



typedef struct {
  ngx_array_t               *certificates;
  ngx_array_t               *certificate_keys;
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
