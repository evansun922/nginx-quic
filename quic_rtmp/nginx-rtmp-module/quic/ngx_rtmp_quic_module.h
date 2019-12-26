
/*
 * Copyright (C) sunlei
 */


#ifndef _NGX_RTMP_QUIC_MODULE_H_INCLUDED_
#define _NGX_RTMP_QUIC_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_rtmp.h>
#include "quic_ngx_rtmp_interface.h"


typedef struct {
  ngx_array_t               *certificates;
  ngx_array_t               *certificate_keys;
  size_t                    flush_interval;  // millisecond
  size_t                    stream_buffered_size;
} ngx_rtmp_quic_srv_conf_t;


typedef ngx_quic_context_t ngx_rtmp_quic_context_t;


extern ngx_module_t  ngx_rtmp_quic_module;


#endif /* _NGX_RTMP_QUIC_MODULE_H_INCLUDED_ */
