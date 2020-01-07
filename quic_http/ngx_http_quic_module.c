
/*
 * Copyright (C) sunlei.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_quic_module.h"
#include "ngx_http_quic_chromium.h"


static ngx_int_t ngx_http_quic_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_quic_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_quic_process_init(ngx_cycle_t *cycle);
static void ngx_http_quic_exit_process(ngx_cycle_t *cycle);


static void *ngx_http_quic_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_quic_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_int_t
ngx_http_quic_check_and_rewrite_handler(ngx_cycle_t *cycle,
                                  ngx_listening_t *ls,
                                  ngx_http_addr_conf_t *conf);
static void ngx_do_quic_interval(ngx_event_t *ev);
static ngx_int_t ngx_http_variable_quic_scheme(ngx_http_request_t *r,
                       ngx_http_variable_value_t *v, uintptr_t data);



static ngx_command_t  ngx_http_quic_commands[] = {

  { ngx_string("ssl_certificate"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(ngx_http_quic_srv_conf_t, certificates),
    NULL },

  { ngx_string("ssl_certificate_key"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_array_slot,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(ngx_http_quic_srv_conf_t, certificate_keys),
    NULL },

  { ngx_string("quic_bbr"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(ngx_http_quic_srv_conf_t, bbr),
    NULL },

  { ngx_string("quic_ietf_draft"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(ngx_http_quic_srv_conf_t, ietf_draft),
    NULL },

  { ngx_string("quic_flush_interval"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(ngx_http_quic_srv_conf_t, flush_interval),
    NULL },

  { ngx_string("quic_idle_network_timeout"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_sec_slot,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(ngx_http_quic_srv_conf_t, idle_network_timeout),
    NULL },

  { ngx_string("quic_stream_buffered_size"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_HTTP_SRV_CONF_OFFSET,
    offsetof(ngx_http_quic_srv_conf_t, stream_buffered_size),
    NULL },  

  ngx_null_command
};


static ngx_http_module_t  ngx_http_quic_module_ctx = {
  ngx_http_quic_add_variables,             /* preconfiguration */
  NULL,                                    /* postconfiguration */

  NULL,                                    /* create main configuration */
  NULL,                                    /* init main configuration */

  ngx_http_quic_create_srv_conf,           /* create server configuration */
  ngx_http_quic_merge_srv_conf,            /* merge server configuration */

  NULL,                                    /* create location configuration */
  NULL                                     /* merge location configuration */
};


ngx_module_t  ngx_http_quic_module = {
  NGX_MODULE_V1,
  &ngx_http_quic_module_ctx,             /* module context */
  ngx_http_quic_commands,                /* module directives */
  NGX_HTTP_MODULE,                       /* module type */
  NULL,                                  /* init master */
  ngx_http_quic_module_init,             /* init module */
  ngx_http_quic_process_init,            /* init process */
  NULL,                                  /* init thread */
  NULL,                                  /* exit thread */
  ngx_http_quic_exit_process,            /* exit process */
  NULL,                                  /* exit master */
  NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_quic_vars[] = {

  // { ngx_string("scheme"),NULL,ngx_http_variable_quic_scheme,0,0,0 },
  
  ngx_http_null_variable
};


static ngx_int_t
ngx_http_quic_add_variables(ngx_conf_t *cf)
{
  ngx_http_variable_t        *var, *v;
  ngx_http_core_main_conf_t  *cmcf;
  ngx_hash_key_t             *key;
  ngx_uint_t                  i;
  ngx_str_t                   scheme_name = ngx_string("scheme");


  // we must reset scheme variable's get_handler = ngx_http_variable_quic_scheme,
  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  key = cmcf->variables_keys->keys.elts;
  for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
    
    if (scheme_name.len != key[i].key.len
        || ngx_strncasecmp(scheme_name.data, key[i].key.data, scheme_name.len) != 0)
    {
      continue;
    }

    v = key[i].value;
    v->get_handler = ngx_http_variable_quic_scheme;
    break;
  }
  
  
  for (v = ngx_http_quic_vars; v->name.len; v++) {
    var = ngx_http_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
      return NGX_ERROR;
    }

    var->get_handler = v->get_handler;
    var->data = v->data;
  }

  return NGX_OK;
}


static ngx_int_t
ngx_http_quic_module_init(ngx_cycle_t *cycle)
{
  ngx_uint_t                i,j;
  ngx_listening_t           *ls;
  ngx_http_port_t           *port;
#if (NGX_HAVE_INET6)
  ngx_http_in6_addr_t       *addrs6;
#endif
  ngx_http_in_addr_t        *addrs;

  
  ls = cycle->listening.elts;
  for (i = 0; i < cycle->listening.nelts; i++) {
    
    if (ls[i].ignore) {
      continue;
    }

    if (ls[i].type != 2) { // udp
      continue;
    }

    if (ls[i].handler != ngx_http_init_connection) {
      continue;
    }

    port = ls[i].servers;
    
    switch (ls[i].sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
      case AF_INET6:
        addrs6 = port->addrs;
        for (j = 0; j < port->naddrs; j++) {
          if (ngx_http_quic_check_and_rewrite_handler(cycle, &ls[i],
                                     &addrs6[j].conf) != NGX_OK) {
            return NGX_ERROR;
          }
        }
      break;
#endif
      default: /* AF_INET */
        addrs = port->addrs;
        for (j = 0; j < port->naddrs; j++) {
          if (ngx_http_quic_check_and_rewrite_handler(cycle, &ls[i],
                                      &addrs[j].conf) != NGX_OK) {
            return NGX_ERROR;
          }
        }
      break;
    }
  }
  return NGX_OK;
}


static ngx_int_t
ngx_http_quic_process_init(ngx_cycle_t *cycle)
{
  char                            **certificate_list;
  char                            **certificate_key_list;
  ngx_array_t                     *certificate_ary;
  ngx_array_t                     *certificate_key_ary;
  ngx_str_t                       *cert, *key, *str;
  ngx_uint_t                      i, j, s, nelts;
  ngx_listening_t                 *ls;
  ngx_connection_t                *lc;
  ngx_pool_t                      *pool;
  ngx_http_quic_context_t         *quic_ctx;
  ngx_event_t                     *ev;

  ngx_http_port_t                 *port;
#if (NGX_HAVE_INET6)
  ngx_http_in6_addr_t             *addrs6;
#endif
  ngx_http_in_addr_t              *addrs;
  ngx_http_addr_conf_t            *conf;
  
  ngx_http_quic_srv_conf_t        *qscf;
  int                             p;

  ngx_http_core_main_conf_t       *cmcf;
  ngx_http_core_srv_conf_t        **cscfp;
  ngx_http_ssl_srv_conf_t         *sscf;  
  
  ls = cycle->listening.elts;
  for (i = 0; i < cycle->listening.nelts; i++) {
      
    if (ls[i].handler == ngx_http_quic_handler_buf_by_quic) {

      port = ls[i].servers;

      switch (ls[i].sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
          addrs6 = port->addrs;
          conf = &addrs6[0].conf;

          p = ntohs(((struct sockaddr_in6*)ls[i].sockaddr)->sin6_port);
        break;
#endif
        default: /* AF_INET */
          addrs = port->addrs;
          conf = &addrs[0].conf;

          p = ntohs(((struct sockaddr_in*)ls[i].sockaddr)->sin_port);
        break;
      }

           
      qscf = ngx_http_conf_get_module_srv_conf(conf->default_server,
                                               ngx_http_quic_module);
      
      
      lc = ls[i].connection;
      if (lc == NULL) {
        continue;
      }
            
      if (lc->data != NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "lc->data in ngx_listening_t of "
                      "ngx_connection_t is not NULL");
        return NGX_ERROR;
      }

      pool = ngx_create_pool(2048, cycle->log);
      if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "ngx_create_pool failed for ngx_http_quic_context_t");
        return NGX_ERROR;
      }
      quic_ctx       = ngx_pcalloc(pool, sizeof(ngx_http_quic_context_t));
      quic_ctx->pool = pool;
      quic_ctx->lc   = lc;
      ev             = &quic_ctx->ngx_quic_interval_event;
      
      ev->handler    = ngx_do_quic_interval;
      ev->log        = cycle->log;
      ev->data       = quic_ctx;

      if (!ev->timer_set) {
        ngx_add_timer(ev, qscf->flush_interval);
        ev->timer_set = 1;
      }

      quic_ctx->flush_interval = qscf->flush_interval;
      quic_ctx->stream_buffered_size = qscf->stream_buffered_size;

      //
      certificate_ary = ngx_array_create(pool, 4, sizeof(ngx_str_t));
      certificate_key_ary = ngx_array_create(pool, 4, sizeof(ngx_str_t));
      
      cmcf = ngx_http_conf_get_module_main_conf(conf->default_server,
                                                ngx_http_core_module);

      cscfp = cmcf->servers.elts;

      for (s = 0; s < cmcf->servers.nelts; s++) {

        qscf = cscfp[s]->ctx->srv_conf[ngx_http_quic_module.ctx_index];
        
        if (!qscf->certificates || !qscf->certificate_keys) {
          continue;
        }

        if (qscf->certificates->nelts != qscf->certificate_keys->nelts) {
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "certificates of count(%u) != certificate_keys of count(%u).",
                        qscf->certificates->nelts, qscf->certificate_keys->nelts);
          return NGX_ERROR;
        }
        
        cert = qscf->certificates->elts;
        key = qscf->certificate_keys->elts;
        nelts = qscf->certificates->nelts;

        for (j = 0; j < nelts; j++) {
          str = ngx_array_push(certificate_ary);
          *str = cert[j];

          str = ngx_array_push(certificate_key_ary);
          *str = key[j];
        }
      }

      nelts = certificate_ary->nelts;
      
      if (nelts == 0) {
        // find certificates from ngx_http_ssl_module
        for (s = 0; s < cmcf->servers.nelts; s++) {

          sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        
          if (!sscf->certificates || !sscf->certificate_keys) {
            continue;
          }

          if (sscf->certificates->nelts != sscf->certificate_keys->nelts) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "certificates of count(%u) != certificate_keys of count(%u).",
                          sscf->certificates->nelts, sscf->certificate_keys->nelts);
            return NGX_ERROR;
          }
        
          cert = sscf->certificates->elts;
          key = sscf->certificate_keys->elts;
          nelts = sscf->certificates->nelts;

          for (j = 0; j < nelts; j++) {
            str = ngx_array_push(certificate_ary);
            *str = cert[j];

            str = ngx_array_push(certificate_key_ary);
            *str = key[j];
          }
        }

        nelts = certificate_ary->nelts;
      
        if (nelts == 0) {
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "certificates or certificate_keys is empty.");
          return NGX_ERROR;
        }
        
      }
      
      cert = certificate_ary->elts;
      key = certificate_key_ary->elts;
      certificate_list = ngx_pcalloc(pool, sizeof(char*)*(nelts+1));
      certificate_key_list = ngx_pcalloc(pool, sizeof(char*)*(nelts+1));
      
      for (j = 0; j < nelts; j++) {
        
        if (key[j].len == 0) {
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "no \"quic_ssl_certificate_key\" is empty.");
          return NGX_ERROR;
        }

        if (cert[j].len == 0) {
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "no \"quic_ssl_certificate\" is empty.");
          return NGX_ERROR;
        }

        if (ngx_get_full_name(pool, &cycle->conf_prefix, &cert[j]) 
            != NGX_OK) {
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "ngx_get_full_name failed, %V", &cert[j]);
          return NGX_ERROR;
        }

        if (ngx_get_full_name(pool, &cycle->conf_prefix, &key[j]) 
            != NGX_OK) {
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "ngx_get_full_name failed, %V", &key[j]);
          return NGX_ERROR;
        }

        if (access((char*)cert[j].data, F_OK) == -1) { 
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "quic ssl_certificate file \"%V\" check failed [%d] %s",
                        &cert[j], errno, strerror(errno));
          return NGX_ERROR;
        }

        if (access((char*)key[j].data, F_OK) == -1) {
          ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                        "quic ssl_certificate_key \"%V\" check failed [%d] %s",
                        &key[j], errno, strerror(errno));
          return NGX_ERROR;
        }

        certificate_list[j] = (char*)cert[j].data;
        certificate_key_list[j] = (char*)key[j].data;
      }

      certificate_list[j] = NULL;
      certificate_key_list[j] = NULL;
      
      quic_ctx->chromium_server = ngx_http_quic_init_chromium(quic_ctx,
                                    ls[i].fd,
                                    p,
                                    ls[i].sockaddr->sa_family,
                                    certificate_list,
                                    certificate_key_list,
                                    qscf->bbr,
                                    qscf->ietf_draft,
                                    qscf->idle_network_timeout);
      if (quic_ctx->chromium_server == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "chromium init failed");
        return NGX_ERROR;
      }
      
      lc->data = quic_ctx;
      lc->read->handler = ngx_http_event_quic_recvmsg;
      lc->write->log = lc->log;
      lc->write->handler = ngx_http_event_quic_can_sendmsg;
    }
  }

  
  return NGX_OK;  
}


static void
ngx_http_quic_exit_process(ngx_cycle_t *cycle)
{

  ngx_uint_t                      i;
  ngx_listening_t                 *ls;
  ngx_connection_t                *lc;
  ngx_pool_t                      *pool;
  ngx_http_quic_context_t         *quic_ctx;
  ngx_event_t                     *ev;
  
  
  ls = cycle->listening.elts;
  for (i = 0; i < cycle->listening.nelts; i++) {
      
    if (ls[i].handler == ngx_http_quic_handler_buf_by_quic) {
      
      lc = ls[i].connection;
      if (lc == NULL) {
        continue;
      }
            
      if (lc->data == NULL) {
        continue;
      }

      quic_ctx = lc->data;

      if (quic_ctx->chromium_server) {
        ngx_http_free_quic(quic_ctx->chromium_server);
        quic_ctx->chromium_server = NULL;
      }

      ev = &quic_ctx->ngx_quic_interval_event;
      if (ev->timer_set) {
        ngx_del_timer(ev);
      }

      quic_ctx->lc = NULL;
      
      pool = quic_ctx->pool;
      ngx_pfree(pool, quic_ctx);
      
      ngx_destroy_pool(pool);

      lc->data = NULL;
    }
    
  }

}

 
static void *
ngx_http_quic_create_srv_conf(ngx_conf_t *cf)
{
  ngx_http_quic_srv_conf_t  *qscf;

  qscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_quic_srv_conf_t));
  if (qscf == NULL) {
    return NULL;
  }

  qscf->certificates         = NGX_CONF_UNSET_PTR;
  qscf->certificate_keys     = NGX_CONF_UNSET_PTR;
  qscf->bbr                  = NGX_CONF_UNSET;
  qscf->ietf_draft           = NGX_CONF_UNSET;
  qscf->flush_interval       = NGX_CONF_UNSET_SIZE;
  qscf->idle_network_timeout = NGX_CONF_UNSET;
  qscf->stream_buffered_size = NGX_CONF_UNSET_SIZE;
  

  return qscf;
}


static char *
ngx_http_quic_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_quic_srv_conf_t *prev = parent;
  ngx_http_quic_srv_conf_t *conf = child;


  ngx_conf_merge_ptr_value(conf->certificates, prev->certificates,
                           NULL);
  ngx_conf_merge_ptr_value(conf->certificate_keys, prev->certificate_keys,
                           NULL);

  ngx_conf_merge_value(conf->bbr, prev->bbr, 0);

  ngx_conf_merge_value(conf->ietf_draft, prev->ietf_draft, 0);
  
  ngx_conf_merge_size_value(conf->flush_interval, prev->flush_interval, 40);

  ngx_conf_merge_value(conf->idle_network_timeout, prev->idle_network_timeout, -1);

  ngx_conf_merge_size_value(conf->stream_buffered_size,
                            prev->stream_buffered_size, 1024*1024);
  
  return NGX_CONF_OK;
}




// static ngx_int_t
// ngx_http_quic_check_all_location(ngx_http_location_tree_node_t *node)
// {
//   ngx_http_core_loc_conf_t        *clcf;

//   if (!node) {
//     return NGX_OK;
//   }

//   clcf = node->inclusive;
//   if (clcf) {
//     if (clcf->sendfile) {
//       return NGX_ERROR;
//     }
//   }

//   if (ngx_http_quic_check_all_location(node->tree) != NGX_OK) {
//     return NGX_ERROR;
//   }
  
//   if (ngx_http_quic_check_all_location(node->left) != NGX_OK) {
//     return NGX_ERROR;
//   }

//   return ngx_http_quic_check_all_location(node->right);
// }


static ngx_int_t
ngx_http_quic_check_and_rewrite_handler(ngx_cycle_t *cycle,
                                  ngx_listening_t *ls,
                                  ngx_http_addr_conf_t *conf)
{
  // ngx_http_core_loc_conf_t        *clcf;
  
  if (conf->quic) {
    if (conf->ssl) {
      ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
                    "gquic and ssl cannot be used together");
      return NGX_ERROR;
    }

    if (conf->http2) {
      ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
                    "gquic and http2 cannot be used together");
      return NGX_ERROR;
    }

    // clcf = ngx_http_conf_get_module_loc_conf(conf->default_server,
    //                                          ngx_http_core_module);
    // if (clcf->sendfile) {
    //   ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
    //                   "Not support sendfile, when used quic.");
    //   return NGX_ERROR;
    // }

    // if (ngx_http_quic_check_all_location(clcf->static_locations) != NGX_OK) {
    //   ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
    //                 "Not support sendfile, when used quic.");
    //   return NGX_ERROR;
    // }
    

    // rewrite ls[i]->handler
    ls->handler = ngx_http_quic_handler_buf_by_quic;
  }
  
  return NGX_OK;
}


static void
ngx_do_quic_interval(ngx_event_t *ev) {

  ngx_http_quic_context_t         *quic_ctx;

  quic_ctx = ev->data;
    
  if (ngx_quit || ngx_exiting) {
    if (quic_ctx->chromium_server) {
      ngx_http_shutdown_quic(quic_ctx->chromium_server);
      ngx_http_free_quic(quic_ctx->chromium_server);
      quic_ctx->chromium_server = NULL;
    }
    return;
  }


  if ((ngx_http_flush_cache_packets(quic_ctx->chromium_server) == NGX_AGAIN ||
       ngx_http_can_write(quic_ctx->chromium_server) == NGX_AGAIN)
      && quic_ctx->lc) {
    ngx_add_event(quic_ctx->lc->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
  }
  
  ngx_add_timer(ev, quic_ctx->flush_interval);
}


static ngx_int_t
ngx_http_variable_quic_scheme(ngx_http_request_t *r,
                 ngx_http_variable_value_t *v, uintptr_t data)
{
  if (r->connection->quic_stream) {
    v->len = sizeof("quic") - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "quic";

    return NGX_OK;
  }
  
#if (NGX_HTTP_SSL)

  if (r->connection->ssl) {
    v->len = sizeof("https") - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "https";

    return NGX_OK;
  }

  #endif

  v->len = sizeof("http") - 1;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  v->data = (u_char *) "http";

  return NGX_OK;
}

