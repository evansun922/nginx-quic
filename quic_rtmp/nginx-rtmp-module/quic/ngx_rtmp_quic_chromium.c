
/*
 * Copyright (C) sunlei
 */


#include "ngx_rtmp_quic_chromium.h"
#include "ngx_rtmp_quic_module.h"


// ? 
struct ngx_udp_connection_s {
    ngx_rbtree_node_t   node;
    ngx_connection_t   *connection;
    ngx_buf_t          *buffer;
};


static void
ngx_rtmp_process_rtmp_data(void *module_context,
                           void *nc,
                           void *quic_visitor,
                           struct sockaddr_storage* self_addr,
                           struct sockaddr_storage* peer_addr,
                           const char *data,
                           int data_len);

static void
ngx_rtmp_set_visitor_for_connection(void* ngx_connection,
                                    void* quic_visitor);


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
                            certificate_key_list,
                            ngx_rtmp_process_rtmp_data,
                            ngx_rtmp_set_visitor_for_connection,
                            ngx_quic_set_epoll_out);
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


void
ngx_rtmp_event_quic_can_sendmsg(ngx_event_t *ev)
{
  
  ngx_connection_t                *lc;
  ngx_rtmp_quic_context_t         *quic_ctx;


  lc = ev->data;
  quic_ctx = lc->data;
  
  if (ngx_rtmp_can_write(quic_ctx->chromium_server) == NGX_OK) {
    ngx_del_event(ev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
  }
}


static ssize_t
ngx_rtmp_quic_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
  ssize_t     n;
  ngx_buf_t  *b;

  if (c->quic_stream == NULL) {
    return 0;
  }

  if (c->udp == NULL || c->udp->buffer == NULL) {
    return NGX_AGAIN;
  }

  b = c->udp->buffer;
  if (b->pos == b->last) {
    return NGX_AGAIN;
  }
    
  n = ngx_min(b->last - b->pos, (ssize_t) size);
  ngx_memcpy(buf, b->pos, n);

  b->pos += n;
  if (b->pos == b->last) {
    b->pos = b->start;
    b->last = b->start;
  } else if (b->last-b->pos <= b->pos-b->start &&
             b->pos != b->start) {
    b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
    b->pos = b->start;
  }

  c->read->ready = 0;
  c->read->active = 1;

  return n;
}


static ssize_t
ngx_rtmp_quic_send(ngx_connection_t *c, u_char *buf, size_t size)
{
  if (ngx_rtmp_send_quic_packets(c->quic_stream,
                                 (char*)buf,
                                 size) == -1) {
    return NGX_ERROR;
  }
  return size;
}


static void
ngx_rtmp_quic_clean_connection(void *data)
{
  ngx_connection_t  *c = data;

  c->udp = NULL;

  if (c->quic_stream) {
    ngx_rtmp_set_nc_for_quic_visitor(c->quic_stream, NULL);
    c->quic_stream = NULL;
  }
}


static void
ngx_rtmp_process_rtmp_data(void *module_context,
                           void *nc,
                           void *quic_visitor,
                           struct sockaddr_storage* self_addr,
                           struct sockaddr_storage* peer_addr,
                           const char *data,
                           int data_len)
{
  ngx_rtmp_quic_context_t   *quic_context;
  ngx_buf_t                 *buf;
  ngx_listening_t           *ls;
  ngx_connection_t          *c, *lc;
  int                        len;
  u_char                    *p;
  
  
  quic_context = module_context;
  lc = quic_context->lc;
  ls = lc->listening;

  if (nc == NULL) {
    // first rtmp handshake
    c = ngx_create_connection_for_quic(
                         lc,
                         self_addr,
                         peer_addr,
                         ngx_rtmp_quic_recv,
                         ngx_rtmp_quic_send,
                         ngx_udp_send_chain,
                         ngx_rtmp_quic_clean_connection);

    if (c == NULL) {
      ngx_rtmp_sendfin(quic_visitor);
      return;
    }
    
    buf = ngx_create_temp_buf(c->pool, data_len*3);
    if (buf == NULL) {
      ngx_quic_close_accepted_udp_connection(c);
      ngx_rtmp_sendfin(quic_visitor);
      return;
    }
    buf->last = ngx_copy(buf->last, data, data_len);

    c->udp->buffer = buf;

  
    c->quic_stream = quic_visitor;
    ngx_rtmp_set_nc_for_quic_visitor(quic_visitor, c);


    // Forge a tcp socket for upstream, limit-rate, api of tcp
    c->fd = ngx_socket(ls->sockaddr->sa_family, SOCK_STREAM, 0);
  
    ls->handler(c);
    return;
  }

  c = nc;
  buf = c->udp->buffer;
  
  if (buf->end - buf->last >= data_len) {
    buf->last = ngx_copy(buf->last, data, data_len);
  } else {
    len = buf->last - buf->pos;
    p = ngx_palloc(c->pool, len + data_len);
    if (len) {
      ngx_copy(p, buf->pos, len);
    }
    ngx_copy(p+len, data, data_len);
    ngx_pfree(c->pool, buf->start);

    buf->start = p;
    buf->pos   = p;
    buf->last  = p + len + data_len;
    buf->end   = buf->last;
  }

  c->read->handler(c->read);
}


static void
ngx_rtmp_set_visitor_for_connection(void* ngx_connection,
                                    void* quic_visitor)
{
  ngx_connection_t  *c = ngx_connection;
  
  c->quic_stream = quic_visitor;
}





  
