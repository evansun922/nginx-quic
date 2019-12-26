
/*
 * Copyright (C) sunlei
 */


#include "ngx_http_quic_chromium.h"


// ? 
struct ngx_udp_connection_s {
    ngx_rbtree_node_t   node;
    ngx_connection_t   *connection;
    ngx_buf_t          *buffer;
};

static void ngx_http_quic_request_quic_2_ngx_in_chromium(void* ngx_connection,
                                             void *quic_stream,
                                             struct sockaddr_storage* self_addr,
                                             struct sockaddr_storage* peer_addr,
                                             const char *header,
                                             int header_len,
                                             const char *body,
                                             int body_len);
static ngx_chain_t *ngx_quic_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
static ssize_t ngx_quic_shared_recv(ngx_connection_t *c, u_char *buf, size_t size);
static void ngx_http_quic_set_stream_for_connection(void* ngx_request, void* quic_stream);
static void ngx_http_set_epoll_out(void *module_context);
static void ngx_http_quic_clean_connection(void *data);
static void ngx_http_quic_close_accepted_udp_connection(ngx_connection_t *c);

void*
ngx_http_quic_init_chromium(ngx_http_quic_context_t *module_context,
                            int listen_fd,
                            int port,
                            int address_family,
                            char **certificate_list,
                            char **certificate_key_list,
                            int bbr,
                            int ietf_draft,
                            int idle_network_timeout)
{  
  return ngx_http_init_quic(module_context,
                       listen_fd,
                       port,
                       address_family,
                       ngx_quic_CreateNgxTimer,
                       ngx_quic_AddNgxTimer,
                       ngx_quic_DelNgxTimer,
                       ngx_quic_FreeNgxTimer,
                       ngx_http_quic_request_quic_2_ngx_in_chromium,
                       ngx_http_quic_set_stream_for_connection,
                       ngx_http_set_epoll_out,
                       certificate_list,
                       certificate_key_list,
                       bbr,
                       ietf_draft,
                       idle_network_timeout);
}


void
ngx_http_event_quic_recvmsg(ngx_event_t *ev)
{

  ngx_listening_t                 *ls;
  ngx_connection_t                *lc;
  ngx_http_quic_context_t         *quic_ctx;


  if (ev->timedout) {
    ev->timedout = 0;
  }

  lc = ev->data;
  ls = lc->listening;
  ev->ready = 0;
  quic_ctx = lc->data;
    
  ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                 "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

  ngx_http_read_dispatch_packets(quic_ctx->chromium_server, lc);
}


void
ngx_event_quic_can_sendmsg(ngx_event_t *ev)
{
  
  ngx_connection_t                *lc;
  ngx_http_quic_context_t         *quic_ctx;


  lc = ev->data;
  quic_ctx = lc->data;
  
  if (ngx_http_can_write(quic_ctx->chromium_server) == NGX_OK &&
      lc->write->active) {
    ngx_del_event(ev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
  }
}


void
ngx_http_quic_handler_buf_by_quic(ngx_connection_t *c)
{
  ngx_http_init_connection(c);
}

static void
ngx_http_quic_request_quic_2_ngx_in_chromium(void* ngx_connection,
                                             void *quic_stream,
                                             struct sockaddr_storage* self_addr,
                                             struct sockaddr_storage* peer_addr,
                                             const char *header,
                                             int header_len,
                                             const char *body,
                                             int body_len) {
  
  ngx_buf_t                 *buf;
  ngx_log_t                 *log;
  socklen_t                 socklen, local_socklen;
  ngx_event_t               *rev, *wev;
  struct sockaddr           *sockaddr, *local_sockaddr;
  ngx_listening_t           *ls;
  ngx_connection_t          *c, *lc;


  ngx_pool_cleanup_t        *cln;
  ngx_udp_connection_t      *udp;
  

  lc = ngx_connection;
  ls = lc->listening;

  socklen = sizeof(struct sockaddr_storage);
  sockaddr = (struct sockaddr *)peer_addr;


#if (NGX_STAT_STUB)
  (void) ngx_atomic_fetch_add(ngx_stat_accepted, 1);
#endif

  ngx_accept_disabled = ngx_cycle->connection_n / 8
    - ngx_cycle->free_connection_n;

  c = ngx_get_connection(lc->fd, lc->read->log);
  if (c == NULL) {
    return;
  }

  //  c->shared = 1;
  c->type = SOCK_DGRAM;
  c->socklen = socklen;

#if (NGX_STAT_STUB)
  (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

  c->pool = ngx_create_pool(ls->pool_size, lc->read->log);
  if (c->pool == NULL) {
    ngx_http_quic_close_accepted_udp_connection(c);
    return;
  }

  c->sockaddr = ngx_palloc(c->pool, socklen);
  if (c->sockaddr == NULL) {
    ngx_http_quic_close_accepted_udp_connection(c);
    return;
  }

  ngx_memcpy(c->sockaddr, sockaddr, socklen);

  log = ngx_palloc(c->pool, sizeof(ngx_log_t));
  if (log == NULL) {
    ngx_http_quic_close_accepted_udp_connection(c);
    return;
  }

  *log = ls->log;

  c->recv = ngx_quic_shared_recv;
  c->send = ngx_udp_send;
  c->send_chain = ngx_quic_send_chain;

  c->log = log;
  c->pool->log = log;
  c->listening = ls;


  local_socklen = sizeof(struct sockaddr_storage); // ls->socklen;
  local_sockaddr = ngx_palloc(c->pool, local_socklen);
  if (local_sockaddr == NULL) {
    ngx_http_quic_close_accepted_udp_connection(c);
    return;
  }

  // ngx_memcpy(local_sockaddr, ls->sockaddr, local_socklen);
  ngx_memcpy(local_sockaddr, (struct sockaddr *)self_addr, local_socklen);
    

  c->local_sockaddr = local_sockaddr;
  c->local_socklen = local_socklen;

    
  rev = c->read;
  wev = c->write;


  rev->log = log;
  wev->log = log;

  /*
   * TODO: MT: - ngx_atomic_fetch_add()
   *             or protection by critical section or light mutex
   *
   * TODO: MP: - allocated in a shared memory
   *           - ngx_atomic_fetch_add()
   *             or protection by critical section or light mutex
   */

  c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

#if (NGX_STAT_STUB)
  (void) ngx_atomic_fetch_add(ngx_stat_handled, 1);
#endif

  if (ls->addr_ntop) {
    c->addr_text.data = ngx_pnalloc(c->pool, ls->addr_text_max_len);
    if (c->addr_text.data == NULL) {
      ngx_http_quic_close_accepted_udp_connection(c);
      return;
    }

    c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                     c->addr_text.data,
                                     ls->addr_text_max_len, 0);
    if (c->addr_text.len == 0) {
      ngx_http_quic_close_accepted_udp_connection(c);
      return;
    }
  }


  udp = ngx_pcalloc(c->pool, sizeof(ngx_udp_connection_t));
  if (udp == NULL) {
    ngx_http_quic_close_accepted_udp_connection(c);
    return;
  }

  udp->connection = c;

  cln = ngx_pool_cleanup_add(c->pool, 0);
  if (cln == NULL) {
    ngx_http_quic_close_accepted_udp_connection(c);
    return;
  }

  cln->data = c;
  cln->handler = ngx_http_quic_clean_connection;
  c->udp = udp;
    

  log->data = NULL;
  log->handler = NULL;

  
  // quic me
  buf = ngx_create_temp_buf(c->pool, header_len + body_len);
  if (buf == NULL) {
    ngx_http_quic_close_accepted_udp_connection(c);
    return;
  }
  buf->last = ngx_copy(buf->last, header, header_len);
  if (body_len) {
    buf->last = ngx_copy(buf->last, body, body_len);
  }

  c->udp->buffer = buf;
  c->buffer = buf;
  
  c->quic_stream = quic_stream;
  ngx_http_set_nc_for_quic_stream(quic_stream, c);


  // Forge a tcp socket for upstream, limit-rate, api of tcp
  c->fd = ngx_socket(ls->sockaddr->sa_family, SOCK_STREAM, 0);

  wev->ready = 1;
  
  ls->handler(c);
}


#define NGX_SENDFILE_MAXSIZE  2147483647L


static ngx_chain_t *
ngx_quic_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
  off_t                    send, old_limit;
  size_t                   size;
  ngx_event_t             *wev;
  u_char                  *buf;
  ssize_t                  n;
  ngx_connection_t        *lc;
  ngx_http_quic_context_t *quic_ctx;
  size_t                  stream_buffered_size;

  if (!c->quic_stream) {
    return NGX_CHAIN_ERROR;
  }

  wev = c->write;

  if (!wev->ready) {
    return in;
  }

  old_limit = limit;
  lc = c->listening->connection;
  quic_ctx = lc->data;

  stream_buffered_size = ngx_http_stream_buffered_size(c->quic_stream);
  if (stream_buffered_size >= quic_ctx->stream_buffered_size) {
    if (old_limit == 0 ) {
      c->write->delayed = 1;
      ngx_add_timer(c->write, 1);
    }
    return in;
  }

  stream_buffered_size = quic_ctx->stream_buffered_size - stream_buffered_size;
  
  if (limit == 0 || limit > (off_t)stream_buffered_size) {
    limit = stream_buffered_size;
  }

  send = 0;
  
  for ( /* void */ ; in; in = in->next) {

    if (ngx_buf_special(in->buf)) {
      continue;
    }

    if (in->buf->in_file) {
      
      size = in->buf->file_last - in->buf->file_pos;

      if (!size) {
        ngx_debug_point();
        return NGX_CHAIN_ERROR;
      }

      if ((off_t)size > limit - send) {
        size = limit - send;
      }

      buf = ngx_calloc(size, c->log);
      if (!buf) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "calloc memory failed in ngx_http_quic_chromium");
        return NGX_CHAIN_ERROR;
      }

      n = ngx_read_file(in->buf->file, buf, size, in->buf->file_pos);
      if (n == NGX_ERROR) {
        ngx_free(buf);
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "read file failed in ngx_http_quic_chromium, errno is %d", errno);
        return NGX_CHAIN_ERROR;
      }

      if (ngx_http_send_quic_packets(c->quic_stream,
                                (const char*)buf, n) == -1) {
        ngx_free(buf);
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "quic send failed in ngx_http_quic_chromium");
        return NGX_CHAIN_ERROR;
      }

      ngx_free(buf);

      size = n;
      in->buf->file_pos += size;
            
    } else {

      size = in->buf->last - in->buf->pos;

      if (!size) {
        ngx_debug_point();
        return NGX_CHAIN_ERROR;
      }
      
      if ((off_t)size > limit - send) {
        size = limit - send;
      }

      if (ngx_http_send_quic_packets(c->quic_stream,
                                (const char*)in->buf->pos, size) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "quic send failed in ngx_http_quic_chromium");
        return NGX_CHAIN_ERROR;
      }
      
      in->buf->pos = in->buf->pos + size;
    }
    
    c->sent += size;
    send += size;

    if (send >= limit) {
      if (old_limit == 0 ) {
        c->write->delayed = 1;
        ngx_add_timer(c->write, 1);
      }
      break;
    }
  }

  if (in) {
    if (in->buf->in_file &&
        in->buf->file_last == in->buf->file_pos) {
      return in->next;
    }

    if (ngx_buf_in_memory(in->buf) &&
        in->buf->last == in->buf->pos) {
      return in->next;
    }
  }

  return in;
}


static ssize_t
ngx_quic_shared_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t     n;
    ngx_buf_t  *b;

    if (c->udp == NULL || c->udp->buffer == NULL) {
        return NGX_AGAIN;
    }

    b = c->udp->buffer;

    if (buf == b->last) {
      // myself
      n = b->last - b->pos;
      b->last = b->pos;
    } else {
    
      n = ngx_min(b->last - b->pos, (ssize_t) size);

      ngx_memcpy(buf, b->pos, n);
    }

    c->udp->buffer = NULL;

    c->read->ready = 0;
    c->read->active = 1;

    return n;
}


static void
ngx_http_quic_set_stream_for_connection(void* ngx_connection,
                                        void* quic_stream)
{
  ngx_connection_t  *c = ngx_connection;
  
  c->quic_stream = quic_stream;
}

static void
ngx_http_set_epoll_out(void *module_context)
{
  ngx_http_quic_context_t *quic_ctx;

  quic_ctx = module_context;
  ngx_add_event(quic_ctx->lc->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
}


static void
ngx_http_quic_clean_connection(void *data)
{
  ngx_connection_t  *c = data;

  c->udp = NULL;

  if (c->quic_stream) {
    ngx_http_set_nc_for_quic_stream(c->quic_stream, NULL);
    c->quic_stream = NULL;
  }
}


static void
ngx_http_quic_close_accepted_udp_connection(ngx_connection_t *c)
{
  ngx_free_connection(c);

  c->fd = (ngx_socket_t) -1;

  if (c->pool) {
    ngx_destroy_pool(c->pool);
  }

#if (NGX_STAT_STUB)
  (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
  #endif
}



