
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
static void ngx_http_quic_clean_connection(void *data);


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
                       ngx_quic_set_epoll_out,
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
ngx_http_event_quic_can_sendmsg(ngx_event_t *ev)
{
  
  ngx_connection_t                *lc;
  ngx_http_quic_context_t         *quic_ctx;


  lc = ev->data;
  quic_ctx = lc->data;
  
  if (ngx_http_can_write(quic_ctx->chromium_server) == NGX_OK) {
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
  ngx_listening_t           *ls;
  ngx_connection_t          *c, *lc;


  lc = ngx_connection;
  ls = lc->listening;
  c = ngx_create_connection_for_quic(lc,
                                     self_addr,
                                     peer_addr,
                                     ngx_quic_shared_recv,
                                     ngx_udp_send,
                                     ngx_quic_send_chain,
                                     ngx_http_quic_clean_connection);

  if (c == NULL) {
    return;
  }
    
  // quic me
  buf = ngx_create_temp_buf(c->pool, header_len + body_len);
  if (buf == NULL) {
    ngx_quic_close_accepted_udp_connection(c);
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
ngx_http_quic_clean_connection(void *data)
{
  ngx_connection_t  *c = data;

  c->udp = NULL;

  if (c->quic_stream) {
    ngx_http_set_nc_for_quic_stream(c->quic_stream, NULL);
    c->quic_stream = NULL;
  }
}





