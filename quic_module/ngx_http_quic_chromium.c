
/*
 * Copyright (C) sunlei
 */

#include <sys/timerfd.h>

#include "ngx_http_quic_chromium.h"
#include "ngx_http_quic_module.h"


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
static void* ngx_http_quic_CreateNgxTimer(void *module_context,
                                          void *chromium_alarm,
                                          OnChromiumAlarm onChromiumAlarm);
static void ngx_http_quic_AddNgxTimer(void *module_context,
                                      void *ngx_timer,
                                      int64_t delay);
static void ngx_http_quic_DelNgxTimer(void *module_context, void *ngx_timer);
static void ngx_http_quic_FreeNgxTimer(void *ngx_timer);
static ngx_chain_t *ngx_quic_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
static ssize_t ngx_quic_shared_recv(ngx_connection_t *c, u_char *buf, size_t size);
static void ngx_http_quic_set_stream_for_connection(void* ngx_request, void* quic_stream);

static void ngx_http_quic_clean_connection(void *data);

static void ngx_http_quic_close_accepted_udp_connection(ngx_connection_t *c);

void*
ngx_http_quic_init_chromium(ngx_http_quic_context_t *module_context,
                            int listen_fd,
                            int port,
                            int address_family,
                            ngx_str_t *certificate,
                            ngx_str_t *certificate_key,
                            int bbr,
                            int idle_network_timeout)
{  
  return ngx_init_quic(module_context,
                       listen_fd,
                       port,
                       address_family,
                       ngx_http_quic_CreateNgxTimer,
                       ngx_http_quic_AddNgxTimer,
                       ngx_http_quic_DelNgxTimer,
                       ngx_http_quic_FreeNgxTimer,
                       ngx_http_quic_request_quic_2_ngx_in_chromium,
                       ngx_http_quic_set_stream_for_connection,
                       (char*)certificate->data,
                       (char*)certificate_key->data,
                       bbr,
                       idle_network_timeout);
}


void
ngx_event_quic_recvmsg(ngx_event_t *ev)
{

  ngx_listening_t                 *ls;
  ngx_connection_t                *lc;
  ngx_http_quic_context_t         *quic_ctx;


  if (ev->timedout) {
    // if (ngx_enable_accept_events((ngx_cycle_t *) ngx_cycle) != NGX_OK) {
    //   return;
    // }

    ev->timedout = 0;
  }

    // TODO what to do in NGX_USE_KQUEUE_EVENT
    // ecf = ngx_event_get_conf(ngx_cycle->conf_ctx, ngx_event_core_module);

    // if (!(ngx_event_flags & NGX_USE_KQUEUE_EVENT)) {
    //     ev->available = ecf->multi_accept;
    // }

  lc = ev->data;
  ls = lc->listening;
  ev->ready = 0;
  quic_ctx = lc->data;
    
  ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                 "recvmsg on %V, ready: %d", &ls->addr_text, ev->available);

  ngx_read_dispatch_packets(quic_ctx->chromium_server, lc);
}


void
ngx_event_quic_can_sendmsg(ngx_event_t *ev)
{
  
  ngx_connection_t                *lc;
  ngx_http_quic_context_t         *quic_ctx;


  lc = ev->data;
  quic_ctx = lc->data;

  if (ngx_can_write(quic_ctx->chromium_server) == NGX_OK &&
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
  ngx_set_nc_for_quic_stream(quic_stream, c);


  // Forge a tcp socket for upstream, limit-rate, api of tcp
  c->fd = ngx_socket(ls->sockaddr->sa_family, SOCK_STREAM, 0);

  ls->handler(c);
}


static void
ngx_do_chromium_alarm(ngx_event_t *ev)
{
  chromium_alarm_t *ca = ev->data;
  ca->onChromiumAlarm(ca->chromium_alarm);
}


static void*
ngx_http_quic_CreateNgxTimer(void *module_context,
                            void *chromium_alarm,
                            OnChromiumAlarm onChromiumAlarm)
{
  ngx_http_quic_context_t *quic_cxt;
  chromium_alarm_t        *ca;
  ngx_connection_t        *c;
  ngx_event_t             *rev,*wev;
  ngx_pool_t              *pool;
  ngx_log_t               *log;


  quic_cxt = module_context;
  pool     = ngx_create_pool(1024, quic_cxt->pool->log);
  if (pool == NULL) {
    ngx_log_error(NGX_LOG_ALERT, quic_cxt->pool->log, 0,
          "create timer: ngx_create_pool failed, errno is %d", errno);
    goto failed_CreateNgxTimer;
  }
  ca       = ngx_palloc(pool, sizeof(chromium_alarm_t));
  ngx_memzero(ca, sizeof(chromium_alarm_t));
  c        = &ca->c;
  c->read  = ngx_palloc(pool, sizeof(ngx_event_t));
  c->write = ngx_palloc(pool, sizeof(ngx_event_t));
  rev      = c->read;
  wev      = c->write;
  ngx_memzero(rev, sizeof(ngx_event_t));
  ngx_memzero(wev, sizeof(ngx_event_t));

  log       = ngx_palloc(pool, sizeof(ngx_log_t));
  *log      = *quic_cxt->pool->log;
  c->pool   = pool;
  c->log    = log;
  pool->log = log;

  ca->chromium_alarm   = chromium_alarm;
  ca->onChromiumAlarm  = onChromiumAlarm;
  c->data              = ca;
  rev->handler         = ngx_do_chromium_alarm;
  rev->log             = c->log;
  rev->data            = ca;
  wev->log             = c->log;

  c->fd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (c->fd == -1) {
    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
          "create timer: timerfd_create failed, errno is %d", errno);
    goto failed_CreateNgxTimer;
  }
  
  struct itimerspec its;
  ngx_memzero(&its, sizeof(struct itimerspec));
  if (timerfd_settime(c->fd, 0, &its, NULL) == -1) {
    ngx_log_error(NGX_LOG_ALERT, c->log, 0,
          "create timer: timerfd_settime failed, errno is %d", errno);
    close(c->fd);
    goto failed_CreateNgxTimer;
  }

  ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT);
  
  return ca;

 failed_CreateNgxTimer:

  if (pool) {
    ngx_destroy_pool(pool);
  }
  return NULL;
}


static void
ngx_http_quic_AddNgxTimer(void *module_context,
                          void *ngx_timer,
                          int64_t delay)
{
  ngx_http_quic_context_t *quic_cxt;
  chromium_alarm_t        *ca;
  
  quic_cxt             = module_context;
  ca                   = ngx_timer;

  struct itimerspec its;
  its.it_value.tv_sec     = delay/1000000000;
  its.it_value.tv_nsec    = delay%1000000000;
  its.it_interval.tv_sec  = 0;
  its.it_interval.tv_nsec = 0;
  
  if (timerfd_settime(ca->c.fd, 0, &its, NULL) == -1) {
    ngx_log_error(NGX_LOG_ALERT, ca->c.log, 0,
          "add timer: timerfd_settime failed, errno is %d", errno);
  }
}


static void
ngx_http_quic_DelNgxTimer(void *module_context, void *ngx_timer)
{
  ngx_http_quic_context_t *quic_cxt;
  chromium_alarm_t        *ca;
  
  quic_cxt             = module_context;
  ca                   = ngx_timer;

  struct itimerspec its;
  ngx_memzero(&its, sizeof(struct itimerspec));
  
  if (timerfd_settime(ca->c.fd, 0, &its, NULL) == -1) {
    ngx_log_error(NGX_LOG_ALERT, ca->c.log, 0,
          "del timer: timerfd_settime failed, errno is %d", errno);
  }
}


static void
ngx_http_quic_FreeNgxTimer(void *ngx_timer)
{
  chromium_alarm_t        *ca;
  ngx_connection_t        *c;


  ca = ngx_timer;
  c  = &ca->c;
  
  if (c->fd > 0) {
    close(c->fd);
  }

  if (c->pool) {
    ngx_destroy_pool(c->pool);
  }
}


#define NGX_SENDFILE_MAXSIZE  2147483647L


static ngx_chain_t *
ngx_quic_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
  off_t                    send;
  size_t                   size;
  ngx_event_t              *wev;


  wev = c->write;

  if (!wev->ready) {
    return in;
  }

  /* the maximum limit size is 2G-1 - the page size */

  if (limit == 0 || limit > (off_t) (NGX_SENDFILE_MAXSIZE - ngx_pagesize)) {
    limit = NGX_SENDFILE_MAXSIZE - ngx_pagesize;
  }

  send = 0;
  
  for ( /* void */ ; in; in = in->next) {

    if (ngx_buf_special(in->buf)) {
      continue;
    }

    if (in->buf->in_file) {
      ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                    "quic send not support file-fd");
      return NGX_CHAIN_ERROR;
    }

    if (!ngx_buf_in_memory(in->buf)) {
      ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                    "bad buf in output chain "
                    "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                    in->buf->temporary,
                    in->buf->recycled,
                    in->buf->in_file,
                    in->buf->start,
                    in->buf->pos,
                    in->buf->last,
                    in->buf->file,
                    in->buf->file_pos,
                    in->buf->file_last);

      ngx_debug_point();

      return NGX_CHAIN_ERROR;
    }

    size = in->buf->last - in->buf->pos;

    if ((off_t)size > limit - send) {
      size = limit - send;
    }

    if (ngx_send_quic_packets(c->quic_stream,
                              (const char*)in->buf->pos, size) == -1) {
      ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                    "quic send failed in ngx_http_quic_chromium");
      return NGX_CHAIN_ERROR;
    }
    
    c->sent += size;
    send += size;
    in->buf->pos = in->buf->pos + size;

    if (send >= limit) {
      break;
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
    ngx_set_nc_for_quic_stream(c->quic_stream, NULL);
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



