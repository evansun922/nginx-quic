
#include "quic_ngx_tools_interface.h"


// ? 
struct ngx_udp_connection_s {
    ngx_rbtree_node_t   node;
    ngx_connection_t   *connection;
    ngx_buf_t          *buffer;
};



static void
ngx_do_chromium_alarm(ngx_event_t *ev) {
  chromium_alarm_t *ca = (chromium_alarm_t *)ev->data;
  ca->onChromiumAlarm(ca->chromium_alarm);
}


void*
ngx_quic_CreateNgxTimer(void *module_context,
                        void *chromium_alarm,
                        OnChromiumAlarm onChromiumAlarm) {
  ngx_quic_context_t      *quic_ctx;
  chromium_alarm_t        *ca;

  quic_ctx = (ngx_quic_context_t *)module_context;
  ca       = (chromium_alarm_t *)ngx_calloc(
             sizeof(chromium_alarm_t), quic_ctx->pool->log);

  ca->chromium_alarm   = chromium_alarm;
  ca->onChromiumAlarm  = onChromiumAlarm;
  ca->ev.handler       = ngx_do_chromium_alarm;
  ca->ev.log           = quic_ctx->pool->log;
  ca->ev.data          = ca;
  
  return ca;
}


void
ngx_quic_AddNgxTimer(void *module_context,
                     void *ngx_timer,
                     int64_t delay) {
  ngx_quic_context_t      *quic_ctx;
  chromium_alarm_t        *ca;

  quic_ctx             = (ngx_quic_context_t *)module_context;
  ca                   = (chromium_alarm_t *)ngx_timer;
  ca->ev.log           = quic_ctx->pool->log;
  ngx_add_timer(&ca->ev, delay);
  ca->ev.timer_set = 1;
}


void
ngx_quic_DelNgxTimer(void *module_context, void *ngx_timer) {
  ngx_quic_context_t      *quic_ctx;
  chromium_alarm_t        *ca;

  quic_ctx = (ngx_quic_context_t *)module_context;
  ca = (chromium_alarm_t *)ngx_timer;
  if (ca->ev.timer_set == 1) {
    ngx_del_timer(&ca->ev);
  }
}


void
ngx_quic_FreeNgxTimer(void *ngx_timer)
{
  ngx_free(ngx_timer);
}


void
ngx_quic_close_accepted_udp_connection(ngx_connection_t *c)
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


ngx_connection_t *
ngx_create_connection_for_quic(ngx_connection_t *lc,
                               struct sockaddr_storage* self_addr,
                               struct sockaddr_storage* peer_addr,
                               ngx_recv_pt recv,
                               ngx_send_pt send,
                               ngx_send_chain_pt send_chain,
                               ngx_pool_cleanup_pt pool_cleanup_handler)
{

  ngx_log_t                 *log;
  socklen_t                  socklen, local_socklen;
  ngx_event_t               *rev, *wev;
  struct sockaddr           *sockaddr, *local_sockaddr;
  ngx_listening_t           *ls;
  ngx_connection_t          *c;


  ngx_pool_cleanup_t        *cln;
  ngx_udp_connection_t      *udp;
  

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
    return NULL;
  }

  //  c->shared = 1;
  c->type = SOCK_DGRAM;
  c->socklen = socklen;

#if (NGX_STAT_STUB)
  (void) ngx_atomic_fetch_add(ngx_stat_active, 1);
#endif

  c->pool = ngx_create_pool(ls->pool_size, lc->read->log);
  if (c->pool == NULL) {
    ngx_quic_close_accepted_udp_connection(c);
    return NULL;
  }

  c->sockaddr = ngx_palloc(c->pool, socklen);
  if (c->sockaddr == NULL) {
    ngx_quic_close_accepted_udp_connection(c);
    return NULL;
  }

  ngx_memcpy(c->sockaddr, sockaddr, socklen);

  log = ngx_palloc(c->pool, sizeof(ngx_log_t));
  if (log == NULL) {
    ngx_quic_close_accepted_udp_connection(c);
    return NULL;
  }

  *log = ls->log;

  c->recv = recv;
  c->send = send;
  c->send_chain = send_chain;

  c->log = log;
  c->pool->log = log;
  c->listening = ls;


  local_socklen = sizeof(struct sockaddr_storage); // ls->socklen;
  local_sockaddr = ngx_palloc(c->pool, local_socklen);
  if (local_sockaddr == NULL) {
    ngx_quic_close_accepted_udp_connection(c);
    return NULL;
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
      ngx_quic_close_accepted_udp_connection(c);
      return NULL;
    }

    c->addr_text.len = ngx_sock_ntop(c->sockaddr, c->socklen,
                                     c->addr_text.data,
                                     ls->addr_text_max_len, 0);
    if (c->addr_text.len == 0) {
      ngx_quic_close_accepted_udp_connection(c);
      return NULL;
    }
  }


  udp = ngx_pcalloc(c->pool, sizeof(ngx_udp_connection_t));
  if (udp == NULL) {
    ngx_quic_close_accepted_udp_connection(c);
    return NULL;
  }

  udp->connection = c;

  cln = ngx_pool_cleanup_add(c->pool, 0);
  if (cln == NULL) {
    ngx_quic_close_accepted_udp_connection(c);
    return NULL;
  }

  cln->data = c;
  cln->handler = pool_cleanup_handler;
  c->udp = udp;
    

  log->data = NULL;
  log->handler = NULL;

  wev->ready = 1;
  
  return c;
}


void
ngx_quic_set_epoll_out(void *module_context)
{
  ngx_quic_context_t *quic_ctx;

  quic_ctx = module_context;

  if (quic_ctx->lc->write->active) {
    return;
  }
  
  ngx_add_event(quic_ctx->lc->write, NGX_WRITE_EVENT, NGX_LEVEL_EVENT);
}

void
nginx_quic_logging_callback(uintptr_t level, const char *str)
{
  ngx_log_error(level, ngx_cycle->log, 0, "chromium_log %s", str);
}
