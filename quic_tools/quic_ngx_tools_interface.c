
#include "quic_ngx_tools_interface.h"

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
