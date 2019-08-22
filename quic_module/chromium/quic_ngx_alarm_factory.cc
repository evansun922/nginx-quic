
/*
 * Copyright (C) sunlei
 */

#include <type_traits>
#include "quic_ngx_alarm_factory.h"
#include "net/third_party/quiche/src/quic/core/quic_arena_scoped_ptr.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"


namespace quic {
namespace {

class QuicNgxAlarm : public QuicAlarm {
 public:
  QuicNgxAlarm(QuicNgxHandle* ngx_handle,
               QuicArenaScopedPtr<QuicAlarm::Delegate> delegate)
               : QuicAlarm(std::move(delegate)),
                 ngx_handle_(*ngx_handle),
                 ngx_timer_(nullptr){}
  
  ~QuicNgxAlarm() override {
    if (ngx_timer_) {
      ngx_handle_.del_ngx_timer(ngx_handle_.ngx_module_context,
                                 ngx_timer_);
      ngx_handle_.free_ngx_timer(ngx_timer_);
      ngx_timer_ = nullptr;
    }
  }

  static void OnAlarm(void *chromium_alarm) {
    QuicNgxAlarm* myself = reinterpret_cast<QuicNgxAlarm*>(chromium_alarm);
    myself->Fire();
  }
  
 protected:
  void SetImpl() override {
    DCHECK(deadline().IsInitialized());
    if (ngx_timer_ == nullptr) {
      ngx_timer_ = ngx_handle_.create_ngx_timer(ngx_handle_.ngx_module_context,
                                                this,
                                                QuicNgxAlarm::OnAlarm);
      if (ngx_timer_ == nullptr) {
        return;
      }
    } else {
      ngx_handle_.del_ngx_timer(ngx_handle_.ngx_module_context,
                                ngx_timer_);
    }
    int64_t now_in_us = (clock_.Now() - QuicTime::Zero()).ToMicroseconds();
    int64_t time_offset = (deadline() - QuicTime::Zero()).ToMicroseconds();
    int64_t wait_time_in_us = time_offset - now_in_us;
    if (wait_time_in_us < 0 ) {
      wait_time_in_us = 1;
    }
    ngx_handle_.add_ngx_timer(ngx_handle_.ngx_module_context,
                              ngx_timer_,
                              wait_time_in_us * 1000);
  }

  void CancelImpl() override {
    DCHECK(!deadline().IsInitialized());
    if (ngx_timer_) {
      ngx_handle_.del_ngx_timer(ngx_handle_.ngx_module_context,
                                 ngx_timer_);
    }
  }

  void UpdateImpl() override {
    SetImpl();
  }

 private:

  QuicNgxHandle ngx_handle_;
  void* ngx_timer_; // nginx ngx_event_t
  QuicChromiumClock clock_;
};

}  // namespace

QuicNgxAlarmFactory::QuicNgxAlarmFactory(void* ngx_module_context,
                                         CreateNgxTimer create_ngx_timer,
                                         AddNgxTimer add_ngx_timer,
                                         DelNgxTimer del_ngx_timer,
                                         FreeNgxTimer free_ngx_timer) {
  ngx_handle_.ngx_module_context = ngx_module_context;
  ngx_handle_.create_ngx_timer = create_ngx_timer;
  ngx_handle_.add_ngx_timer = add_ngx_timer;
  ngx_handle_.del_ngx_timer = del_ngx_timer;
  ngx_handle_.free_ngx_timer = free_ngx_timer;
}

QuicNgxAlarmFactory::~QuicNgxAlarmFactory() = default;

QuicAlarm* QuicNgxAlarmFactory::CreateAlarm(QuicAlarm::Delegate* delegate) {
  return new QuicNgxAlarm(&ngx_handle_,
                          QuicArenaScopedPtr<QuicAlarm::Delegate>(delegate));
}

QuicArenaScopedPtr<QuicAlarm> QuicNgxAlarmFactory::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  if (arena != nullptr) {
    return arena->New<QuicNgxAlarm>(&ngx_handle_, std::move(delegate));
  }
  return QuicArenaScopedPtr<QuicAlarm>(
      new QuicNgxAlarm(&ngx_handle_, std::move(delegate)));
}

}  // namespace quic
