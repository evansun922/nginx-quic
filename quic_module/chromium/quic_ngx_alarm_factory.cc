
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
                 ngx_event_(nullptr){}
  
  ~QuicNgxAlarm() override {
    if (ngx_event_) {
      ngx_handle_.del_ngx_timer(ngx_handle_.ngx_module_context,
                                 ngx_event_);
      // ::free(ngx_event_);
      ngx_event_ = nullptr;
    }
  }

  static void OnAlarm(void *chromium_alarm) {
    QuicNgxAlarm* myself = reinterpret_cast<QuicNgxAlarm*>(chromium_alarm);
    myself->Fire();
  }
  
 protected:
  void SetImpl() override {
    DCHECK(deadline().IsInitialized());
    if (ngx_event_) {
      ngx_handle_.del_ngx_timer(ngx_handle_.ngx_module_context,
                                 ngx_event_);
      // ::free(ngx_event_);
    }
    int64_t now_in_us = (clock_.Now() - QuicTime::Zero()).ToMicroseconds();
    int64_t time_offset = (deadline() - QuicTime::Zero()).ToMicroseconds();
    int64_t wait_time_in_us = time_offset - now_in_us;
    if (wait_time_in_us < 0 ) {
      wait_time_in_us = 0;
    }
    ngx_event_ = ngx_handle_.add_ngx_timer(
                       ngx_handle_.ngx_module_context,
                       this,
                       wait_time_in_us / 1000,
                       QuicNgxAlarm::OnAlarm);
  }

  void CancelImpl() override {
    DCHECK(!deadline().IsInitialized());
    if (ngx_event_) {
      ngx_handle_.del_ngx_timer(ngx_handle_.ngx_module_context,
                                 ngx_event_);
      // ::free(ngx_event_);
      ngx_event_ = nullptr;
    }
  }

  void UpdateImpl() override {
    SetImpl();
  }

 private:

  QuicNgxHandle ngx_handle_;
  void* ngx_event_; // nginx ngx_event_t
  QuicChromiumClock clock_;
};

}  // namespace

QuicNgxAlarmFactory::QuicNgxAlarmFactory(void* ngx_module_context,
                                         AddNgxTimer add_ngx_timer,
                                         DelNgxTimer del_ngx_timer) {
  ngx_handle_.ngx_module_context = ngx_module_context;
  ngx_handle_.add_ngx_timer = add_ngx_timer;
  ngx_handle_.del_ngx_timer = del_ngx_timer;
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
