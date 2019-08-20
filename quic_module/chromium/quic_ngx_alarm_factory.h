
/*
 * Copyright (C) sunlei
 */

#ifndef QUICHE_QUIC_CORE_QUIC_NGX_ALARM_FACTORY_H_
#define QUICHE_QUIC_CORE_QUIC_NGX_ALARM_FACTORY_H_

#include "net/third_party/quiche/src/quic/core/quic_alarm.h"
#include "net/third_party/quiche/src/quic/core/quic_alarm_factory.h"
#include "net/third_party/quiche/src/quic/core/quic_one_block_arena.h"
#include "quic_ngx_interface.h"

namespace quic {

struct QuicNgxHandle {
  void* ngx_module_context;
  CreateNgxTimer create_ngx_timer;
  AddNgxTimer add_ngx_timer;
  DelNgxTimer del_ngx_timer;
  FreeNgxTimer free_ngx_timer;
};
  
// Creates alarms that use the supplied Nginx for timing and firing.
class QuicNgxAlarmFactory : public QuicAlarmFactory {
 public:
  explicit QuicNgxAlarmFactory(void* ngx_module_context,
                               CreateNgxTimer create_ngx_timer,
                               AddNgxTimer add_ngx_timer,
                               DelNgxTimer del_ngx_timer,
                               FreeNgxTimer free_ngx_timer);
  QuicNgxAlarmFactory(const QuicNgxAlarmFactory&) = delete;
  QuicNgxAlarmFactory& operator=(const QuicNgxAlarmFactory&) = delete;
  ~QuicNgxAlarmFactory() override;

  // QuicAlarmFactory interface.
  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;
  QuicArenaScopedPtr<QuicAlarm> CreateAlarm(
      QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
      QuicConnectionArena* arena) override;

 private:
  QuicNgxHandle ngx_handle_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_NGX_ALARM_FACTORY_H_
