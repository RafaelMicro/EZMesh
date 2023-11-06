

#ifndef HAL_KILL_H
#define HAL_KILL_H

int hal_kill_init(void);

void hal_kill_signal(void);

int hal_kill_join(void);

int hal_kill_signal_and_join(void);

#endif //HAL_KILL_H
