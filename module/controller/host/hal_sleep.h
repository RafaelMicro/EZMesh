#ifndef HAL_SLEEP_H
#define HAL_SLEEP_H

#include <stdint.h>

int hal_sleep_ms(uint32_t ms);
int hal_sleep_us(uint32_t us);
int hal_sleep_s(uint32_t s);

#endif
