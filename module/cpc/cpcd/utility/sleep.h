

#ifndef SLEEP_H
#define SLEEP_H

#include <stdint.h>

int sleep_us(uint32_t us);

static inline int sleep_ms(uint32_t ms)
{
    return sleep_us(ms * 1000);
}

int sleep_s(uint32_t s);

#endif /* SLEEP_H */
