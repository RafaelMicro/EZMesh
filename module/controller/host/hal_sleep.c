/**
 * @file sleep.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-10-30
 *
 *
 */

#include "hal_sleep.h"
#include <errno.h>
#include <time.h>

int hal_sleep_ms(uint32_t ms)
{
    int val = 0;
    struct timespec t = {0};

    if (ms < 1000)
    {
        t.tv_sec = 0;
        t.tv_nsec = (long)(ms * 1000000);
    } 
    else
    {
        t.tv_sec = (time_t)(ms / 1000);
        t.tv_nsec = (long)((ms % 1000) * 1000000);
    }

    do
    {
        val = nanosleep(&t, &t);
    } while (val != 0 && errno == EINTR);

    return val;
}

int hal_sleep_us(uint32_t us)
{
    int val = 0;
    struct timespec t = {0};

    if (us < 1000000)
    {
        t.tv_sec = 0;
        t.tv_nsec = (long)(us * 1000);
    } 
    else
    {
        t.tv_sec = (time_t)(us / 1000000);
        t.tv_nsec = (long)((us % 1000000) * 1000);
    }

    do
    {
        val = nanosleep(&t, &t);
    } while (val != 0 && errno == EINTR);

    return val;
}

int hal_sleep_s(uint32_t s)
{
    int val = 0;
    struct timespec t = {0};

    t.tv_sec = (time_t)s;
    t.tv_nsec = 0;

    do
    {
        val = nanosleep(&t, &t);
    } while (val != 0 && errno == EINTR);

    return val;
}
