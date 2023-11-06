/**
 * @file sleep.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-10-30
 *
 *
 */

#include "sleep.h"

#include <errno.h>
#include <time.h>


int sleep_us(uint32_t us)
{
    int ret;
    struct timespec ts;

    if (us < 1000000)
    {
        ts.tv_sec = 0;
        ts.tv_nsec = (long)(us * 1000);
    } else
    {
        ts.tv_sec = (time_t)(us / 1000000);
        ts.tv_nsec = (long)((us % 1000000) * 1000);
    }
    do
    {
        ret = nanosleep(&ts, &ts);
    } while (ret != 0 && errno == EINTR);
    return ret;
}

int sleep_s(uint32_t s)
{
    int ret;
    struct timespec ts;

    ts.tv_sec = (time_t)s;
    ts.tv_nsec = 0;
    do
    {
        ret = nanosleep(&ts, &ts);
    } while (ret != 0 && errno == EINTR);
    return ret;
}
