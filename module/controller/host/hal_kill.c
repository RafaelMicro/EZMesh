#define _GNU_SOURCE             
#include <fcntl.h>          
#include <sys/eventfd.h>
#include <unistd.h>

#include <pthread.h>
#include "hal_kill.h"
#include "utility/log.h"

static int efd = -1;

int hal_kill_init(void)
{
    efd = eventfd(0, EFD_CLOEXEC);
    CHECK_ERROR(efd == -1);
    return efd;
}

void hal_kill_signal(void)
{
    ssize_t ret = 0;
    const uint64_t event_value = 1;

    if (efd == -1)
    {
        return;
    }

    ret = write(efd, &event_value, sizeof(event_value));
    CHECK_ERROR(ret != sizeof(event_value));
}

int hal_kill_join(void)
{
    void *join_value = NULL;
    int ret = 0;
    
    extern pthread_t hal_thread;
    ret = pthread_join(hal_thread, &join_value);

    return ret;
}

int hal_kill_signal_and_join(void)
{
    int ret = 0;
    const uint64_t event_value = 1;
    void *join_value = NULL;

    if (efd == -1) return -1;

    ret = (int)write(efd, &event_value, sizeof(event_value));
    CHECK_ERROR(ret != sizeof(event_value));

    extern pthread_t hal_thread;
    ret = pthread_join(hal_thread, &join_value);

    return ret;
}