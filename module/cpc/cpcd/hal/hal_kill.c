
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Definition of O_* constants */
#include <sys/eventfd.h>
#include <unistd.h>

#include <pthread.h>

#include "hal_kill.h"
#include "utility/logs.h"

static int kill_eventfd = -1;

int hal_kill_init(void)
{
    kill_eventfd = eventfd(0, EFD_CLOEXEC);

    ERROR_ON(kill_eventfd == -1);

    return kill_eventfd;
}

void hal_kill_signal(void)
{
    ssize_t ret;
    const uint64_t event_value = 1; //doesn't matter what it is

    if (kill_eventfd == -1)
    {
        return;
    }

    ret = write(kill_eventfd, &event_value, sizeof(event_value));
    ERROR_ON(ret != sizeof(event_value));
}

int hal_kill_join(void)
{
    void *join_value;
    int ret;

    extern pthread_t hal_thread;
    ret = pthread_join(hal_thread, &join_value);

    return ret;
}

int hal_kill_signal_and_join(void)
{
    hal_kill_signal();

    return hal_kill_join();
}
