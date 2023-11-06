/**
 * @file main.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-10-27
 *
 * @copyright Copyright (c) 2023
 *
 */
#define _GNU_SOURCE

#include <pthread.h>

#include <stdbool.h>
#include <stddef.h>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/time.h>
#include <errno.h>

#include "version.h"
#include "utility/config.h"
#include "utility/logs.h"
#include "utility/sleep.h"
#include "hal/hal_kill.h"
#include "primary/primary_cpcd.h"
#include "primary/epoll_port/epoll_port.h"

#include "hal/hal_uart.h"

//=============================================================================
//                  Constant Definition
//=============================================================================

//=============================================================================
//                  Macro Definition
//=============================================================================

//=============================================================================
//                  Structure Definition
//=============================================================================

//=============================================================================
//                  Global Data Definition
//=============================================================================
static pthread_t daemon_thread = 0;
pthread_t hal_thread = 0;
pthread_t primary_cpcd_thread = 0;

static int daemon_crash_eventfd;
static int daemon_graceful_exit_eventfd;
static int daemon_graceful_exit_signalfd;
static int daemon_wait_crash_or_graceful_exit_epoll;

static int fd_socket_hal_cpcd;
static int fd_socket_hal_cpcd_notify;

static int exit_status = EXIT_SUCCESS;

char **argv_g = 0;
int argc_g = 0;

//=============================================================================
//                  Private Function Definition
//=============================================================================

void main_wait_crash_or_graceful_exit(void);

int main(int argc, char *argv[])
{
    struct epoll_event event = { .events = EPOLLIN };
    sigset_t mask;
    int ret;

    argc_g = argc;
    argv_g = argv;

    daemon_thread = pthread_self();
    pthread_setname_np(daemon_thread, "cpcd");

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);

    ret = sigprocmask(SIG_BLOCK, &mask, NULL);
    ERROR_ON(ret == -1);

    daemon_wait_crash_or_graceful_exit_epoll = epoll_create1(EPOLL_CLOEXEC);
    ERROR_SYSCALL_ON(daemon_wait_crash_or_graceful_exit_epoll < 0);

    daemon_crash_eventfd = eventfd(0, EFD_CLOEXEC);
    ERROR_ON(daemon_crash_eventfd == -1);

    ret = epoll_ctl(daemon_wait_crash_or_graceful_exit_epoll,
                    EPOLL_CTL_ADD,
                    daemon_crash_eventfd,
                    &event);
    ERROR_SYSCALL_ON(ret < 0);

    daemon_graceful_exit_eventfd = eventfd(0, EFD_CLOEXEC);
    ERROR_ON(daemon_graceful_exit_eventfd == -1);

    ret = epoll_ctl(daemon_wait_crash_or_graceful_exit_epoll,
                    EPOLL_CTL_ADD,
                    daemon_graceful_exit_eventfd,
                    &event);
    ERROR_SYSCALL_ON(ret < 0);

    daemon_graceful_exit_signalfd = signalfd(-1, &mask, SFD_CLOEXEC);
    ERROR_ON(daemon_graceful_exit_signalfd == -1);

    ret = epoll_ctl(daemon_wait_crash_or_graceful_exit_epoll,
                    EPOLL_CTL_ADD,
                    daemon_graceful_exit_signalfd,
                    &event);
    ERROR_SYSCALL_ON(ret < 0);

    epoll_port_init();

    logging_init();

    PRINT_INFO("[Daemon v%s] [Library v%d] [Protocol v%d]", PROJECT_VER, LIBRARY_API_VERSION, PROTOCOL_VERSION);
    PRINT_INFO("Git commit: %s / branch: %s", GIT_SHA1, GIT_REFSPEC);
    PRINT_INFO("Sources hash: %s", SOURCES_HASH);
    config_init(argc, argv);

    PRINT_INFO("Daemon Starting ... ");


    // Init HAL
    hal_thread = hal_uart_init(&fd_socket_hal_cpcd,
                               &fd_socket_hal_cpcd_notify,
                               config.uart_file, config.uart_baudrate,
                               config.uart_hardflow);

    primary_cpcd_thread = primary_cpcd_init(fd_socket_hal_cpcd, fd_socket_hal_cpcd_notify);

    main_wait_crash_or_graceful_exit();

    return 0;
}

static void exit_daemon(void)
{
    hal_kill_signal();
    pthread_join(hal_thread, NULL);

    primary_cpcd_kill_signal();
    pthread_join(primary_cpcd_thread, NULL);

    PRINT_INFO("Daemon exit : status %s", (exit_status == 0) ? "EXIT_SUCCESS" : "EXIT_FAILURE");
    logging_kill();

    exit(exit_status);
}

void main_wait_crash_or_graceful_exit(void)
{
    int event_count;
    struct epoll_event events;

    do
    {
        event_count = epoll_wait(daemon_wait_crash_or_graceful_exit_epoll, &events, 1, -1);
    } while (errno == EINTR && event_count < 0);

    ERROR_SYSCALL_ON(event_count <= 0);

    exit_daemon();
}

void signal_crash(void)
{
    uint64_t event_value;

    exit_status = EXIT_FAILURE;

    sleep_s(1);

    if (pthread_self() == daemon_thread)
    {
        exit_daemon();
    } else
    {
        write(daemon_crash_eventfd, &event_value, sizeof(event_value));
    }

    pthread_exit(0);
}