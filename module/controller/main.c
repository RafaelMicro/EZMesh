#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "host/hal_kill.h"
#include "host/hal_epoll.h"
#include "daemon/controller.h"
#include "utility/config.h"
#include "utility/log.h"
#include "host/hal_sleep.h"
#include "version.h"
#include "host/hal_uart.h"

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

typedef struct {
  pthread_t thread;
  sigset_t mask;
  int crash_event_fd;
  int crash_signal_fd;
  int graceful_exit_fd;
  int crash_epoll;
  int socket;
  int socket_notify;
} ez_daemon_t;

static ez_daemon_t ez_daemon;

pthread_t hal_thread = 0;
pthread_t primary_cpcd_thread = 0;

static int exit_status = EXIT_SUCCESS;

char **argv_g = 0;
int argc_g = 0;

//=============================================================================
//                  Private Function Definition
//=============================================================================

void main_wait_crash_or_graceful_exit(void);

int main(int argc, char *argv[]) {
  struct epoll_event event = {.events = EPOLLIN};

  argc_g = argc;
  argv_g = argv;

  ez_daemon.thread = pthread_self();
  pthread_setname_np(ez_daemon.thread, "ezmesh");

  sigemptyset(&ez_daemon.mask);
  sigaddset(&ez_daemon.mask, SIGINT);
  sigaddset(&ez_daemon.mask, SIGTERM);
  sigaddset(&ez_daemon.mask, SIGQUIT);

  CHECK_ERROR(sigprocmask(SIG_BLOCK, &ez_daemon.mask, NULL) == -1);

  ez_daemon.crash_epoll = epoll_create1(EPOLL_CLOEXEC);
  CHECK_ERROR(ez_daemon.crash_epoll < 0);

  ez_daemon.crash_event_fd = eventfd(0, EFD_CLOEXEC);
  CHECK_ERROR(ez_daemon.crash_event_fd == -1);

  CHECK_ERROR(epoll_ctl(ez_daemon.crash_epoll, EPOLL_CTL_ADD, ez_daemon.crash_event_fd, &event) < 0);

  ez_daemon.graceful_exit_fd = eventfd(0, EFD_CLOEXEC);
  CHECK_ERROR(ez_daemon.graceful_exit_fd == -1);

  CHECK_ERROR(epoll_ctl(ez_daemon.crash_epoll, EPOLL_CTL_ADD, ez_daemon.graceful_exit_fd, &event) < 0);

  ez_daemon.crash_signal_fd = signalfd(-1, &ez_daemon.mask, SFD_CLOEXEC);
  CHECK_ERROR(ez_daemon.crash_signal_fd == -1);

  CHECK_ERROR(epoll_ctl(ez_daemon.crash_epoll, EPOLL_CTL_ADD, ez_daemon.crash_signal_fd, &event) < 0);
  hal_epoll_init();

  log_info("[Daemon v%s] [Library v%d] [Protocol v%d]", PROJECT_VER,
           LIBRARY_API_VERSION, PROTOCOL_VERSION);
  log_info("Git commit: %s / branch: %s", GIT_SHA1, GIT_REFSPEC);
  log_info("Sources hash: %s", SOURCES_HASH);
  handle_cli_arg(argc, argv);

  log_info("Daemon Starting ... ");
  hal_thread = hal_uart_init(&ez_daemon.socket, &ez_daemon.socket_notify,
                             config.ep_hw.port, config.ep_hw.baudrate,
                             config.ep_hw.flowcontrol);

  primary_cpcd_thread = controller_init(ez_daemon.socket, ez_daemon.socket_notify);
  main_wait_crash_or_graceful_exit();
  return 0;
}

static void exit_daemon(void) {
  hal_kill_signal_and_join();
  ini_deinit();
  pthread_join(hal_thread, NULL);
  controller_kill_signal();
  pthread_join(primary_cpcd_thread, NULL);
  controller_deinit_signal();
  log_info("Daemon exit : status %s", (exit_status == 0) ? "EXIT_SUCCESS" : "EXIT_FAILURE");
  exit(exit_status);
}

void main_wait_crash_or_graceful_exit(void) {
  int event_count;
  struct epoll_event events;

  do {
    event_count = epoll_wait(ez_daemon.crash_epoll, &events, 1, -1);
  } while (errno == EINTR && event_count < 0);

  CHECK_ERROR(event_count <= 0);

  exit_daemon();
}

void signal_crash(void) {
  uint64_t event_value;
  exit_status = EXIT_FAILURE;

  hal_sleep_s(1);
  if (pthread_self() == ez_daemon.thread) exit_daemon();
  else write(ez_daemon.crash_event_fd, &event_value, sizeof(event_value)); 

  pthread_exit(0);
}
