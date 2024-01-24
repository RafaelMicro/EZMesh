
#ifndef CONTROLLER_H
#define CONTROLLER_H

#define _GNU_SOURCE
#include <pthread.h>

#include <stdint.h>
#include <stdbool.h>

bool controller_reset_sequence_in_progress(void);
uint32_t controller_get_agent_rx_capability(void);
void controller_kill_signal(void);
pthread_t controller_init(int fd_socket_driver_ezmeshd, int fd_socket_driver_ezmeshd_notify);
char *controller_get_agent_app_version(void);

#endif
