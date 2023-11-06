

#ifndef PRIMARY_cpcd_H
#define PRIMARY_cpcd_H

#define _GNU_SOURCE
#include <pthread.h>

#include <stdint.h>
#include <stdbool.h>

uint32_t primary_cpcd_get_secondary_rx_capability(void);

pthread_t primary_cpcd_init(int fd_socket_driver_cpcd, int fd_socket_driver_cpcd_notify);

void primary_cpcd_kill_signal(void);

void primary_cpcd_notify_security_ready(void);

bool primary_cpcd_reset_sequence_in_progress(void);

char *primary_cpcd_get_secondary_app_version(void);

#endif //PRIMARY_cpcd_H
