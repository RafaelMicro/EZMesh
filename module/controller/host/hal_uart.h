#ifndef HAL_UART_H
#define HAL_UART_H

#define _GNU_SOURCE
#include <pthread.h>
#include <stdbool.h>

pthread_t hal_uart_init(int *fd_to_cpcd, int *fd_notify_cpcd, const char *device, unsigned int baudrate, bool hardflow);
int hal_uart_open(const char *device, unsigned int baudrate, bool hardflow);
void hal_uart_assert_rts(bool assert);
void hal_uart_print_overruns(void);
void hal_uart_change_baudrate(void);

#endif
