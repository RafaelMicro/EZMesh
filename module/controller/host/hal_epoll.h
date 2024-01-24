#ifndef HAL_EPOLL_H
#define HAL_EPOLL_H

#include "stdint.h"
#include <sys/epoll.h>

struct hal_epoll_event_data;
typedef struct hal_epoll_event_data hal_epoll_event_data_t;
typedef void (*hal_epoll_callback_t) (hal_epoll_event_data_t *data);
struct hal_epoll_event_data
{
    hal_epoll_callback_t callback;
    int file_descriptor;
    uint8_t endpoint_number;
};

void hal_epoll_init(void);
void hal_epoll_register(hal_epoll_event_data_t *data);
void hal_epoll_unregister(hal_epoll_event_data_t *data);
void hal_epoll_unwatch(hal_epoll_event_data_t *data);
void hal_epoll_watch_back(uint8_t endpoint_number);
uint8_t hal_epoll_check_vaild_event(struct hal_epoll_event_data *events);
size_t hal_epoll_wait_for_event(struct epoll_event events[], size_t event_number);

#endif 
