

#ifndef EPOLL_H
#define EPOLL_H

#include "stdint.h"
#include <sys/epoll.h>

//forward declaration for interdependency
struct epoll_port_private_data;

typedef struct epoll_port_private_data epoll_port_private_data_t;

typedef void (*epoll_port_callback_t)(epoll_port_private_data_t *private_data);

struct epoll_port_private_data
{
    epoll_port_callback_t callback;
    int file_descriptor;
    uint8_t endpoint_number;
};

void epoll_port_init(void);

void epoll_port_register(epoll_port_private_data_t *private_data);

void epoll_port_unregister(epoll_port_private_data_t *private_data);

void epoll_port_unwatch(epoll_port_private_data_t *private_data);

void epoll_port_watch_back(uint8_t endpoint_number);

size_t epoll_port_wait_for_event(struct epoll_event events[], size_t max_event_number);

#endif //EPOLL_H
