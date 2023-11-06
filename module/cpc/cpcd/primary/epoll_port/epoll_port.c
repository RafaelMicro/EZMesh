

#include "epoll_port.h"
#include "utility/logs.h"
#include "utility/slist.h"
#include "utility/utils.h"
#include "primary/cpcd/cpcd.h"
#include "primary/primary/primary.h"

#include <sys/epoll.h>
#include <string.h>
#include <errno.h>

typedef struct
{
    slist_node_t node;
    struct epoll_port_private_data *unregistered_epoll_port_private_data;
}unwatched_endpoint_list_item_t;

/* List to keep track of every connected library instance over the control socket */
static slist_node_t *unwatched_endpoint_list;

static int fd_epoll;

void epoll_port_init(void)
{
    /* Create the epoll set */
    {
        fd_epoll = epoll_create1(EPOLL_CLOEXEC);
        ERROR_SYSCALL_ON(fd_epoll < 0);
    }

    slist_init(&unwatched_endpoint_list);
}

void epoll_port_register(epoll_port_private_data_t *private_data)
{
    struct epoll_event event = {};
    int ret;

    ERROR_ON(private_data == NULL);
    ERROR_ON(private_data->callback == NULL);
    ERROR_ON(private_data->file_descriptor < 1);

    event.events = EPOLLIN; /* Level-triggered read() availability */
    event.data.ptr = private_data;

    ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, private_data->file_descriptor, &event);
    ERROR_SYSCALL_ON(ret < 0);
}

void epoll_port_unregister(epoll_port_private_data_t *private_data)
{
    int ret;
    unwatched_endpoint_list_item_t *item;

    ERROR_ON(private_data == NULL);
    ERROR_ON(private_data->callback == NULL);
    ERROR_ON(private_data->file_descriptor < 1);

    SLIST_FOR_EACH_ENTRY(unwatched_endpoint_list,
                         item,
                         unwatched_endpoint_list_item_t,
                         node)
    {
        if (private_data == item->unregistered_epoll_port_private_data)
        {
            slist_remove(&unwatched_endpoint_list, &item->node);
            free(item);
            return;
        }
    }

    ret = epoll_ctl(fd_epoll, EPOLL_CTL_DEL, private_data->file_descriptor, NULL);

    ERROR_SYSCALL_ON(ret < 0);
}

void epoll_port_unwatch(epoll_port_private_data_t *private_data)
{
    epoll_port_unregister(private_data);

    unwatched_endpoint_list_item_t *item = calloc_port(sizeof(unwatched_endpoint_list_item_t));
    ERROR_ON(item == NULL);

    item->unregistered_epoll_port_private_data = private_data;

    slist_push(&unwatched_endpoint_list, &item->node);
}

void epoll_port_watch_back(uint8_t endpoint_number)
{
    unwatched_endpoint_list_item_t *item;

    slist_node_t *item_node = unwatched_endpoint_list;
    while (1)
    {
        item = SLIST_ENTRY(item_node,
                           unwatched_endpoint_list_item_t,
                           node);
        if (item == NULL)
        {
            break;
        }
        item_node = item_node->node;
        if (endpoint_number == item->unregistered_epoll_port_private_data->endpoint_number)
        {
            epoll_port_register(item->unregistered_epoll_port_private_data);
            slist_remove(&unwatched_endpoint_list, &item->node);
            free(item);
        }
    }
}

size_t epoll_port_wait_for_event(struct epoll_event events[], size_t max_event_number)
{
    int event_count;

    do
    {
        event_count = epoll_wait(fd_epoll, events, (int)max_event_number, -1);
    } while ((event_count == -1) && (errno == EINTR));

    ERROR_SYSCALL_ON(event_count < 0);

    /* Timeouts should not occur */
    ERROR_ON(event_count == 0);

    return (size_t)event_count;
}
