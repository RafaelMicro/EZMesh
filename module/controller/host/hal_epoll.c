#include "hal_epoll.h"
#include "utility/log.h"
#include "utility/list.h"
#include "utility/utility.h"
#include "daemon/hdlc/core.h"
#include "daemon/primary/primary.h"

#include <sys/epoll.h>
#include <string.h>
#include <errno.h>

#define VALID_EPOLL_DATA(data) { \
    CHECK_ERROR(data == NULL); \
    CHECK_ERROR(data->callback == NULL || data->file_descriptor < 1); }

typedef struct
{
    list_node_t node;
    struct hal_epoll_event_data *unregistered_epoll_port_private_data;
} unwatched_endpoint_list_item_t;

/* List to keep track of every connected library instance over the control socket */
static list_node_t *unwatched_endpoint_list;
static list_node_t *register_list;
static int fd_epoll;

void hal_epoll_init(void)
{
    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK_ERROR(fd_epoll < 0);
    list_init(&unwatched_endpoint_list);
    list_init(&register_list);
}

// void hal_epoll_list_all(void)
// {
//     unwatched_endpoint_list_item_t *item = NULL;
//     log_info("");
//     SLIST_FOR_EACH_ENTRY(register_list, item, unwatched_endpoint_list_item_t, node)
//     {
//         log_info("[Epoll] List  data fd 0x%02x, EP %d, cb %p", 
//             item->unregistered_epoll_port_private_data->file_descriptor, 
//             item->unregistered_epoll_port_private_data->endpoint_number, 
//             item->unregistered_epoll_port_private_data->callback);
//     }
//     log_info("");
// }

void hal_epoll_register(hal_epoll_event_data_t *data)
{
    VALID_EPOLL_DATA(data);
    struct epoll_event event = {.events = EPOLLIN, .data.ptr = data};
    CHECK_ERROR(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, data->file_descriptor, &event) < 0);
    // hal_epoll_list_all();
    // log_info("[EPOLL] GEN: fd 0x%02x, ep %d, cb %p", data->file_descriptor, data->endpoint_number, data->callback);

    unwatched_endpoint_list_item_t *item = calloc(1, sizeof(unwatched_endpoint_list_item_t));
    CHECK_ERROR(item == NULL);
    item->unregistered_epoll_port_private_data = data;
    memcpy(item->unregistered_epoll_port_private_data, data, sizeof(hal_epoll_event_data_t));
    list_push(&register_list, &item->node);
    // hal_epoll_list_all();
    return ;
}

void hal_epoll_unregister(hal_epoll_event_data_t *data)
{
    unwatched_endpoint_list_item_t *item = NULL;
    VALID_EPOLL_DATA(data);
    // hal_epoll_list_all();
    // log_info("[EPOLL] Remove data fd 0x%02x, EP %d, cb %p", data->file_descriptor, data->endpoint_number, data->callback);
    SLIST_FOR_EACH_ENTRY(register_list, item, unwatched_endpoint_list_item_t, node)
    {
        if (memcmp(data, item->unregistered_epoll_port_private_data, sizeof(unwatched_endpoint_list_item_t))==0)
        {
            list_remove(&register_list, &item->node);
            free(item);
            break;
        }
    }
    // hal_epoll_list_all();

    SLIST_FOR_EACH_ENTRY(unwatched_endpoint_list, item, unwatched_endpoint_list_item_t, node)
    {
        if (memcmp(data, item->unregistered_epoll_port_private_data, sizeof(unwatched_endpoint_list_item_t))==0)
        {
            list_remove(&unwatched_endpoint_list, &item->node);
            free(item);
            return;
        }
    }
    CHECK_ERROR(epoll_ctl(fd_epoll, EPOLL_CTL_DEL, data->file_descriptor, NULL) < 0);
}

void hal_epoll_unwatch(hal_epoll_event_data_t *data)
{
    hal_epoll_unregister(data);
    unwatched_endpoint_list_item_t *item = calloc(1, sizeof(unwatched_endpoint_list_item_t));
    CHECK_ERROR(item == NULL);
    item->unregistered_epoll_port_private_data = data;
    list_push(&unwatched_endpoint_list, &item->node);
}

void hal_epoll_watch_back(uint8_t endpoint_number)
{
    unwatched_endpoint_list_item_t *item = NULL;

    list_node_t *item_node = unwatched_endpoint_list;
    while (1)
    {
        item = SLIST_ENTRY(item_node, unwatched_endpoint_list_item_t, node);
        if (item == NULL) break;
        item_node = item_node->node;
        if (endpoint_number == item->unregistered_epoll_port_private_data->endpoint_number)
        {
            hal_epoll_register(item->unregistered_epoll_port_private_data);
            list_remove(&unwatched_endpoint_list, &item->node);
            free(item);
        }
    }
}

size_t hal_epoll_wait_for_event(struct epoll_event events[], size_t event_number)
{
    int cnt = 0;
    do
    {
        cnt = epoll_wait(fd_epoll, events, (int)event_number, -1);
    } while ((cnt == -1) && (errno == EINTR));
    CHECK_ERROR(cnt <= 0);
    return (size_t)cnt;
}
