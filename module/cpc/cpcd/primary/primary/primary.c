/**
 * @file primary.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-10-30
 *
 *
 */

#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "utility/errcode.h"
#include "utility/logs.h"
#include "utility/config.h"
#include "utility/utils.h"
#include "utility/slist.h"
#include "primary/primary/primary.h"
#include "primary/primary_cpcd.h"
#include "primary/system/callbacks.h"
#include "primary/system/system.h"
#include "primary/epoll_port/epoll_port.h"
#include "primary/cpcd/cpcd.h"
#include "primary/cpcd/cpcd.h"
#include "libcpc.h"
#include "version.h"
//=============================================================================
//                  Constant Definition
//=============================================================================
#define PRIMARY_EP_MAX_COUNTS   (256)
//=============================================================================
//                  Macro Definition
//=============================================================================

//=============================================================================
//                  Structure Definition
//=============================================================================
typedef struct
{
    slist_node_t node;
    uint8_t endpoint_id;
    int fd_ctrl_data_socket;
}pd_ce_list_t;

typedef struct
{
    slist_node_t node;
    epoll_port_private_data_t data_socket_epoll_port_data;
    pid_t pid;
}ctrl_socket_data_list_t;

typedef struct
{
    slist_node_t node;
    epoll_port_private_data_t event_socket_epoll_port_private_data;
}event_socket_data_list_t;

typedef struct
{
    slist_node_t node;
    epoll_port_private_data_t data_socket_epoll_port_data;
}data_socket_data_list_t;

typedef struct
{
    slist_node_t node;
    int fd_data_socket;
    int fd_ctrl_data_socket;
}data_ctrl_data_socket_pair_close_list_item_t;

typedef struct
{
    uint32_t open_data_connections;
    uint32_t open_event_connections;
    uint32_t pending_close;
    epoll_port_private_data_t event_connection_socket_epoll_port_private_data;
    epoll_port_private_data_t connection_socket_epoll_port_private_data;
    slist_node_t *event_data_socket_epoll_port_data;
    slist_node_t *data_socket_epoll_port_data;
    slist_node_t *data_ctrl_data_socket_pair;
}ep_ctrl_context_t;

//=============================================================================
//                  Global Data Definition
//=============================================================================
static ep_ctrl_context_t ep_ctx[PRIMARY_EP_MAX_COUNTS];
static slist_node_t *pending_connections;
static slist_node_t *ctrl_connections;
static int fd_socket_ctrl;

//=============================================================================
//                  Private Function Definition
//=============================================================================
static void primary_process_epoll_port_fd_ctrl_connection_socket(epoll_port_private_data_t *private_data);
static void primary_process_epoll_port_fd_ctrl_data_socket(epoll_port_private_data_t *private_data);
static void primary_process_epoll_port_fd_ep_connection_socket(epoll_port_private_data_t *private_data);
static void primary_process_epoll_port_fd_ep_data_socket(epoll_port_private_data_t *private_data);

static void primary_handle_client_disconnected(uint8_t endpoint_number);
static void primary_handle_client_closed_ep_connection(int fd_data_socket, uint8_t endpoint_number);
static bool primary_handle_client_closed_ep_notify_close(int fd_data_socket, uint8_t endpoint_number);
static void primary_handle_client_closed_ctrl_connection(int fd_data_socket);
static void primary_ep_push_close_socket_pair(int fd_data_socket, int fd_ctrl_data_socket, uint8_t endpoint_number);
static bool primary_ep_find_close_socket_pair(int fd_data_socket, int fd_ctrl_data_socket, uint8_t endpoint_number);
static int primary_pull_data_from_data_socket(int fd_data_socket, uint8_t **buffer_ptr, size_t *buffer_len_ptr);

//=============================================================================
//                  Global Function Definition
//=============================================================================
void primary_init(void)
{
    int ret, nchars;
    struct sockaddr_un name;
    size_t size, i;
    static epoll_port_private_data_t private_data;

    fd_socket_ctrl = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    ERROR_SYSCALL_ON(fd_socket_ctrl < 0);

    memset(&name, 0, sizeof(name));
    name.sun_family = AF_UNIX;

    size = (sizeof(name.sun_path) - 1);
    nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", config.socket_folder, config.instance_name);
    ERROR_ON(nchars < 0 || (size_t)nchars >= size);

    ret = bind(fd_socket_ctrl, (const struct sockaddr *)&name, sizeof(name));
    ERROR_SYSCALL_ON(ret < 0);

    ret = listen(fd_socket_ctrl, 5);
    ERROR_SYSCALL_ON(ret < 0);

    slist_init(&ctrl_connections);

    slist_init(&pending_connections);

    for (i = 1; i != PRIMARY_EP_MAX_COUNTS; i++)
    {
        ep_ctx[i].open_data_connections = 0;
        ep_ctx[i].open_event_connections = 0;
        ep_ctx[i].pending_close = 0;
        ep_ctx[i].connection_socket_epoll_port_private_data.endpoint_number = (uint8_t)i;
        ep_ctx[i].connection_socket_epoll_port_private_data.file_descriptor = -1;
        ep_ctx[i].event_connection_socket_epoll_port_private_data.file_descriptor = -1;
        slist_init(&ep_ctx[i].data_socket_epoll_port_data);
        slist_init(&ep_ctx[i].event_data_socket_epoll_port_data);
        slist_init(&ep_ctx[i].data_ctrl_data_socket_pair);
    }

    private_data.callback = primary_process_epoll_port_fd_ctrl_connection_socket;
    private_data.file_descriptor = fd_socket_ctrl;
    private_data.endpoint_number = 0;
    epoll_port_register(&private_data);
}

static void primary_process_epoll_port_fd_ctrl_connection_socket(epoll_port_private_data_t *private_data)
{
    (void)private_data;
    int new_data_socket;
    int flags;
    int ret;

    new_data_socket = accept(fd_socket_ctrl, NULL, NULL);
    ERROR_SYSCALL_ON(new_data_socket < 0);

    flags = fcntl(new_data_socket, F_GETFL, NULL);
    ERROR_SYSCALL_ON(flags < 0);
    ret = fcntl(new_data_socket, F_SETFL, flags | O_NONBLOCK);
    ERROR_SYSCALL_ON(ret < 0);

    {
        ctrl_socket_data_list_t *new_item;

        /* Allocate resources for this new connection */
        new_item = calloc_port(sizeof *new_item);
        new_item->pid = -1;

        /* Register this new data socket to epoll set */
        {
            epoll_port_private_data_t *private_data = &new_item->data_socket_epoll_port_data;

            private_data->callback = primary_process_epoll_port_fd_ctrl_data_socket;
            private_data->endpoint_number = 0; /* Irrelevent information in the case of ctrl data sockets */
            private_data->file_descriptor = new_data_socket;

            epoll_port_register(private_data);
        }

        /* Finally, add this new socket item to the list */
        slist_push(&ctrl_connections, &new_item->node);
    }
}

static void primary_process_epoll_port_fd_ctrl_data_socket(epoll_port_private_data_t *private_data)
{
    int fd_ctrl_data_socket = private_data->file_descriptor;
    uint8_t *buffer;
    size_t buffer_len;
    cpc_croe_exange_buffer_t *interface_buffer;
    int ret;

    /* Check if the event is about the client closing the connection */
    {
        int length;

        ret = ioctl(fd_ctrl_data_socket, FIONREAD, &length);
        ERROR_SYSCALL_ON(ret < 0);

        if (length == 0)
        {
            primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
            return;
        }
    }

    /* Retrieve the payload from the endpoint data connection */
    ret = primary_pull_data_from_data_socket(fd_ctrl_data_socket, &buffer, &buffer_len);
    ERROR_ON(ret != 0);

    ERROR_ON(buffer_len < sizeof(cpc_croe_exange_buffer_t));
    interface_buffer = (cpc_croe_exange_buffer_t *)buffer;

    switch (interface_buffer->type)
    {
    case EXCHANGE_EP_STATUS_QUERY:
        /* Client requested an endpoint status */
    {
        cpc_ep_state_t ep_state;
        TRACE_PRIMARY("Received an endpoint status query");

        ASSERT_ON(buffer_len != sizeof(cpc_croe_exange_buffer_t) + sizeof(cpc_ep_state_t));

        ep_state = cpcd_get_endpoint_state(interface_buffer->endpoint_number);

        memcpy(interface_buffer->payload, &ep_state, sizeof(cpc_ep_state_t));

        ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

        if (ret < 0 && errno == EPIPE)
        {
            primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
        } else
        {
            ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
            ERROR_ON((size_t)ret != sizeof(cpc_croe_exange_buffer_t) + sizeof(cpc_ep_state_t));
        }
    }
    break;

    case EXCHANGE_MAX_WRITE_SIZE_QUERY:
        /* Client requested maximum write size */
    {
        TRACE_PRIMARY("Received an maximum write size query");

        ASSERT_ON(buffer_len != sizeof(cpc_croe_exange_buffer_t) + sizeof(uint32_t));
        size_t rx_capability = (size_t)primary_cpcd_get_secondary_rx_capability();
        memcpy(interface_buffer->payload, &rx_capability, sizeof(uint32_t));

        ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

        if (ret < 0 && errno == EPIPE)
        {
            primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
        } else
        {
            ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
            ERROR_ON((size_t)ret != sizeof(cpc_croe_exange_buffer_t) + sizeof(uint32_t));
        }
    }
    break;

    case EXCHANGE_VERSION_QUERY:
        /* Client requested the version of the daemon*/
    {
        char *version = (char *)interface_buffer->payload;
        bool do_close_client = false;

        ERROR_ON(interface_buffer->payload == NULL);

        TRACE_PRIMARY("Received a version query");

        if (buffer_len != sizeof(cpc_croe_exange_buffer_t) + sizeof(char) * PROJECT_MAX_VERSION_SIZE)
        {
            WARN("Client used invalid version buffer_len = %zu", buffer_len);
            break;
        }

        if (strnlen(version, PROJECT_MAX_VERSION_SIZE) == PROJECT_MAX_VERSION_SIZE)
        {
            do_close_client = true;
            WARN("Client used invalid library version, version string is invalid");
        } else if (strcmp(version, PROJECT_VER) != 0)
        {
            do_close_client = true;
            WARN("Client used invalid library version, (v%s) expected (v%s)", version, PROJECT_VER);
        } else
        {
            PRINT_INFO("New client connection using library v%s", version);
        }

        //Reuse the receive buffer to send back the response
        strncpy(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE);

        ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

        if ((ret < 0 && errno == EPIPE) || do_close_client)
        {
            primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
        } else
        {
            ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
            ERROR_ON((size_t)ret != sizeof(cpc_croe_exange_buffer_t) + sizeof(char) * PROJECT_MAX_VERSION_SIZE);
        }
    }
    break;


    case EXCHANGE_OPEN_EP_QUERY:
        /* Client requested to open an endpoint socket*/
    {
        TRACE_PRIMARY("Received an endpoint open query");

        ASSERT_ON(buffer_len != sizeof(cpc_croe_exange_buffer_t) + sizeof(bool));

        /* Add this connection to the pending connections list, we need to check the secondary if the endpoint is open */
        /* This will be done in the primary_process_pending_connections function */
        pd_ce_list_t *pending_connection = calloc_port(sizeof(pd_ce_list_t));
        ERROR_ON(pending_connection == NULL);

        pending_connection->endpoint_id = interface_buffer->endpoint_number;
        pending_connection->fd_ctrl_data_socket = fd_ctrl_data_socket;
        slist_push_back(&pending_connections, &pending_connection->node);
    }
    break;

    case EXCHANGE_CLOSE_EP_QUERY:
    {
        TRACE_PRIMARY("Received a endpoint close query");
        /* Endpoint was closed by secondary */
        if (ep_ctx[interface_buffer->endpoint_number].pending_close > 0)
        {
            ep_ctx[interface_buffer->endpoint_number].pending_close--;
            if (ep_ctx[interface_buffer->endpoint_number].pending_close == 0)
            {
                cpcd_close_endpoint(interface_buffer->endpoint_number, true, false);
            }

            // Ack the close query
            ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
            if (ret < 0 && errno == EPIPE)
            {
                primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
            } else
            {
                ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
                ERROR_ON((size_t)ret != (sizeof(cpc_croe_exange_buffer_t) + sizeof(int)));
                // And notify the caller
                ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
                if (ret < 0 && errno == EPIPE)
                {
                    primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
                } else
                {
                    ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
                    ERROR_ON((size_t)ret != (sizeof(cpc_croe_exange_buffer_t) + sizeof(int)));
                }
            }
        } else
        {
            /* Endpoint was already closed by a client (same ctrl data socket, multiple instances of the same endpoint) */
            if (cpcd_get_endpoint_state(interface_buffer->endpoint_number) == CPC_EP_STATE_CLOSED)
            {
                // Ack the close query
                ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
                if (ret < 0 && errno == EPIPE)
                {
                    primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
                } else
                {
                    ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
                    ERROR_ON((size_t)ret != (sizeof(cpc_croe_exange_buffer_t) + sizeof(int)));
                    // And notify the caller
                    ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
                    if (ret < 0 && errno == EPIPE)
                    {
                        primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
                    } else
                    {
                        ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
                        ERROR_ON((size_t)ret != (sizeof(cpc_croe_exange_buffer_t) + sizeof(int)));
                    }
                }
            } else
            {
                /* Endpoint is about to be closed by a client */
                int fd_data_socket = *(int *)interface_buffer->payload;
                bool fd_data_socket_closed = primary_ep_find_close_socket_pair(fd_data_socket, -1, interface_buffer->endpoint_number);

                if (fd_data_socket_closed)
                {
                    // Socket already closed, ack the close query
                    ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
                    if (ret < 0 && errno == EPIPE)
                    {
                        primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
                    } else
                    {
                        ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
                        ERROR_ON((size_t)ret != (sizeof(cpc_croe_exange_buffer_t) + sizeof(int)));
                        // And notify now
                        ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
                        if (ret < 0 && errno == EPIPE)
                        {
                            primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
                        } else
                        {
                            ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
                            ERROR_ON((size_t)ret != (sizeof(cpc_croe_exange_buffer_t) + sizeof(int)));
                        }
                    }
                } else
                {
                    primary_ep_push_close_socket_pair(fd_data_socket, fd_ctrl_data_socket, interface_buffer->endpoint_number);

                    // Ack the close query
                    ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);
                    if (ret < 0 && errno == EPIPE)
                    {
                        primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
                    } else
                    {
                        ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
                        ERROR_ON((size_t)ret != (sizeof(cpc_croe_exange_buffer_t) + sizeof(int)));
                    }
                }
            }
        }
    }
    break;

    case EXCHANGE_SET_PID_QUERY:
    {
        bool can_connect = true;
        ctrl_socket_data_list_t *item;

        // Set the control socket PID
        item = container_of(private_data, ctrl_socket_data_list_t, data_socket_epoll_port_data);
        item->pid = *(pid_t *)interface_buffer->payload;

        memcpy(interface_buffer->payload, &can_connect, sizeof(bool));

        ASSERT_ON(buffer_len < sizeof(bool));
        ssize_t ret = send(fd_ctrl_data_socket, interface_buffer, buffer_len, 0);

        if (ret < 0 && errno == EPIPE)
        {
            primary_handle_client_closed_ctrl_connection(fd_ctrl_data_socket);
        } else
        {
            ERROR_SYSCALL_ON(ret < 0 && errno != EPIPE);
            ERROR_ON((size_t)ret != sizeof(cpc_croe_exange_buffer_t) + sizeof(pid_t));
        }
    }
    break;
    default:
        break;
    }

    free(buffer);
}

void primary_process_pending_connections(void)
{
    pd_ce_list_t *pending_connection;
    pending_connection = SLIST_ENTRY(pending_connections, pd_ce_list_t, node);

    if (pending_connection != NULL)
    {
        if (cpcd_ep_is_closing(pending_connection->endpoint_id))
        {
            TRACE_PRIMARY("Endpoint #%d is currently closing, waiting before opening", pending_connection->endpoint_id);
            return;
        }

        if (sys_open_ep_step == SYSTEM_OPEN_STEP_IDLE)
        {
            sys_open_ep_step = SYSTEM_OPEN_STEP_STATE_WAITING;
            sys_set_pending_connection(pending_connection->fd_ctrl_data_socket);
            sys_cmd_property_get(sys_get_ep_state_pending_cb,
                                 (property_id_t)(PROP_EP_STATE_0 + pending_connection->endpoint_id),
                                 5,
                                 100000,
                                 false);
        } else if (sys_open_ep_step == SYSTEM_OPEN_STEP_STATE_FETCHED)
        {
        } else if (sys_open_ep_step == SYSTEM_OPEN_STEP_DONE)
        {
            sys_open_ep_step = SYSTEM_OPEN_STEP_IDLE;

            sys_set_pending_connection(0);
            slist_remove(&pending_connections, &pending_connection->node);
            free(pending_connection);
        }
    }
}
static void primary_process_epoll_port_fd_ep_connection_socket(epoll_port_private_data_t *private_data)
{
    int new_data_socket, flags;
    int fd_connection_socket = private_data->file_descriptor;
    uint8_t endpoint_number = private_data->endpoint_number;

    /* Sanity checks */
    {
        /* We don't deal with system endpoint here*/
        ASSERT_ON(endpoint_number == 0);

        /* Make sure the connection socket exists */
        ASSERT_ON(ep_ctx[endpoint_number].connection_socket_epoll_port_private_data.file_descriptor == -1);
    }

    /* Accept the new connection for that endpoint */
    new_data_socket = accept(fd_connection_socket, NULL, NULL);
    ERROR_SYSCALL_ON(new_data_socket < 0);

    /* Set socket as non-blocking */
    flags = fcntl(new_data_socket, F_GETFL, NULL);

    if (flags < 0)
    {
        ERROR("fcntl F_GETFL failed.%s", strerror(errno));
    }

    flags |= O_NONBLOCK;

    if (fcntl(new_data_socket, F_SETFL, flags) < 0)
    {
        ERROR("fcntl F_SETFL failed.%s", strerror(errno));
    }

    /* Add the new data socket in the list of data sockets for that endpoint */
    {
        data_socket_data_list_t *new_item;

        /* Allocate resources for this new connection */
        {
            new_item = (data_socket_data_list_t *)calloc_port(sizeof(data_socket_data_list_t));
            ERROR_ON(new_item == NULL);

            slist_push(&ep_ctx[endpoint_number].data_socket_epoll_port_data, &new_item->node);
        }

        /* Register this new connection's socket to epoll set */
        {
            epoll_port_private_data_t *private_data = &new_item->data_socket_epoll_port_data;

            private_data->callback = primary_process_epoll_port_fd_ep_data_socket;
            private_data->endpoint_number = endpoint_number;
            private_data->file_descriptor = new_data_socket;

            epoll_port_register(private_data);
        }
    }

    ep_ctx[endpoint_number].open_data_connections++;
    PRINT_INFO("Endpoint socket #%d: Client connected. %d connections", endpoint_number, ep_ctx[endpoint_number].open_data_connections);

    /* Tell the cpcd that this endpoint is open */
    cpcd_process_endpoint_change(endpoint_number, CPC_EP_STATE_OPEN);
    TRACE_PRIMARY("Told cpcd to open ep#%u", endpoint_number);

    /* Acknowledge the user so that they can start using the endpoint */
    {
        cpc_croe_exange_buffer_t *buffer;
        size_t buffer_len = sizeof(cpc_croe_exange_buffer_t) + sizeof(int);

        buffer = calloc_port(buffer_len);
        ERROR_SYSCALL_ON(buffer == NULL);
        buffer->endpoint_number = endpoint_number;
        buffer->type = EXCHANGE_OPEN_EP_QUERY;
        *((int *)buffer->payload) = new_data_socket;
        ERROR_SYSCALL_ON(send(new_data_socket, buffer, buffer_len, 0) != (ssize_t)buffer_len);
        free(buffer);
    }
}

static void primary_process_epoll_port_fd_ep_data_socket(epoll_port_private_data_t *private_data)
{
    uint8_t *buffer;
    size_t buffer_len;
    int fd_data_socket = private_data->file_descriptor;
    uint8_t endpoint_number = private_data->endpoint_number;
    int ret;

    if (cpcd_ep_is_busy(endpoint_number))
    {
        epoll_port_unwatch(private_data);
        return;
    }

    /* Check if the event is about the client closing the connection */
    {
        int length;

        ret = ioctl(fd_data_socket, FIONREAD, &length);
        ERROR_SYSCALL_ON(ret < 0);

        if (length == 0)
        {
            primary_handle_client_closed_ep_connection(fd_data_socket, endpoint_number);
            return;
        }
    }
    ret = primary_pull_data_from_data_socket(fd_data_socket, &buffer, &buffer_len);
    if (ret != 0)
    {
        primary_handle_client_closed_ep_connection(fd_data_socket, endpoint_number);
        return;
    }
    if (cpcd_get_endpoint_state(endpoint_number) == CPC_EP_STATE_OPEN)
    {
        cpcd_write(endpoint_number, buffer, buffer_len, 0);
        free(buffer);
    } else
    {
        free(buffer);
        WARN("User tried to push on endpoint %d but it's not open, state is %d", endpoint_number, cpcd_get_endpoint_state(endpoint_number));
        primary_close_endpoint(endpoint_number, false);
    }
}

static void primary_handle_client_disconnected(uint8_t endpoint_number)
{
    ERROR_ON(ep_ctx[endpoint_number].open_data_connections == 0);

    ep_ctx[endpoint_number].open_data_connections--;
    PRINT_INFO("Endpoint socket #%d: Client disconnected. %d connections", endpoint_number, ep_ctx[endpoint_number].open_data_connections);

    if (ep_ctx[endpoint_number].open_data_connections == 0)
    {
        TRACE_PRIMARY("Closing endpoint socket, no more listeners");
        primary_close_endpoint(endpoint_number, false);

        if (ep_ctx[endpoint_number].pending_close == 0)
        {
            TRACE_PRIMARY("No pending close on the endpoint, closing it");
            cpcd_close_endpoint(endpoint_number, true, false);
        }
    }
}

static void primary_handle_client_closed_ep_connection(int fd_data_socket, uint8_t endpoint_number)
{
    data_socket_data_list_t *item;
    data_socket_data_list_t *next_item;

    item = SLIST_ENTRY(ep_ctx[endpoint_number].data_socket_epoll_port_data,
                       data_socket_data_list_t,
                       node);

    if (item == NULL)
    {
        ERROR("data connection not found in the linked list of the endpoint");
    }

    while (1)
    {
        next_item = SLIST_ENTRY((item)->node.node,
                                data_socket_data_list_t,
                                node);
        if (item->data_socket_epoll_port_data.file_descriptor == fd_data_socket)
        {
            epoll_port_unregister(&item->data_socket_epoll_port_data);
            slist_remove(&ep_ctx[endpoint_number].data_socket_epoll_port_data, &item->node);
            primary_handle_client_closed_ep_notify_close(item->data_socket_epoll_port_data.file_descriptor, endpoint_number);

            int ret = shutdown(fd_data_socket, SHUT_RDWR);
            ERROR_SYSCALL_ON(ret < 0);

            ret = close(fd_data_socket);
            ERROR_SYSCALL_ON(ret < 0);

            primary_handle_client_disconnected(endpoint_number);

            free(item);
        }
        item = next_item;
        if (item == NULL)
        {
            break;
        }
    }
}

static void primary_ep_push_close_socket_pair(int fd_data_socket, int fd_ctrl_data_socket, uint8_t endpoint_number)
{
    data_ctrl_data_socket_pair_close_list_item_t *item;
    item = calloc_port(sizeof(data_ctrl_data_socket_pair_close_list_item_t));
    ERROR_SYSCALL_ON(item == NULL);
    item->fd_data_socket = fd_data_socket;
    item->fd_ctrl_data_socket = fd_ctrl_data_socket;
    slist_push(&ep_ctx[endpoint_number].data_ctrl_data_socket_pair, &item->node);
}

static bool primary_ep_find_close_socket_pair(int fd_data_socket, int fd_ctrl_data_socket, uint8_t endpoint_number)
{
    data_ctrl_data_socket_pair_close_list_item_t *item;
    data_ctrl_data_socket_pair_close_list_item_t *next_item;
    bool found = false;

    item = SLIST_ENTRY(ep_ctx[endpoint_number].data_ctrl_data_socket_pair,
                       data_ctrl_data_socket_pair_close_list_item_t,
                       node);

    while (item)
    {
        next_item = SLIST_ENTRY((item)->node.node,
                                data_ctrl_data_socket_pair_close_list_item_t,
                                node);

        if (item->fd_data_socket == fd_data_socket && item->fd_ctrl_data_socket == fd_ctrl_data_socket)
        {
            slist_remove(&ep_ctx[endpoint_number].data_ctrl_data_socket_pair, &item->node);
            free(item);
            found = true;
            break;
        }

        item = next_item;
    }

    return found;
}

static bool primary_handle_client_closed_ep_notify_close(int fd_data_socket, uint8_t endpoint_number)
{
    data_ctrl_data_socket_pair_close_list_item_t *item;
    data_ctrl_data_socket_pair_close_list_item_t *next_item;
    bool notified = false;

    item = SLIST_ENTRY(ep_ctx[endpoint_number].data_ctrl_data_socket_pair,
                       data_ctrl_data_socket_pair_close_list_item_t,
                       node);

    while (item)
    {
        next_item = SLIST_ENTRY((item)->node.node,
                                data_ctrl_data_socket_pair_close_list_item_t,
                                node);

        if (item->fd_data_socket == fd_data_socket && item->fd_ctrl_data_socket > 0)
        {
            slist_remove(&ep_ctx[endpoint_number].data_ctrl_data_socket_pair, &item->node);

            if (!notified)
            {
                ssize_t ret;
                uint8_t query_close_buffer[sizeof(cpc_croe_exange_buffer_t) + sizeof(int)];
                const size_t query_close_len = sizeof(cpc_croe_exange_buffer_t) + sizeof(int);
                cpc_croe_exange_buffer_t *query_close = (cpc_croe_exange_buffer_t *)query_close_buffer;

                query_close->endpoint_number = endpoint_number;
                query_close->type = EXCHANGE_CLOSE_EP_QUERY;
                *((int *)query_close->payload) = fd_data_socket;

                ret = send(item->fd_ctrl_data_socket, query_close, query_close_len, 0);
                if (ret == (ssize_t)query_close_len)
                {
                    notified = true;
                } else
                {
                    if (errno != EPIPE)
                    {
                        WARN("ep notify send() failed, errno = %d", errno);
                    }
                }
            }

            free(item);
        }

        item = next_item;
    }

    return notified;
}

static void primary_handle_client_closed_ctrl_connection(int fd_data_socket)
{
    ctrl_socket_data_list_t *item;
    ctrl_socket_data_list_t *next_item;

    item = SLIST_ENTRY(ctrl_connections,
                       ctrl_socket_data_list_t,
                       node);

    if (item == NULL)
    {
        ERROR("ctrl data connection not found in the linked list of the ctrl socket");
    }

    while (1)
    {
        /* Get the next item */
        next_item = SLIST_ENTRY((item)->node.node,
                                ctrl_socket_data_list_t,
                                node);

        if (item->data_socket_epoll_port_data.file_descriptor == fd_data_socket)
        {
            epoll_port_unregister(&item->data_socket_epoll_port_data);

            slist_remove(&ctrl_connections, &item->node);
            int ret = shutdown(fd_data_socket, SHUT_RDWR);
            ERROR_SYSCALL_ON(ret < 0);

            ret = close(fd_data_socket);
            ERROR_SYSCALL_ON(ret < 0);

            PRINT_INFO("Client disconnected");
            free(item);
        }

        item = next_item;
        if (item == NULL)
        {
            break;
        }
    }
}


void primary_set_endpoint_encryption(uint8_t endpoint_id, bool encryption_enabled)
{
    (void)endpoint_id;
    (void)encryption_enabled;
}

void primary_open_endpoint(uint8_t endpoint_number)
{
    struct sockaddr_un name;
    int fd_connection_sock;
    int ret;

    {
        if (ep_ctx[endpoint_number].connection_socket_epoll_port_private_data.file_descriptor != -1)
        {
            return;
        }
        ASSERT_ON(endpoint_number == 0);

        ASSERT_ON(ep_ctx[endpoint_number].connection_socket_epoll_port_private_data.file_descriptor != -1);

        ASSERT_ON(ep_ctx[endpoint_number].data_socket_epoll_port_data != NULL);
    }

    {
        /* Create the connection socket.*/
        fd_connection_sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        ERROR_SYSCALL_ON(fd_connection_sock < 0);

        {
            memset(&name, 0, sizeof(name));

            name.sun_family = AF_UNIX;

            {
                int nchars;
                const size_t size = sizeof(name.sun_path) - 1;

                nchars = snprintf(name.sun_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", config.socket_folder, config.instance_name, endpoint_number);

                ERROR_ON(nchars < 0 || (size_t)nchars >= size);
            }

            ret = bind(fd_connection_sock, (const struct sockaddr *)&name, sizeof(name));
            ERROR_SYSCALL_ON(ret < 0);
        }
        ret = listen(fd_connection_sock, 5);
        ERROR_SYSCALL_ON(ret < 0);
    }

    {
        epoll_port_private_data_t *private_data = &ep_ctx[endpoint_number].connection_socket_epoll_port_private_data;

        private_data->callback = primary_process_epoll_port_fd_ep_connection_socket;
        private_data->endpoint_number = endpoint_number;
        private_data->file_descriptor = fd_connection_sock;

        epoll_port_register(private_data);
    }

    PRINT_INFO("Opened connection socket for ep#%u", endpoint_number);
}

bool primary_is_endpoint_open(uint8_t endpoint_number)
{
    return ep_ctx[endpoint_number].connection_socket_epoll_port_private_data.file_descriptor == -1 ? false : true;
}


void primary_close_endpoint(uint8_t endpoint_number, bool error)
{
    size_t data_sock_i = 0;
    int ret;

    /* Sanity check */
    {
        ASSERT_ON(endpoint_number == 0);

        if (ep_ctx[endpoint_number].connection_socket_epoll_port_private_data.file_descriptor == -1)
        {
            return;
        }
    }

    while (ep_ctx[endpoint_number].data_socket_epoll_port_data != NULL)
    {
        data_socket_data_list_t *item;
        data_sock_i++;
        slist_node_t *node = slist_pop(&ep_ctx[endpoint_number].data_socket_epoll_port_data);

        item = SLIST_ENTRY(node, data_socket_data_list_t, node);

        epoll_port_unregister(&item->data_socket_epoll_port_data);

        primary_handle_client_closed_ep_notify_close(item->data_socket_epoll_port_data.file_descriptor, endpoint_number);

        ret = shutdown(item->data_socket_epoll_port_data.file_descriptor, SHUT_RDWR);
        ERROR_SYSCALL_ON(ret < 0);

        ret = close(item->data_socket_epoll_port_data.file_descriptor);
        ERROR_SYSCALL_ON(ret < 0);

        free(item);
        TRACE_PRIMARY("Closed data socket #%u on ep#%u", data_sock_i, endpoint_number);
    }

    {
        int fd_connection_socket = ep_ctx[endpoint_number].connection_socket_epoll_port_private_data.file_descriptor;

        if (fd_connection_socket > 0)
        {
            epoll_port_unregister(&ep_ctx[endpoint_number].connection_socket_epoll_port_private_data);

            ret = shutdown(fd_connection_socket, SHUT_RDWR);
            ERROR_SYSCALL_ON(ret < 0);
            ret = close(fd_connection_socket);
            ERROR_SYSCALL_ON(ret < 0);
        }

        {
            char endpoint_path[SIZEOF_MEMBER(struct sockaddr_un, sun_path)];

            {
                int nchars;
                const size_t size = sizeof(endpoint_path);

                nchars = snprintf(endpoint_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", config.socket_folder, config.instance_name, endpoint_number);

                ERROR_ON(nchars < 0 || (size_t)nchars >= size);
            }

            ret = unlink(endpoint_path);
            ERROR_SYSCALL_ON(ret < 0 && errno != ENOENT);
        }
        ep_ctx[endpoint_number].connection_socket_epoll_port_private_data.file_descriptor = -1;

        if (error)
        {
            ep_ctx[endpoint_number].pending_close = ep_ctx[endpoint_number].open_data_connections;
        }
        ep_ctx[endpoint_number].open_data_connections = 0;
    }
}

status_t primary_push_data_to_endpoint(uint8_t endpoint_number, const uint8_t *data, size_t data_len)
{
    data_socket_data_list_t *item;
    int nb_clients = 0;

    {
        ASSERT_ON(ep_ctx[endpoint_number].connection_socket_epoll_port_private_data.file_descriptor == -1);

        WARN_ON(ep_ctx[endpoint_number].data_socket_epoll_port_data == NULL);
    }

    item = SLIST_ENTRY(ep_ctx[endpoint_number].data_socket_epoll_port_data,
                       data_socket_data_list_t,
                       node);

    while (item != NULL)
    {
        ssize_t wc = send(item->data_socket_epoll_port_data.file_descriptor,
                          data,
                          data_len,
                          MSG_DONTWAIT);
        if (wc < 0)
        {
            TRACE_PRIMARY("send() failed with %s", ERRNO_CODENAME[errno]);
        }

        nb_clients++;

        if (wc < 0 && (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EWOULDBLOCK))
        {
            WARN("Unresponsive data socket on ep#%d, closing", endpoint_number);

            if (ep_ctx[endpoint_number].open_data_connections == 1 && nb_clients == 1)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    return STATUS_WOULD_BLOCK;
                }
            }

            epoll_port_unregister(&item->data_socket_epoll_port_data);

            primary_ep_push_close_socket_pair(item->data_socket_epoll_port_data.file_descriptor, -1, endpoint_number);

            int ret = shutdown(item->data_socket_epoll_port_data.file_descriptor, SHUT_RDWR);
            ERROR_SYSCALL_ON(ret < 0);

            ret = close(item->data_socket_epoll_port_data.file_descriptor);
            ERROR_SYSCALL_ON(ret < 0);

            slist_remove(&ep_ctx[endpoint_number].data_socket_epoll_port_data, &item->node);
            free(item);

            ERROR_ON(ep_ctx[endpoint_number].open_data_connections == 0);

            ep_ctx[endpoint_number].open_data_connections--;
            PRINT_INFO("Endpoint socket #%d: Client disconnected. %d connections", endpoint_number, ep_ctx[endpoint_number].open_data_connections);

            if (ep_ctx[endpoint_number].open_data_connections == 0)
            {
                TRACE_PRIMARY("Endpoint was unresponsive, closing endpoint socket, no more listeners");
                primary_close_endpoint(endpoint_number, false);
                return STATUS_FAIL;
            }

            item = SLIST_ENTRY(ep_ctx[endpoint_number].data_socket_epoll_port_data,
                               data_socket_data_list_t,
                               node);
        } else
        {
            ERROR_SYSCALL_ON(wc < 0);
            ERROR_ON((size_t)wc != data_len);

            item = SLIST_ENTRY((item)->node.node,
                               data_socket_data_list_t,
                               node);
        }
    }

    return STATUS_OK;
}

static int primary_pull_data_from_data_socket(int fd_data_socket, uint8_t **buffer_ptr, size_t *buffer_len_ptr)
{
    int datagram_length;
    uint8_t *buffer;
    ssize_t rc;
    int ret;

    {
        ret = ioctl(fd_data_socket, FIONREAD, &datagram_length);

        ERROR_SYSCALL_ON(ret < 0);
        ASSERT_ON(datagram_length == 0);
    }

    {
        buffer = (uint8_t *)calloc_port((size_t)PAD_TO_8_BYTES(datagram_length));
        ERROR_ON(buffer == NULL);
    }

    {
        rc = recv(fd_data_socket, buffer, (size_t)datagram_length, 0);
        if (rc < 0)
        {
            TRACE_PRIMARY("recv() failed with %s", ERRNO_CODENAME[errno]);
        }

        if (rc == 0 || (rc < 0 && errno == ECONNRESET))
        {
            TRACE_PRIMARY("Client is closed");
            free(buffer);
            return -1;
        }
        ERROR_SYSCALL_ON(rc < 0);
    }

    *buffer_ptr = buffer;
    *buffer_len_ptr = (size_t)rc;
    return 0;
}

bool primary_listener_list_empty(uint8_t endpoint_number)
{
    return ep_ctx[endpoint_number].open_data_connections == 0;
}

void primary_notify_connected_libs_of_secondary_reset(void)
{
    ctrl_socket_data_list_t *item;

    SLIST_FOR_EACH_ENTRY(ctrl_connections,
                         item,
                         ctrl_socket_data_list_t,
                         node)
    {
        if (item->pid != getpid())
        {
            if (item->pid > 1)
            {
                kill(item->pid, SIGUSR1);
            } else
            {
                ASSERT("Connected library's pid it not set");
            }
        }
    }
}

static void primary_send_event(int socket_fd, cpc_evt_type_t event_type, uint8_t ep_id, uint8_t *payload, uint32_t payload_length)
{
    cpc_cpcd_event_buffer_t *event = calloc_port(sizeof(cpc_cpcd_event_buffer_t) + payload_length);
    ERROR_SYSCALL_ON(event == NULL);

    event->type = event_type;
    event->endpoint_number = ep_id;
    event->payload_length = payload_length;

    if (payload != NULL && payload_length > 0)
    {
        memcpy(event->payload, payload, payload_length);
    }

    ssize_t ret = send(socket_fd, event, sizeof(cpc_cpcd_event_buffer_t) + payload_length, MSG_DONTWAIT);

    if (ret < 0 && (errno == EPIPE || errno == ECONNRESET || errno == ECONNREFUSED))
    {
    } else if (ret < 0 && errno == EWOULDBLOCK)
    {
        WARN("Client event socket is full, closing the socket..");
        ret = shutdown(socket_fd, SHUT_RDWR);
        ERROR_SYSCALL_ON(ret < 0);
    } else
    {
        ASSERT_ON(ret < 0 || (size_t)ret != sizeof(cpc_cpcd_event_buffer_t) + payload_length);
    }

    free(event);
}

static cpc_evt_type_t primary_get_event_type_from_state(cpc_ep_state_t state)
{
    switch (state)
    {
    case CPC_EP_STATE_OPEN:
        return CPC_EVT_EP_OPENED;
    case CPC_EP_STATE_CLOSED:
        return CPC_EVT_EP_CLOSED;
    case CPC_EP_STATE_CLOSING:
        return CPC_EVT_EP_CLOSING;
    case CPC_EP_STATE_ERROR_DEST_UNREACH:
        return CPC_EVT_EP_ERROR_DESTINATION_UNREACHABLE;
    case CPC_EP_STATE_ERROR_FAULT:
        return CPC_EVT_EP_ERROR_FAULT;
    default:
        ASSERT("A new state (%d) has been added that has no equivalent event type .", state);
    }
}

static void primary_notify_connected_libs_of_endpoint_state_change(uint8_t ep_id, cpc_ep_state_t new_state)
{
    event_socket_data_list_t *item;

    ASSERT_ON(ep_id == CPC_EP_SYSTEM);

    SLIST_FOR_EACH_ENTRY(ep_ctx[ep_id].event_data_socket_epoll_port_data, item,
                         event_socket_data_list_t,
                         node)
    {
        primary_send_event(item->event_socket_epoll_port_private_data.file_descriptor,
                           primary_get_event_type_from_state((new_state)),
                           ep_id,
                           NULL,
                           0);
    }
}

void primary_on_endpoint_state_change(uint8_t ep_id, cpc_ep_state_t state)
{
    if (ep_id != CPC_EP_SYSTEM)
    {
        primary_notify_connected_libs_of_endpoint_state_change(ep_id, state);
    }
}
