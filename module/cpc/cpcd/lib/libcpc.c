/**
 * @file cpc.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-11-02
 *
 *
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include "libcpc.h"
#include "version.h"
#include "utility/utils.h"
#include "utility/sleep.h"

//=============================================================================
//                  Constant Definition
//=============================================================================
#ifndef DEFAULT_INSTANCE_NAME
  #define DEFAULT_INSTANCE_NAME "cpcd_0"
#endif

#define CTRL_SOCKET_TIMEOUT_SEC 2

#define DEFAULT_EP_SOCKET_SIZE LIB_CPC_READ_MINIMUM_SIZE
//=============================================================================
//                  Macro Definition
//=============================================================================
#define INIT_CPC_RET(type) type __cpc_ret = 0
#define RETURN_CPC_RET return __cpc_ret
#define SET_CPC_RET(error) \
    do {                     \
        if (__cpc_ret == 0) {  \
            __cpc_ret = error;   \
        }                      \
    } while (0)

//=============================================================================
//                  Structure Definition
//=============================================================================
typedef struct
{
    int ctrl_sock_fd;
    pthread_mutex_t ctrl_sock_fd_lock;
    size_t max_write_size;
    char *secondary_app_version;
    char *instance_name;
    bool initialized;
} __cpc_handle_t;

typedef struct
{
    uint8_t id;
    int server_sock_fd;
    int sock_fd;
    pthread_mutex_t sock_fd_lock;
    __cpc_handle_t *lib_handle;
} __cpc_ep_t;

typedef struct
{
    int endpoint_id;
    int sock_fd;
    pthread_mutex_t sock_fd_lock;
    __cpc_handle_t *lib_handle;
} __cpc_ep_event_handle_t;

//=============================================================================
//                  Global Data Definition
//=============================================================================
static cpc_reset_cb_t saved_reset_cb;
//=============================================================================
//                  Private Function Definition
//=============================================================================
static cpc_reset_cb_t saved_reset_cb;
int cpc_deinit(cpc_handle_t *handle);

static void SIGUSR1_handler(int signum)
{
    (void)signum;

    if (saved_reset_cb != NULL)
    {
        saved_reset_cb();
    }
}

static int cpc_query_exchange(__cpc_handle_t *lib_handle, int fd, cpc_cpcd_exchange_type_t type, uint8_t ep_id,
                              void *payload, size_t payload_sz)
{
    (void)lib_handle;

    INIT_CPC_RET(int);
    cpc_croe_exange_buffer_t *query = NULL;
    ssize_t bytes_written = 0;
    ssize_t bytes_read = 0;
    const size_t query_len = sizeof(cpc_croe_exange_buffer_t) + payload_sz;

    query = calloc_port(query_len);
    if (query == NULL)
    {
        SET_CPC_RET(-ENOMEM);
        RETURN_CPC_RET;
    }

    query->type = type;
    query->endpoint_number = ep_id;
    if (payload_sz)
    {
        memcpy(query->payload, payload, payload_sz);
    }

    bytes_written = send(fd, query, query_len, 0);
    if (bytes_written < (ssize_t)query_len)
    {
        if (bytes_written == -1)
        {
            SET_CPC_RET(-errno);
        } else
        {
            SET_CPC_RET(-EBADE);
        }
        goto free_query;
    }

    bytes_read = recv(fd, query, query_len, 0);
    if (bytes_read != (ssize_t)query_len)
    {
        if (bytes_read == 0)
        {
            SET_CPC_RET(-ECONNRESET);
        } else if (bytes_read == -1)
        {
            SET_CPC_RET(-errno);
        } else
        {
            SET_CPC_RET(-EBADE);
        }
        goto free_query;
    }

    if (payload_sz)
    {
        memcpy(payload, query->payload, payload_sz);
    }

 free_query:
    free(query);

    RETURN_CPC_RET;
}

static int cpc_query_receive(__cpc_handle_t *lib_handle, int fd, void *payload, size_t payload_sz)
{
    (void)lib_handle;
    INIT_CPC_RET(int);
    cpc_croe_exange_buffer_t *query = NULL;
    ssize_t bytes_read = 0;
    const size_t query_len = sizeof(cpc_croe_exange_buffer_t) + payload_sz;

    query = calloc_port(query_len);
    if (query == NULL)
    {
        SET_CPC_RET(-ENOMEM);
        RETURN_CPC_RET;
    }

    bytes_read = recv(fd, query, query_len, 0);
    if (bytes_read != (ssize_t)query_len)
    {
        if (bytes_read == 0)
        {
            SET_CPC_RET(-ECONNRESET);
        } else if (bytes_read == -1)
        {
            SET_CPC_RET(-errno);
        } else
        {
            SET_CPC_RET(-EBADE);
        }

        goto free_query;
    }

    if (payload_sz && payload)
    {
        memcpy(payload, query->payload, payload_sz);
    }

 free_query:
    free(query);

    RETURN_CPC_RET;
}

static int get_max_write(__cpc_handle_t *lib_handle)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    uint32_t max_write_size = 0;

    tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_MAX_WRITE_SIZE_QUERY, 0,
                                 (void *)&max_write_size, sizeof(max_write_size));

    if (tmp_ret == 0)
    {
        lib_handle->max_write_size = (size_t)max_write_size;
    } else
    {
        SET_CPC_RET(tmp_ret);
    }

    RETURN_CPC_RET;
}

static int check_version(__cpc_handle_t *lib_handle)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    char version[PROJECT_MAX_VERSION_SIZE];

    strncpy(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE);

    tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_VERSION_QUERY, 0,
                                 (void *)version, PROJECT_MAX_VERSION_SIZE);

    if (tmp_ret)
    {
        SET_CPC_RET(tmp_ret);
        RETURN_CPC_RET;
    }

    if (strncmp(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE) != 0)
    {
        SET_CPC_RET(-ELIBBAD);
        RETURN_CPC_RET;
    }

    RETURN_CPC_RET;
}


static int set_pid(__cpc_handle_t *lib_handle)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    bool can_connect = false;
    ssize_t bytes_written = 0;
    const pid_t pid = getpid();
    const size_t set_pid_query_len = sizeof(cpc_croe_exange_buffer_t) + sizeof(pid_t);
    uint8_t buf[set_pid_query_len];
    cpc_croe_exange_buffer_t *set_pid_query = (cpc_croe_exange_buffer_t *)buf;

    set_pid_query->type = EXCHANGE_SET_PID_QUERY;
    set_pid_query->endpoint_number = 0;

    memcpy(set_pid_query->payload, &pid, sizeof(pid_t));

    bytes_written = send(lib_handle->ctrl_sock_fd, set_pid_query, set_pid_query_len, 0);
    if (bytes_written < (ssize_t)set_pid_query_len)
    {
        SET_CPC_RET(-errno);
        RETURN_CPC_RET;
    }

    tmp_ret = cpc_query_receive(lib_handle, lib_handle->ctrl_sock_fd, &can_connect, sizeof(bool));
    if (tmp_ret == 0)
    {
        if (!can_connect)
        {
            SET_CPC_RET(-ELIBMAX);
            RETURN_CPC_RET;
        }
    } else
    {
        SET_CPC_RET(tmp_ret);
        RETURN_CPC_RET;
    }

    RETURN_CPC_RET;
}


int libcpc_init(cpc_handle_t *handle, const char *instance_name, cpc_reset_cb_t reset_cb)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    __cpc_handle_t *lib_handle = NULL;
    struct sockaddr_un server_addr = { 0 };

    if (handle == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    lib_handle = calloc_port(sizeof(__cpc_handle_t));
    if (lib_handle == NULL)
    {
        SET_CPC_RET(-ENOMEM);
        RETURN_CPC_RET;
    }

    saved_reset_cb = reset_cb;

    if (instance_name == NULL)
    {
        /* If the instance name is NULL, use the default name */
        lib_handle->instance_name = strdup(DEFAULT_INSTANCE_NAME);
        if (lib_handle->instance_name == NULL)
        {
            SET_CPC_RET(-errno);
            goto free_lib_handle;
        }
    } else
    {
        /* Instead, use the one supplied by the user */
        lib_handle->instance_name = strdup(instance_name);
        if (lib_handle->instance_name == NULL)
        {
            SET_CPC_RET(-errno);
            goto free_lib_handle;
        }
    }

    /* Create the control socket path */
    {
        int nchars;
        const size_t size = sizeof(server_addr.sun_path) - 1;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sun_family = AF_UNIX;

        nchars = snprintf(server_addr.sun_path, size, "%s/cpcd/%s/ctrl.cpcd.sock", CPC_SOCKET_DIR, lib_handle->instance_name);

        /* Make sure the path fitted entirely in the struct's static buffer */
        if (nchars < 0 || (size_t)nchars >= size)
        {
            SET_CPC_RET(-ERANGE);
            goto free_instance_name;
        }
    }

    // Check if control socket exists
    if (access(server_addr.sun_path, F_OK) != 0)
    {
        SET_CPC_RET(-errno);
        goto free_instance_name;
    }

    lib_handle->ctrl_sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (lib_handle->ctrl_sock_fd < 0)
    {
        SET_CPC_RET(-errno);
        goto free_instance_name;
    }

    if (connect(lib_handle->ctrl_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        SET_CPC_RET(-errno);
        goto close_ctrl_sock_fd;
    }

    // Set ctrl socket timeout
    struct timeval timeout;
    timeout.tv_sec = CTRL_SOCKET_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if (setsockopt(lib_handle->ctrl_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
    {
        SET_CPC_RET(-errno);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = check_version(lib_handle);
    if (tmp_ret < 0)
    {
        SET_CPC_RET(tmp_ret);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = set_pid(lib_handle);
    if (tmp_ret < 0)
    {
        SET_CPC_RET(tmp_ret);
        goto close_ctrl_sock_fd;
    }

    // Check if reset callback is define
    if (reset_cb != NULL)
    {
        signal(SIGUSR1, SIGUSR1_handler);
    }

    // Check if control socket exists
    if (access(server_addr.sun_path, F_OK) != 0)
    {
        SET_CPC_RET(-errno);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = get_max_write(lib_handle);
    if (tmp_ret < 0)
    {
        SET_CPC_RET(tmp_ret);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = pthread_mutex_init(&lib_handle->ctrl_sock_fd_lock, NULL);
    if (tmp_ret != 0)
    {
        SET_CPC_RET(-tmp_ret);
        goto free_secondary_app_version;
    }

    lib_handle->initialized = true;
    handle->ptr = (void *)lib_handle;
    RETURN_CPC_RET;

 free_secondary_app_version:
    free(lib_handle->secondary_app_version);

 close_ctrl_sock_fd:
    if (close(lib_handle->ctrl_sock_fd) < 0)
    {
        SET_CPC_RET(-errno);
    }

 free_instance_name:
    free(lib_handle->instance_name);

 free_lib_handle:
    free(lib_handle);

    RETURN_CPC_RET;
}

int cpc_deinit(cpc_handle_t *handle)
{
    INIT_CPC_RET(int);
    __cpc_handle_t *lib_handle = NULL;

    if (handle->ptr == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    lib_handle = (__cpc_handle_t *)handle->ptr;

    pthread_mutex_destroy(&lib_handle->ctrl_sock_fd_lock);

    free(lib_handle->instance_name);
    free(lib_handle->secondary_app_version);
    free(lib_handle);

    handle->ptr = NULL;

    RETURN_CPC_RET;
}

int libcpc_reset(cpc_handle_t *handle)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    __cpc_handle_t *lib_handle = NULL;

    if (handle->ptr == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    lib_handle = (__cpc_handle_t *)handle->ptr;

    __cpc_handle_t *lib_handle_copy = calloc_port(sizeof(__cpc_handle_t));
    if (lib_handle_copy == NULL)
    {
        SET_CPC_RET(-ENOMEM);
        RETURN_CPC_RET;
    }

    memcpy(lib_handle_copy, lib_handle, sizeof(__cpc_handle_t));
    lib_handle_copy->instance_name = strdup(lib_handle->instance_name);
    if (lib_handle_copy->instance_name == NULL)
    {
        free(lib_handle_copy);
        SET_CPC_RET(-errno);
        RETURN_CPC_RET;
    }

    // De-init the original handle
    if (lib_handle_copy->initialized)
    {
        tmp_ret = cpc_deinit(handle);
        if (tmp_ret != 0)
        {
            // Restore the handle copy on failure
            free(lib_handle_copy->instance_name);
            lib_handle_copy->instance_name = lib_handle->instance_name;
            handle->ptr = (void *)lib_handle_copy;

            SET_CPC_RET(tmp_ret);
            RETURN_CPC_RET;
        }
    }

    // De-init was successful, invalidate copy
    lib_handle_copy->initialized = false;

    // Attemps a connection
    tmp_ret = libcpc_init(handle, lib_handle_copy->instance_name, saved_reset_cb);
    if (tmp_ret != 0)
    {
        sleep_ms(CPCD_REBOOT_TIME_MS); // Wait for the minimum time it takes for CPCd to reboot
        tmp_ret = libcpc_init(handle, lib_handle_copy->instance_name, saved_reset_cb);
        if (tmp_ret != 0)
        {
            // Restore the handle copy on failure
            handle->ptr = (void *)lib_handle_copy;

            SET_CPC_RET(tmp_ret);
            RETURN_CPC_RET;
        }
    }

    // On success we can free the lib_handle_copy
    free(lib_handle_copy->instance_name);
    free(lib_handle_copy);

    RETURN_CPC_RET;
}

int libcpc_open_ep(cpc_handle_t handle, cpc_ep_t *endpoint, uint8_t id, uint8_t tx_win_size)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    int tmp_ret2 = 0;
    bool can_open = false;
    __cpc_handle_t *lib_handle = NULL;
    __cpc_ep_t *ep = NULL;
    struct sockaddr_un ep_addr = { 0 };

    if (id == CPC_EP_SYSTEM || endpoint == NULL || handle.ptr == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    lib_handle = (__cpc_handle_t *)handle.ptr;

    if (tx_win_size != 1)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    ep_addr.sun_family = AF_UNIX;

    /* Create the endpoint socket path */
    {
        int nchars;
        const size_t size = sizeof(ep_addr.sun_path) - 1;

        nchars = snprintf(ep_addr.sun_path, size, "%s/cpcd/%s/ep%d.cpcd.sock", CPC_SOCKET_DIR, lib_handle->instance_name, id);

        /* Make sure the path fitted entirely in the struct sockaddr_un's static buffer */
        if (nchars < 0 || (size_t)nchars >= size)
        {
            SET_CPC_RET(-ERANGE);
            RETURN_CPC_RET;
        }
    }

    ep = calloc_port(sizeof(__cpc_ep_t));
    if (ep == NULL)
    {
        SET_CPC_RET(-ERANGE);
        RETURN_CPC_RET;
    }

    ep->id = id;
    ep->lib_handle = lib_handle;

    tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret != 0)
    {
        SET_CPC_RET(-tmp_ret);
        goto free_endpoint;
    }

    tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_OPEN_EP_QUERY, id,
                                 (void *)&can_open, sizeof(can_open));

    if (tmp_ret)
    {
        SET_CPC_RET(tmp_ret);
    }

    tmp_ret2 = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret2 != 0)
    {
        SET_CPC_RET(-tmp_ret2);
        goto free_endpoint;
    }

    if (tmp_ret)
    {
        goto free_endpoint;
    }

    if (can_open == false)
    {
        SET_CPC_RET(-EAGAIN);
        goto free_endpoint;
    }

    ep->sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (ep->sock_fd < 0)
    {
        SET_CPC_RET(-errno);
        goto free_endpoint;
    }

    tmp_ret = connect(ep->sock_fd, (struct sockaddr *)&ep_addr, sizeof(ep_addr));
    if (tmp_ret < 0)
    {
        SET_CPC_RET(-errno);
        goto close_sock_fd;
    }

    tmp_ret = cpc_query_receive(lib_handle, ep->sock_fd, (void *)&ep->server_sock_fd, sizeof(ep->server_sock_fd));
    if (tmp_ret)
    {
        SET_CPC_RET(tmp_ret);
        goto close_sock_fd;
    }

    int ep_socket_size = DEFAULT_EP_SOCKET_SIZE;
    tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, &ep_socket_size, sizeof(int));
    if (tmp_ret != 0)
    {
        SET_CPC_RET(-errno);
        goto close_sock_fd;
    }

    tmp_ret = pthread_mutex_init(&ep->sock_fd_lock, NULL);
    if (tmp_ret != 0)
    {
        SET_CPC_RET(-tmp_ret);
        goto close_sock_fd;
    }

    endpoint->ptr = (void *)ep;

    SET_CPC_RET(ep->sock_fd);
    RETURN_CPC_RET;

 close_sock_fd:
    if (close(ep->sock_fd) < 0)
    {
        SET_CPC_RET(-errno);
    }

 free_endpoint:
    free(ep);

    RETURN_CPC_RET;
}

int libcpc_close_ep(cpc_ep_t *endpoint)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    __cpc_handle_t *lib_handle = NULL;
    __cpc_ep_t *ep = NULL;

    if (endpoint == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    ep = (__cpc_ep_t *)endpoint->ptr;
    if (ep == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    lib_handle = ep->lib_handle;

    tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret != 0)
    {
        goto destroy_mutex;
    }

    tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_CLOSE_EP_QUERY, ep->id,
                                 (void *)&ep->server_sock_fd, sizeof(ep->server_sock_fd));

    if (close(ep->sock_fd) < 0)
    {
        goto unlock_mutex;
    }
    ep->sock_fd = -1;

    tmp_ret = cpc_query_receive(lib_handle, lib_handle->ctrl_sock_fd, NULL, sizeof(int));
 unlock_mutex:
    tmp_ret = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);


 destroy_mutex:
    tmp_ret = pthread_mutex_destroy(&ep->sock_fd_lock);

    free(ep);
    endpoint->ptr = NULL;

    RETURN_CPC_RET;
}

ssize_t libcpc_read_ep(cpc_ep_t endpoint, void *buffer, size_t count, cpc_ep_read_flags_t flags)
{
    INIT_CPC_RET(ssize_t);
    int sock_flags = 0;
    ssize_t bytes_read = 0;
    __cpc_ep_t *ep = NULL;

    if (buffer == NULL || count < LIB_CPC_READ_MINIMUM_SIZE || endpoint.ptr == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    ep = (__cpc_ep_t *)endpoint.ptr;


    if (flags & CPC_EP_READ_FLAG_NON_BLOCKING)
    {
        sock_flags |= MSG_DONTWAIT;
    }

    bytes_read = recv(ep->sock_fd, buffer, count, sock_flags);
    if (bytes_read == 0)
    {
        SET_CPC_RET(-ECONNRESET);
    } else if (bytes_read < 0)
    {
        SET_CPC_RET(-errno);
    } else
    {
        SET_CPC_RET(bytes_read);
    }

    RETURN_CPC_RET;
}


ssize_t libcpc_write_ep(cpc_ep_t endpoint, const void *data, size_t data_length, cpc_ep_write_flags_t flags)
{
    INIT_CPC_RET(ssize_t);
    int sock_flags = 0;
    ssize_t bytes_written = 0;
    __cpc_ep_t *ep = NULL;

    if (endpoint.ptr == NULL || data == NULL || data_length == 0)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    ep = (__cpc_ep_t *)endpoint.ptr;

    if (data_length > ep->lib_handle->max_write_size)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    if (flags & CPC_EP_WRITE_FLAG_NON_BLOCKING)
    {
        sock_flags |= MSG_DONTWAIT;
    }

    bytes_written = send(ep->sock_fd, data, data_length, sock_flags);
    if (bytes_written == -1)
    {
        SET_CPC_RET(-errno);
        RETURN_CPC_RET;
    } else
    {
        SET_CPC_RET(bytes_written);
    }
    assert((size_t)bytes_written == data_length);

    RETURN_CPC_RET;
}

int libcpc_get_ep_state(cpc_handle_t handle, uint8_t id, cpc_ep_state_t *state)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    __cpc_handle_t *lib_handle = NULL;

    if (state == NULL || handle.ptr == NULL || id == CPC_EP_SYSTEM)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    lib_handle = (__cpc_handle_t *)handle.ptr;

    tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret != 0)
    {
        SET_CPC_RET(-tmp_ret);
        RETURN_CPC_RET;
    }


    tmp_ret = cpc_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_EP_STATUS_QUERY, id,
                                 (void *)state, sizeof(cpc_ep_state_t));

    tmp_ret = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret != 0)
    {
        SET_CPC_RET(-tmp_ret);
        RETURN_CPC_RET;
    }

    RETURN_CPC_RET;
}

int libcpc_set_ep_option(cpc_ep_t endpoint, cpc_option_t option, const void *optval, size_t optlen)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    __cpc_ep_t *ep = NULL;

    if (option == CPC_OPTION_NONE || endpoint.ptr == NULL || optval == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    ep = (__cpc_ep_t *)endpoint.ptr;

    if (option == CPC_OPTION_RX_TIMEOUT)
    {
        cpc_timeval_t *useropt = (cpc_timeval_t *)optval;
        struct timeval sockopt;

        if (optlen != sizeof(cpc_timeval_t))
        {
            SET_CPC_RET(-EINVAL);
            RETURN_CPC_RET;
        }

        sockopt.tv_sec = useropt->seconds;
        sockopt.tv_usec = useropt->microseconds;

        tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
        if (tmp_ret < 0)
        {
            SET_CPC_RET(-errno);
            RETURN_CPC_RET;
        }
    } else if (option == CPC_OPTION_TX_TIMEOUT)
    {
        cpc_timeval_t *useropt = (cpc_timeval_t *)optval;
        struct timeval sockopt;

        if (optlen != sizeof(cpc_timeval_t))
        {
            SET_CPC_RET(-EINVAL);
            RETURN_CPC_RET;
        }

        sockopt.tv_sec = useropt->seconds;
        sockopt.tv_usec = useropt->microseconds;

        tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
        if (tmp_ret < 0)
        {
            SET_CPC_RET(-errno);
            RETURN_CPC_RET;
        }
    } else if (option == CPC_OPTION_BLOCKING)
    {
        if (optlen != sizeof(bool))
        {
            SET_CPC_RET(-EINVAL);
            RETURN_CPC_RET;
        }

        tmp_ret = pthread_mutex_lock(&ep->sock_fd_lock);
        if (tmp_ret != 0)
        {
            SET_CPC_RET(-tmp_ret);
            RETURN_CPC_RET;
        }

        int flags = fcntl(ep->sock_fd, F_GETFL);
        if (flags < 0)
        {
            SET_CPC_RET(-errno);

            tmp_ret = pthread_mutex_unlock(&ep->sock_fd_lock);
            if (tmp_ret != 0)
            {
                SET_CPC_RET(-tmp_ret);
            }

            RETURN_CPC_RET;
        }

        if (*(bool *)optval == true)
        {
            flags &= ~O_NONBLOCK;
        } else
        {
            flags |= O_NONBLOCK;
        }

        tmp_ret = fcntl(ep->sock_fd, F_SETFL, flags);
        if (tmp_ret < 0)
        {
            SET_CPC_RET(-errno);
        }

        tmp_ret = pthread_mutex_unlock(&ep->sock_fd_lock);
        if (tmp_ret != 0)
        {
            SET_CPC_RET(-tmp_ret);
        }

        RETURN_CPC_RET;
    } else if (option == CPC_OPTION_SOCKET_SIZE)
    {
        if (optlen != sizeof(int))
        {
            SET_CPC_RET(-EINVAL);
            RETURN_CPC_RET;
        }

        if (setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, (socklen_t)optlen) != 0)
        {
            SET_CPC_RET(-errno);
            RETURN_CPC_RET;
        }
    } else
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    RETURN_CPC_RET;
}

int libcpc_get_ep_option(cpc_ep_t endpoint, cpc_option_t option, void *optval, size_t *optlen)
{
    INIT_CPC_RET(int);
    int tmp_ret = 0;
    __cpc_ep_t *ep = NULL;

    if (option == CPC_OPTION_NONE || endpoint.ptr == NULL || optval == NULL || optlen == NULL)
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    ep = (__cpc_ep_t *)endpoint.ptr;

    if (option == CPC_OPTION_RX_TIMEOUT)
    {
        cpc_timeval_t *useropt = (cpc_timeval_t *)optval;
        struct timeval sockopt;
        socklen_t socklen = sizeof(sockopt);

        if (*optlen != sizeof(cpc_timeval_t))
        {
            SET_CPC_RET(-EINVAL);
            RETURN_CPC_RET;
        }

        tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, &socklen);
        if (tmp_ret < 0)
        {
            SET_CPC_RET(-errno);
            RETURN_CPC_RET;
        }

        // these values are "usually" of type long, so make sure they
        // fit in integers (really, they should).
        if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX)
        {
            SET_CPC_RET(-EINVAL);
            RETURN_CPC_RET;
        }

        useropt->seconds = (int)sockopt.tv_sec;
        useropt->microseconds = (int)sockopt.tv_usec;
    } else if (option == CPC_OPTION_TX_TIMEOUT)
    {
        cpc_timeval_t *useropt = (cpc_timeval_t *)optval;
        struct timeval sockopt;
        socklen_t socklen = sizeof(sockopt);

        if (*optlen != sizeof(cpc_timeval_t))
        {
            SET_CPC_RET(-EINVAL);
            RETURN_CPC_RET;
        }

        tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &sockopt, &socklen);
        if (tmp_ret < 0)
        {
            SET_CPC_RET(-errno);
            RETURN_CPC_RET;
        }

        if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX)
        {
            SET_CPC_RET(-EINVAL);
            RETURN_CPC_RET;
        }

        useropt->seconds = (int)sockopt.tv_sec;
        useropt->microseconds = (int)sockopt.tv_usec;
    } else if (option == CPC_OPTION_BLOCKING)
    {
        if (*optlen < sizeof(bool))
        {
            SET_CPC_RET(-ENOMEM);
            RETURN_CPC_RET;
        }

        *optlen = sizeof(bool);

        int flags = fcntl(ep->sock_fd, F_GETFL);
        if (flags < 0)
        {
            SET_CPC_RET(-errno);
            RETURN_CPC_RET;
        }

        if (flags & O_NONBLOCK)
        {
            *(bool *)optval = false;
        } else
        {
            *(bool *)optval = true;
        }
    } else if (option == CPC_OPTION_SOCKET_SIZE)
    {
        socklen_t socklen = (socklen_t)*optlen;

        if (*optlen < sizeof(int))
        {
            SET_CPC_RET(-ENOMEM);
            RETURN_CPC_RET;
        }

        tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, &socklen);
        if (tmp_ret < 0)
        {
            SET_CPC_RET(-errno);
            RETURN_CPC_RET;
        }

        *optlen = (size_t)socklen;
    } else if (option == CPC_OPTION_MAX_WRITE_SIZE)
    {
        *optlen = sizeof(size_t);
        memcpy(optval, &ep->lib_handle->max_write_size, sizeof(ep->lib_handle->max_write_size));
    } else
    {
        SET_CPC_RET(-EINVAL);
        RETURN_CPC_RET;
    }

    RETURN_CPC_RET;
}

const char *libcpc_get_lib_ver(void)
{
    return PROJECT_VER;
}

