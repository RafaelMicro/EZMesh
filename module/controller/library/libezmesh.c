/**
 * @file libezmesh.c
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

#include "libezmesh.h"
#include "version.h"
#include "utility/utility.h"
#include "host/hal_sleep.h"

//=============================================================================
//                  Constant Definition
//=============================================================================
#ifndef DEFAULT_INSTANCE_NAME
  #define DEFAULT_INSTANCE_NAME "ezmeshd_0"
#endif

#define CTRL_SOCKET_TIMEOUT_SEC 2

#define DEFAULT_EP_SOCKET_SIZE LIB_EZMESH_READ_MINIMUM_SIZE
//=============================================================================
//                  Macro Definition
//=============================================================================
#define INIT_EZMESH_RET(type) type __ezmesh_ret = 0
#define RETURN_EZMESH_RET return __ezmesh_ret
#define SET_EZMESH_RET(error) \
    do {                     \
        if (__ezmesh_ret == 0) {  \
            __ezmesh_ret = error;   \
        }                      \
    } while (0)

//=============================================================================
//                  Structure Definition
//=============================================================================
typedef struct
{
    uint8_t id;
    int server_sock_fd;
    int sock_fd;
    pthread_mutex_t sock_fd_lock;
    ezmesh_handle_inst_t *lib_handle;
} __ezmesh_ep_t;

typedef struct
{
    int endpoint_id;
    int sock_fd;
    pthread_mutex_t sock_fd_lock;
    ezmesh_handle_inst_t *lib_handle;
} __ezmesh_ep_event_handle_t;

//=============================================================================
//                  Global Data Definition
//=============================================================================
static ezmesh_reset_cb_t saved_reset_cb;
//=============================================================================
//                  Private Function Definition
//=============================================================================
static ezmesh_reset_cb_t saved_reset_cb;
int ezmesh_deinit(ezmesh_handle_t *handle);

static void SIGUSR1_handler(int signum)
{
    (void)signum;
    if (saved_reset_cb != NULL) saved_reset_cb();
}

static int ezmesh_query_exchange(ezmesh_handle_inst_t *lib_handle, int fd, ezmesh_ezmeshd_exchange_type_t type, uint8_t ep_id,
                              void *payload, size_t payload_sz)
{
    (void)lib_handle;
    INIT_EZMESH_RET(int);
    ezmesh_croe_exange_buffer_t *query = NULL;
    ssize_t bytes_written = 0;
    ssize_t bytes_read = 0;
    const size_t query_len = sizeof(ezmesh_croe_exange_buffer_t) + payload_sz;

    query = calloc(1, query_len);
    if (query == NULL)
    {
        SET_EZMESH_RET(-ENOMEM);
        RETURN_EZMESH_RET;
    }

    query->type = type;
    query->endpoint_number = ep_id;
    if (payload_sz) memcpy(query->payload, payload, payload_sz);

    bytes_written = send(fd, query, query_len, 0);
    if (bytes_written < (ssize_t)query_len)
    {
        if (bytes_written == -1) SET_EZMESH_RET(-errno);
        else SET_EZMESH_RET(-EBADE);
        goto free_query;
    }

    bytes_read = recv(fd, query, query_len, 0);
    if (bytes_read != (ssize_t)query_len)
    {
        if (bytes_read == 0) SET_EZMESH_RET(-ECONNRESET);
        else if (bytes_read == -1) SET_EZMESH_RET(-errno);
        else SET_EZMESH_RET(-EBADE);
        goto free_query;
    }

    if (payload_sz) memcpy(payload, query->payload, payload_sz);

 free_query:
    free(query);

    RETURN_EZMESH_RET;
}

static int ezmesh_query_receive(ezmesh_handle_inst_t *lib_handle, int fd, void *payload, size_t payload_sz)
{
    (void)lib_handle;
    INIT_EZMESH_RET(int);
    ezmesh_croe_exange_buffer_t *query = NULL;
    ssize_t bytes_read = 0;
    const size_t query_len = sizeof(ezmesh_croe_exange_buffer_t) + payload_sz;

    query = calloc(1, query_len);
    if (query == NULL)
    {
        SET_EZMESH_RET(-ENOMEM);
        RETURN_EZMESH_RET;
    }

    bytes_read = recv(fd, query, query_len, 0);
    if (bytes_read != (ssize_t)query_len)
    {
        if (bytes_read == 0) SET_EZMESH_RET(-ECONNRESET);
        else if (bytes_read == -1) SET_EZMESH_RET(-errno);
        else SET_EZMESH_RET(-EBADE);
        goto free_query;
    }

    if (payload_sz && payload) memcpy(payload, query->payload, payload_sz);

 free_query:
    free(query);
    RETURN_EZMESH_RET;
}

static int get_max_write(ezmesh_handle_inst_t *lib_handle)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    uint32_t max_write_size = 0;

    tmp_ret = ezmesh_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_MAX_WRITE_SIZE_QUERY, 0,
                                 (void *)&max_write_size, sizeof(max_write_size));

    if (tmp_ret == 0) lib_handle->max_write_size = (size_t)max_write_size;
    else SET_EZMESH_RET(tmp_ret);

    RETURN_EZMESH_RET;
}
static int get_agent_app_version(ezmesh_handle_inst_t *lib_handle)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;

    char version[PROJECT_MAX_VERSION_SIZE];


    tmp_ret = ezmesh_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_GET_AGENT_APP_VERSION_QUERY, 0,
                                 (void *)version, PROJECT_MAX_VERSION_SIZE);
    if (tmp_ret)
    {
        SET_EZMESH_RET(tmp_ret);
        RETURN_EZMESH_RET;
    }

    strncpy(lib_handle->agent_app_version, version, PROJECT_MAX_VERSION_SIZE);

    RETURN_EZMESH_RET;

}

static int check_version(ezmesh_handle_inst_t *lib_handle)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    char version[PROJECT_MAX_VERSION_SIZE];

    strncpy(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE);

    tmp_ret = ezmesh_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_VERSION_QUERY, 0,
                                 (void *)version, PROJECT_MAX_VERSION_SIZE);

    if (tmp_ret)
    {
        SET_EZMESH_RET(tmp_ret);
        RETURN_EZMESH_RET;
    }

    if (strncmp(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE) != 0)
    {
        SET_EZMESH_RET(-ELIBBAD);
        RETURN_EZMESH_RET;
    }

    RETURN_EZMESH_RET;
}


static int set_pid(ezmesh_handle_inst_t *lib_handle)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    bool can_connect = false;
    ssize_t bytes_written = 0;
    const pid_t pid = getpid();
    const size_t set_pid_query_len = sizeof(ezmesh_croe_exange_buffer_t) + sizeof(pid_t);
    uint8_t buf[set_pid_query_len];
    ezmesh_croe_exange_buffer_t *set_pid_query = (ezmesh_croe_exange_buffer_t *)buf;

    set_pid_query->type = EXCHANGE_SET_PID_QUERY;
    set_pid_query->endpoint_number = 0;

    memcpy(set_pid_query->payload, &pid, sizeof(pid_t));

    bytes_written = send(lib_handle->ctrl_sock_fd, set_pid_query, set_pid_query_len, 0);
    if (bytes_written < (ssize_t)set_pid_query_len)
    {
        SET_EZMESH_RET(-errno);
        RETURN_EZMESH_RET;
    }

    tmp_ret = ezmesh_query_receive(lib_handle, lib_handle->ctrl_sock_fd, &can_connect, sizeof(bool));
    if (tmp_ret == 0)
    {
        if (!can_connect)
        {
            SET_EZMESH_RET(-ELIBMAX);
            RETURN_EZMESH_RET;
        }
    } else
    {
        SET_EZMESH_RET(tmp_ret);
        RETURN_EZMESH_RET;
    }

    RETURN_EZMESH_RET;
}


int libezmesh_init(ezmesh_handle_t *handle, const char *instance_name, ezmesh_reset_cb_t reset_cb)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    ezmesh_handle_inst_t *lib_handle = NULL;
    struct sockaddr_un server_addr = { 0 };

    if (handle == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    lib_handle = calloc(1, sizeof(ezmesh_handle_inst_t));
    if (lib_handle == NULL)
    {
        SET_EZMESH_RET(-ENOMEM);
        RETURN_EZMESH_RET;
    }

    saved_reset_cb = reset_cb;

    lib_handle->instance_name = strdup((instance_name == NULL)? DEFAULT_INSTANCE_NAME : instance_name);
    if (lib_handle->instance_name == NULL)
    {
        SET_EZMESH_RET(-errno);
        goto free_lib_handle;
    }

    /* Create the control socket path */
    int nchars;
    const size_t size = sizeof(server_addr.sun_path) - 1;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;

    nchars = snprintf(server_addr.sun_path, size, "%s/%s/ep0.sock", EZMESH_SOCKET_DIR, lib_handle->instance_name);
    /* Make sure the path fitted entirely in the struct's static buffer */
    if (nchars < 0 || (size_t)nchars >= size)
    {
        SET_EZMESH_RET(-ERANGE);
        goto free_instance_name;
    }

    // Check if control socket exists
    if (access(server_addr.sun_path, F_OK) != 0)
    {
        SET_EZMESH_RET(-errno);
        goto free_instance_name;
    }

    lib_handle->ctrl_sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (lib_handle->ctrl_sock_fd < 0)
    {
        SET_EZMESH_RET(-errno);
        goto free_instance_name;
    }

    if (connect(lib_handle->ctrl_sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        SET_EZMESH_RET(-errno);
        goto close_ctrl_sock_fd;
    }

    // Set ctrl socket timeout
    struct timeval timeout;
    timeout.tv_sec = CTRL_SOCKET_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    if (setsockopt(lib_handle->ctrl_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
    {
        SET_EZMESH_RET(-errno);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = check_version(lib_handle);
    if (tmp_ret < 0)
    {
        SET_EZMESH_RET(tmp_ret);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = get_agent_app_version(lib_handle);

    if (tmp_ret < 0)
    {
        SET_EZMESH_RET(tmp_ret);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = set_pid(lib_handle);
    if (tmp_ret < 0)
    {
        SET_EZMESH_RET(tmp_ret);
        goto close_ctrl_sock_fd;
    }

    // Check if reset callback is define
    if (reset_cb != NULL) signal(SIGUSR1, SIGUSR1_handler);

    // Check if control socket exists
    if (access(server_addr.sun_path, F_OK) != 0)
    {
        SET_EZMESH_RET(-errno);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = get_max_write(lib_handle);
    if (tmp_ret < 0)
    {
        SET_EZMESH_RET(tmp_ret);
        goto close_ctrl_sock_fd;
    }

    tmp_ret = pthread_mutex_init(&lib_handle->ctrl_sock_fd_lock, NULL);
    if (tmp_ret != 0)
    {
        SET_EZMESH_RET(-tmp_ret);
        goto close_ctrl_sock_fd;
    }

    lib_handle->initialized = true;
    handle->ptr = (void *)lib_handle;
    RETURN_EZMESH_RET;

 close_ctrl_sock_fd:
    if (close(lib_handle->ctrl_sock_fd) < 0) SET_EZMESH_RET(-errno);

 free_instance_name:
    free(lib_handle->instance_name);

 free_lib_handle:
    free(lib_handle);

    RETURN_EZMESH_RET;
}

int ezmesh_deinit(ezmesh_handle_t *handle)
{
    INIT_EZMESH_RET(int);
    ezmesh_handle_inst_t *lib_handle = NULL;

    if (handle->ptr == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    lib_handle = (ezmesh_handle_inst_t *)handle->ptr;

    pthread_mutex_destroy(&lib_handle->ctrl_sock_fd_lock);

    free(lib_handle->instance_name);
    free(lib_handle);

    handle->ptr = NULL;

    RETURN_EZMESH_RET;
}

int libezmesh_reset(ezmesh_handle_t *handle)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    ezmesh_handle_inst_t *lib_handle = NULL;

    if (handle->ptr == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    lib_handle = (ezmesh_handle_inst_t *)handle->ptr;

    ezmesh_handle_inst_t *lib_handle_copy = calloc(1, sizeof(ezmesh_handle_inst_t));
    if (lib_handle_copy == NULL)
    {
        SET_EZMESH_RET(-ENOMEM);
        RETURN_EZMESH_RET;
    }

    memcpy(lib_handle_copy, lib_handle, sizeof(ezmesh_handle_inst_t));
    lib_handle_copy->instance_name = strdup(lib_handle->instance_name);
    if (lib_handle_copy->instance_name == NULL)
    {
        free(lib_handle_copy);
        SET_EZMESH_RET(-errno);
        RETURN_EZMESH_RET;
    }

    // De-init the original handle
    if (lib_handle_copy->initialized)
    {
        tmp_ret = ezmesh_deinit(handle);
        if (tmp_ret != 0)
        {
            // Restore the handle copy on failure
            free(lib_handle_copy->instance_name);
            lib_handle_copy->instance_name = lib_handle->instance_name;
            handle->ptr = (void *)lib_handle_copy;

            SET_EZMESH_RET(tmp_ret);
            RETURN_EZMESH_RET;
        }
    }

    // De-init was successful, invalidate copy
    lib_handle_copy->initialized = false;

    // Attemps a connection
    tmp_ret = libezmesh_init(handle, lib_handle_copy->instance_name, saved_reset_cb);
    if (tmp_ret != 0)
    {
        hal_sleep_ms(EZMESHD_REBOOT_TIME_MS); // Wait for the minimum time it takes for EZMESHd to reboot
        tmp_ret = libezmesh_init(handle, lib_handle_copy->instance_name, saved_reset_cb);
        if (tmp_ret != 0)
        {
            // Restore the handle copy on failure
            handle->ptr = (void *)lib_handle_copy;

            SET_EZMESH_RET(tmp_ret);
            RETURN_EZMESH_RET;
        }
    }

    // On success we can free the lib_handle_copy
    free(lib_handle_copy->instance_name);
    free(lib_handle_copy);

    RETURN_EZMESH_RET;
}

int libezmesh_open_ep(ezmesh_handle_t handle, ezmesh_ep_t *endpoint, uint8_t id, uint8_t tx_win_size)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    int tmp_ret2 = 0;
    bool can_open = false;
    ezmesh_handle_inst_t *lib_handle = NULL;
    __ezmesh_ep_t *ep = NULL;
    struct sockaddr_un ep_addr = { 0 };

    if (id == EP_SYSTEM || endpoint == NULL || handle.ptr == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    lib_handle = (ezmesh_handle_inst_t *)handle.ptr;

    if (tx_win_size != 1)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    ep_addr.sun_family = AF_UNIX;

    /* Create the endpoint socket path */
    int nchars;
    const size_t size = sizeof(ep_addr.sun_path) - 1;
    nchars = snprintf(ep_addr.sun_path, size, "%s/%s/ep%d.sock", EZMESH_SOCKET_DIR, lib_handle->instance_name, id);
    /* Make sure the path fitted entirely in the struct sockaddr_un's static buffer */
    if (nchars < 0 || (size_t)nchars >= size)
    {
        SET_EZMESH_RET(-ERANGE);
        RETURN_EZMESH_RET;
    }

    ep = calloc(1, sizeof(__ezmesh_ep_t));
    if (ep == NULL)
    {
        SET_EZMESH_RET(-ERANGE);
        RETURN_EZMESH_RET;
    }

    ep->id = id;
    ep->lib_handle = lib_handle;

    tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret != 0)
    {
        SET_EZMESH_RET(-tmp_ret);
        goto free_endpoint;
    }

    tmp_ret = ezmesh_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_OPEN_EP_QUERY, id,
                                 (void *)&can_open, sizeof(can_open));

    if (tmp_ret) { SET_EZMESH_RET(tmp_ret); }

    tmp_ret2 = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret2 != 0)
    {
        SET_EZMESH_RET(-tmp_ret2);
        goto free_endpoint;
    }

    if (tmp_ret) goto free_endpoint;

    if (can_open == false)
    {
        SET_EZMESH_RET(-EAGAIN);
        goto free_endpoint;
    }

    ep->sock_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (ep->sock_fd < 0)
    {
        SET_EZMESH_RET(-errno);
        goto free_endpoint;
    }

    tmp_ret = connect(ep->sock_fd, (struct sockaddr *)&ep_addr, sizeof(ep_addr));
    if (tmp_ret < 0)
    {
        SET_EZMESH_RET(-errno);
        goto close_sock_fd;
    }

    tmp_ret = ezmesh_query_receive(lib_handle, ep->sock_fd, (void *)&ep->server_sock_fd, sizeof(ep->server_sock_fd));
    if (tmp_ret)
    {
        SET_EZMESH_RET(tmp_ret);
        goto close_sock_fd;
    }

    int ep_socket_size = DEFAULT_EP_SOCKET_SIZE;
    tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, &ep_socket_size, sizeof(int));
    if (tmp_ret != 0)
    {
        SET_EZMESH_RET(-errno);
        goto close_sock_fd;
    }

    tmp_ret = pthread_mutex_init(&ep->sock_fd_lock, NULL);
    if (tmp_ret != 0)
    {
        SET_EZMESH_RET(-tmp_ret);
        goto close_sock_fd;
    }

    endpoint->ptr = (void *)ep;

    SET_EZMESH_RET(ep->sock_fd);
    RETURN_EZMESH_RET;

 close_sock_fd:
    if (close(ep->sock_fd) < 0)
    {
        SET_EZMESH_RET(-errno);
    }

 free_endpoint:
    free(ep);

    RETURN_EZMESH_RET;
}

int libezmesh_close_ep(ezmesh_ep_t *endpoint)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    ezmesh_handle_inst_t *lib_handle = NULL;
    __ezmesh_ep_t *ep = NULL;

    if (endpoint == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    ep = (__ezmesh_ep_t *)endpoint->ptr;
    if (ep == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    lib_handle = ep->lib_handle;

    tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret != 0)
    {
        goto destroy_mutex;
    }

    tmp_ret = ezmesh_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_CLOSE_EP_QUERY, ep->id,
                                 (void *)&ep->server_sock_fd, sizeof(ep->server_sock_fd));

    if (close(ep->sock_fd) < 0)
    {
        goto unlock_mutex;
    }
    ep->sock_fd = -1;

    tmp_ret = ezmesh_query_receive(lib_handle, lib_handle->ctrl_sock_fd, NULL, sizeof(int));
 unlock_mutex:
    tmp_ret = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);


 destroy_mutex:
    tmp_ret = pthread_mutex_destroy(&ep->sock_fd_lock);

    free(ep);
    endpoint->ptr = NULL;

    RETURN_EZMESH_RET;
}

ssize_t libezmesh_read_ep(ezmesh_ep_t endpoint, void *buffer, size_t count, ezmesh_ep_read_flags_t flags)
{
    INIT_EZMESH_RET(ssize_t);
    int sock_flags = 0;
    ssize_t bytes_read = 0;
    __ezmesh_ep_t *ep = NULL;

    if (buffer == NULL || count < LIB_EZMESH_READ_MINIMUM_SIZE || endpoint.ptr == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    ep = (__ezmesh_ep_t *)endpoint.ptr;


    if (flags & EP_READ_FLAG_NON_BLOCKING)
    {
        sock_flags |= MSG_DONTWAIT;
    }

    bytes_read = recv(ep->sock_fd, buffer, count, sock_flags);
    if (bytes_read == 0)
    {
        SET_EZMESH_RET(-ECONNRESET);
    } else if (bytes_read < 0)
    {
        SET_EZMESH_RET(-errno);
    } else
    {
        SET_EZMESH_RET(bytes_read);
    }

    RETURN_EZMESH_RET;
}


ssize_t libezmesh_write_ep(ezmesh_ep_t endpoint, const void *data, size_t data_length, ezmesh_ep_write_flags_t flags)
{
    INIT_EZMESH_RET(ssize_t);
    int sock_flags = 0;
    ssize_t bytes_written = 0;
    __ezmesh_ep_t *ep = NULL;

    if (endpoint.ptr == NULL || data == NULL || data_length == 0)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    ep = (__ezmesh_ep_t *)endpoint.ptr;

    if (data_length > ep->lib_handle->max_write_size)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    if (flags & EP_WRITE_FLAG_NON_BLOCKING)
    {
        sock_flags |= MSG_DONTWAIT;
    }

    bytes_written = send(ep->sock_fd, data, data_length, sock_flags);
    if (bytes_written == -1)
    {
        SET_EZMESH_RET(-errno);
        RETURN_EZMESH_RET;
    } else
    {
        SET_EZMESH_RET(bytes_written);
    }
    assert((size_t)bytes_written == data_length);

    RETURN_EZMESH_RET;
}

int libezmesh_get_ep_state(ezmesh_handle_t handle, uint8_t id, ep_state_t *state)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    ezmesh_handle_inst_t *lib_handle = NULL;

    if (state == NULL || handle.ptr == NULL || id == EP_SYSTEM)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    lib_handle = (ezmesh_handle_inst_t *)handle.ptr;

    tmp_ret = pthread_mutex_lock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret != 0)
    {
        SET_EZMESH_RET(-tmp_ret);
        RETURN_EZMESH_RET;
    }


    tmp_ret = ezmesh_query_exchange(lib_handle, lib_handle->ctrl_sock_fd,
                                 EXCHANGE_EP_STATUS_QUERY, id,
                                 (void *)state, sizeof(ep_state_t));

    tmp_ret = pthread_mutex_unlock(&lib_handle->ctrl_sock_fd_lock);
    if (tmp_ret != 0)
    {
        SET_EZMESH_RET(-tmp_ret);
        RETURN_EZMESH_RET;
    }

    RETURN_EZMESH_RET;
}

int libezmesh_set_ep_option(ezmesh_ep_t endpoint, ezmesh_option_t option, const void *optval, size_t optlen)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    __ezmesh_ep_t *ep = NULL;

    if (option == OPTION_NONE || endpoint.ptr == NULL || optval == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    ep = (__ezmesh_ep_t *)endpoint.ptr;

    if (option == OPTION_RX_TIMEOUT)
    {
        ezmesh_timeval_t *useropt = (ezmesh_timeval_t *)optval;
        struct timeval sockopt;

        if (optlen != sizeof(ezmesh_timeval_t))
        {
            SET_EZMESH_RET(-EINVAL);
            RETURN_EZMESH_RET;
        }

        sockopt.tv_sec = useropt->seconds;
        sockopt.tv_usec = useropt->microseconds;

        tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
        if (tmp_ret < 0)
        {
            SET_EZMESH_RET(-errno);
            RETURN_EZMESH_RET;
        }
    } else if (option == OPTION_TX_TIMEOUT)
    {
        ezmesh_timeval_t *useropt = (ezmesh_timeval_t *)optval;
        struct timeval sockopt;

        if (optlen != sizeof(ezmesh_timeval_t))
        {
            SET_EZMESH_RET(-EINVAL);
            RETURN_EZMESH_RET;
        }

        sockopt.tv_sec = useropt->seconds;
        sockopt.tv_usec = useropt->microseconds;

        tmp_ret = setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &sockopt, (socklen_t)sizeof(sockopt));
        if (tmp_ret < 0)
        {
            SET_EZMESH_RET(-errno);
            RETURN_EZMESH_RET;
        }
    } else if (option == OPTION_BLOCKING)
    {
        if (optlen != sizeof(bool))
        {
            SET_EZMESH_RET(-EINVAL);
            RETURN_EZMESH_RET;
        }

        tmp_ret = pthread_mutex_lock(&ep->sock_fd_lock);
        if (tmp_ret != 0)
        {
            SET_EZMESH_RET(-tmp_ret);
            RETURN_EZMESH_RET;
        }

        int flags = fcntl(ep->sock_fd, F_GETFL);
        if (flags < 0)
        {
            SET_EZMESH_RET(-errno);

            tmp_ret = pthread_mutex_unlock(&ep->sock_fd_lock);
            if (tmp_ret != 0)
            {
                SET_EZMESH_RET(-tmp_ret);
            }

            RETURN_EZMESH_RET;
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
            SET_EZMESH_RET(-errno);
        }

        tmp_ret = pthread_mutex_unlock(&ep->sock_fd_lock);
        if (tmp_ret != 0)
        {
            SET_EZMESH_RET(-tmp_ret);
        }

        RETURN_EZMESH_RET;
    } else if (option == OPTION_SOCKET_SIZE)
    {
        if (optlen != sizeof(int))
        {
            SET_EZMESH_RET(-EINVAL);
            RETURN_EZMESH_RET;
        }

        if (setsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, (socklen_t)optlen) != 0)
        {
            SET_EZMESH_RET(-errno);
            RETURN_EZMESH_RET;
        }
    } else
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    RETURN_EZMESH_RET;
}

int libezmesh_get_ep_option(ezmesh_ep_t endpoint, ezmesh_option_t option, void *optval, size_t *optlen)
{
    INIT_EZMESH_RET(int);
    int tmp_ret = 0;
    __ezmesh_ep_t *ep = NULL;

    if (option == OPTION_NONE || endpoint.ptr == NULL || optval == NULL || optlen == NULL)
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    ep = (__ezmesh_ep_t *)endpoint.ptr;

    if (option == OPTION_RX_TIMEOUT)
    {
        ezmesh_timeval_t *useropt = (ezmesh_timeval_t *)optval;
        struct timeval sockopt;
        socklen_t socklen = sizeof(sockopt);

        if (*optlen != sizeof(ezmesh_timeval_t))
        {
            SET_EZMESH_RET(-EINVAL);
            RETURN_EZMESH_RET;
        }

        tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_RCVTIMEO, &sockopt, &socklen);
        if (tmp_ret < 0)
        {
            SET_EZMESH_RET(-errno);
            RETURN_EZMESH_RET;
        }

        // these values are "usually" of type long, so make sure they
        // fit in integers (really, they should).
        if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX)
        {
            SET_EZMESH_RET(-EINVAL);
            RETURN_EZMESH_RET;
        }

        useropt->seconds = (int)sockopt.tv_sec;
        useropt->microseconds = (int)sockopt.tv_usec;
    } else if (option == OPTION_TX_TIMEOUT)
    {
        ezmesh_timeval_t *useropt = (ezmesh_timeval_t *)optval;
        struct timeval sockopt;
        socklen_t socklen = sizeof(sockopt);

        if (*optlen != sizeof(ezmesh_timeval_t))
        {
            SET_EZMESH_RET(-EINVAL);
            RETURN_EZMESH_RET;
        }

        tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDTIMEO, &sockopt, &socklen);
        if (tmp_ret < 0)
        {
            SET_EZMESH_RET(-errno);
            RETURN_EZMESH_RET;
        }

        if (sockopt.tv_sec > INT_MAX || sockopt.tv_usec > INT_MAX)
        {
            SET_EZMESH_RET(-EINVAL);
            RETURN_EZMESH_RET;
        }

        useropt->seconds = (int)sockopt.tv_sec;
        useropt->microseconds = (int)sockopt.tv_usec;
    } else if (option == OPTION_BLOCKING)
    {
        if (*optlen < sizeof(bool))
        {
            SET_EZMESH_RET(-ENOMEM);
            RETURN_EZMESH_RET;
        }

        *optlen = sizeof(bool);

        int flags = fcntl(ep->sock_fd, F_GETFL);
        if (flags < 0)
        {
            SET_EZMESH_RET(-errno);
            RETURN_EZMESH_RET;
        }

        if (flags & O_NONBLOCK)
        {
            *(bool *)optval = false;
        } else
        {
            *(bool *)optval = true;
        }
    } else if (option == OPTION_SOCKET_SIZE)
    {
        socklen_t socklen = (socklen_t)*optlen;

        if (*optlen < sizeof(int))
        {
            SET_EZMESH_RET(-ENOMEM);
            RETURN_EZMESH_RET;
        }

        tmp_ret = getsockopt(ep->sock_fd, SOL_SOCKET, SO_SNDBUF, optval, &socklen);
        if (tmp_ret < 0)
        {
            SET_EZMESH_RET(-errno);
            RETURN_EZMESH_RET;
        }

        *optlen = (size_t)socklen;
    } else if (option == OPTION_MAX_WRITE_SIZE)
    {
        *optlen = sizeof(size_t);
        memcpy(optval, &ep->lib_handle->max_write_size, sizeof(ep->lib_handle->max_write_size));
    } else
    {
        SET_EZMESH_RET(-EINVAL);
        RETURN_EZMESH_RET;
    }

    RETURN_EZMESH_RET;
}

const char *libezmesh_get_lib_ver(void)
{
    return PROJECT_VER;
}

