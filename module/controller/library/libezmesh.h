#ifndef _LIBEZMESH_H
#define _LIBEZMESH_H
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#if !defined(__linux__)
#error Wrong platform
#endif
#define EZMESH_ENUM_DECLARE(name) typedef uint8_t name; enum name ## _enum
#define EZMESH_ENUM_GENERIC_DECLARE(name, type) typedef type name; enum name ## _enum
#ifdef __cplusplus
extern "C"
{
#endif
#define LIB_EZMESH_READ_MINIMUM_SIZE 4087
EZMESH_ENUM_DECLARE(ep_state_t)
{
    ENDPOINT_STATE_OPEN = 0,
    ENDPOINT_STATE_CLOSED,
    ENDPOINT_STATE_CLOSING,
    ENDPOINT_STATE_ERROR_DEST_UNREACH,
    ENDPOINT_STATE_ERROR_FAULT,
    EP_STATE_FREED = 6
};
EZMESH_ENUM_DECLARE(ezmesh_ep_write_flags_t)
{
    EP_WRITE_FLAG_NONE = 0,               ///< No flag
    EP_WRITE_FLAG_NON_BLOCKING = (1 << 0) ///< Set this transaction as non-blocking
};
EZMESH_ENUM_DECLARE(ezmesh_ep_read_flags_t)
{
    EP_READ_FLAG_NONE = 0,                ///< No flag
    EP_READ_FLAG_NON_BLOCKING = (1 << 0)  ///< Set this transaction as non-blocking
};
EZMESH_ENUM_DECLARE(ezmesh_ep_event_flags_t)
{
    EP_EVENT_FLAG_NONE = 0,               ///< No flag
    EP_EVENT_FLAG_NON_BLOCKING = (1 << 0) ///< Set this transaction as non-blocking
};
EZMESH_ENUM_DECLARE(ezmesh_option_t)
{
    OPTION_NONE = 0,
    OPTION_BLOCKING,
    OPTION_RX_TIMEOUT,
    OPTION_TX_TIMEOUT,
    OPTION_SOCKET_SIZE,
    OPTION_MAX_WRITE_SIZE,
};
EZMESH_ENUM_DECLARE(ezmesh_ep_event_option_t)
{
    EP_EVENT_OPTION_NONE = 0,
    EP_EVENT_OPTION_BLOCKING,
    EP_EVENT_OPTION_READ_TIMEOUT,
};
EZMESH_ENUM_DECLARE(ezmesh_srv_ep_id_t)
{
    EP_SYSTEM = 0,
    EP_ZIGBEE = 5,
    EP_OPENTHREAD = 9,
    EP_15_4 = 12,
    EP_CLI = 13,
    EP_BT_RCP = 14
};
EZMESH_ENUM_DECLARE(ezmesh_user_ep_id_t)
{
    EP_USER_ID_0 = 90,
    EP_USER_ID_1 = 91,
    EP_USER_ID_2 = 92,
    EP_USER_ID_3 = 93,
    EP_USER_ID_4 = 94,
    EP_USER_ID_5 = 95,
    EP_USER_ID_6 = 96,
    EP_USER_ID_7 = 97,
    EP_USER_ID_8 = 98,
    EP_USER_ID_9 = 99,
};
EZMESH_ENUM_DECLARE(ezmesh_evt_type_t)
{
    EVT_EP_UNKNOWN = 0,
    EVT_EP_OPENED = 1,
    EVT_EP_CLOSED = 2,
    EVT_EP_CLOSING = 3,
    EVT_EP_ERROR_DESTINATION_UNREACHABLE = 4,
    EVT_EP_ERROR_SECURITY_INCIDENT = 5,
    EVT_EP_ERROR_FAULT = 6,
};
EZMESH_ENUM_GENERIC_DECLARE(ezmesh_ezmeshd_exchange_type_t, uint8_t)
{
    EXCHANGE_EP_STATUS_QUERY,
    EXCHANGE_OPEN_EP_QUERY,
    EXCHANGE_MAX_WRITE_SIZE_QUERY,
    EXCHANGE_VERSION_QUERY,
    EXCHANGE_CLOSE_EP_QUERY,
    EXCHANGE_SET_PID_QUERY,
    EXCHANGE_GET_AGENT_APP_VERSION_QUERY,
};

typedef struct
{
    int ctrl_sock_fd;
    pthread_mutex_t ctrl_sock_fd_lock;
    size_t max_write_size;
    char agent_app_version[16];
    char *instance_name;
    bool initialized;
} ezmesh_handle_inst_t;

typedef struct
{
    ezmesh_ezmeshd_exchange_type_t type;
    uint8_t endpoint_number;
    uint8_t payload[];
} ezmesh_croe_exange_buffer_t;
typedef struct
{
    ezmesh_evt_type_t type;
    uint8_t endpoint_number;
    uint32_t payload_length;
    uint8_t payload[];
} ezmesh_ezmeshd_event_buffer_t;
typedef struct
{
    void *ptr;
} ezmesh_handle_t, ezmesh_ep_t;
typedef struct
{
    int seconds;
    int microseconds;
} ezmesh_timeval_t;
typedef uint8_t ezmesh_evts_flags_t;
typedef void (*ezmesh_reset_cb_t) (void);
typedef void (*ezmesh_ep_state_callback_t) (uint8_t endpoint_id, ep_state_t endpoint_state);
int libezmesh_init(ezmesh_handle_t *handle, const char *instance_name, ezmesh_reset_cb_t reset_cb);
int libezmesh_reset(ezmesh_handle_t *handle);
int libezmesh_open_ep(ezmesh_handle_t handle, ezmesh_ep_t *endpoint, uint8_t id, uint8_t tx_win_size);
int libezmesh_close_ep(ezmesh_ep_t *endpoint);
ssize_t libezmesh_read_ep(ezmesh_ep_t endpoint, void *buffer, size_t count, ezmesh_ep_read_flags_t flags);
ssize_t libezmesh_write_ep(ezmesh_ep_t endpoint, const void *data, size_t data_length, ezmesh_ep_write_flags_t flags);
int libezmesh_get_ep_state(ezmesh_handle_t handle, uint8_t id, ep_state_t *state);
int libezmesh_set_ep_option(ezmesh_ep_t endpoint, ezmesh_option_t option, const void *optval, size_t optlen);
int libezmesh_get_ep_option(ezmesh_ep_t endpoint, ezmesh_option_t option, void *optval, size_t *optlen);
const char *libezmesh_get_lib_ver(void);
#ifdef __cplusplus
}
#endif
#endif // _LIBEZMESH_H
