

#ifndef _LIBCPC_H
#define _LIBCPC_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

#if !defined(__linux__)
#error Wrong platform
#endif

#define CPC_ENUM_DECLARE(name) typedef uint8_t name; enum name ## _enum
#define CPC_ENUM_GENERIC_DECLARE(name, type) typedef type name; enum name ## _enum

#ifdef __cplusplus
extern "C"
{
#endif

#define LIB_CPC_READ_MINIMUM_SIZE 4087


CPC_ENUM_DECLARE(cpc_ep_state_t)
{
    CPC_EP_STATE_OPEN = 0,
    CPC_EP_STATE_CLOSED,
    CPC_EP_STATE_CLOSING,
    CPC_EP_STATE_ERROR_DEST_UNREACH,
    CPC_EP_STATE_ERROR_FAULT
};

CPC_ENUM_DECLARE(cpc_ep_write_flags_t)
{
    CPC_EP_WRITE_FLAG_NONE = 0,               ///< No flag
    CPC_EP_WRITE_FLAG_NON_BLOCKING = (1 << 0) ///< Set this transaction as non-blocking
};


CPC_ENUM_DECLARE(cpc_ep_read_flags_t)
{
    CPC_EP_READ_FLAG_NONE = 0,                ///< No flag
    CPC_EP_READ_FLAG_NON_BLOCKING = (1 << 0)  ///< Set this transaction as non-blocking
};


CPC_ENUM_DECLARE(cpc_ep_event_flags_t)
{
    CPC_EP_EVENT_FLAG_NONE = 0,               ///< No flag
    CPC_EP_EVENT_FLAG_NON_BLOCKING = (1 << 0) ///< Set this transaction as non-blocking
};


CPC_ENUM_DECLARE(cpc_option_t)
{
    CPC_OPTION_NONE = 0,
    CPC_OPTION_BLOCKING,
    CPC_OPTION_RX_TIMEOUT,
    CPC_OPTION_TX_TIMEOUT,
    CPC_OPTION_SOCKET_SIZE,
    CPC_OPTION_MAX_WRITE_SIZE,
};

CPC_ENUM_DECLARE(cpc_ep_event_option_t)
{
    CPC_EP_EVENT_OPTION_NONE = 0,
    CPC_EP_EVENT_OPTION_BLOCKING,
    CPC_EP_EVENT_OPTION_READ_TIMEOUT,
};

CPC_ENUM_DECLARE(cpc_srv_ep_id_t)
{
    CPC_EP_SYSTEM = 0,
    CPC_EP_ZIGBEE = 5,
    CPC_EP_OPENTHREAD = 9,
    CPC_EP_15_4 = 12,
    CPC_EP_CLI = 13,
    CPC_EP_BT_RCP = 14
};

CPC_ENUM_DECLARE(cpc_user_ep_id_t)
{
    CPC_EP_USER_ID_0 = 90,
    CPC_EP_USER_ID_1 = 91,
    CPC_EP_USER_ID_2 = 92,
    CPC_EP_USER_ID_3 = 93,
    CPC_EP_USER_ID_4 = 94,
    CPC_EP_USER_ID_5 = 95,
    CPC_EP_USER_ID_6 = 96,
    CPC_EP_USER_ID_7 = 97,
    CPC_EP_USER_ID_8 = 98,
    CPC_EP_USER_ID_9 = 99,
};

CPC_ENUM_DECLARE(cpc_evt_type_t)
{
    CPC_EVT_EP_UNKNOWN = 0,
    CPC_EVT_EP_OPENED = 1,
    CPC_EVT_EP_CLOSED = 2,
    CPC_EVT_EP_CLOSING = 3,
    CPC_EVT_EP_ERROR_DESTINATION_UNREACHABLE = 4,
    CPC_EVT_EP_ERROR_SECURITY_INCIDENT = 5,
    CPC_EVT_EP_ERROR_FAULT = 6,
};


typedef struct
{
    void *ptr;
} cpc_handle_t, cpc_ep_t;

typedef struct
{
    int seconds;
    int microseconds;
} cpc_timeval_t;

typedef uint8_t cpc_evts_flags_t;

typedef void (*cpc_reset_cb_t) (void);
typedef void (*cpc_ep_state_callback_t) (uint8_t endpoint_id, cpc_ep_state_t endpoint_state);

int libcpc_init(cpc_handle_t *handle, const char *instance_name, cpc_reset_cb_t reset_cb);
int libcpc_reset(cpc_handle_t *handle);
int libcpc_open_ep(cpc_handle_t handle, cpc_ep_t *endpoint, uint8_t id, uint8_t tx_win_size);
int libcpc_close_ep(cpc_ep_t *endpoint);

ssize_t libcpc_read_ep(cpc_ep_t endpoint, void *buffer, size_t count, cpc_ep_read_flags_t flags);
ssize_t libcpc_write_ep(cpc_ep_t endpoint, const void *data, size_t data_length, cpc_ep_write_flags_t flags);

int libcpc_get_ep_state(cpc_handle_t handle, uint8_t id, cpc_ep_state_t *state);
int libcpc_set_ep_option(cpc_ep_t endpoint, cpc_option_t option, const void *optval, size_t optlen);
int libcpc_get_ep_option(cpc_ep_t endpoint, cpc_option_t option, void *optval, size_t *optlen);

const char *libcpc_get_lib_ver(void);



#ifdef __cplusplus
}
#endif

#endif // _LIBCPC_H
