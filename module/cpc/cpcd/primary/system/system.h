

#ifndef __SYSTEM_H__
#define __SYSTEM_H__

#include "primary/epoll_port/epoll_port.h"
#include "utility/slist.h"
#include "libcpc.h"
#include "utility/status.h"

#include <stddef.h>
#include <stdarg.h>

#define CPC_CPC_EP_SYSTEM 0

CPC_ENUM_DECLARE(sys_cmd_id_t)
{
    CMD_SYSTEM_NOOP = 0x00,
    CMD_SYSTEM_RESET = 0x01,
    CMD_SYSTEM_PROP_VALUE_GET = 0x02,
    CMD_SYSTEM_PROP_VALUE_SET = 0x03,
    CMD_SYSTEM_PROP_VALUE_IS = 0x06,
    CMD_SYSTEM_INVALID = 0xFF,
};

CPC_ENUM_GENERIC_DECLARE(property_id_t, uint32_t)
{
    PROP_LAST_STATUS = 0x00,
    PROP_PROTOCOL_VERSION = 0x01,
    PROP_CAPABILITIES = 0x02,
    PROP_SECONDARY_CPC_VERSION = 0x03,
    PROP_SECONDARY_APP_VERSION = 0x04,
    PROP_RX_CAPABILITY = 0x20,
    PROP_FC_VALIDATION_VALUE = 0x30,
    PROP_BUS_SPEED_VALUE = 0x40,

    PROP_BOOTLOADER_REBOOT_MODE = 0x202,

    PROP_cpcd_DEBUG_COUNTERS = 0x400,
    PROP_UFRAME_PROCESSING = 0x500,

    PROP_EP_STATE_0 = 0x1000,

    PROP_EP_STATES = 0x1100,
};

#define EP_ID_TO_PROPERTY_ID(property, ep_id)  ((property_id_t)((property) | ((ep_id) & 0x000000FF)))

#define PROPERTY_ID_TO_EP_ID(property_id) ((uint8_t)(property_id & 0x000000FF))

#define EP_ID_TO_PROPERTY_STATE(ep_id)         EP_ID_TO_PROPERTY_ID(PROP_EP_STATE_0, ep_id)

#define EP_ID_TO_PROPERTY_ENCRYPTION(ep_id)         EP_ID_TO_PROPERTY_ID(PROP_EP_ENCRYPTION, ep_id)


#define AGGREGATED_STATE_LOW(agg)  ((cpc_ep_state_t)(agg & 0x0F))
#define AGGREGATED_STATE_HIGH(agg) ((cpc_ep_state_t)(agg >> 4))

#define GET_EP_STATE_FROM_STATES(payload, ep_id)                      \
    ((ep_id % 2 == 0) ?  AGGREGATED_STATE_LOW(((uint8_t *)payload)[ep_id / 2]) \
     : AGGREGATED_STATE_HIGH(((uint8_t *)payload)[ep_id / 2]))

CPC_ENUM_GENERIC_DECLARE(sys_status_t, uint32_t)
{
    SYS_STATUS_OK = 0,
    SYS_STATUS_FAILURE = 1,
    SYS_STATUS_UNIMPLEMENTED = 2,
    SYS_STATUS_INVALID_ARGUMENT = 3,
    SYS_STATUS_INVALID_STATE = 4,
    SYS_STATUS_INVALID_COMMAND = 5,
    SYS_STATUS_INVALID_INTERFACE = 6,
    SYS_STATUS_INTERNAL_ERROR = 7,
    SYS_STATUS_PARSE_ERROR = 9,
    SYS_STATUS_IN_PROGRESS = 10,
    SYS_STATUS_NOMEM = 11,
    SYS_STATUS_BUSY = 12,
    SYS_STATUS_PROP_NOT_FOUND = 13,
    SYS_STATUS_PACKET_DROPPED = 14,
    SYS_STATUS_EMPTY = 15,
    SYS_STATUS_CMD_TOO_BIG = 16,
    SYS_STATUS_ALREADY = 19,
    SYS_STATUS_ITEM_NOT_FOUND = 20,
    SYS_STATUS_INVALID_COMMAND_FOR_PROP = 21,

    SYS_STATUS_RESET_POWER_ON = 112,
    SYS_STATUS_RESET_EXTERNAL = 113,
    SYS_STATUS_RESET_SOFTWARE = 114,
    SYS_STATUS_RESET_FAULT = 115,
    SYS_STATUS_RESET_CRASH = 116,
    SYS_STATUS_RESET_ASSERT = 117,
    SYS_STATUS_RESET_OTHER = 118,
    SYS_STATUS_RESET_UNKNOWN = 119,
    SYS_STATUS_RESET_WATCHDOG = 120,
};


CPC_ENUM_GENERIC_DECLARE(sys_reboot_mode_t, uint32_t)
{
    REBOOT_APPLICATION = 0,
    REBOOT_BOOTLOADER = 1
};

#define CPC_CAPABILITIES_PACKED_EP_MASK   (1 << 1)
#define CPC_CAPABILITIES_UART_FLOW_CONTROL_MASK (1 << 3)


typedef struct
{
    sys_cmd_id_t command_id; ///< Identifier of the command.
    uint8_t command_seq;               ///< Command sequence number
    uint16_t length;                   ///< Length of the payload in bytes.
    uint8_t payload[];                 ///< Command payload.
}sys_cmd_t;

typedef struct
{
    property_id_t property_id; ///< Identifier of the property.
    uint8_t payload[];              ///< Property value.
}sys_property_cmd_t;

typedef struct
{
    slist_node_t node_commands;
    sys_cmd_t *command; // has to be malloc'ed
    void *on_final;
    uint8_t retry_count;
    bool retry_forever;
    bool is_uframe;
    uint32_t retry_timeout_us;
    status_t error_status;
    uint8_t command_seq;
    bool acked;
    epoll_port_private_data_t re_transmit_timer_private_data; //for epoll for timerfd
} sys_command_handle_t;

void sys_init(void);


typedef void (*sys_unsolicited_status_callback_t) (sys_status_t status);

typedef void (*sys_noop_cmd_cb_t) (sys_command_handle_t *handle, status_t status);


typedef void (*sys_reset_cmd_callback_t) (sys_command_handle_t *handle, status_t command_status, sys_status_t reset_status);

typedef void (*sys_property_get_set_cmd_callback_t) (sys_command_handle_t *handle,
                                                     property_id_t property_id,
                                                     void *property_value,
                                                     size_t property_length,
                                                     status_t status);
void sys_cmd_noop(sys_noop_cmd_cb_t on_noop_reply,
                  uint8_t retry_count_max,
                  uint32_t retry_timeout_us);


void sys_cmd_reboot(sys_reset_cmd_callback_t on_reset_reply,
                    uint8_t retry_count_max,
                    uint32_t retry_timeout_us);

void sys_cmd_property_get(sys_property_get_set_cmd_callback_t on_property_get_reply,
                          property_id_t property_id,
                          uint8_t retry_count_max,
                          uint32_t retry_timeout_us,
                          bool is_uframe);

void sys_cmd_property_set(sys_property_get_set_cmd_callback_t on_property_set_reply,
                          uint8_t retry_count_max,
                          uint32_t retry_timeout_us,
                          property_id_t property_id,
                          const void *value,
                          size_t value_length,
                          bool is_uframe);

void sys_register_unsolicited_prop_last_status_callback(sys_unsolicited_status_callback_t);

void sys_reset_sys_endpoint(void);

void sys_request_sequence_reset(void);

void sys_cmd_poll_acknowledged(const void *data);

bool sys_received_unnumbered_acknowledgement(void);

void sys_on_unnumbered_acknowledgement(void);

void sys_cleanup(void);

#endif
