#ifndef PRIMARY_H
#define PRIMARY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "library/libezmesh.h"
#include "utility/list.h"

#define PRIMARY_EP_MAX_COUNTS (256)
#define CAPABILITIES_PACKED_EP_MASK   (1 << 1)
#define CAPABILITIES_UART_FLOW_CONTROL_MASK (1 << 3)
#define PROPERTY_ID_TO_EP_ID(property_id) ((uint8_t)(property_id & 0x000000FF))

#define EP_ID_TO_PROPERTY_ID(property, ep_id)  ((property_id_t)((property) | ((ep_id) & 0x000000FF)))
#define EP_ID_TO_PROPERTY_STATE(ep_id)    EP_ID_TO_PROPERTY_ID(PROP_EP_STATE_0, ep_id)

typedef enum {
  STATUS_OK = 0,
  STATUS_FAIL,
  STATUS_IN_PROGRESS = 5,
  STATUS_ABORT,
  STATUS_TIMEOUT,
  STATUS_WOULD_BLOCK = 9,
} status_t;

typedef enum {
  OPEN_EP_IDLE,
  OPEN_EP_STATE_WAITING,
  OPEN_EP_STATE_FETCHED,
  OPEN_EP_ENCRYPTION_WAITING,
  OPEN_EP_ENCRYPTION_FETCHED,
  OPEN_EP_DONE,
} ez_open_ep_t;

typedef enum {
  NO_ERROR,

  ERR_SYS_STATUS_OK = 0,
  ERR_SYS_STATUS_FAILURE = 1,
  ERR_SYS_STATUS_UNIMPLEMENTED = 2,
  ERR_SYS_STATUS_INVALID_ARGUMENT = 3,
  ERR_SYS_STATUS_INVALID_STATE = 4,
  ERR_SYS_STATUS_INVALID_COMMAND = 5,
  ERR_SYS_STATUS_INVALID_INTERFACE = 6,
  ERR_SYS_STATUS_INTERNAL_ERROR = 7,
  ERR_SYS_STATUS_PARSE_ERROR = 9,
  ERR_SYS_STATUS_IN_PROGRESS = 10,
  ERR_SYS_STATUS_NOMEM = 11,
  ERR_SYS_STATUS_BUSY = 12,
  ERR_SYS_STATUS_PROP_NOT_FOUND = 13,
  ERR_SYS_STATUS_PACKET_DROPPED = 14,
  ERR_SYS_STATUS_EMPTY = 15,
  ERR_SYS_STATUS_CMD_TOO_BIG = 16,
  ERR_SYS_STATUS_ALREADY = 19,
  ERR_SYS_STATUS_ITEM_NOT_FOUND = 20,
  ERR_SYS_STATUS_INVALID_COMMAND_FOR_PROP = 21,
  ERR_SYS_STATUS_RESET_POWER_ON = 112,
  ERR_SYS_STATUS_RESET_EXTERNAL = 113,
  ERR_SYS_STATUS_RESET_SOFTWARE = 114,
  ERR_SYS_STATUS_RESET_FAULT = 115,
  ERR_SYS_STATUS_RESET_CRASH = 116,
  ERR_SYS_STATUS_RESET_ASSERT = 117,
  ERR_SYS_STATUS_RESET_OTHER = 118,
  ERR_SYS_STATUS_RESET_UNKNOWN = 119,
  ERR_SYS_STATUS_RESET_WATCHDOG = 120,
} ez_err_t;

typedef struct ez_epoll ez_epoll_t;
typedef void (*epoll_cb_t)(ez_epoll_t *data);
struct ez_epoll {
  epoll_cb_t callback;
  int fd;
  uint8_t ep;
};

typedef uint8_t sys_cmd_id_t; 
enum sys_cmd_id_t_enum {
  CMD_SYSTEM_NOOP = 0x00,
  CMD_SYSTEM_RESET = 0x01,
  CMD_SYSTEM_PROP_VALUE_GET = 0x02,
  CMD_SYSTEM_PROP_VALUE_SET = 0x03,
  CMD_SYSTEM_PROP_VALUE_IS = 0x06,
  CMD_SYSTEM_INVALID = 0xFF,
};

typedef uint32_t sys_status_t; 
enum sys_status_t_enum {
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
} ;

typedef uint32_t property_id_t; 
enum property_id_t_enum {
  PROP_LAST_STATUS = 0x00,
  PROP_PROTOCOL_VERSION = 0x01,
  PROP_CAPABILITIES = 0x02,
  PROP_SECONDARY_EZMESH_VERSION = 0x03,
  PROP_SECONDARY_APP_VERSION = 0x04,
  PROP_RX_CAPABILITY = 0x20,
  PROP_FC_VALIDATION_VALUE = 0x30,
  PROP_BUS_SPEED_VALUE = 0x40,

  PROP_BOOTLOADER_REBOOT_MODE = 0x202,

  PROP_EZMESHD_DEBUG_COUNTERS = 0x400,
  PROP_UFRAME_PROCESSING = 0x500,

  PROP_RF_CERT_BAND = 0x800,

  PROP_EP_STATE_0 = 0x1000,

  PROP_EP_STATES = 0x1100,
} ;


typedef uint32_t reboot_mode_t; 
enum reboot_mode_t_enum {
    REBOOT_APPLICATION = 0,
    REBOOT_BOOTLOADER = 1
};

typedef struct {
  uint8_t command_id;      ///< Identifier of the command.
  uint8_t command_seq;     ///< Command sequence number
  uint16_t length;         ///< Length of the payload in bytes.
  uint8_t payload[];       ///< Command payload.
} sys_cmd_t;

typedef struct {
  property_id_t property_id; ///< Identifier of the property.
  uint8_t payload[];         ///< Property value.
} sys_property_cmd_t;

typedef struct {
  list_node_t node_commands;
  sys_cmd_t *command;
  void *on_final;
  uint8_t retry_count;
  bool retry_forever;
  bool is_uframe;
  uint32_t retry_timeout_us;
  status_t error_status;
  uint8_t command_seq;
  bool acked;
  ez_epoll_t retx_socket; // for epoll for timerfd
} sys_cmd_handle_t;

typedef struct {
  uint32_t conn_count;
  uint32_t conn_event;
  uint32_t pending_close;
  ez_epoll_t epoll_conn_event;
  ez_epoll_t socket_instance;
  list_node_t *epoll_event;
  list_node_t *epoll_data;
  list_node_t *ctl_socket_data;
} ep_ctl_t;


// extern ep_ctl_t ep_ctx[PRIMARY_EP_MAX_COUNTS];

void EP_close_cb(sys_cmd_handle_t *handle, property_id_t id, void *property_value,  size_t property_length, status_t status);
ez_err_t EP_open(uint8_t ep, ep_state_t state);
ez_err_t EP_close(uint8_t ep, bool state);
bool EP_get_state(uint8_t ep);
bool EP_is_open(uint8_t ep);
ez_err_t EP_set_state(uint8_t ep, ep_state_t state);
ez_err_t EP_push_data(uint8_t ep, uint8_t *data, size_t data_len);
ez_err_t ctl_proc_conn(void);
ez_err_t ctl_deinit(void);
ez_err_t ctl_init(void);
void ctl_notify_HW_reset(void);
bool EP_list_empty(uint8_t ep);

typedef void (*sys_unsolicited_status_callback_t) (sys_status_t status);
typedef struct
{
  list_node_t node;
  sys_unsolicited_status_callback_t callback;
}last_status_callback_list_t;

typedef void (*sys_noop_cb_t) (sys_cmd_handle_t *handle, status_t status);
typedef void (*sys_reset_cmd_callback_t) (sys_cmd_handle_t *handle, status_t command_status, sys_status_t reset_status);

typedef void (*sys_property_get_set_cmd_callback_t) (sys_cmd_handle_t *handle,
                                                     property_id_t property_id,
                                                     void *property_value,
                                                     size_t property_length,
                                                     status_t status);
typedef void (*reset_cb_t)(sys_cmd_handle_t *handle, status_t command_status, sys_status_t reset_status);
typedef void (*param_get_cb_t)(sys_cmd_handle_t *handle, property_id_t property_id, void *property_value, size_t property_length, status_t status);
typedef void (*param_set_cb_t)(sys_cmd_handle_t *handle, property_id_t property_id, void *property_value, size_t property_length, status_t status);

void sys_sequence_reset(void);
void sys_poll_ack(const void *frame_data);
void sys_cleanup(void);
void sys_ep_no_found_ack(void);
void sys_set_last_status_callback(sys_unsolicited_status_callback_t callback);
void sys_init(void);
void sys_reboot(reset_cb_t cb, uint8_t count, uint32_t time);
void sys_param_get(param_get_cb_t cb, property_id_t id, uint8_t count, uint32_t time, bool is_uframe);
void sys_param_set(param_set_cb_t cb, uint8_t count, uint32_t time, property_id_t id, const void *val, size_t length, bool is_uframe);

#endif
