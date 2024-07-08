#ifndef CORE_H
#define CORE_H
#include <time.h>
#include "library/libezmesh.h"
#include "utility/list.h"
#include "utility/utility.h"
#include "daemon/hdlc/core.h"
#include "daemon/primary/primary.h"

#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#define OPEN_EP_FLAG_IFRAME_DISABLE    0x01 << 0
#define OPEN_EP_FLAG_UFRAME_ENABLE     0x01 << 1
#define OPEN_EP_FLAG_UFRAME_INFORMATION_DISABLE  0x01 << 2
#define FLAG_UFRAME_INFORMATION      0x01 << 1
#define FLAG_UFRAME_POLL             0x01 << 2
#define FLAG_UFRAME_RESET_COMMAND    0x01 << 3
#define FLAG_INFORMATION_POLL        0x01 << 4
// Maximum number of retry while sending a frame
#define RE_TRANSMIT 10
#define MAX_RE_TRANSMIT_TIMEOUT_MS 5000
#define MIN_RE_TRANSMIT_TIMEOUT_MS 5
#define MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS  5
#define TRANSMIT_WINDOW_MIN_SIZE  1u
#define TRANSMIT_WINDOW_MAX_SIZE  1u
#define VERSION_MAJOR 1u
#define VERSION_MINOR 1u
#define EP_MAX_COUNT  256

#define HDLC_FLAG_VAL                  (0x14)

#define HDLC_HEADER_SIZE               (5)
#define HDLC_HEADER_RAW_SIZE           (7)
#define HDLC_FCS_SIZE                  (2)
#define HDLC_REJECT_PAYLOAD_SIZE       (1)
#define HDLC_CONTROL_UFRAME_TYPE_MASK  (0x37)
#define HDLC_ACK_SFRAME_FUNCTION       (0)
#define HDLC_REJECT_SFRAME_FUNCTION    (1)

// Data Types
typedef void (*on_final_t) (uint8_t endpoint_id, void *arg, void *answer, uint32_t answer_lenght);
typedef struct
{
    void *on_fnct_arg;
    on_final_t on_final;
} poll_final_t;
typedef void (*on_data_reception_t) (uint8_t endpoint_id, const void *data, size_t data_len);
/*
 * Internal state for the endpoints. Will be filled by cpc_register_endpoint()
 */
typedef struct endpoint
{
    uint8_t id;
    uint8_t flags;
    uint8_t seq;
    uint8_t ack;
    uint8_t configured_tx_win_size;
    uint8_t current_tx_window_space;
    uint8_t frames_count_retry_queue;
    uint8_t packet_retry_count;
    long retry_timeout_ms;
    void *retry_timer_data;
    ep_state_t state;
    list_node_t *retry_queue;
    list_node_t *holding_list;
    on_data_reception_t on_uframe_data_reception;
    on_data_reception_t on_iframe_data_reception;
    poll_final_t poll_final;
    struct timespec last_iframe_sent_timestamp;
    long smoothed_rtt;
    long rtt_variation;
} endpoint_t;

typedef struct
{
    uint32_t frame_counter;
} security_frame_t;

typedef struct
{
    void *hdlc_header;
    const void *data;
    uint16_t data_length;
    uint8_t fcs[2];
    uint8_t control;
    uint8_t address;
    endpoint_t *endpoint;
    uint8_t pending_ack;
    bool acked;
    bool pending_tx_complete;
} buffer_handle_t;

typedef struct
{
    list_node_t node;
    buffer_handle_t *handle;
} transmit_queue_item_t;

typedef struct
{
    uint8_t header[HDLC_HEADER_RAW_SIZE];
    uint8_t payload[];    // last two bytes are little endian 16bits
} frame_t;

typedef struct
{
  uint32_t endpoint_opened;
  uint32_t endpoint_closed;
  uint32_t rxd_frame;
  uint32_t txd_reject_destination_unreachable;
  uint32_t txd_completed;
  uint32_t retxd_data_frame;
  uint32_t invalid_header_checksum;
  uint32_t invalid_payload_checksum;
} dbg_cts_t;

extern dbg_cts_t primary_cpcd_debug_counters;
extern dbg_cts_t secondary_cpcd_debug_counters;

typedef enum endpoint_option
{
    EP_ON_IFRAME_RECEIVE = 0,
    EP_ON_IFRAME_RECEIVE_ARG,
    EP_ON_UFRAME_RECEIVE,
    EP_ON_UFRAME_RECEIVE_ARG,
    EP_ON_IFRAME_WRITE_COMPLETED,
    EP_ON_IFRAME_WRITE_COMPLETED_ARG,
    EP_ON_UFRAME_WRITE_COMPLETED,
    EP_ON_UFRAME_WRITE_COMPLETED_ARG,
    EP_ON_POLL,
    EP_ON_POLL_ARG,
    EP_ON_FINAL,
    EP_ON_FINAL_ARG,
} endpoint_option_t;

typedef enum hdlc_frame_type
{
    HDLC_FRAME_TYPE_IFRAME = 0,
    HDLC_FRAME_TYPE_SFRAME = 2,
    HDLC_FRAME_TYPE_UFRAME = 3
} hdlc_frame_type_t;

typedef enum hdlc_frame_pos
{
    HDLC_FLAG_POS = 0,
    HDLC_ADDRESS_POS = 1,
    HDLC_LENGTH_POS = 2,
    HDLC_CONTROL_POS = 4,
    HDLC_HCS_POS = 5
} hdlc_frame_pos_t;

typedef enum hdlc_frame_shift
{
    HDLC_CONTROL_UFRAME_TYPE_POS = 0,
#if (EZMESH_HDLC_SEQ_8==1)
    HDLC_CONTROL_P_F_POS = 3,
    HDLC_CONTROL_SEQ_POS = 4,
#else
    HDLC_CONTROL_P_F_POS = 2,
    HDLC_CONTROL_SEQ_POS = 3,    
#endif
    HDLC_CONTROL_SFRAME_FUNCTION_ID_POS = 4,
    HDLC_CONTROL_FRAME_TYPE_POS = 6
} hdlc_frame_shift_t;

typedef enum hdlc_frame_ctrl_u
{
    HDLC_CONTROL_UFRAME_TYPE_INFORMATION = 0x00,
    HDLC_CONTROL_UFRAME_TYPE_POLL_FINAL = 0x04,
    HDLC_CONTROL_UFRAME_TYPE_ACKNOWLEDGE = 0x0E,
    HDLC_CONTROL_UFRAME_TYPE_RESET_SEQ = 0x31,
    HDLC_CONTROL_UFRAME_TYPE_UNKNOWN = 0xFF
} hdlc_frame_ctrl_u_t;

typedef enum reject_reason
{
    HDLC_REJECT_NO_ERROR = 0,
    HDLC_REJECT_CHECKSUM_MISMATCH,
    HDLC_REJECT_SEQUENCE_MISMATCH,
    HDLC_REJECT_OUT_OF_MEMORY,
    HDLC_REJECT_SECURITY_ISSUE,
    HDLC_REJECT_UNREACHABLE_ENDPOINT,
    HDLC_REJECT_ERROR
} reject_reason_t;

void hdlc_create_header(uint8_t *hdr, uint8_t address, uint16_t length, uint8_t control);
void core_init(int driver_fd, int driver_notify_fd);
void core_open_endpoint(uint8_t endpoit_number, uint8_t flags, uint8_t tx_win_size);
void core_process_transmit_queue(void);
void core_reset_endpoint_sequence(uint8_t endpoint_number);
bool core_ep_is_busy(uint8_t ep_id);
status_t core_close_endpoint(uint8_t endpoint_number, bool notify_secondary, bool force_close);
ep_state_t core_get_endpoint_state(uint8_t ep_id);
bool core_get_endpoint_encryption(uint8_t ep_id);
void core_set_endpoint_state(uint8_t ep_id, ep_state_t state);
ep_state_t core_endpoint_state(uint8_t state);
const char *core_stringify_state(ep_state_t state);
void core_write(uint8_t endpoint_number, const void *message, size_t message_len, uint8_t flags);
void core_process_endpoint_change(uint8_t endpoint_number, ep_state_t ep_state);
bool core_endpoint_is_closing(uint8_t ep_id);
void core_set_endpoint_in_error(uint8_t endpoint_number, ep_state_t new_state);
void core_set_endpoint_option(uint8_t endpoint_number, endpoint_option_t option, void *value);
uint16_t core_compute_crc16(uint8_t new_byte, uint16_t prev_result);
uint16_t core_get_crc_sw(const void *buffer, uint16_t buffer_length);
bool core_check_crc_sw(const void *buffer, uint16_t buffer_length, uint16_t expected_crc);

// -----------------------------------------------------------------------------

#endif
