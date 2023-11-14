#ifndef CPCD_H
#define CPCD_H
#include <time.h>
#include "lib/libcpc.h"
#include "hdlc.h"
#include "utility/status.h"
#include "utility/slist.h"
#include "primary/cpcd/cpcd.h"
#define OPEN_EP_FLAG_IFRAME_DISABLE    0x01 << 0
#define OPEN_EP_FLAG_UFRAME_ENABLE     0x01 << 1
#define OPEN_EP_FLAG_UFRAME_INFORMATION_DISABLE  0x01 << 2
#define FLAG_UFRAME_INFORMATION      0x01 << 1
#define FLAG_UFRAME_POLL             0x01 << 2
#define FLAG_UFRAME_RESET_COMMAND    0x01 << 3
#define FLAG_INFORMATION_POLL            0x01 << 4
// Maximum number of retry while sending a frame
#define CPC_RE_TRANSMIT 10
#define MAX_RE_TRANSMIT_TIMEOUT_MS 5000
#define MIN_RE_TRANSMIT_TIMEOUT_MS 50
#define MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS  5
#define TRANSMIT_WINDOW_MIN_SIZE  1u
#define TRANSMIT_WINDOW_MAX_SIZE  1u
#define VERSION_MAJOR 1u
#define VERSION_MINOR 1u
#define EP_MAX_COUNT  256
void cpcd_init(int driver_fd, int driver_notify_fd);
void cpcd_open_endpoint(uint8_t endpoit_number, uint8_t flags, uint8_t tx_win_size);
void cpcd_process_transmit_queue(void);
void cpcd_reset_endpoint_sequence(uint8_t endpoint_number);
bool cpcd_ep_is_busy(uint8_t ep_id);
status_t cpcd_close_endpoint(uint8_t endpoint_number, bool notify_secondary, bool force_close);
cpc_ep_state_t cpcd_get_endpoint_state(uint8_t ep_id);
bool cpcd_get_endpoint_encryption(uint8_t ep_id);
void cpcd_set_endpoint_state(uint8_t ep_id, cpc_ep_state_t state);
cpc_ep_state_t cpcd_state_mapper(uint8_t state);
const char *cpcd_stringify_state(cpc_ep_state_t state);
void cpcd_write(uint8_t endpoint_number, const void *message, size_t message_len, uint8_t flags);
CPC_ENUM_DECLARE(endpoint_option_t)
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
};
void cpcd_process_endpoint_change(uint8_t endpoint_number, cpc_ep_state_t ep_state);
bool cpcd_ep_is_closing(uint8_t ep_id);
void cpcd_set_endpoint_in_error(uint8_t endpoint_number, cpc_ep_state_t new_state);
void cpcd_set_endpoint_option(uint8_t endpoint_number,
                              endpoint_option_t option,
                              void *value);
// -----------------------------------------------------------------------------
// Data Types
typedef void (*on_final_t)(uint8_t endpoint_id, void *arg, void *answer, uint32_t answer_lenght);
typedef struct
{
    void *on_fnct_arg;
    on_final_t on_final;
} poll_final_t;
typedef void (*on_data_reception_t)(uint8_t endpoint_id, const void *data, size_t data_len);
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
    uint8_t frames_count_re_transmit_queue;
    uint8_t packet_re_transmit_count;
    long re_transmit_timeout_ms;
    void *re_transmit_timer_private_data;
    cpc_ep_state_t state;
    slist_node_t *re_transmit_queue;
    slist_node_t *holding_list;
    on_data_reception_t on_uframe_data_reception;
    on_data_reception_t on_iframe_data_reception;
    poll_final_t poll_final;
    struct timespec last_iframe_sent_timestamp;
    long smoothed_rtt;
    long rtt_variation;
}endpoint_t;
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
    slist_node_t node;
    buffer_handle_t *handle;
} transmit_queue_item_t;
typedef struct
{
    uint8_t header[CPC_HDLC_HEADER_RAW_SIZE];
    uint8_t payload[];    // last two bytes are little endian 16bits
}frame_t;
#endif
