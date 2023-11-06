

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/time.h>

#include "utility/config.h"
#include "utility/endian.h"
#include "utility/logs.h"
#include "utility/slist.h"
#include "utility/status.h"
#include "utility/sleep.h"
#include "utility/utils.h"
#include "primary/cpcd/cpcd.h"
#include "primary/primary/primary.h"
#include "primary/epoll_port/epoll_port.h"
#include "primary/system/system.h"
#include "primary/cpcd/cpcd.h"
#include "primary/cpcd/hdlc.h"
#include "primary/cpcd/crc.h"

#define ABS(a)  ((a) < 0 ? -(a) : (a))
#define X_ENUM_TO_STR(x) #x
#define ENUM_TO_STR(x) X_ENUM_TO_STR(x)

/*******************************************************************************
 ***************************  GLOBAL VARIABLES   *******************************
 ******************************************************************************/
cpc_cpcd_dbg_cts_t primary_cpcd_debug_counters;
cpc_cpcd_dbg_cts_t secondary_cpcd_debug_counters;

/*******************************************************************************
 ***************************  LOCAL DECLARATIONS   *****************************
 ******************************************************************************/

/*******************************************************************************
 ***************************  LOCAL VARIABLES   ********************************
 ******************************************************************************/

static int hal_sock_fd;
static int hal_sock_notify_fd;
static int stats_timer_fd;
static endpoint_t cpcd_endpoints[EP_MAX_COUNT];
static slist_node_t *transmit_queue = NULL;
static slist_node_t *pending_on_security_ready_queue = NULL;
static slist_node_t *pending_on_tx_complete = NULL;
/*******************************************************************************
 **************************   LOCAL FUNCTIONS   ********************************
 ******************************************************************************/

static void cpcd_process_rx_hal_notification(epoll_port_private_data_t *event_private_data);
static void cpcd_process_rx_hal(epoll_port_private_data_t *event_private_data);
static void cpcd_process_ep_timeout(epoll_port_private_data_t *event_private_data);

static void cpcd_process_rx_i_frame(frame_t *rx_frame);
static void cpcd_process_rx_s_frame(frame_t *rx_frame);
static void cpcd_process_rx_u_frame(frame_t *rx_frame);

/* CPC cpcd functions  */
static bool cpcd_process_tx_queue(void);
static void cpcd_clear_transmit_queue(slist_node_t **head, int endpoint_id);
static void process_ack(endpoint_t *endpoint, uint8_t ack);
static void transmit_ack(endpoint_t *endpoint);
static void re_transmit_frame(endpoint_t *endpoint);
static bool is_seq_valid(uint8_t seq, uint8_t ack);
static endpoint_t *find_endpoint(uint8_t endpoint_number);
static void transmit_reject(endpoint_t *endpoint, uint8_t address, uint8_t ack, reject_reason_t reason);

/* Functions to operate on linux fd timers */
static void stop_re_transmit_timer(endpoint_t *endpoint);
static void start_re_transmit_timer(endpoint_t *endpoint, struct timespec offset);

/* Functions to communicate with the hal and server */
static void cpcd_push_frame_to_hal(const void *frame, size_t frame_len);
static bool cpcd_pull_frame_from_hal(frame_t **frame_buf, size_t *frame_buf_len);

static status_t cpcd_push_data_to_server(uint8_t ep_id, const void *data, size_t data_len);

static void cpcd_fetch_secondary_debug_counters(epoll_port_private_data_t *event_private_data);

/*******************************************************************************
 **************************   IMPLEMENTATION    ********************************
 ******************************************************************************/
cpc_ep_state_t cpcd_state_mapper(uint8_t state)
{
  #define STATE_FREED 6 // State freed, internal to Secondary

    switch (state)
    {
    case CPC_EP_STATE_OPEN:
    case CPC_EP_STATE_CLOSED:
    case CPC_EP_STATE_CLOSING:
    case CPC_EP_STATE_ERROR_DEST_UNREACH:
    case CPC_EP_STATE_ERROR_FAULT:
        return state;
    case STATE_FREED:
        return CPC_EP_STATE_CLOSED;
    default:
        ASSERT("A new state (%d) has been added to the Secondary that has no equivalent on the daemon.", state);
    }
}

const char *cpcd_stringify_state(cpc_ep_state_t state)
{
    switch (state)
    {
    case CPC_EP_STATE_OPEN:
        return ENUM_TO_STR(CPC_EP_STATE_OPEN);
    case CPC_EP_STATE_CLOSED:
        return ENUM_TO_STR(CPC_EP_STATE_CLOSED);
    case CPC_EP_STATE_CLOSING:
        return ENUM_TO_STR(CPC_EP_STATE_CLOSING);
    case CPC_EP_STATE_ERROR_DEST_UNREACH:
        return ENUM_TO_STR(CPC_EP_STATE_ERROR_DEST_UNREACH);
    case CPC_EP_STATE_ERROR_FAULT:
        return ENUM_TO_STR(CPC_EP_STATE_ERROR_FAULT);
    default:
        ASSERT("A new state (%d) has been added to the Secondary that has no equivalent on the daemon.", state);
    }
}

static void on_disconnect_notification(sys_command_handle_t *handle,
                                       property_id_t property_id,
                                       void *property_value,
                                       size_t property_length,
                                       status_t status)
{
    (void)handle;
    (void)property_length;
    (void)property_value;

    uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);
    ASSERT_ON(cpcd_endpoints[ep_id].state == CPC_EP_STATE_OPEN);

    switch (status)
    {
    case STATUS_IN_PROGRESS:
    case STATUS_OK:
        TRACE_CPCD("Disconnection notification received for ep#%d", ep_id);
        cpcd_set_endpoint_state(ep_id, CPC_EP_STATE_CLOSED);
        break;

    case STATUS_TIMEOUT:
    case STATUS_ABORT:
        cpcd_set_endpoint_in_error(ep_id, CPC_EP_STATE_ERROR_DEST_UNREACH);
        WARN("Failed to receive disconnection notification for ep#%d", ep_id);
        break;
    default:
        ERROR("Unknown status during disconnection notification");
        break;
    }
}

static void cpcd_compute_re_transmit_timeout(endpoint_t *endpoint)
{
    // Implemented using Karn’s algorithm
    // Based off of RFC 2988 Computing TCP's Retransmission Timer
    static bool first_rtt_measurement = true;
    struct timespec current_time;
    int64_t current_timestamp_ms;
    int64_t previous_timestamp_ms;
    long round_trip_time_ms = 0;
    long rto = 0;

    const uint8_t k = 4; // This value is recommended by the Karn’s algorithm

    ERROR_ON(endpoint == NULL);

    clock_gettime(CLOCK_MONOTONIC, &current_time);

    current_timestamp_ms = (current_time.tv_sec * 1000) + (current_time.tv_nsec / 1000000);
    previous_timestamp_ms = (endpoint->last_iframe_sent_timestamp.tv_sec * 1000) + (endpoint->last_iframe_sent_timestamp.tv_nsec / 1000000);

    round_trip_time_ms = (long)(current_timestamp_ms - previous_timestamp_ms);

    if (round_trip_time_ms <= 0)
    {
        round_trip_time_ms = 1;
    }

    ERROR_ON(round_trip_time_ms < 0);

    if (first_rtt_measurement)
    {
        endpoint->smoothed_rtt = round_trip_time_ms;
        endpoint->rtt_variation = round_trip_time_ms / 2;
        first_rtt_measurement = false;
    } else
    {
        // RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'| where beta is 0.25
        endpoint->rtt_variation = 3 * (endpoint->rtt_variation / 4) + ABS(endpoint->smoothed_rtt - round_trip_time_ms) / 4;

        //SRTT <- (1 - alpha) * SRTT + alpha * R' where alpha is 0.125
        endpoint->smoothed_rtt = 7 * (endpoint->smoothed_rtt / 8) + round_trip_time_ms / 8;
    }

    // Impose a lowerbound on the variation, we don't want the RTO to converge too close to the RTT
    if (endpoint->rtt_variation < MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS)
    {
        endpoint->rtt_variation = MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS;
    }

    rto = endpoint->smoothed_rtt + k * endpoint->rtt_variation;
    ERROR_ON(rto <= 0);

    if (rto > MAX_RE_TRANSMIT_TIMEOUT_MS)
    {
        rto = MAX_RE_TRANSMIT_TIMEOUT_MS;
    } else if (rto < MIN_RE_TRANSMIT_TIMEOUT_MS)
    {
        rto = MIN_RE_TRANSMIT_TIMEOUT_MS;
    }

    endpoint->re_transmit_timeout_ms = rto;
}


void cpcd_init(int hal_fd, int hal_notify_fd)
{
    hal_sock_fd = hal_fd;
    hal_sock_notify_fd = hal_notify_fd;

    /* Init all endpoints */
    size_t i = 0;
    for (i = 0; i < EP_MAX_COUNT; i++)
    {
        cpcd_endpoints[i].id = (uint8_t)i;
        cpcd_endpoints[i].state = CPC_EP_STATE_CLOSED;
        cpcd_endpoints[i].ack = 0;
        cpcd_endpoints[i].configured_tx_win_size = 1;
        cpcd_endpoints[i].current_tx_window_space = 1;
        cpcd_endpoints[i].re_transmit_timer_private_data = NULL;
        cpcd_endpoints[i].on_uframe_data_reception = NULL;
        cpcd_endpoints[i].on_iframe_data_reception = NULL;
        cpcd_endpoints[i].last_iframe_sent_timestamp = (struct timespec){0 };
        cpcd_endpoints[i].smoothed_rtt = 0;
        cpcd_endpoints[i].rtt_variation = 0;
        cpcd_endpoints[i].re_transmit_timeout_ms = MAX_RE_TRANSMIT_TIMEOUT_MS;
        cpcd_endpoints[i].packet_re_transmit_count = 0;
    }
    /* Setup epoll */
    {
        /* Setup the hal data socket */
        {
            static epoll_port_private_data_t private_data;

            private_data.callback = cpcd_process_rx_hal;
            private_data.file_descriptor = hal_fd;
            private_data.endpoint_number = 0; /* Irrelevant here */

            epoll_port_register(&private_data);
        }

        /* Setup the hal notification socket */
        {
            static epoll_port_private_data_t private_data_notification;

            private_data_notification.callback = cpcd_process_rx_hal_notification;
            private_data_notification.file_descriptor = hal_notify_fd;
            private_data_notification.endpoint_number = 0; /* Irrelevant here */

            epoll_port_register(&private_data_notification);
        }
    }

    /* Setup timer to fetch secondary debug counter */
    if (config.stats_interval > 0)
    {
        stats_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        ERROR_SYSCALL_ON(stats_timer_fd < 0);

        struct itimerspec timeout_time = { .it_interval = { .tv_sec = config.stats_interval, .tv_nsec = 0 },
                                           .it_value = { .tv_sec = config.stats_interval, .tv_nsec = 0 } };

        int ret = timerfd_settime(stats_timer_fd,
                                  0,
                                  &timeout_time,
                                  NULL);

        ERROR_SYSCALL_ON(ret < 0);

        /* Setup epoll */
        {
            epoll_port_private_data_t *private_data = (epoll_port_private_data_t *)calloc_port(sizeof(epoll_port_private_data_t));
            ERROR_SYSCALL_ON(private_data == NULL);

            private_data->callback = cpcd_fetch_secondary_debug_counters;
            private_data->file_descriptor = stats_timer_fd;

            epoll_port_register(private_data);
        }
    }

    slist_init(&pending_on_tx_complete);
}

void cpcd_process_transmit_queue(void)
{
    /* Flush the transmit queue */
    while (transmit_queue != NULL || pending_on_security_ready_queue != NULL)
    {
        if (!cpcd_process_tx_queue())
        {
            break;
        }
    }
}

cpc_ep_state_t cpcd_get_endpoint_state(uint8_t ep_id)
{
    ERROR_ON(ep_id == 0);
    return cpcd_endpoints[ep_id].state;
}

void cpcd_set_endpoint_state(uint8_t ep_id, cpc_ep_state_t state)
{
    if (cpcd_endpoints[ep_id].state != state)
    {
        TRACE_CPCD("Changing ep#%d state from %s to %s", ep_id, cpcd_stringify_state(cpcd_endpoints[ep_id].state), cpcd_stringify_state(state));
        cpcd_endpoints[ep_id].state = state;
        primary_on_endpoint_state_change(ep_id, state);
    }
}

bool cpcd_get_endpoint_encryption(uint8_t ep_id)
{
    (void)ep_id;
    return false;
}

static void cpcd_update_secondary_debug_counter(sys_command_handle_t *handle,
                                                property_id_t property_id,
                                                void *property_value,
                                                size_t property_length,
                                                status_t status)
{
    (void)handle;

    if (status == STATUS_TIMEOUT)
    {
        WARN("Secondary counters query timed out");
        return;
    } else if (status == STATUS_ABORT)
    {
        WARN("Secondary counters query aborted");
        return;
    }

    if (status != STATUS_OK && status != STATUS_IN_PROGRESS)
    {
        ASSERT();
    }

    if (property_id == PROP_LAST_STATUS)
    {
        ERROR("Secondary does not handle the DEBUG_COUNTERS property, please update secondary or disable print-stats");
    }

    ERROR_ON(property_id != PROP_cpcd_DEBUG_COUNTERS);
    ERROR_ON(property_value == NULL || property_length > sizeof(cpc_cpcd_dbg_cts_t));

    memcpy(&secondary_cpcd_debug_counters, property_value, property_length);
}

static void cpcd_fetch_secondary_debug_counters(epoll_port_private_data_t *event_private_data)
{
    int fd_timer = event_private_data->file_descriptor;

    /* Ack the timer */
    {
        uint64_t expiration;
        ssize_t ret;

        ret = read(fd_timer, &expiration, sizeof(expiration));
        ERROR_ON(ret < 0);
    }

    sys_cmd_property_get(cpcd_update_secondary_debug_counter,
                         PROP_cpcd_DEBUG_COUNTERS, 0, 0, false);
}

static void cpcd_process_rx_hal_notification(epoll_port_private_data_t *event_private_data)
{
    (void)event_private_data;
    uint8_t frame_type;
    slist_node_t *node;
    transmit_queue_item_t *item;
    buffer_handle_t *frame;

    struct timespec tx_complete_timestamp;

    ssize_t ret = recv(hal_sock_notify_fd, &tx_complete_timestamp, sizeof(tx_complete_timestamp), MSG_DONTWAIT);
    if (ret == 0)
    {
        TRACE_CPCD("Driver closed the notification socket");
        int ret_close = close(event_private_data->file_descriptor);
        ERROR_SYSCALL_ON(ret_close != 0);
        return;
    }
    ERROR_SYSCALL_ON(ret < 0);

    // Get first queued frame for transmission
    node = slist_pop(&pending_on_tx_complete);
    item = SLIST_ENTRY(node, transmit_queue_item_t, node);
    ERROR_ON(item == NULL);

    frame = item->handle;
    frame->pending_tx_complete = false;
    frame_type = hdlc_get_frame_type(frame->control);

    switch (frame_type)
    {
    case CPC_HDLC_FRAME_TYPE_IFRAME:

        if (frame->endpoint->state != CPC_EP_STATE_OPEN)
        {
            // Now that tx is completed, we can clear any frames still in the re-tx queue
            cpcd_clear_transmit_queue(&cpcd_endpoints[frame->endpoint->id].re_transmit_queue, -1);
        } else
        {
            // Remember when we sent this i-frame in order to calculate round trip time
            // Only do so if this is not a re_transmit
            if (frame->endpoint->packet_re_transmit_count == 0u)
            {
                frame->endpoint->last_iframe_sent_timestamp = tx_complete_timestamp;
            }

            if (frame->endpoint->re_transmit_queue != NULL && frame->acked == false)
            {
                start_re_transmit_timer(frame->endpoint, tx_complete_timestamp);
            }

            if (frame->acked)
            {
                process_ack(frame->endpoint, frame->pending_ack);
            }
        }

        break;

    case CPC_HDLC_FRAME_TYPE_UFRAME:
    case CPC_HDLC_FRAME_TYPE_SFRAME:
        if (frame->data_length != 0)
        {
            free((void *)frame->data); // Not expecting a reply
        }
        free(frame->hdlc_header);
        free(frame);
        break;

    default:
        ASSERT();
        break;
    }

    free(item);
}

static void cpcd_process_rx_hal(epoll_port_private_data_t *event_private_data)
{
    (void)event_private_data;
    frame_t *rx_frame;
    size_t frame_size;

    /* The hal unblocked, read the frame. Frames from the hal are complete */
    if (cpcd_pull_frame_from_hal(&rx_frame, &frame_size) == false)
    {
        return;
    }

    TRACE_cpcd_RXD_FRAME(rx_frame, frame_size);

    /* Validate header checksum */
    {
        uint16_t hcs = hdlc_get_hcs(rx_frame->header);

        if (!cpc_check_crc_sw(rx_frame->header, CPC_HDLC_HEADER_SIZE, hcs))
        {
            TRACE_cpcd_INVALID_HEADER_CHECKSUM();
            free(rx_frame);
            return;
        }
    }

    uint16_t data_length = hdlc_get_length(rx_frame->header);
    uint8_t address = hdlc_get_address(rx_frame->header);
    uint8_t control = hdlc_get_control(rx_frame->header);
    uint8_t type = hdlc_get_frame_type(control);
    uint8_t ack = hdlc_get_ack(control);

    /* Make sure the length from the header matches the length reported by the hal*/
    ASSERT_ON(data_length != frame_size - CPC_HDLC_HEADER_RAW_SIZE);

    endpoint_t *endpoint = find_endpoint(address);

    /* If endpoint is closed , reject the frame and return unless the frame itself is a reject, if so ignore it */
    if (endpoint->state != CPC_EP_STATE_OPEN)
    {
        if (type != CPC_HDLC_FRAME_TYPE_SFRAME)
        {
            transmit_reject(NULL, address, 0, HDLC_REJECT_UNREACHABLE_ENDPOINT);
        }
        free(rx_frame);
        return;
    }

    /* For data and sframe frames, process the ack right away */
    if (type == CPC_HDLC_FRAME_TYPE_IFRAME || type == CPC_HDLC_FRAME_TYPE_SFRAME)
    {
        process_ack(endpoint, ack);
    }

    switch (type)
    {
    case CPC_HDLC_FRAME_TYPE_IFRAME:
        cpcd_process_rx_i_frame(rx_frame);
        break;
    case CPC_HDLC_FRAME_TYPE_SFRAME:
        cpcd_process_rx_s_frame(rx_frame);
        break;
    case CPC_HDLC_FRAME_TYPE_UFRAME:
        cpcd_process_rx_u_frame(rx_frame);
        break;
    default:
        transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_ERROR);
        TRACE_EP_RXD_SFRAME_DROPPED(endpoint);
        break;
    }

    /* cpcd_pull_frame_from_hal() malloced rx_frame */
    free(rx_frame);
}

bool cpcd_ep_is_closing(uint8_t ep_id)
{
    return cpcd_endpoints[ep_id].state == CPC_EP_STATE_CLOSING;
}

void cpcd_process_endpoint_change(uint8_t endpoint_number, cpc_ep_state_t ep_state)
{
    if (ep_state == CPC_EP_STATE_OPEN)
    {
        if (cpcd_endpoints[endpoint_number].state == CPC_EP_STATE_OPEN)
        {
            return; // Nothing to do
        }

        cpcd_open_endpoint(endpoint_number, 0, 1);
    } else
    {
        cpcd_close_endpoint(endpoint_number, true, false);
    }
}

bool cpcd_ep_is_busy(uint8_t ep_id)
{
    if (cpcd_endpoints[ep_id].holding_list != NULL)
    {
        return true;
    }
    return false;
}

static void cpcd_process_rx_i_frame(frame_t *rx_frame)
{
    endpoint_t *endpoint;

    uint8_t address = hdlc_get_address(rx_frame->header);

    endpoint = &cpcd_endpoints[hdlc_get_address(rx_frame->header)];

    TRACE_EP_RXD_DATA_FRAME(endpoint);

    if (endpoint->id != 0 && (endpoint->state != CPC_EP_STATE_OPEN || primary_listener_list_empty(endpoint->id)))
    {
        transmit_reject(endpoint, address, 0, HDLC_REJECT_UNREACHABLE_ENDPOINT);
        return;
    }

    /* Prevent -2 on a zero length */
    ASSERT_ON(hdlc_get_length(rx_frame->header) < CPC_HDLC_FCS_SIZE);

    uint16_t rx_frame_payload_length = (uint16_t)(hdlc_get_length(rx_frame->header) - CPC_HDLC_FCS_SIZE);

    uint16_t fcs = hdlc_get_fcs(rx_frame->payload, rx_frame_payload_length);

    /* Validate payload checksum. In case it is invalid, NAK the packet. */
    if (!cpc_check_crc_sw(rx_frame->payload, rx_frame_payload_length, fcs))
    {
        WARN("rx_frame_payload_length %d, fcs %04X\r\n", rx_frame_payload_length, fcs);
        transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_CHECKSUM_MISMATCH);
        TRACE_cpcd_INVALID_PAYLOAD_CHECKSUM();
        return;
    }

    uint8_t control = hdlc_get_control(rx_frame->header);
    uint8_t seq = hdlc_get_seq(control);

    // data received, Push in Rx Queue and send Ack
    if (seq == endpoint->ack)
    {
        // Check if the received message is a final reply for the system endpoint
        if (hdlc_is_poll_final(control))
        {
            ASSERT_ON(endpoint->id != 0); // Only system endpoint can receive final messages
            ASSERT_ON(endpoint->poll_final.on_final == NULL); // Received final, but no callback assigned
            endpoint->poll_final.on_final(endpoint->id, (void *)CPC_HDLC_FRAME_TYPE_IFRAME, rx_frame->payload, rx_frame_payload_length);
        } else
        {
            if (endpoint->id == CPC_EP_SYSTEM)
            {
                // unsolicited i-frame
                if (endpoint->on_iframe_data_reception != NULL)
                {
                    endpoint->on_iframe_data_reception(endpoint->id, rx_frame->payload, rx_frame_payload_length);
                }
            } else
            {
                status_t status = cpcd_push_data_to_server(endpoint->id,
                                                           rx_frame->payload,
                                                           rx_frame_payload_length);
                if (status == STATUS_FAIL)
                {
                    // can't recover from that, close endpoint
                    cpcd_close_endpoint(endpoint->id, true, false);
                    return;
                } else if (status == STATUS_WOULD_BLOCK)
                {
                    transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_OUT_OF_MEMORY);
                    return;
                }
            }
        }

        TRACE_EP_RXD_DATA_FRAME_QUEUED(endpoint);

        // Update endpoint acknowledge number
        endpoint->ack++;
        endpoint->ack %= 4;

        // Send ack
        transmit_ack(endpoint);
    } else if (is_seq_valid(seq, endpoint->ack))
    {
        // The packet was already received. We must re-send a ACK because the other side missed it the first time
        TRACE_EP_RXD_DUPLICATE_DATA_FRAME(endpoint);
        transmit_ack(endpoint);
    } else
    {
        transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_SEQUENCE_MISMATCH);
        return;
    }
}

static void cpcd_process_rx_s_frame(frame_t *rx_frame)
{
    endpoint_t *endpoint;
    bool fatal_error = false;

    endpoint = find_endpoint(hdlc_get_address(rx_frame->header));

    TRACE_EP_RXD_SFRAME_FRAME(endpoint);

    cpc_ep_state_t new_state = endpoint->state;

    uint8_t sframe_function = hdlc_get_sframe_function(hdlc_get_control(rx_frame->header));

    uint16_t data_length = (hdlc_get_length(rx_frame->header) > 2) ? (uint16_t)(hdlc_get_length(rx_frame->header) - 2) : 0;

    switch (sframe_function)
    {
    case CPC_HDLC_ACK_SFRAME_FUNCTION:
        TRACE_EP_RXD_SFRAME_PROCESSED(endpoint);
        // ACK; already processed previously by receive_ack(), so nothing to do
        break;

    case CPC_HDLC_REJECT_SFRAME_FUNCTION:

        TRACE_EP_RXD_SFRAME_PROCESSED(endpoint);
        ASSERT_ON(data_length != CPC_HDLC_REJECT_PAYLOAD_SIZE);

        switch (*((reject_reason_t *)rx_frame->payload))
        {
        case HDLC_REJECT_SEQUENCE_MISMATCH:
            // This is not a fatal error when the tx window is > 1
            fatal_error = true;
            new_state = CPC_EP_STATE_ERROR_FAULT;
            TRACE_EP_RXD_REJECT_SEQ_MISMATCH(endpoint);
            WARN("Sequence mismatch on endpoint #%d", endpoint->id);
            break;

        case HDLC_REJECT_CHECKSUM_MISMATCH:
            if (endpoint->re_transmit_queue != NULL)
            {
                re_transmit_frame(endpoint);
            }
            TRACE_EP_RXD_REJECT_CHECKSUM_MISMATCH(endpoint);
            WARN("Remote received a packet with an invalid checksum");
            break;

        case HDLC_REJECT_OUT_OF_MEMORY:
            TRACE_EP_RXD_REJECT_OUT_OF_MEMORY(endpoint);
            break;

        case HDLC_REJECT_UNREACHABLE_ENDPOINT:
            fatal_error = true;
            new_state = CPC_EP_STATE_ERROR_DEST_UNREACH;
            TRACE_EP_RXD_REJECT_DESTINATION_UNREACHABLE(endpoint);
            WARN("Unreachable endpoint #%d", endpoint->id);
            break;

        case HDLC_REJECT_ERROR:
        default:
            fatal_error = true;
            new_state = CPC_EP_STATE_ERROR_FAULT;
            TRACE_EP_RXD_REJECT_FAULT(endpoint);
            WARN("Endpoint #%d fault", endpoint->id);
            break;
        }
        break;

    default:
        ASSERT("Illegal switch");
        break;
    }

    if (fatal_error)
    {
        WARN("Fatal error %d, endoint #%d is in error.", *((reject_reason_t *)rx_frame->payload), endpoint->id);
        cpcd_set_endpoint_in_error(endpoint->id, new_state);
    }
}

static void cpcd_process_rx_u_frame(frame_t *rx_frame)
{
    uint16_t payload_length;
    uint8_t type;
    endpoint_t *endpoint;

    // Retreive info from header
    {
        uint8_t address = hdlc_get_address(rx_frame->header);
        endpoint = find_endpoint(address);
        TRACE_EP_RXD_UFRAME_FRAME(endpoint);

        uint8_t control = hdlc_get_control(rx_frame->header);
        type = hdlc_get_uframe_type(control);

        payload_length = hdlc_get_length(rx_frame->header);

        if (payload_length < 2)
        {
            payload_length = 0;
        } else
        {
            payload_length = (uint16_t)(payload_length - CPC_HDLC_FCS_SIZE);
        }
    }

    // Sanity checks
    {
        // Validate the payload checksum
        if (payload_length > 0)
        {
            uint16_t fcs = hdlc_get_fcs(rx_frame->payload, payload_length);

            if (!cpc_check_crc_sw(rx_frame->payload, payload_length, fcs))
            {
                TRACE_cpcd_INVALID_PAYLOAD_CHECKSUM();
                TRACE_EP_RXD_UFRAME_DROPPED(endpoint, "Bad payload checksum");
                return;
            }
        }

        // Make sure U-Frames are enabled on this endpoint
        if (!(endpoint->flags & OPEN_EP_FLAG_UFRAME_ENABLE))
        {
            TRACE_EP_RXD_UFRAME_DROPPED(endpoint, "U-Frame not enabled on endoint");
            return;
        }

        // If its an Information U-Frame, make sure they are enabled
        if ((type == CPC_HDLC_CONTROL_UFRAME_TYPE_INFORMATION)
            && (endpoint->flags & OPEN_EP_FLAG_UFRAME_INFORMATION_DISABLE))
        {
            TRACE_EP_RXD_UFRAME_DROPPED(endpoint, "Information U-Frame not enabled on endpoint");
            return;
        }
    }

    switch (type)
    {
    case CPC_HDLC_CONTROL_UFRAME_TYPE_INFORMATION:
        if (endpoint->on_uframe_data_reception != NULL)
        {
            endpoint->on_uframe_data_reception(endpoint->id, rx_frame->payload, payload_length);
        }
        break;

    case CPC_HDLC_CONTROL_UFRAME_TYPE_POLL_FINAL:
        if (endpoint->id != CPC_EP_SYSTEM)
        {
            ERROR("Received an unnumbered final frame but it was not addressed to the system enpoint");
        } else if (endpoint->poll_final.on_final != NULL)
        {
            endpoint->poll_final.on_final(endpoint->id, (void *)CPC_HDLC_FRAME_TYPE_UFRAME, rx_frame->payload, payload_length);
        } else
        {
            ASSERT();
        }
        break;

    case CPC_HDLC_CONTROL_UFRAME_TYPE_ACKNOWLEDGE:
        ASSERT_ON(endpoint->id != CPC_EP_SYSTEM);
        sys_on_unnumbered_acknowledgement();
        break;

    default:
        TRACE_EP_RXD_UFRAME_DROPPED(endpoint, "U-Frame not enabled on endpoint");
        return;
    }

    TRACE_EP_RXD_UFRAME_PROCESSED(endpoint);
}

void cpcd_write(uint8_t endpoint_number, const void *message, size_t message_len, uint8_t flags)
{
    endpoint_t *endpoint;
    buffer_handle_t *buffer_handle;
    transmit_queue_item_t *transmit_queue_item;
    bool iframe = true;
    bool poll = (flags & FLAG_INFORMATION_POLL) ? true : false;
    uint8_t type = CPC_HDLC_CONTROL_UFRAME_TYPE_UNKNOWN;
    void *payload = NULL;

    ERROR_ON(message_len > UINT16_MAX);

    endpoint = find_endpoint(endpoint_number);

    /* Sanity checks */
    {
        /* Make sure the endpoint it opened */
        if (endpoint->state != CPC_EP_STATE_OPEN)
        {
            WARN("Tried to write on closed endpoint #%d", endpoint_number);
            return;
        }

        /* if u-frame, make sure they are enabled */
        if ((flags & FLAG_UFRAME_INFORMATION) || (flags & FLAG_UFRAME_RESET_COMMAND) || (flags & FLAG_UFRAME_POLL))
        {
            ERROR_ON(!(endpoint->flags & OPEN_EP_FLAG_UFRAME_ENABLE));

            iframe = false;

            if (flags & FLAG_UFRAME_INFORMATION)
            {
                type = CPC_HDLC_CONTROL_UFRAME_TYPE_INFORMATION;
            } else if (flags & FLAG_UFRAME_RESET_COMMAND)
            {
                type = CPC_HDLC_CONTROL_UFRAME_TYPE_RESET_SEQ;
            } else if ((flags & FLAG_UFRAME_POLL))
            {
                type = CPC_HDLC_CONTROL_UFRAME_TYPE_POLL_FINAL;
            }
        }
        /* if I-frame, make sure they are not disabled */
        else
        {
            ERROR_ON(endpoint->flags & OPEN_EP_FLAG_IFRAME_DISABLE);
        }
    }

    /* Fill the buffer handle */
    {
        buffer_handle = (buffer_handle_t *)calloc_port(sizeof(buffer_handle_t));
        ERROR_SYSCALL_ON(buffer_handle == NULL);

        payload = calloc_port(message_len);
        ERROR_SYSCALL_ON(payload == NULL);
        memcpy(payload, message, message_len);

        buffer_handle->data = payload;
        buffer_handle->data_length = (uint16_t)message_len;
        buffer_handle->endpoint = endpoint;
        buffer_handle->address = endpoint_number;

        if (iframe)
        {
            // Set the SEQ number and ACK number in the control byte
            buffer_handle->control = hdlc_create_ctrl_data(endpoint->seq, endpoint->ack, poll);
            // Update endpoint sequence number
            endpoint->seq++;
            endpoint->seq %= 4;
            TRACE_CPCD("Sequence # is now %d on ep %d", endpoint->seq, endpoint->id);
        } else
        {
            ERROR_ON(type == CPC_HDLC_CONTROL_UFRAME_TYPE_UNKNOWN);
            buffer_handle->control = hdlc_create_ctrl_uframe(type);
        }

        /* Compute the payload's checksum  */
        {
            uint16_t fcs = cpc_get_crc_sw(message, (uint16_t)message_len);

            buffer_handle->fcs[0] = (uint8_t)fcs;
            buffer_handle->fcs[1] = (uint8_t)(fcs >> 8);
        }
    }

    transmit_queue_item = (transmit_queue_item_t *)calloc_port(sizeof(transmit_queue_item_t));
    ERROR_SYSCALL_ON(transmit_queue_item == NULL);

    transmit_queue_item->handle = buffer_handle;

    // Deal with transmit window
    {
        // If U-Frame, skip the window and send immediately
        if (iframe == false)
        {
            slist_push_back(&transmit_queue, &transmit_queue_item->node);
            cpcd_process_transmit_queue();
        } else
        {
            if (endpoint->current_tx_window_space > 0)
            {
                endpoint->current_tx_window_space--;

                //Put frame in Tx Q so that it can be transmitted by CPC Core later
                slist_push_back(&transmit_queue, &transmit_queue_item->node);
                cpcd_process_transmit_queue();
            } else
            {
                //Put frame in endpoint holding list to wait for more space in the transmit window
                slist_push_back(&endpoint->holding_list, &transmit_queue_item->node);
            }
        }
    }
}

void cpcd_open_endpoint(uint8_t endpoint_number, uint8_t flags, uint8_t tx_win_size)
{
    endpoint_t *ep;
    cpc_ep_state_t previous_state;

    ERROR_ON(tx_win_size < TRANSMIT_WINDOW_MIN_SIZE);
    ERROR_ON(tx_win_size > TRANSMIT_WINDOW_MAX_SIZE);

    ep = &cpcd_endpoints[endpoint_number];

    /* Check if endpoint was already opened */
    if (ep->state != CPC_EP_STATE_CLOSED)
    {
        ASSERT("Endpoint already opened");
        return;
    }

    /* Keep the previous state to log the transition */
    previous_state = ep->state;
    memset(ep, 0x00, sizeof(endpoint_t));
    ep->state = previous_state;
    cpcd_set_endpoint_state(endpoint_number, CPC_EP_STATE_OPEN);

    ep->id = endpoint_number;
    ep->flags = flags;
    ep->configured_tx_win_size = tx_win_size;
    ep->current_tx_window_space = ep->configured_tx_win_size;
    ep->re_transmit_timeout_ms = MIN_RE_TRANSMIT_TIMEOUT_MS;

    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    ERROR_SYSCALL_ON(timer_fd < 0);

    /* Setup epoll */
    {
        epoll_port_private_data_t *private_data = (epoll_port_private_data_t *)calloc_port(sizeof(epoll_port_private_data_t));
        ERROR_SYSCALL_ON(private_data == NULL);

        ep->re_transmit_timer_private_data = private_data;

        private_data->callback = cpcd_process_ep_timeout;
        private_data->file_descriptor = timer_fd;
        private_data->endpoint_number = endpoint_number;

        epoll_port_register(private_data);
    }

    slist_init(&ep->re_transmit_queue);
    slist_init(&ep->holding_list);

    TRACE_cpcd_OPEN_ENDPOINT(ep->id);

    return;
}

void cpcd_set_endpoint_in_error(uint8_t endpoint_number, cpc_ep_state_t new_state)
{
    if (endpoint_number == 0)
    {
        WARN("System endpoint in error, new state: %s. Restarting it.", cpcd_stringify_state(new_state));
        sys_request_sequence_reset();
    } else
    {
        WARN("Setting ep#%d in error, new state: %s", endpoint_number, cpcd_stringify_state(new_state));

        primary_close_endpoint(endpoint_number, true);
        cpcd_close_endpoint(endpoint_number, false, false);
        cpcd_set_endpoint_state(endpoint_number, new_state);
    }
}

void cpcd_reset_endpoint_sequence(uint8_t endpoint_number)
{
    cpcd_endpoints[endpoint_number].seq = 0;
    cpcd_endpoints[endpoint_number].ack = 0;
}

static void cpcd_clear_transmit_queue(slist_node_t **head, int endpoint_id)
{
    slist_node_t *current_node;
    slist_node_t *next_node;
    bool filter_with_endpoint_id;
    uint8_t ep_id;

    if (!*head)
    {
        return;
    }

    if (endpoint_id < 0)
    {
        filter_with_endpoint_id = false;
    } else
    {
        filter_with_endpoint_id = true;
        ep_id = (uint8_t)endpoint_id;
    }

    current_node = *head;

    while (current_node)
    {
        next_node = current_node->node;

        transmit_queue_item_t *item = SLIST_ENTRY(current_node, transmit_queue_item_t, node);
        if (!filter_with_endpoint_id
            || (filter_with_endpoint_id && item->handle->address == ep_id))
        {
            if (item->handle->pending_tx_complete == false)
            {
                free(item->handle->hdlc_header);

                // free payload if any
                if (item->handle->data_length != 0)
                {
                    // free payload
                    free((void *)item->handle->data);
                }
                free(item->handle);

                // remove element from list and free it
                slist_remove(head, &item->node);
                free(item);
            }
        }

        current_node = next_node;
    }
}

status_t cpcd_close_endpoint(uint8_t endpoint_number, bool notify_secondary, bool force_close)
{
    endpoint_t *ep;

    ep = find_endpoint(endpoint_number);

    ASSERT_ON(ep->state == CPC_EP_STATE_CLOSED);

    TRACE_CPCD("Closing endpoint #%d", endpoint_number);

    stop_re_transmit_timer(ep);

    cpcd_clear_transmit_queue(&ep->re_transmit_queue, -1);
    cpcd_clear_transmit_queue(&ep->holding_list, -1);
    cpcd_clear_transmit_queue(&transmit_queue, endpoint_number);
    cpcd_clear_transmit_queue(&pending_on_security_ready_queue, endpoint_number);

    if (notify_secondary)
    {
        // State will be set to closed when secondary closes its endpoint
        cpcd_set_endpoint_state(ep->id, CPC_EP_STATE_CLOSING);

        // Notify the secondary that the endpoint should get closed
        sys_cmd_property_set(on_disconnect_notification,
                             5,            /* 5 retries */
                             100000,           /* 100ms between retries*/
                             EP_ID_TO_PROPERTY_STATE(ep->id),
                             &ep->state,
                             sizeof(cpc_ep_state_t),
                             false);
    }

    if (ep->re_transmit_timer_private_data != NULL)
    {
        epoll_port_unregister(ep->re_transmit_timer_private_data);

        close(((epoll_port_private_data_t *)ep->re_transmit_timer_private_data)->file_descriptor);
        free(ep->re_transmit_timer_private_data);

        ep->re_transmit_timer_private_data = NULL;
    }

    if (force_close)
    {
        cpcd_set_endpoint_state(ep->id, CPC_EP_STATE_CLOSED);
        TRACE_cpcd_CLOSE_ENDPOINT(ep->id);
    }

    return STATUS_OK;
}

void cpcd_set_endpoint_option(uint8_t endpoint_number,
                              endpoint_option_t option,
                              void *value)
{
    endpoint_t *ep = &cpcd_endpoints[endpoint_number];

    ERROR_ON(ep->state != CPC_EP_STATE_OPEN);

    switch (option)
    {
    case EP_ON_IFRAME_RECEIVE:
        ep->on_iframe_data_reception = (on_data_reception_t)value;
        break;
    case EP_ON_IFRAME_RECEIVE_ARG:
        ASSERT("invalid option");
        break;
    case EP_ON_UFRAME_RECEIVE:
        ep->on_uframe_data_reception = (on_data_reception_t)value;
        break;
    case EP_ON_UFRAME_RECEIVE_ARG:
        ASSERT("invalid option");
        break;
    case EP_ON_IFRAME_WRITE_COMPLETED:
        ASSERT("invalid option");
        break;
    case EP_ON_IFRAME_WRITE_COMPLETED_ARG:
        ASSERT("invalid option");
        break;
    case EP_ON_UFRAME_WRITE_COMPLETED:
        ASSERT("invalid option");
        break;
    case EP_ON_UFRAME_WRITE_COMPLETED_ARG:
        ASSERT("invalid option");
        break;
    case EP_ON_FINAL:
        ep->poll_final.on_final = value;
        break;
    case EP_ON_POLL:
        // Can't happen on the primary
        ASSERT("invalid option");
        break;
    case EP_ON_POLL_ARG:
    case EP_ON_FINAL_ARG:
        ep->poll_final.on_fnct_arg = value;
        break;
    default:
        ASSERT("invalid option");
        break;
    }
}

static void process_ack(endpoint_t *endpoint, uint8_t ack)
{
    transmit_queue_item_t *item;
    slist_node_t *item_node;
    buffer_handle_t *frame;
    uint8_t control_byte;
    uint8_t seq_number;
    uint8_t ack_range_min;
    uint8_t ack_range_max;
    uint8_t frames_count_ack = 0;

    // Return if no frame to acknowledge
    if (endpoint->re_transmit_queue == NULL)
    {
        return;
    }

    // Get the sequence number of the first frame in the re-transmission queue
    item = SLIST_ENTRY(endpoint->re_transmit_queue, transmit_queue_item_t, node);
    frame = item->handle;

    control_byte = hdlc_get_control(frame->hdlc_header);
    seq_number = hdlc_get_seq(control_byte);

    // Calculate the acceptable ACK number range
    ack_range_min = (uint8_t)(seq_number + 1);
    ack_range_min %= 4;
    ack_range_max = (uint8_t)(seq_number + endpoint->frames_count_re_transmit_queue);
    ack_range_max %= 4;

    // Check that received ACK number is in range
    if (ack_range_max >= ack_range_min)
    {
        if (ack < ack_range_min
            || ack > ack_range_max)
        {
            // Invalid ack number
            return;
        }
    } else
    {
        if (ack > ack_range_max
            && ack < ack_range_min)
        {
            // Invalid ack number
            return;
        }
    }

    // Find number of frames acknowledged with ACK number
    if (ack > seq_number)
    {
        frames_count_ack = (uint8_t)(ack - seq_number);
    } else
    {
        frames_count_ack = (uint8_t)(4 - seq_number);
        frames_count_ack = (uint8_t)(frames_count_ack + ack);
    }

    // Stop incoming re-transmit timeout
    stop_re_transmit_timer(endpoint);

    // This can happen during a re_transmit, process the ack once the frame is sent
    if (frame->pending_tx_complete == true)
    {
        frame->acked = true;
        frame->pending_ack = ack;
        return;
    }

    // Reset re-transmit counter
    endpoint->packet_re_transmit_count = 0u;

    TRACE_CPCD("%d Received ack %d seq number %d", endpoint->id, ack, seq_number);
    cpcd_compute_re_transmit_timeout(endpoint);

    // Remove all acknowledged frames in re-transmit queue
    for (uint8_t i = 0; i < frames_count_ack; i++)
    {
        item_node = slist_pop(&endpoint->re_transmit_queue);
        ASSERT_ON(item_node == NULL);

        item = SLIST_ENTRY(item_node, transmit_queue_item_t, node);
        frame = item->handle;
        control_byte = hdlc_get_control(frame->hdlc_header);

        ASSERT_ON(hdlc_get_frame_type(frame->control) != CPC_HDLC_FRAME_TYPE_IFRAME);

#ifdef USE_ON_WRITE_COMPLETE
        on_write_completed(endpoint->id, STATUS_OK);
#endif

        if (endpoint->id == CPC_EP_SYSTEM && hdlc_is_poll_final(control_byte))
        {
            sys_cmd_poll_acknowledged(frame->data);
        }

        free((void *)frame->data);
        free(frame->hdlc_header);
        free(frame);
        free(item);

        // Update number of frames in re-transmit queue
        endpoint->frames_count_re_transmit_queue--;

        // Update transmit window
        endpoint->current_tx_window_space++;

        if (endpoint->re_transmit_queue == NULL)
        {
            break;
        }
    }

    // Put data frames hold in the endpoint in the tx queue if space in transmit window
    while (endpoint->holding_list != NULL && endpoint->current_tx_window_space > 0)
    {
        slist_node_t *item = slist_pop(&endpoint->holding_list);
        slist_push_back(&transmit_queue, item);
        endpoint->current_tx_window_space--;
        epoll_port_watch_back(endpoint->id);
    }

    TRACE_EP_RXD_ACK(endpoint, ack);
}

static void transmit_ack(endpoint_t *endpoint)
{
    buffer_handle_t *handle;
    transmit_queue_item_t *item;

    // Get new frame handler
    handle = (buffer_handle_t *)calloc_port(sizeof(buffer_handle_t));
    ERROR_SYSCALL_ON(handle == NULL);

    handle->endpoint = endpoint;
    handle->address = endpoint->id;

    // Set ACK number in the sframe control byte
    handle->control = hdlc_create_ctrl_sframe(endpoint->ack, 0);

    // Put frame in Tx Q so that it can be transmitted by CPC Core later
    item = (transmit_queue_item_t *)calloc_port(sizeof(transmit_queue_item_t));
    ERROR_SYSCALL_ON(item == NULL);

    item->handle = handle;

    slist_push_back(&transmit_queue, &item->node);
    TRACE_CPCD("Endpoint #%d sent ACK: %d", endpoint->id, endpoint->ack);

    cpcd_process_transmit_queue();

    TRACE_EP_TXD_ACK(endpoint);
}

static void re_transmit_frame(endpoint_t *endpoint)
{
    transmit_queue_item_t *item;
    slist_node_t *item_node;

    item_node = slist_pop(&endpoint->re_transmit_queue);

    ASSERT_ON(item_node == NULL);

    item = SLIST_ENTRY(item_node, transmit_queue_item_t, node);

    // Don't re_transmit the frame if it is already being transmitted
    if (item->handle->pending_tx_complete == true)
    {
        slist_push(&endpoint->re_transmit_queue, &item->node);
        return;
    }

    // Only i-frames support retransmission
    ASSERT_ON(hdlc_get_frame_type(item->handle->control) != CPC_HDLC_FRAME_TYPE_IFRAME);

    // Free the previous header buffer. The tx queue process will malloc a new one and fill it.
    free(item->handle->hdlc_header);

    endpoint->packet_re_transmit_count++;
    endpoint->frames_count_re_transmit_queue--;

    //Put frame in Tx Q so that it can be transmitted by CPC Core later
    slist_push(&transmit_queue, &item->node);

    TRACE_EP_RETXD_DATA_FRAME(endpoint);

    return;
}

static void transmit_reject(endpoint_t *endpoint,
                            uint8_t address,
                            uint8_t ack,
                            reject_reason_t reason)
{
    uint16_t fcs;
    buffer_handle_t *handle;
    transmit_queue_item_t *item;

    handle = (buffer_handle_t *)calloc_port(sizeof(buffer_handle_t));
    ERROR_ON(handle == NULL);

    handle->address = address;

    // Set the SEQ number and ACK number in the control byte
    handle->control = hdlc_create_ctrl_sframe(ack, CPC_HDLC_REJECT_SFRAME_FUNCTION);

    handle->data = calloc_port(sizeof(uint8_t));
    ERROR_SYSCALL_ON(handle->data == NULL);

    // Set in reason
    *((uint8_t *)handle->data) = (uint8_t)reason;
    handle->data_length = sizeof(uint8_t);

    // Compute payload CRC
    fcs = cpc_get_crc_sw(handle->data, 1);
    handle->fcs[0] = (uint8_t)fcs;
    handle->fcs[1] = (uint8_t)(fcs >> 8);

    // Put frame in Tx Q so that it can be transmitted by CPC Core later
    item = (transmit_queue_item_t *)calloc_port(sizeof(transmit_queue_item_t));
    ERROR_SYSCALL_ON(item == NULL);

    item->handle = handle;

    slist_push_back(&transmit_queue, &item->node);

    if (endpoint != NULL)
    {
        switch (reason)
        {
        case HDLC_REJECT_CHECKSUM_MISMATCH:
            TRACE_EP_TXD_REJECT_CHECKSUM_MISMATCH(endpoint);
            WARN("Host received a packet with an invalid checksum on ep %d", endpoint->id);
            break;
        case HDLC_REJECT_SEQUENCE_MISMATCH:
            TRACE_EP_TXD_REJECT_SEQ_MISMATCH(endpoint);
            break;
        case HDLC_REJECT_OUT_OF_MEMORY:
            TRACE_EP_TXD_REJECT_OUT_OF_MEMORY(endpoint);
            break;
        case HDLC_REJECT_SECURITY_ISSUE:
            TRACE_EP_TXD_REJECT_SECURITY_ISSUE(endpoint);
            break;
        case HDLC_REJECT_UNREACHABLE_ENDPOINT:
            TRACE_EP_TXD_REJECT_DESTINATION_UNREACHABLE(endpoint);
            break;
        case HDLC_REJECT_ERROR:
        default:
            TRACE_EP_TXD_REJECT_FAULT(endpoint);
            break;
        }
    } else
    {
        switch (reason)
        {
        case HDLC_REJECT_UNREACHABLE_ENDPOINT:
            TRACE_cpcd_TXD_REJECT_DESTINATION_UNREACHABLE();
            break;
        default:
            ERROR();
            break;
        }
    }
}

static bool cpcd_process_tx_queue(void)
{
    slist_node_t *node;
    transmit_queue_item_t *item;
    transmit_queue_item_t *tx_complete_item;
    buffer_handle_t *frame;
    uint16_t total_length;
    uint8_t frame_type;

    if (pending_on_security_ready_queue != NULL)
    {
        TRACE_CPCD("Sending packet that were hold back because security was not ready");
        node = slist_pop(&pending_on_security_ready_queue);
    } else
    {
        // Return if nothing to transmit
        if (transmit_queue == NULL)
        {
            TRACE_CPCD("transmit_queue is empty and cpcd is not ready yet to process hold back packets");
            return false;
        }

        // Get first queued frame for transmission
        node = slist_pop(&transmit_queue);
    }

    item = SLIST_ENTRY(node, transmit_queue_item_t, node);
    frame = item->handle;

    frame->hdlc_header = calloc_port(CPC_HDLC_HEADER_RAW_SIZE);
    ERROR_SYSCALL_ON(frame->hdlc_header == NULL);

    // Form the HDLC header
    total_length = (frame->data_length != 0) ? (uint16_t)(frame->data_length + 2) : 0;

    frame_type = hdlc_get_frame_type(frame->control);

    if (frame_type == CPC_HDLC_FRAME_TYPE_IFRAME)
    {
        hdlc_set_ctrl_ack(&frame->control, frame->endpoint->ack);
    } else if (frame_type == CPC_HDLC_FRAME_TYPE_UFRAME)
    {
        ASSERT_ON(frame->endpoint->id != CPC_EP_SYSTEM);
    }

    hdlc_create_header(frame->hdlc_header, frame->address, total_length, frame->control, true);

    uint16_t encrypted_data_length = frame->data_length;
    uint8_t *encrypted_payload = (uint8_t *)frame->data;

    /* Construct and send the frame to the hal */
    {
        // total_length takes into account FCS and security tag
        size_t frame_length = CPC_HDLC_HEADER_RAW_SIZE + total_length;

        frame_t *frame_buffer = (frame_t *)calloc_port(frame_length);
        ERROR_ON(frame_buffer == NULL);

        /* copy the header */
        memcpy(frame_buffer->header, frame->hdlc_header, CPC_HDLC_HEADER_RAW_SIZE);

        /* copy the payload */
        memcpy(frame_buffer->payload, encrypted_payload, encrypted_data_length);

        if (encrypted_data_length != 0)
        {
            memcpy(&frame_buffer->payload[encrypted_data_length], frame->fcs, sizeof(frame->fcs));
        }

        frame->pending_tx_complete = true;

        tx_complete_item = (transmit_queue_item_t *)malloc(sizeof(transmit_queue_item_t));
        ERROR_SYSCALL_ON(tx_complete_item == NULL);
        tx_complete_item->handle = frame;

        slist_push_back(&pending_on_tx_complete, &tx_complete_item->node);

        cpcd_push_frame_to_hal(frame_buffer, frame_length);

        free(frame_buffer);
        if (frame->data != encrypted_payload)
        {
            /* in case a buffer was allocated for allocation, free it */
            free((void *)encrypted_payload);
        }
    }

    TRACE_EP_FRAME_TRANSMIT_SUBMITTED(frame->endpoint);

    if (frame_type == CPC_HDLC_FRAME_TYPE_IFRAME)
    {
        // Put frame in in re-transmission queue if it's a I-frame type (with data)
        slist_push_back(&frame->endpoint->re_transmit_queue, &item->node);
        frame->endpoint->frames_count_re_transmit_queue++;
    } else
    {
        free(item); // Free transmit queue item
    }

    return true;
}

static void re_transmit_timeout(endpoint_t *endpoint)
{
    if (endpoint->packet_re_transmit_count >= CPC_RE_TRANSMIT)
    {
        WARN("Retransmit limit reached on endpoint #%d", endpoint->id);
        cpcd_set_endpoint_in_error(endpoint->id, CPC_EP_STATE_ERROR_DEST_UNREACH);
    } else
    {
        endpoint->re_transmit_timeout_ms *= 2;
        if (endpoint->re_transmit_timeout_ms > MAX_RE_TRANSMIT_TIMEOUT_MS)
        {
            endpoint->re_transmit_timeout_ms = MAX_RE_TRANSMIT_TIMEOUT_MS;
        }

        TRACE_CPCD("New RTO calculated on ep %d, after re_transmit timeout: %ldms", endpoint->id, endpoint->re_transmit_timeout_ms);

        re_transmit_frame(endpoint);
    }
}

static bool is_seq_valid(uint8_t seq, uint8_t ack)
{
    bool result = false;

    if (seq == (ack - 1u))
    {
        result = true;
    } else if (ack == 0u && seq == 3u)
    {
        result = true;
    }

    return result;
}

static endpoint_t *find_endpoint(uint8_t endpoint_number)
{
    return &cpcd_endpoints[endpoint_number];
}

static void stop_re_transmit_timer(endpoint_t *endpoint)
{
    int ret;
    epoll_port_private_data_t *fd_timer_private_data;

    /* Passing itimerspec with it_value of 0 stops the timer. */
    const struct itimerspec cancel_time = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                            .it_value = { .tv_sec = 0, .tv_nsec = 0 } };

    fd_timer_private_data = endpoint->re_transmit_timer_private_data;

    if (fd_timer_private_data == NULL)
    {
        return;
    }

    ret = timerfd_settime(fd_timer_private_data->file_descriptor,
                          0,
                          &cancel_time,
                          NULL);

    ERROR_SYSCALL_ON(ret < 0);
}

static double diff_timespec_ms(const struct timespec *final, const struct timespec *initial)
{
    return (double)((final->tv_sec - initial->tv_sec) * 1000)
           + (double)(final->tv_nsec - initial->tv_nsec) / 1000000.0;
}

static void start_re_transmit_timer(endpoint_t *endpoint, struct timespec offset)
{
    int ret;
    epoll_port_private_data_t *fd_timer_private_data;

    struct timespec current_timestamp;
    clock_gettime(CLOCK_MONOTONIC, &current_timestamp);

    long offset_in_ms;

    offset_in_ms = (long)diff_timespec_ms(&offset, &current_timestamp);

    fd_timer_private_data = endpoint->re_transmit_timer_private_data;

    if (offset_in_ms < 0)
    {
        offset_in_ms = 0;
    }

    if (endpoint->state != CPC_EP_STATE_OPEN)
    {
        return;
    }

    /* Make sure the timer file descriptor is open*/
    ERROR_ON(fd_timer_private_data == NULL);
    ERROR_ON(fd_timer_private_data->file_descriptor < 0);

    struct itimerspec timeout_time = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                       .it_value = { .tv_sec = ((offset_in_ms + endpoint->re_transmit_timeout_ms) / 1000), .tv_nsec = (((offset_in_ms + endpoint->re_transmit_timeout_ms) % 1000) * 1000000) } };

    ret = timerfd_settime(fd_timer_private_data->file_descriptor,
                          0,
                          &timeout_time,
                          NULL);

    ERROR_SYSCALL_ON(ret < 0);
}

static void cpcd_process_ep_timeout(epoll_port_private_data_t *event_private_data)
{
    int fd_timer = event_private_data->file_descriptor;
    uint8_t endpoint_number = event_private_data->endpoint_number;

    /* Ack the timer */
    {
        uint64_t expiration;
        ssize_t ret;

        ret = read(fd_timer, &expiration, sizeof(expiration));
        ERROR_ON(ret < 0);

        /* we missed a timeout*/
        WARN_ON(expiration != 1);
    }

    re_transmit_timeout(&cpcd_endpoints[endpoint_number]);
}

static void cpcd_push_frame_to_hal(const void *frame, size_t frame_len)
{
    TRACE_FRAME("Core : Pushed frame to cpc : ", frame, frame_len);
    ssize_t ret = send(hal_sock_fd, frame, frame_len, 0);

    ERROR_SYSCALL_ON(ret < 0);

    ERROR_ON((size_t)ret != frame_len);

    TRACE_cpcd_TXD_TRANSMIT_COMPLETED();
}

static bool cpcd_pull_frame_from_hal(frame_t **frame_buf, size_t *frame_buf_len)
{
    size_t datagram_length;

    /* Poll the socket to get the next pending datagram size */
    {
        ssize_t retval = recv(hal_sock_fd, NULL, 0, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
        ERROR_SYSCALL_ON(retval < 0);
        datagram_length = (size_t)retval;

        /* Socket closed */
        if (retval == 0)
        {
            TRACE_CPCD("Driver closed the data socket");
            int ret_close = close(hal_sock_fd);
            ERROR_SYSCALL_ON(ret_close != 0);
            return false;
        }

        ASSERT_ON(datagram_length == 0);

        /* The length of the frame should be at minimum a header length */
        ASSERT_ON(datagram_length < sizeof(frame_t));
    }

    /* Allocate a buffer of the right size */
    {
        *frame_buf = (frame_t *)calloc_port((size_t)datagram_length);
        ERROR_SYSCALL_ON(*frame_buf == NULL);
    }

    /* Fetch the datagram from the hal socket */
    {
        ssize_t ret = recv(hal_sock_fd, *frame_buf, (size_t)datagram_length, 0);

        ERROR_SYSCALL_ON(ret < 0);

        /* The next pending datagram size should be equal to what we just read */
        ERROR_ON((size_t)ret != (size_t)datagram_length);
    }

    *frame_buf_len = (size_t)datagram_length;
    return true;
}

static status_t cpcd_push_data_to_server(uint8_t ep_id, const void *data, size_t data_len)
{
    return primary_push_data_to_endpoint(ep_id, data, data_len);
}
