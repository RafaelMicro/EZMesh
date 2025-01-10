#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "utility/config.h"
#include "utility/list.h"
#include "utility/log.h"
#include "utility/utility.h"

#include "core.h"
#include "daemon/primary/primary.h"
#include "host/hal_epoll.h"
#include "host/hal_memory.h"

#define ABS(a) ((a) < 0 ? -(a) : (a))
#define X_ENUM_TO_STR(x) #x
#define ENUM_TO_STR(x) X_ENUM_TO_STR(x)

/*******************************************************************************
 ***************************  GLOBAL VARIABLES   *******************************
 ******************************************************************************/
dbg_cts_t primary_cpcd_debug_counters;
dbg_cts_t secondary_cpcd_debug_counters;

/*******************************************************************************
 ***************************  LOCAL DECLARATIONS   *****************************
 ******************************************************************************/

/*******************************************************************************
 ***************************  LOCAL VARIABLES   ********************************
 ******************************************************************************/
static int hal_sock_fd;
static int hal_sock_notify_fd;
static int timer_fd;
static endpoint_t core_endpoints[EP_MAX_COUNT];
static list_node_t *transmit_queue = NULL;
static list_node_t *pending_on_security_ready_queue = NULL;
static list_node_t *pending_on_tx_complete = NULL;

/*******************************************************************************
 **************************   LOCAL FUNCTIONS   ********************************
 *****************************************************************************/
static void core_proc_rx_hal_notification(hal_epoll_event_data_t *event_data);
static void core_proc_rx_hal(hal_epoll_event_data_t *event_data);
static void core_proc_endpoint_timeout(hal_epoll_event_data_t *event_data);
static void core_proc_rx_iframe(frame_t *rx_frame);
static void core_proc_rx_sframe(frame_t *rx_frame);
static void core_proc_rx_uframe(frame_t *rx_frame);
static bool core_proc_tx_data(void);
static void core_clear_tx_queue(list_node_t **head, int endpoint_id);
static void proc_ack(endpoint_t *endpoint, uint8_t ack);
static void send_ack(endpoint_t *endpoint);
static void retry_frame(endpoint_t *endpoint);
static bool is_seq_valid(uint8_t seq, uint8_t ack);
static endpoint_t *find_endpoint(uint8_t endpoint_number);
static void transmit_reject(endpoint_t *endpoint, uint8_t address, uint8_t ack,
                            reject_reason_t reason);
static void stop_retry_timer(endpoint_t *endpoint);
static void start_retry_timer(endpoint_t *endpoint, struct timespec offset);
static void core_push_frame_to_hal(const void *frame, size_t frame_len);
static bool core_pull_frame_from_hal(frame_t **frame_buf,
                                     size_t *frame_buf_len);
static status_t core_push_data_to_server(uint8_t ep_id, const void *data,
                                         size_t data_len);
static void
core_fetch_secondary_debug_counters(hal_epoll_event_data_t *event_data);

/*******************************************************************************
 **************************   IMPLEMENTATION    ********************************
 ******************************************************************************/

typedef union {
  uint8_t bytes[2];
  uint16_t uint16;
} uint16_u;

static inline uint16_t __hdlc_get_hcs(const uint8_t *header_buf) {
  uint16_u u;
  u.bytes[0] = header_buf[HDLC_HCS_POS];
  u.bytes[1] = header_buf[HDLC_HCS_POS + 1];
  return le16_to_cpu(u.uint16);
}

static inline bool __hdlc_is_poll_final(uint8_t control) {
  return (control & (1 << HDLC_CONTROL_P_F_POS)) ? true : false;
}

static inline void __hdlc_set_ctrl_ack(uint8_t *control, uint8_t ack) {
#if (EZMESH_HDLC_SEQ_8 == 1)
  *control = (uint8_t)(*control & ~0x07);
#else
  *control = (uint8_t)(*control & ~0x03);
#endif
  *control |= ack;
}

static status_t state_passer(ez_err_t val) {
  return (val == NO_ERROR) ? STATUS_OK : STATUS_FAIL;
}

ep_state_t core_endpoint_state(uint8_t state) {
#define STATE_FREED 6 // State freed, internal to Secondary

  switch (state) {
  case ENDPOINT_STATE_OPEN:
  case ENDPOINT_STATE_CLOSED:
  case ENDPOINT_STATE_CLOSING:
  case ENDPOINT_STATE_ERROR_DEST_UNREACH:
  case ENDPOINT_STATE_ERROR_FAULT:
    return state;
  case STATE_FREED:
    return ENDPOINT_STATE_CLOSED;
  default:
    log_crash("A new state (%d) has been added to the Secondary that has no "
              "equivalent on the daemon.",
              state);
  }
  return state;
}

const char *core_stringify_state(ep_state_t state) {
  switch (state) {
  case ENDPOINT_STATE_OPEN:
    return ENUM_TO_STR(ENDPOINT_STATE_OPEN);
  case ENDPOINT_STATE_CLOSED:
    return ENUM_TO_STR(ENDPOINT_STATE_CLOSED);
  case ENDPOINT_STATE_CLOSING:
    return ENUM_TO_STR(ENDPOINT_STATE_CLOSING);
  case ENDPOINT_STATE_ERROR_DEST_UNREACH:
    return ENUM_TO_STR(ENDPOINT_STATE_ERROR_DEST_UNREACH);
  case ENDPOINT_STATE_ERROR_FAULT:
    return ENUM_TO_STR(ENDPOINT_STATE_ERROR_FAULT);
  default:
    log_crash("A new state (%d) has been added to the Secondary that has no "
              "equivalent on the daemon.",
              state);
  }
  return ENUM_TO_STR(state);
}

static void disconnect_notification_callback(sys_cmd_handle_t *handle,
                                             property_id_t property_id,
                                             void *property_value,
                                             size_t property_length,
                                             status_t status) {
  (void)handle;
  (void)property_length;
  (void)property_value;

  uint8_t ep_id = ((uint8_t)(property_id & 0x000000FF));

  CHECK_ERROR(core_endpoints[ep_id].state == ENDPOINT_STATE_OPEN);

  switch (status) {
  case STATUS_IN_PROGRESS:
  case STATUS_OK:
    log_info("Disconnection notification received for ep#%d", ep_id);
    core_set_endpoint_state(ep_id, ENDPOINT_STATE_CLOSED);
    break;

  case STATUS_TIMEOUT:
  case STATUS_ABORT:
    core_set_endpoint_in_error(ep_id, ENDPOINT_STATE_ERROR_DEST_UNREACH);
    log_warn("Failed to receive disconnection notification for ep#%d", ep_id);
    break;
  default:
    log_error("Unknown status during disconnection notification");
    break;
  }
}

static void core_calculate_retry_timeout(endpoint_t *endpoint) {
  static bool first_rtt_measurement = true;
  struct timespec current_time = {0};
  int64_t current_timestamp_ms = 0;
  int64_t previous_timestamp_ms = 0;
  long round_trip_time_ms = 0;
  long rto = 0;

  const uint8_t k = 4;

  CHECK_ERROR(endpoint == NULL);

  clock_gettime(CLOCK_MONOTONIC, &current_time);

  current_timestamp_ms =
      (current_time.tv_sec * 1000) + (current_time.tv_nsec / 1000000);
  previous_timestamp_ms =
      (endpoint->last_iframe_sent_timestamp.tv_sec * 1000) +
      (endpoint->last_iframe_sent_timestamp.tv_nsec / 1000000);
  round_trip_time_ms = (long)(current_timestamp_ms - previous_timestamp_ms);

  if (round_trip_time_ms <= 0) {
    round_trip_time_ms = 1;
  }
  CHECK_ERROR(round_trip_time_ms < 0);

  if (first_rtt_measurement) {
    endpoint->smoothed_rtt = round_trip_time_ms;
    endpoint->rtt_variation = round_trip_time_ms / 2;
    first_rtt_measurement = false;
  } else {
    // RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'| where beta is 0.25
    endpoint->rtt_variation =
        3 * (endpoint->rtt_variation / 4) +
        ABS(endpoint->smoothed_rtt - round_trip_time_ms) / 4;

    // SRTT <- (1 - alpha) * SRTT + alpha * R' where alpha is 0.125
    endpoint->smoothed_rtt =
        7 * (endpoint->smoothed_rtt / 8) + round_trip_time_ms / 8;
  }

  if (endpoint->rtt_variation < MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS) {
    endpoint->rtt_variation = MIN_RE_TRANSMIT_TIMEOUT_MINIMUM_VARIATION_MS;
  }
  rto = endpoint->smoothed_rtt + k * endpoint->rtt_variation;
  CHECK_ERROR(rto <= 0);

  if (rto > MAX_RE_TRANSMIT_TIMEOUT_MS) {
    rto = MAX_RE_TRANSMIT_TIMEOUT_MS;
  } else if (rto < MIN_RE_TRANSMIT_TIMEOUT_MS) {
    rto = MIN_RE_TRANSMIT_TIMEOUT_MS;
  }
  endpoint->retry_timeout_ms = rto;
}

static hal_epoll_event_data_t *core_rx_epoll_data = NULL;
static hal_epoll_event_data_t *core_rx_notification_epoll_data = NULL;

ez_err_t core_deinit(void) {
  log_info("[PRI] HDLC Core Deinit");
  if (core_rx_notification_epoll_data) {
    hal_epoll_unregister(
        (hal_epoll_event_data_t *)core_rx_notification_epoll_data);
    HAL_MEM_FREE(&core_rx_notification_epoll_data);
  }
  if (core_rx_epoll_data) {
    hal_epoll_unregister((hal_epoll_event_data_t *)core_rx_epoll_data);
    HAL_MEM_FREE(&core_rx_epoll_data);
  }
  return NO_ERROR;
}

void core_init(int hal_fd, int hal_notify_fd) {
  hal_sock_fd = hal_fd;
  hal_sock_notify_fd = hal_notify_fd;
  size_t i = 0;

  for (i = 0; i < EP_MAX_COUNT; i++) {
    core_endpoints[i].id = (uint8_t)i;
    core_endpoints[i].state = ENDPOINT_STATE_CLOSED;
    core_endpoints[i].ack = 0;
    core_endpoints[i].configured_tx_win_size = 1;
    core_endpoints[i].current_tx_window_space = 1;
    core_endpoints[i].retry_timer_data = NULL;
    core_endpoints[i].on_uframe_data_reception = NULL;
    core_endpoints[i].on_iframe_data_reception = NULL;
    core_endpoints[i].last_iframe_sent_timestamp = (struct timespec){0};
    core_endpoints[i].smoothed_rtt = 0;
    core_endpoints[i].rtt_variation = 0;
    core_endpoints[i].retry_timeout_ms = MAX_RE_TRANSMIT_TIMEOUT_MS;
    core_endpoints[i].packet_retry_count = 0;
  }

  core_rx_epoll_data =
      (hal_epoll_event_data_t *)HAL_MEM_ALLOC(sizeof(hal_epoll_event_data_t));
  core_rx_epoll_data->callback = core_proc_rx_hal;
  core_rx_epoll_data->file_descriptor = hal_fd;
  core_rx_epoll_data->endpoint_number = 0;
  hal_epoll_register((hal_epoll_event_data_t *)core_rx_epoll_data);

  core_rx_notification_epoll_data =
      (hal_epoll_event_data_t *)HAL_MEM_ALLOC(sizeof(hal_epoll_event_data_t));
  core_rx_notification_epoll_data->callback = core_proc_rx_hal_notification;
  core_rx_notification_epoll_data->file_descriptor = hal_notify_fd;
  core_rx_notification_epoll_data->endpoint_number = 0;
  hal_epoll_register((hal_epoll_event_data_t *)core_rx_notification_epoll_data);

  if (config.stats_interval > 0) {
    int ret = 0;
    struct itimerspec timeout_time = {0};
    hal_epoll_event_data_t *event_epoll = NULL;

    // log_info("timeout: %d\r\n", config.stats_interval);
    timeout_time.it_interval.tv_sec = config.stats_interval;
    timeout_time.it_interval.tv_nsec = 0;
    timeout_time.it_value.tv_sec = config.stats_interval;
    timeout_time.it_value.tv_nsec = 0;

    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    CHECK_ERROR(timer_fd < 0);
    ret = timerfd_settime(timer_fd, 0, &timeout_time, NULL);
    CHECK_ERROR(ret < 0);

    event_epoll =
        (hal_epoll_event_data_t *)HAL_MEM_ALLOC(sizeof(hal_epoll_event_data_t));
    CHECK_ERROR(event_epoll == NULL);

    event_epoll->callback = core_fetch_secondary_debug_counters;
    event_epoll->file_descriptor = timer_fd;
    hal_epoll_register(event_epoll);
  }

  list_init(&pending_on_tx_complete);
}

void core_process_transmit_queue(void) {
  do {
    if (transmit_queue == NULL && pending_on_security_ready_queue == NULL)
      break;
    if (!core_proc_tx_data())
      break;
  } while (1);
}

ep_state_t core_get_endpoint_state(uint8_t ep_id) {
  CHECK_ERROR(ep_id == 0);
  return core_endpoints[ep_id].state;
}

void core_set_endpoint_state(uint8_t ep_id, ep_state_t state) {
  if (core_endpoints[ep_id].state != state) {
    log_info("Changing ep#%d state from %s to %s", ep_id,
             core_stringify_state(core_endpoints[ep_id].state),
             core_stringify_state(state));
    core_endpoints[ep_id].state = state;
    EP_set_state(ep_id, state);
  }
}

bool core_get_endpoint_encryption(uint8_t ep_id) {
  (void)ep_id;
  return false;
}

static void cpcd_update_secondary_debug_counter(sys_cmd_handle_t *handle,
                                                property_id_t property_id,
                                                void *property_value,
                                                size_t property_length,
                                                status_t status) {
  (void)handle;

  if (status == STATUS_TIMEOUT) {
    log_warn("Secondary counters query timed out");
    return;
  } else if (status == STATUS_ABORT) {
    log_warn("Secondary counters query aborted");
    return;
  }
  if (status != STATUS_OK && status != STATUS_IN_PROGRESS)
    log_crash("Exit");
  if (property_id == PROP_LAST_STATUS)
    log_error("Secondary does not handle the DEBUG_COUNTERS property, please "
              "update secondary or disable print-stats");
  CHECK_ERROR(property_id != PROP_EZMESHD_DEBUG_COUNTERS);
  CHECK_ERROR(property_value == NULL || property_length > sizeof(dbg_cts_t));

  memcpy(&secondary_cpcd_debug_counters, property_value, property_length);
}

static void
core_fetch_secondary_debug_counters(hal_epoll_event_data_t *event_data) {
  int fd_timer = 0;
  uint64_t expiration = 0;

  fd_timer = event_data->file_descriptor;
  CHECK_ERROR(read(fd_timer, &expiration, sizeof(expiration)) < 0);
  sys_param_get(cpcd_update_secondary_debug_counter,
                PROP_EZMESHD_DEBUG_COUNTERS, 0, 0, false);
}

static void core_proc_rx_hal_notification(hal_epoll_event_data_t *event_data) {
  uint8_t frame_type = 0;
  list_node_t *node = NULL;
  transmit_queue_item_t *item = NULL;
  buffer_handle_t *frame = NULL;
  struct timespec tx_complete_timestamp = {0};
  ssize_t ret = 0;

  (void)event_data;

  ret = recv(hal_sock_notify_fd, &tx_complete_timestamp,
             sizeof(tx_complete_timestamp), MSG_DONTWAIT);

  if (ret == 0) {
    int ret_close = 0;

    log_info("Driver closed the notification socket");
    ret_close = close(event_data->file_descriptor);
    CHECK_ERROR(ret_close != 0);
    return;
  }
  CHECK_ERROR(ret < 0);

  node = list_pop(&pending_on_tx_complete);
  item = SLIST_ENTRY(node, transmit_queue_item_t, node);
  CHECK_ERROR(item == NULL);

  frame = item->handle;
  frame->pending_tx_complete = false;

  frame_type = frame->control >> HDLC_CONTROL_FRAME_TYPE_POS;
  if (frame_type == 1 || frame_type == 0) {
    frame_type = HDLC_FRAME_TYPE_IFRAME;
  }

  switch (frame_type) {
  case HDLC_FRAME_TYPE_IFRAME:
    if (frame->endpoint->state != ENDPOINT_STATE_OPEN)
      core_clear_tx_queue(&core_endpoints[frame->endpoint->id].retry_queue, -1);
    else {
      if (frame->endpoint->packet_retry_count == 0u)
        frame->endpoint->last_iframe_sent_timestamp = tx_complete_timestamp;
      if (frame->endpoint->retry_queue != NULL && frame->acked == false)
        start_retry_timer(frame->endpoint, tx_complete_timestamp);
      if (frame->acked)
        proc_ack(frame->endpoint, frame->pending_ack);
    }
    break;

  case HDLC_FRAME_TYPE_UFRAME:
  case HDLC_FRAME_TYPE_SFRAME:
    if (frame->data_length != 0)
      HAL_MEM_FREE(&frame->data);
    HAL_MEM_FREE(&frame->hdlc_header);
    HAL_MEM_FREE(&frame);
    break;

  default:
    log_crash("Exit");
    break;
  }
  HAL_MEM_FREE(&item);
}

static void core_proc_rx_hal(hal_epoll_event_data_t *event_data) {
  frame_t *rx_frame = NULL;
  size_t frame_size = 0;
  uint16_t hcs = 0;
  uint16_t data_length = 0;
  uint8_t address = 0;
  uint8_t control = 0;
  uint8_t type = 0;
  uint8_t ack = 0;
  endpoint_t *endpoint = NULL;

  (void)event_data;

  if (core_pull_frame_from_hal(&rx_frame, &frame_size) == false)
    return;

  hcs = __hdlc_get_hcs(rx_frame->header);

  if (!core_check_crc_sw(rx_frame->header, HDLC_HEADER_SIZE, hcs)) {
    // log_info_INVALID_HEADER_CHECKSUM();
    HAL_MEM_FREE(&rx_frame);
    return;
  }

  data_length = (uint16_t)(rx_frame->header[HDLC_LENGTH_POS] |
                           (rx_frame->header[HDLC_LENGTH_POS + 1] << 8));
  address = rx_frame->header[HDLC_ADDRESS_POS];
  control = rx_frame->header[HDLC_CONTROL_POS];
  type = control >> HDLC_CONTROL_FRAME_TYPE_POS;
  if (type == 1 || type == 0) {
    type = HDLC_FRAME_TYPE_IFRAME;
  }
#if (EZMESH_HDLC_SEQ_8 == 1)
  ack = control & 0x07;
#else
  ack = control & 0x03;
#endif
  CHECK_ERROR(data_length != frame_size - HDLC_HEADER_RAW_SIZE);

  endpoint = find_endpoint(address);

  if (endpoint->state != ENDPOINT_STATE_OPEN) {
    if (type != HDLC_FRAME_TYPE_SFRAME)
      transmit_reject(NULL, address, 0, HDLC_REJECT_UNREACHABLE_ENDPOINT);
    HAL_MEM_FREE(&rx_frame);
    return;
  }

  if (type == HDLC_FRAME_TYPE_IFRAME || type == HDLC_FRAME_TYPE_SFRAME)
    proc_ack(endpoint, ack);

  switch (type) {
  case HDLC_FRAME_TYPE_IFRAME: {
    core_proc_rx_iframe(rx_frame);
    break;
  }
  case HDLC_FRAME_TYPE_SFRAME: {
    core_proc_rx_sframe(rx_frame);
    break;
  }
  case HDLC_FRAME_TYPE_UFRAME: {
    core_proc_rx_uframe(rx_frame);
    break;
  }
  default: {
    transmit_reject(endpoint, address, endpoint->ack, HDLC_REJECT_ERROR);
    log_debug("[Core] EP #%u: rxd S-frame dropped", endpoint->id);
    break;
  }
  }

  HAL_MEM_FREE(&rx_frame);
}

bool core_endpoint_is_closing(uint8_t ep_id) {
  return (core_endpoints[ep_id].state == ENDPOINT_STATE_CLOSING);
}

void core_process_endpoint_change(uint8_t endpoint_number,
                                  ep_state_t ep_state) {
  if (ep_state != ENDPOINT_STATE_OPEN) {
    core_close_endpoint(endpoint_number, true, false);
    return;
  }
  if (core_endpoints[endpoint_number].state != ENDPOINT_STATE_OPEN)
    core_open_endpoint(endpoint_number, 0, 4);
  return;
}

bool core_ep_is_busy(uint8_t ep_id) {
  return (core_endpoints[ep_id].holding_list != NULL);
}

static void core_proc_rx_iframe(frame_t *rx_frame) {
  endpoint_t *endpoint = NULL;
  uint8_t address = 0;
  uint16_t payload_length = 0;
  uint16_t fcs = 0;
  uint8_t control = 0;
  uint8_t seq = 0;

  address = rx_frame->header[HDLC_ADDRESS_POS];
  endpoint = &core_endpoints[address];

  log_debug("[Core] EP #%u: rxd I-frame", endpoint->id);

  if (endpoint->id != 0 &&
      (endpoint->state != ENDPOINT_STATE_OPEN || EP_list_empty(endpoint->id))) {
    transmit_reject(endpoint, address, 0, HDLC_REJECT_UNREACHABLE_ENDPOINT);
    return;
  }

  payload_length = (uint16_t)(rx_frame->header[HDLC_LENGTH_POS] |
                              (rx_frame->header[HDLC_LENGTH_POS + 1] << 8));
  CHECK_ERROR(payload_length < HDLC_FCS_SIZE);
  payload_length = (uint16_t)(payload_length - HDLC_FCS_SIZE);
  fcs = (uint16_t)(rx_frame->payload[payload_length] |
                   (rx_frame->payload[payload_length + 1] << 8));

  if (!core_check_crc_sw(rx_frame->payload, payload_length, fcs)) {
    // log_warn("payload_length: %d, fcs: %04X", payload_length, fcs);
    transmit_reject(endpoint, address, endpoint->ack,
                    HDLC_REJECT_CHECKSUM_MISMATCH);
    // log_debug_INVALID_PAYLOAD_CHECKSUM();
    return;
  }

  control = rx_frame->header[HDLC_CONTROL_POS];
#if (EZMESH_HDLC_SEQ_8 == 1)
  seq = (control >> HDLC_CONTROL_SEQ_POS) & 0x07;
#else
  seq = (control >> HDLC_CONTROL_SEQ_POS) & 0x03;
#endif

  log_debug("seq %d, ack %d", seq, endpoint->ack);

  if (seq == endpoint->ack) {
    if (control & (1 << HDLC_CONTROL_P_F_POS)) {
      CHECK_ERROR(endpoint->id != 0);
      CHECK_ERROR(endpoint->poll_final.on_final == NULL);
      endpoint->poll_final.on_final(endpoint->id,
                                    (void *)HDLC_FRAME_TYPE_IFRAME,
                                    rx_frame->payload, payload_length);
    } else {
      if (endpoint->id == EP_SYSTEM) {
        if (endpoint->on_iframe_data_reception != NULL)
          endpoint->on_iframe_data_reception(endpoint->id, rx_frame->payload,
                                             payload_length);
      } else {
        status_t status = core_push_data_to_server(
            endpoint->id, rx_frame->payload, payload_length);
        if (status == STATUS_FAIL) {
          core_close_endpoint(endpoint->id, true, false);
          return;
        } else if (status == STATUS_WOULD_BLOCK) {
          transmit_reject(endpoint, address, endpoint->ack,
                          HDLC_REJECT_OUT_OF_MEMORY);
          return;
        }
      }
    }

    log_debug("[Core] EP #%u: rxd I-frame queued", endpoint->id);
    endpoint->ack++;
#if (EZMESH_HDLC_SEQ_8 == 1)
    endpoint->ack %= 8;
#else
    endpoint->ack %= 4;
#endif
    send_ack(endpoint);
  } else if (is_seq_valid(seq, endpoint->ack)) {
    log_debug("EP #%u: rxd duplicate I-frame", endpoint->id);
    send_ack(endpoint);
  } else {
    transmit_reject(endpoint, address, endpoint->ack,
                    HDLC_REJECT_SEQUENCE_MISMATCH);
    return;
  }
}

static void core_proc_rx_sframe(frame_t *rx_frame) {
  endpoint_t *endpoint = NULL;
  bool fatal_error = false;
  ep_state_t new_state = 0;
  uint8_t sframe_function = 0;
  uint8_t address = 0;
  uint8_t control = 0;
  uint16_t data_length = 0;
  reject_reason_t reason = 0;

  address = rx_frame->header[HDLC_ADDRESS_POS];
  endpoint = find_endpoint(address);
  new_state = endpoint->state;
  control = rx_frame->header[HDLC_CONTROL_POS];
  sframe_function = (control >> HDLC_CONTROL_SFRAME_FUNCTION_ID_POS) & 0x03;
  data_length = (uint16_t)(rx_frame->header[HDLC_LENGTH_POS] |
                           (rx_frame->header[HDLC_LENGTH_POS + 1] << 8));
  data_length = (uint16_t)((data_length > 2) ? (data_length - 2) : 0);
  log_debug("[Core] EP #%u: rxd S-frame", endpoint->id);

  switch (sframe_function) {
  case HDLC_ACK_SFRAME_FUNCTION: {
    log_debug("[Core] EP #%u: rxd S-frame processed", endpoint->id);
    break;
  }

  case HDLC_REJECT_SFRAME_FUNCTION: {
    log_debug("[Core] EP #%u: rxd S-frame rejected", endpoint->id);
    CHECK_ERROR(data_length != HDLC_REJECT_PAYLOAD_SIZE);

    reason = *((reject_reason_t *)rx_frame->payload);
    switch (reason) {
    case HDLC_REJECT_SEQUENCE_MISMATCH:
      // This is not a fatal error when the tx window is > 1
      fatal_error = true;
      new_state = ENDPOINT_STATE_ERROR_FAULT;
      log_debug("[Core] EP #%u: rxd reject seq mismatch", endpoint->id);
      log_warn("Sequence mismatch on endpoint #%d", endpoint->id);
      break;

    case HDLC_REJECT_CHECKSUM_MISMATCH:
      if (endpoint->retry_queue != NULL)
        retry_frame(endpoint);
      log_debug("[Core] EP #%u: rxd reject checksum mismatch", endpoint->id);
      log_warn("Remote received a packet with an invalid checksum");
      break;

    case HDLC_REJECT_OUT_OF_MEMORY:
      log_debug("[Core] EP #%u: rxd reject out of memory", endpoint->id);
      break;

    case HDLC_REJECT_UNREACHABLE_ENDPOINT:
      fatal_error = true;
      new_state = ENDPOINT_STATE_ERROR_DEST_UNREACH;
      log_debug("[Core] EP #%u: rxd reject destination unreachable",
                endpoint->id);
      log_warn("Unreachable endpoint #%d", endpoint->id);
      break;

    case HDLC_REJECT_ERROR:
    default:
      fatal_error = true;
      new_state = ENDPOINT_STATE_ERROR_FAULT;
      log_debug("[Core] EP #%u: rxd reject fault", endpoint->id);
      log_warn("Endpoint #%d fault", endpoint->id);
      break;
    }
    break;
  }

  default: {
    log_crash("Illegal switch");
    break;
  }
  }

  if (fatal_error) {
    log_warn("Fatal error %d, endoint #%d is in error.", reason, endpoint->id);
    core_set_endpoint_in_error(endpoint->id, new_state);
  }
}

static void core_proc_rx_uframe(frame_t *rx_frame) {
  uint16_t payload_length = 0;
  uint8_t type = 0;
  endpoint_t *endpoint = NULL;
  uint8_t address = 0;
  uint8_t control = 0;
  uint16_t fcs = 0;

  address = rx_frame->header[HDLC_ADDRESS_POS];
  endpoint = find_endpoint(address);
  log_debug("EP #%u: rxd U-frame", endpoint->id);

  control = rx_frame->header[HDLC_CONTROL_POS];
  type =
      (control >> HDLC_CONTROL_UFRAME_TYPE_POS) & HDLC_CONTROL_UFRAME_TYPE_MASK;

  payload_length = (uint16_t)(rx_frame->header[HDLC_LENGTH_POS] |
                              (rx_frame->header[HDLC_LENGTH_POS + 1] << 8));
  payload_length =
      (uint16_t)((payload_length < 2) ? 0 : (payload_length - HDLC_FCS_SIZE));

  if (payload_length > 0) {
    fcs = (uint16_t)(rx_frame->payload[payload_length] |
                     (rx_frame->payload[payload_length + 1] << 8));

    if (!core_check_crc_sw(rx_frame->payload, payload_length, fcs)) {
      // log_debug_INVALID_PAYLOAD_CHECKSUM();
      log_debug("[Core] EP #%d: U-frame dropped : Bad payload checksum",
                ((endpoint == NULL) ? -1 : (signed)endpoint->id));
      return;
    }
  }
  if (!(endpoint->flags & OPEN_EP_FLAG_UFRAME_ENABLE)) {
    log_debug("[Core] EP #%d: U-frame dropped : U-Frame not enabled on endoint",
              ((endpoint == NULL) ? -1 : (signed)endpoint->id));
    return;
  }

  if ((type == HDLC_CONTROL_UFRAME_TYPE_INFORMATION) &&
      (endpoint->flags & OPEN_EP_FLAG_UFRAME_INFORMATION_DISABLE)) {
    log_debug(
        "[Core] EP #%d: U-frame dropped : Information U-Frame not enabled "
        "on endpoint",
        ((endpoint == NULL) ? -1 : (signed)endpoint->id));
    return;
  }

  switch (type) {
  case HDLC_CONTROL_UFRAME_TYPE_INFORMATION: {
    if (endpoint->on_uframe_data_reception != NULL)
      endpoint->on_uframe_data_reception(endpoint->id, rx_frame->payload,
                                         payload_length);
    break;
  }

  case HDLC_CONTROL_UFRAME_TYPE_POLL_FINAL:
    if (endpoint->id != EP_SYSTEM)
      log_error("Received an unnumbered final frame but it was not addressed "
                "to the system enpoint");
    else if (endpoint->poll_final.on_final != NULL)
      endpoint->poll_final.on_final(endpoint->id,
                                    (void *)HDLC_FRAME_TYPE_UFRAME,
                                    rx_frame->payload, payload_length);
    else
      log_crash("Exit");
    break;

  case HDLC_CONTROL_UFRAME_TYPE_ACKNOWLEDGE:
    CHECK_ERROR(endpoint->id != EP_SYSTEM);
    sys_ep_no_found_ack();
    break;

  default:
    log_debug(
        "[Core] EP #%d: U-frame dropped : U-Frame not enabled on endpoint",
        ((endpoint == NULL) ? -1 : (signed)endpoint->id));
    return;
  }

  log_debug("[Core] EP #%u: U-frame processed", endpoint->id);
}

void core_write(uint8_t endpoint_number, const void *message,
                size_t message_len, uint8_t flags) {
  endpoint_t *endpoint = NULL;
  buffer_handle_t *buffer_handle = NULL;
  transmit_queue_item_t *transmit_queue_item = NULL;
  bool iframe = true;
  bool poll = (flags & FLAG_INFORMATION_POLL) ? true : false;
  uint8_t type = HDLC_CONTROL_UFRAME_TYPE_UNKNOWN;
  void *payload = NULL;
  uint16_t fcs = 0;

  CHECK_ERROR(message_len > UINT16_MAX);

  endpoint = find_endpoint(endpoint_number);

  if (endpoint->state != ENDPOINT_STATE_OPEN) {
    log_warn("Tried to write on closed endpoint #%d", endpoint_number);
    return;
  }

  if ((flags & FLAG_UFRAME_INFORMATION) ||
      (flags & FLAG_UFRAME_RESET_COMMAND) || (flags & FLAG_UFRAME_POLL)) {
    CHECK_ERROR(!(endpoint->flags & OPEN_EP_FLAG_UFRAME_ENABLE));
    iframe = false;
    if (flags & FLAG_UFRAME_INFORMATION)
      type = HDLC_CONTROL_UFRAME_TYPE_INFORMATION;
    else if (flags & FLAG_UFRAME_RESET_COMMAND)
      type = HDLC_CONTROL_UFRAME_TYPE_RESET_SEQ;
    else if ((flags & FLAG_UFRAME_POLL))
      type = HDLC_CONTROL_UFRAME_TYPE_POLL_FINAL;
  } else
    CHECK_ERROR(endpoint->flags & OPEN_EP_FLAG_IFRAME_DISABLE);

  do {
    buffer_handle = (buffer_handle_t *)HAL_MEM_ALLOC(sizeof(buffer_handle_t));
    CHECK_ERROR(buffer_handle == NULL);

    payload = HAL_MEM_ALLOC(message_len);
    CHECK_ERROR(payload == NULL);
    memcpy(payload, message, message_len);

    buffer_handle->data = payload;
    buffer_handle->data_length = (uint16_t)message_len;
    buffer_handle->endpoint = endpoint;
    buffer_handle->address = endpoint_number;

    if (iframe) {
      uint8_t control = 0;

      control = HDLC_FRAME_TYPE_IFRAME << HDLC_CONTROL_FRAME_TYPE_POS;
      control |= (uint8_t)(endpoint->seq << HDLC_CONTROL_SEQ_POS);
      control |= endpoint->ack;
      control |= (uint8_t)((uint8_t)poll << HDLC_CONTROL_P_F_POS);
      buffer_handle->control = control;
      endpoint->seq++;
#if (EZMESH_HDLC_SEQ_8 == 1)
      endpoint->seq %= 8;
#else
      endpoint->seq %= 4;
#endif
      log_debug("Sequence # is now %d on ep %d", endpoint->seq, endpoint->id);
    } else {
      CHECK_ERROR(type == HDLC_CONTROL_UFRAME_TYPE_UNKNOWN);

      uint8_t control = 0;

      control = HDLC_FRAME_TYPE_UFRAME << HDLC_CONTROL_FRAME_TYPE_POS;
      control |= type << HDLC_CONTROL_UFRAME_TYPE_POS;

      buffer_handle->control = control;
    }

    fcs = core_get_crc_sw(message, (uint16_t)message_len);

    buffer_handle->fcs[0] = (uint8_t)fcs;
    buffer_handle->fcs[1] = (uint8_t)(fcs >> 8);
  } while (0);

  transmit_queue_item =
      (transmit_queue_item_t *)HAL_MEM_ALLOC(sizeof(transmit_queue_item_t));
  CHECK_ERROR(transmit_queue_item == NULL);

  transmit_queue_item->handle = buffer_handle;

  if (iframe == false) {
    list_push(&transmit_queue, &transmit_queue_item->node);
    core_process_transmit_queue();
  } else if (endpoint->current_tx_window_space <= 0)
    list_push_back(&endpoint->holding_list, &transmit_queue_item->node);
  else {
    endpoint->current_tx_window_space--;
    list_push(&transmit_queue, &transmit_queue_item->node);
    core_process_transmit_queue();
  }
}

void core_open_endpoint(uint8_t endpoint_number, uint8_t flags,
                        uint8_t tx_win_size) {
  endpoint_t *ep = NULL;
  ep_state_t previous_state = 0;
  int timer_fd = 0;
  hal_epoll_event_data_t *event = NULL;

  CHECK_ERROR(tx_win_size < TRANSMIT_WINDOW_MIN_SIZE);
  CHECK_ERROR(tx_win_size > TRANSMIT_WINDOW_MAX_SIZE);

  ep = &core_endpoints[endpoint_number];

  if (ep->state != ENDPOINT_STATE_CLOSED) {
    log_crash("Endpoint already opened");
    return;
  }

  previous_state = ep->state;
  memset(ep, 0x00, sizeof(endpoint_t));
  ep->state = previous_state;
  core_set_endpoint_state(endpoint_number, ENDPOINT_STATE_OPEN);

  ep->id = endpoint_number;
  ep->flags = flags;
  ep->configured_tx_win_size = tx_win_size;
  ep->current_tx_window_space = ep->configured_tx_win_size;
  ep->retry_timeout_ms = MIN_RE_TRANSMIT_TIMEOUT_MS;

  timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  CHECK_ERROR(timer_fd < 0);

  event =
      (hal_epoll_event_data_t *)HAL_MEM_ALLOC(sizeof(hal_epoll_event_data_t));
  CHECK_ERROR(event == NULL);
  ep->retry_timer_data = event;
  event->callback = core_proc_endpoint_timeout;
  event->file_descriptor = timer_fd;
  event->endpoint_number = endpoint_number;
  hal_epoll_register(event);

  list_init(&ep->retry_queue);
  list_init(&ep->holding_list);

  // log_debug_OPEN_ENDPOINT(ep->id);
  return;
}

void core_set_endpoint_in_error(uint8_t endpoint_number, ep_state_t new_state) {
  if (endpoint_number == 0) {
    log_warn("System endpoint in error, new state: %s. Restarting it.",
             core_stringify_state(new_state));
    sys_sequence_reset();
  } else {
    log_warn("Setting ep#%d in error, new state: %s", endpoint_number,
             core_stringify_state(new_state));
    EP_close(endpoint_number, true);
    core_close_endpoint(endpoint_number, false, false);
    core_set_endpoint_state(endpoint_number, new_state);
  }
}

void core_reset_endpoint_sequence(uint8_t endpoint_number) {
  core_endpoints[endpoint_number].seq = 0;
  core_endpoints[endpoint_number].ack = 0;
}

static void core_clear_tx_queue(list_node_t **head, int endpoint_id) {
  list_node_t *current_node = NULL;
  list_node_t *next_node = NULL;
  bool filter_with_endpoint_id = false;
  uint8_t ep_id = 0;

  if (!*head)
    return;

  if (endpoint_id < 0)
    filter_with_endpoint_id = false;
  else {
    filter_with_endpoint_id = true;
    ep_id = (uint8_t)endpoint_id;
  }

  current_node = *head;

  while (current_node) {
    next_node = current_node->node;

    transmit_queue_item_t *item =
        SLIST_ENTRY(current_node, transmit_queue_item_t, node);
    if (!filter_with_endpoint_id ||
        (filter_with_endpoint_id && item->handle->address == ep_id)) {
      if (item->handle->pending_tx_complete == false) {
        HAL_MEM_FREE(&item->handle->hdlc_header);
        if (item->handle->data_length != 0)
          HAL_MEM_FREE(&item->handle->data);
        HAL_MEM_FREE(&item->handle);
        list_remove(head, &item->node);
        HAL_MEM_FREE(&item);
      }
    }

    current_node = next_node;
  }
}

status_t core_close_endpoint(uint8_t endpoint_number, bool notify_secondary,
                             bool force_close) {
  endpoint_t *ep = NULL;
  ep = find_endpoint(endpoint_number);
  CHECK_ERROR(ep->state == ENDPOINT_STATE_CLOSED);
  log_debug("Closing endpoint #%d", endpoint_number);
  stop_retry_timer(ep);

  core_clear_tx_queue(&ep->retry_queue, -1);
  core_clear_tx_queue(&ep->holding_list, -1);
  core_clear_tx_queue(&transmit_queue, endpoint_number);
  core_clear_tx_queue(&pending_on_security_ready_queue, endpoint_number);

  if (notify_secondary) {
    core_set_endpoint_state(ep->id, ENDPOINT_STATE_CLOSING);
    sys_param_set(disconnect_notification_callback, 5,
                  /* 5 retries */ 100000, /* 100ms between retries*/
                  EP_ID_TO_PROPERTY_STATE(ep->id), &ep->state,
                  sizeof(ep_state_t), false);
  }

  if (ep->retry_timer_data != NULL) {
    hal_epoll_unregister(ep->retry_timer_data);
    close(((hal_epoll_event_data_t *)ep->retry_timer_data)->file_descriptor);
    HAL_MEM_FREE(&ep->retry_timer_data);
    ep->retry_timer_data = NULL;
  }

  if (force_close) {
    core_set_endpoint_state(ep->id, ENDPOINT_STATE_CLOSED);
    // log_trace_CLOSE_ENDPOINT(ep->id);
  }

  return STATUS_OK;
}

void core_set_endpoint_option(uint8_t endpoint_number, endpoint_option_t option,
                              void *value) {
  endpoint_t *ep = NULL;

  ep = &core_endpoints[endpoint_number];
  CHECK_ERROR(ep->state != ENDPOINT_STATE_OPEN);

  switch (option) {
  case EP_ON_IFRAME_RECEIVE: {
    ep->on_iframe_data_reception = (on_data_reception_t)value;
    break;
  }

  case EP_ON_UFRAME_RECEIVE: {
    ep->on_uframe_data_reception = (on_data_reception_t)value;
    break;
  }

  case EP_ON_FINAL: {
    ep->poll_final.on_final = value;
    break;
  }

  case EP_ON_POLL_ARG:
  case EP_ON_FINAL_ARG: {
    ep->poll_final.on_fnct_arg = value;
    break;
  }

  case EP_ON_POLL:
  case EP_ON_IFRAME_RECEIVE_ARG:
  case EP_ON_UFRAME_RECEIVE_ARG:
  case EP_ON_IFRAME_WRITE_COMPLETED:
  case EP_ON_IFRAME_WRITE_COMPLETED_ARG:
  case EP_ON_UFRAME_WRITE_COMPLETED:
  case EP_ON_UFRAME_WRITE_COMPLETED_ARG:
  default: {
    log_crash("invalid option");
    break;
  }
  }
}

static void proc_ack(endpoint_t *endpoint, uint8_t ack) {
  transmit_queue_item_t *item = NULL;
  list_node_t *item_node = NULL;
  buffer_handle_t *frame = NULL;
  uint8_t control = 0;
  uint8_t seq_number = 0;
  uint8_t ack_range_min = 0;
  uint8_t ack_range_max = 0;
  uint8_t frames_count_ack = 0;

  if (endpoint->retry_queue == NULL)
    return;
  item = SLIST_ENTRY(endpoint->retry_queue, transmit_queue_item_t, node);
  frame = item->handle;

  control = ((uint8_t *)frame->hdlc_header)[HDLC_CONTROL_POS];
#if (EZMESH_HDLC_SEQ_8 == 1)
  seq_number = (control >> HDLC_CONTROL_SEQ_POS) & 0x07;
#else
  seq_number = (control >> HDLC_CONTROL_SEQ_POS) & 0x03;
#endif

  ack_range_min = (uint8_t)(seq_number + 1);
#if (EZMESH_HDLC_SEQ_8 == 1)
  ack_range_min %= 8;
  s
#else
  ack_range_min %= 4;
#endif
      ack_range_max =
          (uint8_t)(seq_number + endpoint->frames_count_retry_queue);
#if (EZMESH_HDLC_SEQ_8 == 1)
  ack_range_max %= 8;
#else
  ack_range_max %= 4;
#endif
  if (ack_range_max >= ack_range_min) {
    if (ack < ack_range_min || ack > ack_range_max)
      return;
  } else if (ack > ack_range_max && ack < ack_range_min)
    return;

  if (ack > seq_number)
    frames_count_ack = (uint8_t)(ack - seq_number);
  else {
#if (EZMESH_HDLC_SEQ_8 == 1)
    frames_count_ack = (uint8_t)(8 - seq_number);
#else
    frames_count_ack = (uint8_t)(4 - seq_number);
#endif
    frames_count_ack = (uint8_t)(frames_count_ack + ack);
  }
  stop_retry_timer(endpoint);

  if (frame->pending_tx_complete == true) {
    frame->acked = true;
    frame->pending_ack = ack;
    return;
  }

  endpoint->packet_retry_count = 0u;

  log_debug("%d Received ack %d seq number %d", endpoint->id, ack, seq_number);
  core_calculate_retry_timeout(endpoint);

  for (uint8_t i = 0; i < frames_count_ack; i++) {
    item_node = list_pop(&endpoint->retry_queue);
    CHECK_ERROR(item_node == NULL);

    item = SLIST_ENTRY(item_node, transmit_queue_item_t, node);
    frame = item->handle;
    control = ((uint8_t *)frame->hdlc_header)[HDLC_CONTROL_POS];

    uint8_t type = 0;

    type = frame->control >> HDLC_CONTROL_FRAME_TYPE_POS;
    if (type == 1 || type == 0) {
      type = HDLC_FRAME_TYPE_IFRAME;
    }
    CHECK_ERROR(type != HDLC_FRAME_TYPE_IFRAME);

#ifdef USE_ON_WRITE_COMPLETE
    on_write_completed(endpoint->id, STATUS_OK);
#endif

    if (endpoint->id == EP_SYSTEM && __hdlc_is_poll_final(control))
      sys_poll_ack(frame->data);
    HAL_MEM_FREE(&frame->data);
    HAL_MEM_FREE(&frame->hdlc_header);
    HAL_MEM_FREE(&frame);
    HAL_MEM_FREE(&item);

    endpoint->frames_count_retry_queue--;
    endpoint->current_tx_window_space++;

    if (endpoint->retry_queue == NULL)
      break;
  }
#if 1
  while (endpoint->holding_list != NULL &&
         endpoint->current_tx_window_space > 0) {
    list_node_t *item = list_pop(&endpoint->holding_list);
    list_push_back(&transmit_queue, item);
    endpoint->current_tx_window_space--;
    //hal_epoll_watch_back(endpoint->id);
    log_info("Endpoint #%d: watching back", endpoint->id);
  }
#endif
  log_debug("[Core] EP #%u: rxd ack %u", endpoint->id, ack);
}

static void send_ack(endpoint_t *endpoint) {
  buffer_handle_t *handle = NULL;
  transmit_queue_item_t *item = NULL;

  handle = (buffer_handle_t *)HAL_MEM_ALLOC(sizeof(buffer_handle_t));
  CHECK_ERROR(handle == NULL);

  handle->endpoint = endpoint;
  handle->address = endpoint->id;
  uint8_t control = 0;

  control = HDLC_FRAME_TYPE_SFRAME << HDLC_CONTROL_FRAME_TYPE_POS;
  control |= (uint8_t)(0 << HDLC_CONTROL_SFRAME_FUNCTION_ID_POS);
  control |= endpoint->ack;
  handle->control = control;

  item = (transmit_queue_item_t *)HAL_MEM_ALLOC(sizeof(transmit_queue_item_t));
  CHECK_ERROR(item == NULL);

  item->handle = handle;

  list_push(&transmit_queue, &item->node);
  log_debug("Endpoint #%d sent ACK: %d", endpoint->id, endpoint->ack);
  core_process_transmit_queue();
  log_debug("[Core] EP #%u: txd ack", endpoint->id);
}

static void retry_frame(endpoint_t *endpoint) {
  transmit_queue_item_t *item = NULL;
  list_node_t *item_node = NULL;

  item_node = list_pop(&endpoint->retry_queue);

  CHECK_ERROR(item_node == NULL);

  item = SLIST_ENTRY(item_node, transmit_queue_item_t, node);

  if (item->handle->pending_tx_complete == true) {
    list_push(&endpoint->retry_queue, &item->node);
    return;
  }

  // CHECK_ERROR(__hdlc_get_frame_type(item->handle->control) !=
  // HDLC_FRAME_TYPE_IFRAME);
  uint8_t type = 0;

  type = item->handle->control >> HDLC_CONTROL_FRAME_TYPE_POS;
  if (type == 1 || type == 0) {
    type = HDLC_FRAME_TYPE_IFRAME;
  }
  CHECK_ERROR(type != HDLC_FRAME_TYPE_IFRAME);

  HAL_MEM_FREE(&item->handle->hdlc_header);

  endpoint->packet_retry_count++;
  endpoint->frames_count_retry_queue--;

  list_push(&transmit_queue, &item->node);

  primary_cpcd_debug_counters.retxd_data_frame++;
  log_debug("[Core] EP #%u: re-txd data frame", endpoint->id);
  return;
}

static void transmit_reject(endpoint_t *endpoint, uint8_t address, uint8_t ack,
                            reject_reason_t reason) {
  uint16_t fcs = 0;
  buffer_handle_t *handle = NULL;
  transmit_queue_item_t *item = NULL;

  handle = (buffer_handle_t *)HAL_MEM_ALLOC(sizeof(buffer_handle_t));
  CHECK_ERROR(handle == NULL);

  handle->address = address;
  uint8_t control = 0;

  control = HDLC_FRAME_TYPE_SFRAME << HDLC_CONTROL_FRAME_TYPE_POS;
  control |= (uint8_t)(HDLC_REJECT_SFRAME_FUNCTION
                       << HDLC_CONTROL_SFRAME_FUNCTION_ID_POS);
  control |= ack;
  handle->control = control;

  handle->data = HAL_MEM_ALLOC(sizeof(uint8_t));
  CHECK_ERROR(handle->data == NULL);

  *((uint8_t *)handle->data) = (uint8_t)reason;
  handle->data_length = sizeof(uint8_t);

  fcs = core_get_crc_sw(handle->data, 1);
  handle->fcs[0] = (uint8_t)(fcs && 0xFF);
  handle->fcs[1] = (uint8_t)(fcs >> 8);

  item = (transmit_queue_item_t *)HAL_MEM_ALLOC(sizeof(transmit_queue_item_t));
  CHECK_ERROR(item == NULL);

  item->handle = handle;

  list_push_back(&transmit_queue, &item->node);

  if (endpoint != NULL) {
    switch (reason) {
    case HDLC_REJECT_CHECKSUM_MISMATCH: {
      log_error("[Core] EP #%u: txd reject checksum mismatch", endpoint->id);
      log_warn("Host received a packet with an invalid checksum on ep %d",
               endpoint->id);
      break;
    }

    case HDLC_REJECT_SEQUENCE_MISMATCH: {
      log_error("[Core] EP #%u: txd reject seq mismatch", endpoint->id);
      break;
    }

    case HDLC_REJECT_OUT_OF_MEMORY: {
      log_error("[Core] EP #%u: txd reject out of memory", endpoint->id);
      break;
    }

    case HDLC_REJECT_SECURITY_ISSUE: {
      log_error("[Core] EP #%u: txd reject security issue", endpoint->id);
      break;
    }

    case HDLC_REJECT_UNREACHABLE_ENDPOINT: {
      log_error("[Core] EP #%d: txd reject destination unreachable",
                (endpoint == NULL) ? -1 : (signed)endpoint->id);
      break;
    }

    case HDLC_REJECT_ERROR:
    default: {
      log_error("[Core] EP #%u: txd reject fault", endpoint->id);
      break;
    }
    }
  } else {
    switch (reason) {
    case HDLC_REJECT_UNREACHABLE_ENDPOINT: {
      // log_debug_TXD_REJECT_DESTINATION_UNREACHABLE();
      break;
    }

    default: {
      log_error("Exit");
      break;
    }
    }
  }
}

static bool core_proc_tx_data(void) {
  list_node_t *node = NULL;
  transmit_queue_item_t *item = NULL;
  transmit_queue_item_t *tx_complete_item = NULL;
  buffer_handle_t *frame = NULL;
  uint16_t total_length = 0;
  uint8_t frame_type = 0;

  uint16_t encrypted_data_length = 0;
  uint8_t *encrypted_payload = 0;
  size_t frame_length = 0;
  frame_t *frame_buffer = NULL;

  if (pending_on_security_ready_queue != NULL) {
    log_debug(
        "Sending packet that were hold back because security was not ready");
    node = list_pop(&pending_on_security_ready_queue);
  } else {
    if (transmit_queue == NULL) {
      log_debug("transmit_queue is empty and cpcd is not ready yet to process "
                "hold back packets");
      return false;
    }

    node = list_pop(&transmit_queue);
  }

  item = SLIST_ENTRY(node, transmit_queue_item_t, node);
  frame = item->handle;

  frame->hdlc_header = HAL_MEM_ALLOC(HDLC_HEADER_RAW_SIZE);
  CHECK_ERROR(frame->hdlc_header == NULL);

  total_length =
      (frame->data_length != 0) ? (uint16_t)(frame->data_length + 2) : 0;
  frame_type = frame->control >> HDLC_CONTROL_FRAME_TYPE_POS;
  if (frame_type == 1 || frame_type == 0) {
    frame_type = HDLC_FRAME_TYPE_IFRAME;
  }

  if (frame_type == HDLC_FRAME_TYPE_IFRAME)
    __hdlc_set_ctrl_ack(&frame->control, frame->endpoint->ack);
  else if (frame_type == HDLC_FRAME_TYPE_UFRAME)
    CHECK_ERROR(frame->endpoint->id != EP_SYSTEM);

  // log_debug("[Core] frame address: %02x", frame->address);
  hdlc_create_header(frame->hdlc_header, frame->address, total_length,
                     frame->control);

  encrypted_data_length = frame->data_length;
  encrypted_payload = (uint8_t *)frame->data;
  frame_length = HDLC_HEADER_RAW_SIZE + total_length;
  frame_buffer = (frame_t *)HAL_MEM_ALLOC(frame_length);
  CHECK_ERROR(frame_buffer == NULL);

  memcpy(frame_buffer->header, frame->hdlc_header, HDLC_HEADER_RAW_SIZE);
  memcpy(frame_buffer->payload, encrypted_payload, encrypted_data_length);

  if (encrypted_data_length != 0)
    memcpy(&frame_buffer->payload[encrypted_data_length], frame->fcs,
           sizeof(frame->fcs));
  frame->pending_tx_complete = true;
  tx_complete_item =
      (transmit_queue_item_t *)HAL_MEM_ALLOC(sizeof(transmit_queue_item_t));
  CHECK_ERROR(tx_complete_item == NULL);
  tx_complete_item->handle = frame;

  list_push_back(&pending_on_tx_complete, &tx_complete_item->node);
  core_push_frame_to_hal(frame_buffer, frame_length);
  HAL_MEM_FREE(&frame_buffer);
  if (frame->data != encrypted_payload)
    HAL_MEM_FREE(&encrypted_payload);
  log_debug("[Core] EP #%d: frame transmit submitted",
            (frame->endpoint == NULL) ? -1 : (signed)frame->endpoint->id);

  if (frame_type == HDLC_FRAME_TYPE_IFRAME) {
    list_push_back(&frame->endpoint->retry_queue, &item->node);
    frame->endpoint->frames_count_retry_queue++;
  } else
    HAL_MEM_FREE(&item);
  return true;
}

static void retry_timeout(endpoint_t *endpoint) {
  if (endpoint->packet_retry_count >= RE_TRANSMIT) {
    log_warn("Retransmit limit reached on endpoint #%d", endpoint->id);
    core_set_endpoint_in_error(endpoint->id, ENDPOINT_STATE_ERROR_DEST_UNREACH);
  } else {
    endpoint->retry_timeout_ms *= 2;
    if (endpoint->retry_timeout_ms > MAX_RE_TRANSMIT_TIMEOUT_MS)
      endpoint->retry_timeout_ms = MAX_RE_TRANSMIT_TIMEOUT_MS;
    log_debug("New RTO calculated on ep %d, after re_transmit timeout: %ldms",
              endpoint->id, endpoint->retry_timeout_ms);
    retry_frame(endpoint);
  }
}
#if (EZMESH_HDLC_SEQ_8 == 1)
static bool is_seq_valid(uint8_t seq, uint8_t ack) {
  return ((seq == (ack - 1u)) || (ack == 0u && seq == 7u));
}
#else
static bool is_seq_valid(uint8_t seq, uint8_t ack) {
  return ((seq == (ack - 1u)) || (ack == 0u && seq == 3u));
}
#endif
static endpoint_t *find_endpoint(uint8_t endpoint_number) {
  return &core_endpoints[endpoint_number];
}

static void stop_retry_timer(endpoint_t *endpoint) {
  hal_epoll_event_data_t *fd_timer_data = NULL;
  struct itimerspec cancel_time = {0};

  fd_timer_data = endpoint->retry_timer_data;
  if (fd_timer_data == NULL)
    return;

  cancel_time.it_interval.tv_sec = 0;
  cancel_time.it_interval.tv_nsec = 0;
  cancel_time.it_value.tv_sec = 0;
  cancel_time.it_value.tv_nsec = 0;

  CHECK_ERROR(timerfd_settime(fd_timer_data->file_descriptor, 0, &cancel_time,
                              NULL) < 0);
}

static double diff_timespec_ms(const struct timespec *final,
                               const struct timespec *initial) {
  return (double)((final->tv_sec - initial->tv_sec) * 1000) +
         (double)(final->tv_nsec - initial->tv_nsec) / 1000000.0;
}

static void start_retry_timer(endpoint_t *endpoint, struct timespec offset) {
  hal_epoll_event_data_t *fd_timer_data = NULL;

  struct timespec current_timestamp = {0};
  clock_gettime(CLOCK_MONOTONIC, &current_timestamp);

  long offset_in_ms = 0;
  struct itimerspec timeout_time = {0};

  offset_in_ms = (long)diff_timespec_ms(&offset, &current_timestamp);
  fd_timer_data = endpoint->retry_timer_data;

  if (offset_in_ms < 0)
    offset_in_ms = 0;
  if (endpoint->state != ENDPOINT_STATE_OPEN)
    return;
  CHECK_ERROR(fd_timer_data == NULL);
  CHECK_ERROR(fd_timer_data->file_descriptor < 0);

  timeout_time.it_interval.tv_sec = 0;
  timeout_time.it_interval.tv_nsec = 0;
  timeout_time.it_value.tv_sec =
      ((offset_in_ms + endpoint->retry_timeout_ms) / 1000);
  timeout_time.it_value.tv_nsec =
      (((offset_in_ms + endpoint->retry_timeout_ms) % 1000) * 1000000);

  CHECK_ERROR(timerfd_settime(fd_timer_data->file_descriptor, 0, &timeout_time,
                              NULL) < 0);
}

static void core_proc_endpoint_timeout(hal_epoll_event_data_t *event_data) {
  int fd_timer = 0;
  uint8_t endpoint_number = 0;
  uint64_t expiration = 0;

  fd_timer = event_data->file_descriptor;
  endpoint_number = event_data->endpoint_number;

  CHECK_ERROR(read(fd_timer, &expiration, sizeof(expiration)) < 0);
  CHECK_WARN(expiration != 1);
  retry_timeout(&core_endpoints[endpoint_number]);
}

static void core_push_frame_to_hal(const void *frame, size_t frame_len) {
  ssize_t ret = 0;

  log_debug_hexdump("[Core] Push frame to hal (host uart tx): ", frame,
                    frame_len);
  ret = send(hal_sock_fd, frame, frame_len, 0);
  CHECK_ERROR(ret < 0);
  CHECK_ERROR((size_t)ret != frame_len);
  // log_debug_TXD_TRANSMIT_COMPLETED();
}

static bool core_pull_frame_from_hal(frame_t **frame_buf,
                                     size_t *frame_buf_len) {
  size_t datagram_length = 0;
  ssize_t retval = 0;
  ssize_t ret = 0;

  CHECK_ERROR(retval < 0);

  retval = recv(hal_sock_fd, NULL, 0, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
  if (retval == 0) {
    log_debug("Driver closed the data socket");
    int ret_close = close(hal_sock_fd);
    CHECK_ERROR(ret_close != 0);
    return false;
  }

  datagram_length = (size_t)retval;
  CHECK_ERROR(datagram_length == 0);
  CHECK_ERROR(datagram_length < sizeof(frame_t));

  *frame_buf = (frame_t *)HAL_MEM_ALLOC((size_t)datagram_length);
  CHECK_ERROR(*frame_buf == NULL);

  ret = recv(hal_sock_fd, *frame_buf, (size_t)datagram_length, 0);
  CHECK_ERROR(ret < 0);
  CHECK_ERROR((size_t)ret != (size_t)datagram_length);

  *frame_buf_len = (size_t)datagram_length;

  log_debug_hexdump("[Core] Pull frame from hal (host uart rx): ", *frame_buf,
                    *frame_buf_len);

  return true;
}

static status_t core_push_data_to_server(uint8_t ep_id, const void *data,
                                         size_t data_len) {
  return state_passer(EP_push_data(ep_id, (uint8_t *)data, data_len));
}

uint16_t core_get_crc_sw(const void *buf, uint16_t length) {
  uint16_t crc = 0;
  for (uint16_t i = 0; i < length; i++)
    crc = core_compute_crc16((uint8_t)((uint8_t *)buf)[i], crc);
  return crc;
}

bool core_check_crc_sw(const void *buf, uint16_t length,
                       uint16_t expected_crc) {
  return (core_get_crc_sw(buf, length) == expected_crc);
}

uint16_t core_compute_crc16(uint8_t new_byte, uint16_t prev_result) {
#if (EZMESH_CRC_0 == 1)
  prev_result = ((uint16_t)(prev_result >> 8)) | ((uint16_t)(prev_result << 8));
  prev_result ^= new_byte;
  prev_result ^= (prev_result & 0xff) >> 4;
  prev_result ^= (uint16_t)(((uint16_t)(prev_result << 8)) << 4);
  prev_result ^=
      ((uint8_t)(((uint8_t)(prev_result & 0xff)) << 5)) |
      ((uint16_t)((uint16_t)((uint8_t)(((uint8_t)(prev_result & 0xff)) >> 3))
                  << 8));
#else
  uint8_t bit;

  for (bit = 0; bit < 8; bit++) {
    prev_result ^= (new_byte & 0x0001);
    prev_result =
        (prev_result & 0x01) ? (prev_result >> 1) ^ 0x8408 : (prev_result >> 1);
    new_byte = new_byte >> 1;
  }
#endif
  return prev_result;
}

void hdlc_create_header(uint8_t *hdr, uint8_t address, uint16_t length,
                        uint8_t control) {
  uint16_t cal_crc16 = 0;

  hdr[0] = HDLC_FLAG_VAL;
  hdr[1] = address;
  hdr[2] = (uint8_t)(length & 0xFF);
  hdr[3] = (uint8_t)((length >> 8) & 0xFF);
  hdr[4] = control;

  cal_crc16 = core_get_crc_sw(hdr, HDLC_HEADER_SIZE);

  hdr[5] = (uint8_t)(cal_crc16 & 0xFF);
  hdr[6] = (uint8_t)((cal_crc16 >> 8) & 0xFF);
}
