
#include "primary.h"
#include "library/libezmesh.h"
#include "utility/log.h"
#include "utility/config.h"
#include "utility/list.h"
#include "daemon/hdlc/core.h"
#include "daemon/controller.h"
#include "host/hal_epoll.h"

#include <stdlib.h>
#include <string.h>

#include <linux/limits.h>
#include <errno.h>
#include <fcntl.h>
// #include <limits.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <unistd.h>
#include "version.h"

// ================================
// private define
// ================================
#define CORE_EXC_SIZE sizeof(ezmesh_croe_exange_buffer_t) + sizeof(int)
#define CHECK_EXIT(cond) if (cond) { return; }
#define RETRY_COUNT 5
#define RETRY_TIMEOUT 100000
#define SIZEOF_SYSTEM_COMMAND(command) (sizeof(sys_cmd_t) + command->length)
#define UFRAME_ACK_TIMEOUT_SECONDS 2

#define SYS_TO_ERR_STATUE(err) ERR_SYS_STATUS_OK + err

typedef struct {
  list_node_t node;
  ez_epoll_t data;
} ez_socket_list_t;

typedef struct {
  list_node_t node;
  int fd_data_socket;
  int socket_fd;
} ez_socket_close_t;

typedef struct {
  list_node_t node;
  uint8_t ep;
  int socket_fd;
} conn_list_t;

typedef struct
{
  list_node_t node;
  ez_epoll_t data_socket_epoll_port_data;
  pid_t pid;
}ctrl_socket_data_list_t;

typedef struct {
  ep_state_t key;
  ezmesh_evt_type_t val;
} key_val_map_t;
static const key_val_map_t evt_map[] = {
  {ENDPOINT_STATE_OPEN, EVT_EP_OPENED},
  {ENDPOINT_STATE_CLOSED, EVT_EP_CLOSED},
  {ENDPOINT_STATE_CLOSING, EVT_EP_CLOSING},
  {ENDPOINT_STATE_ERROR_DEST_UNREACH, EVT_EP_ERROR_DESTINATION_UNREACHABLE},
  {ENDPOINT_STATE_ERROR_FAULT, EVT_EP_ERROR_FAULT}};

// ================================
// public define
// ================================
static list_node_t *connections;
static list_node_t *ctl_connections;
ez_open_ep_t sys_ep_state = OPEN_EP_IDLE;
ep_ctl_t ep_ctx[PRIMARY_EP_MAX_COUNTS];
int ctl_create_conn = 0;
int open_conn_fd = 0;
bool reset_sequence_ack = true;
extern bool ignore_reset_reason;

static list_node_t *pending_commands;
static list_node_t *commands;
static list_node_t *retries;
static list_node_t *commands_in_error;
static list_node_t *prop_last_status_callbacks;

#define SYS_CMD_HDR_SIZE sizeof(sys_cmd_t) + sizeof(property_id_t)

ez_err_t EP_close(uint8_t ep, bool state);
static void on_timer_expired(ez_epoll_t *private_data);
static void close_main_node_connection(int fd_data_socket);

#define SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len) \
        ret = send(fd, interface_buffer, buffer_len, 0); \
        if (ret < 0 && errno == EPIPE) { close_main_node_connection(fd); break; } \
        CHECK_ERROR(ret < 0 && errno != EPIPE); \
        CHECK_ERROR((size_t)ret != (buffer_len));

// ================================
// private function
// ================================
static int gen_socket(int ep) {
  struct sockaddr_un *p_sock = calloc(1, sizeof(struct sockaddr_un));
  int fd;

  fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  CHECK_ERROR(fd == -1);

  p_sock->sun_family = AF_UNIX;
  snprintf(p_sock->sun_path, sizeof(p_sock->sun_path)-1, "%s/%s/ep%d.sock", config.ep_hw.socket_path, config.ep_hw.name, ep);

  log_info("[Sys] Try Generate socket on fd: %d, path: %s", fd, p_sock->sun_path);
  CHECK_ERROR(bind(fd, (const struct sockaddr *)p_sock, sizeof(struct sockaddr_un)) < 0);
  CHECK_ERROR(listen(fd, 5) < 0);
  log_info("[Sys] Generate socket success fd: %d, path: %s", fd, p_sock->sun_path);
  free(p_sock);
  return fd;
}

static int accept_socket(ez_epoll_t *p_data) {
  int socket;
  CHECK_FATAL(p_data->ep < 0 || ep_ctx[p_data->ep].socket_instance.fd == -1);
  socket = accept(p_data->fd, NULL, NULL);
  CHECK_ERROR(socket < 0);
  CHECK_ERROR(fcntl(socket, F_SETFL, fcntl(socket, F_GETFL, NULL) | O_NONBLOCK) < 0);
  return socket;
}

static void del_socket(int ep, bool state) {
  int fd;
  struct sockaddr_un *p_sock = calloc(1, sizeof(struct sockaddr_un));
  
  fd = ep_ctx[ep].socket_instance.fd;
  if (fd > 0) {
    hal_epoll_unregister((hal_epoll_event_data_t*)&ep_ctx[ep].socket_instance);
    CHECK_ERROR(shutdown(fd, SHUT_RDWR) < 0);
    CHECK_ERROR(close(fd) < 0);
  }

  p_sock->sun_family = AF_UNIX;
  snprintf(p_sock->sun_path, sizeof(p_sock->sun_path)-1, "%s/%s/ep%d.sock", config.ep_hw.socket_path, config.ep_hw.name, ep);

  log_info("[Sys] Try delete socket on fd: %d, path: %s", fd, p_sock->sun_path);
  CHECK_ERROR(unlink(p_sock->sun_path) < 0 && errno != ENOENT);
  log_info("[Sys] Delete socket success fd: %d, path: %s", fd, p_sock->sun_path);
  free(p_sock);

  ep_ctx[ep].socket_instance.fd = -1;
  ep_ctx[ep].conn_count = 0;
  if (state) ep_ctx[ep].pending_close = ep_ctx[ep].conn_count;
}

static bool handle_epoll_close(int fd_data_socket, uint8_t ep) {
  
  ez_socket_close_t *item, *next_item;
  ezmesh_croe_exange_buffer_t *buffer;
  bool notified = false;

  item = SLIST_ENTRY(ep_ctx[ep].ctl_socket_data, ez_socket_close_t, node);
  buffer = calloc(CORE_EXC_SIZE, sizeof(uint8_t));   
  
  while (item) {
    next_item = SLIST_ENTRY((item)->node.node, ez_socket_close_t, node);

    if (item->fd_data_socket == fd_data_socket && item->socket_fd > 0) {
      list_remove(&ep_ctx[ep].ctl_socket_data, &item->node);
      if (!notified) {
        log_warn("notified");
        buffer->endpoint_number = ep;
        buffer->type = EXCHANGE_CLOSE_EP_QUERY;
        *((int *)buffer->payload) = fd_data_socket;
        if (send(item->socket_fd, buffer, CORE_EXC_SIZE, 0) == (ssize_t)CORE_EXC_SIZE) notified = true;
        else if (errno != EPIPE) log_warn("ep notify send() failed, errno = %d", errno);
      }
      free(item);
    }
    item = next_item;
  }
  free(buffer);
  return notified;
}

static void handle_user_closed_ep(int fd, uint8_t ep)
{
  ez_socket_list_t *item, *next_item;
  item = SLIST_ENTRY(ep_ctx[ep].epoll_data, ez_socket_list_t, node);
  if (item == NULL) log_error("data connection not found in the linked list of the endpoint");
  
  do{
    next_item = SLIST_ENTRY((item)->node.node, ez_socket_list_t, node);
    if (item->data.fd == fd)
    {
      hal_epoll_unregister((hal_epoll_event_data_t *)&item->data);
      list_remove(&ep_ctx[ep].epoll_data, &item->node);

      handle_epoll_close(item->data.fd, ep);
      CHECK_ERROR(shutdown(fd, SHUT_RDWR) < 0);
      CHECK_ERROR(close(fd) < 0);
      CHECK_ERROR(ep_ctx[ep].conn_count == 0);
      ep_ctx[ep].conn_count--;

      log_info("Endpoint socket #%d: Client disconnected. %d connections", ep, ep_ctx[ep].conn_count);
      if (ep_ctx[ep].conn_count == 0)
      {
        log_info("Closing endpoint socket, no more listeners");
        EP_close(ep, false);
        if (ep_ctx[ep].pending_close == 0)
        {
          log_info("No pending close on the endpoint, closing it");
          core_close_endpoint(ep, true, false);
        }
      }
      free(item);
    }
    item = next_item;
  } while (item != NULL);
}

static int EP_pull_data(int fd_data_socket, uint8_t **buffer_ptr, size_t *buffer_len_ptr)
{
  int datagram_length;
  uint8_t *buffer;
  ssize_t rc;

  CHECK_ERROR(ioctl(fd_data_socket, FIONREAD, &datagram_length) < 0);
  CHECK_FATAL(datagram_length == 0);

  buffer = (uint8_t *)calloc(1, PAD_TO_ALIGNMENT(datagram_length, sizeof(uint8_t)*8));
  CHECK_ERROR(buffer == NULL);

  rc = recv(fd_data_socket, buffer, (size_t)datagram_length, 0);
  if (rc < 0) { log_info("[PRI] recv() failed with %d", errno); }

  if (rc == 0 || (rc < 0 && errno == ECONNRESET))
  {
    log_info("[PRI] Client is closed");
    free(buffer);
    return -1;
  }
  CHECK_ERROR(rc < 0);

  *buffer_ptr = buffer;
  *buffer_len_ptr = (size_t)rc;
  return 0;
}

static void handle_node_event(ez_epoll_t *p_data) {
  
  uint8_t *buf;
  size_t buf_len;
  int fd = p_data->fd, length;
  uint8_t ep = p_data->ep;

  if (core_ep_is_busy(ep)) {
    hal_epoll_unwatch((hal_epoll_event_data_t*)p_data);
    return;
  }

  CHECK_ERROR(ioctl(fd, FIONREAD, &length) < 0);
  if (length == 0) {
    handle_user_closed_ep(fd, ep);
    return;
  }

  if (EP_pull_data(fd, &buf, &buf_len) != 0) {
    handle_user_closed_ep(fd, ep);
    return;
  }

  if (core_get_endpoint_state(ep) == ENDPOINT_STATE_OPEN) core_write(ep, buf, buf_len, 0);
  else {
    log_warn("Push data to close ep #%d, state: %d", ep, core_get_endpoint_state(ep));
    EP_close(ep, false);
  }
  free(buf);
}


static void close_main_node_connection(int fd_data_socket)
{
  ctrl_socket_data_list_t *item;
  ctrl_socket_data_list_t *next_item;

  item = SLIST_ENTRY(ctl_connections, ctrl_socket_data_list_t, node);
  if (item == NULL) log_error("ctrl data connection not found in the linked list of the ctrl socket");

  do {
    next_item = SLIST_ENTRY((item)->node.node, ctrl_socket_data_list_t, node);
    if (item->data_socket_epoll_port_data.fd == fd_data_socket)
    {
      hal_epoll_unregister((hal_epoll_event_data_t *)&item->data_socket_epoll_port_data);
      list_remove(&ctl_connections, &item->node);
      CHECK_ERROR(shutdown(fd_data_socket, SHUT_RDWR) < 0);
      CHECK_ERROR(close(fd_data_socket) < 0);
      log_info("Client disconnected");
      free(item);
    }
    item = next_item;
  } while (item != NULL);
}

static void EP_push_close_socket_pair(int fd_data_socket, int fd_ctrl_data_socket, uint8_t endpoint_number)
{
  ez_socket_close_t *item;
  item = calloc(1, sizeof(ez_socket_close_t));
  CHECK_ERROR(item == NULL);
  item->fd_data_socket = fd_data_socket;
  item->socket_fd = fd_ctrl_data_socket;
  list_push(&ep_ctx[endpoint_number].ctl_socket_data, &item->node);
}

static bool EP_find_close_socket_pair(int fd_data_socket, int fd_ctrl_data_socket, uint8_t endpoint_number)
{
  
  ez_socket_close_t *item;
  ez_socket_close_t *next_item;
  bool found = false;
  item = SLIST_ENTRY(ep_ctx[endpoint_number].ctl_socket_data, ez_socket_close_t, node);
  
  do {
    next_item = SLIST_ENTRY((item)->node.node, ez_socket_close_t, node);
    if (item->fd_data_socket == fd_data_socket && item->socket_fd == fd_ctrl_data_socket)
    {
      list_remove(&ep_ctx[endpoint_number].ctl_socket_data, &item->node);
      free(item);
      found = true;
      break;
    }
    item = next_item;
  } while (item != NULL);
  return found;
}

static void handle_main_node_event(ez_epoll_t *p_data) {
  int fd, length;
  uint8_t *buffer;
  ezmesh_croe_exange_buffer_t *interface_buffer;
  size_t buffer_len;
  ssize_t ret;

  fd = p_data->fd;
  CHECK_ERROR(ioctl(fd, FIONREAD, &length)<0);

  if (length == 0)
  {
    close_main_node_connection(fd);
    return;
  }

  CHECK_ERROR(EP_pull_data(fd, &buffer, &buffer_len) != 0);
  CHECK_ERROR(buffer_len < sizeof(ezmesh_croe_exange_buffer_t));
  interface_buffer = (ezmesh_croe_exange_buffer_t *)buffer;

  switch (interface_buffer->type)
  {
  case EXCHANGE_EP_STATUS_QUERY: {
    /* Client requested an endpoint status */
    ep_state_t ep_state;
    log_info("Received an endpoint status query");
    CHECK_ERROR(buffer_len != sizeof(ezmesh_croe_exange_buffer_t) + sizeof(ep_state_t));
    ep_state = core_get_endpoint_state(interface_buffer->endpoint_number);
    memcpy(interface_buffer->payload, &ep_state, sizeof(ep_state_t));
    SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len);
  break;}

  case EXCHANGE_MAX_WRITE_SIZE_QUERY: {
    /* Client requested maximum write size */
    log_info("Received an maximum write size query");
    CHECK_ERROR(buffer_len != sizeof(ezmesh_croe_exange_buffer_t) + sizeof(uint32_t));
    size_t rx_capability = (size_t)controller_get_agent_rx_capability();
    memcpy(interface_buffer->payload, &rx_capability, sizeof(uint32_t));
    SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len);
  break;}

  case EXCHANGE_VERSION_QUERY:{
    /* Client requested the version of the daemon*/
    char *version = (char *)interface_buffer->payload;
    bool do_close_client = false;
    CHECK_ERROR(interface_buffer->payload == NULL);
    log_info("Received a version query");

    if (buffer_len != sizeof(ezmesh_croe_exange_buffer_t) + sizeof(char) * PROJECT_MAX_VERSION_SIZE)
    {
      log_warn("Client used invalid version buffer_len = %zu", buffer_len);
      break;
    }

    if (strnlen(version, PROJECT_MAX_VERSION_SIZE) == PROJECT_MAX_VERSION_SIZE)
    {
      do_close_client = true;
      log_warn("Client used invalid library version, version string is invalid");
    } 
    else if (strcmp(version, PROJECT_VER) != 0)
    {
      do_close_client = true;
      log_warn("Client used invalid library version, (v%s) expected (v%s)", version, PROJECT_VER);
    } 
    else log_info("New client connection using library v%s", version);

    //Reuse the receive buffer to send back the response
    strncpy(version, PROJECT_VER, PROJECT_MAX_VERSION_SIZE);
    ret = send(fd, interface_buffer, buffer_len, 0);
    if ((ret < 0 && errno == EPIPE )|| do_close_client) { close_main_node_connection(fd); break; } 
    CHECK_ERROR(ret < 0 && errno != EPIPE); 
    CHECK_ERROR((size_t)ret != (buffer_len));
  break;}

  case EXCHANGE_OPEN_EP_QUERY:{
      /* Client requested to open an endpoint socket*/
    log_info("Received an endpoint open query");
    CHECK_ERROR(buffer_len != sizeof(ezmesh_croe_exange_buffer_t) + sizeof(bool));
    conn_list_t *conn = calloc(1, sizeof(conn_list_t));
    CHECK_ERROR(conn == NULL);
    conn->ep = interface_buffer->endpoint_number;
    conn->socket_fd = fd;
    list_push_back(&connections, &conn->node);
  break;}

  case EXCHANGE_CLOSE_EP_QUERY: {
    log_info("Received a endpoint close query");
    /* Endpoint was closed by agent */
    CHECK_ERROR(buffer_len != sizeof(ezmesh_croe_exange_buffer_t) + sizeof(int));
    if (ep_ctx[interface_buffer->endpoint_number].pending_close > 0)
    {
      ep_ctx[interface_buffer->endpoint_number].pending_close--;
      if (ep_ctx[interface_buffer->endpoint_number].pending_close == 0) core_close_endpoint(interface_buffer->endpoint_number, true, false);

      // Ack the close query
      SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len);
      if (ret >= 0 || errno != EPIPE){
        // And notify the caller
        SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len);
      }
    } else
    {
      /* Endpoint was already closed by a client (same ctrl data socket, multiple instances of the same endpoint) */
      if (core_get_endpoint_state(interface_buffer->endpoint_number) == ENDPOINT_STATE_CLOSED)
      {
        // Ack the close query
        SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len);
        if (ret >= 0 || errno != EPIPE){
          // And notify the caller
          SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len);
        }
      } else
      {
        /* Endpoint is about to be closed by a client */
        int fd_data_socket = *(int *)interface_buffer->payload;
        bool fd_data_socket_closed = EP_find_close_socket_pair(fd_data_socket, -1, interface_buffer->endpoint_number);
        if (!fd_data_socket_closed) EP_push_close_socket_pair(fd_data_socket, fd, interface_buffer->endpoint_number);
        // Socket already closed, ack the close query
        SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len);
      }
    }
  }
  break;

  case EXCHANGE_SET_PID_QUERY:{
    log_info("Received set PID");
    bool can_connect = true;
    memcpy(interface_buffer->payload, &can_connect, sizeof(bool));
    CHECK_ERROR(buffer_len < sizeof(bool));
    SEND_DATA_TO_CORE(ret, fd, interface_buffer, buffer_len);
    break;}

  case EXCHANGE_GET_AGENT_APP_VERSION_QUERY:{
    char *app_version = (char *)interface_buffer->payload;
    strncpy(app_version, controller_get_agent_app_version(), PROJECT_MAX_VERSION_SIZE);
    log_info("%s", app_version);

    send(fd, interface_buffer, buffer_len, 0);
    break;}
  default:{break;}
  }
  free(buffer);
}

static void handle_epoll_conn(ez_epoll_t *p_data) {
  
  uint8_t ep;
  int socket;
  ez_socket_list_t *node;

  ep = p_data->ep;
  socket = accept_socket(p_data);
  node = calloc(1, sizeof(ez_socket_list_t));
  CHECK_ERROR(node == NULL);
  list_push(&ep_ctx[ep].epoll_data, &node->node);
  node->data.callback = (ep == 0)? handle_main_node_event : handle_node_event;
  node->data.ep = ep;
  node->data.fd = socket;
  hal_epoll_register((hal_epoll_event_data_t*)&node->data);

  if(ep == 0){ list_push(&ctl_connections, &node->node); }
  else
  {
    ezmesh_croe_exange_buffer_t *buffer;

    ep_ctx[ep].conn_count++;
    log_info("[INFO] EP socket #%d: Client connected. %d connections", ep, ep_ctx[ep].conn_count);

    core_process_endpoint_change(ep, ENDPOINT_STATE_OPEN);
    log_info("[PRI] Told ezmeshd to open ep#%u", ep);

    size_t buffer_len = sizeof(ezmesh_croe_exange_buffer_t) + sizeof(int);
    buffer = calloc(1, buffer_len);
    CHECK_ERROR(buffer == NULL);
    buffer->endpoint_number = ep;
    buffer->type = EXCHANGE_OPEN_EP_QUERY;
    *((int *)buffer->payload) = socket;
    CHECK_ERROR(send(socket, buffer, buffer_len, 0) != (ssize_t)buffer_len);
    free(buffer);
  }
}

static void handle_ep_send(int fd_data_socket, int socket_fd, uint8_t ep) {
  
  ez_socket_close_t *item;
  item = calloc(1, sizeof(ez_socket_close_t));
  CHECK_ERROR(item == NULL);
  item->fd_data_socket = fd_data_socket;
  item->socket_fd = socket_fd;
  list_push(&ep_ctx[ep].ctl_socket_data, &item->node);
  free(item);
}

static void get_hw_state(sys_cmd_handle_t *handle, property_id_t id, void *p_data,
                  size_t p_length, status_t status) {
  (void)handle;
  bool create_flag = false, hw_attach = false;
  uint8_t ep;
  ep_state_t hw_ep_state;
  ep_state_t sw_ep_state;

  switch (status) {
  case STATUS_OK:
  case STATUS_IN_PROGRESS:{
    CHECK_FATAL(p_length != sizeof(ep_state_t));
    log_info("[PRI] Successful callback");
    hw_ep_state = core_endpoint_state(*(uint8_t *)p_data);
    hw_attach = true;
    break;}

  case STATUS_TIMEOUT:
  case STATUS_ABORT:
  default: {
    log_warn("PROP_EP_STATE: 0x%02x", status);
    break;}
  }
  CHECK_FATAL(ctl_create_conn == 0 || (hw_attach && p_length != 1));
  ep = PROPERTY_ID_TO_EP_ID(id);
  sw_ep_state = core_get_endpoint_state(ep);

  log_info("HW State: %d, SW State: %d", hw_ep_state, sw_ep_state);

  if (hw_attach && (hw_ep_state == ENDPOINT_STATE_OPEN) && (sw_ep_state == ENDPOINT_STATE_CLOSED || sw_ep_state == ENDPOINT_STATE_OPEN))
    create_flag = true;

  if (!create_flag && hw_attach)
    log_info("[PRI] Cannot open EP #%d. HW state: %s. Daemon state: %s", ep, core_stringify_state(hw_ep_state), core_stringify_state(sw_ep_state));

  if (!hw_attach) log_warn("Could not read EP state on the HW");

  if (create_flag) EP_open(ep, sw_ep_state); 

  const size_t buffer_len = sizeof(ezmesh_croe_exange_buffer_t) + sizeof(bool);
  ezmesh_croe_exange_buffer_t *interface_buffer = calloc(1, buffer_len);

  interface_buffer->type = EXCHANGE_OPEN_EP_QUERY;
  interface_buffer->endpoint_number = ep;
  memcpy(interface_buffer->payload, &create_flag, sizeof(bool));

  ssize_t ret = send(ctl_create_conn, interface_buffer, buffer_len, 0);
  log_info("[PRI] Replied to endpoint open query on ep#%d", ep);

  if (ret == -1) log_warn("Failed to acknowledge the open request for endpoint #%d", ep);
  else if ((size_t)ret != buffer_len) FATAL("Failed to acknowledge the open request for endpoint #%d. Sent %d, Expected %d", ep, (int)ret, (int)buffer_len);
  
  free(interface_buffer);
  sys_ep_state = OPEN_EP_DONE;
}

void EP_close_cb(sys_cmd_handle_t *handle, property_id_t id, void *property_value, 
                  size_t property_length, status_t status){
  (void)handle;
  (void)property_value;
  (void)property_length;
  uint8_t ep = PROPERTY_ID_TO_EP_ID(id);
  switch (status) {
  case STATUS_IN_PROGRESS:
  case STATUS_OK: {
    log_info("[PRI] ACK HW of async close ep#%d", ep);
    break;
  }

  case STATUS_TIMEOUT:
  case STATUS_ABORT:
  default: {
    log_warn("HW did not receive ACK of async close ep#%d", ep);
    break;
  }
  }
}

bool EP_list_empty(uint8_t ep) { return ep_ctx[ep].conn_count == 0; }

// ================================
// public function
// ================================
ez_err_t EP_open(uint8_t ep, ep_state_t state) {
  CHECK_FATAL(ep == 0 && ep_ctx[ep].socket_instance.fd != -1 && ep_ctx[ep].epoll_data != NULL);
  CHECK_FATAL(ep != 0 && ep_ctx[ep].socket_instance.fd == -1 && ep_ctx[ep].epoll_data != NULL);

  if(ep != 0 && ep_ctx[ep].socket_instance.fd != -1) { EP_close( ep, state); }

  ep_ctx[ep].socket_instance.callback = handle_epoll_conn;
  ep_ctx[ep].socket_instance.ep = ep;
  ep_ctx[ep].socket_instance.fd = gen_socket(ep);

  hal_epoll_register((hal_epoll_event_data_t*)&ep_ctx[ep].socket_instance);
  log_info("[INFO] Opened connection socket for ep#%u", ep);
  return NO_ERROR;
}

ez_err_t EP_close(uint8_t ep, bool state) {
  size_t idx = 0;
  list_node_t *node;
  ez_socket_list_t *item;

  CHECK_FATAL(ep == 0 );
  if(ep_ctx[ep].socket_instance.fd == -1) return NO_ERROR;
  while (ep_ctx[ep].epoll_data != NULL) {
    node = list_pop(&ep_ctx[ep].epoll_data);
    item = SLIST_ENTRY(node, ez_socket_list_t, node);
    idx++;

    hal_epoll_unregister((hal_epoll_event_data_t*)&item->data);
    handle_epoll_close(item->data.fd, ep);

    CHECK_ERROR(shutdown(item->data.fd, SHUT_RDWR) < 0);
    CHECK_ERROR(close(item->data.fd) < 0);
    free(item);
    log_info("[PRI] Closed data socket #%u on ep#%u", idx, ep);
  }
  del_socket(ep, state);
  return NO_ERROR;
}

bool EP_get_state(uint8_t ep) { return ep_ctx[ep].socket_instance.fd != -1; }

bool EP_is_open(uint8_t ep) { return ep_ctx[ep].conn_count == 0; }

ez_err_t EP_set_state(uint8_t ep, ep_state_t state) {
  ez_socket_list_t *item;
  ezmesh_ezmeshd_event_buffer_t *event;
  event = calloc(1, sizeof(ezmesh_ezmeshd_event_buffer_t));
  CHECK_ERROR(event == NULL);
  SLIST_FOR_EACH_ENTRY(ep_ctx[ep].epoll_event, item, ez_socket_list_t, node) {
    event->type = evt_map[state].val;
    event->endpoint_number = ep;
    event->payload_length = 0;

    ssize_t ret = send(item->data.fd, event, sizeof(ezmesh_ezmeshd_event_buffer_t), MSG_DONTWAIT);
    free(event);
    if (ret < 0 && (errno == EPIPE || errno == ECONNRESET || errno == ECONNREFUSED)) {} 
    else if (ret < 0 && errno == EWOULDBLOCK)
    {
      log_warn("Client event socket is full, closing the socket..");
      CHECK_ERROR(shutdown(item->data.fd, SHUT_RDWR) < 0);
    } 
    else { CHECK_FATAL(ret < 0 || (size_t)ret != sizeof(ezmesh_ezmeshd_event_buffer_t)); }
  }
  free(event);
  return NO_ERROR;
}

ez_err_t EP_push_data(uint8_t ep, uint8_t *data, size_t data_len) {
  ez_socket_list_t *item;
  int nb_clients = 0;
  ssize_t wc;

  CHECK_FATAL(ep_ctx[ep].socket_instance.fd == -1);
  CHECK_WARN(ep_ctx[ep].epoll_data == NULL);

  item = SLIST_ENTRY(ep_ctx[ep].epoll_data, ez_socket_list_t, node);

  while (item != NULL) {
    wc = send(item->data.fd, data, data_len, MSG_DONTWAIT);
    if (wc < 0) log_info("[PRI] send() failed with %d", errno);

    nb_clients++;

    if (wc < 0 && (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET ||
                   errno == EWOULDBLOCK)) {
      log_warn("Unresponsive data socket on ep#%d, closing", ep);

      if (ep_ctx[ep].conn_count == 1 && nb_clients == 1 &&
          (errno == EAGAIN || errno == EWOULDBLOCK))
        return SYS_TO_ERR_STATUE(STATUS_WOULD_BLOCK);

      hal_epoll_unregister((hal_epoll_event_data_t*)&item->data);
      handle_ep_send(item->data.fd, -1, ep);

      CHECK_ERROR(shutdown(item->data.fd, SHUT_RDWR) < 0);
      CHECK_ERROR(close(item->data.fd) < 0);
      list_remove(&ep_ctx[ep].epoll_data, &item->node);
      free(item);

      CHECK_ERROR(ep_ctx[ep].conn_count == 0);
      ep_ctx[ep].conn_count--;
      log_info("[INFO] EP #%d: Client disconnected. %d connections", ep, ep_ctx[ep].conn_count);

      if (ep_ctx[ep].conn_count == 0) {
        log_info("[PRI] EP was unresponsive, no more listeners");
        del_socket(ep, false);
        return SYS_TO_ERR_STATUE(STATUS_FAIL);
      }

      item = SLIST_ENTRY(ep_ctx[ep].epoll_data, ez_socket_list_t, node);
    } else {
      CHECK_ERROR(wc < 0);
      CHECK_ERROR((size_t)wc != data_len);
      item = SLIST_ENTRY((item)->node.node, ez_socket_list_t, node);
    }
  }
  return SYS_TO_ERR_STATUE(STATUS_OK);
}

void ctl_notify_HW_reset(void)
{
  ctrl_socket_data_list_t *item;

  SLIST_FOR_EACH_ENTRY(ctl_connections, item, ctrl_socket_data_list_t, node)
  {
    if (item->pid != getpid())
    {
      if (item->pid > 1) { kill(item->pid, SIGUSR1); } 
      else { FATAL("Connected library's pid it not set"); }
    }
  }
}

ez_err_t ctl_proc_conn(void) {
  conn_list_t *item;
  item = SLIST_ENTRY(connections, conn_list_t, node);
  if (item == NULL) return NO_ERROR;

  if (core_endpoint_is_closing(item->ep)) {
    log_info("[PRI] EP #%d is closing, waiting before opening", item->ep);
    return NO_ERROR;
  }

  switch (sys_ep_state) {
    case OPEN_EP_IDLE: {
      sys_ep_state = OPEN_EP_STATE_WAITING;
      open_conn_fd = item->socket_fd;
      ctl_create_conn = item->socket_fd;
      sys_param_get(get_hw_state, (property_id_t)(PROP_EP_STATE_0 + item->ep), 5, 100000, false);
      break;
    }
    case OPEN_EP_DONE: {
      sys_ep_state = OPEN_EP_IDLE;
      open_conn_fd = 0;
      list_remove(&connections, &item->node);
      free(item);
      break;
    }
    case OPEN_EP_STATE_FETCHED:
    default: { break; }
  }
  return NO_ERROR;
}

ez_err_t ctl_init(void) {
  ez_epoll_t *ep_data = calloc(1, sizeof(ez_epoll_t));

  list_init(&ctl_connections);
  list_init(&connections);
  for (size_t i = 1; i != PRIMARY_EP_MAX_COUNTS; i++) {
    ep_ctx[i].conn_count = 0;
    ep_ctx[i].conn_event = 0;
    ep_ctx[i].pending_close = 0;
    ep_ctx[i].socket_instance.ep = (uint8_t)i;
    ep_ctx[i].socket_instance.fd = -1;
    ep_ctx[i].epoll_conn_event.fd = -1;
    list_init(&ep_ctx[i].epoll_event);
    list_init(&ep_ctx[i].epoll_data);
    list_init(&ep_ctx[i].ctl_socket_data);
  }

  ep_data->callback = handle_epoll_conn;
  ep_data->fd = gen_socket(0);
  ep_data->ep = EP_SYSTEM;
  // log_info("EPOLL ADD EVENT: fd 0x%02x, EP %d, cb: %p", ep_data->fd , EP_SYSTEM, ep_data->callback);
  hal_epoll_register((hal_epoll_event_data_t*)ep_data);
  return NO_ERROR;
}

static void sys_cmd_abort(sys_cmd_handle_t *handle, status_t error)
{
  // Stop the re_transmit timer
  if (handle->retx_socket.fd != 0)
  {
    if (handle->is_uframe || handle->acked == true) hal_epoll_unregister((hal_epoll_event_data_t*)&handle->retx_socket); 
    close(handle->retx_socket.fd);
    handle->retx_socket.fd = 0;
  }

  handle->error_status = error; //This will be propagated when calling the callbacks

  switch (handle->command->command_id)
  {
    case CMD_SYSTEM_NOOP:{
      ((sys_noop_cb_t)handle->on_final)(handle, handle->error_status);
      break;}

    case CMD_SYSTEM_RESET:{
      ((sys_reset_cmd_callback_t)handle->on_final)(handle, handle->error_status, SYS_STATUS_FAILURE);
      break;}

    case CMD_SYSTEM_PROP_VALUE_GET:
    case CMD_SYSTEM_PROP_VALUE_SET:{
      sys_property_cmd_t *tx_property_command = (sys_property_cmd_t *)handle->command->payload;

      ((sys_property_get_set_cmd_callback_t)handle->on_final)(handle, tx_property_command->property_id,
                                                              NULL, 0, handle->error_status);
      break;}

    case CMD_SYSTEM_PROP_VALUE_IS: //fall through
    default:{
        FATAL("Invalid command_id");
        break;}
  }

  // Invalidate the command id, now that it is aborted
  handle->command->command_id = CMD_SYSTEM_INVALID;
}


static void write_command(sys_cmd_handle_t *handle)
{
  int timer_fd;
  uint8_t flags = FLAG_INFORMATION_POLL;

  handle->retry_forever = (handle->retry_count == 0)? true : false;
  if (handle->is_uframe) flags = FLAG_UFRAME_POLL;

  list_push_back(&commands, &handle->node_commands);
  handle->acked = false;
  core_write(EP_SYSTEM, (void *)handle->command, SIZEOF_SYSTEM_COMMAND(handle->command), flags);

  log_info("[SYS] Submitted command_id #%d command_seq #%d, frame_type %d", handle->command->command_id, handle->command_seq, handle->is_uframe);

  if (handle->is_uframe)
  {
    const struct itimerspec timeout = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                        .it_value = { .tv_sec = (long int)handle->retry_timeout_us / 1000000, 
                                        .tv_nsec = ((long int)handle->retry_timeout_us * 1000) % 1000000000 } };

    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    CHECK_ERROR(timer_fd < 0);
    int ret = timerfd_settime(timer_fd, 0, &timeout, NULL);
    CHECK_ERROR(ret < 0);

    handle->retx_socket.ep = EP_SYSTEM;
    handle->retx_socket.fd = timer_fd;
    handle->retx_socket.callback = on_timer_expired;
    hal_epoll_register((hal_epoll_event_data_t*)&handle->retx_socket);
  }
}


void sys_ep_no_found_ack()
{
  list_node_t *item;
  sys_cmd_handle_t *handle;

  log_info("[SYS] Received sequence numbers reset acknowledgement");
  reset_sequence_ack = true;

  // Send any pending commands
  item = list_pop(&pending_commands);
  while (item != NULL)
  {
    handle = SLIST_ENTRY(item, sys_cmd_handle_t, node_commands);
    write_command(handle);
    item = list_pop(&pending_commands);
  }
}

static void handle_ack_timeout(ez_epoll_t *private_data) {
  list_node_t *item;
  int timer_fd = private_data->fd;
  sys_cmd_handle_t *handle;
  uint64_t expiration;
  ssize_t ret;

  handle = MEM_INDEX(private_data, sys_cmd_handle_t, retx_socket);
  if (reset_sequence_ack) {
    if (handle->retx_socket.fd != 0) {
      hal_epoll_unregister((hal_epoll_event_data_t*)&handle->retx_socket);
      close(handle->retx_socket.fd);
      handle->retx_socket.fd = 0;
    }
    return;
  }

  log_info("[SYS] Remote is unresponsive, retrying...");

  ret = read(timer_fd, &expiration, sizeof(expiration));
  CHECK_ERROR(ret < 0);
  CHECK_ERROR(ret != sizeof(expiration));
  CHECK_WARN(expiration != 1);

  /* Drop any pending commands to prevent accumulation*/
  item = list_pop(&pending_commands);
  while (item != NULL) {
    handle = SLIST_ENTRY(item, sys_cmd_handle_t, node_commands);

    if (handle->command->command_id != CMD_SYSTEM_INVALID) sys_cmd_abort(handle, STATUS_ABORT);
    free(handle);
    item = list_pop(&pending_commands);
  }

  core_write(EP_SYSTEM, NULL, 0, FLAG_UFRAME_RESET_COMMAND);
}

// ================================
// public function
// ================================

static void sys_init_cmd_handle(sys_cmd_handle_t *handle, void *on_final, uint8_t retry_count, uint32_t retry_timeout_us, bool is_uframe)
{
  static uint8_t next_command_seq = 0;

  CHECK_FATAL(handle == NULL);
  CHECK_FATAL(on_final == NULL);
  handle->acked = false;
  handle->error_status = STATUS_OK;

  handle->on_final = on_final;
  handle->retry_count = retry_count;
  handle->retry_timeout_us = retry_timeout_us;
  handle->command_seq = next_command_seq++;
  handle->is_uframe = is_uframe;
}

static void sys_abort(sys_cmd_handle_t *handle, status_t error)
{
  // Stop the re_transmit timer
  if (handle->retx_socket.fd != 0)
  {
    if (handle->is_uframe || handle->acked == true) hal_epoll_unregister((hal_epoll_event_data_t*)&handle->retx_socket);
    close(handle->retx_socket.fd);
    handle->retx_socket.fd = 0;
  }

  handle->error_status = error; //This will be propagated when calling the callbacks

  switch (handle->command->command_id)
  {
  case CMD_SYSTEM_NOOP:{
    ((sys_noop_cb_t)handle->on_final)(handle, handle->error_status);
    break;}

  case CMD_SYSTEM_RESET:{
    ((sys_reset_cmd_callback_t)handle->on_final)(handle, handle->error_status, SYS_STATUS_FAILURE);
    break;}

  case CMD_SYSTEM_PROP_VALUE_GET:
  case CMD_SYSTEM_PROP_VALUE_SET:{
    ((sys_property_get_set_cmd_callback_t)handle->on_final)(handle, ((sys_property_cmd_t *)handle->command->payload)->property_id, 
                                                            NULL, 0, handle->error_status);
    break;}
  
  case CMD_SYSTEM_PROP_VALUE_IS: //fall through
  default:
      FATAL("Invalid command_id");
      break;
  }

  // Invalidate the command id, now that it is aborted
  handle->command->command_id = CMD_SYSTEM_INVALID;
}


static void on_timer_expired(ez_epoll_t *private_data)
{
  int timer_fd = private_data->fd;
  sys_cmd_handle_t *handle = MEM_INDEX(private_data, sys_cmd_handle_t, retx_socket);

  log_info("[SYS] Command ID #%u SEQ #%u timer expired", handle->command->command_id, handle->command->command_seq);

  uint64_t expiration;
  ssize_t retval;
  retval = read(timer_fd, &expiration, sizeof(expiration));
  CHECK_ERROR(retval < 0);
  CHECK_ERROR(retval != sizeof(expiration));
  CHECK_WARN(expiration != 1); /* we missed a timeout*/

  if (!handle->retry_forever) handle->retry_count--;

  if (handle->retry_count > 0 || handle->retry_forever)
  {
      list_remove(&commands, &handle->node_commands);
      handle->error_status = STATUS_IN_PROGRESS; //at least one timer retry occurred
      write_command(handle);
      if (handle->retry_forever) log_info("[SYS] Command ID #%u SEQ #%u retried", handle->command->command_id, handle->command->command_seq);
      else log_info("[SYS] Command ID #%u SEQ #%u. %u retry left", handle->command->command_id, handle->command->command_seq, handle->retry_count);
  } 
  else 
  { 
    SLIST_FOR_EACH_ENTRY(commands, handle, sys_cmd_handle_t, node_commands)
    {
      if (handle->command_seq == (handle->command)->command_seq) break;
    }
    if (handle == NULL || handle->command_seq != (handle->command)->command_seq) FATAL("A command timed out but it could not be found in the submitted commands list. SEQ#%d", (handle->command)->command_seq);
    list_remove(&commands, &handle->node_commands);
    log_info("[SYS] Command ID #%u SEQ #%u timeout", handle->command->command_id, handle->command->command_seq);
    sys_abort(handle, STATUS_TIMEOUT);
    free(handle->command);
    free(handle);  
  }
}

void sys_reboot(reset_cb_t cb, uint8_t count, uint32_t time) {
  sys_cmd_handle_t *handle;

  handle = calloc(1, sizeof(sys_cmd_handle_t));
  CHECK_ERROR(handle == NULL);

  handle->command = calloc(1, sizeof(sys_cmd_t));
  CHECK_ERROR(handle->command == NULL);

  sys_init_cmd_handle(handle, (void *)cb, count, time, true);
  handle->command->command_id = CMD_SYSTEM_RESET;
  handle->command->command_seq = handle->command_seq;
  handle->command->length = 0;
  write_command(handle);
  log_info("[SYS] reset (id #%u) sent", CMD_SYSTEM_RESET);
}

void sys_param_get(param_get_cb_t cb, property_id_t id, uint8_t count,
                   uint32_t time, bool is_uframe) {
  sys_cmd_handle_t *handle;

  handle = calloc(1, sizeof(sys_cmd_handle_t));
  CHECK_ERROR(handle == NULL);

  handle->command = calloc(1, PAD_TO_ALIGNMENT(SYS_CMD_HDR_SIZE, 8));
  CHECK_ERROR(handle->command == NULL);

  sys_init_cmd_handle(handle, (void *)cb, count, time, is_uframe);


  sys_cmd_t *tx_command =  handle->command;
  sys_property_cmd_t *tx_property_command = (sys_property_cmd_t *)tx_command->payload;

  tx_command->command_id = CMD_SYSTEM_PROP_VALUE_GET;
  tx_command->command_seq = handle->command_seq;
  tx_command->length = sizeof(property_id_t);
  tx_property_command->property_id = cpu_to_le32(id);

  write_command(handle);
  log_info("[SYS] param-get (id #%u) sent with param #%u", CMD_SYSTEM_PROP_VALUE_GET, id);
}

void sys_param_set(param_set_cb_t cb, uint8_t count, uint32_t time,
                   property_id_t id, const void *val, size_t length,
                   bool is_uframe) {
  sys_cmd_handle_t *handle;
  uint8_t *payload;

  handle = calloc(1, sizeof(sys_cmd_handle_t));
  CHECK_ERROR(handle == NULL);
  handle->command = calloc(1, PAD_TO_ALIGNMENT(SYS_CMD_HDR_SIZE + length, 8));
  CHECK_ERROR(handle->command == NULL);

  sys_init_cmd_handle(handle, (void *)cb, count, time, is_uframe);
  payload = ((sys_property_cmd_t *)handle->command->payload)->payload;
  handle->command->command_id = CMD_SYSTEM_PROP_VALUE_SET;
  handle->command->command_seq = handle->command_seq;
  handle->command->length = (uint8_t)(sizeof(property_id_t) + length);
  ((sys_property_cmd_t *)handle->command->payload)->property_id =
      cpu_to_le32(id);

  switch (length) {
    case 0: {
      log_error("Can't send a property-set request with value of length 0");
      break;}

    case 1: {
      memcpy(payload, val, length);
      break;}

    case 2: {
      uint16_t le16 = cpu_to_le16p((uint16_t *)val);
      memcpy(payload, &le16, 2);
      break;}

    case 4: {
      uint32_t le32 = cpu_to_le32p((uint32_t *)val);
      memcpy(payload, &le32, 4);
      break;}

    case 8: {
      uint64_t le64 = cpu_to_le64p((uint64_t *)val);
      memcpy(payload, &le64, 8);
      break;}

    default:{
      memcpy(payload, val, length);
      break;}
  }

  write_command(handle);
  log_info("[SYS] property-set (id #%u) sent with property #%u", CMD_SYSTEM_PROP_VALUE_SET, id);
}

static void on_reply(uint8_t endpoint_id, void *arg, void *answer, uint32_t answer_lenght)
{
  sys_cmd_handle_t *handle;
  sys_cmd_t *reply = (sys_cmd_t *)answer;
  size_t frame_type = (size_t)arg;

  CHECK_FATAL(endpoint_id != 0);
  CHECK_ERROR(reply->length != answer_lenght - sizeof(sys_cmd_t));

  SLIST_FOR_EACH_ENTRY(commands, handle, sys_cmd_handle_t, node_commands)
  {
    if (handle->command_seq != reply->command_seq) continue;
    
    log_info("[SYS] Processing command seq#%d of type %d", reply->command_seq, frame_type); 
    if (frame_type == HDLC_FRAME_TYPE_UFRAME || (frame_type == HDLC_FRAME_TYPE_IFRAME && handle->acked == true))
    {
      CHECK_FATAL(handle->retx_socket.fd <= 0);
      hal_epoll_unregister((hal_epoll_event_data_t*)&handle->retx_socket);
      close(handle->retx_socket.fd);
      handle->retx_socket.fd = 0;
    }

    /* Call the appropriate callback */
    if (frame_type == HDLC_FRAME_TYPE_UFRAME)
    {
      CHECK_FATAL(handle->is_uframe == false);
      switch (reply->command_id)
      {
      case CMD_SYSTEM_RESET:{
        log_info("[SYS] on_final_reset()");
        ignore_reset_reason = false;
        // Deal with endianness of the returned status since its a 32bit value.
        sys_status_t reset_status_le = *((sys_status_t *)(reply->payload));
        sys_status_t reset_status_cpu = le32_to_cpu(reset_status_le);
        ((sys_reset_cmd_callback_t)handle->on_final)(handle, handle->error_status, reset_status_cpu);
        break;}

      case CMD_SYSTEM_PROP_VALUE_IS:{
        sys_property_cmd_t *p_cmd = (sys_property_cmd_t *)reply->payload;
        sys_property_get_set_cmd_callback_t cb = (sys_property_get_set_cmd_callback_t)handle->on_final;

        if (p_cmd->property_id != PROP_RX_CAPABILITY && p_cmd->property_id != PROP_CAPABILITIES
            && p_cmd->property_id != PROP_BUS_SPEED_VALUE && p_cmd->property_id != PROP_PROTOCOL_VERSION
            && p_cmd->property_id != PROP_SECONDARY_EZMESH_VERSION && p_cmd->property_id != PROP_SECONDARY_APP_VERSION
            && p_cmd->property_id != PROP_BOOTLOADER_REBOOT_MODE)
        {
          log_error("Received on_final property_is %x as a u-frame", p_cmd->property_id);
        }
        /* Deal with endianness of the returned property-id since its a 32bit value. */
        property_id_t property_id_le = p_cmd->property_id;
        property_id_t property_id_cpu = le32_to_cpu(property_id_le);
        size_t value_length = reply->length - sizeof(sys_property_cmd_t);
        if(cb) cb(handle, property_id_cpu, p_cmd->payload, value_length, handle->error_status);
        break;}

      default:{
        log_error("system endpoint command id not recognized for u-frame");
        break;}
      }
    } else if (frame_type == HDLC_FRAME_TYPE_IFRAME)
    {
      CHECK_FATAL(handle->is_uframe == true);
      switch (reply->command_id)
      {
      case CMD_SYSTEM_NOOP:{
        log_info("[SYS] on_final_noop()");
        ((sys_noop_cb_t)handle->on_final)(handle, handle->error_status);
        break;}

      case CMD_SYSTEM_PROP_VALUE_IS:{
        sys_property_cmd_t *p_cmd = (sys_property_cmd_t *)reply->payload;
        sys_property_get_set_cmd_callback_t cb = (sys_property_get_set_cmd_callback_t)handle->on_final;
        property_id_t property_id_le = p_cmd->property_id;
        property_id_t property_id_cpu = le32_to_cpu(property_id_le);
        size_t value_length = reply->length - sizeof(sys_property_cmd_t);

        if(cb) cb(handle, property_id_cpu, p_cmd->payload, value_length, handle->error_status);
        break;}

      case CMD_SYSTEM_PROP_VALUE_GET:
      case CMD_SYSTEM_PROP_VALUE_SET:{
        log_error("its the primary who sends those");
        break;}

      default:{
        log_error("system endpoint command id not recognized for i-frame");
        break;}
      }
    } else log_error("Invalid frame_type"); 

    /* Cleanup this command now that it's been serviced */
    list_remove(&commands, &handle->node_commands);
    free(handle->command);
    free(handle);
    return;
  }

  log_warn("Received a system final for which no pending poll is registered");
}

static void on_uframe_receive(uint8_t endpoint_id, const void *data, size_t data_len)
{
  CHECK_ERROR(endpoint_id != EP_SYSTEM);
  log_info("[SYS] Unsolicited uframe received");
  sys_cmd_t *reply = (sys_cmd_t *)data;
  CHECK_ERROR(reply->length != data_len - sizeof(sys_cmd_t));

  if (reply->command_id == CMD_SYSTEM_PROP_VALUE_IS)
  {
    sys_property_cmd_t *property = (sys_property_cmd_t *)reply->payload;
    if (property->property_id == PROP_LAST_STATUS)
    {
      last_status_callback_list_t *item;
      SLIST_FOR_EACH_ENTRY(prop_last_status_callbacks, item, last_status_callback_list_t, node)
      {
        sys_status_t *status = (sys_status_t *)property->payload;
        item->callback(*status);
      }
    }
  }
}

static void on_iframe_unsolicited(uint8_t endpoint_id, const void *data, size_t data_len)
{
    CHECK_ERROR(endpoint_id != EP_SYSTEM);
    log_info("[SYS] Unsolicited i-frame received");
    if (controller_reset_sequence_in_progress())
    {
      log_info("[SYS] Cannot process unsolicited i-frame during reset sequence, ignoring");
      return;
    }

    sys_cmd_t *reply = (sys_cmd_t *)data;
    CHECK_ERROR(reply->length != data_len - sizeof(sys_cmd_t));
    if (reply->command_id == CMD_SYSTEM_PROP_VALUE_IS)
    {
      sys_property_cmd_t *property = (sys_property_cmd_t *)reply->payload;
      if (property->property_id >= PROP_EP_STATE_0 && property->property_id < PROP_EP_STATES)
      {
        uint8_t closed_endpoint_id = PROPERTY_ID_TO_EP_ID(property->property_id);
        ep_state_t endpoint_state = core_endpoint_state(*(uint8_t *)property->payload);

        if (endpoint_state == ENDPOINT_STATE_CLOSING)
        {
          log_info("[SYS] Secondary closed the endpoint #%d", closed_endpoint_id);
          if (!EP_list_empty(closed_endpoint_id) && core_get_endpoint_state(closed_endpoint_id) == ENDPOINT_STATE_OPEN)
            core_set_endpoint_in_error(closed_endpoint_id, ENDPOINT_STATE_ERROR_DEST_UNREACH);
          sys_param_set(EP_close_cb, RETRY_COUNT, RETRY_TIMEOUT, property->property_id, &endpoint_state, sizeof(ep_state_t), false);
        }
        else log_error("Invalid property id");
      }
    }
}

static void sys_open_endpoint()
{
  core_open_endpoint(EP_SYSTEM, OPEN_EP_FLAG_UFRAME_ENABLE, 1);
  core_set_endpoint_option(EP_SYSTEM, EP_ON_FINAL, on_reply);
  core_set_endpoint_option(EP_SYSTEM, EP_ON_UFRAME_RECEIVE, on_uframe_receive);
  core_set_endpoint_option(EP_SYSTEM, EP_ON_IFRAME_RECEIVE, on_iframe_unsolicited);
}

void sys_sequence_reset(void) {
  int fd;
  list_node_t *item;
  sys_cmd_handle_t *handle;

  // Abort any pending commands
  item = list_pop(&commands);
  while (item != NULL)
  {
    handle = SLIST_ENTRY(item, sys_cmd_handle_t, node_commands);

    if (handle->command->command_id != CMD_SYSTEM_INVALID)
    {
      log_warn("Dropping system command id #%d seq#%d", handle->command->command_id, handle->command_seq);
      sys_cmd_abort(handle, STATUS_ABORT);
    }

    // Command payload will be freed once we close the endpoint
    free(handle->command);
    free(handle);
    item = list_pop(&commands);
  }
  core_close_endpoint(EP_SYSTEM, false, true);
  sys_open_endpoint();

  log_info("[SYS] Requesting reset of sequence numbers on the remote");
  core_write(EP_SYSTEM, NULL, 0, FLAG_UFRAME_RESET_COMMAND);

  core_process_transmit_queue();
  const struct itimerspec timeout = {
      .it_interval = {.tv_sec = UFRAME_ACK_TIMEOUT_SECONDS, .tv_nsec = 0},
      .it_value = {.tv_sec = UFRAME_ACK_TIMEOUT_SECONDS, .tv_nsec = 0}};

  fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
  CHECK_ERROR(fd < 0);
  CHECK_ERROR(timerfd_settime(fd, 0, &timeout, NULL) < 0);

  handle = calloc(1, sizeof(sys_cmd_handle_t));
  CHECK_ERROR(handle == NULL);
  handle->retx_socket.fd = fd;
  handle->retx_socket.ep = EP_SYSTEM;
  handle->retx_socket.callback = handle_ack_timeout;

  hal_epoll_register((hal_epoll_event_data_t*)&handle->retx_socket);
  CHECK_ERROR(timerfd_settime(handle->retx_socket.fd, 0, &timeout, NULL) < 0);
  reset_sequence_ack = false;
}

void sys_set_last_status_callback(sys_unsolicited_status_callback_t callback)
{
  last_status_callback_list_t *item = calloc(1, sizeof(last_status_callback_list_t));
  CHECK_ERROR(item == NULL);
  item->callback = callback;
  list_push_back(&prop_last_status_callbacks, &item->node);
}

void sys_poll_ack(const void *frame_data)
{
  int timer_fd;
  sys_cmd_handle_t *handle;
  CHECK_ERROR(frame_data == NULL);
  sys_cmd_t *acked_command = (sys_cmd_t *)frame_data;

  SLIST_FOR_EACH_ENTRY(commands, handle, sys_cmd_handle_t, node_commands)
  {
    if (handle->command_seq != acked_command->command_seq) continue;
  
    log_info("[SYS] Secondary acknowledged command_id #%d command_seq #%d", handle->command->command_id, handle->command_seq);
    const struct itimerspec timeout = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                        .it_value = { .tv_sec = (long int)handle->retry_timeout_us / 1000000, 
                                        .tv_nsec = ((long int)handle->retry_timeout_us * 1000) % 1000000000 } };

    /* Setup timeout timer.*/
    if (handle->error_status == STATUS_OK)
    {
      timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);

      CHECK_ERROR(timer_fd < 0);
      CHECK_ERROR(timerfd_settime(timer_fd, 0, &timeout, NULL) < 0);

      /* Setup the timer in the primary_ezmeshd epoll set */
      handle->retx_socket.ep = EP_SYSTEM; //Irrelevant in this scenario
      handle->retx_socket.fd = timer_fd;
      handle->retx_socket.callback = on_timer_expired;

      hal_epoll_register((hal_epoll_event_data_t*)&handle->retx_socket);
    }
    else if (handle->error_status == STATUS_IN_PROGRESS) { CHECK_ERROR(timerfd_settime(handle->retx_socket.fd, 0, &timeout, NULL) < 0); }
    else { log_warn("Received ACK on a command that timed out or is processed.. ignoring"); }

    handle->acked = true;
    return; // Found the associated command
  }

  log_warn("Received a system poll ack for which no pending poll is registered");
}

void sys_cleanup(void)
{
  list_node_t *item;
  last_status_callback_list_t *cb_item;

  log_info("[Reset Seq] Server ezmeshd cleanup");

  item = list_pop(&prop_last_status_callbacks);
  while (item != NULL)
  {
    cb_item = SLIST_ENTRY(item, last_status_callback_list_t, node);
    free(cb_item);
    item = list_pop(&pending_commands);
  }
  core_close_endpoint(EP_SYSTEM, false, true);
}

void sys_init(void) {
  list_init(&commands);
  list_init(&retries);
  list_init(&pending_commands);
  list_init(&commands_in_error);
  list_init(&prop_last_status_callbacks);

  sys_open_endpoint();
}
