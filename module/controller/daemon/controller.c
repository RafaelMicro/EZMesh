/**
 * @file controller.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-10-30
 *
 *
 */
#define _GNU_SOURCE

#include <pthread.h>

#include <stdio.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/un.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "utility/config.h"
#include "utility/log.h"
#include "utility/utility.h"

#include "primary/primary.h"
#include "daemon/hdlc/core.h"

#include "host/hal_sleep.h"
#include "host/hal_epoll.h"
#include "host/hal_kill.h"
#include "host/hal_uart.h"
#include "host/hal_memory.h"

#include "controller.h"

#include "version.h"

//=============================================================================
//                  Constant Definition
//=============================================================================

//=============================================================================
//                  Macro Definition
//=============================================================================

//=============================================================================
//                  Structure Definition
//=============================================================================
#define MAX_EPOLL_EVENTS 1
// #define THREAD_SLEEP_NS  2000000L

//=============================================================================
//                  Global Data Definition
//=============================================================================
bool ignore_reset_reason = true;
static char *controller_agent_app_version = NULL;
static size_t controller_agent_app_version_len = 0;
static uint8_t controller_agent_protocol_version;
static bool set_reset_mode_ack = false;
static bool reset_ack = false;
static bool agent_ezmesh_version_received = false;
static bool agent_app_version_received_or_not_available = false;
static bool agent_bus_speed_received = false;
static bool failed_to_receive_agent_bus_speed = false;
static bool reset_reason_received = false;
static bool capabilities_received = false;
static bool rx_capability_received = false;
static bool protocol_version_received = false;
static bool set_rf_cert_band_ack = false;
static reboot_mode_t pending_mode;
static int kill_eventfd = -1;
static enum
{
    E_SET_REBOOT_MODE,
    E_WAIT_REBOOT_MODE_ACK,
    E_WAIT_RESET_ACK,
    E_WAIT_RESET_REASON,
    E_WAIT_CAPABILITIES,
    E_WAIT_RX_CAPABILITY,
    E_WAIT_BOOTLOADER_INFO,
    E_WAIT_SECONDARY_EZMESH_VERSION,
    E_WAIT_SECONDARY_APP_VERSION,
    E_WAIT_PROTOCOL_VERSION,
    E_WAIT_SECONDARY_BUS_SPEED,
    E_WAIT_RF_CERT_BAND,
    E_RESET_SEQUENCE_DONE
} reset_sequence_state = E_SET_REBOOT_MODE;

static uint32_t rx_capability = 0;
static uint32_t capabilities = 0;


//=============================================================================
//                  Private Function Definition
//=============================================================================
static void __controller_reset_proc(void);

static status_t state_passer(sys_status_t val) { return (val == SYS_STATUS_OK)? STATUS_OK : STATUS_FAIL; }

static void __controller_remove_socket_folder(const char *folder)
{
    struct dirent *next_file = NULL;
    char filepath[(sizeof(((struct sockaddr_un *)0)->sun_path))] = {};
    DIR *dir = NULL;

    dir = opendir(folder);
    CHECK_ERROR(dir == NULL);

    while ((next_file = readdir(dir)) != NULL)
    {
        strcpy(filepath, folder);
        strcat(filepath, "/");
        strcat(filepath, next_file->d_name);
        if (strstr(filepath, ".sock") != NULL)
        {
            log_info("[Controller] Removing %s", filepath);
            CHECK_ERROR(remove(filepath) < 0);
        }
    }
    closedir(dir);
}

static void *__controller_loop(void *param)
{
    struct epoll_event events[MAX_EPOLL_EVENTS] = {};
    size_t cnt = 0;

    (void)param;

    while (1)
    {
        __controller_reset_proc();
        core_process_transmit_queue();

        cnt = hal_epoll_wait_for_event(events, MAX_EPOLL_EVENTS);
        for (size_t i = 0; i < (size_t)cnt; i++)
        {
            hal_epoll_event_data_t *event_data = (hal_epoll_event_data_t *)events[i].data.ptr;
            // log_info("EPOLL EVENT: fd 0x%02x, EP %d, cb: %p", event_data->file_descriptor, event_data->endpoint_number, event_data->callback);
            if(event_data->callback != NULL) event_data->callback(event_data);
        }
        ctl_proc_conn();
        // nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
    }

    return NULL;
}

static void __controller_set_reset_mode_callback(sys_cmd_handle_t *handle,
                                              property_id_t property_id,
                                              void *property_value,
                                              size_t property_length,
                                              status_t status)
{
    (void)handle;
    (void)property_id;
    (void)property_value;

    switch (status)
    {
    case STATUS_IN_PROGRESS:
    case STATUS_OK:{
        if (property_length != sizeof(sys_status_t)) log_error("Set reset mode reply length error");
        CHECK_FATAL(property_length != sizeof(reboot_mode_t));
        set_reset_mode_ack = true;
        break;}

    case STATUS_TIMEOUT:
    case STATUS_ABORT:{
        log_info("Failed to connect, agent seems unresponsive");
        ignore_reset_reason = false;
        reset_sequence_state = E_SET_REBOOT_MODE;
        //hal_uart_change_baudrate();
        break;}
    default:{
        FATAL("Unhandled __controller_set_reset_mode_callback status");
        break;}
    }
}

static void __controller_reset_callback(sys_cmd_handle_t *handle,
                                  status_t status,
                                  sys_status_t reset_status)
{
    (void)handle;

    switch (status)
    {
    case STATUS_IN_PROGRESS:
    case STATUS_OK:{
        log_info("[Reset Seq] Reset request response received : %d", reset_status);
        if (state_passer(reset_status) == STATUS_OK) reset_ack = true;
        break;}

    case STATUS_TIMEOUT:
    case STATUS_ABORT:{
        log_warn("Failed to reset Agent");
        ignore_reset_reason = false; // Don't ignore a agent that resets
        reset_sequence_state = E_SET_REBOOT_MODE;
        break;}
    default:{
        FATAL("Unhandled __controller_reset_callback status");
        break;}
    }
}

static void __controller_unsolicited_callback(sys_status_t status)
{
    int ret;
    extern char **argv_g;

    if (ignore_reset_reason)
    {
        ignore_reset_reason = false;
        log_info("[Reset Seq] Ignored reset reason : %u", status);
        return;
    }

    if (status <= SYS_STATUS_RESET_WATCHDOG && status >= SYS_STATUS_RESET_POWER_ON)
    {
        log_info("[Reset Seq] Received reset reason : %u", status);
        log_info("[Reset Seq] Reset sequence: %u", reset_sequence_state);

        if (reset_sequence_state == E_WAIT_RESET_REASON) reset_reason_received = true;
        else
        {
            log_info("Agent has reset, reset the daemon.");

            /* Stop driver immediately */
            ret = hal_kill_signal_and_join();
            CHECK_ERROR(ret != 0);
            ctl_notify_HW_reset();
            for (uint8_t i = 1; i < 255; ++i) EP_close(i, false);
            config_restart(argv_g);
        }
    }
}

static void __controller_get_capabilities_callback(sys_cmd_handle_t *handle,
                                                property_id_t property_id,
                                                void *property_value,
                                                size_t property_length,
                                                status_t status)
{
    (void)handle;

    CHECK_ERROR(property_id != PROP_CAPABILITIES);
    CHECK_ERROR(status != STATUS_OK && status != STATUS_IN_PROGRESS);
    CHECK_ERROR(property_value == NULL || property_length != sizeof(uint32_t));

    capabilities = *((uint32_t *)property_value);

    if (capabilities & CAPABILITIES_PACKED_EP_MASK) log_info("[Reset Seq] Received capability : Packed endpoint");
    if (capabilities & CAPABILITIES_UART_FLOW_CONTROL_MASK) log_info("[Reset Seq] Received capability : UART flow control");
    capabilities_received = true;
}

static void __controller_get_rx_capability_callback(sys_cmd_handle_t *handle,
                                                 property_id_t property_id,
                                                 void *property_value,
                                                 size_t property_length,
                                                 status_t status)
{
    (void)handle;

    CHECK_ERROR(property_id != PROP_RX_CAPABILITY);
    CHECK_ERROR(status != STATUS_OK && status != STATUS_IN_PROGRESS);
    CHECK_ERROR(property_value == NULL || property_length != sizeof(uint16_t));

    log_info("[Reset Seq] Received RX capability of %u bytes", *((uint16_t *)property_value));
    rx_capability = *((uint16_t *)property_value);
    rx_capability_received = true;
}

static void __controller_get_agent_ezmesh_version_callback(sys_cmd_handle_t *handle,
                                                   property_id_t property_id,
                                                   void *property_value,
                                                   size_t property_length,
                                                   status_t status)
{
    (void)handle;
    uint32_t *version = property_value;

    if ((property_id != PROP_SECONDARY_EZMESH_VERSION)
        || (status != STATUS_OK && status != STATUS_IN_PROGRESS)
        || (property_value == NULL || property_length != 3 * sizeof(uint32_t)))
    {
        log_error("Cannot get Agent EZMESH version (obsolete RCP firmware?)");
    }

    log_info("[Controller] Agent EZMESH v%d.%d.%d", version[0], version[1], version[2]);
    agent_ezmesh_version_received = true;
}

static void __controller_get_agent_app_version_callback(sys_cmd_handle_t *handle,
                                                   property_id_t property_id,
                                                   void *property_value,
                                                   size_t property_length,
                                                   status_t status)
{
    (void)handle;

    if ((status == STATUS_OK || status == STATUS_IN_PROGRESS) && property_id == PROP_SECONDARY_APP_VERSION)
    {
        CHECK_ERROR(property_value == NULL);
        CHECK_ERROR(property_length == 0);

        const char *version = (const char *)property_value;

        CHECK_FATAL(controller_agent_app_version);

        controller_agent_app_version = (char *)HAL_MEM_ALLOC(property_length);
        CHECK_ERROR(controller_agent_app_version == NULL);
        controller_agent_app_version_len = property_length;

        strncpy(controller_agent_app_version, version, property_length - 1);
        controller_agent_app_version[property_length - 1] = '\0';
        log_info("[Controller] Agent APP v%s", controller_agent_app_version);
    } 
    else log_warn("Cannot get Agent APP version (obsolete RCP firmware?)");

    agent_app_version_received_or_not_available = true;
}

static void __controller_get_agent_bus_speed_callback(sys_cmd_handle_t *handle,
                                                 property_id_t property_id,
                                                 void *property_value,
                                                 size_t property_length,
                                                 status_t status)
{
    (void)handle;
    uint32_t bus_speed = 0;

    if ((status == STATUS_OK || status == STATUS_IN_PROGRESS) && property_id == PROP_BUS_SPEED_VALUE)
    {
        CHECK_ERROR(property_value == NULL);
        CHECK_ERROR(property_length != sizeof(uint32_t));

        memcpy(&bus_speed, property_value, sizeof(uint32_t));

        log_info("[Controller] Agent bus speed is %d", bus_speed);

        if (config.ep_hw.type == EP_TYPE_UART && bus_speed != config.ep_hw.baudrate)
        {
            log_error("Baudrate mismatch (%d) on the daemon versus (%d) on the agent", config.ep_hw.baudrate, bus_speed);
        }

        agent_bus_speed_received = true;
    } 
    else
    {
        log_warn("Could not obtain the agent's bus speed");
        failed_to_receive_agent_bus_speed = true;
    }
}

static void __controller_get_protocol_version_callback(sys_cmd_handle_t *handle,
                                              property_id_t property_id,
                                              void *property_value,
                                              size_t property_length,
                                              status_t status)
{
    (void)handle;

    uint8_t *version = (uint8_t *)property_value;

    if ((property_id != PROP_PROTOCOL_VERSION)
        || (status != STATUS_OK && status != STATUS_IN_PROGRESS)
        || (property_value == NULL || property_length != sizeof(uint8_t)))
    {
        log_error("Cannot get Agent Protocol version (obsolete RCP firmware?)");
    }

    controller_agent_protocol_version = *version;
    log_info("[Controller] Agent Protocol v%d", controller_agent_protocol_version);

    protocol_version_received = true;
}

static void __controller_set_rf_cert_band_callback(sys_cmd_handle_t *handle,
                                              property_id_t property_id,
                                              void *property_value,
                                              size_t property_length,
                                              status_t status)
{
    (void)handle;
    (void)property_id;
    (void)property_value;
    (void)property_length;

    switch (status)
    {
    case STATUS_IN_PROGRESS:
    case STATUS_OK:{
        set_rf_cert_band_ack = true;
        break;}

    case STATUS_TIMEOUT:
    case STATUS_ABORT:{
        log_info("Failed to connect, agent seems unresponsive");
        ignore_reset_reason = false;
        reset_sequence_state = E_SET_REBOOT_MODE;
        break;}
    default:{
        FATAL("Unhandled __controller_set_rf_cert_band_callback status");
        break;}
    }
}

static void __controller_capabilities_check(void)
{
    if ((config.ep_hw.type == EP_TYPE_UART) && (config.ep_hw.flowcontrol != (bool)(capabilities & CAPABILITIES_UART_FLOW_CONTROL_MASK)))
    {
        log_error("UART flow control configuration mismatch between EZMESHd (%s) and Agent (%s)",
              config.ep_hw.flowcontrol ? "enabled" : "disabled",
              (bool)(capabilities & CAPABILITIES_UART_FLOW_CONTROL_MASK) ? "enabled" : "disabled");
    }
}

static void __controller_protocol_version_check(void)
{
    if (controller_agent_protocol_version != PROTOCOL_VERSION)
    {
        log_error("Agent Protocol v%d doesn't match EZMESHd Protocol v%d",
            controller_agent_protocol_version, PROTOCOL_VERSION);
    }
}

static void __controller_reset_proc(void)
{
    switch (reset_sequence_state)
    {
    case E_RESET_SEQUENCE_DONE:{
        return;}

    case E_SET_REBOOT_MODE:{
        log_info("[Controller] Connecting to Agent...");
        const reboot_mode_t reboot_mode = REBOOT_APPLICATION;
        pending_mode = reboot_mode;
        sys_param_set(__controller_set_reset_mode_callback,
                      1, 2000000, PROP_BOOTLOADER_REBOOT_MODE,
                      &reboot_mode, sizeof(reboot_mode), true);
        reset_sequence_state = E_WAIT_REBOOT_MODE_ACK;
        log_info("[Reset Seq] Reboot mode sent");
        break;}

    case E_WAIT_REBOOT_MODE_ACK:{
        if (set_reset_mode_ack)
        {
            sys_reboot(__controller_reset_callback, 5, 100000);
            reset_sequence_state = E_WAIT_RESET_ACK;
            set_reset_mode_ack = false;
            log_info("[Reset Seq] Reboot mode reply received, reset request sent");
        }
        break;}

    case E_WAIT_RESET_ACK:{
        if (reset_ack == true)
        {
            reset_sequence_state = E_WAIT_RESET_REASON;
            reset_ack = false;
            log_info("[Reset Seq] Reset request acknowledged");
        }
        break;}

    case E_WAIT_RESET_REASON:{
        log_info("[Reset Seq] Waiting for reset reason");
        if (reset_reason_received)
        {
            log_info("[Reset Seq] Reset reason received");
            reset_sequence_state = E_WAIT_RX_CAPABILITY;
            sys_param_get(__controller_get_rx_capability_callback,
                           PROP_RX_CAPABILITY, 5, 100000, true);
        }
        break;}

    case E_WAIT_RX_CAPABILITY:{
        if (rx_capability_received)
        {
            log_info("[Reset Seq] Get RX capability");
            log_info("[Controller] Connected to Agent");
            reset_sequence_state = E_WAIT_PROTOCOL_VERSION;
            sys_param_get(__controller_get_protocol_version_callback,
                          PROP_PROTOCOL_VERSION, 5, 100000, true);
        }
        break;}

    case E_WAIT_PROTOCOL_VERSION:{
        if (protocol_version_received)
        {
            log_info("[Reset Seq] Get Protocol version");
            __controller_protocol_version_check();
            reset_sequence_state = E_WAIT_CAPABILITIES;
            sys_param_get(__controller_get_capabilities_callback,
                          PROP_CAPABILITIES, 5, 100000, true);
        }
        break;}

    case E_WAIT_CAPABILITIES:{
        if (capabilities_received)
        {
            log_info("[Reset Seq] Get Capabilites");
            __controller_capabilities_check();
            reset_sequence_state = E_WAIT_SECONDARY_BUS_SPEED;
            sys_param_get(__controller_get_agent_bus_speed_callback,
                          PROP_BUS_SPEED_VALUE, 5, 100000, true);
        }
        break;}

    case E_WAIT_SECONDARY_EZMESH_VERSION:{
        uint32_t rf_cert_band = config.ep_hw.rf_cert_band;
        if (agent_ezmesh_version_received)
        {
            if(rf_cert_band != 0)
            {
                log_info("[Reset Seq] Set RF certificate band setting");
                reset_sequence_state = E_WAIT_RF_CERT_BAND;
                sys_param_set(__controller_set_rf_cert_band_callback,
                            1, 2000000, PROP_RF_CERT_BAND,
                            &rf_cert_band, sizeof(rf_cert_band), true);
            }
            else
            {
                log_info("[Reset Seq] Get Agent EZMESH version");
                reset_sequence_state = E_WAIT_SECONDARY_APP_VERSION;
                sys_param_get(__controller_get_agent_app_version_callback,
                              PROP_SECONDARY_APP_VERSION, 5, 100000, true);                
            }
        }
        break;}

    case E_WAIT_RF_CERT_BAND:{
        if(set_rf_cert_band_ack)
        {
            log_info("[Reset Seq] Get Agent EZMESH version");
            reset_sequence_state = E_WAIT_SECONDARY_APP_VERSION;
            sys_param_get(__controller_get_agent_app_version_callback,
                          PROP_SECONDARY_APP_VERSION, 5, 100000, true);            
        }
        break;}

    case E_WAIT_SECONDARY_BUS_SPEED:{
        if (agent_bus_speed_received || failed_to_receive_agent_bus_speed)
        {
            reset_sequence_state = E_WAIT_SECONDARY_EZMESH_VERSION;
            sys_param_get(__controller_get_agent_ezmesh_version_callback,
                          PROP_SECONDARY_EZMESH_VERSION, 5, 100000, true);
        }
        break;}

    case E_WAIT_SECONDARY_APP_VERSION:{
        if (agent_app_version_received_or_not_available)
        {
            reset_sequence_state = E_RESET_SEQUENCE_DONE;
            ctl_init();
            log_info("Daemon startup was successful. Waiting for client connections");
        }
        break;}

    default:{
        FATAL("Impossible state");
        break;}
    }
}

static void __controller_cleanup(hal_epoll_event_data_t *event_data)
{
    (void)event_data;

    log_info("Server ezmeshd cleanup");
    sys_cleanup();
    pthread_exit(0);
}

bool controller_reset_sequence_in_progress(void) { return reset_sequence_state != E_RESET_SEQUENCE_DONE; }


uint32_t controller_get_agent_rx_capability(void)
{
    CHECK_ERROR(rx_capability == 0);
    return rx_capability;
}

void controller_kill_signal(void)
{
    ssize_t ret = 0;
    const uint64_t event_value = 1;

    if (kill_eventfd == -1) return;

    ret = write(kill_eventfd, &event_value, sizeof(event_value));
    CHECK_ERROR(ret != sizeof(event_value));
}

pthread_t controller_init(int fd_socket_driver_ezmeshd, int fd_socket_driver_ezmeshd_notify)
{
    char *socket_folder = NULL;
    struct stat sb = { 0 };
    pthread_t controller_thread = { 0 };
    int ret = 0;
    static hal_epoll_event_data_t event_data = {0};

    core_init(fd_socket_driver_ezmeshd, fd_socket_driver_ezmeshd_notify);
    sys_init();
    sys_set_last_status_callback(__controller_unsolicited_callback);

    const size_t path_len = strlen(config.ep_hw.socket_path) + strlen("/") + strlen(config.ep_hw.name) + sizeof(char);
  
    socket_folder = (char *)HAL_MEM_ALLOC(path_len);
    CHECK_ERROR(socket_folder == NULL);

    ret = snprintf(socket_folder, path_len, "%s/%s", config.ep_hw.socket_path, config.ep_hw.name);
    CHECK_ERROR(ret < 0 || (size_t)ret >= path_len);

    if (stat(socket_folder, &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        log_info("[Controller] Remove socket folder %s", socket_folder);
        __controller_remove_socket_folder(socket_folder);
    } 
    else
    {
        log_info("[Controller] Remove socket folder %s", socket_folder);
        recursive_mkdir(socket_folder, strlen(socket_folder), S_IRWXU | S_IRWXG | S_ISVTX);
        ret = access(socket_folder, W_OK);
        CHECK_ERROR(ret < 0);
    }

    HAL_MEM_FREE(&socket_folder);

    kill_eventfd = eventfd(0, EFD_CLOEXEC);
    CHECK_ERROR(kill_eventfd == -1);

    event_data.callback = __controller_cleanup;
    event_data.file_descriptor = kill_eventfd;
    event_data.endpoint_number = 0;
    hal_epoll_register(&event_data);

    CHECK_ERROR(pthread_create(&controller_thread, NULL, __controller_loop, NULL) != 0);
    CHECK_ERROR(pthread_setname_np(controller_thread, "primary_ezmeshd") != 0);
    return controller_thread;
}

char *controller_get_agent_app_version(size_t *len)
{
    CHECK_FATAL(controller_agent_app_version == NULL);
    *len = controller_agent_app_version_len;
    return controller_agent_app_version;
}