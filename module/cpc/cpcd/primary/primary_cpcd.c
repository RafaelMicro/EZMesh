/**
 * @file primary_cpcd.c
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
#include "utility/logs.h"
#include "utility/sleep.h"
#include "utility/utils.h"

#include "primary_cpcd.h"
#include "primary/epoll_port/epoll_port.h"
#include "primary/primary/primary.h"
#include "primary/cpcd/cpcd.h"
#include "primary/system/system.h"

#include "hal/hal_kill.h"

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

//=============================================================================
//                  Global Data Definition
//=============================================================================
bool ignore_reset_reason = true;
static char *primary_cpcd_secondary_app_version = NULL;
static uint8_t primary_cpcd_secondary_protocol_version;
static bool set_reset_mode_ack = false;
static bool reset_ack = false;
static bool secondary_cpc_version_received = false;
static bool secondary_app_version_received_or_not_available = false;
static bool secondary_bus_speed_received = false;
static bool failed_to_receive_secondary_bus_speed = false;
static bool reset_reason_received = false;
static bool capabilities_received = false;
static bool rx_capability_received = false;
static bool protocol_version_received = false;
static sys_reboot_mode_t pending_mode;
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
    E_WAIT_SECONDARY_CPC_VERSION,
    E_WAIT_SECONDARY_APP_VERSION,
    E_WAIT_PROTOCOL_VERSION,
    E_WAIT_SECONDARY_BUS_SPEED,
    E_RESET_SEQUENCE_DONE
} reset_sequence_state = E_SET_REBOOT_MODE;

static uint32_t rx_capability = 0;

static uint32_t capabilities = 0;


//=============================================================================
//                  Private Function Definition
//=============================================================================
static void __primary_unsolicited_cb(sys_status_t status);
static void *__primary_cpcd_loop(void *param);
static void __primary_reset_proc(void);
static void __primary_cpcd_cleanup(epoll_port_private_data_t *private_data);
static void __primary_set_reset_mode_callback(sys_command_handle_t *handle,
                                              property_id_t property_id,
                                              void *property_value,
                                              size_t property_length,
                                              status_t status);
static void __reset_cb(sys_command_handle_t *handle,
                       status_t status,
                       sys_status_t reset_status);


static void __primary_remove_socket_folder(const char *folder)
{
    struct dirent *next_file;
    char filepath[SIZEOF_MEMBER(struct sockaddr_un, sun_path)] = {};
    DIR *dir = opendir(folder);
    ERROR_SYSCALL_ON(dir == NULL);

    while ((next_file = readdir(dir)) != NULL)
    {
        strcpy(filepath, folder);
        strcat(filepath, "/");
        strcat(filepath, next_file->d_name);
        if (strstr(filepath, ".cpcd.sock") != NULL)
        {
            TRACE_PRIMARY("Removing %s", filepath);
            ERROR_SYSCALL_ON(remove(filepath) < 0);
        }
    }
    closedir(dir);
}

static void *__primary_cpcd_loop(void *param)
{
    (void)param;
    size_t event_i;
    struct epoll_event events[MAX_EPOLL_EVENTS] = {};
    size_t event_count;

    while (1)
    {
        __primary_reset_proc();
        cpcd_process_transmit_queue();

        event_count = epoll_port_wait_for_event(events, MAX_EPOLL_EVENTS);
        for (event_i = 0; event_i != (size_t)event_count; event_i++)
        {
            epoll_port_private_data_t *private_data = (epoll_port_private_data_t *)events[event_i].data.ptr;
            private_data->callback(private_data);
        }

        primary_process_pending_connections();
    }

    return NULL;
}

static void __primary_set_reset_mode_callback(sys_command_handle_t *handle,
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
    case STATUS_OK:

        if (property_length != sizeof(sys_status_t))
        {
            ERROR("Set reset mode reply length error");
        }

        ASSERT_ON(property_length != sizeof(sys_reboot_mode_t));

        set_reset_mode_ack = true;
        break;

    case STATUS_TIMEOUT:
    case STATUS_ABORT:
        PRINT_INFO("Failed to connect, secondary seems unresponsive");
        ignore_reset_reason = false;
        reset_sequence_state = E_SET_REBOOT_MODE;
        break;
    default:
        ASSERT("Unhandled __primary_set_reset_mode_callback status");
        break;
    }
}

static void __reset_cb(sys_command_handle_t *handle,
                       status_t status,
                       sys_status_t reset_status)
{
    (void)handle;

    switch (status)
    {
    case STATUS_IN_PROGRESS:
    case STATUS_OK:

        TRACE_RESET("Reset request response received : %d", reset_status);

        if (reset_status == STATUS_OK)
        {
            reset_ack = true;
        }
        break;

    case STATUS_TIMEOUT:
    case STATUS_ABORT:
        WARN("Failed to reset Secondary");
        ignore_reset_reason = false; // Don't ignore a secondary that resets
        reset_sequence_state = E_SET_REBOOT_MODE;
        break;
    default:
        ASSERT("Unhandled __reset_cb status");
        break;
    }
}

static void __primary_unsolicited_cb(sys_status_t status)
{
    int ret;
    extern char **argv_g;

    if (ignore_reset_reason)
    {
        ignore_reset_reason = false;
        TRACE_RESET("Ignored reset reason : %u", status);
        return;
    }

    if (status <= SYS_STATUS_RESET_WATCHDOG && status >= SYS_STATUS_RESET_POWER_ON)
    {
        TRACE_RESET("Received reset reason : %u", status);
        TRACE_RESET("Reset sequence: %u", reset_sequence_state);

        if (reset_sequence_state == E_WAIT_RESET_REASON)
        {
            reset_reason_received = true;
        } else
        {
            PRINT_INFO("Secondary has reset, reset the daemon.");

            /* Stop driver immediately */
            ret = hal_kill_signal_and_join();
            ERROR_ON(ret != 0);

            primary_notify_connected_libs_of_secondary_reset();

            for (uint8_t i = 1; i < 255; ++i)
            {
                primary_close_endpoint(i, false);
            }
            config_restart_cpcd(argv_g);
        }
    }
}

static void __primary_get_capabilities_callback(sys_command_handle_t *handle,
                                                property_id_t property_id,
                                                void *property_value,
                                                size_t property_length,
                                                status_t status)
{
    (void)handle;

    ERROR_ON(property_id != PROP_CAPABILITIES);
    ERROR_ON(status != STATUS_OK && status != STATUS_IN_PROGRESS);
    ERROR_ON(property_value == NULL || property_length != sizeof(uint32_t));

    capabilities = *((uint32_t *)property_value);

    if (capabilities & CPC_CAPABILITIES_PACKED_EP_MASK)
    {
        TRACE_RESET("Received capability : Packed endpoint");
    }

    if (capabilities & CPC_CAPABILITIES_UART_FLOW_CONTROL_MASK)
    {
        TRACE_RESET("Received capability : UART flow control");
    }

    capabilities_received = true;
}

static void __primary_get_rx_capability_callback(sys_command_handle_t *handle,
                                                 property_id_t property_id,
                                                 void *property_value,
                                                 size_t property_length,
                                                 status_t status)
{
    (void)handle;

    ERROR_ON(property_id != PROP_RX_CAPABILITY);
    ERROR_ON(status != STATUS_OK && status != STATUS_IN_PROGRESS);
    ERROR_ON(property_value == NULL || property_length != sizeof(uint16_t));

    TRACE_RESET("Received RX capability of %u bytes", *((uint16_t *)property_value));
    rx_capability = *((uint16_t *)property_value);
    rx_capability_received = true;
}

static void __primary_get_secondary_cpc_version_cb(sys_command_handle_t *handle,
                                                   property_id_t property_id,
                                                   void *property_value,
                                                   size_t property_length,
                                                   status_t status)
{
    (void)handle;

    uint32_t version[3];
    memcpy(version, property_value, 3 * sizeof(uint32_t));

    if ((property_id != PROP_SECONDARY_CPC_VERSION)
        || (status != STATUS_OK && status != STATUS_IN_PROGRESS)
        || (property_value == NULL || property_length != 3 * sizeof(uint32_t)))
    {
        ERROR("Cannot get Secondary CPC version (obsolete RCP firmware?)");
    }

    PRINT_INFO("Secondary CPC v%d.%d.%d", version[0], version[1], version[2]);
    secondary_cpc_version_received = true;
}

static void __primary_get_secondary_app_version_cb(sys_command_handle_t *handle,
                                                   property_id_t property_id,
                                                   void *property_value,
                                                   size_t property_length,
                                                   status_t status)
{
    (void)handle;

    if ((status == STATUS_OK || status == STATUS_IN_PROGRESS) && property_id == PROP_SECONDARY_APP_VERSION)
    {
        ERROR_ON(property_value == NULL);
        ERROR_ON(property_length == 0);

        const char *version = (const char *)property_value;

        ASSERT_ON(primary_cpcd_secondary_app_version);

        primary_cpcd_secondary_app_version = calloc_port(property_length);
        ERROR_SYSCALL_ON(primary_cpcd_secondary_app_version == NULL);

        strncpy(primary_cpcd_secondary_app_version, version, property_length - 1);
        primary_cpcd_secondary_app_version[property_length - 1] = '\0';
        PRINT_INFO("Secondary APP v%s", primary_cpcd_secondary_app_version);
    } else
    {
        WARN("Cannot get Secondary APP version (obsolete RCP firmware?)");
    }

    secondary_app_version_received_or_not_available = true;
}

static void __primary_get_secondary_bus_speed_cb(sys_command_handle_t *handle,
                                                 property_id_t property_id,
                                                 void *property_value,
                                                 size_t property_length,
                                                 status_t status)
{
    (void)handle;
    uint32_t bus_speed = 0;

    if ((status == STATUS_OK || status == STATUS_IN_PROGRESS) && property_id == PROP_BUS_SPEED_VALUE)
    {
        ERROR_ON(property_value == NULL);
        ERROR_ON(property_length != sizeof(uint32_t));

        memcpy(&bus_speed, property_value, sizeof(uint32_t));

        PRINT_INFO("Secondary bus speed is %d", bus_speed);

        if (config.bus == UART && bus_speed != config.uart_baudrate)
        {
            ERROR("Baudrate mismatch (%d) on the daemon versus (%d) on the secondary",
                  config.uart_baudrate, bus_speed);
        }

        secondary_bus_speed_received = true;
    } else
    {
        WARN("Could not obtain the secondary's bus speed");
        failed_to_receive_secondary_bus_speed = true;
    }
}

static void __primary_get_protocol_version_cb(sys_command_handle_t *handle,
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
        ERROR("Cannot get Secondary Protocol version (obsolete RCP firmware?)");
    }

    primary_cpcd_secondary_protocol_version = *version;
    PRINT_INFO("Secondary Protocol v%d", primary_cpcd_secondary_protocol_version);

    protocol_version_received = true;
}

static void __primary_capabilities_check(void)
{
    if ((config.bus == UART) && (config.uart_hardflow != (bool)(capabilities & CPC_CAPABILITIES_UART_FLOW_CONTROL_MASK)))
    {
        ERROR("UART flow control configuration mismatch between CPCd (%s) and Secondary (%s)",
              config.uart_hardflow ? "enabled" : "disabled",
              (bool)(capabilities & CPC_CAPABILITIES_UART_FLOW_CONTROL_MASK) ? "enabled" : "disabled");
    }
}

static void __primary_protocol_version_check(void)
{
    if (primary_cpcd_secondary_protocol_version != PROTOCOL_VERSION)
    {
        ERROR("Secondary Protocol v%d doesn't match CPCd Protocol v%d",
              primary_cpcd_secondary_protocol_version, PROTOCOL_VERSION);
    }
}

static void __primary_application_version_check(void)
{
    if (config.application_version_validation && primary_cpcd_secondary_app_version)
    {
        if (strcmp(primary_cpcd_secondary_app_version,
                   config.application_version_validation) != 0)
        {
            ERROR("Secondary APP v%s doesn't match the provided APP v%s",
                  primary_cpcd_secondary_app_version, config.application_version_validation);
        }
    }
}

static void __primary_reset_proc(void)
{
    switch (reset_sequence_state)
    {
    case E_RESET_SEQUENCE_DONE:
        return;

    case E_SET_REBOOT_MODE:
        PRINT_INFO("Connecting to Secondary...");

        /* Send a request to the secondary to set the reboot mode to 'application' */
        {
            const sys_reboot_mode_t reboot_mode = REBOOT_APPLICATION;

            pending_mode = reboot_mode;

            sys_cmd_property_set(__primary_set_reset_mode_callback,
                                 1,
                                 2000000,
                                 PROP_BOOTLOADER_REBOOT_MODE,
                                 &reboot_mode,
                                 sizeof(reboot_mode),
                                 true);

            reset_sequence_state = E_WAIT_REBOOT_MODE_ACK;

            TRACE_RESET("Reboot mode sent");
        }
        break;

    case E_WAIT_REBOOT_MODE_ACK:

        if (set_reset_mode_ack == true)
        {
            /* Now, request a reset  */
            sys_cmd_reboot(__reset_cb, 5, 100000);

            reset_sequence_state = E_WAIT_RESET_ACK;

            /* Set it back to false because it will be used for the bootloader reboot sequence */
            set_reset_mode_ack = false;

            TRACE_RESET("Reboot mode reply received, reset request sent");
        }
        break;

    case E_WAIT_RESET_ACK:

        if (reset_ack == true)
        {
            reset_sequence_state = E_WAIT_RESET_REASON;

            /* Set it back to false because it will be used for the bootloader reboot sequence */
            reset_ack = false;

            TRACE_RESET("Reset request acknowledged");
        }
        break;

    case E_WAIT_RESET_REASON:
        TRACE_RESET("Waiting for reset reason");
        if (reset_reason_received)
        {
            TRACE_RESET("Reset reason received");
            reset_sequence_state = E_WAIT_RX_CAPABILITY;
            sys_cmd_property_get(__primary_get_rx_capability_callback,
                                 PROP_RX_CAPABILITY,
                                 5,
                                 100000,
                                 true);
        }
        break;

    case E_WAIT_RX_CAPABILITY:
        if (rx_capability_received)
        {
            TRACE_RESET("Get RX capability");
            PRINT_INFO("Connected to Secondary");
            reset_sequence_state = E_WAIT_PROTOCOL_VERSION;
            sys_cmd_property_get(__primary_get_protocol_version_cb,
                                 PROP_PROTOCOL_VERSION,
                                 5,
                                 100000,
                                 true);
        }
        break;

    case E_WAIT_PROTOCOL_VERSION:
        if (protocol_version_received)
        {
            TRACE_RESET("Get Protocol version");

            __primary_protocol_version_check();
            reset_sequence_state = E_WAIT_CAPABILITIES;
            sys_cmd_property_get(__primary_get_capabilities_callback,
                                 PROP_CAPABILITIES,
                                 5,
                                 100000,
                                 true);
        }
        break;

    case E_WAIT_CAPABILITIES:
        if (capabilities_received)
        {
            TRACE_RESET("Get Capabilites");

            __primary_capabilities_check();

            reset_sequence_state = E_WAIT_SECONDARY_BUS_SPEED;
            sys_cmd_property_get(__primary_get_secondary_bus_speed_cb,
                                 PROP_BUS_SPEED_VALUE,
                                 5,
                                 100000,
                                 true);
        }
        break;


    case E_WAIT_SECONDARY_CPC_VERSION:
        if (secondary_cpc_version_received)
        {
            TRACE_RESET("Get Secondary CPC version");

            reset_sequence_state = E_WAIT_SECONDARY_APP_VERSION;

            sys_cmd_property_get(__primary_get_secondary_app_version_cb,
                                 PROP_SECONDARY_APP_VERSION,
                                 5,
                                 100000,
                                 true);
        }
        break;

    case E_WAIT_SECONDARY_BUS_SPEED:
        if (secondary_bus_speed_received || failed_to_receive_secondary_bus_speed)
        {
            reset_sequence_state = E_WAIT_SECONDARY_CPC_VERSION;
            sys_cmd_property_get(__primary_get_secondary_cpc_version_cb,
                                 PROP_SECONDARY_CPC_VERSION,
                                 5,
                                 100000,
                                 true);
        }
        break;

    case E_WAIT_SECONDARY_APP_VERSION:
        if (secondary_app_version_received_or_not_available)
        {
            if (primary_cpcd_secondary_app_version)
            {
                TRACE_RESET("Get Secondary APP version");
            }

            if (config.print_secondary_versions_and_exit)
            {
                sleep_s(2);
                exit(EXIT_SUCCESS);
            }
            __primary_application_version_check();

            reset_sequence_state = E_RESET_SEQUENCE_DONE;

            primary_init();
            PRINT_INFO("Daemon startup was successful. Waiting for client connections");
        }
        break;

    default:
        ASSERT("Impossible state");
        break;
    }
}

static void __primary_cpcd_cleanup(epoll_port_private_data_t *private_data)
{
    (void)private_data;

    PRINT_INFO("Server cpcd cleanup");

    sys_cleanup();

    pthread_exit(0);
}

bool primary_cpcd_reset_sequence_in_progress(void)
{
    return reset_sequence_state != E_RESET_SEQUENCE_DONE;
}


uint32_t primary_cpcd_get_secondary_rx_capability(void)
{
    ERROR_ON(rx_capability == 0); // Need to go through reset sequence first
    return rx_capability;
}

void primary_cpcd_kill_signal(void)
{
    ssize_t ret;
    const uint64_t event_value = 1; //doesn't matter what it is

    if (kill_eventfd == -1)
    {
        return;
    }

    ret = write(kill_eventfd, &event_value, sizeof(event_value));
    ERROR_ON(ret != sizeof(event_value));
}

pthread_t primary_cpcd_init(int fd_socket_driver_cpcd, int fd_socket_driver_cpcd_notify)
{
    char *socket_folder = NULL;
    struct stat sb = { 0 };
    pthread_t primary_cpcd_thread = { 0 };
    int ret = 0;

    cpcd_init(fd_socket_driver_cpcd, fd_socket_driver_cpcd_notify);

    sys_init();

    sys_register_unsolicited_prop_last_status_callback(__primary_unsolicited_cb);

    /* Create the string {socket_folder}/cpcd/{instance_name} */
    {
        const size_t socket_folder_string_size = strlen(config.socket_folder) + strlen("/cpcd/") + strlen(config.instance_name) + sizeof(char);
        socket_folder = (char *)calloc_port(socket_folder_string_size);
        ERROR_ON(socket_folder == NULL);

        ret = snprintf(socket_folder, socket_folder_string_size, "%s/cpcd/%s", config.socket_folder, config.instance_name);
        ERROR_ON(ret < 0 || (size_t)ret >= socket_folder_string_size);
    }

    /* Check if the socket folder exists */
    if (stat(socket_folder, &sb) == 0 && S_ISDIR(sb.st_mode))
    {
        TRACE_PRIMARY("Remove socket folder %s", socket_folder);
        __primary_remove_socket_folder(socket_folder);
    } else
    {
        TRACE_PRIMARY("Remove socket folder %s", socket_folder);
        recursive_mkdir(socket_folder, strlen(socket_folder), S_IRWXU | S_IRWXG | S_ISVTX);
        ret = access(socket_folder, W_OK);
        ERROR_SYSCALL_ON(ret < 0);
    }

    free(socket_folder);

    kill_eventfd = eventfd(0, EFD_CLOEXEC);
    ERROR_ON(kill_eventfd == -1);

    static epoll_port_private_data_t private_data;

    private_data.callback = __primary_cpcd_cleanup;
    private_data.file_descriptor = kill_eventfd; /* Irrelevant here */
    private_data.endpoint_number = 0; /* Irrelevant here */

    epoll_port_register(&private_data);

    /* create primary_cpcd thread */
    ret = pthread_create(&primary_cpcd_thread, NULL, __primary_cpcd_loop, NULL);
    ERROR_ON(ret != 0);

    ret = pthread_setname_np(primary_cpcd_thread, "primary_cpcd");
    ERROR_ON(ret != 0);

    return primary_cpcd_thread;
}

char *primary_cpcd_get_secondary_app_version(void)
{
    ASSERT_ON(primary_cpcd_secondary_app_version == NULL);
    return primary_cpcd_secondary_app_version;
}
