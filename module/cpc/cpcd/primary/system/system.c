

#include <stdlib.h>
#include <string.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "primary/cpcd/hdlc.h"
#include "libcpc.h"
#include "system.h"

#include "utility/logs.h"
#include "utility/utils.h"
#include "primary/system/callbacks.h"
#include "primary/primary/primary.h"
#include "primary/cpcd/cpcd.h"
#include "primary/primary_cpcd.h"
#include "utility/utils.h"


#define UFRAME_ACK_TIMEOUT_SECONDS 2
#define SIZEOF_SYSTEM_COMMAND(command) (sizeof(sys_cmd_t) + command->length)
#define EP_CLOSE_RETRIES 5
#define EP_CLOSE_RETRY_TIMEOUT 100000

static slist_node_t *pending_commands;
static slist_node_t *commands;
static slist_node_t *retries;
static slist_node_t *commands_in_error;

static bool received_remote_sequence_numbers_reset_ack = true;

extern bool ignore_reset_reason;

typedef struct
{
    slist_node_t node;
    sys_unsolicited_status_callback_t callback;
}last_status_callback_list_t;

static slist_node_t *prop_last_status_callbacks;

static void on_iframe_unsolicited(uint8_t endpoint_id, const void *data, size_t data_len);
static void on_uframe_receive(uint8_t endpoint_id, const void *data, size_t data_len);
static void on_reply(uint8_t endpoint_id, void *arg, void *answer, uint32_t answer_lenght);
static void on_timer_expired(epoll_port_private_data_t *private_data);
static void write_command(sys_command_handle_t *command_handle);

static void sys_cmd_abort(sys_command_handle_t *command_handle, status_t error);

static void sys_open_endpoint(void)
{
    cpcd_open_endpoint(CPC_EP_SYSTEM, OPEN_EP_FLAG_UFRAME_ENABLE, 1);

    cpcd_set_endpoint_option(CPC_EP_SYSTEM, EP_ON_FINAL, on_reply);

    cpcd_set_endpoint_option(CPC_EP_SYSTEM, EP_ON_UFRAME_RECEIVE, on_uframe_receive);

    cpcd_set_endpoint_option(CPC_EP_SYSTEM, EP_ON_IFRAME_RECEIVE, on_iframe_unsolicited);
}

static void sys_init_command_handle(sys_command_handle_t *command_handle,
                                    void *on_final,
                                    uint8_t retry_count,
                                    uint32_t retry_timeout_us,
                                    bool is_uframe)
{
    static uint8_t next_command_seq = 0;

    ASSERT_ON(command_handle == NULL);
    ASSERT_ON(on_final == NULL);
    command_handle->acked = false;
    command_handle->error_status = STATUS_OK;

    command_handle->on_final = on_final;
    command_handle->retry_count = retry_count;
    command_handle->retry_timeout_us = retry_timeout_us;
    command_handle->command_seq = next_command_seq++;
    command_handle->is_uframe = is_uframe;
}

static void sys_cmd_abort(sys_command_handle_t *command_handle, status_t error)
{
    // Stop the re_transmit timer
    if (command_handle->re_transmit_timer_private_data.file_descriptor != 0)
    {
        if (command_handle->is_uframe || command_handle->acked == true)
        {
            epoll_port_unregister(&command_handle->re_transmit_timer_private_data);
        }
        close(command_handle->re_transmit_timer_private_data.file_descriptor);
        command_handle->re_transmit_timer_private_data.file_descriptor = 0;
    }

    command_handle->error_status = error; //This will be propagated when calling the callbacks

    switch (command_handle->command->command_id)
    {
    case CMD_SYSTEM_NOOP:
        ((sys_noop_cmd_cb_t)command_handle->on_final)(command_handle, command_handle->error_status);
        break;

    case CMD_SYSTEM_RESET:
        ((sys_reset_cmd_callback_t)command_handle->on_final)(command_handle, command_handle->error_status, SYS_STATUS_FAILURE);
        break;

    case CMD_SYSTEM_PROP_VALUE_GET:
    case CMD_SYSTEM_PROP_VALUE_SET:
    {
        sys_property_cmd_t *tx_property_command = (sys_property_cmd_t *)command_handle->command->payload;

        ((sys_property_get_set_cmd_callback_t)command_handle->on_final)(command_handle,
                                                                        tx_property_command->property_id,
                                                                        NULL,
                                                                        0,
                                                                        command_handle->error_status);
    }
    break;

    case CMD_SYSTEM_PROP_VALUE_IS: //fall through
    default:
        ASSERT("Invalid command_id");
        break;
    }

    // Invalidate the command id, now that it is aborted
    command_handle->command->command_id = CMD_SYSTEM_INVALID;
}

/***************************************************************************//**
* Handle the case where the system command timed out
*******************************************************************************/
static void sys_cmd_timed_out(const void *frame_data)
{
    sys_command_handle_t *command_handle;
    sys_cmd_t *timed_out_command;

    ERROR_ON(frame_data == NULL);

    timed_out_command = (sys_cmd_t *)frame_data;

    /* Go through the list of pending requests to find the one for which this reply applies */
    SLIST_FOR_EACH_ENTRY(commands, command_handle, sys_command_handle_t, node_commands)
    {
        if (command_handle->command_seq == timed_out_command->command_seq)
        {
            break;
        }
    }

    if (command_handle == NULL || command_handle->command_seq != timed_out_command->command_seq)
    {
        ASSERT("A command timed out but it could not be found in the submitted commands list. SEQ#%d", timed_out_command->command_seq);
    }

    // We won't need this command anymore. It needs to be resubmitted.
    slist_remove(&commands, &command_handle->node_commands);

    TRACE_SYSTEM("Command ID #%u SEQ #%u timeout", command_handle->command->command_id, command_handle->command->command_seq);

    sys_cmd_abort(command_handle, STATUS_TIMEOUT);

    /* Free the command handle and its buffer */

    free(command_handle->command);
    free(command_handle);
}

void sys_cmd_poll_acknowledged(const void *frame_data)
{
    int timer_fd, ret;
    sys_command_handle_t *command_handle;
    ERROR_ON(frame_data == NULL);
    sys_cmd_t *acked_command = (sys_cmd_t *)frame_data;

    // Go through the command list to figure out which command just got acknowledged
    SLIST_FOR_EACH_ENTRY(commands, command_handle, sys_command_handle_t, node_commands)
    {
        if (command_handle->command_seq == acked_command->command_seq)
        {
            TRACE_SYSTEM("Secondary acknowledged command_id #%d command_seq #%d", command_handle->command->command_id, command_handle->command_seq);
            const struct itimerspec timeout = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                                .it_value = { .tv_sec = (long int)command_handle->retry_timeout_us / 1000000, .tv_nsec = ((long int)command_handle->retry_timeout_us * 1000) % 1000000000 } };

            /* Setup timeout timer.*/
            if (command_handle->error_status == STATUS_OK)
            {
                timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);

                ERROR_SYSCALL_ON(timer_fd < 0);

                ret = timerfd_settime(timer_fd, 0, &timeout, NULL);
                ERROR_SYSCALL_ON(ret < 0);

                /* Setup the timer in the primary_cpcd epoll set */
                command_handle->re_transmit_timer_private_data.endpoint_number = CPC_EP_SYSTEM; //Irrelevant in this scenario
                command_handle->re_transmit_timer_private_data.file_descriptor = timer_fd;
                command_handle->re_transmit_timer_private_data.callback = on_timer_expired;

                epoll_port_register(&command_handle->re_transmit_timer_private_data);
            } else if (command_handle->error_status == STATUS_IN_PROGRESS)
            {
                // Simply restart the timer
                ret = timerfd_settime(command_handle->re_transmit_timer_private_data.file_descriptor, 0, &timeout, NULL);
                ERROR_SYSCALL_ON(ret < 0);
            } else
            {
                WARN("Received ACK on a command that timed out or is processed.. ignoring");
            }

            command_handle->acked = true;

            return; // Found the associated command
        }
    }

    WARN("Received a system poll ack for which no pending poll is registered");
}

void sys_cmd_noop(sys_noop_cmd_cb_t on_noop_reply,
                  uint8_t retry_count_max,
                  uint32_t retry_timeout_us)
{
    sys_command_handle_t *command_handle;

    /* Malloc the command handle and the command buffer */
    {
        command_handle = calloc_port(sizeof(sys_command_handle_t));
        ERROR_ON(command_handle == NULL);

        command_handle->command = calloc_port(sizeof(sys_cmd_t)); //noop had nothing in the 'payload field'
        ERROR_ON(command_handle->command == NULL);
    }

    sys_init_command_handle(command_handle, (void *)on_noop_reply, retry_count_max,
                            retry_timeout_us, false);

    /* Fill the system endpoint command buffer */
    {
        sys_cmd_t *tx_command = command_handle->command;

        tx_command->command_id = CMD_SYSTEM_NOOP;
        tx_command->command_seq = command_handle->command_seq;
        tx_command->length = 0;
    }

    write_command(command_handle);

    TRACE_SYSTEM("NOOP (id #%u) sent", CMD_SYSTEM_NOOP);
}

void sys_cmd_reboot(sys_reset_cmd_callback_t on_reset_reply,
                    uint8_t retry_count_max,
                    uint32_t retry_timeout_us)
{
    sys_command_handle_t *command_handle;

    /* Malloc the command handle and the command buffer */
    {
        command_handle = calloc_port(sizeof(sys_command_handle_t));
        ERROR_ON(command_handle == NULL);

        command_handle->command = calloc_port(sizeof(sys_cmd_t));
        ERROR_ON(command_handle->command == NULL);
    }

    sys_init_command_handle(command_handle, (void *)on_reset_reply, retry_count_max,
                            retry_timeout_us, true);

    /* Fill the system endpoint command buffer */
    {
        sys_cmd_t *tx_command = command_handle->command;

        tx_command->command_id = CMD_SYSTEM_RESET;
        tx_command->command_seq = command_handle->command_seq;
        tx_command->length = 0;
    }

    write_command(command_handle);

    TRACE_SYSTEM("reset (id #%u) sent", CMD_SYSTEM_RESET);
}

bool sys_received_unnumbered_acknowledgement(void)
{
    return received_remote_sequence_numbers_reset_ack;
}

void sys_on_unnumbered_acknowledgement(void)
{
    slist_node_t *item;
    sys_command_handle_t *command_handle;

    TRACE_SYSTEM("Received sequence numbers reset acknowledgement");
    received_remote_sequence_numbers_reset_ack = true;

    // Send any pending commands
    item = slist_pop(&pending_commands);
    while (item != NULL)
    {
        command_handle = SLIST_ENTRY(item, sys_command_handle_t, node_commands);
        write_command(command_handle);
        item = slist_pop(&pending_commands);
    }
}

static void on_unnumbered_acknowledgement_timeout(epoll_port_private_data_t *private_data)
{
    slist_node_t *item;
    int timer_fd = private_data->file_descriptor;
    sys_command_handle_t *command_handle = container_of(private_data,
                                                        sys_command_handle_t,
                                                        re_transmit_timer_private_data);

    if (sys_received_unnumbered_acknowledgement())
    {
        // Unnumbered ack was processed, stop the timeout timer
        if (command_handle->re_transmit_timer_private_data.file_descriptor != 0)
        {
            epoll_port_unregister(&command_handle->re_transmit_timer_private_data);
            close(command_handle->re_transmit_timer_private_data.file_descriptor);
            command_handle->re_transmit_timer_private_data.file_descriptor = 0;
        }
        return;
    }

    TRACE_SYSTEM("Remote is unresponsive, retrying...");

    /* Ack the timer */
    {
        uint64_t expiration;
        ssize_t retval;

        retval = read(timer_fd, &expiration, sizeof(expiration));

        ERROR_SYSCALL_ON(retval < 0);

        ERROR_ON(retval != sizeof(expiration));

        WARN_ON(expiration != 1); /* we missed a timeout*/
    }

    /* Drop any pending commands to prevent accumulation*/
    item = slist_pop(&pending_commands);
    while (item != NULL)
    {
        command_handle = SLIST_ENTRY(item, sys_command_handle_t, node_commands);

        if (command_handle->command->command_id != CMD_SYSTEM_INVALID)
        {
            sys_cmd_abort(command_handle, STATUS_ABORT);
        }
        free(command_handle->command);
        free(command_handle);
        item = slist_pop(&pending_commands);
    }

    cpcd_write(CPC_EP_SYSTEM, NULL, 0, FLAG_UFRAME_RESET_COMMAND);
}

void sys_request_sequence_reset(void)
{
    int timer_fd, ret;
    sys_command_handle_t *command_handle;

    sys_reset_sys_endpoint();

    TRACE_SYSTEM("Requesting reset of sequence numbers on the remote");
    cpcd_write(CPC_EP_SYSTEM, NULL, 0, FLAG_UFRAME_RESET_COMMAND);

    // Push the command right away
    cpcd_process_transmit_queue();

    // Register a timeout timer in case we don't receive an unnumbered acknowledgement
    const struct itimerspec timeout = { .it_interval = { .tv_sec = UFRAME_ACK_TIMEOUT_SECONDS, .tv_nsec = 0 },
                                        .it_value = { .tv_sec = UFRAME_ACK_TIMEOUT_SECONDS, .tv_nsec = 0 } };

    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);

    ERROR_SYSCALL_ON(timer_fd < 0);

    ret = timerfd_settime(timer_fd, 0, &timeout, NULL);
    ERROR_SYSCALL_ON(ret < 0);

    command_handle = calloc_port(sizeof(sys_command_handle_t));
    ERROR_ON(command_handle == NULL);

    /* Setup the timer in the primary_cpcd epoll set */
    command_handle->re_transmit_timer_private_data.file_descriptor = timer_fd;
    command_handle->re_transmit_timer_private_data.callback = on_unnumbered_acknowledgement_timeout;

    epoll_port_register(&command_handle->re_transmit_timer_private_data);

    ret = timerfd_settime(command_handle->re_transmit_timer_private_data.file_descriptor, 0, &timeout, NULL);
    ERROR_SYSCALL_ON(ret < 0);

    received_remote_sequence_numbers_reset_ack = false;
}

void sys_reset_sys_endpoint(void)
{
    slist_node_t *item;
    sys_command_handle_t *command_handle;

    // Abort any pending commands
    item = slist_pop(&commands);
    while (item != NULL)
    {
        command_handle = SLIST_ENTRY(item, sys_command_handle_t, node_commands);

        if (command_handle->command->command_id != CMD_SYSTEM_INVALID)
        {
            WARN("Dropping system command id #%d seq#%d", command_handle->command->command_id, command_handle->command_seq);
            sys_cmd_abort(command_handle, STATUS_ABORT);
        }

        // Command payload will be freed once we close the endpoint
        free(command_handle->command);
        free(command_handle);
        item = slist_pop(&commands);
    }

    // Close the system endpoint
    cpcd_close_endpoint(CPC_EP_SYSTEM, false, true);

    // Re-open the system endpoint
    sys_open_endpoint();
}
void sys_cmd_property_get(sys_property_get_set_cmd_callback_t on_property_get_reply,
                          property_id_t property_id,
                          uint8_t retry_count_max,
                          uint32_t retry_timeout_us,
                          bool is_uframe)
{
    sys_command_handle_t *command_handle;

    /* Malloc the command handle and the command buffer */
    {
        const size_t property_get_buffer_size = sizeof(sys_cmd_t) + sizeof(property_id_t);

        command_handle = calloc_port(sizeof(sys_command_handle_t));
        ERROR_ON(command_handle == NULL);
        command_handle->command = calloc_port(PAD_TO_8_BYTES(property_get_buffer_size)); //property-get has the property id as payload
        ERROR_ON(command_handle->command == NULL);
    }

    sys_init_command_handle(command_handle, (void *)on_property_get_reply, retry_count_max,
                            retry_timeout_us, is_uframe);

    /* Fill the system endpoint command buffer */
    {
        sys_cmd_t *tx_command = command_handle->command;
        sys_property_cmd_t *tx_property_command = (sys_property_cmd_t *)tx_command->payload;

        tx_command->command_id = CMD_SYSTEM_PROP_VALUE_GET;
        tx_command->command_seq = command_handle->command_seq;
        tx_property_command->property_id = cpu_to_le32(property_id);
        tx_command->length = sizeof(property_id_t);
    }

    write_command(command_handle);

    TRACE_SYSTEM("property-get (id #%u) sent with property #%u", CMD_SYSTEM_PROP_VALUE_GET, property_id);
}

/***************************************************************************//**
 * Send a property-set query
 ******************************************************************************/
void sys_cmd_property_set(sys_property_get_set_cmd_callback_t on_property_set_reply,
                          uint8_t retry_count_max,
                          uint32_t retry_timeout_us,
                          property_id_t property_id,
                          const void *value,
                          size_t value_length,
                          bool is_uframe)
{
    sys_command_handle_t *command_handle;

    ASSERT_ON(on_property_set_reply == NULL);

    {
        const size_t property_get_buffer_size = sizeof(sys_cmd_t) + sizeof(property_id_t) + value_length;

        command_handle = calloc_port(sizeof(sys_command_handle_t));
        ERROR_ON(command_handle == NULL);
        command_handle->command = calloc_port(PAD_TO_8_BYTES(property_get_buffer_size)); //property-get has the property id as payload
        ERROR_ON(command_handle->command == NULL);
    }

    sys_init_command_handle(command_handle, (void *)on_property_set_reply,
                            retry_count_max, retry_timeout_us, is_uframe);

    /* Fill the system endpoint command buffer */
    {
        sys_cmd_t *tx_command = command_handle->command;
        sys_property_cmd_t *tx_property_command = (sys_property_cmd_t *)tx_command->payload;;

        tx_command->command_id = CMD_SYSTEM_PROP_VALUE_SET;
        tx_command->command_seq = command_handle->command_seq;
        tx_property_command->property_id = cpu_to_le32(property_id);

        {
            switch (value_length)
            {
            case 0:
                ERROR("Can't send a property-set request with value of length 0");
                break;

            case 1:
                memcpy(tx_property_command->payload, value, value_length);
                break;

            case 2:
            {
                uint16_t le16 = cpu_to_le16p((uint16_t *)value);
                memcpy(tx_property_command->payload, &le16, 2);
            }
            break;

            case 4:
            {
                uint32_t le32 = cpu_to_le32p((uint32_t *)value);
                memcpy(tx_property_command->payload, &le32, 4);
            }
            break;

            case 8:
            {
                uint64_t le64 = cpu_to_le64p((uint64_t *)value);
                memcpy(tx_property_command->payload, &le64, 8);
            }
            break;

            default:
                memcpy(tx_property_command->payload, value, value_length);
                break;
            }
        }

        tx_command->length = (uint8_t)(sizeof(property_id_t) + value_length);
    }

    write_command(command_handle);

    TRACE_SYSTEM("property-set (id #%u) sent with property #%u", CMD_SYSTEM_PROP_VALUE_SET, property_id);
}

static void on_final_noop(sys_command_handle_t *command_handle,
                          sys_cmd_t *reply)
{
    (void)reply;

    TRACE_SYSTEM("on_final_noop()");

    ((sys_noop_cmd_cb_t)command_handle->on_final)(command_handle,
                                                  command_handle->error_status);
}

/***************************************************************************//**
 * Handle reset from SECONDARY:
 *   This functions is called when a reset command is received from the SECONDARY.
 *   The SECONDARY will send back a reset in response to the one sent by the PRIMARY.
 ******************************************************************************/
static void on_final_reset(sys_command_handle_t *command_handle,
                           sys_cmd_t *reply)
{
    TRACE_SYSTEM("on_final_reset()");

    ignore_reset_reason = false;

    // Deal with endianness of the returned status since its a 32bit value.
    sys_status_t reset_status_le = *((sys_status_t *)(reply->payload));
    sys_status_t reset_status_cpu = le32_to_cpu(reset_status_le);

    ((sys_reset_cmd_callback_t)command_handle->on_final)(command_handle,
                                                         command_handle->error_status,
                                                         reset_status_cpu);
}

/***************************************************************************//**
 * Handle property-is from SECONDARY:
 *   This functions is called when a property-is command is received from the SECONDARY.
 *   The SECONDARY emits a property-is in response to a property-get/set.
 ******************************************************************************/
static void on_final_property_is(sys_command_handle_t *command_handle,
                                 sys_cmd_t *reply,
                                 bool is_uframe)
{
    sys_property_cmd_t *property_cmd = (sys_property_cmd_t *)reply->payload;
    sys_property_get_set_cmd_callback_t callback = (sys_property_get_set_cmd_callback_t)command_handle->on_final;

    // Make sure only certain properties are allowed as u-frame (non-encrypted)
    if (is_uframe)
    {
        if (property_cmd->property_id != PROP_RX_CAPABILITY
            && property_cmd->property_id != PROP_CAPABILITIES
            && property_cmd->property_id != PROP_BUS_SPEED_VALUE
            && property_cmd->property_id != PROP_PROTOCOL_VERSION
            && property_cmd->property_id != PROP_SECONDARY_CPC_VERSION
            && property_cmd->property_id != PROP_SECONDARY_APP_VERSION
            && property_cmd->property_id != PROP_BOOTLOADER_REBOOT_MODE)
        {
            ERROR("Received on_final property_is %x as a u-frame", property_cmd->property_id);
        }
    }

    /* Deal with endianness of the returned property-id since its a 32bit value. */
    property_id_t property_id_le = property_cmd->property_id;
    property_id_t property_id_cpu = le32_to_cpu(property_id_le);

    size_t value_length = reply->length - sizeof(sys_property_cmd_t);

    callback(command_handle,
             property_id_cpu,
             property_cmd->payload,
             value_length,
             command_handle->error_status);
}

/***************************************************************************//**
 * This function is called by CPC cpcd poll reply (final) is received
 ******************************************************************************/
static void on_reply(uint8_t endpoint_id,
                     void *arg,
                     void *answer,
                     uint32_t answer_lenght)
{
    sys_command_handle_t *command_handle;
    sys_cmd_t *reply = (sys_cmd_t *)answer;
    size_t frame_type = (size_t)arg;

    (void)answer_lenght;

    ASSERT_ON(endpoint_id != 0);
    ERROR_ON(reply->length != answer_lenght - sizeof(sys_cmd_t));

    /* Go through the list of pending requests to find the one for which this reply applies */
    SLIST_FOR_EACH_ENTRY(commands, command_handle, sys_command_handle_t, node_commands)
    {
        if (command_handle->command_seq == reply->command_seq)
        {
            TRACE_SYSTEM("Processing command seq#%d of type %d", reply->command_seq, frame_type);

            /* Stop and close the retransmit timer */
            if (frame_type == CPC_HDLC_FRAME_TYPE_UFRAME
                || (frame_type == CPC_HDLC_FRAME_TYPE_IFRAME && command_handle->acked == true))
            {
                ASSERT_ON(command_handle->re_transmit_timer_private_data.file_descriptor <= 0);
                epoll_port_unregister(&command_handle->re_transmit_timer_private_data);
                close(command_handle->re_transmit_timer_private_data.file_descriptor);
                command_handle->re_transmit_timer_private_data.file_descriptor = 0;
            }

            /* Call the appropriate callback */
            if (frame_type == CPC_HDLC_FRAME_TYPE_UFRAME)
            {
                ASSERT_ON(command_handle->is_uframe == false);
                switch (reply->command_id)
                {
                case CMD_SYSTEM_RESET:
                    on_final_reset(command_handle, reply);
                    break;
                case CMD_SYSTEM_PROP_VALUE_IS:
                    on_final_property_is(command_handle, reply, true);
                    break;
                default:
                    ERROR("system endpoint command id not recognized for u-frame");
                    break;
                }
            } else if (frame_type == CPC_HDLC_FRAME_TYPE_IFRAME)
            {
                ASSERT_ON(command_handle->is_uframe == true);
                switch (reply->command_id)
                {
                case CMD_SYSTEM_NOOP:
                    on_final_noop(command_handle, reply);
                    break;

                case CMD_SYSTEM_PROP_VALUE_IS:
                    on_final_property_is(command_handle, reply, false);
                    break;

                case CMD_SYSTEM_PROP_VALUE_GET:
                case CMD_SYSTEM_PROP_VALUE_SET:
                    ERROR("its the primary who sends those");
                    break;

                default:
                    ERROR("system endpoint command id not recognized for i-frame");
                    break;
                }
            } else
            {
                ERROR("Invalid frame_type");
            }

            /* Cleanup this command now that it's been serviced */
            slist_remove(&commands, &command_handle->node_commands);
            free(command_handle->command);
            free(command_handle);

            return;
        }
    }

    WARN("Received a system final for which no pending poll is registered");
}

static void on_uframe_receive(uint8_t endpoint_id, const void *data, size_t data_len)
{
    ERROR_ON(endpoint_id != CPC_EP_SYSTEM);

    TRACE_SYSTEM("Unsolicited uframe received");

    sys_cmd_t *reply = (sys_cmd_t *)data;

    ERROR_ON(reply->length != data_len - sizeof(sys_cmd_t));

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
    ERROR_ON(endpoint_id != CPC_EP_SYSTEM);

    TRACE_SYSTEM("Unsolicited i-frame received");

    if (primary_cpcd_reset_sequence_in_progress())
    {
        TRACE_SYSTEM("Cannot process unsolicited i-frame during reset sequence, ignoring");
        return;
    }

    sys_cmd_t *reply = (sys_cmd_t *)data;

    ERROR_ON(reply->length != data_len - sizeof(sys_cmd_t));

    if (reply->command_id == CMD_SYSTEM_PROP_VALUE_IS)
    {
        sys_property_cmd_t *property = (sys_property_cmd_t *)reply->payload;

        if (property->property_id >= PROP_EP_STATE_0 && property->property_id < PROP_EP_STATES)
        {
            uint8_t closed_endpoint_id = PROPERTY_ID_TO_EP_ID(property->property_id);
            cpc_ep_state_t endpoint_state = cpcd_state_mapper(*(uint8_t *)property->payload);

            if (endpoint_state == CPC_EP_STATE_CLOSING)
            {
                TRACE_SYSTEM("Secondary closed the endpoint #%d", closed_endpoint_id);
                // The secondary notified us this endpoint will be closed
                if (!primary_listener_list_empty(closed_endpoint_id) && cpcd_get_endpoint_state(closed_endpoint_id) == CPC_EP_STATE_OPEN)
                {
                    // There are still clients connected to the endpoint
                    // We set this endpoint in error so clients are aware
                    cpcd_set_endpoint_in_error(closed_endpoint_id, CPC_EP_STATE_ERROR_DEST_UNREACH);
                    // And we acknowledge this notification
                    sys_cmd_property_set(sys_closing_ep_async_cb,
                                         EP_CLOSE_RETRIES,
                                         EP_CLOSE_RETRY_TIMEOUT,
                                         property->property_id,
                                         &endpoint_state,
                                         sizeof(cpc_ep_state_t),
                                         false);
                } else
                {
                    // We acknowledge this notification and close the endpoint in the callback
                    sys_cmd_property_set(sys_closing_ep_cb,
                                         EP_CLOSE_RETRIES,
                                         EP_CLOSE_RETRY_TIMEOUT,
                                         property->property_id,
                                         &endpoint_state,
                                         sizeof(cpc_ep_state_t),
                                         false);
                }
            } else
            {
                ERROR("Invalid property id");
            }
        }
    }
}

/***************************************************************************//**
 * System endpoint timer expire callback
 ******************************************************************************/
static void on_timer_expired(epoll_port_private_data_t *private_data)
{
    int timer_fd = private_data->file_descriptor;
    sys_command_handle_t *command_handle = container_of(private_data,
                                                        sys_command_handle_t,
                                                        re_transmit_timer_private_data);

    TRACE_SYSTEM("Command ID #%u SEQ #%u timer expired", command_handle->command->command_id, command_handle->command->command_seq);

    /* Ack the timer */
    {
        uint64_t expiration;
        ssize_t retval;

        retval = read(timer_fd, &expiration, sizeof(expiration));

        ERROR_SYSCALL_ON(retval < 0);

        ERROR_ON(retval != sizeof(expiration));

        WARN_ON(expiration != 1); /* we missed a timeout*/
    }

    if (!command_handle->retry_forever)
    {
        command_handle->retry_count--;
    }

    if (command_handle->retry_count > 0 || command_handle->retry_forever)
    {
        slist_remove(&commands, &command_handle->node_commands);

        command_handle->error_status = STATUS_IN_PROGRESS; //at least one timer retry occurred

        write_command(command_handle);

        if (command_handle->retry_forever)
        {
            TRACE_SYSTEM("Command ID #%u SEQ #%u retried", command_handle->command->command_id, command_handle->command->command_seq);
        } else
        {
            TRACE_SYSTEM("Command ID #%u SEQ #%u. %u retry left", command_handle->command->command_id, command_handle->command->command_seq, command_handle->retry_count);
        }
    } else
    {
        sys_cmd_timed_out(command_handle->command);
    }
}

/***************************************************************************//**
 * Write command on endpoint
 ******************************************************************************/
static void write_command(sys_command_handle_t *command_handle)
{
    int timer_fd;
    uint8_t flags = FLAG_INFORMATION_POLL;

    if (command_handle->retry_count == 0)
    {
        command_handle->retry_forever = true;
    } else
    {
        command_handle->retry_forever = false;
    }

    if (command_handle->is_uframe)
    {
        flags = FLAG_UFRAME_POLL;
    }

#if !defined(UNIT_TESTING)
    // Can't send iframe commands on the system endpoint until the sequence numbers are reset
    if (!command_handle->is_uframe)
    {
        if (!sys_received_unnumbered_acknowledgement())
        {
            slist_push_back(&pending_commands, &command_handle->node_commands);
            return;
        }
    }
#endif

    slist_push_back(&commands, &command_handle->node_commands);

    command_handle->acked = false;

    cpcd_write(CPC_EP_SYSTEM,
               (void *)command_handle->command,
               SIZEOF_SYSTEM_COMMAND(command_handle->command),
               flags);

    TRACE_SYSTEM("Submitted command_id #%d command_seq #%d", command_handle->command->command_id, command_handle->command_seq);

    if (command_handle->is_uframe)
    {
        /* Setup timeout timer.*/
        {
            const struct itimerspec timeout = { .it_interval = { .tv_sec = 0, .tv_nsec = 0 },
                                                .it_value = { .tv_sec = (long int)command_handle->retry_timeout_us / 1000000, .tv_nsec = ((long int)command_handle->retry_timeout_us * 1000) % 1000000000 } };

            timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);

            ERROR_SYSCALL_ON(timer_fd < 0);

            int ret = timerfd_settime(timer_fd,
                                      0,
                                      &timeout,
                                      NULL);

            ERROR_SYSCALL_ON(ret < 0);
        }

        /* Setup the timer in the primary_cpcd epoll set */
        {
            command_handle->re_transmit_timer_private_data.endpoint_number = CPC_EP_SYSTEM;
            command_handle->re_transmit_timer_private_data.file_descriptor = timer_fd;
            command_handle->re_transmit_timer_private_data.callback = on_timer_expired;

            epoll_port_register(&command_handle->re_transmit_timer_private_data);
        }
    }
}

void sys_cleanup(void)
{
    slist_node_t *item;
    last_status_callback_list_t *callback_list_item;

    TRACE_RESET("Server cpcd cleanup");

    item = slist_pop(&prop_last_status_callbacks);
    while (item != NULL)
    {
        callback_list_item = SLIST_ENTRY(item, last_status_callback_list_t, node);
        free(callback_list_item);
        item = slist_pop(&pending_commands);
    }

    // Close the system endpoint
    cpcd_close_endpoint(CPC_EP_SYSTEM, false, true);
}

void sys_init(void)
{
    slist_init(&commands);
    slist_init(&retries);
    slist_init(&pending_commands);
    slist_init(&commands_in_error);
    slist_init(&prop_last_status_callbacks);

    sys_open_endpoint();
}

void sys_register_unsolicited_prop_last_status_callback(sys_unsolicited_status_callback_t callback)
{
    last_status_callback_list_t *item = calloc_port(sizeof(last_status_callback_list_t));
    ERROR_ON(item == NULL);

    item->callback = callback;

    slist_push_back(&prop_last_status_callbacks, &item->node);
}