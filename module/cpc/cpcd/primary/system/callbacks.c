#include <string.h>
#include <sys/socket.h>

#include "utility/config.h"
#include "primary/system/callbacks.h"
#include "primary/cpcd/cpcd.h"
#include "primary/primary/primary.h"
#include "utility/logs.h"
#include "lib/libcpc.h"
#include "primary/cpcd/cpcd.h"

static int fd_ctrl_data_of_pending_open = 0;

sys_open_step_t sys_open_ep_step = SYSTEM_OPEN_STEP_IDLE;

bool sys_is_waiting_for_status_reply(void)
{
    return fd_ctrl_data_of_pending_open != 0;
}

void sys_set_pending_connection(int fd)
{
    fd_ctrl_data_of_pending_open = fd;
}

void sys_closing_ep_async_cb(sys_command_handle_t *handle,
                             property_id_t property_id,
                             void *property_value,
                             size_t property_length,
                             status_t status)
{
    (void)handle;
    (void)property_length;
    (void)property_value;

    uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);

    switch (status)
    {
    case STATUS_IN_PROGRESS:
    case STATUS_OK:
        TRACE_PRIMARY("Acknowledged secondary of asynchronously closing ep#%d", ep_id);
        break;

    case STATUS_TIMEOUT:
    case STATUS_ABORT:
    default:
        WARN("Secondary did not receive acknowledge of asynchronously closing ep#%d", ep_id);
        break;
    }
}

void sys_closing_ep_cb(sys_command_handle_t *handle,
                       property_id_t property_id,
                       void *property_value,
                       size_t property_length,
                       status_t status)
{
    (void)handle;
    (void)property_length;
    (void)property_value;

    uint8_t ep_id = PROPERTY_ID_TO_EP_ID(property_id);

    switch (status)
    {
    case STATUS_IN_PROGRESS:
    case STATUS_OK:
        TRACE_PRIMARY("Acknowledged secondary of closing ep#%d", ep_id);
        cpcd_set_endpoint_state(ep_id, CPC_EP_STATE_CLOSED);
        break;

    case STATUS_TIMEOUT:
    case STATUS_ABORT:
    default:
        WARN("Secondary did not receive acknowledge of closing ep#%d", ep_id);
        break;
    }
}

static void sys_send_open_endpoint_ack(uint8_t endpoint_id, bool can_open)
{
    const size_t buffer_len = sizeof(cpc_croe_exange_buffer_t) + sizeof(bool);
    cpc_croe_exange_buffer_t *interface_buffer;
    uint8_t buffer[buffer_len];

    interface_buffer = (cpc_croe_exange_buffer_t *)buffer;

    // populate fields related to the query
    interface_buffer->type = EXCHANGE_OPEN_EP_QUERY;
    interface_buffer->endpoint_number = endpoint_id;
    memcpy(interface_buffer->payload, &can_open, sizeof(bool));

    ssize_t ret = send(fd_ctrl_data_of_pending_open, interface_buffer, buffer_len, 0);
    TRACE_PRIMARY("Replied to endpoint open query on ep#%d", endpoint_id);

    if (ret == -1)
    {
        WARN("Failed to acknowledge the open request for endpoint #%d. %m", endpoint_id);
    } else if ((size_t)ret != buffer_len)
    {
        ASSERT("Failed to acknowledge the open request for endpoint #%d. Sent %d, Expected %d",
               endpoint_id, (int)ret, (int)buffer_len);
    }

    sys_open_ep_step = SYSTEM_OPEN_STEP_DONE;
}

static void sys_finalize_open_endpoint(uint8_t endpoint_id, bool encryption, bool can_open)
{
    if (can_open)
    {
        primary_set_endpoint_encryption(endpoint_id, encryption);
        primary_open_endpoint(endpoint_id);
    }

    sys_send_open_endpoint_ack(endpoint_id, can_open);
}

void sys_get_ep_state_pending_cb(sys_command_handle_t *handle,
                                 property_id_t property_id,
                                 void *property_value,
                                 size_t property_length,
                                 status_t status)
{
    (void)handle;
    bool can_open = false;
    bool secondary_reachable = false;
    uint8_t endpoint_id;
    cpc_ep_state_t remote_endpoint_state;

    switch (status)
    {
    case STATUS_OK:
        ASSERT_ON(property_length != sizeof(cpc_ep_state_t));
        TRACE_PRIMARY("Property-get::PROP_EP_STATE Successful callback");
        remote_endpoint_state = cpcd_state_mapper(*(uint8_t *)property_value);
        secondary_reachable = true;
        break;
    case STATUS_IN_PROGRESS:
        ASSERT_ON(property_length != sizeof(cpc_ep_state_t));
        TRACE_PRIMARY("Property-get::PROP_EP_STATE Successful callback after retry(ies)");
        remote_endpoint_state = cpcd_state_mapper(*(uint8_t *)property_value);
        secondary_reachable = true;
        break;
    case STATUS_TIMEOUT:
        WARN("Property-get::PROP_EP_STATE timed out");
        break;
    case STATUS_ABORT:
        WARN("Property-get::PROP_EP_STATE aborted");
        break;
    default:
        ERROR();
    }

    /* Sanity checks */
    {
        /* This callback should be called only when we need to reply to a client pending on an open_endpoint call */
        ASSERT_ON(fd_ctrl_data_of_pending_open == 0);

        /* This function's signature is for all properties get/set. Make sure we
         * are dealing with PROP_EP_STATE and with the correct property_length*/
        //ASSERT_ON(property_id < PROP_EP_STATE_1 || property_id > PROP_EP_STATE_255);

        if (secondary_reachable)
        {
            ASSERT_ON(property_length != 1);
        }
    }

    endpoint_id = PROPERTY_ID_TO_EP_ID(property_id);

    if (secondary_reachable && (remote_endpoint_state == CPC_EP_STATE_OPEN)
        && (cpcd_get_endpoint_state(endpoint_id) == CPC_EP_STATE_CLOSED || cpcd_get_endpoint_state(endpoint_id) == CPC_EP_STATE_OPEN))
    {
        can_open = true;

        // endpoint is ready to be opened, the encryption status must now be fetched
    }

    if (!can_open && secondary_reachable)
    {
        TRACE_PRIMARY("Cannot open endpoint #%d. Current state on the secondary is: %s. Current state on daemon is: %s", endpoint_id, cpcd_stringify_state(remote_endpoint_state), cpcd_stringify_state(cpcd_get_endpoint_state(endpoint_id)));
    }

    if (!secondary_reachable)
    {
        WARN("Could not read endpoint state on the secondary");
    }

    if (!can_open)
    {
        // Send "failed to open" ack to control socket
        sys_finalize_open_endpoint(endpoint_id, false, can_open);
    } else
    {
        sys_finalize_open_endpoint(endpoint_id, false, can_open);
    }
}
void sys_noop_cmd_cb(sys_command_handle_t *handle,
                     status_t status)
{
    (void)handle;

    switch (status)
    {
    case STATUS_OK:
        TRACE_PRIMARY("NOOP success");
        break;
    case STATUS_IN_PROGRESS:
        TRACE_PRIMARY("NOOP success with a least one retry");
        break;
    case STATUS_TIMEOUT:
        WARN("The noop keep alive timed out, link dead");
        TRACE_PRIMARY("NOOP timed out!");
        break;
    case STATUS_ABORT:
        WARN("The noop keep alive was aborted");
        TRACE_PRIMARY("NOOP failed!");
        break;
    default:
        ERROR();
        break;
    }
}
