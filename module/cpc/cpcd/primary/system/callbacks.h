

#ifndef __CALLBACKS_H__
#define __CALLBACKS_H__

#include "primary/system/system.h"

#include <stdint.h>

typedef enum
{
    SYSTEM_OPEN_STEP_IDLE,
    SYSTEM_OPEN_STEP_STATE_WAITING,
    SYSTEM_OPEN_STEP_STATE_FETCHED,
    SYSTEM_OPEN_STEP_ENCRYPTION_WAITING,
    SYSTEM_OPEN_STEP_ENCRYPTION_FETCHED,
    SYSTEM_OPEN_STEP_DONE,
} sys_open_step_t;

extern sys_open_step_t sys_open_ep_step;

void sys_set_pending_connection(int fd);
bool sys_is_waiting_for_status_reply(void);

void sys_closing_ep_async_cb(sys_command_handle_t *handle,
                             property_id_t property_id,
                             void *property_value,
                             size_t property_length,
                             status_t status);

void sys_closing_ep_cb(sys_command_handle_t *handle,
                       property_id_t property_id,
                       void *property_value,
                       size_t property_length,
                       status_t status);

void sys_get_ep_state_pending_cb(sys_command_handle_t *handle,
                                 property_id_t property_id,
                                 void *property_value,
                                 size_t property_length,
                                 status_t status);

#if defined(ENABLE_ENCRYPTION)
void property_get_single_endpoint_encryption_state_and_reply_to_pending_open_callback(sys_command_handle_t *handle,
                                                                                      property_id_t property_id,
                                                                                      void *property_value,
                                                                                      size_t property_length,
                                                                                      status_t status);
#endif

void sys_noop_cmd_cb(sys_command_handle_t *handle,
                     status_t status);

#endif //__CALLBACKS_H__
