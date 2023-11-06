

#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stdbool.h>

#include "utility/status.h"
#include "primary/cpcd/cpcd.h"

void primary_init(void);

void primary_open_endpoint(uint8_t endpoint_number);
void primary_close_endpoint(uint8_t endpoint_number, bool error);
void primary_set_endpoint_encryption(uint8_t endpoint_id, bool encryption_enabled);

status_t primary_push_data_to_endpoint(uint8_t endpoint_number, const uint8_t *data, size_t data_len);
void primary_process_pending_connections(void);
bool primary_is_endpoint_open(uint8_t endpoint_number);

bool primary_listener_list_empty(uint8_t endpoint_number);

void primary_notify_connected_libs_of_secondary_reset(void);
void primary_on_endpoint_state_change(uint8_t ep_id, cpc_ep_state_t state);

void primary_push_data_to_cpcd(uint8_t endpoint_number, const void *data, size_t data_len);
void primary_tell_cpcd_to_open_endpoint(uint8_t endpoint_number);

#endif
