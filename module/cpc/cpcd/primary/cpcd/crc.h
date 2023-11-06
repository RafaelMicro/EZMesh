

#ifndef CRC_H
#define CRC_H

#include <stdbool.h>
#include <stdint.h>

uint16_t cpc_get_crc_sw(const void *buffer, uint16_t buffer_length);
bool cpc_check_crc_sw(const void *buffer, uint16_t buffer_length, uint16_t expected_crc);

#endif //CRC_H
