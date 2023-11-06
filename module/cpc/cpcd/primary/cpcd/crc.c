#include "crc.h"

static uint16_t cpc_compute_crc16(uint8_t new_byte, uint16_t prev_result);

uint16_t cpc_get_crc_sw(const void *buffer, uint16_t buffer_length)
{
    uint16_t i;
    uint16_t crc = 0;

    for (i = 0; i < buffer_length; i++)
    {
        crc = cpc_compute_crc16((uint8_t)((uint8_t *)buffer)[i], crc);
    }

    return crc;
}

bool cpc_check_crc_sw(const void *buffer, uint16_t buffer_length, uint16_t expected_crc)
{
    uint16_t computed_crc;

    computed_crc = cpc_get_crc_sw(buffer, buffer_length);

    return(computed_crc == expected_crc);
}

static uint16_t cpc_compute_crc16(uint8_t new_byte, uint16_t prev_result)
{
#if (CPC_CRC_0 == 1)
    prev_result = ((uint16_t)(prev_result >> 8)) | ((uint16_t)(prev_result << 8));
    prev_result ^= new_byte;
    prev_result ^= (prev_result & 0xff) >> 4;
    prev_result ^= (uint16_t)(((uint16_t)(prev_result << 8)) << 4);
    prev_result ^= ((uint8_t)(((uint8_t)(prev_result & 0xff)) << 5))
                   | ((uint16_t)((uint16_t)((uint8_t)(((uint8_t)(prev_result & 0xff)) >> 3)) << 8));
#else
    uint8_t bit;

    for (bit = 0; bit < 8; bit++)
    {
        prev_result ^= (new_byte & 0x01);
        prev_result = (prev_result & 0x01) ? (prev_result >> 1) ^ 0x8408 : (prev_result >> 1);
        new_byte = new_byte >> 1;
    }
#endif
    return prev_result;
}
