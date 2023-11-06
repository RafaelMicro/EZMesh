

#include "hdlc.h"
#include "crc.h"

void hdlc_create_header(uint8_t *header_buf,
                        uint8_t address,
                        uint16_t length,
                        uint8_t control,
                        bool compute_crc)
{
    uint16_u length_union;

    length_union.uint16 = cpu_to_le16(length);

    header_buf[0] = CPC_HDLC_FLAG_VAL;
    header_buf[1] = address;
    header_buf[2] = length_union.bytes[0];
    header_buf[3] = length_union.bytes[1];
    header_buf[4] = control;

    if (compute_crc)
    {
        uint16_u hcs_union;

        hcs_union.uint16 = cpu_to_le16(cpc_get_crc_sw(header_buf, CPC_HDLC_HEADER_SIZE));

        header_buf[5] = hcs_union.bytes[0];
        header_buf[6] = hcs_union.bytes[1];
    }
}
