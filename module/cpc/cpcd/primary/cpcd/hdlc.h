

#ifndef CPC_HDLC_H
#define CPC_HDLC_H

#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include "libcpc.h"
#include "utility/endian.h"

#define CPC_HDLC_FLAG_VAL                       (0x14)

#define CPC_HDLC_HEADER_SIZE                    (5)
#define CPC_HDLC_HEADER_RAW_SIZE                (7)
#define CPC_HDLC_FCS_SIZE                       (2)
#define CPC_HDLC_REJECT_PAYLOAD_SIZE            (1)
#define CPC_HDLC_CONTROL_UFRAME_TYPE_MASK   (0x37)
#define CPC_HDLC_ACK_SFRAME_FUNCTION       (0)
#define CPC_HDLC_REJECT_SFRAME_FUNCTION    (1)


CPC_ENUM_DECLARE(hdlc_frame_type_t)
{
    CPC_HDLC_FRAME_TYPE_IFRAME = 0,
    CPC_HDLC_FRAME_TYPE_SFRAME = 2,
    CPC_HDLC_FRAME_TYPE_UFRAME = 3
};

CPC_ENUM_DECLARE(hdlc_frame_pos_t)
{
    CPC_HDLC_FLAG_POS = 0,
    CPC_HDLC_ADDRESS_POS = 1,
    CPC_HDLC_LENGTH_POS = 2,
    CPC_HDLC_CONTROL_POS = 4,
    CPC_HDLC_HCS_POS = 5
};

CPC_ENUM_DECLARE(hdlc_frame_shift_t)
{
    CPC_HDLC_CONTROL_UFRAME_TYPE_SHIFT = 0,
    CPC_HDLC_CONTROL_P_F_SHIFT = 2,
    CPC_HDLC_CONTROL_SEQ_SHIFT = 3,
    CPC_HDLC_CONTROL_SFRAME_FNCT_ID_SHIFT = 4,
    CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT = 6
};


CPC_ENUM_DECLARE(hdlc_frame_ctrl_u_t)
{
    CPC_HDLC_CONTROL_UFRAME_TYPE_INFORMATION = 0x00,
    CPC_HDLC_CONTROL_UFRAME_TYPE_POLL_FINAL = 0x04,
    CPC_HDLC_CONTROL_UFRAME_TYPE_ACKNOWLEDGE = 0x0E,
    CPC_HDLC_CONTROL_UFRAME_TYPE_RESET_SEQ = 0x31,
    CPC_HDLC_CONTROL_UFRAME_TYPE_UNKNOWN = 0xFF
};


CPC_ENUM_DECLARE(reject_reason_t)
{
    HDLC_REJECT_NO_ERROR = 0,
    HDLC_REJECT_CHECKSUM_MISMATCH,
    HDLC_REJECT_SEQUENCE_MISMATCH,
    HDLC_REJECT_OUT_OF_MEMORY,
    HDLC_REJECT_SECURITY_ISSUE,
    HDLC_REJECT_UNREACHABLE_ENDPOINT,
    HDLC_REJECT_ERROR
};

typedef union
{
    uint8_t bytes[2];
    uint16_t uint16;
}uint16_u;

static inline uint8_t hdlc_get_flag(const uint8_t *header_buf)
{
    return header_buf[CPC_HDLC_FLAG_POS];
}

static inline uint8_t hdlc_get_address(const uint8_t *header_buf)
{
    return header_buf[CPC_HDLC_ADDRESS_POS];
}

static inline uint16_t hdlc_get_length(const uint8_t *header_buf)
{
    uint16_u u;

    u.bytes[0] = header_buf[CPC_HDLC_LENGTH_POS];
    u.bytes[1] = header_buf[CPC_HDLC_LENGTH_POS + 1];

    return le16_to_cpu(u.uint16);
}

static inline uint8_t hdlc_get_control(const uint8_t *header_buf)
{
    return header_buf[CPC_HDLC_CONTROL_POS];
}

static inline uint16_t hdlc_get_hcs(const uint8_t *header_buf)
{
    uint16_u u;

    u.bytes[0] = header_buf[CPC_HDLC_HCS_POS];
    u.bytes[1] = header_buf[CPC_HDLC_HCS_POS + 1];

    return le16_to_cpu(u.uint16);
}

static inline uint16_t hdlc_get_fcs(const uint8_t *payload_buf, uint16_t payload_length)
{
    uint16_u u;

    u.bytes[0] = payload_buf[payload_length];
    u.bytes[1] = payload_buf[payload_length + 1];

    return le16_to_cpu(u.uint16);
}

static inline uint8_t hdlc_get_frame_type(uint8_t control)
{
    uint8_t type = control >> CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT;

    if (type == 1 || type == 0)
    {
        type = CPC_HDLC_FRAME_TYPE_IFRAME;
    }

    return type;
}

static inline uint8_t hdlc_get_seq(uint8_t control)
{
    return (control >> CPC_HDLC_CONTROL_SEQ_SHIFT) & 0x03;
}

static inline uint8_t hdlc_get_ack(uint8_t control)
{
    return control & 0x03;
}

static inline uint8_t hdlc_get_sframe_function(uint8_t control)
{
    return (control >> CPC_HDLC_CONTROL_SFRAME_FNCT_ID_SHIFT) & 0x03;
}

static inline uint8_t hdlc_get_uframe_type(uint8_t control)
{
    return (control >> CPC_HDLC_CONTROL_UFRAME_TYPE_SHIFT) & CPC_HDLC_CONTROL_UFRAME_TYPE_MASK;
}

static inline bool hdlc_is_poll_final(uint8_t control)
{
    if (control & (1 << CPC_HDLC_CONTROL_P_F_SHIFT))
    {
        return true;
    }
    return false;
}

void hdlc_create_header(uint8_t *header_buf,
                        uint8_t address,
                        uint16_t length,
                        uint8_t control,
                        bool compute_crc);

static inline uint8_t hdlc_create_ctrl_data(uint8_t seq, uint8_t ack, bool poll_final)
{
    uint8_t control = CPC_HDLC_FRAME_TYPE_IFRAME << CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT;

    control |= (uint8_t)(seq << CPC_HDLC_CONTROL_SEQ_SHIFT);
    control |= ack;
    control |= (uint8_t)((uint8_t)poll_final << CPC_HDLC_CONTROL_P_F_SHIFT);

    return control;
}


static inline uint8_t hdlc_create_ctrl_sframe(uint8_t ack, uint8_t sframe_function)
{
    uint8_t control = CPC_HDLC_FRAME_TYPE_SFRAME << CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT;

    control |= (uint8_t)(sframe_function << CPC_HDLC_CONTROL_SFRAME_FNCT_ID_SHIFT);
    control |= ack;

    return control;
}

static inline uint8_t hdlc_create_ctrl_uframe(uint8_t type)
{
    uint8_t control = CPC_HDLC_FRAME_TYPE_UFRAME << CPC_HDLC_CONTROL_FRAME_TYPE_SHIFT;

    control |= type << CPC_HDLC_CONTROL_UFRAME_TYPE_SHIFT;

    return control;
}

static inline void hdlc_set_ctrl_ack(uint8_t *control,
                                     uint8_t ack)
{
    *control = (uint8_t)(*control & ~0x03);
    *control |= ack;
}

#endif // CPC_HDLC_H
