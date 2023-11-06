

#ifndef LOGGING_H
#define LOGGING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/// Struct representing CPC CPCd debug counters.
typedef struct
{
    uint32_t endpoint_opened;
    uint32_t endpoint_closed;
    uint32_t rxd_frame;
    uint32_t txd_reject_destination_unreachable;
    uint32_t txd_completed;
    uint32_t retxd_data_frame;
    uint32_t invalid_header_checksum;
    uint32_t invalid_payload_checksum;
} cpc_cpcd_dbg_cts_t;

void logging_init(void);

void init_file_logging();

void init_stats_logging(void);

void logging_kill(void);

void trace(const bool force_stdout, const char *string, ...);

void trace_no_timestamp(const char *string, ...);

void trace_frame(const char *string, const void *buffer, size_t len);

void logging_driver_print_stats(void);

extern cpc_cpcd_dbg_cts_t primary_cpcd_debug_counters;
extern cpc_cpcd_dbg_cts_t secondary_cpcd_debug_counters;

#define EVENT_COUNTER_INC(counter)   ((primary_cpcd_debug_counters.counter)++)

#define TRACE(string, ...)                    do { trace(false, string, ## __VA_ARGS__); } while (0)

#define TRACE_FORCE_STDOUT(string, ...)       do { trace(true, string, ## __VA_ARGS__); } while (0)

#define PRINT_INFO(string, ...)       TRACE_FORCE_STDOUT("Info : "  string "\n", ## __VA_ARGS__)

#define TRACE_HAL(string, ...)        TRACE("HAL  : "  string "\n", ## __VA_ARGS__)

#define TRACE_CPCD(string, ...)       TRACE("CPCd : "  string "\n", ## __VA_ARGS__)

#define TRACE_cpcd_EVENT(event, string, ...)       do { EVENT_COUNTER_INC(event); TRACE("CPCd : "  string "\n", ## __VA_ARGS__); } while (0)

#define TRACE_PRIMARY(string, ...)    TRACE("PRI  : "  string "\n", ## __VA_ARGS__)

#define TRACE_SYSTEM(string, ...)     TRACE("SYS  : "  string "\n", ## __VA_ARGS__)

#define TRACE_RESET(string, ...)      TRACE("Reset Sequence : "  string "\n", ## __VA_ARGS__)

#define trace_lib(string, ...)        TRACE("Lib  : "  string "\n", ## __VA_ARGS__)

#define TRACE_ASSERT(string, ...)     TRACE_FORCE_STDOUT("*** ASSERT *** : " string, ## __VA_ARGS__)

#define TRACE_WARN(string, ...)       TRACE_FORCE_STDOUT("WARNING : " string, ## __VA_ARGS__)

#define TRACE_FRAME(string, buffer, length) trace_frame(string, buffer, length)

#define TRACE_cpcd_OPEN_ENDPOINT(ep_id)                      TRACE_cpcd_EVENT(endpoint_opened, "Open ep #%u", ep_id)

#define TRACE_cpcd_CLOSE_ENDPOINT(ep_id)                     TRACE_cpcd_EVENT(endpoint_closed, "Close ep #%u", ep_id)

#define TRACE_cpcd_RXD_FRAME(buffer, len)                 do { EVENT_COUNTER_INC(rxd_frame); TRACE_FRAME("CPCd : Rx frame from cpc : ", buffer, len); } while (0)

#define TRACE_cpcd_TXD_REJECT_DESTINATION_UNREACHABLE()   TRACE_cpcd_EVENT(txd_reject_destination_unreachable, "txd reject destination unreachable")

#define TRACE_cpcd_INVALID_HEADER_CHECKSUM()              TRACE_cpcd_EVENT(invalid_header_checksum, "invalid hcs")

#define TRACE_cpcd_INVALID_PAYLOAD_CHECKSUM()              TRACE_cpcd_EVENT(invalid_payload_checksum, "invalid pcs")

#define TRACE_cpcd_TXD_TRANSMIT_COMPLETED()               TRACE_cpcd_EVENT(txd_completed, "txd transmit completed")

#define TRACE_EP_RXD_DATA_FRAME(ep)                 TRACE_CPCD("EP #%u: rxd I-frame", ep->id)

#define TRACE_EP_RXD_DATA_FRAME_QUEUED(ep)          TRACE_CPCD("EP #%u: rxd I-frame queued", ep->id)

#define TRACE_EP_RXD_SFRAME_FRAME(ep)          TRACE_CPCD("EP #%u: rxd S-frame", ep->id)

#define TRACE_EP_RXD_SFRAME_PROCESSED(ep)      TRACE_CPCD("EP #%u: rxd S-frame processed", ep->id)

#define TRACE_EP_RXD_SFRAME_DROPPED(ep)        TRACE_CPCD("EP #%u: rxd S-frame dropped", ep->id)

#define TRACE_EP_RXD_UFRAME_FRAME(ep)           TRACE_CPCD("EP #%u: rxd U-frame", ep->id)

#define TRACE_EP_RXD_UFRAME_DROPPED(ep, reason) TRACE_CPCD("EP #%d: U-frame dropped : %s", ((ep == NULL) ? -1 : (signed)ep->id), reason)

#define TRACE_EP_RXD_UFRAME_PROCESSED(ep)       TRACE_CPCD("EP #%u: U-frame processed", ep->id)

#define TRACE_EP_RXD_DUPLICATE_DATA_FRAME(ep)       TRACE_CPCD("EP #%u: rxd duplicate I-frame", ep->id)

#define TRACE_EP_RXD_ACK(ep, ack)                        TRACE_CPCD("EP #%u: rxd ack %u", ep->id, ack)

#define TRACE_EP_RXD_REJECT_DESTINATION_UNREACHABLE(ep)  TRACE_CPCD("EP #%u: rxd reject destination unreachable", ep->id)

#define TRACE_EP_RXD_REJECT_SEQ_MISMATCH(ep)        TRACE_CPCD("EP #%u: rxd reject seq mismatch", ep->id)

#define TRACE_EP_RXD_REJECT_CHECKSUM_MISMATCH(ep)    TRACE_CPCD("EP #%u: rxd reject checksum mismatch", ep->id)

#define TRACE_EP_RXD_REJECT_SECURITY_ISSUE(ep)      TRACE_CPCD("EP #%u: rxd reject security issue", ep->id)

#define TRACE_EP_RXD_REJECT_OUT_OF_MEMORY(ep)       TRACE_CPCD("EP #%u: rxd reject out of memory", ep->id)

#define TRACE_EP_RXD_REJECT_FAULT(ep)               TRACE_CPCD("EP #%u: rxd reject fault", ep->id)

#define TRACE_EP_TXD_ACK(ep)                        TRACE_CPCD("EP #%u: txd ack", ep->id)

#define TRACE_EP_TXD_REJECT_DESTINATION_UNREACHABLE(ep) TRACE_CPCD("EP #%d: txd reject destination unreachable", (ep == NULL) ? -1 : (signed)ep->id)

#define TRACE_EP_TXD_REJECT_SEQ_MISMATCH(ep)        TRACE_CPCD("EP #%u: txd reject seq mismatch", ep->id)

#define TRACE_EP_TXD_REJECT_CHECKSUM_MISMATCH(ep)   TRACE_CPCD("EP #%u: txd reject checksum mismatch", ep->id)

#define TRACE_EP_TXD_REJECT_SECURITY_ISSUE(ep)      TRACE_CPCD("EP #%u: txd reject security issue", ep->id)

#define TRACE_EP_TXD_REJECT_OUT_OF_MEMORY(ep)       TRACE_CPCD("EP #%u: txd reject out of memory", ep->id)

#define TRACE_EP_TXD_REJECT_FAULT(ep)               TRACE_CPCD("EP #%u: txd reject fault", ep->id)

#define TRACE_EP_RETXD_DATA_FRAME(ep)               do { EVENT_COUNTER_INC(retxd_data_frame); TRACE_CPCD("EP #%u: re-txd data frame", ep->id); } while (0)

#define TRACE_EP_FRAME_TRANSMIT_SUBMITTED(ep)       TRACE_CPCD("EP #%d: frame transmit submitted", (ep == NULL) ? -1 : (signed)ep->id)

#define TRACE_HAL_INVALID_HEADER_CHECKSUM()            do { EVENT_COUNTER_INC(invalid_header_checksum); TRACE_HAL("invalid header checksum in driver"); } while (0)

#define OUT_FILE stderr

__attribute__((noreturn)) void signal_crash(void);

#define CRASH() do { signal_crash(); } while (0)

#define WARN(msg, ...)                                                                                                             \
    do {                                                                                                                             \
        TRACE_WARN("[WARN : %s : %d] " msg "\n", __FILE__, __LINE__, ## __VA_ARGS__);                \
        fprintf(OUT_FILE, "[WARN : %s : %d] " msg "\n", __FILE__, __LINE__, ## __VA_ARGS__); \
    } while (0)

#define WARN_ON(cond)                                                                                                      \
    do {                                                                                                                     \
        if (cond) {                                                                                                            \
            TRACE_WARN("On '%s' in function '%s' in file %s at line #%d\n", #cond, __func__, __FILE__, __LINE__);                \
            fprintf(OUT_FILE, "WARNING on '%s' in function '%s' in file %s at line #%d\n", #cond, __func__, __FILE__, __LINE__); \
        }                                                                                                                      \
    } while (0)

#define ERROR(msg, ...)                                                                                                          \
    do {                                                                                                                           \
        TRACE_ASSERT("[ERROR : %s : %d] " msg "\n", __FILE__, __LINE__, ## __VA_ARGS__);      \
        fprintf(OUT_FILE, "[ERROR : %s : %d] " msg "\n", __FILE__, __LINE__, ## __VA_ARGS__); \
        CRASH();                                                                                                                     \
    } while (0)

#define ERROR_ON(cond)                                                                                                   \
    do {                                                                                                                   \
        if (cond) {                                                                                                          \
            TRACE_ASSERT("[ERROR_%s : %s : %d]\n",#cond, __FILE__, __LINE__);      \
            fprintf(OUT_FILE, "[ERROR_%s : %s : %d]\n",#cond, __FILE__, __LINE__); \
            CRASH();                                                                                                           \
        }                                                                                                                    \
    } while (0)

#define ERROR_SYSCALL_ON(cond)                                                                                             \
    do {                                                                                                                     \
        if (cond) {                                                                                                            \
            TRACE_ASSERT("[ERROR_SYS : %s : %d]%m\n", __FILE__, __LINE__);      \
            fprintf(OUT_FILE, "[ERROR_SYS : %s : %d]%m\n", __FILE__, __LINE__); \
            CRASH();                                                                                                             \
        }                                                                                                                      \
    } while (0)

/* Special version used specifically when the trace file hasn't been opened yet (error while creating it) */
#define FATAL_SYSCALL_NO_TRACE_FILE_ON(cond)                                                                               \
    do {                                                                                                                     \
        if (cond) {                                                                                                            \
            fprintf(OUT_FILE, "[FATAL_SYS : %s : %d]%m\n", __FILE__, __LINE__); \
            CRASH();                                                                                                             \
        }                                                                                                                      \
    } while (0)

#define ASSERT(msg, ...)                                                                                                          \
    do {                                                                                                                         \
        TRACE_ASSERT("[ASSERT : file %s : %d : " msg "\n", __FILE__, __LINE__, ## __VA_ARGS__);      \
        fprintf(OUT_FILE, "[ASSERT : file %s : %d : " msg "\n", __FILE__, __LINE__, ## __VA_ARGS__); \
        CRASH();                                                                                                                   \
    } while (0)

#define ASSERT_ON(cond)                                                                                                  \
    do {                                                                                                                \
        if (cond) {                                                                                                       \
            TRACE_ASSERT("ASSERT_%s : %s : %d\n",#cond, __FILE__, __LINE__);      \
            fprintf(OUT_FILE, "ASSERT_%s : %s : %d\n",#cond, __FILE__, __LINE__); \
            CRASH();                                                                                                        \
        }                                                                                                                 \
    } while (0)
#endif //TRACING_H
