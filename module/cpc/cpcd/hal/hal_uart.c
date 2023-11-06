/**
 * @file hal_uart.c
 * @author Rex Huang (rex.huang@rafaelmicro.com)
 * @brief
 * @version 0.1
 * @date 2023-10-30
 *
 *
 */
#define _GNU_SOURCE

#include <pthread.h>

#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <signal.h>
#include <linux/serial.h>

#include "utility/config.h"
#include "utility/logs.h"
#include "utility/sleep.h"
#include "utility/utils.h"
#include "hal/hal_uart.h"
#include "primary/cpcd/hdlc.h"
#include "primary/cpcd/crc.h"
#include "hal/hal_kill.h"

//=============================================================================
//                  Constant Definition
//=============================================================================
//=============================================================================
//                  Macro Definition
//=============================================================================
#define UART_BUFFER_SIZE 4096 + CPC_HDLC_HEADER_RAW_SIZE
#define MAX_EPOLL_EVENTS 1
//=============================================================================
//                  Structure Definition
//=============================================================================
typedef struct notify_private_data
{
    int timer_file_descriptor;
}notify_private_data_t;


//=============================================================================
//                  Global Data Definition
//=============================================================================
static int fd_uart;
static int fd_cpcd;
static int fd_cpcd_notify;
static int fd_stop_drv;
static unsigned int device_baudrate = 0;
static pthread_t rx_drv_thread;
static pthread_t tx_drv_thread;
static pthread_t cleanup_thread;
static const struct
{
    unsigned int val;
    int symbolic;
} conversion[] = {
    { 9600, B9600 },
    { 115200, B115200 },
    { 500000, B500000 },
    { 2000000, B2000000 },
};
//=============================================================================
//                  Private Function Definition
//=============================================================================
static bool __hdlc_header_validate(uint8_t *header_start)
{
    uint16_t hcs;

    if (header_start[CPC_HDLC_FLAG_POS] != CPC_HDLC_FLAG_VAL)
    {
        return false;
    }

    hcs = hdlc_get_hcs(header_start);

    if (!cpc_check_crc_sw(header_start, CPC_HDLC_HEADER_SIZE, hcs))
    {
        TRACE_HAL_INVALID_HEADER_CHECKSUM();
        return false;
    }

    return true;
}

static bool __sync_header(uint8_t *buffer, size_t *buffer_head)
{
    size_t num_header_combination, i;
    if (*buffer_head < CPC_HDLC_HEADER_RAW_SIZE)
    {
        return false;
    }

    num_header_combination = *buffer_head - CPC_HDLC_HEADER_RAW_SIZE + 1;

    for (i = 0; i != num_header_combination; i++)
    {
        if (__hdlc_header_validate(&buffer[i]))
        {
            if (i != 0)
            {
                memmove(&buffer[0], &buffer[i], *buffer_head - i);
                *buffer_head -= i;
            }
            return true;
        }
    }
    memmove(&buffer[0], &buffer[num_header_combination], CPC_HDLC_HEADER_RAW_SIZE - 1);
    *buffer_head = CPC_HDLC_HEADER_RAW_SIZE - 1;

    return false;
}

static bool __push_valid_hdlc_frame(uint8_t *buffer, size_t *buffer_head)
{
    uint16_t payload_len;
    size_t frame_size, remaining_bytes;

    if (*buffer_head < CPC_HDLC_HEADER_RAW_SIZE)
    {
        return false;
    }

    payload_len = hdlc_get_length(buffer);

    frame_size = payload_len + CPC_HDLC_HEADER_RAW_SIZE;

    if (frame_size > *buffer_head)
    {
        return false;
    }

    write(fd_cpcd, buffer, frame_size);

    remaining_bytes = *buffer_head - frame_size;
    memmove(buffer, &buffer[frame_size], remaining_bytes);
    *buffer_head = remaining_bytes;

    return true;
}

/* Append UART new data to the frame delimiter processing buffer */
static size_t __hal_uart_get_fd_data(uint8_t *buffer, size_t buffer_head, size_t buffer_size)
{
    uint8_t temp_buffer[UART_BUFFER_SIZE];

    ASSERT_ON(buffer_head >= buffer_size);

    /* Make sure we don't read more data than the supplied buffer can handle */
    const size_t available_space = buffer_size - buffer_head - 1;

    /* Read the uart data into the temp buffer */
    ssize_t read_retval = read(fd_uart, temp_buffer, available_space);
    ERROR_ON(read_retval < 0);

    /* copy the data in the main buffer */
    memcpy(&buffer[buffer_head], temp_buffer, (size_t)read_retval);

    return (size_t)read_retval;
}


static long __drain_ns(uint32_t bytes_left)
{
    uint64_t nanoseconds;
    uint64_t bytes_per_sec = device_baudrate / 8;

    nanoseconds = bytes_left * (uint64_t)1000000000 / bytes_per_sec;

    return (long)(nanoseconds);
}

static void __hal_uart_proc(void)
{
    int ret;
    int length;
    static uint8_t __hal_uart_buffer[UART_BUFFER_SIZE];
    ssize_t read_retval, write_retval;
    struct timespec txd_timestamp;

    read_retval = read(fd_cpcd, __hal_uart_buffer, sizeof(__hal_uart_buffer));

    ERROR_SYSCALL_ON(read_retval < 0);

    write_retval = write(fd_uart, __hal_uart_buffer, (size_t)read_retval);

    ERROR_SYSCALL_ON(write_retval < 0);

    ERROR_ON((size_t)write_retval != (size_t)read_retval);

    ret = ioctl(fd_uart, TIOCOUTQ, &length);
    ERROR_SYSCALL_ON(ret < 0);

    clock_gettime(CLOCK_MONOTONIC, &txd_timestamp);

    if (txd_timestamp.tv_nsec + __drain_ns((uint32_t)length) > 1000000000)
    {
        txd_timestamp.tv_sec += (txd_timestamp.tv_nsec + __drain_ns((uint32_t)length)) / 1000000000;
    }
    txd_timestamp.tv_nsec += __drain_ns((uint32_t)length);
    txd_timestamp.tv_nsec %= 1000000000;

    write_retval = write(fd_cpcd_notify, &txd_timestamp, sizeof(txd_timestamp));
    ERROR_SYSCALL_ON(write_retval != sizeof(txd_timestamp));
}

static void __hal_uart_proc_fd(void)
{
    static uint8_t __hal_uart_fd_buffer[UART_BUFFER_SIZE];
    static size_t buffer_head = 0;
    static enum { EXPECTING_HEADER, EXPECTING_PAYLOAD } state = EXPECTING_HEADER;

    /* Put the read data at the tip of the buffer head and increment it. */
    buffer_head += __hal_uart_get_fd_data(__hal_uart_fd_buffer, buffer_head, sizeof(__hal_uart_fd_buffer));

    while (1)
    {
        switch (state)
        {
        case EXPECTING_HEADER:
            /* Synchronize the start of 'buffer' with the start of a valid header with valid checksum. */
            if (__sync_header(__hal_uart_fd_buffer, &buffer_head))
            {
                /* We are synchronized on a valid header, start delimiting the data that follows into a frame. */
                state = EXPECTING_PAYLOAD;
            } else
            {
                /* We went through all the data contained in 'buffer' and haven't synchronized on a header.
                 * Go back to waiting for more data. */
                return;
            }
            break;

        case EXPECTING_PAYLOAD:
            if (__push_valid_hdlc_frame(__hal_uart_fd_buffer, &buffer_head))
            {
                /* A frame has been delimited and pushed to the cpcd, go back to synchronizing on the next header */
                state = EXPECTING_HEADER;
            } else
            {
                /* Not yet enough data, go back to waiting. */
                return;
            }
            break;
        default:
            break;
        }
    }
}

static void *__hal_uart_cleanup_thd(void *param)
{
    (void)param;

    // wait for threads to exit
    pthread_join(tx_drv_thread, NULL);
    pthread_join(rx_drv_thread, NULL);

    TRACE_HAL("UART thd cancelled");

    close(fd_uart);
    close(fd_cpcd);
    close(fd_cpcd_notify);
    close(fd_stop_drv);

    pthread_exit(0);
    return NULL;
}

static void *__hal_uart_transmit_thd(void *param)
{
    struct epoll_event ep_event[2] = { { .events = EPOLLIN, .data.fd = fd_cpcd }, { .events = EPOLLIN, .data.fd = fd_stop_drv } };
    bool exit_thread = false;
    size_t event_i;
    int fd_epoll, event_count, ret, current_event_fd;

    (void)param;

    TRACE_HAL("Transmitter thread start");

    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    ERROR_SYSCALL_ON(fd_epoll < 0);


    ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_cpcd, &ep_event[0]);
    ERROR_SYSCALL_ON(ret < 0);

    ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_stop_drv, &ep_event[1]);
    ERROR_SYSCALL_ON(ret < 0);

    while (!exit_thread)
    {
        do
        {
            event_count = epoll_wait(fd_epoll, ep_event, 2, -1);
            if (event_count == -1 && errno == EINTR)
            {
                continue;
            }
            ERROR_SYSCALL_ON(event_count == -1);
            break;
        } while (1);


        for (event_i = 0; event_i != (size_t)event_count; event_i++)
        {
            current_event_fd = ep_event[event_i].data.fd;

            if (current_event_fd == fd_cpcd)
            {
                __hal_uart_proc();
            } else if (current_event_fd == fd_stop_drv)
            {
                exit_thread = true;
            }
        }
    }

    close(fd_epoll);

    return 0;
}

static void *__hal_uart_receive_thd(void *param)
{
    struct epoll_event ep_event[2] = { { .events = EPOLLIN, .data.fd = fd_uart }, { .events = EPOLLIN, .data.fd = fd_stop_drv } };
    bool exit_thread = false;
    int fd_epoll;
    int event_count, ret, current_event_fd;
    size_t event_i;

    (void)param;

    TRACE_HAL("Receiver thread start");

    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    ERROR_SYSCALL_ON(fd_epoll < 0);

    ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_uart, &ep_event[0]);
    ERROR_SYSCALL_ON(ret < 0);

    ret = epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_stop_drv, &ep_event[1]);
    ERROR_SYSCALL_ON(ret < 0);

    while (!exit_thread)
    {
        do
        {
            event_count = epoll_wait(fd_epoll, ep_event, 2, -1);
            if (event_count == -1 && errno == EINTR)
            {
                continue;
            }
            ERROR_SYSCALL_ON(event_count == -1);
            break;
        } while (1);

        for (event_i = 0; event_i != (size_t)event_count; event_i++)
        {
            current_event_fd = ep_event[event_i].data.fd;

            if (current_event_fd == fd_uart)
            {
                __hal_uart_proc_fd();
            } else if (current_event_fd == fd_stop_drv)
            {
                exit_thread = true;
            }
        }
    }

    close(fd_epoll);

    return 0;
}

void hal_uart_assert_rts(bool assert)
{
    int ret;
    int flag = TIOCM_RTS;

    ERROR_ON(fd_uart < 0);

    if (assert)
    {
        ret = ioctl(fd_uart, TIOCMBIS, &flag);
    } else
    {
        ret = ioctl(fd_uart, TIOCMBIC, &flag);
    }

    ERROR_SYSCALL_ON(ret < 0);
}

pthread_t hal_uart_init(int *fd_to_cpcd, int *fd_notify_cpcd, const char *device, unsigned int baudrate, bool hardflow)
{
    int fd_sockets[2];
    int fd_sockets_notify[2];
    ssize_t ret;

    fd_uart = hal_uart_open(device, baudrate, hardflow);

    /* Flush the uart IO fifo */

    tcflush(fd_uart, TCIOFLUSH);

    ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets);
    ERROR_SYSCALL_ON(ret < 0);

    fd_cpcd = fd_sockets[0];
    *fd_to_cpcd = fd_sockets[1];

    ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets_notify);
    ERROR_SYSCALL_ON(ret < 0);

    fd_cpcd_notify = fd_sockets_notify[0];
    *fd_notify_cpcd = fd_sockets_notify[1];

    fd_stop_drv = hal_kill_init();

    /* create transmitter thread */
    ret = pthread_create(&tx_drv_thread, NULL, __hal_uart_transmit_thd, NULL);
    ERROR_ON(ret != 0);

    /* create receiver thread */
    ret = pthread_create(&rx_drv_thread, NULL, __hal_uart_receive_thd, NULL);
    ERROR_ON(ret != 0);

    /* create cleanup thread */
    ret = pthread_create(&cleanup_thread, NULL, __hal_uart_cleanup_thd, NULL);
    ERROR_ON(ret != 0);

    ret = pthread_setname_np(tx_drv_thread, "tx_drv_thread");
    ERROR_ON(ret != 0);

    ret = pthread_setname_np(rx_drv_thread, "rx_drv_thread");
    ERROR_ON(ret != 0);

    TRACE_HAL("Opening uart file %s", device);

    TRACE_HAL("Init done");

    return cleanup_thread;
}

void hal_uart_print_overruns(void)
{
    struct serial_icounter_struct counters;
    int retval = ioctl(fd_uart, TIOCGICOUNT, &counters);
    ERROR_SYSCALL_ON(retval < 0);
    TRACE_HAL("Overruns %d,%d", counters.overrun, counters.buf_overrun);
}

int hal_uart_open(const char *device, unsigned int baudrate, bool hardflow)
{
    struct termios tty;
    int sym_baudrate = -1;
    int fd;

    fd = open(device, O_RDWR | O_CLOEXEC);
    ERROR_SYSCALL_ON(fd < 0);

    ERROR_SYSCALL_ON(tcgetattr(fd, &tty) < 0);

    size_t i;
    for (i = 0; i < ARRAY_SIZE(conversion); i++)
    {
        if (conversion[i].val == baudrate)
        {
            sym_baudrate = conversion[i].symbolic;
        }
    }

    if (sym_baudrate < 0)
    {
        ERROR("invalid baudrate: %d", baudrate);
    }

    cfsetispeed(&tty, (speed_t)sym_baudrate);
    cfsetospeed(&tty, (speed_t)sym_baudrate);
    cfmakeraw(&tty);
    /* Nonblocking read. */
    tty.c_cc[VTIME] = 0;
    tty.c_cc[VMIN] = 1;
    tty.c_iflag &= (unsigned)~(IXON);
    tty.c_iflag &= (unsigned)~(IXOFF);
    tty.c_iflag &= (unsigned)~(IXANY);
    tty.c_cflag &= (unsigned)~(HUPCL);
    tty.c_cflag |= CLOCAL;
    if (hardflow)
    {
        tty.c_cflag |= CRTSCTS;
    } else
    {
        tty.c_cflag &= ~CRTSCTS;
    }

    ERROR_SYSCALL_ON(tcsetattr(fd, TCSANOW, &tty) < 0);

    /* Flush the content of the UART in case there was stale data */
    {
        /* There was once a bug in the kernel requiring a delay before flushing the uart.
         * Keep it there for backward compatibility */
        sleep_ms(10);

        tcflush(fd, TCIOFLUSH);
    }

    device_baudrate = baudrate;

    return fd;
}