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
#include "utility/log.h"
#include "host/hal_sleep.h"
#include "utility/utility.h"
#include "host/hal_uart.h"
#include "daemon/hdlc/core.h"
#include "host/hal_kill.h"

//=============================================================================
//                  Constant Definition
//=============================================================================
//=============================================================================
//                  Macro Definition
//=============================================================================
#define UART_BUFFER_SIZE 4096 + HDLC_HEADER_RAW_SIZE
#define MAX_EPOLL_EVENTS 2
#define EPOLL_TIMEOUT -1
#define UNIT_1G 1000000000
//=============================================================================
//                  Structure Definition
//=============================================================================
typedef struct notify_private_data
{
    int timer_file_descriptor;
} notify_private_data_t;

typedef struct uartConfig
{
    unsigned int val;
    int symbolic;
} uartConfig_t;

typedef enum { PROC_HEADER, PROC_DATA } PROC_STATE;
//=============================================================================
//                  Global Data Definition
//=============================================================================
static int fd_uart;
static int fd_cpcd;
static int fd_cpcd_notify;
static int fd_stop;
static int fd_dev_uart;
static unsigned int drv_baudrate = 0;
static pthread_t rx_drv_thread;
static pthread_t tx_drv_thread;
static pthread_t cleanup_thread;

static size_t g_uart_baudrate_idx = 0;
static uartConfig_t uart_config[] = {
    { 9600,    B9600 },
    { 115200,  B115200 },
    { 500000,  B500000 },
    { 2000000, B2000000 },
};
//=============================================================================
//                  Private Function Definition
//=============================================================================
static bool __hdlc_header_validate(uint8_t *hdr)
{
    uint16_t hcs = 0;
    if (hdr[HDLC_FLAG_POS] != HDLC_FLAG_VAL) return false;

    hcs = (uint16_t)(hdr[HDLC_HCS_POS] | (hdr[HDLC_HCS_POS + 1] << 8));


    if (!core_check_crc_sw(hdr, HDLC_HEADER_SIZE, hcs))
    {
        primary_cpcd_debug_counters.invalid_header_checksum++;
        log_error("invalid header checksum in driver");
        return false;
    }

    return true;
}

static bool __sync_header(uint8_t *buffer, size_t *pos)
{
    size_t num_header_combination;

    if (*pos < HDLC_HEADER_RAW_SIZE) return false;

    num_header_combination = *pos - HDLC_HEADER_RAW_SIZE + 1;

    for (size_t i = 0; i < num_header_combination; i++)
    {
        if (__hdlc_header_validate(&buffer[i]))
        {
            if (i != 0)
            {
                memmove(&buffer[0], &buffer[i], *pos - i);
                *pos -= i;
            }
            return true;
        }
    }
    memmove(&buffer[0], &buffer[num_header_combination], HDLC_HEADER_RAW_SIZE - 1);
    *pos = HDLC_HEADER_RAW_SIZE - 1;

    return false;
}

static bool __push_valid_hdlc_frame(uint8_t *buffer, size_t *pos)
{
    uint16_t payload_len = 0;
    size_t frame_size = 0;
    size_t remaining = 0;

    if (*pos < HDLC_HEADER_RAW_SIZE) return false;

    payload_len = (uint16_t)(buffer[HDLC_LENGTH_POS] | (buffer[HDLC_LENGTH_POS + 1] << 8));

    // log_info("length: %d", payload_len);
    frame_size = payload_len + HDLC_HEADER_RAW_SIZE;

    if (frame_size > *pos) return false;
    // log_info_hexdump("[uart rx]", buffer, frame_size);
    write(fd_cpcd, buffer, frame_size);

    remaining = *pos - frame_size;
    memmove(buffer, &buffer[frame_size], remaining);
    *pos = remaining;

    return true;
}

static size_t __hal_uart_get_fd_data(uint8_t *buffer, size_t pos, size_t size)
{
    uint8_t temp[UART_BUFFER_SIZE];

    CHECK_ERROR(pos >= size);

    const size_t available_space = size - pos - 1;

    ssize_t val = read(fd_uart, temp, available_space);
    CHECK_ERROR(val < 0);

    memcpy(&buffer[pos], temp, (size_t)val);

    return (size_t)val;
}


static long __drain_ns(uint32_t bytes_left)
{
    uint64_t bytes_per_sec = drv_baudrate / 8;
    return (long)(bytes_left * (uint64_t)UNIT_1G / bytes_per_sec);
}

static void __hal_uart_proc(void)
{
    int length = 0;
    static uint8_t uart_buffer[UART_BUFFER_SIZE] = {0};
    ssize_t rval = 0;
    ssize_t wval = 0;
    struct timespec t = {0};

    rval = read(fd_cpcd, uart_buffer, sizeof(uart_buffer));
    CHECK_ERROR(rval < 0);

    // log_info_hexdump("[uart tx]", uart_buffer, rval);
    wval = write(fd_uart, uart_buffer, (size_t)rval);
    CHECK_ERROR(wval < 0);
    CHECK_ERROR((size_t)wval != (size_t)rval);

    CHECK_ERROR(ioctl(fd_uart, TIOCOUTQ, &length) < 0);

    clock_gettime(CLOCK_MONOTONIC, &t);

    long ns = __drain_ns((uint32_t)length);
    if (t.tv_nsec + ns > UNIT_1G) t.tv_sec += (t.tv_nsec + ns) / UNIT_1G;
    t.tv_nsec += ns;
    t.tv_nsec %= UNIT_1G;

    wval = write(fd_cpcd_notify, &t, sizeof(t));
    CHECK_ERROR(wval != sizeof(t));
}

static void __hal_uart_proc_fd(void)
{
    static uint8_t uart_buffer[UART_BUFFER_SIZE] = {0};
    static size_t pos = 0;
    static PROC_STATE state = PROC_HEADER;

    pos += __hal_uart_get_fd_data(uart_buffer, pos, sizeof(uart_buffer));

    do
    {
        switch (state)
        {
        case PROC_HEADER:
            if (__sync_header(uart_buffer, &pos))
            {
                state = PROC_DATA;
                // log_debug_hexdump("PROC_HEADER", uart_buffer, pos);
                break;
            } 

            return;

        case PROC_DATA:
            if (__push_valid_hdlc_frame(uart_buffer, &pos))
            {
                state = PROC_HEADER;
                // log_debug_hexdump("PROC_DATA", uart_buffer, pos);
                break;
            } 

            return;

        default:
            break;
        }
    } while(1);
}

static void *__hal_uart_cleanup_thd(void *arg)
{
    (void)arg;

    pthread_join(tx_drv_thread, NULL);
    pthread_join(rx_drv_thread, NULL);

    log_info("UART thd cancelled");

    close(fd_uart);
    close(fd_cpcd);
    close(fd_cpcd_notify);
    close(fd_stop);

    pthread_exit(0);
    return NULL;
}

static void *__hal_uart_transmit_thd(void *arg)
{
    bool running = false;
    int fd_epoll = 0;
    int cnt = 0;
    struct epoll_event event[MAX_EPOLL_EVENTS] = 
    {
        {.events = EPOLLIN, .data.fd = fd_cpcd},
        {.events = EPOLLIN, .data.fd = fd_stop}
    };

    (void)arg;

    log_info("[HAL] uart tx thread start");

    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK_ERROR(fd_epoll < 0);

    CHECK_ERROR(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_cpcd, &event[0]) < 0);
    CHECK_ERROR(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_stop, &event[1]) < 0);

    while (!running)
    {
        do
        {
            cnt = epoll_wait(fd_epoll, event, MAX_EPOLL_EVENTS, EPOLL_TIMEOUT);
        } while ((cnt == -1) && (errno == EINTR));

        for (int i = 0; i < cnt; i++)
        {
            if (fd_cpcd == event[i].data.fd) __hal_uart_proc();
            else if (fd_stop == event[i].data.fd) running = true;
        }
    }

    close(fd_epoll);
    return 0;
}

static void *__hal_uart_receive_thd(void *arg)
{
    bool running = false;
    int fd_epoll = 0;
    int cnt = 0;
    struct epoll_event event[MAX_EPOLL_EVENTS] = 
    {
        {.events = EPOLLIN, .data.fd = fd_uart},
        {.events = EPOLLIN, .data.fd = fd_stop}
    };

    (void)arg;

    log_info("[HAL] uart rx thread start");

    fd_epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK_ERROR(fd_epoll < 0);

    CHECK_ERROR(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_uart, &event[0]) < 0);
    CHECK_ERROR(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_stop, &event[1]) < 0);

    while (!running)
    {
        do
        {
            cnt = epoll_wait(fd_epoll, event, MAX_EPOLL_EVENTS, EPOLL_TIMEOUT);
        } while ((cnt == -1) && (errno == EINTR));

        for (int i = 0; i < cnt; i++)
        {
            if (fd_uart == event[i].data.fd) __hal_uart_proc_fd();
            else if (fd_stop == event[i].data.fd) running = true;
        }
    }

    close(fd_epoll);
    return 0;
}

void hal_uart_assert_rts(bool assert)
{
    int flag = TIOCM_RTS;
    CHECK_ERROR(fd_uart < 0);
    CHECK_ERROR(ioctl(fd_uart, (assert)? TIOCMBIS : TIOCMBIC, &flag) < 0);
}

void hal_uart_change_baudrate(void)
{
    struct termios tty = {0};
    int sym_baudrate = -1;

    CHECK_ERROR(fd_dev_uart < 0);
    CHECK_ERROR(tcgetattr(fd_dev_uart, &tty) < 0);

    g_uart_baudrate_idx++;
    g_uart_baudrate_idx %=4;

    log_info("change baudrate %d", uart_config[g_uart_baudrate_idx].val);

    sym_baudrate = uart_config[g_uart_baudrate_idx].symbolic;

    cfsetispeed(&tty, (speed_t)sym_baudrate);
    cfsetospeed(&tty, (speed_t)sym_baudrate);
    cfmakeraw(&tty);

    CHECK_ERROR(tcsetattr(fd_dev_uart, TCSANOW, &tty) < 0);

    drv_baudrate = uart_config[g_uart_baudrate_idx].val;    
}

pthread_t hal_uart_init(int *fd_to_cpcd, int *fd_notify_cpcd, const char *device, unsigned int baudrate, bool hardflow)
{
    int fd_sockets[2];
    int fd_sockets_notify[2];

    // log_info("%s", __FUNCTION__);
    log_info("[HAL] dev: %s, baudrate: %d, hardflow: %d", device, baudrate, hardflow);
    fd_uart = hal_uart_open(device, baudrate, hardflow);

    hal_sleep_ms(10);
    tcflush(fd_uart, TCIOFLUSH);

    CHECK_ERROR(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets) < 0);
    fd_cpcd = fd_sockets[0];
    *fd_to_cpcd = fd_sockets[1];

    CHECK_ERROR(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd_sockets_notify) < 0);
    fd_cpcd_notify = fd_sockets_notify[0];
    *fd_notify_cpcd = fd_sockets_notify[1];

    fd_stop = hal_kill_init();

    CHECK_ERROR(pthread_create(&tx_drv_thread, NULL, __hal_uart_transmit_thd, NULL) != 0);
    CHECK_ERROR(pthread_create(&rx_drv_thread, NULL, __hal_uart_receive_thd, NULL) != 0);
    CHECK_ERROR(pthread_create(&cleanup_thread, NULL, __hal_uart_cleanup_thd, NULL) != 0);

    CHECK_ERROR(pthread_setname_np(tx_drv_thread, "tx_drv_thread") != 0);
    CHECK_ERROR(pthread_setname_np(rx_drv_thread, "rx_drv_thread") != 0);
    
    log_info("[HAL] Opening uart file %s", device);
    log_info("[HAL] Init done");
    return cleanup_thread;
}

// void hal_uart_print_overruns(void)
// {
//     struct serial_icounter_struct counters;
//     int retval = ioctl(fd_uart, TIOCGICOUNT, &counters);
//     CHECK_ERROR(retval < 0);
//     log_info("[HAL] Overruns %d,%d", counters.overrun, counters.buf_overrun);
// }

int hal_uart_open(const char *device, unsigned int baudrate, bool hardflow)
{
    struct termios tty = {0};
    int sym_baudrate = -1;

    log_info("opening %s", device);
    fd_dev_uart = open(device, O_RDWR | O_CLOEXEC);
    CHECK_ERROR(fd_dev_uart < 0);
    CHECK_ERROR(tcgetattr(fd_dev_uart, &tty) < 0);

    for (size_t i = 0; i < sizeof(uart_config) / sizeof(uartConfig_t); i++)
    {
        if (uart_config[i].val == baudrate) 
        {
            sym_baudrate = uart_config[i].symbolic;
            g_uart_baudrate_idx = i;
            break;
        }
    }

    if (sym_baudrate < 0) log_info("wrong baudrate: %d", baudrate);

    cfsetispeed(&tty, (speed_t)sym_baudrate);
    cfsetospeed(&tty, (speed_t)sym_baudrate);
    cfmakeraw(&tty);

    drv_baudrate = baudrate;

    // Nonblocking
    tty.c_cc[VTIME] = 0;
    tty.c_cc[VMIN] = 1;
    tty.c_iflag &= (unsigned)~(IXON);
    tty.c_iflag &= (unsigned)~(IXOFF);
    tty.c_iflag &= (unsigned)~(IXANY);
    tty.c_cflag &= (unsigned)~(HUPCL);
    tty.c_cflag |= CLOCAL;
    tty.c_cflag = hardflow ? (tty.c_cflag | CRTSCTS) : (tty.c_cflag & ~CRTSCTS); 

    CHECK_ERROR(tcsetattr(fd_dev_uart, TCSANOW, &tty) < 0);
    return fd_dev_uart;
}