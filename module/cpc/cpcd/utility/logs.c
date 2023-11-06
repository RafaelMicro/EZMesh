
#define _GNU_SOURCE
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <sys/statfs.h>
#include <sys/timerfd.h>
#include <linux/magic.h>

#include "utility/logs.h"
#include "primary/epoll_port/epoll_port.h"
#include "config.h"
#include "utils.h"

static union
{
    uint16_t hex;
    char nibble[2];
} hex_str;

#define NO_LOGGING_ERROR_ON(cond)                                                                                                \
    do {                                                                                                                           \
        if (cond) {                                                                                                                  \
            fprintf(stderr, "NO LOGGER FATAL on '%s' in function '%s' in file %s  at line #%d\n",#cond, __func__, __FILE__, __LINE__); \
            exit(EXIT_FAILURE);                                                                                                        \
        }                                                                                                                            \
    } while (0)

#define NO_LOGGING_ERROR_SYSCALL_ON(cond)                                                                                                     \
    do {                                                                                                                                        \
        if (cond) {                                                                                                                               \
            fprintf(stderr, "NO LOGGER FATAL SYSCALL on '%s' in function '%s' in file %s  at line #%d : %m\n",#cond, __func__, __FILE__, __LINE__); \
            exit(EXIT_FAILURE);                                                                                                                     \
        }                                                                                                                                         \
    } while (0)

static void write_until_success_or_error(int fd, uint8_t *buff, size_t size)
{
    ssize_t ret;
    size_t written = 0;
    size_t remaining = size;

    do
    {
        ret = write(fd, &buff[written], remaining);
        NO_LOGGING_ERROR_SYSCALL_ON(ret < 0);
        remaining -= (size_t)ret;
        written += (size_t)ret;
    } while (remaining != 0);
}

#define ASYNC_LOGGER_PAGE_SIZE    4096
#define ASYNC_LOGGER_PAGE_COUNT   7
#define ASYNC_LOGGER_BUFFER_DEPTH (ASYNC_LOGGER_PAGE_SIZE * ASYNC_LOGGER_PAGE_COUNT)
#define ASYNC_LOGGER_TIMEOUT_MS   100
#define ASYNC_LOGGER_DONT_TRIGG_UNLESS_THIS_CHUNK_SIZE ASYNC_LOGGER_PAGE_SIZE

static volatile bool gracefully_exit = false;

static int stats_timer_fd;

static const char lut[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

typedef struct
{
    FILE *file;
    int fd;
    uint8_t *buffer;
    volatile size_t buffer_size;
    volatile size_t buffer_head;
    volatile size_t buffer_tail;
    volatile size_t buffer_count;
    size_t highwater_mark;
    size_t lost_logs;
    pthread_cond_t condition;
    pthread_mutex_t mutex;
    struct timespec timeout;
    const char *name;
} async_logger_t;

static async_logger_t file_logger;
static async_logger_t stdout_logger;

static pthread_t file_logger_thread;
static pthread_t stdout_logger_thread;

static epoll_port_private_data_t *logging_private_data;

static void *async_logger_thread_func(void *param);

static void async_logger_init(async_logger_t *logger, int file_descriptor, const char *name)
{
    int ret;

    NO_LOGGING_ERROR_ON(logger == NULL);

    logger->fd = file_descriptor;
    logger->buffer_size = ASYNC_LOGGER_BUFFER_DEPTH;
    logger->buffer_head = 0;
    logger->buffer_tail = 0;
    logger->buffer_count = 0;
    logger->highwater_mark = 0;
    logger->lost_logs = 0;
    logger->name = name;

    ret = pthread_cond_init(&logger->condition, NULL);
    NO_LOGGING_ERROR_ON(ret != 0);

    ret = pthread_mutex_init(&logger->mutex, NULL);
    NO_LOGGING_ERROR_ON(ret != 0);

    logger->buffer = calloc_port(logger->buffer_size);
    NO_LOGGING_ERROR_ON(logger->buffer == NULL);

    /* Lock the buffer in RAM since it's a long buffer and we will use it often to prevent
     * page faults. */
    ret = mlock(logger->buffer,
                logger->buffer_size);
    NO_LOGGING_ERROR_SYSCALL_ON(ret != 0);

    logger->timeout.tv_sec = ASYNC_LOGGER_TIMEOUT_MS / 1000;
    logger->timeout.tv_nsec = (ASYNC_LOGGER_TIMEOUT_MS % 1000) * 1000000;
}

static void stdout_logging_init(void)
{
    int ret;

    async_logger_init(&stdout_logger, STDOUT_FILENO, "stdout");

    ret = pthread_create(&stdout_logger_thread,
                         NULL,
                         async_logger_thread_func,
                         &stdout_logger);
    NO_LOGGING_ERROR_ON(ret != 0);

    pthread_setname_np(stdout_logger_thread, "stdout_logger");
}

static void file_logging_init(void)
{
    int ret;
    struct statfs statfs_buf;

    ret = mkdir(config.traces_folder, 0700);
    NO_LOGGING_ERROR_SYSCALL_ON(ret < 0 && errno != EEXIST);

    ret = statfs(config.traces_folder, &statfs_buf);
    NO_LOGGING_ERROR_SYSCALL_ON(ret < 0);
    if (statfs_buf.f_type != TMPFS_MAGIC)
    {
        WARN("Traces folder %s is not mounted on a tmpfs", config.traces_folder);
    }

    ret = access(config.traces_folder, W_OK);
    NO_LOGGING_ERROR_SYSCALL_ON(ret < 0);

    /* Build file string and open file */
    {
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        char buf[512];
        int nchars;

        nchars = snprintf(buf,
                          sizeof(buf),
                          "%s/trace-%d-%02d-%02d_%02d-%02d-%02d.log",
                          config.traces_folder,
                          tm.tm_year + 1900,
                          tm.tm_mon + 1,
                          tm.tm_mday,
                          tm.tm_hour,
                          tm.tm_min,
                          tm.tm_sec);

        /* Make sure the path fitted entirely in the struct's static buffer */
        NO_LOGGING_ERROR_SYSCALL_ON(nchars < 0 || (size_t)nchars >= sizeof(buf));

        file_logger.file = fopen(buf, "w+");
        NO_LOGGING_ERROR_SYSCALL_ON(file_logger.file == NULL);

        PRINT_INFO("Logging to file enabled in file %s.", buf);
    }

    file_logger.fd = fileno(file_logger.file);

    ret = pthread_create(&file_logger_thread,
                         NULL,
                         async_logger_thread_func,
                         &file_logger);
    NO_LOGGING_ERROR_ON(ret != 0);

    pthread_setname_np(file_logger_thread, "file_logger");
}

static void async_logger_write(async_logger_t *logger, void *data, size_t length)
{
    bool do_signal = false;
    size_t count_cpy;

    pthread_mutex_lock(&logger->mutex);
    {
        if (logger->buffer_size - logger->buffer_count < length)
        {
            /* Overflowing traces are discarded */
            fprintf(stderr, "WARNING : %s logger buffer full, lost log.\n", logger->name);
            logger->lost_logs++;
        } else
        {
            size_t remaining = logger->buffer_size - logger->buffer_head;

            if (remaining >= length)
            {
                memcpy(&logger->buffer[logger->buffer_head], data, length);
                logger->buffer_head += length;
            } else /* Split write at buffer boundary */
            {
                memcpy(&logger->buffer[logger->buffer_head], data, remaining);
                memcpy(&logger->buffer[0], data + remaining, length - remaining);
                logger->buffer_head = length - remaining;
            }

            logger->buffer_count += length;

            /* Register the high water mark */
            if (logger->buffer_count > logger->highwater_mark)
            {
                logger->highwater_mark = logger->buffer_count;
            }

            do_signal = true;
            count_cpy = logger->buffer_count;
        }
    }
    pthread_mutex_unlock(&logger->mutex);

    if (do_signal == true)
    {
        if (count_cpy >= ASYNC_LOGGER_DONT_TRIGG_UNLESS_THIS_CHUNK_SIZE)
        {
            pthread_cond_signal(&logger->condition);
        }
    }
}

static void *async_logger_thread_func(void *param)
{
    async_logger_t *logger = (async_logger_t *)param;
    size_t chunk_size;
    ssize_t ret;

    while (1)
    {
        pthread_mutex_lock(&logger->mutex);
        {
            while (logger->buffer_count < ASYNC_LOGGER_DONT_TRIGG_UNLESS_THIS_CHUNK_SIZE && gracefully_exit == false)
            {
                struct timespec max_wait;

                clock_gettime(CLOCK_REALTIME, &max_wait);

                max_wait.tv_sec++;

                ret = pthread_cond_timedwait(&logger->condition,
                                             &logger->mutex,
                                             &max_wait);
                ERROR_ON(ret != 0 && ret != ETIMEDOUT);

                if (ret == ETIMEDOUT)
                {
                    break;
                }
            }

            /* We will write as much data as we have on hand */
            chunk_size = logger->buffer_count;
        } /* Unlock the mutex to allow other threads to continue to write data. */
        pthread_mutex_unlock(&logger->mutex);

        if (chunk_size == 0)
        {
            if (gracefully_exit == true)
            {
                /* Graceful exit requested and no data, kill this thread right away. */
                char buf[256];
                int ret;
                ret = snprintf(buf,
                               sizeof(buf),
                               "Logger buffer size = %zu, highwater mark = %zu : %.2f%%. Lost logs : %zu\n",
                               logger->buffer_size,
                               logger->highwater_mark,
                               100.0f * ((float)logger->highwater_mark / (float)logger->buffer_size),
                               logger->lost_logs);
                /* Dont check for 'ret' overflow, we know 256 bytes was sufficient. */
                (void)write(logger->fd, buf, (size_t)ret);
                fsync(logger->fd);
                if (logger->fd != STDOUT_FILENO)
                {
                    ret = fclose(logger->file);
                    ERROR_ON(ret != 0);
                }
                free(logger->buffer);
                pthread_exit(NULL);
            } else
            {
                continue;
            }
        }

        size_t remaining = logger->buffer_size - logger->buffer_tail;

        {
            if (remaining >= chunk_size)
            {
                write_until_success_or_error(logger->fd,
                                             &logger->buffer[logger->buffer_tail],
                                             chunk_size);
            } else /* Split write at the buffer boundary */
            {
                write_until_success_or_error(logger->fd,
                                             &logger->buffer[logger->buffer_tail],
                                             remaining);

                write_until_success_or_error(logger->fd,
                                             &logger->buffer[0],
                                             chunk_size - remaining);
            }
        }

        pthread_mutex_lock(&logger->mutex);
        {
            if (remaining >= chunk_size)
            {
                logger->buffer_tail += chunk_size;
            } else
            {
                logger->buffer_tail = chunk_size - remaining;
            }

            logger->buffer_count -= chunk_size;
        }
        pthread_mutex_unlock(&logger->mutex);
    }

    return NULL;
}

static void stdio_log(void *data, size_t length)
{
    async_logger_write(&stdout_logger, data, length);
}

static void file_log(void *data, size_t length)
{
    async_logger_write(&file_logger, data, length);
}

void logging_init(void)
{
    stdout_logging_init();

    async_logger_init(&file_logger,
                      -1, /* No file descriptor for the moment */
                      "file");
}

static void logging_print_stats(epoll_port_private_data_t *event_private_data)
{
    int fd_timer = event_private_data->file_descriptor;

    /* Ack the timer */
    {
        uint64_t expiration;
        ssize_t ret;

        ret = read(fd_timer, &expiration, sizeof(expiration));
        ERROR_ON(ret < 0);
    }

    TRACE("Host cpcd debug counters:"
          "\nendpoint_opened %u"
          "\nendpoint_closed %u"
          "\nrxd_frame %u"
          "\ntxd_reject_destination_unreachable %u"
          "\ntxd_completed %u"
          "\nretxd_data_frame %u"
          "\ninvalid_header_checksum %u"
          "\ninvalid_payload_checksum %u\n",
          primary_cpcd_debug_counters.endpoint_opened,
          primary_cpcd_debug_counters.endpoint_closed,
          primary_cpcd_debug_counters.rxd_frame,
          primary_cpcd_debug_counters.txd_reject_destination_unreachable,
          primary_cpcd_debug_counters.txd_completed,
          primary_cpcd_debug_counters.retxd_data_frame,
          primary_cpcd_debug_counters.invalid_header_checksum,
          primary_cpcd_debug_counters.invalid_payload_checksum);

    TRACE("RCP cpcd debug counters"
          "\nendpoint_opened %u"
          "\nendpoint_closed %u"
          "\nrxd_frame %u"
          "\ntxd_reject_destination_unreachable %u"
          "\ntxd_completed %u"
          "\nretxd_data_frame %u"
          "\ndriver_packet_dropped %u"
          "\ninvalid_header_checksum %u"
          "\ninvalid_payload_checksum %u\n",
          secondary_cpcd_debug_counters.endpoint_opened,
          secondary_cpcd_debug_counters.endpoint_closed,
          secondary_cpcd_debug_counters.rxd_frame,
          secondary_cpcd_debug_counters.txd_reject_destination_unreachable,
          secondary_cpcd_debug_counters.txd_completed,
          secondary_cpcd_debug_counters.retxd_data_frame,
          secondary_cpcd_debug_counters.invalid_header_checksum,
          secondary_cpcd_debug_counters.invalid_payload_checksum);
}

void init_stats_logging(void)
{
    /* Setup timer */
    stats_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    ERROR_SYSCALL_ON(stats_timer_fd < 0);

    struct itimerspec timeout_time = { .it_interval = { .tv_sec = config.stats_interval, .tv_nsec = 0 },
                                       .it_value = { .tv_sec = config.stats_interval, .tv_nsec = 0 } };

    int ret = timerfd_settime(stats_timer_fd,
                              0,
                              &timeout_time,
                              NULL);

    ERROR_SYSCALL_ON(ret < 0);

    /* Setup epoll */
    {
        logging_private_data = (epoll_port_private_data_t *)calloc_port(sizeof(epoll_port_private_data_t));
        ERROR_ON(logging_private_data == NULL);

        logging_private_data->callback = logging_print_stats;
        logging_private_data->file_descriptor = stats_timer_fd;

        epoll_port_register(logging_private_data);
    }
}

void init_file_logging()
{
    file_logging_init();
}

void logging_kill(void)
{
    /* Note we don't cancel the threads, we let them finish */

    gracefully_exit = true;

    pthread_cond_signal(&stdout_logger.condition);
    pthread_join(stdout_logger_thread, NULL);

    if (config.file_tracing)
    {
        pthread_cond_signal(&file_logger.condition);
        pthread_join(file_logger_thread, NULL);
    }

    free(logging_private_data);
}

static size_t get_time_string(char *time_string, size_t time_string_size)
{
    long ms;
    time_t s;
    struct timespec spec;
    struct tm *tm_info;
    size_t nchar;
    int ret = clock_gettime(CLOCK_REALTIME, &spec);

    s = spec.tv_sec;

    ms = spec.tv_nsec / 1000000;
    if (ms > 999)
    {
        s++;
        ms = 0;
    }

    if (ret != ((time_t)-1))
    {
        tm_info = localtime(&s);
        nchar = strftime(time_string, time_string_size, "%H:%M:%S", tm_info);
        nchar += (size_t)snprintf(&time_string[nchar], time_string_size - nchar, ":%03ld", ms);
    } else
    {
        nchar = (size_t)snprintf(time_string, time_string_size, "time error");
    }

    return nchar;
}

void trace(const bool force_stdout, const char *string, ...)
{
    char log_string[512];
    size_t log_string_length = 0;

    if (!config.file_tracing && !config.stdout_tracing && !force_stdout)
    {
        return;
    }

    /* Append the time stamp */
    {
        log_string[log_string_length++] = '[';
        log_string_length += get_time_string(&log_string[log_string_length], sizeof(log_string) - log_string_length);
        log_string[log_string_length++] = ']';
        log_string[log_string_length++] = ' ';
    }

    /* Append formated text */
    {
        va_list vl;

        va_start(vl, string);
        {
            size_t size = sizeof(log_string) - log_string_length;

            int nchar = vsnprintf(&log_string[log_string_length], size, string, vl);

            NO_LOGGING_ERROR_ON(nchar < 0);

            if ((size_t)nchar >= size)
            {
                fprintf(stderr, "Truncated log message");
                /* The string was truncated, terminate it properly*/
                log_string[sizeof(log_string) - 1] = '\n';
                log_string_length = sizeof(log_string);
            } else
            {
                log_string_length += (size_t)nchar;
            }
        }
        va_end(vl);
    }

    if (config.stdout_tracing || force_stdout)
    {
        stdio_log(log_string, log_string_length);
    }
    if (config.file_tracing)
    {
        file_log(log_string, log_string_length);
    }
}

void trace_no_timestamp(const char *string, ...)
{
    char log_string[512];
    size_t log_string_length = 0;

    if (!config.file_tracing && !config.stdout_tracing)
    {
        return;
    }

    /* Append formated text */
    {
        va_list vl;

        va_start(vl, string);
        {
            size_t size = sizeof(log_string) - log_string_length;

            int nchar = vsnprintf(&log_string[log_string_length], size, string, vl);

            NO_LOGGING_ERROR_ON(nchar < 0);

            if ((size_t)nchar >= size)
            {
                fprintf(stderr, "Truncated log message");
                /* The string was truncated, terminate it properly*/
                log_string[sizeof(log_string) - 1] = '\n';
                log_string_length = sizeof(log_string);
            } else
            {
                log_string_length += (size_t)nchar;
            }
        }
        va_end(vl);
    }

    if (config.stdout_tracing)
    {
        stdio_log(log_string, log_string_length);
    }
    if (config.file_tracing)
    {
        file_log(log_string, log_string_length);
    }
}

static uint16_t byte_to_hex(uint8_t byte)
{
    uint8_t low = byte & 0x0F;
    uint8_t high = byte >> 4;

    hex_str.nibble[0] = lut[high];
    hex_str.nibble[1] = lut[low];

    return hex_str.hex;
}

void trace_frame(const char *string, const void *buffer, size_t len)
{
    char log_string[4096]; /* Arbitrary size. Large buffer frames will most likely overflow. */
    size_t log_string_length = 0;
    uint8_t *frame = (uint8_t *)buffer;

    if ((!config.file_tracing && !config.stdout_tracing) || config.enable_frame_trace == false)
    {
        return;
    }

    /* Append the time stamp */
    {
        log_string[log_string_length++] = '[';

        log_string_length += get_time_string(&log_string[log_string_length], sizeof(log_string) - log_string_length);

        log_string[log_string_length++] = ']';
        log_string[log_string_length++] = ' ';
    }

    /* Append  string up to buffer */
    for (size_t i = 0; string[i] != '\0'; i++)
    {
        log_string[log_string_length++] = string[i];

        /* Edge case where the string itself can fill the whole buffer.. */
        if (log_string_length == sizeof(log_string))
        {
            /* Flush the buffer */
            if (config.stdout_tracing)
            {
                stdio_log(log_string, log_string_length);
            }
            if (config.file_tracing)
            {
                file_log(log_string, log_string_length);
            }

            /* Start at the beginning */
            log_string_length = 0;
        }
    }

    /* Append hex data */
    for (size_t i = 0; i != len; i++)
    {
        if (log_string_length >= sizeof(log_string) - sizeof("xx:"))
        {
            /* Flush the buffer */
            if (config.stdout_tracing)
            {
                stdio_log(log_string, log_string_length);
            }
            if (config.file_tracing)
            {
                file_log(log_string, log_string_length);
            }

            /* Start at the beginning */
            log_string_length = 0;
        }

        *(uint16_t *)(&log_string[log_string_length]) = byte_to_hex(frame[i]);
        log_string_length += sizeof(uint16_t);
        log_string[log_string_length++] = ' ';
    }

    log_string[log_string_length - 1] = '\n';

    if (config.stdout_tracing)
    {
        stdio_log(log_string, log_string_length);
    }
    if (config.file_tracing)
    {
        file_log(log_string, log_string_length);
    }
}
