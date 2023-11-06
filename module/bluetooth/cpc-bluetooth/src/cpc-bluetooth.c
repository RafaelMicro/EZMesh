#include "libcpc.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <pty.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define LOG_TAG "cpc-bluetooth"

#define TO_CPC_BUF_SIZE     400
#define FROM_CPC_BUF_SIZE   LIB_CPC_READ_MINIMUM_SIZE
#define INST_NAME_LEN       100
#define RETRY_COUNT         10
#define CPC_RETRY_SLEEP_NS  100000000L
#define CPC_RESET_SLEEP_NS  10000L
#define THREAD_SLEEP_NS     1000000L
#define CPC_TRANSMIT_WINDOW 1
#define SYMLINK_PATH        "pts_hci"

// cpc related structures
static cpc_handle_t lib_handle;
static cpc_ep_t endpoint;
// tx/rx buffers
static uint8_t data_to_cpc[TO_CPC_BUF_SIZE];
static uint8_t data_from_cpc[FROM_CPC_BUF_SIZE];
// cpc instance name
static char cpc_instance[INST_NAME_LEN];

static int pty_m;
static int pty_s;

// end the receiving loop if signal is received.
static volatile bool run = true;
// signal if the controller was reset
static volatile bool has_reset = false;

static void reset_cb(void);

// two worker threads
static pthread_t thread_rx;
static pthread_t thread_tx;

// Static receive function
static void *cpc_to_pty_func(void *ptr);
static void *pty_to_cpc_func(void *ptr);

// Custom signal handler.
static void signal_handler(int sig)
{
    (void)sig;
    run = false;
}

/**************************************************************************//**
 * Starts CPC and pty.
 *****************************************************************************/
uint32_t startup(void)
{
    int ret;
    uint8_t retry = 0;

    // Initialize CPC communication
    do
    {
        ret = libcpc_init(&lib_handle, cpc_instance, reset_cb);
        if (ret == 0)
        {
            // speed up boot process if everything seems ok
            break;
        }
        nanosleep((const struct timespec[]){{ 0, CPC_RETRY_SLEEP_NS } }, NULL);
        retry++;
    } while ((ret != 0) && (retry < RETRY_COUNT));

    if (ret < 0)
    {
        perror("cpc_init: ");
        return ret;
    }

    // Start Bluetooth endpoint
    ret = libcpc_open_ep(lib_handle,
                         &endpoint,
                         CPC_EP_BT_RCP,
                         CPC_TRANSMIT_WINDOW);
    if (ret < 0)
    {
        perror("cpc_open_ep ");
        return ret;
    }
    printf("Endpoint opened\n");

    // Open virtual UART device
    ret = openpty(&pty_m, &pty_s, NULL, NULL, NULL);
    if (ret >= 0)
    {
        char *pName = ttyname(pty_s);
        printf("Name of secondary pty side is <%s>\n", pName);
        if (access(SYMLINK_PATH, F_OK) == 0)
        {
            if (remove(SYMLINK_PATH) != 0)
            {
                printf("Error remove symlink file (%s): %s\n",
                       SYMLINK_PATH, strerror(errno));
            }
        }

        if (symlink(pName, SYMLINK_PATH) != 0)
        {
            printf("Error creating symlink (%s): %s\n",
                   SYMLINK_PATH, strerror(errno));
        }
    }
    return ret;
}

/**************************************************************************//**
 * Callback to register reset from other end.
 *****************************************************************************/
static void reset_cb(void)
{
    has_reset = true;
}

/**************************************************************************//**
 * Reset CPC communication after other end restarted.
 *****************************************************************************/
int reset_cpc(void)
{
    int ret;
    uint8_t retry = 0;

    printf("RESET\n");

    // Restart cpp communication
    do
    {
        ret = libcpc_reset(&lib_handle);
        if (ret == 0)
        {
            // speed up boot process if everything seems ok
            break;
        }
        nanosleep((const struct timespec[]){{ 0, CPC_RETRY_SLEEP_NS } }, NULL);
        retry++;
    } while ((ret != 0) && (retry < RETRY_COUNT));
    has_reset = false;

    if (ret < 0)
    {
        perror("cpc restart ");
        return ret;
    }

    // Open Bluetooth endpoint
    ret = libcpc_open_ep(lib_handle,
                         &endpoint,
                         CPC_EP_BT_RCP,
                         CPC_TRANSMIT_WINDOW);
    if (ret < 0)
    {
        perror(" open endpoint ");
    }

    return ret;
}

/**************************************************************************//**
 * Main.
 *****************************************************************************/
int main(int argc, char *argv[])
{
    int ret;
    setvbuf(stdout, NULL, _IONBF, 0);

    // Set up custom signal handler for user interrupt and termination request.
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Set device unique name if different from default
    if (argc > 1)
    {
        strcpy(cpc_instance, argv[1]);
    } else
    {
        strcpy(cpc_instance, "cpcd_0");
    }

    // Start CPC and PTY communication
    if (startup() < 0)
    {
        exit(EXIT_FAILURE);
    }

    // Creating receiving working threads
    ret = pthread_create(&thread_rx, NULL, cpc_to_pty_func, NULL);
    if (ret)
    {
        // sl_log_error(LOG_TAG,"Error - pthread_create(thread_rx) return code: %d", ret);
        exit(EXIT_FAILURE);
    }
    ret = pthread_create(&thread_tx, NULL, pty_to_cpc_func, NULL);
    if (ret)
    {
        // sl_log_error(LOG_TAG,"Error - pthread_create(thread_tx) return code: %d", ret);
        exit(EXIT_FAILURE);
    }

    // sl_log_debug(LOG_TAG,"CPC - VHCI bridge working, main thread is going to sleep");

    // Reset cpc communication if daemon signals
    while (run)
    {
        if (has_reset)
        {
            ret = reset_cpc();
            if (ret < 0)
            {
                perror("reset ");
                exit(EXIT_FAILURE);
            }
        }
        nanosleep((const struct timespec[]){{ 0, CPC_RESET_SLEEP_NS } }, NULL);
    }
}

/**************************************************************************//**
 * Working thread from CPCd
 *****************************************************************************/
void *cpc_to_pty_func(void *ptr)
{
    ssize_t size = 0;

    // unused variable
    (void)ptr;

    while (run)
    {
        // Read data from cpc
        size = libcpc_read_ep(endpoint,
                              &data_from_cpc[0],
                              FROM_CPC_BUF_SIZE,
                              CPC_EP_READ_FLAG_NON_BLOCKING);
        if (size > 0)
        {
            if (write(pty_m, &data_from_cpc[0], size) == -1)
            {
                perror("write error ");
            }


            printf("r-> %ld\n", size);
            for (int i = 0; i < size; i++)
            {
                if ((i & 0xF) == 8)
                {
                    printf(" -");
                } else if (!(i & 0xF))
                {
                    printf("\n");
                }

                printf(" %02X", data_from_cpc[i]);
            }
            printf("\n\n");

            memset(&data_from_cpc[0], 0, FROM_CPC_BUF_SIZE);
        } else if (has_reset)
        {
            // intentionally left blank
        } else if (errno != EAGAIN && errno != ECONNRESET)
        {
            perror("cpc_to_pty_func error ");
            exit(-1);
        }
        nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
    }
    return NULL;
}

/**************************************************************************//**
 * Working thread to CPCd
 *****************************************************************************/
void *pty_to_cpc_func(void *ptr)
{
    ssize_t size = 0;
    unsigned int d_len = 0;

    // unused variable
    (void)ptr;

    while (run)
    {
        // Read data from pty
        size = read(pty_m, data_to_cpc, TO_CPC_BUF_SIZE);
        if (size > 0)
        {
            if (data_to_cpc[0] == 0x02)
            {
                d_len = (data_to_cpc[3] | (data_to_cpc[4] << 8)) + 5;
            } else
            {
                d_len = data_to_cpc[3] + 4;
            }
            printf("w-> %d\n", d_len);
            for (int i = 0; i < d_len; i++)
            {
                if ((i & 0xF) == 8)
                {
                    printf(" -");
                } else if (!(i & 0xF))
                {
                    printf("\n");
                }

                printf(" %02X", data_to_cpc[i]);
            }
            printf("\n\n");
            libcpc_write_ep(endpoint, &data_to_cpc[0], d_len, 0);
            if (size > d_len)
                libcpc_write_ep(endpoint, &data_to_cpc[d_len], size - d_len, 0);
            memset(&data_to_cpc[0], 0, TO_CPC_BUF_SIZE);
        } else if (has_reset)
        {
            // intentionally left blank
        } else if (errno != EAGAIN && errno != ECONNRESET)
        {
            perror("pty_to_cpc_func error");
            exit(-1);
        }
        nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
    }
    return NULL;
}
