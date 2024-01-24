#include "libezmesh.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <pty.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define LOG_TAG "ezmesh-bluetooth"

#define TO_EZMESH_BUF_SIZE     400
#define FROM_EZMESH_BUF_SIZE   LIB_EZMESH_READ_MINIMUM_SIZE
#define INST_NAME_LEN       100
#define RETRY_COUNT         10
#define EZMESH_RETRY_SLEEP_NS  100000000L
#define EZMESH_RESET_SLEEP_NS  10000L
#define THREAD_SLEEP_NS     1000000L
#define EZMESH_TRANSMIT_WINDOW 1
#define SYMLINK_PATH        "pts_subg"

// ezmesh related structures
static ezmesh_handle_t lib_handle;
static ezmesh_ep_t endpoint;
// tx/rx buffers
static uint8_t data_to_ezmesh[TO_EZMESH_BUF_SIZE];
static uint8_t data_from_ezmesh[FROM_EZMESH_BUF_SIZE];
// ezmesh instance name
static char ezmesh_instance[INST_NAME_LEN];

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
static void *ezmesh_to_pty_func(void *ptr);
static void *pty_to_ezmesh_func(void *ptr);

// Custom signal handler.
static void signal_handler(int sig)
{
    (void)sig;
    run = false;
}

/**************************************************************************//**
 * Starts EZMESH and pty.
 *****************************************************************************/
uint32_t startup(void)
{
    int ret;
    uint8_t retry = 0;

    // Initialize EZMESH communication
    do
    {
        ret = libezmesh_init(&lib_handle, ezmesh_instance, reset_cb);
        if (ret == 0)
        {
            // speed up boot process if everything seems ok
            break;
        }
        nanosleep((const struct timespec[]){{ 0, EZMESH_RETRY_SLEEP_NS } }, NULL);
        retry++;
    } while ((ret != 0) && (retry < RETRY_COUNT));

    if (ret < 0)
    {
        perror("ezmesh_init: ");
        return ret;
    }

    ret = libezmesh_open_ep(lib_handle,
                         &endpoint,
                         EP_USER_ID_1,
                         EZMESH_TRANSMIT_WINDOW);
    if (ret < 0)
    {
        perror("ezmesh_open_ep ");
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
 * Reset EZMESH communication after other end restarted.
 *****************************************************************************/
int reset_ezmesh(void)
{
    int ret;
    uint8_t retry = 0;

    printf("RESET\n");

    // Restart cpp communication
    do
    {
        ret = libezmesh_reset(&lib_handle);
        if (ret == 0)
        {
            // speed up boot process if everything seems ok
            break;
        }
        nanosleep((const struct timespec[]){{ 0, EZMESH_RETRY_SLEEP_NS } }, NULL);
        retry++;
    } while ((ret != 0) && (retry < RETRY_COUNT));
    has_reset = false;

    if (ret < 0)
    {
        perror("ezmesh restart ");
        return ret;
    }

    // Open Bluetooth endpoint
    ret = libezmesh_open_ep(lib_handle,
                         &endpoint,
                         EP_USER_ID_1,
                         EZMESH_TRANSMIT_WINDOW);
    if (ret < 0)
    {
        perror(" open endpoint ");
    }
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
        strcpy(ezmesh_instance, argv[1]);
    } else
    {
        strcpy(ezmesh_instance, "ezmeshd_1");
    }

    // Start EZMESH and PTY communication
    if (startup() < 0)
    {
        exit(EXIT_FAILURE);
    }

    // Creating receiving working threads
    ret = pthread_create(&thread_rx, NULL, ezmesh_to_pty_func, NULL);
    if (ret)
    {
        exit(EXIT_FAILURE);
    }
    ret = pthread_create(&thread_tx, NULL, pty_to_ezmesh_func, NULL);
    if (ret)
    {
        exit(EXIT_FAILURE);
    }

    // Reset ezmesh communication if daemon signals
    while (run)
    {
        if (has_reset)
        {
            ret = reset_ezmesh();
            if (ret < 0)
            {
                perror("reset ");
                exit(EXIT_FAILURE);
            }
        }
        nanosleep((const struct timespec[]){{ 0, EZMESH_RESET_SLEEP_NS } }, NULL);
    }
}

/**************************************************************************//**
 * Working thread from EZMESHd
 *****************************************************************************/
void *ezmesh_to_pty_func(void *ptr)
{
    ssize_t size = 0;

    // unused variable
    (void)ptr;

    while (run)
    {
        // Read data from ezmesh
        size = libezmesh_read_ep(endpoint,
                              &data_from_ezmesh[0],
                              FROM_EZMESH_BUF_SIZE,
                              EP_READ_FLAG_NON_BLOCKING);
        if (size > 0)
        {
            if (write(pty_m, &data_from_ezmesh[0], size) == -1)
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

                printf(" %02X", data_from_ezmesh[i]);
            }
            printf("\n\n");

            memset(&data_from_ezmesh[0], 0, FROM_EZMESH_BUF_SIZE);
        } else if (has_reset)
        {
            // intentionally left blank
        } else if (errno != EAGAIN && errno != ECONNRESET)
        {
            perror("ezmesh_to_pty_func error ");
            exit(-1);
        }
        nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
    }
    return NULL;
}

/**************************************************************************//**
 * Working thread to EZMESHd
 *****************************************************************************/
void *pty_to_ezmesh_func(void *ptr)
{
    ssize_t size = 0;
    unsigned int d_len = 0;

    // unused variable
    (void)ptr;

    while (run)
    {
        // Read data from pty
        size = read(pty_m, &data_to_ezmesh[d_len], TO_EZMESH_BUF_SIZE);
        if (size > 0)
        {
            printf("w-> %ld\n", size);
            for (int i = 0; i < size; i++)
            {
                if ((i & 0xF) == 8)
                {
                    printf(" -");
                } else if (!(i & 0xF))
                {
                    printf("\n");
                }

                printf(" %02X", data_to_ezmesh[i+d_len]);
            }
            printf("\n\n");

	    d_len += size;


            if (data_to_ezmesh[d_len-1] == 0x0D)
            {
                libezmesh_write_ep(endpoint, &data_to_ezmesh[0], d_len, 0);
                memset(&data_to_ezmesh[0], 0, TO_EZMESH_BUF_SIZE);
                d_len = 0;
            }
        } else if (has_reset)
        {
            // intentionally left blank
        } else if (errno != EAGAIN && errno != ECONNRESET)
        {
            perror("pty_to_ezmesh_func error");
            exit(-1);
        }
        nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
    }
    return NULL;
}
