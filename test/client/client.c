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
#include <unistd.h>

#define TO_EZMESH_BUF_SIZE     400
#define FROM_EZMESH_BUF_SIZE   LIB_EZMESH_READ_MINIMUM_SIZE
#define INST_NAME_LEN       100
#define RETRY_COUNT         1
#define EZMESH_RETRY_SLEEP_NS  100000000L
#define EZMESH_RESET_SLEEP_NS  10000L
#define THREAD_SLEEP_NS     1000000L
#define EZMESH_TRANSMIT_WINDOW 1


extern char *optarg;
extern int optind, opterr, optopt;

static ezmesh_handle_inst_t *p_ezmesh_inst;
// ezmesh related structures
static ezmesh_handle_t lib_handle;
static ezmesh_ep_t endpoint;
// tx/rx buffers
static uint8_t data_to_ezmesh[TO_EZMESH_BUF_SIZE];
static uint8_t data_from_ezmesh[FROM_EZMESH_BUF_SIZE];
// ezmesh instance name
static char ezmesh_instance[INST_NAME_LEN];

// end the receiving loop if signal is received.
static volatile bool run = true;
// signal if the controller was reset
static volatile bool has_reset = false;

static void reset_cb(void);

static uint8_t g_ver = 0;

// Custom signal handler.
static void signal_handler(int sig)
{
    (void)sig;
    run = false;
}

/**************************************************************************//**
 * Starts EZMESH and pty.
 *****************************************************************************/
int startup(void)
{
    int ret;
    uint8_t retry = 0;
    

    // Initialize EZMESH communication
    do
    {
        ret = libezmesh_init(&lib_handle, ezmesh_instance, reset_cb);
        if (ret == 0)
        {
            p_ezmesh_inst = lib_handle.ptr;     
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
    return ret;
}

/**************************************************************************//**
 * Main.
 *****************************************************************************/
int main(int argc, char *argv[])
{
    int ret;
    int option, opt_cnt = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    // Set up custom signal handler for user interrupt and termination request.
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Set device unique name if different from default
    strcpy(ezmesh_instance, "ezmeshd_0");

    while((option = getopt(argc, argv, "I:v")) != -1)
    {
        opt_cnt++;
        switch (option)
        {
        case 'I':
            strcpy(ezmesh_instance, optarg);
            break;
        case 'v':
            g_ver = 1;
            printf("Get Version ... \n");
            break;            
        default:
            break;
        }
    }


    // Start EZMESH 
    if (startup() < 0)
    {
        run = false;
        printf("start failed\n");
        exit(EXIT_FAILURE);
    }

    if(g_ver)
    {
        printf("Agent app v%s\r\n", p_ezmesh_inst->agent_app_version);
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

    return ret;
}
