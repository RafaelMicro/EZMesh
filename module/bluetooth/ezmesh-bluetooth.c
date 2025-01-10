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

#define TO_EZMESH_BUF_SIZE     1024
#define FROM_EZMESH_BUF_SIZE   4087
#define INST_NAME_LEN       100
#define RETRY_COUNT         300
#define EZMESH_RETRY_SLEEP_NS  100000000L
#define EZMESH_RESET_SLEEP_NS  10000L
#define THREAD_SLEEP_NS     1000000L
#define EZMESH_TRANSMIT_WINDOW 1
#define SYMLINK_PATH        "pts_hci"
#define DEFAULT_DAEMON      "ezmeshd_0"

// ezmesh related structures
static ezmesh_handle_t lib_handle;
static ezmesh_ep_t endpoint;
// tx/rx buffers
static uint8_t data_to_ezmesh[TO_EZMESH_BUF_SIZE];
static uint8_t data_from_ezmesh[FROM_EZMESH_BUF_SIZE];
// ezmesh instance name
static char ezmesh_instance[INST_NAME_LEN];
static char virtual_device[INST_NAME_LEN];

static int pty_m;
static int pty_s;

// end the receiving loop if signal is received.
static volatile bool run = true;
// signal if the controller was reset
static volatile bool has_reset = false;
// signal if the controller was reset
static volatile bool trigger_scan_disable = false;

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
        printf("Try open socket, retry_count %d\n", retry);
        ret = libezmesh_init(&lib_handle, ezmesh_instance, reset_cb);
        if (ret == 0) break;
        nanosleep((const struct timespec[]){{ 0, EZMESH_RETRY_SLEEP_NS } }, NULL);
        retry++;
    } while ((ret != 0) && (retry < RETRY_COUNT));

    if (ret < 0)
    {
        perror("ezmesh_init: ");
        return ret;
    }

    // Start Bluetooth endpoint
    ret = libezmesh_open_ep(lib_handle, &endpoint, EP_BT_RCP, EZMESH_TRANSMIT_WINDOW);
    if (ret < 0)
    {
    	printf("ret %d\n", ret);
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
        if (access(virtual_device, F_OK) == 0)
        {
            if (remove(virtual_device) != 0)
            {
                printf("Error remove symlink file (%s): %s\n",
                       virtual_device, strerror(errno));
            }
        }

        if (symlink(pName, virtual_device) != 0)
        {
            printf("Error creating symlink (%s): %s\n",
                   virtual_device, strerror(errno));
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
        if (ret == 0) break; // speed up boot process if everything seems ok
        //nanosleep((const struct timespec[]){{ 0, EZMESH_RETRY_SLEEP_NS } }, NULL);
	    usleep(100000);
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
                         EP_BT_RCP,
                         EZMESH_TRANSMIT_WINDOW);
    if (ret < 0) perror(" open endpoint ");

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
    strcpy(virtual_device, (argc > 1)? argv[1] : SYMLINK_PATH);
    strcpy(ezmesh_instance, (argc > 2)? argv[2] : DEFAULT_DAEMON);
    
    // Start EZMESH and PTY communication
    if (startup() < 0)
    {
        printf("start failed\n");
        exit(EXIT_FAILURE);
    }

    // Creating receiving working threads
    ret = pthread_create(&thread_rx, NULL, ezmesh_to_pty_func, NULL);
    if (ret)
    {
        printf("Error - pthread_create(thread_rx) return code: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    ret = pthread_create(&thread_tx, NULL, pty_to_ezmesh_func, NULL);
    if (ret)
    {
        printf("Error - pthread_create(thread_tx) return code: %d\n", ret);
        exit(EXIT_FAILURE);
    }

    printf("EZMESH - VHCI bridge working, main thread is going to sleep\n");

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


const uint8_t cmd_complete[] = {0x01, 0x0C, 0x20, 0x00};
uint8_t* find_and_trim_pkt_payload(uint8_t *data, size_t data_len, size_t *new_data_len) {
    size_t i = 0;
    while (i < data_len) {
        uint8_t pkt_length = data[i + 2];
        if (pkt_length == sizeof(cmd_complete) && memcmp(&data[i + 3], cmd_complete, sizeof(cmd_complete)) == 0) {
            *new_data_len = data_len - i;
            return &data[i];
        }
        i += 3 + pkt_length;
    }
    *new_data_len = 0;
    return NULL;
}

/**************************************************************************//**
 * Working thread from EZMESHd
 *****************************************************************************/
void *ezmesh_to_pty_func(void *ptr)
{
    ssize_t size = 0;
    int i;

    // unused variable
    (void)ptr;

    while (run)
    {
        // Read data from ezmesh
        size = libezmesh_read_ep(endpoint,
                              &data_from_ezmesh[0],
                              FROM_EZMESH_BUF_SIZE,
                              0);
        if (size > 0)
        {
            if(trigger_scan_disable){
                size_t new_data_len = 0;
                uint8_t *new_data = find_and_trim_pkt_payload(&data_from_ezmesh[0], size, &new_data_len);

                if (new_data) {
                    trigger_scan_disable = false;
                    memmove(&data_from_ezmesh[0], new_data, new_data_len);
                    size = new_data_len;
                } else {
                    printf("pass r %d-> %ld\n", trigger_scan_disable, size);
                    /*
                    for (i = 0; i < size; i++)
                    {
                        if ((i & 0xF) == 8) printf(" -");
                        else if (!(i & 0xF)) printf("\n");
                        printf(" %02X", data_from_ezmesh[i]);
                    }
                    printf("\n\n");
                    */
                    nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
                    continue;
                }

            }

            if (write(pty_m, &data_from_ezmesh[0], size) == -1) perror("write error "); 
            printf("r %d-> %ld\n", trigger_scan_disable, size);
#if 0
            for (i = 0; i < size; i++)
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
#endif
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
    int i;

    // unused variable
    (void)ptr;

    while (run)
    {
        // Read data from pty
        size = read(pty_m, data_to_ezmesh, TO_EZMESH_BUF_SIZE);
        if (size > 0)
        {
            if (data_to_ezmesh[0] == 0x02)
            {
                d_len = (data_to_ezmesh[3] | (data_to_ezmesh[4] << 8)) + 5;
            } else if(data_to_ezmesh[0] == 0x01)
            {
               d_len = data_to_ezmesh[3] + 4;
            }

            trigger_scan_disable = (data_to_ezmesh[0] == 0x01 && data_to_ezmesh[1] == 0x0C && 
               data_to_ezmesh[2] == 0x20 && data_to_ezmesh[3] == 0x02 && 
               data_to_ezmesh[4] == 0x00 && data_to_ezmesh[5] == 0x00 );
	    trigger_scan_disable = 0;
#if 0            
            for (i = 0; i < size; i++)
            {
                if ((i & 0xF) == 8)
                {
                    printf(" -");
                } else if (!(i & 0xF))
                {
                    printf("\n");
                }

                printf(" %02X", data_to_ezmesh[i]);
            }
            printf("\n\n");
#endif            
      while(size > 0) {
        if (data_to_ezmesh[0] == 0x02) {
          d_len = (data_to_ezmesh[3] | (data_to_ezmesh[4] << 8)) + 5;
        } else if(data_to_ezmesh[0] == 0x01) {
          d_len = data_to_ezmesh[3] + 4;
        }
        printf("w %d-> %d\n", trigger_scan_disable, d_len);
        libezmesh_write_ep(endpoint, &data_to_ezmesh[0], d_len, 0);
	if(size-d_len == 0)
	{
	  size = 0;
	  break;
	 }
        memmove(&data_to_ezmesh[0], &data_to_ezmesh[d_len], (size - d_len));
	size -= d_len;
	nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
      } 
            memset(&data_to_ezmesh[0], 0, TO_EZMESH_BUF_SIZE);
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
