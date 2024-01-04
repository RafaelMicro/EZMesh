#include "libcpc.h"
#include "fsm.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <pty.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FROM_CPC_BUF_SIZE LIB_CPC_READ_MINIMUM_SIZE
#define INST_NAME_LEN 100
#define RETRY_COUNT 10
#define CPC_RETRY_SLEEP_NS 100000000L
#define CPC_RESET_SLEEP_NS 10000L
#define THREAD_SLEEP_NS 1000000L
#define CPC_TRANSMIT_WINDOW 1

static void a_page_read(void *p_data);
static void a_finish(void *p_data);
static void a_write(void *p_data);
static void a_write_start(void *p_data);
static void a_read_mac_addr(void *p_data);

typedef struct __attribute__((packed))
{
    uint32_t command_id;
    uint16_t address;
    uint8_t address_mode;
    uint8_t parameter[];
} gateway_cmd_pd;


#define EVENT_LIST E_START, \ 
    E_PAGE_READ, \
    E_WRITE_START,\
    E_WRITE,     \
    E_READ_FINISH

#define STATE_LIST S_IDLE,             \
    S_PAGE_READ, \
    S_WRITE_START,\
    S_WRITE,     \
    S_READ_FINISH

#define ACTION_LIST A_READ_MAC_ADDR, a_read_mac_addr, \
                    A_PAGE_READ, a_page_read,  \
                    A_WRITE_START, a_write_start, \
                    A_WRITE, a_write, \
                    A_FINISH, a_finish \

typedef void (*flashctl_fsm_action_t)(void *);

typedef enum
{
    DECLARE_ENUM(EVENT_LIST)
} flashctl_event_ids_t;

typedef enum
{
    DECLARE_ENUM(STATE_LIST)
} flashctl_state_ids_t;

typedef enum
{
    DECLARE_ENUM_PAIR(ACTION_LIST)
} flashctl_action_ids_t;

static const flashctl_fsm_action_t flashctl_fsm_actions[] =
{
    DECLARE_HANDLER(ACTION_LIST)
};

static const fsm_transition_t flashctl_fsm_transition_table[] =
{
    FSM_STATE(S_IDLE),
    FSM_TRANSITION(E_START, FSM_NO_GUARD, A_READ_MAC_ADDR, S_PAGE_READ),
    FSM_TRANSITION(E_WRITE_START, FSM_NO_GUARD, A_WRITE_START, S_WRITE),

    FSM_STATE(S_PAGE_READ),
    FSM_TRANSITION(E_PAGE_READ, FSM_NO_GUARD, A_PAGE_READ, S_PAGE_READ),
    FSM_TRANSITION(E_READ_FINISH, FSM_NO_GUARD, A_FINISH, S_IDLE),

    FSM_STATE(S_WRITE),
    FSM_TRANSITION(E_WRITE, FSM_NO_GUARD, A_WRITE, S_WRITE),
    FSM_TRANSITION(E_READ_FINISH, FSM_NO_GUARD, A_FINISH, S_IDLE),    

};

static void flashctl_fsm_action(fsm_action_id_t action_id, void *p_data);

#if FSM_DEBUG
static const char *m_action_lookup_table[] =
{
    DECLARE_STRING_PAIR(ACTION_LIST)
};

static const char *m_guard_lookup_table[] =
{
    DECLARE_STRING_PAIR(GUARD_LIST)
};

static const char *m_event_lookup_table[] =
{
    DECLARE_STRING(EVENT_LIST)
};

static const char *m_state_lookup_table[] =
{
    DECLARE_STRING(STATE_LIST)
};
#endif /* FSM_DEBUG */

static const fsm_const_descriptor_t flashctl_fsm_descriptor =
{
    .transition_table = flashctl_fsm_transition_table,
    .transitions_count = sizeof(flashctl_fsm_transition_table) / sizeof(flashctl_fsm_transition_table[0]),
    .initial_state = S_IDLE,
    .guard = NULL,
    .action = flashctl_fsm_action,
#if FSM_DEBUG
    .fsm_name = "upg_fsm",
    .action_lookup = m_action_lookup_table,
    .event_lookup = m_event_lookup_table,
    .guard_lookup = NULL,
    .state_lookup = m_state_lookup_table
#endif /* FSM_DEBUG */
};

static fsm_t flashctl_fsm;
static FILE *fp;
static FILE *fp_zbaddr;

// cpc related structures
static cpc_handle_t lib_handle;
static cpc_ep_t endpoint;
// tx/rx buffers
static uint8_t data_from_cpc[FROM_CPC_BUF_SIZE];
// cpc instance name
static char cpc_instance[INST_NAME_LEN];

static int upg_complete = -1;

static uint32_t start_address = 0xE0000;

// end the receiving loop if signal is received.
static volatile bool run = true;
// signal if the controller was reset
static volatile bool has_reset = false;

static void reset_cb(void);

// two worker threads
static pthread_t thread_rx;
static pthread_t thread_tx;

// Static receive function
static void *rx_handler(void *ptr);
static void *tx_handler(void *ptr);

// Custom signal handler.
static void signal_handler(int sig)
{
    (void)sig;
    run = false;
}
static void _log_mem(char *prefix, char *pAddr, int bytes)
{
    uintptr_t addr = (uintptr_t)pAddr;
    char *pCur = pAddr;

    for (int i = 0; i < bytes; i++)
    {
        if ((i & 0xF) == 8)
        {
            printf(" -");
        } else if (!(i & 0xF))
        {
            printf("\n%s%08lX |", prefix, addr);
            addr += 16;
        }

        printf(" %02X", pCur[i] & 0xFF);
    }
    printf("\n\n");
    return;
}

static void flashctl_fsm_action(fsm_action_id_t action_id, void *p_data)
{
    flashctl_fsm_actions[action_id](p_data);
}

static void a_write(void *p_data)
{
    unsigned char fw_wr_cmd[0x120] = { 
        0xFF, 0xFC, 0xFC, 0xFF, 
        0x0B, 0x01, 0x00, 0x00,
        0xE0, 0x00, 0x00, 0x00, 
        0x08 };

    if (fp)
    {
        fseek(fp, start_address - 0xE0000, SEEK_SET);

        fread(&fw_wr_cmd[12], 0x100, 1, fp);

        libcpc_write_ep(endpoint, &fw_wr_cmd[0], 0x10D, 0);

        printf("------------------------ >>>> GW      ------------------------\n");
        _log_mem(" ", fw_wr_cmd, sizeof(fw_wr_cmd));
    }        
}

static void a_read_mac_addr(void *p_data)
{
    unsigned char fw_read_mac_cmd[] = { 
        0xFF, 0xFC, 0xFC, 0xFF, 
        0x03, 0x03, 0x00, 0x00,
        0xE0, 0x00, 0x00, 0x00, 
        0x08 };

    libcpc_write_ep(endpoint, &fw_read_mac_cmd[0], sizeof(fw_read_mac_cmd), 0);        
}

static void a_write_start(void *p_data)
{
    unsigned char fw_wr_start_cmd[] = { 
        0xFF, 0xFC, 0xFC, 0xFF, 
        0x0B, 0x00, 0x00, 0x00,
        0xE0, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x0E, 0x00,
        0x00, 0x80, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00,
        0x08 };

    fp_zbaddr = fopen("zb_addr", "rb");
    if (!fp)
    {
        perror("fopen");
    }

    fread(&fw_wr_start_cmd[20], 8, 1, fp_zbaddr);
    fclose(fp_zbaddr);

    libcpc_write_ep(endpoint, &fw_wr_start_cmd[0], sizeof(fw_wr_start_cmd), 0);    
}


static void a_page_read(void *p_data)
{
    unsigned char page_read_cmd[] = { 
        0xFF, 0xFC, 0xFC, 0xFF, 
        0x0B, 0x02, 0x00, 0x00,
        0xE0, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x0E, 0x00,0x08 };

    

    if (fp)
    {
        page_read_cmd[12] = start_address & 0xFF;
        page_read_cmd[13] = (start_address >> 8) & 0xFF;
        page_read_cmd[14] = (start_address >> 16) & 0xFF;
        page_read_cmd[15] = (start_address >> 24) & 0xFF;
        libcpc_write_ep(endpoint, &page_read_cmd[0], sizeof(page_read_cmd), 0);

        printf("------------------------ >>>> GW      ------------------------\n");
        _log_mem(" ", page_read_cmd, sizeof(page_read_cmd));
    }
}

static void a_finish(void *p_data)
{
    fclose(fp);
    run = 0;
}

/**************************************************************************/ /**
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

    ret = libcpc_open_ep(lib_handle,
                         &endpoint,
                         CPC_EP_USER_ID_0,
                         CPC_TRANSMIT_WINDOW);
    if (ret < 0)
    {
        perror("cpc_open_ep ");
        return ret;
    }
    printf("Endpoint opened\n");

    return ret;
}

/**************************************************************************/ /**
 * Callback to register reset from other end.
 *****************************************************************************/
static void reset_cb(void)
{
    has_reset = true;
}

/**************************************************************************/ /**
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

    run = 0;
    return ret;

    // Open Bluetooth endpoint
    ret = libcpc_open_ep(lib_handle,
                         &endpoint,
                         CPC_EP_USER_ID_0,
                         CPC_TRANSMIT_WINDOW);
    if (ret < 0)
    {
        perror(" open endpoint ");
    }

    return ret;
}

/**************************************************************************/ /**
 * Main.
 *****************************************************************************/
int main(int argc, char *argv[])
{
    int ret;
    setvbuf(stdout, NULL, _IONBF, 0);

    // Set up custom signal handler for user interrupt and termination request.
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (argc > 3)
    {
        strcpy(cpc_instance, argv[3]);
    } else
    {
        strcpy(cpc_instance, "cpcd_0");
    }

    fsm_init(&flashctl_fsm, &flashctl_fsm_descriptor);

    // Start CPC and PTY communication
    if (startup() < 0)
    {
        exit(EXIT_FAILURE);
    }

    // Creating receiving working threads
    ret = pthread_create(&thread_rx, NULL, rx_handler, NULL);
    if (ret)
    {
        exit(EXIT_FAILURE);
    }

    if(memcmp(argv[2], "r", 1) == 0)
    {

        fp = fopen(argv[1], "wb");

        if (!fp)
        {
            perror("fopen");
        }
      
        fsm_event_post(&flashctl_fsm, E_START, NULL);
    }
    else
    {
        fp = fopen(argv[1], "rb");

        if (!fp)
        {
            perror("fopen");
        }       
        fsm_event_post(&flashctl_fsm, E_WRITE_START, NULL);
    }


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

    return upg_complete;
}

/**************************************************************************/ /**
 * Working thread from CPCd
 *****************************************************************************/
void *rx_handler(void *ptr)
{
    ssize_t size = 0;
    uint32_t cmd_index, timeout = 0;
    gateway_cmd_pd *pt_pd;
    unsigned int rsp_cnt = 0;

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
            pt_pd = (gateway_cmd_pd *)&data_from_cpc[5];
            cmd_index = pt_pd->command_id;

            if (cmd_index == 0xE0008000)
            {
                fsm_event_post(&flashctl_fsm, E_WRITE, NULL);
            }
            if (cmd_index == 0xE0008001)
            {
                start_address += 0x100;

                if(start_address >= 0xE8000)
                {
                    fsm_event_post(&flashctl_fsm, E_READ_FINISH, NULL);
                }
                else
                {
                    printf("state: E_WRITE\n");
                    fsm_event_post(&flashctl_fsm, E_WRITE, NULL);
                }
            }
            if (cmd_index == 0xE0008002)
            {

                fwrite(pt_pd->parameter, 0x100, 1, fp);

                start_address += 0x100;
                if(start_address >= 0xE8000)
                {
                    fsm_event_post(&flashctl_fsm, E_READ_FINISH, NULL);
                }
                else
                {
                    printf("state: E_PAGE_READ\n");
                    fsm_event_post(&flashctl_fsm, E_PAGE_READ, NULL);
                }
            } 
            if (cmd_index == 0xE0008003)
            {
                printf("MAC Address : %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", 
                    pt_pd->parameter[7], pt_pd->parameter[6], pt_pd->parameter[5], pt_pd->parameter[4],
                    pt_pd->parameter[3], pt_pd->parameter[2], pt_pd->parameter[1], pt_pd->parameter[0]);

                fp_zbaddr = fopen("zb_addr", "wb");
                if (!fp)
                {
                    perror("fopen");
                }
                printf("MAC Address : %02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", 
                    pt_pd->parameter[7], pt_pd->parameter[6], pt_pd->parameter[5], pt_pd->parameter[4],
                    pt_pd->parameter[3], pt_pd->parameter[2], pt_pd->parameter[1], pt_pd->parameter[0]);

                fwrite(pt_pd->parameter, 8, 1, fp_zbaddr);
                fclose(fp_zbaddr);

                fsm_event_post(&flashctl_fsm, E_PAGE_READ, NULL);
            }

            memset(&data_from_cpc[0], 0, FROM_CPC_BUF_SIZE);
        } 
        nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
    }
    return NULL;
}

