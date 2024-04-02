#include "libezmesh.h"
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

 #include "progressbar.h"
 #include "statusbar.h"

#define FROM_EZMESH_BUF_SIZE LIB_EZMESH_READ_MINIMUM_SIZE
#define INST_NAME_LEN 100
#define RETRY_COUNT 10
#define EZMESH_RETRY_SLEEP_NS 100000000L
#define EZMESH_RESET_SLEEP_NS 10000000L
#define THREAD_SLEEP_NS 10000000L
#define EZMESH_TRANSMIT_WINDOW 1

#define DW_REQ_FIXED_LEN 35
#define DW_REQ_PER_PKT_LEN 0x100
#define DW_REQ_PKT_OFFSET (DW_REQ_FIXED_LEN - 1)

static void a_send_clear(void *p_data);
static void a_send_image(void *p_data);
static void a_send_active(void *p_data);

typedef struct __attribute__((packed))
{
    uint8_t header[4];
    uint8_t len;
} gateway_cmd_hdr;
typedef struct __attribute__((packed))
{
    uint32_t command_id;
    uint16_t address;
    uint8_t address_mode;
    uint8_t parameter[];
} gateway_cmd_pd;

typedef struct __attribute__((packed))
{
    uint8_t cs;
} gateway_cmd_end;

#define EVENT_LIST E_UPGRADE_START,         \
    E_UPGRADE_FILE_DOWNLOAD, \
    E_UPGRADE_FINISH

#define STATE_LIST S_IDLE,             \
    S_UPGRADE_DOWNLOAD, \
    S_UPGRADE_FINISH

#define ACTION_LIST A_UPGRADE_SEND_CLEAR, a_send_clear, \
    A_UPGRADE_SEND_IMAGE, a_send_image, \
    A_UPGRADE_SEND_ACTIVE, a_send_active

typedef void (*upgrade_fsm_action_t)(void *);

typedef enum
{
    DECLARE_ENUM(EVENT_LIST)
} upgrade_event_ids_t;

typedef enum
{
    DECLARE_ENUM(STATE_LIST)
} upgrade_state_ids_t;

typedef enum
{
    DECLARE_ENUM_PAIR(ACTION_LIST)
} upgrade_action_ids_t;

static const upgrade_fsm_action_t upgrade_fsm_actions[] =
{
    DECLARE_HANDLER(ACTION_LIST)
};

static const fsm_transition_t upgrade_fsm_transition_table[] =
{
    FSM_STATE(S_IDLE),
    FSM_TRANSITION(E_UPGRADE_START, FSM_NO_GUARD, A_UPGRADE_SEND_CLEAR, S_UPGRADE_DOWNLOAD),

    FSM_STATE(S_UPGRADE_DOWNLOAD),
    FSM_TRANSITION(E_UPGRADE_FILE_DOWNLOAD, FSM_NO_GUARD, A_UPGRADE_SEND_IMAGE, S_UPGRADE_DOWNLOAD),
    FSM_TRANSITION(E_UPGRADE_FINISH, FSM_NO_GUARD, A_UPGRADE_SEND_ACTIVE, S_IDLE),
};

static void upgrade_fsm_action(fsm_action_id_t action_id, void *p_data);

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

static const fsm_const_descriptor_t upgrade_fsm_descriptor =
{
    .transition_table = upgrade_fsm_transition_table,
    .transitions_count = sizeof(upgrade_fsm_transition_table) / sizeof(upgrade_fsm_transition_table[0]),
    .initial_state = S_IDLE,
    .guard = NULL,
    .action = upgrade_fsm_action,
#if FSM_DEBUG
    .fsm_name = "upg_fsm",
    .action_lookup = m_action_lookup_table,
    .event_lookup = m_event_lookup_table,
    .guard_lookup = NULL,
    .state_lookup = m_state_lookup_table
#endif /* FSM_DEBUG */
};

static fsm_t upgrade_fsm;
static FILE *fp;
static size_t file_size = 0, total_pkt = 0;
static size_t g_pkt_size = 0x1C0;
static int current_pkt = 0;
static bool cnt_check = 0;
// ezmesh related structures
static ezmesh_handle_t lib_handle;
static ezmesh_ep_t endpoint;
// tx/rx buffers
static uint8_t data_from_ezmesh[FROM_EZMESH_BUF_SIZE];
// ezmesh instance name
static char ezmesh_instance[INST_NAME_LEN];

static int pty_m;
static int pty_s;
static int upg_complete = -1;

// end the receiving loop if signal is received.
static volatile bool run = true;
// signal if the controller was reset
static volatile bool has_reset = false;

static progressbar *pDownloadBar;

static void reset_cb(void);

// two worker threads
static pthread_t thread_rx;
static pthread_t thread_tx;

static pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

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
    int i = 0;

    for (i = 0; i < bytes; i++)
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

static char _gateway_checksum_calc(char *pBuf, int len)
{
    char cs = 0;
    int i;
    for (i = 0; i < len; i++)
    {
        cs += pBuf[i];
    }
    return(~cs);
}

static void upgrade_fsm_action(fsm_action_id_t action_id, void *p_data)
{
    upgrade_fsm_actions[action_id](p_data);
}

static void a_send_clear(void *p_data)
{
    unsigned char fw_clear_request_cmd[] =
    { 0xFF, 0xFC, 0xFC, 0xFF, 0x07, 0x00, 0x00, 0x00,
      0xF0, 0x00, 0x00, 0x00, 0x08 };

    libezmesh_write_ep(endpoint, &fw_clear_request_cmd[0], sizeof(fw_clear_request_cmd), 0);
}

static void a_send_image(void *p_data)
{
    unsigned char ota_download_request_cmd[512] = {
        0xFF, 0xFC, 0xFC, 0xFF, 157,
        0x01, 0x00, 0x00, 0xF0, // Command id
        0x00, 0x00, 0x00,       // ignore
        0x00, 0x00,             // file type
        0x00, 0x00,             // manufacturer code
        0x00, 0x00, 0x00, 0x00, // file ver
        0x00, 0x00, 0x00, 0x00, // file size
        0x00, 0x00, 0x00, 0x00, // total pkt
        0x00, 0x00, 0x00, 0x00, // current pkt
        0x00, 0x00,             // pkt len

        0x08
    };

    static size_t total_pkt = 0, pkt_len = 0, rt;

    bool check = 0;
    total_pkt = file_size / g_pkt_size + ((file_size % g_pkt_size != 0) ? 1 : 0);
    if (cnt_check == 1)
        current_pkt++;

    if (fp)
    {
        if (current_pkt == total_pkt - 1)
        {
            fread(&ota_download_request_cmd[DW_REQ_PKT_OFFSET], (file_size % g_pkt_size), 1, fp);
            memcpy(&ota_download_request_cmd[28], (unsigned char *)&current_pkt, 4);
            ota_download_request_cmd[4] = (file_size % g_pkt_size) + 29;
            pkt_len = file_size % g_pkt_size;
            memcpy(&ota_download_request_cmd[32], (unsigned char *)&pkt_len, 2);
            ota_download_request_cmd[DW_REQ_FIXED_LEN + pkt_len - 1] = _gateway_checksum_calc(&ota_download_request_cmd[4], 30 + (file_size % g_pkt_size));

            pkt_len += DW_REQ_FIXED_LEN;

            libezmesh_write_ep(endpoint, &ota_download_request_cmd[0], pkt_len, 0);

            //printf("------------------------ >>>> GW      ------------------------\n");
            //_log_mem(" ", ota_download_request_cmd, pkt_len);

            return;
        }
        //printf("current_pkt %d\n", current_pkt);

        memcpy(&ota_download_request_cmd[20], (unsigned char *)&file_size, 4);
        total_pkt = file_size / g_pkt_size + ((file_size % g_pkt_size != 0) ? 1 : 0);
        memcpy(&ota_download_request_cmd[24], (unsigned char *)&total_pkt, 4);

        fseek(fp, current_pkt * g_pkt_size, SEEK_SET);
        rt = fread(&ota_download_request_cmd[DW_REQ_PKT_OFFSET], g_pkt_size, 1, fp);
        memcpy(&ota_download_request_cmd[32], (unsigned char *)&g_pkt_size, 2);

        if (rt != 1)
        {
            //printf("rt %ld\n", rt);
            system("pause");
        }

        memcpy(&ota_download_request_cmd[28], (unsigned char *)&current_pkt, 4);
        ota_download_request_cmd[DW_REQ_FIXED_LEN + g_pkt_size - 1] = _gateway_checksum_calc(&ota_download_request_cmd[4], 30 + g_pkt_size);

        pkt_len = DW_REQ_FIXED_LEN + g_pkt_size;

        libezmesh_write_ep(endpoint, &ota_download_request_cmd[0], pkt_len, 0);

        //printf("------------------------ >>>> GW      ------------------------\n");
        //_log_mem(" ", ota_download_request_cmd, pkt_len);
        cnt_check = 0;
    }
}

static void a_send_active(void *p_data)
{
    unsigned char fw_active_cmd[] =
    { 0xFF, 0xFC, 0xFC, 0xFF, 0x07, 0x02, 0x00, 0x00,
      0xF0, 0x00, 0x00, 0x00, 0x07 };

    fw_active_cmd[12] = _gateway_checksum_calc(&fw_active_cmd[4], 8);

    libezmesh_write_ep(endpoint, &fw_active_cmd[0], sizeof(fw_active_cmd), 0);
}

/**************************************************************************/ /**
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
                         EP_USER_ID_0,
                         EZMESH_TRANSMIT_WINDOW);
    if (ret < 0)
    {
        perror("ezmesh_open_ep ");
        return ret;
    }

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

    run = 0;
    return ret;

    // Open Bluetooth endpoint
    ret = libezmesh_open_ep(lib_handle,
                         &endpoint,
                         EP_USER_ID_0,
                         EZMESH_TRANSMIT_WINDOW);
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

    if (argc > 2)
    {
        strcpy(ezmesh_instance, argv[2]);
    } else
    {
        strcpy(ezmesh_instance, "ezmeshd_0");
    }

    fp = fopen(argv[1], "rb");

    if (!fp)
    {
        perror("fopen");
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);

    total_pkt = file_size / g_pkt_size + ((file_size % g_pkt_size != 0) ? 1 : 0);
    printf("Image : %s size %ld, Total Pkt %ld\n", argv[1], file_size, total_pkt);
    fsm_init(&upgrade_fsm, &upgrade_fsm_descriptor);

    pDownloadBar = progressbar_new("Download",total_pkt);
    // Start EZMESH and PTY communication
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

    fsm_event_post(&upgrade_fsm, E_UPGRADE_START, NULL);

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

    return upg_complete;
}

/**************************************************************************/ /**
 * Working thread from EZMESHd
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
        // Read data from ezmesh
        size = libezmesh_read_ep(endpoint,
                              &data_from_ezmesh[0],
                              FROM_EZMESH_BUF_SIZE,
                              EP_READ_FLAG_NONE);
        if (size > 0)
        {
            pt_pd = (gateway_cmd_pd *)&data_from_ezmesh[5];
            cmd_index = pt_pd->command_id;

            if (cmd_index == 0xF0008000)
            {
                fsm_event_post(&upgrade_fsm, E_UPGRADE_FILE_DOWNLOAD, NULL);
            } else if (cmd_index == 0xF0008001)
            {
                timeout = 1;

                rsp_cnt = (unsigned char)pt_pd->parameter[0] | ((unsigned char)pt_pd->parameter[1] << 8) |
                          ((unsigned char)pt_pd->parameter[2] << 16) | ((unsigned char)pt_pd->parameter[3] << 24);

                if (rsp_cnt == current_pkt)
                {
                    cnt_check = 1;
                    progressbar_inc(pDownloadBar);
                }
                else
                    cnt_check = 0;

                if (current_pkt == (total_pkt - 1))
                {
                    fsm_event_post(&upgrade_fsm, E_UPGRADE_FINISH, NULL);
                    progressbar_finish(pDownloadBar);
                    printf("Download Compelete");
                } else
                {
                    nanosleep((const struct timespec[]){{0, 5000000}}, NULL);
                    fsm_event_post(&upgrade_fsm, E_UPGRADE_FILE_DOWNLOAD, NULL);
                }
            } else if (cmd_index == 0xF0008002)
            {
                run = 0;
                upg_complete = 0;
            }

            memset(&data_from_ezmesh[0], 0, FROM_EZMESH_BUF_SIZE);
        } else
        {
            timeout++;
            if (timeout >= 1000)
            {
                timeout = 1;
                reset_ezmesh();
                //fsm_event_post(&upgrade_fsm, E_UPGRADE_FILE_DOWNLOAD, NULL);
            }
        }
        nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
    }
    return NULL;
}
