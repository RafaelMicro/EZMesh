#include "libezmesh.h"

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define INST_NAME_LEN       100
#define RETRY_COUNT         10
#define TRANSMIT_WINDOW 1
#define DEFAULT_DAEMON      "ezmeshd_0"

static ezmesh_handle_t lib_handle;
static ezmesh_ep_t endpoint;
static char ezmesh_instance[INST_NAME_LEN];

static volatile bool run = true;
static volatile bool has_reset = false;
static void reset_cb(void) { has_reset = true; }
static void signal_handler(int sig) { (void)sig; run = false; }

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    strcpy(ezmesh_instance, (argc > 2) ? argv[2] : DEFAULT_DAEMON);
    
    int ret, retry = 0;
    do {
        ret = libezmesh_init(&lib_handle, ezmesh_instance, reset_cb);
        if (ret == 0) break;
	    usleep(100000);
    } while ((ret != 0) && (retry++ < RETRY_COUNT));

    if (ret < 0) {
        printf("check EZMesh daemon state: deaded , ret: %d\n", ret);
        exit(EXIT_FAILURE);
    }
    puts(((ezmesh_handle_inst_t *)lib_handle.ptr)->agent_app_version);
    return 0;
}