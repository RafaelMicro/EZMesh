// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include "server.h"
#include "Queue.h"
#include "common.h"
#include "libezmesh.h"
#include "S2C.h"

#define FROM_EZMESH_BUF_SIZE   LIB_EZMESH_READ_MINIMUM_SIZE
#define EZMESH_RETRY_SLEEP_NS  100000000L
#define EZMESH_RESET_SLEEP_NS  10000000L
#define THREAD_SLEEP_NS     10000000L


static uint8_t data_from_ezmesh[FROM_EZMESH_BUF_SIZE];

//Thread Ptr
pthread_t tcp_server_listen;
pthread_t mqtt_client_received;
pthread_t thdQueue;
pthread_t thd_EndEvent;
pthread_t thd_System;
static pthread_t thread_rx;

static char ezmesh_instance[100];

static ezmesh_handle_t lib_handle;
static ezmesh_ep_t endpoint;

static volatile bool run = true;
// signal if the controller was reset
static volatile bool has_reset = false;

static void *rx_handler(void *ptr);
static void *tx_handler(void *ptr);

char Write_ED_Table_flag;


static void reset_cb(void)
{
	printf("reset\r\n");
}

static void signal_handler(int sig)
{
	(void)sig;
	run = false;
}


void* Task_Console_Key_Event(void* arg)
{
    static char  ReadkeyEvent[20];
    //----------------------------
    while(run)
    {
         //ReadkeyEvent= getchar();
         scanf("%s",ReadkeyEvent);
         switch(ReadkeyEvent[0])
         {
            case 'p':
			switch(ReadkeyEvent[1])
			{
				case 'j':
					printf(LIGHT_BLUE"Set Coordinator Permit Join\n"NONE);

					gw_cmd_pj();
					break;
			}
			break;

			case 'd' :
			show_dev_info();
			break;
            default :
            	break;
         }
         usleep(1000000); //1ms
    }
    printf("[Task_Console_Key_Event] close .... \n"); 
}

void* Task_System(void* arg)
{
	
	char	line[150];
    FILE *fp;
    int filecnt = 0;
    char checkcnt = 0;

	Coordinator_Initial();
    
    while(run) 
    {
      if(checkcnt++>1)
      {
      	checkcnt = 0;
	    
	    if(Write_ED_Table_flag == true)
	    {
	    	Write_ED_Table_flag = false;
	    	Write_EndDevice_File(); //save to EndDevice_File	    	
		}
	}
	usleep(1000000);
    }   
    printf("[Task_System] close .... \n");
}
#if 0
void _ws_recv(rf_message_t msg){
  printf("\n===== Rx Data =====\n");
  for(int i=0;i<msg.length;i++) printf("%02x ", msg.msg[i]);
  printf("\n===================\n");
}


static void ws_start()
{
    uint8_t config_file_path[] = "./setting.ini";
    config_setconfig(config_file_path, 14);
    if (config_parse_error() < 0) {
      printf("Can't load config file\n");
      return 1;
    }

    ws_init(WSEP_MATTER_ZIGBEE, WSSVC_MATTER);

    ws_set_recevice(_ws_recv);
    tk_start_task();


}
#endif

int main(int argc, char *argv[])
{
	int res;

	// Set up custom signal handler for user interrupt and termination request.
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);	
	
	tcp_server_start();

	// Thread for TCP Server listen to client
	res = pthread_create(&tcp_server_listen,NULL,Task_tcp_server_listen,NULL);

	// Thread for que Z->A data
	res = pthread_create(&thdQueue, NULL, Task_Queue, NULL);


	res = pthread_create(&thread_rx, NULL, rx_handler, NULL);

	res = pthread_create(&thd_EndEvent, NULL, Task_Console_Key_Event, NULL);

 	strcpy(ezmesh_instance, "ezmeshd_0");
       	
	res = libezmesh_init(&lib_handle, ezmesh_instance, reset_cb);

	if (res < 0) {
		perror("ezmesh_init ");
		return res;
	}

	res = libezmesh_open_ep(lib_handle, &endpoint, EP_ZIGBEE, 1);
  
	if (res < 0) {
		perror("ezmesh_open_ep ");
		return res;
	}
  
	printf("Endpoint opened\n");

	System_Initial();
	Show_Fuction();

	res = pthread_create(&thd_System, NULL,Task_System, NULL);

	//ws_start();
	
	while (run) {

		nanosleep((const struct timespec[]){{ 0, EZMESH_RESET_SLEEP_NS } }, NULL);
	}

	return 0;

}

void ezmesh_write_data(uint8_t *pdata, uint16_t len)
{
	ssize_t ret;
	ret = libezmesh_write_ep(endpoint, pdata, len, EP_WRITE_FLAG_NONE);

	if (ret < 0) {
		perror("ezmesh_write_ep ");
	}
}

void *rx_handler(void *ptr)
{
	ssize_t size = 0;
	uint32_t cmd_index;
	unsigned int rsp_cnt =0;

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
			Queue_TX_Write(data_from_ezmesh, size);
			memset(&data_from_ezmesh[0], 0, FROM_EZMESH_BUF_SIZE);
		}
		nanosleep((const struct timespec[]){{ 0, THREAD_SLEEP_NS } }, NULL);
	}
  return NULL;
}
