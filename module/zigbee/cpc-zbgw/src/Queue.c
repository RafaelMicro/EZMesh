#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include "C2S.h"
#include "S2C.h"
#include "Queue.h"
#include "server.h"
#include "common.h"

//========================================================
#define	DATA_ARRAY_LENGTH	1024
#define	QUEUE_RX_MAX_VALUE	10    	
#define	QUEUE_TX_MAX_VALUE	10   
#define	QUEUE_USED             	1
#define	QUEUE_NOT_USED         	0
#define	QUEUE_FULL             	1
#define	QUEUE_NOT_FULL         	0
#define	QUEUE_EMPTY            	1
#define	QUEUE_NOT_EMPTY        	0
//========================================================

//--------------------------------------------------------
unsigned char  RX_DATA[DATA_ARRAY_LENGTH];
unsigned char  TX_DATA[DATA_ARRAY_LENGTH];
int            Queue_Retry_Count; //thread used
//--------------------------------------------------------
//--------------------------------------------------------
struct _Queue  Queue_RX_Table[QUEUE_RX_MAX_VALUE];
int            Queue_RX_Head_Ptr;
int            Queue_RX_Tail_Ptr; 
//--------------------------------------------------------
struct _Queue  Queue_TX_Table[QUEUE_TX_MAX_VALUE];
int            Queue_TX_Head_Ptr;
int            Queue_TX_Tail_Ptr; 
//--------------------------------------------------------

int tcp_received_cnt;
int mqtt_received_cnt;



void* Task_Queue(void* arg)
{
    static unsigned short Quit_Read_Length;
    static unsigned long  rtyErrTime_usec;

    while(1)
    {      
       	if((Queue_RX_Head_Ptr!=Queue_RX_Tail_Ptr) ) 
	{
	        memset(RX_DATA,0x00,DATA_ARRAY_LENGTH);
		
		if(Queue_RX_Read(RX_DATA,&Quit_Read_Length) == QUEUE_NOT_EMPTY)
		{
			C2S_CMD(RX_DATA,Quit_Read_Length);
			memset(RX_DATA,0x00,DATA_ARRAY_LENGTH);
		}
	        Queue_Retry_Count=0;        
		tcp_received_cnt = 0;
	}    
	if((Queue_TX_Head_Ptr!=Queue_TX_Tail_Ptr)) 
	{
	        memset(TX_DATA,0x00,DATA_ARRAY_LENGTH);
		
		if(Queue_TX_Read(TX_DATA,&Quit_Read_Length) == QUEUE_NOT_EMPTY)
		{
			S2C_CMD(TX_DATA,Quit_Read_Length);
			memset(TX_DATA,0x00,DATA_ARRAY_LENGTH);
		}
	        Queue_Retry_Count=0;        
		mqtt_received_cnt = 0;
	}  
	usleep(QUEUE_TIMER);   
    }
    printf("[Task_Queue] close .... \n");
}

void Queue_RX_Write(char *Data,unsigned short rlen)
{
	int i;
   
	if(Queue_RX_Table[Queue_RX_Head_Ptr].Active == 0)
	{        
		 Queue_RX_Table[Queue_RX_Head_Ptr].Active=1;
		 
		 memset(Queue_RX_Table[Queue_RX_Head_Ptr].data,0x00,DATA_ARRAY_LENGTH);
		 memcpy(Queue_RX_Table[Queue_RX_Head_Ptr].data,Data, rlen);
		 Queue_RX_Table[Queue_RX_Head_Ptr].len=rlen; 

		//printf(YELLOW"[RX_DB] Queue RX data write pointer=%d \n"NONE, Queue_RX_Head_Ptr);

		tcp_received_cnt = 1;

		Queue_RX_Head_Ptr++;
                if(Queue_RX_Head_Ptr >=  QUEUE_RX_MAX_VALUE)
                   Queue_RX_Head_Ptr=0;
                       
		return;
	} 
	else 
	{
		 for(i=0;i<QUEUE_RX_MAX_VALUE;i++)
		 {
			 if(Queue_RX_Table[i].Active == 0)
			 {
			     Queue_RX_Head_Ptr=i;
			     return;
			 }
	 	 }
	 return;
	}	
}
int Queue_RX_Read(unsigned char *Data,unsigned short* rlen)
{   
	 int retn=0;

	 Queue_RX_Tail_Ptr=0;

	 while((Queue_RX_Tail_Ptr < QUEUE_RX_MAX_VALUE) )
	 {
	     if(Queue_RX_Table[Queue_RX_Tail_Ptr].Active == 1)
	     {
	         Queue_RX_Table[Queue_RX_Tail_Ptr].Active=0;
	         memcpy(Data,Queue_RX_Table[Queue_RX_Tail_Ptr].data, Queue_RX_Table[Queue_RX_Tail_Ptr].len);

	         *rlen=Queue_RX_Table[Queue_RX_Tail_Ptr].len;
			//printf("[RX_DB] New Data !!\n");
			//printf(YELLOW"[RX_DB] Queue RX Data read pointer=%d \n"NONE, Queue_RX_Tail_Ptr);

	         retn=1;
			 break;
		 }
	     Queue_RX_Tail_Ptr++;
	 }


     if(retn == 1)
        return QUEUE_NOT_EMPTY;
	 else
        return QUEUE_EMPTY;
}
void Queue_TX_Write(char *Data,unsigned short rlen)
{
	int i;
   
	if(Queue_TX_Table[Queue_TX_Head_Ptr].Active == 0)
	{        
		 Queue_TX_Table[Queue_TX_Head_Ptr].Active=1;
		 memset(Queue_TX_Table[Queue_TX_Head_Ptr].data,0x00,DATA_ARRAY_LENGTH);
		 memcpy(Queue_TX_Table[Queue_TX_Head_Ptr].data,Data,rlen);
		 Queue_TX_Table[Queue_TX_Head_Ptr].len=rlen; 


		//printf(BRON"[TX_DB] Queue TX data write pointer=%p len %d\n"NONE, Queue_TX_Table[Queue_TX_Head_Ptr].data, Queue_TX_Table[Queue_TX_Head_Ptr].len);

		 mqtt_received_cnt = 1;

		 Queue_TX_Head_Ptr++;
                 if(Queue_TX_Head_Ptr >=  QUEUE_TX_MAX_VALUE)
                        Queue_TX_Head_Ptr=0;
		 return;
	} 
	else 
	{
		 for(i=0;i<QUEUE_TX_MAX_VALUE;i++)
		 {
			 if(Queue_TX_Table[i].Active == 0)
			 {
			     Queue_TX_Head_Ptr=i;
			     return;
			 }
	 	 }
	 return;
	}	
}
int Queue_TX_Read(unsigned char *Data,unsigned short* rlen)
{   
	 int retn=0;

	 Queue_TX_Tail_Ptr=0;

	 while((Queue_TX_Tail_Ptr < QUEUE_TX_MAX_VALUE) )
	 {
	     if(Queue_TX_Table[Queue_TX_Tail_Ptr].Active == 1)
	     {
	         Queue_TX_Table[Queue_TX_Tail_Ptr].Active=0;

	         memcpy(Data,Queue_TX_Table[Queue_TX_Tail_Ptr].data, Queue_TX_Table[Queue_TX_Tail_Ptr].len);

	         *rlen=Queue_TX_Table[Queue_TX_Tail_Ptr].len;
			//printf("[TX_DB] New Data !!\n");
			//printf(BRON"[TX_DB] Queue TX data read pointer=%d \n"NONE, Queue_TX_Tail_Ptr);

	         retn=1;
			 break;
		}
	     Queue_TX_Tail_Ptr++;
	 }


     if(retn == 1)
        return QUEUE_NOT_EMPTY;
	 else
        return QUEUE_EMPTY;
}
