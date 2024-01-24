//------------------------------
#define  QUEUE_TIMER        	100000 // 10ms
#define  QUEUE_DATA_LENGTH      1024 
//==================================================================
struct  _Queue
{             
    unsigned char  Active;          
    unsigned char  data[QUEUE_DATA_LENGTH];
    unsigned short len;
};
//==================================================================

void* Task_Queue(void* arg);
void Queue_RX_Write(char *Data,unsigned short rlen);
void Queue_TX_Write(char *Data,unsigned short rlen);
int Queue_RX_Read(unsigned char *Data,unsigned short* rlen);
int Queue_TX_Read(unsigned char *Data,unsigned short* rlen);