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
#include <sys/stat.h>

struct _EndDevice   ED[EndDeviceMax];
struct _Coordinator CR;

char EndDevice_Filename[]="/usr/local/var/lib/ez-zbgw/zbdb/sc_enddevice.dat";
char Coordinator_Filename[]="/usr/local/var/lib/ez-zbgw/zbdb/sc_coordinator.dat";

int FileExist(char *fname)
{
    struct stat st;
    return(stat(fname,&st)==0);
}

void Clear_EndDevice_Information()
{
    int i,j;
    //---------------------------------
    for(i=0;i<EndDeviceMax;i++)
    {
        //----------------------------
        memset(ED[i].MacAddress,0x00,8);  
        //----------------------------   
        ED[i].ShortAddress=0;    
        ED[i].Active=0;         
        ED[i].ep_counts=0;

        for(j=0;j<EndPointMax;j++)
            memset(&ED[i].ep_list[j], 0x00, sizeof(struct _EndPoint));
    }
    
}

void Read_Coodinator_File() 
{      
    FILE           *fp;
    int            i;
    int            rsize;
    //----------------------------------------------------------
    printf(GREEN"Get coordinator information file !\n"NONE);
    //----------------------------------------------------------   
    //----------------------------------------------------------
    //--------------------------------------------------------
    if(FileExist(Coordinator_Filename))
    {                
       fp = fopen(Coordinator_Filename,"rb"); 
       if(fp != NULL)
       {
            rsize=fread(&CR, sizeof(struct _Coordinator),1,fp);

            //----------------------------------------------------------------------------
            fclose(fp);
            printf("\n\n");                       
            printf(LIGHT_GREEN"*******************************************\n");      
            //------------------------------------------------------------------                
            printf("Coordinator PANID    : %04X \n",CR.PANID); 
            printf("Coordinator Channel  : %d   \n",CR.CHANNEL);   
            //------------------------------------------------------------------   
            printf("*******************************************\n"NONE);

            gw_cmd_start(CR.CHANNEL, CR.PANID, 0);
       }
       else    
       {   
          printf(LIGHT_RED"Coordinator_Filename Open Failure !\n"NONE);
       }   
    }     
    else    
    {
        printf(LIGHT_BLUE"Coordinator_Filename not found !\n"NONE);
        CR.DevCount=0;

        Set_Coodinator_Info(0xB7B2, 25);

        gw_cmd_start(CR.CHANNEL, CR.PANID, 1);
    }    
}

void Read_EndDevice_File() 
{      
    FILE           *fp;
    int            i;
    int            rsize;
    //----------------------------------------------------------
    printf(GREEN"Get coordinator register endpoint device form file !\n"NONE);
    //----------------------------------------------------------   
    CR.DevCount=0;
    //----------------------------------------------------------
    Clear_EndDevice_Information();
    //--------------------------------------------------------
    if(FileExist(EndDevice_Filename))
    {                
       fp = fopen(EndDevice_Filename,"rb");
       if(fp != NULL)
       {
           while(1)
           {
              rsize=fread(&ED[CR.DevCount].MacAddress[0],sizeof(struct _EndDevice),1,fp);
              if(rsize != 1)
                break;              
              //-------------------------------------------------------------------------
              CR.DevCount++;
           } 
           //----------------------------------------------------------------------------
           fclose(fp);
       }
       else    
       {   
          printf(LIGHT_RED"EndPoint_Filename Open Failure !\n"NONE);
       }
    }
    else
    {
        printf(LIGHT_BLUE"EndDevice table is empty !\n"NONE);
        CR.DevCount=0;
    }
}

void Write_EndDevice_File() 
{      
    FILE    *fp;
    int     write_number=0;
    int     i;
    //----------------------------------------------------------    
    fp = fopen(EndDevice_Filename,"wb"); 
    
    if(fp != NULL)
    {
       for(i=0;i<EndDeviceMax;i++)  
       {                         
        fwrite(&ED[i].MacAddress[0],sizeof(struct _EndDevice),1,fp);       
       }
       //-------------------------------------------------------------
       fclose(fp); 
    }
    else
    {
       printf("EndPoint_Filename Write Failure !\n");
    }            
}

void Write_Coordinator_File() 
{      
    FILE    *FP;
    int     write_number=0;   
    //----------------------------------------------------------    
    FP = fopen(Coordinator_Filename,"w+b"); 
    if(FP != NULL)
    {
       printf("Coordinator information Write to file !\n");
       //---------------------------------------------------------   
       fseek(FP,0,SEEK_SET);       
       write_number=fwrite(&CR, sizeof(struct _Coordinator), 1,FP);        
    }
    else
    {
       printf("Coordinator information Write to file Failure !\n");
    }            
}

void Set_Coodinator_Info(unsigned short PANID,unsigned char CHANNEL)
{
	int i;

	CR.PANID=PANID;
	CR.CHANNEL=CHANNEL;

    Write_Coordinator_File();

}

void Clear_Coordinator_Information()
{
    int i;
    //----------------------------
    memset(CR.MacAddress,0x00,8);  
    //----------------------------   
    CR.PANID=0;     
    CR.CHANNEL=0;   
    CR.DevCount=0; 
    CR.ARCount=0; 
    //----------------------------    
    memset(CR.EXT_PAN_ID,0x00,8);     
}


void Coordinator_Initial()
{
    Clear_Coordinator_Information();
    Clear_EndDevice_Information();
    Read_EndDevice_File();
    Read_Coodinator_File();
}

char* Transfer_End_Device_Mac(unsigned char* src_mac)
{  
    static char Transfer_Device_ED_dest_mac[20];
    snprintf((char *)Transfer_Device_ED_dest_mac,20,"%02X%02X%02X%02X%02X%02X%02X%02X",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5],src_mac[6],src_mac[7]);   
    return ((char *)Transfer_Device_ED_dest_mac);
}

void show_dev_info()
{
    int i, j, k;
    // printf("|      ExtAddr     | Short Addr | Device ID | EP List | Cluster (In) | \r\n");

    for(i=0;i<EndDeviceMax;i++) 
    {
        if(ED[i].Active == 0)
            continue;
        printf("Device %d \r\n", i);

        printf("\t MAC Address :%02X%02X%02X%02X%02X%02X%02X%02X \r\n", ED[i].MacAddress[0], ED[i].MacAddress[1], ED[i].MacAddress[2], ED[i].MacAddress[3],
                                                   ED[i].MacAddress[4], ED[i].MacAddress[5], ED[i].MacAddress[6], ED[i].MacAddress[7]);
        printf("\t Short Addr : 0x%04X\r\n", ED[i].ShortAddress);
        for (j = 0; j < ED[i].ep_counts; j++)
        {
            printf("\tEP-%d \r\n",j);
            printf("\t\t endpoint : %d\r\n", ED[i].ep_list[j].ep);
            printf("\t\t Device ID : %d\r\n", ED[i].ep_list[j].devidId);
            printf("\t\t Cluster ID : ");
            for (k = 0; k < ED[i].ep_list[j].clusterCounts; k++)
                printf("0x%04X ", ED[i].ep_list[j].clusterID[k]);
            printf("\r\n");
        }

        printf("\r\n");
    }
    printf("\r\n");
}
