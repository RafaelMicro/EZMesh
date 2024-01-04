#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "common.h"

#define ED_NO_INDEX -1

extern struct _EndDevice   ED[EndDeviceMax];
extern struct _Coordinator CR;

typedef struct __attribute__((__packed__))
{
    uint8_t status;
    uint16_t nwkAddr;
    uint8_t len;

    uint8_t endpoint;
    uint16_t profileID;
    uint16_t deviceID;

    uint8_t deviceVer;
    uint8_t in_cluster_count;
    uint16_t clusterID[];
    
} zigbee_zdo_simple_desc_idc_t;


void Logger_Z2M_Debug(unsigned char *cmdmsg,unsigned short len) 
{                           
    unsigned short i;
    //--------------------------
    for(i=0;i<len;i++)
    {
       printf("%02X ",cmdmsg[i]);   
    }  
    printf("\n\n");        
} 

void Logger_Z2M_Print(char* action,unsigned char *da,unsigned short len) 
{//AT+ 22 92 00 12 4B 00 05 A7 B6 C2 50 28 00 00 00 13 00 00 00 00 28 50 C2 B6 A7 05 00 4B 12 00 00 86
    unsigned short Shor_Address=da[10]*256+da[9];
    //----------------------------------------------------------------------     
    //if(LogFile_Struct.Z2M_ShowToConsole_Flag & CONSOLE_PRINT_ENABLE )  
    {
        printf("Z2M[%d]:{%s}Len:%d SA:%04X \n",len,action,da[4],Shor_Address);     
       // printf("MA:%02X,%02X,%02X,%02X,%02X,%02X,%02X,%02X \n",da[32],da[31],da[30],da[29],da[28],da[27],da[26],da[25]);              
        //printf("Capabilities:%02X type:%02X \n",da[33],da[17]); 
        //------------------------------------------------------------------         
        printf("\n");   
    }          
} 


static int CheckEd(unsigned char *da,unsigned short len)
{//AT+ 22 92 00 12 4B 00 05 A7 B6 C2 50 28 00 00 00 13 00 00 00 00 28 50 C2 B6 A7 05 00 4B 12 00 00 86
    unsigned short i,j;
    unsigned short sa;    
    unsigned char cmpfg=0;
    //--------------------------
    sa = da[0] | (da[1] << 8);
    //--------------------------
    for(i=0;i<EndDeviceMax;i++)
    {
        if(ED[i].Active == 1)
        {
        	for(j=0;j<8;j++)
        	{
        		if(ED[i].MacAddress[j] != da[2+j]) break;
			}
			
            if(j >=8 )  
            {
                return i;                        
            } 
        }
    }
    return ED_NO_INDEX;
}
static void Z2M_AEP(uint8_t *da, uint16_t len)
{
    unsigned short j;
    int            ED_Index=ED_NO_INDEX;
    int            EP_Count = 0;
    unsigned short Shor_Address;    

    if(da[0] == 0)
    {
        Shor_Address = da[1] | (da[2] << 8);
        
        EP_Count = da[3];
        for(ED_Index=0;ED_Index<EndDeviceMax;ED_Index++)
        {
            if(ED[ED_Index].Active==1)
            {
                if(ED[ED_Index].ShortAddress == Shor_Address)
                {
                    ED[ED_Index].ep_counts = EP_Count;
                    for(int i =0;i<EP_Count;i++)
                    {
                        ED[ED_Index].ep_list[i].ep =  da[4 + i];
                        if( da[4 + i] > 0 &&  da[4 + i] < 10)
                            gw_cmd_simple_desc_req(Shor_Address, ED[ED_Index].ep_list[i].ep);
                    }
                }
            }
        }
    }
}

static void Z2M_AN(uint8_t *da, uint16_t len)
{
    unsigned short j;
    int            ED_Index=ED_NO_INDEX;
    unsigned short Shor_Address;
    int updated = 0;

    Logger_Z2M_Print("Device Add (AN)", da, len);

    Shor_Address = da[0] | (da[1] << 8);

    for(ED_Index=0;ED_Index<EndDeviceMax;ED_Index++)
    {
        if (!memcmp(&ED[ED_Index].MacAddress[0], &da[2], 8) && updated == 0)
        {
            if(updated == 0)
            {
                ED[ED_Index].ShortAddress=Shor_Address;
                ED[ED_Index].Active=1;

                printf("(Z2M_AN)Update ED MacAddress = %s SA=%04X\n",Transfer_End_Device_Mac(ED[ED_Index].MacAddress), ED[ED_Index].ShortAddress);
                updated = 1;
            }
            else
            {
                ED[ED_Index].Active=0;
            }
            Write_ED_Table_flag = 1;
            continue;
        }


        if(ED[ED_Index].Active==0 && updated == 0)
        {
            memcpy(&ED[ED_Index].MacAddress[0], &da[2], 8);
            CR.DevCount++;
            ED[ED_Index].ShortAddress=Shor_Address;
            ED[ED_Index].Active=1;

            printf("(Z2M_AN)Addition New ED MacAddress = %s SA=%04X\n",Transfer_End_Device_Mac(ED[ED_Index].MacAddress), ED[ED_Index].ShortAddress);

            Write_ED_Table_flag = 1;
            break;
        }
    }
    gw_cmd_act_ep(Shor_Address);

}

void Z2M_SD(uint8_t *da, uint16_t len)
{
    unsigned short i, j;
    int            ED_Index=ED_NO_INDEX;
    unsigned short Shor_Address;
    int updated = 0;

    zigbee_zdo_simple_desc_idc_t *pt_idc;

    pt_idc = (zigbee_zdo_simple_desc_idc_t *)da;

    printf("Simple desc : Addr %02X, Endpoint %02X, Profile %04X, DeviceID %04X\r\n",
            pt_idc->nwkAddr, pt_idc->endpoint, pt_idc->profileID, pt_idc->deviceID);

    for(ED_Index=0;ED_Index<EndDeviceMax;ED_Index++)
    {
        if(ED[ED_Index].ShortAddress == pt_idc->nwkAddr)
        {
            for(i=0;i<ED[ED_Index].ep_counts;i++)
            {
                if(ED[ED_Index].ep_list[i].ep != pt_idc->endpoint)
                    continue;
                ED[ED_Index].ep_list[i].clusterCounts = pt_idc->in_cluster_count;
                ED[ED_Index].ep_list[i].devidId = pt_idc->deviceID;

                for(j = 0; j<pt_idc->in_cluster_count; j++ )
                {
                    ED[ED_Index].ep_list[i].clusterID[j] = pt_idc->clusterID[j];
                }

            }
            Write_ED_Table_flag = 1;
            break;
        }
    }

}

void Z2M_CMD(uint8_t *da, uint16_t len)
{
    gateway_cmd_hdr *pt_hd;
    gateway_cmd_pd *pt_pd;

    pt_hd = (gateway_cmd_hdr *)&da[0];
    pt_pd = (gateway_cmd_pd *)&da[5];    


    if ((pt_pd->command_id == 0x0013))
    {
        Z2M_AN(pt_pd->parameter, pt_hd->len);
    }
    else if((pt_pd->command_id == 0x8004))
    {
        Z2M_SD(pt_pd->parameter, pt_hd->len);
    }    
    else if((pt_pd->command_id == 0x8005))
    {
        Z2M_AEP(pt_pd->parameter, pt_hd->len);
    }

}
