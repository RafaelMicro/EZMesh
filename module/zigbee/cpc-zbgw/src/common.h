#include "stdint.h"
//==================================================================
//Color
//==================================================================
#define NONE             "\033[m"
#define RED              "\033[0;32;31m"
#define LIGHT_RED        "\033[1;31m"
#define GREEN            "\033[0;32;32m"
#define LIGHT_GREEN      "\033[1;32m"
#define BLUE             "\033[0;32;34m"
#define LIGHT_BLUE       "\033[1;34m" 
#define CYAN             "\033[0;36m"
#define PUPLE            "\033[0;35m"
#define BRON             "\033[0;33m"
#define YELLOW           "\033[1;33m"
#define WHITE            "\033[1;37m" 
//======================================================================== 
#define EndDeviceMax              250
#define EndPointMax               10
#define ClusterIDMax              30

extern char Write_ED_Table_flag;

struct _EndPoint
{
    unsigned char ep;
    unsigned short devidId;
    unsigned short clusterCounts;
    unsigned short clusterID[ClusterIDMax];
};

struct _EndDevice
{
    unsigned char  MacAddress[8];   //Mac Address(64bits)
    unsigned char  Active;	
    unsigned short ShortAddress;    //Short Address(16bits)
    unsigned char ep_counts;
    struct _EndPoint ep_list[EndPointMax];
    
};

struct _Coordinator
{
    unsigned char  MacAddress[8];   //Mac Address(64bits)
    unsigned short PANID;
    unsigned short DevCount;
    unsigned short ARCount;
    unsigned char  CHANNEL;
    unsigned char  EXT_PAN_ID[8];
};

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


void cpc_write_data(uint8_t *pdata, uint16_t len);

void System_Initial();
void Show_Fuction();
void Coordinator_Initial();
void Write_EndDevice_File();
void Set_Coodinator_Info(unsigned short PANID,unsigned char CHANNEL);
void gw_cmd_start(uint8_t channel, uint16_t panid, uint8_t reset);
void gw_cmd_simple_desc_req(uint16_t saddr, uint8_t ep);
void gw_cmd_pj();
void gw_cmd_act_ep(uint16_t saddr);
char* Transfer_End_Device_Mac(unsigned char* src_mac);
void show_dev_info();