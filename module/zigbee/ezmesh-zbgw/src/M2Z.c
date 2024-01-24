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



static uint8_t _gateway_checksum_calc(uint8_t *pBuf, uint8_t len)
{
    uint8_t cs = 0;

    for (int i = 0; i < len; i++)
    {
        cs += pBuf[i];
    }
    return (~cs);
}


void gw_cmd_start(uint8_t channel, uint16_t panid, uint8_t reset)
{
    uint8_t Command_String[] = {0xFF, 0xFC, 0xFC, 0xFF, 0x0b, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0C, 0x7C, 0x00, 0x00, 0x32}; 

    Command_String[12] = channel;
    Command_String[15] = reset;
    memcpy(&Command_String[13], (uint8_t *)&panid, 2);

    ezmesh_write_data(Command_String, sizeof(Command_String));
}

void gw_cmd_pj()
{
    uint8_t Command_String[] = {0xFF, 0xFC, 0xFC, 0xFF, 0x09, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x01, 0xBF}; 

    ezmesh_write_data(Command_String, sizeof(Command_String));    
}

void gw_cmd_act_ep(uint16_t saddr)
{
    uint8_t Command_String[] = {0xFF, 0xFC, 0xFC, 0xFF, 0x09, 0x05, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xBF}; 

    Command_String[9] = (saddr & 0xFF); 
    Command_String[10] = ((saddr >> 8) & 0xFF); 

    Command_String[12] = (saddr & 0xFF); 
    Command_String[13] = ((saddr >> 8) & 0xFF);     
    ezmesh_write_data(Command_String, sizeof(Command_String));        
}
void gw_cmd_simple_desc_req(uint16_t saddr, uint8_t ep)
{
    uint8_t Command_String[] = {0xFF, 0xFC, 0xFC, 0xFF, 0x0A, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0xBF}; 

    Command_String[9] = (saddr & 0xFF); 
    Command_String[10] = ((saddr >> 8) & 0xFF); 

    Command_String[12] = (saddr & 0xFF); 
    Command_String[13] = ((saddr >> 8) & 0xFF);

    Command_String[14] = ep;

    ezmesh_write_data(Command_String, sizeof(Command_String));            
}