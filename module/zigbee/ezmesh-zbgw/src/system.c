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

void System_Initial() 
{  
    printf(LIGHT_RED"                                        \n");
    printf(" _____     ___         _    _____ _              \n");
    printf("| __  |___|  _|___ ___| |  |     |_|___ ___ ___  \n");
    printf("|    -| .'|  _| .'| -_| |  | | | | |  _|  _| . | \n");
    printf("|__|__|__,|_| |__,|___|_|  |_|_|_|_|___|_| |___| \n");  
    printf("                                   |___| Rafael Micro    \n"NONE);    
    printf("\n");
    printf(LIGHT_GREEN"Rafael Dongle Process Loading....\n"NONE); 
    printf("\n");
   
}

void Show_Fuction() 
{    
    printf(LIGHT_BLUE"***************************************************\n");
    printf("*Press 'a' Dongle   Imformation Print console\n");     
    printf("*Press 'pj' Set Coordinaotr Permit Join\n");
    printf("*Press 'x' soft   reset to coordinat\n");
    printf("*Press 's' Show   function Status\n");
    printf("*Press 'd' Show   Device information\n");
    printf("*Press 'q' Quit   program\n");
    printf("***************************************************\n"NONE);
}

