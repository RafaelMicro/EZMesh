#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include "S2C.h"
#include "Queue.h"
#include "server.h"
#include "common.h"
#include "Z2M.h"


void S2C_CMD(unsigned char *dareal,unsigned short rlen)
{
	tcp_send_flag = 1;
	tcp_server_send(dareal, rlen);
	Z2M_CMD(dareal, rlen);
}

