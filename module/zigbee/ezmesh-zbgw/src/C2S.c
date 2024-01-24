#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include "C2S.h"
#include "Queue.h"
#include "server.h"
#include "common.h"



void C2S_CMD(unsigned char *dareal,unsigned short rlen)
{
	ezmesh_write_data(dareal, rlen);
}

