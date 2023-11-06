

#include "stdint.h"
void tcp_server_start(void);
void * Task_tcp_server_listen(void* arg);
void tcp_server_send(uint8_t *s, uint16_t len);

extern int client_connect_flag;
extern int tcp_send_flag ;
