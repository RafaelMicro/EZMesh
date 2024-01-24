#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "Queue.h"
#include "server.h"
#include "common.h"


#define SERV_PORT 10010

#define TCP_BUFSIZ 1024

int errno;
int socket_fd;			/* file description into transport */
int recfd;     			/* file descriptor to accept        */
int length;     		/* length of address structure      */
int nbytes;     		/* the number of read **/
int tcp_send_flag ;
int client_connect_flag=0 ;
static int	disconnect_cnt ;
char buf[TCP_BUFSIZ],sbuf[TCP_BUFSIZ];
struct sockaddr_in myaddr; 	/* address of this service */
struct sockaddr_in client_addr; /* address of client    */
char cst[255];
//--------------------------------------------------------------------------------------------

char Rx_Tcpbuffer[TCP_BUFSIZ];

void tcp_server_start(void)
{
	//	Get a socket into TCP/IP
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) <0) 
	{
		perror ("socket failed");
		exit(1);
	}

	int val = 1;
	setsockopt(socket_fd, SOL_SOCKET,SO_REUSEADDR,(void *)&val,sizeof(int));	
	
	//	Set up our address
	bzero ((char *)&myaddr, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(SERV_PORT);

	//	Bind to the address to which the service will be offered
	if (bind(socket_fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) <0) 
	{
		perror ("bind failed");
		exit(1);
	}

	//	Set up the socket for listening, with a queue length of 5
	if (listen(socket_fd, 20) <0) 
	{
		perror ("listen failed");
		exit(1);
	}
}

void tcp_server_send(uint8_t *s, uint16_t len)
{	
	if(tcp_send_flag==1 && client_connect_flag)
	{

		if (write(recfd, s, len) == -1) 
		{
			perror ("write to client error");
			client_connect_flag = 0;
			close(recfd);
			//exit(1);
		}
		else
		{		
			printf("Send to client, Message:%p , len = %d\n",s, len);
		}
		tcp_send_flag = 0;
	}
}


void * Task_tcp_server_listen(void* arg)
{
	static int	TaskTcpRxLenth_Flag;
	static int	RxHopping=-1000;
	int 	i;
	

	length = sizeof(client_addr);
	printf("Server is ready to receive !!\n");
	while (1)
	{
		if ((recfd = accept(socket_fd, (struct sockaddr *)&client_addr, &length)) <0) 
		{
			perror ("could not accept call"); 
	 	}
		else
		{
			printf("Client connect from %s : %d\n",inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port)); 
			client_connect_flag = 1;
			disconnect_cnt = 0;
			while (client_connect_flag) 
			{
				memset(Rx_Tcpbuffer,0x00,TCP_BUFSIZ);
				TaskTcpRxLenth_Flag = recv(recfd, Rx_Tcpbuffer, TCP_BUFSIZ,0);

				if ((TaskTcpRxLenth_Flag) < 0) 
				{
					perror("read of data error nbytes !");
				}			
				else if(TaskTcpRxLenth_Flag >0)
				{
					Rx_Tcpbuffer[TaskTcpRxLenth_Flag] = 0x00;										
					printf("Received message from %s : %d\n",inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port));
					printf("Start save data to ring buffer....\n");
					Queue_RX_Write(Rx_Tcpbuffer,TaskTcpRxLenth_Flag);
					
					disconnect_cnt = 0;
				}
				else
				{
						printf("Client connect timeout...\n");
						client_connect_flag = 0;
						close(recfd);
						break;
				}
			}
			printf("Client disconnect from %s : %d\n",inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port)); 
			printf("Wait fot next clinet connect...\n");	
			client_connect_flag = 0;
		}
		usleep(1000000); //1ms
	}
}

