#include "server.h"
#include "Queue.h"
#include "common.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SERV_PORT 10010
#define TCP_BUFSIZ 1024

int errno;
int socket_fd; /* file description into transport */
int recfd;     /* file descriptor to accept        */
int length;    /* length of address structure      */
int nbytes;    /* the number of read **/
int tcp_send_flag;
int client_connect_flag = 0;
static int disconnect_cnt;
char buf[TCP_BUFSIZ], sbuf[TCP_BUFSIZ];
struct sockaddr_in myaddr;      /* address of this service */
struct sockaddr_in client_addr; /* address of client    */
char cst[255];

//--------------------------------------------------------------------------------------------

char Rx_Tcpbuffer[TCP_BUFSIZ];

typedef struct tcp_server_thread {
  bool isConnect;
  int sock;
  struct sockaddr_in client_addr;
  struct tcp_server_thread *next;
} tcp_server_thread_t;

tcp_server_thread_t *clientList;

void tcp_client_list_insert(tcp_server_thread_t **list,
                            tcp_server_thread_t *p) {
  // printf(LIGHT_RED"tcp_client_list_insert\r\n"NONE);

  tcp_server_thread_t *q = *list;

  if (q == 0) {
    *list = p;
  } else {
    while (q->next) {
      q = q->next;
    }
    q->next = p;
  }
}

tcp_server_thread_t *tcp_client_list_delete(tcp_server_thread_t **list,
                                            int sock) {
  // printf(LIGHT_RED"tcp_client_list_delete\r\n"NONE);

  tcp_server_thread_t *p, *q;

  if (*list == 0) {
    return 0;
  }
  p = *list;
  if (p->sock == sock) {
    *list = p->next;
    return p;
  }
  q = p->next;
  while (q) {
    if (q->sock == sock) {
      p->next = q->next;
      return q;
    }
    p = q;
    q = q->next;
  }
  return 0;
}

tcp_server_thread_t *tcp_client_list_search(tcp_server_thread_t *list,
                                            int sock) {
  // printf(LIGHT_RED"tcp_client_list_search\r\n"NONE);

  tcp_server_thread_t *p = list;

  while (p) {
    if (p->sock == sock) {
      return p;
    }
    p = p->next;
  }
  return 0;
}

void tcp_server_start(void) {
  //	Get a socket into TCP/IP
  if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket failed");
    exit(1);
  }

  int val = 1;
  setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(int));

  //	Set up our address
  bzero((char *)&myaddr, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_port = htons(SERV_PORT);

  //	Bind to the address to which the service will be offered
  if (bind(socket_fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
    perror("bind failed");
    exit(1);
  }

  //	Set up the socket for listening, with a queue length of 5
  if (listen(socket_fd, 20) < 0) {
    perror("listen failed");
    exit(1);
  }
}

void tcp_server_send(uint8_t *s, uint16_t len) {
  tcp_server_thread_t *p = clientList;

  while (p) {
    if (write(p->sock, s, len) == -1) {
      perror("write to client error");
      // client_connect_flag = 0;
      p->isConnect = false;
      close(p->sock);
      // exit(1);
    } else {
      // printf("Send to client, Message: %p, len = %d\n", s, len);
      printf("Send to %s: %d, len: %d\r\n", inet_ntoa(p->client_addr.sin_addr),
             htons(p->client_addr.sin_port), len);
    }
    p = p->next;
  }
}

bool gateway_command_check(unsigned char *buf, unsigned int len) {
  unsigned int command_header =
      (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];

  if (command_header != 0xFFFCFCFF) {
    printf("Header Error\r\n");
    return false;
  }

  if (len != 4 + buf[4] + 1 + 1) {
    printf("Length Error\r\n");
    printf("received len: %d\r\n", len);
    return false;
  }

  unsigned char checksum = 0;
  unsigned char *ptr;

  ptr = &buf[4];
  for (unsigned int i = 0; i < 1 + buf[4]; i++) {
    checksum += *ptr;
    ptr++;
  }
  checksum = ~checksum;
  checksum &= 0xFF;
  if (*ptr != checksum) {
    printf("Checksum Error\r\n");
    printf("expected: %02x\r\n", checksum);
    printf("received: %02x\r\n", *ptr);
    return false;
  }

  return true;
}

void *connection_handler(void *arg) {
  char buffer[TCP_BUFSIZ];
  size_t bytes_read;
  tcp_server_thread_t *sock = arg;

  while (sock->isConnect) {
    memset(buffer, 0x0, TCP_BUFSIZ);
    if ((bytes_read = read(sock->sock, buffer, sizeof(buffer))) < 0) {
      perror("read from client error");
    } else if (bytes_read > 0) {
      buffer[bytes_read] = 0;
      printf("Received message from %s: %d\n", inet_ntoa(client_addr.sin_addr),
             htons(client_addr.sin_port));

      // for (int i = 0; i < bytes_read; i++)
      // {
      // 	printf("%02x ", buffer[i]);
      // }
      // printf("\r\n");

      if (!gateway_command_check(buffer, bytes_read)) {
        continue;
      }

      printf("Start save data to ring buffer....\n");
      Queue_RX_Write(buffer, bytes_read);
    } else {
      // printf("Client connect timeout...\n");
      sock->isConnect = false;
      close(sock->sock);
      // break;
    }
    usleep(1000); // 1ms
  }
  printf("Client disconnect from %s: %d\n", inet_ntoa(client_addr.sin_addr),
         htons(client_addr.sin_port));
  // printf("Wait fot next clinet connect...\n");
  sock->isConnect = false;

  tcp_server_thread_t *ptr;
  ptr = tcp_client_list_delete(&clientList, sock->sock);
  if (ptr != NULL) {
    free(ptr);
  }
}

void *Task_tcp_server_listen(void *arg) {
  static int TaskTcpRxLenth_Flag;
  static int RxHopping = -1000;
  int i;

  length = sizeof(client_addr);
  printf("Server is ready to receive !!\n");
  while (1) {
    if ((recfd = accept(socket_fd, (struct sockaddr *)&client_addr, &length)) <
        0) {
      printf("connect error\r\n");
    } else {
      printf("Client connect from %s: %d\n", inet_ntoa(client_addr.sin_addr),
             htons(client_addr.sin_port));

      pthread_t t;
      tcp_server_thread_t *pClient;

      pClient = malloc(sizeof(tcp_server_thread_t));
      pClient->next = NULL;
      pClient->isConnect = true;
      pClient->sock = recfd;
      pClient->client_addr = client_addr;
      tcp_client_list_insert(&clientList, pClient);
      pthread_create(&t, NULL, connection_handler, pClient);
    }
    usleep(1000); // 1ms
  }
}
