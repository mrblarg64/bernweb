#ifndef BERNWEB_PROFILING_H
#define BERNWEB_PROFILING_H


#include <sys/socket.h>
//#include <netinet/tcp.h>
#include <linux/tcp.h>

#include <stdint.h>

#define BERNWEB_P_TLS_HS_S 0
#define BERNWEB_P_TLS_HS_E 1//tcp
#define BERNWEB_P_RECV 2
#define BERNWEB_P_PR_S 4//tcp
#define BERNWEB_P_PR_E 5
#define BERNWEB_P_SEND_S 6
#define BERNWEB_P_SEND_E 7//tcp
#define BERNWEB_P_CLOSE 8//tcp
#define BERNWEB_P_STARTUP 0xff//since we are using monotonic we need to have an initial time

struct packet
{
	uint8_t type;
	struct sockaddr_storage addr;
	struct timespec time;
}__attribute((packed));

struct packettcp
{
	struct packet p;
	struct tcp_info t;
}__attribute((packed));

#endif
