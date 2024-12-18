#define _GNU_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

struct sockaddr_storage srvr;

#define NUM_THREADS 20

#define BERNWEB_LINUX_SENDFILE_MAX 0x7ffff000
#define MINIMUM_RESP_SIZE 100 //todo

const struct sigaction siga = {.sa_handler = SIG_IGN};

#ifdef __ORDER_LITTLE_ENDIAN__
const uint16_t cs = 0x7363;
const uint16_t af = 0x6661;
const uint32_t rnrn = 0x0a0d0a0d;
#else
const uint16_t cs = 0x6373;
const uint16_t af = 0x6166;
const uint32_t rnrn = 0x0d0a0d0a;
#endif

const char * const files[] = {"/", "/02-raw.zip", "/zzz/"};
//const char * const files[] = {"/", "/zzz/"};

static inline uint64_t deltans(struct timespec *l, struct timespec *h)
{
	return ((h->tv_sec * 1000000000L) + h->tv_nsec) - ((l->tv_sec * 1000000000L) + l->tv_nsec);
}

static inline unsigned isrequestcomplete(char *reqresp, unsigned respindex)
{
	unsigned x;
	if (respindex < MINIMUM_RESP_SIZE)
	{
		return 0;
	}
	x = MINIMUM_RESP_SIZE;

	//todo fix this shit slow code
	while (x != respindex)
	{
		if ((*((uint32_t*)(&reqresp[x - sizeof(uint32_t)]))) == rnrn)
		{
			return x-1;
		}
		x++;
	}
	return 0;
}

static inline size_t processresponse(char *reqresp)
{
	char *s;
	//char *endptr;
	size_t retval;

	s = __builtin_strchr(reqresp, '\n');
	//end of HTTP/1.1
	s = __builtin_strchr(s+1, '\n');
	//end of Date
	s = __builtin_strchr(s+1, '\n');
	//end of Server
	s = __builtin_strchr(s+1, '\n');

	while (s)
	{
		if (!__builtin_memcmp(s, "Content-Length: ", sizeof("Content-Length: ") - 1))
		{
			//endptr yolo
			retval = strtoul(&s[16], NULL, 10);
			return retval;
		}
		s = __builtin_strchr(s, '\n');
		s++;
	}
	return 0;
}

void *worker(void *arg)
{
	int sock;
	char *reqresp;
	unsigned short findex;
	int reqlen;
	unsigned respindex;
	size_t fsize;
	size_t todl;
	size_t currecv;
	//int myerrno;
	int ssopt;
	ssize_t recvretval;
	unsigned headend;
	struct timespec start;
	struct timespec end;
	uint64_t dtns;
	long double mbs;

	(void)arg;

	reqresp = mmap(NULL, BERNWEB_LINUX_SENDFILE_MAX, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (reqresp == MAP_FAILED)
	{
		//myerrno = errno;
		perror("mmap()");
		return NULL;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1)
	{
		//myerrno = errno;
		perror("socket()");
		return NULL;
	}

	//the kernel's broken rt_tos2priority() function will
	//not do a good job for most DSCP values
	//but LE will result in a socket priority of 0 so it's fine!
	ssopt = IPTOS_DSCP_LE;
	if (setsockopt(sock, IPPROTO_IP, IP_TOS, &ssopt, sizeof(int)) == -1)
	{
		//myerrno = errno;
		perror("setsockopt()");
		return NULL;
	}

	if (connect(sock, (struct sockaddr*)&srvr, sizeof(struct sockaddr_storage)) == -1)
	{
		//myerrno = errno;
		perror("connect()");
		return NULL;
	}

	while (1)
	{
		__builtin_ia32_rdrand16_step(&findex);
		findex = findex % (sizeof(files)/sizeof(const char * const));
		//findex = 0;
		reqlen = __builtin_sprintf(reqresp, "GET %s HTTP/1.1\r\n\r\n", files[findex]);

		recvretval = send(sock, reqresp, reqlen, 0);
		if (recvretval != reqlen)
		{
			//myerrno = errno;
			perror("send()");
			return NULL;
		}

		respindex = 0;
		while (1)
		{
			recvretval = recv(sock, &reqresp[respindex], 4096, 0);
			if (recvretval <= 0)
			{
				//myerrno = errno;
				perror("recv()");
				return NULL;
			}
			respindex += recvretval;
			headend = isrequestcomplete(reqresp, respindex);
			if (headend)
			{
				reqresp[headend] = 0;
				break;
			}
		}

		clock_gettime(CLOCK_MONOTONIC, &start);
		fsize = processresponse(reqresp);
		todl = fsize;

		//printf("%'lu bytes\n", fsize);
		if (todl)
		{
			todl -= (respindex - (headend + 1));
		}

		while (todl)
		{
			currecv = todl;
			if (currecv > BERNWEB_LINUX_SENDFILE_MAX)
			{
				currecv = BERNWEB_LINUX_SENDFILE_MAX;
			}

			if (recv(sock, reqresp, currecv, MSG_WAITALL) != currecv)
			{
				//myerrno = errno;
				perror("recv()");
				return NULL;
			}
			todl -= currecv;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);

		dtns = deltans(&start, &end);
		mbs = (((long double)fsize)/((long double)1000000.0L))/(((long double)dtns)/1000000000.0L);
		printf("%s %'lu bytes %'lu.%09lus - %Lf MB/s\n", files[findex], fsize, dtns/1000000000L, dtns%1000000000L, mbs);
		//break;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int myerrno;
	pthread_t nt;
	pthread_attr_t pattr;
	unsigned char x;

	if (argc != 2)
	{
		puts("skill issue");
		return EINVAL;
	}

	((struct sockaddr_in*)&srvr)->sin_family = AF_INET;
	#ifdef __ORDER_LITTLE_ENDIAN__
	((struct sockaddr_in*)&srvr)->sin_port = __builtin_bswap16(80);
	#else
	((struct sockaddr_in*)&srvr)->sin_port = 80;
	#endif
	if (!inet_pton(AF_INET, argv[1], &((struct sockaddr_in*)&srvr)->sin_addr.s_addr))
	{
		puts("inet_pton() failed. Bad ip given!");
		return EINVAL;
	}

	if (sigaction(SIGPIPE, &siga, NULL))
	{
		myerrno = errno;
		perror("sigaction()");
		return myerrno;
	}

	pthread_attr_init(&pattr);
	myerrno = pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
	if (myerrno)
	{
		errno = myerrno;
		perror("pthread_attr_setdetachstate()");
		return myerrno;
	}

	x = 0;
	while (x!= (NUM_THREADS - 1))
	{
		myerrno = pthread_create(&nt, &pattr, worker, NULL);
		if (myerrno)
		{
			errno = myerrno;
			perror("pthread_create()");
			return myerrno;
		}
		x++;
	}

	worker(NULL);

	return 0;
}
