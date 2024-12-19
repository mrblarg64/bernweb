#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>

#include <locale.h>

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <bernweb-profiling.h>

#define MAX_IP_STR 46
//45 ip
//5 port
//1 space
//1 null
#define MAX_CLI_STR 52

const char * const profilingtypes[] = {"TLS HS Start", "TLS HS End", "recv()", "Oooooops!!!", "processrequest() start", "processrequest() end", "send() start", "send() end", "close()"};

//a map of what type to look for for the end of the
//current operation when calculating deltas
const unsigned char profilingexpectednext[] = {BERNWEB_P_TLS_HS_E, 0, BERNWEB_P_PR_S, 0, BERNWEB_P_PR_E, 0, BERNWEB_P_SEND_E, 0, 0};

struct cdfnode
{
	uint64_t value;
	uint64_t times;
	struct cdfnode *l;
	struct cdfnode *r;
};

struct cdf
{
	uint64_t total;
	struct cdfnode *n;
};

struct event
{
	struct event *next;
	struct packet *p;
};

struct client
{
	struct sockaddr_storage addr;
	struct client *l;
	struct client *r;
	struct event *head;
	struct event *tail;
};

int ofd;

struct client *clients = NULL;

//times
struct cdf hs = {.total = 0};//tls handshake
struct cdf rc = {.total = 0};//recv()
struct cdf pr = {.total = 0};//processrequest()
struct cdf st = {.total = 0};//send time
//metrics
struct cdf rtt = {.total = 0};
struct cdf ret = {.total = 0};

void printcdfrecursor(struct cdfnode *n)
{
	if (n->l)
	{
		printcdfrecursor(n->l);
	}

	//printf("%lu, %lu\n", n->value, n->times);
	dprintf(ofd, "%lu, %lu\n", n->value, n->times);

	if (n->r)
	{
		printcdfrecursor(n->r);
	}
}

static inline void printcdf(struct cdf *c)
{
	//printf("total %lu\n\n", c->total);
	if (c->total)
	{
		printcdfrecursor(c->n);
	}
}

static inline void initcdf(struct cdf *c, uint64_t value)
{
	c->total = 1;
	c->n = calloc(1, sizeof(struct cdfnode));
	if (!c->n)
	{
		perror("calloc()");
		exit(ENOMEM);
	}
	c->n->value = value;
	c->n->times = 1;
	return;
}

static inline void addtocdf(struct cdf *c, uint64_t value)
{
	struct cdfnode *cur;
	struct cdfnode **npos;

	if (__builtin_expect(!(c->total), 0))
	{
		initcdf(c, value);
		return;
	}

	c->total++;
	cur = c->n;

	while (1)
	{
		if (value == cur->value)
		{
			cur->times++;
			return;
		}
		if (value < cur->value)
		{
			if (cur->l)
			{
				cur = cur->l;
				continue;
			}
			npos = &cur->l;
			break;
		}
		if (cur->r)
		{
			cur = cur->r;
			continue;
		}
		npos = &cur->r;
		break;
	}

	*npos = calloc(1, sizeof(struct cdfnode));
	if (!(*npos))
	{
		perror("calloc()");
		exit(ENOMEM);
	}
	(*npos)->value = value;
	(*npos)->times = 1;
}

static inline void addeventtoclient(struct client *c, struct packet *p)
{
	c->tail->next = malloc(sizeof(struct event));
	if (!c->tail->next)
	{
		perror("malloc()");
	        exit(ENOMEM);
	}
	c->tail = c->tail->next;
	c->tail->next = NULL;
	c->tail->p = p;
}

void addstartupall(struct client *c, struct packet *p)
{
	if (c->l)
	{
		addstartupall(c->l, p);
	}
	if (c->r)
	{
		addstartupall(c->r, p);
	}
	addeventtoclient(c, p);
}

static inline void addnewclient(struct client **nc, struct packet *p)
{
	*nc = malloc(sizeof(struct client));
	if (!*nc)
	{
		perror("malloc");
		exit(ENOMEM);
	}
	__builtin_memcpy(&((*nc)->addr), &p->addr, sizeof(struct sockaddr_storage));
	(*nc)->l = NULL;
	(*nc)->r = NULL;
	(*nc)->head = malloc(sizeof(struct event));
	if (!(*nc)->head)
	{
		perror("malloc()");
		exit(ENOMEM);
	}
	(*nc)->tail = (*nc)->head;
	(*nc)->head->next = NULL;
	(*nc)->head->p = p;
	return;
}

static inline void addevent(struct packet *p)
{
	struct client *cur;
	int cmpretval;

	cur = clients;
	while (1)
	{
		cmpretval = __builtin_memcmp(&p->addr, &cur->addr, sizeof(struct sockaddr_storage));
		if (!cmpretval)
		{
			break;
		}
		if (cmpretval < 0)
		{
			if (cur->l)
			{
				cur = cur->l;
				continue;
			}
			addnewclient(&cur->l, p);
			return;
		}
		if (cur->r)
		{
			cur = cur->r;
			continue;
		}
		addnewclient(&cur->r, p);
		return;
	}
	addeventtoclient(cur, p);
}

static inline void getclistring(struct sockaddr_storage *s, char *clistring)
{
	char ipstring[MAX_IP_STR];
	uint16_t port;
        //get ip string
        if (s->ss_family == AF_INET)
        {
                inet_ntop(AF_INET, &((struct sockaddr_in*)s)->sin_addr.s_addr, ipstring, MAX_IP_STR);
                #ifdef __ORDER_LITTLE_ENDIAN__
                port = __builtin_bswap16(((struct sockaddr_in*)s)->sin_port);
                #else
                port = ((struct sockaddr_in*)s)->sin_port;
                #endif
        }
        else
        {
                inet_ntop(AF_INET6, &((struct sockaddr_in6*)s)->sin6_addr.s6_addr, ipstring, MAX_IP_STR);
                #ifdef __ORDER_LITTLE_ENDIAN__
                port = __builtin_bswap16(((struct sockaddr_in6*)s)->sin6_port);
                #else
                port = ((struct sockaddr_in6*)s)->sin6_port;
                #endif
        }

	__builtin_sprintf(clistring, "%s %hu", ipstring, port);
        return;
}

static inline void printevent(struct packet *p)
{
	struct packettcp *ptcp;
	
	printf("\t[%lu.%09li] - %s\n", p->time.tv_sec, p->time.tv_nsec, profilingtypes[p->type]);
	if (p->type == BERNWEB_P_STARTUP)
	{
		puts("\t\tstartup");
	}
	else if ((p->type == BERNWEB_P_TLS_HS_S) || (p->type == BERNWEB_P_RECV) || (p->type == BERNWEB_P_PR_E) || (p->type == BERNWEB_P_SEND_S))
	{
		puts("\t\tno tcp");
	}
	else
	{
		ptcp = (struct packettcp*)p;
		printf("\t\trtt = %'u\n\t\trtt-min = %'u\n\t\trtt-var = %'u\n\t\tcwnd = %'u\n\t\tpacing rate = %'llu\n\t\tmax pacing rate = %'llu\n\t\trx-bytes = %'llu\n\t\ttx-bytes = %'llu\n\t\tnotsent-bytes = %'u\n\t\tsegs out = %'u\n\t\tretrans = %u\n\t\tsmss = %u\n\t\trmss = %u\n\t\tpmtu %u\n", ptcp->t.tcpi_rtt, ptcp->t.tcpi_min_rtt, ptcp->t.tcpi_rttvar, ptcp->t.tcpi_snd_cwnd, ptcp->t.tcpi_pacing_rate, ptcp->t.tcpi_max_pacing_rate, ptcp->t.tcpi_bytes_received, ptcp->t.tcpi_bytes_sent, ptcp->t.tcpi_notsent_bytes, ptcp->t.tcpi_segs_out, ptcp->t.tcpi_total_retrans, ptcp->t.tcpi_snd_mss, ptcp->t.tcpi_rcv_mss, ptcp->t.tcpi_pmtu);
	}
}

static inline uint64_t deltans(struct timespec *l, struct timespec *h)
{
	return ((h->tv_sec * 1000000000L) + h->tv_nsec) - ((l->tv_sec * 1000000000L) + l->tv_nsec);
}

static inline void printdelta(struct timespec *l, struct timespec *h)
{
	//struct timespec dt;
	unsigned long dtns;

	//dtns = ((h->tv_sec * 1000000000L) + h->tv_nsec) - ((l->tv_sec * 1000000000L) + l->tv_nsec);
	dtns = deltans(l, h);
	printf("\tTime delta %lu.%09lus - %luns\n", dtns/1000000000L, dtns%1000000000L, dtns);
}

void eventsclientorder(struct client *c, unsigned char print)
{
	char clistr[MAX_CLI_STR];
	struct event *ce;//current event
	struct event *tde;//time delta event
	struct event *pe = NULL;//previous event
	//struct event *pss;//previous send start;
	//unsigned char lookforsendcomp = 0;
	unsigned char en;//expected next

	if (c->l)
	{
		eventsclientorder(c->l, print);
	}

	if (print)
	{
		getclistring(&(c->addr), clistr);
		printf("[%s]\n", clistr);
	}

	ce = c->head;
	tde = ce;
	en = profilingexpectednext[tde->p->type];
	while (ce)
	{
		if (__builtin_expect(ce->p->type == BERNWEB_P_STARTUP, 0))
		{
			en = profilingexpectednext[c->head->p->type];
		}
		else if (ce->p->type == en)
		{
			if (!print)
			{
				switch (tde->p->type)
				{
				case BERNWEB_P_TLS_HS_S:
					addtocdf(&hs, deltans(&(tde->p->time), (&ce->p->time)));
					break;
				case BERNWEB_P_RECV:
					addtocdf(&rc, deltans(&(tde->p->time), (&ce->p->time)));
					break;
				case BERNWEB_P_PR_S:
					addtocdf(&pr, deltans(&(tde->p->time), (&ce->p->time)));
					break;
				case BERNWEB_P_SEND_S:
					addtocdf(&st, deltans(&(tde->p->time), (&ce->p->time)));
					break;
				}
			}

			if (print)
			{
				printf("\n\t%s -> %s ================================================================\n", profilingtypes[tde->p->type], profilingtypes[ce->p->type]);
				printdelta(&(tde->p->time), (&ce->p->time));
			}

			/* if ((ce->p->type == BERNWEB_P_SEND_S)) */
			/* { */
			/* 	lookforsendcomp = 0; */
			/* } */
			/* else if ((ce->p->type == BERNWEB_P_SEND_E)) */
			/* { */
			/* 	if (((struct packettcp*)(ce->p))->t.tcpi_notsent_bytes) */
			/* 	{ */
			/* 		lookforsendcomp = 1; */
			/* 	} */
			/* 	else */
			/* 	{ */
			/* 		//TRUE SEND COMPLETION HERE */
			/* 		lookforsendcomp = 0; */
			/* 		puts("SEND COMPLETION DETECTED"); */
			/* 		printdelta(&(pss->p->time), (&ce->p->time)); */
			/* 	} */
			/* } */
			/* else if (ce->p->type == BERNWEB_P_PR_S) */
			/* { */
			/* 	if (lookforsendcomp) */
			/* 	{ */
			/* 		//TRUE SEND COMPLETION HERE */
			/* 		lookforsendcomp = 0; */
			/* 		puts("SEND COMPLETION DETECTED"); */
			/* 		printdelta(&(pss->p->time), (&ce->p->time)); */
			/* 	} */
			/* } */
		}
		/* else if (ce->p->type == BERNWEB_P_SEND_S) */
		/* { */
		/* 	pss = ce; */
		/* } */
		else if ((ce->p->type == BERNWEB_P_CLOSE) && pe)
		{
			//printevent(ce->p);
			if (!print)
			{
				addtocdf(&rtt, ((struct packettcp*)(ce->p))->t.tcpi_rtt);
				addtocdf(&ret, ((struct packettcp*)(ce->p))->t.tcpi_total_retrans);
			}
			//printf("PSCE %p\n", psce);
			/* if (lookforsendcomp) */
			/* { */
			/* 	//TRUE SEND COMPLETION HERE */
			/* 	lookforsendcomp = 0; */
			/* 	puts("SEND COMPLETION DETECTED"); */
			/* 	printdelta(&(pss->p->time), (&ce->p->time)); */
			/* } */
			//printdelta(&(pe->p->time), (&ce->p->time));
		}

		if (profilingexpectednext[ce->p->type])
		{
			tde = ce;
			en = profilingexpectednext[ce->p->type];
		}
		if (print)
		{
			printevent(ce->p);
		}
		pe = ce;
		ce = ce->next;
	}

	if (c->r)
	{
	        eventsclientorder(c->r, print);
	}
}

int main(int argc, char *argv[])
{
	int myerrno;
	int fd;
	struct stat fst;
	uint8_t *finram;
	off_t curpos;
	int curfile;
	char *myname;

	setlocale(LC_ALL, "");

	if (argc > 2)
	{
		curfile = 2;
	}
	else if (argc == 2)
	{
		curfile = 1;
	}
	else
	{
		if (argc)
		{
			myname = argv[0];
		}
		else
		{
			myname = "Unknown";
		}
		printf("Usage: %s [OUTPUT_DIRECTORY] FILE_TO_ANALYZE [MORE_FILES_IF_YOU_HAVE_AN_OUTPUT_DIRECTORY [..]]\n\tRun with one argument (e.g. %s FILE) this program will print decode the profiling data and print it to\n\tstdout\n\tRun with two or more arguments (e.g %s DIRECTORY FILE_A [FILE_B]) it will create the directory DIRECTORY and store a\n\tsorted list of various paramaters along with a count of how many times they were scene.\n\tThis allows you to trivially generate a CCDF with spreadsheet software.\n", myname, myname, myname);
		return EINVAL;
	}

	while (curfile != argc)
	{
		fd = open(argv[curfile], O_RDONLY);
		if (fd == -1)
		{
			myerrno = errno;
			perror("input file open()");
			return myerrno;
		}

		/* ofd = open(argv[2], O_CREAT | O_EXCL | O_WRONLY | O_APPEND, 0644); */
		/* if (ofd == -1) */
		/* { */
		/* 	myerrno = errno; */
		/* 	perror("output file open()"); */
		/* 	return myerrno; */
		/* } */

		if (fstat(fd, &fst))
		{
			myerrno = errno;
			perror("input file fstat()");
			return myerrno;
		}

		finram = mmap(NULL, fst.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (finram == MAP_FAILED)
		{
			myerrno = errno;
			perror("input file mmap()");
			return myerrno;
		}
		close(fd);

		curpos = 0;

		if (finram[curpos] != BERNWEB_P_STARTUP)
		{
			puts("The profiling file starts with an event other than the startup event!");
			return EINVAL;
		}

		while (curpos != fst.st_size)
		{
			if (finram[curpos] == BERNWEB_P_STARTUP)
			{
				if (clients)
				{
					addstartupall(clients, (struct packet*) &finram[curpos]);
				}
				curpos += sizeof(struct packet);
			}
			else
			{
				if (__builtin_expect(!clients, 0))
				{
					addnewclient(&clients, (struct packet *)&finram[curpos]);
				}
				else
				{
					addevent((struct packet *)&finram[curpos]);
				}
			}
			switch (finram[curpos])
			{
			case BERNWEB_P_TLS_HS_S:
				curpos += sizeof(struct packet);
				break;
			case BERNWEB_P_TLS_HS_E:
				//printdata((struct packettcp *)&finram[curpos]);
				curpos += sizeof(struct packettcp);
				break;
			case BERNWEB_P_RECV:
				curpos += sizeof(struct packet);
				break;
			case BERNWEB_P_PR_S:
				//printdata((struct packettcp *)&finram[curpos]);
				curpos += sizeof(struct packettcp);
				break;
			case BERNWEB_P_PR_E:
				curpos += sizeof(struct packet);
				break;
			case BERNWEB_P_SEND_S:
				curpos += sizeof(struct packet);
				break;
			case BERNWEB_P_SEND_E:
				//printdata((struct packettcp *)&finram[curpos]);
				curpos += sizeof(struct packettcp);
				break;
			case BERNWEB_P_CLOSE:
				//printdata((struct packettcp *)&finram[curpos]);
				curpos += sizeof(struct packettcp);
				break;
			case BERNWEB_P_STARTUP:
				curpos += sizeof(struct packet);
				break;
			}
		}

		curfile++;
	}


	//printcdf(&rc);

	if (argc == 2)
	{
		eventsclientorder(clients, 1);
	}
	else
	{
		eventsclientorder(clients, 0);

		if (mkdir(argv[1], 0755))
		{
			myerrno = errno;
			perror("output directory mkdir()");
			return myerrno;
		}

		fd = open(argv[1], O_PATH | O_DIRECTORY);
		if (fd == -1)
		{
			myerrno = errno;
			perror("output directory open()");
			puts("attempting to remove the directory...");
			if (rmdir(argv[1]))
			{
				perror("rmdir()");
			}
			else
			{
				puts("done!");
			}
			return myerrno;
		}

		ofd = openat(fd, "pdf-handshake.csv", O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (ofd == -1)
		{
			myerrno = errno;
			perror("pdf-handshake.csv O_EXCL openat()");
			return myerrno;
		}
		printcdf(&hs);
		close(ofd);

		ofd = openat(fd, "pdf-recv.csv", O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (ofd == -1)
		{
			myerrno = errno;
			perror("pdf-recv.csv O_EXCL openat()");
			return myerrno;
		}
		printcdf(&rc);
		close(ofd);

		ofd = openat(fd, "pdf-processrequest.csv", O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (ofd == -1)
		{
			myerrno = errno;
			perror("pdf-processrequest.csv O_EXCL openat()");
			return myerrno;
		}
		printcdf(&pr);
		close(ofd);

		ofd = openat(fd, "pdf-send.csv", O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (ofd == -1)
		{
			myerrno = errno;
			perror("pdf-send.csv O_EXCL openat()");
			return myerrno;
		}
		printcdf(&st);
		close(ofd);

		ofd = openat(fd, "pdf-rtt.csv", O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (ofd == -1)
		{
			myerrno = errno;
			perror("pdf-rtt.csv O_EXCL openat()");
			return myerrno;
		}
		printcdf(&rtt);
		close(ofd);

		ofd = openat(fd, "pdf-retransmission-count.csv", O_WRONLY | O_CREAT | O_EXCL, 0644);
		if (ofd == -1)
		{
			myerrno = errno;
			perror("pdf-retransmission-count.csv O_EXCL openat()");
			return myerrno;
		}
		printcdf(&ret);
		close(ofd);

		close(fd);
	}
}
