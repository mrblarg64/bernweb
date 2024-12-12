#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>

#include <stdlib.h>
#include <stdio.h>

#include <bernweb-profiling.h>

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

struct client *clients = NULL;

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
	puts("nc");
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

int main(int argc, char *argv[])
{
	int myerrno;
	int ifd;
	int ofd;
	struct stat fst;
	uint8_t *finram;
	off_t curpos = 0;

	if (argc != 3)
	{
		puts("skill issue");
		return EINVAL;
	}

	ifd = open(argv[1], O_RDONLY);
	if (ifd == -1)
	{
		myerrno = errno;
		perror("input file open()");
		return myerrno;
	}

	ofd = open(argv[2], O_CREAT | O_EXCL | O_WRONLY | O_APPEND, 0644);
	if (ofd == -1)
	{
		myerrno = errno;
		perror("output file open()");
		return myerrno;
	}

	if (fstat(ifd, &fst))
	{
		myerrno = errno;
		perror("input file fstat()");
		return myerrno;
	}

	finram = mmap(NULL, fst.st_size, PROT_READ, MAP_PRIVATE, ifd, 0);
	if (finram == MAP_FAILED)
	{
		myerrno = errno;
		perror("input file mmap()");
	}
	close(ifd);

	if (finram[0] != BERNWEB_P_STARTUP)
	{
		puts("The profiling file starts with an event other than the startup event!");
		return EINVAL;
	}

	while (curpos != fst.st_size)
	{
		if ((finram[curpos] == BERNWEB_P_STARTUP) && clients)
		{
			addstartupall(clients, (struct packet*) &finram[curpos]);
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
			curpos += sizeof(struct packettcp);
			break;
		case BERNWEB_P_RECV:
			curpos += sizeof(struct packet);
			break;
		case BERNWEB_P_PR_S:
			curpos += sizeof(struct packettcp);
			break;
		case BERNWEB_P_PR_E:
			curpos += sizeof(struct packet);
			break;
		case BERNWEB_P_SEND_S:
			curpos += sizeof(struct packet);
			break;
		case BERNWEB_P_SEND_E:
			curpos += sizeof(struct packettcp);
			break;
		case BERNWEB_P_CLOSE:
			curpos += sizeof(struct packettcp);
			break;
		case BERNWEB_P_STARTUP:
			curpos += sizeof(struct packet);
			break;
		}
	}
}
