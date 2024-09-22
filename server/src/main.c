//Copyright (C) 2024 Brian William Denton
//Available under the GNU GPLv3 License

#define _GNU_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#define BERNWEB_LOG_REQUESTS

#ifdef BERNWEB_INTERNAL_DENTRY
#error "unfinished due to https://gitlab.com/gnutls/gnutls/-/issues/1580"
#endif

#ifdef BERNWEB_INTERNAL_DENTRY
#include <dirent.h>
#endif

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>

#include <bernweb-xattr.h>

#define BERNWEB_LINUX_SENDFILE_MAX 0x7ffff000

//#define BERNWEB_SH_FLOCK_FILES
#ifndef BERNWEB_PAGE_SIZE
//define this in your CFLAGS if you need to change it
#define BERNWEB_PAGE_SIZE 4096
#endif

//255 for mime
//1 for dscp
#define XATTR_BUF_SIZE 256

#define REQUEST_FLAG_GET 0b1
#define REQUEST_FLAG_IF_RANGE_ETAG 0b10
#define REQUEST_FLAG_IF_NONE_MATCH 0b100
#define REQUEST_FLAG_SRANGE 0b1000
#define REQUEST_FLAG_ERANGE 0b10000
#define REQUEST_FLAG_RANGE_MASK (REQUEST_FLAG_SRANGE | REQUEST_FLAG_ERANGE)
#define REQUEST_FLAG_TLS 0b100000

#define NEW_NOFILE_NUM 548576
#ifndef DEBUG
const struct rlimit newnofile = {NEW_NOFILE_NUM, NEW_NOFILE_NUM};
#else
struct rlimit newnofile = {NEW_NOFILE_NUM, NEW_NOFILE_NUM};
#endif
const struct sigaction siga = {.sa_handler = SIG_IGN};
struct open_how oh = {0};

#define SOCKET_MAX_PRIORITY 6

#define MAX_ACCEPT_EP_EVENTS 100
#define MAX_THREAD_EP_EVENTS 100

#define CONFIG_FILE "/etc/bernweb/bernweb.conf"
#define NEWLINE_CHARS "\n\r"
#define WHITESPACE_CHARS " \t="
#define CONFIG_USERNAME "user"
#define CONFIG_DOCROOT "documentroot"
#define CONFIG_LOGFILE "logfile"
#define CONFIG_CERTFILE "pubcert"
#define CONFIG_KEYFILE "privkey"
#define CONFIG_HTTP_THREADS "httpthreads"
#define CONFIG_HTTPS_THREADS "httpsthreads"
#define CONFIG_DEFAULT_SOCKET_PRIORITY "defaultpriority"
#define CONFIG_DEFAULT_DSCP "defaultdscp"
//#define CONFIG_HTTP_LOGFILE "httplog"
//#define CONFIG_HTTPS_LOGFILE "httpslogfile"
#ifdef BERNWEB_SET_KEEPIDLE
#define CONFIG_TCPKEEPIDLE "tcpkeepidle"
int ssoptkidle = -1;
#endif

#ifdef __ORDER_LITTLE_ENDIAN__
const uint16_t cs = 0x7363;
const uint16_t af = 0x6661;
const uint32_t rnrn = 0x0a0d0a0d;
#else
const uint16_t cs = 0x6373;
const uint16_t af = 0x6166;
const uint32_t rnrn = 0x0d0a0d0a;
#endif

const char * const daystrs[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
const char * const monthstrs[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
#ifdef __ORDER_LITTLE_ENDIAN__
#define MONTH_JAN 0x206e614a
#define MONTH_FEB 0x20626546
#define MONTH_MAR 0x2072614d
#define MONTH_APR 0x20727041
#define MONTH_MAY 0x2079614d
#define MONTH_JUN 0x206e754a
#define MONTH_JUL 0x206c754a
#define MONTH_AUG 0x20677541
#define MONTH_SEP 0x20706553
#define MONTH_OCT 0x2074634f
#define MONTH_NOV 0x20766f4e
#define MONTH_DEC 0x20636544
#else
#define MONTH_JAN 0x4a616e20
#define MONTH_FEB 0x46656220
#define MONTH_MAR 0x4d617220
#define MONTH_APR 0x41707220
#define MONTH_MAY 0x4d617920
#define MONTH_JUN 0x4a756e20
#define MONTH_JUL 0x4a756c20
#define MONTH_AUG 0x41756720
#define MONTH_SEP 0x53657020
#define MONTH_OCT 0x4f637420
#define MONTH_NOV 0x4e6f7620
#define MONTH_DEC 0x44656320
#endif

#define MAX_IP_STR 46
//45 ip
//5 port
//1 space
//1 null
#define MAX_CLI_STR 52

#define REQUEST_SIZE 3872
#define MINIMUM_REQ_SIZE 18
//1 for /
//10 for index.html
//1 for null
#define RESERVED_REQ_SIZE 12


/////////////////////////////////////////////////////
//#define STATE_MASK 0b111

#define HTTP_STATE_PRE_RECV 0
#define HTTP_STATE_RECV 2
#define HTTP_STATE_RESPONDING_HEADER_ONLY_HUP 3
#define HTTP_STATE_RESPONDING_HEADER_ONLY 4
#define HTTP_STATE_RESPONDING_HEADER_FILE 5
#define HTTP_STATE_RESPONDING_FILE 6

#define TLS_STATE_PRE_HANDSHAKE 0
#define TLS_STATE_HANDSHAKE 1
#define TLS_STATE_RECV 2
#define TLS_STATE_RESPONDING_HEADER_ONLY_HUP 3
#define TLS_STATE_RESPONDING_HEADER_ONLY 4
#define TLS_STATE_RESPONDING_HEADER_FILE 5
#define TLS_STATE_RESPONDING_FILE 6
/////////////////////////////////////////////////////

struct clicon
{
	int fd;
        off_t srange;
	uint64_t erange;
	gnutls_session_t session;
	char clistr[MAX_CLI_STR];
	unsigned char state;
	uint8_t prevdscp;
	struct sockaddr_storage addr;
	unsigned short reqindex;
	unsigned short resphsize;
	char r[REQUEST_SIZE];
};

//#define BERNWEB_MADV_FREE

struct request
{
	char *file;
	char *uagent;
	char *referer;
	struct timeval ifmatch;//done
	time_t ifmodsince;//done
	struct timeval ifrange;//done
	unsigned char flags;
};

struct request phonyreq = {.flags = REQUEST_FLAG_GET};

///////////////////////////////////////////////////////////////
//request
//etag size 24

//012345678901234567890123456789
//Mon, 01 Aug 2024 01:01:01 GMT

//if-modified-since - ignore if if-none-match
//01234567890123456789012345678901234567890123456789 - 48
//"If-Modified-Since: Mon, 01 Aug 2024 01:01:01 GMT"
//48

//if-none-match
//012345678901234567 - 17
//"If-None-Match: """
//24 + 17 = 41

//if-match
//0123456789012 - 12
//"If-Match: """
//24 + 12 = 36

//if-range
//0123456789012345678901234567890123456789 - 39
//"If-Range: Mon, 01 Aug 2024 01:01:01 GMT"
//0123456789012 - 12
//"If-Range: """
//39
//24 + 12 = 36

//range
//0123456789012345 - 15
//"Range: bytes=0-"
//15+

//referer
//01234567890 - 10
//"Referer: x"
//10+

//user-agent
//01234567890123 - 13
//"User-Agent: x"
//13+
///////////////////////////////////////////////////////////////

//response
//494 request header too large
//416 range not satisfiable
//405 method not allowed
//304 not modified

//http/1.1 200 OK
//date
//server: bernweb
//last-modified
//etag
//accept-ranges: bytes
//content-length: 23423
//keep-alive - don't need//////////////////////////////////////////////////////////////////
//connection - don't need//////////////////////////////////////////////////////////////////
//content-type: mime


//globals
int logfd;
int docrootfd;
uid_t runasuid;
gid_t runasgid;
char *logfilepath = NULL;
char *docrootpath = NULL;
char *pubcertpath = NULL;
char *privkeypath = NULL;
gnutls_certificate_credentials_t x509cred;
gnutls_priority_t pcache;
//char *httplogpath = NULL;
//char *httpslogpath = NULL;
unsigned short httpthreads;
unsigned short httpsthreads;
unsigned char sockprio = 0;
uint8_t defaultdscp = 0;
int *epfd;
int *tlsepfd;
struct clicon *clitable;

static inline short processdscp(const char * const s)
{
	size_t slen;
	short offset;
	short retval;

	slen = __builtin_strlen(s);

	if (slen == 2)
	{
		if (!__builtin_strcmp(s, "ef"))
		{
			return IPTOS_DSCP_EF;
		}
		if (!__builtin_strcmp(s, "le"))
		{
			return IPTOS_DSCP_LE;
		}
	}
	else if (slen == 3)
	{
		if ((*(uint16_t*)s) == cs)
		{
			offset = ((*(unsigned char*)&s[2]) - 0x30);
			if ((offset > 7) || (offset < 0))
			{
				return -1;
			}
			return (0x20 * offset);
		}
	}
	else if (slen == 4)
	{
		if ((*(uint16_t*)s) == af)
		{
			offset = ((*(unsigned char*)&s[2]) - 0x30);
			if ((offset > 4) || (offset < 1))
			{
				return -1;
			}
			retval = ((0x20 * offset));
			offset = ((*(unsigned char*)&s[3]) - 0x30);
			if ((offset > 3) || (offset < 1))
			{
				return -1;
			}
			return (retval + (offset * 0x8));
		}
	}
	return -1;
}

#ifdef BERNWEB_INTERNAL_DENTRY
void dentryrecursor(int dirfd)
{
	while (1)
	{
		dentretval = getdents64(fd, dents, DENT_BUF_SIZE);
		if (dentretval == -1)
		{
			myerrno = errno;
			perror("getdents64()");
			exit(myerrno);
		}
		if (dentretval == 0)
		{
			return 0;
		}
		curdentpos = 0;
		while (curdentpos != dentretval)
		{
			curdent = (struct dirent64*)&dents[curdentpos];
			if (curdent->d_type == DT_REG)
			{
				__builtin_strcpy(&relpath[pathpos+1], curdent->d_name);
				*prevnext = malloc(sizeof(transqentry));
				if (!prevnext)
				{
					
				}
				/* curtv->type = FTB_TYPE_FILE; */
				/* if (my_send_waitall(session, curtv, sizeof(struct ftblstv)) != sizeof(struct ftblstv)) */
				/* { */
				/* 	goto lstvrecursorfailure; */
				/* } */
				/* if (sendstringretcode(curdent->d_name, session)) */
				/* { */
				/* 	goto lstvrecursorfailure; */
				/* } */
			}
			else if ((curdent->d_type == DT_DIR)&&(curdent->d_name[0] != '.'))
			{
				dirfd = openat(fd, curdent->d_name, O_RDONLY | O_DIRECTORY);
				if (dirfd == -1)
				{
					goto lstvrecursorfailure;
					myerrno = errno;
					perror("lstvrecursor() dirfd failed openat()");
					exit(myerrno);
				}
				/* curtv->type = FTB_TYPE_DIRECTORY; */
				/* if (my_send_waitall(session, curtv, sizeof(struct ftblstv)) != sizeof(struct ftblstv)) */
				/* { */
				/* 	goto lstvrecursorfailure; */
				/* } */
				/* if (sendstringretcode(curdent->d_name, session)) */
				/* { */
				/* 	goto lstvrecursorfailure; */
				/* } */
				/* if (__builtin_add_overflow(curtv->depth, 1, &curtv->depth)) */
				/* { */
				/* 	curtv->depth--; */
				/* 	goto lstvrecursorfailure; */
				/* } */
				retval = lstvrecursor(dirfd, curtv, cliinfo, session);
				/* curtv->depth--; */
				if (retval)
				{
					goto lstvrecursorfailure;
				}
				close(dirfd);
				dirfd = -1;
			}
			curdentpos += curdent->d_reclen;
		}
	}
}

static inline void generatedentry()
{
	dentryrecursor(docrootfd);
}
#endif


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

static inline void logmsg(const char *msg)
{
	struct timespec curtime;
	struct tm tmcurtime;

	clock_gettime(CLOCK_REALTIME, &curtime);
	localtime_r(&curtime.tv_sec, &tmcurtime);

	dprintf(logfd, "[%i-%02i-%02i %02i:%02i:%02i.%03li] - %s\n", tmcurtime.tm_year + 1900, tmcurtime.tm_mon + 1, tmcurtime.tm_mday, tmcurtime.tm_hour, tmcurtime.tm_min, tmcurtime.tm_sec, curtime.tv_nsec/1000000, msg);
}

static inline void logmsgcli(const struct clicon *const curcli, const char *const msg)
{
	struct timespec curtime;
	struct tm tmcurtime;

	clock_gettime(CLOCK_REALTIME, &curtime);
	localtime_r(&curtime.tv_sec, &tmcurtime);

	dprintf(logfd, "[%i-%02i-%02i %02i:%02i:%02i.%03li] - [%s] - tls - %s\n", tmcurtime.tm_year + 1900, tmcurtime.tm_mon + 1, tmcurtime.tm_mday, tmcurtime.tm_hour, tmcurtime.tm_min, tmcurtime.tm_sec, curtime.tv_nsec/1000000, curcli->clistr, msg);
}

static inline void logrequest(const struct clicon *const curcli, unsigned short rcode, const struct request *const parsedreq, struct timespec *curtime)
{
	struct tm tmcurtime;

	localtime_r(&curtime->tv_sec, &tmcurtime);

	dprintf(logfd, "[%i-%02i-%02i %02i:%02i:%02i.%03li] - [%s] - %s - \"%s %s\" %hu \"%s\" \"%s\"\n",
		tmcurtime.tm_year + 1900,
		tmcurtime.tm_mon + 1,
		tmcurtime.tm_mday,
		tmcurtime.tm_hour,
		tmcurtime.tm_min,
		tmcurtime.tm_sec,
		curtime->tv_nsec/1000000,
		curcli->clistr,
		(parsedreq->flags & REQUEST_FLAG_TLS) ? "tls" : "http",
		(parsedreq->flags & REQUEST_FLAG_GET) ? "GET" : "HEAD",
		(parsedreq->file) ? parsedreq->file : "BERNWEB_PARSE_ERROR",
		rcode,
		(parsedreq->referer) ? parsedreq->referer : "-",
		(parsedreq->uagent) ? parsedreq->uagent : "-");
}

static inline void loadconfig()
{
	int myerrno;
	int cfd;
	struct stat fst;
	struct passwd *u;
	char *finram;
	char *cursor;
	char *curline;
	char *curtok;
	char *toka;
	char *tokb;
	unsigned char founduser=0;
	unsigned char foundhttpthreads=0;
	unsigned char foundhttpsthreads=0;
	unsigned char foundsocketprio=0;
	unsigned char founddscp=0;
	unsigned long ulparse;
	short dscpparse;
	char *endptr;
	#ifdef BERNWEB_SET_KEEPIDLE
	unsigned char foundkeepidle=0;
	#endif

	cfd = open(CONFIG_FILE, O_RDONLY);
	if (cfd == -1)
	{
		myerrno = errno;
		logmsg("config file failed open()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	if (fstat(cfd, &fst) == -1)
	{
		myerrno = errno;
		logmsg("config file failed fstat()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	finram = malloc(1 + fst.st_size);//+1 for null
	if (!finram)
	{
		myerrno = errno;
		logmsg("config file parse failed malloc()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	if (read(cfd, finram, fst.st_size) != fst.st_size)
	{
		myerrno = errno;
		logmsg("config file parse failed read()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	close(cfd);
	finram[fst.st_size] = 0;//null the end

	cursor = finram;
	while (cursor)
	{
		curline = strsep(&cursor, NEWLINE_CHARS);
		curtok = __builtin_strchr(curline, '#');
		if (curtok)
		{
			*curtok = 0;
		}
		if (!__builtin_strlen(curline))
		{
			continue;
		}

		curtok = curline;
		while (curtok)
		{
			toka = strsep(&curtok, WHITESPACE_CHARS);
			if (__builtin_strlen(toka))
			{
				break;
			}
		}
		if (!curtok)
		{
			logmsg("bad line in config file (debug info: no token a or only a)");
			exit(1);
		}
		while (curtok)
		{
			tokb = strsep(&curtok, WHITESPACE_CHARS);
			if (__builtin_strlen(tokb))
			{
				break;
			}
		}
		if (!__builtin_strlen(tokb))
		{
			logmsg("bad line in config file (debug info: no token b)");
			exit(1);
		}
		if (!__builtin_strcmp(CONFIG_USERNAME, toka))
		{
			//username
			if (founduser)
			{
				logmsg("config file parse error MULTIPLE USER DEFINITIONS!");
				exit(EINVAL);
			}
			errno = 0;
			u = getpwnam(tokb);
			if (!u)
			{
				myerrno = errno;
				logmsg("config file parse failed getpwnam()");
				if (myerrno)
				{
					logmsg(strerror(myerrno));
					exit(myerrno);
				}
				logmsg("user probably does not exist");
				exit(EINVAL);
			}
			runasuid = u->pw_uid;
			runasgid = u->pw_gid;
			founduser = 1;
		}
		else if (!__builtin_strcmp(CONFIG_DOCROOT, toka))
		{
			//log file
			if (docrootpath)
			{
				logmsg("config file parse error MULTIPLE DOCROOT DEFINITIONS!");
				exit(1);
			}
			docrootpath = strdup(tokb);
			if (!docrootpath)
			{
				myerrno = errno;
				logmsg("config file parse failed (token b) strdup()");
				logmsg(strerror(myerrno));
				exit(myerrno);
			}
		}
		else if (!__builtin_strcmp(CONFIG_LOGFILE, toka))
		{
			//log file
			if (logfilepath)
			{
				logmsg("config file parse error MULTIPLE LOGFILE DEFINITIONS!");
				exit(1);
			}
			logfilepath = strdup(tokb);
			if (!logfilepath)
			{
				myerrno = errno;
				logmsg("config file parse failed (token b) strdup()");
				logmsg(strerror(myerrno));
				exit(myerrno);
			}
		}
		else if (!__builtin_strcmp(CONFIG_CERTFILE, toka))
		{
			//public certificate
			if (pubcertpath)
			{
				logmsg("config file parse error MULTIPLE PUBLIC CERTIFCIATE DEFINITIONS!");
				exit(1);
			}
			pubcertpath = strdup(tokb);
			if (!pubcertpath)
			{
				myerrno = errno;
				logmsg("config file parse failed (token b) strdup()");
				logmsg(strerror(myerrno));
				exit(myerrno);
			}
		}
		else if (!__builtin_strcmp(CONFIG_KEYFILE, toka))
		{
			//private key
			if (privkeypath)
			{
				logmsg("config file parse error MULTIPLE PRIVATE KEYFILE DEFINITIONS!");
				exit(EINVAL);
			}
			privkeypath = strdup(tokb);
			if (!privkeypath)
			{
				myerrno = errno;
				logmsg("config file parse failed (token b) strdup()");
				logmsg(strerror(myerrno));
				exit(myerrno);
			}
		}
		else if (!__builtin_strcmp(CONFIG_HTTP_THREADS, toka))
		{
			//http threads
			if (foundhttpthreads)
			{
				logmsg("config file parse error multiple \"" CONFIG_HTTP_THREADS "\" definitions");
				exit(EINVAL);
			}
			ulparse = strtoul(tokb, &endptr, 10);
			if ((*endptr) || (ulparse > USHRT_MAX))
			{
				if (errno)
				{
					myerrno = errno;
					logmsg("config file parse failed strtoul()");
					logmsg(strerror(myerrno));
					exit(myerrno);
				}
				logmsg("invalid httpthreads value");
				exit(EINVAL);
			}
			httpthreads = ulparse;
			foundhttpthreads = 1;
		}
		else if (!__builtin_strcmp(CONFIG_HTTPS_THREADS, toka))
		{
			//https tls threads
			if (foundhttpsthreads)
			{
				logmsg("config file parse error multiple \"" CONFIG_HTTPS_THREADS "\" definitions");
				exit(EINVAL);
			}
			ulparse = strtoul(tokb, &endptr, 10);
			if ((*endptr) || (ulparse > USHRT_MAX))
			{
				if (errno)
				{
					myerrno = errno;
					logmsg("config file parse failed strtoul()");
					logmsg(strerror(myerrno));
					exit(myerrno);
				}
				logmsg("invalid httpthreads value");
				exit(EINVAL);
			}
			httpsthreads = ulparse;
			foundhttpsthreads = 1;
		}
		else if (!__builtin_strcmp(CONFIG_DEFAULT_SOCKET_PRIORITY, toka))
		{
			//socket priority
			if (foundsocketprio)
			{
				logmsg("config file parse error multiple \"" CONFIG_DEFAULT_SOCKET_PRIORITY "\" definitions");
				exit(EINVAL);
			}
			ulparse = strtoul(tokb, &endptr, 10);
			if ((*endptr) || (ulparse > SOCKET_MAX_PRIORITY))
			{
				if (errno)
				{
					myerrno = errno;
					logmsg("config file parse failed strtoul()");
					logmsg(strerror(myerrno));
					exit(myerrno);
				}
				logmsg("invalid httpthreads value");
				exit(EINVAL);
			}
			httpsthreads = ulparse;
			foundsocketprio = 1;
		}
		else if (!__builtin_strcmp(CONFIG_DEFAULT_DSCP, toka))
		{
			//dscp default
			if (founddscp)
			{
				logmsg("config file parse error multiple \"" CONFIG_DEFAULT_DSCP "\" definitions");
				exit(EINVAL);
			}
			ulparse = strtoul(tokb, &endptr, 0);
			if (*endptr)
			{
				dscpparse = processdscp(tokb);
				if (dscpparse == -1)
				{
					logmsg("config file parse error invalid DSCP value");
					exit(EINVAL);
				}
				defaultdscp = dscpparse;
			}
			else
			{
				if ((ulparse > 0xff) || (ulparse & 0b11))
				{
					logmsg("config file parse error invalid DSCP value");
					exit(EINVAL);
				}
				defaultdscp = dscpparse;
			}
			founddscp = 1;
		}
		#ifdef BERNWEB_SET_KEEPIDLE
		else if (!__builtin_strcmp(CONFIG_TCPKEEPIDLE, toka))
		{
			if (foundkeepidle)
			{
				logmsg("config file parse error MULTIPLE TCPKEEPIDLE DEFINITIONS!");
				exit(1);
			}
			ulparse = strtoul(tokb, &endptr, 10);
			if ((*endptr) || (!ulparse) || (ulparse == ULONG_MAX) || (ulparse > INT_MAX))
			{
				if (errno)
				{
					myerrno = errno;
					logmsg("config file parse failed strtoul()");
					logmsg(strerror(myerrno));
					exit(myerrno);
				}
				logmsg("invalid tcpkeepidle time");
				exit(1);
			}
			ssoptkidle = ulparse;
		}
		#endif
		else
		{
			logmsg("encountered unknown line in config file, check that compile time support for options you want were enabled");
			exit(EINVAL);
		}
	}
	if (!(founduser && foundhttpthreads && foundhttpsthreads && logfilepath && docrootpath))
	{
		logmsg("config file parse failed, missing definition. Verify all are present: user, httpthreads, httpsthreads, logfile, pubcert, privkey");
		exit(EINVAL);
	}

	if (httpsthreads && (!(pubcertpath && privkeypath)))
	{
		logmsg("config file parse failed, non-zero https-threads but no pubcert and privkey!");
		exit(EINVAL);
	}
	if ((!httpthreads) && (!httpsthreads))
	{
		logmsg("config file error: No! I nee threads on!");
		exit(EINVAL);
	}

	free(finram);
}

static inline void setupsocket(int *s, uint16_t port)
{
	int myerrno;
	int ssopt;
	struct sockaddr_storage listener = {0};

	*s = socket(AF_INET, SOCK_STREAM, 0);
	if (*s == -1)
	{
		myerrno = errno;
		logmsg("failed to socket()");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}

	//on linux-6.5.5. these are inhereted after accept()
	//also the kernel's broken rt_tos2priority() function will
	//be fine with the IPTOS_DSCP_LE so there is no need
	//to setsockopt(SO_PRIORITY) (btw priority IS NOT inhereted)
	//I plan on having the default be IPTOS_DSCP_LE
	//bug me if you actually plan to use this server and don't like
	//that behaviour
	ssopt = 1;
	if (setsockopt(*s, SOL_SOCKET, SO_KEEPALIVE, &ssopt, sizeof(int)) == -1)
	{
		myerrno = errno;
		logmsg("SO_KEEPALIVE setsockopt() failed");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	ssopt = defaultdscp;
	if (setsockopt(*s, IPPROTO_IP, IP_TOS, &ssopt, sizeof(int)) == -1)
	{
		myerrno = errno;
		logmsg("IP_TOS (DSCP) setsockopt() failed");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	#ifdef BERNWEB_SET_KEEPIDLE
	if (ssoptkidle != -1)
	{
		if (setsockopt(*s, IPPROTO_TCP, TCP_KEEPIDLE, &ssoptkidle, sizeof(int)) == -1)
		{
			myerrno = errno;
			logmsg("TCP_KEEPIDLE setsockopt() failed");
			logmsg(strerror(myerrno));
			exit(myerrno);
		}
	}
	#endif
	ssopt = 30;
	if (setsockopt(*s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &ssopt, sizeof(int)) == -1)
	{
		myerrno = errno;
		logmsg("TCP_DEFER_ACCEPT setsockopt() failed");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}
	ssopt = 1;
	if (setsockopt(*s, SOL_SOCKET, SO_REUSEADDR, &ssopt, sizeof(int)) == -1)
	{
		myerrno = errno;
		logmsg("SO_REUSEADDR setsockopt() failed");
		logmsg(strerror(myerrno));
		exit(myerrno);
	}

	((struct sockaddr_in*)&listener)->sin_family = AF_INET;
	((struct sockaddr_in*)&listener)->sin_addr.s_addr = 0;
	#ifdef __ORDER_LITTLE_ENDIAN__
	((struct sockaddr_in*)&listener)->sin_port = __builtin_bswap16(port);
	#else
	((struct sockaddr_in*)&listener)->sin_port = port;
	#endif

	if (bind(*s, (struct sockaddr*) &listener, sizeof(struct sockaddr_storage)) == -1)
	{
		myerrno = errno;
		perror("bind()");
		exit(myerrno);
	}

	if (listen(*s, 1024) == -1)
	{
		myerrno = errno;
		perror("listen()");
		exit(myerrno);
	}
}

static inline void parsedate(char *s, time_t *tres)
{
	unsigned long ul;
	struct tm t;
	char *endptr;
	time_t retval;

	//day
	ul = strtoul(&s[5], &endptr, 10);
	if ((*endptr != ' ') || ((!ul) || (ul > 31)))
	{
		return;
	}
	t.tm_mday = ul;

	//month
	switch (*((uint32_t*)&s[8]))
	{
	case MONTH_JAN:
		t.tm_mon = 0;
		break;
	case MONTH_FEB:
		t.tm_mon = 1;
		break;
	case MONTH_MAR:
		t.tm_mon = 2;
		break;
	case MONTH_APR:
		t.tm_mon = 3;
		break;
	case MONTH_MAY:
		t.tm_mon = 4;
		break;
	case MONTH_JUN:
		t.tm_mon = 5;
		break;
	case MONTH_JUL:
		t.tm_mon = 6;
		break;
	case MONTH_AUG:
		t.tm_mon = 7;
		break;
	case MONTH_SEP:
		t.tm_mon = 8;
		break;
	case MONTH_OCT:
		t.tm_mon = 9;
		break;
	case MONTH_NOV:
		t.tm_mon = 10;
		break;
	case MONTH_DEC:
		t.tm_mon = 11;
		break;
	default:
		return;
	}

	//year
	ul = strtoul(&s[12], &endptr, 10);
	if (*endptr != ' ')
	{
		return;
	}
	t.tm_year = (ul - 1900);

	//hour
	ul = strtoul(&s[17], &endptr, 10);
	if ((*endptr != ':') || (ul > 23))
	{
		return;
	}
	t.tm_hour = ul;

	//minute
	ul = strtoul(&s[20], &endptr, 10);
	if ((*endptr != ':') || (ul > 59))
	{
		return;
	}
	t.tm_min = ul;

	//second
	ul = strtoul(&s[23], &endptr, 10);
	if ((*endptr != ' ') || (ul > 59))
	{
		return;
	}
	t.tm_sec = ul;

	retval = timegm(&t);
	if (retval != -1)
	{
		*tres = retval;
	}

	return;
}

static inline void parseetag(char *e, struct timeval *tv)
{
	unsigned long uls;
	unsigned long ulns;
	char *endptr;
	char n;

	n = e[16];
	e[16] = 0;
	uls = strtoul(e, &endptr, 16);
	if (*endptr)
	{
		return;
	}

	e[16] = n;
	ulns = strtoul(&e[16], &endptr, 16);
	if ((*endptr != '"'))
	{
		return;
	}

	tv->tv_sec = uls;
	tv->tv_usec = ulns;
}

static inline void parserange(char *r, struct clicon *curcli, struct request *parsedreq)
{
	unsigned long s;
	unsigned long e;
	char *endptr;
	unsigned char newflags = 0;

	if (r[0] != '-')
	{
		s = strtoul(r, &endptr, 10);
		if ((endptr == r) || (*endptr != '-'))
		{
			return;
		}
		r = (endptr + 1);
		newflags = REQUEST_FLAG_SRANGE;
		if (!(*r))
		{
			curcli->srange = s;
			parsedreq->flags |= REQUEST_FLAG_SRANGE;
			return;
		}
	}
	else
	{
		r++;
	}
	e = strtoul(r, &endptr, 10);
	if ((endptr == r) || (*endptr))
	{
		return;
	}

	e++;
	if (e <= s)
	{
		return;
	}
	curcli->erange = e;
	curcli->srange = s;
	if (curcli->srange < 0)
	{
		return;
	}
	newflags |= REQUEST_FLAG_ERANGE;
	parsedreq->flags |= newflags;

	return;
}

static inline char tlshandshake(int fd, unsigned char again)
{
	int gnutlsretval;

	if (!again)
	{
		if (gnutls_init(&clitable[fd].session, GNUTLS_SERVER | GNUTLS_NONBLOCK | GNUTLS_NO_TICKETS))
		{
			logmsgcli(&clitable[fd], "gnutls_init() failed");
			return -2;
		}
		if (gnutls_priority_set(clitable[fd].session, pcache))
		{
			logmsgcli(&clitable[fd], "gnutls_priority_set() failed");
			return -1;
		}
		if (gnutls_credentials_set(clitable[fd].session, GNUTLS_CRD_CERTIFICATE, x509cred))
		{
			logmsgcli(&clitable[fd], "gnutls_credentials_set() failed");
			return -1;
		}
		gnutls_certificate_server_set_request(clitable[fd].session, GNUTLS_CERT_IGNORE);
		gnutls_handshake_set_timeout(clitable[fd].session, 0);
		gnutls_transport_set_int(clitable[fd].session, fd);
	}

handagain:
	if (clitable[fd].fd)
	{
		do
		{
			gnutlsretval = gnutls_alert_send_appropriate(clitable[fd].session, clitable[fd].fd);
			if (gnutlsretval == GNUTLS_E_AGAIN)
			{
				return 1;
			}
		}
		while (gnutlsretval == GNUTLS_E_INTERRUPTED);
		clitable[fd].fd = 0;
		goto handagain;
	}
	else
	{
		do
		{
			gnutlsretval = gnutls_handshake(clitable[fd].session);
			if (gnutlsretval == GNUTLS_E_AGAIN)
			{
				clitable[fd].fd = 0;
				return 1;
			}
		}
		while (gnutlsretval == GNUTLS_E_INTERRUPTED);
	}

	if ((gnutlsretval < 0) && (gnutlsretval != GNUTLS_E_GOT_APPLICATION_DATA))
	{
		if (!gnutls_error_is_fatal(gnutlsretval))
		{
			clitable[fd].fd = gnutlsretval;
			goto handagain;
		}
		logmsgcli(&clitable[fd], "handshake failed");
		logmsgcli(&clitable[fd], gnutls_strerror_name(gnutlsretval));
		
		return -1;
	}
	return 0;
}

static inline char isrequestcomplete(struct clicon *curcli)
{
	if (curcli->reqindex < MINIMUM_REQ_SIZE)
	{
		return 0;
	}
	if ((*((uint32_t*)(&curcli->r[curcli->reqindex - sizeof(uint32_t)]))) == rnrn)
	{
		return 1;
	}
	if (curcli->reqindex == (REQUEST_SIZE - RESERVED_REQ_SIZE))
	{
		return -1;
	}
	return 0;
}

static inline const char *getcodedesc(unsigned short code, unsigned short *slen)
{
	//todo macros
	switch (code)
	{
	case 200:
		*slen = sizeof("OK") - 1;
		return "OK";
	case 206:
		*slen = sizeof("Partial Content") - 1;
		return "Partial Content";
	/* case 301: */
	/* 	*slen = sizeof("Moved Permanently") - 1; */
	/* 	return "Moved Permanently"; */
	case 304:
		*slen = sizeof("Not Modified") - 1;
		return "Not Modified";
	case 400:
		*slen = sizeof("Bad Request") - 1;
		return "Bad Request";
	case 404:
		*slen = sizeof("Not Found") - 1;
		return "Not Found";
	case 405:
		*slen = sizeof("Method Not Allowed") - 1;
		return "Method Not Allowed";
	case 412:
		*slen = sizeof("Precondition Failed") -1;
		return "Precondition Failed";
	case 414:
		*slen = sizeof("URI Too Long") -1;
		return "URI Too Long";
	case 416:
		*slen = sizeof("Range Not Satisfiable") - 1;
		return "Range Not Satisfiable";
	case 494:
		*slen = sizeof("Request header too large") - 1;
		return "Request header too large";
	case 500:
		*slen = sizeof("Internal Server Error") - 1;
		return "Internal Server Error";
	default:
		*slen = sizeof("FUCK") - 1;
		return "FUCK";
	}
}

static inline const char *getcodelongdesc(unsigned short code, unsigned short *slen)
{
	//todo macros
	switch (code)
	{
	case 400:
		*slen = sizeof("The server was unable to process the http request.") - 1;
		return "The server was unable to process the http request.";
	case 404:
		*slen = sizeof("The requested URL was not found on the server.") - 1;
		return "The requested URL was not found on the server.";
	case 405:
		*slen = sizeof("The requested HTTP method is not allowed on the server") - 1;
		return "The requested HTTP method is not allowed on the server";
	case 414:
		*slen = sizeof("The requested url (filename/path) is too long and the server was unable to process your request") - 1;
		return "The requested url (filename/path) is too long and the server was unable to process your request";
	case 416:
		*slen = sizeof("The requested range is not supported. This server supports only 1 range per request.") - 1;
		return "The requested range is not supported. This server supports only 1 range per request.";
	case 494:
		*slen = sizeof("The http request header is too large for this server to process.") - 1;
		return "The http request header is too large for this server to process.";
	case 500:
		*slen = sizeof("A server error has occured") - 1;
		return "A server error has occured";
	default:
		*slen = sizeof("FUCK") - 1;
		return "FUCK";
	}
}

static inline void generateerrorwithoutbody(struct clicon *curcli, unsigned short code, struct timespec *curtime)
{
	struct tm utc;
	int sretval;
	const char *codedesc;
	unsigned short junk;

	codedesc = getcodedesc(code, &junk);

	gmtime_r(&curtime->tv_sec, &utc);

	//sretval = __builtin_sprintf(curcli->r, "HTTP/1.1 %hu %s\r\nDate: %s, %02i %s %i %02i:%02i:%02i GMT\r\nServer: bernweb\r\nContent-Type: text/html\r\n\r\n",
	sretval = __builtin_sprintf(curcli->r, "HTTP/1.1 %hu %s\r\nDate: %s, %02i %s %i %02i:%02i:%02i GMT\r\nServer: bernweb\r\n\r\n",
				    code,
				    codedesc,
				    daystrs[utc.tm_wday],
				    utc.tm_mday,
				    monthstrs[utc.tm_mon],
				    utc.tm_year + 1900,
				    utc.tm_hour,
				    utc.tm_min,
				    utc.tm_sec);

	//assume sprintf worked
	curcli->resphsize = sretval;
}

static inline void generateerrorwithbody(struct clicon *curcli, unsigned short code, struct timespec *curtime)
{
	struct tm utc;
	int sretval;
	const char *codedesc;
	unsigned short codedescslen;
	const char *codelongdesc;
	unsigned short codelongdescslen;

	codedesc = getcodedesc(code, &codedescslen);
	codelongdesc = getcodelongdesc(code, &codelongdescslen);

	gmtime_r(&curtime->tv_sec, &utc);


	//0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111
	//0000000001111111111222222222233333333334444444444555555555566666666667777777777888888888899999999990000000000111111
	//1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345
	//<!DOCTYPE html><html><head><title>%hu </title></head><body><h1>%hu </h1><p></p><p>bernweb server</p></body></html>\n
	//115 + (2 * codedesc) + (codelongdesc)
	sretval = __builtin_sprintf(curcli->r, "HTTP/1.1 %hu %s\r\nDate: %s, %02i %s %i %02i:%02i:%02i GMT\r\nServer: bernweb\r\nContent-Length: %hu\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><head><title>%hu %s</title></head><body><h1>%hu %s</h1><p>%s</p><p>bernweb server</p></body></html>\n",
				    code,
				    codedesc,
				    daystrs[utc.tm_wday],
				    utc.tm_mday,
				    monthstrs[utc.tm_mon],
				    utc.tm_year + 1900,
				    utc.tm_hour,
				    utc.tm_min,
				    utc.tm_sec,
				    115 + (2 * codedescslen) + codelongdescslen,
				    code,
				    codedesc,
				    code,
				    codedesc,
				    codelongdesc);

	//assume sprintf worked
	curcli->resphsize = sretval;
}

static inline void generateerror(struct clicon *curcli, unsigned short code, int sockfd, struct request *parsedreq)
{
	struct timespec curtime;

	if (curcli->prevdscp != defaultdscp)
	{
		if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &defaultdscp, sizeof(uint8_t)) == -1)
		{
			//todo
		}
		curcli->prevdscp = defaultdscp;
	}

	clock_gettime(CLOCK_REALTIME, &curtime);

	#ifdef BERNWEB_LOG_REQUESTS
	logrequest(curcli, code, parsedreq, &curtime);
	#endif
	if (parsedreq->flags & REQUEST_FLAG_GET)
	{
		generateerrorwithbody(curcli, code, &curtime);
	}
	else
	{
		generateerrorwithoutbody(curcli, code, &curtime);
	}
	if ((code == 400) || (code == 494))
	{
		curcli->state = HTTP_STATE_RESPONDING_HEADER_ONLY_HUP;
	}
	else
	{
		curcli->state = HTTP_STATE_RESPONDING_HEADER_ONLY;
	}
}

void generatedir301(struct clicon *curcli, unsigned short fileslen, int sockfd, struct request *parsedreq)
{
	struct timespec curtime;
	struct tm utc;
	int sretval;
	char *fname;

	if (curcli->prevdscp != defaultdscp)
	{
		if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &defaultdscp, sizeof(uint8_t)) == -1)
		{
			//todo
		}
		curcli->prevdscp = defaultdscp;
	}

	fname = __builtin_alloca(fileslen + 1);
	__builtin_memcpy(fname, parsedreq->file, fileslen+1);
	fname[fileslen] = 0;

	clock_gettime(CLOCK_REALTIME, &curtime);
	gmtime_r(&curtime.tv_sec, &utc);

	#ifdef BERNWEB_LOG_REQUESTS
	logrequest(curcli, 301, parsedreq, &curtime);
	#endif

	sretval = __builtin_sprintf(curcli->r, "HTTP/1.1 301 Moved Permanently\r\nDate: %s, %02i %s %i %02i:%02i:%02i GMT\r\nServer: bernweb\r\nLocation: %s/\r\nContent-Length: 0\r\n\r\n",
				    daystrs[utc.tm_wday],
				    utc.tm_mday,
				    monthstrs[utc.tm_mon],
				    utc.tm_year + 1900,
				    utc.tm_hour,
				    utc.tm_min,
				    utc.tm_sec,
				    fname);

	//assume sprintf worked
	curcli->resphsize = sretval;
	curcli->state = HTTP_STATE_RESPONDING_HEADER_ONLY;
}

static inline void generateheader200(struct clicon *curcli,  char *lmet, char *mime, struct request *parsedreq)
{
	struct timespec curtime;
	struct tm utc;
	int sretval;

	clock_gettime(CLOCK_REALTIME, &curtime);
	gmtime_r(&curtime.tv_sec, &utc);

	#ifdef BERNWEB_LOG_REQUESTS
	logrequest(curcli, 200, parsedreq, &curtime);
	#endif

	sretval = __builtin_sprintf(curcli->r, "HTTP/1.1 200 OK\r\nDate: %s, %02i %s %i %02i:%02i:%02i GMT\r\nServer: bernweb\r\n%s\r\nAccept-Ranges: bytes\r\nContent-Length: %lu\r\nContent-Type: %s\r\n\r\n",
				    daystrs[utc.tm_wday],
				    utc.tm_mday,
				    monthstrs[utc.tm_mon],
				    utc.tm_year + 1900,
				    utc.tm_hour,
				    utc.tm_min,
				    utc.tm_sec,
				    lmet,
				    curcli->erange,
				    mime);

	//assume sprintf worked
	curcli->resphsize = sretval;
	curcli->state = HTTP_STATE_RESPONDING_HEADER_FILE;
}

static inline void generateheader206(struct clicon *curcli, char *lmet, char *mime, uint64_t size, struct request *parsedreq)
{
	struct timespec curtime;
	struct tm utc;
	int sretval;

	clock_gettime(CLOCK_REALTIME, &curtime);
	gmtime_r(&curtime.tv_sec, &utc);

	#ifdef BERNWEB_LOG_REQUESTS
	logrequest(curcli, 206, parsedreq, &curtime);
	#endif

	sretval = __builtin_sprintf(curcli->r, "HTTP/1.1 206 Partial Content\r\nDate: %s, %02i %s %i %02i:%02i:%02i GMT\r\nServer: bernweb\r\n%s\r\nAccept-Ranges: bytes\r\nContent-Length: %lu\r\nContent-Range: bytes %lu-%lu/%lu\r\nContent-Type: %s\r\n\r\n",
				    daystrs[utc.tm_wday],
				    utc.tm_mday,
				    monthstrs[utc.tm_mon],
				    utc.tm_year + 1900,
				    utc.tm_hour,
				    utc.tm_min,
				    utc.tm_sec,
				    lmet,
				    curcli->erange - curcli->srange,
				    curcli->srange,
				    curcli->erange - 1,
				    size,
				    mime);

	//assume sprintf worked
	curcli->resphsize = sretval;
	curcli->state = HTTP_STATE_RESPONDING_HEADER_FILE;
}

static inline void generatelmet(struct statx *fstx, char *lmet)
{
	struct tm modtime;

	gmtime_r(&fstx->stx_mtime.tv_sec, &modtime);

	__builtin_sprintf(lmet, "Last-Modified: %s, %02i %s %i %02i:%02i:%02i GMT\r\nETag: \"%016llx%08x\"",
			  daystrs[modtime.tm_wday],
			  modtime.tm_mday,
			  monthstrs[modtime.tm_mon],
			  modtime.tm_year + 1900,
			  modtime.tm_hour,
			  modtime.tm_min,
			  modtime.tm_sec,
			  fstx->stx_mtime.tv_sec,
			  fstx->stx_mtime.tv_nsec);

	return;
}

void processrequest(int sockfd, unsigned char flags)
{
	char xattr[XATTR_BUF_SIZE];
	char *s;
	char *e;
	struct request parsedreq = {0};
	unsigned short slen;
	unsigned short fileslen;
	struct clicon *curcli;
	struct statx fstx;
	char *openme = NULL;
	#ifndef BERNWEB_INTERNAL_DENTRY
	ssize_t xattrretval;
	//1234567890123456789012345678901234567890123456789012345678901234567890123456789
	//Last-Modified: Mon, 10 Jan 2024 10:10:10 GMTrnETag: "123456789012345678901234"
	char lmet[79];
	#endif

	parsedreq.flags = flags;
	curcli = &clitable[sockfd];

	s = __builtin_strchr(curcli->r, ' ');

	if (!s)
	{
		parsedreq.flags |= REQUEST_FLAG_GET;
		generateerror(curcli, 400, sockfd, &parsedreq);
		return;
	}

	slen = s - curcli->r;
	if (slen == 3)
	{
		if (__builtin_memcmp(curcli->r, "GET", 3))
		{
			parsedreq.flags |= REQUEST_FLAG_GET;
			generateerror(curcli, 405, sockfd, &parsedreq);
			return;
		}
		//get
		parsedreq.flags |= REQUEST_FLAG_GET;
		s++;
	}
	else if (slen == 4)
	{
		if (__builtin_memcmp(curcli->r, "HEAD", 4))
		{
			parsedreq.flags |= REQUEST_FLAG_GET;
			generateerror(curcli, 405, sockfd, &parsedreq);
			return;
		}
		//head
		s++;
	}
	else
	{
		parsedreq.flags |= REQUEST_FLAG_GET;
		generateerror(curcli, 405, sockfd, &parsedreq);
		return;
	}
	e = __builtin_strchr(s, ' ');
	if (!e || (e == s))
	{
		generateerror(curcli, 400, sockfd, &parsedreq);
		return;
	}
	*e = 0;
	parsedreq.file = s;
	fileslen = (e - s);
	//skip rest of line
	//guaranteeed to find something because the string is guaranteed
	//to end in /r/n/r/n by isrequestcomplete()
	//and is null terminated by recv() logic
	s = e + 1;
	e = __builtin_strchr(s, '\r');
	while (1)
	{
		s = e + 2;
		e = __builtin_strchr(s, '\r');
		if (e == s)
		{
			break;
		}
		slen = e-s;
		*e = 0;
		if (slen < 10)
		{
			continue;
		}
		if (!__builtin_memcmp(s, "Referer: ", 9))
		{
			parsedreq.referer = &s[9];
			continue;
		}
		if (slen < 13)
		{
			continue;
		}
		if (!__builtin_memcmp(s, "User-Agent: ", 12))
		{
			parsedreq.uagent = &s[12];
			continue;
		}
		if (slen < 15)
		{
			continue;
		}
		if (!__builtin_memcmp(s, "Range: bytes=", 13))
		{
			parserange(&s[13], curcli, &parsedreq);
			if (!(parsedreq.flags & REQUEST_FLAG_RANGE_MASK))
			{
				generateerror(curcli, 416, sockfd, &parsedreq);
				return;
			}
			continue;
		}
		if (slen == 36)
		{
			if (!((parsedreq.flags & REQUEST_FLAG_IF_NONE_MATCH) || (__builtin_memcmp(s, "If-Match: ", 10))))
			{
				parseetag(&s[11], &parsedreq.ifmatch);
				continue;
			}
			if (!((parsedreq.flags & REQUEST_FLAG_IF_RANGE_ETAG) || (__builtin_memcmp(s, "If-Range: ", 10))))
			{
				parsedreq.flags |= REQUEST_FLAG_IF_RANGE_ETAG;
				parseetag(&s[11], &parsedreq.ifrange);
				continue;
			}
			continue;
		}
		if (slen == 39)
		{
			if (!((parsedreq.flags & REQUEST_FLAG_IF_RANGE_ETAG) || (__builtin_memcmp(s, "If-Range: ", 10))))
			{
				parsedate(&s[10], &parsedreq.ifrange.tv_sec);
			}
			continue;
		}
		if (slen == 41)
		{
			if (!((parsedreq.flags & REQUEST_FLAG_IF_NONE_MATCH) || (__builtin_memcmp(s, "If-None-Match: ", 15))))
			{
				parsedreq.flags |= REQUEST_FLAG_IF_NONE_MATCH;
				parseetag(&s[16], &parsedreq.ifmatch);
			}
			continue;
		}
		if (slen == 48)
		{
			if (!((parsedreq.flags & REQUEST_FLAG_IF_NONE_MATCH) || (__builtin_memcmp(s, "If-Modified-Since: ", 19))))
			{
				parsedate(&s[19], &parsedreq.ifmodsince);
			}
			continue;
		}
	}

	s = __builtin_strchr(parsedreq.file, '?');
	if (s)
	{
		fileslen = s - parsedreq.file;
		*s = 0;
	}
	if (__builtin_expect_with_probability(parsedreq.file[fileslen-1] == '/', 1, 0.5))
	{
		//12345678901
		//index.html
		openme = __builtin_alloca(11 + fileslen);
		__builtin_memcpy(openme, parsedreq.file, fileslen);
		__builtin_memcpy(&openme[fileslen], "index.html", 11);
		if (s)
		{
			*s = '?';
			s = NULL;
		}
		
		#ifdef BERNWEB_INTERNAL_DENTRY
		fileslen += 10;
		#endif
	}
	#ifdef BERNWEB_INTERNAL_DENTRY
	//todo
	#else
openagain:
	curcli->fd = syscall(SYS_openat2, docrootfd, openme ? openme: parsedreq.file, &oh, sizeof(struct open_how));
	if (s)
	{
		*s = '?';
	}
	if (curcli->fd == -1)
	{
		if ((errno == EMFILE) || (errno == ENFILE) || (errno == ENOBUFS) || (errno == ENOMEM))
		{
			//todo
			sleep(1);
			goto openagain;
		}
		if (errno == ENOENT)
		{
			generateerror(curcli, 404, sockfd, &parsedreq);
			return;
		}
		if (errno == ENAMETOOLONG)
		{
			generateerror(curcli, 414, sockfd, &parsedreq);
			return;
		}
		generateerror(curcli, 500, sockfd, &parsedreq);
		return;
	}

	if (statx(curcli->fd, "", AT_EMPTY_PATH, STATX_MODE | STATX_MTIME | STATX_SIZE, &fstx))
	{
		generateerror(curcli, 500, sockfd, &parsedreq);
		close(curcli->fd);
		return;
	}
	if (!(S_ISREG(fstx.stx_mode)))
	{
		close(curcli->fd);
		if (S_ISDIR(fstx.stx_mode))
		{
			generatedir301(curcli, fileslen, sockfd, &parsedreq);
			return;
		}
		generateerror(curcli, 404, sockfd, &parsedreq);
		return;
	}

	xattrretval = fgetxattr(curcli->fd, BERNWEB_XATTR_KEY, xattr, XATTR_BUF_SIZE);
	if (xattrretval == -1)
	{
		close(curcli->fd);
		if (errno == ENODATA)
		{
			generateerror(curcli, 404, sockfd, &parsedreq);
			return;
		}
		generateerror(curcli, 500, sockfd, &parsedreq);
		close(curcli->fd);
		return;
	}
	xattr[xattrretval] = 0;
	if (!xattr[0])
	{
		*((uint8_t*)&xattr[0]) = defaultdscp;
	}
	if (*((uint8_t*)&xattr[0]) != curcli->prevdscp)
	{
		if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &xattr[0], sizeof(char)) == -1)
		{
			//todo
		}
		else
		{
			curcli->prevdscp = *((uint8_t*)&xattr[0]);
		}
	}
		
	if (parsedreq.ifmatch.tv_sec)
	{
		if (parsedreq.flags & REQUEST_FLAG_IF_NONE_MATCH)
		{
			if ((parsedreq.ifmatch.tv_sec == fstx.stx_mtime.tv_sec) && (parsedreq.ifmatch.tv_usec == fstx.stx_mtime.tv_nsec))
			{
				parsedreq.flags &= (~REQUEST_FLAG_GET);
				generateerror(curcli, 304, sockfd, &parsedreq);
				close(curcli->fd);
				return;
			}
		}
		else
		{
			if (!((parsedreq.ifmatch.tv_sec == fstx.stx_mtime.tv_sec) && (parsedreq.ifmatch.tv_usec == fstx.stx_mtime.tv_nsec)))
			{
				parsedreq.flags &= (~REQUEST_FLAG_GET);
				generateerror(curcli, 412, sockfd, &parsedreq);
				close(curcli->fd);
				return;
			}
		}
	}
	else if (parsedreq.ifmodsince)
	{
		if (parsedreq.ifmodsince == fstx.stx_mtime.tv_sec)
		{
			generateerror(curcli, 304, sockfd, &parsedreq);
			close(curcli->fd);
			return;
		}
	}

	generatelmet(&fstx, lmet);

	if ((parsedreq.flags & REQUEST_FLAG_RANGE_MASK) && (parsedreq.flags & REQUEST_FLAG_GET))
	{
		if (parsedreq.ifrange.tv_sec)
		{
			if (!((parsedreq.ifrange.tv_sec == fstx.stx_mtime.tv_sec) && ((!(parsedreq.flags & REQUEST_FLAG_IF_RANGE_ETAG)) || (parsedreq.ifrange.tv_usec == fstx.stx_mtime.tv_nsec))))
			{
				curcli->srange = 0;
				curcli->erange = fstx.stx_size;
				generateheader200(curcli, lmet, &xattr[1], &parsedreq);
			}
		}
		if (parsedreq.flags & REQUEST_FLAG_ERANGE)// && ) || ( && ))
		{
			if (curcli->erange > fstx.stx_size)
			{
				generateerror(curcli, 416, sockfd, &parsedreq);
				close(curcli->fd);
				return;
			}
		}
		else
		{
			curcli->erange = fstx.stx_size;
		}

		if (parsedreq.flags & REQUEST_FLAG_SRANGE)
		{
			if (((size_t)curcli->srange) >= (fstx.stx_size-1))
			{
				generateerror(curcli, 416, sockfd, &parsedreq);
				close(curcli->fd);
				return;
			}
		}
		else
		{
			curcli->srange = 0;
		}
		generateheader206(curcli, lmet, &xattr[1], fstx.stx_size, &parsedreq);
	}
	else
	{
		curcli->srange = 0;
		curcli->erange = fstx.stx_size;
		generateheader200(curcli, lmet, &xattr[1], &parsedreq);
	}
	#endif

	return;
}


void *httpworker(void *arg)
{
	int myerrno;
	int e;
	int wretval;
	struct epoll_event events[MAX_THREAD_EP_EVENTS];
	//struct epoll_event emod;
	ssize_t recvretval;
	struct clicon *curcli;
	char reqstatus;
	off_t cursend;

	e = *((int*)arg);

	while (1)
	{
		wretval = epoll_wait(e, events, MAX_THREAD_EP_EVENTS, -1);

		if (wretval == -1)
		{
			myerrno = errno;
			logmsg("epoll_wait() failed http thread");
			logmsg(strerror(myerrno));
			exit(myerrno);
		}
		while (wretval)
		{
			wretval--;
			curcli = &clitable[events[wretval].data.fd];

			if (events[wretval].events & (EPOLLERR | EPOLLHUP))
			{
				//recv(events[wretval].data.fd, todo, sizetodo, MSG_ERR
				if (curcli->state >= HTTP_STATE_RESPONDING_HEADER_FILE)
				{
					close(curcli->fd);
				}
				#ifdef BERNWEB_MADV_FREE
				madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
				#endif
				close(events[wretval].data.fd);
				continue;
			}
			switch (curcli->state)
			{
			case HTTP_STATE_PRE_RECV:
				curcli->prevdscp = defaultdscp;
				curcli->reqindex = 0;
				getclistring(&curcli->addr, curcli->clistr);
				//fallthrough
			case HTTP_STATE_RECV:
			httprecvagain:
				recvretval = recv(events[wretval].data.fd, &curcli->r[curcli->reqindex], (REQUEST_SIZE - RESERVED_REQ_SIZE) - curcli->reqindex, 0);
				if (recvretval == -1)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
					{
						continue;
					}
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				if (!recvretval)
				{
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				curcli->reqindex += recvretval;
				reqstatus = isrequestcomplete(curcli);
				if (!reqstatus)
				{
					goto httprecvagain;
				}
				if (reqstatus < 0)
				{
					generateerror(curcli, 494, events[wretval].data.fd, &phonyreq);
					goto httpafterprocessreq;
				}
				curcli->r[recvretval] = 0;
				processrequest(events[wretval].data.fd, 0);
			httpafterprocessreq:
				curcli->reqindex = 0;
				//fallthrough
			case HTTP_STATE_RESPONDING_HEADER_ONLY:
			case HTTP_STATE_RESPONDING_HEADER_ONLY_HUP:
			case HTTP_STATE_RESPONDING_HEADER_FILE:
			httpsendhagain:
				recvretval = send(events[wretval].data.fd, &curcli->r[curcli->reqindex], curcli->resphsize - curcli->reqindex, (curcli->state < HTTP_STATE_RESPONDING_HEADER_FILE) ? 0 : MSG_MORE);
				if (recvretval == -1)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
					{
						events[wretval].events = EPOLLOUT;
						epoll_ctl(e, EPOLL_CTL_MOD, events[wretval].data.fd, &events[wretval]);
						continue;
					}
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				curcli->reqindex += recvretval;
				if (curcli->reqindex != curcli->resphsize)
				{
					goto httpsendhagain;
				}
				if (curcli->state == HTTP_STATE_RESPONDING_HEADER_ONLY_HUP)
				{
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				if (curcli->state != HTTP_STATE_RESPONDING_HEADER_FILE)
				{
					curcli->reqindex = 0;
					curcli->state = HTTP_STATE_RECV;
					break;
				}
				curcli->state = HTTP_STATE_RESPONDING_FILE;
				//fallthrough
			case HTTP_STATE_RESPONDING_FILE:
			httpsendfileagain:
				cursend = (curcli->erange - curcli->srange);
				if (cursend > BERNWEB_LINUX_SENDFILE_MAX)
				{
					cursend = BERNWEB_LINUX_SENDFILE_MAX;
				}

				if (sendfile(events[wretval].data.fd, curcli->fd, &curcli->srange, cursend) == -1)
				{
					if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
					{
						if (events[wretval].events != EPOLLOUT)
						{
							events[wretval].events = EPOLLOUT;
							epoll_ctl(e, EPOLL_CTL_MOD, events[wretval].data.fd, &events[wretval]);
						}
						continue;
					}
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				if (((size_t)curcli->srange) != curcli->erange)
				{
					goto httpsendfileagain;
				}
				close(curcli->fd);
				if (events[wretval].events != EPOLLIN)
				{
					events[wretval].events = EPOLLIN;
					epoll_ctl(e, EPOLL_CTL_MOD, events[wretval].data.fd, &events[wretval]);
				}
				curcli->reqindex = 0;
				curcli->state = HTTP_STATE_RECV;
			}
		}
	}
}

void *tlsworker(void *arg)
{
	int myerrno;
	int e;
	int wretval;
	struct epoll_event events[MAX_THREAD_EP_EVENTS];
	//struct epoll_event emod;
	ssize_t recvretval;
	struct clicon *curcli;
	char reqstatus;
	off_t cursend;

	e = *((int*)arg);

	while (1)
	{
		wretval = epoll_wait(e, events, MAX_THREAD_EP_EVENTS, -1);

		if (wretval == -1)
		{
			myerrno = errno;
			logmsg("epoll_wait() failed tls thread");
			logmsg(strerror(myerrno));
			exit(myerrno);
		}
		while (wretval)
		{
			wretval--;
			curcli = &clitable[events[wretval].data.fd];

			if (events[wretval].events & (EPOLLERR | EPOLLHUP))
			{
				//recv(events[wretval].data.fd, todo, sizetodo, MSG_ERR
				if (curcli->state >= TLS_STATE_HANDSHAKE)
				{
					gnutls_deinit(curcli->session);
				}
				if (curcli->state >= TLS_STATE_RESPONDING_HEADER_FILE)
				{
					gnutls_deinit(curcli->session);
					close(curcli->fd);
				}
				#ifdef BERNWEB_MADV_FREE
				madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
				#endif
				close(events[wretval].data.fd);
				continue;
			}
			switch (curcli->state)
			{
			case TLS_STATE_PRE_HANDSHAKE:
				curcli->prevdscp = defaultdscp;
				curcli->reqindex = 0;
				getclistring(&curcli->addr, curcli->clistr);
				curcli->fd = 0;
				//fallthrough
			case TLS_STATE_HANDSHAKE:
				recvretval = tlshandshake(events[wretval].data.fd, (curcli->state == TLS_STATE_HANDSHAKE));
				if (recvretval < 0)
				{
					if (recvretval == -1)
					{
						gnutls_deinit(curcli->session);
					}
					close(events[wretval].data.fd);
					continue;
				}
				if (recvretval == 1)
				{
					//assume we got
					//GNUTLS_E_AGAIN because
					//we are waiting on a recv
					//hopefully we are not waiting on a send
					//or this tcp will block forever
					curcli->state = TLS_STATE_HANDSHAKE;
					continue;
				}
				//fallthrough
			case TLS_STATE_RECV:
			tlsrecvagain:
				recvretval = gnutls_record_recv(curcli->session, &curcli->r[curcli->reqindex], (REQUEST_SIZE - RESERVED_REQ_SIZE) - curcli->reqindex);
				if (recvretval < 0)
				{
					if (recvretval == GNUTLS_E_AGAIN)
					{
						continue;
					}
					if (recvretval != GNUTLS_E_PREMATURE_TERMINATION)
					{
						logmsgcli(curcli, gnutls_strerror_name(recvretval));
					}
					gnutls_deinit(curcli->session);
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				if (!recvretval)
				{
					gnutls_deinit(curcli->session);
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				curcli->reqindex += recvretval;
				reqstatus = isrequestcomplete(curcli);
				if (!reqstatus)
				{
					goto tlsrecvagain;
				}
				if (reqstatus < 0)
				{
					generateerror(curcli, 494, events[wretval].data.fd, &phonyreq);
					goto tlsafterprocessreq;
				}
				curcli->r[recvretval] = 0;
				processrequest(events[wretval].data.fd, REQUEST_FLAG_TLS);
			tlsafterprocessreq:
				curcli->reqindex = 0;
				//fallthrough
			case TLS_STATE_RESPONDING_HEADER_ONLY:
			case TLS_STATE_RESPONDING_HEADER_ONLY_HUP:
			case TLS_STATE_RESPONDING_HEADER_FILE:
			tlssendhagain:
				/* if (curcli->state == TLS_STATE_RESPONDING_HEADER_FILE) */
				/* { */
				/* 	gnutls_record_cork(curcli->session); */
				/* } */
				recvretval = gnutls_record_send(curcli->session, &curcli->r[curcli->reqindex], curcli->resphsize - curcli->reqindex);
				if (recvretval < 0)
				{
					if (recvretval == GNUTLS_E_AGAIN)
					{
						events[wretval].events = EPOLLOUT;
						epoll_ctl(e, EPOLL_CTL_MOD, events[wretval].data.fd, &events[wretval]);
						continue;
					}
					if (recvretval != GNUTLS_E_PREMATURE_TERMINATION)
					{
						logmsgcli(curcli, gnutls_strerror_name(recvretval));
					}
					gnutls_deinit(curcli->session);
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				curcli->reqindex += recvretval;
				if (curcli->reqindex != curcli->resphsize)
				{
					goto tlssendhagain;
				}
				if (curcli->state == TLS_STATE_RESPONDING_HEADER_ONLY_HUP)
				{
					gnutls_bye(curcli->session, GNUTLS_SHUT_RDWR);
					gnutls_deinit(curcli->session);
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				if (curcli->state != TLS_STATE_RESPONDING_HEADER_FILE)
				{
					curcli->reqindex = 0;
					curcli->state = TLS_STATE_RECV;
					break;
				}
				curcli->state = TLS_STATE_RESPONDING_FILE;
				//fallthrough
			case TLS_STATE_RESPONDING_FILE:
			tlssendfileagain:
				cursend = (curcli->erange - curcli->srange);
				if (cursend > BERNWEB_LINUX_SENDFILE_MAX)
				{
					cursend = BERNWEB_LINUX_SENDFILE_MAX;
				}

				recvretval = gnutls_record_send_file(curcli->session, curcli->fd, &curcli->srange, cursend);
				if (recvretval < 0)
				{
					if (recvretval == GNUTLS_E_AGAIN)
					{
						if (events[wretval].events != EPOLLOUT)
						{
							events[wretval].events = EPOLLOUT;
							epoll_ctl(e, EPOLL_CTL_MOD, events[wretval].data.fd, &events[wretval]);
						}
						continue;
					}
					if (recvretval != GNUTLS_E_PREMATURE_TERMINATION)
					{
						logmsgcli(curcli, gnutls_strerror_name(recvretval));
					}
					gnutls_deinit(curcli->session);
					#ifdef BERNWEB_MADV_FREE
					madvise(curcli, BERNWEB_PAGE_SIZE, MADV_FREE);
					#endif
					close(events[wretval].data.fd);
					continue;
				}
				if (((size_t)curcli->srange) != curcli->erange)
				{
					goto tlssendfileagain;
				}
				close(curcli->fd);
				if (events[wretval].events != EPOLLIN)
				{
					events[wretval].events = EPOLLIN;
					epoll_ctl(e, EPOLL_CTL_MOD, events[wretval].data.fd, &events[wretval]);
				}
				curcli->reqindex = 0;
				curcli->state = TLS_STATE_RECV;
			}
		}
	}
}

int main(int argc, char *argv[])
{
	int myerrno;
	int pcreateretval;
	pthread_attr_t pattr;
	pthread_t nt;
	int sock;
	int tlssock;
	int curclifd;
	struct sockaddr_storage curcli;
	socklen_t curclisize;
	int epafd;
	struct epoll_event events[MAX_ACCEPT_EP_EVENTS] = {0};
	struct epoll_event newcli = {0};
	unsigned short thread;
	unsigned short tlsthread;
	int wretval;

	(void)argc;
	(void)argv;

	logfd = STDERR_FILENO;

	loadconfig();

	logfd = open(logfilepath, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (logfd == -1)
	{
		myerrno = errno;
		perror("log file open()");
		return myerrno;
	}
	free(logfilepath);

	logmsg("starting up");

	if (sizeof(struct clicon) != BERNWEB_PAGE_SIZE)
	{
		logmsg("built with incorrect page size stuff todo fixme");
		exit(1);
	}

	if (sigaction(SIGPIPE, &siga, NULL))
	{
		myerrno = errno;
		logmsg("sigaction() failed");
		logmsg(strerror(myerrno));
		return myerrno;
	}

	oh.flags = O_RDONLY;
	oh.resolve = RESOLVE_IN_ROOT;

	#ifdef BERNWEB_INTERNAL_DENTRY
	docrootfd = open(docrootpath, O_RDONLY | O_DIRECTORY);
	#else
	docrootfd = open(docrootpath, O_PATH | O_DIRECTORY);
	#endif
	if (docrootfd == -1)
	{
		myerrno = errno;
		logmsg("failed to open() documentroot");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	free(docrootpath);

	if (httpthreads)
	{
		setupsocket(&sock, 80);
	}

	if (httpsthreads)
	{
		setupsocket(&tlssock, 443);

		if (gnutls_global_init())
		{
			logmsg("gnutls_global_init() failed");
			return 1;
		}
		if (gnutls_certificate_allocate_credentials(&x509cred))
		{
			logmsg("gnutls_certificate_allocate_credentials() failed");
			return 1;
		}
		if (gnutls_certificate_set_x509_key_file(x509cred, pubcertpath, privkeypath, GNUTLS_X509_FMT_PEM))
		{
			logmsg("gnutls_certificate_set_x509_key_file() failed");
			return 1;
		}
		if (gnutls_priority_init(&pcache, "NONE:+VERS-TLS1.2:+AES-256-GCM:+DHE-RSA:+ECDHE-RSA:+SHA384:+AEAD:+CTYPE-SRV-X509:+SIGN-RSA-SHA512:+COMP-NULL:+GROUP-ALL", NULL))
		{
			logmsg("gnutls_priority_init() failed");
			return 1;
		}
		/* if (gnutls_certificate_set_known_dh_params(x509cred, GNUTLS_SEC_PARAM_MAX)) */
		/* { */
		/* 	logmsg("gnutls_certificate_set_known_dh_params() failed"); */
		/* 	return 1; */
		/* } */
		free(pubcertpath);
		free(privkeypath);
	}
	else
	{
		if (pubcertpath)
		{
			free(pubcertpath);
		}
		if (privkeypath)
		{
			free(privkeypath);
		}
	}


	if (setrlimit(RLIMIT_NOFILE, &newnofile))
	{
		myerrno = errno;
		logmsg("failed to setrlimit()");
		logmsg(strerror(myerrno));
		return myerrno;
	}

	#ifdef DEBUG
	newnofile.rlim_cur = RLIM_INFINITY;
	newnofile.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &newnofile))
	{
		myerrno = errno;
		logmsg("failed to setrlimit()");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	#endif

	if (setgroups(0, NULL) != 0)
	{
		myerrno = errno;
		logmsg("setgroups() failed");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	if (setgid(runasgid))
	{
		myerrno = errno;
		logmsg("failed to setgid()");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	if (getgid() != runasgid)
	{
		logmsg("getgid() returned an unexpected result");
		return 1;
	}
	if (setuid(runasuid))
	{
		myerrno = errno;
		logmsg("failed to setuid()");
		logmsg(strerror(myerrno));
		return myerrno;
	}
	if (getuid() != runasuid)
	{
		logmsg("getuid() returned an unexpected result");
		return 1;
	}

	#ifdef BERNWEB_INTERNAL_DENTRY
	generatedentry();
	#endif

	epafd = epoll_create(8);
	if (epafd == -1)
	{
		myerrno = errno;
		logmsg("epoll_create() failed for the accept()ing epollfd");
		logmsg(strerror(myerrno));
		return myerrno;
	}

	if (httpthreads)
	{
		epfd = malloc(sizeof(int) * httpthreads);
		if (!epfd)
		{
			myerrno = errno;
			logmsg("malloc() failed");
			logmsg(strerror(myerrno));
			return myerrno;
		}
		events[0].events = EPOLLIN;
		events[0].data.fd = sock;
		if (epoll_ctl(epafd, EPOLL_CTL_ADD, sock, &events[0]))
		{
			myerrno = errno;
			logmsg("epoll_ctl() failed EPOLL_CTL_ADD http socket");
			logmsg(strerror(myerrno));
			return myerrno;
		}
	}
	if (httpsthreads)
	{
		tlsepfd = malloc(sizeof(int) * httpthreads);
		if (!tlsepfd)
		{
			myerrno = errno;
			logmsg("malloc() failed");
			logmsg(strerror(myerrno));
			return myerrno;
		}
		events[0].events = EPOLLIN;
		events[0].data.fd = tlssock;
		if (epoll_ctl(epafd, EPOLL_CTL_ADD, tlssock, &events[0]))
		{
			myerrno = errno;
			logmsg("epoll_ctl() failed EPOLL_CTL_ADD https socket");
			logmsg(strerror(myerrno));
			return myerrno;
		}
	}

	pthread_attr_init(&pattr);
	myerrno = pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
	if (myerrno)
	{
		logmsg("failed pthread_attr_setdetachstate()");
		logmsg(strerror(myerrno));
		return myerrno;
	}

	clitable = mmap(NULL, NEW_NOFILE_NUM * sizeof(struct clicon), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (clitable == MAP_FAILED)
	{
		myerrno = errno;
		logmsg("mmap() failed");
		logmsg(strerror(myerrno));
		return myerrno;
	}

	thread = 0;
	while (thread != httpthreads)
	{
		epfd[thread] = epoll_create(8);
		if (epfd[thread] == -1)
		{
			myerrno = errno;
			logmsg("epoll_create() failed on an http thread");
			logmsg(strerror(myerrno));
			return myerrno;
		}
		while (1)
		{
			pcreateretval = pthread_create(&nt, &pattr, httpworker, &epfd[thread]);
			if (pcreateretval)
			{
				if (pcreateretval == EAGAIN)
				{
					continue;
				}
				logmsg("pthread_create() failed for http thread");
				logmsg(strerror(pcreateretval));
				return pcreateretval;
			}
			break;
		}
		thread++;
	}
	thread = 0;
	while (thread != httpsthreads)
	{
		tlsepfd[thread] = epoll_create(8);
		if (tlsepfd[thread] == -1)
		{
			myerrno = errno;
			logmsg("epoll_create() failed on an http thread");
			logmsg(strerror(myerrno));
			return myerrno;
		}
		while (1)
		{
			pcreateretval = pthread_create(&nt, &pattr, tlsworker, &tlsepfd[thread]);
			if (pcreateretval)
			{
				if (pcreateretval == EAGAIN)
				{
					continue;
				}
				logmsg("pthread_create() failed for tls thread");
				logmsg(strerror(pcreateretval));
				return pcreateretval;
			}
			break;
		}
		thread++;
	}

	logmsg("startup complete, entering accept loop");

	newcli.events = EPOLLIN;
	thread = 0;
	tlsthread = 0;
	while (1)
	{
		wretval = epoll_wait(epafd, events, MAX_ACCEPT_EP_EVENTS, -1);
		if (wretval == -1)
		{
			myerrno = errno;
			logmsg("epoll_wait() failed accept thread");
			logmsg(strerror(myerrno));
			return myerrno;
		}
		while (wretval)
		{
			wretval--;
		acceptagain:
			curclisize = sizeof(struct sockaddr_storage);
			curclifd = accept4(events[wretval].data.fd, (struct sockaddr*) &curcli, &curclisize, SOCK_NONBLOCK);
			if (curclifd == -1)
			{
				if (errno == ECONNABORTED)
				{
					continue;
				}
				if ((errno == EMFILE) || (errno == ENFILE) || (errno == ENOBUFS) || (errno == ENOMEM))
				{
					sleep(1);
					goto acceptagain;
				}
				myerrno = errno;
				logmsg("accept4() failed");
				logmsg(strerror(myerrno));
				return myerrno;
			}
			__builtin_memcpy(&clitable[curclifd].addr, &curcli, curclisize);
			clitable[curclifd].state = 0;
			newcli.data.fd = curclifd;
			if (events[wretval].data.fd == sock)
			{
				if (epoll_ctl(epfd[thread], EPOLL_CTL_ADD, newcli.data.fd, &newcli))
				{
					myerrno = errno;
					logmsg("epoll_ctl() failed EPOLL_CTL_ADD http worker");
					logmsg(strerror(myerrno));
					return myerrno;
				}
				thread++;
				if (thread == httpthreads)
				{
					thread = 0;
				}
			}
			else
			{
			        if (epoll_ctl(tlsepfd[tlsthread], EPOLL_CTL_ADD, newcli.data.fd, &newcli))
				{
					myerrno = errno;
					logmsg("epoll_ctl() failed EPOLL_CTL_ADD https worker");
					logmsg(strerror(myerrno));
					return myerrno;
				}
				tlsthread++;
				if (tlsthread == httpsthreads)
				{
					tlsthread = 0;
				}
			}
		}
	}

	return 0;
}
