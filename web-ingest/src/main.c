//Copyright (C) 2024 Brian William Denton
//Available under the GNU GPLv3 License

#include <unistd.h>
#include <sys/xattr.h>
#include <errno.h>
#include <magic.h>
#include <stdlib.h>
#include <stdio.h>
//needed for DSCP values
#include <netinet/ip.h>

#include <bernweb-xattr.h>

const char usagestr[] =
"bernweb-web-ingest\n\
\n\
Usage: bernweb-web-ingest file [DSCP_TAG] [MIME]\n\
\n\
bernweb-web-ingest adds the necessary dscp tag and mime info to a file's xattrs\n\
\tso the bernweb web server component can \"see\" the file\n\
\twithout it the server will report 404, even though the file exists\n\
\n\
DSCP_TAG\n\
\tthe DSCP tag that will be set when the server serves this file\n\
\tif DSCP is not provided it will beset to 0 to indicating the\n\
\tuse of the server's default DSCP tag\n\
\tmust either be an 8 bit number (hex, octal, and decimal supported (strtoul()))\n\
\tor one of the following:\n\
\t\tafXY where (1 <= X <= 4) and (1 <= Y <=3) \n\
\t\tcsX where (0 <= X <= 7)\n\
\t\tef\n\
\t\tle\n\
\n\
MIME\n\
\tYou MUST provide a DSCP if you wish to manually supply a mime\n\
\tIf mime is provided it will be used as the mime type for the file\n\
\tIf mime is NOT provided the mime type will be automatically filled in\n\
\tusing libmagic\n";

const char dscpnonum[] = "You have entered an invalid DSCP_TAG\n";
const char dscprange[] = "You have entered a DSCP_TAG that does not fit in 8 bits\n";
const char dscpecn[] = "The 2 least significant bits for DSCP_TAG must be 0 to avoid mangling ECN bits\n";
const char mload[] = "magic_load() failed!\n";
const char mfile[] = "magic_file() failed!\n";
const char done[] = "Done!\n";

#ifdef __ORDER_LITTLE_ENDIAN__
const uint16_t cs = 0x7363;
const uint16_t af = 0x6661;
#else
const uint16_t cs = 0x6373;
const uint16_t af = 0x6166;
#endif

void printusage()
{
	(void)!write(STDOUT_FILENO, usagestr, sizeof(usagestr));
}

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

int main(int argc, const char *argv[])
{
	int myerrno;
	long dscp = 0;
	const char *strptr;
	magic_t m;
	size_t slen;
	char *xattr;

	if ((argc < 2)||(argc > 4))
	{
		printusage();
		return EINVAL;
	}

	if (argc > 2)
	{
		dscp = strtoul(argv[2], &xattr, 0);
		if (*xattr)
		{
			dscp = processdscp(argv[2]);
			if (dscp == -1)
			{
				(void)!write(STDERR_FILENO, dscpnonum, sizeof(dscpnonum));
				return EINVAL;
			}
		}
		else
		{
			if (dscp > 0xff)
			{
				(void)!write(STDERR_FILENO, dscprange, sizeof(dscprange));
				return EINVAL;
			}
			if (dscp & 0b11)
			{
				(void)!write(STDERR_FILENO, dscpecn, sizeof(dscpecn));
				return EINVAL;
			}
		}
	}

	if (argc == 4)
	{
		strptr = argv[3];
	}
	else
	{
		m = magic_open(MAGIC_MIME_TYPE);
		if (!m)
		{
			myerrno = errno;
			perror("magic_open()");
			return myerrno;
		}
		if (magic_load(m, NULL))
		{
			strptr = magic_error(m);
			if (strptr)
			{
				(void)!write(STDERR_FILENO, strptr, __builtin_strlen(strptr));
			}
			(void)!write(STDERR_FILENO, mload, sizeof(mload));
			magic_close(m);
			return 1;
		}
		strptr = magic_file(m, argv[1]);
		if (!strptr)
		{
			strptr = magic_error(m);
			if (strptr)
			{
				(void)!write(STDERR_FILENO, strptr, __builtin_strlen(strptr));
			}
			(void)!write(STDERR_FILENO, mfile, sizeof(mfile));
			magic_close(m);
			return 1;
		}
	}

	slen = __builtin_strlen(strptr);
	//mimes shouldn't be more than 255
	//it's on the user for doing something dumb
	//(including having a fucked libmagic mime DB)
	//and causing this to explode
	//fuckem
	//https://www.youtube.com/watch?v=wst8MpSC5D4
	xattr = __builtin_alloca(slen + 1);
	__builtin_memcpy(&xattr[1], strptr, slen);
	*((unsigned char*)&xattr[0]) = dscp;

	if (argc != 4)
	{
		magic_close(m);
	}

	if (setxattr(argv[1], BERNWEB_XATTR_KEY, xattr, slen+1, 0))
	{
		myerrno = errno;
		perror("setxattr()");
		return myerrno;
	}

	if (xattr[0])
	{
		printf("DSCP = 0x%hhx\nmime = %.*s\n", xattr[0], (int)slen, &xattr[1]);
	}
	else
	{
		printf("DSCP = server default\nmime = %.*s\n", (int)slen, &xattr[1]);
	}

	(void)!write(STDOUT_FILENO, done, sizeof(done));

	return 0;
}
