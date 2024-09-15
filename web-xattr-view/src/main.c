//Copyright (C) 2024 Brian William Denton
//Available under the GNU GPLv3 License

#include <unistd.h>
#include <sys/xattr.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include <bernweb-xattr.h>

const char usagestr[] =
"bernweb-web-xattr-view\n\
\n\
Usage: bernweb-web-xattr-view file\n\
\n\
bernweb-web-xattr-view shows the xattrs used for dscp and mime\n";

const char nodata[] = "The file has no bern-internet xattrs\n";
const char missingdata[] = "The bern-internet xattrs were deleted while attempting to check them\n";

void printusage()
{
	(void)!write(STDOUT_FILENO, usagestr, sizeof(usagestr));
}

int main(int argc, const char *argv[])
{
	int myerrno;
	ssize_t xattrsize;
	ssize_t retval;
	char *xattr;

	if (argc != 2)
	{
		printusage();
		return EINVAL;
	}

again:
	xattrsize = getxattr(argv[1], BERNWEB_XATTR_KEY, NULL, 0);
	if (xattrsize == -1)
	{
		myerrno = errno;
		if (myerrno == ENODATA)
		{
			(void)!write(STDOUT_FILENO, nodata, sizeof(nodata));
			return 0;
		}
		perror("getxattr()");
		return myerrno;
	}

	//see skill issue comment in the ingester
	//user's fault for fucking this lmao
	xattr = __builtin_alloca(xattrsize+10);
	retval = getxattr(argv[1], BERNWEB_XATTR_KEY, xattr, xattrsize+9);
	if (xattrsize == -1)
	{
		myerrno = errno;
		if (myerrno == ENODATA)
		{
			(void)!write(STDOUT_FILENO, missingdata, sizeof(missingdata));
			return 0;
		}
		if (myerrno == ERANGE)
		{
			//stack overflow!!
			goto again;
		}
		perror("getxattr()");
		return myerrno;
	}

	xattr[retval] = 0;
	if (xattr[0])
	{
		printf("DSCP = 0x%hhx\nmime = %s\n", xattr[0], &xattr[1]);
	}
	else
	{
		printf("DSCP = server default\nmime = %s\n", &xattr[1]);
	}

	return 0;
}
