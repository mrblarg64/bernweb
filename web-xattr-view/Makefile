default: all

CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -I../include -flto -fuse-linker-plugin -MMD
LDFLAGS += -march=native -Ofast -pipe -flto -fuse-linker-plugin

CC = gcc
#CC = x86_64-w64-mingw32-gcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
DEPENDS = $(SRCS:.c=.d)

all: web-xattr-view

web-xattr-view: $(OBJS)
	$(CC) $(OBJS) -o web-xattr-view $(LDFLAGS)

-include $(DEPENDS)

clean:
	$(RM) web-xattr-view src/*.o src/*.d
