default: all

CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -I../include -flto -fuse-linker-plugin -MMD
LDFLAGS += -march=native -Ofast -pipe -lmagic -flto -fuse-linker-plugin

CC = gcc
#CC = x86_64-w64-mingw32-gcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
DEPENDS = $(SRCS:.c=.d)

all: web-ingest

web-ingest: $(OBJS)
	$(CC) $(OBJS) -o web-ingest $(LDFLAGS)

-include $(DEPENDS)

clean:
	$(RM) web-ingest src/*.o src/*.d
