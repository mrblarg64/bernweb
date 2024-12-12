default: all

CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -I../include -flto -fuse-linker-plugin -MMD
LDFLAGS += -march=native -Ofast -pipe -flto -fuse-linker-plugin

CC = gcc
#CC = x86_64-w64-mingw32-gcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
DEPENDS = $(SRCS:.c=.d)

all: bernweb-profiling-decode

bernweb-profiling-decode: $(OBJS)
	$(CC) $(OBJS) -o bernweb-profiling-decode $(LDFLAGS)

-include $(DEPENDS)

clean:
	$(RM) bernweb-profiling-decode src/*.o src/*.d
