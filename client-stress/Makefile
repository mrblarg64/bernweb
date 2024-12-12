default: all

CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -I../include -flto -fuse-linker-plugin -MMD
LDFLAGS += -march=native -Ofast -lpthread -pipe -flto -fuse-linker-plugin

CC = gcc
#CC = x86_64-w64-mingw32-gcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
DEPENDS = $(SRCS:.c=.d)

all: bernweb-client-stress

bernweb-client-stress: $(OBJS)
	$(CC) $(OBJS) -o bernweb-client-stress $(LDFLAGS)

-include $(DEPENDS)

clean:
	$(RM) bernweb-client-stress src/*.o src/*.d
