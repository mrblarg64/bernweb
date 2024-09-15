default: all

CFLAGS += -Wall -Wextra -march=native -Ofast -pipe -I../include -flto -fuse-linker-plugin -MMD
LDFLAGS += -lgnutls -march=native -Ofast -pipe -flto -fuse-linker-plugin

CC = gcc
#CC = x86_64-w64-mingw32-gcc

SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
DEPENDS = $(SRCS:.c=.d)

all: bernweb

bernweb: $(OBJS)
	$(CC) $(OBJS) -o bernweb $(LDFLAGS)

-include $(DEPENDS)

clean:
	$(RM) bernweb src/*.o src/*.d
