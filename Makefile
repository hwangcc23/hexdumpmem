CFLAGS := -g3 -O2 -Wall
LDFLAGS :=
SRCS := hexdumpmem.c
OBJS := $(SRCS:.c=.o)
CROSS :=

CC ?= $(CROSS)gcc
LD ?= $(CROSS)ld

all: hexdumpmem

hexdumpmem: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c 
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS) hexdumpmem

.PHONY: clean all
