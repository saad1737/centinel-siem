CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -D_GNU_SOURCE
LDFLAGS = -lcweb -lsodium -ljwt -lpq
SRCS = $(wildcard *.c)
APP_NAME = centinel-engine

all: 
	$(CC) $(CFLAGS) $(SRCS) -o $(APP_NAME) $(LDFLAGS)

clean:
	rm -rf $(APP_NAME)

.PHONY: all clean
