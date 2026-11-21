CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -D_GNU_SOURCE
LDFLAGS = -lcweb -lsodium -ljwt -lpq

APP_NAME = engine

all:
	$(CC) $(CFLAGS) engine.c -o $(APP_NAME) $(LDFLAGS)

clean:
	rm -rf $(APP_NAME)

.PHONY: all clean install
