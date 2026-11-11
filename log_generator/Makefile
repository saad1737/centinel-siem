CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -D_GNU_SOURCE

# Find all .c files in this directory
SRCS = $(wildcard *.c)

all: sentinel_log_gen

# Compile and create the executable
sentinel_log_gen: $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o sentinel_log_gen

clean:
	rm -rf sentinel_log_gen

.PHONY: all clean
