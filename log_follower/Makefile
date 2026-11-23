CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -D_GNU_SOURCE

TARGET = centinel_log_fol
SERVICE = centinel-log-follower.service
DEFAULT = centinel-log-follower.default

PREFIX ?= /usr/local
BINDIR = $(DESTDIR)$(PREFIX)/bin
SYSTEMDDIR = $(DESTDIR)/etc/systemd/system
CONFDIR = $(DESTDIR)/etc/default

# Find all .c files in this directory
SRCS = $(wildcard *.c)

all: $(TARGET)

# Compile and create the executable
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)

clean:
	rm -rf $(TARGET)

install: $(TARGET)
	install -d $(BINDIR)
	install -m 755 $(TARGET) $(BINDIR)/$(TARGET)
	install -d $(SYSTEMDDIR)
	install -m 644 $(SERVICE) $(SYSTEMDDIR)/$(SERVICE)
	install -d $(CONFDIR)
	install -m 644 $(DEFAULT) $(CONFDIR)/centinel-log-follower

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(SYSTEMDDIR)/$(SERVICE)
	rm -f $(CONFDIR)/centinel-log-follower

.PHONY: all clean install uninstall
