# SUID-Locate Makefile

# Compilation Parameters
CC=gcc
CFLAGS= -Iincludes -Wextra -Wall
SOURCES= suid_locate.c

all:
	$(CC) $(SOURCES) $(CFLAGS) -o suid-locate
clean:
	rm -f suid-locate
