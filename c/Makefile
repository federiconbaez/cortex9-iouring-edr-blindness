CFLAGS ?= -O2 -Wall -Wextra
LDLIBS ?= -luring

all: victim

victim: victim.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f victim

.PHONY: all clean
