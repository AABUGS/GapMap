CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -m64

all: payload.exe gapmap.exe

payload.exe: payload.c
	$(CC) $(CFLAGS) -nostdlib -fno-asynchronous-unwind-tables -fno-ident \
		-e payload_entry \
		-Wl,--section-alignment,4096 \
		-Wl,--file-alignment,512 \
		-Wl,-s -Wl,--no-seh \
		-o $@ $<

gapmap.exe: gapmap.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f payload.exe gapmap.exe

.PHONY: all clean
