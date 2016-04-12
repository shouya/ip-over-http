# CFLAGS = -Wall -O2 -pedantic
CFLAGS = -Wall -O2

tun: tun.c


.PHONY: clean
clean:
	rm -f tun
