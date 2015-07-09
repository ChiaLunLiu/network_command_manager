all:
	gcc main.c  nfc_event.c util.c stringbuffer.c testlib.c -O2 -lminimsg -levent
clean:
	rm -f a.out
