all:
	gcc main.c linkedlist.c event.c util.c stringbuffer.c testlib.c -O2
clean:
	rm -f a.out
