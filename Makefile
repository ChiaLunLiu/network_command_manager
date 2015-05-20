all:
	gcc main.c linkedlist.c event.c -O2
clean:
	rm -f a.out
