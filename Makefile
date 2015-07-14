INCLUDE_DIR=/usr/include/nfc
.PHONY:test
all:
	gcc main.c  nfc_event.c util.c stringbuffer.c testlib.c -O2 -lminimsg -levent
	gcc -fPIC util.c libnfc.c -shared -O2 -o libnfc.so -lminimsg 
install:
	install libnfc.so /usr/lib
	mkdir -p ${INCLUDE_DIR}	
	install nfc.h ${INCLUDE_DIR}
	install util.h ${INCLUDE_DIR}
uninstall:
	rm ${INCLUDE_DIR}/util.h
	rm ${INCLUDE_DIR}/nfc.h
	rmdir ${INCLUDE_DIR}
	rm /usr/lib/libnfc.so
test:
	make -C test
clean:
	rm libnfc.so
	make -C test clean

