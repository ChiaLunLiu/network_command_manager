#ifndef __BUFFER_H__
#define __BUFFER_H__
#define INITIAL_BUF_SIZE 2
typedef struct _buffer{
	char* buf;
	int current_size;
	int max_size;
}stringbuffer_t;

stringbuffer_t* stringbuffer_alloc();
void stringbuffer_add(stringbuffer_t* b, const char* data);
void stringbuffer_add_f(stringbuffer_t* b,const char *format, ...);
void stringbuffer_destroy(stringbuffer_t* b);
const char* stringbuffer_get(stringbuffer_t *b);
#endif
