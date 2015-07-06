#include "stringbuffer.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
stringbuffer_t* stringbuffer_alloc()
{
	stringbuffer_t* b;
	b = malloc( sizeof(stringbuffer_t));
	if(!b)return NULL;
	b->buf  = malloc( INITIAL_BUF_SIZE);
	if(!b->buf){
		free(b);
		return NULL;
	}
	b->buf[0]='\0';
	b->current_size = 0;
	b->max_size = INITIAL_BUF_SIZE;
	return b;
}
void stringbuffer_clear(stringbuffer_t* b)
{
	b->current_size = 0;
}
void stringbuffer_add(stringbuffer_t* b, const char* data)
{
	int len = strlen(data);
	
	printf("%d\n",b->max_size);
	if(b->max_size - b->current_size <= len){
		while(b->max_size - b->current_size <= len){
			b->max_size*=2;
//			printf("%d\n",b->max_size);
		}
			b->buf = realloc( b->buf, b->max_size);
	//		printf("done");
	}
	
	memcpy(b->buf + b->current_size, data, len);
	b->current_size+=len;
	b->buf[b->current_size]='\0';
}
void stringbuffer_destroy(stringbuffer_t* b)
{
	free(b->buf);
	free(b);
}
const char* stringbuffer_get(stringbuffer_t *b)
{
	return b->buf;
}

void stringbuffer_add_f(stringbuffer_t* b,const char *format, ...)
{
    va_list argptr;
    va_start (argptr, format);
    char *string = zsys_vprintf (format, argptr);
    va_end (argptr);
    
    if(!string){
		printf("error\n");
	}
    stringbuffer_add(b,string);
    free(string);
    
}
