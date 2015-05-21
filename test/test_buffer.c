#include "stringbuffer.h"
#include <stdio.h>

int main()
{
	stringbuffer_t* b;
	int i;
	b = stringbuffer_alloc();
	
	
	for(i = 0 ;i < 10 ; i++){
		stringbuffer_add(b,"hi ");
	}
	
	stringbuffer_add_f(b,"%d %d",12345,56789);
	printf("str=%s\n",stringbuffer_get(b));
	
	stringbuffer_destroy(b);
	return 0;
}
