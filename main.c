#include "event.h"
#include "linkedlist.h"
#include <stdio.h>
#include <string.h>
void addPermanentRule();
int main()
{
	list_t* l;
	char* ptr;
	l = list_alloc();
	
	list_add(l,"1",strdup("1"));
	
	ptr = list_search(l,"1");
	if(ptr ){ printf("%s\n",ptr);}
	
	
	return 0;
}
