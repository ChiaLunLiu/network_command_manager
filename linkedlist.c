#include "linkedlist.h"
#include <stdlib.h>
#include <string.h>
#define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

lnode_t* lnode_alloc(const char* name,void* data)
{
	lnode_t* l = malloc( sizeof( lnode_t) );
	if(!l)handle_error("lnode malloc");
	l->name = strdup(name);
	l->data = data;
	l->next = NULL;
	return l;
}
void lnode_free(lnode_t* l);

inline int list_size(list_t* l)
{
	return l->number;
}
list_t* list_alloc()
{
	list_t * l;
	l = malloc( sizeof( list_t) );
	if(!l) handle_error("list malloc");
	l->number = 0;
	l->head = NULL;
}
int list_free(list_t* l)
{
	if(l->number > 0) return LIST_FAIL;
	return LIST_OK;
}
void list_add(list_t* l,const char* str, void* data)
{
	lnode_t *n = lnode_alloc(str,data);
	
	if(l->head == NULL) l->head = n;
	else{
		n->next = l->head;
		l->head = n;
	}
	l->number++;
}
void* list_search(list_t* l,const char* str)
{
	lnode_t* i;
	for(i = l->head ; i ; i = i->next){
		if(!strcmp( i->name,str) ){
			return i->data;
		}
	}
	return NULL;
}
