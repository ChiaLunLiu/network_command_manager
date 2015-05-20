
#ifndef __LINKEDLIST_H__
#define __LINKEDLIST_H__
#define LIST_OK 0
#define LIST_FAIL 1

typedef struct _lnode lnode_t;

struct _lnode{
	lnode_t * next;
	char* name;
	void* data;
};

typedef struct _list_t{
	lnode_t * head;
	int number;
}list_t;

lnode_t* lnode_alloc(const char* name,void* data);
void lnode_free(lnode_t* l);

inline int list_size(list_t* l);
list_t* list_alloc();
int list_free(list_t* l);
void list_add(list_t* l,const char* str, void* data);
void* list_search(list_t* l,const char* str);
#endif
