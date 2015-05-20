
#include "event.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define handle_error(msg) do { perror(msg); exit(EXIT_FAILURE); }while(0)

event_t* event_alloc()
{
	event_t* ev;
	ev = malloc( sizeof(event_t));
	if(!ev)handle_error("malloc event");
	return ev;
}
void event_init( event_t* const  e)
{
	e->buf = NULL;
	e->name = NULL;
	e->task = NULL;
}
void eventfactory_init(eventfactory_t *__restrict__ ef)
{
	ef->list_script = list_alloc();
	ef->list_user   = list_alloc();
	ef->list_sys    = list_alloc();
}

void event_register(int type,eventfactory_t* __restrict__ ef, const char*  __restrict__ ename, void(*task)(void*))
{
		event_t* ev = event_alloc();
		event_init(ev);
		ev->name = strdup(ename);
		ev->task = task;
		ev->type = type;
		
		switch(type){
		case EVENTSCRIPT:
			list_add(ef->list_script,ename,ev);
		break;
		case EVENTSYS:
			list_add(ef->list_sys,ename,ev);
		break;
		case EVENTUSER:
			list_add(ef->list_user,ename,ev);
		break;
		default:
			handle_error("undefined type");
		break;
		}
		
}
event_t * event_search(eventfactory_t* __restrict__ ef,const char*  __restrict__ ename, int type)
{
	
	switch(type){
		case EVENTSCRIPT:
			return list_search(ef->list_script,ename);
		break;
		case EVENTSYS:
			return list_search(ef->list_sys,ename);
		break;
		case EVENTUSER:
			return list_search(ef->list_user,ename);
		break;
		default:
			handle_error("undefined type");
		break;
	}
	return NULL;
}
void event_process(eventfactory_t* __restrict__ ef, const char*  __restrict__ ename,int type,int is_on)
{
	event_t* ev;
	char* cmd;
	int len;
	int r;
	ev = event_search(ef,ename,type);
	if(!ev){
		handle_error("event is not defined");
	}
	switch(ev->type){
		case EVENTSCRIPT:
			len = strlen(ev->name) + 7;
			cmd = malloc( len ); /* 7 : max length of start , stop */
			if(!cmd) handle_error("cmd malloc");
			snprintf(cmd,len,"%s stop",ev->name);
			r=system(cmd);
			if(is_on){
				snprintf(cmd,len,"%s start",ev->name);
				r=system(cmd);
			}
			free(cmd);
		break;
		case EVENTUSER:
		case EVENTSYS:
			if(ev->buf){
				r=system(ev->buf);
				free(ev->buf);
				ev->buf = NULL;
			}
			ev->task(ev);
		break;
		default:
			printf("undefined type\n");
		break;
	}
}
inline void event_script_register(eventfactory_t* __restrict__ ef, const char* __restrict__ scriptname)
{
	event_register(EVENTSCRIPT,ef, scriptname, NULL);
}
inline void event_sys_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(void*))
{
	event_register(EVENTSYS,ef, ename, event);
}
inline void event_user_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(void*))
{
	event_register(EVENTUSER,ef, ename, event);
}
/* registered app event */



