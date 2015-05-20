
#include "event.h"

#define handle_error(msg) \
           do { perror(msg); exit(EXIT_FAILURE); } while (0)

event_t* event_alloc()
{
	event_t* ev;
	ev = malloc( sizeof(event_t));
	if(!ev)handle_error("malloc event");
	
	return ev;
}
void event_init(const event_t* __restrict__ e)
{
	e->buf = NULL;
	e->name = NULL;
	e->task = NULL;
}
void event_add(eventfactory_t* __restrict__ ef,const char* __restrict__ ename, event_t* ev, int type)
{
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

void eventfactory_init(eventfactory_t *__restrict__ ef);
{
	ef->eventlist = list_alloc();
}

void event_register(int type,eventfactory_t* __restrict__ ef, const char*  ename, void(*task)(void*));
{
		event_t* ev = event_alloc();
		event_init(ev);
		ev->name = strdup(ename);
		ev->task = task;
		ev->type = type;
		
		event_add(ef->eventlist,ename,ev);
}
event_t * event_search(eventfactory_t* restrict ef,const char* restrict ename, int type)
{
	
	switch(type){
		case EVENTSCRIPT:
			return list_search(ef->list_script,ename,ev);
		break;
		case EVENTSYS:
			return list_search(ef->list_sys,ename,ev);
		break;
		case EVENTUSER:
			return list_search(ef->list_user,ename,ev);
		break;
		default:
			handle_error("undefined type");
		break;
	}
	return NULL;
}
void event_process(eventfactory_t* restrict ef, const char* restrict ename,int type,int is_on);
{
	event_t* ev;
	char* cmd;
	int len;
	ev = event_search(ef->eventlist,ename,type);
	if(!ev)	handle_error("undefined event");
	
	switch(ev->type){
		case EVENTSCRIPT:
			len = strlen(ev->ename) + 6;
			cmd = malloc( len ); /* 6 : max length of start , stop */
			if(!cmd) handle_error("cmd malloc");
			snprintf(cmd,len,"%s stop",ev->ename);
			system(cmd);
			if(is_on){
				snprintf(cmd,len,"%s start",ev->ename);
				system(cmd);
			}
			free(cmd);
		break;
		case EVENTUSER:
		case EVENTSYS:
			if(ev->buf){
				system(ev->buf);
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
inline void event_script_register(eventfactory_t* restrict ef, const char* restrict scriptname)
{
	event_register(EVENTSCRIPT,ef, scriptname, NULL);
}
inline void event_sys_register(eventfactory_t* restrict ef, const char* restrict ename, (void)(*event)(char*))
{
	event_register(EVENTSYS,ef, ename, event);
}
inline void event_user_register(eventfactory_t* restrict ef, const char* restrict ename, (void)(*event)(char*))
{
	event_register(EVENTUSER,ef, ename, event);
}
/* registered app event */
void event_test_sys(void* arg)
{
	printf("%s\n",__func__);
}
void event_test_user(void* arg)
{
	printf("%s\n",__func__);
}


