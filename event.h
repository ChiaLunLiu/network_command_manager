#ifndef __EVENT_H__
#define __EVENT_H__
#include "linkedlist.h"
#include "stringbuffer.h"
#define EVENTSCRIPT 0
#define EVENTSYS    1
#define EVENTUSER   2
typedef struct _event{
	int type;
	char* name; /* event name */
	char* cms_key; /* cms key that indicates on/off */
	void(*task)(void*);
	stringbuffer_t *buf ; /* buffer for event to use */
}event_t;
typedef struct _EventFactory{
	list_t* list_sys;
	list_t* list_user;
	list_t* list_script;
}eventfactory_t;

event_t* event_alloc();
void event_init( event_t* const  e);

void eventfactory_init(eventfactory_t *__restrict__ ef);
void event_process(eventfactory_t* __restrict__ ef, const char*  __restrict__ ename,int type,int is_on);
void event_script_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, const char*  cms_key);
void event_sys_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(void*), const char*  cms_key);
void event_user_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(void*), const char*  cms_key);

/* event */
void app_dhcp(event_t* arg);

#endif





