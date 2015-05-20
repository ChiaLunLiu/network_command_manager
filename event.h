#ifndef __EVENT_H__
#define __EVENT_H__
#include "linkedlist.h"
#define EVENTSCRIPT 0
#define EVENTSYS    1
#define EVENTUSER   2
typedef struct _event{
	int type;
	char* name; /* event name */
	void(*task)(void*);
	char *buf ; /* buffer for event to use */
}event_t;
typedef struct _EventFactory{
	list_t* eventlist;
	list_t* list_sys;
	list_t* list_user;
	list_t* list_script;
}eventfactory_t;

event_t* event_alloc();
void event_init(const event_t* __restrict__ e);


void eventfactory_init(eventfactory_t *__restrict__ ef);
void event_register(eventfactory_t* __restrict__ ef, const char*  ename, void(*event)(char*) );
void event_find(eventfactory_t* __restrict__ ef, const char* __restrict__ ename);

void event_script_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(char*));
void event_sys_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(char*));
void event_user_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(char*));
#endif





