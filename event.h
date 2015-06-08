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
	char* switch_cms_key; /* cms key that indicates on/off */
	void(*task)(struct _event*);
	stringbuffer_t *buf ; /* buffer for event to use */

	/* cms variable that uses in the event 
	* note that variable switch_cms_key is different from these variables
         * switch_cms_key determines everything, when it is on, the event care about list_related_cms_keys
         * when it is off, the event ignore them.
         */ 
	list_t* list_related_cms_keys;
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
void event_sys_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(event_t*), const char*  cms_key);
void event_user_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(event_t*), const char*  cms_key);

/* event */
/* APP */
void app_dhcp(event_t* arg);
void app_dns(event_t* arg);
void app_ntp(event_t* arg);
void app_http(event_t *arg);
void app_https(event_t* arg);
void app_telnet(event_t* arg);
void app_upnp(event_t*arg);
void app_voip(event_t* arg);

void dmz(event_t* arg);
#endif





