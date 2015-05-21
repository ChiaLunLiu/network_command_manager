
#include "event.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



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
	e->cms_key = NULL;
}
void eventfactory_init(eventfactory_t *__restrict__ ef)
{
	ef->list_script = list_alloc();
	ef->list_user   = list_alloc();
	ef->list_sys    = list_alloc();
}

void event_register(int type,eventfactory_t* __restrict__ ef, const char*  __restrict__ ename, void(*task)(void*),const char* cms_key)
{
		event_t* ev = event_alloc();
		event_init(ev);
		ev->name = strdup(ename);
		ev->task = task;
		ev->type = type;
		ev->cms_key = cms_key;
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
	char* value;
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
			if(ev->cms_key){
				value = cms_get_value(ev->cms_key);
				if(!value){
						dbg("cms value not found\n");
				}
				else if(!strcmp(value,"enable") ) ev->task(ev);
			}
		break;
		default:
			printf("undefined type\n");
		break;
	}
}
inline void event_script_register(eventfactory_t* __restrict__ ef, const char* __restrict__ scriptname, const char*  cms_key)
{
	event_register(EVENTSCRIPT,ef, scriptname, NULL,cms_key);
}
inline void event_sys_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(void*), const char*  cms_key)
{
	event_register(EVENTSYS,ef, ename, event,cms_key);
}
inline void event_user_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(void*), const char*  cms_key)
{
	event_register(EVENTUSER,ef, ename, event,cms_key);
}
/* registered app event */

void app_dhcp(event_t* arg)
{
	/* dmz enable */
	char* sys_firewall = NULL;
	char* ui_dmz_enable = NULL;
	char* sys_dnsmasq = NULL;
	char* sys_ext_if = NULL;
	char* sys_lan_if = NULL;
	int mode;
	
	/* get all cms key */
	//TODO
	
	arg->buf = stringbuffer_alloc();
	
	if(!arg->buf){
		dbg("malloc fails\n");
		return ;
	}
	
	mode = get_current_mode();
	if (!strcmp(sys_firewall,"enable") ){
		system("iptables -A INPUT -p udp --dport 67 -j ACCEPT;"
			   "iptables -A INPUT -p udp --dport 68 -j ACCEPT;");
		stringbuffer_add_f(arg->buf,"iptables -D INPUT -p udp --dport 67 -j ACCEPT;"
							  "iptables -D INPUT -p udp --dport 68 -j ACCEPT;");
	}
	
	switch(mode){
		case NAT:
		if( !strcmp(sys_dmz_enable,"enable")){
			systemf("iptables -t nat -A PREROUTING -i %s -p udp --dport 68 -j ACCEPT",sys_ext_if);
			stringbuffer_add_f(arg->buf,"iptables -t nat -D PREROUTING -i %s -p udp --dport 68 -j ACCEPT",sys_ext_if);
		}
		break;

		case BRIDGE:
			if (!strcmp(sys_firewall,"enable") ){
				systemf("iptables -t raw -A PREROUTING -i %s -p udp --dport 68 -j ACCEPT;"
				"ebtables -A FORWARD -i %s -p 0x0800 --ip-protocol udp --ip-dport 67 --ip-sport 68 -j DROP",
				sys_ext_if, sys_lan_if);
				
				stringbuffer_add_f(arg->buf,"iptables -t raw -D PREROUTING -i %s -p udp --dport 68 -j ACCEPT;"
				"ebtables -D FORWARD -i %s -p 0x0800 --ip-protocol udp --ip-dport 67 --ip-sport 68 -j DROP",
				sys_ext_if, sys_lan_if);
			}
		break;
	}
}


