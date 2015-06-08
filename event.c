#include "testlib.h"
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
	e->switch_cms_key = NULL;
	e->list_related_cms_keys = list_alloc();
}
void eventfactory_init(eventfactory_t *__restrict__ ef)
{
	ef->list_script = list_alloc();
	ef->list_user   = list_alloc();
	ef->list_sys    = list_alloc();
}

void event_register(int type,eventfactory_t* __restrict__ ef, const char*  __restrict__ ename, void(*task)(event_t*),const char* cms_key,int num, va_list argptr)
{
	int i;
	char* str;
	va_list my_argptr;
	void * data;
	event_t* ev = event_alloc();
	event_init(ev);
	ev->name = strdup(ename);
	ev->task = task;
	ev->type = type;
	if(cms_key) ev->switch_cms_key = strdup(cms_key);
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

	va_copy (my_argptr, argptr);
	for (i = 0; i < num; i++){
		str = va_arg(valist, char*);
		data = strdup(str);
		if(str== NULL || data == NULL){
			handle_error("malloc or va_arg\n");	
		}
		list_add(ef->list_related_cms_keys, str,data);	
    	}
	va_end (my_argptr);	
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
				r=system(stringbuffer_get(ev->buf));
				stringbuffer_destroy(ev->buf);
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
inline void event_script_register(eventfactory_t* __restrict__ ef, const char* __restrict__ scriptname, const char*  cms_key,int num, ...)
{
	va_list argptr;
    	va_start (argptr, num);
	event_register(EVENTSCRIPT,ef, scriptname, NULL,cms_key,num,argptr);
	va_end (argptr);
}
inline void event_sys_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(event_t*), const char*  cms_key,int num , ...)
{
	
	va_list argptr;
    	va_start (argptr, num);
	event_register(EVENTSYS,ef, ename, event,cms_key,num,argptr);
	va_end (argptr);
}
inline void event_user_register(eventfactory_t* __restrict__ ef, const char* __restrict__ ename, void(*event)(event_t*), const char*  cms_key,int num, ...)
{
	va_list argptr;
    	va_start (argptr, num);
	event_register(EVENTUSER,ef, ename, event,cms_key,num,argptr);
	va_end (argptr);
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
	int r;
	/* get all cms key */
	//TODO
	
	arg->buf = stringbuffer_alloc();
	
	if(!arg->buf){
		dbg("malloc fails\n");
		return ;
	}
	
	mode = get_current_mode();
	if (!strcmp(sys_firewall,"enable") ){
		r=system("iptables -A INPUT -p udp --dport 67 -j ACCEPT;"
			   "iptables -A INPUT -p udp --dport 68 -j ACCEPT;");
		stringbuffer_add_f(arg->buf,"iptables -D INPUT -p udp --dport 67 -j ACCEPT;"
							  "iptables -D INPUT -p udp --dport 68 -j ACCEPT;");
	}
	
	switch(mode){

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

void app_dns(event_t* arg)
{
	char* sys_ext_if;
	arg->buf = stringbuffer_alloc();
	if(!arg->buf){
		dbg("malloc fails\n");
		return ;
	}
	stringbuffer_add_f(arg->buf,"iptables -A INPUT ! -i $_lv_EXTIF -p tcp --dport 53 -j ACCEPT;"
                		    "iptables -A INPUT ! -i $_lv_EXTIF -p udp --dport 53 -j ACCEPT");
}
void app_ntp(event_t* arg);
void app_http(event_t *arg);
void app_https(event_t* arg);
void app_telnet(event_t* arg);
void app_upnp(event_t*arg);
void app_voip(event_t* arg);

void dmz(event_t* arg)
{
	char* sys_ext_if=NULL;
	char* ui_dmz_enable;
	char* dhcp_enable; // TODO
	int mode;
	arg->buf = stringbuffer_alloc();
	/* get cms key */
	mode = get_current_mode();

	switch(mode){
		case NAT:
		if( !strcmp(dhcp_enable,"enable")){
			systemf("iptables -t nat -A PREROUTING -i %s -p udp --dport 68 -j ACCEPT",sys_ext_if);
			stringbuffer_add_f(arg->buf,"iptables -t nat -D PREROUTING -i %s -p udp --dport 68 -j ACCEPT",sys_ext_if);
		}
		break;
		default:
		break;
	}
		
}
