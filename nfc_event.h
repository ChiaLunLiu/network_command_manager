#ifndef __NFC_EVENT_H__
#define __NFC_EVENT_H__
#include "stringbuffer.h"
#include <minimsg/minimsg.h>
#include <limits.h>

#define EBT_FILTER_INPUT 	0
#define EBT_FILTER_OUTPUT 	1
#define EBT_FILTER_FORWARD 	2
#define EBT_NAT_PREROUTING 	3
#define EBT_NAT_OUTPUT 		4
#define EBT_NAT_POSTROUTING 	5
#define EBT_BROUTE_BROUTING 	6
#define IPT_FILTER_INPUT 	7
#define IPT_FILTER_OUTPUT 	8
#define IPT_FILTER_FORWARD 	9
#define IPT_NAT_INPUT 		10
#define IPT_NAT_OUTPUT 		11
#define IPT_NAT_PREROUTING 	12
#define IPT_NAT_POSTROUTING 	13
#define IPT_MANGLE_INPUT 	14
#define IPT_MANGLE_OUTPUT 	15
#define IPT_MANGLE_FORWARD 	16
#define IPT_MANGLE_PREROUTING 	17
#define IPT_MANGLE_POSTROUTING 	18
#define IPT_RAW_PREROUTING 	19
#define IPT_RAW_OUTPUT 		20
#define MAX_CHAIN 		21


#define NO_PRIORITY INT_MAX


struct _event;
typedef struct _event event_t;

typedef struct _timer_data{
	int fd;
	event_t* ev;
	msg_t* m;
	
}timer_data_t;

typedef struct _event_info{
	const char* event_name;
	void( *task)(event_t* ev,const msg_t* m);
	int priority[MAX_CHAIN];
}event_info_t;

typedef struct _network_function_center{
	list_t* list_event;
	/* element is of type (event_t*,number of rule in the table) */
	list_t* chain[MAX_CHAIN];
	list_t*	list_other_rule;	/* keep ip, route cmd */
	list_t* list_timer; /* element is of type (timerfd, event_t*, msg_t* m) */	
	int id_pool; /* only increase , assume that it won't overflow */
	int efd; /* epoll fd */
}nfc_t;

struct _event{
	stringbuffer_t *del_cmd ; /* buffer for event to use */
	const event_info_t* info;
	nfc_t* center;
};

/*--------------------------
 *
 *   NFC
 *
 *--------------------------
 */
nfc_t* nfc_create();
void nfc_free(nfc_t* center);

/*--------------------------
 *
 *   others
 *
 *--------------------------
 */
void nfc_msg_process(nfc_t* center,msg_t* m);


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






