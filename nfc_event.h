#ifndef __NFC_EVENT_H__
#define __NFC_EVENT_H__
#include "stringbuffer.h"
#include "util.h"
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
	void* base; /* libevent base */
}nfc_t;

struct _event{
	void* priv; /* event specific pointer */	
	stringbuffer_t *del_cmd ; /* buffer for event to use */
	const event_info_t* info;
	int id_pool;              /* starts from 1024 */
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



#endif






