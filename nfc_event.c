#include "nfc_event.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>



typedef struct _str_int_pair{
	const char* tool;
	const char* table;
	const char* chain;
	int value;
}str_int_pair_t;

typedef struct _drule{
	int id;
	event_t* ev;
	stringbuffer_t* del_cmd;
}del_rule_t;

/* del_rule_t function */
del_rule_t* del_rule_alloc();
void del_rule_free(del_rule_t* r);

/* declaration for event function */
static void mode_setup(event_t* ev,const msg_t* m);
static void nat(event_t* ev,const msg_t* m);
static void ip_passthrough(event_t* ev,const msg_t* m);
static void data_channel_setup(event_t* ev,const msg_t* m);
static void voice_channel_setup(event_t* ev,const msg_t* m);
static void mgmt_channel_setup(event_t* ev,const msg_t* m);
static void mgmt_dscp(event_t* ev,const msg_t* m);
static void data_dscp(event_t* ev,const msg_t* m);
static void voice_dscp(event_t* ev,const msg_t* m);
static void voice_dscp2(event_t* ev,const msg_t* m);

static void dscp_tagging_with_timeout(event_t* ev,const msg_t* m);
static void dhcp(event_t* ev,const msg_t* m);
static void dmz(event_t* ev,const msg_t* m);
static void udhcpc(event_t* ev,const msg_t* m);
static void ntp(event_t* ev,const msg_t* m);
static void oma(event_t* ev,const msg_t* m);
static void acs(event_t* ev,const msg_t* m);
static void snmp(event_t* ev,const msg_t* m);
static void dns(event_t* ev,const msg_t* m);
static void telnet(event_t* ev,const msg_t* m);
static void upnp(event_t* ev,const msg_t* m);
static void pots(event_t* ev,const msg_t* m);
static void http(event_t* ev,const msg_t* m);
static void https(event_t* ev,const msg_t* m);
static void access_restriction(event_t* ev,const msg_t* m);
static void vpn_passthrough(event_t* ev,const msg_t* m);
static void multicast_filter(event_t* ev,const msg_t* m);
static void user_specified_filter(event_t* ev,const msg_t* m);
static void ping_filter(event_t* ev,const msg_t* m);
static void igmp_filter(event_t* ev,const msg_t* m);
static void dynamic_qos(event_t* ev,const msg_t* m);
static void port_trigger(event_t* ev,const msg_t* m);
static void port_forwarding(event_t* ev,const msg_t* m);
static void vlan_tagging(event_t* ev,const msg_t* m);
static void static_routing(event_t* ev,const msg_t* m);
static void mss_clamping(event_t* ev,const msg_t* m);
static void snat(event_t* ev,const msg_t* m);
static void interface_basic_setup(event_t* ev,const msg_t* m);
static void clean_all(event_t* ev,const msg_t* m);
static void data_route(event_t* ev,const msg_t* m);
static void voice_route(event_t* ev,const msg_t* m);
static void voice_route2(event_t* ev,const msg_t* m);
static void mgmt_vlan(event_t* ev,const msg_t* m);
static void data_vlan(event_t* ev,const msg_t* m);
static void voice_vlan(event_t* ev,const msg_t* m);
static void voice_vlan2(event_t* ev,const msg_t* m);

static void add_timer(event_t* ev,msg_t* m,int timeout_value);


/* variable defination */
/* the smaller value,the higher priority */
static const event_info_t event_info[]={
{"mode setup",mode_setup,	 	   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"nat",nat,		         	   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0,-1,0,0, 0,0,0,0,0} },
{"ip passthrough",ip_passthrough,	   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"data channel setup",data_channel_setup,  		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"voice channel setup",voice_channel_setup,		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"mgmt dscp",mgmt_dscp,			   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"data dscp",data_dscp,			   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 1,0,0,0,0} },
{"voice dscp",voice_dscp,		   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 2,0,0,0,0} },
{"voice dscp2",voice_dscp2,		   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 2,0,0,0,0} },
{"dscp tagging with timeout",dscp_tagging_with_timeout, {0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"dmz",dmz,			   			{0,0, 0, 0,0, 0,0,0,0,0,0,0,10, 0,0,0, 0,0,0,0,0} },
{"dhcp",dhcp,			   			{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"udhcpc",udhcpc,			   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"ntp",ntp,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"oma",oma,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"acs",acs,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"snmp",snmp,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"dns",dns,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"telnet",telnet,			   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"upnp",upnp,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"pots",pots,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"http",http,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"https",https,				   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"access restriction",access_restriction,   		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"vpn passthrough",vpn_passthrough,   			{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"multicast filter",multicast_filter,  			{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"user-specified filter",user_specified_filter,		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"ping filter",ping_filter,	  			{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"igmp filter",igmp_filter,	  			{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"dynamic qos",dynamic_qos,	  			{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"port trigger",port_trigger,	  			{0,0,-1, 0,0, 0,0,0,0,0,0,0, 9, 0,0,0, 0,0,0,0,0} },
{"port forwarding",port_forwarding,  			{0,0,-1, 0,0, 0,0,0,0,0,0,0, 8, 0,0,0, 0,0,0,0,0} },
{"vlan tagging",vlan_tagging,	  			{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"static routing",static_routing,  			{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"mss_clamping",mss_clamping,  				{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0,-1,0,0,0,0} },
{"mgmt channel setup",mgmt_channel_setup,		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"snat",snat,						{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"interface basic setup",interface_basic_setup,		{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"clean all",clean_all,					{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"data route",data_route,				{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"voice route",voice_route,				{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"voice route2",voice_route2,				{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,0, 0,0,0,0,0} },
{"mgmt vlan",mgmt_vlan,					{0,0, 0,-1,0,10,0,0,0,0,0,0, 0, 0,0,1, 0,0,0,0,0} },
{"data vlan",data_vlan,					{0,0, 0,-1,0,10,0,0,0,0,0,0, 0, 0,0,0, 0,0,1,0,0} },
{"voice vlan",voice_vlan,				{0,0, 0,-1,0,10,0,0,0,0,0,0, 0, 0,0,2, 0,0,2,0,0} },
{"voice vlan2",voice_vlan2,				{0,0, 0, 0,0, 0,0,0,0,0,0,0, 0, 0,0,2, 0,0,2,0,0} },
};

str_int_pair_t chain_mapping[]={
 {"ebtables","filter",	"INPUT",	EBT_FILTER_INPUT},
 {"ebtables","filter",	"OUTPUT",	EBT_FILTER_OUTPUT},
 {"ebtables","filter",	"FORWARD",	EBT_FILTER_FORWARD},
 {"ebtables","nat",	"PREROUTING",	EBT_NAT_PREROUTING},
 {"ebtables","nat",	"OUTPUT",	EBT_NAT_OUTPUT},
 {"ebtables","nat",	"POSTROUTING",	EBT_NAT_POSTROUTING},
 {"ebtables","broute",	"BROUTING",	EBT_BROUTE_BROUTING},
 {"iptables","filter",	"INPUT",	IPT_FILTER_INPUT},
 {"iptables","filter",	"OUTPUT",	IPT_FILTER_OUTPUT},
 {"iptables","filter",	"FORWARD",	IPT_FILTER_FORWARD},
 {"iptables","nat",	"INPUT",	IPT_NAT_INPUT},
 {"iptables","nat",	"OUTPUT",	IPT_NAT_OUTPUT},
 {"iptables","nat",	"PREROUTING",	IPT_NAT_PREROUTING},
 {"iptables","nat",	"POSTROUTING",	IPT_NAT_POSTROUTING},
 {"iptables","mangle",	"INPUT",	IPT_MANGLE_INPUT},
 {"iptables","mangle",	"OUTPUT",	IPT_MANGLE_OUTPUT},
 {"iptables","mangle",	"FORWARD",	IPT_MANGLE_FORWARD},
 {"iptables","mangle",	"PREROUTING",	IPT_MANGLE_PREROUTING},
 {"iptables","mangle",	"POSTROUTING",	IPT_MANGLE_POSTROUTING},
 {"iptables","raw",	"PREROUTING",	IPT_RAW_PREROUTING},
 {"iptables","raw",	"OUTPUT",	IPT_RAW_OUTPUT},
};

static event_t * event_search(nfc_t* center,const char* name);

static int chain_str_to_int(const char* tool,const char* table, const char* chain);
static int add_ip_rule(event_t* ev,const char* tool,const char *format, ...);
static void add_ip_rule_and_id(event_t* ev,int id,const char* tool,const char *format, ...);
static int _add_ip_rule_and_id(event_t* ev,int id,const char* tool,const char *format, va_list in_argptr);

static int  add_netfilter_rule(event_t* ev,const char* tool, const char* table, const char* chain, const char *format, ...);
static void  add_netfilter_rule_and_id(event_t* ev,int id,const char* tool, const char* table, const char* chain, const char *format, ...);
static int  _add_netfilter_rule_and_id(event_t* ev,int id,const char* tool, const char* table, const char* chain, const char *format, va_list in_argptr);

static void del_rule_by_id(event_t* ev,int id);
static void del_rule_by_event(event_t* ev);

void show_all_rule(const nfc_t* center);


void show_all_rule(const nfc_t* center)
{
	
	list_t* list;
	list_iterator_t* it;
	list_node_t* prev, * ln;
	const char* cmd;
	int i;
	int j;
	del_rule_t* r;
	int dummy;
	nfc_dbg("\n");
	for(i=0;i< MAX_CHAIN ; i++){
    		it = list_iterator_new(center->chain[i], LIST_HEAD);
		prev = list_iterator_next(it);
		for(j=0;j < MAX_CHAIN;j++){
			if(chain_mapping[j].value == i){
				nfc_dbg("in table %s %s %s\n",chain_mapping[j].tool,chain_mapping[j].table,chain_mapping[j].chain);
				break;
			}
		}
    		while(prev){
			ln = list_iterator_next(it);
			r = (del_rule_t*) prev->val;
			nfc_dbg("%s\n",stringbuffer_get(r->del_cmd));
			prev = ln;
		}
    		list_iterator_destroy(it);
    	}
	/* list_other_rule keeps, ip, route del cmd */
    	it = list_iterator_new(center->list_other_rule, LIST_HEAD);
	prev = list_iterator_next(it);
    	while(prev){
		ln = list_iterator_next(it);
		r = (del_rule_t*) prev->val;
		nfc_dbg("%s\n", stringbuffer_get(r->del_cmd));
		prev= ln;
	}
    	list_iterator_destroy(it);
}
/*
 * del_rule_by_id
 * delete iptables, ebtables rule by id
 *
 */
static void del_rule_by_id(event_t* ev,int id)
{
	nfc_t* center;
	list_t* list;
	list_iterator_t* it;
	list_node_t* prev, * ln;
	const char* cmd;
	del_rule_t* r;
	int i;
	int j;
	int dummy = 0;
	int has_deleted=0;
	nfc_dbg("\n");
	center = ev->center;
	/* chain[i] keeps iptables, ebtables del cmd */
	for(i=0;i< MAX_CHAIN ; i++){
    		it = list_iterator_new(center->chain[i], LIST_HEAD);
		prev = list_iterator_next(it);
    		while(prev){
			ln = list_iterator_next(it);
			r = (del_rule_t*) prev->val;
			if( r->id == id && r->ev == ev){
				list_remove(center->chain[i],prev);
				cmd = stringbuffer_get(r->del_cmd);
				nfc_dbg("delete rule: %s\n",cmd);
				dummy=system(cmd);
				del_rule_free(r);
				has_deleted++;
			}
			prev = ln;
		}
    		list_iterator_destroy(it);
    	}

	/* list_other_rule keeps, ip, route del cmd */
    	it = list_iterator_new(center->list_other_rule, LIST_HEAD);
	prev = list_iterator_next(it);
    	while(prev){
		ln = list_iterator_next(it);
		r = (del_rule_t*) prev->val;
		if( r->id == id && r->ev == ev){
			list_remove(center->list_other_rule,prev);
			cmd = stringbuffer_get(r->del_cmd);
			nfc_dbg("delete rule: %s\n",cmd);
			dummy=system(cmd);
			del_rule_free(r);
			has_deleted++;
		}
		prev= ln;
	}
    	list_iterator_destroy(it);
	
	
	if(has_deleted == 0) nfc_dbg("delete noting\n");
	else nfc_dbg("delete %d rules\n", has_deleted);
}
/*
 * del_rule_by_event
 * go through all list in center and remove the rules if its corresponding event matches the one
 * to delete   
 */
static void del_rule_by_event(event_t* ev)
{
	list_t* list;
	list_iterator_t* it;
	list_node_t* prev, * ln;
	nfc_t* center;
	const char* cmd;
	int i;
	int j;
	del_rule_t* r;
	int dummy;
	nfc_dbg("delete rules of %s\n",ev->info->event_name);
	center = ev->center;
	for(i=0;i< MAX_CHAIN ; i++){
    		it = list_iterator_new(center->chain[i], LIST_HEAD);
		prev = list_iterator_next(it);
		for(j=0;j < MAX_CHAIN;j++){
			if(chain_mapping[j].value == i){
				nfc_dbg("in table %s %s %s\n",chain_mapping[j].tool,chain_mapping[j].table,chain_mapping[j].chain);
				break;
			}
		}
    		while(prev){
			ln = list_iterator_next(it);
			r = (del_rule_t*) prev->val;
			if( r->ev == ev ){
				list_remove(center->chain[i],prev);
				cmd = stringbuffer_get(r->del_cmd);
				nfc_dbg("delete rule: %s\n",cmd);
				dummy=system(cmd );
				del_rule_free(r);
			}
			prev = ln;
		}
    		list_iterator_destroy(it);
    	}
	/* list_other_rule keeps, ip, route del cmd */
    	it = list_iterator_new(center->list_other_rule, LIST_HEAD);
	prev = list_iterator_next(it);
    	while(prev){
		ln = list_iterator_next(it);
		r = (del_rule_t*) prev->val;
		if( r->ev == ev){
			list_remove(center->list_other_rule,prev);
			cmd = stringbuffer_get(r->del_cmd);
			nfc_dbg("delete rule: %s\n",cmd);
			dummy=system(cmd);
			del_rule_free(r);
			dummy = 1;
		}
		prev= ln;
	}
    	list_iterator_destroy(it);

}
static int add_ip_rule(event_t* ev,const char* tool,const char *format, ...)
{
	int id;
	va_list argptr;
	va_start (argptr, format);
	id =_add_ip_rule_and_id(ev,-1,tool,format, argptr);
	va_end (argptr);
	return id;
}
static void add_ip_rule_and_id(event_t* ev,int id,const char* tool,const char *format, ...)
{
	int dummy;
	va_list argptr;
	va_start (argptr, format);
	dummy = _add_ip_rule_and_id(ev,id,tool,format, argptr);
	va_end (argptr);
}
static int _add_ip_rule_and_id(event_t* ev,int id,const char* tool,const char *format, va_list in_argptr)
{
	char* string;
	va_list argptr;
	del_rule_t* r;
	list_node_t* ln;
	nfc_dbg("\n");
	r = del_rule_alloc();
	ln = list_node_new(r);
	if(!ln) nfc_handle_error("list_node_new");
	if(id == -1) r->id = (ev->id_pool++);
	else   r->id = id;
	r->ev = ev;
    	va_copy (argptr, in_argptr);
    	string = zsys_vprintf (format, argptr);
    	va_end (argptr);
	if(!string) nfc_handle_error("null string");
	nfc_dbg("ip %s add %s\n",tool,string);
	systemf("ip %s add %s",tool,string);
	
    	stringbuffer_add_f(r->del_cmd,"ip %s del %s",tool,string);
	list_rpush(ev->center->list_other_rule,ln);
	free(string);
	return r->id;

}

static int add_netfilter_rule(event_t* ev,const char* tool, const char* table, const char* chain, const char *format, ...)
{
    int id;
    va_list argptr;
    va_start (argptr, format);
    id =_add_netfilter_rule_and_id(ev,-1,tool,table,chain,format, argptr);
    va_end (argptr);
    return id;
}

static void add_netfilter_rule_and_id(event_t* ev,int id,const char* tool, const char* table, const char* chain, const char *format, ...)
{
    int dummy;
    va_list argptr;
    va_start (argptr, format);
    dummy = _add_netfilter_rule_and_id(ev,id,tool,table,chain,format, argptr);
    va_end (argptr);
	
}
static int  _add_netfilter_rule_and_id(event_t* ev,int id,const char* tool, const char* table, const char* chain, const char *format,  va_list in_argptr)
{
	va_list argptr;
	unsigned i;
	nfc_t* center;
	unsigned idx;
	unsigned sz;
	int cnt = 0;
	list_t* list;
	list_node_t* ln_new,*ln;
	list_iterator_t* it;
	int list_idx ;
	int insert_pos = -1;
	del_rule_t* dr;
	del_rule_t* tmp_dr;
	char* string;
	dbg("\n");

    	center = ev->center;
	dr = del_rule_alloc();
	if(!dr) nfc_handle_error("del_rule_alloc");
    	va_copy (argptr, in_argptr);
    		string = zsys_vprintf (format, argptr);
    	va_end (argptr);
    	if(!string) nfc_handle_error("rules_changed");

    	sz = sizeof(chain_mapping);
    	for(i=0;i< sz ; i++){
		if(!strcmp(chain_mapping[i].tool,tool) && !strcmp(chain_mapping[i].table,table) && !strcmp(chain_mapping[i].chain,chain) ){
			break;
		}
    	}
    	if(i == sz) nfc_handle_error("fail to find mapping for (%s,%s,%s)\n",tool,table,chain);
	list_idx = chain_mapping[i].value;
    	list = center->chain[ list_idx ];
	
    	it = list_iterator_new(list, LIST_HEAD);

    	while(ln = list_iterator_next(it) ){
		tmp_dr = (del_rule_t*)ln->val;

		if(ev->info->priority[list_idx] < tmp_dr->ev->info->priority[list_idx]){
			/* add it here */
			insert_pos = cnt;
        		printf("insert before: %s\n",stringbuffer_get(tmp_dr->del_cmd));
			break;			
		} 
		cnt++;
    	}
    	list_iterator_destroy(it);

        ln_new = list_node_new(dr);
	if(!ln_new) nfc_handle_error("list_node_new");
        nfc_dbg("insert pos : %d\n",insert_pos);
    	if(insert_pos == -1){
		insert_pos = cnt;
		list_rpush(list,ln_new);
	}
	else
		list_insert(list,ln,ln_new);

	
    	systemf("%s -t %s -I %s %d %s",tool,table,chain,insert_pos+1,string);
    	nfc_dbg("%s -t %s -I %s %d %s\n",tool,table,chain,insert_pos+1,string);

    	stringbuffer_add_f(dr->del_cmd,"%s -t %s -D %s %s",tool,table,chain,string);
	dr->ev = ev;	
	if(id == -1) dr->id = (ev->id_pool++);
	else         dr->id = id;
    	free(string);
	return id;

}
nfc_t* nfc_create()
{
	nfc_t* center;
	unsigned i,sz;
	list_node_t* ln;
        event_t* ev;
	event_t* tmp_ev1,*tmp_ev2;
	center = malloc( sizeof( nfc_t));

	if(!center) nfc_handle_error("malloc");
	
	center->list_event = list_new();
	if(!center->list_event) nfc_handle_error("list_new");


	center->list_other_rule = list_new();
	if(!center->list_other_rule) nfc_handle_error("list_new");

	center->base = event_base_new();
	
	if(!center->base)nfc_handle_error("event_base_new");

	for(i = 0 ;i < MAX_CHAIN;i++){
		center->chain[i] = list_new();
		if(!center->chain[i]) nfc_handle_error("list_new");
	}
	/* register event */
	sz = sizeof(event_info)/sizeof(event_info_t);
	nfc_dbg("sz = %d\n",sz);
	for(i = 0 ;i < sz ; i++){
        	ev = malloc(sizeof( event_t));
        	if(!ev) nfc_handle_error("malloc");
        	ev->del_cmd = stringbuffer_alloc();
		if(!ev->del_cmd) nfc_handle_error("stringbuffer_create fails\n");
        	ev->center = center;
        	ev->info = &event_info[i];
		ev->id_pool = 1024;
        	ln = list_node_new(ev);
        	if(!ln) nfc_handle_error("list_node_new");
        	list_rpush(center->list_event,ln);
		
		/* special handling for some event */
		if(!strcmp(ev->info->event_name,"dscp tagging with timeout")){
			/* mapping list of (ip,port) => timer_event */
			ev->priv = (void*)list_new();
			if(!ev->priv) nfc_handle_error("list_new");
		}
        }
	/* special handling */
	/* bind voice dscp2 to voice dscp */
	tmp_ev1 = event_search(center,"voice dscp");
	tmp_ev2 = event_search(center,"voice dscp2");
	if(tmp_ev1 == NULL || tmp_ev2 == NULL) nfc_handle_error("voice dscp or voice dscp2 event does not exist");
	tmp_ev1->priv = (void*)tmp_ev2;
	/* bind voice vlan2 to voice vlan */
	tmp_ev1 = event_search(center,"voice vlan");
	tmp_ev2 = event_search(center,"voice vlan2");
	if(tmp_ev1 == NULL || tmp_ev2 == NULL) nfc_handle_error("voice vlan or voice vlan2 event does not exist");
	tmp_ev1->priv = (void*)tmp_ev2;
	/* bind voice route2 to voice route */
	tmp_ev1 = event_search(center,"voice route");
	tmp_ev2 = event_search(center,"voice route2");
	if(tmp_ev1 == NULL || tmp_ev2 == NULL) nfc_handle_error("voice route or voice route2 event does not exist");
	tmp_ev1->priv = (void*)tmp_ev2;
	
	return center;

}
void nfc_free(nfc_t* center)
{
	unsigned i;
	event_t* ev;
	list_node_t* ln;
	while( ln = list_lpop(center->list_event)){
		ev = (event_t*) ln->val;
		stringbuffer_destroy(ev->del_cmd);
		free(ln);
	}
	for(i=0; i< MAX_CHAIN;i++){
		list_destroy(center->chain[i]);
	}
	//TODO
	// destroy dscp tagging with timeout
	free(center->list_other_rule);
	free(center->list_event);
	event_base_free(center->base);
	free(center);
}




event_t * event_search(nfc_t* center,const char* name)
{
	list_node_t* ln;
	list_iterator_t * it;
	event_t* ev;
	it = list_iterator_new(center->list_event, LIST_HEAD);
        while(ln = list_iterator_next(it) ){
		ev = (event_t*)ln->val;
		if(!strcmp(ev->info->event_name,name)){
			return ev;
		}
        }
	return NULL;
}
/*
 * nfc_msg_process
 * handler that process the message
 * INPUT ARG
 *	m: message to process
 */
void nfc_msg_process(nfc_t* center,msg_t* m)
{
	event_t* ev;
	char* value;
	char* cmd;
	int len;
	int r;
	int fnum;
	const char* name;
	fnum = msg_number_of_frame(m);
	if(fnum == 0){
		fprintf(stderr,"receive message with 0 frames\n");
		return;
	}
        name=msg_content_at_frame(m,0);
	ev = event_search(center ,name);
	if(!ev){
		fprintf(stderr,"event %s not found\n",name);
		return;
	}
	nfc_dbg("process event %s\n",name);

	ev->info->task(ev,m);
}	
/* registered app event */
void mode_setup(event_t* ev, const msg_t* m)
{
	const char* network_mode;
	const char* radio_interface;
	const char* vendor;
	nfc_t* center;
	
	nfc_dbg("\n");
	del_rule_by_event(ev);
	center = ev->center;
	network_mode = msg_content_at_frame(m,1);
	radio_interface = msg_content_at_frame(m,2);
	
	if(!strcmp(network_mode,"NAT")){
		add_netfilter_rule(ev,"iptables","nat","POSTROUTING","-o %s -j MASQUERADE",radio_interface);
	}
	else if(!strcmp(network_mode,"BRIDGE")){
	
		vendor = msg_content_at_frame(m,3);
		/* SQN THP packet */
		if(!strcmp(vendor,"sqn")) 
			add_netfilter_rule(ev,"ebtables","broute","BROUTING","-i %s --dst 00:16:08:ff:00:01 -j DROP",radio_interface);
	}
}

/*
 * nat
 * add MASQUERADE rule
 */
static void nat(event_t* ev,const msg_t* m)
{
	int num,i;
	const char* interface;
	nfc_t* center;

	center = ev->center; 
	del_rule_by_event(ev);
	num = atoi( msg_content_at_frame(m,1));

	/* frame number checking */
	if( msg_number_of_frame(m) != (num + 2)){
		nfc_dbg("early return due to inconsistent frame (%d,%d)\n",msg_number_of_frame(m) ,num+2);
		return;
	}
	nfc_dbg("num: %d\n",num);
	for(i=0;i<num;i++){
		interface = msg_content_at_frame(m,2+i);
		nfc_dbg("interface: %s\n",interface);
		add_netfilter_rule(ev,"iptables","nat","PREROUTING","-o %s -j MASQUERADE",interface);	
	}
}

/*
 * ip_passthrough
 * enable/disable ip passthrough 
 */
static void ip_passthrough(event_t* ev,const msg_t* m)
{
	int num;
	const char* op;
	num = msg_number_of_frame(m);
	int dummy = -1;
	nfc_dbg("\n");
	op = msg_content_at_frame(m,1);
	if(!strcmp(op,"start")){
		nfc_dbg("ip-passthrough.sh start\n");
		dummy=system("ip-passthrough.sh start");
	}
	else if(!strcmp(op,"stop")){
		nfc_dbg("ip-passthrough.sh stop\n");
		dummy=system("ip-passthrough.sh stop");
	}
	else if(!strcmp(op,"restart")){
		nfc_dbg("ip-passthrough.sh restart\n");
		dummy=system("ip-passthrough.sh restart");
	}
	nfc_dbg("execution result of ip-passthrough.sh = %d\n",dummy);
}
static void data_channel_setup(event_t* ev,const msg_t* m)
{
/*	int enable;
	int should_broute;
	int table_id;
	const char* ims;
	const char* gw;
	const char* data_incoming_interface;
	int number_of_route;
	const char* data_route;
	const char* data_interface;
	const char* data_interface_ip;
	int dns_num;
	const char* dns;
	int i;
	nfc_dbg("\n");

	del_rule_by_event(ev);

	enable = atoi(msg_content_at_frame(m,1));

	if(!enable){
		return ;
	}

	
	should_broute = atoi( msg_content_at_frame(m,2));
	table_id = atoi(msg_content_at_frame(m,3));
	ims = msg_content_at_frame(m,4);
	gw =  msg_content_at_frame(m,5);
	data_incoming_interface = msg_content_at_frame(m,6);
	data_outgoing_interface = msg_content_at_frame(m,7);
	ip =  msg_content_at_frame(m,8);
	dns_num = atoi(msg_content_at_frame(m,9));
	nfc_dbg("cid = %d\n",cid);
*/
	/* policy routing */
	/* ims */
//	if(strcmp(ims,"")) add_ip_rule(ev,"rule","to %s table %d",ims,cid);
	/* dns */
//	for(i=0;i<dns_num;i++){
//		dns = msg_content_at_frame(m,10+i);
//		add_ip_rule(ev,"rule","to %s table %d",dns,cid);
//	}
	/* data */
//	add_ip_rule(ev,"rule","iif %s table %d",data_incoming_interface,cid);
//	add_ip_rule(ev,"rule","iif %s table %d",data_outgoing_interface,cid);
	/* local with IP bound to data interface */
//	add_ip_rule(ev,"rule","from %s table %d",ip,cid);

	/* routing rule */
//	add_ip_rule(ev,"route","`getnet %s` dev %s table %d",data_incoming_interface,data_incoming_interface,cid);
//	add_ip_rule(ev,"route","default via  %s dev %s table %d",gw,data_outgoing_interface,cid);
	
	/* broute */
//	if(should_broute) add_netfilter_rule(ev,"broute","BROUTING","-i %s -j DROP",data_outgoing_interface);
		
	
}
static void voice_channel_setup(event_t* ev,const msg_t* m)
{
	const char* route_non_onboard_voice_packet;
	const char* voice_outgoing_interface;
	const char* voice_incoming_interface;
	const char* op;
	const char* ims;
	const char* dns;
	const char* ip;
	const char* gw;
	int dns_num;
	int num;
	int i,cid;
	int should_broute;
	int sip_server_port;
	dbg("\n");
	/* frame number checking */
	num = msg_number_of_frame(m);
	if(num < 2){
		nfc_dbg("early return due to frame < 2\n");
		return;
	}

	op = msg_content_at_frame(m,1);

	del_rule_by_event(ev);

	if(!strcmp(op,"0")){
		return ;
	}

	if(num <= 11 ){
		nfc_dbg("early return due to frames <= 11\n");
		return;
	}
	dns_num = atoi(msg_content_at_frame(m,11));
	
	if(num != dns_num + 12){
		nfc_dbg("early return due to inconsistent frame (%d,%d)\n",num,dns_num+12);
		return;
	}
	
	route_non_onboard_voice_packet = msg_content_at_frame(m,2);
	sip_server_port = atoi(msg_content_at_frame(m,3));
	should_broute = atoi( msg_content_at_frame(m,4));
	cid = atoi(msg_content_at_frame(m,5));
	ims = msg_content_at_frame(m,6);
	gw =  msg_content_at_frame(m,7);
	voice_incoming_interface = msg_content_at_frame(m,8);
	voice_outgoing_interface = msg_content_at_frame(m,9);
	ip =  msg_content_at_frame(m,10);
	/* policy routing */
	/* ims */
	if(strcmp(ims,"")) add_ip_rule(ev,"rule","from `getnet %s` to %s table %d;\n",voice_incoming_interface,ims,cid);
	/* dns */
	for(i=0;i<dns_num;i++){
		dns = msg_content_at_frame(m,11+i);
		add_ip_rule(ev,"rule","from `getnet %s` to %s table %d;\n",voice_incoming_interface,dns,cid);
	}
	/* incoming pkt to interface */
	add_ip_rule(ev,"rule","iif %s table %d;\n",voice_outgoing_interface,cid);
	/* local with IP bound to data interface */
	add_ip_rule(ev,"rule","from %s table %d;\n",ip,cid);

	/* routing rule */
	add_ip_rule(ev,"route","`getnet %s` dev %s table %d;\n",voice_incoming_interface,voice_outgoing_interface,cid);
	add_ip_rule(ev,"route","default via  %s dev %s table %d;\n",gw,voice_outgoing_interface,cid);
	
	/* broute */
	if(should_broute) add_netfilter_rule(ev,"broute","BROUTING","-i %s -j DROP;\n",voice_outgoing_interface);
	/* handle non-onboard voice pkt */
	add_netfilter_rule(ev,"mangle","PREROUTING","-i %s -p udp --sport %d -j NFQUEUE --queue-num 1;\n",voice_outgoing_interface,sip_server_port);
}
/* TODO 
 * set dscp-target ACCEPT
 */
static void mgmt_dscp(event_t* ev,const msg_t* m)
{
	int enable;
	const char* dscp_value;
	const char* interface;
	nfc_dbg("\n");
	del_rule_by_event(ev);
	enable	  = atoi(msg_content_at_frame(m,1));
	dscp_value= msg_content_at_frame(m,2);
	interface = msg_content_at_frame(m,3);
	if(enable) add_netfilter_rule(ev,"iptables","mangle","OUTPUT","-o %s -j DSCP --set-dscp %s",interface,dscp_value);
	
}
/* TODO 
 * set dscp-target ACCEPT
 */
static void data_dscp(event_t* ev,const msg_t* m)
{
	int enable;
	const char* dscp_value;
	const char* interface;
	nfc_dbg("\n");
	del_rule_by_event(ev);
	enable	  = atoi(msg_content_at_frame(m,1));
	dscp_value= msg_content_at_frame(m,2);
	interface = msg_content_at_frame(m,3);
	if(enable) add_netfilter_rule(ev,"iptables","mangle","FORWARD","-o %s -j DSCP --set-dscp %s",interface,dscp_value);
	
}
/*
 * voice_dscp
 * only handle forwarded packets
 * DSCP default target is CONTINUE, so NFC inserts rules of voice_dscp after rules of data_dscp
 */
static void voice_dscp(event_t* ev,const msg_t* m)
{
	int sip_dscp_enable;
	int rtp_dscp_enable;
	int rtcp_dscp_enable;
	const char* interface;
	const char* sip_protocol;
	const char* sip_dscp_value;
	const char* rtp_dscp_value;
	const char* rtcp_dscp_value;

	nfc_dbg("\n");
	del_rule_by_event(ev);
	
	sip_dscp_enable  	= atoi(msg_content_at_frame(m,1));
	rtp_dscp_enable  	= atoi(msg_content_at_frame(m,2));
	rtcp_dscp_enable  	= atoi(msg_content_at_frame(m,3));
	interface 		= msg_content_at_frame(m,4);
	sip_protocol 		= msg_content_at_frame(m,5);
	sip_dscp_value 		= msg_content_at_frame(m,6);
	rtp_dscp_value 		= msg_content_at_frame(m,7);
	rtcp_dscp_value 	= msg_content_at_frame(m,8);

	if(sip_dscp_enable){
		add_netfilter_rule(ev,"iptables","mangle","FORWARD","-o %s -p %s --dport 5060 -j DSCP --set-dscp %s",
		interface,sip_protocol,sip_dscp_value);
	}
	if(rtp_dscp_enable || rtcp_dscp_enable){
			add_netfilter_rule(ev,"iptables","mangle","FORWARD","-o %s -p %s --sport 5060 -j NFQUEUE --queue-num 0",
			interface,sip_protocol);
	}
	else{
		nfc_dbg("clear all rules of voice dscp2\n");
		del_rule_by_event((event_t*) ev->priv);
	}
	/* TODO
	 * pass the dscp and enable to packet_watcher
	 */

}
/*
 * voice_dscp2
 * only handle forwarded packets
 * DSCP default target is CONTINUE, so NFC inserts rules of voice_dscp2 after rules of data_dscp
 * called by packet_watcher
 */
static void voice_dscp2(event_t* ev,const msg_t* m)
{
	int enable;
	int id;
	int rtp_enable;
	int rtcp_enable;
	const char* interface;
	int rtp_dscp_value;
	int rtcp_dscp_value;
	const char* media_ip;
	int media_port;

	nfc_dbg("\n");

	
	enable  	= atoi(msg_content_at_frame(m,1));
	id  		= atoi(msg_content_at_frame(m,2));
	rtp_enable  	= atoi(msg_content_at_frame(m,3));
	rtcp_enable  	= atoi(msg_content_at_frame(m,4));
	interface 	= msg_content_at_frame(m,5);
	rtp_dscp_value 	= atoi(msg_content_at_frame(m,6));
	rtcp_dscp_value = atoi(msg_content_at_frame(m,7));
	media_ip 	= msg_content_at_frame(m,8);
	media_port 	= atoi(msg_content_at_frame(m,9));

	if(!enable){
		del_rule_by_id(ev,id);
		return;
	}


	if(rtp_enable){
		add_netfilter_rule_and_id(ev,id,"iptables","mangle","FORWARD","-o %s -p udp -s %s --sport %d -j DSCP --set-dscp %d",
		interface,media_ip,media_port,rtp_dscp_value);
	}
	if(rtcp_enable){
		add_netfilter_rule_and_id(ev,id,"iptables","mangle","FORWARD","-o %s -p udp -s %s --sport %d -j DSCP --set-dscp %d",
		interface,media_ip,media_port+1,rtcp_dscp_value);
	}

}
static void dscp_timeout_callback(int fd, short event, void *arg)
{
	msg_t* m;
	int rule_id;
	event_t* ev;
	nfc_t* center;
	msg_t* m_mapping;
	const char* media_ip;
	const char* media_port;
	list_iterator_t* it;
	list_node_t* ln;
	struct event* timer_event;
	int found = 0;
	nfc_dbg("\n");
	m = (msg_t*) arg;

	media_ip =  msg_content_at_frame(m,0);
	media_port =  msg_content_at_frame(m,1);
	ev = (event_t*) strtoul (msg_content_at_frame(m,2), NULL, 16);
	center = (nfc_t*) strtoul (msg_content_at_frame(m,3), NULL, 16);
	rule_id =  atoi(msg_content_at_frame(m,4));
	timer_event = (struct event*) strtoul (msg_content_at_frame(m,5), NULL, 16);

	nfc_dbg("id = %d\n",rule_id);
	nfc_dbg("timer event : %p\n",timer_event);
	del_rule_by_id(ev,rule_id);
	/*find the timer and  remove from list*/
	it = list_iterator_new((list_t*) ev->priv, LIST_HEAD);
        while(ln = list_iterator_next(it)){
		m_mapping = (msg_t*) ln->val;
		if(m_mapping == m){
			found = 1;
			break;
		}		
	}
	
        list_iterator_destroy(it);	

	if(!found) nfc_handle_error("(%s:%s) is not found in dscp timeout list\n",media_ip,media_port);
	list_remove((list_t*)ev->priv,ln);
	event_del(timer_event);
	event_free(timer_event);
	msg_free(m);	
}
static void dscp_tagging_with_timeout(event_t* ev,const msg_t* m)
{
	int enable;
	const char* protocol;
	const char* media_ip;
	const char* media_port;
	const char* dscp_value;
	const char* interface;
	int timeout_value;

	struct event* timer_event;
	msg_t* m_event,* m_mapping;
	nfc_t* center;
	struct timeval tv;
	int rule_id;
	list_node_t* ln;
	list_iterator_t* it;
	event_callback_fn cb;
	void* event_arg;
	int found = 0;
	nfc_dbg("\n");	
	center = ev->center;
	enable = atoi(msg_content_at_frame(m,1));
	protocol = msg_content_at_frame(m,2);
	media_ip = msg_content_at_frame(m,3);
	media_port = msg_content_at_frame(m,4);
	dscp_value = msg_content_at_frame(m,5);
	interface = msg_content_at_frame(m,6);
	timeout_value = atoi(msg_content_at_frame(m,7));


	/* search for repeated element */
	it = list_iterator_new((list_t*) ev->priv, LIST_HEAD);
        while(ln = list_iterator_next(it)){
		m_mapping = (msg_t*) ln->val;		
		if(!strcmp(media_ip,  msg_content_at_frame(m_mapping,0)) && 
		   !strcmp(media_port,msg_content_at_frame(m_mapping,1))){
			found = 1;
			break;
		}
	}
        list_iterator_destroy(it);	

	if(!enable){
		if(!found){
			nfc_dbg("(%s,%s) does not exist in dscp timeout list, maybe it was already timeout\n",media_ip,media_port);
			return;
		}
		nfc_dbg("disable dscp tagging for %s:%s\n",media_ip,media_port);		
		timer_event = (struct event*) strtoul (msg_content_at_frame(m_mapping,5), NULL, 16);
		cb = event_get_callback(timer_event);
		event_arg = event_get_callback_arg(timer_event);
		cb(0,0,event_arg);
		return;
	}
	
	tv.tv_sec = timeout_value;
	tv.tv_usec = 0;

	if(found){
		nfc_dbg("refresh the timer event for (%s:%s)\n",media_ip,media_port);
		timer_event = (struct event*) strtoul (msg_content_at_frame(m_mapping,5), NULL, 16);
		if(event_add(timer_event,&tv) == -1) nfc_handle_error("event_add");
		
	}
	else{
		nfc_dbg("create new timer event\n");
		rule_id = add_netfilter_rule(ev,"iptables","mangle","FORWARD","-o %s -p %s -d %s --dport %s -j DSCP --set-dscp %s",interface,protocol,media_ip,media_port,dscp_value);
		nfc_dbg("rule id : %d\n",rule_id);
		/* record timer_event by media ip and port */
		m_mapping = msg_alloc();
		if(!m_mapping) nfc_handle_error("msg_alloc");
        	timer_event = event_new(center->base,-1, EV_TIMEOUT,dscp_timeout_callback,(void*)m_mapping);
        	if(!timer_event)nfc_handle_error("event_new");

		msg_append_string(m_mapping,media_ip);
		msg_append_string(m_mapping,media_port);
		msg_append_string_f(m_mapping,"%p",ev);
		msg_append_string_f(m_mapping,"%p",center);
		msg_append_string_f(m_mapping,"%d",rule_id);
		msg_append_string_f(m_mapping,"%p",timer_event);
		ln = list_node_new(m_mapping);
		list_rpush((list_t*)ev->priv,ln);
        	if(event_add(timer_event,&tv)== -1) nfc_handle_error("event_add");
		nfc_dbg("timer event : %p\n",timer_event);
	}
}
/* del_rule_t function */
del_rule_t* del_rule_alloc()
{
	del_rule_t* r;
	r = (del_rule_t*) malloc(sizeof( del_rule_t));
	if(!r) nfc_handle_error("malloc");
	r->id = -1;
	r->ev = NULL;
	r->del_cmd = stringbuffer_alloc();
	if(!r->del_cmd) nfc_handle_error("stringbuffer_create fails\n");
	return r;
}
void del_rule_free(del_rule_t* r)
{
	stringbuffer_destroy(r->del_cmd);
	free(r);
}

/*
 * dmz
 */ 
static void dmz(event_t* ev,const msg_t* m)
{
	int i;
	int num;
	int enable;
	const char* interface;
	const char* lan_ip;
	msg_t* tmp_m;
	nfc_dbg("\n");
	num = atoi(msg_content_at_frame(m,1));

	del_rule_by_event(ev);
	
	for(i = 0 ;i <num ; i++){
		interface = msg_content_at_frame(m,2+2*i);
		lan_ip = msg_content_at_frame(m,3+2*i);
		 add_netfilter_rule(ev,"iptables","nat","PREROUTING","-i %s -j DNAT --to %s",interface,lan_ip); 	
	}
	
}
/*
 * dhcp
 */
static void dhcp(event_t* ev,const msg_t* m)
{
	nfc_dbg("\n");
	/* nothing to do */
}
/*
 * udhcp
 */
static void udhcpc(event_t* ev,const msg_t* m)
{
	int enable;

	nfc_dbg("\n");

	enable = atoi(msg_content_at_frame(m,1));

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 68 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p udp --dport 68 -j ACCEPT");
	

}
/*
 * ntp
 */
static void ntp(event_t* ev,const msg_t* m)
{
	int enable;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 123 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p udp --dport 123 -j ACCEPT");
	
}
/*
 * oma
 */
static void oma(event_t* ev,const msg_t* m)
{
	int enable;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 2948 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 7547 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p udp --dport 2948 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p tcp --dport 7547 -j ACCEPT");
}
/*
 * acs
 */
static void acs(event_t* ev,const msg_t* m)
{
	int enable;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 58603 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p tcp --dport 58603 -j ACCEPT");
}
/*
 * snmp
 */
static void snmp(event_t* ev,const msg_t* m)
{
	int enable;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 161 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p udp --dport 161 -j ACCEPT");
}
/*
 * dns
 */
static void dns(event_t* ev,const msg_t* m)
{
	int enable;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 53 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 53 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p udp --dport 53 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p tcp --dport 53 -j ACCEPT");
}
/*
 * telnet
 */
static void telnet(event_t* ev,const msg_t* m)
{
	int enable;
	int i;	
	int num;
	const char* interface;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));
	num = atoi( msg_content_at_frame(m,2));
	
	del_rule_by_event(ev);	
	if(!enable) return;

	for(i = 0 ;i<num ; i++){
		interface = msg_content_at_frame(m,3+i);
		add_netfilter_rule(ev,"iptables","nat","PREROUTING","-i %s -p tcp --dport 23 -j ACCEPT",interface);
		add_netfilter_rule(ev,"iptables","filter","INPUT","-i %s -p tcp --dport 23 -j ACCEPT",interface);
	}
}
/*
 * upnp
 */
static void upnp(event_t* ev,const msg_t* m)
{
	int enable;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 49152 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 1900 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p tcp --dport 49152 -j ACCEPT");
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p tcp --dport 1900 -j ACCEPT");
}
/*
 * pots
 * do nothing 
 */
static void pots(event_t* ev,const msg_t* m)
{
	nfc_dbg("\n");
}
/*
 * http
 */
static void http(event_t* ev,const msg_t* m)
{
	int enable;
	const char* port;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));
	port = msg_content_at_frame(m,2);

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport %s -j ACCEPT",port);
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p tcp --dport %s -j ACCEPT",port);
}
/*
 * https
 */
static void https(event_t* ev,const msg_t* m)
{
	int enable;
	const char* port;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));
	port = msg_content_at_frame(m,2);

	del_rule_by_event(ev);	
	if(!enable) return;

	add_netfilter_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport %s -j ACCEPT",port);
	add_netfilter_rule(ev,"iptables","filter","INPUT","-p tcp --dport %s -j ACCEPT",port);

}
/*
 * access restriction
 */
static void access_restriction(event_t* ev,const msg_t* m)
{
	int i;
	int num;
	const char* mac_address;
	const char* blocked_day;
	const char* blocked_starting_time;
	const char* blocked_ending_time;
	const char* blocked_url;
	const char* blocked_keyword;
	stringbuffer_t* stringbuf;
	nfc_dbg("\n");

	del_rule_by_event(ev);	
	
	stringbuf = stringbuffer_alloc();
	if(!stringbuf){
		
		nfc_dbg("fail to alloc stringbuf\n");
		return;
	}
	num = atoi(msg_content_at_frame(m,1));

	for(i = 0; i<num ; i++){
		stringbuffer_clear(stringbuf);

		mac_address = msg_content_at_frame(m,2+ 6*i);
		blocked_day = msg_content_at_frame(m,3+6*i);
		blocked_starting_time = msg_content_at_frame(m,4+6*i);
		blocked_ending_time = msg_content_at_frame(m,5+6*i);
		blocked_url = msg_content_at_frame(m,6+6*i);
		blocked_keyword = msg_content_at_frame(m,7+6*i);

		if(strcmp(mac_address,"")){
			stringbuffer_add_f(stringbuf,"-m mac --mac-source %s ",mac_address);
		}
		if(strcmp(blocked_day,"every day")){
			stringbuffer_add_f(stringbuf,"-m time --weekdays %s ",blocked_day);
		}
		if(strcmp(blocked_starting_time,"")){
			stringbuffer_add_f(stringbuf,"-m time --timestart %s --timestop %s ",blocked_starting_time, blocked_ending_time);
		}
		if(strcmp(blocked_url,"")){
			stringbuffer_add_f(stringbuf,"-m webstr --url %s ",blocked_url);
		}
		if(strcmp(blocked_keyword,"")){
			stringbuffer_add_f(stringbuf,"-m string --algo bm --string %s ",blocked_keyword);
		}	
		add_netfilter_rule(ev,"iptables","filter","FORWARD",stringbuffer_get(stringbuf));	
	}
	stringbuffer_destroy(stringbuf);
}
/*
 * vpn_passthrough
 */
static void vpn_passthrough(event_t* ev,const msg_t* m)
{
	int gre;
	int l2tp;
	int pppoe;
	int ipsec;
	int pptp;
	
	nfc_dbg("\n");
	gre   = atoi(msg_content_at_frame(m,1));
	l2tp  = atoi(msg_content_at_frame(m,2));
	pppoe = atoi(msg_content_at_frame(m,3));
	ipsec = atoi(msg_content_at_frame(m,4));
	pptp  = atoi(msg_content_at_frame(m,5));

	del_rule_by_event(ev);
	if(gre){
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-p gre -j DROP");
	}
	if(l2tp){
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-p udp --dport 1701 -j DROP");
	}
	if(pptp){
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-p tcp --dport 1723 -j DROP");
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-p gre -j DROP");
	}
	if(pppoe){
		/* TODO */
	}
	if(ipsec){
		/* IKE negotiation */
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-p udp --dport 500 -j DROP");
		/* ESP encryption and authentication */
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-p 50 -j DROP");
		/* AU authentication */
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-p 51 -j DROP");
	}
}
/*
 * multicast filter
 */
static void multicast_filter(event_t* ev,const msg_t* m)
{
	int i;
	int num;
	const char* interface;	
	nfc_dbg("\n");
	num = atoi( msg_content_at_frame(m,1) );

	del_rule_by_event(ev);
	for(i = 0 ;i <num ; i++){
		interface = msg_content_at_frame(m,2+i);
		add_netfilter_rule(ev,"iptables", "raw", "PREROUTING","-i %s -m pkttype --pkt-type multicast -j DROP",interface);
		add_netfilter_rule(ev,"iptables", "raw", "OUTPUT","-o %s -m pkttype --pkt-type multicast -j DROP",interface);
	}
}

/*
 * user-specified filter
 * filter packets by l2 l3 l4 header
 */
static void user_specified_filter(event_t* ev,const msg_t* m)
{
	int i,num;
	const char* action;
	const char* interface;
	const char* source_mac;
	const char* protocol;
	const char* source_ip;
	const char* source_mask;
	const char* destination_ip;
	const char* destination_mask;
	const char* source_starting_port;
	const char* source_ending_port;
	const char* destination_starting_port;
	const char* destination_ending_port;
	const char* type;
	const char* code;
	stringbuffer_t* buf;
	nfc_dbg("\n");
	del_rule_by_event(ev);
	buf = stringbuffer_alloc();
	if(!buf){
		nfc_dbg("stringbuffer_alloc fails\n");
		return;	
	}
	num = atoi( msg_content_at_frame(m,1));
	for(i = 0 ;i <num; i++){

		stringbuffer_clear(buf);

		action    		 = msg_content_at_frame(m,2+14*i);
		interface 		 = msg_content_at_frame(m,3+14*i);
		source_mac 		 = msg_content_at_frame(m,4+14*i);
		protocol  		 = msg_content_at_frame(m,5+14*i);
		source_ip 		 = msg_content_at_frame(m,6+14*i);
		source_mask 		 = msg_content_at_frame(m,7+14*i);
		destination_ip 		 = msg_content_at_frame(m,8+14*i);
		destination_mask 	 = msg_content_at_frame(m,9+14*i);
		source_starting_port 	 = msg_content_at_frame(m,10+14*i);
		source_ending_port 	 = msg_content_at_frame(m,11+14*i);
		destination_starting_port= msg_content_at_frame(m,12+14*i);
		destination_ending_port  = msg_content_at_frame(m,13+14*i);
		type			 = msg_content_at_frame(m,14+14*i);
		code			 = msg_content_at_frame(m,15+14*i);

		stringbuffer_add_f(buf,"-i %s -p %s ",interface,protocol);
		if(strcmp(source_mac,"")){
			stringbuffer_add_f(buf,"-m mac --mac-source %s ",source_mac);
		}

		if(!strcmp(protocol,"tcp") || !strcmp(protocol,"udp")){
			if(strcmp(source_ip,"")){
				stringbuffer_add_f(buf,"-s %s/%s ",source_ip,source_mask);
			}
			if(strcmp(destination_ip,"")){
				stringbuffer_add_f(buf,"-d %s/%s ",destination_ip,destination_mask);
			}
			if(strcmp(source_starting_port,"")){
				stringbuffer_add_f(buf,"--sport %s:%s ",source_starting_port,source_ending_port);
			}
			if(strcmp(destination_starting_port,"")){
				stringbuffer_add_f(buf,"--dport %s:%s ",destination_starting_port,destination_ending_port);
			}
		}
		else if(!strcmp(protocol,"icmp")){
			if(strcmp(type,"")){
				if(strcmp(code,""))
					stringbuffer_add_f(buf,"--icmp-type %s/%s ",type,code);
				else
					stringbuffer_add_f(buf,"--icmp-type %s ",type);
			}
		}
		stringbuffer_add_f(buf,"-j %s",action);

		add_netfilter_rule(ev,"iptables","raw","PREROUTING",stringbuffer_get(buf));
	}
	stringbuffer_destroy(buf);
}
/*
 * ping filter
 * whether to block ping to the device
 */
static void ping_filter(event_t* ev,const msg_t* m)
{
	int enable;
	
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));
	del_rule_by_event(ev);

	if(enable){
		add_netfilter_rule(ev,"iptables","filter","INPUT","-p icmp --icmp-type echo-request -j DROP");
	}
}
/*
 * igmp filter
 * whether to block igmp packet to the device
 */
static void igmp_filter(event_t* ev,const msg_t* m)
{
	int enable;
	nfc_dbg("\n");

	enable = atoi(msg_content_at_frame(m,1));
	del_rule_by_event(ev);

	if(enable){
		add_netfilter_rule(ev,"iptables","raw","PREROUTING","-p igmp -j DROP");
		add_netfilter_rule(ev,"iptables","raw","OUTPUT","-p igmp -j DROP");
	}

}
/*
 * dynamic qos
 * memorize incoming packet's dscp and tag the dscp for outgoing packet
 */
static void dynamic_qos(event_t* ev,const msg_t* m)
{
/* TODO no enable/disable in script */

	int enable;
	const char* mode;
	int ret;
	const char* interface;	
	enable 	  = atoi(msg_content_at_frame(m,1));
	mode 	  = msg_content_at_frame(m,2);
	interface = msg_content_at_frame(m,3);
	nfc_dbg("\n");

	if(!enable){	
		del_rule_by_event(ev);
		return;
	}

	if(!strcmp(mode,"nat")){
		add_netfilter_rule(ev,"iptables","mangle","PREROUTING","-i %s -p tcp -j DYNAMICQOS --record-dscp",interface);
		add_netfilter_rule(ev,"iptables","mangle","POSTROUTING","-o %s -p tcp -j DYNAMICQOS --replay-dscp",interface);
		add_netfilter_rule(ev,"iptables","mangle","PREROUTING","-i %s -p udp -j DYNAMICQOS --record-dscp",interface);
		add_netfilter_rule(ev,"iptables","mangle","POSTROUTING","-o %s -p udp -j DYNAMICQOS --replay-dscp",interface);
	}
	else if(!strcmp(mode,"bridge")){
	     	add_netfilter_rule(ev,"iptables","mangle","PREROUTING","-m physdev --physdev-in %s -p tcp -j DYNAMICQOS --record-dscp",interface);
		add_netfilter_rule(ev,"iptables","mangle","POSTROUTING","-m physdev --physdev-out %s -p tcp -j DYNAMICQOS --replay-dscp",interface);
	     	add_netfilter_rule(ev,"iptables","mangle","PREROUTING","-m physdev --physdev-in %s -p udp -j DYNAMICQOS --record-dscp",interface);
		add_netfilter_rule(ev,"iptables","mangle","POSTROUTING","-m physdev --physdev-out %s -p udp -j DYNAMICQOS --replay-dscp",interface);
	}
}
/*
 * port trigger
 */
static void port_trigger(event_t* ev,const msg_t* m)
{
	int i;
	int num;
	const char* wan_interface;
	const char* lan_interface;
	const char* w_sport;
	const char* w_eport;
	const char* l_sport;
	const char* l_eport;
	
	nfc_dbg("\n");
	del_rule_by_event(ev);

	num = atoi( msg_content_at_frame(m,1));
	for(i = 0 ;i <num; i++){
		wan_interface 	= msg_content_at_frame(m,2+6*i); 
		lan_interface   = msg_content_at_frame(m,3+6*i); 
		w_sport 	= msg_content_at_frame(m,4+6*i); 
		w_eport 	= msg_content_at_frame(m,5+6*i); 
		l_sport 	= msg_content_at_frame(m,6+6*i); 
		l_eport 	= msg_content_at_frame(m,7+6*i); 
		/* tcp */
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-i %s -o %s -p tcp --dport %s:%s -j autofw --action filter"
							,wan_interface,lan_interface,w_sport,w_eport);
		add_netfilter_rule(ev,"iptables","nat","PREROUTING","-i %s -p tcp --dport %s:%s -j autofw --action nat",
							wan_interface,w_sport,w_eport);
		add_netfilter_rule(ev,"iptables","nat","PREROUTING","-i %s -p tcp --dport %s:%s -j autofw --action trigger --related-proto tcp --related-dport %s-%s --related-to %s-%s",
		lan_interface,l_sport,l_eport,l_sport,l_eport,w_sport,w_eport);
		/* udp */
		add_netfilter_rule(ev,"iptables","filter","FORWARD","-i %s -o %s -p udp --dport %s:%s -j autofw --action filter"
							,wan_interface,lan_interface,w_sport,w_eport);
		add_netfilter_rule(ev,"iptables","nat","PREROUTING","-i %s -p udp --dport %s:%s -j autofw --action nat",
							wan_interface,w_sport,w_eport);
		add_netfilter_rule(ev,"iptables","nat","PREROUTING","-i %s -p udp --dport %s:%s -j autofw --action trigger --related-proto udp --related-dport %s-%s --related-to %s-%s",
		lan_interface,l_sport,l_eport,l_sport,l_eport,w_sport,w_eport);
	}
}                                                                               
/*
 * port forwarding
 */
static void port_forwarding(event_t* ev,const msg_t* m)
{
	int i;
	int num;
	const char* wan_interface;
	const char* wan_port;
	const char* lan_ip;
	const char* lan_port;	
	nfc_dbg("\n");
	del_rule_by_event(ev);

	num = atoi(msg_content_at_frame(m,1));
	for(i = 0 ;i <num ; i++){
		wan_interface = msg_content_at_frame(m,2+4*i);
		wan_port = msg_content_at_frame(m,3+4*i);
		lan_ip = msg_content_at_frame(m,4+4*i);
		lan_port = msg_content_at_frame(m,5+4*i);
		add_netfilter_rule(ev,"iptables","nat","PREROUTING","-i %s -p tcp --dport %s -j DNAT --to %s:%s",wan_interface,wan_port,lan_ip,lan_port);
		add_netfilter_rule(ev,"iptables","nat","PREROUTING","-i %s -p udp --dport %s -j DNAT --to %s:%s",wan_interface,wan_port,lan_ip,lan_port);
	}


}
/*
 * vlan tagging
 */
static void vlan_tagging(event_t* ev,const msg_t* m)
{
	/* TODO */	
}
/*
 * static routing
 */
static void static_routing(event_t* ev,const msg_t* m)
{
	int i;
	int num;
	const char* ip;
	const char* mask;
	const char* gw;
	const char* metric;
	const char* dev;
	const char* table;
	nfc_dbg("\n");
	del_rule_by_event(ev);

	num = atoi(msg_content_at_frame(m,1));	
	for(i = 0; i<num;i++){
		ip 	= msg_content_at_frame(m,2+6*i);
		mask 	= msg_content_at_frame(m,3+6*i);
		gw 	= msg_content_at_frame(m,4+6*i);
		metric 	= msg_content_at_frame(m,5+6*i);
		dev 	= msg_content_at_frame(m,6+6*i);
		table 	= msg_content_at_frame(m,7+6*i);
		add_ip_rule(ev,"route","%s/%s via %s metric %s dev %s table %s",ip,mask,gw,metric,dev,table);	
	}
}
/*
 * mss clamping
 */
static void mss_clamping(event_t* ev,const msg_t* m)
{
	int enable;
	nfc_dbg("\n");
	enable = atoi( msg_content_at_frame(m,1));
	del_rule_by_event(ev);
	if(enable){
		add_netfilter_rule(ev,"iptables","mangle","FORWARD","-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu");
	}
}
/*
 * mgmt_channel_setup
 */
static void mgmt_channel_setup(event_t* ev,const msg_t* m)
{
	int i;
	int enable;
	const char* ims;
	const char* gw;
	const char* interface;
	const char* interface_ip;
	const char* number_of_dns;
	const char* dns_ip;
	
	nfc_dbg("\n");

	del_rule_by_event(ev);

	if(!enable) return;

	/* add default gw */
	add_ip_rule(ev,"route","default via %s dev %s",gw,interface);

}
static void snat(event_t* ev,const msg_t* m)
{
	int enable;
	int id;
	const char* interface;
	nfc_dbg("\n");
	
	enable	  = atoi(msg_content_at_frame(m,1)); 
	id	  = atoi(msg_content_at_frame(m,2)); 
	interface = msg_content_at_frame(m,3); 
	
	if(enable)
		add_netfilter_rule_and_id(ev,id,"iptables","nat","POSTROUTING","-o %s -j MASQUERADE",interface);
	else
		del_rule_by_id(ev,id);
		
}
static void interface_basic_setup(event_t* ev,const msg_t* m)
{
	int i;
	int enable;
	int id;
	int should_broute;
	const char* routing_table_id;
	const char* ims_ip;
	const char* gw_ip;
	const char* interface;	
	const char* interface_ip;
	int number_of_dns;
	const char* dns_ip;
	nfc_dbg("\n");

	enable	  	 = atoi(msg_content_at_frame(m,1)); 
	id	  	 = atoi(msg_content_at_frame(m,2)); 
	should_broute  	 = atoi(msg_content_at_frame(m,3)); 
	routing_table_id = msg_content_at_frame(m,4); 
	ims_ip 		 = msg_content_at_frame(m,5); 
	gw_ip 		 = msg_content_at_frame(m,6); 
	interface 	 = msg_content_at_frame(m,7); 
	interface_ip 	 = msg_content_at_frame(m,8); 
	number_of_dns 	 = atoi(msg_content_at_frame(m,9)); 

	nfc_dbg("enable: %d\n",enable);

	if(!enable){
		del_rule_by_id(ev,id);
		return;
	}
	/* policy routing */
	/* ims */
	if(strcmp(ims_ip,"")) add_ip_rule_and_id(ev,id,"rule","to %s table %s",ims_ip,routing_table_id);
	/* dns */
	/* pkts to the interface */
	add_ip_rule_and_id(ev,id,"rule","iif %s table %s",interface,routing_table_id);
	nfc_dbg(".......\n");
	/* local pkts with source IP bound to interface */
	add_ip_rule_and_id(ev,id,"rule","from %s table %s",interface_ip,routing_table_id);
	/* routing rule */
	add_ip_rule_and_id(ev,id,"route","default via %s dev %s table %s",gw_ip,interface,routing_table_id);	
	/* broute */
	if(should_broute) add_netfilter_rule_and_id(ev,id,"ebtables","broute","BROUTING","-i %s -j DROP",interface);
	
	for(i = 0 ;i< number_of_dns ; i++){		
		dns_ip = msg_content_at_frame(m,10+i);
		add_ip_rule_and_id(ev,id,"rule","to %s table %s",dns_ip,routing_table_id);
	}
}
/* 
 * main program calls _clean_all to remove all rules 
 */
void _clean_all(nfc_t* center)
{
	list_node_t* ln;
	list_iterator_t * it;
	event_t* tmp;
	it = list_iterator_new(center->list_event, LIST_HEAD);
        while(ln = list_iterator_next(it) ){
		tmp = (event_t*)ln->val;
		nfc_dbg("delete rules of event %s\n",tmp->info->event_name);
		del_rule_by_event(tmp);
        }
    	list_iterator_destroy(it);
}
static void clean_all(event_t* ev,const msg_t* m)
{
	nfc_t* center;
	nfc_dbg("\n");

	center = ev->center;
	_clean_all(center);
}
static void data_route(event_t* ev,const msg_t* m)
{
	int enable;
	const char*interface;
	int routing_table_id;

	nfc_dbg("\n");
	
	enable = atoi( msg_content_at_frame(m,1));
	interface =  msg_content_at_frame(m,2);
	routing_table_id = atoi(msg_content_at_frame(m,3));

	if(!enable){
		del_rule_by_event(ev);
		return;
	}
	add_ip_rule(ev,"rule","iif %s table %s",interface,routing_table_id);
	
}
static void voice_route(event_t* ev,const msg_t* m)
{

	int enable;
	const char*interface;
	int routing_table_id;

	nfc_dbg("\n");
	
	enable = atoi( msg_content_at_frame(m,1));
	interface =  msg_content_at_frame(m,2);
	routing_table_id = atoi(msg_content_at_frame(m,3));

	if(!enable){
		del_rule_by_event(ev);
		del_rule_by_event((event_t*) ev->priv);
		return;
	}
	/* sip packet */
	add_netfilter_rule(ev,"iptables","mangle","PREROUTING","-i %s -p udp --dport 5060 -j MARK --set-mark 1/1",interface);
	add_ip_rule(ev,"rule","iif %s fwmark 1/1 table %d",interface,routing_table_id);
	/* rtp packet */
	add_netfilter_rule(ev,"iptables","mangle","PREROUTING","-i %s -p udp --dport 5060 -j NFQUEUE --queue-num 1",interface);
}
static void voice_route2(event_t* ev,const msg_t* m)
{
	int enable;
	int id;
	const char*interface;
	const char* media_ip;
	int media_port;

	nfc_dbg("\n");
	
	enable = atoi( msg_content_at_frame(m,1));
	id = atoi( msg_content_at_frame(m,2));
	interface =  msg_content_at_frame(m,3);
	media_ip = msg_content_at_frame(m,4);
	media_port = atoi( msg_content_at_frame(m,5));

	if(!enable){
		del_rule_by_id(ev,id);
		return;
	}
	/* tag mark for policy routing */
	add_netfilter_rule_and_id(ev,id,"iptables","mangle","PREROUTING","-i %s -p udp -s %s --sport %d -j MARK --set-mark 1/1",interface,media_ip,media_port);
	
}
static void mgmt_vlan(event_t* ev,const msg_t* m)
{
	int enable;
	int vlan_id;
	int vlan_priority;
	const char* interface;

	nfc_dbg("\n");
	enable 		= atoi( msg_content_at_frame(m,1));
	vlan_id 	= atoi( msg_content_at_frame(m,2));
	vlan_priority 	= atoi( msg_content_at_frame(m,3));
	interface 	=  msg_content_at_frame(m,4);
	
	if(!enable){
		del_rule_by_event(ev);
		return;
	}
	/* tag */
	add_netfilter_rule(ev,"iptables","mangle","OUTPUT","-j MARK --set-mark 0x10/0xf0");
	add_netfilter_rule(ev,"ebtables","nat","POSTROUTING","-o %s -p 0x0800 --mark 0x10/0xf0 -j vtag --vtag-id %d --vtag-priority %d --vtag-action tag --vtag-target ACCEPT",interface,vlan_id,vlan_priority);
	/* untag */	
	add_netfilter_rule(ev,"ebtables","nat","PREROUTING","-i %s -p 0x8100 --vlan-id %d -j vtag --vtag-id %d --vtag-priority %d --vtag-action untag --vtag-target ACCEPT",interface,vlan_id,vlan_id,vlan_priority);
}
static void data_vlan(event_t* ev,const msg_t* m)
{
	int enable;
	int vlan_id;
	int vlan_priority;
	const char* interface;

	nfc_dbg("\n");
	enable 		= atoi( msg_content_at_frame(m,1));
	vlan_id 	= atoi( msg_content_at_frame(m,2));
	vlan_priority 	= atoi( msg_content_at_frame(m,3));
	interface 	=  msg_content_at_frame(m,4);
	
	if(!enable){
		del_rule_by_event(ev);
		return;
	}
	/* tag */	
	/* this mangle rule is rough because cpe can have many modes and the interface to match can be bridge or physical under different cases
	 * which makes condition to test difficult
	 */
	add_netfilter_rule(ev,"iptables","mangle","FORWARD","-j MARK --set-mark 0x20/0xf0");
	add_netfilter_rule(ev,"ebtables","nat","POSTROUTING","-o %s -p 0x0800 --mark 0x20/0xf0 -j vtag --vtag-id %d --vtag-priority %d --vtag-action tag --vtag-target ACCEPT",interface,vlan_id,vlan_priority);
	/* untag */	
	add_netfilter_rule(ev,"ebtables","nat","PREROUTING","-i %s -p 0x8100 --vlan-id %d -j vtag --vtag-id %d --vtag-priority %d --vtag-action untag --vtag-target ACCEPT",interface,vlan_id,vlan_id,vlan_priority);
}
static void voice_vlan(event_t* ev,const msg_t* m)
{
	int forward_enable;
	int onboard_enable;
	const char* sip_protocol;
	int vlan_id;
	int vlan_priority;
	const char* interface;

	nfc_dbg("\n");
	forward_enable	= atoi( msg_content_at_frame(m,1));
	onboard_enable	= atoi( msg_content_at_frame(m,2));
	sip_protocol	= msg_content_at_frame(m,3);
	vlan_id 	= atoi( msg_content_at_frame(m,4));
	vlan_priority 	= atoi( msg_content_at_frame(m,5));
	interface 	=  msg_content_at_frame(m,6);

	del_rule_by_event(ev);	

	if(forward_enable){
		add_netfilter_rule(ev,"iptables","mangle","FORWARD","-p %s --dport 5060 -j MARK --set-mark 0x30/0xf0",sip_protocol);
		add_netfilter_rule(ev,"iptables","mangle","FORWARD","-p %s --dport 5060 -j NFQUEUE --queue-num 3",sip_protocol);
	}
	if(onboard_enable){
		add_netfilter_rule(ev,"iptables","mangle","OUTPUT","-p %s --dport 5060 -j MARK --set-mark 0x30/0xf0",sip_protocol);
		add_netfilter_rule(ev,"iptables","mangle","OUTPUT","-p %s --dport 5060 -j NFQUEUE --queue-num 3",sip_protocol);
	}
	if(forward_enable || onboard_enable){
		/* tag */
		add_netfilter_rule(ev,"ebtables","nat","POSTROUTING","-o %s -p 0x0800 --mark 0x30/0xf0 -j vtag --vtag-id %d --vtag-priority %d --vtag-action tag --vtag-target ACCEPT",interface,vlan_id,vlan_priority);
		/* untag */	
		add_netfilter_rule(ev,"ebtables","nat","PREROUTING","-i %s -p 0x8100 --vlan-id %d -j vtag --vtag-id %d --vtag-priority %d --vtag-action untag --vtag-target ACCEPT",interface,vlan_id,vlan_id,vlan_priority);
	}
	else{
		nfc_dbg("clear all rules of voice vlan2\n");
		del_rule_by_event( (event_t*) ev->priv);
	}
}
static void voice_vlan2(event_t* ev,const msg_t* m)
{
	int enable;
	int id;
	int forward_or_onboard;
	int rtp_enable;
	int rtcp_enable;
	const char* media_ip;
	int media_port;

	nfc_dbg("\n");
	enable		  	= atoi(msg_content_at_frame(m,1));
	id		  	= atoi(msg_content_at_frame(m,2));
	forward_or_onboard	= atoi(msg_content_at_frame(m,3));
	rtp_enable		= atoi(msg_content_at_frame(m,4));
	rtcp_enable 		= atoi(msg_content_at_frame(m,5));
	media_ip 		= msg_content_at_frame(m,6);
	media_port 		= atoi(msg_content_at_frame(m,7));

	
	if(!enable){
		del_rule_by_id(ev,id);
		return;
	}
	/* forward */
	if(forward_or_onboard == 1){
		if( rtp_enable) add_netfilter_rule_and_id(ev,id,"iptables","mangle","FORWARD","-p udp -s %s --sport %d -j MARK --set-mark 0x30/0xf0",media_ip,media_port);
		if( rtcp_enable) add_netfilter_rule_and_id(ev,id,"iptables","mangle","FORWARD","-p udp -s %s --sport %d -j MARK --set-mark 0x30/0xf0",media_ip,media_port+1);
	}
	/* onboard */	
	else{
		if( rtp_enable) add_netfilter_rule_and_id(ev,id,"iptables","mangle","OUTPUT","-p udp -s %s --sport %d -j MARK --set-mark 0x30/0xf0",media_ip,media_port);
		if( rtcp_enable) add_netfilter_rule_and_id(ev,id,"iptables","mangle","OUTPUT","-p udp -s %s --sport %d -j MARK --set-mark 0x30/0xf0",media_ip,media_port+1);
	}
}
