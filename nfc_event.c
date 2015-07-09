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
static void dscp_tag(event_t* ev,const msg_t* m);
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
static void packet_filter(event_t* ev,const msg_t* m);
static void add_timer(event_t* ev,msg_t* m,int timeout_value);


/* variable defination */
/* the smaller value,the higher priority */
static const event_info_t event_info[]={
{"mode setup",mode_setup,	 	   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"nat",nat,		         	   		{0,0,0,0,0,0,0,0,0,0,0,0, 0,-1,0,0,0,0,0,0,0} },
{"ip passthrough",ip_passthrough,	   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"data channel setup",data_channel_setup,  		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"voice channel setup",voice_channel_setup,		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"dscp tag",dscp_tag,			   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"dscp tagging with timeout",dscp_tagging_with_timeout, {0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"dmz",dmz,			   			{0,0,0,0,0,0,0,0,0,0,0,0,10, 0,0,0,0,0,0,0,0} },
{"dhcp",dhcp,			   			{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"udhcpc",udhcpc,			   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"ntp",ntp,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"oma",oma,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"acs",acs,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"snmp",snmp,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"dns",dns,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"telnet",telnet,			   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"upnp",upnp,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"pots",pots,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"http",http,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"https",https,				   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"access restriction",access_restriction,   		{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"vpn passthrough",vpn_passthrough,   			{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"multicast filter",multicast_filter,  			{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
{"packet filter",packet_filter,  			{0,0,0,0,0,0,0,0,0,0,0,0, 0, 0,0,0,0,0,0,0,0} },
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
 {"iptables","mangle",	"FORWARD",	IPT_MANGLE_PREROUTING},
 {"iptables","mangle",	"PREROUTING",	IPT_MANGLE_PREROUTING},
 {"iptables","mangle",	"POSTROUTING",	IPT_MANGLE_POSTROUTING},
 {"iptables","raw",	"PREROUTING",	IPT_RAW_PREROUTING},
 {"iptables","raw",	"OUTPUT",	IPT_RAW_OUTPUT},
};

static event_t * event_search(nfc_t* center,const char* name);

static int chain_str_to_int(const char* tool,const char* table, const char* chain);
static int add_rule(event_t* ev,const char* tool, const char* table, const char* chain, const char *format, ...);
static void add_ip_rule(event_t* ev,const char* tool,const char *format, ...);
static void del_rule_by_event(event_t* ev);
static void del_rule_by_id(nfc_t* center,int id);
static int  add_rule(event_t* ev,const char* tool, const char* table, const char* chain, const char *format, ...);


/*
 * del_rule_by_id
 * delete iptables, ebtables rule by id
 *
 */
static void del_rule_by_id(nfc_t* center,int id)
{
	
	list_t* list;
	list_iterator_t* it;
	list_node_t* prev, * ln;
	const char* cmd;
	del_rule_t* r;
	int i;
	int dummy=0;
	/* chain[i] keeps iptables, ebtables del cmd */
	for(i=0;i< MAX_CHAIN ; i++){
    		it = list_iterator_new(center->chain[i], LIST_HEAD);
		prev = list_iterator_next(it);
    		while(prev){
			ln = list_iterator_next(it);
			r = (del_rule_t*) prev->val;
			if( r->id == id){
				list_remove(center->chain[i],prev);
				cmd = stringbuffer_get(r->del_cmd);
				nfc_dbg("%s\n",cmd);
				dummy=system(cmd);
				del_rule_free(r);
				dummy = 1;
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
		if( r->id == id){
			list_remove(center->list_other_rule,prev);
			cmd = stringbuffer_get(r->del_cmd);
			nfc_dbg("%s\n",cmd);
			dummy=system(cmd);
			del_rule_free(r);
			dummy = 1;
		}
		prev= ln;
	}
    	list_iterator_destroy(it);
	
	
	if(dummy==0) nfc_dbg("delete noting\n");
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
	del_rule_t* r;
	int dummy;
	nfc_dbg("delete rules of %s\n",ev->info->event_name);
	center = ev->center;
	for(i=0;i< MAX_CHAIN ; i++){
    		it = list_iterator_new(center->chain[i], LIST_HEAD);
		prev = list_iterator_next(it);
    		while(prev){
			ln = list_iterator_next(it);
			r = (del_rule_t*) prev->val;
			if( r->ev == ev ){
				list_remove(center->chain[i],prev);
				cmd = stringbuffer_get(r->del_cmd);
				nfc_dbg("%s\n",cmd);
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
			nfc_dbg("%s\n",cmd);
			dummy=system(cmd);
			del_rule_free(r);
			dummy = 1;
		}
		prev= ln;
	}
    	list_iterator_destroy(it);

}
static void add_ip_rule(event_t* ev,const char* tool,const char *format, ...)
{
	char* string;
	va_list argptr;
	del_rule_t* r;
	list_node_t* ln;
	nfc_dbg("\n");
	r = del_rule_alloc();
	ln = list_node_new(r);
	if(!ln) nfc_handle_error("list_node_new");
	
	r->id = ev->center->id_pool++;
	r->ev = ev;
    	va_start (argptr, format);
    	string = zsys_vprintf (format, argptr);
    	va_end (argptr);
	if(!string) nfc_handle_error("null string");
	systemf("ip %s add %s",tool,string);
	
    	stringbuffer_add_f(r->del_cmd,"ip %s del %s",tool,string);
	list_rpush(ev->center->list_other_rule,ln);

}
static int  add_rule(event_t* ev,const char* tool, const char* table, const char* chain, const char *format, ...)
{
	va_list argptr;
	unsigned i;
	nfc_t* center;
	unsigned idx;
	unsigned sz;
	int cnt = 0;
	list_t* list;
	event_t* tmp_ev;
	list_node_t* ln_new,*ln;
	list_iterator_t* it;
	int insert_pos = -1;
	del_rule_t* dr;
	char* string;
	dbg("\n");

    	center = ev->center;
	dr = del_rule_alloc();
	

    	va_start (argptr, format);
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

    	list = center->chain[i];
	
    	it = list_iterator_new(list, LIST_HEAD);

    	while(ln = list_iterator_next(it) ){
		tmp_ev = (event_t*)ln->val;
		if(ev->info->priority[i] < tmp_ev->info->priority[i]){
			/* add it here */
			insert_pos = cnt;
			break;			
		} 
		cnt++;
        	printf("addr=%s\n",(char*)ln->val);
    	}
    	list_iterator_destroy(it);

        ln_new = list_node_new(dr);
	if(!ln_new) nfc_handle_error("list_node_new");
        
    	if(insert_pos == -1){
		insert_pos = cnt;
		list_rpush(list,ln_new);
	}
	else
		list_insert(list,ln,ln_new);

	
    	systemf("%s -t %s -I %s %d %s",tool,table,insert_pos+1,chain,string);

    	stringbuffer_add_f(dr->del_cmd,"%s -t %s -D %s %s",tool,table,chain,string);
    	free(string);

	return dr->id;
}
nfc_t* nfc_create()
{
	nfc_t* center;
	unsigned i,sz;
	list_node_t* ln;
        event_t* ev;

	center = malloc( sizeof( nfc_t));

	if(!center) nfc_handle_error("malloc");
	
	center->list_event = list_new();
	if(!center->list_event) nfc_handle_error("list_new");


	center->list_other_rule = list_new();
	if(!center->list_other_rule) nfc_handle_error("list_new");

	center->base = event_base_new();
	
	if(!center->base)nfc_handle_error("event_base_new");

	center->id_pool = 0;	
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
	return center;

}
void nfc_free(nfc_t* center)
{
	event_t* ev;
	list_node_t* ln;
	while( ln = list_lpop(center->list_event)){
		ev = (event_t*) ln->val;
		stringbuffer_destroy(ev->del_cmd);
		free(ln);
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
	int network_mode;
	const char* sqn_interface;
	const char* vendor;
	nfc_t* center;
	

	del_rule_by_event(ev);
	center = ev->center;
	network_mode = atoi(msg_content_at_frame(m,1));
	

	switch(network_mode){
		case MODE_NAT:
		/* NAT */
		break;
		case MODE_BRIDGE:
			vendor = msg_content_at_frame(m,2);
			sqn_interface = msg_content_at_frame(m,3);
			/* SQN THP packet */
			if(!strcmp(vendor,"sqn"))
			  add_rule(ev,"ebtables","broute","BROUTING","-i %s --dst 00:16:08:ff:00:01 -j DROP",sqn_interface);
		break;
		case MODE_ROUTER:
		break;
		case MODE_L2TPX2:
		break;
		case MODE_L2TPX3:
		break;
		case MODE_PPPOE:
		break;
		case MODE_GREX2:
		break;
		case MODE_GREX3:
		break;
		default:
		break;
	}	
}
void permanent_rule()
{
	/* connection state control */

	systemf("iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT");
	/* drop invalid packet */
	systemf("iptables -A FORWARD -p tcp -m state --state INVALID -j DROP");
}
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
/*	
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

		case MODE_BRIDGE:
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
*/
}

void app_dns(event_t* arg)
{
/*	char* sys_ext_if;
	arg->buf = stringbuffer_alloc();
	if(!arg->buf){
		dbg("malloc fails\n");
		return ;
	}
	stringbuffer_add_f(arg->buf,"iptables -A INPUT ! -i $_lv_EXTIF -p tcp --dport 53 -j ACCEPT;"
                		    "iptables -A INPUT ! -i $_lv_EXTIF -p udp --dport 53 -j ACCEPT");
*/
}
void app_ntp(event_t* arg);
void app_http(event_t *arg);
void app_https(event_t* arg);
void app_telnet(event_t* arg);
void app_upnp(event_t*arg);
void app_voip(event_t* arg);


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
		add_rule(ev,"iptables","nat","PREROUTING","-o %s -j MASQUERADE",interface);	
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
	int dummy;
	/* frame number checking */
	if(num != 2){
		nfc_dbg("early return due to inconsistent frame (%d,%d)\n",num,2);
		return;
	}
	op = msg_content_at_frame(m,2);
	if(!strcmp(op,"start")) dummy=system("ip-passthrough.sh start");
	else if(!strcmp(op,"stop")) dummy=system("ip-passthrough.sh stop");
	else if(!strcmp(op,"restart")) dummy=system("ip-passthrough.sh restart");
}
static void data_channel_setup(event_t* ev,const msg_t* m)
{
	const char* data_incoming_interface;
	const char* data_outgoing_interface;
	const char* op;
	const char* ims;
	const char* dns;
	const char* ip;
	const char* gw;
	int dns_num;
	int num;
	int i,cid;
	int should_broute;
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

	if(num <=9 ){
		nfc_dbg("early return due to frames <= 9\n");
		return;
	}
	dns_num = atoi(msg_content_at_frame(m,9));
	
	if(num != dns_num + 10){
		nfc_dbg("early return due to inconsistent frame (%d,%d)\n",num,dns_num+10);
		return;
	}
	data_incoming_interface = msg_content_at_frame(m,2);
	should_broute = atoi( msg_content_at_frame(m,3));
	cid = atoi(msg_content_at_frame(m,4));
	ims = msg_content_at_frame(m,5);
	gw =  msg_content_at_frame(m,6);
	data_outgoing_interface = msg_content_at_frame(m,7);
	ip =  msg_content_at_frame(m,8);
	/* policy routing */
	/* ims */
	if(strcmp(ims,"")) add_ip_rule(ev,"rule","from `getnet %s` to %s table %d;\n",data_incoming_interface,ims,cid);
	/* dns */
	for(i=0;i<dns_num;i++){
		dns = msg_content_at_frame(m,8+i);
		add_ip_rule(ev,"rule","from `getnet %s` to %s table %d;\n",data_incoming_interface,dns,cid);
	}
	/* data */
	add_ip_rule(ev,"rule","iif %s table %d;\n",data_incoming_interface,cid);
	add_ip_rule(ev,"rule","iif %s table %d;\n",data_outgoing_interface,cid);
	/* local with IP bound to data interface */
	add_ip_rule(ev,"rule","from %s table %d;\n",ip,cid);

	/* routing rule */
	add_ip_rule(ev,"route","`getnet %s` dev %s table %d;\n",data_incoming_interface,data_incoming_interface,cid);
	add_ip_rule(ev,"route","default via  %s dev %s table %d;\n",gw,data_outgoing_interface,cid);
	
	/* broute */
	if(should_broute) add_rule(ev,"broute","BROUTING","-i %s -j DROP;\n",data_outgoing_interface);
		
	
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
	if(should_broute) add_rule(ev,"broute","BROUTING","-i %s -j DROP;\n",voice_outgoing_interface);
	/* handle non-onboard voice pkt */
	add_rule(ev,"mangle","PREROUTING","-i %s -p udp --sport %d -j NFQUEUE --queue-num 1;\n",voice_outgoing_interface,sip_server_port);
}
static void dscp_tag(event_t* ev,const msg_t* m)
{
	int i;
	int num;
	const char* dscp_value;
	const char* is_sip;
	const char* interface;
	nfc_dbg("\n");
	num = atoi(msg_content_at_frame(m,1));
	dscp_value = msg_content_at_frame(m,2);
	is_sip = msg_content_at_frame(m,3);
	interface = msg_content_at_frame(m,4);
	
	del_rule_by_event(ev);
	
	for(i=0;i<num;i++){
		add_rule(ev,"mangle","POSTROUTING","-o %s -j DSCP --set-dscp %s;\n",interface,dscp_value);
		if(!strcmp(is_sip,"1")){
			add_rule(ev,"mangle","PREROUTING","-i %s -p udp --sport 5060 -j NFQUEUE --queue-num 0;\n",interface);
		}
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
	del_rule_by_id(center,rule_id);
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

	if(!found) nfc_handle_error("fail to delete by %s:%s\n",media_ip,media_port);
	list_remove((list_t*)ev->priv,ln);
	event_del(timer_event);
	msg_free(m);	
}
static void dscp_tagging_with_timeout(event_t* ev,const msg_t* m)
{
	const char* remove_all;
	const char* dscp_value;
	const char* media_ip;
	const char* media_port;
	const char* interface;
	int enable;
	struct event* timer_event;
	msg_t* m_event,* m_mapping;
	nfc_t* center;
	int timeout_value;
	struct timeval tv;
	int rule_id;
	list_node_t* ln;
	list_iterator_t* it;
	event_callback_fn cb;
	void* event_arg;
	int found = 0;
	
	center = ev->center;
	enable = atoi(msg_content_at_frame(m,1));
	media_ip = msg_content_at_frame(m,2);
	media_port = msg_content_at_frame(m,3);
	dscp_value = msg_content_at_frame(m,4);
	interface = msg_content_at_frame(m,5);
	timeout_value = atoi(msg_content_at_frame(m,6));




	/* search for repeated */
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
			nfc_dbg("fail to remove from list by (%s,%s)\n",media_ip,media_port);
			return;
		}
		nfc_dbg("disable dscp tagging for %s:%s\n",media_ip,media_port);		
		list_remove((list_t*)ev->priv,ln);
		timer_event = (struct event*) strtoul (msg_content_at_frame(m,5), NULL, 16);
		cb = event_get_callback(timer_event);
		event_arg = event_get_callback_arg(timer_event);

		if(event_del(timer_event) == -1) nfc_handle_error("event_del");
		cb(0,0,event_arg);

		event_free(timer_event);	
		msg_free(m_mapping);

		return;
	}
	
	if(found){
		nfc_dbg("refresh the timer event\n");
		timer_event = (struct event*) strtoul (msg_content_at_frame(m_mapping,5), NULL, 16);
		if(event_add(timer_event,&tv) == -1) nfc_handle_error("event_add");
		
	}
	else{
		nfc_dbg("create new timer event\n");
		rule_id = add_rule(ev,"mangle","POSTROUTING","-o %s -d %s --dport %s -j DSCP --set-dscp %s",interface,media_ip,media_port,dscp_value);
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
		tv.tv_sec  = timeout_value; 
		tv.tv_usec = 0;
        	if(event_add(timer_event,&tv)== -1) nfc_handle_error("event_add");
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
	interface = msg_content_at_frame(m,2);
	lan_ip = msg_content_at_frame(m,3);

	del_rule_by_event(ev);
	
	for(i = 0 ;i <num ; i++){
		 add_rule(ev,"nat","PREROUTING","-i %s -j DNAT --to %s",interface,lan_ip); 	
	}
	
}
/*
 * dhcp
 */
static void dhcp(event_t* ev,const msg_t* m)
{
	nfc_dbg("\n");
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

	add_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 68 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p udp --dport 68 -j ACCEPT");
	

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

	add_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 123 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p udp --dport 123 -j ACCEPT");
	
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

	add_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 2948 -j ACCEPT");
	add_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 7547 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p udp --dport 2948 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p tcp --dport 7547 -j ACCEPT");
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

	add_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 58603 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p tcp --dport 58603 -j ACCEPT");
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

	add_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 161 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p udp --dport 161 -j ACCEPT");
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

	add_rule(ev,"iptables","nat","PREROUTING","-p udp --dport 53 -j ACCEPT");
	add_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 53 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p udp --dport 53 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p tcp --dport 53 -j ACCEPT");
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
		add_rule(ev,"iptables","nat","PREROUTING","-i %s -p tcp --dport 23 -j ACCEPT",interface);
		add_rule(ev,"iptables","filter","INPUT","-i %s -p tcp --dport 23 -j ACCEPT",interface);
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

	add_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 49152 -j ACCEPT");
	add_rule(ev,"iptables","nat","PREROUTING","-p tcp --dport 1900 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p tcp --dport 49152 -j ACCEPT");
	add_rule(ev,"iptables","filter","INPUT","-p tcp --dport 1900 -j ACCEPT");
}
/*
 * pots
 * onboard phone
 * remove the rules only when enable=0
 * because pots would dynamically add new port
 */
static void pots(event_t* ev,const msg_t* m)
{
	
	int enable;
	int port;
	const char* protocol;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));
	port = atoi(msg_content_at_frame(m,2));
	protocol = msg_content_at_frame(m,3);
	
	
	if(!enable){
		del_rule_by_event(ev);	
		return;
	}
	add_rule(ev,"iptables","nat","PREROUTING","-p %s --dport %d -j ACCEPT",protocol,port);
	add_rule(ev,"iptables","filter","INPUT","-p %s --dport %d -j ACCEPT",protocol,port);
}
/*
 * http
 */
static void http(event_t* ev,const msg_t* m)
{
	int enable;
	const char* port;
	const char* protocol;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));
	port = msg_content_at_frame(m,2);
	protocol = msg_content_at_frame(m,3);

	del_rule_by_event(ev);	
	if(!enable) return;

	add_rule(ev,"iptables","nat","PREROUTING","-p %s --dport %s -j ACCEPT",protocol,port);
	add_rule(ev,"iptables","filter","INPUT","-p %s --dport %s -j ACCEPT",protocol,port);
}
/*
 * https
 */
static void https(event_t* ev,const msg_t* m)
{
	int enable;
	const char* port;
	const char* protocol;
	nfc_dbg("\n");
	enable = atoi(msg_content_at_frame(m,1));
	port = msg_content_at_frame(m,2);
	protocol = msg_content_at_frame(m,3);

	del_rule_by_event(ev);	
	if(!enable) return;

	add_rule(ev,"iptables","nat","PREROUTING","-p %s --dport %s -j ACCEPT",protocol,port);
	add_rule(ev,"iptables","filter","INPUT","-p %s --dport %s -j ACCEPT",protocol,port);

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

		if(strcmp(mac_address,"none")){
			stringbuffer_add_f(stringbuf,"-m mac --mac-source %s ",mac_address);
		}
		if(strcmp(blocked_day,"every day")){
			stringbuffer_add_f(stringbuf,"-m time --weekdays %s ",blocked_day);
		}
		if(strcmp(blocked_starting_time,"none")){
			stringbuffer_add_f(stringbuf,"-m time --timestart %s --timestop %s ",blocked_starting_time, blocked_ending_time);
		}
		if(strcmp(blocked_url,"none")){
			stringbuffer_add_f(stringbuf,"-m webstr --url %s ",blocked_url);
		}
		if(strcmp(blocked_keyword,"none")){
			stringbuffer_add_f(stringbuf,"-m string --algo bm --string %s ",blocked_keyword);
		}	
		add_rule(ev,"iptables","filter","FORWARD",stringbuffer_get(stringbuf));
		
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
		add_rule(ev,"iptables","filter","FORWARD","-p gre -j DROP");
	}
	if(l2tp){
		add_rule(ev,"iptables","filter","FORWARD","-p udp --dport 1701 -j DROP");
	}
	if(pptp){
		add_rule(ev,"iptables","filter","FORWARD","-p tcp --dport 1723 -j DROP");
		add_rule(ev,"iptables","filter","FORWARD","-p gre -j DROP");
	}
	if(pppoe){
		/* TODO */
	}
	if(ipsec){
		add_rule(ev,"iptables","filter","FORWARD","-p udp --dport 500 -j DROP");
		add_rule(ev,"iptables","filter","FORWARD","-p udp --dport 4500 -j DROP");
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
		add_rule(ev,"iptables", "raw", "PREROUTING","-i %s -m pkttype --pkt-type multicast -j DROP",interface);
		add_rule(ev,"iptables", "raw", "OUTPUT","-o %s -m pkttype --pkt-type multicast -j DROP",interface);
	}
}

/*
 * packet filter
 * filter packets by l2 l3 l4 header
 */
static void packet_filter(event_t* ev,const msg_t* m)
{
	int i,num;
	const char* action;
	const char* interface;
	const char* protocol;
	const char* source_ip;
	const char* source_mask;
	const char* destination_ip;
	const char* destination_mask;
	const char* source_starting_port;
	const char* source_ending_port;
	const char* destination_starting_port;
	const char* destination_ending_port;
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

		action    		 = msg_content_at_frame(m,2+11*i);
		interface 		 = msg_content_at_frame(m,3+11*i);
		protocol  		 = msg_content_at_frame(m,4+11*i);
		source_ip 		 = msg_content_at_frame(m,5+11*i);
		source_mask 		 = msg_content_at_frame(m,6+11*i);
		destination_ip 		 = msg_content_at_frame(m,7+11*i);
		destination_mask 	 = msg_content_at_frame(m,8+11*i);
		source_starting_port 	 = msg_content_at_frame(m,9+11*i);
		source_ending_port 	 = msg_content_at_frame(m,10+11*i);
		destination_starting_port= msg_content_at_frame(m,11+11*i);
		destination_ending_port  = msg_content_at_frame(m,12+11*i);
		
		stringbuffer_add_f(buf,"-i %s -p %s ",interface,protocol);
		if(strcmp(source_ip,"none")){
			stringbuffer_add_f(buf,"-s %s/%s ",source_ip,source_mask);
		}
		if(strcmp(destination_ip,"none")){
			stringbuffer_add_f(buf,"-d %s/%s ",destination_ip,destination_mask);
		}
		if(strcmp(source_starting_port,"none")){
			stringbuffer_add_f(buf,"--sport %s:%s ",source_starting_port,source_ending_port);
		}
		if(strcmp(destination_starting_port,"none")){
			stringbuffer_add_f(buf,"--dport %s:%s ",destination_starting_port,destination_ending_port);
		}
		add_rule(ev,"iptables","raw","PREROUTING",stringbuffer_get(buf));
	}
	stringbuffer_destroy(buf);
}
