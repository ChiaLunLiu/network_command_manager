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


/* declaration for event function */
static void mode_setup(event_t* ev,const msg_t* m);
static void nat(event_t* ev,const msg_t* m);
static void ip_passthrough(event_t* ev,const msg_t* m);
static void data_channel_setup(event_t* ev,const msg_t* m);
static void voice_channel_setup(event_t* ev,const msg_t* m);
static void dscp_tag(event_t* ev,const msg_t* m);
static void dscp_tagging_with_timeout(event_t* ev,const msg_t* m);



/* variable defination */
/* the smaller value,the higher priority */
static const event_info_t event_info[]={
{"mode setup",mode_setup,	 	   		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} },
{"nat",nat,		         	   		{0,0,0,0,0,0,0,0,0,0,0,0,0,-1,0,0,0,0,0,0,0} },
{"ip passthrough",ip_passthrough,	   		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} },
{"data channel setup",data_channel_setup,  		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} },
{"voice channel setup",voice_channel_setup,		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} },
{"dscp tag",dscp_tag,			   		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} },
{"dscp tagging with timeout",dscp_tagging_with_timeout, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} },
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
static void add_rule(event_t* ev,const char* tool, const char* table, const char* chain, const char *format, ...);
static void add_ip_rule(event_t* ev,const char* tool,const char *format, ...);
static void del_rule(event_t* ev);


/*
 * del_rule
 * go through all list in center and remove the rules if its corresponding event matches the one
 * to delete   
 */
static void del_rule(event_t* ev)
{
	list_t* list;
	list_iterator_t* it;
	list_node_t* prev, * ln;
	nfc_t* center;
	const char* cmd;
	int i;
	int dummy;
	center = ev->center;
	for(i=0;i< MAX_CHAIN ; i++){
    		it = list_iterator_new(center->chain[i], LIST_HEAD);
		prev = list_iterator_next(it);
    		while(prev){
			ln = list_iterator_next(it);
			if( ev == (event_t*) prev->val){
				list_remove(center->chain[i],prev);
				dbg("remove %s in list %d\n",ev->name,i);
			}
			prev = ln;
		}
    		list_iterator_destroy(it);
    	}
	cmd = stringbuffer_get(ev->del_cmd);
	dbg("%s\n",cmd);
	if(strcmp(cmd,""))	dummy=system(cmd );
	stringbuffer_clear(ev->del_cmd);
	ev->del_cmd = NULL;
}
static void add_ip_rule(event_t* ev,const char* tool,const char *format, ...)
{
	char* string;
	va_list argptr;
	
	dbg("\n");
    	va_start (argptr, format);
    	string = zsys_vprintf (format, argptr);
    	va_end (argptr);
	if(!string) nfc_handle_error("null string");
	systemf("ip %s add %s;\n",tool,string);
    	stringbuffer_add_f(ev->del_cmd,"ip %s del %s;\n",tool,string);
}
static void add_rule(event_t* ev,const char* tool, const char* table, const char* chain, const char *format, ...)
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

	dbg("\n");
    center = ev->center;

    va_start (argptr, format);
    char *string = zsys_vprintf (format, argptr);
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
		if(ev->info->priority < tmp_ev->info->priority){
			/* add it here */
			insert_pos = cnt;
			break;			
		} 
		cnt++;
        	printf("str=%s\n",(char*)ln->val);
    	}
    	list_iterator_destroy(it);

        ln_new = list_node_new(ev);
	if(!ln_new) nfc_handle_error("list_node_new");
        
    	if(insert_pos == -1){
		insert_pos = cnt;
		list_rpush(list,ln_new);
	}
	else
		list_insert(list,ln,ln_new);

    	systemf("%s -t %s -I %s %d %s",tool,table,insert_pos+1,chain,string);

    	stringbuffer_add_f(ev->del_cmd,"%s -t %s -D %s %s;",tool,table,chain,string);
    	free(string);
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

	/* register event */
	sz = sizeof(event_info);
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
	

	del_rule(ev);
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
void vpn_passthrough(const msg_t* m)
{
	/* message structure */
	/* gre
	   l2tp
           ipsec
	   pptp
	 */ 

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

void dmz(event_t* arg)
{
/*	char* sys_ext_if=NULL;
	char* ui_dmz_enable;
	char* dhcp_enable; // TODO
	int mode;
	arg->buf = stringbuffer_alloc();
	mode = get_current_mode();

	switch(mode){
		case MODE_NAT:
		if( !strcmp(dhcp_enable,"enable")){
			systemf("iptables -t nat -A PREROUTING -i %s -p udp --dport 68 -j ACCEPT",sys_ext_if);
			stringbuffer_add_f(arg->buf,"iptables -t nat -D PREROUTING -i %s -p udp --dport 68 -j ACCEPT",sys_ext_if);
		}
		break;
		default:
		break;
	}
*/		
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
	del_rule(ev);
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

	del_rule(ev);

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

	del_rule(ev);

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

	num = atoi(msg_content_at_frame(m,1));
	dscp_value = msg_content_at_frame(m,2);
	is_sip = msg_content_at_frame(m,3);
	interface = msg_content_at_frame(m,4);
	
	del_rule(ev);
	
	for(i=0;i<num;i++){
		add_rule("mangle","POSTROUTING","-o %s -j DSCP --set-dscp %s;\n",interface,dscp_value);
		if(!strcmp(is_sip,"1")){
			add_rule(ev,"mangle","PREROUTING","-i %s -p udp --sport 5060 -j NFQUEUE --queue-num 0;\n");
		}
	}
	
}
static void dscp_tagging_with_timeout(event_t* ev,const msg_t* m)
{
	const char* remove_all;
	const char* dscp_value;
	const char* media_ip;
	const char* media_port;
	const char* interface;
	int timeout_value;
	
	remove_all = msg_content_at_frame(m,1);
	dscp_value = msg_content_at_frame(m,1);
	media_ip = msg_content_at_frame(m,1);
	media_port = msg_content_at_frame(m,1);
	interface = msg_content_at_frame(m,1);
	timeout_value = msg_content_at_frame(m,1);
	
	
}
