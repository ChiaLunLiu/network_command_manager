/*
 *	This program is designed for shell script to call
 *	It utilizes message structure in minimsg but does not create minimsg_socket nor
 *	minimsg_context in order to save time
 *	Date: 2015/06/28
 */
#include<stdio.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<signal.h>
#include<string.h>
#include <minimsg/minimsg.h>
#include <nfc/nfc.h>
#include <sys/un.h>
#define TIME 10
#define SPACING "%-20s"

/* global variable */
int g_sock;
void test_mode_setup_nat(int sock);
void test_mode_setup_bridge(int sock);
void test_ip_passthrough_start(int sock);
void test_ip_passthrough_stop(int sock);
void test_access_restriction_set(int sock);
void test_access_restriction_clear(int sock);
void test_vpn_passthrough_set(int sock);
void test_vpn_passthrough_clear(int sock);
void test_multicast_filter_set(int sock);
void test_multicast_filter_clear(int sock);
void test_user_specified_filter_set(int sock);
void test_user_specified_filter_clear(int sock);
void test_igmp_filter_set(int sock);
void test_igmp_filter_clear(int sock);

void ping_filter_set();
void ping_filter_clear();
void mgmt_dscp_set();
void mgmt_dscp_clear();
void data_dscp_set();
void data_dscp_clear();
void voice_dscp_set();
void voice_dscp_clear();
void mgmt_vlan_set();
void mgmt_vlan_clear();
void data_vlan_set();
void data_vlan_clear();
void voice_vlan_set();
void voice_vlan_clear();
void voice_vlan2_set();
void voice_vlan2_clear();

void test_dscp_tagging_with_timeout_set(int sock);
void test_dscp_tagging_with_timeout_delete_after_timeout(int sock);
void test_dscp_tagging_with_timeout_refresh(int sock);
void test_dscp_tagging_with_timeout_clear(int sock);
void test_udhcpc_set(int sock);
void test_udhcpc_clear(int sock);
void test_ntp_set(int sock);
void test_ntp_clear(int sock);
void test_oma_set(int sock);
void test_oma_clear(int sock);
void test_acs_set(int sock);
void test_acs_clear(int sock);
void test_snmp_set(int sock);
void test_snmp_clear(int sock);
void test_dns_set(int sock);
void test_dns_clear(int sock);
void test_upnp_set(int sock);
void test_upnp_clear(int sock);
void test_telnet_set(int sock);
void test_telnet_clear(int sock);
void test_http_set(int sock);
void test_http_clear(int sock);
void test_https_set(int sock);
void test_https_clear(int sock);
void test_port_trigger_set(int sock);
void test_port_trigger_clear(int sock);
void test_port_forwarding_set(int sock);
void test_port_forwarding_clear(int sock);
void test_dmz_set(int sock);
void test_dmz_clear(int sock);
void test_data_channel_setup_set(int sock);
void test_snat(int sock);
void test_interface_basic_setup(int sock); 
void test_clean_all(int sock);
void test_voice_route(int sock);
void test_voice_rtp_route(int sock);

void print_help()
{
	printf("["SPACING"]: network_mode, radio_interface_name, radio_interface_vendor, number_of_ether_interface"
	",{eth_interface_names}, number_of_wifi_interface, {wifi_interface_names}\n","mode setup");

	printf("["SPACING"]: op\n","ip passthrough");
	printf("["SPACING"]:\n","data channel setup");
}
void test_mode_setup_nat(int sock)
{
	msg_t* m;
	const char* eths[] = {"eth2"};
	m = nfc_mode_setup("NAT","eth0","sqn",1,eths,0,NULL);
	msg_send(sock,m);	

}
void test_mode_setup_bridge(int sock)
{
	msg_t* m;

	m = nfc_mode_setup("BRIDGE","eth2","sqn",0,NULL,0,NULL);
	msg_send(sock,m);
}
void test_ip_passthrough_start(int sock)
{
	msg_t* m;
	m = nfc_ip_passthrough("start");
	msg_send(sock,m);
}
void test_ip_passthrough_stop(int sock)
{
	msg_t* m;
	m = nfc_ip_passthrough("stop");
	msg_send(sock,m);
}

void test_access_restriction_set(int sock)
{
	const char* mac[]={"","00:11:22:33:44:55"};
	const char* day[]={"Mon","Tue"};
	const char* s[]={"00:00","17:00"};
	const char* e[]={"20:00","23:59"};
	const char* url[]={"http://www.yahoo.com.tw",""};
	const char* keyword[]={"fuck",""};
	msg_t* m;
	m = nfc_access_restriction(2,mac,day,s,e,url,keyword);
	msg_send(sock,m);
}
void test_access_restriction_clear(int sock)
{
	const char* mac[]={"","00:11:22:33:44:55"};
	const char* day[]={"Mon","Tue"};
	const char* s[]={"00:00","17:00"};
	const char* e[]={"20:00","23:59"};
	const char* url[]={"http://www.yahoo.com.tw",""};
	const char* keyword[]={"fuck",""};
	msg_t* m;
	m = nfc_access_restriction(0,mac,day,s,e,url,keyword);
	msg_send(sock,m);
}

void test_vpn_passthrough_set(int sock)
{
	msg_t* m;
	m = nfc_vpn_passthrough(1,1,1,1,1);
	msg_send(sock,m);
}
void test_vpn_passthrough_clear(int sock)
{
	msg_t* m;
	m = nfc_vpn_passthrough(0,0,0,0,0);
	msg_send(sock,m);
}

void test_multicast_filter_set(int sock)
{
	msg_t* m;
	const char* itf[]={"eth2","eth3"};
	m = nfc_multicast_filter(2,itf);
	msg_send(sock,m);
}
void test_multicast_filter_clear(int sock)
{
	msg_t* m;
	const char* itf[]={"eth2","eth3"};
	m = nfc_multicast_filter(0,itf);
	msg_send(sock,m);
}

void test_user_specified_filter_set(int sock)
{
	msg_t* m;
	const char* act[]={"ACCEPT","DROP","ACCEPT","DROP"};
	const char* itf[]={"eth1","eth2","eth3","eth4"};
	const char* source_mac[]={"","11:22:33:44:55:66","",""};
	const char* p[]={"tcp","udp","icmp","udp"};
	const char* sip[]={"","","192.168.1.0","10.0.0.0"};
	const char* smask[]={"","","24","8"};
	const char* dip[]={"","","8.8.8.8","9.9.9.9"};
	const char* dmask[]={"","","32","32"};
	const char* ssport[]={"","","","2000"};
	const char* seport[]={"","","","10000"};
	const char* dsport[]={"3000","4000","",""};
	const char* deport[]={"4000","5000","",""};
	const char* type[]={"","","3",""};
	const char* code[]={"","","0",""};
	m = nfc_user_specified_filter(4,act,itf,source_mac,p,sip,smask,dip,dmask,ssport,seport,dsport,deport,type,code);
	msg_send(sock,m);
}
void test_user_specified_filter_clear(int sock)
{
	msg_t* m;
	m = nfc_user_specified_filter(0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
	msg_send(sock,m);
}

void test_igmp_filter_set(int sock)
{
	msg_t* m;
	m = nfc_igmp_filter(1);
	msg_send(sock,m);
}
void test_igmp_filter_clear(int sock)
{
	msg_t* m;
	m = nfc_igmp_filter(0);
	msg_send(sock,m);
}
void test_dscp_tagging_with_timeout_set(int sock)
{
	msg_t* m;
	m = nfc_dscp_tagging_with_timeout(1, "udp","111.111.111.111","12345","8","eth3",3);
	msg_send(sock,m);
}
void test_dscp_tagging_with_timeout_delete_after_timeout(int sock)
{
	msg_t* m;
	m = nfc_dscp_tagging_with_timeout(1, "udp","111.111.111.111","12345","8","eth3",5);
	msg_send(sock,m);
	m = nfc_dscp_tagging_with_timeout(0, "udp","111.111.111.111","12345","8","eth3",10);
	msg_send(sock,m);
	
}
void test_dscp_tagging_with_timeout_refresh(int sock)
{
	msg_t* m;	
	m = nfc_dscp_tagging_with_timeout(1, "udp","111.111.111.123","12345","8","eth3",3);
	msg_send(sock,m);
	m = nfc_dscp_tagging_with_timeout(1, "udp","111.111.111.123","12345","8","eth3",10);
	msg_send(sock,m);
}
void test_dscp_tagging_with_timeout_clear(int sock)
{
	msg_t* m;
	m = nfc_dscp_tagging_with_timeout(0, "udp","111.111.111.111","12345","8","eth3",10);
	msg_send(sock,m);
}
void test_dns_set(int sock)
{
	msg_t* m;
	m = nfc_dns(1);
	msg_send(sock,m);
}
void test_dns_clear(int sock)
{
	msg_t* m;
	m = nfc_dns(0);
	msg_send(sock,m);
}
void test_upnp_set(int sock)
{
	msg_t* m;
	m = nfc_upnp(1);
	msg_send(sock,m);
}
void test_upnp_clear(int sock)
{
	msg_t* m;
	m = nfc_upnp(0);
	msg_send(sock,m);
}
void test_telnet_set(int sock)
{
	msg_t* m;
	const char* itf[]={"ra0","ra1"};
	m = nfc_telnet(1,2,itf);
	msg_send(sock,m);
}
void test_telnet_clear(int sock)
{
	msg_t* m;
	const char* itf[]={"ra0","ra1"};
	m = nfc_telnet(0,2,itf);
	msg_send(sock,m);
	
}
void test_http_set(int sock)
{
	msg_t* m;
	m = nfc_http(1,8080);
	msg_send(sock,m);
}
void test_http_clear(int sock)
{
	msg_t* m;
	m = nfc_http(0,8080);
	msg_send(sock,m);
}
void test_https_set(int sock)
{
	msg_t* m;
	m = nfc_https(1,8082);
	msg_send(sock,m);
}
void test_https_clear(int sock)
{
	msg_t* m;
	m = nfc_https(0,8082);
	msg_send(sock,m);
}
void test_port_trigger_set(int sock)
{
	msg_t* m;
	const char* wan_interfaces[]={"eth1","eth2"};
	const char* lan_interfaces[]={"eth3","eth4"};
	const char* wan_starting_port[]={"10000","30000"};
	const char* wan_ending_port[]={"20000","40000"};
	const char* lan_starting_port[]={"1000","3000"};
	const char* lan_ending_port[]={"2000","4000"};
	m =nfc_port_trigger(2,wan_interfaces, lan_interfaces, wan_starting_port, wan_ending_port, lan_starting_port, lan_ending_port);
	msg_send(sock,m);
}
void test_port_forwarding_set(int sock)
{
	msg_t* m;
	const char* interface[]={"eth1","eth3"};
	const char* wan_port[]={"40000","30000"};
	const char* lan_ip[]={"1.1.1.1","2.2.2.2"};
	const char* lan_port[]={"5000","6000"};
	m =nfc_port_forwarding(2,interface,wan_port,lan_ip,lan_port);
	msg_send(sock,m);
}
void test_port_forwarding_clear(int sock)
{
	msg_t* m;
	m =nfc_port_forwarding(0,NULL,NULL,NULL,NULL);
	msg_send(sock,m);

}
void test_dmz_set(int sock)
{
	msg_t* m;
	const char* interfaces[]={"eth2","eth3"};
	const char* ip[]={"1.1.1.1","2.2.2.2"};
	m = nfc_dmz(2,interfaces,ip);
	msg_send(sock,m);
}
void test_dmz_clear(int sock)
{
	msg_t* m;
	const char* interfaces[]={"eth2","eth3"};
	const char* ip[]={"1.1.1.1","2.2.2.2"};
	m = nfc_dmz(0,interfaces,ip);
	msg_send(sock,m);
}
void test_data_channel_setup_set(int sock)
{
	int enable=1;
	int should_broute=1;
	int table_id=2;
	const char* ims_ip="1.1.1.1";
	const char* gw_ip="2.2.2.2";
	const char* data_subnet="5.5.5.0/24";
	const char* interface="eth2";
	const char* interface_ip="2.2.2.3";
	int number_of_dns=2;
	const char* dns_ip[]={"8.8.8.8","7.7.7.7"};

	msg_t* m;
	m = nfc_data_channel_setup(enable,should_broute,table_id,ims_ip,gw_ip,data_subnet,interface,interface_ip,
	number_of_dns,dns_ip);
	msg_send(sock,m);
}
void test_snat(int sock)
{
	printf("%s\n",__func__);
	msg_t* m;
	m = nfc_snat(1,2,"eth4");
	msg_send(sock,m);
	m = nfc_snat(1,3,"eth5");
	msg_send(sock,m);
	m = nfc_snat(0,2,"");
	msg_send(sock,m);
	m = nfc_snat(0,3,"");
	msg_send(sock,m);
	
}
void test_interface_basic_setup(int sock)
{
	int enable = 1;
	int cid = 2;
	int should_broute = 1;
	const char* routing_table_id = "2";
	const char* ims_ip = "7.7.7.7";
	const char* gw_ip = "10.10.10.1";
	const char* interface = "eth2";
	const char* interface_ip = "10.10.10.2";
	int number_of_dns = 2;
	const char* dns[]={"8.8.8.8","10.10.10.10"};
	
	
	printf("%s\n",__func__);
	msg_t* m;
	m = nfc_interface_basic_setup(enable,cid,should_broute,routing_table_id,ims_ip,gw_ip,interface,interface_ip,number_of_dns,dns);
	msg_send(sock,m);
	m = nfc_interface_basic_setup(0,cid,should_broute,routing_table_id,ims_ip,gw_ip,interface,interface_ip,number_of_dns,dns);
	msg_send(sock,m);
	
}
void test_clean_all(int sock)
{
	msg_t* m;
	m = nfc_clean_all();
	msg_send(sock,m);
}
void test_voice_route(int sock)
{
	msg_t* m;
	int enable = 1;
	const char* interface= "eth0";
	int routing_table_id = 22;
	m = nfc_voice_route(enable,interface,routing_table_id);
	msg_send(sock,m);
}
void test_voice_rtp_route(int sock)
{
	
	msg_t* m;
	int enable = 1;
	int id = 1;
	const char* interface= "eth0";
	const char* media_ip ="2.2.2.2";
	int port = 56;
	m = nfc_voice_rtp_route(enable,id,interface,media_ip,port);
	msg_send(sock,m);
}


struct cmd{
	const char* name;
	void (*set)();
	void(*unset)();
};
struct cmd test_cmd[]={
	{"ping filter",ping_filter_set,ping_filter_clear},
	{"mgmt dscp",mgmt_dscp_set,mgmt_dscp_clear},
	{"data dscp",data_dscp_set,data_dscp_clear},
	{"voice dscp",voice_dscp_set,voice_dscp_clear},
	{"mgmt vlan",mgmt_vlan_set,mgmt_vlan_clear},
	{"data vlan",data_vlan_set,data_vlan_clear},
	{"voice vlan",voice_vlan_set,voice_vlan_clear},
	{"voice vlan2",voice_vlan2_set,voice_vlan2_clear},
};
int main(int argc,char** argv)
{
	int sock;
	int r,i;
	struct sockaddr_in server;
	frame_t * f;
	msg_t * m;
	int sz;
	int j;
	const char* str;
/*	struct sockaddr_un local;
	 socklen_t sock_len; 
*/
	if(argc > 1){
		if(!strcmp(argv[i],"help")){
			print_help();
			return 0;
		}
	}
	sock = socket(AF_INET,SOCK_STREAM,0);
	if(sock == -1)
	{
		perror("could not create socket");
		return 1;
	}
	puts("Socket created");
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(12345);


/*
	for AF_LOCAL
	addr = (struct sockaddr*)&local;
        memset(&local,0,sizeof(local));
        local.sun_family = AF_LOCAL;
	local.sun_path = ???
        sock_len = SUN_LEN(&local);
        sock = socket(AF_LOCAL,SOCK_STREAM,0);
*/	
		
	if (connect(sock,(struct sockaddr*)&server,sizeof(server))<0)
	{
		perror("connect failed.");
		return 1;
	}
	puts("Connected");
	g_sock = sock;
	/* starting test */
	sz = sizeof(test_cmd)/sizeof( struct cmd);
	printf("cmd size : %d\n",sz);
	for(i = 2 ; i < argc ; i+=2){
		for(j = 0 ;j< sz ;j++){
			if(!strcmp(argv[i-1],test_cmd[j].name)) break;
		}
		if(j == sz)printf("unknown command : %s\n",argv[i-1]);
		else{
			if(!strcmp(argv[i],"1")) test_cmd[j].set();
			else if(!strcmp(argv[i],"0")) test_cmd[j].unset();
			else printf("unknown value :%s\n",argv[i]);
		}
	}

//	test_igmp_filter_set(sock);
//	test_igmp_filter_clear(sock);
//	test_user_specified_filter_set(sock);
//	test_user_specified_filter_clear(sock);
//	test_multicast_filter_set(sock);
//	test_multicast_filter_clear(sock);
//	test_vpn_passthrough_set(sock);
//	test_vpn_passthrough_clear(sock);
//	test_access_restriction_set(sock);
//	test_access_restriction_clear(sock);
/*	test_mode_setup_nat(sock);
	test_mode_setup_bridge(sock);

	test_ip_passthrough_start(sock);
	test_ip_passthrough_stop(sock);

	


	
	test_ping_filter_set(sock);
	test_mgmt_dscp_set(sock);

	test_data_dscp_set(sock);
	test_voice_dscp_set_2(sock);
	test_data_dscp_clear(sock);
//	test_dscp_tagging_with_timeout_set(sock);
	test_dscp_tagging_with_timeout_delete_after_timeout(sock);
//	test_dscp_tagging_with_timeout_refresh(sock);
	test_udhcpc_set(sock);
//	test_udhcpc_clear(sock);
	test_ntp_set(sock);
//	test_ntp_clear(sock);
	test_oma_set(sock);
//	test_oma_clear(sock);
	test_acs_set(sock);
//	test_acs_clear( sock);
	test_snmp_set( sock);
//	test_snmp_clear( sock);

	test_dns_set(sock);
	test_dns_set(sock);
	test_dns_clear(sock);
	test_upnp_set(sock);
	test_upnp_clear(sock);
	test_telnet_set(sock);
	test_telnet_clear(sock);

	test_http_set(sock);
	test_https_set(sock);
	test_http_clear(sock);
	test_https_clear(sock);
	test_port_trigger_set(sock);
	
	test_port_forwarding_set(sock);
	test_port_forwarding_clear(sock);
	test_dmz_set(sock);
	test_dmz_clear(sock);
	test_data_channel_setup_set(sock);

	test_snat(sock);
	test_interface_basic_setup(sock);
*/
//	test_voice_route(sock);
//	test_voice_rtp_route(sock);
//	test_clean_all(sock);
	close(sock);	
	return 0;
}
void test_udhcpc_set(int sock)
{
	msg_t* m;
	m = nfc_udhcpc(1);
	msg_send(sock,m);
}
void test_udhcpc_clear(int sock)
{
	
	msg_t* m;
	m = nfc_udhcpc(0);
	msg_send(sock,m);
}
void test_ntp_set(int sock)
{
	msg_t* m;
	m = nfc_ntp(1);
	msg_send(sock,m);
}
void test_ntp_clear(int sock)
{
	msg_t* m;
	m = nfc_ntp(0);
	msg_send(sock,m);
}
void test_oma_set(int sock)
{
	msg_t* m;
	m = nfc_oma(1);
	msg_send(sock,m);
}

void test_oma_clear(int sock)
{
	msg_t* m;
	m = nfc_oma(0);
	msg_send(sock,m);
}
void test_acs_set(int sock)
{
	msg_t* m;
	m = nfc_acs(1);
	msg_send(sock,m);
}
void test_acs_clear(int sock)
{
	msg_t* m;
	m = nfc_acs(0);
	msg_send(sock,m);
}
void test_snmp_set(int sock)
{
	msg_t* m;
	m = nfc_snmp(1);
	msg_send(sock,m);
}
void test_snmp_clear(int sock)
{
	msg_t* m;
	m = nfc_snmp(0);
	msg_send(sock,m);
}
void ping_filter_set()
{
	msg_t* m;
	printf("%s\n",__func__);
	m = nfc_ping_filter(1);
	msg_send(g_sock,m);
}
void ping_filter_clear()
{
	msg_t* m;
	m = nfc_ping_filter(0);
	msg_send(g_sock,m);
}
void mgmt_dscp_set()
{
	msg_t* m;
	m = nfc_mgmt_dscp(1,5,"eth2");
	msg_send(g_sock,m);
}
void mgmt_dscp_clear()
{
	msg_t* m;
	m = nfc_mgmt_dscp(0,5,"eth2");
	msg_send(g_sock,m);
}
void data_dscp_set()
{
	msg_t* m;
	m = nfc_data_dscp(1,6,"eth2");
	msg_send(g_sock,m);
}
void data_dscp_clear()
{
	msg_t* m;
	m = nfc_data_dscp(0,6,"eth2");
	msg_send(g_sock,m);
}
void voice_dscp_set()
{
	msg_t* m;	
	m=nfc_voice_dscp(1,1,1,"eth2","udp",1,2,3);
	msg_send(g_sock,m);
}
void voice_dscp_clear()
{
	msg_t* m;
	m=nfc_voice_dscp(0,0,0,"eth2","udp",1,2,3);
	msg_send(g_sock,m);
}
void mgmt_vlan_set()
{
	msg_t* m;
	m=nfc_mgmt_vlan(1,2,3,"eth0");
	msg_send(g_sock,m);
}
void mgmt_vlan_clear()
{
	msg_t* m;
	m=nfc_mgmt_vlan(0,2,3,"eth0");
	msg_send(g_sock,m);
}
void data_vlan_set()
{
	msg_t* m;
	m=nfc_data_vlan(1,4,5,"eth0");
	msg_send(g_sock,m);
}
void data_vlan_clear()
{
	msg_t* m;
	m=nfc_data_vlan(0,4,5,"eth0");
	msg_send(g_sock,m);
}
void voice_vlan_set()
{
	int forward_enable = 1;
	int onboard_enable = 1;
	const char* sip_protocol = "udp";
	int vlan_id = 3;
	int vlan_prio = 4;
	const char* interface = "eth3";
	msg_t* m;
	m=nfc_voice_vlan(forward_enable,onboard_enable,sip_protocol,vlan_id,vlan_prio,interface);
	msg_send(g_sock,m);
}
void voice_vlan_clear()
{
	int forward_enable = 0;
	int onboard_enable = 0;
	const char* sip_protocol = "udp";
	int vlan_id = 3;
	int vlan_prio = 4;
	const char* interface = "eth3";
	msg_t* m;
	m=nfc_voice_vlan(forward_enable,onboard_enable,sip_protocol,vlan_id,vlan_prio,interface);
	msg_send(g_sock,m);
}
void voice_vlan2_set()
{
	int enable=1;
	int id=1;
	int forward_or_onboard = 1;
	int rtp_enable=1;
	int rtcp_enable=1;
	const char* media_ip="2.2.2.2";
	int media_port=12345;
	msg_t* m;
	m=nfc_voice_vlan2(enable,id,forward_or_onboard,rtp_enable,rtcp_enable,media_ip,media_port);
	msg_send(g_sock,m);
	id = 2;
	media_port = 22222;
	m=nfc_voice_vlan2(enable,id,forward_or_onboard,rtp_enable,rtcp_enable,media_ip,media_port);
	msg_send(g_sock,m);
	
}
void voice_vlan2_clear()
{
	int enable=0;
	int id=1;
	int forward_or_onboard = 1;
	int rtp_enable=1;
	int rtcp_enable=1;
	const char* media_ip="2.2.2.2";
	int media_port=12345;
	msg_t* m;
	m=nfc_voice_vlan2(enable,id,forward_or_onboard,rtp_enable,rtcp_enable,media_ip,media_port);
	msg_send(g_sock,m);
}
