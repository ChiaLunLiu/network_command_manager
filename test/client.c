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
void test_packet_filter_set(int sock);
void test_packet_filter_clear(int sock);
void test_igmp_filter_set(int sock);
void test_igmp_filter_clear(int sock);
void test_ping_filter_set(int sock);
void test_ping_filter_clear(int sock);
void test_mgmt_dscp_set(int sock);
void test_mgmt_dscp_clear(int sock);
void test_data_dscp_set(int sock);
void test_data_dscp_clear(int sock);
void test_voice_dscp_set(int sock);
void test_voice_dscp_clear(int sock);
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
	const char* mac[]={"none","00:11:22:33:44:55"};
	const char* day[]={"Mon","Tue"};
	const char* s[]={"00:00","17:00"};
	const char* e[]={"20:00","23:59"};
	const char* url[]={"http://www.yahoo.com.tw","none"};
	const char* keyword[]={"fuck","none"};
	msg_t* m;
	m = nfc_access_restriction(2,mac,day,s,e,url,keyword);
	msg_send(sock,m);
}
void test_access_restriction_clear(int sock)
{
	const char* mac[]={"none","00:11:22:33:44:55"};
	const char* day[]={"Mon","Tue"};
	const char* s[]={"00:00","17:00"};
	const char* e[]={"20:00","23:59"};
	const char* url[]={"http://www.yahoo.com.tw","none"};
	const char* keyword[]={"fuck","none"};
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

void test_packet_filter_set(int sock)
{
	msg_t* m;
	const char* act[]={"ACCEPT","DROP","ACCEPT","DROP"};
	const char* itf[]={"eth1","eth2","eth3","eth4"};
	const char* p[]={"tcp","udp","icmp","udp"};
	const char* sip[]={"none","none","192.168.1.0","10.0.0.0"};
	const char* smask[]={"none","none","24","8"};
	const char* dip[]={"none","none","8.8.8.8","9.9.9.9"};
	const char* dmask[]={"none","none","32","32"};
	const char* ssport[]={"none","none","none","2000"};
	const char* seport[]={"none","none","none","10000"};
	const char* dsport[]={"3000","4000","none","none"};
	const char* deport[]={"4000","5000","none","none"};
	const char* type[]={"none","none","3","none"};
	const char* code[]={"none","none","0","none"};
	m = nfc_packet_filter(4,act,itf,p,sip,smask,dip,dmask,ssport,seport,dsport,deport,type,code);
	msg_send(sock,m);
}
void test_packet_filter_clear(int sock)
{
	msg_t* m;
	m = nfc_packet_filter(0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
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
void test_ping_filter_set(int sock)
{
	msg_t* m;
	m = nfc_ping_filter(1);
	msg_send(sock,m);
}
void test_ping_filter_clear(int sock)
{
	msg_t* m;
	m = nfc_ping_filter(0);
	msg_send(sock,m);
}
void test_mgmt_dscp_set(int sock)
{
	msg_t* m;
	m = nfc_mgmt_dscp(1,5,"eth2");
	msg_send(sock,m);
}
void test_mgmt_dscp_clear(int sock)
{
	msg_t* m;
	m = nfc_mgmt_dscp(0,5,"eth2");
	msg_send(sock,m);
}
void test_data_dscp_set(int sock)
{
	msg_t* m;
	m = nfc_data_dscp(1,6,"eth2");
	msg_send(sock,m);
}
void test_data_dscp_clear(int sock)
{
	msg_t* m;
	m = nfc_data_dscp(0,6,"eth2");
	msg_send(sock,m);
}
void test_voice_dscp_set_1(int sock)
{
	msg_t* m;	
	m=nfc_voice_dscp(1,1,"eth2","udp","1","2",1,"udp","8.8.8.8","50000","60000");
	msg_send(sock,m);
}
void test_voice_dscp_set_2(int sock)
{
	msg_t* m;	
	m=nfc_voice_dscp(1,1,"eth2","udp","1","2",0,"","","","");
	msg_send(sock,m);
}
void test_voice_dscp_clear(int sock)
{
	msg_t* m;
	m=nfc_voice_dscp(0,0,"eth2","udp","1","2",1,"udp","8.8.8.8","50000","60000");
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
int main(int argc,char** argv)
{
	int sock;
	int r,i;
	struct sockaddr_in server;
	frame_t * f;
	msg_t * m;
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
	/* starting test */
	test_mode_setup_nat(sock);
	test_mode_setup_bridge(sock);

	test_ip_passthrough_start(sock);
	test_ip_passthrough_stop(sock);

	test_access_restriction_set(sock);
	test_access_restriction_clear(sock);
	
	test_vpn_passthrough_set(sock);
	test_vpn_passthrough_clear(sock);

	test_multicast_filter_set(sock);
	test_multicast_filter_clear(sock);

	test_packet_filter_set(sock);
	//test_packet_filter_clear(sock);
	
	test_igmp_filter_set(sock);
//	test_igmp_filter_clear(sock);
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
