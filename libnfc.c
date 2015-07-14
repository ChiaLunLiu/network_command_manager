#include "util.h"
#include "nfc.h"


msg_t* nfc_access_restriction(int number_of_rule,const char** mac, const char** day,const char** start_time,const char** end_time, const char** url, const char** keyword)
{
	int i;
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"access restriction");
	msg_append_string_f(m,"%d",number_of_rule);
	for(i = 0 ;i<number_of_rule ; i++){
		msg_append_string(m,mac[i]);
		msg_append_string(m,day[i]);
		msg_append_string(m,start_time[i]);
		msg_append_string(m,end_time[i]);
		msg_append_string(m,url[i]);
		msg_append_string(m,keyword[i]);
	}
	return m;
}


msg_t*  nfc_mode_setup(const char* network_mode, const char* radio_interface_name, const char* radio_interface_vendor,
      int number_of_ether_interface,const char** eth_interface_names, int number_of_wifi_interface, const char** wifi_interface_names)
{
	int i;
	msg_t* m ; 
	m = msg_alloc();
	if(!m)return NULL;
	
	msg_append_string(m,"mode setup");
	msg_append_string(m,network_mode);
	msg_append_string(m,radio_interface_name);
	msg_append_string(m,radio_interface_vendor);
	msg_append_string_f(m,"%d",number_of_ether_interface);
	for(i = 0 ;i < number_of_ether_interface ; i++) msg_append_string(m,eth_interface_names[i]);
	msg_append_string_f(m,"%d",number_of_wifi_interface);
	for(i = 0 ;i < number_of_wifi_interface ; i++) msg_append_string(m,wifi_interface_names[i]);
	return m;
}


msg_t* nfc_ip_passthrough(const char* op)
{
	msg_t* m;
	m = msg_alloc();
	if(!m) return NULL;
	msg_append_string(m,"ip passthrough");
	msg_append_string(m,op);
	return m;
}
msg_t* nfc_data_channel_setup(int op, int should_broute, int table_id, const char* ims_ip, const char* gw_ip,const char* interface_name, const char* ip, int number_of_dns, char** dns_ip)
{
	int i;
	msg_t* m;
	m = msg_alloc();
	if(!m) return NULL;
	msg_append_string(m,"data channel setup");
	msg_append_string_f(m,"%d",op);	
	msg_append_string_f(m,"%d",should_broute);	
	msg_append_string_f(m,"%d",table_id);
	msg_append_string(m,ims_ip);	
	msg_append_string(m,gw_ip);
	msg_append_string(m,interface_name);	
	msg_append_string(m,ip);	
	msg_append_string_f(m,"%d",number_of_dns);	
	for(i = 0 ;i < number_of_dns ; i++) msg_append_string(m,dns_ip[i]);	
	return m;
}
msg_t* nfc_vpn_passthrough(int gre,int l2tp,int pppoe,int ipsec, int pptp)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"vpn passthrough");
	msg_append_string_f(m,"%d",gre);
	msg_append_string_f(m,"%d",l2tp);
	msg_append_string_f(m,"%d",pppoe);
	msg_append_string_f(m,"%d",ipsec);
	msg_append_string_f(m,"%d",pptp);
	return m;
}

msg_t* nfc_multicast_filter(int number,const char** interface)
{
	int i;
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"multicast filter");
	msg_append_string_f(m,"%d",number);
	for(i = 0;i<number;i++) msg_append_string(m,interface[i]);
	return m;
}
msg_t* nfc_packet_filter(int number,const char** action, const char** interface, const char** protocol, const char** source_ip,const char** source_mask,const char** destination_ip,const char** destination_mask,const char** source_starting_port,const char** source_ending_port,const char** destination_starting_port,const char** destination_ending_port,const char** icmp_type,const char** icmp_code)
{
	int i;
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"packet filter");
	msg_append_string_f(m,"%d",number);
	for(i = 0 ;i< number;i++){
		msg_append_string(m,action[i]);
		msg_append_string(m,interface[i]);
		msg_append_string(m,protocol[i]);
		msg_append_string(m,source_ip[i]);
		msg_append_string(m,source_mask[i]);
		msg_append_string(m,destination_ip[i]);
		msg_append_string(m,destination_mask[i]);
		msg_append_string(m,source_starting_port[i]);
		msg_append_string(m,source_ending_port[i]);
		msg_append_string(m,destination_starting_port[i]);
		msg_append_string(m,destination_ending_port[i]);
		msg_append_string(m,icmp_type[i]);
		msg_append_string(m,icmp_code[i]);
	}
	return m;
}

msg_t* nfc_igmp_filter(int enable)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"igmp filter");
	msg_append_string_f(m,"%d",enable);
	return m;
}
msg_t* nfc_ping_filter(int enable)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"ping filter");
	msg_append_string_f(m,"%d",enable);
	return m;	
}
msg_t* nfc_mgmt_dscp(int enable,int dscp_value,const char* interface)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"mgmt dscp");
	msg_append_string_f(m,"%d",enable);
	msg_append_string_f(m,"%d",dscp_value);
	msg_append_string(m,interface);
	return m;
}
msg_t* nfc_data_dscp(int enable,int dscp_value,const char* interface)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"data dscp");
	msg_append_string_f(m,"%d",enable);
	msg_append_string_f(m,"%d",dscp_value);
	msg_append_string(m,interface);
	return m;
}
msg_t* nfc_voice_dscp(int sip_dscp_enable,int rtp_rtcp_dscp_enable,const char* interface,const char* sip_protocol, const char* sip_dscp_value, const char* rtp_rtcp_dscp_value, int use_pattern_for_rtp_rtcp, const char* pattern_protocol, const char* pattern_ip, const char* pattern_starting_port, const char* pattern_ending_port)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"voice dscp");
	msg_append_string_f(m,"%d",sip_dscp_enable);
	msg_append_string_f(m,"%d",rtp_rtcp_dscp_enable);
	msg_append_string(m,interface);
	msg_append_string(m, sip_protocol);
	msg_append_string(m,sip_dscp_value);
	msg_append_string(m,rtp_rtcp_dscp_value);
	msg_append_string_f(m,"%d",use_pattern_for_rtp_rtcp);
	msg_append_string(m,pattern_protocol);
	msg_append_string(m,pattern_ip);
	msg_append_string(m,pattern_starting_port);
	msg_append_string(m,pattern_ending_port);
	return m;	
}
msg_t* nfc_dscp_tagging_with_timeout(int enable, const char* protocol, const char* media_ip, const char* media_port, const char* dscp_value, const char* interface, int timeout_value)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"dscp tagging with timeout");
	msg_append_string_f(m,"%d",enable);
	msg_append_string(m,protocol);	
	msg_append_string(m,media_ip);	
	msg_append_string(m,media_port);	
	msg_append_string(m,dscp_value);	
	msg_append_string(m,interface);	
	msg_append_string_f(m,"%d",timeout_value);	
	return m;
}
msg_t* nfc_udhcpc(int enable)
{
	
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"udhcpc");
	msg_append_string_f(m,"%d",enable);
	return m;
}
msg_t* nfc_ntp(int enable)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"ntp");
	msg_append_string_f(m,"%d",enable);
	return m;
}
msg_t* nfc_oma(int enable)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"oma");
	msg_append_string_f(m,"%d",enable);
	return m;
}
msg_t* nfc_acs(int enable)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"acs");
	msg_append_string_f(m,"%d",enable);
	return m;
}
msg_t* nfc_snmp(int enable)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"snmp");
	msg_append_string_f(m,"%d",enable);
	return m;
}
msg_t* nfc_dns(int enable)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"dns");
	msg_append_string_f(m,"%d",enable);
	return m;	
}
msg_t* nfc_upnp(int enable)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"upnp");
	msg_append_string_f(m,"%d",enable);
	return m;	
}
msg_t* nfc_telnet(int enable,int num,const char** interfaces)
{
	int i;
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"telnet");
	msg_append_string_f(m,"%d",enable);
	msg_append_string_f(m,"%d",num);
	for(i = 0 ;i<num;i++) msg_append_string(m,interfaces[i]);
	return m;
}
msg_t* nfc_http(int enable,int port)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"http");
	msg_append_string_f(m,"%d",enable);
	msg_append_string_f(m,"%d",port);
	return m;
	
}
msg_t* nfc_https(int enable,int port)
{
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"https");
	msg_append_string_f(m,"%d",enable);
	msg_append_string_f(m,"%d",port);
	return m;
}
msg_t* nfc_port_trigger(int number_of_rule, const char** wan_interfaces, const char** lan_interfaces, const char** wan_starting_port, const char** wan_ending_port, const char** lan_starting_port, const char** lan_ending_port)
{
	int i;
	msg_t* m;
	m = msg_alloc();
	if(!m)return NULL;
	msg_append_string(m,"port trigger");
	msg_append_string_f(m,"%d",number_of_rule);
	for(i = 0;i< number_of_rule ; i++){
		msg_append_string(m,wan_interfaces[i]);
		msg_append_string(m,lan_interfaces[i]);
		msg_append_string(m,wan_starting_port[i]);
		msg_append_string(m,wan_ending_port[i]);
		msg_append_string(m,lan_starting_port[i]);
		msg_append_string(m,lan_ending_port[i]);
	}
	return m;	
}
