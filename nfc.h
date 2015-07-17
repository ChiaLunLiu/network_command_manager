#ifndef __NFC_H__
#define __NFC_H__
#include <minimsg/minimsg.h>
#define NFC_OK 0
#define NFC_FAIL 1


msg_t*  nfc_mode_setup(const char* network_mode, const char* radio_interface_name, const char* radio_interface_vendor,
      int number_of_ether_interface,const char** eth_interface_names, int number_of_wifi_interface,const  char** wifi_interface_names);

msg_t* nfc_ip_passthrough( const char* op);


msg_t* nfc_access_restriction(int number_of_rule,const char** mac, const char** day,const char** start_time,const char** end_time, const char** url, const char** keyword);

msg_t* nfc_vpn_passthrough(int gre,int l2tp,int pppoe,int ipsec, int pptp);

msg_t* nfc_multicast_filter(int number,const char** interface);

msg_t* nfc_packet_filter(int number,const char** action, const char** interface, const char** protocol, const char** source_ip,const char** source_mask,const char** destination_ip,const char** destination_mask,const char** source_starting_port,const char** source_ending_port,const char** destination_starting_port,const char** destination_ending_port,const char** icmp_type,const char** icmp_code);

msg_t* nfc_igmp_filter(int enable);

msg_t* nfc_ping_filter(int enable);

msg_t* nfc_mgmt_dscp(int enable,int dscp_value,const char* interface);
msg_t* nfc_data_dscp(int enable,int dscp_value,const char* interface);
msg_t* nfc_voice_dscp(int sip_dscp_enable,int rtp_rtcp_dscp_enable,const char* interface,const char* sip_protocol, const char* sip_dscp_value, const char* rtp_rtcp_dscp_value, int use_pattern_for_rtp_rtcp, const char* pattern_protocol, const char* pattern_ip, const char* pattern_starting_port, const char* pattern_ending_port);

msg_t* nfc_dscp_tagging_with_timeout(int enable, const char* protocol, const char* media_ip, const char* media_port, const char* dscp_value, const char* interface, int timeout_value);

msg_t* nfc_udhcpc(int enable);
msg_t* nfc_ntp(int enable);
msg_t* nfc_oma(int enable);
msg_t* nfc_acs(int enable);
msg_t* nfc_snmp(int enable);
msg_t* nfc_dns(int enable);
msg_t* nfc_upnp(int enable);
msg_t* nfc_telnet(int enable,int num,const char** interfaces);
msg_t* nfc_http(int enable,int port);
msg_t* nfc_https(int enable,int port);
msg_t* nfc_port_trigger(int number_of_rule, const char** wan_interfaces, const char** lan_interfaces, const char** wan_starting_port, const char** wan_ending_port, const char** lan_starting_port, const char** lan_ending_port);
msg_t* nfc_port_forwarding(int number_of_rule,const char** interface, const char** wan_port, const char** lan_ip,const char** lan_port);
msg_t* nfc_dmz(int number_of_rule, const char** interfaces, const char** ip);
msg_t* nfc_data_channel_setup(int enable,int should_broute,int table_id,const char* ims_ip, const char* gw_ip, const char* data_subnet, const char* interface, const char* interface_ip,int number_of_dns, const char** dns_ip);
msg_t* nfc_snat(int enable,int id,const char* interface);
msg_t* nfc_interface_basic_setup(int enable, int cid, int should_broute,const char* routing_table_id,const char* ims_ip, const char* gw_ip, const char* interface, const char* interface_ip, int number_of_dns, const char** dns_ip);


/*
msg_t* nfc_voice_channel_setup(const msg_t* m);
msg_t* nfc_mgmt_channel_setup(const msg_t* m);
msg_t* nfc_dhcp(const msg_t* m);
msg_t* nfc_pots(const msg_t* m);
msg_t* nfc_dynamic_qos(const msg_t* m);
msg_t* nfc_vlan_tagging(const msg_t* m);
msg_t* nfc_static_routing(const msg_t* m);
msg_t* nfc_mss_clamping(const msg_t* m);
*/
#endif
