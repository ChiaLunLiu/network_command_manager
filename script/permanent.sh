#!/bin/bash
source ./util.sh

get_current_mode mode
echo "hi"
echo $mode

# mode-independent rule
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

if [ $mode == "NAT" ]; then
	echo "nat"
elif [ $mode == "BRIDGE" ]; then
	echo "bridge"
elif [ $mode == "ROUTER" ]; then
	echo "router"
fi
