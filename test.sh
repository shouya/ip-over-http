#!/bin/bash

killall tcpdump

sleep 0.1

ip route add 188.113.88.193 dev tun0

:> pack.pcap
tcpdump -i tun0 -w pack.pcap &
sleep 0.1
curl -v -k https://ifconfig.co/?cmd=curl &

sleep 5

killall -TERM tcpdump
