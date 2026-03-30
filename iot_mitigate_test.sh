#!/bin/sh
# Simple iptables wrapper to isolate devices
iptables -A INPUT -s 192.168.1.10 -j DROP
iptables -A FORWARD -s 192.168.1.10 -j DROP
iptables -A INPUT -s 192.168.1.11 -j DROP
iptables -A FORWARD -s 192.168.1.11 -j DROP
