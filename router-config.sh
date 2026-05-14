#!/bin/bash
# router_config.sh
# Configures the Analyzer machine as a router between two host-only
# networks (VMnet9: 10.10.10.0/24 and VMnet10: 192.168.50.0/24)
# and shares WAN access via the eth0 NAT/bridged interface.
#
# Run on the Analyzer Kali VM. Requires root.

set -e

echo "[*] Enabling IPv4 forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

echo "[*] Adding MASQUERADE rule for WAN egress on eth0..."
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

echo "[*] Allowing FORWARD traffic from eth1 (Attacker LAN) and eth2 (Target LAN)..."
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth2 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth2 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i eth1 -o eth2 -j ACCEPT
sudo iptables -A FORWARD -i eth2 -o eth1 -j ACCEPT

echo "[+] Router configuration complete."
echo "    eth0 (WAN)     : 192.168.10.*"
echo "    eth1 (LAN1)    : 10.10.10.1     -> Attacker (10.10.*.*)"
echo "    eth2 (LAN2)    : 192.168.50.1   -> Metasploitable (192.168.*.*)"
