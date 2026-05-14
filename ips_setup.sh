#!/bin/bash
# ips_setup.sh
# Deploys the IPS layer on the Analyzer: clears existing iptables
# rules, re-enables routing, applies surgical drop rules that target
# the specific signatures of each attack vector, and finally launches
# Snort in daemon mode for continued detection logging.
#
# Run on the Analyzer Kali VM. Requires root.

set -e

echo "[*] Flushing existing iptables rules..."
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X
sudo iptables -P FORWARD ACCEPT

echo "[*] Re-enabling IPv4 forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1

# -------------------------------------------------------------------
# Re-apply baseline routing (NAT + forward)
# -------------------------------------------------------------------
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth2 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# -------------------------------------------------------------------
# 1. Allow ICMP — preserves ping for legitimate connectivity tests
# -------------------------------------------------------------------
echo "[*] Allowing ICMP (ping remains functional)..."
sudo iptables -A FORWARD -p icmp -j ACCEPT

# -------------------------------------------------------------------
# 2. Block the vsftpd 2.3.4 backdoor by matching the ':)' trigger
#    string in the FTP USER payload on port 21.
# -------------------------------------------------------------------
echo "[*] Blocking vsftpd 2.3.4 backdoor (string match ':)')..."
sudo iptables -A FORWARD -p tcp --dport 21 \
    -m string --algo bm --string ":)" -j DROP

# -------------------------------------------------------------------
# 3. Rate-limit TCP SYN packets to break Nmap SYN scans
#    (legitimate handshakes pass; floods are dropped).
# -------------------------------------------------------------------
echo "[*] Rate-limiting TCP SYN to defeat SYN scans (10/s burst 20)..."
sudo iptables -A FORWARD -p tcp --syn \
    -m limit --limit 10/s --limit-burst 20 -j ACCEPT
sudo iptables -A FORWARD -p tcp --syn -j DROP

# -------------------------------------------------------------------
# 4. Cap concurrent FTP connections per source to stop Hydra
# -------------------------------------------------------------------
echo "[*] Blocking FTP brute force (connlimit > 5 per source)..."
sudo iptables -A FORWARD -p tcp --dport 21 \
    -m connlimit --connlimit-above 5 --connlimit-mask 32 -j DROP

# -------------------------------------------------------------------
# Display final rules
# -------------------------------------------------------------------
echo ""
echo "================================================="
echo "  Active FORWARD chain:"
echo "================================================="
sudo iptables -L FORWARD -n -v --line-numbers

# -------------------------------------------------------------------
# Start Snort in daemon mode for continued detection logging
# -------------------------------------------------------------------
echo ""
echo "[*] Starting Snort in daemon mode..."
sudo snort -c /etc/snort/snort.conf \
           -i eth1 -i eth2 \
           -A alert_fast \
           -l /var/log/snort/ \
           -D

echo ""
echo "[+] IPS MODE ACTIVE — Snort logging to: /var/log/snort/alert_fast.txt"
