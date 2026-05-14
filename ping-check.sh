#!/bin/bash
# ping_check.sh
# Verifies reachability from the Analyzer to all relevant hosts before
# deploying Snort. Pings each target with 3 packets and a 2-second
# timeout, then prints SUCCESS or FAILED per target.

TARGETS=("10.10.*.*" "192.168.*.*" "8.8.8.8")
NAMES=("Attacker (Kali)" "Metasploitable 2" "Google DNS")

echo "================================================="
echo "  Connectivity Check from Analyzer"
echo "================================================="

for i in "${!TARGETS[@]}"; do
    ip="${TARGETS[$i]}"
    name="${NAMES[$i]}"

    if ping -c 3 -W 2 "$ip" > /dev/null 2>&1; then
        echo "  $name ($ip)   -> SUCCESS"
    else
        echo "  $name ($ip)   -> FAILED"
    fi
done

echo "================================================="
