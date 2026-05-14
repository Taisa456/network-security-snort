# Snort IDS/IPS Deployment Lab

A full-cycle deployment of **Snort 3** as both an Intrusion Detection System (passive monitoring) and an Intrusion Prevention System (active blocking via iptables), validated against four attack vectors across a three-machine virtual network on Kali Linux.

The lab proves the operational distinction between **detection** and **prevention** by running an identical four-vector attack chain twice — first against an IDS that logs but cannot block, then against an IDS + iptables IPS layer that drops attacks selectively while preserving legitimate traffic.

---

## Table of Contents

- [Lab Environment](#lab-environment)
- [Network Topology](#network-topology)
- [Methodology](#methodology)
- [Snort Configuration](#snort-configuration)
- [Custom Detection Rules](#custom-detection-rules)
- [Stage 1 — IDS Mode](#stage-1--ids-mode)
- [Stage 2 — IPS Mode](#stage-2--ips-mode)
- [IDS vs IPS — Side-by-Side Results](#ids-vs-ips--side-by-side-results)
- [Discussion](#discussion)
- [Architecture Note](#architecture-note)
- [Repository Structure](#repository-structure)
- [Reproducing the Lab](#reproducing-the-lab)
- [Ethical Disclaimer](#ethical-disclaimer)
- [License](#license)

---

## Lab Environment

| Component | Details |
|---|---|
| **Analyzer / Router** | Kali Linux — 3 adapters: `eth0` WAN (192.168.10.143, NAT), `eth1` LAN1 (10.10.10.1, host-only), `eth2` LAN2 (192.168.50.1, host-only) |
| **Attacker** | Kali Linux — `eth0` on VMnet9 (10.10.10.10) — default gateway 10.10.10.1 |
| **Target** | Metasploitable 2 — `eth0` on VMnet10 (192.168.50.10) — default gateway 192.168.50.1 |
| **Snort version** | Snort++ 3.12.1.0-0kali1 (installed on Analyzer) |
| **Attack tooling** | Nmap 7.99, Hydra v9.6, Metasploit Framework (`msfconsole`) |
| **Virtualisation** | VMware — VMnet9 = 10.10.10.0/24, VMnet10 = 192.168.50.0/24 (both host-only) |

---

## Network Topology

All traffic between the Attacker and Metasploitable is forced through the Analyzer, making it the natural chokepoint for both monitoring and enforcement.

```
                           ┌─────────────────────────┐
                           │   Analyzer / Router     │
                           │   Kali + Snort 3        │
                           │                         │
   Attacker Kali ──VMnet9──┤ eth1: 10.10.10.1        │
   10.10.10.10             │                         │
                           │ eth0: 192.168.10.143 ───┼──> WAN (NAT)
                           │                         │
   Metasploitable 2 ─VMnet10┤ eth2: 192.168.50.1     │
   192.168.50.10           │                         │
                           └─────────────────────────┘
```

> Replace this ASCII sketch with `screenshots/01-network-topology.png` once you have the figure in place: `![Topology](screenshots/01-network-topology.png)`

---

## Methodology

The lab executes in two stages with an identical four-vector attack chain in each:

1. **ICMP reconnaissance** — `ping` for host discovery
2. **Nmap SYN scan** — `nmap -sS` for port enumeration (1000 ports)
3. **Hydra FTP brute force** — credential attack against the vsftpd service
4. **vsftpd 2.3.4 backdoor** — Metasploit exploit for [CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)

**Stage 1 (IDS)** runs Snort passively on the Analyzer with five custom rules — observe alerts in real time, confirm exploitation proceeds anyway.

**Stage 2 (IPS)** pairs Snort with an `iptables` enforcement layer using surgical drop rules — confirm attacks are blocked while ICMP ping and legitimate FTP login remain functional.

### Pre-deployment setup

1. Configure the Analyzer with three NICs in VMware (two host-only, one NAT/bridged).
2. Enable IP forwarding and add `MASQUERADE` + `FORWARD` rules so the Analyzer routes between subnets and out to the WAN — see `scripts/router_config.sh`.
3. Verify end-to-end connectivity from each VM with `scripts/ping_check.sh` before installing Snort.

---

## Snort Configuration

Snort is installed via the Kali package manager (`sudo apt install snort -y`) and configured in `/etc/snort/snort.conf`:

```lua
HOME_NET = "10.10.10.0/24,192.168.50.0/24"
EXTERNAL_NET = "any"

ips = {
    enable_builtin_rules = true,
    include = "/etc/snort/rules/local.rules",
    variables = default_variables
}

alert_fast = { file = true, packet = false }
```

`HOME_NET` covers both internal subnets so Snort treats all inter-subnet traffic on the Analyzer as worth inspecting. `alert_fast` produces compact one-line alerts (per-packet logging would generate excessive volume).

**Config validation:**

```bash
sudo snort -T -c /etc/snort/snort.conf
# Result: 652 rules loaded (5 custom text + 647 built-in), 0 warnings
```

---

## Custom Detection Rules

Five rules in `/etc/snort/rules/local.rules` (full file in [`scripts/local.rules`](scripts/local.rules)):

| SID | Name | Trigger |
|---|---|---|
| **1000001** | ICMP Ping Detected | Any ICMP traffic in either direction — catches reconnaissance pings |
| **1000002** | FTP Connection Attempt | Any TCP connection to port 21 — catches legitimate and brute force traffic |
| **1000003** | Possible Nmap SYN Scan | TCP packets with **only** the SYN flag set (`flags:S`) — the signature of a half-open scan |
| **1000004** | VSFTPD 2.3.4 Backdoor Attempt | `content:":)"` on FTP port 21 — the exact CVE-2011-2523 trigger string |
| **1000005** | Possible Metasploit Shellcode | `content:"|90 90 90|"` — x86 NOP sled commonly prepended to Metasploit payloads |

---

## Stage 1 — IDS Mode

Snort runs in passive mode on both internal interfaces:

```bash
sudo snort -c /etc/snort/snort.conf -i eth1 -i eth2 \
    -A alert_fast -l /var/log/snort/

# Watch alerts in a second terminal:
sudo tail -f /var/log/snort/alert_fast.txt
```

Startup output confirms `pcap DAQ configured to passive` — Snort sees every packet but cannot drop or modify any of them.

### IDS Results

After executing `scripts/attack_simulator.sh` from the Attacker:

| Attack | Detection | Outcome |
|---|---|---|
| ICMP recon | ✅ SID 1000001 — bidirectional alerts | Ping completed |
| Nmap SYN scan | ✅ SID 1000003 — thousands of alerts in <1 second | **23 open ports enumerated** |
| Hydra FTP brute force | ✅ SID 1000002 — repeated FTP connection alerts | **`msfadmin:msfadmin` credentials cracked** |
| vsftpd 2.3.4 backdoor | ✅ SID 1000004 — `:)` content match fired | **Root Meterpreter shell obtained** |

> **The IDS detected everything and stopped nothing.** This is the central lesson of Stage 1: a working IDS without enforcement is an alarm system, not a lock. By the time a human analyst reads the alerts, the attacker is already root.

A secondary observation: Snort's built-in rules (`116:408`, `116:414`) fire on DHCP broadcast traffic — not malicious, but in a production deployment they'd need suppression rules to keep the alert log actionable.

---

## Stage 2 — IPS Mode

The IPS layer is deployed with [`scripts/ips_setup.sh`](scripts/ips_setup.sh), which:

1. Flushes existing iptables rules
2. Re-enables IP forwarding and re-applies baseline routing
3. Applies four surgical drop rules targeting specific attack signatures
4. Launches Snort in daemon mode (`-D`) for continued logging

### iptables Rules

| Rule | What it does |
|---|---|
| `ACCEPT icmp` | Explicitly allows all ICMP — preserves connectivity checks |
| `DROP tcp dpt:21 STRING ":)"` | Drops packets containing the vsftpd 2.3.4 backdoor trigger on port 21 |
| `ACCEPT tcp --syn -m limit --limit 10/s --limit-burst 20` | Allows normal TCP handshakes within rate limit |
| `DROP tcp --syn` (after limit) | Drops SYN floods exceeding 10/s — defeats Nmap SYN scans |
| `DROP tcp dpt:21 -m connlimit --connlimit-above 5 --connlimit-mask 32` | Blocks > 5 concurrent FTP connections per source — defeats Hydra's parallelism |
| `ACCEPT eth1→eth0`, `ACCEPT eth2→eth0` | Normal egress routing |
| `ACCEPT -m conntrack --ctstate RELATED,ESTABLISHED` | Stateful — preserves established sessions |

### IPS Results

The same attack script was re-run from the Attacker:

| Attack | Stage 2 outcome |
|---|---|
| ICMP recon | ✅ Allowed (intentional) |
| **Nmap SYN scan** | ❌ **Blocked** — `1000 filtered tcp ports (no-response)`, scan took 21.71 s instead of <1 s |
| **Hydra FTP brute force** | ❌ **Blocked** — `all children were disabled due too many connection errors — 0 valid password found` |
| **vsftpd backdoor** | ❌ **Blocked** — `Rex::ConnectionTimeout — Exploit completed, but no session was created` |

### Normal traffic preserved

Two manual checks confirmed selective enforcement:

- `ping -c 4 192.168.50.10` → 4 packets transmitted, 4 received, 0% loss
- `ftp 192.168.50.10` with `msfadmin:msfadmin` → `220 (vsFTPd 2.3.4)` … `230 Login successful`

Quantitative proof from iptables packet counters during the run: **2051 packets accepted, 12 packets dropped by the FTP connlimit rule, 808 ICMP packets accepted** — selective enforcement in numbers.

### Continued Snort logging

Even in IPS mode, Snort continued to fire SID 1000002 / 1000003 alerts on packets that reached its passive inspection point before iptables dropped subsequent ones — meaning **iptables provides enforcement while Snort provides audit logging**, operating in tandem.

---

## IDS vs IPS — Side-by-Side Results

| Attack / Traffic | Stage 1 (IDS only) | Stage 2 (IDS + iptables IPS) |
|---|---|---|
| ICMP ping | Detected ✅ | Allowed ✅ (intentional) |
| Nmap SYN scan | Detected — **23 open ports found** | **Blocked** — 1000 filtered |
| Hydra FTP brute force | Detected — **`msfadmin:msfadmin` cracked** | **Blocked** — 0 passwords found |
| vsftpd 2.3.4 exploit | Detected — **Root Meterpreter shell** | **Blocked** — connection timeout |
| Legitimate FTP login | n/a | Preserved (`230 Login successful`) |

---

## Discussion

### Were all simulated attacks detected in IDS mode?

Yes — every one of SIDs 1000001–1000004 fired correctly during the attack simulation:

- **ICMP ping (1000001)** — bidirectional alerts for every echo/reply.
- **Nmap SYN scan (1000003)** — flood of alerts within milliseconds, characteristic source-port randomisation.
- **FTP brute force (1000002)** — clean audit trail of Hydra's parallel connection attempts with exact timestamps.
- **vsftpd backdoor (1000004)** — the `:)` content match caught the exact exploit byte sequence.

**But detection ≠ prevention.** The vsftpd exploit opened a root Meterpreter shell while every alert was firing. A SOC analyst watching the IDS in real time would have *seen* the compromise — but with the attacker already root in seconds, alerting alone is not enough. This is the operational core of why IPS exists.

### How effective was IPS at blocking attacks without breaking normal traffic?

The implementation achieved complete attack mitigation with zero observable impact on legitimate traffic. The effectiveness comes from **surgical rule design** — each iptables rule targets a behavioral signature, not a broad protocol:

- **SYN rate-limit** breaks the *flood pattern* of port scans without affecting normal handshakes.
- **`connlimit` per source** blocks the *parallelism* of brute force tools without breaking single-session FTP.
- **`STRING` match** drops the *exact exploit payload* without filtering legitimate FTP login traffic.

One acknowledged limitation: ICMP is fully allowed, which means an attacker can still confirm Metasploitable is alive via ping. In a higher-security environment this would be rate-limited or restricted to trusted sources. In this lab, ICMP is the primary connectivity verification mechanism, so it stays open.

### Dedicated Snort machine vs. pfSense/OPNsense plugin

This lab uses a dedicated Snort machine. Compared to running Snort as a plugin inside a firewall appliance like pfSense or OPNsense:

**Advantages of the dedicated approach:**

- **Performance isolation** — full CPU and RAM available exclusively for packet inspection; no contention with routing, DHCP, VPN, DNS.
- **Positioning flexibility** — the IDS/IPS can sit inline, on a SPAN/mirror port, or at an internal segment boundary to monitor east-west traffic that never reaches the perimeter firewall.
- **Full configuration control** — every preprocessor, DAQ setting, output plugin, and rule update schedule is configurable via CLI. pfSense exposes only a subset through its GUI.
- **Resilience** — the IDS/IPS machine can fail-open or fail-closed independently of the router. In pfSense, a Snort crash takes down both routing and detection at once.

**Trade-offs:**

- **Steeper learning curve** — requires CLI proficiency and direct rule-set management.
- **Maintenance overhead** — rule updates, version upgrades, log rotation, all manual.

Dedicated Snort is the correct choice for enterprise environments needing performance, positioning, and customisation. The pfSense/OPNsense plugin approach makes more sense for small business or home lab environments prioritising ease of use.

---

## Architecture Note

Stage 2 is technically **passive Snort + iptables enforcement**, not Snort running in true inline mode — Snort itself logs (`pcap DAQ configured to passive`), and `iptables` performs the dropping based on rate limits, string matches, and connection counts.

This is a legitimate and common deployment pattern (it's how many real-world Linux-based IDS/IPS stacks operate). A natural follow-up would be migrating Stage 2 to a true inline configuration using `snort --daq nfq` (or `afpacket` in inline mode) with Snort's `reject` / `drop` rule actions, so Snort itself performs the dropping based on full signature matching rather than delegating to iptables.

---

## Repository Structure

```
snort-ids-ips-lab/
├── README.md                       ← this file
├── report/
│   ├── Snort-IDS-IPS-Report.pdf    ← full lab report
│   └── Snort-IDS-IPS-Report.docx   ← editable source
├── scripts/
│   ├── router_config.sh            ← IP forwarding + iptables routing
│   ├── ping_check.sh               ← connectivity verification
│   ├── attack_simulator.sh         ← 4-vector attack chain
│   ├── ips_setup.sh                ← IPS iptables rules + Snort daemon
│   └── local.rules                 ← 5 custom Snort rules (SID 1000001-1000005)
├── screenshots/                    ← report figures
├── .gitignore
└── LICENSE
```

---

## Reproducing the Lab

> ⚠️ **Lab use only.** These scripts run real exploits and brute-force tools against a deliberately vulnerable target. Do not run them against any system you do not own and have explicit written authorisation to test.

1. Build three VMs in VMware per the topology above (VMnet9 and VMnet10 as host-only).
2. On the **Analyzer**: run `scripts/router_config.sh`, then `scripts/ping_check.sh` to confirm full connectivity.
3. Install Snort 3 on the Analyzer:
   ```bash
   sudo apt update && sudo apt install snort -y
   ```
4. Place `scripts/local.rules` at `/etc/snort/rules/local.rules` and set `HOME_NET = "10.10.10.0/24,192.168.50.0/24"` in `/etc/snort/snort.conf`.
5. Validate: `sudo snort -T -c /etc/snort/snort.conf` — expect 652 rules loaded, 0 warnings.
6. **Stage 1 — IDS:**
   ```bash
   sudo snort -c /etc/snort/snort.conf -i eth1 -i eth2 -A alert_fast -l /var/log/snort/
   # In another terminal:
   sudo tail -f /var/log/snort/alert_fast.txt
   ```
   On the Attacker: `sudo ./scripts/attack_simulator.sh` — observe alerts firing and the Meterpreter shell.
7. **Stage 2 — IPS:** on the Analyzer, run `sudo ./scripts/ips_setup.sh`, then re-run the attack chain on the Attacker. Confirm blocks, then manually test:
   ```bash
   ping -c 4 192.168.50.10        # should succeed
   ftp 192.168.50.10              # msfadmin / msfadmin — should succeed
   ```

---

## Ethical Disclaimer

All activities documented in this repository were conducted exclusively within a self-contained VMware virtual lab environment for supervised academic learning purposes. No external, production, or real-world systems were targeted, scanned, or affected in any way. Metasploitable 2 is an intentionally vulnerable virtual machine designed specifically for security training.

**This material must not be used to replicate these activities against any real system without explicit written authorisation from the system owner.** Unauthorised port scanning, credential attacks, or exploitation of network services is illegal in most jurisdictions.

---

## License

MIT — see [LICENSE](LICENSE). The lab report itself is provided for educational reference.
