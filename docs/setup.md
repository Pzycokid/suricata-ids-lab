# Live Lab Setup

All traffic stays on a host-only network that you own.

## 1. Virtual machines

| VM | Purpose |
|---|---|
| Ubuntu 22.04 (sensor) | Runs Suricata; its network adapter is in promiscuous mode |
| Ubuntu 22.04 (target) | Runs SSH (and optionally FTP / a web server) |
| Kali Linux | Generates test traffic |

In VirtualBox: put all three on the same host-only network and set the sensor adapter's
**Promiscuous Mode** to **Allow All** so it sees traffic between the other two.

## 2. Install Suricata on the sensor

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install -y suricata
```

In `/etc/suricata/suricata.yaml`:
- set `HOME_NET: "[192.168.56.0/24]"` (your host-only subnet)
- under `af-packet`, set `interface:` to the sensor's lab interface (e.g. `enp0s8`)
- under `rule-files`, add the full path to this repo's `rules/local.rules`

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml      # test config
sudo systemctl restart suricata
sudo tail -f /var/log/suricata/fast.log              # watch alerts live
```

## 3. Generate traffic from Kali (against your own target VM only)

| Rule | Command on Kali |
|---|---|
| SYN scan (1000001) | `sudo nmap -sS 192.168.56.10` |
| NULL / XMAS scan (1000002 / 1000003) | `sudo nmap -sN 192.168.56.10` and `sudo nmap -sX 192.168.56.10` |
| Ping sweep (1000004) | `sudo nmap -sn 192.168.56.0/24` |
| SSH brute force (1000010) | Run `ssh wronguser@192.168.56.10` repeatedly with wrong passwords |
| DNS abused TLD (1000030) | `nslookup something.zip` from a lab host |

## 4. Review

```bash
python3 tools/eve_summary.py /var/log/suricata/eve.json
```

Take a screenshot of each alert for the repo, and note any false positives you see.
