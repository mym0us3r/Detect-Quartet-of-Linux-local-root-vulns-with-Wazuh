# LPE Quartet Detection with Wazuh 4.14.7

> **Detection engineering for four Linux kernel local privilege escalation flaws · DirtyAH6 / TUNderflow / PPPoEject / DiagSpill · Ubuntu 24.04**

![rules](https://img.shields.io/badge/wazuh_rules-15-brightgreen)
![status](https://img.shields.io/badge/status-lab--validated-success)
![mitre](https://img.shields.io/badge/MITRE-T1068-red)
![cve1](https://img.shields.io/badge/CVE-2026--80844-critical)
![cve2](https://img.shields.io/badge/CVE-2026--81000-critical)
![cve3](https://img.shields.io/badge/CVE-2026--68121-critical)
![cve4](https://img.shields.io/badge/CVE-2026--74469-critical)

---

## What is the LPE Quartet?

On 2026-09-18, Asim Manizada disclosed four independent local privilege escalation (LPE) vulnerabilities in the Linux kernel networking stack, each with a public proof-of-concept (PoC) exploit:

| Name | CVE | Subsystem | Root cause |
|---|---|---|---|
| DirtyAH6 | CVE-2026-80844 | IPv6 Authentication Header (AH6/XFRM) | `ipv6_rearrange_rthdr()` trusts the routing header segment count without validating `segments_left`, moving a pointer out of bounds before `memmove()` |
| TUNderflow | CVE-2026-81000 | TUN/TAP | `tun_set_headroom()` stores headroom without bounds checks; a `netkit` device with 4,096 bytes of headroom under VXLAN and an Open vSwitch datapath underflows `SKB_MAX_HEAD` |
| PPPoEject | CVE-2026-68121 | PPPoE | `pppoe_sendmsg()` keeps a pointer to the `skb` head across `dev_hard_header()`, which can call `pskb_expand_head()` and free it (use-after-free) |
| DiagSpill | CVE-2026-74469 | SCTP / `sock_diag` | The 16-bit SCTP `transport_count` overflows to zero at transport 65,536; `sctp_diag` reserves space for zero peers but copies the full list, writing about 8 MiB past the Netlink reply |

Three of the four require only an **unprivileged user namespace**. DiagSpill requires **no namespace and no special capability**, only the SCTP module and `sctp_diag` available.

> Discovered and published by **Asim Manizada**.

---

## Official References

| Resource | Link |
|---|---|
| Original research - A quartet of Linux local root vulns | https://heyitsas.im/posts/lpe-quartet/ |
| The Hacker News coverage | https://thehackernews.com/2026/09/public-exploits-released-for-four-linux.html |
| Red Hat - CVE-2026-74469 | https://access.redhat.com/security/cve/cve-2026-74469 |
| PoC - DirtyAH6 | https://github.com/manizada/DirtyAH6 |
| PoC - TUNderflow | https://github.com/manizada/TUNderflow |
| PoC - PPPoEject | https://github.com/manizada/PPPoEject |
| PoC - DiagSpill | https://github.com/manizada/DiagSpill |
| Wazuh - Audit configuration | https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html |
| Wazuh - Rules syntax | https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html |
| MITRE ATT&CK T1068 | https://attack.mitre.org/techniques/T1068/ |

---

## Why This Repo Exists

All four flaws corrupt kernel memory. Nothing is written to disk that file integrity monitoring could compare against a baseline, and the exploitation primitives are ordinary syscalls available to unprivileged users: namespace creation, socket creation with a specific family/protocol, and Netlink queries.

**Detection has to be behavioral**, at the syscall level. This repository provides auditd sensor rules and Wazuh detection rules built on three axes:

```
Axis 1 - Common precursor     unprivileged user namespace (unshare / setns)
Axis 2 - Required condition   socket family / protocol / device each exploit needs
Axis 3 - Correlation          precursor + condition in the same login session (audit.session)
Axis 4 - Low-confidence IOC   execution of binaries named after the public PoCs from /tmp or /dev/shm
```

---

## Exploit Prerequisites Observed by the Sensor

```
DirtyAH6    unshare/setns -> socket(AF_NETLINK, NETLINK_XFRM) -> socket(AF_INET6, SOCK_RAW)
TUNderflow  unshare/setns -> /dev/net/tun + socket(AF_NETLINK, NETLINK_ROUTE) (netkit / VXLAN setup)
PPPoEject   unshare/setns -> socket(AF_PPPOX)
DiagSpill   socket(SCTP)  -> socket(AF_NETLINK, NETLINK_SOCK_DIAG) query
```

---

## Affected Kernels and Fixed Versions

The fix is available in the following stable kernels and later:

| Branch | Fixed in |
|---|---|
| 5.10 | 5.10.270 |
| 5.15 | 5.15.221 |
| 6.1 | 6.1.188 |
| 6.6 | 6.6.157 |
| 6.12 | 6.12.109 |
| 6.18 | 6.18.50 |
| 7.2 | 7.2.4 |

### Lab Kernels Used for Validation

Each PoC fingerprints an exact kernel build. Kernels were selected per test with `grub-reboot`.

| CVE | Target kernel (Ubuntu 24.04.5 LTS) | Result |
|---|---|---|
| DirtyAH6 | 6.8.0-134-generic | ROOT CONFIRMED |
| TUNderflow | 6.17.0-40-generic | ROOT CONFIRMED |
| PPPoEject | 6.8.0-136-generic | NOT REPRODUCED |
| DiagSpill | 6.17.0-35-generic | REPRODUCED |

---

## Repository Structure

```
LPE-Quartet-Detection-with-Wazuh-4.14.7/
│
├── rules/
│   └── lpe_quartet.xml              # 15 Wazuh detection rules (400001-400015)
│
├── auditd/
│   └── lpe-quartet-2026.rules       # auditd syscall and watch sensor rules
│
├── docs/                            # Wazuh Discover validation evidence
│
├── LICENSE                          # MIT
└── README.md
```

---

## Detection Architecture

### Layer 1 - auditd Sensor Keys

All syscall rules filter on `uid!=0`, covering interactive users, service accounts and processes without a login session.

| auditd key | Type | Observes |
|---|---|---|
| `lpe_quartet_userns` | syscall | `unshare` / `setns` (common precursor) |
| `lpe_quartet_rawv6` | syscall | `socket` AF_INET6 raw (DirtyAH6) |
| `lpe_quartet_xfrm` | syscall | `socket` AF_NETLINK / NETLINK_XFRM (DirtyAH6) |
| `lpe_quartet_tun` | watch | `/dev/net/tun` access (TUNderflow) |
| `lpe_quartet_netlink_route` | syscall | `socket` AF_NETLINK / NETLINK_ROUTE (TUNderflow) |
| `lpe_quartet_netcfg` | watch | network configuration binaries (`ip`) |
| `lpe_quartet_pppox` | syscall | `socket` AF_PPPOX (PPPoEject) |
| `lpe_quartet_sctp` | syscall | `socket` with SCTP protocol (DiagSpill) |
| `lpe_quartet_sockdiag` | syscall | `socket` AF_NETLINK / NETLINK_SOCK_DIAG (DiagSpill) |
| `lpe_quartet_tmp_exec` | watch | execution from `/tmp` and `/dev/shm` (IOC) |

### Layer 2 - Wazuh Rule Chain

| Rule | CVE | Type | Signal | Status |
|---|---|---|---|---|
| **400001** | All (except DiagSpill) | Base | Unprivileged user namespace (`lpe_quartet_userns`) | CONFIRMED |
| **400002** | DirtyAH6 | Base | Raw IPv6 socket (`lpe_quartet_rawv6`) | CONFIRMED (via 400004) |
| **400003** | DirtyAH6 | Base | NETLINK_XFRM socket (`lpe_quartet_xfrm`) | CONFIRMED (via 400005) |
| **400004** | DirtyAH6 | Correlation | userns + raw IPv6 socket, same session | CONFIRMED |
| **400005** | DirtyAH6 | Correlation | userns + NETLINK_XFRM socket, same session | CONFIRMED |
| **400006** | TUNderflow | Base | `/dev/net/tun` access (`lpe_quartet_tun`) | CONFIRMED (manual `open()`) |
| **400007** | TUNderflow | Base | Network configuration / netkit setup (`lpe_quartet_netcfg`) | NOT CONFIRMED |
| **400008** | TUNderflow | Correlation | userns + (`/dev/net/tun` or NETLINK_ROUTE), same session | CONFIRMED |
| **400009** | PPPoEject | Base | AF_PPPOX socket (`lpe_quartet_pppox`) | NOT REPRODUCED |
| **400010** | PPPoEject | Correlation | userns + AF_PPPOX socket, same session | NOT REPRODUCED |
| **400011** | DiagSpill | Base | SCTP socket (`lpe_quartet_sctp`) | CONFIRMED |
| **400012** | DiagSpill | Base | NETLINK_SOCK_DIAG query (`lpe_quartet_sockdiag`) | CONFIRMED |
| **400013** | DiagSpill | Correlation | SCTP socket + sock_diag query, same session | NOT CONFIRMED |
| **400014** | All | IOC | PoC-named binary executed from `/tmp` or `/dev/shm` | CONFIRMED |
| **400015** | TUNderflow | Base | NETLINK_ROUTE socket (`lpe_quartet_netlink_route`) | FIRED (legitimate tooling only) |

Status criterion: **CONFIRMED** only when the rule fired in Wazuh Discover from a real PoC execution (or, where stated, a manual trigger of the same syscall). `wazuh-logtest` results are not counted as validation.

> **Engineering note**: All correlation rules bind on `same_field` `audit.session`, not `audit.pid`. The DirtyAH6 PoC spreads its steps across different processes (e.g. `esp_receiver` and `ah6_sender`, distinct PIDs) inside the same login session, so a PID-bound correlation never matches the real exploit chain.

---

## Deployment

### Step 1 - Install auditd

```bash
# Ubuntu / Debian
apt install auditd audispd-plugins -y
systemctl enable --now auditd
auditctl -s | grep enabled
```

```bash
# RHEL / Amazon Linux
yum install audit -y
systemctl enable --now auditd
```

### Step 2 - Deploy auditd sensor rules

```bash
cp auditd/lpe-quartet-2026.rules /etc/audit/rules.d/
augenrules --load
auditctl -l | grep lpe_quartet
```

Every key listed in [Layer 1](#layer-1---auditd-sensor-keys) must appear in the output.

> **Rule overlap**: if another project on the same host already loads auditd rules with the same syscall and the same filter fields (`arch=b64` + `uid!=0`), review both files before loading. In the lab, `lpe_quartet_userns` produced no events while an older rule set with matching filters was loaded, and started firing once that rule set was removed. Where another rule set already covers the syscall, reuse its key instead of duplicating it.

### Step 3 - Deploy Wazuh detection rules

```bash
cp rules/lpe_quartet.xml /var/ossec/etc/rules/lpe_quartet.xml
chown wazuh:wazuh /var/ossec/etc/rules/lpe_quartet.xml
chmod 660 /var/ossec/etc/rules/lpe_quartet.xml
```

```bash
# Validate syntax - must exit 0 with zero warnings
/var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5

# Restart manager
systemctl restart wazuh-manager
```

### Step 4 - Configure ossec.conf localfile

Ensure the agent ingests the auditd log:

```xml
<!-- Add inside <ossec_config> -->
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

```bash
systemctl restart wazuh-agent
```

---

## Validation

### Quick test (no exploit)

```bash
# Rule 400006 - /dev/net/tun watch
cat /dev/net/tun

# Verify auditd captured the event
ausearch -k lpe_quartet_tun -ts recent 2>/dev/null | grep "key=\|exe=\|uid=" | head -5

# Verify Wazuh generated the alert
grep -E "400006" /var/ossec/logs/alerts/alerts.log | tail -10
```

### Verify all sensor keys after a PoC run

```bash
for k in userns rawv6 xfrm tun netlink_route netcfg pppox sctp sockdiag tmp_exec; do
  printf '%-22s %s\n' "lpe_quartet_$k" "$(ausearch -k lpe_quartet_$k -ts today 2>/dev/null | grep -c '^----')"
done
```

---

## Production Validation Evidence

Lab: Wazuh manager 4.14.7, agent on Ubuntu 24.04.5 LTS. PoCs executed from unprivileged users (`uid!=0`).

### DirtyAH6 - CVE-2026-80844 (kernel 6.8.0-134-generic)

Full chain in the same login session (`ses=1`), root obtained:

| Time (UTC) | Rule | Key | Process |
|---|---|---|---|
| 17:26:49.598 | 400001 | `lpe_quartet_userns` | `/usr/bin/nsenter` |
| 17:26:49.607 | 400005 | `lpe_quartet_xfrm` | `esp_receiver` (pid 5447) |
| 17:26:51.093 | 400004 | `lpe_quartet_rawv6` | `ah6_sender` (pid 5457) |

![DirtyAH6 - exploit chain](docs/dirtyah6_chain.png)

---

### TUNderflow - CVE-2026-81000 (kernel 6.17.0-40-generic)

Root obtained. Correlation `400001` -> `400008` in the same login session (`ses=1`):

![TUNderflow - exploit chain](docs/tunderflow_chain.png)

Rule `400006` validated separately with a manual `open()` on `/dev/net/tun` (`exe=/usr/bin/cat`):

![TUNderflow - /dev/net/tun watch](docs/tunderflow_dev_net_tun.png)

---

### DiagSpill - CVE-2026-74469 (kernel 6.17.0-35-generic)

Executed from a dedicated unprivileged user with no `sudo`, `lxd` or `adm` membership. Rules `400011` (SCTP socket), `400012` (sock_diag query) and `400014` (PoC-named binary in `/tmp`) fired:

![DiagSpill - base rules](docs/diagspill_bases.png)

---

### PPPoEject - CVE-2026-68121 (kernel 6.8.0-136-generic)

The PoC aborts before creating the AF_PPPOX socket, so `400009` / `400010` did not fire. Only the shared precursor `400001` was observed. Progressing past the PoC's early checks required booting with `nopti` and `nokaslr`, which disable default kernel mitigations; even then it stopped during memory layout preparation.

---

## Known Limitations

1. **DirtyAH6 fallback path.** The PoC has two code paths. The active exploitation path creates the raw IPv6 socket and fires the full chain. When the PoC reports the target as already patched, it still escalates to root through a fallback path that generated no events on any `lpe_quartet_*` key (same kernel, `lost=0`). `lpe_quartet_rawv6` covers active exploitation only.
2. **Base rules are noisy by themselves.** `400015` (NETLINK_ROUTE) fires from `/usr/bin/ip`, `apt`, `sudo`, `fwupdmgr` and `systemd-tmpfiles`; `lpe_quartet_xfrm` fires from `ip xfrm`. `400012` also fires from `ss` and routine monitoring tools. Triage on the correlation rules, not on the base rules alone.
3. **Cross-triggering between CVEs.** `400008` (TUNderflow) also fired during a DirtyAH6 run, because that PoC calls `/usr/bin/ip` inside the user namespace, which creates a NETLINK_ROUTE socket in the same session. Treat `400008` as "user namespace + network configuration", not as TUNderflow-specific evidence.
4. **TUNderflow and `400006`.** The TUNderflow PoC does not produce an observable `open()` on `/dev/net/tun`, so `400006` is a prerequisite indicator, not a trigger of the exploit flow. The detection signal is `400001` -> `400008`.
5. **DiagSpill correlation.** `400013` does not fire against the real PoC event sequence (one SCTP socket, a burst of sock_diag queries, then another SCTP socket). DiagSpill is detected by its base rules `400011` and `400012`.
6. **Path watches and reboots.** auditd `-w` watches bind to the inode at load time. For device nodes recreated at boot, such as `/dev/net/tun`, run `augenrules --load` after boot and confirm with `auditctl -l` before validating.
7. **`audit.session` in the index.** `audit.pid`, `audit.ppid` and `audit.session` are decoded by the auditd decoder and are available to rules, but are not surfaced as `data.audit.*` fields in the Discover index. Session correlation is visible in the rule description, not as a searchable field.

---

## Remediation

Detection via auditd is a compensating control and does not replace the patch.

### Permanent fix

Upgrade to a fixed kernel (see [Affected Kernels and Fixed Versions](#affected-kernels-and-fixed-versions)) through your distribution's kernel update:

```bash
# Ubuntu / Debian
apt update && apt upgrade linux-generic

# RHEL / Amazon Linux
dnf update kernel
```

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-09-18 | Public disclosure by Asim Manizada, with PoCs for all four vulnerabilities |

---

## Comparison Across the Quartet

| | DirtyAH6 | TUNderflow | PPPoEject | DiagSpill |
|---|---|---|---|---|
| Bug class | Out-of-bounds write | Integer underflow | Use-after-free | Integer overflow / heap overflow |
| Unprivileged userns required | Yes | Yes | Yes | No |
| Remote impact | DoS only (IPv6 AH transport-mode gateways) | None | None | DoS only (non-default SCTP options) |
| Lab result | Root confirmed | Root confirmed | Not reproduced | Reproduced |
| Primary detection | 400004 / 400005 | 400001 -> 400008 | 400001 (precursor) | 400011 / 400012 |

---

## Author

**Kislley Rodrigues (m0us3r)**
Wazuh Ambassador | Detection Engineering | Blue Team

---

## Acknowledgments

- **Asim Manizada** for the discovery, write-up and public PoCs of the LPE Quartet
- **Wazuh Team** for the open SIEM/XDR platform and Ambassador Program

---

*Detection rules and auditd sensor configuration validated on Wazuh 4.14.7, Ubuntu 24.04.5 LTS (kernels 6.8.0-134-generic, 6.17.0-40-generic, 6.17.0-35-generic and 6.8.0-136-generic).*

---

## Wazuh

This project was developed as part of the [Wazuh Ambassador Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).

Wazuh is a free, open source security platform that provides unified XDR and SIEM protection.
Learn more at [wazuh.com](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program).
