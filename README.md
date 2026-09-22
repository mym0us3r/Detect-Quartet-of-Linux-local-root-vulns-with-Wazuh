# LPE Quartet 2026 - Detection with Wazuh 4.14.7

Wazuh + auditd detection rules for four Linux kernel local privilege escalation (LPE) vulnerabilities disclosed together by researcher Asim Manizada, each with a public proof-of-concept exploit.

| Codename | CVE | Subsystem | Local privilege required |
|---|---|---|---|
| DirtyAH6 | CVE-2026-80844 | IPv6 Authentication Header (AH6/XFRM) | Unprivileged user namespace |
| TUNderflow | CVE-2026-81000 | TUN/TAP virtual network devices | Unprivileged user namespace |
| PPPoEject | CVE-2026-68121 | PPPoE (PPP over Ethernet) | Unprivileged user namespace |
| DiagSpill | CVE-2026-74469 | SCTP / sock_diag | **None** - any local user |

## What are these vulnerabilities?

**DirtyAH6 (CVE-2026-80844)** - `ipv6_rearrange_rthdr()` trusts a routing-header segment count without validating it against the number of addresses present. A crafted IPv6 packet moves an internal pointer far out of bounds before a `memmove()` call, corrupting kernel memory.

**TUNderflow (CVE-2026-81000)** - `tun_set_headroom()` stores an oversized headroom value used both as spare space and as a size. The size calculation wraps around (integer underflow), and packet data lands outside its allocated buffer.

**PPPoEject (CVE-2026-68121)** - `pppoe_sendmsg()` keeps a pointer into a network buffer (`skb`) across a call to `dev_hard_header()`, which can free and relocate that buffer via `pskb_expand_head()`. Later writes then hit freed memory - a use-after-free.

**DiagSpill (CVE-2026-74469)** - the `transport_count` field tracking SCTP association peers is a 16-bit counter. The 65,536th transport wraps it back to zero. The `sctp_diag` dump code then reserves space for zero peers but copies the full list, writing roughly 8 MiB past the end of the Netlink response buffer. This is the only one of the four that needs no special privilege or capability - just the SCTP kernel module loaded.

Fixed kernel versions: 5.10.270, 5.15.221, 6.1.188, 6.6.157, 6.12.109, 6.18.50, 7.2.4 and later. Detection here is a compensating control, not a substitute for patching.

## Official References

- [A quartet of Linux local root vulns: DirtyAH6, PPPoEject, TUNderflow, and DiagSpill](https://heyitsas.im/posts/lpe-quartet/) - original write-up (Asim Manizada)
- [Public Exploits Released for Four Linux Kernel Flaws That Enable Local Root](https://thehackernews.com/2026/09/public-exploits-released-for-four-linux.html) - The Hacker News
- [CVE-2026-74469 - Red Hat Customer Portal](https://access.redhat.com/security/cve/cve-2026-74469)
- PoC repositories: [DirtyAH6](https://github.com/manizada/DirtyAH6), [TUNderflow](https://github.com/manizada/TUNderflow), [PPPoEject](https://github.com/manizada/PPPoEject), [DiagSpill](https://github.com/manizada/DiagSpill)

## Why behavioral detection

None of the four bugs leaves a network signature or a file-based IOC to match against - they are kernel memory-safety bugs (out-of-bounds write, integer underflow/overflow, use-after-free) triggered internally by syscalls, not by payload content. Detection here is built on three layers instead:

1. **Common precursor** - three of the four require nothing but an unprivileged user namespace (`unshare`/`setns`). Alone this is a weak signal (legitimately used by Docker, Podman, containerd, systemd-nspawn and browser sandboxing), but it anchors the correlation rules below.
2. **Necessary condition per vulnerability** - creation of the specific socket family/protocol each exploit needs (`AF_INET6`+`SOCK_RAW` and `NETLINK_XFRM` for DirtyAH6, `/dev/net/tun` plus a `netkit`+`headroom` device for TUNderflow, `AF_PPPOX` for PPPoEject, SCTP + `sock_diag` for DiagSpill).
3. **Same-process correlation** - `if_matched_sid` + `same_field` on `audit.pid` escalates severity when the precursor and the vulnerability-specific condition fire from the same process within a short window. This is the highest-confidence signal in the set.

A fourth, low-confidence layer flags execution of binaries named after the public PoC repositories from `/tmp` or `/dev/shm` - trivially evaded by renaming, kept as a hunting signal only.

## Repository Structure

```
LPE-Quartet-Detection-with-Wazuh-4.14.7/
├── rules/
│   └── lpe_quartet.xml        # Wazuh rules 400001-400014
├── auditd/
│   └── lpe-quartet-2026.rules # auditctl syscall sensor rules
├── LICENSE
└── README.md
```

Shipped as its own `lpe_quartet.xml` file rather than folded into `local_rules.xml`, so it sits alongside other topic-specific rule files on the manager (`fail2ban_rules.xml`, `fim_anomaly_rules.xml`) without making `local_rules.xml` grow indefinitely.

## Detection Architecture

Two layers, matching the standard Wazuh + auditd pattern:

- **auditd** watches the relevant syscalls (`unshare`, `setns`, `socket` with specific domain/type/protocol arguments) and file paths (`/dev/net/tun`, the `ip` binary, `/tmp`, `/dev/shm`), tagging each with a dedicated `-k` key.
- **Wazuh** decodes the auditd log (`decoded_as=auditd`, base rule `80700`) and layers atomic signal rules per vulnerability plus composite correlation rules keyed on `audit.pid` and a bounded `timeframe`.

Rule ID range: `400001`-`400014` - a dedicated "400" block for this file (quartet), kept separate from whatever ranges are already in use in `local_rules.xml`, `fail2ban_rules.xml` and `fim_anomaly_rules.xml` on the same manager.

## Deployment

### File placement, ownership and permissions

| File | Host | Path | Owner:Group | Mode |
|---|---|---|---|---|
| `auditd/lpe-quartet-2026.rules` | Every monitored endpoint (Wazuh agent) | `/etc/audit/rules.d/lpe-quartet-2026.rules` | `root:root` | `0640` |
| `rules/lpe_quartet.xml` | Wazuh manager | `/var/ossec/etc/rules/lpe_quartet.xml` | match your existing `local_rules.xml`/`fail2ban_rules.xml` | match your existing files |

The `root:root 0640` value for the auditd rule file is not a guess - it is the exact ownership and mode the `auditd` package itself ships `/etc/audit/rules.d/` and its shipped `.rules` files with (verified against the Ubuntu/Debian `auditd` package contents: the directory is `drwxr-x---` and rule files inside are `-rw-r-----`, both `root:root`). Match that on every distribution.

There is no single official mode/owner published by Wazuh for `/var/ossec/etc/rules/*.xml` that applies identically across every 4.14.7 install (it can differ slightly by install method - package vs source, and by whether SELinux/AppArmor profiles are in play). The reliable way to get it right on your specific manager is to copy the ownership and mode of a file that is already loaded and working there, rather than assume a value:

```bash
# on the Wazuh manager
ls -l /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/fail2ban_rules.xml

cp rules/lpe_quartet.xml /var/ossec/etc/rules/lpe_quartet.xml
chown --reference=/var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/lpe_quartet.xml
chmod --reference=/var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/lpe_quartet.xml
ls -l /var/ossec/etc/rules/lpe_quartet.xml   # confirm it now matches
```

**1. Endpoint (Wazuh agent host)**

```bash
apt install -y auditd    # Debian/Ubuntu
dnf install -y audit     # RHEL/Fedora

cp auditd/lpe-quartet-2026.rules /etc/audit/rules.d/
chown root:root /etc/audit/rules.d/lpe-quartet-2026.rules
chmod 0640 /etc/audit/rules.d/lpe-quartet-2026.rules

augenrules --load
auditctl -l | grep lpe_quartet
```

Add to `ossec.conf`/`agent.conf` if not already present:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

```bash
systemctl restart wazuh-agent
```

**2. Wazuh manager**

```bash
cp rules/lpe_quartet.xml /var/ossec/etc/rules/lpe_quartet.xml
chown --reference=/var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/lpe_quartet.xml
chmod --reference=/var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/lpe_quartet.xml

/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

## Validation

Syntax-checked with `xmllint` and cross-referenced against the official CVE records and vendor advisories listed above. **Not yet validated against live execution of the public PoCs** - that is the recommended next step before production rollout:

1. Run each PoC in an isolated lab VM with a Wazuh agent installed.
2. Confirm `audit.pid` is populated consistently across the correlated event pairs (required for rules `400004`, `400005`, `400008`, `400010`, `400013`).
3. Capture real Discover evidence and tune severity levels/`timeframe` values against actual timing observed.
4. Baseline the `lpe_quartet_userns` and `lpe_quartet_sockdiag` signals against normal container and monitoring-tool activity before enabling in production - see the false-positive notes inline in both rule files.

## Remediation

- Immediate/primary: patch to a kernel version listed above.
- Compensating control while patching is pending: these detection rules, plus disabling the SCTP kernel module (`install sctp /bin/false` in `/etc/modprobe.d/`) on hosts that do not use it, to remove DiagSpill's only precondition.

## Disclosure Timeline

- 2026-09-18: Asim Manizada publishes the combined write-up and PoCs for all four vulnerabilities.
- 2026-09-2x: The Hacker News and other outlets cover the disclosure.
- 2026-09-22: This detection rule set published.
