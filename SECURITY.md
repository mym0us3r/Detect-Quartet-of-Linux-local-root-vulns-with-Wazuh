# Security Policy

## Scope

This repository contains **defensive detection content** for Wazuh: detection rules, an auditd sensor configuration, and an SCA policy for four Linux kernel local privilege escalation vulnerabilities (the LPE Quartet: CVE-2026-80844, CVE-2026-81000, CVE-2026-68121, CVE-2026-74469).

It does **not** contain exploit code. The proof-of-concept exploits referenced in the README are third-party projects hosted in their authors' own repositories and are outside the scope of this policy.

## Reporting a kernel vulnerability

The four CVEs covered here are upstream Linux kernel flaws. If you have found a **new** kernel vulnerability, do not report it here. Report it to the Linux kernel security team (`security@kernel.org`) and to your distribution's security contact.

## Reporting an issue with the detection content

Report privately, not in a public issue, if you find:

- a way to run any of the four exploitation chains without triggering the rules (a detection bypass);
- a rule, auditd configuration, or SCA check that exposes sensitive data or weakens the host it is deployed on;
- a false negative or false positive with security impact.

Use GitHub's private vulnerability reporting: **Report a vulnerability** under the repository's **Security** tab. Include the rule ID or file, the Wazuh and kernel versions, and the audit event or steps to reproduce.

Non-security issues (a noisy rule, a documentation fix, a new distribution to support) can go in a normal public issue.

## Supported versions

The detection content is validated against the Wazuh and Ubuntu versions stated in the README. Rules are provided as-is under the MIT license, with no maintenance SLA.

## Coordinated disclosure

Please allow reasonable time to review and, where applicable, correct the detection content before disclosing a bypass publicly.
