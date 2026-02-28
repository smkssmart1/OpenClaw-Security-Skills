# OpenClaw Security Skills Collection

Comprehensive security skill suite for OpenClaw AI agent infrastructure. Curated by **Inspiratek** for enterprise-grade agent security hardening.

## Custom Skills (Built by Inspiratek)

| # | Skill | Domain |
|---|-------|--------|
| 1 | `account-segmentation-credential-governance` | Identity & Credential Management |
| 2 | `allowlist-governance` | User Access Governance |
| 3 | `authentication-access-control` | Authentication & Identity Security |
| 4 | `communication-scope-control` | Interaction Boundary Enforcement |
| 5 | `dedicated-environment-isolation` | Infrastructure & Compute Isolation |
| 6 | `firewall-network-policy-management` | Network Perimeter & Traffic Control |
| 7 | `network-hardening-port-security` | Network Exposure Reduction |
| 8 | `secure-remote-access` | Zero-Trust Remote Access |
| 9 | `security-monitoring-threat-detection` | Monitoring, Detection & Response |
| 10 | `skill-security-analysis-prompt-injection` | AI Supply Chain & Prompt Injection Defense |

## Recommended Skills (From Verified Sources)

| # | Skill | Source | Purpose |
|---|-------|--------|---------|
| 1 | `secureclaw-adversa-ai` | [Adversa AI](https://github.com/adversa-ai/secureclaw) | OWASP-aligned security auditing, hardening, skill scanning (56 checks) |
| 2 | `clawsec-suite-prompt-security` | [Prompt Security](https://github.com/prompt-security/clawsec) | Suite manager with advisory feed, signature verification, guided setup |
| 3 | `clawsec-feed` | [Prompt Security](https://github.com/prompt-security/clawsec) | CVE advisory feed with automated NVD polling |
| 4 | `soul-guardian` | [Prompt Security](https://github.com/prompt-security/clawsec) | SOUL.md drift detection and file integrity protection |
| 5 | `openclaw-audit-watchdog` | [Prompt Security](https://github.com/prompt-security/clawsec) | Automated daily security audits with reporting |
| 6 | `cisco-skill-scanner` | [Cisco AI Defense](https://github.com/cisco-ai-defense/skill-scanner) | Multi-engine skill scanning (static + behavioral + LLM + VirusTotal) |
| 7 | `skill-vetter` | [ClawHub](https://clawhub.ai/spclaudehome/skill-vetter) | Pre-install security vetting protocol |
| 8 | `clawshield-kappa9999` | [kappa9999](https://github.com/kappa9999/ClawShield) | Security preflight and guardrails |
| 9 | `clawshield-policygate` | [PolicyGate](https://github.com/policygate/clawshield) | Static config audit for misconfigurations |
| 10 | `nono-sandbox` | [always-further](https://github.com/always-further/nono) | Kernel-enforced sandbox with rollback and audit chain |

## Coverage Map

| Security Layer | Custom Skills | Recommended Skills |
|---------------|--------------|-------------------|
| Infrastructure Isolation | dedicated-environment-isolation | nono-sandbox |
| Network Hardening | network-hardening-port-security, firewall-network-policy-management | clawshield-policygate |
| Authentication | authentication-access-control | secureclaw-adversa-ai |
| Access Governance | allowlist-governance, communication-scope-control | clawshield-kappa9999 |
| Credential Management | account-segmentation-credential-governance | - |
| Remote Access | secure-remote-access | - |
| Monitoring & Detection | security-monitoring-threat-detection | openclaw-audit-watchdog, clawsec-feed |
| File Integrity | - | soul-guardian |
| Supply Chain Defense | skill-security-analysis-prompt-injection | cisco-skill-scanner, skill-vetter |
| OWASP Compliance | - | secureclaw-adversa-ai |
| CVE Monitoring | - | clawsec-feed, clawsec-suite |

## License

Custom skills are proprietary to Inspiratek. Recommended skills retain their original licenses (see individual directories).
