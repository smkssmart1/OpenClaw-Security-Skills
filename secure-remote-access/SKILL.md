---
name: secure-remote-access
description: "Enterprise-grade skill for implementing zero-trust secure remote access to OpenClaw AI agent infrastructure. Use whenever setting up private networking for AI agents, configuring VPN tunnels, implementing Tailscale/WireGuard/Nebula mesh networks, designing zero-trust access architecture, or eliminating public internet exposure for bot infrastructure. Also trigger for private overlay networks, bastion host design, mTLS implementation, or any remote access pattern that avoids exposing AI agents to the public internet."
---

# Secure Remote Access for OpenClaw AI Infrastructure

## 1. Purpose

OpenClaw agents operate sensitive business logic, access proprietary APIs, and process confidential data. Public internet exposure creates an attack surface that adversaries actively exploit: credential theft, API abuse, exploitation of unpatched vulnerabilities, and lateral movement into your infrastructure. Zero-trust secure remote access eliminates this exposure entirely. Every connection is authenticated, encrypted, and continuously verified—regardless of network origin. This skill implements enterprise-grade patterns to make your AI infrastructure invisible to the public internet.

## 2. First-Principles of Zero Trust

**Never trust, always verify.** Zero trust abandons the perimeter-based security model (public internet = untrusted, internal network = trusted). Instead:

- **Identity-based access**: Users, devices, and agents are verified through cryptographic identity, not IP addresses or network location.
- **Continuous verification**: Every access decision re-evaluates device compliance, user context, and behavioral anomalies—not just on first login.
- **Least-privilege sessions**: Users access only what they need, for only as long as they need it. Privileges never leak sideways.
- **Microsegmentation**: Every agent, API endpoint, and dashboard runs in its own isolated security zone. A compromise in one zone doesn't cascade.

Traditional remote access (VPN + internal network = trusted) violates zero trust. Instead: every connection—whether from your office or a coffee shop—undergoes identical cryptographic verification and continuous authorization.

## 3. Public Internet vs Private Access

**Why public exposure is dangerous:**
- Shodan, Censys, and passive scanning identify your public IPs within hours.
- Credential stuffing and brute-force attacks are automated and continuous.
- A single unpatched CVE (e.g., RCE in SSH, Jenkins, or a reverse proxy) compromises the entire infrastructure.
- Port forwarding from home internet exposes you to ISP-level monitoring and MITM attacks.
- Public APIs leak metadata (version strings, error messages) that attackers use to tailor exploits.

**NAT traversal and the mesh alternative:**
- Traditional approach: Open a port, forward traffic, hope firewalls protect you.
- Mesh approach: All agents and devices are peers in an encrypted overlay network. No inbound listening. Outbound-only connections mean no exposed ports.
- Result: Infrastructure remains dark (invisible) to the public internet while every node can communicate securely.

## 4. OpenClaw Secure Access Model

OpenClaw infrastructure typically requires remote access to three layers:

| Component | Access Type | Sensitivity | Network Exposure |
|-----------|------------|-------------|-----------------|
| Admin SSH (config/restart agents) | Interactive, humans only | Critical | Zero-trust identity required |
| API endpoints (agent requests, webhooks) | Service-to-service | High | Private mesh only |
| Monitoring dashboards (Prometheus, logs) | Read-only, humans | Medium | Private mesh, audit logging required |
| Agent orchestration (control plane) | Automated, agent-to-control | Critical | Private mesh, mTLS mandatory |

**What does NOT need remote access**: Agents themselves never accept inbound connections. They initiate outbound calls to the control plane (over mTLS), and the control plane issues commands back through the same encrypted tunnel. This inverts the traditional model and eliminates inbound attack surfaces entirely.

## 5. Implementation Levels

### Beginner — SSH Tunneling (Single Agent, One Admin)

Minimal overhead. Use for prototyping and small deployments.

```bash
# Admin machine: Create a persistent tunnel to agent
ssh -N -L 8080:localhost:8080 -i ~/.ssh/agent_key user@agent-public-ip

# Use autossh for resilience (reconnects automatically)
autossh -M 0 -N -L 8080:localhost:8080 -i ~/.ssh/agent_key user@agent-public-ip
```

**Then**: Access locally via `http://localhost:8080`. Agent remains private; traffic is encrypted and authenticated.

**Risk**: SSH key compromise means complete access. Agent still has a public IP (listening on SSH port 22). Not production-grade.

### Intermediate — WireGuard Mesh (Team Access, Multiple Agents)

Production-ready. All agents and admins exist in a private overlay network. No public IPs are exposed.

**Server config** (`/etc/wireguard/wg0.conf`):
```ini
[Interface]
PrivateKey = <generated-via-wg genkey>
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Admin peer
[Peer]
PublicKey = <admin-public-key>
AllowedIPs = 10.0.0.10/32

# Agent-1 peer
[Peer]
PublicKey = <agent1-public-key>
AllowedIPs = 10.0.0.20/32

# Agent-2 peer
[Peer]
PublicKey = <agent2-public-key>
AllowedIPs = 10.0.0.30/32
```

**Client config** (admin machine, `/etc/wireguard/wg0.conf`):
```ini
[Interface]
PrivateKey = <admin-private-key>
Address = 10.0.0.10/32
DNS = 10.0.0.1

[Peer]
PublicKey = <server-public-key>
Endpoint = wg-server.example.com:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
```

**Agent config** (on agent host, `/etc/wireguard/wg0.conf`):
```ini
[Interface]
PrivateKey = <agent-private-key>
Address = 10.0.0.20/32

[Peer]
PublicKey = <server-public-key>
Endpoint = wg-server.example.com:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
```

**Bring up the tunnel:**
```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0  # Persist across reboot
```

**Verify connectivity:**
```bash
wg show  # Display all connections and handshakes
ping 10.0.0.1  # Test admin-to-agent connectivity
```

**Result**: Every agent is reachable at its private IP (10.0.0.20, etc.) only from within the WireGuard mesh. The public internet cannot connect to any agent. SSH, HTTP dashboards, and APIs are all private.

### Advanced — Tailscale ACL Policies (Multi-Region, RBAC)

Tailscale is WireGuard with identity management, device compliance, and RBAC built in. No manual key rotation.

**Tailscale ACL policy** (`tailnet.example.com` admin console, Policy tab):
```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:admins"],
      "dst": ["tag:agents:*"]
    },
    {
      "action": "accept",
      "src": ["tag:agents"],
      "dst": ["tag:control-plane:443"]
    },
    {
      "action": "accept",
      "src": ["group:monitoring"],
      "dst": ["tag:agents:9090"]
    },
    {
      "action": "reject",
      "src": ["*"],
      "dst": ["*"]
    }
  ],
  "groups": {
    "group:admins": ["user1@example.com", "user2@example.com"],
    "group:monitoring": ["monitoring@example.com"]
  },
  "tagOwners": {
    "tag:agents": ["group:admins"],
    "tag:control-plane": ["group:admins"]
  }
}
```

**On each agent**, during Tailscale setup:
```bash
tailscale up --authkey=<key> --hostname=agent-01 --advertise-routes=10.1.0.0/24
# Tag via admin console: Applications → Devices → agent-01 → Tags: agents, production
```

**Verification**:
```bash
tailscale status  # Show all connected peers and their ACL tags
ping agent-01.example.com  # Resolve and ping via Tailscale mesh
```

**Benefits**: Device compliance enforcement (e.g., "only macOS with disk encryption can access prod agents"), auto-rotation of keys, seamless multi-region connectivity, audit logging built in.

### Architect — Enterprise Zero-Trust Fabric (BeyondCorp Model)

Large organizations implement identity-aware proxies (IAP) that intercept all traffic and make real-time authorization decisions based on user, device, and contextual signals.

**Architecture**:
```
User Device (enrolled in MDM)
    ↓
Identity-Aware Proxy (Zscaler, Cloudflare Access, Teleport)
    ↓
Device Trust Scoring (compliance checks, location, certificate pinning)
    ↓
Context-Based Access Decision (who, what, when, where, how)
    ↓
OpenClaw Agent (behind IAP, never directly accessible)
```

**Example: Teleport for OpenClaw**
```bash
# Admin: Configure Teleport cluster
tctl create -f rbac-role.yaml
tctl users add admin --roles=access --traits=team=openclawadmins

# Agent: Join cluster with service identity
teleport start --roles=agent --auth-servers=teleport.example.com:3025

# Admin: Access agent via IAP
tsh ssh -l ubuntu agent-01.example.com
# Teleport verifies: (1) user identity, (2) device compliance, (3) approval workflow
```

**Benefits**: Continuous authorization (re-evaluates every 15 minutes), session recording (full audit trail), device compliance enforcement, zero standing privileges, machine learning-based anomaly detection.

## 6. Step-by-Step Setup Framework

**Phase 1: Audit Current State**
```bash
# Identify public-facing services
sudo netstat -tulpn | grep LISTEN | grep -E "0\.0\.0\.0|::"
# Any service listening on 0.0.0.0 is exposed to public internet

# Identify agents with SSH keys in AWS Secrets Manager
aws secretsmanager list-secrets | jq '.SecretList[] | select(.Name | contains("agent"))'

# Identify inbound firewall rules
aws ec2 describe-security-groups --filters Name=tag:component,Values=openclaw --query 'SecurityGroups[*].IpPermissions[?FromPort!=null]'
```

**Phase 2: Deploy Private Mesh (Tailscale)**
```bash
# Step 1: Create Tailscale account and get auth key
# Step 2: On control plane
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --authkey=<key> --hostname=openclaw-control
tailscale set --accept-routes=true  # Accept routes from agents

# Step 3: On each agent
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up --authkey=<key> --hostname=agent-<id> --advertise-routes=10.1.<id>.0/24

# Step 4: Verify mesh
tailscale netmap  # Display full mesh topology
```

**Phase 3: Move Services to Private IPs**
```bash
# Before: Services listen on 0.0.0.0 (public)
netstat -tulpn | grep 8080  # LISTEN 0.0.0.0:8080

# After: Services listen on Tailscale IP or localhost
# Edit agent config to bind to Tailscale IP
TAILSCALE_IP=$(tailscale ip -4)
openclaw-agent --bind=${TAILSCALE_IP}:8080

# Verify
netstat -tulpn | grep 8080  # LISTEN 100.x.x.x:8080 (private)
```

**Phase 4: Revoke Public Access**
```bash
# Revoke public security group rules
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxx \
  --protocol tcp --port 8080 --cidr 0.0.0.0/0

# Verify no inbound rules remain
aws ec2 describe-security-groups --group-ids sg-xxxxx
```

**Phase 5: Test Private-Only Access**
```bash
# From public internet: Connection should fail
curl http://agent-public-ip:8080/health  # Timeout (expected)

# From within Tailscale mesh: Connection succeeds
ssh -i ~/.ssh/tailscale_key ubuntu@agent-01.example.com
curl http://agent-01.example.com:8080/health  # Success (200 OK)
```

## 7. Real Use Cases

### Personal AI Bot — Single User, Multiple Devices

One developer, one agent, three devices (laptop, phone, tablet). Goal: Access the agent's dashboard from anywhere, no public IP.

```bash
# Setup
tailscale up --authkey=<key> --hostname=my-bot

# On each device: Install Tailscale, authenticate, done.
# Access dashboard: open https://my-bot.example.com:9090

# Result: Dashboard is accessible only from devices logged into Tailscale.
# Phone loses connection → immediately locked out (no fallback to public IP).
```

### Remote Business Agent — Team Access with RBAC

Five developers, five agents, role-based access (only senior devs can access prod agents).

```bash
# Tailscale ACL
"acls": [
  {
    "action": "accept",
    "src": ["group:senior-devs"],
    "dst": ["tag:agents-prod:*"]
  },
  {
    "action": "accept",
    "src": ["group:junior-devs"],
    "dst": ["tag:agents-staging:*"]
  }
]

# Result: Junior dev tries to access prod agent → ACL rejects connection.
# Audit log captures the attempt. No confusion, no accidental access.
```

### Multi-Device Access — Phone, Laptop, Tablet

One user needs to view agent status from phone (while traveling), laptop (in office), and tablet (home office).

```bash
# Install Tailscale on all three devices.
# Assign all three to group:admins in Tailscale ACL.
# All three devices automatically gain access to all agents.

# Result: Switch devices → automatic access (no keys to manage, no SSH tunnels to maintain).
# Lose phone → revoke it from Tailscale console (instant, no service interruption on other devices).
```

## 8. Risks of Public Exposure

**Credential Scanning Attack**: Shodan finds your public IP listening on SSH port 22. Attacker runs brute-force password attack. After 10 failed attempts, an unpatched OpenSSH vulnerability allows RCE. Attacker gains shell, escalates to root, installs backdoor, and exfiltrates all API keys.

**Exploit Chain**: Public agent runs a reverse proxy (nginx). Nginx version 1.16.0 has CVE-2019-1010317 (buffer overflow). Attacker crafts malicious HTTP header, gains RCE, pivots to control plane, compromises all agents.

**API Abuse**: Agent exposes `/api/execute` endpoint publicly (no authentication). Attacker discovers endpoint via DNS enumeration. Attacker calls `/api/execute?code=rm -rf /` repeatedly, causing DoS.

**Lateral Movement**: Agent runs on EC2 with IAM role. Attacker gains access to agent, queries EC2 metadata endpoint (http://169.254.169.254), retrieves temporary AWS credentials, and accesses S3, RDS, and other resources under that role.

**ISP-Level Monitoring**: Home internet port forward exposes you to ISP traffic inspection. ISP notifies law enforcement if they detect suspicious activity. Non-technical users (home labbers) are often the target of swatting and law enforcement raids.

## 9. Governance Controls

**Access Request Workflow**:
1. User submits access request in Jira/ServiceNow: "Need prod agent access for 7 days."
2. Manager approves in Slack.
3. Automated workflow invokes Terraform: user is added to `group:prod-access` in Tailscale ACL.
4. User immediately gains access (via Tailscale device).
5. At end of 7 days, user is automatically removed.
6. Audit log captures: who requested, who approved, when access started/ended, all SSH commands executed.

**Session Logging**:
```bash
# Enable auditd on agents
sudo systemctl enable auditd
sudo auditctl -w /home/ubuntu -p wa -k agent-modifications

# Ship logs to centralized syslog
tail -f /var/log/auth.log | nc syslog-server 514

# Investigate: Who SSHed to agent-01 on 2026-02-27?
ausearch -i -k agent-modifications | grep 2026-02-27
journalctl SYSLOG_IDENTIFIER=sshd | grep 2026-02-27
```

**Device Compliance**:
```json
{
  "devicePolicy": {
    "requires": [
      "macOS 13+, Windows 11+, Ubuntu 22.04+",
      "disk encryption enabled (FileVault, BitLocker, LUKS)",
      "antivirus active (CrowdStrike, Microsoft Defender, Sophos)",
      "device enrolled in MDM (Jamf, Intune, Kandji)"
    ],
    "checkFrequency": "every 15 minutes",
    "failureAction": "revoke access immediately"
  }
}
```

**Access Review Cycles**:
- Monthly: Audit all active access grants in Tailscale console. Remove inactive users.
- Quarterly: Review ACL policies. Identify over-provisioned access. Tighten rules.
- Semi-annually: Rotate all WireGuard keys (if using self-hosted).

## 10. Performance Considerations

**Tunnel Overhead**: WireGuard/Tailscale adds ~1-2ms latency per hop. For agent-to-control-plane communication (single hop), impact is negligible. For end-user latency-sensitive operations, consider split tunneling (only agent traffic goes through tunnel, other traffic uses direct internet).

**MTU Optimization**: VPN tunnels reduce MTU from 1500 bytes to ~1420 bytes. Configure agents to use smaller packets:
```bash
# Set MSS for WireGuard tunnel
sudo ip route replace default dev wg0 mtu 1420

# Verify
ip link show wg0 | grep mtu
```

**Split Tunneling Decision**:
- Prod agents: Tunnel ALL traffic (defense-in-depth).
- Development agents: Tunnel only agent traffic, allow direct internet for package downloads (faster development).

**Latency Impact**:
```bash
# Before tunnel
ping control-plane.example.com  # 2ms

# After tunnel (over WireGuard)
ping control-plane.example.com  # 3-4ms
```

**Bandwidth**: WireGuard overhead is minimal (~29 bytes per packet). For typical agent workloads (JSON APIs, log shipping), overhead is <1%. Only a concern for video streaming or high-bandwidth agents.

## 11. Testing Scenarios

**Verify Private-Only Access**:
```bash
# From outside Tailscale mesh
curl http://agent-01.example.com:8080/health  # FAIL (timeout or refused)

# From inside Tailscale mesh
curl http://agent-01.example.com:8080/health  # SUCCESS (200 OK)
```

**Test Failover**:
```bash
# Stop primary Tailscale relay
sudo systemctl stop tailscaled

# Agent should automatically reconnect to backup relay
tailscale status  # Verify "Connected" state restored within 30 seconds
```

**Validate ACLs**:
```bash
# User not in "group:admins" tries to access prod agent
ssh ubuntu@agent-prod.example.com  # FAIL: "network is unreachable"

# User is added to group:admins
# Same command: SUCCESS (connection accepted, ACL allows)
```

**Simulate Unauthorized Access**:
```bash
# Attacker gains knowledge of agent IP (100.x.x.x from Tailscale docs)
# Attacker (not in Tailscale network) tries to connect
nmap 100.x.x.x  # All ports filtered (agent is dark to outside world)

# Only devices within Tailscale mesh can discover agents
```

## 12. Mastery Checklist

- [ ] All agents removed from public internet (no public IPs accepting inbound connections).
- [ ] Tailscale or WireGuard mesh deployed and verified between control plane and all agents.
- [ ] ACL policies written and tested (verify RBAC enforces least privilege).
- [ ] SSH keys rotated and moved to Tailscale-based auth (no static SSH keys in Secrets Manager).
- [ ] Session logging enabled (auditd, journalctl, or centralized syslog).
- [ ] Device compliance checks enforced (encryption, antivirus, MDM enrollment).
- [ ] Access review workflow automated (Jira → Slack → Terraform → Tailscale).
- [ ] Public security group rules revoked (no 0.0.0.0/0 ingress on port 22 or application ports).
- [ ] Split tunneling decision made and documented.
- [ ] Disaster recovery tested (manual access via bastion host if Tailscale fails).

## 13. Anti-Patterns

**Static SSH Keys in Git**: Agents are configured with hardcoded SSH keys. Result: Key rotation requires redeploy. Leaked key means full compromise.
*Fix*: Use Tailscale or signed SSH certificates. Keys are ephemeral and rotate automatically.

**VPN + Internal Network = Trusted**: Employees VPN into corporate network, assume all internal services are safe. Result: One compromised internal service → lateral movement to all services.
*Fix*: Apply zero-trust ACLs even inside VPN. Assume breach.

**Single Public Bastion Host**: All access funnels through one jump host. Result: Single point of failure. Compromised bastion → compromised everything behind it.
*Fix*: Use mesh network (every agent is a bastion). No single point of failure.

**Port Forwarding from Home Internet**: Forward SSH port 22 from home router. Result: ISP can see traffic. Home IP changes frequently (breaks automation). No encryption.
*Fix*: Use Tailscale or WireGuard. Always encrypted, IP changes don't matter.

## 14. KPIs (Key Performance Indicators)

**Public Exposure Elimination Rate**: % of agents with zero inbound public port exposure.
- Target: 100% within 30 days.
- Measure: `aws ec2 describe-security-groups | grep 0.0.0.0/0 | count` → should be 0.

**Unauthorized Access Attempts**: Count of ACL rejections per week.
- Target: <5 per week (indicates ACLs are working, users are occasionally misconfigured).
- Measure: `tailscale debug peerapi-logs | grep 'acl=deny' | wc -l`.

**Session Audit Coverage**: % of sessions with full audit trail (who, when, what, result).
- Target: 100%.
- Measure: Count of SSH sessions with corresponding audit log entry.

**Device Compliance Rate**: % of devices connected to mesh with current compliance status.
- Target: ≥95%.
- Measure: Tailscale admin console → Devices → non-compliant devices.

**Access Review Completion**: % of quarterly access reviews completed on schedule.
- Target: 100%.
- Measure: Calendar audit.

## 15. Enterprise Scaling

**Multi-Region Mesh**: Deploy Tailscale relay servers in every region. Agents automatically connect to nearest relay, reducing latency.

```bash
# On relay server (AWS us-east-1)
tailscale up --authkey=<key> --hostname=relay-us-east --advertise-routes=0.0.0.0/0 --accept-routes
# Set derp region in Tailscale admin: Use relay-us-east for us-east-1 agents
```

**ACL Versioning**: Store ACL policies in Git. Changes require peer review and approval before deployment.

```yaml
# .gitignore: never commit auth keys
/tailnet-auth-keys.txt

# Workflow: ACL change → Git commit → PR review → GitHub Actions tests → Merge → Automated `tctl create` deployment
```

**Audit Trail Centralization**: Ship all agent audit logs to a central Loki/ELK cluster. Query cross-agent for security incidents.

```bash
# On each agent
tail -f /var/log/auth.log | promtail --client.url=http://loki:3100

# Query: "Which agents did user@example.com access in the past 24 hours?"
{job="agent-logs"} | json | user="user@example.com"
```

**Identity-Aware Proxy (Enterprise Scale)**:
```yaml
# Teleport Enterprise: Centralized identity, access, and audit for all OpenClaw infrastructure
teleport:
  cluster_name: openclaw-production
  auth_service:
    enabled: true
    cluster_name: openclaw-production
  proxy_service:
    enabled: true
    public_addr: teleport.example.com:3080
    web_listen_addr: 0.0.0.0:3080
  ssh_service:
    enabled: true
    commands:
      - name: agent-status
        command: /scripts/agent-status.sh
        period: 1h
```

## 16. Architect Notes

**Why Tailscale over bare WireGuard?**
- Tailscale: Identity management, device compliance, auto-key rotation, easier multi-region, better UX. Cost: ~$50/user/month (scales to $100k/year for enterprise).
- WireGuard: Minimal overhead, full control, no vendor lock-in. Cost: operational burden (key rotation, ACL management). Better for organizations with infosec teams.

**Why Mesh over Bastion?**
- Bastion: Single jump host. Simple. Single point of failure.
- Mesh: Every agent is a peer. If one goes down, others are unaffected. Better for distributed teams and disaster recovery.

**Continuous Authorization (Re-evaluation)**:
- Traditional VPN: Authenticate once, trust for days/months.
- Zero-trust: Re-evaluate every 15 minutes. Device becomes non-compliant (malware detected, disk encryption disabled)? Immediately revoke access.

**Incident Response**:
- Compromised user device: Disable device in Tailscale console → instant access revocation (all sessions terminated within seconds).
- Compromised agent: Isolate agent in Tailscale ACLs → deny all inbound access → revoke keys → redeploy.
- Unauthorized SSH attempt: Audit log captures attempt → alert triggered → on-call engineer investigates.

---

**Last Updated**: 2026-02-28
**Maintainer**: OpenClaw Security Team
