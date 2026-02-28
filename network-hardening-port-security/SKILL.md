---
name: network-hardening-port-security
description: "Enterprise-grade skill for hardening network exposure and securing ports on OpenClaw AI agent deployments. Use whenever configuring network security for AI agents, changing default ports, reducing attack surface, hardening service exposure, protecting against port scanning, or designing network architecture for autonomous AI systems. Also trigger for firewall tuning, service binding, TLS configuration, reverse proxy setup, or any network-layer security for bot/agent infrastructure."
---

# Network Hardening & Port Security for OpenClaw AI Agents

## 1. Purpose

OpenClaw AI agents operate within distributed infrastructure—Discord gateways, REST APIs, webhook handlers, and management interfaces. Each open port is an attack vector. Port security reduces reconnaissance surface, eliminates service enumeration, defeats automated scanner attacks, and ensures only intentional services are exposed. Network hardening is foundational: TLS cannot protect an unnecessarily open management port, and authentication cannot compensate for exposed services.

---

## 2. First-Principles of Network Exposure

Every open port broadcasts service presence. The internet is continuously scanned. Shodan indexes all exposed services. Botnets probe common ports daily.

**Network Exposure Theory:**
- Port open ≠ service accessible (firewall context matters)
- Service listening ≠ should be listening (defaults are dangerous)
- Service accessible ≠ should be accessible (binding scope matters)
- Binding to 0.0.0.0 means every network interface replies

**Service Enumeration:** Attackers map ports → services → versions → known CVEs.

**Exposure Relationship:** One careless SSH on port 22 with password auth defeats zero-trust network design.

---

## 3. Port Security Concepts

**Port Categories:**
- Well-known: 0–1023 (SSH:22, HTTP:80, HTTPS:443)
- Registered: 1024–49151 (application-specific)
- Dynamic: 49152–65535 (ephemeral)

**Service Binding:**
- `0.0.0.0` = all IPv4 interfaces (externally exposed)
- `127.0.0.1` = loopback only (local-only)
- `::1` = IPv6 loopback
- Specific IP = only that interface

**Socket Exposure:** `netstat -tulpn` reveals what listens where.

**Default Danger:** Services ship with permissive defaults (Postgres listens 5432 on 0.0.0.0, Redis on 6379 unauth). These must be hardened immediately.

---

## 4. OpenClaw Gateway Architecture

OpenClaw agents typically expose:

| Service | Default Port | Binding | Purpose | Security |
|---------|--------------|---------|---------|----------|
| Discord Gateway | Outbound | N/A | Receive commands | TLS outbound only |
| REST API | 8000 | 0.0.0.0 | Command submission | Should be internal/TLS |
| Webhook Handler | 8001 | 0.0.0.0 | External callbacks | Should use signature verification |
| Management UI | 8080 | 0.0.0.0 | Agent control | Should be bastion-only |
| Metrics (Prometheus) | 9090 | 127.0.0.1 | Internal monitoring | Local only |
| SSH | 22 | 0.0.0.0 | Remote admin | Should change port |

**What Needs External Access:** Only the Webhook Handler (if receiving cloud callbacks) and optionally the REST API (if behind reverse proxy).

**What Must Be Internal-Only:** Management UI, SSH, Prometheus, database ports.

---

## 5. Implementation Levels

### Beginner — Basic Port Changes & Binding

**Change SSH from port 22:**
```bash
# Edit sshd config
sudo nano /etc/ssh/sshd_config
# Change: Port 22
# To: Port 2222

# Restart SSH
sudo systemctl restart ssh

# Test: ssh -p 2222 user@host
# Update firewall before testing to avoid lockout:
sudo ufw allow 2222/tcp
sudo ufw delete allow 22/tcp
```

**Bind services to localhost only:**
```yaml
# openclaw-agent-config.yaml
rest_api:
  host: 127.0.0.1
  port: 8000

management_ui:
  host: 127.0.0.1
  port: 8080

prometheus_metrics:
  host: 127.0.0.1
  port: 9090
```

**Basic UFW rules:**
```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp    # SSH on custom port
sudo ufw allow 8001/tcp    # Webhook handler (external)
sudo ufw enable
```

**Verify exposure:**
```bash
netstat -tulpn | grep LISTEN
# Should show 127.0.0.1:8000, not 0.0.0.0:8000
```

---

### Intermediate — Reverse Proxy & TLS Termination

**Nginx reverse proxy for OpenClaw webhook handler:**
```nginx
upstream openclaw_webhook {
    server 127.0.0.1:8001;
}

server {
    listen 443 ssl http2;
    server_name agent.company.com;

    ssl_certificate /etc/letsencrypt/live/agent.company.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/agent.company.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location /webhook {
        proxy_pass http://openclaw_webhook;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Rate limiting
        limit_req zone=webhook burst=10 nodelay;
    }

    location / {
        return 404;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name agent.company.com;
    return 301 https://$server_name$request_uri;
}

# Rate limiting zone
limit_req_zone $binary_remote_addr zone=webhook:10m rate=5r/s;
```

**Caddy (simpler alternative):**
```
agent.company.com {
    reverse_proxy 127.0.0.1:8001
    header X-Frame-Options DENY
    header X-Content-Type-Options nosniff
}
```

**Certbot for Let's Encrypt:**
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot certonly --nginx -d agent.company.com
# Auto-renewal via systemd timer (installed automatically)
```

**Verify TLS strength:**
```bash
testssl.sh https://agent.company.com
# Check for A+ rating, no weak ciphers
```

---

### Advanced — Network Segmentation & Service Mesh

**Docker network isolation:**
```bash
# Create isolated networks
docker network create openclaw-internal --driver bridge
docker network create openclaw-ingress --driver bridge

# Run internal services on isolated network only
docker run -d \
  --name openclaw-api \
  --network openclaw-internal \
  -p 127.0.0.1:8000:8000 \
  openclaw/agent:latest

# Run webhook handler with access to both (ingress + internal)
docker run -d \
  --name openclaw-webhook \
  --network openclaw-ingress \
  --network openclaw-internal \
  -p 0.0.0.0:8001:8001 \
  openclaw/webhook:latest

# Management UI on internal network only
docker run -d \
  --name openclaw-ui \
  --network openclaw-internal \
  -p 127.0.0.1:8080:8080 \
  openclaw/management-ui:latest
```

**Docker Compose with network segmentation:**
```yaml
version: '3.9'
services:
  openclaw-agent:
    image: openclaw/agent:latest
    networks:
      - internal
    expose:
      - 8000
    environment:
      LISTEN_HOST: 0.0.0.0  # Internal network only

  webhook-handler:
    image: openclaw/webhook:latest
    networks:
      - ingress
      - internal
    ports:
      - "0.0.0.0:8001:8001"

  management-ui:
    image: openclaw/management-ui:latest
    networks:
      - internal
    expose:
      - 8080

  prometheus:
    image: prom/prometheus:latest
    networks:
      - internal
    expose:
      - 9090

networks:
  internal:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.enable_ip_masquerade: "true"
  ingress:
    driver: bridge
```

**mTLS between services (Linkerd/Istio pattern):**
```yaml
# istio-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: openclaw
spec:
  mtls:
    mode: STRICT  # All traffic must be mTLS
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: openclaw-api
namespace: openclaw
spec:
  hosts:
  - openclaw-api
  http:
  - match:
    - sourceLabels:
        version: v1
    route:
    - destination:
        host: openclaw-api
        port:
          number: 8000
```

---

### Architect — Zero-Exposure Architecture

**Bastion host jump pattern:**
```bash
# Bastion host (single hardened entry point)
# Only allows inbound SSH on custom port, rate-limited

# Local machine → SSH to bastion → SSH to internal agents
# ssh -J bastion.company.com:2222 admin@agent-internal.local

# ~/.ssh/config
Host bastion
    HostName bastion.company.com
    Port 2222
    User admin
    IdentityFile ~/.ssh/bastion_key

Host agent-internal
    HostName 10.0.1.5
    ProxyJump bastion
    User admin
    IdentityFile ~/.ssh/agent_key
```

**WireGuard tunnel for management traffic:**
```bash
# On agent host
[Interface]
Address = 10.0.0.2/32
PrivateKey = <agent-private-key>
ListenPort = 51820

[Peer]
PublicKey = <bastion-public-key>
AllowedIPs = 10.0.0.1/32
Endpoint = bastion.company.com:51820
PersistentKeepalive = 25
```

**Zero public ports deployment:**
```bash
# OpenClaw agent listens only on WireGuard interface
openclaw-agent:
  listen_host: 10.0.0.2  # WireGuard only
  listen_port: 8000
  # Webhook callbacks via Discord DM or internal relay
  webhook_mode: discord_dm  # No HTTP listener
```

**Cloudflare Tunnel (zero server-side open ports):**
```bash
# Install cloudflared
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb

# Authenticate
cloudflared tunnel login

# Create tunnel config
cloudflared tunnel create openclaw-agent

# Route traffic
cloudflared tunnel route dns openclaw-agent agent.company.com

# Configure local service
# ~/.cloudflared/config.yml
tunnel: openclaw-agent
credentials-file: ~/.cloudflared/openclaw-agent-credentials.json

ingress:
  - hostname: agent.company.com
    service: http://127.0.0.1:8001
  - service: http_status:404
```

**iptables strict ingress filtering:**
```bash
# Default deny all ingress
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from bastion only
sudo iptables -A INPUT -p tcp --dport 2222 -s 10.0.1.0/24 -j ACCEPT

# Allow webhook from reverse proxy (same host)
sudo iptables -A INPUT -i docker0 -p tcp --dport 8001 -j ACCEPT

# Persist with iptables-persistent
sudo apt install iptables-persistent
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

## 6. Step-by-Step Port Hardening Guide (Ubuntu 22.04)

**1. Audit current exposure:**
```bash
sudo netstat -tulpn | grep LISTEN
sudo ufw status
nmap localhost  # Install: apt install nmap
```

**2. Install firewall:**
```bash
sudo apt update
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

**3. Configure SSH hardening:**
```bash
sudo nano /etc/ssh/sshd_config
# Changes:
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
```

**4. Restart and test before enabling firewall:**
```bash
sudo systemctl restart ssh
ssh -p 2222 localhost  # Test locally first
```

**5. Configure firewall rules:**
```bash
sudo ufw allow 2222/tcp
sudo ufw allow 8001/tcp  # Webhook handler
sudo ufw deny 22/tcp     # Explicit deny old SSH port
sudo ufw enable
```

**6. Bind OpenClaw services to localhost:**
```yaml
# /etc/openclaw/config.yaml
services:
  api:
    bind: 127.0.0.1:8000
  webhook:
    bind: 0.0.0.0:8001  # Behind reverse proxy
  management:
    bind: 127.0.0.1:8080
  metrics:
    bind: 127.0.0.1:9090
```

**7. Setup Nginx reverse proxy:**
```bash
sudo apt install nginx certbot python3-certbot-nginx
sudo systemctl start nginx
# Add config from Intermediate section above
sudo certbot certonly --nginx -d agent.company.com
sudo systemctl reload nginx
```

**8. Disable unused services:**
```bash
sudo systemctl disable avahi-daemon
sudo systemctl disable cups
sudo systemctl mask bluetooth
# Verify no unexpected listeners
sudo ss -tulpn | grep LISTEN
```

**9. Verify hardening:**
```bash
# External scan from different host
nmap -sV agent.company.com
# Should show only port 443 (HTTPS), possibly 80 (HTTP redirect)

# Internal scan
netstat -tulpn
# Should show SSH on 2222, services on 127.0.0.1 only
```

---

## 7. Real Deployment Examples

### Scenario 1: Personal Development Bot

```bash
# Single-host, Discord-only
sudo ufw allow 2222/tcp

# Bind everything to localhost, Discord gateway is outbound-only
openclaw-config:
  mode: development
  api_bind: 127.0.0.1:8000
  management_bind: 127.0.0.1:8080

# SSH via bastion only (or VPN)
# No public-facing services
```

### Scenario 2: Small Team Deployment

```bash
# 2-host setup: bastion + agent

# Bastion host (public)
sudo ufw allow 2222/tcp  # SSH
sudo ufw allow 443/tcp   # Webhook via Nginx
sudo ufw allow 80/tcp    # HTTP redirect

# Agent host (private)
sudo ufw default deny incoming
sudo ufw allow from 10.0.1.0/24  # Bastion only
# No public access, reaches bastion via reverse proxy

# Nginx on bastion:
upstream openclaw {
  server 10.0.1.5:8001;  # Agent's internal IP
}
server {
  listen 443 ssl;
  server_name agent.company.com;
  location /webhook {
    proxy_pass http://openclaw;
  }
}
```

### Scenario 3: Enterprise Multi-Agent

```bash
# Multi-host, Kubernetes, mTLS, zero public ports

apiVersion: v1
kind: Service
metadata:
  name: openclaw-agent-1
spec:
  type: ClusterIP  # Internal only
  selector:
    agent: openclaw-1
  ports:
    - port: 8000
      targetPort: 8000
---
apiVersion: v1
kind: Service
metadata:
  name: ingress-webhook
spec:
  type: LoadBalancer  # Only this is public
  selector:
    component: webhook-ingress
  ports:
    - port: 443
      targetPort: 8001
---
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: STRICT  # All inter-service traffic encrypted

# SSH access via Teleport bastion
# All management traffic via VPN + mTLS
# Prometheus/metrics on internal network only
```

---

## 8. Attack Scenarios & Threat Models

### Port Scanning Attack

**What attacker sees (unhardenhed):**
```bash
nmap -sV agent.company.com
Starting Nmap 7.80
Nmap scan report for agent.company.com (203.0.113.42)
Host is up (0.025s latency).
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 7.4
5432/tcp open  postgresql   PostgreSQL 11
6379/tcp open  redis        Redis 6.0
8000/tcp open  http         OpenClaw API
8080/tcp open  http         OpenClaw Management
9090/tcp open  prometheus   Prometheus 2.20

# Attacker knows: running Postgres (might have CVE), Redis unauth, weak OpenSSH version
```

**Hardened response:**
```bash
nmap -sV agent.company.com
Nmap scan report for agent.company.com (203.0.113.42)
Host is up (0.025s latency).
PORT    STATE    SERVICE VERSION
443/tcp open     ssl/tls
80/tcp  open     http
# Only shows reverse proxy, no service identification possible
```

**Prevention:**
1. Bind internal services to 127.0.0.1 only
2. Firewall closes all non-essential ports
3. Nginx reverse proxy hides backend services
4. Change SSH to non-standard port

### Service Fingerprinting

**Banner grabbing attack (unhardenend):**
```bash
nc -v agent.company.com 22
Connection to agent.company.com 22 port [tcp/ssh] succeeded!
SSH-2.0-OpenSSH_7.4  # Now attacker knows exact version, searches for CVEs
```

**Hardened response:**
```bash
nc -v agent.company.com 22
Connection refused (port behind firewall)

nc -v agent.company.com 443
Connected to reverse proxy (no service version leak)
```

**Prevention:**
1. Change SSH to non-standard port (single-packet fingerprinting blocked)
2. Hide service versions in headers
3. Use reverse proxy that doesn't leak backend versions

### Exploitation of Exposed Service

**Unhardenend Postgres:**
```bash
# Attacker connects to unprotected port 5432
psql -h agent.company.com -U postgres -d openclaw
# Default password attempt works, attacker has database access
```

**Hardened equivalent:**
```bash
psql -h agent.company.com -U postgres
psql: could not translate host name "agent.company.com" to address: Name or service not known
# Database listening on 127.0.0.1 only, network-level blocking
```

**Prevention:**
1. Bind database to 127.0.0.1 only
2. Firewall explicit deny on 5432
3. Use network segmentation (Docker networks)
4. Change default passwords

---

## 9. Safety & Governance Controls

**Change Management for Network Changes:**

1. **Pre-change validation:**
   ```bash
   # Dry-run firewall rules
   sudo ufw show added
   # Review proposed changes before apply

   # Test SSH port change locally before restarting
   sudo sshd -t  # Syntax check
   ```

2. **Documentation:**
   - Record each port change with timestamp, reason, approver
   - Maintain network diagram showing service bindings
   - Document firewall ruleset with comments

3. **Rollback procedures:**
   ```bash
   # Keep old SSH sshd_config
   sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

   # If firewall locks you out:
   sudo ufw disable  # Requires console access (should have IPMI/serial console)
   sudo systemctl restart ssh
   ```

4. **Approval workflow:**
   - Network hardening changes require security team approval
   - Changes to firewall rules logged and auditable
   - Any port opening needs threat justification

---

## 10. Monitoring Network Exposure

**Continuous monitoring tools:**

```bash
# Real-time port monitoring
watch -n5 'netstat -tulpn | grep LISTEN'

# Automated daily port scan (from external perspective)
# /usr/local/bin/port-scan-monitor.sh
#!/bin/bash
SCAN_REPORT="/var/log/port-scan-$(date +%Y%m%d).txt"
nmap -p- agent.company.com > $SCAN_REPORT
OPEN_PORTS=$(grep 'open' $SCAN_REPORT | wc -l)
echo "Open ports: $OPEN_PORTS" | mail -s "Port Scan Report" security@company.com

# Cron: 0 2 * * * /usr/local/bin/port-scan-monitor.sh

# Shodan monitoring (check if exposed in Shodan database)
curl -s "https://api.shodan.io/shodan/host/203.0.113.42?key=API_KEY"
# Check for unexpected exposures

# UFW firewall log monitoring
tail -f /var/log/ufw.log | grep REJECT

# Prometheus network metrics
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['127.0.0.1:9100']

# Alert on unusual listening ports
groups:
  - name: network_exposure
    rules:
      - alert: UnexpectedOpenPort
        expr: node_network_up > 3
        for: 5m
        annotations:
          summary: "Unexpected number of open ports"
```

**Alerting rules:**
- New listening port detected → Alert
- Port scan attempt detected (multiple rejected packets) → Alert
- Service binding changed from 127.0.0.1 to 0.0.0.0 → Alert
- Firewall rule modified → Log and review

---

## 11. Testing Methods

**External port scanning (from different network):**
```bash
# From external host
nmap -sV -p- --open agent.company.com
nmap -A agent.company.com
nmap --script vuln agent.company.com  # Vulnerability detection

# Should only show: port 443 open, no service identification
```

**Internal validation (from agent host):**
```bash
# Verify services listen on correct interfaces
sudo netstat -tulpn | grep LISTEN

# Verify firewall blocks unexpected traffic
sudo iptables -L -n -v

# Test that localhost access works
curl http://127.0.0.1:8000/health  # Should work
curl http://0.0.0.0:8000/health    # Should fail

# Verify SSH port change
ssh -p 2222 localhost  # Should work
ssh -p 22 localhost    # Should timeout
```

**TLS/HTTPS validation:**
```bash
# Full TLS test
testssl.sh https://agent.company.com

# Check certificate
openssl s_client -connect agent.company.com:443 -servername agent.company.com

# Verify security headers
curl -I https://agent.company.com
# Check for: HSTS, X-Frame-Options, X-Content-Type-Options

# Header security scoring
curl -I https://agent.company.com | grep -i 'strict-transport\|x-frame\|x-content'
```

**Docker network validation:**
```bash
# Verify Docker networks are isolated
docker network inspect openclaw-internal
# Check that only intended containers are connected

# Test cross-network communication
docker exec openclaw-api curl http://openclaw-webhook:8001/health
# Should work (on same network)

docker exec openclaw-api curl http://10.0.0.1/health
# Should fail (different network)
```

---

## 12. Mastery Checklist

- [ ] Audit current network exposure (netstat, nmap)
- [ ] Document all listening services and their binding addresses
- [ ] Change SSH from port 22 to non-standard port
- [ ] Setup UFW firewall with default-deny ingress
- [ ] Bind all internal services to 127.0.0.1
- [ ] Configure Nginx/Caddy reverse proxy for external services
- [ ] Obtain TLS certificate and enable HTTPS
- [ ] Verify external port scan shows minimal exposure
- [ ] Implement Docker network segmentation
- [ ] Test that services are not accessible across networks
- [ ] Setup bastion host for SSH access
- [ ] Configure WireGuard for management traffic
- [ ] Implement mTLS for service-to-service communication
- [ ] Deploy Cloudflare Tunnel for zero public ports
- [ ] Setup automated port monitoring and alerting
- [ ] Document network architecture and firewall rules
- [ ] Establish change management for network changes
- [ ] Test disaster recovery (restore from backup config)
- [ ] Perform external penetration test
- [ ] Achieve A+ rating on testssl.sh
- [ ] Zero unexpected ports on external scan
- [ ] All management traffic encrypted (VPN/mTLS)

---

## 13. Common Mistakes

**Running services as root on default ports:**
```bash
# WRONG: Service runs as root on port 80
sudo openclaw-agent --port 80

# RIGHT: Service runs as user, reverse proxy handles 80/443
openclaw-agent --port 8001  # User runs it
# Nginx (root) proxies 443 → 8001 (user)
```

**Exposing management interfaces:**
```yaml
# WRONG: Management UI accessible from internet
management_ui:
  host: 0.0.0.0
  port: 8080

# RIGHT: Management UI internal-only
management_ui:
  host: 127.0.0.1
  port: 8080
  # Access via: ssh -L 8080:127.0.0.1:8080 bastion
```

**No TLS on webhook handler:**
```bash
# WRONG: Webhook handler unencrypted
curl http://agent.company.com/webhook

# RIGHT: TLS reverse proxy terminates HTTPS
curl https://agent.company.com/webhook
# Traffic encrypted in transit, signature verified
```

**Trusting Docker's default networking:**
```bash
# WRONG: All containers on default bridge can reach each other
docker run openclaw-api
docker run postgres
# Container can reach Postgres (shouldn't)

# RIGHT: Explicit network isolation
docker network create internal
docker run --network internal openclaw-api
docker run --network internal postgres
# Only containers on same network can communicate
```

**SSH password authentication enabled:**
```bash
# WRONG: Allows brute-force attacks
PasswordAuthentication yes

# RIGHT: Key-based authentication only
PasswordAuthentication no
PubkeyAuthentication yes
```

---

## 14. Key Performance Indicators

Monitor these continuously:

- **Open Ports Count:** Should be ≤2 (HTTPS + maybe HTTP redirect)
- **Service Binding Scope:** 100% of internal services on 127.0.0.1
- **TLS Grade:** A+ on testssl.sh
- **Time to Detect Exposure:** <1 hour (via automated scanning)
- **Port Scan Resistance Score:** No service identification possible
- **Firewall Rule Changes:** All documented and approved
- **Management Access:** 100% via VPN/bastion, 0% direct SSH from internet
- **Unplanned Port Opens:** Should be 0 (detected within 5 minutes)
- **Certificate Expiry:** Monitored, auto-renewal tested

---

## 15. Scaling Network Security

**Multi-host patterns:**
```bash
# Load balancer (public)
│
├─ Nginx/Caddy (TLS termination)
│  │
│  ├─ OpenClaw Agent 1 (internal, 10.0.1.5)
│  ├─ OpenClaw Agent 2 (internal, 10.0.1.6)
│  └─ OpenClaw Agent 3 (internal, 10.0.1.7)
│
└─ Bastion Host (SSH gateway, 2222)
   │
   ├─ VPN Server (WireGuard)
   └─ Prometheus (metrics collection)

# Load balancer security
- DDoS protection (Cloudflare/AWS Shield)
- Rate limiting per client
- WAF rules for webhook payload validation
- TLS 1.3 only

# Agent-to-agent communication
- mTLS within cluster
- Internal DNS (no external resolution)
- Service mesh (Istio) for policy enforcement
```

**CDN/WAF integration:**
```bash
# Cloudflare WAF rules
- Block non-whitelisted user agents
- Rate limit by IP (10 req/sec)
- Block countries not using service
- Bot management for suspicious patterns

# Origin shielding
- Requests → Cloudflare → Origin Shield → Origin
- Additional caching layer, origin DDoS protection
```

---

## 16. Architect Insights: Future of AI Agent Network Security

**Emerging patterns:**

1. **eBPF-based networking:** Kernel-level packet filtering without IP tables
   - Load program: `bpftool prog load filter.o type xdp dev eth0`
   - Microsecond-level latency, kernel-native performance

2. **Service mesh evolution:** From Istio → eBPF-native (Cilium)
   ```bash
   # Cilium replaces kube-proxy, provides
   - Kernel-native networking (no userspace proxy)
   - Automatic mTLS with certificate rotation
   - Identity-based policies (not IP-based)
   ```

3. **Zero-trust by default:** Assume breach, verify everything
   - Every packet signed and encrypted
   - Identity verified at Layer 3/4, not Layer 2
   - Implicit deny for all services

4. **Encrypted DNS (DoH/DoT):** Hide service discovery from ISP
   ```bash
   # Recursive resolver on local machine
   # All DNS queries → TLS tunnel → Cloudflare/Quad9
   ```

5. **Decentralized identity:** OpenClaw agents identified by keys, not IPs
   - Agents register public key
   - Authentication via HMAC-SHA256 signature
   - IP changes don't break connectivity

**Recommendation for new deployments:**
- Start with Cloudflare Tunnel (zero public ports)
- Plan for Cilium service mesh at scale (>5 agents)
- Implement DoH for DNS privacy immediately
- Design for key-based agent identity (IP-agnostic)

---

**Last updated:** 2026-02-28
**Security review:** Quarterly
**Version:** 2.1 (Enterprise-grade, OpenClaw 3.x+)
