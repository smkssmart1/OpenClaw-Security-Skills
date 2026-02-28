---
name: authentication-access-control
description: "Enterprise-grade skill for implementing robust authentication and access control on OpenClaw AI agent infrastructure. Use whenever configuring SSH key authentication, disabling password login, setting up Fail2Ban, implementing identity security for AI agent servers, hardening login mechanisms, or designing IAM policies for autonomous AI systems. Also trigger for brute-force protection, MFA setup, certificate-based auth, PAM configuration, or any identity/authentication hardening for bot infrastructure."
---

# Authentication & Access Control for OpenClaw AI Infrastructure

## 1. Purpose

Identity is the new perimeter. Authentication & access control form the foundation of OpenClaw security architecture, protecting autonomous AI agent infrastructure from unauthorized access, credential compromise, and lateral movement. This skill ensures that only authenticated, authorized identities can provision agents, execute commands, and access sensitive AI model inference pipelines.

## 2. First-Principles of Identity Security

**Authentication** = proving you are who you claim (identification)
**Authorization** = determining what authenticated identities can do (permissions)
**Accounting** = logging all access, actions, and state changes for audit trails

The security chain is only as strong as the weakest link. Weak authentication enables entire infrastructure compromise. For autonomous AI systems, strong identity controls prevent:
- Malicious actor control of agent fleets
- Unauthorized model access and exfiltration
- Privilege escalation exploits
- Supply chain compromise of AI pipelines

## 3. Why Passwords Fail

**Attack Vectors & Failure Modes:**

- **Brute Force**: 8-character passwords (95^8 = 6.6 trillion) crack in hours with modern GPU clusters (100 billion guesses/sec)
- **Credential Stuffing**: 4.3 billion compromised credentials available on dark web; reuse across services enables instant access
- **Phishing**: 45% of data breaches involve phishing; users are biometric weak point
- **Rainbow Tables**: 100 billion pre-computed password hashes ($20 cloud compute)
- **Weak Hashing**: MD5, SHA1 easily cracked; salting adds only 2^32 entropy

**Why SSH Keys Win:**

- RSA-4096 = 2^4096 possible keys (10^1233 combinations); effectively uncrackable
- Keys never transmitted in authentication (only signatures); immune to credential stuffing
- Revocation is instant; no password reset delays
- Multi-factor capable via hardware security keys (FIDO2)
- Audit trail shows which key authenticated each session

**Statistics**: Organizations using SSH key-only auth see 99.7% reduction in unauthorized access incidents vs password-based systems.

## 4. OpenClaw Access Architecture

```
┌─────────────────────────────────────────────────────┐
│              OpenClaw Access Perimeter              │
├─────────────────────────────────────────────────────┤
│ SSH Access Points                                    │
│  ├─ Agent provisioning server (management plane)   │
│  ├─ Agent compute nodes (inference servers)        │
│  └─ Model repository / artifact storage            │
├─────────────────────────────────────────────────────┤
│ API Endpoints (CI/CD, deployment)                  │
│  ├─ OpenClaw Agent API (gRPC/REST)                │
│  ├─ Model inference endpoints                      │
│  └─ Audit log APIs                                 │
├─────────────────────────────────────────────────────┤
│ Database Connections                               │
│  ├─ Agent state database (PostgreSQL)             │
│  ├─ Audit logs (time-series DB)                   │
│  └─ Secrets vault (HashiCorp Vault)               │
├─────────────────────────────────────────────────────┤
│ Admin Panels (Web UI)                              │
│  ├─ OpenClaw dashboard (OIDC/SAML)                │
│  └─ Prometheus/Grafana (mTLS)                     │
└─────────────────────────────────────────────────────┘
```

Each layer requires its own authentication scheme, coordinated through a central identity provider.

## 5. Implementation Levels

### Beginner — SSH Key Setup & Password Disable

**Goal**: Eliminate password authentication, deploy SSH public-key infrastructure.

**1. Generate SSH Key Pair on Client**
```bash
# Generate 4096-bit RSA key (modern systems support ed25519; for max compatibility, use RSA)
ssh-keygen -t rsa -b 4096 -f ~/.ssh/openclaw_agent_key -C "engineer@openclaw.io" -N "passphrase"

# Set restrictive permissions (critical for security)
chmod 600 ~/.ssh/openclaw_agent_key
chmod 644 ~/.ssh/openclaw_agent_key.pub

# View public key for deployment
cat ~/.ssh/openclaw_agent_key.pub
```

**2. Deploy Public Key to Agent Servers**
```bash
# Copy public key to server
ssh-copy-id -i ~/.ssh/openclaw_agent_key.pub -p 2222 deploy@agent-provisioning.openclaw.io

# Verify (should connect without password)
ssh -i ~/.ssh/openclaw_agent_key -p 2222 deploy@agent-provisioning.openclaw.io 'echo "Auth successful"'
```

**3. Harden sshd_config on Agent Servers**
```bash
# Backup original
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Edit with root privileges
sudo nano /etc/ssh/sshd_config
```

Add/modify these lines:
```
# Disable password authentication entirely
PasswordAuthentication no
PermitEmptyPasswords no
UsePAM yes

# Disable root login
PermitRootLogin no

# Restrict to specific users/groups
AllowUsers deploy monitoring svc-openclaw
AllowGroups openclaw-agents

# Limit concurrent auth attempts
MaxAuthTries 3
MaxSessions 10

# Timeout idle connections
ClientAliveInterval 300
ClientAliveCountMax 2

# Use only secure ciphers (FIPS-140-2 compliant if required)
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
HostKeyAlgorithms ssh-rsa,rsa-sha2-256,rsa-sha2-512
KexAlgorithms diffie-hellman-group-exchange-sha256,ecdh-sha2-nistp256

# Disable risky features
X11Forwarding no
PermitTunnel no
AllowTcpForwarding no
AllowAgentForwarding no

# Enable privilege separation
UsePrivilegeSeparation sandbox

# Logging
SyslogFacility AUTH
LogLevel VERBOSE
```

**4. Restart SSH and Test**
```bash
# Reload sshd (safe; doesn't drop existing connections)
sudo systemctl reload ssh

# Test from client (must succeed without password)
ssh -i ~/.ssh/openclaw_agent_key deploy@agent-provisioning.openclaw.io

# Verify password auth is disabled (should get "Permission denied")
ssh -o PubkeyAuthentication=no deploy@agent-provisioning.openclaw.io
```

### Intermediate — Fail2Ban & Advanced SSH Hardening

**Goal**: Block brute-force and credential-stuffing attacks with dynamic firewall rules.

**1. Install Fail2Ban**
```bash
sudo apt-get update && sudo apt-get install -y fail2ban fail2ban-systemd
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

**2. Configure Fail2Ban for SSH**
Create `/etc/fail2ban/jail.local`:
```ini
[DEFAULT]
# Ban duration: 1 hour
bantime = 3600

# Observation window: 10 minutes
findtime = 600

# Max failed attempts before ban
maxretry = 3

# Action: ban + email notification
action = %(action_mwl)s
         email[dest=security-team@openclaw.io]

# Ignore localhost and internal networks
ignoreip = 127.0.0.1/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

[sshd]
# SSH-specific jail
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
findtime = 600

# Advanced: trigger on multiple failed auth types
action = %(action_mwl)s
         wechat[dest=security-alerts]

[sshd-aggressive]
# Ultra-aggressive: ban on single failed attempt from new IP
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 1
bantime = 86400
findtime = 60
# Only applies to IPs without established SSH history
action = %(action_mwl)s
```

**3. Configure Email Notifications**
Edit `/etc/fail2ban/action.d/sendmail-common.conf`:
```ini
[DEFAULT]
# Email address for alerts
destemail = security-team@openclaw.io
sendername = Fail2Ban (OpenClaw Security)
action_mwl = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
            %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s", protocol="%(protocol)s"]
            %(mta)s-lines[name=%(__name__)s, dest="%(destemail)s", logpath="%(logpath)s"]
```

**4. Monitor Fail2Ban Activity**
```bash
# View current bans
sudo fail2ban-client status sshd

# Check jail details
sudo fail2ban-client -vvv status sshd

# Watch logs in real-time
sudo tail -f /var/log/fail2ban.log | grep -E "Ban|Unban|NOTICE"

# List all IPs currently banned
sudo fail2ban-client status sshd | grep "Currently banned"

# Manually unban an IP (if false positive)
sudo fail2ban-client set sshd unbanip <IP_ADDRESS>
```

**5. Advanced SSH Hardening (sshd_config additions)**
```
# Rate-limit auth attempts per connection
PerSourceNetBlockSize 2
PerSourceMaxStartups 10:30:100

# Enforce key-based auth only
PubkeyAuthentication yes
AuthenticationMethods publickey
IgnoreRhosts yes
HostbasedAuthentication no

# Disable weaker algorithms
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Require host keys to be signed by CA (advanced)
TrustedUserCAKeys /etc/ssh/trusted-ca-keys.pub

# Log all authentication attempts (verbose)
LogLevel VERBOSE
SyslogFacility AUTH
```

**6. Test Brute-Force Protection**
```bash
# Attempt multiple failed logins (will be banned after 3 failures)
for i in {1..5}; do
  ssh -i /dev/null deploy@agent-provisioning.openclaw.io 2>&1 | head -1
  sleep 1
done

# Verify ban is in place
sudo fail2ban-client status sshd
# Should show the attacking IP is banned
```

### Advanced — Certificate-Based Auth & MFA

**Goal**: Implement SSH certificates + time-based one-time passwords (TOTP) for human users.

**1. SSH Certificate Authority Setup**

Generate CA keypair (on secure, air-gapped systems admin workstation):
```bash
# Generate CA key (never shared, kept in vault)
ssh-keygen -t rsa -b 4096 -f ~/ssh-ca-key -C "OpenClaw SSH Certificate Authority" -N "strong-passphrase"

# Generate host CA key (signs server certificates)
ssh-keygen -t rsa -b 4096 -f ~/ssh-host-ca-key -C "OpenClaw SSH Host CA" -N "strong-passphrase"

# Keep these offline; deploy public keys only
ls -la ~/*ca*.pub
```

**2. Deploy CA Public Keys to All Agents**
```bash
# Copy CA public keys to every agent server
scp -i ~/.ssh/openclaw_agent_key ~/ssh-ca-key.pub deploy@agent-provisioning.openclaw.io:/tmp/
ssh -i ~/.ssh/openclaw_agent_key deploy@agent-provisioning.openclaw.io << 'EOF'
  sudo mkdir -p /etc/ssh/ca
  sudo mv /tmp/ssh-ca-key.pub /etc/ssh/ca/user-ca.pub
  sudo mv /tmp/ssh-host-ca-key.pub /etc/ssh/ca/host-ca.pub
  sudo chown -R root:root /etc/ssh/ca
  sudo chmod 755 /etc/ssh/ca && sudo chmod 644 /etc/ssh/ca/*
EOF
```

**3. Update sshd_config for Certificate Auth**
```
# Trust certificates signed by CA
TrustedUserCAKeys /etc/ssh/ca/user-ca.pub

# Require certificate principals (enforces role-based access)
AuthorizedPrincipalsFile /etc/ssh/authorized_principals/%u
```

**4. Generate User Certificates**

For engineer@openclaw.io, valid for 24 hours with specific principals:
```bash
# User signs their existing public key with CA
ssh-keygen -s ~/ssh-ca-key \
  -I "engineer@openclaw.io-2026-02-28" \
  -n "deploy,monitoring,viewer" \
  -V +1d \
  -z 1001 \
  ~/.ssh/openclaw_agent_key.pub

# Output: openclaw_agent_key-cert.pub (certificate)
# User now has both openclaw_agent_key and openclaw_agent_key-cert.pub
```

**5. TOTP MFA Setup (Human Users)**

Install and configure:
```bash
# Install libpam-google-authenticator
sudo apt-get install -y libpam-google-authenticator

# User generates TOTP seed (runs on user machine)
google-authenticator -t -d -w 3 -r 3 -R 30

# Output: QR code + backup codes (store securely in password manager)
# Seed stored in ~/.google_authenticator on user's machine
```

Update PAM config (`/etc/pam.d/sshd`):
```
# Add TOTP challenge after successful key auth
@include common-auth
auth required pam_google_authenticator.so nullok prompt=echo
@include common-account
@include common-session-noninteractive
```

Update sshd_config:
```
# Enable challenge-response for TOTP
ChallengeResponseAuthentication yes
PasswordAuthentication no
```

Test MFA:
```bash
ssh -i ~/.ssh/openclaw_agent_key deploy@agent-provisioning.openclaw.io
# Prompts: "Verification code: "
# Enter 6-digit code from authenticator app
```

**6. Hardware Security Key Support (FIDO2)**

For maximum security, support FIDO2 keys (YubiKey, Titan, etc.):
```bash
# Client: add FIDO2 key
ssh-keygen -t ecdsa-sk -f ~/.ssh/openclaw_sk_key -C "YubiKey OpenClaw Auth"

# Deploy public key
ssh-copy-id -i ~/.ssh/openclaw_sk_key.pub deploy@agent-provisioning.openclaw.io

# Use: requires physical key touch for authentication
ssh -i ~/.ssh/openclaw_sk_key deploy@agent-provisioning.openclaw.io
# Prompts: "Please touch the authenticator"
```

### Architect — Enterprise IAM Integration

**Goal**: Federate identity across OpenClaw with LDAP/AD for on-premises orgs, OIDC/SAML for SaaS deployments.

**1. LDAP Integration for SSH**

Install and configure LDAP client:
```bash
sudo apt-get install -y libnss-ldap libpam-ldap nslcd
sudo auth-client-config -t nss -p lac_ldap
```

Edit `/etc/nslcd.conf`:
```
uri ldap://ldap.internal.openclaw.io:389
base dc=openclaw,dc=io
binddn cn=svc-openclaw,ou=Service Accounts,dc=openclaw,dc=io
bindpw ${LDAP_SERVICE_PASSWORD}

# User and group mappings
filter passwd (&(objectClass=posixAccount)(uid=*))
filter group (&(objectClass=posixGroup)(cn=*))
map passwd uid uid
map passwd homeDirectory "/home/$uid"
map passwd loginShell "/bin/bash"
```

Enable NSS resolution:
```bash
# Update /etc/nsswitch.conf
sudo sed -i 's/passwd:.*/passwd:         files ldap/' /etc/nsswitch.conf
sudo sed -i 's/group:.*/group:          files ldap/' /etc/nsswitch.conf
sudo systemctl restart nslcd
```

Test:
```bash
# Should resolve LDAP users
getent passwd engineer@openclaw.io
# Should show UID, GID, home dir from LDAP
```

**2. OIDC for Web Dashboards (OAuth 2.0)**

Deploy OAuth 2.0 proxy (`oauth2-proxy`) in front of Prometheus/Grafana:
```bash
# Install oauth2-proxy
wget https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v7.4.0/oauth2-proxy-v7.4.0.linux-amd64.tar.gz
tar xzf oauth2-proxy-v7.4.0.linux-amd64.tar.gz
sudo mv oauth2-proxy /usr/local/bin/
sudo chmod +x /usr/local/bin/oauth2-proxy
```

Configure `/etc/oauth2-proxy/config.cfg`:
```ini
# OIDC provider (Auth0, Okta, Google Workspace, etc.)
provider = "oidc"
oidc_issuer_url = "https://auth.openclaw.io"
client_id = "${OIDC_CLIENT_ID}"
client_secret = "${OIDC_CLIENT_SECRET}"

# OAuth redirect
redirect_url = "https://grafana.openclaw.io/oauth2/callback"

# Protect Grafana at upstream
upstreams = ["http://localhost:3000"]
http_address = "127.0.0.1:4180"

# Require specific group membership
oidc_groups_claim = "groups"
allowed_groups = ["openclaw-admins", "openclaw-engineers"]

# Session config
cookie_secure = true
cookie_httponly = true
cookie_samesite = "lax"
cookie_expire = 3600
```

Run behind reverse proxy (nginx):
```nginx
server {
    listen 443 ssl http2;
    server_name grafana.openclaw.io;

    ssl_certificate /etc/letsencrypt/live/grafana.openclaw.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/grafana.openclaw.io/privkey.pem;

    location / {
        auth_request /oauth2/auth;
        error_page 401 = /oauth2/sign_in;

        proxy_pass http://oauth2-proxy:4180;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /oauth2 {
        proxy_pass http://oauth2-proxy:4180;
    }
}
```

**3. Just-In-Time (JIT) Access via Vault**

Use HashiCorp Vault for ephemeral SSH credentials:
```bash
# Enable SSH secrets engine
vault secrets enable ssh

# Configure SSH CA
vault write ssh/config/ca \
  generate_signing_key=true

# Create role for engineers (valid 1 hour)
vault write ssh/roles/engineer-role \
  key_type=ca \
  ttl=3600 \
  max_ttl=3600 \
  allowed_users="*" \
  allow_user_certificates=true \
  key_id_format="{{role_name}}-{{unix_time}}"
```

Engineer requests temporary credential:
```bash
# Authenticate to Vault
vault login -method=oidc

# Request SSH cert (valid 1 hour)
vault write -field=signed_key ssh/sign/engineer-role \
  public_key=@~/.ssh/openclaw_agent_key.pub > ~/.ssh/id-cert.pub

# Connect with temporary cert
ssh -i ~/.ssh/openclaw_agent_key \
    -i ~/.ssh/id-cert.pub \
    deploy@agent-provisioning.openclaw.io
```

All access logged in Vault audit trails.

**4. Privileged Access Management (PAM) Policies**

Implement sudoeers rotation and approval workflows:
```bash
# /etc/sudoers (via visudo only)
# Allow 'deploy' to restart agents without password (MFA sufficient)
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart openclaw-*

# Allow engineers to escalate to 'deployment' role (with approval)
%engineers ALL=(deployment) ALL

# Log all sudo usage to syslog
Defaults syslog=local1
Defaults use_pty
```

## 6. Step-by-Step Authentication Setup Checklist

**Phase 1: SSH Key Infrastructure (Week 1)**
1. [ ] Generate organizational SSH CA keypair (air-gapped workstation)
2. [ ] Deploy CA public key to all agent servers
3. [ ] Harden sshd_config on all agents (PasswordAuthentication=no, PermitRootLogin=no)
4. [ ] Restart SSH and test from all client machines
5. [ ] Verify no password authentication works

**Phase 2: Fail2Ban Protection (Week 1)**
1. [ ] Install fail2ban on all edge/SSH entry points
2. [ ] Configure jail rules (sshd jail with 3 maxretry, 3600s bantime)
3. [ ] Set up email alerts to security team
4. [ ] Test brute-force protection (verify bans are triggered)
5. [ ] Monitor logs for false positives

**Phase 3: Certificate Rollout (Week 2-3)**
1. [ ] Generate user certificates for all SSH users
2. [ ] Deploy TrustedUserCAKeys to all agents
3. [ ] Update authorized_principals files per user role
4. [ ] Test certificate-based login
5. [ ] Revoke old RSA key approvals

**Phase 4: MFA Deployment (Week 3-4)**
1. [ ] Enroll humans in TOTP (google-authenticator)
2. [ ] Deploy FIDO2 keys to high-privilege users
3. [ ] Update PAM config on all agents
4. [ ] Test TOTP challenge during SSH login
5. [ ] Create recovery/backup procedures

**Phase 5: IAM Federation (Week 4-6)**
1. [ ] Configure LDAP client on all agents
2. [ ] Test LDAP user login via SSH
3. [ ] Deploy oauth2-proxy for web dashboards
4. [ ] Configure Vault for ephemeral SSH access
5. [ ] Audit trail: verify all access logs

## 7. Real Attack Prevention Examples

**Scenario 1: Brute-Force Attack (Detected & Stopped)**

Attacker: Attempt 50 SSH logins in 60 seconds
```
# Attacker runs:
for i in {1..50}; do
  ssh -o ConnectTimeout=2 deploy@agent-provisioning.openclaw.io < /dev/null &
done

# Fail2Ban detects 3 failures within 10 minutes
# Immediately adds attacker IP to firewall ban (iptables rule)
# Email alert: "SSHD ban for 203.0.113.45 - maxretry exceeded"
# Attacker's further attempts timeout (firewall DROP rule)
# After 3600 seconds, IP is unbanned (configurable)
```

**Result**: Brute-force attempt failed within seconds. With 100 billion guesses/sec GPU cluster, attacker would need billions of years to crack RSA-4096.

**Scenario 2: Credential Stuffing (Stopped by MFA)**

Attacker: Uses leaked password "OpenClaw2024" from breach database
```
# Attacker runs:
ssh -p 2222 deploy@agent-provisioning.openclaw.io
# Password: OpenClaw2024
# Result: PasswordAuthentication=no
# Connection rejected immediately (no password auth allowed)

# Attacker tries SSH key attack:
ssh -p 2222 deploy@agent-provisioning.openclaw.io
# No private key on attacker machine
# Fail2Ban detects auth failure, bans IP
```

**Result**: Password-based compromise impossible. SSH key infrastructure + Fail2Ban prevented access.

**Scenario 3: Compromised Key (Contained)**

Engineer's laptop stolen with private key
```
# Attacker tries stolen key:
ssh -i ~/.ssh/stolen_openclaw_agent_key deploy@agent-provisioning.openclaw.io

# Authentication succeeds BUT:
# 1. TOTP MFA challenge: "Verification code:"
#    Attacker doesn't have phone/authenticator app
#    MFA requirement blocks access
# 2. Audit log shows: "User 'engineer@openclaw.io' key used from new IP 203.0.113.50"
# 3. Security team receives alert
# 4. Engineer revokes certificate immediately (valid only 24h, expires automatically)

# Engineer issues new certificate:
ssh-keygen -s ~/ssh-ca-key \
  -I "engineer@openclaw.io-2026-02-29" \
  -n "deploy,monitoring,viewer" \
  -V +1d \
  ~/.ssh/openclaw_agent_key.pub
```

**Result**: Compromise contained to <30 minutes (24h cert expiry). Stolen key useless; attacker unable to pass MFA. Full audit trail.

**Scenario 4: Privilege Escalation Blocked**

Attacker gains user 'monitoring' access, attempts sudo exploit
```
# Attacker runs (as 'monitoring' user):
sudo su - root
# Result: "user monitoring is not in sudoers"
# Fail2Ban detects sudo failure
# Alert: "Failed sudo attempt: monitoring -> root"

# Only 'deploy' user has passwordless sudo for systemctl restart
# Role-based access control enforced in sudoers
```

**Result**: Privilege escalation blocked. Principle of least privilege enforced.

## 8. Fail2Ban Logic & Policies Deep Dive

**Filter Regex (Pattern Matching)**

Fail2Ban's filter files use regex to identify failed auth attempts in logs:

`/etc/fail2ban/filter.d/sshd.conf`:
```ini
[Definition]
# Match "Invalid user" attempts
failregex = ^<HOST> \S+ Invalid user \S+ from <HOST> port \d+ ssh2?$
            ^<HOST> \S+ User \S+ from <HOST> not allowed because not in AllowUsers$
            ^<HOST> \S+ Authentication refused: bad packet type$
            ^Failed \S+ for (?:invalid user |)?\S+ from <HOST>(?:\s+ssh2)?$
            ^Received disconnect from <HOST> port \d+:11: Bye Bye \[preauth\]$

# Match successful login (exemption)
ignoreregex = ^<HOST> - SSH client has disconnected$
              ^Connection reset by <HOST>$
```

**Jail Configuration Actions**

```ini
[sshd-enterprise]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log

# Progressive ban: increase ban time with repeated offenses
bantime = 3600,86400,604800
findtime = 600
maxretry = 3

# Custom action chain
action = iptables-multiport[name=SSH, port="2222", protocol=tcp]
         %(action_mwl)s
         custom-webhook[url="https://siem.openclaw.io/fail2ban"]
         slack-notify[token="${SLACK_TOKEN}"]
```

**Whitelisting Rules**

```ini
[DEFAULT]
# IP whitelist (never banned)
ignoreip = 127.0.0.1/8
           10.0.0.0/8
           203.0.113.0/24
           office.openclaw.io

# Regex-based exceptions
ignoreregex = ^<HOST> \S+ svc-monitoring \S+ succeeded$
```

**Custom Actions**

Trigger webhooks on ban/unban:

`/etc/fail2ban/action.d/custom-webhook.conf`:
```ini
[Definition]
actionstart = echo "[$(date)] Fail2Ban action started for %(name)s" >> /var/log/fail2ban-webhook.log
actioncheck = echo "[$(date)] Checking %(name)s status" >> /var/log/fail2ban-webhook.log
actionban = curl -X POST https://siem.openclaw.io/fail2ban \
  -H "Content-Type: application/json" \
  -d '{"action":"ban","jail":"%(name)s","ip":"<ip>","time":"%(bantime)d"}'
actionunban = curl -X POST https://siem.openclaw.io/fail2ban \
  -H "Content-Type: application/json" \
  -d '{"action":"unban","jail":"%(name)s","ip":"<ip>"}'
```

## 9. Governance & Access Policies

**Key Rotation Schedule**

- SSH user certificates: renewed every 24 hours (short-lived, automated)
- SSH host CA key: rotated annually, stored offline, never shared
- User TOTP seeds: replaced every 90 days or on device loss
- LDAP service account password: rotated every 30 days
- OAuth2-proxy client secrets: rotated every 90 days

**Access Review Procedures**

Quarterly (3-month) audit:
```bash
# List all active SSH keys deployed
sudo awk '{print NR, $3}' ~/.ssh/authorized_keys

# Check LDAP group membership
ldapquery cn=openclaw-engineers,ou=Groups,dc=openclaw,dc=io

# Audit Vault SSH role assignments
vault list ssh/roles/

# Review sudo access
sudo grep -E '^%|^[a-z]' /etc/sudoers
```

Remove access:
1. Delete user's public key from `authorized_keys`
2. Revoke certificates (wait for 24h expiry or manually revoke)
3. Remove LDAP group membership
4. Disable Vault SSH role access

**Offboarding Checklist**

When engineer leaves organization:
- [ ] Revoke SSH certificate (issue CA revocation)
- [ ] Delete public key from all servers
- [ ] Remove LDAP account (disables UNIX login)
- [ ] Disable OAuth2 user account
- [ ] Revoke Vault SSH access
- [ ] Audit all access logs for final 90 days
- [ ] Retrieve FIDO2 hardware key

## 10. Monitoring Unauthorized Attempts

**Log Analysis Queries**

```bash
# SSH failed auth attempts (today)
sudo journalctl -u ssh --since today --grep="Failed password|Invalid user" | wc -l

# Fail2Ban bans (last 24h)
sudo grep "Ban" /var/log/fail2ban.log | tail -20

# Successful logins per user
sudo lastlog -t 24h

# Sudo usage (all escalations)
sudo grep "sudo:" /var/log/auth.log | grep "COMMAND="
```

**SIEM Integration**

Forward all auth logs to central SIEM (Splunk, ELK, Datadog):

rsyslog config (`/etc/rsyslog.d/50-default.conf`):
```
# Forward SSH auth logs to SIEM
:programname, isequal, "sshd" @@siem.openclaw.io:514
:programname, isequal, "fail2ban" @@siem.openclaw.io:514
```

**Alerting Rules (Splunk SPL)**

```
# Alert: Multiple failed SSH auth from same IP
index=auth sourcetype=sshd "Failed"
| stats count as failures by src_ip
| where failures > 10
| alert

# Alert: Successful SSH from new country
index=auth sourcetype=sshd "Accepted publickey"
| iplocation src_ip
| where Country != "US" AND Country != "CA"
| alert
```

## 11. Testing Scenarios

**Test 1: Password Auth is Truly Disabled**
```bash
ssh -o PubkeyAuthentication=no deploy@agent-provisioning.openclaw.io
# Expected: "Permission denied (publickey)"
# Should NOT prompt for password
```

**Test 2: Fail2Ban Bans on 3 Failures**
```bash
# Generate 3 failed attempts
for i in {1..3}; do
  ssh -i /dev/null deploy@agent-provisioning.openclaw.io 2>&1 &
  sleep 1
done

# Check status
sudo fail2ban-client status sshd
# Should show "Currently banned: 1"
```

**Test 3: Certificate Auth Works**
```bash
# SSH with certificate (should not prompt for password)
ssh -i ~/.ssh/openclaw_agent_key \
    -i ~/.ssh/openclaw_agent_key-cert.pub \
    deploy@agent-provisioning.openclaw.io
# Expected: immediate shell access
```

**Test 4: TOTP MFA Challenge**
```bash
ssh -i ~/.ssh/openclaw_agent_key deploy@agent-provisioning.openclaw.io
# Expected: "Verification code: " prompt
# Enter 6-digit code from authenticator app
```

**Test 5: LDAP User Resolution**
```bash
getent passwd engineer@openclaw.io
# Expected: uid, gid, home dir from LDAP
ssh engineer@openclaw.io@agent-provisioning.openclaw.io
```

**Test 6: Vault Ephemeral Access**
```bash
# Request temp SSH cert
vault write -field=signed_key ssh/sign/engineer-role \
  public_key=@~/.ssh/id_rsa.pub > /tmp/id-cert.pub

# Use temp cert (should work)
ssh -i ~/.ssh/id_rsa -i /tmp/id-cert.pub deploy@agent-provisioning.openclaw.io

# Verify cert expires
ssh-keygen -L -f /tmp/id-cert.pub | grep -E "Valid|Expiration"
```

## 12. Mastery Checklist

- [ ] Can generate SSH CA keypair and understand why it's kept offline
- [ ] Can deploy SSH public key to 50+ servers at scale (ansible/terraform)
- [ ] Can read sshd_config and explain each security directive
- [ ] Can troubleshoot Fail2Ban bans (view logs, unban false positives)
- [ ] Can write regex filter rules for custom SSH auth scenarios
- [ ] Can issue SSH certificates with specific principals and TTL
- [ ] Can configure TOTP MFA and understand TOTP RFC 6238
- [ ] Can set up LDAP NSS resolution for password-free authentication
- [ ] Can deploy oauth2-proxy for OAuth2 federation
- [ ] Can configure Vault SSH secrets engine for ephemeral credentials
- [ ] Can audit all SSH access via logs and understand patterns
- [ ] Can explain privilege escalation vectors and sudoers rules
- [ ] Can revoke a compromised key and minimize impact window
- [ ] Can scale identity infrastructure to 1000+ users
- [ ] Can explain why RSA-4096 is cryptographically superior to 12-char passwords

## 13. Anti-Patterns (Do NOT Do These)

**Anti-Pattern 1: Shared SSH Keys**
```bash
# BAD: Multiple users share same key
scp openssh_shared_key.pem engineer-1:/home/engineer-1/.ssh/
scp openssh_shared_key.pem engineer-2:/home/engineer-2/.ssh/
# Problem: Cannot audit who accessed what. If key leaked, must revoke access for everyone.
```

**Anti-Pattern 2: Password in SSH Config**
```
# BAD: ~/.ssh/config with IdentityFile pointing to unencrypted key
Host *
    IdentityFile ~/.ssh/unencrypted_key  # No passphrase
    User deploy
# Problem: Laptop theft = immediate compromise. Key should be encrypted with passphrase.
```

**Anti-Pattern 3: Long-Lived User Certificates**
```bash
# BAD: Certificate valid for 1 year
ssh-keygen -s ~/ssh-ca-key -V +365d ~/.ssh/key.pub
# Problem: If certificate leaked, attacker has 365 days to use it. No time window.
# GOOD: Certificate valid for 24 hours, renewed daily
ssh-keygen -s ~/ssh-ca-key -V +1d ~/.ssh/key.pub
```

**Anti-Pattern 4: No MFA for High-Privilege Access**
```
# BAD: deploy user can sudo without password AND no MFA
deploy ALL=(ALL) NOPASSWD: ALL
# Problem: If SSH key stolen, attacker has full system access.
# GOOD: Require both SSH cert AND TOTP before sudo
AuthenticationMethods publickey
ChallengeResponseAuthentication yes
```

**Anti-Pattern 5: Ignoring Fail2Ban**
```bash
# BAD: Fail2Ban installed but not monitored
sudo systemctl start fail2ban
# Problem: Bans happen silently. Legitimate users get locked out. No visibility.
# GOOD: Monitor bans, set up alerts
sudo fail2ban-client status sshd | tee /var/log/fail2ban-status.txt
# Send alerts to security team
```

**Anti-Pattern 6: No Audit Trail**
```bash
# BAD: SSH access not logged
LogLevel QUIET
# Problem: Attacker access invisible. Cannot detect compromise.
# GOOD: Verbose logging + SIEM forwarding
LogLevel VERBOSE
# Forward to SIEM
rsyslog: @@siem.openclaw.io:514
```

## 14. KPIs (Key Performance Indicators)

Monitor these metrics to ensure authentication system health:

| KPI | Target | Measurement |
|-----|--------|-------------|
| SSH auth failure rate | <5% of all attempts | `failed_auths / total_attempts` per day |
| Brute-force blocks | >99% block rate | `blocked_ips / total_attack_attempts` |
| Cert rotation compliance | 100% within 24h | `expired_certs / total_certs` (should be 0) |
| MFA enforcement rate | 100% of humans | `mfa_enabled_users / total_users` |
| Key compromise detection | <1h from incident | MTTR = Mean Time To Revocation |
| Unauthorized escalations | 0 | `failed_sudo_attempts / sudo_attempts` should be log-only |
| Vault audit trail completeness | 100% | `logged_requests / total_requests` |
| LDAP sync delay | <5 minutes | Time from LDAP change to user access change |
| Alert response time | <30 min | Time from alert to human investigation |

## 15. Enterprise IAM Integration Patterns

**Pattern 1: On-Premises Enterprise (LDAP/AD)**
```
┌──────────────────┐
│  Active Directory │ (on-prem)
│  (Company LDAP)  │
└────────┬─────────┘
         │ NSS/PAM
┌────────▼────────────────────┐
│  OpenClaw Agent Servers      │
│  (SSH + LDAP client)         │
│  (verify user @ login)       │
└─────────────────────────────┘
         ▲
         │ SSH via LDAP user
┌────────┴─────────────────────┐
│  Engineer Workstation        │
│  (ssh user@agent via LDAP)   │
└─────────────────────────────┘
```

**Pattern 2: SaaS Enterprise (OIDC/SAML)**
```
┌──────────────────────┐
│  Identity Provider   │
│  (Okta, Auth0,      │
│   Google Workspace)  │
└─────────┬────────────┘
          │ OIDC/SAML
┌─────────▼──────────────────────────┐
│  oauth2-proxy (auth gateway)       │
│  + Vault SSH ephemeral credentials │
└─────────┬──────────────────────────┘
          │ SSH cert request
┌─────────▼──────────────────────────┐
│  OpenClaw Agent Servers             │
│  (verify cert @ SSH login)          │
└─────────────────────────────────────┘
```

**Pattern 3: Hybrid (Both On-Prem + SaaS)**
```
┌──────────────┐       ┌──────────────┐
│  Active Dir  │       │  Auth0 SaaS  │
│  (LDAP)      │       │  (OIDC)      │
└──────┬───────┘       └──────┬───────┘
       │ NSS                 │ OIDC
       │                  ┌──▼────────────────┐
       └──────────┬───────▶│  Vault Identity   │
                  │        │  Broker           │
              ┌───▼────────┴───────────────────┐
              │  OpenClaw Agent Servers        │
              │  (trust both auth sources)     │
              └────────────────────────────────┘
```

## 16. Architect Insights

**Principle 1: Defense in Depth**
No single point of failure. Layer defenses:
1. SSH keys (authentication)
2. Fail2Ban (brute-force protection)
3. MFA (second factor)
4. PAM (privilege gates)
5. Audit logs (detective control)
6. SIEM (correlation & alerting)

Each layer blocks different attack vectors.

**Principle 2: Assume Compromise**
Plan for key theft:
- Short cert TTL (24h) = bounded exposure window
- Immediate revocation capability = rapid response
- Full audit trail = forensics capability
- Role-based principals = least privilege even if key compromised

**Principle 3: Operational Security**
- Keep CA keys offline (air-gapped)
- Separate cert-signing authority from day-to-day operations
- Never ship private keys; only public keys
- Encrypt keys with strong passphrases
- HSM (Hardware Security Module) for CA in production

**Principle 4: Scalability**
- Vault handles 10K+ concurrent sessions
- LDAP can authenticate millions of users
- oauth2-proxy stateless (scale horizontally)
- Fail2Ban at edge (one instance per SSH gateway)
- Centralized audit logs (time-series DB) for 1000s of servers

**Principle 5: User Experience**
Strong security doesn't require friction:
- Cert issuance automated (seamless renewal)
- FIDO2 keys reduce MFA burden (no 6-digit codes)
- Passwordless auth eliminates phishing vector
- JIT access fast (Vault cert in <1s)

**Final Security Posture:**
An OpenClaw deployment with this authentication architecture is:
- **Resistant to brute-force** (Fail2Ban blocks after 3 failures)
- **Resistant to credential stuffing** (no passwords, only keys)
- **Resistant to phishing** (no passwords to phish)
- **Resistant to key compromise** (24h cert TTL, MFA, audit)
- **Compliant** (audit trails for SOC 2, ISO 27001, HIPAA)
- **Scalable** (supports 10K+ users)
- **Auditable** (full chain of custody)

This is production-grade security for autonomous AI agent infrastructure.
