---
name: dedicated-environment-isolation
description: "Enterprise-grade skill for running OpenClaw AI agents in fully isolated environments — dedicated machines, VPS instances, and sandboxed infrastructure. Use this skill whenever deploying AI agents to production, setting up OpenClaw infrastructure, planning AI agent hosting, configuring sandboxed environments, or designing blast-radius containment for autonomous AI systems. Also trigger when users mention VPS deployment, isolated machines, containerized AI, VM-based agents, or any variation of separating AI agent workloads from personal/production systems."
---

# Dedicated Environment Isolation for OpenClaw AI Agents

## 1. Purpose

This skill teaches enterprise-grade isolation strategies for running OpenClaw AI agents safely in production. OpenClaw agents execute code autonomously, hold API credentials, interact with external services, and respond to real-time events. Running them on your personal machine creates catastrophic risk: a prompt injection attack, supply chain compromise, or misconfiguration could result in credential theft, data exfiltration, billing attacks, or lateral movement to sensitive personal systems. This skill provides practical, layered isolation architectures ranging from single dedicated machines to enterprise Kubernetes deployments.

Isolation is not optional for production AI agents. It is foundational infrastructure.

## 2. First-Principles Explanation

Isolation operates on three core principles: **blast radius containment**, **defense-in-depth layering**, and **least privilege enforcement**.

A blast radius defines the maximum damage an attacker can inflict from a single compromise. If OpenClaw runs on your personal laptop, the blast radius includes your SSH keys, bank account logins, work credentials, personal files, and any connected network. If OpenClaw runs on a dedicated VPS with no other services, the blast radius shrinks to that VPS alone.

Defense-in-depth means no single isolation mechanism is trusted completely. Instead, multiple overlapping barriers exist: network firewalls, container boundaries, OS-level permissions, secrets management systems, and monitoring alarms. If an attacker escapes a container, they still hit OS-level restrictions. If they escape the OS, they still face network isolation.

Least privilege means each component gets only the permissions necessary to function. An OpenClaw container doesn't need root. An API token for Slack doesn't need permissions for GitHub. A disaster recovery backup doesn't need write access to production systems. Violation of least privilege is the root cause of most lateral movement attacks.

AI agents amplify these principles because they operate autonomously: no human reviews every API call before execution. Traditional software has humans in the decision loop. OpenClaw doesn't. This shifts security responsibility from runtime monitoring to **proactive isolation design**.

## 3. Why Isolation Matters for AI Agents

Standard software runs predetermined code paths. AI agents run arbitrary code paths determined by language models responding to real-time prompts. This creates four classes of risk unique to agents:

**Autonomous Credential Exposure**: OpenClaw agents hold API keys for Slack, GitHub, email, cloud services. An undefended agent could leak these to an attacker within seconds of compromise. A human-supervised system gives humans time to notice and revoke. An agent doesn't wait for human approval.

**Prompt Injection at Scale**: If an attacker controls an input stream (Discord message, email, RSS feed, webhook), they can inject instructions that override safety guidelines. Isolation doesn't prevent injection attacks, but it contains the damage: injected code runs in a sandbox with no access to credentials, persistent storage, or lateral movement paths.

**Resource Exhaustion**: A malfunctioning agent could spawn thousands of API calls, consuming your cloud billing quota within minutes. Isolation via container limits (CPU, memory, network throughput) prevents a runaway agent from affecting other systems.

**Lateral Movement**: If OpenClaw runs on your laptop and gets compromised, attackers can:
- Access your SSH private keys → compromise production servers
- Read browser cookies → hijack work accounts
- Monitor keyboard/screen → steal credentials in real-time
- Access .aws/credentials → drain cloud infrastructure
- Read email → intercept password resets for other services

Isolation breaks the chain. If OpenClaw runs on a throwaway VPS with no credentials, lateral movement succeeds only in compromising that VPS.

## 4. OpenClaw Infrastructure Context

OpenClaw is a Discord bot framework + skill execution engine. Key components:

- **Bot process**: Discord message listener, skill dispatcher, response handler
- **Skill execution runtime**: Python/Node environment where skills run with specific permissions
- **Credentials storage**: API tokens, service account keys, webhook URLs
- **External integrations**: Slack, GitHub, email, cloud provider SDKs
- **Local filesystem**: Skill code, cache, logs, state

Isolation strategy maps to these components:

| Component | Isolation Requirement | Mechanism |
|-----------|----------------------|-----------|
| Bot process | Prevent credential theft | Container, separate user, secrets manager |
| Skill runtime | Prevent host compromise | Restricted syscalls, read-only filesystem |
| Credentials | Encrypt at rest, prevent exfiltration | Vault or sops, no local .env files |
| External APIs | Limit token scope | Service-specific API keys, not personal tokens |
| Filesystem | Prevent data exfiltration | Container mount restrictions, no /home access |

## 5. Implementation Levels

### Beginner — Single Isolated Machine

**Target**: Personal AI agents, side projects, home infrastructure.

**Architecture**: Dedicated old laptop, Raspberry Pi, or spare desktop. Single machine, separate OS user account for OpenClaw, no shared credentials.

**Threat Model**: Assume no sophisticated attacker. Focus on preventing accidental credential exposure and resource exhaustion.

**Setup**:

1. **Prepare the machine**: Use Ubuntu 22.04 LTS Server (minimal installation). Do not install desktop environment, browser, email client, or other user software.

```bash
# After fresh Ubuntu install, create dedicated user
sudo useradd -m -s /bin/bash openclaw
sudo usermod -aG docker openclaw

# Lock password, use SSH key only
sudo passwd -l openclaw

# Create SSH keypair on secure machine
ssh-keygen -t ed25519 -f openclaw_key -C "openclaw@home"
sudo mkdir -p /home/openclaw/.ssh
sudo chmod 700 /home/openclaw/.ssh
sudo bash -c 'cat >> /home/openclaw/.ssh/authorized_keys' < openclaw_key.pub
sudo chmod 600 /home/openclaw/.ssh/authorized_keys
sudo chown -R openclaw:openclaw /home/openclaw/.ssh
```

2. **Basic firewall**:

```bash
sudo apt update && sudo apt install -y ufw fail2ban
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp  # SSH only
sudo ufw enable

# Fail2ban protects SSH from brute force
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

3. **Install Docker**:

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker openclaw
```

4. **Run OpenClaw in Docker**:

```bash
docker run -d \
  --name openclaw \
  --restart unless-stopped \
  --user openclaw:openclaw \
  --network isolated \
  --memory=512m \
  --cpus=1 \
  -e DISCORD_TOKEN=$(cat /run/secrets/discord_token) \
  -v /home/openclaw/skills:/app/skills:ro \
  -v /home/openclaw/data:/app/data \
  openclaw:latest
```

**Cost**: Free (reuse old hardware) or $50-200 one-time.

**Maintenance**: Monthly OS patching, Docker image updates, log rotation.

### Intermediate — VPS Deployment

**Target**: Reliable 24/7 operation, multiple agents, business use cases.

**Architecture**: Single VPS (Ubuntu 22.04 LTS), hardened OS, Docker containers, automated deployments.

**Threat Model**: Assume external attackers but not nation-state adversaries. Focus on preventing remote code execution, data exfiltration, and billing fraud.

**VPS Provider Selection Criteria**:
- **Privacy**: No-log policy, cryptocurrency payment accepted, European jurisdiction preferred
- **Reliability**: 99.9% uptime SLA, automated backups
- **Cost**: $5-20/month for sufficient capacity
- **Example providers**: Hetzner (EU, KVM, transparent), Linode (US, strong infrastructure), OVH (EU, competitive)

**Step-by-Step Setup**:

1. **Provision VPS**: Ubuntu 22.04 LTS, 2vCPU, 4GB RAM minimum. Upon first login, immediately update:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y

# Set timezone
sudo timedatectl set-timezone UTC
sudo apt install -y chrony  # NTP for accurate time

# Harden SSH
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

2. **Install security tools**:

```bash
sudo apt install -y ufw fail2ban auditd aide net-tools htop
sudo apt install -y curl wget git

# UFW configuration
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable

# Fail2ban for SSH brute-force
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# File integrity monitoring
sudo aideinit
sudo aide --config=/etc/aide/aide.conf --check
```

3. **Create deployment user**:

```bash
sudo useradd -m -s /bin/bash deployer
sudo mkdir -p /home/deployer/.ssh
sudo chmod 700 /home/deployer/.ssh

# Copy your public key
echo "YOUR_SSH_PUBLIC_KEY" | sudo tee /home/deployer/.ssh/authorized_keys
sudo chmod 600 /home/deployer/.ssh/authorized_keys
sudo chown -R deployer:deployer /home/deployer/.ssh

# Allow deployer to restart services via sudo
echo 'deployer ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart openclaw*' | sudo tee /etc/sudoers.d/deployer-restart
```

4. **Install Docker and Docker Compose**:

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker deployer

sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

5. **Secrets Management** (critical):

```bash
# Never use .env files in version control
# Create /home/deployer/.secrets directory (outside repo)
sudo mkdir -p /home/deployer/.secrets
sudo chmod 700 /home/deployer/.secrets

# Store secrets as Docker secrets or use sops
sudo apt install -y sops  # Encrypted YAML editor

# Example: encrypted secrets file
sops --encrypt /home/deployer/.secrets/openclaw.enc.yaml > /home/deployer/.secrets/openclaw.yaml.enc

# In docker-compose.yml:
# environment:
#   DISCORD_TOKEN_FILE: /run/secrets/discord_token
# secrets:
#   discord_token:
#     file: /home/deployer/.secrets/discord_token.txt
```

6. **Docker Compose Configuration**:

```yaml
# docker-compose.yml
version: '3.9'

services:
  openclaw:
    image: openclaw:latest
    container_name: openclaw-agent
    restart: unless-stopped
    user: '1000:1000'
    networks:
      - openclaw-net
    ports: []  # No exposed ports
    volumes:
      - ./skills:/app/skills:ro
      - openclaw-data:/app/data
      - /etc/localtime:/etc/localtime:ro
    environment:
      LOG_LEVEL: INFO
      DISCORD_TOKEN_FILE: /run/secrets/discord_token
      GITHUB_TOKEN_FILE: /run/secrets/github_token
    secrets:
      - discord_token
      - github_token
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  openclaw-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

volumes:
  openclaw-data:
    driver: local

secrets:
  discord_token:
    file: /home/deployer/.secrets/discord_token.txt
  github_token:
    file: /home/deployer/.secrets/github_token.txt
```

7. **Automated Deployment Script**:

```bash
#!/bin/bash
# /home/deployer/deploy.sh

set -e
REPO_URL="https://github.com/yourorg/openclaw-skills.git"
DEPLOY_DIR="/home/deployer/openclaw"

if [ ! -d "$DEPLOY_DIR" ]; then
    git clone "$REPO_URL" "$DEPLOY_DIR"
fi

cd "$DEPLOY_DIR"
git fetch origin
git checkout origin/main

docker-compose pull
docker-compose up -d
docker-compose logs -f openclaw
```

8. **Monitoring and Logging**:

```bash
# View logs
docker-compose logs -f openclaw

# Verify isolation
docker exec openclaw ps aux  # Should see minimal processes
docker exec openclaw env | grep -i token  # Verify no plaintext secrets
docker stats  # Monitor resource usage

# Check network isolation
docker network inspect openclaw_openclaw-net
```

**Cost**: $5-15/month. ROI realized immediately (24/7 operation).

**Maintenance**: Weekly log review, monthly patching, quarterly secrets rotation.

### Advanced — Multi-Environment Separation

**Target**: Multiple agents, development velocity, staging before production.

**Architecture**: Three separate VPS instances (dev/staging/prod) or single VPS with multiple namespaces, Infrastructure-as-Code, centralized secrets management.

**Setup**:

1. **Infrastructure as Code (Terraform)**:

```hcl
# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

variable "environment" {
  type = string
  default = "staging"
}

variable "agent_count" {
  type = number
  default = 1
}

resource "aws_security_group" "openclaw" {
  name        = "openclaw-${var.environment}"
  description = "Security group for OpenClaw agents"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["YOUR_IP/32"]  # Restrict SSH
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Agents can reach external APIs
  }
}

resource "aws_instance" "openclaw" {
  ami           = "ami-0c55b159cbfafe1f0"  # Ubuntu 22.04 LTS
  instance_type = "t3.medium"

  vpc_security_group_ids = [aws_security_group.openclaw.id]

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = true
    encrypted             = true  # Encrypt EBS by default
  }

  tags = {
    Name        = "openclaw-agent-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret" "openclaw_tokens" {
  name = "openclaw-${var.environment}-tokens"
  recovery_window_in_days = 7
}

output "instance_ip" {
  value = aws_instance.openclaw.public_ip
}
```

2. **Secrets Management (HashiCorp Vault)**:

```bash
# Install Vault agent on instance
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt update && sudo apt install vault

# Vault agent config
cat > /etc/vault/agent.hcl << 'EOF'
exit_after_auth = false

auto_auth {
  method {
    type = "approle"

    config = {
      role_id_file_path = "/etc/vault/role-id"
      secret_id_file_path = "/etc/vault/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
}

cache {
  use_auto_auth_token = true
}

listener "unix" {
  address = "/tmp/vault.sock"
  tls_disable = true
}

listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_disable   = true
}
EOF

sudo systemctl enable vault
sudo systemctl start vault
```

3. **Separate Networks**:

```bash
# Create isolated network per environment
docker network create openclaw-prod --subnet=10.0.1.0/24
docker network create openclaw-staging --subnet=10.0.2.0/24
docker network create openclaw-dev --subnet=10.0.3.0/24

# Prod agents cannot reach staging containers
docker run -d --network openclaw-prod --name openclaw-prod-1 openclaw:latest
docker run -d --network openclaw-staging --name openclaw-staging-1 openclaw:latest

# Verify isolation
docker exec openclaw-prod-1 ping openclaw-staging-1  # Will fail (expected)
```

### Architect — Enterprise Sandbox Strategy

**Target**: Large organizations, compliance requirements, multi-tenant AI platforms.

**Architecture**: Kubernetes clusters, service mesh (Istio), hardware-level isolation, centralized SIEM.

**Key Patterns**:

1. **Kubernetes Namespace Isolation**:

```yaml
# openclaw-ns.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: openclaw-prod
  labels:
    environment: production

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: openclaw-isolation
  namespace: openclaw-prod
spec:
  podSelector:
    matchLabels:
      app: openclaw
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: openclaw-prod
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: openclaw-prod
  - to:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 443  # HTTPS to external APIs only
  - to:
    - podSelector: {}
    ports:
    - protocol: TCP
      port: 53   # DNS
    - protocol: UDP
      port: 53
```

2. **Pod Security Policy** (Kubernetes):

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: openclaw-restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'MustRunAs'
    seLinuxOptions:
      level: "s0:c123,c456"
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1000
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1000
        max: 65535
  readOnlyRootFilesystem: true
```

3. **Service Mesh (Istio) for Agent Communication Control**:

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: openclaw-authz
  namespace: openclaw-prod
spec:
  selector:
    matchLabels:
      app: openclaw
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/openclaw-prod/sa/openclaw"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/api/v1/*"]
```

## 6. Step-by-Step Setup Framework

**Complete walkthrough from bare metal to production-ready OpenClaw**:

### Phase 1: Initial System Hardening (Day 1)

```bash
# SSH into fresh VPS
ssh root@VPS_IP

# 1. Update all packages
apt update && apt upgrade -y

# 2. Set hostname
hostnamectl set-hostname openclaw-prod-1

# 3. Configure locale and timezone
timedatectl set-timezone UTC
apt install -y locale-gen
update-locale LANG=en_US.UTF-8

# 4. Create restricted user (never use root)
useradd -m -G sudo,docker -s /bin/bash deployer
passwd -l deployer  # Lock password login

# 5. SSH hardening
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config
systemctl restart ssh

# 6. Firewall
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw enable

# 7. Fail2ban
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban

# 8. Monitoring
apt install -y auditd aide htop iotop
systemctl enable auditd
```

### Phase 2: Container Runtime Setup (Day 1)

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker deployer

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Configure Docker daemon (security)
cat > /etc/docker/daemon.json << 'EOF'
{
  "userns-remap": "default",
  "icc": false,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "labels": "container_name,image_name"
  },
  "seccomp-profile": "/etc/docker/seccomp-default.json"
}
EOF

systemctl restart docker
```

### Phase 3: Application Deployment (Day 2)

```bash
# As deployer user
cd /home/deployer

# Clone skills repository
git clone https://github.com/yourorg/openclaw-skills.git

# Create secrets directory
mkdir -p .secrets
chmod 700 .secrets

# Paste secrets (you provide these securely)
echo "YOUR_DISCORD_TOKEN" > .secrets/discord_token.txt
echo "YOUR_GITHUB_TOKEN" > .secrets/github_token.txt
chmod 600 .secrets/*

# Pull and run container
cd openclaw-skills
docker-compose pull
docker-compose up -d

# Verify running
docker ps
docker logs openclaw
docker stats
```

### Phase 4: Monitoring and Hardening (Day 3+)

```bash
# Check security posture
docker ps --no-trunc
docker network ls
docker volume ls

# Log locations
/var/log/auth.log      # SSH logins, sudo commands
/var/log/audit/audit.log  # System calls
docker logs openclaw   # Application logs

# Resource limits verification
docker inspect openclaw | grep -A 20 "HostConfig"

# Network isolation
docker exec openclaw curl -s http://localhost:8000/health || true
docker exec openclaw ping -c 1 8.8.8.8  # Should fail (isolated network)
```

## 7. Real Examples

### Home Setup: Raspberry Pi OpenClaw

Scenario: Running OpenClaw on a Raspberry Pi 4 for personal Discord bot.

```bash
# Raspberry Pi OS (Ubuntu 22.04 for ARM)
# Installation steps identical to beginner level above

# Adapted docker-compose.yml for ARM32v7
services:
  openclaw:
    image: openclaw:arm32v7  # ARM-specific image
    deploy:
      resources:
        limits:
          cpus: '0.75'  # Don't overwhelm Pi
          memory: 256M  # Pi has 4GB, but be conservative

# Cron-based backups
0 2 * * * /home/openclaw/backup.sh

# backup.sh
#!/bin/bash
tar czf /backup/openclaw-$(date +%Y%m%d).tar.gz /home/openclaw/data
# Keep only last 7 days
find /backup -mtime +7 -delete

# Monitoring via systemd
systemctl status openclaw
journalctl -u openclaw -n 50 -f
```

### VPS Deployment: $5/mo Hetzner Instance

Scenario: Running 3 OpenClaw agents on shared VPS, complete isolation.

```bash
# Hetzner Cloud VPS: CX11 ($5/mo), 1vCPU, 1GB RAM, Ubuntu 22.04

# Filesystem layout
/home/deployer/
├── openclaw-prod/
│   ├── docker-compose.yml
│   ├── .secrets/
│   │   ├── discord_token.txt
│   │   ├── github_token.txt
│   │   └── slack_webhook.txt
│   └── skills/
├── openclaw-staging/
│   └── docker-compose.yml
└── deploy.sh

# Separate networks for agents
docker network create agent-prod --subnet=10.0.1.0/24
docker network create agent-staging --subnet=10.0.2.0/24

# Resource allocation (total 1GB RAM, 1vCPU)
# prod:    512MB RAM, 0.6 vCPU (priority)
# staging: 256MB RAM, 0.3 vCPU (low priority)
# system:  256MB RAM, 0.1 vCPU

# Healthcheck endpoint for monitoring
curl -s https://hc-ping.com/YOUR_UUID/  # Sends ping on success
docker-compose up -d && curl -s https://hc-ping.com/YOUR_UUID/

# Cost optimization
# - Automatic weekly snapshots ($0.50 each, keep 4 = $2/mo)
# - Backups to S3 ($0.001 per GB, ~50MB backup = <$0.01/mo)
# - Monitoring via Uptime Robot (free tier)
```

### Business AI Infrastructure: Multi-Agent Kubernetes Cluster

Scenario: Running 20+ OpenClaw agents for enterprise with compliance.

```bash
# Architecture
# - 3 control plane nodes (HA)
# - 10 worker nodes (agent capacity)
# - 2 ingress controller nodes
# - Centralized logging (ELK stack)
# - Vault for secrets
# - Istio service mesh
# - NetworkPolicies enforcing zero-trust

# Deployment with auto-scaling
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw-agent
  namespace: openclaw-prod
spec:
  replicas: 5  # Start with 5
  selector:
    matchLabels:
      app: openclaw
  template:
    metadata:
      labels:
        app: openclaw
    spec:
      serviceAccountName: openclaw
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: openclaw
        image: myregistry.azurecr.io/openclaw:v1.2.3
        imagePullPolicy: Always
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        env:
        - name: DISCORD_TOKEN
          valueFrom:
            secretKeyRef:
              name: openclaw-tokens
              key: discord-token
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir:
          sizeLimit: 100Mi
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - openclaw
              topologyKey: kubernetes.io/hostname

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: openclaw-autoscaler
  namespace: openclaw-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: openclaw-agent
  minReplicas: 5
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## 8. Risks Without Isolation

**Real attack scenarios if OpenClaw runs on personal machine**:

**Scenario 1: Credential Theft via Prompt Injection**
- Attacker sends Discord message: "@bot download /home/user/.aws/credentials"
- Agent processes message, executes download command
- AWS credentials leaked to attacker's server
- Attacker spins up expensive EC2 instances, steals $50,000
- Cost: $50K+, time to detect: hours to days

**Prevention**: Agent running in container with no /home mount cannot access credentials.

**Scenario 2: Lateral Movement via SSH Key**
- Agent container compromised via malicious skill
- Attacker finds /home/user/.ssh/id_rsa mounted in container
- Uses key to SSH into your production servers
- Deploys cryptominer to all servers
- Cost: $10K+ in cloud bills, data breach exposure

**Prevention**: Separate machine has no SSH keys; even if compromised, no path to production.

**Scenario 3: Resource Exhaustion Billing Attack**
- Malicious skill spawns 10,000 concurrent API requests
- Cloud services bill you for 10,000 requests/second
- Your daily bill explodes from $10 to $5,000
- Takes hours to notice and kill the container

**Prevention**: Resource limits (memory, CPU, network bandwidth) cap damage immediately.

**Scenario 4: Data Exfiltration via Compromised Skill**
- Third-party skill downloads from untrusted source
- Skill contains code that reads all files in /home
- Exfiltrates photos, documents, credentials to attacker
- Personal data stolen, GDPR fines apply

**Prevention**: Isolated machine has minimal data; lost data is low-sensitivity agent configs only.

**Scenario 5: Supply Chain Compromise**
- OpenClaw base image tampered with (registry compromise)
- Image contains cryptocurrency miner preinstalled
- Runs on your personal machine, degrades performance silently
- Consumes 30% CPU for 6 months undetected

**Prevention**: Running on dedicated machine means you notice performance degradation immediately and kill it without impacting personal work.

## 9. Governance & Safety Controls

Procedures for operating OpenClaw at scale with human oversight:

### Change Management

```yaml
# change-request.yaml
apiVersion: governance/v1
kind: ChangeRequest
metadata:
  name: openclaw-skill-deployment-2026-02
spec:
  changeType: "skill_deployment"
  skill:
    name: "email-responder"
    version: "1.2.0"
    author: "team@example.com"
  environment: "staging"
  description: "Deploy email responder skill for customer support"
  riskLevel: "medium"  # API access, email permissions
  approvers:
  - "security@example.com"
  - "engineering-lead@example.com"
  deploymentWindow:
    start: "2026-02-01T02:00:00Z"
    duration: "1800s"  # 30 minutes
  rollbackPlan: "Revert to previous image, restore config from backup"
  validationSteps:
  - "Run skill in staging for 24 hours"
  - "Monitor for API errors, resource usage"
  - "Security team reviews logs for permission abuse"
  - "Team lead approves for production"
  testCases:
  - name: "respond_to_spam"
    input: "SPAM EMAIL"
    expectedBehavior: "no_response"
  - name: "respond_to_support"
    input: "SUPPORT REQUEST"
    expectedBehavior: "send_response"
```

### Access Approval Workflows

```
User Request → Slack/Email → Approval Queue → Implementation → Audit Log

Example:
- Alice requests access to production OpenClaw logs
- Manager Bob receives approval request
- Bob reviews: Alice is SRE, request is legitimate
- Bob approves via Slack reaction
- System grants read-only SSH access to logs directory (expires in 30 days)
- Audit log: "access_granted alice logs 2026-02-01 reviewer:bob"
```

### Audit Logging Requirements

```bash
# What must be logged for compliance
- All SSH logins (who, when, from where)
- All docker-compose changes (what, when, by whom)
- All secret rotations (key ID, timestamp)
- All API calls made by agents (source, destination, status)
- All resource limit violations (timestamp, container, limit exceeded)

# Example audit setup
auditctl -w /home/deployer/openclaw-skills/ -p wa -k openclaw_changes
auditctl -w /home/deployer/.secrets/ -p r -k secret_access

# Centralized logging to SIEM
docker-compose logs --follow | logger -t openclaw -p local0.info
# Forward to Splunk/ELK via rsyslog
```

### Incident Escalation Procedures

```
Severity 1 (Critical): Agent compromised, credentials exposed
└─ Immediate action: Kill all containers, rotate credentials, page oncall
└─ Post-incident: Forensics, root cause analysis, code review of malicious skill

Severity 2 (High): Resource exhaustion, billing anomaly
└─ Action: Investigate within 1 hour, implement rate limiting if needed
└─ Root cause: Skill misconfiguration or malicious intent

Severity 3 (Medium): Failed health checks, intermittent errors
└─ Action: Monitor for patterns, fix within 24 hours
└─ Example: Agent OOM killed due to memory leak in skill

Severity 4 (Low): Log warnings, minor performance degradation
└─ Action: Fix in next scheduled maintenance
└─ Example: Unused Docker image taking up space
```

## 10. Backup & Recovery Strategy

Production systems must survive failure:

```bash
# Backup strategy: 3-2-1 rule
# - 3 copies of data (production, backup1, backup2)
# - 2 different storage types (EBS snapshots, S3)
# - 1 copy offsite (S3 cross-region)

# Automated daily backup
#!/bin/bash
set -e

BACKUP_DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/mnt/backups/openclaw-${BACKUP_DATE}"

mkdir -p "$BACKUP_DIR"

# 1. Snapshot running container state
docker inspect openclaw > "$BACKUP_DIR/container-state.json"

# 2. Backup application data
docker run --rm \
  --volumes-from openclaw \
  -v "$BACKUP_DIR":/backup \
  busybox tar czf /backup/app-data.tar.gz /app/data

# 3. Backup docker-compose configuration
cp /home/deployer/openclaw/docker-compose.yml "$BACKUP_DIR/"

# 4. Backup secrets metadata (not actual secrets)
ls -la /home/deployer/.secrets > "$BACKUP_DIR/secrets-inventory.txt"

# 5. Upload to S3 (for offsite storage)
aws s3 cp "$BACKUP_DIR" "s3://openclaw-backups/daily/${BACKUP_DATE}/" --recursive --sse AES256

# 6. Retain local copies (7 days)
find /mnt/backups -mtime +7 -type d -exec rm -rf {} \;

# Schedule via cron
0 2 * * * /home/deployer/backup.sh
```

### RTO/RPO Targets

| Component | RTO (Recovery Time Objective) | RPO (Recovery Point Objective) |
|-----------|-------------------------------|-------------------------------|
| OpenClaw container | 5 minutes | 0 (stateless) |
| Application data | 15 minutes | 24 hours (daily backups) |
| Secrets | 30 minutes | 0 (encrypted, versioned) |
| Full system | 1 hour | 24 hours |

### Recovery Procedures

```bash
# Scenario: Docker container corrupted, needs rebuild

# Step 1: Pull latest clean image
docker pull openclaw:latest

# Step 2: Restore backup
docker run -d \
  --name openclaw-restore \
  -v /home/deployer/.secrets:/run/secrets:ro \
  -v /mnt/backups/openclaw-20260228-020000:/backup:ro \
  openclaw:latest \
  /bin/bash -c "tar xzf /backup/app-data.tar.gz -C /"

# Step 3: Verify recovery
docker logs openclaw-restore
docker exec openclaw-restore /app/bin/health-check.sh

# Step 4: Switch to restored instance
docker stop openclaw
docker rm openclaw
docker rename openclaw-restore openclaw
docker-compose up -d

# Estimated time: 5 minutes
```

## 11. Testing Scenarios

Validation that isolation actually works:

### Penetration Testing Checklist

```bash
# Test 1: Can escaped process access host filesystem?
docker run --rm -it ubuntu:22.04 bash
# Inside container:
$ cat /etc/shadow  # Should fail (not mounted)
$ ls /home/user  # Should fail (not mounted)
$ apt update  # Should fail (network restricted to DNS + HTTPS only)

# Test 2: Can container exceed memory limits?
docker run --rm --memory=256m ubuntu:22.04 bash
# Inside container:
$ python3 -c "x = [0] * 100000000; print('Allocated 400MB')"
# Process killed by OOMKiller after 256MB (expected)

# Test 3: Can container gain privilege escalation?
docker run --rm --user 1000:1000 --cap-drop=ALL ubuntu:22.04 bash
# Inside container:
$ whoami  # Shows 'openclaw' (UID 1000)
$ sudo su -  # Command not found (no sudo in container)
$ /bin/sh -i -p  # Fails (no setuid bit on busybox)

# Test 4: Can container exhaust CPU?
docker run --rm --cpus=0.5 ubuntu:22.04 bash
# Inside container:
$ for i in {1..4}; do while true; do :; done & done
# Monitor from host: docker stats (shows ~0.5 CPU, not full utilization)

# Test 5: Can container escape via kernel vulnerability?
# Deploy container with all security features enabled
# Attempt known escape vectors (requires specific kernel patches)
# Verify escapes fail due to seccomp/AppArmor profiles
```

### Escape Attempt Simulation

```bash
# Simulation: What happens if malicious code runs inside container?

# Malicious code tries to:
# 1. Read host filesystem
cat /etc/hosts  # Fails (not mounted)

# 2. Access host network
arp-scan -l  # Fails (no raw socket capability)

# 3. Connect to unrestricted ports
curl http://internal-service:8080  # Fails (network policy blocks)

# 4. Fork bomb (resource exhaustion)
:(){ :|:& };:  # Killed after reaching memory limit

# 5. Modify container image
rm -rf /  # Fails (read-only root filesystem)

# Expected result: All attempts fail, contained within 256MB memory, 0.5 CPU
```

### Network Boundary Testing

```bash
# Verify network isolation between environments
docker network ls
docker network inspect openclaw-prod  # Should show only prod containers
docker network inspect openclaw-staging  # Should show only staging containers

# Attempt cross-environment communication
docker exec openclaw-prod-1 ping openclaw-staging-1  # Fails
docker exec openclaw-prod-1 curl http://openclaw-staging-1:8000/health  # Fails

# Verify external API access works (positive test)
docker exec openclaw-prod-1 curl -s https://api.discord.com/api/gateway  # Succeeds

# Verify DNS works
docker exec openclaw-prod-1 nslookup api.github.com  # Succeeds
docker exec openclaw-prod-1 ping internal-db.example.com  # Fails (not allowed)
```

### Credential Leak Detection

```bash
# Automated scanning for accidental credential exposure

# Test 1: Secrets not in environment
docker exec openclaw inspect DISCORD_TOKEN 2>&1 | grep -q "not found"  # Expected

# Test 2: Secrets not in /proc
docker exec openclaw cat /proc/self/environ | grep -q TOKEN && exit 1  # Expected to fail

# Test 3: Secrets not in container history
docker history openclaw | grep -i "token\|secret" && exit 1  # Expected to fail

# Test 4: Secrets not in image layers
docker run --rm openclaw:latest find / -name "*.env" -o -name "secrets*" 2>/dev/null | grep -q . && exit 1

# Test 5: Application logs don't leak secrets
docker logs openclaw | grep -iE "token|password|key" && exit 1  # Should not match
```

## 12. Mastery Checklist

Progressive verification from beginner to architect:

### Beginner (Isolated Machine)
- [ ] Created non-root user for OpenClaw
- [ ] SSH key authentication works, password login disabled
- [ ] UFW firewall active, only port 22 open
- [ ] Docker installed and OpenClaw container runs
- [ ] Can verify container is isolated from host filesystem
- [ ] Basic monitoring: `docker stats` shows resource usage
- [ ] Backup script runs daily
- [ ] Can restore from backup in < 10 minutes

### Intermediate (VPS Deployment)
- [ ] Hardened OS on VPS (SSH, firewall, fail2ban active)
- [ ] Secrets stored in Docker secrets, not .env files
- [ ] docker-compose.yml configured with resource limits
- [ ] Health checks working (HTTP endpoint responds)
- [ ] Logs stored outside container, persistent across restarts
- [ ] Can deploy new agent version without downtime
- [ ] Monitoring dashboard shows CPU, memory, network
- [ ] Automated backup to external storage (S3 or similar)
- [ ] Can SSH to VPS and investigate container issues
- [ ] Security scan passing (no exposed secrets in images)

### Advanced (Multi-Environment)
- [ ] Dev, staging, and production environments isolated on separate machines
- [ ] Separate Docker networks per environment
- [ ] Infrastructure as Code (Terraform) provisions infrastructure
- [ ] Secrets managed centrally (Vault or Secrets Manager)
- [ ] CI/CD pipeline: code → staging → production (automatic gating)
- [ ] NetworkPolicies restrict traffic between environments
- [ ] Centralized logging from all agents (ELK, Splunk, or similar)
- [ ] Change management process followed for all deployments
- [ ] Can simulate disaster and restore from backup
- [ ] Security team has completed audit of deployment
- [ ] RTO/RPO targets defined and tested quarterly
- [ ] Incident response playbook documented and practiced

### Architect (Enterprise Scale)
- [ ] Kubernetes cluster running in HA mode (3+ control planes)
- [ ] Pod Security Policies enforced on all agent pods
- [ ] NetworkPolicies implement zero-trust architecture
- [ ] Service mesh (Istio) controls agent-to-agent communication
- [ ] Multi-region deployment with failover
- [ ] Hardware-level isolation: confidential computing nodes used for sensitive agents
- [ ] Secrets encrypted at rest (etcd encryption enabled)
- [ ] RBAC roles define least-privilege access (engineers can't access secrets)
- [ ] SIEM integration: all container logs shipped to centralized system
- [ ] Audit logging: all API calls to Kubernetes API tracked
- [ ] Compliance mapped: SOC2 Type II, ISO 27001 controls documented
- [ ] Penetration testing: external security firm conducted quarterly tests
- [ ] Disaster recovery: tested RTO < 4 hours, RPO < 1 hour
- [ ] Cost optimization: container resource requests sized properly, no waste
- [ ] Scalability validated: system scales to 100+ agents under load
- [ ] On-call procedures documented: escalation path, runbooks, alerting rules

## 13. Anti-Patterns

Common mistakes that undermine isolation:

**Anti-Pattern 1: Running as Root**
```bash
# WRONG
docker run -d --user root openclaw:latest
docker run -d  # Defaults to root if not specified

# RIGHT
docker run -d --user 1000:1000 openclaw:latest
```

**Anti-Pattern 2: Sharing SSH Keys**
```bash
# WRONG
COPY /home/user/.ssh/id_rsa /app/  # Now agent can impersonate user
docker run -v ~/.ssh:/app/.ssh openclaw  # Mounts host SSH keys

# RIGHT
# OpenClaw VM has no SSH keys at all
# If needed: use dedicated service account with limited scope
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/openclaw-deploy
```

**Anti-Pattern 3: Using Personal Cloud Accounts**
```bash
# WRONG
docker run -e AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE  # Personal account key
docker run -e GITHUB_TOKEN=$GITHUB_TOKEN  # Your full-scope token

# RIGHT
# Create service account with minimal permissions
# OpenClaw can only: create Discord embeds, post to specific channels
# Cannot: access private repos, modify billing, delete anything
```

**Anti-Pattern 4: No Resource Limits**
```yaml
# WRONG
services:
  openclaw:
    image: openclaw:latest
    # No limits specified — can consume 100% CPU, all RAM

# RIGHT
deploy:
  resources:
    limits:
      cpus: '1'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
```

**Anti-Pattern 5: Storing Secrets in Logs**
```bash
# WRONG
openclaw: INFO: Connecting to Slack with token sk-1234567890abcdef
docker logs openclaw | grep -i token  # Secrets visible

# RIGHT
openclaw: INFO: Connecting to Slack (using vault-provided credentials)
docker logs openclaw | grep -i token  # No matches
```

**Anti-Pattern 6: Stale Snapshots**
```bash
# WRONG
aws ec2 describe-snapshots | wc -l  # Returns 200 snapshots (old backups)
# Snapshots from 2024 still stored, costing money

# RIGHT
0 2 * * * aws ec2 describe-snapshots --query 'Snapshots[?StartTime<=`2026-02-01`]' --delete-snapshots
# Automated cleanup keeps only 7 days of backups
```

## 14. KPIs

Metrics that indicate healthy isolation posture:

| KPI | Target | Frequency | Action if Missed |
|-----|--------|-----------|------------------|
| **Security incidents** | 0 per quarter | Monthly review | Incident post-mortem, process improvement |
| **MTTR** (mean time to recover from incident) | < 1 hour | Per incident | Runbook update, on-call training |
| **MTTS** (mean time to isolate) | < 15 minutes | Per incident | Monitoring improvements, alerting rules |
| **Backup success rate** | 100% | Daily | Investigate and fix backup script |
| **RTO validation** | Pass quarterly test | Quarterly | Plan and execute DR drill |
| **RPO validation** | Data loss < 1 hour | Quarterly | Increase backup frequency if needed |
| **Unauthorized access attempts** | Log and alert < 10/day | Daily | Review fail2ban logs, update rules |
| **Container escape simulation** | 0 successful escapes | Quarterly | Update seccomp, Pod security policy |
| **Credential rotation timeliness** | 100% rotated per schedule | Monthly | Automate rotation via Vault |
| **Compliance audit pass rate** | 100% controls passing | Semi-annually | Address findings immediately |
| **Cost per agent** | < $10/month (VPS) | Monthly | Right-size resources, consolidate agents |
| **Secrets exposure incidents** | 0 | Continuous | Automated secret scanning, DLP |

## 15. Scaling Strategy

Handling 10, 50, 100+ agents:

### Horizontal Scaling Patterns

```yaml
# Single machine: 1-5 agents (max ~2GB memory)
# Multi-machine: 6-20 agents (separate instances per environment)
# Kubernetes: 20+ agents (auto-scaling pools)

# Kubernetes HPA example: scale based on load
kubectl autoscale deployment openclaw-agent \
  --min=5 --max=100 \
  --cpu-percent=70 \
  --memory-percent=80
```

### Multi-Region Deployment

```bash
# Deploy agents across regions for resilience + latency
# US region:  5 agents for US-based APIs
# EU region:  5 agents for GDPR-compliant operations
# APAC region: 3 agents for Asian timezones

# DNS-based routing directs traffic to nearest region
nslookup openclaw-api.example.com  # Returns regional IP based on geography
```

### Cost Optimization

```
Single VPS ($5-15/month):
- 1-5 agents
- All environments mixed
- Minimal monitoring
- Total: $10-20/month

Multi-VPS ($20-50/month):
- Dev, staging, prod separated
- 10-20 agents
- Monitoring + backups
- Total: $50-100/month

Kubernetes ($500-2000/month):
- 50+ agents
- HA + auto-scaling
- Enterprise logging
- SIEM integration
- Compliance ready
- Total: $500-2000+/month
```

## 16. Architect Notes

Strategic observations on future of AI agent isolation:

**Trend 1: Confidential Computing becomes standard**
- AMD SEV-SNP, Intel TDX, ARM CCA enable encrypted container execution
- Cloud providers (AWS Nitro Enclaves, Azure Confidential Containers) commoditizing this
- Future: agents running in trusted execution environments (TEEs) by default
- Implication: secrets never visible even to cloud provider

**Trend 2: Supply chain security critical path**
- SLSA framework (supply chain levels for software artifacts) becoming baseline
- Container image provenance (SBOM, signatures) verification mandatory
- Implication: agents deployed only from verified, signed images

**Trend 3: Regulatory convergence**
- EU AI Act, California SB-942 requiring AI system auditability
- SOC2 Type III (specific to AI) emerging as standard
- Implication: isolation documentation becomes compliance requirement, not optional

**Trend 4: Hardware-level isolation commoditizing**
- Multi-tenant cloud becoming liability; single-tenant + dedicated hosts preferred
- Cost premium for dedicated hardware shrinking as competition increases
- Implication: dedicated hosts ($2-5K/month) soon cost same as HA Kubernetes ($2K+/month)

**Trend 5: AI agent regulatory framework solidifying**
- "Right to audit AI systems" becoming legal requirement
- Insurance companies requiring evidence of isolation for coverage
- Implication: isolation isn't security choice—it's legal necessity

---

**Final Principle**: Isolation is not a one-time setup. It is a living system that requires continuous monitoring, regular testing, and periodic review. Treat it as critical infrastructure. Schedule monthly isolation reviews. Run quarterly disaster recovery drills. Rotate credentials every 90 days. Update images monthly. This is the cost of running autonomous AI systems safely.

The alternative is a single incident that costs your company $100K, exposes customer data, and destroys trust. Isolation is cheap insurance against catastrophe.
