---
name: account-segmentation-credential-governance
description: "Enterprise-grade skill for implementing account segmentation and credential governance for OpenClaw AI agent infrastructure. Use whenever separating bot accounts from personal accounts, implementing credential isolation, setting financial limits on AI agent accounts, designing identity isolation strategies, or managing the blast radius of credential compromise. Also trigger for API key management, secrets rotation, financial guardrails on bot accounts, credential vaulting, or any identity/credential segmentation for autonomous AI systems."
---

# Account Segmentation & Credential Governance

## 1. Purpose

Credential isolation is the structural firewall preventing a single compromised API key from becoming a gateway to your entire AI infrastructure. When an autonomous agent operates with unfettered access, compromise becomes catastrophic—not merely of that agent, but of every downstream system it touches. This skill ensures that when (not if) credentials are exposed, the attacker's reach is mathematically constrained to a bounded blast radius.

For OpenClaw specifically: a single leaked Discord bot token should never grant access to your personal cloud account, payment systems, or production deployments. Credential isolation transforms from a security nicety into a non-negotiable architectural requirement.

---

## 2. First-Principles of Credential Isolation

**Blast Radius Theory:** Every credential represents a perimeter. Once crossed by an attacker, what can they access?

- **Unconstrained:** One API key → entire AWS account → billing → production data → personal infrastructure. Blast radius: unlimited.
- **Isolated:** One bot token → Discord server only → rate-limited → immutable audit trail. Blast radius: Discord namespace.

**The Blast Radius Formula:**
```
Risk = (Credential Scope) × (Token Lifetime) × (Audit Visibility)
```

To minimize risk:
- Minimize scope (single service, single action if possible)
- Minimize lifetime (hours, not years)
- Maximize audit visibility (log every use, every permission invocation)

**Core Principle:** Never issue a credential broader than the immediate task requires. If a task requires read-only database access, issue a credential that cannot write, cannot exec, cannot escalate.

---

## 3. Risk Containment Concepts

### Segmentation as Risk Control
Segmentation fragments the attack surface. Each segment is a separate blast radius:

- **Identity Segmentation:** OpenClaw agent account separate from your personal account
- **Financial Segmentation:** Bot account has $50/month budget cap; personal account unlimited
- **Scope Segmentation:** Bot can POST to Discord, cannot access AWS
- **Temporal Segmentation:** Credentials valid for 2 hours, auto-expire
- **Audit Segmentation:** Every action logged to immutable ledger

### Least-Privilege Theory
"Default deny, explicit allow." A credential should be able to do exactly one thing, no more.

```
Bad:  Discord bot token with full server permissions + API key that controls billing
Good: Discord bot token that can only send messages in #ai-outputs channel
```

### Financial Guardrails
Autonomous systems can burn money catastrophically. Implement hard limits:

- Bot AWS account: $100/month cap (CloudWatch alarm at $75)
- Bot Stripe account: $50 daily spending limit
- Bot cloud function calls: quota on API invocations

---

## 4. OpenClaw Account Architecture

### Bot Discord Account (Separate from Personal)
```
Email:     openclaw-bot@yourdomain.com (distinct from personal)
Password:  Vault-managed, 32 random chars, never seen by human
2FA:       SMS to bot phone line or authenticator
Scope:     Discord-only, cannot access personal account settings
Audit:     All login attempts logged to CloudWatch
```

Why separate? If personal Discord account is compromised, bot remains secure. If bot token leaks, attacker cannot access personal Direct Messages, servers, or settings.

### Bot Cloud Account (AWS / GCP / Azure)
```
Account ID:     Separate AWS account from personal
Root User:      Disabled, never used
Service Roles:  Only what bot needs (e.g., S3 read, DynamoDB write)
Payment Method: Separate credit card, monthly budget cap
Audit:          CloudTrail enabled, all API calls logged
```

Why separate AWS account? If bot is compromised, attacker cannot access your personal AWS infrastructure, personal databases, or production systems.

### Bot Email Account
```
Email:     openclaw-bot@yourdomain.com
Managed by: OAuth2 via IdP, not personal email
Recovery:  Separate recovery email (not personal account)
Scope:     Receives bot notifications, verification codes, alerts
```

Why separate? Compromised bot email cannot reset your personal passwords or gain access to personal inboxes.

### Payment/Billing Separation
```
Credit Card:       Virtual card from Privacy.com, $100/month limit
Associated to:     Bot AWS account only
Monitoring:        Daily spend alerts, auto-pause at $90
Owner:             Finance function, not personal
```

Why separate? Bot expenditure is bounded and isolated. No scenario where bot can drain personal credit line.

---

## 5. Implementation Levels

### Beginner — Basic Account Separation
**Goal:** No single point of failure across personal and bot systems.

**Checklist:**
- [x] Create dedicated email for bot (bot@company.com)
- [x] Create separate password (32 char random, stored in password manager)
- [x] Separate bank account or virtual card for bot spending
- [x] Separate cloud account (own AWS account ID, own GCP project)
- [x] Enable 2FA on bot accounts (SMS or authenticator)
- [x] Log bot logins somewhere (even simple CloudWatch Logs)

**Time to implement:** 2 hours

### Intermediate — Credential Vaulting
**Goal:** Credentials are never stored as plaintext in code or config files.

**Tools:** HashiCorp Vault, AWS Secrets Manager, Google Secret Manager, Azure Key Vault

**Config Example (Terraform + Vault):**
```hcl
resource "vault_generic_secret" "discord_token" {
  path      = "secret/openclaw/discord"
  data_json = jsonencode({
    bot_token = var.discord_token
    server_id = var.discord_server_id
  })
}

resource "aws_secretsmanager_secret" "openai_key" {
  name = "openclaw/openai-api-key"
}

resource "aws_secretsmanager_secret_version" "openai_key" {
  secret_id     = aws_secretsmanager_secret.openai_key.id
  secret_string = var.openai_api_key
}
```

**Environment Variable Injection (Lambda/ECS):**
```bash
# Never hardcode. Always inject at runtime:
export DISCORD_TOKEN=$(aws secretsmanager get-secret-value --secret-id openclaw/discord-token --query SecretString --output text | jq -r '.bot_token')
export OPENAI_KEY=$(aws secretsmanager get-secret-value --secret-id openclaw/openai-api-key --query SecretString --output text)
python /app/agent.py
```

**Time to implement:** 4-6 hours

### Advanced — Dynamic Credentials and Rotation
**Goal:** Credentials exist for minutes or hours, not months or years.

**Short-Lived Token Pattern:**
```bash
# Generate 2-hour token via STS AssumeRole
TOKEN=$(aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/openclaw-bot \
  --role-session-name openclaw-session-$(date +%s) \
  --duration-seconds 7200 \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
  --output text)

# Token automatically expires after 2 hours, no manual cleanup needed
```

**Automatic Rotation (Vault):**
```bash
# Vault rotates credentials every 24 hours automatically
vault write -force aws/rotate-root/openclaw
# Old credentials invalidated, new ones issued
```

**Audit Trail (CloudTrail):**
```json
{
  "eventName": "AssumeRole",
  "principal": "openclaw-bot@company.com",
  "resource": "arn:aws:iam::ACCOUNT:role/openclaw-bot",
  "timestamp": "2026-02-28T14:32:19Z",
  "sourceIPAddress": "10.0.1.5",
  "status": "Success"
}
```

**Time to implement:** 8-12 hours

### Architect — Enterprise Credential Governance
**Goal:** Centralized policy, compliance, auditability across all agents and teams.

**Multi-Agent Policy Framework:**
```yaml
# /etc/openclaw/credential-policy.yaml
policies:
  discord-bots:
    max_lifetime: 2h
    rotation_interval: 24h
    audit_required: true
    scope_limit: "read:messages, write:channel-messages"

  ai-agents:
    max_lifetime: 1h
    rotation_interval: 6h
    audit_required: true
    scope_limit: "action-specific"
    financial_limit: "$50/day"

  human-engineers:
    max_lifetime: 8h
    rotation_interval: 7d
    audit_required: true
    scope_limit: "team-specific"
    mfa_required: true

compliance_frameworks:
  - SOC2
  - ISO27001
  - NIST CSF
  - GDPR data processing

audit:
  retention_days: 2555  # 7 years
  immutable_ledger: true
  central_logging: "CloudWatch Logs + S3 + Splunk"
```

**Credential Lifecycle Management:**
```
Created → Staged (waiting for approval) → Active → Expiring (alerting) → Expired (auto-revoked) → Archived
  ↓        (14 days max)                          (7 days warning)        (immutable record)
Scanned for leaks via GitGuardian, TruffleHog
```

**Time to implement:** 20-40 hours (multi-person, architecture-heavy)

---

## 6. Step-by-Step Account Segmentation

### Phase 1: Identity Setup (2 hours)
1. **Create bot email:** openclaw-bot@yourdomain.com
   ```bash
   # If using Google Workspace
   gcloud identity groups create openclaw-bots@yourdomain.com \
     --display-name="OpenClaw Bot Service Accounts"
   ```

2. **Create bot cloud account:**
   ```bash
   # AWS: Create separate AWS account under organization
   aws organizations create-account \
     --email openclaw-bot@yourdomain.com \
     --account-name "OpenClaw AI Agent"
   ```

3. **Set up virtual credit card:**
   - Privacy.com: Create card with $100/month limit, linked to bot AWS account
   - Brex: Create virtual card with spending controls

### Phase 2: Credential Management (4 hours)
1. **Set up Vault (self-hosted or cloud):**
   ```bash
   # Docker-based Vault dev setup
   docker run -d \
     --cap-add IPC_LOCK \
     -e VAULT_DEV_ROOT_TOKEN_ID=mytoken \
     -p 8200:8200 \
     vault:latest
   ```

2. **Store all credentials in Vault:**
   ```bash
   vault kv put secret/openclaw/discord \
     bot_token="MzI4..." \
     server_id="123456789"

   vault kv put secret/openclaw/openai \
     api_key="sk-..."
   ```

3. **Create service account for bot:**
   ```bash
   # AWS: Create service account with minimal permissions
   aws iam create-user --user-name openclaw-bot
   aws iam attach-user-policy \
     --user-name openclaw-bot \
     --policy-arn arn:aws:iam::aws:policy/PowerUserAccess
   # NO, use inline policy with minimal scope instead
   ```

### Phase 3: Access Control (2 hours)
1. **Create IAM roles with least privilege:**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "s3:GetObject",
           "s3:PutObject"
         ],
         "Resource": "arn:aws:s3:::openclaw-data/bot-outputs/*",
         "Condition": {
           "StringEquals": {
             "aws:username": "openclaw-bot"
           }
         }
       },
       {
         "Effect": "Deny",
         "Action": "*",
         "Resource": "*"
       }
     ]
   }
   ```

2. **Enable MFA on all bot accounts:**
   ```bash
   aws iam enable-mfa-device \
     --user-name openclaw-bot \
     --serial-number arn:aws:iam::ACCOUNT:mfa/openclaw-bot \
     --authentication-code1 000000 \
     --authentication-code2 000000
   ```

### Phase 4: Monitoring & Audit (1 hour)
1. **Enable CloudTrail logging:**
   ```bash
   aws cloudtrail create-trail \
     --name openclaw-audit \
     --s3-bucket-name openclaw-audit-logs
   aws cloudtrail start-logging --trail-name openclaw-audit
   ```

2. **Set up billing alerts:**
   ```bash
   aws budgets create-budget \
     --account-id ACCOUNT \
     --budget BudgetName=openclaw-bot,BudgetLimit='{Amount=100,Unit=USD}',TimeUnit=MONTHLY
   ```

---

## 7. Real Examples

### Personal Setup (Freelancer / Solo Developer)
**Context:** You run 2-3 small Discord bots, some personal APIs.

**Architecture:**
```
Personal Account (you)
├── Personal AWS account (personal projects)
└── Personal Discord account (manual servers)

Bot Tier
├── Bot Email: bot@personal-domain.com
├── Bot AWS Account: arn:aws:iam::222222222222:root
├── Bot Discord Account: separate account, same email domain
└── Credentials: stored in .env (local), rotated monthly
```

**Implementation (Bash):**
```bash
#!/bin/bash
# bot-setup.sh

# Create bot email via Gmail
# Create bot AWS account (Organizations)
aws organizations create-account \
  --email bot@mydomain.com \
  --account-name "Bot Tier"

# Store credentials in LastPass / 1Password
# Never commit to Git
echo "DISCORD_TOKEN=MzI4..." >> ~/.openclaw/.env
chmod 600 ~/.openclaw/.env

# Use credentials in bot
source ~/.openclaw/.env
python /opt/openclaw/agent.py
```

**Cost:** ~$20/month (bot AWS + Discord Nitro)

---

### Small Business (5-10 Bots, Team of 3)
**Context:** Marketing agency running customer acquisition bots, internal automation.

**Architecture:**
```
Personal Account (founder)
├── AWS Org Parent: management account
├── Personal cloud resources
└── Billing

Finance Account
├── Budget: $500/month
├── Separate credit card
└── Spending controls via AWS Budgets

Bot Accounts (separate AWS accounts per bot category)
├── Discord-Tier: 3 bots, shared AWS account
├── API-Tier: 2 bots, separate AWS account
└── Data-Tier: 1 bot, read-only S3 access

Engineer Accounts (3 engineers)
├── Personal IAM user per engineer
├── Separate access keys (rotated monthly)
└── Time-limited session credentials (8h max)
```

**Vault Setup (Docker):**
```bash
# docker-compose.yml
version: '3'
services:
  vault:
    image: vault:latest
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: s.root-token
      VAULT_ADDR: http://0.0.0.0:8200
    ports:
      - "8200:8200"
    volumes:
      - vault-data:/vault/data

  vault-init:
    image: vault:latest
    depends_on:
      - vault
    entrypoint: |
      sh -c '
      sleep 2
      vault secrets enable -path=secret kv
      vault secrets enable -path=aws aws
      vault write aws/config/root \
        access_key=$AWS_ACCESS_KEY \
        secret_key=$AWS_SECRET_KEY
      '
    environment:
      VAULT_ADDR: http://vault:8200
      VAULT_TOKEN: s.root-token
      AWS_ACCESS_KEY: $AWS_ACCESS_KEY
      AWS_SECRET_KEY: $AWS_SECRET_KEY

volumes:
  vault-data:
```

**Cost:** ~$200/month (bot infrastructure + Vault license)

---

### Enterprise Multi-Agent (50+ Bots, Team of 20, Compliance)
**Context:** Fintech company running customer support bots, fraud detection bots, internal automation. SOC2 compliance required.

**Architecture:**
```
Org Root Account (billing + audit)
├── CloudTrail to S3 (immutable)
├── AWS Config (compliance scanning)
└── GuardDuty (threat detection)

Development AWS Account
├── Non-prod bots
├── Sandbox environments
└── Development team access

Production AWS Account
├── Customer-facing bots
├── Financial transaction bots
├── Read-only audit logs
└── Limited team access (approval required)

Compliance AWS Account
├── All CloudTrail logs
├── All Config snapshots
├── Splunk integration
└── SOC2 audit materials

Bot Identity Tiers
├── Tier 1 (high-risk): Customer payment bots
│   ├── Credentials: 30-min lifetime
│   ├── Scope: Single operation (debit, credit)
│   ├── Approval: Required before execution
│   └── Audit: Every action logged + reviewed
│
├── Tier 2 (medium-risk): Customer support bots
│   ├── Credentials: 2-hour lifetime
│   ├── Scope: Read customer data, respond in designated channels
│   ├── Approval: Self-approved, audited
│   └── Audit: Daily log review
│
└── Tier 3 (low-risk): Internal bots
    ├── Credentials: 8-hour lifetime
    ├── Scope: Internal API access
    ├── Approval: Self-approved
    └── Audit: Weekly log review

Credential Store (HashiCorp Vault Enterprise)
├── HA cluster (3 nodes)
├── Encrypted at rest + in transit
├── Audit logs sent to Splunk
├── Auto-rotation: 24-hour cycle
└── Compliance: FIPS 140-2 endpoint
```

**Rotation Script (Kubernetes CronJob):**
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: credential-rotation
spec:
  schedule: "0 2 * * *"  # 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: rotator
            image: openclaw/credential-rotator:latest
            env:
            - name: VAULT_ADDR
              value: https://vault.internal:8200
            - name: VAULT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: vault-token
                  key: token
            command:
            - /app/rotate-credentials.sh
          restartPolicy: OnFailure
```

**Cost:** ~$5000+/month (Vault Enterprise, managed AWS accounts, monitoring)

---

## 8. Credential Auditing Framework

### What to Audit
1. **Who created this credential?**
2. **When was it created?**
3. **When does it expire?**
4. **What can it access?**
5. **Who has accessed it?**
6. **When was it last rotated?**
7. **Has it been leaked (GH scan)?**

### Audit Script (Bash + AWS CLI)
```bash
#!/bin/bash
# audit-credentials.sh

echo "=== OpenClaw Credential Audit Report ==="
echo "Generated: $(date)"
echo ""

# Audit IAM credentials
echo "## Bot IAM Users & Keys"
for user in $(aws iam list-users --query 'Users[?UserName==`openclaw*`].UserName' --output text); do
  echo "User: $user"
  keys=$(aws iam list-access-keys --user-name $user --query 'AccessKeyMetadata')
  echo "$keys" | jq '.[] | {KeyId, Status, CreateDate, LastRotatedDate}'
done

echo ""
echo "## Secrets in Vault"
vault kv list secret/openclaw/ | while read secret; do
  echo "Secret: $secret"
  vault kv get secret/openclaw/$secret | grep -E 'Key|Value|metadata'
done

echo ""
echo "## AWS Secrets Manager"
aws secretsmanager list-secrets --query 'SecretList[?Name==`openclaw*`]' | jq '.[] | {Name, CreatedDate, LastRotatedDate, NextRotationDate}'

echo ""
echo "## CloudTrail - Last 100 credential-related events"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::IAM::AccessKey \
  --max-results 100 | jq '.Events[] | {EventTime, EventName, Username, Resources}'
```

### Audit Report Template
```
=== OpenClaw Credential Audit Report ===
Generated: 2026-02-28T14:00:00Z
Auditor: Security Team
Status: COMPLIANT / NON-COMPLIANT

1. IDENTITY INVENTORY
   ✓ openclaw-bot (AWS): Created 2026-01-15, Key age 44 days, Status: Active
   ✓ openclaw-bot (Discord): Created 2026-01-15, Status: Active, 2FA: Enabled
   ✗ legacy-api-key: Created 2024-01-01, Key age 424 days, Status: Active, ROTATION OVERDUE

2. LIFETIME COMPLIANCE
   ✓ All bot credentials < 90 days old
   ✗ 1 legacy credential > 365 days old (must rotate within 7 days)

3. SCOPE COMPLIANCE
   ✓ Bot credentials scoped to least-privilege roles
   ✗ Human engineer "John" has AdministratorAccess (should be scoped)

4. AUDIT LOGGING
   ✓ CloudTrail enabled for all accounts
   ✓ Logs immutable (S3 Object Lock)
   ✓ All credential access logged

5. FINANCIAL CONTROLS
   ✓ Bot AWS account: Spending $45/month (under $100 cap)
   ✓ Budget alerts configured
   ✓ Spending anomalies: None detected

6. LEAK DETECTION
   ✓ Scanned via GitGuardian: No leaks detected in last 30 days
   ✓ Scanned via TruffleHog: No entropy-flagged secrets found

RECOMMENDATIONS:
- Rotate legacy-api-key immediately (424 days old)
- Scope John's IAM permissions to team-specific access
- Enable MFA on bot Discord account (currently SMS only)

Next audit: 2026-03-28
```

---

## 9. Governance Policies

### Policy Template: Credential Lifecycle
```yaml
# /etc/openclaw/policies/credential-lifecycle.yaml

name: "Credential Lifecycle Management"
version: "1.0"
effective_date: "2026-02-28"
owner: "Security Team"

policies:
  creation:
    approval_required: false  # bot credentials auto-created
    mfa_required: true
    notification: true  # notify on creation

  usage:
    audit_logging: mandatory
    rate_limiting: enabled
    anomaly_detection: enabled  # flag unusual access patterns

  rotation:
    interval: "24h"  # rotate every 24 hours
    enforcement: hard  # old credentials stop working
    notification: "7d before expiry"

  expiration:
    default_ttl: "24h"
    max_ttl: "2160h"  # 90 days
    enforcement: auto-revoke on expiry

  deletion:
    retention: "30d"  # keep audit trail 30d after deletion
    approval: required
    notification: true

exceptions:
  human_engineers:
    rotation_interval: "90d"
    max_ttl: "8760h"  # 1 year
    mfa_required: true

  long_lived_service_credentials:
    approval: "CISO review"
    justification_required: true
    quarterly_rotation: mandatory
```

### Policy Template: Scope Limiting
```yaml
# /etc/openclaw/policies/scope-limiting.yaml

name: "Credential Scope Limits"
version: "1.0"

principles:
  - "Default deny, explicit allow"
  - "Least privilege for all credentials"
  - "No wildcard ('*') permissions"

bot_credential_scopes:
  discord_bot:
    allowed_actions:
      - "channels:read"
      - "messages:send"  # only in designated channels
      - "users:read"  # limited to server members
    denied_actions:
      - "admin:*"
      - "server:settings:*"
      - "users:delete"
      - "users:ban"  # unless explicitly approved per-bot

  openai_api_bot:
    allowed_actions:
      - "models:list"
      - "chat:create"
      - "completions:create"
    denied_actions:
      - "files:*"
      - "fine-tunes:*"
      - "billing:*"
    rate_limit: "100 requests/min"
    cost_limit: "$10/day"

  aws_data_bot:
    allowed_actions:
      - "s3:GetObject"  # only from openclaw-data bucket
      - "dynamodb:Query"  # read-only
      - "dynamodb:Scan"   # read-only
    denied_actions:
      - "s3:PutObject"
      - "s3:DeleteObject"
      - "dynamodb:DeleteItem"
      - "ec2:*"
      - "iam:*"
      - "billing:*"

human_engineer_scopes:
  senior_engineer:
    allowed_actions:
      - "code:read"
      - "code:write"
      - "pr:create"
      - "deployment:staging"  # not production
    denied_actions:
      - "deployment:production"
      - "deletion:*"
      - "security:*"

  devops_engineer:
    allowed_actions:
      - "deployment:*"
      - "infrastructure:*"
      - "monitoring:*"
      - "logs:read"
    denied_actions:
      - "billing:write"
      - "security:delete"
      - "user:create"
```

---

## 10. Monitoring Access Scope

### Real-Time Access Monitoring (CloudWatch)
```bash
#!/bin/bash
# monitor-bot-access.sh

# Alert if bot credentials used outside normal hours
aws logs create-metric-filter \
  --log-group-name /aws/lambda/openclaw-bot \
  --filter-name UnusualBotAccess \
  --filter-pattern "[timestamp, request_id, event_type = AssumeRole || GetSecretValue, principal = openclaw*, ...]" \
  --metric-transformations metricName=UnusualBotAccess,metricValue=1

# Alert if bot accesses unauthorized resources
aws logs create-metric-filter \
  --log-group-name /aws/cloudtrail/openclaw \
  --filter-name BotUnauthorizedAccess \
  --filter-pattern '{ ($.principalId = "*openclaw*") && ($.errorCode = "AccessDenied" || $.errorCode = "UnauthorizedOperation") }' \
  --metric-transformations metricName=BotAccessDenied,metricValue=1

# Create alarms
aws cloudwatch put-metric-alarm \
  --alarm-name openclaw-unusual-access \
  --metric-name UnusualBotAccess \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --period 300 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:security-alerts
```

### Weekly Access Report
```bash
#!/bin/bash
# generate-access-report.sh

echo "=== OpenClaw Bot Access Report (Last 7 Days) ==="
echo ""

# What did openclaw-bot access?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=openclaw-bot \
  --start-time $(date -d '7 days ago' -Iseconds) \
  --end-time $(date -Iseconds) \
  | jq -r '.Events[] | "\(.EventTime) \(.EventName) \(.Resources[0].ARN)"' | sort | uniq -c

echo ""
echo "=== Access Denied Events ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=openclaw-bot \
  --start-time $(date -d '7 days ago' -Iseconds) \
  --end-time $(date -Iseconds) \
  | jq '.Events[] | select(.ErrorCode != null) | {Time: .EventTime, Error: .ErrorCode, Event: .EventName}'

echo ""
echo "=== API Quota Usage ==="
# OpenAI API usage
curl -s https://api.openai.com/v1/usage \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  | jq '.data | sort_by(.timestamp) | .[-1]'
```

---

## 11. Testing Scenarios

### Test 1: Credential Leak Detection
**Objective:** Verify that exposed credentials are detected and revoked.

```bash
#!/bin/bash
# test-leak-detection.sh

# 1. Generate test credential
TEST_KEY=$(aws iam create-access-key --user-name openclaw-bot --query 'AccessKey.SecretAccessKey' --output text)

# 2. "Leak" it to Git (test repo)
cd /tmp/test-repo
echo "OPENCLAW_KEY=$TEST_KEY" >> .env
git add .env
git commit -m "Add credentials (test)"
git push origin main

# 3. Verify GitGuardian detects it within 5 minutes
sleep 300
DETECTED=$(curl -s https://api.gitguardian.com/v1/incidents \
  --header "Authorization: Token $GITGUARDIAN_TOKEN" \
  | jq '.incidents[] | select(.secret_type == "AWS Access Key")')

if [ -n "$DETECTED" ]; then
  echo "✓ Leak detected by GitGuardian"

  # 4. Verify credential is auto-revoked
  DISABLED=$(aws iam list-access-keys --user-name openclaw-bot \
    --query 'AccessKeyMetadata[] | select(AccessKeyId == "$TEST_KEY").Status')

  if [ "$DISABLED" == "Inactive" ]; then
    echo "✓ Credential auto-revoked"
  else
    echo "✗ Credential NOT revoked (FAIL)"
  fi
else
  echo "✗ Leak not detected (FAIL)"
fi
```

### Test 2: Credential Expiration
**Objective:** Verify that expired credentials stop working.

```bash
#!/bin/bash
# test-credential-expiry.sh

# 1. Create credential with 1-minute TTL
CRED=$(aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/openclaw-bot \
  --role-session-name test-session \
  --duration-seconds 60)

TOKEN=$(echo $CRED | jq -r '.Credentials.SessionToken')

# 2. Verify credential works
TEST=$(aws s3 ls --region us-east-1 2>&1)
if [ $? -eq 0 ]; then
  echo "✓ Credential works initially"
fi

# 3. Wait 61 seconds
echo "Waiting 61 seconds for credential to expire..."
sleep 61

# 4. Verify credential is expired
TEST=$(aws s3 ls --region us-east-1 --session-token $TOKEN 2>&1)
if echo "$TEST" | grep -q "NotAuthorizedException\|InvalidToken"; then
  echo "✓ Credential expired and rejected"
else
  echo "✗ Expired credential still works (FAIL)"
fi
```

### Test 3: Scope Enforcement
**Objective:** Verify that credentials cannot exceed their scope.

```bash
#!/bin/bash
# test-scope-enforcement.sh

# 1. Get bot credential (Discord-only scope)
BOT_TOKEN=$(vault kv get secret/openclaw/discord --field=bot_token)

# 2. Attempt to access AWS (should fail)
echo "Attempting AWS access with Discord-scoped token..."
TEST=$(curl -s -X POST https://sts.amazonaws.com \
  -H "Authorization: Bearer $BOT_TOKEN" \
  -d 'Action=GetCallerIdentity')

if echo "$TEST" | grep -q "UnauthorizedOperation\|InvalidToken"; then
  echo "✓ Scope enforcement working: Discord token rejected for AWS"
else
  echo "✗ Scope not enforced (FAIL)"
fi

# 3. Attempt to escalate privileges with bot token
echo "Attempting privilege escalation with bot token..."
TEST=$(curl -s -X POST https://iam.amazonaws.com \
  -H "Authorization: Bearer $BOT_TOKEN" \
  -d 'Action=CreateAccessKey&UserName=attacker')

if echo "$TEST" | grep -q "AccessDenied\|UnauthorizedOperation"; then
  echo "✓ Privilege escalation blocked"
else
  echo "✗ Privilege escalation not blocked (FAIL)"
fi
```

---

## 12. Mastery Checklist

### Tier 1: Foundational
- [ ] Separate bot email account created and verified
- [ ] Separate cloud account (AWS/GCP/Azure) created under bot email
- [ ] Separate credit card / virtual card configured with spend limit
- [ ] 2FA enabled on bot accounts (email, cloud, Discord)
- [ ] All credentials stored in password manager (not Git, not plaintext)
- [ ] CloudTrail / Cloud Logging enabled for all accounts
- [ ] Monthly credential rotation policy implemented
- [ ] Documented account segmentation architecture

### Tier 2: Intermediate
- [ ] HashiCorp Vault (or equivalent) deployed and configured
- [ ] All credentials migrated from plaintext to Vault
- [ ] Automated credential injection into applications (via CI/CD)
- [ ] 2-hour credential TTL implemented for bot accounts
- [ ] Automated credential rotation (24-hour cycle) configured
- [ ] IAM roles with least-privilege created for each bot function
- [ ] Budget alerts and spending limits configured
- [ ] Weekly credential audit reports automated

### Tier 3: Advanced
- [ ] Dynamic credential generation (STS AssumeRole) implemented
- [ ] Credential rotation via CI/CD pipeline automated
- [ ] Immutable audit logging to S3 (Object Lock) configured
- [ ] GitGuardian / TruffleHog integration for leak detection
- [ ] Anomaly detection alerts configured (unusual access patterns)
- [ ] Rate limiting / API quotas enforced per credential
- [ ] Access scope monitoring dashboard created
- [ ] Quarterly compliance audit process established

### Tier 4: Architect
- [ ] Multi-account credential governance policy implemented
- [ ] Vault HA cluster (3+ nodes) deployed
- [ ] Integration with corporate IdP / SAML / OAuth
- [ ] Compliance frameworks integrated (SOC2, ISO27001, NIST)
- [ ] Splunk / ELK logging integration for centralized audit
- [ ] Credential lifecycle automation (creation → rotation → deletion)
- [ ] Cross-team credential policy standards documented
- [ ] Annual security audit with external firm completed

---

## 13. Anti-Patterns

### DO NOT
1. **Hardcode credentials in source code**
   ```python
   # ✗ BAD
   DISCORD_TOKEN = "MzI4..."
   OPENAI_KEY = "sk-..."

   # ✓ GOOD
   DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
   OPENAI_KEY = os.getenv("OPENAI_KEY")
   ```

2. **Use root/admin credentials for routine bot operations**
   ```bash
   # ✗ BAD
   # Bot uses AWS root account access key
   export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"

   # ✓ GOOD
   # Bot assumes limited role with STS
   CREDS=$(aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/openclaw-bot)
   ```

3. **Share credentials across humans and bots**
   ```bash
   # ✗ BAD
   # Shared Slack token used by both engineering team AND bot
   export SLACK_TOKEN="xoxb-shared-token"

   # ✓ GOOD
   # Separate tokens for team and bot
   export ENGINEERING_SLACK_TOKEN="xoxp-..."  # human
   export OPENCLAW_SLACK_TOKEN="xoxb-..."     # bot
   ```

4. **Keep credentials in environment variables permanently**
   ```bash
   # ✗ BAD
   # Same token runs for 365 days
   export OPENCLAW_TOKEN="token-from-2025"

   # ✓ GOOD
   # Token refreshed every 2 hours
   export OPENCLAW_TOKEN=$(aws sts assume-role --role-arn ... | jq -r '.Credentials.SessionToken')
   ```

5. **Store credentials in unencrypted config files**
   ```bash
   # ✗ BAD
   cat config.json
   # {"discord_token": "MzI4...", "owner": "user"}

   # ✓ GOOD
   # config.json is encrypted, token pulled from Vault at runtime
   vault kv get secret/openclaw/discord
   ```

6. **Reuse credentials across different environments**
   ```bash
   # ✗ BAD
   # Same token for dev, staging, production
   export OPENAI_KEY="sk-shared-key"

   # ✓ GOOD
   # Separate keys per environment
   export OPENAI_KEY_DEV="sk-dev-..."
   export OPENAI_KEY_STAGING="sk-staging-..."
   export OPENAI_KEY_PROD="sk-prod-..."
   ```

7. **Grant "ADMIN" or "*" scope to bot credentials**
   ```json
   // ✗ BAD
   {
     "Effect": "Allow",
     "Principal": { "AWS": "arn:aws:iam::ACCOUNT:user/openclaw-bot" },
     "Action": "*",
     "Resource": "*"
   }

   // ✓ GOOD
   {
     "Effect": "Allow",
     "Principal": { "AWS": "arn:aws:iam::ACCOUNT:user/openclaw-bot" },
     "Action": ["s3:GetObject"],
     "Resource": "arn:aws:s3:::openclaw-data/bot-outputs/*"
   }
   ```

8. **Never audit or monitor credential usage**
   ```bash
   # ✗ BAD
   # No CloudTrail, no logs, no way to know if credentials were used maliciously

   # ✓ GOOD
   # Every credential access logged, anomaly detected
   aws cloudtrail create-trail --name openclaw-audit --s3-bucket-name openclaw-audit-logs
   ```

---

## 14. KPIs

### Track These Metrics Monthly
1. **Credential Age Distribution**
   - % of credentials < 7 days old: Target 90%+
   - Max credential age: Target < 90 days

2. **Rotation Compliance**
   - % of credentials rotated on schedule: Target 100%
   - Avg days overdue for rotation: Target 0 days

3. **Scope Compliance**
   - % of credentials with least-privilege: Target 100%
   - Max permission scope per credential: Target 3 actions

4. **Leak Detection**
   - Leaks detected per month: Target 0
   - Time to revoke leaked credential: Target < 5 minutes

5. **Financial Controls**
   - Bot spend vs. budget: Target 70-80% utilization
   - Anomalies detected: Target 0

6. **Audit Completeness**
   - % of credentials with audit trail: Target 100%
   - Audit log retention days: Target 2555+ (7 years)

7. **Team Compliance**
   - % of engineers with MFA: Target 100%
   - % of team training completed: Target 100%

---

## 15. Enterprise Scaling

### Multi-Tenant Credential Governance
For orgs running OpenClaw across multiple teams / customers:

```yaml
# /etc/openclaw/multi-tenant.yaml

tenants:
  - name: "customer-acme"
    account_id: "111111111111"
    credential_scope:
      - "discord:acme-servers-only"
      - "openai:acme-models-only"
      - "aws:s3:acme-data-bucket"
    budget: "$1000/month"
    team_size: 5
    compliance: "SOC2"

  - name: "customer-zenith"
    account_id: "222222222222"
    credential_scope:
      - "discord:zenith-servers-only"
      - "openai:zenith-models-only"
      - "aws:s3:zenith-data-bucket"
    budget: "$500/month"
    team_size: 3
    compliance: "HIPAA"

  - name: "internal-engineering"
    account_id: "333333333333"
    credential_scope:
      - "discord:all"
      - "openai:all"
      - "aws:engineering-sandbox"
    budget: "$2000/month"
    team_size: 10
    compliance: "Internal"

governance:
  credential_rotation_interval: "24h"
  mfa_required: true
  audit_retention_years: 7
  quarterly_reviews: true
```

### Vault Multi-Tenant Setup
```hcl
# Enable auth methods per tenant
auth "jwt" {
  description = "JWT for tenant acme"
  path        = "auth/acme"
}

# Separate secret engines per tenant
secret "kv" {
  description = "Secrets for tenant acme"
  path        = "secret/acme"
}

# ACL policies per tenant
path "secret/acme/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/zenith/*" {
  capabilities = []  # No access to other tenant secrets
}
```

---

## 16. Architect Notes

### Why Separate Accounts?
- **Blast Radius Containment:** If one account is compromised, others remain secure
- **Financial Accountability:** Clear cost center attribution per bot/team
- **Compliance Isolation:** Different compliance requirements per account
- **Access Control Simplicity:** IAM boundaries are account boundaries, not just roles
- **Audit Trail Clarity:** Cross-account actions logged separately, easier to track

### Credentials as Risk Vectors
Every credential is a potential exploit vector. The goal is not to eliminate credentials (impossible) but to:
1. Minimize their lifetime (hours, not years)
2. Minimize their scope (single action, not wildcard)
3. Maximize audit visibility (log everything)
4. Automate their lifecycle (creation → rotation → revocation)

### The Zero-Trust Model
Assume all credentials can be compromised. Design systems so that:
- Compromise of one credential does NOT compromise all others
- Every action is logged and auditable
- Every action can be revoked/denied without manual intervention
- No single credential grants broad access

### Future Trends
- **Passwordless Authentication:** SSH keys, WebAuthn, FIDO2 replacing passwords
- **Ephemeral Credentials:** Credentials valid for minutes, not hours
- **Hardware Key Requirements:** Physical security key for high-risk operations
- **AI-Native Credential Management:** ML-based anomaly detection, automatic revocation
- **Blockchain Audit Trails:** Immutable credential audit logs on public/private chains

---

## Appendix: Quick Reference

**30-Second Setup:**
```bash
# 1. Create bot email
gcloud identity groups create bot@company.com

# 2. Create bot AWS account
aws organizations create-account --email bot@company.com --account-name Bot

# 3. Set up Vault
docker run -d vault:latest

# 4. Store credentials
vault kv put secret/openclaw/discord bot_token=MzI4...

# 5. Enable audit logging
aws cloudtrail create-trail --name openclaw --s3-bucket openclaw-audit

Done. Credentials are now segmented and audited.
```

**Common Commands:**
```bash
# Rotate a credential manually
vault kv metadata delete secret/openclaw/discord
vault kv put secret/openclaw/discord bot_token=$(openssl rand -base64 32)

# Check credential age
vault kv metadata get secret/openclaw/discord | grep created_time

# List all bot credentials
vault kv list secret/openclaw/

# Check AWS bot permissions
aws iam get-user-policy --user-name openclaw-bot --policy-name BotPolicy

# Monitor spending
aws ce get-cost-and-usage --time-period Start=2026-02-01,End=2026-02-28 --filter file://openclaw-filter.json

# Audit bot access (last 24h)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=openclaw-bot --start-time $(date -d '24 hours ago' -Iseconds)
```

**Emergency: Revoke Compromised Credential**
```bash
# 1. Immediately disable in Vault
vault kv delete secret/openclaw/COMPROMISED_SERVICE

# 2. Disable in source system
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE

# 3. Rotate to new credential
NEW_KEY=$(aws iam create-access-key --user-name openclaw-bot --query 'AccessKey.SecretAccessKey' --output text)
vault kv put secret/openclaw/aws access_key=$NEW_KEY

# 4. Verify applications using new credential
# (applications automatically pull from Vault on next request)

# 5. Alert team
slack_notify "🚨 Credential compromised and revoked: openclaw-bot AWS key. Applications automatically migrated to new key."

# 6. Post-mortem
# - How was credential exposed?
# - What systems were at risk during exposure window?
# - What safeguards failed?
# - What improvements needed?
```

---

**Version:** 1.0 | **Last Updated:** 2026-02-28 | **Maintainer:** Security Architecture Team
