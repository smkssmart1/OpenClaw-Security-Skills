---
name: communication-scope-control
description: "Enterprise-grade skill for controlling where and how OpenClaw AI agents can operate within communication platforms. Use whenever configuring DM vs group permissions, restricting agent interaction channels, implementing communication boundary policies, designing interaction scope for AI bots, or managing the social attack surface of autonomous AI agents. Also trigger for Discord channel policies, message routing rules, group interaction restrictions, or any behavioral boundary enforcement for AI agent communication."
---

# Communication Scope Control

## 1. Purpose

Controlling where AI agents can communicate is a critical security boundary that determines the agent's attack surface and exposure risk. An agent operating in a private DM has fundamentally different threat vectors than one responding in public group channels or across entire Discord servers. Communication scope is not merely a convenience feature—it is a primary containment mechanism that limits how far a successfully exploited agent can propagate harm.

When an AI agent's communication permissions are undefined, every channel becomes a potential injection vector. When defined precisely, scope enforcement becomes a technical control that mitigates social engineering, prompt injection at scale, unauthorized information disclosure, and lateral movement within organizational networks. This skill ensures that OpenClaw agents operate within predetermined boundaries that protect both the agent and the systems it interacts with.

## 2. First-Principles of Interaction Boundaries

Every communication channel represents a distinct security perimeter. The principle of least interaction states that an agent should operate only within the minimum scope necessary to fulfill its function. This principle applies across three dimensions:

**Channel dimension:** An agent should access only channels required for its purpose. A customer support bot needs access to support channels, not internal engineering discussions. A personal assistant bot requires only DM access, never group channels.

**User dimension:** An agent should respond only to authorized users or respect role-based access controls. Allowing any user to trigger agent behavior in any channel creates a social attack surface where sophisticated prompt injections can cascade.

**Message dimension:** An agent should respond only to direct mentions, commands, or explicitly targeted messages. Passive listening in group chats where the agent processes every message exponentially increases injection opportunities.

Least interaction is enforced through explicit allowlisting, never through blacklisting. A bot configured to "respond everywhere except #spam" is vulnerable to channels added after deployment. A bot configured to "respond only in #support, #general, and DMs" has a defined, auditable perimeter.

## 3. Social Attack Surface Risks

Group channels create a fundamentally different risk profile than direct messages. In a group with ten participants, nine of them are untrusted from the agent's perspective. An attacker does not need to compromise the agent's primary user—they can simply craft a message in a group channel designed to manipulate the agent's behavior.

**Group chat amplification:** A successful prompt injection in a group channel becomes visible to all group members. An agent tricked into revealing sensitive information, executing harmful commands, or propagating misinformation affects the entire group at once. In Discord, this scales to servers with hundreds of members.

**DM safety containment:** A DM conversation between an agent and its authorized user is naturally constrained. The blast radius of an injection is limited to two parties. The attack must be launched by someone with that user's trust or account access, raising the barrier significantly.

**Server infiltration vectors:** An attacker with access to a shared Discord server can join channels where the bot operates. They don't need the bot's owner to add them—if the bot responds in public channels, public server discovery enables reconnaissance and injection.

**Mention-based attacks:** Bots configured to respond to @mentions become vulnerable to cross-channel mentions from untrusted users. An attacker in any channel the bot monitors can mention the bot and trigger behavior, turning the bot into a tool for their own attacks.

**Image and embedded content attacks:** Group channels often contain images, PDFs, and embedded links. A bot that processes images or follows links in group contexts without rate limiting or content validation becomes an attack vector for malware distribution, data exfiltration, or cross-site exploitation.

## 4. OpenClaw Group Policy Management

Discord server configuration provides the foundational layer for agent scope control. OpenClaw agents deployed in Discord environments must inherit and enforce these policies:

**Server roles and permissions:** Create a dedicated role (e.g., `@OpenClaw-Agent`) with minimal permissions. Grant the role channel permissions only for channels where the agent should operate. In Discord, use role-based channel permissions (View Channel, Send Messages, Read Message History) to restrict access at the platform level.

**Bot token scope limitation:** When creating a Discord bot for the agent, request only the OAuth2 scopes required: `bot` scope with granular permissions. Do not request "Administrator" unless absolutely necessary. Request only: `Send Messages`, `Read Messages/View Channels`, `Read Message History`, `Manage Messages` (if needed for cleanup).

**Channel-level configuration:** For each channel where the agent operates, explicitly configure:
- Which bot roles have access
- Whether the bot can send messages (yes/no)
- Whether the bot responds to @mentions (yes/no)
- Whether the bot listens passively (yes/no) or requires explicit trigger

**Webhook configuration:** If using webhooks for message delivery, restrict the webhook to specific channels. A single webhook token should not have permissions across the entire server.

Example Discord role configuration:
```
Role: OpenClaw-Personal-Bot
Channel: #general → View Channel, Send Messages, Read History
Channel: #random → Denied (no access)
Channel: #admin → Denied (no access)
Server Permissions: None (no server-wide permissions)
```

## 5. Implementation Levels

### Beginner — DM-Only Mode

Restrict the agent to operate exclusively in direct messages with authorized users. The agent ignores all group messages, channel mentions, and server-wide triggers.

**Configuration:**
- Disable bot server visibility
- Configure agent to process only DM events
- Ignore all channel message events
- Disable @mention handling in servers
- No channel permissions required

**Code pattern:**
```python
# Only process DM messages
if message.channel.is_private():
    # Process DM
    await agent.handle(message)
else:
    # Ignore group/channel messages
    pass
```

**Use case:** Personal productivity assistant, private research bot, single-user automation.

### Intermediate — Channel Allowlisting

The agent operates in specific approved channels. All other channels are off-limits. This creates a defined perimeter while enabling multi-channel collaboration.

**Configuration:**
- Create a list of approved channel IDs: `["support", "general", "automation"]`
- Agent processes messages only from these channels
- Dynamically check channel membership before responding
- Log all attempted access from unauthorized channels

**Policy example:**
```yaml
agent_name: team-support-bot
scope:
  mode: allowlist
  channels:
    - channel_id: 987654321
      name: "#support"
      permissions: ["read", "send"]
    - channel_id: 987654322
      name: "#general"
      permissions: ["read", "send"]
  excluded_channels:
    - "#admin"
    - "#internal-security"
    - "#financial"
```

**Use case:** Team support bot, multi-team automation, departmental assistant.

### Advanced — Context-Aware Interaction Rules

Different permission levels apply based on channel context, user roles, or message type. An agent might respond to commands in general channels but offer richer functionality in private channels.

**Configuration:**
- Role-based permissions: Only users with @support-staff role can trigger sensitive commands
- Channel-specific behaviors: Different response sets per channel
- Message-type filtering: Respond to `/command` syntax only, not natural language in shared channels
- Rate limiting per scope: Limit frequency of interactions per channel to prevent spam/injection

**Policy example:**
```yaml
agent_name: enterprise-assistant
scope:
  mode: context_aware
  permissions:
    dm_conversations:
      allowed_users: ["owner_id", "admin_id"]
      behaviors: ["full_access"]
      rate_limit: unlimited

    support_channel:
      channel_id: 987654321
      allowed_roles: ["@support-staff", "@manager"]
      behaviors: ["ticket_creation", "faq_response"]
      rate_limit: 10_per_minute
      trigger_pattern: "^/support"

    general_channel:
      channel_id: 987654322
      allowed_roles: ["@everyone"]
      behaviors: ["greeting", "public_faq"]
      rate_limit: 5_per_minute
      trigger_pattern: "@mention"
```

**Use case:** Enterprise assistant serving multiple teams, tiered-access automation, complex permission hierarchies.

### Architect — Enterprise Communication Governance

Centralized policy management across multiple servers, compliance logging, audit trails, and policy-as-code deployment. Agents inherit permissions from a centralized policy store.

**Configuration:**
- Central policy repository (YAML, JSON, or database)
- Policy versioning and approval workflows
- Agent instances reference policy by name and version
- Automatic policy distribution to all running agents
- Compliance reporting and audit logging

**Policy structure:**
```yaml
# /policies/v2/communication-governance.yaml
apiVersion: openclaw.security/v1
kind: CommunicationPolicy
metadata:
  name: enterprise-governance
  version: "2.1"
  approved_by: "security_team"
  effective_date: "2026-02-28"

policies:
  - agent_id: "support-bot-prod"
    servers:
      - server_id: "prod-server-123"
        channels:
          support:
            id: 987654321
            behaviors: ["respond_to_mentions", "command_processing"]
            rate_limit: "20/min"
            audit_log: true
          general:
            id: 987654322
            behaviors: ["respond_to_direct_commands_only"]
            rate_limit: "5/min"
            audit_log: true
          internal:
            id: 987654323
            behaviors: ["none"]
            audit_log: true

  - agent_id: "research-bot-prod"
    access_model: "dm_only"
    authorized_users:
      - user_id: "researcher_001"
      - user_id: "researcher_002"
    audit_log: true
    rate_limit: "unlimited"

compliance:
  logging_endpoint: "https://audit-server.internal/v1/log"
  retention_days: 90
  sensitive_data_masking: true
  suspicious_activity_alerting: true
```

**Use case:** Enterprise-wide AI agent deployment, regulated industries, multi-team governance.

## 6. Step-by-Step Configuration Guide

**Step 1: Define Agent Purpose and Minimum Scope**
- What is the agent's primary function?
- What channels or users must it interact with?
- What channels or users must it never interact with?
- Document in a scope statement

**Step 2: Create Discord Role**
```
Role Name: OpenClaw-{AgentName}
Color: Distinct (for visibility)
Permissions: Minimal (Send Messages, Read Channels, Read History only)
Mentionable: No
```

**Step 3: Configure Channel Permissions**
For each target channel:
```
Channel: #support
Role: OpenClaw-Support-Bot
Permissions:
  - View Channel: Allow
  - Send Messages: Allow
  - Read Message History: Allow
  - Manage Messages: Deny
```

**Step 4: Implement Code-Level Enforcement**
```python
# agent.py
ALLOWED_CHANNELS = {
    "support": 987654321,
    "general": 987654322,
}

async def on_message(message):
    if message.author == client.user:
        return

    # DM check
    if isinstance(message.channel, discord.DMChannel):
        if message.author.id not in AUTHORIZED_USERS:
            return
        return await process_dm(message)

    # Channel check
    if message.channel.id not in ALLOWED_CHANNELS.values():
        return

    # Trigger check
    if not message.content.startswith("/"):
        return

    # Rate limit check
    if not await check_rate_limit(message.author.id, message.channel.id):
        return

    await process_command(message)
```

**Step 5: Deploy with Audit Logging**
```python
# audit.py
async def log_interaction(event_type, user_id, channel_id, message, scope_check_result):
    await audit_db.insert({
        "timestamp": datetime.now(),
        "event_type": event_type,
        "user_id": user_id,
        "channel_id": channel_id,
        "message_preview": message[:100],
        "scope_check": scope_check_result,
        "agent_version": AGENT_VERSION,
    })
```

**Step 6: Test and Validate**
- Test DM access with authorized users
- Test channel access with allowed channels
- Test rejection from disallowed channels
- Verify audit logs capture all events
- Load test with rate limiting enabled

## 7. Real Use Cases

**Personal Assistant (DM-Only)**
- User: Individual researcher
- Scope: DM conversations only
- Configuration: Agent processes only messages from authorized user in private channel
- Risk mitigation: Minimal social attack surface, no group exposure
- Audit: Log all interactions for personal review

**Team Support Bot (Channel Allowlist)**
- User: Support team with 5 members
- Scope: #support channel, #general for announcements only
- Configuration: Full access in #support, read-only in #general
- Risk mitigation: Isolated to support operations, prevents spillover into other teams
- Audit: Log all ticket creation, escalations, and access denials

**Enterprise Assistant (Context-Aware)**
- User: 200-person organization
- Scope: Different access levels by role
  - @admin: DMs + #internal-engineering + #executive
  - @manager: #team-specific + DMs
  - @employee: #general + #faq-only
- Configuration: Role-based permissions, command filtering, rate limiting per role
- Risk mitigation: Prevents information leakage across organizational boundaries
- Audit: Detailed logging of who accessed what, when, and why

## 8. Governance Controls

**Access approval workflow:**
- Request → Review (security + team lead) → Approval → Deployment
- Changes to scope trigger re-review
- DM-only agents require explicit user authorization
- Channel additions require justification

**Periodic access review:**
- Quarterly review of all active agents and their scopes
- Remove agents that no longer have business justification
- Identify scope creep (agents operating in more channels than originally approved)
- Update documentation

**Incident response:**
- If agent is compromised, disable it across all channels immediately
- Audit logs show which interactions occurred while compromised
- Contained agents (DM-only) have smaller incident scope
- Contained agents allow faster recovery without broad impact

## 9. Safety Guardrails

**Hard boundaries:**
- Agent code cannot override configured scope
- Discord bot permissions are enforced at platform level (defense-in-depth)
- Rate limiting is enforced per scope tier, not bypassed by code
- Audit logging cannot be disabled by agent code

**Trigger validation:**
- All messages are validated against trigger patterns before processing
- @mention triggers are verified to come from allowed channels/users
- Command syntax is strictly validated (/command not conversational)
- Image attachments in group contexts are logged but not auto-processed

**Data isolation:**
- Agent running in #support cannot access conversation history from #engineering
- DM-only agents have zero visibility into server channels
- Channel-scoped agents cannot read other channels, even if bot has permissions

**Monitoring and alerting:**
- Alert if agent attempts to access channels outside configured scope
- Alert if rate limits are consistently hit (potential attack)
- Alert if suspicious patterns detected (1000 mentions in 1 hour)
- Alert if audit logs show gaps or missed events

## 10. Testing Scenarios

**Test 1: Scope Boundary Enforcement**
- Deploy agent to #support and #general channels only
- Attempt to trigger agent in #admin channel
- Verify agent does not respond
- Verify audit log shows rejection
- Pass: Agent ignores out-of-scope channels

**Test 2: DM Access Control**
- Configure agent for DM-only mode
- User A in authorized users attempts DM
- User B not in authorized users attempts DM
- Verify User A receives response, User B does not
- Pass: Only authorized users can access agent via DM

**Test 3: Role-Based Permission**
- Configure /sensitive-command to require @admin role
- @support-staff user triggers command
- @admin user triggers command
- Verify support user is rejected, admin succeeds
- Pass: Role-based filtering works

**Test 4: Rate Limiting**
- Set rate limit to 5 messages per minute in #general
- Send 5 messages rapidly
- Send 6th message within minute
- Verify 6th message is rate-limited
- Pass: Rate limiting enforces scope capacity

**Test 5: Audit Logging Integrity**
- Perform 10 interactions (5 allowed, 5 disallowed)
- Query audit log
- Verify all 10 events are captured
- Verify scope_check result is accurate for each
- Pass: Audit trail is complete and accurate

## 11. Mastery Checklist

- [ ] Can define agent scope in writing using first-principles reasoning
- [ ] Can explain why least-interaction principle reduces attack surface
- [ ] Can configure Discord role with minimal permissions
- [ ] Can allowlist specific channels using IDs, not names
- [ ] Can implement code-level scope enforcement
- [ ] Can set up rate limiting per channel/user/role
- [ ] Can audit log all scope decisions
- [ ] Can test scope boundaries before deployment
- [ ] Can respond to scope incidents (agent behaving outside bounds)
- [ ] Can explain DM-only vs channel vs context-aware tradeoffs
- [ ] Can implement role-based permission checks
- [ ] Can deploy agents to multiple servers with unified policy
- [ ] Can version and roll back scope policies
- [ ] Can justify every channel in agent's allowlist

## 12. Anti-Patterns

**Anti-pattern 1: Respond to Everything**
- Agent configured to listen to all messages in server
- No channel restrictions
- No trigger validation
- Impact: Massive attack surface, high injection risk
- Fix: Implement explicit channel allowlist and trigger pattern matching

**Anti-pattern 2: @Mention in Public Channels**
- Agent configured to respond to @mentions in large public channels
- No role-based restrictions on who can mention
- No rate limiting
- Impact: Anyone can trigger agent, including attackers
- Fix: Restrict to DM or allowlisted channel mentions only

**Anti-pattern 3: Admin Permissions**
- Agent bot granted "Administrator" role
- Can access all channels, delete messages, manage roles
- Impact: Compromised agent can modify server structure
- Fix: Minimal permissions, explicit per-channel allowlisting

**Anti-pattern 4: No Audit Trail**
- Agent operates with scope enforcement but no logging
- Scope violations go undetected
- Incident investigation impossible
- Impact: Blind spot for security monitoring
- Fix: Implement audit logging for all scope decisions

**Anti-pattern 5: Human-in-the-Loop Bypass**
- Agent can change its own scope or permissions
- No approval workflow
- Scope creep happens gradually
- Impact: Scope becomes undefined over time
- Fix: Scope is immutable at runtime, changes require redeployment

## 13. KPIs

**Operational KPIs:**
- Scope coverage: % of target channels where agent successfully operates
- Access denial rate: % of messages correctly rejected by scope enforcement
- Rate limit enforcement: # of rate limit violations caught per week
- Deployment time: Time from scope change to live enforcement

**Security KPIs:**
- Scope violations: # of out-of-scope message attempts detected
- Audit log completeness: # of events vs expected baseline
- Incident scope: # of channels affected in agent compromise (lower is better)
- False negatives: # of injections that should have been caught by scope

**Compliance KPIs:**
- Scope approval rate: # of scopes approved / total scope requests
- Policy coverage: % of agents running with documented policy
- Access review completion: Quarterly access review completion rate
- Audit retention: Days of audit logs maintained (minimum 90)

## 14. Enterprise Policy Scaling

**Single server deployment:**
- Central policy file
- Agent auto-loads policy on startup
- Manual policy updates

**Multi-server deployment:**
- Policy repository (Git or database)
- Policy distribution mechanism (webhook, polling)
- Agent instances sync policy hourly
- Secrets management for server credentials

**Compliance-level scaling:**
- Policy as code with version control
- Approval workflow integration
- Compliance report generation
- Audit log shipping to SIEM
- Automated compliance checking (no agent can operate outside policy)

**Enterprise patterns:**
```
Policy Repository (Git)
  ├── /policies/v1/personal-assistant.yaml
  ├── /policies/v1/support-bot.yaml
  ├── /policies/v2/enterprise-assistant.yaml
  └── /audit-log-schema.json

Agent Instances (Running)
  ├── bot-1 (personal-assistant v1)
  ├── bot-2 (support-bot v1)
  └── bot-3 (enterprise-assistant v2)

Audit System
  ├── Central Log Aggregation
  ├── Compliance Reporting
  └── Real-time Alerting
```

## 15. Architect Notes

**When designing scope for new agents, ask:**
1. What is the minimum set of channels/users this agent needs access to?
2. What is the maximum harm if this agent is compromised?
3. Can this scope be enforced at multiple layers (Discord permissions + code + audit)?
4. What rate limits prevent the agent from being weaponized?
5. Can this agent operate DM-only instead?
6. If it needs group access, can we restrict to @mentions only?
7. How would we detect if this agent violated its scope?
8. How would we contain it if compromised?

**Strategic principles:**
- DM-only is always safer than group channels
- Explicit allowlists are always safer than implicit
- Code-level enforcement + platform-level permissions = defense-in-depth
- Rate limiting is not convenience, it is containment
- Audit logging enables forensics after incidents
- Scope creep is the enemy; treat scope as immutable until formally changed

**When under pressure to expand scope:**
- Document the business justification
- Identify what harm could occur with expanded scope
- Implement rate limiting as compensation
- Add monitoring/alerting for new channels
- Plan for rollback if problems emerge
- Review the expansion after 30 days

The principle is simple: an agent operating in one channel with explicit permissions is safer than the same agent operating everywhere with implicit trust. Build systems where trust is earned through narrow scope, not assumed across broad scope.
