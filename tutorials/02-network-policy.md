# Tutorial 2: Network Policy Enforcement

**Difficulty:** Beginner
**Time:** 10 minutes
**Prerequisites:** Tutorial 1 completed, root access

## What You'll Learn

- How to block outbound connections by IP and CIDR
- How to block specific ports and protocols
- How to use direction-aware rules (egress vs bind)
- How to read network block events

## Step 1: Start the Daemon

```bash
# Start in audit mode first
sudo aegisbpf daemon --audit-only
```

## Step 2: Block a Specific IP

Create a policy that blocks connections to a test IP:

```bash
cat > /tmp/aegis-net-policy.conf <<'EOF'
version=1

# Block outbound connections to specific IPs
[deny_ip]
# Example: Block connections to a known mining pool
93.184.216.34

# Block entire CIDR ranges
[deny_cidr]
# Example: Block RFC5737 documentation range
198.51.100.0/24
EOF

sudo aegisbpf policy apply /tmp/aegis-net-policy.conf
```

## Step 3: Test the Block

```bash
# Try to connect to the blocked IP
curl -m 5 http://93.184.216.34/ 2>&1 || true

# Check the daemon logs for a network block event:
# {"type":"net_connect_block","remote_ip":"93.184.216.34","remote_port":80,...}
```

## Step 4: Port-Based Blocking

Block specific ports with protocol and direction:

```bash
cat > /tmp/aegis-net-policy.conf <<'EOF'
version=1

[deny_port]
# Block FTP outbound (port 21, TCP, egress only)
21:tcp:egress

# Block Telnet outbound
23:tcp:egress

# Block IRC (common C2 channel)
6667:tcp:egress

# Block a port for both TCP and UDP, all directions
9999:any:both
EOF

sudo aegisbpf policy apply /tmp/aegis-net-policy.conf
```

Test:
```bash
# This should generate a block event
curl -m 5 ftp://ftp.example.com/ 2>&1 || true
```

## Step 5: Combined Policy

Real-world policies combine file and network rules:

```bash
cat > /tmp/aegis-combined-policy.conf <<'EOF'
version=1

# Protect sensitive files
[deny_path]
/etc/shadow
/root/.ssh/id_rsa

# Block dangerous outbound ports
[deny_port]
21:tcp:egress
23:tcp:egress

# Block known malicious infrastructure
[deny_cidr]
# Example: Block connections to a suspicious network
203.0.113.0/24

# Block kernel tampering
[deny_ptrace]
[deny_module_load]
EOF

sudo aegisbpf policy apply /tmp/aegis-combined-policy.conf
```

## Step 6: View Network Statistics

```bash
# View network-specific metrics
sudo aegisbpf metrics | grep net_block
```

Output shows blocks broken down by type:
```
aegisbpf_net_blocks_total{type="connect"} 3
aegisbpf_net_blocks_total{type="bind"} 0
aegisbpf_net_blocks_total{type="sendmsg"} 1
```

## Direction Reference

| Direction | Meaning | Hooks |
|-----------|---------|-------|
| `egress` | Outbound connections | `socket_connect`, `socket_sendmsg` |
| `bind` | Listening on a port | `socket_bind`, `socket_listen` |
| `both` | Both directions | All socket hooks |

## Cleanup

```bash
rm /tmp/aegis-net-policy.conf /tmp/aegis-combined-policy.conf
```

## What's Next?

- **Tutorial 3:** [Writing Custom Policies](03-custom-policies.md)
- **Tutorial 4:** [Debugging Policy Denials](04-debugging-denials.md)
