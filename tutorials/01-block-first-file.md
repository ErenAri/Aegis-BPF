# Tutorial 1: Block Your First File in 5 Minutes

**Difficulty:** Beginner
**Time:** 5 minutes
**Prerequisites:** Linux host with kernel 5.15+, root access

## What You'll Learn

- How to start AegisBPF in audit mode
- How to create a deny rule for a file
- How to see block events in real-time
- How to switch from audit to enforce mode

## Step 1: Start AegisBPF in Audit Mode

Audit mode logs all enforcement decisions without actually blocking access.
This is the safest way to test new policies.

```bash
# Start the daemon in audit mode (won't block, just logs)
sudo aegisbpf daemon --audit-only
```

You should see output like:
```
{"type":"state_change","state":"running","mode":"audit","reason":"daemon_start"}
```

Leave this terminal running and open a new one for the next steps.

## Step 2: Create a Test File

```bash
# Create a test file we'll protect
echo "sensitive data" > /tmp/aegis-test-secret.txt
```

## Step 3: Apply a Deny Rule

Create a minimal policy that blocks access to our test file:

```bash
cat > /tmp/aegis-test-policy.conf <<'EOF'
version=1

[deny_path]
/tmp/aegis-test-secret.txt
EOF

# Apply the policy
sudo aegisbpf policy apply /tmp/aegis-test-policy.conf
```

## Step 4: Trigger a Block Event

```bash
# Try to read the file (in audit mode, this will succeed but generate a log)
cat /tmp/aegis-test-secret.txt
```

In the daemon terminal, you should see a block event:
```json
{
  "type": "block",
  "pid": 12345,
  "comm": "cat",
  "path": "/tmp/aegis-test-secret.txt",
  "action": "deny"
}
```

## Step 5: Switch to Enforce Mode

Stop the daemon (Ctrl+C) and restart without `--audit-only`:

```bash
# Enforce mode — will actually block access
sudo aegisbpf daemon
```

Re-apply the policy:
```bash
sudo aegisbpf policy apply /tmp/aegis-test-policy.conf
```

Now try reading the file:
```bash
cat /tmp/aegis-test-secret.txt
# Expected: "Permission denied" or "Operation not permitted"
```

The file access is blocked at the kernel level!

## Step 6: View Statistics

```bash
# See block counts
sudo aegisbpf stats

# See detailed Prometheus metrics
sudo aegisbpf metrics
```

## Cleanup

```bash
# Stop the daemon (Ctrl+C in daemon terminal)
rm /tmp/aegis-test-secret.txt /tmp/aegis-test-policy.conf
```

## What's Next?

- **Tutorial 2:** [Network Policy Enforcement](02-network-policy.md)
- **Tutorial 3:** [Writing Custom Policies](03-custom-policies.md)
- **Tutorial 4:** [Debugging Policy Denials](04-debugging-denials.md)

## Key Concepts

- **Audit mode** (`--audit-only`): Logs enforcement decisions without blocking.
  Always start here when testing new policies.
- **Enforce mode** (default): Actually blocks access at the kernel level.
- **Deny rules**: Specify which files/paths/IPs/ports to block.
- **Hot reload**: Policies take effect immediately with `policy apply`.
  No daemon restart needed.
