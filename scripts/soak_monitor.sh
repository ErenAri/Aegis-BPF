#!/bin/bash
# AegisBPF Soak Test Monitoring Script
# Runs every 5 minutes via cron to collect metrics

LOG="/var/log/aegisbpf-soak-metrics.csv"

# CSV header (run once)
if [ ! -f "$LOG" ]; then
    echo "timestamp,cpu_pct,mem_mb,blocks,ringbuf_drops,map_deny_path,map_deny_inode,map_allow_cgroup" > "$LOG"
fi

# Get daemon PID
PID=$(pgrep -f "aegisbpf run")
if [ -z "$PID" ]; then
    echo "$(date +%s),DAEMON_DEAD,0,0,0,0,0,0" >> "$LOG"
    echo "ERROR: AegisBPF daemon not running!" | logger -t aegisbpf-soak
    exit 1
fi

# Collect resource metrics
CPU=$(ps -p $PID -o %cpu= 2>/dev/null | awk '{print $1}')
MEM=$(ps -p $PID -o rss= 2>/dev/null | awk '{print $1/1024}')

# Get BPF stats
STATS=$(sudo /home/ern42/CLionProjects/aegisbpf/build/aegisbpf stats 2>/dev/null)
BLOCKS=$(echo "$STATS" | grep "Total blocks:" | awk '{print $3}')
DROPS=$(echo "$STATS" | grep "Ringbuf drops:" | awk '{print $3}')

# Get map entry counts
METRICS=$(sudo /home/ern42/CLionProjects/aegisbpf/build/aegisbpf metrics 2>/dev/null)
DENY_PATH=$(echo "$METRICS" | grep "aegisbpf_deny_path_entries" | awk '{print $2}')
DENY_INODE=$(echo "$METRICS" | grep "aegisbpf_deny_inode_entries" | awk '{print $2}')
ALLOW_CGROUP=$(echo "$METRICS" | grep "aegisbpf_allow_cgroup_entries" | awk '{print $2}')

# Log data
echo "$(date +%s),${CPU:-0},${MEM:-0},${BLOCKS:-0},${DROPS:-0},${DENY_PATH:-0},${DENY_INODE:-0},${ALLOW_CGROUP:-0}" >> "$LOG"
