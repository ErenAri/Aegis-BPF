#!/usr/bin/env python3
"""
AegisBPF Soak Test Analysis
Plots resource usage over time from CSV metrics
"""

import sys
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

CSV_FILE = '/var/log/aegisbpf-soak-metrics.csv'

try:
    # Read CSV
    df = pd.read_csv(CSV_FILE)

    # Filter out DAEMON_DEAD entries
    df = df[df['cpu_pct'] != 'DAEMON_DEAD']

    # Convert to numeric
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    df['cpu_pct'] = pd.to_numeric(df['cpu_pct'])
    df['mem_mb'] = pd.to_numeric(df['mem_mb'])
    df['ringbuf_drops'] = pd.to_numeric(df['ringbuf_drops'])

    # Calculate stats
    duration_hours = (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600

    print("=== AegisBPF Soak Test Analysis ===")
    print(f"Duration: {duration_hours:.1f} hours ({duration_hours/24:.1f} days)")
    print(f"Samples: {len(df)}")
    print()
    print("CPU Usage:")
    print(f"  Average: {df['cpu_pct'].mean():.2f}%")
    print(f"  p95: {df['cpu_pct'].quantile(0.95):.2f}%")
    print(f"  p99: {df['cpu_pct'].quantile(0.99):.2f}%")
    print(f"  Max: {df['cpu_pct'].max():.2f}%")
    print()
    print("Memory Usage:")
    print(f"  Average: {df['mem_mb'].mean():.1f} MB")
    print(f"  p95: {df['mem_mb'].quantile(0.95):.1f} MB")
    print(f"  Max: {df['mem_mb'].max():.1f} MB")
    print(f"  Growth: {df['mem_mb'].iloc[-1] - df['mem_mb'].iloc[0]:.1f} MB")
    print()
    print("Ring Buffer Drops:")
    print(f"  Total: {df['ringbuf_drops'].max()}")
    print(f"  Rate: {df['ringbuf_drops'].max() / duration_hours:.1f} per hour")
    print()

    # Success criteria check
    success = True
    if df['cpu_pct'].quantile(0.99) > 5:
        print("❌ FAIL: CPU p99 > 5%")
        success = False
    if df['mem_mb'].max() > 50:
        print("⚠️  WARN: Memory > 50MB")
    if df['ringbuf_drops'].max() > (len(df) * 0.0001):
        print("❌ FAIL: Ring buffer drop rate > 0.01%")
        success = False

    if success:
        print("✅ PASS: All criteria met!")

    # Plot
    fig, axes = plt.subplots(4, 1, figsize=(12, 12))

    # CPU
    axes[0].plot(df['timestamp'], df['cpu_pct'], linewidth=0.5)
    axes[0].axhline(y=2, color='g', linestyle='--', label='Target <2%')
    axes[0].axhline(y=5, color='r', linestyle='--', label='Threshold <5%')
    axes[0].set_ylabel('CPU %')
    axes[0].set_title('AegisBPF CPU Usage Over Time')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    # Memory
    axes[1].plot(df['timestamp'], df['mem_mb'], linewidth=0.5)
    axes[1].axhline(y=50, color='r', linestyle='--', label='Threshold <50MB')
    axes[1].set_ylabel('Memory (MB)')
    axes[1].set_title('AegisBPF Memory Usage Over Time')
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    # Ringbuf drops
    axes[2].plot(df['timestamp'], df['ringbuf_drops'], linewidth=0.5)
    axes[2].set_ylabel('Ring Buffer Drops')
    axes[2].set_title('Ring Buffer Drops Over Time')
    axes[2].grid(True, alpha=0.3)

    # Blocks
    axes[3].plot(df['timestamp'], df['blocks'], linewidth=0.5)
    axes[3].set_ylabel('Total Blocks')
    axes[3].set_title('Total Blocks Over Time')
    axes[3].set_xlabel('Time')
    axes[3].grid(True, alpha=0.3)

    plt.tight_layout()
    output_file = '/tmp/aegisbpf-soak-analysis.png'
    plt.savefig(output_file, dpi=150)
    print(f"\nPlot saved to: {output_file}")

except FileNotFoundError:
    print(f"ERROR: CSV file not found: {CSV_FILE}")
    print("Run soak test first!")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
