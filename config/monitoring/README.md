# AegisBPF Monitoring Stack

Quick start monitoring infrastructure for AegisBPF using Docker Compose.

## Components

- **Prometheus**: Metrics collection and storage
- **Grafana**: Visualization and dashboards
- **AlertManager**: Alert routing and notifications
- **Node Exporter**: System metrics for correlation

## Quick Start

### 1. Start the Stack

```bash
cd config/monitoring
docker-compose up -d
```

### 2. Access Services

- Prometheus: http://localhost:9091
- Grafana: http://localhost:3000 (admin/admin)
- AlertManager: http://localhost:9093
- Node Exporter: http://localhost:9100/metrics

### 3. Configure AegisBPF to Export Metrics

```bash
# Run AegisBPF with metrics endpoint
sudo aegisbpf run --enforce --metrics-port=9090
```

### 4. Import Grafana Dashboards

1. Open Grafana: http://localhost:3000
2. Login with admin/admin
3. Go to Dashboards → Import
4. Upload dashboards from `../../docs/MONITORING_GUIDE.md`

## Configuration

### Prometheus

Edit `../prometheus/prometheus.yml` to add scrape targets:

```yaml
scrape_configs:
  - job_name: 'aegisbpf'
    static_configs:
      - targets:
          - 'host.docker.internal:9090'  # AegisBPF on host
```

### AlertManager

Edit `alertmanager/alertmanager.yml` to configure:
- Email recipients
- Slack webhooks
- PagerDuty integration keys

### Alerts

All alert rules are in `../prometheus/alerts.yml`.

Key alerts:
- `AegisBPFDaemonDown`: Daemon stopped
- `AegisBPFHighBlockRate`: Unusual enforcement rate
- `AegisBPFMapNearFull`: Map capacity warning
- `AegisBPFRingbufDropping`: Event processing can't keep up

## Verification

### Check Prometheus Targets

```bash
curl http://localhost:9091/api/v1/targets
```

Should show `aegisbpf` target as UP.

### Check Metrics Are Being Collected

```bash
curl http://localhost:9091/api/v1/query?query=aegisbpf_blocks_total
```

Should return AegisBPF metrics.

### Test Alert Firing

```bash
# Force an alert by stopping AegisBPF
sudo systemctl stop aegisbpf

# Check AlertManager
curl http://localhost:9093/api/v1/alerts
```

## Production Deployment

For production, consider:

1. **Use Kubernetes** instead of Docker Compose
   - See `../../helm/` for Helm charts

2. **Persistent Storage**
   - Mount volumes for Prometheus data
   - Configure retention (default: 15 days)

3. **High Availability**
   - Run multiple Prometheus replicas
   - Use remote storage (Thanos, Cortex, Mimir)

4. **Secure Access**
   - Enable TLS for all endpoints
   - Configure authentication
   - Use reverse proxy (nginx, Traefik)

5. **Backup**
   - Regular snapshots of Prometheus data
   - Export dashboards and alert rules

## Troubleshooting

### Prometheus Can't Scrape AegisBPF

```bash
# Check AegisBPF metrics endpoint
curl http://localhost:9090/metrics

# If running in Docker, use host.docker.internal
# Edit prometheus.yml:
targets: ['host.docker.internal:9090']
```

### Grafana Can't Connect to Prometheus

```bash
# Check Prometheus is accessible from Grafana container
docker exec aegisbpf-grafana wget -O- http://prometheus:9090/api/v1/status/config
```

### Alerts Not Firing

```bash
# Check alert rules loaded
curl http://localhost:9091/api/v1/rules

# Check alert evaluation
curl http://localhost:9091/api/v1/alerts
```

## Stopping the Stack

```bash
docker-compose down

# Remove volumes (data loss!)
docker-compose down -v
```

## Next Steps

1. Import Grafana dashboards from MONITORING_GUIDE.md
2. Configure AlertManager with your notification channels
3. Test alert routing with a simulated incident
4. Review and tune alert thresholds based on your workload
