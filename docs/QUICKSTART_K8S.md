# Kubernetes Quickstart

## Install

```bash
helm install aegisbpf ./helm/aegisbpf \
  --namespace aegisbpf \
  --create-namespace
```

## Verify

```bash
kubectl get pods -n aegisbpf
```

## Audit mode test

```bash
aegisbpf health
```

## Enable enforcement

```bash
helm upgrade aegisbpf ./helm/aegisbpf \
  --set agent.auditMode=false
```

## Uninstall

```bash
helm uninstall aegisbpf -n aegisbpf
```
