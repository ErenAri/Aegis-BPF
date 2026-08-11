# AegisBPF → OCSF → SIEM / data-lake pipeline

Ship AegisBPF enforcement/audit decisions to any OCSF-consuming platform —
**AWS Security Lake, Splunk, Microsoft Sentinel, Google SecOps, Datadog Cloud
SIEM, CrowdStrike** — with a single [Vector](https://vector.dev) pipeline.

This is the "ready now" integration: AegisBPF already emits **schema-valid
OCSF 1.1.0**, so the pipeline only has to *enrich* (cloud/k8s/observables) and
*route*. No code changes to the agent.

## What the agent emits

Run the agent with `--event-format=ocsf`. A denied file open produces a real
OCSF **File Activity (1001)** record — see [`sample-ocsf-event.json`](sample-ocsf-event.json),
captured live on kernel 6.17:

```jsonc
{
  "class_uid": 1001, "class_name": "File Activity",
  "category_uid": 1, "activity_id": 14, "type_uid": 100114,
  "action": "Denied", "disposition": "Blocked",
  "severity_id": 4, "time": 1786311314740,
  "metadata": { "version": "1.1.0", "product": { "name": "AegisBPF", ... } },
  "actor":  { "process": { "pid": 129085, "name": "cat", "parent_process": {...} } },
  "device": { "type": "Server", "hostname": "node-01.example.internal" },
  "file":   { "type": "Regular File" },
  "unmapped": { "aegis_inode": ..., "aegis_cgroup_path": ..., "aegis_parent_exec_id": ... }
}
```

Network denies emit **Network Activity (4001)** the same way. All OCSF/Security-Lake
**required** fields are present (`metadata.version`, `product.name`, `class_uid`,
`category_uid`, `activity_id`, `type_uid`, `severity_id`, `time`, `status_id`);
AegisBPF-specific forensics (inode, device, cgroup, exec lineage) ride correctly
under OCSF `unmapped`.

## The pipeline

[`aegisbpf-ocsf.yaml`](aegisbpf-ocsf.yaml) is a ready Vector config:

```
aegisbpf (--event-format=ocsf)
   │  journald MESSAGE (systemd)  ·  stdout (k8s DaemonSet)
   ▼
Vector: parse_ocsf → enrich_ocsf → [sinks]
   │            └─ adds cloud.provider/region, k8s pod/ns/node (Downward API),
   │               OCSF observables[], metadata.correlation_uid
   ├──► AWS Security Lake (S3, OCSF)
   ├──► Splunk (HEC)
   └──► Microsoft Sentinel / generic OCSF-HTTP (also OTLP-HTTP gateways)
```

Validate and run:

```bash
vector validate integrations/vector/aegisbpf-ocsf.yaml
vector --config integrations/vector/aegisbpf-ocsf.yaml
```

Every sink is **env-gated** — set only the variables for the targets you use.

## Per-target setup

### AWS Security Lake (custom OCSF source)
1. **Register a custom source** (Security Lake console/API) for event classes
   *File System Activity* and *Network Activity*; it provisions the S3 prefix +
   a Glue crawler IAM role and the expected partition layout.
2. Set `AEGIS_SECLAKE_BUCKET`, `AEGIS_CLOUD_REGION`, and give Vector's task role
   `s3:PutObject` on the source prefix.
3. **JSON → Parquet:** Security Lake ingests OCSF **Parquet** in a fixed
   partitioning. Either point the `security_lake_s3` sink at a raw prefix and run
   a Firehose+Glue (or Lambda) conversion, or swap `encoding.codec` for a Parquet
   sink. Field mapping is near pass-through since the input is already OCSF.
4. Query via Athena / Lake Formation, or attach subscribers (Splunk, Sentinel,
   Chronicle all read from the Lake).

### Splunk (HEC)
Set `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN`. Events land with sourcetype
`ocsf:file_activity`. Use the OCSF Splunk app or map fields in Splunk ES.

### Microsoft Sentinel
Point `SENTINEL_DCE_URI` at an Azure Monitor **Data Collection Endpoint**; add a
DCR mapping to a custom (or ASim) table. Attach Vector's Azure auth headers in
the `sentinel_http` sink `request.headers`.

### Datadog Cloud SIEM / Google SecOps / CrowdStrike
All accept OCSF; either route through their OCSF ingest endpoint (add an `http`
sink) or read from Security Lake as above.

## Validation checklist
- [ ] `aegisbpf run --event-format=ocsf` output validates against the OCSF
      `file_activity` / `network_activity` JSON schema (OCSF validator).
- [ ] `vector validate …` passes.
- [ ] A known AegisBPF deny appears end-to-end in the target (Athena row / Splunk
      search / Sentinel table) with `activity_id`, `severity_id`, `time` populated.
- [ ] `observables[]` and `cloud`/`k8s` labels are present after enrichment.

## Alternatives
- **Fluent Bit** — lighter DaemonSet if you only need one sink; use its
  `journald`/`tail` input + `http`/`s3`/`splunk` output. Vector is preferred here
  for the VRL enrichment + multi-sink fan-out.
- **OpenTelemetry Collector** — if you already run an OTel security pipeline,
  read the OCSF via a `filelog`/`journald` receiver and export onward; OCSF↔OTel
  convergence makes this increasingly first-class.
