# Fluent Bit → AegisBPF events

Stream AegisBPF's runtime-security (OCSF) events into any [Fluent Bit](https://fluentbit.io)
output — Splunk, Elasticsearch/OpenSearch, Loki, Kafka, S3, an OTLP endpoint, and
so on — via the native **`aegisbpf`** input plugin.

```
AegisBPF agent ──(control socket, GET /events)──► Fluent Bit in_aegisbpf ──► any output
   OCSF JSON, newline-delimited                     records                  Splunk / ES / Loki / ...
```

## Status

The `in_aegisbpf` input plugin is proposed upstream:

- Plugin: **[fluent/fluent-bit#12272](https://github.com/fluent/fluent-bit/pull/12272)**
- Docs: **[fluent/fluent-bit-docs#2670](https://github.com/fluent/fluent-bit-docs/pull/2670)**

Until it ships in a Fluent Bit release you can build Fluent Bit from that branch,
or use the generic-input fallback below.

## Prerequisites

Run the agent with its control socket enabled:

```bash
AEGIS_API_SOCKET=/var/run/aegisbpf/aegisbpf.sock aegisbpf run --enforce
```

The socket is `0600` root-owned, so Fluent Bit must run as the same user (root).
AegisBPF emits OCSF-formatted events by default (`--event-format ocsf`).

## Native plugin

```ini
[INPUT]
    name         aegisbpf
    socket_path  /var/run/aegisbpf/aegisbpf.sock

[OUTPUT]
    name         stdout
    match        *
```

| Key | Description | Default |
|---|---|---|
| `socket_path` | AegisBPF control socket path | `/var/run/aegisbpf/aegisbpf.sock` |
| `reconnect_sec` | Reconnect interval (seconds) | `2` |

The plugin connects out to the socket, sends `GET /events`, skips the streaming
ack, and forwards each subsequent JSON line as one record (event-driven — it
drains promptly because the agent drops slow readers).

See [`fluent-bit.conf`](fluent-bit.conf) for a fuller example (ships events to an
HTTP/OTLP sink).
