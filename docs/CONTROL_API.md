# Node-local control API

A root-only Unix-domain socket that lets a co-located process **drive AegisBPF
enforcement programmatically** — instead of shelling out to the CLI. This is the
foundation for response-engine integrations (e.g. a Falco Talon actionner or a
SOAR webhook): detect elsewhere, then call the agent to install a race-free
in-kernel deny.

## Enabling it

Opt-in, off by default. Set `AEGIS_API_SOCKET` when starting the daemon:

```bash
sudo AEGIS_API_SOCKET=/var/run/aegisbpf/aegisbpf.sock \
  aegisbpf run --enforce --enforce-signal=none
```

On start the agent logs `Node control API enabled {socket=…}`. The socket file
is created `0600` (owner-only). If the variable is unset or empty, no socket is
created and nothing changes.

## Security model

- **Opt-in** — no socket unless `AEGIS_API_SOCKET` is set.
- **`0600` socket** — only a peer with the daemon's uid (root) can `connect(2)`.
- **`SO_PEERCRED` per request** — control operations additionally require the
  connecting peer's uid to equal `control_uid` (default `0`), checked again on
  every request as defense-in-depth. Unauthorized control requests get
  `{"error":"forbidden"}` and are logged (`Rejected control request from
  unauthorized peer`).
- **Control is separate from read** — `GET` (read) works whenever the socket is
  up; `POST` (mutate) additionally requires the uid check *and* a registered
  control handler. With no handler, `POST` returns `{"error":"control not enabled"}`.

## Protocol

Newline-delimited text over `AF_UNIX`/`SOCK_STREAM`. One request line in; one or
more JSON lines back, terminated by a blank line (`\n\n`).

### Read operations (`GET`)
| Request | Response |
|---|---|
| `GET /health` | `{"status":"ok","service":"aegisbpf"}` |
| `GET /status` | agent status JSON (if a status callback is wired) |
| `GET /stats`  | stats JSON |
| `GET /events` | subscribes the connection to a live newline-delimited event stream |

### Control operations (`POST`, root-only)
| Request | Effect | Response |
|---|---|---|
| `POST /block/add <path>` | add a file deny (inode + path), race-free `-EPERM` | `{"status":"ok"}` |
| `POST /block/del <path>` | remove a file deny | `{"status":"ok"}` |
| `POST /block/clear` | clear all file denies | `{"status":"ok"}` |
| `POST /network/deny/ip <ip>` | add an IP deny | `{"status":"ok"}` |
| `POST /network/deny/cidr <cidr>` | add a CIDR (LPM) deny | `{"status":"ok"}` |

Failures return `{"error":"command failed","rc":<n>}`; an unrecognized verb
returns `{"error":"unknown control verb"}`. The argument may contain spaces
(paths), so it is everything after the verb token.

## Example (Python)

```python
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/var/run/aegisbpf/aegisbpf.sock")
s.sendall(b"POST /block/add /usr/bin/suspicious\n")
print(s.recv(256).decode())   # {"status":"ok"}
```

This is exactly what a Falco Talon actionner (or Falcosidekick webhook responder)
calls: translate a Falco detection into a `POST /block/add <path>` or
`POST /network/deny/cidr <cidr>` and enforcement is installed in-kernel on the
node — see the integration roadmap in the README.

## Behavior notes

- The control handler reuses the same code paths as the `aegisbpf block` /
  `aegisbpf network deny` CLI (`cmd_block_add`, `cmd_network_deny_add_*`), which
  mutate the pinned BPF maps — so a `POST /block/add` takes effect on the running
  daemon's enforcement immediately (verified end-to-end).
- The server runs one accept thread and is RAII-stopped when the daemon exits;
  the socket file is unlinked on shutdown.
- **Not yet exposed:** TTL/auto-expiry of dynamically-added denies and an audit
  trail of who-added-what — recommended before wiring an automated response loop
  that can add denies at volume.
