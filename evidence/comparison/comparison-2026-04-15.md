# Runtime-security comparison results

- host: `ern42-RLEFG-XX-6.17.0-19-generic`
- timestamp: 2026-04-15T09:35:48Z
- workload: open_close
- iterations: 200000

| agent | status | us/op | p50 (µs) | p95 (µs) | p99 (µs) | delta vs none | notes |
|---|---|---|---|---|---|---|---|
| none | ok | 1.69 | 1.56 | 1.64 | 2.53 | — |  |
| aegisbpf | ok | 1.68 | 1.58 | 1.63 | 2.42 | -0.59% |  |
| falco | ok | 2.33 | 2.2 | 2.36 | 3.47 | +37.87% |  |
| tetragon | ok | 1.63 | 1.52 | 1.57 | 2.27 | -3.55% |  |

> Numbers are only meaningful when all agents were measured on the same host
> in the same run of this script. Do not copy rows across runs.
