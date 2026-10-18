# Safe AegisBPF enforcement demonstrations

These are **tests, not deployment instructions**. Run only on a **disposable Linux VM**, with root privileges, kernel BTF, cgroup v2, and `bpf` present in `/sys/kernel/security/lsm`. Kernel LSM hooks affect the host, not just the shell running the demo. **Do not run on production systems or shared developer machines.**

## File deny (recommended first demo)

Build from source as described in the [README](../README.md#quick-start), then:

```bash
sudo AEGIS_BIN=./build/aegisbpf bash scripts/demo_block_shadow.sh
```

This demo creates its own private temporary directory (not a fixed `/tmp` filename), confirms the file can be read before applying the policy, starts the agent in strict enforce mode, adds only that test file's rule and requires `open(2)` to fail with **EPERM**. Exit handlers delete that rule, stop only the agent process started by the demo, and remove temporary files. The demo **fails** rather than reporting success if BPF LSM is missing, if the agent terminates, if the read succeeds or if the operation fails for a different reason. Other pinned policy state is not intentionally cleared.

## Network deny (advanced, explicit opt-in)

This installs a **host-wide IP deny** temporarily. Only try it in a disposable VM, with an already listening service on loopback. In terminal 1:

```bash
python3 -m http.server 8765 --bind 127.0.0.1
```

In terminal 2 (from the repository root):

```bash
sudo AEGIS_BIN=./build/aegisbpf AEGIS_DEMO_NETWORK_OPT_IN=1 \
  AEGIS_DEMO_IP=127.0.0.1 AEGIS_DEMO_PORT=8765 \
  bash scripts/demo_block_network.sh
```

The demo refuses to proceed unless the target TCP connection works **before and after agent startup, but before adding the rule**. It then checks that the connection fails specifically with `EPERM`, not a timeout, refused connection or unrelated network error. It only accepts IPv4 loopback targets to avoid blocking arbitrary public endpoints. Do not assume that unrelated traffic to the loopback address remains unaffected during the test.

## Evidence and limitations

- A successful demo proves the **tested operation on the tested kernel** only. It does not establish full kernel/distro compatibility, production readiness or independent security review.
- The required privileged proof suite is documented in [Enforcement Claims](ENFORCEMENT_CLAIMS.md) and [Quality Gates](QUALITY_GATES.md). Hosted CI builds cannot substitute for BPF-LSM test evidence.
- Both scripts clean up their own rule and temporary files, but cannot guarantee recovery from power loss or `SIGKILL`. Use a disposable VM and revert the VM snapshot if cleanup is interrupted.
- Do not attach arbitrary public-facing network services or test on hosts running live workloads. Inspect the logs and policy state after the demo.
