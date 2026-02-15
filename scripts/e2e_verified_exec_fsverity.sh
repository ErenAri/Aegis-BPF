#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./build/aegisbpf}"

MNT="/usr/local/aegisbpf-verity-e2e"
IMG="/tmp/aegisbpf-verity-e2e.img"
POLICY_FILE=""
LOGFILE=""
AGENT_PID=""

cleanup() {
    set +e
    if [[ -n "${AGENT_PID}" ]]; then
        kill "${AGENT_PID}" 2>/dev/null || true
        wait "${AGENT_PID}" 2>/dev/null || true
        AGENT_PID=""
    fi
    if [[ -x "${BIN}" ]]; then
        "${BIN}" block clear >/dev/null 2>&1 || true
        "${BIN}" network deny clear >/dev/null 2>&1 || true
    fi
    if mountpoint -q "${MNT}" 2>/dev/null; then
        umount "${MNT}" >/dev/null 2>&1 || true
    fi
    rm -f "${IMG}" "${POLICY_FILE}" "${LOGFILE}"
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root (needs mount + fs-verity + BPF LSM)." >&2
    exit 1
fi

if [[ ! -x "${BIN}" ]]; then
    echo "Agent binary not found at ${BIN}. Build first (cmake --build build)." >&2
    exit 1
fi

if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
    echo "BPF LSM is not enabled; VERIFIED_EXEC E2E is not applicable." >&2
    exit 0
fi

if ! command -v fsverity >/dev/null 2>&1; then
    echo "fsverity tool not found (install package 'fsverity')." >&2
    exit 1
fi
if ! command -v mkfs.ext4 >/dev/null 2>&1; then
    echo "mkfs.ext4 not found (install package 'e2fsprogs')." >&2
    exit 1
fi

echo "[*] Preparing ext4 loopback mount at ${MNT}..."
rm -f "${IMG}"
truncate -s 128M "${IMG}"
mkfs.ext4 -F "${IMG}" >/dev/null
mkdir -p "${MNT}"
mount -o loop "${IMG}" "${MNT}"
mkdir -p "${MNT}/bin"

echo "[*] Creating protected resource: ${MNT}/secret.txt..."
cat >"${MNT}/secret.txt" <<'EOF'
top-secret
EOF
chown root:root "${MNT}/secret.txt"
chmod 0644 "${MNT}/secret.txt"

echo "[*] Building test client..."
cat >"${MNT}/client.c" <<'EOF'
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char* kSecretPath = "/usr/local/aegisbpf-verity-e2e/secret.txt";

static void test_open(void) {
    int fd = open(kSecretPath, O_RDONLY);
    if (fd < 0) {
        printf("OPEN fail errno=%d (%s)\n", errno, strerror(errno));
        return;
    }
    char b = 0;
    (void)read(fd, &b, sizeof(b));
    close(fd);
    printf("OPEN ok\n");
}

static void test_connect(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("SOCKET fail errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1);
    (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    int rc = connect(s, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0) {
        printf("CONNECT fail errno=%d (%s)\n", errno, strerror(errno));
    } else {
        printf("CONNECT ok\n");
    }
    close(s);
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    test_open();
    test_connect();
    return 0;
}
EOF
clang -O2 -Wall -Wextra "${MNT}/client.c" -o "${MNT}/bin/client_base"
chown root:root "${MNT}/bin/client_base"
chmod 0755 "${MNT}/bin/client_base"

cp "${MNT}/bin/client_base" "${MNT}/bin/client_unverified"
cp "${MNT}/bin/client_base" "${MNT}/bin/client_verified"
chown root:root "${MNT}/bin/client_unverified" "${MNT}/bin/client_verified"
chmod 0755 "${MNT}/bin/client_unverified" "${MNT}/bin/client_verified"
fsverity enable "${MNT}/bin/client_verified" >/dev/null

echo "[*] Building VERIFIED interpreter binary (basename python3)..."
cp "${MNT}/bin/client_base" "${MNT}/bin/python3"
chown root:root "${MNT}/bin/python3"
chmod 0755 "${MNT}/bin/python3"
fsverity enable "${MNT}/bin/python3" >/dev/null

echo "[*] Creating env-shebang scripts..."
cat >"${MNT}/bin/script_unverified" <<'EOF'
#!/usr/bin/env python3
# The interpreter is a test binary named "python3"; script content is ignored.
EOF
chown root:root "${MNT}/bin/script_unverified"
chmod 0755 "${MNT}/bin/script_unverified"

cp "${MNT}/bin/script_unverified" "${MNT}/bin/script_verified"
chown root:root "${MNT}/bin/script_verified"
chmod 0755 "${MNT}/bin/script_verified"
fsverity enable "${MNT}/bin/script_verified" >/dev/null

POLICY_FILE="$(mktemp)"
cat >"${POLICY_FILE}" <<EOF
version=4

[protect_connect]

[protect_path]
${MNT}/secret.txt
EOF

echo "[*] Applying protected-resource policy..."
"${BIN}" policy apply "${POLICY_FILE}" --reset

echo "[*] Starting agent (enforce mode, enforce-signal=none)..."
LOGFILE="$(mktemp)"
"${BIN}" run --enforce --enforce-signal=none >"${LOGFILE}" 2>&1 &
AGENT_PID="$!"
sleep 2
if ! kill -0 "${AGENT_PID}" 2>/dev/null; then
    echo "[!] Agent failed to start; log follows:" >&2
    cat "${LOGFILE}" >&2
    exit 1
fi

expect_denied() {
    local name="$1"
    shift
    local out
    out="$("$@" 2>&1 || true)"
    echo "[*] ${name} output:"
    echo "${out}"
    echo "${out}" | grep -q "OPEN fail errno=1" || {
        echo "[!] ${name}: expected OPEN EPERM" >&2
        return 1
    }
    echo "${out}" | grep -q "CONNECT fail errno=1" || {
        echo "[!] ${name}: expected CONNECT EPERM" >&2
        return 1
    }
}

expect_allowed() {
    local name="$1"
    shift
    local out
    out="$("$@" 2>&1 || true)"
    echo "[*] ${name} output:"
    echo "${out}"
    echo "${out}" | grep -q "OPEN ok" || {
        echo "[!] ${name}: expected OPEN ok" >&2
        return 1
    }
    if echo "${out}" | grep -q "CONNECT fail errno=1"; then
        echo "[!] ${name}: expected CONNECT not EPERM" >&2
        return 1
    fi
}

echo "[*] Running VERIFIED_EXEC enforcement checks..."

expect_denied "unverified_binary" "${MNT}/bin/client_unverified"
expect_allowed "verified_binary" "${MNT}/bin/client_verified"

PATH="${MNT}/bin:/usr/bin:/bin" expect_denied "env_shebang_unverified_script" "${MNT}/bin/script_unverified"
PATH="${MNT}/bin:/usr/bin:/bin" expect_allowed "env_shebang_verified_script" "${MNT}/bin/script_verified"

expect_denied "python3_inline_code_-c" "${MNT}/bin/python3" -c "print('hi')"

echo "[+] VERIFIED_EXEC fs-verity E2E passed"
