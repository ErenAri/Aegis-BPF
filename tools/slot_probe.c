/* Read the atomic-swap runtime state without bpftool.
 *
 * The validation script needs the live slot, the generation ids and a BPF map
 * count. bpftool is the obvious way to get them, but it is built per kernel
 * release: inside a VM running an older kernel the host's bpftool does not
 * work, every query returns nothing, and checks built on it report the product
 * as broken when only the tool is missing. That turns a portable matrix into
 * noise, so this reads the pinned maps directly through libbpf instead.
 *
 * Usage: slot_probe <command>
 *   active-slot        index active_slot currently names
 *   generation         generation id of the live slot
 *   generations        generation id of both slots, "slot0 slot1"
 *   map-count          number of BPF maps on the system
 *
 * Exit: 0 on success, 1 if the state cannot be read.
 */
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PIN_DIR "/sys/fs/bpf/aegisbpf"

static int lookup_u32(const char *pin, __u32 key, __u32 *out) {
    int fd = bpf_obj_get(pin);
    if (fd < 0) return -1;
    int rc = bpf_map_lookup_elem(fd, &key, out);
    close(fd);
    return rc;
}

static int lookup_u64(const char *pin, __u32 key, __u64 *out) {
    int fd = bpf_obj_get(pin);
    if (fd < 0) return -1;
    int rc = bpf_map_lookup_elem(fd, &key, out);
    close(fd);
    return rc;
}

static int map_count(void) {
    __u32 id = 0;
    int n = 0;
    while (bpf_map_get_next_id(id, &id) == 0) n++;
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <active-slot|generation|generations|map-count>\n", argv[0]); return 2; }

    if (!strcmp(argv[1], "map-count")) { printf("%d\n", map_count()); return 0; }

    __u32 slot = 0;
    if (lookup_u32(PIN_DIR "/active_slot", 0, &slot) != 0) {
        fprintf(stderr, "cannot read active_slot: %s\n", strerror(errno));
        return 1;
    }
    slot &= 1u;

    if (!strcmp(argv[1], "active-slot")) { printf("%u\n", slot); return 0; }

    if (!strcmp(argv[1], "generations")) {
        __u64 g0 = 0, g1 = 0;
        lookup_u64(PIN_DIR "/slot_generation", 0, &g0);
        lookup_u64(PIN_DIR "/slot_generation", 1, &g1);
        printf("%llu %llu\n", (unsigned long long)g0, (unsigned long long)g1);
        return 0;
    }
    if (!strcmp(argv[1], "generation")) {
        __u64 g = 0;
        if (lookup_u64(PIN_DIR "/slot_generation", slot, &g) != 0) {
            fprintf(stderr, "cannot read slot_generation: %s\n", strerror(errno));
            return 1;
        }
        printf("%llu\n", (unsigned long long)g);
        return 0;
    }
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
