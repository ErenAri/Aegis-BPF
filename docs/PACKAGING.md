# AegisBPF — Distro Packaging

This document covers the **maintainer-side** workflow for producing
binary distro packages of AegisBPF (`.deb`, `.rpm`) and uploading them
to public hosted repositories (Ubuntu PPA, Fedora COPR, OpenSUSE OBS,
Arch AUR).

For the **operator-side** "how do I install it" recipe, see the project
[README](../README.md#install).

---

## 1. What this PR ships

This repository now produces two installable binary packages for every
supported architecture, gated by CI:

| File                              | Built by             | Smoke-tested in CI on   |
| --------------------------------- | -------------------- | ----------------------- |
| `aegisbpf_<ver>_<arch>.deb`       | `cpack -G DEB`       | `debian:12`, `ubuntu:24.04` |
| `aegisbpf-<ver>-<rel>.<arch>.rpm` | `cpack -G RPM`       | `fedora:40`, `rockylinux:9` |

The CI workflow `.github/workflows/packaging.yml` runs on every PR that
touches `CMakeLists.txt`, `packaging/**`, or the workflow itself. It:

1. Builds the binary + BPF object on `ubuntu-24.04`.
2. Runs `cpack -G DEB` and `cpack -G RPM`.
3. Verifies the **required-files contract** — every release must ship
   `/usr/bin/aegisbpf`, `/usr/lib/aegisbpf/aegis.bpf.{o,sha256}`,
   `/usr/lib/systemd/system/aegisbpf.service`, `/etc/default/aegisbpf`,
   and `/etc/aegisbpf/policy.example`. A refactor that drops one of
   these will fail the gate, not silently ship an incomplete package.
4. Verifies the RPM scriptlets are wired (`%post`, `%preun`, `%postun`).
5. Spins up a clean container per matrix entry, runs
   `dpkg -i` / `rpm -ivh`, asserts `aegisbpf --version` returns 0,
   then exercises the **remove** and **purge** paths.

The .deb and .rpm artifacts are uploaded as a GitHub Actions artifact
(`aegisbpf-packages`, retention 14 days) so a release engineer can
download and locally `dput` / `copr-cli` from the same bytes the smoke
test verified.

What this PR **does not** ship: hosted-repo upload (PPA / COPR / OBS /
AUR). Those require maintainer-account credentials that are not
appropriate to embed in a public repository's CI; they live in the
release-engineering runbook below.

---

## 2. Source-of-truth: `CMakeLists.txt` CPack block

Package metadata lives at the bottom of `CMakeLists.txt` under the
"CPack configuration" comment. Three classes of metadata, each with a
distinct ABI:

- **Common** (name, vendor, contact, version, homepage, install prefix).
- **Debian** (`CPACK_DEBIAN_*`): section, priority, control fields,
  shlibdeps, and the path to the maintainer scripts directory.
- **RPM** (`CPACK_RPM_*`): license, group, requires (with split
  `_POST`/`_PREUN`/`_POSTUN` for systemd), explicit script-file paths,
  and the `%config(noreplace)` user filelist.

The Debian and RPM metadata reuse the **same three maintainer scripts**
under `packaging/maintainer-scripts/`:

| Script    | Debian role | RPM role | First-arg shape                       |
| --------- | ----------- | -------- | ------------------------------------- |
| `postinst` | postinst    | `%post`  | `configure` (Debian) or `1`/`2` (RPM) |
| `prerm`    | prerm       | `%preun` | `remove`/`upgrade`/... or `0`/`1`     |
| `postrm`   | postrm      | `%postun` | `purge`/`remove`/... or `0`/`1`      |

Each script branches on the first argument to honour both ABIs in one
file. The shared file is the source-of-truth so a fix to one cannot
silently drift from the other. See the header comments in each script
for the full ABI table.

---

## 3. Maintainer-script behaviour contract

| Phase    | Debian (apt/dpkg)        | Fedora/RHEL (dnf/rpm)        | What runs                                                                                              |
| -------- | ------------------------ | ---------------------------- | ------------------------------------------------------------------------------------------------------ |
| Install  | `dpkg -i`                | `rpm -ivh` / `dnf install`   | `mkdir -p /var/lib/aegisbpf /etc/aegisbpf`; `systemctl daemon-reload`; on Debian, `deb-systemd-helper enable` (matches dh_installsystemd default); on RPM, **no** auto-enable (matches Fedora packaging guidelines). |
| Upgrade  | `dpkg -i` (existing)     | `rpm -Uvh` / `dnf upgrade`   | `daemon-reload` only — running service is left running, the new postinst does not stop or restart it. |
| Remove   | `dpkg -r aegisbpf`       | `rpm -e aegisbpf`            | `systemctl disable --now aegisbpf.service` if systemd is around; binary + unit + BPF object removed; `/etc/aegisbpf/*` and `/var/lib/aegisbpf/*` **preserved** (Debian conffile / RPM `%config(noreplace)`). |
| Purge    | `dpkg -P aegisbpf`       | (no equivalent on RPM)       | Debian-only: removes `/var/lib/aegisbpf` and unmasks the unit. Operator config under `/etc/aegisbpf/` is still left in place by Debian conffile policy. |

**No-systemd hosts.** All systemd interaction is conditional on
`/run/systemd/system` existing and `systemctl` being on `$PATH`. A
container build, a chroot, or a non-systemd init (s6, runit, OpenRC)
will install cleanly and silently skip the unit-management steps; the
binary still works under any external supervisor.

---

## 4. Building the packages locally

The `packaging` CI job mirrors the recipe below verbatim. To reproduce
on a developer laptop with the same dependencies:

```sh
sudo apt-get install -y clang llvm libbpf-dev libsystemd-dev libelf-dev \
    pkg-config cmake ninja-build rpm linux-tools-generic
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build --target aegisbpf
( cd build && cpack -G DEB && cpack -G RPM )
ls -la build/aegisbpf_*.deb build/aegisbpf-*.rpm
```

Then smoke-test against a clean image:

```sh
docker run --rm -v "$PWD/build:/pkg" debian:12 \
    bash -c 'apt-get update && apt-get install -y libbpf1 libelf1 \
        && dpkg -i /pkg/aegisbpf_*.deb && /usr/bin/aegisbpf --version'
docker run --rm -v "$PWD/build:/pkg" fedora:40 \
    bash -c 'dnf install -y libbpf elfutils-libelf \
        && rpm -ivh /pkg/aegisbpf-*.rpm && /usr/bin/aegisbpf --version'
```

---

## 5. Uploading to hosted repositories (release engineering)

> :warning: This section requires **maintainer accounts** on each
> hosted service. Credentials must never be embedded in the public
> repository or in CI. Run from a maintainer's local workstation.

### 5.1 Ubuntu PPA (Launchpad)

1. Register a Launchpad account, upload your OpenPGP public key, and
   create a PPA (e.g. `ppa:aegisbpf/stable`).
2. Build a **source package**, not a binary — Launchpad rebuilds .deb
   from source in its own infrastructure:
   ```sh
   debuild -S -sa
   dput ppa:aegisbpf/stable ../aegisbpf_<ver>_source.changes
   ```
3. Wait ~30 min for the Launchpad build farm to finish. Verify with:
   `apt-cache policy aegisbpf` after `add-apt-repository ppa:aegisbpf/stable`.

> The `.deb` produced by `cpack -G DEB` in this repo is suitable for
> direct installation from a release tarball, but it is **not**
> suitable for PPA upload — Launchpad insists on a `debian/` source
> tree. A follow-up PR will add a `debian/` directory generated from
> the same metadata, plus a `.github/workflows/ppa-upload.yml` driven
> by a maintainer-controlled `LAUNCHPAD_GPG_KEY` secret.

### 5.2 Fedora COPR

1. Register at https://copr.fedorainfracloud.org/, install `copr-cli`,
   and run `copr-cli login` once.
2. Create a COPR project (e.g. `aegisbpf/stable`).
3. Upload the source RPM:
   ```sh
   ( cd build && cpack -G RPM --config CPackSourceConfig.cmake ) || \
       rpmbuild -bs aegisbpf.spec    # if you carry a hand-written .spec
   copr-cli build aegisbpf/stable build/aegisbpf-<ver>-<rel>.src.rpm
   ```
4. Verify with `dnf copr enable aegisbpf/stable && dnf install aegisbpf`.

### 5.3 OpenSUSE Build Service (OBS)

1. Register at https://build.opensuse.org/, install `osc`, and check out
   your project (`osc co home:<user>:aegisbpf`).
2. Update the `.spec` and `_service` files; commit:
   ```sh
   osc add *.spec
   osc commit -m "aegisbpf <ver>"
   ```
3. OBS rebuilds for every distro target you have configured (Leap,
   Tumbleweed, etc.).

### 5.4 Arch AUR

1. AUR ships *PKGBUILD*, not a binary; the user's machine compiles.
2. Maintain an `aegisbpf-bin` package that downloads the GitHub
   Releases tarball, plus an `aegisbpf-git` for the bleeding edge.
   Both live in a separate AUR git repo, not in this monorepo.

---

## 6. Versioning + release tagging

CPack pulls the version from `project(... VERSION X.Y.Z ...)` in
`CMakeLists.txt`. The release-tag flow is:

1. Bump `project(aegisbpf VERSION X.Y.Z LANGUAGES C CXX)` and the
   `## [X.Y.Z] - YYYY-MM-DD` heading in `docs/CHANGELOG.md`.
2. Tag: `git tag -s vX.Y.Z -m "vX.Y.Z"`.
3. Push: `git push origin vX.Y.Z` — this fires `release.yml`, which
   runs the e2e + perf gates and creates the GitHub Release.
4. Download `aegisbpf-packages` artifact from the matching
   `packaging.yml` run for that commit; attach to the GitHub Release.
5. Run §5.1 / §5.2 / §5.3 / §5.4 from a maintainer workstation.

---

## 7. Roadmap (out of scope for this PR)

- `debian/` source tree + automated PPA upload via Launchpad GPG.
- `aegisbpf.spec` carried in-tree (in addition to CPack-generated) so
  Fedora / RHEL maintainers can sponsor it into the official repos.
- Reproducible `.deb` / `.rpm` (currently only the binary is
  reproducible — `SOURCE_DATE_EPOCH` is honoured but timestamps inside
  the package format itself are not yet pinned).
- Signed `.deb` / `.rpm` with cosign-derived keys for a hosted
  signed-repo path that does not depend on Launchpad / COPR signing.
