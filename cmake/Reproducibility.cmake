# cmake/Reproducibility.cmake
#
# Bit-for-bit reproducible builds for `aegisbpfd`.
#
# Two builds of the same source tree, with the same compiler version
# and SOURCE_DATE_EPOCH, must produce byte-identical binaries (and a
# byte-identical aegis.bpf.o) regardless of the absolute path of the
# build / source directory, the build host's hostname, the user
# running the build, or the wall-clock time at which the build runs.
#
# Knobs we control here:
#
#   1. -ffile-prefix-map=<src>=. and -ffile-prefix-map=<build>=.
#      Strips absolute paths out of __FILE__, debug info (DWARF
#      DW_AT_*name fields), and the assertion macros. The src and
#      build dirs are mapped to "." so the result is independent of
#      where the tree was checked out.
#
#   2. -fdebug-prefix-map=<src>=.  -fdebug-prefix-map=<build>=.
#      Belt-and-braces for older toolchains where -ffile-prefix-map
#      doesn't yet cover the debug-info case.
#
#   3. -Wl,--build-id=sha1
#      Content-addressed build-id. Without this, ld defaults to a
#      random/uuid build-id that changes every link.
#
#   4. ar -D (deterministic archive: zero out mtime, uid, gid, mode).
#      Set via CMAKE_C_ARCHIVE_CREATE / CMAKE_CXX_ARCHIVE_CREATE so
#      libaegisbpf_lib.a is reproducible too.
#
#   5. SOURCE_DATE_EPOCH propagation.
#      We don't bake __DATE__/__TIME__ into the binary anywhere (a
#      grep verifies this — see scripts/check_reproducible_build.sh),
#      but exporting SOURCE_DATE_EPOCH still matters for any 3rd-party
#      tool the build invokes (libbpf's `make install`, bpftool, …).
#
# What we deliberately do *not* do here:
#   - We don't try to canonicalise the BPF object's BTF section: that
#     is purely a function of the input C source plus clang's CO-RE
#     pipeline, which is already deterministic.
#   - We don't strip the build-id entirely. A reproducible content-
#     hash build-id is more useful than no build-id at all (it lets
#     debuginfod / coredump tooling find symbols).

option(AEGIS_REPRODUCIBLE_BUILD "Enable bit-for-bit reproducible build flags" ON)

if(NOT AEGIS_REPRODUCIBLE_BUILD)
    message(STATUS "Reproducible build flags: disabled (AEGIS_REPRODUCIBLE_BUILD=OFF)")
    return()
endif()

# 1 & 2: file-prefix-map / debug-prefix-map for both C and C++.
# Use unambiguous "=." mappings; keep build dir first so it shadows
# the src mapping for files that live in both (CMake-generated
# headers under the build tree).
set(_aegis_prefix_map_flags
    "-ffile-prefix-map=${CMAKE_BINARY_DIR}=."
    "-ffile-prefix-map=${CMAKE_SOURCE_DIR}=."
    "-fdebug-prefix-map=${CMAKE_BINARY_DIR}=."
    "-fdebug-prefix-map=${CMAKE_SOURCE_DIR}=."
)
foreach(_flag IN LISTS _aegis_prefix_map_flags)
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} ${_flag}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_flag}")
endforeach()

# 3: Content-addressed build-id. Wins over the default uuid/random
# variant because the same .text/.rodata always produces the same
# build-id, which means debuginfod lookups work across rebuilds.
set(CMAKE_EXE_LINKER_FLAGS    "${CMAKE_EXE_LINKER_FLAGS} -Wl,--build-id=sha1")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--build-id=sha1")

# 4: deterministic ar. CMake's default <CMAKE_AR> qc rules into qcs
# rule already; we override to add the -D flag (uppercase D = "use
# zero for timestamps and uids/gids").
# Note: GNU ar has supported -D since binutils 2.30 (2018).
set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Dqc <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_C_ARCHIVE_APPEND   "<CMAKE_AR> Dq  <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -D <TARGET>")
set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Dqc <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_CXX_ARCHIVE_APPEND "<CMAKE_AR> Dq  <TARGET> <LINK_FLAGS> <OBJECTS>")
set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -D <TARGET>")

# 5: SOURCE_DATE_EPOCH. CMake 3.20+ already honors this for some
# generators, but explicit propagation is safer for our custom
# add_custom_command targets (bpftool, libbpf make-build, etc.).
if(DEFINED ENV{SOURCE_DATE_EPOCH})
    message(STATUS "Reproducible build flags: enabled (SOURCE_DATE_EPOCH=$ENV{SOURCE_DATE_EPOCH})")
else()
    message(STATUS "Reproducible build flags: enabled (SOURCE_DATE_EPOCH not set; "
                   "live wall-clock will be used by any tool that needs a timestamp). "
                   "Set SOURCE_DATE_EPOCH for fully reproducible output.")
endif()
