# aegis-next: post-2024 BPF stack prototype.
#
# This subdirectory is an isolated, opt-in playground for kernel
# features that did not exist when AegisBPF's mainline daemon was
# designed. It is NOT part of the mainline aegisbpf binary, does
# NOT ship in release packages, and is gated behind a separate
# CMake flag so a casual `cmake ..` build is unaffected.
#
# To enable:
#   cmake -DBUILD_AEGIS_NEXT=ON ..
#   cmake --build . --target aegisbpf-next
#
# Requires:
#   - Linux >= 6.9   (BPF arena map type, BPF_MAP_TYPE_ARENA)
#   - clang with -target bpf
#   - bpftool with `gen skeleton`
#   - libbpf >= 1.4 with bpf_arena__* helpers
#
# The flag is intentionally OFF by default; when ON we still gate
# every individual feature on a runtime kernel-version probe so
# that contributors on older hosts get a clean "skipped" message
# rather than a confusing build break.

option(BUILD_AEGIS_NEXT "Build the aegis-next prototype (post-2024 BPF stack)" OFF)

if(NOT BUILD_AEGIS_NEXT)
    return()
endif()

# Parse running kernel version. The arena map type is upstream in
# 6.9; older kernels reject the map at load time with EINVAL, which
# is a poor UX, so we gate at configure time too.
execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE AEGIS_NEXT_UNAME_R
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)" _AEGIS_NEXT_KVER_MATCH "${AEGIS_NEXT_UNAME_R}")
set(AEGIS_NEXT_KERNEL_MAJOR "${CMAKE_MATCH_1}")
set(AEGIS_NEXT_KERNEL_MINOR "${CMAKE_MATCH_2}")

if(NOT AEGIS_NEXT_KERNEL_MAJOR OR NOT AEGIS_NEXT_KERNEL_MINOR)
    message(WARNING
        "aegis-next: could not parse kernel version from '${AEGIS_NEXT_UNAME_R}'. "
        "Skipping prototype build. Set BUILD_AEGIS_NEXT=OFF to silence this warning."
    )
    return()
endif()

if(AEGIS_NEXT_KERNEL_MAJOR LESS 6
   OR (AEGIS_NEXT_KERNEL_MAJOR EQUAL 6 AND AEGIS_NEXT_KERNEL_MINOR LESS 9))
    message(WARNING
        "aegis-next: kernel ${AEGIS_NEXT_KERNEL_MAJOR}.${AEGIS_NEXT_KERNEL_MINOR} "
        "is older than the required 6.9 (BPF arena maps). Skipping prototype build."
    )
    return()
endif()

message(STATUS
    "aegis-next: enabled (kernel ${AEGIS_NEXT_KERNEL_MAJOR}.${AEGIS_NEXT_KERNEL_MINOR})"
)

# Where to find vmlinux.h. We reuse the top-level project's vmlinux.h
# rather than re-dumping it; that target is built before us via the
# add_dependencies() call below.
set(AEGIS_NEXT_VMLINUX_HEADER ${CMAKE_BINARY_DIR}/vmlinux.h)

set(AEGIS_NEXT_BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/provenance.bpf.c)
set(AEGIS_NEXT_BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/provenance.bpf.o)
set(AEGIS_NEXT_SKEL_HEADER ${CMAKE_CURRENT_BINARY_DIR}/provenance.skel.h)

set(AEGIS_NEXT_BPF_INCLUDE_FLAGS
    -I${CMAKE_BINARY_DIR}
    -I${CMAKE_CURRENT_BINARY_DIR}
)
foreach(dir IN LISTS LIBBPF_INCLUDE_DIRS)
    list(APPEND AEGIS_NEXT_BPF_INCLUDE_FLAGS -I${dir})
endforeach()

set(AEGIS_NEXT_BPF_TARGET_ARCH ${BPF_TARGET_ARCH})

# Prefer clang-19+ for __BPF_FEATURE_ADDR_SPACE_CAST (arena globals).
# Fall back to system clang if 19 is unavailable.
find_program(CLANG_19 clang-19)
if(CLANG_19)
    set(AEGIS_NEXT_BPF_CLANG ${CLANG_19})
    message(STATUS "aegis-next: using ${CLANG_19} for BPF (addr_space_cast support)")
else()
    set(AEGIS_NEXT_BPF_CLANG ${CLANG})
    message(STATUS "aegis-next: clang-19 not found, using ${CLANG} (arena globals may not work on 6.12+)")
endif()

add_custom_command(
    OUTPUT ${AEGIS_NEXT_BPF_OBJECT}
    COMMAND ${AEGIS_NEXT_BPF_CLANG} -g -O2 -target bpf -mcpu=v4
            -D__TARGET_ARCH_${AEGIS_NEXT_BPF_TARGET_ARCH}
            ${AEGIS_NEXT_BPF_INCLUDE_FLAGS}
            -c ${AEGIS_NEXT_BPF_SOURCE}
            -o ${AEGIS_NEXT_BPF_OBJECT}
    DEPENDS ${AEGIS_NEXT_BPF_SOURCE}
            ${CMAKE_CURRENT_SOURCE_DIR}/bpf/prov_types.h
            ${CMAKE_CURRENT_SOURCE_DIR}/bpf/arena_htable.h
            ${AEGIS_NEXT_VMLINUX_HEADER}
    VERBATIM
    COMMENT "Compiling aegis-next BPF (arena + bprm_check_security)"
)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_SKEL_HEADER}
    COMMAND ${BASH} -c "${BPFTOOL} gen skeleton ${AEGIS_NEXT_BPF_OBJECT} > ${AEGIS_NEXT_SKEL_HEADER}"
    DEPENDS ${AEGIS_NEXT_BPF_OBJECT}
    VERBATIM
    COMMENT "Generating aegis-next BPF skeleton"
)

set_source_files_properties(${AEGIS_NEXT_SKEL_HEADER} PROPERTIES GENERATED TRUE)
add_custom_target(aegis_next_skel DEPENDS ${AEGIS_NEXT_SKEL_HEADER})

# ---- sched_ext quarantine scheduler ----------------------------
set(AEGIS_NEXT_SCHED_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/quarantine.bpf.c)
set(AEGIS_NEXT_SCHED_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/quarantine.bpf.o)
set(AEGIS_NEXT_SCHED_SKEL   ${CMAKE_CURRENT_BINARY_DIR}/quarantine.skel.h)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_SCHED_OBJECT}
    COMMAND ${AEGIS_NEXT_BPF_CLANG} -g -O2 -target bpf -mcpu=v4
            -D__TARGET_ARCH_${AEGIS_NEXT_BPF_TARGET_ARCH}
            ${AEGIS_NEXT_BPF_INCLUDE_FLAGS}
            -c ${AEGIS_NEXT_SCHED_SOURCE}
            -o ${AEGIS_NEXT_SCHED_OBJECT}
    DEPENDS ${AEGIS_NEXT_SCHED_SOURCE}
            ${AEGIS_NEXT_VMLINUX_HEADER}
    VERBATIM
    COMMENT "Compiling aegis-next sched_ext quarantine scheduler"
)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_SCHED_SKEL}
    COMMAND ${BASH} -c "${BPFTOOL} gen skeleton ${AEGIS_NEXT_SCHED_OBJECT} > ${AEGIS_NEXT_SCHED_SKEL}"
    DEPENDS ${AEGIS_NEXT_SCHED_OBJECT}
    VERBATIM
    COMMENT "Generating aegis-next quarantine skeleton"
)

set_source_files_properties(${AEGIS_NEXT_SCHED_SKEL} PROPERTIES GENERATED TRUE)
add_custom_target(aegis_next_sched_skel DEPENDS ${AEGIS_NEXT_SCHED_SKEL})

# ---- legacy provenance (ringbuf-only fallback, kernels < 6.9) ----
set(AEGIS_NEXT_LEGACY_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/provenance_legacy.bpf.c)
set(AEGIS_NEXT_LEGACY_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/provenance_legacy.bpf.o)
set(AEGIS_NEXT_LEGACY_SKEL   ${CMAKE_CURRENT_BINARY_DIR}/provenance_legacy.skel.h)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_LEGACY_OBJECT}
    COMMAND ${AEGIS_NEXT_BPF_CLANG} -g -O2 -target bpf -mcpu=v4
            -D__TARGET_ARCH_${AEGIS_NEXT_BPF_TARGET_ARCH}
            ${AEGIS_NEXT_BPF_INCLUDE_FLAGS}
            -c ${AEGIS_NEXT_LEGACY_SOURCE}
            -o ${AEGIS_NEXT_LEGACY_OBJECT}
    DEPENDS ${AEGIS_NEXT_LEGACY_SOURCE}
            ${CMAKE_CURRENT_SOURCE_DIR}/bpf/prov_types.h
            ${AEGIS_NEXT_VMLINUX_HEADER}
    VERBATIM
    COMMENT "Compiling aegis-next legacy BPF (ringbuf-only fallback)"
)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_LEGACY_SKEL}
    COMMAND ${BASH} -c "${BPFTOOL} gen skeleton ${AEGIS_NEXT_LEGACY_OBJECT} > ${AEGIS_NEXT_LEGACY_SKEL}"
    DEPENDS ${AEGIS_NEXT_LEGACY_OBJECT}
    VERBATIM
    COMMENT "Generating aegis-next legacy skeleton"
)

set_source_files_properties(${AEGIS_NEXT_LEGACY_SKEL} PROPERTIES GENERATED TRUE)
add_custom_target(aegis_next_legacy_skel DEPENDS ${AEGIS_NEXT_LEGACY_SKEL})

# ---- self-protection LSM hooks ---------------------------------
set(AEGIS_NEXT_SELFPROT_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/selfprotect.bpf.c)
set(AEGIS_NEXT_SELFPROT_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/selfprotect.bpf.o)
set(AEGIS_NEXT_SELFPROT_SKEL   ${CMAKE_CURRENT_BINARY_DIR}/selfprotect.skel.h)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_SELFPROT_OBJECT}
    COMMAND ${AEGIS_NEXT_BPF_CLANG} -g -O2 -target bpf -mcpu=v4
            -D__TARGET_ARCH_${AEGIS_NEXT_BPF_TARGET_ARCH}
            ${AEGIS_NEXT_BPF_INCLUDE_FLAGS}
            -c ${AEGIS_NEXT_SELFPROT_SOURCE}
            -o ${AEGIS_NEXT_SELFPROT_OBJECT}
    DEPENDS ${AEGIS_NEXT_SELFPROT_SOURCE}
            ${AEGIS_NEXT_VMLINUX_HEADER}
    VERBATIM
    COMMENT "Compiling aegis-next self-protection LSM hooks"
)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_SELFPROT_SKEL}
    COMMAND ${BASH} -c "${BPFTOOL} gen skeleton ${AEGIS_NEXT_SELFPROT_OBJECT} > ${AEGIS_NEXT_SELFPROT_SKEL}"
    DEPENDS ${AEGIS_NEXT_SELFPROT_OBJECT}
    VERBATIM
    COMMENT "Generating aegis-next self-protection skeleton"
)

set_source_files_properties(${AEGIS_NEXT_SELFPROT_SKEL} PROPERTIES GENERATED TRUE)
add_custom_target(aegis_next_selfprot_skel DEPENDS ${AEGIS_NEXT_SELFPROT_SKEL})

# ---- Phase 4: binary authorization BPF program ------------------
set(AEGIS_NEXT_BINAUTH_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/binary_auth.bpf.c)
set(AEGIS_NEXT_BINAUTH_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/binary_auth.bpf.o)
set(AEGIS_NEXT_BINAUTH_SKEL   ${CMAKE_CURRENT_BINARY_DIR}/binary_auth.skel.h)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_BINAUTH_OBJECT}
    COMMAND ${AEGIS_NEXT_BPF_CLANG} -g -O2 -target bpf -mcpu=v4
            -D__TARGET_ARCH_${AEGIS_NEXT_BPF_TARGET_ARCH}
            ${AEGIS_NEXT_BPF_INCLUDE_FLAGS}
            -c ${AEGIS_NEXT_BINAUTH_SOURCE}
            -o ${AEGIS_NEXT_BINAUTH_OBJECT}
    DEPENDS ${AEGIS_NEXT_BINAUTH_SOURCE}
            ${CMAKE_CURRENT_SOURCE_DIR}/bpf/prov_types.h
            ${AEGIS_NEXT_VMLINUX_HEADER}
    VERBATIM
    COMMENT "Compiling aegis-next binary authorization BPF (fsverity + xattr)"
)

add_custom_command(
    OUTPUT ${AEGIS_NEXT_BINAUTH_SKEL}
    COMMAND ${BASH} -c "${BPFTOOL} gen skeleton ${AEGIS_NEXT_BINAUTH_OBJECT} > ${AEGIS_NEXT_BINAUTH_SKEL}"
    DEPENDS ${AEGIS_NEXT_BINAUTH_OBJECT}
    VERBATIM
    COMMENT "Generating aegis-next binary auth skeleton"
)

set_source_files_properties(${AEGIS_NEXT_BINAUTH_SKEL} PROPERTIES GENERATED TRUE)
add_custom_target(aegis_next_binauth_skel DEPENDS ${AEGIS_NEXT_BINAUTH_SKEL})

# We depend on the parent project's bpf_skel target indirectly via
# vmlinux.h. Express this explicitly so a clean build can't race.
if(TARGET bpf_skel)
    add_dependencies(aegis_next_skel bpf_skel)
    add_dependencies(aegis_next_sched_skel bpf_skel)
    add_dependencies(aegis_next_selfprot_skel bpf_skel)
    add_dependencies(aegis_next_legacy_skel bpf_skel)
    add_dependencies(aegis_next_binauth_skel bpf_skel)
endif()

# Static lib for the testable userspace pieces. Keeps the test
# target and the daemon target in sync without re-listing files.
add_library(aegis_next_core STATIC
    src/prov_walk.cpp
)
target_include_directories(aegis_next_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(aegisbpf-next
    src/main.cpp
    ${AEGIS_NEXT_SKEL_HEADER}
    ${AEGIS_NEXT_SCHED_SKEL}
    ${AEGIS_NEXT_SELFPROT_SKEL}
    ${AEGIS_NEXT_LEGACY_SKEL}
    ${AEGIS_NEXT_BINAUTH_SKEL}
)

add_dependencies(aegisbpf-next aegis_next_skel aegis_next_sched_skel aegis_next_selfprot_skel aegis_next_legacy_skel aegis_next_binauth_skel)

target_include_directories(aegisbpf-next PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf
    ${LIBBPF_INCLUDE_DIRS}
)

# libbpf's LIBBPF_OPTS macro triggers -Wmissing-field-initializers in C++;
# this is a false positive (the macro zero-inits via .sz = sizeof).
target_compile_options(aegisbpf-next PRIVATE -Wno-missing-field-initializers)
target_link_directories(aegisbpf-next PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(aegisbpf-next PRIVATE
    aegis_next_core
    ${LIBBPF_LIBRARIES}
    ZLIB::ZLIB
)

# Mark as non-installed: prototype binaries must not collide with
# the shipped aegisbpf release artifact.
set_target_properties(aegisbpf-next PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/prototype
)

# ---- install targets (for packaging) --------------------------------
install(TARGETS aegisbpf-next RUNTIME DESTINATION bin COMPONENT aegis-next)
install(FILES deploy/aegisbpf-next.service
    DESTINATION lib/systemd/system
    COMPONENT aegis-next)
install(FILES deploy/aegisbpf-next.conf
    DESTINATION share/aegisbpf-next
    COMPONENT aegis-next)
install(DIRECTORY examples/
    DESTINATION share/aegisbpf-next/examples
    COMPONENT aegis-next
    FILES_MATCHING PATTERN "*.rules")

# ----- selftests --------------------------------------------------
#
# Only built when the parent project enables testing AND has
# already discovered GTest. We hard-skip on missing GTest rather
# than re-running FetchContent: the parent project owns that
# decision.
if(BUILD_TESTING AND TARGET GTest::gtest)
    add_executable(aegis_next_test
        tests/test_prov_walk.cpp
    )
    target_link_libraries(aegis_next_test PRIVATE
        aegis_next_core
        GTest::gtest
        GTest::gtest_main
    )
    set_target_properties(aegis_next_test PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/prototype
    )
    include(GoogleTest)
    gtest_discover_tests(aegis_next_test
        DISCOVERY_MODE PRE_TEST
        TEST_PREFIX "aegis_next."
    )
elseif(BUILD_TESTING)
    message(STATUS
        "aegis-next: BUILD_TESTING is ON but GTest::gtest is not "
        "yet defined at this point in configure. Selftests skipped."
    )
endif()
