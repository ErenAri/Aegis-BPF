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

add_custom_command(
    OUTPUT ${AEGIS_NEXT_BPF_OBJECT}
    COMMAND ${CLANG} -g -O2 -target bpf
            -D__TARGET_ARCH_${AEGIS_NEXT_BPF_TARGET_ARCH}
            ${AEGIS_NEXT_BPF_INCLUDE_FLAGS}
            -c ${AEGIS_NEXT_BPF_SOURCE}
            -o ${AEGIS_NEXT_BPF_OBJECT}
    DEPENDS ${AEGIS_NEXT_BPF_SOURCE}
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

# We depend on the parent project's bpf_skel target indirectly via
# vmlinux.h. Express this explicitly so a clean build can't race.
if(TARGET bpf_skel)
    add_dependencies(aegis_next_skel bpf_skel)
endif()

add_executable(aegisbpf-next
    src/main.cpp
    ${AEGIS_NEXT_SKEL_HEADER}
)

add_dependencies(aegisbpf-next aegis_next_skel)

target_include_directories(aegisbpf-next PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf
    ${LIBBPF_INCLUDE_DIRS}
)

target_link_directories(aegisbpf-next PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(aegisbpf-next PRIVATE ${LIBBPF_LIBRARIES})

# Mark as non-installed: prototype binaries must not collide with
# the shipped aegisbpf release artifact.
set_target_properties(aegisbpf-next PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/prototype
)
