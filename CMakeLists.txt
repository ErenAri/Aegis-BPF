cmake_minimum_required(VERSION 3.20)
project(aegisbpf VERSION 0.8.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Local CMake module path so `include(Reproducibility)` works.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)

# Match packaged/systemd paths unless caller overrides explicitly.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "Install prefix" FORCE)
endif()

# Build options
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(BUILD_TESTING "Build tests" ON)
option(BUILD_BENCHMARKS "Build benchmark targets when tests are enabled" ON)
option(ENABLE_FUZZING "Enable fuzzing targets" OFF)
option(SKIP_BPF_BUILD "Skip BPF object compilation (for cross-compilation)" OFF)
option(ENABLE_SIGKILL_ENFORCEMENT
       "Enable dangerous SIGKILL enforcement path (still requires --allow-sigkill at runtime)"
       OFF)

find_program(CLANG clang REQUIRED)
find_program(BASH bash REQUIRED)

# bpftool is only required if we're building BPF objects
if(NOT SKIP_BPF_BUILD)
    find_program(BPFTOOL bpftool REQUIRED)
endif()

find_package(PkgConfig REQUIRED)
option(STATIC_LIBBPF "Build and statically link libbpf from source" OFF)
option(PORTABLE_GLIBC "Suppress glibc 2.38+ C23 redirections for older distro compat" OFF)

if(PORTABLE_GLIBC)
    set(GLIBC_COMPAT_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/cmake/glibc_compat.h")
    # Force-include the compat header before any system headers so that
    # <features.h>'s ISOC2X macros are overridden before <stdlib.h> etc.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -include ${GLIBC_COMPAT_HEADER}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -include ${GLIBC_COMPAT_HEADER}")
    message(STATUS "Portable glibc: suppressing C23 symbol redirections via ${GLIBC_COMPAT_HEADER}")
endif()

if(STATIC_LIBBPF)
    include(FetchContent)
    include(ExternalProject)

    set(LIBBPF_VERSION "1.6.1" CACHE STRING "libbpf version to build from source")

    FetchContent_Declare(
        libbpf_src
        URL https://github.com/libbpf/libbpf/archive/refs/tags/v${LIBBPF_VERSION}.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        TIMEOUT 60
    )
    FetchContent_MakeAvailable(libbpf_src)

    set(LIBBPF_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/libbpf-build)
    set(LIBBPF_INSTALL_DIR ${LIBBPF_BUILD_DIR}/install)
    set(LIBBPF_STATIC_LIB ${LIBBPF_INSTALL_DIR}/lib64/libbpf.a)
    set(LIBBPF_SRC_DIR ${libbpf_src_SOURCE_DIR}/src)

    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBELF REQUIRED libelf)

    # Fuzz targets run in the minimal OSS-Fuzz / ClusterFuzzLite base-runner
    # image, which ships no libelf.so / libz.so. A dynamically-linked fuzzer
    # therefore dies at startup with
    #   "error while loading shared libraries: libelf.so.1".
    # Link libelf -- and its own static deps (elfutils' libelf.a may pull in
    # zstd/lzma/bz2) -- as archives for fuzz builds so the binaries are
    # self-contained. Production builds keep the system's shared libelf.
    if(ENABLE_FUZZING)
        find_library(AEGIS_LIBELF_A NAMES libelf.a)
        if(AEGIS_LIBELF_A)
            set(LIBELF_LIBRARIES ${AEGIS_LIBELF_A})
            foreach(_dep zstd lzma bz2)
                find_library(AEGIS_LIB_${_dep}_A NAMES lib${_dep}.a)
                if(AEGIS_LIB_${_dep}_A)
                    list(APPEND LIBELF_LIBRARIES ${AEGIS_LIB_${_dep}_A})
                endif()
            endforeach()
        else()
            set(LIBELF_LIBRARIES -l:libelf.a)
        endif()
    endif()

    # Pass the glibc compat header to libbpf's Makefile so its object
    # files also avoid __isoc23_* symbols (e.g. __isoc23_strtoull).
    set(LIBBPF_EXTRA_CFLAGS "")
    if(PORTABLE_GLIBC)
        set(LIBBPF_EXTRA_CFLAGS "-include ${GLIBC_COMPAT_HEADER}")
    endif()

    add_custom_command(
        OUTPUT ${LIBBPF_STATIC_LIB}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${LIBBPF_BUILD_DIR}
        COMMAND ${CMAKE_COMMAND} -E env
            "BUILD_STATIC_ONLY=1"
            "OBJDIR=${LIBBPF_BUILD_DIR}"
            "DESTDIR=${LIBBPF_INSTALL_DIR}"
            "PREFIX="
            "EXTRA_CFLAGS=${LIBBPF_EXTRA_CFLAGS}"
            # `install` ships only bpf/*.h; `install_uapi_headers` is a separate
            # target that ships the bundled UAPI linux/{bpf,bpf_common,btf}.h.
            # Without it, libbpf.h's `#include <linux/bpf.h>` falls through to the
            # build image's stale system UAPI (no `enum bpf_link_type`), and
            # libbpf.h:`libbpf_bpf_link_type_str(enum bpf_link_type)` fails to
            # compile under C++ ("ISO C++ forbids forward references to 'enum'").
            make -C ${LIBBPF_SRC_DIR} -j$ENV{NPROC} install install_uapi_headers
        DEPENDS ${LIBBPF_SRC_DIR}/Makefile
        COMMENT "Building libbpf ${LIBBPF_VERSION} (static)"
        VERBATIM
    )
    add_custom_target(libbpf_static DEPENDS ${LIBBPF_STATIC_LIB})

    add_library(libbpf_imported STATIC IMPORTED GLOBAL)
    set_target_properties(libbpf_imported PROPERTIES
        IMPORTED_LOCATION ${LIBBPF_STATIC_LIB}
    )
    add_dependencies(libbpf_imported libbpf_static)

    set(LIBBPF_INCLUDE_DIRS ${LIBBPF_INSTALL_DIR}/include)
    set(LIBBPF_LIBRARY_DIRS "")
    set(LIBBPF_LIBRARIES libbpf_imported ${LIBELF_LIBRARIES})
    message(STATUS "Using static libbpf ${LIBBPF_VERSION} (built from source)")
else()
    pkg_check_modules(LIBBPF REQUIRED libbpf)
    message(STATUS "Using system libbpf")
endif()

pkg_check_modules(SYSTEMD QUIET libsystemd)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
    # Explicitly define NDEBUG to disable debug-only code paths (e.g., BPF verification bypass)
    add_definitions(-DNDEBUG)
endif()

# Security hardening flags
#
# Levels are probed for compiler support so the cross-compiler/cross-arch matrix
# (GCC/Clang, x86_64/arm64) degrades gracefully instead of failing the build.
# Skipped for fuzzing builds, where the sanitizer/fuzzing-engine toolchain owns
# the compile/link flags (FORTIFY can interfere with sanitizer instrumentation).
if(NOT ENABLE_FUZZING)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)

# _FORTIFY_SOURCE: prefer level 3, else 2. Probe with the fortified headers under
# -O2 -Werror so a compiler that only partially supports level 3 (e.g. GCC 11)
# correctly falls back — a bare -D probe wrongly reports success there.
set(CMAKE_REQUIRED_FLAGS "-O2 -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3")
check_cxx_source_compiles(
    "#include <cstring>\nint main(){char b[32];std::memset(b,0,sizeof(b));return b[0];}"
    AEGIS_HAS_FORTIFY3)
unset(CMAKE_REQUIRED_FLAGS)
if(AEGIS_HAS_FORTIFY3)
    set(AEGIS_FORTIFY_LEVEL 3)
else()
    set(AEGIS_FORTIFY_LEVEL 2)
endif()

# Always -U_FORTIFY_SOURCE before redefining: some distros (Ubuntu) predefine it
# (gcc-11 -> 2, gcc-13/Ubuntu 24.04 -> 3), and redefining to a different level is
# a "_FORTIFY_SOURCE redefined" error under -Werror.
set(AEGIS_HARDEN_FLAGS "-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=${AEGIS_FORTIFY_LEVEL} -fstack-protector-strong -fPIE")

# Stack clash protection (large-stack-probe guard; GCC 8+/Clang 11+, x86_64/arm64).
check_cxx_compiler_flag("-fstack-clash-protection" AEGIS_HAS_STACK_CLASH)
if(AEGIS_HAS_STACK_CLASH)
    string(APPEND AEGIS_HARDEN_FLAGS " -fstack-clash-protection")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${AEGIS_HARDEN_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${AEGIS_HARDEN_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now")

# libstdc++ hardened mode (C++ only): bounds/precondition assertions in std:: containers.
check_cxx_compiler_flag("-D_GLIBCXX_ASSERTIONS" AEGIS_HAS_GLIBCXX_ASSERTIONS)
if(AEGIS_HAS_GLIBCXX_ASSERTIONS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_ASSERTIONS")
endif()
endif() # NOT ENABLE_FUZZING

# Sanitizer configuration
if(ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

if(ENABLE_UBSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
endif()

if(ENABLE_TSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
endif()

if(ENABLE_COVERAGE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
endif()

# Reproducibility flags (file-prefix-map, build-id=sha1, ar -D, etc.).
# Must come AFTER all other CMAKE_*_FLAGS edits so the prefix-map flags
# end up applying to every TU compiled below.
include(Reproducibility)

# BPF compilation settings
set(BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/aegis.bpf.c)
set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/aegis.bpf.o)
set(SKELETON_HEADER ${CMAKE_CURRENT_BINARY_DIR}/aegis.skel.h)
set(VMLINUX_HEADER ${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h)

if(NOT SKIP_BPF_BUILD)
    set(BPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR})
    list(APPEND BPF_INCLUDE_DIRS ${LIBBPF_INCLUDE_DIRS})
    set(BPF_INCLUDE_FLAGS "")
    foreach(dir IN LISTS BPF_INCLUDE_DIRS)
        list(APPEND BPF_INCLUDE_FLAGS -I${dir})
    endforeach()

    set(BPF_TARGET_ARCH)
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
        set(BPF_TARGET_ARCH x86)
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        set(BPF_TARGET_ARCH arm64)
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
        set(BPF_TARGET_ARCH arm)
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "ppc64le")
        set(BPF_TARGET_ARCH powerpc)
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "s390x")
        set(BPF_TARGET_ARCH s390)
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
        set(BPF_TARGET_ARCH riscv)
    else()
        set(BPF_TARGET_ARCH ${CMAKE_SYSTEM_PROCESSOR})
    endif()

    # Generate vmlinux.h from kernel BTF
    add_custom_command(
        OUTPUT ${VMLINUX_HEADER}
        COMMAND ${BASH} -c "${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_HEADER}"
        VERBATIM
    )

    # Compile BPF object
    add_custom_command(
        OUTPUT ${BPF_OBJECT}
        COMMAND ${CLANG} -g -O2 -target bpf -D__TARGET_ARCH_${BPF_TARGET_ARCH} ${BPF_INCLUDE_FLAGS} -c ${BPF_SOURCE} -o ${BPF_OBJECT}
        DEPENDS ${BPF_SOURCE}
                ${CMAKE_CURRENT_SOURCE_DIR}/bpf/aegis_common.h
                ${CMAKE_CURRENT_SOURCE_DIR}/bpf/aegis_exec.bpf.h
                ${CMAKE_CURRENT_SOURCE_DIR}/bpf/aegis_file.bpf.h
                ${CMAKE_CURRENT_SOURCE_DIR}/bpf/aegis_process.bpf.h
                ${CMAKE_CURRENT_SOURCE_DIR}/bpf/aegis_net.bpf.h
                ${VMLINUX_HEADER}
        VERBATIM
    )

    # Generate BPF skeleton header
    add_custom_command(
        OUTPUT ${SKELETON_HEADER}
        COMMAND ${BASH} -c "${BPFTOOL} gen skeleton ${BPF_OBJECT} > ${SKELETON_HEADER}"
        DEPENDS ${BPF_OBJECT}
        VERBATIM
    )

    # Target for just the BPF object (no skeleton generation)
    add_custom_target(bpf_obj DEPENDS ${BPF_OBJECT})

    set_source_files_properties(${SKELETON_HEADER} PROPERTIES GENERATED TRUE)
    add_custom_target(bpf_skel DEPENDS ${SKELETON_HEADER})

    # Generate BPF object hash for integrity verification
    set(BPF_HASH_FILE ${CMAKE_CURRENT_BINARY_DIR}/aegis.bpf.sha256)
    add_custom_command(
        OUTPUT ${BPF_HASH_FILE}
        COMMAND ${BASH} -c "sha256sum ${BPF_OBJECT} | cut -d' ' -f1 > ${BPF_HASH_FILE}"
        DEPENDS ${BPF_OBJECT}
        VERBATIM
    )
    add_custom_target(bpf_hash DEPENDS ${BPF_HASH_FILE})
    add_dependencies(bpf_skel bpf_hash)
else()
    # When skipping BPF build, create a dummy target
    add_custom_target(bpf_skel)
    message(STATUS "Skipping BPF build (SKIP_BPF_BUILD=ON)")
endif()

# Userspace source files
set(AEGIS_SOURCES
    src/main.cpp
    src/binary_scan.cpp
    src/cli_bpf.cpp
    src/cli_cgroup.cpp
    src/cli_common.cpp
    src/cli_dispatch.cpp
    src/cli_network.cpp
    src/cli_policy.cpp
    src/cli_run.cpp
    src/commands_block_allow.cpp
    src/commands_cgroup.cpp
    src/commands_emergency.cpp
    src/commands_explain.cpp
    src/commands_health.cpp
    src/commands_network.cpp
    src/commands_policy.cpp
    src/commands_probe.cpp
    src/commands_simulate.cpp
    src/commands_metrics.cpp
    src/commands_keys_survival.cpp
    src/commands_monitoring.cpp
    src/control.cpp
    src/daemon.cpp
    src/daemon_policy_gate.cpp
    src/daemon_posture.cpp
    src/daemon_runtime.cpp
    src/bpf_attach.cpp
    src/bpf_config.cpp
    src/bpf_link_pin.cpp
    src/bpf_integrity.cpp
    src/bpf_maps.cpp
    src/bpf_ops.cpp
    src/btf_loader.cpp
    src/crypto.cpp
    src/exec_identity.cpp
    src/event_dedup.cpp
    src/events.cpp
    src/hook_capabilities.cpp
    src/json_scan.cpp
    src/kernel_features.cpp
    src/network_ops.cpp
    src/otlp_exporter.cpp
    src/socket_api.cpp
    src/policy.cpp
    src/policy_parse.cpp
    src/policy_runtime.cpp
    src/seccomp.cpp
    src/landlock.cpp
    src/capabilities.cpp
    src/sha256.cpp
    src/tweetnacl.c
    src/utils.cpp
    src/selftest.cpp
    src/map_monitor.cpp
    src/proc_scan.cpp
    src/bpf_signing.cpp
    src/binary_hash.cpp
    src/rule_engine.cpp
    src/plugin.cpp
    src/k8s_identity.cpp
    src/ocsf_formatter.cpp
    src/cef_formatter.cpp
)

set(AEGIS_HEADERS
    src/binary_scan.hpp
    src/cli_bpf.hpp
    src/cli_cgroup.hpp
    src/cli_common.hpp
    src/cli_dispatch.hpp
    src/cli_network.hpp
    src/cli_policy.hpp
    src/cli_run.hpp
    src/commands_block_allow.hpp
    src/commands_cgroup.hpp
    src/commands_emergency.hpp
    src/commands_explain.hpp
    src/commands_health.hpp
    src/commands_keys_survival.hpp
    src/commands_metrics.hpp
    src/commands_monitoring.hpp
    src/commands_network.hpp
    src/commands_policy.hpp
    src/commands_probe.hpp
    src/commands_simulate.hpp
    src/commands.hpp
    src/control.hpp
    src/daemon.hpp
    src/daemon_policy_gate.hpp
    src/daemon_posture.hpp
    src/daemon_runtime.hpp
    src/daemon_test_hooks.hpp
    src/bpf_attach.hpp
    src/bpf_config.hpp
    src/bpf_link_pin.hpp
    src/bpf_integrity.hpp
    src/bpf_maps.hpp
    src/bpf_ops.hpp
    src/btf_loader.hpp
    src/crypto.hpp
    src/exec_identity.hpp
    src/event_dedup.hpp
    src/events.hpp
    src/hook_capabilities.hpp
    src/json_scan.hpp
    src/kernel_features.hpp
    src/logging.hpp
    src/network_ops.hpp
    src/policy.hpp
    src/policy_parse.hpp
    src/policy_runtime.hpp
    src/result.hpp
    src/seccomp.hpp
    src/landlock.hpp
    src/capabilities.hpp
    src/sha256.hpp
    src/ocsf_formatter.hpp
    src/cef_formatter.hpp
    src/tracing.hpp
    src/tweetnacl.h
    src/types.hpp
    src/utils.hpp
    src/selftest.hpp
    src/map_monitor.hpp
    src/proc_scan.hpp
    src/bpf_signing.hpp
    src/binary_hash.hpp
    src/rule_engine.hpp
    src/plugin.hpp
    src/k8s_identity.hpp
)

# Portable glibc compat shims (weak stubs for __isoc23_*, arc4random,
# _dl_find_object) so the binary runs on glibc < 2.38.
set(GLIBC_COMPAT_SOURCES "")
if(PORTABLE_GLIBC)
    set(GLIBC_COMPAT_SOURCES src/glibc_compat.c)
endif()

# Build main executable
if(NOT SKIP_BPF_BUILD)
    add_executable(aegisbpf ${AEGIS_SOURCES} ${AEGIS_HEADERS} ${SKELETON_HEADER} ${GLIBC_COMPAT_SOURCES})
    add_dependencies(aegisbpf bpf_skel)
else()
    add_executable(aegisbpf ${AEGIS_SOURCES} ${AEGIS_HEADERS} ${GLIBC_COMPAT_SOURCES})
endif()

target_include_directories(aegisbpf PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_directories(aegisbpf PRIVATE ${LIBBPF_LIBRARY_DIRS})
find_package(ZLIB REQUIRED)
# Same self-contained-fuzzer rationale as libelf above: link zlib statically for
# fuzz builds (libbpf and libelf both need it); production keeps shared zlib.
if(ENABLE_FUZZING)
    find_library(AEGIS_LIBZ_A NAMES libz.a)
    if(AEGIS_LIBZ_A)
        set(AEGIS_ZLIB_LIB ${AEGIS_LIBZ_A})
    else()
        set(AEGIS_ZLIB_LIB -l:libz.a)
    endif()
else()
    set(AEGIS_ZLIB_LIB ZLIB::ZLIB)
endif()
target_link_libraries(aegisbpf PRIVATE ${LIBBPF_LIBRARIES} ${AEGIS_ZLIB_LIB})

# Static libstdc++/libgcc for portable binary packages.
# Eliminates GLIBCXX version dependencies so the binary runs on
# older distros (Debian 12) even when built on Ubuntu 24.04.
# libelf and zlib stay dynamic — the target system's versions are
# compatible with its own glibc, avoiding the __isoc23_* problem
# that arises when static-linking Ubuntu 24.04's pre-compiled .a files.
option(STATIC_STDCXX "Statically link libstdc++ and libgcc" OFF)
if(STATIC_STDCXX)
    target_link_options(aegisbpf PRIVATE -static-libstdc++ -static-libgcc)
endif()

# Systemd integration (optional)
if (SYSTEMD_FOUND)
    target_compile_definitions(aegisbpf PRIVATE HAVE_SYSTEMD)
    target_include_directories(aegisbpf PRIVATE ${SYSTEMD_INCLUDE_DIRS})
    target_link_directories(aegisbpf PRIVATE ${SYSTEMD_LIBRARY_DIRS})
    target_link_libraries(aegisbpf PRIVATE ${SYSTEMD_LIBRARIES})
endif()

set(AEGIS_BPF_OBJ_DEFINE_PATH "${BPF_OBJECT}" CACHE STRING
    "Path embedded into binaries for default BPF object lookup")
if(ENABLE_SIGKILL_ENFORCEMENT)
    set(AEGIS_SIGKILL_ENFORCEMENT_DEFINE 1)
else()
    set(AEGIS_SIGKILL_ENFORCEMENT_DEFINE 0)
endif()

target_compile_definitions(aegisbpf PRIVATE
    AEGIS_BPF_OBJ_PATH="${AEGIS_BPF_OBJ_DEFINE_PATH}"
    AEGIS_ENABLE_SIGKILL_ENFORCEMENT=${AEGIS_SIGKILL_ENFORCEMENT_DEFINE}
    AEGIS_VERSION_STRING="${PROJECT_VERSION}"
)

# Build library for testing (without main)
set(AEGIS_LIB_SOURCES
    src/binary_scan.cpp
    src/commands_block_allow.cpp
    src/commands_cgroup.cpp
    src/commands_emergency.cpp
    src/commands_explain.cpp
    src/commands_health.cpp
    src/commands_network.cpp
    src/commands_policy.cpp
    src/commands_probe.cpp
    src/commands_simulate.cpp
    src/commands_metrics.cpp
    src/commands_keys_survival.cpp
    src/commands_monitoring.cpp
    src/control.cpp
    src/daemon.cpp
    src/daemon_policy_gate.cpp
    src/daemon_posture.cpp
    src/daemon_runtime.cpp
    src/bpf_attach.cpp
    src/bpf_config.cpp
    src/bpf_link_pin.cpp
    src/bpf_integrity.cpp
    src/bpf_maps.cpp
    src/bpf_ops.cpp
    src/btf_loader.cpp
    src/crypto.cpp
    src/exec_identity.cpp
    src/event_dedup.cpp
    src/events.cpp
    src/hook_capabilities.cpp
    src/json_scan.cpp
    src/kernel_features.cpp
    src/network_ops.cpp
    src/otlp_exporter.cpp
    src/socket_api.cpp
    src/policy.cpp
    src/policy_parse.cpp
    src/policy_runtime.cpp
    src/seccomp.cpp
    src/landlock.cpp
    src/capabilities.cpp
    src/sha256.cpp
    src/tweetnacl.c
    src/utils.cpp
    src/selftest.cpp
    src/map_monitor.cpp
    src/proc_scan.cpp
    src/bpf_signing.cpp
    src/binary_hash.cpp
    src/rule_engine.cpp
    src/plugin.cpp
    src/k8s_identity.cpp
    src/ocsf_formatter.cpp
    src/cef_formatter.cpp
)

add_library(aegisbpf_lib STATIC ${AEGIS_LIB_SOURCES} ${AEGIS_HEADERS})
target_include_directories(aegisbpf_lib PUBLIC
    ${LIBBPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_directories(aegisbpf_lib PUBLIC ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(aegisbpf_lib PUBLIC ${LIBBPF_LIBRARIES} ${AEGIS_ZLIB_LIB})
target_compile_definitions(aegisbpf_lib PRIVATE AEGIS_BPF_OBJ_PATH="${AEGIS_BPF_OBJ_DEFINE_PATH}")
target_compile_definitions(aegisbpf_lib PUBLIC AEGIS_ENABLE_SIGKILL_ENFORCEMENT=${AEGIS_SIGKILL_ENFORCEMENT_DEFINE})
target_compile_definitions(aegisbpf_lib PUBLIC AEGIS_VERSION_STRING="${PROJECT_VERSION}")

if (SYSTEMD_FOUND)
    target_compile_definitions(aegisbpf_lib PRIVATE HAVE_SYSTEMD)
    target_include_directories(aegisbpf_lib PUBLIC ${SYSTEMD_INCLUDE_DIRS})
    target_link_directories(aegisbpf_lib PUBLIC ${SYSTEMD_LIBRARY_DIRS})
    target_link_libraries(aegisbpf_lib PUBLIC ${SYSTEMD_LIBRARIES})
endif()

# Testing
if(BUILD_TESTING)
    enable_testing()
    include(FetchContent)

    # Try to use system googletest first
    find_package(GTest QUIET)

    if(NOT GTest_FOUND)
        message(STATUS "System GTest not found, using FetchContent")
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
            URL_HASH SHA256=8ad598c73ad796e0d8280b082cebd82a630d73e73cd3c70057938a6501bba5d7
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
            TIMEOUT 30
        )
        # For Windows: Prevent overriding the parent project's compiler/linker settings
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    else()
        message(STATUS "Using system GTest")
    endif()

    # Test sources
    set(TEST_SOURCES
        tests/test_main.cpp
        tests/test_logging.cpp
        tests/test_bpf_config.cpp
        tests/test_bpf_state.cpp
        tests/test_commands.cpp
        tests/test_crash_policy.cpp
        tests/test_crypto_safe.cpp
        tests/test_exec_identity.cpp
        tests/test_policy_golden.cpp
        tests/test_kernel_features.cpp
        tests/test_utils.cpp
        tests/test_result.cpp
        tests/test_sha256.cpp
        tests/test_policy.cpp
        tests/test_network.cpp
        tests/test_json_scan.cpp
        tests/test_metrics.cpp
        tests/test_bpf_integrity.cpp
        tests/test_bpf_signing.cpp
        tests/test_tracing.cpp
        tests/test_rule_engine.cpp
        tests/test_landlock_sandbox.cpp
        tests/test_capabilities.cpp
        tests/test_ocsf_formatter.cpp
        tests/test_cef_formatter.cpp
        tests/test_bpf_link_pin.cpp
        tests/test_btf_loader.cpp
        tests/test_hook_capabilities.cpp
        tests/test_commands_simulate.cpp
        tests/test_event_dedup.cpp
        tests/test_net_block_event_dedup.cpp
        tests/test_posture_gate.cpp
    )

    add_executable(aegisbpf_test ${TEST_SOURCES})
    target_link_libraries(aegisbpf_test PRIVATE
        aegisbpf_lib
        GTest::gtest
        GTest::gtest_main
    )
    target_include_directories(aegisbpf_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    include(GoogleTest)
    gtest_discover_tests(aegisbpf_test DISCOVERY_MODE PRE_TEST)

    # BPF_PROG_RUN kernel-side tests (require BPF object + root/CAP_BPF)
    if(NOT SKIP_BPF_BUILD)
        add_executable(aegisbpf_bpf_test tests/bpf/test_bpf_prog_run.cpp)
        target_link_libraries(aegisbpf_bpf_test PRIVATE
            ${LIBBPF_LIBRARIES}
            GTest::gtest
            GTest::gtest_main
        )
        target_include_directories(aegisbpf_bpf_test PRIVATE
            ${LIBBPF_INCLUDE_DIRS}
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        target_link_directories(aegisbpf_bpf_test PRIVATE ${LIBBPF_LIBRARY_DIRS})
        target_compile_definitions(aegisbpf_bpf_test PRIVATE
            AEGIS_BPF_OBJ_PATH="${BPF_OBJECT}"
        )
        add_dependencies(aegisbpf_bpf_test bpf_skel)

        # These tests require root and a BPF-capable kernel, so don't auto-discover
        # them into the default ctest run. They run in the kernel-matrix CI job.
        add_test(
            NAME bpf_prog_run
            COMMAND aegisbpf_bpf_test
        )
        set_tests_properties(bpf_prog_run PROPERTIES
            LABELS "bpf;kernel"
            ENVIRONMENT "AEGIS_BPF_OBJ_TEST_PATH=${BPF_OBJECT}"
        )
    endif()

    # E2E bypass tests (require root)
    add_executable(aegisbpf_bypass_test tests/e2e/test_bypasses.cpp)
    target_link_libraries(aegisbpf_bypass_test PRIVATE
        aegisbpf_lib
        GTest::gtest
        GTest::gtest_main
    )
    target_include_directories(aegisbpf_bypass_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    # Benchmark tests (optional, for performance regression)
    if(BUILD_BENCHMARKS)
        # Try to use system googlebenchmark first
        find_package(benchmark QUIET)

        if(NOT benchmark_FOUND)
            message(STATUS "System benchmark not found, using FetchContent")
            FetchContent_Declare(
                googlebenchmark
                URL https://github.com/google/benchmark/archive/refs/tags/v1.8.3.tar.gz
                URL_HASH SHA256=6bc180a57d23d4d9515519f92b0c83d61b05b5bab188961f36ac7b06b0d9e9ce
                DOWNLOAD_EXTRACT_TIMESTAMP TRUE
                TIMEOUT 30
            )
            set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
            FetchContent_MakeAvailable(googlebenchmark)

            # Remove googlebenchmark's .clang-tidy file which has outdated options
            # that conflict with newer clang-tidy versions
            file(REMOVE "${googlebenchmark_SOURCE_DIR}/.clang-tidy")
        else()
            message(STATUS "Using system benchmark")
        endif()

        add_executable(aegisbpf_bench tests/bench_policy.cpp)
        target_link_libraries(aegisbpf_bench PRIVATE
            aegisbpf_lib
            benchmark::benchmark
        )
        target_include_directories(aegisbpf_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

        # Syscall-level benchmarks (require root + BPF LSM)
        add_executable(aegisbpf_bench_syscall tests/bench_syscall.cpp)
        target_link_libraries(aegisbpf_bench_syscall PRIVATE
            aegisbpf_lib
            benchmark::benchmark
        )
        target_include_directories(aegisbpf_bench_syscall PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    endif()

    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(
        NAME event_schema
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_event_schema.py
            --schema ${CMAKE_CURRENT_SOURCE_DIR}/config/event-schema.json
            --samples ${CMAKE_CURRENT_SOURCE_DIR}/tests/event_samples
    )

    add_test(
        NAME systemd_policy_prestart_fails_closed
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_systemd_policy_prestart.py
            ${CMAKE_CURRENT_SOURCE_DIR}/packaging/systemd/aegisbpf.service
    )

    add_test(
        NAME metrics_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_metrics_contract.py
            ${CMAKE_CURRENT_SOURCE_DIR}/src/commands_metrics.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/config/prometheus/alerts.yml
            ${CMAKE_CURRENT_SOURCE_DIR}/config/grafana/dashboard.json
            ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/aegisbpf.1.md
    )

    add_test(
        NAME slo_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_slo_contract.py
            ${CMAKE_CURRENT_SOURCE_DIR}/config/prometheus/alerts.yml
            ${CMAKE_CURRENT_SOURCE_DIR}/docs/PRODUCT.md
    )

    add_test(
        NAME upgrade_compat_n_minus_1
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_upgrade_compat.py
            $<TARGET_FILE:aegisbpf>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/upgrade/policy_v1.conf
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/upgrade/policy_v2.conf
    )

    add_test(
        NAME support_policy_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_support_policy.py
            ${CMAKE_CURRENT_SOURCE_DIR}/docs/SUPPORT_POLICY.md
    )

    add_test(
        NAME vendored_dependency_contract
        COMMAND ${BASH} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_vendored_dependencies.sh
            ${CMAKE_CURRENT_SOURCE_DIR}/config/vendored_deps.json
    )

    add_test(
        NAME feature_surface_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_feature_surface_contract.py
    )

    add_test(
        NAME bpf_map_schema_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_bpf_map_schema.py
    )
    set_tests_properties(bpf_map_schema_contract PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_test(
        NAME failure_modes_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_failure_modes_contract.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_policy.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_commands.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_metrics.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_tracing.cpp
    )


    add_test(
        NAME capability_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/validate_capability_contract.py
            ${CMAKE_CURRENT_SOURCE_DIR}/SECURITY.md
            ${CMAKE_CURRENT_SOURCE_DIR}/packaging/systemd/aegisbpf.service
    )


    add_test(
        NAME runbooks_contract
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_runbooks_contract.py
            ${CMAKE_CURRENT_SOURCE_DIR}/docs/runbooks
    )

    # CLI parser regressions (should fail before any privileged/BPF operations)
    add_test(
        NAME cli_network_deny_rejects_multiple_selectors
        COMMAND $<TARGET_FILE:aegisbpf> network deny add --ip 192.168.1.1 --cidr 10.0.0.0/8
    )
    set_tests_properties(cli_network_deny_rejects_multiple_selectors PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_network_deny_rejects_port_zero
        COMMAND $<TARGET_FILE:aegisbpf> network deny add --port 0
    )
    set_tests_properties(cli_network_deny_rejects_port_zero PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_network_deny_rejects_bad_protocol
        COMMAND $<TARGET_FILE:aegisbpf> network deny add --port 443 --protocol invalid
    )
    set_tests_properties(cli_network_deny_rejects_bad_protocol PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_network_deny_del_rejects_bad_direction
        COMMAND $<TARGET_FILE:aegisbpf> network deny del --port 443 --direction invalid
    )
    set_tests_properties(cli_network_deny_del_rejects_bad_direction PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_policy_apply_rejects_conflicting_hash_flags
        COMMAND $<TARGET_FILE:aegisbpf> policy apply /tmp/policy.conf --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef --sha256-file /tmp/policy.sha256
    )
    set_tests_properties(cli_policy_apply_rejects_conflicting_hash_flags PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_metrics_rejects_unknown_flag
        COMMAND $<TARGET_FILE:aegisbpf> metrics --invalid
    )
    set_tests_properties(cli_metrics_rejects_unknown_flag PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_health_rejects_extra_args
        COMMAND $<TARGET_FILE:aegisbpf> health unexpected
    )
    set_tests_properties(cli_health_rejects_extra_args PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_health_json_rejects_unknown_flag
        COMMAND $<TARGET_FILE:aegisbpf> health --json --unknown
    )
    set_tests_properties(cli_health_json_rejects_unknown_flag PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_run_rejects_invalid_enforce_signal
        COMMAND $<TARGET_FILE:aegisbpf> run --enforce --enforce-signal=bad
    )
    set_tests_properties(cli_run_rejects_invalid_enforce_signal PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_run_rejects_invalid_enforce_fallback
        COMMAND $<TARGET_FILE:aegisbpf> run --enforce --enforce-fallback=bogus
    )
    set_tests_properties(cli_run_rejects_invalid_enforce_fallback PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_run_rejects_sigkill_without_allow_gate
        COMMAND $<TARGET_FILE:aegisbpf> run --enforce --enforce-signal=kill
    )
    set_tests_properties(cli_run_rejects_sigkill_without_allow_gate PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_run_rejects_zero_kill_escalation_threshold
        COMMAND $<TARGET_FILE:aegisbpf> run --enforce --kill-escalation-threshold=0
    )
    set_tests_properties(cli_run_rejects_zero_kill_escalation_threshold PROPERTIES WILL_FAIL TRUE)

    add_test(
        NAME cli_run_rejects_zero_kill_escalation_window
        COMMAND $<TARGET_FILE:aegisbpf> run --enforce --kill-escalation-window-seconds=0
    )
    set_tests_properties(cli_run_rejects_zero_kill_escalation_window PROPERTIES WILL_FAIL TRUE)
endif()

# Fuzzing targets
if(ENABLE_FUZZING)
    message(STATUS "Building fuzzing targets")

    # libFuzzer harness name -> source mapping (flat pairs for list(POP_FRONT)).
    set(AEGIS_FUZZ_TARGETS
        fuzz_policy  tests/fuzz/fuzz_policy_parser.cpp
        fuzz_bundle  tests/fuzz/fuzz_signed_bundle.cpp
        fuzz_network tests/fuzz/fuzz_network_rules.cpp
        fuzz_path    tests/fuzz/fuzz_path_validation.cpp
        fuzz_event   tests/fuzz/fuzz_event_handling.cpp
    )

    # OSS-Fuzz / ClusterFuzzLite inject the fuzzing engine and sanitizers via
    # $LIB_FUZZING_ENGINE + $CFLAGS/$CXXFLAGS. When that is present we must NOT
    # hardcode -fsanitize=fuzzer,address (it conflicts with their toolchain);
    # for local/standalone builds we wire libFuzzer + ASan ourselves.
    set(AEGIS_FUZZ_ENGINE "$ENV{LIB_FUZZING_ENGINE}")

    while(AEGIS_FUZZ_TARGETS)
        list(POP_FRONT AEGIS_FUZZ_TARGETS _fuzz_name _fuzz_src)
        add_executable(${_fuzz_name} ${_fuzz_src})
        target_link_libraries(${_fuzz_name} PRIVATE aegisbpf_lib)
        target_include_directories(${_fuzz_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_compile_options(${_fuzz_name} PRIVATE -fno-omit-frame-pointer)
        if(AEGIS_FUZZ_ENGINE)
            # Engine + sanitizer supplied by the OSS-Fuzz/CFLite environment.
            target_link_options(${_fuzz_name} PRIVATE ${AEGIS_FUZZ_ENGINE})
        else()
            target_compile_options(${_fuzz_name} PRIVATE -fsanitize=fuzzer,address)
            target_link_options(${_fuzz_name} PRIVATE -fsanitize=fuzzer,address)
        endif()
    endwhile()
endif()

# Optional post-2024 BPF stack prototype (BPF arena, sched_ext, ...).
# Gated off by default; see prototype/aegis-next/README.md.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/prototype/aegis-next/CMakeLists.txt")
    add_subdirectory(prototype/aegis-next)
endif()

# Installation
install(TARGETS aegisbpf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(NOT SKIP_BPF_BUILD)
    install(FILES ${BPF_OBJECT} DESTINATION ${CMAKE_INSTALL_LIBDIR}/aegisbpf)
    install(FILES ${BPF_HASH_FILE} DESTINATION ${CMAKE_INSTALL_LIBDIR}/aegisbpf RENAME aegis.bpf.sha256)
endif()
install(FILES packaging/systemd/aegisbpf.service DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)
install(FILES packaging/systemd/aegisbpf.env DESTINATION /etc/default RENAME aegisbpf)
install(FILES config/policy.example DESTINATION /etc/aegisbpf)

# CPack configuration
set(CPACK_PACKAGE_NAME "aegisbpf")
set(CPACK_PACKAGE_VENDOR "AegisBPF")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "AegisBPF runtime security agent")
set(CPACK_PACKAGE_DESCRIPTION
    "AegisBPF is an eBPF + LSM runtime security agent.\n\
It enforces deny / audit policy for file, exec, and network events on\n\
modern Linux kernels with BPF-LSM enabled. The daemon is managed via\n\
the bundled aegisbpf.service systemd unit and configured through\n\
/etc/default/aegisbpf and /etc/aegisbpf/policy.example.")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/ErenAri/Aegis-BPF")
set(CPACK_PACKAGE_CONTACT "AegisBPF maintainers <aegisbpf-maintainers@users.noreply.github.com>")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_SET_DESTDIR ON)
# Default CPack generator is TGZ; downstream callers (release tooling,
# CI packaging job, distro maintainers) override on the command line:
#   cpack -G DEB    # produces aegisbpf_<ver>_<arch>.deb
#   cpack -G RPM    # produces aegisbpf-<ver>-<rel>.<arch>.rpm
set(CPACK_GENERATOR "TGZ")

# --- Debian package metadata -------------------------------------------------
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "admin")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${CPACK_PACKAGE_HOMEPAGE_URL}")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
# Disable shlibdeps when libstdc++/libgcc are static — dpkg-shlibdeps
# misreports glibc version needs from the static archives.  With
# PORTABLE_GLIBC the remaining dynamic deps (libelf, zlib, libc) are
# declared manually above.
if(STATIC_STDCXX)
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
else()
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
endif()
# systemd is a Recommends, not a hard Depends, so the package can also be
# installed on minimal containers / non-systemd hosts (operators run the
# binary directly under their own supervisor in that case).
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "systemd")
if(STATIC_LIBBPF)
    # libelf and zlib are dynamic even with STATIC_STDCXX — they must be
    # present on the target system.
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libelf1t64 | libelf1, zlib1g, libc6")
else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libbpf1 | libbpf0, libelf1t64 | libelf1, libc6")
endif()
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/maintainer-scripts/postinst;\
${CMAKE_CURRENT_SOURCE_DIR}/packaging/maintainer-scripts/prerm;\
${CMAKE_CURRENT_SOURCE_DIR}/packaging/maintainer-scripts/postrm;\
${CMAKE_CURRENT_SOURCE_DIR}/packaging/maintainer-scripts/conffiles")

# --- RPM package metadata ----------------------------------------------------
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
# We install to absolute paths (/etc/default, /etc/aegisbpf, ...) so the
# package is non-relocatable; CPack defaults handle this correctly when
# CPACK_RPM_PACKAGE_RELOCATABLE is left unset.
set(CPACK_RPM_PACKAGE_URL "${CPACK_PACKAGE_HOMEPAGE_URL}")
set(CPACK_RPM_PACKAGE_VENDOR "${CPACK_PACKAGE_VENDOR}")
# CPack's RPM generator falls back to a placeholder if this is unset;
# pin the description explicitly so `rpm -qpi` shows real text.
set(CPACK_RPM_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
set(CPACK_RPM_PACKAGE_SUMMARY "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
if(STATIC_LIBBPF)
    set(CPACK_RPM_PACKAGE_REQUIRES "elfutils-libelf, zlib, glibc")
else()
    set(CPACK_RPM_PACKAGE_REQUIRES "libbpf, elfutils-libelf, glibc")
endif()
set(CPACK_RPM_PACKAGE_REQUIRES_POST "systemd")
set(CPACK_RPM_PACKAGE_REQUIRES_PREUN "systemd")
set(CPACK_RPM_PACKAGE_REQUIRES_POSTUN "systemd")
set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/maintainer-scripts/postinst")
set(CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/maintainer-scripts/prerm")
set(CPACK_RPM_POST_UNINSTALL_SCRIPT_FILE
    "${CMAKE_CURRENT_SOURCE_DIR}/packaging/maintainer-scripts/postrm")
# Strip is intentionally disabled so debug-info post-builders don't change
# the binary in a way that defeats reproducibility verification.
set(CPACK_RPM_SPEC_MORE_DEFINE "%global __brp_strip /bin/true\n%global __brp_strip_static_archive /bin/true")
# Keep RPM file ownership stable across staging directory variation.
set(CPACK_RPM_USER_FILELIST
    "%config(noreplace) /etc/default/aegisbpf"
    "%config(noreplace) /etc/aegisbpf/policy.example")
# /etc/aegisbpf is created by the install rule for policy.example; ensure
# /etc/default/aegisbpf is not flagged %ghost.
if(STATIC_STDCXX)
    set(CPACK_RPM_PACKAGE_AUTOREQPROV OFF)
else()
    set(CPACK_RPM_PACKAGE_AUTOREQPROV ON)
endif()

include(CPack)
