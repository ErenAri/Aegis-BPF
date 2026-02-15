cmake_minimum_required(VERSION 3.20)
project(aegisbpf VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(SYSTEMD QUIET libsystemd)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
    # Explicitly define NDEBUG to disable debug-only code paths (e.g., BPF verification bypass)
    add_definitions(-DNDEBUG)
endif()

# Security hardening flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now")

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
        DEPENDS ${BPF_SOURCE} ${VMLINUX_HEADER}
        VERBATIM
    )

    # Generate BPF skeleton header
    add_custom_command(
        OUTPUT ${SKELETON_HEADER}
        COMMAND ${BASH} -c "${BPFTOOL} gen skeleton ${BPF_OBJECT} > ${SKELETON_HEADER}"
        DEPENDS ${BPF_OBJECT}
        VERBATIM
    )

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
    src/cli_common.cpp
    src/cli_dispatch.cpp
    src/cli_network.cpp
    src/cli_policy.cpp
    src/cli_run.cpp
    src/commands_block_allow.cpp
    src/commands_network.cpp
    src/commands_policy.cpp
    src/commands_keys_survival.cpp
    src/commands_monitoring.cpp
    src/control.cpp
    src/daemon.cpp
    src/bpf_ops.cpp
    src/crypto.cpp
    src/exec_identity.cpp
    src/events.cpp
    src/kernel_features.cpp
    src/network_ops.cpp
    src/policy.cpp
    src/seccomp.cpp
    src/sha256.cpp
    src/tweetnacl.c
    src/utils.cpp
)

set(AEGIS_HEADERS
    src/binary_scan.hpp
    src/cli_common.hpp
    src/cli_dispatch.hpp
    src/cli_network.hpp
    src/cli_policy.hpp
    src/cli_run.hpp
    src/commands_block_allow.hpp
    src/commands_keys_survival.hpp
    src/commands_monitoring.hpp
    src/commands_network.hpp
    src/commands_policy.hpp
    src/commands.hpp
    src/control.hpp
    src/daemon.hpp
    src/daemon_test_hooks.hpp
    src/bpf_ops.hpp
    src/crypto.hpp
    src/exec_identity.hpp
    src/events.hpp
    src/kernel_features.hpp
    src/logging.hpp
    src/network_ops.hpp
    src/policy.hpp
    src/result.hpp
    src/seccomp.hpp
    src/sha256.hpp
    src/tracing.hpp
    src/tweetnacl.h
    src/types.hpp
    src/utils.hpp
)

# Build main executable
if(NOT SKIP_BPF_BUILD)
    add_executable(aegisbpf ${AEGIS_SOURCES} ${AEGIS_HEADERS} ${SKELETON_HEADER})
    add_dependencies(aegisbpf bpf_skel)
else()
    add_executable(aegisbpf ${AEGIS_SOURCES} ${AEGIS_HEADERS})
endif()

target_include_directories(aegisbpf PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_directories(aegisbpf PRIVATE ${LIBBPF_LIBRARY_DIRS})
find_package(ZLIB REQUIRED)
target_link_libraries(aegisbpf PRIVATE ${LIBBPF_LIBRARIES} ZLIB::ZLIB)

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
)

# Build library for testing (without main)
set(AEGIS_LIB_SOURCES
    src/binary_scan.cpp
    src/commands_block_allow.cpp
    src/commands_network.cpp
    src/commands_policy.cpp
    src/commands_keys_survival.cpp
    src/commands_monitoring.cpp
    src/control.cpp
    src/daemon.cpp
    src/bpf_ops.cpp
    src/crypto.cpp
    src/exec_identity.cpp
    src/events.cpp
    src/kernel_features.cpp
    src/network_ops.cpp
    src/policy.cpp
    src/seccomp.cpp
    src/sha256.cpp
    src/tweetnacl.c
    src/utils.cpp
)

add_library(aegisbpf_lib STATIC ${AEGIS_LIB_SOURCES} ${AEGIS_HEADERS})
target_include_directories(aegisbpf_lib PUBLIC
    ${LIBBPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_directories(aegisbpf_lib PUBLIC ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(aegisbpf_lib PUBLIC ${LIBBPF_LIBRARIES} ZLIB::ZLIB)
target_compile_definitions(aegisbpf_lib PRIVATE AEGIS_BPF_OBJ_PATH="${AEGIS_BPF_OBJ_DEFINE_PATH}")
target_compile_definitions(aegisbpf_lib PUBLIC AEGIS_ENABLE_SIGKILL_ENFORCEMENT=${AEGIS_SIGKILL_ENFORCEMENT_DEFINE})

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
        tests/test_metrics.cpp
        tests/test_bpf_integrity.cpp
        tests/test_tracing.cpp
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
            ${CMAKE_CURRENT_SOURCE_DIR}/src/commands_monitoring.cpp
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

    # Policy parser fuzzer
    add_executable(fuzz_policy tests/fuzz/fuzz_policy_parser.cpp)
    target_link_libraries(fuzz_policy PRIVATE aegisbpf_lib)
    target_include_directories(fuzz_policy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_options(fuzz_policy PRIVATE -fsanitize=fuzzer,address -fno-omit-frame-pointer)
    target_link_options(fuzz_policy PRIVATE -fsanitize=fuzzer,address)

    # Signed bundle parser fuzzer
    add_executable(fuzz_bundle tests/fuzz/fuzz_signed_bundle.cpp)
    target_link_libraries(fuzz_bundle PRIVATE aegisbpf_lib)
    target_include_directories(fuzz_bundle PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_options(fuzz_bundle PRIVATE -fsanitize=fuzzer,address -fno-omit-frame-pointer)
    target_link_options(fuzz_bundle PRIVATE -fsanitize=fuzzer,address)

    # Network rules fuzzer
    add_executable(fuzz_network tests/fuzz/fuzz_network_rules.cpp)
    target_link_libraries(fuzz_network PRIVATE aegisbpf_lib)
    target_include_directories(fuzz_network PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_options(fuzz_network PRIVATE -fsanitize=fuzzer,address -fno-omit-frame-pointer)
    target_link_options(fuzz_network PRIVATE -fsanitize=fuzzer,address)

    # Path validation fuzzer
    add_executable(fuzz_path tests/fuzz/fuzz_path_validation.cpp)
    target_link_libraries(fuzz_path PRIVATE aegisbpf_lib)
    target_include_directories(fuzz_path PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_options(fuzz_path PRIVATE -fsanitize=fuzzer,address -fno-omit-frame-pointer)
    target_link_options(fuzz_path PRIVATE -fsanitize=fuzzer,address)

    # Event handling fuzzer
    add_executable(fuzz_event tests/fuzz/fuzz_event_handling.cpp)
    target_link_libraries(fuzz_event PRIVATE aegisbpf_lib)
    target_include_directories(fuzz_event PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_compile_options(fuzz_event PRIVATE -fsanitize=fuzzer,address -fno-omit-frame-pointer)
    target_link_options(fuzz_event PRIVATE -fsanitize=fuzzer,address)
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
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_CONTACT "aegisbpf@localhost")
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_SET_DESTDIR ON)
set(CPACK_GENERATOR "TGZ")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libbpf1 | libbpf0")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_REQUIRES "libbpf")
set(CPACK_RPM_SPEC_MORE_DEFINE "%global __brp_strip /bin/true\n%global __brp_strip_static_archive /bin/true")
include(CPack)
