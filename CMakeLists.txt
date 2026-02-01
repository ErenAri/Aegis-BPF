cmake_minimum_required(VERSION 3.20)
project(aegisbpf VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

# Build options
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(BUILD_TESTING "Build tests" ON)

find_program(CLANG clang REQUIRED)
find_program(BPFTOOL bpftool REQUIRED)
find_program(BASH bash REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(SYSTEMD QUIET libsystemd)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
endif()

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

# Userspace source files
set(AEGIS_SOURCES
    src/main.cpp
    src/bpf_ops.cpp
    src/events.cpp
    src/policy.cpp
    src/seccomp.cpp
    src/sha256.cpp
    src/utils.cpp
)

set(AEGIS_HEADERS
    src/bpf_ops.hpp
    src/events.hpp
    src/logging.hpp
    src/policy.hpp
    src/result.hpp
    src/seccomp.hpp
    src/sha256.hpp
    src/types.hpp
    src/utils.hpp
)

# Build main executable
add_executable(aegisbpf ${AEGIS_SOURCES} ${AEGIS_HEADERS} ${SKELETON_HEADER})
add_dependencies(aegisbpf bpf_skel)

target_include_directories(aegisbpf PRIVATE
    ${LIBBPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_directories(aegisbpf PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(aegisbpf PRIVATE ${LIBBPF_LIBRARIES})

# Systemd integration (optional)
if (SYSTEMD_FOUND)
    target_compile_definitions(aegisbpf PRIVATE HAVE_SYSTEMD)
    target_include_directories(aegisbpf PRIVATE ${SYSTEMD_INCLUDE_DIRS})
    target_link_directories(aegisbpf PRIVATE ${SYSTEMD_LIBRARY_DIRS})
    target_link_libraries(aegisbpf PRIVATE ${SYSTEMD_LIBRARIES})
endif()

target_compile_definitions(aegisbpf PRIVATE AEGIS_BPF_OBJ_PATH="${BPF_OBJECT}")

# Build library for testing (without main)
set(AEGIS_LIB_SOURCES
    src/bpf_ops.cpp
    src/events.cpp
    src/policy.cpp
    src/seccomp.cpp
    src/sha256.cpp
    src/utils.cpp
)

add_library(aegisbpf_lib STATIC ${AEGIS_LIB_SOURCES} ${AEGIS_HEADERS})
target_include_directories(aegisbpf_lib PUBLIC
    ${LIBBPF_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_directories(aegisbpf_lib PUBLIC ${LIBBPF_LIBRARY_DIRS})
target_link_libraries(aegisbpf_lib PUBLIC ${LIBBPF_LIBRARIES})
target_compile_definitions(aegisbpf_lib PRIVATE AEGIS_BPF_OBJ_PATH="${BPF_OBJECT}")

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

    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    # Test sources
    set(TEST_SOURCES
        tests/test_main.cpp
        tests/test_utils.cpp
        tests/test_result.cpp
        tests/test_sha256.cpp
        tests/test_policy.cpp
    )

    add_executable(aegisbpf_test ${TEST_SOURCES})
    target_link_libraries(aegisbpf_test PRIVATE
        aegisbpf_lib
        GTest::gtest
        GTest::gtest_main
    )
    target_include_directories(aegisbpf_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    include(GoogleTest)
    gtest_discover_tests(aegisbpf_test)

    # Benchmark tests (optional, for performance regression)
    FetchContent_Declare(
        googlebenchmark
        URL https://github.com/google/benchmark/archive/refs/tags/v1.8.3.tar.gz
    )
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googlebenchmark)

    add_executable(aegisbpf_bench tests/bench_policy.cpp)
    target_link_libraries(aegisbpf_bench PRIVATE
        aegisbpf_lib
        benchmark::benchmark
    )
    target_include_directories(aegisbpf_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()

# Installation
install(TARGETS aegisbpf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${BPF_OBJECT} DESTINATION ${CMAKE_INSTALL_LIBDIR}/aegisbpf)
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
set(CPACK_GENERATOR "TGZ")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libbpf1 | libbpf0")
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_REQUIRES "libbpf")
set(CPACK_RPM_SPEC_MORE_DEFINE "%global __brp_strip /bin/true\n%global __brp_strip_static_archive /bin/true")
include(CPack)
