cmake_minimum_required(VERSION 3.13)
project(tinybrother C)

set(CMAKE_C_STANDARD 11)

find_program(CLANG_EXECUTABLE clang REQUIRED)
find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)

set(BPF_SRC_DIR ${CMAKE_SOURCE_DIR}/src/bpf)
set(INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)
set(BUILD_DIR_BPF ${CMAKE_BINARY_DIR}/buildbpf)
file(MAKE_DIRECTORY ${BUILD_DIR_BPF})

file(GLOB BPF_SOURCES ${BPF_SRC_DIR}/*.bpf.c)

set(BPF_OBJECTS)
set(BPF_SKELS)

foreach(SRC_FILE ${BPF_SOURCES})
    get_filename_component(FILE_NAME_WE ${SRC_FILE} NAME_WE)
    set(OBJ_FILE ${BUILD_DIR_BPF}/${FILE_NAME_WE}.bpf.o)
    set(SKEL_FILE ${BUILD_DIR_BPF}/${FILE_NAME_WE}_bpf.skel.h)

    add_custom_command(
        OUTPUT ${OBJ_FILE}
        COMMAND ${CLANG_EXECUTABLE}
                -target bpf
                -O2 -g
                -I${INCLUDE_DIRS}
                -c ${SRC_FILE}
                -o ${OBJ_FILE}
        DEPENDS ${SRC_FILE}
        COMMENT "Compiling ${SRC_FILE} to ${OBJ_FILE}"
    )

    add_custom_command(
        OUTPUT ${SKEL_FILE}
        COMMAND ${BPFTOOL_EXECUTABLE} gen skeleton ${OBJ_FILE} > ${SKEL_FILE}
        DEPENDS ${OBJ_FILE}
        COMMENT "Generating skeleton ${SKEL_FILE}"
    )

    list(APPEND BPF_OBJECTS ${OBJ_FILE})
    list(APPEND BPF_SKELS ${SKEL_FILE})
endforeach()

add_custom_target(bpf ALL DEPENDS ${BPF_OBJECTS} ${BPF_SKELS})

# === USER PROGRAM ===
set(BUILD_DIR_USER ${CMAKE_BINARY_DIR}/build)
file(MAKE_DIRECTORY ${BUILD_DIR_USER})

file(GLOB USER_SOURCES ${CMAKE_SOURCE_DIR}/src/user/*.c)

add_executable(tinybrother ${USER_SOURCES})

target_include_directories(tinybrother PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${BUILD_DIR_BPF}  # Pour accéder aux .skel.h
)

set_target_properties(tinybrother PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR_USER}
)

add_dependencies(tinybrother bpf)

# Trouver et lier libbpf
find_library(LIBBPF_LIB bpf REQUIRED)
target_link_libraries(tinybrother PRIVATE ${LIBBPF_LIB})

# === INSTALL & UNINSTALL===
# Path to install BPF objects
# === INSTALL ALL .bpf.o WITH AUTOATTACH ===
set(BPF_INSTALL_DIR ${BUILD_DIR_BPF} CACHE PATH "Local install path for BPF object files")

set(BPF_PIN_DIR /sys/fs/bpf/ CACHE PATH "bpffs path where programs are pinned")

add_custom_target(install_bpf
    COMMENT "Installing and auto-attaching all BPF programs (*.bpf.o)"
)

foreach(OBJ_FILE ${BPF_OBJECTS})
    get_filename_component(OBJ_NAME ${OBJ_FILE} NAME_WE)  # sans extension
    set(INSTALL_PATH ${BPF_INSTALL_DIR}/${OBJ_NAME}.bpf.o)
    set(PIN_PATH ${BPF_PIN_DIR}/${OBJ_NAME})

    add_custom_command(TARGET install_bpf POST_BUILD
        COMMAND ${BPFTOOL_EXECUTABLE} prog load ${INSTALL_PATH} ${PIN_PATH} autoattach
        COMMENT "Installing and auto-attaching ${OBJ_NAME}.bpf.o to ${PIN_PATH}"
        VERBATIM
    )
endforeach()

