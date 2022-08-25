cmake_minimum_required(VERSION 3.13 FATAL_ERROR)

project(arch_ebpf)

if((NOT BN_API_PATH) AND (NOT BN_INTERNAL_BUILD))
	set(BN_API_PATH $ENV{BN_API_PATH})
	if(NOT BN_API_PATH)
		message(FATAL_ERROR "Provide path to Binary Ninja API source in BN_API_PATH")
	endif()
endif()
if(NOT BN_INTERNAL_BUILD)
	add_subdirectory(${BN_API_PATH} ${PROJECT_BINARY_DIR}/api)
endif()

file(GLOB SOURCES
	arch_ebpf.cpp
	disassembler.cpp
	il.cpp
	*.h
)

if(DEMO)
	add_library(arch_ebpf STATIC ${SOURCES})
else()
	add_library(arch_ebpf SHARED ${SOURCES})
endif()

set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE INTERNAL "disable arch by default" FORCE)
set(CAPSTONE_BPF_SUPPORT ON CACHE INTERNAL "enable BPF only" FORCE)
add_subdirectory(${PROJECT_SOURCE_DIR}/capstone)

target_link_libraries(arch_ebpf binaryninjaapi capstone)

set_target_properties(arch_ebpf PROPERTIES
	CXX_STANDARD 17
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)

if(BN_INTERNAL_BUILD)
	plugin_rpath(arch_ebpf)
	set_target_properties(arch_ebpf PROPERTIES
		LIBRARY_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR}
		RUNTIME_OUTPUT_DIRECTORY ${BN_CORE_PLUGIN_DIR})
endif()
