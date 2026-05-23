# ============================================================================
# ldsca.dll - MSI custom-actions DLL for the LDS WiX installer
#
# Exports 3 functions called from WiX (see MergeModule.wxs):
#   BackupOldUaldsIni        - copy ualds.ini -> ualds.ini.old (immediate)
#   UpdateUaldsIni           - rewrite absolute paths in ualds.ini (deferred)
#   CopyPkiKeysFromOldIniFile - preserve user-customized PKI paths (deferred)
#
# Replaces the InstallShield-era project which:
#   - Linked against a prebuilt msiaction.lib (a frozen VS2008 build of
#     UA-LDS\settings.c).  We rebuild that here from the current settings.c.
#   - Also exported AddDiscoveryServiceToFWEL / RemoveDiscoveryServiceFromFWEL
#     for firewall management.  Replaced by WixToolset.Firewall.wixext.
#
# To make UA-LDS\settings.c compile without dragging in the OPC UA AnsiC
# stack and the LDS logger, the stubs/ folder shadows two of its includes:
#   stubs/opcua_p_crypto.h  - empty (no symbols from it are referenced)
#   stubs/log.h             - minimal LogLevel + ualds_log declaration
# `stubs` MUST come first in the include path so it wins over UA-LDS\win32\log.h.
# ============================================================================

cmake_minimum_required(VERSION 3.20)
project(ldsca CXX C)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

set(UALDS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../UA-LDS")
if(NOT EXISTS "${UALDS_DIR}/settings.c")
    message(FATAL_ERROR "Cannot find UA-LDS/settings.c at ${UALDS_DIR}. Expected layout: LDS\\UA-LDS\\ and LDS\\UA-LDS-Installers\\CustomActions\\.")
endif()

add_library(ldsca SHARED
    # Custom-action entry points + their helpers
    dllmain.cpp
    ldsca.cpp
    msilog.cpp
    stdafx.cpp
    log_stub.c
    platform_stub.c

    # Pulled in from UA-LDS so settings.c builds with the same toolchain/CRT as
    # the rest of the installer. Drops the legacy msiaction.lib (VS2008) dep.
    "${UALDS_DIR}/settings.c"
    "${UALDS_DIR}/strlcat.c"
    "${UALDS_DIR}/strlcpy.c"
)

target_compile_definitions(ldsca PRIVATE
    WIN32
    NDEBUG
    _WINDOWS
    _USRDLL
    LDSCA_EXPORTS    # marks LDSCA_API as dllexport (see ldsca.h)
    WINVER=0x0601
    _WIN32_WINNT=0x0601
    NTDDI_VERSION=0x06010100
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
    _CRT_SECURE_NO_DEPRECATE
    _CRT_NONSTDC_NO_WARNINGS
)

# Include path order matters: stubs/ must come before UA-LDS/win32/ so that
# UA-LDS\settings.c's `#include <log.h>` picks up our stub instead of the real
# UA-LDS logger header.
target_include_directories(ldsca PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs"
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${UALDS_DIR}"
    "${UALDS_DIR}/win32"
)

# Static CRT + hardening (rest comes from Hardening.cmake via -C).
set_property(TARGET ldsca PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
target_compile_options(ldsca PRIVATE
    /GS /sdl /guard:cf /wd4996
    /wd4100   # unused param - heavy in settings.c
    /wd4244   # int -> size_t conversion - in settings.c
)

# Disable PCH for the externally-pulled C sources (they don't know stdafx.h).
set_source_files_properties(
    "${UALDS_DIR}/settings.c"
    "${UALDS_DIR}/strlcat.c"
    "${UALDS_DIR}/strlcpy.c"
    log_stub.c
    platform_stub.c
    PROPERTIES SKIP_PRECOMPILE_HEADERS TRUE
)

target_link_libraries(ldsca PRIVATE msi advapi32)

set_target_properties(ldsca PROPERTIES
    OUTPUT_NAME "ldsca"
    PREFIX ""
)

install(TARGETS ldsca RUNTIME DESTINATION bin LIBRARY DESTINATION bin)
