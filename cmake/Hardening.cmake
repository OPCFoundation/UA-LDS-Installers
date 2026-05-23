# Hardening.cmake — shared compile/link flags for the LDS installer build
#
# Loaded by build.ps1 via cmake -C <file>.  Sets cache variables BEFORE the
# project's CMakeLists.txt runs, so its `set(CMAKE_*_FLAGS ...)` lines append
# our flags rather than replacing them.
#
# Per-arch additions (/SAFESEH for x86, /HIGHENTROPYVA for x64) and the
# Spectre opt-in are layered on top by build.ps1 via -D when invoking cmake.
#
# Flag set matches OPC-Classic-CoreComponents:
#   /GS         buffer security check (stack canaries)
#   /sdl        SDL checks (pointer overwrite, format strings)
#   /guard:cf   Control Flow Guard
#   /NXCOMPAT   DEP
#   /DYNAMICBASE ASLR
#   /GUARD:CF   linker side of CFG
#   /SUBSYSTEM:WINDOWS,6.01  Windows 7 SP1 minimum (linker)
# Static CRT (/MT) is selected via CMAKE_MSVC_RUNTIME_LIBRARY.

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded" CACHE STRING "" FORCE)

# /wd4996 disables C4996 (deprecated-API warnings).  Required because LDS still
# uses OpenSSL 3.x deprecated low-level RSA_/AES_/EVP_PKEY_get1_RSA APIs that
# are kept as compat shims but warn under /sdl.  Removing /wd4996 will require
# modernizing UA-LDS\stack to use OpenSSL 3.x EVP_PKEY interfaces.
set(CMAKE_C_FLAGS   "/GS /sdl /guard:cf /wd4996"   CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "/GS /sdl /guard:cf /wd4996"   CACHE STRING "" FORCE)

# EXE linker: NX, ASLR, CFG, Win7-SP1 subsystem.
# opcualds.exe is a CONSOLE program (main, not WinMain), and CMake's compile
# test program is also console — so /SUBSYSTEM:CONSOLE,6.01 is the right
# choice.  The ",6.01" suffix is what sets the Windows 7 SP1 minimum OS
# version in the PE header.
set(CMAKE_EXE_LINKER_FLAGS
    "/NXCOMPAT /DYNAMICBASE /GUARD:CF /SUBSYSTEM:CONSOLE,6.01"
    CACHE STRING "" FORCE)

# Shared (DLL) linker: same minus /SUBSYSTEM.
set(CMAKE_SHARED_LINKER_FLAGS
    "/NXCOMPAT /DYNAMICBASE /GUARD:CF"
    CACHE STRING "" FORCE)
