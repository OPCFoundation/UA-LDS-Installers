# ---------------------------------------------------------------------------
# Opc.Ua.CertificateGenerator - OpenSSL 3.x port
#
# A C re-implementation of the legacy Misc-Tools CertificateGenerator, built
# against the SAME OpenSSL distribution the LDS uses (LDS/stack/openssl-<arch>,
# currently 3.5.7) instead of the end-of-life OpenSSL 1.1.1w the original
# pinned.
#
# The command line is contract: see src/cmdline.c.  Any deviation from the
# legacy tool is listed in README.md.
#
# Unlike the original this does NOT link the OPC UA ANSI C stack.  The legacy
# code pulled in the whole stack for three things - status code constants,
# UTF-8/UTF-16 conversion, and heap wrappers - all of which are a few dozen
# lines of plain C here.  Dropping it removes a vendored copy of the stack from
# the build entirely.
# ---------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.20)

project(OpcUaCertificateGenerator C)

# RC is needed for the VERSIONINFO resource (src/Resource.rc).
enable_language(RC)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# OpenSSL
#
# Defaults to the per-arch tree build.ps1 produces for the LDS.  build.ps1
# passes this explicitly; the default exists so the project is usable standalone.
# ---------------------------------------------------------------------------
if(NOT CERTGEN_OPENSSL_ROOT)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(_arch "x64")
    else()
        set(_arch "x86")
    endif()
    set(CERTGEN_OPENSSL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../LDS/stack/openssl-${_arch}"
        CACHE PATH "Root of the OpenSSL install to link against")
endif()

get_filename_component(CERTGEN_OPENSSL_ROOT "${CERTGEN_OPENSSL_ROOT}" ABSOLUTE)

if(NOT EXISTS "${CERTGEN_OPENSSL_ROOT}/include/openssl/opensslv.h")
    message(FATAL_ERROR
        "OpenSSL not found at ${CERTGEN_OPENSSL_ROOT}.\n"
        "Build it first (build.ps1 phase 2 does this), or pass "
        "-DCERTGEN_OPENSSL_ROOT=<path>.")
endif()

# The LDS builds OpenSSL with `no-shared`, so these are static archives.
find_library(CERTGEN_LIBCRYPTO
    NAMES libcrypto crypto
    PATHS "${CERTGEN_OPENSSL_ROOT}/lib" "${CERTGEN_OPENSSL_ROOT}/lib64"
    NO_DEFAULT_PATH REQUIRED)

# Report the OpenSSL version and whether EC is available, because the latter
# decides whether -keyType can honour anything but `rsa`.  See README.md.
file(STRINGS "${CERTGEN_OPENSSL_ROOT}/include/openssl/opensslv.h" _ossl_ver
     REGEX "OPENSSL_VERSION_STR +\"")
string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" CERTGEN_OPENSSL_VERSION "${_ossl_ver}")

set(_cfg_header "${CERTGEN_OPENSSL_ROOT}/include/openssl/configuration.h")
set(CERTGEN_OPENSSL_HAS_EC TRUE)
if(EXISTS "${_cfg_header}")
    file(STRINGS "${_cfg_header}" _no_ec REGEX "define +OPENSSL_NO_EC[ \t]*$")
    if(_no_ec)
        set(CERTGEN_OPENSSL_HAS_EC FALSE)
    endif()
endif()

message(STATUS "CertificateGenerator: OpenSSL ${CERTGEN_OPENSSL_VERSION} at ${CERTGEN_OPENSSL_ROOT}")
if(CERTGEN_OPENSSL_HAS_EC)
    message(STATUS "CertificateGenerator: EC support ENABLED - all -keyType values available")
else()
    message(WARNING
        "CertificateGenerator: this OpenSSL is built with `no-ec`, so elliptic-curve key "
        "types are NOT available. -keyType rsa works; nistP256, nistP384, "
        "brainpoolP256r1, brainpoolP384r1, curve25519 and curve448 will fail "
        "with a clear error at runtime. See CertificateGenerator/README.md.")
endif()

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------
add_executable(certgen
    src/main.c
    src/util.c
    src/cmdline.c
    src/certops.c
    src/Resource.rc
)

# The installer and any existing scripts expect this exact file name.
set_target_properties(certgen PROPERTIES
    OUTPUT_NAME "Opc.Ua.CertificateGenerator"
    C_VISIBILITY_PRESET hidden
)

target_include_directories(certgen PRIVATE
    src
    "${CERTGEN_OPENSSL_ROOT}/include"
)

target_link_libraries(certgen PRIVATE
    "${CERTGEN_LIBCRYPTO}"
    crypt32     # Windows certificate store (LocalMachine / CurrentUser)
    ws2_32      # OpenSSL
    advapi32
    user32
    bcrypt      # OpenSSL RAND on Windows
    rpcrt4      # UuidCreate, for serial numbers
)

target_compile_definitions(certgen PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    # Match cmake/Hardening.cmake, which build.ps1 applies to the LDS targets.
    # Kept in sync deliberately: a hardening flag set that differs per target is
    # a hardening flag set nobody can reason about.
    target_compile_options(certgen PRIVATE /GS /sdl /guard:cf /W4)
    target_link_options(certgen PRIVATE /NXCOMPAT /DYNAMICBASE /GUARD:CF)

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(certgen PRIVATE /HIGHENTROPYVA)
    else()
        target_link_options(certgen PRIVATE /SAFESEH)
    endif()

    # Static CRT, as the LDS does, so the binary has no redistributable dependency.
    set_property(TARGET certgen PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

    # NOTE: no /wd4996 here, unlike the LDS build.  This port uses the OpenSSL
    # 3.x EVP_PKEY interfaces throughout and must stay free of deprecated-API
    # use; suppressing the warning would hide exactly the regression we care
    # about.
endif()
