# Agent-owned PCRE2 producer triplet.  Cross builds must supply a target C
# compiler (and, where needed, the caller's vcpkg chainload toolchain).
set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
