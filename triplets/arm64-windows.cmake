set(VCPKG_TARGET_ARCHITECTURE arm64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)

if(PORT STREQUAL "openssl")
    # OpenSSL 3.6.3 forces /Gs0, which miscompiles ARM64 prologues with MSVC.
    # Restore the default probe threshold, retaining /GS and large-frame probes.
    # Remove when the pinned port includes upstream e9344b082ffa78cb1d68f6446c1b6417c4244a00.
    # https://github.com/openssl/openssl/pull/32872
    set(VCPKG_C_FLAGS "/Gs4096")
    set(VCPKG_CXX_FLAGS "/Gs4096")
endif()
