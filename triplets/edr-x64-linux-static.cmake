# Agent-owned PCRE2 producer triplet.  The backend P0 publisher links only
# the static library this triplet produces from the locked vcpkg source.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
