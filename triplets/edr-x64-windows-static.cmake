# Agent-owned PCRE2 producer triplet for native AMD64 Windows releases.
# Only the isolated producer prefix uses this triplet; the rest of the
# product dependency closure keeps its existing linkage choices.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
