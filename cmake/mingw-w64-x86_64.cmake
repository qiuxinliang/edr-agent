# MinGW-w64 交叉编译 Windows 可执行文件（CI / 无 MSVC 环境验证用）
# 若本机未把 x86_64-w64-mingw32-gcc 放进 PATH，可设置环境变量 MINGW_PREFIX 为工具链根目录
#（其下应有 bin/x86_64-w64-mingw32-gcc），例如 MacPorts：/opt/local/x86_64-w64-mingw32
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)
if(DEFINED ENV{MINGW_PREFIX} AND NOT "$ENV{MINGW_PREFIX}" STREQUAL "")
  set(_mingw_bin "$ENV{MINGW_PREFIX}/bin")
  set(CMAKE_C_COMPILER "${_mingw_bin}/x86_64-w64-mingw32-gcc")
  set(CMAKE_CXX_COMPILER "${_mingw_bin}/x86_64-w64-mingw32-g++")
  set(CMAKE_RC_COMPILER "${_mingw_bin}/x86_64-w64-mingw32-windres")
else()
  set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
  set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
  set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
endif()
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# vcpkg MinGW deps: headers/libs and CONFIG packages under <prefix>/include, lib/, share/.
# Without listing the prefix here, CMAKE_FIND_ROOT_PATH is empty and *_ONLY modes skip the install tree.
set(_edr_mingw_deps_prefix "")
if(DEFINED ENV{EDR_MINGW_DEPS_PREFIX} AND NOT "$ENV{EDR_MINGW_DEPS_PREFIX}" STREQUAL "")
  set(_edr_mingw_deps_prefix "$ENV{EDR_MINGW_DEPS_PREFIX}")
elseif(DEFINED ENV{EDR_MINGW_GRPC_PREFIX} AND NOT "$ENV{EDR_MINGW_GRPC_PREFIX}" STREQUAL "")
  set(_edr_mingw_deps_prefix "$ENV{EDR_MINGW_GRPC_PREFIX}")
endif()
if(NOT "${_edr_mingw_deps_prefix}" STREQUAL "")
  list(PREPEND CMAKE_FIND_ROOT_PATH "${_edr_mingw_deps_prefix}")
endif()
