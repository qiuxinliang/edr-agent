# 查找 libprotobuf-c（https://github.com/protobuf-c/protobuf-c）
# 成功后: ProtobufC_FOUND, ProtobufC_INCLUDE_DIRS, ProtobufC_LIBRARIES

find_path(ProtobufC_INCLUDE_DIR
  NAMES protobuf-c/protobuf-c.h
  PATHS
    "${ProtobufC_ROOT}/include"
    /usr/include
    /usr/local/include
    /opt/homebrew/include
)

find_library(ProtobufC_LIBRARY
  NAMES protobuf-c
  PATHS
    "${ProtobufC_ROOT}/lib"
    /usr/lib
    /usr/local/lib
    /opt/homebrew/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ProtobufC
  REQUIRED_VARS ProtobufC_LIBRARY ProtobufC_INCLUDE_DIR)

if(ProtobufC_FOUND)
  set(ProtobufC_INCLUDE_DIRS "${ProtobufC_INCLUDE_DIR}")
  set(ProtobufC_LIBRARIES "${ProtobufC_LIBRARY}")
endif()
