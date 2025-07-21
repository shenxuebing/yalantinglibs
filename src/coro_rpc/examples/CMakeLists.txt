set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output/examples/coro_rpc)

add_executable(coro_rpc_ip_whitelist_example ip_whitelist_example.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_SYSTEM_NAME MATCHES "Windows") # mingw-w64
    target_link_libraries(coro_rpc_ip_whitelist_example wsock32 ws2_32)
endif()

add_subdirectory(base_examples)
add_subdirectory(file_transfer)
if (YLT_HAVE_IBVERBS)
  add_subdirectory(rdma_example)
endif()

if (CORO_RPC_USE_OTHER_RPC)
  add_subdirectory(user_defined_rpc_protocol/rest_rpc)
endif()