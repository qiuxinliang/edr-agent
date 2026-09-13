#include "edr/kernel_file_semantics.h"

#include <assert.h>
#include <stdint.h>

int main(void) {
  assert(edr_kernel_file_descriptor_is_create_new(
      30u, 30u, 0u, 1u, UINT64_C(0x1000)));
  assert(!edr_kernel_file_descriptor_is_create_new(
      12u, 12u, 0u, 1u, UINT64_C(0xa0)));
  assert(!edr_kernel_file_descriptor_is_create_new(
      30u, 12u, 0u, 1u, UINT64_C(0x1000)));
  assert(!edr_kernel_file_descriptor_is_create_new(
      30u, 30u, 1u, 1u, UINT64_C(0x1000)));
  assert(!edr_kernel_file_descriptor_is_create_new(
      30u, 30u, 0u, 2u, UINT64_C(0x1000)));
  assert(!edr_kernel_file_descriptor_is_create_new(
      30u, 30u, 0u, 1u, UINT64_C(0xa0)));
  return 0;
}
