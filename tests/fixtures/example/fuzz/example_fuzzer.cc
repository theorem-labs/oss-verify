/* Copyright 2026 Theorem Labs, PBC
 * SPDX-License-Identifier: Apache-2.0 */
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include "example.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string input(reinterpret_cast<const char *>(data), size);
  if (!input.empty() && input[0] == 't') throw std::runtime_error("uncaught");  /* an uncaught exception: 134 */
  if (!input.empty() && input[0] == 'N') {  /* one allocation with new[], which may throw std::bad_alloc */
    char *copy = new char[size];
    std::memcpy(copy, data, size);
    volatile char first = copy[0];
    delete[] copy;
    return first == 'N' ? 0 : 0;
  }
  return example_run(data, size);
}
