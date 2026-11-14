// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

                                                      
                                                                       
                                                                             
                                                                            
                                                                          
                                                                          
                                                                             
                                                                     
                                                                      
                                                                           
               

#include "common.h"
#include "block_base.h"
#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
typedef struct AES_State_opaque AES_State;
int AES_start_operation(const uint8_t key[], size_t key_len, AES_State **pResult);
int AES_stop_operation(BlockBase *state);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (!size)
    return 0;

  enum KeySize { AES128 = 16, AES192 = 24, AES256 = 32, kMaxValue = AES256 };

  FuzzedDataProvider stream(data, size);
  const KeySize keySize = stream.ConsumeEnum<KeySize>();
  if (stream.remaining_bytes() < keySize)
    return 0;

  std::vector<uint8_t> keyBuf = stream.ConsumeBytes<uint8_t>(keySize);
  const uint8_t *key = keyBuf.data();

  BlockBase *state;
  if (AES_start_operation(key, keySize, reinterpret_cast<AES_State **>(&state)))
    return 0;

  uint8_t outEnc[size];
  uint8_t outDec[size];

  state->encrypt(state, data, outEnc, size);
  state->decrypt(state, data, outDec, size);

  AES_stop_operation(state);

  return 0;
}
