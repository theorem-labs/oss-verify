                                                                       
                                                                          
                                                                          
#include "cuda_runtime.h"
extern "C" {
static cudaError_t oftNoCuda(void) { return cudaErrorNotSupported; }
cudaError_t cudaGetLastError(void) { return cudaErrorNotSupported; }
const char* cudaGetErrorString(cudaError_t) { return "oft stub: no CUDA on this target"; }
cudaError_t cudaDriverGetVersion(int* v) { if (v) *v = 0; return oftNoCuda(); }
cudaError_t cudaGetDevice(int* d) { if (d) *d = -1; return oftNoCuda(); }
cudaError_t cudaGetDeviceProperties(struct cudaDeviceProp*, int) { return oftNoCuda(); }
cudaError_t cudaDeviceGetAttribute(int*, enum cudaDeviceAttr, int) { return oftNoCuda(); }
cudaError_t cudaDeviceGetPCIBusId(char*, int, int) { return oftNoCuda(); }
cudaError_t cudaThreadExchangeStreamCaptureMode(enum cudaStreamCaptureMode*) { return oftNoCuda(); }
cudaError_t cudaStreamCreateWithFlags(cudaStream_t*, unsigned int) { return oftNoCuda(); }
cudaError_t cudaStreamDestroy(cudaStream_t) { return oftNoCuda(); }
cudaError_t cudaStreamSynchronize(cudaStream_t) { return oftNoCuda(); }
cudaError_t cudaMalloc(void**, size_t) { return oftNoCuda(); }
cudaError_t cudaFree(void*) { return oftNoCuda(); }
cudaError_t cudaFreeHost(void*) { return oftNoCuda(); }
cudaError_t cudaHostAlloc(void**, size_t, unsigned int) { return oftNoCuda(); }
cudaError_t cudaMemsetAsync(void*, int, size_t, cudaStream_t) { return oftNoCuda(); }
cudaError_t cudaMemcpyAsync(void*, const void*, size_t, enum cudaMemcpyKind, cudaStream_t) { return oftNoCuda(); }
cudaError_t cudaEventSynchronize(cudaEvent_t) { return oftNoCuda(); }
cudaError_t cudaEventQuery(cudaEvent_t) { return oftNoCuda(); }
cudaError_t cudaHostRegister(void*, size_t, unsigned int) { return oftNoCuda(); }
cudaError_t cudaHostUnregister(void*) { return oftNoCuda(); }
cudaError_t cudaHostGetDevicePointer(void**, void*, unsigned int) { return oftNoCuda(); }
}

                                                                       
                                                              
#include "param.h"
#include "nccl.h"
NCCL_PARAM(SetCpuStackSize, "SET_CPU_STACK_SIZE", 1);
                                                           
                                                                         
                                                                   
                                                                     
#include "nccl_common.h"
#include "env.h"
#include <mutex>
static std::once_flag oftEnvInitOnceFlag;
static ncclResult_t oftEnvInitResult = ncclSuccess;
static void oftEnvInitOnceFunc() { oftEnvInitResult = ncclEnvPluginInit(); }
ncclResult_t ncclInitEnv() {
  std::call_once(oftEnvInitOnceFlag, oftEnvInitOnceFunc);
  return oftEnvInitResult;
}
