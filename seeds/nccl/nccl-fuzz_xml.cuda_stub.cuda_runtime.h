                                                                    
                                                                     
                                                           
                                                                       
                                                                 
                                                                      
                                        
#ifndef OFT_CUDA_RUNTIME_STUB_H_
#define OFT_CUDA_RUNTIME_STUB_H_
#include <stddef.h>
#define CUDART_VERSION 0

typedef struct CUstream_st* cudaStream_t;
typedef struct CUevent_st* cudaEvent_t;
typedef enum cudaError {
  cudaSuccess = 0,
  cudaErrorNotReady = 600,
  cudaErrorNotSupported = 801
} cudaError_t;
enum cudaMemcpyKind {
  cudaMemcpyHostToHost = 0, cudaMemcpyHostToDevice = 1,
  cudaMemcpyDeviceToHost = 2, cudaMemcpyDeviceToDevice = 3,
  cudaMemcpyDefault = 4
};
enum cudaStreamCaptureMode {
  cudaStreamCaptureModeGlobal = 0,
  cudaStreamCaptureModeThreadLocal = 1,
  cudaStreamCaptureModeRelaxed = 2
};
struct cudaDeviceProp { char name[256]; int major; int minor; };
typedef struct cudaIpcMemHandle_st { char reserved[64]; } cudaIpcMemHandle_t;
#define cudaStreamLegacy ((cudaStream_t)0x1)
#define cudaStreamNonBlocking 0x01
#define cudaHostAllocMapped 0x02

extern "C" {
cudaError_t cudaGetLastError(void);
const char* cudaGetErrorString(cudaError_t err);
cudaError_t cudaDriverGetVersion(int* v);
cudaError_t cudaGetDevice(int* dev);
cudaError_t cudaGetDeviceProperties(struct cudaDeviceProp* prop, int dev);
cudaError_t cudaThreadExchangeStreamCaptureMode(enum cudaStreamCaptureMode* mode);
cudaError_t cudaStreamCreateWithFlags(cudaStream_t* s, unsigned int flags);
cudaError_t cudaStreamDestroy(cudaStream_t s);
cudaError_t cudaStreamSynchronize(cudaStream_t s);
cudaError_t cudaMalloc(void** p, size_t sz);
cudaError_t cudaFree(void* p);
cudaError_t cudaFreeHost(void* p);
cudaError_t cudaHostAlloc(void** p, size_t sz, unsigned int flags);
cudaError_t cudaMemsetAsync(void* p, int v, size_t n, cudaStream_t s);
cudaError_t cudaMemcpyAsync(void* dst, const void* src, size_t n, enum cudaMemcpyKind k, cudaStream_t s);
}
                                                                           
struct alignas(16) int4 { int x, y, z, w; };
struct alignas(16) ulong2 { unsigned long x, y; };
enum cudaDeviceAttr {
  cudaDevAttrComputeCapabilityMajor = 75,
  cudaDevAttrComputeCapabilityMinor = 76
};
extern "C" {
cudaError_t cudaDeviceGetAttribute(int* value, enum cudaDeviceAttr attr, int device);
cudaError_t cudaDeviceGetPCIBusId(char* pciBusId, int len, int device);
}
typedef struct CUmemPoolHandle_st* cudaMemPool_t;
typedef struct CUgraph_st* cudaGraph_t;
typedef struct CUgraphNode_st* cudaGraphNode_t;
typedef struct CUuserObject_st* cudaUserObject_t;
typedef void (*cudaHostFn_t)(void* userData);
struct dim3 {
  unsigned int x, y, z;
  dim3(unsigned int x_ = 1, unsigned int y_ = 1, unsigned int z_ = 1) : x(x_), y(y_), z(z_) {}
};
#define cudaHostRegisterPortable 0x01
#define cudaHostRegisterMapped 0x02
extern "C" {
cudaError_t cudaEventSynchronize(cudaEvent_t e);
cudaError_t cudaEventQuery(cudaEvent_t e);
cudaError_t cudaHostRegister(void* ptr, size_t size, unsigned int flags);
cudaError_t cudaHostUnregister(void* ptr);
cudaError_t cudaHostGetDevicePointer(void** pDevice, void* pHost, unsigned int flags);
}
#endif
