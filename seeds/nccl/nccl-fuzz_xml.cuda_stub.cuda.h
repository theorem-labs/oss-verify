                                                                         
#ifndef OFT_CUDA_STUB_H_
#define OFT_CUDA_STUB_H_
#include "cuda_runtime.h"
#define CUDA_VERSION 0
typedef enum cudaError_enum {
  CUDA_SUCCESS = 0,
  CUDA_ERROR_NOT_READY = 600,
  CUDA_ERROR_TOO_MANY_PEERS = 711,
  CUDA_ERROR_NOT_SUPPORTED = 801
} CUresult;
typedef int CUdevice;
typedef unsigned long long CUdeviceptr;
typedef unsigned long long CUmemGenericAllocationHandle;
typedef enum CUmemAllocationHandleType_enum {
  CU_MEM_HANDLE_TYPE_NONE = 0x0,
  CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR = 0x1
} CUmemAllocationHandleType;
typedef enum CUmemLocationType_enum {
  CU_MEM_LOCATION_TYPE_INVALID = 0x0,
  CU_MEM_LOCATION_TYPE_DEVICE = 0x1,
  CU_MEM_LOCATION_TYPE_HOST_NUMA = 0x3
} CUmemLocationType;
typedef enum CUmemAllocationType_enum {
  CU_MEM_ALLOCATION_TYPE_INVALID = 0x0,
  CU_MEM_ALLOCATION_TYPE_PINNED = 0x1
} CUmemAllocationType;
typedef enum CUmemAccess_flags_enum {
  CU_MEM_ACCESS_FLAGS_PROT_NONE = 0x0,
  CU_MEM_ACCESS_FLAGS_PROT_READWRITE = 0x3
} CUmemAccess_flags;
typedef enum CUmemAllocationGranularity_flags_enum {
  CU_MEM_ALLOC_GRANULARITY_MINIMUM = 0x0
} CUmemAllocationGranularity_flags;
typedef struct CUmemLocation_st { CUmemLocationType type; int id; } CUmemLocation;
typedef struct CUmemAllocationProp_st {
  CUmemAllocationType type;
  CUmemAllocationHandleType requestedHandleTypes;
  CUmemLocation location;
  void* win32HandleMetaData;
  struct { unsigned char compressionType, gpuDirectRDMACapable; unsigned short usage; unsigned char reserved[4]; } allocFlags;
} CUmemAllocationProp;
typedef struct CUmemAccessDesc_st { CUmemLocation location; CUmemAccess_flags flags; } CUmemAccessDesc;
typedef union CUstreamBatchMemOpParams_union { unsigned char pad[48]; } CUstreamBatchMemOpParams;
typedef enum CUdevice_attribute_enum {
  CU_DEVICE_ATTRIBUTE_HOST_NUMA_ID = 1,
  CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_WITH_CUDA_VMM_SUPPORTED = 3
} CUdevice_attribute;
extern CUmemAllocationHandleType ncclCuMemHandleType;
typedef struct CUctx_st* CUcontext;
typedef struct CUfunc_st* CUfunction;
#endif
