                                                                            
                                                                         
         
  
                                                                              
                                                                       
                                                                          
                                                                        
                                                                      
                                                           
                                                                            
                                                                             
                                                                             
                                                                           
                   
  
                                                                           
                                                                          
                                                                            
                                                                             
                                                                          
                                                               
                                                                          
                                                                       
                                          
  
                                                                         
                                                                             
                                                                            
                                                              
   
#ifndef OFT_PB_MALLOC_SHIM_H
#define OFT_PB_MALLOC_SHIM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
void *realloc_with_check(void *ptr, size_t size);
void free_with_check(void *mem);
#ifdef __cplusplus
}
#endif

#define pb_realloc(ptr, size) realloc_with_check(ptr, size)
#define pb_free(ptr) free_with_check(ptr)

#endif                           
