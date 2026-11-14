                                                                              
  
                                                                          
                                                                             
                                  
  
                                                           
                                                           
                                                                
  
                                                               
                                                                        
                                                                       
                                                                        
                                                                          
                                                                     
                                                                   
                                                                          
  
                                                                       
                                                                          
                                                                        
                                                                      
                                                                        
                                                                            
                                                                  
  
                                                                            
                                                                          
                                                                           
                                                                            
                                                                      
                                                                         
                                                                         
  
                                                                    
                                                                        
   
#include <errno.h>
#include <stdarg.h>

#define OFT_PR_CAPBSET_READ 23
#define OFT_MEASURED_MAX_CAP 40

int prctl(int op, ...)
{
  va_list ap;
  unsigned long a2;
  va_start(ap, op);
  a2 = va_arg(ap, unsigned long);
  va_end(ap);
  if (op == OFT_PR_CAPBSET_READ)
  {
    if (a2 <= OFT_MEASURED_MAX_CAP)
      return 1;
    errno = EINVAL;
    return -1;
  }
  errno = EINVAL;
  return -1;
}
