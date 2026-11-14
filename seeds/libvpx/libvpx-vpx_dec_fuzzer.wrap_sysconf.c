                                                                
  
                                                                            
                                                                              
                                                                         
                                                                               
                                                                               
                                                                         
                                                                                
                                                                       
                                                                            
                                                                             
                                                                        
  
                                                                               
                                                                             
                                                                               
#include <unistd.h>

long __real_sysconf(int name);

long __wrap_sysconf(int name) {
#ifdef _SC_NPROCESSORS_ONLN
  if (name == _SC_NPROCESSORS_ONLN) return 1;
#endif
#ifdef _SC_NPROCESSORS_CONF
  if (name == _SC_NPROCESSORS_CONF) return 1;
#endif
  return __real_sysconf(name);
}
