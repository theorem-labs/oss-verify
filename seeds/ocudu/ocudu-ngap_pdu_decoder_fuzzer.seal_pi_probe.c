                                                                              
                                                      
  
                                                                               
                                                                              
                         
  
                                                                               
                                                                           
                                                                             
                                                                              
                                                                        
                                                                              
                                                                         
                                                    
                                                        
                                                                           
                                                                            
                                                                    
                                         
  
                                                                              
                                                                             
                                                                        
                                                                             
                                                                        
                                                                             
                                                                      
                                                                         
                   
#include <pthread.h>

int __real_pthread_mutexattr_setprotocol(pthread_mutexattr_t *a, int protocol);

int __wrap_pthread_mutexattr_setprotocol(pthread_mutexattr_t *a, int protocol)
{
	if (protocol == PTHREAD_PRIO_INHERIT) {
		a->__attr |= 8;
		return 0;
	}
	return __real_pthread_mutexattr_setprotocol(a, protocol);
}
