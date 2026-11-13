                                                                            
                                                                          
                                                                
  
                                                                          
                                                                               
                                                                               
                                                                            
                                                                               
                                                
  
                                                                                
                                                                
                                                                              
                                                                        
                                                                              
  
                                                                            
                                                                          
                                                                            
                                                                           
                                                                               
                                                                           
                                            
  
                                                                                  
  
                                                                         
                                                                               
                                                                             
                                                                              
                                                                              
                                                                             
                                                                           
                                                                      
                                                                       
                                                                       
                                                                              
                                                                          
                                                                          
                                                                           
                                                                           
                                                                            
                 
  
                                                                             
                                                                               
                                                                                
                                                                           
                                                                           
                                                                          
                                                                        
                                                                            
                                                                              
                                                                              
                                                                               
                                                                              
                                                                            
  
                                                                          
                                                                            
                                                                              
#define _XOPEN_SOURCE 700                                                                          
#include <pthread.h>

int oft_wget_keep_pthread (pthread_mutex_t *m, pthread_mutexattr_t *a,
                           pthread_cond_t *c, pthread_once_t *o,
                           void (*init_routine) (void), int *type);

int
oft_wget_keep_pthread (pthread_mutex_t *m, pthread_mutexattr_t *a,
                       pthread_cond_t *c, pthread_once_t *o,
                       void (*init_routine) (void), int *type)
{
  int r = 0;
  r |= pthread_mutexattr_init (a);
  r |= pthread_mutexattr_settype (a, PTHREAD_MUTEX_RECURSIVE);
  r |= pthread_mutexattr_gettype (a, type);
  r |= pthread_mutexattr_destroy (a);
  r |= pthread_mutex_init (m, a);
  r |= pthread_mutex_lock (m);
  r |= pthread_mutex_unlock (m);
  r |= pthread_mutex_destroy (m);
  r |= pthread_cond_init (c, NULL);
  r |= pthread_cond_signal (c);
  r |= pthread_cond_broadcast (c);
  r |= pthread_cond_wait (c, m);
  r |= pthread_cond_destroy (c);
  r |= pthread_once (o, init_routine);
  return r;
}
