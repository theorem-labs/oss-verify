                                                                       
  
                                                                              
                                                                           
                                                                            
                                                                           
                                      
                                                                              
                                                                          
                                                                             
                                                                        
                                                            
  
                                                                     
                                                                           
                                                                         
                                 
  
                                                                           
                                                                                     
                                                                              
                      
  
                                                              
                                         
                                
                                       
                                                                         
  
                                                                               
                                                                            
                                                                       
                                                                    
                                                                 
                                                                              
                                                                        
                                                                          
                                                                             
                                                                             
  
                                                                
                                                                               
                                                                               
                                                                             
                                                         
                                                                            
                                                                       
                                                                               
                                                                              
                                                                             
                                                         
                                                                             
                                                                            
                    
  
                                                                         
                                                                              
                                                                           
   
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>

                                                                      
                                                                             
                                                                       
uid_t __wrap_geteuid(void) { return 1000; }
gid_t __wrap_getegid(void) { return 1000; }

                                                                          
                                                                            
                                                                       
                                                                            
                                                                          
                                     
long __real_sysconf(int name);
long __wrap_sysconf(int name)
{
    if (name == _SC_NPROCESSORS_ONLN || name == _SC_NPROCESSORS_CONF) {
        return 1;
    }
    return __real_sysconf(name);
}

                                                                          
                                                                            
                                                         
  
                                                                          
                                                        
int sched_getaffinity(pid_t pid, size_t size, void *set)
{
    (void) pid; (void) size; (void) set;
    errno = ENOSYS;
    return -1;
}

                                                          
                                                                        
                                                                       
                                                                           
                                                    
  
                                                                          
                                                                              
                                                                          
int clock_gettime(clockid_t clk, struct timespec *ts)
{
    (void) clk;
    if (ts != NULL) {
        ts->tv_sec = 1000000000;
        ts->tv_nsec = 0;
    }
    return 0;
}

                                                        
                                                                          
                                                                     
                                                                  
                                                                           
                                                                          
                                                                           
                                 
int __wrap_fcntl(int fd, int cmd, ...)
{
    (void) fd; (void) cmd;
    return 0;
}
