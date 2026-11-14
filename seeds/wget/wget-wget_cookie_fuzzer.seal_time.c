                                                                                   
  
                                                                            
                                                                                       
                                                      
                                                                          
                                                                           
                                                                  
                                                                            
                                                          
  
                              
                 
                                                   
                                           
                                                             
                                                                                               
                                    
                                                                               
  
                                                                             
                                                                      
                                                                              
                                                                            
                                                                              
                                                                            
                                                                             
                                                                              
                                                                          
                                                   
  
                                                                               
                                                                               
  
                                                                              
                                                                              
                                                                             
                                                                            
                                                                         
                                                                          
                                                                               
                                                                       
                                                                             
                                                                              
                                                                               
                                                                         
                                                                              
                                                                             
                                    
  
                                                                          
                                                                       
                                                                              
                                                                      
                                                       
                                                                            
                                                                        
                                                                                     
                                                                             
                                                                        
                                                                            
                                                                              
                                                                               
  
                                                                             
                                                                         
                                                                               
                                                                            
  
                                                                           
                                                                      
                                                                         
                                                                    
  
                                                                               
                                                                       
                                                                         
                                                                              
                                                                              
                                               
   

#define OFT_SEALED_TIME 1767225600LL                           

struct oft_timespec { long long tv_sec; long tv_nsec; };
struct oft_timeval  { long long tv_sec; long tv_usec; };

long long time(long long *t)
{
  if (t)
    *t = (long long)OFT_SEALED_TIME;
  return (long long)OFT_SEALED_TIME;
}

int clock_gettime(int clk, struct oft_timespec *ts)
{
  (void)clk;
  if (ts) {
    ts->tv_sec = (long long)OFT_SEALED_TIME;
    ts->tv_nsec = 0;
  }
  return 0;
}

int gettimeofday(struct oft_timeval *tv, void *tz)
{
  (void)tz;
  if (tv) {
    tv->tv_sec = (long long)OFT_SEALED_TIME;
    tv->tv_usec = 0;
  }
  return 0;
}
