                                                                             
                                                                             
                                                          
  
                                                                                       
                                                                     
                                                                              
                                                                            
                                                                           
                                                                      
                                                                           
                                                                             
                                                                            
                                                                           
                                                        
  
                                                                          
                                                                             
                                                                          
                                                                        
                                                                             
                                                    
  
                                                                            
                                                                            
                                                                      
   

                                                                                
struct oft_timeval  { long long tv_sec; long tv_usec; };
struct oft_timespec { long long tv_sec; long tv_nsec; };

int gettimeofday(struct oft_timeval *tv, void *tz)
{
  (void)tz;
  if (tv) { tv->tv_sec = 1700000000LL; tv->tv_usec = 0; }
  return 0;
}

int clock_gettime(int clk, struct oft_timespec *ts)
{
  (void)clk;
  if (ts) { ts->tv_sec = 1700000000LL; ts->tv_nsec = 0; }
  return 0;
}

                                                                         
                                                                 
                                                               
                                                            
                                                                          
                                                                             
                                                                         
                                                                          
                                                                             
                                                                        
                                                                           
                                                     
void __wrap_sctp_startup_iterator(void) { }
