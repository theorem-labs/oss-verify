                                                                               
  
                                                                           
                                                                              
                                                                         
                                                                            
                                                                               
                                                                            
                                                                             
                                                                               
                                                                            
                              
  
                                                                              
                                                                           
                                                                          
                                                                    
                                                                        
                                                                           
  
                                                                               
                                                                            
                                                                         
                                                  
  
                                                                             
                                                                           
                                                                       
                                                                              
                                                                            
                                                                       
                                                                        
                                                                     
#include <time.h>

struct tm *localtime (const time_t *t)
{
  return gmtime (t);
}

struct tm *localtime_r (const time_t *t, struct tm *out)
{
  return gmtime_r (t, out);
}

void tzset (void)
{
}
