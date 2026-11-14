                                                                                                       
                                                    
  
                                                                         
                                                                     
                                                         
                                                                                                                                                                                                
                                                                                 
                                                                             
                                                                             
                                                                     
                                                     
                                                              
                                                                                
                                                                                
                                                                               
                                                                                   
                                                                           
                                                                            
                                                                                      
                                                                            
                                                                          
                     
extern int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle);

int __cxa_thread_atexit(void (*dtor)(void *), void *obj, void *dso_symbol) {
  return __cxa_atexit(dtor, obj, dso_symbol);
}
