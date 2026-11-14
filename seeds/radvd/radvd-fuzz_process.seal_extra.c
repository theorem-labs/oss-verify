                                                                                
  
                                                                              
                                                                              
                                                                            
                                                                     
                                                                        
                                                                          
                                                       
  
                                                                            
                                                                     
                                                                              
                                                                             
                                                                            
                                                                           
                                                                
   
#include <net/if.h>
#include <stdio.h>

char *if_indextoname(unsigned int index, char *name)
{
	snprintf(name, IF_NAMESIZE, "if%u", index);
	return name;
}
