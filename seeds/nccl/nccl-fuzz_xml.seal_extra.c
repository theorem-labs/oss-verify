                                                                          
                                                         
  
                                                                              
                                                                         
                                                                             
                                  
  
                                                                          
                                                                             
                                                                             
                                                                            
                                                                              
                                                                      
                               
  
                                                                        
                                                                         
                                                                             
                                                                       
                                                      
  
                                                                          
                                                                            
                                                                       
                                                                            
                                                                            
                                                                        
                                                                         
                                                                        
  
                                                                     
                                                                         
                                                                      
                                                                           
                                                                        
                                                                             
                           
   

                                                      
struct oft_timespec { long long tv_sec; long tv_nsec; };

int clock_gettime(int clk, struct oft_timespec *ts)
{
  (void)clk;
  if (ts) { ts->tv_sec = 1700000000LL; ts->tv_nsec = 0; }
  return 0;
}

                                              
struct oft_utsname {
  char sysname[65]; char nodename[65]; char release[65];
  char version[65]; char machine[65];  char domainname[65];
};

static void oft_copy(char *dst, const char *src)
{
  int i = 0;
  for (; src[i] && i < 64; i++) dst[i] = src[i];
  dst[i] = '\0';
}

int uname(struct oft_utsname *u)
{
  if (!u) return -1;
  oft_copy(u->sysname, "Linux");
  oft_copy(u->nodename, "oft");
  oft_copy(u->release, "6.0.0-oft");
  oft_copy(u->version, "#1 oft");
  oft_copy(u->machine, "riscv64");
  oft_copy(u->domainname, "(none)");
  return 0;
}

int unlink(const char *path)
{
  (void)path;
  return 0;
}
