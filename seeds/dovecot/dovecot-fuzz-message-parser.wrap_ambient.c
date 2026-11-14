                                                                             
                                                                            
                                                                              
                                                                             
                                                
  
                                                                         
                                 
                                                                       
                                                                    
                                                                     
  
                                                                   
                                                                            
                                                                           
                        
  
                                                                        
                                                                        
                                                                           
                                         
  
                                                                        
                                                                     
                                                                          
                                                                       
                                                                          
                                                                         
                                                     
   
#include <stddef.h>
#include <string.h>

int __wrap_gethostname(char *name, size_t len)
{
	const char *h = "oft-host";
	if (name == NULL || len == 0)
		return -1;
	strncpy(name, h, len - 1);
	name[len - 1] = '\0';
	return 0;
}

                                                                          
                                                                   
void __wrap_fd_close_on_exec(int fd, int set)
{
	(void)fd;
	(void)set;
}

void __wrap_lib_signals_init(void)
{
}

void __wrap_lib_signals_deinit(void)
{
}

void __wrap_lib_signals_ignore(int signo, int restart_syscalls)
{
	(void)signo;
	(void)restart_syscalls;
}

                                                                         
                                                                              
                                                                       
                                                                             
                                                                       
                                                                            
                                                                              
                                                                      
                                                                        
                                                                           
                                                                            
                                       
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>

extern int __real_open(const char *path, int flags, ...);

int __wrap_open(const char *path, int flags, ...)
{
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = (mode_t)va_arg(ap, int);
		va_end(ap);
	}
	if (path != NULL && strcmp(path, "/dev/null") == 0 &&
	    (flags & ~(O_LARGEFILE | O_CLOEXEC)) == O_WRONLY)
		return __real_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	return __real_open(path, flags, mode);
}
