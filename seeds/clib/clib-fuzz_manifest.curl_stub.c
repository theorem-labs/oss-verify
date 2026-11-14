                           
  
                                                                           
                                                                          
                                                                        
                                                                         
                                                                          
  
                                                                              
                                                                   
                                                                    
  
                                                                           
                                                                          
                                                                            
                                                                            
                                                                    
                                                                            
                                                      
   
#include <curl/curl.h>
#include <stdarg.h>

CURLcode curl_global_init(long flags) {
  (void)flags;
  return CURLE_OK;
}

void curl_global_cleanup(void) {}

CURL *curl_easy_init(void) {
  return 0;                                                                 
                                                                            
}

CURLcode curl_easy_setopt(CURL *handle, CURLoption option, ...) {
  (void)handle; (void)option;
  return CURLE_FAILED_INIT;
}

CURLcode curl_easy_perform(CURL *handle) {
  (void)handle;
  return CURLE_FAILED_INIT;                                                   
}

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO info, ...) {
  va_list ap;
  long *out;
  (void)handle; (void)info;
  va_start(ap, info);
  out = va_arg(ap, long *);
  va_end(ap);
  if (out) *out = 0;                                      
  return CURLE_FAILED_INIT;
}

void curl_easy_cleanup(CURL *handle) {
  (void)handle;
}

CURLSH *curl_share_init(void) {
  return 0;                                                                
                                                                           
                                      
}

CURLSHcode curl_share_setopt(CURLSH *share, CURLSHoption option, ...) {
  (void)share; (void)option;
  return CURLSHE_OK;
}

CURLSHcode curl_share_cleanup(CURLSH *share) {
  (void)share;
  return CURLSHE_OK;
}
