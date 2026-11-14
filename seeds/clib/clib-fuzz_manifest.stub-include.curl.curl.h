                                        
  
                                                                             
                                                                             
                                                                         
                                                                           
                                                                             
                                                                      
                                                                            
                                                                         
                                                                           
  
                                                                            
                                                                           
                                                                         
                                                                      
  
                                                                            
                                                                        
                      
   
#ifndef OFT_CLIB_CURL_STUB_H
#define OFT_CLIB_CURL_STUB_H 1

#include <stddef.h>
#include <stdio.h>

typedef void CURL;
typedef void CURLSH;

typedef enum {
  CURLE_OK = 0,
  CURLE_FAILED_INIT = 2,
  CURLE_ABORTED_BY_CALLBACK = 42
} CURLcode;

typedef enum {
  CURLSHE_OK = 0
} CURLSHcode;

                                                                        
                                                                            
                                            
typedef enum {
  CURLOPT_NETRC          = 51,
  CURLOPT_FOLLOWLOCATION = 52,
  CURLOPT_HTTPGET        = 80,
  CURLOPT_WRITEDATA      = 10001,
  CURLOPT_URL            = 10002,
  CURLOPT_USERAGENT      = 10018,
  CURLOPT_SHARE          = 10100,
  CURLOPT_WRITEFUNCTION  = 20011
} CURLoption;

typedef enum {
  CURLINFO_RESPONSE_CODE = 0x200002
} CURLINFO;

typedef enum {
  CURL_LOCK_DATA_NONE = 0,
  CURL_LOCK_DATA_SHARE,
  CURL_LOCK_DATA_COOKIE,
  CURL_LOCK_DATA_DNS,
  CURL_LOCK_DATA_SSL_SESSION,
  CURL_LOCK_DATA_CONNECT,
  CURL_LOCK_DATA_PSL,
  CURL_LOCK_DATA_LAST
} curl_lock_data;

typedef enum {
  CURL_LOCK_ACCESS_NONE   = 0,
  CURL_LOCK_ACCESS_SHARED = 1,
  CURL_LOCK_ACCESS_SINGLE = 2,
  CURL_LOCK_ACCESS_LAST
} curl_lock_access;

typedef enum {
  CURLSHOPT_NONE = 0,
  CURLSHOPT_SHARE,
  CURLSHOPT_UNSHARE,
  CURLSHOPT_LOCKFUNC,
  CURLSHOPT_UNLOCKFUNC,
  CURLSHOPT_USERDATA,
  CURLSHOPT_LAST
} CURLSHoption;

#define CURL_GLOBAL_SSL     (1L<<0)
#define CURL_GLOBAL_WIN32   (1L<<1)
#define CURL_GLOBAL_ALL     (CURL_GLOBAL_SSL|CURL_GLOBAL_WIN32)
#define CURL_GLOBAL_NOTHING 0L
#define CURL_GLOBAL_DEFAULT CURL_GLOBAL_ALL

enum CURL_NETRC_OPTION {
  CURL_NETRC_IGNORED  = 0,
  CURL_NETRC_OPTIONAL = 1,
  CURL_NETRC_REQUIRED = 2,
  CURL_NETRC_LAST
};

CURLcode  curl_global_init(long flags);
void      curl_global_cleanup(void);

CURL     *curl_easy_init(void);
CURLcode  curl_easy_setopt(CURL *handle, CURLoption option, ...);
CURLcode  curl_easy_perform(CURL *handle);
CURLcode  curl_easy_getinfo(CURL *handle, CURLINFO info, ...);
void      curl_easy_cleanup(CURL *handle);

CURLSH   *curl_share_init(void);
CURLSHcode curl_share_setopt(CURLSH *share, CURLSHoption option, ...);
CURLSHcode curl_share_cleanup(CURLSH *share);

#endif                           
