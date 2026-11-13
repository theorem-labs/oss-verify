                                                                        
                                                    
  
                                                                         
                                                                         
                                                                            
                                                               
                                                         
                                                                        
                                                                           
                                                                            
                                                                            
                                                                          
  
                                                                    
                                                                          
                              
  
                                                                             
                                                                           
   
#include <stdbool.h>
#include <string.h>

typedef unsigned __int128 u128;

static volatile char oft_lock16;

static void oft_lk(void) {
  while (__atomic_test_and_set(&oft_lock16, __ATOMIC_ACQUIRE)) {}
}
static void oft_ul(void) { __atomic_clear(&oft_lock16, __ATOMIC_RELEASE); }

u128 __atomic_load_16(const volatile void *mem, int model) {
  (void)model;
  u128 v;
  oft_lk();
  memcpy(&v, (const void *)mem, sizeof v);
  oft_ul();
  return v;
}

void __atomic_store_16(volatile void *mem, u128 val, int model) {
  (void)model;
  oft_lk();
  memcpy((void *)mem, &val, sizeof val);
  oft_ul();
}

u128 __atomic_exchange_16(volatile void *mem, u128 val, int model) {
  (void)model;
  u128 old;
  oft_lk();
  memcpy(&old, (void *)mem, sizeof old);
  memcpy((void *)mem, &val, sizeof val);
  oft_ul();
  return old;
}

bool __atomic_compare_exchange_16(volatile void *mem, void *expected,
                                  u128 desired, int success, int failure) {
  (void)success;
  (void)failure;
  bool ok;
  oft_lk();
  ok = memcmp((void *)mem, expected, sizeof desired) == 0;
  if (ok)
    memcpy((void *)mem, &desired, sizeof desired);
  else
    memcpy(expected, (void *)mem, sizeof desired);
  oft_ul();
  return ok;
}
