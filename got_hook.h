#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int hook_func(const char* lib, void* symbol, void* new_func, void** old_func);

#ifdef __cplusplus
}
#endif
