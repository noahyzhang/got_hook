#include <dlfcn.h>
#include <unistd.h>
#include <iostream>
#include "got_hook.h"

pid_t (*old_getpid)() = NULL;

pid_t new_getpid() {
    return (*old_getpid)() + 1; 
}

int main() {
    // 获取 getpid 函数的地址
    void* addr = dlsym(NULL, "getpid");
    std::cout << "hook before, pid: " << getpid() << std::endl;

    // hook_func("test", addr, (void*)new_getpid, (void**)&old_getpid);
    hook_func("test", addr, (void*)new_getpid, (void**)&old_getpid);

    std::cout << "hook after, pid: " << std::dec << getpid() << std::endl;

    return 0;
}