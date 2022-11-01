#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <iostream>
#include "got_hook.h"

// 修改调用进程内存页的保护属性，修改为 rwx
// mprotect: 可以用来修改一段指定内存区域的保护属性。把自start开始的、长度为len的内存区的保护属性修改为prot指定的值
int change_addr_to_rwx(uint64_t addr) {
    uint64_t page_size = sysconf(_SC_PAGESIZE);
    uint64_t page_start = addr & (~(page_size - 1));
    // std::cout << "page_start: " << page_start << std::endl;
    int res = mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (res < 0) {
        std::cerr << "mprotect err: " << strerror(errno) << std::endl;
        return -1;
    }
    return 0;
}

// 替换 got 表中的关于某个符号的指向
int write_data_to_addr(uint64_t addr, uint64_t value) {
    int res = change_addr_to_rwx(addr);
    if (res < 0) {
        std::cerr << "write data to addr err: " << strerror(errno) << std::endl;
        return -1;
    }
    *(uint64_t*)addr = value;
    return 0;
}

// /proc/self/maps 显示了进程映射了的内存区域和访问权限
// 找到进程中关于 module_name 的内存区域。即拿到虚拟地址空间的起始地址
uint64_t get_module_base(pid_t pid, const char* module_name) {
    FILE* fp = NULL;
    uint64_t addr = 0;
    char* addr_range = NULL;
    char file_name[32] = {0};
    char line[1024] = {0};
    if (pid < 0) {
        snprintf(file_name, sizeof(file_name), "/proc/self/maps");
    } else {
        snprintf(file_name, sizeof(file_name), "/proc/%d/maps", pid);
    }
    fp = fopen(file_name, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            // std::cout << "get module base line: " << line << std::endl;
            if (strstr(line, module_name)) {
                addr_range = strtok(line, "-");
                addr = strtoul(addr_range, NULL, 16);
                if (addr == 0x400000) {
                    addr = 0;
                }
                // std::cout << "addr: " << std::hex << addr << std::endl;
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

// 获取 .got 段表的段虚拟地址和段的长度
int get_got_table_info(const char* lib, uint64_t* base, uint64_t* size) {
    int fd = open(lib, O_RDONLY);
    if (fd < 0) {
        std::cerr << "open file err: " << strerror(errno) << std::endl;
        return -1;
    }
    // 读取 ELF 文件的 Header
    Elf64_Ehdr elf_header;
    memset(&elf_header, 0, sizeof(elf_header));
    read(fd, &elf_header, sizeof(elf_header));

    // 读取 ELF 文件的段表
    Elf64_Shdr elf_section_header;
    memset(&elf_section_header, 0, sizeof(elf_section_header));
    // elf_header.e_shstrndx：段表字符串表所在的段在段表中的下标
    // elf_header.e_shentsize：段表描述符的大小
    // elf_header.e_shoff 指示了 ELF 文件中段表的位置
    // 读取段表字符串表。段表字符串表用来保存段表中用到的字符串，比如段名
    lseek(fd, elf_header.e_shstrndx * elf_header.e_shentsize + elf_header.e_shoff, SEEK_SET);
    read(fd, &elf_section_header, sizeof(elf_section_header));

    // elf_section_header.sh_size 段的长度
    char* lp_string_table = (char*)malloc(elf_section_header.sh_size);
    if (lp_string_table == NULL) {
        std::cerr << "malloc err: " << strerror(errno) << std::endl;
        close(fd);
        return -1;
    }
    // elf_section_header.sh_offset：段偏移，如果该段存在于文件中，则表示该段在文件中的偏移，否则无意义
    lseek(fd, elf_section_header.sh_offset, SEEK_SET);
    // 读取这个段（段表字符串表 Section Header String Table）
    read(fd, lp_string_table, elf_section_header.sh_size);

    // 将文件指针偏移到 ELF 文件中段表的位置
    lseek(fd, elf_header.e_shoff, SEEK_SET);
    int res = -1;
    // elf_header.e_shnum：段表描述符数量，也就是 ELF 文件中拥有的段的数量
    // 读取每个段表
    for (int i = 0;i < elf_header.e_shnum; i++) {
        memset(&elf_section_header, 0, sizeof(elf_section_header));
        read(fd, &elf_section_header, sizeof(elf_section_header));
        // 找到 ".got" 段表。 
        if (elf_section_header.sh_type == SHT_PROGBITS) {
            // sh_name：段名，是个字符串，位于 ".shstrtab" 的字符串表。sh_name 是段名字符串在 ".shstrtab" 中的偏移
            // 通过比较当前段表的段名，获取到 sh_addr、sh_size
            // sh_addr：段虚拟地址，如果该段可以被加载，则 sh_addr 为该段被加载后在进程地址空间中的虚拟地址；否则为0
            // sh_size：段的长度
            if (strcmp(lp_string_table+elf_section_header.sh_name, ".got") == 0) {
                *base = elf_section_header.sh_addr;
                *size = elf_section_header.sh_size;
                res = 0;
                break;
            }
        }
    }
    close(fd);
    return res;
}

/**
 * @brief hook 的入口函数
 * 
 * @param lib 可以是二进制文件，也可以是 so 文件
 * @param symbol 需要 hook 的符号（函数）地址
 * @param new_func 需要替换的函数地址
 * @param old_func 保存原始的函数地址
 * @return int 成功与否
 */
int hook_func(const char* lib, void* symbol, void* new_func, void** old_func) {
    uint64_t got_off, got_size;
    if (get_got_table_info(lib, &got_off, &got_size) < 0) {
        std::cerr << "get got table info err" << std::endl;
        return -1;
    }
    int res = -1;
    uint64_t base = get_module_base(-1, lib);
    if (base == 0) {
        std::cerr << "get module base failed, not find: " << lib << std::endl;
        return -2;
    }
    // 依次遍历寻找这个符号，找到之后进行替换
    for (uint64_t i = 0; i < got_size; i += sizeof(uint64_t)) {
        if ((uint64_t)symbol == (*((uint64_t*)(base + got_off + i)))) {
            *old_func = symbol;
            write_data_to_addr(base + got_off + i, (uint64_t)new_func);
            res = 0;
        }
    }
    if (res < 0) {
        std::cerr << "unable find symbol addr in got table" << std::endl;
    }
    return res;
}
