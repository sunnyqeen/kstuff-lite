#define sysctl __sysctl
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <sys/thr.h>
#include <sys/sysctl.h>
#include <machine/sysarch.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <signal.h>
#include <stddef.h>
#include <time.h>
#include <unistd.h>
#include "../prosper0gdb/r0gdb.h"
#include "../prosper0gdb/offsets.h"
#include "../gdb_stub/dbg.h"

extern uint64_t kdata_base;

#define SYS_mdbg_call 573
#define SYS_dynlib_dlsym 591
#define SYS_dynlib_get_info_ex 608

struct module_segment
{
    uint64_t addr;
    uint32_t size;
    uint32_t flags;
};

struct module_info_ex
{
    size_t st_size;
    char name[256];
    int id;
    uint32_t tls_index;
    uint64_t tls_init_addr;
    uint32_t tls_init_size;
    uint32_t tls_size;
    uint32_t tls_offset;
    uint32_t tls_align;
    uint64_t init_proc_addr;
    uint64_t fini_proc_addr;
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t eh_frame_hdr_addr;
    uint64_t eh_frame_addr;
    uint32_t eh_frame_hdr_size;
    uint32_t eh_frame_size;
    struct module_segment segments[4];
    uint32_t segment_count;
    uint32_t ref_count;
};

int find_proc(const char* name);

void list_proc(void)
{
    for(int pid = 1; pid < 1024; pid++)
    {
        size_t sz = 1096;
        int key[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
        char buf[1097] = {0};
        sysctl(key, 4, buf, &sz, 0, 0);
        char* name = buf + 447;
        if(!*name)
            continue;
        *--name = ' ';
        for(int q = pid; q; q /= 10)
            *--name = '0' + q % 10;
        size_t l = 0;
        while(name[l])
            l++;
        name[l++] = '\n';
        gdb_remote_syscall("write", 3, 0, (uintptr_t)1, (uintptr_t)name, (uintptr_t)l);
    }
}

#define KEKCALL_GETPPID        0x000000027
#define KEKCALL_READ_DR        0x100000027
#define KEKCALL_WRITE_DR       0x200000027
#define KEKCALL_RDMSR          0x300000027
#define KEKCALL_REMOTE_SYSCALL 0x500000027
#define KEKCALL_CHECK          0xffffffff00000027

asm(".section .text\nkekcall:\nmov 8(%rsp), %rax\njmp *p_kekcall(%rip)");
uint64_t kekcall(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t nr);

static int64_t do_remote_syscall(int pid, int sysc, ...)
{
    static uint64_t args_p = 0;
    if(!args_p)
        args_p = r0gdb_kmalloc(48);
    uint64_t args[6];
    va_list l;
    va_start(l, sysc);
    for(int i = 0; i < 6; i++)
        args[i] = va_arg(l, uint64_t);
    va_end(l);
    uint64_t proc;
    uint64_t target = 0;
    copyout(&proc, offsets.allproc, 8);
    while(proc)
    {
        uint32_t pid1;
        copyout(&pid1, proc+0xbc, 4);
        if(pid1 == pid)
        {
            target = proc;
            break;
        }
        copyout(&proc, proc, 8);
    }
    if(!target)
        asm volatile("ud2");
    uint64_t target_thread;
    copyout(&target_thread, target+16, 8);
    copyin(args_p, args, 48);
    uint64_t syscall_fn;
    copyout(&syscall_fn, offsets.sysents+48*sysc+8, 8);
    int err = r0gdb_kfncall(syscall_fn, target_thread, args_p);
    if(err)
        return -err;
    int64_t ans;
    copyout(&ans, target_thread+0x408, 8);
    return ans;
}

int my_nmount(void* a, int b, int c)
{
    return kekcall((uintptr_t)a, b, c, 0, 0, 0, SYS_nmount);
}
