/* Copyright (C) 2025 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */           

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <limits.h>
#include <stdbool.h>

#include <sys/mman.h>
#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/event.h>

#include <machine/param.h>
#include <ps5/payload.h>
#include <ps5/klog.h>
#include <ps5/kernel.h>

#include "shellui_patch.h"
#include "utils.h"
#include "../../lib/r0gdb-bootstrap.h"
#include "../../lib/shellcore-imports.h"

asm(".section .rodata\n"
    ".global ___ps5_kstuff_payload_bin\n"
    "___ps5_kstuff_payload_bin:\n"
    ".incbin \"../../ps5-kstuff/payload.bin\"\n");

extern char ___ps5_kstuff_payload_bin[];
int shellcore_import_got(int pid, uint64_t image_base, uint32_t required_mask,
                         uint64_t got[SHELLCORE_IMPORT_COUNT]);

int patch_app_db(void);
int sceKernelSetProcessName(const char *name);
int monitor_usb_changes(void);
int ppr_patch(void);

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
                     (((x) & PF_W) ? PROT_WRITE : 0) | \
                     (((x) & PF_X) ? PROT_EXEC  : 0))

static void
pt_load(const void* image, void* base, Elf64_Phdr *phdr) {
  if(phdr->p_memsz && phdr->p_filesz) {
      memcpy(base + phdr->p_vaddr, image + phdr->p_offset, phdr->p_filesz);
  }
}

int main(void) {
    sceKernelSetProcessName("kstuff.elf");
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)___ps5_kstuff_payload_bin;
    Elf64_Phdr *phdr = (Elf64_Phdr*)(___ps5_kstuff_payload_bin + ehdr->e_phoff);
    void *base = (void*)0x0000000926100000;
    uintptr_t min_vaddr = -1;
    uintptr_t max_vaddr = 0;
    size_t base_size;

    for(int i=0; i<ehdr->e_phnum; i++) {
        if(phdr[i].p_vaddr < min_vaddr) {
            min_vaddr = phdr[i].p_vaddr;
        }
        if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
        }
    }
    min_vaddr = TRUNC_PG(min_vaddr);
    max_vaddr = ROUND_PG(max_vaddr);
    base_size = max_vaddr - min_vaddr;

    if((base=mmap(base, base_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    for(int i=0; i<ehdr->e_phnum; i++) {
        switch(phdr[i].p_type) {
        case PT_LOAD:
            pt_load(___ps5_kstuff_payload_bin, base, &phdr[i]);
            break;
        }
    }

    for(int i=0; i<ehdr->e_phnum; i++) {
        if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
            continue;
        }
        if(mprotect(base + phdr[i].p_vaddr, ROUND_PG(phdr[i].p_memsz),
                    PFLAGS(phdr[i].p_flags))) {
            perror("mprotect");
            return EXIT_FAILURE;
        }
    }

    void (*entry)(payload_args_t*, uint64_t,
                  intptr_t (*)(int, uint32_t, const char*),
                  int (*)(int, const char*, uint32_t*),
                  kstuff_shellcore_imports_fn) =
        base + ehdr->e_entry;
    payload_args_t* args = payload_get_args();

    // allow dlsym on 5.00+ - https://gist.github.com/TheOfficialFloW/7174351201b5260d7780780f4059bebf#file-exploitnetcontrolimpl-java-L851
    uint64_t proc = kernel_get_proc(-1);
    uint64_t p_dynlib = kernel_getlong(proc + 0x3e8);
    uint64_t dynlib_eboot = kernel_getlong(p_dynlib + 0x00);
    uint64_t eboot_segments = kernel_getlong(dynlib_eboot + 0x40);
    kernel_setlong(eboot_segments + 0x08, 0); // addr
    kernel_setlong(eboot_segments + 0x10, 0xFFFFFFFFFFFFFFFFL); // size

    entry(args, KSTUFF_DYNLIB_RESOLVER_MAGIC,
          kernel_dynlib_resolve, kernel_dynlib_handle,
          shellcore_import_got);
    if(*args->payloadout == 0) {
        puts("patching app.db");
        *args->payloadout = patch_app_db();
    }

    ppr_patch();

    start_shellui_patch_thread();

    monitor_usb_changes();

    return 0; 
}
