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

#include <sys/mman.h>
#include <sys/_iovec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/mdioctl.h>
#include <sys/ioctl.h>

#include <machine/param.h>
#include <ps5/payload.h>
#include <ps5/klog.h>
#include "payload_bin.c"

int patch_app_db(void);
int sceKernelSetProcessName(const char *name);

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))

#define IOVEC_ENTRY(x) { (void*)(x), (x) ? strlen(x) + 1 : 0 }
#define IOVEC_SIZE(x)  (sizeof(x) / sizeof(struct iovec))

#define MD_UNIT_MAX 256

static int remount_system_ex(void) {
    struct iovec iov[] = {
        IOVEC_ENTRY("from"),      IOVEC_ENTRY("/dev/ssd0.system_ex"),
        IOVEC_ENTRY("fspath"),    IOVEC_ENTRY("/system_ex"),
        IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
        IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
        IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
        IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
        IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
    };
    return nmount(iov, IOVEC_SIZE(iov), MNT_UPDATE);
}

static int mount_nullfs(const char* src, const char* dst) {
    struct iovec iov[] = {
        IOVEC_ENTRY("fstype"), IOVEC_ENTRY("nullfs"),
        IOVEC_ENTRY("from"),   IOVEC_ENTRY(src),
        IOVEC_ENTRY("fspath"), IOVEC_ENTRY(dst),
    };
    return nmount(iov, IOVEC_SIZE(iov), 0);
}

// IMAGE TYPE DETECTION
#define UFS2_MAGIC          0x19540119
#define SBLOCK_UFS2_OFFSET  65536      // 64 KB
// Offsets within the superblock
#define OFFSET_UFS_FSIZE        52         // fs_fsize (int32_t)
#define OFFSET_UFS_FSBTODB      100        // fs_fsbtodb (int32_t)
#define OFFSET_UFS_MAGIC        1372       // fs_magic (int32_t)

static int32_t detect_is_ufs(const char* file_path) {
    FILE* fp = fopen(file_path, "rb");
    if (!fp) return 0;
    int32_t fsize = 0, fsbtodb = 0, magic = 0;

    // Verify Magic Number
    if (fseek(fp, SBLOCK_UFS2_OFFSET + OFFSET_UFS_MAGIC, SEEK_SET) == 0)
        fread(&magic, 4, 1, fp);
    if (magic != UFS2_MAGIC) {
        printf("Not a valid UFS image (Magic mismatch).\n");
        fclose(fp);
        return 0;
    }

    // Read fragment size and shift count
    if (fseek(fp, SBLOCK_UFS2_OFFSET + OFFSET_UFS_FSIZE, SEEK_SET) == 0)
        fread(&fsize, 4, 1, fp);

    if (fseek(fp, SBLOCK_UFS2_OFFSET + OFFSET_UFS_FSBTODB, SEEK_SET) == 0)
        fread(&fsbtodb, 4, 1, fp);

    // Calculate Sector Size
    // sector_size = fsize / (2^fsbtodb)
    int32_t sector_size = fsize < 512 ? 0 : (fsize >> fsbtodb);

    fclose(fp);
    return sector_size;
}

#define OFFSET_EXFAT_MAGIC 3
#define OFFSET_EXFAT_SHIFT 108
static int32_t detect_is_exfat(const char *file_path) {
    FILE *fp = fopen(file_path, "rb");
    if (!fp) return 0;

    char magic[9] = {0};
    uint8_t shift = 0;

    // Verify Magic Number ("EXFAT   " at offset 3)
    if (fseek(fp, OFFSET_EXFAT_MAGIC, SEEK_SET) == 0)
        fread(magic, 1, 8, fp);
    if (strncmp(magic, "EXFAT   ", 8) != 0) {
        printf("Not a valid EXFAT image (Magic mismatch).\n");
        fclose(fp);
        return 0;
    }

    // Read BytesPerSectorShift at offset 108
    if (fseek(fp, OFFSET_EXFAT_SHIFT, SEEK_SET) == 0)
        fread(&shift, 1, 1, fp);

    // Calculation: 2^shift
    // Valid values for exFAT are 9 (512 bytes) through 12 (4096 bytes)
    int32_t sector_size = shift < 9 ? 0 : (1 << shift);

    fclose(fp);
    return sector_size;
}

static int mount_ufs_image(const char* file_path, const char* mount_point, const char* fs, int sector_size, char* dev_path, size_t dev_path_len) {
    struct stat st;
    if (stat(file_path, &st) != 0) {
        klog_printf("stat failed: %s", strerror(errno));
        return 0;
    }

    int mdctl = open("/dev/mdctl", O_RDWR);
    if (mdctl < 0) {
        klog_printf("/dev/mdctl open failed: %s", strerror(errno));
        return 0;
    }

    struct md_ioctl mdio;
    char current_file[PATH_MAX];
    int exist = 0;
    int ret;

    for (int unit = 0; unit < MD_UNIT_MAX; unit++) {
        memset(&mdio, 0, sizeof(mdio));
        mdio.md_version = MDIOVERSION;
        mdio.md_unit = unit;
        mdio.md_file = current_file;

        if (ioctl(mdctl, (unsigned long)MDIOCQUERY, &mdio) == 0) {
            if (mdio.md_type == MD_VNODE && strcmp(current_file, file_path) == 0) {
                exist = 1;
                break;
            }
        }
    }

    if (!exist) {
        memset(&mdio, 0, sizeof(mdio));
        mdio.md_version    = MDIOVERSION;
        mdio.md_type       = MD_VNODE;
        mdio.md_file       = (char*)file_path;
        mdio.md_mediasize  = st.st_size;
        mdio.md_sectorsize = sector_size;
        mdio.md_options    = MD_AUTOUNIT;

        ret = ioctl(mdctl, (unsigned long)MDIOCATTACH, &mdio);
        if (ret != 0) {
            klog_printf("MDIOCATTACH failed: %s (errno %d)", strerror(errno), errno);
            close(mdctl);
            return 0;
        }
    }

    snprintf(dev_path, dev_path_len, "/dev/md%u", mdio.md_unit);
    close(mdctl);

    klog_printf("Image attached as %s", dev_path);

    struct iovec iov_ufs[] = {
        IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("ufs"),
        IOVEC_ENTRY("fspath"),    IOVEC_ENTRY(mount_point),
        IOVEC_ENTRY("from"),      IOVEC_ENTRY(dev_path),
        IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
        IOVEC_ENTRY("noatime"),   IOVEC_ENTRY(NULL),
    };
    int iov_ufs_count = sizeof(iov_ufs) / sizeof(iov_ufs[0]);

    struct iovec iov_exfat[] = {
        IOVEC_ENTRY("fstype"),    IOVEC_ENTRY("exfatfs"),
        IOVEC_ENTRY("fspath"),    IOVEC_ENTRY(mount_point),
        IOVEC_ENTRY("from"),      IOVEC_ENTRY(dev_path),
        IOVEC_ENTRY("large"),     IOVEC_ENTRY("yes"),
        IOVEC_ENTRY("timezone"),  IOVEC_ENTRY("static"),
        IOVEC_ENTRY("async"),     IOVEC_ENTRY(NULL),
        IOVEC_ENTRY("ignoreacl"), IOVEC_ENTRY(NULL),
        IOVEC_ENTRY("noatime"),   IOVEC_ENTRY(NULL),
    };
    int iov_exfat_count = sizeof(iov_exfat) / sizeof(iov_exfat[0]);

    struct iovec* iov = (fs[0] == 'u') ? iov_ufs : iov_exfat;
    int iov_count = (fs[0] == 'u') ? iov_ufs_count : iov_exfat_count;
    int ro = 0;

    // Prefer RW first for install compatibility
    ret = nmount(iov, iov_count, 0);
    if (ret != 0) {
        klog_printf("nmount rw failed: %s - falling back to rdonly", strerror(errno));
        ret = nmount(iov, iov_count, MNT_RDONLY);
        if (ret != 0) {
            klog_printf("nmount ufs failed: %s", strerror(errno));
            return 0;
        }
        ro = 1;
    }

    klog_printf("Image mounted OK -> %s (%s)", mount_point, ro ? "ro" : "rw");
    return 1;
}

static void unmount_ufs_image(const char* mount_point, const char* dev_path) {
    unmount(mount_point, MNT_FORCE);

    struct md_ioctl mdio = {0};
    mdio.md_version = MDIOVERSION;
    if (sscanf(dev_path, "/dev/md%u", &mdio.md_unit) > 0) {
        int mdctl = open("/dev/mdctl", O_RDWR);
        if (mdctl < 0) {
            klog_printf("/dev/mdctl open failed: %s", strerror(errno));
            return;
        }

        ioctl(mdctl, (unsigned long)MDIOCDETACH, &mdio);
        close(mdctl);
    }
}

static int bind_mount_title(const char* title_id, const char* src) {
    char dst[PATH_MAX];
    struct stat st;

    snprintf(dst, sizeof(dst), "/system_ex/app/%s/sce_sys", title_id);
    if (stat(dst, &st) == 0) {
        klog_printf("Title already mounted: %s\n", title_id);
        return 0;
    }

    snprintf(dst, sizeof(dst), "/system_ex/app/%s", title_id);
    struct statfs sfs;
    if (statfs(dst, &sfs) == 0 && strcmp(sfs.f_fstypename, "nullfs") != 0) {
        unmount_ufs_image(dst, sfs.f_mntfromname);
    } else if (unmount(dst, MNT_FORCE) != 0 && errno != EINVAL) {
        klog_perror("Failed to unmount partially mounted title");
    }

    if (mkdir(dst, 0755) && errno != EEXIST) {
        klog_perror("Failed to create mount directory for title");
        return -1;
    }

    char dev_path[32] = {0};
    int sector_size = 0;
    if (src[0] == '/') {
        if (mount_nullfs(src, dst) != 0) {
            klog_perror("Failed to bind mount title with mount_nullfs");
            return -1;
        }
    } else if (memcmp(src, "ufs:", 4) == 0 && (sector_size = detect_is_ufs(src + 4)) > 0) {
        if (!mount_ufs_image(src + 4, dst, "ufs", sector_size, dev_path, sizeof(dev_path))) {
            klog_perror("Failed to bind mount title with mount_ufs_image");
            unmount_ufs_image(dst, dev_path);
            return -1;
        }
    } else if (memcmp(src, "exfatfs:", 8) == 0 && (sector_size = detect_is_exfat(src + 8)) > 0) {
        if (!mount_ufs_image(src + 8, dst, "exfatfs", sector_size, dev_path, sizeof(dev_path))) {
            klog_perror("Failed to bind mount title with mount_ufs_image");
            unmount_ufs_image(dst, dev_path);
            return -1;
        }
    } else {
        klog_perror("Failed to bind mount title with not supported fs");
        return -1;
    }

    klog_printf("Title Mounted Successfully: %s -> %s\n", src, dst);
    return 0;
}

static int read_mount_link(const char* path, char* buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        klog_perror("Failed to open mount.lnk file");
        return -1;
    }

    memset(buf, 0, size);
    ssize_t n = read(fd, buf, size - 1);
    if (n < 0) {
        klog_perror("Failed to read mount.lnk file");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int bind_mount_all_titles(const char* path) {
    char mountlnk[PATH_MAX];
    struct dirent *entry;
    struct stat st;
    DIR *dir = opendir(path);

    if (!dir) {
        klog_perror("Failed to open directory while binding mounts");
        return -1;
    }

    while ((entry = readdir(dir))) {
        if (strlen(entry->d_name) != 9) {
            continue;
        }

        snprintf(mountlnk, sizeof(mountlnk), "%s/%s/mount.lnk", path, entry->d_name);

        if (stat(mountlnk, &st) != 0) {
            continue;
        }

        if (read_mount_link(mountlnk, mountlnk, sizeof(mountlnk)) != 0) {
            klog_printf("Failed to read mount.lnk for title %s\n", entry->d_name);
            continue;
        }

        if (bind_mount_title(entry->d_name, mountlnk) != 0) {
            klog_printf("Failed to bind mount title %s -> %s\n", entry->d_name, mountlnk);
            continue;
        }

        klog_printf("Successfully mounted title %s -> %s\n", entry->d_name, mountlnk);
    }

    closedir(dir);
    return 0;
}

static int monitor_usb_changes(void) {
    struct kevent evt;
    int kq;

    if ((kq = kqueue()) < 0) {
        klog_perror("Failed to create kqueue");
        return -1;
    }

    EV_SET(&evt, 0, EVFILT_FS, EV_ADD | EV_CLEAR, 0, 0, 0);
    if (kevent(kq, &evt, 1, NULL, 0, NULL) < 0) {
        klog_perror("Failed to register usb event filter with kevent");
        close(kq);
        return -1;
    }

    while (1) {
        if (kevent(kq, NULL, 0, &evt, 1, NULL) < 0) {
            klog_perror("kevent wait failed while monitoring USB changes");
            break;
        }

        if (bind_mount_all_titles("/user/app") < 0) {
            klog_perror("Failed to bind mount /user/app titles after USB change");
        }
    }

    close(kq);
    return 0;
}

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

    // Compute size of virtual memory region.
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

    // allocate memory.
    if((base=mmap(base, base_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Parse program headers.
    for(int i=0; i<ehdr->e_phnum; i++) {
        switch(phdr[i].p_type) {
        case PT_LOAD:
            pt_load(___ps5_kstuff_payload_bin, base, &phdr[i]);
            break;
        }
    }

    // Set protection bits on mapped segments.
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

    void (*entry)(payload_args_t*) = base + ehdr->e_entry;
    payload_args_t* args = payload_get_args();

    entry(args);
    if(*args->payloadout == 0) {
        puts("patching app.db");
        *args->payloadout = patch_app_db();
    }

    klog_printf("Remounting /system_ex and mounting titles...\n");
    remount_system_ex();
    bind_mount_all_titles("/user/app");

    monitor_usb_changes();

    return 0; 
}
