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
#include <ps5/kernel.h>

enum {
  SYSTEM_STATE_MGR_STATE_INVALID = 0u,
  SYSTEM_STATE_MGR_STATE_INITIALIZING = 10u,
  SYSTEM_STATE_MGR_STATE_SHUTDOWN_ON_GOING = 100u,
  SYSTEM_STATE_MGR_STATE_POWER_SAVING = 200u,
  SYSTEM_STATE_MGR_STATE_SUSPEND_ON_GOING = 300u,
  SYSTEM_STATE_MGR_STATE_MAIN_ON_STANDBY = 500u,
  SYSTEM_STATE_MGR_STATE_WORKING = 1000u,
};
int sceKernelOpenEventFlag(void** handle, const char *name);
int sceKernelPollEventFlag(void* handle, uint64_t bit_pattern,
                           unsigned int wait_mode, uint64_t *result_pattern);
int sceKernelCloseEventFlag(void* handle);

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

static int automount_disabled(void) {
    return access("/data/.kstuff_noautomount", F_OK) == 0;
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

static int scan_and_mount_titles(void) {
    if (automount_disabled()) {
        return 0;
    }

    if (bind_mount_all_titles("/user/app") < 0) {
        klog_perror("Failed to bind mount /user/app titles");
        return -1;
    }

    return 0;
}

static int umount_all_ufs_titles(void) {
    if (automount_disabled()) {
        return 0;
    }

    struct dirent *entry;
    DIR *dir = opendir("/system_ex/app");

    if (!dir) {
        klog_perror("Failed to open directory while binding mounts");
        return -1;
    }

    while ((entry = readdir(dir))) {
        if (strlen(entry->d_name) != 9) {
            continue;
        }

        char dst[PATH_MAX];
        snprintf(dst, sizeof(dst), "%s/%s", "/system_ex/app", entry->d_name);
        struct statfs sfs;
        if (statfs(dst, &sfs) == 0 && strcmp(sfs.f_fstypename, "nullfs") != 0 &&
            strncmp(sfs.f_mntfromname, "/dev/md", 7) == 0) {
            klog_printf("Unmount dev %s -> %s\n", sfs.f_mntfromname, dst);
            unmount_ufs_image(dst, sfs.f_mntfromname);
        }
    }

    closedir(dir);
    return 0;
}

static const char *const watch_paths[] = {
    "/mnt",
    "/mnt/usb0", "/mnt/usb1", "/mnt/usb2", "/mnt/usb3",
    "/mnt/usb4", "/mnt/usb5", "/mnt/usb6", "/mnt/usb7"
};

#define WATCH_COUNT (sizeof(watch_paths) / sizeof(watch_paths[0]))

static unsigned int mounted_usb_roots() {
    struct stat parent;
    unsigned int mask = 0;

    if (stat(watch_paths[0], &parent) != 0) {
        return 0;
    }

    for (size_t i = 1; i < WATCH_COUNT; i++) {
        struct stat root;
        if (stat(watch_paths[i], &root) == 0 &&
            root.st_dev != parent.st_dev) {
            mask |= 1u << (i - 1);
        }
    }
    return mask;
}

int monitor_usb_changes(void) {
    struct kevent evt;
    int kq;
    int nev = -1;
    int ret;
    unsigned int usb_mask = 0;
    void* handle = 0;
    uint64_t pattern = 0, last_pattern = 0;

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

    remount_system_ex();

    ret = sceKernelOpenEventFlag(&handle, "SceSystemStateMgrInfo");
    if (ret) {
        klog_printf("sceKernelOpenEventFlag error %08x", ret);
    }

    while (1) {
        struct timespec tout = {0, 100000000};
        if ((nev = kevent(kq, NULL, 0, &evt, 1, &tout)) < 0) {
            klog_perror("kevent wait failed while monitoring USB changes");
            break;
        }

        if (nev > 0) {
            uint64_t status = pattern & 0xFFFF;
            if (status != SYSTEM_STATE_MGR_STATE_SUSPEND_ON_GOING && status != SYSTEM_STATE_MGR_STATE_SHUTDOWN_ON_GOING) {
                unsigned int mask = mounted_usb_roots();
                if (mask > 0 && mask != usb_mask) {
                    if (scan_and_mount_titles() < 0) {
                        klog_perror("Failed to scan and bind mount titles after USB change");
                    }
                }
                usb_mask = mask;
            }
        } else if (nev == 0 && handle) {
            ret = sceKernelPollEventFlag(handle, 0xFFFF, 0x02, &pattern);
            if (ret == 0) {
                if (pattern != last_pattern) {
                    uint64_t status = pattern & 0xFFFF;
                    if (status == SYSTEM_STATE_MGR_STATE_SUSPEND_ON_GOING || status == SYSTEM_STATE_MGR_STATE_SHUTDOWN_ON_GOING) {
                        umount_all_ufs_titles();
                    } else if (status == SYSTEM_STATE_MGR_STATE_WORKING) {
                        if (scan_and_mount_titles() < 0) {
                            klog_perror("Failed to scan and bind mount titles after USB change");
                        }
                    }
                    klog_printf("sceKernelPollEventFlag: %016x", pattern);
                    last_pattern = pattern;
                }
            } else {
                klog_printf("sceKernelPollEventFlag error %08x", ret);
            }
        }
    }

    if (handle) {
        sceKernelCloseEventFlag(handle);
    }
    close(kq);
    return 0;
}
