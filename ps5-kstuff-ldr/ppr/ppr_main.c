#include "a53_transport.h"
#include "notify.h"
#include "ppr_patch.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <ps5/kernel.h>

#define printf ppr_printf
#define puts ppr_puts

#ifndef PPR_DEFAULT_ACTION
#define PPR_DEFAULT_ACTION PPR_PATCH_INSTALL
#endif
#ifndef PPR_DEFAULT_IDLE_ACK
#define PPR_DEFAULT_IDLE_ACK 1
#endif
#ifndef PPR_DEFAULT_FAST
#define PPR_DEFAULT_FAST 1
#endif
#ifndef PPR_DEFAULT_PERSISTENT
#define PPR_DEFAULT_PERSISTENT 1
#endif
#ifndef PPR_DEFAULT_BATCH
#define PPR_DEFAULT_BATCH 1
#endif
#ifndef PPR_DEFAULT_MIXED_IO
#define PPR_DEFAULT_MIXED_IO 1
#endif
#ifndef PPR_DEFAULT_TIME_ACCELERATION
#define PPR_DEFAULT_TIME_ACCELERATION 1
#endif

static void raise_fd_limit(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 &&
        limit.rlim_cur < limit.rlim_max) {
        limit.rlim_cur = limit.rlim_max;
        (void)setrlimit(RLIMIT_NOFILE, &limit);
    }
}

static int ppr_main(void) {
    setbuf(stdout, NULL);
    raise_fd_limit();

    enum ppr_patch_action action =
        (enum ppr_patch_action)PPR_DEFAULT_ACTION;
    int idle_acknowledged = PPR_DEFAULT_IDLE_ACK;
    int fast_mode = PPR_DEFAULT_FAST;
    int time_acceleration = PPR_DEFAULT_TIME_ACCELERATION;
    struct a53_transport_options options = {
        .persistent = PPR_DEFAULT_PERSISTENT,
        .batch = PPR_DEFAULT_BATCH,
        .mixed_io = PPR_DEFAULT_MIXED_IO,
    };

    /* Installation/restoration is fast by default even through the
     * argument-driven payload. Status stays minimal, and an explicit
     * transport selection (especially --conservative) is never overridden. */
    if (action != PPR_PATCH_STATUS && !fast_mode &&
        !options.persistent && !options.batch && !options.mixed_io) {
        fast_mode = 1;
        options.persistent = 1;
        options.batch = 1;
        options.mixed_io = 1;
    }

    uint32_t system_firmware = kernel_get_fw_version() & 0xffff0000U;
    printf("[+] FW: 0x%x\n", system_firmware);
    if (options.mixed_io && !options.batch) {
        puts("[*] mixed I/O requires batch mode; disabling mixed I/O");
        options.mixed_io = 0;
    }

    const struct a53_transport_options conservative = {0, 0, 0};
    if (a53_transport_initialize(&conservative) != 0)
        return 1;
    if (time_acceleration) {
        if (a53_transport_enable_time_acceleration() != 0) {
            puts("[!] could not safely enable phase5 time acceleration");
            return 1;
        }
    }

    char version[160];
    if (a53_transport_get_version(version, sizeof(version)) != 0) {
        puts("[!] initial GET_CONF failed");
        return 1;
    }
    printf("[*] version string: \"%s\"\n", version);

    uint32_t a53_firmware = a53_transport_parse_release(version);
    if (a53_firmware)
        printf("[*] A53 release parsed as FW 0x%08x\n", a53_firmware);
    else
        puts("[!] A53 release suffix missing; using system firmware");
    if (a53_firmware && a53_firmware != system_firmware)
        printf("[!] system FW 0x%08x != A53 FW 0x%08x\n",
               system_firmware, a53_firmware);

    uint32_t target_firmware = a53_firmware ? a53_firmware : system_firmware;
    enum ppr_target_type target = ppr_patch_parse_target(version);
    printf("[*] A53 target: %s\n", ppr_patch_target_name(target));
    if (!ppr_patch_target_supported(target_firmware, target)) {
        printf("[!] no exact PPR profile for FW 0x%08x target %s\n",
               target_firmware, ppr_patch_target_name(target));
        return 1;
    }

    int fast_probe = a53_transport_verify_and_enable_fast(&options);
    if (fast_probe < 0) {
        puts("[!] could not initialize the verified fast transport");
        return 1;
    }
    if (fast_probe > 0)
        puts("[*] one or more fast transports failed validation; continuing with verified fallbacks");

    struct ppr_patch_transport transport;
    a53_transport_make_ppr(&transport, fast_mode);
    int result = ppr_patch_run_target(&transport, target_firmware, target,
                                      action, idle_acknowledged);
    ppr_notify_flush();
    return result == 0 ? 0 : 1;
}

int ppr_patch(void) {
    int ret = ppr_main();
    ppr_notify_flush();
    return ret;
}
