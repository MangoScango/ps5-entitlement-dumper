#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#include "asset.h"
#include "elfldr.h"
#include "pt.h"

INCASSET(entitlements_elf, "entitlements.elf");

static void diag(const char *fmt, ...) {
  char buf[0x1f0];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  printf("entitlement-injector: %s\n", buf);
  fflush(stdout);
  klog_printf("entitlement-injector: %s\n", buf);
}

static void usage(const char *program) {
  diag("usage: %s [--pid <positive-pid>]", program);
}

static int parse_pid(const char *value, pid_t *pid) {
  char *end;
  long parsed;

  errno = 0;
  parsed = strtol(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed <= 0 ||
      parsed > INT_MAX) {
    return -1;
  }

  *pid = (pid_t)parsed;
  return 0;
}

static int enable_ptrace_debug(uint8_t saved_flags[16], int *changed) {
  uint8_t updated_flags[16];

  if (kernel_get_qaflags(saved_flags)) {
    diag("kernel_get_qaflags failed");
    return -1;
  }

  memcpy(updated_flags, saved_flags, sizeof(updated_flags));
  updated_flags[1] |= 0x03;
  *changed = memcmp(saved_flags, updated_flags, sizeof(updated_flags)) != 0;
  if (*changed && kernel_set_qaflags(updated_flags)) {
    diag("kernel_set_qaflags(enable ptrace) failed");
    return -1;
  }

  return 0;
}

static int restore_ptrace_debug(const uint8_t saved_flags[16], int changed) {
  if (changed && kernel_set_qaflags(saved_flags)) {
    diag("kernel_set_qaflags(restore) failed");
    return -1;
  }

  return 0;
}

/*
 * Walk the kernel process table (KERN_PROC_ALL) looking for an eboot.bin
 * that is jailed differently from our own process.  The injector runs inside
 * SceSpZeroConf; a game is jailed to its own app directory, so its jaildir
 * differs from ours.  Returns the PID on success, -1 if none found or if
 * more than one candidate exists (prints all candidates so the caller can
 * pass --pid explicitly).
 */
static pid_t find_game_pid(void) {
  int mib[4] = {1, 14, 8, 0};
  intptr_t my_jaildir = kernel_get_proc_jaildir(getpid());
  pid_t candidates[32];
  int ncand = 0;
  size_t buf_size;
  uint8_t *buf;

  if (sysctl(mib, 4, NULL, &buf_size, NULL, 0)) {
    diag("sysctl(KERN_PROC_ALL) size: %s", strerror(errno));
    return -1;
  }
  if (!(buf = malloc(buf_size))) {
    diag("malloc failed");
    return -1;
  }
  if (sysctl(mib, 4, buf, &buf_size, NULL, 0)) {
    diag("sysctl(KERN_PROC_ALL): %s", strerror(errno));
    free(buf);
    return -1;
  }

  for (uint8_t *ptr = buf; ptr < buf + buf_size; ) {
    int ki_structsize = *(int *)ptr;
    pid_t ki_pid      = *(pid_t *)(ptr + 72);
    char *ki_tdname   = (char *)(ptr + 447);
    ptr += ki_structsize;

    if (strcmp(ki_tdname, "eboot.bin") != 0 || ki_pid == getpid())
      continue;
    /* skip SceSpZeroConf (our host) and any other process sharing our jail */
    if (kernel_get_proc_jaildir(ki_pid) == my_jaildir)
      continue;
    if (ncand < 32)
      candidates[ncand] = ki_pid;
    ncand++;
  }
  free(buf);

  if (ncand == 1) {
    diag("found game pid=%d", candidates[0]);
    return candidates[0];
  }
  if (ncand == 0) {
    diag("no game process found (is a game running?)");
  } else {
    diag("multiple game candidates (%d); use --pid to select:", ncand);
    for (int i = 0; i < ncand && i < 32; i++)
      diag("  candidate pid=%d", candidates[i]);
  }
  return -1;
}

int main(int argc, char *argv[]) {
  uint8_t saved_flags[16];
  pid_t target_pid = -1;
  int flags_changed = 0;
  int ret = 1;

  if (argc == 1) {
    target_pid = find_game_pid();
    if (target_pid < 0)
      return 1;
  } else if (argc == 3 && strcmp(argv[1], "--pid") == 0) {
    if (parse_pid(argv[2], &target_pid) || target_pid == getpid()) {
      usage(argv[0]);
      return 1;
    }
    diag("selected target pid=%d", target_pid);
  } else {
    usage(argv[0]);
    return 1;
  }

  if (elfldr_sanity_check(entitlements_elf, entitlements_elf_size)) {
    diag("embedded entitlements.elf failed validation");
    return 1;
  }

  if (enable_ptrace_debug(saved_flags, &flags_changed)) {
    return 1;
  }

  diag("attaching to pid=%d", target_pid);
  if (pt_attach(target_pid)) {
    diag("pt_attach failed: %s", strerror(errno));
    goto out;
  }

  diag("mapping and starting entitlements.elf in pid=%d", target_pid);
  if (elfldr_exec(target_pid, STDOUT_FILENO, entitlements_elf)) {
    diag("elfldr_exec failed");
    goto out;
  }

  diag("detached from pid=%d; inspect entitlement diagnostics in klog", target_pid);
  ret = 0;

out:
  if (restore_ptrace_debug(saved_flags, flags_changed)) {
    ret = 1;
  }
  return ret;
}
