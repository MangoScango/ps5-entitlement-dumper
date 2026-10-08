#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/sysctl.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#ifndef SERVICE_LABEL
#define SERVICE_LABEL 0
#endif

#define SCE_NP_ENTITLEMENT_ACCESS_ERROR_NOT_INITIALIZED     0x817d0001
#define SCE_NP_ENTITLEMENT_ACCESS_ERROR_INVALID_ARGUMENT    0x817d0002
#define SCE_NP_ENTITLEMENT_ACCESS_ERROR_ALREADY_INITIALIZED 0x817d0003

#define SYSMODULE_IPMI 0x8000001d

#define SPRX_LIB_PATH  "/system/common/lib/"
#define ENT_SONAME     "libSceNpEntitlementAccess.sprx"
#define APPCO_SONAME   "libSceAppContent.sprx"
#define ENT_PATH       SPRX_LIB_PATH ENT_SONAME
#define APPCO_PATH     SPRX_LIB_PATH APPCO_SONAME

typedef uint32_t SceNpServiceLabel;

typedef struct SceNpUnifiedEntitlementLabel {
  char data[17]; // 16 chars + NUL
  char padding[3];
} SceNpUnifiedEntitlementLabel;

typedef struct SceNpEntitlementAccessAddcontEntitlementInfo {
  SceNpUnifiedEntitlementLabel entitlementLabel;
  int32_t packageType;
  int32_t downloadStatus;
} SceNpEntitlementAccessAddcontEntitlementInfo;

// Initialize rejects these unless every byte is zero.
typedef struct SceNpEntitlementAccessInitParam {
  uint8_t reserved[32];
} SceNpEntitlementAccessInitParam;

typedef struct SceNpEntitlementAccessBootParam {
  uint8_t reserved[32];
} SceNpEntitlementAccessBootParam;

typedef struct SceAppContentInitParam {
  uint8_t reserved[32];
} SceAppContentInitParam;

typedef struct SceAppContentBootParam {
  uint8_t reserved[32];
} SceAppContentBootParam;

typedef struct SceAppContentMountPoint {
  char data[16]; /* at most 15 chars + NUL */
} SceAppContentMountPoint;


_Static_assert(sizeof(SceNpEntitlementAccessAddcontEntitlementInfo) == 28,
               "AddcontEntitlementInfo size");
_Static_assert(sizeof(SceNpEntitlementAccessInitParam) == 32, "InitParam size");
_Static_assert(sizeof(SceNpEntitlementAccessBootParam) == 32, "BootParam size");

extern int sceKernelLoadStartModule(const char *path, size_t argc,
                                    const void *argv, uint32_t flags,
                                    void *opt, int *res);
extern int sceKernelStopUnloadModule(int handle, size_t argc, const void *argv,
                                     uint32_t flags, void *opt, int *res);
extern int32_t sceKernelGetAppInfo(pid_t pid, void *info);
extern int32_t sceSysmoduleLoadModuleInternal(uint32_t id);
extern int32_t sceSysmoduleUnloadModuleInternal(uint32_t id);

typedef struct {
  uint8_t data[16];
} SceNpEntitlementAccessEntitlementKey;

_Static_assert(sizeof(SceNpEntitlementAccessEntitlementKey) == 16, "EntitlementKey size");

typedef int32_t (*ent_initialize_t)(
    const SceNpEntitlementAccessInitParam *initParam,
    SceNpEntitlementAccessBootParam *bootParam);

typedef int32_t (*ent_get_addcont_list_t)(
    SceNpServiceLabel serviceLabel,
    SceNpEntitlementAccessAddcontEntitlementInfo *list, uint32_t listNum,
    uint32_t *hitNum);

typedef int32_t (*ent_get_key_t)(
    SceNpServiceLabel serviceLabel,
    const SceNpUnifiedEntitlementLabel *entitlementLabel,
    SceNpEntitlementAccessEntitlementKey *key);

typedef int32_t (*appco_initialize_t)(const SceAppContentInitParam *initParam,
                                      SceAppContentBootParam *bootParam);

typedef int32_t (*appco_addcont_mount_t)(
    SceNpServiceLabel serviceLabel,
    const SceNpUnifiedEntitlementLabel *entitlementLabel,
    SceAppContentMountPoint *mountPoint);

static ent_initialize_t ent_initialize;
static ent_get_addcont_list_t ent_get_addcont_list;
static ent_get_key_t ent_get_key;
static appco_initialize_t appco_initialize;
static appco_addcont_mount_t appco_addcont_mount;

static int g_ent_handle   = -1;
static int g_appco_handle = -1;

static const char *errname(int32_t rc) {
  switch ((uint32_t)rc) {
  case 0:
    return "OK";
  case SCE_NP_ENTITLEMENT_ACCESS_ERROR_NOT_INITIALIZED:
    return "NOT_INITIALIZED";
  case SCE_NP_ENTITLEMENT_ACCESS_ERROR_INVALID_ARGUMENT:
    return "INVALID_ARGUMENT";
  case SCE_NP_ENTITLEMENT_ACCESS_ERROR_ALREADY_INITIALIZED:
    return "ALREADY_INITIALIZED";
  default:
    return "UNKNOWN";
  }
}

static void diag(const char *fmt, ...) {
  char buf[0x1f0];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  printf("entitlements: %s\n", buf);
  fflush(stdout);
  klog_printf("entitlements: %s\n", buf);
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

static void usage(const char *program) {
  diag("usage: %s [--pid <positive-pid>]", program);
}

/* Walk KERN_PROC_ALL and return the PID of the sole eboot.bin process that
 * lives in a different jail from ours.  Returns -1 on any error or ambiguity.
 *
 * kinfo_proc offsets: ki_structsize @0, ki_pid @72, ki_tdname @447.
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
    /* skip any process sharing our jail (e.g. SceSpZeroConf acting as host) */
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

static intptr_t g_our_app_info_kaddr = 0;
static uint8_t  g_game_app_id[4];
static uint8_t  g_saved_app_info[0x88];

static int spoof_app_info(pid_t target_pid) {
    uint8_t game_info[0x88];
    uint8_t our_info[0x88];
    int32_t rc;

    rc = sceKernelGetAppInfo(target_pid, game_info);
    if (rc < 0) {
        diag("sceKernelGetAppInfo rc=0x%08x", (uint32_t)rc);
        return -1;
    }

    intptr_t game_proc = kernel_get_proc(target_pid);
    intptr_t our_proc  = kernel_get_proc(getpid());
    if (!game_proc || !our_proc) {
        diag("kernel_get_proc failed");
        return -1;
    }

    /* Packed layout: app_id(4) + unknown1(8) + app_type(4) + title_id(10) */
    const int TITLE_ID_OFF = 16;
    const char *title_id   = (char *)(game_info + TITLE_ID_OFF);
    size_t tid_len = strnlen(title_id, 10);
    if (tid_len < 4) {
        diag("game has no title_id — cannot locate app_info");
        return -1;
    }
    diag("locating title_id=%.10s", title_id);

    uint8_t proc_buf[0x1000];
    if (kernel_copyout(game_proc, proc_buf, sizeof(proc_buf)) != 0) {
        diag("kernel_copyout game proc failed");
        return -1;
    }

    int app_info_off = -1;
    for (int i = 0; i + TITLE_ID_OFF + (int)tid_len <= (int)sizeof(proc_buf); i++) {
        if (memcmp(proc_buf + i + TITLE_ID_OFF, title_id, tid_len) != 0) continue;
        app_info_off = i;
        diag("app_info at proc+0x%x", i);
        break;
    }
    if (app_info_off < 0) {
        diag("app_info not found in proc[0..0x1000]");
        return -1;
    }

    if (kernel_copyout(our_proc + app_info_off, our_info, sizeof(our_info)) != 0) {
        diag("kernel_copyout our app_info failed");
        return -1;
    }

    memcpy(g_game_app_id,    game_info, 4);
    memcpy(g_saved_app_info, our_info,  sizeof(our_info));
    g_our_app_info_kaddr = our_proc + app_info_off;

    /* Patch everything except app_id (offset 0, 4 bytes).  Patching app_id
     * before IPMI loads breaks things; swap it in afterward. */
    memcpy(our_info + 4, game_info + 4, sizeof(our_info) - 4);
    return kernel_copyin(our_info, g_our_app_info_kaddr, sizeof(our_info)) ? -1 : 0;
}

/* Called after IPMI loads so IPMI registers us under our own app_id first. */
static void patch_app_id(void) {
    if (g_our_app_info_kaddr)
        kernel_copyin(g_game_app_id, g_our_app_info_kaddr, 4);
}

static void restore_app_info(void) {
    if (g_our_app_info_kaddr)
        kernel_copyin(g_saved_app_info, g_our_app_info_kaddr,
                      sizeof(g_saved_app_info));
}

static void cleanup(void) {
    if (g_appco_handle >= 0) {
        int res = 0;
        sceKernelStopUnloadModule(g_appco_handle, 0, NULL, 0, NULL, &res);
        g_appco_handle = -1;
    }
    restore_app_info();
    if (g_ent_handle >= 0) {
        int res = 0;
        sceKernelStopUnloadModule(g_ent_handle, 0, NULL, 0, NULL, &res);
        g_ent_handle = -1;
    }
    sceSysmoduleUnloadModuleInternal(SYSMODULE_IPMI);
}

int main(int argc, char *argv[]) {
  SceNpEntitlementAccessInitParam initParam;
  SceNpEntitlementAccessBootParam bootParam;
  SceNpEntitlementAccessAddcontEntitlementInfo *list;
  SceNpServiceLabel label = SERVICE_LABEL;
  pid_t target_pid;
  uint32_t hitNum = 0;
  uint32_t fetched = 0;
  uint32_t count;
  int startRes = 0;
  int32_t rc;

  if (argc == 1) {
    target_pid = find_game_pid();
    if (target_pid < 0)
      return 1;
  } else if (argc == 3 && strcmp(argv[1], "--pid") == 0) {
    if (parse_pid(argv[2], &target_pid) || target_pid == getpid()) {
      usage(argv[0]);
      return 1;
    }
  } else {
    usage(argv[0]);
    return 1;
  }

  diag("start target_pid=%d label=%u", target_pid, label);

  if (spoof_app_info(target_pid))
    return 1;

  diag("sceSysmoduleLoadModuleInternal(0x%08x libSceIpmi) ...", SYSMODULE_IPMI);
  rc = sceSysmoduleLoadModuleInternal(SYSMODULE_IPMI);
  diag("sceSysmoduleLoadModuleInternal rc=0x%08x", (uint32_t)rc);
  if (rc < 0)
    return 1;

  /* IPMI has now registered our process under our own app_id.
   * Patch in the game's app_id so the NP service finds the right session. */
  patch_app_id();

  diag("sceKernelLoadStartModule(%s) ...", ENT_PATH);
  g_ent_handle = sceKernelLoadStartModule(ENT_PATH, 0, NULL, 0, NULL, &startRes);
  diag("sceKernelLoadStartModule handle=0x%08x start_res=0x%08x",
       (uint32_t)g_ent_handle, (uint32_t)startRes);
  if (g_ent_handle < 0)
    return 1;

  ent_initialize = (ent_initialize_t)kernel_dynlib_dlsym(
      -1, (uint32_t)g_ent_handle, "sceNpEntitlementAccessInitialize");
  diag("dlsym sceNpEntitlementAccessInitialize = %p", (void *)ent_initialize);
  if (!ent_initialize) {
    cleanup();
    return 1;
  }
  ent_get_addcont_list = (ent_get_addcont_list_t)kernel_dynlib_dlsym(
      -1, (uint32_t)g_ent_handle,
      "sceNpEntitlementAccessGetAddcontEntitlementInfoList");
  diag("dlsym sceNpEntitlementAccessGetAddcontEntitlementInfoList = %p",
       (void *)ent_get_addcont_list);
  if (!ent_get_addcont_list) {
    cleanup();
    return 1;
  }
  ent_get_key = (ent_get_key_t)kernel_dynlib_dlsym(
      -1, (uint32_t)g_ent_handle,
      "sceNpEntitlementAccessGetEntitlementKey");
  diag("dlsym sceNpEntitlementAccessGetEntitlementKey = %p",
       (void *)ent_get_key);
  if (!ent_get_key) {
    cleanup();
    return 1;
  }

  memset(&initParam, 0, sizeof(initParam));
  memset(&bootParam, 0, sizeof(bootParam));
  diag("sceNpEntitlementAccessInitialize ...");
  rc = ent_initialize(&initParam, &bootParam);
  diag("sceNpEntitlementAccessInitialize rc=0x%08x (%s)", (uint32_t)rc,
       errname(rc));
  if (rc < 0 &&
      (uint32_t)rc != SCE_NP_ENTITLEMENT_ACCESS_ERROR_ALREADY_INITIALIZED) {
    cleanup();
    return 1;
  }

  {
    int appco_startRes = 0;

    diag("sceKernelLoadStartModule(%s) ...", APPCO_PATH);
    g_appco_handle = sceKernelLoadStartModule(APPCO_PATH, 0, NULL, 0, NULL,
                                              &appco_startRes);
    diag("sceKernelLoadStartModule handle=0x%08x start_res=0x%08x",
         (uint32_t)g_appco_handle, (uint32_t)appco_startRes);
    if (g_appco_handle >= 0) {
      appco_initialize = (appco_initialize_t)kernel_dynlib_dlsym(
          -1, (uint32_t)g_appco_handle, "sceAppContentInitialize");
      diag("dlsym sceAppContentInitialize = %p", (void *)appco_initialize);
      appco_addcont_mount = (appco_addcont_mount_t)kernel_dynlib_dlsym(
          -1, (uint32_t)g_appco_handle, "sceAppContentAddcontMount");
      diag("dlsym sceAppContentAddcontMount = %p", (void *)appco_addcont_mount);
    }
  }

  if (appco_initialize) {
    SceAppContentInitParam appcoInitParam;
    SceAppContentBootParam appcoBootParam;
    memset(&appcoInitParam, 0, sizeof(appcoInitParam));
    memset(&appcoBootParam, 0, sizeof(appcoBootParam));
    diag("sceAppContentInitialize ...");
    rc = appco_initialize(&appcoInitParam, &appcoBootParam);
    diag("sceAppContentInitialize rc=0x%08x", (uint32_t)rc);
  }

  // A NULL list makes the library return only the count.
  diag("GetAddcontEntitlementInfoList(count) ...");
  rc = ent_get_addcont_list(label, NULL, 0, &hitNum);
  diag("GetAddcontEntitlementInfoList(count) rc=0x%08x (%s) hitNum=%u",
       (uint32_t)rc, errname(rc), hitNum);
  if (rc < 0) {
    cleanup();
    return 1;
  }
  if (hitNum == 0) {
    diag("no add-on entitlements");
    cleanup();
    return 0;
  }

  list = calloc(hitNum, sizeof(*list));
  if (!list) {
    diag("calloc(%u) failed", hitNum);
    return 1;
  }

  diag("GetAddcontEntitlementInfoList(list, %u) ...", hitNum);
  rc = ent_get_addcont_list(label, list, hitNum, &fetched);
  diag("GetAddcontEntitlementInfoList(list) rc=0x%08x (%s) hitNum=%u",
       (uint32_t)rc, errname(rc), fetched);
  if (rc < 0) {
    free(list);
    return 1;
  }

  count = fetched < hitNum ? fetched : hitNum;
  for (uint32_t i = 0; i < count; i++) {
    SceNpEntitlementAccessEntitlementKey key;

    list[i].entitlementLabel.data[16] = '\0';
    diag("[%u] label=%.16s packageType=%d downloadStatus=%d", i,
         list[i].entitlementLabel.data, list[i].packageType,
         list[i].downloadStatus);

    diag("[%u] GetEntitlementKey ...", i);
    rc = ent_get_key(label, &list[i].entitlementLabel, &key);
    diag("[%u] GetEntitlementKey rc=0x%08x (%s)", i, (uint32_t)rc, errname(rc));
    if (rc == 0) {
      diag("[%u] key=%02x%02x%02x%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x%02x%02x%02x", i,
           key.data[0],  key.data[1],  key.data[2],  key.data[3],
           key.data[4],  key.data[5],  key.data[6],  key.data[7],
           key.data[8],  key.data[9],  key.data[10], key.data[11],
           key.data[12], key.data[13], key.data[14], key.data[15]);
    }

    /* packageType 2 = PSAC (additional content with file data) */
    if (appco_addcont_mount && list[i].packageType == 2) {
      SceAppContentMountPoint mp;
      memset(&mp, 0, sizeof(mp));
      rc = appco_addcont_mount(label, &list[i].entitlementLabel, &mp);
      diag("[%u] mount rc=0x%08x mp=%s", i, (uint32_t)rc, mp.data);
    }
  }
  if (fetched > hitNum) {
    diag("list truncated, %u of %u entries shown", hitNum, fetched);
  }

  free(list);
  cleanup();
  diag("done");
  return 0;
}
