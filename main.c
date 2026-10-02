#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>

#ifndef SERVICE_LABEL
#define SERVICE_LABEL 0
#endif

// Run stages 0..STAGE and exit; 99 runs everything.
#ifndef STAGE
#define STAGE 99
#endif

#ifndef PRELOAD_IPMI
#define PRELOAD_IPMI 1
#endif

#ifndef USE_SYSMODULE
#define USE_SYSMODULE 0
#endif

#define SCE_NP_ENTITLEMENT_ACCESS_ERROR_NOT_INITIALIZED     0x817d0001
#define SCE_NP_ENTITLEMENT_ACCESS_ERROR_INVALID_ARGUMENT    0x817d0002
#define SCE_NP_ENTITLEMENT_ACCESS_ERROR_ALREADY_INITIALIZED 0x817d0003

#define SYSMODULE_IPMI                  0x8000001d
#define SYSMODULE_NP_ENTITLEMENT_ACCESS 0x113

#define ENT_SONAME "libSceNpEntitlementAccess.sprx"
#define ENT_PATH   "/system/common/lib/" ENT_SONAME

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


_Static_assert(sizeof(SceNpEntitlementAccessAddcontEntitlementInfo) == 28,
               "AddcontEntitlementInfo size");
_Static_assert(sizeof(SceNpEntitlementAccessInitParam) == 32, "InitParam size");
_Static_assert(sizeof(SceNpEntitlementAccessBootParam) == 32, "BootParam size");

int sceKernelLoadStartModule(const char *path, size_t argc, const void *argv,
                             uint32_t flags, void *opt, int *res);
int32_t sceSysmoduleLoadModuleInternal(uint32_t id);
int32_t sceSysmoduleLoadModule(uint32_t id);

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

static ent_initialize_t ent_initialize;
static ent_get_addcont_list_t ent_get_addcont_list;
static ent_get_key_t ent_get_key;

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

static int stop_after(int n) {
  if (STAGE <= n) {
    diag("STAGE=%d: stopping after stage %d", STAGE, n);
    return 1;
  }
  return 0;
}

static void report_loaded(const char *soname) {
  uint32_t h;

  if (!kernel_dynlib_handle(-1, soname, &h)) {
    diag("%s loaded, handle=0x%x", soname, h);
  } else {
    diag("%s not loaded", soname);
  }
}

int main(void) {
  SceNpEntitlementAccessInitParam initParam;
  SceNpEntitlementAccessBootParam bootParam;
  SceNpEntitlementAccessAddcontEntitlementInfo *list;
  SceNpServiceLabel label = SERVICE_LABEL;
  uint32_t hitNum = 0;
  uint32_t fetched = 0;
  uint32_t count;
  int handle;
  int32_t rc;

  diag("start pid=%d STAGE=%d PRELOAD_IPMI=%d USE_SYSMODULE=%d label=%u",
       getpid(), STAGE, PRELOAD_IPMI, USE_SYSMODULE, label);
  if (stop_after(0)) {
    return 0;
  }

  report_loaded("libSceIpmi.sprx");
  if (PRELOAD_IPMI) {
    diag("sceSysmoduleLoadModuleInternal(0x%08x libSceIpmi) ...",
         SYSMODULE_IPMI);
    rc = sceSysmoduleLoadModuleInternal(SYSMODULE_IPMI);
    diag("sceSysmoduleLoadModuleInternal rc=0x%08x", (uint32_t)rc);
    if (rc < 0) {
      return 1;
    }
    report_loaded("libSceIpmi.sprx");
  }
  if (stop_after(1)) {
    return 0;
  }

  {
    uint32_t existing;

    report_loaded(ENT_SONAME);
    if (!kernel_dynlib_handle(-1, ENT_SONAME, &existing)) {
      handle = (int)existing;
      diag("%s already resident, using handle=0x%x", ENT_SONAME, existing);
    } else if (USE_SYSMODULE) {
      diag("sceSysmoduleLoadModule(0x%x) ...", SYSMODULE_NP_ENTITLEMENT_ACCESS);
      rc = sceSysmoduleLoadModule(SYSMODULE_NP_ENTITLEMENT_ACCESS);
      diag("sceSysmoduleLoadModule rc=0x%08x", (uint32_t)rc);
      if (rc < 0) {
        return 1;
      }
      if (kernel_dynlib_handle(-1, ENT_SONAME, &existing)) {
        diag("%s not found after sceSysmoduleLoadModule", ENT_SONAME);
        return 1;
      }
      handle = (int)existing;
      diag("%s handle=0x%x", ENT_SONAME, existing);
    } else {
      int startRes = 0;

      diag("sceKernelLoadStartModule(%s) ...", ENT_PATH);
      handle = sceKernelLoadStartModule(ENT_PATH, 0, NULL, 0, NULL, &startRes);
      diag("sceKernelLoadStartModule handle=0x%08x start_res=0x%08x",
           (uint32_t)handle, (uint32_t)startRes);
      if (handle < 0) {
        return 1;
      }
    }
  }
  if (stop_after(2)) {
    return 0;
  }

  ent_initialize = (ent_initialize_t)kernel_dynlib_dlsym(
      -1, (uint32_t)handle, "sceNpEntitlementAccessInitialize");
  diag("dlsym sceNpEntitlementAccessInitialize = %p", (void *)ent_initialize);
  if (!ent_initialize) {
    return 1;
  }
  ent_get_addcont_list = (ent_get_addcont_list_t)kernel_dynlib_dlsym(
      -1, (uint32_t)handle,
      "sceNpEntitlementAccessGetAddcontEntitlementInfoList");
  diag("dlsym sceNpEntitlementAccessGetAddcontEntitlementInfoList = %p",
       (void *)ent_get_addcont_list);
  if (!ent_get_addcont_list) {
    return 1;
  }
  ent_get_key = (ent_get_key_t)kernel_dynlib_dlsym(
      -1, (uint32_t)handle,
      "sceNpEntitlementAccessGetEntitlementKey");
  diag("dlsym sceNpEntitlementAccessGetEntitlementKey = %p",
       (void *)ent_get_key);
  if (!ent_get_key) {
    return 1;
  }
  if (stop_after(3)) {
    return 0;
  }

  memset(&initParam, 0, sizeof(initParam));
  memset(&bootParam, 0, sizeof(bootParam));
  diag("sceNpEntitlementAccessInitialize ...");
  rc = ent_initialize(&initParam, &bootParam);
  diag("sceNpEntitlementAccessInitialize rc=0x%08x (%s)", (uint32_t)rc,
       errname(rc));
  if (rc < 0 &&
      (uint32_t)rc != SCE_NP_ENTITLEMENT_ACCESS_ERROR_ALREADY_INITIALIZED) {
    return 1;
  }
  if (stop_after(4)) {
    return 0;
  }

  // A NULL list makes the library return only the count.
  diag("GetAddcontEntitlementInfoList(count) ...");
  rc = ent_get_addcont_list(label, NULL, 0, &hitNum);
  diag("GetAddcontEntitlementInfoList(count) rc=0x%08x (%s) hitNum=%u",
       (uint32_t)rc, errname(rc), hitNum);
  if (rc < 0) {
    return 1;
  }
  if (hitNum == 0) {
    diag("no add-on entitlements");
    return 0;
  }
  if (stop_after(5)) {
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
  }
  if (fetched > hitNum) {
    diag("list truncated, %u of %u entries shown", hitNum, fetched);
  }

  free(list);
  diag("done");
  return 0;
}
