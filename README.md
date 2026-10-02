# ps5-entitlements-dumper

Dumps add-on entitlements and their keys from `libSceNpEntitlementAccess.sprx`
for the running game. Thanks to John for the SDK and process injecting logic.

## Build

```console
make PS5_PAYLOAD_SDK=/path/to/sdk
```

Defaults to `/opt/ps5-payload-sdk`. `make all` produces both ELFs.

## Run

Send `entitlement-injector.elf` over socat. It finds the running game
automatically and injects `entitlements.elf` into it:

```console
socat -t 600 - TCP:<ps5-ip>:9021 < entitlement-injector.elf
```

Output comes back on that socket and also goes to klog. Pass `--pid <n>` if
there are multiple game processes or auto-detection fails.

## Output
```
entitlements: start pid=152 STAGE=99 PRELOAD_IPMI=1 USE_SYSMODULE=0 label=0
entitlements: libSceNpEntitlementAccess.sprx already resident, using handle=0xe0dc
entitlements: sceNpEntitlementAccessInitialize rc=0x817d0003 (ALREADY_INITIALIZED)
entitlements: GetAddcontEntitlementInfoList(count) rc=0x00000000 (OK) hitNum=1
entitlements: [0] label=REALLYCOOLADDON1 packageType=2 downloadStatus=4
entitlements: [0] GetEntitlementKey rc=0x00000000 (OK)
entitlements: [0] key=67676767676766767676767676676767
entitlements: done
```