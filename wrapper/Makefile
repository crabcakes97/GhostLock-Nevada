API ?= 35
OUTDIR ?= build
BINARY := $(OUTDIR)/unplus

DEFAULT_NDK_ROOT := $(HOME)/android-ndk-cache/android-ndk-r29
DARWIN_NDK_ROOT := $(lastword $(sort $(wildcard $(HOME)/Library/Android/sdk/ndk/*)))
NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(wildcard $(DEFAULT_NDK_ROOT)),$(DARWIN_NDK_ROOT))
NDK_PREBUILT := $(if $(filter Darwin,$(shell uname -s)),darwin-x86_64,linux-x86_64)
NDK_TOOLCHAIN ?= $(if $(NDK_ROOT),$(NDK_ROOT)/toolchains/llvm/prebuilt/$(NDK_PREBUILT))
NDK_CC := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang
HOST_CLANG ?= clang
SYSROOT ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/sysroot)
RESOURCE_DIR ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/lib/clang/21)

HOST_TARGET_FLAGS := \
  --target=aarch64-linux-android$(API) \
  --sysroot=$(SYSROOT) \
  -resource-dir $(RESOURCE_DIR) \
  --rtlib=compiler-rt \
  --unwindlib=none

HOST_COMMON_LDFLAGS := \
  -fuse-ld=lld \
  -Wl,-rpath-link,$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android

HOST_PIE_LDFLAGS := \
  $(HOST_COMMON_LDFLAGS) \
  -Wl,-dynamic-linker,/system/bin/linker64

ifneq ($(origin CC),default)
  TARGET_CC := $(CC)
  TARGET_FLAGS :=
  TARGET_LDFLAGS :=
else ifneq ($(wildcard $(NDK_CC)),)
  NDK_CC_WORKS := $(shell $(NDK_CC) --version >/dev/null 2>&1 && echo yes)
  ifeq ($(NDK_CC_WORKS),yes)
    TARGET_CC := $(NDK_CC)
    TARGET_FLAGS :=
    TARGET_LDFLAGS :=
  else
    TARGET_CC := $(HOST_CLANG)
    TARGET_FLAGS := $(HOST_TARGET_FLAGS)
    TARGET_LDFLAGS := $(HOST_PIE_LDFLAGS)
  endif
else
  TARGET_CC := $(HOST_CLANG)
  TARGET_FLAGS := $(HOST_TARGET_FLAGS)
  TARGET_LDFLAGS := $(HOST_PIE_LDFLAGS)
endif

CFLAGS := -O2 -g0 -Wall -Wextra -fPIE -pie -I.
WARN_CFLAGS := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function

SRCS := main.c
PAYLOAD_H := payload/payload_data.h

.PHONY: all clean

all: $(BINARY)

$(PAYLOAD_H):
	@echo "Run embed_payloads.py first to generate payload data:"
	@echo "  python3 embed_payloads.py \\"
	@echo "    --unplus ../build/unplus \\"
	@echo "    --preload ../build/unplus_preload.so \\"
	@echo "    --magiskpolicy <path> \\"
	@echo "    --ksud <path> \\"
	@echo "    --kernelsu <path> \\"
	@echo "    --out payload/"
	@false

$(BINARY): $(SRCS) $(PAYLOAD_H) | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(CFLAGS) $(WARN_CFLAGS) \
	  $(SRCS) $(TARGET_LDFLAGS) \
	  -o $@ -pthread

$(OUTDIR):
	mkdir -p $@

clean:
	rm -rf $(OUTDIR) payload/
