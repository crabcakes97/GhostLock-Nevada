API ?= 35
OUTDIR ?= build

PRELOAD := $(OUTDIR)/unplus_preload.so
BINARY := $(OUTDIR)/unplus

DEFAULT_NDK_ROOT := $(HOME)/android-ndk-cache/android-ndk-r29
DARWIN_NDK_ROOT := $(lastword $(sort $(wildcard $(HOME)/Library/Android/sdk/ndk/*)))
NDK_ROOT ?= $(or $(ANDROID_NDK_ROOT),$(ANDROID_NDK_HOME),$(wildcard $(DEFAULT_NDK_ROOT)),$(DARWIN_NDK_ROOT))
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
  TARGET_COMMON_LDFLAGS :=
  TARGET_PIE_LDFLAGS :=
else ifneq ($(wildcard $(NDK_CC)),)
  NDK_CC_WORKS := $(shell $(NDK_CC) --version >/dev/null 2>&1 && echo yes)
  ifeq ($(NDK_CC_WORKS),yes)
    TARGET_CC := $(NDK_CC)
    TARGET_FLAGS :=
    TARGET_COMMON_LDFLAGS :=
    TARGET_PIE_LDFLAGS :=
  else
    TARGET_CC := $(HOST_CLANG)
    TARGET_FLAGS := $(HOST_TARGET_FLAGS)
    TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
    TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
  endif
else
  TARGET_CC := $(HOST_CLANG)
  TARGET_FLAGS := $(HOST_TARGET_FLAGS)
  TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
  TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
endif

COMMON_CFLAGS := -O2 -g0 -Wall -Wextra -Isrc
PIE_CFLAGS := -fPIE -pie $(COMMON_CFLAGS)
SO_CFLAGS := -fPIC $(COMMON_CFLAGS)
WARN_CFLAGS := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
TARGET_CFLAGS := -DTARGET_CONFIG_H=\"target.h\"

CORE_SRCS := \
  src/route.c \
  src/stage1.c \
  src/direct_write.c \
  src/pipe_direct.c \
  src/slide.c \
  src/fops.c \
  src/util.c

PRELOAD_SRCS := \
  $(CORE_SRCS) \
  src/pipe_physrw.c \
  src/root.c \
  src/main.c

BINARY_SRCS := \
  $(CORE_SRCS) \
  src/pipe_physrw.c \
  src/root.c \
  src/main.c

.PHONY: all preload binary clean

all: preload binary

preload: $(PRELOAD)

binary: $(BINARY)

$(OUTDIR):
	mkdir -p $@

$(PRELOAD): $(PRELOAD_SRCS) src/target.h src/unplus.h | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(SO_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) -DUNPLUS_PRELOAD \
	  $(PRELOAD_SRCS) $(TARGET_COMMON_LDFLAGS) \
	  -shared -o $@ -pthread
	sha256sum $@

$(BINARY): $(BINARY_SRCS) src/target.h src/unplus.h | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(PIE_CFLAGS) $(WARN_CFLAGS) $(TARGET_CFLAGS) \
	  $(BINARY_SRCS) $(TARGET_PIE_LDFLAGS) \
	  -o $@ -pthread
	sha256sum $@

clean:
	rm -rf $(OUTDIR)
