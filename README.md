# unplus

<p align="center">
  <img src="assets/banner.png" alt="UnPlus">
</p>

CVE-2026-43499 (Futex PI UAF) 内核任意地址写入 exploit 的核心逻辑代码，用于绕过 SELinux 获取 root。

> 本仓库只包含核心 exploit 逻辑源码（`src/`）和单二进制打包器（`wrapper/`）。
> `src/target.h` 是**模板**，需填入你自己设备的参数才能运行（见下文"设备适配"）。

## 构建

### 核心逻辑（src/）

```bash
# 环境要求: Android NDK r29+ (API 35, aarch64)
export ANDROID_NDK_ROOT=/path/to/android-ndk

# 构建纯逻辑产物
make
# → build/unplus            (exploit 二进制)
# → build/unplus_preload.so (preload 库)
```

产物是两个 ELF，不嵌入任何外部二进制。

### 完整单二进制打包（wrapper/）

要把 exploit 和外部荷载（magiskpolicy / ksud / kernelsu.ko）打包成一键运行的单二进制，需自备这些外部荷载后用 `wrapper/` 打包：

```bash
# 1. 先构建 src/ 产物（见上）
# 2. 生成 payload 数据（payload_data.h 不在仓库，由用户自生成，含外部二进制字节流）
cd wrapper
python3 embed_payloads.py \
  --unplus ../build/unplus \
  --preload ../build/unplus_preload.so \
  --magiskpolicy <path> \
  --ksud <path> \
  --kernelsu <path> \
  --out payload/
# 3. 编译单二进制
make    # → wrapper/build/unplus
```

## 源码结构

```
src/
├── target.h          设备参数模板（◆ FILL IN 标记处需填你的设备值）
├── offset.h          target.h 的路由胶水（经 -DTARGET_CONFIG_H 注入）
├── unplus.h          编排头 + 共享声明（含 P0 alias / data_addr 等派生宏）
├── main.c            入口编排
├── stage1.c          Write 1/2：SELinux 关闭 + cred 覆写
├── root.c            Android root 落地（SELinux golden 修复 + sepolicy + KSU allowlist）
├── slide.c           KASLR leak
├── fops.c            configfs/fops 路由 + 内核基址推导
├── route.c           PI futex 路由线程
├── direct_write.c    direct read 原语
├── pipe_direct.c     direct pselect write
├── pipe_physrw.c     pipe physrw 原语
├── util.c            工具函数
├── utils.h           通用工具（日志、procfs 路径）
├── kernelsnitch.h    架构层（ARM64/x86 identity-map）
├── futex_hash.h      内核 jhash 移植（通用）
└── timeutils.h       架构层计时（ARM/x86/AMD）
```

## 设备适配

`src/target.h` 分两类常量：

- **`◆ FILL IN` 标记的**：设备/内核相关，必须填你自己的值。模板里用 `0xDEADBEEF...` 占位，能编译但跑起来会崩。
- **无标记的**：GKI 6.6 不变量（struct 字段偏移），通常不用改。

换设备 = 填好 `◆ FILL IN` 部分。具体每个字段是什么、怎么获取，见下文 [附录：字段说明](#附录字段说明)。

## 附录：字段说明

`target.h` 里 `◆ FILL IN` 的字段按用途分组：

| 分组 | 字段（示例） | 含义 / 获取方式 |
|------|------------|----------------|
| **Build identity** | `BUILD_VARIANT_LABEL`、`BUILD_FINGERPRINT` | 任意标识串，用于日志。填你设备的 build fingerprint |
| **Memory layout** | `KIMAGE_TEXT_BASE`、`P0_PHYS_OFFSET`、`VMEMMAP_START` 等 | 内核虚拟/物理地址布局。arm64 VA39 通常已给默认值；从 IKCONFIG / kallsyms / `/proc/iomem` 确认 |
| **ASHMEM** | `ASHMEM_IOCTL_OFF` ... `ASHMEM_MISC_FOPS_OFF` | ashmem 驱动各 fops 成员 + misc 的符号偏移。`kallsyms_lookup_name("ashmem_fops")` 等 |
| **CONFIGFS / PIPE / VFS** | `CONFIGFS_READ_ITER_OFF`、`ANON_PIPE_BUF_OPS_OFF`、`KMALLOC_CACHES_OFF` 等 | configfs 读写、splice、pipe_buf_ops、kmalloc_caches 偏移。kallsyms 查 |
| **SELinux** | `SELINUX_ENFORCING_OFF`、`SELINUX_BLOB_SIZES_OFF`、`SECURITY_HOOK_HEADS_OFF` | selinux_state / selinux_blob_sizes / security_hook_heads 偏移。**`SELINUX_ENFORCING_OFF` 是内核 build 匹配锚点**，必须精确 |
| **Core kernel symbols** | `INIT_TASK_OFF`、`INIT_CRED_OFF`、`ENTRY_TASK_PERCPU_OFF` 等 | init_task / init_cred / entry_task / __per_cpu_offset / root_task_group 偏移。kallsyms 查；`ENTRY_TASK_PERCPU_OFF` 是 `__entry_task` 在 percpu section 内的偏移 |
| **Per-CPU runtime** | `TARGET_PCPU_BASE_ADDR`、`TARGET_PCPU_UNIT_SIZE` | per-CPU chunk 的**运行时**地址（KASLR 后），每次开机变。需运行时 dump；`UNIT_SIZE` 取决于 CPU 数 |
| **SLIDE (KASLR leak)** | `SLIDE_NFULNL_LOGGER_OFF`、`SLIDE_RANDOM_BOOT_ID_DATA_OFF` 等 | 用于 KASLR 泄漏的内核数据符号偏移（nfulnl_logger / boot_id data 等）。kallsyms 查 |
| **SELinux golden** | `TARGET_SELINUX_GOLDEN` | `selinux_state` 前 16 字节 boolean 模板，跨重启稳定但每设备不同。需从你设备的 selinux_state dump。byte0 是 enforcing 位，调用方写 0x00 表示 permissive |
| **pipe inode info** | `PIPE_INODE_INFO_*`、`PIPE_HEAD_OFF` 等 | pipe_inode_info 结构布局，同 GKI family 内通常稳定，换内核 build 需核验 |

**通用经验**：所有 `*_OFF` 类偏移都可用 root 设备的 `kallsyms_lookup_name` 拿到符号地址后减去 `KIMAGE_TEXT_BASE` 得到。`TARGET_PCPU_*` 和 `TARGET_SELINUX_GOLDEN` 是运行时/dump 值，无法从静态镜像获取。

## 许可证

[WTFPL](LICENSE) — Do What The Fuck You Want To Public License.

## 致谢

- CyberMeowfia 团队 — pipe physrw 提权框架
- 社区设备适配参考
