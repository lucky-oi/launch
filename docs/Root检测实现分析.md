# Root 检测实现分析文档

## 一、整体架构

该项目采用 **三层递进式检测架构（Multi-Layer Detection）**，从易到难绕过依次为：

| 层级 | 实现方式 | 可信度 | 绕过难度 |
|------|----------|--------|----------|
| **Java Layer** | Java File API / PackageManager | 低 | 容易被 Xposed/LSPosed Hook |
| **Native Layer** | libc 函数 (`access()`, `open()`, `opendir()`) | 中 | 可能被 PLT/GOT Hook 绕过 |
| **Syscall Layer** | 内联汇编直接执行 SVC 指令 | 高 | 极难绕过，直接与内核通信 |

### 关键检测原则

- **任意层级检测到即判定为风险**（`DetectionItem.getMostTrustworthyResult()` 逻辑）
- **层间不一致视为可疑**：如 Java 层未检测到但 Syscall 层检测到，说明 Java 层可能被 Hook
- 每项检测独立维护三层结果，最终综合判断

### 代码位置总览

```
Java 层:
  app/src/main/java/com/xff/launch/detector/RootDetector.java      -- Root检测主类
  app/src/main/java/com/xff/launch/detector/NativeDetector.java     -- Native JNI 接口
  app/src/main/java/com/xff/launch/detector/ReadlinkDetector.java   -- 符号链接检测
  app/src/main/java/com/xff/launch/detector/ZygoteDetector.java     -- Zygote注入检测
  app/src/main/java/com/xff/launch/detector/SideChannelDetector.java -- 旁路检测
  app/src/main/java/com/xff/launch/detector/HookDetector.java       -- Hook框架检测

Native 层:
  app/src/main/cpp/detector/root_detector.cpp/.h   -- Root检测 C++ 实现
  app/src/main/cpp/detector/hook_detector.cpp/.h   -- Hook检测 C++ 实现
  app/src/main/cpp/syscall/syscall_wrapper.h       -- 直接syscall封装(核心)
  app/src/main/cpp/native-lib.cpp                  -- JNI桥接层 (10万+行)
```

---

## 二、各检测项详细分析

### 2.1 Magisk 检测

**代码位置**: `RootDetector.java:139-169` (Java), `root_detector.cpp:114-122` (Native), `root_detector.cpp:255-263` (Syscall)

**检测原理**:

#### Java 层
```java
// RootDetector.java:565-568
private boolean checkMagiskJava() {
    return isPackageInstalled("com.topjohnwu.magisk") ||     // 检测Magisk Manager应用
            new File("/sbin/.magisk").exists() ||             // 检查Magisk标记目录
            new File("/data/adb/magisk").exists();           // 检查Magisk数据目录
}
```

#### Native 层（libc `access()`）
```cpp
// root_detector.cpp:114-122
bool RootDetector::checkMagiskNative() {
    // 遍历每个路径，调用 access(path, F_OK) 检测是否存在
    for (const auto& path : getMagiskPaths()) { ... }
}
```
检测路径清单：
- `/sbin/.magisk` — Magisk 核心标记
- `/data/adb/magisk` — Magisk 数据目录
- `/data/adb/magisk.img` — Magisk 镜像文件
- `/data/adb/magisk.db` — Magisk 数据库
- `/cache/magisk.log` — Magisk 日志
- `/cache/.disable_magisk` — Magisk 禁用标记
- `/dev/.magisk.unblock` — Magisk 解锁设备节点
- `/data/adb/modules` — Magisk 模块目录

#### Syscall 层（直接 SVC 指令）
```cpp
// syscall_wrapper.h:147-149 (ARM64)
static inline int syscall_access(const char *path) {
    return (int)syscall_raw(__NR_faccessat, AT_FDCWD, (long)path, F_OK, 0);
}
```
ARM64 上使用内联汇编 `svc #0` 直接发起系统调用，绕过 libc 的 `access()`：
```asm
// syscall_wrapper.h:97-116
__asm__ volatile("svc #0"
    : "+r"(x0)
    : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
    : "memory"
);
```

**详细检测辅助** (`RootDetector.java:654-717`):
- 读取 `/proc/self/mountinfo` 统计 Magisk 挂载点数量
- 检测 Zygisk 标记文件 `/data/adb/modules/.zygisk`

---

### 2.2 SU 文件检测

**代码位置**: `RootDetector.java:97-134` (Java), `root_detector.cpp:104-112` (Native), `root_detector.cpp:245-253` (Syscall)

**检测原理**:

遍历以下路径检测 SU 二进制文件是否存在：

```java
// RootDetector.java:25-36
private static final String[] SU_PATHS = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
    "/system/sd/xbin/su", "/system/bin/failsafe/su",
    "/vendor/bin/su", "/su/bin/su"
};
```

三层检测逻辑相同，区别在于文件访问方式：
- **Java**: `new File(path).exists()`
- **Native**: `access(path, F_OK)` — 通过 libc
- **Syscall**: 汇编 `svc #0` + `__NR_faccessat` — 绕过所有用户态 Hook

---

### 2.3 KernelSU 检测

**代码位置**: `RootDetector.java:175-206` (Java), `root_detector.cpp:124-132` (Native), `root_detector.cpp:265-273` (Syscall)

**检测原理**:

#### 文件路径检测
```cpp
// root_detector.cpp:44-52
const std::vector<std::string>& RootDetector::getKernelSUPaths() {
    return { "/data/adb/ksu", "/data/adb/ksud",
             "/data/adb/ksu/bin/busybox", "/data/adb/ksu/bin/resetprop" };
}
```

#### Java 层补充检测
```java
// RootDetector.java:571-574
private boolean checkKernelSUJava() {
    return isPackageInstalled("me.weishu.kernelsu") ||   // KernelSU Manager
            new File("/data/adb/ksu").exists();          // KernelSU 数据目录
}
```

#### 内核模块检测（辅助确认）
```java
// RootDetector.java:751-763
// 读取 /proc/modules，查找包含 "kernelsu" 或 "ksu" 的内核模块
BufferedReader reader = new BufferedReader(new FileReader("/proc/modules"));
```

**核心原理**: KernelSU 是基于内核的 Root 方案（Linux Kernel LKM），其用户态文件位于 `/data/adb/ksu/`。与 Magisk 不同，KernelSU 不需要修改 system 分区，而是直接在内核空间工作。检测通过验证用户态管理文件的存在性来实现。

---

### 2.4 APatch 检测

**代码位置**: `RootDetector.java:211-242` (Java), `root_detector.cpp:134-143` (Native), `root_detector.cpp:275-283` (Syscall)

**检测原理**:

```cpp
// root_detector.cpp:54-60
const std::vector<std::string>& RootDetector::getAPatchPaths() {
    return { "/data/adb/ap", "/data/adb/apd", "/data/adb/ap/bin" };
}
```

```java
// RootDetector.java:576-579
private boolean checkAPatchJava() {
    return isPackageInstalled("me.bmax.apatch") ||        // APatch Manager
            new File("/data/adb/ap").exists();            // APatch 数据目录
}
```

**辅助检测** - SuperKey 机制（APatch 特有）:
```java
// RootDetector.java:797-802
File superKeyMarker = new File("/data/adb/ap/.superkey");
if (superKeyMarker.exists()) { /* 检测到 APatch SuperKey */ }
```

**核心原理**: APatch 是一种基于内核注入的 Root 方案，类似于 KernelSU。其数据目录 `/data/adb/ap/` 是区别于其他 Root 方案的特征标识。

---

### 2.5 SukiSU 检测

**代码位置**: `RootDetector.java:247-278` (Java), `root_detector.cpp:144-164` (Native), `root_detector.cpp:285-300` (Syscall)

**检测原理**:

```cpp
// root_detector.cpp:63-69
const std::vector<std::string>& RootDetector::getSukiSUPaths() {
    return { "/data/adb/sukisu", "/data/adb/ksu" };  // SukiSU继承自KernelSU
}
```

**SUSFS 文件系统检测**（SukiSU 特有特征）:
```cpp
// root_detector.cpp:153-163 (Native 层)
std::ifstream file("/proc/filesystems");
while (std::getline(file, line)) {
    if (line.find("susfs") != std::string::npos) {  // SUSFS 是 SukiSU 的特有文件系统
        return true;
    }
}
```

```java
// RootDetector.java:823-837 (Java 辅助)
BufferedReader reader = new BufferedReader(new FileReader("/proc/filesystems"));
while ((line = reader.readLine()) != null) {
    if (line.contains("susfs")) { /* 检测到 SUSFS 文件系统 */ }
}
```

**隐藏挂载检测**:
```java
// RootDetector.java:850-867
// 检查 /proc/self/mountinfo 中的 "sus_" 或 "susfs" 挂载点
if (line.contains("sus_") || line.contains("susfs")) { suspiciousMounts++; }
```

**核心原理**: SukiSU 是基于 KernelSU 的增强版本，引入 SUSFS（Super User File System）实现文件隐藏。通过检测 `/proc/filesystems` 中是否注册了 `susfs` 文件系统类型、以及 `/proc/self/mountinfo` 中是否存在 SUSFS 挂载点来判断。

---

### 2.6 Root 管理器检测

**代码位置**: `RootDetector.java:283-308`

**检测原理**:

纯 Java 层检测，通过 `PackageManager` 查询已安装应用：

```java
// RootDetector.java:39-50
private static final String[] ROOT_PACKAGES = {
    "com.topjohnwu.magisk",       // Magisk Manager
    "me.weishu.kernelsu",         // KernelSU Manager
    "me.bmax.apatch",             // APatch Manager
    "org.sukisu.manager",         // SukiSU Manager
    "com.noshufou.android.su",    // Superuser
    "eu.chainfire.supersu",       // SuperSU
    "com.koushikdutta.superuser", // ClockworkMod Superuser
    "com.kingroot.kinguser",      // KingRoot
    "com.kingo.root",             // Kingo Root
    "me.phh.superuser"            // PHH Superuser
};
```

检测方法：`context.getPackageManager().getPackageInfo(packageName, 0)` 是否抛出 `NameNotFoundException`。

**局限**: 可通过 Hide My Applist / XPrivacyLua 等模块隐藏应用，因此本检测只作为辅助参考。

---

### 2.7 Root 隐藏模块检测

**代码位置**: `RootDetector.java:313-340` (Java), `root_detector.cpp:230-238` (Native), `root_detector.cpp:376-384` (Syscall)

**检测原理**:

检测已知的 Root 隐藏模块目录：

```cpp
// root_detector.cpp:87-97
const std::vector<std::string>& RootDetector::getRootHidingPaths() {
    return {
        "/data/adb/modules/shamiko",          // Shamiko (Magisk模块隐藏)
        "/data/adb/modules/zygisk-assistant", // Zygisk Assistant (隐藏注入)
        "/data/adb/modules/playintegrityfix", // Play Integrity Fix
        "/data/adb/modules/zygiskNext",       // Zygisk Next (新一代Zygisk)
        "/data/adb/modules/rezygisk",         // ReZygisk (KernelSU的Zygisk)
        "/data/adb/modules/lsposed"           // LSPosed (Hook框架)
    };
}
```

Java 层辅助增强 (`RootDetector.java:900-955`):
- 遍历 `/data/adb/modules/` 下所有子目录，匹配模块名称关键字
- 读取每个匹配模块的 `module.prop` 文件获取详情（名称/版本/作者）
- 检测 Shamiko 白名单配置目录 `/data/adb/shamiko`

**模块匹配关键字**: `shamiko`, `zygisk-assistant`, `zygiskNext`, `HideMyApplist`, `playintegrityfix`, `trickystore`

---

### 2.8 可疑挂载检测

**代码位置**: `RootDetector.java:345-372` (Java 调度), `root_detector.cpp:184-228` (Native), `root_detector.cpp:315-374` (Syscall)

**检测原理**:

解析 `/proc/self/mountinfo`，匹配 Root 相关挂载特征：

```cpp
// root_detector.cpp:191-200
const std::vector<std::string> suspiciousPatterns = {
    "magisk", "zygisk", "zygisksu", "kernelsu",
    "apatch", "/data/adb/modules", "/data/adb/ksu",
    "/data/adb/ap", "module.prop"
};
```

Java 层增强检测 (`RootDetector.java:957-1076`):
1. **Root 挂载点匹配**: 遍历 mountinfo 每一行，匹配上述模式
2. **重复 cacerts 挂载检测**: 统计同一行中 `cacerts` 出现次数 > 2（正常系统只有一个证书目录挂载）
3. **ZygiskSU 文件系统挂载**: 检测 `zygisksu` / `zygisk_su` 挂载
4. **异常证书挂载**: cacerts 挂载点数量 > 1 即为异常

---

### 2.9 Riru/Dreamland 检测

**代码位置**: `RootDetector.java:396-493`

**检测原理**:

#### Riru 路径检测 (Java + Native + Syscall)
```java
// RootDetector.java:60-68
private static final String[] RIRU_PATHS = {
    "/system/lib/libriruloader.so",           // Riru Loader 32位
    "/system/lib64/libriruloader.so",         // Riru Loader 64位
    "/data/misc/riru/modules/edxp",           // EdXposed 模块目录
    "/data/misc/riru/modules/dreamland",      // Dreamland 模块目录
    "/data/adb/riru/modules/edxp.prop",       // EdXposed 属性文件
    "/data/adb/riru/modules/dreamland",       // Dreamland ADB路径
    "/sbin/.magisk/modules/dreamland"         // Magisk Dreamland
};
```

#### 内存映射检测 (Native 层)
```java
// RootDetector.java:71-75
private static final String[] RIRU_MEMORY_SIGNATURES = {
    "libriru_edxp.so",       // EdXposed Riru 库
    "libriruloader.so",      // Riru 加载器
    "zygisk_module_entry"    // Zygisk 模块入口符号
};
```
读取 `/proc/self/maps` 逐行匹配上述签名。

#### YAHFA 类检测 (Java 层)
```java
// RootDetector.java:422-426
try {
    Class.forName("com.elderdrivers.riru.edxp.core.Yahfa");
    javaDetected = true;  // YAHFA Hook引擎类已加载
} catch (ClassNotFoundException ignored) {}
```

**核心原理**: Riru 是一种通过 `ro.dalvik.vm.native.bridge` 属性劫持 Zygote 进程注入的框架。Dreamland 是基于 Riru 的 Xposed 兼容框架。检测通过文件系统路径、内存映射签名、类名特征三维度进行。

---

### 2.10 动态路径检测

**代码位置**: `RootDetector.java:499-537`

**检测原理**:

通过扫描 `PATH` 环境变量中的所有目录，查找 Root 相关的可执行文件：

```java
// RootDetector.java:499-537
public DetectionItem detectDynamicSuPaths() {
    String pathEnv = System.getenv("PATH");
    if (pathEnv != null) {
        String[] dirs = pathEnv.split(":");
        String[] binaries = {"su", "magisk", "magiskhide", "ksud", "apd"};

        for (String dir : dirs) {
            for (String bin : binaries) {
                String fullPath = dir + "/" + bin;
                // Java 检测 + Native 检测
                if (new File(fullPath).exists()) { detected = true; }
                if (nativeDetector.fileExistsNative(fullPath)) { detected = true; }
            }
        }
    }
}
```

**检测目标二进制文件**:
- `su` — 通用 Root 切换工具
- `magisk` — Magisk 命令行工具
- `magiskhide` — Magisk Hide 命令行
- `ksud` — KernelSU 守护进程
- `apd` — APatch 守护进程

**核心原理**: Root 工具通常会把自己的二进制文件放在 PATH 可访问的目录下（如 `/data/adb/ksu/bin` 被添加到 PATH），通过枚举 PATH 中每个目录来发现这些隐蔽安装的 root 工具。

---

## 三、辅助检测机制

### 3.1 符号链接检测 (ReadlinkDetector)

**代码位置**: `ReadlinkDetector.java`

检测目标：
- `/proc/self/exe` — 进程可执行文件路径（不应指向可疑目标）
- `/proc/self/maps` — 内存映射
- `/proc/self/mounts` — 挂载命名空间
- `/proc/self/root` — 进程根目录
- `/proc/self/cwd` — 当前工作目录
- `/proc/self/fd` — 文件描述符（检测打开的可疑文件）
- 系统二进制文件的符号链接目标（`/system/bin/sh`, `app_process` 等）

**原理**: 使用 `readlink()` / `realpath()` 解析符号链接的真实目标，如果指向 `magisk` / `su` / `kernelsu` 等可疑目标则告警。

### 3.2 Zygote 注入检测 (ZygoteDetector)

**代码位置**: `ZygoteDetector.java`

覆盖检测：
- Zygisk 注入（内存映射中的 `libzygisk.so`）
- Riru 注入（路径 + 内存映射）
- Native Bridge 劫持（`ro.dalvik.vm.native.bridge` 属性）
- SELinux 上下文异常
- app_process 完整性
- InMemoryDexClassLoader（动态 DEX 加载）

### 3.3 系统库完整性检测 (SideChannelDetector)

**代码位置**: `SideChannelDetector.java`

通过比对磁盘上的 SO 文件与内存中加载的代码段，检测 Inline Hook：
- `libc.so` — 检测 `open/openat/read/access/stat` 等函数
- `libart.so` — 检测 ART 运行时函数（Xposed/LSPosed Hook 目标）
- `libandroid_runtime.so` — 检测 Zygote 相关函数

### 3.4 SMAPS 代码段脏页检测

**代码位置**: `hook_detector.cpp:659-750`

```cpp
// 核心原理：检测代码段(r-xp)的 Private_Dirty 页
// 正常只读代码段为0，被Inline Hook后触发Copy-on-Write，Private_Dirty > 0
bool HookDetector::checkSmapsIntegrity() {
    int fd = syscall(__NR_openat, AT_FDCWD, "/proc/self/smaps", O_RDONLY);
    // 逐行解析，定位关键库的代码段，检查 Private_Dirty 字段
    if (line.find("Private_Dirty:") != std::string::npos) {
        int dirty_kb = atoi(value_str.c_str());
        if (dirty_kb > 0) { detected = true; }  // 代码被篡改！
    }
}
```

**这是几乎无法绕过的检测技术**，因为修改只读代码段必然触发 COW。

---

## 四、总结

| 检测项 | Java层 | Native层 | Syscall层 | 核心检测方法 |
|--------|--------|----------|-----------|------------|
| Magisk检测 | PackageManager + File.exists | access(F_OK) | faccessat syscall | 路径存在性 + 挂载点 |
| SU文件检测 | File.exists | access(F_OK) | faccessat syscall | 遍历10个常见SU路径 |
| KernelSU检测 | PackageManager + File.exists | access(F_OK) | faccessat syscall | 路径 + /proc/modules |
| APatch检测 | PackageManager + File.exists | access(F_OK) | faccessat syscall | 路径 + SuperKey标记 |
| SukiSU检测 | PackageManager + File.exists | access + /proc/filesystems | faccessat + 直接读 | 路径 + SUSFS文件系统 |
| Root管理器 | PackageManager | — | — | 应用安装列表 |
| Root隐藏模块 | — | access(F_OK) | faccessat syscall | 模块目录 + module.prop |
| 可疑挂载 | mountinfo解析 | mountinfo解析 | syscall读mountinfo | 挂载特征匹配 + cacerts计数 |
| Riru/Dreamland | File.exists + Class.forName | access + /proc/maps | faccessat syscall | 路径+内存签名+YAHFA类 |
| 动态路径 | PATH枚举 + File.exists | PATH枚举 + access | — | PATH环境变量扫描 |
| SMAPS脏页 | — | syscall读取smaps | syscall读取smaps | 代码段Private_Dirty检测 |
