# AOSP 修改实现 Root 隐藏 — 完整代码实现方案

## 概述

本方案基于以下三个信息源交叉分析得出：

| 来源 | 内容 |
|------|------|
| 看雪文章 [thread-273485](https://bbs.kanxue.com/thread-273485.htm) | 应用 root 检测通杀篇 — ROM 层魔改 su + test-keys |
| 看雪文章 [thread-275109](https://bbs.kanxue.com/thread-275109.htm) | 源码编译（4）— root 指纹定制和抹除 |
| 本仓库 `launch` app 源码 | 10 项 Root 检测 + 三层架构实际代码 |

**核心思路**：不是拦截检测行为，而是从 AOSP 编译阶段 **消除所有 Root 指纹**，使得检测方"无特征可检"。

---

## 一、6 种主流检测方法 → 本 App 对应实现 → AOSP 对策映射

### 方法 1：Build.prop 调试密钥检测

```
┌─────────────────────────────────────────────────────────────────────┐
│ 检测原理                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ 读取 /system/build.prop 中的:                                         │
│   ro.build.tags=test-keys   ← 非正式签名 → 判定为 Root/Debug 设备      │
│   ro.debuggable=1           ← 可调试 → 存在注入风险                     │
│   ro.secure=0               ← ADB 无认证 → 可被远程控制                 │
└─────────────────────────────────────────────────────────────────────┘
```

**本 App 对应代码**：

该 app 的 `RootDetector.java` 虽然没有直接读取 `ro.build.tags`，但其 Native 层 `root_detector.cpp:386-389` 有 `checkBuildTags()` 函数：

```cpp
// root_detector.cpp:386-389
bool RootDetector::checkBuildTags() {
    std::string content = syscall_read_file("/system/build.prop", 16384);
    return content.find("ro.build.tags=test-keys") != std::string::npos;
}
```

同时 `SideChannelDetector.java:66-129` 检测 SELinux 状态（`/sys/fs/selinux/enforce`），这也是判断设备安全级别的关键特征。

**AOSP 对策**：

#### (a) 修改 build/make/core/Makefile — BUILD_KEYS 源头

```makefile
# build/make/core/Makefile
# 原始代码：
# ifeq ($(TARGET_BUILD_VARIANT),user)
#     BUILD_KEYS := release-keys
# else
#     BUILD_KEYS := test-keys
# endif

# === 修改后：所有变体统一 release-keys ===
ifeq ($(TARGET_BUILD_VARIANT),user)
    BUILD_KEYS := release-keys
else ifeq ($(TARGET_BUILD_VARIANT),userdebug)
    BUILD_KEYS := release-keys      # 原本是 test-keys
else  # eng
    BUILD_KEYS := release-keys      # 原本是 test-keys
endif
```

#### (b) 修改 build/make/tools/buildinfo.sh

```bash
# build/make/tools/buildinfo.sh
# BUILD_VERSION_TAGS 来源于 Makefile 中的 BUILD_KEYS
# 确认此脚本中从环境变量读取 BUILD_VERSION_TAGS 后直接写入 build.prop:
echo "ro.build.tags=$BUILD_VERSION_TAGS"

# 额外硬编码兜底（防止环境变量传递失败）：
if [ -z "$BUILD_VERSION_TAGS" ]; then
    BUILD_VERSION_TAGS="release-keys"
fi

# 同时写入 ro.build.type=user（即使是 userdebug 编译）
echo "ro.build.type=user"
echo "ro.debuggable=0"
echo "ro.secure=1"
echo "ro.adb.secure=1"
```

#### (c) 修改 frameworks/base/core/java/android/os/Build.java

```java
// frameworks/base/core/java/android/os/Build.java
// 硬编码覆盖，双重保险

public static final String TYPE = "user";           // 即使是 userdebug 编译
public static final String TAGS = "release-keys";   // 硬编码

// 覆盖 isDebuggable() — 这是 App 运行时最常用的判断
public static boolean isDebuggable() {
    return false;  // 永远返回 false
}
```

#### (d) device 级 system.prop 全覆盖

```properties
# device/<vendor>/<device>/system.prop
ro.build.tags=release-keys
ro.build.type=user
ro.debuggable=0
ro.secure=1
ro.adb.secure=1

# 指纹伪装（照抄 Pixel 6 真实设备）
ro.build.fingerprint=google/oriole/oriole:13/TQ3A.230901.001/10750268:user/release-keys
ro.build.description=oriole-user 13 TQ3A.230901.001 10750268 release-keys

# 设备信息伪装
ro.product.brand=google
ro.product.manufacturer=Google
ro.product.model=Pixel 6
ro.product.name=oriole

# 编译信息去特征
ro.build.user=android-build
ro.build.host=abfarm-release-rbe-00032
ro.build.date=Thu Aug 31 22:00:00 UTC 2023
ro.build.date.utc=1693522800
```

---

### 方法 2：SuperSU 等特征文件检查

```
┌─────────────────────────────────────────────────────────────────────┐
│ 检测原理                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ 遍历固定路径列表，检查 su/Magisk/KernelSU/APatch 等特征文件是否存在      │
└─────────────────────────────────────────────────────────────────────┘
```

**本 App 对应代码**：

这是该 app 最核心的检测手段，所有 Root 方案都通过路径特征检测：

```java
// RootDetector.java:25-36 — SU 路径 (10个)
private static final String[] SU_PATHS = {
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
    "/system/sd/xbin/su", "/system/bin/failsafe/su",
    "/vendor/bin/su", "/su/bin/su"
};
```

```cpp
// root_detector.cpp:31-41 — Magisk 路径 (8个)
const std::vector<std::string>& RootDetector::getMagiskPaths() {
    return { "/sbin/.magisk", "/data/adb/magisk", "/data/adb/magisk.img",
             "/data/adb/magisk.db", "/cache/magisk.log",
             "/cache/.disable_magisk", "/dev/.magisk.unblock",
             "/data/adb/modules" };
}

// root_detector.cpp:44-52 — KernelSU 路径
{ "/data/adb/ksu", "/data/adb/ksud", "/data/adb/ksu/bin/busybox",
  "/data/adb/ksu/bin/resetprop" }

// root_detector.cpp:54-60 — APatch 路径
{ "/data/adb/ap", "/data/adb/apd", "/data/adb/ap/bin" }

// root_detector.cpp:63-69 — SukiSU 路径
{ "/data/adb/sukisu", "/data/adb/ksu" }
```

检测在三个层级同时进行，Syscall 层使用汇编 `svc #0` 直接发起 `faccessat`：

```cpp
// syscall_wrapper.h:147-149
static inline int syscall_access(const char *path) {
    return (int)syscall_raw(__NR_faccessat, AT_FDCWD, (long)path, F_OK, 0);
}
```

**AOSP 对策**：

#### (a) su 重命名 + 路径清除（核心策略，来自273485文章）

这是文章的核心洞察：**不拦截检测，而是让 su 文件在检测路径中不存在**。

```makefile
# system/extras/su/Android.bp (新版本) 或 Android.mk (旧版本)
cc_binary {
    name: "mysu",           // ← 原来是 "su"，改为无特征名称
    srcs: ["su.c"],
    cflags: ["-Wall"],
    shared_libs: ["libcutils"],
    // 安装到自定义路径
    relative_install_path: "mysu_bin",  // 最终路径: /system/bin/mysu_bin/mysu
}
```

```cpp
// system/core/libcutils/fs_config.cpp
// 修改文件系统配置，移除 /system/xbin/su 的权限配置
// 原始：{ 04750, AID_ROOT, AID_SHELL, 0, "system/xbin/su" },
// 改为：{ 04750, AID_ROOT, AID_SHELL, 0, "system/xbin/mysu" },
static const struct fs_path_config android_files[] = {
    // ... 其他配置 ...
    { 04750, AID_ROOT, AID_SHELL, 0, "system/xbin/mysu" },  // 改名
};
```

```text
# system/sepolicy/private/file_contexts
# 修改 SELinux 文件上下文
# 原始：/system/xbin/su  u:object_r:su_exec:s0
# 改为：
/system/xbin/mysu  u:object_r:su_exec:s0
```

```makefile
# device/<vendor>/<device>/device.mk
# 确保原始路径无任何 su 文件
# 不要在 PRODUCT_COPY_FILES 中出现 /system/bin/su、/system/xbin/su
PRODUCT_COPY_FILES += \
    device/myvendor/mysu:system/xbin/mysu
```

#### (b) Magisk 路径内核层隐藏

```c
// 内核层: fs/namei.c — VFS 路径访问过滤
// 在 inode_permission() 中拦截非白名单进程对 Magisk 路径的探测

#define HIDDEN_PATH_COUNT 8
static const char *hidden_paths[HIDDEN_PATH_COUNT] = {
    "/sbin/.magisk",
    "/data/adb/magisk",
    "/data/adb/ksu",
    "/data/adb/ap",
    "/data/adb/sukisu",
    "/data/adb/magisk.db",
    "/data/adb/modules",
    "/dev/.magisk.unblock",
};

static bool should_hide_path(const char *path) {
    for (int i = 0; i < HIDDEN_PATH_COUNT; i++) {
        if (strncmp(path, hidden_paths[i], strlen(hidden_paths[i])) == 0)
            return true;
    }
    return false;
}

// 在 vfs_path_walk 或 inode_permission 检查点:
static int hidden_path_permission(struct inode *inode, int mask) {
    // 获取当前调用进程信息
    if (!should_hide_from_process(current))
        return 0;  // 白名单进程（如 root shell、Magisk 自身）不受影响

    // 只对非白名单进程返回文件不存在
    return -ENOENT;
}
```

#### (c) 动态路径检测防御

```cpp
// 因为 su 已重命名为 mysu，且不安装在标准 PATH 目录下
// PATH 扫描检测自然失效
// 只需确保 mysu 的安装目录不在 PATH 环境变量中

// 额外：在 init.rc 中配置的 PATH 保持标准值
# init.rc
export PATH /product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin
# 注意：不要添加 mysu 所在的自定义目录到全局 PATH
```

---

### 方法 3：特殊软件包检测

```
┌─────────────────────────────────────────────────────────────────────┐
│ 检测原理                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ 通过 PackageManager 查询 Root 管理类 / 危险工具类应用是否已安装         │
└─────────────────────────────────────────────────────────────────────┘
```

**本 App 对应代码**：

```java
// RootDetector.java:39-50 — Root 管理器包名 (10个)
private static final String[] ROOT_PACKAGES = {
    "com.topjohnwu.magisk",
    "me.weishu.kernelsu",
    "me.bmax.apatch",
    "org.sukisu.manager",
    "com.noshufou.android.su",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "me.phh.superuser"
};
```

```java
// RootDetector.java:586-593 — 检测方法
private boolean isPackageInstalled(String packageName) {
    try {
        context.getPackageManager().getPackageInfo(packageName, 0);
        return true;
    } catch (PackageManager.NameNotFoundException e) {
        return false;
    }
}
```

**AOSP 对策**：

#### PMS 层统一拦截（来自275109文章实践）

```java
// frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java

import java.util.Set;
import java.util.HashSet;
import java.util.stream.Collectors;
import java.util.function.Function;

public class PackageManagerService extends IPackageManager.Stub {

    // === 全量隐藏包名集合 ===

    // Root 管理类
    private static final Set<String> ROOT_MANAGER_PACKAGES = Set.of(
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch",
        "org.sukisu.manager",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
        "me.phh.superuser"
    );

    // 危险工具类
    private static final Set<String> DANGEROUS_PACKAGES = Set.of(
        "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher",
        "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine",
        "com.ramdroid.appquarantinepro",
        "com.android.vending.billing.InAppBillingService.COIN",
        "com.android.vending.billing.InAppBillingService.LUCK",
        "com.chelpus.luckypatcher",
        "com.blackmartalpha",
        "org.blackmart.market",
        "com.allinone.free",
        "com.repodroid.app",
        "org.creeplays.hack",
        "com.baseappfull.fwd",
        "com.zmapp",
        "com.dv.marketmod.installer",
        "org.mobilism.android",
        "com.android.wp.net.log",
        "com.android.camera.update",
        "cc.madkite.freedom"
    );

    // 合并全量
    private static final Set<String> ALL_HIDDEN_PACKAGES;
    static {
        ALL_HIDDEN_PACKAGES = new HashSet<>();
        ALL_HIDDEN_PACKAGES.addAll(ROOT_MANAGER_PACKAGES);
        ALL_HIDDEN_PACKAGES.addAll(DANGEROUS_PACKAGES);
    }

    // === 白名单机制 ===
    // 仅系统核心进程和 Magisk/KernelSU 自己的 daemon 不受影响
    private boolean isTrustedCaller(int callingUid) {
        return callingUid == android.os.Process.SYSTEM_UID
            || callingUid == android.os.Process.ROOT_UID
            || callingUid == android.os.Process.SHELL_UID;
    }

    // === 拦截所有查询接口 ===

    @Override
    public PackageInfo getPackageInfo(String packageName, int flags, int userId) {
        int callingUid = Binder.getCallingUid();
        PackageInfo result = getPackageInfoInternal(packageName, flags, userId);
        if (result != null && !isTrustedCaller(callingUid)
            && ALL_HIDDEN_PACKAGES.contains(packageName)) {
            throw new PackageManager.NameNotFoundException(packageName);
        }
        return result;
    }

    @Override
    public ApplicationInfo getApplicationInfo(String packageName, int flags, int userId) {
        int callingUid = Binder.getCallingUid();
        if (!isTrustedCaller(callingUid)
            && ALL_HIDDEN_PACKAGES.contains(packageName)) {
            throw new PackageManager.NameNotFoundException(packageName);
        }
        return getApplicationInfoInternal(packageName, flags, userId);
    }

    @Override
    public List<PackageInfo> getInstalledPackages(int flags, int userId) {
        int callingUid = Binder.getCallingUid();
        List<PackageInfo> result = getInstalledPackagesInternal(flags, userId);
        if (isTrustedCaller(callingUid)) return result;
        return result.stream()
            .filter(pkg -> !ALL_HIDDEN_PACKAGES.contains(pkg.packageName))
            .collect(Collectors.toList());
    }

    @Override
    public List<ApplicationInfo> getInstalledApplications(int flags, int userId) {
        int callingUid = Binder.getCallingUid();
        List<ApplicationInfo> result = getInstalledApplicationsInternal(flags, userId);
        if (isTrustedCaller(callingUid)) return result;
        return result.stream()
            .filter(app -> !ALL_HIDDEN_PACKAGES.contains(app.packageName))
            .collect(Collectors.toList());
    }
}
```

---

### 方法 4：/data 目录权限测试

```
┌─────────────────────────────────────────────────────────────────────┐
│ 检测原理                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ 尝试在 /data、/system、/etc 等只有 root 才有写入权限的目录创建文件      │
│ 如果在非 root 权限下能写入 → 说明有 root 权限                          │
│ 如果能读取某些 root-only 文件 → 说明有 root 权限                       │
└─────────────────────────────────────────────────────────────────────┘
```

**本 App 对应代码**：

该 app 没有直接的目录写测试，但通过多层文件检测本质上等价——**三层（Java/Native/Syscall）逐级验证文件存在性**，Syscall 层的 `svc #0` 能绕过一切用户态 Hook 直接触达内核。此外：

- `SideChannelDetector.java` 读取 `/sys/fs/selinux/enforce` 等敏感系统文件
- `ReadlinkDetector.java` 读取 `/proc/self/root`、`/proc/self/fd` 等
- 可疑挂载检测读取 `/proc/self/mountinfo` 并分析挂载来源

**AOSP 对策**：

#### 内核 VFS 层兜底过滤

```c
// 内核源码: fs/namei.c
// 在 vfs 路径解析阶段，对敏感目录的探测返回"权限拒绝"

static bool is_sensitive_dir_for_hiding(const char *path) {
    // 匹配需要隐藏的敏感目录路径
    if (strncmp(path, "/data/adb/", 10) == 0)      return true;
    if (strncmp(path, "/sbin/.magisk", 13) == 0)   return true;
    if (strncmp(path, "/dev/.magisk", 12) == 0)    return true;
    if (strncmp(path, "/cache/.disable_magisk", 23) == 0) return true;
    return false;
}

static int root_hidden_permission_check(struct inode *inode, int mask,
                                         const char *path) {
    // 仅对"写入权限检查"或"存在性检查"进行拦截
    // 对于白名单进程放行
    if (should_hide_from_process(current)) {
        if (is_sensitive_dir_for_hiding(path)) {
            // 返回 EACCES 模拟"无权限访问"（比 ENOENT 更自然）
            return -EACCES;
        }
        // 对 /data、/system、/etc 目录上的写权限检查统一拒绝
        if ((mask & MAY_WRITE) && (
            strncmp(path, "/data", 5) == 0 ||
            strncmp(path, "/system", 7) == 0 ||
            strncmp(path, "/etc", 4) == 0)) {
            return -EACCES;
        }
    }
    return 0;
}

// 在 inode_permission() 函数中插入调用:
int inode_permission(struct user_namespace *mnt_userns, struct inode *inode, int mask) {
    int ret = root_hidden_permission_check(inode, mask, get_current_path());
    if (ret < 0) return ret;
    // ... 原始逻辑
}
```

#### /proc 文件系统过滤

```c
// 内核源码: fs/proc/array.c — 过滤 /proc/self/status 中的 TracerPid
// 本 app 的 HookDetector.java 会检查 TracerPid 来判断是否被 ptrace 监控

static int proc_pid_status(struct seq_file *m, struct pid_namespace *ns,
                            struct pid *pid, struct task_struct *task) {
    // ... 原始逻辑 ...
    
    // 隐藏 TracerPid：非白名单进程永远看到 0
    if (should_hide_from_process(current)) {
        seq_put_decimal_ull(m, "\nTracerPid:\t", 0);
    } else {
        seq_put_decimal_ull(m, "\nTracerPid:\t", task->ptrace ? task->parent->pid : 0);
    }
    // ...
}
```

```c
// 内核源码: fs/proc/task_mmu.c — 过滤 /proc/self/maps
// 本 app 在 RootDetector.java、ZygoteDetector.java、HookDetector.java
// 等多处读取 /proc/self/maps 匹配 Root/Hook 签名

static int show_map_vma(struct seq_file *m, struct vm_area_struct *vma) {
    // ... 获取 maps 行内容 ...
    char path_buf[PATH_MAX];
    char *path = get_vma_path(vma, path_buf, sizeof(path_buf));
    
    // 如果映射路径包含了 Magisk/Zygisk/Riru/模块 等敏感路径，过滤掉
    if (path && should_hide_from_process(current)) {
        if (strstr(path, "magisk") || strstr(path, "zygisk")
            || strstr(path, "riru")   || strstr(path, "lsposed")
            || strstr(path, "/data/adb/modules/")
            || strstr(path, "libzygisk.so")) {
            return 0;  // 跳过，不输出到 maps
        }
    }
    // ... 原始逻辑
}
```

```c
// 内核源码: fs/proc/task_mmu.c — 过滤 /proc/self/smaps
// 本 app 的 SMAPS 完整性检测会通过 Private_Dirty 判断代码篡改
// 虽然无法完全隐藏 COW 行为，但可以隐藏敏感库的 smaps 条目

// 过滤 /proc/filesystems 中的 "susfs" — 本 app 的 SukiSU 检测
// 内核源码: fs/filesystems.c
static int filesystems_proc_show(struct seq_file *m, void *v) {
    struct file_system_type *fs = v;
    if (should_hide_from_process(current)) {
        // 隐藏 susfs 文件系统类型
        if (strcmp(fs->name, "susfs") == 0)
            return 0;  // 跳过
    }
    seq_printf(m, "\t%s\n", fs->name);
    return 0;
}
```

---

### 方法 5：Shell 命令执行测试

```
┌─────────────────────────────────────────────────────────────────────┐
│ 检测原理                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ Runtime.exec("su") 执行，如果 su 能返回 shell 交互 → 判定为 Root        │
│ Runtime.exec("which su") 在 PATH 中搜索 su                            │
│ Runtime.exec("find / -name su") 全盘搜索                              │
└─────────────────────────────────────────────────────────────────────┘
```

**本 App 对应代码**：

该 app 通过 `detectDynamicSuPaths()` 遍历 PATH 环境变量搜索 su/magisk/ksud/apd：

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
                if (new File(fullPath).exists()) { detected = true; }
                if (nativeDetector.fileExistsNative(fullPath)) { detected = true; }
            }
        }
    }
}
```

**AOSP 对策**：

#### su 重命名策略天然防 shell 检测

由于 su 已改名为 `mysu`，所有形式的 shell 命令探测自然失效：

```bash
# 检测方的命令全部返回空/失败:
$ which su       → (空)
$ type su        → su: not found
$ find /system -name su → (空)
$ find /sbin -name su   → (空)
$ ls /system/xbin/su    → No such file or directory

# 只有知道新名称的管理者才能使用:
$ /system/xbin/mysu     → # (root shell)
```

#### Runtime.exec 层额外防御

```java
// frameworks/base/core/java/java/lang/ProcessBuilder.java
// 在进程创建时的 exec 阶段做命令过滤

public class ProcessBuilder {
    // ...
    Process start() throws IOException {
        // 对敏感命令做二次确认
        for (String cmd : command) {
            if (isSuspiciousRootCommand(cmd)) {
                // 如果发现直接执行 "su" 的请求，替换为 false
                throw new IOException("Error running exec(). Command not found");
            }
        }
        return ProcessImpl.start(command, environment, dir, redirects, redirectErrorStream);
    }

    private static boolean isSuspiciousRootCommand(String cmd) {
        // su 已经重命名，这里处理特殊情况: 硬编码路径调用
        return cmd.equals("su")
            || cmd.endsWith("/su")
            || cmd.equals("/system/bin/su")
            || cmd.equals("/system/xbin/su")
            || cmd.equals("/sbin/su");
    }
}
```

---

### 方法 6：su 文件存在性验证

```
┌─────────────────────────────────────────────────────────────────────┐
│ 检测原理                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ 对固定路径用 Java File.exists() / libc access() / 直接 syscall        │
│ 三重验证 su 文件是否真实存在                                           │
│ 三层检测逻辑：任一层检测到即为风险                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**本 App 对应代码**：

这是该 app 最强大的架构设计——**三层递进式检测**：

```java
// RootDetector.java:97-134 — 三层检测典型模式
public DetectionItem detectSuFiles() {
    DetectionItem item = new DetectionItem("SU 文件检测", "检测 SU 二进制文件");

    // Java 层：new File(path).exists()
    boolean javaResult = checkSuFilesJavaDetailed(detectedPaths);
    item.setLayerResult(DetectionLayer.JAVA, javaResult);

    // Native 层：access(path, F_OK) — libc
    boolean nativeResult = nativeDetector.checkSuFilesNative();
    item.setLayerResult(DetectionLayer.NATIVE, nativeResult);

    // Syscall 层：汇编 SVC #0 — 绕过所有用户态 Hook
    boolean syscallResult = nativeDetector.checkSuFilesSyscall();
    item.setLayerResult(DetectionLayer.SYSCALL, syscallResult);

    // 任意一层检测到 → 判定 RISK
    if (item.getMostTrustworthyResult()) {
        item.setStatus(DetectionStatus.RISK);
    }
}
```

```cpp
// syscall_wrapper.h:97-116 — ARM64 直接 SVC 指令（极难绕过）
static inline long syscall_raw(long number, ...) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = arg0;
    // ...
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory"
    );
    return x0;
}
```

**AOSP 对策**：

#### 三层逆向对抗策略

```
层级          App 检测方法            AOSP 对抗策略
───────────────────────────────────────────────────────────
Java 层        File.exists()          su 已重命名 → 永远不存在
Native 层      access(F_OK)           su 已重命名 → 永远不存在
Syscall 层     SVC #0 + faccessat     内核 VFS 层返回 -ENOENT（兜底）
```

**Syscall 层的终极保证**：即使 App 绕过一切 Hook 直接 syscall，内核层的 VFS 过滤依然生效——因为过滤发生在 `inode_permission()` 中，这是 **所有文件访问系统调用的必经之路**。

```c
// 所有文件访问最终都会调用到 inode_permission
// SVC #0 → SYS_faccessat → user_path_at_empty → filename_lookup
//   → link_path_walk → walk_component → step_into
//     → may_lookup → inode_permission()
//                        ↓
//                  这里就是拦截点
```

**结论**：su 重命名 + 内核 VFS 过滤 的双重防御，可以同时应对 Java/Native/Syscall 三层检测。

---

## 二、App 特有检测的额外对策

除了上述 6 种主流方法，该 app 还有以下特有检测需要应对：

### 2.1 可疑挂载检测 → /proc/self/mountinfo 过滤

```c
// 内核: fs/proc_namespace.c
// 过滤 mountinfo 中的敏感条目
static int show_mountinfo(struct seq_file *m, struct vfsmount *mnt) {
    char *mount_source = get_mount_source(mnt);
    char *mount_point = get_mount_point(mnt);
    
    if (should_hide_from_process(current)) {
        if (strstr(mount_source, "magisk") || strstr(mount_point, "magisk")
         || strstr(mount_source, "zygisk") || strstr(mount_point, "zygisk")
         || strstr(mount_source, "kernelsu") || strstr(mount_point, "kernelsu")
         || strstr(mount_point, "/data/adb/")) {
            return 0;  // 跳过此行
        }
    }
    // ... 正常输出
}
```

### 2.2 Readlink 检测 → 符号链接目标过滤

该 app 的 `ReadlinkDetector.java` 读取 `/proc/self/exe` 和各种符号链接目标：

```c
// 内核: fs/proc/base.c
// proc_pid_readlink() - 保证 /proc/self/root 返回 "/"
// 已由 su 重命名策略覆盖，因为 exe/maps/mounts 中不存在 magisk/su 等关键词
```

### 2.3 Zygisk 检测 → 守护进程 + 内存映射双重隐藏

```java
// ZygoteDetector.java:209-234 — 扫描 /proc 中所有 cmdline 找 zygiskd 守护进程
// 对策: 在 proc_pid_cmdline 读取时过滤

// HookDetector.java:1677-1721 — 扫描 /proc/self/maps 找 libzygisk.so
// 对策: 在内核 show_map_vma 中过滤（见上方 /proc/self/maps 过滤）
```

---

## 三、完整文件修改清单

```
AOSP 根目录
│
├── build/make/
│   ├── core/Makefile                          [改] BUILD_KEYS → release-keys
│   └── tools/buildinfo.sh                     [改] 写入 user + release-keys 属性
│
├── frameworks/base/
│   ├── core/java/android/os/
│   │   ├── Build.java                         [改] TYPE/TAGS 硬编码, isDebuggable()=false
│   │   └── SystemProperties.java              [改] 属性读取拦截（可选）
│   ├── core/java/java/lang/
│   │   └── ProcessBuilder.java                [改] su 命令过滤（兜底）
│   └── services/core/java/com/android/server/
│       └── pm/PackageManagerService.java      [改] 43+ 个包名全量过滤
│
├── system/extras/su/
│   ├── Android.bp                             [改] su → mysu, 自定义路径
│   └── su.c                                   [检] 确保无特征字符串
│
├── system/core/libcutils/
│   └── fs_config.cpp                          [改] su → mysu
│
├── system/sepolicy/private/
│   └── file_contexts                          [改] su_exec 路径
│
├── device/<vendor>/<device>/
│   ├── system.prop                            [改] 全量属性覆盖（ro.build.fingerprint等）
│   ├── device.mk                              [改] 不部署 /system/bin/su
│   └── init.rc                                [检] PATH 不含自定义 su 目录
│
└── kernel/<device>/
    ├── fs/namei.c                             [改] VFS 路径过滤（inode_permission）
    ├── fs/proc/array.c                        [改] TracerPid 过滤
    ├── fs/proc/task_mmu.c                     [改] maps/smaps 条目过滤
    ├── fs/proc/base.c                         [改] cmdline/readlink 过滤
    ├── fs/proc_namespace.c                    [改] mountinfo 条目过滤
    └── fs/filesystems.c                       [改] susfs 隐藏
```

---

## 四、优先级与效果矩阵

```
优先级  措施                      实现难度  覆盖的 App 检测项
──────────────────────────────────────────────────────────────────
P0 ★★★  su 重命名 + 路径自定义     低       SU文件检测、动态路径检测、
                                            Shell命令测试、文件存在性验证

P0 ★★★  test-keys → release-keys  低       Build.prop调试密钥检测
        (Makefile + buildinfo.sh)

P0 ★★★  ro.debuggable=0 等属性    低       Build.prop调试密钥检测、
        全覆盖 (system.prop)                buildTags检测

P1 ★★   PMS 包名全量过滤 (43+)    中       Root管理器检测、
                                           特殊软件包检测

P1 ★★   Build.java 硬编码         低       Build.prop调试密钥检测（运行时保险）

P2 ★     内核 /proc/maps 过滤      高       Zygisk注入检测、Riru/Dreamland检测、
                                           内存映射检测、SMAPS检测

P2 ★     内核 /proc/mountinfo 过滤 高       可疑挂载检测

P2 ★     内核 VFS 路径过滤         高       SU文件Syscall检测（终极兜底）、
        (inode_permission)                 /data目录权限测试

P2 ★     内核 /proc/status 过滤    高       Zygote注入检测 (TracerPid)
```

**P0 三件套是最低成本、最高收益的基础方案**：
- su 重命名从根本上消除了 "su 文件存在性" 这个最大检测目标
- test-keys→release-keys 消除了编译类型特征
- system.prop 全量属性覆盖消除设备指纹差异

**P1 是用户态的最强补充**，直接对抗包名查询检测。

**P2 是内核态兜底**，成本最高但对 Syscall 层检测（该 app 最核心的优势）提供终极对抗。
