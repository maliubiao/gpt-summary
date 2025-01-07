Response:
Let's break down the thought process for analyzing the provided `audit.h` header file.

1. **Identify the Core Purpose:** The filename `audit.handroid` and the comment "bionic is Android's C library..." immediately tell us this file defines structures and constants related to the Linux audit subsystem within the Android environment. The `#ifndef _UAPI_LINUX_AUDIT_H_` confirms it's a header file intended for inclusion in user-space (uapi).

2. **High-Level Feature Extraction:**  A quick scan reveals a lot of `#define` statements. These are likely constants defining various audit events, filters, and configuration options. The presence of `AUDIT_GET`, `AUDIT_SET`, `AUDIT_ADD`, `AUDIT_DEL`, etc., suggests a system for managing audit rules and retrieving audit information.

3. **Categorize the Constants:**  Start grouping the `#define` constants logically:
    * **Control Operations:** `AUDIT_GET`, `AUDIT_SET`, `AUDIT_LIST`, `AUDIT_ADD`, `AUDIT_DEL`, etc. These seem to be commands you can issue to the audit subsystem.
    * **Event Types:**  `AUDIT_USER_AVC`, `AUDIT_USER_TTY`, `AUDIT_DAEMON_START`, `AUDIT_SYSCALL`, `AUDIT_EXECVE`, `AUDIT_MMAP`, `AUDIT_AVC`, etc. These represent the different types of events the audit system can record. Notice the patterns: `AUDIT_USER_...`, `AUDIT_DAEMON_...`, `AUDIT_...`.
    * **Filter Options:** `AUDIT_FILTER_USER`, `AUDIT_FILTER_TASK`, `AUDIT_FILTER_ENTRY`, `AUDIT_FILTER_WATCH`, etc. These are used to specify which events should be audited.
    * **Comparison Operators:** `AUDIT_NEGATE`, `AUDIT_BIT_MASK`, `AUDIT_LESS_THAN`, `AUDIT_GREATER_THAN`, etc. These are used in audit rules to create conditions.
    * **Status Flags:** `AUDIT_STATUS_ENABLED`, `AUDIT_STATUS_FAILURE`, `AUDIT_STATUS_PID`, etc. These describe the current state of the audit subsystem.
    * **Feature Bits:** `AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT`, `AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH`, etc. These indicate optional features the audit system supports.
    * **Architectures:** `AUDIT_ARCH_AARCH64`, `AUDIT_ARCH_ARM`, `AUDIT_ARCH_X86_64`, etc. This indicates support for filtering audits based on the system architecture.
    * **Permissions:** `AUDIT_PERM_EXEC`, `AUDIT_PERM_WRITE`, `AUDIT_PERM_READ`, etc. Used in audit rules related to file access.

4. **Identify Structures:** The presence of `struct audit_status`, `struct audit_features`, `struct audit_tty_status`, and `struct audit_rule_data` is crucial. These define the data structures used to interact with the audit subsystem. Note the members of each struct and their likely purpose (e.g., `mask` and `enabled` in `audit_status`).

5. **Relate to Android:**  Consider how these audit features might be used in Android.
    * **Security Auditing:**  A primary use case. Auditing system calls, file accesses, security policy changes (SELinux - note `AUDIT_AVC`, `AUDIT_SELINUX_ERR`).
    * **Debugging/Troubleshooting:**  Tracking down issues by logging system events.
    * **Security Enforcement:**  Potentially used by security frameworks to monitor for policy violations.

6. **Libc Function Mapping (Conceptual):** While the header file itself *doesn't contain libc function implementations*, it *defines the constants used by* libc functions that interact with the kernel's audit subsystem. The relevant libc functions would be syscall wrappers like `syscall(SYS_AUDIT, ...)`. The header defines the `cmd` argument and potentially structures used in the `args`.

7. **Dynamic Linker (Indirect Relation):** The audit subsystem can log events related to library loading (though not explicitly shown in *this* header). Think about `dlopen`, `mmap` (for loading shared objects), and how these might be audited. The dynamic linker itself isn't directly *defined* here, but its actions *can be audited*.

8. **Common Usage Errors:**  Think about how developers might misuse the audit system:
    * **Not enabling auditing:** Forgetting to configure and start the audit daemon.
    * **Too broad rules:**  Creating rules that generate excessive logs, impacting performance.
    * **Incorrect filtering:**  Missing important events or capturing irrelevant ones.
    * **Misinterpreting logs:**  Understanding the structure and meaning of audit log messages is crucial.

9. **Android Framework/NDK Path:**  Consider how a request to audit an event might travel:
    * **App/NDK:** An app might perform an action (e.g., open a file).
    * **System Call:** This action translates into a system call (e.g., `openat`).
    * **Kernel Audit Subsystem:** The kernel intercepts the syscall and, based on the configured audit rules, generates an audit event.
    * **Audit Daemon:** The audit daemon (`auditd`) reads these events from the kernel and writes them to a log file.
    * **Framework (Potentially):**  The Android framework itself might configure audit rules or read audit logs for specific purposes.

10. **Frida Hooking:**  Think about where you could intercept the audit process:
    * **System Call Level:** Hooking the `syscall` function with `SYS_AUDIT`.
    * **Audit Daemon:** Hooking functions within `auditd` to see how it processes events.
    * **Libc wrappers:** If specific libc functions exist for audit interaction (likely), they could be hooked.

11. **Structure and Refine:** Organize the information into logical sections, like the provided good example answer. Provide specific examples where possible. Use clear and concise language. Avoid overly technical jargon where simpler terms suffice.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "These are just constants."  **Correction:**  These constants define the *interface* to the audit subsystem. Understanding them is key to understanding how it works.
* **Initial thought:** "This file implements audit functionality." **Correction:** This is a *header file*. It *declares* interfaces and data structures, but the *implementation* is in the kernel and potentially some libc functions (not shown here).
* **Consider the "why":**  Why does Android need auditing?  Focus on security, debugging, and compliance.
* **Be precise about terminology:**  Distinguish between user-space and kernel-space. Explain what a system call is.

By following this systematic breakdown, categorizing information, connecting it to Android concepts, and considering practical aspects like usage errors and debugging, you can arrive at a comprehensive understanding of the provided `audit.h` file.
这个文件 `bionic/libc/kernel/uapi/linux/audit.handroid` 是 Android Bionic C 库中的一个头文件，它定义了与 Linux 审计子系统相关的用户空间 API（UAPI）。  这意味着它定义了用户空间程序可以用来与内核中的审计功能进行交互的常量、结构体和宏。

**它的功能：**

该头文件定义了与 Linux 审计子系统交互所需的各种常量和数据结构，主要功能可以归纳为：

1. **定义审计事件类型（Audit Event Types）：**  定义了各种可以被审计的系统事件，例如：
    * `AUDIT_SYSCALL`: 系统调用事件
    * `AUDIT_EXECVE`: `execve` 系统调用（程序执行）事件
    * `AUDIT_OPENAT2`: `openat2` 系统调用（文件打开）事件
    * `AUDIT_MMAP`: `mmap` 系统调用（内存映射）事件
    * `AUDIT_SOCKETCALL`: 套接字相关系统调用事件
    * `AUDIT_USER_AVC`: SELinux 访问控制向量 (AVC) 消息
    * `AUDIT_USER_TTY`: 用户终端 (TTY) 活动
    * `AUDIT_DAEMON_START`, `AUDIT_DAEMON_END`: 审计守护进程的启动和结束
    * 以及许多其他与文件系统操作、进程管理、网络、安全相关的事件。

2. **定义审计控制操作（Audit Control Operations）：**  定义了用于管理审计规则和状态的操作码，例如：
    * `AUDIT_GET`: 获取审计状态
    * `AUDIT_SET`: 设置审计状态
    * `AUDIT_ADD_RULE`: 添加审计规则
    * `AUDIT_DEL_RULE`: 删除审计规则
    * `AUDIT_LIST_RULES`: 列出审计规则

3. **定义审计过滤器（Audit Filters）：** 定义了用于指定哪些事件应该被审计的过滤器类型，例如：
    * `AUDIT_FILTER_USER`: 用户空间过滤器
    * `AUDIT_FILTER_TASK`: 任务过滤器
    * `AUDIT_FILTER_EXIT`: 退出过滤器

4. **定义审计规则字段（Audit Rule Fields）：** 定义了在审计规则中可以用于匹配的各种字段，例如：
    * `AUDIT_PID`: 进程 ID
    * `AUDIT_UID`: 用户 ID
    * `AUDIT_EUID`: 有效用户 ID
    * `AUDIT_GID`: 组 ID
    * `AUDIT_EGID`: 有效组 ID
    * `AUDIT_ARCH`: 体系结构
    * `AUDIT_MSGTYPE`: 消息类型
    * `AUDIT_ARG0`, `AUDIT_ARG1`, ...: 系统调用参数

5. **定义审计规则比较操作符（Audit Rule Comparison Operators）：** 定义了用于在审计规则中进行比较的操作符，例如：
    * `AUDIT_EQUAL`: 等于
    * `AUDIT_NOT_EQUAL`: 不等于
    * `AUDIT_LESS_THAN`: 小于
    * `AUDIT_GREATER_THAN`: 大于

6. **定义审计状态标志（Audit Status Flags）：** 定义了表示审计子系统状态的标志，例如：
    * `AUDIT_STATUS_ENABLED`: 审计是否启用
    * `AUDIT_STATUS_FAILURE`: 失败处理模式

7. **定义审计特征位图（Audit Feature Bitmaps）：** 定义了审计子系统支持的可选功能。

8. **定义架构常量（Architecture Constants）：** 定义了各种处理器架构的常量，用于在审计规则中指定架构。

9. **定义权限常量（Permission Constants）：** 定义了文件权限的常量，用于在审计规则中指定需要审计的权限。

10. **定义数据结构（Data Structures）：** 定义了与审计子系统交互时使用的数据结构，例如：
    * `struct audit_status`: 用于获取和设置审计状态。
    * `struct audit_rule_data`: 用于添加和删除审计规则。
    * `struct audit_features`: 用于获取审计子系统的特性。
    * `struct audit_tty_status`: 用于获取和设置 TTY 审计状态。

**它与 Android 功能的关系及举例说明：**

Linux 审计子系统是 Android 安全框架的一个重要组成部分，用于记录系统中发生的各种安全相关的事件。 Android 使用审计子系统来实现以下功能：

* **安全审计和监控:**  记录关键系统调用、文件访问、网络连接、安全策略变更等事件，用于安全分析、入侵检测和合规性检查。
    * **例如:** Android 可以配置审计规则来记录所有对敏感文件（如 `/data/system/packages.list`）的访问，以便追踪潜在的恶意行为。对应的 `AUDIT_PATH` 事件类型和 `AUDIT_PERM_READ`/`AUDIT_PERM_WRITE` 权限可以用于定义此类规则。
* **SELinux 集成:**  审计子系统与 SELinux 集成，记录 SELinux 的访问控制决策 (AVC 消息)。 `AUDIT_USER_AVC` 和相关的 `AUDIT_AVC_PATH` 事件类型用于记录这些信息，帮助开发者和安全分析师理解 SELinux 的行为。
    * **例如:** 当一个应用尝试访问其没有权限访问的资源时，SELinux 会拒绝该操作，并且审计子系统会记录一个 `AUDIT_USER_AVC` 事件，包含被拒绝的访问类型、主体、客体等信息。
* **完整性监控:**  可以使用审计规则来监控关键文件的修改，以检测系统完整性是否受到破坏。
    * **例如:** 可以配置审计规则来监控系统关键库文件（如 Bionic 库本身）的修改。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身**不包含**任何 libc 函数的实现。它只是一个头文件，定义了常量和数据结构。  与审计子系统交互的实际 libc 函数通常是 `syscall()` 函数的包装器。  用户空间的程序会使用这些常量和结构体，通过 `syscall()` 发送相应的命令到内核中的审计子系统。

例如，要获取审计状态，程序可能会使用 `syscall(SYS_AUDIT, AUDIT_GET, &status)`，其中 `SYS_AUDIT` 是审计相关的系统调用号，`AUDIT_GET` 是定义在这个头文件中的常量，`&status` 是一个 `struct audit_status` 类型的指针，用于接收内核返回的状态信息。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件本身**不直接**涉及 dynamic linker 的功能。 然而，dynamic linker 的行为可以通过审计子系统进行监控。 例如，`dlopen()` 函数加载共享库时，可能会触发与文件访问相关的审计事件（例如 `AUDIT_OPENAT2`）。

**so 布局样本 (假设我们审计了 `dlopen` 加载 `libfoo.so` 的过程):**

```
# type=PROCTITLE msg=audit(1678886400.123:456): proctitle=test_app
# type=SYSCALL msg=audit(1678886400.123:456): arch=x86_64 syscall=__NR_openat ... pathname="/system/lib64/libfoo.so" ...
# type=PATH msg=audit(1678886400.123:456): item=0 name="/system/lib64/libfoo.so" inode=123456 dev=ca:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 syz_dev=00:00 syz_inode=0
# type=MMAP msg=audit(1678886400.123:457): ... a0=7f881234000 a1=8000 ...
```

* **`PROCTITLE`:**  记录了执行 `dlopen` 的进程的命令行。
* **`SYSCALL`:** 记录了 `openat` 系统调用，这是 dynamic linker 加载共享库时打开文件的一部分。
* **`PATH`:** 提供了被访问的文件路径和相关属性。
* **`MMAP`:** 记录了 dynamic linker 将共享库映射到进程地址空间的操作。

**链接的处理过程:**

当 `dlopen("libfoo.so", ...)` 被调用时：

1. **查找共享库:** dynamic linker 会根据配置的路径（例如 LD_LIBRARY_PATH）查找 `libfoo.so` 文件。
2. **打开共享库:**  dynamic linker 使用 `openat` 等系统调用打开 `libfoo.so` 文件，这会触发 `AUDIT_SYSCALL` 和 `AUDIT_PATH` 事件。
3. **内存映射:** dynamic linker 使用 `mmap` 系统调用将 `libfoo.so` 的不同段（代码段、数据段等）映射到调用进程的地址空间，这会触发 `AUDIT_MMAP` 事件。
4. **符号解析和重定位:** dynamic linker 解析 `libfoo.so` 的符号表，并将其引用的外部符号链接到相应的地址。 这个过程本身可能不会直接产生特定的审计事件，但与内存操作相关联。

**如果做了逻辑推理，请给出假设输入与输出：**

假设我们添加了一条审计规则来监控对 `/etc/passwd` 文件的读取操作：

**假设输入（通过 `syscall(SYS_AUDIT, AUDIT_ADD_RULE, &rule)`）：**

```c
struct audit_rule_data rule;
rule.flags = 0;
rule.action = AUDIT_ALWAYS; // 总是记录
rule.field_count = 2;
rule.fields[0] = AUDIT_MSGTYPE;
rule.values[0] = AUDIT_SYSCALL;
rule.fieldflags[0] = 0;
rule.fields[1] = AUDIT_PATH;
rule.values[1] = (unsigned long long)"/etc/passwd";
rule.fieldflags[1] = 0;
// ... 其他字段初始化 ...
```

**假设输出（当某个进程读取 `/etc/passwd` 文件时，在审计日志中）：**

```
type=SYSCALL msg=audit(1678887000.456:789): arch=x86_64 syscall=__NR_openat ... pathname="/etc/passwd" ...
type=PATH msg=audit(1678887000.456:789): item=0 name="/etc/passwd" inode=654321 dev=ca:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 syz_dev=00:00 syz_inode=0
```

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **未启用审计守护进程 (auditd):**  即使配置了审计规则，如果 `auditd` 服务没有运行，审计事件将不会被记录到磁盘。 这是一个非常常见的错误，导致用户误以为审计功能失效。

2. **配置过于宽泛的规则:**  配置了过于宽泛的审计规则，例如记录所有系统调用，会导致产生大量的审计日志，消耗大量的磁盘空间，并可能影响系统性能。

3. **配置过于严格的规则:**  配置了过于严格的审计规则，可能会遗漏重要的安全事件。

4. **错误地理解审计日志的含义:**  审计日志包含大量的细节信息，如果不能正确理解这些信息的含义，就无法有效地进行安全分析。 例如，区分成功的和失败的系统调用非常重要。

5. **权限问题:**  尝试配置或读取审计规则可能需要 root 权限。 普通用户可能无法执行某些审计操作。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android Framework 或 NDK 应用本身不会直接调用底层的 `syscall(SYS_AUDIT, ...)`。 它们通常通过更高层次的抽象接口与内核审计子系统交互。  这些抽象可能存在于 Framework 的 Java 代码中，或者在 Native 代码中通过封装好的 C/C++ 库来实现。

**Android Framework 到审计子系统的路径：**

1. **Framework API 调用:** Android Framework 中的某些安全相关的服务（例如 `SecurityLog` 服务）可能会接收来自应用程序或系统的安全事件通知。
2. **Binder IPC:**  这些服务通常通过 Binder IPC 与底层的 Native 代码进行通信。
3. **Native 代码 (C++/Java Native Interface - JNI):** Framework 的 Native 代码部分可能会使用 `liblog` 库或其他内部机制来记录安全日志。
4. **Kernel Logging (可选):** 某些情况下，Framework 可能会将事件记录到内核日志缓冲区 (dmesg)，但这通常不是直接的审计。
5. **Audit Daemon (auditd):**  `auditd` 守护进程独立于 Framework 运行，负责读取内核审计事件并将它们写入日志文件。 Framework 可能不会直接与 `auditd` 交互，而是依赖内核审计子系统和 `auditd` 的配置。

**NDK 到审计子系统的路径：**

1. **NDK 应用调用系统调用:** NDK 应用可以直接使用 `syscall()` 函数调用 Linux 系统调用，包括与审计相关的系统调用（尽管这通常不推荐，而是应该使用更高层次的库）。
2. **封装库:**  更常见的情况是，NDK 应用会使用 Bionic 提供的标准 C 库函数，这些函数在内部会调用相应的系统调用。  例如，如果 NDK 应用执行了 `open()` 操作，而系统配置了对文件打开的审计规则，那么内核就会生成相应的审计事件。

**Frida Hook 示例：**

假设我们想监控 NDK 应用中 `openat` 系统调用是否触发了审计事件。我们可以 hook `openat` 系统调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

device = frida.get_usb_device(timeout=10)
pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

try:
    if pid:
        session = device.attach(pid)
    else:
        package_name = "your.ndk.app" # 替换为你的 NDK 应用包名
        pid = device.spawn([package_name])
        session = device.attach(pid)
        device.resume(pid)
except frida.ProcessNotFoundError:
    print(f"Process with PID {pid} not found.")
    sys.exit(1)
except frida.ServerNotRespondingError:
    print("Frida server not responding. Ensure frida-server is running on the device.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "openat"), {
    onEnter: function(args) {
        this.pathname = Memory.readUtf8String(args[1]);
        console.log(`[+] openat() called with pathname: ${this.pathname}`);
    },
    onLeave: function(retval) {
        console.log(`[+] openat() returned: ${retval}`);
        // 这里可以添加逻辑来检查是否产生了相应的审计日志
        // 可以尝试读取审计日志文件（需要 root 权限）或者监控 auditd 的活动
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 示例:**

1. **连接到设备和进程:**  代码首先尝试连接到 USB 设备上的 Frida 服务，并附加到指定的进程 ID 或启动一个 NDK 应用。
2. **Hook `openat`:**  使用 `Interceptor.attach` hook 了 `openat` 系统调用。
3. **`onEnter`:**  在 `openat` 函数调用之前，`onEnter` 函数被执行，读取并打印了要打开的文件路径。
4. **`onLeave`:** 在 `openat` 函数返回之后，`onLeave` 函数被执行，打印了返回值。
5. **检查审计日志 (需要在 `onLeave` 中实现):**  在 `onLeave` 函数中，你可以添加额外的逻辑来检查是否因为这次 `openat` 调用产生了相应的审计日志。这通常需要：
    * **读取审计日志文件:**  这需要 root 权限，并且要知道审计日志文件的位置（通常是 `/var/log/audit/audit.log` 或类似的位置）。
    * **监控 `auditd` 的活动:**  可以使用其他 Frida hook 或系统工具来监控 `auditd` 守护进程的行为。

**注意:**  直接读取审计日志文件通常需要 root 权限。 在非 root 设备上，Frida 可能无法直接访问这些文件。  监控审计事件的更常见方法是在运行审计的系统上分析审计日志，或者使用专门的审计分析工具。

总结来说，这个头文件是理解 Android 系统审计机制的基础，它定义了用户空间程序与内核审计子系统交互的 "词汇表"。 虽然 Android 应用通常不直接操作这些底层的常量和结构体，但理解它们有助于深入理解 Android 的安全审计功能。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/audit.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_LINUX_AUDIT_H_
#define _UAPI_LINUX_AUDIT_H_
#include <linux/types.h>
#include <linux/elf-em.h>
#define AUDIT_GET 1000
#define AUDIT_SET 1001
#define AUDIT_LIST 1002
#define AUDIT_ADD 1003
#define AUDIT_DEL 1004
#define AUDIT_USER 1005
#define AUDIT_LOGIN 1006
#define AUDIT_WATCH_INS 1007
#define AUDIT_WATCH_REM 1008
#define AUDIT_WATCH_LIST 1009
#define AUDIT_SIGNAL_INFO 1010
#define AUDIT_ADD_RULE 1011
#define AUDIT_DEL_RULE 1012
#define AUDIT_LIST_RULES 1013
#define AUDIT_TRIM 1014
#define AUDIT_MAKE_EQUIV 1015
#define AUDIT_TTY_GET 1016
#define AUDIT_TTY_SET 1017
#define AUDIT_SET_FEATURE 1018
#define AUDIT_GET_FEATURE 1019
#define AUDIT_FIRST_USER_MSG 1100
#define AUDIT_USER_AVC 1107
#define AUDIT_USER_TTY 1124
#define AUDIT_LAST_USER_MSG 1199
#define AUDIT_FIRST_USER_MSG2 2100
#define AUDIT_LAST_USER_MSG2 2999
#define AUDIT_DAEMON_START 1200
#define AUDIT_DAEMON_END 1201
#define AUDIT_DAEMON_ABORT 1202
#define AUDIT_DAEMON_CONFIG 1203
#define AUDIT_SYSCALL 1300
#define AUDIT_PATH 1302
#define AUDIT_IPC 1303
#define AUDIT_SOCKETCALL 1304
#define AUDIT_CONFIG_CHANGE 1305
#define AUDIT_SOCKADDR 1306
#define AUDIT_CWD 1307
#define AUDIT_EXECVE 1309
#define AUDIT_IPC_SET_PERM 1311
#define AUDIT_MQ_OPEN 1312
#define AUDIT_MQ_SENDRECV 1313
#define AUDIT_MQ_NOTIFY 1314
#define AUDIT_MQ_GETSETATTR 1315
#define AUDIT_KERNEL_OTHER 1316
#define AUDIT_FD_PAIR 1317
#define AUDIT_OBJ_PID 1318
#define AUDIT_TTY 1319
#define AUDIT_EOE 1320
#define AUDIT_BPRM_FCAPS 1321
#define AUDIT_CAPSET 1322
#define AUDIT_MMAP 1323
#define AUDIT_NETFILTER_PKT 1324
#define AUDIT_NETFILTER_CFG 1325
#define AUDIT_SECCOMP 1326
#define AUDIT_PROCTITLE 1327
#define AUDIT_FEATURE_CHANGE 1328
#define AUDIT_REPLACE 1329
#define AUDIT_KERN_MODULE 1330
#define AUDIT_FANOTIFY 1331
#define AUDIT_TIME_INJOFFSET 1332
#define AUDIT_TIME_ADJNTPVAL 1333
#define AUDIT_BPF 1334
#define AUDIT_EVENT_LISTENER 1335
#define AUDIT_URINGOP 1336
#define AUDIT_OPENAT2 1337
#define AUDIT_DM_CTRL 1338
#define AUDIT_DM_EVENT 1339
#define AUDIT_AVC 1400
#define AUDIT_SELINUX_ERR 1401
#define AUDIT_AVC_PATH 1402
#define AUDIT_MAC_POLICY_LOAD 1403
#define AUDIT_MAC_STATUS 1404
#define AUDIT_MAC_CONFIG_CHANGE 1405
#define AUDIT_MAC_UNLBL_ALLOW 1406
#define AUDIT_MAC_CIPSOV4_ADD 1407
#define AUDIT_MAC_CIPSOV4_DEL 1408
#define AUDIT_MAC_MAP_ADD 1409
#define AUDIT_MAC_MAP_DEL 1410
#define AUDIT_MAC_IPSEC_ADDSA 1411
#define AUDIT_MAC_IPSEC_DELSA 1412
#define AUDIT_MAC_IPSEC_ADDSPD 1413
#define AUDIT_MAC_IPSEC_DELSPD 1414
#define AUDIT_MAC_IPSEC_EVENT 1415
#define AUDIT_MAC_UNLBL_STCADD 1416
#define AUDIT_MAC_UNLBL_STCDEL 1417
#define AUDIT_MAC_CALIPSO_ADD 1418
#define AUDIT_MAC_CALIPSO_DEL 1419
#define AUDIT_IPE_ACCESS 1420
#define AUDIT_IPE_CONFIG_CHANGE 1421
#define AUDIT_IPE_POLICY_LOAD 1422
#define AUDIT_FIRST_KERN_ANOM_MSG 1700
#define AUDIT_LAST_KERN_ANOM_MSG 1799
#define AUDIT_ANOM_PROMISCUOUS 1700
#define AUDIT_ANOM_ABEND 1701
#define AUDIT_ANOM_LINK 1702
#define AUDIT_ANOM_CREAT 1703
#define AUDIT_INTEGRITY_DATA 1800
#define AUDIT_INTEGRITY_METADATA 1801
#define AUDIT_INTEGRITY_STATUS 1802
#define AUDIT_INTEGRITY_HASH 1803
#define AUDIT_INTEGRITY_PCR 1804
#define AUDIT_INTEGRITY_RULE 1805
#define AUDIT_INTEGRITY_EVM_XATTR 1806
#define AUDIT_INTEGRITY_POLICY_RULE 1807
#define AUDIT_KERNEL 2000
#define AUDIT_FILTER_USER 0x00
#define AUDIT_FILTER_TASK 0x01
#define AUDIT_FILTER_ENTRY 0x02
#define AUDIT_FILTER_WATCH 0x03
#define AUDIT_FILTER_EXIT 0x04
#define AUDIT_FILTER_EXCLUDE 0x05
#define AUDIT_FILTER_TYPE AUDIT_FILTER_EXCLUDE
#define AUDIT_FILTER_FS 0x06
#define AUDIT_FILTER_URING_EXIT 0x07
#define AUDIT_NR_FILTERS 8
#define AUDIT_FILTER_PREPEND 0x10
#define AUDIT_NEVER 0
#define AUDIT_POSSIBLE 1
#define AUDIT_ALWAYS 2
#define AUDIT_MAX_FIELDS 64
#define AUDIT_MAX_KEY_LEN 256
#define AUDIT_BITMASK_SIZE 64
#define AUDIT_WORD(nr) ((__u32) ((nr) / 32))
#define AUDIT_BIT(nr) (1U << ((nr) - AUDIT_WORD(nr) * 32))
#define AUDIT_SYSCALL_CLASSES 16
#define AUDIT_CLASS_DIR_WRITE 0
#define AUDIT_CLASS_DIR_WRITE_32 1
#define AUDIT_CLASS_CHATTR 2
#define AUDIT_CLASS_CHATTR_32 3
#define AUDIT_CLASS_READ 4
#define AUDIT_CLASS_READ_32 5
#define AUDIT_CLASS_WRITE 6
#define AUDIT_CLASS_WRITE_32 7
#define AUDIT_CLASS_SIGNAL 8
#define AUDIT_CLASS_SIGNAL_32 9
#define AUDIT_UNUSED_BITS 0x07FFFC00
#define AUDIT_COMPARE_UID_TO_OBJ_UID 1
#define AUDIT_COMPARE_GID_TO_OBJ_GID 2
#define AUDIT_COMPARE_EUID_TO_OBJ_UID 3
#define AUDIT_COMPARE_EGID_TO_OBJ_GID 4
#define AUDIT_COMPARE_AUID_TO_OBJ_UID 5
#define AUDIT_COMPARE_SUID_TO_OBJ_UID 6
#define AUDIT_COMPARE_SGID_TO_OBJ_GID 7
#define AUDIT_COMPARE_FSUID_TO_OBJ_UID 8
#define AUDIT_COMPARE_FSGID_TO_OBJ_GID 9
#define AUDIT_COMPARE_UID_TO_AUID 10
#define AUDIT_COMPARE_UID_TO_EUID 11
#define AUDIT_COMPARE_UID_TO_FSUID 12
#define AUDIT_COMPARE_UID_TO_SUID 13
#define AUDIT_COMPARE_AUID_TO_FSUID 14
#define AUDIT_COMPARE_AUID_TO_SUID 15
#define AUDIT_COMPARE_AUID_TO_EUID 16
#define AUDIT_COMPARE_EUID_TO_SUID 17
#define AUDIT_COMPARE_EUID_TO_FSUID 18
#define AUDIT_COMPARE_SUID_TO_FSUID 19
#define AUDIT_COMPARE_GID_TO_EGID 20
#define AUDIT_COMPARE_GID_TO_FSGID 21
#define AUDIT_COMPARE_GID_TO_SGID 22
#define AUDIT_COMPARE_EGID_TO_FSGID 23
#define AUDIT_COMPARE_EGID_TO_SGID 24
#define AUDIT_COMPARE_SGID_TO_FSGID 25
#define AUDIT_MAX_FIELD_COMPARE AUDIT_COMPARE_SGID_TO_FSGID
#define AUDIT_PID 0
#define AUDIT_UID 1
#define AUDIT_EUID 2
#define AUDIT_SUID 3
#define AUDIT_FSUID 4
#define AUDIT_GID 5
#define AUDIT_EGID 6
#define AUDIT_SGID 7
#define AUDIT_FSGID 8
#define AUDIT_LOGINUID 9
#define AUDIT_PERS 10
#define AUDIT_ARCH 11
#define AUDIT_MSGTYPE 12
#define AUDIT_SUBJ_USER 13
#define AUDIT_SUBJ_ROLE 14
#define AUDIT_SUBJ_TYPE 15
#define AUDIT_SUBJ_SEN 16
#define AUDIT_SUBJ_CLR 17
#define AUDIT_PPID 18
#define AUDIT_OBJ_USER 19
#define AUDIT_OBJ_ROLE 20
#define AUDIT_OBJ_TYPE 21
#define AUDIT_OBJ_LEV_LOW 22
#define AUDIT_OBJ_LEV_HIGH 23
#define AUDIT_LOGINUID_SET 24
#define AUDIT_SESSIONID 25
#define AUDIT_FSTYPE 26
#define AUDIT_DEVMAJOR 100
#define AUDIT_DEVMINOR 101
#define AUDIT_INODE 102
#define AUDIT_EXIT 103
#define AUDIT_SUCCESS 104
#define AUDIT_WATCH 105
#define AUDIT_PERM 106
#define AUDIT_DIR 107
#define AUDIT_FILETYPE 108
#define AUDIT_OBJ_UID 109
#define AUDIT_OBJ_GID 110
#define AUDIT_FIELD_COMPARE 111
#define AUDIT_EXE 112
#define AUDIT_SADDR_FAM 113
#define AUDIT_ARG0 200
#define AUDIT_ARG1 (AUDIT_ARG0 + 1)
#define AUDIT_ARG2 (AUDIT_ARG0 + 2)
#define AUDIT_ARG3 (AUDIT_ARG0 + 3)
#define AUDIT_FILTERKEY 210
#define AUDIT_NEGATE 0x80000000
#define AUDIT_BIT_MASK 0x08000000
#define AUDIT_LESS_THAN 0x10000000
#define AUDIT_GREATER_THAN 0x20000000
#define AUDIT_NOT_EQUAL 0x30000000
#define AUDIT_EQUAL 0x40000000
#define AUDIT_BIT_TEST (AUDIT_BIT_MASK | AUDIT_EQUAL)
#define AUDIT_LESS_THAN_OR_EQUAL (AUDIT_LESS_THAN | AUDIT_EQUAL)
#define AUDIT_GREATER_THAN_OR_EQUAL (AUDIT_GREATER_THAN | AUDIT_EQUAL)
#define AUDIT_OPERATORS (AUDIT_EQUAL | AUDIT_NOT_EQUAL | AUDIT_BIT_MASK)
enum {
  Audit_equal,
  Audit_not_equal,
  Audit_bitmask,
  Audit_bittest,
  Audit_lt,
  Audit_gt,
  Audit_le,
  Audit_ge,
  Audit_bad
};
#define AUDIT_STATUS_ENABLED 0x0001
#define AUDIT_STATUS_FAILURE 0x0002
#define AUDIT_STATUS_PID 0x0004
#define AUDIT_STATUS_RATE_LIMIT 0x0008
#define AUDIT_STATUS_BACKLOG_LIMIT 0x0010
#define AUDIT_STATUS_BACKLOG_WAIT_TIME 0x0020
#define AUDIT_STATUS_LOST 0x0040
#define AUDIT_STATUS_BACKLOG_WAIT_TIME_ACTUAL 0x0080
#define AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT 0x00000001
#define AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME 0x00000002
#define AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH 0x00000004
#define AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND 0x00000008
#define AUDIT_FEATURE_BITMAP_SESSIONID_FILTER 0x00000010
#define AUDIT_FEATURE_BITMAP_LOST_RESET 0x00000020
#define AUDIT_FEATURE_BITMAP_FILTER_FS 0x00000040
#define AUDIT_FEATURE_BITMAP_ALL (AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT | AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME | AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH | AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND | AUDIT_FEATURE_BITMAP_SESSIONID_FILTER | AUDIT_FEATURE_BITMAP_LOST_RESET | AUDIT_FEATURE_BITMAP_FILTER_FS)
#define AUDIT_VERSION_LATEST AUDIT_FEATURE_BITMAP_ALL
#define AUDIT_VERSION_BACKLOG_LIMIT AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT
#define AUDIT_VERSION_BACKLOG_WAIT_TIME AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME
#define AUDIT_FAIL_SILENT 0
#define AUDIT_FAIL_PRINTK 1
#define AUDIT_FAIL_PANIC 2
#define __AUDIT_ARCH_CONVENTION_MASK 0x30000000
#define __AUDIT_ARCH_CONVENTION_MIPS64_N32 0x20000000
#define __AUDIT_ARCH_64BIT 0x80000000
#define __AUDIT_ARCH_LE 0x40000000
#define AUDIT_ARCH_AARCH64 (EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_ALPHA (EM_ALPHA | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_ARCOMPACT (EM_ARCOMPACT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_ARCOMPACTBE (EM_ARCOMPACT)
#define AUDIT_ARCH_ARCV2 (EM_ARCV2 | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_ARCV2BE (EM_ARCV2)
#define AUDIT_ARCH_ARM (EM_ARM | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_ARMEB (EM_ARM)
#define AUDIT_ARCH_C6X (EM_TI_C6000 | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_C6XBE (EM_TI_C6000)
#define AUDIT_ARCH_CRIS (EM_CRIS | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_CSKY (EM_CSKY | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_FRV (EM_FRV)
#define AUDIT_ARCH_H8300 (EM_H8_300)
#define AUDIT_ARCH_HEXAGON (EM_HEXAGON)
#define AUDIT_ARCH_I386 (EM_386 | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_IA64 (EM_IA_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_M32R (EM_M32R)
#define AUDIT_ARCH_M68K (EM_68K)
#define AUDIT_ARCH_MICROBLAZE (EM_MICROBLAZE)
#define AUDIT_ARCH_MIPS (EM_MIPS)
#define AUDIT_ARCH_MIPSEL (EM_MIPS | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_MIPS64 (EM_MIPS | __AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_MIPS64N32 (EM_MIPS | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_CONVENTION_MIPS64_N32)
#define AUDIT_ARCH_MIPSEL64 (EM_MIPS | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_MIPSEL64N32 (EM_MIPS | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE | __AUDIT_ARCH_CONVENTION_MIPS64_N32)
#define AUDIT_ARCH_NDS32 (EM_NDS32 | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_NDS32BE (EM_NDS32)
#define AUDIT_ARCH_NIOS2 (EM_ALTERA_NIOS2 | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_OPENRISC (EM_OPENRISC)
#define AUDIT_ARCH_PARISC (EM_PARISC)
#define AUDIT_ARCH_PARISC64 (EM_PARISC | __AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_PPC (EM_PPC)
#define AUDIT_ARCH_PPC64 (EM_PPC64 | __AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_PPC64LE (EM_PPC64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_RISCV32 (EM_RISCV | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_RISCV64 (EM_RISCV | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_S390 (EM_S390)
#define AUDIT_ARCH_S390X (EM_S390 | __AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_SH (EM_SH)
#define AUDIT_ARCH_SHEL (EM_SH | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_SH64 (EM_SH | __AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_SHEL64 (EM_SH | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_SPARC (EM_SPARC)
#define AUDIT_ARCH_SPARC64 (EM_SPARCV9 | __AUDIT_ARCH_64BIT)
#define AUDIT_ARCH_TILEGX (EM_TILEGX | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_TILEGX32 (EM_TILEGX | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_TILEPRO (EM_TILEPRO | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_UNICORE (EM_UNICORE | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_X86_64 (EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_XTENSA (EM_XTENSA)
#define AUDIT_ARCH_LOONGARCH32 (EM_LOONGARCH | __AUDIT_ARCH_LE)
#define AUDIT_ARCH_LOONGARCH64 (EM_LOONGARCH | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#define AUDIT_PERM_EXEC 1
#define AUDIT_PERM_WRITE 2
#define AUDIT_PERM_READ 4
#define AUDIT_PERM_ATTR 8
#define AUDIT_MESSAGE_TEXT_MAX 8560
enum audit_nlgrps {
  AUDIT_NLGRP_NONE,
  AUDIT_NLGRP_READLOG,
  __AUDIT_NLGRP_MAX
};
#define AUDIT_NLGRP_MAX (__AUDIT_NLGRP_MAX - 1)
struct audit_status {
  __u32 mask;
  __u32 enabled;
  __u32 failure;
  __u32 pid;
  __u32 rate_limit;
  __u32 backlog_limit;
  __u32 lost;
  __u32 backlog;
  union {
    __u32 version;
    __u32 feature_bitmap;
  };
  __u32 backlog_wait_time;
  __u32 backlog_wait_time_actual;
};
struct audit_features {
#define AUDIT_FEATURE_VERSION 1
  __u32 vers;
  __u32 mask;
  __u32 features;
  __u32 lock;
};
#define AUDIT_FEATURE_ONLY_UNSET_LOGINUID 0
#define AUDIT_FEATURE_LOGINUID_IMMUTABLE 1
#define AUDIT_LAST_FEATURE AUDIT_FEATURE_LOGINUID_IMMUTABLE
#define audit_feature_valid(x) ((x) >= 0 && (x) <= AUDIT_LAST_FEATURE)
#define AUDIT_FEATURE_TO_MASK(x) (1 << ((x) & 31))
struct audit_tty_status {
  __u32 enabled;
  __u32 log_passwd;
};
#define AUDIT_UID_UNSET (unsigned int) - 1
#define AUDIT_SID_UNSET ((unsigned int) - 1)
struct audit_rule_data {
  __u32 flags;
  __u32 action;
  __u32 field_count;
  __u32 mask[AUDIT_BITMASK_SIZE];
  __u32 fields[AUDIT_MAX_FIELDS];
  __u32 values[AUDIT_MAX_FIELDS];
  __u32 fieldflags[AUDIT_MAX_FIELDS];
  __u32 buflen;
  char buf[];
};
#endif

"""

```