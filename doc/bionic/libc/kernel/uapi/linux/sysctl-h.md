Response:
Let's break down the thought process for answering this complex request about the `sysctl.h` file.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of a specific header file (`sysctl.h`) within Android's Bionic library. The key aspects to cover are:

* **Functionality:** What does this file define and what is its purpose?
* **Android Relevance:** How does this relate to Android's operation?
* **libc Function Explanation (though no actual libc *functions* are in this header):** This is a slight misdirection in the request. The file defines constants and structures, not functions. We need to address this and focus on the meaning of these definitions in the context of the `sysctl` system call.
* **Dynamic Linker Connection:** How, if at all, does this relate to the dynamic linker?
* **Logic and Examples:** Provide concrete examples of usage and potential issues.
* **Android Framework/NDK Path:** How does data or control flow reach this point?
* **Frida Hooking:** Demonstrate how to inspect this in a running Android system.

**2. Initial Analysis of the Header File:**

The first step is to read and understand the contents of `sysctl.h`. Key observations:

* **Auto-generated:** The header explicitly states it's auto-generated, which hints at its connection to the kernel.
* **`#ifndef _UAPI_LINUX_SYSCTL_H`:** This is a standard include guard, preventing multiple inclusions.
* **Includes:** It includes other kernel headers (`linux/const.h`, `linux/types.h`, `linux/compiler.h`), reinforcing its kernel-level nature.
* **`struct __sysctl_args`:** This structure clearly defines the arguments for the `sysctl` system call. This is *the* core of the file.
* **`enum` definitions (CTL_*, KERN_*, VM_*, NET_*, etc.):**  These are enumerations defining constants used to identify specific kernel parameters. These are organized hierarchically.

**3. Deconstructing the Request - Addressing Each Point Systematically:**

* **功能 (Functionality):** The file defines the structure and constants necessary to interact with the Linux kernel's `sysctl` mechanism. This mechanism allows querying and setting kernel parameters at runtime.

* **与Android的功能关系 (Relation to Android Functionality):**  `sysctl` is a fundamental Linux kernel feature. Android, being built on Linux, uses it extensively. Examples: network configuration (`net.*`), memory management (`vm.*`), kernel information (`kern.*`).

* **详细解释libc函数的功能是如何实现的 (Explanation of libc Function Implementation):** This requires recognizing the "trick."  The header doesn't *implement* libc functions. Instead, it *defines the interface* for the `sysctl` *system call*. The *libc wrapper function* (likely `syscall(SYS_sysctl, ...)` or a more direct `__NR_sysctl` call) would use these definitions. We need to explain the *purpose* of each field in `__sysctl_args`.

* **涉及dynamic linker的功能 (Dynamic Linker Functionality):** This is less direct. The dynamic linker itself doesn't directly *use* `sysctl.h`. However, processes launched by the dynamic linker might use the `sysctl` mechanism. Therefore, the connection is through the *processes* the dynamic linker manages, not the linker itself. The SO layout isn't directly relevant to this header file's *definitions*. The linking process also isn't directly affected.

* **逻辑推理，假设输入与输出 (Logic and Examples):**  We can provide hypothetical scenarios. Getting the hostname: `name = {CTL_KERN, KERN_NODENAME}`, `nlen = 2`, `oldval` buffer, `oldlenp` size. Setting the hostname: Same input, plus `newval` (new hostname) and `newlen`. Potential errors: invalid `name`, insufficient buffer size.

* **用户或者编程常见的使用错误 (Common User/Programming Errors):**  Incorrect `name` array, wrong `nlen`, buffer overflows (not allocating enough space for `oldval`), and incorrect data types for setting values.

* **说明android framework or ndk是如何一步步的到达这里 (Android Framework/NDK Path):**  Start with high-level Android components. Framework services (e.g., `ConnectivityService`, `ActivityManager`) might need to query or set kernel parameters. They would use system calls. NDK developers can directly use the `syscall` function with `__NR_sysctl`. Trace the typical path: Java framework -> Native code (JNI) -> Bionic libc wrapper -> `syscall`.

* **给出frida hook示例调试这些步骤 (Frida Hooking):** Demonstrate hooking the `syscall` function, checking the `__NR_sysctl` number, and inspecting the arguments of `__sysctl_args`. This shows how to observe the interaction with the `sysctl` system call in real-time.

**4. Structuring the Answer:**

Organize the response logically, addressing each point of the request. Use clear headings and bullet points for readability. Provide code examples and explanations. Emphasize the core purpose of the file and its connection to the `sysctl` system call. Clarify the indirect relationship with the dynamic linker.

**5. Refining and Reviewing:**

Read through the generated answer to ensure accuracy, clarity, and completeness. Correct any misinterpretations or omissions. For example, initially, I might focus too much on hypothetical libc functions within the file. Reviewing would catch that and shift the focus to the system call interface. Ensure the Frida example is correct and explains the key points being observed.

This detailed thought process helps in dissecting the request, understanding the technical details, and crafting a comprehensive and accurate answer. It also addresses the potential "tricks" or misinterpretations within the prompt itself.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/sysctl.h` 这个头文件。

**功能列举:**

这个头文件主要定义了与 Linux 内核 `sysctl` 机制交互所需的常量、结构体和枚举类型。`sysctl` 是一种在运行时检查和修改内核参数的方式。具体来说，它定义了：

1. **`struct __sysctl_args`:**  这个结构体定义了调用 `sysctl` 系统调用时需要传递的参数。它包含了指向要查询或设置的内核参数名称的指针、名称长度、旧值的缓冲区和长度指针、新值缓冲区和长度等信息。

2. **`enum` 类型的常量定义:**  定义了各种用于标识内核参数的常量，这些常量被组织成层次结构，例如：
   - **`CTL_*`:**  定义了顶层控制组，如 `CTL_KERN` (内核), `CTL_VM` (虚拟机), `CTL_NET` (网络) 等。
   - **`KERN_*`:**  定义了 `CTL_KERN` 组下的具体参数，例如 `KERN_OSTYPE` (操作系统类型), `KERN_OSRELEASE` (操作系统版本), `KERN_PANIC` (内核崩溃处理方式) 等。
   - **`VM_*`:** 定义了 `CTL_VM` 组下的具体参数，例如 `VM_OVERCOMMIT_MEMORY` (内存过提交策略), `VM_SWAPPINESS` (交换分区使用倾向) 等。
   - **`NET_*`:** 定义了 `CTL_NET` 组下的具体参数，进一步按网络协议或功能划分，例如 `NET_CORE` (核心网络参数), `NET_IPV4` (IPv4 参数), `NET_TCP_*` (TCP 参数) 等。
   - **`FS_*`:** 定义了 `CTL_FS` 组下的具体参数，涉及文件系统相关的配置。
   - **`DEV_*`:** 定义了 `CTL_DEV` 组下的具体参数，涉及设备相关的配置。
   - 其他如 `BUS_*`, `ABI_*` 等。

**与 Android 功能的关系及举例说明:**

`sysctl` 是 Linux 内核的核心功能，Android 作为基于 Linux 内核的操作系统，自然也使用了 `sysctl` 机制来配置和管理系统行为。以下是一些与 Android 功能相关的例子：

* **网络配置:**  `NET_*` 组下的参数直接影响 Android 设备的网络功能。例如：
    - `NET_IPV4_FORWARD`: 控制 IP 转发是否开启，这对于路由功能至关重要。Android 设备作为热点时会启用 IP 转发。
    - `NET_IPV4_TCP_SYNCOOKIES`:  用于防御 SYN Flood 攻击，在 Android 设备上可能被启用以提高网络安全性。
    - `NET_IPV4_LOCAL_PORT_RANGE`:  定义了本地端口的范围，影响网络连接的建立。
* **内存管理:** `VM_*` 组下的参数影响 Android 的内存管理策略。例如：
    - `VM_SWAPPINESS`:  决定了系统使用交换分区的积极程度。Android 可能会调整这个值以优化内存性能。
    - `VM_OVERCOMMIT_MEMORY`:  控制内存过提交的行为，影响内存分配的策略。
* **内核信息:** `KERN_*` 组下的参数提供了关于内核的信息。例如：
    - `KERN_OSTYPE`, `KERN_OSRELEASE`, `KERN_VERSION`:  用于获取操作系统类型、版本和内核版本号。Android 系统信息界面会显示这些内容。
    - `KERN_PANIC`:  控制内核发生严重错误时的行为，例如是否自动重启。
* **文件系统:** `FS_*` 组下的参数影响文件系统的行为。例如：
    - `FS_NRINODE`, `FS_NRFILE`:  显示当前 inodes 和 file handles 的数量。
* **设备:** `DEV_*` 组下的参数影响设备的行为。例如：
    - `DEV_CDROM_AUTOCLOSE`:  控制光驱是否自动关闭。

**libc 函数功能实现解释:**

这个头文件本身 **没有定义或实现任何 libc 函数**。它只是定义了与 `sysctl` 系统调用相关的常量和数据结构。

真正执行 `sysctl` 操作的是 **系统调用**。libc 中通常会提供一个封装 `sysctl` 系统调用的函数，例如 `syscall(SYS_sysctl, ...)` 或者可能有一个更方便的包装函数（尽管在标准 C 库中 `sysctl` 通常作为一个直接的系统调用接口存在，而不是像 `fopen` 这样的封装函数）。

**`sysctl` 系统调用的大致实现原理：**

1. **用户空间调用:** 用户空间的程序通过 libc 提供的接口（通常直接使用 `syscall`）发起 `sysctl` 系统调用，并将参数填充到 `__sysctl_args` 结构体中。
2. **进入内核:** 系统调用陷入内核态。
3. **参数解析和权限检查:** 内核接收到系统调用请求后，会解析 `__sysctl_args` 中的 `name` 数组，确定要访问或修改的具体内核参数。同时会进行权限检查，确保调用者有权限执行该操作。
4. **查找和操作内核参数:**  内核根据 `name` 数组遍历内核的 `sysctl` 树状结构，找到对应的内核变量。
5. **读取或设置值:**
   - **读取:** 如果 `oldval` 不为空，内核会将当前内核参数的值复制到 `oldval` 指向的缓冲区，并通过 `oldlenp` 返回实际读取的长度。
   - **设置:** 如果 `newval` 不为空，内核会将 `newval` 指向的缓冲区中的值设置到对应的内核参数，并根据 `newlen` 确定写入的长度。
6. **返回用户空间:** 系统调用执行完毕，内核将结果返回给用户空间。

**涉及 dynamic linker 的功能:**

这个头文件 **与 dynamic linker 没有直接的功能关系**。Dynamic linker (例如 Android 中的 `linker64` 或 `linker`) 的主要职责是加载共享库 (SO 文件) 到进程的地址空间，并解析和重定位符号。

虽然 dynamic linker 本身不直接使用 `sysctl.h` 中定义的常量，但是 **被 dynamic linker 加载的应用程序或共享库可能会使用 `sysctl` 系统调用** 来查询或修改内核参数。

**SO 布局样本和链接处理过程 (不适用):**

由于 `sysctl.h` 与 dynamic linker 没有直接关系，因此这里不需要提供 SO 布局样本和链接处理过程。Dynamic linker 的链接处理过程主要涉及：

1. **读取 ELF 文件头:** 获取 SO 文件的基本信息。
2. **加载程序段 (segments):** 将 SO 文件的代码段、数据段等加载到内存中。
3. **解析动态符号表:**  查找需要的外部符号 (函数、变量)。
4. **重定位:**  修改代码和数据中的地址，使其指向正确的内存位置。
5. **执行初始化函数:** 调用 SO 文件中的 `.init` 和 `.ctors` 部分的代码。

**逻辑推理，假设输入与输出:**

假设我们想要获取内核的主机名 (nodename)。

**假设输入:**

* `name` 数组: `{CTL_KERN, KERN_NODENAME}`
* `nlen`: 2
* `oldval`: 指向一个足够大的字符缓冲区的指针 (例如 256 字节)
* `oldlenp`: 指向一个 `size_t` 变量的指针，其初始值设置为缓冲区的大小 (256)
* `newval`: `NULL`
* `newlen`: 0

**预期输出:**

* `sysctl` 系统调用成功返回 (通常返回 0)。
* `oldval` 指向的缓冲区中包含当前系统的主机名，例如 "my-android-device"。
* `oldlenp` 指向的 `size_t` 变量的值被更新为实际主机名的长度 (不包括 null 终止符)。

**用户或编程常见的使用错误:**

1. **`name` 数组错误:**  传递了不存在或无效的 `name` 数组，例如拼写错误或层次结构错误。
   ```c
   int name[] = {CTL_KERN, KERN_NONEXISTENT_PARAM}; // 错误的参数名
   size_t oldlen = 256;
   char oldval[256];
   if (syscall(SYS_sysctl, name, 2, oldval, &oldlen, NULL, 0) == -1) {
       perror("sysctl"); // 可能会输出 "No such file or directory" 或其他错误
   }
   ```

2. **缓冲区溢出:**  提供的 `oldval` 缓冲区太小，无法容纳内核返回的值。
   ```c
   int name[] = {CTL_KERN, KERN_VERSION};
   size_t oldlen = 10; // 缓冲区太小
   char oldval[10];
   if (syscall(SYS_sysctl, name, 2, oldval, &oldlen, NULL, 0) == -1) {
       perror("sysctl");
   } else {
       // oldval 中的数据可能被截断，或者发生缓冲区溢出
   }
   ```

3. **权限不足:**  尝试修改需要 root 权限才能修改的内核参数。
   ```c
   int name[] = {CTL_NET, NET_IPV4, NET_IPV4_FORWARD};
   int new_value = 1;
   if (syscall(SYS_sysctl, name, 3, NULL, 0, &new_value, sizeof(new_value)) == -1) {
       perror("sysctl"); // 可能会输出 "Operation not permitted"
   }
   ```

4. **错误的 `nlen` 值:** `nlen` 值与 `name` 数组的实际长度不匹配。

5. **尝试设置只读参数:**  某些内核参数是只读的，尝试设置会失败。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤:**

通常情况下，Android Framework 的高级 API 不会直接调用 `sysctl`。但是，在一些底层服务或 Native 代码中可能会使用。

**Android Framework 路径示例:**

1. **Java Framework (例如 `ConnectivityService`):**  某些 Framework 服务可能需要获取或设置网络相关的内核参数。
2. **JNI 调用:** Framework 服务可能会调用 Native 代码 (C/C++) 通过 JNI (Java Native Interface) 来实现。
3. **Native 代码:** Native 代码中会使用 libc 提供的系统调用接口 (通常是 `syscall`) 来调用 `sysctl`。

**NDK 路径示例:**

1. **NDK 应用代码:** 使用 NDK 开发的应用程序可以直接调用 libc 的系统调用接口。
2. **`syscall(SYS_sysctl, ...)`:**  NDK 代码可以直接调用 `syscall` 函数，传入 `SYS_sysctl` 常量和相应的参数。

**Frida Hook 示例:**

我们可以使用 Frida hook `syscall` 函数，并检查第一个参数是否是 `SYS_sysctl` 的值来捕获 `sysctl` 调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['content']))
    else:
        print(message)

def hook_sysctl():
    session = frida.attach("目标进程名称或PID")

    script_code = """
    'use strict';

    const SYSCALL_NUMBER_SYSCTL = 160; // 不同架构的 sysctl 系统调用号可能不同，需要根据实际情况调整

    Interceptor.attach(Module.findExportByName(null, "syscall"), {
        onEnter: function(args) {
            const syscall_num = args[0].toInt32();
            if (syscall_num === SYSCALL_NUMBER_SYSCTL) {
                const name_ptr = ptr(args[1]);
                const nlen = args[2].toInt32();
                const oldval_ptr = ptr(args[3]);
                const oldlenp_ptr = ptr(args[4]);
                const newval_ptr = ptr(args[5]);
                const newlen = args[6].toInt32();

                let name_str = "";
                for (let i = 0; i < nlen; i++) {
                    name_str += Memory.readS32(name_ptr.add(i * 4)) + ", ";
                }
                name_str = name_str.slice(0, -2); // 去掉最后的逗号和空格

                let oldlen = 0;
                if (oldlenp_ptr.isNull() === false) {
                    oldlen = Memory.readUSize(oldlenp_ptr);
                }

                let new_value_str = "";
                if (newval_ptr.isNull() === false) {
                    if (newlen > 0 && newlen < 1024) { // 避免读取过大的数据
                        new_value_str = hexdump(Memory.readByteArray(newval_ptr, newlen), { ansi: true });
                    } else {
                        new_value_str = "[size: " + newlen + "]";
                    }
                }

                send({
                    tag: "sysctl",
                    content: "syscall(SYS_sysctl, name=[" + name_str + "], nlen=" + nlen +
                             ", oldval=" + oldval_ptr + ", oldlen=" + oldlen +
                             ", newval=" + newval_ptr + ", newlen=" + newlen +
                             ", new_value=" + new_value_str + ")"
                });
            }
        },
        onLeave: function(retval) {
            if (this.syscall_num === SYSCALL_NUMBER_SYSCTL) {
                send({ tag: "sysctl", content: "=> Returned: " + retval });
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
```

**使用步骤:**

1. 将上面的 Python 代码保存为 `hook_sysctl.py`。
2. 将 `SYSCALL_NUMBER_SYSCTL` 的值替换为目标 Android 进程架构下 `sysctl` 系统调用的编号。你可以在 `<asm/unistd.h>` 或 `<sys/syscall.h>` 中找到。不同 Android 版本和架构可能不同。
3. 将 `"目标进程名称或PID"` 替换为你要 hook 的 Android 进程的名称或 PID。
4. 运行 Frida： `frida -UF -f 目标进程的包名 --no-pause -l hook_sysctl.py`  或者 `frida -p 目标进程PID -l hook_sysctl.py`。
5. 在 Android 设备上执行相关操作，触发 `sysctl` 调用。
6. Frida 控制台会输出捕获到的 `sysctl` 调用信息，包括参数值。

这个 Frida 脚本会 hook `syscall` 函数，并在进入时检查是否是 `sysctl` 调用，如果是，则读取并打印出 `__sysctl_args` 结构体中的参数信息，帮助你调试 Android Framework 或 NDK 如何使用 `sysctl`。

希望这个详细的解答能够帮助你理解 `bionic/libc/kernel/uapi/linux/sysctl.h` 文件及其在 Android 中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/sysctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_SYSCTL_H
#define _UAPI_LINUX_SYSCTL_H
#include <linux/const.h>
#include <linux/types.h>
#include <linux/compiler.h>
#define CTL_MAXNAME 10
struct __sysctl_args {
  int  * name;
  int nlen;
  void  * oldval;
  size_t  * oldlenp;
  void  * newval;
  size_t newlen;
  unsigned long __linux_unused[4];
};
enum {
  CTL_KERN = 1,
  CTL_VM = 2,
  CTL_NET = 3,
  CTL_PROC = 4,
  CTL_FS = 5,
  CTL_DEBUG = 6,
  CTL_DEV = 7,
  CTL_BUS = 8,
  CTL_ABI = 9,
  CTL_CPU = 10,
  CTL_ARLAN = 254,
  CTL_S390DBF = 5677,
  CTL_SUNRPC = 7249,
  CTL_PM = 9899,
  CTL_FRV = 9898,
};
enum {
  CTL_BUS_ISA = 1
};
enum {
  INOTIFY_MAX_USER_INSTANCES = 1,
  INOTIFY_MAX_USER_WATCHES = 2,
  INOTIFY_MAX_QUEUED_EVENTS = 3
};
enum {
  KERN_OSTYPE = 1,
  KERN_OSRELEASE = 2,
  KERN_OSREV = 3,
  KERN_VERSION = 4,
  KERN_SECUREMASK = 5,
  KERN_PROF = 6,
  KERN_NODENAME = 7,
  KERN_DOMAINNAME = 8,
  KERN_PANIC = 15,
  KERN_REALROOTDEV = 16,
  KERN_SPARC_REBOOT = 21,
  KERN_CTLALTDEL = 22,
  KERN_PRINTK = 23,
  KERN_NAMETRANS = 24,
  KERN_PPC_HTABRECLAIM = 25,
  KERN_PPC_ZEROPAGED = 26,
  KERN_PPC_POWERSAVE_NAP = 27,
  KERN_MODPROBE = 28,
  KERN_SG_BIG_BUFF = 29,
  KERN_ACCT = 30,
  KERN_PPC_L2CR = 31,
  KERN_RTSIGNR = 32,
  KERN_RTSIGMAX = 33,
  KERN_SHMMAX = 34,
  KERN_MSGMAX = 35,
  KERN_MSGMNB = 36,
  KERN_MSGPOOL = 37,
  KERN_SYSRQ = 38,
  KERN_MAX_THREADS = 39,
  KERN_RANDOM = 40,
  KERN_SHMALL = 41,
  KERN_MSGMNI = 42,
  KERN_SEM = 43,
  KERN_SPARC_STOP_A = 44,
  KERN_SHMMNI = 45,
  KERN_OVERFLOWUID = 46,
  KERN_OVERFLOWGID = 47,
  KERN_SHMPATH = 48,
  KERN_HOTPLUG = 49,
  KERN_IEEE_EMULATION_WARNINGS = 50,
  KERN_S390_USER_DEBUG_LOGGING = 51,
  KERN_CORE_USES_PID = 52,
  KERN_TAINTED = 53,
  KERN_CADPID = 54,
  KERN_PIDMAX = 55,
  KERN_CORE_PATTERN = 56,
  KERN_PANIC_ON_OOPS = 57,
  KERN_HPPA_PWRSW = 58,
  KERN_HPPA_UNALIGNED = 59,
  KERN_PRINTK_RATELIMIT = 60,
  KERN_PRINTK_RATELIMIT_BURST = 61,
  KERN_PTY = 62,
  KERN_NGROUPS_MAX = 63,
  KERN_SPARC_SCONS_PWROFF = 64,
  KERN_HZ_TIMER = 65,
  KERN_UNKNOWN_NMI_PANIC = 66,
  KERN_BOOTLOADER_TYPE = 67,
  KERN_RANDOMIZE = 68,
  KERN_SETUID_DUMPABLE = 69,
  KERN_SPIN_RETRY = 70,
  KERN_ACPI_VIDEO_FLAGS = 71,
  KERN_IA64_UNALIGNED = 72,
  KERN_COMPAT_LOG = 73,
  KERN_MAX_LOCK_DEPTH = 74,
  KERN_NMI_WATCHDOG = 75,
  KERN_PANIC_ON_NMI = 76,
  KERN_PANIC_ON_WARN = 77,
  KERN_PANIC_PRINT = 78,
};
enum {
  VM_UNUSED1 = 1,
  VM_UNUSED2 = 2,
  VM_UNUSED3 = 3,
  VM_UNUSED4 = 4,
  VM_OVERCOMMIT_MEMORY = 5,
  VM_UNUSED5 = 6,
  VM_UNUSED7 = 7,
  VM_UNUSED8 = 8,
  VM_UNUSED9 = 9,
  VM_PAGE_CLUSTER = 10,
  VM_DIRTY_BACKGROUND = 11,
  VM_DIRTY_RATIO = 12,
  VM_DIRTY_WB_CS = 13,
  VM_DIRTY_EXPIRE_CS = 14,
  VM_NR_PDFLUSH_THREADS = 15,
  VM_OVERCOMMIT_RATIO = 16,
  VM_PAGEBUF = 17,
  VM_HUGETLB_PAGES = 18,
  VM_SWAPPINESS = 19,
  VM_LOWMEM_RESERVE_RATIO = 20,
  VM_MIN_FREE_KBYTES = 21,
  VM_MAX_MAP_COUNT = 22,
  VM_LAPTOP_MODE = 23,
  VM_BLOCK_DUMP = 24,
  VM_HUGETLB_GROUP = 25,
  VM_VFS_CACHE_PRESSURE = 26,
  VM_LEGACY_VA_LAYOUT = 27,
  VM_SWAP_TOKEN_TIMEOUT = 28,
  VM_DROP_PAGECACHE = 29,
  VM_PERCPU_PAGELIST_FRACTION = 30,
  VM_ZONE_RECLAIM_MODE = 31,
  VM_MIN_UNMAPPED = 32,
  VM_PANIC_ON_OOM = 33,
  VM_VDSO_ENABLED = 34,
  VM_MIN_SLAB = 35,
};
enum {
  NET_CORE = 1,
  NET_ETHER = 2,
  NET_802 = 3,
  NET_UNIX = 4,
  NET_IPV4 = 5,
  NET_IPX = 6,
  NET_ATALK = 7,
  NET_NETROM = 8,
  NET_AX25 = 9,
  NET_BRIDGE = 10,
  NET_ROSE = 11,
  NET_IPV6 = 12,
  NET_X25 = 13,
  NET_TR = 14,
  NET_DECNET = 15,
  NET_ECONET = 16,
  NET_SCTP = 17,
  NET_LLC = 18,
  NET_NETFILTER = 19,
  NET_DCCP = 20,
  NET_IRDA = 412,
};
enum {
  RANDOM_POOLSIZE = 1,
  RANDOM_ENTROPY_COUNT = 2,
  RANDOM_READ_THRESH = 3,
  RANDOM_WRITE_THRESH = 4,
  RANDOM_BOOT_ID = 5,
  RANDOM_UUID = 6
};
enum {
  PTY_MAX = 1,
  PTY_NR = 2
};
enum {
  BUS_ISA_MEM_BASE = 1,
  BUS_ISA_PORT_BASE = 2,
  BUS_ISA_PORT_SHIFT = 3
};
enum {
  NET_CORE_WMEM_MAX = 1,
  NET_CORE_RMEM_MAX = 2,
  NET_CORE_WMEM_DEFAULT = 3,
  NET_CORE_RMEM_DEFAULT = 4,
  NET_CORE_MAX_BACKLOG = 6,
  NET_CORE_FASTROUTE = 7,
  NET_CORE_MSG_COST = 8,
  NET_CORE_MSG_BURST = 9,
  NET_CORE_OPTMEM_MAX = 10,
  NET_CORE_HOT_LIST_LENGTH = 11,
  NET_CORE_DIVERT_VERSION = 12,
  NET_CORE_NO_CONG_THRESH = 13,
  NET_CORE_NO_CONG = 14,
  NET_CORE_LO_CONG = 15,
  NET_CORE_MOD_CONG = 16,
  NET_CORE_DEV_WEIGHT = 17,
  NET_CORE_SOMAXCONN = 18,
  NET_CORE_BUDGET = 19,
  NET_CORE_AEVENT_ETIME = 20,
  NET_CORE_AEVENT_RSEQTH = 21,
  NET_CORE_WARNINGS = 22,
};
enum {
  NET_UNIX_DESTROY_DELAY = 1,
  NET_UNIX_DELETE_DELAY = 2,
  NET_UNIX_MAX_DGRAM_QLEN = 3,
};
enum {
  NET_NF_CONNTRACK_MAX = 1,
  NET_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT = 2,
  NET_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV = 3,
  NET_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED = 4,
  NET_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT = 5,
  NET_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT = 6,
  NET_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK = 7,
  NET_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT = 8,
  NET_NF_CONNTRACK_TCP_TIMEOUT_CLOSE = 9,
  NET_NF_CONNTRACK_UDP_TIMEOUT = 10,
  NET_NF_CONNTRACK_UDP_TIMEOUT_STREAM = 11,
  NET_NF_CONNTRACK_ICMP_TIMEOUT = 12,
  NET_NF_CONNTRACK_GENERIC_TIMEOUT = 13,
  NET_NF_CONNTRACK_BUCKETS = 14,
  NET_NF_CONNTRACK_LOG_INVALID = 15,
  NET_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS = 16,
  NET_NF_CONNTRACK_TCP_LOOSE = 17,
  NET_NF_CONNTRACK_TCP_BE_LIBERAL = 18,
  NET_NF_CONNTRACK_TCP_MAX_RETRANS = 19,
  NET_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED = 20,
  NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT = 21,
  NET_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED = 22,
  NET_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED = 23,
  NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT = 24,
  NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD = 25,
  NET_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT = 26,
  NET_NF_CONNTRACK_COUNT = 27,
  NET_NF_CONNTRACK_ICMPV6_TIMEOUT = 28,
  NET_NF_CONNTRACK_FRAG6_TIMEOUT = 29,
  NET_NF_CONNTRACK_FRAG6_LOW_THRESH = 30,
  NET_NF_CONNTRACK_FRAG6_HIGH_THRESH = 31,
  NET_NF_CONNTRACK_CHECKSUM = 32,
};
enum {
  NET_IPV4_FORWARD = 8,
  NET_IPV4_DYNADDR = 9,
  NET_IPV4_CONF = 16,
  NET_IPV4_NEIGH = 17,
  NET_IPV4_ROUTE = 18,
  NET_IPV4_FIB_HASH = 19,
  NET_IPV4_NETFILTER = 20,
  NET_IPV4_TCP_TIMESTAMPS = 33,
  NET_IPV4_TCP_WINDOW_SCALING = 34,
  NET_IPV4_TCP_SACK = 35,
  NET_IPV4_TCP_RETRANS_COLLAPSE = 36,
  NET_IPV4_DEFAULT_TTL = 37,
  NET_IPV4_AUTOCONFIG = 38,
  NET_IPV4_NO_PMTU_DISC = 39,
  NET_IPV4_TCP_SYN_RETRIES = 40,
  NET_IPV4_IPFRAG_HIGH_THRESH = 41,
  NET_IPV4_IPFRAG_LOW_THRESH = 42,
  NET_IPV4_IPFRAG_TIME = 43,
  NET_IPV4_TCP_MAX_KA_PROBES = 44,
  NET_IPV4_TCP_KEEPALIVE_TIME = 45,
  NET_IPV4_TCP_KEEPALIVE_PROBES = 46,
  NET_IPV4_TCP_RETRIES1 = 47,
  NET_IPV4_TCP_RETRIES2 = 48,
  NET_IPV4_TCP_FIN_TIMEOUT = 49,
  NET_IPV4_IP_MASQ_DEBUG = 50,
  NET_TCP_SYNCOOKIES = 51,
  NET_TCP_STDURG = 52,
  NET_TCP_RFC1337 = 53,
  NET_TCP_SYN_TAILDROP = 54,
  NET_TCP_MAX_SYN_BACKLOG = 55,
  NET_IPV4_LOCAL_PORT_RANGE = 56,
  NET_IPV4_ICMP_ECHO_IGNORE_ALL = 57,
  NET_IPV4_ICMP_ECHO_IGNORE_BROADCASTS = 58,
  NET_IPV4_ICMP_SOURCEQUENCH_RATE = 59,
  NET_IPV4_ICMP_DESTUNREACH_RATE = 60,
  NET_IPV4_ICMP_TIMEEXCEED_RATE = 61,
  NET_IPV4_ICMP_PARAMPROB_RATE = 62,
  NET_IPV4_ICMP_ECHOREPLY_RATE = 63,
  NET_IPV4_ICMP_IGNORE_BOGUS_ERROR_RESPONSES = 64,
  NET_IPV4_IGMP_MAX_MEMBERSHIPS = 65,
  NET_TCP_TW_RECYCLE = 66,
  NET_IPV4_ALWAYS_DEFRAG = 67,
  NET_IPV4_TCP_KEEPALIVE_INTVL = 68,
  NET_IPV4_INET_PEER_THRESHOLD = 69,
  NET_IPV4_INET_PEER_MINTTL = 70,
  NET_IPV4_INET_PEER_MAXTTL = 71,
  NET_IPV4_INET_PEER_GC_MINTIME = 72,
  NET_IPV4_INET_PEER_GC_MAXTIME = 73,
  NET_TCP_ORPHAN_RETRIES = 74,
  NET_TCP_ABORT_ON_OVERFLOW = 75,
  NET_TCP_SYNACK_RETRIES = 76,
  NET_TCP_MAX_ORPHANS = 77,
  NET_TCP_MAX_TW_BUCKETS = 78,
  NET_TCP_FACK = 79,
  NET_TCP_REORDERING = 80,
  NET_TCP_ECN = 81,
  NET_TCP_DSACK = 82,
  NET_TCP_MEM = 83,
  NET_TCP_WMEM = 84,
  NET_TCP_RMEM = 85,
  NET_TCP_APP_WIN = 86,
  NET_TCP_ADV_WIN_SCALE = 87,
  NET_IPV4_NONLOCAL_BIND = 88,
  NET_IPV4_ICMP_RATELIMIT = 89,
  NET_IPV4_ICMP_RATEMASK = 90,
  NET_TCP_TW_REUSE = 91,
  NET_TCP_FRTO = 92,
  NET_TCP_LOW_LATENCY = 93,
  NET_IPV4_IPFRAG_SECRET_INTERVAL = 94,
  NET_IPV4_IGMP_MAX_MSF = 96,
  NET_TCP_NO_METRICS_SAVE = 97,
  NET_TCP_DEFAULT_WIN_SCALE = 105,
  NET_TCP_MODERATE_RCVBUF = 106,
  NET_TCP_TSO_WIN_DIVISOR = 107,
  NET_TCP_BIC_BETA = 108,
  NET_IPV4_ICMP_ERRORS_USE_INBOUND_IFADDR = 109,
  NET_TCP_CONG_CONTROL = 110,
  NET_TCP_ABC = 111,
  NET_IPV4_IPFRAG_MAX_DIST = 112,
  NET_TCP_MTU_PROBING = 113,
  NET_TCP_BASE_MSS = 114,
  NET_IPV4_TCP_WORKAROUND_SIGNED_WINDOWS = 115,
  NET_TCP_DMA_COPYBREAK = 116,
  NET_TCP_SLOW_START_AFTER_IDLE = 117,
  NET_CIPSOV4_CACHE_ENABLE = 118,
  NET_CIPSOV4_CACHE_BUCKET_SIZE = 119,
  NET_CIPSOV4_RBM_OPTFMT = 120,
  NET_CIPSOV4_RBM_STRICTVALID = 121,
  NET_TCP_AVAIL_CONG_CONTROL = 122,
  NET_TCP_ALLOWED_CONG_CONTROL = 123,
  NET_TCP_MAX_SSTHRESH = 124,
  NET_TCP_FRTO_RESPONSE = 125,
};
enum {
  NET_IPV4_ROUTE_FLUSH = 1,
  NET_IPV4_ROUTE_MIN_DELAY = 2,
  NET_IPV4_ROUTE_MAX_DELAY = 3,
  NET_IPV4_ROUTE_GC_THRESH = 4,
  NET_IPV4_ROUTE_MAX_SIZE = 5,
  NET_IPV4_ROUTE_GC_MIN_INTERVAL = 6,
  NET_IPV4_ROUTE_GC_TIMEOUT = 7,
  NET_IPV4_ROUTE_GC_INTERVAL = 8,
  NET_IPV4_ROUTE_REDIRECT_LOAD = 9,
  NET_IPV4_ROUTE_REDIRECT_NUMBER = 10,
  NET_IPV4_ROUTE_REDIRECT_SILENCE = 11,
  NET_IPV4_ROUTE_ERROR_COST = 12,
  NET_IPV4_ROUTE_ERROR_BURST = 13,
  NET_IPV4_ROUTE_GC_ELASTICITY = 14,
  NET_IPV4_ROUTE_MTU_EXPIRES = 15,
  NET_IPV4_ROUTE_MIN_PMTU = 16,
  NET_IPV4_ROUTE_MIN_ADVMSS = 17,
  NET_IPV4_ROUTE_SECRET_INTERVAL = 18,
  NET_IPV4_ROUTE_GC_MIN_INTERVAL_MS = 19,
};
enum {
  NET_PROTO_CONF_ALL = - 2,
  NET_PROTO_CONF_DEFAULT = - 3
};
enum {
  NET_IPV4_CONF_FORWARDING = 1,
  NET_IPV4_CONF_MC_FORWARDING = 2,
  NET_IPV4_CONF_PROXY_ARP = 3,
  NET_IPV4_CONF_ACCEPT_REDIRECTS = 4,
  NET_IPV4_CONF_SECURE_REDIRECTS = 5,
  NET_IPV4_CONF_SEND_REDIRECTS = 6,
  NET_IPV4_CONF_SHARED_MEDIA = 7,
  NET_IPV4_CONF_RP_FILTER = 8,
  NET_IPV4_CONF_ACCEPT_SOURCE_ROUTE = 9,
  NET_IPV4_CONF_BOOTP_RELAY = 10,
  NET_IPV4_CONF_LOG_MARTIANS = 11,
  NET_IPV4_CONF_TAG = 12,
  NET_IPV4_CONF_ARPFILTER = 13,
  NET_IPV4_CONF_MEDIUM_ID = 14,
  NET_IPV4_CONF_NOXFRM = 15,
  NET_IPV4_CONF_NOPOLICY = 16,
  NET_IPV4_CONF_FORCE_IGMP_VERSION = 17,
  NET_IPV4_CONF_ARP_ANNOUNCE = 18,
  NET_IPV4_CONF_ARP_IGNORE = 19,
  NET_IPV4_CONF_PROMOTE_SECONDARIES = 20,
  NET_IPV4_CONF_ARP_ACCEPT = 21,
  NET_IPV4_CONF_ARP_NOTIFY = 22,
  NET_IPV4_CONF_ARP_EVICT_NOCARRIER = 23,
};
enum {
  NET_IPV4_NF_CONNTRACK_MAX = 1,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_SENT = 2,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_SYN_RECV = 3,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_ESTABLISHED = 4,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_FIN_WAIT = 5,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE_WAIT = 6,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_LAST_ACK = 7,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_TIME_WAIT = 8,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_CLOSE = 9,
  NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT = 10,
  NET_IPV4_NF_CONNTRACK_UDP_TIMEOUT_STREAM = 11,
  NET_IPV4_NF_CONNTRACK_ICMP_TIMEOUT = 12,
  NET_IPV4_NF_CONNTRACK_GENERIC_TIMEOUT = 13,
  NET_IPV4_NF_CONNTRACK_BUCKETS = 14,
  NET_IPV4_NF_CONNTRACK_LOG_INVALID = 15,
  NET_IPV4_NF_CONNTRACK_TCP_TIMEOUT_MAX_RETRANS = 16,
  NET_IPV4_NF_CONNTRACK_TCP_LOOSE = 17,
  NET_IPV4_NF_CONNTRACK_TCP_BE_LIBERAL = 18,
  NET_IPV4_NF_CONNTRACK_TCP_MAX_RETRANS = 19,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_CLOSED = 20,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_WAIT = 21,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_COOKIE_ECHOED = 22,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_ESTABLISHED = 23,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_SENT = 24,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_RECD = 25,
  NET_IPV4_NF_CONNTRACK_SCTP_TIMEOUT_SHUTDOWN_ACK_SENT = 26,
  NET_IPV4_NF_CONNTRACK_COUNT = 27,
  NET_IPV4_NF_CONNTRACK_CHECKSUM = 28,
};
enum {
  NET_IPV6_CONF = 16,
  NET_IPV6_NEIGH = 17,
  NET_IPV6_ROUTE = 18,
  NET_IPV6_ICMP = 19,
  NET_IPV6_BINDV6ONLY = 20,
  NET_IPV6_IP6FRAG_HIGH_THRESH = 21,
  NET_IPV6_IP6FRAG_LOW_THRESH = 22,
  NET_IPV6_IP6FRAG_TIME = 23,
  NET_IPV6_IP6FRAG_SECRET_INTERVAL = 24,
  NET_IPV6_MLD_MAX_MSF = 25,
};
enum {
  NET_IPV6_ROUTE_FLUSH = 1,
  NET_IPV6_ROUTE_GC_THRESH = 2,
  NET_IPV6_ROUTE_MAX_SIZE = 3,
  NET_IPV6_ROUTE_GC_MIN_INTERVAL = 4,
  NET_IPV6_ROUTE_GC_TIMEOUT = 5,
  NET_IPV6_ROUTE_GC_INTERVAL = 6,
  NET_IPV6_ROUTE_GC_ELASTICITY = 7,
  NET_IPV6_ROUTE_MTU_EXPIRES = 8,
  NET_IPV6_ROUTE_MIN_ADVMSS = 9,
  NET_IPV6_ROUTE_GC_MIN_INTERVAL_MS = 10
};
enum {
  NET_IPV6_FORWARDING = 1,
  NET_IPV6_HOP_LIMIT = 2,
  NET_IPV6_MTU = 3,
  NET_IPV6_ACCEPT_RA = 4,
  NET_IPV6_ACCEPT_REDIRECTS = 5,
  NET_IPV6_AUTOCONF = 6,
  NET_IPV6_DAD_TRANSMITS = 7,
  NET_IPV6_RTR_SOLICITS = 8,
  NET_IPV6_RTR_SOLICIT_INTERVAL = 9,
  NET_IPV6_RTR_SOLICIT_DELAY = 10,
  NET_IPV6_USE_TEMPADDR = 11,
  NET_IPV6_TEMP_VALID_LFT = 12,
  NET_IPV6_TEMP_PREFERED_LFT = 13,
  NET_IPV6_REGEN_MAX_RETRY = 14,
  NET_IPV6_MAX_DESYNC_FACTOR = 15,
  NET_IPV6_MAX_ADDRESSES = 16,
  NET_IPV6_FORCE_MLD_VERSION = 17,
  NET_IPV6_ACCEPT_RA_DEFRTR = 18,
  NET_IPV6_ACCEPT_RA_PINFO = 19,
  NET_IPV6_ACCEPT_RA_RTR_PREF = 20,
  NET_IPV6_RTR_PROBE_INTERVAL = 21,
  NET_IPV6_ACCEPT_RA_RT_INFO_MAX_PLEN = 22,
  NET_IPV6_PROXY_NDP = 23,
  NET_IPV6_ACCEPT_SOURCE_ROUTE = 25,
  NET_IPV6_ACCEPT_RA_FROM_LOCAL = 26,
  NET_IPV6_ACCEPT_RA_RT_INFO_MIN_PLEN = 27,
  NET_IPV6_RA_DEFRTR_METRIC = 28,
  __NET_IPV6_MAX
};
enum {
  NET_IPV6_ICMP_RATELIMIT = 1,
  NET_IPV6_ICMP_ECHO_IGNORE_ALL = 2
};
enum {
  NET_NEIGH_MCAST_SOLICIT = 1,
  NET_NEIGH_UCAST_SOLICIT = 2,
  NET_NEIGH_APP_SOLICIT = 3,
  NET_NEIGH_RETRANS_TIME = 4,
  NET_NEIGH_REACHABLE_TIME = 5,
  NET_NEIGH_DELAY_PROBE_TIME = 6,
  NET_NEIGH_GC_STALE_TIME = 7,
  NET_NEIGH_UNRES_QLEN = 8,
  NET_NEIGH_PROXY_QLEN = 9,
  NET_NEIGH_ANYCAST_DELAY = 10,
  NET_NEIGH_PROXY_DELAY = 11,
  NET_NEIGH_LOCKTIME = 12,
  NET_NEIGH_GC_INTERVAL = 13,
  NET_NEIGH_GC_THRESH1 = 14,
  NET_NEIGH_GC_THRESH2 = 15,
  NET_NEIGH_GC_THRESH3 = 16,
  NET_NEIGH_RETRANS_TIME_MS = 17,
  NET_NEIGH_REACHABLE_TIME_MS = 18,
  NET_NEIGH_INTERVAL_PROBE_TIME_MS = 19,
};
enum {
  NET_DCCP_DEFAULT = 1,
};
enum {
  NET_IPX_PPROP_BROADCASTING = 1,
  NET_IPX_FORWARDING = 2
};
enum {
  NET_LLC2 = 1,
  NET_LLC_STATION = 2,
};
enum {
  NET_LLC2_TIMEOUT = 1,
};
enum {
  NET_LLC_STATION_ACK_TIMEOUT = 1,
};
enum {
  NET_LLC2_ACK_TIMEOUT = 1,
  NET_LLC2_P_TIMEOUT = 2,
  NET_LLC2_REJ_TIMEOUT = 3,
  NET_LLC2_BUSY_TIMEOUT = 4,
};
enum {
  NET_ATALK_AARP_EXPIRY_TIME = 1,
  NET_ATALK_AARP_TICK_TIME = 2,
  NET_ATALK_AARP_RETRANSMIT_LIMIT = 3,
  NET_ATALK_AARP_RESOLVE_TIME = 4
};
enum {
  NET_NETROM_DEFAULT_PATH_QUALITY = 1,
  NET_NETROM_OBSOLESCENCE_COUNT_INITIALISER = 2,
  NET_NETROM_NETWORK_TTL_INITIALISER = 3,
  NET_NETROM_TRANSPORT_TIMEOUT = 4,
  NET_NETROM_TRANSPORT_MAXIMUM_TRIES = 5,
  NET_NETROM_TRANSPORT_ACKNOWLEDGE_DELAY = 6,
  NET_NETROM_TRANSPORT_BUSY_DELAY = 7,
  NET_NETROM_TRANSPORT_REQUESTED_WINDOW_SIZE = 8,
  NET_NETROM_TRANSPORT_NO_ACTIVITY_TIMEOUT = 9,
  NET_NETROM_ROUTING_CONTROL = 10,
  NET_NETROM_LINK_FAILS_COUNT = 11,
  NET_NETROM_RESET = 12
};
enum {
  NET_AX25_IP_DEFAULT_MODE = 1,
  NET_AX25_DEFAULT_MODE = 2,
  NET_AX25_BACKOFF_TYPE = 3,
  NET_AX25_CONNECT_MODE = 4,
  NET_AX25_STANDARD_WINDOW = 5,
  NET_AX25_EXTENDED_WINDOW = 6,
  NET_AX25_T1_TIMEOUT = 7,
  NET_AX25_T2_TIMEOUT = 8,
  NET_AX25_T3_TIMEOUT = 9,
  NET_AX25_IDLE_TIMEOUT = 10,
  NET_AX25_N2 = 11,
  NET_AX25_PACLEN = 12,
  NET_AX25_PROTOCOL = 13,
  NET_AX25_DAMA_SLAVE_TIMEOUT = 14
};
enum {
  NET_ROSE_RESTART_REQUEST_TIMEOUT = 1,
  NET_ROSE_CALL_REQUEST_TIMEOUT = 2,
  NET_ROSE_RESET_REQUEST_TIMEOUT = 3,
  NET_ROSE_CLEAR_REQUEST_TIMEOUT = 4,
  NET_ROSE_ACK_HOLD_BACK_TIMEOUT = 5,
  NET_ROSE_ROUTING_CONTROL = 6,
  NET_ROSE_LINK_FAIL_TIMEOUT = 7,
  NET_ROSE_MAX_VCS = 8,
  NET_ROSE_WINDOW_SIZE = 9,
  NET_ROSE_NO_ACTIVITY_TIMEOUT = 10
};
enum {
  NET_X25_RESTART_REQUEST_TIMEOUT = 1,
  NET_X25_CALL_REQUEST_TIMEOUT = 2,
  NET_X25_RESET_REQUEST_TIMEOUT = 3,
  NET_X25_CLEAR_REQUEST_TIMEOUT = 4,
  NET_X25_ACK_HOLD_BACK_TIMEOUT = 5,
  NET_X25_FORWARD = 6
};
enum {
  NET_TR_RIF_TIMEOUT = 1
};
enum {
  NET_DECNET_NODE_TYPE = 1,
  NET_DECNET_NODE_ADDRESS = 2,
  NET_DECNET_NODE_NAME = 3,
  NET_DECNET_DEFAULT_DEVICE = 4,
  NET_DECNET_TIME_WAIT = 5,
  NET_DECNET_DN_COUNT = 6,
  NET_DECNET_DI_COUNT = 7,
  NET_DECNET_DR_COUNT = 8,
  NET_DECNET_DST_GC_INTERVAL = 9,
  NET_DECNET_CONF = 10,
  NET_DECNET_NO_FC_MAX_CWND = 11,
  NET_DECNET_MEM = 12,
  NET_DECNET_RMEM = 13,
  NET_DECNET_WMEM = 14,
  NET_DECNET_DEBUG_LEVEL = 255
};
enum {
  NET_DECNET_CONF_LOOPBACK = - 2,
  NET_DECNET_CONF_DDCMP = - 3,
  NET_DECNET_CONF_PPP = - 4,
  NET_DECNET_CONF_X25 = - 5,
  NET_DECNET_CONF_GRE = - 6,
  NET_DECNET_CONF_ETHER = - 7
};
enum {
  NET_DECNET_CONF_DEV_PRIORITY = 1,
  NET_DECNET_CONF_DEV_T1 = 2,
  NET_DECNET_CONF_DEV_T2 = 3,
  NET_DECNET_CONF_DEV_T3 = 4,
  NET_DECNET_CONF_DEV_FORWARDING = 5,
  NET_DECNET_CONF_DEV_BLKSIZE = 6,
  NET_DECNET_CONF_DEV_STATE = 7
};
enum {
  NET_SCTP_RTO_INITIAL = 1,
  NET_SCTP_RTO_MIN = 2,
  NET_SCTP_RTO_MAX = 3,
  NET_SCTP_RTO_ALPHA = 4,
  NET_SCTP_RTO_BETA = 5,
  NET_SCTP_VALID_COOKIE_LIFE = 6,
  NET_SCTP_ASSOCIATION_MAX_RETRANS = 7,
  NET_SCTP_PATH_MAX_RETRANS = 8,
  NET_SCTP_MAX_INIT_RETRANSMITS = 9,
  NET_SCTP_HB_INTERVAL = 10,
  NET_SCTP_PRESERVE_ENABLE = 11,
  NET_SCTP_MAX_BURST = 12,
  NET_SCTP_ADDIP_ENABLE = 13,
  NET_SCTP_PRSCTP_ENABLE = 14,
  NET_SCTP_SNDBUF_POLICY = 15,
  NET_SCTP_SACK_TIMEOUT = 16,
  NET_SCTP_RCVBUF_POLICY = 17,
};
enum {
  NET_BRIDGE_NF_CALL_ARPTABLES = 1,
  NET_BRIDGE_NF_CALL_IPTABLES = 2,
  NET_BRIDGE_NF_CALL_IP6TABLES = 3,
  NET_BRIDGE_NF_FILTER_VLAN_TAGGED = 4,
  NET_BRIDGE_NF_FILTER_PPPOE_TAGGED = 5,
};
enum {
  FS_NRINODE = 1,
  FS_STATINODE = 2,
  FS_MAXINODE = 3,
  FS_NRDQUOT = 4,
  FS_MAXDQUOT = 5,
  FS_NRFILE = 6,
  FS_MAXFILE = 7,
  FS_DENTRY = 8,
  FS_NRSUPER = 9,
  FS_MAXSUPER = 10,
  FS_OVERFLOWUID = 11,
  FS_OVERFLOWGID = 12,
  FS_LEASES = 13,
  FS_DIR_NOTIFY = 14,
  FS_LEASE_TIME = 15,
  FS_DQSTATS = 16,
  FS_XFS = 17,
  FS_AIO_NR = 18,
  FS_AIO_MAX_NR = 19,
  FS_INOTIFY = 20,
  FS_OCFS2 = 988,
};
enum {
  FS_DQ_LOOKUPS = 1,
  FS_DQ_DROPS = 2,
  FS_DQ_READS = 3,
  FS_DQ_WRITES = 4,
  FS_DQ_CACHE_HITS = 5,
  FS_DQ_ALLOCATED = 6,
  FS_DQ_FREE = 7,
  FS_DQ_SYNCS = 8,
  FS_DQ_WARNINGS = 9,
};
enum {
  DEV_CDROM = 1,
  DEV_HWMON = 2,
  DEV_PARPORT = 3,
  DEV_RAID = 4,
  DEV_MAC_HID = 5,
  DEV_SCSI = 6,
  DEV_IPMI = 7,
};
enum {
  DEV_CDROM_INFO = 1,
  DEV_CDROM_AUTOCLOSE = 2,
  DEV_CDROM_AUTOEJECT = 3,
  DEV_CDROM_DEBUG = 4,
  DEV_CDROM_LOCK = 5,
  DEV_CDROM_CHECK_MEDIA = 6
};
enum {
  DEV_PARPORT_DEFAULT = - 3
};
enum {
  DEV_RAID_SPEED_LIMIT_MIN = 1,
  DEV_RAID_SPEED_LIMIT_MAX = 2
};
enum {
  DEV_PARPORT_DEFAULT_TIMESLICE = 1,
  DEV_PARPORT_DEFAULT_SPINTIME = 2
};
enum {
  DEV_PARPORT_SPINTIME = 1,
  DEV_PARPORT_BASE_ADDR = 2,
  DEV_PARPORT_IRQ = 3,
  DEV_PARPORT_DMA = 4,
  DEV_PARPORT_MODES = 5,
  DEV_PARPORT_DEVICES = 6,
  DEV_PARPORT_AUTOPROBE = 16
};
enum {
  DEV_PARPORT_DEVICES_ACTIVE = - 3,
};
enum {
  DEV_PARPORT_DEVICE_TIMESLICE = 1,
};
enum {
  DEV_MAC_HID_KEYBOARD_SENDS_LINUX_KEYCODES = 1,
  DEV_MAC_HID_KEYBOARD_LOCK_KEYCODES = 2,
  DEV_MAC_HID_MOUSE_BUTTON_EMULATION = 3,
  DEV_MAC_HID_MOUSE_BUTTON2_KEYCODE = 4,
  DEV_MAC_HID_MOUSE_BUTTON3_KEYCODE = 5,
  DEV_MAC_HID_ADB_MOUSE_SENDS_KEYCODES = 6
};
enum {
  DEV_SCSI_LOGGING_LEVEL = 1,
};
enum {
  DEV_IPMI_POWEROFF_POWERCYCLE = 1,
};
enum {
  ABI_DEFHANDLER_COFF = 1,
  ABI_DEFHANDLER_ELF = 2,
  ABI_DEFHANDLER_LCALL7 = 3,
  ABI_DEFHANDLER_LIBCSO = 4,
  ABI_TRACE = 5,
  ABI_FAKE_UTSNAME = 6,
};
#endif

"""

```