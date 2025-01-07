Response:
Let's break down the thought process for answering the user's request about the `seccomp_policy.cpp` file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of this specific file within the Android Bionic library, how it relates to Android, the implementation details of its libc functions, dynamic linker aspects (if any), potential errors, and how it's reached from higher Android layers, along with a debugging example.

**2. Initial Assessment of the Code:**

Scanning the code, the most prominent feature is the use of `seccomp`. Keywords like `SECCOMP_MODE_FILTER`, `sock_filter`, `BPF_STMT`, `SECCOMP_RET_ALLOW`, and architecture-specific definitions (`AUDIT_ARCH_AARCH64`, `arm64_app_filter`) immediately point to its purpose: defining and installing seccomp filters.

**3. Identifying Key Functionalities:**

Based on the code and the understanding of seccomp, the main functions are:

* **Defining Seccomp Policies:**  The numerous `*_app_filter`, `*_zygote_filter`, and `*_system_filter` variables, along with their sizes, clearly represent pre-defined seccomp policies for different Android process types. The architecture-specific conditional compilation (`#if defined __arm__ || ...`) indicates the file handles multiple architectures.
* **Installing Seccomp Filters:** The `install_filter` function is the core mechanism for applying a given filter to the current process using `prctl(PR_SET_SECCOMP, ...)`.
* **Specialized Filters (SetUID/GID):** The `_install_setuidgid_filter` and `ValidateSetUidGid` functions handle a specific filtering scenario related to `setresuid` and `setresgid`, focusing on restricting the allowed UID/GID ranges.
* **Helper Functions:** The `Allow`, `Disallow`, `ExamineSyscall`, and the architecture validation functions (`ValidateArchitecture`, `ValidateArchitectureAndJumpIfNeeded`, `SetValidateArchitectureJumpTarget`) are building blocks for constructing the seccomp filters.

**4. Connecting to Android Features:**

The presence of `APP`, `APP_ZYGOTE`, and `SYSTEM` filter types directly connects to Android's process model. Zygote is the process from which most Android apps are forked. System processes run with higher privileges. Seccomp is used to sandbox these processes, limiting the system calls they can make for security.

**5. Explaining Libc Functions:**

The code directly uses `prctl`. The explanation needs to cover its purpose in general (process control) and specifically how it's used with `PR_SET_SECCOMP` to install seccomp filters. The `syscall()` function is implicitly used when the BPF filter returns `SECCOMP_RET_TRAP`, so that needs explanation too (though not directly called in *this* code).

**6. Addressing Dynamic Linker Aspects:**

While the code itself *doesn't* directly interact with the dynamic linker, seccomp policies can *affect* the dynamic linker. For example, if a dynamic linker needs to make a disallowed syscall, the process will be terminated. Therefore, the explanation needs to touch on this indirect relationship. A hypothetical scenario of a disallowed `open()` call during library loading would be a good example.

**7. Identifying Potential User Errors:**

The most obvious user error is trying to perform a syscall that is blocked by the active seccomp policy. Trying to change UID/GID outside the allowed range (if the UID/GID filter is active) is another specific error scenario.

**8. Tracing the Path from Android Framework/NDK:**

This requires understanding the Android process lifecycle. The Zygote process plays a crucial role. The framework (e.g., ActivityManagerService) requests Zygote to fork a new app process. Zygote, *before* executing the app's code, applies the appropriate seccomp filter. System server and other privileged processes might have different filters applied. The NDK doesn't directly *call* these functions, but the compiled NDK code runs within the constraints imposed by the seccomp filter set by the framework/Zygote.

**9. Developing a Frida Hook Example:**

A simple Frida hook should demonstrate how to intercept the `prctl` call that installs the seccomp filter. Hooking `prctl` and logging the arguments, especially the `SECCOMP_MODE_FILTER` and the size of the filter, will provide valuable insight.

**10. Structuring the Response:**

Organize the information logically based on the user's request:

* **Functionality:** Start with a high-level overview.
* **Relationship to Android:** Connect the concepts to Android's process model and security features.
* **Libc Function Explanation:** Provide details on `prctl`.
* **Dynamic Linker:** Explain the indirect impact and provide an example.
* **Logical Reasoning (Assumptions/Outputs):** Illustrate how the filter matching works with a simple example.
* **User Errors:** Give concrete examples of common mistakes.
* **Android Framework/NDK Path:** Detail the process from Zygote to the application of the filter.
* **Frida Hook:** Provide a practical debugging example.

**Self-Correction/Refinement during the Thought Process:**

* **Initial Thought:** Focus solely on the technical aspects of BPF filters.
* **Correction:** Realize the importance of connecting it to the *Android context* to fully answer the user's question. Emphasize the Zygote and process model aspects.
* **Initial Thought:**  Deep dive into the intricacies of BPF instructions.
* **Correction:** Keep the explanation at a high level, focusing on the purpose of the filters rather than the low-level BPF details, unless specifically asked. Mention the BPF nature but avoid getting lost in the details.
* **Initial Thought:**  The dynamic linker section might require deep knowledge of its internals.
* **Correction:** Focus on the *impact* of seccomp on the dynamic linker, using a concrete example of a blocked syscall during library loading.

By following this structured approach and performing self-correction, a comprehensive and informative answer can be constructed that addresses all aspects of the user's request.
好的，让我们详细分析一下 `bionic/libc/seccomp/seccomp_policy.cpp` 这个文件。

**文件功能概述**

这个文件的核心功能是定义和安装 seccomp (secure computing mode) 策略。Seccomp 是一种 Linux 内核安全特性，允许进程限制自身可以发起的系统调用。通过预先定义好的策略，可以显著降低恶意代码利用漏洞进行攻击的可能性，增强系统的安全性。

**详细功能分解**

1. **定义 Seccomp 策略 (BPF 过滤器):**
   - 文件中定义了多种 seccomp 策略，这些策略以 BPF (Berkeley Packet Filter) 指令的形式存在。BPF 最初用于网络数据包过滤，后来被扩展用于系统调用过滤。
   - 这些策略以静态数组的形式定义，例如 `arm64_app_filter`, `x86_64_system_filter` 等。
   - 不同的策略针对不同的进程类型，例如：
     - `*_app_filter`:  应用于普通 Android 应用程序进程。
     - `*_app_zygote_filter`: 应用于 Zygote 进程 (孵化器进程，用于 fork 新的应用程序进程)。
     - `*_system_filter`: 应用于 Android 系统进程。
   - 策略的内容是允许或禁止特定的系统调用。例如，一个应用程序可能被允许执行 `read`, `write`, `openat` 等常见操作，但禁止执行 `fork`, `execve` 等可能被滥用的系统调用。
   - 文件通过宏定义 (`#if defined __arm__ ...`) 为不同的 CPU 架构 (ARM, ARM64, x86, x86_64, RISC-V) 定义了对应的策略。

2. **安装 Seccomp 策略:**
   - `install_filter(filter const& f)` 函数负责将一个 BPF 过滤器安装到当前进程。
   - 它使用 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` 系统调用来完成安装。
   - `PR_SET_SECCOMP` 是 `prctl` 系统调用的一个选项，用于设置 seccomp 模式。
   - `SECCOMP_MODE_FILTER` 指定使用 BPF 过滤器模式。
   - `prog` 是一个 `sock_fprog` 结构体，包含了 BPF 过滤器的指令和大小。

3. **辅助函数:**
   - `Allow(filter& f)`: 向 BPF 过滤器添加一条允许执行当前系统调用的指令。
   - `Disallow(filter& f)`: 向 BPF 过滤器添加一条禁止执行当前系统调用的指令，并触发 `SECCOMP_RET_TRAP`，通常会导致进程收到 `SIGSYS` 信号并可能被终止。
   - `ExamineSyscall(filter& f)`: 向 BPF 过滤器添加一条加载当前系统调用号的指令，以便后续的判断。
   - `ValidateArchitecture(...)`: 用于在多架构系统上验证当前执行的架构是否与策略匹配。这在 32 位和 64 位系统混合的环境中很重要。
   - `ValidateSyscallArgInRange(...)`: 用于检查系统调用的某个参数是否在指定的范围内。
   - `ValidateSetUidGid(...)`:  一个特定的过滤器，用于限制 `setresuid` 和 `setresgid` 系统调用的参数范围，通常用于限制 UID/GID 的更改。

4. **对外接口函数:**
   - `set_app_seccomp_filter()`: 安装应用程序的 seccomp 策略。
   - `set_app_zygote_seccomp_filter()`: 安装 Zygote 进程的 seccomp 策略。
   - `set_system_seccomp_filter()`: 安装系统进程的 seccomp 策略。
   - `install_setuidgid_seccomp_filter(uint32_t uid_gid_min, uint32_t uid_gid_max)`: 安装限制 UID/GID 范围的 seccomp 策略。

**与 Android 功能的关系及举例**

Seccomp 是 Android 安全模型的重要组成部分。它可以防止应用程序和系统服务执行不必要的系统调用，从而减少安全漏洞被利用的风险。

**举例说明:**

- **应用程序沙箱:** 当 Android 启动一个新的应用程序时，Zygote 进程会 fork 出新的进程，并在执行应用程序代码之前，调用 `set_app_seccomp_filter()` 来安装应用程序的 seccomp 策略。这个策略限制了应用程序可以调用的系统调用，例如，它通常会禁止应用程序直接操作硬件或进行某些特权操作。这增强了应用程序的安全性，即使应用程序存在漏洞，攻击者也难以利用这些漏洞进行提权或访问敏感资源。
- **系统服务隔离:** 类似的，Android 的系统服务也会应用 seccomp 策略。例如，媒体服务器进程可能会被限制只能访问音频和视频相关的设备和文件，而无法访问网络或文件系统中的其他敏感数据。
- **防止特权提升:**  `install_setuidgid_seccomp_filter` 可以被用于限制进程更改其用户 ID 或组 ID 的能力。这在某些需要降低权限的场景下非常有用，可以防止进程意外或恶意地提升权限。

**libc 函数的实现细节**

这个文件中主要涉及的 libc 函数是 `prctl`。

- **`prctl()`:**  `prctl` 是 "process control" 的缩写，它提供了一系列进程控制操作。其原型如下：

  ```c
  #include <sys/prctl.h>

  int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
  ```

  - **`option`**: 指定要执行的操作类型。在这个文件中，`option` 的值是 `PR_SET_SECCOMP`，表示要设置 seccomp 模式。
  - **`arg2`**:  当 `option` 为 `PR_SET_SECCOMP` 时，`arg2` 指定 seccomp 模式。这里的值是 `SECCOMP_MODE_FILTER`，表示使用 BPF 过滤器。
  - **`arg3`**:  当 `arg2` 为 `SECCOMP_MODE_FILTER` 时，`arg3` 是指向 `sock_fprog` 结构体的指针，该结构体定义了 BPF 过滤器。
  - **`arg4`, `arg5`**:  通常未使用，或者根据 `option` 的不同有特定的含义。

  **`prctl` 的实现:** `prctl` 是一个系统调用，其具体实现位于 Linux 内核中。当用户空间的进程调用 `prctl` 时，会触发一个系统调用陷入内核。内核根据传入的 `option` 参数执行相应的操作。对于 `PR_SET_SECCOMP`，内核会解析 `sock_fprog` 结构体中的 BPF 指令，并将这些指令加载到进程的 seccomp 上下文中。一旦 seccomp 过滤器被激活，进程发起的每个系统调用都会先经过过滤器的检查。

**涉及 dynamic linker 的功能**

这个文件本身并不直接涉及 dynamic linker 的操作。然而，seccomp 策略会影响 dynamic linker 的行为。

**SO 布局样本 (假设某个使用了 seccomp 的应用):**

```
/system/bin/app_process64  (主进程)
  |-- zygote64            (孵化器进程，启动时已设置 seccomp)
      |-- com.example.myapp (应用程序进程，由 zygote fork 并应用 seccomp 策略)
          |-- /system/lib64/libc.so
          |-- /system/lib64/libm.so
          |-- /data/app/com.example.myapp/lib/arm64/libnative.so
```

**链接的处理过程:**

1. 当 `com.example.myapp` 启动时，它的进程是通过 Zygote fork 出来的。
2. 在 Zygote fork 后，但在执行应用程序的主要代码之前，Android framework 会设置应用程序的 seccomp 策略（通常通过调用 `set_app_seccomp_filter()`）。
3. 当应用程序的代码执行到需要加载动态链接库 (如 `libnative.so`) 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。
4. dynamic linker 在加载和链接共享库的过程中，需要执行一系列操作，包括打开文件、读取文件内容、解析 ELF 格式、分配内存、重定位符号等。
5. **Seccomp 的影响:** 应用程序的 seccomp 策略限制了 dynamic linker 在这个过程中可以调用的系统调用。例如，如果应用程序的策略禁止了 `openat` 系统调用，那么 dynamic linker 在尝试打开共享库文件时将会失败，进程可能会因为收到 `SIGSYS` 信号而终止。
6. **策略调整:** Android 系统会精心设计应用程序的 seccomp 策略，以确保 dynamic linker 可以正常完成加载共享库所需的必要操作，同时限制其他潜在的危险操作。

**逻辑推理 (假设输入与输出)**

**假设输入:**

- 当前进程是应用程序进程。
- `set_app_seccomp_filter()` 被调用。
- `primary_app_filter` (假设架构是 ARM64) 包含了以下 BPF 指令 (简化示例)：
  - 允许 `read` 系统调用。
  - 允许 `write` 系统调用。
  - 禁止 `openat` 系统调用。

**输出:**

- 进程的 seccomp 上下文被设置为 `primary_app_filter` 定义的策略。
- 当应用程序尝试调用 `read()` 或 `write()` 时，系统调用会被允许执行。
- 当应用程序尝试调用 `openat()` 时，BPF 过滤器会匹配到禁止规则，返回 `SECCOMP_RET_TRAP`，导致进程收到 `SIGSYS` 信号 (默认行为是终止进程)。

**用户或编程常见的使用错误**

1. **尝试调用被禁止的系统调用:** 最常见的使用错误是应用程序尝试执行 seccomp 策略不允许的系统调用。这通常不是程序员直接编写的代码错误，而是因为他们使用的库或系统调用在当前 seccomp 策略下是被禁止的。

   **示例:** 假设一个应用程序尝试使用 `socket()` 系统调用创建一个网络套接字，但应用程序的 seccomp 策略禁止了 `socket()`。这时，应用程序会收到 `SIGSYS` 信号。

2. **没有考虑 seccomp 策略的影响:** 开发者在编写 Native 代码时，需要了解目标 Android 版本的 seccomp 策略，避免使用被禁止的系统调用。

3. **在错误的进程中尝试设置 seccomp:**  通常只有具有 `CAP_SYS_ADMIN` 权限的进程或者已经设置了 `PR_SET_NO_NEW_PRIVS` 标志的进程才能成功设置 seccomp 策略。普通应用程序无法随意修改自己的 seccomp 策略。

**Android Framework 或 NDK 如何到达这里**

以下是从 Android Framework 到达 `seccomp_policy.cpp` 的一个简化的流程：

1. **应用程序启动:** 当用户启动一个应用程序时，Activity Manager Service (AMS) 会请求 Zygote 进程 fork 一个新的进程来运行该应用程序。
2. **Zygote 进程处理:** Zygote 进程接收到 AMS 的请求后，会执行以下步骤：
   - 调用 `fork()` 创建一个新的子进程。
   - 在子进程中，调用 `android_set_application_seccomp_policy()` (这是一个 Java Native Interface 函数，定义在 `frameworks/base/core/jni/com_android_internal_os_Zygote.cpp` 中)。
   - `android_set_application_seccomp_policy()` 内部会调用到 Bionic 库中的 `set_app_seccomp_filter()` 函数 (定义在 `bionic/libc/seccomp/seccomp_policy.cpp` 中)。
   - `set_app_seccomp_filter()` 函数会根据当前架构选择相应的应用程序 seccomp 策略，并调用 `install_filter()` 来安装策略。
   - 完成 seccomp 策略安装后，Zygote 子进程会执行应用程序的 `main()` 函数。

3. **NDK 的影响:**  使用 NDK 开发的 Native 代码运行在应用程序进程中，因此也会受到应用程序 seccomp 策略的限制。如果 NDK 代码尝试调用被禁止的系统调用，同样会触发 seccomp 机制。

**Frida Hook 示例调试步骤**

可以使用 Frida Hook 来观察 seccomp 策略的安装过程。以下是一个 Hook `prctl` 函数的示例：

```javascript
if (Process.platform === 'linux') {
  const prctl = Module.findExportByName(null, 'prctl');
  if (prctl) {
    Interceptor.attach(prctl, {
      onEnter: function (args) {
        const option = args[0].toInt();
        if (option === 157) { // PR_SET_SECCOMP 的值
          const mode = args[1].toInt();
          if (mode === 1) { // SECCOMP_MODE_FILTER 的值
            const uaddr = ptr(args[2]);
            const prog = uaddr.readU32();
            const len = uaddr.add(4).readU16();
            console.log('[Seccomp] prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog=' + prog + ', len=' + len + ')');
            // 你可以进一步解析 BPF 指令，但这比较复杂
          }
        }
      },
      onLeave: function (retval) {
        // console.log('[Seccomp] prctl returned:', retval);
      }
    });
  } else {
    console.log('[Seccomp] prctl not found!');
  }
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 frida-server。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `seccomp_hook.js`。
3. **运行 Frida 脚本:** 使用 Frida 命令将脚本注入到目标进程 (例如，你要观察哪个应用程序的 seccomp 策略安装过程)。你可以通过进程名称或 PID 来指定目标进程。

   ```bash
   frida -U -f com.example.myapp -l seccomp_hook.js --no-pause
   # 或者，如果已知进程 PID
   frida -U <PID> -l seccomp_hook.js --no-pause
   ```

   - `-U`: 连接 USB 设备。
   - `-f com.example.myapp`: 启动并附加到 `com.example.myapp` 进程。
   - `-l seccomp_hook.js`: 加载 Frida 脚本。
   - `--no-pause`:  不暂停进程启动。

4. **查看输出:** 当目标应用程序启动并设置 seccomp 策略时，Frida 会拦截 `prctl` 调用，并在控制台上打印相关信息，包括 `PR_SET_SECCOMP`、`SECCOMP_MODE_FILTER` 以及 BPF 过滤器的地址和长度。

**更深入的 Hook (解析 BPF 指令):**

要更深入地了解具体的 seccomp 策略内容，你需要解析 BPF 指令。这需要理解 BPF 的指令格式。你可以读取 `args[2]` 指向的内存区域，并根据 BPF 的结构 (`struct sock_filter`) 解析每一条指令的操作码、跳转等信息。这部分比较复杂，需要参考 BPF 的相关文档。

希望以上详细的解释能够帮助你理解 `bionic/libc/seccomp/seccomp_policy.cpp` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/seccomp/seccomp_policy.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "seccomp_policy.h"

#include <assert.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <vector>

#include <android-base/logging.h>
#include <android-base/macros.h>

#include "func_to_syscall_nrs.h"
#include "seccomp_bpfs.h"

#if defined __arm__ || defined __aarch64__

#define PRIMARY_ARCH AUDIT_ARCH_AARCH64
static const struct sock_filter* primary_app_filter = arm64_app_filter;
static const size_t primary_app_filter_size = arm64_app_filter_size;
static const struct sock_filter* primary_app_zygote_filter = arm64_app_zygote_filter;
static const size_t primary_app_zygote_filter_size = arm64_app_zygote_filter_size;
static const struct sock_filter* primary_system_filter = arm64_system_filter;
static const size_t primary_system_filter_size = arm64_system_filter_size;

static const long primary_setresgid = __arm64_setresgid;
static const long primary_setresuid = __arm64_setresuid;
#define SECONDARY_ARCH AUDIT_ARCH_ARM
static const struct sock_filter* secondary_app_filter = arm_app_filter;
static const size_t secondary_app_filter_size = arm_app_filter_size;
static const struct sock_filter* secondary_app_zygote_filter = arm_app_zygote_filter;
static const size_t secondary_app_zygote_filter_size = arm_app_zygote_filter_size;
static const struct sock_filter* secondary_system_filter = arm_system_filter;
static const size_t secondary_system_filter_size = arm_system_filter_size;

static const long secondary_setresgid = __arm_setresgid;
static const long secondary_setresuid = __arm_setresuid;

#elif defined __i386__ || defined __x86_64__

#define PRIMARY_ARCH AUDIT_ARCH_X86_64
static const struct sock_filter* primary_app_filter = x86_64_app_filter;
static const size_t primary_app_filter_size = x86_64_app_filter_size;
static const struct sock_filter* primary_app_zygote_filter = x86_64_app_zygote_filter;
static const size_t primary_app_zygote_filter_size = x86_64_app_zygote_filter_size;
static const struct sock_filter* primary_system_filter = x86_64_system_filter;
static const size_t primary_system_filter_size = x86_64_system_filter_size;

static const long primary_setresgid = __x86_64_setresgid;
static const long primary_setresuid = __x86_64_setresuid;
#define SECONDARY_ARCH AUDIT_ARCH_I386
static const struct sock_filter* secondary_app_filter = x86_app_filter;
static const size_t secondary_app_filter_size = x86_app_filter_size;
static const struct sock_filter* secondary_app_zygote_filter = x86_app_zygote_filter;
static const size_t secondary_app_zygote_filter_size = x86_app_zygote_filter_size;
static const struct sock_filter* secondary_system_filter = x86_system_filter;
static const size_t secondary_system_filter_size = x86_system_filter_size;

static const long secondary_setresgid = __x86_setresgid;
static const long secondary_setresuid = __x86_setresuid;

#elif defined(__riscv)

#define PRIMARY_ARCH AUDIT_ARCH_RISCV64
static const struct sock_filter* primary_app_filter = riscv64_app_filter;
static const size_t primary_app_filter_size = riscv64_app_filter_size;
static const struct sock_filter* primary_app_zygote_filter = riscv64_app_zygote_filter;
static const size_t primary_app_zygote_filter_size = riscv64_app_zygote_filter_size;
static const struct sock_filter* primary_system_filter = riscv64_system_filter;
static const size_t primary_system_filter_size = riscv64_system_filter_size;

static const long primary_setresgid = __riscv64_setresgid;
static const long primary_setresuid = __riscv64_setresuid;

#else
#error No architecture was defined!
#endif


#define syscall_nr (offsetof(struct seccomp_data, nr))
#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define arch_nr (offsetof(struct seccomp_data, arch))

typedef std::vector<sock_filter> filter;

inline void Allow(filter& f) {
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW));
}

inline void Disallow(filter& f) {
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP));
}

static void ExamineSyscall(filter& f) {
    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, syscall_nr));
}

#if defined(SECONDARY_ARCH)
static bool SetValidateArchitectureJumpTarget(size_t offset, filter& f) {
    size_t jump_length = f.size() - offset - 1;
    auto u8_jump_length = (__u8) jump_length;
    if (u8_jump_length != jump_length) {
        LOG(FATAL)
            << "Can't set jump greater than 255 - actual jump is " <<  jump_length;
        return false;
    }
    f[offset] = BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SECONDARY_ARCH, u8_jump_length, 0);
    return true;
}

static size_t ValidateArchitectureAndJumpIfNeeded(filter& f) {
    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, arch_nr));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PRIMARY_ARCH, 2, 0));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SECONDARY_ARCH, 1, 0));
    Disallow(f);
    return f.size() - 2;
}
#else
static void ValidateArchitecture(filter& f) {
    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, arch_nr));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PRIMARY_ARCH, 1, 0));
    Disallow(f);
}
#endif

static void ValidateSyscallArgInRange(filter& f, __u32 arg_num, __u32 range_min, __u32 range_max) {
    const __u32 syscall_arg = syscall_arg(arg_num);

    if (range_max == UINT32_MAX) {
        LOG(FATAL) << "range_max exceeds maximum argument range.";
        return;
    }

    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, syscall_arg));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, range_min, 0, 1));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, range_max + 1, 0, 1));
    Disallow(f);
}

// This filter is meant to be installed in addition to a regular allowlist filter.
// Therefore, it's default action has to be Allow, except when the evaluated
// system call matches setresuid/setresgid and the arguments don't fall within the
// passed in range.
//
// The regular allowlist only allows setresuid/setresgid for UID/GID changes, so
// that's the only system call we need to check here. A CTS test ensures the other
// calls will remain blocked.
static void ValidateSetUidGid(filter& f, uint32_t uid_gid_min, uint32_t uid_gid_max, bool primary) {
#if defined(SECONDARY_ARCH)
    __u32 setresuid_nr = primary ? primary_setresuid : secondary_setresuid;
    __u32 setresgid_nr = primary ? primary_setresgid : secondary_setresgid;
#else
    __u32 setresuid_nr = primary_setresuid;
    __u32 setresgid_nr = primary_setresgid;
    UNUSED(primary);
#endif

    // Check setresuid(ruid, euid, sguid) fall within range
    ExamineSyscall(f);
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, setresuid_nr, 0, 12));
    for (int arg = 0; arg < 3; arg++) {
        ValidateSyscallArgInRange(f, arg, uid_gid_min, uid_gid_max);
    }

    // Check setresgid(rgid, egid, sgid) fall within range
    ExamineSyscall(f);
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, setresgid_nr, 0, 12));
    for (int arg = 0; arg < 3; arg++) {
        ValidateSyscallArgInRange(f, arg, uid_gid_min, uid_gid_max);
    }

    // Default is to allow; other filters may still reject this call.
    Allow(f);
}

static bool install_filter(filter const& f) {
    struct sock_fprog prog = {
        static_cast<unsigned short>(f.size()),
        const_cast<struct sock_filter*>(&f[0]),
    };
    // This assumes either the current process has CAP_SYS_ADMIN, or PR_SET_NO_NEW_PRIVS bit is set.
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        PLOG(FATAL) << "Could not set seccomp filter of size " << f.size();
        return false;
    }
    return true;
}

bool _install_setuidgid_filter(uint32_t uid_gid_min, uint32_t uid_gid_max) {
    filter f;
#if defined(SECONDARY_ARCH)
    // Note that for mixed 64/32 bit architectures, ValidateArchitecture inserts a
    // jump that must be changed to point to the start of the 32-bit policy
    // 32 bit syscalls will not hit the policy between here and the call to SetJump
    auto offset_to_secondary_filter = ValidateArchitectureAndJumpIfNeeded(f);
#else
    ValidateArchitecture(f);
#endif

    ValidateSetUidGid(f, uid_gid_min, uid_gid_max, true /* primary */);

#if defined(SECONDARY_ARCH)
    if (!SetValidateArchitectureJumpTarget(offset_to_secondary_filter, f)) {
        return false;
    }

    ValidateSetUidGid(f, uid_gid_min, uid_gid_max, false /* primary */);
#endif

    return install_filter(f);
}

enum FilterType {
  APP,
  APP_ZYGOTE,
  SYSTEM,
};

bool _set_seccomp_filter(FilterType type) {
    filter f;

    const sock_filter* p;
    size_t p_size;
#if defined(SECONDARY_ARCH)
    const sock_filter* s;
    size_t s_size;
#endif

    switch (type) {
      case APP:
        p = primary_app_filter;
        p_size = primary_app_filter_size;
#if defined(SECONDARY_ARCH)
        s = secondary_app_filter;
        s_size = secondary_app_filter_size;
#endif
        break;
      case APP_ZYGOTE:
        p = primary_app_zygote_filter;
        p_size = primary_app_zygote_filter_size;
#if defined(SECONDARY_ARCH)
        s = secondary_app_zygote_filter;
        s_size = secondary_app_zygote_filter_size;
#endif
        break;
      case SYSTEM:
        p = primary_system_filter;
        p_size = primary_system_filter_size;
#if defined(SECONDARY_ARCH)
        s = secondary_system_filter;
        s_size = secondary_system_filter_size;
#endif
        break;
    }

#if defined(SECONDARY_ARCH)
    // Note that for mixed 64/32 bit architectures, ValidateArchitecture inserts a
    // jump that must be changed to point to the start of the 32-bit policy
    // 32 bit syscalls will not hit the policy between here and the call to SetJump
    auto offset_to_secondary_filter = ValidateArchitectureAndJumpIfNeeded(f);
#else
    ValidateArchitecture(f);
#endif

    ExamineSyscall(f);

    for (size_t i = 0; i < p_size; ++i) {
        f.push_back(p[i]);
    }
    Disallow(f);

#if defined(SECONDARY_ARCH)
    if (!SetValidateArchitectureJumpTarget(offset_to_secondary_filter, f)) {
        return false;
    }

    ExamineSyscall(f);

    for (size_t i = 0; i < s_size; ++i) {
        f.push_back(s[i]);
    }
    Disallow(f);
#endif

    return install_filter(f);
}

bool set_app_seccomp_filter() {
    return _set_seccomp_filter(FilterType::APP);
}

bool set_app_zygote_seccomp_filter() {
    return _set_seccomp_filter(FilterType::APP_ZYGOTE);
}

bool set_system_seccomp_filter() {
    return _set_seccomp_filter(FilterType::SYSTEM);
}

bool install_setuidgid_seccomp_filter(uint32_t uid_gid_min, uint32_t uid_gid_max) {
    return _install_setuidgid_filter(uid_gid_min, uid_gid_max);
}

"""

```