Response:
Thinking Process:

1. **Understand the Goal:** The request asks for a comprehensive analysis of the provided `sched.h` header file from Android's Bionic libc. This includes its functionalities, relationship to Android, implementation details, dynamic linker aspects, potential errors, and how Android frameworks and NDK interact with it. The response needs to be in Chinese and include Frida hook examples.

2. **High-Level Overview:**  The file `sched.h` deals with thread scheduling policies and CPU affinity. It essentially provides an interface to the Linux kernel's scheduling features.

3. **Break Down the Request:**  Address each point in the request systematically:

    * **Functionalities:** List the constants (scheduling policies) and function declarations. Briefly describe what each does.

    * **Relationship with Android:** Explain how these scheduling controls are used in Android to manage app and system process priorities, impacting performance and responsiveness. Think of concrete examples like UI threads, background services, and CPU-intensive tasks.

    * **libc Function Implementation:**  This requires understanding that these are *declarations*. The *implementations* are in the Bionic libc source code (likely in `bionic/libc/bionic/syscalls/` or similar). Explain that these functions ultimately make system calls to the Linux kernel.

    * **Dynamic Linker:** Identify functions related to process creation and namespaces (`clone`, `unshare`, `setns`). Explain how these are used when starting new processes or containers, involving the dynamic linker to load shared libraries.

    * **Logic and Assumptions:** For functions with direct input/output (like getting/setting scheduler parameters or affinity), illustrate with simple examples. For more complex ones like `clone`, focus on the core concept.

    * **Common Errors:** Think about typical programming mistakes when dealing with scheduling and CPU affinity. Incorrect priority settings, affinity masks, and not checking return values are good examples.

    * **Android Framework/NDK Interaction:** Trace the path from a user action (like launching an app) down to the system calls related to scheduling. Highlight the roles of the Android Runtime (ART), Zygote, and NDK.

    * **Frida Hooks:** Provide practical examples of using Frida to intercept calls to these scheduling functions. Focus on logging parameters and return values.

4. **Detailed Examination of the Code:** Go through the `sched.h` file line by line:

    * **Copyright and License:** Acknowledge the open-source nature.
    * **`#pragma once`:** Note its purpose in preventing multiple inclusions.
    * **Includes:**  Recognize the dependency on `sys/cdefs.h` and `linux/sched.h`. The latter is crucial as it defines the actual Linux kernel constants.
    * **Scheduling Policy Definitions (`SCHED_NORMAL`, `SCHED_FIFO`, etc.):** Explain each policy and its intended use case. Point out `SCHED_OTHER` as the POSIX equivalent of `SCHED_NORMAL`.
    * **`sched_param` struct:**  Describe its role in holding the scheduling priority.
    * **Function Declarations (`sched_setscheduler`, `sched_getscheduler`, etc.):**  For each function:
        * Briefly explain its purpose based on the provided comments.
        * Note the parameters and return values.
        * Emphasize the interaction with the kernel.
    * **GNU Extensions (`#if defined(__USE_GNU)`):**  Highlight the functions within this block (`clone`, `unshare`, `setns`, `sched_getcpu`, CPU affinity functions) and their relationship to process/thread management and resource isolation.
    * **CPU Affinity Macros (`CPU_SETSIZE`, `CPU_ZERO`, `CPU_SET`, etc.):** Explain how these macros are used to manipulate CPU sets.

5. **Address Specific Request Points:**

    * **Dynamic Linker Details:**  For `clone`, explain how the `flags` parameter can influence which resources are shared with the child process. For the SO layout, create a simplified example showing how the linker maps libraries into the address space. Describe the linking process (symbol resolution, relocation).

    * **Implementation Details:** While direct implementation code isn't in the header, explain the general mechanism of system calls.

    * **Frida Examples:** Create concise JavaScript snippets demonstrating how to hook `sched_setscheduler` and `sched_getaffinity`, logging the PID, policy, parameters, and return value.

6. **Structure and Language:**

    * Organize the response logically, following the structure of the request.
    * Use clear and concise Chinese.
    * Provide examples to illustrate concepts.
    * Use appropriate terminology (e.g., "系统调用" for system call, "进程" for process, "线程" for thread).

7. **Review and Refine:**  Read through the generated response to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. Ensure all parts of the prompt are addressed. For example, double-check that both Android Framework and NDK paths are illustrated.

By following this systematic approach, the goal is to produce a comprehensive and accurate answer that addresses all aspects of the original request. The key is to combine a high-level understanding with a detailed examination of the provided code.
这是一个关于 Android Bionic 库中 `sched.h` 文件的分析。`sched.h` 文件定义了与线程执行调度相关的接口。

**文件功能概览:**

`bionic/libc/include/sched.handroid/sched.h` 文件定义了用于控制和查询线程调度策略和 CPU 亲和性的函数和宏。它为用户空间程序提供了与 Linux 内核调度器交互的接口。主要功能可以归纳为：

1. **定义调度策略常量:**  例如 `SCHED_NORMAL`、`SCHED_FIFO`、`SCHED_RR` 等，这些常量代表了不同的线程调度方式。
2. **定义调度参数结构体:**  `sched_param` 结构体用于设置和获取线程的调度优先级。
3. **声明调度相关函数:**  例如 `sched_setscheduler`（设置调度策略）、`sched_getscheduler`（获取调度策略）、`sched_yield`（线程让出 CPU）、`sched_setaffinity`（设置 CPU 亲和性）等。
4. **定义 CPU 亲和性相关的宏和类型:** 例如 `cpu_set_t` 结构体和 `CPU_ZERO`、`CPU_SET`、`CPU_ISSET` 等宏，用于管理线程可以运行的 CPU 核心。
5. **提供进程创建和命名空间管理的接口:** 例如 `clone`、`unshare`、`setns`，这些函数与进程/线程的创建和隔离有关。

**与 Android 功能的关系及举例说明:**

`sched.h` 中定义的函数和宏在 Android 系统中被广泛使用，以实现对进程和线程的精细化管理，从而影响系统的性能、响应速度和资源利用率。

* **优先级控制:** Android 系统使用调度策略和优先级来确保重要的进程（例如前台应用、系统服务）能够及时获得 CPU 资源，而降低后台进程的优先级以减少资源占用。
    * **举例:** Android 的 `ActivityManagerService` (AMS) 会根据应用的可见性和重要性，调用 `sched_setscheduler` 和 `sched_setparam` 来调整进程的调度策略和优先级。例如，前台 Activity 的线程通常会被设置为较高的优先级。
* **实时性要求:** 对于一些对延迟非常敏感的任务，例如音频处理或图形渲染，可以使用 `SCHED_FIFO` 或 `SCHED_RR` 策略来保证其得到实时的调度。
    * **举例:** Android 的 SurfaceFlinger 服务负责屏幕合成，它的一些关键线程可能会使用实时调度策略以确保流畅的 UI 渲染。
* **CPU 亲和性:** 通过 `sched_setaffinity`，可以将特定的线程绑定到特定的 CPU 核心上运行，这可以提高 CPU 缓存的命中率，减少线程切换的开销，从而优化性能。
    * **举例:**  Android 的 RenderThread 可能会被绑定到某些 CPU 核心上，以减少与应用主线程的竞争，提高渲染效率。对于多核设备，可以将不同的任务分配到不同的核心上并行执行。
* **进程隔离:** `clone`、`unshare`、`setns` 等函数用于创建新的进程或线程，并控制它们之间的隔离程度。这对于实现 Android 的安全模型和容器化技术至关重要。
    * **举例:**  当 Android 启动一个新的应用进程时，会使用 `clone` 系统调用创建进程，并使用不同的标志来控制进程间的资源共享。`setns` 用于将进程加入到特定的命名空间，实现网络、挂载点等资源的隔离。

**libc 函数的实现原理:**

`sched.h` 文件本身只包含了函数声明，实际的函数实现位于 Bionic libc 的源代码中，通常会通过系统调用与 Linux 内核交互。

以 `sched_setscheduler` 为例：

1. **用户空间调用:** 应用程序调用 `sched_setscheduler(pid, policy, param)`，其中 `pid` 是目标线程的 ID，`policy` 是要设置的调度策略，`param` 包含了优先级等参数。
2. **Bionic libc 包装:**  Bionic libc 中的 `sched_setscheduler` 函数会将这些参数打包，然后发起一个 `syscall` 指令，陷入内核态。
3. **内核处理:** Linux 内核接收到系统调用请求后，会执行相应的内核函数（例如 `sys_sched_setscheduler`）。这个内核函数会进行权限检查，验证参数的有效性，然后修改目标线程的调度策略和参数。
4. **返回用户空间:** 内核操作完成后，会将结果返回给 Bionic libc 的包装函数，包装函数再将结果返回给应用程序。

其他 `sched.h` 中声明的函数也类似，它们都是 Bionic libc 对 Linux 内核提供的调度相关系统调用的封装。

**涉及 dynamic linker 的功能:**

`sched.h` 中与 dynamic linker 直接相关的功能主要是 `clone`、`unshare` 和 `setns`，因为它们涉及到进程的创建和命名空间的管理，而这与动态链接库的加载和管理密切相关。

**so 布局样本:**

当使用 `clone` 创建一个新进程时，新进程需要加载所需的动态链接库。以下是一个简化的 so 布局样本：

```
Address Space:

Stack:          0xbef00000 - 0xbf000000
Heap:           0xb8000000 - 0xbeefffff
libm.so:        0xb7f00000 - 0xb7f10fff  (loaded from /system/lib/libm.so)
libc.so:        0xb7e00000 - 0xb7efffff  (loaded from /system/lib/libc.so)
linker:         0xb7d00000 - 0xb7d0ffff  (loaded from /system/bin/linker)
executable:     0xb7c00000 - 0xb7c0ffff  (/path/to/executable)
```

**链接的处理过程:**

1. **`clone` 系统调用:** 父进程调用 `clone` 创建子进程，可以指定 `CLONE_VM`（共享内存空间）等标志。
2. **加载器启动:** 新进程启动时，内核会将控制权交给 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`)。
3. **解析依赖:** Linker 首先解析可执行文件头部的动态链接信息，找到所需的共享库依赖。
4. **加载共享库:** Linker 根据依赖关系，在文件系统中查找并加载相应的 `.so` 文件到进程的地址空间。这涉及到读取 ELF 文件头、映射代码段和数据段等操作。
5. **符号解析和重定位:** Linker 解析各个共享库的符号表，解决库之间的符号依赖关系。它会修改代码和数据中的地址引用，使其指向正确的内存地址。这个过程称为重定位。
6. **执行程序:** 重定位完成后，Linker 将控制权交给应用程序的入口点，程序开始执行。

**假设输入与输出 (针对 `sched_setscheduler`):**

* **假设输入:**
    * `pid`: 1234 (目标线程的进程 ID)
    * `policy`: `SCHED_FIFO` (先进先出调度策略)
    * `param`: `{ sched_priority: 50 }` (优先级为 50)
* **逻辑推理:** 系统调用会将进程 1234 的调度策略设置为 `SCHED_FIFO`，并将其优先级设置为 50。
* **预期输出:**
    * 如果设置成功，`sched_setscheduler` 返回 0。
    * 如果设置失败（例如权限不足），`sched_setscheduler` 返回 -1，并设置 `errno`。

**用户或编程常见的使用错误:**

1. **权限不足:**  普通进程可能无法修改其他进程（尤其是特权进程）的调度策略和优先级。尝试修改会返回错误，并设置 `errno` 为 `EPERM`。
    * **例子:**  一个非 root 权限的 APP 尝试将 system server 的线程设置为 `SCHED_FIFO` 策略。
2. **无效的策略或优先级:**  传递了内核不支持的调度策略或者超出了允许范围的优先级值。
    * **例子:**  调用 `sched_setscheduler` 时，`policy` 参数传递了一个未定义的常量，或者 `sched_priority` 超出了 `sched_get_priority_min` 和 `sched_get_priority_max` 返回的范围。
3. **忘记检查返回值:**  调用调度相关函数后，没有检查返回值，导致忽略了可能发生的错误。
    * **例子:**  调用 `sched_setscheduler` 后，没有判断返回值是否为 0，就假设调度策略设置成功。
4. **不理解不同调度策略的含义:**  错误地使用了调度策略，导致性能问题或资源饥饿。
    * **例子:**  将一个长时间运行的后台任务设置为 `SCHED_FIFO` 策略，可能会导致其他低优先级的进程无法获得 CPU 资源。
5. **滥用 CPU 亲和性:**  过度限制线程的 CPU 亲和性，反而可能导致性能下降，特别是在 CPU 负载不均衡的情况下。
    * **例子:**  将所有线程都绑定到同一个 CPU 核心上，在高负载情况下会导致该核心过载，而其他核心处于空闲状态。

**Android framework 或 ndk 如何一步步的到达这里:**

以 NDK 应用调用 `sched_setscheduler` 为例：

1. **NDK 应用代码:**  开发者在 NDK 的 C/C++ 代码中调用 `sched_setscheduler` 函数。
   ```c++
   #include <sched.h>
   #include <unistd.h>
   #include <errno.h>
   #include <stdio.h>

   int main() {
       pid_t pid = getpid();
       struct sched_param params;
       params.sched_priority = 50;
       int ret = sched_setscheduler(pid, SCHED_RR, &params);
       if (ret == -1) {
           perror("sched_setscheduler failed");
           return 1;
       }
       printf("Successfully set scheduler to SCHED_RR with priority 50\n");
       return 0;
   }
   ```
2. **NDK 编译:** 使用 NDK 提供的工具链编译这段代码，生成可执行文件或共享库。
3. **Android Framework 调用:**  如果这是一个 Android 应用，当应用启动或在运行过程中，Android Framework 的相关组件可能会触发执行这段 NDK 代码。例如，通过 JNI 调用 NDK 中的函数。
4. **JNI 调用:**  Java 代码通过 JNI (Java Native Interface) 调用 NDK 中 `sched_setscheduler` 所在的 native 函数。
5. **Bionic libc:**  NDK 代码中调用的 `sched_setscheduler` 函数是 Bionic libc 提供的。
6. **系统调用:** Bionic libc 中的 `sched_setscheduler` 函数会将参数传递给内核，发起 `sched_setscheduler` 系统调用。
7. **内核调度器:** Linux 内核的调度器接收到系统调用后，会根据提供的参数修改目标线程的调度属性。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `sched_setscheduler` 函数来观察其调用情况和参数。

```javascript
if (Process.platform === 'linux') {
  const sched_setscheduler = Module.findExportByName(null, 'sched_setscheduler');

  if (sched_setscheduler) {
    Interceptor.attach(sched_setscheduler, {
      onEnter: function (args) {
        const pid = args[0].toInt32();
        const policy = args[1].toInt32();
        const paramPtr = args[2];
        const priority = paramPtr.readInt();

        console.log(`[sched_setscheduler] PID: ${pid}, Policy: ${policy}, Priority: ${priority}`);

        // 可以进一步解析 policy 的值，例如：
        const policyNames = {
          0: 'SCHED_NORMAL',
          1: 'SCHED_FIFO',
          2: 'SCHED_RR',
          3: 'SCHED_BATCH',
          4: 'SCHED_IDLE',
          5: 'SCHED_DEADLINE'
        };
        console.log(`[sched_setscheduler] Policy Name: ${policyNames[policy] || 'Unknown'}`);
      },
      onLeave: function (retval) {
        console.log(`[sched_setscheduler] Return Value: ${retval}`);
        if (retval.toInt32() === -1) {
          const errno_val = System.errno();
          console.error(`[sched_setscheduler] Error: ${errno_val}`);
        }
      }
    });
    console.log('Attached to sched_setscheduler');
  } else {
    console.log('sched_setscheduler not found');
  }
}
```

这个 Frida 脚本会 hook `sched_setscheduler` 函数，并在其调用前后打印出相关的参数（PID、策略、优先级）和返回值。如果调用失败，还会打印出 `errno` 的值，方便调试。

要调试 CPU 亲和性相关的函数，可以类似地 hook `sched_setaffinity` 和 `sched_getaffinity`，并解析 `cpu_set_t` 结构体中的 CPU 掩码。

总结来说，`bionic/libc/include/sched.handroid/sched.h` 文件定义了 Android 系统中线程调度的核心接口，它与 Android 的性能管理、实时性需求和进程隔离等功能密切相关。理解这些接口的功能和使用方式对于开发高性能的 Android 应用和进行系统级别的调试至关重要。

Prompt: 
```
这是目录为bionic/libc/include/sched.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

/**
 * @file sched.h
 * @brief Thread execution scheduling.
 */

#include <sys/cdefs.h>

#include <bits/timespec.h>
#include <linux/sched.h>

__BEGIN_DECLS

/*
 * @def SCHED_NORMAL
 * The standard (as opposed to real-time) round-robin scheduling policy.
 *
 * (Linux's name for POSIX's SCHED_OTHER.)
 *
 * See [sched(7)](https://man7.org/linux/man-pages/man7/sched.7.html)
 */

/*
 * @def SCHED_FIFO
 * The real-time first-in/first-out scheduling policy.
 *
 * See [sched(7)](https://man7.org/linux/man-pages/man7/sched.7.html)
 */

/*
 * @def SCHED_RR
 * The real-time round-robin policy. (See also SCHED_NORMAL/SCHED_OTHER.)
 *
 * See [sched(7)](https://man7.org/linux/man-pages/man7/sched.7.html)
 */

/*
 * @def SCHED_BATCH
 * The batch scheduling policy.
 *
 * See [sched(7)](https://man7.org/linux/man-pages/man7/sched.7.html)
 */

/*
 * @def SCHED_IDLE
 * The low priority "only when otherwise idle" scheduling priority.
 *
 * See [sched(7)](https://man7.org/linux/man-pages/man7/sched.7.html)
 */

/*
 * @def SCHED_DEADLINE
 * The deadline scheduling policy.
 *
 * See [sched(7)](https://man7.org/linux/man-pages/man7/sched.7.html)
 */

/*
 * The standard (as opposed to real-time) round-robin scheduling policy.
 *
 * (POSIX's name for Linux's SCHED_NORMAL.)
 */
#define SCHED_OTHER SCHED_NORMAL

/**
 * See sched_getparam()/sched_setparam() and
 * sched_getscheduler()/sched_setscheduler().
 */
struct sched_param {
  int sched_priority;
};

/**
 * [sched_setscheduler(2)](https://man7.org/linux/man-pages/man2/sched_setscheduler.2.html)
 * sets the scheduling policy and associated parameters for the given thread.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int sched_setscheduler(pid_t __pid, int __policy, const struct sched_param* _Nonnull __param);

/**
 * [sched_getscheduler(2)](https://man7.org/linux/man-pages/man2/sched_getscheduler.2)
 * gets the scheduling policy for the given thread.
 *
 * Returns a non-negative thread policy on success and returns -1 and sets
 * `errno` on failure.
 */
int sched_getscheduler(pid_t __pid);

/**
 * [sched_yield(2)](https://man7.org/linux/man-pages/man2/sched_yield.2.html)
 * voluntarily gives up using the CPU so that another thread can run.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int sched_yield(void);

/**
 * [sched_get_priority_max(2)](https://man7.org/linux/man-pages/man2/sched_get_priority_max.2.html)
 * gets the maximum priority value allowed for the given scheduling policy.
 *
 * Returns a priority on success and returns -1 and sets `errno` on failure.
 */
int sched_get_priority_max(int __policy);

/**
 * [sched_get_priority_min(2)](https://man7.org/linux/man-pages/man2/sched_get_priority_min.2.html)
 * gets the minimum priority value allowed for the given scheduling policy.
 *
 * Returns a priority on success and returns -1 and sets `errno` on failure.
 */
int sched_get_priority_min(int __policy);

/**
 * [sched_setparam(2)](https://man7.org/linux/man-pages/man2/sched_setparam.2.html)
 * sets the scheduling parameters for the given thread.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int sched_setparam(pid_t __pid, const struct sched_param* _Nonnull __param);

/**
 * [sched_getparam(2)](https://man7.org/linux/man-pages/man2/sched_getparam.2.html)
 * gets the scheduling parameters for the given thread.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int sched_getparam(pid_t __pid, struct sched_param* _Nonnull __param);

/**
 * [sched_rr_get_interval(2)](https://man7.org/linux/man-pages/man2/sched_rr_get_interval.2.html)
 * queries the round-robin time quantum for the given thread.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int sched_rr_get_interval(pid_t __pid, struct timespec* _Nonnull __quantum);

#if defined(__USE_GNU)

/**
 * [clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html)
 * creates a new child process.
 *
 * Returns the pid of the child to the caller on success and
 * returns -1 and sets `errno` on failure.
 */
int clone(int (* __BIONIC_COMPLICATED_NULLNESS __fn)(void* __BIONIC_COMPLICATED_NULLNESS ), void* __BIONIC_COMPLICATED_NULLNESS __child_stack, int __flags, void* _Nullable __arg, ...);

/**
 * [unshare(2)](https://man7.org/linux/man-pages/man2/unshare.2.html)
 * disassociates part of the caller's execution context.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int unshare(int __flags);

/**
 * [setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html)
 * reassociates a thread with a different namespace.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int setns(int __fd, int __ns_type);

/**
 * [sched_getcpu(3)](https://man7.org/linux/man-pages/man3/sched_getcpu.3.html)
 * reports which CPU the caller is running on.
 *
 * Returns a non-negative CPU number on success and returns -1 and sets
 * `errno` on failure.
 */
int sched_getcpu(void);

#ifdef __LP64__
#define CPU_SETSIZE 1024
#else
#define CPU_SETSIZE 32
#endif

#define __CPU_BITTYPE  unsigned long int  /* mandated by the kernel  */
#define __CPU_BITS     (8 * sizeof(__CPU_BITTYPE))
#define __CPU_ELT(x)   ((x) / __CPU_BITS)
#define __CPU_MASK(x)  ((__CPU_BITTYPE)1 << ((x) & (__CPU_BITS - 1)))

/**
 * [cpu_set_t](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) is a
 * statically-sized CPU set. See `CPU_ALLOC` for dynamically-sized CPU sets.
 */
typedef struct {
  __CPU_BITTYPE  __bits[ CPU_SETSIZE / __CPU_BITS ];
} cpu_set_t;

/**
 * [sched_setaffinity(2)](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html)
 * sets the CPU affinity mask for the given thread.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int sched_setaffinity(pid_t __pid, size_t __set_size, const cpu_set_t* _Nonnull __set);

/**
 * [sched_getaffinity(2)](https://man7.org/linux/man-pages/man2/sched_getaffinity.2.html)
 * gets the CPU affinity mask for the given thread.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int sched_getaffinity(pid_t __pid, size_t __set_size, cpu_set_t* _Nonnull __set);

/**
 * [CPU_ZERO](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) clears all
 * bits in a static CPU set.
 */
#define CPU_ZERO(set)          CPU_ZERO_S(sizeof(cpu_set_t), set)
/**
 * [CPU_ZERO_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) clears all
 * bits in a dynamic CPU set allocated by `CPU_ALLOC`.
 */
#define CPU_ZERO_S(setsize, set)  __builtin_memset(set, 0, setsize)

/**
 * [CPU_SET](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) sets one
 * bit in a static CPU set.
 */
#define CPU_SET(cpu, set)      CPU_SET_S(cpu, sizeof(cpu_set_t), set)
/**
 * [CPU_SET_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) sets one
 * bit in a dynamic CPU set allocated by `CPU_ALLOC`.
 */
#define CPU_SET_S(cpu, setsize, set) \
  do { \
    size_t __cpu = (cpu); \
    if (__cpu < 8 * (setsize)) \
      (set)->__bits[__CPU_ELT(__cpu)] |= __CPU_MASK(__cpu); \
  } while (0)

/**
 * [CPU_CLR](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) clears one
 * bit in a static CPU set.
 */
#define CPU_CLR(cpu, set)      CPU_CLR_S(cpu, sizeof(cpu_set_t), set)
/**
 * [CPU_CLR_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) clears one
 * bit in a dynamic CPU set allocated by `CPU_ALLOC`.
 */
#define CPU_CLR_S(cpu, setsize, set) \
  do { \
    size_t __cpu = (cpu); \
    if (__cpu < 8 * (setsize)) \
      (set)->__bits[__CPU_ELT(__cpu)] &= ~__CPU_MASK(__cpu); \
  } while (0)

/**
 * [CPU_ISSET](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) tests
 * whether the given bit is set in a static CPU set.
 */
#define CPU_ISSET(cpu, set)    CPU_ISSET_S(cpu, sizeof(cpu_set_t), set)
/**
 * [CPU_ISSET_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) tests
 * whether the given bit is set in a dynamic CPU set allocated by `CPU_ALLOC`.
 */
#define CPU_ISSET_S(cpu, setsize, set) \
  (__extension__ ({ \
    size_t __cpu = (cpu); \
    (__cpu < 8 * (setsize)) \
      ? ((set)->__bits[__CPU_ELT(__cpu)] & __CPU_MASK(__cpu)) != 0 \
      : 0; \
  }))

/**
 * [CPU_COUNT](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) counts
 * how many bits are set in a static CPU set.
 */
#define CPU_COUNT(set)         CPU_COUNT_S(sizeof(cpu_set_t), set)
/**
 * [CPU_COUNT_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) counts
 * how many bits are set in a dynamic CPU set allocated by `CPU_ALLOC`.
 */
#define CPU_COUNT_S(setsize, set)  __sched_cpucount((setsize), (set))
int __sched_cpucount(size_t __set_size, const cpu_set_t* _Nonnull __set);

/**
 * [CPU_EQUAL](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) tests
 * whether two static CPU sets have the same bits set and cleared as each other.
 */
#define CPU_EQUAL(set1, set2)  CPU_EQUAL_S(sizeof(cpu_set_t), set1, set2)
/**
 * [CPU_EQUAL_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) tests
 * whether two dynamic CPU sets allocated by `CPU_ALLOC` have the same bits
 * set and cleared as each other.
 */
#define CPU_EQUAL_S(setsize, set1, set2)  (__builtin_memcmp(set1, set2, setsize) == 0)

/**
 * [CPU_AND](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) ands two
 * static CPU sets.
 */
#define CPU_AND(dst, set1, set2)  __CPU_OP(dst, set1, set2, &)
/**
 * [CPU_AND_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) ands two
 * dynamic CPU sets allocated by `CPU_ALLOC`.
 */
#define CPU_AND_S(setsize, dst, set1, set2)  __CPU_OP_S(setsize, dst, set1, set2, &)

/**
 * [CPU_OR](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) ors two
 * static CPU sets.
 */
#define CPU_OR(dst, set1, set2)   __CPU_OP(dst, set1, set2, |)
/**
 * [CPU_OR_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html) ors two
 * dynamic CPU sets allocated by `CPU_ALLOC`.
 */
#define CPU_OR_S(setsize, dst, set1, set2)   __CPU_OP_S(setsize, dst, set1, set2, |)

/**
 * [CPU_XOR](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
 * exclusive-ors two static CPU sets.
 */
#define CPU_XOR(dst, set1, set2)  __CPU_OP(dst, set1, set2, ^)
/**
 * [CPU_XOR_S](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
 * exclusive-ors two dynamic CPU sets allocated by `CPU_ALLOC`.
 */
#define CPU_XOR_S(setsize, dst, set1, set2)  __CPU_OP_S(setsize, dst, set1, set2, ^)

#define __CPU_OP(dst, set1, set2, op)  __CPU_OP_S(sizeof(cpu_set_t), dst, set1, set2, op)

#define __CPU_OP_S(setsize, dstset, srcset1, srcset2, op) \
  do { \
    cpu_set_t* __dst = (dstset); \
    const __CPU_BITTYPE* __src1 = (srcset1)->__bits; \
    const __CPU_BITTYPE* __src2 = (srcset2)->__bits; \
    size_t __nn = 0, __nn_max = (setsize)/sizeof(__CPU_BITTYPE); \
    for (; __nn < __nn_max; __nn++) \
      (__dst)->__bits[__nn] = __src1[__nn] op __src2[__nn]; \
  } while (0)

/**
 * [CPU_ALLOC_SIZE](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
 * returns the size of a CPU set large enough for CPUs in the range 0..count-1.
 */
#define CPU_ALLOC_SIZE(count) \
  __CPU_ELT((count) + (__CPU_BITS - 1)) * sizeof(__CPU_BITTYPE)

/**
 * [CPU_ALLOC](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
 * allocates a CPU set large enough for CPUs in the range 0..count-1.
 */
#define CPU_ALLOC(count)  __sched_cpualloc((count))
cpu_set_t* _Nullable __sched_cpualloc(size_t __count);

/**
 * [CPU_FREE](https://man7.org/linux/man-pages/man3/CPU_SET.3.html)
 * deallocates a CPU set allocated by `CPU_ALLOC`.
 */
#define CPU_FREE(set)     __sched_cpufree((set))
void __sched_cpufree(cpu_set_t* _Nonnull __set);

#endif /* __USE_GNU */

__END_DECLS

"""

```