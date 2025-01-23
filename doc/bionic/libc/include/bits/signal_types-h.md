Response:
Let's break down the thought process for analyzing this `signal_types.handroid` header file.

**1. Understanding the Goal:**

The core request is to understand the *purpose* and *functionality* of this header file within the context of Android's Bionic libc. This means going beyond just listing the definitions and explaining *why* they are there and how they are used.

**2. Initial Reading and Keyword Identification:**

The first step is to read through the code and identify key elements:

* **Copyright and License:** This tells us the source and licensing terms, which isn't directly functional but provides context.
* **`#pragma once`:**  A standard header guard, indicating it should only be included once per compilation unit.
* **Includes:**  `<sys/cdefs.h>`, `<limits.h>`, `<linux/signal.h>`, `<sys/types.h>`. These are crucial for understanding dependencies. We know this file relies on lower-level system and kernel definitions.
* **Macros:** `#ifndef _KERNEL__NSIG`, `#define _KERNEL__NSIG`, `#define _NSIG`, `#define NSIG`. These define constants related to signal numbers.
* **Typedefs:** `sig_atomic_t`, `sig_t`, `sighandler_t`, `sigset64_t`. These define type aliases for signal-related concepts.
* **Structs:** `sigaction`, `sigaction64`. These are key data structures for handling signals.
* **Conditional Compilation:** `#if defined(__LP64__)` and `#else`. This highlights platform differences (32-bit vs. 64-bit).
* **Comments:** The comments provide valuable hints about the purpose and history (e.g., "The arm and x86 kernel header files don't define _NSIG," "Userspace's NSIG is the kernel's _NSIG + 1," "sigset_t is already large enough on LP64," "For 32-bit, Android's ABIs used a too-small sigset_t...").

**3. Deconstructing the Components:**

Now, let's examine each identified element in detail:

* **Signal Numbers (Macros):**  The macros related to `_NSIG` are about defining the maximum number of signals the system supports. The kernel defines one value (`_KERNEL__NSIG`), and userspace adds one more, likely for a signal related to real-time extensions or specific userspace needs. The comment explicitly states this.

* **Basic Signal Types (Typedefs):**
    * `sig_atomic_t`:  This is about ensuring atomic operations, crucial for signal handlers to prevent race conditions.
    * `sig_t` and `sighandler_t`: These are aliases for function pointers that take an integer (signal number) and return void. They represent the type of a signal handler function. The comments clarify BSD and glibc compatibility.

* **Signal Sets (`sigset64_t`):** This is where the 32-bit/64-bit difference becomes significant. The comments clearly explain that the 32-bit `sigset_t` was too small, hence the need for `sigset64_t`. This is a key Android-specific adaptation. Understanding how signal sets work (bitmasks representing which signals are blocked or acted upon) is essential.

* **Signal Actions (`sigaction` and `sigaction64`):**  These structs are the core of how signals are handled.
    * `sa_handler`: A simple function pointer for basic signal handling.
    * `sa_sigaction`: A more advanced function pointer that provides more information (signal number, `siginfo_t`, `ucontext_t`).
    * `sa_mask`:  A `sigset_t` (or `sigset64_t`) to block other signals while this handler is running.
    * `sa_flags`:  Flags to control the behavior of signal handling (e.g., `SA_RESTART`, `SA_SIGINFO`).
    * `sa_restorer`:  Less commonly used, historically for restoring the signal mask on return.

    The conditional compilation here highlights the ABI differences between 32-bit and 64-bit Android. The comments explicitly explain the 32-bit issue with the smaller `sigset_t` within the original `sigaction` struct and how `sigaction64` was introduced to rectify this.

**4. Connecting to Android Functionality:**

The next step is to link these definitions to concrete Android features:

* **Process Management:** Signals are fundamental to process management, allowing the kernel to notify processes of events (like termination requests, errors, I/O completion).
* **Inter-Process Communication (IPC):** Signals can be used for simple IPC between related processes.
* **Exception Handling:** Certain signals (like `SIGSEGV`) relate to memory errors and can be used for exception handling mechanisms.
* **Native Development (NDK):** NDK developers directly interact with these signal types and functions when handling asynchronous events or implementing custom signal handling.

**5. Explaining Libc Function Implementation (General Approach):**

The prompt asks about the implementation of libc functions related to signals. While this header file *defines types*, it doesn't *implement* the functions. The implementation resides in other parts of Bionic. However, we can explain *how* those functions likely work:

* **`signal()`:**  This is a higher-level interface that often maps to `sigaction()`. It involves setting the `sa_handler` and potentially some flags.
* **`sigaction()`:** This system call interacts directly with the kernel. The kernel stores the provided `sigaction` structure for the specified signal and process.
* **`sigprocmask()`:** This function modifies the process's signal mask, controlled by the `sa_mask` in `sigaction`.
* **`raise()`/`kill()`:**  These functions trigger the sending of a signal. The kernel then looks up the registered handler (if any) and executes it.

**6. Dynamic Linker and SO Layout:**

The prompt also asks about the dynamic linker. While this header file doesn't *directly* involve the dynamic linker, signals can interact with it:

* **Lazy Binding:**  Signals might interrupt the lazy binding process.
* **Library Unloading:** Signals might arrive during library unloading.

A simplified SO layout example helps visualize memory regions. The linking process involves resolving symbols between different SOs and the main executable, which can be affected by signal handling.

**7. Potential Errors and Frida Hooking:**

Identifying common programming errors is crucial for practical advice. Examples like not using atomic operations in signal handlers or forgetting to restore the signal mask are common pitfalls.

Finally, the Frida example provides a concrete way to observe signal handling in action, hooking the `sigaction` function to see which signals are being registered and with what handlers.

**8. Structuring the Response:**

Organizing the information logically is key to a good answer. Using clear headings, bullet points, and code examples improves readability and understanding. The thought process followed the structure of the prompt itself, addressing each point systematically.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus too much on the definitions themselves.
* **Correction:**  Shift focus to the *purpose* and *usage* of these definitions within the Android system.
* **Initial thought:** Try to explain the exact assembly code of libc functions.
* **Correction:**  Focus on the high-level mechanisms and interactions with the kernel, as the detailed implementation is complex and outside the scope of analyzing this header file.
* **Initial thought:**  Overlook the significance of the conditional compilation.
* **Correction:** Emphasize the 32-bit/64-bit differences and the historical reasons for the separate `sigaction` and `sigaction64` structs in 32-bit Android.

By following these steps of reading, deconstruction, connecting to the system, and providing practical examples, we arrive at a comprehensive and informative answer.
这个文件 `bionic/libc/include/bits/signal_types.handroid` 是 Android Bionic C 库中定义与信号处理相关的核心数据类型和宏定义的文件。它的主要功能是为用户空间程序提供处理信号所需的结构和类型信息，以便程序能够正确地注册信号处理函数、屏蔽信号以及获取信号相关的信息。

**主要功能列举:**

1. **定义信号数量相关的宏:**
   - `_KERNEL__NSIG`: 定义内核支持的信号数量。
   - `_NSIG`: 定义用户空间可见的信号数量，通常比内核支持的数量多一个。
   - `NSIG`:  `_NSIG` 的别名，表示系统支持的信号总数。

2. **定义基本的信号处理相关类型:**
   - `sig_atomic_t`:  一种可以原子访问的整数类型，用于在信号处理函数中安全地访问和修改共享变量，避免竞态条件。
   - `sig_t` 和 `sighandler_t`:  都是函数指针类型，指向信号处理函数。 `sig_t` 是 BSD 兼容的定义，而 `sighandler_t` 是 glibc 兼容的定义，在 Bionic 中它们是相同的。

3. **定义信号集类型 `sigset64_t`:**
   - 用于表示一组信号。程序可以使用信号集来屏蔽某些信号，或者等待一组信号中的任意一个。
   - 在 64 位系统 (`__LP64__`) 上，直接使用内核定义的 `sigset_t`，其大小足够表示所有信号。
   - 在 32 位系统上，由于历史原因，早期 Android ABI 中使用的 `sigset_t` 太小，无法支持实时信号，因此定义了 `sigset64_t` 来提供足够的空间。

4. **定义信号动作结构体 `sigaction` 和 `sigaction64`:**
   - 用于定义当特定信号发生时应该采取的动作。
   - 包含信号处理函数指针 (`sa_handler` 或 `sa_sigaction`)、信号掩码 (`sa_mask`) 和标志 (`sa_flags`)。
   - 在 64 位系统上，`sigaction` 和 `sigaction64` 的定义相同。
   - 在 32 位系统上，由于 `sigset_t` 的问题，`sigaction` 和 `sigaction64` 的结构有所不同，`sigaction64` 使用 `sigset64_t` 来存储信号掩码。

**与 Android 功能的关系及举例:**

这个文件直接关系到 Android 系统中进程间通信和异常处理的核心机制——信号。

* **进程管理:** Android 系统使用信号来管理进程的生命周期，例如，`SIGKILL` 信号可以强制终止一个进程。
* **应用程序崩溃处理:** 当应用程序发生崩溃（例如，访问非法内存）时，系统会发送 `SIGSEGV` 信号。Android 的 `zygote` 进程和 `app_process` 进程会设置相应的信号处理函数来捕获这些信号，进行错误报告和进程清理。
* **NDK 开发:** 使用 NDK 进行 Native 开发的开发者可以直接使用这些数据类型和相关的 libc 函数来处理信号，例如，自定义信号处理函数来优雅地处理异步事件或者执行清理操作。
* **ANR (Application Not Responding):**  Android 系统会监控应用程序的 UI 线程是否阻塞。如果 UI 线程长时间无响应，系统会发送特定的信号，例如 `SIGQUIT`，来触发 ANR 报告。

**libc 函数的功能和实现 (概述):**

这个头文件定义了类型，而具体的 libc 函数的实现位于 Bionic 的其他源文件中，例如 `bionic/libc/bionic/signal.cpp` 和相关的系统调用封装代码中。以下是一些相关 libc 函数的功能概述：

* **`signal(int signum, sighandler_t handler)`:**
   - **功能:**  设置指定信号 `signum` 的处理方式。`handler` 可以是 `SIG_DFL` (默认处理), `SIG_IGN` (忽略信号) 或者一个用户定义的信号处理函数。
   - **实现:**  在内部，`signal` 函数通常会调用更底层的 `sigaction` 函数来实现。它会将 `handler` 转换为 `sigaction` 结构体中对应的成员。
   - **常见错误:**  在信号处理函数中使用不可重入的函数（例如 `printf`, `malloc` 等），可能导致死锁或未定义行为。

* **`sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`:**
   - **功能:**  更强大和灵活的设置信号处理方式的函数。可以设置更详细的信号处理行为，包括信号掩码和标志。
   - **实现:**  `sigaction` 是一个系统调用，它会陷入内核，内核会将用户提供的 `sigaction` 结构体保存到进程的信号处理表中。当信号发生时，内核会根据这个表中的信息来决定如何处理。
   - **常见错误:**  不理解 `sa_mask` 的作用，导致信号处理函数执行期间屏蔽了不应该屏蔽的信号。

* **`sigprocmask(int how, const sigset_t *set, sigset_t *oldset)`:**
   - **功能:**  用于检查或更改进程的信号屏蔽字 (signal mask)。信号屏蔽字决定了哪些信号会被阻塞，不会立即传递给进程。
   - **实现:**  `sigprocmask` 也是一个系统调用，它会修改内核中进程的信号屏蔽字。`how` 参数指定如何修改屏蔽字 (`SIG_BLOCK`, `SIG_UNBLOCK`, `SIG_SETMASK`)。
   - **常见错误:**  错误地阻塞了关键信号，导致程序无法响应外部事件或无法正常终止。

* **`raise(int sig)`:**
   - **功能:**  向当前进程发送一个信号。
   - **实现:**  `raise` 函数通常会调用 `kill(getpid(), sig)`，即向当前进程发送指定的信号。

* **`kill(pid_t pid, int sig)`:**
   - **功能:**  向指定的进程 `pid` 发送信号 `sig`。
   - **实现:**  `kill` 是一个系统调用，它允许一个进程向另一个进程发送信号（需要有足够的权限）。

**涉及 dynamic linker 的功能及 SO 布局样本和链接处理过程:**

虽然 `signal_types.handroid` 本身不直接涉及 dynamic linker 的代码，但信号处理与动态链接过程有一定的交互。例如：

* **信号处理函数可能位于动态链接的共享库 (SO) 中。**
* **动态链接器在加载和卸载 SO 时，可能会禁用或屏蔽某些信号，以保证操作的原子性。**
* **如果信号处理函数尝试访问尚未加载的 SO 中的符号，可能会导致问题。**

**SO 布局样本:**

假设我们有一个应用程序 `app`，它链接了一个共享库 `libfoo.so`。

```
内存布局：

[ 应用程序可执行文件 (app) ]
  - .text (代码段)
  - .data (已初始化数据段)
  - .bss (未初始化数据段)
  - ...
  - [ 动态链接器 (linker64/linker) ]  <-- 动态链接器会被加载到进程地址空间
    - ... (动态链接器的代码和数据)

[ 共享库 libfoo.so ]
  - .text (代码段)
  - .data (已初始化数据段)
  - .bss (未初始化数据段)
  - .plt (过程链接表)
  - .got (全局偏移表)
  - ...
```

**链接的处理过程 (简化):**

1. **加载 SO:** 当应用程序启动或者通过 `dlopen` 加载 SO 时，动态链接器会将 SO 加载到进程的地址空间。
2. **符号解析:** 动态链接器会解析 SO 中的符号引用，找到它们在其他 SO 或主程序中的定义地址。这涉及到查找 `.symtab` (符号表) 和 `.strtab` (字符串表)。
3. **重定位:** 动态链接器会修改 SO 中的某些指令和数据，使其指向正确的内存地址。这通常涉及到 `.rel.plt` 和 `.rel.dyn` 重定位段。
4. **`PLT` 和 `GOT`:**  对于延迟绑定的函数调用，会使用过程链接表 (`.plt`) 和全局偏移表 (`.got`)。初始时，`GOT` 表项指向 `PLT` 中的一段代码，当函数第一次被调用时，`PLT` 中的代码会调用动态链接器来解析函数地址，并将地址写入 `GOT` 表，后续调用将直接通过 `GOT` 表跳转。

**信号处理与动态链接的交互:**

* 如果一个信号在动态链接器执行关键操作时被传递，可能会导致不一致的状态。因此，动态链接器在某些关键时刻会屏蔽某些信号。
* 如果信号处理函数调用了位于尚未加载的 SO 中的函数，会导致错误。

**假设输入与输出 (逻辑推理):**

假设有一个程序注册了一个信号处理函数来处理 `SIGINT` (Ctrl+C)。

**输入:** 用户按下 Ctrl+C。

**输出:** 系统向程序发送 `SIGINT` 信号。程序的信号处理函数被调用。处理函数可以执行一些清理操作，然后优雅地退出程序，或者忽略该信号继续运行（不推荐）。

**用户或编程常见的使用错误举例:**

1. **在信号处理函数中使用非原子操作或不可重入函数:**
   ```c
   #include <stdio.h>
   #include <signal.h>
   #include <unistd.h>
   #include <stdlib.h>

   volatile int counter = 0;

   void sigint_handler(int signum) {
       // 错误：printf 不是可重入函数
       printf("收到信号 %d，计数器值：%d\n", signum, counter);
       counter++; // 错误：自增操作可能不是原子的
       exit(0);  // 相对安全，但最好使用 _exit
   }

   int main() {
       signal(SIGINT, sigint_handler);
       while (1) {
           sleep(1);
       }
       return 0;
   }
   ```
   **问题:** `printf` 不是可重入函数，如果在信号处理期间调用，可能会导致程序崩溃或输出混乱。`counter++` 在某些架构上可能不是原子操作，可能导致竞态条件。

2. **忘记恢复被屏蔽的信号:**
   ```c
   #include <stdio.h>
   #include <signal.h>
   #include <unistd.h>

   void handler(int signum) {
       printf("收到信号 %d\n", signum);
   }

   int main() {
       sigset_t mask, orig_mask;
       sigemptyset(&mask);
       sigaddset(&mask, SIGINT);

       // 屏蔽 SIGINT 信号
       if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0) {
           perror("sigprocmask");
           return 1;
       }

       printf("SIGINT 已被屏蔽...\n");
       sleep(5);

       // 错误：忘记恢复原始的信号掩码
       // if (sigprocmask(SIG_SETMASK, &orig_mask, NULL) < 0) {
       //     perror("sigprocmask");
       //     return 1;
       // }

       signal(SIGINT, handler); // 即使设置了处理函数，由于信号仍然被屏蔽，也不会执行

       printf("等待信号...\n");
       pause(); // 程序将永远阻塞，因为 SIGINT 被屏蔽了

       return 0;
   }
   ```
   **问题:**  程序屏蔽了 `SIGINT` 信号，但在之后没有恢复原始的信号掩码，导致即使设置了信号处理函数，`SIGINT` 信号也无法传递给进程。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

1. **Android Framework:**
   - 当一个应用崩溃时，`ActivityManagerService` 等系统服务会接收到内核发送的信号（例如 `SIGSEGV`）。
   - 这些服务会捕获信号，分析崩溃信息，并可能创建 ANR 对话框或记录崩溃日志。
   - Framework 层自身也可能使用信号进行进程间通信或管理。

2. **NDK:**
   - NDK 开发者可以直接调用 libc 的信号处理函数（如 `signal` 或 `sigaction`）来注册自定义的信号处理函数。
   - 当 Native 代码中发生错误（例如，空指针解引用）导致信号产生时，注册的信号处理函数会被调用。

**Frida Hook 示例:**

我们可以使用 Frida hook `sigaction` 函数来观察哪些信号被注册了，以及相应的处理函数是什么。

```javascript
// Frida 脚本示例

if (Process.platform === 'android') {
  const sigaction = Module.findExportByName('libc.so', 'sigaction');
  if (sigaction) {
    Interceptor.attach(sigaction, {
      onEnter: function (args) {
        const signum = args[0].toInt32();
        const act = ptr(args[1]);
        const oldact = ptr(args[2]);

        const sa_handler_ptr = act.readPointer();
        const sa_flags = act.add(Process.pointerSize).readInt();

        console.log(`[sigaction] 注册信号: ${signum}`);
        console.log(`[sigaction] sa_handler 地址: ${sa_handler_ptr}`);
        console.log(`[sigaction] sa_flags: ${sa_flags}`);

        // 可以进一步读取 sa_mask 等信息
      },
      onLeave: function (retval) {
        // console.log('[sigaction] 返回值:', retval);
      }
    });
  } else {
    console.log('找不到 sigaction 函数');
  }
} else {
  console.log('此脚本仅适用于 Android');
}
```

**步骤说明:**

1. **找到 `sigaction` 函数:**  使用 `Module.findExportByName('libc.so', 'sigaction')` 找到 `libc.so` 中 `sigaction` 函数的地址。
2. **附加 Interceptor:** 使用 `Interceptor.attach` 拦截对 `sigaction` 函数的调用。
3. **`onEnter` 回调:** 在函数调用之前执行，可以访问函数参数：
   - `args[0]`：信号编号 (`signum`).
   - `args[1]`：指向 `sigaction` 结构体的指针 (`act`).
   - `args[2]`：指向用于存储旧的 `sigaction` 结构体的指针 (`oldact`).
4. **读取结构体成员:** 通过指针操作读取 `sigaction` 结构体中的 `sa_handler` (信号处理函数指针) 和 `sa_flags`。根据 32 位或 64 位架构，可能需要调整偏移量来读取 `sa_mask`。
5. **打印信息:** 将读取到的信息打印到 Frida 控制台，可以观察到哪些信号被注册，以及对应的处理函数地址和标志。

通过这个 Frida 脚本，你可以在 Android 设备上运行你的目标进程，并观察到系统或应用程序注册的信号处理函数，从而理解信号处理机制的运作方式。你可以针对特定的 Android 组件或应用进行 hook，例如 hook `zygote` 进程启动时对关键信号的处理函数的注册，或者 hook 特定应用中 NDK 部分的信号处理。

### 提示词
```
这是目录为bionic/libc/include/bits/signal_types.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <sys/cdefs.h>

#include <limits.h>
#include <linux/signal.h>
#include <sys/types.h>

/* The arm and x86 kernel header files don't define _NSIG. */
#ifndef _KERNEL__NSIG
#define _KERNEL__NSIG 64
#endif

/* Userspace's NSIG is the kernel's _NSIG + 1. */
#define _NSIG (_KERNEL__NSIG + 1)
#define NSIG _NSIG

typedef int sig_atomic_t;

typedef __sighandler_t sig_t; /* BSD compatibility. */
typedef __sighandler_t sighandler_t; /* glibc compatibility. */

/* sigset_t is already large enough on LP64, but LP32's sigset_t
 * is just `unsigned long`.
 */
#if defined(__LP64__)
typedef sigset_t sigset64_t;
#else
typedef struct { unsigned long __bits[_KERNEL__NSIG/(8*sizeof(long))]; } sigset64_t;
#endif

/* The kernel's struct sigaction doesn't match the POSIX one. */

#if defined(__LP64__)

/* For 64-bit, that's the only problem, and we only need two structs
 * for source compatibility with 32-bit. */

#define __SIGACTION_BODY \
  int sa_flags; \
  union { \
    sighandler_t sa_handler; \
    void (*sa_sigaction)(int, struct siginfo*, void*); \
  }; \
  sigset_t sa_mask; \
  void (*sa_restorer)(void); \

struct sigaction { __SIGACTION_BODY };
struct sigaction64 { __SIGACTION_BODY };

#undef __SIGACTION_BODY

#else

/* For 32-bit, Android's ABIs used a too-small sigset_t that doesn't
 * support RT signals, so we need two different structs.
 */

/* The arm32 kernel headers also pollute the namespace with these,
 * but our header scrubber doesn't know how to remove #defines. */
#undef sa_handler
#undef sa_sigaction

struct sigaction {
  union {
    sighandler_t sa_handler;
    void (*sa_sigaction)(int, struct siginfo*, void*);
  };
  sigset_t sa_mask;
  int sa_flags;
  void (*sa_restorer)(void);
};

struct sigaction64 {
  union {
    sighandler_t sa_handler;
    void (*sa_sigaction)(int, struct siginfo*, void*);
  };
  int sa_flags;
  void (*sa_restorer)(void);
  sigset64_t sa_mask;
};

#endif
```