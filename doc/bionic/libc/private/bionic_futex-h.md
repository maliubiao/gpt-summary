Response:
Let's break down the thought process for answering the request about `bionic_futex.h`.

**1. Understanding the Core Request:**

The request asks for an analysis of a C header file (`bionic_futex.h`) within the context of Android's Bionic library. The key elements to address are:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it fit into the bigger Android picture?
* **Implementation Details:** How are the functions actually implemented?
* **Dynamic Linking:** What's the role concerning shared libraries?
* **Logic/Assumptions:**  Are there any implicit assumptions in the code?
* **Common Errors:** What mistakes do developers make when using this?
* **Android Flow:** How does execution reach these functions from Android framework/NDK?
* **Debugging:** How can we inspect this code in action (using Frida)?

**2. Initial Code Examination & Keyword Spotting:**

The first step is to read the code and look for important keywords and structures. Key observations include:

* **`#ifndef _BIONIC_FUTEX_H`:**  This is a standard header guard to prevent multiple inclusions.
* **`#include <errno.h>`, `#include <linux/futex.h>`:**  This tells us the file interacts with system-level error codes and the Linux futex mechanism. This immediately points to the core functionality: synchronization primitives.
* **`syscall(__NR_futex, ...)`:** This confirms the file is a direct interface to a Linux system call. `__NR_futex` is the syscall number.
* **`FUTEX_WAKE`, `FUTEX_WAIT`, `FUTEX_UNLOCK_PI`:** These are constants from `linux/futex.h`, defining specific futex operations. This further reinforces the synchronization purpose.
* **`shared` parameter:**  The presence of `shared` suggests this handles both inter-process and intra-process synchronization.
* **`timespec`:**  This indicates the possibility of timed waits.
* **`__LIBC_HIDDEN__`:**  This suggests these functions are internal to the C library and not meant for direct public use (though they *can* be used).
* **`inline __always_inline`:**  This means the `__futex` function will likely be directly embedded at the call site, optimizing performance.

**3. Deducing Functionality:**

Based on the keywords and included headers, the core functionality becomes clear:  This header file provides wrappers around the Linux `futex` system call, a fundamental building block for synchronization primitives. It allows threads (and processes) to wait for a condition and to signal that a condition has become true.

**4. Connecting to Android:**

The name "bionic" itself signifies Android's C library. Synchronization is critical for any multi-threaded or multi-process application, including the Android framework and apps. Examples immediately come to mind:

* **Java synchronization:** `synchronized` blocks and `java.util.concurrent` are often implemented using lower-level primitives like futexes.
* **Native code:**  NDK developers use mutexes, condition variables, etc., which often rely on futexes under the hood.
* **Android system services:** These services often involve multiple threads and processes that need to communicate and synchronize.

**5. Explaining Implementation:**

The key function is `__futex`. The explanation should cover:

* **System Call:** It's a direct system call.
* **Parameters:** Briefly explain the purpose of `ftx`, `op`, `value`, `timeout`, and `bitset`.
* **Error Handling:** Explain how `errno` is handled and the return values.
* **Inline Functions:** Emphasize the performance benefits.

The other functions (`__futex_wake`, `__futex_wait`, etc.) are just convenience wrappers around `__futex` with specific operation codes. Explain what each wrapper does in terms of waking or waiting.

**6. Addressing Dynamic Linking:**

While this specific header file *doesn't directly handle dynamic linking*, the *functions it defines are used by code that *is* part of shared libraries*. Therefore, the explanation should focus on:

* **Usage within shared libraries:**  Libraries like `libc.so` use these functions.
* **SO layout:**  Provide a basic example of a shared library's structure.
* **Linking process:** Briefly describe how the dynamic linker resolves symbols and loads libraries.

**7. Logical Reasoning and Assumptions:**

The primary assumption is that the caller knows what they are doing with the futex. The code itself doesn't enforce higher-level locking semantics. A simple example of a wait-wake sequence illustrates the basic logic.

**8. Common User Errors:**

This is important for practical understanding. Common mistakes include:

* **Incorrect initial value:** Leading to missed wake-ups.
* **Spurious wake-ups:**  The possibility of waking up without a signal.
* **Forgetting to wake:** Causing deadlocks.
* **Incorrect `shared` flag:**  Leading to issues with inter-process synchronization.

**9. Tracing the Execution Flow (Android Framework/NDK):**

This requires some understanding of Android's architecture. Start with high-level concepts and work down:

* **Java level:**  `synchronized` keyword, `java.util.concurrent` classes.
* **Native level (NDK):** `pthread_mutex_t`, `pthread_cond_t`.
* **Bionic libc:**  These pthread primitives are often implemented using futexes.
* **System call:** The eventual call to the `futex` system call.

The Frida example is crucial for demonstrating how to actually observe this in action. It should target a relevant function like `pthread_mutex_lock` and show how to trace down to the `__futex` call.

**10. Structuring the Answer:**

Finally, organize the information logically with clear headings and explanations. Use formatting (like bold text and code blocks) to improve readability. The goal is to be comprehensive yet easy to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus too much on the `syscall` details. **Correction:**  Shift focus to the higher-level concepts of synchronization and how futexes enable it.
* **Overlook the `shared` parameter.** **Correction:** Emphasize its role in inter-process vs. intra-process synchronization.
* **Not enough concrete examples.** **Correction:** Add examples of common errors and the Frida hook.
* **Vague explanation of the Android flow.** **Correction:**  Break down the flow from Java to native code and system calls.

By following these steps, including anticipating the user's needs and refining the explanation along the way, a comprehensive and helpful answer can be constructed.
好的，让我们来详细分析一下 `bionic/libc/private/bionic_futex.handroid` 这个头文件的功能及其在 Android 中的作用。

**功能概述:**

`bionic_futex.h` 文件定义了 Bionic C 库中用于操作 **futex** (fast userspace mutex) 的内联函数。 Futex 是 Linux 内核提供的一种轻量级的同步机制，允许用户空间的程序在没有竞争的情况下快速获取和释放锁，只有在出现竞争时才需要陷入内核。

这个头文件主要提供了以下功能：

1. **定义了与 futex 系统调用交互的内联函数:** 它封装了底层的 `syscall(__NR_futex, ...)` 调用，使其更容易在 Bionic C 库的其他部分使用。
2. **提供了常用的 futex 操作的便捷函数:** 例如 `__futex_wake` (唤醒等待的线程)、`__futex_wait` (等待某个条件成立)、`__futex_pi_unlock` (优先级继承解锁) 和 `__futex_pi_lock_ex` (优先级继承加锁)。
3. **区分了共享和私有的 futex 操作:**  通过 `shared` 参数来区分操作的是进程间共享的 futex 还是进程内的 futex。
4. **支持带超时的等待操作:** 允许指定等待的最长时间。

**与 Android 功能的关系及举例说明:**

Futex 是 Android 底层同步机制的关键组成部分。许多高级的同步原语，例如互斥锁 (mutex)、条件变量 (condition variable) 和读写锁 (read-write lock)，在 Bionic C 库中的实现都依赖于 futex。

**举例说明:**

* **Java 的 `synchronized` 关键字和 `java.util.concurrent` 包:**  虽然 Java 层面提供了高级的同步机制，但在 Android 的 Dalvik/ART 虚拟机中，这些机制的底层实现往往会使用 native 代码，而 native 代码中就可能使用到基于 futex 的同步原语。例如，当一个 Java 线程尝试进入一个 `synchronized` 代码块时，如果锁被其他线程持有，虚拟机会调用 native 代码进行阻塞，这个阻塞的过程可能就涉及到 futex 的 `FUTEX_WAIT` 操作。当持有锁的线程退出 `synchronized` 代码块时，它会调用 native 代码唤醒等待的线程，这可能涉及到 futex 的 `FUTEX_WAKE` 操作。
* **NDK 开发中的线程同步:**  使用 NDK 进行 Android native 开发时，开发者可以使用 `pthread` 库提供的线程同步原语，例如 `pthread_mutex_t` 和 `pthread_cond_t`。  Bionic C 库中 `pthread` 库的实现就大量使用了 futex。例如，`pthread_mutex_lock` 的实现可能会尝试原子地获取锁，如果获取失败，就会调用 `__futex_wait` 进入等待状态。`pthread_mutex_unlock` 则会调用 `__futex_wake` 唤醒等待该锁的线程。
* **Android 系统服务:** Android 的许多系统服务是多线程的，它们需要使用同步机制来保护共享资源，避免数据竞争。这些服务在 native 代码中可能会直接或间接地使用 futex。

**libc 函数的实现细节:**

让我们逐个解释 `bionic_futex.h` 中定义的 libc 函数的实现：

1. **`__futex(volatile void* ftx, int op, int value, const timespec* timeout, int bitset)`:**
   * **功能:** 这是所有其他 futex 操作的基础函数。它直接调用 Linux 的 `futex` 系统调用。
   * **实现:**
     * `ftx`: 指向用户空间的一个内存地址，这个地址会被用作 futex 的标识符。
     * `op`:  指定要执行的 futex 操作，例如 `FUTEX_WAIT`, `FUTEX_WAKE`, `FUTEX_LOCK_PI` 等，这些常量定义在 `<linux/futex.h>` 中。
     * `value`:  对于某些操作（例如 `FUTEX_WAIT`），表示期望 futex 指向的值。只有当 futex 的当前值与 `value` 相同时，才会进入等待状态。
     * `timeout`:  一个指向 `timespec` 结构的指针，用于指定等待的超时时间。如果为 `nullptr`，则表示无限期等待。
     * `bitset`:  用于 `FUTEX_WAIT_BITSET` 操作，允许等待多个 bitset 中的任意一个被设置。
     * `syscall(__NR_futex, ...)`:  实际执行系统调用，`__NR_futex` 是 futex 系统调用的编号。
     * **错误处理:**  Bionic 的实现中，系统调用的返回值如果是 -1，表示出错。此时，原始的 `errno` 会被保存，然后将返回值设置为 `-errno`（POSIX 风格的错误码）。在返回前，恢复原始的 `errno`，因为调用者（例如 `pthread` 函数）可能不想修改 `errno`。

2. **`__futex_wake(volatile void* ftx, int count)`:**
   * **功能:** 唤醒最多 `count` 个等待在 `ftx` 地址上的线程。
   * **实现:** 调用 `__futex`，并将 `op` 设置为 `FUTEX_WAKE`，`count` 作为 `value` 传递。

3. **`__futex_wake_ex(volatile void* ftx, bool shared, int count)`:**
   * **功能:** 唤醒最多 `count` 个等待在 `ftx` 地址上的线程，可以指定是唤醒共享的还是私有的 futex。
   * **实现:** 调用 `__futex`，`op` 根据 `shared` 的值设置为 `FUTEX_WAKE` 或 `FUTEX_WAKE_PRIVATE`。

4. **`__futex_wait(volatile void* ftx, int value, const timespec* timeout)`:**
   * **功能:** 等待 `ftx` 地址的值变为 `value`。
   * **实现:** 调用 `__futex`，并将 `op` 设置为 `FUTEX_WAIT`，`value` 作为 `value` 传递，`timeout` 也传递下去。

5. **`__futex_wait_ex(volatile void* ftx, bool shared, int value)`:**
   * **功能:** 等待 `ftx` 地址的值变为 `value`，可以指定是等待共享的还是私有的 futex。
   * **实现:** 调用 `__futex`，`op` 根据 `shared` 的值设置为 `FUTEX_WAIT_BITSET` 或 `FUTEX_WAIT_BITSET_PRIVATE`，并设置 `bitset` 为 `FUTEX_BITSET_MATCH_ANY`，这意味着等待任何 bit 的匹配。

6. **`__futex_wait_ex(volatile void* ftx, bool shared, int value, bool use_realtime_clock, const timespec* abs_timeout)`:**
   * **功能:** 这是另一个 `__futex_wait_ex` 的版本，允许指定是否使用实时时钟以及绝对超时时间。
   * **实现:**  由于该函数被标记为 `__LIBC_HIDDEN__`，其具体实现在其他源文件中。它最终会调用底层的 `futex` 系统调用，并根据 `use_realtime_clock` 的值来设置相应的标志（例如 `FUTEX_CLOCK_REALTIME`）。

7. **`__futex_pi_unlock(volatile void* ftx, bool shared)`:**
   * **功能:** 解锁一个优先级继承 (priority inheritance) futex。
   * **实现:** 调用 `__futex`，并将 `op` 设置为 `FUTEX_UNLOCK_PI` 或 `FUTEX_UNLOCK_PI_PRIVATE`，取决于 `shared` 的值。优先级继承是一种解决优先级反转问题的机制。

8. **`__futex_pi_lock_ex(volatile void* ftx, bool shared, bool use_realtime_clock, const timespec* abs_timeout)`:**
   * **功能:** 尝试获取一个优先级继承 futex 锁，可以指定是否使用实时时钟以及绝对超时时间。
   * **实现:**  同样被标记为 `__LIBC_HIDDEN__`，其具体实现在其他源文件中。它会调用底层的 `futex` 系统调用，并将 `op` 设置为 `FUTEX_LOCK_PI` 或 `FUTEX_LOCK_PI_PRIVATE`，并根据参数设置相应的标志。

**涉及 dynamic linker 的功能:**

`bionic_futex.h` 本身并不直接涉及 dynamic linker 的功能。它定义的是用于线程同步的底层原语。然而，这些 futex 函数会被 Bionic C 库中的其他部分使用，而 Bionic C 库是以共享库 (`libc.so`) 的形式存在的，所以 dynamic linker 在加载和链接 `libc.so` 时会涉及到这些符号。

**so 布局样本:**

一个典型的 `libc.so` 的布局可能如下：

```
libc.so:
  .text        # 代码段，包含 __futex 等函数的机器码
  .rodata      # 只读数据段，包含常量字符串等
  .data        # 可读写数据段，包含全局变量等
  .bss         # 未初始化数据段
  .symtab      # 符号表，包含 __futex 等符号的信息
  .strtab      # 字符串表，包含符号名等
  .dynsym      # 动态符号表
  .dynstr      # 动态字符串表
  .plt         # Procedure Linkage Table，用于延迟绑定
  .got         # Global Offset Table，用于访问全局数据
  ...
```

**链接的处理过程:**

1. **编译:** 当一个程序或共享库依赖于 `libc.so` 中的 futex 函数时，编译器会将对这些函数的调用记录下来，并在生成的目标文件中创建一个重定位条目。
2. **链接:**
   * **静态链接 (不常用):** 如果是静态链接，链接器会将 `libc.so` 的相关代码直接复制到最终的可执行文件中。
   * **动态链接 (常用):** 如果是动态链接，链接器会在可执行文件中创建一个指向 `libc.so` 中 futex 函数的引用。这个引用会通过 `.plt` 和 `.got` 来实现。
3. **加载:** 当 Android 系统加载可执行文件时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载所有依赖的共享库，包括 `libc.so`。
4. **符号解析:** dynamic linker 会根据可执行文件和共享库的符号表 (`.dynsym`) 和字符串表 (`.dynstr`)，找到 `__futex` 等符号在 `libc.so` 中的地址，并将这些地址填入可执行文件的 `.got` 表中。
5. **延迟绑定:** 为了提高启动速度，通常会使用延迟绑定。这意味着在程序第一次调用 `__futex` 时，才会通过 `.plt` 中的代码跳转到 dynamic linker，由 dynamic linker 真正解析符号并更新 `.got` 表。后续的调用将直接通过 `.got` 表跳转到 `__futex` 的实际地址。

**逻辑推理 (假设输入与输出):**

假设我们有如下简单的代码片段：

```c
#include <unistd.h>
#include <stdio.h>
#include "bionic_futex.h"

int main() {
  volatile int futex_var = 0;

  if (__futex_wait(&futex_var, 1, NULL) == 0) {
    printf("Futex wait returned successfully.\n");
  } else {
    perror("Futex wait failed");
  }

  return 0;
}
```

**假设输入:**  在程序运行前，`futex_var` 的值为 0。

**输出:**  程序会阻塞在 `__futex_wait` 调用上，因为期望的值是 1，而当前的值是 0。程序会一直等待，直到其他线程或进程将 `futex_var` 的值修改为 1 并调用 `__futex_wake` 唤醒它。如果没有其他线程唤醒，程序会一直阻塞。

**用户或编程常见的使用错误:**

1. **忘记初始化 futex 变量:**  Futex 变量需要根据同步的需求进行合适的初始化。例如，作为互斥锁使用时，初始值可能为 0 表示未锁定。
2. **错误的期望值:** 在 `__futex_wait` 中使用了错误的期望值，导致线程一直阻塞或无法正确唤醒。
3. **忘记唤醒等待的线程:**  持有锁的线程在释放锁后，必须调用 `__futex_wake` 来唤醒等待的线程，否则会导致死锁。
4. **竞争条件:** 在没有合适的保护措施下，多个线程同时修改 futex 变量可能导致未定义的行为。
5. **不匹配的共享/私有操作:**  如果一个进程创建了一个私有的 futex，而另一个进程尝试使用共享的 futex 操作访问它，会导致错误。
6. **超时时间设置不当:**  如果超时时间设置过短，可能会导致即使条件最终会满足，线程也因为超时而过早返回。

**Android framework 或 ndk 如何一步步到达这里:**

让我们以 `pthread_mutex_lock` 为例，说明 Android framework 或 NDK 如何一步步到达 `bionic_futex.h` 中的函数：

1. **Android Framework (Java):**  在 Java 代码中使用 `synchronized` 关键字或者 `java.util.concurrent` 包中的锁（例如 `ReentrantLock`）。
2. **ART/Dalvik 虚拟机 (Native):**  当 Java 代码执行到需要获取锁的地方时，虚拟机内部会调用 native 代码来实现锁的获取。例如，对于 `synchronized` 关键字，虚拟机可能会调用 `Object::MonitorEnter` 或类似的函数。
3. **Bionic libc (NDK):**  NDK 开发者可以直接使用 `pthread` 库进行线程同步。例如，调用 `pthread_mutex_lock(&mutex)`.
4. **`pthread_mutex_lock` 实现:**  `pthread_mutex_lock` 在 Bionic C 库中的实现通常会先尝试原子地获取锁（例如使用 CAS 操作）。如果获取失败，就会调用底层的 futex 函数，例如 `__futex_wait`，让当前线程进入等待状态。
5. **`__futex_wait`:**  最终调用 `bionic_futex.h` 中定义的 `__futex_wait` 内联函数。
6. **`__futex` 系统调用:** `__futex_wait` 函数内部会调用 `syscall(__NR_futex, ...)` 发起 futex 系统调用，将请求传递给 Linux 内核。
7. **Linux Kernel:**  内核处理 futex 系统调用，管理等待队列，并在条件满足时唤醒等待的线程。

**Frida hook 示例调试步骤:**

我们可以使用 Frida 来 hook `pthread_mutex_lock` 函数，并观察它如何最终调用 `__futex`。

```python
import frida
import sys

# 要 hook 的目标进程
package_name = "你的目标应用包名"

# Frida 脚本
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "pthread_mutex_lock"), {
  onEnter: function(args) {
    console.log("pthread_mutex_lock called!");
    var mutex_ptr = args[0];
    console.log("Mutex address:", mutex_ptr);

    // Hook __futex_wait
    Interceptor.attach(Module.findExportByName("libc.so", "__futex_wait"), {
      onEnter: function(futex_args) {
        console.log("  __futex_wait called!");
        console.log("    Futex address:", futex_args[0]);
        console.log("    Expected value:", futex_args[1]);
        // 可以进一步打印其他参数
      },
      onLeave: function(retval) {
        console.log("  __futex_wait returned:", retval);
      }
    });
  },
  onLeave: function(retval) {
    console.log("pthread_mutex_lock returned:", retval);
  }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()  # Keep the script running
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found.")
except Exception as e:
    print(e)
```

**使用步骤:**

1. **安装 Frida:** 确保你的电脑上安装了 Frida 和 frida-tools。
2. **连接 Android 设备:** 将你的 Android 设备通过 USB 连接到电脑，并确保 adb 连接正常。
3. **启动目标应用:** 运行你想调试的 Android 应用。
4. **运行 Frida 脚本:** 将上面的 Python 代码保存为 `.py` 文件，并将 `package_name` 替换为你的目标应用的包名，然后在终端中运行该脚本：`python your_script_name.py`。
5. **触发锁竞争:** 在你的应用中执行一些会触发锁竞争的操作，例如点击一个按钮，该操作内部会使用互斥锁。
6. **查看 Frida 输出:**  Frida 会打印出 `pthread_mutex_lock` 被调用以及其内部调用的 `__futex_wait` 的相关信息，包括 futex 的地址和期望值。

通过这个 Frida 脚本，你可以观察到 `pthread_mutex_lock` 如何间接地调用 `__futex_wait` 来实现线程同步。你可以进一步扩展这个脚本来 hook 其他 futex 函数，以更深入地了解其工作原理。

希望这个详细的解释能够帮助你理解 `bionic_futex.handroid` 的功能和在 Android 中的作用。

### 提示词
```
这是目录为bionic/libc/private/bionic_futex.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _BIONIC_FUTEX_H
#define _BIONIC_FUTEX_H

#include <errno.h>
#include <linux/futex.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/cdefs.h>
#include <sys/syscall.h>
#include <unistd.h>

struct timespec;

static inline __always_inline int __futex(volatile void* ftx, int op, int value,
                                          const timespec* timeout, int bitset) {
  // Our generated syscall assembler sets errno, but our callers (pthread functions) don't want to.
  int saved_errno = errno;
  int result = syscall(__NR_futex, ftx, op, value, timeout, NULL, bitset);
  if (__predict_false(result == -1)) {
    result = -errno;
    errno = saved_errno;
  }
  return result;
}

static inline int __futex_wake(volatile void* ftx, int count) {
  return __futex(ftx, FUTEX_WAKE, count, nullptr, 0);
}

static inline int __futex_wake_ex(volatile void* ftx, bool shared, int count) {
  return __futex(ftx, shared ? FUTEX_WAKE : FUTEX_WAKE_PRIVATE, count, nullptr, 0);
}

static inline int __futex_wait(volatile void* ftx, int value, const timespec* timeout) {
  return __futex(ftx, FUTEX_WAIT, value, timeout, 0);
}

static inline int __futex_wait_ex(volatile void* ftx, bool shared, int value) {
  return __futex(ftx, (shared ? FUTEX_WAIT_BITSET : FUTEX_WAIT_BITSET_PRIVATE), value, nullptr,
                 FUTEX_BITSET_MATCH_ANY);
}

__LIBC_HIDDEN__ int __futex_wait_ex(volatile void* ftx, bool shared, int value,
                                    bool use_realtime_clock, const timespec* abs_timeout);

static inline int __futex_pi_unlock(volatile void* ftx, bool shared) {
  return __futex(ftx, shared ? FUTEX_UNLOCK_PI : FUTEX_UNLOCK_PI_PRIVATE, 0, nullptr, 0);
}

__LIBC_HIDDEN__ int __futex_pi_lock_ex(volatile void* ftx, bool shared, bool use_realtime_clock,
                                       const timespec* abs_timeout);

#endif /* _BIONIC_FUTEX_H */
```