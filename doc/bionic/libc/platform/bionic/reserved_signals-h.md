Response:
Let's break down the thought process for answering this complex request about the `reserved_signals.handroid` file.

**1. Understanding the Core Request:**

The fundamental goal is to understand the purpose and functionality of this specific header file within Android's Bionic library. The request emphasizes its relationship to Android, detailed explanations, dynamic linking, error scenarios, and tracing its usage.

**2. Initial Analysis of the File:**

The first step is to read and understand the provided source code. Key observations include:

* **Copyright Header:** Indicates it's part of the Android Open Source Project (AOSP).
* **`#pragma once`:** Prevents multiple inclusions.
* **Includes:** `<sys/cdefs.h>` (standard C definitions), `<signal.h>` (signal handling), and `"macros.h"` (Bionic-specific macros). This immediately tells us it's related to signal handling.
* **Comments:** The comments explicitly state these are "Realtime signals reserved for internal use." This is the most crucial piece of information.
* **`#define` Macros:**  These define specific real-time signal numbers, associating them with internal Android components (POSIX timers, libbacktrace, debuggerd, etc.).
* **`filter_reserved_signals` Function:**  This function manipulates signal sets based on a `how` parameter (SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK). It selectively blocks or unblocks certain reserved signals.

**3. Deconstructing the Request and Planning the Answer Structure:**

The request has several explicit parts. To address them systematically, I planned the following structure:

* **文件功能 (File Functionality):**  Start with a high-level summary of the file's purpose.
* **与 Android 的关系及举例 (Relationship with Android and Examples):** Connect the defined signals to specific Android components and explain their usage.
* **libc 函数功能详解 (Detailed Explanation of libc Functions):** Focus on the `filter_reserved_signals` function and the standard signal-related functions it uses.
* **动态链接相关功能 (Dynamic Linking Functionality):** Explain the *implication* of these signals in the dynamic linking process, even if this specific file doesn't *directly* handle linking.
* **逻辑推理 (Logical Deduction):** Explore the purpose of the `filter_reserved_signals` function, specifically the blocking/unblocking logic.
* **用户或编程常见错误 (Common User/Programming Errors):** Discuss potential issues arising from misunderstanding or interfering with these internal signals.
* **Android Framework/NDK 到达此处的步骤 (Path from Framework/NDK):** Illustrate how a signal might propagate from the application level down to this Bionic component.
* **Frida Hook 示例 (Frida Hook Example):** Provide a practical example of how to observe the behavior of these signals.

**4. Addressing Each Part Systematically:**

* **功能:** The core function is to define and manage a set of real-time signals reserved for internal Android use.
* **Android 关系:**  Explain how each defined signal is used by a specific Android component. For example, `BIONIC_SIGNAL_DEBUGGER` is for `debuggerd`, allowing it to handle crashes and collect information.
* **libc 函数:** Detail the `filter_reserved_signals` function's logic. Explain `sigaddset64`, `sigdelset64`, and the purpose of blocking the POSIX timer signal while generally leaving others unblocked.
* **动态链接:** While this file doesn't contain dynamic linker code, explain that these signals can be used by the dynamic linker (e.g., for internal communication or error handling). Provide a simplified `so` layout example and a general overview of the linking process. *Initially, I considered going deeper into dynamic linking details, but decided to keep it focused on the relevance to these signals.*
* **逻辑推理:**  The main deduction is that blocking the POSIX timer signal is essential for proper timer functionality, while keeping others unblocked allows the respective internal components to function correctly. Consider the "what if" scenario of blocking a signal like `BIONIC_SIGNAL_DEBUGGER`.
* **常见错误:**  Emphasize the dangers of developers trying to use these reserved signals directly or accidentally blocking them, which could lead to unpredictable behavior or crashes.
* **Framework/NDK 路径:**  Start with a high-level action (e.g., a crash), and trace it down through the Android framework (ActivityManager, zygote) to Bionic and potentially the signal handling mechanisms.
* **Frida Hook:**  Provide a simple Frida script to intercept the `sigaction` system call and observe how these reserved signals are being handled.

**5. Refinement and Language:**

Throughout the process, I focused on clarity and accuracy. Using precise terminology and providing concrete examples is crucial. Since the request specified Chinese, I ensured the language was natural and grammatically correct. I also used formatting (like bolding and bullet points) to improve readability.

**Self-Correction/Improvements during the process:**

* **Initial thought:** I initially considered focusing more on the low-level details of signal delivery.
* **Correction:**  I realized the request was more about understanding the *purpose* and *context* of these reserved signals within Android, so I shifted the focus accordingly.
* **Dynamic Linking Depth:**  I initially considered providing more detailed information about the dynamic linker.
* **Correction:**  I realized the request was primarily about the signals themselves, not a full dynamic linking tutorial. I kept the dynamic linking explanation concise and focused on the relevance of signals.
* **Frida Hook Complexity:** I initially considered a more complex Frida script.
* **Correction:**  I opted for a simpler example to make it easier to understand the basic concept of hooking signal-related system calls.

By following this structured approach, considering potential misunderstandings, and refining the explanation iteratively, I was able to generate a comprehensive and informative answer to the complex request.
## 对 `bionic/libc/platform/bionic/reserved_signals.handroid` 文件的分析

这个文件 `reserved_signals.handroid` 定义了一组 **保留的实时信号**，这些信号被 Android 内部的各个组件使用，**不应该被应用程序直接使用或干扰**。  它位于 Bionic 库的平台特定部分，这表明这些信号的定义和使用可能与底层操作系统或架构有关。

**文件功能：**

1. **定义内部使用的实时信号:** 该文件通过 `#define` 预处理指令，为一系列实时信号赋予了有意义的名称。这些信号都是基于 `__SIGRTMIN` 宏定义的偏移量计算出来的。实时信号是 Linux 中允许应用程序自定义处理的信号，但 Android 保留了一部分用于内部目的。
2. **提供信号名称的符号常量:**  这使得在 Bionic 库的其他代码中引用这些信号时更加清晰易懂，避免了直接使用数字带来的混淆。例如，使用 `BIONIC_SIGNAL_DEBUGGER` 比直接使用数字 35 更具可读性。
3. **提供过滤保留信号的函数:**  `filter_reserved_signals` 函数允许根据操作类型（阻塞、设置掩码、取消阻塞）来修改给定的信号集。它硬编码了哪些保留信号应该被阻塞以及哪些应该保持未阻塞。

**与 Android 的关系及举例说明：**

这些保留信号在 Android 系统中扮演着关键的角色，用于内部组件之间的通信和控制。以下是每个信号及其用途的详细说明：

* **`BIONIC_SIGNAL_POSIX_TIMERS (__SIGRTMIN + 0)` (POSIX 计时器):**  用于实现 POSIX 标准的定时器功能，例如 `timer_create`、`timer_settime` 等。Android 框架和服务会使用这些计时器来执行周期性任务或在特定时间触发操作。
    * **举例:**  `AlarmManager` 服务可能会使用 POSIX 计时器来按时唤醒设备或启动应用程序。
* **`BIONIC_SIGNAL_BACKTRACE (__SIGRTMIN + 1)` (libbacktrace):**  `libbacktrace` 库用于在程序崩溃时生成堆栈回溯信息。当需要收集回溯时，可能会发送此信号。
    * **举例:**  当应用程序发生崩溃时，`debuggerd` 会接收到导致崩溃的信号，并可能使用 `libbacktrace` 库来生成崩溃时的函数调用堆栈，用于分析问题。
* **`BIONIC_SIGNAL_DEBUGGER (__SIGRTMIN + 3)` (debuggerd):**  `debuggerd` 是 Android 的调试守护进程，负责处理进程崩溃、ANR (Application Not Responding) 等事件。当进程发生异常需要调试时，会涉及到此信号。
    * **举例:**  当一个应用发生 Segmentation Fault 时，操作系统会发送一个 `SIGSEGV` 信号。`debuggerd` 可能会接收到这个信号，并可能发送 `BIONIC_SIGNAL_DEBUGGER` 或采取其他措施来启动调试流程或收集崩溃信息。
* **`BIONIC_SIGNAL_PROFILER (__SIGRTMIN + 4)` (平台性能分析器):**  用于触发平台级的性能分析工具，例如 `heapprofd` (堆内存分析器) 和 `traced_perf` (系统跟踪工具)。
    * **举例:**  开发者可以使用 `perfetto` 或 `systrace` 等工具来收集系统级别的性能数据。这些工具的底层机制可能涉及到发送 `BIONIC_SIGNAL_PROFILER` 信号来触发数据收集。
* **`BIONIC_SIGNAL_COVERAGE (__SIGRTMIN + 5)` (libprofile-extras):**  用于代码覆盖率分析。当需要收集代码执行覆盖率信息时，可能会使用此信号。
    * **举例:**  在进行代码测试或构建发布版本时，可以使用代码覆盖率工具来评估代码的测试程度。这些工具可能会利用 `BIONIC_SIGNAL_COVERAGE` 来标记已执行的代码块。
* **`BIONIC_SIGNAL_ART_PROFILER (__SIGRTMIN + 6)` (heapprofd ART 托管堆转储):**  用于触发 ART (Android Runtime) 虚拟机的托管堆转储，用于分析内存使用情况。特殊情况下，在 `debuggerd` 中，当进程因 MTE (Memory Tagging Extension) 错误崩溃时，会使用这个信号来通知 `init` 进程。
    * **举例:**  开发者可以使用 Android Studio 的内存分析器来检查应用程序的内存使用情况。在底层，这可能涉及到发送 `BIONIC_SIGNAL_ART_PROFILER` 信号来触发 ART 生成堆转储文件。
* **`BIONIC_SIGNAL_FDTRACK (__SIGRTMIN + 7)` (fdtrack):**  用于跟踪文件描述符的分配和释放情况，帮助检测文件描述符泄漏等问题。
    * **举例:**  Android 系统可以使用 `fdtrack` 机制来监控关键进程的文件描述符使用情况，及时发现潜在的资源泄漏问题。
* **`BIONIC_SIGNAL_RUN_ON_ALL_THREADS (__SIGRTMIN + 8)` (bionic/pthread_internal.cpp):**  用于在所有线程上执行特定操作，通常用于内部同步或状态更新。
    * **举例:**  Bionic 库内部可能需要在所有线程上执行一个同步操作，例如更新全局状态。它可以使用这个信号来触发所有线程执行相应的处理函数。
* **`BIONIC_ENABLE_MTE (__SIGRTMIN + 9)` (重新启用线程上的 MTE):**  用于在支持 MTE 的设备上重新启用特定线程的内存标记功能。
    * **举例:**  在某些情况下，可能需要临时禁用线程的 MTE 功能，然后可以使用此信号重新启用。

**libc 函数功能详解：**

唯一一个在这个文件中定义的 libc 函数是 `filter_reserved_signals`。

```c
static inline __always_inline sigset64_t filter_reserved_signals(sigset64_t sigset, int how) {
  int (*block)(sigset64_t*, int);
  int (*unblock)(sigset64_t*, int);
  switch (how) {
    case SIG_BLOCK:
      __BIONIC_FALLTHROUGH;
    case SIG_SETMASK:
      block = sigaddset64;
      unblock = sigdelset64;
      break;

    case SIG_UNBLOCK:
      block = sigdelset64;
      unblock = sigaddset64;
      break;
  }

  // The POSIX timer signal must be blocked.
  block(&sigset, __SIGRTMIN + 0);

  // Everything else must remain unblocked.
  unblock(&sigset, __SIGRTMIN + 1);
  unblock(&sigset, __SIGRTMIN + 2);
  unblock(&sigset, __SIGRTMIN + 3);
  unblock(&sigset, __SIGRTMIN + 4);
  unblock(&sigset, __SIGRTMIN + 5);
  unblock(&sigset, __SIGRTMIN + 6);
  unblock(&sigset, __SIGRTMIN + 7);
  unblock(&sigset, __SIGRTMIN + 8);
  unblock(&sigset, __SIGRTMIN + 9);
  return sigset;
}
```

* **功能:**  `filter_reserved_signals` 函数接收一个信号集 `sigset` 和一个操作类型 `how` 作为输入。它的目的是根据指定的 `how` 来修改 `sigset`，确保某些保留信号被阻塞或取消阻塞。
* **实现:**
    1. **确定操作类型:**  根据 `how` 的值（`SIG_BLOCK`, `SIG_SETMASK`, `SIG_UNBLOCK`）来选择用于阻塞和取消阻塞信号的函数。
       * `SIG_BLOCK` 和 `SIG_SETMASK` 都表示要设置信号掩码，所以都使用 `sigaddset64` 来添加信号到信号集，使用 `sigdelset64` 从信号集中移除信号。
       * `SIG_UNBLOCK` 表示要取消阻塞信号，所以使用 `sigdelset64` 从信号集中移除信号（取消阻塞），使用 `sigaddset64` 添加信号到信号集（意味着信号仍然可以被传递）。
    2. **处理 POSIX 计时器信号:**  **POSIX 计时器信号 (`__SIGRTMIN + 0`) 总是被阻塞**。这可能是为了确保计时器事件能够被正确处理，避免被意外的信号处理程序干扰。
    3. **处理其他保留信号:**  **除了 POSIX 计时器信号之外的所有其他定义的保留信号都被明确地取消阻塞**。这意味着这些信号可以被传递和处理，允许 Android 内部组件按需使用它们。
    4. **返回值:**  函数返回修改后的信号集。

**涉及 dynamic linker 的功能及处理过程：**

虽然这个文件本身没有直接涉及到 dynamic linker 的代码，但这些保留信号可能会被 dynamic linker 使用进行内部通信或错误处理。

**so 布局样本 (简化)：**

假设有一个名为 `libmylib.so` 的动态链接库：

```
libmylib.so:
    .text          (代码段)
    .data          (已初始化数据段)
    .bss           (未初始化数据段)
    .dynsym        (动态符号表)
    .dynstr        (动态字符串表)
    .rel.dyn       (动态重定位表)
    .rela.plt      (PLT 重定位表)
    ...
```

**链接的处理过程 (与保留信号的潜在关联):**

1. **加载 so 文件:** 当一个程序需要使用 `libmylib.so` 时，dynamic linker (例如 `/system/bin/linker64`) 会将其加载到内存中。
2. **符号解析和重定位:**  dynamic linker 会解析 `libmylib.so` 中引用的外部符号，并在其他已加载的共享库中找到这些符号的定义。然后，它会修改 `libmylib.so` 的代码和数据，使其指向正确的内存地址。
3. **启动 so 文件中的代码:**  一旦链接完成，程序就可以调用 `libmylib.so` 中定义的函数。

**保留信号的潜在使用场景：**

* **内部错误通知:**  如果 dynamic linker 在加载或链接过程中遇到严重的内部错误，它可能会发送一个保留信号给自身或其他系统组件，以便进行错误处理或记录。
* **与其他 Bionic 组件通信:** dynamic linker 可能会使用保留信号与其他 Bionic 库（例如负责信号处理的组件）进行通信。
* **性能分析和调试:**  性能分析工具或调试器可能通过发送保留信号来触发 dynamic linker 执行特定的操作，例如收集加载的库的信息。

**逻辑推理、假设输入与输出：**

假设有一个场景，Android 系统需要触发所有线程执行一个特定的清理操作。

* **假设输入:**  一个内部组件（例如 Bionic 的某个部分）调用一个内部函数，该函数会设置一个信号处理程序来响应 `BIONIC_SIGNAL_RUN_ON_ALL_THREADS`，并向所有线程发送这个信号。
* **逻辑推理:**  当接收到 `BIONIC_SIGNAL_RUN_ON_ALL_THREADS` 信号时，每个线程都会执行预先设置好的信号处理程序，完成清理操作。
* **预期输出:**  所有线程都执行了清理操作，系统的内部状态得到更新。

**用户或者编程常见的使用错误：**

**最大的错误是应用程序尝试直接使用或干扰这些保留信号。**  这些信号是 Android 内部使用的，应用程序不应该假设它们的行为或含义保持不变。

* **错误 1：尝试发送保留信号:**  应用程序不应该使用 `kill()` 或 `pthread_kill()` 等函数向进程或线程发送这些保留信号。这样做可能会导致不可预测的行为，甚至系统崩溃。
    ```c
    // 错误示例：尝试向自身发送 BIONIC_SIGNAL_DEBUGGER
    #include <signal.h>
    #include <sys/types.h>
    #include "bionic/reserved_signals.handroid"
    #include <unistd.h>

    int main() {
        kill(getpid(), BIONIC_SIGNAL_DEBUGGER); // 错误！
        return 0;
    }
    ```
* **错误 2：尝试捕获保留信号:**  应用程序不应该使用 `sigaction()` 或 `signal()` 函数来注册处理这些保留信号的处理程序。这样做可能会干扰 Android 内部组件的正常运行。
    ```c
    // 错误示例：尝试捕获 BIONIC_SIGNAL_PROFILER
    #include <signal.h>
    #include <stdio.h>
    #include "bionic/reserved_signals.handroid"

    void profiler_handler(int signum) {
        printf("Received profiler signal!\n");
    }

    int main() {
        struct sigaction sa;
        sa.sa_handler = profiler_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(BIONIC_SIGNAL_PROFILER, &sa, NULL); // 错误！

        // ... 其他代码
        return 0;
    }
    ```
* **错误 3：在信号掩码中意外阻塞保留信号（除了 `BIONIC_SIGNAL_POSIX_TIMERS`）：** 虽然 `filter_reserved_signals` 函数会确保大部分保留信号不被阻塞，但如果应用程序错误地设置了信号掩码，可能会意外地阻止某些内部信号的传递，导致系统功能异常。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**场景：应用程序崩溃**

1. **应用程序发生错误:**  假设一个 NDK 编写的应用程序由于访问了无效的内存地址而导致崩溃（Segmentation Fault）。操作系统会向该应用程序的进程发送 `SIGSEGV` 信号。
2. **内核处理信号:**  内核会查找进程的信号处理表，看是否有为 `SIGSEGV` 注册的处理程序。如果没有，或者默认处理方式是终止进程，内核会执行相应的操作。
3. **`debuggerd` 介入:**  Android 系统通常配置 `debuggerd` 来监听某些关键信号，包括 `SIGSEGV`。当发生崩溃时，内核可能会通知 `debuggerd`。
4. **`debuggerd` 分析:**  `debuggerd` 接收到崩溃信号后，会执行以下操作：
    * 收集进程的信息，例如 PID、UID、GID 等。
    * 可能使用 `ptrace` 系统调用来检查进程的状态。
    * **可能使用 `libbacktrace` 库，这可能会触发 `BIONIC_SIGNAL_BACKTRACE` 信号的内部使用。**
    * 如果配置为生成 tombstone 文件，`debuggerd` 会将崩溃信息写入到 `/data/tombstones` 目录下的文件中。
    * **在某些情况下，`debuggerd` 可能会发送 `BIONIC_SIGNAL_ART_PROFILER` 信号来通知 `init` 进程，特别是当崩溃是由 MTE 错误引起的。**
5. **init 进程处理 (针对 `BIONIC_SIGNAL_ART_PROFILER`):** 如果 `debuggerd` 发送了 `BIONIC_SIGNAL_ART_PROFILER`，`init` 进程会接收到这个信号，并根据信号的含义采取相应的措施，例如记录事件或进行其他系统级别的处理。

**Frida Hook 示例：**

我们可以使用 Frida Hook `sigaction` 系统调用来观察哪些信号被设置了处理程序，以及处理程序是什么。

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用程序包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "sigaction"), {
  onEnter: function(args) {
    var signum = args[0].toInt32();
    var act_ptr = args[1];
    var oldact_ptr = args[2];

    var signame = "UNKNOWN_SIGNAL";
    if (signum >= 1 && signum <= 64) {
      signame = "SIG" + Process.getSignalName(signum).toUpperCase().substring(3);
    }

    if (act_ptr.isNull() == false) {
      var sa_handler = act_ptr.readPointer();
      var sa_mask = act_ptr.add(Process.pointerSize).readByteArray(8); // sizeof(sigset_t) or sigset64_t
      var sa_flags = act_ptr.add(Process.pointerSize + 8).readInt32();

      send({
        type: "sigaction",
        event: "enter",
        signum: signum,
        signame: signame,
        sa_handler: sa_handler,
        sa_mask: hexdump(sa_mask, { ansi: true }),
        sa_flags: sa_flags
      });
    } else {
      send({
        type: "sigaction",
        event: "enter",
        signum: signum,
        signame: signame,
        act_ptr_is_null: true
      });
    }
  },
  onLeave: function(retval) {
    send({
      type: "sigaction",
      event: "leave",
      retval: retval.toInt32()
    });
  }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**运行上述 Frida 脚本，并让目标应用程序崩溃，你可能会在输出中看到类似这样的信息：**

```
[*] {
  "type": "sigaction",
  "event": "enter",
  "signum": 11,
  "signame": "SIGSEGV",
  "sa_handler": "0xf76b1488",
  "sa_mask": "\u0010\u0000\u0000\u0000\u0000\u0000\u0000\u0000",
  "sa_flags": 4
}
```

这表明应用程序为 `SIGSEGV` (信号编号 11) 设置了一个处理程序，处理程序的地址是 `0xf76b1488`，信号掩码和标志也一并显示出来。

**要观察 Bionic 内部如何使用保留信号，你可能需要 Hook 更底层的函数，例如 `pthread_kill` 或 `tgkill`，并过滤发送的信号是否是保留信号。**  或者，你可以在 `debuggerd` 进程中进行 Hook，观察它如何处理崩溃信号。

**总结:**

`reserved_signals.handroid` 文件定义了一组供 Android 内部使用的实时信号。理解这些信号及其用途有助于理解 Android 系统的底层工作原理，并避免在应用程序开发中犯一些常见的错误，例如尝试使用或干扰这些保留信号。通过 Frida 等工具，我们可以观察这些信号的传递和处理过程，从而更深入地了解 Android 系统的内部机制。

### 提示词
```
这是目录为bionic/libc/platform/bionic/reserved_signals.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <signal.h>

#include "macros.h"

// Realtime signals reserved for internal use:
//   32 (__SIGRTMIN + 0)        POSIX timers
//   33 (__SIGRTMIN + 1)        libbacktrace
//   34 (__SIGRTMIN + 2)        libcore
//   35 (__SIGRTMIN + 3)        debuggerd
//   36 (__SIGRTMIN + 4)        platform profilers (heapprofd, traced_perf)
//   37 (__SIGRTMIN + 5)        coverage (libprofile-extras)
//   38 (__SIGRTMIN + 6)        heapprofd ART managed heap dumps
//   39 (__SIGRTMIN + 7)        fdtrack
//   40 (__SIGRTMIN + 8)        android_run_on_all_threads (bionic/pthread_internal.cpp)
//   41 (__SIGRTMIN + 9)        re-enable MTE on thread

#define BIONIC_SIGNAL_POSIX_TIMERS (__SIGRTMIN + 0)
#define BIONIC_SIGNAL_BACKTRACE (__SIGRTMIN + 1)
#define BIONIC_SIGNAL_DEBUGGER (__SIGRTMIN + 3)
#define BIONIC_SIGNAL_PROFILER (__SIGRTMIN + 4)
// When used for the dumping a heap dump, BIONIC_SIGNAL_ART_PROFILER is always handled
// gracefully without crashing.
// In debuggerd, we crash the process with this signal to indicate to init that
// a process has been terminated by an MTEAERR SEGV. This works because there is
// no other reason a process could have terminated with this signal.
// This is to work around the limitation of that it is not possible to get the
// si_code that terminated a process.
#define BIONIC_SIGNAL_ART_PROFILER (__SIGRTMIN + 6)
#define BIONIC_SIGNAL_FDTRACK (__SIGRTMIN + 7)
#define BIONIC_SIGNAL_RUN_ON_ALL_THREADS (__SIGRTMIN + 8)
#define BIONIC_ENABLE_MTE (__SIGRTMIN + 9)

#define __SIGRT_RESERVED 10
static inline __always_inline sigset64_t filter_reserved_signals(sigset64_t sigset, int how) {
  int (*block)(sigset64_t*, int);
  int (*unblock)(sigset64_t*, int);
  switch (how) {
    case SIG_BLOCK:
      __BIONIC_FALLTHROUGH;
    case SIG_SETMASK:
      block = sigaddset64;
      unblock = sigdelset64;
      break;

    case SIG_UNBLOCK:
      block = sigdelset64;
      unblock = sigaddset64;
      break;
  }

  // The POSIX timer signal must be blocked.
  block(&sigset, __SIGRTMIN + 0);

  // Everything else must remain unblocked.
  unblock(&sigset, __SIGRTMIN + 1);
  unblock(&sigset, __SIGRTMIN + 2);
  unblock(&sigset, __SIGRTMIN + 3);
  unblock(&sigset, __SIGRTMIN + 4);
  unblock(&sigset, __SIGRTMIN + 5);
  unblock(&sigset, __SIGRTMIN + 6);
  unblock(&sigset, __SIGRTMIN + 7);
  unblock(&sigset, __SIGRTMIN + 8);
  unblock(&sigset, __SIGRTMIN + 9);
  return sigset;
}
```