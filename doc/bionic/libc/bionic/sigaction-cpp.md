Response:
Let's break down the thought process for answering the request about `bionic/libc/bionic/sigaction.cpp`.

**1. Understanding the Core Request:**

The primary goal is to understand the functionality of the `sigaction.cpp` file within the Android Bionic library. The request specifically asks for:

* **Functionality:** What does this code do?
* **Android Relevance:** How does it relate to the broader Android system?
* **Detailed Implementation:**  How do the internal libc functions work?
* **Dynamic Linker Involvement:** If it relates to the dynamic linker, explain how.
* **Logic and Examples:** Provide hypothetical inputs and outputs.
* **Common Errors:**  Illustrate typical programmer mistakes.
* **Android Framework/NDK Flow:**  Trace the path from a high-level Android operation to this code.
* **Debugging:** Offer a Frida hook example.

**2. Initial Code Analysis (Skimming and Identifying Key Elements):**

The first step is to quickly scan the code to get a general idea of its purpose. I'd look for:

* **Includes:** `<signal.h>`, `<string.h>`, `<platform/bionic/reserved_signals.h>`. These suggest it's dealing with signal handling.
* **Function Declarations:** `sigaction`, `sigaction64`, `__rt_sigaction`, `__restore_rt`, `__restore`. This highlights the core functions being implemented and the underlying syscall.
* **Conditional Compilation (`#if defined(__LP64__)`):**  This immediately tells me there are differences between 32-bit and 64-bit architectures. I'll need to analyze both branches.
* **Structure Manipulation:**  The code works with `struct sigaction` and `struct sigaction64` (and their kernel counterparts). This means it's about setting up signal handlers.
* **Kernel Interaction:** The presence of `__rt_sigaction` strongly indicates a system call interface.
* **`SA_RESTORER` Flag:** The checks for `SA_RESTORER` and the assignment of `__restore_rt` and `__restore` are important and need further investigation.

**3. Deeper Dive into Functionality (Focusing on `sigaction`):**

The central function is `sigaction`. I'd analyze its behavior in both the 64-bit and 32-bit branches:

* **64-bit:**  The code copies data between the `bionic_new_action` and `kernel_new_action` structures. It checks for `SA_RESTORER` and sets it along with the `__restore_rt` function. It calls `__rt_sigaction`. The return value and copying back of old action are standard.
* **32-bit:**  This is more complex. It mentions the "broken" 32-bit ABI due to the size of `sigset_t`. It translates between `sigaction` and `sigaction64`. The `__sigaction64` function handles the core logic, similar to the 64-bit `sigaction`. The `__restore` function is also used here.

**4. Connecting to Android:**

The code is part of Bionic, Android's C library. Signal handling is fundamental to operating systems, including Android. I'd think about:

* **Process Management:**  Android uses signals for inter-process communication and managing process behavior (e.g., `SIGKILL`, `SIGTERM`).
* **Exception Handling:** Signals can be used to represent certain types of exceptions (e.g., `SIGSEGV`).
* **Framework Interaction:**  The Android Framework (written in Java/Kotlin) needs a way to handle events that translate to signals at the native level.
* **NDK Development:** NDK developers writing native code directly interact with these libc functions.

**5. Examining `__rt_sigaction`:**

This is clearly the system call. I'd state its purpose: interacting with the kernel to modify signal handlers.

**6. Investigating `__restore_rt` and `__restore`:**

These are crucial for understanding how the program resumes after a signal handler executes. I'd explain their role in restoring the execution context (registers, stack pointer, etc.). The difference between them (related to `SA_SIGINFO`) needs to be clarified.

**7. Dynamic Linker (Less Direct, but Important):**

While `sigaction.cpp` doesn't *directly* implement dynamic linking, the functions it calls (`__rt_sigaction`) are likely resolved through the dynamic linker. The `[vdso]` mention in the comments is a key connection point. I'd explain the role of `vdso` in providing kernel functionalities efficiently.

**8. Hypothetical Inputs and Outputs:**

Create a simple scenario where a signal handler is registered and then the old handler is retrieved. This makes the abstract concepts more concrete.

**9. Common Errors:**

Focus on typical mistakes developers make when using `sigaction`, such as not handling `SA_SIGINFO` correctly, forgetting to restore the old handler, or misunderstanding signal masks.

**10. Android Framework/NDK Flow:**

Trace a simple example: a button click in an Android app causing an event that eventually leads to a signal being raised and handled. Start from the Java/Kotlin layer and work down to the native code.

**11. Frida Hook Example:**

Provide a practical Frida script that intercepts the `sigaction` call, logs its arguments, and potentially modifies its behavior. This demonstrates a real-world debugging technique.

**12. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use code formatting to make the code snippets readable. Explain technical terms clearly.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe focus heavily on the assembly code of `__restore_rt`. **Correction:**  While interesting, it's probably too much detail for this general explanation. Focus on its purpose instead.
* **Initial thought:**  Overlook the 32-bit ABI differences. **Correction:**  The code explicitly mentions this, so it's a critical point to address.
* **Initial thought:** Not clearly explain the role of `vdso`. **Correction:** The comments provide a clue; research `vdso` and its significance in the signal handling context.
* **Initial thought:** Make the Frida example too complex. **Correction:**  Keep it simple and focused on demonstrating the hook.

By following these steps, breaking down the problem, and constantly refining the understanding, a comprehensive and accurate answer can be constructed. The key is to go from a high-level understanding to the specifics of the code and then back to the broader context of Android.
这个文件 `bionic/libc/bionic/sigaction.cpp` 是 Android Bionic C 库中关于信号处理的关键文件。它主要实现了 `sigaction` 和 `sigaction64` 这两个 POSIX 标准的 C 库函数，用于查询和修改进程的信号处理方式。

**它的主要功能:**

1. **提供 `sigaction` 和 `sigaction64` 函数的 Bionic 实现:** 这两个函数允许程序为特定的信号注册自定义的处理函数，以便在接收到该信号时执行特定的操作。
2. **处理 32 位和 64 位架构的差异:** 由于 32 位和 64 位架构下 `sigaction` 结构体的定义存在差异（主要是 `sigset_t` 的大小），这个文件包含针对两种架构的不同实现，以保证兼容性。
3. **与内核进行交互:**  `sigaction` 函数最终会通过系统调用 `__rt_sigaction` 与 Linux 内核进行交互，将用户空间的信号处理设置传递给内核。
4. **管理信号处理函数的恢复:**  代码中涉及 `__restore_rt` 和 `__restore` 函数，它们是信号处理函数执行完毕后，恢复程序执行状态的关键。在某些架构上，Bionic 需要显式地设置信号恢复函数。
5. **处理 ART 的 interposition:**  在 32 位架构上，特别提到了 ART (Android Runtime) 可能会对 `sigaction` 进行 interposition（拦截），代码中采取了措施来避免无限递归调用。

**与 Android 功能的关系及举例说明:**

信号处理是操作系统核心功能之一，对于 Android 这样的操作系统来说至关重要。以下是一些与 Android 功能相关的例子：

* **进程管理:** Android 系统使用信号来管理进程的生命周期。例如，当用户强制停止一个应用时，AMS (Activity Manager Service) 可能会向应用的进程发送 `SIGKILL` 或 `SIGTERM` 信号来终止它。`sigaction` 允许应用为这些信号注册清理函数，在进程终止前执行一些必要的清理工作（尽管对于 `SIGKILL` 来说，这是不太可能的）。
* **崩溃报告:** 当应用发生崩溃（例如，访问了无效内存地址），系统会发送 `SIGSEGV` 信号。应用可以通过 `sigaction` 注册一个信号处理函数来捕获这个信号，并进行一些处理，例如生成崩溃报告并上传。 हालांकि，Android 通常会有一个默认的崩溃处理机制，开发者通常不需要手动处理 `SIGSEGV`。
* **NDK 开发:** 使用 NDK 进行原生开发的开发者会直接使用 `sigaction` 等信号处理函数来控制其原生代码对信号的响应。例如，一个游戏引擎可能需要捕获 `SIGINT` 信号（通常由 Ctrl+C 产生）来优雅地退出。
* **后台服务:**  Android 的后台服务可能会使用信号进行进程间的通信或者处理特定的系统事件。
* **定时器:**  可以使用 `sigaction` 配合 `timer_create` 等函数来创建基于信号的定时器。

**详细解释 libc 函数的功能是如何实现的:**

1. **`sigaction(int signal, const struct sigaction* bionic_new_action, struct sigaction* bionic_old_action)` (针对 64 位架构):**
   - **参数:**
     - `signal`: 要操作的信号编号 (例如 `SIGINT`, `SIGSEGV`)。
     - `bionic_new_action`: 指向包含新的信号处理方式的 `struct sigaction` 结构体的指针。如果为 `nullptr`，则不修改信号处理方式。
     - `bionic_old_action`: 指向用于存储旧的信号处理方式的 `struct sigaction` 结构体的指针。如果为 `nullptr`，则不获取旧的信号处理方式。
   - **实现:**
     - 将用户空间提供的 `bionic_new_action` 结构体转换为内核使用的 `__kernel_sigaction` 结构体。这涉及到结构体成员的复制，例如 `sa_flags` (信号标志), `sa_handler` (信号处理函数指针), `sa_mask` (信号屏蔽字)。
     - **`sa_restorer` 的处理 (x86_64):**  对于 x86_64 架构，代码会检查 `SA_RESTORER` 标志。如果未设置，则会强制设置该标志，并将 `sa_restorer` 设置为 `__restore_rt` 函数的地址。这确保了信号处理函数返回后，程序能够正确恢复执行。对于其他架构（arm64），则依赖内核提供的默认 restorer。
     - 调用内核系统调用 `__rt_sigaction`，将新的信号处理方式传递给内核，并获取旧的信号处理方式（如果 `bionic_old_action` 不为 `nullptr`）。
     - 将内核返回的 `__kernel_sigaction` 结构体转换回用户空间的 `bionic_old_action` 结构体。
   - **逻辑推理:** 假设用户程序调用 `sigaction(SIGINT, &new_action, &old_action)`，其中 `new_action` 定义了一个新的处理 `SIGINT` 信号的函数。`sigaction` 函数会将 `new_action` 中的信息传递给内核，内核会将该进程处理 `SIGINT` 的方式更新为 `new_action` 中指定的方式。同时，如果 `old_action` 不是 `nullptr`，内核会将之前处理 `SIGINT` 的方式的信息存储到 `old_action` 指向的内存中。

2. **`sigaction(int signal, const struct sigaction* bionic_new, struct sigaction* bionic_old)` (针对 32 位架构):**
   - **实现:**
     - 由于 32 位 ABI 的 `struct sigaction` 中 `sigset_t` 的大小不足，该实现首先将用户空间的 `struct sigaction` 转换为 `struct sigaction64`。
     - 调用静态函数 `__sigaction64`，它与 64 位架构的 `sigaction` 类似，但直接操作 `struct sigaction64`。
     - 将 `__sigaction64` 返回的旧的 `struct sigaction64` 转换回用户空间的 `struct sigaction`。

3. **`__rt_sigaction(int, const struct __kernel_sigaction*, struct __kernel_sigaction*, size_t)`:**
   - 这是一个系统调用，直接与 Linux 内核交互。它的具体实现位于内核代码中。
   - **功能:** 接收信号编号和新的信号处理配置，更新内核中该进程的信号处理方式，并返回旧的信号处理配置。
   - **动态链接处理:**  `__rt_sigaction` 是一个外部符号，它的地址在程序运行时由动态链接器 `linker` 解析。
     - **so 布局样本:**
       ```
       libc.so (Bionic 的 C 库)
         |
         |--> sigaction.o (包含 sigaction 函数的编译单元)
         |     |
         |     |--> 引用外部符号 __rt_sigaction
         |
       /system/lib[64]/libc.so (实际的 Bionic 库文件)
         |
         |-->  __rt_sigaction (系统调用的包装函数或直接的 syscall 指令)
       ```
     - **链接处理过程:**
       1. 当程序启动时，动态链接器 `linker` 会加载程序依赖的共享库，例如 `libc.so`。
       2. 在加载 `libc.so` 时，链接器会遍历其符号表，找到 `sigaction` 函数的定义。
       3. 当执行到 `sigaction` 函数内部调用 `__rt_sigaction` 时，由于 `__rt_sigaction` 是一个外部符号，链接器需要在其他地方找到它的定义。
       4. 链接器会在内核提供的虚拟动态共享对象 `[vdso]` 或 `[vsyscall]` 中查找 `__rt_sigaction` 的地址。这些特殊区域包含了一些可以直接调用的内核函数，避免了陷入内核的开销。
       5. 找到 `__rt_sigaction` 的地址后，链接器会将其地址填入 `sigaction` 函数内部的相应位置，使得 `sigaction` 可以正确调用内核的系统调用。

4. **`__restore_rt(void)` 和 `__restore(void)`:**
   - 这两个函数是信号处理函数执行完毕后，用于恢复程序执行状态的关键。它们通常是用汇编语言实现的，因为需要直接操作处理器的寄存器和堆栈。
   - **`__restore_rt`:** 用于通过 `SA_SIGINFO` 标志注册的信号处理函数。这类处理函数会接收一个 `siginfo_t` 结构体，其中包含了关于信号的更详细信息。`__restore_rt` 负责恢复寄存器状态，包括栈指针，并返回到程序中断前的执行位置。
   - **`__restore`:** 用于传统的信号处理函数（没有 `SA_SIGINFO` 标志）。功能类似 `__restore_rt`，但可能略有不同，因为它不需要处理 `siginfo_t`。
   - **作用:** 当信号处理函数执行完毕后，控制权会转移到 `__restore_rt` 或 `__restore`。这些函数会恢复被信号中断的上下文（例如，程序计数器、寄存器等），使得程序可以从中断的地方继续执行。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

已在 `__rt_sigaction` 的解释中说明。

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个程序想要捕获 `SIGINT` 信号，并在接收到该信号时打印一条消息。

**假设输入:**

```c++
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

void sigint_handler(int signum) {
  printf("收到 SIGINT 信号！\n");
}

int main() {
  struct sigaction new_action, old_action;
  new_action.sa_handler = sigint_handler;
  sigemptyset(&new_action.sa_mask); // 不屏蔽其他信号
  new_action.sa_flags = 0;

  if (sigaction(SIGINT, &new_action, &old_action) == -1) {
    perror("sigaction");
    return 1;
  }

  printf("程序运行中，请按 Ctrl+C 发送 SIGINT 信号。\n");
  while (1) {
    sleep(1);
  }
  return 0;
}
```

**预期输出:**

1. 程序启动后，会打印 "程序运行中，请按 Ctrl+C 发送 SIGINT 信号。"
2. 当用户按下 Ctrl+C 时，会向程序发送 `SIGINT` 信号。
3. 由于程序通过 `sigaction` 注册了 `sigint_handler` 函数来处理 `SIGINT` 信号，所以会执行 `sigint_handler` 函数，打印 "收到 SIGINT 信号！"。
4. 之后，程序会继续执行 `while` 循环（除非在信号处理函数中调用 `exit` 或类似函数）。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **未正确初始化 `struct sigaction`:**  例如，忘记使用 `sigemptyset` 初始化 `sa_mask`，可能导致意外的信号被屏蔽。
   ```c++
   struct sigaction new_action;
   new_action.sa_handler = sigint_handler;
   // 忘记初始化 sa_mask，可能包含随机值
   new_action.sa_flags = 0;
   ```
2. **信号处理函数中执行不安全的操作:** 信号处理函数可能会在程序执行的任何时间被中断执行，因此在其中执行的操作必须是异步信号安全的。例如，在信号处理函数中调用 `malloc` 或 `printf` 等非异步信号安全的函数可能会导致死锁或其他问题。
   ```c++
   void sigint_handler(int signum) {
       printf("收到信号 %d\n", signum); // printf 不是异步信号安全的
       exit(0); // exit 是异步信号安全的
   }
   ```
3. **混淆 `sa_handler` 和 `sa_sigaction`:**  如果设置了 `SA_SIGINFO` 标志，则应该使用 `sa_sigaction` 成员来指定信号处理函数，该函数接收三个参数 (信号编号, `siginfo_t*`, `void*`)，而不是 `sa_handler` (只接收信号编号)。
   ```c++
   void sigint_handler(int signum) { /* ... */ }

   struct sigaction new_action;
   new_action.sa_flags = SA_SIGINFO;
   new_action.sa_handler = sigint_handler; // 错误：应该使用 sa_sigaction
   ```
4. **忘记恢复旧的信号处理方式:** 有时程序需要在完成特定操作后恢复之前的信号处理方式。忘记这样做可能会影响程序的后续行为或其他库的信号处理。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `sigaction` 的路径示例：处理应用崩溃**

1. **Java/Kotlin 代码崩溃:**  应用的主线程或某个工作线程中发生了未捕获的异常，例如 `NullPointerException`。
2. **ART 捕获异常:** Android Runtime (ART) 会捕获这个未捕获的 Java/Kotlin 异常。
3. **转换为信号:** ART 内部会将某些类型的异常转换为 POSIX 信号。例如，访问无效内存地址可能导致 `SIGSEGV` 信号。
4. **内核发送信号:** 内核会向发生异常的进程发送相应的信号。
5. **信号处理 (可能涉及 `sigaction`):**
   - **默认处理:** 如果应用没有通过 `sigaction` 注册自定义的 `SIGSEGV` 处理函数，内核会执行默认的处理方式，通常是终止进程并生成 core dump 文件（如果配置允许）。
   - **自定义处理 (通过 NDK):** 如果 NDK 开发者在原生代码中使用了 `sigaction` 为 `SIGSEGV` 注册了自定义的处理函数，那么在信号到达时，会执行该处理函数。

**NDK 到 `sigaction` 的路径示例：原生代码设置信号处理**

1. **NDK 代码调用 `sigaction`:**  原生 C/C++ 代码可以直接调用 `sigaction` 函数来设置信号处理程序。
   ```c++
   #include <signal.h>

   void my_signal_handler(int signum) {
       // 处理信号
   }

   int main() {
       struct sigaction sa;
       sa.sa_handler = my_signal_handler;
       sigemptyset(&sa.sa_mask);
       sa.sa_flags = 0;
       sigaction(SIGINT, &sa, nullptr);
       // ...
       return 0;
   }
   ```
2. **Bionic `sigaction` 执行:**  这个调用会进入 `bionic/libc/bionic/sigaction.cpp` 中实现的 `sigaction` 函数。
3. **系统调用:** `sigaction` 函数最终会调用 `__rt_sigaction` 系统调用，将信号处理设置传递给内核。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `sigaction` 函数的示例，用于查看哪些信号以及如何被处理：

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([package_name])
    session = device.attach(pid)
except frida.errors.FailedToStartProcessError as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "sigaction"), {
    onEnter: function(args) {
        const signum = args[0].toInt32();
        const new_action_ptr = args[1];
        const old_action_ptr = args[2];

        let new_action = {};
        if (new_action_ptr.isNull() === false) {
            new_action.sa_handler = new_action_ptr.readPointer();
            new_action.sa_mask = new_action_ptr.add(Process.pointerSize).readByteArray(Process.pointerSize * 16 / 8); // 假设 sigset_t 大小为 16 字节
            new_action.sa_flags = new_action_ptr.add(Process.pointerSize * (1 + 16/8)).readInt32();
            this.new_action = new_action;
        }

        let old_action = {};
        if (old_action_ptr.isNull() === false) {
            this.want_old_action = true;
        }

        send({
            type: "sigaction",
            signum: signum,
            new_action: new_action,
            want_old_action: this.want_old_action || false
        });
    },
    onLeave: function(retval) {
        if (this.want_old_action && this.new_action && retval.toInt32() === 0) {
            const old_action_ptr = arguments[2];
            let old_action = {};
            old_action.sa_handler = old_action_ptr.readPointer();
            old_action.sa_mask = old_action_ptr.add(Process.pointerSize).readByteArray(Process.pointerSize * 16 / 8);
            old_action.sa_flags = old_action_ptr.add(Process.pointerSize * (1 + 16/8)).readInt32();
            send({
                type: "sigaction_result",
                old_action: old_action
            });
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)
input() # 等待用户输入以保持脚本运行
```

**Frida Hook 示例说明:**

1. **连接到目标应用:**  脚本首先尝试连接到指定包名的应用进程。
2. **Hook `sigaction`:** 使用 `Interceptor.attach` 拦截 `libc.so` 中的 `sigaction` 函数。
3. **`onEnter`:** 在 `sigaction` 函数被调用时执行：
   - 获取信号编号 (`signum`) 和 `new_action` 和 `old_action` 结构体的指针。
   - 读取 `new_action` 结构体中的 `sa_handler`, `sa_mask`, `sa_flags` 等成员的值（需要注意不同架构下结构体的大小和布局）。
   - 发送包含信号信息的消息到 Frida host。
4. **`onLeave`:** 在 `sigaction` 函数返回后执行：
   - 如果 `old_action` 指针不为空，并且 `sigaction` 调用成功（返回 0），则读取 `old_action` 结构体的内容。
   - 发送包含旧信号处理信息的消息到 Frida host。
5. **输出:** Frida host 会打印出每次 `sigaction` 调用时的信号编号、新的信号处理方式以及旧的信号处理方式。

通过这个 Frida 脚本，你可以动态地观察 Android 应用在运行时如何设置信号处理程序，这对于调试和理解应用的信号处理行为非常有帮助。你需要根据目标应用的架构（32 位或 64 位）调整读取结构体成员的方式和大小。

### 提示词
```
这是目录为bionic/libc/bionic/sigaction.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <signal.h>
#include <string.h>

#include <platform/bionic/reserved_signals.h>

extern "C" void __restore_rt(void);
extern "C" void __restore(void);

#if defined(__LP64__)

extern "C" int __rt_sigaction(int, const struct __kernel_sigaction*, struct __kernel_sigaction*, size_t);

int sigaction(int signal, const struct sigaction* bionic_new_action, struct sigaction* bionic_old_action) {
  __kernel_sigaction kernel_new_action = {};
  if (bionic_new_action != nullptr) {
    kernel_new_action.sa_flags = bionic_new_action->sa_flags;
    kernel_new_action.sa_handler = bionic_new_action->sa_handler;
    // Don't filter signals here; if the caller asked for everything to be blocked, we should obey.
    kernel_new_action.sa_mask = bionic_new_action->sa_mask;
#if defined(__x86_64__)
    // riscv64 doesn't have sa_restorer. For arm64 and 32-bit x86, unwinding
    // works best if you just let the kernel supply the default restorer
    // from [vdso]. gdb doesn't care, but libgcc needs the nop that the
    // kernel includes before the actual code. (We could add that ourselves,
    // but why bother?)
    // TODO: why do arm32 and x86-64 need this to unwind through signal handlers?
    kernel_new_action.sa_restorer = bionic_new_action->sa_restorer;
    if (!(kernel_new_action.sa_flags & SA_RESTORER)) {
      kernel_new_action.sa_flags |= SA_RESTORER;
      kernel_new_action.sa_restorer = &__restore_rt;
    }
#endif
  }

  __kernel_sigaction kernel_old_action;
  int result = __rt_sigaction(signal,
                              (bionic_new_action != nullptr) ? &kernel_new_action : nullptr,
                              (bionic_old_action != nullptr) ? &kernel_old_action : nullptr,
                              sizeof(sigset_t));

  if (bionic_old_action != nullptr) {
    bionic_old_action->sa_flags = kernel_old_action.sa_flags;
    bionic_old_action->sa_handler = kernel_old_action.sa_handler;
    bionic_old_action->sa_mask = kernel_old_action.sa_mask;
#if defined(SA_RESTORER)
    bionic_old_action->sa_restorer = kernel_old_action.sa_restorer;
#endif
  }

  return result;
}

__strong_alias(sigaction64, sigaction);

#else

extern "C" int __rt_sigaction(int, const struct sigaction64*, struct sigaction64*, size_t);

// sigaction and sigaction64 get interposed in ART: ensure that we don't end up calling
//     sigchain sigaction -> bionic sigaction -> sigchain sigaction64 -> bionic sigaction64
// by extracting the implementation of sigaction64 to a static function.
static int __sigaction64(int signal, const struct sigaction64* bionic_new,
                         struct sigaction64* bionic_old) {
  struct sigaction64 kernel_new = {};
  if (bionic_new) {
    kernel_new = *bionic_new;
#if defined(__arm__)
    // (See sa_restorer comment in sigaction() above.)
    if (!(kernel_new.sa_flags & SA_RESTORER)) {
      kernel_new.sa_flags |= SA_RESTORER;
      kernel_new.sa_restorer = (kernel_new.sa_flags & SA_SIGINFO) ? &__restore_rt : &__restore;
    }
#endif
    // Don't filter signals here; if the caller asked for everything to be blocked, we should obey.
    kernel_new.sa_mask = kernel_new.sa_mask;
  }

  return __rt_sigaction(signal, bionic_new ? &kernel_new : nullptr, bionic_old,
                        sizeof(kernel_new.sa_mask));
}

int sigaction(int signal, const struct sigaction* bionic_new, struct sigaction* bionic_old) {
  // The 32-bit ABI is broken. struct sigaction includes a too-small sigset_t,
  // so we have to translate to struct sigaction64 first.
  struct sigaction64 kernel_new = {};
  if (bionic_new) {
    kernel_new.sa_flags = bionic_new->sa_flags;
    kernel_new.sa_handler = bionic_new->sa_handler;
#if defined(SA_RESTORER)
    kernel_new.sa_restorer = bionic_new->sa_restorer;
#endif
    // Don't filter signals here; if the caller asked for everything to be blocked, we should obey.
    memcpy(&kernel_new.sa_mask, &bionic_new->sa_mask, sizeof(bionic_new->sa_mask));
  }

  struct sigaction64 kernel_old;
  int result = __sigaction64(signal, bionic_new ? &kernel_new : nullptr, &kernel_old);
  if (bionic_old) {
    *bionic_old = {};
    bionic_old->sa_flags = kernel_old.sa_flags;
    bionic_old->sa_handler = kernel_old.sa_handler;
#if defined(SA_RESTORER)
    bionic_old->sa_restorer = kernel_old.sa_restorer;
#endif
    memcpy(&bionic_old->sa_mask, &kernel_old.sa_mask, sizeof(bionic_old->sa_mask));
  }
  return result;
}

int sigaction64(int signal, const struct sigaction64* bionic_new, struct sigaction64* bionic_old) {
  return __sigaction64(signal, bionic_new, bionic_old);
}

#endif
```