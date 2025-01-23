Response:
Let's break down the thought process for answering this complex question about `sigprocmask.cpp`.

**1. Understanding the Core Request:**

The fundamental request is to analyze the provided C++ source code for `sigprocmask.cpp` in Android's Bionic library. This means dissecting its functionality, its relationship to Android, its implementation details (especially the interaction with the kernel via `__rt_sigprocmask`), and potential usage scenarios, errors, and debugging approaches.

**2. Initial Code Examination:**

* **Includes:**  The first step is to identify the included header files: `<errno.h>`, `<signal.h>`, `<platform/bionic/reserved_signals.h>`, and `"private/SigSetConverter.h"`. These immediately hint at the core functionality: signal handling, error reporting, and likely some Android-specific signal management.
* **External Function:** The declaration `extern "C" int __rt_sigprocmask(int, const sigset64_t*, sigset64_t*, size_t);` is crucial. It tells us that the real work of `sigprocmask` is delegated to a lower-level system call or kernel function. The `__rt_` prefix is a common convention for these types of functions in Bionic.
* **`sigprocmask64`:** This function seems to be the primary implementation for 64-bit architectures. The `__attribute__((__noinline__))` is a compiler hint to prevent inlining, likely because libsigchain needs to intercept this specific function. The core logic here is validating the `how` argument and filtering reserved signals.
* **`sigprocmask`:**  The presence of two `sigprocmask` functions, one with `sigset64_t` and one with `sigset_t`, points to handling different architectures (LP64 vs. ILP32). The `#ifdef __LP64__` and `#else` blocks confirm this. The `__strong_alias` for LP64 indicates they are the same, while ILP32 uses `SigSetConverter` for compatibility.
* **`SigSetConverter`:** The inclusion of `SigSetConverter.h` and its usage in the ILP32 `sigprocmask` strongly suggest a conversion mechanism between different signal set representations.

**3. Deconstructing the Requirements:**

The prompt asks for several things, so it's important to address each one systematically:

* **Functionality:** What does `sigprocmask.cpp` *do*?
* **Android Relationship:** How does this fit into the broader Android ecosystem?
* **Implementation Details:** How are the functions implemented, particularly the `libc` functions?
* **Dynamic Linker:** Are there interactions with the dynamic linker? If so, provide examples.
* **Logic/Assumptions:** If there's any internal reasoning or filtering, describe it with examples.
* **Common Errors:** What mistakes do programmers often make when using these functions?
* **Android Framework/NDK Path:** How does a call originate from the application layer and reach this code?
* **Frida Hooking:** How can these functions be observed and debugged using Frida?

**4. Detailed Analysis and Answering Each Point:**

* **Functionality:**  The core function is to manipulate a thread's signal mask. This leads to explaining the different `how` options (SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK) and the purpose of the signal mask (controlling which signals a thread will receive).

* **Android Relationship:**  Think about how signal handling is crucial in Android:
    * **Inter-process communication (IPC):** Signals are a primitive IPC mechanism.
    * **Process management:**  The system uses signals to manage processes (e.g., SIGKILL).
    * **Exception handling:** Signals can be used to handle errors.
    * **`filter_reserved_signals`:**  This is a key Android-specific aspect. Explain why certain signals might be reserved by the system.

* **Implementation Details:**  Focus on:
    * The role of `__rt_sigprocmask` as the underlying system call. Emphasize the transition from user space to the kernel.
    * The purpose of `sigset64_t` and `sigset_t` and why the conversion is needed for ILP32. Explain that `SigSetConverter` bridges the gap.

* **Dynamic Linker:** While `sigprocmask.cpp` itself doesn't directly *call* dynamic linker functions, it's *part of* `libc.so`, which *is* loaded by the dynamic linker. Explain this indirect relationship. Provide a simplified `libc.so` layout and the linking process (finding symbols, relocation).

* **Logic/Assumptions:** The `filter_reserved_signals` function is the main piece of logic. Provide examples of reserved signals and how they might be filtered depending on the `how` argument.

* **Common Errors:**  Brainstorm common pitfalls:
    * Forgetting to restore the signal mask.
    * Incorrectly using `how` values.
    * Signal masking in multithreaded programs (race conditions).

* **Android Framework/NDK Path:** Trace the call flow from a high-level application action (e.g., native crash) down to the `sigprocmask` call. Illustrate the involvement of the Android Runtime (ART), NDK, and finally, Bionic.

* **Frida Hooking:**  Provide practical Frida code snippets to intercept both `sigprocmask` and `sigprocmask64`. Show how to log arguments and potentially modify behavior.

**5. Structuring the Answer:**

Organize the answer logically, using clear headings and subheadings for each requirement. Use bullet points, code blocks, and examples to make the information easier to understand. Start with a high-level overview and then delve into the details.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the dynamic linker interaction is more direct.
* **Correction:** Realized that `sigprocmask.cpp` itself doesn't call `dlopen` or similar functions. The interaction is through being *part* of the dynamically linked `libc.so`.
* **Initial thought:**  Focus heavily on the bit manipulation of signal sets.
* **Correction:** While important, the prompt asks for broader context. Balance the technical details with the Android-specific aspects and usage scenarios.
* **Ensuring Clarity:** Double-check that the explanation of `SigSetConverter` is clear, especially the need for it on ILP32.

By following this thought process, breaking down the problem, and iteratively refining the analysis, we can arrive at a comprehensive and accurate answer like the example provided in the initial prompt.
这是一个关于 Android Bionic 库中 `sigprocmask.cpp` 文件的详细分析。这个文件实现了 `sigprocmask` 及相关的函数，用于管理线程的信号掩码。

**`sigprocmask.cpp` 的功能**

`sigprocmask.cpp` 文件主要实现了以下功能：

1. **修改线程的信号掩码：** 信号掩码定义了线程阻塞（忽略）哪些信号。`sigprocmask` 函数允许程序修改当前线程的信号掩码。
2. **查询线程的当前信号掩码：**  `sigprocmask` 可以用于获取线程当前的信号掩码而不进行修改。
3. **兼容不同架构：**  针对不同的 CPU 架构（如 ARM 32 位和 64 位），提供了相应的实现，并使用 `SigSetConverter` 类来处理不同大小的信号集结构。
4. **过滤保留信号：**  通过 `filter_reserved_signals` 函数，它会过滤掉一些 Android 系统保留的信号，防止应用程序干扰系统的正常运行。

**与 Android 功能的关系及举例说明**

`sigprocmask` 是一个标准的 POSIX 函数，在所有符合 POSIX 标准的系统中都存在，包括 Android。它在 Android 中扮演着至关重要的角色，因为它涉及到进程和线程的信号处理，这对于以下 Android 功能至关重要：

* **进程间通信 (IPC):** 信号是一种基本的进程间通信机制。例如，一个进程可以使用 `kill()` 函数向另一个进程发送信号。接收进程可以使用 `sigprocmask` 来决定如何处理这些信号，例如阻塞某个信号直到稍后处理。
    * **例子:**  一个守护进程可能需要忽略 `SIGCHLD` 信号，直到它准备好处理子进程的退出状态。它会使用 `sigprocmask` 来阻塞 `SIGCHLD`，然后在适当的时候解除阻塞并处理。
* **进程管理:** Android 系统本身会使用信号来管理进程，例如发送 `SIGKILL` 来终止一个无响应的进程。应用程序可以通过 `sigprocmask` 来影响对某些系统信号的响应，但通常不建议这样做，因为它可能导致系统不稳定。
* **异常处理:**  虽然不常见，但信号也可以用于实现一些形式的异常处理。例如，`SIGSEGV` 信号表示段错误。应用程序可以使用信号处理函数来捕获这些信号，进行清理工作，或者记录错误信息。`sigprocmask` 可以用来临时阻塞某些可能干扰异常处理的信号。
* **Native Crash 处理:** 当 native 代码发生崩溃时，系统会发送特定的信号（如 `SIGSEGV`，`SIGABRT`）。Android 的 crash reporting 机制会捕获这些信号，生成 tombstone 文件，并将崩溃信息报告给系统。`sigprocmask` 在这个过程中可能被使用，以确保 crash handler 能够可靠地执行。

**每一个 libc 函数的功能是如何实现的**

`sigprocmask.cpp` 文件中实现了以下两个主要的 libc 函数：

1. **`sigprocmask64`:** 这是 64 位架构下的主要实现。
   * **功能:**  根据 `how` 参数（`SIG_BLOCK`, `SIG_UNBLOCK`, `SIG_SETMASK`）修改或查询当前线程的 64 位信号掩码。
   * **实现:**
     * **参数校验:** 首先检查 `new_set` 是否为空，如果不为空，则检查 `how` 参数的有效性。如果 `how` 无效，则设置 `errno` 为 `EINVAL` 并返回 -1。
     * **过滤保留信号:** 如果 `new_set` 不为空，则调用 `filter_reserved_signals(*new_set, how)` 函数来创建一个可变的信号集 `mutable_new_set`，其中排除了 Android 系统保留的信号。
     * **调用系统调用:**  最终，它调用了底层的系统调用 `__rt_sigprocmask` 来完成实际的信号掩码操作。`__rt_sigprocmask` 是一个在内核中实现的函数，负责修改或查询线程的信号掩码。
     * **参数传递:** 将 `how`，指向（可能经过过滤的）新信号集的指针 `mutable_new_set_ptr`，以及用于存储旧信号集的指针 `old_set` 和信号集的大小 `sizeof(*new_set)` 传递给 `__rt_sigprocmask`。
     * **返回值:** 返回 `__rt_sigprocmask` 的返回值，通常是 0 表示成功，-1 表示失败并设置了 `errno`。

2. **`sigprocmask`:** 这是 32 位架构下的实现，也是一个通用的别名。
   * **功能:** 与 `sigprocmask64` 类似，但处理的是 32 位的信号掩码结构 `sigset_t`。
   * **实现 (针对 32 位架构):**
     * **使用 `SigSetConverter`:** 由于 32 位和 64 位架构下信号集结构的大小可能不同，这里使用了 `SigSetConverter` 类来进行转换。
     * **构造转换器:** 创建 `SigSetConverter` 对象 `new_set` 和 `old_set`，分别用于处理新的和旧的信号集。如果传入的 `bionic_new_set` 或 `bionic_old_set` 不为空，则转换器会存储指向这些结构的指针。
     * **调用 `sigprocmask64`:**  关键在于，32 位的 `sigprocmask` 最终会调用 64 位的 `sigprocmask64`，将 32 位的信号集转换为 64 位的信号集进行处理。通过 `new_set.ptr` 和 `old_set.ptr` 获取 `SigSetConverter` 内部存储的 64 位信号集指针。
     * **转换结果 (如果需要):** 如果 `sigprocmask64` 调用成功 (`rc == 0`) 并且 `bionic_old_set` 不为空，则调用 `old_set.copy_out()` 将 64 位的结果信号集转换回 32 位并复制到 `bionic_old_set` 指向的内存。
     * **返回值:** 返回 `sigprocmask64` 的返回值。

**`filter_reserved_signals` 的功能 (虽然代码中未直接展示，但被调用)**

虽然 `filter_reserved_signals` 的具体实现没有在这个文件中，但可以推断其功能：

* **功能:** 接收一个信号集和一个操作类型 (`how`)，返回一个新的信号集，其中排除了 Android 系统保留的信号。
* **目的:**  防止应用程序阻塞或修改 Android 系统关键的信号，确保系统的稳定性和正常运行。例如，Android 系统可能会使用某些信号来管理进程或进行内部通信。
* **实现推测:**  它可能维护一个包含所有保留信号的列表或位掩码，并根据 `how` 的值进行相应的操作：
    * `SIG_BLOCK`:  如果 `how` 是 `SIG_BLOCK`，则将新信号集与保留信号集合的补集进行按位与运算，从而确保保留信号不会被阻塞。
    * `SIG_UNBLOCK`: 如果 `how` 是 `SIG_UNBLOCK`，则不会过滤，因为取消阻塞保留信号不会有问题。
    * `SIG_SETMASK`: 如果 `how` 是 `SIG_SETMASK`，则将新信号集与保留信号集合的补集进行按位与运算，确保保留信号始终不被阻塞。

**涉及 dynamic linker 的功能，so 布局样本，以及链接的处理过程**

`sigprocmask.cpp` 自身并没有直接涉及动态链接器的功能。然而，它编译生成的代码会被链接到 `libc.so` 库中，这个库会被动态链接器加载到进程的地址空间。

**`libc.so` 布局样本 (简化)**

```
libc.so:
  .text:
    _start:  // 进程的入口点 (由 linker 提供)
    sigprocmask:
    sigprocmask64:
    __rt_sigprocmask: // 系统调用的 wrapper
    // ... 其他 libc 函数的代码 ...
  .data:
    // ... 全局变量 ...
  .bss:
    // ... 未初始化的全局变量 ...
  .dynamic:
    // ... 动态链接信息 (例如，依赖的库，符号表位置) ...
  .symtab:
    // ... 符号表 (包含导出的符号，例如 sigprocmask) ...
  .strtab:
    // ... 字符串表 (用于存储符号名称等) ...
```

**链接的处理过程**

1. **编译:** `sigprocmask.cpp` 被编译器编译成目标文件 (`.o` 文件)。
2. **链接:**  链接器（在 Android 上通常是 `lld`）将 `sigprocmask.o` 和其他 libc 的目标文件链接在一起，生成共享库 `libc.so`。
3. **符号导出:**  在链接过程中，`sigprocmask` 和 `sigprocmask64` 等函数被标记为导出的符号，这意味着其他共享库或可执行文件可以调用这些函数。
4. **动态链接:** 当一个应用程序启动时，操作系统的加载器会加载可执行文件，并解析其依赖的共享库，其中就包括 `libc.so`。
5. **符号查找和重定位:** 动态链接器会查找应用程序中调用的 `sigprocmask` 等符号，并在 `libc.so` 的符号表中找到它们的地址。然后，它会修改应用程序的指令，将对这些符号的引用指向 `libc.so` 中相应的函数地址。这个过程称为重定位。
6. **`__rt_sigprocmask`:**  需要注意的是，`__rt_sigprocmask` 通常是一个由 Bionic 库提供的 wrapper 函数，它负责将用户空间的调用转换为内核空间的系统调用。这个函数的具体实现可能在架构相关的代码中。

**逻辑推理的假设输入与输出**

假设输入：

* `how = SIG_BLOCK`
* `new_set` (初始状态): 包含 `SIGINT` 和 `SIGQUIT`
* Android 保留信号: `SIGRTMIN`

输出：

* `mutable_new_set`: 包含 `SIGINT` 和 `SIGQUIT` (假设保留信号不包括 `SIGINT` 和 `SIGQUIT`)。如果保留信号包括 `SIGINT` 或 `SIGQUIT`，那么在 `mutable_new_set` 中这些信号将被移除，因为 `SIG_BLOCK` 操作意味着要阻塞这些信号，而保留信号不能被阻塞。
* 调用 `__rt_sigprocmask` 时，传递的 `new_set` 指针将指向 `mutable_new_set`。

假设输入：

* `how = SIG_SETMASK`
* `new_set` (初始状态): 包含 `SIGUSR1`
* Android 保留信号: `SIGRTMIN`

输出：

* `mutable_new_set`:  如果 `SIGUSR1` 不是保留信号，则包含 `SIGUSR1`。如果 `SIGUSR1` 是保留信号，则 `mutable_new_set` 将为空或不包含 `SIGUSR1`，因为 `SIG_SETMASK` 会直接设置信号掩码，保留信号不能被应用程序控制。通常，保留信号会被强制不阻塞。

**用户或编程常见的使用错误**

1. **忘记保存和恢复旧的信号掩码:**  在修改信号掩码后，如果忘记保存之前的状态并在操作完成后恢复，可能会导致意外的行为。例如，如果一个库修改了信号掩码但没有恢复，可能会影响调用该库的程序的信号处理。

   ```c++
   #include <signal.h>
   #include <stdio.h>

   int main() {
       sigset_t old_mask, new_mask;
       sigemptyset(&new_mask);
       sigaddset(&new_mask, SIGINT);

       // 错误：忘记保存 old_mask
       if (sigprocmask(SIG_BLOCK, &new_mask, NULL) == -1) {
           perror("sigprocmask");
           return 1;
       }

       // 执行一些需要阻塞 SIGINT 的操作
       printf("SIGINT is now blocked.\n");

       // 错误：忘记恢复 old_mask

       return 0;
   }
   ```

2. **在多线程程序中错误地使用信号掩码:** 信号掩码是每个线程的属性。在一个多线程程序中，如果在一个线程中修改了信号掩码，不会影响其他线程。错误地假设一个线程的信号掩码会影响所有线程是常见的错误。

3. **阻塞不应该阻塞的信号:**  错误地阻塞某些重要的信号（例如，用于进程管理的信号）可能导致程序行为异常或无法被正常终止。

4. **没有正确处理 `sigprocmask` 的返回值:** `sigprocmask` 在出错时会返回 -1 并设置 `errno`。没有检查返回值会导致忽略错误。

5. **与信号处理函数 (`signal` 或 `sigaction`) 混淆:**  `sigprocmask` 用于控制哪些信号被阻塞，而 `signal` 或 `sigaction` 用于设置信号的处理方式（例如，调用哪个函数来处理信号）。这两个概念是不同的。

**Android framework 或 ndk 是如何一步步的到达这里**

1. **NDK 开发:** 开发者使用 NDK 编写 C/C++ 代码，其中可能直接调用 `sigprocmask` 函数。

   ```c++
   #include <signal.h>
   #include <unistd.h>
   #include <stdio.h>

   int main() {
       sigset_t mask;
       sigemptyset(&mask);
       sigaddset(&mask, SIGUSR1);

       if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
           perror("sigprocmask");
           return 1;
       }

       printf("SIGUSR1 blocked. Sending signal in 5 seconds...\n");
       sleep(5);

       // ... 后续代码 ...

       return 0;
   }
   ```

2. **编译和链接:**  NDK 工具链将 C/C++ 代码编译成机器码，并链接到必要的库，包括 `libc.so`。`sigprocmask` 函数的符号会被解析到 `libc.so` 中的实现。

3. **应用程序启动:** 当 Android 系统启动包含上述 native 代码的应用程序时，动态链接器会加载 `libc.so` 到应用程序的进程空间。

4. **调用 `sigprocmask`:** 当应用程序执行到调用 `sigprocmask` 的代码时，实际上会跳转到 `libc.so` 中 `sigprocmask` 函数的实现。

5. **系统调用:**  `libc.so` 中的 `sigprocmask` 实现（即 `sigprocmask.cpp` 中的代码）最终会通过 `__rt_sigprocmask` 发起一个系统调用，进入 Linux 内核。

6. **内核处理:** Linux 内核接收到系统调用后，会修改当前线程的信号掩码。

**Frida hook 示例调试这些步骤**

可以使用 Frida 来 hook `sigprocmask` 函数，查看其参数和返回值，从而调试上述步骤。

```python
import frida
import sys

# 要 hook 的进程名称或 PID
package_name = "your.package.name"

# Frida script
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "sigprocmask"), {
    onEnter: function(args) {
        console.log("sigprocmask called!");
        console.log("  how:", args[0]);
        console.log("  new_set:", args[1]);
        if (args[1].isNull()) {
            console.log("  new_set is NULL");
        } else {
            var sigset = new NativePointer(args[1]);
            // 读取 sigset_t 的内容 (假设 32 位)
            console.log("  new_set content:", sigset.readU32());
        }
        console.log("  old_set:", args[2]);
    },
    onLeave: function(retval) {
        console.log("sigprocmask returned:", retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "sigprocmask64"), {
    onEnter: function(args) {
        console.log("sigprocmask64 called!");
        console.log("  how:", args[0]);
        console.log("  new_set:", args[1]);
        if (args[1].isNull()) {
            console.log("  new_set is NULL");
        } else {
            var sigset = new NativePointer(args[1]);
            // 读取 sigset64_t 的内容 (假设 64 位)
            console.log("  new_set content low:", sigset.readU32());
            console.log("  new_set content high:", sigset.add(4).readU32());
        }
        console.log("  old_set:", args[2]);
    },
    onLeave: function(retval) {
        console.log("sigprocmask64 returned:", retval);
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
except Exception as e:
    print(e)
```

**使用方法:**

1. 将上述 Python 代码保存为 `hook_sigprocmask.py`。
2. 将 `your.package.name` 替换为你要调试的 Android 应用程序的包名。
3. 确保你的 Android 设备已连接并通过 USB 调试模式启用。
4. 运行 Frida 服务在你的 Android 设备上。
5. 运行 `python hook_sigprocmask.py`。
6. 运行或操作你的 Android 应用程序，当应用程序调用 `sigprocmask` 或 `sigprocmask64` 时，Frida 会拦截调用并打印相关信息。

这个 Frida 脚本会 hook `libc.so` 中的 `sigprocmask` 和 `sigprocmask64` 函数，并在函数调用时打印出 `how` 参数、`new_set` 和 `old_set` 指针的值，以及函数的返回值。通过分析这些信息，你可以了解应用程序是如何使用 `sigprocmask` 来管理信号掩码的。

### 提示词
```
这是目录为bionic/libc/bionic/sigprocmask.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <signal.h>

#include <platform/bionic/reserved_signals.h>

#include "private/SigSetConverter.h"

extern "C" int __rt_sigprocmask(int, const sigset64_t*, sigset64_t*, size_t);

//
// These need to be kept separate from pthread_sigmask, sigblock, sigsetmask,
// sighold, and sigset because libsigchain only intercepts sigprocmask so we
// can't allow clang to decide to inline sigprocmask.
//

int sigprocmask64(int how,
                  const sigset64_t* new_set,
                  sigset64_t* old_set) __attribute__((__noinline__)) {
  // how is only checked for validity if new_set is provided.
  if (new_set && how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) {
    errno = EINVAL;
    return -1;
  }

  sigset64_t mutable_new_set;
  sigset64_t* mutable_new_set_ptr = nullptr;
  if (new_set) {
    mutable_new_set = filter_reserved_signals(*new_set, how);
    mutable_new_set_ptr = &mutable_new_set;
  }
  return __rt_sigprocmask(how, mutable_new_set_ptr, old_set, sizeof(*new_set));
}

#if defined(__LP64__)
// For LP64, `sigset64_t` and `sigset_t` are the same.
__strong_alias(sigprocmask, sigprocmask64);
#else
// ILP32 needs a shim.
int sigprocmask(int how,
                const sigset_t* bionic_new_set,
                sigset_t* bionic_old_set) __attribute__((__noinline__)) {
  SigSetConverter new_set{bionic_new_set};
  SigSetConverter old_set{bionic_old_set};
  int rc = sigprocmask64(how, new_set.ptr, old_set.ptr);
  if (rc == 0 && bionic_old_set != nullptr) {
    old_set.copy_out();
  }
  return rc;
}
#endif
```