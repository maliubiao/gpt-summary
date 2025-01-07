Response:
Let's break down the thought process for analyzing the `libc_init_static.cpp` file and addressing the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of this specific source file within the Android Bionic library. They're particularly interested in its role in static linking, its relationship to Android functionality, the implementation details of libc functions called within, how it interacts with the dynamic linker (even though it's for static linking), and how Android frameworks/NDK lead to its execution. They also want practical debugging examples using Frida.

**2. Initial Scan and Keyword Spotting:**

The first step is to quickly read through the code, looking for keywords and patterns:

* **`static`:**  This immediately signals that the file is about static linking and initialization.
* **`__libc_init`:** This is a crucial entry point for the C library.
* **Include headers:**  These hint at the functionalities used: `<android/api-level.h>`, `<elf.h>`, `<errno.h>`, `<malloc.h>`, `<signal.h>`, `<sys/auxv.h>`, `<sys/mman.h>`, and others related to threading (`pthread_internal.h`), system properties (`sys/system_properties.h`), and internal Bionic components.
* **Function names:**  Functions like `call_array`, `call_fini_array`, `call_ifunc_resolvers`, `apply_gnu_relro`, `layout_static_tls`, `__real_libc_init`  suggest the sequence of initialization steps.
* **Data structures:** `structors_array_t`, `KernelArgumentBlock`, `StaticTlsLayout`, `TlsModule` point to key data being manipulated.
* **`__attribute__((weak))`:** This is important for understanding how the file interacts with potentially missing symbols (like the ifunc resolver arrays).
* **Preprocessor directives:** `#if defined(__arm__)`, `#else` indicate architecture-specific handling.
* **`extern "C"`:**  Shows interaction with C code and the linker.
* **`exit(slingshot(...))`:** Highlights the transition to the user's `main` function.

**3. Deciphering the Flow:**

Based on the keywords and function names, a general flow emerges:

* **Early Initialization:** Setting up the Thread Control Block (TCB), global variables, and handling command-line arguments.
* **TLS Setup:**  Managing thread-local storage, even in static linking.
* **Function Pointer Calls:** Invoking functions from `.init_array`, `.fini_array`, and handling IFUNC resolvers.
* **Security Measures:** Applying RELRO (Relocation Read-Only) for security.
* **Final Initialization:**  Calling common libc initialization routines.
* **Transition to `main`:**  Finally executing the user's program.

**4. Addressing Specific User Questions (Iterative Process):**

Now, let's map the code back to the user's questions:

* **功能 (Functionality):**  Summarize the main steps observed in the flow. Emphasize the static linking aspect and contrast it with dynamic linking.
* **与 Android 功能的关系 (Relationship to Android):**  Connect the code to core Android functionalities: API level, process startup, thread management, security features, and the NDK. Provide examples like `android_get_application_target_sdk_version`.
* **libc 函数功能实现 (libc Function Implementation):** Focus on *which* libc functions are called *in this file*. No need to explain the entire implementation of `mprotect` or `signal`. Explain their purpose *within the context of this initialization*. For example, `mprotect` is used for security (RELRO). `signal` is used to ignore profiler signals in static binaries.
* **dynamic linker 功能 (Dynamic Linker Functionality):** This is tricky because it's a *static* initialization file. The key is to explain *why* dynamic linker concepts like IFUNC resolvers are still relevant (optimization, potential for shared library dependencies even in "static" builds sometimes). Explain the role of the `__rela_iplt_start`/`__rel_iplt_start` symbols and the process of resolving IFUNCs. Provide a simplified SO layout example to illustrate how these symbols are placed. Explain the linking process briefly.
* **逻辑推理 (Logical Deduction):**  For functions like `call_array` and `call_fini_array`, provide simple examples of how the arrays are processed. Assume simple input and show the output (function calls).
* **用户或编程常见的使用错误 (Common User/Programming Errors):** Think about what could go wrong in this static initialization context. Examples include incorrect linker scripts, missing dependencies (though less common with truly static linking), and issues with global constructors.
* **Android framework or ndk 如何到达这里 (How Android Framework/NDK Reaches Here):**  Explain the startup sequence from the kernel, through the zygote (for apps), or directly for native executables. Highlight the role of `crtbegin.o` and `crtend.o`. For the NDK, explain the compilation and linking process that leads to this code being included.
* **frida hook 示例 (Frida Hook Example):** Choose key functions like `__libc_init` or `call_array` to demonstrate how to intercept their execution and examine their arguments using Frida.

**5. Structuring the Answer:**

Organize the information logically, following the user's questions. Use clear headings and bullet points for readability.

**6. Refinement and Clarity:**

Review the answer for accuracy and clarity. Ensure that technical terms are explained or are reasonably well-known. Provide enough detail to be informative but avoid overwhelming the reader with unnecessary low-level specifics. Make sure the Chinese translation is accurate and natural.

**Self-Correction/Refinement Example During the Process:**

Initially, I might focus too much on the *general* functionality of the C library. Then, I'd realize the user wants to know specifically about *this file's* role. So, I'd refine the answer to emphasize the static initialization aspects and only discuss the libc functions called *within this file*. Similarly, with the dynamic linker, I'd initially explain the full dynamic linking process but then realize the focus should be on the IFUNC resolvers within this static context.
好的，让我们深入分析 `bionic/libc/bionic/libc_init_static.cpp` 这个文件。

**文件功能概述:**

`libc_init_static.cpp` 是 Android Bionic C 库中用于**静态链接可执行文件**初始化的关键文件。当一个程序被静态链接时，其所有依赖的库（包括 libc）的代码都被直接嵌入到可执行文件中。这个文件定义了静态链接的程序启动时，C 库初始化所执行的核心步骤。

**主要功能点:**

1. **早期线程初始化 (`__libc_init_main_thread_early`, `__libc_init_main_thread_late`, `__libc_init_main_thread_final`):**  为主线程设置必要的 TLS (Thread Local Storage，线程本地存储) 数据结构。这是每个线程都需要的一块私有内存区域。
2. **全局变量初始化 (`__libc_init_globals`):** 初始化 libc 内部使用的全局变量，例如程序名称。
3. **安全标志初始化 (`__libc_init_AT_SECURE`):**  检查环境变量，判断程序是否以安全模式运行。这会影响某些操作的权限。
4. **静态 TLS 布局 (`layout_static_tls`):**  为静态链接的程序布局 TLS 区域。即使是静态链接，也需要为线程局部变量分配空间。
5. **通用 libc 初始化 (`__libc_init_common`):** 调用一些通用的 libc 初始化函数，这些函数在静态和动态链接中都可能被使用。
6. **内存标签扩展 (MTE) 初始化 (`__libc_init_mte`, `__libc_init_mte_stack`, `__libc_init_mte_late`):** 如果硬件支持 MTE，则进行相关的初始化，以提供更强的内存安全保护。
7. **Scudo (内存分配器) 初始化 (`__libc_init_scudo`):** 初始化 Bionic 默认的内存分配器 Scudo。
8. **性能分析处理函数初始化 (`__libc_init_profiling_handlers`):**  对于静态链接的程序，通常会忽略性能分析信号。
9. **fork 处理函数初始化 (`__libc_init_fork_handler`):** 设置 `fork()` 系统调用后的处理逻辑。
10. **IFUNC (Indirect Function) 解析 (`call_ifunc_resolvers`):**  解析 IFUNC 符号。即使是静态链接，编译器也可能生成 IFUNC 来优化某些函数的调用，例如根据 CPU 特性选择最优实现。
11. **应用 GNU RELRO (`apply_gnu_relro`):**  将某些内存区域标记为只读，以提高安全性。
12. **调用构造函数 (`call_array`):** 执行 `.preinit_array` 和 `.init_array` 中指定的函数。这些数组通常包含全局对象的构造函数或需要在 `main` 函数执行前运行的代码。
13. **注册析构函数 (`__cxa_atexit`, `call_fini_array`):**  注册 `.fini_array` 中指定的析构函数，这些函数将在程序退出时按相反的顺序执行。
14. **设置目标 SDK 版本 (`android_get_application_target_sdk_version`, `android_set_application_target_sdk_version`):**  管理应用程序的目标 SDK 版本。
15. **进入用户代码 (`exit(slingshot(args.argc, args.argv, args.envp))`):**  最终调用用户提供的 `slingshot` 函数（通常是 `main` 函数），开始执行用户程序的逻辑。

**与 Android 功能的关系及举例:**

* **API Level (`<android/api-level.h>`, `android_get_application_target_sdk_version`, `android_set_application_target_sdk_version`):**  Android 需要知道应用程序的目标 SDK 版本，以便提供兼容性支持。`libc_init_static.cpp` 中定义的函数允许获取和设置这个版本。例如，Android Framework 可以通过这些函数来调整某些系统行为，以适应不同版本的应用程序。
* **进程启动:** `libc_init_static.cpp` 是 Android 进程启动的关键部分。当操作系统加载静态链接的可执行文件时，会首先执行 `_start` (或类似的入口点)，然后会调用 `__libc_init`。
* **线程管理 (TLS):**  Android 依赖于线程来实现并发。即使是静态链接的程序，也可能使用线程。`layout_static_tls` 确保每个线程都有自己的私有存储空间。
* **安全性 (RELRO, MTE):**  `apply_gnu_relro` 和 MTE 初始化增强了 Android 平台的安全性，防止某些类型的内存攻击。
* **NDK 开发:**  使用 NDK 进行静态链接的本地代码最终会走到这里的初始化流程。

**libc 函数的实现解释:**

由于篇幅限制，我们无法详细解释每一个 libc 函数的完整实现。但我们可以关注 `libc_init_static.cpp` 中**直接调用或涉及**的 libc 函数：

* **`mprotect(void *addr, size_t len, int prot)`:**  这是一个系统调用，用于修改内存区域的保护属性。在 `apply_gnu_relro` 中，它被用来将加载器重定位表所在的内存区域标记为只读 (`PROT_READ`)，防止被恶意修改。
    * **实现:**  `mprotect` 是一个内核提供的服务。当用户空间程序调用它时，会触发一个系统调用陷入内核，内核会验证请求的有效性（例如，调用者是否有权限修改该内存区域的属性），然后更新内存页表的权限信息。
* **`signal(int signum, sighandler_t handler)`:**  这是一个用于设置信号处理函数的系统调用。在 `__libc_init_profiling_handlers` 中，它被用来忽略 (`SIG_IGN`) 一些用于性能分析的信号。
    * **实现:**  `signal` 也是一个系统调用。当程序调用它时，内核会更新与该进程关联的信号处理表，将指定的信号与提供的处理函数关联起来。当该信号发生时，内核会中断程序的正常执行，转而执行注册的处理函数。
* **`exit(int status)`:**  这是一个用于正常终止进程的函数。在 `__real_libc_init` 的末尾，它被用来结束程序的执行，并将状态码返回给操作系统。
    * **实现:**  `exit` 函数会执行一系列清理操作，例如调用通过 `atexit` 注册的函数，刷新 I/O 缓冲区，然后通过 `_exit` 系统调用将控制权交还给操作系统。
* **`__cxa_atexit(void (*func)(void *), void *arg, void *dso_handle)`:**  这是一个 C++ 运行时库提供的函数，用于注册在程序退出时需要调用的函数（析构函数）。`call_fini_array` 函数通过它来注册 `.fini_array` 中的析构函数。
    * **实现:**  `__cxa_atexit` 通常会将要调用的函数指针和参数存储在一个链表中。当 `exit` 被调用时，它会遍历这个链表，并按注册顺序的相反顺序调用这些函数。
* **`getauxval(unsigned long type)`:**  这是一个用于获取辅助向量 (auxiliary vector) 中特定类型值的系统调用。辅助向量包含了操作系统传递给进程的一些启动信息，例如程序头表的地址 (`AT_PHDR`) 和大小 (`AT_PHNUM`)。
    * **实现:**  当操作系统加载程序时，会将辅助向量的信息放在进程的堆栈中。`getauxval` 函数会直接从内存中读取这些信息。

**涉及 dynamic linker 的功能:**

即使是静态链接，也可能涉及到动态链接器的一些概念，特别是在处理 IFUNC 时。

* **IFUNC (Indirect Function):**  IFUNC 允许在运行时根据 CPU 的特性或其他条件来选择函数的具体实现。编译器会生成一个解析器函数，动态链接器会在程序启动时调用这个解析器，解析器会返回最终要调用的函数地址。

**SO 布局样本 (假设存在 IFUNC):**

由于是静态链接，通常不会有单独的 `.so` 文件。但为了说明 IFUNC 的概念，我们可以想象一个静态链接的可执行文件内部的布局，其中包含了 IFUNC 相关的数据：

```
.text:
    ...
    callq  resolve_my_ifunc  ; 调用 IFUNC 解析器
    ...
    jmp    *my_ifunc_address  ; 跳转到解析后的函数地址

.rela.iplt:  ; RELA 表（现代架构）或 .rel.iplt（旧架构）
    offset to my_ifunc_address:  ; 需要被重定位的地址
        r_offset:  地址 `my_ifunc_address` 在内存中的偏移
        r_info:    包含符号信息和重定位类型
        r_addend:  解析器函数的地址 `resolve_my_ifunc`

.symtab:
    ...
    my_ifunc:  类型为 IFUNC，指向 `resolve_my_ifunc`
    ...

.dynsym:
    ... (可能包含 IFUNC 符号，取决于链接器行为) ...
```

**链接的处理过程 (针对 IFUNC):**

1. **编译:** 编译器遇到需要使用 IFUNC 的函数调用时，会生成一个对解析器函数的调用，并将最终函数地址的占位符放在代码中。
2. **链接:** 链接器会收集所有需要 IFUNC 解析的条目，并将相关信息添加到 `.rela.iplt` (或 `.rel.iplt`) 表中。`r_addend` 字段会存储解析器函数的地址。
3. **加载:** 操作系统加载静态链接的可执行文件。
4. **初始化:** 在 `libc_init_static.cpp` 的 `call_ifunc_resolvers` 函数中，代码会遍历 `.rela.iplt` (或 `.rel.iplt`) 表。
5. **解析:** 对于每个 IFUNC 条目，代码会：
    * 获取解析器函数的地址 (`r->r_addend` 或直接从偏移量获取）。
    * 调用 `__bionic_call_ifunc_resolver`，它会执行解析器函数。
    * 解析器函数会根据条件选择合适的函数实现，并返回该实现的地址。
    * 将返回的地址写入到之前占位符的位置 (`*offset = ...`)。
6. **后续调用:** 当程序后续调用该函数时，会直接跳转到解析后得到的实际函数地址。

**逻辑推理 (假设输入与输出):**

考虑 `call_array` 函数。

**假设输入:**

* `list`: 指向一个包含两个函数指针的数组: `{func1, func2}`
* `count`: 2
* `argc`, `argv`, `envp`:  程序的命令行参数和环境变量。

**输出:**

* 先调用 `func1(argc, argv, envp)`
* 然后调用 `func2(argc, argv, envp)`

**假设输入:**

* `structors->fini_array`: 指向一个包含两个函数指针的数组: `{fini_func1, fini_func2}`
* `structors->fini_array_count`: 2

**输出 (在 `call_fini_array` 中):**

* 先调用 `fini_func2()`
* 然后调用 `fini_func1()` (注意是逆序调用)

**用户或编程常见的使用错误:**

* **静态链接库的顺序问题:**  如果静态链接的库之间存在依赖关系，链接顺序很重要。如果顺序不当，可能导致符号未定义错误。
* **全局构造函数的副作用:**  `.init_array` 中的函数（通常是全局对象的构造函数）会在 `main` 函数之前执行。如果这些构造函数执行了耗时的操作或者依赖于尚未初始化的状态，可能导致程序启动缓慢或崩溃。
* **忘记处理静态链接的依赖:**  有时开发者可能期望某些库像动态链接一样在运行时加载，但静态链接时需要确保所有依赖都正确包含在最终的可执行文件中。
* **过度使用全局变量:**  静态链接会将所有代码和数据都放在一个地址空间中，过度使用全局变量可能导致命名冲突或难以管理状态。

**Android Framework 或 NDK 如何到达这里:**

**Android Framework:**

1. **Zygote 进程:** 大部分 Android 应用程序进程都是由 Zygote 进程 fork 出来的。Zygote 进程本身是一个启动时就链接了大部分常用库的进程。
2. **应用启动请求:** 当用户启动一个应用时，Activity Manager Service (AMS) 会向 Zygote 请求创建一个新的进程。
3. **Fork 和初始化:** Zygote 通过 `fork()` 系统调用创建一个新的进程。新进程会继承 Zygote 的内存布局，包括已经加载的库。
4. **`app_process`:**  对于 Java 应用程序，新进程通常会执行 `app_process` 可执行文件。`app_process` 是一个 native 程序，它的 `main` 函数会调用到 `__libc_init`。
5. **静态链接的情况 (较少见):**  虽然 Android 应用通常是动态链接的，但如果某个特定的 native 组件是静态链接的，那么它的初始化流程会直接走到 `libc_init_static.cpp`。

**NDK (Native Development Kit):**

1. **编译和链接:** 使用 NDK 构建 native 代码时，开发者可以选择静态链接某些库。
2. **生成可执行文件或共享库:** 如果构建的是一个独立的可执行文件，链接器会将 libc (以及其他静态链接的库) 的代码合并到最终的可执行文件中。
3. **执行:** 当这个静态链接的可执行文件被执行时，操作系统会加载它，并从入口点开始执行，最终会调用到 `__libc_init`。
4. **作为共享库的一部分 (更常见):**  更常见的情况是，NDK 代码被编译成共享库 (`.so`)，然后被 Java 代码通过 JNI (Java Native Interface) 调用。即使如此，如果这个共享库内部包含了静态链接的代码，`libc_init_static.cpp` 中的某些初始化逻辑仍然会被执行，尽管其入口点可能不是 `__libc_init`，而是共享库的构造函数。

**Frida Hook 示例:**

假设我们想 hook `call_array` 函数，查看它调用了哪些初始化函数。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['name'], message['payload']['args']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <target_process>".format(__file__))
        sys.exit(1)

    target_process = sys.argv[1]

    try:
        session = frida.attach(target_process)
    except frida.ProcessNotFoundError:
        print(f"Process '{target_process}' not found.")
        sys.exit(1)

    script_code = """
    console.log("Script loaded");

    const libc_init_static = Module.findExportByName(null, "__libc_init");
    if (libc_init_static) {
        console.log("__libc_init found at:", libc_init_static);
    } else {
        console.log("__libc_init not found.");
    }

    const call_array_address = Module.findExportByName(null, "_Z10call_arrayIPPFiPiciS_EEvPT_mS3_S3_S3_"); // Mangled name of call_array
    if (call_array_address) {
        console.log("call_array found at:", call_array_address);

        Interceptor.attach(call_array_address, {
            onEnter: function(args) {
                const list = ptr(args[0]);
                const count = args[1].toInt();
                const argc = args[2].toInt();
                const argv = new NativePointer(args[3]);
                const envp = new NativePointer(args[4]);

                console.log("[call_array] count:", count, "argc:", argc);
                for (let i = 0; i < count; i++) {
                    const funcPtr = list.readPointer();
                    const funcName = DebugSymbol.fromAddress(funcPtr).name || 'unknown function';
                    send({ name: "call_array", args: [funcName, argc, argv, envp] });
                    list.add(Process.pointerSize);
                }
            }
        });
    } else {
        console.log("call_array not found.");
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to exit.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("Exiting...")
        session.detach()

if __name__ == "__main__":
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `frida_hook.py`。
2. 找到你想要分析的静态链接的可执行文件的进程名称或 PID。
3. 运行 Frida 脚本: `python frida_hook.py <进程名称或 PID>`

**预期输出:**

Frida 会连接到目标进程，找到 `call_array` 函数的地址，并 hook 它。每当 `call_array` 被调用时，`onEnter` 函数会被执行，它会读取函数指针数组，并打印出每个被调用函数的名称 (如果可以解析出符号的话)。

这个 Frida 示例可以帮助你动态地观察静态链接程序的初始化过程，验证 `call_array` 是否按预期调用了初始化函数。

希望这个详细的解释能够帮助你理解 `libc_init_static.cpp` 的功能和作用。记住，静态链接在 Android 中相对较少见，主要用于一些底层的系统组件或者使用 NDK 构建的独立可执行文件。大部分 Android 应用和库仍然依赖于动态链接。

Prompt: 
```
这是目录为bionic/libc/bionic/libc_init_static.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <android/api-level.h>
#include <elf.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/mman.h>

#include "async_safe/log.h"
#include "heap_tagging.h"
#include "libc_init_common.h"
#include "platform/bionic/macros.h"
#include "platform/bionic/mte.h"
#include "platform/bionic/page.h"
#include "platform/bionic/reserved_signals.h"
#include "private/KernelArgumentBlock.h"
#include "private/bionic_asm.h"
#include "private/bionic_asm_note.h"
#include "private/bionic_call_ifunc_resolver.h"
#include "private/bionic_elf_tls.h"
#include "private/bionic_globals.h"
#include "private/bionic_tls.h"
#include "private/elf_note.h"
#include "pthread_internal.h"
#include "sys/system_properties.h"
#include "sysprop_helpers.h"

#if __has_feature(hwaddress_sanitizer)
#include <sanitizer/hwasan_interface.h>
#endif

// Leave the variable uninitialized for the sake of the dynamic loader, which
// links in this file. The loader will initialize this variable before
// relocating itself.
#if defined(__i386__)
__LIBC_HIDDEN__ void* __libc_sysinfo;
#endif

extern "C" int __cxa_atexit(void (*)(void *), void *, void *);
extern "C" const char* __gnu_basename(const char* path);

static void call_array(init_func_t** list, size_t count, int argc, char* argv[], char* envp[]) {
  while (count-- > 0) {
    init_func_t* function = *list++;
    (*function)(argc, argv, envp);
  }
}

static void call_fini_array(void* arg) {
  structors_array_t* structors = reinterpret_cast<structors_array_t*>(arg);
  fini_func_t** array = structors->fini_array;
  size_t count = structors->fini_array_count;
  // Now call each destructor in reverse order.
  while (count-- > 0) {
    fini_func_t* function = array[count];
    (*function)();
  }
}

#if defined(__arm__) || defined(__i386__)  // Legacy architectures used REL...
extern __LIBC_HIDDEN__ __attribute__((weak)) ElfW(Rel) __rel_iplt_start[], __rel_iplt_end[];

static void call_ifunc_resolvers() {
  for (ElfW(Rel)* r = __rel_iplt_start; r != __rel_iplt_end; ++r) {
    ElfW(Addr)* offset = reinterpret_cast<ElfW(Addr)*>(r->r_offset);
    ElfW(Addr) resolver = *offset;
    *offset = __bionic_call_ifunc_resolver(resolver);
  }
}
#else  // ...but modern architectures use RELA instead.
extern __LIBC_HIDDEN__ __attribute__((weak)) ElfW(Rela) __rela_iplt_start[], __rela_iplt_end[];

static void call_ifunc_resolvers() {
  for (ElfW(Rela)* r = __rela_iplt_start; r != __rela_iplt_end; ++r) {
    ElfW(Addr)* offset = reinterpret_cast<ElfW(Addr)*>(r->r_offset);
    ElfW(Addr) resolver = r->r_addend;
    *offset = __bionic_call_ifunc_resolver(resolver);
  }
}
#endif

static void apply_gnu_relro() {
  ElfW(Phdr)* phdr_start = reinterpret_cast<ElfW(Phdr)*>(getauxval(AT_PHDR));
  unsigned long int phdr_ct = getauxval(AT_PHNUM);

  for (ElfW(Phdr)* phdr = phdr_start; phdr < (phdr_start + phdr_ct); phdr++) {
    if (phdr->p_type != PT_GNU_RELRO) {
      continue;
    }

    ElfW(Addr) seg_page_start = page_start(phdr->p_vaddr);
    ElfW(Addr) seg_page_end = page_end(phdr->p_vaddr + phdr->p_memsz);

    // Check return value here? What do we do if we fail?
    mprotect(reinterpret_cast<void*>(seg_page_start), seg_page_end - seg_page_start, PROT_READ);
  }
}

static void layout_static_tls(KernelArgumentBlock& args) {
  StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
  layout.reserve_bionic_tls();

  const char* progname = args.argv[0];
  ElfW(Phdr)* phdr_start = reinterpret_cast<ElfW(Phdr)*>(getauxval(AT_PHDR));
  size_t phdr_ct = getauxval(AT_PHNUM);

  static TlsModule mod;
  TlsModules& modules = __libc_shared_globals()->tls_modules;
  if (__bionic_get_tls_segment(phdr_start, phdr_ct, 0, &mod.segment)) {
    if (!__bionic_check_tls_align(mod.segment.aligned_size.align.value)) {
      async_safe_fatal("error: TLS segment alignment in \"%s\" is not a power of 2: %zu\n",
                       progname, mod.segment.aligned_size.align.value);
    }
    mod.static_offset = layout.reserve_exe_segment_and_tcb(&mod.segment, progname);
    mod.first_generation = kTlsGenerationFirst;

    modules.module_count = 1;
    modules.static_module_count = 1;
    modules.module_table = &mod;
  } else {
    layout.reserve_exe_segment_and_tcb(nullptr, progname);
  }
  // Enable the fast path in __tls_get_addr.
  __libc_tls_generation_copy = modules.generation;

  layout.finish_layout();
}
void __libc_init_profiling_handlers() {
  // The dynamic variant of this function is more interesting, but this
  // at least ensures that static binaries aren't killed by the kernel's
  // default disposition for these two real-time signals that would have
  // handlers installed if this was a dynamic binary.
  signal(BIONIC_SIGNAL_PROFILER, SIG_IGN);
  signal(BIONIC_SIGNAL_ART_PROFILER, SIG_IGN);
}

__attribute__((no_sanitize("memtag"))) __noreturn static void __real_libc_init(
    KernelArgumentBlock& args, void* raw_args, void (*onexit)(void) __unused,
    int (*slingshot)(int, char**, char**), structors_array_t const* const structors,
    bionic_tcb* temp_tcb) {
  BIONIC_STOP_UNWIND;

  __libc_init_main_thread_early(args, temp_tcb);
  __libc_init_main_thread_late();
  __libc_init_globals();
  __libc_shared_globals()->init_progname = args.argv[0];
  __libc_init_AT_SECURE(args.envp);
  layout_static_tls(args);
  __libc_init_main_thread_final();
  __libc_init_common();
  __libc_init_mte(/*memtag_dynamic_entries=*/nullptr,
                  reinterpret_cast<ElfW(Phdr)*>(getauxval(AT_PHDR)), getauxval(AT_PHNUM),
                  /*load_bias = */ 0);
  __libc_init_mte_stack(/*stack_top = */ raw_args);
  __libc_init_scudo();
  __libc_init_profiling_handlers();
  __libc_init_fork_handler();

  call_ifunc_resolvers();
  apply_gnu_relro();

  // Several Linux ABIs don't pass the onexit pointer, and the ones that
  // do never use it.  Therefore, we ignore it.

  call_array(structors->preinit_array, structors->preinit_array_count, args.argc, args.argv,
             args.envp);
  call_array(structors->init_array, structors->init_array_count, args.argc, args.argv, args.envp);

  // The executable may have its own destructors listed in its .fini_array
  // so we need to ensure that these are called when the program exits
  // normally.
  if (structors->fini_array_count > 0) {
    __cxa_atexit(call_fini_array, const_cast<structors_array_t*>(structors), nullptr);
  }

  __libc_init_mte_late();

  exit(slingshot(args.argc, args.argv, args.envp));
}

extern "C" void __hwasan_init_static();

// This __libc_init() is only used for static executables, and is called from crtbegin.c.
//
// The 'structors' parameter contains pointers to various initializer
// arrays that must be run before the program's 'main' routine is launched.
__attribute__((no_sanitize("hwaddress", "memtag"))) __noreturn void __libc_init(
    void* raw_args, void (*onexit)(void) __unused, int (*slingshot)(int, char**, char**),
    structors_array_t const* const structors) {
  // We _really_ don't want the compiler to call memset() here,
  // but it's done so before for riscv64 (http://b/365618934),
  // so we have to force it to behave.
  bionic_tcb temp_tcb __attribute__((uninitialized));
  __builtin_memset_inline(&temp_tcb, 0, sizeof(temp_tcb));

  KernelArgumentBlock args(raw_args);
#if __has_feature(hwaddress_sanitizer)
  // Install main thread TLS early. It will be initialized later in __libc_init_main_thread. For now
  // all we need is access to TLS_SLOT_SANITIZER and read auxval for the page size.
  __set_tls(&temp_tcb.tls_slot(0));
  __libc_shared_globals()->auxv = args.auxv;
  // Initialize HWASan enough to run instrumented code. This sets up TLS_SLOT_SANITIZER, among other
  // things.
  __hwasan_init_static();
  // We are ready to run HWASan-instrumented code, proceed with libc initialization...
#endif

  __real_libc_init(args, raw_args, onexit, slingshot, structors, &temp_tcb);
}

static int g_target_sdk_version{__ANDROID_API__};

extern "C" int android_get_application_target_sdk_version() {
  return g_target_sdk_version;
}

extern "C" void android_set_application_target_sdk_version(int target) {
  g_target_sdk_version = target;
  __libc_set_target_sdk_version(target);
}

// This function is called in the dynamic linker before ifunc resolvers have run, so this file is
// compiled with -ffreestanding to avoid implicit string.h function calls. (It shouldn't strictly
// be necessary, though.)
__LIBC_HIDDEN__ libc_shared_globals* __libc_shared_globals() {
  BIONIC_USED_BEFORE_LINKER_RELOCATES static libc_shared_globals globals;
  return &globals;
}

"""

```