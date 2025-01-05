Response:
Let's break down the thought process for generating the detailed response to the user's request about the `execinfo.handroid` header file.

**1. Understanding the Core Request:**

The user wants to understand the purpose and functionality of `execinfo.handroid`, specifically within the context of Android's Bionic library. Key aspects requested are:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it relate to Android features?
* **Detailed Explanation:**  Explain the inner workings of any involved libc functions.
* **Dynamic Linking:**  Address any interaction with the dynamic linker.
* **Reasoning and Examples:** Provide hypothetical scenarios and their outcomes.
* **Common Errors:** Highlight potential pitfalls for developers.
* **Call Stack:** Trace how Android components reach this code.
* **Frida Hooking:** Demonstrate how to inspect this code in action.

**2. Initial Analysis of the File Content:**

The provided file `execinfo.handroid` is surprisingly short. The core content is:

```c
#pragma once

/* ... copyright ... */

#define __INTRODUCED_IN(x)
#define __BIONIC_AVAILABILITY_GUARD(x) 1
#include <bionic/execinfo.h>
#undef __BIONIC_AVAILABILITY_GUARD
#undef __INTRODUCED_IN
```

This immediately suggests:

* **Wrapper/Compatibility Layer:** It's not defining core functionalities itself. It's including another header (`bionic/execinfo.h`).
* **Conditional Compilation:** The `#define` and `#undef` hints at handling different build environments or configurations. The comment about "musl" further reinforces this.

**3. Deconstructing the Code Snippet:**

* **`#pragma once`:**  Standard practice to prevent multiple inclusions of the header file during compilation.
* **Copyright Notice:**  Standard boilerplate.
* **`#define __INTRODUCED_IN(x)` and `#define __BIONIC_AVAILABILITY_GUARD(x) 1`:** These are the key parts. The comments explain they are for compatibility with musl, a different C library implementation. Bionic uses these macros for versioning and availability control of its APIs. This file effectively disables these checks when compiling for musl (or potentially other scenarios). The `1` for `__BIONIC_AVAILABILITY_GUARD` implies the feature is *always* available in this context.
* **`#include <bionic/execinfo.h>`:** This is the crucial line. It includes the *actual* header file containing the definitions for the `execinfo` functions.
* **`#undef __BIONIC_AVAILABILITY_GUARD` and `#undef __INTRODUCED_IN`:**  Clean up the macro definitions after including the header, likely to avoid unintended side effects in the surrounding code.

**4. Inferring Functionality Based on Included Header:**

Since `execinfo.handroid` primarily includes `bionic/execinfo.h`, the functionality resides there. The standard `execinfo` library provides functions for obtaining backtraces (stack traces) of a running program. The typical functions are:

* `backtrace()`:  Gets the raw addresses of the stack frames.
* `backtrace_symbols()`:  Translates the addresses into human-readable strings (often including function names and offsets).
* `backtrace_symbols_fd()`:  Similar to `backtrace_symbols()` but writes to a file descriptor.

**5. Connecting to Android:**

The `execinfo` functionality is fundamental for debugging and error reporting in Android. Think about:

* **Crash Reporting:** When an app crashes, Android often generates a stack trace. `execinfo` is likely involved in capturing this information.
* **Native Debugging:** Developers using the NDK need stack traces to debug native crashes and errors.
* **Profiling Tools:** Tools that analyze application performance often rely on backtraces to identify bottlenecks.

**6. Detailed Explanation of `execinfo` Functions (Anticipating Content of `bionic/execinfo.h`):**

* **`backtrace()`:** The core mechanism. Internally, it likely iterates through the stack frames, reading the return addresses. The implementation is architecture-specific (how the stack is structured).
* **`backtrace_symbols()`:**  This involves:
    * **Address to Symbol Mapping:**  Looking up the address in the program's symbol tables (present in the executable and loaded shared libraries). This is where the dynamic linker plays a crucial role.
    * **Demangling:**  Converting mangled C++ function names back to their original form.
* **`backtrace_symbols_fd()`:**  Similar to `backtrace_symbols()` but uses `write()` to output to the specified file descriptor.

**7. Dynamic Linker Integration:**

* **Symbol Tables:** The dynamic linker (`linker64` or `linker`) is responsible for loading shared libraries (`.so` files) and resolving symbols between them. It creates and maintains symbol tables that map function names (symbols) to their addresses in memory.
* **`backtrace_symbols()` and the Linker:** When `backtrace_symbols()` needs to translate an address to a symbol, it consults the symbol tables maintained by the dynamic linker for *all* loaded libraries.

**8. Reasoning and Examples:**

Think of a simple crash scenario in native code. `backtrace()` captures the raw addresses, and `backtrace_symbols()` makes them understandable.

**9. Common User Errors:**

Focus on misuse or misunderstanding of the `execinfo` functions, such as:

* **Incorrect Buffer Size:**  Passing a too-small buffer to `backtrace()`.
* **Memory Management:**  Forgetting to `free()` the memory returned by `backtrace_symbols()`.
* **Limitations:** Understanding that `backtrace()` might not capture the entire call stack in all situations (e.g., due to stack corruption).

**10. Android Framework/NDK Call Stack:**

Imagine an app with native code crashing. The Android OS's signal handling mechanism would be the first responder. This would likely call into Bionic's signal handling, which in turn would use `backtrace()` to capture the crash information. The NDK exposes these functions directly to native developers.

**11. Frida Hooking:**

Demonstrate how to intercept calls to `backtrace()` or `backtrace_symbols()` using Frida to inspect the arguments and return values.

**12. Structuring the Response:**

Organize the information logically, starting with a high-level overview and then diving into details. Use clear headings and examples to make the information accessible. Address each part of the user's request explicitly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps `execinfo.handroid` contains platform-specific implementations.
* **Correction:** The code clearly indicates it's a wrapper for `bionic/execinfo.h`, likely for compatibility reasons.
* **Initial thought:**  Focus heavily on the implementation details of `backtrace()`.
* **Refinement:** While mentioning the internal mechanisms is good, emphasize the *user-facing* functionality and the role of the dynamic linker.
* **Initial thought:** Provide very complex Frida scripts.
* **Refinement:**  Start with a simple Frida example that illustrates the basic hooking principle.

By following this systematic approach, breaking down the request, analyzing the code snippet, and leveraging knowledge of Android internals and the `execinfo` library, a comprehensive and accurate answer can be generated.
好的，让我们来详细分析一下 `bionic/libc/execinfo/include/execinfo.handroid` 这个头文件。

**功能列举:**

这个头文件本身的主要功能是作为一个兼容性包装器 (compatibility wrapper)。它做了以下几件事：

1. **包含 `bionic/execinfo.h`:**  这是核心功能，它将 Android Bionic 提供的 `execinfo.h` 头文件包含进来。这意味着它最终提供了 `execinfo` 库中定义的函数，如 `backtrace`, `backtrace_symbols`, 和 `backtrace_symbols_fd`。
2. **处理宏定义:**
   - `#define __INTRODUCED_IN(x)`:  这是一个空宏定义。在 Bionic 中，`__INTRODUCED_IN` 用于标记 API 的引入版本。这里将其定义为空，可能是为了在某些特定的编译环境下（比如与 musl libc 兼容）禁用或忽略版本检查。
   - `#define __BIONIC_AVAILABILITY_GUARD(x) 1`:  在 Bionic 中，`__BIONIC_AVAILABILITY_GUARD` 用于控制 API 的可用性。将其定义为 `1` 意味着相关的 API 在当前上下文中被认为是可用的。
3. **取消宏定义:**
   - `#undef __BIONIC_AVAILABILITY_GUARD` 和 `#undef __INTRODUCED_IN`: 在包含了 `bionic/execinfo.h` 之后，取消了这两个宏的定义，可能是为了避免它们影响后续的代码或头文件。

**与 Android 功能的关系及举例:**

`execinfo` 库在 Android 中扮演着重要的调试和错误报告角色。它允许程序在运行时获取当前调用栈的信息。以下是一些相关的 Android 功能和示例：

* **崩溃报告 (Crash Reporting):** 当 Android 应用（无论是 Java/Kotlin 还是 Native 代码）发生崩溃时，系统会生成一个崩溃报告，其中包含了调用栈信息。`execinfo` 库提供的函数被用于收集 Native 代码的调用栈，帮助开发者定位崩溃发生的位置。

   **例子:** 当一个 Native (NDK) 应用发生 SIGSEGV 信号时，Android 的 `linker` 或 `debuggerd` 进程会使用 `backtrace` 等函数来获取崩溃时的函数调用栈，并将这些信息记录到 `logcat` 中或者生成 tombstone 文件。

* **性能分析 (Profiling):** 一些性能分析工具可能会使用 `backtrace` 来采样程序的执行路径，帮助开发者找到性能瓶颈。

   **例子:**  一个性能分析工具可以周期性地调用 `backtrace` 来获取当前正在执行的函数，从而统计各个函数的执行时间占比。

* **调试器 (Debugger):** 调试器 (如 gdb, lldb) 在单步调试或断点命中时，可以使用 `backtrace` 来显示当前的函数调用栈，方便开发者理解程序的执行流程。

   **例子:**  使用 lldb 连接到 Android 设备上的一个 Native 进程，可以在断点处执行 `bt` (backtrace) 命令来查看当前的调用栈。

**详细解释每一个 libc 函数的功能是如何实现的:**

`execinfo.handroid` 本身并没有实现任何 libc 函数，它只是包含了 `bionic/execinfo.h`。  `bionic/execinfo.h` 中声明的函数通常由底层的操作系统和架构相关代码实现。以下是 `execinfo` 中主要函数的实现原理概述：

* **`backtrace(void** buffer, int size)`:**
    - **功能:** 获取当前线程的调用栈信息，并将返回地址存储在 `buffer` 中，最多存储 `size` 个地址。
    - **实现原理:**  这个函数的实现高度依赖于 CPU 架构和调用约定。
        - 它通常会从当前的栈帧指针（例如 x86 的 `RBP` 或 ARM 的 `FP`）开始，沿着栈帧链向上遍历。
        - 每个栈帧都包含着返回地址，这个返回地址指向了调用当前函数的指令的下一条指令。
        - `backtrace` 函数会读取这些返回地址，并将它们存储到提供的 `buffer` 中。
        - 遍历过程会持续到栈底或者存储的地址数量达到 `size`。

* **`backtrace_symbols(void* const* buffer, int size)`:**
    - **功能:** 将 `backtrace` 获取的返回地址数组转换为人类可读的字符串数组，通常包含函数名、偏移量以及可能的共享库信息。
    - **实现原理:**
        - 对于 `buffer` 中的每个地址，`backtrace_symbols` 需要找到该地址所属的函数和共享库。
        - **符号查找:**  它会查找进程的内存映射和加载的共享库的符号表。符号表包含了函数名和它们的起始地址之间的映射关系。
        - **地址匹配:** 通过比较返回地址和符号表中函数的地址范围，找到最匹配的函数。
        - **偏移计算:** 计算返回地址相对于函数起始地址的偏移量。
        - **共享库信息:** 如果地址属于一个共享库，还需要确定该地址属于哪个共享库。
        - **Demangling (C++):** 对于 C++ 函数，还需要进行名称反修饰 (demangling) 将编译器生成的 mangled name 转换为可读的函数名。
        - **内存分配:**  `backtrace_symbols` 会分配内存来存储生成的字符串数组，调用者需要负责释放这些内存。

* **`backtrace_symbols_fd(void* const* buffer, int size, int fd)`:**
    - **功能:**  与 `backtrace_symbols` 类似，但它将生成的符号信息直接写入到指定的文件描述符 `fd` 中，而不是返回一个字符串数组。
    - **实现原理:**  其核心的符号查找和地址解析过程与 `backtrace_symbols` 相同。主要的区别在于输出方式：它使用系统调用（如 `write`）将结果写入文件描述符，避免了内存分配和后续释放的需要。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`backtrace_symbols` 函数与动态链接器 (`linker`) 密切相关。当它需要将一个地址转换为符号时，需要依赖动态链接器加载的共享库的信息。

**SO 布局样本:**

假设我们有一个名为 `libexample.so` 的共享库：

```
libexample.so:
    .text:  # 代码段
        function_a:
            ...
        function_b:
            ...
    .data:  # 数据段
        global_var:
            ...
    .rodata: # 只读数据段
        constant_str:
            ...
    .dynamic: # 动态链接信息
        ...
    .symtab: # 符号表
        STT_FUNC function_a  0x1000
        STT_FUNC function_b  0x1020
        STT_OBJECT global_var  0x2000
        ...
    .strtab: # 字符串表 (存储符号名)
        function_a\0
        function_b\0
        global_var\0
        ...
```

* **`.text` (代码段):** 包含可执行的机器代码。
* **`.data` (数据段):** 包含已初始化的全局变量和静态变量。
* **`.rodata` (只读数据段):** 包含只读的数据，例如字符串常量。
* **`.dynamic` (动态链接信息):** 包含动态链接器所需的各种信息，例如依赖的共享库、符号表的地址等。
* **`.symtab` (符号表):**  核心部分，包含了共享库导出的符号（函数、全局变量等）的名称和地址。`STT_FUNC` 表示这是一个函数符号，`STT_OBJECT` 表示这是一个对象符号。
* **`.strtab` (字符串表):** 存储符号表中用到的字符串，例如函数名和变量名。

**链接的处理过程:**

1. **加载共享库:** 当一个程序需要使用 `libexample.so` 中的函数时，动态链接器会将其加载到内存中。动态链接器会解析 `.dynamic` 段的信息，确定符号表和字符串表的位置。
2. **符号解析 (Symbol Resolution):** 当 `backtrace_symbols` 接收到一个属于 `libexample.so` 的地址时，它会：
   - 确定该地址属于哪个加载的共享库（通常通过遍历进程的内存映射）。
   - 访问该共享库的 `.symtab` 和 `.strtab`。
   - 遍历符号表，查找与给定地址最匹配的函数符号。匹配的标准通常是符号的地址小于等于给定的地址，并且是所有满足条件的符号中地址最大的那个。
   - 计算地址相对于找到的函数符号起始地址的偏移量。
   - 从字符串表中获取函数符号的名称。
3. **生成符号信息字符串:**  `backtrace_symbols` 将以上信息组合成一个字符串，例如：
   `libexample.so (function_a+0x10)`  表示地址位于 `libexample.so` 中 `function_a` 函数偏移 `0x10` 字节的位置。

**假设输入与输出 (对于 `backtrace_symbols`):**

**假设输入:**

* `buffer`:  包含一个地址 `0xb7489010`
* `size`: 1

**假设场景:**

* `libexample.so` 被加载到内存地址 `0xb7489000`。
* `libexample.so` 的符号表中 `function_a` 的地址是 `0x10` (相对于 `libexample.so` 的基地址，即绝对地址为 `0xb7489000 + 0x10 = 0xb7489010`)。

**预期输出 (字符串数组中的第一个元素):**

`libexample.so (function_a+0)`

**如果做了逻辑推理，请给出假设输入与输出 (例如，`backtrace`):**

**假设输入 (对于 `backtrace`):**

* `buffer`: 一个大小为 10 的 `void*` 数组。
* 当前线程的调用栈如下 (由内向外):
    1. `function_c` (地址 `0xaaaa`) 调用了
    2. `function_b` (地址 `0xbbbb`) 调用了
    3. `function_a` (地址 `0xcccc`)

**预期输出:**

`buffer` 的前三个元素将包含返回地址 (这些地址指向调用者的下一条指令，因此会略高于函数起始地址):

* `buffer[0]`:  指向 `function_b` 调用 `function_c` 之后的指令的地址 (例如 `0xaaae`).
* `buffer[1]`:  指向 `function_a` 调用 `function_b` 之后的指令的地址 (例如 `0xbbbe`).
* `buffer[2]`:  指向调用 `function_a` 的函数的下一条指令的地址 (假设在主程序中，例如 `0xccce`).
* `buffer[3]` 到 `buffer[9]` 的值取决于栈的深度和大小，如果栈更浅，则可能包含 NULL 或者之前的栈帧信息。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **`backtrace` 的 `size` 参数过小:**

   ```c
   void* buffer[2]; // 只能存储 2 个返回地址
   int nptrs = backtrace(buffer, sizeof(buffer) / sizeof(buffer[0]));
   ```

   **错误:** 如果实际的调用栈深度超过 2，那么 `backtrace` 只会捕获到最内层的 2 个栈帧，丢失了更外层的调用信息，导致调试困难。

2. **忘记 `free` `backtrace_symbols` 返回的内存:**

   ```c
   void* buffer[10];
   int nptrs = backtrace(buffer, 10);
   char** strings = backtrace_symbols(buffer, nptrs);
   // ... 使用 strings ...
   // 忘记调用 free(strings);  导致内存泄漏
   ```

   **错误:** `backtrace_symbols` 会动态分配内存来存储字符串数组，如果忘记释放，会导致内存泄漏。

3. **假设 `backtrace_symbols` 总是能找到符号信息:**

   ```c
   void* buffer[10];
   int nptrs = backtrace(buffer, 10);
   char** strings = backtrace_symbols(buffer, nptrs);
   for (int i = 0; i < nptrs; i++) {
       printf("%s\n", strings[i]); // 假设 strings[i] 总是有效
   }
   free(strings);
   ```

   **错误:** 在某些情况下，`backtrace_symbols` 可能无法找到某个地址对应的符号信息，这时 `strings` 数组中对应的元素可能是 NULL。直接解引用 NULL 指针会导致程序崩溃。应该在使用前检查 `strings[i]` 是否为 NULL。

4. **在信号处理函数中使用 `backtrace_symbols`:**

   虽然 `backtrace` 本身在信号处理函数中通常是安全的，但 `backtrace_symbols` 内部可能会调用 `malloc` 等函数，这些函数在某些信号处理的上下文中可能不是异步信号安全的 (async-signal-safe)。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `execinfo` 的路径 (以崩溃报告为例):**

1. **Native 代码崩溃:**  假设一个使用 NDK 编写的库发生了一个错误，例如访问了无效的内存地址，导致 CPU 发送一个信号 (如 `SIGSEGV`)。
2. **内核信号传递:**  Linux 内核会将这个信号传递给导致崩溃的进程。
3. **Bionic 的信号处理:** Android 的 Bionic libc 注册了默认的信号处理程序。当接收到 `SIGSEGV` 等信号时，Bionic 的信号处理程序会被调用。
4. **`linker` 或 `debuggerd` 的介入:** 对于一些严重的信号（如导致崩溃的信号），Bionic 的信号处理程序可能会通知 `linker` (对于动态链接库) 或 `debuggerd` 进程。
5. **调用 `backtrace`:** `linker` 或 `debuggerd` 进程会调用 `backtrace` 函数来获取崩溃时的调用栈信息。
6. **调用 `backtrace_symbols` 或 `backtrace_symbols_fd`:**  为了将原始的地址信息转换为可读的符号信息，`linker` 或 `debuggerd` 会调用 `backtrace_symbols` 或 `backtrace_symbols_fd`。
7. **生成 tombstone 或 logcat 输出:** 获取到的调用栈信息会被格式化并写入到 tombstone 文件 (位于 `/data/tombstones`) 或 logcat 中。

**NDK 到 `execinfo` 的路径:**

1. **NDK 代码直接调用:** NDK 开发者可以直接在他们的 C/C++ 代码中调用 `backtrace`, `backtrace_symbols`, 或 `backtrace_symbols_fd`。这通常用于自定义的错误报告或日志记录。

   ```c++
   #include <execinfo.h>
   #include <stdio.h>
   #include <stdlib.h>

   void my_error_handler() {
       void* buffer[10];
       int nptrs = backtrace(buffer, 10);
       char** strings = backtrace_symbols(buffer, nptrs);
       if (strings) {
           fprintf(stderr, "Error occurred, backtrace:\n");
           for (int i = 0; i < nptrs; i++) {
               fprintf(stderr, "%s\n", strings[i]);
           }
           free(strings);
       }
   }
   ```

**Frida Hook 示例:**

以下是一个使用 Frida hook `backtrace` 函数的示例：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['name'], message['payload']['address']))
    else:
        print(message)

session = frida.attach(sys.argv[1]) # 附加到目标进程

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "backtrace"), {
    onEnter: function(args) {
        var buffer = ptr(args[0]);
        var size = args[1].toInt3d();
        console.log("[*] backtrace called, buffer:", buffer, "size:", size);
        this.buffer = buffer;
        this.size = size;
    },
    onLeave: function(retval) {
        var nptrs = retval.toInt3d();
        console.log("[*] backtrace returned:", nptrs);
        for (var i = 0; i < Math.min(nptrs, this.size); i++) {
            var address = this.buffer.readPointer();
            send({ name: "Stack Frame " + i, address: address });
            this.buffer = this.buffer.add(Process.pointerSize);
        }
    }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将以上 Python 代码保存为 `hook_backtrace.py`。
2. 确保已安装 Frida 和 Python 的 Frida 模块。
3. 运行目标 Android 应用。
4. 使用 adb 找到目标应用的进程 ID (PID)。
5. 运行 Frida hook 脚本: `python hook_backtrace.py <目标进程的 PID>`

**Frida Hook 解释:**

* `Interceptor.attach`:  用于拦截对 `backtrace` 函数的调用。
* `onEnter`:  在 `backtrace` 函数被调用之前执行。我们打印出传递给 `backtrace` 的 `buffer` 指针和 `size`。
* `onLeave`: 在 `backtrace` 函数执行完成并返回后执行。我们打印出返回值 (捕获到的栈帧数量)，然后遍历 `buffer` 并读取返回地址，并通过 `send` 函数将地址信息发送回 Python 脚本。
* `on_message`:  Python 脚本接收来自 Frida 注入的代码的消息，并打印出栈帧的地址。

通过这个 Frida hook 示例，你可以观察到 `backtrace` 函数何时被调用，以及它捕获到的返回地址，从而深入理解 `execinfo` 库在 Android 系统中的工作方式。

希望以上详细的解释能够帮助你理解 `bionic/libc/execinfo/include/execinfo.handroid` 这个头文件及其相关功能。

Prompt: 
```
这是目录为bionic/libc/execinfo/include/execinfo.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2021 The Android Open Source Project
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

/*
 * This file is exported as part of libexecinfo for use with musl, which doesn't
 * define __INTRODUCED_IN or __BIONIC_AVAILABILITY_GUARD.  Stub them out.
 */
#define __INTRODUCED_IN(x)
#define __BIONIC_AVAILABILITY_GUARD(x) 1
#include <bionic/execinfo.h>
#undef __BIONIC_AVAILABILITY_GUARD
#undef __INTRODUCED_IN

"""

```