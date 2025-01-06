Response:
Let's break down the thought process to answer the user's request about `elftls_dtv_resize_helper.cpp`.

**1. Understanding the Goal:**

The user wants a comprehensive explanation of a specific C++ test file within Android's Bionic library. They're interested in its functionality, relation to Android, how specific libc functions work within it, how it interacts with the dynamic linker, potential errors, and how it can be reached and debugged.

**2. Initial Analysis of the Code:**

The first step is to read the provided source code. Key observations include:

* **Includes:** `dlfcn.h`, `stdio.h`, `stdlib.h`, `<functional>`, `<iostream>`, and `bionic/pthread_internal.h`. This immediately suggests interaction with dynamic linking, standard I/O, memory allocation, and threading (specifically related to TLS).
* **`constexpr bool kDumpModulesForDebugging = false;`:** This hints at debugging features, even if currently disabled.
* **Helper Functions:**  `fix_nullptr`, `check`, `ASSERT_*` macros. These are utility functions for assertions and handling potential null pointer output.
* **`highest_loaded_modid()`:**  This function iterates through loaded shared objects using `dl_iterate_phdr` and finds the highest TLS module ID. This is a strong indicator the test is about TLS.
* **`dtv()`:**  This function retrieves the current thread's DTV (Dynamic Thread Vector) using Bionic-specific functions `__get_tcb_dtv` and `__get_bionic_tcb`. This is central to understanding the file's purpose.
* **`highest_modid_in_dtv()`:**  This iterates through the DTV to find the highest allocated module ID within it.
* **`__thread int g_tls_var_placeholder = 42;`:**  This declares a thread-local variable, confirming the focus on TLS. The comment explains its purpose is to prevent optimization.
* **`main()` function:**  The core logic resides here. It loads shared libraries (`libtest_elftls_dynamic_filler_*.so`), calls functions within them (`bump`), and makes assertions about the state of the DTV.

**3. Identifying the Core Functionality:**

Based on the code, the primary function of `elftls_dtv_resize_helper.cpp` is to **test the dynamic resizing of the DTV (Dynamic Thread Vector)**. It does this by:

* Loading shared libraries that have thread-local storage.
* Accessing these thread-local variables, which triggers the allocation of slots in the DTV.
* Systematically loading more libraries to force the DTV to grow beyond its initial capacity.
* Using assertions to verify that the DTV is resized correctly and that the module IDs are properly tracked.

**4. Connecting to Android Functionality:**

* **Dynamic Linking:** The use of `dlopen`, `dlsym`, and `dl_iterate_phdr` directly relates to Android's dynamic linker (`linker64` or `linker`). Android apps and libraries rely heavily on dynamic linking.
* **Thread-Local Storage (TLS):**  TLS is a crucial feature for managing per-thread data. Android uses TLS extensively in its frameworks and native libraries.
* **Bionic:**  The file resides within Bionic and uses Bionic-specific functions, highlighting its role in the core Android C library.

**5. Explaining libc Functions:**

The key libc functions used are:

* **`dlopen()`:**  Loads a dynamic library. The explanation should cover its role in dynamic linking, the `RTLD_LOCAL` and `RTLD_NOW` flags, and what it returns.
* **`dlsym()`:**  Finds the address of a symbol within a loaded library. The explanation should cover its purpose, potential errors (if the symbol is not found), and the casting of the returned `void*`.
* **`dl_iterate_phdr()`:** Iterates through the program headers of all loaded shared objects. The explanation should focus on how it provides information about loaded modules, including TLS data.
* **`abort()`:**  Terminates the program immediately. Explain its purpose in handling assertion failures.
* **`fprintf()`/`std::cerr`:** Output for debugging/errors.

**6. Addressing Dynamic Linker Aspects:**

This requires explaining:

* **SO Layout:**  A simplified example of how shared objects are laid out in memory (text, data, BSS, PLT, GOT, and importantly, the TLS section).
* **Linking Process:**  Focus on the dynamic linking stage, particularly how the linker resolves TLS addresses. Briefly mention the DTV and how it's used to locate thread-local variables.
* **DTV Role:** Explain how the DTV maps module IDs to the actual memory locations of the TLS blocks for each module in a thread.

**7. Logical Reasoning and Assumptions:**

The test makes assumptions about the initial DTV size and the order in which modules are loaded. These should be stated explicitly. The input is essentially the act of loading specific shared libraries in a sequence. The expected output is that the assertions within the code pass, indicating correct DTV resizing.

**8. Common User Errors:**

Focus on errors related to TLS usage in an Android context:

* Incorrectly declaring or accessing thread-local variables.
* Not understanding the limitations of TLS with dynamically loaded libraries (the order of initialization matters).

**9. Android Framework/NDK Path and Frida Hooking:**

This requires tracing back how such low-level tests are relevant:

* **NDK:** Developers using the NDK can create shared libraries that use TLS. Understanding DTV resizing is important for ensuring proper TLS behavior.
* **Android Framework:**  The Android runtime (ART) and native libraries within the framework also use TLS.
* **Frida Hooking:** Provide a practical example of how to use Frida to inspect the DTV at runtime, demonstrating how to verify the test's behavior in a real Android environment. Focus on hooking the `__get_tcb_dtv` function to observe the DTV structure.

**10. Structuring the Answer:**

Organize the information logically, using headings and bullet points to improve readability. Start with a summary of the file's purpose, then delve into details about libc functions, dynamic linking, error scenarios, and finally, how to reach and debug the code.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the resizing aspect.
* **Correction:**  Realized the need to explain *why* resizing is necessary (loading more libraries with TLS).
* **Initial thought:** Provide very technical details about the DTV structure.
* **Correction:**  Simplify the explanation of the DTV for better understanding, focusing on its purpose rather than intricate bit-level details.
* **Initial thought:**  Assume the user has deep knowledge of dynamic linking.
* **Correction:** Explain the fundamental concepts of dynamic linking and TLS in the context of Android.

By following this structured thought process, incorporating code analysis, and addressing each aspect of the user's request, a comprehensive and informative answer can be generated.
好的，让我们来详细分析一下 `bionic/tests/libs/elftls_dtv_resize_helper.cpp` 这个文件。

**文件功能概述:**

`elftls_dtv_resize_helper.cpp` 是 Android Bionic 库中的一个测试文件。它的主要功能是 **测试动态链接器 (dynamic linker) 在处理线程局部存储 (Thread-Local Storage, TLS) 时，动态线程向量 (Dynamic Thread Vector, DTV) 的自动扩容机制是否正常工作。**

简单来说，这个测试模拟了加载多个共享库，并且这些共享库都使用了 TLS 变量的情况。当一个新的使用了 TLS 的共享库被加载时，动态链接器需要为该库的 TLS 数据在当前线程的 DTV 中分配空间。如果当前的 DTV 容量不足，动态链接器需要自动扩展 DTV 的大小。这个测试就是用来验证这个自动扩展的过程是否正确。

**与 Android 功能的关系及举例说明:**

这个测试直接关系到 Android 系统中动态链接和线程管理的核心功能。

* **动态链接:** Android 应用和系统库大量使用动态链接。当应用启动或者动态加载库时，动态链接器负责将这些库加载到内存并解析符号引用。`dlopen`, `dlsym` 等函数是动态链接的关键 API。
* **线程局部存储 (TLS):** TLS 允许每个线程拥有自己独立的全局变量副本。这对于编写线程安全的代码至关重要。Android 中的许多库（包括 libc, libc++, ART 虚拟机等）都使用了 TLS 来存储线程特定的数据。例如，`errno` 变量就是一个典型的 TLS 变量，每个线程都有自己的 `errno` 值。

**举例说明:**

假设一个 Android 应用使用了多个动态链接库，其中一个库 `libfoo.so` 定义了一个 TLS 变量 `__thread int my_thread_local_var;`。当这个库被加载并且应用中的一个线程首次访问 `my_thread_local_var` 时，动态链接器会确保该线程的 DTV 中有足够的空间来存储 `libfoo.so` 的 TLS 数据。`elftls_dtv_resize_helper.cpp` 就是在模拟这种场景，并验证 DTV 是否能正确地扩展以容纳新的 TLS 数据。

**详细解释每一个 libc 函数的功能是如何实现的:**

* **`dlfcn.h` 中的函数:**
    * **`dlopen(const char *filename, int flag)`:**  打开一个动态链接库。
        * **功能:**  加载由 `filename` 指定的共享库到进程的地址空间。如果该库已经被加载，则增加其引用计数。
        * **实现:**  `dlopen` 是动态链接器的入口点。它会解析库文件的头部信息（例如 ELF 头），找到需要的段（如 `.text`, `.data`, `.bss`, `.dynamic`），并将其映射到内存中。`flag` 参数指定了加载的方式，例如 `RTLD_LOCAL` 表示符号仅对当前库可见，`RTLD_NOW` 表示立即解析所有符号。
    * **`dlsym(void *handle, const char *symbol)`:**  根据符号名查找共享库中的符号地址。
        * **功能:**  在由 `handle` 指定的已加载共享库中查找名为 `symbol` 的符号的地址。
        * **实现:**  `dlsym` 会遍历共享库的符号表（通常位于 `.dynsym` 段），查找匹配的符号。如果找到，则返回该符号的地址；否则返回 `NULL`。
* **`stdio.h` 中的函数:**
    * **`fprintf(FILE *stream, const char *format, ...)`:**  格式化输出到指定的文件流。
        * **功能:**  将格式化的数据输出到由 `stream` 指定的文件流。在这个测试中，`stream` 通常是 `stderr`（标准错误流），用于输出调试信息。
        * **实现:**  `fprintf` 会解析 `format` 字符串中的格式说明符（例如 `%d`, `%s`），并将后续的参数按照指定的格式转换为字符串，然后写入到文件流中。
* **`stdlib.h` 中的函数:**
    * **`abort()`:**  使程序异常终止。
        * **功能:**  立即终止程序的执行，通常用于处理严重的错误情况。
        * **实现:**  `abort` 函数通常会触发一个 `SIGABRT` 信号，导致程序非正常退出。在测试中，当断言失败时，会调用 `abort` 来停止测试。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**SO 布局样本 (简化):**

```
ELF Header
Program Headers:
  LOAD: 可执行代码和只读数据 (.text, .rodata 等)
  LOAD: 可读写数据 (.data, .bss 等)
  TLS:  线程局部存储数据
  DYNAMIC: 动态链接信息
Section Headers:
  .text:  可执行代码
  .rodata: 只读数据
  .data:  已初始化的全局变量
  .bss:   未初始化的全局变量
  .dynsym: 动态符号表
  .dynstr: 动态字符串表
  .rela.dyn: 重定位表 (数据段)
  .rela.plt: 重定位表 (PLT)
  .tbss:  TLS 未初始化数据
  .tdata: TLS 已初始化数据
```

**链接的处理过程 (与 TLS 相关):**

1. **编译时:** 编译器会将 TLS 变量的访问编译成特定的指令序列，这些指令会访问当前线程的 TLS 区域。对于动态链接库，编译器会生成重定位条目，指示动态链接器在加载时需要填充 TLS 变量的地址。
2. **加载时 (动态链接器):**
   * 当动态链接器加载一个包含 TLS 段的共享库时，它会为该库的 TLS 数据分配一块内存。
   * 每个线程都有自己的 TLS 区域，由线程控制块 (Thread Control Block, TCB) 指向。
   * 动态链接器会维护一个 DTV，这是一个数组，用于存储每个已加载的、拥有 TLS 段的共享库的 TLS 数据的地址。DTV 的索引通常与共享库的加载顺序有关（模 ID）。
   * 当一个线程首次访问一个共享库的 TLS 变量时，如果 DTV 中还没有该库的条目，动态链接器会为该库分配一个 DTV 条目，并将该库的 TLS 数据地址存储在该条目中。
   * **DTV 扩容:** 如果 DTV 当前的容量不足以容纳新的库的 TLS 数据，动态链接器会分配一块更大的内存，将旧的 DTV 内容复制到新的 DTV 中，然后添加新库的条目。
3. **运行时:** 当线程访问一个 TLS 变量时，CPU 会使用特殊的指令（例如 x86-64 上的 `fs` 段寄存器，ARM64 上的 `TPIDR_EL0` 寄存器）来找到当前线程的 TLS 区域。然后，通过 DTV 查找对应共享库的 TLS 数据地址，并最终访问到 TLS 变量。

**假设输入与输出 (逻辑推理):**

**假设输入:**

* 依次加载 `libtest_elftls_dynamic_filler_1.so`, `libtest_elftls_dynamic_filler_2.so`, ..., `libtest_elftls_dynamic_filler_5.so` 这些共享库。
* 每个 `libtest_elftls_dynamic_filler_*.so` 都有一个导出的函数 `bump`，该函数会访问该库内部的一个 TLS 变量。

**预期输出:**

* 最初的 DTV 可能很小，例如只能容纳几个模块的 TLS 数据。
* 当加载更多的共享库并访问它们的 TLS 变量时，DTV 会动态扩展。
* `ASSERT_*` 宏应该不会触发，表明 DTV 的大小和内容都符合预期。例如，`highest_modid_in_dtv()` 函数返回的值应该随着加载的库的数量增加而增加，并且 `dtv()->count` (DTV 的容量) 也会随着需要而增大。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误地假设 TLS 变量在所有线程中共享:**  TLS 变量是线程局部的，每个线程都有自己的副本。如果开发者错误地认为一个线程修改了 TLS 变量，其他线程也能看到这个修改，就会导致并发问题。
   ```c++
   // lib.so
   __thread int counter = 0;

   int increment() {
       return ++counter;
   }

   // main.cpp
   #include <iostream>
   #include <thread>
   #include <dlfcn.h>

   int main() {
       void* handle = dlopen("./lib.so", RTLD_NOW);
       int (*increment)() = (int(*)())dlsym(handle, "increment");

       std::thread t1([increment](){
           for (int i = 0; i < 5; ++i) {
               std::cout << "Thread 1: " << increment() << std::endl;
           }
       });

       std::thread t2([increment](){
           for (int i = 0; i < 5; ++i) {
               std::cout << "Thread 2: " << increment() << std::endl;
           }
       });

       t1.join();
       t2.join();
       dlclose(handle);
       return 0;
   }
   ```
   在这个例子中，每个线程都有自己独立的 `counter` 变量，所以输出结果会是每个线程从 1 递增到 5，而不是两个线程共享一个计数器。

2. **在动态加载的库中使用 TLS，但没有正确处理初始化顺序:**  如果一个动态加载的库的 TLS 变量依赖于其他库的初始化，可能会出现问题。动态链接器会确保 TLS 变量在首次访问时被初始化，但这并不保证跨库的初始化顺序。
3. **过度使用 TLS 导致内存消耗增加:**  虽然 TLS 方便了线程安全编程，但每个线程都有一份 TLS 变量的副本，如果大量使用 TLS 变量，可能会导致内存消耗增加。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

`elftls_dtv_resize_helper.cpp` 位于 Bionic 的测试目录中，它本身不是 Android Framework 或 NDK 的直接组成部分。但是，它测试的功能是 Android 系统运行时的核心机制。

**NDK 的路径:**

1. **NDK 开发者使用 TLS:** NDK 开发者可以使用 `__thread` 关键字声明线程局部变量。
2. **编译 NDK 代码:** 当 NDK 代码被编译成共享库时，编译器会生成与 TLS 相关的代码和元数据。
3. **应用加载 NDK 库:** 当 Android 应用加载 NDK 编译的共享库时，动态链接器会参与加载过程，并为这些库的 TLS 数据分配空间。

**Android Framework 的路径:**

1. **Framework 内部使用 TLS:** Android Framework 的许多 native 组件（例如 ART 虚拟机、System Server 的 native 部分等）都使用了 TLS 来管理线程特定的状态。
2. **Framework 库的加载:** 当 Android 系统启动或运行时，Framework 的各种共享库会被动态加载。动态链接器会处理这些库的 TLS 初始化和 DTV 管理。

**到达 `elftls_dtv_resize_helper.cpp` 测试场景的步骤 (逻辑上的，非实际执行路径):**

1. **应用或系统服务启动一个新线程。**
2. **动态链接器加载包含 TLS 变量的共享库 (无论是 Framework 的库还是 NDK 的库)。**
3. **线程首次访问该共享库的 TLS 变量。**
4. **动态链接器检查当前线程的 DTV 是否有足够的空间。**
5. **如果空间不足，动态链接器会分配更大的 DTV 并更新相关数据结构。**

**Frida Hook 示例调试步骤:**

我们可以使用 Frida 来 Hook 动态链接器中与 DTV 管理相关的函数，以观察 DTV 的变化。以下是一个示例，Hook 了 `__get_tcb_dtv` 函数，该函数返回当前线程的 DTV 指针。

```python
import frida
import sys

# 要附加的进程名称或进程 ID
package_name = "com.example.myapp" # 替换为你的应用包名

# Frida 脚本
hook_script = """
Interceptor.attach(Module.findExportByName(null, "__get_tcb_dtv"), {
    onEnter: function(args) {
        console.log("[*] __get_tcb_dtv called");
        // 可以进一步检查调用栈，确定调用时机
        // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));
    },
    onLeave: function(retval) {
        console.log("[*] __get_tcb_dtv returned: " + retval);
        // 可以检查 DTV 的内容
        if (retval.isNull()) {
            console.log("[!] DTV is NULL");
        } else {
            // 假设 TlsDtv 结构如下 (需要根据实际情况调整)
            // struct TlsDtv {
            //   size_t count;
            //   TlsDtv* next;
            //   uint64_t generation;
            //   void* modules[];
            // };
            var dtv = ptr(retval);
            var count = dtv.readUSize();
            var next = dtv.add(Process.pointerSize).readPointer();
            var generation = dtv.add(2 * Process.pointerSize).readU64();
            console.log("    DTV count: " + count);
            console.log("    DTV next: " + next);
            console.log("    DTV generation: " + generation);
            // 可以遍历 modules 数组
            // for (let i = 0; i < count; i++) {
            //     var modulePtr = dtv.add(3 * Process.pointerSize + i * Process.pointerSize).readPointer();
            //     console.log("    Module[" + i + "]: " + modulePtr);
            // }
        }
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[Frida]:", message['payload'])
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(hook_script)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, press Ctrl+C to exit.")
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
except Exception as e:
    print(f"发生错误: {e}")
```

**使用步骤:**

1. **安装 Frida:** 确保你的开发机器上安装了 Frida 和 Frida-tools。
2. **运行目标应用:** 启动你想要调试的 Android 应用。
3. **运行 Frida 脚本:** 将上面的 Python 代码保存为 `hook_dtv.py`，然后在终端中运行 `python hook_dtv.py`。
4. **观察输出:** 当应用加载使用了 TLS 的库并访问其 TLS 变量时，Frida 脚本会拦截对 `__get_tcb_dtv` 的调用，并打印 DTV 的相关信息，包括 DTV 的指针、计数、下一个 DTV 和 generation。通过观察这些信息的变化，你可以了解 DTV 何时被访问以及可能何时发生了扩容。

**注意:**

* Hook 动态链接器的函数需要 root 权限或在可调试的应用上进行。
* 上面的 Frida 脚本只是一个基本示例，你可以根据需要 Hook 其他与 DTV 管理相关的函数（例如分配 DTV 内存的函数）来更深入地了解 DTV 的扩容过程。
* 需要根据目标 Android 版本的 Bionic 库中 `TlsDtv` 结构的实际定义来调整 Frida 脚本中读取 DTV 成员的代码。

希望这些详细的解释能够帮助你理解 `elftls_dtv_resize_helper.cpp` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/libs/elftls_dtv_resize_helper.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2024 The Android Open Source Project
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

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include <functional>
#include <iostream>

#include "bionic/pthread_internal.h"

constexpr bool kDumpModulesForDebugging = false;

// The old external/libcxx doesn't have operator<< for nullptr.
// TODO(b/175635923): Remove this hack after upgrading libc++.
template <class T>
T fix_nullptr(T&& arg) {
  return arg;
}
void* fix_nullptr(nullptr_t arg) {
  return static_cast<void*>(arg);
}

template <class Val1, class Val2, class Compare>
void check(int line, const char* val1_expr, Val1&& val1, const char* val2_expr, Val2&& val2,
           Compare compare) {
  if (!compare(val1, val2)) {
    std::cerr << __FILE__ << ":" << line << ": assertion failed: LHS(" << val1_expr << ") is "
              << fix_nullptr(val1) << ", RHS(" << val2_expr << ") is " << fix_nullptr(val2) << "\n"
              << std::flush;
    abort();
  }
}

#define ASSERT_EQ(val1, val2) check(__LINE__, #val1, val1, #val2, val2, std::equal_to())
#define ASSERT_NE(val1, val2) check(__LINE__, #val1, val1, #val2, val2, std::not_equal_to())
#define ASSERT_LT(val1, val2) check(__LINE__, #val1, val1, #val2, val2, std::less())
#define ASSERT_LE(val1, val2) check(__LINE__, #val1, val1, #val2, val2, std::less_equal())

static size_t highest_loaded_modid() {
  size_t result = 0;
  auto update_result = [](struct dl_phdr_info* info, size_t size __unused, void* data) {
    size_t& result = *reinterpret_cast<size_t*>(data);
    if (kDumpModulesForDebugging) {
      fprintf(stderr, "module %s: TLS modid %zu\n", info->dlpi_name, info->dlpi_tls_modid);
    }
    result = std::max(result, info->dlpi_tls_modid);
    return 0;
  };
  dl_iterate_phdr(update_result, &result);
  return result;
}

static TlsDtv* dtv() {
  return __get_tcb_dtv(__get_bionic_tcb());
}

static size_t highest_modid_in_dtv() {
  TlsDtv* current_dtv = dtv();
  size_t result = 0;
  for (size_t i = 0; i < current_dtv->count; ++i) {
    if (current_dtv->modules[i] != nullptr) {
      result = __tls_module_idx_to_id(i);
    }
  }
  return result;
}

// Unused, but ensures that the test executable has a TLS segment. With a
// new-enough libc++_static.a, the test executable will tend to has a TLS
// segment to hold the libc++ EH globals pointer.
__thread int g_tls_var_placeholder = 42;

int main() {
  // Prevent this TLS variable from being optimized away.
  ASSERT_EQ(42, g_tls_var_placeholder);

  auto load_lib = [](const char* soname) {
    void* lib = dlopen(soname, RTLD_LOCAL | RTLD_NOW);
    ASSERT_NE(nullptr, lib);
    auto func = reinterpret_cast<int (*)()>(dlsym(lib, "bump"));
    ASSERT_NE(nullptr, func);
    return func;
  };

  static_assert(sizeof(TlsDtv) == 3 * sizeof(void*),
                "This test assumes that the Dtv has a 3-word header");

  // Initially there are 2-4 modules:
  //  - 1: test executable
  //  - 2: libc
  //  - 3: libc++ (when using a new-enough libc++)
  //  - 4: libclang_rt.hwasan (when running with HWASan)
  size_t first_filler_modid = highest_loaded_modid() + 1;
  ASSERT_LE(2, highest_loaded_modid());
  ASSERT_LE(highest_loaded_modid(), 4);

  // The initial DTV is an empty DTV with no generation and a size of 0.
  TlsDtv* zero_dtv = dtv();
  ASSERT_EQ(0u, zero_dtv->count);
  ASSERT_EQ(nullptr, zero_dtv->next);
  ASSERT_EQ(kTlsGenerationNone, zero_dtv->generation);

  // Load a module. The DTV is still empty unless the TLS variable is accessed.
  auto func1 = load_lib("libtest_elftls_dynamic_filler_1.so");
  ASSERT_EQ(zero_dtv, dtv());
  ASSERT_EQ(first_filler_modid, highest_loaded_modid());

  // After accessing a TLS variable, the DTV should be initialized. It should be
  // 8 words in size, with a 5-entry capacity.
  ASSERT_EQ(101, func1());
  TlsDtv* initial_dtv = dtv();
  ASSERT_EQ(5u, dtv()->count);
  ASSERT_EQ(zero_dtv, initial_dtv->next);
  ASSERT_LT(0u, initial_dtv->generation);
  ASSERT_EQ(first_filler_modid, highest_modid_in_dtv());
  ASSERT_NE(nullptr, initial_dtv->modules[__tls_module_id_to_idx(first_filler_modid)]);

  size_t current_generation = initial_dtv->generation;

  // Fill the rest of the DTV up. (i.e. Ensure that exactly 5 modules with TLS
  // segments are loaded.)
  auto fill_entry = [&](size_t modid, const char* soname, int tls_var_value) {
    if (highest_modid_in_dtv() == modid - 1) {
      auto func = load_lib(soname);

      // Loading the module doesn't affect the DTV yet.
      ASSERT_EQ(initial_dtv, dtv());
      ASSERT_EQ(modid, highest_loaded_modid());
      ASSERT_EQ(modid - 1, highest_modid_in_dtv());
      ASSERT_EQ(current_generation, initial_dtv->generation);

      // Access the TLS variable, which will allocate it in the DTV.
      ASSERT_EQ(tls_var_value, func());

      // Verify allocation and a bumped generation.
      ASSERT_EQ(initial_dtv, dtv());
      ASSERT_EQ(modid, highest_modid_in_dtv());
      ASSERT_LT(current_generation, initial_dtv->generation);
      current_generation = initial_dtv->generation;
    }
  };

  fill_entry(4u, "libtest_elftls_dynamic_filler_2.so", 201);
  fill_entry(5u, "libtest_elftls_dynamic_filler_3.so", 301);
  ASSERT_EQ(5u, highest_modid_in_dtv());

  // Load module 6, which will require doubling the size of the DTV.
  auto func4 = load_lib("libtest_elftls_dynamic_filler_4.so");
  ASSERT_EQ(6u, highest_loaded_modid());
  ASSERT_EQ(5u, highest_modid_in_dtv());
  ASSERT_EQ(initial_dtv, dtv());

  // Access a TLS variable from the first filler module.
  ASSERT_EQ(102, func1());
  ASSERT_EQ(5u, highest_modid_in_dtv());
#if defined(__aarch64__) || defined(__riscv)
  // The arm64 and riscv64 TLSDESC resolver doesn't update the DTV if it is new enough for
  // the given access.
  ASSERT_EQ(initial_dtv, dtv());
  ASSERT_EQ(5u, dtv()->count);
  ASSERT_EQ(current_generation, dtv()->generation);
#else
  // __tls_get_addr updates the DTV anytime the generation counter changes, but
  // the highest modid in the DTV is still 5, because module 6 hasn't been
  // allocated yet.
  ASSERT_NE(initial_dtv, dtv());
  ASSERT_EQ(13u, dtv()->count);
  ASSERT_LT(current_generation, dtv()->generation);
#endif

  // Accessing the TLS variable in the latest module will always expand the DTV.
  ASSERT_EQ(401, func4());
  TlsDtv* new_dtv = dtv();
  ASSERT_NE(initial_dtv, new_dtv);
  ASSERT_EQ(initial_dtv, new_dtv->next);
  ASSERT_EQ(13u, new_dtv->count);
  ASSERT_LT(current_generation, new_dtv->generation);
  ASSERT_EQ(6u, highest_modid_in_dtv());
  current_generation = new_dtv->generation;

  // Load one more filler, module 7.
  auto func5 = load_lib("libtest_elftls_dynamic_filler_5.so");
  ASSERT_EQ(103, func1());
  ASSERT_EQ(402, func4());
  ASSERT_EQ(6u, highest_modid_in_dtv());
  ASSERT_EQ(501, func5());
  ASSERT_EQ(7u, highest_modid_in_dtv());

  // Verify that no new DTV has been allocated.
  ASSERT_EQ(new_dtv, dtv());
  ASSERT_EQ(13u, new_dtv->count);
  ASSERT_LT(current_generation, new_dtv->generation);

  return 0;
}

"""

```