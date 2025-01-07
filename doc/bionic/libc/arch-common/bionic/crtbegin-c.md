Response:
Let's break down the thought process to generate the comprehensive answer about `crtbegin.c`.

**1. Understanding the Core Request:**

The request asks for a detailed explanation of the `crtbegin.c` file within Android Bionic. Key aspects to address include:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it relate to the broader Android system?
* **libc Function Explanation:** Deep dive into the functions it calls, particularly `__libc_init`.
* **Dynamic Linker Involvement:**  How does it interact with the dynamic linker? (SO layout and linking process).
* **Logic/Assumptions:** If there's conditional logic, what are the inputs and outputs?
* **Common Errors:** What programming mistakes could relate to this code?
* **Android Framework/NDK Path:** How does execution reach this code?
* **Frida Hooking:**  How can we observe this in action?

**2. Initial Analysis of the Code:**

The first step is to read the provided `crtbegin.c` source code carefully. Key observations:

* **Includes:** It includes `<stddef.h>`, `<stdint.h>`, and `"../../bionic/libc_init_common.h"`, hinting at its role in the very early stages of program startup.
* **Global Symbols:** It declares external symbols like `__preinit_array_start`, `__init_array_start`, `__fini_array_start`, which are clearly related to initialization and finalization.
* **`call_fini_array`:** This function explicitly deals with calling finalization functions. The sentinels are a curious detail.
* **`_start_main`:** This function seems to be the core logic, setting up initialization and calling `__libc_init`.
* **Assembly Code:**  Significant blocks of assembly are present for various architectures. This immediately suggests it's the entry point of the program.
* **`__dso_handle.h`, `atexit.h`, `pthread_atfork.h`:** These includes further solidify its role in libc initialization and thread-related setup.
* **Conditional Compilation (`#if defined(CRTBEGIN_STATIC)`)**:  This indicates different behavior for static and dynamic linking.
* **TLS Alignment:** The code mentions TLS alignment for newer Android versions, highlighting its awareness of low-level system details.

**3. Deconstructing the Functionality:**

Based on the initial analysis, the core functionalities emerge:

* **Entry Point:**  The assembly code makes it clear that `_start` is the program's entry point.
* **Initialization Array Handling:**  `_start_main` collects addresses of initialization functions (`__preinit_array`, `__init_array`).
* **Finalization Array Handling:**  `call_fini_array` handles finalization functions (`__fini_array`).
* **`__libc_init` Call:** The crucial call to `__libc_init` signals the beginning of libc's initialization.

**4. Connecting to Android:**

Now, relate these functionalities to the Android ecosystem:

* **Application Startup:** `crtbegin.c` is the very first code executed when an Android app (or native executable) starts.
* **Bionic's Role:** As part of Bionic, it's responsible for setting up the runtime environment for C/C++ code.
* **Dynamic Linking:**  The presence of finalization arrays and the conditional logic for static linking directly connects to dynamic linking.

**5. Explaining Key Functions:**

* **`call_fini_array`:** The explanation needs to cover the purpose of finalization functions (destructors, cleanup), the reverse order of execution, and the sentinel values (likely for robustness or linker conventions).
* **`_start_main`:** Explain how it collects the initialization and finalization function pointers and passes them to `__libc_init`.
* **`__libc_init`:** This requires a more detailed explanation, as it's the heart of libc initialization. The answer needs to cover its key responsibilities: argument parsing, environment setup, TLS setup, auxiliary vector processing, atexit handling, and finally calling `main`.

**6. Addressing Dynamic Linking:**

* **SO Layout:** Describe the typical structure of a shared object, highlighting the `.init_array`, `.fini_array`, and how the dynamic linker maps these sections.
* **Linking Process:**  Explain the role of the dynamic linker in resolving symbols, relocating code, and calling the initialization functions in the correct order. Mention the steps involved (loading, resolving, relocating, initialization).

**7. Considering Logic and Assumptions:**

* **Static vs. Dynamic Linking:** Explain how the `#ifdef CRTBEGIN_STATIC` affects the handling of the finalization array. Provide an example of how this would differ.

**8. Identifying Common Errors:**

Think about common programming mistakes that could interact with this low-level code:

* **Missing `main`:**  The program won't start.
* **Incorrect Initialization/Finalization:**  Resources might not be properly set up or cleaned up.
* **Double-Free/Use-After-Free in Destructors:** This can lead to crashes during finalization.

**9. Tracing the Execution Path:**

* **Android Framework/NDK:**  Describe the sequence from launching an app/process, to Zygote forking, to the dynamic linker loading the executable, and finally reaching `_start` in `crtbegin.c`.

**10. Providing Frida Hooks:**

Craft concrete Frida examples to demonstrate how to hook into `_start`, `_start_main`, `__libc_init`, and functions within the initialization/finalization arrays. This makes the explanation more practical.

**11. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use formatting (bolding, code blocks) to improve readability.

**Self-Correction/Refinement During Thought Process:**

* **Initial Thought:**  Focus solely on the C code.
* **Correction:** Realize the assembly code is crucial for understanding the entry point.
* **Initial Thought:**  Explain `__libc_init` briefly.
* **Correction:** Recognize its importance and provide a more detailed breakdown.
* **Initial Thought:**  Just mention dynamic linking.
* **Correction:** Include details about SO layout and the linking process.
* **Initial Thought:** Generic examples for errors.
* **Correction:**  Tailor the examples to the context of initialization and finalization.

By following this thought process, combining code analysis with understanding of the Android runtime and dynamic linking, and continually refining the explanations, we can arrive at a comprehensive and accurate answer.
好的，我们来详细分析一下 `bionic/libc/arch-common/bionic/crtbegin.c` 这个文件。

**功能概述**

`crtbegin.c` 是 Android Bionic C 库中与程序启动密切相关的一个源文件。它的主要功能是：

1. **程序入口点 (`_start`):**  定义了程序的实际入口点。这是操作系统加载程序后执行的第一段代码。
2. **C 运行时环境初始化前的工作:** 在执行 `main` 函数之前，进行一些必要的初始化工作。
3. **调用初始化函数 (`__preinit_array`, `__init_array`):**  执行在编译时标记为需要在 `main` 函数之前执行的函数。这通常用于 C++ 静态对象的构造等。
4. **为动态链接库准备 `fini_array`:**  对于动态链接的程序，准备用于在程序退出时调用析构函数的数组 (`__fini_array`)。
5. **调用 `__libc_init`:**  这是 Bionic C 库的核心初始化函数，负责更广泛的运行时环境设置。

**与 Android 功能的关系及举例说明**

`crtbegin.c` 是 Android 应用程序和 native 进程启动的基石。它确保了在执行用户代码之前，C 运行时环境处于一个正确的、可用的状态。

* **应用程序启动:** 当 Android 系统启动一个应用程序时，Zygote 进程会 fork 出一个新的进程。这个新进程加载应用程序的可执行文件，而 `crtbegin.c` 中定义的 `_start` 就是这个可执行文件的入口点。
* **NDK 开发:** 使用 Android NDK 开发 native 代码时，编译出的共享库或可执行文件同样会包含类似的 `crtbegin.c` 的逻辑 (尽管可能有所不同，例如 `crtbegin_so.c` 用于共享库)。这确保了 native 代码的正常初始化。
* **系统服务:** Android 的许多系统服务也是使用 C++ 编写的，它们的启动过程同样会涉及到 `crtbegin.c` 的执行。

**每一个 libc 函数的功能实现**

在这个文件中，我们主要看到的是对 `__libc_init` 的调用。

* **`__libc_init(void* raw_args, void (*fini_fn)(void), void (*app_main)(int, char**, char**), structors_array_t* structors)`:**

   `__libc_init` 是 Bionic C 库中非常重要的一个函数，它负责执行一系列关键的初始化步骤，以便程序能够正常运行。其实现位于 `bionic/libc/bionic/libc_init_common.c` 或类似的文件中。其主要功能包括：

   1. **参数处理:** 解析命令行参数 (`raw_args`)。
   2. **环境变量设置:** 初始化和处理环境变量。
   3. **TLS (Thread Local Storage) 设置:** 为线程局部存储分配和初始化内存。
   4. **Auxiliary Vector 处理:** 处理来自内核的辅助向量信息，这些信息包含了关于系统和硬件的信息。
   5. **`atexit` 处理:** 初始化 `atexit` 机制，用于在程序退出时注册需要执行的函数。
   6. **`pthread_atfork` 处理:** 初始化 `pthread_atfork` 机制，用于在 `fork` 调用前后执行特定的处理函数。
   7. **调用初始化函数:** 执行 `structors` 参数中指定的初始化函数 (来自 `__preinit_array` 和 `__init_array`)。
   8. **调用 `main` 函数:**  最终调用应用程序的 `main` 函数 (`app_main`)，并将解析后的参数传递给它。

**涉及 dynamic linker 的功能、SO 布局样本及链接处理过程**

`crtbegin.c` 中与动态链接器相关的主要是对 `__fini_array` 的处理。

**SO 布局样本：**

一个典型的动态链接的共享库 (SO) 或可执行文件的内存布局中，与 `crtbegin.c` 相关的段包括：

```
.text        :  代码段，包含可执行指令，包括 _start 函数等
.rodata      :  只读数据段，包含字符串字面量、常量等
.data        :  已初始化的全局变量和静态变量
.bss         :  未初始化的全局变量和静态变量
.init_array  :  初始化函数指针数组
.fini_array  :  终止化函数指针数组
```

**链接处理过程：**

1. **链接器 (ld):** 在编译链接阶段，链接器会将所有编译后的目标文件 (.o) 合并成一个可执行文件或共享库。
2. **`.init_array` 和 `.fini_array` 的填充:**  编译器会在目标文件中生成 `.init_array` 和 `.fini_array` 段，并将标记为需要在程序启动和退出时执行的函数的地址放入这些段中。例如，C++ 全局对象的构造函数会被放入 `.init_array`，析构函数会被放入 `.fini_array`。
3. **动态链接器 (linker):** 当操作系统加载动态链接的程序时，动态链接器负责：
   * **加载共享库:**  将程序依赖的共享库加载到内存中。
   * **符号解析:**  解析程序和共享库之间的符号引用，将函数调用和变量访问指向正确的地址。
   * **重定位:**  调整代码和数据中的地址，使其在内存中的实际位置正确。
   * **执行初始化函数:** 在完成加载和链接后，动态链接器会遍历所有加载的共享库和可执行文件的 `.init_array` 段，并按照顺序调用其中的函数。这对应于 `crtbegin.c` 中 `__libc_init` 调用初始化数组的步骤。
   * **注册终止化函数:** 动态链接器也会记录每个共享库和可执行文件的 `.fini_array` 段，以便在程序退出时调用其中的函数。

**`crtbegin.c` 中对 `fini_array` 的处理：**

```c
#if !defined(CRTBEGIN_STATIC)
static void call_fini_array() {
  fini_func_t** array = __fini_array_start;
  size_t count = __fini_array_end - __fini_array_start;
  while (count-- > 0) {
    fini_func_t* function = array[count];
    (*function)();
  }
}

static fini_func_t* fini_array_with_sentinels[] = {
    (fini_func_t*)-1,
    &call_fini_array,
    (fini_func_t*)0,
};
#endif

__used static void _start_main(void* raw_args) {
  structors_array_t array = {};
#if defined(CRTBEGIN_STATIC)
  // ... (静态链接情况)
#else
  if (__fini_array_end - __fini_array_start > 0) {
    array.fini_array = fini_array_with_sentinels;
  }
#endif
  // ...
}
```

对于动态链接的情况 (`!defined(CRTBEGIN_STATIC)`),  `crtbegin.c` 定义了一个包含哨兵值的 `fini_array_with_sentinels` 数组。这个数组中包含一个指向 `call_fini_array` 函数的指针。当程序正常退出时，C 运行时库会调用 `call_fini_array`，它会遍历 `.fini_array` 段中的函数指针，并按照**相反的顺序**调用这些函数。这确保了对象析构的正确顺序，例如，后构造的对象先析构。

**逻辑推理：假设输入与输出**

* **假设输入：** 一个简单的动态链接的 C++ 可执行文件，其中定义了一个全局对象 `MyObject`，其构造函数和析构函数会打印消息。
* **输出：**
   1. 程序启动时，动态链接器加载可执行文件和依赖的共享库。
   2. 动态链接器执行 `.init_array` 中的函数，`MyObject` 的构造函数被调用，打印 "MyObject constructed"。
   3. 应用程序的 `main` 函数执行。
   4. 程序退出时，C 运行时库调用 `call_fini_array`。
   5. `call_fini_array` 遍历 `.fini_array`，`MyObject` 的析构函数被调用，打印 "MyObject destructed"。

**涉及用户或者编程常见的使用错误**

1. **未定义 `main` 函数:**  如果程序中没有定义 `main` 函数，链接器会报错，因为 `crtbegin.c` 最终需要调用 `main`。
2. **全局对象的构造/析构顺序依赖错误:**  由于 `.init_array` 和 `.fini_array` 中函数执行的顺序由链接器决定，因此不应该依赖不同编译单元中全局对象的构造和析构的特定顺序。
3. **在全局对象的构造函数或析构函数中进行复杂操作或访问未初始化的资源:** 由于这些函数在 `main` 函数执行之前或之后运行，此时的运行时环境可能尚未完全初始化或已经部分销毁，进行不安全的操作可能导致崩溃或未定义的行为。
4. **静态链接时的 `fini_array` 使用不当:**  在静态链接的情况下，`crtbegin.c` 直接使用 `.fini_array`。错误地使用或修改 `.fini_array` 可能会导致程序退出时出现问题。

**Android framework or ndk 是如何一步步的到达这里**

**Android Framework 应用程序启动流程:**

1. **用户启动应用:** 用户点击应用图标或通过其他方式启动应用程序。
2. **ActivityManagerService (AMS):**  AMS 接收到启动应用的请求。
3. **Zygote 进程:** AMS 向 Zygote 进程发送 fork 请求。Zygote 是 Android 中所有应用程序进程的父进程，它预先加载了常用的库和资源，以加速应用启动。
4. **Fork 新进程:** Zygote 进程 fork 出一个新的子进程。
5. **加载应用程序:** 新进程执行应用的入口点，通常由 `app_process` 或类似的进程负责。
6. **动态链接器 (linker):** 动态链接器被调用，负责加载应用程序的可执行文件 (DEX 文件被解释或编译成本地代码) 和其依赖的 native 库 (.so 文件)。
7. **加载 native 库:** 如果应用包含 native 代码，动态链接器会加载这些 native 库。
8. **执行 `_start`:** 对于 native 库或可执行文件，动态链接器会找到入口点 `_start`，这是在 `crtbegin.c` 中定义的。
9. **执行初始化:** 从这里开始，就进入了 `crtbegin.c` 的逻辑，包括调用 `_start_main` 和 `__libc_init`，执行初始化数组中的函数，最终调用 `main` 函数。

**NDK 开发流程:**

1. **编写 Native 代码:**  开发者使用 C/C++ 编写 native 代码。
2. **编译 Native 代码:** 使用 NDK 的工具链（例如 Clang）编译 native 代码，生成共享库 (.so 文件)。
3. **打包到 APK:**  编译后的共享库会被打包到 APK 文件中。
4. **应用启动 (如上所述):** 当包含 native 代码的应用启动时，动态链接器会加载这些共享库。
5. **执行共享库的初始化:**  与应用程序的可执行文件类似，共享库也会有自己的 `crtbegin.c` (通常是 `crtbegin_so.c` 或类似名称)，其 `_start` 函数会被执行，完成共享库的初始化。

**Frida Hook 示例调试步骤**

我们可以使用 Frida hook 关键函数来观察 `crtbegin.c` 的执行过程。以下是一个简单的示例：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用程序的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit(1)

script_code = """
console.log("Script loaded");

// Hook _start 函数
Interceptor.attach(Module.findExportByName(null, "_start"), {
    onEnter: function(args) {
        console.log("[_start] Entered");
    },
    onLeave: function(retval) {
        console.log("[_start] Leaving, return value:", retval);
    }
});

// Hook _start_main 函数
Interceptor.attach(Module.findExportByName(null, "_start_main"), {
    onEnter: function(args) {
        console.log("[_start_main] Entered, arguments:", args[0]);
    },
    onLeave: function(retval) {
        console.log("[_start_main] Leaving");
    }
});

// Hook __libc_init 函数
Interceptor.attach(Module.findExportByName(null, "__libc_init"), {
    onEnter: function(args) {
        console.log("[__libc_init] Entered, raw_args:", args[0], "fini_fn:", args[1], "app_main:", args[2], "structors:", args[3]);
    }
});

// Hook 初始化数组中的函数 (需要找到具体的函数地址或符号)
// 示例：假设有一个名为 my_init_function 的初始化函数
// const myInitFuncAddr = Module.findExportByName(null, "my_init_function");
// if (myInitFuncAddr) {
//     Interceptor.attach(myInitFuncAddr, {
//         onEnter: function(args) {
//             console.log("[my_init_function] Entered");
//         }
//     });
// }

"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤：**

1. **安装 Frida 和 frida-tools:** 确保你的电脑上安装了 Frida 和 frida-tools。
2. **连接 Android 设备:** 将你的 Android 设备连接到电脑，并确保 adb 可以正常工作。
3. **运行 Frida Server:** 在你的 Android 设备上运行 Frida Server。
4. **修改 Python 脚本:** 将 `你的应用包名` 替换为你要调试的应用程序的包名。
5. **运行 Python 脚本:** 运行上述 Python 脚本。
6. **启动应用程序:** 在 Android 设备上启动你要调试的应用程序。

**预期输出:**

当你启动应用程序时，Frida 会 hook 到指定的函数，并在控制台上输出相应的日志信息，例如：

```
[*] Script loaded
[*] [_start] Entered
[*] [_start] Leaving, return value: 0
[*] [_start_main] Entered, arguments: [object Object]
[*] [__libc_init] Entered, raw_args: [object Object] fini_fn: null app_main: [object Object] structors: [object Object]
```

通过这种方式，你可以观察程序启动时 `crtbegin.c` 中关键函数的执行情况，以及传递的参数。你可以进一步扩展这个脚本，hook 初始化数组和终止化数组中的函数，以更深入地了解程序的启动和退出过程。

希望以上详细的解释能够帮助你理解 `bionic/libc/arch-common/bionic/crtbegin.c` 的功能和作用。

Prompt: 
```
这是目录为bionic/libc/arch-common/bionic/crtbegin.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2012 The Android Open Source Project
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

#include "../../bionic/libc_init_common.h"
#include <stddef.h>
#include <stdint.h>

extern init_func_t* __preinit_array_start[];
extern init_func_t* __preinit_array_end[];
extern init_func_t* __init_array_start[];
extern init_func_t* __init_array_end[];
extern fini_func_t* __fini_array_start[];
extern fini_func_t* __fini_array_end[];

#if !defined(CRTBEGIN_STATIC)
/* This function will be called during normal program termination
 * to run the destructors that are listed in the .fini_array section
 * of the executable, if any.
 *
 * 'fini_array' points to a list of function addresses.
 */
static void call_fini_array() {
  fini_func_t** array = __fini_array_start;
  size_t count = __fini_array_end - __fini_array_start;
  // Call fini functions in reverse order.
  while (count-- > 0) {
    fini_func_t* function = array[count];
    (*function)();
  }
}

// libc.so needs fini_array with sentinels. So create a fake fini_array with sentinels.
// It contains a function to call functions in real fini_array.
static fini_func_t* fini_array_with_sentinels[] = {
    (fini_func_t*)-1,
    &call_fini_array,
    (fini_func_t*)0,
};
#endif  // !defined(CRTBEGIN_STATIC)

__used static void _start_main(void* raw_args) {
  structors_array_t array = {};
#if defined(CRTBEGIN_STATIC)
  array.preinit_array = __preinit_array_start;
  array.preinit_array_count = __preinit_array_end - __preinit_array_start;
  array.init_array = __init_array_start;
  array.init_array_count = __init_array_end - __init_array_start;
  array.fini_array = __fini_array_start;
  array.fini_array_count = __fini_array_end - __fini_array_start;
#else
  if (__fini_array_end - __fini_array_start > 0) {
    array.fini_array = fini_array_with_sentinels;
  }
#endif  // !defined(CRTBEGIN_STATIC)

  __libc_init(raw_args, NULL, &main, &array);
}

#define PRE ".text; .global _start; .type _start,%function; _start:"
#define POST "; .size _start, .-_start"

#if defined(__aarch64__)
__asm__(PRE "bti j; mov x29,#0; mov x30,#0; mov x0,sp; b _start_main" POST);
#elif defined(__arm__)
__asm__(PRE "mov fp,#0; mov lr,#0; mov r0,sp; b _start_main" POST);
#elif defined(__i386__)
__asm__(PRE
        "xorl %ebp,%ebp; movl %esp,%eax; andl $~0xf,%esp; subl $12,%esp; pushl %eax;"
        "call _start_main" POST);
#elif defined(__riscv)
__asm__(PRE "li fp,0; li ra,0; mv a0,sp; tail _start_main" POST);
#elif defined(__x86_64__)
__asm__(PRE "xorl %ebp, %ebp; movq %rsp,%rdi; andq $~0xf,%rsp; callq _start_main" POST);
#else
#error unsupported architecture
#endif

#undef PRE
#undef POST

// On arm32 and arm64, when targeting Q and up, overalign the TLS segment to
// (8 * sizeof(void*)), which reserves enough space between the thread pointer
// and the executable's TLS segment for Bionic's TLS slots. It has the side
// effect of placing a 0-sized TLS segment into Android executables that don't
// use TLS, but this should be harmless.
//
// To ensure that the .tdata input section isn't deleted (e.g. by
// --gc-sections), the .text input section (which contains _start) has a
// relocation to the .tdata input section.
#if __ANDROID_API__ >= 29
#if defined(__arm__)
asm("  .section .tdata,\"awT\",%progbits\n"
    "  .p2align 5\n"
    "  .text\n"
    "  .reloc 0, R_ARM_NONE, .tdata\n");
#elif defined(__aarch64__)
asm("  .section .tdata,\"awT\",@progbits\n"
    "  .p2align 6\n"
    "  .text\n"
    "  .reloc 0, R_AARCH64_NONE, .tdata\n");
#endif
#endif

#include "__dso_handle.h"
#include "atexit.h"
#include "pthread_atfork.h"

"""

```