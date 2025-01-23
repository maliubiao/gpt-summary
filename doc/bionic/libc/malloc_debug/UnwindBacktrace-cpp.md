Response:
Let's break down the thought process for analyzing this C++ code snippet. The goal is to understand its functionality, its relation to Android, how it works internally (especially `libc` functions and the dynamic linker), potential usage errors, and how it's invoked within the Android framework. Finally, we need to provide a Frida hook example.

**1. Initial Code Scan and High-Level Understanding:**

* **Keywords:**  Immediately spot keywords like `unwind`, `backtrace`, `frames`, `pc`, `map_info`, `function_name`, `demangle`. These strongly suggest the code is related to stack unwinding and getting information about function calls.
* **Includes:**  Look at the included headers:
    * `<cxxabi.h>`:  Signals C++ ABI-related functions, likely for demangling symbols.
    * `<inttypes.h>`, `<stdint.h>`: Standard integer types.
    * `<pthread.h>`:  Threading related, though not directly used in this snippet, it hints at the context where this might be called.
    * `<algorithm>`, `<memory>`, `<string>`, `<vector>`: Standard C++ library components.
    * `<android-base/stringprintf.h>`: Android-specific string formatting.
    * `<unwindstack/AndroidUnwinder.h>`, `<unwindstack/Unwinder.h>`: Core unwinding functionality from the `unwindstack` library.
    * `"UnwindBacktrace.h"`, `"debug_log.h"`: Local headers, suggesting this is part of a larger module.
* **Function Signatures:** Analyze the main functions:
    * `Unwind(std::vector<uintptr_t>*, std::vector<unwindstack::FrameData>*, size_t)`: Takes vectors to store frame addresses and detailed frame information, along with a maximum frame count. Returns a boolean indicating success.
    * `UnwindLog(const std::vector<unwindstack::FrameData>&)`:  Takes a vector of frame information and logs it in a human-readable format.

**2. Dissecting the `Unwind` Function:**

* **Static Unwinder:** The `[[clang::no_destroy]] static unwindstack::AndroidLocalUnwinder unwinder(...)` line is crucial. It creates a *static* unwinder object. The `no_destroy` attribute likely ensures it's not destroyed when the function exits, persisting across calls. The constructor argument `{"libc_malloc_debug.so"}` suggests this unwinder is specifically designed to unwind the stack while inside `libc_malloc_debug.so`. This is a *local* unwinder.
* **`AndroidUnwinderData`:**  An object to hold the unwinding results.
* **`unwinder.Unwind(data)`:** This is the core unwinding call. It uses the configured unwinder to walk the stack and fill the `data` object.
* **Error Handling:** The `if (!unwinder.Unwind(data))` check indicates that unwinding can fail. If it does, the output vectors are cleared.
* **Result Population:**  The code then copies the program counter (PC) values from `data.frames` to the `frames` vector and moves the entire `data.frames` vector to `frame_info`.

**3. Dissecting the `UnwindLog` Function:**

* **Iteration:**  Loops through the `frame_info` vector.
* **Formatting:** Uses `android::base::StringPrintf` for formatted output.
* **Map Information:** Accesses `info->map_info` to get information about the memory mapping where the function resides (name, offset, start address).
* **Symbol Demangling:**  Calls `abi::__cxa_demangle` to convert mangled C++ symbol names into human-readable form. This is essential for understanding stack traces. Remembering to `free` the demangled name is important.
* **Function Offset:**  Appends the offset within the function.
* **Logging:** Uses `error_log_string` (presumably a macro or function defined in `"debug_log.h"`) to output the formatted stack frame information.

**4. Connecting to Android Functionality:**

* **Memory Allocation Debugging:** The file path `bionic/libc/malloc_debug/UnwindBacktrace.cpp` immediately suggests this code is part of the memory allocation debugging tools in Android's C library.
* **Stack Traces for Debugging:** Unwinding is a fundamental part of debugging crashes, memory leaks, and other issues. Android uses stack traces extensively in error reporting and logging.
* **`unwindstack` Library:** Recognizing the use of `unwindstack` points to Android's dedicated library for reliable stack unwinding.

**5. Dynamic Linker Aspects:**

* **`map_info`:** The `map_info` obtained during unwinding contains information about the loaded shared objects (SOs). This directly involves the dynamic linker.
* **SO Layout Sample:**  Thinking about how SOs are laid out in memory is important. Imagine a simple case with the main executable and a single shared library.
* **Linking Process:** Briefly explain how the dynamic linker resolves symbols and loads libraries at runtime.

**6. Potential Usage Errors:**

* **Incorrect `max_frames`:**  Providing too small a value for `max_frames` will truncate the backtrace.
* **Not Checking Return Value:**  Failing to check the boolean return value of `Unwind` means you might process an empty or incomplete backtrace.
* **Memory Management with Demangling:** Forgetting to `free` the result of `abi::__cxa_demangle` leads to memory leaks.

**7. Android Framework/NDK Path:**

* **Framework Example:** Trace a scenario where a native crash might occur in an Android app. The framework's error handling mechanism would likely trigger the unwinding process.
* **NDK Example:**  A similar flow applies to NDK apps. A crash in native code would involve unwinding.

**8. Frida Hook Example:**

* **Target Function:** Choose a relevant function to hook, such as `UnwindLog`.
* **Basic Hook Structure:**  Use Frida's `Interceptor.attach` to intercept the function.
* **Argument Access:** Show how to access the `frame_info` argument.
* **Custom Logging:** Demonstrate how to log the frame information from within the hook.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks like standard stack unwinding."  **Refinement:** "It's *specifically* for `libc_malloc_debug.so` based on the `AndroidLocalUnwinder` initialization. This suggests a focused use case."
* **Initial thought:** "Just list the libc functions used." **Refinement:** "Actually, there's only `free` from `libc` directly. The core unwinding logic is in `unwindstack`. Focus on explaining `free` and the role of `unwindstack`."
* **Initial thought:** "Explain dynamic linking in general." **Refinement:** "Focus on *how* it relates to the `map_info` and how the linker's work makes unwinding possible by providing the necessary information."

By following this structured approach, combining code analysis with knowledge of Android internals and debugging techniques, you can arrive at a comprehensive explanation like the example provided.
这个文件 `bionic/libc/malloc_debug/UnwindBacktrace.cpp` 是 Android Bionic 库中 `malloc_debug` 组件的一部分，主要功能是用于 **获取和记录调用栈回溯 (backtrace)**。它的目的是在内存分配和释放相关的调试场景下，提供发生问题的上下文信息。

以下是它的详细功能分解和相关说明：

**1. 功能概述:**

* **`Unwind(std::vector<uintptr_t>* frames, std::vector<unwindstack::FrameData>* frame_info, size_t max_frames)`:**
    * **获取调用栈帧 (Stack Frames):**  这是核心功能。它使用 `unwindstack` 库来遍历当前的调用栈，并提取每一帧的信息。
    * **存储帧地址:** 将每一帧的程序计数器 (PC) 值存储到 `frames` 向量中。
    * **存储详细帧信息:** 将更详细的帧信息（例如，所在库的名称、函数名称、偏移量等）存储到 `frame_info` 向量中。
    * **限制帧数:**  `max_frames` 参数允许限制要获取的栈帧数量。
    * **针对特定库 (`libc_malloc_debug.so`) 的 Unwinding:**  它初始化了一个 `unwindstack::AndroidLocalUnwinder` 对象，并指定了 `"libc_malloc_debug.so"`。这意味着这个 unwinder 主要用于在 `libc_malloc_debug.so` 内部进行栈回溯。
* **`UnwindLog(const std::vector<unwindstack::FrameData>& frame_info)`:**
    * **格式化输出栈回溯信息:**  接收 `Unwind` 函数获取的详细帧信息，并将其格式化成易于阅读的字符串。
    * **包含程序计数器 (PC):**  输出每一帧的相对程序计数器 (`info->rel_pc`).
    * **包含内存映射信息:**  如果可用，输出代码所在内存映射的偏移量、名称或起始地址。
    * **包含函数名称:** 输出函数名称。
    * **符号反解 (Demangling):** 使用 `abi::__cxa_demangle` 将 C++ 的 mangled 函数名还原成可读的形式。
    * **包含函数偏移量:** 输出函数内部的偏移量。
    * **日志输出:** 使用 `error_log_string` 函数（可能是一个宏或函数调用）将格式化后的栈帧信息记录到日志中。

**2. 与 Android 功能的关系和举例:**

这个文件是 Android Bionic 库的一部分，直接服务于 Android 系统的内存管理调试功能。

* **`malloc_debug` 组件:**  `malloc_debug` 是 Bionic 中用于检测内存泄漏、double free、use-after-free 等内存错误的工具。`UnwindBacktrace.cpp` 提供的栈回溯信息是 `malloc_debug` 定位这些错误的关键。
* **内存分配/释放时的上下文:** 当 `malloc_debug` 检测到内存错误时，它会调用 `Unwind` 函数来获取当时的调用栈。这些调用栈信息可以帮助开发者追溯到导致错误的代码位置。
* **系统日志 (logcat):**  `UnwindLog` 函数会将栈回溯信息输出到系统日志中，开发者可以通过 `adb logcat` 命令查看。

**举例说明:**

假设你的 Android 应用在使用 `malloc` 分配内存后，忘记 `free` 导致内存泄漏。 `malloc_debug` 可能会在某个时间点检测到这种泄漏。  这时，它会调用 `Unwind` 获取内存分配时的调用栈，并通过 `UnwindLog` 将信息记录到 logcat，你可能会看到类似这样的输出：

```
01-01 00:00:00.000  1234  5678 E DEBUG   : [memory-leak] ...
01-01 00:00:00.000  1234  5678 E DEBUG   : Backtrace at allocation:
01-01 00:00:00.000  1234  5678 E DEBUG   :           #00  pc 0000000000012345  /system/lib64/libc.so (malloc+10)
01-01 00:00:00.000  1234  5678 E DEBUG   :           #01  pc 00000000000abcdef  /data/app/com.example.myapp/lib64/libnative.so (MyClass::allocateMemory()+20)
01-01 00:00:00.000  1234  5678 E DEBUG   :           #02  pc 0000000000fedcba  /data/app/com.example.myapp/lib64/libnative.so (Java_com_example_myapp_MainActivity_nativeMethod+30)
...
```

这里的每一行 `#xx pc ...` 就是 `UnwindLog` 格式化输出的栈帧信息，它显示了 `malloc` 函数被调用的路径。

**3. libc 函数的功能实现:**

在这个文件中，直接使用的 libc 函数主要是：

* **`free(void* ptr)`:**  用于释放 `abi::__cxa_demangle` 分配的内存。 `abi::__cxa_demangle` 在成功反解符号后，会分配一块内存来存储反解后的字符串，需要手动 `free` 掉。

**`free` 的实现简述：**

`free` 的具体实现比较复杂，涉及到内存管理器的内部机制。  简单来说，它的主要步骤包括：

1. **验证指针:** 检查传入的指针是否有效（例如，是否指向之前通过 `malloc` 或相关函数分配的内存块）。
2. **查找元数据:** 根据指针找到该内存块的元数据信息（例如，块的大小、是否被使用等），这些元数据通常存储在分配的内存块的头部或旁边。
3. **标记为空闲:** 将该内存块标记为空闲状态。
4. **合并空闲块 (可选):**  内存管理器可能会尝试将相邻的空闲块合并成更大的空闲块，以提高内存利用率。
5. **归还内存 (可选):**  在某些情况下，如果释放的内存块足够大，内存管理器可能会将一部分或全部内存归还给操作系统。

**4. 涉及 dynamic linker 的功能:**

`UnwindBacktrace.cpp` 通过 `unwindstack` 库间接地与 dynamic linker 交互。  `unwindstack` 需要依赖 dynamic linker 提供的信息来确定函数所在的共享库以及在库中的偏移量。

* **SO 布局样本:**

假设一个简单的 Android 进程加载了一个可执行文件 `app_process64` 和一个共享库 `libnative.so`。内存布局可能如下所示 (简化表示)：

```
[内存地址范围]   [映射名称]
-------------------------------------
0x0000007000000000 - 0x0000007000001000  [anon:stack_and_tls:0]  // 线程栈
0x0000007000001000 - 0x0000007000002000  /system/bin/app_process64
0x0000007000002000 - 0x0000007000103000  /system/bin/app_process64 (代码段)
0x0000007000103000 - 0x0000007000104000  /system/bin/app_process64 (只读数据段)
0x0000007000104000 - 0x0000007000105000  /system/bin/app_process64 (可读写数据段)
0x0000007100000000 - 0x0000007100010000  /data/app/com.example.myapp/lib64/libnative.so
0x0000007100010000 - 0x0000007100111000  /data/app/com.example.myapp/lib64/libnative.so (代码段)
0x0000007100111000 - 0x0000007100112000  /data/app/com.example.myapp/lib64/libnative.so (只读数据段)
0x0000007100112000 - 0x0000007100113000  /data/app/com.example.myapp/lib64/libnative.so (可读写数据段)
0x0000007fffffe000 - 0x0000008000000000  [anon:libc_malloc]  // 堆内存
...
```

* **链接的处理过程:**

1. **加载时链接:** 当操作系统加载可执行文件时，dynamic linker (在 Android 中通常是 `linker64` 或 `linker`) 会被启动。
2. **解析依赖:** Dynamic linker 读取可执行文件的头部信息，找到其依赖的共享库列表 (例如 `libnative.so`)。
3. **加载共享库:** Dynamic linker 搜索共享库文件，并将其加载到进程的地址空间中。
4. **符号解析 (Symbol Resolution):**  Dynamic linker 解析可执行文件和共享库中的符号表。当代码中调用一个外部函数时，dynamic linker 会查找该函数在哪个共享库中定义，并将其地址链接到调用点。这通常是延迟绑定的 (lazy binding)，即在第一次调用时才解析。
5. **重定位 (Relocation):**  由于共享库加载到内存的地址可能每次都不同，dynamic linker 需要调整代码和数据中的地址引用，使其指向正确的内存位置。

**`unwindstack` 如何利用这些信息:**

当 `unwindstack` 遍历堆栈帧时，它会获取每个栈帧的程序计数器 (PC) 值。然后，它会查找该 PC 值落在哪一个内存映射区域内。通过比对 PC 值与已加载的共享库的地址范围，`unwindstack` 可以确定该函数属于哪个共享库。  dynamic linker 维护着这些内存映射信息，`unwindstack` 可以通过读取 `/proc/self/maps` 文件或其他机制来获取这些信息。

**5. 逻辑推理、假设输入与输出:**

**假设输入:**

假设当前线程的调用栈如下 (从栈顶到栈底)：

1. `MyClass::myMethod()` in `libnative.so`
2. `anotherFunction()` in `libutils.so`
3. `malloc()` in `libc.so`

并且 `max_frames` 设置为 10。

**输出 (粗略估计，具体数值会变):**

`Unwind` 函数的输出：

* `frames`:  可能包含 `malloc` 函数的返回地址，以及 `anotherFunction` 和 `myMethod` 的返回地址。例如：`[0x7b4ace1234, 0x7b4ad05678, 0x7b4af98765]`
* `frame_info`:  会包含更详细的信息，例如：

```
[
  { num: 0, pc: 0x7b4ace1234, rel_pc: 0x1234, map_info: { start: 0x7b4ace0000, end: 0x7b4acf0000, offset: 0, name: "/system/lib64/libc.so" }, function_name: "malloc", function_offset: 10 },
  { num: 1, pc: 0x7b4ad05678, rel_pc: 0x5678, map_info: { start: 0x7b4ad00000, end: 0x7b4ad10000, offset: 0, name: "/system/lib64/libutils.so" }, function_name: "anotherFunction", function_offset: 20 },
  { num: 2, pc: 0x7b4af98765, rel_pc: 0x8765, map_info: { start: 0x7b4af90000, end: 0x7b4afa0000, offset: 0, name: "/data/app/com.example.myapp/lib64/libnative.so" }, function_name: "_ZN9MyClass8myMethodEv", function_offset: 30 }
]
```

`UnwindLog` 函数的输出到日志：

```
          #0  pc 00001234  /system/lib64/libc.so (malloc+10)
          #1  pc 00005678  /system/lib64/libutils.so (anotherFunction+20)
          #2  pc 00008765  /data/app/com.example.myapp/lib64/libnative.so (MyClass::myMethod()+30)
```

**6. 用户或编程常见的使用错误:**

* **没有检查 `Unwind` 的返回值:** 如果 `Unwind` 返回 `false`，说明获取栈回溯失败，但如果没有检查返回值，可能会继续使用空的 `frames` 或 `frame_info`，导致程序行为异常或崩溃。
* **`max_frames` 设置过小:** 如果 `max_frames` 设置得太小，可能无法获取完整的调用栈，从而丢失重要的调试信息。
* **内存泄漏 (在调用 `UnwindLog` 的上下文):**  虽然 `UnwindLog` 内部会 `free` 掉 `abi::__cxa_demangle` 分配的内存，但如果调用者没有正确管理 `frame_info` 的生命周期，可能会导致内存泄漏。
* **假设栈回溯总是成功:**  在某些异常情况下，栈回溯可能会失败，例如栈被破坏等。  开发者应该考虑到这种情况并进行适当的错误处理。

**7. Android framework 或 ndk 如何一步步的到达这里:**

**Android Framework 示例 (Native Crash):**

1. **Java 代码执行:**  Android 应用的 Java 代码在执行过程中可能会调用到 Native 代码 (通过 JNI)。
2. **NDK 代码执行:** NDK 代码在执行过程中发生错误，例如访问了无效的内存地址，导致 Segmentation Fault 信号 (SIGSEGV)。
3. **Signal Handler:**  操作系统会捕获到 SIGSEGV 信号，并调用进程预先注册的信号处理函数。
4. **Crash Reporting (Tombstone):**  Android 系统通常会有一个机制来记录应用崩溃的信息，包括生成 tombstone 文件。
5. **Unwinding as Part of Crash Handling:** 在生成 tombstone 文件的过程中，或者在调试器附加时，系统会尝试获取崩溃时的调用栈。  这可能会涉及调用类似 `Unwind` 这样的函数。
6. **`malloc_debug` 介入 (如果开启):** 如果 `malloc_debug` 功能被启用，并且崩溃发生在内存分配或释放相关的上下文中，`malloc_debug` 可能会使用 `UnwindBacktrace.cpp` 中的函数来记录更详细的栈回溯信息。

**NDK 示例 (手动触发):**

1. **NDK 代码显式调用:** NDK 开发者可能在代码中显式地使用 `malloc_debug` 提供的 API 来获取和记录栈回溯信息，以便进行调试。 这通常需要在编译时链接 `libc_malloc_debug.so`。
2. **`malloc_debug` 内部调用 `Unwind`:**  `malloc_debug` 的某些功能 (例如，在检测到内存泄漏时记录分配时的栈回溯) 会间接地调用 `UnwindBacktrace.cpp` 中的 `Unwind` 和 `UnwindLog` 函数。

**8. Frida Hook 示例调试这些步骤:**

以下是一个使用 Frida Hook 拦截 `UnwindLog` 函数并打印其参数的示例：

```javascript
if (Process.arch === 'arm64') {
    var module_name = "libc.so"; // 或 "libc_malloc_debug.so" 如果你想更精确
} else {
    var module_name = "libc.so"; // 根据实际架构调整
}

var module = Process.getModuleByName(module_name);
var unwindLogAddress = module.findExportByName("_ZN6UnwindLogERKSt6vectorIN9unwindstack9FrameDataESaIS2_EE"); // 根据实际符号 mangling 调整

if (unwindLogAddress) {
    Interceptor.attach(unwindLogAddress, {
        onEnter: function (args) {
            console.log("[+] UnwindLog called!");
            var frameInfoVector = new NativePointer(args[0]);
            var size = frameInfoVector.readUSize(); // 获取 vector 的 size

            console.log("Frame Count:", size);
            for (let i = 0; i < size; i++) {
                var frameDataPtr = frameInfoVector.add(Process.pointerSize * 2 + i * 48); // 计算 FrameData 结构体的地址 (假设 FrameData 大小为 48 字节，需要根据实际情况调整)
                var frameData = {
                    pc: frameDataPtr.add(8).readPointer(), // 假设 pc 在偏移 8 的位置
                    // ... 读取其他 FrameData 成员
                };
                console.log("  Frame #" + i + ", PC:", frameData.pc);
            }
        }
    });
    console.log("[+] Hooked UnwindLog at:", unwindLogAddress);
} else {
    console.error("[-] Could not find UnwindLog function.");
}
```

**Frida Hook 说明:**

1. **获取模块:**  根据架构获取 `libc.so` 或 `libc_malloc_debug.so` 模块。
2. **查找函数地址:** 使用 `findExportByName` 查找 `UnwindLog` 函数的地址。需要注意 C++ 函数的名称 mangling，你可能需要使用 `frida-ps -d <pid>` 或其他工具来获取正确的 mangled 名称。
3. **拦截函数:** 使用 `Interceptor.attach` 拦截 `UnwindLog` 函数。
4. **`onEnter` 回调:**  在 `onEnter` 回调中，`args[0]` 指向 `frame_info` 向量的起始地址。
5. **解析 `std::vector`:** 需要了解 `std::vector` 在内存中的布局 (通常包含指向数据的指针、大小和容量)，以便读取 `FrameData` 结构体。
6. **解析 `FrameData`:**  需要了解 `unwindstack::FrameData` 结构体的内存布局，才能正确读取其成员，例如 `pc`。  这可能需要查看 `unwindstack` 库的头文件。
7. **打印信息:**  将解析出的栈帧信息打印到 Frida 控制台。

请注意，上述 Frida Hook 示例中的地址偏移和结构体大小是假设的，可能需要根据具体的 Android 版本和架构进行调整。 你可以使用像 `Memory.readByteArray` 和结构体定义来更精确地解析 `FrameData`。

### 提示词
```
这是目录为bionic/libc/malloc_debug/UnwindBacktrace.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <cxxabi.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <android-base/stringprintf.h>
#include <unwindstack/AndroidUnwinder.h>
#include <unwindstack/Unwinder.h>

#include "UnwindBacktrace.h"
#include "debug_log.h"

#if defined(__LP64__)
#define PAD_PTR "016" PRIx64
#else
#define PAD_PTR "08" PRIx64
#endif

bool Unwind(std::vector<uintptr_t>* frames, std::vector<unwindstack::FrameData>* frame_info,
            size_t max_frames) {
  [[clang::no_destroy]] static unwindstack::AndroidLocalUnwinder unwinder(
      std::vector<std::string>{"libc_malloc_debug.so"});
  unwindstack::AndroidUnwinderData data(max_frames);
  if (!unwinder.Unwind(data)) {
    frames->clear();
    frame_info->clear();
    return false;
  }

  frames->resize(data.frames.size());
  for (const auto& frame : data.frames) {
    frames->at(frame.num) = frame.pc;
  }
  *frame_info = std::move(data.frames);
  return true;
}

void UnwindLog(const std::vector<unwindstack::FrameData>& frame_info) {
  for (size_t i = 0; i < frame_info.size(); i++) {
    const unwindstack::FrameData* info = &frame_info[i];
    auto map_info = info->map_info;

    std::string line = android::base::StringPrintf("          #%0zd  pc %" PAD_PTR "  ", i, info->rel_pc);
    if (map_info != nullptr && map_info->offset() != 0) {
      line += android::base::StringPrintf("(offset 0x%" PRIx64 ") ", map_info->offset());
    }

    if (map_info == nullptr) {
      line += "<unknown>";
    } else if (map_info->name().empty()) {
      line += android::base::StringPrintf("<anonymous:%" PRIx64 ">", map_info->start());
    } else {
      line += map_info->name();
    }

    if (!info->function_name.empty()) {
      line += " (";
      char* demangled_name =
          abi::__cxa_demangle(info->function_name.c_str(), nullptr, nullptr, nullptr);
      if (demangled_name != nullptr) {
        line += demangled_name;
        free(demangled_name);
      } else {
        line += info->function_name;
      }
      if (info->function_offset != 0) {
        line += "+" + std::to_string(info->function_offset);
      }
      line += ")";
    }
    error_log_string(line.c_str());
  }
}
```