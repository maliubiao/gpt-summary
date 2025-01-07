Response:
Let's break down the thought process for analyzing the `backtrace.cpp` code.

**1. Understanding the Goal:**

The core purpose of this file is clear from its name and the surrounding context (bionic/libc/malloc_debug): it's about capturing and formatting stack backtraces, primarily for debugging purposes, especially in the context of memory allocation issues.

**2. Initial Code Scan - Identifying Key Components:**

My first step is to quickly scan the code for major elements:

* **Includes:** These tell me the dependencies and general areas the code interacts with (`cxxabi.h` for demangling, `dlfcn.h` for dynamic linking, `unwind.h` for stack unwinding, etc.).
* **Global Variables:** `g_map_data` and `g_current_code_map` stand out. Their names suggest managing memory maps, which is crucial for translating addresses to library names and offsets.
* **Functions:**  I note the key functions: `backtrace_startup`, `backtrace_shutdown`, `backtrace_get`, `backtrace_string`, `backtrace_log`. These seem to be the main interface for using the backtracing functionality.
* **Structs:** `stack_crawl_state_t` seems to hold the state during the unwinding process.
* **Helper Functions:**  `find_current_map` and `trace_function` are likely internal helpers for the unwinding process.

**3. Deeper Dive into Functionality - Function by Function:**

Now I examine each function more closely, focusing on what it does and how it achieves it:

* **`backtrace_startup`:**  It reads memory maps (`g_map_data.ReadMaps()`) and then uses `_Unwind_Backtrace` with `find_current_map`. This immediately tells me it's initializing the memory map data, likely at program startup. `find_current_map` seems to identify the memory region where the initial call to this function originated.
* **`backtrace_shutdown`:** Empty, so no specific cleanup actions are needed.
* **`stack_crawl_state_t`:**  A simple struct to hold the results of the backtrace.
* **`trace_function`:** This is the core unwinding logic. It's called by `_Unwind_Backtrace`. It gets the instruction pointer (`_Unwind_GetIP`), adjusts it (with architecture-specific logic), checks if the frame is within the current library (to avoid self-referential frames), and stores the adjusted IP.
* **`backtrace_get`:**  This is the primary function to get the raw backtrace addresses. It creates a `stack_crawl_state_t` and then calls `_Unwind_Backtrace` with `trace_function`.
* **`backtrace_string`:** This is responsible for formatting the raw backtrace into a human-readable string. It uses `dladdr` to get symbol information and library names, demangles C++ symbols using `abi::__cxa_demangle`, and uses `MapData` to get more detailed information about the memory region.
* **`backtrace_log`:**  A convenience function to directly log the backtrace string.

**4. Connecting to Android Functionality:**

At this point, I consider how this fits into Android:

* **Memory Debugging:** The file is located in `bionic/libc/malloc_debug`, strongly suggesting its use in debugging memory allocation issues. When a crash or memory corruption happens, obtaining a backtrace is crucial for diagnosing the problem.
* **NDK and Framework:** Both NDK and Android framework components rely on `libc`. When these components crash or exhibit errors, backtraces generated using this code help developers pinpoint the source of the issue.
* **Dynamic Linking:** The use of `dlfcn.h` and `dladdr` clearly links this code to the dynamic linker. The backtrace needs to identify which shared libraries are involved in the call stack.

**5. Explaining Key Libc Functions:**

I focus on the most important libc functions used:

* **`dladdr`:** I explain its purpose (getting symbol information) and how it interacts with the dynamic linker's data structures.
* **`abi::__cxa_demangle`:**  I explain its role in making C++ symbols readable.
* **`_Unwind_Backtrace` and related `_Unwind_*` functions:**  I explain these are the low-level mechanisms for traversing the stack frames.

**6. Dynamic Linker Aspects:**

This requires understanding how shared libraries are loaded and managed:

* **SO Layout:** I visualize a typical process memory layout with multiple SOs.
* **Linking Process:** I describe the steps involved in resolving symbols during the linking process.

**7. Logic Inference and Examples:**

I think about simple scenarios to illustrate the functionality:

* **Hypothetical Input/Output:**  I create a simple example of a stack with function calls across different SOs and show what the output of `backtrace_string` might look like.
* **Common Usage Errors:**  I consider how a programmer might misuse the backtracing functions (e.g., passing incorrect buffer sizes).

**8. Android Framework/NDK Integration and Frida Hooking:**

I trace the path from a high-level Android component to this code:

* **Framework:**  An app crash or ANR can trigger backtrace collection.
* **NDK:**  A native crash in an NDK library will also utilize this code.
* **Frida Hooking:** I demonstrate how to use Frida to intercept calls to `backtrace_get` or `backtrace_string` to observe the backtrace being captured. This provides a practical way to debug and understand the process in real-time.

**9. Structuring the Response:**

Finally, I organize the information into a clear and logical structure, addressing each part of the prompt systematically:

* Functionality overview
* Relationship to Android
* Detailed explanations of libc functions
* Dynamic linker aspects
* Logic inference and examples
* Common usage errors
* Android/NDK integration and Frida

Throughout the process, I try to be precise with terminology and provide concrete examples where possible. I also anticipate potential questions a reader might have and try to address them proactively.
好的，让我们详细分析一下 `bionic/libc/malloc_debug/backtrace.cpp` 这个文件。

**文件功能概览**

这个文件实现了在 Android Bionic 库中获取和格式化程序调用栈回溯 (backtrace) 的功能。主要目的是为了在调试过程中，特别是与内存管理相关的错误（例如，由 `malloc_debug` 触发的错误）发生时，能够追踪到问题的根源。

**具体功能分解**

1. **获取当前指令指针位置：** 通过 `_Unwind_GetIP` 函数获取当前执行到的指令的地址。

2. **读取进程内存映射信息：** 使用 `MapData` 类来读取 `/proc/self/maps` 文件，该文件包含了当前进程加载的所有共享库及其内存地址范围。这对于将指令地址转换为具体的库和函数名至关重要。

3. **栈回溯核心逻辑：** 使用 libunwind 库提供的 `_Unwind_Backtrace` 函数进行栈回溯。这个函数会遍历当前的调用栈，并对每一帧调用一个回调函数。

4. **过滤自身库的帧：**  在栈回溯过程中，会过滤掉属于 `backtrace.cpp` 自身所在共享库的栈帧，避免在回溯信息中出现过多的自身调用。

5. **将地址转换为符号信息：**  对于栈回溯得到的每个指令地址，使用 `dladdr` 函数尝试找到包含该地址的共享库和符号信息（例如，函数名）。

6. **C++ 符号反解析 (Demangling)：**  对于获取到的 C++ 符号，使用 `abi::__cxa_demangle` 函数将其从编译器 mangled 的形式转换为更易读的形式。

7. **格式化回溯信息：** 将获取到的指令地址、库名、偏移、函数名等信息格式化成易于阅读的字符串。

8. **输出回溯信息：**  提供 `backtrace_log` 函数，可以将格式化后的回溯信息输出到日志系统。

**与 Android 功能的关系及举例说明**

这个 `backtrace.cpp` 文件是 Android 系统底层库的一部分，与 Android 系统的稳定性和调试能力密切相关。

* **内存调试 (Memory Debugging):** `malloc_debug` 组件使用这个文件提供的功能来记录内存分配和释放的调用栈。当检测到内存泄漏、重复释放等错误时，可以打印出导致错误的调用栈，帮助开发者定位问题。例如，当一个应用发生内存泄漏时，`malloc_debug` 可以记录下分配这块内存的调用栈，而 `backtrace.cpp` 就负责生成这个调用栈信息。

* **崩溃报告 (Crash Reporting):** 当应用程序或系统服务崩溃时，通常会生成一个 crash dump 或 tombstone 文件，其中包含了崩溃时的调用栈。`backtrace.cpp` 提供的功能是生成这些调用栈信息的基础。例如，一个 Java 应用调用了 Native 代码，Native 代码中发生了 segmentation fault，系统会调用到 Bionic 库的异常处理机制，最终会使用 `backtrace.cpp` 来获取 Native 层的调用栈。

* **性能分析 (Performance Profiling):** 虽然 `backtrace.cpp` 的主要目的是调试，但在某些性能分析工具中，也会使用类似的技术来采样程序的调用栈，分析热点代码。

**libc 函数功能实现详解**

1. **`dladdr(const void *addr, Dl_info *info)`:**
   - **功能：**  `dladdr` 函数尝试查找包含指定地址 `addr` 的共享库 (shared object) 的信息，并将这些信息存储在 `Dl_info` 结构体中。
   - **实现：**
     - `dladdr` 遍历当前进程加载的共享库列表（这些信息由动态链接器维护）。
     - 对于每个共享库，它检查 `addr` 是否位于该共享库的内存地址范围内。
     - 如果找到包含 `addr` 的共享库，它会填充 `Dl_info` 结构体，包括：
       - `dli_fname`: 指向共享库文件路径名的指针。
       - `dli_fbase`: 共享库在内存中的加载基地址。
       - `dli_sname`: 指向与 `addr` 最接近的符号名称的指针（如果没有精确匹配的符号，则可能为 NULL）。
       - `dli_saddr`: 符号的起始地址。
     - 查找符号信息通常涉及到读取共享库的符号表。

2. **`abi::__cxa_demangle(const char *mangled_name, char *output_buffer, size_t *length, int *status)`:**
   - **功能：** `abi::__cxa_demangle` 函数将 C++ 编译器 mangled (编码) 过的符号名称 `mangled_name` 转换回原始的、更易读的符号名称。
   - **实现：**
     - C++ 编译器为了支持函数重载、命名空间等特性，会将符号名称进行编码，生成 mangled name。
     - `abi::__cxa_demangle` 函数实现了与这种编码方案相反的解码过程。
     - 它会解析 `mangled_name` 中的编码信息，提取出函数名、参数类型、命名空间等信息。
     - 如果 `output_buffer` 为 NULL，则函数会分配足够的内存来存储 demangled 后的名称，并将指针返回。调用者需要负责释放这块内存。
     - 如果 `output_buffer` 不为 NULL，则函数会将 demangled 后的名称复制到该缓冲区中，并通过 `length` 参数返回实际写入的长度。
     - `status` 参数用于返回 demangling 的状态（例如，成功、内存不足、无效的 mangled name 等）。

3. **`_Unwind_Backtrace(_Unwind_Trace_Fn callback, void *opaque)`:**
   - **功能：** `_Unwind_Backtrace` 函数是 libunwind 库提供的核心函数，用于执行栈回溯。它遍历当前的函数调用栈，并对栈中的每一帧调用指定的回调函数 `callback`。
   - **实现：**
     - `_Unwind_Backtrace` 的实现依赖于平台的 ABI (Application Binary Interface) 和栈帧的布局。
     - 它通常会从当前的栈指针 (SP) 和帧指针 (FP) 开始，根据栈帧的结构（例如，返回地址的位置、保存的寄存器等）来定位上一帧的信息。
     - 对于每一帧，它会调用 `callback` 函数，并将当前帧的上下文信息（通过 `_Unwind_Context` 结构体传递）和用户提供的 `opaque` 数据作为参数传递给回调函数。
     - 回调函数的返回值决定了是否继续进行栈回溯。如果回调函数返回 `_URC_NO_REASON`，则继续回溯；如果返回 `_URC_END_OF_STACK` 或其他错误码，则停止回溯。
     - `backtrace.cpp` 中使用了两个不同的回调函数：
       - `find_current_map`: 用于在启动时确定当前代码所在的内存区域。
       - `trace_function`: 用于收集每一帧的指令指针地址。

**涉及 dynamic linker 的功能**

`backtrace.cpp` 与 dynamic linker (动态链接器) 紧密相关，因为它需要获取已加载共享库的信息来解析地址。

**SO 布局样本**

假设一个 Android 应用加载了多个共享库，其内存布局可能如下所示（简化示例）：

```
地址范围          权限     偏移量     设备       inode       pathname
----------------- -------- ---------- ---------- ---------- ------------------------------------
000000709f000000-000000709f001000 r--p     00000000 00:00 0
000000709f001000-000000709f002000 r-xp     00000000 00:00 0                  [vectors]
000000709f002000-000000709f003000 r--p     00000000 00:00 0
000000709f003000-000000709f004000 r--p     00000000 00:00 0
000000709f004000-000000709f005000 rw-p     00000000 00:00 0
000000709f005000-000000709f006000 r--p     00000000 00:00 0
714b840000-714b850000 r-xp 00000000 103:02 131073 /system/lib64/libutils.so
714b850000-714b851000 r--p 00010000 103:02 131073 /system/lib64/libutils.so
714b851000-714b852000 rw-p 00011000 103:02 131073 /system/lib64/libutils.so
714b852000-714b853000 rw-p 00000000 00:00 0
714b853000-714b860000 r-xp 00000000 103:02 131074 /system/lib64/libc.so
714b860000-714b861000 r--p 0000d000 103:02 131074 /system/lib64/libc.so
714b861000-714b863000 rw-p 0000e000 103:02 131074 /system/lib64/libc.so
714b863000-714b864000 rw-p 00000000 00:00 0
714b864000-714b870000 r-xp 00000000 103:02 131075 /system/lib64/libm.so
...
```

* **地址范围:** 表示共享库在进程内存空间中占用的地址范围。
* **权限:**  表示内存页的访问权限 (r=读, w=写, x=执行, p=私有映射)。
* **偏移量:**  表示共享库在文件中的偏移量。
* **设备:**  设备号。
* **inode:**  文件 inode 号。
* **pathname:**  共享库的文件路径。

**链接的处理过程**

1. **加载时链接：** 当 Android 系统启动应用或者动态加载共享库时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责将共享库加载到内存中的合适位置，并解析共享库之间的依赖关系。
2. **符号解析：** Dynamic linker 会读取共享库的 ELF 文件头、程序头表和动态链接段，获取共享库的依赖关系和需要解析的符号信息。
3. **重定位：**  Dynamic linker 会根据加载地址调整共享库中的一些地址引用（例如，全局变量的地址、函数地址），这个过程称为重定位。
4. **`dladdr` 的工作原理：**  `dladdr` 函数依赖于 dynamic linker 维护的数据结构，这些数据结构记录了当前进程加载的所有共享库的信息（例如，加载地址、符号表等）。当 `dladdr` 被调用时，它会查询这些数据结构来查找指定地址所属的共享库以及相关的符号信息。

**逻辑推理、假设输入与输出**

假设我们有以下简单的调用栈：

```
#0  0x000000714b855000 in some_function in /system/lib64/libutils.so
#1  0x000000714b854000 in another_function in /system/lib64/libutils.so
#2  0x000000714b85a000 in yet_another_function in /system/lib64/libc.so
```

**假设输入 (在 `trace_function` 中)：**

* `context`: 指向当前栈帧的上下文信息，包含指令指针 (IP) 等。
* `arg`: 指向 `stack_crawl_state_t` 结构体的指针。

**假设输出 (存储在 `stack_crawl_state_t` 中的 `frames` 数组)：**

假设 `trace_function` 被调用三次（对应栈中的三帧），并且 `g_current_code_map` 指向 `backtrace.cpp` 所在的共享库的内存区域。

* **第一次调用 `trace_function`：**
    - `ip` (来自 `_Unwind_GetIP(context)`) 可能接近 `0x000000714b855004` (假设指令长度为 4 字节)。
    - 由于 `ip` 不在 `g_current_code_map` 的范围内，所以 `state->frames[0]` 将被设置为 `0x000000714b855000` (经过架构相关的调整)。
* **第二次调用 `trace_function`：**
    - `ip` 可能接近 `0x000000714b854004`。
    - `state->frames[1]` 将被设置为 `0x000000714b854000`。
* **第三次调用 `trace_function`：**
    - `ip` 可能接近 `0x000000714b85a004`。
    - `state->frames[2]` 将被设置为 `0x000000714b85a000`。

**假设输出 (由 `backtrace_string` 生成)：**

基于 `frames` 数组和上述 SO 布局，`backtrace_string` 可能生成如下字符串：

```
          #00  pc 0000000000004000  /system/lib64/libutils.so (some_function+0)
          #01  pc 0000000000003000  /system/lib64/libutils.so (another_function+0)
          #02  pc 0000000000007000  /system/lib64/libc.so (yet_another_function+0)
```

**涉及用户或者编程常见的使用错误**

1. **`backtrace_get` 提供的缓冲区太小：** 如果 `frames` 数组的大小 `frame_count` 不足以容纳实际的调用栈深度，`backtrace_get` 将会返回实际获取到的帧数，但可能会丢失部分栈帧信息。

   ```c++
   uintptr_t frames[5];
   size_t count = backtrace_get(frames, 5); // 如果调用栈深度超过 5，将会丢失信息
   ```

2. **误解偏移量的含义：** 在 `backtrace_string` 的输出中，函数名后面的偏移量是指令地址相对于符号起始地址的偏移，而不是相对于共享库加载基地址的偏移。初学者可能会混淆。

3. **忘记处理 `abi::__cxa_demangle` 的内存：** 如果 `abi::__cxa_demangle` 返回了一个非 NULL 的指针，表示它分配了内存来存储 demangled 的名称，调用者需要使用 `free()` 来释放这块内存，否则会导致内存泄漏。

   ```c++
   char* demangled_name = abi::__cxa_demangle(symbol, nullptr, nullptr, nullptr);
   // ... 使用 demangled_name
   free(demangled_name); // 必须释放
   ```

4. **在信号处理函数中使用 `backtrace_string` 或 `backtrace_log`：**  这些函数内部可能会使用到一些非异步信号安全的函数，如果在信号处理函数中调用，可能会导致死锁或其他不可预测的行为。建议在信号处理函数中只使用异步信号安全的函数。

**Android Framework 或 NDK 如何一步步到达这里**

1. **Android Framework 触发：**
   - 应用程序发生崩溃（例如，未捕获的异常、ANR）。
   - Android 系统的 `ActivityManagerService` 或 `WindowManagerService` 等系统服务检测到崩溃。
   - 系统会尝试收集崩溃信息，包括 Native 层的调用栈。
   - 这通常涉及到调用 `libc.so` 中的信号处理机制 (例如 `SIGSEGV`, `SIGABRT`)。
   - 在信号处理函数中，会调用到 `bionic` 库提供的栈回溯功能，最终调用到 `backtrace_get` 和 `backtrace_string`。

2. **NDK 代码触发：**
   - NDK 开发的 Native 代码中发生错误（例如，访问空指针、数组越界）。
   - 操作系统会向进程发送信号。
   - 如果程序没有自定义信号处理函数，或者自定义的信号处理函数中需要获取调用栈，最终会调用到 `bionic` 库的默认信号处理逻辑。
   - 例如，`libandroid_runtime.so` 中的 JNI 调用可能会导致 Native 代码崩溃，此时会使用到 `backtrace.cpp`。

**Frida Hook 示例调试步骤**

我们可以使用 Frida hook `backtrace_get` 函数来观察其行为。

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload:", message['payload'])
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "backtrace_get"), {
    onEnter: function(args) {
        console.log("[*] backtrace_get called");
        this.frames = args[0];
        this.frame_count = args[1].toInt();
        console.log("[*] Frame buffer address:", this.frames);
        console.log("[*] Frame count:", this.frame_count);
    },
    onLeave: function(retval) {
        console.log("[*] backtrace_get returned:", retval.toInt());
        if (retval.toInt() > 0) {
            console.log("[*] Stack frames:");
            for (let i = 0; i < retval.toInt(); i++) {
                let frame = this.frames.add(i * Process.pointerSize).readPointer();
                console.log("    [*] #" + i + ": " + frame);
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤解释：**

1. **导入 Frida 库。**
2. **指定要 Hook 的应用包名。**
3. **连接到目标 Android 设备上的应用进程。**
4. **编写 Frida 脚本：**
   - 使用 `Interceptor.attach` Hook `libc.so` 中的 `backtrace_get` 函数。
   - 在 `onEnter` 中，打印 `backtrace_get` 被调用时的参数：`frames` 缓冲区的地址和请求的帧数。
   - 在 `onLeave` 中，打印 `backtrace_get` 的返回值（实际获取到的帧数），并遍历 `frames` 缓冲区，打印每个栈帧的地址。
5. **创建并加载 Frida 脚本。**
6. **保持脚本运行，等待事件发生。**

当目标应用中发生某些事件导致 `backtrace_get` 被调用时，Frida 将会拦截调用并打印出相关信息，帮助你理解调用栈的收集过程。你可以修改脚本来 Hook `backtrace_string` 或其他相关函数，以观察更详细的回溯信息。

希望以上详细的解释能够帮助你理解 `bionic/libc/malloc_debug/backtrace.cpp` 的功能和实现原理。

Prompt: 
```
这是目录为bionic/libc/malloc_debug/backtrace.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <cxxabi.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <malloc.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <unwind.h>

#include "MapData.h"
#include "backtrace.h"
#include "debug_log.h"

#if defined(__LP64__)
#define PAD_PTR "016" PRIxPTR
#else
#define PAD_PTR "08" PRIxPTR
#endif

typedef struct _Unwind_Context __unwind_context;

static MapData g_map_data;
static MapEntry g_current_code_map;

static _Unwind_Reason_Code find_current_map(__unwind_context* context, void*) {
  uintptr_t ip = _Unwind_GetIP(context);

  if (ip == 0) {
    return _URC_END_OF_STACK;
  }
  auto map = g_map_data.find(ip);
  if (map != nullptr) {
    g_current_code_map = *map;
  }
  return _URC_END_OF_STACK;
}

void backtrace_startup() {
  g_map_data.ReadMaps();
  _Unwind_Backtrace(find_current_map, nullptr);
}

void backtrace_shutdown() {}

struct stack_crawl_state_t {
  uintptr_t* frames;
  size_t frame_count;
  size_t cur_frame = 0;

  stack_crawl_state_t(uintptr_t* frames, size_t frame_count)
      : frames(frames), frame_count(frame_count) {}
};

static _Unwind_Reason_Code trace_function(__unwind_context* context, void* arg) {
  stack_crawl_state_t* state = static_cast<stack_crawl_state_t*>(arg);

  uintptr_t ip = _Unwind_GetIP(context);

  // `ip` is the address of the instruction *after* the call site in
  // `context`, so we want to back up by one instruction. This is hard for
  // every architecture except arm64, so we just make sure we're *inside*
  // that instruction, not necessarily at the start of it. (If the value
  // is too low to be valid, we just leave it alone.)
  if (ip >= 4096) {
#if defined(__aarch64__)
    ip -= 4;  // Exactly.
#elif defined(__arm__) || defined(__riscv)
    ip -= 2;  // At least.
#elif defined(__i386__) || defined(__x86_64__)
    ip -= 1;  // At least.
#endif
  }

  // Do not record the frames that fall in our own shared library.
  if (g_current_code_map.start() != 0 && (ip >= g_current_code_map.start()) &&
      ip < g_current_code_map.end()) {
    return _URC_NO_REASON;
  }

  state->frames[state->cur_frame++] = ip;
  return (state->cur_frame >= state->frame_count) ? _URC_END_OF_STACK : _URC_NO_REASON;
}

size_t backtrace_get(uintptr_t* frames, size_t frame_count) {
  stack_crawl_state_t state(frames, frame_count);
  _Unwind_Backtrace(trace_function, &state);
  return state.cur_frame;
}

std::string backtrace_string(const uintptr_t* frames, size_t frame_count) {
  if (g_map_data.NumMaps() == 0) {
    g_map_data.ReadMaps();
  }

  std::string str;

  for (size_t frame_num = 0; frame_num < frame_count; frame_num++) {
    uintptr_t offset = 0;
    const char* symbol = nullptr;

    Dl_info info;
    if (dladdr(reinterpret_cast<void*>(frames[frame_num]), &info) != 0) {
      offset = reinterpret_cast<uintptr_t>(info.dli_saddr);
      symbol = info.dli_sname;
    } else {
      info.dli_fname = nullptr;
    }

    uintptr_t rel_pc = offset;
    const MapEntry* entry = g_map_data.find(frames[frame_num], &rel_pc);

    const char* soname = (entry != nullptr) ? entry->name().c_str() : info.dli_fname;
    if (soname == nullptr) {
      soname = "<unknown>";
    }

    char offset_buf[128];
    if (entry != nullptr && entry->elf_start_offset() != 0) {
      snprintf(offset_buf, sizeof(offset_buf), " (offset 0x%" PRIxPTR ")",
               entry->elf_start_offset());
    } else {
      offset_buf[0] = '\0';
    }

    char buf[1024];
    if (symbol != nullptr) {
      char* demangled_name = abi::__cxa_demangle(symbol, nullptr, nullptr, nullptr);
      const char* name;
      if (demangled_name != nullptr) {
        name = demangled_name;
      } else {
        name = symbol;
      }
      async_safe_format_buffer(buf, sizeof(buf),
                               "          #%02zd  pc %" PAD_PTR "  %s%s (%s+%" PRIuPTR ")\n",
                               frame_num, rel_pc, soname, offset_buf, name,
                               frames[frame_num] - offset);
      free(demangled_name);
    } else {
      async_safe_format_buffer(buf, sizeof(buf), "          #%02zd  pc %" PAD_PTR "  %s%s\n",
                               frame_num, rel_pc, soname, offset_buf);
    }
    str += buf;
  }

  return str;
}

void backtrace_log(const uintptr_t* frames, size_t frame_count) {
  g_map_data.ReadMaps();
  error_log_string(backtrace_string(frames, frame_count).c_str());
}

"""

```