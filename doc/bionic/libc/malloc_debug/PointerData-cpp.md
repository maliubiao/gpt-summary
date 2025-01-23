Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Goal:** The request is to analyze the `PointerData.cpp` file within Android's bionic library, specifically focusing on its functionality, relationship to Android, implementation details of libc functions, dynamic linker interactions, potential errors, and how it's reached from higher levels (Android Framework/NDK).

2. **Initial Code Scan and High-Level Understanding:**  First, I'd quickly scan the code to get a general idea of what it does. I'd look for:
    * **Includes:**  Standard C/C++ headers (like `<stdlib.h>`, `<string.h>`, `<mutex>`, `<unordered_map>`) and Android-specific headers (`<android-base/stringprintf.h>`, `<platform/bionic/macros.h>`). This immediately suggests memory management and debugging features.
    * **Class Definition:** The presence of a `PointerData` class is a key indicator.
    * **Member Variables:**  Look for data structures. The `pointers_`, `frames_`, `key_to_index_`, and `free_pointers_` maps and deque are prominent and hint at tracking allocated and freed memory. The `std::mutex` members suggest thread safety is a concern.
    * **Key Methods:**  Names like `Add`, `Remove`, `AddFreed`, `LogLeaks`, `GetList`, `DumpLiveToFile` provide strong clues about the core functionality.
    * **Global Variables:**  `g_cmp_mem` and the static signal handlers suggest specific features like memory comparison after freeing and signal-based control.

3. **Identify Core Functionality:** Based on the initial scan, the primary functions appear to be:
    * **Tracking Allocations:**  Storing information about allocated memory blocks (pointer, size, backtrace).
    * **Tracking Frees:** Storing information about freed memory blocks, potentially for detecting use-after-free errors.
    * **Backtrace Management:**  Collecting and storing stack backtraces associated with allocations and frees.
    * **Error Detection:**  Identifying potential memory errors like use-after-free and leaks.
    * **Data Reporting/Dumping:** Providing ways to inspect the tracked memory information.

4. **Connect to Android's Functionality:**  Knowing that bionic is the core C library for Android, the purpose of this code within a `malloc_debug` directory becomes clearer. It's likely part of a debugging mechanism for memory allocation within Android applications and the system itself. The ability to trigger backtraces via signals is a common debugging technique in Android.

5. **Detailed Analysis of Key Methods:**  Now, I'd go through the important methods one by one, focusing on:
    * **`Initialize`:**  How is the tracking system set up?  What configuration options are involved? The signal handling for enabling backtraces and dumping is a key detail.
    * **`Add`:** How is allocation information stored?  How are backtraces added?  The use of `ManglePointer` and the `pointers_` map are important.
    * **`Remove`:** How is deallocation tracked?  How are backtraces removed to avoid memory leaks in the debugging system itself?
    * **`AddBacktrace`:** How are stack frames captured? The use of `backtrace_get` and `Unwind` (likely for more detailed backtraces) is significant. The `frames_` and `key_to_index_` maps are used to deduplicate backtraces.
    * **`AddFreed`:** How is freed memory tracked? The `free_pointers_` deque and the `VerifyFreedPointer` function are important for detecting use-after-free.
    * **`VerifyFreedPointer`:** How is the content of freed memory checked for corruption? The `g_cmp_mem` buffer is crucial here.
    * **`LogLeaks`:** How are memory leaks reported?
    * **`GetList`/`GetUniqueList`:**  How is the collected information structured and presented?
    * **`DumpLiveToFile`:** How is the data exported for offline analysis? The output format is important to note.
    * **Thread Safety:** The frequent use of `std::mutex` indicates careful consideration of concurrency issues. The `PrepareFork`, `PostForkParent`, and `PostForkChild` methods are specifically for handling forking, a common operation in Unix-like systems.

6. **Focus on libc and Dynamic Linker:**
    * **libc Functions:**  Identify calls to standard libc functions like `malloc_usable_size`, `memcpy`, `memcmp`, `abort`, `getprogname`, `strerror`, `getpid`. Explain their basic purpose and how they are used within the context of memory debugging. No reimplementation is present here; the code *uses* these libc functions.
    * **Dynamic Linker:** The `backtrace_get` function is the primary interaction with the dynamic linker here. It relies on the linker to provide information about the call stack. The `Unwind` function might involve more direct interaction or leverage other libraries built on top of dynamic linker information. The output of `DumpLiveToFile` (specifically the `bt_info` section) shows detailed information obtained by potentially using libraries that work with the dynamic linker to resolve symbols. Generating a sample SO layout is a good way to illustrate the context in which these backtraces are generated.

7. **Identify Potential Errors:** Look for common programming mistakes that this debugging code is designed to catch:
    * **Memory Leaks:**  Failure to `free` allocated memory.
    * **Use-After-Free:** Accessing memory after it has been freed. The `FREE_TRACK` option and the `VerifyFreedPointer` function are explicitly for this.
    * **Heap Corruption:** Overwriting memory outside of allocated bounds (though this code primarily *detects* the *effects* of corruption rather than the act itself, like the header tag check).

8. **Trace the Path from Framework/NDK:** Think about how an Android application would interact with this code.
    * **NDK:**  Native code directly uses `malloc`, `free`, etc., which are provided by bionic. The debug malloc implementation would intercept these calls.
    * **Android Framework:** Higher-level Java code eventually calls native methods that allocate memory. These allocations would also go through bionic's malloc. The `zygote_child_alloc` flag suggests awareness of Android's process forking model. Frida is a good tool for demonstrating this interaction.

9. **Construct Frida Hooks:**  Based on the analysis, design Frida hooks to intercept relevant functions (`malloc`, `free`) and potentially functions within `PointerData` itself to observe the tracking in action.

10. **Structure the Answer:** Organize the information logically, covering each point in the prompt. Use clear headings and examples.

11. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any misunderstandings or omissions. For example, initially, I might just say "tracks allocations."  Refining that to include "stores pointer, size, and potentially backtrace" adds more detail. Similarly, explicitly linking `backtrace_get` and `Unwind` to the dynamic linker enhances the explanation. Making sure to explicitly mention that the libc functions aren't *implemented* in this file, but *used*, is important.
这是一个位于 `bionic/libc/malloc_debug/PointerData.cpp` 的源代码文件，属于 Android Bionic 库的 `malloc_debug` 组件。该文件主要负责**跟踪和管理程序运行时分配和释放的内存指针信息**，用于帮助开发者检测内存泄漏、使用已释放内存等问题。

以下是 `PointerData.cpp` 的功能列表及其详细解释：

**核心功能：**

1. **跟踪内存分配：**
   - 记录已分配内存块的起始地址和大小。
   - 可选地记录分配时的堆栈回溯 (backtrace)。
   - 区分 Zygote 子进程的内存分配。

2. **跟踪内存释放：**
   - 记录已释放内存块的起始地址。
   - 可选地记录释放时的堆栈回溯。
   - 将释放的内存块信息保存在一个队列中，用于后续的释放后使用 (use-after-free) 检测。

3. **检测内存错误：**
   - **内存泄漏检测：** 在程序退出时，报告所有仍未释放的内存块。
   - **释放后使用检测：** 当访问已释放的内存块时，发出警告或终止程序。它通过填充已释放内存并比较后续访问是否与填充值一致来实现。
   - **堆损坏检测（间接）：** 虽然 `PointerData` 不直接检测所有类型的堆损坏，但它可以检测到释放时元数据损坏的情况 (例如，header tag)。

4. **提供内存信息查询接口：**
   - 可以查询特定指针是否已被跟踪。
   - 可以获取与指针关联的分配时的堆栈回溯。
   - 可以列出所有当前已分配的内存块及其信息。
   - 可以导出内存分配信息到文件，用于离线分析。

5. **与信号处理集成：**
   - 可以通过发送特定信号来动态启用/禁用堆栈回溯功能。
   - 可以通过发送特定信号来触发当前内存分配信息的转储。

**与 Android 功能的关系及举例说明：**

- **内存调试工具的基础：** `PointerData` 是 Android 平台内存调试工具（如 `dmtrace`, `memtrack`）的基础组件之一。这些工具依赖于 `PointerData` 提供的内存跟踪信息来帮助开发者分析应用的内存使用情况。
- **Zygote 优化：** Android 使用 Zygote 进程来加速应用启动。`PointerData` 能够区分 Zygote 父进程和子进程的内存分配，这对于理解和优化 Zygote 的内存共享机制至关重要。例如，Zygote 父进程分配的只读内存在子进程中可以共享，而子进程的修改会触发写时复制。`PointerData` 可以帮助识别哪些内存是在 Zygote 父进程中分配的。
- **系统服务调试：** Android 的系统服务也运行在 Bionic 之上，`PointerData` 可以帮助调试系统服务中的内存问题。
- **NDK 开发支持：** 使用 NDK 开发的 Android 应用的内存管理也由 Bionic 提供，因此 `PointerData` 同样适用于 NDK 开发中的内存调试。

**详细解释每一个 libc 函数的功能是如何实现的：**

`PointerData.cpp` 本身**不实现**任何 libc 函数。它**使用**了一些 libc 函数来完成其功能。以下是代码中使用的 libc 函数及其作用：

- **`<cxxabi.h>` 中的 `abi::__cxa_demangle`:**  用于将 C++ mangled 的函数名还原为可读的形式，用于在打印堆栈回溯时提供更清晰的信息。
- **`<errno.h>`:** 用于获取系统调用错误码，例如在 `sigaction64` 失败时获取错误信息。
- **`<inttypes.h>`:** 提供了一些跨平台的整数类型定义和格式化宏，例如 `PRIxPTR` 用于打印指针地址。
- **`<signal.h>`:** 用于处理信号，例如设置信号处理函数来动态启用/禁用堆栈回溯和转储内存信息。
  - `sigaction64`: 设置指定信号的处理方式。
- **`<stdint.h>`:** 提供了一些精确宽度的整数类型定义，例如 `uintptr_t`。
- **`<stdlib.h>`:** 提供了一些通用工具函数，例如：
  - `abort`: 立即终止程序，通常在检测到严重错误时使用。
  - `calloc`: 分配指定大小的内存块并将其初始化为零。
  - `free`: 释放之前分配的内存块。
  - `getprogname`: 获取程序的名称。
- **`<string.h>`:** 提供了一些字符串处理函数，例如：
  - `memcpy`: 将一块内存的内容复制到另一块内存。
  - `memcmp`: 比较两块内存的内容。
  - `strerror`: 将错误码转换为错误描述字符串。
- **`<sys/types.h>`:** 定义了一些基本的数据类型，例如 `size_t`。
- **`<unistd.h>`:** 提供了一些 POSIX 操作系统 API，例如：
  - `getpid`: 获取当前进程的 ID。
  - `dprintf`: 将格式化的输出写入到文件描述符。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程：**

`PointerData.cpp` 通过 `backtrace_get` 和可能的 `Unwind` 函数（如果开启了 `BACKTRACE_FULL` 选项）与 dynamic linker 交互来获取堆栈回溯。

**SO 布局样本：**

假设一个简单的 Android 应用加载了一个名为 `libexample.so` 的动态链接库：

```
# memory map of the process
0000000000400000-0000000000401000 r--p 00000000 00:00 12345  /system/bin/app_process64
0000000000401000-0000000000500000 r-xp 00001000 00:00 12345  /system/bin/app_process64
0000000000500000-00000000005ff000 r--p 00100000 00:00 12345  /system/bin/app_process64
00000000005ff000-0000000000600000 rw-p 001ff000 00:00 12345  /system/bin/app_process64
...
0000007b80000000-0000007b80001000 r--p 00000000 00:00 67890  /apex/com.android.runtime/lib64/bionic/libm.so
0000007b80001000-0000007b8000b000 r-xp 00001000 00:00 67890  /apex/com.android.runtime/lib64/bionic/libm.so
0000007b8000b000-0000007b8000c000 r--p 0000b000 00:00 67890  /apex/com.android.runtime/lib64/bionic/libm.so
0000007b8000c000-0000007b8000d000 rw-p 0000c000 00:00 67890  /apex/com.android.runtime/lib64/bionic/libm.so
...
0000007b81000000-0000007b81010000 r--p 00000000 00:00 98765  /data/app/com.example/lib/arm64/libexample.so
0000007b81010000-0000007b81020000 r-xp 00010000 00:00 98765  /data/app/com.example/lib/arm64/libexample.so
0000007b81020000-0000007b81030000 r--p 00020000 00:00 98765  /data/app/com.example/lib/arm64/libexample.so
0000007b81030000-0000007b81040000 rw-p 00030000 00:00 98765  /data/app/com.example/lib/arm64/libexample.so
...
```

在这个例子中，`libexample.so` 被加载到内存地址 `0000007b81000000` 到 `0000007b81040000`。SO 文件被分为不同的段：

- **r--p:** 只读段（例如，`.rodata`）
- **r-xp:** 只读可执行段（例如，`.text`）
- **rw-p:** 读写段（例如，`.data`, `.bss`）

**链接的处理过程：**

1. **`backtrace_get` 函数：**  当 `PointerData::AddBacktrace` 被调用时，如果启用了基本的堆栈回溯 (`BACKTRACE` 选项)，它会调用 `backtrace_get` 函数。
2. **动态链接器参与：** `backtrace_get` 内部会与动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 交互。动态链接器维护了当前进程加载的所有共享库的信息，包括它们的加载地址。
3. **栈帧遍历：** `backtrace_get` 会遍历当前的调用栈，读取每个栈帧的返回地址（通常存储在栈上）。
4. **地址查找：** 对于每个返回地址，动态链接器会查找该地址属于哪个加载的共享库（或主程序）。这通过比较返回地址与每个 SO 的加载地址范围来实现。
5. **符号解析 (通常需要额外的库)：**  `backtrace_get` 通常只返回 IP (Instruction Pointer) 地址。要将这些地址转换为函数名和偏移量，需要进行符号解析。这通常需要访问 SO 文件的符号表，可能由 `libunwind` 或类似的库完成，而 `Unwind` 函数很可能就使用了 `libunwind`。
6. **`Unwind` 函数 (如果使用)：** 如果启用了 `BACKTRACE_FULL`，`PointerData` 会调用 `Unwind` 函数。这个函数通常使用 `libunwind` 库来执行更精确的堆栈回溯。`libunwind` 可以处理更复杂的情况，例如帧指针优化 (frame pointer optimization)。它也依赖于动态链接器提供的加载信息以及 SO 文件中的调试信息（例如，`.eh_frame`）。

**假设输入与输出 (逻辑推理)：**

**假设输入：**

1. 程序执行到某个点，调用了 `malloc(1024)`。
2. `Config` 中启用了 `BACKTRACE` 选项。

**处理过程：**

1. `malloc` 的包装函数 (由 `malloc_debug` 提供) 会调用 `PointerData::Add`。
2. `PointerData::Add` 检测到 `BACKTRACE` 已启用，会调用 `PointerData::AddBacktrace(backtrace_frames, 1024)`。
3. `PointerData::AddBacktrace` 调用 `backtrace_get` 获取当前堆栈的回溯地址。
4. `backtrace_get` 与 dynamic linker 交互，获取调用栈上的返回地址。
5. `PointerData::AddBacktrace` 将分配的地址、大小以及获取到的回溯信息存储在 `pointers_` 和 `frames_` 等数据结构中。

**假设输出 (存储在 `PointerData` 的内部数据结构中)：**

- `pointers_`: 可能包含一个条目，键是分配的指针地址 (经过 `ManglePointer` 处理)，值包含分配大小和回溯信息的索引。
- `frames_`: 可能包含一个条目，键是回溯帧的哈希值，值包含回溯帧的向量。

**假设输入：**

1. 程序后续调用了 `free` 之前分配的地址。

**处理过程：**

1. `free` 的包装函数会调用 `PointerData::Remove`。
2. `PointerData::Remove` 根据指针地址找到对应的分配信息，并调用 `PointerData::RemoveBacktrace` 来减少回溯信息的引用计数。

**用户或编程常见的使用错误及举例说明：**

1. **忘记释放内存 (内存泄漏)：**
   ```c++
   void foo() {
       int* ptr = (int*)malloc(sizeof(int) * 10);
       // ... 一些操作，但忘记 free ptr 了
   }
   ```
   `PointerData` 会在程序退出时检测到 `ptr` 指向的内存块未被释放并报告泄漏。

2. **释放已释放的内存 (Double Free)：**
   ```c++
   int* ptr = (int*)malloc(sizeof(int));
   free(ptr);
   free(ptr); // 错误！
   ```
   虽然 `PointerData` 主要关注 use-after-free 和 leaks，但一些更高级的 `malloc_debug` 配置可能会检测到 double free。

3. **使用已释放的内存 (Use-After-Free)：**
   ```c++
   int* ptr = (int*)malloc(sizeof(int));
   *ptr = 10;
   free(ptr);
   *ptr = 20; // 错误！访问已释放的内存
   ```
   如果启用了 `FREE_TRACK` 选项，`PointerData` 会用特定的值填充已释放的内存。当后续访问该内存时，如果内容与填充值不一致，`PointerData` 会检测到 use-after-free 错误。

4. **写入超出分配范围的内存 (Heap Buffer Overflow)：**
   ```c++
   int* arr = (int*)malloc(sizeof(int) * 5);
   arr[10] = 100; // 错误！越界访问
   ```
   虽然 `PointerData` 不直接阻止堆溢出，但如果溢出破坏了内存分配器的元数据，可能会在后续的分配或释放操作中被检测到。

**说明 Android Framework 或 NDK 是如何一步步到达这里的，给出 Frida Hook 示例调试这些步骤。**

**Android Framework 到 `PointerData` 的路径：**

1. **Java 代码请求分配内存：** Android Framework 中的 Java 代码（例如，`Bitmap.allocateBuffer()`，`new byte[size]` 等）最终会调用 native 方法。
2. **Native 方法调用 `malloc`：** 这些 native 方法通常会通过 JNI 调用 Bionic 库提供的内存分配函数，例如 `malloc`。
3. **`malloc_debug` 的介入：** 如果启用了 `malloc_debug`，对 `malloc` 的调用会被 `malloc_debug` 提供的包装函数拦截。
4. **`PointerData` 的调用：** `malloc_debug` 的包装函数会调用 `PointerData::Add` 来记录分配信息。

**NDK 到 `PointerData` 的路径：**

1. **NDK 代码调用 `malloc`：** 使用 NDK 开发的应用直接调用 Bionic 库提供的 `malloc` 函数。
2. **`malloc_debug` 的介入：** 同样，如果启用了 `malloc_debug`，调用会被拦截。
3. **`PointerData` 的调用：** `malloc_debug` 的包装函数调用 `PointerData::Add`。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `malloc` 函数并观察 `PointerData::Add` 调用的示例：

```javascript
// hook_malloc.js
if (Process.arch === 'arm64' || Process.arch === 'x64') {
  const mallocPtr = Module.findExportByName(null, 'malloc');
  if (mallocPtr) {
    Interceptor.attach(mallocPtr, {
      onEnter: function (args) {
        const size = args[0].toInt();
        console.log(`malloc(${size})`);
      },
      onLeave: function (retval) {
        const ptr = retval;
        if (ptr.isNull()) {
          console.log('malloc returned NULL');
        } else {
          console.log(`malloc returned ${ptr}`);
          // Hook PointerData::Add (需要找到其地址)
          const pointerDataModule = Process.getModuleByName("libc.so"); // 或 "libc++.so"
          const addSymbol = pointerDataModule.findSymbolByName("_ZN11PointerData3AddEPKvj"); // 需要 demangle 得到确切符号名
          if (addSymbol) {
            Interceptor.attach(addSymbol.address, {
              onEnter: function(args) {
                const p = args[0];
                const sz = args[1].toInt();
                console.log(`  PointerData::Add(ptr=${p}, size=${sz})`);
              }
            });
          }
        }
      }
    });
  } else {
    console.log('malloc not found');
  }
} else {
  console.log('Unsupported architecture for this example.');
}
```

**使用方法：**

1. 将上述代码保存为 `hook_malloc.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_malloc.js --no-pause
   ```
   或者，如果进程已经运行：
   ```bash
   frida -U <package_name> -l hook_malloc.js
   ```

**调试步骤：**

1. 运行包含内存分配的 Android 应用或执行 NDK 代码。
2. Frida 脚本会拦截对 `malloc` 的调用，并打印分配的大小和返回的指针。
3. 脚本还会尝试 Hook `PointerData::Add` 函数。你需要根据目标 Android 版本的 Bionic 库找到 `PointerData::Add` 的确切符号名 (可能需要使用 `ndk-stack` 或类似的工具)。
4. 当 `PointerData::Add` 被调用时，Frida 会打印传递给它的指针和大小信息，从而让你观察到内存分配是如何被 `PointerData` 跟踪的。

**注意：** Hook 系统库函数可能需要 root 权限或在可调试的进程中进行。符号名的 mangling 规则可能因编译器版本而异，因此需要根据实际情况调整 Frida 脚本。

通过以上分析，我们可以看到 `PointerData.cpp` 在 Android 内存管理和调试中扮演着至关重要的角色，它为开发者提供了强大的工具来识别和解决内存相关的问题。

### 提示词
```
这是目录为bionic/libc/malloc_debug/PointerData.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>
#include <platform/bionic/macros.h>

#include "Config.h"
#include "DebugData.h"
#include "PointerData.h"
#include "backtrace.h"
#include "debug_log.h"
#include "malloc_debug.h"
#include "UnwindBacktrace.h"

std::atomic_uint8_t PointerData::backtrace_enabled_;
std::atomic_bool PointerData::backtrace_dump_;

std::mutex PointerData::pointer_mutex_;
std::unordered_map<uintptr_t, PointerInfoType> PointerData::pointers_ GUARDED_BY(
    PointerData::pointer_mutex_);

std::mutex PointerData::frame_mutex_;
std::unordered_map<FrameKeyType, size_t> PointerData::key_to_index_ GUARDED_BY(
    PointerData::frame_mutex_);
std::unordered_map<size_t, FrameInfoType> PointerData::frames_ GUARDED_BY(PointerData::frame_mutex_);
std::unordered_map<size_t, std::vector<unwindstack::FrameData>> PointerData::backtraces_info_
    GUARDED_BY(PointerData::frame_mutex_);
constexpr size_t kBacktraceEmptyIndex = 1;
size_t PointerData::cur_hash_index_ GUARDED_BY(PointerData::frame_mutex_);

std::mutex PointerData::free_pointer_mutex_;
std::deque<FreePointerInfoType> PointerData::free_pointers_ GUARDED_BY(
    PointerData::free_pointer_mutex_);

// Buffer to use for comparison.
static constexpr size_t kCompareBufferSize = 512 * 1024;
static std::vector<uint8_t> g_cmp_mem(0);

static void ToggleBacktraceEnable(int, siginfo_t*, void*) {
  g_debug->pointer->ToggleBacktraceEnabled();
}

static void EnableDump(int, siginfo_t*, void*) {
  g_debug->pointer->EnableDumping();
}

PointerData::PointerData(DebugData* debug_data) : OptionData(debug_data) {}

bool PointerData::Initialize(const Config& config) NO_THREAD_SAFETY_ANALYSIS {
  pointers_.clear();
  key_to_index_.clear();
  frames_.clear();
  free_pointers_.clear();
  // A hash index of kBacktraceEmptyIndex indicates that we tried to get
  // a backtrace, but there was nothing recorded.
  cur_hash_index_ = kBacktraceEmptyIndex + 1;

  backtrace_enabled_ = config.backtrace_enabled();
  if (config.backtrace_enable_on_signal()) {
    struct sigaction64 enable_act = {};
    enable_act.sa_sigaction = ToggleBacktraceEnable;
    enable_act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    if (sigaction64(config.backtrace_signal(), &enable_act, nullptr) != 0) {
      error_log("Unable to set up backtrace signal enable function: %s", strerror(errno));
      return false;
    }
    if (config.options() & VERBOSE) {
      info_log("%s: Run: 'kill -%d %d' to enable backtracing.", getprogname(),
               config.backtrace_signal(), getpid());
    }
  }

  if (config.options() & BACKTRACE) {
    struct sigaction64 act = {};
    act.sa_sigaction = EnableDump;
    act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    if (sigaction64(config.backtrace_dump_signal(), &act, nullptr) != 0) {
      error_log("Unable to set up backtrace dump signal function: %s", strerror(errno));
      return false;
    }
    if (config.options() & VERBOSE) {
      info_log("%s: Run: 'kill -%d %d' to dump the backtrace.", getprogname(),
               config.backtrace_dump_signal(), getpid());
    }
  }

  backtrace_dump_ = false;

  if (config.options() & FREE_TRACK) {
    g_cmp_mem.resize(kCompareBufferSize, config.fill_free_value());
  }
  return true;
}

static inline bool ShouldBacktraceAllocSize(size_t size_bytes) {
  static bool only_backtrace_specific_sizes =
      g_debug->config().options() & BACKTRACE_SPECIFIC_SIZES;
  if (!only_backtrace_specific_sizes) {
    return true;
  }
  static size_t min_size_bytes = g_debug->config().backtrace_min_size_bytes();
  static size_t max_size_bytes = g_debug->config().backtrace_max_size_bytes();
  return size_bytes >= min_size_bytes && size_bytes <= max_size_bytes;
}

size_t PointerData::AddBacktrace(size_t num_frames, size_t size_bytes) {
  if (!ShouldBacktraceAllocSize(size_bytes)) {
    return kBacktraceEmptyIndex;
  }

  std::vector<uintptr_t> frames;
  std::vector<unwindstack::FrameData> frames_info;
  if (g_debug->config().options() & BACKTRACE_FULL) {
    if (!Unwind(&frames, &frames_info, num_frames)) {
      return kBacktraceEmptyIndex;
    }
  } else {
    frames.resize(num_frames);
    num_frames = backtrace_get(frames.data(), frames.size());
    if (num_frames == 0) {
      return kBacktraceEmptyIndex;
    }
    frames.resize(num_frames);
  }

  FrameKeyType key{.num_frames = frames.size(), .frames = frames.data()};
  size_t hash_index;
  std::lock_guard<std::mutex> frame_guard(frame_mutex_);
  auto entry = key_to_index_.find(key);
  if (entry == key_to_index_.end()) {
    hash_index = cur_hash_index_++;
    key.frames = frames.data();
    key_to_index_.emplace(key, hash_index);

    frames_.emplace(hash_index, FrameInfoType{.references = 1, .frames = std::move(frames)});
    if (g_debug->config().options() & BACKTRACE_FULL) {
      backtraces_info_.emplace(hash_index, std::move(frames_info));
    }
  } else {
    hash_index = entry->second;
    FrameInfoType* frame_info = &frames_[hash_index];
    frame_info->references++;
  }
  return hash_index;
}

void PointerData::RemoveBacktrace(size_t hash_index) {
  if (hash_index <= kBacktraceEmptyIndex) {
    return;
  }

  std::lock_guard<std::mutex> frame_guard(frame_mutex_);
  auto frame_entry = frames_.find(hash_index);
  if (frame_entry == frames_.end()) {
    error_log("hash_index %zu does not have matching frame data.", hash_index);
    return;
  }
  FrameInfoType* frame_info = &frame_entry->second;
  if (--frame_info->references == 0) {
    FrameKeyType key{.num_frames = frame_info->frames.size(), .frames = frame_info->frames.data()};
    key_to_index_.erase(key);
    frames_.erase(hash_index);
    if (g_debug->config().options() & BACKTRACE_FULL) {
      backtraces_info_.erase(hash_index);
    }
  }
}

void PointerData::Add(const void* ptr, size_t pointer_size) {
  size_t hash_index = 0;
  if (backtrace_enabled_) {
    hash_index = AddBacktrace(g_debug->config().backtrace_frames(), pointer_size);
  }

  std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
  uintptr_t mangled_ptr = ManglePointer(reinterpret_cast<uintptr_t>(ptr));
  pointers_[mangled_ptr] =
      PointerInfoType{PointerInfoType::GetEncodedSize(pointer_size), hash_index};
}

void PointerData::Remove(const void* ptr) {
  size_t hash_index;
  {
    std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
    uintptr_t mangled_ptr = ManglePointer(reinterpret_cast<uintptr_t>(ptr));
    auto entry = pointers_.find(mangled_ptr);
    if (entry == pointers_.end()) {
      // Attempt to remove unknown pointer.
      error_log("No tracked pointer found for 0x%" PRIxPTR, DemanglePointer(mangled_ptr));
      return;
    }
    hash_index = entry->second.hash_index;
    pointers_.erase(mangled_ptr);
  }

  RemoveBacktrace(hash_index);
}

size_t PointerData::GetFrames(const void* ptr, uintptr_t* frames, size_t max_frames) {
  size_t hash_index;
  {
    std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
    uintptr_t mangled_ptr = ManglePointer(reinterpret_cast<uintptr_t>(ptr));
    auto entry = pointers_.find(mangled_ptr);
    if (entry == pointers_.end()) {
      return 0;
    }
    hash_index = entry->second.hash_index;
  }

  if (hash_index <= kBacktraceEmptyIndex) {
    return 0;
  }

  std::lock_guard<std::mutex> frame_guard(frame_mutex_);
  auto frame_entry = frames_.find(hash_index);
  if (frame_entry == frames_.end()) {
    return 0;
  }
  FrameInfoType* frame_info = &frame_entry->second;
  if (max_frames > frame_info->frames.size()) {
    max_frames = frame_info->frames.size();
  }
  memcpy(frames, &frame_info->frames[0], max_frames * sizeof(uintptr_t));

  return max_frames;
}

void PointerData::LogBacktrace(size_t hash_index) {
  std::lock_guard<std::mutex> frame_guard(frame_mutex_);
  if (g_debug->config().options() & BACKTRACE_FULL) {
    auto backtrace_info_entry = backtraces_info_.find(hash_index);
    if (backtrace_info_entry != backtraces_info_.end()) {
      UnwindLog(backtrace_info_entry->second);
      return;
    }
  } else {
    auto frame_entry = frames_.find(hash_index);
    if (frame_entry != frames_.end()) {
      FrameInfoType* frame_info = &frame_entry->second;
      backtrace_log(frame_info->frames.data(), frame_info->frames.size());
      return;
    }
  }
  error_log("  hash_index %zu does not have matching frame data.", hash_index);
}

void PointerData::LogFreeError(const FreePointerInfoType& info, size_t max_cmp_bytes) {
  error_log(LOG_DIVIDER);
  uintptr_t pointer = DemanglePointer(info.mangled_ptr);
  uint8_t* memory = reinterpret_cast<uint8_t*>(pointer);
  error_log("+++ ALLOCATION %p USED AFTER FREE", memory);
  uint8_t fill_free_value = g_debug->config().fill_free_value();
  for (size_t i = 0; i < max_cmp_bytes; i++) {
    if (memory[i] != fill_free_value) {
      error_log("  allocation[%zu] = 0x%02x (expected 0x%02x)", i, memory[i], fill_free_value);
    }
  }

  if (info.hash_index > kBacktraceEmptyIndex) {
    error_log("Backtrace at time of free:");
    LogBacktrace(info.hash_index);
  }

  error_log(LOG_DIVIDER);
  if (g_debug->config().options() & ABORT_ON_ERROR) {
    abort();
  }
}

void PointerData::VerifyFreedPointer(const FreePointerInfoType& info) {
  size_t usable_size;
  uintptr_t pointer = DemanglePointer(info.mangled_ptr);
  if (g_debug->HeaderEnabled()) {
    // Check to see if the tag data has been damaged.
    Header* header = g_debug->GetHeader(reinterpret_cast<const void*>(pointer));
    if (header->tag != DEBUG_FREE_TAG) {
      error_log(LOG_DIVIDER);
      error_log("+++ ALLOCATION 0x%" PRIxPTR " HAS CORRUPTED HEADER TAG 0x%x AFTER FREE", pointer,
                header->tag);
      error_log(LOG_DIVIDER);
      if (g_debug->config().options() & ABORT_ON_ERROR) {
        abort();
      }

      // Stop processing here, it is impossible to tell how the header
      // may have been damaged.
      return;
    }
    usable_size = header->usable_size;
  } else {
    usable_size = g_dispatch->malloc_usable_size(reinterpret_cast<const void*>(pointer));
  }

  size_t bytes = (usable_size < g_debug->config().fill_on_free_bytes())
                     ? usable_size
                     : g_debug->config().fill_on_free_bytes();
  size_t max_cmp_bytes = bytes;
  const uint8_t* memory = reinterpret_cast<const uint8_t*>(pointer);
  while (bytes > 0) {
    size_t bytes_to_cmp = (bytes < g_cmp_mem.size()) ? bytes : g_cmp_mem.size();
    if (memcmp(memory, g_cmp_mem.data(), bytes_to_cmp) != 0) {
      LogFreeError(info, max_cmp_bytes);
    }
    bytes -= bytes_to_cmp;
    memory = &memory[bytes_to_cmp];
  }
}

void* PointerData::AddFreed(const void* ptr, size_t size_bytes) {
  size_t hash_index = 0;
  size_t num_frames = g_debug->config().free_track_backtrace_num_frames();
  if (num_frames) {
    hash_index = AddBacktrace(num_frames, size_bytes);
  }

  void* last = nullptr;
  std::lock_guard<std::mutex> freed_guard(free_pointer_mutex_);
  if (free_pointers_.size() == g_debug->config().free_track_allocations()) {
    FreePointerInfoType info(free_pointers_.front());
    free_pointers_.pop_front();
    VerifyFreedPointer(info);
    RemoveBacktrace(info.hash_index);
    last = reinterpret_cast<void*>(DemanglePointer(info.mangled_ptr));
  }

  uintptr_t mangled_ptr = ManglePointer(reinterpret_cast<uintptr_t>(ptr));
  free_pointers_.emplace_back(FreePointerInfoType{mangled_ptr, hash_index});
  return last;
}

void PointerData::LogFreeBacktrace(const void* ptr) {
  size_t hash_index = 0;
  {
    uintptr_t pointer = reinterpret_cast<uintptr_t>(ptr);
    std::lock_guard<std::mutex> freed_guard(free_pointer_mutex_);
    for (const auto& info : free_pointers_) {
      if (DemanglePointer(info.mangled_ptr) == pointer) {
        hash_index = info.hash_index;
        break;
      }
    }
  }

  if (hash_index <= kBacktraceEmptyIndex) {
    return;
  }

  error_log("Backtrace of original free:");
  LogBacktrace(hash_index);
}

void PointerData::VerifyAllFreed() {
  std::lock_guard<std::mutex> freed_guard(free_pointer_mutex_);
  for (auto& free_info : free_pointers_) {
    VerifyFreedPointer(free_info);
  }
}

void PointerData::GetList(std::vector<ListInfoType>* list, bool only_with_backtrace)
    REQUIRES(pointer_mutex_, frame_mutex_) {
  for (const auto& entry : pointers_) {
    FrameInfoType* frame_info = nullptr;
    std::vector<unwindstack::FrameData>* backtrace_info = nullptr;
    uintptr_t pointer = DemanglePointer(entry.first);
    size_t hash_index = entry.second.hash_index;
    if (hash_index > kBacktraceEmptyIndex) {
      auto frame_entry = frames_.find(hash_index);
      if (frame_entry == frames_.end()) {
        // Somehow wound up with a pointer with a valid hash_index, but
        // no frame data. This should not be possible since adding a pointer
        // occurs after the hash_index and frame data have been added.
        // When removing a pointer, the pointer is deleted before the frame
        // data.
        error_log("Pointer 0x%" PRIxPTR " hash_index %zu does not exist.", pointer, hash_index);
      } else {
        frame_info = &frame_entry->second;
      }

      if (g_debug->config().options() & BACKTRACE_FULL) {
        auto backtrace_entry = backtraces_info_.find(hash_index);
        if (backtrace_entry == backtraces_info_.end()) {
          error_log("Pointer 0x%" PRIxPTR " hash_index %zu does not exist.", pointer, hash_index);
        } else {
          backtrace_info = &backtrace_entry->second;
        }
      }
    }
    if (hash_index == 0 && only_with_backtrace) {
      continue;
    }

    list->emplace_back(ListInfoType{pointer, 1, entry.second.RealSize(),
                                    entry.second.ZygoteChildAlloc(), frame_info, backtrace_info});
  }

  // Sort by the size of the allocation.
  std::sort(list->begin(), list->end(), [](const ListInfoType& a, const ListInfoType& b) {
    // Put zygote child allocations first.
    bool a_zygote_child_alloc = a.zygote_child_alloc;
    bool b_zygote_child_alloc = b.zygote_child_alloc;
    if (a_zygote_child_alloc && !b_zygote_child_alloc) {
      return false;
    }
    if (!a_zygote_child_alloc && b_zygote_child_alloc) {
      return true;
    }

    // Sort by size, descending order.
    if (a.size != b.size) return a.size > b.size;

    // Put pointers with no backtrace last.
    FrameInfoType* a_frame = a.frame_info;
    FrameInfoType* b_frame = b.frame_info;
    if (a_frame == nullptr && b_frame != nullptr) {
      return false;
    } else if (a_frame != nullptr && b_frame == nullptr) {
      return true;
    } else if (a_frame == nullptr && b_frame == nullptr) {
      return a.pointer < b.pointer;
    }

    // Put the pointers with longest backtrace first.
    if (a_frame->frames.size() != b_frame->frames.size()) {
      return a_frame->frames.size() > b_frame->frames.size();
    }

    // Last sort by pointer.
    return a.pointer < b.pointer;
  });
}

void PointerData::GetUniqueList(std::vector<ListInfoType>* list, bool only_with_backtrace)
    REQUIRES(pointer_mutex_, frame_mutex_) {
  GetList(list, only_with_backtrace);

  // Remove duplicates of size/backtraces.
  for (auto iter = list->begin(); iter != list->end();) {
    auto dup_iter = iter + 1;
    bool zygote_child_alloc = iter->zygote_child_alloc;
    size_t size = iter->size;
    FrameInfoType* frame_info = iter->frame_info;
    for (; dup_iter != list->end(); ++dup_iter) {
      if (zygote_child_alloc != dup_iter->zygote_child_alloc || size != dup_iter->size ||
          frame_info != dup_iter->frame_info) {
        break;
      }
      iter->num_allocations++;
    }
    iter = list->erase(iter + 1, dup_iter);
  }
}

void PointerData::LogLeaks() {
  std::vector<ListInfoType> list;

  std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
  std::lock_guard<std::mutex> frame_guard(frame_mutex_);
  GetList(&list, false);

  size_t track_count = 0;
  for (const auto& list_info : list) {
    error_log("+++ %s leaked block of size %zu at 0x%" PRIxPTR " (leak %zu of %zu)", getprogname(),
              list_info.size, list_info.pointer, ++track_count, list.size());
    if (list_info.backtrace_info != nullptr) {
      error_log("Backtrace at time of allocation:");
      UnwindLog(*list_info.backtrace_info);
    } else if (list_info.frame_info != nullptr) {
      error_log("Backtrace at time of allocation:");
      backtrace_log(list_info.frame_info->frames.data(), list_info.frame_info->frames.size());
    }
    // Do not bother to free the pointers, we are about to exit any way.
  }
}

void PointerData::GetAllocList(std::vector<ListInfoType>* list) {
  std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
  std::lock_guard<std::mutex> frame_guard(frame_mutex_);

  if (pointers_.empty()) {
    return;
  }

  GetList(list, false);
}

void PointerData::GetInfo(uint8_t** info, size_t* overall_size, size_t* info_size,
                          size_t* total_memory, size_t* backtrace_size) {
  std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
  std::lock_guard<std::mutex> frame_guard(frame_mutex_);

  if (pointers_.empty()) {
    return;
  }

  std::vector<ListInfoType> list;
  GetUniqueList(&list, true);
  if (list.empty()) {
    return;
  }

  *backtrace_size = g_debug->config().backtrace_frames();
  *info_size = sizeof(size_t) * 2 + sizeof(uintptr_t) * *backtrace_size;
  *overall_size = *info_size * list.size();
  *info = reinterpret_cast<uint8_t*>(g_dispatch->calloc(*info_size, list.size()));
  if (*info == nullptr) {
    return;
  }

  uint8_t* data = *info;
  *total_memory = 0;
  for (const auto& list_info : list) {
    FrameInfoType* frame_info = list_info.frame_info;
    *total_memory += list_info.size * list_info.num_allocations;
    size_t allocation_size =
        PointerInfoType::GetEncodedSize(list_info.zygote_child_alloc, list_info.size);
    memcpy(data, &allocation_size, sizeof(size_t));
    memcpy(&data[sizeof(size_t)], &list_info.num_allocations, sizeof(size_t));
    if (frame_info != nullptr) {
      memcpy(&data[2 * sizeof(size_t)], frame_info->frames.data(),
             frame_info->frames.size() * sizeof(uintptr_t));
    }
    data += *info_size;
  }
}

bool PointerData::Exists(const void* ptr) {
  std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
  uintptr_t mangled_ptr = ManglePointer(reinterpret_cast<uintptr_t>(ptr));
  return pointers_.count(mangled_ptr) != 0;
}

void PointerData::DumpLiveToFile(int fd) {
  std::vector<ListInfoType> list;

  std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
  std::lock_guard<std::mutex> frame_guard(frame_mutex_);
  GetUniqueList(&list, false);

  size_t total_memory = 0;
  for (const auto& info : list) {
    total_memory += info.size * info.num_allocations;
  }

  dprintf(fd, "Total memory: %zu\n", total_memory);
  dprintf(fd, "Allocation records: %zd\n", list.size());
  dprintf(fd, "Backtrace size: %zu\n", g_debug->config().backtrace_frames());
  dprintf(fd, "\n");

  for (const auto& info : list) {
    dprintf(fd, "z %d  sz %8zu  num    %zu  bt", (info.zygote_child_alloc) ? 1 : 0, info.size,
            info.num_allocations);
    FrameInfoType* frame_info = info.frame_info;
    if (frame_info != nullptr) {
      for (size_t i = 0; i < frame_info->frames.size(); i++) {
        if (frame_info->frames[i] == 0) {
          break;
        }
        dprintf(fd, " %" PRIxPTR, frame_info->frames[i]);
      }
    }
    dprintf(fd, "\n");
    if (info.backtrace_info != nullptr) {
      dprintf(fd, "  bt_info");
      for (const auto& frame : *info.backtrace_info) {
        dprintf(fd, " {");
        if (frame.map_info != nullptr && !frame.map_info->name().empty()) {
          dprintf(fd, "\"%s\"", frame.map_info->name().c_str());
        } else {
          dprintf(fd, "\"\"");
        }
        dprintf(fd, " %" PRIx64, frame.rel_pc);
        if (frame.function_name.empty()) {
          dprintf(fd, " \"\" 0}");
        } else {
          char* demangled_name =
              abi::__cxa_demangle(frame.function_name.c_str(), nullptr, nullptr, nullptr);
          const char* name;
          if (demangled_name != nullptr) {
            name = demangled_name;
          } else {
            name = frame.function_name.c_str();
          }
          dprintf(fd, " \"%s\" %" PRIx64 "}", name, frame.function_offset);
          free(demangled_name);
        }
      }
      dprintf(fd, "\n");
    }
  }
}

void PointerData::PrepareFork() NO_THREAD_SAFETY_ANALYSIS {
  free_pointer_mutex_.lock();
  pointer_mutex_.lock();
  frame_mutex_.lock();
}

void PointerData::PostForkParent() NO_THREAD_SAFETY_ANALYSIS {
  frame_mutex_.unlock();
  pointer_mutex_.unlock();
  free_pointer_mutex_.unlock();
}

void PointerData::PostForkChild() __attribute__((no_thread_safety_analysis)) {
  // Make sure that any potential mutexes have been released and are back
  // to an initial state.
  frame_mutex_.try_lock();
  frame_mutex_.unlock();
  pointer_mutex_.try_lock();
  pointer_mutex_.unlock();
  free_pointer_mutex_.try_lock();
  free_pointer_mutex_.unlock();
}

void PointerData::IteratePointers(std::function<void(uintptr_t pointer)> fn) {
  std::lock_guard<std::mutex> pointer_guard(pointer_mutex_);
  for (const auto entry : pointers_) {
    fn(DemanglePointer(entry.first));
  }
}
```