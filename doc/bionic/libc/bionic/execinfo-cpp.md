Response:
Let's break down the thought process to answer the user's request about `bionic/libc/bionic/execinfo.cpp`.

**1. Understanding the Core Request:**

The user wants a comprehensive explanation of the `execinfo.cpp` file in Android's Bionic library. This includes:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it tie into the Android ecosystem?
* **Detailed Implementation:** How do the individual functions work internally?
* **Dynamic Linking:** How does it interact with the dynamic linker, including SO layout and linking process?
* **Logical Reasoning:**  Are there any assumptions or input/output scenarios to consider?
* **Common Errors:** What mistakes do developers often make when using these functions?
* **Android Framework/NDK Integration:**  How does a call to these functions originate from higher levels in Android?
* **Frida Hooking:** How can these functions be inspected using Frida?

**2. High-Level Functionality Identification:**

A quick scan of the code reveals the presence of standard C library functions related to stack traces: `backtrace`, `backtrace_symbols`, and `backtrace_symbols_fd`. The inclusion of `<unwind.h>` and the `_Unwind_Backtrace` function strongly suggests that this code is about capturing and processing stack unwinding information.

**3. Detailed Function Analysis (Iterative Process):**

For each function, I need to understand its purpose and implementation.

* **`backtrace(void** buffer, int size)`:**
    * **Purpose:**  Collect raw stack frame addresses.
    * **Implementation:** Uses `_Unwind_Backtrace` with a custom callback (`TraceFunction`). The `TraceFunction`'s logic adjusts the instruction pointer (`ip`) based on the architecture (ARM, AArch64, RISC-V, x86) to point to the actual function call. This is crucial for accuracy. It stores these adjusted `ip` values into the provided `buffer`.
    * **Key Insight:**  The architecture-specific adjustments are important details.

* **`TraceFunction(_Unwind_Context* context, void* arg)`:**
    * **Purpose:** The callback function for `_Unwind_Backtrace`. It's the workhorse of `backtrace`.
    * **Implementation:**  Retrieves the instruction pointer using `_Unwind_GetIP`, performs architecture-specific adjustments, and stores the result in the `frames` buffer.
    * **Key Insight:**  Understanding how `_Unwind_Backtrace` works is essential here.

* **`backtrace_symbols(void* const* buffer, int size)`:**
    * **Purpose:**  Convert raw addresses from `backtrace` into human-readable symbols.
    * **Implementation:** Uses `backtrace_symbols_fd` to write the symbol information to a temporary file (using `memfd_create`). It then reads the contents of this file into a single large buffer containing both the pointers to the strings and the string data itself. This optimizes memory management (only one `free` is needed).
    * **Key Insight:** The use of `memfd_create` and the single buffer allocation are Android-specific optimizations.

* **`backtrace_symbols_fd(void* const* buffer, int size, int fd)`:**
    * **Purpose:** The core logic for converting addresses to symbols and writing them to a file descriptor.
    * **Implementation:** Iterates through the addresses. For each address, it uses `dladdr` to find the corresponding shared object, function name, and offset within the function. It then formats this information and writes it to the provided file descriptor.
    * **Key Insight:** The reliance on `dladdr` is crucial for understanding how it resolves symbols at runtime.

**4. Addressing Specific User Questions:**

* **Functionality:**  Summarize the purpose of each function and the file as a whole (capturing stack traces).
* **Android Relevance:** Explain how stack traces are used for debugging, crash reporting, and profiling on Android. Give concrete examples like ANRs and crash dumps.
* **Libc Function Implementation:** Detail the inner workings of each function as described in the detailed analysis above.
* **Dynamic Linker Interaction:**
    * **SO Layout Sample:** Provide a simplified example of how shared libraries are laid out in memory. Include sections like `.text`, `.data`, `.bss`, and `.plt`, `.got`.
    * **Linking Process:** Briefly describe the role of the dynamic linker in resolving symbols at runtime, focusing on `dladdr`. Explain PLT/GOT.
* **Logical Reasoning:** Consider scenarios like calling `backtrace` with a small buffer. Explain the potential output.
* **Common Errors:** Highlight issues like buffer overflows, forgetting to free memory, and interpreting the output incorrectly.
* **Android Framework/NDK Integration:** Trace a call from a high-level framework component (like an exception handler) down to the NDK and then to `backtrace`.
* **Frida Hooking:** Provide practical Frida script examples to hook `backtrace`, `backtrace_symbols`, and `backtrace_symbols_fd` to log their input and output.

**5. Structuring the Response:**

Organize the information logically, addressing each part of the user's request systematically. Use headings and bullet points for clarity. Provide code examples where appropriate (SO layout, Frida scripts).

**6. Language and Tone:**

Use clear and concise Chinese. Explain technical terms where necessary. Adopt a helpful and informative tone.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe just focus on the C++ code.
* **Correction:** Realized the importance of explaining the underlying C functions and the dynamic linker interaction.
* **Initial thought:** Just list the functions.
* **Correction:**  Need to explain the *how* behind the implementation, not just the *what*.
* **Initial thought:** Provide very complex SO layouts.
* **Correction:**  Keep the SO layout simple and illustrative for better understanding.
* **Initial thought:**  Assume the user knows about Frida.
* **Correction:** Briefly explain what Frida is before providing the hook examples.

By following this structured approach, combining code analysis with an understanding of the underlying concepts and addressing each aspect of the user's request, a comprehensive and helpful answer can be generated.
好的，让我们详细分析一下 `bionic/libc/bionic/execinfo.cpp` 这个文件。

**功能概述**

`execinfo.cpp` 提供了用于获取和解析程序运行时调用栈信息的功能。它包含了以下几个主要的函数：

* **`backtrace(void** buffer, int size)`:**  用于获取当前线程的调用栈信息，并将返回的指令指针地址存储在 `buffer` 中。`size` 参数指定了 `buffer` 的大小，限制了可以获取的栈帧数量。
* **`backtrace_symbols(void* const* buffer, int size)`:**  将 `backtrace` 函数返回的指令指针地址数组转换为可读的符号名称字符串数组。它会尝试查找每个地址对应的函数名、偏移量以及所在的共享库。
* **`backtrace_symbols_fd(void* const* buffer, int size, int fd)`:**  与 `backtrace_symbols` 功能类似，但它将符号信息直接写入到指定的文件描述符 `fd` 中，而不是返回字符串数组。

**与 Android 功能的关系及举例说明**

`execinfo.cpp` 中提供的功能对于 Android 平台的调试、错误报告和性能分析至关重要。

* **崩溃报告 (Crash Reporting):** 当 Android 应用发生崩溃时，系统会收集应用的调用栈信息。这些信息通常是通过类似 `backtrace` 和 `backtrace_symbols` 的机制获取的，并包含在错误报告中。开发者可以通过分析这些调用栈，定位导致崩溃的代码位置。
    * **举例:**  一个 Java 应用调用了 JNI 代码，JNI 代码中发生了空指针异常。Android 系统会捕获到这个异常，并生成一个包含 native 层调用栈的 tombstone 文件。这个调用栈信息就是通过 `backtrace` 等函数获取的。
* **ANR (Application Not Responding) 分析:**  当应用的主线程阻塞过久时，系统会弹出 ANR 对话框。为了帮助开发者诊断 ANR 问题，系统也会收集应用的调用栈信息。
    * **举例:**  主线程执行了一个耗时的同步操作，导致 UI 线程卡顿。开发者可以通过分析 ANR 报告中的调用栈，找出导致主线程阻塞的代码。
* **性能分析 (Profiling):**  一些性能分析工具会周期性地采样应用的调用栈信息，以了解程序的热点函数，帮助开发者进行性能优化。
    * **举例:**  使用 Android Studio 的 Profiler 工具，可以查看应用的 CPU 使用情况和调用栈信息，从而找出性能瓶颈。

**libc 函数的实现细节**

1. **`backtrace(void** buffer, int size)` 的实现:**

   * **核心机制:**  `backtrace` 函数的核心是调用了 `_Unwind_Backtrace` 函数。这是一个与平台架构相关的底层 unwinding (栈回溯) 机制。
   * **`_Unwind_Backtrace(TraceFunction, &state)`:**  `_Unwind_Backtrace` 接受一个回调函数 `TraceFunction` 和一个用户提供的参数 `state`。它会遍历当前的调用栈帧。对于每一个栈帧，它会调用 `TraceFunction`，并将当前栈帧的上下文信息 (`_Unwind_Context`) 和用户提供的参数传递给它。
   * **`TraceFunction(_Unwind_Context* context, void* arg)` 的实现:**
     * **获取指令指针 (IP):** `TraceFunction` 首先通过 `_Unwind_GetIP(context)` 获取当前栈帧的指令指针地址。这个地址通常指向函数返回后的下一条指令。
     * **调整指令指针:**  为了指向实际的函数起始位置，代码根据不同的 CPU 架构进行了调整：
       * **ARM:**  检查指令是 16 位还是 32 位，并相应地减去 2 或 4。
       * **AArch64:** 所有指令都是 4 字节，减去 4。
       * **RISC-V:** C 扩展指令最短为 2 字节，减去 2。
       * **i386/x86_64:**  指令长度不固定，简单地减去 1 作为估计。
     * **存储地址:**  将调整后的指令指针地址存储到 `StackState` 结构体中的 `frames` 数组中。
     * **控制回溯:**  如果已收集到足够数量的栈帧（达到 `size`），则返回 `_URC_END_OF_STACK`，通知 `_Unwind_Backtrace` 停止回溯。否则返回 `_URC_NO_REASON` 继续回溯。
   * **`StackState` 结构体:**  用于在 `backtrace` 和 `TraceFunction` 之间传递数据，包括存储栈帧地址的缓冲区 `frames`，缓冲区大小 `frame_count` 和当前已存储的栈帧数量 `cur_frame`。

2. **`backtrace_symbols(void* const* buffer, int size)` 的实现:**

   * **创建内存文件描述符:**  使用 `memfd_create` 创建一个匿名内存文件描述符，用于临时存储符号信息。`MFD_CLOEXEC` 标志确保该文件描述符在 `execve` 后会被关闭。
   * **调用 `backtrace_symbols_fd`:**  将栈帧地址数组、大小和内存文件描述符传递给 `backtrace_symbols_fd` 进行处理。
   * **获取文件大小:**  使用 `lseek` 获取内存文件的大小，即 `backtrace_symbols_fd` 写入的符号信息的大小。
   * **分配内存:**  分配一块足够大的内存来存储所有符号字符串的指针以及实际的符号字符串数据。这样做的好处是只需要 `free` 一次内存。
   * **读取符号信息:**  使用 `read` 将内存文件中的符号信息读取到分配的内存中。
   * **解析字符串:**  遍历读取到的数据，将每个换行符替换为 null 终止符，并将指向每个符号字符串起始位置的指针存储到 `symbol_data` 的前面部分。
   * **返回指针数组:**  返回指向符号字符串指针数组的指针。

3. **`backtrace_symbols_fd(void* const* buffer, int size, int fd)` 的实现:**

   * **遍历栈帧地址:**  遍历 `buffer` 中的每个指令指针地址。
   * **使用 `dladdr` 获取符号信息:**  对于每个地址，调用 `dladdr(address, &info)`。`dladdr` 是 dynamic linker (动态链接器) 提供的函数，用于查找指定地址所属的共享库、函数名以及地址在函数内的偏移量。
     * **`Dl_info` 结构体:**  `dladdr` 将查找到的信息存储在 `Dl_info` 结构体中，包括：
       * `dli_fname`: 共享库的文件路径。
       * `dli_fbase`: 共享库的加载基址。
       * `dli_sname`: 最接近地址的符号名称 (函数名)。
       * `dli_saddr`: 符号的起始地址。
   * **格式化输出:**  根据 `dladdr` 返回的信息，将符号信息格式化后写入到文件描述符 `fd` 中：
     * 如果找到了共享库名 (`info.dli_fname`)，则写入共享库名。
     * 如果找到了符号名 (`info.dli_sname`)，则写入符号名和地址相对于符号起始地址的偏移量。
     * 如果没有找到符号名，则写入符号的起始地址。
     * 最后，写入原始的指令指针地址。

**涉及 dynamic linker 的功能**

`backtrace_symbols_fd` 函数的核心就是与 dynamic linker 交互，通过 `dladdr` 函数来解析地址对应的符号信息。

**SO 布局样本:**

假设我们有一个简单的共享库 `libtest.so`，它包含一个函数 `my_function`：

```
(内存地址递增)
--------------------
| .text (代码段)   |  <-- my_function 的代码可能在这里
--------------------
| .rodata (只读数据) |
--------------------
| .data (已初始化数据) |
--------------------
| .bss (未初始化数据) |
--------------------
| .plt (过程链接表)  |  <-- 用于延迟绑定
--------------------
| .got (全局偏移表)  |  <-- 存储全局变量和函数地址
--------------------
```

**链接的处理过程:**

1. **编译时:** 编译器在编译 `libtest.so` 时，会将 `my_function` 的符号信息记录在符号表 (symbol table) 中。
2. **加载时:** 当 Android 系统加载 `libtest.so` 时，dynamic linker 会将它加载到内存中的某个地址。
3. **运行时 (调用 `dladdr`):**  当 `backtrace_symbols_fd` 调用 `dladdr(address, &info)` 时，dynamic linker 会执行以下操作：
   * **查找共享库:**  根据 `address` 所在的内存范围，确定它属于哪个已加载的共享库 (`libtest.so`)。
   * **查找符号:** 在 `libtest.so` 的符号表中查找最接近 `address` 的符号。
   * **计算偏移量:** 计算 `address` 与找到的符号的起始地址 (`info.dli_saddr`) 之间的偏移量。
   * **填充 `Dl_info`:** 将找到的共享库路径、加载基址、符号名和符号地址填充到 `Dl_info` 结构体中。

**假设输入与输出 (针对 `backtrace_symbols_fd`)**

**假设输入:**

* `buffer`: 包含一个指令指针地址的数组，例如 `{0xb740156c}` (假设这是 `libtest.so` 中 `my_function` 函数内部的某个地址)。
* `size`: 1
* `fd`: 指向一个已打开的文件。

**可能输出到 fd 的内容:**

```
/system/lib/libtest.so(my_function+0x1c) [0xb740156c]
```

**解释:**

* `/system/lib/libtest.so`:  dynamic linker 找到了地址 `0xb740156c` 属于 `libtest.so` 这个共享库。
* `my_function`: dynamic linker 在 `libtest.so` 的符号表中找到了最接近 `0xb740156c` 的符号是 `my_function`。
* `+0x1c`: 计算出地址 `0xb740156c` 相对于 `my_function` 起始地址的偏移量是 `0x1c`。
* `[0xb740156c]`:  原始的指令指针地址。

**用户或编程常见的使用错误**

1. **`backtrace` 缓冲区过小:** 如果传递给 `backtrace` 的 `size` 参数太小，无法容纳所有的栈帧，那么返回的调用栈信息会被截断，可能丢失关键的调用信息。
   * **举例:**
     ```c++
     void* buffer[10];
     int size = backtrace(buffer, 10);
     // 如果实际栈帧超过 10 个，那么 size < 实际栈帧数
     ```
2. **忘记 `free` `backtrace_symbols` 返回的内存:** `backtrace_symbols` 会分配内存来存储符号字符串数组，用户需要在使用完后手动释放这块内存，否则会导致内存泄漏。
   * **举例:**
     ```c++
     void* buffer[20];
     int size = backtrace(buffer, 20);
     char** strings = backtrace_symbols(buffer, size);
     if (strings != nullptr) {
         for (int i = 0; i < size; ++i) {
             printf("%s\n", strings[i]);
         }
         free(strings); // 必须释放内存
     }
     ```
3. **错误地解释 `backtrace` 返回的地址:**  `backtrace` 返回的是指令指针地址，通常指向函数返回后的下一条指令。在 `TraceFunction` 中，代码会尝试调整这个地址以指向实际的函数起始位置，但这仍然可能存在精度问题，特别是在有指令重排等优化的情况下。
4. **在信号处理程序中使用分配内存的函数:**  `backtrace_symbols` 内部会分配内存。在信号处理程序 (signal handler) 中调用可能会导致不可预测的行为，因为信号处理程序可能会中断内存分配操作。`backtrace_symbols_fd` 更适合在信号处理程序中使用，因为它避免了内存分配。

**Android framework 或 NDK 如何一步步到达这里**

1. **Android Framework 层:**  当 Java 代码发生未捕获的异常时，JVM 会捕获这个异常。
2. **Native Bridge 或 JNI:**  如果异常发生在 native 代码中（例如，通过 JNI 调用），或者 JVM 需要报告 native 代码的崩溃，它会调用相关的 native 方法。
3. **Bionic Libc (libbase 或 libc.so):**  Android 的 runtime (ART) 或其他 native 组件可能会调用 libc 提供的函数来获取调用栈信息。
    * 例如，`libbase` 库中的 `android::base::GetStackTrace` 函数会使用 `backtrace` 和 `backtrace_symbols` 来获取和格式化调用栈信息。
4. **`execinfo.cpp` 中的函数:**  最终会调用到 `bionic/libc/bionic/execinfo.cpp` 中定义的 `backtrace` 和 `backtrace_symbols` 函数。
5. **Dynamic Linker (`linker64` 或 `linker`):** `backtrace_symbols` 或 `backtrace_symbols_fd` 会调用 `dladdr`，这是一个由 dynamic linker 提供的函数。

**Frida Hook 示例调试这些步骤**

以下是使用 Frida Hook 调试 `backtrace`, `backtrace_symbols`, 和 `backtrace_symbols_fd` 的示例：

```javascript
// Hook backtrace
Interceptor.attach(Module.findExportByName("libc.so", "backtrace"), {
  onEnter: function (args) {
    console.log("backtrace called!");
    this.buffer = args[0];
    this.size = args[1].toInt();
    console.log("  buffer:", this.buffer);
    console.log("  size:", this.size);
  },
  onLeave: function (retval) {
    console.log("backtrace returned:", retval.toInt());
    if (retval.toInt() > 0) {
      console.log("  Stack frames:");
      for (let i = 0; i < retval.toInt(); i++) {
        const address = this.buffer.readPointer();
        console.log("    [" + i + "]: " + address);
        this.buffer = this.buffer.add(Process.pointerSize);
      }
    }
  },
});

// Hook backtrace_symbols
Interceptor.attach(Module.findExportByName("libc.so", "backtrace_symbols"), {
  onEnter: function (args) {
    console.log("backtrace_symbols called!");
    this.buffer = args[0];
    this.size = args[1].toInt();
    console.log("  buffer:", this.buffer);
    console.log("  size:", this.size);
  },
  onLeave: function (retval) {
    console.log("backtrace_symbols returned:", retval);
    if (!retval.isNull()) {
      for (let i = 0; i < this.size; i++) {
        const symbolPtr = retval.readPointer();
        if (!symbolPtr.isNull()) {
          const symbol = symbolPtr.readCString();
          console.log("  [" + i + "]: " + symbol);
        } else {
          console.log("  [" + i + "]: (null)");
        }
        retval = retval.add(Process.pointerSize);
      }
    }
  },
});

// Hook backtrace_symbols_fd
Interceptor.attach(Module.findExportByName("libc.so", "backtrace_symbols_fd"), {
  onEnter: function (args) {
    console.log("backtrace_symbols_fd called!");
    this.buffer = args[0];
    this.size = args[1].toInt();
    this.fd = args[2].toInt();
    console.log("  buffer:", this.buffer);
    console.log("  size:", this.size);
    console.log("  fd:", this.fd);
  },
});
```

**使用方法:**

1. 将上述 JavaScript 代码保存到一个文件中，例如 `hook_execinfo.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_execinfo.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_execinfo.js
   ```
3. 在目标应用中触发调用栈信息获取的操作（例如，导致崩溃或 ANR）。
4. 查看 Frida 的输出，你将看到 `backtrace`, `backtrace_symbols`, 和 `backtrace_symbols_fd` 被调用时的参数和返回值，从而可以调试调用栈信息的获取过程。

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/execinfo.cpp` 的功能、实现以及在 Android 中的应用。

### 提示词
```
这是目录为bionic/libc/bionic/execinfo.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <dlfcn.h>
#include <execinfo.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <unwind.h>

#include "private/ScopedFd.h"

struct StackState {
  void** frames;
  int frame_count;
  int cur_frame = 0;

  StackState(void** frames, int frame_count) : frames(frames), frame_count(frame_count) {}
};

static _Unwind_Reason_Code TraceFunction(_Unwind_Context* context, void* arg) {
  // The instruction pointer is pointing at the instruction after the return
  // call on all architectures.
  // Modify the pc to point at the real function.
  uintptr_t ip = _Unwind_GetIP(context);
  if (ip != 0) {
#if defined(__arm__)
    // If the ip is suspiciously low, do nothing to avoid a segfault trying
    // to access this memory.
    if (ip >= 4096) {
      // Check bits [15:11] of the first halfword assuming the instruction
      // is 32 bits long. If the bits are any of these values, then our
      // assumption was correct:
      //  b11101
      //  b11110
      //  b11111
      // Otherwise, this is a 16 bit instruction.
      uint16_t value = (*reinterpret_cast<uint16_t*>(ip - 2)) >> 11;
      if (value == 0x1f || value == 0x1e || value == 0x1d) {
        ip -= 4;
      } else {
        ip -= 2;
      }
    }
#elif defined(__aarch64__)
    // All instructions are 4 bytes long, skip back one instruction.
    ip -= 4;
#elif defined(__riscv)
    // C instructions are the shortest at 2 bytes long. (Unlike thumb, it's
    // non-trivial to recognize C instructions when going backwards in the
    // instruction stream.)
    ip -= 2;
#elif defined(__i386__) || defined(__x86_64__)
    // It's difficult to decode exactly where the previous instruction is,
    // so subtract 1 to estimate where the instruction lives.
    ip--;
#endif
  }

  StackState* state = static_cast<StackState*>(arg);
  state->frames[state->cur_frame++] = reinterpret_cast<void*>(ip);
  return (state->cur_frame >= state->frame_count) ? _URC_END_OF_STACK : _URC_NO_REASON;
}

int backtrace(void** buffer, int size) {
  if (size <= 0) {
    return 0;
  }

  StackState state(buffer, size);
  _Unwind_Backtrace(TraceFunction, &state);
  return state.cur_frame;
}

char** backtrace_symbols(void* const* buffer, int size) {
  if (size <= 0) {
    return nullptr;
  }
  // Do this calculation first in case the user passes in a bad value.
  size_t ptr_size;
  if (__builtin_mul_overflow(sizeof(char*), size, &ptr_size)) {
    return nullptr;
  }

  ScopedFd fd(memfd_create("backtrace_symbols_fd", MFD_CLOEXEC));
  if (fd.get() == -1) {
    return nullptr;
  }
  backtrace_symbols_fd(buffer, size, fd.get());

  // Get the size of the file.
  off_t file_size = lseek(fd.get(), 0, SEEK_END);
  if (file_size <= 0) {
    return nullptr;
  }

  // The interface for backtrace_symbols indicates that only the single
  // returned pointer must be freed by the caller. Therefore, allocate a
  // buffer that includes the memory for the strings and all of the pointers.
  // Add one byte at the end just in case the file didn't end with a '\n'.
  size_t symbol_data_size;
  if (__builtin_add_overflow(ptr_size, file_size, &symbol_data_size) ||
      __builtin_add_overflow(symbol_data_size, 1, &symbol_data_size)) {
    return nullptr;
  }

  uint8_t* symbol_data = reinterpret_cast<uint8_t*>(malloc(symbol_data_size));
  if (symbol_data == nullptr) {
    return nullptr;
  }

  // Copy the string data into the buffer.
  char* cur_string = reinterpret_cast<char*>(&symbol_data[ptr_size]);
  // If this fails, the read won't read back the correct number of bytes.
  lseek(fd.get(), 0, SEEK_SET);
  ssize_t num_read = read(fd.get(), cur_string, file_size);
  fd.reset(-1);
  if (num_read != file_size) {
    free(symbol_data);
    return nullptr;
  }

  // Make sure the last character in the file is '\n'.
  if (cur_string[file_size] != '\n') {
    cur_string[file_size++] = '\n';
  }

  for (int i = 0; i < size; i++) {
    (reinterpret_cast<char**>(symbol_data))[i] = cur_string;
    cur_string = strchr(cur_string, '\n');
    if (cur_string == nullptr) {
      free(symbol_data);
      return nullptr;
    }
    cur_string[0] = '\0';
    cur_string++;
  }
  return reinterpret_cast<char**>(symbol_data);
}

// This function should do no allocations if possible.
void backtrace_symbols_fd(void* const* buffer, int size, int fd) {
  if (size <= 0 || fd < 0) {
    return;
  }

  for (int frame_num = 0; frame_num < size; frame_num++) {
    void* address = buffer[frame_num];
    Dl_info info;
    if (dladdr(address, &info) != 0) {
      if (info.dli_fname != nullptr) {
        write(fd, info.dli_fname, strlen(info.dli_fname));
      }
      if (info.dli_sname != nullptr) {
        dprintf(fd, "(%s+0x%" PRIxPTR ") ", info.dli_sname,
                reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(info.dli_saddr));
      } else {
        dprintf(fd, "(+%p) ", info.dli_saddr);
      }
    }

    dprintf(fd, "[%p]\n", address);
  }
}
```