Response:
Let's break down the thought process for answering the request about `PointerData.handroid`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided C++ header file. The key elements to address are:

* **Functionality:** What does this code do? What are its main purposes and features?
* **Android Relevance:** How does this code relate to the broader Android system? Provide concrete examples.
* **Detailed Explanation of libc Functions:**  Explain how the functions within the file are implemented (even though it's just a header). This requires *inferring* likely implementations based on the function signatures and context.
* **Dynamic Linker Interaction:**  If the code interacts with the dynamic linker, explain how. This likely involves analyzing memory layouts and linking processes. Provide a sample SO layout.
* **Logic and Assumptions:** If any reasoning or inference is made, state the assumptions and potential inputs/outputs.
* **Common User/Programming Errors:** Identify typical mistakes developers might make when dealing with the functionalities exposed (or implied) by this code.
* **Android Framework/NDK Path:**  Trace how Android components might eventually interact with this code.
* **Frida Hook Examples:**  Provide practical debugging examples using Frida.

**2. Initial Analysis of the Header File:**

* **Name and Location:** `bionic/libc/malloc_debug/PointerData.handroid` suggests this is part of the memory management debugging infrastructure within Android's libc. The `.handroid` suffix might indicate an Android-specific aspect.
* **Includes:**  The included headers (`stdint.h`, `stdio.h`, `<atomic>`, etc.) give clues about the functionality. We see standard library components, atomic operations, mutexes, data structures (`deque`, `unordered_map`, `vector`), and Android-specific includes like `platform/bionic/macros.h` and `unwindstack/Unwinder.h`. This strongly suggests memory tracking, backtracing, and thread safety.
* **Key Data Structures:** The structs (`FrameKeyType`, `FrameInfoType`, `PointerInfoType`, `FreePointerInfoType`, `ListInfoType`) are central. Understanding their members is crucial to understanding the code's purpose. Notice the focus on frames (likely for stack traces), sizes, and zygote child allocation.
* **`PointerData` Class:** This is the main class. Its public methods suggest actions like initializing, enabling/disabling backtraces, adding/removing pointers, handling freed pointers, logging leaks, and dumping information.
* **Static Members:**  The presence of many static members (`pointer_mutex_`, `pointers_`, `frame_mutex_`, etc.) implies a shared, global state managed by this class. This further reinforces the idea of a central memory management debugging component.
* **Mangling/Demangling:** The `ManglePointer` and `DemanglePointer` functions suggest an attempt to obfuscate or protect pointer values, likely to prevent unintended access or manipulation.

**3. Detailed Function Breakdown (Mental Simulation):**

Even though the header doesn't contain implementations, we can reason about what each function *likely* does:

* **`Initialize(const Config& config)`:**  Reads configuration settings, possibly to enable/disable features or set thresholds for leak detection.
* **Backtrace Functions (`ShouldBacktrace`, `ToggleBacktraceEnabled`, `EnableDumping`, `ShouldDumpAndReset`):**  Control the capturing and dumping of stack traces for memory allocations.
* **Fork Handling (`PrepareFork`, `PostForkParent`, `PostForkChild`):**  Necessary to correctly manage memory tracking across `fork()` calls, especially considering the zygote.
* **Pointer Management (`Add`, `Remove`, `Exists`):**  Tracks allocated memory blocks and their sizes. Likely uses the `pointers_` map.
* **Freed Pointer Management (`AddFreed`, `LogFreeError`, `LogFreeBacktrace`, `VerifyFreedPointer`, `VerifyAllFreed`):**  Detects double frees and use-after-frees. The `free_pointers_` deque probably holds recently freed pointers for a short period.
* **Leak Detection (`GetAllocList`, `LogLeaks`, `DumpLiveToFile`):**  Identifies memory blocks that haven't been freed when the application exits.
* **Information Retrieval (`GetInfo`, `GetFrames`):** Provides debugging information about allocated memory.

**4. Connecting to Android Functionality:**

* **Zygote:** The `g_zygote_child` and the handling of zygote child allocations are clear indicators of interaction with the Android application startup process.
* **Memory Debugging Tools:** This code likely forms the backend for tools like `memtrack`, `dmalloc`, and ASan (AddressSanitizer), providing the core mechanisms for tracking memory allocations and detecting errors.
* **NDK Development:** NDK developers using `malloc` and `free` will indirectly interact with this code. Memory errors in their native code will be detected and reported through this infrastructure.

**5. Dynamic Linker Interaction (Hypothetical):**

While the provided code doesn't directly *call* dynamic linker functions, its presence within `libc` means it's *part* of the address space managed by the dynamic linker. The linker sets up the initial memory layout, including where `libc.so` is loaded. The `PointerData` class relies on this established layout.

**6. User/Programming Errors:**

Focus on common memory management mistakes:

* **Memory Leaks:** Forgetting to `free` allocated memory.
* **Double Free:** Calling `free` on the same memory block twice.
* **Use-After-Free:** Accessing memory after it has been freed.
* **Heap Corruption:** Writing beyond the bounds of an allocated memory block.

**7. Android Framework/NDK Path:**

Trace a typical allocation scenario:

1. **Java Code:** `new SomeObject()`
2. **Dalvik/ART:**  Manages object allocation in the managed heap.
3. **Native Allocation (via JNI):**  `malloc()` called from native code.
4. **`libc.so`:**  The `malloc()` implementation in `libc` (which might have hooks or instrumentation provided by `malloc_debug`).
5. **`PointerData`:**  If enabled, `PointerData` records the allocation.

**8. Frida Hooks:**

Think about what aspects of the memory allocation process would be useful to monitor or modify during debugging. Hooking `malloc`, `free`, and potentially functions within `PointerData` itself are good starting points.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus too much on the exact code implementation.
* **Correction:** Realize that with just the header, the focus needs to be on the *purpose* and *functionality* implied by the declarations, and to make reasonable inferences about the underlying implementation.
* **Initial thought:**  Overlook the importance of the `unwindstack` library.
* **Correction:** Recognize that backtracing is a core feature and that `unwindstack` is responsible for generating the stack traces.
* **Initial thought:**  Not clearly distinguish between direct and indirect interaction with the dynamic linker.
* **Correction:**  Explain that while `PointerData` doesn't directly call `dlopen` or similar functions, it exists within the memory space managed by the linker and relies on the linker's setup.

By following this kind of structured analysis, combining code-level understanding with knowledge of the Android platform, it's possible to generate a comprehensive and informative answer to the request.
好的，让我们来详细分析一下 `bionic/libc/malloc_debug/PointerData.handroid` 这个文件。

**功能概述**

`PointerData.handroid` 是 Android Bionic C 库中 `malloc_debug` 组件的一个头文件。它的主要功能是**跟踪和管理应用程序分配和释放的内存指针信息**，用于内存调试和分析。具体来说，它负责：

1. **记录内存分配信息:**  当程序调用 `malloc` 等函数分配内存时，`PointerData` 会记录分配的指针地址、分配的大小以及分配时的调用堆栈信息（backtrace）。
2. **记录内存释放信息:** 当程序调用 `free` 等函数释放内存时，`PointerData` 会记录被释放的指针地址。
3. **检测内存错误:** 基于记录的信息，`PointerData` 可以检测各种内存错误，例如：
    * **内存泄漏 (Memory Leaks):**  程序退出时，仍然有已分配但未释放的内存。
    * **重复释放 (Double Free):**  对同一个内存块多次调用 `free`。
    * **释放非法指针 (Invalid Free):**  尝试释放一个未被 `malloc` 分配的指针。
    * **使用已释放内存 (Use-After-Free):**  访问已经通过 `free` 释放的内存。
4. **提供内存使用统计:** 可以提供当前已分配内存的总量、不同调用堆栈的内存分配情况等统计信息。
5. **支持 zygote 进程的特殊处理:**  Android 的 zygote 进程是应用进程的孵化器，其内存管理有一些特殊性，`PointerData` 能够处理这些情况。

**与 Android 功能的关系及举例**

`PointerData` 是 Android 系统内存调试机制的核心组成部分，与以下 Android 功能紧密相关：

* **`malloc_debug` 组件:**  `PointerData` 是 `malloc_debug` 的一部分，`malloc_debug` 是一组用于在开发和测试阶段帮助开发者发现内存问题的工具。可以通过设置环境变量或系统属性来启用。
* **`dmalloc` (Debug Malloc):**  `dmalloc` 是 Android 提供的另一种内存调试工具，它在内部就使用了 `malloc_debug` 的功能，包括 `PointerData` 中定义的数据结构和逻辑。
* **`memtrack` 服务:**  Android 的 `memtrack` 服务用于跟踪各个进程的内存使用情况。`malloc_debug` 可以为 `memtrack` 提供更详细的 native 内存分配信息。
* **AddressSanitizer (ASan):**  ASan 是一种更强大的内存错误检测工具，它在底层也可能依赖于或与 `malloc_debug` 协作来完成内存错误的检测。
* **LeakCanary:**  这是一个流行的 Android 第三方内存泄漏检测库，其原理与 `malloc_debug` 类似，但它在应用层实现，而 `malloc_debug` 在 C 库层实现。

**举例说明：**

假设一个 Android 应用的 native 代码中存在内存泄漏。在开发者启用 `malloc_debug` 后，当应用退出时，`PointerData` 会检测到有未释放的内存，并可以将这些泄漏的内存块的分配地址和分配时的调用堆栈信息记录到 logcat 中，帮助开发者定位泄漏发生的位置。

**libc 函数的实现解释**

虽然 `PointerData.handroid` 只是一个头文件，声明了类和结构体，但它所关联的 libc 函数（例如 `malloc` 和 `free` 的 debug 版本）的功能实现会用到这里定义的数据结构。

* **`malloc(size_t size)` 的 debug 版本:**
    1. 调用原始的 `malloc` 获取内存块。
    2. 如果启用了 backtrace，则调用 `unwindstack` 库获取当前的调用堆栈信息。
    3. 创建一个 `PointerInfoType` 结构体，存储分配的大小 `size`，以及可能的 zygote 子进程标记。
    4. 创建一个 `FrameKeyType` 结构体，包含 backtrace 的帧数和帧地址。
    5. 在 `frame_mutex_` 锁的保护下，检查 `key_to_index_` 中是否已经存在相同的调用堆栈。
        * 如果存在，则增加对应 `FrameInfoType` 的引用计数 `references`。
        * 如果不存在，则将当前的调用堆栈信息添加到 `frames_` 和 `backtraces_info_`，并在 `key_to_index_` 中建立映射。
    6. 在 `pointer_mutex_` 锁的保护下，将分配的指针地址（经过 `ManglePointer` 处理）和对应的 `PointerInfoType` 结构体添加到 `pointers_` 哈希表中。
* **`free(void* ptr)` 的 debug 版本:**
    1. 如果 `ptr` 为空，则直接返回。
    2. 对 `ptr` 进行 `ManglePointer` 的逆操作得到原始指针。
    3. 在 `pointer_mutex_` 锁的保护下，查找 `pointers_` 哈希表，检查 `ptr` 是否是一个有效的已分配指针。
        * 如果找不到，则可能是一个重复释放或释放了非法指针，会记录错误信息。
        * 如果找到，则获取对应的 `PointerInfoType` 和 `hash_index`。
    4. 在 `frame_mutex_` 锁的保护下，通过 `hash_index` 找到对应的 `FrameInfoType` 并减少其引用计数。如果引用计数变为 0，则可以考虑从 `frames_` 和 `backtraces_info_` 中移除该 backtrace 信息。
    5. 在 `pointer_mutex_` 锁的保护下，将 `ptr` 从 `pointers_` 哈希表中移除。
    6. 调用原始的 `free` 释放内存块。
    7. 如果启用了 freed pointer 的跟踪，则将释放的指针信息添加到 `free_pointers_` 队列中，用于检测 use-after-free 等错误。

**涉及 dynamic linker 的功能及处理过程**

`PointerData` 本身并不直接与 dynamic linker 交互，但它所处的 `libc.so` 是由 dynamic linker 加载的，并且它的功能会受到 dynamic linker 的影响。

**so 布局样本：**

```
Load map:
0000007b7000-0000007b7fff r--p 00000000 b3:0f 1000000000 /system/lib64/ld-android.so
0000007b8000-0000007b8fff r-xp 00001000 b3:0f 1000000000 /system/lib64/ld-android.so
0000007b9000-0000007b9fff r--p 00002000 b3:0f 1000000000 /system/lib64/ld-android.so
0000007ba000-0000007bafff r--p 00003000 b3:0f 1000000000 /system/lib64/ld-android.so
0000007bb000-0000007bbfff rw-p 00004000 b3:0f 1000000000 /system/lib64/ld-android.so
0000007bc000-0000007bdfff rw-p 00000000 00:00 0
0000007bd000-0000007bdfff r--p 00000000 b3:0f 2000000000 /system/lib64/libc.so
0000007be000-0000007cafff r-xp 00001000 b3:0f 2000000000 /system/lib64/libc.so
0000007cb000-0000007cdfff r--p 001cb000 b3:0f 2000000000 /system/lib64/libc.so
0000007ce000-0000007cefff r--p 001cd000 b3:0f 2000000000 /system/lib64/libc.so
0000007cf000-0000007d0fff rw-p 001cf000 b3:0f 2000000000 /system/lib64/libc.so
0000007d1000-0000007d2fff rw-p 00000000 00:00 0
...
```

在这个布局中，`libc.so` 被加载到某个地址范围。`PointerData` 中定义的静态变量（例如 `pointers_`, `frames_`）会分配在这个 `libc.so` 的数据段中。

**链接的处理过程：**

1. 当应用程序启动时，dynamic linker (`ld-android.so`) 会负责加载应用程序依赖的共享库，包括 `libc.so`。
2. 在加载 `libc.so` 的过程中，dynamic linker 会解析 `libc.so` 的符号表，找到 `malloc`、`free` 等函数的地址。
3. 如果启用了 `malloc_debug`，则会使用 `malloc_debug` 提供的 debug 版本的 `malloc` 和 `free` 函数，这些 debug 版本会调用 `PointerData` 中定义的功能来记录内存信息。
4. 应用程序调用 `malloc` 或 `free` 时，实际上会调用 dynamic linker 解析出的 debug 版本函数的地址。

**逻辑推理、假设输入与输出**

假设输入：

```c++
#include <stdlib.h>
#include <stdio.h>

int main() {
  void *ptr1 = malloc(10);
  void *ptr2 = malloc(20);
  free(ptr1);
  // 忘记 free ptr2，导致内存泄漏
  return 0;
}
```

在启用了 `malloc_debug` 的情况下运行此程序：

输出（logcat 中可能包含）：

```
D MallocDebug: ### Leak Report ###
D MallocDebug: 0x...: allocated 20 bytes with backtrace:
D MallocDebug:     #00 pc 0x... /path/to/your/program
D MallocDebug:     #01 pc 0x... /path/to/your/program
... (backtrace信息)
```

**解释：**

* `malloc(10)` 和 `malloc(20)` 会被 `PointerData` 记录，分别对应不同的分配大小和可能的调用堆栈。
* `free(ptr1)` 会将 `ptr1` 从 `PointerData` 的记录中移除。
* 由于程序结束时 `ptr2` 仍然存在于 `PointerData` 的记录中，因此 `malloc_debug` 会将其识别为内存泄漏，并在 logcat 中输出相关信息，包括泄漏的地址、大小以及分配时的 backtrace。

**用户或编程常见的使用错误**

1. **忘记释放内存 (Memory Leaks):**  这是最常见的错误，分配了内存但没有调用 `free` 释放。
2. **重复释放 (Double Free):**  对同一个指针调用 `free` 多次，会导致堆损坏。
3. **释放未分配的内存 (Invalid Free):**  尝试释放一个不是由 `malloc` (或相关函数) 分配的指针，或者释放栈上的地址。
4. **使用已释放的内存 (Use-After-Free):**  在 `free` 之后继续访问已经释放的内存，会导致未定义的行为，可能崩溃或数据损坏。
5. **缓冲区溢出 (Buffer Overflow):**  写入超过分配的内存大小，可能覆盖到其他内存块的元数据，导致 `free` 时出现问题。

**Android framework or ndk 如何一步步的到达这里**

1. **Android Framework (Java 层):**  当 Java 代码需要分配 native 内存时，通常会通过 JNI (Java Native Interface) 调用 NDK 中的 C/C++ 代码。
2. **NDK 代码 (C/C++ 层):**  NDK 代码中，开发者会使用 `malloc`、`calloc`、`realloc` 和 `free` 等标准 C 库函数来管理内存。
3. **Bionic libc:** 这些标准 C 库函数的实现位于 Android 的 Bionic C 库 (`libc.so`) 中。
4. **`malloc` 实现 (debug 版本):** 如果启用了 `malloc_debug`，那么 `libc.so` 中 `malloc` 和 `free` 等函数的实现会被替换成包含调试功能的版本。
5. **`PointerData` 的调用:**  这些 debug 版本的 `malloc` 和 `free` 函数会调用 `PointerData` 类中的静态方法（例如 `Add`、`Remove`、`AddFreed`）来记录和管理内存信息。

**Frida hook 示例调试步骤**

以下是一些使用 Frida hook `PointerData` 相关功能的示例：

**1. Hook `PointerData::Add` 来查看内存分配信息：**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const pointerDataAdd = Module.findExportByName("libc.so", "_ZN9PointerData3AddEPKvj"); // ARM64 & ARM
  if (pointerDataAdd) {
    Interceptor.attach(pointerDataAdd, {
      onEnter: function (args) {
        const pointer = args[0];
        const size = args[1].toInt();
        console.log(`[PointerData::Add] Pointer: ${pointer}, Size: ${size}`);
        // 可以进一步读取 backtrace 信息（如果已启用）
      }
    });
  } else {
    console.log("PointerData::Add not found.");
  }
}
```

**2. Hook `PointerData::Remove` 来查看内存释放信息：**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const pointerDataRemove = Module.findExportByName("libc.so", "_ZN9PointerData6RemoveEPKv"); // ARM64 & ARM
  if (pointerDataRemove) {
    Interceptor.attach(pointerDataRemove, {
      onEnter: function (args) {
        const pointer = args[0];
        console.log(`[PointerData::Remove] Pointer: ${pointer}`);
        // 可以尝试读取被释放内存的内容（谨慎操作）
      }
    });
  } else {
    console.log("PointerData::Remove not found.");
  }
}
```

**3. Hook `malloc` 和 `free` (debug 版本，如果启用)：**

```javascript
const mallocPtr = Module.findExportByName("libc.so", "malloc");
const freePtr = Module.findExportByName("libc.so", "free");

if (mallocPtr) {
  Interceptor.attach(mallocPtr, {
    onEnter: function (args) {
      const size = args[0].toInt();
      console.log(`[malloc] Size: ${size}`);
    },
    onLeave: function (retval) {
      console.log(`[malloc] Returned: ${retval}`);
    }
  });
}

if (freePtr) {
  Interceptor.attach(freePtr, {
    onEnter: function (args) {
      const ptr = args[0];
      console.log(`[free] Pointer: ${ptr}`);
    }
  });
}
```

**调试步骤：**

1. **确定目标进程:**  使用 Frida 连接到要调试的 Android 进程。
2. **编写 Frida 脚本:**  编写 JavaScript 代码，使用 `Module.findExportByName` 找到 `PointerData` 或 `malloc`/`free` 的符号地址。注意需要考虑不同的 CPU 架构（ARM、ARM64）。
3. **附加 Interceptor:** 使用 `Interceptor.attach` 在目标函数入口或出口设置 hook，并在回调函数中打印参数、返回值或其他感兴趣的信息。
4. **运行程序并观察输出:**  运行目标 Android 应用，并观察 Frida 输出的日志信息，分析内存分配和释放的行为。

**注意:**

* 上述 Frida hook 示例中的符号名称是基于常见的命名规则，可能因 Android 版本和编译选项而有所不同。可以使用 `frida-ps -U` 找到目标进程，然后使用 `frida -U -n <process_name> --explore` 来探索进程的模块和导出符号。
* Hook libc 的 `malloc` 和 `free` 会影响所有使用这些函数的代码，包括 Android Framework 本身。
* 在生产环境或对性能敏感的应用中，不应长时间启用 `malloc_debug` 或使用过于频繁的 Frida hook，因为它们会带来性能开销。

希望这个详细的分析能够帮助你理解 `bionic/libc/malloc_debug/PointerData.handroid` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/malloc_debug/PointerData.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

#include <stdint.h>
#include <stdio.h>

#include <atomic>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <platform/bionic/macros.h>
#include <unwindstack/Unwinder.h>

#include "OptionData.h"
#include "UnwindBacktrace.h"

extern bool* g_zygote_child;

// Forward declarations.
class Config;

struct FrameKeyType {
  size_t num_frames;
  uintptr_t* frames;

  bool operator==(const FrameKeyType& comp) const {
    if (num_frames != comp.num_frames) return false;
    for (size_t i = 0; i < num_frames; i++) {
      if (frames[i] != comp.frames[i]) {
        return false;
      }
    }
    return true;
  }
};

namespace std {
template <>
struct hash<FrameKeyType> {
  std::size_t operator()(const FrameKeyType& key) const {
    std::size_t cur_hash = key.frames[0];
    // Limit the number of frames to speed up hashing.
    size_t max_frames = (key.num_frames > 5) ? 5 : key.num_frames;
    for (size_t i = 1; i < max_frames; i++) {
      cur_hash ^= key.frames[i];
    }
    return cur_hash;
  }
};
};  // namespace std

struct FrameInfoType {
  size_t references = 0;
  std::vector<uintptr_t> frames;
};

struct PointerInfoType {
  size_t size;
  size_t hash_index;
  size_t RealSize() const { return size & ~(1U << 31); }
  bool ZygoteChildAlloc() const { return size & (1U << 31); }
  static size_t GetEncodedSize(size_t size) {
    return GetEncodedSize(*g_zygote_child, size);
  }
  static size_t GetEncodedSize(bool child_alloc, size_t size) {
    return size | ((child_alloc) ? (1U << 31) : 0);
  }
  static size_t MaxSize() { return (1U << 31) - 1; }
};

struct FreePointerInfoType {
  uintptr_t mangled_ptr;
  size_t hash_index;
};

struct ListInfoType {
  uintptr_t pointer;
  size_t num_allocations;
  size_t size;
  bool zygote_child_alloc;
  FrameInfoType* frame_info;
  std::vector<unwindstack::FrameData>* backtrace_info;
};

class PointerData : public OptionData {
 public:
  explicit PointerData(DebugData* debug_data);
  virtual ~PointerData() = default;

  bool Initialize(const Config& config);

  inline size_t alloc_offset() { return alloc_offset_; }

  bool ShouldBacktrace() { return backtrace_enabled_ == 1; }
  void ToggleBacktraceEnabled() { backtrace_enabled_.fetch_xor(1); }

  void EnableDumping() { backtrace_dump_ = true; }
  bool ShouldDumpAndReset() {
    bool expected = true;
    return backtrace_dump_.compare_exchange_strong(expected, false);
  }

  void PrepareFork();
  void PostForkParent();
  void PostForkChild();

  static void IteratePointers(std::function<void(uintptr_t pointer)> fn);

  static size_t AddBacktrace(size_t num_frames, size_t size_bytes);
  static void RemoveBacktrace(size_t hash_index);

  static void Add(const void* pointer, size_t size);
  static void Remove(const void* pointer);

  static void* AddFreed(const void* pointer, size_t size_bytes);
  static void LogFreeError(const FreePointerInfoType& info, size_t usable_size);
  static void LogFreeBacktrace(const void* ptr);
  static void VerifyFreedPointer(const FreePointerInfoType& info);
  static void VerifyAllFreed();

  static void GetAllocList(std::vector<ListInfoType>* list);
  static void LogLeaks();
  static void DumpLiveToFile(int fd);

  static void GetInfo(uint8_t** info, size_t* overall_size, size_t* info_size, size_t* total_memory,
                      size_t* backtrace_size);

  static size_t GetFrames(const void* pointer, uintptr_t* frames, size_t max_frames);

  static bool Exists(const void* pointer);

 private:
  // Only keep mangled pointers in internal data structures. This avoids
  // problems where libmemunreachable finds these pointers and thinks they
  // are not unreachable.
  static inline uintptr_t ManglePointer(uintptr_t pointer) { return pointer ^ UINTPTR_MAX; }
  static inline uintptr_t DemanglePointer(uintptr_t pointer) { return pointer ^ UINTPTR_MAX; }

  static std::string GetHashString(uintptr_t* frames, size_t num_frames);
  static void LogBacktrace(size_t hash_index);

  static void GetList(std::vector<ListInfoType>* list, bool only_with_backtrace);
  static void GetUniqueList(std::vector<ListInfoType>* list, bool only_with_backtrace);

  size_t alloc_offset_ = 0;
  std::vector<uint8_t> cmp_mem_;

  static std::atomic_uint8_t backtrace_enabled_;

  static std::atomic_bool backtrace_dump_;

  static std::mutex pointer_mutex_;
  static std::unordered_map<uintptr_t, PointerInfoType> pointers_;

  static std::mutex frame_mutex_;
  static std::unordered_map<FrameKeyType, size_t> key_to_index_;
  static std::unordered_map<size_t, FrameInfoType> frames_;
  static std::unordered_map<size_t, std::vector<unwindstack::FrameData>> backtraces_info_;
  static size_t cur_hash_index_;

  static std::mutex free_pointer_mutex_;
  static std::deque<FreePointerInfoType> free_pointers_;

  BIONIC_DISALLOW_COPY_AND_ASSIGN(PointerData);
};

"""

```