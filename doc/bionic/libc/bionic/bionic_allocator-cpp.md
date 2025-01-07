Response:
Let's break down the thought process for answering the prompt about `bionic_allocator.cpp`.

**1. Understanding the Core Request:**

The fundamental request is to analyze the provided C++ source code of `bionic_allocator.cpp` and explain its functionality within the context of Android's Bionic libc. This involves dissecting the code, understanding its data structures, algorithms, and interactions with the operating system. The prompt also asks for specific examples and explanations related to Android, dynamic linking, common errors, and how Android frameworks interact with this code.

**2. Initial Code Scan and High-Level Understanding:**

The first step is a quick scan of the code to grasp its overall structure and identify key components. Keywords like `alloc`, `free`, `realloc`, `mmap`, `munmap`, and class names like `BionicSmallObjectAllocator` and `BionicAllocator` stand out. The comments at the beginning provide a high-level overview of the allocator's strategy: small objects use a dedicated allocator, and larger objects are handled with `mmap`.

**3. Deconstructing Functionality (The "What"):**

Next, systematically go through the code, function by function, and class by class. For each significant element, ask: "What does this do?"

* **`BionicSmallObjectAllocator`:** Focus on its constructor, `alloc`, `free`, `alloc_page`, `add_to_page_list`, and `remove_from_page_list`. Notice the use of linked lists for managing free blocks and pages. The logic for recycling pages (keeping one in reserve) is important.
* **`BionicAllocator`:** Analyze `initialize_allocators`, `alloc_mmap`, `alloc_impl`, `alloc`, `memalign`, `realloc`, `free`, and `get_chunk_size`. Understand how it dispatches allocation requests based on size, using either `BionicSmallObjectAllocator` or `mmap`. The `get_page_info` functions and the `kSignature` are crucial for validating pointers.
* **Helper Functions:**  Note `log2`, the use of `CHECK` and `async_safe_fatal`, and the constants like `kSmallObjectMaxSize`.

**4. Connecting to Android (The "Why" and "Where"):**

The prompt emphasizes the Android context. Consider how this allocator fits into the broader Android system:

* **`libc`:**  Recognize that this is part of Android's standard C library. This immediately implies its use by almost *all* native code on Android.
* **Memory Management:** Understand its role in providing the fundamental memory allocation functions (`malloc`, `free`, etc.) that are essential for any program.
* **Performance:**  The small object allocator is a clear optimization for common, smaller allocations, which can improve performance compared to always using `mmap`.
* **Security:** The signature check in `get_page_info` hints at security measures to detect invalid pointers.

**5. Explaining Implementation Details (The "How"):**

This is where the detailed analysis of each function comes in. For example, for `BionicSmallObjectAllocator::alloc()`:

* **Find a free block:**  Explain how it iterates through the `page_list_` and `free_block_list`.
* **Split blocks:** Describe the logic for splitting a larger free block into smaller ones if necessary.
* **Page management:**  Explain how pages are allocated (`alloc_page`) and potentially freed (`free_page`) to manage memory efficiently.

For `BionicAllocator::alloc()`:

* **Size threshold:** Explain the distinction between small and large allocations.
* **`mmap` for large objects:**  Describe the direct use of `mmap`.
* **`BionicSmallObjectAllocator` for small objects:** Explain the lookup based on size.

**6. Dynamic Linking Aspects:**

The prompt specifically asks about the dynamic linker. Consider:

* **`so` layout:** How are shared libraries loaded into memory?  What are the different segments (.text, .data, .bss)?
* **Linking process:**  How does the dynamic linker resolve symbols (like `malloc`) to their actual implementations in `libc.so`?  Mention relocation.
* **Example:** Provide a concrete example of how a program links against `libc.so` and uses `malloc`.

**7. Common Errors and Debugging:**

Think about typical mistakes developers make with memory management:

* **Memory leaks:** Forgetting to `free` allocated memory.
* **Double frees:**  Freeing the same memory twice.
* **Use-after-free:** Accessing memory after it has been freed.
* **Heap corruption:** Writing beyond the bounds of allocated memory.

For debugging, `frida` is mentioned. Show how to hook `malloc` and `free` to trace allocations and detect issues.

**8. Android Framework and NDK Interaction:**

Connect the allocator to higher-level Android components:

* **NDK:**  Explain that native code developed with the NDK directly uses these allocation functions.
* **Android Framework:**  While the framework is largely Java-based, system services and some lower-level components might use native code and thus rely on this allocator. Give a plausible scenario (e.g., a native library used by a framework service).

**9. Structuring the Answer:**

Organize the information logically. Use headings and bullet points for clarity. Address each part of the prompt systematically. Start with a general overview and then delve into specifics.

**10. Review and Refine:**

After drafting the answer, review it for accuracy, completeness, and clarity. Ensure that the explanations are easy to understand and that the examples are helpful. Check for any technical inaccuracies or omissions. For example, initially, I might forget to explicitly mention the role of `page_info` in tracking metadata about allocations, so I'd add that during the review. Also, ensuring the Frida example is clear and runnable is crucial.

By following these steps, you can systematically analyze the code and construct a comprehensive and accurate answer to the prompt. The key is to break down the problem into smaller, manageable parts and then synthesize the information into a coherent explanation.
好的，我们来详细分析一下 `bionic/libc/bionic/bionic_allocator.cpp` 这个文件。

**文件功能概述**

`bionic_allocator.cpp` 文件实现了 Android Bionic libc 库中的核心内存分配器。它的主要功能是提供与标准 C 库中的 `malloc`、`free`、`realloc` 和 `memalign` 函数相同的功能。  简单来说，它负责在 Android 系统中为应用程序分配和释放内存。

**核心功能及与 Android 的关系**

1. **内存分配 (`malloc`)**:
   - **功能实现:**
     - 对于小于等于 1KB 的内存请求，`BionicAllocator` 使用 `BionicSmallObjectAllocator`。`BionicSmallObjectAllocator` 维护着一系列固定大小的内存块（大小为 2 的幂）。它会将请求的大小向上取整到最近的 2 的幂，并从相应的内存池中分配一个块。
     - 对于大于 1KB 的内存请求，`BionicAllocator` 直接调用 `mmap` 系统调用来分配一块匿名内存区域。
   - **Android 关系举例:** 当一个 Android 应用（无论是 Java 还是 Native 代码）调用 `malloc` 来分配一块小内存，例如创建一个小的对象或者分配一个短字符串时，`BionicAllocator` 的小对象分配器就会被调用。

2. **内存释放 (`free`)**:
   - **功能实现:**
     - 如果释放的内存是通过 `mmap` 分配的（大对象），`BionicAllocator` 调用 `munmap` 系统调用来释放该内存区域。
     - 如果释放的内存是通过 `BionicSmallObjectAllocator` 分配的（小对象），`BionicAllocator` 会将该内存块添加回对应大小内存池的空闲列表。为了优化，如果某个内存页上的空闲块数量达到一定程度（默认是 2 个完整的页），`BionicSmallObjectAllocator` 会释放其中的一个页，保留一个备用。
   - **Android 关系举例:** 当 Android 应用不再需要之前 `malloc` 分配的内存时，调用 `free` 函数会将内存归还给系统，这个过程由 `BionicAllocator` 处理。

3. **内存重新分配 (`realloc`)**:
   - **功能实现:**
     - 如果传入的指针 `ptr` 为 `nullptr`，则等同于调用 `malloc(size)`。
     - 如果请求的大小 `size` 为 0，则等同于调用 `free(ptr)`。
     - 如果请求的新大小 `size` 小于或等于原有内存块的大小，则直接返回原指针 `ptr`。
     - 如果请求的新大小 `size` 大于原有内存块的大小：
       - 分配一块新的内存块（大小为 `size`）。
       - 将原内存块的内容拷贝到新的内存块中。
       - 释放原有的内存块。
       - 返回指向新内存块的指针。
   - **Android 关系举例:** 当 Android 应用需要调整已分配内存块的大小时，例如需要存储更长的字符串，就会调用 `realloc`。

4. **内存对齐分配 (`memalign`)**:
   - **功能实现:**
     - `BionicAllocator` 通过 `alloc_impl` 函数来处理内存分配，`alloc_impl` 内部会区分大对象和小对象。
     - 对于大对象，`alloc_mmap` 会分配足够大的内存，并在分配的内存区域内找到满足对齐要求的地址返回。`kPageInfoSize` 用于存储分配信息的头部，需要考虑对齐。
     - 对于小对象，由于 `BionicSmallObjectAllocator` 分配的块大小是 2 的幂，天然满足 16 字节对齐。对于更大的对齐需求，会回退到 `alloc_mmap`。
     - 支持的最大对齐值为页大小。
   - **Android 关系举例:** 在某些需要特定内存对齐的场景，例如处理多媒体数据或者使用 SIMD 指令时，Android 应用可能会调用 `memalign` 来确保分配的内存地址满足要求。

**libc 函数的实现细节**

我们来详细解释一下 `BionicAllocator` 中关键 libc 函数的实现方式：

* **`malloc(size_t size)`:**
    - 如果 `size` 为 0，则将其视为分配大小为 1。
    - 调用 `alloc_impl(16, size)`，默认按照 16 字节对齐。
    - `alloc_impl` 函数会根据 `size` 的大小选择不同的分配策略：
        - 如果 `size > kSmallObjectMaxSize` (默认为 1KB)，则调用 `alloc_mmap`。
        - 否则，计算出最接近且不小于 `size` 的 2 的幂作为 `log2_size`，并调用对应的 `BionicSmallObjectAllocator` 的 `alloc()` 方法。

* **`free(void* ptr)`:**
    - 如果 `ptr` 为 `nullptr`，则直接返回。
    - 调用 `get_page_info(ptr)` 获取指向该内存块所属页的 `page_info` 结构体，其中包含分配该内存块的元数据。
    - 根据 `page_info->type` 判断是小对象还是大对象：
        - 如果是 `kLargeObject`，则调用 `munmap(info, info->allocated_size)` 释放整个 `mmap` 区域。
        - 如果是小对象，则调用对应的 `BionicSmallObjectAllocator` 的 `free(ptr)` 方法。

* **`realloc(void* ptr, size_t size)`:**
    - 处理 `ptr` 为 `nullptr` 和 `size` 为 0 的特殊情况。
    - 调用 `get_page_info(ptr)` 获取内存块的信息。
    - 获取原有内存块的大小 `old_size`，根据是大对象还是小对象采取不同的计算方式。
    - 如果 `old_size < size`，则分配一块新的内存 `result = alloc(size)`，将原有数据拷贝到新内存，释放旧内存，并返回新内存地址。
    - 否则，直接返回原指针 `ptr`。

* **`memalign(size_t align, size_t size)`:**
    - 限制最大对齐值为页大小，最小对齐值为 16 字节。
    - 如果 `align` 不是 2 的幂，则向上取整到最近的 2 的幂。
    - 确保 `size` 不小于 `align`。
    - 调用 `alloc_impl(align, size)`。

**涉及 Dynamic Linker 的功能**

虽然 `bionic_allocator.cpp` 本身不直接参与动态链接的过程，但它是 `libc.so` 的一部分，而 `libc.so` 是动态链接器在链接和加载应用程序时需要处理的关键共享库。

**SO 布局样本 (libc.so):**

```
LOAD           00000000  00000000  [R E]    8f000  8f000
LOAD           00090000  00090000  [RW ]     a000    c000
```

这是一个简化的 `libc.so` 内存布局示例，其中：

- `LOAD 00000000`:  表示一个可加载段，起始地址为 `00000000` (这是一个相对地址，实际加载时会被调整)。
    - `[R E]`:  表示该段具有读 (R) 和执行 (E) 权限，通常包含代码段 (.text)。`malloc`, `free` 等函数的代码就位于这里。
    - `8f000`:  表示该段在文件中的大小。
    - `8f000`:  表示该段加载到内存后的大小。
- `LOAD 00090000`: 表示另一个可加载段。
    - `[RW ]`: 表示该段具有读 (R) 和写 (W) 权限，通常包含数据段 (.data) 和未初始化数据段 (.bss)。全局变量，例如 `BionicAllocator` 的内部状态，可能位于这里。
    - `a000`: 表示该段在文件中的大小。
    - `c000`: 表示该段加载到内存后的大小 (可能因为包含 .bss 段而大于文件中的大小)。

**链接的处理过程:**

1. **应用程序加载:** 当 Android 系统启动一个应用程序时，动态链接器 (e.g., `/system/bin/linker64`) 会首先被加载。
2. **依赖项解析:** 动态链接器会解析应用程序依赖的共享库，其中包括 `libc.so`。
3. **加载共享库:** 动态链接器将 `libc.so` 加载到内存中，根据其 ELF 文件头的指示，将其不同的段 (如代码段、数据段) 加载到合适的内存地址，并设置相应的内存保护属性。
4. **符号解析 (Relocation):** 应用程序的代码中可能会调用 `malloc` 等 `libc.so` 提供的函数。这些调用在编译时只是占位符。动态链接器会进行符号解析，找到 `malloc` 函数在 `libc.so` 中的实际地址，并更新应用程序代码中的调用地址，使其指向正确的实现。这个过程称为重定位 (Relocation)。

在链接过程中，`bionic_allocator.cpp` 编译生成的代码（例如 `BionicAllocator::alloc`）会被放入 `libc.so` 的代码段。当应用程序调用 `malloc` 时，最终会跳转到 `libc.so` 中 `BionicAllocator::alloc` 的代码执行。

**假设输入与输出 (逻辑推理)**

假设我们有以下代码片段：

```c++
#include <stdlib.h>
#include <stdio.h>

int main() {
  int *ptr = (int *)malloc(sizeof(int) * 10);
  if (ptr != nullptr) {
    for (int i = 0; i < 10; ++i) {
      ptr[i] = i;
    }
    for (int i = 0; i < 10; ++i) {
      printf("%d ", ptr[i]);
    }
    printf("\n");
    free(ptr);
  }
  return 0;
}
```

**假设输入:** 程序启动，操作系统分配进程空间。
**输出:**
- `malloc(sizeof(int) * 10)`:  `BionicAllocator` 会分配一块至少能容纳 40 字节的内存（假设 `sizeof(int)` 为 4）。由于小于 1KB，它会从 `BionicSmallObjectAllocator` 中分配，大小可能是 64 字节 (向上取整到 2 的幂)。返回一个指向该内存块起始地址的指针。
- 循环赋值后，内存块中的前 40 个字节会被填充为 `0, 1, 2, 3, 4, 5, 6, 7, 8, 9`。
- `printf` 输出：`0 1 2 3 4 5 6 7 8 9`
- `free(ptr)`: `BionicAllocator` 将分配的内存块添加回对应大小内存池的空闲列表。

**用户或编程常见的使用错误**

1. **内存泄漏:** 分配了内存但忘记释放。
   ```c++
   void foo() {
     int *ptr = (int *)malloc(100);
     // ... 没有调用 free(ptr)
   } // ptr 作用域结束，但分配的内存仍然占用
   ```
   如果 `foo` 函数被多次调用，会导致内存持续增长。

2. **重复释放 (Double Free):** 释放同一块内存两次。
   ```c++
   int *ptr = (int *)malloc(100);
   free(ptr);
   free(ptr); // 错误：重复释放
   ```
   这会导致堆损坏，可能导致程序崩溃或安全漏洞。`BionicAllocator` 的 `get_page_info` 中会检查签名，可能在第二次 `free` 时检测到错误。

3. **释放未分配的内存或栈内存:** 尝试释放不是通过 `malloc` (或其变体) 分配的内存。
   ```c++
   int a;
   free(&a); // 错误：尝试释放栈内存
   ```
   `BionicAllocator` 会根据 `page_info` 的签名检查来尝试捕获这类错误。

4. **使用已释放的内存 (Use-After-Free):** 在内存被 `free` 之后继续访问它。
   ```c++
   int *ptr = (int *)malloc(10);
   *ptr = 5;
   free(ptr);
   *ptr = 10; // 错误：访问已释放的内存
   ```
   这会导致未定义行为，可能导致程序崩溃、数据损坏或其他不可预测的结果。

5. **缓冲区溢出 (Buffer Overflow):** 写入超过分配大小的内存区域。
   ```c++
   char *buf = (char *)malloc(10);
   strcpy(buf, "This is a long string"); // 错误：超出 buf 的大小
   ```
   这会覆盖堆上的其他数据，可能导致程序崩溃或安全漏洞。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 开发:**
   - 使用 NDK 开发 Android Native 代码时，开发者可以直接调用标准 C 库的内存管理函数 (`malloc`, `free`, etc.)。
   - 当 Native 代码被编译链接到共享库 (`.so`) 中时，这些内存管理函数的调用会被链接到 Android 系统的 `libc.so`。
   - 当应用运行到调用这些内存管理函数的代码时，最终会执行 `bionic_allocator.cpp` 中的实现。

2. **Android Framework (通过 JNI):**
   - Android Framework 主要使用 Java 编写，但有时需要调用 Native 代码来执行性能敏感或平台特定的操作。
   - Java 代码可以通过 JNI (Java Native Interface) 调用 Native 代码。
   - 在 JNI Native 方法中，开发者可以使用 `malloc` 等函数来分配内存。
   - 这些 `malloc` 调用最终也会路由到 `bionic_allocator.cpp`。

**Frida Hook 示例**

以下是一个使用 Frida Hook 调试 `malloc` 和 `free` 的示例：

```python
import frida
import sys

package_name = "你的应用包名" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到应用: {package_name}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function(args) {
        var size = args[0].toInt();
        send({type: 'malloc', size: size});
        this.startTime = Date.now();
    },
    onLeave: function(retval) {
        var duration = Date.now() - this.startTime;
        send({type: 'malloc_return', address: retval, duration: duration});
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "free"), {
    onEnter: function(args) {
        var address = args[0];
        send({type: 'free', address: address});
        this.startTime = Date.now();
    },
    onLeave: function() {
        var duration = Date.now() - this.startTime;
        send({type: 'free_return', duration: duration});
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. 确保你的 Android 设备已连接并启用 USB 调试。
2. 安装 Frida 和 Python 的 Frida 模块 (`pip install frida-tools`).
3. 将 `你的应用包名` 替换为你要调试的 Android 应用的实际包名。
4. 运行该 Python 脚本。
5. 运行你的 Android 应用，并执行会触发 `malloc` 和 `free` 的操作。
6. Frida 脚本会在终端输出 `malloc` 和 `free` 函数的调用信息，包括分配的大小、返回的地址等。

这个 Frida 脚本会 Hook `libc.so` 中的 `malloc` 和 `free` 函数，并在它们被调用时发送消息到 Frida 主机，从而让你观察内存分配和释放的行为。你可以根据需要扩展这个脚本来记录更多的信息，例如调用栈等。

希望这个详细的解释能够帮助你理解 `bionic_allocator.cpp` 的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/bionic_allocator.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "private/bionic_allocator.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <new>

#include <async_safe/log.h>
#include <async_safe/CHECK.h>

#include "platform/bionic/page.h"
#include "platform/bionic/macros.h"

//
// BionicAllocator is a general purpose allocator designed to provide the same
// functionality as the malloc/free/realloc/memalign libc functions.
//
// On alloc:
// If size is > 1k allocator proxies malloc call directly to mmap.
// If size <= 1k allocator uses BionicSmallObjectAllocator for the size
// rounded up to the nearest power of two.
//
// On free:
//
// For a pointer allocated using proxy-to-mmap allocator unmaps
// the memory.
//
// For a pointer allocated using BionicSmallObjectAllocator it adds
// the block to free_blocks_list in the corresponding page. If the number of
// free pages reaches 2, BionicSmallObjectAllocator munmaps one of the pages
// keeping the other one in reserve.

// Memory management for large objects is fairly straightforward, but for small
// objects it is more complicated.  If you are changing this code, one simple
// way to evaluate the memory usage change is by running 'dd' and examine the
// memory usage by 'showmap $(pidof dd)'.  'dd' is nice in that:
//   1. It links in quite a few libraries, so you get some linker memory use.
//   2. When run with no arguments, it sits waiting for input, so it is easy to
//      examine its memory usage with showmap.
//   3. Since it does nothing while waiting for input, the memory usage is
//      determinisitic.

static const char kSignature[4] = {'L', 'M', 'A', 1};

static const size_t kSmallObjectMaxSize = 1 << kSmallObjectMaxSizeLog2;

// This type is used for large allocations (with size >1k)
static const uint32_t kLargeObject = 111;

// Allocated pointers must be at least 16-byte aligned.  Round up the size of
// page_info to multiple of 16.
static constexpr size_t kPageInfoSize = __BIONIC_ALIGN(sizeof(page_info), 16);

static inline uint16_t log2(size_t number) {
  uint16_t result = 0;
  number--;

  while (number != 0) {
    result++;
    number >>= 1;
  }

  return result;
}

BionicSmallObjectAllocator::BionicSmallObjectAllocator(uint32_t type, size_t block_size)
    : type_(type),
      block_size_(block_size),
      blocks_per_page_((page_size() - sizeof(small_object_page_info)) / block_size),
      free_pages_cnt_(0),
      page_list_(nullptr) {}

void* BionicSmallObjectAllocator::alloc() {
  CHECK(block_size_ != 0);

  if (page_list_ == nullptr) {
    alloc_page();
  }

  // Fully allocated pages are de-managed and removed from the page list, so
  // every page from the page list must be useable.  Let's just take the first
  // one.
  small_object_page_info* page = page_list_;
  CHECK(page->free_block_list != nullptr);

  small_object_block_record* const block_record = page->free_block_list;
  if (block_record->free_blocks_cnt > 1) {
    small_object_block_record* next_free =
        reinterpret_cast<small_object_block_record*>(
            reinterpret_cast<uint8_t*>(block_record) + block_size_);
    next_free->next = block_record->next;
    next_free->free_blocks_cnt = block_record->free_blocks_cnt - 1;
    page->free_block_list = next_free;
  } else {
    page->free_block_list = block_record->next;
  }

  if (page->free_blocks_cnt == blocks_per_page_) {
    free_pages_cnt_--;
  }

  page->free_blocks_cnt--;

  memset(block_record, 0, block_size_);

  if (page->free_blocks_cnt == 0) {
    // De-manage fully allocated pages.  These pages will be managed again if
    // a block is freed.
    remove_from_page_list(page);
  }

  return block_record;
}

void BionicSmallObjectAllocator::free_page(small_object_page_info* page) {
  CHECK(page->free_blocks_cnt == blocks_per_page_);
  if (page->prev_page) {
    page->prev_page->next_page = page->next_page;
  }
  if (page->next_page) {
    page->next_page->prev_page = page->prev_page;
  }
  if (page_list_ == page) {
    page_list_ = page->next_page;
  }
  munmap(page, page_size());
  free_pages_cnt_--;
}

void BionicSmallObjectAllocator::free(void* ptr) {
  small_object_page_info* const page =
      reinterpret_cast<small_object_page_info*>(page_start(reinterpret_cast<uintptr_t>(ptr)));

  if (reinterpret_cast<uintptr_t>(ptr) % block_size_ != 0) {
    async_safe_fatal("invalid pointer: %p (block_size=%zd)", ptr, block_size_);
  }

  memset(ptr, 0, block_size_);
  small_object_block_record* const block_record =
      reinterpret_cast<small_object_block_record*>(ptr);

  block_record->next = page->free_block_list;
  block_record->free_blocks_cnt = 1;

  page->free_block_list = block_record;
  page->free_blocks_cnt++;

  if (page->free_blocks_cnt == blocks_per_page_) {
    if (++free_pages_cnt_ > 1) {
      // if we already have a free page - unmap this one.
      free_page(page);
    }
  } else if (page->free_blocks_cnt == 1) {
    // We just freed from a full page.  Add this page back to the list.
    add_to_page_list(page);
  }
}

void BionicSmallObjectAllocator::alloc_page() {
  void* const map_ptr =
      mmap(nullptr, page_size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (map_ptr == MAP_FAILED) {
    async_safe_fatal("mmap failed: %m");
  }

  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, map_ptr, page_size(), "bionic_alloc_small_objects");

  small_object_page_info* const page =
      reinterpret_cast<small_object_page_info*>(map_ptr);
  memcpy(page->info.signature, kSignature, sizeof(kSignature));
  page->info.type = type_;
  page->info.allocator_addr = this;

  page->free_blocks_cnt = blocks_per_page_;

  // Align the first block to block_size_.
  const uintptr_t first_block_addr =
      __BIONIC_ALIGN(reinterpret_cast<uintptr_t>(page + 1), block_size_);
  small_object_block_record* const first_block =
      reinterpret_cast<small_object_block_record*>(first_block_addr);

  first_block->next = nullptr;
  first_block->free_blocks_cnt = blocks_per_page_;

  page->free_block_list = first_block;

  add_to_page_list(page);

  free_pages_cnt_++;
}

void BionicSmallObjectAllocator::add_to_page_list(small_object_page_info* page) {
  page->next_page = page_list_;
  page->prev_page = nullptr;
  if (page_list_) {
    page_list_->prev_page = page;
  }
  page_list_ = page;
}

void BionicSmallObjectAllocator::remove_from_page_list(
    small_object_page_info* page) {
  if (page->prev_page) {
    page->prev_page->next_page = page->next_page;
  }
  if (page->next_page) {
    page->next_page->prev_page = page->prev_page;
  }
  if (page_list_ == page) {
    page_list_ = page->next_page;
  }
  page->prev_page = nullptr;
  page->next_page = nullptr;
}

void BionicAllocator::initialize_allocators() {
  if (allocators_ != nullptr) {
    return;
  }

  BionicSmallObjectAllocator* allocators =
      reinterpret_cast<BionicSmallObjectAllocator*>(allocators_buf_);

  for (size_t i = 0; i < kSmallObjectAllocatorsCount; ++i) {
    uint32_t type = i + kSmallObjectMinSizeLog2;
    new (allocators + i) BionicSmallObjectAllocator(type, 1 << type);
  }

  allocators_ = allocators;
}

void* BionicAllocator::alloc_mmap(size_t align, size_t size) {
  size_t header_size = __BIONIC_ALIGN(kPageInfoSize, align);
  size_t allocated_size;
  if (__builtin_add_overflow(header_size, size, &allocated_size) ||
      page_end(allocated_size) < allocated_size) {
    async_safe_fatal("overflow trying to alloc %zu bytes", size);
  }
  allocated_size = page_end(allocated_size);
  void* map_ptr = mmap(nullptr, allocated_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
                       -1, 0);

  if (map_ptr == MAP_FAILED) {
    async_safe_fatal("mmap failed: %m");
  }

  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, map_ptr, allocated_size, "bionic_alloc_lob");

  void* result = static_cast<char*>(map_ptr) + header_size;
  page_info* info = get_page_info_unchecked(result);
  memcpy(info->signature, kSignature, sizeof(kSignature));
  info->type = kLargeObject;
  info->allocated_size = allocated_size;

  return result;
}


inline void* BionicAllocator::alloc_impl(size_t align, size_t size) {
  if (size > kSmallObjectMaxSize) {
    return alloc_mmap(align, size);
  }

  uint16_t log2_size = log2(size);

  if (log2_size < kSmallObjectMinSizeLog2) {
    log2_size = kSmallObjectMinSizeLog2;
  }

  return get_small_object_allocator_unchecked(log2_size)->alloc();
}

void* BionicAllocator::alloc(size_t size) {
  // treat alloc(0) as alloc(1)
  if (size == 0) {
    size = 1;
  }
  return alloc_impl(16, size);
}

void* BionicAllocator::memalign(size_t align, size_t size) {
  // The Bionic allocator only supports alignment up to one page, which is good
  // enough for ELF TLS.
  align = MIN(align, page_size());
  align = MAX(align, 16);
  if (!powerof2(align)) {
    align = BIONIC_ROUND_UP_POWER_OF_2(align);
  }
  size = MAX(size, align);
  return alloc_impl(align, size);
}

inline page_info* BionicAllocator::get_page_info_unchecked(void* ptr) {
  uintptr_t header_page = page_start(reinterpret_cast<size_t>(ptr) - kPageInfoSize);
  return reinterpret_cast<page_info*>(header_page);
}

inline page_info* BionicAllocator::get_page_info(void* ptr) {
  page_info* info = get_page_info_unchecked(ptr);
  if (memcmp(info->signature, kSignature, sizeof(kSignature)) != 0) {
    async_safe_fatal("invalid pointer %p (page signature %04x instead of %04x)", ptr,
                     *reinterpret_cast<const unsigned*>(info->signature),
                     *reinterpret_cast<const unsigned*>(kSignature));
  }
  return info;
}

void* BionicAllocator::realloc(void* ptr, size_t size) {
  if (ptr == nullptr) {
    return alloc(size);
  }

  if (size == 0) {
    free(ptr);
    return nullptr;
  }

  page_info* info = get_page_info(ptr);

  size_t old_size = 0;

  if (info->type == kLargeObject) {
    old_size = info->allocated_size - (static_cast<char*>(ptr) - reinterpret_cast<char*>(info));
  } else {
    old_size = get_small_object_allocator(info, ptr)->get_block_size();
  }

  if (old_size < size) {
    void *result = alloc(size);
    memcpy(result, ptr, old_size);
    free(ptr);
    return result;
  }

  return ptr;
}

void BionicAllocator::free(void* ptr) {
  if (ptr == nullptr) {
    return;
  }

  page_info* info = get_page_info(ptr);
  if (info->type == kLargeObject) {
    munmap(info, info->allocated_size);
  } else {
    get_small_object_allocator(info, ptr)->free(ptr);
  }
}

size_t BionicAllocator::get_chunk_size(void* ptr) {
  if (ptr == nullptr) return 0;

  page_info* info = get_page_info_unchecked(ptr);
  if (memcmp(info->signature, kSignature, sizeof(kSignature)) != 0) {
    // Invalid pointer (mismatched signature)
    return 0;
  }
  if (info->type == kLargeObject) {
    return info->allocated_size - (static_cast<char*>(ptr) - reinterpret_cast<char*>(info));
  }

  BionicSmallObjectAllocator* allocator = get_small_object_allocator_unchecked(info->type);
  if (allocator != info->allocator_addr) {
    // Invalid pointer.
    return 0;
  }
  return allocator->get_block_size();
}

BionicSmallObjectAllocator* BionicAllocator::get_small_object_allocator_unchecked(uint32_t type) {
  if (type < kSmallObjectMinSizeLog2 || type > kSmallObjectMaxSizeLog2) {
    async_safe_fatal("invalid type: %u", type);
  }

  initialize_allocators();
  return &allocators_[type - kSmallObjectMinSizeLog2];
}

BionicSmallObjectAllocator* BionicAllocator::get_small_object_allocator(page_info* pi, void* ptr) {
  BionicSmallObjectAllocator* result = get_small_object_allocator_unchecked(pi->type);
  if (result != pi->allocator_addr) {
    async_safe_fatal("invalid pointer %p (invalid allocator address for the page)", ptr);
  }
  return result;
}
"""

```