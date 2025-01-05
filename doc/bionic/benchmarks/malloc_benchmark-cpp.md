Response:
Let's break down the thought process for analyzing this C++ benchmark file. The initial request is quite broad, so a structured approach is key.

**1. Understanding the Goal of the File:**

The filename `malloc_benchmark.cpp` immediately suggests its purpose: to measure the performance of memory allocation (`malloc`) and deallocation (`free`) within Android's Bionic library. The presence of `<benchmark/benchmark.h>` confirms this, as it's a standard C++ benchmarking library.

**2. Identifying Key Functionalities:**

I scanned the code for distinct functions and their roles:

* **`RunMalloptPurge`:**  This function clearly focuses on testing the `mallopt` function, specifically with `M_PURGE` and `M_PURGE_ALL`. The logic involves allocating memory, freeing it, and then calling `mallopt` to observe its effect.
* **`RunThreadsThroughput`:** This function is designed to test the throughput of `malloc` and `free` under multi-threading. The nested loops and thread creation are strong indicators of this.
* **`BM_mallopt_purge` and `BM_mallopt_purge_all`:** These are thin wrappers around `RunMalloptPurge`, configuring it for different `mallopt` options. The `BIONIC_BENCHMARK` macro signifies their role in the benchmarking framework.
* **`BM_malloc_threads_throughput_...`:**  These are macro-generated functions that call `RunThreadsThroughput` with varying allocation sizes and thread counts. This signifies testing under different contention levels.

**3. Analyzing Individual Functions in Detail:**

* **`RunMalloptPurge`:**
    * **`mallopt(M_DECAY_TIME, 1)`:**  Recognize that `M_DECAY_TIME` likely relates to how quickly the allocator releases unused memory. Setting it to 1 probably makes it more aggressive.
    * **`mallopt(M_PURGE_ALL, 0)`:** This is a setup step, likely ensuring a baseline state before the actual purge test.
    * **Allocation Loop:** Notice the increasing allocation sizes and the `MakeAllocationResident` call (even though its implementation isn't in this file, its name hints at ensuring the memory is actually used/touched). The allocation amount is at least two pages, suggesting the test aims to observe page-level behavior.
    * **Freeing Loop:**  Simple deallocation of the allocated blocks.
    * **`mallopt(purge_value, 0)`:** The core of the test, measuring the performance impact of purging memory.
    * **`ScopedDecayTimeRestorer`:**  Recognize this as a RAII mechanism to restore the `M_DECAY_TIME` setting after the benchmark.

* **`RunThreadsThroughput`:**
    * **Thread Creation and Synchronization:**  The use of `std::thread`, `std::mutex`, and `std::condition_variable` clearly indicates a multi-threaded test. The `ready` flag and `cv.wait`/`cv.notify_all` are standard patterns for synchronizing thread startup.
    * **Allocation/Deallocation Pattern:** The nested loops with `AllocCounts` and `AllocRounds` control the number of allocations and deallocations each thread performs. The bitwise shift (`>> id`) and left shift (`<< id`) applied to these values based on the thread ID are crucial. This creates the interleaved allocation/deallocation patterns described in the comments. This is a key insight into *how* the benchmark is stressing the allocator.
    * **Shuffling:** The `std::shuffle` step adds randomness to the deallocation order, likely to avoid predictable patterns that might artificially improve performance.
    * **`state.SetBytesProcessed`:** This is part of the benchmarking framework, calculating the total amount of data processed.

**4. Addressing Specific Questions from the Prompt:**

* **Functionality:**  Summarize the purpose of each function as described above.
* **Relationship to Android:** Explain that this benchmarks Bionic's `malloc`, which is fundamental to Android's memory management. Give concrete examples of where `malloc` is used (e.g., object creation, string manipulation).
* **`libc` Function Details:** Focus on `malloc`, `free`, `getpagesize`, and `mallopt`. Explain their basic function and, importantly, acknowledge that *this benchmark doesn't reveal the internal implementation*. Avoid speculation about the internal mechanisms.
* **Dynamic Linker:** Recognize that this file *doesn't directly test the dynamic linker*. Explain the linker's role, provide a basic SO layout, and explain symbol resolution (using placeholders like `GLOBAL`, `LOCAL`, `WEAK`). This shows understanding even though it's not the focus of the code.
* **Logic and Assumptions:**  For `RunThreadsThroughput`, the core assumption is that varying allocation/deallocation patterns across threads will expose contention issues in the memory allocator. The input is the `size` and `num_threads`; the output is the benchmark result (throughput).
* **Common Errors:** Focus on typical `malloc`/`free` errors: double-free, memory leaks, using freed memory.
* **Android Framework/NDK Trace:**  Outline the layers: Android Framework (Java), JNI, NDK (C/C++), Bionic. Explain how memory allocation requests flow down this stack.

**5. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Start with a high-level overview and then delve into specifics. Address each part of the original prompt.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Perhaps I should try to guess the exact implementation details of `malloc`. **Correction:** This benchmark doesn't provide that level of detail. Focus on the *observable behavior* and the purpose of the tests.
* **Initial thought:**  Should I dive deep into the intricacies of the benchmarking framework? **Correction:**  Keep it concise. Focus on how the framework is used in this specific file (e.g., `state` object, `BIONIC_BENCHMARK` macro).
* **Realization:** The interleaved allocation/deallocation pattern in `RunThreadsThroughput` is a key aspect of the benchmark's design. Emphasize this in the explanation.

By following these steps, I could systematically analyze the provided code and generate a comprehensive and accurate response that addresses all aspects of the prompt. The key is to break down the problem, understand the purpose of the code, and connect it to the broader context of Android system development.
好的，我们来详细分析一下 `bionic/benchmarks/malloc_benchmark.cpp` 这个文件。

**文件功能概述**

这个 C++ 文件是一个性能基准测试，专门用于评估 Android Bionic 库中内存分配器（`malloc` 和 `free` 等函数）的性能。它使用 Google Benchmark 框架来执行各种内存分配和释放的场景，并测量其吞吐量和效率。

**与 Android 功能的关系及举例**

Bionic 是 Android 的 C 标准库，因此 `malloc` 和 `free` 是 Android 系统中非常核心的功能。几乎所有在 Android 上运行的进程，包括系统服务、应用程序框架、以及 NDK 开发的本地代码，都会频繁地使用 `malloc` 来动态分配内存，以及 `free` 来释放不再使用的内存。

* **系统服务 (System Server):** Android 的核心系统服务，如 Activity Manager、Package Manager 等，都使用 C++ 编写，需要动态分配内存来管理各种系统资源和对象。例如，当启动一个新的 Activity 时，Activity Manager 可能会分配内存来存储 Activity 的状态信息。
* **应用程序框架 (Application Framework):** 虽然上层应用主要使用 Java/Kotlin，但框架层仍然有大量的 C/C++ 代码。例如，Media Framework 处理音视频数据时，需要分配缓冲区来存储解码后的帧数据。
* **NDK 开发:** 使用 NDK 开发的应用，其本地代码完全依赖 Bionic 提供的 `malloc` 和 `free` 进行内存管理。例如，一个游戏引擎需要动态分配内存来存储游戏对象、纹理、模型等数据。

**libc 函数功能详解**

这个基准测试中主要涉及的 libc 函数有：

1. **`malloc(size_t size)`:**
   * **功能:**  `malloc` 函数用于在堆（heap）上分配一块指定大小（`size` 字节）的内存块。它返回一个指向被分配内存起始位置的 `void*` 指针。如果分配失败（例如，没有足够的内存），则返回 `nullptr`。
   * **实现 (Bionic 中的 Scudo 内存分配器):**  Bionic 使用 Scudo 作为其默认的内存分配器。Scudo 是一种现代的、具有安全特性的分配器，其实现相当复杂，主要包括以下步骤：
      * **确定分配大小类别 (Size Class):**  Scudo 将不同大小的分配请求映射到预定义的 "大小类别"，以减少内存碎片。
      * **从 Span 中分配:** 每个大小类别都有一个或多个 "Span"（连续的内存页）与之关联。`malloc` 会尝试从当前 Span 中找到足够大的空闲块。
      * **分配新的 Span (如果需要):** 如果当前 Span 没有足够的空闲块，Scudo 会向操作系统申请新的内存页来创建一个新的 Span。
      * **返回指针:**  返回指向分配到的内存块的指针。
   * **本例使用:** `RunMalloptPurge` 和 `RunThreadsThroughput` 函数都使用 `malloc` 来分配不同大小的内存块，以模拟不同的内存分配场景。

2. **`free(void* ptr)`:**
   * **功能:** `free` 函数用于释放之前通过 `malloc`、`calloc` 或 `realloc` 分配的内存块。参数 `ptr` 必须是之前 `malloc` 等函数返回的有效指针，否则会导致未定义行为（例如，崩溃）。
   * **实现 (Bionic 中的 Scudo):**
      * **确定 Span:**  根据传入的指针 `ptr`，Scudo 确定该内存块所属的 Span。
      * **标记为空闲:** 将该内存块标记为空闲，并将其添加到 Span 的空闲链表中。
      * **Span 合并和释放 (可能):** 如果一个 Span 中的所有块都被释放，Scudo 可能会将这个 Span 返回给操作系统。
   * **本例使用:**  `RunMalloptPurge` 和 `RunThreadsThroughput` 函数在完成内存使用后，使用 `free` 来释放之前分配的内存。

3. **`getpagesize()`:**
   * **功能:**  `getpagesize` 函数返回系统的内存页大小，单位是字节。内存页是操作系统进行内存管理的基本单位。
   * **实现 (系统调用):**  `getpagesize` 通常通过一个系统调用来实现，直接从操作系统内核获取页大小信息。
   * **本例使用:** `RunMalloptPurge` 使用 `getpagesize` 来确定分配至少两个内存页大小的内存，以便更有效地测试 `mallopt` 的 `M_PURGE` 功能。

4. **`mallopt(int cmd, int value)`:**
   * **功能:** `mallopt` 函数用于调整内存分配器的行为。不同的 `cmd` 参数对应不同的调整选项。
   * **实现 (Bionic 中的 Scudo):** Scudo 支持的 `mallopt` 选项有限。本例中使用的两个选项是：
      * **`M_DECAY_TIME`:**  设置空闲内存页返回给操作系统的延迟时间。`value` 参数表示延迟的秒数。`RunMalloptPurge` 中设置为 1 秒。
      * **`M_PURGE`:** 尝试释放可以释放的空闲内存页。
      * **`M_PURGE_ALL`:** 强制释放所有可以释放的空闲内存页。
   * **本例使用:** `RunMalloptPurge` 函数使用 `mallopt` 来测试 `M_PURGE` 和 `M_PURGE_ALL` 的效果，观察在分配和释放大量内存后，调用这些选项能否有效地将空闲内存返回给操作系统。

**dynamic linker 的功能、SO 布局和符号处理**

虽然这个基准测试文件本身没有直接测试 dynamic linker (在 Bionic 中是 `linker64` 或 `linker`)，但理解 dynamic linker 对于理解 Bionic 的整体架构至关重要。

**功能:** Dynamic Linker 负责在程序启动时，将程序依赖的共享库（Shared Objects, `.so` 文件）加载到内存中，并解析和链接程序中使用的符号。

**SO 布局样本:**

一个典型的 `.so` 文件（如 `libfoo.so`）的布局大致如下：

```
ELF Header:
  Magic number (标识 ELF 文件)
  ... 其他元数据

Program Headers:
  描述了 SO 文件在内存中的段 (segment) 如何加载
  典型的段包括：
    - LOAD (可执行代码和数据)
    - DYNAMIC (动态链接信息)
    - ...

Section Headers:
  包含了各种 Section 的信息，用于链接和调试
  典型的 Section 包括：
    - .text (可执行代码)
    - .rodata (只读数据)
    - .data (已初始化的可读写数据)
    - .bss (未初始化的可读写数据)
    - .symtab (符号表)
    - .strtab (字符串表，用于存储符号名等)
    - .dynsym (动态符号表)
    - .dynstr (动态字符串表)
    - .rel.dyn (动态重定位信息)
    - .rel.plt (Procedure Linkage Table 重定位信息)
    - ...

... Section 内容 ...
```

**符号处理过程:**

1. **查找依赖:** Dynamic Linker 首先读取可执行文件（或 SO 文件）的 `DYNAMIC` 段，找到其依赖的其他 SO 文件。
2. **加载 SO 文件:**  将依赖的 SO 文件加载到内存中的某个地址空间。加载地址通常是随机的 (ASLR - Address Space Layout Randomization) 以提高安全性。
3. **符号解析:**
   * **全局符号 (GLOBAL):**  在 SO 文件中声明为全局的符号（例如，使用 `extern` 且没有 `static` 关键字声明的函数或变量）。这些符号可以被其他 SO 文件或主程序引用。Dynamic Linker 会在所有已加载的 SO 文件中查找这些符号的定义。
   * **本地符号 (LOCAL):** 在 SO 文件中声明为本地的符号（例如，使用 `static` 关键字声明的函数或变量）。这些符号的作用域仅限于当前 SO 文件，不会被其他 SO 文件看到。Dynamic Linker 通常会忽略本地符号。
   * **弱符号 (WEAK):**  一种特殊的全局符号。如果在多个 SO 文件中定义了相同的弱符号，链接器会选择其中一个，而不会报错。这通常用于提供默认实现，可以被更强的符号覆盖。
4. **重定位:**  由于 SO 文件被加载到内存的随机地址，其中引用的全局符号的地址在编译时是未知的。Dynamic Linker 会根据 `.rel.dyn` 和 `.rel.plt` 段中的信息，修改代码和数据段中对这些符号的引用，使其指向正确的内存地址。
   * **`.rel.dyn`:** 处理数据段中的全局符号引用。
   * **`.rel.plt`:** 处理函数调用，通常通过 Procedure Linkage Table (PLT) 实现延迟绑定 (lazy binding)。只有在函数第一次被调用时才解析其地址。

**逻辑推理、假设输入与输出 (针对 `RunThreadsThroughput`)**

**假设输入:**
* `size`:  要分配的内存块大小，例如 64 字节。
* `num_threads`:  执行分配和释放的线程数量，例如 4。

**执行流程推理:**

1. **线程创建:** 创建 `num_threads` 个线程，每个线程执行 `thread_task` 函数。
2. **线程同步:** 使用互斥锁和条件变量确保所有线程都创建完成并准备好开始。
3. **并发分配和释放:** 每个线程会执行多次（`AllocRounds`）以下操作：
   * 分配 `AllocCounts` 个大小为 `size` 的内存块，并将指针存储在 `MemPool` 中。`AllocCounts` 的计算方式使得不同线程分配的总字节数大致相同。
   * 对 `MemPool` 中的指针进行随机排序。
   * 释放 `MemPool` 中的所有内存块。
4. **基准测试统计:** Google Benchmark 框架会测量整个过程的时间，并计算出每秒处理的字节数。

**预期输出:**

基准测试的输出会显示在给定的 `size` 和 `num_threads` 下，内存分配和释放的吞吐量（例如，操作次数/秒 或 字节数/秒）。例如：

```
BM_malloc_threads_throughput_64_4  41.2 ms       41.1 ms       17  16.0 GiB/s
```

这表示在分配 64 字节的内存块，使用 4 个线程并发执行时，每次迭代耗时约 41.1 毫秒，吞吐量约为 16.0 GiB/秒。

**用户或编程常见的使用错误举例**

与 `malloc` 和 `free` 相关的常见错误包括：

1. **内存泄漏 (Memory Leak):**
   * **错误:** 分配了内存但忘记释放。
   * **示例:**
     ```c++
     void foo() {
       int* ptr = (int*)malloc(sizeof(int) * 10);
       // ... 使用 ptr ...
       // 忘记 free(ptr);
     }
     ```
   * **后果:** 随着程序运行，占用的内存越来越多，最终可能导致程序崩溃或系统性能下降。

2. **重复释放 (Double Free):**
   * **错误:**  尝试释放已经被释放过的内存。
   * **示例:**
     ```c++
     int* ptr = (int*)malloc(sizeof(int));
     free(ptr);
     free(ptr); // 错误：ptr 指向的内存已被释放
     ```
   * **后果:** 导致内存分配器的内部数据结构损坏，可能引发崩溃或其他不可预测的行为。

3. **释放未分配的内存:**
   * **错误:**  尝试释放一个并非由 `malloc` 等函数分配的内存地址。
   * **示例:**
     ```c++
     int x;
     free(&x); // 错误：&x 指向栈上的变量，不是通过 malloc 分配的
     ```
   * **后果:**  与重复释放类似，会导致内存分配器错误。

4. **使用已释放的内存 (Use After Free):**
   * **错误:**  在内存被释放后，仍然尝试访问或修改该内存。
   * **示例:**
     ```c++
     int* ptr = (int*)malloc(sizeof(int));
     *ptr = 10;
     free(ptr);
     int value = *ptr; // 错误：ptr 指向的内存已被释放
     ```
   * **后果:**  可能读取到垃圾数据，或者更严重的情况下，导致程序崩溃。

5. **缓冲区溢出 (Buffer Overflow):**
   * **错误:**  写入的数据超过了分配的内存块的大小。这通常不是 `malloc` 本身的错误，而是使用 `malloc` 分配的缓冲区时的错误。
   * **示例:**
     ```c++
     char* buffer = (char*)malloc(10);
     strcpy(buffer, "This is a very long string"); // 错误：字符串超过了 10 字节
     ```
   * **后果:**  可能覆盖相邻的内存区域，导致程序崩溃或安全漏洞。

**Android Framework 或 NDK 如何到达这里 (调试线索)**

当你在 Android 上进行开发时，无论是通过 Java/Kotlin Framework 还是通过 NDK，最终的内存分配请求都会落到 Bionic 的 `malloc` 实现上。以下是可能的路径：

1. **Java/Kotlin Framework:**
   * 当 Java/Kotlin 代码中创建对象时（例如，`new Object()`），底层的虚拟机 (Dalvik/ART) 需要分配内存来存储该对象。
   * 虚拟机的内存管理部分会调用底层的 C/C++ 代码，最终通过 Bionic 的 `malloc` 来分配堆内存。
   * 例如，`java.lang.String` 对象的字符数组存储在堆上，其内存分配就依赖于 `malloc`。

2. **NDK 开发:**
   * 当你在 NDK 的 C/C++ 代码中使用 `new` 运算符或直接调用 `malloc` 函数时，这些调用会直接链接到 Bionic 提供的 `malloc` 实现。
   * 例如，一个使用 OpenGL ES 的游戏引擎，需要分配内存来存储顶点数据、纹理数据等，这些都会通过 `malloc` 完成。

**调试线索:**

当你遇到与内存分配相关的问题时，可以利用以下调试线索：

* **崩溃日志 (Crash Logs):**  如果程序由于内存错误崩溃，系统通常会生成崩溃日志，其中可能包含导致崩溃的内存地址、调用堆栈等信息。分析这些日志可以帮助定位问题代码。
* **AddressSanitizer (ASan):**  一个强大的内存错误检测工具。你可以在编译时启用 ASan，它会在运行时检查内存泄漏、使用已释放的内存、缓冲区溢出等错误，并在发现错误时立即报告。NDK 支持 ASan。
* **Memory Profilers:**  Android Studio 提供了内存分析工具，可以帮助你监控应用程序的内存使用情况，查找内存泄漏。
* **`dmalloc` 或其他内存调试库:**  在 NDK 开发中，你可以使用 `dmalloc` 等第三方内存调试库来跟踪内存分配和释放，帮助定位内存错误。
* **`adb shell dumpsys meminfo <process_name>`:**  这个命令可以显示指定进程的内存使用情况，包括堆大小、已分配的内存、空闲内存等信息，有助于监控内存泄漏。
* **Bionic 的调试符号:** 如果你需要深入了解 Bionic `malloc` 的行为，可以使用包含调试符号的 Bionic 库进行调试，例如通过 GDB。

总结来说，`bionic/benchmarks/malloc_benchmark.cpp` 是一个重要的性能测试工具，用于确保 Android 系统的核心内存分配机制高效可靠。理解其功能和测试方法，以及与 Android 系统其他组件的关系，对于 Android 开发和性能优化至关重要。

Prompt: 
```
这是目录为bionic/benchmarks/malloc_benchmark.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于dynamic linker的功能，请给so布局样本，以及每种符号如何的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <malloc.h>
#include <unistd.h>

#include <condition_variable>
#include <mutex>
#include <random>
#include <thread>
#include <vector>

#include <benchmark/benchmark.h>
#include "ScopedDecayTimeRestorer.h"
#include "util.h"

#if defined(__BIONIC__)

static void RunMalloptPurge(benchmark::State& state, int purge_value) {
  ScopedDecayTimeRestorer restorer;

  static size_t sizes[] = {8, 16, 32, 64, 128, 1024, 4096, 16384, 65536, 131072, 1048576};
  static int pagesize = getpagesize();
  mallopt(M_DECAY_TIME, 1);
  mallopt(M_PURGE_ALL, 0);
  for (auto _ : state) {
    state.PauseTiming();
    std::vector<void*> ptrs;
    for (auto size : sizes) {
      // Allocate at least two pages worth of the allocations.
      for (size_t allocated = 0; allocated < 2 * static_cast<size_t>(pagesize); allocated += size) {
        void* ptr = malloc(size);
        if (ptr == nullptr) {
          state.SkipWithError("Failed to allocate memory");
        }
        MakeAllocationResident(ptr, size, pagesize);
        ptrs.push_back(ptr);
      }
    }
    // Free the memory, which should leave many of the pages resident until
    // the purge call.
    for (auto ptr : ptrs) {
      free(ptr);
    }
    ptrs.clear();
    state.ResumeTiming();

    mallopt(purge_value, 0);
  }
}

static void RunThreadsThroughput(benchmark::State& state, size_t size, size_t num_threads) {
  constexpr size_t kMaxBytes = 1 << 24;
  constexpr size_t kMaxThreads = 8;
  constexpr size_t kMinRounds = 4;
  const size_t MaxAllocCounts = kMaxBytes / size;
  std::mutex m;
  bool ready = false;
  std::condition_variable cv;
  std::thread* threads[kMaxThreads];

  // The goal is to create malloc/free interleaving patterns across threads.
  // The bytes processed by each thread will be the same. The difference is the
  // patterns. Here's an example:
  //
  // A: Allocation
  // D: Deallocation
  //
  //   T1    T2    T3
  //   A     A     A
  //   A     A     D
  //   A     D     A
  //   A     D     D
  //   D     A     A
  //   D     A     D
  //   D     D     A
  //   D     D     D
  //
  // To do this, `AllocCounts` and `AllocRounds` will be adjusted according to the
  // thread id.
  auto thread_task = [&](size_t id) {
    {
      std::unique_lock lock(m);
      // Wait until all threads are created.
      cv.wait(lock, [&] { return ready; });
    }

    void** MemPool;
    const size_t AllocCounts = (MaxAllocCounts >> id);
    const size_t AllocRounds = (kMinRounds << id);
    MemPool = new void*[AllocCounts];

    for (size_t i = 0; i < AllocRounds; ++i) {
      for (size_t j = 0; j < AllocCounts; ++j) {
        void* ptr = malloc(size);
        MemPool[j] = ptr;
      }

      // Use a fix seed to reduce the noise of different round of benchmark.
      const unsigned seed = 33529;
      std::shuffle(MemPool, &MemPool[AllocCounts], std::default_random_engine(seed));

      for (size_t j = 0; j < AllocCounts; ++j) free(MemPool[j]);
    }

    delete[] MemPool;
  };

  for (auto _ : state) {
    state.PauseTiming();
    // Don't need to acquire the lock because no thread is created.
    ready = false;

    for (size_t i = 0; i < num_threads; ++i) threads[i] = new std::thread(thread_task, i);

    state.ResumeTiming();

    {
      std::unique_lock lock(m);
      ready = true;
    }

    cv.notify_all();

    for (size_t i = 0; i < num_threads; ++i) {
      threads[i]->join();
      delete threads[i];
    }
  }

  const size_t ThreadsBytesProcessed = kMaxBytes * kMinRounds * num_threads;
  state.SetBytesProcessed(ThreadsBytesProcessed * static_cast<size_t>(state.iterations()));
}

static void BM_mallopt_purge(benchmark::State& state) {
  RunMalloptPurge(state, M_PURGE);
}
BIONIC_BENCHMARK(BM_mallopt_purge);

static void BM_mallopt_purge_all(benchmark::State& state) {
  RunMalloptPurge(state, M_PURGE_ALL);
}
BIONIC_BENCHMARK(BM_mallopt_purge_all);

// Note that this will only test a single size class at a time so that we can
// observe the impact of contention more often.
#define BM_MALLOC_THREADS_THROUGHPUT(SIZE, NUM_THREADS)                                      \
  static void BM_malloc_threads_throughput_##SIZE##_##NUM_THREADS(benchmark::State& state) { \
    RunThreadsThroughput(state, SIZE, NUM_THREADS);                                          \
  }                                                                                          \
  BIONIC_BENCHMARK(BM_malloc_threads_throughput_##SIZE##_##NUM_THREADS);

// There are three block categories in Scudo, we choose 1 from each category.
BM_MALLOC_THREADS_THROUGHPUT(64, 2);
BM_MALLOC_THREADS_THROUGHPUT(64, 4);
BM_MALLOC_THREADS_THROUGHPUT(64, 8);
BM_MALLOC_THREADS_THROUGHPUT(512, 2);
BM_MALLOC_THREADS_THROUGHPUT(512, 4);
BM_MALLOC_THREADS_THROUGHPUT(512, 8);
BM_MALLOC_THREADS_THROUGHPUT(8192, 2);
BM_MALLOC_THREADS_THROUGHPUT(8192, 4);
BM_MALLOC_THREADS_THROUGHPUT(8192, 8);

#endif

"""

```