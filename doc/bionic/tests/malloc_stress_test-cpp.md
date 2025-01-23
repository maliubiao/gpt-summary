Response:
Let's break down the thought process for analyzing this C++ stress test. The goal is to answer the user's request comprehensively, covering functionality, relation to Android, libc functions, dynamic linking, potential errors, and tracing.

**1. Understanding the Core Purpose:**

The first step is to read the code and identify its primary objective. The test name `malloc_stress` and the loop that repeatedly allocates and frees memory in multiple threads immediately suggest its purpose: to stress-test the memory allocator (malloc/free). The `multiple_threads_forever` part emphasizes the concurrent and long-running nature of the test.

**2. Deconstructing the Code - Key Components:**

Next, dissect the code into its functional parts:

* **Includes:**  Note the standard C/C++ headers (`gtest`, `inttypes.h`, `malloc.h`, etc.) and the Bionic-specific ones (`meminfo/procmeminfo.h`, `procinfo/process_map.h`, `log/log.h`, `log/log_read.h`). This separation gives a clue about the code's dependencies and potential Android-specific interactions.
* **`PrintLogStats` function:** This function is clearly related to logging. The use of `android_logger_list_open`, `android_logger_list_read`, and the tag checks ("scudo", "jemalloc") indicate it reads allocator-specific log messages. Recognize this is an Android logging mechanism.
* **`TEST(malloc_stress, multiple_threads_forever)`:** This is the main test function using Google Test. Focus on the core logic within this function.
* **Thread creation and management:** The loop creating and joining threads, each allocating and freeing memory.
* **Memory allocation and deallocation:** The core operations being tested: `malloc`, `memset`, `sleep`, `free`.
* **Memory statistics gathering (inside `#if defined(__BIONIC__)`):** This section uses `proc_mem` to get memory usage information (RSS and VSS). The filtering by VMA names ("libc_malloc", "scudo", "GWP-ASan") is crucial for understanding what memory regions are being monitored.
* **`mallinfo()` usage:**  This standard libc function provides allocator statistics.
* **`mallopt()` usage:** The calls to `mallopt(M_DECAY_TIME, 1)` and `mallopt(M_LOG_STATS, 0)` suggest control over allocator behavior (decay time and logging).
* **The infinite loop:** The `for (size_t i = 0; ; i++)` indicates the test runs indefinitely, stressing the allocator over time.

**3. Connecting to Android:**

Identify the parts of the code that are specific to Android:

* **`__BIONIC__` macro:**  This immediately flags code sections that are exclusive to the Bionic C library environment.
* **Headers:**  The inclusion of `meminfo/procmeminfo.h`, `procinfo/process_map.h`, `log/log.h`, `log/log_read.h` is a strong indicator of Android dependency.
* **Logging functions:** `android_logger_list_open`, `android_logger_list_read`, `android_name_to_log_id`, `strerrordesc_np`, `android_logger_list_close`.
* **Memory map analysis:** The use of `ProcMemInfo` and `Vma` to analyze process memory maps is an Android-specific technique.
* **Allocator names in logs:** "scudo" and "jemalloc" are the names of Android's memory allocators.

**4. Explaining libc Functions:**

For each libc function used (`malloc`, `free`, `memset`, `sleep`, `mallinfo`, `mallopt`), provide a concise explanation of its purpose and how it is implemented within the Bionic context (or generally if the implementation details are not readily available in the provided code). Mention any Android-specific considerations if known.

**5. Addressing Dynamic Linking:**

While the code doesn't directly demonstrate dynamic linking in the same way as loading a shared library, it *relies* on the dynamic linker. Explain this implicit dependency. A basic SO layout example is helpful to illustrate the concept of how shared libraries are loaded. Briefly describe the linking process.

**6. Identifying Potential Errors:**

Consider common errors related to memory management:

* **Memory leaks:** Although this test tries to avoid them by calling `free`, it's a general concern.
* **Double frees:**  A classic error.
* **Use-after-free:**  Accessing memory after it has been freed.
* **Null pointer dereferences:** If `malloc` fails.

**7. Tracing with Frida:**

Explain how Frida can be used to intercept function calls and inspect their arguments and return values. Provide concrete examples of Frida scripts to hook `malloc`, `free`, and the Android logging functions. Explain *why* these hooks are useful for understanding the test's behavior.

**8. Structuring the Response:**

Organize the answer logically according to the user's request:

* Functionality of the test.
* Relationship to Android with examples.
* Detailed explanation of libc functions.
* Dynamic linking aspects (even if implicit).
* Potential errors.
* Tracing with Frida.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus heavily on the threading aspect. **Correction:** While threading is important, the *core* is memory allocation stress. The threads are a *mechanism* to achieve this.
* **Initial thought:**  Try to explain the *exact* implementation of `malloc` in Bionic. **Correction:** The code doesn't provide that level of detail. Focus on the *behavior* and purpose of `malloc` and mention the allocators used by Android (scudo, jemalloc).
* **Initial thought:** Only mention explicit dynamic linking (e.g., `dlopen`). **Correction:**  Recognize that the *use* of standard libc functions implicitly relies on the dynamic linker loading `libc.so`.
* **Initial thought:**  Provide very basic Frida examples. **Correction:** Provide more specific examples relevant to the functions used in the test, demonstrating how to get useful information.

By following these steps, the comprehensive and well-structured answer can be generated, addressing all aspects of the user's request.
## 对 bionic/tests/malloc_stress_test.cpp 的功能分析

这个 C++ 文件 `malloc_stress_test.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是对内存分配器（malloc）进行压力测试。

**功能列举:**

1. **多线程并发压力测试:**  它会创建多个线程 (默认为 256 个)，每个线程都会执行以下操作：
    * 分配一块内存 (4096 字节)。
    * 使用 `memset` 将分配的内存清零。
    * 休眠 1 秒。
    * 释放分配的内存。
2. **循环反复测试:**  这个过程会在一个无限循环中重复进行，持续不断地对内存分配器施加压力。
3. **监控内存使用情况 (Bionic 特有):**  如果定义了 `__BIONIC__` 宏（表示在 Bionic 环境中编译），测试会监控进程的内存使用情况，包括：
    * **RSS (Resident Set Size):** 进程实际使用的物理内存大小。
    * **VSS (Virtual Set Size):** 进程可以访问的虚拟地址空间大小。
    * 它会特别关注与内存分配器相关的内存区域，例如 `[anon:libc_malloc]`, `[anon:scudo:]`, `[anon:GWP-ASan]`。
4. **获取 malloc 统计信息:**  使用 `mallinfo()` 获取内存分配器的统计信息，例如已分配的内存块大小。
5. **日志记录内存分配器统计信息 (Bionic 特有):**  如果定义了 `__BIONIC__` 宏，测试会定期 (每 100 次循环) 调用 `mallopt(M_LOG_STATS, 0)` 将内存分配器的统计信息发送到 Android 的日志系统。
6. **读取并打印内存分配器日志 (Bionic 特有):**  如果定义了 `__BIONIC__` 宏，测试会读取 Android 日志系统中标记为 "scudo" 或 "jemalloc" 的日志消息，并打印出来。这两个标签分别对应 Android 可能使用的两种内存分配器。

**与 Android 功能的关系及举例说明:**

这个测试文件直接关系到 Android 系统的核心功能——内存管理。Android 系统依赖于其 C 库 Bionic 提供的 `malloc` 和 `free` 等函数来进行内存的动态分配和释放。这个压力测试的目标是确保 Bionic 的内存分配器在多线程高并发的情况下能够稳定可靠地工作，防止出现内存泄漏、崩溃等问题。

**举例说明:**

* **Android 应用的创建和销毁:** 当 Android 应用启动时，系统会为其分配内存来加载代码、数据等。应用运行过程中，也需要动态地分配和释放内存来创建对象、处理数据。Bionic 的 `malloc` 和 `free` 直接参与了这个过程。例如，当创建一个 `Bitmap` 对象时，可能会调用 `malloc` 来分配存储像素数据的内存。当 `Bitmap` 对象不再使用时，会调用 `free` 释放这部分内存。
* **Android Framework 服务的运行:**  Android Framework 中许多服务都是用 C++ 编写的，例如 `SurfaceFlinger` (负责屏幕合成) 和 `AudioFlinger` (负责音频处理)。这些服务在运行过程中会频繁地进行内存的分配和释放。这个压力测试可以帮助验证 Bionic 的内存分配器是否能够支撑这些高负载的场景。
* **NDK 开发:** 使用 Android NDK 进行 native 开发时，开发者可以直接调用 Bionic 提供的 `malloc` 和 `free` 函数来管理内存。这个压力测试的结果直接关系到 NDK 开发的程序的稳定性和性能。

**libc 函数的功能实现详解:**

1. **`malloc(size_t size)`:**
   * **功能:** 从堆上分配一块至少 `size` 字节大小的内存块。
   * **实现 (Bionic 中可能使用 Scudo 或 jemalloc):**
     * **Scudo:**  一种安全加固的内存分配器，旨在检测和缓解内存错误，例如堆溢出和 use-after-free。它将堆内存划分为不同的区域，并在元数据中存储分配信息，以便进行安全检查。
     * **jemalloc:** 一种高性能的通用内存分配器，以其低碎片率和良好的多线程性能而闻名。它采用 arenas 的概念来减少线程之间的竞争。
     * **具体实现细节非常复杂，涉及内存管理的数据结构、算法和系统调用。**  Bionic 会根据配置和平台选择使用哪种分配器。
   * **假设输入与输出:**
     * 输入: `size = 1024`
     * 输出: 返回一个指向新分配的 1024 字节内存块的指针。如果分配失败，返回 `NULL`。

2. **`free(void* ptr)`:**
   * **功能:** 释放之前通过 `malloc`, `calloc`, 或 `realloc` 分配的内存块。
   * **实现:**
     * 分配器 (Scudo 或 jemalloc) 根据传入的指针 `ptr` 找到对应的内存块的元数据。
     * 将该内存块标记为未使用，并将其添加到空闲链表中，以便后续的内存分配可以重用这块内存。
     * 可能会进行一些清理工作，例如清除内存内容 (为了安全考虑)。
   * **假设输入与输出:**
     * 输入: 一个通过 `malloc` 返回的有效指针 `ptr`。
     * 输出: 无返回值。 `ptr` 指向的内存块被释放，不能再被访问。

3. **`memset(void* ptr, int value, size_t num)`:**
   * **功能:** 将 `ptr` 指向的内存块的前 `num` 个字节设置为 `value` (转换为 `unsigned char`)。
   * **实现:**  这是一个相对简单的函数，通常会使用汇编级别的优化，以高效地填充内存。它会遍历内存块，逐字节地设置值。
   * **假设输入与输出:**
     * 输入: `ptr` 指向一块已分配的内存，`value = 0`, `num = 4096`
     * 输出: 无返回值。 `ptr` 指向的内存块的前 4096 个字节都被设置为 0。

4. **`sleep(unsigned int seconds)`:**
   * **功能:** 让当前线程休眠指定的秒数。
   * **实现:**  这是一个系统调用，会通知操作系统暂停当前线程的执行，直到指定的时间过去。操作系统会调度其他线程执行。
   * **假设输入与输出:**
     * 输入: `seconds = 1`
     * 输出: 返回实际休眠的秒数 (通常接近输入值)。

5. **`mallinfo()`:**
   * **功能:** 返回一个 `struct mallinfo` 结构体，其中包含了关于内存分配器的各种统计信息，例如已分配的块数、总分配大小、空闲块数等。
   * **实现:**  分配器 (Scudo 或 jemalloc) 维护着这些统计信息。 `mallinfo()` 函数会访问这些内部数据结构并返回。
   * **假设输入与输出:**
     * 输入: 无输入。
     * 输出: 返回一个 `struct mallinfo` 结构体，包含当前的内存分配器状态信息。

6. **`mallopt(int cmd, int value)`:**
   * **功能:** 用于调整内存分配器的行为。
   * **实现:**  不同的 `cmd` 值对应不同的配置选项，分配器会根据 `value` 来修改其内部参数。例如，`M_DECAY_TIME` 可以设置空闲内存返回给操作系统的延迟时间， `M_LOG_STATS` 可以触发统计信息的记录。
   * **假设输入与输出 (针对代码中的使用):**
     * `mallopt(M_DECAY_TIME, 1)`: 设置空闲内存返回给操作系统的延迟时间为 1 秒。
     * `mallopt(M_LOG_STATS, 0)`: 触发内存分配器将统计信息记录到日志。
     * 输出: 返回 0 表示失败，非零表示成功。

**涉及 dynamic linker 的功能:**

虽然这段代码本身并没有显式地调用 `dlopen` 或 `dlsym` 等 dynamic linker 相关的函数，但它 *隐式地* 依赖于 dynamic linker。

* **依赖 `libc.so`:**  代码中使用的 `malloc`, `free`, `memset`, `sleep`, `mallinfo`, `mallopt` 等函数都属于 `libc.so` (Android 上的 Bionic C 库)。当程序启动时，dynamic linker 负责加载 `libc.so` 并将这些函数的地址链接到程序中。

**so 布局样本:**

```
加载地址             权限      映射文件
-------------------  ------  --------------------------------------------
...
0000007744000000-00000077441f5000 r--p  /apex/com.android.runtime/lib64/bionic/libc.so
00000077441f5000-000000774427d000 r-xp  /apex/com.android.runtime/lib64/bionic/libc.so
000000774427d000-00000077442e2000 r--p  /apex/com.android.runtime/lib64/bionic/libc.so
00000077442e2000-00000077442e4000 rw-p  /apex/com.android.runtime/lib64/bionic/libc.so
...
```

* **加载地址:** `libc.so` 被加载到内存中的起始地址。
* **权限:**
    * `r--p`: 可读，不可写，私有 (只对当前进程可见)。 通常是只读的代码段和常量数据段。
    * `r-xp`: 可读，可执行，私有。 通常是可执行的代码段。
    * `rw-p`: 可读，可写，私有。 通常是全局变量和未初始化数据段。
* **映射文件:**  `libc.so` 在文件系统中的路径。

**链接的处理过程:**

1. **程序启动:** 当 `malloc_stress_test` 程序启动时，操作系统会加载程序本身。
2. **dynamic linker 介入:** 操作系统发现程序依赖于共享库 (例如 `libc.so`)，会将控制权交给 dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`)。
3. **查找依赖库:** dynamic linker 会根据程序的依赖关系查找需要的共享库文件 (`libc.so`)。
4. **加载共享库:** dynamic linker 将 `libc.so` 加载到进程的地址空间中。
5. **符号解析 (Symbol Resolution):** dynamic linker 遍历程序的重定位表 (Relocation Table)，找到程序中对 `malloc`, `free` 等外部符号的引用。
6. **地址绑定 (Address Binding):** dynamic linker 在 `libc.so` 的符号表中查找这些符号的地址，并将这些地址写入到程序中相应的内存位置，从而将程序的调用指向 `libc.so` 中对应的函数实现。

**假设输入与输出 (逻辑推理):**

假设我们运行这个测试一段时间后，内存分配器运行良好，没有出现严重的内存泄漏或崩溃。

* **假设输入:** 测试运行了 1000 个循环。
* **可能输出:**
    * 打印出 "Pass 0" 到 "Pass 999"。
    * 打印出每次循环的 RSS、VSS 以及 `mallinfo()` 返回的已分配内存大小，这些值可能会在一定范围内波动，但不会持续显著增长。
    * 每 100 次循环会打印出 "Log stats:"，后面跟着从 Android 日志系统中读取到的 "scudo" 或 "jemalloc" 的统计信息。
    * 如果内存分配器出现问题，可能会打印 "Failed to allocate memory" 并调用 `_exit(1)` 终止程序。

**用户或编程常见的使用错误举例:**

1. **内存泄漏:**  如果在一个循环中分配了内存但忘记释放，会导致内存占用持续增长，最终可能导致程序崩溃或系统性能下降。
   ```c++
   // 错误示例
   void* leak_buf = malloc(4096);
   // 忘记 free(leak_buf);
   ```

2. **重复释放 (Double Free):** 释放已经被释放过的内存块，会导致内存分配器的内部数据结构损坏，引发崩溃。
   ```c++
   void* buf = malloc(4096);
   free(buf);
   free(buf); // 错误：重复释放
   ```

3. **释放未分配的内存:** 尝试释放一个从未通过 `malloc` 等函数分配的内存地址，也会导致崩溃。
   ```c++
   int x;
   free(&x); // 错误：释放栈上的变量
   ```

4. **使用已释放的内存 (Use-After-Free):** 在内存被释放后继续访问该内存，会导致未定义的行为，可能崩溃，也可能产生难以追踪的 bug。
   ```c++
   void* buf = malloc(4096);
   memset(buf, 0, 4096);
   free(buf);
   memset(buf, 1, 4096); // 错误：使用已释放的内存
   ```

5. **分配的内存大小不足:**  分配的内存空间小于实际需要存储的数据大小，会导致缓冲区溢出。
   ```c++
   char* str = (char*)malloc(10);
   strcpy(str, "This is a long string"); // 错误：缓冲区溢出
   ```

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

1. **Android Framework 调用:**
   * 许多 Framework 服务 (例如 `SurfaceFlinger`, `AudioFlinger`) 内部使用 C++ 编写，并直接调用 Bionic 的 `malloc` 和 `free`。
   * 当 Framework 需要分配内存时 (例如，分配一块 buffer 来存储图形数据或音频数据)，最终会调用到 Bionic 的 `malloc`。

2. **NDK 调用:**
   * 使用 NDK 开发的 native 代码可以直接调用 Bionic 的 C 库函数。
   * 例如，一个 NDK 应用需要创建一个大的数据结构，可以使用 `malloc` 分配内存。

**Frida Hook 示例:**

以下是一些使用 Frida hook 来观察 `malloc` 和 `free` 调用的示例：

```javascript
// Hook malloc
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
  onEnter: function(args) {
    this.size = args[0].toInt();
    console.log("malloc called with size: " + this.size);
  },
  onLeave: function(retval) {
    if (retval.isNull()) {
      console.log("malloc failed");
    } else {
      console.log("malloc returned: " + retval);
    }
  }
});

// Hook free
Interceptor.attach(Module.findExportByName("libc.so", "free"), {
  onEnter: function(args) {
    this.ptr = args[0];
    console.log("free called with pointer: " + this.ptr);
  }
});

// Hook Android log function (例如 __android_log_print)
Interceptor.attach(Module.findExportByName("liblog.so", "__android_log_print"), {
  onEnter: function(args) {
    var tag = Memory.readCString(args[2]);
    var message = Memory.readCString(args[3]);
    console.log("android_log_print - Tag: " + tag + ", Message: " + message);
  }
});

// Hook mallopt
Interceptor.attach(Module.findExportByName("libc.so", "mallopt"), {
  onEnter: function(args) {
    var cmd = args[0].toInt();
    var value = args[1].toInt();
    console.log("mallopt called with cmd: " + cmd + ", value: " + value);
  }
});
```

**调试步骤 (使用 Frida):**

1. **准备环境:** 确保你的 Android 设备已 root，并安装了 Frida 服务端。在你的 PC 上安装了 Frida 客户端。
2. **找到目标进程:** 确定你要监控的进程的 PID。这可以是你的 NDK 应用的进程，或者一个 Framework 服务的进程。
3. **运行 Frida 脚本:** 使用 Frida 客户端连接到目标进程，并运行上面的 JavaScript 脚本。例如：
   ```bash
   frida -U -f <package_name> -l your_script.js  // 附加到新启动的应用
   frida -U <process_name_or_pid> -l your_script.js // 附加到正在运行的进程
   ```
4. **观察输出:**  当目标进程执行到 `malloc`, `free`, `__android_log_print`, 或 `mallopt` 函数时，Frida 脚本会拦截这些调用，并打印出相关的参数和返回值，帮助你理解内存分配的流程和日志信息。

通过这些 Frida hook，你可以观察到 Android Framework 或 NDK 应用在运行时如何调用 Bionic 的内存管理函数，以及内存分配器是如何工作的，从而更深入地理解这个压力测试的意义和作用。

### 提示词
```
这是目录为bionic/tests/malloc_stress_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <inttypes.h>
#include <malloc.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <thread>
#include <vector>

#if defined(__BIONIC__)
#include <meminfo/procmeminfo.h>
#include <procinfo/process_map.h>

#include <log/log.h>
#include <log/log_read.h>
#endif

#if defined(__BIONIC__)
static void PrintLogStats(uint64_t& last_time) {
  logger_list* logger =
      android_logger_list_open(android_name_to_log_id("main"), ANDROID_LOG_NONBLOCK, 0, getpid());
  if (logger == nullptr) {
    printf("Failed to open log for main\n");
    return;
  }

  uint64_t last_message_time = last_time;
  while (true) {
    log_msg entry;
    ssize_t retval = android_logger_list_read(logger, &entry);
    if (retval == 0) {
      break;
    }
    if (retval < 0) {
      if (retval == -EINTR) {
        continue;
      }
      // EAGAIN means there is nothing left to read when ANDROID_LOG_NONBLOCK is set.
      if (retval != -EAGAIN) {
        printf("Failed to read log entry: %s\n", strerrordesc_np(retval));
      }
      break;
    }
    if (entry.msg() == nullptr) {
      continue;
    }
    // Only print allocator tagged log entries.
    std::string_view tag(entry.msg() + 1);
    if (tag != "scudo" && tag != "jemalloc") {
      continue;
    }
    if (entry.nsec() > last_time) {
      printf("  %s\n", &tag.back() + 2);
      // Only update the last time outside this loop just in case two or more
      // messages have the same timestamp.
      last_message_time = entry.nsec();
    }
  }
  android_logger_list_close(logger);
  last_time = last_message_time;
}
#endif

TEST(malloc_stress, multiple_threads_forever) {
  constexpr size_t kMaxThreads = 256;
  constexpr size_t kAllocSize = 4096;
#if defined(__BIONIC__)
  uint64_t rss_min = UINT64_MAX;
  uint64_t rss_max = 0;
  uint64_t vss_min = UINT64_MAX;
  uint64_t vss_max = 0;
  ASSERT_EQ(1, mallopt(M_DECAY_TIME, 1));
#endif
  uint64_t mallinfo_min = UINT64_MAX;
  uint64_t mallinfo_max = 0;

  uint64_t last_message_time = 0;
  for (size_t i = 0; ; i++) {
    printf("Pass %zu\n", i);

    std::vector<std::thread*> threads;
    for (size_t i = 0; i < kMaxThreads; i++) {
      threads.push_back(new std::thread([]() {
        void* buf = malloc(4096);
        if (buf == nullptr) {
          printf("Failed to allocate memory\n");
          _exit(1);
        }
        memset(buf, 0, kAllocSize);
        sleep(1);
        free(buf);
      }));
    }

    for (auto thread : threads) {
      thread->join();
      delete thread;
    }
    threads.clear();

#if defined(__BIONIC__)
    android::meminfo::ProcMemInfo proc_mem(getpid());
    const std::vector<android::meminfo::Vma>& maps = proc_mem.MapsWithoutUsageStats();
    uint64_t rss_bytes = 0;
    uint64_t vss_bytes = 0;
    for (auto& vma : maps) {
      if (vma.name == "[anon:libc_malloc]" || vma.name.starts_with("[anon:scudo:") ||
          vma.name.starts_with("[anon:GWP-ASan")) {
        android::meminfo::Vma update_vma(vma);
        ASSERT_TRUE(proc_mem.FillInVmaStats(update_vma));
        rss_bytes += update_vma.usage.rss;
        vss_bytes += update_vma.usage.vss;
      }
    }
    if (rss_bytes < rss_min) {
      rss_min = rss_bytes;
    }
    if (rss_bytes > rss_max) {
      rss_max = rss_bytes;
    }
    if (vss_bytes < vss_min) {
      vss_min = vss_bytes;
    }
    if (vss_bytes > vss_max) {
      vss_max = vss_bytes;
    }
    printf("RSS %" PRIu64 " %0.2fMB\n", rss_bytes, rss_bytes / (1024.0 * 1024.0));
    printf("  Min %" PRIu64 " %0.2fMB\n", rss_min, rss_min / (1024.0 * 1024.0));
    printf("  Max %" PRIu64 " %0.2fMB\n", rss_max, rss_max / (1024.0 * 1024.0));
    printf("VSS %" PRIu64 " %0.2f MB\n", vss_bytes, vss_bytes / (1024.0 * 1024.0));
    printf("  Min %" PRIu64 " %0.2fMB\n", vss_min, vss_min / (1024.0 * 1024.0));
    printf("  Max %" PRIu64 " %0.2fMB\n", vss_max, vss_max / (1024.0 * 1024.0));
#endif

    size_t mallinfo_bytes = mallinfo().uordblks;
    if (mallinfo_bytes < mallinfo_min) {
      mallinfo_min = mallinfo_bytes;
    }
    if (mallinfo_bytes > mallinfo_max) {
      mallinfo_max = mallinfo_bytes;
    }
    printf("Allocated memory %zu %0.2fMB\n", mallinfo_bytes, mallinfo_bytes / (1024.0 * 1024.0));
    printf("  Min %" PRIu64 " %0.2fMB\n", mallinfo_min, mallinfo_min / (1024.0 * 1024.0));
    printf("  Max %" PRIu64 " %0.2fMB\n", mallinfo_max, mallinfo_max / (1024.0 * 1024.0));

#if defined(__BIONIC__)
    if (((i + 1) % 100) == 0) {
      // Send native allocator stats to the log
      mallopt(M_LOG_STATS, 0);

      printf("Log stats:\n");
      PrintLogStats(last_message_time);
    }
#endif
  }
}
```