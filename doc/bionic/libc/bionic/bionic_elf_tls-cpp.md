Response:
Let's break down the thought process for answering the request about `bionic_elf_tls.cpp`.

**1. Understanding the Core Task:**

The request asks for a comprehensive analysis of the `bionic_elf_tls.cpp` file. This means going beyond simply listing functions and requires understanding their purpose, interaction with the Android ecosystem (especially the dynamic linker), and potential issues.

**2. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code, looking for key terms and patterns:

* **TLS:**  This is obviously the central theme. Recognize that TLS stands for Thread-Local Storage.
* **`__tls_get_addr`:**  A very important function for accessing TLS variables.
* **`TlsSegment`, `TlsDtv`, `TlsModule`:**  Data structures related to TLS management.
* **`StaticTlsLayout`:** Hints at static allocation of TLS.
* **`dynamic linker`:** Explicitly mentioned in the request and relevant to TLS loading.
* **`bionic_tcb`:**  The Thread Control Block, crucial for per-thread data.
* **`pthread_internal.h`:**  Indicates involvement with thread management.
* **`async_safe`:**  Suggests handling of signals and concurrency.
* **`ScopedRWLock`, `ScopedSignalBlocker`:**  Concurrency control mechanisms.
* **`__libc_shared_globals()`:** Access to global state in `libc`.

**3. Categorizing Functionality:**

Based on the initial scan, start grouping the code into functional areas:

* **TLS Segment Handling:**  Functions like `__bionic_get_tls_segment`, `__bionic_check_tls_align`. These deal with parsing ELF headers to find TLS information.
* **Static TLS Layout:** The `StaticTlsLayout` class and its methods (`reserve_exe_segment_and_tcb`, `reserve_bionic_tls`, `reserve`, etc.) are responsible for managing the layout of statically allocated TLS.
* **Dynamic TLS Management:**  Functions involving `TlsDtv`, allocation (`calculate_new_dtv_count`), and the slow path of `__tls_get_addr`.
* **Accessing TLS Variables:**  The core function `TLS_GET_ADDR` and its fast/slow paths.
* **Initialization and Cleanup:** `__init_static_tls`, `__free_dynamic_tls`, `__notify_thread_exit_callbacks`.
* **Helper Functions:** `align_checked`, `dtv_size_in_bytes`.

**4. Detailed Analysis of Key Functions:**

Now, dive deeper into the most important functions:

* **`__bionic_get_tls_segment`:** Understand how it iterates through program headers to find the `PT_TLS` entry and extracts relevant information (size, alignment, address).
* **`StaticTlsLayout::reserve_exe_segment_and_tcb`:**  This is complex. Recognize the architecture-specific handling (especially ARM's "variant 1" layout) and the need to align the executable's TLS segment correctly relative to the thread pointer.
* **`TLS_GET_ADDR`:** Analyze the fast path (checking the generation counter) and the slow path (locking, DTV update, allocation).
* **`update_tls_dtv`:**  Understand how the Dynamic Thread Vector (DTV) is managed, expanded, and how module pointers are updated.
* **`__init_static_tls`:**  How the initial values of static TLS variables are copied.
* **`__free_dynamic_tls`:**  The process of freeing dynamically allocated TLS and DTVs.

**5. Relating to Android Functionality:**

Think about how TLS is used in Android:

* **NDK:** Native code relies heavily on TLS for thread-local variables.
* **Android Framework:**  Although less direct, some framework components might use native libraries that use TLS.
* **Dynamic Linking:** The dynamic linker is responsible for loading libraries and setting up their TLS segments.

Provide concrete examples of NDK usage and how the linker is involved.

**6. Dynamic Linker Aspects:**

Focus on the interaction with the dynamic linker:

* **ELF Structure:** Explain how the `PT_TLS` program header provides the necessary information.
* **SO Layout:**  Create a simplified example SO layout showing the TLS segment.
* **Linking Process:** Describe how the linker allocates space and initializes the static TLS during library loading.

**7. Logic and Assumptions:**

When explaining the fast and slow paths of `TLS_GET_ADDR`, explicitly state the assumptions made for the fast path (generation counter match, module pointer not null).

**8. Common Errors:**

Consider what mistakes developers might make when working with TLS:

* **Incorrect Initialization:** Not properly initializing TLS variables.
* **Race Conditions (if manual management):** Although `bionic` handles much of this, understanding the concept is important.
* **Exceeding Static TLS Limits:** Though less common now with dynamic TLS.

**9. Android Framework/NDK Entry Point and Frida Hook:**

Trace how an NDK call could lead to TLS access and then to the `bionic_elf_tls.cpp` code. Provide a practical Frida hook example targeting `TLS_GET_ADDR`.

**10. Structure and Language:**

Organize the answer logically with clear headings and subheadings. Use precise language, explaining technical terms where necessary. Ensure the response is in Chinese as requested.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Focus too much on individual function implementation details.
* **Correction:** Shift focus to the overall *purpose* of the file and how its components work *together*.
* **Initial thought:**  Not enough emphasis on the dynamic linker.
* **Correction:**  Add a dedicated section explaining the dynamic linker's role and provide an SO layout example.
* **Initial thought:**  Frida hook example too complex.
* **Correction:** Simplify the Frida hook to target the core function (`TLS_GET_ADDR`) and demonstrate basic parameter and return value inspection.

By following these steps, iterating through the code, and considering the broader context of Android and dynamic linking, a comprehensive and accurate answer can be constructed. The process involves both understanding the code's mechanics and its role within the larger system.
这是一个关于 Android Bionic 库中处理线程局部存储 (Thread-Local Storage, TLS) 的源代码文件。它负责管理和访问线程私有的数据，这是多线程编程中非常重要的一个概念。

下面我们详细列举它的功能，并结合 Android 的特性进行说明：

**主要功能：**

1. **定义 TLS 相关的数据结构：**  例如 `TlsSegment`（描述 TLS 段的信息），`TlsDtv` (Thread-Local Storage Data Vector，用于存储动态加载的 TLS 模块的地址)，`TlsModule` (描述 TLS 模块的信息) 以及 `StaticTlsLayout` (用于管理静态 TLS 的布局)。

2. **获取 TLS 段信息 (`__bionic_get_tls_segment`)：**  遍历 ELF 文件的程序头表 (Program Header Table) 找到类型为 `PT_TLS` 的段，提取其大小、对齐方式、初始数据地址和大小等信息。这在加载可执行文件和共享库时至关重要，动态链接器需要知道每个模块的 TLS 段在哪里以及如何初始化。

   * **Android 举例：** 当 `dalvikvm` 或 `art` 虚拟机启动一个新的 Java 线程时，该线程可能需要加载一些 native 库。动态链接器在加载这些库时会调用此函数来获取库的 TLS 段信息，以便为该线程分配和初始化 TLS 空间。

3. **检查 TLS 对齐 (`__bionic_check_tls_align`)：** 确保 TLS 段的对齐方式是 2 的幂次方。这是 TLS 实现的一个基本要求，有助于提高访问效率。

4. **管理静态 TLS 布局 (`StaticTlsLayout` 类)：**  在程序启动时，会预先分配一块静态 TLS 区域。`StaticTlsLayout` 负责规划这块区域，包括分配 Bionic TCB (Thread Control Block，Bionic 中用于管理线程信息的结构体) 的空间、可执行文件的 TLS 段空间以及其他静态 TLS 模块的空间。

   * **`reserve_exe_segment_and_tcb`：**  为可执行文件的 TLS 段和 Bionic TCB 分配空间，并确保它们之间的相对偏移符合架构 ABI 的规定。不同架构 (如 ARM, x86) 对 TLS 的布局有不同的约定。
   * **`reserve_bionic_tls`：** 为 Bionic 库自身的 TLS 数据分配空间。
   * **`reserve`：**  在静态 TLS 区域中预留指定大小和对齐方式的内存块。
   * **`align_cursor`：**  调整静态 TLS 分配的游标，以满足特定的对齐要求。

   * **Android 举例：** 当 `zygote` 进程 fork 出新的应用进程时，新进程会继承 `zygote` 的内存布局，包括静态 TLS 区域。`StaticTlsLayout` 确保了每个进程都有正确的静态 TLS 设置。

5. **初始化静态 TLS (`__init_static_tls`)：**  将每个静态 TLS 模块的初始化数据从 ELF 文件中复制到预先分配的静态 TLS 区域。这发生在线程创建初期。

   * **实现细节：**  它会遍历 `tls_modules` 列表，该列表包含了所有已加载模块的 TLS 信息。对于静态 TLS 模块，它会使用 `memcpy` 将其 `init_ptr` 指向的数据复制到 `static_tls + module.static_offset` 的位置。

6. **计算动态 TLS 数据向量 (DTV) 的大小 (`calculate_new_dtv_count`)：**  DTV 是一个数组，用于存储每个动态加载的 TLS 模块的地址。这个函数计算需要分配的 DTV 槽的数量，并尝试将 DTV 的总大小向上圆整到 2 的幂次方，以优化内存使用。

7. **更新线程的 DTV (`update_tls_dtv`)：**  当加载新的共享库，并且该库有 TLS 数据时，需要更新线程的 DTV。如果当前的 DTV 容量不足，会分配一个新的更大的 DTV，并将旧的 DTV 链接到新 DTV 的 `next` 指针，形成一个链表。

   * **实现细节：**
      * 检查 DTV 的 `generation` 字段是否与全局的 `tls_modules.generation` 一致，如果一致则说明 DTV 是最新的，无需更新。
      * 如果需要更新，并且当前 DTV 容量不足以容纳新的模块，则分配一个更大的 DTV，并将旧的数据复制过去。
      * 遍历所有已加载的模块，如果模块是静态的，则将静态 TLS 中的地址写入 DTV；如果是动态的，并且是第一次被访问，则将 DTV 中的对应槽设置为 `nullptr`。对于已经被卸载的模块，会调用注册的析构回调函数 (`modules.on_destruction_cb`) 并释放其 TLS 内存。

8. **获取 TLS 变量地址 (`TLS_GET_ADDR`)：** 这是访问 TLS 变量的核心函数。

   * **快速路径：** 首先检查全局的 TLS 代数 (`__libc_tls_generation_copy`) 是否与当前线程 DTV 的代数 (`dtv->generation`) 一致，并且对应的模块指针不为空。如果条件满足，则可以直接计算出 TLS 变量的地址。这种方式非常高效，因为它避免了加锁和复杂的查找。
   * **慢速路径 (`tls_get_addr_slow_path`)：**  如果快速路径失败，则需要进入慢速路径。慢速路径会：
      * 加锁 `TlsModules` 以确保线程安全。
      * 调用 `update_tls_dtv` 更新 DTV。
      * 查找或分配动态 TLS 模块的内存。如果该模块的 TLS 内存尚未分配，则会分配新的内存块，并从 ELF 文件中复制初始化数据。
      * 返回 TLS 变量的实际地址。

   * **Android 举例：** 当 native 代码中访问一个 `__thread` 修饰的全局变量时，编译器会生成对 `__tls_get_addr` (在 ARM64 上可能是通过 TLSDESC 机制，但最终也会调用到类似的功能) 的调用。

9. **释放动态 TLS (`__free_dynamic_tls`)：**  在线程退出时，需要释放该线程分配的动态 TLS 内存和 DTV 链表。

   * **实现细节：**
      * 遍历当前 DTV，释放其中指向的动态分配的 TLS 模块内存。会调用注册的析构回调函数。
      * 遍历 DTV 链表，释放所有分配的 DTV 对象。
      * 清空 TCB 中的 DTV 槽。

10. **通知线程退出回调 (`__notify_thread_exit_callbacks`)：**  在线程退出时，执行所有通过 `pthread_key_create` 注册的析构函数，以及通过 Bionic 自身机制注册的线程退出回调。

**与 Android 功能的关系和举例：**

* **NDK 开发：** NDK 开发中广泛使用 `__thread` 关键字来声明线程局部变量。当 native 代码访问这些变量时，最终会调用到 `TLS_GET_ADDR` 来获取变量的地址。
   ```c++
   // NDK 代码示例
   #include <pthread.h>
   #include <stdio.h>

   __thread int my_thread_local_variable = 0;

   void* thread_function(void* arg) {
       my_thread_local_variable++;
       printf("Thread ID: %lu, my_thread_local_variable: %d\n", pthread_self(), my_thread_local_variable);
       return NULL;
   }

   int main() {
       pthread_t thread1, thread2;
       pthread_create(&thread1, NULL, thread_function, NULL);
       pthread_create(&thread2, NULL, thread_function, NULL);
       pthread_join(thread1, NULL);
       pthread_join(thread2, NULL);
       return 0;
   }
   ```
   在这个例子中，`my_thread_local_variable` 是一个线程局部变量。每个线程都有自己独立的 `my_thread_local_variable` 副本。当线程执行 `my_thread_local_variable++` 时，它操作的是自己线程的副本，而不会影响其他线程。`bionic_elf_tls.cpp` 中的代码负责确保每个线程都能正确访问到自己的 TLS 变量。

* **动态链接器 (`linker`)：**  动态链接器在加载共享库时，会读取 ELF 文件的 `PT_TLS` 段信息，并调用 `bionic_elf_tls.cpp` 中的函数来分配和初始化 TLS 空间。`linker` 负责设置初始的静态 TLS 布局。

* **`libpthread`：** `libpthread` 库依赖于 Bionic 的 TLS 实现来管理线程的私有数据，例如线程特定的错误码。

**详细解释 libc 函数的功能是如何实现的：**

* **`memcpy`：**  用于在 `__init_static_tls` 中将 TLS 模块的初始化数据复制到静态 TLS 区域，以及在 `update_tls_dtv` 中复制旧的 DTV 数据到新的 DTV。这是一个标准的 C 库函数，通常通过优化的汇编代码实现，用于高效地复制内存块。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

**SO 布局样本：**

假设我们有一个名为 `libexample.so` 的共享库，它包含一个 TLS 变量。其 ELF 文件结构可能包含以下部分：

```
ELF Header
Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSize MemSize Flags Align
  LOAD           0x000000 0xXXXXXXXXXXXX0000 0xXXXXXXXXXXXX0000 0x001000 0x001000 R E   0x1000
  LOAD           0x001000 0xXXXXXXXXXXXX1000 0xXXXXXXXXXXXX1000 0x000100 0x000100 RW    0x1000
  PT_TLS         0x001100 0xXXXXXXXXXXXX1100 0xXXXXXXXXXXXX1100 0x000020 0x000040 R     0x8  // TLS 段
Dynamic Section
Symbol Table
...
```

* **`PT_TLS` 段：**  这个程序头指示了 TLS 段的存在。
    * `p_offset`:  TLS 数据在文件中的偏移量 (0x001100)。
    * `p_vaddr`:  TLS 数据在内存中的虚拟地址 (0xXXXXXXXXXXXX1100)。
    * `p_filesz`:  TLS 数据的初始大小 (0x20 字节)。
    * `p_memsz`:  TLS 段在内存中需要分配的大小 (0x40 字节，可能包含未初始化的部分)。
    * `p_align`:  TLS 段的对齐要求 (0x8 字节)。

**链接的处理过程：**

1. **加载共享库：** 当 Android 系统加载 `libexample.so` 时，动态链接器会解析其 ELF 文件头和程序头表。
2. **识别 TLS 段：** 动态链接器会找到 `PT_TLS` 类型的程序头，并从中提取 TLS 段的相关信息 (大小、对齐、初始数据等)。
3. **分配 TLS 空间：**
   * **静态 TLS：**  如果这是主可执行文件或在程序启动早期加载的库，其 TLS 数据可能会被分配到静态 TLS 区域。`StaticTlsLayout` 会根据 `PT_TLS` 的信息预留空间。
   * **动态 TLS：**  对于后续动态加载的库，其 TLS 数据会在线程首次访问该库的 TLS 变量时动态分配。
4. **初始化 TLS 数据：** 动态链接器会根据 `PT_TLS` 中的 `p_offset` 和 `p_filesz`，将文件中的 TLS 初始数据复制到分配的 TLS 内存中。
5. **更新 DTV：**  动态链接器会更新当前线程的 DTV，将 `libexample.so` 的 TLS 内存地址存储到 DTV 的相应槽位中。
6. **符号重定位：**  如果 `libexample.so` 中有引用其他库的 TLS 变量，链接器会进行相应的重定位操作。

**如果做了逻辑推理，请给出假设输入与输出：**

**假设输入 `TLS_GET_ADDR`：**

* `ti->module_id`:  表示要访问的 TLS 变量所属的模块 ID。假设为模块 2。
* `ti->offset`:  表示 TLS 变量在该模块 TLS 段内的偏移量。假设为 0x10。
* 当前线程的 DTV (`__get_tcb_dtv(__get_bionic_tcb())`) 的 `generation` 与全局的 `__libc_tls_generation_copy` 相等。
* DTV 中模块 2 的指针 (`dtv->modules[2]`) 指向有效的 TLS 内存地址，假设为 `0xAAAAABBBBC000`。

**输出：**

`TLS_GET_ADDR` 将返回 TLS 变量的实际内存地址：`0xAAAAABBBBC000 + 0x10 + TLS_DTV_OFFSET`。 `TLS_DTV_OFFSET` 通常为 0，因此结果为 `0xAAAAABBBBC010`。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **未初始化 TLS 变量：**  与普通全局变量类似，如果未显式初始化 `__thread` 变量，其初始值是不确定的。依赖未初始化的 TLS 变量会导致程序行为不可预测。

   ```c++
   __thread int my_uninitialized_tls_var; // 未初始化

   void some_function() {
       my_uninitialized_tls_var++; // 首次使用时值不确定
   }
   ```

2. **在错误的生命周期访问 TLS 变量：**  虽然 TLS 变量与线程的生命周期绑定，但在某些特殊情况下，例如使用线程池时，如果线程被复用，需要注意 TLS 变量的状态。如果期望 TLS 变量在每次任务开始时都是初始状态，则需要进行显式重置。

3. **在静态初始化中使用 TLS 变量：**  在动态链接库的全局对象的静态构造函数或全局变量的初始化器中访问 TLS 变量可能会导致问题，因为此时 TLS 可能尚未完全初始化。

   ```c++
   // libexample.so
   #include <pthread.h>

   __thread int my_tls_var = 10;
   int global_var = my_tls_var; // 静态初始化中访问 TLS 变量，可能出错
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `bionic_elf_tls.cpp` 的路径：**

1. **Android Framework 代码 (Java)：**  例如，一个 Activity 或 Service 创建了一个新的 Java 线程。
2. **`java.lang.Thread` (Java)：**  Java 线程的创建最终会调用到 native 方法。
3. **`pthread_create` (Native):**  `java.lang.Thread` 的 native 实现通常会使用 POSIX 线程 API `pthread_create` 来创建底层的操作系统线程。
4. **Bionic `pthread_create` 实现：**  Android 的 `pthread_create` 实现位于 Bionic 库中。
5. **TLS 初始化：** 在新线程创建的过程中，Bionic 的 `pthread_create` 实现会负责初始化该线程的 TLS。这包括分配 TLS 空间、设置线程控制块 (TCB) 中的 TLS 指针等。
6. **加载 native 库 (如果需要)：** 如果新创建的线程需要执行 native 代码，动态链接器会加载相关的共享库。
7. **访问 `__thread` 变量 (NDK):**  当 NDK 代码中访问 `__thread` 变量时，编译器会生成对 `TLS_GET_ADDR` 的调用。
8. **`TLS_GET_ADDR` 执行：**  `TLS_GET_ADDR` 函数的实现就在 `bionic_elf_tls.cpp` 中。

**NDK 到 `bionic_elf_tls.cpp` 的路径：**

1. **NDK 代码使用 `__thread`：**  NDK 开发者在 native 代码中使用 `__thread` 关键字声明线程局部变量。
2. **编译器生成代码：**  编译器会将对 `__thread` 变量的访问转换为对 `TLS_GET_ADDR` (或其平台特定的别名) 的函数调用。
3. **动态链接：** 当包含这些 `__thread` 变量的共享库被加载时，动态链接器会处理其 TLS 段。
4. **运行时访问：** 当程序执行到访问 `__thread` 变量的代码时，会调用 `TLS_GET_ADDR`。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `TLS_GET_ADDR` 函数调用的示例：

```javascript
// Frida 脚本

// 获取 TLS_GET_ADDR 函数的地址 (需要根据目标进程的 libc.so 地址调整)
const tlsGetAddrPtr = Module.findExportByName("libc.so", "__tls_get_addr");
if (!tlsGetAddrPtr) {
  console.error("找不到 __tls_get_addr 函数");
} else {
  console.log("找到 __tls_get_addr 函数，地址:", tlsGetAddrPtr);

  Interceptor.attach(tlsGetAddrPtr, {
    onEnter: function (args) {
      console.log("调用 __tls_get_addr");
      const tiPtr = ptr(args[0]);
      const moduleId = tiPtr.readU32();
      const offset = tiPtr.add(4).readU32();
      console.log("  TlsIndex:");
      console.log("    module_id:", moduleId);
      console.log("    offset:", offset);
    },
    onLeave: function (retval) {
      console.log("__tls_get_addr 返回值:", retval);
    },
  });
}
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `hook_tls_get_addr.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_tls_get_addr.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <process_name_or_pid> -l hook_tls_get_addr.js
   ```
3. 当目标进程执行到访问 `__thread` 变量的代码时，Frida 会拦截对 `__tls_get_addr` 的调用，并打印出 `TlsIndex` 的信息 (模块 ID 和偏移量) 以及函数的返回值 (TLS 变量的地址)。

**注意：**

* 函数名在不同的 Android 版本和架构上可能略有不同 (例如，在 32 位 x86 上可能是 `___tls_get_addr`)。你需要根据实际情况调整 Frida 脚本。
* `Module.findExportByName` 的第一个参数 `"libc.so"` 可能需要根据目标进程实际加载的 C 库名称进行调整。
* Hook 底层函数需要 root 权限或使用特定的 Frida 配置。

通过 Frida Hook，你可以动态地观察 `TLS_GET_ADDR` 的调用过程，了解哪些模块正在访问 TLS 变量，以及访问的偏移量是多少，从而更好地理解 Android TLS 的工作原理。

Prompt: 
```
这是目录为bionic/libc/bionic/bionic_elf_tls.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "private/bionic_elf_tls.h"

#include <async_safe/CHECK.h>
#include <async_safe/log.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

#include "platform/bionic/macros.h"
#include "platform/bionic/page.h"
#include "private/ScopedRWLock.h"
#include "private/ScopedSignalBlocker.h"
#include "private/bionic_globals.h"
#include "private/bionic_tls.h"
#include "pthread_internal.h"

// Every call to __tls_get_addr needs to check the generation counter, so
// accesses to the counter need to be as fast as possible. Keep a copy of it in
// a hidden variable, which can be accessed without using the GOT. The linker
// will update this variable when it updates its counter.
//
// To allow the linker to update this variable, libc.so's constructor passes its
// address to the linker. To accommodate a possible __tls_get_addr call before
// libc.so's constructor, this local copy is initialized to SIZE_MAX, forcing
// __tls_get_addr to initially use the slow path.
__LIBC_HIDDEN__ _Atomic(size_t) __libc_tls_generation_copy = SIZE_MAX;

// Search for a TLS segment in the given phdr table. Returns true if it has a
// TLS segment and false otherwise.
bool __bionic_get_tls_segment(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                              ElfW(Addr) load_bias, TlsSegment* out) {
  for (size_t i = 0; i < phdr_count; ++i) {
    const ElfW(Phdr)& phdr = phdr_table[i];
    if (phdr.p_type == PT_TLS) {
      *out = TlsSegment{
          .aligned_size =
              TlsAlignedSize{
                  .size = phdr.p_memsz,
                  .align =
                      TlsAlign{
                          .value = phdr.p_align ?: 1,  // 0 means "no alignment requirement"
                          .skew = phdr.p_vaddr % MAX(1, phdr.p_align),
                      },
              },
          .init_ptr = reinterpret_cast<void*>(load_bias + phdr.p_vaddr),
          .init_size = phdr.p_filesz,
      };
      return true;
    }
  }
  return false;
}

// Return true if the alignment of a TLS segment is a valid power-of-two.
bool __bionic_check_tls_align(size_t align) {
  // Note: The size does not need to be a multiple of the alignment. With ld.bfd
  // (or after using binutils' strip), the TLS segment's size isn't rounded up.
  return powerof2(align);
}

static void static_tls_layout_overflow() {
  async_safe_fatal("error: TLS segments in static TLS overflowed");
}

static size_t align_checked(size_t value, TlsAlign tls_align) {
  const size_t align = tls_align.value;
  const size_t skew = tls_align.skew;
  CHECK(align != 0 && powerof2(align + 0) && skew < align);
  const size_t result = ((value - skew + align - 1) & ~(align - 1)) + skew;
  if (result < value) static_tls_layout_overflow();
  return result;
}

size_t StaticTlsLayout::offset_thread_pointer() const {
  return offset_bionic_tcb_ + (-MIN_TLS_SLOT * sizeof(void*));
}

// Allocates the Bionic TCB and the executable's TLS segment in the static TLS
// layout, satisfying alignment requirements for both.
//
// For an executable's TLS accesses (using the LocalExec model), the static
// linker bakes TLS offsets directly into the .text section, so the loader must
// place the executable segment at the same offset relative to the TP.
// Similarly, the Bionic TLS slots (bionic_tcb) must also be allocated at the
// correct offset relative to the TP.
//
// Returns the offset of the executable's TLS segment.
//
// Note: This function has unit tests, but they are in bionic-unit-tests-static,
// not bionic-unit-tests.
size_t StaticTlsLayout::reserve_exe_segment_and_tcb(const TlsSegment* seg,
                                                    const char* progname __attribute__((unused))) {
  // Special case: if the executable has no TLS segment, then just allocate a
  // TCB and skip the minimum alignment check on ARM.
  if (seg == nullptr) {
    offset_bionic_tcb_ = reserve_type<bionic_tcb>();
    return 0;
  }

#if defined(__arm__) || defined(__aarch64__)
  // ARM uses a "variant 1" TLS layout. The ABI specifies that the TP points at
  // a 2-word TCB, followed by the executable's segment. In practice, libc
  // implementations actually allocate a larger TCB at negative offsets from the
  // TP.
  //
  // Historically, Bionic allocated an 8-word TCB starting at TP+0, so to keep
  // the executable's TLS segment from overlapping the last 6 slots, Bionic
  // requires that executables have an 8-word PT_TLS alignment to ensure that
  // the TCB fits in the alignment padding, which it accomplishes using
  // crtbegin.c. Bionic uses negative offsets for new TLS slots to avoid this
  // problem.

  static_assert(MIN_TLS_SLOT <= 0 && MAX_TLS_SLOT >= 1);
  static_assert(sizeof(bionic_tcb) == (MAX_TLS_SLOT - MIN_TLS_SLOT + 1) * sizeof(void*));
  static_assert(alignof(bionic_tcb) == sizeof(void*));
  const size_t max_align = MAX(alignof(bionic_tcb), seg->aligned_size.align.value);

  // Allocate the TCB first. Split it into negative and non-negative slots and
  // ensure that TP (i.e. the first non-negative slot) is aligned to max_align.
  const size_t tcb_size_pre = -MIN_TLS_SLOT * sizeof(void*);
  const size_t tcb_size_post = (MAX_TLS_SLOT + 1) * sizeof(void*);
  const auto pair =
      reserve_tp_pair(TlsAlignedSize{.size = tcb_size_pre},
                      TlsAlignedSize{.size = tcb_size_post, .align = TlsAlign{.value = max_align}});
  offset_bionic_tcb_ = pair.before;
  const size_t offset_tp = pair.tp;

  // Allocate the segment.
  offset_exe_ = reserve(seg->aligned_size);

  // Verify that the ABI and Bionic tpoff values are equal, which is equivalent
  // to checking whether the segment is sufficiently aligned.
  const size_t abi_tpoff = align_checked(2 * sizeof(void*), seg->aligned_size.align);
  const size_t actual_tpoff = align_checked(tcb_size_post, seg->aligned_size.align);
  CHECK(actual_tpoff == offset_exe_ - offset_tp);

  if (abi_tpoff != actual_tpoff) {
    async_safe_fatal(
        "error: \"%s\": executable's TLS segment is underaligned: "
        "alignment is %zu (skew %zu), needs to be at least %zu for %s Bionic",
        progname, seg->aligned_size.align.value, seg->aligned_size.align.skew, tcb_size_post,
        (sizeof(void*) == 4 ? "ARM" : "ARM64"));
  }

#elif defined(__i386__) || defined(__x86_64__)

  auto pair = reserve_tp_pair(seg->aligned_size, TlsAlignedSize::of_type<bionic_tcb>());
  offset_exe_ = pair.before;
  offset_bionic_tcb_ = pair.after;

#elif defined(__riscv)
  static_assert(MAX_TLS_SLOT == -1, "Last slot of bionic_tcb must be slot #(-1) on riscv");

  auto pair = reserve_tp_pair(TlsAlignedSize::of_type<bionic_tcb>(), seg->aligned_size);
  offset_bionic_tcb_ = pair.before;
  offset_exe_ = pair.after;

#else
#error "Unrecognized architecture"
#endif

  return offset_exe_;
}

size_t StaticTlsLayout::reserve_bionic_tls() {
  offset_bionic_tls_ = reserve_type<bionic_tls>();
  return offset_bionic_tls_;
}

void StaticTlsLayout::finish_layout() {
  // Round the offset up to the alignment.
  cursor_ = align_checked(cursor_, TlsAlign{.value = align_});
}

size_t StaticTlsLayout::align_cursor(TlsAlign align) {
  cursor_ = align_checked(cursor_, align);
  align_ = MAX(align_, align.value);
  return cursor_;
}

size_t StaticTlsLayout::align_cursor_unskewed(size_t align) {
  return align_cursor(TlsAlign{.value = align});
}

// Reserve the requested number of bytes at the requested alignment. The
// requested size is not required to be a multiple of the alignment, nor is the
// cursor aligned after the allocation.
size_t StaticTlsLayout::reserve(TlsAlignedSize aligned_size) {
  align_cursor(aligned_size.align);
  const size_t result = cursor_;
  if (__builtin_add_overflow(cursor_, aligned_size.size, &cursor_)) static_tls_layout_overflow();
  return result;
}

// Calculate the TP offset and allocate something before it and something after
// it. The TP will be aligned to:
//
//     MAX(before.align.value, after.align.value)
//
// The `before` and `after` allocations are each allocated as closely as
// possible to the TP.
StaticTlsLayout::TpAllocations StaticTlsLayout::reserve_tp_pair(TlsAlignedSize before,
                                                                TlsAlignedSize after) {
  // Tentative `before` allocation.
  const size_t tentative_before = reserve(before);
  const size_t tentative_before_end = align_cursor_unskewed(before.align.value);

  const size_t offset_tp = align_cursor_unskewed(MAX(before.align.value, after.align.value));

  const size_t offset_after = reserve(after);

  // If the `after` allocation has higher alignment than `before`, then there
  // may be alignment padding to remove between `before` and the TP. Shift
  // `before` forward to remove this padding.
  CHECK(((offset_tp - tentative_before_end) & (before.align.value - 1)) == 0);
  const size_t offset_before = tentative_before + (offset_tp - tentative_before_end);

  return TpAllocations{offset_before, offset_tp, offset_after};
}

// Copy each TLS module's initialization image into a newly-allocated block of
// static TLS memory. To reduce dirty pages, this function only writes to pages
// within the static TLS that need initialization. The memory should already be
// zero-initialized on entry.
void __init_static_tls(void* static_tls) {
  // The part of the table we care about (i.e. static TLS modules) never changes
  // after startup, but we still need the mutex because the table could grow,
  // moving the initial part. If this locking is too slow, we can duplicate the
  // static part of the table.
  TlsModules& modules = __libc_shared_globals()->tls_modules;
  ScopedSignalBlocker ssb;
  ScopedReadLock locker(&modules.rwlock);

  for (size_t i = 0; i < modules.module_count; ++i) {
    TlsModule& module = modules.module_table[i];
    if (module.static_offset == SIZE_MAX) {
      // All of the static modules come before all of the dynamic modules, so
      // once we see the first dynamic module, we're done.
      break;
    }
    if (module.segment.init_size == 0) {
      // Skip the memcpy call for TLS segments with no initializer, which is
      // common.
      continue;
    }
    memcpy(static_cast<char*>(static_tls) + module.static_offset,
           module.segment.init_ptr,
           module.segment.init_size);
  }
}

static inline size_t dtv_size_in_bytes(size_t module_count) {
  return sizeof(TlsDtv) + module_count * sizeof(void*);
}

// Calculates the number of module slots to allocate in a new DTV. For small
// objects (up to 1KiB), the TLS allocator allocates memory in power-of-2 sizes,
// so for better space usage, ensure that the DTV size (header + slots) is a
// power of 2.
//
// The lock on TlsModules must be held.
static size_t calculate_new_dtv_count() {
  size_t loaded_cnt = __libc_shared_globals()->tls_modules.module_count;
  size_t bytes = dtv_size_in_bytes(MAX(1, loaded_cnt));
  if (!powerof2(bytes)) {
    bytes = BIONIC_ROUND_UP_POWER_OF_2(bytes);
  }
  return (bytes - sizeof(TlsDtv)) / sizeof(void*);
}

// This function must be called with signals blocked and a write lock on
// TlsModules held.
static void update_tls_dtv(bionic_tcb* tcb) {
  const TlsModules& modules = __libc_shared_globals()->tls_modules;
  BionicAllocator& allocator = __libc_shared_globals()->tls_allocator;

  // Use the generation counter from the shared globals instead of the local
  // copy, which won't be initialized yet if __tls_get_addr is called before
  // libc.so's constructor.
  if (__get_tcb_dtv(tcb)->generation == atomic_load(&modules.generation)) {
    return;
  }

  const size_t old_cnt = __get_tcb_dtv(tcb)->count;

  // If the DTV isn't large enough, allocate a larger one. Because a signal
  // handler could interrupt the fast path of __tls_get_addr, we don't free the
  // old DTV. Instead, we add the old DTV to a list, then free all of a thread's
  // DTVs at thread-exit. Each time the DTV is reallocated, its size at least
  // doubles.
  if (modules.module_count > old_cnt) {
    size_t new_cnt = calculate_new_dtv_count();
    TlsDtv* const old_dtv = __get_tcb_dtv(tcb);
    TlsDtv* const new_dtv = static_cast<TlsDtv*>(allocator.alloc(dtv_size_in_bytes(new_cnt)));
    memcpy(new_dtv, old_dtv, dtv_size_in_bytes(old_cnt));
    new_dtv->count = new_cnt;
    new_dtv->next = old_dtv;
    __set_tcb_dtv(tcb, new_dtv);
  }

  TlsDtv* const dtv = __get_tcb_dtv(tcb);

  const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
  char* static_tls = reinterpret_cast<char*>(tcb) - layout.offset_bionic_tcb();

  // Initialize static TLS modules and free unloaded modules.
  for (size_t i = 0; i < dtv->count; ++i) {
    if (i < modules.module_count) {
      const TlsModule& mod = modules.module_table[i];
      if (mod.static_offset != SIZE_MAX) {
        dtv->modules[i] = static_tls + mod.static_offset;
        continue;
      }
      if (mod.first_generation != kTlsGenerationNone &&
          mod.first_generation <= dtv->generation) {
        continue;
      }
    }
    if (modules.on_destruction_cb != nullptr) {
      void* dtls_begin = dtv->modules[i];
      void* dtls_end =
          static_cast<void*>(static_cast<char*>(dtls_begin) + allocator.get_chunk_size(dtls_begin));
      modules.on_destruction_cb(dtls_begin, dtls_end);
    }
    allocator.free(dtv->modules[i]);
    dtv->modules[i] = nullptr;
  }

  dtv->generation = atomic_load(&modules.generation);
}

__attribute__((noinline)) static void* tls_get_addr_slow_path(const TlsIndex* ti) {
  TlsModules& modules = __libc_shared_globals()->tls_modules;
  bionic_tcb* tcb = __get_bionic_tcb();

  // Block signals and lock TlsModules. We may need the allocator, so take
  // a write lock.
  ScopedSignalBlocker ssb;
  ScopedWriteLock locker(&modules.rwlock);

  update_tls_dtv(tcb);

  TlsDtv* dtv = __get_tcb_dtv(tcb);
  const size_t module_idx = __tls_module_id_to_idx(ti->module_id);
  void* mod_ptr = dtv->modules[module_idx];
  if (mod_ptr == nullptr) {
    const TlsSegment& segment = modules.module_table[module_idx].segment;
    // TODO: Currently the aligned_size.align.skew property is ignored.
    // That is, for a dynamic TLS block at addr A, (A % p_align) will be 0, not
    // (p_vaddr % p_align).
    mod_ptr = __libc_shared_globals()->tls_allocator.memalign(segment.aligned_size.align.value,
                                                              segment.aligned_size.size);
    if (segment.init_size > 0) {
      memcpy(mod_ptr, segment.init_ptr, segment.init_size);
    }
    dtv->modules[module_idx] = mod_ptr;

    // Reports the allocation to the listener, if any.
    if (modules.on_creation_cb != nullptr) {
      modules.on_creation_cb(
          mod_ptr, static_cast<void*>(static_cast<char*>(mod_ptr) + segment.aligned_size.size));
    }
  }

  return static_cast<char*>(mod_ptr) + ti->offset + TLS_DTV_OFFSET;
}

// Returns the address of a thread's TLS memory given a module ID and an offset
// into that module's TLS segment. This function is called on every access to a
// dynamic TLS variable on targets that don't use TLSDESC. arm64 uses TLSDESC,
// so it only calls this function on a thread's first access to a module's TLS
// segment.
//
// On most targets, this accessor function is __tls_get_addr and
// TLS_GET_ADDR_CALLING_CONVENTION is unset, but 32-bit x86 uses
// ___tls_get_addr (with three underscores) instead, and a regparm
// calling convention.
extern "C" void* TLS_GET_ADDR(const TlsIndex* ti) TLS_GET_ADDR_CALLING_CONVENTION {
  TlsDtv* dtv = __get_tcb_dtv(__get_bionic_tcb());

  // TODO: See if we can use a relaxed memory ordering here instead.
  size_t generation = atomic_load(&__libc_tls_generation_copy);
  if (__predict_true(generation == dtv->generation)) {
    void* mod_ptr = dtv->modules[__tls_module_id_to_idx(ti->module_id)];
    if (__predict_true(mod_ptr != nullptr)) {
      return static_cast<char*>(mod_ptr) + ti->offset + TLS_DTV_OFFSET;
    }
  }

  return tls_get_addr_slow_path(ti);
}

// This function frees:
//  - TLS modules referenced by the current DTV.
//  - The list of DTV objects associated with the current thread.
//
// The caller must have already blocked signals.
void __free_dynamic_tls(bionic_tcb* tcb) {
  TlsModules& modules = __libc_shared_globals()->tls_modules;
  BionicAllocator& allocator = __libc_shared_globals()->tls_allocator;

  // If we didn't allocate any dynamic memory, skip out early without taking
  // the lock.
  TlsDtv* dtv = __get_tcb_dtv(tcb);
  if (dtv->generation == kTlsGenerationNone) {
    return;
  }

  // We need the write lock to use the allocator.
  ScopedWriteLock locker(&modules.rwlock);

  // First free everything in the current DTV.
  for (size_t i = 0; i < dtv->count; ++i) {
    if (i < modules.module_count && modules.module_table[i].static_offset != SIZE_MAX) {
      // This module's TLS memory is allocated statically, so don't free it here.
      continue;
    }

    if (modules.on_destruction_cb != nullptr) {
      void* dtls_begin = dtv->modules[i];
      void* dtls_end =
          static_cast<void*>(static_cast<char*>(dtls_begin) + allocator.get_chunk_size(dtls_begin));
      modules.on_destruction_cb(dtls_begin, dtls_end);
    }

    allocator.free(dtv->modules[i]);
  }

  // Now free the thread's list of DTVs.
  while (dtv->generation != kTlsGenerationNone) {
    TlsDtv* next = dtv->next;
    allocator.free(dtv);
    dtv = next;
  }

  // Clear the DTV slot. The DTV must not be used again with this thread.
  tcb->tls_slot(TLS_SLOT_DTV) = nullptr;
}

// Invokes all the registered thread_exit callbacks, if any.
void __notify_thread_exit_callbacks() {
  TlsModules& modules = __libc_shared_globals()->tls_modules;
  if (modules.first_thread_exit_callback == nullptr) {
    // If there is no first_thread_exit_callback, there shouldn't be a tail.
    CHECK(modules.thread_exit_callback_tail_node == nullptr);
    return;
  }

  // Callbacks are supposed to be invoked in the reverse order
  // in which they were registered.
  CallbackHolder* node = modules.thread_exit_callback_tail_node;
  while (node != nullptr) {
    node->cb();
    node = node->prev;
  }
  modules.first_thread_exit_callback();
}

"""

```