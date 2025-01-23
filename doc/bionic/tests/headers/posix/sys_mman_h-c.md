Response:
Let's break down the thought process for answering the request.

**1. Understanding the Request:**

The core request is to analyze the provided C header file test (`bionic/tests/headers/posix/sys_mman_h.c`) and explain its purpose, functions, relationship to Android, and provide debugging information. The key elements to address are:

* **Functionality of the test file:** What does it *do*?
* **Relationship to Android:** How do these functions fit into the larger Android ecosystem?
* **Detailed explanations of libc functions:**  How do these memory management functions work at a lower level?
* **Dynamic linker implications:**  Are there any dependencies or interactions with the dynamic linker? If so, how does that work?
* **Logic and assumptions:** If there's any reasoning or assumptions made, explain them.
* **Common usage errors:**  What are the typical mistakes developers make when using these functions?
* **Android framework/NDK path:** How does code execution reach these functions from a higher level?
* **Frida hooking:** How can these functions be observed and manipulated at runtime using Frida?

**2. Analyzing the Source Code:**

The provided C code is not a functional library but a *header check* file. This is a crucial realization. It's designed to verify the existence and basic properties (macros, types, function signatures) of the `sys/mman.h` header file. This significantly impacts how the questions are answered.

* **Macros:** The `MACRO()` calls verify the existence of preprocessor macros related to memory protection (e.g., `PROT_READ`, `PROT_WRITE`), mapping flags (e.g., `MAP_PRIVATE`, `MAP_SHARED`), and `msync` and `madvise` options.
* **Types:** The `TYPE()` calls verify the existence of fundamental types like `mode_t`, `off_t`, and `size_t`, as well as the `posix_typed_mem_info` structure (conditionally).
* **Function signatures:** The `FUNCTION()` calls are the most important part. They check the existence and expected signature (return type and argument types) of various memory management functions. The function pointer syntax (`int (*f)(const void*, size_t)`) is the key here.
* **Conditional Compilation:** The `#if !defined(__linux__)` and `#if !defined(__BIONIC__)` blocks indicate features or functions that are specific to non-Linux or non-Bionic environments (or excluded for specific reasons).

**3. Addressing the Request Points (Iterative Refinement):**

* **Functionality:**  Initially, one might think this file *implements* the functions. However, the `FUNCTION()` macro syntax clarifies it's just *checking* for their presence and signatures. The answer should reflect this: it's a header test.
* **Relationship to Android:**  Since `bionic` *is* Android's C library, these functions are fundamental to Android's memory management. Examples of how Android uses these functions should be provided (e.g., shared memory for inter-process communication, memory mapping files).
* **Libc Function Details:** For each listed function (e.g., `mmap`, `mprotect`, `munmap`), provide a concise explanation of its purpose and core functionality. Avoid getting bogged down in implementation details, as the test file doesn't provide them. Focus on the *what* and *why*.
* **Dynamic Linker:**  Memory mapping is inherently linked to the dynamic linker when loading shared libraries. Explain how `mmap` is used to map shared object files into the process's address space. Illustrate with a simplified SO layout. Describe the linking process (symbol resolution, relocation).
* **Logic and Assumptions:** The primary assumption is that the test file correctly reflects the expected interface of `sys/mman.h`. Mentioning this adds clarity.
* **Common Usage Errors:** Think about common mistakes when using these functions. For example, incorrect permissions with `mprotect`, failing to unmap memory with `munmap`, or misuse of `MAP_SHARED`.
* **Android Framework/NDK Path:**  Trace a potential path from the Android framework down to these libc calls. Start with a high-level Android API (e.g., Binder for IPC), then show how that might involve memory mapping, eventually calling `mmap`. For NDK, a direct call to `mmap` is simpler.
* **Frida Hooking:** Provide concrete Frida code examples for hooking functions like `mmap` and logging their arguments and return values. This requires understanding Frida's syntax.

**4. Structuring the Answer:**

Organize the answer logically, addressing each point in the request clearly. Use headings and bullet points to improve readability.

**5. Language and Tone:**

Use clear and concise language. Avoid overly technical jargon where possible. Since the request is in Chinese, the response should also be in Chinese.

**Self-Correction/Refinement during the process:**

* **Initial Misunderstanding:**  Initially, I might have assumed the code *implements* the `sys/mman.h` functions. Realizing it's a *header check* is a crucial correction.
* **Level of Detail:** Avoid going too deep into kernel implementation details of the memory management functions. Focus on the user-level interface and common usage.
* **Dynamic Linker Complexity:** Keep the dynamic linker explanation relatively high-level. A full deep dive into ELF format and relocation tables isn't necessary.
* **Frida Example Specificity:** Ensure the Frida examples are practical and directly relevant to the functions being discussed.

By following these steps and engaging in self-correction, we arrive at the comprehensive and accurate answer provided previously. The key is to carefully analyze the source code, understand the intent of the test file, and address each aspect of the request systematically.
这个文件 `bionic/tests/headers/posix/sys_mman_h.c` 是 Android Bionic 库中的一个测试文件。它的主要功能是 **验证 `sys/mman.h` 头文件是否正确定义了相关的宏、类型和函数签名**。  它本身并不实现任何内存管理功能，而是用来确保 Bionic 提供的 `sys/mman.h` 符合 POSIX 标准（或 Bionic 的特定要求）。

**功能列举：**

1. **检查宏定义 (MACRO):** 验证 `sys/mman.h` 中是否定义了预期的宏常量，例如：
   - 内存保护标志：`PROT_EXEC`, `PROT_NONE`, `PROT_READ`, `PROT_WRITE`
   - 内存映射标志：`MAP_FIXED`, `MAP_PRIVATE`, `MAP_SHARED`
   - `msync` 同步标志：`MS_ASYNC`, `MS_INVALIDATE`, `MS_SYNC`
   - `mlock` 锁定标志：`MCL_CURRENT`, `MCL_FUTURE`
   - `posix_madvise` 建议标志：`POSIX_MADV_DONTNEED`, `POSIX_MADV_NORMAL`, `POSIX_MADV_RANDOM`, `POSIX_MADV_SEQUENTIAL`, `POSIX_MADV_WILLNEED`
   -  特定于非 Linux 的宏 (例如 `POSIX_TYPED_MEM_ALLOCATE`)。

2. **检查类型定义 (TYPE):** 验证 `sys/mman.h` 中是否定义了必要的类型，例如：
   - `mode_t`: 用于表示文件权限模式。
   - `off_t`: 用于表示文件偏移量。
   - `size_t`: 用于表示内存大小。
   - 特定于非 Linux 的结构体 `struct posix_typed_mem_info`。

3. **检查结构体成员 (STRUCT_MEMBER):** 验证结构体中是否包含预期的成员，例如 `struct posix_typed_mem_info` 的成员 `posix_tmi_length`。

4. **检查函数签名 (FUNCTION):** 验证 `sys/mman.h` 中声明的函数的签名是否正确，包括函数名、参数类型和返回类型。 这包括：
   - 内存锁定和解锁函数：`mlock`, `mlockall`, `munlock`, `munlockall`
   - 内存映射函数：`mmap`, `munmap`
   - 内存保护函数：`mprotect`
   - 内存同步函数：`msync`
   - 内存建议函数：`posix_madvise`
   - 特定于非 Linux 的函数：`posix_mem_offset`, `posix_typed_mem_get_info`, `posix_typed_mem_open`
   - 因 SELinux 限制而未实现的函数（在非 Bionic 环境下检查）：`shm_open`, `shm_unlink`

**与 Android 功能的关系和举例说明：**

`sys/mman.h` 中定义的函数是 Android 系统中进行内存管理的关键组成部分。Android 的许多核心功能都依赖于这些函数：

1. **进程间通信 (IPC):**
   - `mmap` 可以用于创建匿名共享内存区域，或将文件映射到内存中，从而实现进程间的数据共享。例如，`SurfaceFlinger` 和应用进程之间会使用共享内存来传递图形缓冲区。
   - **举例:** 当应用绘制 UI 时，它会将渲染结果写入一块共享内存区域，`SurfaceFlinger` 会读取这块内存并将内容显示到屏幕上。

2. **动态链接器:**
   - `mmap` 是动态链接器加载共享库 (`.so` 文件) 的关键。链接器使用 `mmap` 将共享库的代码段、数据段等映射到进程的地址空间。
   - **举例:** 当一个应用启动时，动态链接器会使用 `mmap` 加载 `libc.so`, `libm.so` 等系统库，以及应用依赖的其他共享库。

3. **文件操作:**
   - `mmap` 可以将文件内容直接映射到内存，避免了传统的 `read`/`write` 系统调用，提高了文件访问效率。
   - **举例:**  数据库系统可能会使用 `mmap` 来直接操作数据库文件，减少 I/O 开销。

4. **内存保护:**
   - `mprotect` 用于修改内存区域的访问权限（读、写、执行）。Android 系统使用 `mprotect` 来增强安全性，例如防止代码段被意外修改。
   - **举例:**  ART (Android Runtime) 会使用 `mprotect` 将已加载的 DEX 代码标记为只读和可执行，防止恶意代码注入。

5. **内存锁定:**
   - `mlock` 和 `mlockall` 用于将内存页锁定在物理内存中，防止它们被交换到磁盘。这对于需要高性能和实时性的应用非常重要。
   - **举例:**  音频或视频处理应用可能会使用内存锁定来避免因内存交换导致的卡顿。

6. **内存建议:**
   - `posix_madvise` 用于向内核提供关于内存使用模式的建议，帮助内核优化内存管理。
   - **举例:**  图片加载库可能会使用 `POSIX_MADV_SEQUENTIAL` 来提示内核即将按顺序访问映射的图像数据。

**libc 函数的功能实现详解：**

由于这是一个测试头文件的代码，它本身并不包含 `libc` 函数的实现。这些函数的具体实现位于 Bionic 库的源文件中（通常在 `bionic/libc/bionic/` 目录下）。

以下简要解释这些 `libc` 函数的功能（基于其常见实现方式，具体实现可能因操作系统和架构而异）：

- **`mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)`:**
  - **功能:** 将文件或匿名内存区域映射到调用进程的地址空间。
  - **实现:**
    1. 系统调用进入内核。
    2. 内核找到或创建一个与 `fd` 关联的文件或匿名内存区域。
    3. 内核在进程的虚拟地址空间中找到一块大小为 `length` 的空闲区域。如果 `addr` 不为 `NULL` 且指定了 `MAP_FIXED`，则尝试映射到该地址，否则由内核选择地址。
    4. 创建页表项，将进程虚拟地址空间中的页映射到文件或匿名内存区域的物理页。
    5. 返回映射区域的起始地址。

- **`munmap(void *addr, size_t length)`:**
  - **功能:** 解除 `mmap` 创建的内存映射。
  - **实现:**
    1. 系统调用进入内核。
    2. 内核查找起始地址为 `addr`，长度为 `length` 的映射区域。
    3. 移除相应的页表项，取消虚拟地址到物理页的映射。
    4. 如果是文件映射，并且指定了 `MAP_SHARED`，则根据 `msync` 的调用情况将修改写回磁盘。
    5. 释放进程地址空间中的相应区域。

- **`mprotect(void *addr, size_t len, int prot)`:**
  - **功能:** 修改指定内存区域的保护属性（读、写、执行）。
  - **实现:**
    1. 系统调用进入内核。
    2. 内核查找覆盖 `addr` 到 `addr + len` 的虚拟内存区域。
    3. 修改对应页表项的权限位，更新内存区域的访问权限。
    4. 可能需要刷新 TLB (Translation Lookaside Buffer) 以确保权限更改立即生效。

- **`msync(void *addr, size_t length, int flags)`:**
  - **功能:** 将内存映射区域的修改同步回磁盘。
  - **实现:**
    1. 系统调用进入内核。
    2. 内核查找起始地址为 `addr`，长度为 `length` 的共享映射区域。
    3. 根据 `flags` 的设置 (`MS_SYNC` 或 `MS_ASYNC`)，将内存中的修改立即或稍后写回磁盘上的文件。
    4. `MS_INVALIDATE` 可以用来使其他映射到相同文件的进程的缓存失效。

- **`mlock(const void *addr, size_t len)`:**
  - **功能:** 将指定范围的内存页锁定在物理 RAM 中，防止被交换到磁盘。
  - **实现:**
    1. 系统调用进入内核。
    2. 内核查找覆盖 `addr` 到 `addr + len` 的虚拟内存区域。
    3. 标记对应的物理页为不可交换。
    4. 需要 root 权限才能锁定超过一定限制的内存。

- **`munlock(const void *addr, size_t len)`:**
  - **功能:** 解除 `mlock` 设置的内存锁定。
  - **实现:**
    1. 系统调用进入内核。
    2. 内核查找覆盖 `addr` 到 `addr + len` 的虚拟内存区域。
    3. 取消对应物理页的不可交换标记。

- **`mlockall(int flags)`:**
  - **功能:** 锁定调用进程的所有或未来分配的内存。
  - **实现:**
    1. 系统调用进入内核。
    2. 根据 `flags` 的设置 (`MCL_CURRENT`, `MCL_FUTURE`, 或两者都设置)，锁定进程当前或将来分配的所有内存页。

- **`munlockall(void)`:**
  - **功能:** 解除进程通过 `mlockall` 设置的所有内存锁定。
  - **实现:**
    1. 系统调用进入内核。
    2. 解除进程所有内存页的不可交换标记。

- **`posix_madvise(void *addr, size_t len, int advice)`:**
  - **功能:** 向内核提供关于应用程序对内存区域使用模式的建议，以便内核优化内存管理。
  - **实现:**
    1. 系统调用进入内核。
    2. 内核根据 `advice` 的值（例如 `POSIX_MADV_DONTNEED`, `POSIX_MADV_WILLNEED`）调整对相关内存页的处理策略，例如更积极地回收或提前加载。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程：**

`mmap` 是动态链接器加载共享库的关键。当动态链接器需要加载一个共享库时，它会执行以下步骤：

1. **打开共享库文件:** 使用 `open()` 系统调用打开 `.so` 文件。
2. **确定共享库大小:** 获取文件的大小。
3. **使用 `mmap` 映射共享库:** 调用 `mmap` 将共享库的不同段（例如 `.text` 代码段, `.rodata` 只读数据段, `.data` 可读写数据段, `.bss` 未初始化数据段）映射到进程的地址空间。

**SO 布局样本:**

一个典型的共享库 (`.so`) 文件（例如 `libmylib.so`) 的布局可能如下（简化）：

```
LOAD           0xXXXXXXXX000  0xXXXXXXXX100  0x100 R E   # 代码段 (.text)
LOAD           0xXXXXXXXX100  0xXXXXXXXX200  0x100 R     # 只读数据段 (.rodata)
LOAD           0xXXXXXXXX200  0xXXXXXXXX300  0x100 RW    # 数据段 (.data)
LOAD           0xXXXXXXXX300  0xXXXXXXXX400  0x100 RW    # BSS段 (.bss) (在文件中通常大小为 0)
```

- `LOAD`: 表示这是一个需要加载到内存的段。
- `0xXXXXXXXX000` 等是虚拟内存地址。实际加载地址由加载器决定。
- `0x100` 是段的大小。
- `R`, `W`, `E` 分别表示读、写、执行权限。

**链接的处理过程：**

1. **加载共享库:** 动态链接器使用 `mmap` 将共享库的各个段映射到进程的地址空间。映射时会根据段的权限设置相应的内存保护属性（使用 `mprotect`）。
2. **符号解析 (Symbol Resolution):**
   - 动态链接器需要找到程序中引用的外部符号（函数、全局变量）在共享库中的地址。
   - 这通常通过查找共享库的符号表来实现。
   - 延迟绑定 (Lazy Binding) 可以优化这个过程，只在首次使用时解析符号。
3. **重定位 (Relocation):**
   - 共享库在编译时并不知道最终加载到哪个地址，因此需要进行重定位。
   - 动态链接器会修改共享库中某些指令或数据，使其指向正确的内存地址。例如，将对全局变量的引用修改为加载后的实际地址。
4. **执行共享库代码:** 完成加载和链接后，程序就可以调用共享库中的函数或访问其中的数据了。

**假设输入与输出 (逻辑推理)：**

这个测试文件本身并没有逻辑推理，它只是静态地检查头文件的定义。没有运行时输入和输出的概念。

**用户或编程常见的使用错误：**

1. **`mmap` 后忘记 `munmap`:** 导致内存泄漏。
   ```c
   void* ptr = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   // ... 使用 ptr ...
   // 忘记 munmap(ptr, 1024);
   ```

2. **`mprotect` 使用不当:**
   - 尝试修改没有写权限的内存区域。
   - 将代码段设置为可写可能导致安全漏洞。
   ```c
   void* code = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   // ... 写入代码到 code ...
   // 错误：尝试写入到只读的内存
   // *((int*)code) = 0x1234;

   // 错误：将代码段设置为可写可能带来安全风险
   // mprotect(code, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
   ```

3. **`MAP_SHARED` 使用不当导致数据竞争:**
   - 多个进程或线程共享同一块内存，但没有适当的同步机制。
   ```c
   // 进程 1
   int fd = shm_open("/my_shared_memory", O_CREAT | O_RDWR, 0666);
   ftruncate(fd, sizeof(int));
   int* shared_value = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
   *shared_value = 10;

   // 进程 2
   int fd2 = shm_open("/my_shared_memory", O_RDWR, 0666);
   int* shared_value2 = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
   // 可能在进程 1 修改完成前读取到旧值
   printf("Shared value: %d\n", *shared_value2);
   ```

4. **`mlock` 使用过多导致系统资源耗尽:**
   - 锁定过多的内存会限制系统的可用内存，可能导致其他进程性能下降甚至崩溃。

5. **不检查 `mmap` 的返回值:** `mmap` 失败时会返回 `MAP_FAILED`。
   ```c
   void* ptr = mmap(NULL, 1024, PROT_READ, MAP_PRIVATE, -1, 0);
   if (ptr == MAP_FAILED) {
       perror("mmap failed");
       // 处理错误
   }
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `sys/mman.h` 中函数的路径：**

1. **Android Framework (Java 代码):**
   - 许多 Android Framework 的核心组件都依赖于 native 代码实现。例如，`SurfaceFlinger` (负责屏幕合成) 使用 native 代码进行帧缓冲区的管理，这可能涉及到共享内存 (`mmap`)。
   - 通过 JNI (Java Native Interface)，Java 代码可以调用 native 代码。

2. **Native 代码 (C/C++):**
   - Framework 中的 native 代码会直接或间接地调用 `bionic` 库提供的 `sys/mman.h` 中声明的函数。

**NDK 到 `sys/mman.h` 中函数的路径：**

1. **NDK 代码 (C/C++):**
   - 使用 NDK 开发的应用程序可以直接包含 `<sys/mman.h>` 头文件，并调用其中的函数。
   - 例如，一个需要进行高性能内存管理的图形渲染引擎或音视频处理应用可能会直接使用 `mmap`, `mprotect` 等函数。

**Frida Hook 示例：**

以下是一些使用 Frida hook `mmap` 函数的示例，可以用来调试这些步骤：

**示例 1：Hook `mmap` 并打印参数：**

```javascript
// Hook mmap in any process
Interceptor.attach(Module.findExportByName(null, "mmap"), {
  onEnter: function (args) {
    console.log("mmap called");
    console.log("  addr:", args[0]);
    console.log("  length:", args[1]);
    console.log("  prot:", args[2]);
    console.log("  flags:", args[3]);
    console.log("  fd:", args[4]);
    console.log("  offset:", args[5]);
  },
  onLeave: function (retval) {
    console.log("mmap returned:", retval);
  }
});
```

**示例 2：Hook 特定进程的 `mmap`：**

```javascript
// Hook mmap in a specific process by name (replace "com.example.myapp")
if (Process.enumerateModules().length > 0) {
  Interceptor.attach(Module.findExportByName(null, "mmap"), {
    onEnter: function (args) {
      if (Process.getCurrentProcess().name === "com.example.myapp") {
        console.log("[com.example.myapp] mmap called");
        console.log("  addr:", args[0]);
        console.log("  length:", args[1]);
        // ...
      }
    }
  });
}
```

**示例 3：修改 `mmap` 的参数或返回值（谨慎使用）：**

```javascript
Interceptor.attach(Module.findExportByName(null, "mmap"), {
  onEnter: function (args) {
    // 将映射长度增加一倍 (可能导致错误)
    args[1] = ptr(args[1].toInt64() * 2);
  },
  onLeave: function (retval) {
    // 如果 mmap 成功，将返回地址偏移 0x100
    if (!retval.isNull()) {
      retval.add(0x100);
    }
  }
});
```

**调试步骤示例 (使用 Frida Hook)：**

1. **找到目标进程:** 确定你想要观察哪个进程的 `mmap` 调用 (例如，你的应用进程或 `SurfaceFlinger`)。
2. **编写 Frida 脚本:** 使用上面的示例或其他自定义脚本来 hook `mmap` 函数。
3. **运行 Frida:** 使用 Frida CLI 连接到目标设备或模拟器，并加载你的脚本。
   ```bash
   frida -U -f com.example.myapp -l your_script.js --no-pause
   # 或连接到正在运行的进程
   frida -U com.example.myapp -l your_script.js
   ```
4. **触发 `mmap` 调用:** 在你的应用中执行某些操作，例如加载一个大的图片或进行进程间通信，以触发 `mmap` 的调用。
5. **查看 Frida 输出:** Frida 会在控制台输出 `mmap` 的调用信息，包括参数和返回值。
6. **分析结果:** 根据 Frida 的输出，你可以了解 `mmap` 是如何被调用的，映射了哪些内存区域，以及是否出现了错误。

通过 Frida hook，你可以深入了解 Android 系统和应用是如何使用 `sys/mman.h` 中定义的内存管理函数的，从而帮助你调试问题、理解系统行为或进行安全分析。请记住，在生产环境中使用 Frida 修改函数行为需要谨慎，因为它可能会导致应用崩溃或不可预测的行为。

### 提示词
```
这是目录为bionic/tests/headers/posix/sys_mman_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```c
/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <sys/mman.h>

#include "header_checks.h"

static void sys_mman_h() {
  MACRO(PROT_EXEC);
  MACRO(PROT_NONE);
  MACRO(PROT_READ);
  MACRO(PROT_WRITE);

  MACRO(MAP_FIXED);
  MACRO(MAP_PRIVATE);
  MACRO(MAP_SHARED);

  MACRO(MS_ASYNC);
  MACRO(MS_INVALIDATE);
  MACRO(MS_SYNC);

  MACRO(MCL_CURRENT);
  MACRO(MCL_FUTURE);

  void* p;
  p = MAP_FAILED;

  MACRO(POSIX_MADV_DONTNEED);
  MACRO(POSIX_MADV_NORMAL);
  MACRO(POSIX_MADV_RANDOM);
  MACRO(POSIX_MADV_SEQUENTIAL);
  MACRO(POSIX_MADV_WILLNEED);

#if !defined(__linux__)
  MACRO(POSIX_TYPED_MEM_ALLOCATE);
  MACRO(POSIX_TYPED_MEM_ALLOCATE_CONTIG);
  MACRO(POSIX_TYPED_MEM_ALLOCATABLE);
#endif

  TYPE(mode_t);
  TYPE(off_t);
  TYPE(size_t);

#if !defined(__linux__)
  TYPE(struct posix_typed_mem_info);
  STRUCT_MEMBER(struct posix_typed_mem_info, size_t, posix_tmi_length);
#endif

  FUNCTION(mlock, int (*f)(const void*, size_t));
  FUNCTION(mlockall, int (*f)(int));
  FUNCTION(mmap, void* (*f)(void*, size_t, int, int, int, off_t));
  FUNCTION(mprotect, int (*f)(void*, size_t, int));
  FUNCTION(msync, int (*f)(void*, size_t, int));
  FUNCTION(munlock, int (*f)(const void*, size_t));
  FUNCTION(munlockall, int (*f)(void));
  FUNCTION(munmap, int (*f)(void*, size_t));
  FUNCTION(posix_madvise, int (*f)(void*, size_t, int));
#if !defined(__linux__)
  FUNCTION(posix_mem_offset, int (*f)(const void*, size_t, off_t*, size_t*, int*));
  FUNCTION(posix_typed_mem_get_info, int (*f)(int, struct posix_typed_mem_info*));
  FUNCTION(posix_typed_mem_open, int (*f)(const char*, int, int));
#endif
#if !defined(__BIONIC__) // Disallowed by SELinux, so not implemented.
  FUNCTION(shm_open, int (*f)(const char*, int, mode_t));
  FUNCTION(shm_unlink, int (*f)(const char*));
#endif
}
```