Response:
Let's break down the thought process for analyzing the `sys_mman_test.cpp` file. The request is quite comprehensive, touching upon various aspects of system programming and Android specifics. Here’s a simulated thought process:

1. **Understand the Core Request:** The main goal is to analyze the provided C++ test file and explain its functionality, relation to Android, the implementation of libc functions, dynamic linking aspects (if any), potential errors, and how to trace its execution within Android.

2. **Initial Scan and Identify Key Areas:**  Quickly skim the code. Notice the `#include` directives. `sys/mman.h` immediately stands out as the central theme, indicating memory management testing. Other includes like `fcntl.h`, `unistd.h`, `android-base/file.h`, and `gtest/gtest.h` provide context: file operations, standard POSIX functions, Android-specific utilities, and Google Test framework for unit testing.

3. **Categorize the Tests:**  The code is organized into `TEST` blocks. Start grouping these tests by the system call or concept they are testing. This will be the backbone of the analysis:

    * **`mmap` and `mmap64`:** Standard and 64-bit memory mapping.
    * **File Mapping:** Testing `mmap` with file descriptors, including offset handling.
    * **`munmap`:**  Unmapping memory regions.
    * **`posix_madvise`:** Providing hints to the kernel about memory usage.
    * **`mremap`:** Remapping memory regions.
    * **`mlock` and `mlock2`:** Locking memory to prevent swapping.
    * **`memfd_create`:** Creating anonymous file descriptors in memory.
    * **`mseal`:** Sealing memory regions against further modifications.
    * **Error Handling:** Tests with `ASSERT_EQ(MAP_FAILED, ...)` indicating checks for expected failures.

4. **Analyze Each Test Case:** For each group of tests, dissect the logic:

    * **What system call is being tested?**
    * **What are the inputs to the system call?** (e.g., address, length, protection flags, mapping flags, file descriptor, offset).
    * **What is the expected outcome?** (Success, failure, specific behavior).
    * **How is the outcome verified?** (`ASSERT_NE`, `ASSERT_EQ`, `ASSERT_STREQ`).
    * **Are there any edge cases or error conditions being tested?** (e.g., bad offsets, large sizes, invalid pointers).

5. **Relate to Android Functionality:**  Consider how these memory management functions are used within Android:

    * **Application Memory:** Apps use `mmap` for loading libraries, allocating memory (indirectly through `malloc`), and shared memory.
    * **Shared Memory:**  Inter-process communication (IPC) often relies on shared memory regions created with `mmap`. Examples include Ashmem or ASharedMemory.
    * **File-backed Memory:**  Accessing files efficiently, loading resources, and databases.
    * **Dynamic Linker:** The dynamic linker (`linker64`, `linker`) heavily uses `mmap` to load shared libraries into process address spaces.

6. **Explain Libc Function Implementations:**  Focus on the core system calls being tested (`mmap`, `munmap`, `posix_madvise`, etc.). Provide a general, high-level explanation of what these system calls do at the kernel level. Avoid going into kernel-specific implementation details, as the request focuses on the user-space test.

7. **Address Dynamic Linking (If Applicable):**  While this specific test file doesn't directly test the dynamic linker, `mmap` is fundamental to its operation. Provide a basic example of a shared library layout in memory and briefly describe the linking process. Emphasize the role of `mmap` in loading the `.text`, `.data`, and `.bss` sections.

8. **Identify Common Errors:**  Think about common mistakes developers make when using these functions:

    * **Incorrect Size:** Providing the wrong size to `mmap` or `munmap`.
    * **Invalid Offset:** Providing a non-page-aligned offset for file-backed mappings.
    * **Protection Mismatches:** Trying to write to a read-only mapping.
    * **Forgetting to `munmap`:** Leading to memory leaks.
    * **Race Conditions:** In shared memory scenarios.

9. **Explain Android Framework/NDK Integration:** Outline the call chain from a high-level Android component down to the libc level.

    * **Java Layer:**  Android framework APIs (e.g., `MemoryFile`, `MappedByteBuffer`).
    * **JNI Layer:** Native methods that call into the NDK.
    * **NDK:**  Provides C/C++ APIs that wrap libc functions.
    * **Bionic (libc):** Implements the system call wrappers.
    * **Kernel:** Executes the actual memory management operations.

10. **Provide Frida Hook Examples:**  Illustrate how to use Frida to intercept calls to `mmap` and `munmap`, showing how to inspect arguments and return values. This adds a practical debugging dimension to the analysis.

11. **Structure the Response:** Organize the information logically with clear headings and subheadings to address each part of the request. Use code blocks for the test code and Frida examples. Maintain a consistent and easy-to-understand writing style.

12. **Review and Refine:**  Read through the entire analysis to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that need further explanation. Ensure the language is appropriate for the technical level implied by the request. For example, clarify terms like "VMA" if necessary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe go into deep detail about the kernel implementation of `mmap`.
* **Correction:** The request is about the test file and its context. Focus on the user-space behavior and the purpose of the tests. Keep kernel details high-level.

* **Initial thought:**  Just list the functions.
* **Correction:**  Explain *how* they are used in the tests and what aspects of their behavior are being verified.

* **Initial thought:**  Assume the reader is an expert in Android internals.
* **Correction:**  Provide a clear path from the Android framework to the libc for less experienced readers.

By following this detailed process, including self-correction, a comprehensive and accurate analysis like the example provided in the initial prompt can be generated. The key is to break down the problem, systematically analyze each component, and connect the pieces to the broader Android ecosystem.
这个`bionic/tests/sys_mman_test.cpp` 文件是 Android Bionic 库中的一个测试文件，专门用于测试与内存映射相关的系统调用（System Calls），主要是 `sys/mman.h` 中定义的函数。它使用 Google Test 框架来编写单元测试，验证这些内存管理函数在各种场景下的行为是否符合预期。

**主要功能：**

1. **测试 `mmap` 和 `mmap64`：**
   - 验证匿名内存映射：测试使用 `MAP_ANONYMOUS` 和 `MAP_PRIVATE` 创建的内存映射能否成功创建和释放。
   - 验证文件内存映射：测试使用 `MAP_SHARED` 映射文件内容，包括读取和写入操作。
   - 验证文件映射偏移：测试使用 `mmap` 映射文件时，指定不同的偏移量是否能正确映射到文件的相应部分。
   - 验证错误的偏移量：测试当提供无效的文件偏移量时，`mmap` 是否返回 `MAP_FAILED`。
   - 验证大尺寸映射：测试映射非常大的内存区域是否会失败。

2. **测试 `munmap`：**
   - 验证内存映射的释放：在 `mmap` 创建映射后，测试 `munmap` 能否正确释放该映射。

3. **测试 `posix_madvise`：**
   - 验证内存管理建议：测试 `posix_madvise` 函数，它可以向内核提供关于内存区域使用模式的建议（例如，顺序访问、随机访问、即将使用等）。虽然测试本身无法直接断言 `posix_madvise` 的效果，但可以验证其调用是否成功。
   - 验证 `POSIX_MADV_DONTNEED`：测试在调用 `POSIX_MADV_DONTNEED` 后，匿名映射的内存是否仍然可以访问，这有助于验证内存是否真的被释放或只是被标记为可回收。

4. **测试 `mremap`：**
   - 验证内存重新映射：测试 `mremap` 函数，它可以改变现有内存映射的大小或位置。
   - 验证错误输入：测试使用 `nullptr` 作为参数调用 `mremap` 是否返回 `MAP_FAILED`。
   - 验证 `MREMAP_FIXED`：测试 `MREMAP_FIXED` 标志是否能按预期工作，即将映射移动到指定的地址。

5. **测试 `mlock` 和 `mlock2`：**
   - 验证内存锁定：测试 `mlock` 和 `mlock2` 函数，它们可以将内存页锁定在 RAM 中，防止被交换到磁盘。由于实际效果难以在测试中直接断言，测试主要验证函数调用是否成功。

6. **测试 `memfd_create`：**
   - 验证匿名文件描述符创建：测试 `memfd_create` 函数，它创建一个匿名的文件描述符，可以像普通文件一样使用，但其内容存储在内存中。测试包括验证 `MFD_CLOEXEC` 标志的行为以及基本的读写操作。

7. **测试 `mseal`：**
   - 验证内存密封：测试 `mseal` 函数，它可以限制对内存区域的进一步操作，例如防止修改保护属性。

**与 Android 功能的关系及举例说明：**

这些系统调用是 Android 操作系统底层内存管理的基础，对于应用和系统服务的正常运行至关重要。

* **应用程序内存分配：** 当应用程序通过 `malloc` 或 `new` 分配内存时，底层的 C 库（Bionic）可能会使用 `mmap` 来分配一块大的匿名内存区域，然后从中进行细粒度的分配。
* **共享内存（Shared Memory）：** Android 提供了多种共享内存的机制，例如 Ashmem（匿名共享内存）和 ASharedMemory (基于 `memfd_create`)。这些机制都依赖于 `mmap` 来将同一块物理内存映射到多个进程的地址空间中，实现进程间通信。例如，SurfaceFlinger 使用共享内存来传递图形缓冲区。
* **加载共享库（Shared Libraries）：** 当 Android 加载一个共享库（`.so` 文件）时，动态链接器会使用 `mmap` 将库的代码段、数据段等映射到进程的地址空间中。
* **文件访问：** 应用程序可以使用 `mmap` 来直接将文件内容映射到内存中，从而像访问内存一样访问文件，这比传统的 `read` 和 `write` 操作更高效，尤其对于大文件。例如，读取大型资源文件或数据库文件。
* **匿名内存映射用于创建私有副本（Copy-on-Write）：** 当使用 `fork` 创建子进程时，子进程最初会共享父进程的内存页。当父进程或子进程尝试修改这些共享页时，内核会使用写时复制（Copy-on-Write）机制，为修改进程创建一个私有的内存页副本。这通常是通过匿名私有映射实现的。

**libc 函数的功能及实现解释：**

这些都是系统调用，意味着它们最终会陷入到 Linux 内核中执行。Bionic 中的这些函数是对内核系统调用的封装。

* **`mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)`：**
    - **功能：** 在进程的地址空间中创建一个新的内存映射。
    - **实现：**  Bionic 中的 `mmap` 函数会将参数传递给内核的 `mmap` 系统调用。内核会根据参数创建一个新的虚拟内存区域（VMA），并将其映射到物理内存或文件。
        - `addr`：建议的映射起始地址，通常为 `nullptr`，让内核选择。
        - `length`：映射的长度。
        - `prot`：内存保护属性（`PROT_READ`、`PROT_WRITE`、`PROT_EXEC`）。
        - `flags`：映射类型（`MAP_ANONYMOUS`、`MAP_SHARED`、`MAP_PRIVATE` 等）。
        - `fd`：如果映射文件，则为文件描述符，否则为 `-1`（对于匿名映射）。
        - `offset`：文件映射的起始偏移量，必须是页对齐的。
    - **内核实现简述：** 内核会分配或找到合适的物理页，建立页表项，将虚拟地址映射到物理地址。对于文件映射，会记录文件和偏移量信息，当进程访问映射区域时，如果物理页不在内存中，会发生缺页中断，内核再从文件中读取数据到内存。

* **`munmap(void *addr, size_t length)`：**
    - **功能：**  删除进程地址空间中的一个内存映射。
    - **实现：** Bionic 中的 `munmap` 函数会将参数传递给内核的 `munmap` 系统调用。内核会释放与该映射相关的虚拟内存区域，解除虚拟地址到物理地址的映射，并可能释放相关的物理内存或取消与文件的关联。
    - **内核实现简述：** 内核会查找指定的 VMA，释放相关的页表项，并递减物理页的引用计数。如果物理页的引用计数降为零，则该物理页可以被回收。

* **`posix_madvise(void *addr, size_t length, int advice)`：**
    - **功能：** 向内核提供关于指定内存区域使用模式的建议，以优化性能。
    - **实现：** Bionic 中的 `posix_madvise` 函数会将参数传递给内核的 `madvise` 系统调用。内核会根据建议调整其内存管理策略，例如预取页面、释放不再需要的页面等。
    - **内核实现简述：** 内核会根据 `advice` 参数（例如 `POSIX_MADV_NORMAL`, `POSIX_MADV_SEQUENTIAL`, `POSIX_MADV_RANDOM`, `POSIX_MADV_WILLNEED`, `POSIX_MADV_DONTNEED`）调整其内部状态，影响页面的换入换出、预取等行为。

* **`mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */)`：**
    - **功能：** 调整一个现有内存映射的大小或位置。
    - **实现：** Bionic 中的 `mremap` 函数会将参数传递给内核的 `mremap` 系统调用。
        - 如果只改变大小，内核可能会尝试在原地扩展或收缩映射。
        - 如果指定了 `MREMAP_MAYMOVE`，内核可以将映射移动到新的地址。
        - 如果指定了 `MREMAP_FIXED`，则必须提供新的地址，内核会将映射移动到该地址，如果目标地址已被占用则可能失败。
    - **内核实现简述：** 内核需要更新 VMA 的大小和起始地址，并可能需要调整页表映射。如果需要移动映射，可能需要分配新的虚拟地址空间和物理页。

* **`mlock(const void *addr, size_t len)` 和 `mlock2(const void *addr, size_t len, int flags)`：**
    - **功能：** 将指定范围内的内存页锁定在 RAM 中，防止被交换到磁盘。`mlock2` 是一个更新的版本，提供了额外的标志。
    - **实现：** Bionic 中的 `mlock` 和 `mlock2` 函数会将参数传递给内核的 `mlock` 或 `mlock2` 系统调用。内核会标记相应的物理页为不可交换。
    - **内核实现简述：** 内核会修改页表项，阻止这些页被放入交换空间。这可以提高性能，但过度使用可能导致内存压力。

* **`memfd_create(const char *name, unsigned int flags)`：**
    - **功能：** 创建一个匿名的文件描述符，其内容驻留在内存中。
    - **实现：** Bionic 中的 `memfd_create` 函数会将参数传递给内核的 `memfd_create` 系统调用。内核会创建一个特殊的文件对象，并将其关联的内存区域存储在 RAM 中。
    - **内核实现简述：** 内核会分配一段匿名内存，并创建一个与该内存关联的文件描述符。这个文件描述符可以像普通文件一样使用 `write`, `read`, `mmap` 等操作。

* **`mseal(void *addr, size_t len, int seals)`：**
    - **功能：** 对内存区域应用“密封”，限制对其的进一步操作。
    - **实现：** Bionic 中的 `mseal` 函数会将参数传递给内核的 `mseal` 系统调用。可以设置不同的 seal，例如 `F_SEAL_SHRINK`（禁止收缩）、`F_SEAL_GROW`（禁止增长）、`F_SEAL_WRITE`（禁止写入）、`F_SEAL_SEAL`（禁止进一步密封）。
    - **内核实现简述：** 内核会记录应用于该内存区域的 seal，并在后续操作（如 `mprotect`, `ftruncate`, `mremap` 等）尝试违反 seal 时返回错误。

**涉及 dynamic linker 的功能、so 布局样本和链接处理过程：**

`mmap` 是动态链接器加载共享库的关键。

**so 布局样本：**

一个典型的共享库 `.so` 文件（例如 `libfoo.so`）在内存中被 `mmap` 后，通常会包含以下几个主要段（segments）：

```
[ 0x...7f9b... ]   .text      代码段（可执行，只读）
[ 0x...7f9c... ]   .rodata    只读数据段
[ 0x...7f9d... ]   .data      已初始化的可读写数据段
[ 0x...7f9e... ]   .bss       未初始化的可读写数据段（在内存中会被清零）
[ 0x...7f9f... ]   .plt/.got  过程链接表/全局偏移表 (用于动态链接)
... 其他段 ...
```

**链接的处理过程：**

1. **加载器启动：** 当程序需要加载一个共享库时，例如通过 `dlopen` 或程序启动时依赖的库，动态链接器（`/system/bin/linker` 或 `/system/bin/linker64`）会被调用。
2. **查找共享库：** 链接器会在预定义的路径中查找共享库文件。
3. **`mmap` 映射：** 链接器会使用 `mmap` 将共享库的各个段映射到进程的地址空间中。通常，`.text` 段会被映射为可执行和只读，`.data` 和 `.bss` 段会被映射为可读写。
4. **重定位（Relocation）：** 共享库在编译时并不知道最终加载到哪个地址，因此需要进行重定位。链接器会修改代码和数据中的地址，使其指向正确的内存位置。这涉及到修改 `.got` (Global Offset Table) 和 `.plt` (Procedure Linkage Table)。
5. **符号解析（Symbol Resolution）：** 如果共享库依赖于其他共享库的符号（函数或变量），链接器会查找这些符号的定义，并更新相应的引用。
6. **执行控制转移：** 一旦所有必要的库都被加载和链接，程序就可以开始执行。当程序调用共享库中的函数时，会通过 `.plt` 跳转到实际的函数地址。

**假设输入与输出 (逻辑推理)：**

以 `TEST(sys_mman, mmap_file_read)` 为例：

* **假设输入：**
    - 创建一个临时文件 `tf`。
    - 向文件中写入字符串 "012345678\nabcdefgh\n"。
    - 使用 `mmap` 将整个文件映射到内存。
* **逻辑推理：**
    - `mmap` 应该成功返回一个指向映射区域的指针。
    - 读取映射区域的内容应该与写入文件的内容一致。
    - `munmap` 应该成功释放映射。
* **预期输出：**
    - `ASSERT_NE(MAP_FAILED, map)` 应该为真。
    - `ASSERT_STREQ(STRING_MSG, data)` 应该为真，即映射的数据与 `STRING_MSG` 相同。
    - `ASSERT_EQ(0, munmap(map, sizeof(STRING_MSG)))` 应该为真。

**用户或编程常见的使用错误举例说明：**

1. **`munmap` 的大小不匹配：**
   ```c++
   void* map = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   // ... 使用 map ...
   munmap(map, 8192); // 错误：munmap 的大小与 mmap 的大小不一致
   ```
   **后果：** 可能导致程序崩溃或内存泄漏，行为未定义。

2. **对只读映射进行写入：**
   ```c++
   void* map = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   char* data = static_cast<char*>(map);
   data[0] = 'A'; // 错误：尝试写入只读内存
   ```
   **后果：** 触发 `SIGSEGV` 信号，导致程序崩溃。

3. **文件映射的偏移量不是页对齐的：**
   ```c++
   TemporaryFile tf;
   // ... 向 tf.fd 写入数据 ...
   void* map = mmap(nullptr, 100, PROT_READ, MAP_SHARED, tf.fd, 1); // 错误：偏移量 1 不是页对齐的
   ```
   **后果：** `mmap` 调用失败，返回 `MAP_FAILED`。

4. **忘记 `munmap`：**
   ```c++
   void* map = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
   // ... 使用 map ...
   // 忘记调用 munmap
   ```
   **后果：** 导致内存泄漏，长期运行的程序可能会耗尽内存。

**Android framework 或 ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

以 Android 应用程序使用 `mmap` 读取文件为例：

1. **Java 层：** 应用程序可能使用 `java.io.FileInputStream` 读取文件内容，或者使用 `java.nio.MappedByteBuffer` 直接进行内存映射文件。

2. **Framework 层：** 如果使用 `MappedByteBuffer`，Java 代码最终会调用 Native 方法。例如，`java.nio.MemoryBlock.map(int prot, long offset, long length)`。

3. **NDK 层：** `MemoryBlock.map` 的 Native 实现会调用 NDK 提供的相关函数，这些函数通常是对 Bionic 库中系统调用的封装。例如，可能会直接调用 `mmap`。

4. **Bionic 库：** Bionic 库中的 `mmap` 函数（如本测试文件所测试的）会将参数传递给 Linux 内核的 `mmap` 系统调用。

5. **内核层：** Linux 内核执行 `mmap` 系统调用，创建内存映射。

**Frida Hook 示例：**

可以使用 Frida hook Bionic 库中的 `mmap` 函数，查看其调用参数和返回值：

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "mmap"), {
    onEnter: function(args) {
        console.log("\\n[*] mmap called");
        console.log("    addr:   " + args[0]);
        console.log("    length: " + args[1]);
        console.log("    prot:   " + args[2]);
        console.log("    flags:  " + args[3]);
        console.log("    fd:     " + args[4]);
        console.log("    offset: " + args[5]);
    },
    onLeave: function(retval) {
        console.log("[*] mmap returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "munmap"), {
    onEnter: function(args) {
        console.log("\\n[*] munmap called");
        console.log("    addr:   " + args[0]);
        console.log("    length: " + args[1]);
    },
    onLeave: function(retval) {
        console.log("[*] munmap returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. 确保你的 Android 设备已连接，并且安装了 Frida 服务。
2. 将 `your.app.package.name` 替换为你要调试的应用程序的包名。
3. 运行 Python 脚本。
4. 在你的 Android 应用程序中执行涉及到 `mmap` 的操作（例如，打开大文件，使用 `MappedByteBuffer` 等）。
5. Frida 会拦截对 `mmap` 和 `munmap` 的调用，并打印出其参数和返回值，帮助你理解内存映射的过程。

这个测试文件是理解 Android 底层内存管理机制的重要入口，通过阅读和分析这些测试用例，可以更深入地了解 `mmap` 等系统调用的行为和使用方法。同时，结合 Frida 这样的动态分析工具，可以更有效地调试和理解 Android 应用程序中内存管理相关的操作。

### 提示词
```
这是目录为bionic/tests/sys_mman_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <gtest/gtest.h>

#include "utils.h"

static const size_t kPageSize = getpagesize();

TEST(sys_mman, mmap_std) {
  void* map = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  ASSERT_NE(MAP_FAILED, map);
  ASSERT_EQ(0, munmap(map, 4096));
}

TEST(sys_mman, mmap64_std) {
  void* map = mmap64(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  ASSERT_NE(MAP_FAILED, map);
  ASSERT_EQ(0, munmap(map, 4096));
}

TEST(sys_mman, mmap_file_bad_offset) {
  TemporaryFile tf;

  void* map = mmap(nullptr, 100, PROT_READ, MAP_SHARED, tf.fd, 1);
  ASSERT_EQ(MAP_FAILED, map);
}

TEST(sys_mman, mmap64_file_bad_offset) {
  TemporaryFile tf;

  void* map = mmap64(nullptr, 100, PROT_READ, MAP_SHARED, tf.fd, 1);
  ASSERT_EQ(MAP_FAILED, map);
}

#define STR_SSIZE(str) static_cast<ssize_t>(sizeof(str))

#define STRING_MSG  "012345678\nabcdefgh\n"
#define INITIAL_MSG "000000000\n00000000\n"

TEST(sys_mman, mmap_file_read) {
  TemporaryFile tf;

  ASSERT_EQ(STR_SSIZE(STRING_MSG), write(tf.fd, STRING_MSG, sizeof(STRING_MSG)));

  void* map = mmap(nullptr, sizeof(STRING_MSG), PROT_READ, MAP_SHARED, tf.fd, 0);
  ASSERT_NE(MAP_FAILED, map);

  char* data = reinterpret_cast<char*>(map);
  ASSERT_STREQ(STRING_MSG, data);

  ASSERT_EQ(0, munmap(map, sizeof(STRING_MSG)));
}

TEST(sys_mman, mmap_file_write) {
  TemporaryFile tf;

  ASSERT_EQ(STR_SSIZE(INITIAL_MSG), write(tf.fd, INITIAL_MSG, sizeof(INITIAL_MSG)));
  lseek(tf.fd, 0, SEEK_SET);

  void* map = mmap(nullptr, sizeof(STRING_MSG), PROT_WRITE, MAP_SHARED, tf.fd, 0);
  ASSERT_NE(MAP_FAILED, map);
  close(tf.fd);

  memcpy(map, STRING_MSG, sizeof(STRING_MSG));

  ASSERT_EQ(0, munmap(map, sizeof(STRING_MSG)));

  tf.fd = open(tf.path, O_RDWR);
  char buf[sizeof(STRING_MSG)];
  memset(buf, 0, sizeof(STRING_MSG));
  ASSERT_EQ(STR_SSIZE(STRING_MSG), read(tf.fd, buf, sizeof(STRING_MSG)));

  ASSERT_STREQ(STRING_MSG, buf);
}

#define PAGE0_MSG "00PAGE00"
#define PAGE1_MSG "111PAGE111"
#define PAGE2_MSG "2222PAGE2222"
#define END_MSG "E"

TEST(sys_mman, mmap_file_read_at_offset) {
  TemporaryFile tf;
  size_t pagesize = sysconf(_SC_PAGESIZE);

  // Create the file with three pages worth of data.
  ASSERT_EQ(STR_SSIZE(PAGE0_MSG), write(tf.fd, PAGE0_MSG, sizeof(PAGE0_MSG)));
  ASSERT_NE(-1, lseek(tf.fd, pagesize, SEEK_SET));
  ASSERT_EQ(STR_SSIZE(PAGE1_MSG), write(tf.fd, PAGE1_MSG, sizeof(PAGE1_MSG)));
  ASSERT_NE(-1, lseek(tf.fd, 2 * pagesize, SEEK_SET));
  ASSERT_EQ(STR_SSIZE(PAGE2_MSG), write(tf.fd, PAGE2_MSG, sizeof(PAGE2_MSG)));
  ASSERT_NE(-1, lseek(tf.fd, 3 * pagesize - sizeof(END_MSG), SEEK_SET));
  ASSERT_EQ(STR_SSIZE(END_MSG), write(tf.fd, END_MSG, sizeof(END_MSG)));

  ASSERT_NE(-1, lseek(tf.fd, 0, SEEK_SET));

  void* map = mmap(nullptr, pagesize, PROT_READ, MAP_SHARED, tf.fd, pagesize);
  ASSERT_NE(MAP_FAILED, map);

  char* data = reinterpret_cast<char*>(map);
  ASSERT_STREQ(PAGE1_MSG, data);

  ASSERT_EQ(0, munmap(map, pagesize));

  map = mmap(nullptr, pagesize, PROT_READ, MAP_SHARED, tf.fd, 2 * pagesize);
  ASSERT_NE(MAP_FAILED, map);

  data = reinterpret_cast<char*>(map);
  ASSERT_STREQ(PAGE2_MSG, data);
  ASSERT_STREQ(END_MSG, data+pagesize-sizeof(END_MSG));

  ASSERT_EQ(0, munmap(map, pagesize));
}

#define NEWPAGE1_MSG "1NEW1PAGE1"
#define NEWPAGE2_MSG "22NEW22PAGE22"

TEST(sys_mman, mmap_file_write_at_offset) {
  TemporaryFile tf;
  size_t pagesize = sysconf(_SC_PAGESIZE);

  // Create the file with three pages worth of data.
  ASSERT_EQ(STR_SSIZE(PAGE0_MSG), write(tf.fd, PAGE0_MSG, sizeof(PAGE0_MSG)));
  ASSERT_NE(-1, lseek(tf.fd, pagesize, SEEK_SET));
  ASSERT_EQ(STR_SSIZE(PAGE1_MSG), write(tf.fd, PAGE1_MSG, sizeof(PAGE1_MSG)));
  ASSERT_NE(-1, lseek(tf.fd, 2 * pagesize, SEEK_SET));
  ASSERT_EQ(STR_SSIZE(PAGE2_MSG), write(tf.fd, PAGE2_MSG, sizeof(PAGE2_MSG)));
  ASSERT_NE(-1, lseek(tf.fd, 3 * pagesize - sizeof(END_MSG), SEEK_SET));
  ASSERT_EQ(STR_SSIZE(END_MSG), write(tf.fd, END_MSG, sizeof(END_MSG)));

  ASSERT_NE(-1, lseek(tf.fd, 0, SEEK_SET));

  void* map = mmap(nullptr, pagesize, PROT_WRITE, MAP_SHARED, tf.fd, pagesize);
  ASSERT_NE(MAP_FAILED, map);
  close(tf.fd);

  memcpy(map, NEWPAGE1_MSG, sizeof(NEWPAGE1_MSG));
  ASSERT_EQ(0, munmap(map, pagesize));

  tf.fd = open(tf.path, O_RDWR);
  map = mmap(nullptr, pagesize, PROT_WRITE, MAP_SHARED, tf.fd, 2 * pagesize);
  ASSERT_NE(MAP_FAILED, map);
  close(tf.fd);

  memcpy(map, NEWPAGE2_MSG, sizeof(NEWPAGE2_MSG));
  ASSERT_EQ(0, munmap(map, pagesize));

  tf.fd = open(tf.path, O_RDWR);
  char buf[pagesize];
  ASSERT_EQ(static_cast<ssize_t>(pagesize), read(tf.fd, buf, pagesize));
  ASSERT_STREQ(PAGE0_MSG, buf);
  ASSERT_NE(-1, lseek(tf.fd, pagesize, SEEK_SET));
  ASSERT_EQ(static_cast<ssize_t>(pagesize), read(tf.fd, buf, pagesize));
  ASSERT_STREQ(NEWPAGE1_MSG, buf);
  ASSERT_NE(-1, lseek(tf.fd, 2 * pagesize, SEEK_SET));
  ASSERT_EQ(static_cast<ssize_t>(pagesize), read(tf.fd, buf, pagesize));
  ASSERT_STREQ(NEWPAGE2_MSG, buf);
  ASSERT_STREQ(END_MSG, buf+pagesize-sizeof(END_MSG));
}

TEST(sys_mman, posix_madvise) {
  TemporaryFile tempfile;
  size_t pagesize = sysconf(_SC_PAGESIZE);
  char buf[pagesize];

  // Prepare environment.
  ASSERT_EQ(static_cast<ssize_t>(pagesize), write(tempfile.fd, buf, pagesize));
  void* map = mmap(nullptr, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, tempfile.fd, 0);
  ASSERT_NE(MAP_FAILED, map);

  // Verify different options of posix_madvise.
  ASSERT_EQ(0, posix_madvise(map, pagesize, POSIX_MADV_NORMAL));
  ASSERT_EQ(0, posix_madvise(map, pagesize, POSIX_MADV_SEQUENTIAL));
  ASSERT_EQ(0, posix_madvise(map, pagesize, POSIX_MADV_RANDOM));
  ASSERT_EQ(0, posix_madvise(map, pagesize, POSIX_MADV_WILLNEED));

  ASSERT_EQ(0, munmap(map, pagesize));
}

// Verify that memory can still access after posix_madvise(POSIX_MADV_DONTNEED).
// We should test on MAP_ANONYMOUS memory to verify whether the memory is discarded,
// because the content of non MAP_ANONYMOUS memory can be reread from file.
TEST(sys_mman, posix_madvise_POSIX_MADV_DONTNEED) {
  size_t pagesize = sysconf(_SC_PAGESIZE);

  void* map = mmap(nullptr, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, map);

  int* int_ptr = reinterpret_cast<int*>(map);
  for (int i = 0; i < static_cast<int>(pagesize / sizeof(int)); ++i) {
    *int_ptr++ = i;
  }

  ASSERT_EQ(0, posix_madvise(map, pagesize, POSIX_MADV_DONTNEED));

  int_ptr = reinterpret_cast<int*>(map);
  for (int i = 0; i < static_cast<int>(pagesize / sizeof(int)); ++i) {
    ASSERT_EQ(i, *int_ptr++);
  }

  ASSERT_EQ(0, munmap(map, pagesize));
}

TEST(sys_mman, mremap) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  ASSERT_EQ(MAP_FAILED, mremap(nullptr, 0, 0, 0));
#pragma clang diagnostic pop
}

constexpr size_t kHuge = size_t(PTRDIFF_MAX) + 1;

TEST(sys_mman, mmap_PTRDIFF_MAX) {
  ASSERT_EQ(MAP_FAILED, mmap(nullptr, kHuge, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
}

TEST(sys_mman, mremap_PTRDIFF_MAX) {
  void* map = mmap(nullptr, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, map);

  ASSERT_EQ(MAP_FAILED, mremap(map, kPageSize, kHuge, MREMAP_MAYMOVE));

  ASSERT_EQ(0, munmap(map, kPageSize));
}

TEST(sys_mman, mremap_MREMAP_FIXED) {
  // We're not trying to test the kernel here; that's external/ltp's job.
  // We just want to check that optional argument (mremap() is varargs)
  // gets passed through in an MREMAP_FIXED call.
  void* vma1 = mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, vma1);

  void* vma2 = mmap(NULL, getpagesize(), PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, vma2);

  void* vma3 = mremap(vma1, getpagesize(), getpagesize(), MREMAP_FIXED | MREMAP_MAYMOVE, vma2);
  ASSERT_EQ(vma2, vma3);
}

TEST(sys_mman, mmap_bug_27265969) {
  char* base = reinterpret_cast<char*>(
      mmap(nullptr, kPageSize * 2, PROT_EXEC | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
  // Some kernels had bugs that would cause segfaults here...
  __builtin___clear_cache(base, base + (kPageSize * 2));
}

TEST(sys_mman, mlock) {
  void* map = mmap(nullptr, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, map);

  // Not really anything we can assert about this.
  mlock(map, kPageSize);

  ASSERT_EQ(0, munmap(map, kPageSize));
}

TEST(sys_mman, mlock2) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "needs glibc 2.27";
#else
  void* map = mmap(nullptr, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, map);

  // Not really anything we can assert about this.
  mlock2(map, kPageSize, MLOCK_ONFAULT);

  ASSERT_EQ(0, munmap(map, kPageSize));
#endif
}

TEST(sys_mman, memfd_create) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "needs glibc 2.27";
#else
  // Is the MFD_CLOEXEC flag obeyed?
  errno = 0;
  int fd = memfd_create("doesn't matter", 0);
  if (fd == -1 && errno == ENOSYS) GTEST_SKIP() << "no memfd_create() in this kernel";
  ASSERT_NE(-1, fd) << strerror(errno);

  int f = fcntl(fd, F_GETFD);
  ASSERT_NE(-1, f);
  ASSERT_FALSE(f & FD_CLOEXEC);
  close(fd);

  errno = 0;
  fd = memfd_create("doesn't matter", MFD_CLOEXEC);
  f = fcntl(fd, F_GETFD);
  ASSERT_NE(-1, f);
  ASSERT_TRUE(f & FD_CLOEXEC);

  // Can we read and write?
  std::string expected("hello, world!");
  ASSERT_TRUE(android::base::WriteStringToFd(expected, fd));
  ASSERT_EQ(0, lseek(fd, 0, SEEK_SET));
  std::string actual;
  ASSERT_TRUE(android::base::ReadFdToString(fd, &actual));
  ASSERT_EQ(expected, actual);

  close(fd);
#endif
}

TEST(sys_mseal, mseal) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "needs glibc 2.40";
#else
  void* map = mmap(nullptr, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, map);

#if defined(__LP64__)
  int rc = mseal(map, kPageSize, 0);
  if (rc == -1) {
    ASSERT_ERRNO(ENOSYS);
    GTEST_SKIP() << "needs kernel with mseal(2)";
  }
  ASSERT_EQ(-1, mprotect(map, kPageSize, PROT_READ));
  ASSERT_ERRNO(EPERM);
#else
  // No mseal() for ILP32.
  errno = 0;
  ASSERT_EQ(-1, mseal(map, kPageSize, 0));
  ASSERT_ERRNO(ENOSYS);
  GTEST_SKIP() << "mseal(2) is LP64-only";
#endif

  // We can't munmap() our test mapping if mseal() actually succeeded :-)
#endif
}
```