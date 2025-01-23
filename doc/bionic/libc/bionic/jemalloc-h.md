Response:
Let's break down the thought process for answering this complex request. The request asks for a detailed analysis of the provided C header file, including its functionality, relationship to Android, implementation details, dynamic linking aspects, potential errors, and how it's used within Android.

**1. Initial Understanding and Keyword Extraction:**

First, I scanned the provided header file and the surrounding context ("bionic/libc/bionic/jemalloc.handroid"). Key terms jumped out:

* `jemalloc`:  A memory allocator.
* `bionic`: Android's C library.
* `handroid`:  Likely a modification or adaptation of jemalloc for Android.
* `malloc.h`: Standard C memory allocation functions.
* `dynamic linker`: Implies interaction with loading and linking shared libraries.
* Function names like `je_aligned_alloc_wrapper`, `je_malloc_iterate`, `je_mallctl`, etc.

This immediately tells me this file is about customizing or integrating the jemalloc memory allocator within Android's libc.

**2. Functionality Identification (Direct Observation):**

The most straightforward part is listing the declared functions. I simply went through each function declaration and noted its name and basic signature:

* `je_aligned_alloc_wrapper(size_t, size_t)`
* `je_malloc_iterate(uintptr_t, size_t, void (*)(uintptr_t, size_t, void*), void*)`
* `je_mallctl(...)`
* `je_mallinfo()`
* `je_malloc_disable()`
* `je_malloc_enable()`
* `je_malloc_info(...)`
* `je_mallopt(...)`
* `je_memalign_round_up_boundary(size_t, size_t)`
* `je_pvalloc(size_t)`

**3. Inferring Functionality (Based on Names and Context):**

For each function, I tried to infer its purpose based on its name and its relationship to standard memory allocation functions.

* `je_aligned_alloc_wrapper`:  The "wrapper" suffix suggests it's modifying or adapting the behavior of a standard `aligned_alloc`. The comment in the code confirms this, explaining the need to enforce size being a multiple of alignment.
* `je_malloc_iterate`:  The name suggests iterating over allocated memory blocks, likely for debugging or profiling.
* `je_mallctl`:  Looks like a control function for jemalloc's internal settings, similar to `ioctl` for devices. The "ctl" suffix is a common indicator.
* `je_mallinfo`:  Standard function for getting memory allocation statistics.
* `je_malloc_disable`/`je_malloc_enable`:  Likely used to temporarily disable/enable jemalloc, potentially for testing or specific scenarios.
* `je_malloc_info`:  Getting detailed information about jemalloc's state.
* `je_mallopt`:  Setting options related to memory allocation behavior.
* `je_memalign_round_up_boundary`: Similar to `memalign`, but the "round_up_boundary" suggests a specific handling of alignment. The comment confirms this, explaining the workaround for non-power-of-two alignments.
* `je_pvalloc`:  Standard function for allocating page-aligned memory.

**4. Relating to Android Functionality:**

The key here is recognizing that this is part of Android's libc. Therefore, these functions directly provide the memory allocation mechanisms used by Android applications and the Android framework. I focused on providing concrete examples:

* Apps using `malloc`, `calloc`, `free` (which are backed by jemalloc).
* The framework allocating objects.
* NDK developers using these functions directly.

**5. Implementation Details (Conceptual):**

The prompt asks for "how the libc function is implemented."  Since we only have the header file, we can't give the exact C code. Instead, I focused on the *general principles* of how a memory allocator like jemalloc works:

* Managing a heap.
* Tracking allocated and free blocks.
* Using data structures to manage metadata.
* Handling fragmentation.
* Optimizations for speed and memory usage.

**6. Dynamic Linker Aspects:**

This requires understanding how shared libraries work in Android.

* **SO Layout:** I described the basic structure of a shared object (`.so`) file, including code, data, and the GOT/PLT.
* **Linking Process:**  I outlined the steps involved in dynamic linking: loading, symbol resolution (using GOT/PLT), and relocation.
* **Connection to `jemalloc`:** The dynamic linker needs to resolve calls to `malloc`, `free`, etc., which are provided by `libc.so` (where jemalloc resides).

**7. Assumptions, Inputs, and Outputs:**

This is about demonstrating logical reasoning. I chose examples that illustrate the behavior of some of the wrapper functions:

* `je_memalign_round_up_boundary`:  Showed how it rounds up non-power-of-two alignments.
* `je_aligned_alloc_wrapper`: Showed how it enforces the size being a multiple of the alignment.

**8. Common Usage Errors:**

I drew on common pitfalls related to memory management in C/C++:

* Memory leaks (forgetting to `free`).
* Double frees.
* Use-after-free.
* Buffer overflows (related to the allocated memory).
* Alignment errors (though the wrappers mitigate some of these).

**9. Android Framework/NDK Usage and Frida Hooking:**

This required explaining the layers of Android:

* Application uses standard library calls.
* These calls are implemented within `libc.so`.
* `libc.so` contains the jemalloc implementation (or wraps it).

For Frida, I provided examples of hooking `malloc` and `free` to demonstrate how to intercept these calls at the library level. This is a practical way to observe memory allocation behavior.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on the differences between `jemalloc` and the standard `malloc`. **Correction:**  The header file focuses on *integration* with Android, so the emphasis should be on how `jemalloc` is *used* within Android.
* **Initial thought:** Go deep into the internal algorithms of `jemalloc`. **Correction:**  Since only the header is provided, high-level concepts are more appropriate. Focus on the *purpose* of the functions rather than the exact implementation details.
* **Initial thought:**  Overcomplicate the dynamic linking explanation. **Correction:** Simplify the explanation to focus on the core concepts of symbol resolution and the role of `libc.so`.

By following these steps, combining direct observation, inference, and knowledge of Android internals, I was able to construct a comprehensive answer that addresses the different aspects of the request.
这是一个位于 `bionic/libc/bionic/jemalloc.handroid` 目录下的 C 头文件，属于 Android 的 C 库 bionic 的一部分。它主要定义了与 jemalloc 内存分配器相关的接口。jemalloc 是一个通用的、并发的 `malloc(3)` 实现，以其高性能和低碎片化而闻名。

**功能列举:**

这个头文件定义了一系列函数，主要用于内存管理，是对 jemalloc 提供的部分功能的封装和适配，以便更好地融入 Android 系统。其主要功能包括：

1. **内存分配:**  提供各种粒度的内存分配函数，例如分配指定大小的内存块。
2. **带对齐的内存分配:** 提供分配指定对齐方式的内存块的函数。
3. **内存信息获取:** 提供获取内存分配器状态和统计信息的函数。
4. **内存管理控制:** 提供控制内存分配器行为的函数，例如启用/禁用分配器。
5. **内存遍历:** 提供遍历已分配内存块的函数，用于调试和分析。

**与 Android 功能的关系及举例说明:**

jemalloc 在 Android 系统中作为默认的内存分配器，负责管理应用程序和系统服务的内存分配和释放。它对 Android 的性能和稳定性至关重要。

* **应用程序内存管理:**  Android 应用程序在执行过程中需要动态分配内存，例如创建对象、读取文件等。这些操作最终会调用到 `malloc`、`calloc`、`realloc` 和 `free` 等标准 C 库函数，而 bionic 中的这些函数正是由 jemalloc 实现的。
    * **举例:** 当一个 Java 应用程序创建一个新的 `ArrayList` 对象时，底层会调用到 Native 层的内存分配函数来为 `ArrayList` 的内部数组分配内存。这个分配操作最终会路由到 jemalloc 的实现。
* **Android Framework 服务:** Android Framework 的各种服务，例如 Activity Manager、WindowManager 等，在运行过程中也需要分配和管理内存。它们同样依赖 jemalloc 来完成这些任务。
    * **举例:**  当系统启动一个新的 Activity 时，Activity Manager 服务需要分配内存来存储 Activity 的状态信息。这个内存分配同样由 jemalloc 负责。
* **NDK 开发:**  使用 Android NDK 进行原生开发的开发者可以直接调用 C/C++ 的内存分配函数，这些函数也由 jemalloc 实现。
    * **举例:**  一个使用 NDK 开发的游戏需要动态分配内存来存储游戏对象和资源。开发者调用 `malloc` 分配的内存实际上由 jemalloc 管理。

**每一个 libc 函数的功能实现 (基于头文件推断):**

由于只提供了头文件，我们无法看到具体的实现代码。但我们可以根据函数名和注释推断其功能以及可能的实现方式：

* **`je_aligned_alloc_wrapper(size_t, size_t)`:**
    * **功能:**  分配指定大小和对齐方式的内存块。它是一个包装器，用于解决 jemalloc 自身在处理非 2 的幂对齐时的限制。
    * **实现推断:** 内部可能会先调用 jemalloc 的 `je_aligned_alloc`，如果对齐不是 2 的幂，则可能采用其他方式，例如分配更大的内存块然后调整指针位置来实现对齐。头文件中的注释表明它会强制 `size` 是 `alignment` 的倍数。

* **`je_malloc_iterate(uintptr_t, size_t, void (*)(uintptr_t, size_t, void*), void*)`:**
    * **功能:**  遍历从指定地址开始的内存块，并对每个块执行回调函数。
    * **实现推断:**  jemalloc 内部会维护已分配内存块的元数据信息。这个函数很可能通过遍历这些元数据，依次获取每个内存块的起始地址和大小，然后调用用户提供的回调函数。

* **`je_mallctl(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen)`:**
    * **功能:**  提供一种通用的方式来读取和修改 jemalloc 的内部配置参数和统计信息。
    * **实现推断:**  jemalloc 内部维护着一个包含各种控制变量和统计数据的结构。`je_mallctl` 函数通过 `name` 参数来索引到相应的变量，并根据 `oldp`、`oldlenp`、`newp` 和 `newlen` 来读取或写入值。这类似于通过字符串名称来访问和修改内部状态。

* **`struct mallinfo je_mallinfo()`:**
    * **功能:**  返回一个包含内存分配器状态信息的结构体，例如已分配的内存大小、空闲内存大小等。
    * **实现推断:**  jemalloc 内部会维护这些统计信息。`je_mallinfo` 函数简单地读取这些信息并填充到 `mallinfo` 结构体中返回。

* **`void je_malloc_disable()` 和 `void je_malloc_enable()`:**
    * **功能:**  分别用于禁用和启用 jemalloc 内存分配器。
    * **实现推断:**  jemalloc 内部可能有一个全局标志位来控制分配器的启用状态。禁用时，内存分配请求可能会返回错误或使用备用的分配机制。启用时，则恢复正常的 jemalloc 分配流程。

* **`int je_malloc_info(int options, FILE* fp)`:**
    * **功能:**  将 jemalloc 的详细信息输出到指定的文件流中，`options` 参数可以控制输出信息的详细程度。
    * **实现推断:**  jemalloc 内部会收集各种统计信息，包括内存使用情况、arena 状态等。这个函数会根据 `options` 参数格式化这些信息，并将结果写入到 `fp` 指定的文件中。

* **`int je_mallopt(int, int)`:**
    * **功能:**  用于设置内存分配器的选项，但其功能已被 `je_mallctl` 取代。
    * **实现推断:**  早期的内存分配器通常使用 `mallopt` 来设置选项。jemalloc 为了提供更灵活的控制，引入了 `je_mallctl`。`je_mallopt` 可能是为了兼容性而保留，其内部实现可能会调用 `je_mallctl` 来完成相应的操作。

* **`void* je_memalign_round_up_boundary(size_t, size_t)`:**
    * **功能:**  分配指定大小和对齐方式的内存块。与 `je_aligned_alloc_wrapper` 类似，但专门用于处理非 2 的幂的对齐，它会向上取整到最近的对齐边界。
    * **实现推断:**  它会计算出满足对齐要求的最小的 2 的幂的边界，然后使用 jemalloc 的标准分配函数分配内存，并返回对齐后的地址。

* **`void* je_pvalloc(size_t)`:**
    * **功能:**  分配大小为 `size` 的页对齐内存。
    * **实现推断:**  它会计算出分配所需页面的数量，然后调用底层的页面分配机制来分配内存，确保返回的地址是页面大小的整数倍。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

jemalloc 本身是 `libc.so` 的一部分，因此它直接影响着动态链接器的行为，但它本身不直接参与动态链接的过程。动态链接器负责加载共享库，并解析库之间的符号引用。

**SO 布局样本 (`libc.so`):**

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          ...
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         ...
  Size of section headers:           64 (bytes)
  Number of section headers:         ...
  String table index:                ...

Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x00000000XXXXXXXX 0x00000000XXXXXXXX 0x00000000000258 0x00000000000258  R      8
  INTERP         0x0000000000000298 0x00000000XXXXXXXX 0x00000000XXXXXXXX 0x0000000000001c 0x0000000000001c  R      8
      [Requesting program interpreter: /system/bin/linker64]
  LOAD           0x0000000000000000 0x00000000XXXXXXXX 0x00000000XXXXXXXX 0x00000000XXXXXX 0x00000000XXXXXX  R E    0x10000
  LOAD           0x00000000000XXXXX 0x00000000XXXXXXXX 0x00000000XXXXXXXX 0x00000000XXXXXX 0x00000000XXXXXX  RW     0x10000
  DYNAMIC        0x00000000000XXXXX 0x00000000XXXXXXXX 0x00000000XXXXXXXX 0x00000000000350 0x00000000000350  RW     8
  GNU_RELRO      0x00000000000XXXXX 0x00000000XXXXXXXX 0x00000000XXXXXXXX 0x0000000000XXXX 0x0000000000XXXX  R      8
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000 0x00000000000000 0x00000000000000  RW     0x10

Sections:
  .text          0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**4
      PROGBITS, ALLOC, EXEC, LOAD
  .rodata        0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**5
      PROGBITS, ALLOC, LOAD
  .data          0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**5
      PROGBITS, ALLOC, WRITE, LOAD
  .bss           0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**5
      NOBITS, ALLOC, WRITE, LOAD
  .dynamic       0000XXXXXXXX  0000XXXXXXXX  00000350  2**3
      DYNAMIC, ALLOC, WRITE, LOAD
  .dynsym        0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**3
      DYNSYM, ALLOC, LOAD
  .dynstr        0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**1
      STRTAB, ALLOC, LOAD
  .hash          0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**3
      HASH, ALLOC, LOAD
  .gnu.version   0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**1
      VERSYM, ALLOC, LOAD
  .gnu.version_r 0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**1
      VERNEED, ALLOC, LOAD
  .rela.dyn      0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**3
      RELA, ALLOC, LOAD
  .rela.plt      0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**3
      RELA, ALLOC, LOAD
  .plt           0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**4
      PROGBITS, ALLOC, EXEC, LOAD
  .got.plt       0000XXXXXXXX  0000XXXXXXXX  000XXXXX  2**3
      PROGBITS, ALLOC, WRITE, LOAD
  ...
  [jemalloc 的代码和数据会位于 .text, .rodata, .data, .bss 等 section 中]
```

**链接的处理过程:**

1. **编译时:** 当应用程序或共享库的代码中调用 `malloc` 等函数时，编译器会生成对这些符号的引用。
2. **链接时 (静态链接):** 如果是静态链接，`jemalloc` 的代码会被直接链接到可执行文件中。
3. **链接时 (动态链接):**  Android 系统默认使用动态链接。
    * **加载时:** 当应用程序启动或加载共享库时，动态链接器 (`/system/bin/linker64`) 会被调用。
    * **符号查找:**  动态链接器会遍历已加载的共享库的符号表（`.dynsym` section），查找被引用的符号（例如 `malloc`）。
    * **重定位:**  一旦找到符号的定义（在 `libc.so` 中，由 jemalloc 提供），动态链接器会修改调用点的地址，使其指向 `libc.so` 中 `malloc` 函数的实际地址。这个过程涉及到 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table)。
    * **GOT:** GOT 中存储着外部符号的运行时地址。PLT 中的代码负责在第一次调用时解析符号，并将解析后的地址写入 GOT。后续调用会直接跳转到 GOT 中已解析的地址。

**逻辑推理，假设输入与输出:**

**假设输入:**

* 调用 `je_memalign_round_up_boundary(10, 7)`  (分配 10 字节，对齐到 7 字节边界)
* 调用 `je_aligned_alloc_wrapper(8, 3)` (分配 8 字节，对齐到 3 字节边界)

**输出:**

* `je_memalign_round_up_boundary(10, 7)`: 返回一个指向至少 10 字节大小的内存块的指针，该指针的地址是 8 的倍数（因为 8 是大于 7 的最小的 2 的幂）。
* `je_aligned_alloc_wrapper(8, 3)`:  由于 8 不是 3 的倍数，根据头文件注释，`je_aligned_alloc_wrapper` 会执行某些操作（具体实现未知，但很可能失败或返回错误，或者分配更大的空间来满足条件）。

**用户或编程常见的使用错误:**

1. **内存泄漏:** 分配了内存但忘记释放 (`free`)，导致内存占用不断增加。
   ```c
   void test_leak() {
       void *ptr = malloc(100);
       // 忘记 free(ptr);
   }
   ```
2. **重复释放 (Double Free):** 多次释放同一块内存，导致内存管理器的状态混乱。
   ```c
   void test_double_free() {
       void *ptr = malloc(100);
       free(ptr);
       free(ptr); // 错误！
   }
   ```
3. **使用已释放的内存 (Use-After-Free):**  释放内存后仍然尝试访问该内存，导致未定义行为。
   ```c
   void test_use_after_free() {
       void *ptr = malloc(100);
       free(ptr);
       memset(ptr, 0, 100); // 错误！
   }
   ```
4. **缓冲区溢出:** 写入的数据超过了分配的内存大小，可能覆盖其他数据或导致程序崩溃。
   ```c
   void test_overflow() {
       char *buffer = malloc(10);
       strcpy(buffer, "This is a long string"); // 错误！缓冲区溢出
       free(buffer);
   }
   ```
5. **对齐错误:** 在需要特定对齐的场景下使用了不满足对齐要求的指针，可能导致性能问题或崩溃（尤其是在使用 SIMD 指令等场景）。
   ```c
   void test_alignment() {
       void *ptr = malloc(10); // 默认对齐可能不足以满足某些需求
       // ... 使用 ptr 进行需要更高对齐的操作 ...
       free(ptr);
   }
   ```

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤:**

**Android Framework 到 jemalloc 的路径:**

1. **Java 代码请求分配内存:**  Android Framework 的 Java 代码（例如在创建对象时）会调用到虚拟机 (Dalvik/ART) 的内存分配机制。
2. **虚拟机调用 Native 代码:** 虚拟机内部需要分配 Native 内存来支持 Java 对象的存储和其他操作。这会调用到 Native 层的内存分配函数。
3. **Native 层调用 libc 函数:** 虚拟机最终会调用到 bionic 库提供的标准 C 库函数，例如 `malloc`。
4. **libc 函数调用 jemalloc:** bionic 库中的 `malloc` 等函数的实现实际上是 jemalloc 提供的。

**NDK 到 jemalloc 的路径:**

1. **NDK 代码调用标准 C 库函数:**  NDK 开发者在 C/C++ 代码中直接调用 `malloc`, `free` 等函数。
2. **libc 函数调用 jemalloc:**  这些标准 C 库函数在 bionic 中由 jemalloc 实现。

**Frida Hook 示例:**

可以使用 Frida 来 hook `malloc` 函数，观察其调用栈和参数，从而追踪内存分配的来源。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['thread_id'], message['payload']['message']))
    else:
        print(message)

package_name = "your.app.package.name"  # 替换为你要调试的应用包名

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function(args) {
        var size = args[0].toInt();
        var threadId = Process.getCurrentThreadId();
        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n');
        send({ 'thread_id': threadId, 'message': 'malloc called with size: ' + size + '\\nBacktrace:\\n' + backtrace });
    },
    onLeave: function(retval) {
        // console.log('malloc returned: ' + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "free"), {
    onEnter: function(args) {
        var ptr = args[0];
        var threadId = Process.getCurrentThreadId();
        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n');
        send({ 'thread_id': threadId, 'message': 'free called with pointer: ' + ptr + '\\nBacktrace:\\n' + backtrace });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

1. **`frida.attach(package_name)`:** 连接到目标 Android 应用程序。
2. **`Module.findExportByName("libc.so", "malloc")`:**  在 `libc.so` 中查找 `malloc` 函数的地址。
3. **`Interceptor.attach(...)`:**  拦截对 `malloc` 函数的调用。
4. **`onEnter`:**  在 `malloc` 函数执行之前执行。
   - `args[0].toInt()`: 获取 `malloc` 的 `size` 参数。
   - `Process.getCurrentThreadId()`: 获取当前线程 ID。
   - `Thread.backtrace(...)`: 获取调用栈信息。
   - `send(...)`:  将信息发送回 Frida 主机。
5. **`onLeave`:** 在 `malloc` 函数执行之后执行 (本例中注释掉了)。
6. **类似地，Hook 了 `free` 函数来观察内存释放操作。**

运行这个 Frida 脚本后，当目标应用程序执行内存分配和释放操作时，Frida 会打印出调用 `malloc` 和 `free` 的线程 ID、分配的大小（对于 `malloc`）以及调用栈信息，从而帮助你追踪内存分配的来源，了解 Android Framework 或 NDK 代码是如何一步步调用到 jemalloc 的。

### 提示词
```
这是目录为bionic/libc/bionic/jemalloc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2012 The Android Open Source Project
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

#pragma once

#include <jemalloc/jemalloc.h>
#include <malloc.h>  // For struct mallinfo.

// Need to wrap memalign since je_memalign fails on non-power of 2 alignments.
#define je_memalign je_memalign_round_up_boundary

// Need to wrap aligned_alloc since je_aligned_alloc does not enforce
// that size is a multiple of alignment.
#define je_aligned_alloc je_aligned_alloc_wrapper

__BEGIN_DECLS

void* je_aligned_alloc_wrapper(size_t, size_t);
int je_malloc_iterate(uintptr_t, size_t, void (*)(uintptr_t, size_t, void*), void*);
int je_mallctl(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) __attribute__((nothrow));
struct mallinfo je_mallinfo();
void je_malloc_disable();
void je_malloc_enable();
int je_malloc_info(int options, FILE* fp);
int je_mallopt(int, int);
void* je_memalign_round_up_boundary(size_t, size_t);
void* je_pvalloc(size_t);

__END_DECLS
```