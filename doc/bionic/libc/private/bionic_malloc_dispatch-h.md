Response:
Let's break down the thought process for answering the prompt about `bionic_malloc_dispatch.h`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided header file and explain its purpose within the Android Bionic library. The prompt specifically asks for:

* Functionality listing.
* Relationship to Android (with examples).
* Detailed explanations of libc functions.
* Dynamic linker aspects (SO layout, linking process).
* Logic with hypothetical inputs/outputs.
* Common usage errors.
* How the code is reached from the Android framework/NDK (with Frida hook example).

**2. Initial Analysis of the Header File:**

The first step is to recognize the structure of the header. It defines:

* **Typedefs for function pointers:** These function pointers have specific signatures (`size_t, size_t` for `MallocCalloc`, `void*` for `MallocFree`, etc.). This immediately suggests a dispatch table or interface for different memory allocation implementations. The naming convention `Malloc*` reinforces this idea.
* **A `MallocDispatch` struct:** This struct contains members that are precisely those function pointer typedefs. The `__attribute__((aligned(32)))` suggests alignment requirements, likely for performance or specific memory management strategies.
* **Conditional compilation (`#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)`)**:  This indicates that certain functions (like `pvalloc` and `valloc`) might not always be present, depending on the build configuration.

**3. Deducing Functionality:**

Based on the function pointer names and common C library knowledge, we can deduce the core functionalities:

* **Basic allocation/deallocation:** `malloc`, `calloc`, `free`, `realloc`.
* **Size information:** `malloc_usable_size`.
* **Alignment:** `memalign`, `posix_memalign`, `aligned_alloc`.
* **Memory management introspection:** `mallinfo`, `malloc_info`, `malloc_iterate`.
* **Control:** `malloc_disable`, `malloc_enable`, `mallopt`.
* **Deprecated functions:** `pvalloc`, `valloc`.

**4. Connecting to Android:**

Knowing this is part of Bionic, Android's C library, the connection is direct. Android apps and system components use these functions for memory management. Examples are easy to generate: allocating memory for a string, a bitmap, or a data structure.

**5. Explaining libc Function Implementations:**

This requires some background knowledge about how memory allocators work. Key concepts include:

* **Heap management:**  The allocator manages a region of memory (the heap).
* **Metadata:**  Each allocated block needs metadata (size, free/used status, etc.).
* **Strategies:** Different allocators use different strategies (e.g., best-fit, first-fit). Bionic likely uses a sophisticated allocator like jemalloc or a variant.
* **System calls:** Ultimately, `malloc` and its siblings interact with the kernel (e.g., via `mmap`, `brk`).

The explanation should touch upon these concepts without getting *too* deep into the implementation details (since the header file doesn't provide that). The focus should be on the general idea.

**6. Addressing Dynamic Linker Aspects:**

The `MallocDispatch` structure strongly suggests a mechanism for *choosing* which memory allocator implementation to use. This is where the dynamic linker comes in.

* **SO Layout:**  Imagine different shared libraries (`.so` files) potentially using different memory allocators (though in practice, Bionic provides the standard one). The SO layout would include the code for the allocator functions.
* **Linking Process:** The dynamic linker resolves symbols at runtime. When an application calls `malloc`, the linker needs to find the correct implementation. The `MallocDispatch` table acts as an indirection layer, allowing the linker (or Bionic's initialization code) to populate the table with the appropriate function pointers.

A sample SO layout would show the `malloc` function residing within `libc.so`. The linking process involves symbol resolution and relocation.

**7. Logic with Hypothetical Inputs/Outputs:**

For each function, a simple example demonstrating its behavior is helpful. For `malloc`, the input is a size, and the output is a memory address (or NULL on failure). For `free`, the input is a memory address.

**8. Common Usage Errors:**

This draws on common C/C++ memory management pitfalls:

* **Memory leaks:** Forgetting to `free` allocated memory.
* **Double frees:** Calling `free` on the same memory twice.
* **Use-after-free:** Accessing memory after it has been freed.
* **Buffer overflows:** Writing beyond the allocated bounds.
* **Incorrect `realloc` usage:**  Not handling the return value correctly.

**9. Tracing from Android Framework/NDK:**

This requires understanding the call stack. A high-level explanation would involve:

* An app making an allocation request.
* The request going through the Android runtime (ART for Java/Kotlin, or directly for native code).
* The request eventually reaching the C library (`libc`).
* The call being dispatched through the `MallocDispatch` table to the actual allocator implementation.

The Frida hook example should demonstrate how to intercept the `malloc` call and inspect its arguments and return value. Focus on hooking the functions defined in the `MallocDispatch` struct.

**10. Structuring the Answer:**

Organize the information logically using headings and bullet points for readability. Start with a summary of the file's purpose, then address each point from the prompt.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file *implements* the allocators.
* **Correction:**  The function pointers suggest it's a dispatch mechanism, not the implementation itself.
* **Further refinement:** The `__attribute__((aligned(32)))` is important and should be mentioned as a potential optimization or requirement.
* **Ensuring clarity:** Use clear and concise language, avoiding overly technical jargon where possible. Provide concrete examples.

By following this thought process, breaking down the request into manageable parts, and leveraging existing knowledge of C/C++ and Android, we can generate a comprehensive and accurate answer.
这个头文件 `bionic_malloc_dispatch.h` 定义了一个函数指针结构体 `MallocDispatch`，它本质上是一个 **内存分配器操作的函数表 (function dispatch table)**。 这个表允许 Android Bionic C 库在运行时选择或切换不同的内存分配器实现。

**它的主要功能是提供一个抽象层，将内存分配和释放的接口与具体的实现分离。** 这样做的目的是为了：

* **灵活性：** 可以在不修改调用代码的情况下替换底层的内存分配器。例如，可以切换到性能更好的分配器或用于调试目的的分配器。
* **可测试性：**  可以方便地注入自定义的内存分配器进行单元测试或性能分析。
* **兼容性：**  允许不同组件或库使用不同的分配策略，虽然在 Android 中，通常会使用一个统一的分配器。

**与 Android 功能的关系及其举例说明：**

这个文件是 Android 底层基础设施的关键部分。几乎所有在 Android 上运行的进程都需要进行内存分配，无论是 Java 层的应用，还是 Native (C/C++) 层的系统服务或应用。

* **Android Framework:** 当一个 Java 对象被创建时，Android Runtime (ART) 或 Dalvik 需要在堆上分配内存。虽然 ART/Dalvik 有自己的垃圾回收机制，但在 Native 代码中分配的内存最终会通过 `malloc` 等函数进行。
    * **例子：**  当你在 Java 中创建一个 `Bitmap` 对象时，底层的像素数据很可能是在 Native 堆上分配的，最终会调用到 `malloc` 或 `calloc`。
* **NDK (Native Development Kit):**  使用 NDK 开发的 Android 应用可以直接调用 `malloc`, `free`, `calloc`, `realloc` 等标准 C 库的内存分配函数。这些函数最终会通过 `MallocDispatch` 表中指向的实际分配器函数来执行。
    * **例子：**  一个游戏引擎使用 NDK 进行开发，它会频繁地分配和释放内存来管理游戏对象、纹理等资源。这些分配操作会最终通过 Bionic 的内存分配器。
* **系统服务 (System Services):**  Android 的各种系统服务，如 `SurfaceFlinger`, `AudioFlinger` 等，都是用 C++ 编写的，它们会使用 Bionic 的内存分配函数来管理内部数据结构。
    * **例子：**  `SurfaceFlinger` 负责屏幕合成，它需要分配内存来管理图层、缓冲区等信息。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身 **没有实现** 这些 libc 函数，它只是定义了指向这些函数的函数指针类型。 实际的实现位于 Bionic C 库的其他源文件中，通常是在 `bionic/libc/bionic/malloc_*.c` 或类似的目录中。

`MallocDispatch` 结构体定义了以下函数指针类型，对应着常见的内存管理函数：

* **`MallocCalloc calloc;`**: `calloc(size_t num, size_t size)` 分配 `num * size` 字节的内存，并将分配的内存初始化为零。
    * **实现原理：**  通常会在堆上找到一块足够大的连续内存块，将其标记为已分配，并在返回之前用零填充该内存块。
* **`MallocFree free;`**: `free(void* ptr)`  释放之前通过 `malloc`, `calloc`, `realloc` 等分配的内存块。
    * **实现原理：**  根据 `ptr` 指向的内存块的元数据（例如，大小），将该内存块标记为未分配，使其可以被后续的分配操作重用。为了避免悬挂指针，调用 `free` 后应该将指向已释放内存的指针设置为 `NULL`。
* **`MallocMallinfo mallinfo;`**: `struct mallinfo mallinfo()` 返回包含有关堆使用情况统计信息的结构体。
    * **实现原理：**  遍历内存分配器的内部数据结构，统计已分配的块数、空闲的块数、总堆大小等信息。
* **`MallocMalloc malloc;`**: `malloc(size_t size)` 分配至少 `size` 字节的内存，但不初始化。
    * **实现原理：**  在堆上找到一块足够大的连续内存块，将其标记为已分配，并返回指向该内存块的指针。
* **`MallocMallocInfo malloc_info;`**: `int malloc_info(int options, FILE *stream)`  将内存分配器的详细信息输出到指定的流。
    * **实现原理：**  遍历内存分配器的内部数据结构，并将各种信息（如分配策略、内存碎片情况等）格式化输出到 `stream`。
* **`MallocMallocUsableSize malloc_usable_size;`**: `size_t malloc_usable_size(const void* ptr)` 返回由 `ptr` 指向的已分配内存块的可用大小（可能大于请求的大小）。
    * **实现原理：**  根据 `ptr` 指向的内存块的元数据，获取实际分配的内存大小。这个大小可能由于内存分配器的对齐或管理开销而略大于请求的大小。
* **`MallocMemalign memalign;`**: `void* memalign(size_t alignment, size_t size)` 分配至少 `size` 字节的内存，并保证返回的指针是 `alignment` 的倍数。`alignment` 必须是 2 的幂。
    * **实现原理：**  可能需要分配比请求更大的内存块，以便在其中找到满足对齐要求的地址。未使用的部分可能会被浪费。
* **`MallocPosixMemalign posix_memalign;`**: `int posix_memalign(void **memptr, size_t alignment, size_t size)`  与 `memalign` 功能类似，但增加了错误处理，通过 `memptr` 返回分配的内存地址。`alignment` 必须是 2 的幂次且是 `sizeof(void*)` 的倍数。
    * **实现原理：**  与 `memalign` 类似，但如果分配失败，会返回错误码而不是 `NULL`。
* **`MallocRealloc realloc;`**: `void* realloc(void* ptr, size_t size)`  调整之前分配的内存块的大小。
    * **实现原理：**
        * 如果 `ptr` 为 `NULL`，则相当于 `malloc(size)`。
        * 如果 `size` 为 0，则相当于 `free(ptr)`。
        * 如果 `ptr` 不为 `NULL` 且 `size` 大于原始大小，可能会尝试在原位置扩展内存块。如果无法扩展，则会分配一块新的内存，将原数据拷贝到新内存，并释放原内存块。
        * 如果 `ptr` 不为 `NULL` 且 `size` 小于原始大小，可能会直接截断内存块，也可能分配新的更小的内存块并将数据拷贝过去。
* **`MallocIterate malloc_iterate;`**: `int malloc_iterate(uintptr_t base, size_t size, void (*callback)(uintptr_t, size_t, void*), void *arg)` 遍历指定地址范围内的已分配内存块，并对每个块调用回调函数。
    * **实现原理：**  遍历内存分配器的内部数据结构，找到指定范围内的已分配块，并将每个块的起始地址和大小传递给回调函数。
* **`MallocMallocDisable malloc_disable;`**: `void malloc_disable()` 禁用内存分配器（可能用于调试或特定场景）。
    * **实现原理：**  具体实现取决于分配器，可能会设置一个标志位来阻止新的分配操作。
* **`MallocMallocEnable malloc_enable;`**: `void malloc_enable()` 启用之前禁用的内存分配器。
    * **实现原理：**  清除之前设置的禁用标志。
* **`MallocMallopt mallopt;`**: `int mallopt(int cmd, int value)`  用于调整内存分配器的各种参数。
    * **实现原理：**  根据 `cmd` 参数修改内存分配器的内部配置，例如调整内存池大小、设置释放策略等。具体的 `cmd` 和 `value` 取决于具体的分配器实现。
* **`MallocAlignedAlloc aligned_alloc;`**: `void* aligned_alloc(size_t alignment, size_t size)`  类似于 `memalign` 和 `posix_memalign`，C11 引入的标准，分配 `size` 字节的内存，并保证返回的指针是 `alignment` 的倍数。`alignment` 必须是 2 的幂次且是有效的大小值。
    * **实现原理：** 与 `memalign` 类似，但通常是更推荐的用于内存对齐分配的函数，因为它更清晰且避免了 `posix_memalign` 中 `memptr` 的使用。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

虽然 `bionic_malloc_dispatch.h` 本身不直接参与动态链接，但它所定义的函数表是动态链接器需要处理的关键部分。

**SO 布局样本 (以 `libc.so` 为例):**

```
libc.so:
  .text:  # 代码段
    ...
    malloc:  # malloc 函数的实现代码
    free:    # free 函数的实现代码
    calloc:  # calloc 函数的实现代码
    ...
  .data:  # 已初始化数据段
    ...
    __malloc_dispatch: # MallocDispatch 结构体的实例
    ...
  .bss:   # 未初始化数据段
    ...
  .dynsym: # 动态符号表 (包含导出的符号)
    malloc
    free
    calloc
    __malloc_dispatch
    ...
  .dynstr: # 动态字符串表 (符号名字符串)
    ...
  .rel.dyn: # 动态重定位表 (在加载时需要调整的地址)
    ...
```

**链接的处理过程：**

1. **编译时：** 当一个程序或共享库调用 `malloc` 时，编译器会生成对 `malloc` 符号的未解析引用。
2. **链接时（静态链接，不常见于 Android 应用）：** 静态链接器会将所有依赖的库的代码合并到最终的可执行文件中，并解析所有符号引用。
3. **运行时（动态链接，Android 常用）：**
   * 当程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载程序依赖的共享库，例如 `libc.so`。
   * 动态链接器会解析未解析的符号引用。当遇到对 `malloc` 的调用时，它会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `malloc` 的地址。
   * **关键点：**  动态链接器也会找到 `__malloc_dispatch` 这个符号，它指向 `MallocDispatch` 结构体的实例。
   * Bionic 的初始化代码会在 `libc.so` 加载时运行，它会将实际的内存分配器函数的地址（`malloc` 在 `libc.so` 中的实现地址）赋值给 `__malloc_dispatch.malloc` 成员，`free` 的实现地址赋值给 `__malloc_dispatch.free`，以此类推。
   * 因此，当程序调用 `malloc` 时，实际上会跳转到 `__malloc_dispatch.malloc` 指向的地址，即 `libc.so` 中 `malloc` 的实现代码。

**假设输入与输出 (逻辑推理):**

假设有一个函数调用了 `malloc(1024)`:

* **假设输入：** `size = 1024`
* **逻辑推理：**
    1. 程序调用 `malloc(1024)`.
    2. 由于动态链接，实际上调用的是 `__malloc_dispatch.malloc(1024)`.
    3. `__malloc_dispatch.malloc` 指向 `libc.so` 中 `malloc` 的实现。
    4. `libc.so` 的 `malloc` 实现会在堆上找到一块至少 1024 字节的空闲内存块。
    5. `malloc` 会返回指向该内存块起始地址的指针。
* **假设输出：** 一个有效的内存地址（例如 `0x12345678`），或者如果分配失败则返回 `NULL`。

假设有一个函数调用了 `free(ptr)`，其中 `ptr` 是之前通过 `malloc` 分配的内存地址：

* **假设输入：** `ptr = 0x12345678` (之前分配的地址)
* **逻辑推理：**
    1. 程序调用 `free(0x12345678)`.
    2. 实际上调用的是 `__malloc_dispatch.free(0x12345678)`.
    3. `__malloc_dispatch.free` 指向 `libc.so` 中 `free` 的实现。
    4. `libc.so` 的 `free` 实现会根据 `ptr` 找到对应的内存块，并将其标记为空闲。
* **假设输出：** 无返回值（`void`）。但其副作用是释放了 `ptr` 指向的内存。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **内存泄漏 (Memory Leak):**  分配了内存但忘记释放。
   ```c
   void foo() {
       void* ptr = malloc(1024);
       // ... 使用 ptr，但忘记 free(ptr);
   } // ptr 指向的内存无法被回收
   ```
2. **重复释放 (Double Free):**  对同一块内存调用 `free` 多次。
   ```c
   void foo() {
       void* ptr = malloc(1024);
       free(ptr);
       free(ptr); // 错误！导致堆损坏
   }
   ```
3. **使用已释放的内存 (Use-After-Free):**  在 `free` 之后继续访问已释放的内存。
   ```c
   void foo() {
       void* ptr = malloc(1024);
       free(ptr);
       * (int*)ptr = 10; // 错误！访问已释放的内存
   }
   ```
4. **野指针 (Wild Pointer):**  指针指向的内存已经无效（例如，指向栈上的局部变量在函数返回后）。
   ```c
   int* foo() {
       int x = 10;
       return &x; // 返回指向局部变量的指针
   }

   void bar() {
       int* ptr = foo();
       *ptr = 20; // 错误！访问已失效的栈内存
   }
   ```
5. **缓冲区溢出 (Buffer Overflow):**  写入超过分配大小的内存。
   ```c
   void foo() {
       char* buffer = (char*)malloc(10);
       strcpy(buffer, "This is a long string"); // 错误！溢出 buffer
       free(buffer);
   }
   ```
6. **`realloc` 使用不当:**  没有检查 `realloc` 的返回值，或者在 `realloc` 失败后继续使用旧指针。
   ```c
   void foo() {
       void* ptr = malloc(10);
       ptr = realloc(ptr, 2048);
       if (ptr == NULL) {
           // 处理 realloc 失败的情况，但如果没有检查，旧的 ptr 可能已经失效
       } else {
           // 使用新的 ptr
       }
   }
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `bionic_malloc_dispatch.h` 的路径 (以 Java 代码分配内存为例):**

1. **Java 代码请求分配内存：** 例如，创建一个 `Bitmap` 对象。
   ```java
   Bitmap bitmap = Bitmap.createBitmap(100, 100, Bitmap.Config.ARGB_8888);
   ```
2. **Framework 层调用 Native 代码：**  `Bitmap.createBitmap` 的实现最终会调用到 Native 代码 (C++)。这通常通过 JNI (Java Native Interface) 完成。
3. **Native 代码调用 Bionic 的内存分配函数：** 在 Native 代码中，可能会调用 `malloc`, `calloc` 等函数来分配存储 Bitmap 像素数据的内存。
   ```c++
   // 在 Skia 库或 Android Framework 的 Native 代码中
   void* pixels = calloc(width * height * 4, 1);
   ```
4. **调用 `__malloc_dispatch` 中的函数指针：** Bionic C 库中的 `calloc` 实现会间接地通过 `__malloc_dispatch.calloc` 来调用实际的分配器实现。

**NDK 到 `bionic_malloc_dispatch.h` 的路径:**

1. **NDK 应用调用标准 C 库函数：**  使用 NDK 开发的应用程序可以直接调用 `malloc`, `free` 等。
   ```c
   // NDK 应用代码
   void* data = malloc(256);
   ```
2. **链接到 Bionic C 库：** NDK 应用在编译链接时会链接到 Android 系统的 Bionic C 库 (`libc.so`).
3. **调用 `__malloc_dispatch` 中的函数指针：**  与 Framework 类似，NDK 应用调用的 `malloc` 等函数实际上会通过 `__malloc_dispatch` 中的函数指针来执行。

**Frida Hook 示例：**

可以使用 Frida Hook 来拦截对 `malloc` 函数的调用，并查看其参数和返回值。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function(args) {
        var size = args[0].toInt();
        console.log("[Malloc] Size: " + size);
    },
    onLeave: function(retval) {
        console.log("[Malloc] Returned address: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "free"), {
    onEnter: function(args) {
        var address = args[0];
        console.log("[Free] Address: " + address);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 步骤解释：**

1. **导入 Frida 库：**  `import frida`
2. **指定目标应用包名：**  `package_name = "你的应用包名"`
3. **连接到设备并附加到进程：**  `frida.get_usb_device().attach(package_name)`
4. **编写 Frida 脚本：**
   * `Module.findExportByName("libc.so", "malloc")`:  找到 `libc.so` 中导出的 `malloc` 函数的地址。
   * `Interceptor.attach(...)`:  拦截对 `malloc` 函数的调用。
   * `onEnter`:  在 `malloc` 函数执行之前调用，可以访问参数 (`args`)。这里打印了分配的大小。
   * `onLeave`:  在 `malloc` 函数执行之后调用，可以访问返回值 (`retval`)。这里打印了分配的内存地址。
   * 类似地，Hook 了 `free` 函数，打印要释放的内存地址。
5. **创建并加载脚本：** `session.create_script(script_code)`, `script.on('message', on_message)`, `script.load()`
6. **保持脚本运行：** `sys.stdin.read()`

运行此 Frida 脚本后，当目标应用进行内存分配和释放操作时，Frida 控制台会打印出相应的日志，显示分配的大小和内存地址。你可以修改脚本来 Hook 其他内存分配函数，例如 `calloc`, `realloc` 等，以更深入地了解内存分配的行为。

**总结：**

`bionic_malloc_dispatch.h` 定义了一个内存分配器操作的函数表，它是 Android Bionic C 库中实现内存管理的关键抽象层。Android Framework 和 NDK 最终都会通过这个函数表来调用实际的内存分配器实现。使用 Frida 可以方便地 Hook 这些函数，从而调试和分析 Android 应用的内存分配行为。

### 提示词
```
这是目录为bionic/libc/private/bionic_malloc_dispatch.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _PRIVATE_BIONIC_MALLOC_DISPATCH_H
#define _PRIVATE_BIONIC_MALLOC_DISPATCH_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <private/bionic_config.h>

// Entry in malloc dispatch table.
typedef void* (*MallocCalloc)(size_t, size_t);
typedef void (*MallocFree)(void*);
typedef struct mallinfo (*MallocMallinfo)();
typedef void* (*MallocMalloc)(size_t);
typedef int (*MallocMallocInfo)(int, FILE*);
typedef size_t (*MallocMallocUsableSize)(const void*);
typedef void* (*MallocMemalign)(size_t, size_t);
typedef int (*MallocPosixMemalign)(void**, size_t, size_t);
typedef void* (*MallocRealloc)(void*, size_t);
typedef int (*MallocIterate)(uintptr_t, size_t, void (*)(uintptr_t, size_t, void*), void*);
typedef void (*MallocMallocDisable)();
typedef void (*MallocMallocEnable)();
typedef int (*MallocMallopt)(int, int);
typedef void* (*MallocAlignedAlloc)(size_t, size_t);

#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
typedef void* (*MallocPvalloc)(size_t);
typedef void* (*MallocValloc)(size_t);
#endif

struct MallocDispatch {
  MallocCalloc calloc;
  MallocFree free;
  MallocMallinfo mallinfo;
  MallocMalloc malloc;
  MallocMallocUsableSize malloc_usable_size;
  MallocMemalign memalign;
  MallocPosixMemalign posix_memalign;
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  MallocPvalloc pvalloc;
#endif
  MallocRealloc realloc;
#if defined(HAVE_DEPRECATED_MALLOC_FUNCS)
  MallocValloc valloc;
#endif
  MallocIterate malloc_iterate;
  MallocMallocDisable malloc_disable;
  MallocMallocEnable malloc_enable;
  MallocMallopt mallopt;
  MallocAlignedAlloc aligned_alloc;
  MallocMallocInfo malloc_info;
} __attribute__((aligned(32)));

#endif
```