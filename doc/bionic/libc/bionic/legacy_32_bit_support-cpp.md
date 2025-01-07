Response:
Let's break down the thought process to generate the detailed explanation of `legacy_32_bit_support.cpp`.

**1. Understanding the Core Purpose:**

The first and most crucial step is recognizing the file's name and the `#if defined(__LP64__)` check. This immediately signals that the file's *raison d'être* is to provide 32-bit compatibility shims/wrappers on a system that might have underlying 64-bit support. The comment `This code is only needed on 32-bit systems!` reinforces this.

**2. Identifying the Targeted System Calls and libc Functions:**

Next, I would scan the file for the functions it defines (like `lseek64`, `pread`, `pwrite`, etc.) and the underlying system calls it invokes (like `__llseek`, `pread64`, `pwrite64`, `prlimit64`, `__mmap2`, `__mremap`). This reveals the core functionality being addressed. The presence of `64` in some function names suggests they are bridging the gap between 32-bit and 64-bit representations of data (like file offsets and resource limits).

**3. Analyzing Each Function Individually:**

For each defined function, the thought process would be:

* **What problem does this function solve on a 32-bit system?**  The key is the limitations of 32-bit integers. They can't directly represent file offsets or resource limits that exceed 4GB.
* **What underlying 64-bit system call does it use?**  This is usually explicitly stated in the code (e.g., `pread64`, `pwrite64`, `prlimit64`).
* **How does it convert between 32-bit and 64-bit representations?** This involves casting (`static_cast<off64_t>(offset)`) and potentially bit manipulation (like the `__llseek` example).
* **Are there any special considerations or error handling?**  Look for `errno` assignments and checks for invalid input. For example, the `mmap64` function has checks for negative offsets and alignment.
* **What's the purpose of the `extern "C"` declarations?**  This signifies interaction with system calls or other C-style interfaces.

**4. Connecting to Android Functionality:**

Once the individual functions are understood, the next step is to relate them to Android. The core idea is that Android, even on 32-bit architectures, needs to handle potentially large files and resources. Examples should illustrate how these functions enable this. For example, accessing large files in the file system, managing memory mappings for large applications, and controlling resource limits for processes.

**5. Delving into the Dynamic Linker (if applicable):**

While this specific file doesn't directly implement dynamic linking, the functions it provides are *used* by dynamically linked libraries. Therefore, the explanation needs to touch upon how the dynamic linker resolves symbols and how 32-bit applications interact with potentially 64-bit aware libraries or the kernel. The concept of PLT/GOT is relevant here. A simplified SO layout helps visualize this.

**6. Identifying Common Usage Errors:**

Based on the function signatures and their purpose, common errors can be inferred. For example, passing a negative offset to `lseek64`, forgetting to handle potential errors from these functions (checking return values), or misunderstandings about the limitations of 32-bit address spaces.

**7. Tracing the Execution Path (Framework/NDK):**

This is where we bridge the gap from high-level Android components to the low-level bionic library. The thought process here is to follow the typical path:

* **High-level framework:**  An app makes a request (e.g., file access).
* **System services:** The request is handled by system services (written in Java or native code).
* **NDK:**  If the app uses native code (via the NDK), the native code will call standard C library functions.
* **Bionic:** These C library calls are implemented in bionic, and this is where the functions in `legacy_32_bit_support.cpp` come into play.

A simplified call stack and an example using `open()` and `lseek()` illustrate this.

**8. Crafting Frida Hooks:**

For debugging and analysis, Frida is a powerful tool. The thought process for creating Frida hooks is:

* **Identify the target functions:** The functions defined in the file.
* **Determine what information to log:** Function arguments, return values, and potentially error codes.
* **Write the JavaScript code:** Use Frida's API to intercept function calls and log the desired information.

**9. Structuring the Answer:**

Finally, organize the information logically:

* Start with the file's overall purpose.
* Detail the functionality of each function.
* Connect to Android functionality with examples.
* Explain the (indirect) relationship to the dynamic linker.
* Discuss common usage errors.
* Describe the path from the framework/NDK to these functions.
* Provide Frida hook examples.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus only on the direct functionality of each function.
* **Correction:** Realize the need to explain the *why* – the 32-bit limitations that necessitate these wrappers.
* **Initial thought:**  Ignore the dynamic linker since it's not directly implemented here.
* **Correction:** Understand that these functions are part of the interface used by dynamically linked libraries, so mentioning the linker's role in symbol resolution is important.
* **Initial thought:**  Provide very technical explanations.
* **Correction:** Balance technical details with clear, understandable explanations and examples. Use analogies if helpful.

By following these steps, including analyzing the code, understanding the context, and thinking about potential usage scenarios, a comprehensive and accurate explanation of `legacy_32_bit_support.cpp` can be generated.
这个文件 `bionic/libc/bionic/legacy_32_bit_support.cpp` 的主要功能是 **在 32 位 Android 系统上提供对某些 64 位相关系统调用的兼容性支持**。由于 32 位架构的限制，它无法直接处理 64 位的数据类型（例如 `off64_t`，用于表示大文件偏移量）和某些 64 位的系统调用。这个文件中的函数作为**包装器**，将 32 位的调用转换为相应的 64 位系统调用，从而使得即使在 32 位系统上也能处理超出 4GB 大小的文件或使用需要 64 位参数的接口。

**功能列表:**

1. **`lseek64(int fd, off64_t off, int whence)`:**  提供 64 位的文件偏移量查找功能。在 32 位系统中，原生的 `lseek` 函数只能处理 32 位的偏移量。`lseek64` 通过调用底层的 `__llseek` 系统调用来实现，该系统调用接受两个 32 位参数来表示 64 位的偏移量。

2. **`pread(int fd, void* buf, size_t byte_count, off_t offset)`:**  提供带有偏移量的读取文件功能。在 32 位系统中，原生的 `pread` 函数使用 32 位的 `off_t` 偏移量。这个函数将其转换为 64 位的 `off64_t` 并调用 `pread64`。

3. **`pwrite(int fd, const void* buf, size_t byte_count, off_t offset)`:** 提供带有偏移量的写入文件功能。与 `pread` 类似，它将 32 位的偏移量转换为 64 位并调用 `pwrite64`。

4. **`fallocate(int fd, int mode, off_t offset, off_t length)`:** 提供预分配文件空间的功能。它将 32 位的偏移量和长度转换为 64 位并调用 `fallocate64`。

5. **`getrlimit64(int resource, rlimit64* limits64)`:** 获取进程资源限制的 64 位版本。由于 32 位系统没有 `getrlimit64` 系统调用，它使用 `prlimit64`，并将进程 ID 设置为 0（表示当前进程）。

6. **`setrlimit64(int resource, const rlimit64* limits64)`:** 设置进程资源限制的 64 位版本。同样使用 `prlimit64`，进程 ID 为 0。

7. **`prlimit(pid_t pid, int resource, const rlimit* n32, rlimit* o32)`:** 提供设置和获取进程资源限制的功能，兼容 32 位和 64 位的数据结构。它内部将 32 位的 `rlimit` 结构体转换为 64 位的 `rlimit64` 结构体，然后调用 `prlimit64`。

8. **`mmap64(void* addr, size_t size, int prot, int flags, int fd, off64_t offset)`:** 提供 64 位偏移量的内存映射功能。在 32 位系统中，通常使用 `mmap`，其偏移量是 32 位的。`mmap64` 通过调用 `__mmap2` 系统调用来实现，该系统调用的偏移量以 4KB 的块为单位，从而允许映射超过 4GB 的文件部分。

9. **`mmap(void* addr, size_t size, int prot, int flags, int fd, off_t offset)`:**  32 位版本的 `mmap`，它内部调用 `mmap64`，将 32 位的偏移量转换为 64 位。

10. **`mremap(void* old_address, size_t old_size, size_t new_size, int flags, ...)`:** 重新映射内存区域。在 32 位系统中，该函数调用底层的 `__mremap`。

11. **`mseal(void*, size_t, unsigned long)`:**  这是一个在 LP64 (Long Pointer 64-bit) 系统上才有的功能，用于密封内存映射，防止进一步修改。在 32 位系统中，该函数直接返回错误 `ENOSYS` (功能未实现)。

**与 Android 功能的关系及举例说明:**

这些函数对于 Android 在 32 位架构上的正常运行至关重要，因为 Android 系统需要处理各种大小的文件和资源。

* **文件系统操作:**
    * 当一个 32 位 Android 应用需要访问一个大于 4GB 的文件时，例如播放一个高清视频或下载一个大型 APK 文件，`lseek64`、`pread` 和 `pwrite` 就发挥了作用。没有这些函数，32 位应用将无法定位到文件超过 4GB 后的部分。
    * `fallocate` 可以被用于预分配文件空间，这在创建大型数据库文件或者进行文件下载时可以提高效率。

* **内存管理:**
    * `mmap64` 使得 32 位应用可以映射大型文件的一部分到内存中，即使文件大小超过了 32 位地址空间的限制。例如，一个图像处理应用可能需要映射一个大的图像文件来进行编辑。
    * `mremap` 用于调整已映射的内存区域的大小。

* **资源管理:**
    * `getrlimit64` 和 `setrlimit64` 允许应用查询和设置进程的资源限制，例如可以打开的最大文件数、最大的内存使用量等。这对于系统的稳定性和应用的正常运行非常重要。

**libc 函数的实现细节:**

* **`lseek64`:**  它直接调用了 `__llseek` 系统调用。`__llseek` 是一个特殊的系统调用，在 32 位内核上用于处理 64 位的偏移量。它接收文件描述符 `fd`，偏移量的高 32 位 `off_hi`，偏移量的低 32 位 `off_lo`，一个指向 `off64_t` 结果的指针 `result`，以及 `whence` 参数。内核计算出最终的 64 位偏移量并将其写入 `result` 指向的内存。

  ```c
  extern "C" int __llseek(int, unsigned long, unsigned long, off64_t*, int);

  off64_t lseek64(int fd, off64_t off, int whence) {
    off64_t result;
    unsigned long off_hi = static_cast<unsigned long>(off >> 32);
    unsigned long off_lo = static_cast<unsigned long>(off);
    if (__llseek(fd, off_hi, off_lo, &result, whence) < 0) {
      return -1;
    }
    return result;
  }
  ```

* **`pread` 和 `pwrite`:**  这两个函数非常简单，它们只是将传入的 32 位 `offset` 强制转换为 64 位的 `off64_t`，然后直接调用对应的 64 位系统调用 `pread64` 和 `pwrite64`。

  ```c
  ssize_t pread(int fd, void* buf, size_t byte_count, off_t offset) {
    return pread64(fd, buf, byte_count, static_cast<off64_t>(offset));
  }
  ```

* **`fallocate`:**  与 `pread` 和 `pwrite` 类似，它将 32 位的 `offset` 和 `length` 转换为 64 位并调用 `fallocate64`。

* **`getrlimit64` 和 `setrlimit64`:**  由于 32 位系统没有 `getrlimit64` 和 `setrlimit64` 系统调用，它们使用 `prlimit64`，并将 `pid` 参数设置为 0，表示操作当前进程。

  ```c
  int getrlimit64(int resource, rlimit64* limits64) {
    return prlimit64(0, resource, nullptr, limits64);
  }
  ```

* **`prlimit`:**  这个函数需要处理 32 位和 64 位的 `rlimit` 结构体。如果传入的是 32 位的结构体指针，它会将其成员值复制到 64 位的结构体中，注意 `RLIM_INFINITY` 的转换。然后调用 `prlimit64`。如果调用成功且需要返回旧的限制，它会将 64 位的值转换回 32 位。

  ```c
  int prlimit(pid_t pid, int resource, const rlimit* n32, rlimit* o32) {
    rlimit64 n64;
    if (n32 != nullptr) {
      n64.rlim_cur = (n32->rlim_cur == RLIM_INFINITY) ? RLIM64_INFINITY : n32->rlim_cur;
      n64.rlim_max = (n32->rlim_max == RLIM_INFINITY) ? RLIM64_INFINITY : n32->rlim_max;
    }

    rlimit64 o64;
    int result = prlimit64(pid, resource,
                           (n32 != nullptr) ? &n64 : nullptr,
                           (o32 != nullptr) ? &o64 : nullptr);
    if (result != -1 && o32 != nullptr) {
      o32->rlim_cur = (o64.rlim_cur == RLIM64_INFINITY) ? RLIM_INFINITY : o64.rlim_cur;
      o32->rlim_max = (o64.rlim_max == RLIM64_INFINITY) ? RLIM_INFINITY : o64.rlim_max;
    }
    return result;
  }
  ```

* **`mmap64`:**  它调用了 `__mmap2` 系统调用。`__mmap2` 的特殊之处在于其偏移量是以 4096 字节（4KB）的块为单位的。这使得在 32 位系统上映射超过 4GB 的文件成为可能，因为偏移量只需要 32 位来表示，但实际上指向的是大文件中的某个 4KB 块的起始位置。代码中首先检查偏移量是否有效（非负且对齐到 4KB），然后将偏移量右移 12 位（相当于除以 4096）作为 `__mmap2` 的参数。

  ```c
  extern "C" void* __mmap2(void*, size_t, int, int, int, size_t);

  void* mmap64(void* addr, size_t size, int prot, int flags, int fd, off64_t offset) {
    static constexpr size_t MMAP2_SHIFT = 12;

    if (offset < 0 || (offset & ((1UL << MMAP2_SHIFT) - 1)) != 0) {
      errno = EINVAL;
      return MAP_FAILED;
    }
    // ... 省略大小检查 ...
    return __mmap2(addr, size, prot, flags, fd, offset >> MMAP2_SHIFT);
  }
  ```

* **`mmap`:**  简单地将 32 位的 `offset` 转换为 64 位并调用 `mmap64`。

* **`mremap`:**  直接调用了底层的 `__mremap` 系统调用。`__mremap` 的签名可能因架构而异。这个包装器处理了可变参数 `new_address`，该参数仅在设置 `MREMAP_FIXED` 标志时使用。

**涉及 dynamic linker 的功能:**

这个文件中定义的函数本身不是 dynamic linker 的功能。然而，它们作为 libc 的一部分，会被动态链接的库所使用。当一个 32 位的 Android 应用或库调用这些函数时，dynamic linker 负责找到这些函数的实现（在这个 `legacy_32_bit_support.cpp` 文件编译成的库中）。

**so 布局样本和链接处理过程:**

假设有一个名为 `libmylib.so` 的 32 位 native 库，它使用了 `lseek64` 函数。

**`libmylib.so` 的布局可能如下（简化）：**

```
.text:  // 包含代码段
    ...
    call    PLT[lseek64]  // 调用 lseek64 的位置，通过 PLT 跳转
    ...
.plt:   // Procedure Linkage Table (PLT)
    lseek64@plt:
        jmp    GOT[lseek64]  // 跳转到 GOT 表项
    ...
.got:   // Global Offset Table (GOT)
    lseek64@got:
        <linker 运行时填充的 lseek64 的地址>
    ...
```

**链接处理过程:**

1. **编译时:** 当 `libmylib.so` 被编译时，对 `lseek64` 的调用会生成一个到 PLT 中 `lseek64@plt` 的跳转指令。GOT 中 `lseek64@got` 的初始值通常是一个指向 PLT 中下一条指令的地址。

2. **加载时:** 当 Android 系统加载 `libmylib.so` 时，dynamic linker (linker64 或 linker) 会解析其依赖关系。如果 `libmylib.so` 依赖于 libc (bionic)，linker 会找到 libc 中 `lseek64` 的实现地址。

3. **首次调用:** 当 `libmylib.so` 首次调用 `lseek64` 时：
   - 程序跳转到 `lseek64@plt`。
   - `lseek64@plt` 跳转到 `GOT[lseek64]` 指向的地址（初始是 PLT 中的下一条指令）。
   - PLT 中的这段代码会将 `lseek64` 的符号 ID 推入栈，并跳转到一个 linker 提供的解析函数。
   - Linker 解析 `lseek64` 符号，找到 `bionic/libc.so` 中 `lseek64` 的实际地址。
   - Linker 将 `lseek64` 的实际地址写入 `GOT[lseek64]`。

4. **后续调用:** 当 `libmylib.so` 再次调用 `lseek64` 时：
   - 程序跳转到 `lseek64@plt`。
   - `lseek64@plt` 跳转到 `GOT[lseek64]` 指向的地址，此时 GOT 表项已经被 linker 更新为 `lseek64` 的实际地址。
   - 程序直接跳转到 `lseek64` 的实现代码。

**假设输入与输出（以 `lseek64` 为例）:**

假设一个 32 位应用尝试查找一个大于 4GB 文件的偏移量：

**假设输入:**

* `fd`: 一个已打开的大文件的文件描述符。
* `off`: 偏移量 `0x100000000LL` (4294967296，即 4GB)。这是一个超过 32 位有符号整数最大值的偏移量。
* `whence`: `SEEK_SET` (从文件开头计算偏移量)。

**逻辑推理:**

1. 32 位应用调用 `lseek64(fd, 0x100000000LL, SEEK_SET)`。
2. `lseek64` 函数内部将 64 位偏移量拆分为高 32 位 (`off_hi = 1`) 和低 32 位 (`off_lo = 0`)。
3. 调用底层的 `__llseek(fd, 1, 0, &result, SEEK_SET)`。
4. 内核执行查找操作，并将结果（新的文件指针位置）写入 `result` 指向的内存。
5. `lseek64` 返回 `result` 的值。

**输出:**

* 如果查找成功，`lseek64` 返回 `0x100000000LL`。
* 如果发生错误（例如，文件描述符无效），`lseek64` 返回 `-1` 并设置 `errno`。

**用户或编程常见的使用错误:**

1. **在 32 位系统上直接使用 64 位类型而不调用这些包装函数:** 尽管 C++ 允许声明 `off64_t` 类型的变量，但在 32 位系统上直接将其传递给原生的 `lseek` 等函数会导致数据截断或类型不匹配，从而导致错误的行为。

   ```c++
   // 错误示例（在 32 位系统上）
   off64_t large_offset = 0x100000000LL;
   lseek(fd, large_offset, SEEK_SET); // 可能会截断 large_offset
   ```

2. **忘记检查返回值和 `errno`:** 像 `lseek64` 这样的函数在出错时会返回 `-1` 并设置全局变量 `errno` 来指示错误类型。开发者必须检查这些返回值并处理可能的错误情况。

   ```c++
   off64_t offset = lseek64(fd, some_offset, SEEK_SET);
   if (offset == -1) {
       perror("lseek64 failed"); // 打印错误信息
       // 处理错误
   }
   ```

3. **在不合适的场景下使用这些函数:** 虽然这些函数提供了 64 位支持，但在不需要处理大于 4GB 的文件或资源时，使用原生的 32 位函数可能更简洁。

**Android framework 或 ndk 如何一步步的到达这里:**

1. **Android Framework (Java 代码):**  假设一个 Java 应用需要读取一个大文件。它可能会使用 `java.io.FileInputStream`.

2. **System Services (Native 代码):** `FileInputStream` 的底层实现最终会调用到 Android 系统的 native 代码，这些代码通常在 frameworks/base 仓库中。

3. **NDK (Native 代码):** 如果应用直接使用 NDK 开发，它可能会直接调用 C 标准库函数。例如，使用 `<fcntl.h>` 中的 `open()` 打开文件，然后使用 `<unistd.h>` 中的 `lseek()` 或 `pread()` 进行读取。

4. **Bionic (C 库):**  当 native 代码调用 `lseek()` 或 `pread()` 时，如果是在 32 位系统上且需要处理 64 位偏移量，实际上会调用到 `bionic/libc/bionic/legacy_32_bit_support.cpp` 中定义的包装函数 `lseek64` 或 `pread`。

   例如，如果 NDK 代码调用 `lseek(fd, large_offset, SEEK_SET)`，并且 `large_offset` 的值超过了 32 位整数的范围，libc 的实现可能会检测到这种情况，或者该代码本身就被编译为调用 `lseek64`。

**Frida hook 示例调试步骤:**

可以使用 Frida hook 来拦截这些函数的调用，查看参数和返回值。以下是一个 hook `lseek64` 的示例：

```javascript
if (Process.arch === 'arm') { // 仅在 32 位 ARM 架构上 hook
  const lseek64 = Module.findExportByName("libc.so", "lseek64");
  if (lseek64) {
    Interceptor.attach(lseek64, {
      onEnter: function (args) {
        console.log("lseek64 called");
        console.log("  fd:", args[0]);
        console.log("  offset:", args[1].toString()); // 将 NativePointer 转换为字符串
        console.log("  whence:", args[2]);
      },
      onLeave: function (retval) {
        console.log("lseek64 returned:", retval.toString());
      }
    });
  } else {
    console.log("lseek64 not found in libc.so");
  }
} else {
  console.log("Skipping lseek64 hook on non-32-bit architecture.");
}
```

**调试步骤:**

1. **准备环境:** 确保你有一个 32 位的 Android 设备或模拟器，并安装了 Frida 服务。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_lseek64.js`.
3. **找到目标进程:** 确定你想要 hook 的应用的进程名称或进程 ID。
4. **运行 Frida 命令:** 使用 Frida CLI 将脚本注入到目标进程中。例如：
   ```bash
   frida -U -f <package_name> -l hook_lseek64.js --no-pause
   ```
   或者，如果已知进程 ID：
   ```bash
   frida -p <pid> -l hook_lseek64.js
   ```
5. **触发 `lseek64` 调用:** 在目标应用中执行会导致调用 `lseek64` 的操作，例如打开一个大文件并尝试查找超过 4GB 的偏移量。
6. **查看 Frida 输出:** Frida 会在控制台上打印出 `lseek64` 被调用时的参数和返回值，帮助你理解函数的执行过程。

通过这种方式，你可以详细观察 32 位 Android 系统中如何处理 64 位相关的操作，以及 `legacy_32_bit_support.cpp` 中定义的函数是如何被调用的。

Prompt: 
```
这是目录为bionic/libc/bionic/legacy_32_bit_support.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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

#undef _FORTIFY_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include "platform/bionic/macros.h"
#include "platform/bionic/page.h"
#include "private/ErrnoRestorer.h"
#include "private/bionic_fdtrack.h"

#if defined(__LP64__)
#error This code is only needed on 32-bit systems!
#endif

// To implement lseek64() on ILP32, we need to use the _llseek() system call
// which splits the off64_t into two 32-bit arguments and returns the off64_t
// result via a pointer because 32-bit kernels can't accept 64-bit arguments
// or return 64-bit results. (Our symbol is __llseek with two underscores for
// historical reasons, but it's exposed as ABI so we can't fix it.)
extern "C" int __llseek(int, unsigned long, unsigned long, off64_t*, int);

off64_t lseek64(int fd, off64_t off, int whence) {
  off64_t result;
  unsigned long off_hi = static_cast<unsigned long>(off >> 32);
  unsigned long off_lo = static_cast<unsigned long>(off);
  if (__llseek(fd, off_hi, off_lo, &result, whence) < 0) {
    return -1;
  }
  return result;
}

// There is no pread for 32-bit off_t, so we need to widen and call pread64.
ssize_t pread(int fd, void* buf, size_t byte_count, off_t offset) {
  return pread64(fd, buf, byte_count, static_cast<off64_t>(offset));
}

// There is no pwrite for 32-bit off_t, so we need to widen and call pwrite64.
ssize_t pwrite(int fd, const void* buf, size_t byte_count, off_t offset) {
  return pwrite64(fd, buf, byte_count, static_cast<off64_t>(offset));
}

// There is no fallocate for 32-bit off_t, so we need to widen and call fallocate64.
int fallocate(int fd, int mode, off_t offset, off_t length) {
  return fallocate64(fd, mode, static_cast<off64_t>(offset), static_cast<off64_t>(length));
}

// There is no getrlimit64 system call, so we need to use prlimit64.
int getrlimit64(int resource, rlimit64* limits64) {
  return prlimit64(0, resource, nullptr, limits64);
}

// There is no setrlimit64 system call, so we need to use prlimit64.
int setrlimit64(int resource, const rlimit64* limits64) {
  return prlimit64(0, resource, limits64, nullptr);
}

// There is no prlimit system call, so we need to use prlimit64.
int prlimit(pid_t pid, int resource, const rlimit* n32, rlimit* o32) {
  rlimit64 n64;
  if (n32 != nullptr) {
    n64.rlim_cur = (n32->rlim_cur == RLIM_INFINITY) ? RLIM64_INFINITY : n32->rlim_cur;
    n64.rlim_max = (n32->rlim_max == RLIM_INFINITY) ? RLIM64_INFINITY : n32->rlim_max;
  }

  rlimit64 o64;
  int result = prlimit64(pid, resource,
                         (n32 != nullptr) ? &n64 : nullptr,
                         (o32 != nullptr) ? &o64 : nullptr);
  if (result != -1 && o32 != nullptr) {
    o32->rlim_cur = (o64.rlim_cur == RLIM64_INFINITY) ? RLIM_INFINITY : o64.rlim_cur;
    o32->rlim_max = (o64.rlim_max == RLIM64_INFINITY) ? RLIM_INFINITY : o64.rlim_max;
  }
  return result;
}

// mmap2(2) is like mmap(2), but the offset is in 4096-byte blocks (regardless
// of page size), not bytes, to enable mapping parts of large files past the
// 4GiB limit but without the inconvenience of dealing with 64-bit values, with
// no down side since mappings need to be page aligned anyway, and the 32-bit
// architectures that support this system call all have 4KiB pages.
extern "C" void* __mmap2(void*, size_t, int, int, int, size_t);

void* mmap64(void* addr, size_t size, int prot, int flags, int fd, off64_t offset) {
  static constexpr size_t MMAP2_SHIFT = 12;

  if (offset < 0 || (offset & ((1UL << MMAP2_SHIFT) - 1)) != 0) {
    errno = EINVAL;
    return MAP_FAILED;
  }

  // Prevent allocations large enough for `end - start` to overflow,
  // to avoid security bugs.
  size_t rounded = __BIONIC_ALIGN(size, page_size());
  if (rounded < size || rounded > PTRDIFF_MAX) {
    errno = ENOMEM;
    return MAP_FAILED;
  }

  return __mmap2(addr, size, prot, flags, fd, offset >> MMAP2_SHIFT);
}

void* mmap(void* addr, size_t size, int prot, int flags, int fd, off_t offset) {
  return mmap64(addr, size, prot, flags, fd, static_cast<off64_t>(offset));
}

// The only difference here is that the libc API uses varargs for the
// optional `new_address` argument that's only used by MREMAP_FIXED.
extern "C" void* __mremap(void*, size_t, size_t, int, void*);

void* mremap(void* old_address, size_t old_size, size_t new_size, int flags, ...) {
  // Prevent allocations large enough for `end - start` to overflow,
  // to avoid security bugs.
  size_t rounded = __BIONIC_ALIGN(new_size, page_size());
  if (rounded < new_size || rounded > PTRDIFF_MAX) {
    errno = ENOMEM;
    return MAP_FAILED;
  }

  // The optional argument is only valid if the MREMAP_FIXED flag is set,
  // so we assume it's not present otherwise.
  void* new_address = nullptr;
  if ((flags & MREMAP_FIXED) != 0) {
    va_list ap;
    va_start(ap, flags);
    new_address = va_arg(ap, void*);
    va_end(ap);
  }
  return __mremap(old_address, old_size, new_size, flags, new_address);
}

// mseal(2) is LP64-only.
int mseal(void*, size_t, unsigned long) {
  errno = ENOSYS;
  return -1;
}

"""

```