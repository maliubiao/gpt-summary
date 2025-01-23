Response:
Let's break down the thought process for analyzing this C code and generating the detailed explanation.

**1. Initial Understanding of the Goal:**

The request asks for a comprehensive analysis of the `open_wmemstream.c` file, focusing on its functionality, Android relevance, implementation details, dynamic linking aspects (if any), potential errors, and how it's reached from Android's higher layers, including Frida hooking.

**2. Deconstructing the Code:**

The first step is to read through the code carefully, identifying the key components and their roles.

*   **Headers:**  Recognize standard C headers (`errno.h`, `fcntl.h`, `stdio.h`, etc.) and the custom `local.h`. This immediately suggests standard input/output and some potentially internal library functions.
*   **`MINIMUM` Macro:**  A simple helper macro for finding the minimum of two values.
*   **`struct state`:**  This is the core data structure associated with the memory stream. Understand the purpose of each member:
    *   `string`: The actual wide character buffer.
    *   `pbuf`: A pointer to the user-provided pointer that will hold the address of `string`.
    *   `psize`: A pointer to the user-provided size variable.
    *   `pos`: The current writing position within the buffer.
    *   `size`: The allocated size of the buffer.
    *   `len`: The length of the data currently written to the buffer.
    *   `mbs`: Multibyte conversion state (important for handling different character encodings).
*   **Static Functions:**  These are helper functions used internally by `open_wmemstream`:
    *   `wmemstream_write`: Handles writing data to the memory buffer. Key operations: reallocation if needed, multibyte to wide character conversion, updating `pos` and `len`.
    *   `wmemstream_seek`: Handles seeking within the memory stream. Key operations: calculating the new position, handling different `whence` modes, resetting the multibyte conversion state (important to note the comment about limitations).
    *   `wmemstream_close`: Handles closing the memory stream and freeing the allocated `state` structure.
*   **`open_wmemstream` Function:** This is the main function being analyzed. Key operations:
    *   Argument validation (checking for `NULL` pointers).
    *   Allocation of the `state` structure.
    *   Acquiring a `FILE` structure (using `__sfp()`, which strongly suggests involvement with standard I/O).
    *   Initial allocation of the wide character buffer.
    *   Initialization of the `state` structure members.
    *   Setting up the `FILE` structure's function pointers (`_read`, `_write`, `_seek`, `_close`) to point to the static helper functions.
    *   Setting flags (`__SWR`) and orientation.
    *   Returning the newly created `FILE` pointer.

**3. Analyzing Functionality and Android Relevance:**

*   **Core Functionality:**  The code implements an in-memory wide character stream. This means you can write wide character data to memory as if it were a file.
*   **Android Relevance:**  Bionic is Android's C library, so this function *is* an Android function. It's used for tasks where you need to build up a wide character string in memory before using it elsewhere. Examples: creating formatted output, preparing text for display, or processing internationalized text.

**4. Detailed Explanation of `libc` Functions:**

For each `libc` function used, explain its purpose in the context of `open_wmemstream`:

*   `malloc`, `calloc`, `reallocarray`, `free`: Memory management.
*   `errno`: Setting error codes.
*   `stdio.h` elements (`FILE`, `BUFSIZ`, `_flags`, `_file`, `_cookie`, `_read`, `_write`, `_seek`, `_close`, `_SET_ORIENTATION`): Standard I/O structures and functions. Crucially, `__sfp()` needs explanation (acquiring a `FILE` structure).
*   `string.h` elements (`memset`, `bzero`):  Zeroing memory.
*   `wchar.h` elements (`wchar_t`, `mbsnrtowcs`): Wide character handling and multibyte to wide character conversion.
*   `fcntl.h` elements (`SEEK_SET`, `SEEK_CUR`, `SEEK_END`): Seek modes.

**5. Dynamic Linking:**

At this stage, recognize that `open_wmemstream.c` itself doesn't *directly* involve dynamic linking in its core logic. However, it *uses* functions provided by the C library, which is dynamically linked.

*   **SO Layout:** Describe a typical layout of `libc.so` with sections like `.text`, `.data`, `.bss`, and the Global Offset Table (GOT) and Procedure Linkage Table (PLT).
*   **Linking Process:**  Explain how the dynamic linker resolves symbols like `malloc`, `calloc`, `__sfp`, etc., at runtime using the GOT and PLT.

**6. Logical Reasoning and Input/Output:**

*   **Assumptions:**  Think about how a programmer would use this function. They would provide pointers to `wchar_t*` and `size_t`.
*   **Input:**  The `open_wmemstream` function takes pointers as input. The subsequent `fwrite` (or similar operation on the returned `FILE*`) would provide the actual data.
*   **Output:**  The function returns a `FILE*`. Crucially, the pointers provided by the user are modified to point to the allocated memory and its initial size.

**7. Common Usage Errors:**

Think about mistakes developers might make:

*   Not checking for `NULL` return values.
*   Memory leaks if the `FILE*` is not closed.
*   Incorrectly assuming the buffer size.
*   Misunderstanding how `psize` is updated.

**8. Android Framework/NDK Path and Frida Hooking:**

This requires knowledge of the Android architecture.

*   **NDK:** Start with the NDK. Explain how an NDK developer would use standard C library functions like `fwprintf` (which internally might use `open_wmemstream`).
*   **Framework:**  Consider how higher-level Android components (written in Java or Kotlin) might indirectly use wide character streams, potentially through JNI calls to native code. Give an example like text rendering or internationalization.
*   **Frida Hooking:**  Demonstrate how to use Frida to intercept the `open_wmemstream` function, log arguments, and potentially modify its behavior. Provide a concise JavaScript example.

**9. Structuring the Output:**

Organize the information logically with clear headings and bullet points. Use code snippets where appropriate. Ensure the language is clear and precise.

**Self-Correction/Refinement during the Process:**

*   **Initial thought:**  "Does this directly involve dynamic linking?"  Correction: While the *code itself* doesn't perform dynamic linking, it relies on dynamically linked libraries. Shift the focus to how the *used functions* are resolved.
*   **Clarity of Explanation:** Review the explanations for each `libc` function. Are they clear and concise?  Could they be more specific to the context of `open_wmemstream`?
*   **Frida Example:** Ensure the Frida example is practical and demonstrates a useful debugging technique.
*   **Completeness:** Double-check that all aspects of the prompt have been addressed.

By following this structured approach, breaking down the code, and considering the broader Android ecosystem, it's possible to generate a comprehensive and accurate explanation like the example provided in the prompt.
好的，让我们详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/stdio/open_wmemstream.c` 这个文件。

**功能概述**

`open_wmemstream` 函数的功能是创建一个关联内存缓冲区的宽字符输出流 (wide-character output stream)。与 `fopen` 打开文件不同，它不会关联到一个实际的文件，而是将数据写入到内存中的一块缓冲区。

具体来说，它执行以下操作：

1. **分配一个 `FILE` 结构：** 这是标准 C 库中表示流的对象。
2. **分配一个内部状态结构 `state`：**  这个结构维护了内存缓冲区的信息，例如缓冲区的起始地址、已分配的大小、当前写入位置等。
3. **初始化 `FILE` 结构：** 将 `FILE` 结构与内部状态结构关联起来，并设置相应的读写、定位和关闭操作函数指针。
4. **返回指向 `FILE` 结构的指针：**  用户可以使用这个指针进行宽字符输出操作，例如 `fwprintf`。

**与 Android 功能的关系及举例**

`open_wmemstream` 是 Android Bionic C 库的一部分，因此在 Android 系统和 NDK (Native Development Kit) 开发中都有潜在的应用。

**举例说明：**

* **字符串格式化和构建：** 在需要动态构建宽字符串的场景中，可以使用 `open_wmemstream` 将格式化的输出写入内存缓冲区，然后再将缓冲区的内容用于其他操作，例如显示到 UI 上或传递给其他函数。
  ```c
  #include <stdio.h>
  #include <wchar.h>
  #include <locale.h>

  int main() {
      setlocale(LC_ALL, "zh_CN.UTF-8"); // 设置本地化，确保宽字符正确处理
      wchar_t *buffer;
      size_t buffer_size;
      FILE *stream = open_wmemstream(&buffer, &buffer_size);
      if (stream == NULL) {
          perror("open_wmemstream");
          return 1;
      }

      fwprintf(stream, L"你好，世界！%d\n", 123);
      fclose(stream); // 关闭流，此时 buffer 和 buffer_size 会被更新

      wprintf(L"缓冲区内容：%ls\n", buffer);
      free(buffer); // 记得释放内存
      return 0;
  }
  ```
  在这个例子中，`open_wmemstream` 创建了一个内存输出流，`fwprintf` 将宽字符数据写入到这个流中。关闭流后，`buffer` 指向包含 "你好，世界！123\n" 的内存，`buffer_size` 包含了实际写入的字符数。

* **日志记录：**  在某些情况下，可能需要在内存中构建格式化的日志信息，然后再统一写入到文件或进行其他处理。`open_wmemstream` 可以作为构建内存日志缓冲区的工具。

**libc 函数的实现细节**

让我们逐个分析代码中涉及的关键 `libc` 函数的实现：

1. **`malloc(sizeof(*st))`:**
   - **功能：**  从堆上分配一块大小为 `sizeof(struct state)` 的内存，用于存储内部状态结构。
   - **实现：** `malloc` 的具体实现依赖于底层的内存分配器（例如 Bionic 使用 jemalloc 或 scudo）。它会在堆上找到一块足够大的空闲内存块，标记为已使用，并返回指向该内存块起始地址的指针。如果分配失败，则返回 `NULL`。

2. **`__sfp()`:**
   - **功能：**  获取一个可用的 `FILE` 结构。在标准 C 库中，`FILE` 结构用于管理流。
   - **实现：**  `__sfp` (likely standing for "standard file pointer") 是一个 Bionic 内部函数。它通常会维护一个 `FILE` 结构体的数组或链表。当调用 `__sfp` 时，它会查找一个当前未被使用的 `FILE` 结构，并返回指向它的指针。如果所有 `FILE` 结构都在使用中，则可能返回 `NULL` 并设置 `errno` 为 `ENFILE` 或 `EMFILE`。

3. **`calloc(1, st->size)`:**
   - **功能：**  从堆上分配一块大小为 `st->size` 字节的内存，并将其所有字节初始化为零。`st->size` 在这里被初始化为 `BUFSIZ * sizeof(wchar_t)`，即一个默认缓冲区大小乘以宽字符的大小。
   - **实现：** `calloc(n, size)` 相当于 `malloc(n * size)` 后调用 `memset` 将分配的内存清零。它也依赖于底层的内存分配器。

4. **`free(st)`:**
   - **功能：**  释放之前通过 `malloc` 或 `calloc` 分配的内存块。
   - **实现：** `free` 将之前分配的内存块标记为空闲，以便将来可以重新分配。传递给 `free` 的指针必须是之前 `malloc`、`calloc` 或 `realloc` 返回的有效指针。释放已经释放过的内存或无效指针会导致未定义行为。

5. **`bzero(&st->mbs, sizeof(st->mbs))`:**
   - **功能：**  将 `st->mbs` 指向的内存块（大小为 `sizeof(st->mbs)` 字节）的所有字节设置为零。`st->mbs` 是一个 `mbstate_t` 类型的变量，用于存储多字节字符转换的状态。
   - **实现：**  `bzero` 通常是通过循环将内存块的每个字节设置为 0 来实现的，或者使用优化的汇编指令。

6. **`recallocarray(st->string, st->size, sz, sizeof(wchar_t))` (在 `wmemstream_write` 中):**
   - **功能：** 重新分配 `st->string` 指向的内存块。它试图将现有内存块的大小调整为能够容纳 `sz` 个 `wchar_t` 元素。它还会保留原有内存块中的内容。
   - **实现：** `recallocarray(ptr, old_count, new_count, size)` 的行为类似于先调用 `free(ptr)`，然后调用 `calloc(new_count, size)`。  Bionic 的 `recallocarray` 实现可能会尝试在原地扩展内存块，如果不可能，则会分配新的内存块，将旧数据复制过去，然后释放旧的内存块。

7. **`mbsnrtowcs(st->string + st->pos, &b, nmc, l, &st->mbs)` (在 `wmemstream_write` 中):**
   - **功能：** 将最多 `l` 个字节的以 `b` 开头的多字节字符串转换为宽字符字符串，并将结果存储到以 `st->string + st->pos` 开头的缓冲区中。`nmc` 指定了目标缓冲区最多可以容纳的宽字符数量。 `&st->mbs` 用于维护转换状态，以便处理包含移位序列的多字节编码。
   - **实现：** `mbsnrtowcs` 的实现依赖于当前的 locale 设置。它会根据 locale 中指定的字符编码（例如 UTF-8）将多字节序列解码为对应的宽字符。如果遇到无效的多字节序列，则返回 `(size_t)-1` 并设置 `errno` 为 `EILSEQ`。

**涉及 dynamic linker 的功能**

`open_wmemstream.c` 本身的代码并没有直接涉及 dynamic linker 的功能。然而，它所调用的 `libc` 函数（例如 `malloc`，`calloc`，`__sfp` 等）都是由 dynamic linker 在程序启动时进行链接和加载的。

**so 布局样本 (以 libc.so 为例):**

```
libc.so:
    .interp        # 指向动态链接器的路径
    .note.android.ident
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .hash          # 符号哈希表
    .gnu.version   # 版本信息
    .gnu.version_r # 版本需求信息
    .rel.dyn       # 重定位表 (数据段)
    .rel.plt       # 重定位表 (PLT)
    .plt           # Procedure Linkage Table (PLT)
    .text          # 代码段 (包含 open_wmemstream, malloc, etc. 的指令)
    .rodata        # 只读数据段
    .data          # 初始化数据段 (例如全局变量)
    .bss           # 未初始化数据段
    ...
```

**链接的处理过程：**

1. **编译时：** 编译器生成目标文件 (`.o`)，其中包含对外部符号（例如 `malloc`）的引用。这些引用在目标文件中并没有被解析，而是以占位符的形式存在。
2. **链接时：** 链接器（在 Android 上通常是 `lld`）将多个目标文件链接成一个共享库 (`.so`) 或可执行文件。对于外部符号，链接器会查找所需的符号定义，通常在 `libc.so` 等共享库中。链接器会生成重定位信息，指示在加载时如何修改代码和数据，以指向正确的符号地址。
3. **加载时：** 当程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载程序所需的共享库。
4. **符号解析：** Dynamic linker 会遍历程序的依赖关系，加载 `libc.so` 等库。然后，它会根据重定位信息，修改程序代码中的占位符，将它们替换为 `libc.so` 中 `malloc` 等函数的实际地址。这个过程通常使用 **延迟绑定 (lazy binding)** 或 **过程链接表 (PLT)** 和 **全局偏移表 (GOT)** 来优化性能。

   - **PLT (Procedure Linkage Table):**  当程序第一次调用一个外部函数时，会跳转到 PLT 中对应的条目。
   - **GOT (Global Offset Table):**  GOT 中存储着外部函数的实际地址。最初，GOT 中的条目指向 PLT 中的一段代码。
   - **第一次调用：** PLT 中的代码会调用 dynamic linker 来解析符号，找到函数的实际地址，并将其写入 GOT 中。
   - **后续调用：**  后续对同一外部函数的调用会直接跳转到 PLT，PLT 再跳转到 GOT，此时 GOT 中已经存储了函数的实际地址，避免了重复的符号解析。

**假设输入与输出 (逻辑推理)**

**假设输入：**

```c
wchar_t *buffer;
size_t buffer_size;
FILE *stream = open_wmemstream(&buffer, &buffer_size);
```

**预期输出：**

* `stream`：一个非 `NULL` 的 `FILE` 指针，表示成功创建的内存输出流。
* `buffer`：一个非 `NULL` 的 `wchar_t *` 指针，指向新分配的内存缓冲区。
* `buffer_size`：初始值为 `0`，因为此时缓冲区中还没有写入任何数据。缓冲区的实际分配大小由内部状态结构 `st->size` 管理，初始值为 `BUFSIZ * sizeof(wchar_t)`。

**后续操作的假设输入与输出：**

```c
fwprintf(stream, L"测试数据");
```

**预期输出：**

* 内存缓冲区 `buffer` 中将包含宽字符字符串 "测试数据"。
* `buffer_size` 的值将更新为写入的宽字符数量（不包括 null 终止符）。

**常见的使用错误**

1. **未检查 `open_wmemstream` 的返回值：** 如果内存分配失败，`open_wmemstream` 会返回 `NULL`，但如果不进行检查，后续操作可能会导致空指针解引用。
   ```c
   wchar_t *buffer;
   size_t buffer_size;
   FILE *stream = open_wmemstream(&buffer, &buffer_size);
   // 缺少 NULL 检查
   fwprintf(stream, L"数据"); // 如果 stream 为 NULL，则会崩溃
   ```

2. **内存泄漏：**  通过 `open_wmemstream` 分配的缓冲区内存需要手动释放。如果在 `fclose` 调用后没有 `free(buffer)`，则会发生内存泄漏。
   ```c
   wchar_t *buffer;
   size_t buffer_size;
   FILE *stream = open_wmemstream(&buffer, &buffer_size);
   fwprintf(stream, L"数据");
   fclose(stream);
   // 缺少 free(buffer);
   ```

3. **误解 `buffer_size` 的含义：** `buffer_size` 在 `open_wmemstream` 返回时为 0，在 `fclose` 调用后才会被更新为实际写入的字符数。在写入过程中，缓冲区的实际大小可能会自动扩展，但 `buffer_size` 不会动态更新。

4. **忘记设置 locale：** 对于涉及非 ASCII 字符的宽字符操作，需要正确设置 locale，否则可能导致字符转换错误。
   ```c
   wchar_t *buffer;
   size_t buffer_size;
   FILE *stream = open_wmemstream(&buffer, &buffer_size);
   fwprintf(stream, L"中文"); // 如果 locale 未设置，可能无法正确处理
   fclose(stream);
   free(buffer);
   ```

**Android Framework 或 NDK 如何到达这里**

1. **NDK 开发：**
   - NDK 开发者可以直接调用标准 C 库函数，包括 `open_wmemstream`。例如，在 C++ 代码中，可以使用 `std::wostringstream`，它在底层可能会使用 `open_wmemstream` 或类似的机制来构建宽字符串。
   - 当 NDK 代码需要处理或生成宽字符数据时，可能会间接或直接使用到这个函数。

2. **Android Framework (通过 JNI):**
   - Android Framework 主要使用 Java 和 Kotlin 编写。当 Framework 需要执行某些需要高性能或访问底层系统资源的宽字符操作时，可能会通过 JNI (Java Native Interface) 调用 Native 代码。
   - 在这些 Native 代码中，可能会使用 `open_wmemstream` 来构建或处理宽字符串。
   - 例如，在文本渲染、国际化处理等模块中，可能存在这样的调用路径.

**Frida Hook 示例调试**

可以使用 Frida 来 hook `open_wmemstream` 函数，以观察其调用和参数。

```javascript
if (Process.platform === 'android') {
  const open_wmemstream = Module.findExportByName("libc.so", "open_wmemstream");
  if (open_wmemstream) {
    Interceptor.attach(open_wmemstream, {
      onEnter: function (args) {
        console.log("[open_wmemstream] Called");
        this.pbuf = args[0];
        this.psize = args[1];
        console.log("  pbuf (wchar_t**):", args[0]);
        console.log("  psize (size_t*):", args[1]);
      },
      onLeave: function (retval) {
        console.log("  Return value (FILE*):", retval);
        if (retval.isNull()) {
          console.log("  open_wmemstream failed!");
          const errno_val = Module.findExportByName(null, "__errno_location")();
          const errno_p = new NativePointer(errno_val);
          const errno = errno_p.readInt();
          console.log("  errno:", errno);
        } else {
          const bufferPtr = Memory.readPointer(this.pbuf);
          const sizeVal = Memory.readULong(this.psize);
          console.log("  *pbuf (wchar_t*):", bufferPtr);
          console.log("  *psize (size_t):", sizeVal);
        }
      }
    });
  } else {
    console.log("[open_wmemstream] Not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**代码解释：**

1. **检查平台：** 确保脚本在 Android 平台上运行。
2. **查找函数地址：** 使用 `Module.findExportByName` 在 `libc.so` 中查找 `open_wmemstream` 函数的地址。
3. **附加 Interceptor：** 使用 `Interceptor.attach` 拦截 `open_wmemstream` 的调用。
4. **`onEnter`：** 在函数调用前执行。
   - 打印调用信息。
   - 记录参数 `pbuf` 和 `psize` 的值。
5. **`onLeave`：** 在函数调用返回后执行。
   - 打印返回值（`FILE*`）。
   - 如果返回值为空，则说明函数调用失败，尝试读取并打印 `errno` 的值。
   - 如果返回值不为空，则读取 `pbuf` 和 `psize` 指向的内存，打印 `wchar_t*` 缓冲区的地址和初始大小。

**使用方法：**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_open_wmemstream.js`）。
2. 使用 Frida 连接到目标 Android 设备或模拟器上的进程：
   ```bash
   frida -U -f <包名> -l hook_open_wmemstream.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <进程名或PID> -l hook_open_wmemstream.js
   ```
3. 当目标应用中调用 `open_wmemstream` 时，Frida 会拦截调用并打印相关信息到控制台，帮助你理解函数的行为和参数。

希望这个详细的分析能够帮助你理解 `open_wmemstream.c` 的功能、实现以及在 Android 中的应用。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdio/open_wmemstream.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: open_wmemstream.c,v 1.10 2023/07/11 12:14:16 claudio Exp $	*/

/*
 * Copyright (c) 2011 Martin Pieuchot <mpi@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "local.h"

#define	MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

struct state {
	wchar_t		 *string;	/* actual stream */
	wchar_t		**pbuf;		/* point to the stream */
	size_t		 *psize;	/* point to min(pos, len) */
	size_t		  pos;		/* current position */
	size_t		  size;		/* number of allocated wchar_t */
	size_t		  len;		/* length of the data */
	mbstate_t	  mbs;		/* conversion state of the stream */
};

static int
wmemstream_write(void *v, const char *b, int l)
{
	struct state	*st = v;
	wchar_t		*p;
	size_t		 nmc, len, end;

	end = (st->pos + l);

	if (end >= st->size) {
		/* 1.6 is (very) close to the golden ratio. */
		size_t	sz = st->size * 8 / 5;

		if (sz < end + 1)
			sz = end + 1;
		p = recallocarray(st->string, st->size, sz, sizeof(wchar_t));
		if (!p)
			return (-1);
		*st->pbuf = st->string = p;
		st->size = sz;
	}

	nmc = (st->size - st->pos) * sizeof(wchar_t);
	len = mbsnrtowcs(st->string + st->pos, &b, nmc, l, &st->mbs);
	if (len == (size_t)-1)
		return (-1);
	st->pos += len;

	if (st->pos > st->len) {
		st->len = st->pos;
		st->string[st->len] = L'\0';
	}

	*st->psize = st->pos;

	return (len);
}

static fpos_t
wmemstream_seek(void *v, fpos_t off, int whence)
{
	struct state	*st = v;
	ssize_t		 base = 0;

	switch (whence) {
	case SEEK_SET:
		break;
	case SEEK_CUR:
		base = st->pos;
		break;
	case SEEK_END:
		base = st->len;
		break;
	}

	if (off > (SIZE_MAX / sizeof(wchar_t)) - base || off < -base) {
		errno = EOVERFLOW;
		return (-1);
	}

	/*
	 * XXX Clearing mbs here invalidates shift state for state-
	 * dependent encodings, but they are not (yet) supported.
	 */
	bzero(&st->mbs, sizeof(st->mbs));

	st->pos = base + off;
	*st->psize = MINIMUM(st->pos, st->len);

	return (st->pos);
}

static int
wmemstream_close(void *v)
{
	struct state	*st = v;

	free(st);

	return (0);
}

FILE *
open_wmemstream(wchar_t **pbuf, size_t *psize)
{
	struct state	*st;
	FILE		*fp;

	if (pbuf == NULL || psize == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if ((st = malloc(sizeof(*st))) == NULL)
		return (NULL);

	if ((fp = __sfp()) == NULL) {
		free(st);
		return (NULL);
	}

	st->size = BUFSIZ * sizeof(wchar_t);
	if ((st->string = calloc(1, st->size)) == NULL) {
		free(st);
		fp->_flags = 0;
		return (NULL);
	}

	st->pos = 0;
	st->len = 0;
	st->pbuf = pbuf;
	st->psize = psize;
	bzero(&st->mbs, sizeof(st->mbs));

	*pbuf = st->string;
	*psize = st->len;

	fp->_flags = __SWR;
	fp->_file = -1;
	fp->_cookie = st;
	fp->_read = NULL;
	fp->_write = wmemstream_write;
	fp->_seek = wmemstream_seek;
	fp->_close = wmemstream_close;
	_SET_ORIENTATION(fp, 1);

	return (fp);
}
```