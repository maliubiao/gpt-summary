Response:
Let's break down the thought process for analyzing the `open_memstream.c` code.

**1. Understanding the Core Goal:**

The first step is to understand the fundamental purpose of the code. The name `open_memstream` immediately suggests a memory-based stream. The function signature `open_memstream(char **pbuf, size_t *psize)` reinforces this, hinting that it creates a stream that writes to dynamically allocated memory.

**2. High-Level Functionality Identification:**

Scanning the code reveals key functions: `memstream_write`, `memstream_seek`, `memstream_close`, and the main `open_memstream`. This suggests the core operations of a stream: writing data, seeking within the stream, and closing the stream. The `open_memstream` function itself is responsible for setting up this stream.

**3. Data Structure Analysis (`struct state`):**

The `struct state` is crucial. It holds the internal state of the memory stream. Analyzing its members reveals:

* `string`: The actual dynamically allocated memory buffer.
* `pbuf`: A pointer to the user-provided `char **` to update with the buffer's address.
* `psize`: A pointer to the user-provided `size_t *` to update with the current data size.
* `pos`: The current write position within the buffer.
* `size`: The total allocated size of the buffer.
* `len`: The length of the data written so far.

Understanding `struct state` is key to understanding how the memory stream manages its internal buffer and communicates its state to the caller.

**4. Function-by-Function Breakdown:**

* **`open_memstream`:** This is the entry point. Its job is to:
    * Validate input (`pbuf`, `psize`).
    * Allocate the `struct state`.
    * Obtain a `FILE` structure using `__sfp()`. This is a strong indicator of integration with the standard I/O library.
    * Allocate the initial memory buffer (`calloc`).
    * Initialize the `struct state` members.
    * Update the user-provided pointers `*pbuf` and `*psize`.
    * Configure the `FILE` structure by setting flags (`__SWR`), file descriptor (-1, indicating no actual file), cookie (the `struct state`), and the custom read, write, seek, and close functions.

* **`memstream_write`:**  This handles writing data to the memory buffer.
    * It calculates the required size.
    * It dynamically resizes the buffer using `recallocarray` if necessary. The 1.6 growth factor is an optimization.
    * It copies the input data to the buffer.
    * It updates `pos` and `len`.
    * It ensures the buffer is null-terminated.
    * It updates `*st->psize`.

* **`memstream_seek`:** This handles moving the read/write position within the stream.
    * It supports `SEEK_SET`, `SEEK_CUR`, and `SEEK_END`.
    * It performs bounds checking to prevent overflow.
    * It updates `pos` and `*st->psize`.

* **`memstream_close`:** This cleans up the allocated memory. Crucially, it *only* frees the `struct state`, not the buffer pointed to by `*pbuf`. This is a design decision that allows the user to access the buffer after closing the stream.

**5. Identifying Android Specifics (or Lack Thereof):**

The code itself doesn't have any explicit Android-specific function calls or constructs. However, its presence *within* the Android bionic library makes it an Android function. The integration point is the standard C library functions (`stdio.h`). Android apps using standard C I/O functions will indirectly use this implementation.

**6. Dynamic Linker Considerations:**

The code doesn't directly interact with the dynamic linker. However, its presence within `libc.so` means it will be loaded and linked like any other library function. The `DEF_WEAK(open_memstream)` suggests it can be overridden, although this isn't directly related to the core functionality.

**7. Error Handling and Potential Issues:**

The code handles errors like allocation failures (`malloc`, `recallocarray`) and invalid input (`pbuf`, `psize` being NULL). A common user error would be forgetting to `free` the memory pointed to by `*pbuf` after closing the stream (since `memstream_close` doesn't free it).

**8. Tracing the Execution Flow (Conceptual):**

To understand how an Android app reaches `open_memstream`:

1. **NDK/Framework Call:**  An Android app (either through NDK or framework) might call a function that ultimately needs to write data to memory. Examples: `snprintf`, some string manipulation functions, or even custom code using `FILE*` streams.
2. **Standard C Library:**  These high-level functions often rely on standard C library functions like `fopen`, `fwrite`, etc.
3. **`open_memstream`:** In scenarios where a memory-based stream is needed, a developer might directly call `open_memstream` or an internal function within the C library might use it as an implementation detail.

**9. Frida Hooking Strategy:**

To observe `open_memstream`, you'd hook the function itself. Capturing the arguments (`pbuf`, `psize`) and the return value (`FILE*`) would provide insight into its usage. Hooking the internal functions (`memstream_write`, `memstream_seek`, `memstream_close`) could further detail the stream's behavior.

**Self-Correction/Refinement during the process:**

* Initially, I might have overlooked the significance of `DEF_WEAK`. Realizing it indicates a weak symbol and potential overriding adds depth to the analysis.
*  I might have initially focused too much on explicit Android API calls. Recognizing the indirect involvement through the standard C library is crucial.
*  Understanding the memory management aspect – specifically, that `memstream_close` doesn't free the buffer – is a critical detail that needs to be highlighted.

By following these steps,  we can systematically analyze the provided code and generate a comprehensive explanation covering its functionality, Android relevance, implementation details, dynamic linking aspects, potential errors, and how it's used within the Android ecosystem.
好的，让我们详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/stdio/open_memstream.c` 这个文件。

**功能列举:**

`open_memstream` 函数的主要功能是创建一个与动态分配的内存缓冲区关联的流（`FILE *`）。这意味着你可以像操作普通文件流一样向这个流写入数据，但数据实际上会被写入到内存中。

具体来说，它的功能包括：

1. **动态内存分配:**  它会动态分配一块内存来存储写入流的数据。
2. **可增长的缓冲区:** 当写入的数据超过当前分配的内存大小时，它会自动重新分配更大的内存缓冲区。
3. **提供内存缓冲区的指针和大小:** 它会将指向内存缓冲区的指针和当前数据大小的指针返回给调用者。
4. **标准 I/O 操作:**  创建的流可以像标准文件流一样使用 `fprintf`, `fwrite` 等函数进行写入。
5. **可寻址:**  支持 `fseek` 等操作来在内存缓冲区中移动读写位置。
6. **关闭流:**  提供关闭流的机制，虽然关闭流本身不会释放内存缓冲区（需要用户手动释放）。

**与 Android 功能的关系和举例:**

`open_memstream` 是 Android Bionic C 库的一部分，因此直接被 Android 系统和应用程序所使用。它在以下场景中非常有用：

1. **格式化字符串到内存:**  例如，你可能需要将格式化的数据存储到内存中的一个字符串，而不是直接输出到文件或屏幕。可以使用 `open_memstream` 创建一个内存流，使用 `fprintf` 将格式化的数据写入，然后通过返回的指针访问生成的字符串。

   ```c
   #include <stdio.h>
   #include <stdlib.h>

   int main() {
       char *buffer;
       size_t size;
       FILE *memstream = open_memstream(&buffer, &size);
       if (memstream == NULL) {
           perror("open_memstream");
           return 1;
       }

       fprintf(memstream, "Hello, world! The answer is %d.\n", 42);
       fclose(memstream);

       printf("Buffer content: %s", buffer);
       printf("Buffer size: %zu\n", size);

       free(buffer); // 需要手动释放内存
       return 0;
   }
   ```

2. **在内存中构建数据:** 你可能需要先在内存中构建一些数据结构，然后再将其发送到网络或写入文件。`open_memstream` 提供了一个方便的方式来实现这一点。

3. **作为临时缓冲区:**  在某些情况下，你可能需要一个临时的、可增长的缓冲区来处理一些数据，而不需要涉及实际的文件操作。

**libc 函数实现详解:**

接下来，我们详细解释一下代码中每个 `libc` 函数的功能是如何实现的：

* **`errno.h`:**  定义了错误码相关的宏，例如 `EINVAL`（无效参数），`EOVERFLOW`（值超出范围）等。当函数遇到错误时，会设置 `errno` 变量来指示具体的错误类型。
* **`fcntl.h`:**  虽然包含了头文件，但在这个特定的 `open_memstream.c` 文件中并没有直接使用 `fcntl.h` 中定义的常量或函数。可能是为了保持与 OpenBSD 源代码的兼容性。
* **`stdint.h`:** 定义了跨平台的整数类型，如 `size_t`（用于表示对象大小）和 `intptr_t`（可以容纳指针的整数类型）。
* **`stdio.h`:**  包含了标准输入输出库的声明，例如 `FILE` 结构体定义，`fopen`, `fclose`, `fprintf`, `fwrite`, `fseek` 等函数的声明。 `open_memstream` 返回的是一个 `FILE *` 指针，它使用了 `stdio.h` 提供的基础设施。
* **`stdlib.h`:** 包含了通用工具函数，例如内存分配和释放函数 `malloc`, `calloc`, `reallocarray`, `free`。 `open_memstream` 使用这些函数来管理内存缓冲区。
* **`string.h`:** 包含了字符串操作函数，例如 `memcpy`（虽然代码中没有直接使用，但逻辑上涉及到内存拷贝），以及 `NULL` 的定义。
* **`local.h`:**  这是一个内部头文件，包含了 bionic 特有的定义。在这个文件中，它可能包含了 `__sfp()` 的声明和 `_SET_ORIENTATION` 的宏定义。
    * **`__sfp()`:**  这个函数（通常是内部函数）的作用是获取一个可用的 `FILE` 结构体。标准 C 库会维护一个 `FILE` 结构体的池，当需要创建一个新的流时，会从这个池中获取一个。
    * **`_SET_ORIENTATION(fp, -1)`:**  这个宏用于设置流的宽字符方向。 `-1` 表示流还没有确定是面向单字节还是多字节。

**具体实现分析:**

1. **`struct state`:**  这是一个内部结构体，用于保存 `open_memstream` 创建的内存流的状态信息。
    * `string`: 指向实际分配的内存缓冲区的指针。
    * `pbuf`: 指向用户提供的 `char **` 指针，用于更新内存缓冲区的地址。
    * `psize`: 指向用户提供的 `size_t *` 指针，用于更新当前数据的大小。
    * `pos`: 当前的写入位置。
    * `size`: 已分配的内存缓冲区的大小。
    * `len`: 实际写入的数据长度。

2. **`memstream_write(void *v, const char *b, int l)`:**  这个函数是 `FILE` 结构体的写回调函数。当使用 `fwrite` 或其他写入函数向内存流写入数据时，实际上会调用这个函数。
    * 它首先获取 `struct state` 指针。
    * 计算写入数据后所需的总大小 `end`。
    * 如果 `end` 大于当前分配的内存大小 `st->size`，则使用 `recallocarray` 重新分配更大的内存。 `recallocarray`  会分配新的内存，将旧数据拷贝过去，并释放旧的内存。增长因子大约为 1.6 (8/5)，这是一个常见的优化策略，可以在分配次数和内存浪费之间取得平衡。
    * 将要写入的数据拷贝到内存缓冲区。
    * 更新当前写入位置 `st->pos` 和数据长度 `st->len`。
    * 在数据末尾添加 null 终止符，以确保可以将其作为 C 字符串处理。
    * 更新用户提供的 `*st->psize` 指针，指向当前数据大小。

3. **`memstream_seek(void *v, fpos_t off, int whence)`:** 这个函数是 `FILE` 结构体的定位回调函数。当使用 `fseek` 等函数在内存流中移动读写位置时，会调用这个函数。
    * 它根据 `whence` 参数（`SEEK_SET`, `SEEK_CUR`, `SEEK_END`）计算新的位置。
    * 进行溢出检查，确保新的位置不会超出 `size_t` 的范围。
    * 更新当前的写入位置 `st->pos`。
    * 更新用户提供的 `*st->psize` 指针，指向 `st->pos` 和 `st->len` 中的较小值，因为用户可见的大小不会超过实际写入的数据长度。

4. **`memstream_close(void *v)`:**  这个函数是 `FILE` 结构体的关闭回调函数。当使用 `fclose` 关闭内存流时，会调用这个函数。
    * 它释放了 `struct state` 结构体占用的内存。
    * **注意：**  `memstream_close` **不会** 释放由 `st->string` 指向的内存缓冲区。 这是 `open_memstream` 的一个重要特性，允许用户在关闭流后仍然可以访问和使用内存缓冲区。 用户需要负责手动 `free(*pbuf)`。

5. **`open_memstream(char **pbuf, size_t *psize)`:**  这是创建内存流的主要函数。
    * 它首先检查输入参数 `pbuf` 和 `psize` 是否为 `NULL`，如果是则设置 `errno` 为 `EINVAL` 并返回 `NULL`。
    * 分配 `struct state` 结构体的内存。
    * 调用 `__sfp()` 获取一个可用的 `FILE` 结构体。
    * 初始化 `struct state` 的成员，包括分配初始大小为 `BUFSIZ` 的内存缓冲区。
    * 将用户提供的指针 `pbuf` 和 `psize` 存储到 `struct state` 中。
    * 更新用户提供的 `*pbuf` 指针，使其指向新分配的内存缓冲区。
    * 更新用户提供的 `*psize` 指针，初始值为 0。
    * 配置 `FILE` 结构体的各种成员：
        * `_flags = __SWR`: 设置流的标志为可写。
        * `_file = -1`:  表示这不是一个与文件描述符关联的流。
        * `_cookie = st`:  将 `struct state` 指针存储到 `FILE` 结构体中，以便在回调函数中访问。
        * `_read = NULL`:  内存流不可读。
        * `_write = memstream_write`:  设置写回调函数。
        * `_seek = memstream_seek`:  设置定位回调函数。
        * `_close = memstream_close`: 设置关闭回调函数。
        * `_SET_ORIENTATION(fp, -1)`: 设置流的宽字符方向。

6. **`DEF_WEAK(open_memstream)`:**  这是一个宏定义，通常用于表示该符号是弱符号。这意味着如果在链接时找到了另一个名为 `open_memstream` 的强符号定义，链接器会优先使用强符号。这允许库在运行时被覆盖或提供不同的实现。

**涉及 dynamic linker 的功能:**

`open_memstream` 本身的代码并没有直接涉及到动态链接器的具体操作。但是，作为 `libc.so` 的一部分，它的加载和链接是由动态链接器负责的。

**so 布局样本:**

```
libc.so:
    ...
    .text:
        ...
        open_memstream:  // open_memstream 函数的代码
            ...
        memstream_write: // memstream_write 函数的代码
            ...
        memstream_seek:  // memstream_seek 函数的代码
            ...
        memstream_close: // memstream_close 函数的代码
            ...
    .data:
        ...
    .bss:
        ...
    .dynsym: // 动态符号表，包含 open_memstream 等导出符号
        ... open_memstream ...
    .dynstr: // 动态字符串表，包含符号名称
        ... "open_memstream" ...
    .rel.dyn: // 动态重定位表
        ...
```

**链接的处理过程:**

1. **编译:** 当你编译一个使用 `open_memstream` 的程序时，编译器会生成对 `open_memstream` 的未定义符号引用。
2. **链接:**  链接器在链接时会查找 `libc.so` 中的 `open_memstream` 符号。由于 `open_memstream` 是 `libc.so` 导出的符号，链接器会将程序中的符号引用解析到 `libc.so` 中 `open_memstream` 的地址。
3. **加载:** 当程序运行时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载 `libc.so` 到进程的地址空间。
4. **重定位:** 动态链接器会根据 `.rel.dyn` 表中的信息，调整程序中对 `open_memstream` 的调用地址，使其指向 `libc.so` 中 `open_memstream` 的实际地址。

**假设输入与输出 (逻辑推理):**

假设我们有以下代码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *buffer;
    size_t size;
    FILE *memstream = open_memstream(&buffer, &size);
    if (memstream == NULL) {
        perror("open_memstream");
        return 1;
    }

    fprintf(memstream, "Test data: %d", 123);
    fclose(memstream);

    printf("Buffer: \"%s\", Size: %zu\n", buffer, size);
    free(buffer);
    return 0;
}
```

**预期输出:**

```
Buffer: "Test data: 123", Size: 13
```

**解释:**

* `open_memstream` 会分配一个初始缓冲区。
* `fprintf` 会将 "Test data: 123" (加上 null 终止符共 13 字节) 写入内存流。
* `fclose` 关闭流，但不释放 `buffer` 指向的内存。
* `printf` 打印 `buffer` 的内容和 `size` 的值。
* `free(buffer)` 释放分配的内存。

**用户或编程常见的使用错误:**

1. **忘记检查返回值:** `open_memstream` 可能返回 `NULL` (例如，内存分配失败)。不检查返回值会导致空指针解引用。
   ```c
   char *buffer;
   size_t size;
   FILE *memstream = open_memstream(&buffer, &size);
   fprintf(memstream, "Data"); // 如果 open_memstream 返回 NULL，这里会崩溃
   ```

2. **忘记释放内存:** `open_memstream` 分配的内存需要用户手动释放。如果忘记 `free(buffer)`，会导致内存泄漏。
   ```c
   char *buffer;
   size_t size;
   FILE *memstream = open_memstream(&buffer, &size);
   fprintf(memstream, "Data");
   fclose(memstream);
   // 忘记 free(buffer);
   ```

3. **假设缓冲区以 null 结尾但没有写入任何内容:** 如果你创建了一个内存流但不向其写入任何内容，`buffer` 指向的内存可能没有 null 终止符。
   ```c
   char *buffer;
   size_t size;
   FILE *memstream = open_memstream(&buffer, &size);
   fclose(memstream);
   printf("%s\n", buffer); // 可能读取到未初始化的内存
   free(buffer);
   ```
   实际上，`open_memstream` 的实现会在初始分配时使用 `calloc`，保证了初始缓冲区是零初始化的，并且在每次写入后会添加 null 终止符。但这仍然是一个需要注意的点，特别是在更复杂的场景中。

4. **在 `fclose` 之后访问缓冲区但没有写入任何数据:** 虽然 `fclose` 不会释放缓冲区，但如果你没有写入任何数据，缓冲区的内容可能是未定义的。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 使用:**  Native 代码（使用 NDK 开发的 C/C++ 代码）可以直接调用 `open_memstream`，因为它属于标准 C 库的一部分。

   ```c++
   // NDK 代码
   #include <cstdio>
   #include <cstdlib>

   void writeToMemory() {
       char *buffer;
       size_t size;
       FILE *memstream = open_memstream(&buffer, &size);
       if (memstream) {
           fprintf(memstream, "Data from NDK");
           fclose(memstream);
           // ... 使用 buffer ...
           free(buffer);
       }
   }
   ```

2. **Framework 使用 (间接):** Android Framework 的某些部分可能在内部使用标准 C 库的功能，从而间接地使用 `open_memstream`。例如，某些格式化操作或数据处理可能会用到内存流作为中间缓冲区。

   例如，Java 代码可能会调用一个 native 方法，该 native 方法使用 `snprintf` 或类似的函数将数据格式化到内存中。虽然没有直接调用 `open_memstream`，但 `snprintf` 的底层实现可能涉及到类似内存缓冲区的管理。

**Frida Hook 示例调试步骤:**

可以使用 Frida Hook 来观察 `open_memstream` 的调用和行为。以下是一个基本的 Frida 脚本示例：

```javascript
if (Process.platform === 'android') {
  const open_memstreamPtr = Module.findExportByName("libc.so", "open_memstream");

  if (open_memstreamPtr) {
    Interceptor.attach(open_memstreamPtr, {
      onEnter: function (args) {
        console.log("[open_memstream] Called");
        this.pbuf = args[0];
        this.psize = args[1];
        console.log("[open_memstream] pbuf:", args[0]);
        console.log("[open_memstream] psize:", args[1]);
      },
      onLeave: function (retval) {
        console.log("[open_memstream] Returned:", retval);
        if (retval.isNull()) {
          console.log("[open_memstream] Error: Return value is NULL");
        } else {
          const bufferPtr = Memory.readPointer(this.pbuf);
          const sizeValue = Memory.readULong(this.psize);
          console.log("[open_memstream] *pbuf (buffer address):", bufferPtr);
          console.log("[open_memstream] *psize (initial size):", sizeValue);
        }
      }
    });

    const memstream_writePtr = Module.findExportByName("libc.so", "memstream_write");
    if (memstream_writePtr) {
        Interceptor.attach(memstream_writePtr, {
            onEnter: function(args) {
                console.log("[memstream_write] Called");
                console.log("[memstream_write] v:", args[0]);
                console.log("[memstream_write] b:", args[1]);
                console.log("[memstream_write] l:", args[2]);
                console.log("[memstream_write] Data to write:", Memory.readUtf8String(args[1], args[2].toInt()));
            },
            onLeave: function(retval) {
                console.log("[memstream_write] Returned:", retval);
            }
        });
    }

    const fclosePtr = Module.findExportByName("libc.so", "fclose");
    if (fclosePtr) {
        Interceptor.attach(fclosePtr, {
            onEnter: function(args) {
                console.log("[fclose] Called");
                console.log("[fclose] stream:", args[0]);
            },
            onLeave: function(retval) {
                console.log("[fclose] Returned:", retval);
            }
        });
    }
  } else {
    console.log("[open_memstream] Not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 frida-server。
2. **找到目标进程:** 确定你想要 hook 的进程的名称或 PID。
3. **运行 Frida 脚本:** 使用 `frida -U -f <包名> -l your_script.js --no-pause`  或 `frida -U <进程名或 PID> -l your_script.js` 运行上述 Frida 脚本。
4. **观察输出:** 当目标应用调用 `open_memstream`, `memstream_write`, 或 `fclose` 时，Frida 会拦截这些调用并打印相关信息，例如传入的参数、返回值以及写入的数据。

通过 Frida Hook，你可以动态地观察 `open_memstream` 的行为，了解何时被调用，传入了哪些参数，以及内存缓冲区是如何被分配和写入的。这对于理解 Android 系统或应用如何使用这个函数非常有帮助。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdio/open_memstream.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: open_memstream.c,v 1.10 2023/07/11 12:14:16 claudio Exp $	*/

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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "local.h"

#define	MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

struct state {
	char		 *string;	/* actual stream */
	char		**pbuf;		/* point to the stream */
	size_t		 *psize;	/* point to min(pos, len) */
	size_t		  pos;		/* current position */
	size_t		  size;		/* number of allocated char */
	size_t		  len;		/* length of the data */
};

static int
memstream_write(void *v, const char *b, int l)
{
	struct state	*st = v;
	char		*p;
	size_t		 i, end;

	end = (st->pos + l);

	if (end >= st->size) {
		/* 1.6 is (very) close to the golden ratio. */
		size_t	sz = st->size * 8 / 5;

		if (sz < end + 1)
			sz = end + 1;
		p = recallocarray(st->string, st->size, sz, 1);
		if (!p)
			return (-1);
		*st->pbuf = st->string = p;
		st->size = sz;
	}

	for (i = 0; i < l; i++)
		st->string[st->pos + i] = b[i];
	st->pos += l;

	if (st->pos > st->len) {
		st->len = st->pos;
		st->string[st->len] = '\0';
	}

	*st->psize = st->pos;

	return (i);
}

static fpos_t
memstream_seek(void *v, fpos_t off, int whence)
{
	struct state	*st = v;
	size_t		 base = 0;

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

	if ((off > 0 && off > SIZE_MAX - base) || (off < 0 && base < -off)) {
		errno = EOVERFLOW;
		return (-1);
	}

	st->pos = base + off;
	*st->psize = MINIMUM(st->pos, st->len);

	return (st->pos);
}

static int
memstream_close(void *v)
{
	struct state	*st = v;

	free(st);

	return (0);
}

FILE *
open_memstream(char **pbuf, size_t *psize)
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

	st->size = BUFSIZ;
	if ((st->string = calloc(1, st->size)) == NULL) {
		free(st);
		fp->_flags = 0;
		return (NULL);
	}

	st->pos = 0;
	st->len = 0;
	st->pbuf = pbuf;
	st->psize = psize;

	*pbuf = st->string;
	*psize = st->len;

	fp->_flags = __SWR;
	fp->_file = -1;
	fp->_cookie = st;
	fp->_read = NULL;
	fp->_write = memstream_write;
	fp->_seek = memstream_seek;
	fp->_close = memstream_close;
	_SET_ORIENTATION(fp, -1);

	return (fp);
}
DEF_WEAK(open_memstream);

"""

```