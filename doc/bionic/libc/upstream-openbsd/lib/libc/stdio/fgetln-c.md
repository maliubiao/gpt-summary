Response:
Let's break down the thought process for analyzing the `fgetln.c` code.

1. **Understanding the Request:** The core request is to analyze the provided C code for `fgetln`, explain its functionality, connect it to Android, detail the implementation of related libc functions, address dynamic linking (if applicable), consider common errors, and explain how Android frameworks use this function, ending with a Frida hook example.

2. **Initial Code Scan and Core Functionality Identification:**  The first step is to read through the code and identify the main purpose. The function `fgetln` is clearly about reading a line from a file stream. The function signature `char *fgetln(FILE *fp, size_t *lenp)` strongly suggests it returns a pointer to the line and its length.

3. **Deconstructing the Function Logic:** Now, go through the code block by block:
    * **Includes:**  Note the included headers (`stdio.h`, `stdlib.h`, `string.h`, `local.h`). These hint at standard input/output operations, memory allocation, string manipulation, and internal libc structures.
    * **`__slbexpand` Function:** This static helper function is for expanding the line buffer. Its logic involves checking if the current buffer is large enough and using `recallocarray` to resize it. It's crucial for handling lines longer than the initial buffer size.
    * **`fgetln` Function:**
        * **Locking:** `FLOCKFILE(fp)` suggests thread safety.
        * **Orientation:** `_SET_ORIENTATION(fp, -1)` deals with wide character streams, relevant for internationalization but less so for basic line reading.
        * **Initial Input Check:** `fp->_r <= 0 && __srefill(fp)` shows how the function handles an empty buffer, triggering a refill operation.
        * **Newline Search (First Attempt):** `memchr(fp->_p, '\n', fp->_r)` is the core optimization: if the newline is already in the current buffer, it's the fastest path.
        * **Copying to Line Buffer (If Newline Not Found):** The `for` loop handles cases where the newline isn't immediately present. This involves expanding the line buffer, copying existing data, refilling the file buffer, and repeating until a newline is found or EOF is reached.
        * **Handling EOF:** The `__SEOF` flag check is important for correctly handling the end of the file.
        * **Return Value:**  The function returns a pointer to the line and updates the `lenp` argument with the line's length.
        * **Error Handling:** The `goto error` paths are essential for cleaning up and returning `NULL` in case of issues.
        * **`DEF_WEAK(fgetln)`:** This indicates that `fgetln` might be overridden or have a default weak implementation.

4. **Connecting to Android:**
    * **Bionic:**  The prompt itself establishes that this is Bionic code, the C library for Android. This is the most direct connection.
    * **System Calls:**  Implicitly, `__srefill` (and potentially `recallocarray` internally) will eventually make system calls to read from the file descriptor.
    * **Framework/NDK:** Any Android application using standard C file operations (`fopen`, `fgets`-like behavior, though `fgetln` is less common) will indirectly use this code. The NDK provides the necessary headers and libraries.

5. **Explaining Libc Functions:**  Focus on the core libc functions used within `fgetln`:
    * **`stdio.h` related:**  `FILE`, `fopen`, `fclose`, `fread` (via `__srefill`), etc. Explain the buffering mechanism and the role of the `FILE` structure.
    * **`stdlib.h` related:** `recallocarray`, `malloc`, `free`. Explain dynamic memory allocation.
    * **`string.h` related:** `memchr`, `memcpy`. Explain basic string/memory operations.
    * **`local.h` related:** `FLOCKFILE`, `FUNLOCKFILE`, `_SET_ORIENTATION`, internal `FILE` structure members (`_r`, `_p`, `_flags`, `_lb`). Highlight the thread safety and internal buffering details.

6. **Addressing Dynamic Linking:**  `fgetln` itself doesn't directly involve dynamic linking in the sense of loading shared libraries. However, the *libc* it belongs to *is* a shared library.
    * **SO Layout:** Describe the typical structure of a `.so` file (text, data, plt, got).
    * **Linking Process:** Explain how the dynamic linker resolves symbols when an application uses `fgetln`. Focus on the PLT and GOT.

7. **Hypothetical Inputs and Outputs:** Create simple examples to illustrate how `fgetln` works with different input scenarios (short line, long line, no newline, EOF).

8. **Common Usage Errors:** Identify common mistakes developers make when using functions like `fgetln`:
    * **Forgetting to free:** If the user copies the returned buffer, they might need to free it (though `fgetln`'s buffer is managed internally).
    * **Assuming null termination:** Emphasize that `fgetln` doesn't guarantee a null terminator.
    * **Incorrect length handling:**  Misusing the returned length.

9. **Android Framework/NDK Usage:**  Illustrate how an Android app (via the NDK) might indirectly call `fgetln` through standard C file operations.

10. **Frida Hook Example:**  Provide a concise Frida script demonstrating how to intercept calls to `fgetln` and log its arguments and return value. This brings the analysis into a practical debugging context.

11. **Structure and Language:** Organize the information logically using headings and bullet points. Use clear and concise Chinese. Ensure all aspects of the prompt are addressed.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe `fgetln` is directly used by high-level Android APIs. **Correction:**  It's more likely used indirectly through standard C file operations within native code.
* **Dynamic Linking Focus:** Initially, I might overemphasize the dynamic linking *within* `fgetln` itself. **Correction:** Focus on the dynamic linking of the *libc* where `fgetln` resides.
* **Frida Complexity:**  Start with a simple Frida hook and avoid overly complex examples.

By following these steps and refining the analysis along the way, we can produce a comprehensive and accurate answer to the given request.
好的，我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/stdio/fgetln.c` 这个文件，它是 Android Bionic C 库中 `fgetln` 函数的源代码。

**`fgetln` 函数的功能**

`fgetln` 函数的主要功能是从指定的文件流（`FILE *fp`）中读取一行，但不像 `fgets` 那样会将换行符 `\n` 包含在返回的字符串中，并且返回的字符串也不会以空字符 `\0` 结尾。

更具体地说，`fgetln` 的功能是：

1. **读取一行数据：** 从文件流 `fp` 中读取字符，直到遇到换行符 `\n` 或文件结束符（EOF）。
2. **返回指针和长度：**
   - 返回一个指向包含读取到的行数据的缓冲区的指针 (`char *`)。这个缓冲区可能是 stdio 库内部的缓冲区，也可能是动态分配的。
   - 通过 `size_t *lenp` 参数返回读取到的行的长度，**不包括**可能的换行符。
3. **不保证空字符结尾：** 返回的字符串**不一定**以空字符 `\0` 结尾，因此不能直接作为 C 风格的字符串使用。
4. **允许修改返回的行：** `fgetln` 允许调用者修改返回的行数据。

**与 Android 功能的关系及举例说明**

`fgetln` 是标准 C 库函数的一部分，在 Android 系统中，它作为 Bionic libc 的一部分，被底层的系统调用和更高级的库函数所使用。虽然开发者通常不会直接调用 `fgetln`，但许多其他 I/O 操作的实现可能会依赖它。

**举例：读取配置文件**

假设一个 Android 原生应用需要读取一个文本配置文件，每行包含一个配置项。虽然开发者可能会使用更高级的函数如 `fgets` 或自定义的行读取函数，但 `fgetln` 可以作为底层实现的一部分。

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *fp = fopen("/sdcard/config.txt", "r");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    size_t len;
    char *line;
    while ((line = fgetln(fp, &len)) != NULL) {
        // 注意：line 不是以空字符结尾的，需要根据 len 来处理
        printf("Read line of length %zu: %.*s\n", len, (int)len, line);
    }

    fclose(fp);
    return 0;
}
```

在这个例子中，`fgetln` 被用来逐行读取配置文件。需要注意的是，打印读取到的行时，使用了 `%.*s` 来指定打印的长度，因为 `fgetln` 返回的字符串不保证以空字符结尾。

**详细解释每一个 libc 函数的功能是如何实现的**

1. **`__slbexpand(FILE *fp, size_t newsize)` (static 函数):**
   - **功能：** 这个函数用于扩展文件流 `fp` 的行缓冲区。当需要读取的行比当前缓冲区大时，就需要扩展缓冲区。
   - **实现：**
     - 首先检查当前缓冲区的大小 `fp->_lb._size` 是否已经大于等于 `newsize`，如果是，则不需要扩展，直接返回 0。
     - 否则，使用 `recallocarray(fp->_lb._base, fp->_lb._size, newsize, 1)` 重新分配缓冲区。
       - `recallocarray` 是 Bionic libc 提供的函数，类似于 `realloc`，但会先将新分配的内存清零。它接受旧的指针、旧的元素数量、新的元素数量和每个元素的大小作为参数。
     - 如果 `recallocarray` 分配失败（返回 `NULL`），则返回 -1。
     - 如果分配成功，更新文件流 `fp` 的行缓冲区指针 `fp->_lb._base` 和大小 `fp->_lb._size`。

2. **`fgetln(FILE *fp, size_t *lenp)`:**
   - **功能：** 从文件流 `fp` 中读取一行。
   - **实现：**
     - **加锁：** `FLOCKFILE(fp)` 用于获取文件流的锁，保证线程安全。
     - **设置方向：** `_SET_ORIENTATION(fp, -1)` 用于处理宽字符流，这里设置为 -1 表示不强制指定方向。
     - **检查是否有输入：** 如果当前缓冲区为空 (`fp->_r <= 0`) 并且需要填充缓冲区 (`__srefill(fp)`)，则尝试从底层文件描述符读取数据。如果填充失败（例如，到达文件末尾），则跳转到 `error` 标签。
     - **查找换行符（优化路径）：** 使用 `memchr(fp->_p, '\n', fp->_r)` 在当前缓冲区中查找换行符。
       - 如果找到换行符：
         - 将指针 `p` 指向换行符的下一个字符。
         - 设置返回的行指针 `ret` 为当前缓冲区的起始位置 `fp->_p`。
         - 计算行的长度 `len = p - fp->_p`。
         - 将长度赋值给 `*lenp`。
         - 设置文件流的 `__SMOD` 标志，表示缓冲区已被修改，这会影响某些 `fseek` 的优化。
         - 更新文件流的剩余可读字节数 `fp->_r` 和当前读取位置 `fp->_p`。
         - 解锁文件流 `FUNLOCKFILE(fp)` 并返回读取到的行指针 `ret`。
     - **处理换行符不在当前缓冲区的情况：**
       - 进入一个循环，不断扩展行缓冲区并读取数据。
       - 使用 `__slbexpand(fp, len + OPTIMISTIC)` 扩展行缓冲区，`OPTIMISTIC` 是一个预估的剩余行长度。
       - 使用 `memcpy(fp->_lb._base + off, fp->_p, len - off)` 将当前缓冲区的数据复制到行缓冲区。
       - 调用 `__srefill(fp)` 尝试填充文件流缓冲区。如果填充失败且不是因为文件结束，则跳转到 `error` 标签。
       - 再次使用 `memchr` 在新填充的缓冲区中查找换行符。
       - 如果找到换行符：
         - 计算剩余部分的长度并复制到行缓冲区。
         - 更新文件流的状态。
         - 跳出循环。
     - **处理文件结束：** 如果在循环中 `__srefill` 返回错误并且设置了 `__SEOF` 标志，则表示到达文件末尾，跳出循环。
     - **设置返回值：** 将行缓冲区的起始地址赋值给 `ret`，将总长度赋值给 `*lenp`。
     - **解锁并返回：** 解锁文件流并返回行指针。
     - **错误处理：** 如果在任何阶段发生错误，跳转到 `error` 标签，解锁文件流，设置 `*lenp` 为 0 并返回 `NULL`。

**涉及 dynamic linker 的功能**

`fgetln` 函数本身不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库，并解析和绑定符号引用。

然而，`fgetln` 属于 Bionic libc 这个共享库。当一个程序调用 `fgetln` 时，实际上是调用了 `libc.so` 中的 `fgetln` 函数。这个过程涉及到 dynamic linker 的以下方面：

1. **共享库加载：** 当程序启动时，dynamic linker 会加载程序依赖的共享库，包括 `libc.so`。
2. **符号解析：** 当程序调用 `fgetln` 时，链接器需要找到 `libc.so` 中 `fgetln` 函数的地址。这通常通过 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT) 来实现。

**SO 布局样本**

一个简化的 `libc.so` 的布局可能如下所示：

```
libc.so:
  .text:  // 包含可执行代码，如 fgetln 函数的机器码
    ...
    fgetln:
      <fgetln 函数的机器码>
    __slbexpand:
      <__slbexpand 函数的机器码>
    ...
  .data:  // 包含已初始化的全局变量
    ...
  .bss:   // 包含未初始化的全局变量
    ...
  .rodata: // 包含只读数据
    ...
  .plt:   // Procedure Linkage Table，用于延迟绑定
    fgetln@plt:
      <跳转到 GOT 表项的指令>
  .got:   // Global Offset Table，存储全局变量和函数地址
    fgetln@got:
      <初始时为空，运行时被 dynamic linker 填充 fgetln 的实际地址>
    ...
```

**链接的处理过程**

1. **编译时：** 编译器将 `fgetln` 的调用生成为对 PLT 中 `fgetln@plt` 的跳转。
2. **加载时：** Dynamic linker 加载 `libc.so`，并将 `fgetln@got` 的初始值设置为一个指向 PLT 中下一条指令的地址。
3. **第一次调用 `fgetln`：**
   - 程序执行到 `fgetln` 调用，跳转到 `fgetln@plt`。
   - `fgetln@plt` 中的指令将控制权转移回 dynamic linker。
   - Dynamic linker 查找 `libc.so` 中 `fgetln` 函数的实际地址。
   - Dynamic linker 将 `fgetln` 的实际地址写入 `fgetln@got`。
   - Dynamic linker 将控制权返回给程序。
4. **后续调用 `fgetln`：**
   - 程序执行到 `fgetln` 调用，跳转到 `fgetln@plt`。
   - `fgetln@plt` 中的指令直接跳转到 `fgetln@got` 中存储的 `fgetln` 实际地址，避免了再次调用 dynamic linker。

**假设输入与输出**

假设我们有一个名为 `input.txt` 的文件，内容如下：

```
This is the first line.
This is the second line.
And this is the third.
```

如果我们使用 `fgetln` 读取这个文件：

**第一次调用 `fgetln(fp, &len)`：**
- **假设输入：** `fp` 指向 `input.txt`，当前读取位置在文件开头。
- **预期输出：** `line` 指向 "This is the first line."，`len` 的值为 21。

**第二次调用 `fgetln(fp, &len)`：**
- **假设输入：** `fp` 指向 `input.txt`，当前读取位置在第一行末尾。
- **预期输出：** `line` 指向 "This is the second line."，`len` 的值为 22。

**第三次调用 `fgetln(fp, &len)`：**
- **假设输入：** `fp` 指向 `input.txt`，当前读取位置在第二行末尾。
- **预期输出：** `line` 指向 "And this is the third."，`len` 的值为 20。

**第四次调用 `fgetln(fp, &len)`：**
- **假设输入：** `fp` 指向 `input.txt`，当前读取位置在文件末尾。
- **预期输出：** `line` 为 `NULL`，`len` 的值不确定（通常为 0）。

**涉及用户或者编程常见的使用错误**

1. **假设返回的字符串以空字符结尾：** `fgetln` 返回的字符串不保证以空字符结尾，如果直接将其传递给需要空字符结尾的函数（如 `printf` 的 `%s`），可能会导致读取越界。

   ```c
   FILE *fp = fopen("file.txt", "r");
   size_t len;
   char *line = fgetln(fp, &len);
   if (line) {
       // 错误用法：假设 line 以空字符结尾
       printf("Line: %s\n", line); // 可能读取越界
       // 正确用法：指定打印长度
       printf("Line: %.*s\n", (int)len, line);
   }
   fclose(fp);
   ```

2. **忘记处理返回的长度：** 由于返回的字符串没有空字符结尾，必须使用返回的长度来正确处理字符串。

   ```c
   FILE *fp = fopen("file.txt", "r");
   size_t len;
   char *line = fgetln(fp, &len);
   if (line) {
       // 错误用法：没有使用 len，可能导致处理不完整或越界
       for (int i = 0; line[i] != '\0'; ++i) { // 错误：line 不一定以 '\0' 结尾
           // ...
       }
       // 正确用法：使用 len 来遍历字符串
       for (int i = 0; i < len; ++i) {
           // ...
       }
   }
   fclose(fp);
   ```

3. **内存管理错误（虽然 `fgetln` 内部管理缓冲区）：**  虽然 `fgetln` 内部负责缓冲区的管理，但如果用户复制了返回的字符串，需要自行管理复制的内存。

**说明 android framework or ndk 是如何一步步的到达这里**

1. **Android Framework (Java/Kotlin):**
   - Android Framework 通常使用 Java 或 Kotlin 编写。
   - 当 Framework 需要进行文件操作时，可能会使用 `java.io` 包中的类，如 `FileInputStream`, `BufferedReader` 等。
   - 这些 Java 类在底层会调用 Native 代码（通常通过 JNI）。

2. **NDK (Native Development Kit):**
   - 使用 NDK 开发的 C/C++ 代码可以直接调用 Bionic libc 提供的函数。
   - 例如，一个 NDK 应用可以使用 `fopen`, `fgetc`, `fgets` 等标准 C 库函数进行文件操作。
   - 如果底层实现中需要逐行读取，并且选择了 `fgetln` 这种方式（虽然不常见），那么就会直接调用到 `bionic/libc/upstream-openbsd/lib/libc/stdio/fgetln.c` 中的代码。

3. **系统调用：**
   - 无论是 Framework 还是 NDK，最终的文件操作都会通过系统调用（如 `read`, `open`, `close` 等）与 Linux 内核交互。
   - `fgetln` 内部的 `__srefill` 等函数会调用底层的 `read` 系统调用来填充缓冲区。

**简化的调用链示例：**

```
Android Framework (Java):
  java.io.BufferedReader.readLine()  ->  (JNI 调用)

Native Code (C++, NDK):
  <自定义的行读取函数，可能使用 fgets 或更底层的操作>
  或者，如果直接使用 Bionic libc 函数：
  FILE *fp = fopen(...);
  char *line;
  size_t len;
  while ((line = fgetln(fp, &len)) != NULL) {
      // ...
  }
  fclose(fp);

Bionic libc (C):
  bionic/libc/upstream-openbsd/lib/libc/stdio/fgetln.c (本文件)
  内部调用 __srefill 等函数

系统调用 (Kernel):
  read()
```

**Frida Hook 示例调试这些步骤**

可以使用 Frida hook `fgetln` 函数，观察其被调用时的参数和返回值。

```javascript
// attach 到目标进程
function hook_fgetln() {
    const fgetlnPtr = Module.findExportByName("libc.so", "fgetln");
    if (fgetlnPtr) {
        Interceptor.attach(fgetlnPtr, {
            onEnter: function (args) {
                const fp = new NativePointer(args[0]);
                const lenp = new NativePointer(args[1]);
                console.log("[fgetln] Called");
                console.log("  fp:", fp);
                // 可以尝试读取 FILE 结构体的内容，但结构体布局可能因 Android 版本而异
                // console.log("  fp->_fileno:", Memory.readS32(fp.add(offset_of__fileno)));
                console.log("  lenp:", lenp);
            },
            onLeave: function (retval) {
                const lenp = this.args[1];
                const len = Memory.readULong(lenp);
                if (retval) {
                    console.log("[fgetln] Return value:", retval, "Length:", len);
                    // 可以尝试读取返回的字符串，注意指定长度
                    // console.log("  Line:", Memory.readUtf8String(retval, len));
                } else {
                    console.log("[fgetln] Return value:", retval);
                }
            }
        });
        console.log("[fgetln] Hooked!");
    } else {
        console.error("[fgetln] Not found in libc.so");
    }
}

setImmediate(hook_fgetln);
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_fgetln.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_fgetln.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_fgetln.js
   ```
3. 当目标应用执行到调用 `fgetln` 的代码时，Frida 会拦截调用并打印相关信息，包括 `fp` 指针、`lenp` 指针、返回值以及读取的长度。

**注意：**

- 上述 Frida 脚本中的 `offset_of__fileno` 需要根据具体的 Android 版本和 Bionic libc 的实现来确定 `FILE` 结构体的布局。
- 读取返回的字符串时，需要使用正确的长度，避免读取越界。

希望这个详细的分析能够帮助你理解 `fgetln` 函数的功能、实现以及在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdio/fgetln.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: fgetln.c,v 1.17 2017/03/17 14:53:08 deraadt Exp $ */
/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "local.h"

/*
 * Expand the line buffer.  Return -1 on error.
 */
static int
__slbexpand(FILE *fp, size_t newsize)
{
	void *p;

	if (fp->_lb._size >= newsize)
		return (0);
	if ((p = recallocarray(fp->_lb._base, fp->_lb._size, newsize, 1)) == NULL)
		return (-1);
	fp->_lb._base = p;
	fp->_lb._size = newsize;
	return (0);
}

/*
 * Get an input line.  The returned pointer often (but not always)
 * points into a stdio buffer.  Fgetline does not alter the text of
 * the returned line (which is thus not a C string because it will
 * not necessarily end with '\0'), but does allow callers to modify
 * it if they wish.  Thus, we set __SMOD in case the caller does.
 */
char *
fgetln(FILE *fp, size_t *lenp)
{
	unsigned char *p;
	char *ret;
	size_t len;
	size_t off;

	FLOCKFILE(fp);
	_SET_ORIENTATION(fp, -1);

	/* make sure there is input */
	if (fp->_r <= 0 && __srefill(fp))
		goto error;

	/* look for a newline in the input */
	if ((p = memchr(fp->_p, '\n', fp->_r)) != NULL) {
		/*
		 * Found one.  Flag buffer as modified to keep fseek from
		 * `optimising' a backward seek, in case the user stomps on
		 * the text.
		 */
		p++;		/* advance over it */
		ret = (char *)fp->_p;
		*lenp = len = p - fp->_p;
		fp->_flags |= __SMOD;
		fp->_r -= len;
		fp->_p = p;
		FUNLOCKFILE(fp);
		return (ret);
	}

	/*
	 * We have to copy the current buffered data to the line buffer.
	 * As a bonus, though, we can leave off the __SMOD.
	 *
	 * OPTIMISTIC is length that we (optimistically) expect will
	 * accommodate the `rest' of the string, on each trip through the
	 * loop below.
	 */
#define OPTIMISTIC 80

	for (len = fp->_r, off = 0;; len += fp->_r) {
		size_t diff;

		/*
		 * Make sure there is room for more bytes.  Copy data from
		 * file buffer to line buffer, refill file and look for
		 * newline.  The loop stops only when we find a newline.
		 */
		if (__slbexpand(fp, len + OPTIMISTIC))
			goto error;
		(void)memcpy(fp->_lb._base + off, fp->_p, len - off);
		off = len;
		if (__srefill(fp)) {
			if (fp->_flags & __SEOF)
				break;
			goto error;
		}
		if ((p = memchr(fp->_p, '\n', fp->_r)) == NULL)
			continue;

		/* got it: finish up the line (like code above) */
		p++;
		diff = p - fp->_p;
		len += diff;
		if (__slbexpand(fp, len))
			goto error;
		(void)memcpy(fp->_lb._base + off, fp->_p, diff);
		fp->_r -= diff;
		fp->_p = p;
		break;
	}
	*lenp = len;
	ret = (char *)fp->_lb._base;
	FUNLOCKFILE(fp);
	return (ret);

error:
	FUNLOCKFILE(fp);
	*lenp = 0;
	return (NULL);
}
DEF_WEAK(fgetln);

"""

```