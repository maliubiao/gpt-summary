Response:
Let's break down the thought process for analyzing the `ungetc.c` code.

**1. Understanding the Goal:**

The primary request is to analyze the `ungetc.c` file, explain its functionality, its relation to Android, delve into the implementation details of its associated libc functions, touch upon dynamic linking aspects (if any), discuss potential errors, and outline its usage within the Android ecosystem, including debugging via Frida.

**2. Initial Code Scan and Core Function Identification:**

The first step is to quickly scan the code to identify the main function and any helper functions. In this case, the main function is clearly `ungetc`, and there's a static helper function `__submore`. The copyright notice indicates it's derived from OpenBSD, providing context. The `#include` directives point to standard C library headers and a local header, suggesting reliance on other libc components.

**3. Deciphering `ungetc`'s Purpose:**

Based on the function name and the context of stdio, it's clear that `ungetc` is related to "un-getting" a character from a stream. The code confirms this by putting a character back into the input buffer of a `FILE` pointer.

**4. Analyzing `ungetc`'s Logic - Step by Step:**

Now, a deeper dive into the `ungetc` function's implementation is needed:

* **Error Handling:** The function immediately checks if `c` is `EOF`. This is a common error case.
* **Initialization:**  The `!__sdidinit` check suggests a lazy initialization of the stdio library.
* **Locking:** `FLOCKFILE(fp)` indicates thread safety considerations.
* **Orientation:** `_SET_ORIENTATION(fp, -1)` deals with wide character streams, ensuring compatibility. It doesn't directly manipulate the ungetc buffer itself, but it's an important side effect.
* **Read/Write Mode Checks:** The code verifies if the stream is open for reading or read/write. If it's write-only, `ungetc` won't work without flushing the write buffer first. This is a crucial constraint.
* **The `HASUB(fp)` Branch:** This is the core logic for handling existing "ungetc" buffers.
    * **Buffer Expansion:** If the buffer is full, `__submore` is called to expand it.
    * **Putting the Character Back:** The character `c` is placed at the "beginning" (conceptually, it's a stack) of the ungetc buffer. `fp->_p` is decremented, and `fp->_r` is incremented.
* **The "Backing Up" Optimization:** Before creating a new ungetc buffer, the code checks if the character can simply be placed back in the regular read buffer if it matches the last character read. This optimization avoids allocating a separate ungetc buffer in simple cases.
* **Creating a New Ungetc Buffer:**  If the above conditions are not met, a new ungetc buffer is created. The reserved buffer (`fp->_ubuf`) is used initially. Pointers and sizes are adjusted accordingly.

**5. Analyzing `__submore`:**

The purpose of `__submore` is to increase the size of the ungetc buffer. The logic involves:

* **Initial Allocation:** If the buffer is the initial small, statically allocated buffer (`fp->_ubuf`), it allocates a larger buffer using `malloc`, copies the contents, and updates the `FILE` structure.
* **Reallocation:** If it's already a dynamically allocated buffer, `reallocarray` is used to double its size, and the existing content is copied to the end of the new buffer. This stack-like behavior is key.

**6. Connecting to Android:**

* **libc Importance:** Emphasize that `ungetc` is a standard C library function and therefore fundamental to Android's C/C++ ecosystem.
* **NDK Usage:**  Highlight how NDK developers directly or indirectly use `ungetc` through standard I/O functions.
* **Framework Usage:** Mention how the Android framework, being built on C/C++, relies on libc functions like `ungetc` internally.

**7. Dynamic Linking (Limited Scope Here):**

While `ungetc.c` itself doesn't directly involve dynamic linking mechanisms, the concept of `libc.so` is relevant. Explain that `ungetc` is part of `libc.so`, which is dynamically linked to applications. Provide a basic `libc.so` layout example.

**8. Common Errors:**

Think about how developers might misuse `ungetc`:

* Calling `ungetc` with `EOF`.
* Calling `ungetc` on a write-only stream.
* Un-getting too many characters without reading them, potentially leading to memory issues (although the buffer expands).

**9. Frida Hooking:**

Provide a simple Frida script to demonstrate how to intercept calls to `ungetc`. Focus on logging arguments and return values.

**10. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use code blocks for the source code and Frida examples. Provide concrete examples for error cases and the linking process.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Focus too much on the low-level buffer manipulation. **Correction:**  Elevate the explanation to cover the higher-level functionality and context within the C library and Android.
* **Initial thought:**  Overlook the dynamic linking aspect. **Correction:**  Include a basic explanation of `libc.so` and its role.
* **Initial thought:**  Not provide concrete examples of errors. **Correction:**  Add specific scenarios where `ungetc` might be used incorrectly.
* **Initial thought:**  Make the Frida example too complex. **Correction:**  Simplify it to demonstrate the core concept of hooking function calls.

By following these steps and constantly refining the explanation, a comprehensive and accurate analysis of the `ungetc.c` code can be achieved. The key is to break down the problem into smaller, manageable parts and then synthesize the information into a coherent response.
好的，我们来详细分析一下 `bionic/libc/upstream-openbsd/lib/libc/stdio/ungetc.c` 这个文件。

**功能概述**

`ungetc.c` 文件实现了标准 C 库中的 `ungetc()` 函数。 `ungetc()` 函数的功能是将一个字符“放回”到输入流（`FILE` 指针）中。  这意味着，下一次从该流读取字符时，将会首先读取刚刚通过 `ungetc()` 放回的字符。

**与 Android 功能的关系**

`ungetc()` 是标准 C 库的一部分，因此它是 Android 系统中 C/C++ 代码的基础功能之一。 Android 的 Bionic C 库提供了对 `ungetc()` 的实现。

**举例说明:**

假设你正在编写一个解析器，从文件中读取数据。当你读取到一个字符后，发现它不是你期望的，你需要“撤回”这个字符，以便下一次读取操作能够正确处理。 这时 `ungetc()` 就派上用场了。

例如，你可能正在解析一个数字，你读取了一系列数字字符，直到遇到一个非数字字符。为了让后续的代码能够处理这个非数字字符，你需要使用 `ungetc()` 将其放回输入流。

**libc 函数的实现细节**

让我们详细解释 `ungetc()` 函数的实现：

1. **错误检查:**
   ```c
   if (c == EOF)
       return (EOF);
   ```
   首先，检查要放回的字符 `c` 是否是 `EOF`（文件结束符）。如果是，则直接返回 `EOF`，因为无法放回文件结束符。

2. **初始化检查:**
   ```c
   if (!__sdidinit)
       __sinit();
   ```
   这部分代码检查标准 I/O 库是否已经初始化。如果未初始化，则调用 `__sinit()` 进行初始化。这确保了在调用任何标准 I/O 函数之前，相关的内部数据结构都已准备就绪。

3. **线程安全:**
   ```c
   FLOCKFILE(fp);
   ```
   `FLOCKFILE()` 是一个宏，通常用于获取与 `FILE` 对象关联的锁，以确保在多线程环境中的线程安全。

4. **流方向设置:**
   ```c
   _SET_ORIENTATION(fp, -1);
   ```
   这部分代码处理流的字符方向（宽字符或窄字符）。`-1` 通常表示保持当前的字符方向。

5. **读取状态检查:**
   ```c
   if ((fp->_flags & __SRD) == 0) {
       // ...
   }
   ```
   检查文件流是否处于读取状态 (`__SRD` 标志)。如果不是，则需要进行一些额外的处理：
   * **读写权限检查:** 如果文件不是以读写模式打开 (`__SRW`)，则不能进行 `ungetc()` 操作，因为没有读取权限。
   * **刷新写缓冲区:** 如果文件是以写入模式打开 (`__SWR`) 并且有待写入的数据，则需要先调用 `__sflush(fp)` 将缓冲区中的数据写入文件。之后，清除写入相关的标志。
   * **设置读取标志:**  将文件流的状态设置为读取 (`fp->_flags |= __SRD`)。

6. **类型转换:**
   ```c
   c = (unsigned char)c;
   ```
   将要放回的字符 `c` 转换为 `unsigned char`，以确保处理的是字节值。

7. **处理已存在的 ungetc 缓冲区:**
   ```c
   if (HASUB(fp)) {
       if (fp->_r >= _UB(fp)._size && __submore(fp))
           goto error;
       *--fp->_p = c;
   inc_ret:	fp->_r++;
       FUNLOCKFILE(fp);
       return (c);
   }
   ```
   `HASUB(fp)` 宏检查 `FILE` 对象是否已经有用于 `ungetc` 的缓冲区。
   * **缓冲区扩展:** 如果缓冲区已满 (`fp->_r >= _UB(fp)._size`)，则调用 `__submore(fp)` 来扩展缓冲区。
   * **放入字符:** 将字符 `c` 放入缓冲区的前端。`fp->_p` 指针向前移动一个位置，指向新放入的字符。
   * **增加计数器:** `fp->_r` 记录了 ungetc 缓冲区中字符的数量，将其加 1。
   * **释放锁并返回:** 解锁文件流并返回放回的字符 `c`。

8. **处理文件结束符标志:**
   ```c
   fp->_flags &= ~__SEOF;
   ```
   如果之前读取到了文件结束符，调用 `ungetc()` 会清除文件结束符标志 (`__SEOF`)。

9. **优化：直接回退:**
   ```c
   if (fp->_bf._base != NULL && fp->_p > fp->_bf._base &&
       fp->_p[-1] == c) {
       fp->_p--;
       goto inc_ret;
   }
   ```
   这是一个优化措施。如果文件流有缓冲区 (`fp->_bf._base != NULL`) 并且当前指针 `fp->_p` 可以回退一个位置，并且回退位置的字符与要放回的字符 `c` 相同，则直接将指针 `fp->_p` 回退一个位置，相当于放回了字符。这避免了使用专门的 `ungetc` 缓冲区。

10. **创建 ungetc 缓冲区:**
    ```c
    fp->_ur = fp->_r;
    fp->_up = fp->_p;
    _UB(fp)._base = fp->_ubuf;
    _UB(fp)._size = sizeof(fp->_ubuf);
    fp->_ubuf[sizeof(fp->_ubuf) - 1] = c;
    fp->_p = &fp->_ubuf[sizeof(fp->_ubuf) - 1];
    fp->_r = 1;
    FUNLOCKFILE(fp);
    return (c);
    ```
    如果以上条件都不满足，则需要创建一个用于 `ungetc` 的缓冲区。
    * **保存原始状态:** 保存当前的读取计数器 `fp->_r` 到 `fp->_ur` 和当前指针 `fp->_p` 到 `fp->_up`。
    * **使用预留缓冲区:**  通常会先使用 `FILE` 结构体中预留的小缓冲区 `fp->_ubuf`。
    * **设置缓冲区信息:** 设置 ungetc 缓冲区的基地址 `_UB(fp)._base`，大小 `_UB(fp)._size`。
    * **放入字符:** 将字符 `c` 放入缓冲区的末尾。
    * **调整指针和计数器:** 将 `fp->_p` 指向缓冲区中刚放入的字符，并将 `fp->_r` 设置为 1。
    * **释放锁并返回:** 解锁文件流并返回放回的字符 `c`。

**`__submore(FILE *fp)` 函数的实现:**

```c
static int
__submore(FILE *fp)
{
	int i;
	unsigned char *p;

	if (_UB(fp)._base == fp->_ubuf) {
		/*
		 * Get a new buffer (rather than expanding the old one).
		 */
		if ((p = malloc(BUFSIZ)) == NULL)
			return (EOF);
		_UB(fp)._base = p;
		_UB(fp)._size = BUFSIZ;
		p += BUFSIZ - sizeof(fp->_ubuf);
		for (i = sizeof(fp->_ubuf); --i >= 0;)
			p[i] = fp->_ubuf[i];
		fp->_p = p;
		return (0);
	}
	i = _UB(fp)._size;
	p = reallocarray(_UB(fp)._base, i, 2);
	if (p == NULL)
		return (EOF);
	/* no overlap (hence can use memcpy) because we doubled the size */
	(void)memcpy(p + i, p, i);
	fp->_p = p + i;
	_UB(fp)._base = p;
	_UB(fp)._size = i * 2;
	return (0);
}
```

`__submore()` 函数的作用是扩展 `ungetc` 使用的缓冲区。

1. **检查是否使用预留缓冲区:**
   ```c
   if (_UB(fp)._base == fp->_ubuf) {
       // ...
   }
   ```
   如果当前使用的缓冲区是 `FILE` 结构体内的预留小缓冲区 `fp->_ubuf`，则需要分配一块更大的新缓冲区。
   * **分配新缓冲区:** 使用 `malloc(BUFSIZ)` 分配大小为 `BUFSIZ` 的内存。如果分配失败，则返回 `EOF`。
   * **设置缓冲区信息:** 更新 `FILE` 结构体中 ungetc 缓冲区的基地址和大小。
   * **复制数据:** 将原预留缓冲区中的数据复制到新缓冲区的尾部，模拟栈的行为。
   * **调整指针:** 更新 `fp->_p` 指针。

2. **扩展已分配的缓冲区:**
   ```c
   i = _UB(fp)._size;
   p = reallocarray(_UB(fp)._base, i, 2);
   if (p == NULL)
       return (EOF);
   /* no overlap (hence can use memcpy) because we doubled the size */
   (void)memcpy(p + i, p, i);
   fp->_p = p + i;
   _UB(fp)._base = p;
   _UB(fp)._size = i * 2;
   return (0);
   ```
   如果当前使用的缓冲区是动态分配的，则使用 `reallocarray()` 重新分配内存，通常会将其大小翻倍。
   * **重新分配内存:**  `reallocarray(_UB(fp)._base, i, 2)` 尝试将缓冲区大小扩展到原来的两倍。如果分配失败，返回 `EOF`。
   * **复制数据:** 由于缓冲区大小翻倍，新旧区域没有重叠，可以使用 `memcpy` 将旧缓冲区的内容复制到新缓冲区的后半部分。
   * **更新缓冲区信息:** 更新 `FILE` 结构体中 ungetc 缓冲区的基地址和大小。
   * **调整指针:** 更新 `fp->_p` 指针。

**涉及 dynamic linker 的功能**

在这个 `ungetc.c` 文件中，并没有直接涉及 dynamic linker 的功能。`ungetc` 是一个标准 C 库函数，它的实现会被编译到 `libc.so` 中。当一个程序调用 `ungetc` 时，dynamic linker 负责在运行时找到 `libc.so` 中对应的函数并进行链接。

**so 布局样本 (libc.so 的简化示例):**

```
libc.so:
    .text:
        ...
        ungetc:  # ungetc 函数的代码
            <ungetc 函数的汇编指令>
        ...
        malloc:   # malloc 函数的代码
            <malloc 函数的汇编指令>
        ...
        reallocarray: # reallocarray 函数的代码
            <reallocarray 函数的汇编指令>
        ...
    .data:
        ...
        __sdidinit: # 全局变量，标记 stdio 是否已初始化
        ...
    .bss:
        ...
```

**链接的处理过程:**

1. **编译时:** 当你的程序代码中调用了 `ungetc`，编译器会在生成目标文件时，为 `ungetc` 创建一个未解析的符号引用。
2. **链接时:** 链接器将你的目标文件与 C 运行时库（通常是 `libc.so` 的静态链接版本或包含符号信息的版本）链接在一起。链接器会记录下 `ungetc` 这个符号需要在运行时从共享库中解析。
3. **运行时:** 当程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，例如 `libc.so`。
4. **符号解析:** dynamic linker 会查找 `libc.so` 的符号表，找到 `ungetc` 函数的地址，并将程序中对 `ungetc` 的调用地址更新为 `libc.so` 中 `ungetc` 函数的实际地址。这样，当程序执行到调用 `ungetc` 的地方时，就能正确跳转到 `libc.so` 中的代码执行。

**逻辑推理的假设输入与输出**

假设我们有一个文件 "test.txt"，内容为 "abc"。

**场景 1:**

* **假设输入:** 从 "test.txt" 读取一个字符 'a'，然后调用 `ungetc('Z', fp)`。
* **输出:** 下一次从该流读取字符时，将会得到 'Z'。

**场景 2:**

* **假设输入:** 从 "test.txt" 读取三个字符 'a', 'b', 'c'。然后连续调用 `ungetc('3', fp)`, `ungetc('2', fp)`, `ungetc('1', fp)`。
* **输出:** 下三次从该流读取字符时，将会依次得到 '1', '2', '3'。

**用户或编程常见的使用错误**

1. **在未打开读取的文件流上调用 `ungetc`:**
   ```c
   FILE *fp = fopen("output.txt", "w");
   if (fp == NULL) {
       perror("fopen");
       return 1;
   }
   if (ungetc('A', fp) == EOF) { // 错误：文件以写入模式打开
       perror("ungetc");
   }
   fclose(fp);
   ```
   **错误说明:** `ungetc` 主要用于将字符放回输入流，如果文件是以写入模式打开，则无法进行此操作。

2. **连续 `ungetc` 过多字符而没有读取:**
   虽然 `ungetc` 的缓冲区会自动扩展，但如果在一个循环中不断 `ungetc` 字符而不进行读取，可能会消耗大量内存。虽然逻辑上没有错误，但可能导致资源问题。

3. **尝试 `ungetc(EOF, fp)`:**
   ```c
   FILE *fp = fopen("input.txt", "r");
   if (fp == NULL) {
       perror("fopen");
       return 1;
   }
   if (ungetc(EOF, fp) == EOF) { // 错误：不能 ungetc EOF
       perror("ungetc");
   }
   fclose(fp);
   ```
   **错误说明:**  `EOF` 表示文件结束，不是一个有效的字符，因此无法将其放回输入流。

**Android Framework 或 NDK 如何到达这里**

1. **NDK 开发:**
   * 当 NDK 开发者使用标准 C/C++ 库函数进行文件操作时，例如 `fopen`, `fgetc`, `fread` 等，在某些需要回溯输入流的情况下会间接或直接调用 `ungetc`。
   * 例如，一个 NDK 模块需要解析一个配置文件，读取到某个字符后需要判断是否是预期内容的一部分，如果不是，则可能使用 `ungetc` 将其放回。

2. **Android Framework:**
   * Android Framework 的底层是用 C/C++ 实现的，包括各种系统服务和库。
   * 在 Framework 的某些组件中，可能需要解析各种格式的数据，例如配置文件、网络协议数据等。在这些解析过程中，如果使用了标准 C 库的 I/O 函数，并且逻辑上需要将字符放回输入流，则会调用到 `ungetc`。
   * 例如，在解析 XML 或 JSON 等结构化数据时，如果读取到一个分隔符或特殊字符后需要回退，就可能用到 `ungetc`。

**Frida Hook 示例调试步骤**

以下是一个使用 Frida Hook 调试 `ungetc` 函数的示例：

假设你有一个 Android 可执行文件 `my_app`，它使用了 `ungetc` 函数。

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida server。在你的 PC 上安装了 Frida 工具。

2. **编写 Frida Hook 脚本 (ungetc_hook.js):**
   ```javascript
   if (Process.platform === 'android') {
     const libc = Process.getModuleByName("libc.so");
     const ungetcPtr = libc.getExportByName("ungetc");

     if (ungetcPtr) {
       Interceptor.attach(ungetcPtr, {
         onEnter: function (args) {
           const c = args[0].toInt();
           const fp = args[1];
           const filename = Memory.readUtf8String(Module.findRangeByAddress(fp).file.path);
           console.log(`[+] ungetc called`);
           console.log(`\tCharacter: '${String.fromCharCode(c)}' (ASCII: ${c})`);
           console.log(`\tFILE pointer: ${fp}`);
           console.log(`\tFile path: ${filename}`);
         },
         onLeave: function (retval) {
           console.log(`[+] ungetc returned: ${retval}`);
         }
       });
       console.log("[+] Hooked ungetc");
     } else {
       console.log("[-] ungetc function not found in libc.so");
     }
   } else {
     console.log("[-] This script is designed for Android.");
   }
   ```

3. **运行 Frida:**
   在你的 PC 上，使用 adb 将 Frida server 推送到 Android 设备并运行。

4. **执行 Hook 命令:**
   打开一个新的终端，执行以下 Frida 命令，将 Hook 脚本附加到目标进程：
   ```bash
   frida -U -f <your_app_package_name> -l ungetc_hook.js --no-pause
   ```
   或者，如果你的应用已经在运行：
   ```bash
   frida -U <your_app_package_name> -l ungetc_hook.js
   ```
   将 `<your_app_package_name>` 替换为你的 Android 应用的包名，或者使用进程 ID。

5. **观察输出:**
   当你的目标应用执行到 `ungetc` 函数时，Frida Hook 脚本将会拦截这次调用，并在终端上打印出相关的参数信息（要放回的字符、`FILE` 指针、可能的文件路径）以及返回值。

通过这个 Frida Hook 示例，你可以实时观察 `ungetc` 函数的调用情况，帮助你理解代码的执行流程和调试相关问题。

希望这个详细的解释能够帮助你理解 `ungetc.c` 文件的功能和实现细节。

### 提示词
```
这是目录为bionic/libc/upstream-openbsd/lib/libc/stdio/ungetc.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: ungetc.c,v 1.15 2016/09/21 04:38:56 guenther Exp $ */
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

static int __submore(FILE *);
/*
 * Expand the ungetc buffer `in place'.  That is, adjust fp->_p when
 * the buffer moves, so that it points the same distance from the end,
 * and move the bytes in the buffer around as necessary so that they
 * are all at the end (stack-style).
 */
static int
__submore(FILE *fp)
{
	int i;
	unsigned char *p;

	if (_UB(fp)._base == fp->_ubuf) {
		/*
		 * Get a new buffer (rather than expanding the old one).
		 */
		if ((p = malloc(BUFSIZ)) == NULL)
			return (EOF);
		_UB(fp)._base = p;
		_UB(fp)._size = BUFSIZ;
		p += BUFSIZ - sizeof(fp->_ubuf);
		for (i = sizeof(fp->_ubuf); --i >= 0;)
			p[i] = fp->_ubuf[i];
		fp->_p = p;
		return (0);
	}
	i = _UB(fp)._size;
	p = reallocarray(_UB(fp)._base, i, 2);
	if (p == NULL)
		return (EOF);
	/* no overlap (hence can use memcpy) because we doubled the size */
	(void)memcpy(p + i, p, i);
	fp->_p = p + i;
	_UB(fp)._base = p;
	_UB(fp)._size = i * 2;
	return (0);
}

int
ungetc(int c, FILE *fp)
{
	if (c == EOF)
		return (EOF);
	if (!__sdidinit)
		__sinit();
	FLOCKFILE(fp);
	_SET_ORIENTATION(fp, -1);
	if ((fp->_flags & __SRD) == 0) {
		/*
		 * Not already reading: no good unless reading-and-writing.
		 * Otherwise, flush any current write stuff.
		 */
		if ((fp->_flags & __SRW) == 0) {
error:			FUNLOCKFILE(fp);
			return (EOF);
		}
		if (fp->_flags & __SWR) {
			if (__sflush(fp))
				goto error;
			fp->_flags &= ~__SWR;
			fp->_w = 0;
			fp->_lbfsize = 0;
		}
		fp->_flags |= __SRD;
	}
	c = (unsigned char)c;

	/*
	 * If we are in the middle of ungetc'ing, just continue.
	 * This may require expanding the current ungetc buffer.
	 */
	if (HASUB(fp)) {
		if (fp->_r >= _UB(fp)._size && __submore(fp))
			goto error;
		*--fp->_p = c;
inc_ret:	fp->_r++;
		FUNLOCKFILE(fp);
		return (c);
	}
	fp->_flags &= ~__SEOF;

	/*
	 * If we can handle this by simply backing up, do so,
	 * but never replace the original character.
	 * (This makes sscanf() work when scanning `const' data.)
	 */
	if (fp->_bf._base != NULL && fp->_p > fp->_bf._base &&
	    fp->_p[-1] == c) {
		fp->_p--;
		goto inc_ret;
	}

	/*
	 * Create an ungetc buffer.
	 * Initially, we will use the `reserve' buffer.
	 */
	fp->_ur = fp->_r;
	fp->_up = fp->_p;
	_UB(fp)._base = fp->_ubuf;
	_UB(fp)._size = sizeof(fp->_ubuf);
	fp->_ubuf[sizeof(fp->_ubuf) - 1] = c;
	fp->_p = &fp->_ubuf[sizeof(fp->_ubuf) - 1];
	fp->_r = 1;
	FUNLOCKFILE(fp);
	return (c);
}
DEF_STRONG(ungetc);
```