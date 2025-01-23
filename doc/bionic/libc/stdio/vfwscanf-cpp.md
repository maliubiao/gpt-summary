Response:
Let's break down the thought process for analyzing the `vfwscanf.cpp` code and generating the comprehensive response.

**1. Understanding the Core Task:**

The primary goal is to understand the functionality of `vfwscanf` in Android's `bionic` library. This involves not just a surface-level description, but also delving into implementation details, Android-specific aspects, and common usage scenarios.

**2. Initial Scan and Keyword Identification:**

I started by scanning the code for key terms and patterns:

* **`vfwscanf`:** The main function, indicating variable arguments and wide character input from a file stream.
* **`FILE*`:**  Input is taken from a file pointer, a standard C I/O concept.
* **`wchar_t*`:**  Deals with wide characters, crucial for internationalization.
* **`__va_list`:**  Handles variable arguments, a key feature of `scanf`-like functions.
* **Format specifiers (`%d`, `%s`, `%c`, etc.):** The core of `scanf`'s parsing logic.
* **`iswspace`, `__fgetwc_unlock`, `__ungetwc`:**  Wide character I/O functions.
* **`wcstoimax`, `wcstoumax`, `wcstod`, `wcstof`, `wcstold`:** Wide character string conversion functions.
* **Flags (e.g., `SUPPRESS`, `LONG`, `SHORT`):**  Modify the behavior of format specifiers.
* **Character classes (`[]`):**  Matching specific sets of characters.
* **Multibyte conversions (`wcrtomb`):** Handling conversions between wide and multibyte characters.
* **`BUF`, `MB_LEN_MAX`:**  Constants related to buffer sizes.

**3. Deconstructing the Functionality:**

Based on the keywords and structure, I started outlining the main functions:

* **Parsing the Format String:** Identifying format specifiers, flags, and widths.
* **Reading Input:**  Fetching characters from the input stream (`FILE*`).
* **Matching Literals:** Handling non-format specifier characters.
* **Performing Conversions:**  Converting input based on the format specifier (integer, float, string, etc.).
* **Storing Results:** Writing the converted values to the provided arguments.
* **Error Handling:**  Dealing with input failures and mismatches.

**4. Detailed Analysis of Libc Functions:**

For each significant libc function called within `vfwscanf`, I considered its purpose:

* **`iswspace`:**  Checks for wide character whitespace.
* **`__fgetwc_unlock`:**  Reads a wide character from a file stream (thread-unsafe version).
* **`__ungetwc`:** Pushes a wide character back onto the input stream.
* **`wcstoimax`, `wcstoumax`:** Converts wide character strings to integer types. I noted the `base` parameter and handling of prefixes.
* **`wcstod`, `wcstof`, `wcstold`:** Converts wide character strings to floating-point types.
* **`wcrtomb`:** Converts a wide character to a multibyte sequence.

**5. Connecting to Android:**

The prompt specifically asked about Android relevance. I considered:

* **`bionic`:**  The context itself indicates this is part of Android's libc.
* **Internationalization:** Wide character support is vital for Android's global user base.
* **NDK Usage:**  `vfwscanf` is directly accessible through the NDK for native code.
* **Framework Calls:**  Android framework components likely use standard C library functions internally.

**6. Addressing Dynamic Linking (and Recognizing Its Absence):**

The prompt mentioned the dynamic linker. While `vfwscanf` itself *doesn't directly interact with the dynamic linker*, I realized that:

* **`vfwscanf` is *part* of a shared library (libc.so).**
* When an Android app uses `vfwscanf`, the dynamic linker is responsible for loading `libc.so` and resolving symbols.

Therefore, I explained the typical SO layout and the linking process in the broader context of using `vfwscanf`. I had to infer this broader context as the provided code snippet doesn't *contain* dynamic linking logic itself.

**7. Logical Reasoning and Examples:**

To solidify understanding, I created:

* **Input/Output Examples:** Demonstrating how different format specifiers work.
* **Common Usage Errors:**  Highlighting pitfalls like buffer overflows, format string mismatches, and incorrect argument types.

**8. Frida Hooking:**

To show how to observe `vfwscanf` in action, I crafted a Frida hook example. This involved:

* **Identifying the Target Function:** `vfwscanf` in `libc.so`.
* **Hooking Logic:** Intercepting the function call, logging arguments, and potentially modifying behavior.

**9. Structuring the Response:**

I organized the information logically:

* **Functionality Summary:**  A high-level overview.
* **Android Relevance:**  Specific connections to the Android ecosystem.
* **Detailed Libc Function Explanations:**  In-depth descriptions.
* **Dynamic Linking:**  Contextual explanation.
* **Logical Reasoning (Examples):** Illustrative scenarios.
* **Common Usage Errors:** Practical advice.
* **Android Framework/NDK Path:**  Tracing the call stack.
* **Frida Hook Example:**  A practical debugging technique.

**10. Language and Tone:**

I maintained a clear and informative tone, using Chinese as requested. I aimed for a balance between technical detail and understandable explanations.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the code *directly* manipulates dynamic linking structures.
* **Correction:**  Realized that `vfwscanf` itself is a user-space function within libc and relies on the dynamic linker implicitly when the library is loaded. The focus should be on how it *uses* functions that are resolved by the dynamic linker.
* **Considering the scope of "dynamic linker functionality":**  Shifted from expecting explicit dynamic linker calls within the `vfwscanf` code to explaining the *broader* context of how the dynamic linker makes `vfwscanf` available to applications.

By following this systematic approach, combining code analysis with contextual understanding and illustrative examples, I was able to generate a comprehensive and accurate response to the prompt.
好的，让我们详细分析一下 `bionic/libc/stdio/vfwscanf.cpp` 这个文件。

**功能概述:**

`vfwscanf` 函数是 C 标准库 `<stdio.h>` 中 `fwscanf` 函数的可变参数版本。它从指定的输入流 `fp` 中读取格式化的数据，并将结果存储到由可变参数列表 `ap` 指向的位置。简单来说，它的主要功能是：

1. **格式化输入:**  根据提供的格式字符串 `fmt` 解析输入流中的数据。
2. **数据转换:** 将输入流中的文本数据转换为指定的数据类型（例如，整数、浮点数、字符串）。
3. **存储结果:** 将转换后的数据存储到 `ap` 指向的变量中。

**与 Android 功能的关系及举例:**

作为 Android 的 C 库（bionic）的一部分，`vfwscanf` 是 Android 系统和应用程序中处理格式化输入的基础工具。很多上层组件和应用程序都会间接地或直接地使用它。

**举例说明:**

* **命令行工具:**  Android 的 shell 环境和一些命令行工具（例如 `dumpsys`, `logcat`）在处理用户输入或解析配置文件时，可能会使用 `vfwscanf` 或其相关函数。例如，一个工具可能需要从用户输入中读取一个整数和一个字符串：

   ```c
   #include <stdio.h>
   #include <wchar.h>

   int main() {
       int number;
       wchar_t text[100];

       fwscanf(stdin, L"%d %ls", &number, text);
       wprintf(L"你输入了数字: %d，文本: %ls\n", number, text);
       return 0;
   }
   ```

* **系统服务:**  Android 的一些系统服务可能会使用 `vfwscanf` 解析配置文件或接收到的格式化数据。例如，一个网络服务可能需要解析包含 IP 地址和端口号的字符串。

* **NDK 开发:**  使用 Android NDK 进行原生 C/C++ 开发时，开发者可以直接调用 `vfwscanf` 函数来处理输入。例如，一个游戏引擎可能需要从配置文件中读取关卡数据。

**libc 函数的实现细节:**

现在，让我们逐行分析代码，解释其中涉及的关键 libc 函数的实现：

1. **`_SET_ORIENTATION(fp, ORIENT_CHARS);`**:
   - 功能：设置文件流 `fp` 的方向为字符方向。这对于处理宽字符流非常重要，确保后续的宽字符 I/O 操作正确进行。
   - 实现：这个宏通常会调用底层的文件操作函数，例如 `fwide`（如果存在）或者直接设置 `FILE` 结构体内部的标志位来指示流的方向。

2. **`iswspace(c)`**:
   - 功能：判断宽字符 `c` 是否是空白字符（例如空格、制表符、换行符）。
   - 实现：通常会查阅一个预定义的表格或者使用位运算来检查字符的 Unicode 属性。不同的空白字符在 Unicode 标准中有明确的定义。

3. **`__fgetwc_unlock(fp)`**:
   - 功能：从文件流 `fp` 中读取下一个宽字符。`_unlock` 后缀表明这是一个非线程安全的版本，通常在已经持有文件锁的情况下使用，以提高性能。
   - 实现：会调用底层的系统调用（例如 `read`）从文件描述符读取数据，然后根据文件流的编码方式（例如 UTF-8）将读取的字节序列转换为宽字符。如果到达文件末尾，则返回 `WEOF`。

4. **`__ungetwc(c, fp)`**:
   - 功能：将宽字符 `c` 推回文件流 `fp`，使得下一次读取操作会先读到这个字符。
   - 实现：通常会将字符存储回文件流的内部缓冲区中，并调整缓冲区的指针。每次 `ungetwc` 只能推回一个字符。

5. **`in_ccl(wchar_t wc, const wchar_t* ccl)` (静态内联函数)**:
   - 功能：判断宽字符 `wc` 是否属于字符类 `ccl` 中定义的字符集合。字符类通常用于 `scanf` 的 `%[` 格式符。
   - 实现：
     - 首先检查字符类是否以 `^` 开头，表示取反。
     - 遍历字符类字符串，处理特殊字符 `-`（表示范围）和 `]`（表示字符类结束）。
     - 如果 `wc` 在字符类定义的范围内，则返回 `true`（或 `false` 如果字符类是取反的）。

6. **`wcstoimax(buf, NULL, base)` 和 `wcstoumax(buf, NULL, base)`**:
   - 功能：将宽字符串 `buf` 转换为 `intmax_t` (有符号最大整数类型) 或 `uintmax_t` (无符号最大整数类型)。 `base` 参数指定了数字的基数（例如 10 表示十进制，16 表示十六进制）。
   - 实现：
     - 跳过前导的空白字符。
     - 处理可选的正负号。
     - 根据 `base` 的值，解析数字的每一位。
     - 进行溢出检查，确保结果在目标类型的范围内。
     - 返回转换后的整数值。

7. **`wcstold(buf, &p)`, `wcstod(buf, &p)`, `wcstof(buf, &p)`**:
   - 功能：将宽字符串 `buf` 转换为 `long double`, `double`, 或 `float` 类型的浮点数。
   - 实现：
     - 跳过前导的空白字符。
     - 处理可选的正负号。
     - 解析整数部分、小数点和小数部分。
     - 处理可选的指数部分（例如 `e+10`）。
     - 根据 IEEE 754 标准将解析出的数值转换为浮点数。
     - 更新指针 `p` 指向解析停止的位置。

8. **`wcrtomb(mbp, wi, &mbs)`**:
   - 功能：将宽字符 `wi` 转换为多字节序列，并存储到 `mbp` 指向的缓冲区中。 `mbs` 是一个 `mbstate_t` 类型的对象，用于维护转换状态，这对于处理有状态的编码（例如 Shift-JIS）很重要。
   - 实现：
     - 根据当前的 locale 设置和编码方式，将宽字符转换为相应的多字节序列。
     - 更新 `mbs` 的状态，以便后续的转换可以正确进行。
     - 返回写入 `mbp` 的字节数，如果发生错误则返回 `(size_t)(-1)`。

**涉及 dynamic linker 的功能 (间接涉及):**

`vfwscanf.cpp` 本身并没有直接涉及动态链接器的代码。然而，作为 `libc.so` 的一部分，`vfwscanf` 的运行依赖于动态链接器在程序启动时完成符号解析和库加载。

**so 布局样本 (libc.so):**

```
libc.so:
    .text         # 包含可执行代码
        vfwscanf   # vfwscanf 函数的代码位于 .text 段
        ...        # 其他 libc 函数
    .data         # 包含已初始化的全局变量
        ...
    .bss          # 包含未初始化的全局变量
        ...
    .dynsym       # 动态符号表，包含导出的符号（例如 vfwscanf）
    .dynstr       # 动态字符串表，包含符号名称的字符串
    .rel.dyn      # 动态重定位表，用于在加载时修正地址
    .plt          # 程序链接表，用于延迟绑定
    .got          # 全局偏移表，存储外部符号的地址
```

**链接的处理过程:**

1. **编译时:** 编译器将 `vfwscanf` 的调用生成为对外部符号的引用。
2. **链接时:** 静态链接器（在构建 shared library 时）会在 `libc.so` 的 `.dynsym` 和 `.dynstr` 中记录导出的符号 `vfwscanf`。
3. **运行时:** 当一个应用程序调用 `vfwscanf` 时：
   - 如果是静态链接，`vfwscanf` 的代码直接包含在应用程序的可执行文件中（这种情况较少见，Android 应用通常动态链接 libc）。
   - 如果是动态链接，动态链接器负责加载 `libc.so` 到内存中。
   - 动态链接器会查看应用程序的依赖关系，找到 `libc.so`。
   - 它会解析应用程序中对 `vfwscanf` 的引用，并在 `libc.so` 的 `.dynsym` 中找到 `vfwscanf` 的地址。
   - 动态链接器会更新应用程序的全局偏移表 (`.got`) 或程序链接表 (`.plt`)，使得对 `vfwscanf` 的调用能够跳转到 `libc.so` 中 `vfwscanf` 的实际代码位置。
   - **延迟绑定:** 通常情况下，为了提高启动速度，动态链接器会使用延迟绑定。这意味着在第一次调用 `vfwscanf` 时才会进行符号解析和地址绑定。`plt` 表中的指令会跳转到动态链接器的代码，由动态链接器完成符号解析，并将 `got` 表项更新为 `vfwscanf` 的真实地址，后续的调用将直接跳转到 `vfwscanf`。

**逻辑推理的假设输入与输出:**

假设我们有以下代码片段：

```c
#include <stdio.h>
#include <wchar.h>

int main() {
    int num1, num2;
    wchar_t str[20];
    FILE *fp = stdin; // 从标准输入读取

    fwscanf(fp, L"%d %x %ls", &num1, &num2, str);
    wprintf(L"num1: %d, num2: %x, str: %ls\n", num1, num2, str);
    return 0;
}
```

**假设输入:**

```
123  0xabc  测试字符串
```

**预期输出:**

```
num1: 123, num2: abc, str: 测试字符串
```

**详细解释:**

- `%d`: 读取一个十进制整数，将 "123" 转换为整数 `123` 并存储到 `num1`。
- `%x`: 读取一个十六进制整数，将 "0xabc" 转换为整数 `0xabc`（十进制 2748）并存储到 `num2`。注意，`fwscanf` 会自动处理 "0x" 前缀。
- `%ls`: 读取一个宽字符串，直到遇到空白字符为止，将 "测试字符串" 存储到 `str`。

**用户或编程常见的使用错误:**

1. **缓冲区溢出:**  使用 `%s` 或 `%[` 读取字符串时，如果输入的字符串长度超过了目标缓冲区的大小，会导致缓冲区溢出，可能引发安全漏洞。

   ```c
   wchar_t buffer[10];
   fwscanf(stdin, L"%ls", buffer); // 如果输入超过 9 个字符的字符串，就会溢出
   ```

2. **格式字符串不匹配:**  提供的格式字符串与实际的输入数据不符，会导致解析错误或未定义的行为。

   ```c
   int num;
   wchar_t str[20];
   fwscanf(stdin, L"%ls %d", &num, str); // 期望先输入字符串，再输入数字，如果输入反了就会出错
   ```

3. **参数类型不匹配:**  传递给 `fwscanf` 的参数类型与格式符不匹配。

   ```c
   int num;
   fwscanf(stdin, L"%ls", &num); // 期望读取字符串，但却传递了 int 的地址
   ```

4. **忘记检查返回值:** `fwscanf` 的返回值表示成功匹配和赋值的字段数。忽略返回值可能导致程序在输入不符合预期时出现逻辑错误。

   ```c
   int num;
   if (fwscanf(stdin, L"%d", &num) != 1) {
       // 输入不是一个有效的整数，处理错误
       wprintf(L"输入错误！\n");
   }
   ```

5. **使用 `%c` 读取单个字符时的空白问题:** `%c` 不会跳过空白字符，如果需要跳过空白字符，需要在 `%c` 前面加一个空格。

   ```c
   wchar_t ch;
   fwscanf(stdin, L" %c", &ch); // 注意 %c 前面的空格
   ```

**Android framework 或 NDK 如何到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `vfwscanf` 的路径 (可能路径):**

1. **Java Framework 层:** Android Framework 的 Java 代码（例如，在 `InputMethodService` 中处理用户输入）可能会调用 JNI 方法。
2. **JNI 层:** JNI 方法会调用 Native 代码。
3. **Native 代码:** Native 代码中可能调用了标准 C 库函数，例如 `fscanf`, `fwscanf` 或其变体。例如，一个处理配置文件或网络数据的模块。

**NDK 到 `vfwscanf` 的路径:**

1. **NDK 应用代码:**  使用 NDK 开发的应用程序可以直接调用标准 C 库函数，包括 `vfwscanf`。
2. **libc.so:** 这些调用会链接到 `bionic` 提供的 `libc.so` 中的 `vfwscanf` 实现。

**Frida Hook 示例:**

以下是一个使用 Frida hook `vfwscanf` 的示例，用于观察其参数和行为：

```javascript
// frida script

if (Process.arch === "arm64" || Process.arch === "arm") {
    const libc = Process.getModuleByName("libc.so");
    const vfwscanfPtr = libc.getExportByName("vfwscanf");

    if (vfwscanfPtr) {
        Interceptor.attach(vfwscanfPtr, {
            onEnter: function (args) {
                const fp = new NativePointer(args[0]);
                const fmt = new NativePointer(args[1]).readUtf16String();
                console.log(`[vfwscanf] Entering vfwscanf`);
                console.log(`[vfwscanf]   fp: ${fp}`);
                console.log(`[vfwscanf]   fmt: ${fmt}`);

                // 你可以遍历 args 来查看更多参数，但这需要知道格式字符串的含义
                // 例如，如果 fmt 是 "%d %s"，那么 args[2] 和 args[3] 就是存储结果的指针
            },
            onLeave: function (retval) {
                console.log(`[vfwscanf] Leaving vfwscanf`);
                console.log(`[vfwscanf]   retval: ${retval}`);
            }
        });
    } else {
        console.log("[vfwscanf] vfwscanf not found in libc.so");
    }
} else {
    console.log("[vfwscanf] Hooking vfwscanf is only supported on ARM and ARM64 architectures.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存到一个文件中，例如 `hook_vfwscanf.js`。
2. 确保你的 Android 设备已 root，并且安装了 Frida。
3. 使用 adb 连接到你的设备。
4. 找到你想要 hook 的进程的进程 ID (PID)。
5. 运行 Frida 命令：

   ```bash
   frida -U -f <包名> -l hook_vfwscanf.js
   # 或者，如果进程已经在运行：
   frida -U <进程名或 PID> -l hook_vfwscanf.js
   ```

   将 `<包名>` 替换为你要 hook 的应用的包名，或者将 `<进程名或 PID>` 替换为进程名或 PID。

**Frida Hook 输出示例:**

当你 hook 的应用程序调用 `vfwscanf` 时，你会在 Frida 的控制台看到类似以下的输出：

```
[#] Attaching...
[#] Loaded script: hook_vfwscanf.js
[vfwscanf] Entering vfwscanf
[vfwscanf]   fp: 0xXXXXXXXXXXXX
[vfwscanf]   fmt: %d %s
[vfwscanf] Leaving vfwscanf
[vfwscanf]   retval: 2
```

这个输出表明 `vfwscanf` 被调用了，并显示了文件指针 `fp` 的地址、格式字符串 `fmt` 的内容，以及返回值（表示成功匹配了 2 个字段）。你可以根据需要修改 Frida 脚本来查看和修改参数，以进行更深入的调试。

希望这个详细的分析对你有所帮助！

### 提示词
```
这是目录为bionic/libc/stdio/vfwscanf.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: vfwscanf.c,v 1.4 2014/03/19 05:17:01 guenther Exp $ */
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

#include "scanf_common.h"

// An interpretive version of __sccl from vfscanf.c --- a table of all wchar_t values would
// be a little too expensive, and some kind of compressed version isn't worth the trouble.
static inline bool in_ccl(wchar_t wc, const wchar_t* ccl) {
  // Is this a negated set?
  bool member_result = true;
  if (*ccl == '^') {
    member_result = false;
    ++ccl;
  }

  // The first character may be ']' or '-' without being special.
  if (*ccl == '-' || *ccl == ']') {
    // A literal match?
    if (*ccl == wc) return member_result;
    ++ccl;
  }

  while (*ccl && *ccl != ']') {
    // The last character may be '-' without being special.
    if (*ccl == '-' && ccl[1] != '\0' && ccl[1] != ']') {
      wchar_t first = *(ccl - 1);
      wchar_t last = *(ccl + 1);
      if (first <= last) {
        // In the range?
        if (wc >= first && wc <= last) return member_result;
        ccl += 2;
        continue;
      }
      // A '-' is not considered to be part of a range if the character after
      // is not greater than the character before, so fall through...
    }
    // A literal match?
    if (*ccl == wc) return member_result;
    ++ccl;
  }
  return !member_result;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-larger-than="

/*
 * vfwscanf
 */
int __vfwscanf(FILE* __restrict fp, const wchar_t* __restrict fmt, __va_list ap) {
  wint_t c;               /* character from format, or conversion */
  size_t width;           /* field width, or 0 */
  wchar_t* p;             /* points into all kinds of strings */
  int n;                  /* handy integer */
  int flags;              /* flags as defined above */
  wchar_t* p0;            /* saves original value of p when necessary */
  int nassigned;          /* number of fields assigned */
  int nconversions;       /* number of conversions */
  int nread;              /* number of characters consumed from fp */
  int base;               /* base argument to strtoimax/strtouimax */
  wchar_t buf[BUF];       /* buffer for numeric conversions */
  const wchar_t* ccl;
  wint_t wi;              /* handy wint_t */
  char* mbp;              /* multibyte string pointer for %c %s %[ */
  size_t nconv;           /* number of bytes in mb. conversion */
  char mbbuf[MB_LEN_MAX]; /* temporary mb. character buffer */
  mbstate_t mbs;

  _SET_ORIENTATION(fp, ORIENT_CHARS);

  nassigned = 0;
  nconversions = 0;
  nread = 0;
  base = 0; /* XXX just to keep gcc happy */
  for (;;) {
    c = *fmt++;
    if (c == 0) {
      return (nassigned);
    }
    if (iswspace(c)) {
      while ((c = __fgetwc_unlock(fp)) != WEOF && iswspace(c))
        ;
      if (c != WEOF) __ungetwc(c, fp);
      continue;
    }
    if (c != '%') goto literal;
    width = 0;
    flags = 0;
    /*
     * switch on the format.  continue if done;
     * break once format type is derived.
     */
  again:
    c = *fmt++;
  reswitch:
    switch (c) {
      case '%':
      literal:
        if ((wi = __fgetwc_unlock(fp)) == WEOF) goto input_failure;
        if (wi != c) {
          __ungetwc(wi, fp);
          goto match_failure;
        }
        nread++;
        continue;

      case '*':
        flags |= SUPPRESS;
        goto again;
      case 'j':
        flags |= MAXINT;
        goto again;
      case 'L':
        flags |= LONGDBL;
        goto again;
      case 'h':
        if (*fmt == 'h') {
          fmt++;
          flags |= SHORTSHORT;
        } else {
          flags |= SHORT;
        }
        goto again;
      case 'l':
        if (*fmt == 'l') {
          fmt++;
          flags |= LLONG;
        } else {
          flags |= LONG;
        }
        goto again;
      case 'q':
        flags |= LLONG; /* deprecated */
        goto again;
      case 't':
        flags |= PTRINT;
        goto again;
      case 'z':
        flags |= SIZEINT;
        goto again;

      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        width = width * 10 + c - '0';
        goto again;

      /*
       * Conversions.
       * Those marked `compat' are for 4.[123]BSD compatibility.
       */
      case 'b':
        c = CT_INT;
        base = 2;
        flags |= PFBOK; /* enable 0b prefixing */
        break;

      case 'D': /* compat */
        flags |= LONG;
        __BIONIC_FALLTHROUGH;
      case 'd':
        c = CT_INT;
        base = 10;
        break;

      case 'i':
        c = CT_INT;
        base = 0;
        break;

      case 'O': /* compat */
        flags |= LONG;
        __BIONIC_FALLTHROUGH;
      case 'o':
        c = CT_INT;
        flags |= UNSIGNED;
        base = 8;
        break;

      case 'u':
        c = CT_INT;
        flags |= UNSIGNED;
        base = 10;
        break;

      case 'w': {
        int size = 0;
        bool fast = false;
        c = *fmt++;
        if (c == 'f') {
          fast = true;
          c = *fmt++;
        }
        while (is_digit(c)) {
          APPEND_DIGIT(size, c);
          c = *fmt++;
        }
        flags |= w_to_flag(size, fast);
        goto reswitch;
      }

      case 'X':
      case 'x':
        flags |= PFXOK; /* enable 0x prefixing */
        c = CT_INT;
        flags |= UNSIGNED;
        base = 16;
        break;

      case 'e':
      case 'E':
      case 'f':
      case 'F':
      case 'g':
      case 'G':
      case 'a':
      case 'A':
        c = CT_FLOAT;
        break;

      case 's':
        c = CT_STRING;
        break;

      case '[':
        ccl = fmt;
        if (*fmt == '^') fmt++;
        if (*fmt == ']') fmt++;
        while (*fmt != '\0' && *fmt != ']') fmt++;
        fmt++;
        flags |= NOSKIP;
        c = CT_CCL;
        break;

      case 'c':
        flags |= NOSKIP;
        c = CT_CHAR;
        break;

      case 'p': /* pointer format is like hex */
        flags |= POINTER | PFXOK;
        c = CT_INT;
        flags |= UNSIGNED;
        base = 16;
        break;

      case 'n':
        nconversions++;
        if (flags & SUPPRESS) continue;
        if (flags & SHORTSHORT)
          *va_arg(ap, signed char*) = nread;
        else if (flags & SHORT)
          *va_arg(ap, short*) = nread;
        else if (flags & LONG)
          *va_arg(ap, long*) = nread;
        else if (flags & SIZEINT)
          *va_arg(ap, ssize_t*) = nread;
        else if (flags & PTRINT)
          *va_arg(ap, ptrdiff_t*) = nread;
        else if (flags & LLONG)
          *va_arg(ap, long long*) = nread;
        else if (flags & MAXINT)
          *va_arg(ap, intmax_t*) = nread;
        else
          *va_arg(ap, int*) = nread;
        continue;

      /*
       * Disgusting backwards compatibility hacks.	XXX
       */
      case '\0': /* compat */
        return (EOF);

      default: /* compat */
        if (iswupper(c)) flags |= LONG;
        c = CT_INT;
        base = 10;
        break;
    }

    /*
     * Consume leading white space, except for formats
     * that suppress this.
     */
    if ((flags & NOSKIP) == 0) {
      while ((wi = __fgetwc_unlock(fp)) != WEOF && iswspace(wi)) nread++;
      if (wi == WEOF) goto input_failure;
      __ungetwc(wi, fp);
    }

    /*
     * Do the conversion.
     */
    switch (c) {
      case CT_CHAR:
        /* scan arbitrary characters (sets NOSKIP) */
        if (width == 0) width = 1;
        if (flags & LONG) {
          if (!(flags & SUPPRESS)) p = va_arg(ap, wchar_t*);
          n = 0;
          while (width-- != 0 && (wi = __fgetwc_unlock(fp)) != WEOF) {
            if (!(flags & SUPPRESS)) *p++ = static_cast<wchar_t>(wi);
            n++;
          }
          if (n == 0) goto input_failure;
          nread += n;
          if (!(flags & SUPPRESS)) nassigned++;
        } else {
          if (!(flags & SUPPRESS)) mbp = va_arg(ap, char*);
          n = 0;
          memset(&mbs, 0, sizeof(mbs));
          while (width != 0 && (wi = __fgetwc_unlock(fp)) != WEOF) {
            if (width >= MB_CUR_MAX && !(flags & SUPPRESS)) {
              nconv = wcrtomb(mbp, wi, &mbs);
              if (nconv == static_cast<size_t>(-1)) goto input_failure;
            } else {
              nconv = wcrtomb(mbbuf, wi, &mbs);
              if (nconv == static_cast<size_t>(-1)) goto input_failure;
              if (nconv > width) {
                __ungetwc(wi, fp);
                break;
              }
              if (!(flags & SUPPRESS)) memcpy(mbp, mbbuf, nconv);
            }
            if (!(flags & SUPPRESS)) mbp += nconv;
            width -= nconv;
            n++;
          }
          if (n == 0) goto input_failure;
          nread += n;
          if (!(flags & SUPPRESS)) nassigned++;
        }
        nconversions++;
        break;

      case CT_CCL:
      case CT_STRING:
        // CT_CCL: scan a (nonempty) character class (sets NOSKIP).
        // CT_STRING: like CCL, but zero-length string OK, & no NOSKIP.
        if (width == 0) width = SIZE_MAX; // 'infinity'.
        if ((flags & SUPPRESS) && (flags & LONG)) {
          n = 0;
          while ((wi = __fgetwc_unlock(fp)) != WEOF && width-- != 0 && ((c == CT_CCL && in_ccl(wi, ccl)) || (c == CT_STRING && !iswspace(wi)))) n++;
          if (wi != WEOF) __ungetwc(wi, fp);
        } else if (flags & LONG) {
          p0 = p = va_arg(ap, wchar_t*);
          while ((wi = __fgetwc_unlock(fp)) != WEOF && width-- != 0 && ((c == CT_CCL && in_ccl(wi, ccl)) || (c == CT_STRING && !iswspace(wi)))) {
            *p++ = static_cast<wchar_t>(wi);
          }
          if (wi != WEOF) __ungetwc(wi, fp);
          n = p - p0;
        } else {
          if (!(flags & SUPPRESS)) mbp = va_arg(ap, char*);
          n = 0;
          memset(&mbs, 0, sizeof(mbs));
          while ((wi = __fgetwc_unlock(fp)) != WEOF && width != 0 && ((c == CT_CCL && in_ccl(wi, ccl)) || (c == CT_STRING && !iswspace(wi)))) {
            if (width >= MB_CUR_MAX && !(flags & SUPPRESS)) {
              nconv = wcrtomb(mbp, wi, &mbs);
              if (nconv == static_cast<size_t>(-1)) goto input_failure;
            } else {
              nconv = wcrtomb(mbbuf, wi, &mbs);
              if (nconv == static_cast<size_t>(-1)) goto input_failure;
              if (nconv > width) break;
              if (!(flags & SUPPRESS)) memcpy(mbp, mbbuf, nconv);
            }
            if (!(flags & SUPPRESS)) mbp += nconv;
            width -= nconv;
            n++;
          }
          if (wi != WEOF) __ungetwc(wi, fp);
        }
        if (c == CT_CCL && n == 0) goto match_failure;
        if (!(flags & SUPPRESS)) {
          if (flags & LONG) {
            *p = L'\0';
          } else {
            *mbp = '\0';
          }
          ++nassigned;
        }
        nread += n;
        nconversions++;
        break;

      case CT_INT:
        /* scan an integer as if by strtoimax/strtoumax */
        if (width == 0 || width > sizeof(buf) / sizeof(*buf) - 1)
          width = sizeof(buf) / sizeof(*buf) - 1;
        flags |= SIGNOK | NDIGITS | NZDIGITS;
        for (p = buf; width; width--) {
          c = __fgetwc_unlock(fp);
          /*
           * Switch on the character; `goto ok'
           * if we accept it as a part of number.
           */
          switch (c) {
            /*
             * The digit 0 is always legal, but is
             * special.  For %i conversions, if no
             * digits (zero or nonzero) have been
             * scanned (only signs), we will have
             * base==0.  In that case, we should set
             * it to 8 and enable 0b/0x prefixing.
             * Also, if we have not scanned zero digits
             * before this, do not turn off prefixing
             * (someone else will turn it off if we
             * have scanned any nonzero digits).
             */
            case '0':
              if (base == 0) {
                base = 8;
                flags |= PFBOK | PFXOK;
              }
              if (flags & NZDIGITS) {
                flags &= ~(SIGNOK | NZDIGITS | NDIGITS);
              } else {
                flags &= ~(SIGNOK | PFBOK | PFXOK | NDIGITS);
              }
              goto ok;

            /* 1 through 7 always legal */
            case 'B':
            case 'b':
              // Is this 'b' potentially part of an "0b" prefix?
              if ((flags & PFBOK) && p == buf + 1 + !!(flags & HAVESIGN)) {
                base = 2;
                flags &= ~PFBOK;
                goto ok;
              }
              // No? Fall through and see if it's a hex digit instead then...
              __BIONIC_FALLTHROUGH;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case 'A':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
            case 'a':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
              if (base == 0) base = 10;
              if (base != 16 && static_cast<int>(c - '0') >= base) break; /* not legal here */
              flags &= ~(SIGNOK | PFBOK | PFXOK | NDIGITS);
              goto ok;

            /* sign ok only as first character */
            case '+':
            case '-':
              if (flags & SIGNOK) {
                flags &= ~SIGNOK;
                flags |= HAVESIGN;
                goto ok;
              }
              break;

            /*
             * x ok iff flag still set and 2nd char (or
             * 3rd char if we have a sign).
             */
            case 'x':
            case 'X':
              if ((flags & PFXOK) && p == buf + 1 + !!(flags & HAVESIGN)) {
                base = 16; /* if %i */
                flags &= ~PFXOK;
                goto ok;
              }
              break;
          }

          /*
           * If we got here, c is not a legal character
           * for a number.  Stop accumulating digits.
           */
          if (c != WEOF) __ungetwc(c, fp);
          break;
        ok:
          /*
           * c is legal: store it and look at the next.
           */
          *p++ = static_cast<wchar_t>(c);
        }
        /*
         * If we had only a sign, it is no good; push back the sign.
         * If the number was `[-+]0[BbXx]`, push back and treat it
         * as `[-+]0`.
         */
        if (flags & NDIGITS) {
          if (p > buf) __ungetwc(*--p, fp);
          goto match_failure;
        }
        c = p[-1];
        if ((base == 2 && (c == 'b' || c == 'B')) || c == 'x' || c == 'X') {
          --p;
          __ungetwc(c, fp);
        }
        if ((flags & SUPPRESS) == 0) {
          uintmax_t res;

          *p = '\0';
          if (flags & UNSIGNED)
            res = wcstoimax(buf, NULL, base);
          else
            res = wcstoumax(buf, NULL, base);
          if (flags & POINTER)
            *va_arg(ap, void**) = reinterpret_cast<void*>(res);
          else if (flags & MAXINT)
            *va_arg(ap, intmax_t*) = res;
          else if (flags & LLONG)
            *va_arg(ap, long long*) = res;
          else if (flags & SIZEINT)
            *va_arg(ap, ssize_t*) = res;
          else if (flags & PTRINT)
            *va_arg(ap, ptrdiff_t*) = res;
          else if (flags & LONG)
            *va_arg(ap, long*) = res;
          else if (flags & SHORT)
            *va_arg(ap, short*) = res;
          else if (flags & SHORTSHORT)
            *va_arg(ap, signed char*) = res;
          else
            *va_arg(ap, int*) = res;
          nassigned++;
        }
        nread += p - buf;
        nconversions++;
        break;

      case CT_FLOAT:
        /* scan a floating point number as if by strtod */
        if (width == 0 || width > sizeof(buf) / sizeof(*buf) - 1)
          width = sizeof(buf) / sizeof(*buf) - 1;
        if ((width = wparsefloat(fp, buf, buf + width)) == 0) goto match_failure;
        if ((flags & SUPPRESS) == 0) {
          if (flags & LONGDBL) {
            long double res = wcstold(buf, &p);
            *va_arg(ap, long double*) = res;
          } else if (flags & LONG) {
            double res = wcstod(buf, &p);
            *va_arg(ap, double*) = res;
          } else {
            float res = wcstof(buf, &p);
            *va_arg(ap, float*) = res;
          }
          if (static_cast<size_t>(p - buf) != width) abort();
          nassigned++;
        }
        nread += width;
        nconversions++;
        break;
    }
  }
input_failure:
  return (nconversions != 0 ? nassigned : EOF);
match_failure:
  return (nassigned);
}
#pragma GCC diagnostic pop
```