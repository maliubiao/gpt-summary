Response:
Let's break down the thought process for answering the request about `c32rtomb.cpp`.

**1. Understanding the Core Request:**

The fundamental request is to analyze the provided C++ code snippet for `c32rtomb.cpp` within the context of Android's Bionic library. The request asks for a detailed explanation of its functionality, its relation to Android, how it's implemented, and considerations for linking, errors, usage, and debugging.

**2. Initial Code Analysis (High-Level):**

* **File and Purpose:** The filename `c32rtomb.cpp` and the include of `<uchar.h>` strongly suggest it deals with converting 32-bit characters (`char32_t`) to multibyte character sequences. The "rtomb" part hints at a "restartable to multibyte" conversion, suggesting state management.
* **Includes:**  `<errno.h>`, `<uchar.h>`, `<wchar.h>` confirm character encoding and error handling are involved. The private header `"private/bionic_mbstate.h"` indicates interaction with Bionic's internal multibyte state management.
* **Function Signature:** `size_t c32rtomb(char* s, char32_t c32, mbstate_t* ps)` clearly defines the input: a destination buffer (`s`), a 32-bit character (`c32`), and a state object (`ps`). It returns the number of bytes written.

**3. Detailed Code Walkthrough and Functionality Identification:**

* **State Management:** The code handles the `ps` pointer. If it's null, it uses a static private state. This confirms the restartable nature and the provision for stateless calls.
* **Null Pointer Handling:**  If `s` is null, it resets the state and returns 1 (equivalent to converting a null wide character). This is a POSIX requirement.
* **Null Character Handling:**  If `c32` is a null character, it writes a null byte and resets the state.
* **Shift State Handling (or Lack Thereof):** The comment explicitly mentions shift sequences are not supported. This simplifies the implementation.
* **ASCII Optimization:**  There's a fast path for ASCII characters (0-127), writing a single byte.
* **UTF-8 Encoding:** The code then checks the range of `c32` to determine the number of bytes required for UTF-8 encoding (2, 3, or 4 bytes). The bitwise operations and the `lead` variable (0xc0, 0xe0, 0xf0) are the telltale signs of UTF-8 encoding prefixes.
* **Error Handling:**  If `c32` falls outside the valid Unicode range (requiring more than 4 bytes, which UTF-8 doesn't directly support), it sets `errno` to `EILSEQ` and returns a special error code.
* **Byte Construction:** The loop constructs the multibyte sequence, placing the most significant bits into the leading byte and subsequent 6-bit chunks into following bytes with the `0x80` prefix.

**4. Relating to Android:**

* **Core C Library:**  `c32rtomb` is part of the standard C library, so it's fundamental to many Android components.
* **Internationalization (I18N):**  Android needs to support various languages and character sets, making Unicode conversion functions like this crucial.
* **Text Processing:**  Any operation involving text manipulation, from UI rendering to file I/O, might indirectly use this function.

**5. libc Function Implementation Details:**

The code itself *is* the implementation. The explanation involves breaking down the logic of each conditional statement, bitwise operation, and loop. The key is explaining *why* each step is taken (e.g., the purpose of the `lead` byte, the `0x80` mask).

**6. Dynamic Linker Aspects:**

* **Symbol Resolution:**  The `c32rtomb` function itself needs to be resolved by the dynamic linker when a program uses it.
* **Shared Library Structure:** The explanation involves describing the typical structure of a shared object (`.so`) containing libc, including the `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), and symbol tables.
* **Linking Process:** The steps involve the linker finding the symbol, relocating it, and making it available to the calling program.

**7. Logic Inference (Hypothetical Input/Output):**

Creating examples of different input `char32_t` values and the expected UTF-8 output helps solidify understanding. This involves manually applying the encoding rules.

**8. Common Usage Errors:**

Identifying potential errors helps users avoid pitfalls. Examples include buffer overflows, incorrect state management, and passing invalid `char32_t` values.

**9. Android Framework/NDK Path and Frida Hooking:**

* **Tracing the Call Stack:**  This requires thinking about how a high-level Android API (e.g., `String`) might eventually lead to a low-level C function like `c32rtomb`.
* **NDK Usage:**  Demonstrating how an NDK application could directly call `c32rtomb`.
* **Frida:**  Providing concrete Frida code to intercept and inspect the function's arguments and return value. This involves knowing basic Frida syntax.

**10. Structuring the Answer:**

Organizing the information logically is crucial for clarity. Using headings and bullet points helps break down the complex information into manageable chunks. Starting with a general overview and then diving into details is a good strategy.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  "It converts char32_t to multibyte."  *Refinement:*  Be more specific: "It converts a 32-bit character to its UTF-8 representation."
* **Initial thought:** "It handles errors." *Refinement:*  Specify the type of error (invalid character sequence) and how it's reported (`errno`).
* **Realization:**  The code explicitly mentions the lack of shift state support. This needs to be highlighted as a simplification.
* **Dynamic Linker:** Initially, I might just say "the linker resolves it." *Refinement:* Provide more details about the sections of the `.so` file and the steps involved in linking.
* **Frida Example:**  Start with a basic hook and then add details like printing arguments and the return value.

By following these steps of analysis, detailed examination, relating to the environment, and structuring the information, one can arrive at a comprehensive and accurate answer to the user's request. The key is to move from the general to the specific and to explain the "why" behind the code's logic.
好的，我们来详细分析一下 `bionic/libc/bionic/c32rtomb.cpp` 这个文件的功能和实现。

**功能列举:**

`c32rtomb` 函数的主要功能是将一个 32 位的宽字符 `char32_t` (通常用于表示 Unicode 代码点) 转换为一个多字节序列，存储在 `char` 类型的缓冲区中。更具体地说，它将 `char32_t` 编码为 UTF-8 格式的多字节序列。

**与 Android 功能的关系及举例:**

`c32rtomb` 是 Android C 库 (Bionic) 的一部分，因此它直接支持 Android 系统和应用程序的国际化 (i18n) 和本地化 (l10n) 功能。Android 需要处理各种语言的字符，而 UTF-8 是一种广泛使用的 Unicode 字符编码。

**举例说明:**

* **Java/Kotlin String 与 NDK 交互:** 当 Java 或 Kotlin 代码中的 `String` 对象（内部使用 UTF-16 编码）传递到 NDK (Native Development Kit) 代码中，可能需要转换为 UTF-8 以便与 C/C++ 库或系统调用交互。反之亦然。`c32rtomb` 可以作为转换过程中的一个环节。例如，一个 Java `String` 中的字符可能先被转换为 `char32_t`，然后使用 `c32rtomb` 编码为 UTF-8 字节序列。
* **文件 I/O:**  Android 系统中，文件通常以 UTF-8 编码存储。当原生代码需要将 Unicode 字符写入文件时，可以使用 `c32rtomb` 将 `char32_t` 转换为 UTF-8 字节。
* **网络传输:**  很多网络协议也使用 UTF-8 编码传输文本数据。在原生网络编程中，`c32rtomb` 可以用于将 Unicode 字符转换为网络传输所需的 UTF-8 格式。

**libc 函数的实现细节:**

我们逐行分析 `c32rtomb` 函数的实现：

1. **包含头文件:**
   ```c++
   #include <errno.h>
   #include <uchar.h>
   #include <wchar.h>

   #include "private/bionic_mbstate.h"
   ```
   * `<errno.h>`:  用于定义错误代码，例如 `EILSEQ` (非法字节序列)。
   * `<uchar.h>`:  定义了 `char32_t` 类型。
   * `<wchar.h>`:  提供了宽字符相关的函数和类型，虽然 `c32rtomb` 处理的是 `char32_t`，但与宽字符处理有一定的关联。
   * `"private/bionic_mbstate.h"`:  定义了多字节转换状态 `mbstate_t` 的相关操作，是 Bionic 内部使用的头文件。

2. **函数签名:**
   ```c++
   size_t c32rtomb(char* s, char32_t c32, mbstate_t* ps)
   ```
   * `s`: 指向用于存储多字节序列的缓冲区的指针。如果 `s` 为 `nullptr`，则该函数相当于调用 `c32rtomb(buf, U'\0', ps)`，即处理空字符。
   * `c32`: 要转换的 32 位宽字符。
   * `ps`: 指向多字节转换状态对象的指针。如果 `ps` 为 `nullptr`，则使用静态的私有状态 `__private_state`。

3. **处理空指针 `s`:**
   ```c++
   static mbstate_t __private_state;
   mbstate_t* state = (ps == nullptr) ? &__private_state : ps;

   if (s == nullptr) {
     // Equivalent to c32rtomb(buf, U'\0', ps).
     return mbstate_reset_and_return(1, state);
   }
   ```
   * 如果 `s` 为 `nullptr`，则函数不会执行转换，而是重置转换状态 `state` 并返回 1，这符合 POSIX 标准，表示处理空宽字符。`mbstate_reset_and_return` 是 Bionic 内部用于处理状态重置的辅助函数。

4. **处理空字符 `c32`:**
   ```c++
   if (c32 == U'\0') {
     *s = '\0';
     return mbstate_reset_and_return(1, state);
   }
   ```
   * 如果要转换的字符是空字符 (`U'\0'`)，则在缓冲区 `s` 中写入一个空字节 (`'\0'`)，并重置转换状态，返回 1。

5. **检查初始转换状态:**
   ```c++
   if (!mbstate_is_initial(state)) {
     return mbstate_reset_and_return_illegal(EILSEQ, state);
   }
   ```
   * `mbstate_is_initial` 检查转换状态是否处于初始状态。由于 UTF-8 编码是无状态的，这里通常应该返回 true。如果状态不是初始状态，则表示可能存在错误，函数会返回一个错误值，并将 `errno` 设置为 `EILSEQ`。

6. **快速处理 ASCII 字符:**
   ```c++
   if ((c32 & ~0x7f) == 0) {
     // Fast path for plain ASCII characters.
     *s = c32;
     return 1;
   }
   ```
   * 如果 `c32` 是一个 ASCII 字符 (其值小于等于 127，二进制表示的最高位为 0)，则直接将其写入缓冲区 `s`，并返回 1，因为 ASCII 字符在 UTF-8 中占用一个字节。

7. **确定 UTF-8 编码所需的字节数:**
   ```c++
   uint8_t lead;
   size_t length;
   // We already handled the 1-byte case above, so we go straight to 2-bytes...
   if ((c32 & ~0x7ff) == 0) {
     lead = 0xc0;
     length = 2;
   } else if ((c32 & ~0xffff) == 0) {
     lead = 0xe0;
     length = 3;
   } else if ((c32 & ~0x1fffff) == 0) {
     lead = 0xf0;
     length = 4;
   } else {
     errno = EILSEQ;
     return BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE;
   }
   ```
   * 这部分代码根据 `c32` 的值范围确定其 UTF-8 编码所需的字节数。UTF-8 编码规则如下：
     * 0x00 - 0x7F:  1 字节 (已在前面的 ASCII 处理中覆盖)
     * 0x80 - 0x7FF: 2 字节，第一个字节以 `0xC0` (110xxxxx) 开头
     * 0x800 - 0xFFFF: 3 字节，第一个字节以 `0xE0` (1110xxxx) 开头
     * 0x10000 - 0x1FFFFF: 4 字节，第一个字节以 `0xF0` (11110xxx) 开头
   * `lead` 变量存储 UTF-8 序列的第一个字节的前缀部分，用于指示序列的长度。
   * `length` 变量存储所需的字节数。
   * 如果 `c32` 的值超过了 4 字节 UTF-8 编码的范围，则认为是非法序列，设置 `errno` 并返回错误代码 `BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE`。

8. **生成 UTF-8 字节序列:**
   ```c++
   for (size_t i = length - 1; i > 0; i--) {
     s[i] = (c32 & 0x3f) | 0x80;
     c32 >>= 6;
   }
   *s = (c32 & 0xff) | lead;
   ```
   * 这是一个循环，用于生成 UTF-8 序列的后续字节（除了第一个字节）。
   * `c32 & 0x3f`:  提取 `c32` 的低 6 位。
   * `| 0x80`:  将低 6 位与 `0x80` (10xxxxxx) 进行或运算，得到 UTF-8 序列中后续字节的格式。
   * `c32 >>= 6`:  将 `c32` 右移 6 位，准备处理下一组 6 位。
   * 循环结束后，处理第一个字节：
     * `c32 & 0xff`:  提取剩余的低 8 位（或更少）。
     * `| lead`:  将提取的位与前面计算得到的 `lead` 值进行或运算，得到 UTF-8 序列的第一个字节。

9. **返回写入的字节数:**
   ```c++
   return length;
   ```
   * 函数返回写入到缓冲区 `s` 的字节数，即 UTF-8 序列的长度。

**Dynamic Linker 的功能及 SO 布局样本和链接处理过程:**

`c32rtomb` 函数本身是 Bionic libc 库中的一个普通函数，不直接涉及 dynamic linker 的核心功能，例如符号重定位等。但是，当一个应用程序调用 `c32rtomb` 时，dynamic linker 负责加载 libc 库，并将应用程序的调用链接到 libc 中 `c32rtomb` 函数的实现。

**SO 布局样本 (libc.so):**

```
libc.so:
  .note.android.ident
  .plt             # Procedure Linkage Table，用于延迟绑定
  .text            # 代码段，包含 c32rtomb 等函数的机器码
    c32rtomb:
      <c32rtomb 函数的机器码>
  .rodata          # 只读数据段，例如字符串常量
  .data            # 已初始化数据段，例如全局变量
  .bss             # 未初始化数据段
  .symtab          # 符号表，包含 c32rtomb 等函数的符号信息
  .strtab          # 字符串表，存储符号名等字符串
  .rel.dyn         # 动态重定位表
  ...
```

**链接的处理过程:**

1. **编译时链接:** 编译器在编译应用程序时，如果遇到 `c32rtomb` 函数的调用，会生成一个对该符号的未解析引用。
2. **打包:** 打包工具将应用程序及其依赖的库（包括 libc.so）打包成 APK 文件。
3. **加载时链接 (Dynamic Linking):** 当 Android 系统启动应用程序时，`linker` (dynamic linker) 负责加载应用程序依赖的共享库。
4. **符号解析:** `linker` 会解析应用程序中对 `c32rtomb` 的引用。它会在 `libc.so` 的符号表 (`.symtab`) 中查找名为 `c32rtomb` 的符号。
5. **重定位:** 找到符号后，`linker` 会更新应用程序代码中的地址，使其指向 `libc.so` 中 `c32rtomb` 函数的实际地址。这个过程称为重定位。
6. **延迟绑定 (Lazy Binding):** 通常，为了提高启动速度，动态链接器会采用延迟绑定。这意味着在第一次调用 `c32rtomb` 时才会进行真正的符号查找和重定位。PLT (Procedure Linkage Table) 和 GOT (Global Offset Table) 用于实现延迟绑定。

**假设输入与输出 (逻辑推理):**

* **假设输入:** `c32 = U'A'` (ASCII 字符 'A', 十进制 65), `s` 指向一个至少 1 字节的缓冲区。
   * **输出:** `s[0] = 'A'`, 函数返回 `1`。
* **假设输入:** `c32 = U'é'` (拉丁字母 'é', Unicode 代码点 U+00E9, 十进制 233), `s` 指向一个至少 2 字节的缓冲区。
   * **输出:** `s[0] = 0xC3`, `s[1] = 0xA9` (UTF-8 编码), 函数返回 `2`。
* **假设输入:** `c32 = U'中'` (汉字 '中', Unicode 代码点 U+4E2D, 十进制 20013), `s` 指向一个至少 3 字节的缓冲区。
   * **输出:** `s[0] = 0xE4`, `s[1] = 0xB8`, `s[2] = 0xAD` (UTF-8 编码), 函数返回 `3`。
* **假设输入:** `c32 = U'🚀'` (火箭表情符号, Unicode 代码点 U+1F680, 十进制 128640), `s` 指向一个至少 4 字节的缓冲区。
   * **输出:** `s[0] = 0xF0`, `s[1] = 0x9F`, `s[2] = 0x9A`, `s[3] = 0x80` (UTF-8 编码), 函数返回 `4`。
* **假设输入:** `c32` 是一个无效的 Unicode 代码点 (超出 UTF-8 编码范围)，例如一个非常大的数。
   * **输出:** 函数返回 `BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE`，并且 `errno` 被设置为 `EILSEQ`。

**用户或编程常见的使用错误:**

* **缓冲区溢出:**  如果提供的缓冲区 `s` 太小，无法容纳转换后的 UTF-8 序列，会导致缓冲区溢出，造成程序崩溃或安全漏洞。
   ```c++
   char buf[2]; // 缓冲区太小，无法存储 '中' 的 UTF-8 编码
   char32_t c = U'中';
   c32rtomb(buf, c, nullptr); // 缓冲区溢出
   ```
* **未检查返回值:**  `c32rtomb` 返回写入的字节数。如果发生错误，会返回一个特定的错误值。程序员应该检查返回值以处理错误情况。
   ```c++
   char buf[4];
   char32_t c = some_input;
   size_t result = c32rtomb(buf, c, nullptr);
   if (result == (size_t)-1) { // 假设 BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE 为 -1
       perror("c32rtomb failed");
   }
   ```
* **错误地理解状态参数:** 虽然 `c32rtomb` 的 UTF-8 转换通常是无状态的，但在某些情况下，使用 `mbstate_t` 可以处理更复杂的字符编码。对于 UTF-8，通常可以传递 `nullptr` 作为状态参数。但是，如果与其他有状态的转换函数混用，可能会导致问题。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

**Android Framework 到 `c32rtomb` 的路径 (示例):**

1. **Java `String` 操作:**  Android Framework 中的文本处理通常从 Java 层的 `String` 类开始。
2. **JNI 调用:** 当需要将 Java `String` 传递到 Native 代码时，会使用 JNI (Java Native Interface)。
3. **`GetStringUTFChars` 或 `GetStringUTFRegion`:** JNI 函数如 `GetStringUTFChars` 或 `GetStringUTFRegion` 可以将 Java `String` 转换为 UTF-8 格式的 C 风格字符串。
4. **Bionic libc 函数:**  `GetStringUTFChars` 的内部实现可能会调用 Bionic libc 中与字符编码转换相关的函数，这些函数可能会间接或直接地使用到 `c32rtomb` 或类似的函数，例如 `wcrtomb`（用于转换宽字符）。

**NDK 到 `c32rtomb` 的路径 (示例):**

1. **NDK C/C++ 代码:**  开发者在 NDK 中编写 C/C++ 代码。
2. **直接调用:**  如果需要在 Native 代码中处理 `char32_t` 到 UTF-8 的转换，可以直接调用 `c32rtomb` 函数。

**Frida Hook 示例:**

以下是一个使用 Frida hook `c32rtomb` 函数的示例：

```javascript
// attach 到目标进程
const processName = "your.app.package.name";
const session = frida.attach(processName);

session.then(() => {
    const libc = Process.getModuleByName("libc.so");
    const c32rtombAddress = libc.getExportByName("c32rtomb");

    if (c32rtombAddress) {
        Interceptor.attach(c32rtombAddress, {
            onEnter: function (args) {
                const s = args[0];
                const c32 = args[1].toInt();
                const ps = args[2];

                console.log("[c32rtomb] Called");
                console.log("  s:", s);
                console.log("  c32:", c32, "(U+" + c32.toString(16).toUpperCase() + ")");
                console.log("  ps:", ps);

                // 如果 s 不为空，读取缓冲区内容 (注意大小)
                if (!s.isNull()) {
                    // 假设最大可能写入 4 个字节
                    console.log("  Buffer before:", hexdump(s, { length: 4 }));
                }
            },
            onLeave: function (retval) {
                console.log("[c32rtomb] Returning:", retval.toInt());
                if (this.context.r0 != 0) { // 假设返回值在 r0 寄存器
                    const s = this.args[0];
                    if (!s.isNull() && retval.toInt() > 0) {
                        console.log("  Buffer after:", hexdump(s, { length: retval.toInt() }));
                    }
                }
            }
        });
        console.log("[*] Hooked c32rtomb");
    } else {
        console.log("[!] c32rtomb not found");
    }
});
```

**Frida Hook 步骤说明:**

1. **附加到进程:** 使用 `frida.attach()` 函数附加到目标 Android 进程。
2. **获取模块:** 使用 `Process.getModuleByName("libc.so")` 获取 `libc.so` 模块的句柄。
3. **获取函数地址:** 使用 `libc.getExportByName("c32rtomb")` 获取 `c32rtomb` 函数的地址。
4. **拦截函数:** 使用 `Interceptor.attach()` 拦截 `c32rtomb` 函数的调用。
5. **`onEnter`:** 在函数调用前执行，可以访问函数参数。
   * `args[0]`: 指向目标缓冲区的指针 `s`。
   * `args[1]`: `char32_t` 类型的字符 `c32`。
   * `args[2]`: 指向状态对象的指针 `ps`。
6. **`onLeave`:** 在函数返回后执行，可以访问返回值。
   * `retval`: 函数的返回值。
   * `this.context.r0`:  在 ARM 架构中，函数返回值通常存储在 `r0` 寄存器中。
7. **打印信息:** 在 `onEnter` 和 `onLeave` 中打印函数参数、返回值以及缓冲区的内容，以便观察函数的行为。
8. **`hexdump`:** 可以使用 Frida 内置的 `hexdump` 函数以十六进制格式查看内存内容。

通过这样的 Frida hook，你可以在运行时动态地观察 `c32rtomb` 函数的调用情况，包括传入的字符、缓冲区地址以及转换后的 UTF-8 字节序列，从而帮助你调试和理解 Android Framework 或 NDK 如何使用这个函数。

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/c32rtomb.cpp` 的功能和实现。

Prompt: 
```
这是目录为bionic/libc/bionic/c32rtomb.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <errno.h>
#include <uchar.h>
#include <wchar.h>

#include "private/bionic_mbstate.h"

size_t c32rtomb(char* s, char32_t c32, mbstate_t* ps) {
  static mbstate_t __private_state;
  mbstate_t* state = (ps == nullptr) ? &__private_state : ps;

  if (s == nullptr) {
    // Equivalent to c32rtomb(buf, U'\0', ps).
    return mbstate_reset_and_return(1, state);
  }

  // POSIX states that if char32_t is a null wide character, a null byte shall
  // be stored, preceded by any shift sequence needed to restore the initial
  // shift state. Since shift states are not supported, only the null byte is
  // stored.
  if (c32 == U'\0') {
    *s = '\0';
    return mbstate_reset_and_return(1, state);
  }

  if (!mbstate_is_initial(state)) {
    return mbstate_reset_and_return_illegal(EILSEQ, state);
  }

  if ((c32 & ~0x7f) == 0) {
    // Fast path for plain ASCII characters.
    *s = c32;
    return 1;
  }

  // Determine the number of octets needed to represent this character.
  // We always output the shortest sequence possible. Also specify the
  // first few bits of the first octet, which contains the information
  // about the sequence length.
  uint8_t lead;
  size_t length;
  // We already handled the 1-byte case above, so we go straight to 2-bytes...
  if ((c32 & ~0x7ff) == 0) {
    lead = 0xc0;
    length = 2;
  } else if ((c32 & ~0xffff) == 0) {
    lead = 0xe0;
    length = 3;
  } else if ((c32 & ~0x1fffff) == 0) {
    lead = 0xf0;
    length = 4;
  } else {
    errno = EILSEQ;
    return BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE;
  }

  // Output the octets representing the character in chunks
  // of 6 bits, least significant last. The first octet is
  // a special case because it contains the sequence length
  // information.
  for (size_t i = length - 1; i > 0; i--) {
    s[i] = (c32 & 0x3f) | 0x80;
    c32 >>= 6;
  }
  *s = (c32 & 0xff) | lead;

  return length;
}

"""

```