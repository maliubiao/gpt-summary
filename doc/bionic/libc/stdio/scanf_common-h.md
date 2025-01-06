Response:
Let's break down the thought process for analyzing the provided C code and generating the comprehensive response.

**1. Understanding the Request:**

The request asks for a detailed analysis of the `scanf_common.handroid` file within Android's Bionic libc. Key points to address include:

* **Functionality:** What does this code *do*?
* **Android Relevance:** How does this relate to Android's workings?
* **Libc Function Implementation:** Explain the mechanics of the functions.
* **Dynamic Linking:** If relevant, describe how it interacts with the dynamic linker, providing an SO layout example.
* **Logic Inference:** Provide examples of inputs and outputs.
* **Common Errors:** Highlight potential user/programming mistakes.
* **Android Framework/NDK Path:** Explain how this code gets invoked from higher levels.
* **Frida Hooking:**  Give a practical example of using Frida for debugging.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly read through the code to grasp its general purpose. Keywords like `vfscanf`, flags like `LONG`, `SHORT`, and data types like `intmax_t` and `ptrdiff_t` strongly suggest that this code is involved in parsing formatted input, likely for functions like `scanf`, `fscanf`, and `sscanf`. The presence of `#include <stdio.h>`, `<stdarg.h>`, `<stdlib.h>`, and `<string.h>` reinforces this. The `BUF 513` constant hints at a buffer used during parsing.

**3. Identifying Key Components and Functions:**

* **Flags (Macros):**  The numerous `#define` statements for flags like `LONG`, `SUPPRESS`, `UNSIGNED`, etc., indicate a state machine or a set of options controlling the parsing process.
* **Conversion Types (Macros):** `CT_CHAR`, `CT_CCL`, `CT_STRING`, `CT_INT`, `CT_FLOAT` clearly represent the different data types the parsing logic can handle.
* **Helper Macros:** `to_digit`, `is_digit`, and `APPEND_DIGIT` suggest specific logic for handling digit conversions and overflow checks, primarily for integer parsing.
* **`w_to_flag` Function:** This function, while seemingly small, is interesting. Its name and the comment about `%w/%wf` indicate handling of fixed-size integer arguments, which is a more specialized aspect of formatted input. The `__fortify_fatal` call suggests error handling in a debug or fortified build.

**4. Deeper Dive into Functionality:**

Based on the identified components, we can infer the following:

* **Core Purpose:** The code provides the core logic for parsing formatted input strings according to a format string, extracting values, and storing them in provided memory locations. This is the heart of the `scanf` family of functions.
* **Format Specifier Handling:** The flags and conversion types are used to interpret the format specifiers in the input string (e.g., `%d`, `%s`, `%f`, `%ld`).
* **Data Type Support:** The code handles various integer types (signed/unsigned, different sizes), floating-point numbers, characters, and strings.
* **Error Handling:**  The `APPEND_DIGIT` macro's overflow check and the `__fortify_fatal` in `w_to_flag` indicate attention to potential errors during parsing.
* **Memory Management (Optional):** The `ALLOCATE` flag suggests the possibility of dynamically allocating memory for strings.

**5. Connecting to Android:**

Since this is part of Bionic, Android's C library, its relevance is direct and fundamental:

* **System Calls:**  While this specific file might not directly make system calls, the higher-level `scanf` family will eventually rely on system calls (e.g., `read` for `fscanf`).
* **NDK Usage:**  NDK developers directly use functions like `scanf`, `fscanf`, and `sscanf` defined in `<stdio.h>`, which internally rely on this code.
* **Framework Usage:**  Although less direct, parts of the Android framework (written in C/C++) might use `scanf`-like functionality for parsing configuration files or other textual data.

**6. Explaining Libc Function Implementation:**

The request asks for details on *how* the libc functions are implemented. While this file *doesn't* implement the complete `scanf` function, it provides a crucial part. The general implementation idea involves:

* **Parsing the Format String:** Iterating through the format string, identifying format specifiers (`%d`, `%s`, etc.).
* **Matching Input:**  For each specifier, reading and parsing the corresponding data from the input stream. This involves skipping whitespace, handling signs, converting characters to numbers, etc.
* **Storing Results:**  Converting the parsed data to the appropriate type and storing it in the memory locations provided as arguments.
* **Error Handling:** Detecting mismatches between the format string and the input, overflow conditions, and other errors.

The `scanf_common.handroid` file seems to contain the common logic shared by different `scanf` variants (like `fscanf`, `sscanf`). The actual implementation of each `scanf` function would likely call into this common logic.

**7. Dynamic Linking Considerations:**

The `scanf` family of functions resides within `libc.so`. A typical SO layout would include:

* **`.text` Section:**  Contains the executable code, including the code from this file (after compilation).
* **`.rodata` Section:**  Read-only data, potentially including format strings used internally.
* **`.data` and `.bss` Sections:**  Global and static variables.
* **Symbol Table:**  Contains entries for exported functions (like `scanf`, `fscanf`).
* **Dynamic Symbol Table:**  Contains entries for symbols that need to be resolved at runtime.

The linking process would involve:

1. **Compilation:**  The `scanf_common.handroid` file is compiled into object code.
2. **Linking:** The linker combines this object code with other libc components to create `libc.so`.
3. **Dynamic Linking (at runtime):** When an application calls `scanf`, the dynamic linker (`linker64` or `linker`) resolves the `scanf` symbol to its address within `libc.so`.

**8. Logic Inference and Examples:**

Creating input/output examples is crucial for illustrating the behavior of different format specifiers and flags. Think about how the flags affect parsing.

**9. Common Errors:**

Identifying common mistakes helps users understand potential pitfalls when using `scanf`. Focus on the most frequent issues.

**10. Android Framework/NDK Path and Frida Hooking:**

Tracing the execution flow from the Android framework or NDK down to this low-level code requires understanding the call stack. Start with a high-level function call (e.g., from Java through JNI or directly in native code) and then trace the calls through the libc. Frida is an excellent tool for this. The Frida example should demonstrate how to intercept calls related to `scanf`.

**11. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use bullet points and code blocks to make the explanation easier to read and understand. Provide concise explanations for each point. Use Chinese as requested.

**Self-Correction/Refinement During the Process:**

* **Initial Assumption Check:**  Verify that the initial assumption about the file's core purpose is correct.
* **Specificity:** Avoid vague statements. Provide concrete examples and explanations.
* **Technical Accuracy:** Double-check the details about dynamic linking, SO layout, and Frida usage.
* **Completeness:** Ensure that all aspects of the request are addressed.
* **Clarity:** Review the language and ensure it is clear and easy to understand for someone with a reasonable understanding of C programming and Android.

By following this structured thought process, we can generate a comprehensive and accurate response that addresses all aspects of the user's request.
这是一个关于 Android Bionic C 库中 `scanf` 系列函数共用代码的文件 (`scanf_common.handroid`). 它包含了实现 `scanf`, `fscanf`, `sscanf` 等函数的核心逻辑。

**功能列举:**

1. **格式化输入解析:**  该文件定义了用于解析格式化输入字符串的逻辑。它负责根据格式字符串中的格式符（例如 `%d`, `%s`, `%f`）从输入流中提取数据。
2. **数据类型转换:** 它能够将输入的字符串转换为各种 C 数据类型，如整数（`int`, `long`, `long long`, `short`, `char`）、浮点数（`float`, `double`, `long double`）、字符和字符串。
3. **格式符处理:**  它解析各种格式符和修饰符，例如：
    * **类型修饰符:** `h` (short), `l` (long), `ll` (long long), `L` (long double), `z` (size_t), `j` (intmax_t), `t` (ptrdiff_t)。
    * **宽度修饰符:**  用于限制读取的字符数。
    * **域宽度:**  指定最大读取宽度。
    * **赋值抑制符:** `*`，表示读取输入但不赋值给变量。
    * **标志位:**  例如 `UNSIGNED` 用于处理无符号整数。
4. **错误处理:**  虽然代码片段本身没有显式的错误处理代码，但它在数据转换过程中会设置 `errno` 来指示错误，例如 `ENOMEM` (内存不足)。
5. **字符集匹配 (`%[...]`)**: 支持使用字符集来匹配输入。
6. **空白字符处理:** 默认情况下，`scanf` 会跳过输入中的空白字符（空格、制表符、换行符）。可以使用 `%c` 或 `[` 格式符来禁用此行为。
7. **固定大小整数支持 (`%w`)**:  提供对固定大小整数（例如 int8_t, int16_t）的支持，这在需要精确控制数据大小的场景中很有用。

**与 Android 功能的关系及举例:**

`scanf` 系列函数是 C 标准库的一部分，在 Android 系统中被广泛使用：

1. **系统服务和守护进程:** Android 的许多底层系统服务和守护进程（使用 C/C++ 编写）可能会使用 `scanf` 系列函数来解析配置文件、命令行参数或从管道读取数据。
    * **举例:** 一个负责网络配置的守护进程可能使用 `fscanf` 从配置文件中读取 IP 地址和子网掩码。
2. **NDK 开发:**  使用 Android NDK 进行原生开发的应用程序可以直接调用 `scanf`, `fscanf`, `sscanf` 等函数。
    * **举例:**  一个使用 NDK 开发的游戏可能使用 `sscanf` 解析用户输入的命令字符串。
3. **Framework 层 (间接使用):** 虽然 Android Framework 主要使用 Java 编写，但在底层的 Native 代码中，例如在 JNI 调用中，仍然会使用 `scanf` 系列函数。
    * **举例:**  一个 Framework 层的组件通过 JNI 调用到底层 Native 代码，Native 代码可能使用 `sscanf` 解析从 Java 层传递过来的字符串数据。

**libc 函数功能实现详解:**

虽然提供的代码片段只是 `scanf` 实现的一部分，我们可以推断其功能实现：

1. **状态机:** `scanf` 的实现通常使用状态机来处理格式字符串。它会逐个解析格式符，并根据当前状态采取相应的行动。
2. **格式符解析循环:**  主循环遍历格式字符串，识别不同的格式符和修饰符。
3. **输入读取:**  根据格式符的要求，从输入流中读取字符。这可能涉及到调用底层的 `read()` 系统调用 (对于 `fscanf`) 或直接从字符串读取 (对于 `sscanf`)。
4. **数据转换:**  对于数字类型的格式符，会使用类似于 `strtoimax`, `strtod` 的函数将读取的字符串转换为相应的数值类型。 代码中的 `APPEND_DIGIT` 宏展示了整数转换的一部分，它负责将读取的数字字符追加到当前数值，并检查溢出。
5. **赋值操作:** 如果格式符没有使用 `*` 抑制赋值，则将转换后的值存储到提供的参数指针指向的内存位置。
6. **错误处理:**  如果输入与格式不匹配，或者发生溢出等错误，`scanf` 会返回已成功匹配和赋值的参数数量，并可能设置 `errno`。

**涉及 dynamic linker 的功能:**

这个代码文件本身并不直接涉及 dynamic linker 的功能。`scanf` 系列函数的链接和加载是由 dynamic linker 负责的。

**so 布局样本:**

```
libc.so:
    .text         # 包含 scanf_common.handroid 编译后的机器码以及其他 libc 函数的代码
    .rodata       # 只读数据，例如格式字符串字面量
    .data         # 已初始化的全局变量和静态变量
    .bss          # 未初始化的全局变量和静态变量
    .dynsym       # 动态符号表，包含导出的符号 (例如 scanf, fscanf)
    .dynstr       # 动态字符串表，包含符号名称
    .rel.dyn      # 动态重定位表，用于在加载时调整地址
    .plt          # 程序链接表，用于延迟绑定
    .got.plt      # 全局偏移表，存储外部符号的地址
```

**链接的处理过程:**

1. **编译时:** 当编译包含 `scanf` 调用的代码时，编译器会生成对 `scanf` 函数的外部引用。
2. **链接时:** 链接器将编译后的目标文件与 libc.so 链接在一起。链接器会在 `libc.so` 的动态符号表中找到 `scanf` 的定义。
3. **运行时:** 当程序启动时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会加载程序依赖的共享库，包括 `libc.so`。
4. **符号解析:** 当程序首次调用 `scanf` 时，dynamic linker 会通过 `.plt` 和 `.got.plt` 进行延迟绑定，将 `scanf` 的地址解析为 `libc.so` 中 `scanf` 函数的实际地址。后续调用将直接跳转到该地址。

**逻辑推理与假设输入输出:**

假设我们有以下代码：

```c
#include <stdio.h>

int main() {
  int num;
  char str[20];
  scanf("%d %s", &num, str);
  printf("num: %d, str: %s\n", num, str);
  return 0;
}
```

**假设输入:** `123 hello`

**输出:** `num: 123, str: hello`

**推理过程:**

1. `scanf` 函数被调用，格式字符串为 `"%d %s"`。
2. `%d` 格式符指示读取一个整数。`scanf_common.handroid` 中的代码会跳过前导空白，读取 "123"，并将其转换为整数 123。
3. `%s` 格式符指示读取一个字符串。`scanf_common.handroid` 中的代码会跳过空白，读取 "hello"，直到遇到下一个空白字符或到达字符串末尾。
4. 转换后的整数 123 被赋值给变量 `num`，字符串 "hello" 被赋值给字符数组 `str`。
5. `printf` 函数打印结果。

**涉及用户或编程常见的使用错误:**

1. **格式符与参数类型不匹配:**  这是最常见的错误。例如，使用 `%d` 读取字符串，或者使用 `%s` 读取整数。这会导致未定义的行为，可能崩溃或产生错误的结果。
    * **例子:** `int num; scanf("%s", &num);` (应该使用 `%d`)
2. **缓冲区溢出:** 当使用 `%s` 读取字符串时，如果没有指定最大读取宽度，并且输入字符串过长，可能会导致缓冲区溢出。
    * **例子:** `char str[5]; scanf("%s", str);` 如果输入超过 4 个字符（加上 null 终止符），就会溢出。应该使用 `%Ns`，其中 N 是缓冲区大小减 1，例如 `scanf("%4s", str);`
3. **忘记取地址符 (`&`)**:  对于非数组类型的参数，需要使用 `&` 获取变量的地址。忘记使用 `&` 会导致 `scanf` 写入到错误的内存位置。
    * **例子:** `int num; scanf("%d", num);` (应该使用 `&num`)
4. **输入数据类型错误:**  如果输入的数据类型与格式符不匹配，`scanf` 可能会停止解析或产生错误的结果。
    * **例子:** `int num; scanf("%d", &num);` 如果输入 "abc"，`scanf` 将无法解析，并可能返回 0。
5. **忽略 `scanf` 的返回值:** `scanf` 返回成功匹配和赋值的输入项的数量。忽略返回值可能导致程序在输入错误时没有得到通知。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤。**

**Android Framework 到 `scanf` 的路径 (示例):**

1. **Java 代码:** Android Framework 的 Java 代码可能需要解析一些文本数据，例如从配置文件读取。
2. **JNI 调用:**  Java 代码会通过 JNI (Java Native Interface) 调用到 Native 代码 (C/C++)。
3. **Native 代码:**  在 Native 代码中，可能会使用 `sscanf` 解析从 Java 层传递过来的字符串。
   ```c++
   // JNI 函数示例
   JNIEXPORT jint JNICALL Java_com_example_myapp_MyClass_parseData(JNIEnv *env, jobject thiz, jstring data) {
       const char *utfChars = env->GetStringUTFChars(data, nullptr);
       if (utfChars == nullptr) {
           return -1;
       }
       int value1, value2;
       if (sscanf(utfChars, "%d,%d", &value1, &value2) == 2) {
           // 解析成功
           env->ReleaseStringUTFChars(data, utfChars);
           return value1 + value2;
       } else {
           // 解析失败
           env->ReleaseStringUTFChars(data, utfChars);
           return -1;
       }
   }
   ```
4. **`sscanf` 调用:**  在上面的 `sscanf` 调用中，最终会调用到 `bionic/libc/stdio/scanf_common.handroid` 中定义的通用解析逻辑。

**NDK 应用直接调用 `scanf`:**

1. **C/C++ 代码:** NDK 应用可以直接包含 `<stdio.h>` 并调用 `scanf`, `fscanf`, `sscanf` 等函数。
   ```c++
   #include <stdio.h>

   int main() {
       int age;
       printf("Enter your age: ");
       scanf("%d", &age);
       printf("You are %d years old.\n", age);
       return 0;
   }
   ```
2. **`scanf` 调用:**  这里的 `scanf` 调用会直接使用 `bionic/libc/stdio/scanf_common.handroid` 中的实现。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `sscanf` 函数的示例，可以观察其参数和返回值：

```javascript
if (Process.platform === 'android') {
  const sscanfPtr = Module.findExportByName("libc.so", "sscanf");
  if (sscanfPtr) {
    Interceptor.attach(sscanfPtr, {
      onEnter: function (args) {
        console.log("[sscanf] Called");
        console.log("[sscanf] format:", Memory.readUtf8String(args[1]));
        if (args[0]) {
          console.log("[sscanf] buffer:", Memory.readUtf8String(args[0]));
        }
        // 你可以进一步打印后续参数的值，根据格式字符串的类型进行读取
      },
      onLeave: function (retval) {
        console.log("[sscanf] Result:", retval);
      }
    });
  } else {
    console.log("[-] sscanf not found in libc.so");
  }
} else {
  console.log("[*] This script is for Android.");
}
```

**解释 Frida Hook 代码:**

1. **检查平台:**  首先检查是否在 Android 平台上运行。
2. **查找 `sscanf` 函数:** 使用 `Module.findExportByName` 在 `libc.so` 中查找 `sscanf` 函数的地址。
3. **附加拦截器:**  使用 `Interceptor.attach` 附加一个拦截器到 `sscanf` 函数。
4. **`onEnter` 函数:**  在 `sscanf` 函数被调用之前执行。
   - 打印调用信息。
   - 读取并打印格式字符串 (`args[1]`)。
   - 读取并打印输入缓冲区 (`args[0]`) (如果存在)。
   - 可以根据格式字符串进一步读取和打印后续参数的值。
5. **`onLeave` 函数:** 在 `sscanf` 函数执行完毕后执行，打印其返回值。

通过这个 Frida Hook，你可以观察到 `sscanf` 何时被调用，传递了什么参数（输入字符串和格式字符串），以及返回了什么结果。这有助于理解 Android Framework 或 NDK 如何使用 `sscanf` 以及 `scanf_common.handroid` 是如何在幕后工作的。

要调试更深层次的 `scanf_common.handroid` 内部逻辑，可能需要使用更底层的调试工具，例如 gdb 配合 Android 的 ndk-gdb，或者使用 IDA Pro 等反汇编工具进行静态分析。Frida 也可以用于 hook `scanf_common.handroid` 内部的函数（如果已知函数名或地址），但这通常需要更深入的逆向工程知识。

Prompt: 
```
这是目录为bionic/libc/stdio/scanf_common.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: vfscanf.c,v 1.31 2014/03/19 05:17:01 guenther Exp $ */
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

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <wctype.h>
#include "local.h"

#include <platform/bionic/macros.h>
#include <private/bionic_fortify.h>
#include <private/bionic_mbstate.h>

#define BUF 513 /* Maximum length of numeric string. */

// Flags used during conversion.
// Size/type:
#define LONG 0x00001        // l: long or double
#define LONGDBL 0x00002     // L: long double
#define SHORT 0x00004       // h: short
#define SHORTSHORT 0x00008  // hh: 8 bit integer
#define LLONG 0x00010       // ll: long long (+ deprecated q: quad)
#define POINTER 0x00020     // p: void* (as hex)
#define SIZEINT 0x00040     // z: (signed) size_t
#define MAXINT 0x00080      // j: intmax_t
#define PTRINT 0x00100      // t: ptrdiff_t
#define NOSKIP 0x00200      // [ or c: do not skip blanks
// Modifiers:
#define SUPPRESS 0x00400  // *: suppress assignment
#define UNSIGNED 0x00800  // %[oupxX] conversions
#define ALLOCATE 0x01000  // m: allocate a char*
// Internal use during integer parsing:
#define SIGNOK 0x02000    // +/- is (still) legal
#define HAVESIGN 0x04000  // Sign detected
#define NDIGITS 0x08000   // No digits detected
#define PFXOK 0x10000     // "0x" prefix is (still) legal
#define PFBOK 0x20000     // "0b" prefix is (still) legal
#define NZDIGITS 0x40000  // No zero digits detected

// Conversion types.
#define CT_CHAR 0    // %c conversion
#define CT_CCL 1     // %[...] conversion
#define CT_STRING 2  // %s conversion
#define CT_INT 3     // Integer: strtoimax/strtoumax
#define CT_FLOAT 4   // Float: strtod

#define to_digit(c) static_cast<int>((c) - '0')
#define is_digit(c) (static_cast<unsigned>(to_digit(c)) <= 9)

// Append a digit to a value and check for overflow.
#define APPEND_DIGIT(val, dig)               \
  do {                                       \
    if ((val) > INT_MAX / 10)                \
      errno = ENOMEM;                        \
    else {                                   \
      (val) *= 10;                           \
      if ((val) > INT_MAX - to_digit((dig))) \
        errno = ENOMEM;                      \
      else                                   \
        (val) += to_digit((dig));            \
    }                                        \
  } while (0)

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
// Trasnlate a fixed size integer argument for the %w/%wf format to a
// flag representation. Supported sizes are 8, 16, 32, and 64 so far.
// See details in bionic/libc/include/stdint.h
static int w_to_flag(int size, bool fast) {
  static constexpr int fast_size = sizeof(void*) == 8 ? LLONG : 0;
  if (size == 8) return SHORTSHORT;
  if (size == 16) return fast ? fast_size : SHORT;
  if (size == 32) return fast ? fast_size : 0;
  if (size == 64) return LLONG;
  __fortify_fatal("%%w%s%d is unsupported", fast ? "f" : "", size);
}

#pragma clang diagnostic pop

"""

```