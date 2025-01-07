Response:
Here's a breakdown of the thinking process to generate the comprehensive answer:

1. **Understand the Request:** The request asks for a detailed explanation of the `printf_common.handroid` source code, focusing on its functionality, relation to Android, implementation details, interaction with the dynamic linker, common errors, and debugging techniques. The output needs to be in Chinese.

2. **Initial Code Analysis (Skimming):**  Read through the code to get a high-level understanding. Identify key components like `#include` directives, data structures (like the `union arg`), helper functions, macros, and global definitions. Notice the copyright information indicating its Berkeley origins. Recognize that it's core to the `printf` family of functions.

3. **Identify Core Functionality:** The primary goal of this file is to handle the common logic for the `printf` family of functions. This includes parsing the format string, extracting arguments, converting them to strings, and handling flags and modifiers.

4. **Break Down Key Areas:**  Divide the analysis into logical sections based on the request's requirements:
    * Functionality overview.
    * Android relevance and examples.
    * Detailed explanation of key libc functions.
    * Dynamic linker aspects.
    * Logical reasoning (input/output).
    * Common user errors.
    * Android framework/NDK path to this code.
    * Frida hooking examples.

5. **Address Each Section Systematically:**

    * **Functionality:** Summarize the main tasks: format string parsing, argument extraction, type handling, output formatting, and handling locale.

    * **Android Relevance:** Explain why `printf` is essential for logging, debugging, and general output in Android. Provide examples of `Log.d()` usage in Java and `__android_log_print()` in native code, linking them to the underlying `printf` implementation.

    * **Libc Function Details:**  Focus on the core functions present in the code:
        * `__sbprintf`: Explain its purpose of handling unbuffered output by using a temporary buffer. Emphasize the `noinline` attribute for stack usage optimization.
        * `__find_arguments`: Describe its crucial role in handling positional arguments (`%n$`). Detail the argument type table and the dynamic allocation using `mmap`.
        * `__grow_type_table`: Explain how the argument type table is dynamically resized using `mmap`.
        * `exponent`: Describe its specific purpose in formatting floating-point numbers in scientific notation.
        * Helper functions (within the `helpers` struct):
            * `sprint`: Explain its role in flushing the output buffer.
            * `wcsconv`: Detail the conversion from wide character strings to multibyte strings, handling precision.
            * `xfputwc`: Explain how it writes wide characters, specifically handling string files.
            * `mbsconv`: Describe the conversion from multibyte strings to wide character strings, handling precision.
            * `w_to_flag`: Explain its purpose in translating size specifiers in format strings (`%w`, `%wf`) to internal flags.

    * **Dynamic Linker:**  Explain that `printf_common.handroid` itself doesn't directly interact with the dynamic linker. However, the `libc.so` library, which contains this code, is loaded by the dynamic linker. Provide a simplified `libc.so` layout and illustrate the symbol resolution process when a function like `printf` is called.

    * **Logical Reasoning (Input/Output):** Provide a simple `printf` example and trace the execution flow conceptually, explaining how the format string is parsed and the arguments are used.

    * **Common User Errors:**  List frequent mistakes, like format string mismatches, buffer overflows (implicitly through functions using `printf`), and incorrect use of format specifiers.

    * **Android Framework/NDK Path:**  Illustrate the call chain from high-level Android components (Java `Log` class) down to the native `printf` implementation via JNI and `liblog.so`. Similarly, show the simpler path from NDK code using `__android_log_print`.

    * **Frida Hooking:** Provide practical Frida examples to intercept `printf` and `__android_log_print`. Explain how to modify arguments and return values.

6. **Refine and Organize:**  Review the generated content for clarity, accuracy, and completeness. Ensure the Chinese translation is accurate and natural. Organize the information logically using headings and bullet points for better readability.

7. **Self-Correction/Improvements:** During the process, consider potential omissions or areas needing more detail. For example, initially, the explanation of the dynamic linker might be too brief, so expand it with a concrete example of symbol resolution. Ensure the Frida examples are practical and easily understandable. Double-check the explanations of the helper functions for accuracy.

By following these steps, the comprehensive and well-structured answer can be generated, addressing all aspects of the original request. The iterative nature of this process, including refinement and self-correction, is key to producing a high-quality result.这是一个关于 Android Bionic C 库中 `stdio/printf_common.handroid` 源代码文件的分析。这个文件是 `printf` 系列函数的通用实现部分。

**功能列举:**

这个文件包含了 `printf`、`fprintf`、`sprintf`、`snprintf` 等函数的共享核心逻辑。其主要功能包括：

1. **格式化字符串解析:** 解析 `printf` 函数族接收的格式化字符串 (`fmt`)，识别格式说明符（例如 `%d`, `%s`, `%f` 等）。
2. **参数提取:**  根据格式说明符，从可变参数列表 (`va_list ap`) 中提取相应的参数。
3. **类型处理:**  根据格式说明符，确定参数的类型（例如 `int`, `char*`, `double`），并进行相应的类型转换和处理。
4. **格式化输出:**  根据格式说明符中的标志（flags，如 `#`, `0`, `-`）、宽度和精度等信息，将提取的参数格式化为字符串。
5. **输出到目标:**  将格式化后的字符串输出到指定的目标，例如标准输出、文件或字符串缓冲区。
6. **处理本地化:**  考虑本地化设置，例如数字的分隔符和小数点。
7. **处理宽字符:** 支持宽字符 (`wchar_t`) 和宽字符串 (`wchar_t*`) 的格式化输出。
8. **处理参数位置:** 支持使用 `$n` 来指定参数的位置，允许不按顺序访问参数。

**与 Android 功能的关系及举例:**

`printf` 函数族是 C 语言中最常用的输出函数之一，在 Android 系统中扮演着至关重要的角色：

1. **日志记录:** Android 系统和应用程序广泛使用 `printf` 相关的函数进行日志记录。例如，在 native 代码中，可以使用 `__android_log_print` 函数，它最终会调用到 `printf` 的实现。Java 层的 `Log` 类的方法，例如 `Log.d()`, `Log.e()` 等，底层也会通过 JNI 调用到 native 的日志打印函数，这些函数通常会使用 `printf` 进行格式化。

   **例子 (Android Java):**
   ```java
   import android.util.Log;

   public class MyClass {
       public void myMethod(String name, int age) {
           Log.d("MyTag", String.format("User name: %s, age: %d", name, age));
       }
   }
   ```
   这里的 `String.format` 底层会调用到类似于 `snprintf` 的函数。

   **例子 (Android NDK):**
   ```c
   #include <android/log.h>

   void nativeMethod(const char* name, int age) {
       __android_log_print(ANDROID_LOG_DEBUG, "NativeTag", "User name: %s, age: %d", name, age);
   }
   ```
   这里的 `__android_log_print` 会调用到 Bionic libc 的 `vfprintf` 等函数。

2. **调试信息:** 开发者在调试 Android 应用程序和系统组件时，经常使用 `printf` 输出调试信息。

3. **系统服务:** Android 的一些底层系统服务可能也会使用 `printf` 进行状态输出或错误报告。

**Libc 函数的功能实现详解:**

以下是一些关键 libc 函数的实现解释：

* **`__sbprintf(FILE* fp, const CHAR_TYPE* fmt, va_list ap)`:**
    * **功能:**  这是一个辅助函数，用于处理向无缓冲 UNIX 文件 (`fp`) 进行格式化输出的情况。由于文件是无缓冲的，直接写入可能会导致多次小的 `write` 系统调用，效率较低。
    * **实现:**
        1. 创建一个临时的 `FILE` 结构体 `fake` 和一个缓冲区 `buf`。
        2. 将原始 `fp` 的一些关键属性（如文件描述符、写操作函数等）复制到 `fake` 结构体。
        3. 将 `fake` 结构体的缓冲区设置为临时缓冲区 `buf`。
        4. 调用底层的格式化输出函数 `FUNCTION_NAME` (通常是 `vfprintf`) 对 `fake` 结构体进行操作。
        5. 如果格式化成功，则调用 `__sflush(&fake)` 将临时缓冲区的内容刷新到实际的文件 `fp` 中。
        6. 复制 `fake` 结构体的错误状态到 `fp`。
        * **目的:** 通过使用临时缓冲区，将多次小的输出操作合并成一次大的输出操作，提高效率。`__attribute__((__noinline__))`  阻止编译器内联这个函数，可能是为了避免在 `printf` 家族函数中增加栈的使用，因为这种情况比较少见。

* **`__find_arguments(const CHAR_TYPE* fmt0, va_list ap, union arg** argtable, size_t* argtablesiz)`:**
    * **功能:**  用于查找格式化字符串中的所有参数，特别是当遇到位置参数（如 `%1$d`）时。它会创建一个参数表，存储每个参数的值。
    * **实现:**
        1. 扫描格式化字符串 `fmt0`，查找所有的格式说明符。
        2. 对于每个格式说明符，根据其类型修饰符（如 `l`, `ll`, `h`）确定参数的类型。
        3. 如果遇到位置参数，则记录参数的位置。
        4. 创建一个类型表 `typetable`，存储每个参数的类型信息。如果参数数量超过预设的静态大小 `STATIC_ARG_TBL_SIZE`，则使用 `mmap` 动态分配更大的内存。
        5. 遍历类型表，使用 `va_arg` 从 `ap` 中提取对应类型的参数，并将参数值存储到 `argtable` 中。
        * **目的:**  支持位置参数，允许不按顺序访问参数。动态分配参数表可以处理大量参数的情况。

* **`__grow_type_table(unsigned char** typetable, int* tablesize)`:**
    * **功能:**  当参数类型表 `typetable` 的空间不足时，动态增加其大小。
    * **实现:**
        1. 计算新的表大小 `new_size`，通常是当前大小的两倍，但至少是一个页面的大小。
        2. 如果当前表是静态分配的（大小为 `STATIC_ARG_TBL_SIZE`），则使用 `mmap` 分配新的内存，并将旧表的内容复制到新表。
        3. 如果当前表是动态分配的，则使用 `mmap` 分配新的内存，将旧表内容复制到新表，然后使用 `munmap` 释放旧表的内存。
        4. 使用 `memset` 将新表扩展部分初始化为 `T_UNUSED`。
        * **目的:**  避免在处理大量参数时，由于静态分配的参数表过小而导致错误。

* **`exponent(CharT* p0, int exp, int fmtch)`:**
    * **功能:**  用于格式化浮点数的指数部分（例如 `e+03`）。
    * **实现:**
        1. 将指数指示符 (`fmtch`, 例如 'e' 或 'E') 写入缓冲区 `p0`。
        2. 处理指数的符号，写入 '+' 或 '-'。
        3. 将指数值转换为字符串，并写入缓冲区。对于十进制浮点数的指数，至少需要两位数字。
        * **目的:**  生成符合 `printf` 格式规范的浮点数指数部分。

* **`helpers` 结构体中的函数:**
    * **`sprint(FILE* fp, struct __suio* uio)`:** 将 `uio` 结构体中描述的缓冲区内容刷新到文件 `fp`。`uio` 用于表示多个内存块组成的输出流。
    * **`wcsconv(wchar_t* wcsarg, int prec)`:** 将宽字符串 `wcsarg` 转换为多字节字符串。 `prec` 指定最大输出字节数。
    * **`xfputwc(wchar_t wc, FILE* fp)`:**  类似于 `__fputwc_unlock`，但专门处理文件类型为字符串 (`__SSTR`) 的情况。
    * **`mbsconv(const char* mbsarg, int prec)`:** 将多字节字符串 `mbsarg` 转换为宽字符串。`prec` 指定最大处理字节数。
    * **`w_to_flag(int size, bool fast)`:**  将固定大小的整数参数（用于 `%w` 或 `%wf` 格式）转换为内部标志。支持的大小包括 8, 16, 32, 和 64。

**涉及 dynamic linker 的功能及处理:**

`printf_common.handroid` 本身的代码并不直接与 dynamic linker 交互。但是，这个文件是 `libc.so` 库的一部分，而 `libc.so` 是由 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 加载到进程地址空间的。

**so 布局样本 (简化):**

```
libc.so:
    .text:  // 存放代码段
        printf_common.o 的代码
        vfprintf.o 的代码
        ... 其他 stdio 相关代码 ...
    .data:  // 存放已初始化的全局变量
        ...
    .bss:   // 存放未初始化的全局变量
        ...
    .symtab: // 符号表，记录导出的符号 (函数名、变量名)
        printf
        vfprintf
        __sbprintf
        __find_arguments
        ...
    .dynsym: // 动态符号表，用于动态链接
        printf
        ...
```

**链接的处理过程:**

1. **加载:** 当一个 Android 应用或系统进程需要使用 `printf` 函数时，dynamic linker 会负责加载 `libc.so` 到进程的内存空间。
2. **符号查找:** 当代码中调用 `printf` 时，编译器会生成一个对 `printf` 符号的引用。在链接时，dynamic linker 会在 `libc.so` 的 `.dynsym` (或 `.symtab`) 中查找 `printf` 符号的地址。
3. **重定位:**  找到 `printf` 的地址后，dynamic linker 会更新调用点的指令，将对 `printf` 符号的引用替换为其实际的内存地址。
4. **执行:** 当程序执行到 `printf` 调用点时，会跳转到 `libc.so` 中 `printf` 函数的实现代码执行。

**假设输入与输出 (逻辑推理):**

假设有以下 C 代码：

```c
#include <stdio.h>

int main() {
    const char* name = "Android";
    int version = 13;
    printf("The operating system is %s, version %d\n", name, version);
    return 0;
}
```

**输入:**

* 格式化字符串: `"The operating system is %s, version %d\n"`
* 参数 1 (`%s`): 指向字符串 "Android" 的指针
* 参数 2 (`%d`): 整数值 `13`

**输出:**

标准输出将会打印：

```
The operating system is Android, version 13
```

**处理过程:**

1. `printf` 函数被调用，接收格式化字符串和参数。
2. `printf` 内部会调用 `vfprintf` 或类似的函数。
3. `vfprintf` 会解析格式化字符串，遇到 `%s`，提取第一个参数（指向 "Android" 的指针），并将字符串 "Android" 插入到输出缓冲区。
4. 遇到 `%d`，提取第二个参数（整数 `13`），将其转换为字符串 "13"，并插入到输出缓冲区。
5. 遇到 `\n`，插入换行符。
6. 最终，缓冲区的内容被写入到标准输出。

**用户或编程常见的使用错误举例:**

1. **格式说明符与参数类型不匹配:**
   ```c
   int num = 10;
   printf("The number is %s\n", num); // 错误：期望字符串，但提供了整数
   ```
   这会导致未定义的行为，可能打印出乱码或崩溃。

2. **格式化字符串中的参数数量与实际提供的参数数量不符:**
   ```c
   printf("Name: %s, Age: %d\n", "Alice"); // 错误：缺少 age 参数
   ```
   这也会导致未定义的行为，可能读取到栈上的其他数据。

3. **缓冲区溢出 (对于 `sprintf` 和 `snprintf`):**
   ```c
   char buffer[10];
   sprintf(buffer, "This is a long string"); // 错误：字符串长度超过缓冲区大小
   ```
   `sprintf` 不进行边界检查，可能导致缓冲区溢出，覆盖其他内存区域。应该使用 `snprintf` 并指定缓冲区大小。

4. **忘记为字符串参数提供有效的指针:**
   ```c
   char *str;
   printf("The string is %s\n", str); // 错误：str 未初始化或指向无效内存
   ```
   这会导致程序崩溃。

5. **使用了不安全的格式说明符 (`%n`):**
   ```c
   int count;
   printf("Hello%n\n", &count);
   ```
   `%n` 会将到目前为止输出的字符数写入到 `count` 指向的地址。这可能被恶意利用进行内存写入，因此在 Android 中是被禁止的。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例:**

**Android Framework 到 `printf` 的路径 (简化):**

1. **Java 代码:**  Android Framework 中的 Java 代码，例如 `android.util.Log` 类的方法 (`Log.d`, `Log.e` 等) 被调用。
2. **JNI 调用:** `Log` 类的方法会通过 Java Native Interface (JNI) 调用到 native 代码，通常是 `liblog.so` 库中的函数，例如 `__android_log_print`.
3. **`liblog.so`:** `__android_log_print` 函数接收 tag 和格式化字符串以及参数。
4. **Bionic libc:** `__android_log_print` 内部会调用 Bionic libc 中的 `vfprintf` 或类似的函数，最终会使用到 `printf_common.handroid` 中的逻辑。

**NDK 到 `printf` 的路径:**

1. **C/C++ 代码:** NDK 开发的 native 代码直接调用 `printf` 或其他 `printf` 家族的函数。
2. **Bionic libc:** 这些调用会直接链接到 Bionic libc 中对应的函数实现。

**Frida Hook 示例:**

以下是一些使用 Frida hook `printf` 和 `__android_log_print` 的示例：

**Hook `printf`:**

```javascript
// attach 到目标进程
function hook_printf() {
    const printfPtr = Module.findExportByName("libc.so", "printf");
    if (printfPtr) {
        Interceptor.attach(printfPtr, {
            onEnter: function (args) {
                const format = Memory.readUtf8String(args[0]);
                console.log("[printf] format:", format);
                // 打印参数
                for (let i = 1; i < args.length; i++) {
                    console.log("[printf] arg" + i + ":", args[i]);
                }
            },
            onLeave: function (retval) {
                console.log("[printf] return value:", retval);
            }
        });
    } else {
        console.log("[-] printf not found");
    }
}

setImmediate(hook_printf);
```

**Hook `__android_log_print`:**

```javascript
function hook_android_log_print() {
    const androidLogPrintPtr = Module.findExportByName("liblog.so", "__android_log_print");
    if (androidLogPrintPtr) {
        Interceptor.attach(androidLogPrintPtr, {
            onEnter: function (args) {
                const priority = args[0].toInt32();
                const tag = Memory.readUtf8String(args[1]);
                const format = Memory.readUtf8String(args[2]);
                console.log("[__android_log_print] priority:", priority, "tag:", tag, "format:", format);
                // 打印参数
                for (let i = 3; i < args.length; i++) {
                    console.log("[__android_log_print] arg" + (i - 2) + ":", args[i]);
                }
            },
            onLeave: function (retval) {
                console.log("[__android_log_print] return value:", retval);
            }
        });
    } else {
        console.log("[-] __android_log_print not found");
    }
}

setImmediate(hook_android_log_print);
```

这些 Frida 脚本可以帮助你监控应用程序或系统进程中 `printf` 和 `__android_log_print` 的调用，观察其参数和返回值，从而进行调试和分析。

总而言之，`bionic/libc/stdio/printf_common.handroid` 是 Android Bionic C 库中 `printf` 函数族的核心实现，负责处理格式化字符串的解析、参数提取、类型处理和输出格式化等关键任务，在 Android 系统中被广泛用于日志记录、调试输出等方面。了解其实现细节有助于理解 Android 系统的底层工作原理。

Prompt: 
```
这是目录为bionic/libc/stdio/printf_common.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
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

#include <sys/mman.h>
#include <sys/types.h>

#include <errno.h>
#include <float.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include <platform/bionic/macros.h>

#include "fvwrite.h"
#include "gdtoa.h"
#include "local.h"

union arg {
  int intarg;
  unsigned int uintarg;
  long longarg;
  unsigned long ulongarg;
  long long longlongarg;
  unsigned long long ulonglongarg;
  ptrdiff_t ptrdiffarg;
  size_t sizearg;
  ssize_t ssizearg;
  intmax_t intmaxarg;
  uintmax_t uintmaxarg;
  void* pvoidarg;
  char* pchararg;
  signed char* pschararg;
  short* pshortarg;
  int* pintarg;
  long* plongarg;
  long long* plonglongarg;
  ptrdiff_t* pptrdiffarg;
  ssize_t* pssizearg;
  intmax_t* pintmaxarg;
  double doublearg;
  long double longdoublearg;
  wint_t wintarg;
  wchar_t* pwchararg;
};

// Helper function for `fprintf to unbuffered unix file': creates a
// temporary buffer.  We only work on write-only files; this avoids
// worries about ungetc buffers and so forth.
//
// We prevent inlining because this massively increases the printf()
// family's stack usage to support a rare case.
__attribute__((__noinline__))
static int __sbprintf(FILE* fp, const CHAR_TYPE* fmt, va_list ap) {
  FILE fake;
  struct __sfileext fakeext;
  unsigned char buf[BUFSIZ];

  _FILEEXT_SETUP(&fake, &fakeext);
  /* copy the important variables */
  fake._flags = fp->_flags & ~__SNBF;
  fake._file = fp->_file;
  fake._cookie = fp->_cookie;
  fake._write = fp->_write;

  /* set up the buffer */
  fake._bf._base = fake._p = buf;
  fake._bf._size = fake._w = sizeof(buf);
  fake._lbfsize = 0; /* not actually used, but Just In Case */

  /* do the work, then copy any error status */
  int ret = FUNCTION_NAME(&fake, fmt, ap);
  if (ret >= 0 && __sflush(&fake)) ret = EOF;
  if (fake._flags & __SERR) fp->_flags |= __SERR;
  return ret;
}

static int __find_arguments(const CHAR_TYPE* fmt0, va_list ap, union arg** argtable, size_t* argtablesiz);
static int __grow_type_table(unsigned char** typetable, int* tablesize);

#define DEFPREC 6

#define to_digit(c) ((c) - '0')
#define is_digit(c) ((unsigned)to_digit(c) <= 9)
#define to_char(n) ((CHAR_TYPE)((n) + '0'))

template <typename CharT>
static int exponent(CharT* p0, int exp, int fmtch) {
  CharT* p = p0;
  *p++ = fmtch;
  if (exp < 0) {
    exp = -exp;
    *p++ = '-';
  } else {
    *p++ = '+';
  }

  CharT expbuf[MAXEXPDIG];
  CharT* t = expbuf + MAXEXPDIG;
  if (exp > 9) {
    do {
      *--t = to_char(exp % 10);
    } while ((exp /= 10) > 9);
    *--t = to_char(exp);
    for (; t < expbuf + MAXEXPDIG; *p++ = *t++) /* nothing */;
  } else {
    /*
     * Exponents for decimal floating point conversions
     * (%[eEgG]) must be at least two characters long,
     * whereas exponents for hexadecimal conversions can
     * be only one character long.
     */
    if (fmtch == 'e' || fmtch == 'E') *p++ = '0';
    *p++ = to_char(exp);
  }
  return (p - p0);
}

#define PAD(howmany, with)     \
  do {                         \
    if ((n = (howmany)) > 0) { \
      while (n > PADSIZE) {    \
        PRINT(with, PADSIZE);  \
        n -= PADSIZE;          \
      }                        \
      PRINT(with, n);          \
    }                          \
  } while (0)

#define PRINTANDPAD(p, ep, len, with)       \
  do {                                      \
    n2 = (ep) - (p);                        \
    if (n2 > (len)) n2 = (len);             \
    if (n2 > 0) PRINT((p), n2);             \
    PAD((len) - (n2 > 0 ? n2 : 0), (with)); \
  } while (0)

/*
 * The size of the buffer we use as scratch space for integer
 * conversions, among other things.  Technically, we would need the
 * most space for base 10 conversions with thousands' grouping
 * characters between each pair of digits.  100 bytes is a
 * conservative overestimate even for a 128-bit uintmax_t.
 */
#define BUF 100

#define STATIC_ARG_TBL_SIZE 8 /* Size of static argument table. */

/*
 * Flags used during conversion.
 */
#define ALT 0x0001      /* alternate form */
#define LADJUST 0x0004  /* left adjustment */
#define LONGDBL 0x0008  /* long double */
#define LONGINT 0x0010  /* long integer */
#define LLONGINT 0x0020 /* long long integer */
#define SHORTINT 0x0040 /* short integer */
#define ZEROPAD 0x0080  /* zero (as opposed to blank) pad */
#define FPT 0x0100      /* Floating point number */
#define PTRINT 0x0200   /* (unsigned) ptrdiff_t */
#define SIZEINT 0x0400  /* (signed) size_t */
#define CHARINT 0x0800  /* 8 bit integer */
#define MAXINT 0x1000   /* largest integer size (intmax_t) */

/*
 * Type ids for argument type table.
 */
#define T_UNUSED 0
#define T_SHORT 1
#define T_U_SHORT 2
#define TP_SHORT 3
#define T_INT 4
#define T_U_INT 5
#define TP_INT 6
#define T_LONG 7
#define T_U_LONG 8
#define TP_LONG 9
#define T_LLONG 10
#define T_U_LLONG 11
#define TP_LLONG 12
#define T_DOUBLE 13
#define T_LONG_DOUBLE 14
#define TP_CHAR 15
#define TP_VOID 16
#define T_PTRINT 17
#define TP_PTRINT 18
#define T_SIZEINT 19
#define T_SSIZEINT 20
#define TP_SSIZEINT 21
#define T_MAXINT 22
#define T_MAXUINT 23
#define TP_MAXINT 24
#define T_CHAR 25
#define T_U_CHAR 26
#define T_WINT 27
#define TP_WCHAR 28

// To extend shorts properly, we need both signed and unsigned
// argument extraction methods.
#define SARG()                                                                               \
  ((intmax_t)(flags & MAXINT                                                                 \
                  ? GETARG(intmax_t)                                                         \
                  : flags & LLONGINT                                                         \
                        ? GETARG(long long)                                                  \
                        : flags & LONGINT                                                    \
                              ? GETARG(long)                                                 \
                              : flags & PTRINT                                               \
                                    ? GETARG(ptrdiff_t)                                      \
                                    : flags & SIZEINT                                        \
                                          ? GETARG(ssize_t)                                  \
                                          : flags & SHORTINT                                 \
                                                ? (short)GETARG(int)                         \
                                                : flags & CHARINT ? (signed char)GETARG(int) \
                                                                  : GETARG(int)))
#define UARG()                                                                                \
  ((uintmax_t)(flags & MAXINT                                                                 \
                   ? GETARG(uintmax_t)                                                        \
                   : flags & LLONGINT                                                         \
                         ? GETARG(unsigned long long)                                         \
                         : flags & LONGINT                                                    \
                               ? GETARG(unsigned long)                                        \
                               : flags & PTRINT ? (uintptr_t)GETARG(ptrdiff_t) : /* XXX */    \
                                     flags & SIZEINT                                          \
                                         ? GETARG(size_t)                                     \
                                         : flags & SHORTINT                                   \
                                               ? (unsigned short)GETARG(int)                  \
                                               : flags & CHARINT ? (unsigned char)GETARG(int) \
                                                                 : GETARG(unsigned int)))

// Append a digit to a value and check for overflow.
#define APPEND_DIGIT(val, dig)                            \
  do {                                                    \
    if ((val) > INT_MAX / 10) goto overflow;              \
    (val) *= 10;                                          \
    if ((val) > INT_MAX - to_digit((dig))) goto overflow; \
    (val) += to_digit((dig));                             \
  } while (0)

// Get * arguments, including the form *nn$.  Preserve the nextarg
// that the argument can be gotten once the type is determined.
#define GETASTER(val)                                                     \
  n2 = 0;                                                                 \
  cp = fmt;                                                               \
  while (is_digit(*cp)) {                                                 \
    APPEND_DIGIT(n2, *cp);                                                \
    cp++;                                                                 \
  }                                                                       \
  if (*cp == '$') {                                                       \
    int hold = nextarg;                                                   \
    if (argtable == NULL) {                                               \
      argtable = statargtable;                                            \
      if (__find_arguments(fmt0, orgap, &argtable, &argtablesiz) == -1) { \
        ret = -1;                                                         \
        goto error;                                                       \
      }                                                                   \
    }                                                                     \
    nextarg = n2;                                                         \
    val = GETARG(int);                                                    \
    nextarg = hold;                                                       \
    fmt = ++cp;                                                           \
  } else {                                                                \
    val = GETARG(int);                                                    \
  }

// Get the argument indexed by nextarg.   If the argument table is
// built, use it to get the argument.  If its not, get the next
// argument (and arguments must be gotten sequentially).
#define GETARG(type) \
  ((argtable != NULL) ? *((type*)(&argtable[nextarg++])) : (nextarg++, va_arg(ap, type)))

/*
 * Find all arguments when a positional parameter is encountered.  Returns a
 * table, indexed by argument number, of pointers to each arguments.  The
 * initial argument table should be an array of STATIC_ARG_TBL_SIZE entries.
 * It will be replaced with a mmap-ed one if it overflows (malloc cannot be
 * used since we are attempting to make snprintf thread safe, and alloca is
 * problematic since we have nested functions..)
 */
static int __find_arguments(const CHAR_TYPE* fmt0, va_list ap, union arg** argtable,
                            size_t* argtablesiz) {
  int ch;                   /* character from fmt */
  int n, n2;                /* handy integer (short term usage) */
  int flags;                /* flags as above */
  unsigned char* typetable; /* table of types */
  unsigned char stattypetable[STATIC_ARG_TBL_SIZE];
  int tablesize; /* current size of type table */
  int tablemax;  /* largest used index in table */
  int nextarg;   /* 1-based argument index */
  int ret = 0;   /* return value */

  /*
   * Add an argument type to the table, expanding if necessary.
   */
#define ADDTYPE(type)                                                      \
  ((nextarg >= tablesize) ? __grow_type_table(&typetable, &tablesize) : 0, \
   (nextarg > tablemax) ? tablemax = nextarg : 0, typetable[nextarg++] = type)

#define ADDSARG()                                                                             \
  ((flags & MAXINT)                                                                           \
       ? ADDTYPE(T_MAXINT)                                                                    \
       : ((flags & PTRINT) ? ADDTYPE(T_PTRINT)                                                \
                           : ((flags & SIZEINT)                                               \
                                  ? ADDTYPE(T_SSIZEINT)                                       \
                                  : ((flags & LLONGINT)                                       \
                                         ? ADDTYPE(T_LLONG)                                   \
                                         : ((flags & LONGINT)                                 \
                                                ? ADDTYPE(T_LONG)                             \
                                                : ((flags & SHORTINT)                         \
                                                       ? ADDTYPE(T_SHORT)                     \
                                                       : ((flags & CHARINT) ? ADDTYPE(T_CHAR) \
                                                                            : ADDTYPE(T_INT))))))))

#define ADDUARG()                                                                  \
  ((flags & MAXINT)                                                                \
       ? ADDTYPE(T_MAXUINT)                                                        \
       : ((flags & PTRINT)                                                         \
              ? ADDTYPE(T_PTRINT)                                                  \
              : ((flags & SIZEINT)                                                 \
                     ? ADDTYPE(T_SIZEINT)                                          \
                     : ((flags & LLONGINT)                                         \
                            ? ADDTYPE(T_U_LLONG)                                   \
                            : ((flags & LONGINT)                                   \
                                   ? ADDTYPE(T_U_LONG)                             \
                                   : ((flags & SHORTINT)                           \
                                          ? ADDTYPE(T_U_SHORT)                     \
                                          : ((flags & CHARINT) ? ADDTYPE(T_U_CHAR) \
                                                               : ADDTYPE(T_U_INT))))))))

  /*
   * Add * arguments to the type array.
   */
#define ADDASTER()         \
  n2 = 0;                  \
  cp = fmt;                \
  while (is_digit(*cp)) {  \
    APPEND_DIGIT(n2, *cp); \
    cp++;                  \
  }                        \
  if (*cp == '$') {        \
    int hold = nextarg;    \
    nextarg = n2;          \
    ADDTYPE(T_INT);        \
    nextarg = hold;        \
    fmt = ++cp;            \
  } else {                 \
    ADDTYPE(T_INT);        \
  }
  CHAR_TYPE* fmt = const_cast<CHAR_TYPE*>(fmt0);
  CHAR_TYPE* cp;
  typetable = stattypetable;
  tablesize = STATIC_ARG_TBL_SIZE;
  tablemax = 0;
  nextarg = 1;
  memset(typetable, T_UNUSED, STATIC_ARG_TBL_SIZE);

  /*
   * Scan the format for conversions (`%' character).
   */
  for (;;) {
    for (cp = fmt; (ch = *fmt) != '\0' && ch != '%'; fmt++) continue;
    if (ch == '\0') goto done;
    fmt++; /* skip over '%' */

    flags = 0;

  rflag:
    ch = *fmt++;
  reswitch:
    switch (ch) {
      case ' ':
      case '#':
      case '\'':
        goto rflag;
      case '*':
        ADDASTER();
        goto rflag;
      case '-':
      case '+':
        goto rflag;
      case '.':
        if ((ch = *fmt++) == '*') {
          ADDASTER();
          goto rflag;
        }
        while (is_digit(ch)) {
          ch = *fmt++;
        }
        goto reswitch;
      case '0':
        goto rflag;
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        n = 0;
        do {
          APPEND_DIGIT(n, ch);
          ch = *fmt++;
        } while (is_digit(ch));
        if (ch == '$') {
          nextarg = n;
          goto rflag;
        }
        goto reswitch;
      case 'L':
        flags |= LONGDBL;
        goto rflag;
      case 'h':
        if (*fmt == 'h') {
          fmt++;
          flags |= CHARINT;
        } else {
          flags |= SHORTINT;
        }
        goto rflag;
      case 'j':
        flags |= MAXINT;
        goto rflag;
      case 'l':
        if (*fmt == 'l') {
          fmt++;
          flags |= LLONGINT;
        } else {
          flags |= LONGINT;
        }
        goto rflag;
      case 'q':
        flags |= LLONGINT;
        goto rflag;
      case 't':
        flags |= PTRINT;
        goto rflag;
      case 'z':
        flags |= SIZEINT;
        goto rflag;
      case 'C':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'c':
        if (flags & LONGINT)
          ADDTYPE(T_WINT);
        else
          ADDTYPE(T_INT);
        break;
      case 'D':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'd':
      case 'i':
        ADDSARG();
        break;
      case 'a':
      case 'A':
      case 'e':
      case 'E':
      case 'f':
      case 'F':
      case 'g':
      case 'G':
        if (flags & LONGDBL)
          ADDTYPE(T_LONG_DOUBLE);
        else
          ADDTYPE(T_DOUBLE);
        break;
      case 'n':
        __fortify_fatal("%%n not allowed on Android");
      case 'O':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'o':
        ADDUARG();
        break;
      case 'p':
        ADDTYPE(TP_VOID);
        break;
      case 'S':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 's':
        ADDTYPE((flags & LONGINT) ? TP_WCHAR : TP_CHAR);
        break;
      case 'U':
        flags |= LONGINT;
        __BIONIC_FALLTHROUGH;
      case 'u':
      case 'X':
      case 'x':
      case 'B':
      case 'b':
        ADDUARG();
        break;
      case 'w': {
        n = 0;
        bool fast = false;
        ch = *fmt++;
        if (ch == 'f') {
          fast = true;
          ch = *fmt++;
        }
        while (is_digit(ch)) {
          APPEND_DIGIT(n, ch);
          ch = *fmt++;
        }
        if (n == 64) {
          flags |= LLONGINT;
        } else {
          if (n != 8 && fast) {
#if defined(__LP64__)
            flags |= LLONGINT;
#endif
          }
        }
        goto reswitch;
      }
      default: /* "%?" prints ?, unless ? is NUL */
        if (ch == '\0') goto done;
        break;
    }
  }
done:
  /*
   * Build the argument table.
   */
  if (tablemax >= STATIC_ARG_TBL_SIZE) {
    *argtablesiz = sizeof(union arg) * (tablemax + 1);
    *argtable = static_cast<arg*>(mmap(nullptr, *argtablesiz,
                                       PROT_WRITE | PROT_READ,
                                       MAP_ANON | MAP_PRIVATE, -1, 0));
    if (*argtable == MAP_FAILED) return -1;
  }

  for (n = 1; n <= tablemax; n++) {
    switch (typetable[n]) {
      case T_UNUSED:
      case T_CHAR:
      case T_U_CHAR:
      case T_SHORT:
      case T_U_SHORT:
      case T_INT:
        (*argtable)[n].intarg = va_arg(ap, int);
        break;
      case TP_SHORT:
        (*argtable)[n].pshortarg = va_arg(ap, short*);
        break;
      case T_U_INT:
        (*argtable)[n].uintarg = va_arg(ap, unsigned int);
        break;
      case TP_INT:
        (*argtable)[n].pintarg = va_arg(ap, int*);
        break;
      case T_LONG:
        (*argtable)[n].longarg = va_arg(ap, long);
        break;
      case T_U_LONG:
        (*argtable)[n].ulongarg = va_arg(ap, unsigned long);
        break;
      case TP_LONG:
        (*argtable)[n].plongarg = va_arg(ap, long*);
        break;
      case T_LLONG:
        (*argtable)[n].longlongarg = va_arg(ap, long long);
        break;
      case T_U_LLONG:
        (*argtable)[n].ulonglongarg = va_arg(ap, unsigned long long);
        break;
      case TP_LLONG:
        (*argtable)[n].plonglongarg = va_arg(ap, long long*);
        break;
      case T_DOUBLE:
        (*argtable)[n].doublearg = va_arg(ap, double);
        break;
      case T_LONG_DOUBLE:
        (*argtable)[n].longdoublearg = va_arg(ap, long double);
        break;
      case TP_CHAR:
        (*argtable)[n].pchararg = va_arg(ap, char*);
        break;
      case TP_VOID:
        (*argtable)[n].pvoidarg = va_arg(ap, void*);
        break;
      case T_PTRINT:
        (*argtable)[n].ptrdiffarg = va_arg(ap, ptrdiff_t);
        break;
      case TP_PTRINT:
        (*argtable)[n].pptrdiffarg = va_arg(ap, ptrdiff_t*);
        break;
      case T_SIZEINT:
        (*argtable)[n].sizearg = va_arg(ap, size_t);
        break;
      case T_SSIZEINT:
        (*argtable)[n].ssizearg = va_arg(ap, ssize_t);
        break;
      case TP_SSIZEINT:
        (*argtable)[n].pssizearg = va_arg(ap, ssize_t*);
        break;
      case T_MAXINT:
        (*argtable)[n].intmaxarg = va_arg(ap, intmax_t);
        break;
      case T_MAXUINT:
        (*argtable)[n].uintmaxarg = va_arg(ap, uintmax_t);
        break;
      case TP_MAXINT:
        (*argtable)[n].pintmaxarg = va_arg(ap, intmax_t*);
        break;
      case T_WINT:
        (*argtable)[n].wintarg = va_arg(ap, wint_t);
        break;
      case TP_WCHAR:
        (*argtable)[n].pwchararg = va_arg(ap, wchar_t*);
        break;
    }
  }
  goto finish;

overflow:
  errno = ENOMEM;
  ret = -1;

finish:
  if (typetable != nullptr && typetable != stattypetable) {
    munmap(typetable, *argtablesiz);
    typetable = nullptr;
  }
  return (ret);
}

/*
 * Increase the size of the type table.
 */
static int __grow_type_table(unsigned char** typetable, int* tablesize) {
  unsigned char* old_table = *typetable;
  int new_size = *tablesize * 2;

  if (new_size < getpagesize()) new_size = getpagesize();

  if (*tablesize == STATIC_ARG_TBL_SIZE) {
    *typetable = static_cast<unsigned char*>(mmap(nullptr, new_size,
                                                  PROT_WRITE | PROT_READ,
                                                  MAP_ANON | MAP_PRIVATE, -1, 0));
    if (*typetable == MAP_FAILED) return -1;
    bcopy(old_table, *typetable, *tablesize);
  } else {
    unsigned char* new_table = static_cast<unsigned char*>(mmap(nullptr, new_size,
                                                                PROT_WRITE | PROT_READ,
                                                                MAP_ANON | MAP_PRIVATE, -1, 0));
    if (new_table == MAP_FAILED) return -1;
    memmove(new_table, *typetable, *tablesize);
    munmap(*typetable, *tablesize);
    *typetable = new_table;
  }
  memset(*typetable + *tablesize, T_UNUSED, (new_size - *tablesize));

  *tablesize = new_size;
  return 0;
}

struct helpers {
  // Flush out all the vectors defined by the given uio,
  // then reset it so that it can be reused.
  static int sprint(FILE* fp, struct __suio* uio) {
    if (uio->uio_resid == 0) {
      uio->uio_iovcnt = 0;
      return 0;
    }
    int result = __sfvwrite(fp, uio);
    uio->uio_resid = 0;
    uio->uio_iovcnt = 0;
    return result;
  }

  // Convert a wide character string argument for the %ls format to a multibyte
  // string representation. If not -1, prec specifies the maximum number of
  // bytes to output, and also means that we can't assume that the wide char
  // string is null-terminated.
  static char* wcsconv(wchar_t* wcsarg, int prec) {
    mbstate_t mbs;
    char buf[MB_LEN_MAX];
    wchar_t* p;
    char* convbuf;
    size_t clen, nbytes;

    // Allocate space for the maximum number of bytes we could output.
    if (prec < 0) {
      memset(&mbs, 0, sizeof(mbs));
      p = wcsarg;
      nbytes = wcsrtombs(nullptr, (const wchar_t**)&p, 0, &mbs);
      if (nbytes == (size_t)-1) return nullptr;
    } else {
      // Optimisation: if the output precision is small enough,
      // just allocate enough memory for the maximum instead of
      // scanning the string.
      if (prec < 128) {
        nbytes = prec;
      } else {
        nbytes = 0;
        p = wcsarg;
        memset(&mbs, 0, sizeof(mbs));
        for (;;) {
          clen = wcrtomb(buf, *p++, &mbs);
          if (clen == 0 || clen == (size_t)-1 || nbytes + clen > (size_t)prec) break;
          nbytes += clen;
        }
        if (clen == (size_t)-1) return nullptr;
      }
    }
    if ((convbuf = static_cast<char*>(malloc(nbytes + 1))) == nullptr) return nullptr;

    // Fill the output buffer.
    p = wcsarg;
    memset(&mbs, 0, sizeof(mbs));
    if ((nbytes = wcsrtombs(convbuf, (const wchar_t**)&p, nbytes, &mbs)) == (size_t)-1) {
      free(convbuf);
      return nullptr;
    }
    convbuf[nbytes] = '\0';
    return convbuf;
  }

  // Like __fputwc_unlock, but handles fake string (__SSTR) files properly.
  // File must already be locked.
  static wint_t xfputwc(wchar_t wc, FILE* fp) {
    if ((fp->_flags & __SSTR) == 0) return __fputwc_unlock(wc, fp);

    char buf[MB_LEN_MAX];
    mbstate_t mbs = {};
    size_t len = wcrtomb(buf, wc, &mbs);
    if (len == (size_t)-1) {
      fp->_flags |= __SERR;
      errno = EILSEQ;
      return WEOF;
    }

    struct __siov iov;
    iov.iov_base = buf;
    iov.iov_len = len;
    struct __suio uio;
    uio.uio_iov = &iov;
    uio.uio_resid = len;
    uio.uio_iovcnt = 1;
    return (__sfvwrite(fp, &uio) != EOF ? (wint_t)wc : WEOF);
  }

  // Convert a multibyte character string argument for the %s format to a wide
  // string representation. ``prec'' specifies the maximum number of bytes
  // to output. If ``prec'' is greater than or equal to zero, we can't assume
  // that the multibyte character string ends in a null character.
  //
  // Returns NULL on failure.
  // To find out what happened check errno for ENOMEM, EILSEQ and EINVAL.
  static wchar_t* mbsconv(const char* mbsarg, int prec) {
    mbstate_t mbs;
    const char* p;
    size_t insize, nchars, nconv;

    if (mbsarg == nullptr) return nullptr;

    // Supplied argument is a multibyte string; convert it to wide characters first.
    if (prec >= 0) {
      // String is not guaranteed to be NUL-terminated. Find the number of characters to print.
      p = mbsarg;
      insize = nchars = nconv = 0;
      bzero(&mbs, sizeof(mbs));
      while (nchars != (size_t)prec) {
        nconv = mbrlen(p, MB_CUR_MAX, &mbs);
        if (nconv == (size_t)0 || nconv == (size_t)-1 || nconv == (size_t)-2) break;
        p += nconv;
        nchars++;
        insize += nconv;
      }
      if (nconv == (size_t)-1 || nconv == (size_t)-2) return (nullptr);
    } else {
      insize = strlen(mbsarg);
    }

    // Allocate buffer for the result and perform the conversion,
    // converting at most `size' bytes of the input multibyte string to
    // wide characters for printing.
    wchar_t* convbuf = static_cast<wchar_t*>(calloc(insize + 1, sizeof(*convbuf)));
    if (convbuf == nullptr) return nullptr;
    wchar_t* wcp = convbuf;
    p = mbsarg;
    bzero(&mbs, sizeof(mbs));
    nconv = 0;
    while (insize != 0) {
      nconv = mbrtowc(wcp, p, insize, &mbs);
      if (nconv == 0 || nconv == (size_t)-1 || nconv == (size_t)-2) break;
      wcp++;
      p += nconv;
      insize -= nconv;
    }
    if (nconv == (size_t)-1 || nconv == (size_t)-2) {
      free(convbuf);
      return nullptr;
    }
    *wcp = '\0';

    return convbuf;
  }

  // Trasnlate a fixed size integer argument for the %w/%wf format to a
  // flag representation. Supported sizes are 8, 16, 32, and 64 so far.
  // See details in bionic/libc/include/stdint.h
  static int w_to_flag(int size, bool fast) {
    static constexpr int fast_size = sizeof(void*) == 8 ? LLONGINT : 0;
    if (size == 8) return CHARINT;
    if (size == 16) return fast ? fast_size : SHORTINT;
    if (size == 32) return fast ? fast_size : 0;
    if (size == 64) return LLONGINT;
    __fortify_fatal("%%w%s%d is unsupported", fast ? "f" : "", size);
  }
};

"""

```