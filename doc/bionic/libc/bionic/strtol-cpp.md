Response:
Let's break down the thought process for answering the request about `bionic/libc/bionic/strtol.cpp`.

**1. Understanding the Core Request:**

The main goal is to analyze the `strtol.cpp` file and explain its functionality, its relation to Android, implementation details, interactions with the dynamic linker (if any), potential errors, and how Android frameworks use it. The request specifically asks for details about each libc function.

**2. Initial High-Level Analysis of the Code:**

* **Template Function:** The code heavily relies on a template function `StrToI`. This suggests a common underlying logic for converting strings to different integer types.
* **Multiple Functions:**  Several functions are defined: `atoi`, `atol`, `atoll`, `strtoimax`, `wcstoimax`, `strtol`, `wcstol`, `strtoll`, `wcstoll`, `strtoul`, `wcstoul`, `strtoull`, `wcstoull`, `strtoumax`, and `wcstoumax`. This confirms the file's primary purpose: string-to-integer conversion for various integer sizes and signedness.
* **Input Validation:**  The `StrToI` function checks for a valid base (2-36 or 0).
* **Whitespace and Sign Handling:** The code skips leading whitespace and handles optional '+' or '-' signs.
* **Base Detection:**  It recognizes prefixes like "0x" for hexadecimal and "0b" for binary. If no prefix, base 0 defaults to 8 (octal if leading '0') or 10 (decimal).
* **Overflow Detection:**  The code uses `__builtin_mul_overflow` and `__builtin_sub_overflow`/`__builtin_add_overflow` to detect potential overflows during the conversion.
* **Error Handling:**  `errno` is set to `EINVAL` for invalid bases and `ERANGE` for overflows. The `end_ptr` is used to indicate where the parsing stopped.
* **`__strong_alias`:** This indicates that certain functions (like `strtol_l`) are aliases for other functions (like `strtol`). This is an optimization or a way to provide locale-aware versions without duplicating code (though the implementation here doesn't show locale handling directly within this file).
* **Wide Character Support:** The presence of `wchar_t` versions (e.g., `wcstol`) suggests support for internationalization.

**3. Detailed Function Analysis (Iterating Through Each Function):**

For each function, the analysis should cover:

* **Purpose:** What does this function do (e.g., convert a string to a long integer)?
* **Parameters:** What input does it take (string, end pointer, base)?
* **Return Value:** What does it return (the converted integer, or potentially error values)?
* **How it's Implemented (referencing `StrToI`):** Explain how it leverages the template function, specifying the template arguments (type, min, max).

**4. Addressing Android-Specific Context:**

* **Bionic as Android's libc:**  Emphasize that this is part of the core C library for Android, making these functions fundamental.
* **Examples of Use in Android:** Think about common scenarios:
    * Parsing command-line arguments.
    * Reading configuration files.
    * Handling user input.
    * Converting data from network or file formats.

**5. Dynamic Linker Aspects:**

* **Absence of Direct Dynamic Linker Code:**  A crucial observation is that `strtol.cpp` itself *doesn't directly interact* with the dynamic linker. It's a utility function within libc.
* **How libc is Linked:** Explain that `strtol` (and other libc functions) are part of `libc.so`, which is a shared library. Applications and other shared libraries link against `libc.so`.
* **SO Layout (Conceptual):** Provide a simplified view of how `libc.so` would be structured in memory, including the `.text` (code) and `.data` (data) sections.
* **Linking Process:** Describe the basic steps: the linker resolves symbols like `strtol` to their addresses within `libc.so` during application loading.

**6. Common Usage Errors:**

Think about the typical mistakes programmers make when using these functions:

* **Not Checking `end_ptr`:**  Failing to verify if the entire string was converted.
* **Ignoring `errno`:**  Not checking for overflow or invalid input.
* **Incorrect Base:**  Providing a base outside the valid range.
* **Assuming Success:**  Not handling potential errors.

**7. Tracing from Android Framework/NDK:**

* **Framework:** Start with a high-level Android framework component (e.g., an Activity). Show how it might indirectly use `strtol` through Java Native Interface (JNI) calls to native code.
* **NDK:**  Demonstrate a more direct path through NDK, where C/C++ code directly calls `strtol`.
* **Frida Hooking:** Provide concrete Frida code examples to intercept calls to `strtol` and related functions, showing how to inspect arguments and return values.

**8. Logical Reasoning and Examples:**

For each function, provide simple input and expected output examples to illustrate its behavior, especially for edge cases like:

* Leading/trailing whitespace.
* Positive/negative signs.
* Different bases (binary, octal, decimal, hexadecimal).
* Overflow/underflow scenarios.

**9. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use bullet points and code blocks to improve readability. Start with a summary and then delve into the details. Ensure the language is clear and concise.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe `strtol` directly calls dynamic linker functions."  **Correction:** Realize that `strtol` is a fundamental libc function and doesn't usually involve the dynamic linker in its core logic. Its interaction is at the library linking level.
* **Considering locale:**  The `__strong_alias` suggests locale awareness. While the provided code doesn't *show* locale handling, it's important to mention this potential aspect and acknowledge that locale-specific versions might exist elsewhere in bionic.
* **Frida Examples:** Make sure the Frida code is practical and demonstrates how to intercept the relevant functions and access their parameters.

By following this structured thought process, including considering potential pitfalls and refining initial assumptions, a comprehensive and accurate answer to the request can be constructed.
好的，我们来详细分析一下 `bionic/libc/bionic/strtol.cpp` 这个文件。

**功能概述**

`strtol.cpp` 文件在 Android Bionic 库中实现了将字符串转换为整数的各种函数。这些函数主要用于将以字符串形式表示的数字转换为不同大小和类型的整数值。它提供了处理不同进制（如十进制、十六进制、八进制、二进制）数字字符串的能力，并能检测溢出等错误情况。

该文件定义了以下主要函数：

* **`atoi`**: 将字符串转换为 `int` 类型的整数。
* **`atol`**: 将字符串转换为 `long` 类型的整数。
* **`atoll`**: 将字符串转换为 `long long` 类型的整数。
* **`strtoimax`**: 将字符串转换为 `intmax_t` 类型的整数。
* **`wcstoimax`**: 将宽字符串转换为 `intmax_t` 类型的整数。
* **`strtol`**: 将字符串转换为 `long` 类型的整数，并可以指定进制。
* **`wcstol`**: 将宽字符串转换为 `long` 类型的整数，并可以指定进制。
* **`strtoll`**: 将字符串转换为 `long long` 类型的整数，并可以指定进制。
* **`wcstoll`**: 将宽字符串转换为 `long long` 类型的整数，并可以指定进制。
* **`strtoul`**: 将字符串转换为 `unsigned long` 类型的整数，并可以指定进制。
* **`wcstoul`**: 将宽字符串转换为 `unsigned long` 类型的整数，并可以指定进制。
* **`strtoull`**: 将字符串转换为 `unsigned long long` 类型的整数，并可以指定进制。
* **`wcstoull`**: 将宽字符串转换为 `unsigned long long` 类型的整数，并可以指定进制。
* **`strtoumax`**: 将字符串转换为 `uintmax_t` 类型的整数。
* **`wcstoumax`**: 将宽字符串转换为 `uintmax_t` 类型的整数。

所有这些函数的核心实现都依赖于一个模板函数 `StrToI`。

**与 Android 功能的关系及举例说明**

这些字符串转换函数在 Android 系统中被广泛使用，因为很多数据和配置信息是以字符串的形式存在的。以下是一些例子：

1. **解析命令行参数：** 当 Android 应用（特别是 Native 应用）启动时，可能会接收到命令行参数，这些参数通常是字符串。`strtol` 等函数用于将这些字符串参数转换为整数进行处理。例如，一个应用可能接收一个端口号作为参数，需要用 `atoi` 或 `strtol` 将其转换为整数。

   ```c++
   // 假设在 Native 代码的 main 函数中接收到端口号参数
   int main(int argc, char* argv[]) {
       if (argc > 1) {
           int port = atoi(argv[1]);
           // 使用 port 进行后续操作
       }
       return 0;
   }
   ```

2. **读取配置文件：** Android 应用或系统服务经常需要读取配置文件（例如，文本格式的配置文件）。配置文件中的数值通常以字符串形式存储，需要使用这些转换函数将其转换为相应的整数类型。例如，读取一个包含超时时间的配置文件。

   ```c++
   // 假设从配置文件中读取到 "timeout=1000"
   std::string line = "timeout=1000";
   size_t pos = line.find("=");
   if (pos != std::string::npos) {
       std::string valueStr = line.substr(pos + 1);
       long timeout = strtol(valueStr.c_str(), nullptr, 10); // 转换为十进制 long
       // 使用 timeout
   }
   ```

3. **处理用户输入：** 虽然 Android 应用的用户界面通常使用更高层的 API 进行交互，但在某些底层场景或 Native 开发中，可能需要处理字符串形式的用户输入，并将其转换为整数。

4. **网络编程：** 在进行网络编程时，端口号、IP 地址等信息有时以字符串形式传输，需要转换为整数进行处理。

**libc 函数的实现细节**

所有提供的函数最终都调用了模板函数 `StrToI`。我们详细解释一下 `StrToI` 的实现逻辑：

```c++
template <typename T, T Min, T Max, typename CharT>
__attribute__((always_inline)) T StrToI(const CharT* s, CharT** end_ptr, int base) {
  // 1. 基础校验：检查 base 的有效性 (0 或 2-36)
  if (base < 0 || base == 1 || base > 36) {
    if (end_ptr != nullptr) *end_ptr = const_cast<CharT*>(s);
    errno = EINVAL; // 设置错误码为无效参数
    return 0;
  }

  // 2. 跳过空白字符，识别正负号
  const CharT* p = s;
  int c;
  while (isspace(c = *p++)) {} // 跳过空格、制表符等
  bool neg = false;
  if (c == '-') {
    neg = true;
    c = *p++;
  } else if (c == '+') {
    c = *p++;
  }

  // 3. 处理进制前缀 (0x, 0X, 0b, 0B)
  if ((base == 0 || base == 16) && c == '0' && (*p == 'x' || *p == 'X') && isxdigit(p[1])) {
    c = p[1];
    p += 2;
    base = 16;
  }
  if ((base == 0 || base == 2) && c == '0' && (*p == 'b' || *p == 'B') && isdigit(p[1])) {
    c = p[1];
    p += 2;
    base = 2;
  }
  if (base == 0) base = (c == '0') ? 8 : 10; // base 为 0 时，根据前导 0 确定为八进制，否则为十进制

  // 4. 转换核心逻辑
  constexpr bool is_signed = (Min != 0); // 判断类型是否为有符号
  T acc = 0; // 累加器
  int any = 0; // 标记是否解析到任何数字，负数表示溢出
  for (;; c = *p++) {
    if (isdigit(c)) {
      c -= '0';
    } else if (isalpha(c)) {
      c = 10 + (_tolower(c) - 'a'); // 将字母转换为 10-35 的值
    } else {
      break; // 遇到非数字/字母字符，停止解析
    }
    if (c >= base) break; // 当前字符的值大于等于进制，无效

    if (any < 0) continue; // 如果已经溢出，继续读取但不进行计算

    if (is_signed) {
      // 有符号数，在负数范围内计算，避免正数溢出检查的边界问题
      if (__builtin_mul_overflow(acc, base, &acc) || __builtin_sub_overflow(acc, c, &acc)) {
        any = -1; // 标记溢出
        continue;
      }
    } else {
      // 无符号数
      if (__builtin_mul_overflow(acc, base, &acc) || __builtin_add_overflow(acc, c, &acc)) {
        any = -1; // 标记溢出
        continue;
      }
    }
    any = 1; // 标记已解析到数字
  }

  // 5. 设置 end_ptr
  if (end_ptr != nullptr) *end_ptr = const_cast<CharT*>(any ? p - 1 : s);
    // 如果解析到数字，end_ptr 指向最后一个有效字符的下一个位置；否则指向原始字符串的起始位置

  // 6. 处理溢出
  if (any == -1) {
    errno = ERANGE; // 设置错误码为结果超出范围
    return (is_signed && neg) ? Min : Max; // 返回最小值或最大值
  }

  // 7. 处理有符号数的特殊溢出情况
  if (any > 0 && is_signed && !neg && acc == Min) {
    errno = ERANGE;
    return Max;
  }

  // 8. 返回结果
  if (is_signed) return neg ? acc : -acc;
  return neg ? -acc : acc; // 无符号数无需取反，但为了统一，这里也做了判断
}
```

**涉及 dynamic linker 的功能**

`strtol.cpp` 本身的代码并没有直接涉及 dynamic linker 的功能。这些函数是标准 C 库的一部分，会被编译成 `libc.so` 这个共享库。Dynamic linker 的作用是在程序启动时加载 `libc.so`，并将程序中对 `strtol` 等函数的调用链接到 `libc.so` 中对应的实现。

**SO 布局样本**

假设 `libc.so` 的内存布局（简化）：

```
地址范围        | 内容
----------------|------------------------------------
...             | ...
0xb7000000 - 0xb700ffff | .text (代码段) - 包含 strtol 等函数的机器码
...             | ...
0xb7010000 - 0xb7010fff | .rodata (只读数据段) - 可能包含字符串常量等
...             | ...
0xb7020000 - 0xb702ffff | .data (数据段) - 包含全局变量等
...             | ...
```

**链接的处理过程**

1. **编译时：** 当一个程序（例如，一个 Android 应用的 Native 组件）调用了 `strtol` 函数时，编译器会在目标文件中生成一个对 `strtol` 符号的未定义引用。

2. **链接时：** 链接器（在 Android 上通常是 `lld`）在链接这个程序时，会查找所需的共享库。如果程序链接了 `libc.so`，链接器会在 `libc.so` 的符号表中查找 `strtol` 的定义。

3. **运行时：** 当 Android 系统加载这个程序时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
   * 加载程序本身到内存。
   * 加载程序依赖的共享库，包括 `libc.so`。
   * **重定位：** dynamic linker 会解析程序中对共享库函数的未定义引用，并将这些引用指向 `libc.so` 中 `strtol` 函数的实际内存地址（例如，位于 `.text` 段内的某个地址）。

**逻辑推理、假设输入与输出**

以下是一些 `strtol` 函数的示例输入和输出：

* **假设输入:** `s = "  -123  abc"`, `base = 10`
   * **输出:** `-123`, `*end_ptr` 指向 `" abc"` 的起始位置。

* **假设输入:** `s = "0xFF"`, `base = 0`
   * **输出:** `255` (因为前缀 "0x" 自动识别为十六进制), `*end_ptr` 指向字符串末尾。

* **假设输入:** `s = "101010"`, `base = 2`
   * **输出:** `42`, `*end_ptr` 指向字符串末尾。

* **假设输入:** `s = "9999999999999999999"`, `base = 10` (假设超出 `long` 的范围)
   * **输出:** `LONG_MAX` 或 `LONG_MIN` (取决于正负号), `errno` 被设置为 `ERANGE`。

* **假设输入:** `s = "invalid"`, `base = 10`
   * **输出:** `0`, `*end_ptr` 指向原始字符串的起始位置。

* **假设输入:** `s = "10"`, `base = 8`
   * **输出:** `8`, `*end_ptr` 指向字符串末尾。

**用户或编程常见的使用错误**

1. **不检查 `end_ptr`：** 用户可能会忽略 `end_ptr`，导致没有完全转换的字符串被错误地接受。例如：

   ```c++
   const char* str = "123abc";
   long value = strtol(str, nullptr, 10); // endptr 为 nullptr
   // value 为 123，但 "abc" 没有被处理，如果期望整个字符串都是数字则会出错。

   char* endptr;
   long value2 = strtol(str, &endptr, 10);
   if (*endptr != '\0') {
       // 错误：字符串包含非数字字符
   }
   ```

2. **不检查 `errno`：**  忽略 `errno` 的值可能导致未检测到溢出错误。

   ```c++
   const char* large_number = "9999999999999999999";
   errno = 0;
   long value = strtol(large_number, nullptr, 10);
   if (errno == ERANGE) {
       // 处理溢出错误
   }
   ```

3. **错误的 `base` 值：**  提供超出范围的 `base` 值（例如，小于 0 或大于 36），会导致未定义的行为或错误的结果。

4. **假设输入总是有效的：** 没有对输入字符串进行预先验证，直接进行转换，可能导致程序崩溃或产生意外结果。

**Android framework 或 NDK 如何到达这里**

1. **Android Framework (Java 层):**
   * Java 代码中，需要将字符串转换为整数时，可能会调用 Java 的 `Integer.parseInt()`, `Long.parseLong()` 等方法。
   * 这些 Java 方法的底层实现最终会通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 中的本地代码。
   * ART 的本地代码中，可能会调用 Bionic 库提供的 `strtol` 或类似的函数。

   **示例 Frida Hook (Hook Java 层):**

   ```python
   import frida, sys

   package_name = "your.target.app" # 替换为你的应用包名

   def on_message(message, data):
       if message['type'] == 'send':
           print("[*] {0}".format(message['payload']))
       else:
           print(message)

   try:
       session = frida.get_usb_device().attach(package_name)
   except Exception as e:
       print(f"[-] Error attaching to the application: {e}")
       sys.exit(1)

   script_code = """
   Java.perform(function () {
       var Integer = Java.use("java.lang.Integer");
       Integer.parseInt.overload('java.lang.String').implementation = function (s) {
           console.log("Hooked Integer.parseInt, input: " + s);
           var result = this.parseInt(s);
           console.log("Integer.parseInt result: " + result);
           return result;
       };

       var Long = Java.use("java.lang.Long");
       Long.parseLong.overload('java.lang.String').implementation = function (s) {
           console.log("Hooked Long.parseLong, input: " + s);
           var result = this.parseLong(s);
           console.log("Long.parseLong result: " + result);
           return result;
       };
   });
   """

   script = session.create_script(script_code)
   script.on('message', on_message)
   script.load()
   sys.stdin.read()
   ```

2. **NDK (Native 开发):**
   * 在使用 NDK 进行 Android Native 开发时，C/C++ 代码可以直接调用 Bionic 库提供的 `strtol` 等函数。

   **示例 Frida Hook (Hook Native 层):**

   首先，你需要找到 `libc.so` 在目标进程中的加载地址。可以使用 `Process.getModuleByName("libc.so").base`。

   ```python
   import frida, sys

   package_name = "your.target.app" # 替换为你的应用包名

   def on_message(message, data):
       if message['type'] == 'send':
           print("[*] {0}".format(message['payload']))
       else:
           print(message)

   try:
       session = frida.get_usb_device().attach(package_name)
   except Exception as e:
       print(f"[-] Error attaching to the application: {e}")
       sys.exit(1)

   script_code = """
   Interceptor.attach(Module.findExportByName("libc.so", "strtol"), {
       onEnter: function(args) {
           console.log("Hooked strtol");
           console.log("  string: " + Memory.readUtf8String(args[0]));
           console.log("  endptr address: " + args[1]);
           console.log("  base: " + args[2].toInt32());
       },
       onLeave: function(retval) {
           console.log("strtol returned: " + retval);
           if (this.context.r1) { // 假设在 ARM64 上，r1 寄存器可能存储了 endptr 指向的值
               console.log("  *endptr: " + Memory.readUtf8String(ptr(this.context.r1)));
           }
       }
   });

   Interceptor.attach(Module.findExportByName("libc.so", "atoi"), {
       onEnter: function(args) {
           console.log("Hooked atoi");
           console.log("  string: " + Memory.readUtf8String(args[0]));
       },
       onLeave: function(retval) {
           console.log("atoi returned: " + retval);
       }
   });
   """

   script = session.create_script(script_code)
   script.on('message', on_message)
   script.load()
   sys.stdin.read()
   ```

**步骤总结 (Framework 到 `strtol`)**

1. **Java 代码调用 `Integer.parseInt()` 或 `Long.parseLong()`。**
2. **这些方法内部通过 JNI 调用到 ART 的本地代码。**
3. **ART 的本地代码可能会调用 Bionic 库中的 `strtol` 等函数来完成实际的字符串到整数的转换。**

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/strtol.cpp` 文件的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/strtol.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (c) 1992 The Regents of the University of California.
 * All rights reserved.
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
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <wchar.h>

template <typename T, T Min, T Max, typename CharT>
__attribute__((always_inline)) T StrToI(const CharT* s, CharT** end_ptr, int base) {
  // Ensure that base is between 2 and 36 inclusive, or the special value of 0.
  if (base < 0 || base == 1 || base > 36) {
    if (end_ptr != nullptr) *end_ptr = const_cast<CharT*>(s);
    errno = EINVAL;
    return 0;
  }

  // Skip white space and pick up leading +/- sign if any.
  const CharT* p = s;
  int c;
  while (isspace(c = *p++)) {
  }
  bool neg = false;
  if (c == '-') {
    neg = true;
    c = *p++;
  } else if (c == '+') {
    c = *p++;
  }

  // If base is 0 or 16, allow "0x" prefix for hex.
  if ((base == 0 || base == 16) && c == '0' && (*p == 'x' || *p == 'X') && isxdigit(p[1])) {
    c = p[1];
    p += 2;
    base = 16;
  }
  // If base is 0 or 2, allow "0b" prefix for binary.
  if ((base == 0 || base == 2) && c == '0' && (*p == 'b' || *p == 'B') && isdigit(p[1])) {
    c = p[1];
    p += 2;
    base = 2;
  }
  // If base is 0, allow "0" prefix for octal, otherwise base is 10.
  if (base == 0) base = (c == '0') ? 8 : 10;

  constexpr bool is_signed = (Min != 0);
  T acc = 0;
  // Non-zero if any digits consumed; negative to indicate overflow/underflow.
  int any = 0;
  for (;; c = *p++) {
    if (isdigit(c)) {
      c -= '0';
    } else if (isalpha(c)) {
      c = 10 + (_tolower(c) - 'a');
    } else {
      break;
    }
    if (c >= base) break;
    if (any < 0) continue;
    if (is_signed) {
      // We work in the negative space because the most negative value has a
      // larger magnitude than the most positive value.
      if (__builtin_mul_overflow(acc, base, &acc) || __builtin_sub_overflow(acc, c, &acc)) {
        any = -1;
        continue;
      }
    } else {
      if (__builtin_mul_overflow(acc, base, &acc) || __builtin_add_overflow(acc, c, &acc)) {
        any = -1;
        continue;
      }
    }
    any = 1;
  }

  if (end_ptr != nullptr) *end_ptr = const_cast<CharT*>(any ? p - 1 : s);

  // Detected overflow/underflow in the loop?
  if (any == -1) {
    errno = ERANGE;
    return (is_signed && neg) ? Min : Max;
  }

  // Will we overflow by trying to negate the most negative value?
  if (any > 0 && is_signed && !neg && acc == Min) {
    errno = ERANGE;
    return Max;
  }

  if (is_signed) return neg ? acc : -acc;
  return neg ? -acc : acc;
}

int atoi(const char* s) {
  return strtol(s, nullptr, 10);
}

long atol(const char* s) {
  return strtol(s, nullptr, 10);
}

long long atoll(const char* s) {
  return strtoll(s, nullptr, 10);
}

intmax_t strtoimax(const char* s, char** end, int base) {
  return StrToI<intmax_t, INTMAX_MIN, INTMAX_MAX, char>(s, end, base);
}

intmax_t wcstoimax(const wchar_t* s, wchar_t** end, int base) {
  return StrToI<intmax_t, INTMAX_MIN, INTMAX_MAX, wchar_t>(s, end, base);
}

long strtol(const char* s, char** end, int base) {
  return StrToI<long, LONG_MIN, LONG_MAX, char>(s, end, base);
}
__strong_alias(strtol_l, strtol);

long wcstol(const wchar_t* s, wchar_t** end, int base) {
  return StrToI<long, LONG_MIN, LONG_MAX, wchar_t>(s, end, base);
}
__strong_alias(wcstol_l, wcstol);

long long strtoll(const char* s, char** end, int base) {
  return StrToI<long long, LLONG_MIN, LLONG_MAX, char>(s, end, base);
}
__strong_alias(strtoll_l, strtoll);

long long wcstoll(const wchar_t* s, wchar_t** end, int base) {
  return StrToI<long long, LLONG_MIN, LLONG_MAX, wchar_t>(s, end, base);
}
__strong_alias(wcstoll_l, wcstoll);

unsigned long strtoul(const char* s, char** end, int base) {
  return StrToI<unsigned long, 0, ULONG_MAX, char>(s, end, base);
}
__strong_alias(strtoul_l, strtoul);

unsigned long wcstoul(const wchar_t* s, wchar_t** end, int base) {
  return StrToI<unsigned long, 0, ULONG_MAX, wchar_t>(s, end, base);
}
__strong_alias(wcstoul_l, wcstoul);

unsigned long long strtoull(const char* s, char** end, int base) {
  return StrToI<unsigned long long, 0, ULLONG_MAX, char>(s, end, base);
}
__strong_alias(strtoull_l, strtoull);

unsigned long long wcstoull(const wchar_t* s, wchar_t** end, int base) {
  return StrToI<unsigned long long, 0, ULLONG_MAX, wchar_t>(s, end, base);
}
__strong_alias(wcstoull_l, wcstoull);

uintmax_t strtoumax(const char* s, char** end, int base) {
  return StrToI<uintmax_t, 0, UINTMAX_MAX, char>(s, end, base);
}

uintmax_t wcstoumax(const wchar_t* s, wchar_t** end, int base) {
  return StrToI<uintmax_t, 0, UINTMAX_MAX, wchar_t>(s, end, base);
}

"""

```