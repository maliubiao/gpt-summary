Response:
Let's break down the thought process to generate the comprehensive answer about `wchar_h.c`.

**1. Understanding the Core Request:**

The request is to analyze the `wchar_h.c` file, which is a test file for the `wchar.h` header in Android's Bionic libc. The key tasks are:

* List the functions declared in the header.
* Explain the purpose of each function.
* Relate these functions to Android functionality.
* Detail the implementation of some libc functions.
* Discuss dynamic linking aspects.
* Provide example usage errors.
* Explain how Android frameworks reach this code.
* Offer Frida hook examples.

**2. Initial Analysis of the File:**

The provided code snippet is not the *implementation* of `wchar.h` or its functions. It's a *test file*. It checks for the *presence* and *signatures* of the functions and macros defined in `wchar.h`. This is a crucial distinction. Therefore, the focus will be on what the functions *are*, not how they are implemented *in this file*. The actual implementations reside in other Bionic source files.

**3. Categorizing the Functions:**

The functions in `wchar.h` deal with wide characters and multi-byte characters. It's helpful to mentally group them:

* **Input/Output:** `fgetwc`, `fgetws`, `fputwc`, `fputws`, `fwprintf`, `fwscanf`, `getwc`, `getwchar`, `putwc`, `putwchar`, `swprintf`, `swscanf`, `ungetwc`, `vfwprintf`, `vfwscanf`, `vswprintf`, `vswscanf`, `vwprintf`, `vwscanf`, `wprintf`, `wscanf`, `open_wmemstream`.
* **Conversion:** `btowc`, `mbrlen`, `mbrtowc`, `mbsinit`, `mbsnrtowcs`, `mbsrtowcs`, `wcrtomb`, `wcsnrtombs`, `wcsrtombs`, `wctob`.
* **String Manipulation:** `wcpcpy`, `wcpncpy`, `wcscasecmp`, `wcscasecmp_l`, `wcscat`, `wcschr`, `wcscmp`, `wcscoll`, `wcscoll_l`, `wcscpy`, `wcscspn`, `wcsdup`, `wcslen`, `wcsncasecmp`, `wcsncasecmp_l`, `wcsncat`, `wcsncmp`, `wcsncpy`, `wcsnlen`, `wcspbrk`, `wcsrchr`, `wcsspn`, `wcsstr`, `wcstok`, `wmemchr`, `wmemcmp`, `wmemcpy`, `wmemmove`, `wmemset`.
* **Time/Locale:** `wcsftime`, `wcsxfrm`, `wcsxfrm_l`.
* **Numeric Conversion:** `wcstod`, `wcstof`, `wcstol`, `wcstold`, `wcstoll`, `wcstoul`, `wcstoull`.
* **Width Calculation:** `wcswidth`, `wcwidth`.
* **Other:** `fwide`.

**4. Explaining Functionality:**

For each function, a concise explanation of its purpose is needed. Think about what kind of operation it performs on wide character strings or how it handles conversions. Referring to standard C library documentation (like cppreference.com) is helpful here.

**5. Connecting to Android:**

This is where we consider how these functions are used in the Android ecosystem. Examples include:

* **Internationalization (i18n) and Localization (l10n):**  Core usage for displaying text in different languages.
* **File I/O:** Reading and writing files with wide character encodings.
* **UI Rendering:** Handling text input and display in various languages.
* **NDK Development:**  Developers using the NDK can directly use these functions.

**6. Implementation Details (with the caveat of this being a test file):**

Since the provided code is a test, we can't give the exact *source code* implementation. Instead, the explanation should focus on the *general* approach:

* **Low-level system calls:**  Many of these functions will eventually call underlying system calls for I/O or memory manipulation.
* **State management (for conversions):** Functions like `mbrtowc` need to keep track of the conversion state.
* **Locale handling:** Functions with the `_l` suffix rely on locale information.

**7. Dynamic Linking:**

* **SO Layout:** Describe a typical structure of a shared library (`.so`) including code, data, and the Global Offset Table (GOT) and Procedure Linkage Table (PLT).
* **Linking Process:**  Explain how the dynamic linker (`linker64` or `linker`) resolves symbols at runtime using the GOT and PLT. Briefly mention lazy binding.

**8. Common Usage Errors:**

Think about typical mistakes programmers make when using wide character functions:

* **Mismatched encodings:** Trying to interpret a narrow string as a wide string.
* **Buffer overflows:**  Not allocating enough space for wide character strings.
* **Incorrect locale settings:** Leading to unexpected behavior in locale-sensitive functions.
* **Mixing wide and narrow character functions incorrectly.**

**9. Android Framework and NDK Path:**

Trace the execution flow from a high-level Android component down to the libc functions:

* **Framework (Java/Kotlin):**  Android framework components use Java/Kotlin APIs.
* **JNI:**  To call native code, the Java Native Interface (JNI) is used.
* **NDK:**  Native code written using the NDK can directly call libc functions.

**10. Frida Hook Examples:**

Provide practical Frida snippets to intercept calls to some of the `wchar.h` functions. Focus on logging arguments and return values.

**11. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Start with a general overview and then go into more detail for each aspect. Use bullet points and code formatting to improve readability.

**Self-Correction/Refinement During the Process:**

* **Realizing the file's nature:** The initial assumption might be that the file *implements* the functions. Quickly correcting this to understand it's a *test* file is crucial.
* **Focusing on general principles for implementation:**  Since the actual code isn't provided, the explanation of implementation needs to be more abstract.
* **Providing concrete Android examples:**  Instead of just saying "used in Android," give specific scenarios like UI rendering or file handling.
* **Ensuring the Frida examples are practical and understandable.**

By following these steps and continually refining the approach, a comprehensive and accurate answer can be constructed. The key is to understand the context of the provided file (a test file) and then leverage general knowledge of C library functions, Android architecture, and dynamic linking.
好的，让我们来详细分析 `bionic/tests/headers/posix/wchar_h.c` 这个文件。

**文件的功能**

这个 `wchar_h.c` 文件本身并不是实现任何功能的源代码。它的主要功能是作为一个**测试文件**，用于验证 Android Bionic C 库中 `<wchar.h>` 头文件的正确性。 具体来说，它会检查：

1. **头文件是否包含必要的类型定义:**  例如 `FILE*`, `locale_t`, `mbstate_t`, `size_t`, `wchar_t`, `wctype_t`, `wint_t` 等。
2. **头文件是否定义了必要的宏:** 例如 `WCHAR_MAX`, `WCHAR_MIN`, `WEOF`, `NULL`。
3. **头文件是否声明了所有预期的函数:**  并验证这些函数的签名（返回类型和参数类型）是否正确。

简单来说，这个文件像一个清单，检查 `<wchar.h>` 是否按照 POSIX 标准的要求提供了所有必要的定义和声明。

**与 Android 功能的关系及举例说明**

`<wchar.h>` 头文件中定义的函数和类型是用于处理**宽字符**和**多字节字符**的重要工具，这对于支持**国际化（i18n）**和**本地化（l10n）**至关重要。Android 系统需要能够处理各种语言的文本，而这些文本可能包含非 ASCII 字符，需要用宽字符或多字节字符编码来表示。

以下是一些与 Android 功能相关的例子：

* **显示不同语言的文字:** Android UI 框架需要能够渲染各种语言的文字。`<wchar.h>` 中的函数，如 `wcscpy`, `wcslen`, `wprintf` 等，可以用于操作和显示这些文字。例如，在显示用户界面文本时，Android framework 可能会使用这些函数来处理不同语言的字符串。
* **文件 I/O 操作:**  当 Android 应用需要读取或写入包含非 ASCII 字符的文件时，可能需要使用宽字符相关的 I/O 函数，例如 `fgetws`, `fputws`, `fwprintf`。
* **NDK 开发:**  使用 Android NDK 开发原生应用的开发者可以直接使用 `<wchar.h>` 中定义的函数来处理宽字符和多字节字符，以便他们的应用能够支持多种语言。例如，一个游戏引擎用 NDK 开发，需要显示包含中文、日文等字符的文本，就会用到这些函数。

**libc 函数的功能及其实现 (通用解释，因为此文件是测试)**

由于 `wchar_h.c` 只是一个测试文件，它本身不包含任何 libc 函数的实现。  libc 函数的实际实现位于 Bionic 库的其他源文件中。  下面我们来解释一些 `<wchar.h>` 中声明的常见 libc 函数的功能和通用实现思路：

* **字符分类函数 (例如 `iswalpha`, `iswdigit` - 虽然不在本文件中，但与宽字符相关):**
    * **功能:**  判断一个宽字符是否属于特定的字符类别（例如，字母、数字）。
    * **实现:**  通常会使用查找表或者位掩码的方式，根据宽字符的值来判断其类别。会考虑不同的 locale 设置，因为不同语言的字符分类规则可能不同。

* **宽字符串操作函数 (例如 `wcscpy`, `wcslen`, `wcscmp`):**
    * **功能:**  复制、计算长度、比较宽字符串。
    * **实现:**  类似于窄字符的字符串操作函数（如 `strcpy`, `strlen`, `strcmp`），但操作的是 `wchar_t` 类型的字符。`wcscpy` 会逐个复制宽字符直到遇到空宽字符 (`L'\0'`)，`wcslen` 会遍历宽字符串直到遇到空宽字符并返回长度，`wcscmp` 会逐个比较宽字符的数值。

* **宽字符 I/O 函数 (例如 `fgetwc`, `fputwc`, `fwprintf`):**
    * **功能:**  从流中读取/写入单个宽字符或格式化的宽字符串。
    * **实现:**  这些函数通常会调用底层的文件 I/O 系统调用（例如 `read`, `write`），并负责宽字符和多字节字符之间的转换（如果需要）。`fwprintf` 的实现比较复杂，涉及到格式化字符串的解析和参数的处理，然后将宽字符输出到指定的流。

* **多字节字符和宽字符之间的转换函数 (例如 `mbtowc`, `wctomb` - 虽然不在本文件中，但与宽字符相关):**
    * **功能:**  在多字节字符和宽字符之间进行转换。
    * **实现:**  这些函数需要维护转换状态（`mbstate_t`）。转换的实现依赖于当前系统的 locale 设置和字符编码。例如，从 UTF-8 转换为宽字符需要识别 UTF-8 编码的字节序列，并将其转换为对应的 `wchar_t` 值。

**涉及 dynamic linker 的功能 (通用解释)**

`<wchar.h>` 中声明的函数最终都会被编译成机器码，并链接到动态链接库 (通常是 `libc.so`) 中。 当 Android 应用或系统服务调用这些函数时，动态链接器负责在运行时找到这些函数的实现并将其加载到进程的内存空间中。

**SO 布局样本:**

一个典型的 `libc.so` 的布局可能如下：

```
libc.so:
    .text         # 包含函数的可执行代码
        ...
        btowc:    # btowc 函数的机器码
            ...
        fgetwc:   # fgetwc 函数的机器码
            ...
        # 其他 wchar.h 中声明的函数的机器码
        ...
    .rodata       # 只读数据，例如字符串常量
        ...
    .data         # 可读写数据，例如全局变量
        ...
    .bss          # 未初始化的数据段
        ...
    .dynamic      # 动态链接信息
        ...
    .got          # 全局偏移量表 (Global Offset Table)
        ...
    .plt          # 过程链接表 (Procedure Linkage Table)
        ...
```

**链接的处理过程:**

1. **编译时:**  编译器在编译调用 `<wchar.h>` 中函数的代码时，会生成对这些函数的**未定义引用**。这些引用指向 `.plt` (Procedure Linkage Table) 中的条目。
2. **加载时:** 当 Android 系统加载包含这些调用的可执行文件或共享库时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`，取决于架构) 会被激活。
3. **符号解析:** 动态链接器会遍历可执行文件和其依赖的共享库的符号表，尝试找到未定义引用的符号 (例如 `btowc`, `fgetwc`) 的定义。
4. **GOT 和 PLT 的作用:**
   * **PLT (过程链接表):**  PLT 中的每个条目都对应一个外部函数。第一次调用该函数时，PLT 条目会跳转到动态链接器。
   * **GOT (全局偏移量表):** GOT 中保存着外部函数的实际地址。初始时，GOT 条目指向 PLT 中的一段代码。
5. **第一次调用:**  当第一次调用 `btowc` 时，会跳转到 `btowc` 在 PLT 中的条目。这个 PLT 条目会：
   * 将函数的符号信息压入栈。
   * 跳转到动态链接器的一个通用解析例程。
6. **动态链接器解析:** 动态链接器会：
   * 查找 `libc.so` 中 `btowc` 的实际地址。
   * 更新 GOT 中对应 `btowc` 的条目，使其指向 `btowc` 的实际地址。
   * 跳转到 `btowc` 的实际地址执行。
7. **后续调用:**  后续对 `btowc` 的调用会直接跳转到 PLT 条目，而 PLT 条目现在会直接跳转到 GOT 中保存的 `btowc` 的实际地址，避免了重复的符号解析。

这个过程被称为**延迟绑定**或**按需绑定**，可以提高程序的启动速度，因为只有在函数第一次被调用时才进行符号解析。

**逻辑推理、假设输入与输出 (对于测试文件而言)**

对于 `wchar_h.c` 这个测试文件，其逻辑推理很简单：

* **假设输入:**  编译器能够成功找到并解析 `<wchar.h>` 头文件。
* **预期输出:**  测试程序编译通过，并且所有测试断言（例如检查类型定义、宏定义、函数声明）都通过。如果任何断言失败，则说明 `<wchar.h>` 的定义不正确。

例如，测试文件中 `TYPE(wchar_t);` 这行代码会检查 `wchar_t` 是否被定义为一个类型。 如果 `<wchar.h>` 中没有 `typedef` 定义 `wchar_t`，则这个测试会失败。

**用户或编程常见的使用错误**

使用 `<wchar.h>` 中定义的函数时，常见的错误包括：

1. **编码不匹配:**  在多字节字符和宽字符之间转换时，使用了错误的编码方式，导致字符显示乱码或转换失败。例如，假设当前 locale 设置为 UTF-8，但尝试使用 `mbtowc` 解析一个 GBK 编码的字符串。
2. **缓冲区溢出:**  在使用宽字符串操作函数（如 `wcscpy`, `wcsncat`）时，目标缓冲区的大小不足以容纳源字符串，导致内存溢出。
   ```c
   wchar_t dest[5];
   wchar_t src[] = L"This is a long string";
   wcscpy(dest, src); // 潜在的缓冲区溢出
   ```
3. **未初始化 `mbstate_t`:** 在使用需要 `mbstate_t` 参数的转换函数时，没有正确初始化 `mbstate_t` 结构体，可能导致转换状态错误。
   ```c
   mbstate_t ps; // 未初始化
   wchar_t wc;
   mbrtowc(&wc, "a", 1, &ps); // 可能行为不确定
   ```
4. **错误地混合使用窄字符和宽字符函数:**  尝试将窄字符字符串传递给宽字符函数，或者反之。
5. **Locale 设置不正确:**  某些宽字符函数（例如 `wcscoll`, `wcstod`）的行为受当前 locale 设置的影响。如果 locale 设置不正确，可能会导致意外的结果。

**Android framework 或 NDK 如何到达这里**

1. **Android Framework (Java/Kotlin):**
   * Android Framework 本身主要使用 Java 或 Kotlin 编写。
   * 当 Framework 需要处理国际化文本时，它会使用 Java 提供的相关类，例如 `String`, `Character`, `Locale` 等。
   * 在某些底层操作中，Java Framework 可能会通过 **Java Native Interface (JNI)** 调用 Native 代码 (C/C++)。
   * 这些 Native 代码可能会使用 NDK 提供的 C 库函数，其中就包括 `<wchar.h>` 中定义的函数。
   * **例子:**  当 Android framework 需要将用户输入的文本保存到文件系统中，或者在 UI 上渲染不同语言的文本时，底层的 Native 代码可能会使用宽字符函数来处理这些文本。

2. **Android NDK:**
   * 使用 Android NDK 开发的应用可以直接使用 C/C++ 语言编写，并链接到 Bionic C 库。
   * NDK 开发者可以直接 `#include <wchar.h>` 并使用其中定义的函数来处理宽字符和多字节字符。
   * **例子:**  一个使用 NDK 开发的文本编辑器应用，需要读取和编辑各种编码的文本文件，就会直接使用 `<wchar.h>` 中的函数。

**Frida Hook 示例调试步骤**

假设我们想 hook `wcslen` 函数，来观察它的调用情况：

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const wcslenPtr = libc.getExportByName("wcslen");

  if (wcslenPtr) {
    Interceptor.attach(wcslenPtr, {
      onEnter: function (args) {
        const wstr = Memory.readUtf16String(args[0]);
        console.log("[wcslen] Called with wstr:", wstr);
      },
      onLeave: function (retval) {
        console.log("[wcslen] Returned:", retval.toInt());
      }
    });
    console.log("[wcslen] Hooked!");
  } else {
    console.log("[wcslen] Not found!");
  }
} else {
  console.log("This script is for Android.");
}
```

**调试步骤:**

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida server。你的 PC 上也安装了 Frida 客户端。
2. **找到目标进程:** 确定你要调试的 Android 应用或进程的进程 ID (PID) 或包名。
3. **运行 Frida 命令:** 使用 Frida 客户端连接到目标进程并运行 hook 脚本。 例如：
   ```bash
   frida -U -f <package_name> -l hook_wcslen.js --no-pause
   ```
   或者如果知道 PID：
   ```bash
   frida -U <pid> -l hook_wcslen.js
   ```
4. **触发 `wcslen` 调用:**  在目标应用中执行一些操作，这些操作可能会导致调用 `wcslen` 函数。 例如，如果 hook 的是一个文本编辑器应用，你可以打开一个包含宽字符的文本文件。
5. **查看 Frida 输出:**  Frida 会在控制台上打印出 `wcslen` 函数被调用时的参数（宽字符串内容）和返回值（字符串长度）。

**更复杂的 Hook 示例 (例如 hook `fputws`):**

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const fputwsPtr = libc.getExportByName("fputws");

  if (fputwsPtr) {
    Interceptor.attach(fputwsPtr, {
      onEnter: function (args) {
        const wstr = Memory.readUtf16String(args[0]);
        const filePtr = args[1];
        console.log("[fputws] Called with wstr:", wstr, "filePtr:", filePtr);
      },
      onLeave: function (retval) {
        console.log("[fputws] Returned:", retval.toInt());
      }
    });
    console.log("[fputws] Hooked!");
  } else {
    console.log("[fputws] Not found!");
  }
} else {
  console.log("This script is for Android.");
}
```

这个示例 hook 了 `fputws` 函数，可以查看写入到文件流中的宽字符串内容和文件指针。

通过 Frida hook，你可以动态地观察这些函数的调用情况，帮助你理解 Android 系统或应用在处理宽字符时的行为，并进行调试和分析。

### 提示词
```
这是目录为bionic/tests/headers/posix/wchar_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <wchar.h>

#include "header_checks.h"

static void wchar_h() {
  TYPE(FILE*);
  TYPE(locale_t);
  TYPE(mbstate_t);
  TYPE(size_t);
  TYPE(va_list);
  TYPE(wchar_t);
  TYPE(wctype_t);
  TYPE(wint_t);

  MACRO(WCHAR_MAX);
  MACRO(WCHAR_MIN);
  MACRO(WEOF);
  MACRO(NULL);

  FUNCTION(btowc, wint_t (*f)(int));
  FUNCTION(fgetwc, wint_t (*f)(FILE*));
  FUNCTION(fgetws, wchar_t* (*f)(wchar_t*, int, FILE*));
  FUNCTION(fputwc, wint_t (*f)(wchar_t, FILE*));
  FUNCTION(fputws, int (*f)(const wchar_t*, FILE*));
  FUNCTION(fwide, int (*f)(FILE*, int));
  FUNCTION(fwprintf, int (*f)(FILE*, const wchar_t*, ...));
  FUNCTION(fwscanf, int (*f)(FILE*, const wchar_t*, ...));
  FUNCTION(getwc, wint_t (*f)(FILE*));
  FUNCTION(getwchar, wint_t (*f)(void));
  FUNCTION(mbrlen, size_t (*f)(const char*, size_t, mbstate_t*));
  FUNCTION(mbrtowc, size_t (*f)(wchar_t*, const char*, size_t, mbstate_t*));
  FUNCTION(mbsinit, int (*f)(const mbstate_t*));
  FUNCTION(mbsnrtowcs, size_t (*f)(wchar_t*, const char**, size_t, size_t, mbstate_t*));
  FUNCTION(mbsrtowcs, size_t (*f)(wchar_t*, const char**, size_t, mbstate_t*));
  FUNCTION(open_wmemstream, FILE* (*f)(wchar_t**, size_t*));
  FUNCTION(putwc, wint_t (*f)(wchar_t, FILE*));
  FUNCTION(putwchar, wint_t (*f)(wchar_t));
  FUNCTION(swprintf, int (*f)(wchar_t*, size_t, const wchar_t*, ...));
  FUNCTION(swscanf, int (*f)(const wchar_t*, const wchar_t*, ...));
  FUNCTION(ungetwc, wint_t (*f)(wint_t, FILE*));
  FUNCTION(vfwprintf, int (*f)(FILE*, const wchar_t*, va_list));
  FUNCTION(vfwscanf, int (*f)(FILE*, const wchar_t*, va_list));
  FUNCTION(vswprintf, int (*f)(wchar_t*, size_t, const wchar_t*, va_list));
  FUNCTION(vswscanf, int (*f)(const wchar_t*, const wchar_t*, va_list));
  FUNCTION(vwprintf, int (*f)(const wchar_t*, va_list));
  FUNCTION(vwscanf, int (*f)(const wchar_t*, va_list));
  FUNCTION(wcpcpy, wchar_t* (*f)(wchar_t*, const wchar_t*));
  FUNCTION(wcpncpy, wchar_t* (*f)(wchar_t*, const wchar_t*, size_t));
  FUNCTION(wcrtomb, size_t (*f)(char*, wchar_t, mbstate_t*));
  FUNCTION(wcscasecmp, int (*f)(const wchar_t*, const wchar_t*));
  FUNCTION(wcscasecmp_l, int (*f)(const wchar_t*, const wchar_t*, locale_t));
  FUNCTION(wcscat, wchar_t* (*f)(wchar_t*, const wchar_t*));
  FUNCTION(wcschr, wchar_t* (*f)(const wchar_t*, wchar_t));
  FUNCTION(wcscmp, int (*f)(const wchar_t*, const wchar_t*));
  FUNCTION(wcscoll, int (*f)(const wchar_t*, const wchar_t*));
  FUNCTION(wcscoll_l, int (*f)(const wchar_t*, const wchar_t*, locale_t));
  FUNCTION(wcscpy, wchar_t* (*f)(wchar_t*, const wchar_t*));
  FUNCTION(wcscspn, size_t (*f)(const wchar_t*, const wchar_t*));
  FUNCTION(wcsdup, wchar_t* (*f)(const wchar_t*));
  FUNCTION(wcsftime, size_t (*f)(wchar_t*, size_t, const wchar_t*, const struct tm*));
  FUNCTION(wcslen, size_t (*f)(const wchar_t*));
  FUNCTION(wcsncasecmp, int (*f)(const wchar_t*, const wchar_t*, size_t));
  FUNCTION(wcsncasecmp_l, int (*f)(const wchar_t*, const wchar_t*, size_t, locale_t));
  FUNCTION(wcsncat, wchar_t* (*f)(wchar_t*, const wchar_t*, size_t));
  FUNCTION(wcsncmp, int (*f)(const wchar_t*, const wchar_t*, size_t));
  FUNCTION(wcsncpy, wchar_t* (*f)(wchar_t*, const wchar_t*, size_t));
  FUNCTION(wcsnlen, size_t (*f)(const wchar_t*, size_t));
  FUNCTION(wcsnrtombs, size_t (*f)(char*, const wchar_t**, size_t, size_t, mbstate_t*));
  FUNCTION(wcspbrk, wchar_t* (*f)(const wchar_t*, const wchar_t*));
  FUNCTION(wcsrchr, wchar_t* (*f)(const wchar_t*, wchar_t));
  FUNCTION(wcsrtombs, size_t (*f)(char*, const wchar_t**, size_t, mbstate_t*));
  FUNCTION(wcsspn, size_t (*f)(const wchar_t*, const wchar_t*));
  FUNCTION(wcsstr, wchar_t* (*f)(const wchar_t*, const wchar_t*));
  FUNCTION(wcstod, double (*f)(const wchar_t*, wchar_t**));
  FUNCTION(wcstof, float (*f)(const wchar_t*, wchar_t**));
  FUNCTION(wcstok, wchar_t* (*f)(wchar_t*, const wchar_t*, wchar_t**));
  FUNCTION(wcstol, long (*f)(const wchar_t*, wchar_t**, int));
  FUNCTION(wcstold, long double (*f)(const wchar_t*, wchar_t**));
  FUNCTION(wcstoll, long long (*f)(const wchar_t*, wchar_t**, int));
  FUNCTION(wcstoul, unsigned long (*f)(const wchar_t*, wchar_t**, int));
  FUNCTION(wcstoull, unsigned long long (*f)(const wchar_t*, wchar_t**, int));
  FUNCTION(wcswidth, int (*f)(const wchar_t*, size_t));
  FUNCTION(wcsxfrm, size_t (*f)(wchar_t*, const wchar_t*, size_t));
  FUNCTION(wcsxfrm_l, size_t (*f)(wchar_t*, const wchar_t*, size_t, locale_t));
  FUNCTION(wctob, int (*f)(wint_t));
  FUNCTION(wcwidth, int (*f)(wchar_t));
  FUNCTION(wmemchr, wchar_t* (*f)(const wchar_t*, wchar_t, size_t));
  FUNCTION(wmemcmp, int (*f)(const wchar_t*, const wchar_t*, size_t));
  FUNCTION(wmemcpy, wchar_t* (*f)(wchar_t*, const wchar_t*, size_t));
  FUNCTION(wmemmove, wchar_t* (*f)(wchar_t*, const wchar_t*, size_t));
  FUNCTION(wmemset, wchar_t* (*f)(wchar_t*, wchar_t, size_t));
  FUNCTION(wprintf, int (*f)(const wchar_t*, ...));
  FUNCTION(wscanf, int (*f)(const wchar_t*, ...));
}
```