Response:
Let's break down the thought process for answering the user's request about `bionic/libc/include/ctype.h`.

**1. Understanding the Request:**

The user provided the source code for `ctype.h` and asked for a comprehensive explanation covering various aspects:

* **Functionality:** What does this file *do*?
* **Android Relevance:** How does it relate to Android? Examples?
* **Implementation Details:** How are the functions implemented?
* **Dynamic Linker:**  Are there any dynamic linking aspects? If so, examples and process.
* **Logic/Assumptions:**  If there's any implicit logic, illustrate with input/output.
* **Common Errors:**  What mistakes do programmers make when using these functions?
* **Android Integration:** How does the Android framework/NDK use this? Tracing/debugging.

**2. Initial Analysis of the Code:**

* **Header File (`.h`):**  This immediately tells me it's a declaration file, primarily defining function signatures and constants. The actual implementations are likely in a `.c` file.
* **Copyright:**  Indicates it's part of the Android Open Source Project (AOSP).
* **`#pragma once`:** Prevents multiple inclusions of the header.
* **`#include <sys/cdefs.h>` and `#include <xlocale.h>`:**  These indicate dependencies on other system-level headers. `sys/cdefs.h` likely handles compiler-specific definitions, and `xlocale.h` suggests locale support (though the functions in *this* file largely ignore it).
* **`__BIONIC_CTYPE_INLINE`:** This macro is crucial. It defaults to `static __inline`, meaning these functions are intended to be inlined for performance. The comment explains this rationale.
* **`_CTYPE_*` Macros:** These are internal bitmask definitions related to character types. The comment "Internal implementation detail. Do not use." is a strong hint to ignore them for general usage.
* **Function Declarations:**  The core of the file. Functions like `isalpha`, `isdigit`, `tolower`, etc., are standard C library functions for character classification and conversion. The `_` prefixed versions (`_tolower`, `_toupper`) are internal helpers.
* **`__bionic_ctype_in_range`:** Another internal helper for range checking.
* **Locale Variants (`*_l`):**  Functions like `isalnum_l` exist but explicitly ignore the `locale_t` argument. This is a key point regarding Android's (at least this part of) locale handling.
* **`__BEGIN_DECLS` and `__END_DECLS`:**  These are common macros for managing C++ name mangling when including C headers in C++ code.

**3. Addressing Each Point in the Request:**

* **Functionality:**  The core purpose is ASCII character classification and case conversion. List the common functions.
* **Android Relevance:**
    * **Foundation:** Emphasize its role as a fundamental part of `libc` and thus used by *everything*.
    * **NDK:**  Developers directly use these functions in native code.
    * **Framework:**  The Android framework (written in Java/Kotlin) often interacts with native code that uses these functions.
    * **Examples:**  Provide concrete scenarios like input validation, text processing, etc.

* **Implementation Details:**  Focus on the key idea of inlining for performance. Explain the basic logic of each function. For example, `isalpha` uses `_tolower` and range checking. Mention the bitwise operations in `_tolower` and `_toupper`.

* **Dynamic Linker:** This is where careful thought is needed. The *header file itself* doesn't directly involve the dynamic linker. However, the *implementation* of these functions resides in `libc.so`, which *is* linked dynamically.
    * **SO Layout:** Provide a simplified representation of `libc.so` with code and data sections.
    * **Linking Process:** Explain how the compiler and linker resolve function calls to `libc.so`. Mention the role of the dynamic linker (`linker64` or `linker`) at runtime. Explain the concept of shared libraries.

* **Logic/Assumptions:** The internal range-checking function `__bionic_ctype_in_range` embodies a clear logic. Illustrate with a simple input/output example.

* **Common Errors:**  Brainstorm typical mistakes developers make, like assuming locale support where it's not fully present (for these specific functions), and potential issues with signed/unsigned chars.

* **Android Integration/Frida:**
    * **Path Tracing:**  Start from a user action (e.g., typing in a text field), go through the Java framework, JNI calls, and finally reaching `libc`. This requires some knowledge of the Android architecture.
    * **Frida Hook:** Provide a practical Frida script demonstrating how to intercept and observe calls to `isalpha`. Explain how to attach to a process, find the function, and log arguments and return values.

**4. Structuring the Answer:**

Organize the information logically, following the user's request structure as a guideline. Use clear headings and bullet points for readability. Use code blocks for the Frida example and SO layout.

**5. Language and Tone:**

Use clear, concise, and technically accurate language. Explain concepts simply without oversimplification. Maintain a helpful and informative tone. Since the request is in Chinese, provide the answer in Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe delve into the `_ctype_` array. **Correction:** The comments strongly advise against it and it's an internal detail. Focus on the exposed functions.
* **Initial thought:**  Overcomplicate the dynamic linker explanation. **Correction:** Keep it high-level and focused on how `libc.so` is used, avoiding excessive detail on symbol resolution.
* **Initial thought:**  Assume full locale support. **Correction:** Emphasize that the `*_l` functions in *this* file are stubs and don't actually use the locale.
* **Initial thought:**  Provide overly complex Frida code. **Correction:** Keep the Frida example simple and focused on the core task of hooking and logging.

By following this structured thought process, including analysis, addressing each point, and self-correction, a comprehensive and accurate answer can be generated.
好的，让我们详细分析一下 `bionic/libc/include/ctype.h` 这个文件。

**功能列举**

这个头文件定义了一系列用于对 ASCII 字符进行分类和转换的宏和内联函数。主要功能包括：

* **字符分类:**  判断一个字符是否属于特定的类别，例如字母、数字、空白字符、标点符号、控制字符等。
* **字符大小写转换:** 将字符转换为大写或小写。
* **ASCII 相关:**  判断字符是否是 ASCII 字符，以及将字符转换为 ASCII 码。

**与 Android 功能的关系及举例说明**

`ctype.h` 中定义的函数是 C 标准库的一部分，对于任何使用 C 或 C++ 编写的 Android 代码来说都是基础且必不可少的。它们在以下 Android 功能中扮演着重要的角色：

* **输入验证:** 在各种场景下，例如用户输入、网络数据处理等，都需要验证输入的字符是否符合预期。例如，验证用户名是否只包含字母和数字，验证输入的数字是否在特定范围内。
* **文本处理:**  许多文本处理操作，例如字符串的规范化、搜索、替换等，都依赖于字符分类和转换功能。例如，将所有输入文本转换为小写进行不区分大小写的比较。
* **文件和数据解析:**  解析文本文件或数据流时，需要识别和处理不同类型的字符，例如分隔符、数字、字母等。
* **网络协议处理:**  在处理网络协议时，需要解析和生成符合协议规范的文本数据，其中涉及到字符分类和转换。

**举例说明:**

* **输入法 (IME):** 当用户在输入法中输入字符时，输入法程序可能会使用 `isalpha` 或 `isdigit` 来判断输入的字符是否为字母或数字，从而进行候选词的匹配和预测。
* **命令行工具 (Shell):** Android 的 shell 环境中的各种命令，例如 `grep` (用于搜索文本)，可能会使用 `isspace` 来识别命令参数之间的空格。
* **应用开发:**  开发者可以使用 `isdigit` 来验证用户在表单中输入的电话号码是否只包含数字。可以使用 `tolower` 或 `toupper` 来进行不区分大小写的字符串比较，例如比较用户输入的用户名和已存在的用户名。

**libc 函数的功能实现**

由于这个头文件中的函数都被定义为 `__BIONIC_CTYPE_INLINE` (默认情况下是 `static __inline`)，这意味着这些函数的实现通常非常简单，并且在编译时会被直接嵌入到调用代码中，以提高性能。

* **`_tolower(int __ch)` 和 `_toupper(int __ch)`:**
    * `_tolower`: 通过将字符的 ASCII 码与 `0x20` 进行按位或运算来实现。对于大写字母，其 ASCII 码的第 6 位为 0，进行按位或 `0x20` (二进制 `00100000`) 后，第 6 位变为 1，从而得到对应的小写字母的 ASCII 码。
    * `_toupper`: 通过将字符的 ASCII 码与 `0x20` 进行按位异或运算来实现。对于小写字母，其 ASCII 码的第 6 位为 1，进行按位异或 `0x20` 后，第 6 位变为 0，从而得到对应的大写字母的 ASCII 码。
    * **假设输入与输出:**
        * `_tolower('A')` 输出 `'a'`
        * `_toupper('a')` 输出 `'A'`

* **`__bionic_ctype_in_range(unsigned __lo, int __ch, unsigned __hi)`:**
    * 这个函数用于判断字符 `__ch` 是否在给定的 ASCII 码范围内 `[__lo, __hi]`。它通过将 `__ch` 转换为无符号类型并减去下界 `__lo`，然后判断结果是否小于等于范围的长度 `(__hi - __lo + 1)` 来实现。
    * **假设输入与输出:**
        * `__bionic_ctype_in_range('a', 'c', 'z')` 输出 `true`
        * `__bionic_ctype_in_range('a', '1', 'z')` 输出 `false`

* **`isalpha(int __ch)`:**
    * 判断字符是否为字母。它调用 `_tolower(__ch)` 将字符转换为小写，然后使用 `__bionic_ctype_in_range` 判断转换后的字符是否在 `'a'` 到 `'z'` 的范围内。

* **`isblank(int __ch)`:**
    * 判断字符是否为空格或制表符。直接使用 `||` 运算符判断 `__ch` 是否等于 `' '` 或 `'\t'`。

* **`iscntrl(int __ch)`:**
    * 判断字符是否为控制字符。控制字符的 ASCII 码小于空格 (ASCII 码 32) 或者等于 DEL (ASCII 码 127)。

* **`isdigit(int __ch)`:**
    * 判断字符是否为数字。使用 `__bionic_ctype_in_range` 判断字符是否在 `'0'` 到 `'9'` 的范围内。

* **`isgraph(int __ch)`:**
    * 判断字符是否为可打印字符，但不包括空格。可打印字符的 ASCII 码范围是 `'!'` 到 `'~'`。

* **`islower(int __ch)` 和 `isupper(int __ch)`:**
    * 分别判断字符是否为小写字母或大写字母。使用 `__bionic_ctype_in_range` 判断字符是否在相应的范围内。

* **`isprint(int __ch)`:**
    * 判断字符是否为可打印字符，包括空格。可打印字符的 ASCII 码范围是 `' '` 到 `'~'`。

* **`isspace(int __ch)`:**
    * 判断字符是否为空白字符，包括空格、换页符、换行符、回车符、水平制表符和垂直制表符。

* **`isxdigit(int __ch)`:**
    * 判断字符是否为十六进制数字 (`0-9`, `a-f`, `A-F`)。它结合了 `isdigit` 和判断小写或大写字母的逻辑。

* **`isalnum(int __ch)`:**
    * 判断字符是否为字母或数字。直接调用 `isalpha(__ch) || isdigit(__ch)`。

* **`ispunct(int __ch)`:**
    * 判断字符是否为标点符号。它判断字符是否是可打印字符 (`isgraph(__ch)`) 且不是字母或数字 (`!isalnum(__ch)`).

* **`tolower(int __ch)` 和 `toupper(int __ch)`:**
    * 这两个函数是更常用的版本，它们会先判断字符是否需要转换，如果需要才调用 `_tolower` 或 `_toupper`。

* **`isascii(int __ch)`:**
    * 判断字符的 ASCII 码是否小于 128 (0x80)，即是否为标准的 7 位 ASCII 字符。

* **`toascii(int __ch)`:**
    * 将字符的 ASCII 码截断到 7 位，相当于 `__ch & 0x7f`。

* **带 `_l` 后缀的函数 (例如 `isalnum_l`):**
    * 这些函数接受一个 `locale_t` 参数，但在这个特定的 `ctype.h` 实现中，它们会忽略这个参数，直接调用不带 `_l` 后缀的对应函数。这表明 Android 的 bionic libc 对于这些基本的字符分类和转换函数，并没有实现复杂的本地化支持。

**涉及 dynamic linker 的功能**

这个 `ctype.h` 文件本身是头文件，不包含可执行代码，因此它不直接涉及 dynamic linker 的功能。但是，这个头文件中声明的函数的实现代码位于 `libc.so` (或者对于 32 位系统是 `libc.so`) 动态链接库中。

**so 布局样本 (以 64 位为例)**

```
libc.so (动态链接库)
├── .text (代码段)
│   ├── isalpha  <-- isalpha 函数的实现代码
│   ├── isdigit
│   ├── tolower
│   ├── ...
├── .data (已初始化数据段)
│   └── ...
├── .bss (未初始化数据段)
│   └── ...
├── .dynsym (动态符号表)
│   ├── isalpha  <-- 包含 isalpha 的符号信息
│   ├── isdigit
│   ├── tolower
│   ├── ...
├── .dynstr (动态字符串表)
│   └── "isalpha"
│       "isdigit"
│       "tolower"
│       ...
├── .plt (过程链接表)
│   └── ...
├── .got.plt (全局偏移量表)
│   └── ...
└── ...
```

**链接的处理过程**

1. **编译时:** 当你编译一个使用 `ctype.h` 中函数的 C/C++ 代码时，编译器会识别出这些函数调用。由于这些函数在头文件中被声明为内联的，编译器可能会尝试将简单的实现直接嵌入到你的代码中。然而，对于更复杂的实现或者当编译器决定不进行内联时，它会在目标文件中生成对这些函数的符号引用，例如 `isalpha`。

2. **链接时:** 链接器 (例如 `ld`) 会将你的目标文件与 Android 系统提供的 `libc.so` 链接在一起。链接器会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `isalpha` 等函数的符号定义，并将你代码中对这些符号的引用指向 `libc.so` 中对应的函数地址。

3. **运行时:** 当你的应用程序在 Android 设备上运行时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有需要的共享库，包括 `libc.so`。动态链接器会使用全局偏移量表 (`.got.plt`) 来解析对外部函数的调用。当你的代码第一次调用 `isalpha` 时，会通过 PLT 跳转到 GOT 表项，GOT 表项最初包含一个指向 PLT 中下一条指令的地址。然后，动态链接器会解析 `isalpha` 的实际地址，并更新 GOT 表项，使其指向 `libc.so` 中 `isalpha` 函数的真正入口点。后续对 `isalpha` 的调用将直接通过 GOT 表项跳转到该函数的实现。

**逻辑推理的假设输入与输出**

大部分函数的逻辑都很直接，上面已经举例说明了。

**用户或编程常见的使用错误**

* **假设本地化支持:**  开发者可能会错误地认为 `ctype.h` 中的 `*_l` 函数会根据当前 locale 进行字符分类和转换，但实际上在 bionic libc 中，这些函数的行为与不带 `_l` 后缀的版本相同，它们只处理 ASCII 字符。这可能会导致在处理非 ASCII 字符时出现问题。
    * **错误示例:** 期望 `tolower_l('Á', locale)` 能正确转换为小写，但实际上会返回 'Á'。

* **字符范围假设:**  开发者可能会错误地假设字符的范围，例如认为所有字母都在 `a-z` 或 `A-Z` 的连续范围内，而忽略了其他扩展字符集。`ctype.h` 中的函数主要针对 ASCII 字符集。

* **误用带符号的 char:**  C/C++ 中 `char` 的符号性是实现定义的。如果将带符号的 `char` 直接传递给 `ctype.h` 中的函数，可能会导致意外的结果，因为这些函数通常将输入视为无符号的字符值。建议在使用这些函数时，将 `char` 类型转换为 `unsigned char` 或 `int`。
    * **错误示例:**  如果 `char` 是有符号的，且其值为负数（例如，表示扩展 ASCII 字符），直接传递给 `isalpha` 可能会导致访问越界或错误的判断。

**Android framework 或 NDK 如何到达这里**

1. **Android Framework (Java/Kotlin):**
   * 当 Android Framework 中的 Java 或 Kotlin 代码需要进行字符处理时，通常会使用 Java 标准库提供的 `Character` 类或正则表达式等 API。
   * 在某些情况下，Framework 代码可能会通过 JNI (Java Native Interface) 调用到 Native 代码 (C/C++)。

2. **NDK (Native Development Kit):**
   * NDK 允许开发者使用 C 和 C++ 编写 Android 应用的一部分。
   * 在 NDK 代码中，开发者可以直接包含 `<ctype.h>` 头文件并调用其中的函数。

**步骤示例 (假设一个简单的 NDK 应用验证用户输入):**

1. **用户在 Android 应用的 EditText 中输入文本。**
2. **Java 代码获取 EditText 的文本内容。**
3. **Java 代码通过 JNI 调用 NDK 中的一个 C++ 函数，将输入的文本传递给该函数。**
4. **NDK 的 C++ 函数中包含了 `<ctype.h>` 头文件。**
5. **C++ 函数使用 `isalpha` 或 `isdigit` 等函数遍历输入的字符串，验证每个字符是否为字母或数字。**
6. **验证结果被传递回 Java 代码，用于进一步处理。**

**Frida Hook 示例调试步骤**

假设我们要 hook `isalpha` 函数，查看它的输入和输出：

```python
import frida
import sys

package_name = "your.application.package"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] 进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "isalpha"), {
    onEnter: function(args) {
        var charCode = args[0].toInt();
        send({type: "send", payload: "isalpha called with charCode: " + charCode + ", char: '" + String.fromCharCode(charCode) + "'"});
        this.charCode = charCode;
    },
    onLeave: function(retval) {
        send({type: "send", payload: "isalpha returned: " + retval + " for charCode: " + this.charCode});
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print(f"[*] 已连接到进程 '{package_name}'，正在 hook isalpha 函数...")
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida:** 确保你的开发机器上安装了 Frida 和 Python 的 Frida 模块。
2. **准备目标应用:** 确保你要调试的 Android 应用已经安装并在设备上运行。
3. **替换包名:** 将 `your.application.package` 替换为你要调试的应用的实际包名。
4. **运行 Frida 脚本:** 在终端中运行这个 Python 脚本。
5. **触发函数调用:** 在你的 Android 应用中执行一些操作，这些操作会调用到 `isalpha` 函数，例如在 EditText 中输入字符。
6. **查看输出:** Frida 脚本会将 `isalpha` 函数的调用信息（输入字符的 ASCII 码和字符本身）以及返回值打印到终端。

这个 Frida 脚本通过 `Interceptor.attach` 拦截了 `libc.so` 中 `isalpha` 函数的调用，并在函数入口 (`onEnter`) 和出口 (`onLeave`) 处执行自定义的代码，从而实现了对函数调用的监控。

希望这个详细的解释能够帮助你理解 `bionic/libc/include/ctype.h` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/include/ctype.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

/**
 * @file ctype.h
 * @brief ASCII character classification.
 */

#include <sys/cdefs.h>
#include <xlocale.h>

/* All the functions in this file are trivial, being but a single
 * instruction on most architectures. For that reason, we inline them by
 * default. This macro is meant for internal use only, so that we can
 * also provide actual symbols for any caller that needs them.
 */
#if !defined(__BIONIC_CTYPE_INLINE)
#define __BIONIC_CTYPE_INLINE static __inline
#endif

/** Internal implementation detail. Do not use. */
#define _CTYPE_U 0x01
/** Internal implementation detail. Do not use. */
#define _CTYPE_L 0x02
/** Internal implementation detail. Do not use. */
#define _CTYPE_D 0x04
/** Internal implementation detail. Do not use. */
#define _CTYPE_S 0x08
/** Internal implementation detail. Do not use. */
#define _CTYPE_P 0x10
/** Internal implementation detail. Do not use. */
#define _CTYPE_C 0x20
/** Internal implementation detail. Do not use. */
#define _CTYPE_X 0x40
/** Internal implementation detail. Do not use. */
#define _CTYPE_B 0x80
/** Internal implementation detail. Do not use. */
#define _CTYPE_R (_CTYPE_P|_CTYPE_U|_CTYPE_L|_CTYPE_D|_CTYPE_B)
/** Internal implementation detail. Do not use. */
#define _CTYPE_A (_CTYPE_L|_CTYPE_U)
/** Internal implementation detail. Do not use. */
#define _CTYPE_N _CTYPE_D

__BEGIN_DECLS

/** Internal implementation detail. Do not use. */
extern const char* _ctype_;

/**
 * Returns the corresponding lower-case character if `ch` is upper-case, or undefined otherwise.
 *
 * Prefer tolower() instead.
 */
__BIONIC_CTYPE_INLINE int _tolower(int __ch) {
  return __ch | 0x20;
}

/**
 * Returns the corresponding upper-case character if `ch` is lower-case, or undefined otherwise.
 *
 * Prefer toupper() instead.
 */
__BIONIC_CTYPE_INLINE int _toupper(int __ch) {
  // Using EOR rather than AND makes no difference on arm, but saves an
  // instruction on arm64.
  return __ch ^ 0x20;
}

/** Internal implementation detail. Do not use. */
__attribute__((__no_sanitize__("unsigned-integer-overflow")))
__BIONIC_CTYPE_INLINE int __bionic_ctype_in_range(unsigned __lo, int __ch, unsigned __hi) {
  return (__BIONIC_CAST(static_cast, unsigned, __ch) - __lo) < (__hi - __lo + 1);
}

/** Returns true if `ch` is in `[A-Za-z]`. */
__BIONIC_CTYPE_INLINE int isalpha(int __ch) {
  return __bionic_ctype_in_range('a', _tolower(__ch), 'z');
}

/** Returns true if `ch` is a space or tab. */
__BIONIC_CTYPE_INLINE int isblank(int __ch) {
  return __ch == ' ' || __ch == '\t';
}

/** Returns true if `ch` is a control character (any character before space, plus DEL). */
__BIONIC_CTYPE_INLINE int iscntrl(int __ch) {
  return (__BIONIC_CAST(static_cast, unsigned, __ch) < ' ') || __ch == 0x7f;
}

/** Returns true if `ch` is in `[0-9]`. */
__BIONIC_CTYPE_INLINE int isdigit(int __ch) {
  return __bionic_ctype_in_range('0', __ch, '9');
}

/** Returns true if `ch` is `[A-Za-z0-9]` or punctuation. */
__BIONIC_CTYPE_INLINE int isgraph(int __ch) {
  return __bionic_ctype_in_range('!', __ch, '~');
}

/** Returns true if `ch` is in `[a-z]`. */
__BIONIC_CTYPE_INLINE int islower(int __ch) {
  return __bionic_ctype_in_range('a', __ch, 'z');
}

/** Returns true if `ch` is `[A-Za-z0-9]` or punctuation or space. */
__BIONIC_CTYPE_INLINE int isprint(int __ch) {
  return __bionic_ctype_in_range(' ', __ch, '~');
}

/** Returns true if `ch` is in `[ \f\n\r\t\v]`. */
__BIONIC_CTYPE_INLINE int isspace(int __ch) {
  return __ch == ' ' || __bionic_ctype_in_range('\t', __ch, '\r');
}

/** Returns true if `ch` is in `[A-Z]`. */
__BIONIC_CTYPE_INLINE int isupper(int __ch) {
  return __bionic_ctype_in_range('A', __ch, 'Z');
}

/** Returns true if `ch` is in `[0-9A-Fa-f]`. */
__BIONIC_CTYPE_INLINE int isxdigit(int __ch) {
  return isdigit(__ch) || __bionic_ctype_in_range('a', _tolower(__ch), 'f') ;
}

/** Returns true if `ch` is in `[A-Za-z0-9]`. */
__BIONIC_CTYPE_INLINE int isalnum(int __ch) {
  return isalpha(__ch) || isdigit(__ch);
}

/** Returns true if `ch` is punctuation. */
__BIONIC_CTYPE_INLINE int ispunct(int __ch) {
  return isgraph(__ch) && !isalnum(__ch);
}

/** Returns the corresponding lower-case character if `ch` is upper-case, or `ch` otherwise. */
__BIONIC_CTYPE_INLINE int tolower(int __ch) {
  return (__bionic_ctype_in_range('A', __ch, 'Z')) ? _tolower(__ch) : __ch;
}

/** Returns the corresponding upper-case character if `ch` is lower-case, or `ch` otherwise. */
__BIONIC_CTYPE_INLINE int toupper(int __ch) {
  return (__bionic_ctype_in_range('a', __ch, 'z')) ? _toupper(__ch) : __ch;
}

/** Returns true if `ch` is less than 0x80. */
__BIONIC_CTYPE_INLINE int isascii(int __ch) {
  return __BIONIC_CAST(static_cast, unsigned, __ch) < 0x80;
}

/** Returns `ch & 0x7f`. */
__BIONIC_CTYPE_INLINE int toascii(int __ch) {
  return __ch & 0x7f;
}

/** Like isalnum() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isalnum_l(int __ch, locale_t __l) {
  return isalnum(__ch);
}

/** Like isalpha() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isalpha_l(int __ch, locale_t __l) {
  return isalpha(__ch);
}

/** Like isblank() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isblank_l(int __ch, locale_t __l) {
  return isblank(__ch);
}

/** Like iscntrl() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int iscntrl_l(int __ch, locale_t __l) {
  return iscntrl(__ch);
}

/** Like isdigit() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isdigit_l(int __ch, locale_t __l) {
  return isdigit(__ch);
}

/** Like isgraph() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isgraph_l(int __ch, locale_t __l) {
  return isgraph(__ch);
}

/** Like islower() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int islower_l(int __ch, locale_t __l) {
  return islower(__ch);
}

/** Like isprint() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isprint_l(int __ch, locale_t __l) {
  return isprint(__ch);
}

/** Like ispunct() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int ispunct_l(int __ch, locale_t __l) {
  return ispunct(__ch);
}

/** Like isspace() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isspace_l(int __ch, locale_t __l) {
  return isspace(__ch);
}

/** Like isupper() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isupper_l(int __ch, locale_t __l) {
  return isupper(__ch);
}

/** Like isxdigit() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int isxdigit_l(int __ch, locale_t __l) {
  return isxdigit(__ch);
}

/** Like tolower() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int tolower_l(int __ch, locale_t __l) {
  return tolower(__ch);
}

/** Like toupper() but with an ignored `locale_t`. */
__BIONIC_CTYPE_INLINE int toupper_l(int __ch, locale_t __l) {
  return toupper(__ch);
}

__END_DECLS

"""

```