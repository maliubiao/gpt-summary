Response:
Let's break down the thought process for generating the comprehensive analysis of `wctype.cpp`.

**1. Understanding the Request:**

The core request is to analyze the provided C++ source code file (`wctype.cpp`) from Android's Bionic library. The analysis should cover:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it fit into the Android ecosystem?
* **Implementation Details:**  How do the individual functions work?
* **Dynamic Linking:**  How does it interact with the dynamic linker?
* **Logic and Assumptions:**  Demonstrate understanding through input/output examples.
* **Common Errors:** Highlight potential pitfalls for developers.
* **Android Integration:** How is it used within Android, and how can it be debugged?

**2. Initial Code Examination and High-Level Understanding:**

The first step is to read through the code and identify the key elements:

* **Header Inclusion:** The file includes standard C headers (`wctype.h`, `ctype.h`, etc.) and Bionic-specific headers (`bionic/macros.h`, `private/icu.h`). This immediately suggests that the file deals with wide character classification and conversion, leveraging both standard C and ICU (International Components for Unicode) functionality.
* **`enum` `WC_TYPE`:**  This enumeration defines constants representing different wide character classes (alnum, alpha, digit, etc.). This hints at the core purpose of classifying wide characters.
* **`__find_icu_symbol`:** This function is used repeatedly to load functions from ICU dynamically. This indicates that Bionic is dynamically linking against the ICU library for extended wide character support.
* **`DO_ISW` Macro:** This macro is used to define many of the `isw*` functions. It encapsulates the logic for checking if a character is within the ASCII range (0-127) and, if not, calling an ICU function. This highlights the dual approach of using standard C for ASCII and ICU for broader Unicode support.
* **Individual `isw*`, `tow*`, `wctype`, `wctrans`, `towctrans` functions:** These are standard C library functions related to wide character classification and conversion. The code provides their implementations using the `DO_ISW` macro and direct ICU calls.
* **`__strong_alias`:** This macro likely creates aliases for the functions, probably for compatibility with locale-specific versions (e.g., `iswalnum_l`).
* **Static `wctrans_t` variables:** These represent predefined wide character transformation types ("tolower" and "toupper").

**3. Deeper Dive into Functionality and Implementation:**

For each function, the thought process would be:

* **Purpose:** What is the standard C library function supposed to do? (e.g., `iswalnum` checks if a wide character is alphanumeric).
* **Implementation:** How does this specific implementation work?
    * **ASCII Check:**  The code often checks if the character is within the ASCII range (0-127). If so, it uses the corresponding standard `ctype.h` function.
    * **ICU Integration:** If the character is outside the ASCII range, it dynamically loads the relevant ICU function using `__find_icu_symbol` and calls it. This is the crucial part for handling Unicode characters.
    * **`DO_ISW` Macro Breakdown:** Understand how the macro simplifies the common pattern of checking for ASCII and then using ICU.
* **Relationship to Android:** Why is this important in Android?  Android needs to support a wide range of languages and character sets, making Unicode support essential.

**4. Addressing Dynamic Linking:**

The presence of `__find_icu_symbol` is the key indicator of dynamic linking. The analysis needs to cover:

* **Purpose of Dynamic Linking:** Why is ICU linked dynamically? (Reduces binary size, allows updates to ICU without recompiling everything).
* **`so` Layout:**  Imagine the structure of the relevant shared objects (`libc.so`, `libicuuc.so`, `libicui18n.so`). Where would these functions reside?
* **Linking Process:** How does `dlopen`/`dlsym` (or similar mechanisms) work to resolve the ICU symbols at runtime?

**5. Constructing Examples and Identifying Errors:**

* **Input/Output Examples:** Create simple examples to illustrate how each function works. Include both ASCII and non-ASCII inputs to demonstrate the ICU integration.
* **Common Errors:** Think about how developers might misuse these functions. For instance, forgetting to set the locale, assuming ASCII-only behavior, or misinterpreting the return values.

**6. Tracing Android Integration and Debugging:**

* **Android Framework/NDK:** Consider scenarios where these functions would be used. Examples include text input, internationalization APIs, and file handling.
* **Frida Hooking:**  Demonstrate how Frida can be used to intercept calls to these functions and inspect their arguments and return values. This requires knowing the function signatures and how Frida works.

**7. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Start with a high-level overview and then delve into details for each function and concept. Use clear and concise language, and provide code snippets where appropriate.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe just list the functions.
* **Correction:** The request asks for more detail, including implementation, Android relevance, and dynamic linking. Need to expand on each point.
* **Initial thought:**  Focus only on the C++ code.
* **Correction:**  The request explicitly asks about Android Framework/NDK integration, so examples beyond just the C library are needed.
* **Initial thought:**  Just describe `__find_icu_symbol`.
* **Correction:** Explain the broader concept of dynamic linking and how it applies to ICU in Android.

By following these steps and iteratively refining the analysis, a comprehensive and accurate response can be generated, addressing all aspects of the original request. The key is to combine code-level understanding with knowledge of Android's architecture and development practices.
好的，我们来详细分析一下 `bionic/libc/bionic/wctype.cpp` 这个文件。

**文件功能概述**

`wctype.cpp` 文件是 Android Bionic C 库的一部分，它实现了与宽字符分类和转换相关的函数。这些函数定义在标准 C 库的 `<wctype.h>` 头文件中。 它的主要功能是提供一组用于处理 Unicode 字符的函数，例如判断字符是否是字母、数字、空格等等，以及将字符转换为大写或小写。

**与 Android 功能的关系**

这个文件在 Android 系统中扮演着至关重要的角色，因为它提供了处理多语言文本的基础设施。Android 作为一个全球化的操作系统，需要支持各种不同的语言和字符集。`wctype.cpp` 提供的函数使得 Android 应用程序能够正确地处理和显示来自不同语言环境的文本。

**举例说明:**

* **文本输入和显示:** 当用户在 Android 设备上输入文本时，系统需要判断输入的字符类型（例如，是否是字母或数字）以便进行验证或格式化。`wctype.cpp` 中的函数被用来实现这些功能。例如，一个输入框可能只允许输入数字，`iswdigit()` 函数可以用来检查用户输入的字符是否是数字。
* **文本处理:**  Android 系统和应用程序经常需要对文本进行处理，例如搜索、排序、转换大小写等。`wctype.cpp` 提供的函数可以帮助实现这些操作。例如，在搜索功能中，可能需要将所有文本转换为小写，`towlower()` 函数可以完成这个任务。
* **国际化 (i18n):**  为了支持不同语言的用户，Android 框架需要根据用户的语言设置来处理文本。`wctype.cpp` 中的函数是实现国际化功能的基础组成部分。例如，在某些语言中，空格的定义可能与英语不同，`iswspace()` 函数可以根据当前的语言环境来判断字符是否是空格。

**libc 函数的实现细节**

`wctype.cpp` 的实现策略是：

1. **优先使用标准的 ASCII 函数:** 对于 ASCII 范围内的字符 (0-127)，直接调用 `<ctype.h>` 中对应的标准 C 函数，例如 `isalnum()`，`isalpha()` 等。这是为了追求性能，因为 ASCII 字符的处理通常更快。
2. **利用 ICU 库处理 Unicode 字符:** 对于超出 ASCII 范围的字符，它会动态地加载 ICU (International Components for Unicode) 库中相应的函数。ICU 是一个强大的、广泛使用的 Unicode 支持库。

让我们逐个分析一些关键的函数：

* **`iswalnum(wint_t wc)`:**  判断宽字符 `wc` 是否是字母或数字。
    * **实现:**  首先使用 `__predict_true(wc < 0x80)` 进行快速判断，如果 `wc` 是 ASCII 字符，则直接调用 `isalnum(wc)`。
    * **ICU 部分:** 如果 `wc` 超出 ASCII 范围，则通过 `__find_icu_symbol("u_hasBinaryProperty")` 动态获取 ICU 的 `u_hasBinaryProperty` 函数的地址。然后调用 `u_hasBinaryProperty(wc, UCHAR_POSIX_ALNUM)` 来判断。`UCHAR_POSIX_ALNUM` 是 ICU 定义的表示字母或数字的属性常量。
    * **假设输入与输出:**
        * 输入: `L'A'` (ASCII 大写字母) -> 输出: 非零值 (真)
        * 输入: `L'7'` (ASCII 数字) -> 输出: 非零值 (真)
        * 输入: `L'α'` (希腊小写字母) -> 输出: 非零值 (真)
        * 输入: `L' '` (ASCII 空格) -> 输出: 0 (假)

* **`iswalpha(wint_t wc)`:** 判断宽字符 `wc` 是否是字母。实现方式与 `iswalnum` 类似，只是使用的 ICU 常量是 `UCHAR_ALPHABETIC`，调用的窄字符函数是 `isalpha`。

* **`iswblank(wint_t wc)`:** 判断宽字符 `wc` 是否是空格或制表符。实现方式类似，使用 `UCHAR_POSIX_BLANK` 和 `isblank`。

* **`iswcntrl(wint_t wc)`:** 判断宽字符 `wc` 是否是控制字符。
    * **实现:** ASCII 部分调用 `iscntrl(wc)`。
    * **ICU 部分:**  动态获取 `u_charType` 函数，然后判断 `u_charType(wc)` 的返回值是否等于 `U_CONTROL_CHAR`。

* **`iswdigit(wint_t wc)`:** 判断宽字符 `wc` 是否是数字。
    * **实现:** ASCII 部分调用 `isdigit(wc)`。
    * **ICU 部分:** 动态获取 `u_isdigit` 函数并调用。

* **`iswpunct(wint_t wc)`:** 判断宽字符 `wc` 是否是标点符号。
    * **实现:** ASCII 部分调用 `ispunct(wc)`。
    * **ICU 部分:** 动态获取 `u_ispunct` 函数并调用。

* **`iswspace(wint_t wc)`:** 判断宽字符 `wc` 是否是空白字符（包括空格、制表符、换行符等）。实现方式类似，使用 `UCHAR_WHITE_SPACE` 和 `isspace`。

* **`iswupper(wint_t wc)` 和 `iswlower(wint_t wc)`:** 分别判断宽字符是否是大写或小写字母。实现方式类似。

* **`iswxdigit(wint_t wc)`:** 判断宽字符 `wc` 是否是十六进制数字。实现方式类似。

* **`iswctype(wint_t wc, wctype_t char_class)`:**  根据给定的字符类别 `char_class` 判断宽字符 `wc` 是否属于该类别。
    * **实现:** 它维护了一个函数指针数组 `fns`，其中包含了前面介绍的 `isw*` 函数的指针。根据 `char_class` 的值（例如 `WC_TYPE_ALNUM`），它会调用数组中对应的函数。

* **`towlower(wint_t wc)`:** 将宽字符 `wc` 转换为小写。
    * **实现:** ASCII 部分调用 `tolower(wc)`。
    * **ICU 部分:** 动态获取 `u_tolower` 函数并调用。

* **`towupper(wint_t wc)`:** 将宽字符 `wc` 转换为大写。实现方式类似。

* **`wctype(const char* property)`:**  根据给定的属性名称字符串，返回对应的 `wctype_t` 值。例如，`wctype("alnum")` 会返回 `WC_TYPE_ALNUM`。

* **`wctrans(const char* name)`:**  根据给定的转换名称字符串，返回对应的 `wctrans_t` 值。目前只支持 "tolower" 和 "toupper"。

* **`towctrans(wint_t c, wctrans_t t)`:**  根据给定的转换类型 `t`，对宽字符 `c` 进行转换。例如，如果 `t` 是 `wctrans_tolower`，则调用 `towlower(c)`。

**涉及 dynamic linker 的功能**

`wctype.cpp` 依赖 dynamic linker 来加载 ICU 库中的函数。它使用了 Bionic 提供的 `__find_icu_symbol` 函数来实现这个功能。

**`so` 布局样本:**

```
/system/lib64/libc.so  (或其他架构对应的 libc.so 路径)
    ... (libc 的其他代码)
    wctype.o  (编译后的 wctype.cpp 代码)
    __find_icu_symbol  (dynamic linker 相关的辅助函数)
    ...

/system/lib64/libicuuc.so  (ICU 的 Unicode 字符通用库)
    ...
    u_hasBinaryProperty  (ICU 提供的函数)
    u_charType
    u_isdigit
    u_ispunct
    u_tolower
    u_toupper
    ...
```

**链接的处理过程:**

1. **编译时:**  `wctype.cpp` 在编译时，对 ICU 函数的调用只是声明了函数原型，并没有实际链接到 ICU 库。
2. **运行时:**
   * 当 `iswalnum` 等函数被首次调用，并且需要处理非 ASCII 字符时，会执行 `__find_icu_symbol("u_hasBinaryProperty")`。
   * `__find_icu_symbol` 函数会：
     * 尝试找到并加载 ICU 相关的共享库 (例如 `libicuuc.so` 或 `libicui18n.so`)。这可能通过 `dlopen` 或类似的系统调用完成。
     * 在加载的库中查找名为 "u_hasBinaryProperty" 的符号的地址。这通常通过 `dlsym` 完成。
     * 如果找到该符号，则返回其地址，并将其缓存起来，以便后续调用可以直接使用，而无需再次查找。
   * 之后，`iswalnum` 函数就可以通过获取到的函数指针来调用 ICU 的 `u_hasBinaryProperty` 函数。

**逻辑推理、假设输入与输出**

在上面分析每个函数时，已经给出了一些假设输入和输出的例子。这些例子展示了函数如何根据不同的输入返回不同的结果，以及如何处理 ASCII 和非 ASCII 字符。

**用户或编程常见的使用错误**

1. **未设置正确的 locale:**  `wctype.h` 中定义的很多函数的行为受到当前 locale 的影响。如果 locale 设置不正确，可能会导致这些函数返回意外的结果。
   ```c
   #include <stdio.h>
   #include <wchar.h>
   #include <locale.h>

   int main() {
       setlocale(LC_CTYPE, "en_US.UTF-8"); // 设置 locale

       wchar_t ch = L'é'; // 带音标的字符
       if (iswalpha(ch)) {
           printf("'%lc' is an alphabet character.\n", ch);
       } else {
           printf("'%lc' is not an alphabet character.\n", ch);
       }

       return 0;
   }
   ```
   如果忘记设置 locale 或者设置了不支持 UTF-8 的 locale，`iswalpha(L'é')` 可能返回 0。

2. **假设字符是 ASCII:**  有些开发者可能会错误地假设所有需要处理的字符都是 ASCII 字符，从而直接使用 `<ctype.h>` 中的函数，而忽略了宽字符函数。这会导致程序无法正确处理 Unicode 字符。
   ```c
   #include <stdio.h>
   #include <ctype.h>
   #include <wchar.h>

   int main() {
       wchar_t ch = L'你好'; // 中文字符
       if (isalpha(ch)) { // 错误地使用了 isalpha
           printf("'%lc' is an alphabet character.\n", ch);
       } else {
           printf("'%lc' is not an alphabet character.\n", ch);
       }
       return 0;
   }
   ```
   在这个例子中，`isalpha(L'你好')` 会将宽字符截断为窄字符，导致判断错误。应该使用 `iswalpha(L'你好')`。

3. **混淆字符和字符串处理:**  `wctype.h` 中的函数主要用于处理单个宽字符 (`wint_t`)。如果需要处理宽字符串，应该使用 `<wchar.h>` 中提供的宽字符串处理函数，例如 `wcslen`, `wcscpy` 等。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 代码):**
   * 当 Android Framework 需要处理文本时，例如在 `TextView` 中显示文本、处理用户输入等，它会调用底层的 Native 代码（通常通过 JNI）。
   * 例如，`java.lang.Character` 类中的很多静态方法，如 `isDigit()`, `isLetter()` 等，其底层实现会调用 Bionic 库中对应的 `iswdigit()`, `iswalpha()` 等函数。
   * **示例:** 当 `TextView` 需要判断一个字符是否需要进行双向文本处理时，可能会间接地调用到 `wctype.cpp` 中的函数。

2. **Android NDK (C/C++ 代码):**
   * NDK 允许开发者使用 C/C++ 编写 Android 应用的 Native 代码。
   * 在 Native 代码中，开发者可以直接包含 `<wctype.h>` 头文件，并调用其中定义的函数。
   * **示例:** 一个使用 NDK 开发的文本编辑器应用，可能会使用 `iswspace()` 来判断用户输入的字符是否是空格，以便进行自动缩进或换行处理。

**Frida Hook 示例调试步骤**

假设我们想 hook `iswalpha` 函数，查看其输入和输出：

```python
import frida
import sys

# 要 hook 的目标进程
package_name = "your.target.app" # 替换为你的目标应用的包名

# Frida 脚本
hook_script = """
Interceptor.attach(Module.findExportByName(null, "iswalpha"), {
    onEnter: function(args) {
        console.log("iswalpha called with argument:", ptr(args[0]).readU32());
        // 可以根据需要读取更多信息，例如将 wint_t 转换为字符
        var charCode = ptr(args[0]).readU32();
        console.log("Character code:", charCode);
        if (charCode < 128) {
            console.log("ASCII character:", String.fromCharCode(charCode));
        }
    },
    onLeave: function(retval) {
        console.log("iswalpha returned:", retval);
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload:", message['payload'])
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script = session.create_script(hook_script)
script.on('message', on_message)
script.load()

print(f"[*] 成功 Hooked 进程 '{package_name}'. Press Ctrl+C to detach.")
sys.stdin.read()
session.detach()
```

**使用步骤:**

1. **安装 Frida 和 Python binding:**  确保你的开发机器上安装了 Frida 和 Python 的 Frida binding (`pip install frida-tools`).
2. **找到目标应用的包名:**  你需要知道你想调试的应用的包名。
3. **运行目标应用:**  在 Android 设备或模拟器上运行目标应用。
4. **运行 Frida 脚本:**  将上面的 Python 代码保存为一个 `.py` 文件（例如 `hook_iswalpha.py`），然后运行 `python hook_iswalpha.py`。
5. **在应用中触发 `iswalpha` 的调用:**  在目标应用中执行一些操作，例如输入文本，这些操作可能会调用到 `iswalpha` 函数。
6. **查看 Frida 输出:**  Frida 会打印出 `iswalpha` 函数被调用时的参数和返回值。

**说明:**

* `Module.findExportByName(null, "iswalpha")` 用于查找名为 "iswalpha" 的导出函数。`null` 表示在所有已加载的模块中查找。
* `Interceptor.attach` 用于拦截对该函数的调用。
* `onEnter` 函数在 `iswalpha` 函数执行之前被调用，我们可以在这里打印出函数的参数。`args[0]` 是 `wint_t wc` 参数的指针。
* `onLeave` 函数在 `iswalpha` 函数执行之后被调用，我们可以在这里打印出函数的返回值。

通过这种方式，你可以观察 `wctype.cpp` 中函数的实际调用情况，帮助理解其工作原理和调试相关问题。

希望以上详细的分析能够帮助你理解 `bionic/libc/bionic/wctype.cpp` 的功能和实现细节。

Prompt: 
```
这是目录为bionic/libc/bionic/wctype.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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

#include <wctype.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "bionic/macros.h"
#include "private/icu.h"

enum {
  WC_TYPE_INVALID = 0,
  WC_TYPE_ALNUM,
  WC_TYPE_ALPHA,
  WC_TYPE_BLANK,
  WC_TYPE_CNTRL,
  WC_TYPE_DIGIT,
  WC_TYPE_GRAPH,
  WC_TYPE_LOWER,
  WC_TYPE_PRINT,
  WC_TYPE_PUNCT,
  WC_TYPE_SPACE,
  WC_TYPE_UPPER,
  WC_TYPE_XDIGIT,
  WC_TYPE_MAX
};

static u_hasBinaryProperty_t __find_u_hasBinaryProperty() {
  static auto u_hasBinaryProperty =
      reinterpret_cast<u_hasBinaryProperty_t>(__find_icu_symbol("u_hasBinaryProperty"));
  return u_hasBinaryProperty;
}

#define DO_ISW(icu_constant, narrow_fn) \
  u_hasBinaryProperty_t u_hasBinaryProperty; \
  if (__predict_true(wc < 0x80) || \
      !(u_hasBinaryProperty = __find_u_hasBinaryProperty())) { \
    return narrow_fn(wc); \
  } \
  return u_hasBinaryProperty(wc, icu_constant); \

int iswalnum(wint_t wc) { DO_ISW(UCHAR_POSIX_ALNUM, isalnum); }
__strong_alias(iswalnum_l, iswalnum);
int iswalpha(wint_t wc) { DO_ISW(UCHAR_ALPHABETIC, isalpha); }
__strong_alias(iswalpha_l, iswalpha);
int iswblank(wint_t wc) { DO_ISW(UCHAR_POSIX_BLANK, isblank); }
__strong_alias(iswblank_l, iswblank);
int iswgraph(wint_t wc) { DO_ISW(UCHAR_POSIX_GRAPH, isgraph); }
__strong_alias(iswgraph_l, iswgraph);
int iswlower(wint_t wc) { DO_ISW(UCHAR_LOWERCASE, islower); }
__strong_alias(iswlower_l, iswlower);
int iswprint(wint_t wc) { DO_ISW(UCHAR_POSIX_PRINT, isprint); }
__strong_alias(iswprint_l, iswprint);
int iswspace(wint_t wc) { DO_ISW(UCHAR_WHITE_SPACE, isspace); }
__strong_alias(iswspace_l, iswspace);
int iswupper(wint_t wc) { DO_ISW(UCHAR_UPPERCASE, isupper); }
__strong_alias(iswupper_l, iswupper);
int iswxdigit(wint_t wc) { DO_ISW(UCHAR_POSIX_XDIGIT, isxdigit); }
__strong_alias(iswxdigit_l, iswxdigit);

int iswcntrl(wint_t wc) {
  if (wc < 0x80) return iscntrl(wc);
  typedef int8_t (*FnT)(UChar32);
  static auto u_charType = reinterpret_cast<FnT>(__find_icu_symbol("u_charType"));
  return u_charType ? (u_charType(wc) == U_CONTROL_CHAR) : iscntrl(wc);
}
__strong_alias(iswcntrl_l, iswcntrl);

int iswdigit(wint_t wc) {
  if (wc < 0x80) return isdigit(wc);
  typedef UBool (*FnT)(UChar32);
  static auto u_isdigit = reinterpret_cast<FnT>(__find_icu_symbol("u_isdigit"));
  return u_isdigit ? u_isdigit(wc) : isdigit(wc);
}
__strong_alias(iswdigit_l, iswdigit);

int iswpunct(wint_t wc) {
  if (wc < 0x80) return ispunct(wc);
  typedef UBool (*FnT)(UChar32);
  static auto u_ispunct = reinterpret_cast<FnT>(__find_icu_symbol("u_ispunct"));
  return u_ispunct ? u_ispunct(wc) : ispunct(wc);
}
__strong_alias(iswpunct_l, iswpunct);

int iswctype(wint_t wc, wctype_t char_class) {
  if (char_class < WC_TYPE_ALNUM || char_class > WC_TYPE_XDIGIT) return 0;
  static int (*fns[])(wint_t) = {
    iswalnum, iswalpha, iswblank, iswcntrl, iswdigit, iswgraph,
    iswlower, iswprint, iswpunct, iswspace, iswupper, iswxdigit
  };
  return fns[char_class - WC_TYPE_ALNUM](wc);
}
__strong_alias(iswctype_l, iswctype);

wint_t towlower(wint_t wc) {
  if (wc < 0x80) return tolower(wc);

  typedef UChar32 (*FnT)(UChar32);
  static auto u_tolower = reinterpret_cast<FnT>(__find_icu_symbol("u_tolower"));
  return u_tolower ? u_tolower(wc) : tolower(wc);
}
__strong_alias(towlower_l, towlower);

wint_t towupper(wint_t wc) {
  if (wc < 0x80) return toupper(wc);

  typedef UChar32 (*FnT)(UChar32);
  static auto u_toupper = reinterpret_cast<FnT>(__find_icu_symbol("u_toupper"));
  return u_toupper ? u_toupper(wc) : toupper(wc);
}
__strong_alias(towupper_l, towupper);

wctype_t wctype(const char* property) {
  static const char* const  properties[WC_TYPE_MAX - 1] = {
    "alnum", "alpha", "blank", "cntrl", "digit", "graph",
    "lower", "print", "punct", "space", "upper", "xdigit"
  };
  for (size_t i = 0; i < arraysize(properties); ++i) {
    if (!strcmp(properties[i], property)) {
      return static_cast<wctype_t>(WC_TYPE_ALNUM + i);
    }
  }
  return static_cast<wctype_t>(0);
}
__strong_alias(wctype_l, wctype);

static wctrans_t wctrans_tolower = wctrans_t(1);
static wctrans_t wctrans_toupper = wctrans_t(2);

wctrans_t wctrans(const char* name) {
  if (strcmp(name, "tolower") == 0) return wctrans_tolower;
  if (strcmp(name, "toupper") == 0) return wctrans_toupper;
  errno = EINVAL;
  return nullptr;
}
__strong_alias(wctrans_l, wctrans);

wint_t towctrans(wint_t c, wctrans_t t) {
  if (t == wctrans_tolower) return towlower(c);
  if (t == wctrans_toupper) return towupper(c);
  errno = EINVAL;
  return c;
}
__strong_alias(towctrans_l, towctrans);

"""

```