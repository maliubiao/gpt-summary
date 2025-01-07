Response:
Let's break down the thought process to generate the detailed response for the `wchar.h` header file.

**1. Understanding the Request:**

The core request is to analyze a C header file (`wchar.h`) from Android's Bionic library and explain its functionality, connections to Android, implementation details, dynamic linking aspects, potential errors, and how it's used within the Android ecosystem. The output should be in Chinese.

**2. Initial Analysis of the Header File:**

The first step is to recognize what `wchar.h` is about. The name itself is a strong clue: it deals with "wide characters". The inclusion of other headers like `stdio.h`, `stddef.h`, `time.h`, `locale.h` provides context – it's about input/output, basic definitions, time handling, and localization, specifically for wide characters.

**3. Categorizing Functions:**

To make sense of the many functions, it's useful to group them by their general purpose. I mentally categorized them into:

* **Input/Output:** Functions dealing with reading and writing wide characters to/from streams (files, strings). Examples: `fwprintf`, `fwscanf`, `fgetwc`, `fputws`.
* **String Manipulation:** Functions for working with wide character strings (copying, comparing, searching, concatenating). Examples: `wcscpy`, `wcscmp`, `wcschr`, `wcscat`.
* **Conversion:** Functions for converting between narrow and wide characters, and other types. Examples: `btowc`, `wcrtomb`, `wcstod`, `wcstol`.
* **Memory Manipulation:** Functions for working with blocks of wide characters in memory. Examples: `wmemcpy`, `wmemcmp`, `wmemset`.
* **Localization:** Functions that take `locale_t` as an argument, indicating they handle locale-specific behavior. Examples: `wcscoll_l`, `wcsftime_l`.
* **Miscellaneous:** Other functions that don't fit neatly into the above categories. Examples: `fwide`, `mbsinit`.

**4. Detailing Function Implementations (Conceptual):**

For each category, I considered the *general* implementation strategy. The request specifically asks for *how* the functions are implemented. While I don't have the actual C source code for these functions within Bionic, I can infer their underlying logic based on standard C library knowledge and the function signatures:

* **I/O:** These functions likely call lower-level operating system APIs (like `read`, `write`) after performing any necessary encoding/decoding or buffering.
* **String Manipulation:** These often involve iterating through the wide character strings, comparing or manipulating individual `wchar_t` units. Care must be taken with null terminators.
* **Conversion:**  These functions would involve looking up character mappings based on the current locale and performing the necessary transformations between different character encodings.
* **Memory Manipulation:**  These are generally implemented using optimized memory access routines (like `memcpy`, `memcmp`).
* **Localization:**  These rely on locale data (character sets, sorting rules, formatting conventions) to perform their operations.

**5. Connecting to Android:**

The key here is to understand *why* Android needs wide character support. The main reason is internationalization (i18n). Android apps need to support various languages, many of which require characters outside the basic ASCII range. Wide characters provide a way to represent these characters.

* **Example Scenarios:** Displaying localized text in UI elements, handling user input in different languages, storing internationalized data.

**6. Dynamic Linking:**

This requires understanding how shared libraries (`.so` files) work on Android.

* **SO Layout:** I described a typical layout with `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), and `.dynamic` (linking information) sections.
* **Linking Process:**  The dynamic linker resolves symbols at runtime. I outlined the steps: loading libraries, resolving symbols using the `.dynsym` and `.hash` tables, and performing relocations.

**7. Common Errors:**

Thinking about common mistakes developers make when working with wide characters is important.

* **Mixing narrow and wide strings:**  A classic error.
* **Incorrect buffer sizes:**  Wide characters can occupy more than one byte, so using byte-based length calculations can be wrong.
* **Locale issues:**  Not setting the locale correctly can lead to incorrect conversions and comparisons.
* **Forgetting the null terminator:**  Wide character strings, like regular C strings, need a null terminator.

**8. Tracing the Call Stack (Android Framework/NDK):**

This involves understanding how a high-level Android operation might eventually call a `wchar.h` function.

* **Android Framework:**  Starts with Java code (e.g., `TextView.setText()`), goes down to native code through JNI, and potentially uses Bionic functions for text rendering or manipulation.
* **NDK:** Developers directly use C/C++ code, so calling these functions is more direct.
* **Frida Hook:**  I provided `Interceptor.attach` examples to show how to hook these functions and inspect their arguments and return values.

**9. Structuring the Response:**

Organizing the information clearly is crucial. I used headings and subheadings to structure the answer logically, addressing each part of the request.

**10. Language and Tone:**

The request specified a Chinese response, so the language was naturally Chinese. The tone aimed to be informative and helpful, providing explanations and examples.

**Self-Correction/Refinement during the process:**

* Initially, I might have just listed the functions without grouping them. Recognizing the patterns and grouping them makes the explanation clearer.
* For the dynamic linking section, I made sure to explain the key components and the overall process, rather than just stating facts.
* When explaining common errors, I tried to provide concrete examples rather than just listing abstract concepts.
* I ensured the Frida examples were practical and demonstrated how to hook functions with different argument types.

By following these steps, the goal is to provide a comprehensive and understandable explanation of the `wchar.h` header file within the context of Android.
这个目录 `bionic/libc/include/wchar.handroid` 下的源代码文件 `wchar.h` 是 Android Bionic C 库的一部分，它定义了用于处理**宽字符 (wide character)** 的函数和类型。宽字符是一种可以表示更多字符集的字符类型，例如包含 Unicode 字符的文本。

**功能列举:**

这个头文件主要定义了以下几个方面的功能：

1. **宽字符 I/O:**  处理宽字符的输入和输出，类似于 `stdio.h` 中面向窄字符的函数。
   - 从/向文件读写宽字符：`fwprintf`, `fwscanf`, `fgetwc`, `fgetws`, `fputwc`, `fputws`, `getwc`, `getwchar`, `putwc`, `putwchar`, `ungetwc`。
   - 格式化宽字符输出到缓冲区：`swprintf`, `vswprintf`, `swscanf`, `vswscanf`。
   - 格式化宽字符输出到标准输出：`wprintf`, `vwprintf`, `wscanf`, `vwscanf`。
   - 打开宽字符内存流：`open_wmemstream`。

2. **宽字符串操作:**  提供操作宽字符串的各种函数，类似于 `string.h` 中面向窄字符串的函数。
   - 复制宽字符串：`wcscpy`, `wcpncpy`, `wcpcpy`, `wmemcpy`, `wmempcpy`, `wmemmove`, `wcsdup`, `wcslcpy`, `wcslcat`。
   - 连接宽字符串：`wcscat`, `wcsncat`。
   - 比较宽字符串：`wcscmp`, `wcsncmp`, `wcscasecmp`, `wcsncasecmp`, `wmemcmp`, `wcscoll`, `wcscoll_l`。
   - 查找宽字符串中的字符或子串：`wcschr`, `wcsrchr`, `wcspbrk`, `wcsstr`, `wmemchr`。
   - 获取宽字符串的长度：`wcslen`, `wcsnlen`。
   - 获取宽字符串中不属于指定字符集的字符的起始位置：`wcscspn`。
   - 获取宽字符串中属于指定字符集的字符的起始位置：`wcsspn`。
   - 将宽字符串转换为 `double`, `float`, `long`, `long long`, `unsigned long`, `unsigned long long`: `wcstod`, `wcstof`, `wcstol`, `wcstoll`, `wcstoul`, `wcstoull`，以及其带 locale 的版本。
   - 将宽字符串分割成 token：`wcstok`。
   - 转换宽字符串表示为适合排序的字符串：`wcsxfrm`, `wcsxfrm_l`。

3. **宽字符和多字节字符之间的转换:**  用于在宽字符和多字节字符 (通常是 UTF-8) 之间进行转换。
   - 单个字符转换：`btowc`, `wctob`。
   - 宽字符到多字节字符的转换：`wcrtomb`, `wcsrtombs`, `wcsnrtombs`, `wcsrtombs_l`。
   - 多字节字符到宽字符的转换：`mbrlen`, `mbrtowc`, `mbsrtowcs`, `mbsnrtowcs`, `mbsrtowcs_l`, `mbsinit`。

4. **其他宽字符相关功能:**
   - 获取字符的宽度（在终端中占用的列数）：`wcwidth`, `wcswidth`。
   - 设置宽/窄字符流的模式：`fwide`。
   - 格式化日期和时间为宽字符串：`wcsftime`, `wcsftime_l`。

**与 Android 功能的关系及举例说明:**

由于 Bionic 是 Android 的 C 库，`wchar.h` 中定义的函数在 Android 系统和应用程序的很多地方都有应用，主要与**国际化 (Internationalization, i18n)** 和**本地化 (Localization, L10n)** 相关。

* **支持多种语言:** Android 需要支持全球各种语言，这些语言的字符集往往超出 ASCII 的范围。宽字符提供了一种统一的方式来表示这些字符。例如，显示中文、日文、韩文等字符就需要使用宽字符。
* **用户界面 (UI) 文本显示:** Android Framework 中的文本显示组件 (例如 `TextView`, `EditText`) 在底层会使用 Bionic 提供的宽字符函数来处理和渲染文本内容。
* **文件系统操作:** 虽然 Android 的文件路径通常是 UTF-8 编码的，但在某些内部处理或与旧系统的交互中，可能涉及到宽字符表示的文件名。
* **NDK 开发:**  使用 Native Development Kit (NDK) 进行原生开发的开发者可以使用 `wchar.h` 中定义的函数来处理宽字符，例如处理用户输入的文本、进行国际化的文本处理等。

**举例说明:**

假设一个 Android 应用需要显示用户设置的语言名称。语言名称可能是英文 "English"，也可能是中文 "中文"。

1. **Framework 层:**  Android Framework 可能会从资源文件中读取本地化的语言名称，这些名称通常以 UTF-8 编码存储。
2. **JNI 调用:** 当需要将这些语言名称传递给 Native 代码 (通过 NDK) 进行处理或显示时，可能会涉及到从 UTF-8 到宽字符的转换。
3. **Native 代码 (C/C++)**: 在 Native 代码中，可以使用 `mbsrtowcs` 函数将 UTF-8 编码的多字节字符串转换为宽字符串 (`wchar_t*`)，然后可以使用 `wprintf` 或其他宽字符输出函数进行显示，或者使用 `wcslen`, `wcscmp` 等函数进行处理。

**详细解释每一个 libc 函数的功能是如何实现的:**

由于 `wchar.h` 只是头文件，它定义了函数的接口，具体的实现位于 Bionic 库的源文件中 (通常是 `.c` 文件)。这里我们只能给出这些函数的功能描述和大致的实现思路。

**通用实现思路：**

* **I/O 函数:**  底层的宽字符 I/O 函数通常会调用底层的字节流 I/O 函数 (如 `read`, `write`)，并在读写过程中处理字符编码的转换。例如，`fwprintf` 可能会将宽字符串转换为多字节字符串 (根据当前的 locale) 后写入文件。
* **字符串操作函数:**  这些函数通常会遍历宽字符串中的每个 `wchar_t` 单元进行操作。例如，`wcslen` 会遍历字符串直到遇到空宽字符 (`\0`)。`wcscmp` 会逐个比较两个宽字符串的 `wchar_t` 值。
* **转换函数:**  这些函数会根据当前的 locale 信息进行字符编码的转换。`mbsrtowcs` 需要知道输入多字节字符串的编码，并将其转换为目标宽字符编码。
* **Locale 支持:**  许多带有 `_l` 后缀的函数 (例如 `wcscoll_l`) 允许指定 locale，从而实现与语言文化相关的操作，例如不同语言的字符串排序规则不同，`wcscoll_l` 可以根据指定的 locale 进行排序比较。

**动态链接的功能，对应的 so 布局样本，以及链接的处理过程:**

`wchar.h` 本身是头文件，不涉及动态链接。但是，它声明的函数的实现位于 Bionic 库的共享对象 (`.so`) 文件中，例如 `libc.so`。应用程序需要通过动态链接器来使用这些函数。

**SO 布局样本 (`libc.so` 简略示意):**

```
libc.so:
    .text          # 代码段，包含函数指令
        btowc: ...
        fwprintf: ...
        wcscmp: ...
        ...
    .data          # 初始化数据段，包含全局变量等
        ...
    .rodata        # 只读数据段，包含字符串常量等
        ...
    .bss           # 未初始化数据段
        ...
    .dynsym        # 动态符号表，包含导出的符号 (函数名、变量名等)
        btowc
        fwprintf
        wcscmp
        ...
    .dynstr        # 动态字符串表，包含符号表中符号的字符串形式
        btowc
        fwprintf
        wcscmp
        ...
    .plt           # Procedure Linkage Table，过程链接表，用于延迟绑定
    .got           # Global Offset Table，全局偏移表，用于存储全局变量和函数的地址
    .hash          # 符号哈希表，用于快速查找符号
    ...
```

**链接的处理过程:**

1. **编译时:**  编译器遇到 `wchar.h` 中声明的函数时，会生成对这些函数的外部引用。
2. **链接时:**  静态链接器在构建可执行文件或共享库时，会记录下这些未解析的符号。
3. **运行时:**
   - 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会被加载。
   - 动态链接器会加载应用程序依赖的共享库，包括 `libc.so`。
   - **符号查找:** 当应用程序调用 `wchar.h` 中声明的函数时，动态链接器会根据函数名在 `libc.so` 的 `.dynsym` (动态符号表) 中查找对应的符号。`.hash` 表可以加速查找过程。
   - **重定位:**  一旦找到符号，动态链接器会更新应用程序的 `.got` (全局偏移表) 中的条目，使其指向 `libc.so` 中对应函数的实际地址。这被称为**重定位 (Relocation)**。
   - **延迟绑定:**  为了提高启动速度，Android 使用**延迟绑定 (Lazy Binding)**。这意味着在函数第一次被调用时才会进行符号查找和重定位。`.plt` (过程链接表) 中的代码会负责在第一次调用时跳转到动态链接器进行解析，之后直接跳转到函数的实际地址。

**假设输入与输出 (逻辑推理):**

以 `wcslen` 函数为例：

**假设输入:**  一个指向以 null 宽字符结尾的宽字符串的指针 `__s`。
**预期输出:**  该宽字符串中宽字符的数量，不包括 null 宽字符。

**示例:**

```c
#include <wchar.h>
#include <stdio.h>

int main() {
    wchar_t str[] = L"你好，世界";
    size_t len = wcslen(str);
    printf("宽字符串的长度是: %zu\n", len); // 预期输出: 5
    return 0;
}
```

**用户或编程常见的使用错误:**

1. **混合使用窄字符和宽字符函数:**  例如，将宽字符串传递给 `strlen` 函数，或者将窄字符串传递给 `wcslen` 函数，会导致错误或不可预测的行为。
   ```c
   char narrow_str[] = "hello";
   wchar_t wide_str[] = L"你好";
   size_t len1 = strlen(wide_str); // 错误: 可能会读取到非 null 字节，导致长度计算错误
   size_t len2 = wcslen(narrow_str); // 错误: 窄字符串会被解释为宽字符，导致读取越界或错误结果
   ```

2. **缓冲区溢出:**  在使用宽字符字符串复制或连接函数时，如果没有为目标缓冲区分配足够的空间来容纳源字符串，可能会导致缓冲区溢出。
   ```c
   wchar_t dest[5];
   wchar_t src[] = L"这是一个很长的字符串";
   wcscpy(dest, src); // 错误: dest 缓冲区太小，会导致溢出
   ```

3. **字符编码问题:**  在宽字符和多字节字符之间转换时，如果没有正确设置或理解 locale，可能会导致字符转换错误或乱码。
   ```c
   #include <locale.h>
   #include <stdlib.h>

   int main() {
       setlocale(LC_ALL, "en_US.UTF-8"); // 设置 locale
       wchar_t wstr[] = L"你好";
       char mbs[10];
       wcstombs(mbs, wstr, sizeof(mbs)); // 如果 locale 设置不当，转换可能出错
       return 0;
   }
   ```

4. **忘记空宽字符终止符:**  宽字符串也需要以空宽字符 (`\0`) 结尾。如果忘记添加，会导致字符串操作函数读取超出预期的范围。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `wchar.h` 函数的调用路径 (示例，以显示文本为例):**

1. **Java 代码:**  在 Android Framework 的 Java 层，例如 `TextView` 组件调用 `setText()` 方法来设置显示的文本。
2. **Native 代码 (通过 JNI):** `TextView` 的 `setText()` 方法最终会调用到 Native 代码，通常涉及到 Skia 图形库进行文本渲染。
3. **Skia 库:** Skia 库是 Android 用于 2D 图形渲染的核心库，它使用 C++ 实现。
4. **Bionic 库调用:** Skia 库在处理文本时，可能会调用 Bionic 库中与宽字符相关的函数，例如：
   - **字符转换:**  将 UTF-8 编码的文本转换为宽字符以便进行内部处理 (`mbsrtowcs`).
   - **文本测量:**  计算宽字符串的宽度以便进行布局 (`wcswidth`).
   - **字符串操作:**  进行字符串的复制、比较等操作 (`wcscpy`, `wcscmp`).

**NDK 直接调用:**

使用 NDK 进行开发的应用程序可以直接调用 `wchar.h` 中声明的函数，只需包含相应的头文件。

**Frida Hook 示例:**

假设我们要 hook `wcslen` 函数，观察传递给它的宽字符串以及返回的长度。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(__file__))
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
        session = frida.attach(pid)
    except ValueError:
        process_name = sys.argv[1]
        session = frida.attach(process_name)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "wcslen"), {
        onEnter: function(args) {
            var ws = Memory.readUtf16String(args[0]);
            console.log("[wcslen] Input wide string: " + ws);
            this.ws = ws; // 保存宽字符串，在 onLeave 中使用
        },
        onLeave: function(retval) {
            console.log("[wcslen] Length of '" + this.ws + "' is: " + retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Running, press Ctrl+C to stop")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `hook_wcslen.py`。
2. 确保已安装 Frida 和 frida-tools。
3. 找到你想要 hook 的 Android 进程的名称或 PID。
4. 运行命令：`python hook_wcslen.py <进程名称或PID>`

**Frida Hook 解释:**

* `Interceptor.attach`: 用于 hook 指定地址的函数。
* `Module.findExportByName("libc.so", "wcslen")`: 查找 `libc.so` 中导出的 `wcslen` 函数的地址。
* `onEnter`: 在 `wcslen` 函数被调用时执行。
    - `args[0]`:  `wcslen` 的第一个参数，即指向宽字符串的指针。
    - `Memory.readUtf16String(args[0])`: 从内存中读取宽字符串 (UTF-16 编码)。
    - `this.ws = ws`: 将宽字符串保存在 `this` 上，以便在 `onLeave` 中访问。
* `onLeave`: 在 `wcslen` 函数执行完毕即将返回时执行。
    - `retval`: `wcslen` 函数的返回值。

通过这个 Frida 脚本，你可以动态地观察应用程序调用 `wcslen` 函数时的输入和输出，从而调试宽字符相关的逻辑。你可以类似地 hook 其他 `wchar.h` 中声明的函数，以理解 Android 系统或应用如何使用它们。

Prompt: 
```
这是目录为bionic/libc/include/wchar.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _WCHAR_H_
#define _WCHAR_H_

#include <sys/cdefs.h>
#include <stdio.h>

#include <stdarg.h>
#include <stddef.h>
#include <time.h>
#include <xlocale.h>

#include <bits/bionic_multibyte_result.h>
#include <bits/mbstate_t.h>
#include <bits/wchar_limits.h>
#include <bits/wctype.h>

__BEGIN_DECLS

wint_t btowc(int __ch);
int fwprintf(FILE* _Nonnull __fp, const wchar_t* _Nonnull __fmt, ...);
int fwscanf(FILE* _Nonnull __fp, const wchar_t* _Nonnull __fmt, ...);
wint_t fgetwc(FILE* _Nonnull __fp);
wchar_t* _Nullable fgetws(wchar_t* _Nonnull __buf, int __size, FILE* _Nonnull __fp);
wint_t fputwc(wchar_t __wc, FILE* _Nonnull __fp);
int fputws(const wchar_t* _Nonnull __s, FILE* _Nonnull __fp);
int fwide(FILE* _Nonnull __fp, int __mode);
wint_t getwc(FILE* _Nonnull __fp);
wint_t getwchar(void);
int mbsinit(const mbstate_t* _Nullable __ps);
size_t mbrlen(const char* _Nullable __s, size_t __n, mbstate_t* _Nullable __ps);
size_t mbrtowc(wchar_t* _Nullable __buf, const char* _Nullable __s, size_t __n, mbstate_t* _Nullable __ps);
size_t mbsrtowcs(wchar_t* _Nullable __dst, const char* _Nullable * _Nonnull __src, size_t __dst_n, mbstate_t* _Nullable __ps);
size_t mbsrtowcs_l(wchar_t* _Nullable __dst, const char* _Nullable * _Nonnull __src, size_t __dst_n, mbstate_t* _Nullable __ps, locale_t _Nonnull __l) __RENAME(mbsrtowcs);
size_t mbsnrtowcs(wchar_t* _Nullable __dst, const char* _Nullable * _Nullable  __src, size_t __src_n, size_t __dst_n, mbstate_t* _Nullable __ps);
wint_t putwc(wchar_t __wc, FILE* _Nonnull __fp);
wint_t putwchar(wchar_t __wc);
int swprintf(wchar_t* _Nonnull __buf, size_t __n, const wchar_t* _Nonnull __fmt, ...);
int swscanf(const wchar_t* _Nonnull __s, const wchar_t* _Nonnull __fmt, ...);
wint_t ungetwc(wint_t __wc, FILE* _Nonnull __fp);
int vfwprintf(FILE* _Nonnull __fp, const wchar_t* _Nonnull __fmt, va_list __args);
int vfwscanf(FILE* _Nonnull __fp, const wchar_t* _Nonnull __fmt, va_list __args);
int vswprintf(wchar_t* _Nonnull __buf, size_t __n, const wchar_t* _Nonnull __fmt, va_list __args);
int vswscanf(const wchar_t* _Nonnull __s, const wchar_t* _Nonnull __fmt, va_list __args);
int vwprintf(const wchar_t* _Nonnull __fmt, va_list __args);
int vwscanf(const wchar_t* _Nonnull __fmt, va_list __args);
wchar_t* _Nonnull wcpcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src);
wchar_t* _Nonnull wcpncpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
size_t wcrtomb(char* _Nullable __buf, wchar_t __wc, mbstate_t* _Nullable __ps);
int wcscasecmp(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs);

#if __BIONIC_AVAILABILITY_GUARD(23)
int wcscasecmp_l(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, locale_t _Nonnull __l) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

wchar_t* _Nonnull wcscat(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src);
wchar_t* _Nullable wcschr(const wchar_t * _Nonnull __s, wchar_t __wc);
int wcscmp(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs);
int wcscoll(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs);
wchar_t* _Nonnull wcscpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src);
size_t wcscspn(const wchar_t* _Nonnull __s, const wchar_t* _Nonnull __accept);
size_t wcsftime(wchar_t* _Nonnull __buf, size_t __n, const wchar_t* _Nullable __fmt, const struct tm* _Nonnull __tm);

#if __BIONIC_AVAILABILITY_GUARD(28)
size_t wcsftime_l(wchar_t* _Nonnull __buf, size_t __n, const wchar_t* _Nullable __fmt, const struct tm* _Nonnull __tm, locale_t _Nonnull __l) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

size_t wcslen(const wchar_t* _Nonnull __s);
int wcsncasecmp(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, size_t __n);

#if __BIONIC_AVAILABILITY_GUARD(23)
int wcsncasecmp_l(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, size_t __n, locale_t _Nonnull __l) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

wchar_t* _Nonnull wcsncat(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
int wcsncmp(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, size_t __n);
wchar_t* _Nonnull wcsncpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
size_t wcsnrtombs(char* _Nullable __dst, const wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __src, size_t __src_n, size_t __dst_n, mbstate_t* _Nullable __ps);
wchar_t* _Nullable wcspbrk(const wchar_t* _Nonnull __s, const wchar_t* _Nonnull __accept);
wchar_t* _Nullable wcsrchr(const wchar_t* _Nonnull __s, wchar_t __wc);
size_t wcsrtombs(char* _Nullable __dst, const wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __src, size_t __dst_n, mbstate_t* _Nullable __ps);
size_t wcsrtombs_l(char* _Nullable __dst, const wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __src, size_t __dst_n, mbstate_t* _Nullable __ps, locale_t _Nonnull __l) __RENAME(wcsrtombs);
size_t wcsspn(const wchar_t* _Nonnull __s, const wchar_t* _Nonnull __accept);
wchar_t* _Nullable wcsstr(const wchar_t* _Nonnull __haystack, const wchar_t* _Nonnull __needle);
double wcstod(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr);
double wcstod_l(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, locale_t _Nonnull __l) __RENAME(wcstod);
float wcstof(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr);
float wcstof_l(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, locale_t _Nonnull __l) __RENAME(wcstof);
wchar_t* _Nullable wcstok(wchar_t* _Nullable __s, const wchar_t* _Nonnull __delimiter, wchar_t* _Nonnull * _Nonnull __ptr);
long wcstol(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, int __base);
long wcstol_l(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, int __base, locale_t _Nonnull __l) __RENAME(wcstol);
long long wcstoll(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, int __base);
long double wcstold(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr);
unsigned long wcstoul(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, int __base);
unsigned long wcstoul_l(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, int __base, locale_t _Nonnull __l) __RENAME(wcstoul);
unsigned long long wcstoull(const wchar_t* _Nonnull __s, wchar_t* __BIONIC_COMPLICATED_NULLNESS * _Nullable __end_ptr, int __base);
int wcswidth(const wchar_t* _Nonnull __s, size_t __n);
size_t wcsxfrm(wchar_t* __BIONIC_COMPLICATED_NULLNESS __dst, const wchar_t* _Nonnull __src, size_t __n);
int wctob(wint_t __wc);
int wcwidth(wchar_t __wc);
wchar_t* _Nullable wmemchr(const wchar_t* _Nonnull __src, wchar_t __wc, size_t __n);
int wmemcmp(const wchar_t* _Nullable __lhs, const wchar_t* _Nullable __rhs, size_t __n);
wchar_t* _Nonnull wmemcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
#if defined(__USE_GNU)

#if __BIONIC_AVAILABILITY_GUARD(23)
wchar_t* _Nonnull wmempcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

#endif
wchar_t* _Nonnull wmemmove(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
wchar_t* _Nonnull wmemset(wchar_t* _Nonnull __dst, wchar_t __wc, size_t __n);
int wprintf(const wchar_t* _Nonnull __fmt, ...);
int wscanf(const wchar_t* _Nonnull __fmt, ...);

long long wcstoll_l(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, int __base, locale_t _Nonnull __l);
unsigned long long wcstoull_l(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, int __base, locale_t _Nonnull __l);
long double wcstold_l(const wchar_t* _Nonnull __s, wchar_t* _Nullable * _Nullable __end_ptr, locale_t _Nonnull __l);

int wcscoll_l(const wchar_t* _Nonnull __lhs, const wchar_t* _Nonnull __rhs, locale_t _Nonnull __l) __attribute_pure__;
size_t wcsxfrm_l(wchar_t* __BIONIC_COMPLICATED_NULLNESS __dst, const wchar_t* _Nonnull __src, size_t __n, locale_t _Nonnull __l);
size_t wcslcat(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);
size_t wcslcpy(wchar_t* _Nonnull __dst, const wchar_t* _Nonnull __src, size_t __n);


#if __BIONIC_AVAILABILITY_GUARD(23)
FILE* _Nullable open_wmemstream(wchar_t* _Nonnull * _Nonnull __ptr, size_t* _Nonnull  __size_ptr) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

wchar_t* _Nullable wcsdup(const wchar_t* _Nonnull __s);
size_t wcsnlen(const wchar_t* _Nonnull __s, size_t __n);

__END_DECLS

#endif

"""

```