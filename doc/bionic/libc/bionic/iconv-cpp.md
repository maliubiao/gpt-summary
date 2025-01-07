Response:
Let's break down the thought process for answering the prompt about `bionic/libc/bionic/iconv.cpp`.

**1. Understanding the Core Request:**

The central request is to understand the functionality of this specific `iconv.cpp` file within the Android Bionic library. It's not about the general `iconv` API, but this *particular implementation*. The prompt also asks for connections to Android functionality, detailed explanations of libc functions within the file, dynamic linker aspects, usage errors, and how to reach this code from higher levels.

**2. Initial Scan and Keyword Identification:**

I started by reading through the code, looking for key functions and data structures:

* **`iconv_open`, `iconv`, `iconv_close`:** These are the standard `iconv` API functions, indicating the core purpose of the file.
* **`Encoding` enum:**  This tells me the supported character encodings.
* **`Mode` enum:** This points to how the conversion handles errors or incompatible characters (error, ignore, translit).
* **`__iconv_t` struct:** This is the internal representation of the conversion state.
* **`__match_encoding`, `__parse_encoding`:** These are helper functions for processing encoding names.
* **`GetNext`, `Convert`, `Emit`, `Done`:** These are internal methods within `__iconv_t` that implement the conversion logic.
* **`mbrtoc32`, `c32rtomb`:** These are standard C library functions related to multi-byte character conversion.
* **Endianness-related logic (`__swap16`, `__swap32`, `In16`, `In32`, `Out16`, `Out32`):**  Indicates handling of different byte orders for encodings like UTF-16 and UTF-32.

**3. Mapping to Prompt Requirements:**

Now, I systematically addressed each part of the prompt:

* **功能 (Functionality):** The core functionality is clearly character encoding conversion. The code explicitly lists supported encodings. I noted the limited set of encodings, as highlighted in the comment about ICU4C.
* **与 Android 功能的关系 (Relationship with Android):** Bionic is Android's C library. Therefore, `iconv` is used by Android components (framework, apps) that need character encoding conversion. Examples include handling text input, network communication, and file I/O. I specifically mentioned NDK, as it's a common entry point for developers using these low-level APIs.
* **libc 函数的功能实现 (Implementation of libc functions):** I focused on the usage of standard C library functions *within this specific `iconv.cpp`*. I explained `mbrtoc32` and `c32rtomb` in detail, as they are central to the UTF-8 handling. I also mentioned `memcpy`, `memset`, `strcmp`, `strstr`, `tolower`, `isalnum`, and the endianness functions.
* **dynamic linker 功能 (Dynamic linker functionality):** This was a key part of the request. I explained that while this *specific* file doesn't directly *implement* dynamic linking, it's *part* of a library (`libc.so`) that *is* loaded by the dynamic linker. I provided a basic `libc.so` layout and explained the linking process (symbol resolution, relocation). The crucial point is that `iconv` functions are *symbols* within `libc.so`.
* **逻辑推理 (Logical reasoning):** I chose to illustrate the core conversion logic with a simple UTF-8 to UTF-16-LE example. This helped to visualize the flow of data and the role of the `__iconv_t` structure.
* **用户或编程常见的使用错误 (Common usage errors):** I considered typical mistakes developers make with `iconv`, such as incorrect encoding names, buffer overflows, and forgetting to close the converter.
* **Android framework or NDK 如何到达这里 (How Android reaches this code):** I traced the call flow from a high-level Android framework component (like a `TextView`) down to the NDK and then to the `iconv` functions in `libc.so`. This involved explaining the layers of abstraction.
* **Frida hook 示例 (Frida hook example):**  I provided a basic Frida script targeting `iconv` to demonstrate how to intercept and observe its execution, logging arguments and return values. This is a practical way to debug and understand the function's behavior.

**3. Structuring the Answer:**

I organized the answer according to the prompt's requests, using clear headings and bullet points to improve readability. I tried to balance technical detail with clarity, explaining concepts without getting bogged down in overly specific implementation details. The use of code examples (even short ones) helps to illustrate the points.

**4. Refinement and Review:**

After drafting the initial answer, I reviewed it to ensure accuracy, completeness, and clarity. I checked for any logical inconsistencies or missing information. For example, I made sure to emphasize the *limitations* of this particular `iconv` implementation compared to a full ICU4C-based solution. I also made sure the Frida example was functional and understandable.

This iterative process of understanding, mapping, structuring, and refining allowed me to address the complex requirements of the prompt in a comprehensive and informative way. The key was to treat each part of the prompt as a specific question and then provide targeted information.
这个文件 `bionic/libc/bionic/iconv.cpp` 是 Android Bionic 库中 `iconv` 接口的一个**简化实现**。它的主要功能是提供基本的字符编码转换能力。 由于 Android 更倾向于使用 ICU4C 库进行更全面的国际化支持，Bionic 中的 `iconv` 实现相对简单，仅支持几种常见的编码格式。

下面详细列举它的功能和相关说明：

**1. 功能：基本的字符编码转换**

*   **支持的编码格式:**  这个实现支持以下几种字符编码格式：
    *   `US-ASCII`
    *   `UTF-8`
    *   `UTF-16LE` (Little Endian)
    *   `UTF-16BE` (Big Endian)
    *   `UTF-32LE` (Little Endian)
    *   `UTF-32BE` (Big Endian)
    *   `WCHAR_T` (与平台相关的宽字符类型，在 Android 上通常是 UTF-32)
*   **转换操作:**  它提供 `iconv_open` 用于打开一个转换描述符，`iconv` 用于执行实际的转换，以及 `iconv_close` 用于关闭转换描述符。
*   **错误处理模式:**  它支持几种处理无法转换字符或非法序列的模式：
    *   `ERROR` (默认):  遇到错误返回 -1 并设置 `errno` 为 `EILSEQ`。
    *   `IGNORE`:  忽略无法转换的字符。
    *   `TRANSLIT`:  尝试将无法转换的字符转换为相似的字符（当前实现中是将所有无法转换的字符替换为 `'?'`）。

**2. 与 Android 功能的关系及举例说明**

尽管 Bionic 中的 `iconv` 实现相对简单，但它仍然在 Android 的一些底层组件中被使用，尤其是在不需要 ICU4C 提供的全部功能的场景下。

*   **系统工具:**  一些底层的系统工具，例如可能需要处理不同编码的文本文件，可能会使用 `iconv` 进行基本的转换。
*   **低级 I/O 操作:**  某些处理文本数据的低级操作，例如从文件或网络读取数据时，可能会用到 `iconv` 进行编码转换。
*   **NDK 开发:**  使用 NDK 进行原生开发的开发者可以直接调用 `iconv` 相关的函数来进行字符编码转换。

**举例说明:**

假设一个 NDK 应用需要将一个 UTF-8 编码的字符串转换为 UTF-16LE 编码，可以使用以下步骤：

```c++
#include <iconv.h>
#include <string>
#include <vector>

std::vector<char> utf8_to_utf16le(const std::string& utf8_str) {
    iconv_t cd = iconv_open("UTF-16LE", "UTF-8");
    if (cd == reinterpret_cast<iconv_t>(-1)) {
        // 处理错误
        return {};
    }

    size_t inbytesleft = utf8_str.size();
    char* inbuf = const_cast<char*>(utf8_str.data());
    size_t outbytesleft = utf8_str.size() * 4 + 2; // 预估输出缓冲区大小，UTF-16 最多是 UTF-8 的两倍，加 2 个字节的 BOM (虽然这个实现可能不处理 BOM)
    std::vector<char> utf16le_buf(outbytesleft);
    char* outbuf = utf16le_buf.data();

    size_t result = iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    if (result == (size_t)-1) {
        // 处理错误
        iconv_close(cd);
        return {};
    }

    iconv_close(cd);
    utf16le_buf.resize(utf16le_buf.size() - outbytesleft); // 调整缓冲区大小
    return utf16le_buf;
}
```

**3. 详细解释每一个 libc 函数的功能是如何实现的**

*   **`iconv_open(const char* __dst_encoding, const char* __src_encoding)`:**
    *   **功能:**  创建一个用于字符编码转换的描述符 (`iconv_t`)。
    *   **实现:**
        1. 分配一个 `__iconv_t` 结构体的内存。
        2. 调用内部函数 `__parse_encoding` 解析源编码 (`__src_encoding`) 和目标编码 (`__dst_encoding`) 的字符串，并将解析结果存储到 `__iconv_t` 结构体的 `src_encoding`、`dst_encoding` 和 `mode` 成员中。`__parse_encoding` 函数通过一系列字符串比较 (`__match_encoding`) 来识别编码格式，并处理像 `//IGNORE` 和 `//TRANSLIT` 这样的后缀来设置错误处理模式。
        3. 如果编码解析失败，则释放已分配的内存，设置 `errno` 为 `EINVAL`，并返回 `INVALID_ICONV_T`（即 `reinterpret_cast<iconv_t>(-1)`）。
        4. 如果解析成功，则返回指向新分配的 `__iconv_t` 结构体的指针。

*   **`size_t iconv(iconv_t __converter, char** __src_buf, size_t* __src_bytes_left, char** __dst_buf, size_t* __dst_bytes_left)`:**
    *   **功能:**  执行实际的字符编码转换。
    *   **实现:**
        1. 检查 `__converter` 是否是有效的描述符。如果无效，设置 `errno` 为 `EBADF` 并返回 -1。
        2. 如果 `__src_buf` 为 `nullptr`，则执行状态刷新操作（对于无状态的编码，这是一个空操作），返回 0。
        3. 调用 `__converter` 指向的 `__iconv_t` 对象的 `Convert` 方法来执行转换。
        4. **`__iconv_t::Convert` 方法的实现:**
            *   初始化转换状态，例如重置内部缓冲区和标志。
            *   在一个循环中，只要还有剩余的输入字节 (`*src_bytes_left > 0`)，就执行以下操作：
                *   调用 `GetNext()` 从输入缓冲区获取下一个 Unicode 代码点 (`wc`)。`GetNext()` 的实现根据 `src_encoding` 来解析多字节字符序列，例如 UTF-8 的 `mbrtoc32` 或 UTF-16 的字节序处理。如果遇到非法序列，则设置 `errno` 为 `EILSEQ`。
                *   调用 `Convert()` 将获取到的 Unicode 代码点转换为目标编码的字节序列，并存储到内部缓冲区 `buf` 中。`Convert()` 的实现根据 `dst_encoding` 来生成多字节字符序列，例如 UTF-8 的 `c32rtomb` 或 UTF-16 的字节序处理。如果无法转换，则设置 `errno` 为 `EILSEQ`。
                *   如果遇到 `EILSEQ` 错误，则根据 `mode` 的设置进行处理：
                    *   `ERROR`: 返回 -1。
                    *   `IGNORE`: 跳过当前字符，继续处理下一个字符。
                    *   `TRANSLIT`: 将当前字符替换为 `'?'`，然后继续转换。
                *   调用 `Emit()` 将内部缓冲区 `buf` 中的转换结果写入到输出缓冲区 (`__dst_buf`)。`Emit()` 会检查输出缓冲区是否有足够的空间，如果空间不足则设置 `errno` 为 `E2BIG`。
            *   循环结束后，调用 `Done()` 返回转换的最终状态，例如在 `TRANSLIT` 模式下返回替换的字符数，或在 `IGNORE` 模式下且发生忽略时返回 -1 并设置 `errno` 为 `EILSEQ`。

*   **`int iconv_close(iconv_t __converter)`:**
    *   **功能:**  关闭一个字符编码转换描述符，释放相关资源。
    *   **实现:**
        1. 检查 `__converter` 是否是有效的描述符。如果无效，设置 `errno` 为 `EBADF` 并返回 -1。
        2. 使用 `delete` 运算符释放 `__converter` 指向的 `__iconv_t` 结构体的内存。
        3. 返回 0 表示成功。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

`iconv.cpp` 本身是 `libc.so` 的一部分，它不直接涉及 dynamic linker 的功能，而是被 dynamic linker 加载和链接。

**`libc.so` 布局样本 (简化)**

```
ELF Header
...
Program Headers:
  LOAD ... R-X ... # 代码段
  LOAD ... R-- ... # 只读数据段
  LOAD ... RW- ... # 读写数据段
Dynamic Section:
  NEEDED        libm.so
  SONAME        libc.so
  SYMTAB        ...
  STRTAB        ...
  ...
Symbol Table (SYMTAB):
  ...
  iconv_open  (address in code section)
  iconv       (address in code section)
  iconv_close (address in code section)
  ...
String Table (STRTAB):
  ...
  iconv_open
  iconv
  iconv_close
  ...
Relocation Tables:
  ... (如果有外部符号引用需要重定位)
...
```

**链接的处理过程:**

1. **加载:** 当一个可执行文件或共享库依赖于 `libc.so` 时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载 `libc.so` 到进程的地址空间。
2. **符号解析:** 当程序调用 `iconv_open`、`iconv` 或 `iconv_close` 等函数时，dynamic linker 需要找到这些符号在 `libc.so` 中的地址。
3. **查找依赖:**  dynamic linker 读取可执行文件和共享库的 `Dynamic Section`，找到其依赖的共享库列表 (`NEEDED`)。
4. **加载依赖:**  dynamic linker 按照依赖关系加载所需的共享库，例如 `libm.so`。
5. **符号表查找:**  dynamic linker 在加载的共享库的符号表 (`SYMTAB`) 中查找被引用的符号。例如，当程序调用 `iconv_open` 时，linker 会在 `libc.so` 的符号表中查找名为 `iconv_open` 的符号，并找到其对应的地址。
6. **重定位:**  如果可执行文件或共享库中引用了来自 `libc.so` 的符号，dynamic linker 需要更新这些引用，使其指向 `libc.so` 中符号的实际加载地址。这通过 `Relocation Tables` 完成。例如，程序中调用 `iconv_open` 的指令可能包含一个占位符地址，linker 会将其替换为 `iconv_open` 在 `libc.so` 中的实际地址。
7. **绑定:**  在完成加载、符号解析和重定位后，程序就可以成功调用 `libc.so` 中提供的 `iconv` 相关函数了。

**5. 逻辑推理与假设输入输出**

**假设输入:**

*   源编码: "UTF-8"
*   目标编码: "UTF-16LE"
*   输入字符串 (UTF-8): "你好世界" (假设 UTF-8 编码为 `E4 BD A0 E5 A5 BD E4 B8 96 E7 95 8C`)

**逻辑推理:**

1. `iconv_open("UTF-16LE", "UTF-8")` 被调用，创建一个 `__iconv_t` 结构，设置 `src_encoding` 为 `UTF_8`，`dst_encoding` 为 `UTF_16_LE`，`mode` 为 `ERROR` (默认)。
2. `iconv` 被调用，传递输入缓冲区和输出缓冲区。
3. `__iconv_t::Convert` 方法被执行：
    *   读取输入缓冲区的第一个 UTF-8 字符 "你" (`E4 BD A0`)，`GetNext` 将其解析为 Unicode 代码点 `U+4F60`。
    *   `Convert` 将 `U+4F60` 转换为 UTF-16LE 编码 (`60 4F`)。
    *   `Emit` 将 `60 4F` 写入输出缓冲区。
    *   重复以上步骤处理 "好" (`E5 A5 BD` -> `U+597D` -> `7D 59`)，"世" (`E4 B8 96` -> `U+4E16` -> `16 4E`)，"界" (`E7 95 8C` -> `U+754C` -> `4C 75`)。

**假设输出 (UTF-16LE 字节序列):** `60 4F 7D 59 16 4E 4C 75`

**6. 用户或编程常见的使用错误**

*   **使用错误的编码名称:**  `iconv_open` 的编码名称字符串必须与支持的编码名称匹配，否则会返回错误。例如，将 "utf8" 误写成 "utf-8"。
*   **输出缓冲区过小:**  如果提供的输出缓冲区不足以容纳转换后的数据，`iconv` 会设置 `errno` 为 `E2BIG`。程序员需要预先估计或动态调整输出缓冲区的大小。
*   **忘记调用 `iconv_close`:**  打开的 `iconv_t` 描述符会占用资源，忘记关闭会导致资源泄漏。
*   **没有正确处理 `iconv` 的返回值:**  `iconv` 返回 `(size_t)-1` 表示发生错误，需要检查 `errno` 来确定具体的错误类型。
*   **假设编码是有状态的:**  这个简单的 `iconv` 实现是无状态的，但在其他 `iconv` 实现中，编码可能是有状态的，需要正确处理状态转换。
*   **在多线程环境中使用同一个 `iconv_t` 实例而不进行同步:**  `iconv_t` 结构体的内部状态可能会在 `iconv` 调用期间被修改，因此在多线程环境中使用需要进行适当的同步。

**7. 说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `iconv` 的路径 (示例):**

1. **Java 代码:**  Android Framework 中的 Java 代码，例如 `java.lang.String` 或处理文本显示的组件 (如 `TextView`)，在进行字符编码转换时可能会调用 NDK 中的相关方法。
2. **NDK (JNI):**  Java 代码通过 JNI (Java Native Interface) 调用到 Native 代码。例如，`java.lang.String` 内部可能使用 JNI 调用到 Bionic 库中的字符串处理函数。
3. **Bionic 库 (libc.so):**  Bionic 的 `libc.so` 实现了 `iconv` 接口。当 Native 代码需要进行字符编码转换时，就会调用 `iconv_open`、`iconv` 和 `iconv_close` 这些函数。

**NDK 直接调用 `iconv`:**

1. **NDK 应用代码:**  使用 NDK 开发的 C/C++ 应用可以直接包含 `<iconv.h>` 头文件，并调用 `iconv` 相关的函数。
2. **链接到 `libc.so`:**  在编译和链接 NDK 应用时，链接器会将应用链接到 `libc.so`，从而使得应用可以使用 `iconv` 提供的功能。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `iconv` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    var iconv_open_ptr = Module.findExportByName("libc.so", "iconv_open");
    var iconv_ptr = Module.findExportByName("libc.so", "iconv");
    var iconv_close_ptr = Module.findExportByName("libc.so", "iconv_close");

    if (iconv_open_ptr) {
        Interceptor.attach(iconv_open_ptr, {
            onEnter: function (args) {
                console.log("[iconv_open] source_encoding:", Memory.readUtf8String(args[1]), "dest_encoding:", Memory.readUtf8String(args[0]));
            },
            onLeave: function (retval) {
                console.log("[iconv_open] returning:", retval);
            }
        });
    }

    if (iconv_ptr) {
        Interceptor.attach(iconv_ptr, {
            onEnter: function (args) {
                var converter = args[0];
                var src_buf = args[1];
                var src_bytes_left = args[2];
                var dst_buf = args[3];
                var dst_bytes_left = args[4];

                var src_str = src_buf.isNull() ? "NULL" : Memory.readUtf8String(Memory.readPointer(src_buf), src_bytes_left.readU32());
                console.log("[iconv] converter:", converter, "src_buf:", src_buf, "src_bytes_left:", src_bytes_left, "dst_buf:", dst_buf, "dst_bytes_left:", dst_bytes_left);
                console.log("[iconv] src_string:", src_str);
            },
            onLeave: function (retval) {
                console.log("[iconv] returning:", retval);
            }
        });
    }

    if (iconv_close_ptr) {
        Interceptor.attach(iconv_close_ptr, {
            onEnter: function (args) {
                console.log("[iconv_close] converter:", args[0]);
            },
            onLeave: function (retval) {
                console.log("[iconv_close] returning:", retval);
            }
        });
    }
} else {
    console.log("Frida hook only supported on ARM architectures for this example.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `iconv_hook.js`)。
2. 使用 Frida 连接到目标 Android 进程：
    ```bash
    frida -U -f <package_name> -l iconv_hook.js --no-pause
    ```
    或者连接到正在运行的进程：
    ```bash
    frida -U <package_name> -l iconv_hook.js
    ```
3. 当目标应用调用 `iconv_open`, `iconv`, 或 `iconv_close` 时，Frida 会拦截这些调用并打印出相关的参数和返回值，从而帮助你调试和理解代码的执行流程。

这个 Frida 脚本会拦截 `iconv_open`，打印源编码和目标编码；拦截 `iconv`，打印转换器指针、输入输出缓冲区指针和长度，以及尝试读取输入字符串；拦截 `iconv_close`，打印转换器指针。通过这些信息，你可以观察到 Android Framework 或 NDK 应用在进行字符编码转换时是如何使用 `iconv` 接口的。

Prompt: 
```
这是目录为bionic/libc/bionic/iconv.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <iconv.h>

#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <uchar.h>

#include "private/bionic_mbstate.h"

#define INVALID_ICONV_T reinterpret_cast<iconv_t>(-1)

// Ideally we'd use icu4c but the API mismatch seems too great. So we just offer something
// equivalent to (but slightly easier to use for runs of text than) <uchar.h>. If you're
// here to add more encodings, consider working on finishing the icu4c NDK wrappers instead.
enum Encoding {
  US_ASCII,
  UTF_8,
  UTF_16_LE,
  UTF_16_BE,
  UTF_32_LE,
  UTF_32_BE,
  WCHAR_T,
};

enum Mode {
  ERROR,
  IGNORE,
  TRANSLIT,
};

// This matching is strange but true.
// See http://www.unicode.org/reports/tr22/#Charset_Alias_Matching.
static bool __match_encoding(const char* lhs, const char* rhs) {
  while (*lhs && *rhs) {
    // Skip non-alnum in lhs; "UTF-8", "UTF_8", "UTF8", "UTF 8" are all equivalent.
    // Also implement the "delete each 0 that is not preceded by a digit" rule.
    for (; *lhs; ++lhs) {
      if (isalnum(*lhs) && (*lhs != '0' || !isdigit(*(lhs + 1)))) break;
    }
    // Case doesn't matter either.
    if (tolower(*lhs) != tolower(*rhs)) break;
    ++lhs;
    ++rhs;
  }
  // As a special case we treat the GNU "//" extensions as end of string.
  if ((*lhs == '\0' || strstr(lhs, "//") == lhs) && *rhs == '\0') return true;
  return false;
}

static bool __parse_encoding(const char* s, Encoding* encoding, Mode* mode) {
  const char* suffix = strstr(s, "//");
  if (suffix) {
    if (!mode) return false;
    if (strcmp(suffix, "//IGNORE") == 0) {
      *mode = IGNORE;
    } else if (strcmp(suffix, "//TRANSLIT") == 0) {
      *mode = TRANSLIT;
    } else {
      return false;
    }
  }
  if (__match_encoding(s, "utf8")) {
    *encoding = UTF_8;
  } else if (__match_encoding(s, "ascii") || __match_encoding(s, "usascii")) {
    *encoding = US_ASCII;
  } else if (__match_encoding(s, "utf16le")) {
    *encoding = UTF_16_LE;
  } else if (__match_encoding(s, "utf16be")) {
    *encoding = UTF_16_BE;
  } else if (__match_encoding(s, "utf32le")) {
    *encoding = UTF_32_LE;
  } else if (__match_encoding(s, "utf32be")) {
    *encoding = UTF_32_BE;
  } else if (__match_encoding(s, "wchart")) {
    *encoding = WCHAR_T;
  } else {
    return false;
  }
  return true;
}

struct __iconv_t {
  Encoding src_encoding;
  Encoding dst_encoding;
  Mode mode;

  __iconv_t() : mode(ERROR) {
  }

  int Convert(char** src_buf0, size_t* src_bytes_left0, char** dst_buf0, size_t* dst_bytes_left0) {
    // Reset state.
    wc = 0;
    memset(&ps, 0, sizeof(ps));
    replacement_count = 0;
    ignored = false;
    src_buf = src_buf0;
    src_bytes_left = src_bytes_left0;
    dst_buf = dst_buf0;
    dst_bytes_left = dst_bytes_left0;

    while (*src_bytes_left > 0) {
      if (!GetNext() || !Convert()) return -1;
    }
    return Done();
  }

 private:
  char32_t wc;
  char buf[16];
  size_t src_bytes_used;
  size_t dst_bytes_used;
  mbstate_t ps;

  size_t replacement_count;
  bool ignored;

  char** src_buf;
  size_t* src_bytes_left;
  char** dst_buf;
  size_t* dst_bytes_left;

  bool GetNext() {
    errno = 0;
    switch (src_encoding) {
      case US_ASCII:
        wc = **src_buf;
        src_bytes_used = 1;
        if (wc > 0x7f) errno = EILSEQ;
        break;

      case UTF_8:
        src_bytes_used = mbrtoc32(&wc, *src_buf, *src_bytes_left, &ps);
        if (src_bytes_used == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
          break;  // EILSEQ already set.
        } else if (src_bytes_used == BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE) {
          errno = EINVAL;
          return false;
        }
        break;

      case UTF_16_BE:
      case UTF_16_LE: {
        if (*src_bytes_left < 2) {
          errno = EINVAL;
          return false;
        }
        bool swap = (src_encoding == UTF_16_BE);
        wc = In16(*src_buf, swap);
        // 0xd800-0xdbff: high surrogates
        // 0xdc00-0xdfff: low surrogates
        if (wc >= 0xd800 && wc <= 0xdfff) {
          if (wc >= 0xdc00) {  // Low surrogate before high surrogate.
            errno = EILSEQ;
            return false;
          }
          if (*src_bytes_left < 4) {
            errno = EINVAL;
            return false;
          }
          uint16_t hi = wc;
          uint16_t lo = In16(*src_buf + 2, swap);
          wc = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
          src_bytes_used = 4;
        }
        break;
      }

      case UTF_32_BE:
      case UTF_32_LE:
      case WCHAR_T:
        if (*src_bytes_left < 4) {
          errno = EINVAL;
          return false;
        }
        wc = In32(*src_buf, (src_encoding == UTF_32_BE));
        break;
    }

    if (errno == EILSEQ) {
      switch (mode) {
        case ERROR:
          return false;
        case IGNORE:
          *src_buf += src_bytes_used;
          *src_bytes_left -= src_bytes_used;
          ignored = true;
          return GetNext();
        case TRANSLIT:
          wc = '?';
          ++replacement_count;
          return true;
      }
    }
    return true;
  }

  bool Convert() {
    errno = 0;
    switch (dst_encoding) {
      case US_ASCII:
        buf[0] = wc;
        dst_bytes_used = 1;
        if (wc > 0x7f) errno = EILSEQ;
        break;

      case UTF_8:
        dst_bytes_used = c32rtomb(buf, wc, &ps);
        if (dst_bytes_used == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
          break;  // EILSEQ already set.
        } else if (dst_bytes_used == BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE) {
          errno = EINVAL;
          return false;
        }
        break;

      case UTF_16_BE:
      case UTF_16_LE: {
        bool swap = (dst_encoding == UTF_16_BE);
        if (wc < 0x10000) {  // BMP.
          Out16(buf, wc, swap);
        } else {  // Supplementary plane; output surrogate pair.
          wc -= 0x10000;
          char16_t hi = 0xd800 | (wc >> 10);
          char16_t lo = 0xdc00 | (wc & 0x3ff);
          Out16(buf + 0, hi, swap);
          Out16(buf + 2, lo, swap);
          dst_bytes_used = 4;
        }
      } break;

      case UTF_32_BE:
      case UTF_32_LE:
      case WCHAR_T:
        Out32(wc, (dst_encoding == UTF_32_BE));
        break;
    }

    if (errno == EILSEQ) {
      if (mode == IGNORE) {
        *src_buf += src_bytes_used;
        *src_bytes_left -= src_bytes_used;
        ignored = true;
        return true;
      } else if (mode == TRANSLIT) {
        wc = '?';
        ++replacement_count;
        return Convert();
      }
      return false;
    }

    return Emit();
  }

  uint16_t In16(const char* buf, bool swap) {
    const uint8_t* src = reinterpret_cast<const uint8_t*>(buf);
    uint16_t wc = (src[0]) | (src[1] << 8);
    if (swap) wc = __swap16(wc);
    src_bytes_used = 2;
    return wc;
  }

  uint32_t In32(const char* buf, bool swap) {
    const uint8_t* src = reinterpret_cast<const uint8_t*>(buf);
    uint32_t wc = (src[0]) | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
    if (swap) wc = __swap32(wc);
    src_bytes_used = 4;
    return wc;
  }

  void Out16(char* dst, char16_t ch, bool swap) {
    if (swap) ch = __swap16(ch);
    dst[0] = ch;
    dst[1] = ch >> 8;
    dst_bytes_used = 2;
  }

  void Out32(char32_t ch, bool swap) {
    if (swap) ch = __swap32(ch);
    buf[0] = ch;
    buf[1] = ch >> 8;
    buf[2] = ch >> 16;
    buf[3] = ch >> 24;
    dst_bytes_used = 4;
  }

  bool Emit() {
    if (dst_bytes_used > *dst_bytes_left) {
      errno = E2BIG;
      return false;
    }

    memcpy(*dst_buf, buf, dst_bytes_used);
    *src_buf += src_bytes_used;
    *src_bytes_left -= src_bytes_used;
    *dst_buf += dst_bytes_used;
    *dst_bytes_left -= dst_bytes_used;
    return true;
  }

  int Done() {
    if (mode == TRANSLIT) return replacement_count;
    if (ignored) {
      errno = EILSEQ;
      return -1;
    }
    return 0;
  }
};

iconv_t iconv_open(const char* __dst_encoding, const char* __src_encoding) {
  iconv_t result = new __iconv_t;
  if (!__parse_encoding(__src_encoding, &result->src_encoding, nullptr) ||
      !__parse_encoding(__dst_encoding, &result->dst_encoding, &result->mode)) {
    delete result;
    errno = EINVAL;
    return INVALID_ICONV_T;
  }
  return result;
}

size_t iconv(iconv_t __converter,
             char** __src_buf, size_t* __src_bytes_left,
             char** __dst_buf, size_t* __dst_bytes_left) {
  if (__converter == INVALID_ICONV_T) {
    errno = EBADF;
    return -1;
  }

  // Since none of our encodings are stateful, state flushing is a no-op.
  if (!__src_buf) return 0;

  return __converter->Convert(__src_buf, __src_bytes_left, __dst_buf, __dst_bytes_left);
}

int iconv_close(iconv_t __converter) {
  if (__converter == INVALID_ICONV_T) {
    errno = EBADF;
    return -1;
  }
  delete __converter;
  return 0;
}

"""

```