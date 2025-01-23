Response:
Let's break down the thought process for answering the user's request about `bionic/tests/ctype_test.cpp`.

**1. Understanding the Core Request:**

The user has provided a C++ test file and wants to understand its purpose and its relation to Android's Bionic library. The key elements to address are: functionality, relationship to Android, implementation details (especially of `libc` functions and dynamic linking), potential errors, and how it's invoked within the Android ecosystem.

**2. Initial Analysis of the Test File:**

* **File Type:**  The `#include <gtest/gtest.h>` immediately signals that this is a unit test file using the Google Test framework.
* **Purpose:** The filename `ctype_test.cpp` and the included header `<ctype.h>` strongly suggest that this file tests the character classification and conversion functions defined in the C standard library.
* **Test Structure:** The `TEST(ctype, function_name)` macros define individual test cases for various `ctype.h` functions (e.g., `isalnum`, `isalpha`, `tolower`, etc.).
* **Testing Logic:** Each test case iterates through a range of integer values (from -1 to 255) and uses `EXPECT_TRUE` and `EXPECT_FALSE` to assert the correctness of the `ctype` functions for different inputs. The `_l` suffixed functions suggest testing locale-aware versions, although in this specific test, they always use `LC_GLOBAL_LOCALE`.

**3. Addressing the Specific Questions:**

Now, let's tackle each part of the user's multi-faceted question:

* **Functionality:**  This is straightforward. The file tests the standard C library character handling functions. List each function being tested.

* **Relationship to Android:** Bionic *is* Android's C library. Therefore, these tests are directly testing the implementation of `ctype.h` functions within Bionic. Examples:  Any Android app using `isalpha()` is indirectly relying on the correctness of the Bionic implementation being tested here. Mention the NDK as the developer-facing interface.

* **`libc` Function Implementation:**  This requires a bit of generalization since the provided file *tests* the functions, but doesn't *implement* them. Focus on the common implementation strategies for `ctype.h` functions:
    * **Lookup Tables:** The historical and still common approach for basic ASCII character sets. Explain how it works (index by character value).
    * **Direct Comparison/Bitwise Operations:** For simple cases or optimization. Give examples from the test code itself (e.g., the `if` conditions).
    * **Locale Support:** Briefly explain how the `_l` versions might use locale data to handle different character sets. Acknowledge that this test uses `LC_GLOBAL_LOCALE`, simplifying the scenario.

* **Dynamic Linker:**  This is a trickier point based on the provided code *alone*. The `ctype_test.cpp` itself doesn't *directly* interact with the dynamic linker. However, the `ctype` functions reside within `libc.so`, which *is* loaded by the dynamic linker. Therefore:
    * **SO Layout:**  Describe a typical `libc.so` layout (sections like `.text`, `.data`, `.bss`, `.dynsym`, `.dynstr`). Emphasize that the `ctype` functions will be in the `.text` section.
    * **Linking Process:** Explain the basics of dynamic linking: compilation, creation of shared objects, the role of the dynamic linker in resolving symbols at runtime (using the PLT and GOT). Highlight that when a program calls `isalnum`, the dynamic linker has already linked it to the `isalnum` implementation in `libc.so`.

* **Logical Reasoning (Input/Output):** The test file *itself* embodies logical reasoning. For each test, the *input* is a character (represented as an integer), and the *output* is a boolean (whether the character satisfies the condition). Provide specific examples from the test cases.

* **User/Programming Errors:**  Focus on common mistakes when using `ctype` functions:
    * **Incorrect Range:**  Passing values outside the defined range (although the test explicitly covers this).
    * **Assuming ASCII:**  Not considering locale differences (even though these tests use the global locale).
    * **Misunderstanding `toascii`:** Explain its specific behavior.
    * **Using `_tolower` and `_toupper` incorrectly:**  Highlight their potential to mangle non-alphabetic characters.

* **Android Framework/NDK and Frida Hooking:**
    * **Framework:**  Start with a high-level Android application, mention the SDK, and explain how Java code might call native methods via JNI. These native methods could then use `ctype` functions.
    * **NDK:** Explain that NDK developers can directly use the C standard library, including `ctype.h`. Give a simple NDK code example.
    * **Frida Hooking:** Provide a concrete JavaScript Frida example that intercepts a call to `isalnum`. Explain how to set it up and what information can be observed.

**4. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Start with a concise summary of the file's purpose. Then, address each of the user's questions systematically.

**5. Refinement and Language:**

* **Clarity:** Use clear and concise language, avoiding jargon where possible or explaining it when necessary.
* **Accuracy:** Ensure the technical details are correct.
* **Completeness:** Try to address all aspects of the user's request.
* **Chinese:**  Since the request is in Chinese, ensure the entire response is in Chinese and uses appropriate terminology.

**Self-Correction/Improvements During the Process:**

* **Initial thought:**  Focus heavily on the specific test conditions.
* **Correction:**  Shift focus to the *purpose* of the tests and the broader context of the `ctype` functions within Bionic and Android.
* **Initial thought:**  Overlook the dynamic linker aspect because it's not explicitly in the test code.
* **Correction:**  Realize that the tested functions reside in a shared library, making the dynamic linker relevant to how these functions are made available to applications.
* **Initial thought:**  Provide very technical details about `libc` implementation.
* **Correction:**  Offer a balanced explanation, covering common implementation strategies without getting bogged down in platform-specific details of Bionic's implementation (which isn't in the provided file).

By following this structured approach and continually refining the answer, we can create a comprehensive and informative response that addresses all aspects of the user's request.
好的，让我们详细分析一下 `bionic/tests/ctype_test.cpp` 这个文件。

**文件功能概览**

`bionic/tests/ctype_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试 C 标准库 `<ctype.h>` 头文件中声明的字符分类和转换函数。它的主要功能是：

1. **验证 `<ctype.h>` 函数的正确性：** 该文件包含了多个针对不同 `ctype` 函数的测试用例，例如 `isalnum`（是否是字母或数字）、`isalpha`（是否是字母）、`isdigit`（是否是数字）、`isspace`（是否是空白字符）、`tolower`（转换为小写）等等。
2. **覆盖不同的输入范围：**  测试用例通常会遍历一个预定义的字符范围（从 -1 到 255，涵盖 EOF 和所有可能的单字节字符），以确保函数在各种输入下都能正确工作。
3. **使用 Google Test 框架：** 该文件使用了 Google Test 框架来组织和执行测试，利用 `TEST` 宏定义测试用例，并使用 `EXPECT_TRUE`、`EXPECT_FALSE`、`EXPECT_EQ` 等断言来验证函数的行为是否符合预期。
4. **测试本地化版本：** 除了标准的 `ctype` 函数外，该文件还测试了带有 `_l` 后缀的本地化版本（例如 `isalnum_l`），尽管在这些测试中通常使用 `LC_GLOBAL_LOCALE` 全局 locale。

**与 Android 功能的关系及举例说明**

Bionic 是 Android 的 C 库，因此 `ctype.h` 中定义的函数是 Android 系统和应用开发的基础组成部分。许多 Android 的核心功能和应用都依赖于这些字符处理函数。

**举例说明：**

1. **文本处理：** Android 系统和应用需要处理大量的文本数据，例如用户输入、文件内容、网络数据等。`ctype` 函数被广泛用于分析和操作这些文本，例如：
    * **输入验证：** 检查用户输入的用户名或密码是否只包含字母和数字（使用 `isalnum`）。
    * **解析配置文件：** 读取配置文件时，可能需要判断某个字符是否是空格或注释符号（使用 `isspace`）。
    * **URL 处理：**  解析 URL 时，可能需要判断字符是否是合法的 URL 组成部分。
2. **国际化和本地化（I18N/L10N）：** 虽然此测试文件主要使用 `LC_GLOBAL_LOCALE`，但 `ctype_l` 函数的存在表明 Bionic 支持本地化的字符处理。不同的语言和文化可能对字符的分类有不同的定义。例如，某些语言可能有额外的字母。Android 框架在处理不同语言的文本时，会利用这些本地化的 `ctype` 函数。
3. **编程语言和工具：**  Android 的 NDK (Native Development Kit) 允许开发者使用 C/C++ 编写本地代码。这些本地代码可以直接使用 Bionic 提供的 `ctype` 函数。例如，一个使用 NDK 开发的图像处理库可能需要判断文件名扩展名是否为小写字母（使用 `islower`）。

**libc 函数的功能及其实现**

让我们逐个解释 `ctype_test.cpp` 中涉及的 `libc` 函数的功能和常见的实现方式：

* **`isalnum(int c)`：**
    * **功能：** 检查字符 `c` 是否是字母（a-z 或 A-Z）或数字（0-9）。
    * **实现：**  常见的实现方式是使用一个查找表（通常是一个 256 字节的数组）。数组的索引对应字符的 ASCII 值，数组的值表示该字符是否是字母或数字。另一种实现方式是直接进行范围判断，例如 `(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')`，就像测试代码中那样。现代 Bionic 可能采用更高效的位运算或查表优化方式。

* **`isalpha(int c)`：**
    * **功能：** 检查字符 `c` 是否是字母（a-z 或 A-Z）。
    * **实现：**  类似于 `isalnum`，可以使用查找表或范围判断 `(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')`。

* **`isascii(int c)`：**
    * **功能：** 检查字符 `c` 是否是 ASCII 字符（0 到 127）。
    * **实现：**  通常使用简单的范围判断 `c >= 0 && c <= 127` 或位运算 `(c & ~0x7F) == 0`。

* **`isblank(int c)`：**
    * **功能：** 检查字符 `c` 是否是空白字符（通常指空格 ' ' 和水平制表符 '\t'）。
    * **实现：**  简单的比较 `c == ' ' || c == '\t'`。

* **`iscntrl(int c)`：**
    * **功能：** 检查字符 `c` 是否是控制字符（ASCII 码 0 到 31 以及 127）。
    * **实现：**  范围判断 `(c >= 0 && c < ' ') || c == 0x7f`。

* **`isdigit(int c)`：**
    * **功能：** 检查字符 `c` 是否是数字（0-9）。
    * **实现：**  范围判断 `c >= '0' && c <= '9'`。

* **`isgraph(int c)`：**
    * **功能：** 检查字符 `c` 是否是图形字符（除空格外的可打印字符）。
    * **实现：**  范围判断，通常是 ASCII 码 33 ('!') 到 126 ('~')。

* **`islower(int c)`：**
    * **功能：** 检查字符 `c` 是否是小写字母（a-z）。
    * **实现：**  范围判断 `c >= 'a' && c <= 'z'`。

* **`isprint(int c)`：**
    * **功能：** 检查字符 `c` 是否是可打印字符（包括空格）。
    * **实现：**  范围判断，通常是 ASCII 码 32 (' ') 到 126 ('~')。

* **`ispunct(int c)`：**
    * **功能：** 检查字符 `c` 是否是标点符号（既不是控制字符、数字、字母，也不是空白字符）。
    * **实现：**  通常使用一个查找表或组合多个条件判断。测试代码中给出的范围是常见的 ASCII 标点符号。

* **`isspace(int c)`：**
    * **功能：** 检查字符 `c` 是否是空白字符（空格 ' '、换页 '\f'、换行 '\n'、回车 '\r'、水平制表符 '\t'、垂直制表符 '\v'）。
    * **实现：**  通常使用多个 `||` 运算符进行比较。

* **`isupper(int c)`：**
    * **功能：** 检查字符 `c` 是否是大写字母（A-Z）。
    * **实现：**  范围判断 `c >= 'A' && c <= 'Z'`。

* **`isxdigit(int c)`：**
    * **功能：** 检查字符 `c` 是否是十六进制数字（0-9，a-f，A-F）。
    * **实现：**  组合多个范围判断。

* **`toascii(int c)`：**
    * **功能：** 将字符 `c` 转换为 ASCII 码（通过与 0x7F 进行按位与运算）。
    * **实现：**  位运算 `c & 0x7f`。

* **`tolower(int c)`：**
    * **功能：** 将大写字母转换为小写字母，其他字符保持不变。
    * **实现：**  通常使用查找表。对于 ASCII 字符，如果 `isupper(c)` 为真，则返回 `c + ('a' - 'A')`。

* **`_tolower(int c)`：**
    * **功能：**  与 `tolower` 类似，但行为可能略有不同，尤其是在处理非字母字符时。它可能不会先检查是否为大写字母。
    * **实现：**  通常是一个更简单的版本，不进行额外的检查，直接进行转换操作。

* **`toupper(int c)`：**
    * **功能：** 将小写字母转换为大写字母，其他字符保持不变。
    * **实现：**  类似于 `tolower`，如果 `islower(c)` 为真，则返回 `c - ('a' - 'A')`。

* **`_toupper(int c)`：**
    * **功能：** 与 `toupper` 类似，行为可能略有不同，可能不会先检查是否为小写字母。
    * **实现：**  通常是一个更简单的版本，直接进行转换。

**关于 dynamic linker 的功能**

`ctype_test.cpp` 本身并不直接涉及 dynamic linker 的功能。然而，它测试的 `ctype` 函数是 Bionic 库（通常是 `libc.so`）的一部分，而 `libc.so` 的加载和链接是由 dynamic linker 负责的。

**SO 布局样本 (libc.so 的简化示例):**

```
libc.so:
    .interp         # 指向 dynamic linker 的路径
    .note.android.ident
    .gnu.hash
    .dynsym         # 动态符号表
    .dynstr         # 动态字符串表
    .gnu.version
    .gnu.version_r
    .rel.dyn
    .rel.plt
    .plt            # 程序链接表 (Procedure Linkage Table)
    .text           # 代码段 (包含 isalnum, isalpha 等函数的机器码)
        ...
        isalnum:
            ; ... isalnum 函数的机器码 ...
        isalpha:
            ; ... isalpha 函数的机器码 ...
        ...
    .rodata         # 只读数据段 (可能包含 ctype 函数使用的查找表)
        ctype_table:
            ; ... ctype 函数使用的查找表数据 ...
    .data           # 已初始化的数据段
    .bss            # 未初始化的数据段
    .symtab         # 符号表
    .strtab         # 字符串表
```

**链接的处理过程：**

1. **编译时：** 当编译一个需要使用 `ctype` 函数的 Android 应用或 NDK 模块时，编译器会生成对这些函数的未解析引用。
2. **链接时：** 链接器（在 Android 上通常是 `lld` 或 `gold`）会将这些未解析引用标记为需要动态链接。
3. **运行时：**
    * 当 Android 系统启动一个应用或加载一个共享库时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。
    * Dynamic linker 首先加载应用本身的可执行文件，并解析其头部信息，找到依赖的共享库列表（例如 `libc.so`）。
    * Dynamic linker 接着加载 `libc.so` 到内存中的某个地址。
    * **符号解析：** Dynamic linker 会遍历应用中对 `ctype` 函数的未解析引用，并在 `libc.so` 的动态符号表 (`.dynsym`) 中查找这些符号的地址（例如 `isalnum`）。
    * **重定位：** 找到符号地址后，dynamic linker 会更新应用代码中的相应位置，将对 `isalnum` 的未解析引用替换为 `libc.so` 中 `isalnum` 函数的实际内存地址。这个过程称为重定位。通常使用 PLT (Procedure Linkage Table) 和 GOT (Global Offset Table) 来实现延迟绑定，即在第一次调用函数时才解析其地址。
    * **PLT 和 GOT：**  当应用第一次调用 `isalnum` 时，会跳转到 PLT 中对应 `isalnum` 的条目。PLT 条目会通过 GOT 调用 dynamic linker，dynamic linker 解析 `isalnum` 的地址并更新 GOT。后续对 `isalnum` 的调用将直接通过 GOT 跳转到 `isalnum` 的实现，避免了重复解析。

**假设输入与输出 (逻辑推理)**

`ctype_test.cpp` 的每个测试用例都包含了假设的输入和预期的输出。例如：

* **测试 `isalnum`：**
    * **假设输入：** 字符 'a'
    * **预期输出：** `true` (因为 'a' 是字母)
    * **假设输入：** 字符 '7'
    * **预期输出：** `true` (因为 '7' 是数字)
    * **假设输入：** 字符 '!'
    * **预期输出：** `false` (因为 '!' 既不是字母也不是数字)

* **测试 `tolower`：**
    * **假设输入：** 字符 'A'
    * **预期输出：** 字符 'a'
    * **假设输入：** 字符 'b'
    * **预期输出：** 字符 'b'
    * **假设输入：** 字符 '$'
    * **预期输出：** 字符 '$'

**用户或编程常见的使用错误**

1. **假设字符编码为 ASCII：**  虽然 `ctype` 函数最初是为 ASCII 设计的，但在现代系统中，字符编码可能是 UTF-8 或其他编码。直接使用 `ctype` 函数处理非 ASCII 字符可能会得到意想不到的结果。
    * **示例：**  对于某些 UTF-8 字符，`isalpha` 可能返回 false，即使它们在某种语言中被认为是字母。
2. **未考虑本地化：** 使用不带 `_l` 后缀的 `ctype` 函数会使用默认的 locale，这可能不符合用户的预期。
    * **示例：** 在某些 locale 中，某些字符可能被认为是字母，但在其他 locale 中则不然。
3. **将 `ctype` 函数的返回值直接用于数组索引：** `ctype` 函数返回的是布尔值（0 或非零），不能直接用于数组索引。
4. **混淆 `tolower` 和 `_tolower` 以及 `toupper` 和 `_toupper`：**  `_tolower` 和 `_toupper` 是 POSIX 标准之外的函数，其行为可能因实现而异，并且可能不会进行额外的检查。
    * **示例：** `_tolower('A')` 返回 'a'，但 `_tolower('$')` 的行为可能未定义或返回意外的值。
5. **对 EOF 的处理：**  某些 `ctype` 函数对 EOF（通常是 -1）的行为是明确定义的，而其他情况下则可能未定义。应该仔细查阅文档。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 代码):**
   * Android Framework 的 Java 代码在某些情况下需要与 native 代码进行交互，这通常通过 JNI (Java Native Interface) 实现。
   * Framework 中的某些核心功能，例如文本处理、国际化等，可能会调用底层的 native 代码。
   * 这些 native 代码（通常在 C/C++ 编写的系统服务或库中）会链接到 Bionic 库，从而可以使用 `ctype` 函数。
   * **示例：** `android.text` 包中的某些文本处理类，例如用于判断字符类型的函数，其底层实现可能会调用 Bionic 的 `ctype` 函数。

2. **Android NDK (Native 代码):**
   * 使用 NDK 开发的应用可以直接包含 `<ctype.h>` 头文件，并调用其中的函数。
   * 当 NDK 代码被编译和链接时，链接器会将代码链接到 Bionic 库。
   * **示例：** 一个使用 NDK 开发的文本编辑器应用，其 native 代码可以使用 `isalpha` 来判断用户输入是否为字母。

**Frida Hook 示例**

以下是一个使用 Frida Hook 拦截 `isalnum` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const isalnumPtr = Module.findExportByName("libc.so", "isalnum");

  if (isalnumPtr) {
    Interceptor.attach(isalnumPtr, {
      onEnter: function (args) {
        const charCode = args[0].toInt32();
        console.log(`[isalnum] Called with character code: ${charCode} ('${String.fromCharCode(charCode)}')`);
      },
      onLeave: function (retval) {
        const result = retval.toInt32();
        console.log(`[isalnum] Returned: ${result}`);
      }
    });
    console.log("[Frida] Attached to isalnum");
  } else {
    console.log("[Frida] isalnum not found in libc.so");
  }
} else {
  console.log("[Frida] Skipping isalnum hook on non-ARM architecture.");
}
```

**调试步骤：**

1. **准备环境：** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **编写 Frida 脚本：** 将上面的 JavaScript 代码保存到一个文件中，例如 `isalnum_hook.js`。
3. **找到目标进程：** 确定你想要 hook 的进程的名称或 PID。
4. **运行 Frida：** 使用 Frida CLI 工具运行脚本，指定目标进程。例如：
   ```bash
   frida -U -f <package_name> -l isalnum_hook.js --no-pause
   # 或者如果进程已经在运行
   frida -U <process_name> -l isalnum_hook.js
   ```
   将 `<package_name>` 替换为你要调试的 Android 应用的包名，或者 `<process_name>` 替换为进程名。
5. **触发调用：** 在目标应用中执行某些操作，这些操作会触发对 `isalnum` 函数的调用。例如，在文本框中输入字符。
6. **查看输出：** Frida 会在你的终端上输出 `isalnum` 函数被调用时的参数（字符的 ASCII 码）和返回值。

通过这种方式，你可以监控 `ctype` 函数在 Android 系统或应用中的实际调用情况，帮助理解其工作方式和排查问题。

希望以上详细的解释能够帮助你理解 `bionic/tests/ctype_test.cpp` 文件的功能以及它在 Android 生态系统中的作用。

### 提示词
```
这是目录为bionic/tests/ctype_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <ctype.h>

// We test from -1 (EOF) to 0xff, because that's the range for which behavior
// is actually defined. (It's explicitly undefined below or above that.) Most
// of our routines are no longer table-based and behave correctly for the
// entire int range, but that's not true of other C libraries that we might
// want to compare against, nor of our isalnum(3) and ispunt(3).
static constexpr int kMin = -1;
static constexpr int kMax = 256;

TEST(ctype, isalnum) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= '0' && i <= '9') ||
        (i >= 'A' && i <= 'Z') ||
        (i >= 'a' && i <= 'z')) {
      EXPECT_TRUE(isalnum(i)) << i;
    } else {
      EXPECT_FALSE(isalnum(i)) << i;
    }
  }
}

TEST(ctype, isalnum_l) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= '0' && i <= '9') ||
        (i >= 'A' && i <= 'Z') ||
        (i >= 'a' && i <= 'z')) {
      EXPECT_TRUE(isalnum_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isalnum_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, isalpha) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= 'A' && i <= 'Z') ||
        (i >= 'a' && i <= 'z')) {
      EXPECT_TRUE(isalpha(i)) << i;
    } else {
      EXPECT_FALSE(isalpha(i)) << i;
    }
  }
}

TEST(ctype, isalpha_l) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= 'A' && i <= 'Z') ||
        (i >= 'a' && i <= 'z')) {
      EXPECT_TRUE(isalpha_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isalpha_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, isascii) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= 0 && i <= 0x7f) {
      EXPECT_TRUE(isascii(i)) << i;
    } else {
      EXPECT_FALSE(isascii(i)) << i;
    }
  }
}

TEST(ctype, isblank) {
  for (int i = kMin; i < kMax; ++i) {
    if (i == '\t' || i == ' ') {
      EXPECT_TRUE(isblank(i)) << i;
    } else {
      EXPECT_FALSE(isblank(i)) << i;
    }
  }
}

TEST(ctype, isblank_l) {
  for (int i = kMin; i < kMax; ++i) {
    if (i == '\t' || i == ' ') {
      EXPECT_TRUE(isblank_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isblank_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, iscntrl) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= 0 && i < ' ') || i == 0x7f) {
      EXPECT_TRUE(iscntrl(i)) << i;
    } else {
      EXPECT_FALSE(iscntrl(i)) << i;
    }
  }
}

TEST(ctype, iscntrl_l) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= 0 && i < ' ') || i == 0x7f) {
      EXPECT_TRUE(iscntrl_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(iscntrl_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, isdigit) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= '0' && i <= '9') {
      EXPECT_TRUE(isdigit(i)) << i;
    } else {
      EXPECT_FALSE(isdigit(i)) << i;
    }
  }
}

TEST(ctype, isdigit_l) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= '0' && i <= '9') {
      EXPECT_TRUE(isdigit_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isdigit_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, isgraph) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= '!' && i <= '~') {
      EXPECT_TRUE(isgraph(i)) << i;
    } else {
      EXPECT_FALSE(isgraph(i)) << i;
    }
  }
}

TEST(ctype, isgraph_l) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= '!' && i <= '~') {
      EXPECT_TRUE(isgraph_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isgraph_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, islower) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= 'a' && i <= 'z') {
      EXPECT_TRUE(islower(i)) << i;
    } else {
      EXPECT_FALSE(islower(i)) << i;
    }
  }
}

TEST(ctype, islower_l) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= 'a' && i <= 'z') {
      EXPECT_TRUE(islower_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(islower_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, isprint) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= ' ' && i <= '~') {
      EXPECT_TRUE(isprint(i)) << i;
    } else {
      EXPECT_FALSE(isprint(i)) << i;
    }
  }
}

TEST(ctype, isprint_l) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= ' ' && i <= '~') {
      EXPECT_TRUE(isprint_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isprint_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, ispunct) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= '!' && i <= '/') ||
        (i >= ':' && i <= '@') ||
        (i >= '[' && i <= '`') ||
        (i >= '{' && i <= '~')) {
      EXPECT_TRUE(ispunct(i)) << i;
    } else {
      EXPECT_FALSE(ispunct(i)) << i;
    }
  }
}

TEST(ctype, ispunct_l) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= '!' && i <= '/') ||
        (i >= ':' && i <= '@') ||
        (i >= '[' && i <= '`') ||
        (i >= '{' && i <= '~')) {
      EXPECT_TRUE(ispunct_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(ispunct_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, isspace) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= '\t' && i <= '\r') || i == ' ') {
      EXPECT_TRUE(isspace(i)) << i;
    } else {
      EXPECT_FALSE(isspace(i)) << i;
    }
  }
}

TEST(ctype, isspace_l) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= '\t' && i <= '\r') || i == ' ') {
      EXPECT_TRUE(isspace_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isspace_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, isupper) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= 'A' && i <= 'Z') {
      EXPECT_TRUE(isupper(i)) << i;
    } else {
      EXPECT_FALSE(isupper(i)) << i;
    }
  }
}

TEST(ctype, isupper_l) {
  for (int i = kMin; i < kMax; ++i) {
    if (i >= 'A' && i <= 'Z') {
      EXPECT_TRUE(isupper_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isupper_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, isxdigit) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= '0' && i <= '9') ||
        (i >= 'A' && i <= 'F') ||
        (i >= 'a' && i <= 'f')) {
      EXPECT_TRUE(isxdigit(i)) << i;
    } else {
      EXPECT_FALSE(isxdigit(i)) << i;
    }
  }
}

TEST(ctype, isxdigit_l) {
  for (int i = kMin; i < kMax; ++i) {
    if ((i >= '0' && i <= '9') ||
        (i >= 'A' && i <= 'F') ||
        (i >= 'a' && i <= 'f')) {
      EXPECT_TRUE(isxdigit_l(i, LC_GLOBAL_LOCALE)) << i;
    } else {
      EXPECT_FALSE(isxdigit_l(i, LC_GLOBAL_LOCALE)) << i;
    }
  }
}

TEST(ctype, toascii) {
  // POSIX explicitly says that toascii() returns (c & 0x7f),
  // so there's no EOF-preserving behavior here and we start from 0.
  for (int i = 0; i < kMax; ++i) {
    if (i <= 0x7f) {
      EXPECT_EQ(i, toascii(i));
    } else {
      EXPECT_EQ(i & 0x7f, toascii(i));
    }
  }
}

TEST(ctype, tolower) {
  EXPECT_EQ('!', tolower('!'));
  EXPECT_EQ('a', tolower('a'));
  EXPECT_EQ('a', tolower('A'));
  EXPECT_EQ('z', tolower('z'));
  EXPECT_EQ('z', tolower('Z'));
}

TEST(ctype, tolower_l) {
  EXPECT_EQ('!', tolower_l('!', LC_GLOBAL_LOCALE));
  EXPECT_EQ('a', tolower_l('a', LC_GLOBAL_LOCALE));
  EXPECT_EQ('a', tolower_l('A', LC_GLOBAL_LOCALE));
  EXPECT_EQ('z', tolower_l('z', LC_GLOBAL_LOCALE));
  EXPECT_EQ('z', tolower_l('Z', LC_GLOBAL_LOCALE));
}

TEST(ctype, _tolower) {
  // _tolower may mangle characters for which isupper is false.
  EXPECT_EQ('a', _tolower('A'));
  EXPECT_EQ('z', _tolower('Z'));
}

TEST(ctype, toupper) {
  EXPECT_EQ('!', toupper('!'));
  EXPECT_EQ('A', toupper('a'));
  EXPECT_EQ('A', toupper('A'));
  EXPECT_EQ('Z', toupper('z'));
  EXPECT_EQ('Z', toupper('Z'));
}

TEST(ctype, toupper_l) {
  EXPECT_EQ('!', toupper_l('!', LC_GLOBAL_LOCALE));
  EXPECT_EQ('A', toupper_l('a', LC_GLOBAL_LOCALE));
  EXPECT_EQ('A', toupper_l('A', LC_GLOBAL_LOCALE));
  EXPECT_EQ('Z', toupper_l('z', LC_GLOBAL_LOCALE));
  EXPECT_EQ('Z', toupper_l('Z', LC_GLOBAL_LOCALE));
}

TEST(ctype, _toupper) {
  // _toupper may mangle characters for which islower is false.
  EXPECT_EQ('A', _toupper('a'));
  EXPECT_EQ('Z', _toupper('z'));
}
```