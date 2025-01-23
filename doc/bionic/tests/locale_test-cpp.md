Response:
Let's break down the thought process for answering the user's request about `bionic/tests/locale_test.cpp`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of a specific test file within Android's Bionic library. The key is to infer the tested functionality by examining the test cases.

**2. Initial Scan of the Code:**

The first step is to quickly read through the C++ code. Keywords like `TEST`, `EXPECT_STREQ`, `EXPECT_EQ`, `ASSERT_TRUE`, and function names like `localeconv`, `setlocale`, `newlocale`, `duplocale`, `uselocale`, and `mb_cur_max` immediately stand out. These suggest the file is testing locale-related functions.

**3. Identifying Key Tested Functions and Their Purposes:**

Based on the `TEST` macro and the function calls within each test case, we can identify the core libc functions being tested:

*   `localeconv()`:  The test checks the initial values of its members. This suggests it's about retrieving locale-specific formatting information.
*   `setlocale()`: This test checks setting the locale to `nullptr`, invalid categories, "C", and "POSIX". This indicates it's about changing the program's locale and handling errors.
*   `newlocale()`: Tests cover invalid category masks, `NULL` locale names, bad locale names, and a successful call. This suggests it's about creating new locale objects.
*   `duplocale()`: Tests cloning the global locale. This points to duplicating locale objects.
*   `uselocale()`: Tests switching between locales and getting the current locale. This clearly is about setting the active locale for a thread.
*   `MB_CUR_MAX`:  The test manipulates the locale and checks the value of `MB_CUR_MAX`. This indicates it's about the maximum number of bytes in a multibyte character for the current locale.

**4. Inferring Functionality from the Tests:**

Now, for each tested function, we can infer its purpose and how Bionic implements (or doesn't fully implement) it based on the test assertions:

*   **`localeconv()`:** The tests assert that most fields are initially empty or `CHAR_MAX`. This strongly implies that Bionic's initial "C" locale provides minimal or default formatting information. This is a key insight related to Android's locale support.
*   **`setlocale()`:** The successful tests with "C" and "POSIX" (which defaults to "C") and the check for "C.UTF-8" for `nullptr` and `""` reveal that Bionic primarily supports the "C" locale and its UTF-8 variant. The error handling tests confirm proper error code setting.
*   **`newlocale()`:** The tests for invalid inputs and the successful case demonstrate the function's behavior in creating locale objects.
*   **`duplocale()`:**  The test confirms the ability to create a copy of the global locale.
*   **`uselocale()`:**  The tests show how to switch the current thread's locale and retrieve the currently active locale.
*   **`MB_CUR_MAX`:** The tests clearly show that the "C" locale has a maximum multibyte character size of 1, while "C.UTF-8" has 4. This highlights the impact of the locale on multibyte character handling.

**5. Connecting to Android Functionality:**

At this point, we can start linking the tested functions to broader Android concepts:

*   **Localization:** The whole point of locales is to support different languages and regional settings. Android apps use these settings for displaying dates, numbers, currencies, and handling text input/output correctly.
*   **Bionic's Role:** Bionic provides the underlying C library functions that Android's Java framework and native code rely on for locale handling.
*   **NDK:** NDK developers directly use these libc functions.
*   **Framework:** The Java framework uses higher-level APIs, but these ultimately rely on the lower-level libc functions provided by Bionic.

**6. Addressing Specific Request Points:**

*   **Detailed Explanation of libc Functions:** We've essentially done this by analyzing the tests. The key is to focus on *what* the tests are verifying, not necessarily the internal implementation details of Bionic (which we don't have the source code for in this exercise).
*   **Dynamic Linker (Limited):** The `locale_test.cpp` doesn't directly test dynamic linking. However, the fact that these are libc functions implies they reside in a shared library (likely `libc.so`). We need to address this even though it's not directly tested. We can provide a basic `libc.so` layout and a general description of the linking process.
*   **Logic Inference (Input/Output):** The test cases themselves provide examples of input (function arguments) and expected output (the `EXPECT_*` assertions). We can use these as examples.
*   **Common Usage Errors:** Think about how developers might misuse locale functions. For example, forgetting to set the locale, making assumptions about the default locale, or using the wrong locale for a specific task.
*   **Android Framework/NDK Path:** Trace the high-level flow: Android app -> Java framework (e.g., `java.util.Locale`) -> JNI calls -> Bionic libc functions.
*   **Frida Hooking:**  Provide concrete Frida examples to intercept calls to these locale functions. This requires knowing the function signatures.

**7. Structuring the Response:**

Organize the information logically:

*   Start with a summary of the file's purpose.
*   Detail the functionality of each tested function.
*   Explain the connection to Android.
*   Address the dynamic linker aspect.
*   Provide input/output examples.
*   Illustrate common errors.
*   Explain the Android framework/NDK path.
*   Include Frida hooking examples.

**8. Refining and Adding Detail:**

Go back through each section and add more specific details and explanations. For example, when discussing `setlocale`, mention the implications of Bionic's limited locale support. For Frida, provide specific code snippets.

**Self-Correction/Refinement during the process:**

*   **Initial thought:** Maybe try to explain the internal implementation of `setlocale`. **Correction:**  Without the source code, focus on the observable behavior as tested.
*   **Initial thought:**  Overlook the dynamic linker aspect. **Correction:**  Realize that libc functions *are* part of a shared library and address that, even if the test doesn't directly test linking.
*   **Initial thought:**  Provide very technical Frida examples. **Correction:**  Keep the Frida examples relatively simple and focused on demonstrating interception.

By following this detailed thought process, we can systematically analyze the provided code and generate a comprehensive and informative answer to the user's complex request.
好的，让我们来详细分析一下 `bionic/tests/locale_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/locale_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试与 **locale (本地化)** 相关的 C 标准库函数的功能。Locale 设置影响着程序对日期、时间、数字、货币以及字符排序等信息的处理方式，使其能够适应不同国家和地区的习惯。

这个测试文件使用 Google Test 框架编写，它包含了多个独立的测试用例 (由 `TEST` 宏定义)，分别针对不同的 locale 函数进行测试，以确保 Bionic 库中这些函数的实现符合预期。

**具体功能拆解与 Android 的关联**

以下是文件中每个测试用例的功能以及与 Android 功能的关联：

1. **`TEST(locale, localeconv)`**

    *   **功能:** 测试 `localeconv()` 函数的行为。`localeconv()` 函数用于获取当前 locale 的数值和货币格式信息。它返回一个指向 `lconv` 结构体的指针，该结构体包含了诸如小数点、千位分隔符、货币符号等信息。
    *   **测试逻辑:** 该测试用例断言了在默认 "C" locale 下，`localeconv()` 返回的结构体中的各种字段的初始值。这些值通常是空的字符串或者 `CHAR_MAX`，表示默认 locale 没有特定的格式化信息。
    *   **与 Android 的关联:**
        *   Android 系统和应用程序在显示数字、货币等信息时需要考虑用户的语言和地区设置。`localeconv()` 提供了一种获取这些格式化信息的方式。
        *   例如，一个金融应用程序需要根据用户的 locale 来显示货币符号（如 $ 或 €）和千位分隔符（如逗号或句点）。
    *   **实现解释:** `localeconv()` 的实现通常会读取系统或进程的 locale 设置，并返回一个包含相应格式化信息的 `lconv` 结构体。在 Bionic 中，由于对 locale 的支持较为有限（主要支持 "C" 和 "C.UTF-8"），因此默认情况下返回的 `lconv` 结构体中的许多字段都是默认值。

2. **`TEST(locale, setlocale)`**

    *   **功能:** 测试 `setlocale()` 函数的行为。`setlocale()` 函数用于设置或查询程序的当前 locale。
    *   **测试逻辑:**
        *   测试了使用 `nullptr` 查询当前 locale，预期返回 "C.UTF-8" (Bionic 特定的默认值)。
        *   测试了使用无效的 category 和 locale 值，预期返回 `nullptr` 并设置相应的 `errno` (例如 `EINVAL`, `ENOENT`)。
        *   测试了设置 locale 为 `""`，在 Bionic 中预期返回 "C.UTF-8"。
        *   测试了设置 locale 为 "C" 和 "POSIX"，预期返回 "C"。
    *   **与 Android 的关联:**
        *   Android 应用程序可以通过 `setlocale()` 函数来改变程序的 locale 设置。虽然在 Android 中更常见的是使用 Java Framework 提供的 `java.util.Locale` 类，但底层仍然会调用到 C 库的 `setlocale()` 函数。
        *   例如，一个应用程序可能需要在启动时根据用户的系统语言设置来设置程序的 locale。
    *   **实现解释:** `setlocale()` 的实现会根据传入的 category 和 locale 名称来更新进程的 locale 设置。Bionic 的实现相对简单，主要支持 "C" 和 "C.UTF-8" locale。对于其他 locale，`setlocale()` 通常会失败。

3. **`TEST(locale, newlocale_invalid_category_mask)`**

    *   **功能:** 测试 `newlocale()` 函数对无效 category mask 的处理。`newlocale()` 函数用于创建一个新的 locale 对象。
    *   **测试逻辑:** 尝试使用一个无效的 category mask 调用 `newlocale()`，预期返回 `nullptr` 并设置 `errno` 为 `EINVAL`。
    *   **与 Android 的关联:**  `newlocale()` 提供了一种创建独立于全局 locale 的 locale 对象的方式。Android 的某些组件或库可能需要使用特定的 locale 设置，而不想影响全局 locale。
    *   **实现解释:** `newlocale()` 的实现会检查传入的 category mask 是否有效。如果无效，则返回错误。

4. **`TEST(locale, newlocale_NULL_locale_name)`**

    *   **功能:** 测试 `newlocale()` 函数对 `NULL` locale name 的处理。
    *   **测试逻辑:** 尝试使用 `NULL` 的 locale name 调用 `newlocale()`，预期返回 `nullptr` 并设置 `errno` 为 `EINVAL`。
    *   **与 Android 的关联:** 同上。
    *   **实现解释:** `newlocale()` 的实现会检查 locale name 是否为 `NULL`。如果是，则返回错误。

5. **`TEST(locale, newlocale_bad_locale_name)`**

    *   **功能:** 测试 `newlocale()` 函数对无效 locale name 的处理。
    *   **测试逻辑:** 尝试使用一个无效的 locale name (例如 "this-is-not-a-locale") 调用 `newlocale()`，预期返回 `nullptr` 并设置 `errno` 为 `ENOENT`。
    *   **与 Android 的关联:** 同上。
    *   **实现解释:** `newlocale()` 的实现会尝试查找指定的 locale。如果找不到，则返回错误。

6. **`TEST(locale, newlocale)`**

    *   **功能:** 测试 `newlocale()` 函数成功创建 locale 对象的情况。
    *   **测试逻辑:** 使用 "C" locale 创建一个新的 locale 对象，并断言返回的指针不为 `nullptr`。创建后使用 `freelocale()` 释放资源。
    *   **与 Android 的关联:** 同上。
    *   **实现解释:** `newlocale()` 的实现会分配内存来存储新的 locale 对象，并初始化其内部状态。

7. **`TEST(locale, duplocale)`**

    *   **功能:** 测试 `duplocale()` 函数的功能。`duplocale()` 函数用于复制一个现有的 locale 对象。
    *   **测试逻辑:** 复制全局 locale (`LC_GLOBAL_LOCALE`)，并断言返回的指针不为 `nullptr`。创建后使用 `freelocale()` 释放资源。
    *   **与 Android 的关联:**  `duplocale()` 允许创建现有 locale 对象的副本，避免修改原始 locale 对象。
    *   **实现解释:** `duplocale()` 的实现会分配新的内存，并将原始 locale 对象的内容复制到新的内存中。

8. **`TEST(locale, uselocale)`**

    *   **功能:** 测试 `uselocale()` 函数的功能。`uselocale()` 函数用于设置或查询当前线程的 locale。
    *   **测试逻辑:**
        *   首先调用 `uselocale(nullptr)` 获取当前的线程 locale，预期是全局 locale (`LC_GLOBAL_LOCALE`)。
        *   创建一个新的 locale 对象。
        *   使用 `uselocale()` 将当前线程的 locale 设置为新创建的 locale，并断言之前返回的是全局 locale。
        *   再次使用 `uselocale(nullptr)` 确认当前的线程 locale 已经被改变。
    *   **与 Android 的关联:**
        *   Android 是一个多线程环境，每个线程可以有自己的 locale 设置。`uselocale()` 允许在线程级别管理 locale。
        *   这在处理来自不同用户的请求或者在执行特定于语言环境的任务时非常有用。
    *   **实现解释:** `uselocale()` 的实现会修改当前线程的 locale 上下文。

9. **`TEST(locale, mb_cur_max)`**

    *   **功能:** 测试 `MB_CUR_MAX` 宏的值。`MB_CUR_MAX` 宏定义了当前 locale 下多字节字符的最大字节数。
    *   **测试逻辑:**
        *   创建 "C" 和 "C.UTF-8" 两个 locale 对象。
        *   先将线程 locale 设置为 "C"，断言 `MB_CUR_MAX` 为 1。
        *   然后将线程 locale 设置为 "C.UTF-8"，断言 `MB_CUR_MAX` 为 4。
        *   最后恢复之前的 locale 设置。
    *   **与 Android 的关联:**
        *   多字节字符 (如 UTF-8 编码的字符) 的处理与 locale 设置密切相关。`MB_CUR_MAX` 的值影响着程序如何读取和处理多字节字符。
        *   例如，在处理文本输入或输出时，需要知道 `MB_CUR_MAX` 的值才能正确地解析字符。
    *   **实现解释:** `MB_CUR_MAX` 的值通常由当前的 locale 设置决定。对于 "C" locale，通常只支持单字节字符，因此 `MB_CUR_MAX` 为 1。对于支持 UTF-8 的 locale，`MB_CUR_MAX` 通常为 4。

**dynamic linker 的功能与 so 布局和链接过程**

尽管 `locale_test.cpp` 主要测试 libc 函数，但这些函数最终都链接到 Bionic 的共享库 `libc.so` 中。Dynamic linker (动态链接器，在 Android 上通常是 `linker64` 或 `linker`) 负责在程序运行时加载和链接这些共享库。

**so 布局样本 (libc.so 的简化示例):**

```
libc.so:
    .dynsym:  // 动态符号表
        Symbol: localeconv (类型: FUNCTION, 地址: 0x1000)
        Symbol: setlocale  (类型: FUNCTION, 地址: 0x1050)
        Symbol: newlocale  (类型: FUNCTION, 地址: 0x10A0)
        ...

    .text:     // 代码段
        0x1000:  // localeconv 函数的代码
            ...
        0x1050:  // setlocale 函数的代码
            ...
        0x10A0:  // newlocale 函数的代码
            ...
```

**链接的处理过程:**

1. **加载:** 当 Android 系统启动一个使用了 libc 函数的应用程序时，dynamic linker 会被调用。
2. **依赖分析:** Dynamic linker 会分析应用程序的可执行文件头，查找其依赖的共享库 (例如 `libc.so`)。
3. **加载共享库:** Dynamic linker 会将 `libc.so` 加载到内存中的某个地址空间。
4. **符号解析:** Dynamic linker 会遍历应用程序和 `libc.so` 的动态符号表。当应用程序中调用了 `localeconv` 等 libc 函数时，dynamic linker 会在 `libc.so` 的动态符号表中找到对应的符号和其在内存中的地址。
5. **重定位:**  由于共享库加载到内存的地址可能每次都不同，dynamic linker 需要更新应用程序中对 `libc.so` 函数的调用地址，使其指向 `libc.so` 在内存中的实际地址。这个过程称为重定位。
6. **执行:** 一旦链接完成，应用程序就可以正常调用 `libc.so` 中提供的 locale 相关函数了。

**假设输入与输出 (以 `setlocale` 为例)**

*   **假设输入:** `setlocale(LC_ALL, "fr_FR.UTF-8")`
*   **预期输出 (在 glibc 等完整 locale 支持的系统中):** 返回 "fr_FR.UTF-8"，表示成功将 locale 设置为法语 (法国)。
*   **实际输出 (在 Bionic 中):** 返回 `nullptr`，并且 `errno` 被设置为 `ENOENT`，因为 Bionic 默认不支持 "fr_FR.UTF-8" 这样的完整 locale。

**用户或编程常见的使用错误**

1. **假设默认 locale:**  开发者可能错误地假设程序的默认 locale 是他们期望的特定 locale (例如用户的系统语言)，而没有显式地设置。在 Android 上，默认通常是 "C.UTF-8"，可能与预期不符。
2. **不检查 `setlocale` 的返回值:**  `setlocale` 可能会失败并返回 `nullptr`。如果开发者不检查返回值，就可能在错误的 locale 环境下运行程序，导致意外的行为。
3. **线程安全问题:**  在多线程环境中，如果不小心地修改全局 locale，可能会影响到其他线程的 locale 设置，导致并发问题。应该使用 `newlocale` 和 `uselocale` 来管理线程局部的 locale。
4. **过度依赖系统 locale:**  直接使用空的 locale name `""` 依赖于系统的配置，这在不同的 Android 设备上可能会有差异，导致行为不一致。
5. **错误地理解 `MB_CUR_MAX`:**  开发者可能没有意识到 `MB_CUR_MAX` 的值会随着 locale 的变化而变化，导致在处理多字节字符时出现错误，例如缓冲区溢出或截断。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 代码):**
    *   当 Android 应用需要进行本地化相关的操作时，通常会使用 `java.util.Locale` 类来表示一个特定的 locale。
    *   例如，使用 `Locale.getDefault()` 获取系统的当前 locale，或者使用 `new Locale("fr", "FR")` 创建一个表示法国法语的 `Locale` 对象。
    *   Java Framework 中的 `DateFormat`, `NumberFormat` 等类会使用 `Locale` 对象来进行格式化操作。
    *   在底层，Java Framework 会通过 **Java Native Interface (JNI)** 调用 Bionic 库中相应的 C 函数。例如，在某些情况下，`java.text` 包中的本地化功能可能会调用到 `localeconv` 或 `setlocale`。

2. **Android NDK (C/C++ 代码):**
    *   使用 NDK 开发的 C/C++ 代码可以直接调用 Bionic 库提供的标准 C 库函数，包括 `localeconv`, `setlocale`, `newlocale`, `uselocale` 等。
    *   开发者可以使用 `<locale.h>` 头文件来包含这些函数的声明。
    *   例如，一个使用 NDK 开发的游戏可能需要根据用户的语言设置来显示本地化的文本。

**Frida Hook 示例调试步骤**

假设我们想 hook `setlocale` 函数来观察其调用情况：

```python
import frida
import sys

# 要 hook 的目标进程
package_name = "your.target.package"  # 替换为你的应用包名

# Frida 脚本
hook_script = """
Interceptor.attach(Module.findExportByName("libc.so", "setlocale"), {
    onEnter: function(args) {
        console.log("setlocale called!");
        console.log("  category:", args[0]);
        console.log("  locale:", Memory.readUtf8String(args[1]));
        // 你可以修改参数，例如强制设置为 "C"
        // args[1] = Memory.allocUtf8String("C");
    },
    onLeave: function(retval) {
        console.log("setlocale returned:", Memory.readUtf8String(retval));
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(hook_script)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()  # 保持脚本运行，直到手动停止
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found.")
except Exception as e:
    print(e)
```

**调试步骤:**

1. **安装 Frida:** 确保你的电脑和 Android 设备上都安装了 Frida。
2. **找到目标进程:** 将 `your.target.package` 替换为你想要调试的 Android 应用的包名。
3. **运行 Frida 脚本:** 运行上面的 Python 脚本。
4. **操作目标应用:** 在你的 Android 设备上操作目标应用，触发可能调用 `setlocale` 的代码路径（例如，改变应用的语言设置）。
5. **查看 Frida 输出:** Frida 脚本会在控制台打印出 `setlocale` 函数被调用的信息，包括传入的 category 和 locale 参数，以及返回值。

这个 Frida 示例可以帮助你理解 Android Framework 或 NDK 代码是如何一步步调用到 Bionic 的 locale 函数的。你可以根据需要修改 Frida 脚本来 hook 其他 locale 函数，或者查看更详细的参数和返回值。

希望这个详细的分析能够帮助你理解 `bionic/tests/locale_test.cpp` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/locale_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <limits.h>
#include <locale.h>

#include "utils.h"

TEST(locale, localeconv) {
  EXPECT_STREQ(".", localeconv()->decimal_point);
  EXPECT_STREQ("", localeconv()->thousands_sep);
  EXPECT_STREQ("", localeconv()->grouping);
  EXPECT_STREQ("", localeconv()->int_curr_symbol);
  EXPECT_STREQ("", localeconv()->currency_symbol);
  EXPECT_STREQ("", localeconv()->mon_decimal_point);
  EXPECT_STREQ("", localeconv()->mon_thousands_sep);
  EXPECT_STREQ("", localeconv()->mon_grouping);
  EXPECT_STREQ("", localeconv()->positive_sign);
  EXPECT_STREQ("", localeconv()->negative_sign);
  EXPECT_EQ(CHAR_MAX, localeconv()->int_frac_digits);
  EXPECT_EQ(CHAR_MAX, localeconv()->frac_digits);
  EXPECT_EQ(CHAR_MAX, localeconv()->p_cs_precedes);
  EXPECT_EQ(CHAR_MAX, localeconv()->p_sep_by_space);
  EXPECT_EQ(CHAR_MAX, localeconv()->n_cs_precedes);
  EXPECT_EQ(CHAR_MAX, localeconv()->n_sep_by_space);
  EXPECT_EQ(CHAR_MAX, localeconv()->p_sign_posn);
  EXPECT_EQ(CHAR_MAX, localeconv()->n_sign_posn);
  EXPECT_EQ(CHAR_MAX, localeconv()->int_p_cs_precedes);
  EXPECT_EQ(CHAR_MAX, localeconv()->int_p_sep_by_space);
  EXPECT_EQ(CHAR_MAX, localeconv()->int_n_cs_precedes);
  EXPECT_EQ(CHAR_MAX, localeconv()->int_n_sep_by_space);
  EXPECT_EQ(CHAR_MAX, localeconv()->int_p_sign_posn);
  EXPECT_EQ(CHAR_MAX, localeconv()->int_n_sign_posn);
}

TEST(locale, setlocale) {
  EXPECT_STREQ("C.UTF-8", setlocale(LC_ALL, nullptr));
  EXPECT_STREQ("C.UTF-8", setlocale(LC_CTYPE, nullptr));

  errno = 0;
  EXPECT_EQ(nullptr, setlocale(-1, nullptr));
  EXPECT_ERRNO(EINVAL);
  errno = 0;
  EXPECT_EQ(nullptr, setlocale(13, nullptr));
  EXPECT_ERRNO(EINVAL);

#if defined(__BIONIC__)
  // The "" locale is implementation-defined. For bionic, it's the C.UTF-8 locale, which is
  // pretty much all we support anyway.
  // glibc will give us something like "en_US.UTF-8", depending on the user's configuration.
  EXPECT_STREQ("C.UTF-8", setlocale(LC_ALL, ""));
#endif
  EXPECT_STREQ("C", setlocale(LC_ALL, "C"));
  EXPECT_STREQ("C", setlocale(LC_ALL, "POSIX"));

  errno = 0;
  EXPECT_EQ(nullptr, setlocale(LC_ALL, "this-is-not-a-locale"));
  EXPECT_ERRNO(ENOENT);  // POSIX specified, not an implementation detail!
}

TEST(locale, newlocale_invalid_category_mask) {
  errno = 0;
  EXPECT_EQ(nullptr, newlocale(1 << 20, "C", nullptr));
  EXPECT_ERRNO(EINVAL);
}

TEST(locale, newlocale_NULL_locale_name) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  errno = 0;
  EXPECT_EQ(nullptr, newlocale(LC_ALL, nullptr, nullptr));
  EXPECT_ERRNO(EINVAL);
#pragma clang diagnostic pop
}

TEST(locale, newlocale_bad_locale_name) {
  errno = 0;
  EXPECT_EQ(nullptr, newlocale(LC_ALL, "this-is-not-a-locale", nullptr));
  EXPECT_ERRNO(ENOENT);  // POSIX specified, not an implementation detail!
}

TEST(locale, newlocale) {
  locale_t l = newlocale(LC_ALL, "C", nullptr);
  ASSERT_TRUE(l != nullptr);
  freelocale(l);
}

TEST(locale, duplocale) {
  locale_t cloned_global = duplocale(LC_GLOBAL_LOCALE);
  ASSERT_TRUE(cloned_global != nullptr);
  freelocale(cloned_global);
}

TEST(locale, uselocale) {
  locale_t original = uselocale(nullptr);
  EXPECT_FALSE(original == nullptr);
  EXPECT_EQ(LC_GLOBAL_LOCALE, original);

  locale_t n = newlocale(LC_ALL, "C", nullptr);
  EXPECT_FALSE(n == nullptr);
  EXPECT_FALSE(n == original);

  locale_t old = uselocale(n);
  EXPECT_TRUE(old == original);

  EXPECT_EQ(n, uselocale(nullptr));
}

TEST(locale, mb_cur_max) {
  // We can't reliably test the behavior with setlocale(3) or the behavior for
  // initial program conditions because (unless we're the only test that was
  // run), another test has almost certainly called uselocale(3) in this thread.
  // See b/16685652.
  locale_t cloc = newlocale(LC_ALL, "C", nullptr);
  locale_t cloc_utf8 = newlocale(LC_ALL, "C.UTF-8", nullptr);

  locale_t old_locale = uselocale(cloc);
  ASSERT_EQ(1U, MB_CUR_MAX);
  uselocale(cloc_utf8);
  ASSERT_EQ(4U, MB_CUR_MAX);

  uselocale(old_locale);
  freelocale(cloc);
  freelocale(cloc_utf8);
}
```