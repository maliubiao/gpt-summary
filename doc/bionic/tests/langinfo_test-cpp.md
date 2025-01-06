Response:
Let's break down the thought process for generating the comprehensive answer.

1. **Understand the Goal:** The core request is to analyze the provided C++ test file (`langinfo_test.cpp`) and explain its functionality within the Android Bionic context. This involves dissecting the code, linking it to broader Android concepts, and explaining the underlying mechanisms of the libc functions used.

2. **Initial Code Scan (High-Level):**  The first step is to quickly read through the code to get a general sense of what it's doing. Key observations:
    * It's a C++ test file using Google Test (`gtest`).
    * It includes `<langinfo.h>`.
    * It uses `setlocale` and `nl_langinfo`.
    * It makes assertions and expectations about the return values of `nl_langinfo` for different categories (CTYPE, TIME, NUMERIC, MESSAGES, MONETARY).
    * It tests for invalid inputs to `nl_langinfo`.
    * It compares the results of `nl_langinfo` with `localeconv`.

3. **Identify Key Functions:** The core functions to focus on are:
    * `setlocale`:  This sets the locale for the program. It's crucial for understanding the context of the tests.
    * `nl_langinfo`: This is the function being tested. It retrieves locale-specific information.
    * `localeconv`:  This function gets detailed numeric and monetary formatting information. The test file uses it for comparison, so understanding its purpose is important.

4. **Relate to Android Bionic:** The prompt explicitly mentions Android Bionic. This triggers the need to explain that Bionic is Android's C library and how locale information is relevant in that context (internationalization, supporting different languages and cultural conventions). The `#if defined(__BIONIC__)` directives in the code directly point to Bionic-specific behavior.

5. **Explain Functionality (Detailed):** For each key function, the explanation needs to be comprehensive:
    * **`setlocale`:**
        * Purpose: Sets the program's locale.
        * Parameters:  `category` (e.g., `LC_ALL`, `LC_CTYPE`) and `locale` string.
        * Return Value:  Pointer to the new locale string, or NULL on error.
        * Android Relevance:  Essential for applications needing to adapt to user language and region settings.
        * Common Errors: Incorrect locale strings, attempting to set unsupported locales.
    * **`nl_langinfo`:**
        * Purpose: Retrieves locale-specific information based on the `item` parameter.
        * Parameter: `item` (constants defined in `<langinfo.h>` like `CODESET`, `D_T_FMT`, etc.).
        * Return Value: A pointer to a static string containing the requested information.
        * Implementation (Conceptual):  This involves looking up the requested `item` in locale data files. Bionic likely uses a combination of compiled-in defaults and loaded locale data. *Initially, I might not know the exact implementation details, but I can infer the core mechanism.*
        * Android Relevance: Used by various system components and applications to format dates, times, numbers, etc., according to the user's locale.
        * Common Errors: Using invalid `item` values.
    * **`localeconv`:**
        * Purpose: Returns a pointer to a `lconv` struct containing detailed numeric and monetary formatting information.
        * Implementation (Conceptual): Similar to `nl_langinfo`, it retrieves information from locale data.
        * Android Relevance:  Used for precise control over number and currency formatting.
        * Common Errors:  Assuming the contents of the `lconv` struct are modifiable (they are not).

6. **Dynamic Linker Aspect:** The prompt specifically asks about the dynamic linker. While this test file doesn't directly interact with the dynamic linker in a complex way, the connection is that `libc.so` (where `langinfo` functions reside) is loaded by the dynamic linker. This necessitates:
    * Explaining the role of the dynamic linker in loading shared libraries.
    * Providing a basic example of SO layout in memory.
    * Briefly describing the linking process (symbol resolution).

7. **Android Framework/NDK Integration:** The prompt requests tracing how an Android app reaches this code. The flow is:
    * Android Framework uses system calls or NDK APIs.
    * NDK APIs often wrap libc functions.
    * Thus, calling a function like `strftime` (which relies on locale information) will eventually call `nl_langinfo` through Bionic's implementation.
    * Provide a simplified call stack illustration.

8. **Frida Hooking:**  Demonstrate how to use Frida to intercept calls to `nl_langinfo`. This involves:
    * Identifying the target function (`nl_langinfo`).
    * Getting the address of the function in `libc.so`.
    * Using Frida's `Interceptor.attach` to hook the function.
    * Logging arguments and return values.

9. **Assumptions and Logic:**  Where the code makes assumptions (like the expected output for the "C.UTF-8" locale), explicitly state these as assumptions. For example, the tests expect specific date and time formats.

10. **Structure and Language:** Organize the information logically with clear headings and subheadings. Use precise and understandable language, avoiding overly technical jargon where possible, or explaining it if necessary. Since the request is in Chinese, the response needs to be in fluent Chinese.

11. **Review and Refine:** After drafting the initial response, review it for accuracy, completeness, and clarity. Ensure all parts of the prompt have been addressed. For instance, double-check the explanations of libc functions and the dynamic linker. Ensure the Frida example is correct and easy to understand.

**Self-Correction/Refinement Example during the process:**

* **Initial thought:** "The dynamic linker isn't really involved here."
* **Correction:** "Wait, `nl_langinfo` is in `libc.so`, and that's loaded by the dynamic linker. I need to explain that connection, even if this test doesn't directly call `dlopen` or similar."  This leads to including the section about SO layout and linking.

* **Initial thought:** "Just explain what each test case does."
* **Refinement:** "While describing the tests is important, I also need to explain *why* these specific assertions are being made. What do the `nl_langinfo` constants mean?  What's the significance of the different locale categories?" This leads to more detailed explanations of the `nl_langinfo` constants and their relation to locale categories.

By following this structured approach, continuously checking against the prompt's requirements, and being willing to refine the explanation, a comprehensive and accurate answer can be generated.
这个文件 `bionic/tests/langinfo_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试与 **locale 信息** 相关的 C 标准库函数，主要是 `nl_langinfo` 和 `setlocale`。

**功能列举:**

1. **测试 `nl_langinfo` 函数:**  该文件通过一系列的单元测试，验证 `nl_langinfo` 函数在不同 locale 设置下，对于各种语言和地区信息的返回是否正确。这些信息包括：
    * **字符类型 (CTYPE):**  例如字符编码 (`CODESET`)。
    * **时间格式 (TIME):**  例如日期和时间格式 (`D_T_FMT`, `D_FMT`, `T_FMT` 等)，AM/PM 表示 (`AM_STR`, `PM_STR`)，星期和月份的名称 (`DAY_1` 到 `DAY_7`, `MON_1` 到 `MON_12`，以及它们的缩写)。
    * **数字格式 (NUMERIC):**  例如小数点字符 (`RADIXCHAR`) 和千位分隔符 (`THOUSEP`)。
    * **消息格式 (MESSAGES):**  例如肯定和否定回答的正则表达式 (`YESEXPR`, `NOEXPR`)。
    * **货币格式 (MONETARY):**  例如货币符号 (`CRNCYSTR`)。
2. **测试 `setlocale` 函数:**  测试用例首先使用 `setlocale(LC_ALL, "C.UTF-8")` 来设置 locale 环境，为后续的 `nl_langinfo` 测试提供一个已知的环境。
3. **测试无效输入:**  测试用例还会验证当 `nl_langinfo` 传入无效的 `item` 参数时，是否能正确返回空字符串。
4. **对比 `nl_langinfo` 和 `localeconv`:**  测试用例对比了 `nl_langinfo` 和 `localeconv` 函数对于某些相同信息的返回值，例如小数点和千位分隔符，以确保一致性。

**与 Android 功能的关系及举例说明:**

Android 作为一款全球化的操作系统，需要支持各种不同的语言和地区习惯。`langinfo` 相关的函数在 Android 中扮演着重要的角色，用于实现应用程序的国际化 (i18n) 和本地化 (l10n)。

* **用户界面显示:** Android Framework 中的各种组件，例如日期选择器、时间选择器、数字输入框等，都需要根据用户的 locale 设置来显示和格式化信息。例如，日期格式在美国可能是 "MM/DD/YYYY"，而在其他地区可能是 "DD/MM/YYYY"。`nl_langinfo` 提供的 `D_FMT` 信息就用于确定这种格式。
* **文本处理:**  应用程序在处理文本时，需要知道当前的字符编码。`nl_langinfo(CODESET)` 返回的字符编码信息 (例如 "UTF-8") 可以用于正确地解码和显示文本。
* **货币和数字格式化:**  金融类应用或者需要显示货币的应用需要根据用户的 locale 设置来显示货币符号、小数点和千位分隔符。例如，在美国使用 "." 作为小数点，"," 作为千位分隔符，而在某些欧洲国家则相反。`nl_langinfo(RADIXCHAR)` 和 `nl_langinfo(THOUSEP)` 以及 `nl_langinfo(CRNCYSTR)` 就提供了这些信息。

**举例说明:**

假设一个 Android 应用需要显示当前日期。它可能会调用 Android Framework 提供的日期格式化 API，而这些 API 底层会使用 Bionic 库中的 `strftime` 函数。`strftime` 函数会根据当前的 locale 设置，调用 `nl_langinfo` 获取 `D_FMT` (日期格式) 信息，然后将日期格式化成用户期望的格式。

```c++
// Android 应用代码示例 (简化)
#include <ctime>
#include <iostream>
#include <locale.h>

int main() {
  setlocale(LC_ALL, ""); // 设置为用户默认 locale
  std::time_t t = std::time(nullptr);
  std::tm* now = std::localtime(&t);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%x", now); // %x 通常对应 D_FMT
  std::cout << "Current date: " << buf << std::endl;
  return 0;
}
```

在这个例子中，`strftime` 函数会根据当前的 locale 设置，最终通过 `nl_langinfo` 获取日期格式信息。

**libc 函数的功能实现详解:**

* **`setlocale(int category, const char* locale)`:**
    * **功能:** 设置或查询程序的 locale 信息。`category` 参数指定要设置的 locale 类别 (例如 `LC_ALL` 表示所有类别，`LC_CTYPE` 表示字符类型，`LC_TIME` 表示时间格式等)。`locale` 参数是一个字符串，指定要设置的 locale 名称 (例如 "en_US.UTF-8", "zh_CN.GBK", "C")。如果 `locale` 为 `NULL`，则返回当前 locale 的字符串。
    * **实现:**  Bionic 维护着一个全局的 locale 状态，`setlocale` 函数会根据传入的 `category` 和 `locale` 参数更新这个状态。它会查找与指定的 locale 对应的 locale 数据文件（这些数据通常以二进制格式存储在 Android 系统分区中），并将相关信息加载到内存中。对于 "C" locale，通常会使用内置的默认值。如果找不到指定的 locale，则设置会失败并返回 `NULL`。
* **`nl_langinfo(nl_item item)`:**
    * **功能:** 根据 `item` 参数获取当前 locale 中指定的语言和地区信息。`item` 是一个枚举值，定义在 `<langinfo.h>` 中，例如 `CODESET`, `D_T_FMT`, `RADIXCHAR` 等。
    * **实现:** `nl_langinfo` 函数会根据当前的 locale 设置和传入的 `item` 参数，查找之前由 `setlocale` 加载的 locale 数据。这些数据通常以结构化的方式存储，`nl_langinfo` 会根据 `item` 的值，从相应的结构中提取出所需的信息，并返回指向该信息的静态字符串的指针。这个字符串通常是硬编码在 locale 数据文件中的。

**dynamic linker 的功能，SO 布局样本及链接处理过程:**

虽然 `langinfo_test.cpp` 本身没有直接涉及动态链接的复杂操作，但 `nl_langinfo` 和 `setlocale` 这些函数都位于 `libc.so` (Bionic 的 C 库) 中，而 `libc.so` 是通过动态链接器加载到进程内存中的。

**SO 布局样本:**

假设一个简单的 Android 应用程序加载了 `libc.so`，其内存布局可能如下（简化）：

```
[内存地址范围]   [内容]
----------------------
...
[0xb7000000 - 0xb7fff000]  /system/lib/libc.so  (加载基址)
    [0xb7001000]          .text 段 (代码段，包含 nl_langinfo 和 setlocale 的机器码)
    [0xb7ff0000]          .rodata 段 (只读数据段，包含 locale 数据，例如日期格式字符串)
    [0xb7ffe000]          .data 段 (已初始化数据段，包含全局变量，例如当前的 locale 设置)
    [0xb7fff800]          .bss 段 (未初始化数据段)
...
```

* **加载基址:**  `libc.so` 被动态链接器加载到内存中的某个地址。
* **段 (Segments):**  SO 文件被分成不同的段，如 `.text` (代码)、`.rodata` (只读数据)、`.data` (可读写数据) 和 `.bss` (未初始化数据)。
* **`nl_langinfo` 和 `setlocale` 的位置:**  这两个函数的机器码位于 `.text` 段。
* **locale 数据的位置:**  locale 数据（例如各种格式字符串、月份名称等）通常位于 `.rodata` 段，因为这些数据在运行时是只读的。

**链接处理过程:**

1. **应用程序启动:** 当 Android 启动一个应用程序时，操作系统会创建一个新的进程。
2. **动态链接器启动:**  操作系统会加载动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 到进程的内存空间。
3. **加载依赖库:**  动态链接器会分析应用程序的可执行文件头，找出它依赖的共享库，例如 `libc.so`。
4. **加载 `libc.so`:** 动态链接器会在内存中找到 `libc.so`，或者从磁盘加载它，并将其加载到进程的地址空间中的某个位置。
5. **符号解析 (Symbol Resolution):**  动态链接器会解析应用程序中对 `libc.so` 中符号的引用，例如对 `nl_langinfo` 和 `setlocale` 的调用。它会找到 `libc.so` 中这些符号的地址，并将应用程序中的调用指令指向这些地址。这个过程涉及到查找符号表和重定位。
6. **执行应用程序:**  一旦所有依赖的库都被加载和链接，操作系统就会开始执行应用程序的代码。

当应用程序调用 `nl_langinfo` 或 `setlocale` 时，实际上是跳转到 `libc.so` 中对应函数的机器码执行。

**假设输入与输出 (针对测试用例):**

由于这是测试代码，我们可以基于代码中的断言来推断假设的输入和预期的输出。

**`TEST(langinfo, category_CTYPE)`:**

* **假设输入:**  调用 `setlocale(LC_ALL, "C.UTF-8")`，然后调用 `nl_langinfo(CODESET)`。
* **预期输出:** `nl_langinfo(CODESET)` 应该返回字符串 "UTF-8"。

**`TEST(langinfo, category_TIME)`:**

* **假设输入:** 调用 `setlocale(LC_ALL, "C.UTF-8")`，然后调用一系列 `nl_langinfo`，例如 `nl_langinfo(D_T_FMT)`, `nl_langinfo(D_FMT)` 等。
* **预期输出:**
    * 在 Bionic 环境下，`nl_langinfo(D_T_FMT)` 返回 "%F %T %z"。
    * 在 Bionic 环境下，`nl_langinfo(D_FMT)` 返回 "%F"。
    * `nl_langinfo(T_FMT)` 返回 "%T"。
    * `nl_langinfo(AM_STR)` 返回 "AM"。
    * ...等等，代码中列出的所有预期字符串。

**`TEST(langinfo, invalid)`:**

* **假设输入:** 调用 `setlocale(LC_ALL, "C.UTF-8")`，然后调用 `nl_langinfo(-1)`, `nl_langinfo(0)`, `nl_langinfo(666)`。
* **预期输出:** 所有这些 `nl_langinfo` 调用都应该返回空字符串 `""`。

**用户或编程常见的使用错误:**

1. **未设置 locale 或设置错误的 locale:**  如果在调用 `nl_langinfo` 之前没有调用 `setlocale` 或者设置了一个不支持的 locale，`nl_langinfo` 的行为可能是未定义的或者返回错误的信息。
    ```c++
    #include <langinfo.h>
    #include <iostream>

    int main() {
      // 忘记设置 locale
      std::cout << "CODESET: " << nl_langinfo(CODESET) << std::endl; // 可能返回意外结果
      return 0;
    }
    ```
2. **假设 "C" locale 的行为与其他 locale 相同:** "C" locale 是一个最小化的 locale，其行为可能与其他 locale (例如 "en_US.UTF-8") 不同。开发者应该避免在需要特定 locale 行为时依赖 "C" locale。
3. **错误地使用 `nl_item` 枚举值:**  如果传递给 `nl_langinfo` 的 `item` 参数是无效的或者与当前的 locale 不相关，`nl_langinfo` 通常会返回空字符串。开发者应该查阅 `<langinfo.h>` 了解可用的 `item` 值。
4. **修改 `nl_langinfo` 返回的字符串:** `nl_langinfo` 返回的指针指向静态存储区，不应该被修改。修改这些字符串可能导致程序崩溃或其他未定义的行为。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤:**

**调用链:**

1. **Android Framework:**  Android Framework 中的某些组件，例如 `android.text.format.DateFormat` 或 `java.util.Date`, `java.text.SimpleDateFormat` 等，需要格式化日期、时间或数字。
2. **NDK (Native Development Kit):**  如果应用程序使用 NDK 进行本地开发，它可能会直接调用 C 标准库函数，例如 `strftime` 或自己使用 `nl_langinfo`。
3. **Bionic libc:**  无论是 Framework 还是 NDK，最终都会调用到 Bionic 的 C 库实现。例如，`strftime` 的实现内部会使用 `nl_langinfo` 来获取日期和时间格式信息。

**Frida Hook 示例:**

可以使用 Frida 来 hook `nl_langinfo` 函数，观察其被调用的情况和参数。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(sys.argv[0]))
        sys.exit(1)

    try:
        pid = int(sys.argv[1])
        session = frida.attach(pid)
    except ValueError:
        process_name = sys.argv[1]
        session = frida.attach(process_name)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "nl_langinfo"), {
        onEnter: function(args) {
            var item = args[0].toInt();
            var itemName = "";
            // 这里可以根据 item 的值来获取对应的宏名称，为了简化，这里只输出数值
            if (item === 0) itemName = "EMPTY";
            else if (item === 1) itemName = "CODESET";
            else if (item === 2) itemName = "D_T_FMT";
            // ... 添加更多 item 的映射 ...
            else itemName = "Unknown(" + item + ")";

            console.log("[nl_langinfo] Called with item:", itemName, "(" + item + ")");
        },
        onLeave: function(retval) {
            console.log("[nl_langinfo] Returning:", retval.readUtf8String());
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    input()

if __name__ == '__main__':
    main()
```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Python 的 Frida 模块。
2. **运行 Android 应用:** 启动你想要监控的 Android 应用。
3. **运行 Frida 脚本:**  在你的电脑上运行上面的 Python 脚本，并将目标应用的进程名或 PID 作为参数传递。
4. **观察输出:** 当 Android 应用执行涉及到 locale 信息的操作时，Frida 脚本会拦截对 `nl_langinfo` 的调用，并打印出传入的 `item` 值以及返回的字符串。

通过观察 Frida 的输出，你可以追踪 `nl_langinfo` 是如何被调用的，以及哪些 locale 信息被请求，从而理解 Android Framework 或 NDK 如何利用这些 Bionic 库提供的功能。

Prompt: 
```
这是目录为bionic/tests/langinfo_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <langinfo.h>

TEST(langinfo, category_CTYPE) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_ALL, "C.UTF-8"));

  EXPECT_STREQ("UTF-8", nl_langinfo(CODESET));
}

TEST(langinfo, category_TIME) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_ALL, "C.UTF-8"));

#if defined(__BIONIC__)
  // bionic's C locale is ISO rather than en_US.
  EXPECT_STREQ("%F %T %z", nl_langinfo(D_T_FMT));
  EXPECT_STREQ("%F", nl_langinfo(D_FMT));
#else
  EXPECT_STREQ("%a %d %b %Y %r %Z", nl_langinfo(D_T_FMT));
  EXPECT_STREQ("%m/%d/%Y", nl_langinfo(D_FMT));
#endif
  EXPECT_STREQ("%T", nl_langinfo(T_FMT));
  EXPECT_STREQ("%I:%M:%S %p", nl_langinfo(T_FMT_AMPM));
  EXPECT_STREQ("AM", nl_langinfo(AM_STR));
  EXPECT_STREQ("PM", nl_langinfo(PM_STR));
  EXPECT_STREQ("Sunday", nl_langinfo(DAY_1));
  EXPECT_STREQ("Monday", nl_langinfo(DAY_2));
  EXPECT_STREQ("Tuesday", nl_langinfo(DAY_3));
  EXPECT_STREQ("Wednesday", nl_langinfo(DAY_4));
  EXPECT_STREQ("Thursday", nl_langinfo(DAY_5));
  EXPECT_STREQ("Friday", nl_langinfo(DAY_6));
  EXPECT_STREQ("Saturday", nl_langinfo(DAY_7));
  EXPECT_STREQ("Sun", nl_langinfo(ABDAY_1));
  EXPECT_STREQ("Mon", nl_langinfo(ABDAY_2));
  EXPECT_STREQ("Tue", nl_langinfo(ABDAY_3));
  EXPECT_STREQ("Wed", nl_langinfo(ABDAY_4));
  EXPECT_STREQ("Thu", nl_langinfo(ABDAY_5));
  EXPECT_STREQ("Fri", nl_langinfo(ABDAY_6));
  EXPECT_STREQ("Sat", nl_langinfo(ABDAY_7));
  EXPECT_STREQ("January", nl_langinfo(MON_1));
  EXPECT_STREQ("February", nl_langinfo(MON_2));
  EXPECT_STREQ("March", nl_langinfo(MON_3));
  EXPECT_STREQ("April", nl_langinfo(MON_4));
  EXPECT_STREQ("May", nl_langinfo(MON_5));
  EXPECT_STREQ("June", nl_langinfo(MON_6));
  EXPECT_STREQ("July", nl_langinfo(MON_7));
  EXPECT_STREQ("August", nl_langinfo(MON_8));
  EXPECT_STREQ("September", nl_langinfo(MON_9));
  EXPECT_STREQ("October", nl_langinfo(MON_10));
  EXPECT_STREQ("November", nl_langinfo(MON_11));
  EXPECT_STREQ("December", nl_langinfo(MON_12));
  EXPECT_STREQ("Jan", nl_langinfo(ABMON_1));
  EXPECT_STREQ("Feb", nl_langinfo(ABMON_2));
  EXPECT_STREQ("Mar", nl_langinfo(ABMON_3));
  EXPECT_STREQ("Apr", nl_langinfo(ABMON_4));
  EXPECT_STREQ("May", nl_langinfo(ABMON_5));
  EXPECT_STREQ("Jun", nl_langinfo(ABMON_6));
  EXPECT_STREQ("Jul", nl_langinfo(ABMON_7));
  EXPECT_STREQ("Aug", nl_langinfo(ABMON_8));
  EXPECT_STREQ("Sep", nl_langinfo(ABMON_9));
  EXPECT_STREQ("Oct", nl_langinfo(ABMON_10));
  EXPECT_STREQ("Nov", nl_langinfo(ABMON_11));
  EXPECT_STREQ("Dec", nl_langinfo(ABMON_12));
  EXPECT_STREQ("", nl_langinfo(ERA));
  EXPECT_STREQ("", nl_langinfo(ERA_D_FMT));
  EXPECT_STREQ("", nl_langinfo(ERA_D_T_FMT));
  EXPECT_STREQ("", nl_langinfo(ERA_T_FMT));
  EXPECT_STREQ("", nl_langinfo(ALT_DIGITS));
}

TEST(langinfo, category_NUMERIC) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_ALL, "C.UTF-8"));

  EXPECT_STREQ(".", nl_langinfo(RADIXCHAR));
  EXPECT_STREQ("", nl_langinfo(THOUSEP));
}

TEST(langinfo, category_MESSAGES) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_ALL, "C.UTF-8"));

  EXPECT_STREQ("^[yY]", nl_langinfo(YESEXPR));
  EXPECT_STREQ("^[nN]", nl_langinfo(NOEXPR));
}

TEST(langinfo, category_MONETARY) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_ALL, "C.UTF-8"));

  // POSIX says that if the currency symbol is the empty string (as it is for
  // the C locale), an implementation can return the empty string and not
  // include the leading [+-.] that signifies where the currency symbol should
  // appear. For consistency with localeconv (which POSIX says to prefer for
  // RADIXCHAR, THOUSEP, and CRNCYSTR) we return the empty string. glibc
  // disagrees.
#if defined(__BIONIC__)
  EXPECT_STREQ("", nl_langinfo(CRNCYSTR));
#else
  EXPECT_STREQ("-", nl_langinfo(CRNCYSTR));
#endif
}

TEST(langinfo, invalid) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_ALL, "C.UTF-8"));

  EXPECT_STREQ("", nl_langinfo(-1));
  EXPECT_STREQ("", nl_langinfo(0));
  EXPECT_STREQ("", nl_langinfo(666));
}

TEST(langinfo, matches_localeconv) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_ALL, "C.UTF-8"));

  EXPECT_STREQ(localeconv()->decimal_point, nl_langinfo(RADIXCHAR));
  EXPECT_STREQ(localeconv()->thousands_sep, nl_langinfo(THOUSEP));
#if defined(__BIONIC__)
  // (See comment in category_MONETARY test.)
  EXPECT_STREQ(localeconv()->currency_symbol, nl_langinfo(CRNCYSTR));
#endif
}

"""

```