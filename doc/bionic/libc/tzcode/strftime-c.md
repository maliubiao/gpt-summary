Response:
Let's break down the thought process for answering the request about `bionic/libc/tzcode/strftime.c`.

**1. Understanding the Core Request:**

The primary goal is to analyze the functionality of `strftime.c`, its relation to Android, its internal implementation, interaction with the dynamic linker (if any), potential errors, and its place within the Android ecosystem, culminating in a Frida hook example. The key is to be detailed and comprehensive.

**2. Initial Code Examination and High-Level Functionality:**

First, I'd skim the code to get a general idea of what it does. The comments at the beginning clearly state: "Convert a broken-down timestamp to a string." This immediately points to its core function: formatting time and date information. The presence of `#include <time.h>` (implicitly through other includes) and the `struct tm` parameter in the `strftime` function signature confirms this.

**3. Listing Functionality (Point 1 of the Request):**

Based on the code and the understanding of its core purpose, I'd list its main functionalities:

*   **Formatting time and date:** This is the primary function.
*   **Handling different format specifiers:** The `%` character and the subsequent characters indicate format specifiers (e.g., `%Y` for year, `%m` for month).
*   **Localization (limited in this version):**  Although the code includes `locale.h` and `strftime_l`, the comment in `strftime_l` explicitly states that only the C locale is supported in this Bionic version. This is important to note.
*   **Handling timezones:** The code interacts with timezone information, even though the details might be handled by other parts of the library. The `%Z` and `%z` specifiers are clear indicators.
*   **Handling modifiers:** The `_`, `-`, `0`, `^`, `#` modifiers after the `%` sign extend the formatting options.
*   **Handling year 2000 issues (legacy):**  The `DEPRECATE_TWO_DIGIT_YEARS` and `YEAR_2000_NAME` suggest past considerations for two-digit year representations.

**4. Relationship to Android (Point 2 of the Request):**

Since this is part of Bionic, the Android C library, its functions are directly used by Android. Examples include:

*   **System logging (logcat):**  Log timestamps are a common use case.
*   **File timestamps:**  When displaying file information.
*   **Applications needing time/date formatting:** Any Android app using standard C library functions for time formatting will go through `strftime`.
*   **Network protocols:** Protocols that require timestamps in specific formats.

**5. Detailed Explanation of Libc Functions (Point 3 of the Request):**

I'd go through each significant function in the file:

*   **`strftime`:** The main entry point. It sets up the locale (though limited), calls the internal formatting function `_fmt`, handles errors, and potentially issues warnings about two-digit years.
*   **`strftime_l`:**  A locale-aware version, but in this Bionic implementation, it simply calls `strftime`.
*   **`_fmt`:** The core logic. It iterates through the format string, identifies format specifiers, and calls appropriate helper functions to format the time components. It also handles modifiers.
*   **`_add`:**  Appends a string to the output buffer, handling modifiers like case conversion.
*   **`_conv`:** Converts an integer to a string with padding and formatting based on the provided format string. The optimization comment about avoiding `snprintf` is crucial to mention.
*   **`_yconv`:** Specifically handles year formatting, including handling negative years and the logic for `%C` and `%y`.
*   **`getformat`:** A helper to select the correct format string based on the modifier.
*   **`_safe_tm_zone`:**  An Android-specific function to safely retrieve the timezone name, handling cases where `TM_ZONE` might be null.

For each function, I would explain its parameters, return value, and the core algorithm it implements.

**6. Dynamic Linker Interaction (Point 4 of the Request):**

This `strftime.c` file itself **does not directly interact with the dynamic linker**. It's a standard C library function. However, the *timezone data* it uses is often loaded dynamically. Therefore, the connection to the dynamic linker is **indirect**.

*   **SO Layout:** The `libc.so` would contain the `strftime` function. Timezone data (like the `tzdata` files or compiled-in timezone information) might be in a separate file or section within `libc.so`.
*   **Linking Process:** When a program calls `strftime`, it's linked against `libc.so`. The dynamic linker resolves the `strftime` symbol to its implementation in `libc.so`. The `tzset()` function within `strftime` (or functions it calls) might then trigger the loading of timezone data if it hasn't been loaded yet.

**7. Logical Reasoning, Assumptions, Input/Output (Point 5 of the Request):**

For functions like `_conv` and `_yconv`, providing examples of input and output based on different format strings and input values is helpful to illustrate their behavior. This demonstrates understanding of the formatting logic. For example:

*   `_conv(5, "02", ...)` -> "05"
*   `_conv(5, " 2", ...)` -> " 5"
*   `_yconv(2023, 1900, true, true, ...)` -> "2023"

**8. Common Usage Errors (Point 6 of the Request):**

Listing common mistakes helps users avoid pitfalls:

*   **Insufficient buffer size:** Leading to buffer overflows.
*   **Incorrect format specifiers:** Using specifiers that don't exist or are not appropriate for the given time structure.
*   **Locale issues:**  Assuming locale support where it's limited (important for this Bionic version).
*   **Two-digit year ambiguity:**  The Y2K issue is still relevant for older systems or when dealing with legacy data.

**9. Android Framework/NDK Path and Frida Hook (Point 7 of the Request):**

Tracing the execution path is crucial for understanding the function's place in the larger system:

*   **Android Framework:**  A high-level framework component (e.g., `SimpleDateFormat` in Java) might eventually call down to native code for formatting. This involves JNI calls.
*   **NDK:**  NDK developers can directly call `strftime` or related time functions from their C/C++ code.
*   **Bionic:** The NDK calls go directly to Bionic's implementation of `strftime`.

The Frida hook example demonstrates how to intercept the `strftime` call, inspect its arguments, and potentially modify its behavior. This provides a practical way to debug and understand its usage. The explanation of how to set up the hook and interpret the output is essential.

**10. Language and Structure:**

The final step is to organize the information clearly using headings and bullet points, and to provide the answers in Chinese as requested. Ensuring clarity and accuracy in the technical details is paramount. Reviewing the entire answer for consistency and completeness is the final check.
好的，让我们详细分析一下 `bionic/libc/tzcode/strftime.c` 文件的功能和实现。

**文件功能：**

`strftime.c` 文件的主要功能是将一个分解的时间戳（`struct tm`）转换为一个格式化的字符串。它实现了标准 C 库函数 `strftime` 和 `strftime_l`（在 Bionic 中，`strftime_l` 只是简单地调用 `strftime`，因为只支持 C locale）。

具体来说，它允许开发者使用各种格式化指令（以 `%` 开头）来控制输出字符串中日期和时间的表示方式。

**与 Android 功能的关系及举例说明：**

`strftime` 是 C 标准库的一部分，因此在 Android 系统中被广泛使用。任何需要将时间信息格式化为字符串的地方都可能用到它。

* **系统日志 (logcat):**  Android 的日志系统 `logcat` 经常需要记录事件发生的时间。它可能会使用 `strftime` 将时间戳格式化为易于阅读的格式。例如，日志消息的时间戳可能是 "YYYY-MM-DD HH:MM:SS.milliseconds"。
* **文件系统:**  当列出文件信息时，文件的时间戳（如修改时间）需要被格式化后显示给用户。`ls -l` 命令的输出中就包含了格式化的时间信息。
* **网络编程:**  某些网络协议可能需要在消息中包含格式化的时间戳。例如，HTTP 协议的某些头部字段会包含日期和时间。
* **应用程序开发:**  Android 应用程序（无论是 Java/Kotlin 代码通过 JNI 调用，还是使用 NDK 开发的 C/C++ 代码）可以使用 `strftime` 来格式化用户界面上显示的时间和日期，或者用于数据存储和交换。

**libc 函数的功能实现：**

下面详细解释 `strftime.c` 中主要的 libc 函数的实现方式：

1. **`strftime(char *restrict s, size_t maxsize, const char *restrict format, const struct tm *restrict t)`:**
    *   这是 `strftime` 函数的入口点。
    *   它首先保存当前的 `errno` 值，并在函数结束时恢复，以避免修改调用者的错误状态。
    *   调用 `tzset()` 函数来更新全局时区信息（这涉及到与动态链接器的交互，后面会详细解释）。
    *   调用核心格式化函数 `_fmt()` 来执行实际的格式化操作。
    *   检查 `_fmt()` 的返回值，如果返回 `NULL`，则表示输出缓冲区溢出，设置 `errno` 为 `EOVERFLOW` 并返回 0。
    *   如果定义了 `DEPRECATE_TWO_DIGIT_YEARS` 并且检测到使用了可能导致两位数年份的格式，并且设置了环境变量 `YEAR_2000_NAME`，则会向 `stderr` 输出警告信息。这主要是为了提醒开发者注意潜在的 Y2K 问题。
    *   在输出字符串的末尾添加空字符 `\0`。
    *   返回写入到缓冲区 `s` 的字符数（不包括空字符）。

2. **`strftime_l(char *restrict s, size_t maxsize, const char *restrict format, const struct tm *restrict t, ATTRIBUTE_MAYBE_UNUSED locale_t locale)`:**
    *   这是 `strftime` 的 locale-aware 版本。
    *   但在 Bionic 中，由于只支持 C locale，这个函数实际上只是简单地调用了 `strftime`，忽略了 `locale` 参数。

3. **`_fmt(const char *format, const struct tm *t, char *pt, const char *ptlim, enum warn *warnp)`:**
    *   这是 `strftime` 的核心实现函数。
    *   它遍历格式字符串 `format`。
    *   如果遇到 `%` 字符，则解析后续的格式化指令。
    *   根据不同的格式化指令，调用不同的辅助函数（如 `_add`, `_conv`, `_yconv`）来处理时间结构体 `t` 中的相应字段，并将格式化后的字符串添加到输出缓冲区 `pt`。
    *   `ptlim` 指向输出缓冲区的末尾，用于防止缓冲区溢出。
    *   `warnp` 用于记录是否使用了可能导致两位数年份的格式，以便 `strftime` 函数在必要时发出警告。
    *   支持大量的格式化指令，例如：
        *   `%Y`: 四位数的年份
        *   `%m`: 月份（01-12）
        *   `%d`: 日期（01-31）
        *   `%H`: 小时（00-23）
        *   `%M`: 分钟（00-59）
        *   `%S`: 秒（00-59）
        *   `%Z`: 时区名称或缩写
        *   `%z`: UTC 偏移
        *   等等。
    *   还支持一些修饰符，如 `_`, `-`, `0`, `^`, `#`，用于改变输出的填充方式或大小写。

4. **`_add(const char *str, char *pt, const char *const ptlim, int modifier)`:**
    *   将字符串 `str` 添加到输出缓冲区 `pt`。
    *   `modifier` 参数用于指定一些额外的处理，如强制转换为小写 (`FORCE_LOWER_CASE`)、转换为大写 (`^`) 或反转大小写 (`#`)。

5. **`_conv(int n, const char *format, char *pt, const char *ptlim)`:**
    *   将整数 `n` 转换为字符串并添加到输出缓冲区 `pt`。
    *   `format` 字符串指定了输出的格式，例如填充字符（`0` 或空格）和宽度。例如，`"02"` 表示填充 `0`，宽度为 2。
    *   该函数为了性能考虑，没有使用标准的 `snprintf`，而是自己实现了整数到字符串的转换逻辑。

6. **`_yconv(int a, int b, bool convert_top, bool convert_yy, char *pt, const char *ptlim, int modifier)`:**
    *   专门用于处理年份的转换。
    *   `a` 是年份，`b` 是基准年份（通常是 `TM_YEAR_BASE`，即 1900）。
    *   `convert_top` 控制是否转换世纪部分（用于 `%C`）。
    *   `convert_yy` 控制是否转换年份的后两位（用于 `%y`）。
    *   这个函数处理了负数年份的情况，并确保 `%C` 和 `%y` 组合起来与 `%Y` 的输出一致。

7. **`getformat(int modifier, char *normal, char *underscore, char *dash, char *zero)`:**
    *   根据修饰符 `modifier` 返回相应的格式字符串。

8. **`_safe_tm_zone(const struct tm* tm)`:** (Android 特有)
    *   这个函数是 Android 引入的，用于安全地获取时区名称。
    *   它首先尝试使用 `tm->TM_ZONE`，如果 `TM_ZONE` 为空或者未初始化，则根据 `tm->tm_isdst` 的值使用 `tzname[0]` 或 `tzname[1]`（标准时区名称或夏令时名称）。
    *   如果仍然没有找到时区信息，则返回空字符串。这避免了在 `TM_ZONE` 未设置时访问空指针的风险。

**涉及 dynamic linker 的功能及处理过程：**

`strftime.c` 本身的核心功能并不直接与 dynamic linker 交互。然而，它所依赖的一些功能和服务，特别是时区信息的加载和管理，会涉及到 dynamic linker。

*   **`tzset()` 函数:**  `strftime` 函数会调用 `tzset()` 函数来初始化或更新时区信息。`tzset()` 函数的实现通常会涉及到：
    *   读取环境变量 `TZ`。
    *   打开并解析时区信息文件（通常位于 `/usr/share/zoneinfo/` 或类似路径下）。
    *   根据读取到的信息设置全局变量，如 `timezone`、`daylight` 和 `tzname`。

*   **Dynamic Linking 的角色:**  `tzset()` 函数的实现以及时区信息文件的访问通常由 C 库（`libc.so`）提供。当一个程序调用 `strftime` 时，dynamic linker 负责将程序与 `libc.so` 链接起来，使得程序能够调用 `tzset()` 函数。

*   **SO 布局样本：**

    ```
    # objdump -T /apex/com.android.runtime/lib64/bionic/libc.so | grep tzset
    0000000000579e80 g    DF .text                00000000000000f4  LIBC    GLIBC_2.17  tzset
    ```

    这表明 `tzset` 函数在 `libc.so` 中。

*   **链接的处理过程：**
    1. 当一个程序调用 `strftime` 时，编译器会将这个函数调用编译成对 `strftime` 的符号引用。
    2. 在程序加载时，dynamic linker（如 `linker64`）会扫描程序的依赖库列表，找到 `libc.so`。
    3. dynamic linker 会解析 `libc.so` 的符号表，找到 `strftime` 函数的地址，并将程序中对 `strftime` 的符号引用替换为实际的内存地址。
    4. 当 `strftime` 函数内部调用 `tzset()` 时，也会经过类似的符号解析和地址替换过程，确保调用到 `libc.so` 中 `tzset()` 的实现。
    5. `tzset()` 的具体实现可能会涉及到打开文件（例如，`/apex/com.android.runtime/etc/tz/tzdata` 中的时区数据文件），这部分可能由操作系统内核提供支持，但 C 库提供了访问这些底层服务的接口。

**逻辑推理，假设输入与输出：**

假设我们有以下输入：

*   `format`: `"%Y-%m-%d %H:%M:%S %Z"`
*   `struct tm t`:
    *   `tm_year`: 123  (表示 1900 + 123 = 2023 年)
    *   `tm_mon`: 1    (表示 2 月，因为月份从 0 开始)
    *   `tm_mday`: 15
    *   `tm_hour`: 10
    *   `tm_min`: 30
    *   `tm_sec`: 45
    *   `tm_isdst`: 0 (非夏令时)
    *   假设当前时区设置为 `Asia/Shanghai`

输出：

```
2023-02-15 10:30:45 CST
```

**解释：**

*   `%Y` 被替换为 `2023`。
*   `%m` 被替换为 `02`。
*   `%d` 被替换为 `15`。
*   `%H` 被替换为 `10`。
*   `%M` 被替换为 `30`。
*   `%S` 被替换为 `45`。
*   `%Z` 被替换为 `CST` (中国标准时间)。

**涉及用户或者编程常见的使用错误：**

1. **缓冲区溢出:**  提供的缓冲区 `s` 的大小 `maxsize` 不足以容纳格式化后的字符串，导致内存溢出。
    ```c
    char buf[10];
    time_t timer;
    struct tm *tm_info;
    time(&timer);
    tm_info = localtime(&timer);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info); // 如果时间字符串超过 9 个字符，就会溢出
    ```

2. **错误的格式化字符串:**  使用了不存在或错误的格式化指令。虽然 `strftime` 通常会忽略未知的格式化字符，但可能会导致输出不符合预期。
    ```c
    strftime(buf, sizeof(buf), "%QQQQ", tm_info); // "%Q" 不是有效的格式化指令
    ```

3. **未初始化的 `struct tm`:**  将未初始化的 `struct tm` 结构体传递给 `strftime`，会导致未定义的行为。
    ```c
    struct tm tm_info; // 未初始化
    strftime(buf, sizeof(buf), "%Y", &tm_info);
    ```

4. **假设时区已正确设置:**  在某些情况下，如果时区没有正确设置，`strftime` 中与时区相关的格式化指令（如 `%Z`, `%z`) 可能输出错误的信息。

5. **忽略返回值:**  `strftime` 返回写入缓冲区的字符数。忽略返回值可能导致没有正确处理输出结果。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `strftime` 的路径 (示例):**

1. **Java 代码:** Android Framework 中的 Java 类，例如 `java.text.SimpleDateFormat`，用于格式化日期和时间。
2. **Native 方法调用:** `SimpleDateFormat` 内部最终会调用底层的 native 方法来执行格式化。这通常涉及 JNI (Java Native Interface)。
3. **`libicu_jni.so` 或其他 JNI 桥接库:**  这些库包含了 Java 代码调用的 native 方法的实现。例如，`SimpleDateFormat` 可能会调用 `icu4c` 库（International Components for Unicode），或者在某些情况下，直接调用 Bionic 提供的函数。
4. **Bionic C 库:** 如果最终的实现依赖于 Bionic 的 `strftime`，那么 JNI 代码会调用 Bionic 中 `time.h` 声明的 `strftime` 函数。

**NDK 到 `strftime` 的路径:**

1. **C/C++ 代码:**  使用 NDK 开发的应用程序可以直接调用标准 C 库函数，包括 `strftime`。
2. **Bionic C 库:**  NDK 应用程序链接到 Bionic C 库 (`libc.so`)，当调用 `strftime` 时，会执行 `bionic/libc/tzcode/strftime.c` 中的代码。

**Frida Hook 示例：**

以下是一个使用 Frida hook `strftime` 函数的示例：

```javascript
function hook_strftime() {
    const strftimePtr = Module.findExportByName("libc.so", "strftime");
    if (strftimePtr) {
        Interceptor.attach(strftimePtr, {
            onEnter: function (args) {
                const buf = args[0];
                const maxsize = args[1].toInt();
                const format = Memory.readUtf8String(args[2]);
                const tmPtr = args[3];

                const tm_sec = Memory.readInt(tmPtr.add(0));
                const tm_min = Memory.readInt(tmPtr.add(4));
                const tm_hour = Memory.readInt(tmPtr.add(8));
                const tm_mday = Memory.readInt(tmPtr.add(12));
                const tm_mon = Memory.readInt(tmPtr.add(16));
                const tm_year = Memory.readInt(tmPtr.add(20));
                const tm_wday = Memory.readInt(tmPtr.add(24));
                const tm_yday = Memory.readInt(tmPtr.add(28));
                const tm_isdst = Memory.readInt(tmPtr.add(32));

                console.log("strftime called with:");
                console.log("  Buffer:", buf);
                console.log("  Max size:", maxsize);
                console.log("  Format:", format);
                console.log("  struct tm:");
                console.log("    tm_sec:", tm_sec);
                console.log("    tm_min:", tm_min);
                console.log("    tm_hour:", tm_hour);
                console.log("    tm_mday:", tm_mday);
                console.log("    tm_mon:", tm_mon);
                console.log("    tm_year:", tm_year);
                console.log("    tm_wday:", tm_wday);
                console.log("    tm_yday:", tm_yday);
                console.log("    tm_isdst:", tm_isdst);
            },
            onLeave: function (retval) {
                console.log("strftime returned:", retval.toInt());
                if (retval.toInt() > 0) {
                    const result = Memory.readUtf8String(this.context.r0);
                    console.log("  Resulting string:", result);
                }
            }
        });
    } else {
        console.log("Failed to find strftime in libc.so");
    }
}

setImmediate(hook_strftime);
```

**Frida Hook 调试步骤：**

1. **准备环境:** 确保你的设备已 root，并且安装了 Frida 和 Frida-server。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_strftime.js`。
3. **运行 Frida 脚本:** 使用 Frida 命令将脚本附加到目标进程。你需要找到目标进程的进程 ID 或应用程序包名。
    ```bash
    frida -U -f <应用程序包名> --no-pause -l hook_strftime.js
    # 或
    frida -U <进程ID> -l hook_strftime.js
    ```
4. **触发 `strftime` 调用:** 在目标应用程序中执行某些操作，这些操作会导致调用 `strftime` 函数。例如，打开一个显示时间信息的界面，或者执行一个记录时间戳的操作。
5. **查看 Frida 输出:** Frida 会拦截对 `strftime` 的调用，并在控制台上打印出 `onEnter` 和 `onLeave` 中记录的信息，包括传入的参数和返回值，以及格式化后的字符串。

通过这个 Frida Hook 示例，你可以观察到哪些地方调用了 `strftime`，使用了什么样的格式化字符串，以及传入的时间结构体的值，从而更好地理解 `strftime` 在 Android 系统中的使用方式。

Prompt: 
```
这是目录为bionic/libc/tzcode/strftime.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/* Convert a broken-down timestamp to a string.  */

/* Copyright 1989 The Regents of the University of California.
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the University nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
   SUCH DAMAGE.  */

/*
** Based on the UCB version with the copyright notice appearing above.
**
** This is ANSIish only when "multibyte character == plain character".
*/

#include "private.h"

#include <fcntl.h>
#include <locale.h>
#include <stdio.h>

#ifndef DEPRECATE_TWO_DIGIT_YEARS
# define DEPRECATE_TWO_DIGIT_YEARS false
#endif

#if defined(__BIONIC__)

/* LP32 had a 32-bit time_t, so we need to work around that here. */
#if defined(__LP64__)
#define time64_t time_t
#define mktime64 mktime
#define localtime64_r localtime_r
#else
#include <time64.h>
#endif

#include <ctype.h>

#endif

struct lc_time_T {
    const char *    mon[MONSPERYEAR];
    const char *    month[MONSPERYEAR];
    const char *    wday[DAYSPERWEEK];
    const char *    weekday[DAYSPERWEEK];
    const char *    X_fmt;
    const char *    x_fmt;
    const char *    c_fmt;
    const char *    am;
    const char *    pm;
    const char *    date_fmt;
};

static const struct lc_time_T   C_time_locale = {
    {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    }, {
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    }, {
        "Sun", "Mon", "Tue", "Wed",
        "Thu", "Fri", "Sat"
    }, {
        "Sunday", "Monday", "Tuesday", "Wednesday",
        "Thursday", "Friday", "Saturday"
    },

    /* X_fmt */
    "%H:%M:%S",

    /*
    ** x_fmt
    ** C99 and later require this format.
    ** Using just numbers (as here) makes Quakers happier;
    ** it's also compatible with SVR4.
    */
    "%m/%d/%y",

    /*
    ** c_fmt
    ** C99 and later require this format.
    ** Previously this code used "%D %X", but we now conform to C99.
    ** Note that
    **  "%a %b %d %H:%M:%S %Y"
    ** is used by Solaris 2.3.
    */
    "%a %b %e %T %Y",

    /* am */
    "AM",

    /* pm */
    "PM",

    /* date_fmt */
    "%a %b %e %H:%M:%S %Z %Y"
};

enum warn { IN_NONE, IN_SOME, IN_THIS, IN_ALL };

static char *   _add(const char *, char *, const char *, int);
static char *   _conv(int, const char *, char *, const char *);
static char *   _fmt(const char *, const struct tm *, char *, const char *,
            enum warn *);
static char *   _yconv(int, int, bool, bool, char *, const char *, int);

#ifndef YEAR_2000_NAME
# define YEAR_2000_NAME  "CHECK_STRFTIME_FORMATS_FOR_TWO_DIGIT_YEARS"
#endif /* !defined YEAR_2000_NAME */

#if HAVE_STRFTIME_L
size_t
strftime_l(char *restrict s, size_t maxsize, char const *restrict format,
	   struct tm const *restrict t,
	   ATTRIBUTE_MAYBE_UNUSED locale_t locale)
{
  /* Just call strftime, as only the C locale is supported.  */
  return strftime(s, maxsize, format, t);
}
#endif

#define FORCE_LOWER_CASE 0x100 /* Android extension. */

size_t
strftime(char *restrict s, size_t maxsize, char const *restrict format,
	 struct tm const *restrict t)
{
    char *  p;
    int saved_errno = errno;
    enum warn warn = IN_NONE;

    tzset();
    p = _fmt(format, t, s, s + maxsize, &warn);
    if (!p) {
       errno = EOVERFLOW;
       return 0;
    }
    if (DEPRECATE_TWO_DIGIT_YEARS
          && warn != IN_NONE && getenv(YEAR_2000_NAME)) {
        fprintf(stderr, "\n");
        fprintf(stderr, "strftime format \"%s\" ", format);
        fprintf(stderr, "yields only two digits of years in ");
        if (warn == IN_SOME)
            fprintf(stderr, "some locales");
        else if (warn == IN_THIS)
            fprintf(stderr, "the current locale");
        else    fprintf(stderr, "all locales");
        fprintf(stderr, "\n");
    }
    if (p == s + maxsize) {
        errno = ERANGE;
        return 0;
    }
    *p = '\0';
    errno = saved_errno;
    return p - s;
}

static char *getformat(int modifier, char *normal, char *underscore,
                       char *dash, char *zero) {
    switch (modifier) {
    case '_':
        return underscore;
    case '-':
        return dash;
    case '0':
        return zero;
    }
    return normal;
}

// Android-added: fall back mechanism when TM_ZONE is not initialized.
#ifdef TM_ZONE
static const char* _safe_tm_zone(const struct tm* tm) {
  const char* zone = tm->TM_ZONE;
  if (!zone || !*zone) {
    // "The value of tm_isdst shall be positive if Daylight Savings Time is
    // in effect, 0 if Daylight Savings Time is not in effect, and negative
    // if the information is not available."
    if (tm->tm_isdst == 0) {
      zone = tzname[0];
    } else if (tm->tm_isdst > 0) {
      zone = tzname[1];
    }

    // "Replaced by the timezone name or abbreviation, or by no bytes if no
    // timezone information exists."
    if (!zone || !*zone) zone = "";
  }

  return zone;
}
#endif

static char *
_fmt(const char *format, const struct tm *t, char *pt,
        const char *ptlim, enum warn *warnp)
{
	struct lc_time_T const *Locale = &C_time_locale;

    for ( ; *format; ++format) {
        if (*format == '%') {
            int modifier = 0;
label:
            switch (*++format) {
            case '\0':
                --format;
                break;
            case 'A':
                pt = _add((t->tm_wday < 0 ||
                    t->tm_wday >= DAYSPERWEEK) ?
                    "?" : Locale->weekday[t->tm_wday],
                    pt, ptlim, modifier);
                continue;
            case 'a':
                pt = _add((t->tm_wday < 0 ||
                    t->tm_wday >= DAYSPERWEEK) ?
                    "?" : Locale->wday[t->tm_wday],
                    pt, ptlim, modifier);
                continue;
            case 'B':
                pt = _add((t->tm_mon < 0 ||
                                t->tm_mon >= MONSPERYEAR) ?
                                "?" : Locale->month[t->tm_mon],
                                pt, ptlim, modifier);
                continue;
            case 'b':
            case 'h':
                pt = _add((t->tm_mon < 0 ||
                    t->tm_mon >= MONSPERYEAR) ?
                    "?" : Locale->mon[t->tm_mon],
                    pt, ptlim, modifier);
                continue;
            case 'C':
                /*
                ** %C used to do a...
                **  _fmt("%a %b %e %X %Y", t);
                ** ...whereas now POSIX 1003.2 calls for
                ** something completely different.
                ** (ado, 1993-05-24)
                */
                pt = _yconv(t->tm_year, TM_YEAR_BASE,
                    true, false, pt, ptlim, modifier);
                continue;
            case 'c':
                {
                enum warn warn2 = IN_SOME;

                pt = _fmt(Locale->c_fmt, t, pt, ptlim, &warn2);
                if (warn2 == IN_ALL)
                    warn2 = IN_THIS;
                if (warn2 > *warnp)
                    *warnp = warn2;
                }
                continue;
            case 'D':
                                pt = _fmt("%m/%d/%y", t, pt, ptlim, warnp);
                continue;
            case 'd':
              pt = _conv(t->tm_mday, getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 'E':
            case 'O':
                /*
                ** Locale modifiers of C99 and later.
                ** The sequences
                **  %Ec %EC %Ex %EX %Ey %EY
                **  %Od %oe %OH %OI %Om %OM
                **  %OS %Ou %OU %OV %Ow %OW %Oy
                ** are supposed to provide alternative
                ** representations.
                */
                goto label;
            case '_':
            case '-':
            case '0':
            case '^':
            case '#':
                modifier = *format;
                goto label;
            case 'e':
              pt = _conv(t->tm_mday, getformat(modifier, " 2", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 'F':
                pt = _fmt("%Y-%m-%d", t, pt, ptlim, warnp);
                continue;
            case 'H':
              pt = _conv(t->tm_hour, getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 'I':
              pt = _conv((t->tm_hour % 12) ? (t->tm_hour % 12) : 12,
                         getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 'j':
              pt = _conv(t->tm_yday + 1, getformat(modifier, "03", " 3", "  ", "03"), pt, ptlim);
              continue;
            case 'k':
                /*
                ** This used to be...
                **  _conv(t->tm_hour % 12 ?
                **      t->tm_hour % 12 : 12, 2, ' ');
                ** ...and has been changed to the below to
                ** match SunOS 4.1.1 and Arnold Robbins'
                ** strftime version 3.0. That is, "%k" and
                ** "%l" have been swapped.
                ** (ado, 1993-05-24)
                */
                pt = _conv(t->tm_hour, getformat(modifier, " 2", " 2", "  ", "02"), pt, ptlim);
                continue;
#ifdef KITCHEN_SINK
            case 'K':
                /*
                ** After all this time, still unclaimed!
                */
                pt = _add("kitchen sink", pt, ptlim);
                continue;
#endif /* defined KITCHEN_SINK */
            case 'l':
                /*
                ** This used to be...
                **  _conv(t->tm_hour, 2, ' ');
                ** ...and has been changed to the below to
                ** match SunOS 4.1.1 and Arnold Robbin's
                ** strftime version 3.0. That is, "%k" and
                ** "%l" have been swapped.
                ** (ado, 1993-05-24)
                */
                pt = _conv((t->tm_hour % 12) ? (t->tm_hour % 12) : 12,
                           getformat(modifier, " 2", " 2", "  ", "02"), pt, ptlim);
                continue;
            case 'M':
              pt = _conv(t->tm_min, getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 'm':
              pt = _conv(t->tm_mon + 1, getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 'n':
                pt = _add("\n", pt, ptlim, modifier);
                continue;
            case 'P':
            case 'p':
                pt = _add((t->tm_hour >= (HOURSPERDAY / 2)) ?
                    Locale->pm :
                    Locale->am,
                    pt, ptlim, (*format == 'P') ? FORCE_LOWER_CASE : modifier);
                continue;
            case 'R':
                pt = _fmt("%H:%M", t, pt, ptlim, warnp);
                continue;
            case 'r':
                pt = _fmt("%I:%M:%S %p", t, pt, ptlim, warnp);
                continue;
            case 'S':
              pt = _conv(t->tm_sec, getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 's':
                {
                    struct tm   tm;
                    char buf[INT_STRLEN_MAXIMUM(time64_t) + 1] __attribute__((__uninitialized__));
                    time64_t    mkt;

          					tm.tm_sec = t->tm_sec;
					          tm.tm_min = t->tm_min;
          					tm.tm_hour = t->tm_hour;
					          tm.tm_mday = t->tm_mday;
          					tm.tm_mon = t->tm_mon;
					          tm.tm_year = t->tm_year;
          					tm.tm_isdst = t->tm_isdst;
#if defined TM_GMTOFF && ! UNINIT_TRAP
					          tm.TM_GMTOFF = t->TM_GMTOFF;
#endif
                    mkt = mktime64(&tm);
					/* If mktime fails, %s expands to the
              value of (time_t) -1 as a failure
              marker; this is better in practice
              than strftime failing.  */
                    if (TYPE_SIGNED(time64_t)) {
                      intmax_t n = mkt;
                      sprintf(buf, "%"PRIdMAX, n);
                    } else {
                      uintmax_t n = mkt;
                      sprintf(buf, "%"PRIuMAX, n);
                    }
                    pt = _add(buf, pt, ptlim, modifier);
                }
                continue;
            case 'T':
                pt = _fmt("%H:%M:%S", t, pt, ptlim, warnp);
                continue;
            case 't':
                pt = _add("\t", pt, ptlim, modifier);
                continue;
            case 'U':
              pt = _conv((t->tm_yday + DAYSPERWEEK - t->tm_wday) / DAYSPERWEEK,
                         getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 'u':
                /*
                ** From Arnold Robbins' strftime version 3.0:
                ** "ISO 8601: Weekday as a decimal number
                ** [1 (Monday) - 7]"
                ** (ado, 1993-05-24)
                */
                pt = _conv((t->tm_wday == 0) ? DAYSPERWEEK : t->tm_wday, "  ", pt, ptlim);
                continue;
            case 'V':   /* ISO 8601 week number */
            case 'G':   /* ISO 8601 year (four digits) */
            case 'g':   /* ISO 8601 year (two digits) */
/*
** From Arnold Robbins' strftime version 3.0: "the week number of the
** year (the first Monday as the first day of week 1) as a decimal number
** (01-53)."
** (ado, 1993-05-24)
**
** From <https://www.cl.cam.ac.uk/~mgk25/iso-time.html> by Markus Kuhn:
** "Week 01 of a year is per definition the first week which has the
** Thursday in this year, which is equivalent to the week which contains
** the fourth day of January. In other words, the first week of a new year
** is the week which has the majority of its days in the new year. Week 01
** might also contain days from the previous year and the week before week
** 01 of a year is the last week (52 or 53) of the previous year even if
** it contains days from the new year. A week starts with Monday (day 1)
** and ends with Sunday (day 7). For example, the first week of the year
** 1997 lasts from 1996-12-30 to 1997-01-05..."
** (ado, 1996-01-02)
*/
                {
                    int year;
                    int base;
                    int yday;
                    int wday;
                    int w;

                    year = t->tm_year;
                    base = TM_YEAR_BASE;
                    yday = t->tm_yday;
                    wday = t->tm_wday;
                    for ( ; ; ) {
                        int len;
                        int bot;
                        int top;

                        len = isleap_sum(year, base) ?
                            DAYSPERLYEAR :
                            DAYSPERNYEAR;
                        /*
                        ** What yday (-3 ... 3) does
                        ** the ISO year begin on?
                        */
                        bot = ((yday + 11 - wday) %
                            DAYSPERWEEK) - 3;
                        /*
                        ** What yday does the NEXT
                        ** ISO year begin on?
                        */
                        top = bot -
                            (len % DAYSPERWEEK);
                        if (top < -3)
                            top += DAYSPERWEEK;
                        top += len;
                        if (yday >= top) {
                            ++base;
                            w = 1;
                            break;
                        }
                        if (yday >= bot) {
                            w = 1 + ((yday - bot) /
                                DAYSPERWEEK);
                            break;
                        }
                        --base;
                        yday += isleap_sum(year, base) ?
                            DAYSPERLYEAR :
                            DAYSPERNYEAR;
                    }
#ifdef XPG4_1994_04_09
                    if ((w == 52 &&
                        t->tm_mon == TM_JANUARY) ||
                        (w == 1 &&
                        t->tm_mon == TM_DECEMBER))
                            w = 53;
#endif /* defined XPG4_1994_04_09 */
                    if (*format == 'V')
                      pt = _conv(w, getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
                    else if (*format == 'g') {
                        *warnp = IN_ALL;
                        pt = _yconv(year, base,
                            false, true,
                            pt, ptlim, modifier);
                    } else  pt = _yconv(year, base,
                            true, true,
                            pt, ptlim, modifier);
                }
                continue;
            case 'v':
                /*
                ** From Arnold Robbins' strftime version 3.0:
                ** "date as dd-bbb-YYYY"
                ** (ado, 1993-05-24)
                */
                pt = _fmt("%e-%b-%Y", t, pt, ptlim, warnp);
                continue;
            case 'W':
              pt = _conv(
                  (t->tm_yday + DAYSPERWEEK - (t->tm_wday ? (t->tm_wday - 1) : (DAYSPERWEEK - 1))) /
                      DAYSPERWEEK,
                  getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
              continue;
            case 'w':
              pt = _conv(t->tm_wday, "  ", pt, ptlim);
              continue;
            case 'X':
                pt = _fmt(Locale->X_fmt, t, pt, ptlim, warnp);
                continue;
            case 'x':
                {
                enum warn warn2 = IN_SOME;

                pt = _fmt(Locale->x_fmt, t, pt, ptlim, &warn2);
                if (warn2 == IN_ALL)
                    warn2 = IN_THIS;
                if (warn2 > *warnp)
                    *warnp = warn2;
                }
                continue;
            case 'y':
                *warnp = IN_ALL;
                pt = _yconv(t->tm_year, TM_YEAR_BASE,
                    false, true,
                    pt, ptlim, modifier);
                continue;
            case 'Y':
                pt = _yconv(t->tm_year, TM_YEAR_BASE,
                    true, true,
                    pt, ptlim, modifier);
                continue;
            case 'Z':
#ifdef TM_ZONE
                // BEGIN: Android-changed.
                pt = _add(_safe_tm_zone(t), pt, ptlim, modifier);
                // END: Android-changed.
#elif HAVE_TZNAME
                if (t->tm_isdst >= 0)
                    pt = _add(tzname[t->tm_isdst != 0],
                        pt, ptlim);
#endif
                /*
                ** C99 and later say that %Z must be
                ** replaced by the empty string if the
                ** time zone abbreviation is not
                ** determinable.
                */
                continue;
            case 'z':
#if defined TM_GMTOFF || USG_COMPAT || ALTZONE
                {
                long     diff;
                char const *    sign;
                bool negative;

# ifdef TM_GMTOFF
                diff = t->TM_GMTOFF;
# else
                /*
                ** C99 and later say that the UT offset must
                ** be computed by looking only at
                ** tm_isdst. This requirement is
                ** incorrect, since it means the code
                ** must rely on magic (in this case
                ** altzone and timezone), and the
                ** magic might not have the correct
                ** offset. Doing things correctly is
                ** tricky and requires disobeying the standard;
                ** see GNU C strftime for details.
                ** For now, punt and conform to the
                ** standard, even though it's incorrect.
                **
                ** C99 and later say that %z must be replaced by
                ** the empty string if the time zone is not
                ** determinable, so output nothing if the
                ** appropriate variables are not available.
                */
                if (t->tm_isdst < 0)
                    continue;
                if (t->tm_isdst == 0)
#  if USG_COMPAT
                    diff = -timezone;
#  else
                    continue;
#  endif
                else
#  if ALTZONE
                    diff = -altzone;
#  else
                    continue;
#  endif
# endif
                negative = diff < 0;
                if (diff == 0) {
# ifdef TM_ZONE
                  // Android-changed: do not use TM_ZONE as it is as it may be null.
                  {
                    const char* zone = _safe_tm_zone(t);
                    negative = zone[0] == '-';
                  }
# else
                    negative = t->tm_isdst < 0;
#  if HAVE_TZNAME
                    if (tzname[t->tm_isdst != 0][0] == '-')
                        negative = true;
#  endif
# endif
                }
                if (negative) {
                    sign = "-";
                    diff = -diff;
                } else  sign = "+";
                pt = _add(sign, pt, ptlim, modifier);
                diff /= SECSPERMIN;
                diff = (diff / MINSPERHOUR) * 100 +
                    (diff % MINSPERHOUR);
                pt = _conv(diff, getformat(modifier, "04", " 4", "  ", "04"), pt, ptlim);
                }
#endif
                continue;
            case '+':
                pt = _fmt(Locale->date_fmt, t, pt, ptlim,
                    warnp);
                continue;
            case '%':
            /*
            ** X311J/88-090 (4.12.3.5): if conversion char is
            ** undefined, behavior is undefined. Print out the
            ** character itself as printf(3) also does.
            */
            default:
                break;
            }
        }
        if (pt == ptlim)
            break;
        *pt++ = *format;
    }
    return pt;
}

static char *
_conv(int n, const char *format, char *pt, const char *ptlim)
{
  // The original implementation used snprintf(3) here, but rolling our own is
  // about 5x faster. Seems like a good trade-off for so little code, especially
  // for users like logcat that have a habit of formatting 10k times all at
  // once...

  // Format is '0' or ' ' for the fill character, followed by a single-digit
  // width or ' ' for "whatever".
  //   %d -> "  "
  //  %2d -> " 2"
  // %02d -> "02"
  char fill = format[0];
  int width = format[1] == ' ' ? 0 : format[1] - '0';

  char buf[32] __attribute__((__uninitialized__));

  // Terminate first, so we can walk backwards from the least-significant digit
  // without having to later reverse the result.
  char* p = &buf[31];
  *--p = '\0';
  char* end = p;

  // Output digits backwards, from least-significant to most.
  while (n >= 10) {
    *--p = '0' + (n % 10);
    n /= 10;
  }
  *--p = '0' + n;

  // Fill if more digits are required by the format.
  while ((end - p) < width) {
    *--p = fill;
  }

  return _add(p, pt, ptlim, 0);
}

static char *
_add(const char *str, char *pt, const char *const ptlim, int modifier)
{
        int c;

        switch (modifier) {
        case FORCE_LOWER_CASE:
                while (pt < ptlim && (*pt = tolower(*str++)) != '\0') {
                        ++pt;
                }
                break;

        case '^':
                while (pt < ptlim && (*pt = toupper(*str++)) != '\0') {
                        ++pt;
                }
                break;

        case '#':
                while (pt < ptlim && (c = *str++) != '\0') {
                        if (isupper(c)) {
                                c = tolower(c);
                        } else if (islower(c)) {
                                c = toupper(c);
                        }
                        *pt = c;
                        ++pt;
                }

                break;

        default:
                while (pt < ptlim && (*pt = *str++) != '\0') {
                        ++pt;
                }
        }

    return pt;
}

/*
** POSIX and the C Standard are unclear or inconsistent about
** what %C and %y do if the year is negative or exceeds 9999.
** Use the convention that %C concatenated with %y yields the
** same output as %Y, and that %Y contains at least 4 bytes,
** with more only if necessary.
*/

static char *
_yconv(int a, int b, bool convert_top, bool convert_yy,
       char *pt, const char *ptlim, int modifier)
{
    register int    lead;
    register int    trail;

    int DIVISOR = 100;
    trail = a % DIVISOR + b % DIVISOR;
    lead = a / DIVISOR + b / DIVISOR + trail / DIVISOR;
    trail %= DIVISOR;
    if (trail < 0 && lead > 0) {
        trail += DIVISOR;
        --lead;
    } else if (lead < 0 && trail > 0) {
        trail -= DIVISOR;
        ++lead;
    }
    if (convert_top) {
        if (lead == 0 && trail < 0)
            pt = _add("-0", pt, ptlim, modifier);
        else
          pt = _conv(lead, getformat(modifier, "02", " 2", "  ", "02"), pt, ptlim);
    }
    if (convert_yy)
      pt = _conv(((trail < 0) ? -trail : trail), getformat(modifier, "02", " 2", "  ", "02"), pt,
                 ptlim);
    return pt;
}

"""

```