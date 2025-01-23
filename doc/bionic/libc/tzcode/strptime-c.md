Response:
Let's break down the thought process for analyzing the `strptime.c` code and generating the comprehensive response.

**1. Understanding the Request:**

The core request is to analyze the `strptime.c` file, which is part of Android's Bionic libc. The analysis should cover its functionality, relationship to Android, internal implementation details (especially libc functions and dynamic linking), common usage errors, and how it's accessed from higher levels (Android Framework/NDK). The request also asks for Frida hook examples.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for important keywords and patterns. This helps in forming a high-level understanding:

* **Headers:** `<ctype.h>`, `<errno.h>`, `<limits.h>`, `<locale.h>`, `<stdlib.h>`, `<string.h>`, `<time.h>` are standard C library headers, indicating core C functionality. `"private.h"`, `"localedef.h"`, `"tzfile.h"` suggest internal Bionic/glibc dependencies related to time and localization.
* **Function Signature:** `char *strptime(const char *buf, const char *fmt, struct tm *tm)` is the central function. This immediately tells us its purpose: parsing a time string according to a format string and storing the result in a `struct tm`.
* **Macros:**  `_ctloc`, `_ALT_E`, `_ALT_O`, `_LEGAL_ALT`, `FIELD_TM_*` are used for internal logic, likely for locale handling and tracking which time fields have been parsed.
* **Static Data:** `gmt`, `utc`, `nast`, `nadt`, `mon_lengths` are constant arrays, likely used for matching time zone abbreviations and month lengths.
* **Static Functions:** `_conv_num`, `epoch_to_tm`, `leaps_thru_end_of`, `_strptime`, `_find_string` are internal helper functions.
* **Android Specifics:** The comments "// Android:" highlight Android-specific adjustments or considerations.

**3. Dissecting Functionality:**

Based on the function signature and the internal logic, the core functionality is clear: parsing a date/time string. The format string (`fmt`) guides the parsing process. Key aspects of the functionality include:

* **Format Specifiers:**  The code handles various format specifiers (e.g., `%Y`, `%m`, `%d`, `%H`, `%M`, `%S`, `%Z`).
* **Locale Awareness:**  The use of `_ctloc` indicates that the parsing is locale-aware, meaning it can handle different date/time formats and month/day names based on the current locale.
* **Error Handling:**  The function returns `NULL` on parsing errors.
* **Partial Parsing:** The code appears to handle cases where the input string doesn't match the entire format.

**4. Identifying Android Relevance:**

The "// Android:" comments directly point to Android-specific adaptations. The mention of `strftime()` compatibility suggests that Android has tailored the implementation to align with the behavior of the `strftime()` function. The ignored `-Wpointer-sign` warnings indicate areas where the code might not strictly adhere to modern pointer safety guidelines, which is a common consideration in legacy codebases.

**5. Deep Dive into Libc Functions:**

For each libc function used, the explanation should cover its standard purpose and how it's used within `strptime.c`. For example:

* `isspace()`:  Used to skip whitespace.
* `strncasecmp()`: Used for case-insensitive string comparison of month and day names.
* `strlen()`: Used to determine the length of locale-specific strings.
* `isdigit()`: Used to check if a character is a digit.
* `strtoll()`: Used to convert a string to a long long integer (specifically for parsing seconds since the epoch).
* `localtime_r()`: Used to convert a timestamp (seconds since the epoch) to a `struct tm` in the local timezone.
* `tzset()`:  Used to initialize the timezone information from the environment.

**6. Dynamic Linking Considerations (Initially Not Directly Obvious):**

The code itself doesn't *explicitly* call dynamic linking functions like `dlopen` or `dlsym`. However, the reliance on locale data (`_ctloc`) and timezone information (`tzset`, `tzname`, `timezone`) implies interaction with the dynamic linker. The locale data and timezone information are typically loaded dynamically.

* **Hypothesizing SO Layout:**  Based on common Android library structure, `libc.so` would contain `strptime`. Locale data and timezone data would likely reside in separate shared objects or data files loaded by `libc.so`.
* **Linking Process:** When `strptime` is called, the dynamic linker ensures that the necessary locale and timezone data is available. This might involve resolving symbols and loading shared objects at runtime.

**7. Logic Inference and Examples:**

For demonstrating logic, creating concrete input/output examples is crucial. This helps clarify how the format specifiers work and how the parsing occurs. Think of various format combinations and their expected outcomes.

**8. Common Usage Errors:**

Consider common mistakes developers make when using `strptime`:

* **Incorrect Format String:** The most frequent error.
* **Insufficient Buffer Size (although `strptime` doesn't directly use output buffers, the caller needs to handle the input string correctly).**
* **Locale Issues:**  Assuming a specific date format without considering the current locale.
* **Timezone Problems:**  Not understanding how timezone information affects parsing.

**9. Android Framework/NDK Interaction and Frida Hooking:**

* **Tracing the Call Stack:**  Think about how date/time parsing is used in Android. The Android Framework (Java/Kotlin code) often needs to parse dates received from network requests, user input, etc. This usually involves using Java's `SimpleDateFormat` or similar classes, which internally might call down to native code (`strptime`). NDK developers directly use C/C++, so they can call `strptime` directly.
* **Frida Hooking:**  Identify key points in the execution flow to hook with Frida. Hooking the entry point of `strptime` is the most straightforward. Hooking internal functions like `_conv_num` can provide more granular insight.

**10. Structuring the Response:**

Organize the information logically, using headings and bullet points for clarity. Start with a high-level overview, then delve into details, and finally provide examples and debugging techniques. Use clear and concise language, explaining technical terms when necessary.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Focus heavily on direct dynamic linking calls within the `strptime.c` code.
* **Correction:** Realize that the dynamic linking interaction is more implicit through the use of locale and timezone functions. Adjust the explanation accordingly.
* **Initial Thought:**  Provide very basic usage examples.
* **Correction:** Create more comprehensive examples covering different format specifiers and potential edge cases.
* **Initial Thought:** Briefly mention Frida.
* **Correction:** Provide more detailed Frida hook examples with explanations of how to use them.

By following this structured approach, combined with careful reading of the code and consideration of the request's different aspects, a comprehensive and accurate response can be generated.
好的，我们来详细分析一下 `bionic/libc/tzcode/strptime.c` 这个文件。

**strptime.c 的功能**

`strptime.c` 文件实现了 `strptime` 函数，其主要功能是将一个表示日期和时间的字符串根据指定的格式进行解析，并将解析结果存储在一个 `struct tm` 结构体中。简单来说，它就是将字符串形式的时间转换为计算机可以理解的时间结构。

**与 Android 功能的关系及举例说明**

`strptime` 函数是 C 标准库函数，在 Android Bionic 中作为 libc 的一部分提供，因此它被广泛用于 Android 系统和应用程序中处理日期和时间相关的字符串解析。

**举例说明:**

* **系统时间解析:** Android 系统在启动、接收网络时间同步等过程中，可能需要解析各种格式的时间字符串，例如从 NTP 服务器获取的时间信息。
* **日志处理:**  许多 Android 系统组件和应用程序会生成包含时间戳的日志。解析这些日志文件时，可能需要使用 `strptime` 将日志中的时间字符串转换为 `struct tm`以便进行进一步处理和分析。
* **应用开发:** Android 应用程序，尤其是涉及到日历、日程安排、时间显示等功能的应用，很可能需要解析用户输入的日期和时间字符串，或者解析从服务器端接收到的日期和时间数据。例如，用户在日历应用中输入一个事件的开始时间 "2023-12-25 10:00"，应用可以使用 `strptime` 将其转换为 `struct tm` 结构，方便存储和计算。

**详细解释每一个 libc 函数的功能是如何实现的**

以下是 `strptime.c` 中使用到的关键 libc 函数的功能和简要实现说明：

* **`ctype.h` 中的函数 (`isspace`, `isdigit`):**
    * **`isspace(int c)`:** 检查字符 `c` 是否是空白字符（空格、制表符、换行符等）。`strptime` 使用它来跳过输入字符串和格式字符串中的空白。
    * **`isdigit(int c)`:** 检查字符 `c` 是否是数字字符（'0' 到 '9'）。`strptime` 使用它来判断输入字符串中是否是数字，用于解析数值型的日期和时间部分。
    * **实现:** 这些函数通常通过查表来实现，根据字符的 ASCII 值或其他编码值，在预先定义的表中查找该字符的属性。

* **`errno.h` 中的 `errno`:**
    * **`errno`:**  是一个全局变量，用于指示最近一次系统调用或库函数调用是否发生错误。如果发生错误，`errno` 会被设置为一个特定的错误码。
    * **`strptime` 的使用:** `strptime` 在内部调用 `strtoll` 解析秒数时，会保存和恢复 `errno` 的值，以避免 `strtoll` 的错误影响到 `strptime` 自身的错误判断。

* **`limits.h` 中的 `LLONG_MAX`:**
    * **`LLONG_MAX`:** 定义了 `long long` 数据类型的最大值。
    * **`strptime` 的使用:** 在解析秒数时，`strptime` 会检查 `strtoll` 的返回值是否等于 `LLONG_MAX` 且 `errno` 为 `ERANGE`，以判断是否发生了溢出错误。

* **`locale.h` 中的 `locale` 相关:**
    * **`locale`:**  用于定义特定文化或地域的习惯，包括日期和时间的格式、货币符号等。
    * **`strptime` 的使用:** `strptime` 通过 `_ctloc` 宏访问当前 locale 的日期和时间格式信息，例如月份和星期的名称、AM/PM 表示等。这些信息存储在 `localedef.h` 中定义的结构体中。

* **`stdlib.h` 中的函数 (`strtoll`):**
    * **`strtoll(const char *nptr, char **endptr, int base)`:** 将字符串 `nptr` 转换为 `long long` 类型的整数。`endptr` 指向转换停止的字符位置，`base` 是进制。
    * **`strptime` 的使用:** 用于解析以秒为单位表示的时间戳（`%s` 格式）。

* **`string.h` 中的函数 (`strlen`, `strncasecmp`, `strncmp`):**
    * **`strlen(const char *s)`:** 计算字符串 `s` 的长度，不包括结尾的空字符。
    * **`strncasecmp(const char *s1, const char *s2, size_t n)`:** 对字符串 `s1` 和 `s2` 的前 `n` 个字符进行不区分大小写的比较。
    * **`strncmp(const char *s1, const char *s2, size_t n)`:** 对字符串 `s1` 和 `s2` 的前 `n` 个字符进行区分大小写的比较。
    * **`strptime` 的使用:** 这些函数用于比较输入字符串与 locale 中定义的月份名、星期名、时区缩写等。

* **`time.h` 中的函数和结构体 (`struct tm`, `time_t`, `localtime_r`, `tzset`):**
    * **`struct tm`:**  一个结构体，用于存储分解后的日期和时间信息，包括年、月、日、时、分、秒、星期几、一年中的第几天、是否夏令时等。`strptime` 的目标就是填充这个结构体。
    * **`time_t`:**  通常是一个整数类型，表示自 Epoch (UTC 1970-01-01 00:00:00) 以来经过的秒数。
    * **`localtime_r(const time_t *timep, struct tm *result)`:** 将 `time_t` 表示的时间转换为本地时间的 `struct tm` 结构体。`_strptime` 在解析 `%s` 格式时会调用它。
    * **`tzset(void)`:** 根据环境变量（如 `TZ`）设置时区信息。`strptime` 在解析时区信息 (`%Z`) 时会调用它。

* **自定义头文件 (`private.h`, `localedef.h`, `tzfile.h`):**
    * **`private.h`:** 包含 Bionic 内部使用的私有定义和声明。
    * **`localedef.h`:** 定义了与 locale 相关的结构体和宏，例如存储月份和星期名称的数组。
    * **`tzfile.h`:** 定义了与时区文件格式相关的结构体。

**涉及 dynamic linker 的功能**

`strptime.c` 本身并没有直接调用 dynamic linker 的 API (如 `dlopen`, `dlsym`)。然而，它依赖于 locale 和时区信息的加载，这些信息通常是由 dynamic linker 在运行时加载的共享库或数据文件提供的。

**so 布局样本:**

```
/system/lib[64]/libc.so  (包含 strptime 的实现)
/system/usr/share/zoneinfo/ (时区数据文件)
/system/usr/share/i18n/locales/ (locale 数据文件，可能以共享库形式存在)
```

**链接的处理过程:**

1. 当应用程序或系统组件调用 `strptime` 函数时，该调用会链接到 `libc.so` 中的 `strptime` 实现。
2. `strptime` 内部需要访问 locale 信息（例如月份名称）。它通过 `_ctloc` 宏访问 `_CurrentTimeLocale` 变量。
3. `_CurrentTimeLocale` 指向的 locale 数据结构在 `libc.so` 初始化时被加载。这个加载过程可能涉及到读取 locale 数据文件，并将其映射到内存中。Dynamic linker 负责在 `libc.so` 加载时解析其依赖，并加载所需的 locale 数据或共享库。
4. 同样，当 `strptime` 解析时区信息时，它会调用 `tzset`。`tzset` 函数会读取环境变量 `TZ`，并加载相应的时区数据文件（例如 `/system/usr/share/zoneinfo/Asia/Shanghai`）。这个过程可能也涉及到 dynamic linker 加载必要的共享库或数据文件。

**逻辑推理 (假设输入与输出)**

**假设输入:**

* `buf`: "2023-10-26 15:30:00"
* `fmt`: "%Y-%m-%d %H:%M:%S"
* `tm` (初始状态可以是任意值)

**输出:**

`strptime` 函数会尝试将 `buf` 按照 `fmt` 的格式解析，并将结果存储到 `tm` 指向的 `struct tm` 结构体中。成功解析后，`tm` 的内容可能如下：

```
tm_sec: 0
tm_min: 30
tm_hour: 15
tm_mday: 26
tm_mon: 9  // 注意：月份是从 0 开始的，所以 10 月对应 9
tm_year: 123 // 年份是相对于 1900 的偏移，2023 - 1900 = 123
tm_wday:  // 根据日期计算的星期几
tm_yday:  // 根据日期计算的一年中的第几天
tm_isdst: -1 // 通常表示未知或未指定
```

函数会返回指向输入字符串中未解析部分的指针，在这个例子中，如果整个字符串都被成功解析，则返回指向字符串结尾 `\0` 的指针。如果解析失败，则返回 `NULL`。

**用户或编程常见的使用错误**

* **格式字符串与输入字符串不匹配:** 这是最常见的错误。例如，格式字符串是 `"%Y-%m-%d"`，但输入字符串却是 `"2023/10/26"`。
* **错误的格式符:**  使用了 `strptime` 不支持的格式符，或者拼写错误。
* **locale 设置不当:** 如果依赖于 locale 特定的格式（例如月份名称），但系统的 locale 设置与输入字符串的 locale 不一致，会导致解析失败。
* **假设固定的日期格式:**  硬编码日期格式，而没有考虑到用户可能输入不同的格式，或者不同的数据来源使用不同的格式。
* **忽略返回值:** 没有检查 `strptime` 的返回值，导致在解析失败的情况下继续使用未初始化的 `struct tm` 结构体，产生不可预测的结果。

**示例:**

```c
#include <stdio.h>
#include <time.h>

int main() {
    const char *date_str = "October 26, 2023";
    const char *format = "%B %d, %Y";
    struct tm t;

    if (strptime(date_str, format, &t) == NULL) {
        fprintf(stderr, "strptime failed\n");
        return 1;
    }

    printf("Year: %d\n", t.tm_year + 1900);
    printf("Month: %d\n", t.tm_mon + 1);
    printf("Day: %d\n", t.tm_mday);

    return 0;
}
```

如果运行这个程序时，系统的 locale 设置中月份的完整名称与 `"October"` 不匹配，`strptime` 可能会返回 `NULL`。

**说明 Android Framework 或 NDK 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `strptime` 的路径 (示例)**

1. **Java 代码:** Android Framework 中的 Java 代码，例如 `java.text.SimpleDateFormat` 类，用于格式化和解析日期和时间。
2. **`SimpleDateFormat.parse()`:** 当 Java 代码调用 `SimpleDateFormat.parse()` 方法解析日期字符串时。
3. **Native 方法调用:** `SimpleDateFormat` 内部会调用其 native 方法，这些 native 方法通常在 `libicuuc.so` 或相关的 ICU (International Components for Unicode) 库中实现。
4. **ICU 库:** ICU 库提供了强大的国际化支持，包括日期和时间处理。ICU 的日期和时间解析功能可能会使用底层的 C 库函数。
5. **Bionic libc (`strptime`):** 在某些情况下，ICU 库可能会调用 Bionic libc 提供的 `strptime` 函数进行底层的日期字符串解析。这取决于 ICU 的实现细节以及使用的具体格式。

**NDK 到 `strptime` 的路径:**

1. **C/C++ 代码:** 使用 Android NDK 开发的应用程序可以直接调用标准的 C/C++ 库函数。
2. **直接调用 `strptime`:**  NDK 代码可以直接包含 `<time.h>` 并调用 `strptime` 函数。

**Frida Hook 示例调试步骤**

假设我们想 hook `strptime` 函数，看看哪个模块调用了它，以及传入的参数是什么。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const strptime = Module.findExportByName("libc.so", "strptime");

  if (strptime) {
    Interceptor.attach(strptime, {
      onEnter: function (args) {
        const buf = Memory.readUtf8String(args[0]);
        const fmt = Memory.readUtf8String(args[1]);
        console.log("[strptime] Called from:", Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));
        console.log("[strptime] buf:", buf);
        console.log("[strptime] fmt:", fmt);
      },
      onLeave: function (retval) {
        console.log("[strptime] Return value:", retval);
      }
    });
    console.log("[+] Hooked strptime");
  } else {
    console.log("[-] strptime not found in libc.so");
  }
} else {
  console.log("[-] Not an Android platform");
}
```

**使用步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并安装了 Frida 服务。在 PC 上安装了 Frida 和 adb 工具。
2. **找到目标进程:** 确定你想要调试的 Android 应用程序的进程名称或 PID。
3. **运行 Frida 脚本:** 使用 Frida 命令将脚本注入到目标进程中。例如，如果目标进程的名称是 `com.example.myapp`，则可以运行：
   ```bash
   frida -U -f com.example.myapp -l your_frida_script.js --no-pause
   ```
   或者，如果进程已经在运行，可以使用 PID：
   ```bash
   frida -U <PID> -l your_frida_script.js
   ```
4. **触发 `strptime` 调用:** 在目标应用程序中执行一些操作，这些操作预期会调用日期和时间解析功能。例如，打开一个包含日期信息的界面，或者解析从网络接收到的日期字符串。
5. **查看 Frida 输出:** Frida 会在终端上输出 `strptime` 函数被调用时的堆栈信息、传入的参数（`buf` 和 `fmt`），以及返回值。通过查看堆栈信息，你可以追踪到是哪个模块或函数调用了 `strptime`。

**分析 Frida 输出:**

Frida 的输出会显示 `strptime` 被调用时的上下文，包括调用堆栈。通过分析调用堆栈，你可以逐步向上追溯，了解 Android Framework 或 NDK 中的哪个部分最终调用了 `strptime`。例如，你可能会看到调用链中包含 `libicuuc.so` 的函数，这表明日期解析可能经过了 ICU 库。

通过这种方式，你可以详细了解 Android 系统或应用程序是如何使用 `strptime` 函数的，以及数据是如何从上层 Framework 或 NDK 流向底层的 C 库函数的。

### 提示词
```
这是目录为bionic/libc/tzcode/strptime.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: strptime.c,v 1.31 2023/03/02 16:21:51 millert Exp $ */
/*	$NetBSD: strptime.c,v 1.12 1998/01/20 21:39:40 mycroft Exp $	*/
/*-
 * Copyright (c) 1997, 1998, 2005, 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code was contributed to The NetBSD Foundation by Klaus Klein.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "private.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "localedef.h"
#include "tzfile.h"

// Android: ignore OpenBSD's DEF_WEAK() stuff.
#define DEF_WEAK(sym) /* */
// Android: this code is not pointer-sign clean.
#pragma clang diagnostic ignored "-Wpointer-sign"
#pragma clang diagnostic ignored "-Wunused-function"
// Android: clang thinks people don't know && has higher precedence than ||.
#pragma clang diagnostic ignored "-Wlogical-op-parentheses"

#define	_ctloc(x)		(_CurrentTimeLocale->x)

/*
 * We do not implement alternate representations. However, we always
 * check whether a given modifier is allowed for a certain conversion.
 */
#define _ALT_E			0x01
#define _ALT_O			0x02
#define	_LEGAL_ALT(x)		{ if (alt_format & ~(x)) return (0); }

/*
 * We keep track of some of the fields we set in order to compute missing ones.
 */
#define FIELD_TM_MON	(1 << 0)
#define FIELD_TM_MDAY	(1 << 1)
#define FIELD_TM_WDAY	(1 << 2)
#define FIELD_TM_YDAY	(1 << 3)
#define FIELD_TM_YEAR	(1 << 4)

static const char gmt[] = { "GMT" };
static const char utc[] = { "UTC" };
/* RFC-822/RFC-2822 */
static const char * const nast[5] = {
       "EST",    "CST",    "MST",    "PST",    "\0\0\0"
};
static const char * const nadt[5] = {
       "EDT",    "CDT",    "MDT",    "PDT",    "\0\0\0"
};

static const int mon_lengths[2][MONSPERYEAR] = {
        { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
        { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static	int _conv_num(const unsigned char **, int *, int, int);
static	int epoch_to_tm(const unsigned char **, struct tm *);
static	int leaps_thru_end_of(const int y);
static	char *_strptime(const char *, const char *, struct tm *, int);
static	const u_char *_find_string(const u_char *, int *, const char * const *,
	    const char * const *, int);


char *
strptime(const char *buf, const char *fmt, struct tm *tm)
{
	return(_strptime(buf, fmt, tm, 1));
}
DEF_WEAK(strptime);
__strong_alias(strptime_l, strptime);

static char *
_strptime(const char *buf, const char *fmt, struct tm *tm, int initialize)
{
	unsigned char c;
	const unsigned char *bp, *ep;
	size_t len;
	int alt_format, i, offs;
	int neg = 0;
	static int century, relyear, fields;

	if (initialize) {
		century = TM_YEAR_BASE;
		relyear = -1;
		fields = 0;
	}

	bp = (const unsigned char *)buf;
	while ((c = *fmt) != '\0') {
		/* Clear `alternate' modifier prior to new conversion. */
		alt_format = 0;

		/* Eat up white-space. */
		if (isspace(c)) {
			while (isspace(*bp))
				bp++;

			fmt++;
			continue;
		}

		if ((c = *fmt++) != '%')
			goto literal;


again:		switch (c = *fmt++) {
		case '%':	/* "%%" is converted to "%". */
literal:
		if (c != *bp++)
			return (NULL);

		break;

		/*
		 * "Alternative" modifiers. Just set the appropriate flag
		 * and start over again.
		 */
		case 'E':	/* "%E?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_E;
			goto again;

		case 'O':	/* "%O?" alternative conversion modifier. */
			_LEGAL_ALT(0);
			alt_format |= _ALT_O;
			goto again;

		/*
		 * "Complex" conversion rules, implemented through recursion.
		 */
		case 'c':	/* Date and time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			if (!(bp = _strptime(bp, _ctloc(d_t_fmt), tm, 0)))
				return (NULL);
			break;

		case 'D':	/* The date as "%m/%d/%y". */
			_LEGAL_ALT(0);
			if (!(bp = _strptime(bp, "%m/%d/%y", tm, 0)))
				return (NULL);
			break;

		case 'F':	/* The date as "%Y-%m-%d". */
			_LEGAL_ALT(0);
			if (!(bp = _strptime(bp, "%Y-%m-%d", tm, 0)))
				return (NULL);
			continue;

		case 'R':	/* The time as "%H:%M". */
			_LEGAL_ALT(0);
			if (!(bp = _strptime(bp, "%H:%M", tm, 0)))
				return (NULL);
			break;

		case 'r':	/* The time as "%I:%M:%S %p". */
			_LEGAL_ALT(0);
			if (!(bp = _strptime(bp, "%I:%M:%S %p", tm, 0)))
				return (NULL);
			break;

		case 'T':	/* The time as "%H:%M:%S". */
			_LEGAL_ALT(0);
			if (!(bp = _strptime(bp, "%H:%M:%S", tm, 0)))
				return (NULL);
			break;

		case 'v':	/* Android: the date as "%e-%b-%Y" for strftime() compat; glibc does this too. */
			_LEGAL_ALT(0);
			if (!(bp = _strptime(bp, "%e-%b-%Y", tm, 0)))
				return (NULL);
			break;

		case 'X':	/* The time, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			if (!(bp = _strptime(bp, _ctloc(t_fmt), tm, 0)))
				return (NULL);
			break;

		case 'x':	/* The date, using the locale's format. */
			_LEGAL_ALT(_ALT_E);
			if (!(bp = _strptime(bp, _ctloc(d_fmt), tm, 0)))
				return (NULL);
			break;

		/*
		 * "Elementary" conversion rules.
		 */
		case 'A':	/* The day of week, using the locale's form. */
		case 'a':
			_LEGAL_ALT(0);
			for (i = 0; i < 7; i++) {
				/* Full name. */
				len = strlen(_ctloc(day[i]));
				if (strncasecmp(_ctloc(day[i]), bp, len) == 0)
					break;

				/* Abbreviated name. */
				len = strlen(_ctloc(abday[i]));
				if (strncasecmp(_ctloc(abday[i]), bp, len) == 0)
					break;
			}

			/* Nothing matched. */
			if (i == 7)
				return (NULL);

			tm->tm_wday = i;
			bp += len;
			fields |= FIELD_TM_WDAY;
			break;

		case 'B':	/* The month, using the locale's form. */
		case 'b':
		case 'h':
			_LEGAL_ALT(0);
			for (i = 0; i < 12; i++) {
				/* Full name. */
				len = strlen(_ctloc(mon[i]));
				if (strncasecmp(_ctloc(mon[i]), bp, len) == 0)
					break;

				/* Abbreviated name. */
				len = strlen(_ctloc(abmon[i]));
				if (strncasecmp(_ctloc(abmon[i]), bp, len) == 0)
					break;
			}

			/* Nothing matched. */
			if (i == 12)
				return (NULL);

			tm->tm_mon = i;
			bp += len;
			fields |= FIELD_TM_MON;
			break;

		case 'C':	/* The century number. */
			_LEGAL_ALT(_ALT_E);
			if (!(_conv_num(&bp, &i, 0, 99)))
				return (NULL);

			century = i * 100;
			break;

		case 'e':	/* The day of month. */
			if (isspace(*bp))
				bp++;
			/* FALLTHROUGH */
		case 'd':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_mday, 1, 31)))
				return (NULL);
			fields |= FIELD_TM_MDAY;
			break;

		case 'k':	/* The hour (24-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'H':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_hour, 0, 23)))
				return (NULL);
			break;

		case 'l':	/* The hour (12-hour clock representation). */
			_LEGAL_ALT(0);
			/* FALLTHROUGH */
		case 'I':
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_hour, 1, 12)))
				return (NULL);
			break;

		case 'j':	/* The day of year. */
			_LEGAL_ALT(0);
			if (!(_conv_num(&bp, &tm->tm_yday, 1, 366)))
				return (NULL);
			tm->tm_yday--;
			fields |= FIELD_TM_YDAY;
			break;

		case 'M':	/* The minute. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_min, 0, 59)))
				return (NULL);
			break;

		case 'm':	/* The month. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_mon, 1, 12)))
				return (NULL);
			tm->tm_mon--;
			fields |= FIELD_TM_MON;
			break;

		case 'P':	/* Android addition for strftime() compat; glibc does this too. */
		case 'p':	/* The locale's equivalent of AM/PM. */
			_LEGAL_ALT(0);
			/* AM? */
			len = strlen(_ctloc(am_pm[0]));
			if (strncasecmp(_ctloc(am_pm[0]), bp, len) == 0) {
				if (tm->tm_hour > 12)	/* i.e., 13:00 AM ?! */
					return (NULL);
				else if (tm->tm_hour == 12)
					tm->tm_hour = 0;

				bp += len;
				break;
			}
			/* PM? */
			len = strlen(_ctloc(am_pm[1]));
			if (strncasecmp(_ctloc(am_pm[1]), bp, len) == 0) {
				if (tm->tm_hour > 12)	/* i.e., 13:00 PM ?! */
					return (NULL);
				else if (tm->tm_hour < 12)
					tm->tm_hour += 12;

				bp += len;
				break;
			}

			/* Nothing matched. */
			return (NULL);

		case 'S':	/* The seconds. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_sec, 0, 60)))
				return (NULL);
			break;
		case 's':	/* Seconds since epoch. */
			if (!(epoch_to_tm(&bp, tm)))
				return (NULL);
			fields = 0xffff;	 /* everything */
			break;
		case 'U':	/* The week of year, beginning on sunday. */
		case 'W':	/* The week of year, beginning on monday. */
			_LEGAL_ALT(_ALT_O);
			/*
			 * XXX This is bogus, as we can not assume any valid
			 * information present in the tm structure at this
			 * point to calculate a real value, so just check the
			 * range for now.
			 */
			 if (!(_conv_num(&bp, &i, 0, 53)))
				return (NULL);
			 break;

		case 'w':	/* The day of week, beginning on sunday. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &tm->tm_wday, 0, 6)))
				return (NULL);
			fields |= FIELD_TM_WDAY;
			break;

		case 'u':	/* The day of week, monday = 1. */
			_LEGAL_ALT(_ALT_O);
			if (!(_conv_num(&bp, &i, 1, 7)))
				return (NULL);
			tm->tm_wday = i % 7;
			fields |= FIELD_TM_WDAY;
			continue;

		case 'g':	/* The year corresponding to the ISO week
				 * number but without the century.
				 */
			if (!(_conv_num(&bp, &i, 0, 99)))
				return (NULL);
			continue;

		case 'G':	/* The year corresponding to the ISO week
				 * number with century.
				 */
			do
				bp++;
			while (isdigit(*bp));
			continue;

		case 'V':	/* The ISO 8601:1988 week number as decimal */
			if (!(_conv_num(&bp, &i, 0, 53)))
				return (NULL);
			continue;

		case 'Y':	/* The year. */
			_LEGAL_ALT(_ALT_E);
			if (!(_conv_num(&bp, &i, 0, 9999)))
				return (NULL);

			relyear = -1;
			tm->tm_year = i - TM_YEAR_BASE;
			fields |= FIELD_TM_YEAR;
			break;

		case 'y':	/* The year within the century (2 digits). */
			_LEGAL_ALT(_ALT_E | _ALT_O);
			if (!(_conv_num(&bp, &relyear, 0, 99)))
				return (NULL);
			break;

		case 'Z':
			tzset();
			if (strncmp((const char *)bp, gmt, 3) == 0) {
				tm->tm_isdst = 0;
				tm->tm_gmtoff = 0;
				tm->tm_zone = gmt;
				bp += 3;
			} else if (strncmp((const char *)bp, utc, 3) == 0) {
				tm->tm_isdst = 0;
				tm->tm_gmtoff = 0;
				tm->tm_zone = utc;
				bp += 3;
			} else {
				ep = _find_string(bp, &i,
						 (const char * const *)tzname,
						  NULL, 2);
				if (ep == NULL)
					return (NULL);

				tm->tm_isdst = i;
				tm->tm_gmtoff = -(timezone);
				tm->tm_zone = tzname[i];
				bp = ep;
			}
			continue;

		case 'z':
			/*
			 * We recognize all ISO 8601 formats:
			 * Z	= Zulu time/UTC
			 * [+-]hhmm
			 * [+-]hh:mm
			 * [+-]hh
			 * We recognize all RFC-822/RFC-2822 formats:
			 * UT|GMT
			 *          North American : UTC offsets
			 * E[DS]T = Eastern : -4 | -5
			 * C[DS]T = Central : -5 | -6
			 * M[DS]T = Mountain: -6 | -7
			 * P[DS]T = Pacific : -7 | -8
			 */
			while (isspace(*bp))
				bp++;

			switch (*bp++) {
			case 'G':
				if (*bp++ != 'M')
					return NULL;
				/*FALLTHROUGH*/
			case 'U':
				if (*bp++ != 'T')
					return NULL;
				/*FALLTHROUGH*/
			case 'Z':
				tm->tm_isdst = 0;
				tm->tm_gmtoff = 0;
				tm->tm_zone = utc;
				continue;
			case '+':
				neg = 0;
				break;
			case '-':
				neg = 1;
				break;
			default:
				--bp;
				ep = _find_string(bp, &i, nast, NULL, 4);
				if (ep != NULL) {
					tm->tm_gmtoff = (-5 - i) * SECSPERHOUR;
					tm->tm_zone = (char *)nast[i];
					bp = ep;
					continue;
				}
				ep = _find_string(bp, &i, nadt, NULL, 4);
				if (ep != NULL) {
					tm->tm_isdst = 1;
					tm->tm_gmtoff = (-4 - i) * SECSPERHOUR;
					tm->tm_zone = (char *)nadt[i];
					bp = ep;
					continue;
				}
				return NULL;
			}
			if (!isdigit(bp[0]) || !isdigit(bp[1]))
				return NULL;
			offs = ((bp[0]-'0') * 10 + (bp[1]-'0')) * SECSPERHOUR;
			bp += 2;
			if (*bp == ':')
				bp++;
			if (isdigit(*bp)) {
				offs += (*bp++ - '0') * 10 * SECSPERMIN;
				if (!isdigit(*bp))
					return NULL;
				offs += (*bp++ - '0') * SECSPERMIN;
			}
			if (neg)
				offs = -offs;
			tm->tm_isdst = 0;	/* XXX */
			tm->tm_gmtoff = offs;
			tm->tm_zone = NULL;	/* XXX */
			continue;

		/*
		 * Miscellaneous conversions.
		 */
		case 'n':	/* Any kind of white-space. */
		case 't':
			_LEGAL_ALT(0);
			while (isspace(*bp))
				bp++;
			break;


		default:	/* Unknown/unsupported conversion. */
			return (NULL);
		}


	}

	/*
	 * We need to evaluate the two digit year spec (%y)
	 * last as we can get a century spec (%C) at any time.
	 */
	if (relyear != -1) {
		if (century == TM_YEAR_BASE) {
			if (relyear <= 68)
				tm->tm_year = relyear + 2000 - TM_YEAR_BASE;
			else
				tm->tm_year = relyear + 1900 - TM_YEAR_BASE;
		} else {
			tm->tm_year = relyear + century - TM_YEAR_BASE;
		}
		fields |= FIELD_TM_YEAR;
	}

	/* Compute some missing values when possible. */
	if (fields & FIELD_TM_YEAR) {
		const int year = tm->tm_year + TM_YEAR_BASE;
		const int *mon_lens = mon_lengths[isleap(year)];
		if (!(fields & FIELD_TM_YDAY) &&
		    (fields & FIELD_TM_MON) && (fields & FIELD_TM_MDAY)) {
			tm->tm_yday = tm->tm_mday - 1;
			for (i = 0; i < tm->tm_mon; i++)
				tm->tm_yday += mon_lens[i];
			fields |= FIELD_TM_YDAY;
		}
		if (fields & FIELD_TM_YDAY) {
			int days = tm->tm_yday;
			if (!(fields & FIELD_TM_WDAY)) {
				tm->tm_wday = EPOCH_WDAY +
				    ((year - EPOCH_YEAR) % DAYSPERWEEK) *
				    (DAYSPERNYEAR % DAYSPERWEEK) +
				    leaps_thru_end_of(year - 1) -
				    leaps_thru_end_of(EPOCH_YEAR - 1) +
				    tm->tm_yday;
				tm->tm_wday %= DAYSPERWEEK;
				if (tm->tm_wday < 0)
					tm->tm_wday += DAYSPERWEEK;
			}
			if (!(fields & FIELD_TM_MON)) {
				tm->tm_mon = 0;
				while (tm->tm_mon < MONSPERYEAR && days >= mon_lens[tm->tm_mon])
					days -= mon_lens[tm->tm_mon++];
			}
			if (!(fields & FIELD_TM_MDAY))
				tm->tm_mday = days + 1;
		}
	}

	return ((char *)bp);
}


static int
_conv_num(const unsigned char **buf, int *dest, int llim, int ulim)
{
	int result = 0;
	int rulim = ulim;

	if (**buf < '0' || **buf > '9')
		return (0);

	/* we use rulim to break out of the loop when we run out of digits */
	do {
		result *= 10;
		result += *(*buf)++ - '0';
		rulim /= 10;
	} while ((result * 10 <= ulim) && rulim && **buf >= '0' && **buf <= '9');

	if (result < llim || result > ulim)
		return (0);

	*dest = result;
	return (1);
}

static int
epoch_to_tm(const unsigned char **buf, struct tm *tm)
{
	int saved_errno = errno;
	int ret = 0;
	time_t secs;
	char *ep;

	errno = 0;
	secs = strtoll(*buf, &ep, 10);
	if (*buf == (unsigned char *)ep)
		goto done;
	if (secs < 0 ||
	    secs == LLONG_MAX && errno == ERANGE)
		goto done;
	if (localtime_r(&secs, tm) == NULL)
		goto done;
	ret = 1;
done:
	*buf = ep;
	errno = saved_errno;
	return (ret);
}

static const u_char *
_find_string(const u_char *bp, int *tgt, const char * const *n1,
		const char * const *n2, int c)
{
	int i;
	unsigned int len;

	/* check full name - then abbreviated ones */
	for (; n1 != NULL; n1 = n2, n2 = NULL) {
		for (i = 0; i < c; i++, n1++) {
			len = strlen(*n1);
			if (strncasecmp(*n1, (const char *)bp, len) == 0) {
				*tgt = i;
				return bp + len;
			}
		}
	}

	/* Nothing matched */
	return NULL;
}

static int
leaps_thru_end_of(const int y)
{
	return (y >= 0) ? (y / 4 - y / 100 + y / 400) :
		-(leaps_thru_end_of(-(y + 1)) + 1);
}
```