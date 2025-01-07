Response:
Let's break down the thought process for answering the request about `bionic/tests/headers/posix/time_h.c`.

**1. Understanding the Core Purpose of the File:**

The first and most crucial step is to recognize what kind of file this is. The path `bionic/tests/headers/posix/time_h.c` immediately suggests it's a test file, specifically for the `time.h` header file within Android's Bionic libc. The `header_checks.h` inclusion further reinforces this. Test files for headers primarily check for the *presence* and *correct definition* of types, structures, macros, and functions declared in the corresponding header.

**2. Identifying Key Elements within the Code:**

Next, I'd scan the code for patterns and keywords:

* **`TYPE(...)`:** This macro is clearly used to check if a type is defined. Examples: `TYPE(clock_t);`, `TYPE(struct tm);`.
* **`STRUCT_MEMBER(...)`:** This macro checks for the existence and type of members within a structure. Example: `STRUCT_MEMBER(struct tm, int, tm_sec);`.
* **`MACRO(...)`:** This verifies the definition of preprocessor macros. Example: `MACRO(NULL);`, `MACRO(CLOCK_MONOTONIC);`.
* **`FUNCTION(...)`:** This confirms the declaration of functions, along with their expected signature (return type and argument types). Example: `FUNCTION(asctime, char* (*f)(const struct tm*));`.

**3. Inferring Functionality Based on Code Elements:**

Based on the identified elements, I can deduce the file's primary functions:

* **Type Checking:** Ensuring that standard C time-related types (`clock_t`, `time_t`, etc.) are defined by the `time.h` header.
* **Structure Member Checking:** Verifying that the members of key time-related structures (`struct tm`, `struct timespec`, `struct itimerspec`) are present and have the correct types.
* **Macro Checking:** Confirming the definition of important time-related macros (`NULL`, `CLOCKS_PER_SEC`, `CLOCK_MONOTONIC`, etc.).
* **Function Declaration Checking:** Verifying that the standard POSIX time functions are declared in the `time.h` header with the correct signatures.

**4. Relating to Android's Functionality:**

Since Bionic is Android's C library, these checks directly relate to the functionality available to Android developers (both NDK and framework). The `time.h` header provides the foundation for time-related operations in Android. Examples:

* **`clock_gettime`:** Used throughout the Android system for getting the current time. Essential for timestamps, scheduling, etc.
* **`nanosleep`:** Allows pausing execution for a specified duration, crucial for synchronization and event timing.
* **`localtime`:**  Converts a UTC time to the local time, respecting the device's timezone.

**5. Explaining `libc` Function Implementations (General Approach):**

Since this is a *test file*, it doesn't contain the *implementation* of the libc functions. The explanation should focus on the *purpose* of each function, drawing from general POSIX/C knowledge. For instance, explaining `clock_gettime` involves mentioning its role in retrieving the time of a specific clock.

**6. Addressing Dynamic Linker Aspects:**

This test file *doesn't directly involve* the dynamic linker. The dynamic linker is responsible for loading shared libraries (`.so` files) at runtime. The `time.h` header declares functions that are *implemented* in a shared library (likely `libc.so`), but this test only checks the header. Therefore, the explanation regarding the dynamic linker should focus on how these functions would be part of `libc.so` and how the linker would resolve symbols.

**7. Handling Logical Inference, Assumptions, and Input/Output:**

As it's a header test, there's minimal logical inference to perform. The "input" is the `time.h` header file itself, and the "output" is whether the checks pass or fail. This is more of a validation process than a functional one.

**8. Addressing Common Usage Errors:**

Thinking about how developers commonly misuse time functions is important. Examples include:

* **Incorrect format strings in `strftime`:** Leading to unexpected output or crashes.
* **Ignoring return values:** Not checking for errors from functions like `clock_gettime`.
* **Timezone issues:** Misunderstanding the difference between UTC and local time.

**9. Tracing from Android Framework/NDK:**

This requires tracing the call stack. Think of scenarios where time functions are used:

* **Framework:**  UI rendering timestamps, alarm management, system time updates.
* **NDK:**  Game development (frame timing), network operations (timeouts), logging.

The Frida hook example demonstrates how to intercept calls to functions like `clock_gettime` to observe their usage.

**10. Structuring the Response:**

Organizing the information logically is key. Using headings and bullet points makes the explanation clear and easy to understand. Following the order of the prompts in the request helps ensure all aspects are addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "I need to explain how `clock_gettime` is *implemented*."
* **Correction:** "No, this is a *header test*. I need to explain its *purpose* and where the *implementation* resides (in `libc.so`)."

* **Initial thought:** "This file interacts heavily with the dynamic linker."
* **Correction:** "This file *declares* functions that the dynamic linker will resolve. The file itself doesn't perform dynamic linking."

By following these steps, refining understanding, and focusing on the purpose of a header test file, a comprehensive and accurate answer can be constructed.
这个`bionic/tests/headers/posix/time_h.c` 文件是 Android Bionic C 库中的一个测试文件，它的主要功能是**验证 `time.h` 头文件是否正确定义了 POSIX 标准中与时间相关的各种类型、结构体、宏和函数声明**。

简单来说，它不是一个实现具体功能的代码，而是一个用来确保 `time.h` 这个“蓝图”定义正确性的“质检员”。

下面详细列举其功能和相关说明：

**1. 功能概述：**

该测试文件通过一系列 `TYPE()`, `STRUCT_MEMBER()`, `MACRO()`, 和 `FUNCTION()` 宏来检查 `time.h` 头文件中声明的：

* **数据类型 (Types):**  验证像 `clock_t`, `size_t`, `time_t`, `clockid_t`, `timer_t`, `locale_t`, `pid_t` 这样的基本时间相关类型是否被定义。
* **结构体 (Structures):** 验证像 `struct tm`, `struct timespec`, `struct itimerspec` 这样的结构体及其成员是否被正确声明。例如，它会检查 `struct tm` 是否包含 `tm_sec`, `tm_min`, `tm_hour` 等成员。
* **宏 (Macros):** 验证像 `NULL`, `CLOCKS_PER_SEC`, `CLOCK_MONOTONIC`, `TIMER_ABSTIME` 这样的宏定义是否正确。
* **函数声明 (Function Declarations):** 验证像 `asctime`, `clock_gettime`, `nanosleep`, `timer_create` 等函数的声明是否存在，并且参数和返回值类型是否符合预期。

**2. 与 Android 功能的关系及举例说明：**

`time.h` 中定义的类型、结构体、宏和函数是 Android 系统中进行时间操作的基础。Android Framework 和 NDK 中很多功能都直接或间接地依赖于这些定义。

* **时间获取：**
    * `clock_gettime(CLOCK_MONOTONIC, &ts)`:  获取单调递增的时间，常用于性能测量，不受系统时间修改的影响。Android 系统内部很多地方使用它来计算时间间隔，例如 `Choreographer` 用于屏幕刷新同步。
    * `clock_gettime(CLOCK_REALTIME, &ts)`: 获取系统当前时间，受系统时间修改的影响。应用程序获取当前日期和时间就需要用到这个。
* **延时和睡眠：**
    * `nanosleep(&req, &rem)`: 使当前线程休眠指定的纳秒数，常用于需要精确控制时间的应用，例如游戏开发中的帧率控制。
* **定时器：**
    * `timer_create`, `timer_settime`, `timer_gettime`: 用于创建和管理 POSIX 间隔定时器。Android 系统中的 `AlarmManager` 底层可能涉及到这些机制。
* **时间转换：**
    * `localtime`, `gmtime`: 在本地时间和 UTC 时间之间进行转换。Android 系统在显示时间和处理跨时区数据时会用到这些函数。
    * `strftime`, `strptime`:  将时间结构体格式化为字符串，或者将字符串解析为时间结构体。例如，日期时间选择器或者日志记录功能会用到。

**3. Libc 函数的功能及实现（由于是测试文件，这里解释的是被测试的函数的功能，而非测试代码的实现）：**

这个测试文件本身不包含 libc 函数的实现，它只是检查这些函数是否被正确声明。这些函数的具体实现位于 Bionic 的其他源文件中。以下解释几个关键函数的功能：

* **`clock(void)`:** 返回程序自启动以来消耗的处理器时间，单位是 `clock_t`。它的实现通常依赖于操作系统提供的机制来获取进程的 CPU 时间。
* **`clock_getcpuclockid(pid_t pid, clockid_t *clockid)`:** 获取指定进程的 CPU 时钟 ID。实现需要操作系统支持查询进程的 CPU 时钟。
* **`clock_getres(clockid_t clock_id, struct timespec *res)`:** 获取指定时钟的分辨率（精度）。实现需要操作系统提供时钟分辨率信息。
* **`clock_gettime(clockid_t clock_id, struct timespec *tp)`:** 获取指定时钟的当前时间。实现需要访问操作系统提供的时钟源。例如，`CLOCK_MONOTONIC` 可能读取一个不受系统时间修改影响的硬件计数器。
* **`clock_nanosleep(clockid_t clock_id, int flags, const struct timespec *req, struct timespec *rem)`:**  使当前线程休眠，基于指定的时钟。`flags` 可以是 `TIMER_ABSTIME` 表示绝对时间休眠。实现会利用操作系统的休眠机制，并考虑所选时钟的影响。
* **`clock_settime(clockid_t clock_id, const struct timespec *tp)`:** 设置指定时钟的时间。这个函数通常需要 root 权限，因为修改系统时间会影响整个系统。
* **`ctime(const time_t *timer)`:** 将 `time_t` 表示的时间转换为本地时间的字符串格式。内部会调用 `localtime` 和其他格式化函数。
* **`difftime(time_t time1, time_t time0)`:** 计算两个 `time_t` 值之间的时间差，以秒为单位。这是一个简单的减法运算。
* **`gmtime(const time_t *timer)`:** 将 `time_t` 表示的时间转换为 UTC 时间的 `struct tm` 结构体。实现需要进行时区转换。
* **`localtime(const time_t *timer)`:** 将 `time_t` 表示的时间转换为本地时间的 `struct tm` 结构体。实现需要考虑系统时区设置。
* **`mktime(struct tm *timeptr)`:** 将 `struct tm` 表示的本地时间转换为 `time_t` 值。实现需要进行日期和时间的计算。
* **`nanosleep(const struct timespec *req, struct timespec *rem)`:** 使当前线程休眠指定的纳秒数，使用 `CLOCK_REALTIME` 时钟。实现依赖于操作系统的休眠机制。
* **`strftime(char *s, size_t max, const char *format, const struct tm *tm)`:** 根据指定的格式将 `struct tm` 表示的时间格式化为字符串。实现需要解析格式字符串并填充时间信息。
* **`strptime(const char *s, const char *format, struct tm *tm)`:** 将字符串解析为 `struct tm` 结构体，根据指定的格式。实现需要解析字符串并将其转换为时间结构体的各个字段。
* **`time(time_t *timer)`:** 获取当前时间，通常以自 Epoch (1970-01-01 00:00:00 UTC) 以来的秒数表示。实现通常直接调用 `clock_gettime(CLOCK_REALTIME, ...)`。
* **`timer_create`, `timer_delete`, `timer_getoverrun`, `timer_gettime`, `timer_settime`: **  这些是 POSIX 间隔定时器相关的函数，用于创建、删除、查询和设置定时器。它们的实现依赖于操作系统提供的定时器机制，通常涉及到信号处理。
* **`tzset(void)`:** 根据环境变量（如 `TZ`）设置时区信息。实现会读取环境变量并更新内部的时区数据。

**4. 涉及 Dynamic Linker 的功能：**

这个测试文件本身不涉及 dynamic linker 的功能。它只是检查头文件中的声明。  然而，这些被声明的函数最终会被链接到共享库 `libc.so` 中，dynamic linker 负责在程序运行时加载和链接这个库。

**So 布局样本：**

```
# 假设的 libc.so 布局

.text:0000AAAA  <clock 函数的实现代码>
.text:0000BBBB  <clock_gettime 函数的实现代码>
...
.data:0000CCCC  <timezone 变量的数据>
...
.symtab:
    clock: .text:0000AAAA
    clock_gettime: .text:0000BBBB
    timezone: .data:0000CCCC
    ...
```

**链接的处理过程：**

1. **编译时：** 当应用程序代码调用 `clock_gettime` 等函数时，编译器会查找对应的函数声明（在 `time.h` 中）。链接器会将对这些函数的调用记录下来，标记为未解析的符号。
2. **运行时：** 当程序启动时，dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。
3. **加载共享库：** dynamic linker 会根据程序的依赖关系加载 `libc.so` 到内存中的某个地址。
4. **符号解析（Symbol Resolution）：** dynamic linker 会遍历 `libc.so` 的符号表 (`.symtab`)，找到与程序中未解析符号匹配的函数地址。例如，它会将程序中对 `clock_gettime` 的调用指向 `libc.so` 中 `clock_gettime` 函数的实际内存地址 (`.text:0000BBBB`)。
5. **重定位（Relocation）：** dynamic linker 可能会修改程序代码中的一些指令，将对共享库中变量和函数的引用更新为实际的内存地址。

**5. 逻辑推理、假设输入与输出（由于是测试文件，逻辑推理较少）：**

这个测试文件主要是进行静态的检查，没有复杂的逻辑推理。其“输入”是 `time.h` 文件的内容，输出是测试是否通过（即定义的类型、结构体、宏和函数声明是否符合预期）。

**假设输入（`time.h` 的一部分内容）：**

```c
typedef unsigned long size_t;
typedef long time_t;

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

int clock_gettime(clockid_t clk_id, struct timespec *tp);
```

**输出（针对上述输入的测试结果）：**

* `TYPE(size_t)`: 通过
* `TYPE(time_t)`: 通过
* `TYPE(struct timespec)`: 通过
* `STRUCT_MEMBER(struct timespec, time_t, tv_sec)`: 通过
* `FUNCTION(clock_gettime, int (*f)(clockid_t, struct timespec*))`: 通过

**6. 用户或编程常见的使用错误：**

* **`strftime` 格式字符串错误：** 使用错误的格式字符可能导致输出不正确甚至程序崩溃。
    ```c
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%mm-%dd", t); // 错误：月份应该是 %m
    printf("%s\n", buffer);
    ```
* **忘记检查函数返回值：** 像 `clock_gettime` 这样的函数在某些情况下可能会失败。
    ```c
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
        perror("clock_gettime failed");
        // 处理错误
    }
    ```
* **时区处理不当：** 混淆本地时间和 UTC 时间，或者没有正确设置时区环境变量。
* **`strptime` 解析错误：** 输入字符串的格式与指定的格式字符串不匹配，导致解析失败。
    ```c
    struct tm t;
    strptime("2023/10/27", "%Y-%m-%d", &t); // 错误：输入格式不匹配
    ```
* **滥用 `ctime` 和 `asctime`：** 这些函数返回的字符串格式是固定的，不够灵活，并且不是线程安全的（有 `_r` 版本是线程安全的）。

**7. Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤。**

**Android Framework 示例 (获取当前时间)：**

1. **Java 代码:**  Android Framework 中的 Java 代码，例如 `java.util.Date` 或 `System.currentTimeMillis()`，最终会调用到 Native 代码。
2. **Framework NDK 桥接:**  Framework 使用 JNI (Java Native Interface) 调用到 C++ Native 代码。例如，`System.currentTimeMillis()` 可能会调用到 `android_os_SystemClock.cpp` 中的 `SystemClock_uptimeMillis` 函数。
3. **Bionic 系统调用:**  在 Bionic 的 Native 代码中，例如 `SystemClock_uptimeMillis` 可能会调用 Bionic 提供的函数，最终会调用到系统调用，例如 `clock_gettime(CLOCK_MONOTONIC, ...)`。

**NDK 示例 (使用 `nanosleep` 进行延时)：**

1. **NDK C/C++ 代码:**  NDK 开发者可以直接调用 `nanosleep` 函数。
   ```c++
   #include <time.h>
   #include <stdio.h>

   int main() {
       struct timespec req, rem;
       req.tv_sec = 0;
       req.tv_nsec = 100000000; // 100 毫秒
       nanosleep(&req, &rem);
       printf("Waited for 100 milliseconds.\n");
       return 0;
   }
   ```
2. **链接到 Bionic:**  NDK 应用在编译时会链接到 Bionic 库。
3. **运行时调用:**  当 NDK 应用执行到 `nanosleep` 时，它会调用 Bionic 库中 `nanosleep` 的实现。

**Frida Hook 示例 (Hook `clock_gettime`):**

```python
import frida
import sys

package_name = "your.target.app"  # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "clock_gettime"), {
    onEnter: function(args) {
        var clock_id = ptr(args[0]).toInt32();
        var timespec_ptr = ptr(args[1]);
        console.log("clock_gettime called with clock_id:", clock_id);
        // 你可以在这里读取或修改参数
    },
    onLeave: function(retval) {
        console.log("clock_gettime returned:", retval);
        // 你可以在这里读取返回值
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码：**

1. **导入 Frida 库。**
2. **指定要 Hook 的目标应用的包名。**
3. **定义消息处理函数 `on_message`，用于打印 Frida 发送的消息。**
4. **使用 `frida.get_usb_device().attach(package_name)` 连接到目标应用。**
5. **编写 Frida 脚本代码：**
   - `Interceptor.attach`:  用于拦截函数调用。
   - `Module.findExportByName("libc.so", "clock_gettime")`: 查找 `libc.so` 中名为 `clock_gettime` 的导出函数。
   - `onEnter`:  在 `clock_gettime` 函数被调用之前执行。
     - `args`:  包含函数参数的数组。`args[0]` 是 `clockid_t`，`args[1]` 是 `struct timespec*`。
     - `ptr(args[0]).toInt32()`: 将参数指针转换为整数。
     - `console.log`:  在 Frida 控制台中打印日志。
   - `onLeave`: 在 `clock_gettime` 函数执行完毕后执行。
     - `retval`: 函数的返回值。
6. **创建并加载 Frida 脚本。**
7. **保持脚本运行，直到用户输入结束。**

通过运行这个 Frida 脚本，你可以观察到目标应用何时调用了 `clock_gettime` 函数，以及传递的参数和返回值，从而了解 Android Framework 或 NDK 代码是如何一步步地使用到 Bionic 的时间相关函数的。你可以修改脚本来 Hook 其他 `time.h` 中声明的函数，以调试不同的时间相关操作。

Prompt: 
```
这是目录为bionic/tests/headers/posix/time_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#if !defined(DO_NOT_INCLUDE_TIME_H)
#include <time.h>
#endif

#include "header_checks.h"

static void time_h() {
  TYPE(clock_t);
  TYPE(size_t);
  TYPE(time_t);

  TYPE(clockid_t);
  TYPE(timer_t);

  TYPE(locale_t);

  TYPE(pid_t);

  TYPE(struct tm);
  STRUCT_MEMBER(struct tm, int, tm_sec);
  STRUCT_MEMBER(struct tm, int, tm_min);
  STRUCT_MEMBER(struct tm, int, tm_hour);
  STRUCT_MEMBER(struct tm, int, tm_mday);
  STRUCT_MEMBER(struct tm, int, tm_mon);
  STRUCT_MEMBER(struct tm, int, tm_year);
  STRUCT_MEMBER(struct tm, int, tm_wday);
  STRUCT_MEMBER(struct tm, int, tm_yday);
  STRUCT_MEMBER(struct tm, int, tm_isdst);

  TYPE(struct timespec);
  STRUCT_MEMBER(struct timespec, time_t, tv_sec);
  STRUCT_MEMBER(struct timespec, long, tv_nsec);

  TYPE(struct itimerspec);
  STRUCT_MEMBER(struct itimerspec, struct timespec, it_interval);
  STRUCT_MEMBER(struct itimerspec, struct timespec, it_value);

  MACRO(NULL);
  MACRO(CLOCKS_PER_SEC);

  MACRO(CLOCK_MONOTONIC);
  MACRO(CLOCK_PROCESS_CPUTIME_ID);
  MACRO(CLOCK_REALTIME);
  MACRO(CLOCK_THREAD_CPUTIME_ID);

  MACRO(TIMER_ABSTIME);

  FUNCTION(asctime, char* (*f)(const struct tm*));
  FUNCTION(asctime_r, char* (*f)(const struct tm*, char*));
  FUNCTION(clock, clock_t (*f)(void));
  FUNCTION(clock_getcpuclockid, int (*f)(pid_t, clockid_t*));
  FUNCTION(clock_getres, int (*f)(clockid_t, struct timespec*));
  FUNCTION(clock_gettime, int (*f)(clockid_t, struct timespec*));
  FUNCTION(clock_nanosleep, int (*f)(clockid_t, int, const struct timespec*, struct timespec*));
  FUNCTION(clock_settime, int (*f)(clockid_t, const struct timespec*));
  FUNCTION(ctime, char* (*f)(const time_t*));
  FUNCTION(ctime_r, char* (*f)(const time_t*, char*));
  FUNCTION(difftime, double (*f)(time_t, time_t));
#if !defined(__BIONIC__)
  FUNCTION(getdate, struct tm* (*f)(const char*));
#endif
  FUNCTION(gmtime, struct tm* (*f)(const time_t*));
  FUNCTION(gmtime_r, struct tm* (*f)(const time_t*, struct tm*));
  FUNCTION(localtime, struct tm* (*f)(const time_t*));
  FUNCTION(localtime_r, struct tm* (*f)(const time_t*, struct tm*));
  FUNCTION(mktime, time_t (*f)(struct tm*));
  FUNCTION(nanosleep, int (*f)(const struct timespec*, struct timespec*));
  FUNCTION(strftime, size_t (*f)(char*, size_t, const char*, const struct tm*));
  FUNCTION(strftime_l, size_t (*f)(char*, size_t, const char*, const struct tm*, locale_t));
  FUNCTION(strptime, char* (*f)(const char*, const char*, struct tm*));
  FUNCTION(time, time_t (*f)(time_t*));
  FUNCTION(timer_create, int (*f)(clockid_t, struct sigevent*, timer_t*));
  FUNCTION(timer_delete, int (*f)(timer_t));
  FUNCTION(timer_getoverrun, int (*f)(timer_t));
  FUNCTION(timer_gettime, int (*f)(timer_t, struct itimerspec*));
  FUNCTION(timer_settime, int (*f)(timer_t, int, const struct itimerspec*, struct itimerspec*));
  FUNCTION(tzset, void (*f)(void));

  int i = daylight;
  long l = timezone;
  char** sp = tzname;
}

"""

```