Response:
Let's break down the thought process for answering the request about `bionic/libc/bionic/time64.c`.

**1. Understanding the Core Request:**

The fundamental goal is to analyze the `time64.c` file within the Android Bionic library and explain its functionality, especially in the context of Android. The request also asks for explanations of individual functions, dynamic linker involvement, error handling, usage scenarios, and how Android components reach this code. Finally, it requests a Frida hook example.

**2. Initial Assessment of the Code:**

A quick skim of the code reveals the following key aspects:

* **64-bit Time Handling:** The primary purpose is to handle 64-bit time values (`time64_t`) on 32-bit systems. This addresses the Year 2038 problem where standard 32-bit `time_t` values will overflow.
* **Wrappers for `localtime_r` and `gmtime_r`:** The code defines `LOCALTIME_R` and `GMTIME_R` macros, potentially providing fallback implementations if the system doesn't have the thread-safe `_r` versions.
* **Calendar Calculations:**  The presence of arrays like `days_in_month`, `julian_days_by_month`, and constants related to Gregorian cycles indicates that the code performs date and time calculations.
* **Safe Year Mapping:**  The `safe_year` function and associated constants suggest a mechanism to handle dates outside the representable range of 32-bit `time_t` by mapping them to a safe interval.
* **`mktime64` and `timegm64`:** These functions are the 64-bit equivalents of `mktime` and `timegm`, responsible for converting `struct tm` to `time64_t` and vice-versa.
* **Conditional Compilation:** `#ifdef` directives like `__LP64__`, `HAS_LOCALTIME_R`, `USE_SYSTEM_LOCALTIME`, and `TIME_64_DEBUG` indicate different compilation paths and debugging options.

**3. Structuring the Answer:**

To provide a comprehensive and organized response, I decided to structure the answer according to the request's points:

* **功能列表:** Start with a high-level overview of the file's purpose.
* **与 Android 功能的关系:** Explain how this addresses the Y2038 issue in Android.
* **libc 函数详解:**  Go through the important functions one by one, explaining their implementation.
* **动态链接器功能:** Address this part specifically, even though the code doesn't directly show dynamic linking actions. Infer the potential involvement.
* **逻辑推理:** Provide examples of input and output for key functions.
* **用户/编程常见错误:**  Point out typical pitfalls when using these time functions.
* **Android Framework/NDK 调用路径:** Explain how higher-level Android components might eventually call these functions.
* **Frida Hook 示例:** Provide a practical example of how to intercept calls to these functions.

**4. Detailed Analysis and Explanation (Iterative Process):**

For each function, the thought process involved:

* **Identifying the Core Task:** What is the function's primary purpose (e.g., converting `time64_t` to `struct tm` in UTC)?
* **Analyzing the Implementation:**
    * Look for key algorithms and data structures. For example, the Gregorian cycle calculations in `gmtime64_r`.
    * Identify any branching logic (e.g., using system calls when possible).
    * Understand how the function handles edge cases or potential overflows.
    * Note any use of helper functions.
* **Relating to Standard `libc` Functions:** Emphasize that these are 64-bit equivalents of standard functions.
* **Considering Android Context:**  Why is this function needed in Android? How does it fit into the larger picture?

**5. Addressing Dynamic Linker Concerns:**

Although `time64.c` doesn't directly manipulate the dynamic linker, it *is part* of `libc.so`, which is linked dynamically. Therefore, the explanation focused on:

* **Location within `libc.so`:**  This is the key point.
* **Dynamic Linking Process:** Briefly explain how the linker resolves symbols at runtime.
* **`DT_SONAME`:** Mentioning this helps illustrate how libraries are identified.
* **`dlopen`/`dlsym` (indirectly):** While not used *in* this code, these are the common mechanisms for dynamic linking in user-space.

**6. Crafting Examples and Error Scenarios:**

* **Logic Examples:**  Choose simple but illustrative inputs for `gmtime64_r` and `localtime64_r` to show basic conversion.
* **Common Errors:** Think about the common mistakes developers make with time functions, such as ignoring return values or assuming thread safety without using the `_r` versions (although this file is specifically about the thread-safe 64-bit versions).

**7. Tracing the Android Call Path:**

This required some general knowledge of Android architecture:

* **NDK as the Entry Point:**  NDK is the most direct way for developers to access Bionic's `libc`.
* **Java Framework Calling Native Code:**  Explain the JNI mechanism.
* **System Services:**  Mention that some Android system services might use these functions internally.

**8. Creating the Frida Hook:**

* **Function Signature:**  Know the function's name and parameter types.
* **Frida Basics:** Use `Interceptor.attach` to intercept function calls.
* **Logging Arguments and Return Values:**  Show how to access and print function parameters and return values.

**9. Language and Tone:**

The request specified Chinese, so the entire response was written in Chinese. The tone aimed for clarity and accuracy, explaining technical concepts in a way that is understandable but not overly simplified.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focusing too much on the low-level bit manipulation. **Correction:** Shift focus to the higher-level functionality and the "why" behind the code.
* **Realization:**  The code uses macros for `localtime_r` and `gmtime_r`. **Correction:** Explain the implications of this (potential fallback implementations).
* **Considering the dynamic linker:** Initially might have thought there was no direct connection. **Correction:** Realize that being part of `libc.so` *is* the connection to the dynamic linker.
* **Frida hook complexity:** Start with a simple hook and gradually add more details like logging arguments.

By following this structured and iterative approach, I could generate a comprehensive and accurate response that addressed all aspects of the original request.
好的，让我们深入分析一下 `bionic/libc/bionic/time64.c` 这个文件。

**文件功能概览**

`time64.c` 文件是 Android Bionic C 库的一部分，主要目的是为 32 位 Android 系统提供处理 64 位时间戳的能力，以解决著名的 “2038 年问题”。 传统的 32 位 `time_t` 类型在 2038 年 1 月 19 日之后会发生溢出，导致时间表示错误。`time64.c` 提供的函数使用 `time64_t` (通常是 `long long`) 来存储时间戳，从而可以表示更久远的未来时间。

**主要功能列表**

该文件主要提供以下功能：

1. **64 位时间的结构体和类型定义:** 定义了 `time64_t` 类型，用于存储 64 位的时间戳。
2. **`gmtime64_r()` 和 `localtime64_r()`:**  分别是 `gmtime_r()` 和 `localtime_r()` 的 64 位版本。它们将 64 位时间戳转换为 `struct tm` 结构体，分别表示 UTC 时间和本地时间。
3. **`mktime64()` 和 `timelocal64()`:**  分别是 `mktime()` 的 64 位版本。它们将 `struct tm` 结构体转换为 64 位时间戳（本地时间）。`timelocal64()` 实际上就是 `mktime64()` 的别名。
4. **`asctime64_r()` 和 `ctime64_r()`:** 分别是 `asctime_r()` 和 `ctime_r()` 的 64 位版本。它们将 `struct tm` 结构体或 64 位时间戳格式化为可读的字符串。
5. **非线程安全版本:**  提供了 `localtime64()`, `gmtime64()`, `asctime64()`, `ctime64()`，这些函数使用静态缓冲区存储结果，因此不是线程安全的。
6. **辅助宏和常量:**  定义了一些辅助宏（如 `IS_LEAP` 判断闰年）和常量（如 `days_in_month` 每个月的天数），用于日期和时间计算。
7. **兼容性处理:**  通过宏 `HAS_LOCALTIME_R` 和 `HAS_GMTIME_R` 来判断系统是否提供了线程安全的 `localtime_r` 和 `gmtime_r` 函数，如果没有则提供替代的 `fake_localtime_r` 和 `fake_gmtime_r`。
8. **安全年份映射:**  `safe_year()` 函数及其相关的 `safe_years_high` 和 `safe_years_low` 数组用于将超出 32 位 `time_t` 表示范围的年份映射到一个安全的年份区间，以便使用标准的 `localtime_r` 和 `gmtime_r` 函数进行中间计算。

**与 Android 功能的关系及举例说明**

`time64.c` 对于 Android 系统的稳定性和未来兼容性至关重要。

* **解决 2038 年问题:**  对于运行在 32 位架构上的 Android 设备（虽然现在大部分是 64 位），`time64.c` 提供的函数可以处理 2038 年之后的时间，避免了时间溢出导致的各种错误。
* **系统 API 的支持:** Android 系统的一些底层 API 或服务可能需要处理未来的时间戳，例如：
    * **AlarmManager:** 设置在未来很长时间后触发的闹钟。
    * **Calendar/Date API:** Java 层面的日期和时间 API 底层可能调用到 Native 层的这些 64 位时间函数。
    * **File System Timestamps:** 某些文件系统操作可能会涉及未来时间的文件时间戳。

**举例说明:**

假设一个 Android 应用需要在 2040 年执行某个操作。如果只使用 32 位的 `time_t`，时间戳会溢出。通过使用 `time64_t` 和 `time64.c` 提供的函数，应用可以正确地处理这个未来的时间。例如，可以使用 `mktime64()` 将一个表示 2040 年某个日期的 `struct tm` 结构体转换为 `time64_t` 时间戳，然后传递给相关的系统 API。

**每一个 libc 函数的功能及实现详解**

* **`gmtime64_r(const Time64_T *in_time, struct TM *p)`:**
    * **功能:** 将一个 64 位 UTC 时间戳 `in_time` 转换为 `struct TM` 结构体，并将结果存储在 `p` 指向的内存中。
    * **实现:**
        1. **检查系统 `gmtime_r`:** 如果 `SHOULD_USE_SYSTEM_GMTIME(*in_time)` 为真（时间戳在系统 `gmtime_r` 的安全范围内），则直接调用系统的 `gmtime_r` 进行转换。
        2. **手动计算:** 否则，进行一系列的数学运算，将时间戳分解为秒、分、时、天。
        3. **处理闰年和月份:**  根据格里高利历的规则，计算年份、月份和日期，并处理闰年。
        4. **处理大时间跨度优化:** 使用 `CHEAT_DAYS` 和格里高利周期计算来加速大时间跨度的转换。
        5. **边界检查:**  检查年份是否溢出。
        6. **填充 `struct TM`:** 将计算出的年、月、日、时、分、秒等信息填充到 `p` 指向的 `struct TM` 结构体中。

* **`localtime64_r(const Time64_T *time, struct TM *local_tm)`:**
    * **功能:** 将一个 64 位时间戳 `time` 转换为本地时间的 `struct TM` 结构体，并将结果存储在 `local_tm` 指向的内存中。
    * **实现:**
        1. **检查系统 `localtime_r`:** 如果 `SHOULD_USE_SYSTEM_LOCALTIME(*time)` 为真，则直接调用系统的 `localtime_r` 进行转换。
        2. **转换为 UTC 时间:**  先调用 `gmtime64_r()` 将 64 位时间戳转换为 UTC 的 `struct TM` 结构体。
        3. **安全年份映射:** 如果 UTC 时间的年份超出 32 位 `time_t` 的表示范围，则使用 `safe_year()` 将年份映射到一个安全的年份。
        4. **转换为本地时间:**  使用 `timegm64()` 将映射后的安全年份的 `struct TM` 结构体转换为 `time_t` (32 位)。然后调用系统的 `localtime_r()` 将这个 `time_t` 值转换为本地时间的 `struct tm`。
        5. **恢复原始年份:** 将本地时间 `struct tm` 的年份恢复为原始的年份。
        6. **处理跨年跨月的情况:**  处理 UTC 时间和本地时间由于时区差异导致的跨年跨月的情况。
        7. **边界检查:** 检查年份是否溢出。
        8. **填充 `struct TM`:** 将结果填充到 `local_tm` 指向的 `struct TM` 结构体中。

* **`mktime64(const struct TM *input_date)` 和 `timelocal64(const struct TM *date)`:**
    * **功能:** 将本地时间的 `struct TM` 结构体转换为 64 位时间戳。`timelocal64` 只是 `mktime64` 的别名。
    * **实现:**
        1. **安全年份检查:**  检查输入 `struct TM` 的年份是否在 32 位 `time_t` 的安全范围内。
        2. **直接调用 `mktime`:** 如果年份安全，则直接将 `struct TM` 转换为 `struct tm` 并调用系统的 `mktime()`。
        3. **安全年份转换和计算差值:** 如果年份不安全，则使用 `safe_year()` 将年份映射到一个安全的年份，并将 `struct TM` 转换为 `struct tm` 并调用 `mktime()`。然后，计算原始年份和安全年份之间的时间差，并将这个差值加到 `mktime()` 的结果上。

* **`asctime64_r(const struct TM *date, char *result)`:**
    * **功能:** 将 `struct TM` 结构体格式化为 `Www Mmm dd hh:mm:ss yyyy\n` 格式的字符串，并将结果存储在 `result` 指向的缓冲区中。
    * **实现:**  使用 `snprintf` 函数将 `struct TM` 的各个字段格式化为指定的字符串。

* **`ctime64_r(const Time64_T *time, char *result)`:**
    * **功能:** 将 64 位时间戳转换为本地时间，并格式化为 `Www Mmm dd hh:mm:ss yyyy\n` 格式的字符串，并将结果存储在 `result` 指向的缓冲区中。
    * **实现:**  先调用 `localtime64_r()` 将时间戳转换为 `struct TM`，然后调用 `asctime64_r()` 进行格式化。

**涉及 dynamic linker 的功能**

`time64.c` 本身的代码不直接涉及动态链接器的操作，因为它属于 `libc.so` 这个共享库的一部分。动态链接器（在 Android 上是 `linker` 或 `linker64`）负责在程序启动时加载 `libc.so`，并将程序中对 `time64.c` 中定义的函数的调用链接到 `libc.so` 中的实际实现。

**so 布局样本:**

假设 `libc.so` 的部分布局如下（简化）：

```
libc.so:
    .text:  // 代码段
        ...
        gmtime64_r:  // gmtime64_r 函数的代码
            ...
        localtime64_r: // localtime64_r 函数的代码
            ...
        mktime64:     // mktime64 函数的代码
            ...
        ...
    .data:  // 数据段
        ...
    .dynamic: // 动态链接信息
        DT_SYMTAB:  // 符号表
            ...
            gmtime64_r  (地址)
            localtime64_r (地址)
            mktime64     (地址)
            ...
        DT_STRTAB:  // 字符串表
            ...
            "gmtime64_r"
            "localtime64_r"
            "mktime64"
            ...
        DT_SONAME:  "libc.so"
        ...
```

**链接的处理过程:**

1. **编译:** 当一个程序（例如，一个 NDK 应用）调用了 `gmtime64_r()` 函数时，编译器会在生成的目标文件中记录一个对 `gmtime64_r` 的未定义引用。
2. **链接:** 链接器在链接这个程序时，会查找程序依赖的共享库（通常在编译时指定）。
3. **加载:** 当程序启动时，Android 的动态链接器会加载程序依赖的共享库，包括 `libc.so`。
4. **符号解析:** 动态链接器会读取 `libc.so` 的 `.dynamic` 段中的符号表 (`DT_SYMTAB`) 和字符串表 (`DT_STRTAB`)。它会查找程序中未定义的符号（例如 `gmtime64_r`）在 `libc.so` 中的地址。
5. **重定位:** 动态链接器会将程序中对 `gmtime64_r` 的调用地址重定向到 `libc.so` 中 `gmtime64_r` 函数的实际地址。

**逻辑推理：假设输入与输出**

**假设输入 `gmtime64_r`:**

```c
Time64_T timestamp = 1678886400LL; // 2023-03-15 00:00:00 UTC
struct TM result;
```

**预期输出 `gmtime64_r`:**

```
result.tm_sec = 0
result.tm_min = 0
result.tm_hour = 0
result.tm_mday = 15
result.tm_mon = 2  // March (0-based)
result.tm_year = 123 // 2023 - 1900
result.tm_wday = 3  // Wednesday (0-based, Sunday is 0)
result.tm_yday = 73  // Day of the year (0-based)
result.tm_isdst = 0
```

**假设输入 `localtime64_r` (假设时区为 Asia/Shanghai，UTC+8):**

```c
Time64_T timestamp = 1678886400LL; // 2023-03-15 00:00:00 UTC
struct TM result;
```

**预期输出 `localtime64_r`:**

```
result.tm_sec = 0
result.tm_min = 0
result.tm_hour = 8
result.tm_mday = 15
result.tm_mon = 2
result.tm_year = 123
result.tm_wday = 3
result.tm_yday = 73
result.tm_isdst = 0
```

**假设输入 `mktime64`:**

```c
struct TM input_tm = {
    .tm_sec = 30,
    .tm_min = 15,
    .tm_hour = 10,
    .tm_mday = 20,
    .tm_mon = 5, // June
    .tm_year = 145 // 2045
};
```

**预期输出 `mktime64` (假设时区为 Asia/Shanghai):**

输出将会是一个 `Time64_T` 类型的时间戳，表示 2045 年 6 月 20 日 10:15:30 在 Asia/Shanghai 时区的 Unix 时间戳。具体的数值需要根据实际的 `mktime` 实现来计算。

**涉及用户或者编程常见的使用错误**

1. **忽略返回值:**  某些函数（例如 `localtime64_r`, `gmtime64_r`）在发生错误时可能返回 `NULL`，用户应该检查返回值以处理错误情况。
2. **缓冲区溢出:**  在使用 `asctime64_r` 和 `ctime64_r` 时，需要确保提供的缓冲区足够大以容纳结果字符串。文档中提到 `asctime64_r` 的缓冲区至少需要 26 字节。
3. **线程安全问题:**  直接使用非线程安全版本的函数 (`localtime64`, `gmtime64`, `asctime64`, `ctime64`) 在多线程环境中可能导致数据竞争和未定义行为。应该优先使用带 `_r` 后缀的线程安全版本。
4. **时区处理不当:**  混淆 UTC 时间和本地时间，或者在没有正确设置时区的情况下进行时间转换。
5. **假设 `time_t` 是 64 位的:**  在 32 位 Android 系统上，`time_t` 仍然是 32 位的。用户应该使用 `time64_t` 和相关的 64 位函数来处理超出 2038 年的时间。

**举例说明错误:**

```c
// 错误示例：忽略返回值
struct TM my_tm;
localtime64_r(&my_timestamp, &my_tm); // 如果 my_timestamp 无效，可能返回 NULL，导致后续使用 my_tm 时出现问题

// 正确示例：检查返回值
struct TM my_tm;
if (localtime64_r(&my_timestamp, &my_tm) == NULL) {
    // 处理错误
    perror("localtime64_r failed");
} else {
    // 使用 my_tm
}
```

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `time64.c` 的调用路径 (简化):**

1. **Java Framework API 调用:**  例如，`java.util.Calendar` 或 `java.util.Date` 类的方法被调用，需要获取或设置时间。
2. **JNI 调用:**  Java Framework 层的方法通过 JNI (Java Native Interface) 调用到 Android 运行时 (ART) 或 Dalvik 虚拟机中的 Native 代码。
3. **Native Framework 或 Library:**  Android 的 Native Framework (例如，System Server 的某些部分) 或其他 Native 库可能会调用 Bionic 的 C 库函数。
4. **Bionic `libc` 函数:** Native 代码最终会调用 `libc.so` 中提供的日期和时间函数，例如 `localtime64_r` 或 `gmtime64_r`。

**NDK 到 `time64.c` 的调用路径:**

1. **NDK 应用调用:**  NDK 开发的应用直接使用 C/C++ 代码，可以调用 Bionic 提供的标准 C 库函数。
2. **Bionic `libc` 函数:**  NDK 应用中的代码直接链接到 `libc.so`，并调用 `time64.c` 中定义的函数。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `localtime64_r` 函数调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
    var localtime64_r_ptr = Module.findExportByName("libc.so", "localtime64_r");
} else if (Process.arch === 'arm' || Process.arch === 'ia32') {
    var localtime64_r_ptr = Module.findExportByName("libc.so", "__localtime64_r"); // 32位系统可能使用不同的符号名称
}

if (localtime64_r_ptr) {
    Interceptor.attach(localtime64_r_ptr, {
        onEnter: function (args) {
            console.log("[*] Hooking localtime64_r");
            this.time = ptr(args[0]).readU64();
            this.result_ptr = ptr(args[1]);
            console.log("\tTime (timestamp): " + this.time);
            console.log("\tResult struct tm* : " + this.result_ptr);
        },
        onLeave: function (retval) {
            if (retval.isNull()) {
                console.log("\tReturn value: NULL");
            } else {
                console.log("\tReturn value: " + retval);
                var tm_sec = this.result_ptr.readInt();
                var tm_min = this.result_ptr.add(4).readInt();
                var tm_hour = this.result_ptr.add(8).readInt();
                var tm_mday = this.result_ptr.add(12).readInt();
                var tm_mon = this.result_ptr.add(16).readInt();
                var tm_year = this.result_ptr.add(20).readInt();
                console.log("\tstruct tm {");
                console.log("\t\ttm_sec: " + tm_sec);
                console.log("\t\ttm_min: " + tm_min);
                console.log("\t\ttm_hour: " + tm_hour);
                console.log("\t\ttm_mday: " + tm_mday);
                console.log("\t\ttm_mon: " + tm_mon);
                console.log("\t\ttm_year: " + tm_year);
                console.log("\t}");
            }
        }
    });
} else {
    console.error("[-] Failed to find localtime64_r in libc.so");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_localtime64.js`）。
2. 使用 Frida 连接到目标 Android 进程：`frida -U -f <package_name> -l hook_localtime64.js --no-pause` 或 `frida -H <device_ip>:<port> <process_name> -l hook_localtime64.js`。
3. 当目标应用调用 `localtime64_r` 时，Frida 会拦截调用并打印出相关的参数（时间戳、`struct tm` 指针）和返回值（`struct tm` 指针以及结构体的内容）。

这个 Frida Hook 示例可以帮助你调试哪些代码路径会调用到 `localtime64_r`，以及传递的参数和返回的结果是什么。你可以根据需要修改 Hook 代码来拦截其他函数或提取更多信息。

希望以上详细的分析能够帮助你理解 `bionic/libc/bionic/time64.c` 文件的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/time64.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*

Copyright (c) 2007-2008  Michael G Schwern

This software originally derived from Paul Sheer's pivotal_gmtime_r.c.

The MIT License:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

/* See http://code.google.com/p/y2038 for this code's origin */

#if defined(__LP64__)
#error This cruft should be LP32 only!
#endif

/*

Programmers who have available to them 64-bit time values as a 'long
long' type can use localtime64_r() and gmtime64_r() which correctly
converts the time even on 32-bit systems. Whether you have 64-bit time
values will depend on the operating system.

localtime64_r() is a 64-bit equivalent of localtime_r().

gmtime64_r() is a 64-bit equivalent of gmtime_r().

*/

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "time64.h"

/* BIONIC_BEGIN */
/* the following are here to avoid exposing time64_config.h and
 * other types in our public time64.h header
 */
#include "time64_config.h"

/* Not everyone has gm/localtime_r(), provide a replacement */
#ifdef HAS_LOCALTIME_R
# define LOCALTIME_R(clock, result) localtime_r(clock, result)
#else
# define LOCALTIME_R(clock, result) fake_localtime_r(clock, result)
#endif
#ifdef HAS_GMTIME_R
# define GMTIME_R(clock, result) gmtime_r(clock, result)
#else
# define GMTIME_R(clock, result) fake_gmtime_r(clock, result)
#endif

typedef int64_t  Int64;
typedef time64_t Time64_T;
typedef int64_t  Year;
#define  TM      tm
/* BIONIC_END */

/* Spec says except for stftime() and the _r() functions, these
   all return static memory.  Stabbings! */
static struct TM   Static_Return_Date;
static char        Static_Return_String[35];

static const int days_in_month[2][12] = {
    {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
    {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
};

static const int julian_days_by_month[2][12] = {
    {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334},
    {0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335},
};

static char const wday_name[7][3] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static char const mon_name[12][3] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const int length_of_year[2] = { 365, 366 };

/* Some numbers relating to the gregorian cycle */
static const Year     years_in_gregorian_cycle   = 400;
#define               days_in_gregorian_cycle      ((365 * 400) + 100 - 4 + 1)
static const Time64_T seconds_in_gregorian_cycle = days_in_gregorian_cycle * 60LL * 60LL * 24LL;

/* Year range we can trust the time funcitons with */
#define MAX_SAFE_YEAR 2037
#define MIN_SAFE_YEAR 1971

/* 28 year Julian calendar cycle */
#define SOLAR_CYCLE_LENGTH 28

/* Year cycle from MAX_SAFE_YEAR down. */
static const int safe_years_high[SOLAR_CYCLE_LENGTH] = {
    2016, 2017, 2018, 2019,
    2020, 2021, 2022, 2023,
    2024, 2025, 2026, 2027,
    2028, 2029, 2030, 2031,
    2032, 2033, 2034, 2035,
    2036, 2037, 2010, 2011,
    2012, 2013, 2014, 2015
};

/* Year cycle from MIN_SAFE_YEAR up */
static const int safe_years_low[SOLAR_CYCLE_LENGTH] = {
    1996, 1997, 1998, 1971,
    1972, 1973, 1974, 1975,
    1976, 1977, 1978, 1979,
    1980, 1981, 1982, 1983,
    1984, 1985, 1986, 1987,
    1988, 1989, 1990, 1991,
    1992, 1993, 1994, 1995,
};

/* Let's assume people are going to be looking for dates in the future.
   Let's provide some cheats so you can skip ahead.
   This has a 4x speed boost when near 2008.
*/
/* Number of days since epoch on Jan 1st, 2008 GMT */
#define CHEAT_DAYS  (1199145600 / 24 / 60 / 60)
#define CHEAT_YEARS 108

#define IS_LEAP(n)      ((!(((n) + 1900) % 400) || (!(((n) + 1900) % 4) && (((n) + 1900) % 100))) != 0)
#define WRAP(a,b,m)     ((a) = ((a) <  0  ) ? ((b)--, (a) + (m)) : (a))

#ifdef USE_SYSTEM_LOCALTIME
#    define SHOULD_USE_SYSTEM_LOCALTIME(a)  (       \
    (a) <= SYSTEM_LOCALTIME_MAX &&              \
    (a) >= SYSTEM_LOCALTIME_MIN                 \
)
#else
#    define SHOULD_USE_SYSTEM_LOCALTIME(a)      (0)
#endif

#ifdef USE_SYSTEM_GMTIME
#    define SHOULD_USE_SYSTEM_GMTIME(a)     (       \
    (a) <= SYSTEM_GMTIME_MAX    &&              \
    (a) >= SYSTEM_GMTIME_MIN                    \
)
#else
#    define SHOULD_USE_SYSTEM_GMTIME(a)         (0)
#endif

/* Multi varadic macros are a C99 thing, alas */
#ifdef TIME_64_DEBUG
#    define TRACE(format) (fprintf(stderr, format))
#    define TRACE1(format, var1)    (fprintf(stderr, format, var1))
#    define TRACE2(format, var1, var2)    (fprintf(stderr, format, var1, var2))
#    define TRACE3(format, var1, var2, var3)    (fprintf(stderr, format, var1, var2, var3))
#else
#    define TRACE(format) ((void)0)
#    define TRACE1(format, var1) ((void)0)
#    define TRACE2(format, var1, var2) ((void)0)
#    define TRACE3(format, var1, var2, var3) ((void)0)
#endif


static int is_exception_century(Year year)
{
    int is_exception = ((year % 100 == 0) && !(year % 400 == 0));
    TRACE1("# is_exception_century: %s\n", is_exception ? "yes" : "no");

    return(is_exception);
}


/* timegm() is not in the C or POSIX spec, but it is such a useful
   extension I would be remiss in leaving it out.  Also I need it
   for localtime64()
*/
Time64_T timegm64(const struct TM *date) {
    Time64_T days    = 0;
    Time64_T seconds = 0;
    Year     year;
    Year     orig_year = (Year)date->tm_year;
    int      cycles  = 0;

    if( orig_year > 100 ) {
        cycles = (orig_year - 100) / 400;
        orig_year -= cycles * 400;
        days      += (Time64_T)cycles * days_in_gregorian_cycle;
    }
    else if( orig_year < -300 ) {
        cycles = (orig_year - 100) / 400;
        orig_year -= cycles * 400;
        days      += (Time64_T)cycles * days_in_gregorian_cycle;
    }
    TRACE3("# timegm/ cycles: %d, days: %lld, orig_year: %lld\n", cycles, days, orig_year);

    if( orig_year > 70 ) {
        year = 70;
        while( year < orig_year ) {
            days += length_of_year[IS_LEAP(year)];
            year++;
        }
    }
    else if ( orig_year < 70 ) {
        year = 69;
        do {
            days -= length_of_year[IS_LEAP(year)];
            year--;
        } while( year >= orig_year );
    }


    days += julian_days_by_month[IS_LEAP(orig_year)][date->tm_mon];
    days += date->tm_mday - 1;

    seconds = days * 60 * 60 * 24;

    seconds += date->tm_hour * 60 * 60;
    seconds += date->tm_min * 60;
    seconds += date->tm_sec;

    return(seconds);
}


#if !defined(NDEBUG)
static int check_tm(struct TM *tm)
{
    /* Don't forget leap seconds */
    assert(tm->tm_sec >= 0);
    assert(tm->tm_sec <= 61);

    assert(tm->tm_min >= 0);
    assert(tm->tm_min <= 59);

    assert(tm->tm_hour >= 0);
    assert(tm->tm_hour <= 23);

    assert(tm->tm_mday >= 1);
    assert(tm->tm_mday <= days_in_month[IS_LEAP(tm->tm_year)][tm->tm_mon]);

    assert(tm->tm_mon  >= 0);
    assert(tm->tm_mon  <= 11);

    assert(tm->tm_wday >= 0);
    assert(tm->tm_wday <= 6);

    assert(tm->tm_yday >= 0);
    assert(tm->tm_yday <= length_of_year[IS_LEAP(tm->tm_year)]);

#ifdef HAS_TM_TM_GMTOFF
    assert(tm->tm_gmtoff >= -24 * 60 * 60);
    assert(tm->tm_gmtoff <=  24 * 60 * 60);
#endif

    return 1;
}
#endif


/* The exceptional centuries without leap years cause the cycle to
   shift by 16
*/
static Year cycle_offset(Year year)
{
    const Year start_year = 2000;
    Year year_diff  = year - start_year;
    Year exceptions;

    if( year > start_year )
        year_diff--;

    exceptions  = year_diff / 100;
    exceptions -= year_diff / 400;

    TRACE3("# year: %lld, exceptions: %lld, year_diff: %lld\n",
          year, exceptions, year_diff);

    return exceptions * 16;
}

/* For a given year after 2038, pick the latest possible matching
   year in the 28 year calendar cycle.

   A matching year...
   1) Starts on the same day of the week.
   2) Has the same leap year status.

   This is so the calendars match up.

   Also the previous year must match.  When doing Jan 1st you might
   wind up on Dec 31st the previous year when doing a -UTC time zone.

   Finally, the next year must have the same start day of week.  This
   is for Dec 31st with a +UTC time zone.
   It doesn't need the same leap year status since we only care about
   January 1st.
*/
static int safe_year(const Year year)
{
    int safe_year = 0;
    Year year_cycle;

    if( year >= MIN_SAFE_YEAR && year <= MAX_SAFE_YEAR ) {
        return (int)year;
    }

    year_cycle = year + cycle_offset(year);

    /* safe_years_low is off from safe_years_high by 8 years */
    if( year < MIN_SAFE_YEAR )
        year_cycle -= 8;

    /* Change non-leap xx00 years to an equivalent */
    if( is_exception_century(year) )
        year_cycle += 11;

    /* Also xx01 years, since the previous year will be wrong */
    if( is_exception_century(year - 1) )
        year_cycle += 17;

    year_cycle %= SOLAR_CYCLE_LENGTH;
    if( year_cycle < 0 )
        year_cycle = SOLAR_CYCLE_LENGTH + year_cycle;

    assert( year_cycle >= 0 );
    assert( year_cycle < SOLAR_CYCLE_LENGTH );
    if( year < MIN_SAFE_YEAR )
        safe_year = safe_years_low[year_cycle];
    else if( year > MAX_SAFE_YEAR )
        safe_year = safe_years_high[year_cycle];
    else
        assert(0);

    TRACE3("# year: %lld, year_cycle: %lld, safe_year: %d\n",
          year, year_cycle, safe_year);

    assert(safe_year <= MAX_SAFE_YEAR && safe_year >= MIN_SAFE_YEAR);

    return safe_year;
}


static void copy_tm_to_TM(const struct tm *src, struct TM *dest) {
    if( src == NULL ) {
        memset(dest, 0, sizeof(*dest));
    }
    else {
#       ifdef USE_TM64
            dest->tm_sec        = src->tm_sec;
            dest->tm_min        = src->tm_min;
            dest->tm_hour       = src->tm_hour;
            dest->tm_mday       = src->tm_mday;
            dest->tm_mon        = src->tm_mon;
            dest->tm_year       = (Year)src->tm_year;
            dest->tm_wday       = src->tm_wday;
            dest->tm_yday       = src->tm_yday;
            dest->tm_isdst      = src->tm_isdst;

#           ifdef HAS_TM_TM_GMTOFF
                dest->tm_gmtoff  = src->tm_gmtoff;
#           endif

#           ifdef HAS_TM_TM_ZONE
                dest->tm_zone  = src->tm_zone;
#           endif

#       else
            /* They're the same type */
            memcpy(dest, src, sizeof(*dest));
#       endif
    }
}


static void copy_TM_to_tm(const struct TM *src, struct tm *dest) {
    if( src == NULL ) {
        memset(dest, 0, sizeof(*dest));
    }
    else {
#       ifdef USE_TM64
            dest->tm_sec        = src->tm_sec;
            dest->tm_min        = src->tm_min;
            dest->tm_hour       = src->tm_hour;
            dest->tm_mday       = src->tm_mday;
            dest->tm_mon        = src->tm_mon;
            dest->tm_year       = (int)src->tm_year;
            dest->tm_wday       = src->tm_wday;
            dest->tm_yday       = src->tm_yday;
            dest->tm_isdst      = src->tm_isdst;

#           ifdef HAS_TM_TM_GMTOFF
                dest->tm_gmtoff  = src->tm_gmtoff;
#           endif

#           ifdef HAS_TM_TM_ZONE
                dest->tm_zone  = src->tm_zone;
#           endif

#       else
            /* They're the same type */
            memcpy(dest, src, sizeof(*dest));
#       endif
    }
}


/* Simulate localtime_r() to the best of our ability */
struct tm * fake_localtime_r(const time_t *clock, struct tm *result) {
    const struct tm *static_result = localtime(clock);

    assert(result != NULL);

    if( static_result == NULL ) {
        memset(result, 0, sizeof(*result));
        return NULL;
    }
    else {
        memcpy(result, static_result, sizeof(*result));
        return result;
    }
}



/* Simulate gmtime_r() to the best of our ability */
struct tm * fake_gmtime_r(const time_t *clock, struct tm *result) {
    const struct tm *static_result = gmtime(clock);

    assert(result != NULL);

    if( static_result == NULL ) {
        memset(result, 0, sizeof(*result));
        return NULL;
    }
    else {
        memcpy(result, static_result, sizeof(*result));
        return result;
    }
}


static Time64_T seconds_between_years(Year left_year, Year right_year) {
    int increment = (left_year > right_year) ? 1 : -1;
    Time64_T seconds = 0;
    int cycles;

    if( left_year > 2400 ) {
        cycles = (left_year - 2400) / 400;
        left_year -= cycles * 400;
        seconds   += cycles * seconds_in_gregorian_cycle;
    }
    else if( left_year < 1600 ) {
        cycles = (left_year - 1600) / 400;
        left_year += cycles * 400;
        seconds   += cycles * seconds_in_gregorian_cycle;
    }

    while( left_year != right_year ) {
        seconds += length_of_year[IS_LEAP(right_year - 1900)] * 60 * 60 * 24;
        right_year += increment;
    }

    return seconds * increment;
}


/* This implementation violates mktime specification, according to which
   tm_yday, tm_wday, and tm_isdst fields should be updated. This function
   leaves input_date unmodified. Given that there were no bug reports, fixing
   it might cause more troubles than just leaving it as it is.
 */
Time64_T mktime64(const struct TM *input_date) {
    struct tm safe_date;
    struct TM date;
    Time64_T  time;
    Year      year = input_date->tm_year + 1900;

    if( MIN_SAFE_YEAR <= year && year <= MAX_SAFE_YEAR ) {
        copy_TM_to_tm(input_date, &safe_date);
        return (Time64_T)mktime(&safe_date);
    }

    /* Have to make the year safe in date else it won't fit in safe_date */
    date = *input_date;
    date.tm_year = safe_year(year) - 1900;
    copy_TM_to_tm(&date, &safe_date);

    time = (Time64_T)mktime(&safe_date);

    time += seconds_between_years(year, (Year)(safe_date.tm_year + 1900));

    return time;
}


/* Because I think mktime() is a crappy name */
Time64_T timelocal64(const struct TM *date) {
    return mktime64(date);
}


struct TM *gmtime64_r (const Time64_T *in_time, struct TM *p)
{
    int v_tm_sec, v_tm_min, v_tm_hour, v_tm_mon, v_tm_wday;
    Time64_T v_tm_tday;
    int leap;
    Time64_T m;
    Time64_T time = *in_time;
    Year year = 70;
    int cycles = 0;

    assert(p != NULL);

    /* Use the system gmtime() if time_t is small enough */
    if( SHOULD_USE_SYSTEM_GMTIME(*in_time) ) {
        time_t safe_time = *in_time;
        struct tm safe_date;
        GMTIME_R(&safe_time, &safe_date);

        copy_tm_to_TM(&safe_date, p);
        assert(check_tm(p));

        return p;
    }

#ifdef HAS_TM_TM_GMTOFF
    p->tm_gmtoff = 0;
#endif
    p->tm_isdst  = 0;

#ifdef HAS_TM_TM_ZONE
    p->tm_zone   = "UTC";
#endif

    v_tm_sec =  (int)(time % 60);
    time /= 60;
    v_tm_min =  (int)(time % 60);
    time /= 60;
    v_tm_hour = (int)(time % 24);
    time /= 24;
    v_tm_tday = time;

    WRAP (v_tm_sec, v_tm_min, 60);
    WRAP (v_tm_min, v_tm_hour, 60);
    WRAP (v_tm_hour, v_tm_tday, 24);

    v_tm_wday = (int)((v_tm_tday + 4) % 7);
    if (v_tm_wday < 0)
        v_tm_wday += 7;
    m = v_tm_tday;

    if (m >= CHEAT_DAYS) {
        year = CHEAT_YEARS;
        m -= CHEAT_DAYS;
    }

    if (m >= 0) {
        /* Gregorian cycles, this is huge optimization for distant times */
        cycles = (int)(m / (Time64_T) days_in_gregorian_cycle);
        if( cycles ) {
            m -= (cycles * (Time64_T) days_in_gregorian_cycle);
            year += (cycles * years_in_gregorian_cycle);
        }

        /* Years */
        leap = IS_LEAP (year);
        while (m >= (Time64_T) length_of_year[leap]) {
            m -= (Time64_T) length_of_year[leap];
            year++;
            leap = IS_LEAP (year);
        }

        /* Months */
        v_tm_mon = 0;
        while (m >= (Time64_T) days_in_month[leap][v_tm_mon]) {
            m -= (Time64_T) days_in_month[leap][v_tm_mon];
            v_tm_mon++;
        }
    } else {
        year--;

        /* Gregorian cycles */
        cycles = (int)((m / (Time64_T) days_in_gregorian_cycle) + 1);
        if( cycles ) {
            m -= (cycles * (Time64_T) days_in_gregorian_cycle);
            year += (cycles * years_in_gregorian_cycle);
        }

        /* Years */
        leap = IS_LEAP (year);
        while (m < (Time64_T) -length_of_year[leap]) {
            m += (Time64_T) length_of_year[leap];
            year--;
            leap = IS_LEAP (year);
        }

        /* Months */
        v_tm_mon = 11;
        while (m < (Time64_T) -days_in_month[leap][v_tm_mon]) {
            m += (Time64_T) days_in_month[leap][v_tm_mon];
            v_tm_mon--;
        }
        m += (Time64_T) days_in_month[leap][v_tm_mon];
    }

    p->tm_year = year;
    if( p->tm_year != year ) {
#ifdef EOVERFLOW
        errno = EOVERFLOW;
#endif
        return NULL;
    }

    /* At this point m is less than a year so casting to an int is safe */
    p->tm_mday = (int) m + 1;
    p->tm_yday = julian_days_by_month[leap][v_tm_mon] + (int)m;
    p->tm_sec  = v_tm_sec;
    p->tm_min  = v_tm_min;
    p->tm_hour = v_tm_hour;
    p->tm_mon  = v_tm_mon;
    p->tm_wday = v_tm_wday;

    assert(check_tm(p));

    return p;
}


struct TM *localtime64_r (const Time64_T *time, struct TM *local_tm)
{
    time_t safe_time;
    struct tm safe_date;
    struct TM gm_tm;
    Year orig_year;
    int month_diff;

    assert(local_tm != NULL);

    /* Use the system localtime() if time_t is small enough */
    if( SHOULD_USE_SYSTEM_LOCALTIME(*time) ) {
        safe_time = *time;

        TRACE1("Using system localtime for %lld\n", *time);

        LOCALTIME_R(&safe_time, &safe_date);

        copy_tm_to_TM(&safe_date, local_tm);
        assert(check_tm(local_tm));

        return local_tm;
    }

    if( gmtime64_r(time, &gm_tm) == NULL ) {
        TRACE1("gmtime64_r returned null for %lld\n", *time);
        return NULL;
    }

    orig_year = gm_tm.tm_year;

    if (gm_tm.tm_year > (2037 - 1900) ||
        gm_tm.tm_year < (1970 - 1900)
       )
    {
        TRACE1("Mapping tm_year %lld to safe_year\n", (Year)gm_tm.tm_year);
        gm_tm.tm_year = safe_year((Year)(gm_tm.tm_year + 1900)) - 1900;
    }

    safe_time = timegm64(&gm_tm);
    if( LOCALTIME_R(&safe_time, &safe_date) == NULL ) {
        TRACE1("localtime_r(%d) returned NULL\n", (int)safe_time);
        return NULL;
    }

    copy_tm_to_TM(&safe_date, local_tm);

    local_tm->tm_year = orig_year;
    if( local_tm->tm_year != orig_year ) {
        TRACE2("tm_year overflow: tm_year %lld, orig_year %lld\n",
              (Year)local_tm->tm_year, (Year)orig_year);

#ifdef EOVERFLOW
        errno = EOVERFLOW;
#endif
        return NULL;
    }


    month_diff = local_tm->tm_mon - gm_tm.tm_mon;

    /*  When localtime is Dec 31st previous year and
        gmtime is Jan 1st next year.
    */
    if( month_diff == 11 ) {
        local_tm->tm_year--;
    }

    /*  When localtime is Jan 1st, next year and
        gmtime is Dec 31st, previous year.
    */
    if( month_diff == -11 ) {
        local_tm->tm_year++;
    }

    /* GMT is Jan 1st, xx01 year, but localtime is still Dec 31st
       in a non-leap xx00.  There is one point in the cycle
       we can't account for which the safe xx00 year is a leap
       year.  So we need to correct for Dec 31st comming out as
       the 366th day of the year.
    */
    if( !IS_LEAP(local_tm->tm_year) && local_tm->tm_yday == 365 )
        local_tm->tm_yday--;

    assert(check_tm(local_tm));

    return local_tm;
}


static int valid_tm_wday( const struct TM* date ) {
    if( 0 <= date->tm_wday && date->tm_wday <= 6 )
        return 1;
    else
        return 0;
}

static int valid_tm_mon( const struct TM* date ) {
    if( 0 <= date->tm_mon && date->tm_mon <= 11 )
        return 1;
    else
        return 0;
}


char *asctime64_r( const struct TM* date, char *result ) {
    /* I figure everything else can be displayed, even hour 25, but if
       these are out of range we walk off the name arrays */
    if (!valid_tm_wday(date) || !valid_tm_mon(date)) {
        return NULL;
    }

    /* Docs state this function does not support years beyond 9999. */
    if (1900 + date->tm_year > 9999) {
        return NULL;
    }

    /*
     * The IBM docs for this function state that the result buffer can be
     * assumed to be at least 26 bytes wide. The docs also state that this is
     * only valid for years <= 9999, so we know this format string will not
     * print more than that many characters.
     *
     * http://www-01.ibm.com/support/knowledgecenter/SSLTBW_2.1.0/com.ibm.zos.v2r1.bpxbd00/asctimer.htm
     */
    snprintf(result, 26, "%.3s %.3s%3d %.2d:%.2d:%.2d %d\n",
        wday_name[date->tm_wday],
        mon_name[date->tm_mon],
        date->tm_mday, date->tm_hour,
        date->tm_min, date->tm_sec,
        1900 + date->tm_year);

    return result;
}


char *ctime64_r( const Time64_T* time, char* result ) {
    struct TM date;

    localtime64_r( time, &date );
    return asctime64_r( &date, result );
}


/* Non-thread safe versions of the above */
struct TM *localtime64(const Time64_T *time) {
    return localtime64_r(time, &Static_Return_Date);
}

struct TM *gmtime64(const Time64_T *time) {
    return gmtime64_r(time, &Static_Return_Date);
}

char *asctime64( const struct TM* date ) {
    return asctime64_r( date, Static_Return_String );
}

char *ctime64( const Time64_T* time ) {
    return asctime64(localtime64(time));
}
```