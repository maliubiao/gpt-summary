Response:
The user wants to understand the functionality of the `bionic/libc/include/time.h` header file in Android. I need to:

1. **List the functionalities:**  Go through each function, macro, and structure defined in the header and describe its purpose.
2. **Explain the relationship with Android:**  Highlight how these functionalities are used or relevant in the Android operating system.
3. **Detail libc function implementations:** Explain how the standard C library functions related to time are implemented in bionic. This might involve mentioning system calls they wrap.
4. **Address dynamic linker aspects:** Identify if any functions directly involve the dynamic linker. Based on the content, `time.h` primarily deals with time-related functions and doesn't directly interact with the dynamic linker. However, it's used by libraries loaded by the dynamic linker. I need to provide a sample SO layout and explain the general linking process, even if this specific header doesn't initiate it.
5. **Provide examples of logical reasoning:** For functions that involve calculations or transformations (like converting between time formats), create hypothetical inputs and their corresponding outputs.
6. **Illustrate common usage errors:**  Point out typical mistakes developers make when using these time-related functions.
7. **Explain how Android Framework/NDK reaches here:** Describe the path from higher-level Android components (Java framework, NDK) to the C library functions defined in this header.
8. **Offer Frida hook examples:** Provide code snippets demonstrating how to use Frida to intercept and monitor the execution of some of these functions.

**Plan:**

* Iterate through the `time.h` file, explaining each element.
* For each function, consider its Android relevance, implementation details, potential errors, and how it's used in Android development.
* Since there are no direct dynamic linker functions in this header, I will focus on how libraries using these functions are linked.
* Create simple, illustrative examples for input/output and common errors.
* Outline the calling sequence from Android Framework/NDK to these libc functions.
* Write basic Frida hook examples for some key time functions.
这个 `bionic/libc/include/time.h` 文件是 Android C 库 (bionic) 中关于时间和时钟功能的头文件。它定义了用于处理时间和时区的结构体、宏定义和函数声明。

**功能列表:**

1. **基本时间获取:**
    * `time()`: 获取自 Unix 纪元（1970-01-01 00:00:00 UTC）以来的秒数。
2. **时间睡眠:**
    * `nanosleep()`: 让当前线程休眠指定的时间（纳秒精度）。
    * `clock_nanosleep()`:  基于指定的时钟休眠指定的时间。
3. **时间格式化与解析:**
    * `asctime()`: 将 `tm` 结构体表示的时间转换为可读的字符串格式。
    * `asctime_r()`: `asctime()` 的线程安全版本，将结果存储在提供的缓冲区中。
    * `ctime()`: 将 `time_t` 表示的时间转换为可读的字符串格式。
    * `ctime_r()`: `ctime()` 的线程安全版本，将结果存储在提供的缓冲区中。
    * `strftime()`:  使用指定的格式将 `tm` 结构体表示的时间格式化为字符串。
    * `strftime_l()`:  `strftime()` 的本地化版本（但在 Android 上等同于 `strftime()`，因为只支持 C/POSIX locale）。
    * `strptime()`:  将字符串解析为 `tm` 结构体表示的时间。
    * `strptime_l()`:  `strptime()` 的本地化版本（但在 Android 上等同于 `strptime()`）。
4. **时间转换:**
    * `localtime()`: 将 `time_t` 表示的 UTC 时间转换为本地时间，结果存储在静态缓冲区中。
    * `localtime_r()`: `localtime()` 的线程安全版本，将结果存储在提供的 `tm` 结构体中。
    * `localtime_rz()`:  使用指定的时区将 `time_t` 表示的 UTC 时间转换为本地时间。
    * `gmtime()`: 将 `time_t` 表示的时间转换为 UTC 时间，结果存储在静态缓冲区中。
    * `gmtime_r()`: `gmtime()` 的线程安全版本，将结果存储在提供的 `tm` 结构体中。
    * `mktime()`: 将 `tm` 结构体表示的本地时间转换为 `time_t` (自 Unix 纪元以来的秒数)。
    * `mktime_z()`:  使用指定的时区将 `tm` 结构体表示的本地时间转换为 `time_t`。
    * `timelocal()`:  `mktime()` 的别名（在某些系统中）。
    * `timegm()`: 将 `tm` 结构体表示的 UTC 时间转换为 `time_t`。
5. **时区处理:**
    * `tzset()`:  通知 libc 时区已更改，会读取系统属性 `persist.sys.timezone` 和环境变量 `TZ`。
    * `tzalloc()`:  为给定的 Olson ID 分配一个时区对象。
    * `tzfree()`:  释放由 `tzalloc()` 分配的时区对象。
    * `tzname`: 全局变量，存储当前时区的非夏令时和夏令时名称。
    * `daylight`: 全局变量，指示当前时区是否使用夏令时。
    * `timezone`: 全局变量，存储 UTC 和当前时区之间的秒数差。
6. **高精度时钟:**
    * `clock()`: 获取进程使用的 CPU 时间的近似值。
    * `clock_getcpuclockid()`: 获取给定进程的 CPU 时间时钟的 ID。
    * `clock_getres()`: 获取指定时钟的分辨率。
    * `clock_gettime()`: 获取指定时钟的当前时间。
    * `clock_settime()`: 设置指定时钟的时间（需要特权）。
7. **POSIX 计时器:**
    * `timer_create()`: 创建一个 POSIX 计时器。
    * `timer_delete()`: 删除一个 POSIX 计时器。
    * `timer_settime()`: 启动或停止一个 POSIX 计时器。
    * `timer_gettime()`: 获取计时器下次触发的时间。
    * `timer_getoverrun()`: 获取计时器上次触发时错过的次数。
8. **其他:**
    * `difftime()`: 计算两个 `time_t` 值之间的时间差（以秒为单位）。
    * `timespec_get()`: 获取与指定基准（如 `CLOCK_REALTIME`）对应的时钟时间。
    * `timespec_getres()`: 获取与指定基准对应的时钟分辨率。
    * `CLOCKS_PER_SEC`: 宏定义，用于将 `clock()` 的返回值转换为秒。
    * `struct tm`:  表示分解时间的结构体（年、月、日、小时、分钟、秒等）。
    * `struct timespec`: 表示以秒和纳秒为单位的时间间隔的结构体。
    * `struct sigevent`: 用于计时器通知的事件结构体。
    * `timezone_t`:  表示时区的类型。
    * `TIME_UTC`, `TIME_MONOTONIC`, `TIME_ACTIVE`, `TIME_THREAD_ACTIVE`:  `timespec_get()` 和 `timespec_getres()` 的时间基准常量。

**与 Android 功能的关系及举例说明:**

* **系统时间:** Android 系统使用这些函数来获取和设置系统时间。例如，在设置应用中更改时区或时间，最终会调用到 `clock_settime()` 或影响 `tzset()` 的行为。
* **应用开发:** Android 应用（包括 Java 代码和 Native 代码）经常使用这些函数来处理时间相关的操作，如记录事件发生的时间戳、设置定时任务、显示当前时间等。
    * **Java 代码:**  Android Framework 提供了 `java.util.Date`, `java.util.Calendar`, `java.time` 等类来处理时间。这些 Java 类在底层会通过 JNI 调用到 bionic 提供的 C 函数。
    * **NDK 开发:** 使用 NDK 开发的 C/C++ 应用可以直接使用 `time.h` 中声明的函数。
* **AlarmManager:** Android 的 `AlarmManager` 服务允许应用在未来的某个时间执行操作。这通常涉及到使用 `timer_create()` 和 `timer_settime()` 等函数来设置定时器。
* **线程睡眠:** 应用可以使用 `nanosleep()` 让线程暂停执行一段时间，例如在动画的每一帧之间添加延迟。
* **日志记录:** Android 系统和应用经常需要在日志中记录时间戳，这会用到如 `strftime()` 或 `ctime()` 等函数。
* **时区处理:**  Android 系统需要处理不同地区的时区差异，`tzset()`, `tzalloc()`, `localtime_r()`, `gmtime_r()` 等函数在其中扮演重要角色。例如，在接收到来自其他时区的事件时，需要进行时区转换。

**详细解释每一个 libc 函数的功能是如何实现的:**

由于 `time.h` 是头文件，它只包含函数声明。具体的实现位于 bionic 库的源文件中（通常在 `bionic/libc/bionic/` 目录下）。以下是一些函数的实现方式概述：

* **`time()`:**  通常会调用底层的 Linux 系统调用 `gettimeofday()` 或 `clock_gettime(CLOCK_REALTIME)` 来获取当前时间，并将其转换为自 Unix 纪元以来的秒数。
* **`nanosleep()`:**  直接对应 Linux 系统调用 `nanosleep()`，该系统调用会使调用线程休眠指定的时间。
* **`asctime()` 和 `asctime_r()`:**  这些函数将 `tm` 结构体中的各个字段（年、月、日等）格式化为固定的字符串形式。它们内部可能会使用静态缓冲区（`asctime()`）或用户提供的缓冲区（`asctime_r()`）。
* **`ctime()` 和 `ctime_r()`:**  内部会先调用 `localtime_r()` 将 `time_t` 转换为本地时间的 `tm` 结构体，然后调用类似 `asctime()` 的格式化函数。
* **`strftime()` 和 `strftime_l()`:**  这是一个复杂的函数，它根据提供的格式字符串解析 `tm` 结构体中的时间信息，并将结果写入缓冲区。实现会处理各种格式化指令（如 `%Y`, `%m`, `%d` 等）。
* **`strptime()` 和 `strptime_l()`:**  与 `strftime()` 相反，它解析输入字符串，根据格式字符串提取时间信息，并填充到 `tm` 结构体中。
* **`localtime()` 和 `localtime_r()`:** 这些函数涉及到时区转换。它们会读取时区信息（可能来自 `/usr/share/zoneinfo` 目录下的时区数据库），并根据这些信息将 UTC 时间转换为本地时间。`localtime()` 使用静态缓冲区，而 `localtime_r()` 是线程安全的。
* **`localtime_rz()`:**  与 `localtime_r()` 类似，但使用用户提供的 `timezone_t` 对象，避免了全局时区状态的线程安全问题。
* **`gmtime()` 和 `gmtime_r()`:**  将 `time_t` 转换为 UTC 时间的 `tm` 结构体。相对简单，不需要读取复杂的时区信息。
* **`mktime()` 和 `mktime_z()`:**  将 `tm` 结构体表示的本地时间转换为 `time_t`。这涉及到逆向的时区计算，可能需要考虑闰年、夏令时等因素。
* **`tzset()`:**  核心功能是读取系统属性 `persist.sys.timezone` 和环境变量 `TZ`，然后加载对应的时区信息到 libc 的全局状态中，影响后续的 `localtime()` 等函数的行为。
* **`tzalloc()` 和 `tzfree()`:**  提供了线程安全的方式来处理时区。`tzalloc()` 会加载指定 Olson ID 的时区信息并返回一个 `timezone_t` 对象，`tzfree()` 用于释放该对象。
* **`clock()`:**  通常会调用 `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)` 并将结果转换为 `clock_t` 类型。
* **`clock_getcpuclockid()`:**  调用底层的系统调用，用于获取特定进程的 CPU 时钟 ID。
* **`clock_getres()`，`clock_gettime()`，`clock_settime()`，`clock_nanosleep()`:** 这些函数直接对应于 Linux 的 `clock_getres()`, `clock_gettime()`, `clock_settime()`, `clock_nanosleep()` 系统调用，提供了对各种系统时钟的访问和控制。
* **`timer_create()`，`timer_delete()`，`timer_settime()`，`timer_gettime()`，`timer_getoverrun()`:** 这些函数直接对应于 Linux 的 POSIX 计时器相关的系统调用。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`time.h` 本身不直接涉及 dynamic linker 的功能。然而，bionic 库（`libc.so`）中实现了这些函数，而 `libc.so` 是由 dynamic linker 加载的。

**so 布局样本 (`libc.so` 的简化示例):**

```
libc.so:
    .text:  # 代码段，包含 time(), nanosleep() 等函数的机器码
        time:
            # time() 函数的汇编代码
        nanosleep:
            # nanosleep() 函数的汇编代码
        ...

    .rodata: # 只读数据段，可能包含一些常量字符串，例如用于时间格式化的字符串
        asctime_format: "..."

    .data:  # 可读写数据段，包含全局变量，例如 tzname, daylight, timezone
        tzname: ...
        daylight: ...
        timezone: ...

    .bss:   # 未初始化数据段

    .dynsym: # 动态符号表，列出可以被其他共享库引用的符号 (函数和全局变量)
        time
        nanosleep
        asctime
        ...

    .dynstr: # 动态字符串表，存储 .dynsym 中符号的名称字符串

    .plt:   # Procedure Linkage Table，过程链接表，用于延迟绑定
        条目指向 time@GLIBC_...
        条目指向 nanosleep@GLIBC_...
        ...

    .got:   # Global Offset Table，全局偏移表，存储外部符号的地址
        time 的实际地址 (在运行时由 linker 填充)
        nanosleep 的实际地址 (在运行时由 linker 填充)
        ...
```

**链接的处理过程 (以调用 `time()` 函数为例):**

1. **编译时:** 当你编译一个 C/C++ 程序并使用了 `time()` 函数时，编译器会在生成的目标文件中记录对 `time` 符号的未解析引用。
2. **链接时:**  静态链接器（在构建 APK 的过程中）会将你的目标文件与 bionic 库进行链接。它会找到 `libc.so` 中 `time` 符号的定义，并更新你的目标文件，使其知道 `time` 函数位于 `libc.so` 中。
3. **运行时:** 当你的应用程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载应用程序依赖的共享库，包括 `libc.so`。
4. **加载 `libc.so`:** dynamic linker 会将 `libc.so` 加载到内存中，并将其各个段（如 `.text`, `.data`）映射到相应的内存地址。
5. **符号解析 (延迟绑定):** 默认情况下，Android 使用延迟绑定。当你的程序第一次调用 `time()` 函数时：
    * CPU 会跳转到 `time` 在 `.plt` 中的条目。
    * `.plt` 中的代码会跳转到 dynamic linker 预先设置好的代码。
    * dynamic linker 会查找 `libc.so` 的符号表 (`.dynsym`)，找到 `time` 符号的实际内存地址。
    * dynamic linker 将 `time` 的实际地址写入 `.got.plt` 中 `time` 对应的条目。
    * dynamic linker 再次跳转到 `time` 函数的实际地址。
6. **后续调用:**  后续对 `time()` 的调用会直接跳转到 `.plt` 中，然后直接从 `.got.plt` 获取 `time` 的实际地址，避免了重复的符号解析过程。

**如果做了逻辑推理，请给出假设输入与输出:**

* **`mktime()` 示例:**
    * **假设输入:** 一个 `tm` 结构体，表示 2023 年 10 月 27 日 10:30:00 (本地时间，假设时区为 Asia/Shanghai，没有夏令时)。
    ```c
    struct tm t;
    t.tm_year = 2023 - 1900; // 年份需要减去 1900
    t.tm_mon = 10 - 1;     // 月份从 0 开始
    t.tm_mday = 27;
    t.tm_hour = 10;
    t.tm_min = 30;
    t.tm_sec = 0;
    t.tm_isdst = -1;       // 让 mktime 自动判断是否是夏令时
    ```
    * **输出:** `mktime(&t)` 的返回值将是自 Unix 纪元以来到 2023-10-27 10:30:00 Asia/Shanghai 的秒数。你需要使用其他工具或函数来验证具体的数值。
* **`strftime()` 示例:**
    * **假设输入:** 一个 `tm` 结构体，表示 2023 年 10 月 27 日，格式字符串为 "%Y-%m-%d"。
    ```c
    struct tm t;
    char buf[20];
    t.tm_year = 2023 - 1900;
    t.tm_mon = 10 - 1;
    t.tm_mday = 27;
    strftime(buf, sizeof(buf), "%Y-%m-%d", &t);
    ```
    * **输出:** `buf` 将包含字符串 "2023-10-27"。
* **`strptime()` 示例:**
    * **假设输入:** 字符串 "2023/11/15 14:45:30"，格式字符串为 "%Y/%m/%d %H:%M:%S"。
    ```c
    struct tm t;
    strptime("2023/11/15 14:45:30", "%Y/%m/%d %H:%M:%S", &t);
    ```
    * **输出:** `t.tm_year` 将是 123，`t.tm_mon` 将是 10，`t.tm_mday` 将是 15，`t.tm_hour` 将是 14，`t.tm_min` 将是 45，`t.tm_sec` 将是 30。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **`tm_mon` 的范围:** 忘记 `tm_mon` 的范围是 0-11（而不是 1-12），导致月份错误。
    ```c
    struct tm t;
    t.tm_mon = 12; // 错误！应该使用 11 表示 12 月
    mktime(&t); // 可能导致意外的结果
    ```
* **`tm_year` 的范围:** 忘记 `tm_year` 是自 1900 年起的年数。
    ```c
    struct tm t;
    t.tm_year = 2023; // 错误！应该使用 2023 - 1900 = 123
    mktime(&t);
    ```
* **缓冲区溢出:** 在使用 `asctime_r()`、`ctime_r()` 或 `strftime()` 时，提供的缓冲区大小不足以存储结果字符串。
    ```c
    char buf[5]; // 缓冲区太小
    struct tm t;
    // ... 初始化 t ...
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t); // 可能发生缓冲区溢出
    ```
* **`localtime()` 的线程安全性:**  在多线程程序中使用 `localtime()`，因为其使用静态缓冲区，可能导致数据竞争和意外结果。应该使用 `localtime_r()` 或 `localtime_rz()`。
* **时区处理错误:**  在需要特定时区时，错误地依赖全局时区设置（通过 `tzset()`），而不是使用 `tzalloc()` 和 `localtime_rz()` 或 `mktime_z()` 来显式处理时区。
* **`strptime()` 的返回值检查:**  忘记检查 `strptime()` 的返回值，如果解析失败，返回值是 NULL。
    ```c
    struct tm t;
    if (strptime(time_str, "%Y-%m-%d", &t) == NULL) {
        // 解析失败，处理错误
    }
    ```
* **滥用 `tzset()`:** 在多线程程序中调用 `tzset()` 会影响所有线程的全局时区设置，可能导致难以调试的问题。应该避免在多线程环境中使用 `tzset()`。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `time.h` 函数的调用路径示例 (以获取当前时间为例):**

1. **Java 代码 (Android Framework):**
   ```java
   // 例如，在某个系统服务中或应用代码中
   long currentTimeMillis = System.currentTimeMillis();
   ```
2. **`System.currentTimeMillis()` 的实现:**  这个 Java 方法最终会调用到 `java.lang.System` 类的 native 方法 `currentTimeMillis()`.
3. **JNI 调用:**  Android Runtime (ART) 会通过 Java Native Interface (JNI) 调用到对应的 native 代码实现。
4. **Native 代码 (libjavacore.so 或 libart.so):**  在 ART 的相关库中，会找到 `System.currentTimeMillis()` 的 native 实现。这个实现通常会调用 bionic 库中的 `clock_gettime(CLOCK_REALTIME, ...)` 或 `gettimeofday(...)`.
5. **bionic 库 (libc.so):**  `clock_gettime()` 或 `gettimeofday()` 的实现位于 `libc.so` 中。

**NDK 到 `time.h` 函数的调用路径:**

1. **C/C++ 代码 (NDK):**
   ```c++
   #include <time.h>
   #include <stdio.h>

   int main() {
       time_t now = time(nullptr);
       printf("Current time: %ld\n", now);
       return 0;
   }
   ```
2. **编译和链接:**  使用 NDK 工具链编译上述代码，链接器会将你的代码与 `libc.so` 链接。
3. **运行时:**  当你的 NDK 应用运行时，它会直接调用 `libc.so` 中实现的 `time()` 函数。

**Frida Hook 示例:**

以下是一些使用 Frida hook `time()` 和 `localtime_r()` 函数的示例：

**Hook `time()`:**

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, "libc.so");
  if (libc) {
    const timePtr = Module.findExportByName(libc.name, "time");
    if (timePtr) {
      Interceptor.attach(timePtr, {
        onEnter: function (args) {
          console.log("[time] Entered");
        },
        onLeave: function (retval) {
          console.log("[time] Leaving, return value =", retval.toInt());
        }
      });
    } else {
      console.log("Could not find 'time' function.");
    }
  } else {
    console.log("Could not find 'libc.so'.");
  }
}
```

**Hook `localtime_r()`:**

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, "libc.so");
  if (libc) {
    const localtime_rPtr = Module.findExportByName(libc.name, "localtime_r");
    if (localtime_rPtr) {
      Interceptor.attach(localtime_rPtr, {
        onEnter: function (args) {
          console.log("[localtime_r] Entered");
          const timep = ptr(args[0]);
          const resultp = ptr(args[1]);
          console.log("[localtime_r] timep =", timep, ", resultp =", resultp);
          // 可以读取 timep 指向的值
          const timeVal = Memory.readLong(timep);
          console.log("[localtime_r] time value =", timeVal);
        },
        onLeave: function (retval) {
          console.log("[localtime_r] Leaving, return value =", retval);
          if (!retval.isNull()) {
            // 可以读取返回值指向的 tm 结构体
            const tm_sec = retval.readInt();
            const tm_min = retval.add(4).readInt();
            const tm_hour = retval.add(8).readInt();
            console.log("[localtime_r] Returned tm_sec =", tm_sec, ", tm_min =", tm_min, ", tm_hour =", tm_hour);
          }
        }
      });
    } else {
      console.log("Could not find 'localtime_r' function.");
    }
  } else {
    console.log("Could not find 'libc.so'.");
  }
}
```

**Frida 调试步骤:**

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。你的电脑上安装了 Frida 客户端 (`pip install frida-tools`).
2. **找到目标进程:** 确定你要 hook 的进程的包名或进程 ID。
3. **编写 Frida 脚本:**  根据你需要 hook 的函数编写 JavaScript 脚本（如上面的示例）。
4. **运行 Frida 脚本:** 使用 Frida 客户端连接到目标进程并执行脚本。
   ```bash
   frida -U -f <包名> -l <你的脚本.js> --no-pause  # 附加到应用启动
   # 或者
   frida -U <进程ID> -l <你的脚本.js>             # 附加到已运行的进程
   ```
5. **触发目标函数:** 在你的 Android 应用中执行会导致调用被 hook 函数的操作。
6. **查看 Frida 输出:**  Frida 会在你的终端中打印出 hook 函数的调用信息和参数。

通过 Frida hook，你可以动态地观察这些时间函数的调用，查看参数和返回值，有助于理解 Android Framework 和 NDK 如何与 bionic 库中的时间函数交互。

### 提示词
```
这是目录为bionic/libc/include/time.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

/**
 * @file time.h
 * @brief Clock and timer functionality.
 */

#include <sys/cdefs.h>
#include <sys/time.h>
#include <xlocale.h>

__BEGIN_DECLS

/* If we just use void* in the typedef, the compiler exposes that in error messages. */
struct __timezone_t;

/**
 * The `timezone_t` type that represents a timezone.
 *
 * To use this with std::unique_ptr you'll want something like
 * `std::unique_ptr<std::remove_pointer_t<timezone_t>, decltype(&tzfree)> tz{tzalloc("Asia/Seoul"), tzfree};`
 * to remove the pointer.
 */
typedef struct __timezone_t* timezone_t;

/** Divisor to compute seconds from the result of a call to clock(). */
#define CLOCKS_PER_SEC 1000000

/**
 * The name of the current timezone's non-daylight savings (`tzname[0]`) and
 * daylight savings (`tzname[1]`) variants. See tzset().
 */
extern char* _Nonnull tzname[];

/** Whether the current timezone ever uses daylight savings time. See tzset(). */
extern int daylight;

/** The difference in seconds between UTC and the current timezone. See tzset(). */
extern long int timezone;

struct sigevent;

/**
 * A "broken-down" time, useful for parsing/formatting times for human consumption.
 */
struct tm {
  /** Seconds, 0-60. (60 is a leap second.) */
  int tm_sec;
  /** Minutes, 0-59. */
  int tm_min;
  /** Hours, 0-23. */
  int tm_hour;
  /** Day of month, 1-31. */
  int tm_mday;
  /** Month of year, 0-11. (Not 1-12!) */
  int tm_mon;
  /** Years since 1900. (So 2023 is 123, not 2023!) */
  int tm_year;
  /** Day of week, 0-6. (Sunday is 0, Saturday is 6.) */
  int tm_wday;
  /** Day of year, 0-365. */
  int tm_yday;
  /** Daylight savings flag, positive for DST in effect, 0 for DST not in effect, and -1 for unknown. */
  int tm_isdst;
  /** Offset from UTC (GMT) in seconds for this time. */
  long int tm_gmtoff;
  /** Name of the timezone for this time. */
  const char* _Nullable tm_zone;
};

/** Alternative name for `tm_zone` in `struct tm`. */
#define TM_ZONE tm_zone

/**
 * [time(2)](https://man7.org/linux/man-pages/man2/time.2.html) returns
 * the number of seconds since the Unix epoch (1970-01-01 00:00:00 +0000).
 *
 * Returns the time in seconds on success, and returns -1 and sets `errno` on failure.
 */
time_t time(time_t* _Nullable __t);

/**
 * [nanosleep(2)](https://man7.org/linux/man-pages/man2/nanosleep.2.html) sleeps
 * for at least the given time (or until a signal arrives).
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure. If the sleep
 * was interrupted by a signal, `errno` will be `EINTR` and `remainder` will be
 * the amount of time remaining.
 */
int nanosleep(const struct timespec* _Nonnull __duration, struct timespec* _Nullable __remainder);

/**
 * [asctime(3)](https://man7.org/linux/man-pages/man3/asctime.3p.html) formats
 * the time `tm` as a string.
 *
 * Returns a pointer to a string on success, and returns NULL on failure.
 *
 * That string will be overwritten by later calls to this function.
 *
 * New code should prefer strftime().
 */
char* _Nullable asctime(const struct tm* _Nonnull __tm);

/**
 * [asctime_r(3)](https://man7.org/linux/man-pages/man3/asctime_r.3p.html) formats
 * the time `tm` as a string in the given buffer `buf`.
 *
 * Returns a pointer to a string on success, and returns NULL on failure.
 *
 * New code should prefer strftime().
 */
char* _Nullable asctime_r(const struct tm* _Nonnull __tm, char* _Nonnull __buf);

/**
 * [difftime(3)](https://man7.org/linux/man-pages/man3/difftime.3.html) returns
 * the difference between two times.
 *
 * Returns the difference in seconds.
 */
double difftime(time_t __lhs, time_t __rhs);

/**
 * [mktime(3)](https://man7.org/linux/man-pages/man3/mktime.3p.html) converts
 * broken-down time `tm` into the number of seconds since the Unix epoch.
 *
 * See tzset() for details of how the timezone is set, and mktime_rz()
 * for an alternative.
 *
 * Returns the time in seconds on success, and returns -1 and sets `errno` on failure.
 */
time_t mktime(struct tm* _Nonnull __tm);

/**
 * mktime_z(3) converts broken-down time `tm` into the number of seconds
 * since the Unix epoch, assuming the given timezone.
 *
 * Returns the time in seconds on success, and returns -1 and sets `errno` on failure.
 *
 * Available since API level 35.
 */

#if __BIONIC_AVAILABILITY_GUARD(35)
time_t mktime_z(timezone_t _Nonnull __tz, struct tm* _Nonnull __tm) __INTRODUCED_IN(35);
#endif /* __BIONIC_AVAILABILITY_GUARD(35) */


/**
 * [localtime(3)](https://man7.org/linux/man-pages/man3/localtime.3p.html) converts
 * the number of seconds since the Unix epoch in `t` to a broken-down time, taking
 * the device's timezone into account.
 *
 * That broken-down time will be overwritten by later calls to this function.
 *
 * Returns a pointer to a broken-down time on success, and returns null and sets `errno` on failure.
 */
struct tm* _Nullable localtime(const time_t* _Nonnull __t);

/**
 * [localtime_r(3)](https://man7.org/linux/man-pages/man3/localtime_r.3p.html) converts
 * the number of seconds since the Unix epoch in `t` to a broken-down time.
 * That broken-down time will be written to the given struct `tm`.
 *
 * See tzset() for details of how the timezone is set, and localtime_rz()
 * for an alternative.
 *
 * Returns a pointer to a broken-down time on success, and returns null and sets `errno` on failure.
 */
struct tm* _Nullable localtime_r(const time_t* _Nonnull __t, struct tm* _Nonnull __tm);

/**
 * localtime_rz(3) converts the number of seconds since the Unix epoch in
 * `t` to a broken-down time, assuming the given timezone. That broken-down
 * time will be written to the given struct `tm`.
 *
 * Returns a pointer to a broken-down time on success, and returns null and sets `errno` on failure.
 *
 * Available since API level 35.
 */

#if __BIONIC_AVAILABILITY_GUARD(35)
struct tm* _Nullable localtime_rz(timezone_t _Nonnull __tz, const time_t* _Nonnull __t, struct tm* _Nonnull __tm) __INTRODUCED_IN(35);
#endif /* __BIONIC_AVAILABILITY_GUARD(35) */


/**
 * Inverse of localtime().
 */
time_t timelocal(struct tm* _Nonnull __tm);

/**
 * [gmtime(3)](https://man7.org/linux/man-pages/man3/gmtime.3p.html) converts
 * the number of seconds since the Unix epoch in `t` to a broken-down time, using
 * UTC (historically also known as GMT).
 *
 * That broken-down time will be overwritten by later calls to this function.
 *
 * Returns a pointer to a broken-down time on success, and returns null and sets `errno` on failure.
 */
struct tm* _Nullable gmtime(const time_t* _Nonnull __t);

/**
 * [gmtime_r(3)](https://man7.org/linux/man-pages/man3/gmtime_r.3p.html) converts
 * the number of seconds since the Unix epoch in `t` to a broken-down time, using
 * UTC (historically also known as GMT).
 *
 * That broken-down time will be written to the provided struct `tm`.
 *
 * Returns a pointer to a broken-down time on success, and returns null and sets `errno` on failure.
 */
struct tm* _Nullable gmtime_r(const time_t* _Nonnull __t, struct tm* _Nonnull __tm);

/**
 * Inverse of gmtime().
 */
time_t timegm(struct tm* _Nonnull __tm);

/**
 * [strptime(3)](https://man7.org/linux/man-pages/man3/strptime.3.html) parses
 * a string `s` assuming format `fmt` into broken-down time `tm`.
 *
 * Returns a pointer to the first character _not_ parsed, or null if no characters were parsed.
 */
char* _Nullable strptime(const char* _Nonnull __s, const char* _Nonnull __fmt, struct tm* _Nonnull __tm) __strftimelike(2);

/**
 * Equivalent to strptime() on Android where only C/POSIX locales are available.
 */
char* _Nullable strptime_l(const char* _Nonnull __s, const char* _Nonnull __fmt, struct tm* _Nonnull __tm, locale_t _Nonnull __l) __strftimelike(2) __RENAME(strptime);

/**
 * [strftime(3)](https://man7.org/linux/man-pages/man3/strftime.3.html) formats
 * a broken-down time `tm` into the buffer `buf` using format `fmt`.
 *
 * Returns a pointer to the first character _not_ parsed, or null if no characters were parsed.
 */
size_t strftime(char* _Nonnull __buf, size_t __n, const char* _Nonnull __fmt, const struct tm* _Nullable __tm) __strftimelike(3);

/**
 * Equivalent to strftime() on Android where only C/POSIX locales are available.
 */
size_t strftime_l(char* _Nonnull __buf, size_t __n, const char* _Nonnull __fmt, const struct tm* _Nullable __tm, locale_t _Nonnull __l) __strftimelike(3);

/**
 * [ctime(3)](https://man7.org/linux/man-pages/man3/ctime.3p.html) formats
 * the time `tm` as a string.
 *
 * Returns a pointer to a string on success, and returns NULL on failure.
 *
 * That string will be overwritten by later calls to this function.
 *
 * New code should prefer strftime().
 */
char* _Nullable ctime(const time_t* _Nonnull __t);

/**
 * [ctime_r(3)](https://man7.org/linux/man-pages/man3/ctime.3p.html) formats
 * the time `tm` as a string in the given buffer `buf`.
 *
 * Returns a pointer to a string on success, and returns NULL on failure.
 *
 * New code should prefer strftime().
 */
char* _Nullable ctime_r(const time_t* _Nonnull __t, char* _Nonnull __buf);

/**
 * [tzset(3)](https://man7.org/linux/man-pages/man3/tzset.3.html) tells
 * libc that the timezone has changed.
 *
 * tzset() on Android looks at both the system property
 * `persist.sys.timezone` and the environment variable `TZ`. The former is
 * the device's current timezone as shown in Settings, while the latter is
 * usually unset but can be used to override the global setting. This is a
 * bad idea outside of unit tests or single-threaded programs because it's
 * inherently thread-unsafe. See tzalloc(), localtime_rz(), mktime_z(),
 * and tzfree() for an alternative.
 */
void tzset(void);

/**
 * tzalloc(3) allocates a timezone corresponding to the given Olson ID.
 *
 * A null `id` returns the system timezone (as seen in Settings) from
 * the system property `persist.sys.timezone`, ignoring `$TZ`. Although
 * tzset() honors `$TZ`, callers of tzalloc() can use `$TZ` themselves if
 * that's the (thread-unsafe) behavior they want, but by ignoring `$TZ`
 * tzalloc() is thread safe (though obviously the system timezone can
 * change, especially if your mobile device is actually mobile!).
 *
 * To use this with std::unique_ptr you'll want something like
 * `std::unique_ptr<std::remove_pointer_t<timezone_t>, decltype(&tzfree)> tz{tzalloc("Asia/Seoul"), tzfree};`
 * to remove the pointer.
 *
 * Returns a timezone object on success, and returns NULL and sets `errno` on failure.
 *
 * Available since API level 35.
 */

#if __BIONIC_AVAILABILITY_GUARD(35)
timezone_t _Nullable tzalloc(const char* _Nullable __id) __INTRODUCED_IN(35);

/**
 * tzfree(3) frees a timezone object returned by tzalloc().
 *
 * To use this with std::unique_ptr you'll want something like
 * `std::unique_ptr<std::remove_pointer_t<timezone_t>, decltype(&tzfree)> tz{tzalloc("Asia/Seoul"), tzfree};`
 * to remove the pointer.
 *
 * Available since API level 35.
 */
void tzfree(timezone_t _Nullable __tz) __INTRODUCED_IN(35);
#endif /* __BIONIC_AVAILABILITY_GUARD(35) */


/**
 * [clock(3)](https://man7.org/linux/man-pages/man3/clock.3.html)
 * returns an approximation of CPU time used, equivalent to
 * `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)` but with more confusing
 * units. Use `CLOCKS_PER_SEC` to convert the result to seconds.
 *
 * Returns the time in seconds on success, and returns -1 and sets `errno` on failure.
 *
 * New code should prefer `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)`.
 */
clock_t clock(void);

/**
 * [clock_getcpuclockid(3)](https://man7.org/linux/man-pages/man3/clock_getcpuclockid.3.html)
 * gets the clock ID of the cpu-time clock for the given `pid`.
 *
 * Returns 0 on success, and returns -1 and returns an error number on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(23)
int clock_getcpuclockid(pid_t __pid, clockid_t* _Nonnull __clock) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


/**
 * [clock_getres(2)](https://man7.org/linux/man-pages/man2/clock_getres.2.html)
 * gets the resolution of the given clock.
 *
 * Returns 0 on success, and returns -1 and returns an error number on failure.
 */
int clock_getres(clockid_t __clock, struct timespec* _Nullable __resolution);

/**
 * [clock_gettime(2)](https://man7.org/linux/man-pages/man2/clock_gettime.2.html)
 * gets the time according to the given clock.
 *
 * Returns 0 on success, and returns -1 and returns an error number on failure.
 */
int clock_gettime(clockid_t __clock, struct timespec* _Nonnull __ts);

/**
 * [clock_nanosleep(2)](https://man7.org/linux/man-pages/man2/clock_nanosleep.2.html)
 * sleeps for the given time (or until the given time if the TIMER_ABSTIME flag
 * is used), as measured by the given clock.
 *
 * Returns 0 on success, and returns -1 and returns an error number on failure.
 * If the sleep was interrupted by a signal, the return value will be `EINTR`
 * and `remainder` will be the amount of time remaining.
 */
int clock_nanosleep(clockid_t __clock, int __flags, const struct timespec* _Nonnull __time, struct timespec* _Nullable __remainder);

/**
 * [clock_settime(2)](https://man7.org/linux/man-pages/man2/clock_settime.2.html)
 * sets the time for the given clock.
 *
 * Returns 0 on success, and returns -1 and returns an error number on failure.
 */
int clock_settime(clockid_t __clock, const struct timespec* _Nonnull __ts);

/**
 * [timer_create(2)](https://man7.org/linux/man-pages/man2/timer_create.2.html)
 * creates a POSIX timer.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int timer_create(clockid_t __clock, struct sigevent* _Nullable __event, timer_t _Nonnull * _Nonnull __timer_ptr);

/**
 * [timer_delete(2)](https://man7.org/linux/man-pages/man2/timer_delete.2.html)
 * destroys a POSIX timer.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int timer_delete(timer_t _Nonnull __timer);

/**
 * [timer_settime(2)](https://man7.org/linux/man-pages/man2/timer_settime.2.html)
 * starts or stops a POSIX timer.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int timer_settime(timer_t _Nonnull __timer, int __flags, const struct itimerspec* _Nonnull __new_value, struct itimerspec* _Nullable __old_value);

/**
 * [timer_gettime(2)](https://man7.org/linux/man-pages/man2/timer_gettime.2.html)
 * gets the time until the given timer next fires.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int timer_gettime(timer_t _Nonnull _timer, struct itimerspec* _Nonnull __ts);

/**
 * [timer_getoverrun(2)](https://man7.org/linux/man-pages/man2/timer_getoverrun.2.html)
 * gets the overrun count (the number of times the timer should have fired, but
 * didn't) for the last time the timer fired.
 *
 * Returns the overrun count on success, and returns -1 and sets `errno` on failure.
 */
int timer_getoverrun(timer_t _Nonnull __timer);

/**
 * The timebase for timespec_get() and timespec_getres() corresponding to CLOCK_REALTIME.
 *
 * Available since API level 29.
 */
#define TIME_UTC (CLOCK_REALTIME+1)

/**
 * The timebase for timespec_get() and timespec_getres() corresponding to CLOCK_MONOTONIC.
 *
 * Available since API level 35.
 */
#define TIME_MONOTONIC (CLOCK_MONOTONIC+1)

/**
 * The timebase for timespec_get() and timespec_getres() corresponding to CLOCK_PROCESS_CPUTIME_ID.
 *
 * Available since API level 35.
 */
#define TIME_ACTIVE (CLOCK_PROCESS_CPUTIME_ID+1)

/**
 * The timebase for timespec_get() and timespec_getres() corresponding to CLOCK_THREAD_CPUTIME_ID.
 *
 * Available since API level 35.
 */
#define TIME_THREAD_ACTIVE (CLOCK_THREAD_CPUTIME_ID+1)

/**
 * timespec_get(3) is equivalent to clock_gettime() for the clock corresponding to the given base.
 *
 * Returns the base on success and returns 0 on failure.
 *
 * Available since API level 29 for TIME_UTC; other bases arrived later.
 * Code for Android should prefer clock_gettime().
 */

#if __BIONIC_AVAILABILITY_GUARD(29)
int timespec_get(struct timespec* _Nonnull __ts, int __base) __INTRODUCED_IN(29);
#endif /* __BIONIC_AVAILABILITY_GUARD(29) */


/**
 * timespec_getres(3) is equivalent to clock_getres() for the clock corresponding to the given base.
 *
 * Returns the base on success and returns 0 on failure.
 *
 * Available since API level 35.
 * Code for Android should prefer clock_gettime().
 */

#if __BIONIC_AVAILABILITY_GUARD(35)
int timespec_getres(struct timespec* _Nonnull __ts, int __base) __INTRODUCED_IN(35);
#endif /* __BIONIC_AVAILABILITY_GUARD(35) */


__END_DECLS
```