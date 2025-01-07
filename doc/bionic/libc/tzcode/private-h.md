Response:
Let's break down the thought process for analyzing the provided C header file.

**1. Initial Understanding - The Big Picture:**

The first step is to recognize what the file is and its purpose. The introductory comments clearly state: "Private header for tzdb code."  The path `bionic/libc/tzcode/private.handroid` and the description of Bionic further clarify that this file is a private header used by the time zone database code within Android's C library. The crucial takeaway here is "private"—this means it's *internal* to the tzcode implementation and not meant for direct use by applications.

**2. Identifying Key Functional Areas (by scanning and grouping):**

Next, I'd skim through the code, looking for distinct sections and patterns. I'd mentally (or physically) group related definitions and macros:

* **Copyright and Usage Restrictions:** The initial comments about being in the public domain but for internal use are important.
* **Compiler/Library Support Macros (PORT_TO_C89, SUPPORT_C89, __STDC_VERSION__):** These hints at handling different C standards and potentially older compilers.
* **Basic Type Definitions (true, false, bool, static_assert):**  Standard boolean definitions.
* **`USE_LTZ` and `GRANDPARENTED`:**  These look like specific configuration options or constants related to time zone handling.
* **Feature Detection Macros (HAVE_DECL_ASCTIME_R, HAVE_GETTEXT, etc.):**  A large section dedicated to detecting the presence of various functions and headers. This is common in portable C code.
* **GNU Extensions and POSIX Semantics (_GNU_SOURCE, _POSIX_PTHREAD_SEMANTICS, __EXTENSIONS__):**  Enabling specific extensions.
* **Time Bit Configuration (_FILE_OFFSET_BITS, _TIME_BITS):**  Dealing with 32-bit vs. 64-bit time representations.
* **Renaming Macros (localtime_rz, mktime_z, etc.):**  Avoiding naming conflicts, particularly relevant in a library like `libc`.
* **Includes:**  Standard C headers (`time.h`, `stddef.h`, `string.h`, etc.).
* **Error Code Definitions (EINVAL, ELOOP, etc.):**  Mapping error codes.
* **Feature Check for `strftime_l` and Time Zone Names (HAVE_STRFTIME_L, HAVE_TZNAME):** More feature detection.
* **Compiler-Specific Macros (PORT_TO_C89 block):** Handling older compilers and providing fallback definitions for things like `intmax_t`.
* **Checked Arithmetic Macros (ckd_add, ckd_sub, ckd_mul):** Safe arithmetic to prevent overflows.
* **Compiler Attributes (ATTRIBUTE_MALLOC, ATTRIBUTE_DEPRECATED, etc.):**  Hints for the compiler about function properties.
* **`time_tz` Configuration:** A mechanism to potentially use a custom `time_t` for testing or specific builds. This is a strong indicator of internal control and customization.
* **Redefining Standard Time Functions (asctime, ctime, localtime, etc.):**  This is the core of the time zone library's functionality – providing its own implementations. The `tz_` prefix suggests these are the internal versions.
* **Declarations with Conditional Compilation (HAVE_DECL_TIMEGM, HAVE_DECL_ENVIRON):** Providing declarations when the system headers don't.
* **NetBSD Compatibility (NETBSD_INSPIRED block):** Supporting NetBSD-specific functions.
* **Convenience Macros (TYPE_BIT, TYPE_SIGNED, min, max, MAXVAL, MINVAL):**  Helper macros for type manipulation.
* **Time Value Limits (TIME_T_MIN, TIME_T_MAX):** Defining the range of representable time values.
* **String Length Calculation (INT_STRLEN_MAXIMUM):**  Calculating the maximum length of an integer converted to a string.
* **Initialization Macro (INITIALIZE):**  Potentially used for zeroing out variables.
* **Unreachable Macro:**  Marking code that should never be reached.
* **Localization Macro (_):**  For internationalization.
* **Error Handling (HAVE_INCOMPATIBLE_CTIME_R):**  Addressing compatibility issues.
* **Time and Date Constants (SECSPERMIN, MINSPERHOUR, etc.):** Fundamental time units.

**3. Connecting to Android Functionality:**

With the functional areas identified, the next step is to connect them to Android's broader system. The key connection is the time zone handling. Android relies on a correct and up-to-date time zone database for various functionalities:

* **System Clock and Time Display:**  The most obvious connection.
* **Scheduling Events:**  `AlarmManager`, `JobScheduler` depend on accurate time.
* **Date and Time APIs:**  Java's `java.util.Date`, `java.util.Calendar`, and the newer `java.time` package ultimately rely on the underlying C library.
* **Networking and Security:**  Time synchronization (NTP) and certificate validation are time-sensitive.
* **Logging and Debugging:** Timestamps in logs are crucial for debugging.

The `tzcode` library is the fundamental building block for these time-related features in Android.

**4. Deep Dive into `libc` Functions (Conceptual):**

Since this is a *private* header, it doesn't *define* the `libc` functions. Instead, it provides declarations and potentially redefines them internally using the `tz_` prefix. Therefore, the explanation of `libc` function implementations needs to be more conceptual, focusing on their standard behavior related to time zone handling. For example, `localtime` converts a `time_t` value to local time based on the current time zone settings. The header provides mechanisms for the underlying implementation to achieve this.

**5. Dynamic Linker and SO Layout (Hypothetical):**

Because this is a *private* header, it's unlikely to directly expose dynamic linker functionality. However, understanding how the `tzcode` library itself might be structured as a shared object (`.so`) is relevant. I'd imagine a structure like:

```
libtz.so (example name)
  |-- .text (code for tz functions)
  |-- .rodata (read-only data, including timezone data files)
  |-- .data (initialized data)
  |-- .bss (uninitialized data)
  |-- .symtab (symbol table)
  |-- .dynsym (dynamic symbol table)
  |-- .rel.dyn (dynamic relocation information)
  |-- .rel.plt (procedure linkage table relocation)
```

The linking process would involve resolving symbols related to time zone conversions used by other parts of Bionic.

**6. Logical Inference, Assumptions, and Errors:**

Given the nature of the header file, direct logical inference with specific inputs and outputs isn't really applicable. The assumptions are more about the underlying system and how time is represented. Common errors would be related to incorrect time zone configuration or assumptions about time zone rules.

**7. Android Framework and NDK Journey, and Frida Hooking:**

Tracing how the Android Framework or NDK reaches this code involves understanding the call stack. An app using `java.util.Calendar` will eventually make native calls into Bionic's time-related functions, which in turn would use the `tzcode` library. Frida can be used to hook these native calls to observe the parameters and return values at different stages.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this file defines some core time zone data structures. **Correction:**  It's a *private header*, so it's more likely to *declare* structures used internally by the `tzcode` implementation, rather than define the actual data.
* **Initial thought:** Explain the exact algorithm of `localtime`. **Correction:**  Since it's a private header, the *implementation details* aren't exposed here. Focus on the *purpose* of the functions and the *mechanisms* provided by the header (like feature detection and redefinitions).
* **Realization:**  The heavy use of `#ifndef` and `#define` is crucial for understanding how this header adapts to different environments and configurations.

By following these steps, systematically analyzing the code, and connecting it to the broader Android ecosystem, I can generate a comprehensive and informative answer.
这个文件 `private.h` 是 Android Bionic C 库中 `tzcode` 模块的私有头文件。`tzcode` 模块负责处理时区信息的转换和管理。由于它是私有头文件，这意味着它主要用于 `tzcode` 模块的内部实现，不应该被外部代码直接包含和使用。

**功能列举:**

这个头文件定义了许多宏和类型定义，用于配置和支持 `tzcode` 模块的编译和运行。其核心功能可以归纳为：

1. **配置编译选项:**  定义了诸如 `PORT_TO_C89` 和 `SUPPORT_C89` 这样的宏，用于控制是否需要兼容旧的 C89 标准。虽然这些宏被标记为过时，但它们的存在表明了对不同编译环境的考虑。
2. **功能特性检测:**  通过 `HAVE_DECL_ASCTIME_R`, `HAVE_GETTEXT`, `HAVE_UNISTD_H` 等一系列 `HAVE_` 开头的宏，检测当前编译环境中是否存在特定的函数、头文件或语言特性。这使得 `tzcode` 可以在不同的系统和编译器下进行适配。
3. **系统兼容性处理:**  定义了一些宏来处理不同操作系统的差异，例如 `NETBSD_INSPIRED`。
4. **提供类型别名和宏:** 定义了像 `ATTRIBUTE_MALLOC`, `ATTRIBUTE_DEPRECATED` 这样的宏，用于提供编译器属性，以及像 `min`, `max` 这样的通用宏。
5. **处理 `time_t` 类型:**  通过 `TZ_TIME_T` 宏，允许使用自定义的 `time_t` 类型进行编译，这在测试和调试时很有用。同时，也定义了 `TIME_T_MIN` 和 `TIME_T_MAX` 来表示 `time_t` 的最小值和最大值。
6. **定义错误码:**  为了一些可能在 `tzcode` 中出现的错误定义了宏，例如 `EINVAL`, `ELOOP`。
7. **国际化支持:**  通过 `HAVE_GETTEXT` 宏检测 `gettext` 函数是否存在，以支持多语言环境。
8. **定义时间相关的常量:**  定义了 `SECSPERMIN`, `MINSPERHOUR`, `HOURSPERDAY` 等表示时间单位的常量。

**与 Android 功能的关系及举例说明:**

`tzcode` 模块是 Android 系统时间管理的核心组成部分，它直接影响着 Android 的以下功能：

* **系统时钟和日期显示:** Android 系统需要准确地显示当前时间，这依赖于 `tzcode` 正确处理时区信息。例如，当用户在 Android 设置中更改时区时，系统会调用 `tzcode` 相关的函数来更新时间显示。
* **定时任务和闹钟:** `AlarmManager` 和 `JobScheduler` 等服务依赖于准确的时间信息来触发定时任务。`tzcode` 保证了这些任务在用户所在时区正确的时间执行。
* **日期和时间相关的 API:** Android SDK 提供的 `java.util.Date`, `java.util.Calendar`, 以及新的 `java.time` 包，其底层实现会调用 Bionic C 库中的时间处理函数，而这些函数会用到 `tzcode` 提供的时区信息。
* **网络通信:** 许多网络协议，如 HTTP，都依赖于时间戳。`tzcode` 确保了 Android 设备发送和接收到的时间信息的准确性。
* **日志记录:** Android 系统的日志通常包含时间戳，`tzcode` 保证了这些时间戳反映了正确的本地时间。

**详细解释 libc 函数的功能是如何实现的:**

`private.h` 本身并不实现任何 `libc` 函数。它主要提供宏和类型定义来辅助 `tzcode` 模块的实现。`tzcode` 模块会使用这些定义来实现诸如 `localtime`, `gmtime`, `mktime` 等标准 C 库中与时间相关的函数。

例如，`localtime` 函数的功能是将一个 `time_t` 值（通常表示自 Epoch 以来的秒数）转换为本地时间的 `struct tm` 结构。`tzcode` 实现 `localtime` 的过程大致如下：

1. **获取当前时区信息:**  `localtime` 首先需要知道当前系统的时区设置。这通常是通过读取环境变量 `TZ` 或查找特定的时区数据文件来完成。
2. **查找时区规则:**  根据获取到的时区信息，`tzcode` 会查找对应的时区规则，包括标准时间偏移、夏令时规则等。
3. **应用时区偏移:**  将 `time_t` 值减去 UTC 的偏移量，得到本地时间。如果当前时间处于夏令时期间，还需要加上夏令时的偏移量。
4. **填充 `struct tm`:**  将计算得到的本地时间分解为年、月、日、时、分、秒等，并填充到 `struct tm` 结构中。

`private.h` 中的宏，例如 `TZ_TIME_T`，可能会影响 `localtime` 使用的 `time_t` 类型。功能特性检测宏，例如 `HAVE_GETTEXT`，可能会影响错误信息的国际化处理。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `private.h` 本身不直接涉及 dynamic linker 的功能，但 `tzcode` 模块最终会被编译成一个共享库（.so 文件），并由 dynamic linker 加载和链接。

**so 布局样本 (libtimezone.so - 示例名称):**

```
libtimezone.so:
    .text         # 包含可执行代码
    .rodata       # 包含只读数据，例如时区规则数据
    .data         # 包含已初始化的全局变量
    .bss          # 包含未初始化的全局变量
    .symtab       # 符号表，包含库中定义的全局符号
    .strtab       # 字符串表，存储符号名称
    .dynsym       # 动态符号表，包含需要动态链接的符号
    .dynstr       # 动态字符串表
    .plt          # Procedure Linkage Table，用于延迟绑定
    .got.plt      # Global Offset Table for PLT
    .rel.dyn      # 动态重定位信息
    .rel.plt      # PLT 的重定位信息
```

**链接的处理过程:**

1. **编译生成目标文件:**  `tzcode` 模块的源代码会被编译成一系列的目标文件 (.o)。
2. **链接生成共享库:**  链接器 (ld) 将这些目标文件以及相关的库文件链接在一起，生成 `libtimezone.so`。在链接过程中，链接器会处理符号引用和定义，确保所有需要的符号都能找到。
3. **加载共享库:**  当 Android 应用程序或系统服务需要使用 `tzcode` 提供的功能时，dynamic linker (通常是 `linker` 或 `linker64` 进程) 会负责加载 `libtimezone.so` 到进程的地址空间。
4. **符号解析和重定位:**  dynamic linker 会解析 `libtimezone.so` 中对其他共享库（例如 `libc.so`）的符号引用，并将这些引用绑定到目标库中的实际地址。同时，它还会根据 `.rel.dyn` 和 `.rel.plt` 中的信息，修改共享库中的代码和数据，以确保代码能够正确访问全局变量和调用外部函数。
5. **延迟绑定:**  对于一些函数调用，dynamic linker 可能会采用延迟绑定的策略。这意味着在第一次调用该函数时，dynamic linker 才会解析其地址并更新 PLT 和 GOT。

**如果做了逻辑推理，请给出假设输入与输出:**

`private.h` 主要定义宏和类型，本身不包含逻辑推理的代码。逻辑推理发生在 `tzcode` 模块的实现代码中。

例如，在 `localtime` 的实现中，可能存在这样的逻辑推理：

**假设输入:**

* `time_t` 值: `1678886400` (表示 UTC 时间 2023-03-15 00:00:00)
* 当前时区: "Asia/Shanghai"

**逻辑推理:**

1. 查询 "Asia/Shanghai" 时区的规则。
2. 确定 2023-03-15 00:00:00 UTC 对应的本地时间是否处于夏令时期间。在中国，通常没有夏令时。
3. 计算 UTC 偏移量：Asia/Shanghai 的 UTC 偏移量是 +8 小时。
4. 将 UTC 时间加上偏移量：2023-03-15 00:00:00 + 8 小时 = 2023-03-15 08:00:00。

**输出:**

一个 `struct tm` 结构，其中包含了 2023-03-15 08:00:00 的各个部分：

```
tm_sec = 0
tm_min = 0
tm_hour = 8
tm_mday = 15
tm_mon = 2  // 注意：月份从 0 开始，2 表示 3 月
tm_year = 123 // 年份是相对于 1900 的偏移量
tm_wday = 3  // 星期三
tm_yday = 73  // 一年中的第 73 天
tm_isdst = 0 // 没有夏令时
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然用户不会直接使用 `private.h`，但与 `tzcode` 相关的常见编程错误包括：

1. **错误的时区字符串:**  在设置时区环境变量 `TZ` 或调用 `tzset` 函数时，使用了不正确的时区字符串，导致时间转换错误。
   ```c
   // 错误示例：使用了错误的城市名
   setenv("TZ", "Invalid/TimeZone", 1);
   tzset();
   ```
2. **忽略时区信息:**  在处理时间时，没有考虑到时区的影响，导致在不同时区的设备上显示或处理时间时出现偏差。
   ```c
   time_t t = time(NULL);
   struct tm *local = localtime(&t); // 假设在某个特定时区
   // ... 将 local 中的时间信息传递到另一个系统，而没有明确时区
   ```
3. **混淆 UTC 和本地时间:**  没有清晰地区分 UTC 时间和本地时间，在进行时间转换或存储时发生错误。
   ```c
   time_t t = time(NULL);
   // 错误地将 UTC 时间当成本地时间处理
   printf("Current time: %s", ctime(&t));
   ```
4. **夏令时处理不当:**  在需要考虑夏令时的场景下，没有正确处理夏令时的开始和结束时间，导致时间计算错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

当 Android 应用程序需要获取或处理时间信息时，通常会通过以下步骤到达 `tzcode` 模块：

1. **Java 代码调用 Android Framework API:** 例如，使用 `java.util.Calendar` 或 `java.time` 包中的类来获取当前时间或进行时区转换。
   ```java
   Calendar calendar = Calendar.getInstance(); // 获取当前时区的 Calendar 实例
   Date now = new Date();
   ```

2. **Framework 层调用 Native 方法:**  Android Framework 中的 Java 代码会调用相应的 Native 方法（通常在 `libjavacrypto.so`, `libicuuc.so` 等库中），这些 Native 方法会进一步调用 Bionic C 库中的函数。

3. **Bionic C 库函数调用 `tzcode` 函数:**  例如，`java.util.Calendar.getInstance()` 最终可能会调用到 `localtime` 函数，而 `localtime` 的实现位于 `tzcode` 模块中。

**Frida Hook 示例:**

可以使用 Frida 来 Hook 这些调用，观察参数和返回值，从而调试调用链。以下是一个简单的 Frida Hook 示例，用于 Hook `localtime` 函数：

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, 'libc.so');
  if (libc) {
    const localtimePtr = Module.findExportByName(libc.name, 'localtime');
    if (localtimePtr) {
      Interceptor.attach(localtimePtr, {
        onEnter: function (args) {
          const timePtr = ptr(args[0]);
          const timeVal = timePtr.readS64();
          console.log(`[localtime] time_t: ${timeVal}`);
        },
        onLeave: function (retval) {
          if (!retval.isNull()) {
            const tmPtr = ptr(retval);
            const tm_sec = tmPtr.readInt();
            const tm_min = tmPtr.add(4).readInt();
            const tm_hour = tmPtr.add(8).readInt();
            // ... 读取其他 tm 结构成员
            console.log(`[localtime] struct tm: { tm_sec: ${tm_sec}, tm_min: ${tm_min}, tm_hour: ${tm_hour}, ... }`);
          } else {
            console.log('[localtime] returned NULL');
          }
        }
      });
      console.log('[Frida] localtime hooked');
    } else {
      console.log('[Frida] localtime not found');
    }
  } else {
    console.log('[Frida] libc.so not found');
  }
}
```

**调试步骤:**

1. **安装 Frida 和配置环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. **编写 Frida 脚本:**  将上面的 JavaScript 代码保存为 `.js` 文件。
3. **运行 Frida 脚本:**  使用 Frida 命令行工具将脚本注入到目标 Android 进程中。例如：
   ```bash
   frida -U -f <package_name> -l localtime_hook.js --no-pause
   ```
   将 `<package_name>` 替换为你要调试的应用程序的包名。
4. **触发时间相关的操作:**  在应用程序中执行会导致调用 `localtime` 等函数的操作，例如获取当前时间。
5. **查看 Frida 输出:**  Frida 会在控制台上打印出 Hook 到的 `localtime` 函数的输入参数（`time_t` 值）和输出结果（`struct tm` 结构的内容）。

通过这种方式，你可以观察到 Android Framework 是如何一步步调用到 Bionic C 库中的时间处理函数的，并分析 `tzcode` 模块在其中的作用。

请注意，由于 `private.h` 是私有头文件，其内部定义的宏和类型可能在 Android 的不同版本之间发生变化。因此，直接依赖这些私有定义进行开发是不可取的。开发者应该使用 Android SDK 提供的公共 API 来处理时间和时区信息。

Prompt: 
```
这是目录为bionic/libc/tzcode/private.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/* Private header for tzdb code.  */

#ifndef PRIVATE_H

#define PRIVATE_H

/*
** This file is in the public domain, so clarified as of
** 1996-06-05 by Arthur David Olson.
*/

/*
** This header is for use ONLY with the time conversion code.
** There is no guarantee that it will remain unchanged,
** or that it will remain at all.
** Do NOT copy it to any system include directory.
** Thank you!
*/

/* PORT_TO_C89 means the code should work even if the underlying
   compiler and library support only C89.  SUPPORT_C89 means the
   tzcode library should support C89 callers in addition to the usual
   support for C99-and-later callers.  These macros are obsolescent,
   and the plan is to remove them along with any code needed only when
   they are nonzero.  */
#ifndef PORT_TO_C89
# define PORT_TO_C89 0
#endif
#ifndef SUPPORT_C89
# define SUPPORT_C89 0
#endif

#ifndef __STDC_VERSION__
# define __STDC_VERSION__ 0
#endif

/* Define true, false and bool if they don't work out of the box.  */
#if PORT_TO_C89 && __STDC_VERSION__ < 199901
# define true 1
# define false 0
# define bool int
#elif __STDC_VERSION__ < 202311
# include <stdbool.h>
#endif

#if __STDC_VERSION__ < 202311
# define static_assert(cond) extern int static_assert_check[(cond) ? 1 : -1]
#endif

/*
** zdump has been made independent of the rest of the time
** conversion package to increase confidence in the verification it provides.
** You can use zdump to help in verifying other implementations.
** To do this, compile with -DUSE_LTZ=0 and link without the tz library.
*/
#ifndef USE_LTZ
# define USE_LTZ 1
#endif

/* This string was in the Factory zone through version 2016f.  */
#define GRANDPARENTED	"Local time zone must be set--see zic manual page"

/*
** Defaults for preprocessor symbols.
** You can override these in your C compiler options, e.g. '-DHAVE_GETTEXT=1'.
*/

#ifndef HAVE_DECL_ASCTIME_R
# define HAVE_DECL_ASCTIME_R 1
#endif

#if !defined HAVE__GENERIC && defined __has_extension
# if __has_extension(c_generic_selections)
#  define HAVE__GENERIC 1
# else
#  define HAVE__GENERIC 0
# endif
#endif
/* _Generic is buggy in pre-4.9 GCC.  */
#if !defined HAVE__GENERIC && defined __GNUC__ && !defined __STRICT_ANSI__
# define HAVE__GENERIC (4 < __GNUC__ + (9 <= __GNUC_MINOR__))
#endif
#ifndef HAVE__GENERIC
# define HAVE__GENERIC (201112 <= __STDC_VERSION__)
#endif

#if !defined HAVE_GETTEXT && defined __has_include
# if __has_include(<libintl.h>)
#  define HAVE_GETTEXT true
# endif
#endif
#ifndef HAVE_GETTEXT
# define HAVE_GETTEXT false
#endif

#ifndef HAVE_INCOMPATIBLE_CTIME_R
# define HAVE_INCOMPATIBLE_CTIME_R 0
#endif

#ifndef HAVE_LINK
# define HAVE_LINK 1
#endif /* !defined HAVE_LINK */

#ifndef HAVE_MALLOC_ERRNO
# define HAVE_MALLOC_ERRNO 1
#endif

#ifndef HAVE_POSIX_DECLS
# define HAVE_POSIX_DECLS 1
#endif

#ifndef HAVE_SETENV
# define HAVE_SETENV 1
#endif

#ifndef HAVE_STRDUP
# define HAVE_STRDUP 1
#endif

#ifndef HAVE_SYMLINK
# define HAVE_SYMLINK 1
#endif /* !defined HAVE_SYMLINK */

#if !defined HAVE_SYS_STAT_H && defined __has_include
# if !__has_include(<sys/stat.h>)
#  define HAVE_SYS_STAT_H false
# endif
#endif
#ifndef HAVE_SYS_STAT_H
# define HAVE_SYS_STAT_H true
#endif

#if !defined HAVE_UNISTD_H && defined __has_include
# if !__has_include(<unistd.h>)
#  define HAVE_UNISTD_H false
# endif
#endif
#ifndef HAVE_UNISTD_H
# define HAVE_UNISTD_H true
#endif

#ifndef NETBSD_INSPIRED
# define NETBSD_INSPIRED 1
#endif

#if HAVE_INCOMPATIBLE_CTIME_R
# define asctime_r _incompatible_asctime_r
# define ctime_r _incompatible_ctime_r
#endif /* HAVE_INCOMPATIBLE_CTIME_R */

/* Enable tm_gmtoff, tm_zone, and environ on GNUish systems.  */
#define _GNU_SOURCE 1
/* Fix asctime_r on Solaris 11.  */
#define _POSIX_PTHREAD_SEMANTICS 1
/* Enable strtoimax on pre-C99 Solaris 11.  */
#define __EXTENSIONS__ 1

/* On GNUish systems where time_t might be 32 or 64 bits, use 64.
   On these platforms _FILE_OFFSET_BITS must also be 64; otherwise
   setting _TIME_BITS to 64 does not work.  The code does not
   otherwise rely on _FILE_OFFSET_BITS being 64, since it does not
   use off_t or functions like 'stat' that depend on off_t.  */
#ifndef _FILE_OFFSET_BITS
# define _FILE_OFFSET_BITS 64
#endif
#if !defined _TIME_BITS && _FILE_OFFSET_BITS == 64
# define _TIME_BITS 64
#endif

/*
** Nested includes
*/

/* Avoid clashes with NetBSD by renaming NetBSD's declarations.
   If defining the 'timezone' variable, avoid a clash with FreeBSD's
   'timezone' function by renaming its declaration.  */
#define localtime_rz sys_localtime_rz
#define mktime_z sys_mktime_z
#define posix2time_z sys_posix2time_z
#define time2posix_z sys_time2posix_z
#if defined USG_COMPAT && USG_COMPAT == 2
# define timezone sys_timezone
#endif
#define timezone_t sys_timezone_t
#define tzalloc sys_tzalloc
#define tzfree sys_tzfree
#include <time.h>
#undef localtime_rz
#undef mktime_z
#undef posix2time_z
#undef time2posix_z
#if defined USG_COMPAT && USG_COMPAT == 2
# undef timezone
#endif
#undef timezone_t
#undef tzalloc
#undef tzfree

#include <stddef.h>
#include <string.h>
#if !PORT_TO_C89
# include <inttypes.h>
#endif
#include <limits.h>	/* for CHAR_BIT et al. */
#include <stdlib.h>

#include <errno.h>

#ifndef EINVAL
# define EINVAL ERANGE
#endif

#ifndef ELOOP
# define ELOOP EINVAL
#endif
#ifndef ENAMETOOLONG
# define ENAMETOOLONG EINVAL
#endif
#ifndef ENOMEM
# define ENOMEM EINVAL
#endif
#ifndef ENOTSUP
# define ENOTSUP EINVAL
#endif
#ifndef EOVERFLOW
# define EOVERFLOW EINVAL
#endif

#if HAVE_GETTEXT
# include <libintl.h>
#endif /* HAVE_GETTEXT */

#if HAVE_UNISTD_H
# include <unistd.h> /* for R_OK, and other POSIX goodness */
#endif /* HAVE_UNISTD_H */

#ifndef HAVE_STRFTIME_L
# if _POSIX_VERSION < 200809
#  define HAVE_STRFTIME_L 0
# else
#  define HAVE_STRFTIME_L 1
# endif
#endif

#ifndef USG_COMPAT
# ifndef _XOPEN_VERSION
#  define USG_COMPAT 0
# else
#  define USG_COMPAT 1
# endif
#endif

#ifndef HAVE_TZNAME
# if _POSIX_VERSION < 198808 && !USG_COMPAT
#  define HAVE_TZNAME 0
# else
#  define HAVE_TZNAME 1
# endif
#endif

#ifndef ALTZONE
# if defined __sun || defined _M_XENIX
#  define ALTZONE 1
# else
#  define ALTZONE 0
# endif
#endif

#ifndef R_OK
# define R_OK 4
#endif /* !defined R_OK */

#if PORT_TO_C89

/*
** Define HAVE_STDINT_H's default value here, rather than at the
** start, since __GLIBC__ and INTMAX_MAX's values depend on
** previously included files.  glibc 2.1 and Solaris 10 and later have
** stdint.h, even with pre-C99 compilers.
*/
#if !defined HAVE_STDINT_H && defined __has_include
# define HAVE_STDINT_H true /* C23 __has_include implies C99 stdint.h.  */
#endif
#ifndef HAVE_STDINT_H
# define HAVE_STDINT_H \
   (199901 <= __STDC_VERSION__ \
    || 2 < __GLIBC__ + (1 <= __GLIBC_MINOR__) \
    || __CYGWIN__ || INTMAX_MAX)
#endif /* !defined HAVE_STDINT_H */

#if HAVE_STDINT_H
# include <stdint.h>
#endif /* !HAVE_STDINT_H */

#ifndef HAVE_INTTYPES_H
# define HAVE_INTTYPES_H HAVE_STDINT_H
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif

/* Pre-C99 GCC compilers define __LONG_LONG_MAX__ instead of LLONG_MAX.  */
#if defined __LONG_LONG_MAX__ && !defined __STRICT_ANSI__
# ifndef LLONG_MAX
#  define LLONG_MAX __LONG_LONG_MAX__
# endif
# ifndef LLONG_MIN
#  define LLONG_MIN (-1 - LLONG_MAX)
# endif
# ifndef ULLONG_MAX
#  define ULLONG_MAX (LLONG_MAX * 2ull + 1)
# endif
#endif

#ifndef INT_FAST64_MAX
# if 1 <= LONG_MAX >> 31 >> 31
typedef long int_fast64_t;
#  define INT_FAST64_MIN LONG_MIN
#  define INT_FAST64_MAX LONG_MAX
# else
/* If this fails, compile with -DHAVE_STDINT_H or with a better compiler.  */
typedef long long int_fast64_t;
#  define INT_FAST64_MIN LLONG_MIN
#  define INT_FAST64_MAX LLONG_MAX
# endif
#endif

#ifndef PRIdFAST64
# if INT_FAST64_MAX == LONG_MAX
#  define PRIdFAST64 "ld"
# else
#  define PRIdFAST64 "lld"
# endif
#endif

#ifndef SCNdFAST64
# define SCNdFAST64 PRIdFAST64
#endif

#ifndef INT_FAST32_MAX
# if INT_MAX >> 31 == 0
typedef long int_fast32_t;
#  define INT_FAST32_MAX LONG_MAX
#  define INT_FAST32_MIN LONG_MIN
# else
typedef int int_fast32_t;
#  define INT_FAST32_MAX INT_MAX
#  define INT_FAST32_MIN INT_MIN
# endif
#endif

#ifndef INTMAX_MAX
# ifdef LLONG_MAX
typedef long long intmax_t;
#  ifndef HAVE_STRTOLL
#   define HAVE_STRTOLL true
#  endif
#  if HAVE_STRTOLL
#   define strtoimax strtoll
#  endif
#  define INTMAX_MAX LLONG_MAX
#  define INTMAX_MIN LLONG_MIN
# else
typedef long intmax_t;
#  define INTMAX_MAX LONG_MAX
#  define INTMAX_MIN LONG_MIN
# endif
# ifndef strtoimax
#  define strtoimax strtol
# endif
#endif

#ifndef PRIdMAX
# if INTMAX_MAX == LLONG_MAX
#  define PRIdMAX "lld"
# else
#  define PRIdMAX "ld"
# endif
#endif

#ifndef PTRDIFF_MAX
# define PTRDIFF_MAX MAXVAL(ptrdiff_t, TYPE_BIT(ptrdiff_t))
#endif

#ifndef UINT_FAST32_MAX
typedef unsigned long uint_fast32_t;
#endif

#ifndef UINT_FAST64_MAX
# if 3 <= ULONG_MAX >> 31 >> 31
typedef unsigned long uint_fast64_t;
#  define UINT_FAST64_MAX ULONG_MAX
# else
/* If this fails, compile with -DHAVE_STDINT_H or with a better compiler.  */
typedef unsigned long long uint_fast64_t;
#  define UINT_FAST64_MAX ULLONG_MAX
# endif
#endif

#ifndef UINTMAX_MAX
# ifdef ULLONG_MAX
typedef unsigned long long uintmax_t;
#  define UINTMAX_MAX ULLONG_MAX
# else
typedef unsigned long uintmax_t;
#  define UINTMAX_MAX ULONG_MAX
# endif
#endif

#ifndef PRIuMAX
# ifdef ULLONG_MAX
#  define PRIuMAX "llu"
# else
#  define PRIuMAX "lu"
# endif
#endif

#ifndef SIZE_MAX
# define SIZE_MAX ((size_t) -1)
#endif

#endif /* PORT_TO_C89 */

/* The maximum size of any created object, as a signed integer.
   Although the C standard does not outright prohibit larger objects,
   behavior is undefined if the result of pointer subtraction does not
   fit into ptrdiff_t, and the code assumes in several places that
   pointer subtraction works.  As a practical matter it's OK to not
   support objects larger than this.  */
#define INDEX_MAX ((ptrdiff_t) min(PTRDIFF_MAX, SIZE_MAX))

/* Support ckd_add, ckd_sub, ckd_mul on C23 or recent-enough GCC-like
   hosts, unless compiled with -DHAVE_STDCKDINT_H=0 or with pre-C23 EDG.  */
#if !defined HAVE_STDCKDINT_H && defined __has_include
# if __has_include(<stdckdint.h>)
#  define HAVE_STDCKDINT_H true
# endif
#endif
#ifdef HAVE_STDCKDINT_H
# if HAVE_STDCKDINT_H
#  include <stdckdint.h>
# endif
#elif defined __EDG__
/* Do nothing, to work around EDG bug <https://bugs.gnu.org/53256>.  */
#elif defined __has_builtin
# if __has_builtin(__builtin_add_overflow)
#  define ckd_add(r, a, b) __builtin_add_overflow(a, b, r)
# endif
# if __has_builtin(__builtin_sub_overflow)
#  define ckd_sub(r, a, b) __builtin_sub_overflow(a, b, r)
# endif
# if __has_builtin(__builtin_mul_overflow)
#  define ckd_mul(r, a, b) __builtin_mul_overflow(a, b, r)
# endif
#elif 7 <= __GNUC__
# define ckd_add(r, a, b) __builtin_add_overflow(a, b, r)
# define ckd_sub(r, a, b) __builtin_sub_overflow(a, b, r)
# define ckd_mul(r, a, b) __builtin_mul_overflow(a, b, r)
#endif

#if 3 <= __GNUC__
# define ATTRIBUTE_MALLOC __attribute__((malloc))
# define ATTRIBUTE_FORMAT(spec) __attribute__((format spec))
#else
# define ATTRIBUTE_MALLOC /* empty */
# define ATTRIBUTE_FORMAT(spec) /* empty */
#endif

#if (defined __has_c_attribute \
     && (202311 <= __STDC_VERSION__ || !defined __STRICT_ANSI__))
# define HAVE___HAS_C_ATTRIBUTE true
#else
# define HAVE___HAS_C_ATTRIBUTE false
#endif

#if HAVE___HAS_C_ATTRIBUTE
# if __has_c_attribute(deprecated)
#  define ATTRIBUTE_DEPRECATED [[deprecated]]
# endif
#endif
#ifndef ATTRIBUTE_DEPRECATED
# if 3 < __GNUC__ + (2 <= __GNUC_MINOR__)
#  define ATTRIBUTE_DEPRECATED __attribute__((deprecated))
# else
#  define ATTRIBUTE_DEPRECATED /* empty */
# endif
#endif

#if HAVE___HAS_C_ATTRIBUTE
# if __has_c_attribute(fallthrough)
#  define ATTRIBUTE_FALLTHROUGH [[fallthrough]]
# endif
#endif
#ifndef ATTRIBUTE_FALLTHROUGH
# if 7 <= __GNUC__
#  define ATTRIBUTE_FALLTHROUGH __attribute__((fallthrough))
# else
#  define ATTRIBUTE_FALLTHROUGH ((void) 0)
# endif
#endif

#if HAVE___HAS_C_ATTRIBUTE
# if __has_c_attribute(maybe_unused)
#  define ATTRIBUTE_MAYBE_UNUSED [[maybe_unused]]
# endif
#endif
#ifndef ATTRIBUTE_MAYBE_UNUSED
# if 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define ATTRIBUTE_MAYBE_UNUSED __attribute__((unused))
# else
#  define ATTRIBUTE_MAYBE_UNUSED /* empty */
# endif
#endif

#if HAVE___HAS_C_ATTRIBUTE
# if __has_c_attribute(noreturn)
#  define ATTRIBUTE_NORETURN [[noreturn]]
# endif
#endif
#ifndef ATTRIBUTE_NORETURN
# if 201112 <= __STDC_VERSION__
#  define ATTRIBUTE_NORETURN _Noreturn
# elif 2 < __GNUC__ + (8 <= __GNUC_MINOR__)
#  define ATTRIBUTE_NORETURN __attribute__((noreturn))
# else
#  define ATTRIBUTE_NORETURN /* empty */
# endif
#endif

#if HAVE___HAS_C_ATTRIBUTE
# if __has_c_attribute(reproducible)
#  define ATTRIBUTE_REPRODUCIBLE [[reproducible]]
# endif
#endif
#ifndef ATTRIBUTE_REPRODUCIBLE
# if 3 <= __GNUC__
#  define ATTRIBUTE_REPRODUCIBLE __attribute__((pure))
# else
#  define ATTRIBUTE_REPRODUCIBLE /* empty */
# endif
#endif

#if HAVE___HAS_C_ATTRIBUTE
# if __has_c_attribute(unsequenced)
#  define ATTRIBUTE_UNSEQUENCED [[unsequenced]]
# endif
#endif
#ifndef ATTRIBUTE_UNSEQUENCED
# if 3 <= __GNUC__
#  define ATTRIBUTE_UNSEQUENCED __attribute__((const))
# else
#  define ATTRIBUTE_UNSEQUENCED /* empty */
# endif
#endif

#if (__STDC_VERSION__ < 199901 && !defined restrict \
     && (PORT_TO_C89 || defined _MSC_VER))
# define restrict /* empty */
#endif

/*
** Workarounds for compilers/systems.
*/

#ifndef EPOCH_LOCAL
# define EPOCH_LOCAL 0
#endif
#ifndef EPOCH_OFFSET
# define EPOCH_OFFSET 0
#endif
#ifndef RESERVE_STD_EXT_IDS
# define RESERVE_STD_EXT_IDS 0
#endif

/* If standard C identifiers with external linkage (e.g., localtime)
   are reserved and are not already being renamed anyway, rename them
   as if compiling with '-Dtime_tz=time_t'.  */
#if !defined time_tz && RESERVE_STD_EXT_IDS && USE_LTZ
# define time_tz time_t
#endif

/*
** Compile with -Dtime_tz=T to build the tz package with a private
** time_t type equivalent to T rather than the system-supplied time_t.
** This debugging feature can test unusual design decisions
** (e.g., time_t wider than 'long', or unsigned time_t) even on
** typical platforms.
*/
#if defined time_tz || EPOCH_LOCAL || EPOCH_OFFSET != 0
# define TZ_TIME_T 1
#else
# define TZ_TIME_T 0
#endif

#if defined LOCALTIME_IMPLEMENTATION && TZ_TIME_T
static time_t sys_time(time_t *x) { return time(x); }
#endif

#if TZ_TIME_T

typedef time_tz tz_time_t;

# undef  asctime
# define asctime tz_asctime
# undef  asctime_r
# define asctime_r tz_asctime_r
# undef  ctime
# define ctime tz_ctime
# undef  ctime_r
# define ctime_r tz_ctime_r
# undef  difftime
# define difftime tz_difftime
# undef  gmtime
# define gmtime tz_gmtime
# undef  gmtime_r
# define gmtime_r tz_gmtime_r
# undef  localtime
# define localtime tz_localtime
# undef  localtime_r
# define localtime_r tz_localtime_r
# undef  localtime_rz
# define localtime_rz tz_localtime_rz
# undef  mktime
# define mktime tz_mktime
# undef  mktime_z
# define mktime_z tz_mktime_z
# undef  offtime
# define offtime tz_offtime
# undef  posix2time
# define posix2time tz_posix2time
# undef  posix2time_z
# define posix2time_z tz_posix2time_z
# undef  strftime
# define strftime tz_strftime
# undef  time
# define time tz_time
# undef  time2posix
# define time2posix tz_time2posix
# undef  time2posix_z
# define time2posix_z tz_time2posix_z
# undef  time_t
# define time_t tz_time_t
# undef  timegm
# define timegm tz_timegm
# undef  timelocal
# define timelocal tz_timelocal
# undef  timeoff
# define timeoff tz_timeoff
# undef  tzalloc
# define tzalloc tz_tzalloc
# undef  tzfree
# define tzfree tz_tzfree
# undef  tzset
# define tzset tz_tzset
# if HAVE_STRFTIME_L
#  undef  strftime_l
#  define strftime_l tz_strftime_l
# endif
# if HAVE_TZNAME
#  undef  tzname
#  define tzname tz_tzname
# endif
# if USG_COMPAT
#  undef  daylight
#  define daylight tz_daylight
#  undef  timezone
#  define timezone tz_timezone
# endif
# if ALTZONE
#  undef  altzone
#  define altzone tz_altzone
# endif

# if __STDC_VERSION__ < 202311
#  define DEPRECATED_IN_C23 /* empty */
# else
#  define DEPRECATED_IN_C23 ATTRIBUTE_DEPRECATED
# endif
DEPRECATED_IN_C23 char *asctime(struct tm const *);
char *asctime_r(struct tm const *restrict, char *restrict);
DEPRECATED_IN_C23 char *ctime(time_t const *);
char *ctime_r(time_t const *, char *);
ATTRIBUTE_UNSEQUENCED double difftime(time_t, time_t);
size_t strftime(char *restrict, size_t, char const *restrict,
		struct tm const *restrict);
# if HAVE_STRFTIME_L
size_t strftime_l(char *restrict, size_t, char const *restrict,
		  struct tm const *restrict, locale_t);
# endif
struct tm *gmtime(time_t const *);
struct tm *gmtime_r(time_t const *restrict, struct tm *restrict);
struct tm *localtime(time_t const *);
struct tm *localtime_r(time_t const *restrict, struct tm *restrict);
time_t mktime(struct tm *);
time_t time(time_t *);
time_t timegm(struct tm *);
void tzset(void);
#endif

#ifndef HAVE_DECL_TIMEGM
# if (202311 <= __STDC_VERSION__ \
      || defined __GLIBC__ || defined __tm_zone /* musl */ \
      || defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ \
      || (defined __APPLE__ && defined __MACH__))
#  define HAVE_DECL_TIMEGM true
# else
#  define HAVE_DECL_TIMEGM false
# endif
#endif
#if !HAVE_DECL_TIMEGM && !defined timegm
time_t timegm(struct tm *);
#endif

#if !HAVE_DECL_ASCTIME_R && !defined asctime_r
extern char *asctime_r(struct tm const *restrict, char *restrict);
#endif

#ifndef HAVE_DECL_ENVIRON
# if defined environ || defined __USE_GNU
#  define HAVE_DECL_ENVIRON 1
# else
#  define HAVE_DECL_ENVIRON 0
# endif
#endif

#if !HAVE_DECL_ENVIRON
extern char **environ;
#endif

#if 2 <= HAVE_TZNAME + (TZ_TIME_T || !HAVE_POSIX_DECLS)
extern char *tzname[];
#endif
#if 2 <= USG_COMPAT + (TZ_TIME_T || !HAVE_POSIX_DECLS)
extern long timezone;
extern int daylight;
#endif
#if 2 <= ALTZONE + (TZ_TIME_T || !HAVE_POSIX_DECLS)
extern long altzone;
#endif

/*
** The STD_INSPIRED functions are similar, but most also need
** declarations if time_tz is defined.
*/

#ifndef STD_INSPIRED
# define STD_INSPIRED 0
#endif
#if STD_INSPIRED
# if TZ_TIME_T || !defined offtime
struct tm *offtime(time_t const *, long);
# endif
# if TZ_TIME_T || !defined timelocal
time_t timelocal(struct tm *);
# endif
# if TZ_TIME_T || !defined timeoff
time_t timeoff(struct tm *, long);
# endif
# if TZ_TIME_T || !defined time2posix
time_t time2posix(time_t);
# endif
# if TZ_TIME_T || !defined posix2time
time_t posix2time(time_t);
# endif
#endif

/* Infer TM_ZONE on systems where this information is known, but suppress
   guessing if NO_TM_ZONE is defined.  Similarly for TM_GMTOFF.  */
#if (defined __GLIBC__ \
     || defined __tm_zone /* musl */ \
     || defined __FreeBSD__ || defined __NetBSD__ || defined __OpenBSD__ \
     || (defined __APPLE__ && defined __MACH__))
# if !defined TM_GMTOFF && !defined NO_TM_GMTOFF
#  define TM_GMTOFF tm_gmtoff
# endif
# if !defined TM_ZONE && !defined NO_TM_ZONE
#  define TM_ZONE tm_zone
# endif
#endif

/*
** Define functions that are ABI compatible with NetBSD but have
** better prototypes.  NetBSD 6.1.4 defines a pointer type timezone_t
** and labors under the misconception that 'const timezone_t' is a
** pointer to a constant.  This use of 'const' is ineffective, so it
** is not done here.  What we call 'struct state' NetBSD calls
** 'struct __state', but this is a private name so it doesn't matter.
*/
#if NETBSD_INSPIRED
typedef struct state *timezone_t;
struct tm *localtime_rz(timezone_t restrict, time_t const *restrict,
			struct tm *restrict);
time_t mktime_z(timezone_t restrict, struct tm *restrict);
timezone_t tzalloc(char const *);
void tzfree(timezone_t);
# if STD_INSPIRED
#  if TZ_TIME_T || !defined posix2time_z
ATTRIBUTE_REPRODUCIBLE time_t posix2time_z(timezone_t, time_t);
#  endif
#  if TZ_TIME_T || !defined time2posix_z
ATTRIBUTE_REPRODUCIBLE time_t time2posix_z(timezone_t, time_t);
#  endif
# endif
#endif

/*
** Finally, some convenience items.
*/

#define TYPE_BIT(type) (CHAR_BIT * (ptrdiff_t) sizeof(type))
#define TYPE_SIGNED(type) (((type) -1) < 0)
#define TWOS_COMPLEMENT(t) ((t) ~ (t) 0 < 0)

/* Minimum and maximum of two values.  Use lower case to avoid
   naming clashes with standard include files.  */
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

/* Max and min values of the integer type T, of which only the bottom
   B bits are used, and where the highest-order used bit is considered
   to be a sign bit if T is signed.  */
#define MAXVAL(t, b)						\
  ((t) (((t) 1 << ((b) - 1 - TYPE_SIGNED(t)))			\
	- 1 + ((t) 1 << ((b) - 1 - TYPE_SIGNED(t)))))
#define MINVAL(t, b)						\
  ((t) (TYPE_SIGNED(t) ? - TWOS_COMPLEMENT(t) - MAXVAL(t, b) : 0))

/* The extreme time values, assuming no padding.  */
#define TIME_T_MIN_NO_PADDING MINVAL(time_t, TYPE_BIT(time_t))
#define TIME_T_MAX_NO_PADDING MAXVAL(time_t, TYPE_BIT(time_t))

/* The extreme time values.  These are macros, not constants, so that
   any portability problems occur only when compiling .c files that use
   the macros, which is safer for applications that need only zdump and zic.
   This implementation assumes no padding if time_t is signed and
   either the compiler lacks support for _Generic or time_t is not one
   of the standard signed integer types.  */
#if HAVE__GENERIC
# define TIME_T_MIN \
    _Generic((time_t) 0, \
	     signed char: SCHAR_MIN, short: SHRT_MIN, \
	     int: INT_MIN, long: LONG_MIN, long long: LLONG_MIN, \
	     default: TIME_T_MIN_NO_PADDING)
# define TIME_T_MAX \
    (TYPE_SIGNED(time_t) \
     ? _Generic((time_t) 0, \
		signed char: SCHAR_MAX, short: SHRT_MAX, \
		int: INT_MAX, long: LONG_MAX, long long: LLONG_MAX, \
		default: TIME_T_MAX_NO_PADDING)			    \
     : (time_t) -1)
enum { SIGNED_PADDING_CHECK_NEEDED
         = _Generic((time_t) 0,
		    signed char: false, short: false,
		    int: false, long: false, long long: false,
		    default: true) };
#else
# define TIME_T_MIN TIME_T_MIN_NO_PADDING
# define TIME_T_MAX TIME_T_MAX_NO_PADDING
enum { SIGNED_PADDING_CHECK_NEEDED = true };
#endif
/* Try to check the padding assumptions.  Although TIME_T_MAX and the
   following check can both have undefined behavior on oddball
   platforms due to shifts exceeding widths of signed integers, these
   platforms' compilers are likely to diagnose these issues in integer
   constant expressions, so it shouldn't hurt to check statically.  */
static_assert(! TYPE_SIGNED(time_t) || ! SIGNED_PADDING_CHECK_NEEDED
	      || TIME_T_MAX >> (TYPE_BIT(time_t) - 2) == 1);

/*
** 302 / 1000 is log10(2.0) rounded up.
** Subtract one for the sign bit if the type is signed;
** add one for integer division truncation;
** add one more for a minus sign if the type is signed.
*/
#define INT_STRLEN_MAXIMUM(type) \
	((TYPE_BIT(type) - TYPE_SIGNED(type)) * 302 / 1000 + \
	1 + TYPE_SIGNED(type))

/*
** INITIALIZE(x)
*/

#ifdef GCC_LINT
# define INITIALIZE(x)	((x) = 0)
#else
# define INITIALIZE(x)
#endif

/* Whether memory access must strictly follow the C standard.
   If 0, it's OK to read uninitialized storage so long as the value is
   not relied upon.  Defining it to 0 lets mktime access parts of
   struct tm that might be uninitialized, as a heuristic when the
   standard doesn't say what to return and when tm_gmtoff can help
   mktime likely infer a better value.  */
#ifndef UNINIT_TRAP
# define UNINIT_TRAP 0
#endif

#ifdef DEBUG
# undef unreachable
# define unreachable() abort()
#elif !defined unreachable
# ifdef __has_builtin
#  if __has_builtin(__builtin_unreachable)
#   define unreachable() __builtin_unreachable()
#  endif
# elif 4 < __GNUC__ + (5 <= __GNUC_MINOR__)
#  define unreachable() __builtin_unreachable()
# endif
# ifndef unreachable
#  define unreachable() ((void) 0)
# endif
#endif

/*
** For the benefit of GNU folk...
** '_(MSGID)' uses the current locale's message library string for MSGID.
** The default is to use gettext if available, and use MSGID otherwise.
*/

#if HAVE_GETTEXT
#define _(msgid) gettext(msgid)
#else /* !HAVE_GETTEXT */
#define _(msgid) msgid
#endif /* !HAVE_GETTEXT */

#if !defined TZ_DOMAIN && defined HAVE_GETTEXT
# define TZ_DOMAIN "tz"
#endif

#if HAVE_INCOMPATIBLE_CTIME_R
#undef asctime_r
#undef ctime_r
char *asctime_r(struct tm const *restrict, char *restrict);
char *ctime_r(time_t const *, char *);
#endif /* HAVE_INCOMPATIBLE_CTIME_R */

/* Handy macros that are independent of tzfile implementation.  */

enum {
  SECSPERMIN = 60,
  MINSPERHOUR = 60,
  SECSPERHOUR = SECSPERMIN * MINSPERHOUR,
  HOURSPERDAY = 24,
  DAYSPERWEEK = 7,
  DAYSPERNYEAR = 365,
  DAYSPERLYEAR = DAYSPERNYEAR + 1,
  MONSPERYEAR = 12,
  YEARSPERREPEAT = 400	/* years before a Gregorian repeat */
};

#define SECSPERDAY	((int_fast32_t) SECSPERHOUR * HOURSPERDAY)

#define DAYSPERREPEAT		((int_fast32_t) 400 * 365 + 100 - 4 + 1)
#define SECSPERREPEAT		((int_fast64_t) DAYSPERREPEAT * SECSPERDAY)
#define AVGSECSPERYEAR		(SECSPERREPEAT / YEARSPERREPEAT)

enum {
  TM_SUNDAY,
  TM_MONDAY,
  TM_TUESDAY,
  TM_WEDNESDAY,
  TM_THURSDAY,
  TM_FRIDAY,
  TM_SATURDAY
};

enum {
  TM_JANUARY,
  TM_FEBRUARY,
  TM_MARCH,
  TM_APRIL,
  TM_MAY,
  TM_JUNE,
  TM_JULY,
  TM_AUGUST,
  TM_SEPTEMBER,
  TM_OCTOBER,
  TM_NOVEMBER,
  TM_DECEMBER
};

enum {
  TM_YEAR_BASE = 1900,
  TM_WDAY_BASE = TM_MONDAY,
  EPOCH_YEAR = 1970,
  EPOCH_WDAY = TM_THURSDAY
};

#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

/*
** Since everything in isleap is modulo 400 (or a factor of 400), we know that
**	isleap(y) == isleap(y % 400)
** and so
**	isleap(a + b) == isleap((a + b) % 400)
** or
**	isleap(a + b) == isleap(a % 400 + b % 400)
** This is true even if % means modulo rather than Fortran remainder
** (which is allowed by C89 but not by C99 or later).
** We use this to avoid addition overflow problems.
*/

#define isleap_sum(a, b)	isleap((a) % 400 + (b) % 400)

#endif /* !defined PRIVATE_H */

"""

```