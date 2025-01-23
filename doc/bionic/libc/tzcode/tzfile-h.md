Response:
Let's break down the thought process for analyzing the `tzfile.h` file and generating the comprehensive answer.

**1. Understanding the Request:**

The core request is to analyze the `tzfile.h` header file, which is part of Android's Bionic library, specifically dealing with timezone information. The analysis needs to cover its functionality, relationship to Android, implementation details of related libc functions, dynamic linker aspects, usage errors, and how Android frameworks interact with it, including a Frida hook example.

**2. Initial Analysis of the Header File:**

The first step is to read through the header file and identify its key components:

* **Purpose Statement:** The initial comments clearly state its purpose: defining the layout and location of TZif (Time Zone Information Format) files. It's for use *only* with time conversion code and shouldn't be copied to system include directories. This immediately highlights its role as an internal detail for Bionic's time handling.
* **Directory Definitions:**  `TZDIR`, `TZDEFAULT`, and `TZDEFRULES` define the default locations for timezone files, the local timezone file, and default rules, respectively. This gives us context about where these files reside within the Android system.
* **`tzhead` Structure:**  This structure is central. It defines the header format of the TZif files. The member names provide clues about the information stored: magic number, version, counts of transitions, types, leap seconds, and abbreviation characters.
* **TZif File Layout:** The comments after the `tzhead` structure detail the subsequent data layout within the TZif file. This includes transition times, local time type information, abbreviations, leap second data, and optional POSIX TZ string.
* **Version Handling:**  The comments about `tzh_version` '2' and '3' indicate the evolution of the TZif format, introducing 8-byte transition times and extended POSIX TZ string capabilities.
* **Limits:** `TZ_MAX_TIMES`, `TZ_MAX_TYPES`, `TZ_MAX_CHARS`, and `TZ_MAX_LEAPS` define internal limitations for processing TZif files, likely for performance and memory management.
* **Time-Related Constants:**  Constants like `SECSPERMIN`, `MINSPERHOUR`, `DAYSPERWEEK`, `EPOCH_YEAR`, etc., are standard time calculations and definitions. These are fundamental for any time-related functionality.
* **`isleap` Macro:** This macro determines if a year is a leap year.

**3. Identifying Key Functionality:**

Based on the header file's content, the primary functionality is:

* **Defining the structure of timezone data files (TZif).**
* **Providing default paths for timezone-related files.**
* **Setting limits for processing timezone data.**
* **Defining fundamental time-related constants.**

**4. Connecting to Android Functionality:**

The core connection is time zone handling. This is crucial for any operating system and particularly relevant for a mobile platform used globally. Examples of Android features that rely on this include:

* **Displaying the correct time:** The system clock relies on timezone information.
* **Scheduling events:** Alarms and scheduled tasks need to account for time zones.
* **Date and time formatting:** Displaying dates and times correctly in different locales requires timezone awareness.
* **Network time synchronization:**  Synchronizing time over the network needs to consider time zones.

**5. Explaining Libc Functions (Conceptual):**

The header file itself *doesn't implement* libc functions. It *describes the data format* that libc functions like `localtime`, `gmtime`, `mktime`, and `strptime` use. The explanation focuses on how these functions would utilize the data described in the header:

* **`localtime`:** Reads TZif files to convert UTC time to local time.
* **`gmtime`:** The inverse of `localtime`, converting local time to UTC (though it doesn't directly use TZif files as input).
* **`mktime`:**  Converts a broken-down time structure to a `time_t`, needing timezone information for calculations involving daylight saving time.
* **`strptime`:** Parses a time string, potentially needing timezone information to interpret timezone abbreviations.

**6. Dynamic Linker Aspects:**

The header file doesn't directly involve the dynamic linker. However, the *usage* of the functions that *use* this header (like `localtime`) does. The dynamic linker loads the libc (bionic) which contains the implementation of these time functions.

* **SO Layout:** The example SO layout shows a typical structure with sections for code (`.text`), read-only data (`.rodata`), and read-write data (`.data`). The key is that the `localtime` implementation resides within `libc.so`.
* **Linking Process:** When an application calls `localtime`, the dynamic linker resolves the symbol to the implementation within `libc.so`.

**7. Logical Reasoning (Hypothetical Input/Output):**

This section provides concrete examples of how the data in the header would be used. The example focuses on a transition time within a TZif file and how `localtime` would use that information to determine the correct local time and DST status.

**8. Common Usage Errors:**

This section covers potential mistakes developers might make when dealing with time zones, such as assuming a fixed offset, ignoring DST, or mishandling time zone abbreviations.

**9. Android Framework/NDK Interaction and Frida Hook:**

This explains the path from the Android Framework down to the libc functions that use the `tzfile.h` data.

* **Framework Level:**  Classes like `java.util.TimeZone` provide high-level timezone handling.
* **System Services:**  `TimeManagerService` is a key system component.
* **JNI Bridge:**  Native calls go through JNI.
* **NDK:** NDK allows direct use of C/C++ standard library functions.
* **libc (Bionic):**  Finally, the calls reach the libc implementations that utilize the TZif file format.

The Frida hook example demonstrates how to intercept the `__tzset_unlocked` function (which is related to setting the timezone) to observe the timezone being set.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Focus heavily on the `tzhead` structure.
* **Correction:** Realize the importance of the *entire* TZif file layout and how the `tzhead` provides metadata for the subsequent data.
* **Initial thought:** Directly link the header file to dynamic linking.
* **Correction:** Understand that the header *describes data*, while dynamic linking is involved in loading the *code* that uses that data. The connection is indirect, via the libc functions.
* **Initial thought:** Provide a low-level, bit-by-bit explanation of how `localtime` works.
* **Correction:**  Focus on the *conceptual* use of the TZif data by `localtime` and other related functions, as the actual implementation is complex and not directly revealed by the header.
* **Initial thought:** Only provide a code snippet for the Frida hook.
* **Correction:** Explain *why* that particular function is targeted and what the hook achieves in the context of timezone setting.

By following this detailed analysis and refinement process, the comprehensive and accurate answer is generated. The key is to not just describe the header file in isolation but to connect it to the broader Android ecosystem and how it's used in practice.

好的，我们来详细分析一下 `bionic/libc/tzcode/tzfile.handroid` 这个头文件。

**文件功能概述**

`tzfile.h` 文件定义了用于存储时区信息的 TZif (Time Zone Information Format) 文件的布局和格式。它并不包含任何可执行代码，而是一个数据结构的定义，以及一些相关的宏定义和常量。

**主要功能点：**

1. **定义 TZif 文件结构:**  `tzfile.h` 中最核心的部分是 `struct tzhead`，它定义了 TZif 文件的头部结构。这个头部包含了关于时区数据的重要元信息，例如版本号、过渡时间数量、时区类型数量等。

2. **指定 TZif 文件路径:**  头文件中定义了几个宏，用于指定默认的 TZif 文件路径：
   - `TZDIR`:  时区对象文件目录，默认为 `/usr/share/zoneinfo`。Android 系统通常会将时区数据文件放在这个目录下。
   - `TZDEFAULT`:  本地时区文件的路径，默认为 `/etc/localtime`。这个文件通常是一个指向具体时区文件的符号链接。
   - `TZDEFRULES`:  默认时区规则文件名，默认为 `posixrules`。

3. **定义 TZif 数据格式:**  除了头部结构，头文件中的注释详细描述了 TZif 文件中后续数据的布局，包括过渡时间、本地时间类型、时区缩写、闰秒信息等。

4. **定义限制:**  头文件定义了一些宏，例如 `TZ_MAX_TIMES`，`TZ_MAX_TYPES` 等，用于限制可以处理的最大过渡时间、时区类型等数量。这可能是为了防止解析过大的时区文件，或者出于性能考虑。

5. **定义时间相关的常量:**  头文件中还定义了一些常用的时间相关的常量，例如 `SECSPERMIN` (每分钟秒数)、`MINSPERHOUR` (每小时分钟数) 等，以及一些用于 `tm` 结构体的常量，例如 `TM_SUNDAY`，`TM_JANUARY` 等。

**与 Android 功能的关系及举例说明**

`tzfile.h` 文件直接关系到 Android 系统的时间和日期处理功能。Android 系统需要根据用户的地理位置和设置来显示正确的本地时间，并处理夏令时等时区变化。

**举例说明：**

* **系统时钟显示:** 当 Android 设备显示当前时间时，它需要知道当前设置的时区。系统会读取 `TZDEFAULT` 指向的本地时区文件（通常在 `/data/misc/zoneinfo/` 下），该文件是一个 TZif 格式的文件。`tzfile.h` 中定义的结构体和数据格式就用于解析这个文件，从而获取正确的时区偏移和夏令时规则，最终显示正确的本地时间。
* **闹钟和定时任务:** Android 的闹钟和定时任务功能也需要考虑时区。当用户设置一个特定时间的闹钟时，系统会将其转换为 UTC 时间存储，并在触发时根据当前时区再转换回本地时间。这个转换过程就依赖于对 TZif 文件的解析。
* **Java `java.util.TimeZone` 类:**  Android 的 Java 框架中的 `java.util.TimeZone` 类提供了时区处理的功能。它的底层实现会调用 Native 代码，最终读取和解析 TZif 文件来获取时区信息。

**libc 函数的实现细节**

`tzfile.h` 文件本身并不实现任何 libc 函数。它只是定义了数据结构。真正使用这些定义的 libc 函数是与时间相关的函数，例如：

* **`localtime()`:**  此函数将 `time_t` (自 Epoch 以来的秒数，通常指 UTC 时间) 转换为本地时间的 `struct tm` 结构体。其实现会读取并解析 TZif 文件，根据 TZif 文件中定义的过渡时间 (transition times) 和时区类型 (local time types) 来确定指定时间点对应的本地时间偏移和夏令时状态。
    * **实现步骤 (简化)：**
        1. 确定要转换的时间点。
        2. 读取 `TZ` 环境变量或默认的本地时区文件 (`/etc/localtime`)，获取 TZif 文件路径。
        3. 打开并读取 TZif 文件，解析 `tzhead` 结构体。
        4. 根据 `tzhead` 中的信息，读取过渡时间数组。
        5. 在过渡时间数组中查找最接近且早于目标时间的过渡点。
        6. 根据该过渡点对应的时区类型信息 (UTC 偏移、是否夏令时、时区缩写索引)，计算出本地时间。

* **`gmtime()`:** 此函数将 `time_t` 转换为 UTC 时间的 `struct tm` 结构体。它不直接依赖 TZif 文件，因为它处理的是 UTC 时间，没有时区概念。

* **`mktime()`:** 此函数将本地时间的 `struct tm` 结构体转换为 `time_t`。它的实现需要考虑时区信息，特别是夏令时。它可能会尝试匹配 `struct tm` 中的信息到 TZif 文件中的某个时间点，以确定正确的 UTC 时间。

* **`strptime()`:** 此函数将一个时间字符串解析为 `struct tm` 结构体。如果时间字符串中包含时区信息 (例如时区缩写)，则 `strptime()` 的实现会查找 TZif 文件中的时区缩写，以正确解析时间。

**dynamic linker 的功能及 SO 布局样本和链接处理过程**

`tzfile.h` 文件本身不涉及 dynamic linker 的功能。但是，使用了 `tzfile.h` 中定义的结构体的 libc 函数 (例如 `localtime`) 是在动态链接库 `libc.so` 中实现的。

**SO 布局样本 (`libc.so`)：**

```
libc.so:
    .interp         // 指向动态链接器的路径
    .note.android.ident
    .dynsym         // 动态符号表
    .dynstr         // 动态字符串表
    .hash           // 符号哈希表
    .gnu.version    // GNU 版本信息
    .gnu.version_r  // GNU 版本需求
    .rel.dyn        // 重定位表 (动态)
    .rel.plt        // 重定位表 (PLT)
    .plt            // 过程链接表 (Procedure Linkage Table)
    .text           // 代码段 (包含 localtime 等函数的机器码)
    .rodata         // 只读数据段 (可能包含 TZif 文件的默认路径字符串等)
    .data           // 可读写数据段
    .bss            // 未初始化数据段
    ...
```

**链接处理过程：**

1. **编译时：** 当应用程序调用 `localtime()` 函数时，编译器在编译阶段并不知道 `localtime()` 函数的具体地址。它会在生成的目标文件中记录一个对 `localtime` 符号的未解析引用。
2. **链接时：**  链接器 (通常是 `ld`) 将应用程序的目标文件与所需的共享库 (`libc.so`) 链接在一起。链接器会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `localtime` 符号的定义。
3. **运行时：** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载应用程序依赖的共享库，包括 `libc.so`。
4. **符号解析：** 动态链接器会解析应用程序中对 `localtime` 符号的引用，将其指向 `libc.so` 中 `localtime` 函数的实际内存地址。这个过程称为动态链接。
5. **调用执行：** 当应用程序执行到调用 `localtime()` 的代码时，程序会跳转到 `libc.so` 中 `localtime` 函数的内存地址执行。

**逻辑推理 (假设输入与输出)**

假设有一个 TZif 文件，其中定义了如下一个过渡：

* **过渡时间:**  Unix 时间戳 `1677648000` (对应 2023 年 3 月 1 日 00:00:00 UTC)
* **过渡类型:**  UTC 偏移为 +8 小时，不启用夏令时，时区缩写索引指向 "CST"。

**假设输入：**

* `localtime(1677648000)`  // 将 UTC 时间 2023-03-01 00:00:00 转换为本地时间

**输出：**

`localtime()` 函数会读取 TZif 文件，找到上述过渡点，并根据其对应的时区类型信息进行转换。输出的 `struct tm` 结构体可能包含以下信息：

```
tm_sec: 0
tm_min: 0
tm_hour: 8       // UTC + 8 小时
tm_mday: 1
tm_mon: 2        // 0 表示 1 月
tm_year: 123     // 从 1900 年开始的年数
tm_wday: 3       // 星期几 (0-6, 0 表示周日)
tm_yday: 59      // 一年中的第几天 (0-365)
tm_isdst: 0      // 不启用夏令时
```

**常见的使用错误**

1. **假设固定的时区偏移:**  开发者可能会错误地假设一个地区始终具有相同的 UTC 偏移，而忽略了夏令时的存在。例如，认为北京的 UTC 偏移一直是 +8 小时。
2. **硬编码时区信息:**  在代码中硬编码时区名称或偏移量是不可取的，因为时区规则可能会发生变化。应该依赖系统提供的时区数据。
3. **混淆本地时间和 UTC 时间:**  在处理时间时，没有明确区分本地时间和 UTC 时间会导致错误的时区转换。
4. **不处理 `TZ` 环境变量:**  用户可以通过设置 `TZ` 环境变量来覆盖系统默认的时区设置。开发者应该考虑到这种情况。
5. **在不同时区之间传递时间戳时缺乏转换:**  如果需要在不同时区的系统之间传递时间信息，应该使用 UTC 时间戳，并在接收端根据目标时区进行转换。

**Android Framework 或 NDK 如何到达这里**

Android Framework 和 NDK 中与时间相关的操作最终会调用到 Bionic libc 中提供的函数，从而间接地使用到 `tzfile.h` 中定义的信息。

**步骤说明：**

1. **Android Framework (Java 层):**
   - 应用程序使用 `java.util.TimeZone` 类来获取和设置时区信息。
   - 例如，`TimeZone.getDefault()` 获取默认时区，`TimeZone.getTimeZone(String id)` 根据 ID 获取时区。
   - 这些 Java 类的方法最终会调用到 Native 代码。

2. **System Server (Java 层):**
   - `android.app.AlarmManager` 和 `android.app.job.JobScheduler` 等服务在处理定时任务时需要考虑时区。
   - `android.content.Intent` 的时间相关字段也可能涉及到时区。

3. **JNI (Java Native Interface):**
   - Java 层的 `java.util.TimeZone` 类的方法会通过 JNI 调用到 Native 层对应的实现。
   - 例如，`TimeZone.getTimeZone()` 可能会调用到 `TimeZone_getIosID()` 或类似的 Native 函数。

4. **NDK (Native Development Kit):**
   - 使用 NDK 开发的应用程序可以直接调用 Bionic libc 中提供的标准 C 函数，例如 `localtime()`, `gmtime()`, `mktime()`, `tzset()` 等。
   - 这些函数会直接读取和解析 TZif 文件。

5. **Bionic libc (`libc.so`):**
   - `localtime()`, `tzset()` 等函数的实现会读取 `TZ` 环境变量或默认的本地时区文件路径 (`/etc/localtime`)。
   - 打开并解析 TZif 文件，根据 `tzfile.h` 中定义的结构体和数据格式来获取时区信息。

**Frida Hook 示例调试步骤**

我们可以使用 Frida hook `tzset()` 函数来观察 Android 系统如何加载和设置时区信息。`tzset()` 函数是 libc 中用于设置时区信息的函数，它会读取 `TZ` 环境变量或默认的时区文件。

**Frida Hook 示例：**

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: The process '{package_name}' was not found. Make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "tzset"), {
    onEnter: function (args) {
        console.log("[*] tzset() called");
        var tz_env = Process.getEnv()["TZ"];
        if (tz_env) {
            console.log("[*] TZ environment variable: " + tz_env);
        } else {
            console.log("[*] TZ environment variable is not set.");
            // You could try to read the content of /etc/localtime here if needed
        }
    },
    onLeave: function (retval) {
        console.log("[*] tzset() returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤：**

1. **准备环境:** 确保你的 Android 设备已连接并通过 USB 调试，并且安装了 Frida。
2. **替换包名:** 将 `package_name` 变量替换为你想要调试的应用程序的包名。如果你想监控整个系统，可以尝试 hook 系统进程，但这可能更复杂。
3. **运行 Frida 脚本:** 运行上述 Python 脚本。
4. **触发时区设置:** 在你的 Android 设备上，尝试修改系统时区设置，或者运行一个会用到时区信息的应用程序。
5. **查看 Frida 输出:** Frida 会拦截对 `tzset()` 函数的调用，并在控制台输出相关信息，例如 `TZ` 环境变量的值。

**更深入的 Hook：**

你还可以 hook 与读取 TZif 文件相关的函数，例如 `open()` 或 `__openat()`，并检查打开的文件路径是否是 `/etc/localtime` 或 `/usr/share/zoneinfo` 下的文件。 还可以 hook `localtime()` 函数，查看其参数和返回值，以及在 `localtime()` 内部读取 TZif 数据的过程。

希望以上详细的分析能够帮助你理解 `bionic/libc/tzcode/tzfile.handroid` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/tzcode/tzfile.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/* Layout and location of TZif files.  */

#ifndef TZFILE_H

#define TZFILE_H

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

/*
** Information about time zone files.
*/

#ifndef TZDIR
# define TZDIR "/usr/share/zoneinfo" /* Time zone object file directory */
#endif /* !defined TZDIR */

#ifndef TZDEFAULT
# define TZDEFAULT "/etc/localtime"
#endif /* !defined TZDEFAULT */

#ifndef TZDEFRULES
# define TZDEFRULES "posixrules"
#endif /* !defined TZDEFRULES */


/* See Internet RFC 8536 for more details about the following format.  */

/*
** Each file begins with. . .
*/

#define	TZ_MAGIC	"TZif"

struct tzhead {
	char	tzh_magic[4];		/* TZ_MAGIC */
	char	tzh_version[1];		/* '\0' or '2'-'4' as of 2021 */
	char	tzh_reserved[15];	/* reserved; must be zero */
	char	tzh_ttisutcnt[4];	/* coded number of trans. time flags */
	char	tzh_ttisstdcnt[4];	/* coded number of trans. time flags */
	char	tzh_leapcnt[4];		/* coded number of leap seconds */
	char	tzh_timecnt[4];		/* coded number of transition times */
	char	tzh_typecnt[4];		/* coded number of local time types */
	char	tzh_charcnt[4];		/* coded number of abbr. chars */
};

/*
** . . .followed by. . .
**
**	tzh_timecnt (char [4])s		coded transition times a la time(2)
**	tzh_timecnt (unsigned char)s	types of local time starting at above
**	tzh_typecnt repetitions of
**		one (char [4])		coded UT offset in seconds
**		one (unsigned char)	used to set tm_isdst
**		one (unsigned char)	that's an abbreviation list index
**	tzh_charcnt (char)s		'\0'-terminated zone abbreviations
**	tzh_leapcnt repetitions of
**		one (char [4])		coded leap second transition times
**		one (char [4])		total correction after above
**	tzh_ttisstdcnt (char)s		indexed by type; if 1, transition
**					time is standard time, if 0,
**					transition time is local (wall clock)
**					time; if absent, transition times are
**					assumed to be local time
**	tzh_ttisutcnt (char)s		indexed by type; if 1, transition
**					time is UT, if 0, transition time is
**					local time; if absent, transition
**					times are assumed to be local time.
**					When this is 1, the corresponding
**					std/wall indicator must also be 1.
*/

/*
** If tzh_version is '2' or greater, the above is followed by a second instance
** of tzhead and a second instance of the data in which each coded transition
** time uses 8 rather than 4 chars,
** then a POSIX-TZ-environment-variable-style string for use in handling
** instants after the last transition time stored in the file
** (with nothing between the newlines if there is no POSIX representation for
** such instants).
**
** If tz_version is '3' or greater, the above is extended as follows.
** First, the POSIX TZ string's hour offset may range from -167
** through 167 as compared to the POSIX-required 0 through 24.
** Second, its DST start time may be January 1 at 00:00 and its stop
** time December 31 at 24:00 plus the difference between DST and
** standard time, indicating DST all year.
*/

/*
** In the current implementation, "tzset()" refuses to deal with files that
** exceed any of the limits below.
*/

#ifndef TZ_MAX_TIMES
/* This must be at least 242 for Europe/London with 'zic -b fat'.  */
# define TZ_MAX_TIMES 2000
#endif /* !defined TZ_MAX_TIMES */

#ifndef TZ_MAX_TYPES
/* This must be at least 18 for Europe/Vilnius with 'zic -b fat'.  */
# define TZ_MAX_TYPES 256 /* Limited by what (unsigned char)'s can hold */
#endif /* !defined TZ_MAX_TYPES */

#ifndef TZ_MAX_CHARS
/* This must be at least 40 for America/Anchorage.  */
# define TZ_MAX_CHARS 50	/* Maximum number of abbreviation characters */
				/* (limited by what unsigned chars can hold) */
#endif /* !defined TZ_MAX_CHARS */

#ifndef TZ_MAX_LEAPS
/* This must be at least 27 for leap seconds from 1972 through mid-2023.
   There's a plan to discontinue leap seconds by 2035.  */
# define TZ_MAX_LEAPS 50	/* Maximum number of leap second corrections */
#endif /* !defined TZ_MAX_LEAPS */

#define SECSPERMIN	60
#define MINSPERHOUR	60
#define HOURSPERDAY	24
#define DAYSPERWEEK	7
#define DAYSPERNYEAR	365
#define DAYSPERLYEAR	366
#define SECSPERHOUR	(SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY	((int_fast32_t) SECSPERHOUR * HOURSPERDAY)
#define MONSPERYEAR	12

#define TM_SUNDAY	0
#define TM_MONDAY	1
#define TM_TUESDAY	2
#define TM_WEDNESDAY	3
#define TM_THURSDAY	4
#define TM_FRIDAY	5
#define TM_SATURDAY	6

#define TM_JANUARY	0
#define TM_FEBRUARY	1
#define TM_MARCH	2
#define TM_APRIL	3
#define TM_MAY		4
#define TM_JUNE		5
#define TM_JULY		6
#define TM_AUGUST	7
#define TM_SEPTEMBER	8
#define TM_OCTOBER	9
#define TM_NOVEMBER	10
#define TM_DECEMBER	11

#define TM_YEAR_BASE	1900

#define EPOCH_YEAR	1970
#define EPOCH_WDAY	TM_THURSDAY

#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

/*
** Since everything in isleap is modulo 400 (or a factor of 400), we know that
**	isleap(y) == isleap(y % 400)
** and so
**	isleap(a + b) == isleap((a + b) % 400)
** or
**	isleap(a + b) == isleap(a % 400 + b % 400)
** This is true even if % means modulo rather than Fortran remainder
** (which is allowed by C89 but not C99).
** We use this to avoid addition overflow problems.
*/

#define isleap_sum(a, b)	isleap((a) % 400 + (b) % 400)

#endif /* !defined TZFILE_H */
```