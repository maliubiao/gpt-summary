Response:
Let's break down the thought process for answering the user's request about `bionic/libc/tzcode/bionic.cpp`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of this specific file within Android's Bionic libc. They are interested in its purpose, how it relates to Android, implementation details, interactions with the dynamic linker, potential issues, and how it's reached from higher levels of the Android stack.

**2. Identifying Key Areas of Functionality:**

A quick scan of the code reveals several key areas:

* **Timezone Handling:** The presence of `tzset_unlocked`, `__bionic_get_system_tz`, `__bionic_open_tzdata`, and `tzsetlcl` strongly suggests timezone management.
* **System Properties:** The use of `CachedProperty` indicates interaction with Android system properties, specifically `persist.sys.timezone`.
* **File Access:** The `__bionic_open_tzdata_path` function clearly deals with opening and reading timezone data files.
* **Error Handling:**  The code includes `fprintf(stderr)`, `abort()`, and checks for file open/read errors.
* **Platform Differences:** The `#if defined(__ANDROID__)` block highlights platform-specific behavior.

**3. Answering "What are its functions?":**

Based on the identified key areas, the primary functions are:

* **Getting the system timezone:**  `__bionic_get_system_tz` retrieves the timezone from the `persist.sys.timezone` property.
* **Setting the timezone:** `tzset_unlocked` combines looking at the `TZ` environment variable and the system property to determine the active timezone, delegating the actual setting to `tzsetlcl`.
* **Opening timezone data files:** `__bionic_open_tzdata` searches for and opens the appropriate timezone data file based on the Olson ID.

**4. Connecting to Android Functionality with Examples:**

* **System Timezone:** The `persist.sys.timezone` property is set by the Android system and used by Java and native code. The code handles a specific quirk with "GMT+/-xxxx" format used in system properties.
* **Timezone Database:** The opening of `tzdata` files is essential for the `localtime` and other time-related functions to work correctly.

**5. Explaining Libc Function Implementations:**

Focus on the non-trivial functions within the file:

* **`__bionic_get_system_tz`:** Explain how it reads the system property, handles the null case (defaulting to GMT), and the "GMT+/-xxxx" sign flip.
* **`tzset_unlocked`:**  Describe the order of precedence (`TZ` env var, then system property) and its delegation to `tzsetlcl`. *Initially, I might not know the exact details of `tzsetlcl`, but acknowledge its role in the actual timezone setting.*
* **`__bionic_open_tzdata` and `__bionic_open_tzdata_path`:** This is the most complex part. Explain the file header structure, the index, how it searches for a specific Olson ID, and the fallback mechanism for finding the `tzdata` file.

**6. Addressing Dynamic Linker Aspects:**

This file *doesn't directly implement dynamic linking logic*. However, it *relies* on it. Therefore:

* **SO Layout:** Provide a standard SO layout, explaining sections like `.text`, `.data`, `.bss`, and the GOT/PLT.
* **Linking Process:** Explain the basic steps of dynamic linking: symbol resolution, relocation, and how the dynamic linker loads shared libraries and resolves function calls. Mention the GOT and PLT. *It's important to be clear that this file doesn't perform the linking itself but is part of a library that *is* linked.*

**7. Logical Reasoning, Assumptions, and Inputs/Outputs:**

Consider specific scenarios and predict the behavior:

* **Scenario:**  `persist.sys.timezone` is "America/Los_Angeles", `TZ` is unset.
* **Expected Output:** `__bionic_get_system_tz` will return "America/Los_Angeles". `tzset_unlocked` will use this value.
* **Scenario:** `persist.sys.timezone` is unset, `TZ` is "Europe/London".
* **Expected Output:** `__bionic_get_system_tz` will return "GMT". `tzset_unlocked` will use "Europe/London".
* **Scenario:** `persist.sys.timezone` is "GMT+0800".
* **Expected Output:** `__bionic_get_system_tz` will return "GMT-0800".

**8. Common Usage Errors:**

Think about how developers might misuse these functions or related time functions:

* **Incorrect Timezone Strings:**  Passing invalid Olson IDs.
* **Assuming System Timezone is Always Set:**  The fallback to "GMT" is important to highlight.
* **Not Handling Timezone Changes:**  Understanding that timezone can change and invalidating cached time information.

**9. Android Framework/NDK Path and Frida Hook:**

* **Framework:** Start with high-level Java APIs like `TimeZone.getTimeZone()`, trace down to native calls using JNI.
* **NDK:** Show a simple NDK example using `<ctime>` functions like `localtime`.
* **Frida:** Provide practical examples of hooking `__bionic_get_system_tz` and `__bionic_open_tzdata` to observe behavior and arguments.

**10. Language and Detail:**

* Use clear and concise Chinese.
* Explain technical terms (like Olson ID, GOT, PLT).
* Provide sufficient detail without being overwhelming.
* Organize the answer logically, following the user's request.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on the intricacies of `tzsetlcl`. **Correction:** Realized that the file doesn't implement `tzsetlcl`, so focus on its role as a delegate.
* **Initial thought:**  Provide a deep dive into the binary format of the tzdata file. **Correction:**  Provide enough information to understand the index and data sections, but avoid going into excessive detail about the time zone rules themselves, as that's not the focus of *this* file.
* **Ensuring Clarity about Dynamic Linking:** Make sure to explicitly state that this file *uses* dynamic linking but doesn't *implement* the linker itself. This prevents confusion.

By following this systematic approach, the comprehensive and informative answer provided earlier can be constructed. The key is to break down the request, analyze the code, and then address each aspect of the user's query in a structured and understandable way.
好的，让我们详细分析一下 `bionic/libc/tzcode/bionic.cpp` 这个文件。

**文件功能概述:**

这个 `bionic.cpp` 文件是 Android Bionic libc 中专门负责处理**时区 (Time Zone)** 相关的核心逻辑。它的主要功能包括：

1. **获取系统默认时区：** 从 Android 系统属性中读取系统设置的时区信息。
2. **设置当前进程的时区：**  根据环境变量 `TZ` 和系统属性来设置当前进程使用的时区。
3. **打开时区数据文件：**  根据指定的时区 ID (如 "America/Los_Angeles")，在 Android 系统中查找并打开对应的时区数据文件。这些数据文件包含了时区的详细规则（例如夏令时转换）。

**与 Android 功能的关系及举例说明:**

这个文件与 Android 的核心功能息息相关，因为它直接影响到系统中所有依赖系统时间的应用和服务的时区设置。以下是一些例子：

* **系统时间显示：** Android 系统 UI 显示的时间需要根据当前时区进行调整。`bionic.cpp` 中的函数负责获取正确的时区信息，确保系统显示的时间是准确的。例如，在设置中更改时区后，Android Framework 会更新 `persist.sys.timezone` 属性，`__bionic_get_system_tz` 函数会读取到新的值。
* **Java `java.util.TimeZone`：** Java 代码中使用的 `TimeZone` 类最终会调用到底层的 native 代码来获取时区信息。`bionic.cpp` 提供的功能是 Java 时区支持的基础。
* **网络时间同步 (NTP)：**  即使设备通过 NTP 同步了 UTC 时间，也需要根据时区信息将其转换为本地时间。
* **AlarmManager 和定时任务：**  Android 的 `AlarmManager` 允许开发者设置在特定时间触发的任务。这些时间通常是基于本地时区的，`bionic.cpp` 的功能确保了定时任务在正确的本地时间执行。

**libc 函数功能实现详解:**

1. **`void __bionic_get_system_tz(char* buf, size_t n)`:**
   * **功能：**  获取 Android 系统设置的时区名称。
   * **实现：**
     * 它使用 `CachedProperty` 类来缓存对系统属性 "persist.sys.timezone" 的读取结果。`CachedProperty` 是一种优化手段，避免每次都进行系统调用读取属性。
     * 首先尝试从缓存中获取 "persist.sys.timezone" 的值。
     * 如果系统属性未设置（例如在 recovery 模式下），则默认使用 "GMT"。
     * 使用 `strlcpy` 将时区名称复制到提供的缓冲区 `buf` 中，确保不会发生缓冲区溢出。
     * **关键的 Android 特性处理：** 针对 "GMT+xxxx" 格式的时区字符串进行特殊处理。Java 中 "GMT+3" 表示东三区，而 POSIX 标准中表示西三区。由于 Android 系统属性中的时区字符串可能来源于 Java 层，因此这里会将符号翻转，以符合 POSIX 标准。

2. **`void tzset_unlocked(void)`:**
   * **功能：**  设置当前进程的时区。
   * **实现：**
     * **优先级：**  首先检查环境变量 `TZ` 是否已设置。如果设置了，则使用环境变量的值，因为环境变量具有更高的优先级。
     * 如果 `TZ` 未设置，则调用 `__bionic_get_system_tz` 获取系统默认时区。
     * 最后，调用 `tzsetlcl(name)` 来实际设置时区。`tzsetlcl` 是一个更底层的函数，负责解析时区字符串并加载相应的时区规则。

3. **`int __bionic_open_tzdata(const char* olson_id, int32_t* entry_length)`:**
   * **功能：**  根据给定的 Olson 时区 ID，打开对应的时区数据文件。
   * **实现：**
     * **查找路径：**  它会尝试在两个不同的位置查找时区数据文件（`tzdata`）：
       * `/apex/com.android.tzdata/etc/tz/tzdata`：这是 Android 模块化更新的时区数据，通常是首选位置。
       * `/system/usr/share/zoneinfo/tzdata`：这是系统分区中的备份时区数据。
     * **`__bionic_open_tzdata_path`：** 实际的打开和读取逻辑在 `__bionic_open_tzdata_path` 函数中。
     * **`__bionic_open_tzdata_path` 的实现细节：**
       * **打开文件：**  使用 `open` 系统调用以只读和 `O_CLOEXEC` 标志打开文件。
       * **读取头部：**  读取 `bionic_tzdata_header_t` 结构，该结构包含了版本信息和索引/数据偏移量。
       * **校验头部：**  检查 magic number ("tzdata") 和版本信息。
       * **读取索引：**  根据头部信息，`lseek` 到索引区域，并读取所有索引条目。每个 `index_entry_t` 结构包含时区名称、数据起始位置和长度。
       * **查找时区 ID：**  遍历索引，查找与给定的 `olson_id` 匹配的条目。
       * **定位数据：**  如果找到匹配的条目，则计算出该时区数据在文件中的偏移量。
       * **返回文件描述符：**  `lseek` 到数据起始位置，并将文件描述符返回给调用者。同时，将数据长度写入 `entry_length` 指向的内存。
       * **错误处理：**  如果文件不存在、头部格式错误、找不到指定的时区 ID 等情况，会返回错误代码。特别地，如果找到了有效的 `tzdata` 文件但找不到指定的时区 ID，会设置 `errno` 为 `ENOENT`。

**涉及 dynamic linker 的功能：**

这个 `bionic.cpp` 文件本身**不直接实现** dynamic linker 的功能。然而，它作为 Bionic libc 的一部分，会被动态链接到其他可执行文件和共享库中。

**SO 布局样本：**

一个典型的共享库 (.so) 文件布局如下（简化）：

```
.text         # 存放可执行的代码段
.rodata       # 存放只读数据，例如字符串常量
.data         # 存放已初始化的全局变量和静态变量
.bss          # 存放未初始化的全局变量和静态变量
.symtab       # 符号表，包含导出的和导入的符号信息
.strtab       # 字符串表，存放符号名称等字符串
.rel.dyn      # 动态重定位表，用于在加载时调整地址
.plt          # 程序链接表，用于延迟绑定
.got.plt      # 全局偏移量表，用于存储外部函数的实际地址
...          # 其他段，例如调试信息等
```

**链接的处理过程：**

1. **编译时：** 编译器将 `bionic.cpp` 编译成目标文件 (`.o`)，其中包含了符号信息（例如 `__bionic_get_system_tz` 的符号）。
2. **链接时：** 链接器 (linker) 将多个目标文件和库文件链接成一个可执行文件或共享库。当链接器处理依赖 Bionic libc 的目标文件时，会记录下对 `bionic.cpp` 中定义的符号的引用。
3. **加载时：** 当 Android 系统加载一个使用了 Bionic libc 的进程时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有需要的共享库，包括 `libc.so`。
4. **符号解析和重定位：** dynamic linker 会解析未定义的符号，找到它们在共享库中的定义。例如，当加载的程序调用 `tzset_unlocked` 时，dynamic linker 会在 `libc.so` 中找到该函数的地址。同时，dynamic linker 会根据重定位表的信息，调整程序和共享库中某些指令和数据的地址，使其在内存中能够正确访问。
5. **延迟绑定（Lazy Binding）：** 为了提高加载速度，dynamic linker 通常采用延迟绑定技术。这意味着对外部函数的解析和地址绑定只在第一次调用该函数时发生。`.plt` 和 `.got.plt` 表格就是用于实现延迟绑定的。

**假设输入与输出（逻辑推理）：**

假设我们有以下输入：

* **系统属性 "persist.sys.timezone"：** "Asia/Shanghai"
* **环境变量 "TZ"：** 未设置

**调用 `__bionic_get_system_tz(buf, sizeof(buf))`：**

* **假设输入：** `buf` 是一个足够大的字符数组。
* **输出：** `buf` 的内容将是 "Asia/Shanghai"。

**调用 `tzset_unlocked()`：**

* **假设输入：**  上述系统属性和环境变量。
* **输出：**  `tzset_unlocked` 函数会调用 `tzsetlcl("Asia/Shanghai")` 来设置当前进程的时区为 "Asia/Shanghai"。

**调用 `__bionic_open_tzdata("America/Los_Angeles", &entry_length)`：**

* **假设输入：**  系统包含时区数据文件 `/apex/com.android.tzdata/etc/tz/tzdata` 且其中包含 "America/Los_Angeles" 的信息。
* **输出：**  该函数会返回一个打开的文件描述符，指向 "America/Los_Angeles" 时区数据在文件中的起始位置，并且 `entry_length` 会被设置为该数据的长度。

**用户或编程常见的使用错误：**

1. **假设系统属性总是存在：**  开发者可能会假设 `persist.sys.timezone` 总是被设置，但实际上在某些早期启动阶段或特殊环境下可能为空。应该考虑 `__bionic_get_system_tz` 返回 "GMT" 的情况。
2. **错误地使用 `TZ` 环境变量：**  开发者可能会错误地设置 `TZ` 环境变量，例如使用不正确的时区字符串，导致程序行为异常。
3. **不理解时区数据更新：**  Android 的时区数据可能会通过模块化更新进行升级。开发者不应该硬编码旧版本的时区规则。
4. **在多线程环境中使用时区相关函数不当：** 一些时区相关的函数可能不是线程安全的，需要在多线程环境下进行适当的同步。虽然 `tzset_unlocked` 名字里有 "unlocked"，但它本身会调用其他可能不是完全线程安全的函数。

**Android framework 或 ndk 如何一步步的到达这里：**

**Android Framework (Java 层):**

1. **`java.util.TimeZone.getTimeZone(String id)`:**  在 Java 代码中，通常使用 `TimeZone.getTimeZone()` 方法来获取时区对象。
2. **`System.setProperty("persist.sys.timezone", timezoneId)`:**  在系统设置中更改时区时，Framework 会调用 `System.setProperty()` 来设置系统属性 "persist.sys.timezone"。
3. **Native 方法调用：** `java.util.TimeZone` 的很多操作最终会委托给 native 方法实现。例如，获取时区偏移量、夏令时规则等。
4. **JNI 调用 `__bionic_get_system_tz` 或其他相关函数：**  Java native 方法通过 JNI (Java Native Interface) 调用 Bionic libc 中提供的函数，例如 `__bionic_get_system_tz` 来获取系统时区，或者调用其他底层函数来加载和处理时区数据。

**NDK (Native 层):**

1. **包含头文件：** 在 NDK 代码中，可以通过包含 `<time.h>` 头文件来使用标准 C 库的时间和时区相关函数。
2. **调用 libc 函数：**  例如，可以直接调用 `tzset()` 函数（它内部会调用 `tzset_unlocked()`）来设置进程时区，或者调用 `localtime()`、`gmtime()` 等函数，这些函数会依赖于已设置的时区信息。
3. **Bionic libc 提供实现：** NDK 中使用的这些标准 C 库函数，其具体实现就位于 Bionic libc 中，包括 `bionic.cpp` 中的函数。

**Frida Hook 示例调试步骤：**

假设我们要 hook `__bionic_get_system_tz` 函数，以查看它何时被调用以及返回的时区字符串。

**Frida Hook Script (JavaScript):**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const bionicLib = Module.load("libc.so");
  const bionic_get_system_tz = bionicLib.getExportByName("__bionic_get_system_tz");

  if (bionic_get_system_tz) {
    Interceptor.attach(bionic_get_system_tz, {
      onEnter: function (args) {
        console.log("[*] __bionic_get_system_tz called");
      },
      onLeave: function (retval) {
        const buf = this.context.x0; // 获取第一个参数，假设是 arm64
        const timezone = Memory.readCString(ptr(buf));
        console.log("[*] __bionic_get_system_tz returned: " + timezone);
      },
    });
  } else {
    console.error("[-] __bionic_get_system_tz not found");
  }
} else {
  console.log("Unsupported architecture for this hook.");
}
```

**调试步骤：**

1. **准备环境：** 确保你的 Android 设备已 root，并安装了 Frida 服务。
2. **找到目标进程：** 确定你要调试的进程的包名或进程 ID。
3. **运行 Frida 命令：** 使用 Frida 命令行工具将 hook 脚本注入到目标进程。例如：
   ```bash
   frida -U -f <package_name> -l your_hook_script.js --no-pause
   ```
   或者，如果已知进程 ID：
   ```bash
   frida -U <process_id> -l your_hook_script.js --no-pause
   ```
4. **触发时区相关操作：** 在目标应用中执行一些可能会触发时区相关操作的功能，例如打开设置界面、查看时间显示等。
5. **查看 Frida 输出：** Frida 会在控制台输出 hook 到的信息，包括 `__bionic_get_system_tz` 何时被调用以及返回的时区字符串。

**Hook `__bionic_open_tzdata` 的示例：**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const bionicLib = Module.load("libc.so");
  const bionic_open_tzdata = bionicLib.getExportByName("__bionic_open_tzdata");

  if (bionic_open_tzdata) {
    Interceptor.attach(bionic_open_tzdata, {
      onEnter: function (args) {
        const olson_id = Memory.readCString(ptr(args[0]));
        console.log("[*] __bionic_open_tzdata called with Olson ID: " + olson_id);
      },
      onLeave: function (retval) {
        console.log("[*] __bionic_open_tzdata returned file descriptor: " + retval);
      },
    });
  } else {
    console.error("[-] __bionic_open_tzdata not found");
  }
} else {
  console.log("Unsupported architecture for this hook.");
}
```

通过这些 Frida hook 示例，你可以实时观察这些底层时区相关函数的调用情况，帮助你理解 Android 系统是如何处理时区的。

希望以上详细的解释能够帮助你理解 `bionic/libc/tzcode/bionic.cpp` 文件的功能及其在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/tzcode/bionic.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <arpa/inet.h> // For ntohl(3).
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "private/CachedProperty.h"

extern "C" void tzset_unlocked(void);
extern "C" void __bionic_get_system_tz(char* buf, size_t n);
extern "C" int __bionic_open_tzdata(const char*, int32_t*);

extern "C" void tzsetlcl(char const*);

void __bionic_get_system_tz(char* buf, size_t n) {
  static CachedProperty persist_sys_timezone("persist.sys.timezone");
  const char* name = persist_sys_timezone.Get();

  // If the system property is not set, perhaps because this is called
  // before the default value has been set (the recovery image being a
  // classic example), fall back to GMT.
  if (name == nullptr) name = "GMT";

  strlcpy(buf, name, n);

  if (!strcmp(buf, "GMT")) {
    // Typically we'll set the system property to an Olson ID, but
    // java.util.TimeZone also supports the "GMT+xxxx" style, and at
    // least historically (see http://b/25463955) some Android-based set
    // top boxes would get the timezone from the TV network in this format
    // and use it directly in the system property. This caused trouble
    // for native code because POSIX and Java disagree about the sign in
    // a timezone string. For POSIX, "GMT+3" means "3 hours west/behind",
    // but for Java it means "3 hours east/ahead". Since (a) Java is the
    // one that matches human expectations and (b) this system property is
    // used directly by Java, we flip the sign here to translate from Java
    // to POSIX. We only need to worry about the "GMT+xxxx" case because
    // the expectation is that these are valid java.util.TimeZone ids,
    // not general POSIX custom timezone specifications (which is why this
    // code only applies to the system property, and not to the environment
    // variable).
    char sign = buf[3];
    if (sign == '-' || sign == '+') {
      buf[3] = (sign == '-') ? '+' : '-';
    }
  }
}

void tzset_unlocked() {
  // The TZ environment variable is meant to override the system-wide setting.
  const char* name = getenv("TZ");
  char buf[PROP_VALUE_MAX];

  // If that's not set, look at the "persist.sys.timezone" system property.
  if (name == nullptr) {
    __bionic_get_system_tz(buf, sizeof(buf));
    name = buf;
  }

  tzsetlcl(name);
}

#if !defined(__ANDROID__)
static char* make_path(const char* path_prefix_variable,
                       const char* path_suffix) {
  const char* path_prefix = getenv(path_prefix_variable);
  if (path_prefix == nullptr) {
    fprintf(stderr, "%s: %s not set!\n", __FUNCTION__, path_prefix_variable);
    abort();
  }
  char* path;
  if (asprintf(&path, "%s/%s", path_prefix, path_suffix) == -1) {
    fprintf(stderr, "%s: couldn't allocate \"%s/%s\"\n", __FUNCTION__, path_prefix, path_suffix);
    abort();
  }
  return path;
}
#endif

// byte[12] tzdata_version  -- "tzdata2012f\0"
// int index_offset
// int data_offset
// int final_offset
struct bionic_tzdata_header_t {
  char tzdata_version[12];
  int32_t index_offset;
  int32_t data_offset;
  int32_t final_offset;
};
static constexpr size_t NAME_LENGTH = 40;
struct index_entry_t {
  char buf[NAME_LENGTH];
  int32_t start;
  int32_t length;
  int32_t unused; // Was raw GMT offset; always 0 since tzdata2014f (L).
};

// Returns -2 for a soft failure (where the caller should try another file),
// -1 for a hard failure (where the caller should give up), and >= 0 is a
// file descriptor whose offset points to the data for the given olson id in
// the given file (and *entry_length is the size of the data).
static int __bionic_open_tzdata_path(const char* path,
                                     const char* olson_id,
                                     int32_t* entry_length) {
  int fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    // We don't log here, because this is quite common --- current devices
    // aren't expected to have the old APK tzdata, for example.
    return -2;
  }

  bionic_tzdata_header_t header = {};
  ssize_t bytes_read = TEMP_FAILURE_RETRY(read(fd, &header, sizeof(header)));
  if (bytes_read != sizeof(header)) {
    fprintf(stderr, "%s: could not read header of \"%s\": %s\n",
            __FUNCTION__, path, (bytes_read == -1) ? strerror(errno) : "short read");
    close(fd);
    return -2;
  }

  if (strncmp(header.tzdata_version, "tzdata", 6) != 0 || header.tzdata_version[11] != 0) {
    fprintf(stderr, "%s: bad magic in \"%s\": \"%.6s\"\n", __FUNCTION__, path, header.tzdata_version);
    close(fd);
    return -2;
  }

  if (TEMP_FAILURE_RETRY(lseek(fd, ntohl(header.index_offset), SEEK_SET)) == -1) {
    fprintf(stderr, "%s: couldn't seek to index in \"%s\": %s\n", __FUNCTION__, path, strerror(errno));
    close(fd);
    return -2;
  }

  if (ntohl(header.index_offset) > ntohl(header.data_offset)) {
    fprintf(stderr, "%s: invalid data and index offsets in \"%s\": %u %u\n",
            __FUNCTION__, path, ntohl(header.data_offset), ntohl(header.index_offset));
    close(fd);
    return -2;
  }
  const size_t index_size = ntohl(header.data_offset) - ntohl(header.index_offset);
  if ((index_size % sizeof(index_entry_t)) != 0) {
    fprintf(stderr, "%s: invalid index size in \"%s\": %zd\n", __FUNCTION__, path, index_size);
    close(fd);
    return -2;
  }

  char* index = reinterpret_cast<char*>(malloc(index_size));
  if (index == nullptr) {
    fprintf(stderr, "%s: couldn't allocate %zd-byte index for \"%s\"\n", __FUNCTION__, index_size, path);
    close(fd);
    return -2;
  }
  if (TEMP_FAILURE_RETRY(read(fd, index, index_size)) != static_cast<ssize_t>(index_size)) {
    fprintf(stderr, "%s: could not read index of \"%s\": %s\n",
            __FUNCTION__, path, (bytes_read == -1) ? strerror(errno) : "short read");
    free(index);
    close(fd);
    return -2;
  }

  off_t specific_zone_offset = -1;
  size_t id_count = index_size / sizeof(index_entry_t);
  index_entry_t* entry = reinterpret_cast<index_entry_t*>(index);
  for (size_t i = 0; i < id_count; ++i) {
    char this_id[NAME_LENGTH + 1];
    memcpy(this_id, entry->buf, NAME_LENGTH);
    this_id[NAME_LENGTH] = '\0';

    if (strcmp(this_id, olson_id) == 0) {
      specific_zone_offset = ntohl(entry->start) + ntohl(header.data_offset);
      *entry_length = ntohl(entry->length);
      break;
    }

    ++entry;
  }
  free(index);

  if (specific_zone_offset == -1) {
    // We found a valid tzdata file, but didn't find the requested id in it.
    // Give up now, and don't try fallback tzdata files. We don't log here
    // because for all we know the given olson id was nonsense.
    close(fd);
    // This file descriptor (-1) is passed to localtime.c. In invalid fd case
    // upstream passes errno value around methods and having 0 there will
    // indicate that timezone was found and read successfully and localtime's
    // internal state was properly initialized (which wasn't as we couldn't find
    // requested timezone in the tzdata file).
    // If we reached this point errno is unlikely to be touched. It is only
    // close(fd) which can do it, but that is very unlikely to happen. And
    // even if it happens we can't extract any useful insights from it.
    // We are overriding it to ENOENT as it matches upstream expectations -
    // timezone is absent in the tzdata file == there is no TZif file in
    // /usr/share/zoneinfo.
    errno = ENOENT;
    return -1;
  }

  if (TEMP_FAILURE_RETRY(lseek(fd, specific_zone_offset, SEEK_SET)) == -1) {
    fprintf(stderr, "%s: could not seek to %ld in \"%s\": %s\n",
            __FUNCTION__, specific_zone_offset, path, strerror(errno));
    close(fd);
    return -2;
  }

  return fd;
}

int __bionic_open_tzdata(const char* olson_id, int32_t* entry_length) {
  int fd;

  // Try the two locations for the tzdata file in a strict order:
  // 1: The timezone data module which contains the main copy. This is the
  //    common case for current devices.
  // 2: The ultimate fallback: the non-updatable copy in /system.

#if defined(__ANDROID__)
  // On Android devices, bionic has to work even if exec takes place without
  // environment variables set. So, all paths are hardcoded here.
  fd = __bionic_open_tzdata_path("/apex/com.android.tzdata/etc/tz/tzdata",
                                 olson_id, entry_length);
  if (fd >= -1) return fd;

  fd = __bionic_open_tzdata_path("/system/usr/share/zoneinfo/tzdata",
                                 olson_id, entry_length);
  if (fd >= -1) return fd;
#else
  // On the host, we don't expect the hard-coded locations above to exist, and
  // we're not worried about security so we trust $ANDROID_TZDATA_ROOT, and
  // $ANDROID_ROOT to point us in the right direction instead.

  char* path = make_path("ANDROID_TZDATA_ROOT", "/etc/tz/tzdata");
  fd = __bionic_open_tzdata_path(path, olson_id, entry_length);
  free(path);
  if (fd >= -1) return fd;

  path = make_path("ANDROID_ROOT", "/usr/share/zoneinfo/tzdata");
  fd = __bionic_open_tzdata_path(path, olson_id, entry_length);
  free(path);
  if (fd >= -1) return fd;
#endif

  // Not finding any tzdata is more serious that not finding a specific zone,
  // and worth logging.
  if (fd == -2) {
    // The first thing that 'recovery' does is try to format the current time. It doesn't have
    // any tzdata available, so we must not abort here --- doing so breaks the recovery image!
    fprintf(stderr, "%s: couldn't find any tzdata when looking for %s!\n", __FUNCTION__, olson_id);
  }

  // Otherwise we were successful.
  return fd;
}

"""

```