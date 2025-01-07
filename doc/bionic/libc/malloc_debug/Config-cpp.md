Response:
Let's break down the thought process to answer the request about `bionic/libc/malloc_debug/Config.cpp`.

**1. Understanding the Goal:**

The core request is to analyze the provided C++ code, `Config.cpp`, within the context of Android's Bionic library. This means identifying its purpose, functionality, how it interacts with Android, how its functions are implemented, its role in the dynamic linking process (if any), potential user errors, and how to debug it.

**2. Initial Code Scan and High-Level Interpretation:**

The first step is to quickly read through the code to get a general sense of what it's doing. Keywords and patterns that stand out include:

* `#include` statements for various standard C/C++ libraries (`assert.h`, `ctype.h`, `errno.h`, etc.) and Bionic-specific headers.
* `Config` class with member variables and methods.
* Constants defined at the top (e.g., `DEFAULT_FILL_ALLOC_VALUE`, `DEFAULT_GUARD_BYTES`).
* A static `std::unordered_map` called `kOptions`.
* Functions like `ParseValue`, `SetGuard`, `SetBacktrace`, etc.
* Logging via `error_log`.

From this initial scan, it's clear that this code is responsible for *configuring* some debugging features related to memory allocation. The `kOptions` map likely defines the available configuration options and their associated processing functions.

**3. Detailed Analysis of Functionality:**

Now, go through the code function by function and constant by constant.

* **Constants:**  Document what each constant represents (default values, limits).
* **`kOptions` Map:**  Crucially important. List each option, its short description, and the flags it sets/uses. Recognize that the flags (like `FRONT_GUARD`, `BACKTRACE`) likely control which debugging features are active. Note the associated setter functions.
* **`ParseValue` Overloads:**  Understand how these functions parse string values into `size_t`, handling errors and validating ranges.
* **Setter Functions (e.g., `SetGuard`, `SetBacktrace`):**  Describe the purpose of each setter. Notice how they update the `Config` object's member variables. Pay attention to special logic, like the alignment in `SetFrontGuard`.
* **`VerifyValueEmpty`:**  Understand that some options are boolean flags and don't take a value.
* **`LogUsage`:**  Simple function to display help information.
* **`GetOption`:**  This is key to understanding how the configuration string is parsed. It tokenizes the input string based on spaces and the `=` sign.
* **`Init`:**  The initialization function. It sets default values and then parses the configuration string using `GetOption` and the `kOptions` map. It also sets internal flags based on the parsed options.

**4. Connecting to Android Functionality:**

The file path (`bionic/libc/malloc_debug/Config.cpp`) immediately tells us this is part of Android's C library. The debugging options described in the code (guard pages, backtraces, fill patterns, etc.) are standard techniques for detecting memory errors. Consider:

* **Guard Pages:**  How do they detect buffer overflows?
* **Backtraces:** How are they used for debugging allocation/deallocation issues?
* **Fill Patterns:** How do they help identify use-after-free errors?

Think about *where* these configurations might come from. Environment variables are a likely candidate. The code itself doesn't directly specify the source, but the name "options_str" in the `Init` function suggests a string-based configuration.

**5. Dynamic Linker Interaction (and Realization of Limited Scope):**

Carefully examine the code for any explicit interactions with the dynamic linker (e.g., calls to `dlopen`, `dlsym`, or specific linker data structures). *In this particular file, there are no direct interactions with the dynamic linker*. It focuses solely on memory allocation debugging *within* the process. Therefore, the explanation regarding the dynamic linker should acknowledge this limited scope and potentially mention how these malloc debugging features might interact with dynamically loaded libraries indirectly through memory allocation.

**6. User Errors and Examples:**

Think about common mistakes developers make related to memory management and how these debugging options could help detect them:

* **Buffer overflows:** Guard pages will trigger an error.
* **Use-after-free:** Fill patterns make freed memory easily identifiable.
* **Memory leaks:** Leak tracking (although the implementation isn't in this file) would be relevant.

Provide simple code snippets demonstrating these errors and how enabling the relevant options would help.

**7. Tracing from Android Framework/NDK:**

Consider how a typical Android application might end up using this code. The flow would be:

1. An app uses standard C/C++ allocation functions (`malloc`, `free`, `new`, `delete`).
2. Bionic's `malloc` implementation includes the malloc debugging logic if enabled.
3. The configuration for malloc debugging is likely set through environment variables.

To hook into this using Frida, target the `malloc` and `free` functions in `libc.so`. Show a basic Frida script that intercepts these calls and logs information. Mention that hooking *this* `Config.cpp` file directly isn't the typical way, as it's about the *setup* of the debugging, not the core allocation logic.

**8. Structuring the Response:**

Organize the information logically, following the points raised in the request:

* Functionality overview.
* Relationship to Android (with examples).
* Detailed explanation of each function.
* Dynamic linker aspects (even if limited, explain why).
* Input/output examples (for parsing).
* Common user errors.
* Tracing from Android/NDK (with Frida example).

**9. Language and Tone:**

Use clear and concise Chinese. Explain technical concepts in a way that is understandable to someone familiar with programming but perhaps not deeply familiar with Android internals.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this `Config.cpp` directly interacts with the dynamic linker to set up debugging for loaded libraries. **Correction:** After reviewing the code, realize it primarily configures the *malloc* implementation itself. The interaction with dynamic linking is indirect.
* **Initial thought:** Focus heavily on the implementation details of every function. **Correction:**  Prioritize the *purpose* and *impact* of each function. Implementation details can be summarized unless they are particularly important.
* **Initial thought:** Provide very complex Frida examples. **Correction:** Keep the Frida examples simple and focused on demonstrating the core concept of hooking `malloc` and `free`.

By following these steps, combining code analysis with an understanding of the Android environment, and refining the approach as needed, one can construct a comprehensive and accurate answer to the request.
好的，让我们详细分析一下 `bionic/libc/malloc_debug/Config.cpp` 这个文件。

**文件功能总览**

`Config.cpp` 文件的主要功能是**解析和存储用于控制 bionic libc 中内存分配调试功能的配置选项**。它定义了一个 `Config` 类，负责从字符串（通常是环境变量）中读取配置，并根据这些配置设置各种调试特性，例如：

* **Guard Pages（保护页）:** 在分配的内存区域前后添加保护区域，用于检测缓冲区溢出。
* **Backtraces（回溯跟踪）:** 记录内存分配和释放时的调用栈信息，帮助定位问题。
* **Fill Patterns（填充模式）:**  在分配或释放的内存中填充特定的字节值，用于检测 use-after-free 等错误。
* **Leak Tracking（内存泄漏跟踪）:**  记录所有分配但未释放的内存，并在程序退出时报告。
* **Allocation Recording（分配记录）:** 将所有内存分配信息记录到文件中。

**与 Android 功能的关系及举例说明**

`Config.cpp` 是 bionic libc 的一部分，而 bionic libc 是 Android 操作系统的核心 C 库。因此，这个文件直接影响着 Android 平台上所有使用标准 C 内存分配函数（如 `malloc`, `free`, `calloc`, `realloc` 等）的进程。

**举例说明：**

1. **开发者调试 Native 代码:** Android NDK 允许开发者使用 C/C++ 开发 Native 代码。当开发者在 Native 代码中遇到内存相关的错误（如缓冲区溢出、内存泄漏）时，他们可以通过设置环境变量来启用 `malloc_debug` 的各种功能。例如，设置 `LIBC_DEBUG=guard` 可以启用 guard pages 来检测缓冲区溢出。

2. **系统服务调试:** Android 系统服务通常使用 C/C++ 编写。当系统服务出现内存问题时，开发者可以使用 `adb shell setprop libc.debug.malloc <options>` 命令来动态配置内存调试选项，无需重启服务。

3. **应用崩溃分析:**  当应用发生与内存相关的崩溃时，如果启用了回溯跟踪等功能，可以提供更详细的崩溃信息，帮助开发者定位问题。

**详细解释每一个 libc 函数的功能是如何实现的**

`Config.cpp` 本身**不实现** libc 的内存分配函数（如 `malloc`, `free`）。它的作用是**配置**用于调试这些内存分配函数的机制。

内存分配函数的具体实现位于 bionic libc 的其他文件中，例如 `bionic/libc/bionic/malloc.cpp`。`Config.cpp` 中解析的配置信息会被传递给内存分配函数的实现，从而启用或禁用相应的调试特性。

例如，当 `Config.cpp` 解析到 `guard` 选项时，它会设置 `front_guard_bytes_` 和 `rear_guard_bytes_` 变量。在 `malloc` 的实际实现中，会检查这些变量的值，如果大于 0，则会在分配的内存块前后添加指定大小的保护区域。访问这些保护区域会导致内存访问错误，从而被操作系统捕获。

**涉及 dynamic linker 的功能、so 布局样本及链接处理过程**

`Config.cpp` 本身**不直接涉及 dynamic linker 的核心功能**，例如符号解析和库加载。它的主要作用域是内存分配调试，这发生在进程的运行时。

**但是，`malloc_debug` 的某些功能可能会间接地与 dynamic linker 交互。** 例如，当启用回溯跟踪时，需要获取当前调用栈的信息。这可能涉及到访问与 dynamic linker 相关的数据结构，例如用于 unwind 栈帧的信息。

**SO 布局样本（仅为示意，不一定完全对应实际情况）：**

```
加载地址: 0xb4000000

libc.so (Android's C library)
    .text   (代码段)
        malloc()  <-- malloc 函数的实现
        free()    <-- free 函数的实现
        // ... 其他 libc 函数 ...
    .data   (已初始化数据段)
        // ... 全局变量 ...
    .bss    (未初始化数据段)
        // ... 全局变量 ...
    .dynamic (动态链接信息)
        // ... 符号表，重定位表等 ...

libmaldvb.so (假设存在一个专门用于 malloc 调试的 SO，实际可能集成在 libc.so 中)
    .text
        // ... malloc_debug 的相关逻辑，可能读取 Config 的配置 ...
```

**链接处理过程：**

1. 当一个应用启动时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载应用的依赖库，包括 `libc.so`。
2. 在 `libc.so` 初始化阶段，可能会读取环境变量 `LIBC_DEBUG` 或通过 `setprop` 设置的属性来获取 malloc 调试的配置信息。
3. `Config::Init()` 函数会被调用，解析配置字符串，并设置相应的内部状态。
4. 当应用调用 `malloc` 等内存分配函数时，`libc.so` 中的 `malloc` 实现会检查 `Config` 对象中设置的调试选项，并执行相应的调试操作（例如添加 guard pages，记录回溯信息）。

**逻辑推理、假设输入与输出**

假设我们设置了环境变量 `LIBC_DEBUG="guard=32 backtrace=10"`。

**假设输入：** 环境变量字符串 `"guard=32 backtrace=10"`

**`Config::Init()` 的处理过程：**

1. `GetOption` 函数会依次解析出 `"guard"` 和 `"32"`，然后解析出 `"backtrace"` 和 `"10"`。
2. 对于 `"guard"` 选项，`Config::SetGuard("guard", "32")` 会被调用。`ParseValue` 函数会将字符串 `"32"` 解析为整数 32，并设置 `front_guard_bytes_` 和 `rear_guard_bytes_` 为 32（并进行对齐）。
3. 对于 `"backtrace"` 选项，`Config::SetBacktrace("backtrace", "10")` 会被调用。`ParseValue` 函数会将字符串 `"10"` 解析为整数 10，并设置 `backtrace_enabled_` 为 `true`，`backtrace_frames_` 为 10。

**假设输出（`Config` 对象的内部状态）：**

* `front_guard_bytes_`: 32 (或对齐后的值)
* `rear_guard_bytes_`: 32
* `backtrace_enabled_`: true
* `backtrace_frames_`: 10
* 其他配置选项保持默认值或之前设置的值。

**涉及用户或编程常见的使用错误及举例说明**

1. **拼写错误或不支持的选项名：**  如果环境变量中使用了错误的选项名，例如 `LIBC_DEBUG="grd=32"`, `Config::Init()` 会输出错误日志 "unknown option grd"，并且该选项不会生效。

   ```
   error_log("%s: unknown option %s", getprogname(), option.c_str());
   ```

2. **选项值格式错误：** 如果选项的值不是合法的数字，例如 `LIBC_DEBUG="guard=abc"`, `ParseValue` 函数会解析失败并输出错误日志。

   ```
   error_log("%s: bad value for option '%s'", getprogname(), option.c_str());
   ```

3. **选项值超出范围：**  如果选项的值超出了允许的范围，例如 `LIBC_DEBUG="guard=20000"`, `ParseValue` 函数会检查范围并输出错误日志。

   ```
   error_log("%s: bad value for option '%s', value must be <= %zu: %ld", getprogname(),
             option.c_str(), max_value, long_value);
   ```

4. **为不需要值的选项设置了值：**  对于像 `leak_track` 这样的选项，它不需要值，如果设置了值，例如 `LIBC_DEBUG="leak_track=1"`, `VerifyValueEmpty` 函数会输出错误日志。

   ```
   error_log("%s: value set for option '%s' which does not take a value", getprogname(),
             option.c_str());
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `Config.cpp` 的路径：**

1. **应用启动:** 当一个 Android 应用（Java 或 Kotlin）启动时，Zygote 进程会 fork 出一个新的进程来运行应用。
2. **加载 Native 库:** 如果应用使用了 NDK 开发的 Native 代码，系统会加载相关的 `.so` 文件，通常包括 `libc.so`。
3. **`libc.so` 初始化:** 在 `libc.so` 加载时，其初始化代码会被执行。这其中可能包括读取环境变量 `LIBC_DEBUG` 或系统属性 `libc.debug.malloc`。
4. **调用 `Config::Init()`:**  `libc.so` 的初始化代码会创建一个 `Config` 对象，并调用其 `Init()` 方法，将读取到的配置字符串传递给它。
5. **配置生效:** `Config::Init()` 解析配置并设置内部状态，这些状态会影响后续的内存分配操作。

**NDK 到 `Config.cpp` 的路径：**

1. **NDK 代码调用 `malloc`:**  NDK 开发的 C/C++ 代码会直接调用 `malloc`, `free` 等标准 C 库的内存分配函数。
2. **调用 `libc.so` 中的实现:** 这些调用最终会跳转到 `libc.so` 中对应的函数实现。
3. **检查 `Config` 状态:** `libc.so` 中的 `malloc` 实现会检查 `Config` 对象中的配置，例如是否启用了 guard pages，是否需要记录回溯信息。
4. **执行调试操作:**  根据 `Config` 的配置，`malloc` 实现会执行相应的调试操作。

**Frida Hook 示例：**

我们可以使用 Frida Hook `Config::Init` 函数来观察配置的解析过程。

```python
import frida
import sys

package_name = "你的应用包名" # 替换为你要调试的应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到包名为 {package_name} 的进程，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "_ZN6Config4InitEPKc"), {
    onEnter: function(args) {
        console.log("[+] Config::Init called with options: " + ptr(args[0]).readCString());
    },
    onLeave: function(retval) {
        console.log("[+] Config::Init returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用说明：**

1. 将 `你的应用包名` 替换为你要调试的 Android 应用的包名。
2. 确保你的 Android 设备已连接并启用了 USB 调试。
3. 运行 Frida 脚本。
4. 启动目标应用。

**预期输出：**

Frida 会 Hook `libc.so` 中的 `Config::Init` 函数，并在其被调用时打印出传递给它的配置字符串。你可以在启动应用前设置不同的 `LIBC_DEBUG` 环境变量或系统属性，然后观察 Frida 的输出，了解 `Config::Init` 是如何被调用的以及传递了哪些配置信息。

例如，如果你设置了 `LIBC_DEBUG="guard=64"`, 你可能会在 Frida 的输出中看到类似这样的信息：

```
[*] [+] Config::Init called with options: guard=64
[*] [+] Config::Init returned: 1
```

这个 Frida 示例只是一个起点。你可以进一步 Hook `Config` 类的其他方法或相关的内存分配函数，以更深入地了解内存调试功能的运作方式。

希望以上详细的解答能够帮助你理解 `bionic/libc/malloc_debug/Config.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/malloc_debug/Config.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>

#include <string>
#include <vector>

#include <platform/bionic/macros.h>

#include "Config.h"
#include "debug_log.h"

// Config constants
static constexpr uint8_t DEFAULT_FILL_ALLOC_VALUE = 0xeb;
static constexpr uint8_t DEFAULT_FILL_FREE_VALUE = 0xef;

static constexpr uint8_t DEFAULT_FRONT_GUARD_VALUE = 0xaa;
static constexpr uint8_t DEFAULT_REAR_GUARD_VALUE = 0xbb;

// Used as the default for all guard values.
static constexpr size_t DEFAULT_GUARD_BYTES = 32;
static constexpr size_t MAX_GUARD_BYTES = 16384;

static constexpr size_t DEFAULT_BACKTRACE_FRAMES = 16;
static constexpr size_t MAX_BACKTRACE_FRAMES = 256;
static constexpr const char DEFAULT_BACKTRACE_DUMP_PREFIX[] = "/data/local/tmp/backtrace_heap";

static constexpr size_t DEFAULT_EXPAND_BYTES = 16;
static constexpr size_t MAX_EXPAND_BYTES = 16384;

static constexpr size_t DEFAULT_FREE_TRACK_ALLOCATIONS = 100;
static constexpr size_t MAX_FREE_TRACK_ALLOCATIONS = 16384;

static constexpr size_t DEFAULT_RECORD_ALLOCS = 8000000;
static constexpr size_t MAX_RECORD_ALLOCS = 50000000;
static constexpr const char DEFAULT_RECORD_ALLOCS_FILE[] = "/data/local/tmp/record_allocs.txt";

const std::unordered_map<std::string, Config::OptionInfo> Config::kOptions = {
    {
        "guard",
        {FRONT_GUARD | REAR_GUARD | TRACK_ALLOCS, &Config::SetGuard},
    },
    {
        "front_guard",
        {FRONT_GUARD | TRACK_ALLOCS, &Config::SetFrontGuard},
    },
    {
        "rear_guard",
        {REAR_GUARD | TRACK_ALLOCS, &Config::SetRearGuard},
    },

    {
        "backtrace_size",
        {BACKTRACE_SPECIFIC_SIZES, &Config::SetBacktraceSize},
    },
    {
        "bt_sz",
        {BACKTRACE_SPECIFIC_SIZES, &Config::SetBacktraceSize},
    },
    {
        "backtrace_min_size",
        {BACKTRACE_SPECIFIC_SIZES, &Config::SetBacktraceMinSize},
    },
    {
        "bt_min_sz",
        {BACKTRACE_SPECIFIC_SIZES, &Config::SetBacktraceMinSize},
    },
    {
        "backtrace_max_size",
        {BACKTRACE_SPECIFIC_SIZES, &Config::SetBacktraceMaxSize},
    },
    {
        "bt_max_sz",
        {BACKTRACE_SPECIFIC_SIZES, &Config::SetBacktraceMaxSize},
    },
    {
        "backtrace",
        {BACKTRACE | TRACK_ALLOCS, &Config::SetBacktrace},
    },
    {
        "bt",
        {BACKTRACE | TRACK_ALLOCS, &Config::SetBacktrace},
    },
    {
        "backtrace_enable_on_signal",
        {BACKTRACE | TRACK_ALLOCS, &Config::SetBacktraceEnableOnSignal},
    },
    {
        "bt_en_on_sig",
        {BACKTRACE | TRACK_ALLOCS, &Config::SetBacktraceEnableOnSignal},
    },
    {
        "backtrace_dump_on_exit",
        {0, &Config::SetBacktraceDumpOnExit},
    },
    {
        "bt_dmp_on_ex",
        {0, &Config::SetBacktraceDumpOnExit},
    },
    {
        "backtrace_dump_prefix",
        {0, &Config::SetBacktraceDumpPrefix},
    },
    {
        "bt_dmp_pre",
        {0, &Config::SetBacktraceDumpPrefix},
    },
    {
        "backtrace_full",
        {BACKTRACE_FULL, &Config::VerifyValueEmpty},
    },
    {
        "bt_full",
        {BACKTRACE_FULL, &Config::VerifyValueEmpty},
    },

    {
        "fill",
        {FILL_ON_ALLOC | FILL_ON_FREE, &Config::SetFill},
    },
    {
        "fill_on_alloc",
        {FILL_ON_ALLOC, &Config::SetFillOnAlloc},
    },
    {
        "fill_on_free",
        {FILL_ON_FREE, &Config::SetFillOnFree},
    },

    {
        "expand_alloc",
        {EXPAND_ALLOC, &Config::SetExpandAlloc},
    },

    {
        "free_track",
        {FREE_TRACK | FILL_ON_FREE | TRACK_ALLOCS, &Config::SetFreeTrack},
    },
    {
        "free_track_backtrace_num_frames",
        {0, &Config::SetFreeTrackBacktraceNumFrames},
    },

    {
        "leak_track",
        {LEAK_TRACK | TRACK_ALLOCS, &Config::VerifyValueEmpty},
    },

    {
        "record_allocs",
        {RECORD_ALLOCS, &Config::SetRecordAllocs},
    },
    {
        "record_allocs_file",
        {0, &Config::SetRecordAllocsFile},
    },
    {
        "record_allocs_on_exit",
        {0, &Config::SetRecordAllocsOnExit},
    },

    {
        "verify_pointers",
        {TRACK_ALLOCS, &Config::VerifyValueEmpty},
    },
    {
        "abort_on_error",
        {ABORT_ON_ERROR, &Config::VerifyValueEmpty},
    },
    {
        "verbose",
        {VERBOSE, &Config::VerifyValueEmpty},
    },
    {
        "check_unreachable_on_signal",
        {CHECK_UNREACHABLE_ON_SIGNAL, &Config::VerifyValueEmpty},
    },
    {
        "log_allocator_stats_on_signal",
        {LOG_ALLOCATOR_STATS_ON_SIGNAL, &Config::VerifyValueEmpty},
    },
    {
        "log_allocator_stats_on_exit",
        {LOG_ALLOCATOR_STATS_ON_EXIT, &Config::VerifyValueEmpty},
    },
};

bool Config::ParseValue(const std::string& option, const std::string& value, size_t min_value,
                        size_t max_value, size_t* parsed_value) const {
  assert(!value.empty());

  // Parse the value into a size_t value.
  errno = 0;
  char* end;
  long long_value = strtol(value.c_str(), &end, 10);
  if (errno != 0) {
    error_log("%s: bad value for option '%s': %s", getprogname(), option.c_str(), strerror(errno));
    return false;
  }
  if (end == value.c_str()) {
    error_log("%s: bad value for option '%s'", getprogname(), option.c_str());
    return false;
  }
  if (static_cast<size_t>(end - value.c_str()) != value.size()) {
    error_log("%s: bad value for option '%s', non space found after option: %s", getprogname(),
              option.c_str(), end);
    return false;
  }
  if (long_value < 0) {
    error_log("%s: bad value for option '%s', value cannot be negative: %ld", getprogname(),
              option.c_str(), long_value);
    return false;
  }

  if (static_cast<size_t>(long_value) < min_value) {
    error_log("%s: bad value for option '%s', value must be >= %zu: %ld", getprogname(),
              option.c_str(), min_value, long_value);
    return false;
  }
  if (static_cast<size_t>(long_value) > max_value) {
    error_log("%s: bad value for option '%s', value must be <= %zu: %ld", getprogname(),
              option.c_str(), max_value, long_value);
    return false;
  }
  *parsed_value = static_cast<size_t>(long_value);
  return true;
}

bool Config::ParseValue(const std::string& option, const std::string& value, size_t default_value,
                        size_t min_value, size_t max_value, size_t* new_value) const {
  if (value.empty()) {
    *new_value = default_value;
    return true;
  }
  return ParseValue(option, value, min_value, max_value, new_value);
}

bool Config::SetGuard(const std::string& option, const std::string& value) {
  if (value.empty()) {
    // Set the defaults.
    front_guard_bytes_ = DEFAULT_GUARD_BYTES;
    rear_guard_bytes_ = DEFAULT_GUARD_BYTES;
    return true;
  }

  if (!ParseValue(option, value, 1, MAX_GUARD_BYTES, &rear_guard_bytes_)) {
    return false;
  }

  // It's necessary to align the front guard to MINIMUM_ALIGNMENT_BYTES to
  // make sure that the header is aligned properly.
  front_guard_bytes_ = __BIONIC_ALIGN(rear_guard_bytes_, MINIMUM_ALIGNMENT_BYTES);
  return true;
}

bool Config::SetFrontGuard(const std::string& option, const std::string& value) {
  if (!ParseValue(option, value, DEFAULT_GUARD_BYTES, 1, MAX_GUARD_BYTES, &front_guard_bytes_)) {
    return false;
  }
  // It's necessary to align the front guard to MINIMUM_ALIGNMENT_BYTES to
  // make sure that the header is aligned properly.
  front_guard_bytes_ = __BIONIC_ALIGN(front_guard_bytes_, MINIMUM_ALIGNMENT_BYTES);
  return true;
}

bool Config::SetRearGuard(const std::string& option, const std::string& value) {
  return ParseValue(option, value, DEFAULT_GUARD_BYTES, 1, MAX_GUARD_BYTES, &rear_guard_bytes_);
}

bool Config::SetFill(const std::string& option, const std::string& value) {
  if (value.empty()) {
    // Set the defaults.
    fill_on_alloc_bytes_ = SIZE_MAX;
    fill_on_free_bytes_ = SIZE_MAX;
    return true;
  }

  if (!ParseValue(option, value, 1, SIZE_MAX, &fill_on_alloc_bytes_)) {
    return false;
  }
  fill_on_free_bytes_ = fill_on_alloc_bytes_;
  return true;
}

bool Config::SetFillOnAlloc(const std::string& option, const std::string& value) {
  return ParseValue(option, value, SIZE_MAX, 1, SIZE_MAX, &fill_on_alloc_bytes_);
}

bool Config::SetFillOnFree(const std::string& option, const std::string& value) {
  return ParseValue(option, value, SIZE_MAX, 1, SIZE_MAX, &fill_on_free_bytes_);
}

bool Config::SetBacktrace(const std::string& option, const std::string& value) {
  backtrace_enabled_ = true;
  return ParseValue(option, value, DEFAULT_BACKTRACE_FRAMES, 1, MAX_BACKTRACE_FRAMES,
                    &backtrace_frames_);
}

bool Config::SetBacktraceEnableOnSignal(const std::string& option, const std::string& value) {
  backtrace_enable_on_signal_ = true;
  return ParseValue(option, value, DEFAULT_BACKTRACE_FRAMES, 1, MAX_BACKTRACE_FRAMES,
                    &backtrace_frames_);
}

bool Config::SetBacktraceDumpOnExit(const std::string& option, const std::string& value) {
  if (Config::VerifyValueEmpty(option, value)) {
    backtrace_dump_on_exit_ = true;
    return true;
  }
  return false;
}

bool Config::SetBacktraceDumpPrefix(const std::string&, const std::string& value) {
  if (value.empty()) {
    backtrace_dump_prefix_ = DEFAULT_BACKTRACE_DUMP_PREFIX;
  } else {
    backtrace_dump_prefix_ = value;
  }
  return true;
}

bool Config::SetBacktraceSize(const std::string& option, const std::string& value) {
  if (!ParseValue(option, value, 1, SIZE_MAX, &backtrace_min_size_bytes_)) {
    return false;
  }
  backtrace_max_size_bytes_ = backtrace_min_size_bytes_;

  return true;
}

bool Config::SetBacktraceMinSize(const std::string& option, const std::string& value) {
  return ParseValue(option, value, 1, SIZE_MAX, &backtrace_min_size_bytes_);
}

bool Config::SetBacktraceMaxSize(const std::string& option, const std::string& value) {
  return ParseValue(option, value, 1, SIZE_MAX, &backtrace_max_size_bytes_);
}

bool Config::SetExpandAlloc(const std::string& option, const std::string& value) {
  return ParseValue(option, value, DEFAULT_EXPAND_BYTES, 1, MAX_EXPAND_BYTES, &expand_alloc_bytes_);
}

bool Config::SetFreeTrack(const std::string& option, const std::string& value) {
  // This option enables fill on free, so set the bytes to the default value.
  if (fill_on_free_bytes_ == 0) {
    fill_on_free_bytes_ = SIZE_MAX;
  }
  if (free_track_backtrace_num_frames_ == 0) {
    free_track_backtrace_num_frames_ = DEFAULT_BACKTRACE_FRAMES;
  }

  return ParseValue(option, value, DEFAULT_FREE_TRACK_ALLOCATIONS, 1, MAX_FREE_TRACK_ALLOCATIONS,
                    &free_track_allocations_);
}

bool Config::SetFreeTrackBacktraceNumFrames(const std::string& option, const std::string& value) {
  return ParseValue(option, value, DEFAULT_BACKTRACE_FRAMES, 0, MAX_BACKTRACE_FRAMES,
                    &free_track_backtrace_num_frames_);
}

bool Config::SetRecordAllocs(const std::string& option, const std::string& value) {
  if (record_allocs_file_.empty()) {
    record_allocs_file_ = DEFAULT_RECORD_ALLOCS_FILE;
  }
  return ParseValue(option, value, DEFAULT_RECORD_ALLOCS, 1, MAX_RECORD_ALLOCS,
                    &record_allocs_num_entries_);
}

bool Config::SetRecordAllocsFile(const std::string&, const std::string& value) {
  if (value.empty()) {
    // Set the default.
    record_allocs_file_ = DEFAULT_RECORD_ALLOCS_FILE;
    return true;
  }
  record_allocs_file_ = value;
  return true;
}

bool Config::SetRecordAllocsOnExit(const std::string& option, const std::string& value) {
  if (Config::VerifyValueEmpty(option, value)) {
    record_allocs_on_exit_ = true;
    return true;
  }
  return false;
}

bool Config::VerifyValueEmpty(const std::string& option, const std::string& value) {
  if (!value.empty()) {
    // This is not valid.
    error_log("%s: value set for option '%s' which does not take a value", getprogname(),
              option.c_str());
    return false;
  }
  return true;
}

void Config::LogUsage() const {
  error_log("For malloc debug option descriptions go to:");
  error_log(
      "  https://android.googlesource.com/platform/bionic/+/main/libc/malloc_debug/README.md");
}

bool Config::GetOption(const char** options_str, std::string* option, std::string* value) {
  const char* cur = *options_str;
  // Process each property name we can find.
  while (isspace(*cur)) ++cur;

  if (*cur == '\0') {
    *options_str = cur;
    return false;
  }

  const char* start = cur;
  while (!isspace(*cur) && *cur != '=' && *cur != '\0') ++cur;

  *option = std::string(start, cur - start);

  // Skip any spaces after the name.
  while (isspace(*cur)) ++cur;

  value->clear();
  if (*cur == '=') {
    ++cur;
    // Skip the space after the equal.
    while (isspace(*cur)) ++cur;

    start = cur;
    while (!isspace(*cur) && *cur != '\0') ++cur;

    if (cur != start) {
      *value = std::string(start, cur - start);
    }
  }
  *options_str = cur;
  return true;
}

bool Config::Init(const char* options_str) {
  // Initialize a few default values.
  fill_alloc_value_ = DEFAULT_FILL_ALLOC_VALUE;
  fill_free_value_ = DEFAULT_FILL_FREE_VALUE;
  front_guard_value_ = DEFAULT_FRONT_GUARD_VALUE;
  rear_guard_value_ = DEFAULT_REAR_GUARD_VALUE;
  backtrace_signal_ = SIGRTMAX - 19;
  backtrace_dump_signal_ = SIGRTMAX - 17;
  record_allocs_signal_ = SIGRTMAX - 18;
  free_track_backtrace_num_frames_ = 0;
  record_allocs_file_.clear();
  fill_on_free_bytes_ = 0;
  backtrace_enable_on_signal_ = false;
  backtrace_enabled_ = false;
  backtrace_dump_on_exit_ = false;
  backtrace_dump_prefix_ = DEFAULT_BACKTRACE_DUMP_PREFIX;
  backtrace_min_size_bytes_ = 0;
  backtrace_max_size_bytes_ = SIZE_MAX;
  check_unreachable_signal_ = SIGRTMAX - 16;
  log_allocator_stats_signal_ = SIGRTMAX - 15;

  // Process each option name we can find.
  std::string option;
  std::string value;
  bool valid = true;
  while (GetOption(&options_str, &option, &value)) {
    auto entry = kOptions.find(option);
    if (entry == kOptions.end()) {
      error_log("%s: unknown option %s", getprogname(), option.c_str());
      valid = false;
      break;
    }

    const OptionInfo* info = &entry->second;
    auto process_func = info->process_func;
    if (process_func != nullptr && !(this->*process_func)(option, value)) {
      valid = false;
      break;
    }
    options_ |= info->option;
  }

  if (!valid || *options_str != '\0') {
    LogUsage();
    return false;
  }

  return true;
}

"""

```