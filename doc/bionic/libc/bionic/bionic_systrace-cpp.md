Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `bionic_systrace.cpp` file within the Android Bionic library. This involves identifying its purpose, explaining how it works, relating it to Android features, and illustrating its usage and potential issues.

**2. Initial Code Scan and Keyword Identification:**

First, I'd scan the code for key terms and patterns:

* **Includes:**  `errno.h`, `fcntl.h`, `stdio.h`, `stdlib.h`, `string.h`,  `bionic/pthread_internal.h`, `private/bionic_lock.h`, `private/bionic_systrace.h`, `private/bionic_tls.h`, `private/CachedProperty.h`, `async_safe/log.h`, `cutils/trace.h`. These headers suggest interactions with file operations, threading, locking, system properties, thread-local storage, and low-level utilities. The `cutils/trace.h` is a big clue about its tracing functionality.
* **Global Variables:** `g_lock`, `g_debug_atrace_tags_enableflags`, `g_tags`, `g_trace_marker_fd`. These indicate shared state and the use of locking for thread safety. The names strongly suggest a mechanism for enabling/disabling tracing based on tags.
* **Functions:** `should_trace`, `get_trace_marker_fd`, `trace_begin_internal`, `bionic_trace_begin`, `trace_end_internal`, `bionic_trace_end`, `ScopedTrace` (constructor, destructor, `End`). The naming convention clearly indicates tracing related operations.
* **System Calls:**  `open`, `write`. These point to direct interaction with the kernel.
* **Constants:** `WRITE_OFFSET`.
* **Macros:** `TEMP_FAILURE_RETRY`.
* **Thread Local Storage:** The code uses `__get_bionic_tls()` and a `bionic_systrace_disabled` flag within the thread-local storage. This is crucial for preventing recursion.
* **Class:** `ScopedTrace`. This suggests a RAII (Resource Acquisition Is Initialization) approach for managing trace scopes.

**3. Deduce Core Functionality:**

Based on the keywords and structure, the primary function is clearly *system tracing*. The file seems to provide functions to:

* **Check if tracing is enabled:** `should_trace()` by reading a system property.
* **Obtain a file descriptor for the trace marker:** `get_trace_marker_fd()`.
* **Write begin and end trace events to the trace marker:** `trace_begin_internal()`, `trace_end_internal()`.
* **Provide public API for tracing:** `bionic_trace_begin()`, `bionic_trace_end()`, `ScopedTrace`.
* **Handle potential recursion:** Using thread-local storage.

**4. Connect to Android Features:**

The presence of `cutils/trace.h` and the system property `debug.atrace.tags.enableflags` immediately connects this code to Android's system tracing infrastructure (systrace/atrace). The `ATRACE_TAG_BIONIC` macro confirms this file is specifically for tracing within the Bionic library.

**5. Explain Libc Function Implementations:**

The core libc functions used are relatively straightforward:

* `open()`:  Standard libc function for opening files. The explanation would detail the flags (`O_CLOEXEC`, `O_WRONLY`) and the fallback path.
* `write()`: Standard libc function for writing to file descriptors. The explanation should highlight the buffer formatting and the `TEMP_FAILURE_RETRY` macro.
* `strlen()`: Standard libc function to get the length of a string.
* `strtoull()`: Standard libc function to convert a string to an unsigned long long.
* `getpid()`: Standard libc function to get the process ID.

**6. Analyze Dynamic Linker Involvement:**

While this specific file *doesn't directly* implement dynamic linking, it *is part of Bionic*, which includes the dynamic linker. Therefore, it's important to explain the context:

* **How this code might be used in a dynamically linked context:** The `bionic_trace_begin` and `bionic_trace_end` functions are likely exported symbols, meaning other shared libraries (``.so`` files) can call them.
* **Illustrate a simple shared library layout:** Show how the tracing functions would reside within `.text` and how symbols are resolved.
* **Describe the linking process conceptually:** How the dynamic linker resolves symbols at runtime.

**7. Logical Reasoning and Examples:**

* **Assumptions and Outputs:**  Consider scenarios like tracing being enabled or disabled, and how the output would look in the trace buffer.
* **User Errors:** Focus on common mistakes like forgetting to end a trace scope or misinterpreting the output.

**8. Android Framework and NDK Connection:**

* **Framework:** Explain how system services and higher-level Android components might indirectly trigger Bionic functions that use tracing.
* **NDK:** Show how an NDK developer can directly use Bionic tracing functions.

**9. Frida Hook Examples:**

Provide practical Frida code snippets to demonstrate how to intercept and observe the key functions, showing the arguments and return values.

**10. Structure and Refinement:**

Organize the information logically using headings and bullet points for clarity. Use clear and concise language, avoiding overly technical jargon where possible. Review and refine the explanation for accuracy and completeness. For example, initially, I might have focused too much on the locking mechanism without fully explaining the thread-local storage's role in preventing recursion. A review would highlight this missing piece. Similarly, I would ensure the dynamic linker explanation is contextual and doesn't misrepresent the file's direct involvement.

By following this systematic approach, combining code analysis with understanding of the broader Android ecosystem, a comprehensive and accurate explanation can be generated.
好的，让我们来详细分析 `bionic/libc/bionic/bionic_systrace.cpp` 这个文件。

**功能概述**

`bionic_systrace.cpp` 文件的主要功能是为 Android Bionic 库提供系统跟踪 (systrace) 的支持。它允许 Bionic 库内部的关键操作生成跟踪事件，这些事件可以被 `systrace` 工具捕获和分析，帮助开发者了解 Bionic 库的运行行为，进行性能分析和调试。

**与 Android 功能的关系和举例**

这个文件直接关联到 Android 的性能监控和调试功能。`systrace` 是 Android 平台提供的一种强大的性能分析工具，它可以记录内核活动、服务调用、应用程序操作等信息。`bionic_systrace.cpp` 的作用是让 Bionic 库本身也成为 `systrace` 的一个信息来源。

**举例说明：**

* **跟踪锁的竞争:** Bionic 库中使用了大量的锁来保证线程安全。通过 `bionic_systrace.cpp` 提供的接口，可以在加锁和解锁的关键代码段添加跟踪事件。例如，当多个线程竞争同一个锁时，`systrace` 可以显示出哪个线程等待了多长时间，从而帮助开发者发现潜在的性能瓶颈。
* **跟踪内存分配和释放:** Bionic 库负责管理进程的内存。通过跟踪内存分配 (`malloc`) 和释放 (`free`) 等操作，可以帮助开发者分析内存使用情况，发现内存泄漏等问题。
* **跟踪系统调用:** Bionic 库是对 Linux 系统调用的封装。跟踪系统调用的入口和出口，可以帮助理解 Bionic 库如何与内核交互。例如，跟踪 `open()`、`read()`、`write()` 等系统调用，可以了解文件 I/O 的性能。

**libc 函数的功能和实现**

让我们逐个解释代码中使用的 libc 函数：

1. **`open(const char *pathname, int flags, ...)`:**
   * **功能:** 打开一个文件描述符。
   * **实现:**  这是一个系统调用的封装。它会调用底层的 Linux 内核的 `open` 系统调用。内核会根据 `pathname` 查找文件，根据 `flags` 设置打开模式（例如只读 `O_RDONLY`，只写 `O_WRONLY`，读写 `O_RDWR`），并返回一个非负的文件描述符，如果出错则返回 -1 并设置 `errno`。
   * **本文件中的使用:**  `get_trace_marker_fd()` 函数使用 `open()` 打开 `/sys/kernel/tracing/trace_marker` 或 `/sys/kernel/debug/tracing/trace_marker` 文件。这两个文件是 Linux ftrace 功能提供的接口，用于向内核的跟踪缓冲区写入数据。`O_CLOEXEC` 标志确保了子进程不会继承这个文件描述符，`O_WRONLY` 表示以只写模式打开。

2. **`write(int fd, const void *buf, size_t count)`:**
   * **功能:** 向一个打开的文件描述符写入数据。
   * **实现:**  这是一个系统调用的封装。它会调用底层的 Linux 内核的 `write` 系统调用。内核会将 `buf` 指向的 `count` 个字节的数据写入到文件描述符 `fd` 对应的文件中。成功时返回实际写入的字节数，出错时返回 -1 并设置 `errno`。
   * **本文件中的使用:** `trace_begin_internal()` 和 `trace_end_internal()` 函数使用 `write()` 将跟踪信息写入到 trace marker 文件描述符中。写入的内容是格式化的字符串，用于标识跟踪事件的开始和结束。

3. **`strlen(const char *s)`:**
   * **功能:** 计算字符串的长度，不包括结尾的空字符 `\0`。
   * **实现:**  通常通过循环遍历字符串，直到遇到空字符为止，并返回遍历的次数。
   * **本文件中的使用:** `trace_begin_internal()` 函数使用 `strlen()` 计算消息字符串的长度，以便分配足够大的缓冲区来格式化跟踪信息。

4. **`strtoull(const char *nptr, char **endptr, int base)`:**
   * **功能:** 将字符串转换为无符号长长整型数 (unsigned long long)。
   * **实现:**  会跳过字符串开头的空白字符，然后根据指定的 `base`（例如 10 表示十进制，16 表示十六进制）将字符串中的数字字符转换为 `unsigned long long` 类型的值。如果 `endptr` 不为空，它会指向转换停止的字符。
   * **本文件中的使用:** `should_trace()` 函数使用 `strtoull()` 将系统属性 `debug.atrace.tags.enableflags` 的字符串值转换为一个 64 位的整数，用于判断是否启用了 Bionic 的跟踪。

5. **`getpid(void)`:**
   * **功能:** 获取当前进程的进程 ID。
   * **实现:**  这是一个系统调用的封装，直接调用底层的 Linux 内核的 `getpid` 系统调用。
   * **本文件中的使用:** `trace_begin_internal()` 函数使用 `getpid()` 获取当前进程的 ID，并将其包含在写入 trace marker 的信息中。

**dynamic linker 的功能和链接处理过程**

虽然 `bionic_systrace.cpp` 本身不直接实现 dynamic linker 的功能，但它是 Bionic 库的一部分，而 Bionic 库就包含了 dynamic linker (`linker64` 或 `linker`)。这个文件中的函数很可能会被其他动态链接的库调用。

**so 布局样本：**

假设有一个名为 `libmylib.so` 的动态链接库，它使用了 `bionic_systrace.cpp` 中定义的 `bionic_trace_begin` 和 `bionic_trace_end` 函数：

```
libmylib.so:
    .text:  # 存放代码段
        ...
        call bionic_trace_begin  # 调用 Bionic 库中的函数
        ...
        call bionic_trace_end    # 调用 Bionic 库中的函数
        ...
    .rodata: # 存放只读数据
        trace_message: .string "MyLib Function Called"
        ...
    .data:  # 存放可写数据
        ...
    .bss:   # 存放未初始化的数据
        ...
    .dynsym: # 动态符号表，包含导入和导出的符号
        bionic_trace_begin (EXTERNAL)
        bionic_trace_end   (EXTERNAL)
        ...
    .dynstr: # 动态字符串表，存储符号名称
        bionic_trace_begin
        bionic_trace_end
        ...
    .plt:   # Procedure Linkage Table，用于延迟绑定
        entry for bionic_trace_begin
        entry for bionic_trace_end
        ...
    .got:   # Global Offset Table，用于存储外部符号的地址
        entry for bionic_trace_begin
        entry for bionic_trace_end
        ...
```

**链接的处理过程：**

1. **编译时：** 编译 `libmylib.so` 时，编译器会识别出对 `bionic_trace_begin` 和 `bionic_trace_end` 的外部引用。这些符号在 `libmylib.so` 的 `.dynsym` 和 `.dynstr` 中被标记为外部符号。
2. **加载时：** 当 Android 系统加载 `libmylib.so` 时，dynamic linker (例如 `/system/bin/linker64`) 会执行以下操作：
   * **查找依赖库：**  `libmylib.so` 依赖于 Bionic 库（通常是 `libc.so`）。dynamic linker 会加载 `libc.so` 到内存中。
   * **符号解析：** dynamic linker 会遍历 `libmylib.so` 的 `.rel.dyn` 或 `.rel.plt` 重定位表，找到所有对外部符号的引用，例如 `bionic_trace_begin` 和 `bionic_trace_end`。
   * **查找符号定义：** dynamic linker 会在 `libc.so` 的动态符号表中查找这些符号的定义。由于 `bionic_trace_begin` 和 `bionic_trace_end` 是 `libc.so` 导出的符号，dynamic linker 会找到它们的地址。
   * **重定位：** dynamic linker 会修改 `libmylib.so` 的 `.got` (Global Offset Table) 中的相应条目，将 `bionic_trace_begin` 和 `bionic_trace_end` 的实际内存地址填入。
   * **PLT (Procedure Linkage Table)：**  通常情况下，会使用 PLT 进行延迟绑定。第一次调用 `bionic_trace_begin` 或 `bionic_trace_end` 时，会先跳转到 PLT 中的一个桩代码，这个桩代码会调用 dynamic linker 来解析符号并更新 GOT 表。后续的调用将直接通过 GOT 表跳转到实际的函数地址，避免了重复的符号解析。

**假设输入与输出 (针对 tracing 功能)**

**假设输入：**

1. 系统属性 `debug.atrace.tags.enableflags` 设置为包含 `ATRACE_TAG_BIONIC` 的值（例如，如果 `ATRACE_TAG_BIONIC` 是 1，则可以设置为 1 或包含 1 的其他位掩码值）。
2. 代码中调用了 `bionic_trace_begin("my_function_entry")` 和 `bionic_trace_end()`。

**预期输出 (在 systrace 日志中)：**

```
<进程ID>  [<线程ID>] B| <进程ID> |my_function_entry
<进程ID>  [<线程ID>] E|
```

* `<进程ID>`:  调用 `bionic_trace_begin` 和 `bionic_trace_end` 的进程 ID。
* `<线程ID>`:  调用 `bionic_trace_begin` 和 `bionic_trace_end` 的线程 ID。
* `B|`:  表示一个跟踪事件的开始。
* `E|`:  表示一个跟踪事件的结束。
* `my_function_entry`:  传递给 `bionic_trace_begin` 的消息。

**用户或编程常见的使用错误**

1. **忘记调用 `bionic_trace_end` 或 `ScopedTrace` 的析构函数没有被执行：** 这会导致跟踪事件不完整，`systrace` 工具可能会显示不匹配的开始和结束事件。

   ```c++
   void my_function() {
       bionic_trace_begin("my_function");
       // ... 执行一些操作 ...
       // 忘记调用 bionic_trace_end();  <-- 错误
   }

   // 或者

   void my_function_with_scope() {
       ScopedTrace trace("my_function_with_scope");
       // ... 执行一些操作 ...
       // 如果在作用域结束前抛出异常，且没有捕获，析构函数可能不会被执行
   }
   ```

2. **在 `bionic_trace_begin` 和 `bionic_trace_end` 之间执行耗时操作，但没有细粒度的跟踪：** 这会导致 `systrace` 中只有一个大的时间段，无法了解内部的细节。应该在关键的操作前后添加更多的 `bionic_trace_begin` 和 `bionic_trace_end` 调用。

3. **错误地设置或理解 `debug.atrace.tags.enableflags`：** 如果该属性没有正确设置，或者不包含 `ATRACE_TAG_BIONIC`，那么 `bionic_trace_begin` 和 `bionic_trace_end` 将不会产生任何输出。

4. **在中断上下文或不允许阻塞的环境中调用 `bionic_trace_begin` 或 `bionic_trace_end`：** 虽然代码中使用了 `async_safe_format_buffer` 和 `TEMP_FAILURE_RETRY`，但仍然应该避免在严格不允许阻塞的环境中调用这些函数，因为内部可能涉及锁操作。

**Android Framework 或 NDK 如何到达这里**

**Android Framework 到 `bionic_systrace.cpp` 的路径：**

1. **Framework 组件调用 Bionic 库函数：** Android Framework 中的各种服务（例如 ActivityManagerService、WindowManagerService）或应用进程会调用 Bionic 库提供的函数，例如内存分配、文件操作、线程管理等。
2. **Bionic 库函数内部的 tracing 调用：** 在 Bionic 库的关键函数内部，会插入对 `bionic_trace_begin` 和 `bionic_trace_end` 的调用。
3. **检查 tracing 是否启用：** `bionic_trace_begin` 内部会调用 `should_trace()` 检查系统属性 `debug.atrace.tags.enableflags`。
4. **写入 trace marker：** 如果 tracing 被启用，相关信息会被格式化并写入到 `/sys/kernel/tracing/trace_marker` 或 `/sys/kernel/debug/tracing/trace_marker`。
5. **`systrace` 工具捕获事件：** 当 `systrace` 工具运行时，它会读取内核的 ftrace 缓冲区，并将这些事件呈现给开发者。

**NDK 到 `bionic_systrace.cpp` 的路径：**

1. **NDK 代码调用 Bionic 库函数：** 使用 NDK 开发的 C/C++ 代码可以直接调用 Bionic 库提供的函数。
2. **NDK 代码显式调用 `bionic_trace_begin` 和 `bionic_trace_end`：** NDK 开发者也可以直接在他们的代码中调用 `bionic_trace_begin` 和 `bionic_trace_end` 来添加自定义的跟踪事件。这需要包含 `<bionic/systrace.h>` 头文件。

   ```c++
   #include <bionic/systrace.h>

   void my_ndk_function() {
       BIONIC_TRACE_BEGIN("my_ndk_function"); // 使用宏
       // ... 执行 NDK 代码 ...
       BIONIC_TRACE_END(); // 使用宏
   }
   ```

**Frida Hook 示例调试步骤**

假设你想 hook `bionic_trace_begin` 函数，查看它接收到的消息参数：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "bionic_trace_begin"), {
    onEnter: function(args) {
        var message = Memory.readUtf8String(args[0]);
        send({"type": "trace", "message": "bionic_trace_begin called", "arg0": message});
        console.log("[bionic_trace_begin] message: " + message);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "bionic_trace_end"), {
    onEnter: function(args) {
        send({"type": "trace", "message": "bionic_trace_end called"});
        console.log("[bionic_trace_end]");
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤解释：**

1. **导入 Frida 库：** 导入 `frida` 和 `sys` 库。
2. **指定目标应用包名：** 将 `package_name` 替换为你要调试的 Android 应用的包名。
3. **连接到设备和进程：** 使用 `frida.get_usb_device().attach(package_name)` 连接到 USB 连接的 Android 设备，并附加到目标应用的进程。
4. **编写 Frida Script：**
   * **`Interceptor.attach`：** 使用 `Interceptor.attach` 函数来 hook `libc.so` 中的 `bionic_trace_begin` 和 `bionic_trace_end` 函数。
   * **`Module.findExportByName`：**  找到 `libc.so` 库中名为 `bionic_trace_begin` 和 `bionic_trace_end` 的导出函数。
   * **`onEnter` 回调：**  定义在函数入口处执行的回调函数。
     * **`bionic_trace_begin` 的 hook：**
       * `args[0]` 包含了 `bionic_trace_begin` 的第一个参数，即消息字符串的指针。
       * `Memory.readUtf8String(args[0])` 读取该指针指向的 UTF-8 字符串。
       * `send()` 函数将消息发送回 Frida 主机。
       * `console.log()` 将消息打印到 Frida 的控制台。
     * **`bionic_trace_end` 的 hook：**
       * 简单地发送一个消息表示该函数被调用。
5. **创建和加载 Script：** 使用 `session.create_script()` 创建 Frida Script，并使用 `script.load()` 加载它到目标进程。
6. **处理消息：** `script.on('message', on_message)` 注册一个消息处理函数，用于接收来自 Script 的消息并打印出来。
7. **保持脚本运行：** `sys.stdin.read()` 阻止脚本退出，直到用户在终端中输入内容。

**运行 Frida 脚本的步骤：**

1. 确保你的 Android 设备已连接到电脑，并且 adb 可用。
2. 确保你的电脑上安装了 Frida 和 frida-tools (`pip install frida-tools`).
3. 运行你要调试的 Android 应用。
4. 将上面的 Python 代码保存为例如 `hook_systrace.py`。
5. 在终端中运行 `python hook_systrace.py`。

当目标应用调用 `bionic_trace_begin` 和 `bionic_trace_end` 时，Frida 脚本会拦截这些调用，并将相关信息打印到你的终端。你将看到类似如下的输出：

```
[*] Received: {'type': 'trace', 'message': 'bionic_trace_begin called', 'arg0': 'my_function_entry'}
[bionic_trace_begin] message: my_function_entry
[*] Received: {'type': 'trace', 'message': 'bionic_trace_end called'}
[bionic_trace_end]
```

这个 Frida 示例可以帮助你动态地观察 `bionic_systrace.cpp` 中函数的行为，验证你的理解，并进行更深入的调试。

Prompt: 
```
这是目录为bionic/libc/bionic/bionic_systrace.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bionic/pthread_internal.h"
#include "private/bionic_lock.h"
#include "private/bionic_systrace.h"
#include "private/bionic_tls.h"
#include "private/CachedProperty.h"

#include <async_safe/log.h>
#include <cutils/trace.h> // For ATRACE_TAG_BIONIC.

#define WRITE_OFFSET   32

static Lock g_lock;
static CachedProperty g_debug_atrace_tags_enableflags("debug.atrace.tags.enableflags");
static uint64_t g_tags;
static int g_trace_marker_fd = -1;

static bool should_trace() {
  g_lock.lock();
  if (g_debug_atrace_tags_enableflags.DidChange()) {
    g_tags = strtoull(g_debug_atrace_tags_enableflags.Get(), nullptr, 0);
  }
  g_lock.unlock();
  return ((g_tags & ATRACE_TAG_BIONIC) != 0);
}

static int get_trace_marker_fd() {
  g_lock.lock();
  if (g_trace_marker_fd == -1) {
    g_trace_marker_fd = open("/sys/kernel/tracing/trace_marker", O_CLOEXEC | O_WRONLY);
    if (g_trace_marker_fd == -1) {
      g_trace_marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_CLOEXEC | O_WRONLY);
    }
  }
  g_lock.unlock();
  return g_trace_marker_fd;
}

static void trace_begin_internal(const char* message) {
  if (!should_trace()) {
    return;
  }

  int trace_marker_fd = get_trace_marker_fd();
  if (trace_marker_fd == -1) {
    return;
  }

  // If bionic tracing has been enabled, then write the message to the
  // kernel trace_marker.
  int length = strlen(message);
  char buf[length + WRITE_OFFSET];
  size_t len = async_safe_format_buffer(buf, length + WRITE_OFFSET, "B|%d|%s", getpid(), message);

  // Tracing may stop just after checking property and before writing the message.
  // So the write is acceptable to fail. See b/20666100.
  TEMP_FAILURE_RETRY(write(trace_marker_fd, buf, len));
}

void bionic_trace_begin(const char* message) {
  // Some functions called by trace_begin_internal() can call
  // bionic_trace_begin(). Prevent infinite recursion and non-recursive mutex
  // deadlock by using a flag in the thread local storage.
  bionic_tls& tls = __get_bionic_tls();
  if (tls.bionic_systrace_disabled) {
    return;
  }
  tls.bionic_systrace_disabled = true;

  trace_begin_internal(message);

  tls.bionic_systrace_disabled = false;
}

static void trace_end_internal() {
  if (!should_trace()) {
    return;
  }

  int trace_marker_fd = get_trace_marker_fd();
  if (trace_marker_fd == -1) {
    return;
  }

  // This code is intentionally "sub-optimal"; do not optimize this by inlining
  // the E| string into the write.
  //
  // This is because if the const char* string passed to write(trace_marker) is not
  // in resident memory (e.g. the page of the .rodata section that contains it has
  // been paged out, or the anonymous page that contained a heap-based string is
  // swapped in zram), the ftrace code will NOT page it in and instead report
  // <faulted>.
  //
  // We "fix" this by putting the string on the stack, which is more unlikely
  // to be paged out and pass the pointer to that instead.
  //
  // See b/197620214 for more context on this.
  volatile char buf[2]{'E', '|'};
  TEMP_FAILURE_RETRY(write(trace_marker_fd, const_cast<const char*>(buf), 2));
}

void bionic_trace_end() {
  // Some functions called by trace_end_internal() can call
  // bionic_trace_begin(). Prevent infinite recursion and non-recursive mutex
  // deadlock by using a flag in the thread local storage.
  bionic_tls& tls = __get_bionic_tls();
  if (tls.bionic_systrace_disabled) {
    return;
  }
  tls.bionic_systrace_disabled = true;

  trace_end_internal();

  tls.bionic_systrace_disabled = false;
}

ScopedTrace::ScopedTrace(const char* message) : called_end_(false) {
  bionic_trace_begin(message);
}

ScopedTrace::~ScopedTrace() {
  End();
}

void ScopedTrace::End() {
  if (!called_end_) {
    bionic_trace_end();
    called_end_ = true;
  }
}

"""

```