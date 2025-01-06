Response:
Let's break down the thought process for analyzing the `RecordData.cpp` file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `RecordData.cpp` file within the context of Android's bionic library. This involves understanding its functionality, its role within Android, its interaction with other parts of the system (especially the dynamic linker and libc), common usage errors, and debugging techniques.

**2. Initial Code Scan & High-Level Understanding:**

First, I'd quickly read through the code to get a general idea of what it does. Keywords like "record_allocs", "memory_trace", "WriteEntries", "ThreadKeyDelete", and the use of mutexes and thread-local storage (pthread_key) stand out. This suggests the code is involved in recording memory allocation events, likely for debugging purposes.

**3. Identifying Key Components and Functionality:**

I'd then focus on identifying the core components and their roles:

* **`RecordData` class:** This is the central class. It manages the recording process. It holds the buffer for entries, the file to write to, and synchronization mechanisms.
* **`ThreadData` struct:**  This appears to be used to manage per-thread data related to recording. The `count` member and the logic in `ThreadKeyDelete` suggest it handles some lifecycle management related to threads.
* **`memory_trace::Entry` struct:**  This likely defines the structure of a single memory allocation record. The `type` member suggests different kinds of events are recorded.
* **`InternalReserveEntry()` and `ReserveEntry()`:** These are clearly the mechanisms for obtaining a slot to store a memory allocation record. The difference between them is likely related to thread-local storage.
* **`WriteEntries()`:** This function handles writing the recorded entries to a file.
* **`ThreadKeyDelete()`:** This function is called when a thread-specific key is deleted, indicating thread exit.
* **Signal Handling (`WriteData()`):** The `WriteData` function is a signal handler, indicating a way to trigger the dumping of the recorded data on demand.

**4. Analyzing Each Function in Detail:**

Next, I'd go through each function and understand its exact behavior:

* **`ThreadKeyDelete()`:** The critical insight here is the double `pthread_setspecific`. The first call is likely a "retry" mechanism if the thread is being reused. The `count == 4` check is a bit unusual and suggests some specific lifecycle management within the recording system. The important part is recording the `THREAD_DONE` event upon actual thread exit.
* **`WriteData()`:**  Straightforward signal handler - just calls `WriteEntries()`. The comment about not allocating is important.
* **`WriteEntriesOnExit()`:**  This is called at program exit, ensuring the data is written. Appending the PID to the filename prevents conflicts in multi-process scenarios.
* **`WriteEntries(const std::string& file)`:** Handles the actual file writing. Includes error handling and iterates through the recorded entries. The skipping of `UNKNOWN` entries is important.
* **`RecordData()`:** Initializes the thread-specific key.
* **`Initialize()`:** Sets up the signal handler, initializes the entry buffer, and logs a helpful message.
* **`~RecordData()`:** Destroys the thread-specific key.
* **`InternalReserveEntry()`:**  Reserves a slot in the buffer, handling buffer overflow.
* **`ReserveEntry()`:**  Gets or creates the thread-local data and then calls `InternalReserveEntry()`. This is where the per-thread recording context is managed.

**5. Connecting to Android Functionality:**

Now, I'd start connecting the dots to Android's functionality:

* **Memory Debugging:** The core function is clearly related to debugging memory allocation issues. This is a crucial part of Android development.
* **`bionic` and `libc`:** This file is part of `bionic`, Android's C library. This means it's deeply integrated into the system's core functionalities, especially memory management.
* **NDK:** NDK applications use `bionic` for memory allocation, so this code directly impacts them.
* **Framework:** The Android Framework relies on `bionic` as well.

**6. Considering Dynamic Linker Interactions:**

While this specific file doesn't directly perform dynamic linking, it *benefits* from it. The `memory_trace` library and other dependencies are likely loaded using the dynamic linker. I'd explain this indirect relationship and provide a basic SO layout example.

**7. Thinking About User Errors and Assumptions:**

I'd consider how developers might misuse this system (even indirectly):

* **Not triggering the dump:**  If the signal isn't sent or the application exits normally before the signal, the data might be lost (though `WriteEntriesOnExit` helps here).
* **Performance impact:**  Continuously recording allocations can have a performance overhead.
* **File I/O issues:** Permissions problems or disk space limitations can prevent the file from being written.

**8. Developing a Frida Hook Example:**

To demonstrate debugging, a Frida hook would be very useful. I'd choose a key function like `RecordData::ReserveEntry` to intercept and log when a new allocation is being recorded. This shows how to inspect the data being collected.

**9. Structuring the Response:**

Finally, I'd structure the response logically, starting with a summary of functionality, then detailed explanations of each component, connections to Android, dynamic linker aspects, user errors, and the Frida example. Using clear headings and bullet points makes the information easier to digest.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This might be directly involved in malloc/free interception."  **Correction:** While related to memory allocation, the code seems to *record* events rather than *intercepting* the core malloc/free calls directly. It's more of a post-event recording mechanism.
* **Initial thought:** "The `count == 4` in `ThreadKeyDelete` is arbitrary." **Refinement:** It's likely related to the pthread key deletion process. The thread might go through several stages of cleanup, and this ensures the record is only made on the final, "true" exit.
* **Consideration:**  "How does the data get *used*?"  While the file doesn't show the *analysis* of the recorded data, it's important to mention that this data is likely used by other tools for memory leak detection, profiling, etc.

By following this structured approach, combining code analysis with contextual knowledge of Android and debugging techniques, I can generate a comprehensive and accurate response to the request.
这个 `RecordData.cpp` 文件是 Android bionic 库中 `malloc_debug` 组件的一部分。它的主要功能是**记录内存分配和释放的事件信息，用于调试目的，例如检测内存泄漏和悬挂指针。**

**功能列举:**

1. **记录内存事件:** 记录诸如内存分配 (`malloc`)、释放 (`free`) 以及线程创建和销毁等事件。
2. **线程局部存储:** 使用 `pthread_key_create` 和 `pthread_setspecific` 来管理每个线程的记录状态，确保线程安全。
3. **事件缓冲:**  使用一个 `std::vector<memory_trace::Entry>` 类型的缓冲区 `entries_` 来存储记录的事件。
4. **写入记录到文件:**  提供将记录的事件写入文件的功能。文件名可以通过配置指定。
5. **信号处理:** 注册一个信号处理函数 (`WriteData`)，允许用户通过发送特定信号来触发将当前记录的事件写入文件。
6. **程序退出时写入:**  注册一个在程序退出时执行的函数 (`WriteEntriesOnExit`)，确保在程序结束前将所有记录的事件写入文件。
7. **防止多进程冲突:** 在写入文件时，会将进程 ID (PID) 添加到文件名中，以避免多个进程同时写入同一个文件导致数据损坏。
8. **内部互斥锁:** 使用 `std::mutex` `entries_lock_` 来保护对事件缓冲区 `entries_` 的并发访问。

**与 Android 功能的关系及举例说明:**

这个文件直接参与了 Android 系统级别的内存调试。 当开发者或系统需要追踪内存分配行为时，`malloc_debug` 组件可以被启用。

**举例说明:**

* **内存泄漏检测:**  如果一个 Android 应用存在内存泄漏，即分配的内存没有被正确释放，`RecordData` 记录的分配和释放事件可以被分析，找出哪些内存被分配了但没有被释放。
* **悬挂指针调试:**  如果程序尝试访问已经被释放的内存（悬挂指针），`RecordData` 可以记录内存释放的事件，帮助开发者定位错误发生的位置。
* **性能分析:**  记录内存分配的大小和时间，可以帮助开发者分析应用的内存使用模式，优化性能。

**libc 函数的功能实现:**

* **`pthread_key_create(&key_, ThreadKeyDelete);`:**  这个函数在 `RecordData` 的构造函数中被调用。它创建一个线程特定的数据键 `key_`，并指定一个析构函数 `ThreadKeyDelete`。这意味着每个线程都可以拥有与这个键关联的私有数据，并且当线程退出时，`ThreadKeyDelete` 会被调用来清理这些数据。

   **`ThreadKeyDelete(void* data)` 的实现:**
   1. 将传入的 `data` 转换为 `ThreadData*` 类型。
   2. 递增 `thread_data->count`。这个 `count` 似乎用于控制 `ThreadKeyDelete` 被调用的次数。
   3. 当 `thread_data->count` 等于 4 时，它会执行以下操作：
      * 创建一个 `ScopedDisableDebugCalls` 对象，这很可能用于禁用调试相关的调用，防止递归调用。
      * 调用 `thread_data->record_data->InternalReserveEntry()` 尝试预留一个内存跟踪条目。
      * 如果预留成功，则填充该条目，记录线程结束事件 (`memory_trace::THREAD_DONE`) 和结束时间。
      * 删除 `thread_data` 对象。
   4. 如果 `thread_data->count` 不等于 4，它会再次将 `data` 设置回线程特定的键，这可能是一种重试机制，确保在线程真正退出时记录事件。

* **`pthread_setspecific(key_, nullptr);`:** 在 `RecordData::Initialize` 中被调用。它将当前线程与 `key_` 关联的线程特定数据设置为 `nullptr`。这通常用于初始化线程的记录状态。

* **`gettid()`:**  获取当前线程的 ID。用于在记录的事件中标识发生事件的线程。

* **`open(file.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0755)`:** 在 `RecordData::WriteEntries` 中被调用。用于打开或创建用于写入内存分配记录的文件。
    * `O_WRONLY`: 以只写模式打开文件。
    * `O_CREAT`: 如果文件不存在则创建文件。
    * `O_TRUNC`: 如果文件存在则将其截断为零长度。
    * `O_CLOEXEC`:  设置 close-on-exec 标志，防止子进程继承该文件描述符。
    * `O_NOFOLLOW`: 如果路径名是一个符号链接，则打开操作失败。
    * `0755`: 设置创建文件的权限为所有者读/写/执行，组和其他用户读/执行。

* **`strerror(errno)`:**  在文件操作失败时被调用，用于获取与 `errno` 相关的错误描述字符串。

* **`close(dump_fd)`:**  关闭打开的文件描述符。

* **`sigaction64(config.record_allocs_signal(), &dump_act, nullptr)`:** 在 `RecordData::Initialize` 中被调用。用于注册一个信号处理函数。
    * `config.record_allocs_signal()`:  指定要捕获的信号，例如 `SIGUSR1` 或 `SIGUSR2`。
    * `&dump_act`:  指向 `sigaction64` 结构体的指针，该结构体包含了信号处理函数 (`RecordData::WriteData`) 和标志。
    * `SA_RESTART`:  如果信号中断了某个系统调用，则尝试重新启动该系统调用。
    * `SA_SIGINFO`:  表示信号处理函数使用三个参数的版本 (`WriteData` 的签名)。
    * `SA_ONSTACK`:  在备用信号栈上执行信号处理函数。

**涉及 dynamic linker 的功能及处理过程:**

虽然 `RecordData.cpp` 本身没有直接涉及动态链接的过程，但它所依赖的库（例如 `libmemory_trace.so`，通过 `#include <memory_trace/MemoryTrace.h>` 引入）是由 dynamic linker 加载的。

**so 布局样本:**

假设 `libmemory_trace.so` 是一个独立的共享库，它的布局可能如下：

```
地址范围        | 内容
----------------|------------------------------------
0xXXXXXXXX000 | ELF Header
0xXXXXXXXX100 | Program Headers (描述内存段)
0xXXXXXXXX200 | Section Headers (描述节)
...             | .text (代码段) - memory_trace 的函数代码
...             | .rodata (只读数据段)
...             | .data (已初始化数据段)
...             | .bss (未初始化数据段)
...             | .dynsym (动态符号表)
...             | .dynstr (动态字符串表)
...             | .rel.dyn (重定位信息 - 数据)
...             | .rel.plt (重定位信息 - 函数)
```

**链接的处理过程:**

1. **加载:** 当程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 根据可执行文件的依赖关系，找到 `libmemory_trace.so`。
2. **查找:** dynamic linker 在预定义的路径（例如 `/system/lib64`, `/vendor/lib64` 等）中查找 `libmemory_trace.so` 文件。
3. **加载到内存:**  将 `libmemory_trace.so` 的各个段（代码段、数据段等）加载到内存中的合适地址。为了安全性和效率，通常会使用地址空间布局随机化 (ASLR)。
4. **符号解析:**  `RecordData.cpp` 中调用了 `memory_trace::Entry` 和 `memory_trace::WriteEntryToFd` 等符号。dynamic linker 会在 `libmemory_trace.so` 的 `.dynsym` 和 `.dynstr` 中查找这些符号的定义。
5. **重定位:**  由于共享库加载的地址可能每次都不同，dynamic linker 需要修改代码和数据中的地址引用，使其指向正确的内存位置。`.rel.dyn` 和 `.rel.plt` 节包含了重定位所需的信息。例如，对 `memory_trace::Entry` 的引用可能需要更新为 `libmemory_trace.so` 中 `Entry` 结构体的实际地址。对 `memory_trace::WriteEntryToFd` 函数的调用需要通过过程链接表 (PLT) 和全局偏移表 (GOT) 进行间接跳转，dynamic linker 会在 GOT 中填入函数的实际地址。
6. **绑定:**  完成重定位后，程序就可以正确地调用 `libmemory_trace.so` 中定义的函数和访问其数据。

**假设输入与输出 (逻辑推理):**

假设开启了内存分配记录功能，并且设置了记录到文件 `/data/local/tmp/alloc_records.txt`。

**假设输入:**

1. 程序启动并分配了一些内存 (`malloc(10)`, `malloc(20)`)。
2. 其中一块内存被释放 (`free(ptr1)`)。
3. 用户发送了 `SIGUSR1` 信号给该进程。
4. 程序继续运行并分配了更多内存。
5. 程序正常退出。

**预期输出:**

`/data/local/tmp/alloc_records.txt.<pid>` 文件（`<pid>` 是进程 ID）中会包含类似以下的记录（`memory_trace::Entry` 的具体格式取决于实现）：

```
{ tid: <thread_id_1>, type: MALLOC, ptr: 0x..., size: 10, time: <timestamp> }
{ tid: <thread_id_1>, type: MALLOC, ptr: 0x..., size: 20, time: <timestamp> }
{ tid: <thread_id_1>, type: FREE,   ptr: 0x...,               time: <timestamp> }
```

当收到 `SIGUSR1` 信号时，会触发 `WriteData`，将当前缓冲区的内容写入文件。程序退出时，`WriteEntriesOnExit` 会再次将剩余的记录写入文件。因此，最终的文件会包含所有分配和释放事件的记录。

**用户或编程常见的使用错误:**

1. **未初始化 `RecordData`:** 如果 `RecordData::Initialize` 没有被正确调用，记录功能将不会启用。
2. **配置文件错误:** 如果 `Config` 对象中的配置（例如记录文件名，信号量）配置不正确，可能导致记录无法写入文件或无法通过信号触发。
3. **文件权限问题:** 如果程序没有写入目标目录的权限，`open` 函数会失败。
4. **缓冲区溢出:** 虽然代码中会检查缓冲区是否已满，但如果记录的事件过多，可能会丢失部分事件。
5. **信号冲突:**  使用的信号量可能与其他信号处理程序冲突。
6. **多线程竞争:**  虽然使用了互斥锁，但如果在使用记录的数据时没有进行适当的同步，可能会出现数据竞争。

**Android framework or ndk 是如何一步步的到达这里:**

1. **Framework/NDK 代码调用 `malloc` 等函数:**  无论是 Java Framework 代码通过 JNI 调用 Native 代码，还是 NDK 应用直接调用 C/C++ 标准库函数，最终都会调用到 bionic 库提供的 `malloc`、`free` 等内存分配函数。
2. **`malloc` 的实现:** bionic 的 `malloc` 实现（例如 `dlmalloc` 或 `scudo`）可能会集成或hook `malloc_debug` 的功能。
3. **条件启用 `malloc_debug`:**  `malloc_debug` 的功能通常不是默认启用的，可能需要通过系统属性、环境变量或开发者选项来开启。
4. **`RecordData::Initialize` 的调用:**  当 `malloc_debug` 被启用时，系统的初始化代码或者 `malloc` 的实现可能会调用 `RecordData::Initialize` 来初始化记录机制。`Config` 对象会从系统属性或环境变量中读取配置信息。
5. **内存事件记录:** 当 `malloc` 或 `free` 被调用时，如果 `malloc_debug` 处于活动状态，相关的事件信息会被添加到当前线程的 `RecordData` 缓冲区中。
6. **触发数据写入:** 可以通过发送预先配置的信号（例如 `kill -s SIGUSR1 <pid>`）来触发 `RecordData::WriteData` 函数，将缓冲区的内容写入文件。或者在程序退出时，`RecordData::WriteEntriesOnExit` 会被调用。

**Frida hook 示例调试步骤:**

假设你想观察何时有新的内存分配事件被记录到缓冲区。你可以 hook `RecordData::InternalReserveEntry` 函数。

```python
import frida
import sys

package_name = "your.app.package" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([package_name])
    session = device.attach(pid)
except frida.TimedOutError:
    print(f"[-] Could not find USB device. Ensure device is connected and adb is running.")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print(f"[-] Process with package name '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "_ZN10RecordData18InternalReserveEntryEv"), {
    onEnter: function(args) {
        console.log("[*] RecordData::InternalReserveEntry called");
        // 可以进一步检查当前缓冲区的使用情况等
        // var cur_index_ptr = this.context.rdi.add(offset_of_cur_index_); // 假设 rdi 是 this 指针
        // var cur_index = cur_index_ptr.readU32();
        // console.log("Current index:", cur_index);
    },
    onLeave: function(retval) {
        if (retval.isNull()) {
            console.log("[*] InternalReserveEntry returned null (buffer full?)");
        } else {
            console.log("[*] InternalReserveEntry returned:", retval);
            // 可以读取返回的 memory_trace::Entry 的内容
        }
    }
});

// 假设你知道 RecordData 实例的地址，可以直接 hook ReserveEntry
// var record_data_instance_address = ...;
// Interceptor.attach(record_data_instance_address.add(offset_of_reserve_entry_), { ... });

"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

device.resume(pid)

try:
    input("Press Enter to detach...\n")
except KeyboardInterrupt:
    pass

session.detach()
```

**解释 Frida Hook 步骤:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **指定包名:** 将 `your.app.package` 替换为你要调试的 Android 应用的包名。
3. **连接设备和附加进程:** 使用 Frida 连接到 USB 设备并附加到目标应用进程。
4. **编写 Frida 脚本:**
   * `Interceptor.attach`:  使用 `Interceptor.attach` 函数 hook `RecordData::InternalReserveEntry` 函数。你需要找到 `libc.so` 中该函数的导出名称。
   * `onEnter`:  在函数入口处执行的代码。这里打印一条消息，表明该函数被调用。你可以尝试读取函数的参数（例如 `this` 指针）来获取更多信息。
   * `onLeave`: 在函数退出处执行的代码。这里打印函数的返回值，如果返回值为空，可能表示缓冲区已满。
5. **创建和加载脚本:** 使用 `session.create_script` 创建 Frida 脚本，并使用 `script.load()` 加载它。
6. **处理消息:** 设置 `script.on('message', on_message)` 来接收来自脚本的消息，例如 `console.log` 的输出。
7. **恢复进程:** 使用 `device.resume(pid)` 恢复应用的执行。
8. **保持连接:** 使用 `input()` 保持脚本运行，直到用户按下 Enter 键。
9. **分离会话:**  使用 `session.detach()` 分离 Frida 会话。

**要使这个 Frida 脚本工作，你需要：**

* 确保你的 Android 设备已连接并通过 ADB 可访问。
* 你的设备上安装了 Frida server。
* 你知道 `RecordData::InternalReserveEntry` 在 `libc.so` 中的确切符号名称（可以通过 `adb shell cat /proc/<pid>/maps` 或使用工具如 `readelf` 查看）。
* 如果你想直接 hook 某个 `RecordData` 实例的方法，你需要知道该实例的内存地址，这可能需要一些逆向工程工作。

这个 Frida 示例提供了一个基本的框架，你可以根据需要扩展它来检查函数参数、返回值、修改内存等，以更深入地调试内存分配记录过程。

Prompt: 
```
这是目录为bionic/libc/malloc_debug/RecordData.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include <mutex>

#include <android-base/stringprintf.h>
#include <memory_trace/MemoryTrace.h>

#include "Config.h"
#include "DebugData.h"
#include "Nanotime.h"
#include "RecordData.h"
#include "debug_disable.h"
#include "debug_log.h"

struct ThreadData {
  ThreadData(RecordData* record_data) : record_data(record_data) {}

  RecordData* record_data = nullptr;
  size_t count = 0;
};

void RecordData::ThreadKeyDelete(void* data) {
  ThreadData* thread_data = reinterpret_cast<ThreadData*>(data);

  thread_data->count++;

  // This should be the last time we are called.
  if (thread_data->count == 4) {
    ScopedDisableDebugCalls disable;

    memory_trace::Entry* entry = thread_data->record_data->InternalReserveEntry();
    if (entry != nullptr) {
      *entry = memory_trace::Entry{
          .tid = gettid(), .type = memory_trace::THREAD_DONE, .end_ns = Nanotime()};
    }
    delete thread_data;
  } else {
    pthread_setspecific(thread_data->record_data->key(), data);
  }
}

RecordData* RecordData::record_obj_ = nullptr;

void RecordData::WriteData(int, siginfo_t*, void*) {
  // Dump from here, the function must not allocate so this is safe.
  record_obj_->WriteEntries();
}

void RecordData::WriteEntriesOnExit() {
  if (record_obj_ == nullptr) return;

  // Append the current pid to the file name to avoid multiple processes
  // writing to the same file.
  std::string file(record_obj_->file());
  file += "." + std::to_string(getpid());
  record_obj_->WriteEntries(file);
}

void RecordData::WriteEntries() {
  WriteEntries(file_);
}

void RecordData::WriteEntries(const std::string& file) {
  std::lock_guard<std::mutex> entries_lock(entries_lock_);
  if (cur_index_ == 0) {
    info_log("No alloc entries to write.");
    return;
  }

  int dump_fd = open(file.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0755);
  if (dump_fd == -1) {
    error_log("Cannot create record alloc file %s: %s", file.c_str(), strerror(errno));
    return;
  }

  for (size_t i = 0; i < cur_index_; i++) {
    if (entries_[i].type == memory_trace::UNKNOWN) {
      // This can happen if an entry was reserved but not filled in due to some
      // type of error during the operation.
      continue;
    }
    if (!memory_trace::WriteEntryToFd(dump_fd, entries_[i])) {
      error_log("Failed to write record alloc information: %s", strerror(errno));
      break;
    }
  }
  close(dump_fd);

  // Mark the entries dumped.
  cur_index_ = 0U;
}

RecordData::RecordData() {
  pthread_key_create(&key_, ThreadKeyDelete);
}

bool RecordData::Initialize(const Config& config) {
  record_obj_ = this;
  struct sigaction64 dump_act = {};
  dump_act.sa_sigaction = RecordData::WriteData;
  dump_act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
  if (sigaction64(config.record_allocs_signal(), &dump_act, nullptr) != 0) {
    error_log("Unable to set up record dump signal function: %s", strerror(errno));
    return false;
  }
  pthread_setspecific(key_, nullptr);

  if (config.options() & VERBOSE) {
    info_log("%s: Run: 'kill -%d %d' to dump the allocation records.", getprogname(),
             config.record_allocs_signal(), getpid());
  }

  entries_.resize(config.record_allocs_num_entries());
  cur_index_ = 0U;
  file_ = config.record_allocs_file();

  return true;
}

RecordData::~RecordData() {
  pthread_key_delete(key_);
}

memory_trace::Entry* RecordData::InternalReserveEntry() {
  std::lock_guard<std::mutex> entries_lock(entries_lock_);
  if (cur_index_ == entries_.size()) {
    return nullptr;
  }

  memory_trace::Entry* entry = &entries_[cur_index_];
  entry->type = memory_trace::UNKNOWN;
  if (++cur_index_ == entries_.size()) {
    info_log("Maximum number of records added, all new operations will be dropped.");
  }
  return entry;
}

memory_trace::Entry* RecordData::ReserveEntry() {
  void* data = pthread_getspecific(key_);
  if (data == nullptr) {
    ThreadData* thread_data = new ThreadData(this);
    pthread_setspecific(key_, thread_data);
  }

  return InternalReserveEntry();
}

"""

```