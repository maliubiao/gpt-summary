Response:
Let's break down the thought process for answering this request. The user has provided C source code and wants a comprehensive explanation. Here's a possible thought sequence:

1. **Understand the Core Purpose:** The filename and the code itself strongly suggest this is about tracking file descriptor (FD) activity (creation and closure). The presence of `android_fdtrack_hook_t` reinforces this. The "handroid bionic" part confirms it's specific to Android's C library.

2. **Identify Key Components:** Scan the code for crucial elements:
    * **Macros:** `FDTRACK_CREATE_NAME`, `FDTRACK_CREATE`, `FDTRACK_CLOSE`. These are the primary ways this functionality is used.
    * **Global Variables:** `__android_fdtrack_hook`, `__android_fdtrack_globally_disabled`. These control the tracking mechanism.
    * **Data Structures:** `android_fdtrack_event`. This holds the information being tracked.
    * **Functions/Structures from other Headers:** `bionic_tls`, `__get_thread()`, `ErrnoRestorer`. These indicate dependencies on other parts of Bionic.
    * **Atomic Operations:** `atomic_load`. This signals thread-safety concerns.

3. **Deconstruct Each Macro:**  Analyze what each macro does step-by-step:
    * **`FDTRACK_CREATE_NAME(name, fd_value)`:**
        * Takes a name (usually the function creating the FD) and the FD value.
        * Checks if the FD is valid (`!= -1`).
        * Checks if the hook is active (`__android_fdtrack_hook`).
        * Checks if it's not in a `vfork()` context.
        * Gets thread-local storage (`bionic_tls`).
        * Checks for re-entrant calls (`tls.fdtrack_disabled`) and global disablement.
        * If tracking is enabled:
            * Creates an `android_fdtrack_event`.
            * Populates it with the FD, event type (CREATE), and function name.
            * Calls the hook function.
        * Returns the original FD value.
    * **`FDTRACK_CREATE(fd_value)`:**  Just a convenience wrapper using `__func__` for the name.
    * **`FDTRACK_CLOSE(fd_value)`:** Similar to `FDTRACK_CREATE_NAME`, but the event type is CLOSE and it saves/restores `errno`.

4. **Explain the Functionality:**  Based on the macro analysis, describe the overall purpose: to provide a hook mechanism for tracking FD creation and closure in Android's C library.

5. **Connect to Android Features:**  Think about *why* Android would need this. Resource tracking, debugging, security analysis come to mind. Provide specific examples like detecting FD leaks.

6. **Explain libc Function Implementation:** Since the provided code is *not* the implementation of libc functions, clarify that it's a *mechanism used within* those functions. Emphasize that the macros get *inserted* into functions like `socket()`, `open()`, and `close()`.

7. **Dynamic Linker Aspects:**  This code snippet doesn't directly involve the dynamic linker. State this clearly. Explain that the hook mechanism itself might be *configured* or *used* by components loaded by the dynamic linker, but the code itself isn't a core dynamic linker feature. Avoid making up connections where they don't exist.

8. **Logical Reasoning (Input/Output):**  Focus on the *effect* of the macros. If `__android_fdtrack_hook` is set, calling a function with `FDTRACK_CREATE` will trigger the hook with creation information. Similarly for `FDTRACK_CLOSE`. Provide a simple code example to illustrate this.

9. **Common Usage Errors:**  Think about mistakes developers might make: forgetting to check the return value of FD-creating functions, closing FDs incorrectly, double-closing. Explain how this tracking could *reveal* these errors.

10. **Android Framework/NDK Integration:** Explain the likely flow:  An app makes a system call (e.g., `socket()`). The Bionic libc `socket()` implementation, which now includes the `FDTRACK_CREATE` macro, will trigger the hook. The Android framework or other system components can set the `__android_fdtrack_hook` to receive these events.

11. **Frida Hooking:**  Provide a concrete Frida example showing how to intercept the global hook variable and log the events. This makes the explanation practical.

12. **Structure and Language:** Organize the answer logically with clear headings. Use precise language but avoid overly technical jargon where simpler terms suffice. Ensure the response is in Chinese as requested.

13. **Review and Refine:** Read through the entire answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have focused too much on the technical details of the macros. Reviewing would remind me to also explain the *broader purpose* and its connection to Android.

By following these steps, you can systematically analyze the code and generate a comprehensive and helpful answer that addresses all aspects of the user's request. The key is to break down the problem, understand the individual components, and then synthesize a coherent explanation.
这个目录 `bionic/libc/private/bionic_fdtrack.handroid bionic` 下的源代码文件 `bionic_fdtrack.h` 定义了一个用于跟踪文件描述符（file descriptor，简称 fd）创建和关闭的机制。它主要用于 Android 系统内部的调试和资源管理。

下面详细列举其功能，并结合 Android 功能进行说明：

**主要功能：文件描述符追踪 (File Descriptor Tracking)**

这个头文件的核心功能是提供宏定义，允许在 Bionic libc 的其他部分插入代码，以便在文件描述符被创建和关闭时发出通知。这种机制允许系统级别的监控和分析文件描述符的使用情况。

**功能分解：**

1. **定义追踪事件结构体 (`android_fdtrack_event`) (在 `platform/bionic/fdtrack.h` 中定义，此处引用)：**
   - 该结构体用于存储文件描述符追踪事件的信息，例如：
     - `fd`: 被创建或关闭的文件描述符的值。
     - `type`: 事件类型，可以是 `ANDROID_FDTRACK_EVENT_TYPE_CREATE` (创建) 或 `ANDROID_FDTRACK_EVENT_TYPE_CLOSE` (关闭)。
     - `data`: 一个联合体，包含与事件类型相关的数据。对于创建事件，它包含一个指向创建该文件描述符的函数名称的指针 (`function_name`)。

2. **定义全局钩子函数指针 (`__android_fdtrack_hook`)：**
   - 这是一个 `atomic(android_fdtrack_hook_t)` 类型的全局变量。 `android_fdtrack_hook_t` 是一个函数指针类型，指向一个接收 `android_fdtrack_event*` 作为参数的函数。
   - 这个钩子函数允许外部代码（通常是 Android 系统服务或调试工具）注册一个回调函数，以便在每次文件描述符创建或关闭时收到通知。

3. **定义全局禁用标志 (`__android_fdtrack_globally_disabled`)：**
   - 这是一个 `bool` 类型的全局变量，用于全局性地禁用文件描述符追踪。如果设置为 `true`，则不会触发任何追踪事件。

4. **提供用于记录文件描述符创建的宏 (`FDTRACK_CREATE_NAME`, `FDTRACK_CREATE`)：**
   - **`FDTRACK_CREATE_NAME(name, fd_value)`:**
     - 接收两个参数：`name` (一个字符串，通常是创建文件描述符的函数名) 和 `fd_value` (创建的文件描述符的值)。
     - **逻辑：**
       - 首先，将 `fd_value` 赋值给局部变量 `__fd`。
       - 检查 `__fd` 是否有效（不等于 -1）且全局钩子函数指针 `__android_fdtrack_hook` 不为空，并且当前线程不是由 `vfork()` 创建的子进程。
       - 获取当前线程的线程本地存储 (`bionic_tls`)。
       - 检查是否处于重入调用（`tls.fdtrack_disabled`）或全局追踪被禁用状态。如果是，则不进行追踪。
       - 如果满足追踪条件，则：
         - 创建一个 `ErrnoRestorer` 对象，用于在执行追踪代码后恢复 `errno` 的值。
         - 设置线程本地存储中的 `fdtrack_disabled` 标志为 `true`，防止递归调用。
         - 填充 `android_fdtrack_event` 结构体，设置文件描述符、事件类型为创建，并设置函数名为 `name`。
         - 调用通过 `__android_fdtrack_hook` 注册的钩子函数，传递事件信息。
         - 恢复线程本地存储中的 `fdtrack_disabled` 标志为 `false`。
       - 最后，返回文件描述符的值 `__fd`。
   - **`FDTRACK_CREATE(fd_value)`:**
     - 是 `FDTRACK_CREATE_NAME` 的一个简化版本，它自动使用 `__func__` (当前函数名) 作为 `name` 参数。

5. **提供用于记录文件描述符关闭的宏 (`FDTRACK_CLOSE`)：**
   - **`FDTRACK_CLOSE(fd_value)`:**
     - 接收一个参数：`fd_value` (要关闭的文件描述符的值)。
     - **逻辑：**
       - 与 `FDTRACK_CREATE_NAME` 类似，但事件类型设置为 `ANDROID_FDTRACK_EVENT_TYPE_CLOSE`，并且不记录函数名。
       - 在调用钩子函数前后保存和恢复 `errno` 的值，因为钩子函数的执行可能会修改 `errno`。

**与 Android 功能的关系及举例说明：**

这个文件描述符追踪机制是 Android 系统内部用于诊断和监控资源使用的重要工具。

* **调试和性能分析：**
    - **示例：** Android 系统可以使用这个机制来检测文件描述符泄漏。如果一个应用或系统服务打开了文件描述符却没有正确关闭，追踪机制可以记录下这些创建事件，但没有对应的关闭事件，从而帮助开发者定位问题。
    - **例子：**  当一个应用打开一个 socket 连接但忘记在操作完成后关闭它时，这个追踪机制可以记录下 `socket()` 函数的调用以及返回的文件描述符，但缺少后续的 `close()` 调用。

* **安全性分析：**
    - **示例：**  可以监控特定类型文件描述符的创建和使用，例如 binder 文件描述符或特定的设备文件描述符，以检测潜在的恶意行为。

* **资源管理：**
    - **示例：**  系统可以跟踪当前系统中打开的文件描述符总数，以及每个进程打开的文件描述符数量，以便更好地管理系统资源，防止资源耗尽。

**libc 函数的实现方式：**

这个头文件本身并没有实现任何 libc 函数。它提供的是一种**框架**或者**基础设施**，用于在 libc 函数的实现中插入追踪代码。

例如，`socket()`、`open()`、`pipe()` 等创建文件描述符的 libc 函数的实现会使用 `FDTRACK_CREATE` 宏：

```c
// 假设这是 socket() 函数的简化实现
int socket(int domain, int type, int protocol) {
  int fd = __socket(domain, type, protocol); // 调用真正的 socket 系统调用
  return FDTRACK_CREATE(fd); // 使用宏记录文件描述符的创建
}

// 假设这是 close() 函数的简化实现
int close(int fd) {
  FDTRACK_CLOSE(fd); // 使用宏记录文件描述符的关闭
  return __close(fd); // 调用真正的 close 系统调用
}
```

**涉及 dynamic linker 的功能：**

这个代码片段本身并没有直接涉及到 dynamic linker 的核心功能。 然而，可以理解的是，`__android_fdtrack_hook` 这个全局变量的设置和使用，可能会在动态链接器加载共享库时进行初始化或配置。

**so 布局样本和链接处理过程：**

假设有一个名为 `libfdtrack_monitor.so` 的共享库，它实现了文件描述符追踪的钩子函数：

```c
// libfdtrack_monitor.c
#include <stdio.h>
#include <bionic/fdtrack.h>

void my_fdtrack_hook(android_fdtrack_event* event) {
  if (event->type == ANDROID_FDTRACK_EVENT_TYPE_CREATE) {
    printf("FD Created: %d, Function: %s\n", event->fd, event->data.create.function_name);
  } else if (event->type == ANDROID_FDTRACK_EVENT_TYPE_CLOSE) {
    printf("FD Closed: %d\n", event->fd);
  }
}

__attribute__((constructor)) void fdtrack_init() {
  extern _Atomic(android_fdtrack_hook_t) __android_fdtrack_hook;
  atomic_store(&__android_fdtrack_hook, my_fdtrack_hook);
  printf("FD Tracking initialized.\n");
}
```

**so 布局样本：**

```
libfdtrack_monitor.so:
    .text:  // 代码段，包含 my_fdtrack_hook 和 fdtrack_init 函数
    .data:  // 数据段，可能包含一些局部变量
    .rodata: // 只读数据段，可能包含字符串常量
    .dynamic: // 动态链接信息
    ...
```

**链接处理过程：**

1. **加载共享库：** 当某个进程启动或使用 `dlopen` 加载 `libfdtrack_monitor.so` 时，dynamic linker 会将其加载到进程的地址空间。
2. **执行构造函数：** Dynamic linker 会执行共享库中标记为构造函数的函数，例如这里的 `fdtrack_init` 函数。
3. **设置钩子：** `fdtrack_init` 函数会获取指向全局变量 `__android_fdtrack_hook` 的指针，并使用 `atomic_store` 原子操作将其设置为 `my_fdtrack_hook` 函数的地址。
4. **开始追踪：** 一旦钩子函数被设置，任何调用包含 `FDTRACK_CREATE` 或 `FDTRACK_CLOSE` 宏的 libc 函数的操作，都会触发 `my_fdtrack_hook` 函数的执行。

**假设输入与输出（逻辑推理）：**

假设一个简单的程序调用 `socket()` 创建一个 socket，然后调用 `close()` 关闭它，并且 `libfdtrack_monitor.so` 已经被加载。

**假设输入：**

```c
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

int main() {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd != -1) {
    printf("Socket created with FD: %d\n", sockfd);
    close(sockfd);
  } else {
    perror("socket");
  }
  return 0;
}
```

**预期输出（在加载了 `libfdtrack_monitor.so` 的情况下）：**

```
FD Tracking initialized.
Socket created with FD: 3
FD Created: 3, Function: socket
FD Closed: 3
```

**用户或编程常见的使用错误：**

1. **忘记检查文件描述符的返回值：**  `socket()`、`open()` 等函数在失败时会返回 -1。如果没有检查返回值，就直接使用返回的 -1 作为文件描述符传递给其他函数（如 `close()`），会导致错误。虽然追踪机制会记录 -1 的关闭事件，但这通常不是预期的。

   ```c
   int fd = open("nonexistent_file.txt", O_RDONLY);
   close(fd); // 如果 open 失败，fd 的值为 -1，关闭无效的文件描述符
   ```

2. **文件描述符泄漏：**  打开了文件描述符，但在不再需要时忘记关闭。这会导致系统资源被占用，最终可能导致程序崩溃或系统不稳定。追踪机制可以帮助发现这种泄漏。

   ```c
   int fd = open("my_file.txt", O_RDONLY);
   // ... 一些操作，但忘记调用 close(fd);
   ```

3. **重复关闭同一个文件描述符：**  对同一个文件描述符调用 `close()` 两次会导致错误。

   ```c
   int fd = open("my_file.txt", O_RDONLY);
   close(fd);
   close(fd); // 错误：尝试关闭已经关闭的文件描述符
   ```

**Android Framework 或 NDK 如何一步步到达这里：**

1. **NDK 应用调用系统调用：** NDK 应用通常通过 libc 提供的函数来执行系统调用。例如，调用 `socket()` 函数会最终调用底层的 `__socket` 系统调用。

2. **Bionic libc 函数执行：**  NDK 应用调用的 `socket()` 函数是 Bionic libc 中的实现。如前所述，Bionic libc 的 `socket()` 实现会包含 `FDTRACK_CREATE` 宏。

3. **触发追踪宏：** 当 `socket()` 函数被执行时，`FDTRACK_CREATE` 宏内的条件判断会检查 `__android_fdtrack_hook` 是否被设置。

4. **调用钩子函数：** 如果钩子函数被设置，`atomic_load (&__android_fdtrack_hook)(&event)` 会调用已注册的钩子函数，并将包含文件描述符创建信息的事件传递给它。

5. **Framework 设置钩子：**  Android Framework 或系统服务（例如 `system_server`）可能会在启动时或运行时，通过某种机制设置 `__android_fdtrack_hook` 变量，以便监控系统中文件描述符的使用情况。这可能涉及到加载特定的共享库或直接修改该全局变量。

**Frida Hook 示例调试这些步骤：**

可以使用 Frida Hook 来观察 `__android_fdtrack_hook` 的设置和文件描述符追踪事件的触发。

```python
import frida
import sys

# 要附加的进程名称或 PID
package_name = "com.example.myapp" # 替换为你的应用包名

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
console.log("开始 Hook __android_fdtrack_hook...");

var fdtrack_hook_ptr = Module.findExportByName("libc.so", "__android_fdtrack_hook");
if (fdtrack_hook_ptr) {
    console.log("__android_fdtrack_hook 地址:", fdtrack_hook_ptr);

    // Hook __android_fdtrack_hook 的赋值操作
    Interceptor.attach(fdtrack_hook_ptr.write(), {
        onEnter: function(args) {
            var new_hook_addr = this.context.r0; // 假设是 ARM 架构，钩子函数地址通常在 r0 寄存器
            console.log("__android_fdtrack_hook 被设置为:", new_hook_addr);

            // 如果需要，可以进一步 Hook 新设置的钩子函数
            if (!new_hook_addr.isNull()) {
                Interceptor.attach(new_hook_addr, {
                    onEnter: function(args) {
                        var event_ptr = ptr(args[0]);
                        var event = event_ptr.readStruct({
                            fd: 'int',
                            type: 'int',
                            data: {
                                create: {
                                    function_name: 'pointer'
                                }
                            }
                        });

                        if (event.type == 0) { // ANDROID_FDTRACK_EVENT_TYPE_CREATE
                            var function_name = event.data.create.function_name.readCString();
                            console.log("FD Track Event (Create): FD =", event.fd, ", Function =", function_name);
                        } else if (event.type == 1) { // ANDROID_FDTRACK_EVENT_TYPE_CLOSE
                            console.log("FD Track Event (Close): FD =", event.fd);
                        }
                    }
                });
            }
        }
    });

    // 读取初始值
    var initial_hook_addr = ptr(fdtrack_hook_ptr.readPointer());
    console.log("__android_fdtrack_hook 初始值:", initial_hook_addr);
} else {
    console.error("找不到 __android_fdtrack_hook 符号");
}
"""

script = session.create_script(script_code)

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Frida]: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[Frida Error]: {message['stack']}")

script.on('message', on_message)
script.load()

print("Frida 脚本已加载，等待事件发生...")
sys.stdin.read()
session.detach()
```

**Frida Hook 示例说明：**

1. **附加进程：**  脚本首先尝试附加到指定包名的 Android 进程。
2. **查找符号：**  使用 `Module.findExportByName` 查找 `libc.so` 中 `__android_fdtrack_hook` 变量的地址。
3. **Hook 赋值操作：**  使用 `Interceptor.attach` Hook 对 `__android_fdtrack_hook` 地址的写入操作。当有代码尝试设置这个全局变量时，`onEnter` 函数会被调用，打印新的钩子函数地址。
4. **Hook 钩子函数：**  在 `onEnter` 中，如果新的钩子函数地址不为空，则进一步 Hook 这个新的钩子函数，以便在文件描述符创建或关闭事件发生时记录相关信息。
5. **读取初始值：**  脚本也会读取并打印 `__android_fdtrack_hook` 的初始值。
6. **打印事件信息：**  在 Hook 的钩子函数中，解析 `android_fdtrack_event` 结构体，并打印文件描述符和事件类型等信息。

通过运行这个 Frida 脚本，你可以观察到 Android Framework 或应用何时设置了文件描述符追踪的钩子函数，以及在应用运行过程中触发的文件描述符创建和关闭事件。这有助于理解这个追踪机制在实际运行中的行为。

### 提示词
```
这是目录为bionic/libc/private/bionic_fdtrack.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdatomic.h>
#include <sys/cdefs.h>

#include "platform/bionic/fdtrack.h"

#include "bionic/pthread_internal.h"
#include "private/ErrnoRestorer.h"
#include "private/bionic_tls.h"

extern "C" _Atomic(android_fdtrack_hook_t) __android_fdtrack_hook;
extern "C" bool __android_fdtrack_globally_disabled;

// Macro to record file descriptor creation.
// e.g.:
//   int socket(int domain, int type, int protocol) {
//     return FDTRACK_CREATE_NAME("socket", __socket(domain, type, protocol));
//   }
#define FDTRACK_CREATE_NAME(name, fd_value)                        \
  ({                                                               \
    int __fd = (fd_value);                                         \
    if (__fd != -1 && __predict_false(__android_fdtrack_hook) &&   \
        !__predict_false(__get_thread()->is_vforked())) {          \
      bionic_tls& tls = __get_bionic_tls();                        \
      /* fdtrack_disabled is only true during reentrant calls. */  \
      if (!__predict_false(tls.fdtrack_disabled) &&                \
          !__predict_false(__android_fdtrack_globally_disabled)) { \
        ErrnoRestorer r;                                           \
        tls.fdtrack_disabled = true;                               \
        android_fdtrack_event event;                               \
        event.fd = __fd;                                           \
        event.type = ANDROID_FDTRACK_EVENT_TYPE_CREATE;            \
        event.data.create.function_name = name;                    \
        atomic_load (&__android_fdtrack_hook)(&event);             \
        tls.fdtrack_disabled = false;                              \
      }                                                            \
    }                                                              \
    __fd;                                                          \
  })

// Macro to record file descriptor creation, with the current function's name.
// e.g.:
//   int socket(int domain, int type, int protocol) {
//     return FDTRACK_CREATE_NAME(__socket(domain, type, protocol));
//   }
#define FDTRACK_CREATE(fd_value) FDTRACK_CREATE_NAME(__func__, (fd_value))

// Macro to record file descriptor closure.
// Note that this does not actually close the file descriptor.
#define FDTRACK_CLOSE(fd_value)                                    \
  ({                                                               \
    int __fd = (fd_value);                                         \
    if (__fd != -1 && __predict_false(__android_fdtrack_hook) &&   \
        !__predict_false(__get_thread()->is_vforked())) {          \
      bionic_tls& tls = __get_bionic_tls();                        \
      if (!__predict_false(tls.fdtrack_disabled) &&                \
          !__predict_false(__android_fdtrack_globally_disabled)) { \
        int saved_errno = errno;                                   \
        tls.fdtrack_disabled = true;                               \
        android_fdtrack_event event;                               \
        event.fd = __fd;                                           \
        event.type = ANDROID_FDTRACK_EVENT_TYPE_CLOSE;             \
        atomic_load (&__android_fdtrack_hook)(&event);             \
        tls.fdtrack_disabled = false;                              \
        errno = saved_errno;                                       \
      }                                                            \
    }                                                              \
    __fd;                                                          \
  })
```