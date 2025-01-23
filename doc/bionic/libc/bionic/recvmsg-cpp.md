Response:
Let's break down the thought process to generate the comprehensive answer about `bionic/libc/bionic/recvmsg.cpp`.

**1. Understanding the Core Request:**

The fundamental goal is to understand the functionality of the provided C++ code snippet within the context of Android's Bionic library. This requires dissecting the code, explaining its purpose, relating it to Android's functionality, detailing the underlying libc function implementations, addressing dynamic linking aspects, considering common usage errors, and outlining how to reach this code within the Android ecosystem. The prompt also asks for specific examples and debugging techniques.

**2. Initial Code Analysis (Line by Line):**

* **Copyright and License:** Recognize this is standard boilerplate and can be mentioned briefly.
* **Includes:** Identify the included headers (`string.h`, `sys/socket.h`, `async_safe/log.h`, `private/bionic_fdtrack.h`). These hints at the code's purpose: socket communication and file descriptor tracking.
* **External Declarations:**  Spot the `extern "C"` declarations for `__recvmsg` and `__recvmmsg`. This is a crucial clue: these are the *actual* system calls. The functions in this file are wrappers around them. Note the double underscores, which is a common convention for internal or low-level functions.
* **`track_fds` Function:**  This is the core of the added functionality. Analyze its logic:
    * Check `__android_fdtrack_hook`. This suggests a mechanism to enable/disable file descriptor tracking.
    * Iterate through control messages (`cmsghdr`). Recognize `SCM_RIGHTS` as indicating file descriptor passing.
    * Validate the length of the control message data.
    * Extract file descriptors from the control message data.
    * Call `FDTRACK_CREATE_NAME`. This clearly links to the `private/bionic_fdtrack.h` header and the purpose of tracking.
* **`recvmsg` Function:**
    * Call `__recvmsg`. Confirming it's a wrapper.
    * Check for errors (`rc == -1`). Standard error handling.
    * Call `track_fds`. This is where the tracking logic is injected.
* **`recvmmsg` Function:**
    * Call `__recvmmsg`. Another wrapper.
    * Check for errors.
    * Loop through the returned messages and call `track_fds` for each.

**3. Identifying Key Functions and Concepts:**

From the code analysis, the core functionalities are:

* **Receiving data over sockets:**  This is the primary purpose of `recvmsg` and `recvmmsg`.
* **File Descriptor Passing:** The `track_fds` function highlights the ability to transfer file descriptors between processes via socket control messages.
* **File Descriptor Tracking:** The `FDTRACK_CREATE_NAME` call signifies a debugging or monitoring feature within Bionic.

**4. Connecting to Android Functionality:**

Think about how these concepts relate to Android:

* **Inter-Process Communication (IPC):** Socket communication is a fundamental way Android apps and system services communicate. `recvmsg` is essential for this.
* **Service Management:**  `system_server`, app processes, and other system components heavily rely on IPC via sockets.
* **Binder:** While not directly shown here, Binder, Android's primary IPC mechanism, often uses file descriptor passing under the hood.
* **Debugging and Monitoring:** The file descriptor tracking feature likely exists to help Android developers diagnose issues related to resource leaks or incorrect FD usage.

**5. Explaining Libc Function Implementations:**

* **`recvmsg` and `recvmmsg`:** Emphasize that these are system calls. The Bionic versions are thin wrappers. The actual implementation resides in the Linux kernel. Briefly describe the parameters of `msghdr` and `mmsghdr`.
* **`track_fds`:** Explain its purpose in detail, focusing on the control message handling and the file descriptor extraction.
* **`CMSG_FIRSTHDR`, `CMSG_NXTHDR`, `CMSG_DATA`:** Describe these macros and their role in navigating the control message structure.

**6. Addressing Dynamic Linking:**

* Recognize that `__recvmsg` and `__recvmmsg` are likely resolved by the dynamic linker.
* Create a simple SO layout example showing how the application, libc.so, and the kernel interact.
* Outline the linking process: the application calls `recvmsg`, which calls `__recvmsg`. The dynamic linker resolves `__recvmsg` to the kernel's implementation via the system call interface.

**7. Considering Common Usage Errors:**

Think about typical mistakes developers might make when using these functions:

* **Incorrect Buffer Sizes:** Provide an example of allocating an insufficient buffer for incoming data.
* **Invalid Flags:** Give an example of using incorrect flags with `recvmsg`.
* **Incorrect `msghdr` Setup:** Demonstrate an error in configuring the `msghdr` structure.
* **Forgetting Error Handling:** Emphasize the importance of checking the return value.

**8. Illustrating Android Framework/NDK Usage:**

* Start with a high-level Android framework component (e.g., `Socket`).
* Show how this framework class internally uses the NDK `socket` functions.
* Demonstrate how the NDK `socket` functions ultimately call the Bionic `recvmsg`.

**9. Providing Frida Hook Examples:**

* Offer practical Frida scripts to intercept `recvmsg` and `track_fds`.
* Show how to log arguments and the return value.
* Demonstrate how to inspect the contents of the `msghdr` structure.

**10. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use code formatting for code snippets and examples. Maintain a consistent and informative tone. Address all parts of the original prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe delve deep into kernel implementation details. **Correction:** Focus on the Bionic library's role and the interaction with the kernel.
* **Initial thought:** Just list the functions. **Correction:** Explain *how* they work and their significance.
* **Initial thought:**  Briefly mention dynamic linking. **Correction:** Provide a concrete SO layout and explain the resolution process.
* **Initial thought:**  Generic error examples. **Correction:** Tailor the examples to the specific functions and potential pitfalls.
* **Initial thought:** Assume the user knows Frida. **Correction:**  Provide basic Frida script examples that are easy to understand.

By following this structured thought process, iterating through the code, connecting it to broader concepts, and anticipating the user's needs, a comprehensive and accurate answer can be generated.
## 针对 bionic/libc/bionic/recvmsg.cpp 的功能、实现、Android 集成和调试分析

这是 Android Bionic 库中处理接收 socket 消息的核心文件之一。它主要负责实现 `recvmsg` 和 `recvmmsg` 两个 POSIX 标准的 socket 函数，并加入了 Android 特有的文件描述符跟踪机制。

**功能列举:**

1. **实现 `recvmsg` 函数:** 接收一个 socket 上的消息。可以接收普通数据以及辅助数据（例如文件描述符）。
2. **实现 `recvmmsg` 函数:**  接收一个 socket 上的多个消息。这是一个批量接收的优化版本，可以减少系统调用次数。
3. **文件描述符跟踪 (`track_fds`):**  当接收到的消息中包含通过 `SCM_RIGHTS` 传递的文件描述符时，记录这些文件描述符的创建信息，用于调试和资源管理。

**与 Android 功能的关系和举例:**

`recvmsg` 和 `recvmmsg` 是 Android 中实现进程间通信 (IPC) 的重要基础。许多 Android 核心功能和应用程序都依赖于 socket 通信。

* **Binder 通信:** Android 的主要 IPC 机制 Binder 在底层传输数据时，可能会使用 socket 来传递文件描述符。例如，当一个 Service 需要将一个打开的文件或者其他资源句柄传递给 Client 时，就需要通过 `SCM_RIGHTS` 传递文件描述符，而 `recvmsg` 就是接收这些文件描述符的关键。
* **Network 通信:**  应用程序通过 Java Socket API 或 NDK Socket API 进行网络通信时，最终会调用到 `recvmsg` 来接收网络数据。
* **Unix Domain Socket 通信:** Android 系统服务之间经常使用 Unix Domain Socket 进行本地通信，`recvmsg` 用于接收这些服务间传递的消息。

**举例说明:**

假设一个 Android 应用需要打开一个文件，并将该文件的描述符传递给另一个进程处理。

1. **进程 A (发送者):** 打开文件，并通过 `sendmsg` 发送文件描述符。`sendmsg` 会将文件描述符放入 `cmsghdr` 结构的 `cmsg_data` 中，并将 `cmsg_type` 设置为 `SCM_RIGHTS`。
2. **进程 B (接收者):** 调用 `recvmsg` 接收消息。
3. **`recvmsg.cpp`:**
   -  `__recvmsg` 系统调用实际从 socket 接收数据和辅助数据 (控制消息)。
   -  `track_fds` 函数被调用，遍历 `msghdr` 中的控制消息。
   -  如果找到 `cmsg_type` 为 `SCM_RIGHTS` 的控制消息，则从中提取文件描述符。
   -  `FDTRACK_CREATE_NAME` 宏会被展开，调用相应的函数记录该文件描述符的创建信息，可能包含创建时的函数名 ("recvmsg")。

**详细解释 libc 函数的功能实现:**

* **`recvmsg(int __fd, struct msghdr* __msg, int __flags)`:**
    1. **调用系统调用 `__recvmsg(__fd, __msg, __flags)`:** 这是实际执行接收操作的内核函数。它从文件描述符 `__fd` 指代的 socket 接收数据，并将接收到的数据、发送者地址以及可能的控制消息（如文件描述符）填充到 `__msg` 指向的 `msghdr` 结构体中。`__flags` 参数用于指定接收的行为，例如是否阻塞等待数据、是否窥探数据等。
    2. **错误处理:** 如果 `__recvmsg` 返回 -1，表示发生错误，`recvmsg` 也直接返回 -1。
    3. **调用 `track_fds(__msg, "recvmsg")`:**  如果接收成功，则调用 `track_fds` 函数来处理接收到的控制消息中可能包含的文件描述符。
    4. **返回接收到的字节数:** 如果接收成功，则返回实际接收到的数据字节数。

* **`recvmmsg(int __fd, struct mmsghdr* __msgs, unsigned int __msg_count, int __flags, const struct timespec* __timeout)`:**
    1. **调用系统调用 `__recvmmsg(__fd, __msgs, __msg_count, __flags, __timeout)`:**  这是一个批量接收消息的系统调用。它可以一次接收多个消息，并将每个消息的信息存储在 `__msgs` 数组中的 `mmsghdr` 结构体中。`__msg_count` 指定要接收的消息数量，`__flags` 和 `__timeout` 参数与 `recvmsg` 类似，用于控制接收行为和超时时间。
    2. **错误处理:** 如果 `__recvmmsg` 返回 -1，表示发生错误，`recvmmsg` 也直接返回 -1。
    3. **循环调用 `track_fds`:**  如果接收到多个消息 (返回值 `rc` 大于 0)，则循环遍历接收到的每个消息，并调用 `track_fds` 函数来处理每个消息的控制消息中可能包含的文件描述符。
    4. **返回接收到的消息数量:** 如果接收成功，则返回实际接收到的消息数量。

* **`track_fds(struct msghdr* msg, const char* function_name)`:**
    1. **检查 `__android_fdtrack_hook`:**  这是一个全局原子变量，用于控制文件描述符跟踪功能是否启用。如果未启用，则直接返回。
    2. **遍历控制消息:** 使用 `CMSG_FIRSTHDR` 和 `CMSG_NXTHDR` 宏遍历 `msghdr` 结构体中的控制消息链表。
    3. **检查 `cmsg_type`:**  对于每个控制消息，检查其 `cmsg_type` 是否为 `SCM_RIGHTS`。这表示该控制消息包含了传递的文件描述符。
    4. **验证 `cmsg_len`:** 检查控制消息的长度是否有效，确保至少包含 `cmsghdr` 结构的大小。
    5. **计算数据长度:** 计算实际的文件描述符数据长度。
    6. **验证数据长度:** 确保数据长度是 `sizeof(int)` 的整数倍，因为文件描述符以 `int` 类型存储。如果不是，则调用 `async_safe_fatal` 报告错误。
    7. **提取文件描述符:**  使用 `CMSG_DATA` 宏获取控制消息的数据部分，并按照 `sizeof(int)` 的步长遍历，将每个 `int` 值视为一个文件描述符。
    8. **调用 `FDTRACK_CREATE_NAME`:** 对于提取到的每个文件描述符 `fd`，调用 `FDTRACK_CREATE_NAME(function_name, fd)` 宏。这个宏的实际实现会根据编译配置和系统状态，将文件描述符的创建信息记录下来，`function_name` 参数通常是调用 `track_fds` 的函数名 ("recvmsg" 或 "recvmmsg")。

**涉及 dynamic linker 的功能:**

这里的代码本身不直接涉及 dynamic linker 的加载和链接过程。但是，`__recvmsg` 和 `__recvmmsg` 这两个函数是系统调用的封装，它们的实际实现在内核中。  Bionic libc 提供了这些函数的封装，应用程序调用这些函数时，实际上会通过 **系统调用接口 (system call interface)** 进入内核。

**SO 布局样本:**

假设一个简单的 Android 应用 `my_app` 使用了 socket 通信：

```
/system/bin/linker64 (或 linker)  # 动态链接器
/system/lib64/libc.so           # Bionic C 库
/system/lib64/libnetd_client.so  # 可能用于网络相关的辅助功能
/data/app/com.example.my_app/lib/arm64-v8a/my_app.so # 应用程序的 native 代码
```

**链接的处理过程:**

1. **应用程序 `my_app.so` 中调用 `recvmsg`:**  当应用程序需要接收 socket 数据时，会调用 Bionic libc 提供的 `recvmsg` 函数。
2. **符号查找:** 动态链接器在加载 `my_app.so` 时，会记录其依赖的共享库，包括 `libc.so`。当执行到 `recvmsg` 调用时，链接器已经将 `recvmsg` 的符号地址解析到 `libc.so` 中对应的实现。
3. **`libc.so` 中的 `recvmsg` 执行:** 执行流进入 `bionic/libc/bionic/recvmsg.cpp` 中的 `recvmsg` 函数。
4. **调用 `__recvmsg`:** `recvmsg` 函数内部会调用 `__recvmsg`。
5. **系统调用:** `__recvmsg` 实际上是一个系统调用的包装。它会将参数传递给内核，触发内核中 socket 接收相关的代码执行。
6. **内核处理:** 内核接收数据并填充到提供的 `msghdr` 结构中。
7. **返回:** 内核将结果返回给 `__recvmsg`，然后 `recvmsg` 继续执行 `track_fds` 等后续操作。

**逻辑推理、假设输入与输出:**

**假设输入:**

* `__fd`: 一个已经连接的 socket 文件描述符。
* `__msg`: 一个指向 `msghdr` 结构的指针，该结构体的缓冲区已分配，用于存储接收到的数据和控制消息。
* `__flags`:  设置为 0，表示阻塞等待接收数据。

**预期输出:**

* 如果 socket 上有数据可读：
    * `recvmsg` 返回接收到的字节数 (大于 0)。
    * `__msg` 结构体被填充，`msg_iov` 指向的缓冲区包含接收到的数据，`msg_controllen` 和 `msg_control` 包含接收到的控制消息（如果有）。
    * 如果控制消息中包含 `SCM_RIGHTS` 类型的文件描述符，`track_fds` 会记录这些文件描述符的信息。
* 如果 socket 连接已关闭 (对端发送了 FIN)：
    * `recvmsg` 返回 0。
* 如果接收过程中发生错误 (例如 socket 无效)：
    * `recvmsg` 返回 -1，并设置 `errno` 来指示错误类型。

**涉及用户或编程常见的使用错误:**

1. **`msghdr` 结构体配置错误:**
   ```c
   struct msghdr msg;
   struct iovec iov;
   char buffer[1024];

   iov.iov_base = buffer;
   // 错误: 没有设置 iov_len，导致 recvmsg 不知道要接收多少数据
   msg.msg_iov = &iov;
   msg.msg_iovlen = 1;
   msg.msg_name = NULL;
   msg.msg_namelen = 0;
   msg.msg_control = NULL;
   msg.msg_controllen = 0;

   ssize_t bytes_received = recvmsg(sockfd, &msg, 0);
   if (bytes_received == -1) {
       perror("recvmsg"); // 可能出现 "Invalid argument" 错误
   }
   ```
2. **缓冲区大小不足:**
   ```c
   struct msghdr msg;
   struct iovec iov;
   char buffer[10]; // 缓冲区太小

   iov.iov_base = buffer;
   iov.iov_len = sizeof(buffer);
   msg.msg_iov = &iov;
   msg.msg_iovlen = 1;
   // ... 其他 msg 字段初始化

   ssize_t bytes_received = recvmsg(sockfd, &msg, 0);
   if (bytes_received > sizeof(buffer)) {
       // 接收到的数据超过缓冲区大小，可能导致数据截断
   }
   ```
3. **忘记处理错误返回值:**
   ```c
   struct msghdr msg;
   // ... 初始化 msg

   recvmsg(sockfd, &msg, 0); // 没有检查返回值，可能忽略了错误
   ```
4. **错误地处理控制消息:**
   ```c
   struct msghdr msg;
   // ... 接收消息

   for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
       if (cmsg->cmsg_type == SCM_RIGHTS) {
           // 错误: 没有检查 cmsg->cmsg_len 是否足够存储文件描述符
           int fd = *(int *)CMSG_DATA(cmsg);
           // ... 使用 fd
       }
   }
   ```

**说明 Android framework or ndk 是如何一步步的到达这里:**

1. **Android Framework (Java):**
   -  例如，`java.net.SocketInputStream` 或 `java.nio.channels.SocketChannel` 的读取操作。
   -  这些 Java 类会通过 JNI 调用到 Android 的 Native 代码。

2. **NDK (Native Development Kit):**
   -  NDK 代码可以使用 POSIX socket API，例如 `recv()` 或 `recvmsg()`。
   -  当 NDK 代码调用 `recvmsg()` 时，链接器会将该调用解析到 Bionic libc 中的 `recvmsg` 函数。

3. **Bionic libc (`bionic/libc/bionic/recvmsg.cpp`):**
   -  执行到 `recvmsg` 函数。
   -  `recvmsg` 内部调用 `__recvmsg` 系统调用封装。

4. **Kernel:**
   -  系统调用 `__recvmsg` 会陷入内核空间。
   -  内核中的 socket 子系统处理接收操作，将数据拷贝到用户空间的缓冲区。
   -  内核返回结果。

5. **Bionic libc 返回:**
   -  `__recvmsg` 返回到 Bionic libc 的 `recvmsg` 函数。
   -  `recvmsg` 调用 `track_fds` 处理文件描述符跟踪。
   -  `recvmsg` 将结果返回给 NDK 代码或通过 JNI 返回给 Java 代码。

**Frida hook 示例调试这些步骤:**

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] 应用 {package_name} 未运行，请先启动应用")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "recvmsg"), {
    onEnter: function(args) {
        console.log("[recvmsg] Called");
        console.log("[recvmsg] fd:", args[0]);
        var msghdrPtr = ptr(args[1]);
        console.log("[recvmsg] msghdr:", msghdrPtr);

        // 可以尝试读取 msghdr 结构体的内容
        // 注意：这只是示例，需要根据实际结构体定义来读取
        // var iov = msghdrPtr.readPointer();
        // var iov_base = iov.readPointer();
        // var iov_len = iov.readUSize();
        // console.log("[recvmsg]   iov_base:", iov_base);
        // console.log("[recvmsg]   iov_len:", iov_len);
    },
    onLeave: function(retval) {
        console.log("[recvmsg] Return value:", retval);
    }
});

Interceptor.attach(Module.findExportByName(null, "__recvmsg"), { // Hook 系统调用
    onEnter: function(args) {
        console.log("[__recvmsg] Called (System Call)");
        console.log("[__recvmsg] fd:", args[0]);
    },
    onLeave: function(retval) {
        console.log("[__recvmsg] Return value:", retval);
    }
});

Interceptor.attach(Module.findExportByName(null, "track_fds"), {
    onEnter: function(args) {
        console.log("[track_fds] Called");
        console.log("[track_fds] msg:", args[0]);
        console.log("[track_fds] function_name:", Memory.readUtf8String(args[1]));
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将 `your.app.package.name` 替换为你要调试的 Android 应用的包名。
2. 确保你的 Android 设备或模拟器已连接并运行了 Frida Server。
3. 运行该 Python 脚本。
4. 在你的 Android 应用中触发使用 socket 接收消息的操作。
5. Frida 会打印出 `recvmsg`, `__recvmsg` 和 `track_fds` 函数被调用时的参数和返回值，帮助你观察数据流和文件描述符的传递过程。

这个 Frida 脚本提供了一个基本的框架，你可以根据需要扩展它，例如读取 `msghdr` 结构体的更多字段，或者根据特定的条件进行断点和修改。

### 提示词
```
这是目录为bionic/libc/bionic/recvmsg.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
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

#include <string.h>
#include <sys/socket.h>

#include <async_safe/log.h>

#include "private/bionic_fdtrack.h"

extern "C" ssize_t __recvmsg(int __fd, struct msghdr* __msg, int __flags);
extern "C" int __recvmmsg(int __fd, struct mmsghdr* __msgs, unsigned int __msg_count, int __flags,
                          const struct timespec* __timeout);

static inline __attribute__((artificial)) __attribute__((always_inline)) void track_fds(
    struct msghdr* msg, const char* function_name) {
  if (!atomic_load(&__android_fdtrack_hook)) {
    return;
  }

  for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
    if (cmsg->cmsg_type != SCM_RIGHTS) {
      continue;
    }

    if (cmsg->cmsg_len <= sizeof(struct cmsghdr)) {
      continue;
    }

    size_t data_length = cmsg->cmsg_len - sizeof(struct cmsghdr);
    if (data_length % sizeof(int) != 0) {
      async_safe_fatal("invalid cmsg length: %zu", data_length);
    }

    for (size_t offset = 0; offset < data_length; offset += sizeof(int)) {
      int fd;
      memcpy(&fd, CMSG_DATA(cmsg) + offset, sizeof(int));
      FDTRACK_CREATE_NAME(function_name, fd);
    }
  }
}

ssize_t recvmsg(int __fd, struct msghdr* __msg, int __flags) {
  ssize_t rc = __recvmsg(__fd, __msg, __flags);
  if (rc == -1) {
    return -1;
  }
  track_fds(__msg, "recvmsg");
  return rc;
}

int recvmmsg(int __fd, struct mmsghdr* __msgs, unsigned int __msg_count, int __flags,
             const struct timespec* __timeout) {
  int rc = __recvmmsg(__fd, __msgs, __msg_count, __flags, __timeout);
  if (rc == -1) {
    return -1;
  }
  for (int i = 0; i < rc; ++i) {
    track_fds(&__msgs[i].msg_hdr, "recvmmsg");
  }
  return rc;
}
```