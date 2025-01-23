Response:
Let's break down the thought process for answering the user's request. The request is quite comprehensive, requiring understanding of the provided C++ code and its context within Android.

**1. Understanding the Core Functionality:**

The first step is to identify the primary purpose of the `system_property_set.cpp` file. A quick scan of the code reveals the function `__system_property_set`. The name strongly suggests it's related to setting system properties in Android. The inclusion of `<sys/system_properties.h>` further confirms this.

**2. Identifying Key Components and Data Structures:**

Next, I'll look for the main data structures and classes involved:

* **`PropertyServiceConnection`:** This class manages the connection to the property service. It handles socket creation, connection, and error handling.
* **`SocketWriter`:** This helper class simplifies sending data over the socket connection, handling buffer management and `writev`.
* **`prop_msg`:** This structure represents the message format used in the older property service protocol.

**3. Tracing the Execution Flow of `__system_property_set`:**

Now, I'll trace the execution flow of the core function, `__system_property_set`:

* **Input Validation:** Checks for null `key`. If `value` is null, it defaults to an empty string.
* **Protocol Version Detection:**  It detects the property service protocol version. This is crucial because the communication mechanism differs between versions.
* **Version 1 Handling:**  If the protocol is version 1:
    * It checks for name and value length limits.
    * It constructs a `prop_msg`.
    * It calls `send_prop_msg`.
* **Version 2 Handling:** If the protocol is version 2 or higher:
    * It checks value length limits for non-"ro." properties.
    * It creates a `PropertyServiceConnection`.
    * It uses a `SocketWriter` to send the `PROP_MSG_SETPROP2` command, key, and value.
    * It receives the result from the property service.
    * It handles potential errors.
* **`send_prop_msg` Function:**  This function establishes a connection using `PropertyServiceConnection` and sends the `prop_msg`. It then waits for the property service to close the connection as an acknowledgment.

**4. Answering Specific Questions:**

With a good understanding of the code, I can now address the user's specific questions:

* **Functionality:**  Summarize the core purpose: setting system properties.
* **Relationship to Android:** Explain how system properties are fundamental to Android's configuration and behavior. Give examples like `ro.build.version.sdk`.
* **libc Function Implementation:**  Detail the purpose and implementation of each libc function used (e.g., `socket`, `connect`, `send`, `recv`, `poll`, `strlen`, `strlcpy`, `memset`, `strcmp`, `access`, `atoll`).
* **Dynamic Linker:** Recognize that this specific file *doesn't directly interact with the dynamic linker*. It uses standard system calls. Therefore, explain *why* it doesn't apply and provide a *general* explanation of dynamic linking and an example SO layout. It's important to acknowledge when a requested element isn't present.
* **Logic Inference (Hypothetical Input/Output):**  Create scenarios for both protocol versions, showing the expected function calls and outcomes (success or failure).
* **Common Usage Errors:** Identify common mistakes like exceeding length limits or incorrect permissions.
* **Android Framework/NDK Path:** Describe the layers involved (Framework -> Binder -> Native Service -> `setprop` command/API -> `__system_property_set`).
* **Frida Hooking:** Provide a concrete Frida example targeting `__system_property_set` to demonstrate how to intercept and inspect calls.

**5. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Address each of the user's requests explicitly.

**6. Review and Refinement:**

Finally, review the answer for accuracy, clarity, and completeness. Ensure that technical terms are explained appropriately and that the examples are relevant. Double-check the code analysis and the explanations of libc functions. Ensure the Frida example is functional and easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus solely on the `__system_property_set` function.
* **Correction:** Realized the helper classes `PropertyServiceConnection` and `SocketWriter` are crucial to understanding how `__system_property_set` works, so include detailed explanations of them.
* **Initial thought:** Just list the libc functions.
* **Correction:** The request asks for *how* they are implemented *within this context*. So, focus on their specific usage in this file (e.g., `socket` for local sockets, `connect` to the property service).
* **Initial thought:** Directly connect this to dynamic linking.
* **Correction:** Recognize the code doesn't show direct dynamic linking. Explain this clearly and provide a *generalized* overview of dynamic linking as requested, even if not directly present in this *specific* file. This demonstrates understanding of the broader Android context.
* **Initial thought:**  A simple "it works" for successful cases.
* **Correction:**  Provide more detail about the communication flow, including the socket closing mechanism for the older protocol.

By following this structured thought process, I can address the multi-faceted request effectively and provide a comprehensive and accurate answer.好的，我们来详细分析一下 `bionic/libc/bionic/system_property_set.cpp` 这个文件。

**功能列举:**

这个文件的核心功能是提供 C 库函数 `__system_property_set` 的实现，用于设置 Android 系统属性。更具体地说，它负责将新的系统属性键值对发送到 `property_service` 进程，由该进程进行实际的属性更新。

**与 Android 功能的关系及举例说明:**

系统属性是 Android 操作系统中非常重要的配置机制。它们以键值对的形式存在，被用于控制和配置系统的各个方面。`__system_property_set` 函数是应用程序和服务修改这些属性的关键入口点。

**举例说明:**

* **修改设备名称:**  应用程序或服务可以通过调用 `__system_property_set("ro.product.name", "MyCustomDevice")` 来设置设备的名称。这个属性会被系统读取并显示在“关于手机”等设置界面中。
* **控制调试模式:**  开发者可以通过 `adb shell setprop debug.myapp true` 命令来启用特定应用的调试模式。这个命令最终会调用 `__system_property_set("debug.myapp", "true")`。Android framework 或应用可以读取这个属性来决定是否开启额外的调试日志或功能。
* **设置网络相关属性:**  例如，设置 DNS 服务器地址：`__system_property_set("net.dns1", "8.8.8.8")`。
* **触发系统重启:**  拥有足够权限的进程可以调用 `__system_property_set("sys.powerctl", "reboot")` 来触发设备重启。

**详细解释 libc 函数的功能实现:**

下面我们逐个解释 `system_property_set.cpp` 中使用的 libc 函数及其实现方式：

1. **`<errno.h>`:**
   - **功能:** 定义了错误码宏，例如 `errno`，用于指示系统调用的失败原因。
   - **实现:**  通常由编译器内置，提供预定义的整数值。

2. **`<poll.h>`:**
   - **功能:** 提供了 `poll` 系统调用，用于监控多个文件描述符上的事件，例如可读、可写或发生错误。
   - **实现:**  `poll` 系统调用会陷入内核，内核会监控指定的文件描述符，并在有事件发生或超时时返回。

3. **`<stdatomic.h>`:**
   - **功能:** 提供了原子操作相关的类型和函数，用于在多线程环境下安全地访问和修改共享变量。
   - **实现:**  通常利用 CPU 提供的原子指令来实现，例如 compare-and-swap (CAS)。

4. **`<stddef.h>`:**
   - **功能:** 定义了一些常用的类型和宏，例如 `size_t`, `ptrdiff_t`, `offsetof` 等。
   - **实现:**  由编译器提供，定义了一些平台相关的类型大小和偏移量。

5. **`<stdint.h>`:**
   - **功能:** 定义了具有特定位宽的整数类型，例如 `uint32_t`, `int64_t` 等。
   - **实现:**  由编译器提供，根据目标平台的字长定义这些类型。

6. **`<stdlib.h>`:**
   - **功能:** 包含通用工具函数，例如内存分配 (`malloc`, `free`), 类型转换 (`atoi`, `atoll`), 随机数生成等。
   - **实现:**
     - `malloc`:  通常使用 `brk` 或 `mmap` 系统调用向操作系统申请内存，并维护一个空闲内存块的链表。
     - `free`:  将释放的内存块添加到空闲链表中，以便后续分配。
     - `atoll`:  将字符串转换为 `long long` 类型，跳过前导空格，处理正负号，并逐个解析数字字符。

7. **`<string.h>`:**
   - **功能:** 提供了字符串操作函数，例如 `strlen`, `strcpy`, `strcmp`, `memset`, `strlcpy` 等。
   - **实现:**
     - `strlen`:  从字符串首地址开始遍历，直到遇到空字符 `\0`，返回遍历的字符数。
     - `strcpy`:  将源字符串复制到目标字符串，直到遇到源字符串的空字符。存在缓冲区溢出的风险。
     - `strcmp`:  逐个比较两个字符串的字符，直到遇到不同的字符或空字符。返回正数、负数或零表示大小关系。
     - `memset`:  将指定内存块的每个字节设置为指定的值。
     - `strlcpy`:  安全地将源字符串复制到目标字符串，最多复制 `size - 1` 个字符，并确保目标字符串以空字符结尾，防止缓冲区溢出。

8. **`<sys/socket.h>`:**
   - **功能:** 提供了 socket 编程相关的函数和结构体，用于网络通信。
   - **实现:**
     - `socket`:  创建一个新的 socket 文件描述符，需要指定协议族 (例如 `AF_LOCAL` for Unix domain sockets, `AF_INET` for IPv4) 和 socket 类型 (例如 `SOCK_STREAM` for TCP, `SOCK_DGRAM` for UDP)。会陷入内核，内核会分配相应的资源并返回文件描述符。

9. **`<sys/system_properties.h>`:**
   - **功能:** 定义了访问系统属性的函数声明，例如 `__system_property_get` (在其他文件中实现)。
   - **实现:**  通常是一个头文件，不包含实现。

10. **`<sys/types.h>`:**
    - **功能:** 定义了一些基本的数据类型，例如 `pid_t`, `uid_t`, `gid_t` 等。
    - **实现:**  由编译器提供，定义了一些平台相关的类型。

11. **`<sys/uio.h>`:**
    - **功能:** 提供了向量化的 I/O 操作函数，例如 `writev`, `readv`，可以一次性写入或读取多个缓冲区。
    - **实现:**  `writev` 系统调用会陷入内核，内核会将多个缓冲区的数据按顺序写入到文件描述符中。

12. **`<sys/un.h>`:**
    - **功能:** 定义了 Unix domain socket 的地址结构 `sockaddr_un`。
    - **实现:**  通常是一个头文件，定义了结构体的布局。

13. **`<unistd.h>`:**
    - **功能:** 提供了各种系统调用接口，例如文件操作 (`read`, `write`, `close`), 进程控制 (`fork`, `exec`), 以及本文件中使用的 `connect`, `access` 等。
    - **实现:**
      - `connect`:  客户端使用 `connect` 系统调用连接到指定的 socket 地址。对于 Unix domain socket，内核会检查目标 socket 是否存在并监听连接。
      - `access`:  检查调用进程是否具有访问指定文件的权限。会陷入内核，内核会根据文件权限和进程的 UID/GID 进行检查。

14. **`<async_safe/log.h>`:**
    - **功能:** 提供了异步安全的日志记录函数，例如 `async_safe_format_log`。
    - **实现:**  通常会使用一个无锁的环形缓冲区来存储日志消息，然后由单独的线程或机制异步地将日志写入到文件或其它输出。

15. **`<async_safe/CHECK.h>`:**
    - **功能:** 提供了断言宏 `CHECK`，用于在运行时检查条件，如果条件为假则终止程序执行。
    - **实现:**  通常在 debug 版本中会输出错误信息并调用 `abort()` 或类似的函数终止程序。

16. **`"private/bionic_defs.h"`:**
    - **功能:** 定义了 Bionic libc 内部使用的一些宏和定义。
    - **实现:**  Bionic libc 内部的头文件，包含一些平台相关的定义。

17. **`"platform/bionic/macros.h"`:**
    - **功能:** 定义了一些通用的宏，例如禁用拷贝构造函数和赋值运算符的宏 `BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS`。
    - **实现:**  包含一些常用的编程模式宏。

18. **`"private/ScopedFd.h"`:**
    - **功能:** 提供了一个 RAII (Resource Acquisition Is Initialization) 风格的类 `ScopedFd`，用于自动管理文件描述符的生命周期，防止资源泄漏。
    - **实现:**  `ScopedFd` 的构造函数获取文件描述符，析构函数调用 `close` 关闭文件描述符。

**涉及 dynamic linker 的功能:**

这个 `system_property_set.cpp` 文件本身 **并不直接涉及 dynamic linker 的功能**。它主要关注与 `property_service` 进程的通信，使用的是 socket 和系统调用。

然而，理解动态链接对于理解 Android 系统的工作方式至关重要。当一个应用程序或库调用 `__system_property_set` 时，这个函数位于 `libc.so` 中，而应用程序本身可能位于不同的 `.apk` 或 `.so` 文件中。dynamic linker 负责在程序启动时或者运行时加载和链接这些共享库。

**SO 布局样本:**

假设我们有一个简单的应用程序 `my_app`，它链接了 `libc.so`。

```
/system/bin/my_app  (可执行文件)
/system/lib/libc.so   (共享库)
```

**链接的处理过程:**

1. **加载:** 当 `my_app` 启动时，操作系统的加载器会首先加载 `my_app` 本身。
2. **依赖解析:** 加载器会解析 `my_app` 的依赖项，发现它依赖于 `libc.so`。
3. **加载共享库:** dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被调用来加载 `libc.so` 到内存中的某个地址。
4. **符号解析和重定位:** dynamic linker 会解析 `my_app` 中对 `libc.so` 中符号（例如 `__system_property_set`）的引用，并将这些引用重定向到 `libc.so` 中 `__system_property_set` 函数的实际地址。这个过程涉及到 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table)。
5. **执行:** 当 `my_app` 调用 `__system_property_set` 时，程序会跳转到 `libc.so` 中该函数的正确地址执行。

**逻辑推理，假设输入与输出:**

假设我们调用 `__system_property_set("my.custom.prop", "my_value")`。

**假设输入:**
- `key`: "my.custom.prop"
- `value`: "my_value"

**输出 (取决于 property service 的状态和权限):**
- **成功:** 返回 `0`。
- **失败:** 返回 `-1`，并且 `errno` 会被设置为相应的错误码，例如：
    - `EACCES`:  权限不足，无法设置该属性。
    - 其他与 socket 通信相关的错误。

**常见的使用错误:**

1. **属性名或值过长:** 旧版本的 property service 对属性名和值的长度有限制 (`PROP_NAME_MAX`, `PROP_VALUE_MAX`)。如果超出限制，`__system_property_set` 会直接返回 `-1`。新版本协议对 `ro.` 开头的属性值长度限制有所放宽。
   ```c++
   // 错误示例
   char long_name[PROP_NAME_MAX + 10];
   memset(long_name, 'a', sizeof(long_name));
   long_name[sizeof(long_name) - 1] = '\0';
   __system_property_set(long_name, "value"); // 可能失败
   ```

2. **权限不足:** 只有具有特定权限的进程才能设置某些系统属性。尝试设置受保护的属性可能会导致失败。
   ```c++
   // 错误示例 (普通应用尝试设置需要 root 权限的属性)
   __system_property_set("persist.sys.usb.config", "adb"); // 可能失败
   ```

3. **在错误的时刻设置属性:**  某些属性的设置时机非常重要。例如，在系统启动早期设置某些属性可能无效。

4. **忽略返回值:**  开发者应该检查 `__system_property_set` 的返回值，以确定属性是否设置成功，并根据 `errno` 处理错误。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework:**
   - 在 Java 代码中，可以使用 `SystemProperties.set(String key, String value)` 来设置系统属性。
   - `SystemProperties.set` 方法是一个 native 方法，它的实现位于 `frameworks/base/core/jni/android/os/SystemProperties.cpp`。
   - 该 native 方法最终会调用 Bionic libc 中的 `__system_property_set` 函数。通常是通过 JNI (Java Native Interface) 调用实现的。

2. **Android NDK:**
   - NDK 允许开发者使用 C/C++ 代码直接与底层系统交互。
   - 在 NDK 代码中，可以直接包含 `<sys/system_properties.h>` 并调用 `__system_property_set` 函数。
   - NDK 编译的共享库会被加载到应用程序进程中，可以直接链接到 `libc.so`。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida 来 hook `__system_property_set` 函数，以观察其调用情况和参数。

**Frida Hook 示例:**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const SystemPropertySet = Module.findExportByName("libc.so", "__system_property_set");
  if (SystemPropertySet) {
    Interceptor.attach(SystemPropertySet, {
      onEnter: function (args) {
        const key = Memory.readCString(args[0]);
        const value = Memory.readCString(args[1]);
        console.log(`__system_property_set called with key: ${key}, value: ${value}`);
      },
      onLeave: function (retval) {
        console.log(`__system_property_set returned: ${retval}`);
      }
    });
  } else {
    console.error("__system_property_set not found in libc.so");
  }
} else {
  console.warn("Frida hook for __system_property_set is only supported on ARM architectures.");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端 (`frida-server`)。
2. **运行目标应用:** 启动你想要监控其系统属性设置行为的应用程序。
3. **运行 Frida 脚本:** 使用 Frida 客户端连接到目标进程并执行上面的 JavaScript 脚本。例如：
   ```bash
   frida -U -f <package_name> -l hook_system_property_set.js --no-pause
   ```
   将 `<package_name>` 替换为目标应用程序的包名。
4. **触发属性设置:** 在目标应用程序中执行会导致调用 `__system_property_set` 的操作。
5. **查看 Frida 输出:** Frida 会在控制台上打印出 `__system_property_set` 的调用信息，包括传入的 key 和 value，以及返回值。

这个 Frida 脚本会在 `__system_property_set` 函数被调用时拦截，并在 `onEnter` 中打印出 key 和 value 参数，在 `onLeave` 中打印出返回值。这可以帮助我们理解哪些属性被设置了，以及设置是否成功。

希望以上分析能够帮助你理解 `bionic/libc/bionic/system_property_set.cpp` 的功能和实现细节。

### 提示词
```
这是目录为bionic/libc/bionic/system_property_set.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <async_safe/log.h>
#include <async_safe/CHECK.h>

#include "private/bionic_defs.h"
#include "platform/bionic/macros.h"
#include "private/ScopedFd.h"

static const char property_service_socket[] = "/dev/socket/" PROP_SERVICE_NAME;
static const char property_service_for_system_socket[] =
    "/dev/socket/" PROP_SERVICE_FOR_SYSTEM_NAME;
static const char* kServiceVersionPropertyName = "ro.property_service.version";

class PropertyServiceConnection {
 public:
  PropertyServiceConnection(const char* name) : last_error_(0) {
    socket_.reset(::socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (socket_.get() == -1) {
      last_error_ = errno;
      return;
    }

    // If we're trying to set "sys.powerctl" from a privileged process, use the special
    // socket. Because this socket is only accessible to privileged processes, it can't
    // be DoSed directly by malicious apps. (The shell user should be able to reboot,
    // though, so we don't just always use the special socket for "sys.powerctl".)
    // See b/262237198 for context
    const char* socket = property_service_socket;
    if (strcmp(name, "sys.powerctl") == 0 &&
        access(property_service_for_system_socket, W_OK) == 0) {
      socket = property_service_for_system_socket;
    }

    const size_t namelen = strlen(socket);
    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    strlcpy(addr.sun_path, socket, sizeof(addr.sun_path));
    addr.sun_family = AF_LOCAL;
    socklen_t alen = namelen + offsetof(sockaddr_un, sun_path) + 1;

    if (TEMP_FAILURE_RETRY(connect(socket_.get(),
                                   reinterpret_cast<sockaddr*>(&addr), alen)) == -1) {
      last_error_ = errno;
      socket_.reset();
    }
  }

  bool IsValid() {
    return socket_.get() != -1;
  }

  int GetLastError() {
    return last_error_;
  }

  bool RecvInt32(int32_t* value) {
    int result = TEMP_FAILURE_RETRY(recv(socket_.get(), value, sizeof(*value), MSG_WAITALL));
    return CheckSendRecvResult(result, sizeof(*value));
  }

  int socket() {
    return socket_.get();
  }

 private:
  bool CheckSendRecvResult(int result, int expected_len) {
    if (result == -1) {
      last_error_ = errno;
    } else if (result != expected_len) {
      last_error_ = -1;
    } else {
      last_error_ = 0;
    }

    return last_error_ == 0;
  }

  ScopedFd socket_;
  int last_error_;

  friend class SocketWriter;
};

class SocketWriter {
 public:
  explicit SocketWriter(PropertyServiceConnection* connection)
      : connection_(connection), iov_index_(0), uint_buf_index_(0) {
  }

  SocketWriter& WriteUint32(uint32_t value) {
    CHECK(uint_buf_index_ < kUintBufSize);
    CHECK(iov_index_ < kIovSize);
    uint32_t* ptr = uint_buf_ + uint_buf_index_;
    uint_buf_[uint_buf_index_++] = value;
    iov_[iov_index_].iov_base = ptr;
    iov_[iov_index_].iov_len = sizeof(*ptr);
    ++iov_index_;
    return *this;
  }

  SocketWriter& WriteString(const char* value) {
    uint32_t valuelen = strlen(value);
    WriteUint32(valuelen);
    if (valuelen == 0) {
      return *this;
    }

    CHECK(iov_index_ < kIovSize);
    iov_[iov_index_].iov_base = const_cast<char*>(value);
    iov_[iov_index_].iov_len = valuelen;
    ++iov_index_;

    return *this;
  }

  bool Send() {
    if (!connection_->IsValid()) {
      return false;
    }

    if (writev(connection_->socket(), iov_, iov_index_) == -1) {
      connection_->last_error_ = errno;
      return false;
    }

    iov_index_ = uint_buf_index_ = 0;
    return true;
  }

 private:
  static constexpr size_t kUintBufSize = 8;
  static constexpr size_t kIovSize = 8;

  PropertyServiceConnection* connection_;
  iovec iov_[kIovSize];
  size_t iov_index_;
  uint32_t uint_buf_[kUintBufSize];
  size_t uint_buf_index_;

  BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS(SocketWriter);
};

struct prop_msg {
  unsigned cmd;
  char name[PROP_NAME_MAX];
  char value[PROP_VALUE_MAX];
};

static int send_prop_msg(const prop_msg* msg) {
  PropertyServiceConnection connection(msg->name);
  if (!connection.IsValid()) {
    return connection.GetLastError();
  }

  int result = -1;
  int s = connection.socket();

  const int num_bytes = TEMP_FAILURE_RETRY(send(s, msg, sizeof(prop_msg), 0));
  if (num_bytes == sizeof(prop_msg)) {
    // We successfully wrote to the property server but now we
    // wait for the property server to finish its work.  It
    // acknowledges its completion by closing the socket so we
    // poll here (on nothing), waiting for the socket to close.
    // If you 'adb shell setprop foo bar' you'll see the POLLHUP
    // once the socket closes.  Out of paranoia we cap our poll
    // at 250 ms.
    pollfd pollfds[1];
    pollfds[0].fd = s;
    pollfds[0].events = 0;
    const int poll_result = TEMP_FAILURE_RETRY(poll(pollfds, 1, 250 /* ms */));
    if (poll_result == 1 && (pollfds[0].revents & POLLHUP) != 0) {
      result = 0;
    } else {
      // Ignore the timeout and treat it like a success anyway.
      // The init process is single-threaded and its property
      // service is sometimes slow to respond (perhaps it's off
      // starting a child process or something) and thus this
      // times out and the caller thinks it failed, even though
      // it's still getting around to it.  So we fake it here,
      // mostly for ctl.* properties, but we do try and wait 250
      // ms so callers who do read-after-write can reliably see
      // what they've written.  Most of the time.
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Property service has timed out while trying to set \"%s\" to \"%s\"",
                            msg->name, msg->value);
      result = 0;
    }
  }

  return result;
}

static constexpr uint32_t kProtocolVersion1 = 1;
static constexpr uint32_t kProtocolVersion2 = 2;  // current

static atomic_uint_least32_t g_propservice_protocol_version = 0;

static void detect_protocol_version() {
  char value[PROP_VALUE_MAX];
  if (__system_property_get(kServiceVersionPropertyName, value) == 0) {
    g_propservice_protocol_version = kProtocolVersion1;
    async_safe_format_log(ANDROID_LOG_WARN, "libc",
                          "Using old property service protocol (\"%s\" is not set)",
                          kServiceVersionPropertyName);
  } else {
    uint32_t version = static_cast<uint32_t>(atoll(value));
    if (version >= kProtocolVersion2) {
      g_propservice_protocol_version = kProtocolVersion2;
    } else {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Using old property service protocol (\"%s\"=\"%s\")",
                            kServiceVersionPropertyName, value);
      g_propservice_protocol_version = kProtocolVersion1;
    }
  }
}

static const char* __prop_error_to_string(int error) {
  switch (error) {
  case PROP_ERROR_READ_CMD: return "PROP_ERROR_READ_CMD";
  case PROP_ERROR_READ_DATA: return "PROP_ERROR_READ_DATA";
  case PROP_ERROR_READ_ONLY_PROPERTY: return "PROP_ERROR_READ_ONLY_PROPERTY";
  case PROP_ERROR_INVALID_NAME: return "PROP_ERROR_INVALID_NAME";
  case PROP_ERROR_INVALID_VALUE: return "PROP_ERROR_INVALID_VALUE";
  case PROP_ERROR_PERMISSION_DENIED: return "PROP_ERROR_PERMISSION_DENIED";
  case PROP_ERROR_INVALID_CMD: return "PROP_ERROR_INVALID_CMD";
  case PROP_ERROR_HANDLE_CONTROL_MESSAGE: return "PROP_ERROR_HANDLE_CONTROL_MESSAGE";
  case PROP_ERROR_SET_FAILED: return "PROP_ERROR_SET_FAILED";
  }
  return "<unknown>";
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int __system_property_set(const char* key, const char* value) {
  if (key == nullptr) return -1;
  if (value == nullptr) value = "";

  if (g_propservice_protocol_version == 0) {
    detect_protocol_version();
  }

  if (g_propservice_protocol_version == kProtocolVersion1) {
    // Old protocol does not support long names or values
    if (strlen(key) >= PROP_NAME_MAX) return -1;
    if (strlen(value) >= PROP_VALUE_MAX) return -1;

    prop_msg msg;
    memset(&msg, 0, sizeof msg);
    msg.cmd = PROP_MSG_SETPROP;
    strlcpy(msg.name, key, sizeof msg.name);
    strlcpy(msg.value, value, sizeof msg.value);

    return send_prop_msg(&msg);
  } else {
    // New protocol only allows long values for ro. properties only.
    if (strlen(value) >= PROP_VALUE_MAX && strncmp(key, "ro.", 3) != 0) return -1;
    // Use proper protocol
    PropertyServiceConnection connection(key);
    if (!connection.IsValid()) {
      errno = connection.GetLastError();
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Unable to set property \"%s\" to \"%s\": connection failed: %m", key,
                            value);
      return -1;
    }

    SocketWriter writer(&connection);
    if (!writer.WriteUint32(PROP_MSG_SETPROP2).WriteString(key).WriteString(value).Send()) {
      errno = connection.GetLastError();
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Unable to set property \"%s\" to \"%s\": write failed: %m", key,
                            value);
      return -1;
    }

    int result = -1;
    if (!connection.RecvInt32(&result)) {
      errno = connection.GetLastError();
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Unable to set property \"%s\" to \"%s\": recv failed: %m", key, value);
      return -1;
    }

    if (result != PROP_SUCCESS) {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "Unable to set property \"%s\" to \"%s\": %s (0x%x)", key, value,
                            __prop_error_to_string(result), result);
      return -1;
    }

    return 0;
  }
}
```