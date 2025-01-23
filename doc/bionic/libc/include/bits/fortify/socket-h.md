Response:
Let's break down the thought process to answer the user's request about the `socket.handroid` file.

**1. Understanding the Request:**

The user has provided the source code of a header file within the Android Bionic library, specifically related to socket functions. They want to know:

* **Functionality:** What does this file do?
* **Android Relevance:** How does it relate to Android's workings?
* **Detailed Function Explanation:** How are the individual libc functions implemented (specifically the `_chk` variants and the fortified inline functions)?
* **Dynamic Linker Involvement:**  If dynamic linking is relevant, how does it work, with examples?
* **Logic and Examples:** Provide examples of input/output based on the logic.
* **Common Errors:** What mistakes do developers often make?
* **Android Framework/NDK Path:** How does code execution reach this part of the Bionic library?
* **Frida Hooking:** How can this be debugged using Frida?

**2. Initial Code Analysis (Skimming and High-Level Understanding):**

* **Copyright Header:**  Confirms it's an Android Open Source Project file.
* **`#ifndef _SYS_SOCKET_H_` and `#error`:** This is a guard to prevent direct inclusion and enforces including the standard `<sys/socket.h>` header. This is crucial for correct dependency management.
* **`__BIONIC_AVAILABILITY_GUARD(26)`:** This indicates that the `__sendto_chk` function is introduced in Android API level 26 (Oreo). This immediately tells us this file is version-aware.
* **`__sendto_chk` and `__recvfrom_chk`:** These functions, ending in `_chk`, strongly suggest they are "checked" versions of the standard `sendto` and `recvfrom` system calls. This hints at security or robustness enhancements.
* **`#if defined(__BIONIC_FORTIFY)`:** This block contains functions likely related to "fortification," a security technique to prevent buffer overflows and other memory safety issues.
* **`__BIONIC_FORTIFY_INLINE`:**  Indicates these functions are meant to be inlined by the compiler, potentially for performance.
* **`recvfrom`, `sendto`, `recv`, `send`:** These are the standard socket functions. The code within the `__BIONIC_FORTIFY` block seems to be *wrapping* these functions.
* **`__pass_object_size0`:** This macro likely passes the size of the buffer.
* **`__clang_error_if`:** This is a compile-time check to detect if the provided length exceeds the buffer size.
* **`__bos0(buf)`:**  Likely retrieves the buffer object size.
* **`__bos_unevaluated_lt` and `__bos_trivially_ge`:** These are likely internal Bionic functions to compare buffer sizes.
* **`__ANDROID_API__ >= 24` and `__BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED`:** These conditional compilation directives indicate runtime checks are enabled based on the Android API level and fortification settings.
* **`__call_bypassing_fortify`:** This suggests a mechanism to call the underlying system call directly, bypassing the fortification checks under certain conditions.

**3. Detailed Function Analysis (Hypothesizing and Inferring):**

* **`__sendto_chk` and `__recvfrom_chk`:** These are probably the *actual* system call wrappers with additional size checks. They likely take an extra `size_t` argument representing the buffer's allocated size.
* **Fortified Inline Functions:** The core idea seems to be:
    * **Compile-time check:** `__clang_error_if` catches potential buffer overflows at compile time.
    * **Runtime check (if enabled):** If the API level and fortification settings allow, it checks at runtime if the requested length exceeds the buffer size using `__bos_trivially_ge`. If it does, it calls the `_chk` version (with the buffer size) which presumably can handle the error more robustly.
    * **Bypass (if checks pass):** If the checks pass, it calls the underlying system call using `__call_bypassing_fortify`. This avoids the overhead of the extra checks when they are deemed unnecessary.
* **`recv` and `send` implementations:** They are simply calling `recvfrom` and `sendto` with `NULL` for the address and 0 for the address length, as expected for connection-oriented sockets.

**4. Addressing Specific Questions:**

* **Functionality:** Summarize the core purpose: buffer overflow protection for socket functions.
* **Android Relevance:** Explain how this enhances security and stability in Android. Give concrete examples like network communication.
* **Detailed Implementation:** Describe the compile-time and runtime checks. Explain the role of the `_chk` functions.
* **Dynamic Linker:** While this specific file *doesn't* directly deal with dynamic linking, the *underlying* `sendto` and `recvfrom` system calls do. Explain that system calls are handled by the kernel, and the libc functions act as wrappers. Briefly touch on how the dynamic linker is involved in loading the libc. (Initially, I might overthink the dynamic linker aspect for *this specific file*, but realizing it's mainly about fortification helps narrow the focus.)
* **Logic and Examples:** Create simple scenarios demonstrating how the compile-time and runtime checks would behave with correct and incorrect buffer sizes.
* **Common Errors:** Focus on buffer overflows and how the fortification mechanisms help prevent them.
* **Android Framework/NDK Path:**  Trace a typical network request: application code -> NDK socket functions -> Bionic libc -> system call.
* **Frida Hooking:** Provide examples of hooking the fortified and the underlying system calls to observe the behavior.

**5. Structuring the Answer:**

Organize the information logically, addressing each part of the user's request clearly. Use headings and bullet points for readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this file directly handles system call invocation. **Correction:** Realized it's mainly about *fortification* and relies on the standard system call mechanism.
* **Overthinking dynamic linking:**  Initially considered going deep into dynamic linking details. **Correction:**  Focused on its role in providing the libc and how system calls are ultimately kernel-level operations.
* **Clarity of explanation:** Ensured the explanation of compile-time vs. runtime checks is clear and concise.

By following this systematic approach, analyzing the code, and addressing each aspect of the user's query, a comprehensive and accurate answer can be constructed. The key is to start with a high-level understanding and gradually delve into the specifics while keeping the user's questions in mind.
这是一个位于 Android Bionic 库中，专门针对 socket 操作进行安全加固（fortification）的头文件。它位于 `bionic/libc/include/bits/fortify/socket.handroid.h`（根据你的描述推断，实际文件名可能略有不同，因为你说是 `socket.handroid`，这里假设是头文件）。

**功能列举:**

1. **提供带有安全检查的 `sendto`, `recvfrom`, `send`, `recv` 函数的内联版本。** 这些内联函数的主要目的是在编译时和运行时检测潜在的缓冲区溢出错误。
2. **定义了内部的 `__sendto_chk` 和 `__recvfrom_chk` 函数。** 这些是带有额外大小参数的“checked”版本，用于实现运行时的安全检查。
3. **使用 Clang 的静态分析功能进行编译时检查。**  `__clang_error_if` 宏会在编译时检查用户提供的缓冲区长度是否超过了实际缓冲区的大小。
4. **在运行时执行额外的安全检查（可选）。**  通过 `__ANDROID_API__` 和 `__BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` 宏控制，在满足条件时，会调用 `_chk` 版本进行检查。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 应用程序的网络通信安全。Android 上的应用程序，无论是 Java 层（通过 Android Framework）还是 Native 层（通过 NDK），最终都需要通过底层的系统调用来进行网络操作，比如发送和接收数据。

**举例说明:**

* **Android 应用发送 HTTP 请求:** 当一个 Android 应用使用 `HttpURLConnection` 或 `OkHttp` 等库发送 HTTP 请求时，底层最终会调用到 `socket` 相关的系统调用来发送数据。`sendto` 函数就是用于向指定的网络地址发送数据报。这个文件中的 `sendto` 加固版本可以防止开发者在调用 `sendto` 时，提供的发送数据长度超过了实际分配的缓冲区大小，从而避免潜在的内存安全问题。
* **NDK 开发的游戏进行网络通信:** 使用 NDK 开发的游戏通常会直接使用 socket API 进行网络通信。如果开发者在调用 `recvfrom` 接收网络数据时，提供的缓冲区太小，可能会导致数据丢失或者其他问题。这个文件中的 `recvfrom` 加固版本可以帮助开发者在编译时或运行时发现这种错误。

**详细解释 libc 函数的实现:**

**1. `__sendto_chk(int, const void* _Nonnull, size_t, size_t, int, const struct sockaddr* _Nullable, socklen_t)` 和 `__recvfrom_chk(int, void* _Nullable, size_t, size_t, int, struct sockaddr* _Nullable, socklen_t* _Nullable)`:**

* 这些函数是实际执行带有安全检查的发送和接收操作的函数。
* 它们比标准的 `sendto` 和 `recvfrom` 多了一个 `size_t` 类型的参数，这个参数代表了用户提供的缓冲区的实际大小。
* **实现方式:**  这些 `_chk` 函数在内部会首先检查用户提供的长度参数是否超过了实际的缓冲区大小。如果超过了，它们可能会返回错误，或者触发一个更安全的处理机制（例如，终止程序或记录错误）。如果长度是合法的，它们会调用底层的、未加固的系统调用来执行实际的发送或接收操作。

**2. `recvfrom(int fd, void* _Nullable const buf __pass_object_size0, size_t len, int flags, struct sockaddr* _Nullable src_addr, socklen_t* _Nullable addr_len)` (加固版本):**

```c
__BIONIC_FORTIFY_INLINE
ssize_t recvfrom(int fd, void* _Nullable const buf __pass_object_size0, size_t len, int flags, struct sockaddr* _Nullable src_addr, socklen_t* _Nullable addr_len)
    __overloadable
    __clang_error_if(__bos_unevaluated_lt(__bos0(buf), len),
                     "'recvfrom' called with size bigger than buffer") {
#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
  size_t bos = __bos0(buf);

  if (!__bos_trivially_ge(bos, len)) {
    return __recvfrom_chk(fd, buf, len, bos, flags, src_addr, addr_len);
  }
#endif
  return __call_bypassing_fortify(recvfrom)(fd, buf, len, flags, src_addr, addr_len);
}
```

* **编译时检查 (`__clang_error_if`):**  `__bos0(buf)` 宏会获取 `buf` 指向的缓冲区的实际大小（在编译时已知）。`__bos_unevaluated_lt(__bos0(buf), len)` 检查用户提供的长度 `len` 是否大于缓冲区的大小。如果条件为真，Clang 编译器会产生一个错误，阻止编译通过。这可以在开发阶段尽早发现潜在的缓冲区溢出问题。
* **运行时检查 (`#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED`):**
    * `__bos0(buf)` 在运行时获取缓冲区大小。
    * `__bos_trivially_ge(bos, len)` 检查缓冲区大小 `bos` 是否大于等于用户提供的长度 `len`。
    * 如果缓冲区大小小于提供的长度，则调用 `__recvfrom_chk`，将实际的缓冲区大小 `bos` 传递给它。`__recvfrom_chk` 可以根据实际大小进行更安全的处理。
* **绕过加固的版本 (`__call_bypassing_fortify(recvfrom)`):** 如果运行时检查通过（缓冲区足够大），则直接调用底层的、未加固的 `recvfrom` 系统调用。这避免了额外的检查开销。

**3. `sendto(int fd, const void* _Nonnull const buf __pass_object_size0, size_t len, int flags, const struct sockaddr* _Nullable dest_addr, socklen_t addr_len)` (加固版本):**

实现逻辑与 `recvfrom` 类似，只是针对发送操作。它同样包含编译时和运行时的缓冲区大小检查，并在必要时调用 `__sendto_chk`。

**4. `recv(int socket, void* _Nullable const buf __pass_object_size0, size_t len, int flags)` 和 `send(int socket, const void* _Nonnull const buf __pass_object_size0, size_t len, int flags)` (加固版本):**

这两个函数实际上是对 `recvfrom` 和 `sendto` 的封装，用于面向连接的 socket（不需要指定目标地址）。它们直接调用对应的 `...from` 版本，并将地址相关的参数设置为 `NULL` 和 `0`。同样，它们也包含了缓冲区大小的安全检查。

**涉及 dynamic linker 的功能:**

这个特定的头文件 **不直接** 涉及 dynamic linker 的功能。它定义的是内联函数和一些声明，这些函数最终会链接到 Bionic libc 库中的实现。

然而，理解 `sendto` 和 `recvfrom` 等函数的最终实现，以及 Bionic libc 如何被加载和链接，需要了解 dynamic linker 的作用。

**so 布局样本 (假设一个简单的使用 socket 的程序):**

假设我们有一个名为 `my_app` 的 native 可执行文件，它使用了 `sendto` 函数。

```
/system/bin/my_app  (可执行文件)
/system/lib64/libc.so (Bionic C 库)
/system/lib64/libnetd_client.so (可能间接依赖)
...其他共享库...
```

**链接的处理过程:**

1. **编译时:** 当 `my_app.c` 包含 `<sys/socket.h>` 并调用 `sendto` 时，编译器会解析头文件，并知道 `sendto` 是一个外部函数。链接器会记录下对 `sendto` 的符号引用。
2. **打包时:**  打包工具会将 `my_app` 和它依赖的共享库（包括 `libc.so`）打包到 APK 中。
3. **运行时 (加载时):**
   * Android 的 zygote 进程 fork 出新的应用进程。
   * Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载 `my_app` 可执行文件。
   * linker 解析 `my_app` 的 ELF 头，找到其依赖的共享库列表，其中包括 `libc.so`。
   * linker 加载 `libc.so` 到进程的地址空间。
   * linker 解析 `my_app` 的重定位表，找到对 `sendto` 的符号引用。
   * linker 在 `libc.so` 的符号表中查找 `sendto` 的地址。
   * linker 将 `my_app` 中调用 `sendto` 的指令地址修改为 `libc.so` 中 `sendto` 函数的实际地址，这个过程称为 **符号解析 (symbol resolution)** 或 **重定位 (relocation)**。

**假设输入与输出 (针对加固的 `sendto`):**

**假设输入 (编译时):**

```c
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

int main() {
  int sockfd;
  struct sockaddr_in dest_addr;
  char buffer[10];
  const char* message = "This is a long message";

  // ... 初始化 sockfd 和 dest_addr ...

  // 错误用法：尝试发送比缓冲区大的数据
  sendto(sockfd, message, strlen(message), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

  return 0;
}
```

**编译时输出:**  由于 `strlen(message)` (假设大于 10) 大于 `buffer` 的大小，Clang 编译器会因为 `__clang_error_if` 的检查失败而报错，阻止编译通过，错误信息类似于:

```
error: "'sendto' called with size bigger than buffer"
```

**假设输入 (运行时，假设运行时检查开启):**

```c
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

int main() {
  int sockfd;
  struct sockaddr_in dest_addr;
  char buffer[10];
  const char* message = "Short";

  // ... 初始化 sockfd 和 dest_addr ...

  // 正确用法：发送的数据小于等于缓冲区大小
  ssize_t sent_bytes = sendto(sockfd, message, strlen(message), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

  return 0;
}
```

**运行时输出:**  因为 `strlen(message)` (5) 小于 `buffer` 的大小 (10)，运行时检查会通过，最终会调用底层的 `sendto` 系统调用，成功发送数据。`sent_bytes` 会返回实际发送的字节数 (5)。

**假设输入 (运行时，假设运行时检查开启，但数据过长):**

```c
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

int main() {
  int sockfd;
  struct sockaddr_in dest_addr;
  char buffer[10];
  const char* message = "This is a long message";

  // ... 初始化 sockfd 和 dest_addr ...

  // 错误用法：尝试发送比缓冲区大的数据
  ssize_t sent_bytes = sendto(sockfd, message, strlen(message), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));

  // 此时会调用 __sendto_chk
  return 0;
}
```

**运行时输出:**  运行时检查会发现 `strlen(message)` 大于 `buffer` 的大小。会调用 `__sendto_chk`，该函数可能会：

* **返回错误:** `sent_bytes` 可能返回 -1，并设置 `errno` 为 `EMSGSIZE` 或其他相关错误码。
* **触发安全机制:**  根据 Bionic 的具体实现，可能会有更严格的安全处理，例如终止程序。

**涉及用户或者编程常见的使用错误:**

1. **缓冲区溢出:** 最常见也是这个文件要防止的错误。开发者在调用 `sendto` 或 `recvfrom` 时，提供的长度参数超过了实际分配给缓冲区的空间。
   ```c
   char buffer[10];
   ssize_t bytes_received = recvfrom(sockfd, buffer, 100, 0, ...); // 错误：尝试接收 100 字节到 10 字节的缓冲区
   ```
2. **未初始化缓冲区:** 在发送数据前，忘记初始化要发送的缓冲区，导致发送不期望的数据。
3. **接收缓冲区过小:** 在接收数据时，提供的缓冲区太小，导致数据被截断或者接收失败。
4. **错误的长度计算:** 在调用 `sendto` 时，错误地计算了要发送的数据长度。
5. **忘记处理返回值:** 没有检查 `sendto` 或 `recvfrom` 的返回值，忽略了可能发生的错误。

**Android framework or ndk 是如何一步步的到达这里:**

1. **Java 层 Framework (例如发送网络请求):**
   * 应用层代码使用 `HttpURLConnection`, `OkHttp`, 或其他网络库。
   * 这些库最终会调用到 Android Framework 层的网络相关服务 (例如 `ConnectivityService`, `NetworkStackService`)。
   * Framework 层会创建 `Socket` 对象，并调用其 `getOutputStream()` 或 `getInputStream()` 方法。
   * 这些 Stream 的底层实现会使用 Java Native Interface (JNI) 调用到 Native 代码。

2. **NDK 层 (直接使用 Socket API):**
   * Native 代码直接包含 `<sys/socket.h>` 头文件。
   * Native 代码调用 `socket()`, `bind()`, `connect()`, `sendto()`, `recvfrom()` 等 socket 相关函数。

3. **Bionic libc:**
   * 当 NDK 代码调用 `sendto()` 时，实际上会调用到 Bionic libc 中 `bits/fortify/socket.handroid.h` 定义的加固版本 `sendto` 内联函数。
   * 加固版本可能会执行编译时或运行时的检查。
   * 如果检查通过，最终会调用 Bionic libc 中 `unistd/sendto.c` 或类似文件中实现的底层的 `sendto` 系统调用包装函数（可能会绕过加固版本）。
   * Bionic libc 的这些函数会使用 `syscall()` 指令触发内核态的系统调用。

4. **Linux Kernel:**
   * Linux 内核接收到 `sendto` 系统调用请求。
   * 内核执行实际的网络数据发送操作。
   * 内核将数据发送到网络协议栈，最终通过网络接口发送出去。

**Frida hook 示例调试这些步骤:**

假设我们要 hook `sendto` 函数，观察其参数和返回值。

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received message:")
        print(message['payload'])

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "sendto"), {
  onEnter: function(args) {
    console.log("[Sendto] Called");
    console.log("  fd:", args[0]);
    console.log("  buf:", args[1]);
    console.log("  len:", args[2]);
    console.log("  flags:", args[3]);
    // 可以读取发送的数据内容 (小心长度)
    // console.log("  data:", Memory.readUtf8String(args[1], args[2].toInt()));
  },
  onLeave: function(retval) {
    console.log("[Sendto] Return value:", retval);
  }
});

// 如果要 hook 加固版本的 sendto (内联函数可能不容易直接 hook，可以尝试 hook __sendto_chk)
Interceptor.attach(Module.findExportByName("libc.so", "__sendto_chk"), {
  onEnter: function(args) {
    console.log("[__sendto_chk] Called");
    console.log("  fd:", args[0]);
    console.log("  buf:", args[1]);
    console.log("  len:", args[2]);
    console.log("  size:", args[3]); // 注意：__sendto_chk 多了一个 size 参数
    console.log("  flags:", args[4]);
    // ...
  },
  onLeave: function(retval) {
    console.log("[__sendto_chk] Return value:", retval);
  }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**Frida Hook 示例说明:**

* **`frida.get_usb_device().attach(package_name)`:**  连接到 USB 设备上运行的目标应用进程。
* **`Interceptor.attach(Module.findExportByName("libc.so", "sendto"), ...)`:**  Hook Bionic libc 中名为 `sendto` 的导出函数。`onEnter` 函数在 `sendto` 被调用前执行，可以打印参数；`onLeave` 函数在 `sendto` 返回后执行，可以打印返回值。
* **`Module.findExportByName("libc.so", "__sendto_chk")`:**  尝试 hook `__sendto_chk` 函数。由于加固版本的 `sendto` 是内联的，直接 hook 它可能比较困难。Hook `__sendto_chk` 可以观察到运行时检查被触发的情况。
* **`Memory.readUtf8String(args[1], args[2].toInt())`:**  可以尝试读取发送缓冲区的内容，但要注意 `args[2]` 是长度，需要转换为整数。
* **`script.load()` 和 `sys.stdin.read()`:**  加载 Frida 脚本并保持运行状态，直到用户按下 Ctrl+D。

通过 Frida hook，你可以观察到 `sendto` 或 `__sendto_chk` 何时被调用，查看传递给它们的参数（包括文件描述符、缓冲区指针、长度等），以及它们的返回值，从而调试网络通信过程和安全加固机制的运作情况。

### 提示词
```
这是目录为bionic/libc/include/bits/fortify/socket.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _SYS_SOCKET_H_
#error "Never include this file directly; instead, include <sys/socket.h>"
#endif


#if __BIONIC_AVAILABILITY_GUARD(26)
ssize_t __sendto_chk(int, const void* _Nonnull, size_t, size_t, int, const struct sockaddr* _Nullable, socklen_t) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */

ssize_t __recvfrom_chk(int, void* _Nullable, size_t, size_t, int, struct sockaddr* _Nullable, socklen_t* _Nullable);

#if defined(__BIONIC_FORTIFY)

__BIONIC_FORTIFY_INLINE
ssize_t recvfrom(int fd, void* _Nullable const buf __pass_object_size0, size_t len, int flags, struct sockaddr* _Nullable src_addr, socklen_t* _Nullable addr_len)
    __overloadable
    __clang_error_if(__bos_unevaluated_lt(__bos0(buf), len),
                     "'recvfrom' called with size bigger than buffer") {
#if __ANDROID_API__ >= 24 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
  size_t bos = __bos0(buf);

  if (!__bos_trivially_ge(bos, len)) {
    return __recvfrom_chk(fd, buf, len, bos, flags, src_addr, addr_len);
  }
#endif
  return __call_bypassing_fortify(recvfrom)(fd, buf, len, flags, src_addr, addr_len);
}

__BIONIC_FORTIFY_INLINE
ssize_t sendto(int fd, const void* _Nonnull const buf __pass_object_size0, size_t len, int flags, const struct sockaddr* _Nullable dest_addr, socklen_t addr_len)
    __overloadable
    __clang_error_if(__bos_unevaluated_lt(__bos0(buf), len),
                     "'sendto' called with size bigger than buffer") {
#if __ANDROID_API__ >= 26 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
  size_t bos = __bos0(buf);

  if (!__bos_trivially_ge(bos, len)) {
    return __sendto_chk(fd, buf, len, bos, flags, dest_addr, addr_len);
  }
#endif
  return __call_bypassing_fortify(sendto)(fd, buf, len, flags, dest_addr, addr_len);
}

__BIONIC_FORTIFY_INLINE
ssize_t recv(int socket, void* _Nullable const buf __pass_object_size0, size_t len, int flags)
    __overloadable
    __clang_error_if(__bos_unevaluated_lt(__bos0(buf), len),
                     "'recv' called with size bigger than buffer") {
  return recvfrom(socket, buf, len, flags, NULL, 0);
}

__BIONIC_FORTIFY_INLINE
ssize_t send(int socket, const void* _Nonnull const buf __pass_object_size0, size_t len, int flags)
    __overloadable
    __clang_error_if(__bos_unevaluated_lt(__bos0(buf), len),
                     "'send' called with size bigger than buffer") {
  return sendto(socket, buf, len, flags, NULL, 0);
}

#endif /* __BIONIC_FORTIFY */
```