Response:
Let's break down the thought process for analyzing this C test file.

**1. Understanding the Goal:**

The core request is to analyze `bionic/tests/headers/posix/netinet_in_h.c` and explain its purpose, its relation to Android, its internal workings (where applicable), and provide usage examples and debugging strategies. The file itself is a test file, so the interpretation needs to center around *testing* rather than *implementation*.

**2. Initial Observation and Interpretation:**

The filename immediately suggests this file is a test for the `netinet/in.h` header file within the Android Bionic library. The `#include <netinet/in.h>` confirms this. The rest of the code looks like a series of checks using `TYPE`, `STRUCT_MEMBER`, `MACRO`, `MACRO_VALUE`, and `FUNCTION`. These are not standard C keywords, strongly implying they are macros defined in `header_checks.h`.

**3. Deciphering the Test Logic (Key Insight):**

The crucial step is understanding what `TYPE`, `STRUCT_MEMBER`, etc., *do*. Since it's a test file, these macros are likely designed to check for the *existence* and *correct definition* of types, structure members, macros, and functions within the included header. They are probably designed to cause a compilation error if something is missing or incorrectly defined.

**4. Categorizing the Elements Being Tested:**

Looking at the arguments passed to these macros, we can categorize what aspects of `netinet/in.h` are being tested:

* **Basic Types:** `in_port_t`, `in_addr_t`, `sa_family_t`, `uint8_t`, `uint32_t`.
* **Structures:** `struct in_addr`, `struct sockaddr_in`, `struct in6_addr`, `struct sockaddr_in6`, `struct ipv6_mreq`.
* **Structure Members:** Individual fields within the structures (e.g., `sin_family`, `s_addr`).
* **Global Variables (treated like macros here):** `in6addr_any`, `in6addr_loopback`.
* **Macros:** Constants defined using `#define` (e.g., `IPPROTO_TCP`, `INADDR_ANY`).
* **Macro Values:** Macros that should have specific integer values (e.g., `INET_ADDRSTRLEN`, `INET6_ADDRSTRLEN`).
* **Functions (by signature):** `htonl`, `htons`, `ntohl`, `ntohs`.
* **Specific Conditionals (using `#if !defined`):** Presence of specific macros like `IN6_IS_ADDR_UNSPECIFIED`.

**5. Relating to Android Functionality:**

`netinet/in.h` is a fundamental header for network programming. Android uses it extensively for:

* **Networking Stack:**  Low-level network operations, IP addressing, port numbers.
* **Sockets:**  Creating and managing network connections.
* **Inter-Process Communication (IPC):** Using network sockets for communication between apps and system services.

Examples are relatively straightforward: An app connecting to a web server uses `sockaddr_in` to specify the server's IP and port. System services might use `in6_addr` for IPv6 communication.

**6. Explaining Libc Functions (Focus on the Test Context):**

The test file *declares* the function signatures but doesn't show their *implementation*. Therefore, the explanation should focus on their *purpose* in network programming:

* `htonl`, `htons`: Host-to-network byte order conversion.
* `ntohl`, `ntohs`: Network-to-host byte order conversion.

The *how* they are implemented is not relevant to *this specific test file*.

**7. Addressing Dynamic Linker:**

This test file doesn't directly involve the dynamic linker. It checks header file definitions. However, the functions declared here (`htonl`, etc.) *are* implemented in libc.so, and the dynamic linker is responsible for loading libc.so and resolving these symbols when an application uses them. The SO layout and linking process explanation should be general, covering how dynamic linking works in Android.

**8. Hypothetical Inputs and Outputs (Limited Scope):**

Since this is a test file, the "input" is the *presence* or *absence* of the definitions in `netinet/in.h`. The "output" is either successful compilation (if everything is defined correctly) or a compilation error (if something is missing).

**9. Common User Errors:**

Relate common errors to the *concepts* tested in the header, such as incorrect byte order when sending data over the network, or using the wrong address family.

**10. Android Framework/NDK and Frida Hooking:**

The goal here is to trace how the header gets used.

* **Framework:** An Android app making a network request ultimately uses Java APIs that call native code, eventually reaching libc functions.
* **NDK:** NDK developers directly use the header and its functions.
* **Frida:**  Show how to hook a function declared in the header (like `connect`) to see the `sockaddr_in` structure being passed.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe the test file *implements* some of these functions for testing. **Correction:**  No, the `FUNCTION` macro with the signature implies it's checking for the *existence* and *correct type signature* of functions defined elsewhere.
* **Initial thought:** Focus heavily on the internal implementation of `htonl`, etc. **Correction:** The question asks about this *file's* function. This file's function is *testing* their existence, not implementing them. Focus on their *purpose*.
* **Initial thought:** Provide very specific Frida scripts. **Refinement:**  Provide general examples that illustrate the *principle* of hooking relevant functions.

By following these steps, focusing on the nature of the file as a *test*, and connecting the tested elements to real-world Android scenarios, we arrive at a comprehensive and accurate explanation.
这个文件 `bionic/tests/headers/posix/netinet_in_h.c` 的主要功能是**测试 Android Bionic 库中 `netinet/in.h` 头文件的内容是否符合 POSIX 标准以及 Android 的特定要求。**

它并不实现任何网络功能，而是一个**测试文件**，用于确保 `netinet/in.h` 头文件中定义了预期的类型、结构体、结构体成员、宏定义和函数声明。

**具体功能分解：**

1. **类型检查 (`TYPE`)**:  验证 `netinet/in.h` 中是否定义了特定的数据类型，例如 `in_port_t`（端口号类型）、`in_addr_t`（IPv4地址类型）、`sa_family_t`（地址族类型）等。如果类型未定义，会导致编译错误。
2. **结构体成员检查 (`STRUCT_MEMBER`)**: 验证特定结构体中是否存在指定的成员变量，并且成员变量的类型是否正确。例如，它会检查 `struct sockaddr_in` 结构体是否包含 `sin_family`、`sin_port` 和 `sin_addr` 成员，并且它们的类型分别是 `sa_family_t`、`in_port_t` 和 `struct in_addr`。
3. **结构体数组成员检查 (`STRUCT_MEMBER_ARRAY`)**: 类似于 `STRUCT_MEMBER`，但用于检查结构体中的数组成员。例如，检查 `struct in6_addr` 中的 `s6_addr` 数组。
4. **宏定义检查 (`MACRO`)**:  验证 `netinet/in.h` 中是否定义了特定的宏。例如，检查是否存在 `IPPROTO_TCP`、`INADDR_ANY` 等宏。
5. **宏值检查 (`MACRO_VALUE`)**: 验证宏定义的值是否符合预期。例如，检查 `INET_ADDRSTRLEN` 的值是否为 16。
6. **函数声明检查 (`FUNCTION`)**: 验证 `netinet/in.h` 中是否声明了特定的函数，并检查其函数签名（参数和返回值类型）是否正确。例如，它会检查 `htonl`、`htons`、`ntohl` 和 `ntohs` 函数的声明。
7. **特定宏未定义检查 (`#if !defined`)**: 验证某些特定的宏是否*没有*被定义。这通常用于检查某些在特定条件下才应该定义的宏。

**与 Android 功能的关系及举例说明：**

`netinet/in.h` 是网络编程的基础头文件，Android 作为支持网络功能的操作系统，自然需要它。这个测试文件确保了 Bionic 提供的 `netinet/in.h` 与标准和 Android 的需求一致。

* **网络编程 API:** Android 的 Java 网络 API (例如 `java.net.Socket`, `java.net.ServerSocket`) 底层会调用 Native 代码，而这些 Native 代码会使用 `netinet/in.h` 中定义的结构体和常量。例如，创建一个 socket 并绑定到特定端口需要使用 `sockaddr_in` 结构体，其中 `sin_family` 设置为 `AF_INET` (通过 `netinet/in.h` 引入)，`sin_port` 设置为端口号（`in_port_t` 类型）。
* **NDK 开发:**  使用 Android NDK 进行 Native 开发的开发者可以直接包含 `netinet/in.h` 来进行底层的网络编程。他们会使用这里定义的结构体、宏和函数来操作 IP 地址、端口等。
* **系统服务:** Android 的一些系统服务，例如网络相关的守护进程 (daemons)，也可能使用这些定义来进行网络通信。

**libc 函数功能解释：**

这个测试文件本身不实现 libc 函数，它只是检查这些函数是否在头文件中声明了。这些函数的实际实现在 Bionic 的 libc 库中。

* **`htonl(uint32_t hostlong)` (Host to Network Long):**
    * **功能:** 将主机字节序的 32 位无符号长整型数转换为网络字节序。网络字节序通常是大端序 (Big-Endian)，而主机字节序可能是大端或小端序 (Little-Endian)。
    * **实现:**  通常会检查当前主机的字节序，如果是小端序，则需要将字节顺序反转。如果是大端序，则直接返回。
    * **Android 关系:**  在网络编程中，为了保证不同架构的机器之间能够正确地解析多字节数据（如 IP 地址），需要在发送数据前将数据转换为网络字节序。
    * **假设输入与输出:**
        * **假设输入 (小端主机):** `0x12345678`
        * **输出 (网络字节序):** `0x78563412`
* **`htons(uint16_t hostshort)` (Host to Network Short):**
    * **功能:** 将主机字节序的 16 位无符号短整型数转换为网络字节序。
    * **实现:** 类似于 `htonl`，但操作的是 16 位数据。
    * **Android 关系:** 用于转换端口号等 16 位的网络数据。
    * **假设输入 (小端主机):** `0x1234`
    * **输出 (网络字节序):** `0x3412`
* **`ntohl(uint32_t netlong)` (Network to Host Long):**
    * **功能:** 将网络字节序的 32 位无符号长整型数转换为主机字节序。
    * **实现:**  与 `htonl` 相反的操作。
    * **Android 关系:**  在接收到网络数据后，需要将其转换为主机字节序才能正确使用。
    * **假设输入 (网络字节序):** `0x78563412`
    * **输出 (小端主机):** `0x12345678`
* **`ntohs(uint16_t netshort)` (Network to Host Short):**
    * **功能:** 将网络字节序的 16 位无符号短整型数转换为主机字节序。
    * **实现:**  与 `htons` 相反的操作。
    * **Android 关系:** 用于转换接收到的端口号等 16 位网络数据。
    * **假设输入 (网络字节序):** `0x3412`
    * **输出 (小端主机):** `0x1234`

**涉及 dynamic linker 的功能：**

这个测试文件本身并不直接涉及 dynamic linker 的功能。它主要关注头文件的定义。但是，上述的 `htonl`、`htons`、`ntohl` 和 `ntohs` 函数的实现是在 `libc.so` 中。当应用程序需要调用这些函数时，dynamic linker (在 Android 上是 `linker64` 或 `linker`) 负责在运行时加载 `libc.so` 并解析这些函数的符号地址，以便程序能够正确调用它们。

**so 布局样本 (针对 `libc.so`)：**

```
Load map:
0000007b8d000000-0000007b8d1f0000 r--p 00000000 b4:08 13424      /apex/com.android.runtime/lib64/bionic/libc.so
0000007b8d1f0000-0000007b8d3c4000 r-xp 001f0000 b4:08 13424      /apex/com.android.runtime/lib64/bionic/libc.so
0000007b8d3c4000-0000007b8d4b5000 r--p 003c4000 b4:08 13424      /apex/com.android.runtime/lib64/bionic/libc.so
0000007b8d4b5000-0000007b8d4c2000 r--p 004b5000 b4:08 13424      /apex/com.android.runtime/lib64/bionic/libc.so
0000007b8d4c2000-0000007b8d4f7000 rw-p 004c2000 b4:08 13424      /apex/com.android.runtime/lib64/bionic/libc.so
... (其他 sections)
```

**链接的处理过程：**

1. **编译时:** 编译器在编译应用程序的代码时，如果遇到了对 `htonl` 等函数的调用，会在生成的目标文件 (`.o`) 中生成一个未解析的符号引用。
2. **链接时 (静态链接，不常用):** 如果是静态链接，链接器会将 `libc.a` (静态库) 中的函数代码直接复制到最终的可执行文件中。
3. **运行时 (动态链接，Android 使用):**
    * 当应用程序启动时，操作系统会加载应用程序的可执行文件。
    * Dynamic linker 会被操作系统启动。
    * Dynamic linker 读取应用程序的 ELF header，找到需要加载的共享库列表 (例如 `libc.so`)。
    * Dynamic linker 加载这些共享库到内存中。
    * Dynamic linker 解析应用程序中未解析的符号引用 (例如 `htonl`)。它会在加载的共享库的符号表 (`.dynsym` section) 中查找匹配的符号。
    * 找到符号后，Dynamic linker 会将应用程序中对该符号的引用重定向到共享库中该符号的实际地址。这个过程称为**符号解析**或**重定位**。
    * 之后，应用程序调用 `htonl` 函数时，实际上会跳转到 `libc.so` 中该函数的代码执行。

**用户或编程常见的使用错误：**

1. **忘记进行字节序转换:**  在网络编程中，如果不使用 `htonl` 和 `htons` 将主机字节序转换为网络字节序，或者不使用 `ntohl` 和 `ntohs` 将网络字节序转换为主机字节序，可能会导致在不同字节序的机器之间通信时数据解析错误。
    * **错误示例:**
      ```c
      struct sockaddr_in server_addr;
      server_addr.sin_family = AF_INET;
      server_addr.sin_port = 80; // 错误！应该使用 htons(80)
      server_addr.sin_addr.s_addr = inet_addr("192.168.1.100");
      ```
2. **错误地假设网络字节序:** 有些开发者可能会错误地假设网络字节序总是大端序，并手动进行字节反转，而不是使用标准的转换函数。虽然网络字节序确实通常是大端序，但使用标准函数更具有可移植性。
3. **结构体成员访问错误:**  错误地访问 `sockaddr_in` 或 `sockaddr_in6` 结构体的成员，例如访问不存在的成员或使用错误的类型。
4. **宏定义使用错误:**  错误地使用 `netinet/in.h` 中定义的宏，例如将端口号直接赋值为宏的值，而没有理解宏的含义。

**Android framework 或 NDK 如何到达这里：**

**Android Framework 到 `netinet/in.h` 的路径：**

1. **Java 网络 API 调用:**  Android 应用程序通常使用 Java 网络 API (位于 `java.net` 包下) 进行网络操作，例如 `Socket`、`ServerSocket`、`HttpURLConnection` 等。
2. **Native 方法调用:** 这些 Java 类的方法最终会调用 Android 平台的 Native 代码。例如，`java.net.Socket.connect()` 方法会调用 Native 方法 `connect0()`。
3. **`libjavacrypto.so` 或其他 Native 库:**  这些 Native 方法的实现可能在 `libjavacrypto.so` 或其他与网络相关的 Native 库中。
4. **系统调用包装:** 这些 Native 代码最终会调用 Linux 内核提供的系统调用，例如 `connect()`、`bind()`、`sendto()` 等。
5. **Bionic libc:** Bionic libc 提供了这些系统调用的 C 语言包装函数。例如，`connect()` 系统调用的 C 语言包装函数也在 Bionic libc 中。
6. **`netinet/in.h` 的使用:**  Bionic libc 的网络相关函数实现会包含 `netinet/in.h` 头文件，以使用其中定义的结构体 (`sockaddr_in`, `sockaddr_in6`) 和常量 (`AF_INET`, `SOCK_STREAM` 等)。

**NDK 到 `netinet/in.h` 的路径：**

1. **NDK 代码 `#include <netinet/in.h>`:**  使用 Android NDK 进行 Native 开发时，开发者可以在 C/C++ 代码中直接包含 `<netinet/in.h>` 头文件。
2. **使用网络编程 API:**  开发者可以直接使用 POSIX 标准的 socket API (例如 `socket()`, `bind()`, `connect()`, `send()`, `recv()`)，这些 API 的参数和数据结构都依赖于 `netinet/in.h` 中定义的类型和结构体。
3. **编译和链接:**  使用 NDK 构建工具链编译和链接 Native 代码时，编译器会处理 `#include <netinet/in.h>` 指令，并将相关的符号引用到 Bionic libc。

**Frida hook 示例调试步骤：**

假设我们想观察一个应用程序在建立 TCP 连接时传递给 `connect()` 系统调用的 `sockaddr_in` 结构体内容。

**Frida Hook 代码 (JavaScript):**

```javascript
if (ObjC.available) {
    // 如果是 Objective-C 应用
    var connect = Module.findExportByName(null, "connect");
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                var sockfd = args[0].toInt32();
                var addrPtr = args[1];
                var addrlen = args[2].toInt32();

                if (addrlen == 16) { // sizeof(struct sockaddr_in)
                    console.log("connect() called with sockfd:", sockfd);

                    var sockaddr_in = Memory.readByteArray(addrPtr, addrlen);
                    console.log("sockaddr_in:", hexdump(sockaddr_in, { ansi: true }));

                    // 解析 sockaddr_in 结构体
                    var sin_family = Memory.readU16(addrPtr);
                    var sin_port = Memory.readU16(addrPtr.add(2));
                    var sin_addr = Memory.readU32(addrPtr.add(4));

                    console.log("sin_family:", sin_family);
                    console.log("sin_port (network byte order):", sin_port);
                    console.log("sin_port (host byte order):", ntohs(sin_port));
                    console.log("sin_addr (network byte order):", sin_addr);
                    console.log("sin_addr (dotted decimal):", inet_ntoa({ s_addr: sin_addr }));
                }
            }
        });
    }
} else if (Process.platform === 'android') {
    // 如果是 Android 应用
    var connect = Module.findExportByName("libc.so", "connect");
    if (connect) {
        Interceptor.attach(connect, {
            onEnter: function(args) {
                var sockfd = args[0].toInt32();
                var addrPtr = args[1];
                var addrlen = args[2].toInt32();

                if (addrlen == 16) { // sizeof(struct sockaddr_in)
                    console.log("connect() called with sockfd:", sockfd);

                    var sockaddr_in = Memory.readByteArray(addrPtr, addrlen);
                    console.log("sockaddr_in:", hexdump(sockaddr_in, { ansi: true }));

                    // 解析 sockaddr_in 结构体
                    var sin_family = Memory.readU16(addrPtr);
                    var sin_port = Memory.readU16(addrPtr.add(2));
                    var sin_addr = Memory.readU32(addrPtr.add(4));

                    console.log("sin_family:", sin_family);
                    console.log("sin_port (network byte order):", sin_port);
                    console.log("sin_port (host byte order):", ntohs(sin_port));
                    console.log("sin_addr (network byte order):", sin_addr);

                    // 需要自己实现 inet_ntoa 或者使用其他库
                    // 这里简单打印数值
                    console.log("sin_addr:", sin_addr);
                }
            }
        });
    }
}

// 辅助函数 (需要自己实现或引入)
function ntohs(n) {
  return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF);
}

// ... (inet_ntoa 的实现，可以将 IP 地址的数值转换为点分十进制字符串)
```

**调试步骤：**

1. **准备 Frida 环境:** 确保已安装 Frida 和 Frida-Server，并且 Frida-Server 正在目标 Android 设备上运行。
2. **运行目标应用:** 启动你想要调试的 Android 应用程序。
3. **运行 Frida Hook 脚本:** 使用 Frida 命令将上述 JavaScript 代码注入到目标应用程序的进程中。
   ```bash
   frida -U -f <package_name> -l your_script.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <package_name> -l your_script.js
   ```
4. **触发网络连接:** 在应用程序中执行会导致建立网络连接的操作，例如访问一个网站或连接到服务器。
5. **查看 Frida 输出:** Frida 会拦截对 `connect()` 函数的调用，并在控制台上打印出 `sockfd`、`sockaddr_in` 结构体的原始字节数据以及解析后的结构体成员值，包括地址族、端口号（网络字节序和主机字节序）和 IP 地址（网络字节序）。

通过这种方式，你可以动态地观察应用程序在进行网络操作时传递给底层系统调用的参数，从而理解 Android framework 或 NDK 如何使用 `netinet/in.h` 中定义的结构体。

### 提示词
```
这是目录为bionic/tests/headers/posix/netinet_in_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <netinet/in.h>

#include "header_checks.h"

static void netinet_in_h() {
  TYPE(in_port_t);
  TYPE(in_addr_t);
  TYPE(sa_family_t);
  TYPE(uint8_t);
  TYPE(uint32_t);

  TYPE(struct in_addr);
  STRUCT_MEMBER(struct in_addr, in_addr_t, s_addr);

  TYPE(struct sockaddr_in);
  STRUCT_MEMBER(struct sockaddr_in, sa_family_t, sin_family);
  STRUCT_MEMBER(struct sockaddr_in, in_port_t, sin_port);
  STRUCT_MEMBER(struct sockaddr_in, struct in_addr, sin_addr);

  TYPE(struct in6_addr);
  STRUCT_MEMBER_ARRAY(struct in6_addr, uint8_t/*[]*/, s6_addr);

  TYPE(struct sockaddr_in6);
  STRUCT_MEMBER(struct sockaddr_in6, sa_family_t, sin6_family);
  STRUCT_MEMBER(struct sockaddr_in6, in_port_t, sin6_port);
  STRUCT_MEMBER(struct sockaddr_in6, uint32_t, sin6_flowinfo);
  STRUCT_MEMBER(struct sockaddr_in6, struct in6_addr, sin6_addr);
  STRUCT_MEMBER(struct sockaddr_in6, uint32_t, sin6_scope_id);

  struct in6_addr any_global = in6addr_any;
  struct in6_addr any_macro = IN6ADDR_ANY_INIT;
  struct in6_addr loop_global = in6addr_loopback;
  struct in6_addr loop_macro = IN6ADDR_LOOPBACK_INIT;

  TYPE(struct ipv6_mreq);
  STRUCT_MEMBER(struct ipv6_mreq, struct in6_addr, ipv6mr_multiaddr);
#if defined(__BIONIC__) // Currently comes from uapi header.
  STRUCT_MEMBER(struct ipv6_mreq, int, ipv6mr_interface);
#else
  STRUCT_MEMBER(struct ipv6_mreq, unsigned, ipv6mr_interface);
#endif

  MACRO(IPPROTO_IP);
  MACRO(IPPROTO_IPV6);
  MACRO(IPPROTO_ICMP);
  MACRO(IPPROTO_RAW);
  MACRO(IPPROTO_TCP);
  MACRO(IPPROTO_UDP);

  MACRO(INADDR_ANY);
  MACRO(INADDR_BROADCAST);

  MACRO_VALUE(INET_ADDRSTRLEN, 16);

  FUNCTION(htonl, uint32_t (*f)(uint32_t));
  FUNCTION(htons, uint16_t (*f)(uint16_t));
  FUNCTION(ntohl, uint32_t (*f)(uint32_t));
  FUNCTION(ntohs, uint16_t (*f)(uint16_t));

  MACRO_VALUE(INET6_ADDRSTRLEN, 46);

  MACRO(IPV6_JOIN_GROUP);
  MACRO(IPV6_LEAVE_GROUP);
  MACRO(IPV6_MULTICAST_HOPS);
  MACRO(IPV6_MULTICAST_IF);
  MACRO(IPV6_MULTICAST_LOOP);
  MACRO(IPV6_UNICAST_HOPS);
  MACRO(IPV6_V6ONLY);

#if !defined(IN6_IS_ADDR_UNSPECIFIED)
#error IN6_IS_ADDR_UNSPECIFIED
#endif
#if !defined(IN6_IS_ADDR_LOOPBACK)
#error IN6_IS_ADDR_LOOPBACK
#endif
#if !defined(IN6_IS_ADDR_MULTICAST)
#error IN6_IS_ADDR_MULTICAST
#endif
#if !defined(IN6_IS_ADDR_LINKLOCAL)
#error IN6_IS_ADDR_LINKLOCAL
#endif
#if !defined(IN6_IS_ADDR_SITELOCAL)
#error IN6_IS_ADDR_SITELOCAL
#endif
#if !defined(IN6_IS_ADDR_V4MAPPED)
#error IN6_IS_ADDR_V4MAPPED
#endif
#if !defined(IN6_IS_ADDR_V4COMPAT)
#error IN6_IS_ADDR_V4COMPAT
#endif
#if !defined(IN6_IS_ADDR_MC_NODELOCAL)
#error IN6_IS_ADDR_MC_NODELOCAL
#endif
#if !defined(IN6_IS_ADDR_MC_LINKLOCAL)
#error IN6_IS_ADDR_MC_LINKLOCAL
#endif
#if !defined(IN6_IS_ADDR_MC_SITELOCAL)
#error IN6_IS_ADDR_MC_SITELOCAL
#endif
#if !defined(IN6_IS_ADDR_MC_ORGLOCAL)
#error IN6_IS_ADDR_MC_ORGLOCAL
#endif
#if !defined(IN6_IS_ADDR_MC_GLOBAL)
#error IN6_IS_ADDR_MC_GLOBAL
#endif
}
```