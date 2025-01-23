Response:
Let's break down the thought process for generating the response to your request about `bionic/tests/ifaddrs_test.cpp`.

**1. Understanding the Core Request:**

The fundamental goal is to analyze a C++ test file within the Android Bionic library and explain its purpose, functionality, and connections to the broader Android ecosystem. The request has several specific sub-questions that guide the analysis.

**2. Initial Analysis of the Code:**

* **Identify the Test Subject:** The filename `ifaddrs_test.cpp` and the inclusion of `<ifaddrs.h>` immediately tell us that this file tests the `getifaddrs` and `freeifaddrs` functions, which are standard POSIX functions for retrieving network interface addresses.

* **Recognize the Testing Framework:** The inclusion of `<gtest/gtest.h>` indicates the use of Google Test as the testing framework. This means the core logic will be within `TEST()` macros.

* **Scan the Tests:** Quickly read through each `TEST()` block to get a high-level understanding of what each test verifies. Keywords like "null," "lo" (loopback), "interfaces," "INET," "scope_ids," "kernel_bug," and "errno" provide clues.

* **Identify Key System Calls and Libraries:** Note the inclusion of headers like `<dirent.h>`, `<fcntl.h>`, `<net/ethernet.h>`, `<net/if.h>`, `<netdb.h>`, `<netinet/in.h>`, `<sys/ioctl.h>`, `<linux/if.h>`, and `<linux/if_packet.h>`. This reveals the system calls and data structures involved in network interface management, especially `ioctl`.

**3. Addressing the Specific Questions Systematically:**

* **Functionality Listing:**  Based on the test names and the code within each `TEST()` block, create a concise list of the test file's functions. Focus on what aspects of `getifaddrs` are being verified (e.g., handling null pointers, loopback interface, consistency with `/sys/class/net`, IPv4/IPv6/AF_PACKET addresses, scope IDs, error handling).

* **Relationship to Android:**  Think about *why* these tests are important for Android. Android relies on networking, and `getifaddrs` is a fundamental function for managing network connections. Examples include Wi-Fi, mobile data, and the loopback interface for internal communication.

* **Explanation of `libc` Functions:** Focus on the core `libc` functions used in the tests: `getifaddrs`, `freeifaddrs`, `strcmp`, `socket`, `ioctl`, `open`, `close`, `opendir`, `readdir`, `getnameinfo`, `strerror`, `gai_strerror`. Explain their purpose in the context of network interface information retrieval. *Self-correction:* Initially, I might just define the functions generically. The key is to contextualize their use *within* the `ifaddrs_test.cpp` file.

* **Dynamic Linker (Limited Relevance):**  While the file is part of Bionic, it doesn't directly test dynamic linking. Acknowledge this but explain that `getifaddrs` and related functions are part of `libc.so`, which *is* a dynamically linked library. Provide a basic `libc.so` layout example and the general linking process. Emphasize that this test file itself doesn't exercise the dynamic linker directly.

* **Logical Inference (Assumptions and Outputs):** For some tests, you can infer input and expected output. For example, the `freeifaddrs_null` test assumes a null pointer as input and expects no crash. The `getifaddrs_lo` test assumes a loopback interface exists and expects specific IP addresses.

* **Common Usage Errors:**  Think about how developers might misuse `getifaddrs` and `freeifaddrs`. Forgetting to call `freeifaddrs` leads to memory leaks. Not checking the return value of `getifaddrs` can lead to crashes.

* **Android Framework/NDK Path:**  Trace the high-level path from an Android app using network functionality down to `getifaddrs`. Start with Java APIs, then the NDK, and finally the Bionic `libc`.

* **Frida Hook Examples:** Provide practical Frida examples for intercepting `getifaddrs` and related calls, demonstrating how to inspect arguments and return values. Include examples for both synchronous and asynchronous hooking.

**4. Structuring the Response:**

Organize the information logically, following the structure of the original request. Use clear headings and subheadings. Provide code examples where relevant.

**5. Refining and Reviewing:**

* **Clarity and Accuracy:** Ensure the explanations are easy to understand and technically correct. Double-check the function descriptions and code examples.
* **Completeness:** Make sure all parts of the original request are addressed.
* **Conciseness:** Avoid unnecessary jargon or overly verbose explanations.
* **Language:** Use the requested language (Chinese).

**Self-Correction Example During the Process:**

While explaining the dynamic linker, I might initially focus on complex linking scenarios. However, recognizing that *this specific test file* doesn't heavily involve the dynamic linker, I'd adjust the explanation to be more focused on the fact that `libc.so` itself is dynamically linked and where `getifaddrs` resides within it. This avoids going into unnecessary detail about symbol resolution for this particular analysis.

By following this structured approach, combining code analysis with an understanding of the underlying concepts and the specific requirements of the request, it's possible to generate a comprehensive and accurate response.
好的，让我们详细分析一下 `bionic/tests/ifaddrs_test.cpp` 这个文件。

**功能概述**

这个 C++ 文件是 Android Bionic 库中的一个测试文件，专门用于测试 `ifaddrs.h` 头文件中定义的网络接口地址相关的函数，主要是 `getifaddrs()` 和 `freeifaddrs()`。  其主要功能可以归纳为：

1. **`freeifaddrs(nullptr)` 的安全性测试:** 验证 `freeifaddrs()` 函数在接收到空指针时不会崩溃。
2. **`getifaddrs()` 的基本功能测试:**
   - 验证 `getifaddrs()` 能成功返回一个非空的 `ifaddrs` 结构体链表。
   - 针对 loopback 接口 ("lo") 进行特定属性的验证，例如是否存在 IPv4、IPv6 和 AF_PACKET 类型的地址，以及这些地址的值是否正确（例如 IPv4 的 127.0.0.1，IPv6 的 ::1）。
3. **网络接口列表一致性测试:** 验证 `getifaddrs()` 返回的网络接口列表与 `/sys/class/net` 目录下的内容是否一致，确保系统报告的网络接口信息是准确的。
4. **`getifaddrs()` 返回的 IP 地址正确性测试:**
   - 验证通过 `getifaddrs()` 获取的 IPv4 地址与通过 `ioctl` 系统调用（`SIOCGIFADDR`, `SIOCGIFBRDADDR`, `SIOCGIFDSTADDR`）获取的地址是否一致。
5. **输出 `ifaddrs` 结构体信息的调试工具:** 提供一个 `dump` 测试用例，用于打印 `getifaddrs()` 返回的详细信息，方便开发人员调试。
6. **IPv6 Scope ID 测试:** 验证对于 Link-local 或 Multicast Link-local 的 IPv6 地址，`sin6_scope_id` 字段是否被正确设置（非 0）。
7. **内核 Bug 回归测试 (31038971):**  针对特定内核 bug 进行了测试，该 bug 可能导致 `getifaddrs()` 返回错误，但 Bionic 未正确设置 `errno`。这个测试用例通过并发调用 `getifaddrs()` 来检测该问题。
8. **`errno` 设置测试:**  模拟打开大量文件导致 `EMFILE` 错误的情况，验证 `getifaddrs()` 在遇到资源限制时是否能正确设置 `errno`。

**与 Android 功能的关系及举例**

`getifaddrs()` 函数在 Android 系统中扮演着重要的角色，因为它提供了获取设备网络接口配置信息的标准方法。Android 的很多网络相关的组件和服务都依赖于此功能。

* **获取网络连接信息:**  Android 系统需要知道设备有哪些网络接口（例如 Wi-Fi、移动数据、以太网、蓝牙网络共享），以及每个接口的 IP 地址、MAC 地址、广播地址等信息。这些信息对于建立网络连接、进行网络通信至关重要。
    * **举例:** 当你的 Android 手机连接到 Wi-Fi 时，系统会使用 `getifaddrs()` 来获取 Wi-Fi 接口的 IP 地址，以便应用程序可以通过该 IP 地址连接到互联网。
* **网络状态监控:**  Android 系统可以监控网络接口的状态（例如是否连接、是否可用）。`getifaddrs()` 返回的接口标志 (flags) 可以用来判断接口的状态。
    * **举例:**  Android 设置中的 "Wi-Fi" 页面会显示当前连接的 Wi-Fi 网络的名称和 IP 地址。这些信息很可能就是通过 `getifaddrs()` 获取的。
* **VPN 连接:**  当建立 VPN 连接时，系统会创建一个新的虚拟网络接口。`getifaddrs()` 可以用来列出这个新的 VPN 接口及其配置信息。
* **网络调试工具:**  像 `ip` 命令这样的网络工具，在 Android 系统中也是通过调用 `getifaddrs()` 等函数来获取网络接口信息的。
* **应用程序开发:**  Android 应用程序可以通过 NDK 调用 `getifaddrs()` 来获取设备的网络接口信息。这对于需要了解网络配置的应用程序（例如网络监控工具、P2P 应用）非常有用。

**`libc` 函数功能详解**

1. **`getifaddrs(ifaddrs **ifap)`:**
   - **功能:**  获取当前系统的网络接口地址信息。它会分配内存，并将一个指向 `ifaddrs` 结构体链表的指针存储在 `*ifap` 中。每个 `ifaddrs` 结构体包含一个网络接口的信息。
   - **实现:**
     - 在 Bionic 中，`getifaddrs()` 的实现通常会与内核进行交互，主要通过 **Netlink Socket**。
     - 它会打开一个 Netlink Socket，并发送一个请求（`RTM_GETADDR`，`RTM_GETLINK` 等）到内核网络子系统。
     - 内核会响应包含所有网络接口信息的 Netlink 消息。
     - `getifaddrs()` 解析这些 Netlink 消息，并将接口信息填充到 `ifaddrs` 结构体中，构建成一个链表。
     - 涉及到的内核数据结构包括 `struct net_device`（网络设备）、`struct inet_address`（IP 地址）等。
     - `getifaddrs()` 还需要处理不同类型的地址族（`AF_INET`，`AF_INET6`，`AF_PACKET` 等）。

2. **`freeifaddrs(ifaddrs *ifa)`:**
   - **功能:** 释放 `getifaddrs()` 分配的内存。
   - **实现:**
     - `freeifaddrs()` 遍历 `getifaddrs()` 返回的 `ifaddrs` 结构体链表。
     - 对于链表中的每个 `ifaddrs` 结构体，它会释放结构体本身以及结构体中指向的地址信息（`ifa_addr`，`ifa_netmask`，`ifa_broadaddr` 等）。
     - 它需要小心处理空指针的情况，就像测试用例中验证的那样。

3. **`strcmp(const char *s1, const char *s2)`:**
   - **功能:**  比较两个字符串。
   - **实现:**  逐个字符比较 `s1` 和 `s2`，直到遇到不同的字符或者字符串的结尾。如果所有字符都相同，则返回 0；如果 `s1` 的字符在 `s2` 之前，则返回负数；否则返回正数。

4. **`socket(int domain, int type, int protocol)`:**
   - **功能:**  创建一个网络套接字。
   - **实现:**  它是一个系统调用，会通知内核创建一个新的套接字文件描述符。内核会根据 `domain` (例如 `AF_INET`，`AF_NETLINK`)，`type` (例如 `SOCK_DGRAM`，`SOCK_RAW`) 和 `protocol` 来分配相应的资源和数据结构。

5. **`ioctl(int fd, unsigned long request, ...)`:**
   - **功能:**  设备输入/输出控制。这是一个通用的系统调用，可以用于对各种设备（包括网络接口）执行特定的操作。
   - **实现:**  内核会根据文件描述符 `fd` 和请求码 `request` 来执行相应的操作。对于网络接口，常见的请求码包括 `SIOCGIFADDR`（获取接口地址）、`SIOCSIFADDR`（设置接口地址）、`SIOCGIFFLAGS`（获取接口标志）等。

6. **`open(const char *pathname, int flags, ...)`:**
   - **功能:**  打开文件或设备。
   - **实现:**  内核会在文件系统中查找指定的路径名，并根据 `flags` 打开文件或设备，返回一个文件描述符。

7. **`close(int fd)`:**
   - **功能:**  关闭一个文件描述符。
   - **实现:**  通知内核释放与该文件描述符相关的资源。

8. **`opendir(const char *name)`:**
   - **功能:**  打开一个目录流。
   - **实现:**  内核会打开指定的目录，并返回一个指向 `DIR` 结构体的指针，该结构体可以用于读取目录中的条目。

9. **`readdir(DIR *dirp)`:**
   - **功能:**  从目录流中读取下一个目录项。
   - **实现:**  内核会返回目录流中的下一个 `dirent` 结构体，该结构体包含目录项的名称等信息。

10. **`getnameinfo(const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags)`:**
    - **功能:**  将套接字地址结构体转换为主机名和服务名。
    - **实现:**  它会根据套接字地址的地址族（例如 `AF_INET`，`AF_INET6`）查找相应的名称信息。通常会涉及 DNS 查询，但在这个测试用例中使用了 `NI_NUMERICHOST` 标志，表示只返回数字形式的 IP 地址。

11. **`strerror(int errnum)`:**
    - **功能:**  将错误代码转换为错误消息字符串。
    - **实现:**  它会根据传入的错误代码 `errnum` 在一个预定义的错误消息数组中查找对应的字符串。

12. **`gai_strerror(int errcode)`:**
    - **功能:**  将 `getaddrinfo()` 或 `getnameinfo()` 返回的错误代码转换为错误消息字符串。
    - **实现:**  类似于 `strerror()`，但用于处理与地址和名称解析相关的错误。

**涉及 Dynamic Linker 的功能**

`ifaddrs_test.cpp` 本身并没有直接测试 dynamic linker 的功能。然而，`getifaddrs()` 和 `freeifaddrs()` 函数是 `libc.so` 库的一部分，而 `libc.so` 是一个动态链接库。

**`libc.so` 布局样本 (简化)**

```
libc.so
├── .text        # 代码段
│   ├── getifaddrs
│   ├── freeifaddrs
│   ├── ... 其他 libc 函数 ...
├── .data        # 已初始化数据段
├── .bss         # 未初始化数据段
├── .dynamic    # 动态链接信息
│   ├── DT_NEEDED: libdl.so
│   ├── DT_SONAME: libc.so
│   ├── DT_SYMTAB: ...
│   ├── DT_STRTAB: ...
│   └── ...
├── .symtab      # 符号表
│   ├── getifaddrs (地址)
│   ├── freeifaddrs (地址)
│   └── ...
├── .strtab      # 字符串表
│   ├── "getifaddrs"
│   ├── "freeifaddrs"
│   └── ...
└── ... 其他段 ...
```

**链接的处理过程**

1. **编译时:** 当编译链接使用 `getifaddrs()` 或 `freeifaddrs()` 的代码时，编译器会在代码中生成对这些函数的符号引用。链接器在链接时会记录这些未解析的符号。
2. **加载时:** 当 Android 系统加载可执行文件或动态库时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被激活。
3. **查找依赖库:** Dynamic linker 会读取可执行文件或动态库的 `.dynamic` 段，找到其依赖的库（`DT_NEEDED` 条目，例如 `libc.so`）。
4. **加载依赖库:** Dynamic linker 会加载这些依赖库到内存中。如果 `libc.so` 尚未加载，则会加载它。
5. **符号解析 (Symbol Resolution):** Dynamic linker 会遍历可执行文件或动态库中未解析的符号，并在已加载的动态库的符号表 (`.symtab`) 中查找匹配的符号。
6. **重定位 (Relocation):** 找到符号后，dynamic linker 会更新可执行文件或动态库中的代码和数据，将对符号的引用指向其在内存中的实际地址。例如，对 `getifaddrs()` 的调用会被重定位到 `libc.so` 中 `getifaddrs()` 函数的实际地址。

**假设输入与输出 (逻辑推理)**

* **`TEST(ifaddrs, freeifaddrs_null)`:**
    - **假设输入:**  `nullptr` 传递给 `freeifaddrs()`。
    - **预期输出:**  程序不会崩溃或产生错误。

* **`TEST(ifaddrs, getifaddrs_lo)`:**
    - **假设输入:** 系统存在一个名为 "lo" 的 loopback 网络接口。
    - **预期输出:**
        - `getifaddrs()` 返回成功 (0)。
        - 返回的链表中包含一个 `ifa_name` 为 "lo" 的 `ifaddrs` 结构体。
        - 该结构体包含 `ifa_addr`，其 `sa_family` 为 `AF_INET`，且地址为 `127.0.0.1`。
        - 该结构体包含 `ifa_addr`，其 `sa_family` 为 `AF_INET6`，且地址为 `::1`。
        - 该结构体包含 `ifa_addr`，其 `sa_family` 为 `AF_PACKET`。

* **`TEST(ifaddrs, getifaddrs_interfaces)`:**
    - **假设输入:**  `/sys/class/net` 目录存在，并且其中包含当前系统的网络接口。
    - **预期输出:** `getifaddrs()` 返回的接口名称（`AF_PACKET` 或 `AF_UNSPEC`）列表与 `/sys/class/net` 中的目录项名称列表相同（顺序可能不同）。

**用户或编程常见的使用错误**

1. **忘记调用 `freeifaddrs()`:**  `getifaddrs()` 会动态分配内存来存储接口信息，如果忘记调用 `freeifaddrs()` 来释放这些内存，会导致内存泄漏。

   ```c++
   ifaddrs* addrs;
   if (getifaddrs(&addrs) == 0) {
       // 使用 addrs 中的信息
       // 错误：忘记调用 freeifaddrs(addrs);
   }
   ```

2. **错误地假设接口始终存在或具有特定属性:**  网络接口的可用性和属性可能因设备和网络配置而异。应用程序应该检查 `getifaddrs()` 的返回值以及每个 `ifaddrs` 结构体的内容。

   ```c++
   ifaddrs* addrs;
   if (getifaddrs(&addrs) == 0) {
       for (ifaddrs* current = addrs; current != nullptr; current = current->ifa_next) {
           if (strcmp(current->ifa_name, "wlan0") == 0) {
               // 错误：假设 wlan0 总是存在
               sockaddr_in* addr = (sockaddr_in*)current->ifa_addr;
               // ... 使用 addr ...
           }
       }
       freeifaddrs(addrs);
   }
   ```

3. **不检查 `getifaddrs()` 的返回值:**  `getifaddrs()` 在失败时会返回 -1 并设置 `errno`。不检查返回值可能导致使用未初始化的指针。

   ```c++
   ifaddrs* addrs;
   getifaddrs(&addrs); // 错误：未检查返回值
   // 尝试使用 addrs，如果 getifaddrs 失败，addrs 可能为 nullptr
   ```

**Android Framework 或 NDK 如何到达这里**

一个应用程序的网络请求流程，最终可能会间接地涉及到 `getifaddrs()`：

1. **Android Framework (Java):**  应用程序通常使用 Java 网络 API (例如 `java.net.InetAddress`, `java.net.NetworkInterface`) 来获取网络信息或建立网络连接。
2. **Framework Native 代码:**  Java Framework 的网络相关类通常会在 Native 层有对应的实现 (例如在 `libjavacrypto.so`, `libnetd_client.so` 等库中)。
3. **NDK (C/C++):**  如果应用程序使用 NDK 进行网络编程，它可以直接调用 Bionic 提供的 C 标准库函数，包括 `getifaddrs()`.
4. **Bionic `libc.so`:**  无论是 Framework 的 Native 代码还是 NDK 代码，最终都会调用到 Bionic 的 `libc.so` 中实现的 `getifaddrs()` 函数。
5. **Kernel (Netlink):** `libc.so` 中的 `getifaddrs()` 实现会通过 Netlink Socket 与 Linux 内核的网络子系统通信，获取网络接口信息。

**Frida Hook 示例**

以下是一些使用 Frida Hook 调试 `getifaddrs()` 相关步骤的示例：

```javascript
// Hook getifaddrs 函数，打印返回值和 errno
Interceptor.attach(Module.findExportByName("libc.so", "getifaddrs"), {
  onEnter: function (args) {
    console.log("getifaddrs called");
  },
  onLeave: function (retval) {
    console.log("getifaddrs returned:", retval);
    if (retval.toInt32() === -1) {
      const errnoPtr = Module.findExportByName(null, "__errno_location")();
      const errnoValue = errnoPtr.readInt();
      console.log("errno:", errnoValue, "(" + new NativePointer(Module.findExportByName(null, "strerror")(errnoValue)).readCString() + ")");
    } else {
      const ifapPtr = Memory.readPointer(this.context.sp + Process.pointerSize); // 假设指针作为第一个参数传递
      if (ifapPtr.isNull()) {
        console.log("ifap is null, potential error");
      } else {
        // 这里可以进一步解析 ifaddrs 结构体的内容
        console.log("ifaddrs pointer:", ifapPtr);
      }
    }
  },
});

// Hook freeifaddrs 函数
Interceptor.attach(Module.findExportByName("libc.so", "freeifaddrs"), {
  onEnter: function (args) {
    console.log("freeifaddrs called with:", args[0]);
  },
});

// Hook socket 系统调用 (可能间接影响 getifaddrs)
Interceptor.attach(Module.findExportByName("libc.so", "socket"), {
  onEnter: function (args) {
    console.log("socket called with domain:", args[0], "type:", args[1], "protocol:", args[2]);
  },
  onLeave: function (retval) {
    console.log("socket returned:", retval);
  },
});

// Hook ioctl 系统调用 (getifaddrs 内部可能会使用)
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
  onEnter: function (args) {
    const request = args[1].toInt32();
    const requestName = (request === 0x8915 ? "SIOCGIFADDR" :
                         request === 0x8919 ? "SIOCGIFBRDADDR" :
                         request === 0x891d ? "SIOCGIFDSTADDR" :
                         "Unknown");
    console.log("ioctl called with fd:", args[0], "request:", ptr(request), "(" + requestName + ")");
  },
  onLeave: function (retval) {
    console.log("ioctl returned:", retval);
  },
});
```

这些 Frida 脚本可以帮助你跟踪 `getifaddrs()` 的调用时机、参数、返回值以及相关的系统调用，从而更深入地理解其工作原理和排查问题。

希望以上分析对您有所帮助！

### 提示词
```
这是目录为bionic/tests/ifaddrs_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <ifaddrs.h>

#include <dirent.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

// (glibc as of 2.37 has redefinitions if you include these before <net/if.h>.)
#include <linux/if.h>
#include <linux/if_packet.h>

#include <algorithm>
#include <map>
#include <thread>
#include <vector>

#include "utils.h"

TEST(ifaddrs, freeifaddrs_null) {
  freeifaddrs(nullptr);
}

// We can't statically say much about what network interfaces are available, but we can be pretty
// sure there's a loopback interface, and that it has IPv4, IPv6, and AF_PACKET entries.
TEST(ifaddrs, getifaddrs_lo) {
  ifaddrs* addrs = nullptr;

  ASSERT_EQ(0, getifaddrs(&addrs));
  ASSERT_TRUE(addrs != nullptr);

  ifaddrs* lo_inet4 = nullptr;
  ifaddrs* lo_inet6 = nullptr;
  ifaddrs* lo_packet = nullptr;
  for (ifaddrs* addr = addrs; addr != nullptr; addr = addr->ifa_next) {
    if (addr->ifa_name && strcmp(addr->ifa_name, "lo") == 0) {
      if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET) lo_inet4 = addr;
      else if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET6) lo_inet6 = addr;
      else if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_PACKET) lo_packet = addr;
    }
  }

  // Does the IPv4 entry look right?
  ASSERT_TRUE(lo_inet4 != nullptr);
  const sockaddr_in* sa_inet4 = reinterpret_cast<const sockaddr_in*>(lo_inet4->ifa_addr);
  ASSERT_TRUE(ntohl(sa_inet4->sin_addr.s_addr) == INADDR_LOOPBACK);

  // Does the IPv6 entry look right?
  ASSERT_TRUE(lo_inet6 != nullptr);
  const sockaddr_in6* sa_inet6 = reinterpret_cast<const sockaddr_in6*>(lo_inet6->ifa_addr);
  ASSERT_TRUE(IN6_IS_ADDR_LOOPBACK(&sa_inet6->sin6_addr));

  // Does the AF_PACKET entry look right?
  ASSERT_TRUE(lo_packet != nullptr);
  const sockaddr_ll* sa_ll = reinterpret_cast<const sockaddr_ll*>(lo_packet->ifa_addr);
  ASSERT_EQ(6, sa_ll->sll_halen);

  freeifaddrs(addrs);
}

// Check that getifaddrs sees the same list of interfaces as /sys/class/net.
TEST(ifaddrs, getifaddrs_interfaces) {
  std::vector<std::string> ifaddrs_socks;
  {
    ifaddrs* addrs;
    ASSERT_EQ(0, getifaddrs(&addrs));

    for (ifaddrs* addr = addrs; addr != nullptr; addr = addr->ifa_next) {
      int family = addr->ifa_addr ? addr->ifa_addr->sa_family :
          addr->ifa_broadaddr ? addr->ifa_broadaddr->sa_family :
          AF_UNSPEC;

      if (family == AF_PACKET || family == AF_UNSPEC) {
        ifaddrs_socks.push_back(std::string(addr->ifa_name));
      }
    }

    freeifaddrs(addrs);
  }

  std::vector<std::string> sys_class_net;
  {
    std::unique_ptr<DIR, decltype(&closedir)> d(opendir("/sys/class/net"), closedir);
    ASSERT_TRUE(d != nullptr);
    dirent* dir;
    while ((dir = readdir(d.get())) != nullptr) {
      if (dir->d_type == DT_LNK) {
        sys_class_net.push_back(std::string(dir->d_name));
      }
    }
  }

  ASSERT_TRUE(std::is_permutation(ifaddrs_socks.begin(), ifaddrs_socks.end(),
                                  sys_class_net.begin()));
}

static void CheckAddressIsInSet(const std::string& if_name, bool unicast,
                                const std::set<in_addr_t>& addrs) {
  ifreq ifr = {.ifr_addr.sa_family = AF_INET};
  if_name.copy(ifr.ifr_name, IFNAMSIZ - 1);

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(fd != -1);

  int request = SIOCGIFADDR;
  if (!unicast) {
    // For non-unicast, the specific ioctl to use depends on whether the IFF_BROADCAST flag is set.
    ASSERT_EQ(0, ioctl(fd, SIOCGIFFLAGS, &ifr)) << if_name << ' ' << strerror(errno);
    request = ((ifr.ifr_flags & IFF_BROADCAST) != 0) ? SIOCGIFBRDADDR : SIOCGIFDSTADDR;
  }

  ASSERT_EQ(0, ioctl(fd, request, &ifr)) << if_name << ' ' << strerror(errno);
  close(fd);

  sockaddr_in* sock = reinterpret_cast<sockaddr_in*>(&ifr.ifr_addr);
  in_addr_t addr = sock->sin_addr.s_addr;

  EXPECT_TRUE(addrs.contains(addr)) << if_name << ' ' << std::hex << ntohl(addr);
}

TEST(ifaddrs, getifaddrs_INET) {
  std::map<std::string, std::set<in_addr_t>> inet_addrs;
  std::map<std::string, std::set<in_addr_t>> broad_addrs;

  // Collect the IPv4 addresses for each interface.
  ifaddrs* addrs;
  ASSERT_EQ(0, getifaddrs(&addrs));
  for (ifaddrs* addr = addrs; addr != nullptr; addr = addr->ifa_next) {
    if (addr->ifa_name && addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET) {
      auto sock = reinterpret_cast<sockaddr_in*>(addr->ifa_addr);
      inet_addrs[addr->ifa_name].insert(sock->sin_addr.s_addr);
    }
    if (addr->ifa_name && addr->ifa_broadaddr && addr->ifa_broadaddr->sa_family == AF_INET) {
      auto sock = reinterpret_cast<sockaddr_in*>(addr->ifa_broadaddr);
      broad_addrs[addr->ifa_name].insert(sock->sin_addr.s_addr);
    }
  }
  freeifaddrs(addrs);

  // Check that the addresses returned by the SIOCGIFADDR and SIOCGIFBRDADDR/SIOCGIFDSTADDR ioctls
  // are in our collections.
  for (const auto& it : inet_addrs) CheckAddressIsInSet(it.first, true, it.second);
  for (const auto& it : broad_addrs) CheckAddressIsInSet(it.first, false, it.second);
}

static void print_sockaddr_ll(const char* what, const sockaddr* p) {
  const sockaddr_ll* s = reinterpret_cast<const sockaddr_ll*>(p);
  printf("\t\t%s\t", what);
  for (int i = 0; i < s->sll_halen; ++i) {
    if (i > 0) printf(":");
    printf("%02X", s->sll_addr[i]);
  }
  printf(" (%d bytes)\n", s->sll_halen);
}

static void print_sockaddr_inet(const char* what, const sockaddr* addr) {
  char host[NI_MAXHOST];
  int family = addr->sa_family;
  int error = getnameinfo(addr,
                          (family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6),
                          host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
  if (error != 0) {
    printf("%d getnameinfo() failed: %s\n", family, gai_strerror(error));
    strcpy(host, "???");
  }
  printf("\t\t%s: <%s>\n", what, host);
}

static const char* FamilyToName(int family) {
  if (family == AF_INET) return "AF_INET";
  if (family == AF_INET6) return "AF_INET6";
  if (family == AF_PACKET) return "AF_PACKET";
  if (family == AF_UNSPEC) return "AF_UNSPEC";
  return "?";
}

static std::string FlagsToString(short flags) {
  std::string result;
  if ((flags & IFF_UP) != 0) result += " UP";
  if ((flags & IFF_BROADCAST) != 0) result += " BROADCAST";
  if ((flags & IFF_DEBUG) != 0) result += " DEBUG";
  if ((flags & IFF_LOOPBACK) != 0) result += " LOOPBACK";
  if ((flags & IFF_POINTOPOINT) != 0) result += " POINTOPOINT";
  if ((flags & IFF_NOTRAILERS) != 0) result += " NOTRAILERS";
  if ((flags & IFF_RUNNING) != 0) result += " RUNNING";
  if ((flags & IFF_NOARP) != 0) result += " NOARP";
  if ((flags & IFF_PROMISC) != 0) result += " PROMISC";
  if ((flags & IFF_ALLMULTI) != 0) result += " ALLMULTI";
  if ((flags & IFF_MASTER) != 0) result += " MASTER";
  if ((flags & IFF_SLAVE) != 0) result += " SLAVE";
  if ((flags & IFF_MULTICAST) != 0) result += " MULTICAST";
  if ((flags & IFF_PORTSEL) != 0) result += " PORTSEL";
  if ((flags & IFF_AUTOMEDIA) != 0) result += " AUTOMEDIA";
  if ((flags & IFF_DYNAMIC) != 0) result += " DYNAMIC";
  if ((flags & IFF_LOWER_UP) != 0) result += " LOWER_UP";
  if ((flags & IFF_DORMANT) != 0) result += " DORMANT";
  if ((flags & IFF_ECHO) != 0) result += " ECHO";
  return result;
}

// Not really a test, but a useful debugging tool.
TEST(ifaddrs, dump) {
  ifaddrs* addrs;
  ASSERT_EQ(0, getifaddrs(&addrs));

  for (ifaddrs* ifa = addrs; ifa != nullptr; ifa = ifa->ifa_next) {
    int family = ifa->ifa_addr ? ifa->ifa_addr->sa_family :
                                 ifa->ifa_broadaddr ? ifa->ifa_broadaddr->sa_family : AF_UNSPEC;

    printf("\t%s\n"
           "\t\t%s (%d) flags=%#x%s\n",
           ifa->ifa_name, FamilyToName(family), family,
           ifa->ifa_flags, FlagsToString(ifa->ifa_flags).c_str());

    if (family == AF_PACKET) {
      if (ifa->ifa_addr) print_sockaddr_ll("hwaddr", ifa->ifa_addr);
      if (ifa->ifa_broadaddr) print_sockaddr_ll("hwbroad", ifa->ifa_addr);
    } else if (family == AF_INET || family == AF_INET6) {
      if (ifa->ifa_addr) print_sockaddr_inet("address", ifa->ifa_addr);
      if (ifa->ifa_broadaddr && (ifa->ifa_flags & (IFF_BROADCAST | IFF_POINTOPOINT)) != 0) {
        print_sockaddr_inet((ifa->ifa_flags & IFF_BROADCAST) ? "broadcast" : "destination",
                            ifa->ifa_broadaddr);
      }
    }

    fflush(stdout);
  }

  freeifaddrs(addrs);
}

TEST(ifaddrs, inet6_scope_ids) {
  ifaddrs* addrs;
  ASSERT_EQ(0, getifaddrs(&addrs));

  for (ifaddrs* ifa = addrs; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
      sockaddr_in6* sa6 = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr);
      // Any link-local IPv6 address should have a scope id. (http://b/27219454.)
      // 0 isn't a valid interface index, so that would mean the scope id wasn't set.
      if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr) || IN6_IS_ADDR_MC_LINKLOCAL(&sa6->sin6_addr)) {
        ASSERT_NE(sa6->sin6_scope_id, 0U);
      }
    }
  }

  freeifaddrs(addrs);
}

TEST(ifaddrs, kernel_bug_31038971) {
  // Some kernels had a bug that would lead to an NLMSG_ERROR response,
  // but bionic wasn't setting errno based on the value in the message.
  // This is the test for the kernel bug, but on a device with a bad
  // kernel this test was also useful for testing the bionic errno fix.
  std::vector<std::thread*> threads;
  for (size_t i = 0; i < 128; ++i) {
    threads.push_back(new std::thread([]() {
      ifaddrs* addrs = nullptr;
      ASSERT_EQ(0, getifaddrs(&addrs)) << strerror(errno);
      freeifaddrs(addrs);
    }));
  }
  for (auto& t : threads) {
    t->join();
    delete t;
  }
}

TEST(ifaddrs, errno_EMFILE) {
  std::vector<int> fds;
  while (true) {
    int fd = open("/dev/null", O_RDONLY|O_CLOEXEC);
    if (fd == -1) {
      ASSERT_ERRNO(EMFILE);
      break;
    }
    fds.push_back(fd);
  }

  ifaddrs* addrs;
  EXPECT_EQ(-1, getifaddrs(&addrs));
  EXPECT_ERRNO(EMFILE);

  for (int fd : fds) close(fd);
}
```