Response:
Let's break down the thought process for analyzing the `netdb_test.cpp` file and generating the detailed response.

**1. Understanding the Core Request:**

The request is to analyze a C++ test file for `netdb` functions within the Android Bionic library. The key is to explain the *purpose* of the file, the *functionality* of the tested functions, their relationship to Android, dynamic linking aspects, common errors, and how Android frameworks reach this level. A Frida hook example is also requested.

**2. Initial Scans and Categorization:**

The first step is to quickly scan the code and identify the main areas. Keywords like `TEST`, function names (`getaddrinfo`, `freeaddrinfo`, `getnameinfo`, `gethostbyname`, `getservbyname`, etc.), and included headers (`<netdb.h>`, `<arpa/inet.h>`, etc.) provide immediate clues. I'd categorize the tests based on the `netdb` functions they exercise.

* **Address Resolution:** `getaddrinfo`, `freeaddrinfo`
* **Name Resolution (IP to Name/Name to IP):** `getnameinfo`, `gethostbyname`, `gethostbyname2`, `gethostbyaddr` (and their reentrant `_r` versions)
* **Service Resolution:** `getservbyname`, `getservbyport`
* **Network Database Enumeration:** `getnetent`, `setnetent`, `endnetent`
* **Protocol Database Enumeration:** `getprotoent`, `setprotoent`, `endprotoent`
* **Service Database Enumeration:** `getservent`, `setservent`, `endservent`
* **Host Database Enumeration:** `gethostent`, `sethostent`, `endhostent`

**3. Analyzing Individual Tests:**

For each test case, I'd do the following:

* **Identify the Tested Function(s):**  The `TEST(netdb, function_name)` structure clearly indicates this.
* **Understand the Test's Goal:** What specific aspect of the function is being tested?  Look at the assertions (`ASSERT_EQ`, `ASSERT_TRUE`, `ASSERT_STREQ`, `EXPECT_EQ`). For example, a test with `freeaddrinfo(nullptr)` tests the function's behavior with a null pointer.
* **Identify Key Parameters and Return Values:** Note what inputs are being provided to the function and what the expected outputs or side effects are.
* **Infer Functionality:** Based on the test and the function's name, deduce the general purpose of the underlying `libc` function.

**4. Connecting to Android Functionality:**

This is where general knowledge of Android's networking stack comes in. Key connections include:

* **Network Communication:** All these functions are fundamental for network operations in Android apps. Any app that needs to connect to a server (HTTP requests, socket connections, etc.) will indirectly use these functions.
* **DNS Resolution:** `getaddrinfo` and `gethostbyname` are crucial for translating domain names into IP addresses.
* **Service Discovery:** `getservbyname` and `getservbyport` help in finding the port number associated with a known service name.
* **System Configuration:**  The functions might interact with files like `/etc/hosts` or system properties to resolve names and services.

**5. Explaining `libc` Function Implementations:**

This requires understanding the general principles of how these functions are implemented. It doesn't necessitate knowing the exact Bionic source code line-by-line (unless explicitly requested and time permits). The focus is on the *typical* implementation patterns:

* **`getaddrinfo`:**  Likely involves querying multiple sources (local files, DNS servers) and returning a linked list of `addrinfo` structures.
* **`freeaddrinfo`:** Simple memory deallocation.
* **`getnameinfo`:** Reverse lookup, potentially involving reverse DNS queries.
* **`gethostbyname` (and variants):** Primarily focused on IP address lookup based on hostname.
* **`getservbyname` (and variants):**  Lookup in a service database (likely `/system/etc/services`).

**6. Addressing Dynamic Linking:**

* **Identifying Relevant Functions:** Focus on functions that might involve resolving dependencies or loading libraries, although the provided test file doesn't directly test dynamic linking *mechanisms*. However, the `libc` functions themselves are part of the dynamically linked `libc.so`.
* **SO Layout Sample:**  A basic example of how `libc.so` might be laid out in memory, including sections for code, data, and symbol tables.
* **Linking Process:**  A high-level explanation of how the dynamic linker (`linker64` or `linker`) resolves symbols at runtime. Key steps involve finding the library, loading it, and resolving dependencies.

**7. Providing Examples and Reasoning:**

* **Hypothetical Inputs and Outputs:** Choose relevant functions and demonstrate their behavior with simple inputs. For example, `getaddrinfo("www.google.com", "80", ...)` and the expected IP address.
* **Common User Errors:**  Think about typical mistakes developers make when using these networking functions, like forgetting to handle errors, leaking memory with `addrinfo`, or using incorrect flags.

**8. Explaining the Android Framework Connection:**

Trace how a high-level Android API call might eventually lead to these `libc` functions:

* **Example Scenario:**  Making an HTTP request using `HttpURLConnection`.
* **Step-by-Step Breakdown:**  The journey from Java code down to native calls, involving Android framework components, the NDK, and finally Bionic.

**9. Creating a Frida Hook Example:**

Choose a relevant function (like `getaddrinfo`) and demonstrate how to intercept its calls using Frida. Show how to log arguments and the return value.

**10. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use formatting (like bullet points and code blocks) to improve readability. Ensure the language is clear and concise, avoiding unnecessary jargon.

**Self-Correction/Refinement During the Process:**

* **Initial Overemphasis on Test Internals:**  Initially, I might have focused too much on the details of the Google Test framework. I'd then shift focus to the *underlying* `netdb` functions being tested.
* **Balancing Detail:**  Decide how much detail to provide for each `libc` function's implementation. A high-level overview is usually sufficient unless the request specifically asks for in-depth details.
* **Ensuring Clarity:**  Review the explanation to ensure it's easy for someone unfamiliar with the Bionic library to understand. Avoid assumptions about the reader's knowledge.
* **Verifying Accuracy:** Double-check the function names, parameters, and general behavior of the `netdb` functions.

By following these steps, iterating, and refining the information, a comprehensive and accurate response can be generated, addressing all aspects of the original request.
好的，让我们详细分析一下 `bionic/tests/netdb_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/netdb_test.cpp` 是 Android Bionic 库中用于测试网络数据库相关函数（通常在 `netdb.h` 头文件中声明）的功能和正确性的单元测试文件。它使用了 Google Test 框架 (`gtest`) 来组织和执行测试用例。

**测试的功能点**

这个文件主要测试了以下 `netdb.h` 中声明的函数：

* **`freeaddrinfo()`:** 释放 `getaddrinfo()` 返回的 `addrinfo` 结构体链表。
* **`getaddrinfo()`:** 将主机名和服务名转换为套接字地址结构。
* **`getnameinfo()`:** 将套接字地址结构转换为主机名和服务名。
* **`gethostbyname()`:** 通过主机名获取主机信息。
* **`gethostbyname2()`:** 通过主机名和地址族获取主机信息。
* **`gethostbyaddr()`:** 通过 IP 地址获取主机信息。
* **`gethostbyname_r()`, `gethostbyname2_r()`, `gethostbyaddr_r()`:**  `gethostbyname` 等函数的线程安全版本。
* **`getservbyname()`:** 通过服务名和协议获取服务信息。
* **`getservbyport()`:** 通过端口号和协议获取服务信息。
* **`getnetent()`, `setnetent()`, `endnetent()`:** 枚举网络数据库条目。
* **`getnetbyaddr()`:** 通过网络地址获取网络信息。
* **`getnetbyname()`:** 通过网络名获取网络信息。
* **`getprotoent()`, `setprotoent()`, `endprotoent()`:** 枚举协议数据库条目。
* **`getprotobyname()`:** 通过协议名获取协议信息。
* **`getprotobynumber()`:** 通过协议号获取协议信息。
* **`getservent()`, `setservent()`, `endservent()`:** 枚举服务数据库条目。
* **`sethostent()`, `endhostent()`:** 控制 `gethostent()` 的操作。

**与 Android 功能的关系及举例说明**

这些 `netdb` 函数是 Android 系统网络编程的基础。Android 应用程序或底层系统服务需要进行网络通信时，会间接地或直接地使用这些函数。

* **域名解析:** `getaddrinfo()` 和 `gethostbyname()` 用于将用户友好的域名（如 `www.google.com`）转换为 IP 地址，这是建立网络连接的第一步。例如，当你在浏览器中输入网址时，浏览器底层会调用这些函数来获取服务器的 IP 地址。
* **服务发现:** `getservbyname()` 用于查找特定服务的端口号。例如，当应用程序需要连接到 SMTP 服务器发送邮件时，可以使用 `getservbyname("smtp", "tcp")` 来获取 SMTP 服务的端口号 (25)。
* **反向域名解析:** `getnameinfo()` 用于将 IP 地址转换回主机名。这在网络诊断、日志记录等方面很有用。例如，当服务器收到来自某个 IP 地址的连接请求时，可以使用 `getnameinfo()` 来尝试获取该 IP 地址对应的主机名。

**libc 函数的功能实现详解**

这些 `libc` 函数的实现通常涉及以下几个方面：

* **数据源:**  这些函数需要查询一些数据源来获取网络配置信息。这些数据源可能包括：
    * **本地配置文件:**  例如 `/etc/hosts`（或 Android 上的 `/system/etc/hosts`）用于主机名到 IP 地址的映射，`/etc/services`（或 Android 上的 `/system/etc/services`）用于服务名到端口号的映射。
    * **DNS 服务器:** 对于不在本地配置文件中的主机名，系统会向配置的 DNS 服务器发送查询请求。
    * **网络数据库:**  例如 `networks` 文件（通常在 Android 上可能被抽象或集成到其他配置中）。
    * **协议数据库:** 例如 `protocols` 文件（通常在 Android 上可能被抽象或集成到其他配置中）。

* **`freeaddrinfo()`:**  这个函数负责释放 `getaddrinfo()` 分配的内存。`getaddrinfo()` 返回的是一个 `addrinfo` 结构体的链表，因此 `freeaddrinfo()` 需要遍历这个链表并逐个释放每个节点的内存。如果传入 `nullptr`，则应该安全地返回，避免崩溃（正如测试用例所展示的）。

* **`getaddrinfo()`:**  这是最核心的函数之一。它的实现通常包括以下步骤：
    1. **参数校验:** 检查传入的参数是否有效。
    2. **处理主机名:**
        * 如果主机名是 NULL，则表示通配地址。
        * 如果主机名是数字 IP 地址，则直接解析为相应的地址结构。
        * 如果主机名是普通主机名，则：
            * 查询本地 `/system/etc/hosts` 文件。
            * 如果找不到，则向配置的 DNS 服务器发送 DNS 查询请求。
    3. **处理服务名/端口:**
        * 如果服务名是 NULL，则端口号部分为 0。
        * 如果服务名是数字端口号，则直接使用。
        * 如果服务名是服务名称，则查询 `/system/etc/services` 文件获取对应的端口号。
    4. **根据 `hints` 参数过滤结果:**  `hints` 结构体允许调用者指定所需的地址族、套接字类型和协议等信息，`getaddrinfo()` 会根据这些信息过滤返回的结果。
    5. **构建 `addrinfo` 链表:** 将解析到的地址信息填充到 `addrinfo` 结构体中，并构建成一个链表返回。

* **`getnameinfo()`:** 这个函数执行与 `getaddrinfo()` 相反的操作。它的实现通常包括：
    1. **参数校验:** 检查传入的参数是否有效。
    2. **根据地址族处理:**  根据传入的 `sockaddr` 结构的地址族（`AF_INET` 或 `AF_INET6`）来确定如何解析。
    3. **查找主机名:**
        * 如果设置了 `NI_NUMERICHOST` 标志，则直接将 IP 地址转换为字符串形式（例如 "192.168.1.1" 或 "::1"）。
        * 否则，尝试进行反向 DNS 查询，将 IP 地址解析为主机名。也可能查询本地 `/system/etc/hosts` 文件。
    4. **查找服务名:**
        * 如果设置了 `NI_NUMERICSERV` 标志，则直接将端口号转换为字符串形式。
        * 否则，查询 `/system/etc/services` 文件，将端口号转换为服务名。

* **`gethostbyname()`、`gethostbyname2()`、`gethostbyaddr()`:** 这些函数是 `getaddrinfo()` 的早期版本，功能相对简单。它们主要负责主机名到 IP 地址的转换（`gethostbyname` 和 `gethostbyname2`) 或 IP 地址到主机名的转换 (`gethostbyaddr`)。它们的实现逻辑与 `getaddrinfo()` 的主机名处理部分类似，但通常只返回单个 `hostent` 结构体，而不是链表。

* **`getservbyname()` 和 `getservbyport()`:** 这两个函数负责查询服务数据库 (`/system/etc/services`) 来获取服务信息（服务名、端口号、协议）。

* **`getnetent()` 等:** 这些函数用于枚举网络、协议和服务数据库中的条目。它们的实现通常需要读取相应的配置文件，并逐行解析。`setnetent()` 和 `setprotoent()` 等函数用于重置枚举的起始位置，`endnetent()` 等函数用于关闭打开的文件资源。

**涉及 dynamic linker 的功能**

`netdb_test.cpp` 中测试的函数本身是 `libc.so` 的一部分，因此它们的运行依赖于动态链接器。

**SO 布局样本：`libc.so`**

```
libc.so
├── .text          (代码段 - 包含 getaddrinfo, getnameinfo 等函数的机器码)
├── .rodata        (只读数据段 - 例如字符串常量，服务名列表等)
├── .data          (已初始化的全局变量和静态变量)
├── .bss           (未初始化的全局变量和静态变量)
├── .plt           (Procedure Linkage Table - 用于延迟绑定)
├── .got.plt       (Global Offset Table - 用于存储外部符号的地址)
└── ...其他段...
```

**链接的处理过程**

1. **编译时:** 当应用程序或系统服务链接 `libc.so` 时，编译器会在其可执行文件中记录对 `netdb` 函数的引用。`.plt` 和 `.got.plt` 表会被创建。
2. **加载时:** 当应用程序启动时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会加载 `libc.so` 到内存中。
3. **符号解析:**  当第一次调用 `getaddrinfo()` 等函数时，由于使用了延迟绑定，链接器会介入：
    * 链接器查看 `.got.plt` 中对应的条目，该条目最初指向 `.plt` 中的一段代码。
    * `.plt` 中的代码会调用链接器自身的函数来解析 `getaddrinfo()` 的实际地址。
    * 链接器在 `libc.so` 的符号表（`.symtab` 和 `.strtab`，虽然未在上述布局中显式列出）中查找 `getaddrinfo()` 的符号。
    * 找到 `getaddrinfo()` 的地址后，链接器会更新 `.got.plt` 中对应的条目，使其直接指向 `getaddrinfo()` 的代码。
4. **后续调用:**  后续对 `getaddrinfo()` 的调用将直接跳转到 `.got.plt` 中存储的地址，不再需要链接器介入，提高了效率。

**假设输入与输出（逻辑推理）**

* **`getaddrinfo("www.google.com", "80", nullptr, &ai)`:**
    * **假设输入:** 主机名 "www.google.com"，服务名 "80"（HTTP 端口），`hints` 为 `nullptr`。
    * **预期输出:** `ai` 指向一个 `addrinfo` 结构体链表，其中包含 "www.google.com" 对应的 IPv4 和 IPv6 地址信息，端口号为 80，套接字类型可能包括 `SOCK_STREAM` (TCP) 和 `SOCK_DGRAM` (UDP)。

* **`getnameinfo(sockaddr_in{AF_INET, htons(80), inet_addr("172.217.160.142")}, sizeof(sockaddr_in), host, NI_MAXHOST, service, NI_MAXSERV, 0)`:**
    * **假设输入:** IPv4 地址 `172.217.160.142` 和端口号 80。
    * **预期输出:** `host` 缓冲区可能包含 "www.google.com"（取决于 DNS 反向解析结果），`service` 缓冲区包含 "http"。

**用户或编程常见的使用错误**

* **忘记释放 `addrinfo` 链表:** `getaddrinfo()` 分配的内存需要通过 `freeaddrinfo()` 释放，否则会导致内存泄漏。
    ```c++
    addrinfo* ai;
    getaddrinfo("example.com", "80", nullptr, &ai);
    // ... 使用 ai
    // 忘记调用 freeaddrinfo(ai); // 内存泄漏
    ```
* **错误处理不当:** 网络操作可能失败，例如 DNS 解析失败。应该检查函数的返回值，并根据错误码（例如 `EAI_NONAME`, `EAI_AGAIN`) 进行处理。
    ```c++
    addrinfo* ai;
    int result = getaddrinfo("nonexistent.example.com", "80", nullptr, &ai);
    if (result != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(result));
        // ... 处理错误
    } else {
        // ... 使用 ai
        freeaddrinfo(ai);
    }
    ```
* **缓冲区溢出:** 在使用 `getnameinfo()`、`gethostbyname_r()` 等需要用户提供缓冲区的函数时，如果提供的缓冲区太小，可能导致缓冲区溢出。
    ```c++
    char host[16]; // 缓冲区太小
    sockaddr_in addr = { /* ... */ };
    getnameinfo((sockaddr*)&addr, sizeof(addr), host, sizeof(host), nullptr, 0, 0); // 可能溢出
    ```
* **线程安全问题:**  早期的 `gethostbyname` 等函数不是线程安全的。在多线程程序中应该使用其线程安全版本 (`_r` 版本）。

**Android Framework 或 NDK 如何到达这里**

以下是一个从 Android Framework 到达 `netdb` 函数的典型路径，以 HTTP 请求为例：

1. **Java 代码 (Android Framework):**  应用程序使用 `java.net.URL`, `java.net.HttpURLConnection` 等类发起 HTTP 请求。
   ```java
   URL url = new URL("http://www.example.com");
   HttpURLConnection connection = (HttpURLConnection) url.openConnection();
   InputStream inputStream = connection.getInputStream();
   // ...
   ```
2. **Native 代码 (Android Framework / NDK):** `HttpURLConnection` 的底层实现会调用 native 方法（通过 JNI）。这些 native 代码可能位于 `libandroid_runtime.so` 或其他 Android 系统库中。
3. **Socket 创建和连接:**  native 代码会使用 socket 相关的系统调用（例如 `socket()`, `connect()`) 来建立网络连接。在 `connect()` 之前，需要知道服务器的 IP 地址。
4. **域名解析:**  为了获取服务器的 IP 地址，native 代码会调用 Bionic 库中的 `getaddrinfo()` 函数。
5. **`getaddrinfo()` 实现:**  `getaddrinfo()` 函数会按照上面描述的步骤进行域名解析，可能查询本地 hosts 文件或向 DNS 服务器发起请求。
6. **返回 IP 地址:** `getaddrinfo()` 返回解析到的 IP 地址信息。
7. **`connect()` 调用:**  native 代码使用解析到的 IP 地址和端口号调用 `connect()` 系统调用，建立与服务器的 TCP 连接。

**Frida Hook 示例调试步骤**

假设我们想 hook `getaddrinfo()` 函数，观察其输入参数和返回值：

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "getaddrinfo"), {
    onEnter: function(args) {
        var host = Memory.readUtf8String(args[0]);
        var service = Memory.readUtf8String(args[1]);
        console.log("[*] getaddrinfo called");
        console.log("[*] \tHost: " + host);
        console.log("[*] \tService: " + service);
        this.host = host;
        this.service = service;
    },
    onLeave: function(retval) {
        console.log("[*] getaddrinfo returned: " + retval);
        if (retval == 0) {
            var addrinfoPtr = ptr(this.context.r3); // 假设 ai 指针在 r3 寄存器中 (可能需要根据架构调整)
            if (!addrinfoPtr.isNull()) {
                var addrinfo = Memory.readPointer(addrinfoPtr);
                // 可以进一步解析 addrinfo 结构体的内容
                console.log("[*] \taddrinfo pointer: " + addrinfo);
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤解释:**

1. **导入 Frida 库:** 导入必要的 Frida 库。
2. **指定目标应用:**  将 `package_name` 替换为你要调试的 Android 应用的包名。
3. **连接到设备和进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到 USB 设备上的目标应用进程。
4. **编写 Frida Script:**
   * `Interceptor.attach`:  用于 hook `getaddrinfo` 函数。
   * `Module.findExportByName("libc.so", "getaddrinfo")`: 找到 `libc.so` 中导出的 `getaddrinfo` 函数。
   * `onEnter`:  在 `getaddrinfo` 函数被调用前执行。
     * `args`:  包含函数参数的数组。`args[0]` 是主机名，`args[1]` 是服务名。
     * `Memory.readUtf8String()`: 读取内存中的字符串。
     * `this.host`, `this.service`:  将参数存储到 `this` 上，以便在 `onLeave` 中访问。
   * `onLeave`: 在 `getaddrinfo` 函数返回后执行。
     * `retval`:  函数的返回值。
     * `this.context.r3`:  尝试获取 `getaddrinfo` 的第四个参数 (`ai`)，该参数是指向 `addrinfo*` 的指针。**注意：寄存器位置可能因架构和调用约定而异，需要根据实际情况调整。**
     * `Memory.readPointer()`: 读取指针指向的内存地址。
5. **加载和运行 Script:** 将 Script 加载到目标进程并运行。
6. **执行应用操作:**  在你的 Android 应用中触发需要进行域名解析的操作（例如访问一个网址）。
7. **查看 Frida 输出:** Frida 会在终端输出 `getaddrinfo` 的调用信息，包括主机名、服务名以及返回值。

这个 Frida 示例提供了一个基本的调试框架。你可以根据需要扩展它，例如解析 `addrinfo` 结构体的更多内容，或者 hook 其他相关的 `netdb` 函数。

希望这个详细的解释能够帮助你理解 `bionic/tests/netdb_test.cpp` 文件及其背后的原理和应用场景。

### 提示词
```
这是目录为bionic/tests/netdb_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2013 The Android Open Source Project
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

#include <netdb.h>

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/socket.h>
#include <sys/types.h>

// https://code.google.com/p/android/issues/detail?id=13228
TEST(netdb, freeaddrinfo_NULL) {
  freeaddrinfo(nullptr);
}

TEST(netdb, getaddrinfo_NULL_host) {
  // It's okay for the host argument to be NULL, as long as service isn't.
  addrinfo* ai = nullptr;
  ASSERT_EQ(0, getaddrinfo(nullptr, "smtp", nullptr, &ai));
  // (sockaddr_in::sin_port and sockaddr_in6::sin6_port overlap.)
  ASSERT_EQ(25U, ntohs(reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_port));
  freeaddrinfo(ai);
}

TEST(netdb, getaddrinfo_NULL_service) {
  // It's okay for the service argument to be NULL, as long as host isn't.
  addrinfo* ai = nullptr;
  ASSERT_EQ(0, getaddrinfo("localhost", nullptr, nullptr, &ai));
  ASSERT_TRUE(ai != nullptr);
  freeaddrinfo(ai);
}

TEST(netdb, getaddrinfo_NULL_hints) {
  addrinfo* ai = nullptr;
  ASSERT_EQ(0, getaddrinfo("localhost", "9999", nullptr, &ai));

  bool saw_tcp = false;
  bool saw_udp = false;
  for (addrinfo* p = ai; p != nullptr; p = p->ai_next) {
    ASSERT_TRUE(p->ai_family == AF_INET || p->ai_family == AF_INET6);
    if (p->ai_socktype == SOCK_STREAM) {
      ASSERT_EQ(IPPROTO_TCP, p->ai_protocol);
      saw_tcp = true;
    } else if (p->ai_socktype == SOCK_DGRAM) {
      ASSERT_EQ(IPPROTO_UDP, p->ai_protocol);
      saw_udp = true;
    }
  }
  ASSERT_TRUE(saw_tcp);
  ASSERT_TRUE(saw_udp);

  freeaddrinfo(ai);
}

TEST(netdb, getaddrinfo_service_lookup) {
  addrinfo* ai = nullptr;
  ASSERT_EQ(0, getaddrinfo("localhost", "smtp", nullptr, &ai));
  ASSERT_EQ(SOCK_STREAM, ai->ai_socktype);
  ASSERT_EQ(IPPROTO_TCP, ai->ai_protocol);
  ASSERT_EQ(25, ntohs(reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_port));
  freeaddrinfo(ai);
}

TEST(netdb, getaddrinfo_hints) {
  addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM, .ai_protocol = IPPROTO_TCP};

  addrinfo* ai = nullptr;
  ASSERT_EQ(0, getaddrinfo( "localhost", "9999", &hints, &ai));
  ASSERT_TRUE(ai != nullptr);
  // In glibc, getaddrinfo() converts ::1 to 127.0.0.1 for localhost,
  // so one or two addrinfo may be returned.
  addrinfo* tai = ai;
  while (tai != nullptr) {
    ASSERT_EQ(AF_INET, tai->ai_family);
    ASSERT_EQ(SOCK_STREAM, tai->ai_socktype);
    ASSERT_EQ(IPPROTO_TCP, tai->ai_protocol);
    tai = tai->ai_next;
  }
  freeaddrinfo(ai);
}

TEST(netdb, getaddrinfo_ip6_localhost) {
  addrinfo* ai = nullptr;
  ASSERT_EQ(0, getaddrinfo("ip6-localhost", nullptr, nullptr, &ai));
  ASSERT_TRUE(ai != nullptr);
  ASSERT_GE(ai->ai_addrlen, static_cast<socklen_t>(sizeof(sockaddr_in6)));
  ASSERT_TRUE(ai->ai_addr != nullptr);
  sockaddr_in6 *addr = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
  ASSERT_EQ(addr->sin6_family, AF_INET6);
  ASSERT_EQ(0, memcmp(&addr->sin6_addr, &in6addr_loopback, sizeof(in6_addr)));
  freeaddrinfo(ai);
}

TEST(netdb, getnameinfo_salen) {
  sockaddr_storage ss = {};
  sockaddr* sa = reinterpret_cast<sockaddr*>(&ss);
  char tmp[16];

  ss.ss_family = AF_INET;
  socklen_t too_much = sizeof(ss);
  socklen_t just_right = sizeof(sockaddr_in);
  socklen_t too_little = sizeof(sockaddr_in) - 1;

  ASSERT_EQ(0, getnameinfo(sa, too_much, tmp, sizeof(tmp), nullptr, 0, NI_NUMERICHOST));
  ASSERT_STREQ("0.0.0.0", tmp);
  ASSERT_EQ(0, getnameinfo(sa, just_right, tmp, sizeof(tmp), nullptr, 0, NI_NUMERICHOST));
  ASSERT_STREQ("0.0.0.0", tmp);
  ASSERT_EQ(EAI_FAMILY, getnameinfo(sa, too_little, tmp, sizeof(tmp), nullptr, 0, NI_NUMERICHOST));

  ss.ss_family = AF_INET6;
  just_right = sizeof(sockaddr_in6);
  too_little = sizeof(sockaddr_in6) - 1;
  too_much = just_right + 1;

  ASSERT_EQ(0, getnameinfo(sa, too_much, tmp, sizeof(tmp), nullptr, 0, NI_NUMERICHOST));
  ASSERT_STREQ("::", tmp);
  ASSERT_EQ(0, getnameinfo(sa, just_right, tmp, sizeof(tmp), nullptr, 0, NI_NUMERICHOST));
  ASSERT_STREQ("::", tmp);
  ASSERT_EQ(EAI_FAMILY, getnameinfo(sa, too_little, tmp, sizeof(tmp), nullptr, 0, NI_NUMERICHOST));
}

TEST(netdb, getnameinfo_localhost) {
  char host[NI_MAXHOST];
  sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001)};
  ASSERT_EQ(0, getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                           host, sizeof(host), nullptr, 0, 0));
  ASSERT_STREQ(host, "localhost");
}

static void VerifyLocalhostName(const char* name) {
  // Test possible localhost name and aliases, which depend on /etc/hosts or /system/etc/hosts.
  ASSERT_TRUE(strcmp(name, "localhost") == 0 ||
              strcmp(name, "ip6-localhost") == 0 ||
              strcmp(name, "ip6-loopback") == 0) << name;
}

TEST(netdb, getnameinfo_ip6_localhost) {
  char host[NI_MAXHOST];
  sockaddr_in6 addr = {.sin6_family = AF_INET6, .sin6_addr = in6addr_loopback};
  ASSERT_EQ(0, getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                           host, sizeof(host), nullptr, 0, 0));
  VerifyLocalhostName(host);
}

static void VerifyLocalhost(hostent *hent) {
  ASSERT_TRUE(hent != nullptr);
  VerifyLocalhostName(hent->h_name);
  for (size_t i = 0; hent->h_aliases[i] != nullptr; ++i) {
    VerifyLocalhostName(hent->h_aliases[i]);
  }
  ASSERT_EQ(hent->h_addrtype, AF_INET);
  ASSERT_EQ(hent->h_addr[0], 127);
  ASSERT_EQ(hent->h_addr[1], 0);
  ASSERT_EQ(hent->h_addr[2], 0);
  ASSERT_EQ(hent->h_addr[3], 1);
}

TEST(netdb, gethostbyname) {
  hostent* hp = gethostbyname("localhost");
  VerifyLocalhost(hp);
}

TEST(netdb, gethostbyname2) {
  hostent* hp = gethostbyname2("localhost", AF_INET);
  VerifyLocalhost(hp);
}

TEST(netdb, gethostbyname_r) {
  hostent hent;
  hostent *hp;
  char buf[512];
  int err;
  int result = gethostbyname_r("localhost", &hent, buf, sizeof(buf), &hp, &err);
  ASSERT_EQ(0, result);
  VerifyLocalhost(hp);

  // Change hp->h_addr to test reentrancy.
  hp->h_addr[0] = 0;

  hostent hent2;
  hostent *hp2;
  char buf2[512];
  result = gethostbyname_r("localhost", &hent2, buf2, sizeof(buf2), &hp2, &err);
  ASSERT_EQ(0, result);
  VerifyLocalhost(hp2);

  ASSERT_EQ(0, hp->h_addr[0]);
}

TEST(netdb, gethostbyname2_r) {
  hostent hent;
  hostent *hp;
  char buf[512];
  int err;
  int result = gethostbyname2_r("localhost", AF_INET, &hent, buf, sizeof(buf), &hp, &err);
  ASSERT_EQ(0, result);
  VerifyLocalhost(hp);

  // Change hp->h_addr to test reentrancy.
  hp->h_addr[0] = 0;

  hostent hent2;
  hostent *hp2;
  char buf2[512];
  result = gethostbyname2_r("localhost", AF_INET, &hent2, buf2, sizeof(buf2), &hp2, &err);
  ASSERT_EQ(0, result);
  VerifyLocalhost(hp2);

  ASSERT_EQ(0, hp->h_addr[0]);
}

TEST(netdb, gethostbyaddr) {
  in_addr addr = { htonl(0x7f000001) };
  hostent *hp = gethostbyaddr(&addr, sizeof(addr), AF_INET);
  VerifyLocalhost(hp);
}

TEST(netdb, gethostbyaddr_r) {
  in_addr addr = { htonl(0x7f000001) };
  hostent hent;
  hostent *hp;
  char buf[512];
  int err;
  int result = gethostbyaddr_r(&addr, sizeof(addr), AF_INET, &hent, buf, sizeof(buf), &hp, &err);
  ASSERT_EQ(0, result);
  VerifyLocalhost(hp);

  // Change hp->h_addr to test reentrancy.
  hp->h_addr[0] = 0;

  hostent hent2;
  hostent *hp2;
  char buf2[512];
  result = gethostbyaddr_r(&addr, sizeof(addr), AF_INET, &hent2, buf2, sizeof(buf2), &hp2, &err);
  ASSERT_EQ(0, result);
  VerifyLocalhost(hp2);

  ASSERT_EQ(0, hp->h_addr[0]);
}

#if defined(ANDROID_HOST_MUSL)
// musl doesn't define NETDB_INTERNAL.  It also never sets *err to -1, but
// since gethostbyname_r is a glibc extension, the difference in behavior
// between musl and  glibc should probably be considered a bug in musl.
#define NETDB_INTERNAL -1
#endif

TEST(netdb, gethostbyname_r_ERANGE) {
  hostent hent;
  hostent *hp;
  char buf[4]; // Use too small buffer.
  int err = 0;
  int result = gethostbyname_r("localhost", &hent, buf, sizeof(buf), &hp, &err);
  EXPECT_EQ(NETDB_INTERNAL, err);
  EXPECT_EQ(ERANGE, result);
  EXPECT_EQ(nullptr, hp);
}

TEST(netdb, gethostbyname2_r_ERANGE) {
  hostent hent;
  hostent *hp;
  char buf[4]; // Use too small buffer.
  int err = 0;
  int result = gethostbyname2_r("localhost", AF_INET, &hent, buf, sizeof(buf), &hp, &err);
  EXPECT_EQ(NETDB_INTERNAL, err);
  EXPECT_EQ(ERANGE, result);
  EXPECT_EQ(nullptr, hp);
}

TEST(netdb, gethostbyaddr_r_ERANGE) {
  in_addr addr = { htonl(0x7f000001) };
  hostent hent;
  hostent *hp;
  char buf[4]; // Use too small buffer.
  int err = 0;
  int result = gethostbyaddr_r(&addr, sizeof(addr), AF_INET, &hent, buf, sizeof(buf), &hp, &err);
  EXPECT_EQ(NETDB_INTERNAL, err);
  EXPECT_EQ(ERANGE, result);
  EXPECT_EQ(nullptr, hp);
}

TEST(netdb, gethostbyname_r_HOST_NOT_FOUND) {
  hostent hent;
  hostent *hp;
  char buf[BUFSIZ];
  int err;
  int result = gethostbyname_r("does.not.exist.google.com", &hent, buf, sizeof(buf), &hp, &err);
  EXPECT_EQ(HOST_NOT_FOUND, err);
  EXPECT_EQ(0, result);
  EXPECT_EQ(nullptr, hp);
}

TEST(netdb, gethostbyname2_r_HOST_NOT_FOUND) {
  hostent hent;
  hostent *hp;
  char buf[BUFSIZ];
  int err;
  int result = gethostbyname2_r("does.not.exist.google.com", AF_INET, &hent, buf, sizeof(buf), &hp, &err);
  EXPECT_EQ(HOST_NOT_FOUND, err);
  EXPECT_EQ(0, result);
  EXPECT_EQ(nullptr, hp);
}

TEST(netdb, gethostbyaddr_r_HOST_NOT_FOUND) {
  in_addr addr = { htonl(0xffffffff) };
  hostent hent;
  hostent *hp;
  char buf[BUFSIZ];
  int err;
  int result = gethostbyaddr_r(&addr, sizeof(addr), AF_INET, &hent, buf, sizeof(buf), &hp, &err);
  EXPECT_EQ(HOST_NOT_FOUND, err);
  EXPECT_EQ(0, result);
  EXPECT_EQ(nullptr, hp);
}

TEST(netdb, getservbyname) {
  // smtp is TCP-only, so we know we'll get 25/tcp back.
  servent* s = getservbyname("smtp", nullptr);
  ASSERT_TRUE(s != nullptr);
  ASSERT_STREQ("smtp", s->s_name);
  ASSERT_EQ(25, ntohs(s->s_port));
  ASSERT_STREQ("tcp", s->s_proto);

  // We get the same result by explicitly asking for tcp.
  s = getservbyname("smtp", "tcp");
  ASSERT_TRUE(s != nullptr);
  ASSERT_STREQ("smtp", s->s_name);
  ASSERT_EQ(25, ntohs(s->s_port));
  ASSERT_STREQ("tcp", s->s_proto);

  // And we get a failure if we explicitly ask for udp.
  s = getservbyname("smtp", "udp");
  ASSERT_TRUE(s == nullptr);

  // But there are actually udp services.
  s = getservbyname("echo", "udp");
  ASSERT_TRUE(s != nullptr);
  ASSERT_STREQ("echo", s->s_name);
  ASSERT_EQ(7, ntohs(s->s_port));
  ASSERT_STREQ("udp", s->s_proto);
}

TEST(netdb, getservbyport) {
  // smtp is TCP-only, so we know we'll get 25/tcp back.
  servent* s = getservbyport(htons(25), nullptr);
  ASSERT_TRUE(s != nullptr);
  ASSERT_STREQ("smtp", s->s_name);
  ASSERT_EQ(25, ntohs(s->s_port));
  ASSERT_STREQ("tcp", s->s_proto);

  // We get the same result by explicitly asking for tcp.
  s = getservbyport(htons(25), "tcp");
  ASSERT_TRUE(s != nullptr);
  ASSERT_STREQ("smtp", s->s_name);
  ASSERT_EQ(25, ntohs(s->s_port));
  ASSERT_STREQ("tcp", s->s_proto);

  // And we get a failure if we explicitly ask for udp.
  s = getservbyport(htons(25), "udp");
  ASSERT_TRUE(s == nullptr);

  // But there are actually udp services.
  s = getservbyport(htons(7), "udp");
  ASSERT_TRUE(s != nullptr);
  ASSERT_STREQ("echo", s->s_name);
  ASSERT_EQ(7, ntohs(s->s_port));
  ASSERT_STREQ("udp", s->s_proto);
}

TEST(netdb, endnetent_getnetent_setnetent) {
  setnetent(0);
  setnetent(1);
  endnetent();
  while (getnetent() != nullptr) {
  }
}

TEST(netdb, getnetbyaddr) {
  getnetbyaddr(0, 0);
}

TEST(netdb, getnetbyname) {
  getnetbyname("x");
}

TEST(netdb, endprotoent_getprotoent_setprotoent) {
  setprotoent(0);
  setprotoent(1);
  endprotoent();
  while (getprotoent() != nullptr) {
  }
}

TEST(netdb, getprotobyname) {
  getprotobyname("tcp");
}

TEST(netdb, getprotobynumber) {
  getprotobynumber(6);
}

TEST(netdb, endservent_getservent_setservent) {
  setservent(0);
  setservent(1);
  endservent();
  size_t service_count = 0;
  while (getservent() != nullptr) {
    ++service_count;
  }
  ASSERT_GT(service_count, 0U);
}

TEST(netdb, getservbyname_getservent_conflicts) {
  // Calling getservbyname shouldn't affect getservent's iteration order.
  endservent();
  while (getservent() != nullptr) {
    ASSERT_TRUE(getservbyname("smtp", "tcp") != nullptr);
  }
}

TEST(netdb, getservbyport_getservent_conflicts) {
  // Calling getservbyport shouldn't affect getservent's iteration order.
  endservent();
  while (getservent() != nullptr) {
    ASSERT_TRUE(getservbyport(htons(25), "tcp") != nullptr);
  }
}

TEST(netdb, endservent_resets) {
  endservent();
  std::string first_service(getservent()->s_name);
  endservent();
  ASSERT_EQ(first_service, std::string(getservent()->s_name));
}

TEST(netdb, setservent_resets) {
  endservent();
  std::string first_service(getservent()->s_name);
  setservent(0);
  ASSERT_EQ(first_service, std::string(getservent()->s_name));
}

TEST(netdb, endhostent_gethostent_sethostent) {
  sethostent(0);
  sethostent(1);
  endhostent();
  size_t host_count = 0;
  while (gethostent() != nullptr) {
    ++host_count;
  }
  ASSERT_GT(host_count, 0U);
}

TEST(netdb, endhostent_resets) {
  endhostent();
  std::string first_host(gethostent()->h_name);
  endhostent();
  ASSERT_EQ(first_host, std::string(gethostent()->h_name));
}

TEST(netdb, sethostent_resets) {
  endhostent();
  std::string first_host(gethostent()->h_name);
  sethostent(0);
  ASSERT_EQ(first_host, std::string(gethostent()->h_name));
}
```