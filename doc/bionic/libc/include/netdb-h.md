Response:
Let's break down the thought process to generate the comprehensive analysis of `bionic/libc/include/netdb.h`.

**1. Understanding the Core Request:**

The fundamental request is to analyze a C header file (`netdb.h`) from Android's Bionic library. The analysis needs to cover its functionality, relationship to Android, implementation details (where possible from the header), dynamic linking aspects, potential errors, and how Android frameworks use it. The response should be in Chinese and include Frida hooking examples.

**2. Initial Information Extraction (Surface Level):**

First, I skim the header file itself. I notice:

* **Copyright notices:**  Indicates it's derived from BSD and Digital Equipment Corporation work. This is a strong clue about its purpose: network database related functions.
* **Include directives:**  `<sys/cdefs.h>`, `<sys/types.h>`, `<sys/socket.h>`. This confirms its role in network programming, as it relies on socket structures and definitions.
* **`#define` constants:**  Paths like `/system/etc/hosts`, `/system/etc/services`, error codes (like `HOST_NOT_FOUND`, `EAI_ADDRFAMILY`), and flags for functions. These are crucial for understanding the configuration files and the behavior of the functions.
* **`struct` definitions:** `hostent`, `netent`, `servent`, `protoent`, `addrinfo`. These are the core data structures used by the network database functions. I recognize these from standard network programming.
* **Function declarations:**  A series of function prototypes like `getaddrinfo`, `gethostbyname`, `getservbyport`, etc. These are the primary interface the header provides. The `_Nullable` and `_Nonnull` annotations are Bionic specific and relate to null safety. The `__INTRODUCED_IN(xx)` macros indicate API levels.

**3. Categorizing Functionality:**

Based on the structures and function names, I can categorize the functionality:

* **Host resolution:**  `gethostbyname`, `gethostbyaddr`, `getaddrinfo`. These functions translate hostnames to IP addresses and vice versa.
* **Network information:** `getnetbyname`, `getnetbyaddr`. These deal with network names and numbers.
* **Service information:** `getservbyname`, `getservbyport`. These map service names (like "http") to port numbers and protocols.
* **Protocol information:** `getprotobyname`, `getprotobynumber`. These map protocol names (like "tcp") to protocol numbers.
* **Error handling:** `h_errno`, `herror`, `hstrerror`, `gai_strerror`. These are for retrieving and displaying error messages related to the network database functions.
* **Modern address resolution:** `getaddrinfo`, `getnameinfo`, `freeaddrinfo`. These are the more modern, protocol-independent replacements for the older `gethostby...` functions.

**4. Connecting to Android:**

The presence of paths like `/system/etc/hosts` strongly links this header to Android's networking configuration. I know Android uses these files for basic name resolution. The functions defined in this header are fundamental for any application that needs to interact with the network. Examples would be:

* **Web browsers:**  Use `getaddrinfo` to resolve website addresses.
* **Networking utilities (ping, traceroute):** Rely on these functions for hostname resolution.
* **System services:** May use these functions for internal communication.

**5. Implementation Details (Header Analysis Limitations):**

The header file *declares* the functions but doesn't *implement* them. Therefore, detailed implementation explanations are limited. I can, however, discuss the *general concepts* behind these functions:

* **File parsing:** Functions like `gethostbyname` likely read and parse the `/system/etc/hosts` file.
* **DNS resolution:** For names not found in `/system/etc/hosts`, they would initiate DNS queries (this detail isn't in the header but is implicit).
* **Data structures:** Explain how the `hostent`, `servent`, etc., structures store the retrieved information.

**6. Dynamic Linking:**

The header file itself doesn't contain dynamic linking information. However, the functions declared here are *implemented* in shared libraries (likely `libc.so`). To address the dynamic linking aspect, I need to:

* **Illustrate a typical `libc.so` layout:** Show sections like `.text`, `.data`, `.bss`, `.dynsym`, `.dynstr`, and where the network database functions would reside.
* **Describe the linking process:** Explain how the dynamic linker (`/system/bin/linker64` or similar) resolves symbols at runtime, referencing the GOT and PLT.

**7. Error Scenarios:**

Based on my understanding of network programming, I can anticipate common errors:

* **Incorrect hostname/service name:** Leading to `HOST_NOT_FOUND`, `EAI_NONAME`, etc.
* **Network issues:** Causing timeouts and `TRY_AGAIN`.
* **Incorrect API usage:**  Forgetting to free memory allocated by `getaddrinfo`.

**8. Android Framework and NDK Usage:**

* **Android Framework:**  High-level Java APIs like `InetAddress.getByName()` internally call down to native code, eventually reaching these `netdb.h` functions in Bionic.
* **NDK:**  NDK developers can directly use these C functions in their native code.

**9. Frida Hooking:**

For each key function (e.g., `getaddrinfo`, `gethostbyname`), I can create a basic Frida hook example:

* **Show how to attach to a process.**
* **Intercept the function call.**
* **Log the input arguments.**
* **Log the return value.**

**10. Structuring the Response (Chinese):**

Finally, I organize the information into a logical flow, ensuring clarity and accuracy in the Chinese translation. I use headings and bullet points to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on file parsing.
* **Correction:** Realize that DNS resolution is a crucial aspect not explicitly in the header, but essential to mention for a complete picture.
* **Initial thought:**  Just list the functions.
* **Refinement:** Group functions by category to better explain their purpose.
* **Initial thought:**  Provide very basic Frida examples.
* **Refinement:** Make the Frida examples more illustrative by logging arguments and return values.
* **Ensure language accuracy:** Double-check technical terms and translations into Chinese.

By following these steps, and continually refining the analysis, I can generate a comprehensive and accurate response to the prompt. The key is to move from the surface-level information in the header file to a deeper understanding of the underlying concepts and their role within the Android ecosystem.
这是一个名为 `netdb.h` 的头文件，它位于 Android Bionic 库的 `include/netdb.handroid` 目录下。Bionic 是 Android 的 C 库、数学库和动态链接器。这个头文件定义了用于网络数据库操作的接口和数据结构。这些操作允许程序查询网络主机、服务和协议的信息。

**它的功能:**

`netdb.h` 定义了以下主要功能，用于进行网络相关的查找和信息获取：

1. **主机信息查找 (Host Information):**
   - 根据主机名获取主机信息（如 IP 地址、别名）：`gethostbyname`, `gethostbyname2`, `gethostbyname_r`, `gethostbyname2_r`
   - 根据 IP 地址获取主机信息：`gethostbyaddr`, `gethostbyaddr_r`
   - 获取所有主机信息的入口点：`gethostent`, `sethostent`, `endhostent`
   - 获取地址信息（更通用的方式，支持 IPv4 和 IPv6）：`getaddrinfo`, `freeaddrinfo`
   - 根据套接字地址获取主机名和服务名：`getnameinfo`

2. **网络信息查找 (Network Information):**
   - 根据网络号获取网络信息：`getnetbyaddr`
   - 根据网络名获取网络信息：`getnetbyname`
   - 获取所有网络信息的入口点：`getnetent`, `setnetent`, `endnetent` (在较新的 Android 版本中已废弃，返回 nullptr)

3. **服务信息查找 (Service Information):**
   - 根据服务名和协议获取服务信息（如端口号）：`getservbyname`
   - 根据端口号和协议获取服务信息：`getservbyport`
   - 获取所有服务信息的入口点：`getservent`, `setservent`, `endservent`

4. **协议信息查找 (Protocol Information):**
   - 根据协议名获取协议信息（如协议号）：`getprotobyname`
   - 根据协议号获取协议信息：`getprotobynumber`
   - 获取所有协议信息的入口点：`getprotoent`, `setprotoent`, `endprotoent` (在较新的 Android 版本中已废弃，返回 nullptr)

5. **错误处理 (Error Handling):**
   - 获取主机相关的错误代码：`h_errno`, `__get_h_errno`
   - 将主机错误代码转换为可读的错误消息：`hstrerror`
   - 打印主机错误消息到标准错误输出：`herror`
   - 将 `getaddrinfo` 错误代码转换为可读的错误消息：`gai_strerror`

**与 Android 功能的关系及举例说明:**

`netdb.h` 中定义的函数是 Android 网络功能的基础。许多 Android 系统服务和应用程序都依赖这些函数来进行网络通信。

**举例说明:**

* **域名解析:** 当 Android 应用程序需要连接到一个使用域名（如 `www.google.com`）的服务器时，它会调用 `getaddrinfo` 或 `gethostbyname` 来将域名解析为 IP 地址。
* **服务发现:** 应用程序可能需要找到特定服务（如 HTTP、FTP）的端口号。它们可以使用 `getservbyname` 来根据服务名称获取端口号。
* **系统服务:** Android 系统服务（如 `netd`，负责网络管理）使用这些函数来处理网络配置和连接。例如，`netd` 可能使用 `getaddrinfo` 来解析网络接口的配置信息。

**详细解释每一个 libc 函数的功能是如何实现的:**

由于这是一个头文件，它只声明了函数的接口，并没有包含具体的实现代码。这些函数的实现位于 Bionic 库的源代码中（通常是 `libc.so`）。

以下是每个主要函数概念上的实现方式：

* **`gethostbyname(const char *name)`:**
    1. **查找本地 `/system/etc/hosts` 文件:** 首先，它会查找 `/system/etc/hosts` 文件，看是否存在与 `name` 匹配的条目。如果找到，则从该文件中提取主机信息。
    2. **DNS 查询:** 如果在 `/system/etc/hosts` 文件中没有找到，它会向配置的 DNS 服务器发送 DNS 查询请求，以解析该主机名。
    3. **缓存:**  为了提高效率，结果可能会被缓存一段时间。
    4. **返回 `hostent` 结构体:** 成功后，它会返回一个指向 `hostent` 结构体的指针，该结构体包含了主机的官方名称、别名、地址类型、地址长度以及 IP 地址列表。

* **`gethostbyaddr(const void *addr, socklen_t len, int type)`:**
    1. **查找本地 `/system/etc/hosts` 文件:**  与 `gethostbyname` 类似，它也会先查找本地 `/system/etc/hosts` 文件，尝试匹配提供的 IP 地址。
    2. **反向 DNS 查询:** 如果在本地文件中没有找到，它会向配置的 DNS 服务器发送反向 DNS 查询（PTR 记录），以查找与该 IP 地址关联的主机名。
    3. **返回 `hostent` 结构体:** 成功后，返回包含主机信息的 `hostent` 结构体。

* **`getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)`:**
    1. **处理 `node` 和 `service` 参数:**  `node` 可以是主机名或数字地址，`service` 可以是服务名或端口号。
    2. **根据 `hints` 进行过滤:**  `hints` 结构体允许调用者指定地址族、套接字类型和协议等偏好。
    3. **查找本地文件:**  会查找 `/system/etc/hosts` 和 `/system/etc/services` 等本地配置文件。
    4. **DNS 查询和名称解析:**  如果需要，会进行 DNS 查询来解析主机名。
    5. **创建 `addrinfo` 链表:**  返回一个指向 `addrinfo` 结构体链表的指针，每个结构体包含一个可用的网络地址信息（包括地址族、套接字类型、协议、套接字地址等）。`getaddrinfo` 是一个更现代、更灵活的函数，支持 IPv4 和 IPv6。

* **`getservbyname(const char *name, const char *proto)`:**
    1. **查找 `/system/etc/services` 文件:**  读取 `/system/etc/services` 文件，查找与 `name` 和 `proto` 匹配的条目。
    2. **返回 `servent` 结构体:** 如果找到匹配项，返回一个指向 `servent` 结构体的指针，该结构体包含服务的官方名称、别名、端口号和协议。

* **`getservbyport(int port, const char *proto)`:**
    1. **查找 `/system/etc/services` 文件:**  读取 `/system/etc/services` 文件，查找与 `port` 和 `proto` 匹配的条目。请注意，`port` 需要以网络字节序传入。
    2. **返回 `servent` 结构体:** 如果找到匹配项，返回一个指向 `servent` 结构体。

* **`getprotobyname(const char *name)` 和 `getprotobynumber(int proto)`:**
    1. **查找 `/system/etc/protocols` 文件:**  这些函数读取 `/system/etc/protocols` 文件，查找与协议名或协议号匹配的条目。
    2. **返回 `protoent` 结构体:**  如果找到匹配项，返回一个指向 `protoent` 结构体的指针，包含协议的官方名称、别名和协议号。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`netdb.h` 本身是头文件，不涉及动态链接。但是，其中声明的函数在运行时需要从共享库 (`libc.so`) 中加载。

**`libc.so` 布局样本 (简化):**

```
libc.so:
  .text         # 包含可执行代码
    gethostbyname:
      ... 代码 ...
    getaddrinfo:
      ... 代码 ...
    ... 其他 netdb 函数 ...
  .data         # 包含已初始化的全局变量
  .bss          # 包含未初始化的全局变量
  .dynsym       # 动态符号表，列出导出的符号 (函数名、变量名等)
    gethostbyname
    getaddrinfo
    ...
  .dynstr       # 动态字符串表，包含符号表中字符串的实际内容
    "gethostbyname"
    "getaddrinfo"
    ...
  .rel.dyn      # 动态重定位表，指示需要在加载时修改的位置
  .plt          # 程序链接表 (Procedure Linkage Table)，用于延迟绑定
  .got          # 全局偏移表 (Global Offset Table)，用于存储外部符号的地址
```

**链接的处理过程:**

1. **编译时:** 当应用程序链接到 `libc.so` 时，链接器会在其可执行文件中创建一个动态链接段。
2. **加载时:** 当 Android 系统加载应用程序时，动态链接器 (`/system/bin/linker64` 或类似) 负责加载所有需要的共享库，包括 `libc.so`。
3. **符号解析:** 动态链接器会遍历应用程序和 `libc.so` 的动态符号表 (`.dynsym`) 和动态字符串表 (`.dynstr`)，找到应用程序中引用的 `netdb.h` 中声明的函数的实际地址。
4. **重定位:** 动态链接器使用重定位表 (`.rel.dyn`) 来修改应用程序的全局偏移表 (`.got`) 和程序链接表 (`.plt`) 中的条目，将它们指向 `libc.so` 中对应函数的地址。
5. **延迟绑定 (Lazy Binding):** 通常，为了提高启动速度，函数绑定是延迟的。当应用程序第一次调用 `gethostbyname` 时，会跳转到 `.plt` 中的一个桩代码。这个桩代码会调用动态链接器来解析 `gethostbyname` 的实际地址，并将该地址写入 `.got` 中。后续调用将直接跳转到 `.got` 中存储的地址。

**如果做了逻辑推理，请给出假设输入与输出:**

**假设输入 `gethostbyname("www.google.com")`:**

* **逻辑推理:**
    1. 函数首先查找本地 `/system/etc/hosts` 文件。假设该文件中没有 `www.google.com` 的条目。
    2. 函数会发起一个 DNS 查询请求，向配置的 DNS 服务器询问 `www.google.com` 的 IP 地址。
    3. DNS 服务器返回 `www.google.com` 的一个或多个 IP 地址（例如 `142.250.180.142`）。
    4. 函数将这些信息填充到 `hostent` 结构体中。

* **假设输出 (指向 `hostent` 结构体的指针):**

```c
struct hostent {
  char *h_name = "www.google.com";
  char **h_aliases = {NULL}; // 通常会有一些别名，这里简化
  int h_addrtype = AF_INET; // 或 AF_INET6
  int h_length = 4; // 或 16
  char **h_addr_list = { /* 指向包含 IP 地址的内存 */ };
  // h_addr 指向 h_addr_list[0]
};
// h_addr_list[0] 的内容可能是：{ 142, 250, 180, 142 } (网络字节序)
```

**假设输入 `getservbyname("http", "tcp")`:**

* **逻辑推理:**
    1. 函数读取 `/system/etc/services` 文件。
    2. 它会找到包含 "http" 和 "tcp" 的行，该行可能类似于：`http        80/tcp`。
    3. 函数解析该行，提取端口号 (80) 和协议。

* **假设输出 (指向 `servent` 结构体的指针):**

```c
struct servent {
  char *s_name = "http";
  char **s_aliases = {NULL}; // 可能有别名
  int s_port = htons(80); // 网络字节序
  char *_Nullable s_proto = "tcp";
};
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记检查返回值:**  许多 `netdb.h` 中的函数在出错时返回 `NULL` 指针。如果用户程序没有检查返回值，就直接访问返回的指针，会导致程序崩溃。

   ```c
   struct hostent *host = gethostbyname("invalid_hostname");
   // 错误：如果 gethostbyname 返回 NULL，访问 host->h_addr 会导致崩溃
   struct in_addr addr = *((struct in_addr *)host->h_addr);
   ```

2. **内存泄漏:**  `getaddrinfo` 函数会分配内存来存储 `addrinfo` 结构体链表。用户程序必须调用 `freeaddrinfo` 来释放这些内存，否则会导致内存泄漏。

   ```c
   struct addrinfo *res;
   getaddrinfo("www.example.com", "80", NULL, &res);
   // ... 使用 res ...
   // 忘记调用 freeaddrinfo(res);
   ```

3. **阻塞调用:**  `gethostbyname` 等函数可能会阻塞当前线程，直到 DNS 查询完成。在 UI 线程中直接调用这些函数会导致应用程序无响应。应该在后台线程中执行这些操作。

4. **不正确的字节序:** 网络编程中，多字节数据（如端口号和 IP 地址）需要以网络字节序传输。用户可能会错误地使用主机字节序，导致连接失败。`htons` 和 `ntohs` 函数用于主机字节序和网络字节序之间的转换。

   ```c
   struct sockaddr_in server_addr;
   server_addr.sin_port = 80; // 错误：应该使用 htons(80)
   ```

5. **缓冲区溢出:** 在使用 `getnameinfo` 时，如果提供的缓冲区 `__host` 或 `__service` 不够大，可能会发生缓冲区溢出。

   ```c
   char host[64];
   char service[32];
   struct sockaddr_in sa;
   socklen_t sa_len = sizeof(sa);
   // 如果主机名或服务名很长，可能会溢出
   getnameinfo((struct sockaddr *)&sa, sa_len, host, sizeof(host), service, sizeof(service), 0);
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `netdb.h` 的路径:**

1. **Java 代码:** Android Framework 中的 Java 代码，例如 `java.net.InetAddress.getByName()`，是发起网络请求的常见入口点。
2. **Native 方法调用:** `InetAddress.getByName()` 最终会调用底层的 native 方法（通常在 `libjavacrypto.so` 或 `libnetd_client.so` 等库中）。
3. **JNI 调用:** 这些 native 方法通过 JNI (Java Native Interface) 与 C/C++ 代码交互。
4. **Bionic 库调用:** JNI 代码会调用 Bionic 库中的函数，例如 `getaddrinfo` 或 `gethostbyname`，这些函数在 `libc.so` 中实现，并在 `netdb.h` 中声明。

**NDK 到 `netdb.h` 的路径:**

1. **NDK C/C++ 代码:** 使用 Android NDK 开发的应用程序可以直接调用 `netdb.h` 中声明的函数。
2. **链接到 Bionic:** NDK 构建系统会将应用程序链接到 Bionic 库 (`libc.so`)。
3. **直接调用:** 应用程序可以直接调用 `getaddrinfo`、`gethostbyname` 等函数。

**Frida Hook 示例:**

以下是一个使用 Frida Hook `getaddrinfo` 函数的示例：

```javascript
// attach 到目标进程
function hook_getaddrinfo() {
  const getaddrinfoPtr = Module.findExportByName("libc.so", "getaddrinfo");
  if (getaddrinfoPtr) {
    Interceptor.attach(getaddrinfoPtr, {
      onEnter: function (args) {
        const node = args[0];
        const service = args[1];
        const hints = args[2];

        const nodeStr = node ? Memory.readUtf8String(node) : null;
        const serviceStr = service ? Memory.readUtf8String(service) : null;

        console.log("[getaddrinfo] node:", nodeStr, "service:", serviceStr);
        if (hints) {
          const ai_family = Memory.readS32(hints);
          const ai_socktype = Memory.readS32(hints.add(4));
          const ai_protocol = Memory.readS32(hints.add(8));
          console.log("[getaddrinfo] hints - family:", ai_family, "socktype:", ai_socktype, "protocol:", ai_protocol);
        }
      },
      onLeave: function (retval) {
        console.log("[getaddrinfo] returned:", retval);
        if (retval == 0) { // 成功
          const resPtr = Memory.readPointer(this.context.sp.add(Process.pointerSize * 2)); // 根据调用约定，结果指针通常在栈上
          if (resPtr) {
            const ai_family = Memory.readS32(resPtr);
            const ai_socktype = Memory.readS32(resPtr.add(4));
            const ai_protocol = Memory.readS32(resPtr.add(8));
            const ai_addrlen = Memory.readU32(resPtr.add(12));
            const ai_addr = Memory.readPointer(resPtr.add(24));
            if (ai_addr) {
              const sin_family = Memory.readU16(ai_addr);
              if (sin_family === 2) { // AF_INET
                const sin_port = Memory.readU16(ai_addr.add(2));
                const sin_addr = Memory.readU32(ai_addr.add(4));
                console.log("[getaddrinfo] result - family:", ai_family, "socktype:", ai_socktype, "protocol:", ai_protocol, "addrlen:", ai_addrlen, "port:", sin_port, "addr:", inet_ntoa(sin_addr));
              } else if (sin_family === 10) { // AF_INET6
                // 解析 IPv6 地址
                console.log("[getaddrinfo] result - IPv6 address");
              }
            }
          }
        }
      },
    });
  } else {
    console.error("Failed to find getaddrinfo in libc.so");
  }
}

function inet_ntoa(ip) {
  const part1 = (ip >> 0) & 0xFF;
  const part2 = (ip >> 8) & 0xFF;
  const part3 = (ip >> 16) & 0xFF;
  const part4 = (ip >> 24) & 0xFF;
  return `${part1}.${part2}.${part3}.${part4}`;
}

setImmediate(hook_getaddrinfo);
```

**Frida Hook 调试步骤:**

1. **确定目标进程:** 找到你想调试的网络应用程序的进程 ID 或进程名。
2. **运行 Frida:** 使用 Frida 连接到目标进程：`frida -U -f <package_name> -l script.js --no-pause` 或 `frida -p <pid> -l script.js`.
3. **观察输出:** Frida 脚本会在 `getaddrinfo` 函数被调用时打印出相关的参数（主机名、服务名、hints）和返回值。如果调用成功，还会尝试解析并打印出解析得到的 IP 地址和端口号。

你可以修改 Frida 脚本来 hook 其他 `netdb.h` 中声明的函数，例如 `gethostbyname`、`getservbyname` 等，以观察它们的行为和参数。这对于理解应用程序的网络行为以及排查网络相关问题非常有帮助。

### 提示词
```
这是目录为bionic/libc/include/netdb.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*-
 * Copyright (c) 1980, 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */

/*
 *      @(#)netdb.h	8.1 (Berkeley) 6/2/93
 *      From: Id: netdb.h,v 8.9 1996/11/19 08:39:29 vixie Exp $
 * $FreeBSD: /repoman/r/ncvs/src/include/netdb.h,v 1.41 2006/04/15 16:20:26 ume Exp $
 */

#ifndef _NETDB_H_
#define _NETDB_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef _PATH_HEQUIV
# define	_PATH_HEQUIV	"/system/etc/hosts.equiv"
#endif
#define	_PATH_HOSTS	"/system/etc/hosts"
#define	_PATH_NETWORKS	"/system/etc/networks"
#define	_PATH_PROTOCOLS	"/system/etc/protocols"
#define	_PATH_SERVICES	"/system/etc/services"

/*
 * Structures returned by network data base library.  All addresses are
 * supplied in host order, and returned in network order (suitable for
 * use in system calls).
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
struct hostent {
	char	*h_name;	/* official name of host */
	char	**h_aliases;	/* alias list */
	int	h_addrtype;	/* host address type */
	int	h_length;	/* length of address */
	char	**h_addr_list;	/* list of addresses from name server */
#define	h_addr	h_addr_list[0]	/* address, for backward compatibility */
};

struct netent {
	char		*n_name;	/* official name of net */
	char		**n_aliases;	/* alias list */
	int		n_addrtype;	/* net address type */
	uint32_t	n_net;		/* network # */
};

struct servent {
	char	*s_name;	/* official service name */
	char	**s_aliases;	/* alias list */
	int	s_port;		/* port # */
	char	* _Nullable s_proto;	/* protocol to use */
};

struct protoent {
	char	*p_name;	/* official protocol name */
	char	**p_aliases;	/* alias list */
	int	p_proto;	/* protocol # */
};

struct addrinfo {
	int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST */
	int	ai_family;	/* PF_xxx */
	int	ai_socktype;	/* SOCK_xxx */
	int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	socklen_t ai_addrlen;	/* length of ai_addr */
	char	*ai_canonname;	/* canonical name for hostname */
	struct	sockaddr *ai_addr;	/* binary address */
	struct	addrinfo *ai_next;	/* next structure in linked list */
};
#pragma clang diagnostic pop

/*
 * Error return codes from gethostbyname() and gethostbyaddr()
 * (left in h_errno).
 */

#define	NETDB_INTERNAL	-1	/* see errno */
#define	NETDB_SUCCESS	0	/* no problem */
#define	HOST_NOT_FOUND	1 /* Authoritative Answer Host not found */
#define	TRY_AGAIN	2 /* Non-Authoritative Host not found, or SERVERFAIL */
#define	NO_RECOVERY	3 /* Non recoverable errors, FORMERR, REFUSED, NOTIMP */
#define	NO_DATA		4 /* Valid name, no data record of requested type */
#define	NO_ADDRESS	NO_DATA		/* no address, look for MX record */

/*
 * Error return codes from getaddrinfo()
 */
#define	EAI_ADDRFAMILY	 1	/* address family for hostname not supported */
#define	EAI_AGAIN	 2	/* temporary failure in name resolution */
#define	EAI_BADFLAGS	 3	/* invalid value for ai_flags */
#define	EAI_FAIL	 4	/* non-recoverable failure in name resolution */
#define	EAI_FAMILY	 5	/* ai_family not supported */
#define	EAI_MEMORY	 6	/* memory allocation failure */
#define	EAI_NODATA	 7	/* no address associated with hostname */
#define	EAI_NONAME	 8	/* hostname nor servname provided, or not known */
#define	EAI_SERVICE	 9	/* servname not supported for ai_socktype */
#define	EAI_SOCKTYPE	10	/* ai_socktype not supported */
#define	EAI_SYSTEM	11	/* system error returned in errno */
#define	EAI_BADHINTS	12	/* invalid value for hints */
#define	EAI_PROTOCOL	13	/* resolved protocol is unknown */
#define	EAI_OVERFLOW	14	/* argument buffer overflow */
#define	EAI_MAX		15

/*
 * Flag values for getaddrinfo()
 */
#define	AI_PASSIVE	0x00000001 /* get address to use bind() */
#define	AI_CANONNAME	0x00000002 /* fill ai_canonname */
#define	AI_NUMERICHOST	0x00000004 /* prevent host name resolution */
#define	AI_NUMERICSERV	0x00000008 /* prevent service name resolution */
/* valid flags for addrinfo (not a standard def, apps should not use it) */
#define AI_MASK \
    (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | \
    AI_ADDRCONFIG)

#define	AI_ALL		0x00000100 /* IPv6 and IPv4-mapped (with AI_V4MAPPED) */
#define	AI_V4MAPPED_CFG	0x00000200 /* accept IPv4-mapped if kernel supports */
#define	AI_ADDRCONFIG	0x00000400 /* only if any address is assigned */
#define	AI_V4MAPPED	0x00000800 /* accept IPv4-mapped IPv6 address */
/* special recommended flags for getipnodebyname */
#define	AI_DEFAULT	(AI_V4MAPPED_CFG | AI_ADDRCONFIG)

/*
 * Constants for getnameinfo()
 */
#define	NI_MAXHOST	1025
#define	NI_MAXSERV	32

/*
 * Flag values for getnameinfo()
 */
#define	NI_NOFQDN	0x00000001
#define	NI_NUMERICHOST	0x00000002
#define	NI_NAMEREQD	0x00000004
#define	NI_NUMERICSERV	0x00000008
#define	NI_DGRAM	0x00000010
#if 0 /* obsolete */
#define NI_WITHSCOPEID	0x00000020
#endif

/*
 * Scope delimit character
 */
#define	SCOPE_DELIMITER	'%'

#define IPPORT_RESERVED 1024

__BEGIN_DECLS

int getaddrinfo(const char* _Nullable __node, const char* _Nullable __service, const struct addrinfo* _Nullable __hints, struct addrinfo* _Nullable * _Nonnull __result);
void freeaddrinfo(struct addrinfo* _Nullable __ptr);

/* Android ABI error: POSIX getnameinfo(3) uses socklen_t rather than size_t. */
int getnameinfo(const struct sockaddr* _Nonnull __sa, socklen_t __sa_length, char* _Nullable __host, size_t __host_length, char* _Nullable __service, size_t __service_length, int __flags);
const char* _Nonnull gai_strerror(int __error);

/* These functions are obsolete. Use getaddrinfo/getnameinfo instead. */
#define h_errno (*__get_h_errno())
int* _Nonnull __get_h_errno(void);
void herror(const char* _Nonnull __s);
const char* _Nonnull hstrerror(int __error);
struct hostent* _Nullable gethostbyaddr(const void* _Nonnull __addr, socklen_t __length, int __type);

#if __BIONIC_AVAILABILITY_GUARD(23)
int gethostbyaddr_r(const void* _Nonnull __addr, socklen_t __length, int __type, struct hostent* _Nonnull __ret, char* _Nonnull __buf, size_t __buf_size, struct hostent* _Nullable * _Nonnull __result, int* _Nonnull __h_errno_ptr) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */

struct hostent* _Nullable gethostbyname(const char* _Nonnull __name);
int gethostbyname_r(const char* _Nonnull __name, struct hostent* _Nonnull __ret, char* _Nonnull __buf, size_t __buf_size, struct hostent* _Nullable * _Nonnull __result, int* _Nonnull __h_errno_ptr);
struct hostent* _Nullable gethostbyname2(const char* _Nonnull __name, int __af);

#if __BIONIC_AVAILABILITY_GUARD(23)
int gethostbyname2_r(const char* _Nonnull __name, int __af, struct hostent* _Nonnull __ret, char* _Nonnull __buf, size_t __buf_size, struct hostent* _Nullable * _Nonnull __result, int* _Nonnull __h_errno_ptr) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(28)
void endhostent(void) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

struct hostent* _Nullable gethostent(void);

#if __BIONIC_AVAILABILITY_GUARD(28)
void sethostent(int __stay_open) __INTRODUCED_IN(28);

/* These functions are obsolete. None of these functions return anything but nullptr. */
void endnetent(void) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

struct netent* _Nullable getnetbyaddr(uint32_t __net, int __type);
struct netent* _Nullable getnetbyname(const char* _Nonnull __name);

#if __BIONIC_AVAILABILITY_GUARD(28)
struct netent* _Nullable getnetent(void) __INTRODUCED_IN(28);
void setnetent(int __stay_open) __INTRODUCED_IN(28);

/* None of these functions return anything but nullptr. */
void endprotoent(void) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

struct protoent* _Nullable getprotobyname(const char* _Nonnull __name);
struct protoent* _Nullable getprotobynumber(int __proto);

#if __BIONIC_AVAILABILITY_GUARD(28)
struct protoent* _Nullable getprotoent(void) __INTRODUCED_IN(28);
void setprotoent(int __stay_open) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


/* These functions return entries from a built-in database. */
void endservent(void);
struct servent* _Nullable getservbyname(const char* _Nonnull __name, const char* _Nullable __proto);
struct servent* _Nullable getservbyport(int __port_in_network_order, const char* _Nullable __proto);
struct servent* _Nullable getservent(void);
void setservent(int __stay_open);

__END_DECLS

#endif
```