Response:
Let's break down the thought process for answering the request about `bionic/libc/include/arpa/nameser.h`.

**1. Understanding the Core Request:**

The fundamental goal is to analyze the provided C header file (`nameser.h`) and explain its purpose, functions, relationship to Android, and debugging. The key here is to recognize this is a *header file*, meaning it *declares* interfaces, constants, and data structures related to DNS (Domain Name System), but doesn't *implement* the actual logic.

**2. Initial Analysis of the Header File:**

* **Copyright Notices:**  Recognize the multiple copyright holders (ISC, Regents of the University of California). This immediately suggests the code originates from a well-established project (BIND).
* **`#ifndef _ARPA_NAMESER_H_`:** This is a standard header guard, preventing multiple inclusions.
* **Includes:**  `sys/cdefs.h` and `sys/types.h` are standard C library headers.
* **`__NAMESER` Macro:**  This is a versioning mechanism. Note the comment about not comparing for equality, but using it for greater-than checks.
* **Constant Definitions (`#define`):**  A significant portion of the file consists of constants. Start grouping them logically:
    * Packet sizes, name lengths (`NS_PACKETSZ`, `NS_MAXDNAME`, etc.)
    * Header and record sizes (`NS_HFIXEDSZ`, `NS_QFIXEDSZ`, etc.)
    * Address sizes (`NS_INADDRSZ`, `NS_IN6ADDRSZ`)
    * Compression flags (`NS_CMPRSFLGS`)
    * Default port (`NS_DEFAULTPORT`)
* **`typedef enum`:**  These define enumerated types. Identify the key categories:
    * `ns_sect`: Sections of a DNS message (Question, Answer, Authority, Additional).
    * `ns_flag`:  Flags within the DNS header (QR, Opcode, AA, etc.).
    * `ns_opcode`:  Types of DNS queries (Query, IQuery, Update, etc.).
    * `ns_rcode`:  DNS response codes (NoError, FormErr, ServFail, etc.).
    * `ns_update_operation`: Actions for DNS updates (Delete, Add).
    * `ns_type`:  DNS record types (A, NS, CNAME, MX, etc.).
    * `ns_class`:  DNS classes (IN, CH, HS, etc.).
    * DNSSEC related types (`ns_key_types`, `ns_cert_types`).
* **`typedef struct`:** These define data structures:
    * `ns_msg`: Represents a DNS message. Note the leading underscores, indicating internal members. The comment emphasizes using accessor macros.
    * `ns_newmsg`: Used for constructing new DNS messages.
    * `ns_rr`: Represents a DNS resource record.
    * `ns_rr2`:  Similar to `ns_rr`, but using uncompressed names and standard C types.
    * `ns_tsig_key`:  For TSIG (Transaction Signatures).
    * `ns_tcp_tsig_state`:  For TSIG with TCP.
* **Accessor Macros (`#define ns_msg_id(...)`, etc.):**  These provide a controlled way to access members of the `ns_msg` and `ns_rr` structures.
* **Inline Functions/Macros (`#define NS_GET16(...)`, etc.):**  These are efficient ways to read and write short and long integers from/to byte streams, used in parsing DNS messages.
* **Function Declarations:** The `__BEGIN_DECLS` and `__END_DECLS` and the `__INTRODUCED_IN(22)` annotations strongly suggest this header is part of the Android Bionic library. The declarations without implementations confirm this is a header file. The `__ns_*` prefix also points to Bionic's internal naming conventions.
* **`BIND_4_COMPAT`:**  This suggests compatibility with older BIND versions.

**3. Mapping to the Request's Questions:**

* **功能 (Functionality):**  The primary function is to define the structures and constants necessary for working with DNS messages. It's about *representing* DNS data, not *processing* it.
* **与 Android 的关系 (Relationship with Android):**  The `bionic/libc` path is a direct indication. DNS resolution is crucial for network connectivity on Android. Give examples like resolving URLs in apps.
* **libc 函数的实现 (Implementation of libc functions):** This header *declares* functions. The *implementation* would be in `.c` files within the Bionic library. Mention this distinction. Briefly describe what each declared function likely does (parsing, printing, name manipulation).
* **dynamic linker 的功能 (Dynamic linker functionality):**  This header itself *doesn't* directly involve the dynamic linker. However, the *functions declared here* will be implemented in shared libraries (`.so` files). Explain the role of the dynamic linker in loading these libraries. Provide a basic `.so` layout example. Describe the linking process at a high level.
* **逻辑推理 (Logical reasoning):**  For macros like `NS_GET16`, illustrate with a simple byte array example.
* **用户/编程常见的使用错误 (Common user/programming errors):** Focus on mistakes when *using* the defined structures and functions. Examples include buffer overflows, incorrect sizes, wrong assumptions about data formats.
* **Android framework or ndk 如何到达这里 (How Android framework/NDK reaches here):** Trace a likely path:  High-level Android framework (Java), to native code (NDK), to libc functions (like `getaddrinfo`), which internally use the structures and constants defined in this header.
* **Frida hook 示例 (Frida hook example):** Choose a key function declared in the header (e.g., `ns_name_ntop`) and provide a basic Frida script to intercept it, log arguments, and potentially modify the return value.

**4. Structuring the Answer:**

Organize the answer according to the request's points. Use clear headings and bullet points for readability. Provide code examples where appropriate. Explain technical terms.

**5. Refinement and Accuracy:**

Review the answer for accuracy and completeness. Ensure the explanations are clear and concise. Double-check the function descriptions and their likely purpose. Pay attention to the distinction between declaration and implementation.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the implementation details of the functions.
* **Correction:** Realize the request is primarily about the *header file* and its *declarations*. Shift focus accordingly and emphasize that implementation details are in separate `.c` files.
* **Initial thought:** Overcomplicate the dynamic linker explanation.
* **Correction:** Keep the dynamic linker explanation high-level and focus on its role in loading the shared libraries where these functions are implemented. A simple `.so` layout is sufficient.
* **Initial thought:** Provide overly complex Frida hook examples.
* **Correction:**  Simplify the Frida example to demonstrate the basic interception concept. Focus on logging arguments and return values.

By following this structured thought process, including self-correction, you can generate a comprehensive and accurate answer that addresses all aspects of the original request.
好的，让我们来详细分析一下 `bionic/libc/include/arpa/nameser.h` 这个头文件。

**功能概述**

`nameser.h` 文件是 Android Bionic C 库中用于域名系统 (DNS) 操作的关键头文件。它定义了用于构建、解析和处理 DNS 消息的常量、数据结构和函数声明。简单来说，它提供了 C 语言层面操作 DNS 数据的接口。

其主要功能包括：

1. **定义 DNS 消息的结构：**  定义了 DNS 消息的各个组成部分，如头部、问题部分、答案部分、权威应答部分和附加信息部分。
2. **定义 DNS 记录的结构：** 定义了各种 DNS 资源记录（RR）的结构，例如 A 记录（地址记录）、CNAME 记录（别名记录）、MX 记录（邮件交换记录）等。
3. **定义 DNS 消息头部的标志位：** 定义了 DNS 消息头部中用于指示消息类型、查询/应答、权威应答等信息的标志位。
4. **定义 DNS 查询类型和类：** 定义了各种 DNS 查询类型（例如，查询 A 记录、查询 MX 记录）和 DNS 类（例如，Internet 类）。
5. **提供用于打包和解包 DNS 消息的工具：**  声明了用于将 DNS 数据打包成网络字节流以及从网络字节流中解包 DNS 数据的函数。
6. **提供用于打印 DNS 记录的函数：** 声明了用于将 DNS 记录以人类可读的格式打印出来的函数。

**与 Android 功能的关系及举例说明**

`nameser.h` 与 Android 的网络功能紧密相关。当 Android 设备需要解析域名时，例如访问一个网站或者连接到一个服务器，操作系统会使用 DNS 协议来将域名转换为 IP 地址。

**举例说明：**

* **网络请求:** 当一个 Android 应用发起一个网络请求，例如使用 `HttpURLConnection` 或 `OkHttp` 访问 `www.google.com` 时，Android 系统底层的网络库会使用 DNS 解析来获取 `www.google.com` 的 IP 地址。这个过程会涉及到使用 `nameser.h` 中定义的结构和函数来构建和解析 DNS 查询和响应。
* **域名解析服务:** Android 系统提供域名解析服务，例如 `getaddrinfo` 函数，它允许应用程序通过域名获取一个或多个 IP 地址。`getaddrinfo` 的底层实现会使用 `nameser.h` 中定义的结构来处理 DNS 消息。
* **VPN 和 DNS 服务器配置:**  Android 系统允许用户配置自定义的 DNS 服务器。系统在处理这些配置时，可能会使用到 `nameser.h` 中定义的常量和结构来表示 DNS 服务器的地址和类型。

**libc 函数的功能及其实现**

`nameser.h` 文件本身是一个头文件，它只包含了 **声明**，并没有包含函数的具体 **实现**。这些函数的实现位于 Bionic C 库的其他源文件中，编译后链接到 `libc.so` 中。

以下是 `nameser.h` 中声明的一些关键函数的解释：

* **`ns_initparse(const u_char *msg, int msg_size, ns_msg *handle)`:**
    * **功能：** 初始化一个 `ns_msg` 结构体，用于解析 DNS 消息。
    * **实现：**  该函数接收一个 DNS 消息的字节流 (`msg`) 和消息大小 (`msg_size`)，并将消息的各个部分（头部、各个段）的指针和计数存储到 `ns_msg` 结构体中。它主要是设置解析状态，以便后续的解析函数可以访问消息的不同部分。
* **`ns_skiprr(const u_char *ptr, const u_char *eom, ns_sect section, int count)`:**
    * **功能：** 跳过 DNS 消息的指定段中的指定数量的资源记录。
    * **实现：**  该函数从给定的指针 (`ptr`) 开始，根据资源记录的格式（名称长度、类型、类、TTL、数据长度等）计算每个记录的长度，并跳过指定段 (`section`) 中的 `count` 个记录。`eom` 指向消息的末尾，用于防止越界。
* **`ns_parserr(ns_msg *handle, ns_sect section, int rr_number, ns_rr *rr)`:**
    * **功能：** 解析 DNS 消息的指定段中的特定资源记录。
    * **实现：**  该函数使用 `ns_initparse` 初始化后的 `ns_msg` 句柄 (`handle`)，定位到指定段 (`section`) 的第 `rr_number` 个资源记录，然后解析记录的各个字段（名称、类型、类、TTL、数据长度、数据），并将解析结果存储到 `ns_rr` 结构体中。涉及到域名压缩解压缩等操作。
* **`ns_sprintrr(const ns_msg *handle, const ns_rr *rr, const char *name_ctx, const char *origin, char *buf, size_t buf_size)`:**
    * **功能：** 将一个 DNS 资源记录以人类可读的格式打印到缓冲区中。
    * **实现：**  该函数接收一个 `ns_msg` 句柄和 `ns_rr` 结构体，以及可选的上下文信息 (`name_ctx`, `origin`)，并将 `ns_rr` 中的数据格式化成字符串，存储到提供的缓冲区 (`buf`) 中，最大长度为 `buf_size`。
* **`ns_format_ttl(u_long ttl, char *dst, size_t dst_size)`:**
    * **功能：** 将 TTL (Time To Live) 值格式化成易于理解的字符串（例如 "1d" 表示 1 天）。
    * **实现：** 该函数接收一个 TTL 的秒数值 (`ttl`)，将其转换为天、小时、分钟和秒，并格式化成字符串存储到 `dst` 缓冲区中。
* **`ns_name_ntol(const u_char *src, u_char *dst, size_t dst_size)`:**
    * **功能：** 将 DNS 域名从网络格式（带长度前缀的标签）转换为本地格式（点分隔的字符串）。
    * **实现：** 该函数读取 `src` 指向的域名，根据每个标签的长度前缀提取标签，并将它们用点连接起来，存储到 `dst` 缓冲区中。
* **`ns_name_ntop(const u_char *src, char *dst, size_t dst_size)`:**
    * **功能：**  与 `ns_name_ntol` 功能相同，都是将网络格式的域名转换为点分隔的字符串。这是历史遗留的两个功能相似的函数。
* **`ns_name_pton(const char *src, u_char *dst, size_t dst_size)`:**
    * **功能：** 将点分隔的域名字符串转换为网络格式。
    * **实现：** 该函数解析 `src` 指向的域名字符串，将其分割成标签，并在每个标签前加上长度前缀，然后存储到 `dst` 缓冲区中。
* **`ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src, u_char *dst, size_t dst_size)`:**
    * **功能：** 从 DNS 消息中解压缩域名。
    * **实现：**  该函数处理域名压缩的情况。如果域名被压缩（通过指针指向消息中之前出现过的域名），则它会根据指针找到原始域名并复制到 `dst`。否则，它会直接复制未压缩的域名。
* **`ns_name_pack(const u_char *src, u_char *dst, int dst_size, const u_char * const *dn_ptrs, const u_char * const *last_dn_ptr)`:**
    * **功能：** 将域名压缩并打包到 DNS 消息中。
    * **实现：** 该函数尝试在 `dn_ptrs` 数组中查找与 `src` 指向的域名相同的域名，如果找到，则将压缩指针写入 `dst`。否则，将未压缩的域名写入 `dst`，并更新 `dn_ptrs` 数组以供后续压缩使用。
* **`ns_name_uncompress(const u_char *msg, const u_char *eom, const u_char *src, char *dst, size_t dst_size)`:**
    * **功能：**  与 `ns_name_unpack` 功能类似，但结果存储到 `char*` 类型的缓冲区。
* **`ns_name_compress(const char *src, u_char *dst, size_t dst_size, const u_char * const *dn_ptrs, const u_char * const *last_dn_ptr)`:**
    * **功能：** 与 `ns_name_pack` 功能类似，但输入是点分隔的字符串。
* **`ns_name_skip(const u_char **ptr_ptr, const u_char *eom)`:**
    * **功能：** 跳过 DNS 消息中的一个域名（无论是压缩的还是未压缩的）。
    * **实现：** 该函数读取域名开头的长度字节，如果表示压缩，则跳过 2 个字节的指针；否则，跳过整个域名。
* **`ns_makecanon(const char *src, char *dst, size_t dst_size)`:**
    * **功能：** 将域名转换为规范格式（所有字母小写）。
    * **实现：** 该函数将 `src` 指向的域名字符串转换为小写并存储到 `dst` 缓冲区。
* **`ns_samename(const char *lhs, const char *rhs)`:**
    * **功能：** 比较两个域名是否相同（忽略大小写）。
    * **实现：** 该函数将两个域名都转换为小写，然后逐字符比较它们是否相等。

**涉及 dynamic linker 的功能、so 布局样本和链接处理过程**

`nameser.h` 本身并不直接涉及 dynamic linker 的功能。但是，其中声明的函数最终会被编译到 `libc.so` 这个共享库中。Dynamic linker (在 Android 上通常是 `linker64` 或 `linker`) 负责在程序运行时加载和链接这些共享库。

**so 布局样本 (`libc.so`)：**

```
libc.so:
    .text         # 代码段，包含 ns_initparse, ns_parserr 等函数的机器码
    .rodata       # 只读数据段，包含常量字符串等
    .data         # 可读写数据段，包含全局变量
    .bss          # 未初始化数据段
    .dynsym       # 动态符号表，列出导出的符号（函数和变量）
    .dynstr       # 动态字符串表，存储符号名称
    .plt          # 程序链接表，用于延迟绑定
    .got          # 全局偏移表，用于访问全局数据
    ...
```

**链接的处理过程：**

1. **编译时链接：** 当你使用 NDK 编译包含 `nameser.h` 中声明的函数的代码时，编译器会记录下对这些函数的引用，但不会将其具体代码链接进来。
2. **运行时加载：** 当 Android 系统启动你的应用程序时，dynamic linker 会被调用。
3. **查找依赖：** Dynamic linker 会读取应用程序的可执行文件头，找到其依赖的共享库，包括 `libc.so`。
4. **加载共享库：** Dynamic linker 将 `libc.so` 加载到内存中的某个地址空间。
5. **符号解析（链接）：**
   * 当程序执行到调用 `nameser.h` 中声明的函数时，例如 `ns_parserr`，程序会先查找全局偏移表 (GOT)。
   * GOT 中对应 `ns_parserr` 的条目最初可能包含一个指向 PLT (程序链接表) 中一段代码的地址。
   * PLT 中的代码会调用 dynamic linker 的解析函数。
   * Dynamic linker 会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `ns_parserr` 的地址。
   * 找到地址后，dynamic linker 会更新 GOT 中 `ns_parserr` 的条目，使其直接指向 `libc.so` 中 `ns_parserr` 函数的实际地址。
   * 下次调用 `ns_parserr` 时，程序就可以直接通过 GOT 跳转到函数的实际地址，而无需再次调用 dynamic linker。这被称为 **延迟绑定** 或 **懒加载**。

**假设输入与输出 (逻辑推理)**

以 `ns_name_pton` 函数为例：

**假设输入：**

* `src`: 指向字符串 "www.example.com" 的指针
* `dst`: 指向一个足够大的 `u_char` 数组的指针
* `dst_size`: 数组的大小，例如 256

**输出：**

* `dst` 指向的数组将包含以下字节序列（十六进制表示）：`03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00`
    * `03`:  标签 "www" 的长度
    * `77 77 77`: 字符 'w', 'w', 'w' 的 ASCII 码
    * `07`:  标签 "example" 的长度
    * `65 78 61 6d 70 6c 65`: 字符 'e', 'x', 'a', 'm', 'p', 'l', 'e' 的 ASCII 码
    * `03`:  标签 "com" 的长度
    * `63 6f 6d`: 字符 'c', 'o', 'm' 的 ASCII 码
    * `00`:  域名结束符

**用户或编程常见的使用错误**

1. **缓冲区溢出：**  在使用像 `ns_name_ntop` 或 `ns_sprintrr` 这样的函数时，如果提供的缓冲区 `buf` 的大小 `buf_size` 不足以容纳结果字符串，可能会导致缓冲区溢出，覆盖其他内存区域，导致程序崩溃或安全漏洞。
   ```c
   char buf[10];
   const u_char name[] = { 0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00 };
   ns_name_ntop(name, buf, sizeof(buf)); // 错误：buf 太小
   ```

2. **错误的缓冲区大小：**  传递给 `sizeof()` 的参数错误，导致计算出的缓冲区大小不正确。
   ```c
   char buf[100];
   ns_name_ntop(name, buf, 10); // 错误：传递了错误的缓冲区大小
   ```

3. **未初始化 `ns_msg` 结构体：**  在使用 `ns_parserr` 等函数之前，忘记使用 `ns_initparse` 初始化 `ns_msg` 结构体。
   ```c
   ns_msg msg;
   // 缺少 ns_initparse 调用
   ns_rr rr;
   ns_parserr(&msg, ns_s_an, 0, &rr); // 错误：msg 未初始化
   ```

4. **对网络字节序的误解：**  DNS 协议中很多数据（如类型、类、长度）使用网络字节序（大端序）。直接使用本地字节序的数据可能会导致解析错误。`nameser.h` 中提供的 `NS_GET16` 和 `NS_PUT16` 等宏可以帮助处理字节序转换。

**Android framework or ndk 如何一步步的到达这里**

以下是一个简化的调用链示例，展示了 Android Framework 如何最终使用到 `nameser.h` 中定义的结构和函数：

1. **Android Framework (Java):** 应用程序发起一个网络请求，例如使用 `java.net.URL` 或 `android.net.http.HttpURLConnection`。
   ```java
   URL url = new URL("http://www.example.com");
   HttpURLConnection con = (HttpURLConnection) url.openConnection();
   ```

2. **Framework 网络库 (Java/Native):** Framework 的网络库会将域名解析的任务委托给底层的 native 代码。例如，`InetAddress.getAllByName()` 方法最终会调用 native 方法。

3. **NDK (Native 代码):**  Framework 的 native 代码会调用 Bionic C 库提供的网络相关函数，例如 `getaddrinfo()`。

4. **Bionic C 库 (`libc.so`):** `getaddrinfo()` 函数是用于获取与主机名和服务名关联的地址信息的标准 C 库函数。它的实现内部会进行 DNS 查询。

5. **DNS 查询构建和解析:** `getaddrinfo()` 的实现会使用 `nameser.h` 中定义的结构体（如 `ns_msg`，`ns_rr`）和函数（如 `ns_initparse`，`ns_parserr`，`ns_name_pton`，`ns_name_ntop`）来构建 DNS 查询报文，发送到 DNS 服务器，并解析 DNS 服务器返回的响应报文。

**Frida Hook 示例调试步骤**

假设我们想 hook `ns_name_ntop` 函数，查看域名从网络格式转换成字符串的过程。

**Frida Hook 脚本 (Python):**

```python
import frida
import sys

package_name = "你的应用包名" # 替换成你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[{message['payload']['function']}]")
        for arg in message['payload']['args']:
            print(f"  arg: {arg}")
        print(f"  ret: {message['payload']['ret']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到应用: {package_name}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__ns_name_ntop"), {
    onEnter: function(args) {
        this.src = args[0];
        this.dst = args[1];
        this.size = args[2];
        console.log("[ns_name_ntop]");
        console.log("  src:", Memory.readByteArray(this.src, 30)); // 读取 30 字节的网络格式域名
        console.log("  size:", this.size);
    },
    onLeave: function(retval) {
        if (retval > 0) {
            console.log("  dst:", Memory.readUtf8String(this.dst)); // 读取转换后的字符串
        }
        send({
            function: "ns_name_ntop",
            args: [
                Memory.readByteArray(this.src, 30),
                this.size.toString()
            ],
            ret: retval.toString()
        });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤：**

1. **安装 Frida 和 Frida-server:** 确保你的 Android 设备上安装了 Frida-server，你的电脑上安装了 Frida。
2. **找到目标应用的包名:**  例如，你要调试浏览器应用，需要找到其包名。
3. **运行 Frida Hook 脚本:**  将上面的 Python 脚本保存为 `hook_dns.py`，并将 `package_name` 替换为你的目标应用的包名，然后在终端运行 `frida -UF -l hook_dns.py`。或者，如果你的设备通过 USB 连接，可以运行 `frida -U -f 你的应用包名 -l hook_dns.py --no-pause` 来启动并附加到应用。
4. **在应用中触发 DNS 解析:**  在你的目标应用中执行一些会触发 DNS 解析的操作，例如在浏览器中访问一个网站。
5. **查看 Frida 输出:**  Frida 会拦截 `ns_name_ntop` 函数的调用，并在终端输出函数的参数（网络格式的域名和缓冲区大小）以及返回值（通常是转换后的字符串）。你可以看到域名是如何从网络格式转换成可读的字符串的。

这个 Frida 示例只是一个简单的演示，你可以根据需要 hook 其他函数，查看和修改参数、返回值，从而更深入地理解 DNS 解析的过程。

希望以上详细的解释能够帮助你理解 `bionic/libc/include/arpa/nameser.h` 的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/include/arpa/nameser.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$NetBSD: nameser.h,v 1.25 2009/04/12 17:07:34 christos Exp $	*/

/*
 * Portions Copyright (C) 2004, 2005, 2008, 2009  Internet Systems Consortium, Inc. ("ISC")
 * Portions Copyright (C) 1996-2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copyright (c) 1983, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 */

/*
 *	Id: nameser.h,v 1.16 2009/03/03 01:52:48 each Exp
 */

#ifndef _ARPA_NAMESER_H_
#define _ARPA_NAMESER_H_

#define BIND_4_COMPAT

#include <sys/cdefs.h>

#include <sys/types.h>

/*
 * Revision information.  This is the release date in YYYYMMDD format.
 * It can change every day so the right thing to do with it is use it
 * in preprocessor commands such as "#if (__NAMESER > 19931104)".  Do not
 * compare for equality; rather, use it to determine whether your libbind.a
 * contains a new enough lib/nameser/ to support the feature you need.
 */

#define __NAMESER	20090302	/*%< New interface version stamp. */

/*
 * Define constants based on RFC0883, RFC1034, RFC 1035
 */
#define NS_PACKETSZ	512	/* default UDP packet size */
#define NS_MAXDNAME	1025	/* maximum domain name (presentation format)*/
#define NS_MAXMSG	65535	/* maximum message size */
#define NS_MAXCDNAME	255	/* maximum compressed domain name */
#define NS_MAXLABEL	63	/* maximum length of domain label */
#define NS_MAXLABELS	128	/* theoretical max #/labels per domain name */
#define NS_MAXNNAME	256	/* maximum uncompressed (binary) domain name*/
#define	NS_MAXPADDR	(sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
#define NS_HFIXEDSZ	12	/* #/bytes of fixed data in header */
#define NS_QFIXEDSZ	4	/* #/bytes of fixed data in query */
#define NS_RRFIXEDSZ	10	/* #/bytes of fixed data in r record */
#define NS_INT32SZ	4	/* #/bytes of data in a uint32_t */
#define NS_INT16SZ	2	/* #/bytes of data in a uint16_t */
#define NS_INT8SZ	1	/* #/bytes of data in a uint8_t */
#define NS_INADDRSZ	4	/* IPv4 T_A */
#define NS_IN6ADDRSZ	16	/* IPv6 T_AAAA */
#define NS_CMPRSFLGS	0xc0	/* Flag bits indicating name compression. */
#define NS_DEFAULTPORT	53	/* For both TCP and UDP. */

/*
 * These can be expanded with synonyms, just keep ns_parse.c:ns_parserecord()
 * in synch with it.
 */
typedef enum __ns_sect {
	ns_s_qd = 0,		/* Query: Question. */
	ns_s_zn = 0,		/* Update: Zone. */
	ns_s_an = 1,		/* Query: Answer. */
	ns_s_pr = 1,		/* Update: Prerequisites. */
	ns_s_ns = 2,		/* Query: Name servers. */
	ns_s_ud = 2,		/* Update: Update. */
	ns_s_ar = 3,		/* Query|Update: Additional records. */
	ns_s_max = 4
} ns_sect;

/*
 * Network name (compressed or not) type.  Equivilent to a pointer when used
 * in a function prototype.  Can be const'd.
 */
typedef u_char ns_nname[NS_MAXNNAME];
typedef const u_char *ns_nname_ct;
typedef u_char *ns_nname_t;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
struct ns_namemap { ns_nname_ct base; int len; };
typedef struct ns_namemap *ns_namemap_t;
typedef const struct ns_namemap *ns_namemap_ct;

/*
 * This is a message handle.  It is caller allocated and has no dynamic data.
 * This structure is intended to be opaque to all but ns_parse.c, thus the
 * leading _'s on the member names.  Use the accessor functions, not the _'s.
 */
typedef struct __ns_msg {
	const u_char	*_msg, *_eom;
	uint16_t	_id, _flags, _counts[ns_s_max];
	const u_char	*_sections[ns_s_max];
	ns_sect		_sect;
	int		_rrnum;
	const u_char	*_msg_ptr;
} ns_msg;
/*
 * This is a newmsg handle, used when constructing new messages with
 * ns_newmsg_init, et al.
 */
struct ns_newmsg {
	ns_msg		msg;
	const u_char	*dnptrs[25];
	const u_char	**lastdnptr;
};
typedef struct ns_newmsg ns_newmsg;

/* Accessor macros - this is part of the public interface. */

#define ns_msg_id(handle) ((handle)._id + 0)
#define ns_msg_base(handle) ((handle)._msg + 0)
#define ns_msg_end(handle) ((handle)._eom + 0)
#define ns_msg_size(handle) ((size_t)((handle)._eom - (handle)._msg))
#define ns_msg_count(handle, section) ((handle)._counts[section] + 0)

/*
 * This is a parsed record.  It is caller allocated and has no dynamic data.
 */
typedef	struct __ns_rr {
	char		name[NS_MAXDNAME];
	uint16_t	type;
	uint16_t	rr_class;
	uint32_t	ttl;
	uint16_t	rdlength;
	const u_char *	rdata;
} ns_rr;

/*
 * Same thing, but using uncompressed network binary names, and real C types.
 */
typedef	struct __ns_rr2 {
	ns_nname	nname;
	size_t		nnamel;
	int		type;
	int		rr_class;
	u_int		ttl;
	int		rdlength;
	const u_char *	rdata;
} ns_rr2;
/* Accessor macros - this is part of the public interface. */
#define ns_rr_name(rr)	(((rr).name[0] != '\0') ? (rr).name : ".")
#define ns_rr_nname(rr)	((const ns_nname_t)(rr).nname)
#define ns_rr_nnamel(rr) ((rr).nnamel + 0)
#define ns_rr_type(rr)	((ns_type)((rr).type + 0))
#define ns_rr_class(rr)	((ns_class)((rr).rr_class + 0))
#define ns_rr_ttl(rr)	((u_long)(rr).ttl + 0)
#define ns_rr_rdlen(rr)	((size_t)(rr).rdlength + 0)
#define ns_rr_rdata(rr)	((rr).rdata + 0)

/*
 * These don't have to be in the same order as in the packet flags word,
 * and they can even overlap in some cases, but they will need to be kept
 * in synch with ns_parse.c:ns_flagdata[].
 */
typedef enum __ns_flag {
	ns_f_qr,		/* Question/Response. */
	ns_f_opcode,		/* Operation code. */
	ns_f_aa,		/* Authoritative Answer. */
	ns_f_tc,		/* Truncation occurred. */
	ns_f_rd,		/* Recursion Desired. */
	ns_f_ra,		/* Recursion Available. */
	ns_f_z,			/* MBZ. */
	ns_f_ad,		/* Authentic Data (DNSSEC). */
	ns_f_cd,		/* Checking Disabled (DNSSEC). */
	ns_f_rcode,		/* Response code. */
	ns_f_max
} ns_flag;

/*
 * Currently defined opcodes.
 */
typedef enum __ns_opcode {
	ns_o_query = 0,		/* Standard query. */
	ns_o_iquery = 1,	/* Inverse query (deprecated/unsupported). */
	ns_o_status = 2,	/* Name server status query (unsupported). */
				/* Opcode 3 is undefined/reserved. */
	ns_o_notify = 4,	/* Zone change notification. */
	ns_o_update = 5,	/* Zone update message. */
	ns_o_max = 6
} ns_opcode;

/*
 * Currently defined response codes.
 */
typedef	enum __ns_rcode {
	ns_r_noerror = 0,	/* No error occurred. */
	ns_r_formerr = 1,	/* Format error. */
	ns_r_servfail = 2,	/* Server failure. */
	ns_r_nxdomain = 3,	/* Name error. */
	ns_r_notimpl = 4,	/* Unimplemented. */
	ns_r_refused = 5,	/* Operation refused. */
	/* these are for BIND_UPDATE */
	ns_r_yxdomain = 6,	/* Name exists */
	ns_r_yxrrset = 7,	/* RRset exists */
	ns_r_nxrrset = 8,	/* RRset does not exist */
	ns_r_notauth = 9,	/* Not authoritative for zone */
	ns_r_notzone = 10,	/* Zone of record different from zone section */
	ns_r_max = 11,
	/* The following are EDNS extended rcodes */
	ns_r_badvers = 16,
	/* The following are TSIG errors */
	ns_r_badsig = 16,
	ns_r_badkey = 17,
	ns_r_badtime = 18
} ns_rcode;

/* BIND_UPDATE */
typedef enum __ns_update_operation {
	ns_uop_delete = 0,
	ns_uop_add = 1,
	ns_uop_max = 2
} ns_update_operation;

/*
 * This structure is used for TSIG authenticated messages
 */
struct ns_tsig_key {
        char name[NS_MAXDNAME], alg[NS_MAXDNAME];
        unsigned char *data;
        int len;
};
typedef struct ns_tsig_key ns_tsig_key;

/*
 * This structure is used for TSIG authenticated TCP messages
 */
struct ns_tcp_tsig_state {
	int counter;
	struct dst_key *key;
	void *ctx;
	unsigned char sig[NS_PACKETSZ];
	int siglen;
};
typedef struct ns_tcp_tsig_state ns_tcp_tsig_state;

#pragma clang diagnostic pop

#define NS_TSIG_FUDGE 300
#define NS_TSIG_TCP_COUNT 100
#define NS_TSIG_ALG_HMAC_MD5 "HMAC-MD5.SIG-ALG.REG.INT"

#define NS_TSIG_ERROR_NO_TSIG -10
#define NS_TSIG_ERROR_NO_SPACE -11
#define NS_TSIG_ERROR_FORMERR -12

/*
 * Currently defined type values for resources and queries.
 */
typedef enum __ns_type {
	ns_t_invalid = 0,	/* Cookie. */
	ns_t_a = 1,		/* Host address. */
	ns_t_ns = 2,		/* Authoritative server. */
	ns_t_md = 3,		/* Mail destination. */
	ns_t_mf = 4,		/* Mail forwarder. */
	ns_t_cname = 5,		/* Canonical name. */
	ns_t_soa = 6,		/* Start of authority zone. */
	ns_t_mb = 7,		/* Mailbox domain name. */
	ns_t_mg = 8,		/* Mail group member. */
	ns_t_mr = 9,		/* Mail rename name. */
	ns_t_null = 10,		/* Null resource record. */
	ns_t_wks = 11,		/* Well known service. */
	ns_t_ptr = 12,		/* Domain name pointer. */
	ns_t_hinfo = 13,	/* Host information. */
	ns_t_minfo = 14,	/* Mailbox information. */
	ns_t_mx = 15,		/* Mail routing information. */
	ns_t_txt = 16,		/* Text strings. */
	ns_t_rp = 17,		/* Responsible person. */
	ns_t_afsdb = 18,	/* AFS cell database. */
	ns_t_x25 = 19,		/* X_25 calling address. */
	ns_t_isdn = 20,		/* ISDN calling address. */
	ns_t_rt = 21,		/* Router. */
	ns_t_nsap = 22,		/* NSAP address. */
	ns_t_nsap_ptr = 23,	/* Reverse NSAP lookup (deprecated). */
	ns_t_sig = 24,		/* Security signature. */
	ns_t_key = 25,		/* Security key. */
	ns_t_px = 26,		/* X.400 mail mapping. */
	ns_t_gpos = 27,		/* Geographical position (withdrawn). */
	ns_t_aaaa = 28,		/* IPv6 Address. */
	ns_t_loc = 29,		/* Location Information. */
	ns_t_nxt = 30,		/* Next domain (security). */
	ns_t_eid = 31,		/* Endpoint identifier. */
	ns_t_nimloc = 32,	/* Nimrod Locator. */
	ns_t_srv = 33,		/* Server Selection. */
	ns_t_atma = 34,		/* ATM Address */
	ns_t_naptr = 35,	/* Naming Authority PoinTeR */
	ns_t_kx = 36,		/* Key Exchange */
	ns_t_cert = 37,		/* Certification record */
	ns_t_a6 = 38,		/* IPv6 address (experimental) */
	ns_t_dname = 39,	/* Non-terminal DNAME */
	ns_t_sink = 40,		/* Kitchen sink (experimentatl) */
	ns_t_opt = 41,		/* EDNS0 option (meta-RR) */
	ns_t_apl = 42,		/* Address prefix list (RFC 3123) */
	ns_t_ds = 43,		/* Delegation Signer */
	ns_t_sshfp = 44,	/* SSH Fingerprint */
	ns_t_ipseckey = 45,	/* IPSEC Key */
	ns_t_rrsig = 46,	/* RRset Signature */
	ns_t_nsec = 47,		/* Negative security */
	ns_t_dnskey = 48,	/* DNS Key */
	ns_t_dhcid = 49,	/* Dynamic host configuratin identifier */
	ns_t_nsec3 = 50,	/* Negative security type 3 */
	ns_t_nsec3param = 51,	/* Negative security type 3 parameters */
	ns_t_hip = 55,		/* Host Identity Protocol */
	ns_t_spf = 99,		/* Sender Policy Framework */
	ns_t_tkey = 249,	/* Transaction key */
	ns_t_tsig = 250,	/* Transaction signature. */
	ns_t_ixfr = 251,	/* Incremental zone transfer. */
	ns_t_axfr = 252,	/* Transfer zone of authority. */
	ns_t_mailb = 253,	/* Transfer mailbox records. */
	ns_t_maila = 254,	/* Transfer mail agent records. */
	ns_t_any = 255,		/* Wildcard match. */
	ns_t_zxfr = 256,	/* BIND-specific, nonstandard. */
	ns_t_dlv = 32769,	/* DNSSEC look-aside validatation. */
	ns_t_max = 65536
} ns_type;

/* Exclusively a QTYPE? (not also an RTYPE) */
#define	ns_t_qt_p(t) (ns_t_xfr_p(t) || (t) == ns_t_any || \
		      (t) == ns_t_mailb || (t) == ns_t_maila)
/* Some kind of meta-RR? (not a QTYPE, but also not an RTYPE) */
#define	ns_t_mrr_p(t) ((t) == ns_t_tsig || (t) == ns_t_opt)
/* Exclusively an RTYPE? (not also a QTYPE or a meta-RR) */
#define ns_t_rr_p(t) (!ns_t_qt_p(t) && !ns_t_mrr_p(t))
#define ns_t_udp_p(t) ((t) != ns_t_axfr && (t) != ns_t_zxfr)
#define ns_t_xfr_p(t) ((t) == ns_t_axfr || (t) == ns_t_ixfr || \
		       (t) == ns_t_zxfr)

/*
 * Values for class field
 */
typedef enum __ns_class {
	ns_c_invalid = 0,	/* Cookie. */
	ns_c_in = 1,		/* Internet. */
	ns_c_2 = 2,		/* unallocated/unsupported. */
	ns_c_chaos = 3,		/* MIT Chaos-net. */
	ns_c_hs = 4,		/* MIT Hesiod. */
	/* Query class values which do not appear in resource records */
	ns_c_none = 254,	/* for prereq. sections in update requests */
	ns_c_any = 255,		/* Wildcard match. */
	ns_c_max = 65536
} ns_class;

/* DNSSEC constants. */

typedef enum __ns_key_types {
	ns_kt_rsa = 1,		/* key type RSA/MD5 */
	ns_kt_dh  = 2,		/* Diffie Hellman */
	ns_kt_dsa = 3,		/* Digital Signature Standard (MANDATORY) */
	ns_kt_private = 254	/* Private key type starts with OID */
} ns_key_types;

typedef enum __ns_cert_types {
	cert_t_pkix = 1,	/* PKIX (X.509v3) */
	cert_t_spki = 2,	/* SPKI */
	cert_t_pgp  = 3,	/* PGP */
	cert_t_url  = 253,	/* URL private type */
	cert_t_oid  = 254	/* OID private type */
} ns_cert_types;

/* Flags field of the KEY RR rdata. */
#define	NS_KEY_TYPEMASK		0xC000	/* Mask for "type" bits */
#define	NS_KEY_TYPE_AUTH_CONF	0x0000	/* Key usable for both */
#define	NS_KEY_TYPE_CONF_ONLY	0x8000	/* Key usable for confidentiality */
#define	NS_KEY_TYPE_AUTH_ONLY	0x4000	/* Key usable for authentication */
#define	NS_KEY_TYPE_NO_KEY	0xC000	/* No key usable for either; no key */
/* The type bits can also be interpreted independently, as single bits: */
#define	NS_KEY_NO_AUTH		0x8000	/* Key unusable for authentication */
#define	NS_KEY_NO_CONF		0x4000	/* Key unusable for confidentiality */
#define	NS_KEY_RESERVED2	0x2000	/* Security is *mandatory* if bit=0 */
#define	NS_KEY_EXTENDED_FLAGS	0x1000	/* reserved - must be zero */
#define	NS_KEY_RESERVED4	0x0800  /* reserved - must be zero */
#define	NS_KEY_RESERVED5	0x0400  /* reserved - must be zero */
#define	NS_KEY_NAME_TYPE	0x0300	/* these bits determine the type */
#define	NS_KEY_NAME_USER	0x0000	/* key is assoc. with user */
#define	NS_KEY_NAME_ENTITY	0x0200	/* key is assoc. with entity eg host */
#define	NS_KEY_NAME_ZONE	0x0100	/* key is zone key */
#define	NS_KEY_NAME_RESERVED	0x0300	/* reserved meaning */
#define	NS_KEY_RESERVED8	0x0080  /* reserved - must be zero */
#define	NS_KEY_RESERVED9	0x0040  /* reserved - must be zero */
#define	NS_KEY_RESERVED10	0x0020  /* reserved - must be zero */
#define	NS_KEY_RESERVED11	0x0010  /* reserved - must be zero */
#define	NS_KEY_SIGNATORYMASK	0x000F	/* key can sign RR's of same name */
#define	NS_KEY_RESERVED_BITMASK ( NS_KEY_RESERVED2 | \
				  NS_KEY_RESERVED4 | \
				  NS_KEY_RESERVED5 | \
				  NS_KEY_RESERVED8 | \
				  NS_KEY_RESERVED9 | \
				  NS_KEY_RESERVED10 | \
				  NS_KEY_RESERVED11 )
#define NS_KEY_RESERVED_BITMASK2 0xFFFF /* no bits defined here */

/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
#define	NS_ALG_MD5RSA		1	/* MD5 with RSA */
#define	NS_ALG_DH               2	/* Diffie Hellman KEY */
#define	NS_ALG_DSA              3	/* DSA KEY */
#define	NS_ALG_DSS              NS_ALG_DSA
#define	NS_ALG_EXPIRE_ONLY	253	/* No alg, no security */
#define	NS_ALG_PRIVATE_OID	254	/* Key begins with OID giving alg */

/* Protocol values  */
/* value 0 is reserved */
#define NS_KEY_PROT_TLS         1
#define NS_KEY_PROT_EMAIL       2
#define NS_KEY_PROT_DNSSEC      3
#define NS_KEY_PROT_IPSEC       4
#define NS_KEY_PROT_ANY		255

/* Signatures */
#define	NS_MD5RSA_MIN_BITS	 512	/* Size of a mod or exp in bits */
#define	NS_MD5RSA_MAX_BITS	4096
	/* Total of binary mod and exp */
#define	NS_MD5RSA_MAX_BYTES	((NS_MD5RSA_MAX_BITS+7/8)*2+3)
	/* Max length of text sig block */
#define	NS_MD5RSA_MAX_BASE64	(((NS_MD5RSA_MAX_BYTES+2)/3)*4)
#define NS_MD5RSA_MIN_SIZE	((NS_MD5RSA_MIN_BITS+7)/8)
#define NS_MD5RSA_MAX_SIZE	((NS_MD5RSA_MAX_BITS+7)/8)

#define NS_DSA_SIG_SIZE         41
#define NS_DSA_MIN_SIZE         213
#define NS_DSA_MAX_BYTES        405

/* Offsets into SIG record rdata to find various values */
#define	NS_SIG_TYPE	0	/* Type flags */
#define	NS_SIG_ALG	2	/* Algorithm */
#define	NS_SIG_LABELS	3	/* How many labels in name */
#define	NS_SIG_OTTL	4	/* Original TTL */
#define	NS_SIG_EXPIR	8	/* Expiration time */
#define	NS_SIG_SIGNED	12	/* Signature time */
#define	NS_SIG_FOOT	16	/* Key footprint */
#define	NS_SIG_SIGNER	18	/* Domain name of who signed it */

/* How RR types are represented as bit-flags in NXT records */
#define	NS_NXT_BITS 8
#define	NS_NXT_BIT_SET(  n,p) (p[(n)/NS_NXT_BITS] |=  (0x80>>((n)%NS_NXT_BITS)))
#define	NS_NXT_BIT_CLEAR(n,p) (p[(n)/NS_NXT_BITS] &= ~(0x80>>((n)%NS_NXT_BITS)))
#define	NS_NXT_BIT_ISSET(n,p) (p[(n)/NS_NXT_BITS] &   (0x80>>((n)%NS_NXT_BITS)))
#define NS_NXT_MAX 127

/*
 * EDNS0 extended flags and option codes, host order.
 */
#define NS_OPT_DNSSEC_OK	0x8000U
#define NS_OPT_NSID             3
#define NS_OPT_PADDING          12

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 */
#define NS_GET16(s, cp) do { \
	const u_char *t_cp = (const u_char *)(cp); \
	(s) = ((uint16_t)t_cp[0] << 8) \
	    | ((uint16_t)t_cp[1]) \
	    ; \
	(cp) += NS_INT16SZ; \
} while (/*CONSTCOND*/0)

#define NS_GET32(l, cp) do { \
	const u_char *t_cp = (const u_char *)(cp); \
	(l) = ((uint32_t)t_cp[0] << 24) \
	    | ((uint32_t)t_cp[1] << 16) \
	    | ((uint32_t)t_cp[2] << 8) \
	    | ((uint32_t)t_cp[3]) \
	    ; \
	(cp) += NS_INT32SZ; \
} while (/*CONSTCOND*/0)

#define NS_PUT16(s, cp) do { \
	uint32_t t_s = (uint32_t)(s); \
	u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += NS_INT16SZ; \
} while (/*CONSTCOND*/0)

#define NS_PUT32(l, cp) do { \
	uint32_t t_l = (uint32_t)(l); \
	u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += NS_INT32SZ; \
} while (/*CONSTCOND*/0)

__BEGIN_DECLS

#if !defined(__LP64__)
/* Annoyingly, LP32 shipped with __ names. */
#define ns_format_ttl __ns_format_ttl
#define ns_get16 __ns_get16
#define ns_get32 __ns_get32
#define ns_initparse __ns_initparse
#define ns_makecanon __ns_makecanon
#define ns_msg_getflag __ns_msg_getflag
#define ns_name_compress __ns_name_compress
#define ns_name_ntol __ns_name_ntol
#define ns_name_ntop __ns_name_ntop
#define ns_name_pack __ns_name_pack
#define ns_name_pton __ns_name_pton
#define ns_name_rollback __ns_name_rollback
#define ns_name_skip __ns_name_skip
#define ns_name_uncompress __ns_name_uncompress
#define ns_name_unpack __ns_name_unpack
#define ns_parserr __ns_parserr
#define ns_put16 __ns_put16
#define ns_put32 __ns_put32
#define ns_samename __ns_samename
#define ns_skiprr __ns_skiprr
#define ns_sprintrr __ns_sprintrr
#define ns_sprintrrf __ns_sprintrrf
#endif


#if __BIONIC_AVAILABILITY_GUARD(22)
int ns_msg_getflag(ns_msg __handle, int __flag) __INTRODUCED_IN(22);
uint16_t ns_get16(const u_char* _Nonnull __src) __INTRODUCED_IN(22);
uint32_t ns_get32(const u_char* _Nonnull __src) __INTRODUCED_IN(22);
void ns_put16(uint16_t __src, u_char* _Nonnull __dst) __INTRODUCED_IN(22);
void ns_put32(uint32_t __src, u_char* _Nonnull __dst) __INTRODUCED_IN(22);
int ns_initparse(const u_char* _Nonnull __msg, int __msg_size, ns_msg* _Nonnull __handle) __INTRODUCED_IN(22);
int ns_skiprr(const u_char* _Nonnull __ptr, const u_char* _Nonnull __eom, ns_sect __section, int __count) __INTRODUCED_IN(22);
int ns_parserr(ns_msg* _Nonnull __handle, ns_sect __section, int __rr_number, ns_rr* _Nonnull __rr) __INTRODUCED_IN(22);
int ns_sprintrr(const ns_msg* _Nonnull  __handle, const ns_rr* _Nonnull __rr, const char* _Nullable __name_ctx, const char* _Nullable __origin, char* _Nonnull __buf, size_t __buf_size) __INTRODUCED_IN(22);
int ns_sprintrrf(const u_char* _Nonnull __msg, size_t __msg_size, const char* _Nonnull __name, ns_class __class, ns_type __type, u_long __ttl, const u_char* _Nonnull __rdata, size_t __rdata_size, const char* _Nullable __name_ctx, const char* _Nullable __origin, char* _Nonnull __buf, size_t __buf_size) __INTRODUCED_IN(22);
int ns_format_ttl(u_long __ttl, char* _Nonnull __dst, size_t __dst_size) __INTRODUCED_IN(22);
int ns_name_ntol(const u_char* _Nonnull __src, u_char* _Nonnull __dst, size_t __dst_size) __INTRODUCED_IN(22);
int ns_name_ntop(const u_char* _Nonnull __src, char* _Nonnull __dst, size_t __dst_size) __INTRODUCED_IN(22);
int ns_name_pton(const char* _Nonnull __src, u_char* _Nonnull __dst, size_t __dst_size) __INTRODUCED_IN(22);
int ns_name_unpack(const u_char* _Nonnull __msg, const u_char* _Nonnull __eom, const u_char* _Nonnull __src, u_char* _Nonnull __dst, size_t __dst_size) __INTRODUCED_IN(22);
int ns_name_pack(const u_char* _Nonnull __src, u_char* _Nonnull __dst, int __dst_size, const u_char* _Nullable * _Nullable __dn_ptrs, const u_char* _Nullable * _Nullable __last_dn_ptr) __INTRODUCED_IN(22);
int ns_name_uncompress(const u_char* _Nonnull __msg, const u_char* _Nonnull __eom, const u_char* _Nonnull __src, char* _Nonnull __dst, size_t __dst_size) __INTRODUCED_IN(22);
int ns_name_compress(const char* _Nonnull __src, u_char* _Nonnull __dst, size_t __dst_size, const u_char* _Nullable * _Nullable __dn_ptrs, const u_char* _Nullable * _Nullable __last_dn_ptr) __INTRODUCED_IN(22);
int ns_name_skip(const u_char* _Nullable * _Nonnull __ptr_ptr, const u_char* _Nonnull __eom) __INTRODUCED_IN(22);
void ns_name_rollback(const u_char* _Nonnull __src, const u_char* _Nullable * _Nonnull __dn_ptrs, const u_char* _Nullable * _Nonnull __last_dn_ptr) __INTRODUCED_IN(22);

int ns_makecanon(const char* _Nonnull __src, char* _Nonnull __dst, size_t __dst_size) __INTRODUCED_IN(22);
int ns_samename(const char* _Nonnull __lhs, const char* _Nonnull __rhs) __INTRODUCED_IN(22);
#endif /* __BIONIC_AVAILABILITY_GUARD(22) */


__END_DECLS

#ifdef BIND_4_COMPAT
#include <arpa/nameser_compat.h>
#endif

#endif /* !_ARPA_NAMESER_H_ */
```