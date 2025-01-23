Response:
Let's break down the thought process for analyzing the `arpa_inet_test.cpp` file.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the C code provided. This means identifying the purpose of the file, what functions it tests, and how those functions work. Because the context is Android's `bionic` library, we also need to consider the relationship to Android and how these functions might be used in that ecosystem. The request also specifically asks for details on libc function implementation, dynamic linking aspects, potential errors, and how Android frameworks might use these functions.

**2. Initial Overview - What is this file?**

The first step is to read the comments and the basic structure. The `/* ... */` block at the beginning gives us the crucial information: this is a test file (`arpa_inet_test.cpp`) within Android's `bionic` library. The `arpa/inet.h` include immediately tells us it's related to network address manipulation functions. The `TEST` macros indicate it's using Google Test (gtest) for unit testing.

**3. Function Identification and Grouping:**

Next, I'd scan the file for the `TEST` blocks. Each `TEST` block focuses on specific functions from `arpa/inet.h`. I'd make a list of these functions:

* `inet_addr`
* `inet_aton`
* `inet_lnaof`
* `inet_makeaddr`
* `inet_netof`
* `inet_network`
* `inet_ntoa`
* `inet_pton`
* `inet_ntop`
* `inet_nsap_addr`
* `inet_nsap_ntoa`

Then, I'd group them conceptually. Many operate in pairs or relate to the same task:

* **String to Network Address:** `inet_addr`, `inet_aton`, `inet_network`, `inet_pton`, `inet_nsap_addr`
* **Network Address to String:** `inet_ntoa`, `inet_ntop`, `inet_nsap_ntoa`
* **Address Manipulation:** `inet_lnaof`, `inet_makeaddr`, `inet_netof`

**4. Analyzing Individual Tests and Function Behavior:**

Now comes the core work. For each `TEST` block, I'd examine the assertions (`ASSERT_EQ`, `ASSERT_STREQ`). These assertions provide concrete examples of how the functions are expected to behave with different inputs.

* **Example: `inet_aton`:**  I'd notice the different formats it handles: dotted decimal (a.b.c.d), shorter forms (a.b.c, a.b, a), hexadecimal, and octal. The tests cover both valid and invalid inputs, which is crucial for understanding function limitations and error handling. The `nullptr` tests are important for understanding how null pointers are handled.

* **Example: `inet_ntop` and `inet_pton`:**  The test explicitly mentions overflow bugs in other implementations, indicating a focus on robustness in the Android version.

* **Example: `inet_nsap_addr` and `inet_nsap_ntoa`:**  The comments within these tests are invaluable, explaining their undocumented nature and purpose (handling arbitrary-length hexadecimal strings). The tests themselves demonstrate how punctuation is handled and the behavior with different inputs. The conditional compilation (`#if !defined(ANDROID_HOST_MUSL)`) signals potential platform differences.

**5. Connecting to Android:**

At this point, I'd start thinking about how these functions are relevant to Android. Networking is fundamental to mobile operating systems. I'd consider scenarios like:

* **Network Configuration:**  Parsing IP addresses from configuration files or user input.
* **Socket Programming:**  Converting human-readable IP addresses to the binary format needed for socket operations.
* **DNS Resolution:**  While not directly in this file, the output of DNS lookups often needs to be converted and manipulated using these functions.
* **Inter-Process Communication (IPC):**  Some IPC mechanisms might involve network-like addressing.

**6. Libc Function Implementation (Conceptual):**

While the source code for the libc functions isn't provided in this file, I'd leverage my knowledge of standard C libraries to describe their general implementation:

* **`inet_addr` and `inet_aton`:**  Likely involve string parsing, handling different number bases (decimal, hex, octal), range checking for each octet, and bitwise operations to assemble the 32-bit IP address.
* **`inet_ntoa` and `inet_ntop`:**  Involve extracting the bytes from the 32-bit IP address and formatting them into a dotted decimal string. `inet_ntop` is more general and handles IPv6 as well.
* **`inet_lnaof`, `inet_makeaddr`, `inet_netof`, `inet_network`:** These are older functions related to classful networking. Their implementation involves bitwise masking and shifting to extract or construct network and host parts of the address.
* **`inet_nsap_addr` and `inet_nsap_ntoa`:**  These would involve iterating through the input string/byte array, converting hex digits to their binary representation, and handling the optional punctuation.

**7. Dynamic Linking:**

The request specifically asks about the dynamic linker. Since this is a *test* file, it's less directly involved with dynamic linking than the actual library implementation. However, the tests rely on the `arpa/inet.h` functions being available at runtime. I'd explain the basic dynamic linking process:

* The test executable is linked against `libc.so` (where these functions reside).
* When the test runs, the dynamic linker finds and loads `libc.so` into memory.
* The test code can then call the `inet_*` functions.

I'd create a simple `libc.so` layout example and explain the relocation process.

**8. Common Errors:**

By looking at the "invalid" test cases in `inet_aton`, I could deduce common usage errors:

* Invalid input formats (leading/trailing junk, incorrect number bases).
* Out-of-range values for IP address parts.
* Passing `nullptr` when not allowed.
* Buffer overflows (relevant to `inet_ntop` if the buffer size is too small).

**9. Android Framework and NDK Usage:**

I'd think about how an Android app might indirectly use these functions:

* **Framework:**  The Android framework uses networking extensively for internet access, location services, etc. Framework components would call system services, which in turn use these lower-level networking functions provided by `bionic`.
* **NDK:**  NDK developers can directly access these functions by including `<arpa/inet.h>`. This is common for network-intensive apps or libraries.

**10. Frida Hooking:**

Finally, I'd devise Frida hook examples to demonstrate how to intercept calls to these functions to inspect arguments and return values. This helps in debugging and understanding the flow of execution.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the implementation details of each libc function.
* **Correction:** Realize that the *test file* doesn't contain the *implementation*. Shift focus to explaining the *expected behavior* based on the tests and general knowledge of network functions.
* **Initial thought:** Overcomplicate the dynamic linking explanation.
* **Correction:** Simplify to the essential concepts of loading `libc.so` and symbol resolution in the context of the test program.
* **Initial thought:**  Not enough emphasis on practical Android usage scenarios.
* **Correction:**  Add concrete examples of how the framework and NDK utilize these functions.

By following these steps, I could systematically analyze the code, connect it to the broader Android ecosystem, and address all the specific requirements of the prompt. The key is to break down the problem into smaller, manageable parts and leverage existing knowledge of networking, C libraries, and Android development.
好的，我们来详细分析一下 `bionic/tests/arpa_inet_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/arpa_inet_test.cpp` 是 Android Bionic 库中关于网络地址转换相关函数（定义在 `<arpa/inet.h>` 头文件中）的单元测试文件。它的主要功能是：

1. **验证 `<arpa/inet.h>` 中函数的正确性**: 通过编写各种测试用例，覆盖不同输入场景，断言函数的输出是否符合预期。
2. **作为示例代码**:  开发者可以通过阅读这些测试用例，了解如何正确使用 `<arpa/inet.h>` 中提供的函数。

**与 Android 功能的关系及举例说明**

`arpa/inet.h` 中定义的函数是网络编程的基础，在 Android 系统中被广泛使用，用于处理 IP 地址的转换和表示。

* **网络配置**: Android 系统在配置网络接口时，例如设置静态 IP 地址，需要将用户输入的点分十进制 IP 地址字符串转换为 32 位的网络字节序整数，这时就会用到 `inet_addr` 或 `inet_aton`。
* **Socket 编程**:  Android 应用进行网络通信时，需要创建 socket 并绑定或连接到特定的 IP 地址和端口。`sockaddr_in` 结构体中存储 IP 地址的字段通常是通过 `inet_addr` 或 `inet_aton` 将字符串转换为网络字节序整数后赋值的。
* **DNS 解析**:  当 Android 应用需要解析域名时，底层的 DNS 解析过程会将域名转换为 IP 地址。这个 IP 地址通常以点分十进制字符串的形式返回，可能需要使用 `inet_addr` 或 `inet_aton` 转换为网络字节序整数以便在 socket 中使用。
* **网络工具**: Android 系统自带的网络工具（如 `ping`, `netstat` 等）在处理 IP 地址时也会用到这些函数。

**举例说明:**

假设一个 Android 应用需要连接到 IP 地址为 "192.168.1.100" 的服务器。在 Java 层可能通过 `InetAddress.getByName("192.168.1.100")` 获取 IP 地址对象，而在 native 层，则可能使用如下代码：

```c++
#include <arpa/inet.h>
#include <stdio.h>

int main() {
  const char* ip_str = "192.168.1.100";
  struct sockaddr_in server_addr;

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(8080); // 假设端口是 8080

  if (inet_aton(ip_str, &server_addr.sin_addr) == 0) {
    perror("inet_aton failed");
    return 1;
  }

  // 现在 server_addr.sin_addr 包含了 IP 地址的网络字节序整数
  printf("IP address in network byte order: %u\n", server_addr.sin_addr.s_addr);

  return 0;
}
```

**详细解释每一个 libc 函数的功能是如何实现的**

这个测试文件本身并不包含这些 libc 函数的实现，它只是测试这些函数的行为。这些函数的实现位于 Bionic 库的 `libc.so` 中。  以下是这些函数的功能和大致实现思路：

1. **`inet_addr(const char *cp)`**:
   * **功能**: 将点分十进制的 IPv4 地址字符串 (`a.b.c.d`) 转换为 32 位的网络字节序整数。如果输入字符串无效，则返回 `INADDR_NONE`。
   * **实现思路**:
     * 解析输入字符串，按点号分隔成最多四个部分。
     * 将每个部分转换为整数。
     * 检查每个整数是否在 0-255 的范围内。
     * 根据部分的数量，将整数组合成 32 位整数。
     * 如果只有一个部分，则直接作为 32 位地址。
     * 如果有两个部分，后一部分被解释为最后两个字节（网络号和本地主机号）。
     * 如果有三个部分，最后一部分被解释为最后一个字节（子网号和本地主机号）。
     * 如果有四个部分，则按顺序组合。
     * 将结果转换为网络字节序 (大端)。

2. **`inet_aton(const char *cp, struct in_addr *inp)`**:
   * **功能**: 功能与 `inet_addr` 类似，但如果转换成功，则将结果存储在 `inp` 指向的 `in_addr` 结构体中，并返回非零值；如果输入字符串无效，则返回 0。
   * **实现思路**: 与 `inet_addr` 类似，但多了将结果存储到指定内存的功能。

3. **`inet_lnaof(struct in_addr in)`**:
   * **功能**: 返回给定网络地址的本地主机地址部分（Host ID）。这个函数与早期的有类网络地址划分有关。
   * **实现思路**:  根据地址的类别（A, B, C 类），通过位掩码操作提取出 Host ID 部分。例如，对于 C 类地址，Host ID 是最后 8 位。

4. **`inet_makeaddr(int net, int host)`**:
   * **功能**:  根据网络号 (`net`) 和本地主机号 (`host`) 组合成一个网络地址。这个函数也与早期的有类网络地址划分有关。
   * **实现思路**: 根据网络号的大小确定地址类别，然后将网络号和主机号组合成 32 位整数，并转换为网络字节序。

5. **`inet_netof(struct in_addr in)`**:
   * **功能**: 返回给定网络地址的网络号部分（Network ID）。这个函数与早期的有类网络地址划分有关。
   * **实现思路**:  根据地址的类别，通过位掩码操作提取出 Network ID 部分。

6. **`inet_network(const char *cp)`**:
   * **功能**: 将点分十进制的 IPv4 地址字符串转换为 **主机字节序** 的 32 位整数。与 `inet_addr` 的主要区别在于字节序。
   * **实现思路**:  与 `inet_addr` 类似进行解析和转换，但最终结果使用主机字节序。

7. **`inet_ntoa(struct in_addr in)`**:
   * **功能**: 将 32 位的网络字节序 IPv4 地址转换为点分十进制的字符串表示。返回指向静态缓冲区的指针，该缓冲区会被后续调用覆盖。
   * **实现思路**:
     * 将输入的网络字节序整数转换为主机字节序。
     * 将 32 位整数拆分成四个 8 位的部分。
     * 将每个 8 位部分转换为十进制字符串。
     * 将四个字符串用点号连接起来。
     * 将结果存储在静态缓冲区中。

8. **`inet_pton(int af, const char *src, void *dst)`**:
   * **功能**: 将网络地址（IPv4 或 IPv6）从文本表示转换为二进制表示，存储到 `dst` 指向的缓冲区中。`af` 指定地址族 (如 `AF_INET`, `AF_INET6`)。
   * **实现思路**:
     * 根据 `af` 的值选择相应的处理逻辑。
     * 对于 IPv4 (`AF_INET`)，解析点分十进制字符串，与 `inet_aton` 类似，并将结果存储到 `dst` 中。
     * 对于 IPv6 (`AF_INET6`)，解析冒号分隔的十六进制字符串，并将 128 位地址存储到 `dst` 中。

9. **`inet_ntop(int af, const void *src, char *dst, socklen_t size)`**:
   * **功能**: 将网络地址（IPv4 或 IPv6）从二进制表示转换为文本表示，存储到 `dst` 指向的缓冲区中。`af` 指定地址族，`size` 是 `dst` 缓冲区的大小。
   * **实现思路**:
     * 根据 `af` 的值选择相应的处理逻辑。
     * 对于 IPv4 (`AF_INET`)，从 `src` 读取 32 位地址，并格式化为点分十进制字符串存储到 `dst` 中。
     * 对于 IPv6 (`AF_INET6`)，从 `src` 读取 128 位地址，并格式化为冒号分隔的十六进制字符串存储到 `dst` 中。
     * 确保 `dst` 缓冲区有足够的空间，防止溢出。

10. **`inet_nsap_addr(const char *cp, u_char *buf, int buflen)`** (非标准，可能在某些系统上不可用):
    * **功能**: 将表示 NSAP 地址的字符串转换为二进制形式。
    * **实现思路**: 解析以 "0x" 开头的十六进制字符串，忽略点号、加号和斜杠等分隔符，并将十六进制数转换为字节存储到 `buf` 中。

11. **`inet_nsap_ntoa(int len, const u_char *inp, char *buf)`** (非标准，可能在某些系统上不可用):
    * **功能**: 将二进制 NSAP 地址转换为字符串表示。
    * **实现思路**: 将 `inp` 指向的字节数组转换为以 "0x" 开头的十六进制字符串，每两个字节用点号分隔。

**涉及 dynamic linker 的功能**

此测试文件本身不直接涉及 dynamic linker 的具体操作。然而，它依赖于 `libc.so` 中实现的这些网络函数。当这个测试程序被执行时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责：

1. **加载共享库**:  加载测试程序依赖的共享库，其中最重要的是 `libc.so`。
2. **符号解析**:  解析测试程序中对 `inet_addr` 等函数的引用，找到 `libc.so` 中这些函数的地址。
3. **重定位**:  调整代码和数据中的地址，确保它们在内存中的正确位置。

**`libc.so` 布局样本**

```
libc.so:
  .text:  // 存放代码段
    inet_addr: ... // inet_addr 函数的机器码
    inet_aton: ... // inet_aton 函数的机器码
    inet_ntoa: ... // inet_ntoa 函数的机器码
    ...

  .data:  // 存放已初始化的全局变量和静态变量

  .bss:   // 存放未初始化的全局变量和静态变量

  .dynsym: // 动态符号表，包含导出的符号（函数名、变量名等）及其地址
    inet_addr
    inet_aton
    inet_ntoa
    ...

  .dynstr: // 动态字符串表，存储符号的名字

  .plt:    // Procedure Linkage Table，过程链接表，用于延迟绑定

  .got:    // Global Offset Table，全局偏移表，存储全局变量和函数的地址
```

**链接的处理过程**

1. **编译链接阶段**:  编译测试代码时，编译器看到对 `inet_addr` 等函数的调用，会生成一个对这些符号的引用。链接器会将这些引用记录在测试程序的可执行文件中。
2. **加载执行阶段**:
   * 当测试程序被执行时，dynamic linker 首先被加载。
   * Dynamic linker 解析测试程序的可执行文件头，找到它依赖的共享库列表（通常在 `.dynamic` 段）。
   * Dynamic linker 加载 `libc.so` 到内存中的某个地址。
   * Dynamic linker 遍历测试程序中的重定位表，找到需要重定位的符号（例如 `inet_addr`）。
   * Dynamic linker 在 `libc.so` 的 `.dynsym` 表中查找 `inet_addr` 符号，找到其在 `libc.so` 中的地址。
   * Dynamic linker 将找到的地址填入测试程序的 `.got` 表中对应的条目。
   * 首次调用 `inet_addr` 时，会通过 `.plt` 表跳转到 `.got` 表中对应的地址，从而执行 `libc.so` 中的 `inet_addr` 函数。后续调用会直接通过 `.got` 表跳转，避免重复查找。

**假设输入与输出 (逻辑推理)**

以 `inet_aton` 为例：

* **假设输入**: `cp = "192.168.1.100"`, `inp` 指向一个 `in_addr` 结构体。
* **预期输出**: 函数返回 1，`inp->s_addr` 的值为 `htonl(0xC0A80164)` (0xC0A80164 是 192.168.1.100 的十六进制表示，`htonl` 确保是大端字节序)。

以 `inet_ntoa` 为例：

* **假设输入**: `in.s_addr = htonl(0xC0A80164)`。
* **预期输出**: 函数返回指向静态缓冲区的指针，缓冲区内容为字符串 `"192.168.1.100"`。

**涉及用户或者编程常见的使用错误**

1. **传递无效的 IP 地址字符串给 `inet_addr` 或 `inet_aton`**: 例如，包含非数字字符、数字超出范围、格式不正确等。测试文件中有很多这样的例子。
2. **假设 `inet_ntoa` 返回的字符串是线程安全的或持久的**: `inet_ntoa` 使用静态缓冲区，多线程环境下可能出现竞争条件，并且后续调用会覆盖之前的结果。应该将结果复制到自己的缓冲区中。
3. **字节序错误**:  网络编程中需要使用网络字节序（大端），而主机使用的可能是小端。如果直接使用未转换的地址，会导致连接错误。 应该使用 `htonl` 将主机字节序转换为网络字节序，`ntohl` 进行反向转换。
4. **缓冲区溢出**:  在使用 `inet_ntop` 时，如果提供的缓冲区 `size` 不够大，会导致缓冲区溢出。应该使用 `INET_ADDRSTRLEN` (对于 IPv4) 或 `INET6_ADDRSTRLEN` (对于 IPv6) 来确保缓冲区足够大。
5. **混淆 `inet_addr` 和 `inet_network` 的字节序**:  `inet_addr` 返回网络字节序，而 `inet_network` 返回主机字节序。错误地使用会导致地址解析错误。

**Android Framework or NDK 是如何一步步的到达这里**

**Android Framework (Java 层):**

1. **应用发起网络请求**: 例如，使用 `HttpURLConnection` 或 `OkHttp` 发起 HTTP 请求。
2. **域名解析**:  如果请求的目标是域名，Framework 会使用 `java.net.InetAddress.getByName()` 进行域名解析。
3. **系统服务调用**: `InetAddress.getByName()` 底层会调用到 Android 系统的 `netd` (network daemon) 服务。
4. **`netd` 处理**: `netd` 负责处理网络相关的请求，包括 DNS 解析。它可能会调用底层的 Bionic 库函数，例如与 socket 操作相关的函数，这些函数内部可能会用到 `inet_addr` 或 `inet_aton` 来处理 IP 地址。

**Android NDK (C/C++ 层):**

1. **NDK 应用使用 Socket API**:  NDK 开发者可以直接使用 POSIX socket API 进行网络编程。
2. **包含头文件**:  开发者需要包含 `<sys/socket.h>` 和 `<netinet/in.h>` (或者 `<arpa/inet.h>`) 等头文件。
3. **使用 `inet_addr`, `inet_aton` 等函数**:  开发者可以使用这些函数将 IP 地址字符串转换为网络字节序的整数，填充 `sockaddr_in` 结构体，用于 `bind`, `connect` 等 socket 操作。

**Frida Hook 示例调试步骤**

假设我们想 hook `inet_aton` 函数，查看其输入和输出：

```python
import frida
import sys

# 要 hook 的目标进程
package_name = "com.example.myapp"  # 替换为你的应用包名

# Frida script
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "inet_aton"), {
  onEnter: function(args) {
    var cp = Memory.readCString(args[0]);
    var inp = ptr(args[1]);
    console.log("inet_aton called with cp: " + cp + ", inp: " + inp);
  },
  onLeave: function(retval) {
    console.log("inet_aton returned: " + retval);
    if (retval != 0) {
      var inp_addr = this.context.r1; // 或者根据架构使用对应的寄存器
      var s_addr = Memory.readU32(inp_addr);
      console.log("inet_aton result s_addr: " + s_addr);
    }
  }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()  # Keep the script running
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the app is running.")
except Exception as e:
    print(e)
```

**步骤解释:**

1. **导入 Frida 库**: 导入 `frida` 和 `sys` 库。
2. **指定目标进程**:  将 `package_name` 替换为你要调试的 Android 应用的包名。
3. **编写 Frida Script**:
   * `Interceptor.attach`:  使用 Frida 的 `Interceptor` API 附加到 `libc.so` 中的 `inet_aton` 函数。
   * `onEnter`:  在 `inet_aton` 函数被调用前执行。
     * `Memory.readCString(args[0])`: 读取第一个参数（`cp`，IP 地址字符串）。
     * `ptr(args[1])`: 获取第二个参数（指向 `in_addr` 结构体的指针）。
     * 打印输入参数。
   * `onLeave`: 在 `inet_aton` 函数返回后执行。
     * 打印返回值。
     * 如果返回值非零（表示成功），则读取 `in_addr` 结构体中的 `s_addr` 字段。需要根据 CPU 架构确定 `in_addr` 结构体的地址，这里假设 `inp` 指针存储在 `r1` 寄存器中。
4. **定义消息处理函数**: `on_message` 函数用于处理 Frida script 发送的消息（例如 `console.log` 的输出）。
5. **连接设备并加载 Script**:
   * `frida.get_usb_device().attach(package_name)`: 连接到 USB 设备上的目标进程。
   * `session.create_script(script_code)`: 创建 Frida script 对象。
   * `script.on('message', on_message)`: 注册消息处理函数。
   * `script.load()`: 加载并执行 script。
6. **保持 Script 运行**: `sys.stdin.read()` 阻止 Python 脚本退出，保持 Frida hook 持续生效。

**运行流程:**

1. 确保你的 Android 设备已连接并通过 USB 调试。
2. 确保 Frida 服务已在 Android 设备上运行。
3. 运行这个 Python 脚本。
4. 启动或操作你的目标 Android 应用，使其调用到 `inet_aton` 函数（例如，进行网络连接）。
5. Frida script 会捕获到 `inet_aton` 的调用，并在终端输出其输入参数和返回值，以及转换后的 IP 地址数值。

通过这种方式，你可以监控 Android 应用中对网络地址转换函数的调用，帮助你理解其内部工作原理和调试网络相关问题。

### 提示词
```
这是目录为bionic/tests/arpa_inet_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <sys/cdefs.h>

#include <gtest/gtest.h>

#include <arpa/inet.h>

TEST(arpa_inet, inet_addr) {
  ASSERT_EQ((htonl)(0x7f000001), inet_addr("127.0.0.1"));
}

TEST(arpa_inet, inet_aton) {
  in_addr a;

  // a.b.c.d
  a.s_addr = 0;
  ASSERT_EQ(1, inet_aton("127.1.2.3", &a));
  ASSERT_EQ((htonl)(0x7f010203), a.s_addr);

  // a.b.c
  a.s_addr = 0;
  ASSERT_EQ(1, inet_aton("127.1.2", &a));
  ASSERT_EQ((htonl)(0x7f010002), a.s_addr);

  // a.b
  a.s_addr = 0;
  ASSERT_EQ(1, inet_aton("127.1", &a));
  ASSERT_EQ((htonl)(0x7f000001), a.s_addr);

  // a
  a.s_addr = 0;
  ASSERT_EQ(1, inet_aton("0x7f000001", &a));
  ASSERT_EQ((htonl)(0x7f000001), a.s_addr);

  // Hex (0x) and mixed-case hex digits.
  a.s_addr = 0;
  ASSERT_EQ(1, inet_aton("0xFf.0.0.1", &a));
  ASSERT_EQ((htonl)(0xff000001), a.s_addr);

  // Hex (0X) and mixed-case hex digits.
  a.s_addr = 0;
  ASSERT_EQ(1, inet_aton("0XfF.0.0.1", &a));
  ASSERT_EQ((htonl)(0xff000001), a.s_addr);

  // Octal.
  a.s_addr = 0;
  ASSERT_EQ(1, inet_aton("0177.0.0.1", &a));
  ASSERT_EQ((htonl)(0x7f000001), a.s_addr);

  a.s_addr = 0;
  ASSERT_EQ(1, inet_aton("036", &a));
  ASSERT_EQ((htonl)(036U), a.s_addr);
}

TEST(arpa_inet, inet_aton_nullptr) {
  ASSERT_EQ(0, inet_aton("", nullptr));
  ASSERT_EQ(1, inet_aton("127.0.0.1", nullptr));
}

TEST(arpa_inet, inet_aton_invalid) {
  ASSERT_EQ(0, inet_aton("", nullptr)); // Empty.
  ASSERT_EQ(0, inet_aton("x", nullptr)); // Leading junk.
  ASSERT_EQ(0, inet_aton("127.0.0.1x", nullptr)); // Trailing junk.
  ASSERT_EQ(0, inet_aton("09.0.0.1", nullptr)); // Invalid octal.
  ASSERT_EQ(0, inet_aton("0xg.0.0.1", nullptr)); // Invalid hex.

  ASSERT_EQ(0, inet_aton("1.2.3.4.5", nullptr)); // Too many dots.
  ASSERT_EQ(0, inet_aton("1.2.3.4.", nullptr)); // Trailing dot.

  // Out of range a.b.c.d form.
  ASSERT_EQ(0, inet_aton("999.0.0.1", nullptr));
  ASSERT_EQ(0, inet_aton("0.999.0.1", nullptr));
  ASSERT_EQ(0, inet_aton("0.0.999.1", nullptr));
  ASSERT_EQ(0, inet_aton("0.0.0.999", nullptr));

  // Out of range a.b.c form.
  ASSERT_EQ(0, inet_aton("256.0.0", nullptr));
  ASSERT_EQ(0, inet_aton("0.256.0", nullptr));
  ASSERT_EQ(0, inet_aton("0.0.0x10000", nullptr));

  // Out of range a.b form.
  ASSERT_EQ(0, inet_aton("256.0", nullptr));
  ASSERT_EQ(0, inet_aton("0.0x1000000", nullptr));

  // Out of range a form.
  ASSERT_EQ(0, inet_aton("0x100000000", nullptr));

  // 64-bit overflow.
  ASSERT_EQ(0, inet_aton("0x10000000000000000", nullptr));

  // Out of range octal.
  ASSERT_EQ(0, inet_aton("0400.0.0.1", nullptr));
}

TEST(arpa_inet, inet_lnaof) {
  in_addr a = { htonl(0x12345678) };
  ASSERT_EQ(0x00345678U, inet_lnaof(a));
}

TEST(arpa_inet, inet_makeaddr) {
  in_addr a = inet_makeaddr(0x12U, 0x345678);
  ASSERT_EQ((htonl)(0x12345678), a.s_addr);
}

TEST(arpa_inet, inet_netof) {
  in_addr a = { htonl(0x12345678) };
  ASSERT_EQ(0x12U, inet_netof(a));
}

TEST(arpa_inet, inet_network) {
  ASSERT_EQ(0x7f000001U, inet_network("127.0.0.1"));
  ASSERT_EQ(0x7fU, inet_network("0x7f"));
  ASSERT_EQ(~0U, inet_network(""));
}

TEST(arpa_inet, inet_ntoa) {
  in_addr a = { (htonl)(0x7f000001) };
  ASSERT_STREQ("127.0.0.1", inet_ntoa(a));
}

TEST(arpa_inet, inet_pton__inet_ntop) {
  sockaddr_storage ss;
  ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.1", &ss));

  char s[INET_ADDRSTRLEN];
  ASSERT_STREQ("127.0.0.1", inet_ntop(AF_INET, &ss, s, INET_ADDRSTRLEN));
}

TEST(arpa_inet, inet_ntop_overflow) {
  // OpenBSD's inet_ntop had a bug where passing a 'size' larger than INET_ADDRSTRLEN
  // for AF_INET or INET6_ADDRSTRLEN for AF_INET6 would cause inet_ntop to overflow an
  // internal buffer.

  sockaddr_storage ss4;
  ASSERT_EQ(1, inet_pton(AF_INET, "127.0.0.1", &ss4));

  sockaddr_storage ss6;
  ASSERT_EQ(1, inet_pton(AF_INET6, "::1", &ss6));

  char s4[INET_ADDRSTRLEN];
  char s6[INET6_ADDRSTRLEN];
  ASSERT_STREQ("127.0.0.1", inet_ntop(AF_INET, &ss4, s4, INET_ADDRSTRLEN));
  ASSERT_STREQ("127.0.0.1", inet_ntop(AF_INET, &ss4, s4, 2*INET_ADDRSTRLEN));
  ASSERT_STREQ("::1", inet_ntop(AF_INET6, &ss6, s6, INET_ADDRSTRLEN));
  ASSERT_STREQ("::1", inet_ntop(AF_INET6, &ss6, s6, INET6_ADDRSTRLEN));
  ASSERT_STREQ("::1", inet_ntop(AF_INET6, &ss6, s6, 2*INET6_ADDRSTRLEN));
}

TEST(arpa_inet, inet_nsap_addr) {
#if !defined(ANDROID_HOST_MUSL)
  // inet_nsap_addr() doesn't seem to be documented anywhere, but it's basically
  // text to binary for arbitrarily-long strings like "0xdeadbeef". Any
  // '.', '+', or '/' characters are ignored as punctuation. The return value is
  // the length in bytes, or 0 for all errors.
  u_char buf[32];

  // Missing "0x" prefix.
  ASSERT_EQ(0U, inet_nsap_addr("123", buf, sizeof(buf)));
  ASSERT_EQ(0U, inet_nsap_addr("012", buf, sizeof(buf)));

  // 1 byte.
  ASSERT_EQ(1U, inet_nsap_addr("0x12", buf, sizeof(buf)));
  ASSERT_EQ(0x12, buf[0]);

  // 10 bytes.
  ASSERT_EQ(10U, inet_nsap_addr("0x1234567890abcdef0011", buf, sizeof(buf)));
  ASSERT_EQ(0x12, buf[0]);
  ASSERT_EQ(0x34, buf[1]);
  ASSERT_EQ(0x56, buf[2]);
  ASSERT_EQ(0x78, buf[3]);
  ASSERT_EQ(0x90, buf[4]);
  ASSERT_EQ(0xab, buf[5]);
  ASSERT_EQ(0xcd, buf[6]);
  ASSERT_EQ(0xef, buf[7]);
  ASSERT_EQ(0x00, buf[8]);
  ASSERT_EQ(0x11, buf[9]);

  // Ignored punctuation.
  ASSERT_EQ(10U, inet_nsap_addr("0x1122.3344+5566/7788/99aa", buf, sizeof(buf)));
  ASSERT_EQ(0x11, buf[0]);
  ASSERT_EQ(0x22, buf[1]);
  ASSERT_EQ(0x33, buf[2]);
  ASSERT_EQ(0x44, buf[3]);
  ASSERT_EQ(0x55, buf[4]);
  ASSERT_EQ(0x66, buf[5]);
  ASSERT_EQ(0x77, buf[6]);
  ASSERT_EQ(0x88, buf[7]);
  ASSERT_EQ(0x99, buf[8]);
  ASSERT_EQ(0xaa, buf[9]);

  // Truncated.
  ASSERT_EQ(4U, inet_nsap_addr("0xdeadbeef666666666666", buf, 4));
  // Overwritten...
  ASSERT_EQ(0xde, buf[0]);
  ASSERT_EQ(0xad, buf[1]);
  ASSERT_EQ(0xbe, buf[2]);
  ASSERT_EQ(0xef, buf[3]);
  // Same as before...
  ASSERT_EQ(0x55, buf[4]);
  ASSERT_EQ(0x66, buf[5]);
  ASSERT_EQ(0x77, buf[6]);
  ASSERT_EQ(0x88, buf[7]);
  ASSERT_EQ(0x99, buf[8]);
  ASSERT_EQ(0xaa, buf[9]);

  // Case insensitivity.
  ASSERT_EQ(6U, inet_nsap_addr("0xaAbBcCdDeEfF", buf, 6));
  ASSERT_EQ(0xaa, buf[0]);
  ASSERT_EQ(0xbb, buf[1]);
  ASSERT_EQ(0xcc, buf[2]);
  ASSERT_EQ(0xdd, buf[3]);
  ASSERT_EQ(0xee, buf[4]);
  ASSERT_EQ(0xff, buf[5]);

  // Punctuation isn't allowed within a byte.
  ASSERT_EQ(0U, inet_nsap_addr("0x1.122", buf, sizeof(buf)));
  // Invalid punctuation.
  ASSERT_EQ(0U, inet_nsap_addr("0x11,22", buf, sizeof(buf)));
  // Invalid hex digit.
  ASSERT_EQ(0U, inet_nsap_addr("0x11.g2", buf, sizeof(buf)));
  ASSERT_EQ(0U, inet_nsap_addr("0x11.2g", buf, sizeof(buf)));
  // Invalid half-byte.
  ASSERT_EQ(0U, inet_nsap_addr("0x11.2", buf, sizeof(buf)));
#else
  GTEST_SKIP() << "musl doesn't have inet_nsap_addr";
#endif
}

TEST(arpa_inet, inet_nsap_ntoa) {
#if !defined(ANDROID_HOST_MUSL)
  // inet_nsap_ntoa() doesn't seem to be documented anywhere, but it's basically
  // binary to text for arbitrarily-long byte buffers.
  // The return value is a pointer to the buffer. No errors are possible.
  const unsigned char bytes[] = {0x01, 0x00, 0x02, 0x0e, 0xf0, 0x20};
  char dst[32];
  ASSERT_EQ(dst, inet_nsap_ntoa(6, bytes, dst));
  ASSERT_STREQ(dst, "0x01.0002.0EF0.20");
#else
  GTEST_SKIP() << "musl doesn't have inet_nsap_ntoa";
#endif
}

TEST(arpa_inet, inet_nsap_ntoa__nullptr) {
#if !defined(ANDROID_HOST_MUSL)
  // If you don't provide a destination, a static buffer is provided for you.
  const unsigned char bytes[] = {0x01, 0x00, 0x02, 0x0e, 0xf0, 0x20};
  ASSERT_STREQ("0x01.0002.0EF0.20", inet_nsap_ntoa(6, bytes, nullptr));
#else
  GTEST_SKIP() << "musl doesn't have inet_nsap_ntoa";
#endif
}
```