Response:
Let's break down the thought process to generate the comprehensive answer about the `services.handroid` file.

1. **Understanding the Request:** The core request is to analyze a source code file, understand its functionality, relate it to Android, explain its implementation details, discuss dynamic linking aspects, address potential usage errors, and demonstrate its usage within the Android ecosystem. The request also emphasizes the need for examples, including Frida hooks.

2. **Initial Analysis of the Source Code:**  The provided code snippet is a single, large string literal named `_services`. This immediately suggests it's a data structure, not executable code. The content of the string appears to be a list of service names and associated information. The structure within the string needs closer examination. The `\0` delimiters are key here, separating fields.

3. **Deconstructing the Data Structure:**  By observing the repeated patterns, we can deduce the structure of each entry in the `_services` string. It seems to be:

   * Service Name (Null-terminated string)
   * Protocol (Null-terminated string, likely 't' for TCP, 'u' for UDP)
   * Port Number (Single byte representing the port number)
   * Aliases (Optional, potentially multiple null-terminated strings)

4. **Identifying the Purpose:**  Given the file name "services.handroid" and the context of being within Android's C library DNS component, the most likely purpose is to provide a mapping between service names and port numbers. This is a fundamental function in networking. The "handroid" suffix might suggest a customized or Android-specific version of a standard services database.

5. **Relating to Android Functionality:**  How does Android use this?  Android applications need to connect to network services. Instead of hardcoding port numbers, they can use service names. The system then needs a way to translate these names to port numbers. This file likely plays that role. Examples would include an app connecting to an HTTP server (port 80), an SSH server (port 22), or a DNS server (port 53).

6. **Explaining Libc Function Implementation:** The crucial point here is that this *isn't* a function. It's a static data structure. The *functions* that *use* this data are the ones whose implementation needs explaining. These would be functions like `getservbyname()` and `getservbyport()`, which are standard POSIX functions likely implemented within Android's libc. The explanation needs to cover how these functions would parse the `_services` data to find the requested information.

7. **Dynamic Linker Aspects:**  This file itself doesn't directly involve the dynamic linker. However, the *libc* it belongs to *does*. So, the explanation needs to cover the general role of the dynamic linker (`linker64` or `linker`) in loading shared libraries (like libc.so) and resolving symbols. A sample `so` layout and the linking process should be included.

8. **Logical Reasoning and Assumptions:** The core logic is the lookup process. Assume an input service name (e.g., "http") and a protocol ("tcp"). The output would be the corresponding port number (80). Similarly, for a port number and protocol, the output would be the service name.

9. **Common Usage Errors:**  A common error for developers is using the wrong protocol or assuming a service exists on a particular port without proper error handling. Examples should illustrate these situations.

10. **Android Framework/NDK Flow:**  Tracing how a network request reaches this data involves multiple layers. Start from the application using the NDK (e.g., `getaddrinfo`), then trace down through system calls, potentially through `netd` (the network daemon), and finally to libc's DNS resolution functions which would consult this data.

11. **Frida Hook Example:**  To demonstrate how to inspect this in a running process, a Frida hook targeting a function that likely uses this data (e.g., `getservbyname`) is crucial. The hook should print the arguments and return value to show the interaction.

12. **Structuring the Answer:** Organize the information logically into sections: Functionality, Relation to Android, Libc Function Implementation, Dynamic Linker, Logical Reasoning, Usage Errors, Android Framework/NDK Flow, and Frida Hook Example. Use clear headings and subheadings.

13. **Language and Tone:**  Maintain a clear, concise, and informative tone in Chinese, as requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is a function definition."  **Correction:** "No, it's a static array of characters."
* **Initial thought:** "Explain the implementation of this code." **Correction:** "Explain how *other* libc functions use this *data*."
* **Ensuring clarity:**  Rephrase complex technical terms simply and provide context.
* **Completeness:** Double-check that all parts of the prompt have been addressed, including the Frida example and dynamic linking details.

By following this detailed thought process, we arrive at the comprehensive and accurate answer provided previously. It involves understanding the code itself, its purpose within the broader system, and how different components interact with it.
这个文件 `bionic/libc/dns/net/services.handroid` 是 Android Bionic C 库中用于 DNS 解析的一个数据文件。它定义了一个静态的、硬编码的服务名称到端口号以及协议的映射表。

**它的功能：**

这个文件的核心功能是提供一个服务名称和其对应的端口号以及所用协议的静态映射。 当应用程序尝试连接到一个使用服务名称而不是直接使用端口号的服务时，Android 系统会查找这个文件来获取相应的端口和协议信息。

**与 Android 功能的关系及举例说明：**

Android 系统中的很多网络功能都依赖于这个映射表。例如：

* **`getaddrinfo()` 函数：** 这是 NDK 中常用的一个函数，用于将主机名和服务名转换为地址信息。当服务名被提供时，`getaddrinfo()` 会调用底层的 DNS 解析函数，而这些函数会查询 `services.handroid` 来查找服务名对应的端口和协议。

   **举例：**  一个 Android 应用想要连接到 Web 服务器，可以使用以下代码（简化）：

   ```c
   struct addrinfo hints, *res;
   memset(&hints, 0, sizeof hints);
   hints.ai_family = AF_UNSPEC; // 可以是 IPv4 或 IPv6
   hints.ai_socktype = SOCK_STREAM; // 使用 TCP

   int status = getaddrinfo("www.example.com", "http", &hints, &res);
   if (status == 0) {
       // 连接到 res 指向的地址
       freeaddrinfo(res);
   } else {
       // 处理错误
   }
   ```

   在这个例子中，`"http"` 作为服务名传递给 `getaddrinfo()`。 底层的解析过程会查找 `services.handroid` 中 `"http"` 对应的端口号 `80` 和协议 `"tcp"`。

* **网络调试工具：** 一些网络调试工具，如 `netstat` 或 `ss`，可能会使用这个文件来将端口号转换为服务名称进行显示，方便用户理解。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个文件本身不是 libc 函数，而是一个静态数据。真正使用这个数据的是 libc 中的 DNS 解析相关的函数，例如：

* **`getservbyname(const char *name, const char *proto)`：**  这个函数接收服务名 (`name`) 和协议 (`proto`) 作为参数，然后在 `_services` 数组中查找匹配的条目。

   **实现原理：**
   1. 函数接收服务名和协议字符串。
   2. 它遍历 `_services` 数组，该数组以 null 结尾的字符串形式存储服务信息。
   3. 对于数组中的每个条目，它会提取服务名和协议部分。
   4. 它使用 `strcmp()` 等字符串比较函数来比较输入的 `name` 和 `proto` 与当前条目的服务名和协议。
   5. 如果找到匹配的条目，它会解析该条目中的端口号并创建一个 `servent` 结构体，该结构体包含服务名、别名列表（如果有）、端口号和协议。
   6. 函数返回指向该 `servent` 结构体的指针。如果未找到匹配的条目，则返回 `NULL`。

* **`getservbyport(int port, const char *proto)`：** 这个函数接收端口号 (`port`) 和协议 (`proto`) 作为参数，然后在 `_services` 数组中查找匹配的条目。

   **实现原理：**
   1. 函数接收端口号（通常需要进行网络字节序转换）和协议字符串。
   2. 它遍历 `_services` 数组。
   3. 对于数组中的每个条目，它会提取端口号和协议部分。
   4. 它比较输入的 `port` 和 `proto` 与当前条目的端口号和协议。注意，存储在 `_services` 中的端口号是单个字节，需要转换为整数进行比较。
   5. 如果找到匹配的条目，它会解析该条目并创建一个 `servent` 结构体。
   6. 函数返回指向该 `servent` 结构体的指针。如果未找到匹配的条目，则返回 `NULL`。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`services.handroid` 本身不直接涉及动态链接器。它是 libc 的一部分，在 libc 被加载到进程空间后，相关的解析函数可以直接访问这个静态数据。

**libc.so 的布局样本：**

一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
    .text          // 包含可执行代码，如 getservbyname, getservbyport 等
    .rodata        // 包含只读数据，如 _services 数组、字符串常量等
    .data          // 包含已初始化的全局变量和静态变量
    .bss           // 包含未初始化的全局变量和静态变量
    .dynamic       // 动态链接信息
    .symtab        // 符号表
    .strtab        // 字符串表
    ...
```

**链接的处理过程：**

1. **加载：** 当一个 Android 应用启动时，操作系统会加载其依赖的共享库，包括 `libc.so`。动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责这个过程。
2. **符号解析：**  当应用调用 `getaddrinfo()` 等函数时，如果这些函数位于 `libc.so` 中，动态链接器会解析这些符号，将应用的调用指向 `libc.so` 中对应函数的地址。
3. **访问数据：**  `getservbyname()` 和 `getservbyport()` 函数在 `libc.so` 的 `.text` 段中执行，它们可以直接访问位于 `libc.so` 的 `.rodata` 段中的 `_services` 数组。由于 `_services` 是静态数据，在 `libc.so` 加载时就已经被加载到内存中。

**逻辑推理，假设输入与输出：**

**假设输入 (对于 `getservbyname`)：**

* `name`: "http"
* `proto`: "tcp"

**预期输出：**

一个指向 `servent` 结构体的指针，该结构体的内容为：

* `s_name`: "http"
* `s_aliases`: 指向包含 "www" 的字符串数组（根据数据推测）
* `s_port`: 80 (网络字节序，即大端序)
* `s_proto`: "tcp"

**假设输入 (对于 `getservbyport`)：**

* `port`: 80 (主机字节序)
* `proto`: "tcp"

**预期输出：**

一个指向 `servent` 结构体的指针，该结构体的内容为：

* `s_name`: "http"
* `s_aliases`: 指向包含 "www" 的字符串数组
* `s_port`: 80 (网络字节序)
* `s_proto`: "tcp"

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **假设服务不存在：** 如果应用程序尝试使用一个在 `services.handroid` 中没有定义的名称，例如 `getaddrinfo("example.com", "my-custom-service", ...)`，则底层的 `getservbyname()` 将返回 `NULL`，导致 `getaddrinfo()` 失败。开发者需要妥善处理这种情况。

2. **协议不匹配：**  如果应用程序指定的协议与 `services.handroid` 中定义的协议不匹配，例如尝试使用 UDP 连接到 HTTP 服务 (`getaddrinfo("example.com", "http", ..., SOCK_DGRAM, ...)`，而 HTTP 默认是 TCP)，`getservbyname()` 将找不到匹配的条目并返回 `NULL`。

3. **大小写敏感性：**  虽然通常服务名比较是大小写不敏感的，但依赖于具体的实现。开发者应该注意服务名的大小写，并尽量使用标准的服务名。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤：**

1. **NDK 调用：** Android 应用的 Native 代码通常通过 NDK 调用 libc 提供的网络函数，如 `getaddrinfo()`.

2. **libc 中的 `getaddrinfo()`：**  `getaddrinfo()` 函数负责将主机名和服务名解析为网络地址。当提供的是服务名时，它需要查找对应的端口号和协议。

3. **调用 `getservbyname()` 或 `getservbyport()`：**  `getaddrinfo()` 内部会根据传入的参数选择调用 `getservbyname()` (如果提供的是服务名) 或 `getservbyport()` (如果提供的是端口号)。

4. **查询 `_services` 数组：** `getservbyname()` 或 `getservbyport()` 函数会遍历 `services.handroid` 文件对应的内存区域 (`_services` 数组) 来查找匹配的条目。

**Frida Hook 示例：**

可以使用 Frida hook `getservbyname()` 函数来观察其行为：

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换成你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请先启动应用。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "getservbyname"), {
    onEnter: function(args) {
        var name = Memory.readUtf8String(args[0]);
        var proto = Memory.readUtf8String(args[1]);
        send({from: "getservbyname", name: name, proto: proto});
        console.log("getservbyname called with name: " + name + ", proto: " + proto);
    },
    onLeave: function(retval) {
        if (retval.isNull()) {
            send({from: "getservbyname", result: "NULL"});
            console.log("getservbyname returned NULL");
        } else {
            var servent = ptr(retval);
            var s_name = Memory.readUtf8String(servent.readPointer());
            var s_port = servent.add(8).readU16(); // 假设端口号在偏移 8 的位置，需要根据实际结构调整
            var s_proto = Memory.readUtf8String(servent.add(16).readPointer()); // 假设协议在偏移 16 的位置
            send({from: "getservbyname", result: "success", s_name: s_name, s_port: s_port, s_proto: s_proto});
            console.log("getservbyname returned servent struct, name: " + s_name + ", port: " + s_port + ", proto: " + s_proto);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. 将 `your.app.package.name` 替换为你想要调试的 Android 应用的包名。
2. 确保你的 Android 设备已连接并通过 USB 调试模式连接到电脑。
3. 运行这个 Python 脚本。
4. 在你的 Android 应用中触发需要进行网络连接的操作（例如，访问一个网页）。
5. Frida 会拦截对 `getservbyname()` 的调用，并打印出传入的参数（服务名和协议）以及返回值（`servent` 结构体的信息）。

**注意：**

* 上述 Frida 脚本中的偏移量 (`add(8)`, `add(16)`) 是基于对 `servent` 结构体布局的假设，可能需要根据实际的 Bionic libc 版本进行调整。你可以通过查看 Bionic 的头文件来确定 `servent` 结构体的准确布局。
* 需要安装 Frida 和相关的 Python 库 (`frida-tools`).

通过这个 Frida hook 示例，你可以观察到 Android 应用在进行网络请求时，是如何一步步地调用到 `getservbyname()`，并利用 `services.handroid` 中的数据来获取服务信息的。

Prompt: 
```
这是目录为bionic/libc/dns/net/services.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/* generated by genserv.py - do not edit */
static const char  _services[] = "\
\6tcpmux\0\1t\0\
\4echo\0\7t\0\
\4echo\0\7u\0\
\7discard\0\11t\2\4sink\4null\
\7discard\0\11u\2\4sink\4null\
\6systat\0\13t\1\5users\
\7daytime\0\15t\0\
\7daytime\0\15u\0\
\7netstat\0\17t\0\
\4qotd\0\21t\1\5quote\
\3msp\0\22t\0\
\3msp\0\22u\0\
\7chargen\0\23t\2\6ttytst\6source\
\7chargen\0\23u\2\6ttytst\6source\
\10ftp-data\0\24t\0\
\3ftp\0\25t\0\
\3fsp\0\25u\1\4fspd\
\3ssh\0\26t\0\
\3ssh\0\26u\0\
\6telnet\0\27t\0\
\4smtp\0\31t\1\4mail\
\4time\0\45t\1\11timserver\
\4time\0\45u\1\11timserver\
\3rlp\0\47u\1\10resource\
\12nameserver\0\52t\1\4name\
\5whois\0\53t\1\7nicname\
\6tacacs\0\61t\0\
\6tacacs\0\61u\0\
\12re-mail-ck\0\62t\0\
\12re-mail-ck\0\62u\0\
\6domain\0\65t\0\
\6domain\0\65u\0\
\3mtp\0\71t\0\
\11tacacs-ds\0\101t\0\
\11tacacs-ds\0\101u\0\
\6bootps\0\103t\0\
\6bootps\0\103u\0\
\6bootpc\0\104t\0\
\6bootpc\0\104u\0\
\4tftp\0\105u\0\
\6gopher\0\106t\0\
\6gopher\0\106u\0\
\3rje\0\115t\1\6netrjs\
\6finger\0\117t\0\
\4http\0\120t\1\3www\
\4http\0\120u\0\
\4link\0\127t\1\7ttylink\
\10kerberos\0\130t\3\11kerberos5\4krb5\14kerberos-sec\
\10kerberos\0\130u\3\11kerberos5\4krb5\14kerberos-sec\
\6supdup\0\137t\0\
\11hostnames\0\145t\1\10hostname\
\10iso-tsap\0\146t\1\4tsap\
\10acr-nema\0\150t\1\5dicom\
\10acr-nema\0\150u\1\5dicom\
\10csnet-ns\0\151t\1\6cso-ns\
\10csnet-ns\0\151u\1\6cso-ns\
\7rtelnet\0\153t\0\
\7rtelnet\0\153u\0\
\4pop2\0\155t\2\12postoffice\5pop-2\
\4pop2\0\155u\1\5pop-2\
\4pop3\0\156t\1\5pop-3\
\4pop3\0\156u\1\5pop-3\
\6sunrpc\0\157t\1\12portmapper\
\6sunrpc\0\157u\1\12portmapper\
\4auth\0\161t\3\16authentication\3tap\5ident\
\4sftp\0\163t\0\
\11uucp-path\0\165t\0\
\4nntp\0\167t\2\10readnews\4untp\
\3ntp\0\173t\0\
\3ntp\0\173u\0\
\6pwdgen\0\201t\0\
\6pwdgen\0\201u\0\
\7loc-srv\0\207t\1\5epmap\
\7loc-srv\0\207u\1\5epmap\
\12netbios-ns\0\211t\0\
\12netbios-ns\0\211u\0\
\13netbios-dgm\0\212t\0\
\13netbios-dgm\0\212u\0\
\13netbios-ssn\0\213t\0\
\13netbios-ssn\0\213u\0\
\5imap2\0\217t\1\4imap\
\5imap2\0\217u\1\4imap\
\4snmp\0\241t\0\
\4snmp\0\241u\0\
\11snmp-trap\0\242t\1\10snmptrap\
\11snmp-trap\0\242u\1\10snmptrap\
\10cmip-man\0\243t\0\
\10cmip-man\0\243u\0\
\12cmip-agent\0\244t\0\
\12cmip-agent\0\244u\0\
\5mailq\0\256t\0\
\5mailq\0\256u\0\
\5xdmcp\0\261t\0\
\5xdmcp\0\261u\0\
\10nextstep\0\262t\2\10NeXTStep\10NextStep\
\10nextstep\0\262u\2\10NeXTStep\10NextStep\
\3bgp\0\263t\0\
\3bgp\0\263u\0\
\10prospero\0\277t\0\
\10prospero\0\277u\0\
\3irc\0\302t\0\
\3irc\0\302u\0\
\4smux\0\307t\0\
\4smux\0\307u\0\
\7at-rtmp\0\311t\0\
\7at-rtmp\0\311u\0\
\6at-nbp\0\312t\0\
\6at-nbp\0\312u\0\
\7at-echo\0\314t\0\
\7at-echo\0\314u\0\
\6at-zis\0\316t\0\
\6at-zis\0\316u\0\
\4qmtp\0\321t\0\
\4qmtp\0\321u\0\
\5z3950\0\322t\1\4wais\
\5z3950\0\322u\1\4wais\
\3ipx\0\325t\0\
\3ipx\0\325u\0\
\5imap3\0\334t\0\
\5imap3\0\334u\0\
\7pawserv\1\131t\0\
\7pawserv\1\131u\0\
\5zserv\1\132t\0\
\5zserv\1\132u\0\
\7fatserv\1\133t\0\
\7fatserv\1\133u\0\
\13rpc2portmap\1\161t\0\
\13rpc2portmap\1\161u\0\
\11codaauth2\1\162t\0\
\11codaauth2\1\162u\0\
\11clearcase\1\163t\1\11Clearcase\
\11clearcase\1\163u\1\11Clearcase\
\11ulistserv\1\164t\0\
\11ulistserv\1\164u\0\
\4ldap\1\205t\0\
\4ldap\1\205u\0\
\4imsp\1\226t\0\
\4imsp\1\226u\0\
\6svrloc\1\253t\0\
\6svrloc\1\253u\0\
\5https\1\273t\0\
\5https\1\273u\0\
\4snpp\1\274t\0\
\4snpp\1\274u\0\
\14microsoft-ds\1\275t\0\
\14microsoft-ds\1\275u\0\
\7kpasswd\1\320t\0\
\7kpasswd\1\320u\0\
\4saft\1\347t\0\
\4saft\1\347u\0\
\6isakmp\1\364t\0\
\6isakmp\1\364u\0\
\4rtsp\2\52t\0\
\4rtsp\2\52u\0\
\3nqs\2\137t\0\
\3nqs\2\137u\0\
\12npmp-local\2\142t\1\16dqs313_qmaster\
\12npmp-local\2\142u\1\16dqs313_qmaster\
\10npmp-gui\2\143t\1\14dqs313_execd\
\10npmp-gui\2\143u\1\14dqs313_execd\
\10hmmp-ind\2\144t\1\20dqs313_intercell\
\10hmmp-ind\2\144u\1\20dqs313_intercell\
\4qmqp\2\164t\0\
\4qmqp\2\164u\0\
\3ipp\2\167t\0\
\3ipp\2\167u\0\
\4exec\2\0t\0\
\4biff\2\0u\1\6comsat\
\5login\2\1t\0\
\3who\2\1u\1\4whod\
\5shell\2\2t\1\3cmd\
\6syslog\2\2u\0\
\7printer\2\3t\1\7spooler\
\4talk\2\5u\0\
\5ntalk\2\6u\0\
\5route\2\10u\2\6router\6routed\
\5timed\2\15u\1\12timeserver\
\5tempo\2\16t\1\7newdate\
\7courier\2\22t\1\3rpc\
\12conference\2\23t\1\4chat\
\7netnews\2\24t\1\10readnews\
\7netwall\2\25u\0\
\6gdomap\2\32t\0\
\6gdomap\2\32u\0\
\4uucp\2\34t\1\5uucpd\
\6klogin\2\37t\0\
\6kshell\2\40t\1\5krcmd\
\15dhcpv6-client\2\42t\0\
\15dhcpv6-client\2\42u\0\
\15dhcpv6-server\2\43t\0\
\15dhcpv6-server\2\43u\0\
\12afpovertcp\2\44t\0\
\12afpovertcp\2\44u\0\
\4idfp\2\45t\0\
\4idfp\2\45u\0\
\10remotefs\2\54t\2\12rfs_server\3rfs\
\5nntps\2\63t\1\5snntp\
\5nntps\2\63u\1\5snntp\
\12submission\2\113t\0\
\12submission\2\113u\0\
\5ldaps\2\174t\0\
\5ldaps\2\174u\0\
\4tinc\2\217t\0\
\4tinc\2\217u\0\
\4silc\2\302t\0\
\4silc\2\302u\0\
\14kerberos-adm\2\355t\0\
\7webster\2\375t\0\
\7webster\2\375u\0\
\5rsync\3\151t\0\
\5rsync\3\151u\0\
\11ftps-data\3\335t\0\
\4ftps\3\336t\0\
\7telnets\3\340t\0\
\7telnets\3\340u\0\
\5imaps\3\341t\0\
\5imaps\3\341u\0\
\4ircs\3\342t\0\
\4ircs\3\342u\0\
\5pop3s\3\343t\0\
\5pop3s\3\343u\0\
\5socks\4\70t\0\
\5socks\4\70u\0\
\6proofd\4\105t\0\
\6proofd\4\105u\0\
\5rootd\4\106t\0\
\5rootd\4\106u\0\
\7openvpn\4\252t\0\
\7openvpn\4\252u\0\
\13rmiregistry\4\113t\0\
\13rmiregistry\4\113u\0\
\5kazaa\4\276t\0\
\5kazaa\4\276u\0\
\6nessus\4\331t\0\
\6nessus\4\331u\0\
\11lotusnote\5\110t\1\12lotusnotes\
\11lotusnote\5\110u\1\12lotusnotes\
\10ms-sql-s\5\231t\0\
\10ms-sql-s\5\231u\0\
\10ms-sql-m\5\232t\0\
\10ms-sql-m\5\232u\0\
\12ingreslock\5\364t\0\
\12ingreslock\5\364u\0\
\13prospero-np\5\365t\0\
\13prospero-np\5\365u\0\
\13datametrics\6\155t\1\12old-radius\
\13datametrics\6\155u\1\12old-radius\
\13sa-msg-port\6\156t\1\13old-radacct\
\13sa-msg-port\6\156u\1\13old-radacct\
\6kermit\6\161t\0\
\6kermit\6\161u\0\
\11groupwise\6\215t\0\
\11groupwise\6\215u\0\
\3l2f\6\245t\1\4l2tp\
\3l2f\6\245u\1\4l2tp\
\6radius\7\24t\0\
\6radius\7\24u\0\
\13radius-acct\7\25t\1\7radacct\
\13radius-acct\7\25u\1\7radacct\
\4msnp\7\107t\0\
\4msnp\7\107u\0\
\13unix-status\7\245t\0\
\12log-server\7\246t\0\
\12remoteping\7\247t\0\
\12cisco-sccp\7\320t\0\
\12cisco-sccp\7\320u\0\
\6search\7\332t\1\4ndtp\
\13pipe-server\7\332t\1\13pipe_server\
\3nfs\10\1t\0\
\3nfs\10\1u\0\
\6gnunet\10\46t\0\
\6gnunet\10\46u\0\
\12rtcm-sc104\10\65t\0\
\12rtcm-sc104\10\65u\0\
\15gsigatekeeper\10\107t\0\
\15gsigatekeeper\10\107u\0\
\4gris\10\127t\0\
\4gris\10\127u\0\
\12cvspserver\11\141t\0\
\12cvspserver\11\141u\0\
\5venus\11\176t\0\
\5venus\11\176u\0\
\10venus-se\11\177t\0\
\10venus-se\11\177u\0\
\7codasrv\11\200t\0\
\7codasrv\11\200u\0\
\12codasrv-se\11\201t\0\
\12codasrv-se\11\201u\0\
\3mon\12\27t\0\
\3mon\12\27u\0\
\4dict\12\104t\0\
\4dict\12\104u\0\
\15f5-globalsite\12\350t\0\
\15f5-globalsite\12\350u\0\
\6gsiftp\12\373t\0\
\6gsiftp\12\373u\0\
\4gpsd\13\203t\0\
\4gpsd\13\203u\0\
\6gds-db\13\352t\1\6gds_db\
\6gds-db\13\352u\1\6gds_db\
\5icpv2\14\72t\1\3icp\
\5icpv2\14\72u\1\3icp\
\5mysql\14\352t\0\
\5mysql\14\352u\0\
\3nut\15\245t\0\
\3nut\15\245u\0\
\6distcc\16\60t\0\
\6distcc\16\60u\0\
\4daap\16\151t\0\
\4daap\16\151u\0\
\3svn\16\152t\1\12subversion\
\3svn\16\152u\1\12subversion\
\5suucp\17\277t\0\
\5suucp\17\277u\0\
\6sysrqd\17\376t\0\
\6sysrqd\17\376u\0\
\5sieve\20\136t\0\
\4epmd\21\21t\0\
\4epmd\21\21u\0\
\6remctl\21\25t\0\
\6remctl\21\25u\0\
\11f5-iquery\21\1t\0\
\11f5-iquery\21\1u\0\
\3iax\21\331t\0\
\3iax\21\331u\0\
\3mtn\22\123t\0\
\3mtn\22\123u\0\
\13radmin-port\23\43t\0\
\13radmin-port\23\43u\0\
\3rfe\23\212u\0\
\3rfe\23\212t\0\
\4mmcc\23\272t\0\
\4mmcc\23\272u\0\
\3sip\23\304t\0\
\3sip\23\304u\0\
\7sip-tls\23\305t\0\
\7sip-tls\23\305u\0\
\3aol\24\106t\0\
\3aol\24\106u\0\
\13xmpp-client\24\146t\1\15jabber-client\
\13xmpp-client\24\146u\1\15jabber-client\
\13xmpp-server\24\225t\1\15jabber-server\
\13xmpp-server\24\225u\1\15jabber-server\
\10cfengine\24\274t\0\
\10cfengine\24\274u\0\
\4mdns\24\351t\0\
\4mdns\24\351u\0\
\12postgresql\25\70t\1\10postgres\
\12postgresql\25\70u\1\10postgres\
\7freeciv\25\264t\1\4rptp\
\7freeciv\25\264u\0\
\4amqp\26\50t\0\
\4amqp\26\50u\0\
\3ggz\26\70t\0\
\3ggz\26\70u\0\
\3x11\27\160t\1\5x11-0\
\3x11\27\160u\1\5x11-0\
\5x11-1\27\161t\0\
\5x11-1\27\161u\0\
\5x11-2\27\162t\0\
\5x11-2\27\162u\0\
\5x11-3\27\163t\0\
\5x11-3\27\163u\0\
\5x11-4\27\164t\0\
\5x11-4\27\164u\0\
\5x11-5\27\165t\0\
\5x11-5\27\165u\0\
\5x11-6\27\166t\0\
\5x11-6\27\166u\0\
\5x11-7\27\167t\0\
\5x11-7\27\167u\0\
\14gnutella-svc\30\312t\0\
\14gnutella-svc\30\312u\0\
\14gnutella-rtr\30\313t\0\
\14gnutella-rtr\30\313u\0\
\13sge-qmaster\31\54t\1\13sge_qmaster\
\13sge-qmaster\31\54u\1\13sge_qmaster\
\11sge-execd\31\55t\1\11sge_execd\
\11sge-execd\31\55u\1\11sge_execd\
\13mysql-proxy\31\56t\0\
\13mysql-proxy\31\56u\0\
\17afs3-fileserver\33\130t\1\3bbs\
\17afs3-fileserver\33\130u\1\3bbs\
\15afs3-callback\33\131t\0\
\15afs3-callback\33\131u\0\
\15afs3-prserver\33\132t\0\
\15afs3-prserver\33\132u\0\
\15afs3-vlserver\33\133t\0\
\15afs3-vlserver\33\133u\0\
\15afs3-kaserver\33\134t\0\
\15afs3-kaserver\33\134u\0\
\13afs3-volser\33\135t\0\
\13afs3-volser\33\135u\0\
\13afs3-errors\33\136t\0\
\13afs3-errors\33\136u\0\
\10afs3-bos\33\137t\0\
\10afs3-bos\33\137u\0\
\13afs3-update\33\140t\0\
\13afs3-update\33\140u\0\
\13afs3-rmtsys\33\141t\0\
\13afs3-rmtsys\33\141u\0\
\14font-service\33\274t\1\3xfs\
\14font-service\33\274u\1\3xfs\
\10http-alt\37\220t\1\10webcache\
\10http-alt\37\220u\0\
\12bacula-dir\43\215t\0\
\12bacula-dir\43\215u\0\
\11bacula-fd\43\216t\0\
\11bacula-fd\43\216u\0\
\11bacula-sd\43\217t\0\
\11bacula-sd\43\217u\0\
\5xmms2\45\303t\0\
\5xmms2\45\303u\0\
\3nbd\52\71t\0\
\14zabbix-agent\47\102t\0\
\14zabbix-agent\47\102u\0\
\16zabbix-trapper\47\103t\0\
\16zabbix-trapper\47\103u\0\
\6amanda\47\140t\0\
\6amanda\47\140u\0\
\3hkp\54\153t\0\
\3hkp\54\153u\0\
\4bprd\65\230t\0\
\4bprd\65\230u\0\
\5bpdbm\65\231t\0\
\5bpdbm\65\231u\0\
\13bpjava-msvc\65\232t\0\
\13bpjava-msvc\65\232u\0\
\5vnetd\65\234t\0\
\5vnetd\65\234u\0\
\4bpcd\65\326t\0\
\4bpcd\65\326u\0\
\6vopied\65\327t\0\
\6vopied\65\327u\0\
\4dcap\126\155t\0\
\7gsidcap\126\160t\0\
\4wnn6\127\1t\0\
\4wnn6\127\1u\0\
\11kerberos4\2\356u\2\13kerberos-iv\3kdc\
\11kerberos4\2\356t\2\13kerberos-iv\3kdc\
\17kerberos-master\2\357u\1\17kerberos_master\
\17kerberos-master\2\357t\0\
\15passwd-server\2\360u\1\15passwd_server\
\10krb-prop\2\362t\3\10krb_prop\11krb5_prop\5hprop\
\11krbupdate\2\370t\1\4kreg\
\4swat\3\205t\0\
\4kpop\4\125t\0\
\5knetd\10\5t\0\
\12zephyr-srv\10\66u\0\
\12zephyr-clt\10\67u\0\
\11zephyr-hm\10\70u\0\
\7eklogin\10\71t\0\
\2kx\10\77t\0\
\5iprop\10\111t\0\
\12supfilesrv\3\147t\0\
\12supfiledbg\4\147t\0\
\11linuxconf\0\142t\0\
\10poppassd\0\152t\0\
\10poppassd\0\152u\0\
\5ssmtp\1\321t\1\5smtps\
\10moira-db\3\7t\1\10moira_db\
\14moira-update\3\11t\1\14moira_update\
\12moira-ureg\3\13u\1\12moira_ureg\
\5spamd\3\17t\0\
\5omirr\3\50t\1\6omirrd\
\5omirr\3\50u\1\6omirrd\
\7customs\3\351t\0\
\7customs\3\351u\0\
\7skkserv\4\232t\0\
\7predict\4\272u\0\
\6rmtcfg\4\324t\0\
\5wipld\5\24t\0\
\4xtel\5\41t\0\
\5xtelw\5\42t\0\
\7support\5\371t\0\
\7cfinger\7\323t\0\
\4frox\10\111t\0\
\10ninstall\10\146t\0\
\10ninstall\10\146u\0\
\10zebrasrv\12\50t\0\
\5zebra\12\51t\0\
\4ripd\12\52t\0\
\6ripngd\12\53t\0\
\5ospfd\12\54t\0\
\4bgpd\12\55t\0\
\6ospf6d\12\56t\0\
\7ospfapi\12\57t\0\
\5isisd\12\60t\0\
\10afbackup\13\254t\0\
\10afbackup\13\254u\0\
\11afmbackup\13\255t\0\
\11afmbackup\13\255u\0\
\5xtell\20\200t\0\
\3fax\21\315t\0\
\7hylafax\21\317t\0\
\7distmp3\21\370t\0\
\5munin\23\125t\1\4lrrd\
\13enbd-cstatd\23\273t\0\
\13enbd-sstatd\23\274t\0\
\4pcrd\24\37t\0\
\6noclog\24\352t\0\
\6noclog\24\352u\0\
\7hostmon\24\353t\0\
\7hostmon\24\353u\0\
\5rplay\25\263u\0\
\4nrpe\26\42t\0\
\4nsca\26\43t\0\
\4mrtd\26\52t\0\
\6bgpsim\26\53t\0\
\5canna\26\60t\0\
\11sane-port\31\246t\2\4sane\5saned\
\4ircd\32\13t\0\
\10zope-ftp\37\125t\0\
\6tproxy\37\221t\0\
\7omniorb\37\230t\0\
\7omniorb\37\230u\0\
\20clc-build-daemon\43\36t\0\
\6xinetd\43\212t\0\
\13mandelspawn\44\217u\1\12mandelbrot\
\3git\44\312t\0\
\4zope\45\311t\0\
\6webmin\47\20t\0\
\7kamanda\47\141t\0\
\7kamanda\47\141u\0\
\11amandaidx\47\142t\0\
\11amidxtape\47\143t\0\
\5smsqp\53\301t\0\
\5smsqp\53\301u\0\
\6xpilot\73\361t\0\
\6xpilot\73\361u\0\
\10sgi-cmsd\102\151u\0\
\10sgi-crsd\102\152u\0\
\7sgi-gcd\102\153u\0\
\7sgi-cad\102\154t\0\
\7isdnlog\116\53t\0\
\7isdnlog\116\53u\0\
\5vboxd\116\54t\0\
\5vboxd\116\54u\0\
\5binkp\137\352t\0\
\3asp\152\356t\0\
\3asp\152\356u\0\
\6csync2\170\221t\0\
\11dircproxy\336\250t\0\
\5tfido\353\21t\0\
\4fido\353\23t\0\
\0";


"""

```