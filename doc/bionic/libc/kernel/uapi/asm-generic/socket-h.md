Response:
Let's break down the thought process for answering the request about `bionic/libc/kernel/uapi/asm-generic/socket.handroid`.

**1. Understanding the Nature of the File:**

The first and most crucial step is recognizing what kind of file this is. The header comment is explicit: "This file is auto-generated. Modifications will be lost."  This immediately tells us:

* **It's not meant to be edited directly.**  It's a derived artifact.
* **Its content reflects a more fundamental source of truth.**  Likely a Linux kernel header.
* **Its primary purpose is to provide definitions.** Specifically, constant definitions related to sockets.

The path also gives significant clues: `bionic/libc/kernel/uapi/asm-generic/`. This indicates:

* **`bionic`:**  It's part of Android's core C library.
* **`libc`:**  Confirms it's a C library component.
* **`kernel`:**  This interacts with the Linux kernel.
* **`uapi`:** User-space API. These are definitions exposed to applications.
* **`asm-generic`:**  Architecturally neutral definitions.

**2. Identifying the Core Function:**

Given that the file contains `#define` statements, the core function is to define symbolic constants. These constants represent socket options and levels used with system calls like `getsockopt` and `setsockopt`.

**3. Linking to Android Functionality:**

Since bionic is Android's C library, any functionality defined here is inherently related to Android. The key is *how* it's used. Sockets are fundamental to networking. Therefore, any Android app or system service that uses network communication (which is virtually everything) will indirectly rely on these definitions.

**4. Explaining Libc Function Implementation:**

The request asks for the implementation of *libc functions*. This is a trick question (or requires careful interpretation). This specific file *doesn't contain libc function implementations*. It contains *definitions used by* libc functions. The libc functions themselves (like `socket()`, `bind()`, `listen()`, `connect()`, `getsockopt()`, `setsockopt()`) are implemented in other parts of bionic.

The answer needs to clarify this distinction. It should explain that this file provides the *names* and *values* for socket options, while the *implementation* of how these options are handled resides within the kernel and the socket-related libc functions.

**5. Addressing Dynamic Linker Aspects:**

Again, this file doesn't directly involve the dynamic linker. The linker's job is to resolve symbols and load shared libraries. While socket-related functions are part of libc (a shared library), this header file itself doesn't trigger linker behavior. The answer needs to clarify this and explain when the dynamic linker *does* become involved (when loading apps or libraries that use socket functions). Providing a sample `so` layout and linking process example in the context of networking functions would be appropriate here, even though this specific header doesn't directly cause it.

**6. Considering Logical Reasoning, Assumptions, and Input/Output:**

The "logical reasoning" here is relatively straightforward:  The `#define` statements map symbolic names to integer values. A reasonable assumption is that these values are consistent with the underlying Linux kernel.

A simple input/output scenario could be: An application tries to set the `SO_REUSEADDR` option. The compiler uses the definition from this header file (value `2`). The `setsockopt` system call in the kernel receives this value and acts accordingly.

**7. Identifying Common Usage Errors:**

Common errors revolve around using incorrect option values or trying to set options on inappropriate socket types or at the wrong time. Examples like setting `SO_REUSEADDR` on a client socket (less impactful) versus a server socket (intended use) are good. Incorrectly setting buffer sizes or timeout values are also common mistakes.

**8. Tracing the Path from Android Framework/NDK:**

This is a key part of the request. The path involves several layers:

* **NDK:** Developers using the NDK directly use standard C socket functions. The NDK's libc headers include this file (or a similar kernel header).
* **Android Framework (Java):** When Java code uses `java.net.Socket`, `ServerSocket`, etc., these classes internally use native code (often in the `libjavacrypto.so` or other networking-related libraries) that ultimately calls the same libc socket functions.
* **System Services:** Many Android system services rely on network communication and thus use sockets.

The Frida hook example should target a relevant libc function like `setsockopt` to demonstrate how to observe the use of these constants.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe I should explain how `getsockopt` and `setsockopt` work internally.
* **Correction:** This file *only* provides the *definitions*. The internal workings of those system calls are beyond the scope of this specific file. Focus on the definitions and their purpose.

* **Initial thought:**  The dynamic linker isn't really relevant here.
* **Refinement:** While this header *itself* doesn't trigger the linker, the *functions that use these definitions* are part of shared libraries. So, explain the linker's role in that broader context, even if this specific file isn't the direct cause.

By following these steps and continually refining the understanding of the file's role within the larger Android ecosystem, a comprehensive and accurate answer can be constructed. The key is to distinguish between the definitions provided by this header and the implementation of the functions that utilize those definitions.
这是一个定义 Linux 内核中通用 socket 选项的头文件，被 Android 的 Bionic C 库使用。它本身并不包含可执行代码或函数实现，而是定义了一些常量，这些常量用于与 socket 相关的系统调用，例如 `setsockopt` 和 `getsockopt`。

**它的功能：**

这个文件的核心功能是定义了一系列宏，这些宏代表了不同的 socket 选项和协议层。这些宏在用户空间程序中被用来指定想要配置或查询的 socket 行为。

具体来说，它定义了：

* **Socket 级别 (SOL_SOCKET):**  表示这些选项是应用于 socket 层本身的。
* **Socket 选项 (SO_XXX):**  各种可以设置或获取的 socket 属性，例如：
    * **通用选项:** `SO_DEBUG`, `SO_REUSEADDR`, `SO_TYPE`, `SO_ERROR`, `SO_DONTROUTE`, `SO_BROADCAST`, `SO_SNDBUF`, `SO_RCVBUF`, `SO_KEEPALIVE`, `SO_LINGER` 等。
    * **安全选项:** `SO_PASSCRED`, `SO_PEERCRED`, `SO_SECURITY_AUTHENTICATION`, `SO_SECURITY_ENCRYPTION_TRANSPORT`, `SO_SECURITY_ENCRYPTION_NETWORK` 等。
    * **过滤选项:** `SO_ATTACH_FILTER`, `SO_DETACH_FILTER`, `SO_ATTACH_BPF`, `SO_DETACH_BPF` 等，用于网络包过滤。
    * **性能选项:** `SO_BUSY_POLL`, `SO_MAX_PACING_RATE` 等。
    * **时间戳选项:** `SO_TIMESTAMP`, `SO_TIMESTAMPNS`, `SO_TIMESTAMPING` 等，用于获取数据包的时间戳。
    * **其他选项:** `SO_BINDTODEVICE`, `SO_PEERNAME`, `SO_ACCEPTCONN`, `SO_MARK`, `SO_PROTOCOL`, `SO_DOMAIN` 等。
* **辅助控制消息类型 (SCM_XXX):**  与 `sendmsg` 和 `recvmsg` 系统调用一起使用的辅助数据类型，例如 `SCM_WIFI_STATUS`, `SCM_TIMESTAMPING_OPT_STATS`。

**与 Android 功能的关系及举例说明：**

由于 Bionic 是 Android 的 C 库，这个文件定义的常量直接被 Android 系统和应用程序使用，用于配置和操作网络 socket。

**举例说明：**

1. **端口复用 (SO_REUSEADDR, SO_REUSEPORT):**  Android 应用程序（例如 HTTP 服务器）在绑定端口时，通常会设置 `SO_REUSEADDR` 选项，允许在 socket 关闭后立即重新绑定该端口，而无需等待操作系统释放。 `SO_REUSEPORT` 则允许多个进程或线程绑定到同一个端口，内核负责负载均衡。
   ```c
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <unistd.h>
   #include <stdio.h>

   int main() {
       int sockfd = socket(AF_INET, SOCK_STREAM, 0);
       if (sockfd == -1) {
           perror("socket");
           return 1;
       }

       int reuse = 1;
       if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
           perror("setsockopt SO_REUSEADDR");
           close(sockfd);
           return 1;
       }

       struct sockaddr_in addr;
       addr.sin_family = AF_INET;
       addr.sin_addr.s_addr = INADDR_ANY;
       addr.sin_port = htons(8080);

       if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
           perror("bind");
           close(sockfd);
           return 1;
       }

       // ... 监听和接受连接 ...

       close(sockfd);
       return 0;
   }
   ```

2. **设置发送和接收缓冲区大小 (SO_SNDBUF, SO_RCVBUF):**  Android 应用可以调整 socket 的发送和接收缓冲区大小，以优化网络性能。例如，对于需要传输大量数据的应用，可以增大缓冲区大小。
   ```c
   #include <sys/socket.h>
   #include <stdio.h>
   #include <unistd.h>

   int main() {
       int sockfd = socket(AF_INET, SOCK_STREAM, 0);
       if (sockfd == -1) {
           perror("socket");
           return 1;
       }

       int send_buf_size = 131072; // 128KB
       if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &send_buf_size, sizeof(send_buf_size)) == -1) {
           perror("setsockopt SO_SNDBUF");
           close(sockfd);
           return 1;
       }

       int recv_buf_size = 131072; // 128KB
       if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &recv_buf_size, sizeof(recv_buf_size)) == -1) {
           perror("setsockopt SO_RCVBUF");
           close(sockfd);
           return 1;
       }

       // ... 连接和通信 ...

       close(sockfd);
       return 0;
   }
   ```

3. **获取错误信息 (SO_ERROR):** 当 socket 操作失败时，可以使用 `getsockopt` 和 `SO_ERROR` 来获取更详细的错误代码。
   ```c
   #include <sys/socket.h>
   #include <stdio.h>
   #include <unistd.h>
   #include <errno.h>

   int main() {
       int sockfd = socket(AF_INET, SOCK_STREAM, 0);
       if (sockfd == -1) {
           perror("socket");
           return 1;
       }

       // 尝试连接到不存在的地址
       struct sockaddr_in addr;
       addr.sin_family = AF_INET;
       addr.sin_addr.s_addr = inet_addr("192.0.2.1"); //  示例：保留的文档 IP 地址
       addr.sin_port = htons(80);

       if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
           if (errno == ECONNREFUSED) {
               printf("Connection refused.\n");
           } else {
               int error;
               socklen_t len = sizeof(error);
               if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == 0) {
                   printf("Connect error: %s\n", strerror(error));
               } else {
                   perror("getsockopt SO_ERROR");
               }
           }
       }

       close(sockfd);
       return 0;
   }
   ```

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个文件中并没有 libc 函数的实现。** 它只是定义了一些常量。这些常量被 libc 中的 socket 相关函数（例如 `socket`, `bind`, `listen`, `connect`, `setsockopt`, `getsockopt`, `send`, `recv`, `sendto`, `recvfrom` 等）使用。

这些 libc 函数的实现通常会调用底层的 Linux 内核系统调用。 例如：

* `socket()`:  会调用 `sys_socket()` 系统调用，在内核中创建一个 socket 文件描述符并分配相应的内核数据结构。
* `bind()`: 会调用 `sys_bind()` 系统调用，将 socket 文件描述符绑定到一个本地地址和端口。
* `setsockopt()`: 会调用 `sys_setsockopt()` 系统调用，根据传入的 `level`（例如 `SOL_SOCKET`）和 `optname`（例如 `SO_REUSEADDR`），修改 socket 相关的内核数据结构。  这个文件中定义的常量 `SO_REUSEADDR` 等会被 `setsockopt` 函数使用，以识别用户想要设置哪个 socket 选项。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的作用是在程序启动时加载共享库，并解析符号引用。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text:
        socket:  // socket 函数的实现代码
            ...
        bind:    // bind 函数的实现代码
            ...
        setsockopt: // setsockopt 函数的实现代码
            ...
        getsockopt: // getsockopt 函数的实现代码
            ...
        // 其他 libc 函数 ...
    .data:
        // 全局变量 ...
    .rodata:
        // 只读数据，例如字符串常量 ...
    .dynsym:
        socket  // 导出符号表，列出可被其他 so 链接的符号
        bind
        setsockopt
        getsockopt
        // ...
    .dynstr:
        "socket"
        "bind"
        "setsockopt"
        "getsockopt"
        // ...
    .rel.dyn:  // 重定位表，用于在加载时修改代码中的地址
        // ...
```

**链接的处理过程:**

1. **应用程序请求使用 socket 功能:**  应用程序代码中调用了 `socket()`, `bind()`, `setsockopt()` 等函数。
2. **编译链接:** 编译器将这些函数调用转换为对外部符号的引用。链接器在链接时会查找这些符号，并将其标记为需要动态链接。
3. **程序加载:** 当 Android 启动应用程序时，`linker64` (或 `linker`) 会被调用。
4. **加载共享库:** `linker64` 根据应用程序的依赖关系，加载 `libc.so` (其中包含了 `socket`, `bind`, `setsockopt` 等函数的实现)。
5. **符号解析 (重定位):** `linker64` 会遍历应用程序和 `libc.so` 的重定位表。对于应用程序中对 `socket` 等符号的引用，`linker64` 会在 `libc.so` 的 `.dynsym` 段中找到这些符号的地址，并更新应用程序代码中的相应地址，使其指向 `libc.so` 中 `socket` 函数的实际代码。

**假设输入与输出 (针对 `setsockopt` 函数):**

假设输入：

* `sockfd`: 一个已经创建的 socket 文件描述符。
* `level`: `SOL_SOCKET` (值为 1，由该头文件定义)。
* `optname`: `SO_REUSEADDR` (值为 2，由该头文件定义)。
* `optval`: 指向整数 1 的指针 (表示启用该选项)。
* `optlen`: `sizeof(int)`。

逻辑推理：

`setsockopt` 函数会根据 `level` 和 `optname` 确定要修改的 socket 选项。在这个例子中，它会找到 `SOL_SOCKET` 层的 `SO_REUSEADDR` 选项，并将与该 socket 关联的内核数据结构中表示 `SO_REUSEADDR` 状态的标志设置为 `optval` 指向的值 (即 1)。

输出：

* 如果操作成功，`setsockopt` 返回 0。
* 如果操作失败（例如，socket 无效，或者权限不足），`setsockopt` 返回 -1，并设置 `errno` 来指示错误原因。

**用户或者编程常见的使用错误：**

1. **使用错误的 `optname` 值:**  传递了未定义的或错误的 `SO_XXX` 常量值给 `setsockopt` 或 `getsockopt`。
2. **在错误的 socket 状态下设置选项:**  某些选项只能在特定的 socket 状态下设置。例如，某些选项需要在 `bind` 或 `connect` 之前设置。
3. **`optval` 和 `optlen` 不匹配:**  传递给 `setsockopt` 或 `getsockopt` 的 `optval` 指针指向的数据类型和 `optlen` 指定的长度不一致。
4. **权限问题:**  某些 socket 选项需要 root 权限才能设置。
5. **误解选项的含义:**  不理解每个选项的具体作用，导致设置了不期望的行为。例如，错误地设置 `SO_LINGER` 可能导致程序在 `close` 时阻塞。

**Android Framework 或 NDK 是如何一步步的到达这里:**

1. **Android Framework (Java):**
   * 当 Java 代码中使用 `java.net.Socket`, `java.net.ServerSocket` 等类进行网络编程时，这些 Java 类的方法会通过 JNI (Java Native Interface) 调用 Android 平台的 native 代码。
   * 这些 native 代码通常位于 `libjavacrypto.so`, `libnetd_client.so` 等共享库中。
   * 这些 native 代码最终会调用 Bionic 提供的 socket 相关的 C 函数，例如 `socket()`, `bind()`, `setsockopt()` 等。
   * 在调用 `setsockopt()` 时，会使用这个头文件中定义的 `SOL_SOCKET` 和 `SO_XXX` 常量。

2. **Android NDK (C/C++):**
   * NDK 开发者可以直接使用 Bionic 提供的标准 C 库函数进行网络编程。
   * 在 NDK 代码中，可以直接包含 `<sys/socket.h>` 头文件，该头文件（或其包含的头文件）会包含 `asm-generic/socket.h`，从而可以使用这里定义的 `SOL_SOCKET` 和 `SO_XXX` 常量。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `setsockopt` 函数来观察 Android 应用或 framework 如何使用这些 socket 选项。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

package_name = "com.example.myapp" # 替换为目标应用包名

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[*] Process '{package_name}' not found. Make sure the app is running.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "setsockopt"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var level = args[1].toInt32();
        var optname = args[2].toInt32();
        var optval = args[3];
        var optlen = args[4].toInt32();

        var level_str = "";
        if (level == 1) {
            level_str = "SOL_SOCKET";
        } else {
            level_str = level;
        }

        var optname_str = "";
        if (level == 1) {
            if (optname == 1) optname_str = "SO_DEBUG";
            else if (optname == 2) optname_str = "SO_REUSEADDR";
            else if (optname == 3) optname_str = "SO_TYPE";
            // ... 添加其他 SO_XXX 的映射 ...
            else optname_str = optname;
        } else {
            optname_str = optname;
        }

        var optval_str = "";
        if (optlen == 4) {
            optval_str = ptr(optval).readInt();
        } else {
            optval_str = "size: " + optlen;
        }

        send({
            "type": "setsockopt",
            "sockfd": sockfd,
            "level": level_str,
            "optname": optname_str,
            "optval": optval_str,
            "optlen": optlen
        });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到目标 Android 设备上的目标应用程序进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "setsockopt"), ...)`:**  Hook `libc.so` 中的 `setsockopt` 函数。
3. **`onEnter: function(args)`:**  在 `setsockopt` 函数被调用时执行。
4. **`args`:**  包含传递给 `setsockopt` 函数的参数。
5. **`args[0]` (sockfd), `args[1]` (level), `args[2]` (optname), `args[3]` (optval), `args[4]` (optlen)`:** 获取 `setsockopt` 的参数。
6. **代码中将数字常量映射到字符串:**  例如，如果 `level` 是 1，则将其映射为 "SOL_SOCKET"，如果 `optname` 是 2，并且 `level` 是 1，则将其映射为 "SO_REUSEADDR"。你需要根据这个文件中的定义添加更多的映射。
7. **读取 `optval` 的值:**  根据 `optlen` 的大小读取 `optval` 指向的数据。
8. **`send({...})`:**  通过 Frida 的 `send` 函数将捕获到的信息发送回 Python 脚本。
9. **Python 脚本的 `on_message` 函数:** 接收并打印来自 Frida 脚本的消息，显示 `setsockopt` 的调用信息，包括 socket 文件描述符、level、optname 和 optval。

通过运行这个 Frida 脚本，你可以观察到目标应用程序在执行网络操作时，具体调用了 `setsockopt` 函数来设置哪些 socket 选项，以及传递了什么值。这有助于理解 Android framework 或 NDK 如何使用这些底层的 socket 常量。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-generic/socket.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef __ASM_GENERIC_SOCKET_H
#define __ASM_GENERIC_SOCKET_H
#include <linux/posix_types.h>
#include <asm/sockios.h>
#define SOL_SOCKET 1
#define SO_DEBUG 1
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_DONTROUTE 5
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_SNDBUFFORCE 32
#define SO_RCVBUFFORCE 33
#define SO_KEEPALIVE 9
#define SO_OOBINLINE 10
#define SO_NO_CHECK 11
#define SO_PRIORITY 12
#define SO_LINGER 13
#define SO_BSDCOMPAT 14
#define SO_REUSEPORT 15
#ifndef SO_PASSCRED
#define SO_PASSCRED 16
#define SO_PEERCRED 17
#define SO_RCVLOWAT 18
#define SO_SNDLOWAT 19
#define SO_RCVTIMEO_OLD 20
#define SO_SNDTIMEO_OLD 21
#endif
#define SO_SECURITY_AUTHENTICATION 22
#define SO_SECURITY_ENCRYPTION_TRANSPORT 23
#define SO_SECURITY_ENCRYPTION_NETWORK 24
#define SO_BINDTODEVICE 25
#define SO_ATTACH_FILTER 26
#define SO_DETACH_FILTER 27
#define SO_GET_FILTER SO_ATTACH_FILTER
#define SO_PEERNAME 28
#define SO_ACCEPTCONN 30
#define SO_PEERSEC 31
#define SO_PASSSEC 34
#define SO_MARK 36
#define SO_PROTOCOL 38
#define SO_DOMAIN 39
#define SO_RXQ_OVFL 40
#define SO_WIFI_STATUS 41
#define SCM_WIFI_STATUS SO_WIFI_STATUS
#define SO_PEEK_OFF 42
#define SO_NOFCS 43
#define SO_LOCK_FILTER 44
#define SO_SELECT_ERR_QUEUE 45
#define SO_BUSY_POLL 46
#define SO_MAX_PACING_RATE 47
#define SO_BPF_EXTENSIONS 48
#define SO_INCOMING_CPU 49
#define SO_ATTACH_BPF 50
#define SO_DETACH_BPF SO_DETACH_FILTER
#define SO_ATTACH_REUSEPORT_CBPF 51
#define SO_ATTACH_REUSEPORT_EBPF 52
#define SO_CNX_ADVICE 53
#define SCM_TIMESTAMPING_OPT_STATS 54
#define SO_MEMINFO 55
#define SO_INCOMING_NAPI_ID 56
#define SO_COOKIE 57
#define SCM_TIMESTAMPING_PKTINFO 58
#define SO_PEERGROUPS 59
#define SO_ZEROCOPY 60
#define SO_TXTIME 61
#define SCM_TXTIME SO_TXTIME
#define SO_BINDTOIFINDEX 62
#define SO_TIMESTAMP_OLD 29
#define SO_TIMESTAMPNS_OLD 35
#define SO_TIMESTAMPING_OLD 37
#define SO_TIMESTAMP_NEW 63
#define SO_TIMESTAMPNS_NEW 64
#define SO_TIMESTAMPING_NEW 65
#define SO_RCVTIMEO_NEW 66
#define SO_SNDTIMEO_NEW 67
#define SO_DETACH_REUSEPORT_BPF 68
#define SO_PREFER_BUSY_POLL 69
#define SO_BUSY_POLL_BUDGET 70
#define SO_NETNS_COOKIE 71
#define SO_BUF_LOCK 72
#define SO_RESERVE_MEM 73
#define SO_TXREHASH 74
#define SO_RCVMARK 75
#define SO_PASSPIDFD 76
#define SO_PEERPIDFD 77
#define SO_DEVMEM_LINEAR 78
#define SCM_DEVMEM_LINEAR SO_DEVMEM_LINEAR
#define SO_DEVMEM_DMABUF 79
#define SCM_DEVMEM_DMABUF SO_DEVMEM_DMABUF
#define SO_DEVMEM_DONTNEED 80
#if __BITS_PER_LONG == 64 || defined(__x86_64__) && defined(__ILP32__)
#define SO_TIMESTAMP SO_TIMESTAMP_OLD
#define SO_TIMESTAMPNS SO_TIMESTAMPNS_OLD
#define SO_TIMESTAMPING SO_TIMESTAMPING_OLD
#define SO_RCVTIMEO SO_RCVTIMEO_OLD
#define SO_SNDTIMEO SO_SNDTIMEO_OLD
#else
#define SO_TIMESTAMP (sizeof(time_t) == sizeof(__kernel_long_t) ? SO_TIMESTAMP_OLD : SO_TIMESTAMP_NEW)
#define SO_TIMESTAMPNS (sizeof(time_t) == sizeof(__kernel_long_t) ? SO_TIMESTAMPNS_OLD : SO_TIMESTAMPNS_NEW)
#define SO_TIMESTAMPING (sizeof(time_t) == sizeof(__kernel_long_t) ? SO_TIMESTAMPING_OLD : SO_TIMESTAMPING_NEW)
#define SO_RCVTIMEO (sizeof(time_t) == sizeof(__kernel_long_t) ? SO_RCVTIMEO_OLD : SO_RCVTIMEO_NEW)
#define SO_SNDTIMEO (sizeof(time_t) == sizeof(__kernel_long_t) ? SO_SNDTIMEO_OLD : SO_SNDTIMEO_NEW)
#endif
#define SCM_TIMESTAMP SO_TIMESTAMP
#define SCM_TIMESTAMPNS SO_TIMESTAMPNS
#define SCM_TIMESTAMPING SO_TIMESTAMPING
#endif
```