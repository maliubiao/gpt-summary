Response:
Let's break down the thought process for analyzing the provided C header file (`tcp.h`).

**1. Understanding the Context:**

The first step is to acknowledge the provided context: "目录为bionic/libc/kernel/uapi/linux/tcp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker." This immediately tells us several crucial things:

* **Location:**  The file is part of Android's low-level system libraries, specifically related to kernel-level TCP interactions. The `uapi` directory signifies user-space facing definitions that match kernel structures.
* **Purpose:**  It defines structures, enums, and constants related to TCP (Transmission Control Protocol) as seen from the user-space perspective within Android.
* **Language:** It's C header code.
* **Relevance to Android:**  Since it's part of Bionic, it's directly used by Android's networking stack.

**2. Initial Scan and Categorization:**

Next, I'd scan the file for high-level structural elements. I'd notice:

* **Includes:**  `<bits/tcphdr.h>`, `<linux/types.h>`, `<asm/byteorder.h>`, `<linux/socket.h>`. These hint at dependencies on lower-level network and system definitions.
* **`union tcp_word_hdr`:** This is a way to access the TCP header as either a structure or an array of 32-bit words. This likely allows for efficient bit manipulation of TCP flags.
* **`enum`s:**  `TCP_FLAG_*`, various `TCP_*` option enums, `tcp_fastopen_client_fail`, `tcp_ca_state`. These define symbolic names for TCP flags, socket options, and TCP state machine states.
* **`#define`s:** Many constants related to TCP flags, options, and default values.
* **`struct`s:** `tcp_repair_opt`, `tcp_repair_window`, `tcp_info`, `tcp_md5sig`, `tcp_diag_md5sig`, `tcp_ao_*`, `tcp_zerocopy_receive`. These are data structures used to represent TCP-related information and configuration.

Based on this initial scan, I can categorize the file's content:

* **TCP Header Manipulation:** `union tcp_word_hdr`, `tcp_flag_word`, `TCP_FLAG_*`.
* **TCP Socket Options:** `TCP_NODELAY`, `TCP_MAXSEG`, etc.
* **TCP Repair and Queueing:** `TCP_REPAIR_*`, `tcp_repair_opt`, `tcp_repair_window`, `TCP_NO_QUEUE`, etc.
* **TCP Fast Open:** `TCP_FASTOPEN_*`, `tcp_fastopen_client_fail`.
* **TCP Information (via `getsockopt`)**: `tcp_info`, `TCPI_OPT_*`, `tcp_ca_state`, `TCP_NLA_*`.
* **TCP MD5 Signature (Authentication):** `TCP_MD5SIG_*`, `tcp_md5sig`, `tcp_diag_md5sig`.
* **TCP Authentication Option (TCP-AO):** `TCP_AO_*`, `tcp_ao_*`.
* **TCP Zero-Copy Receive:** `TCP_ZEROCOPY_RECEIVE`.

**3. Detailed Analysis of Key Elements:**

Now, I would dive into the more significant parts:

* **TCP Flags:** The `TCP_FLAG_*` enums and the `tcp_flag_word` macro are crucial for understanding how TCP control bits are accessed and manipulated. The bitwise OR nature of these flags is important.
* **TCP Socket Options:**  I'd recognize these as arguments to `setsockopt()` and `getsockopt()` system calls. I'd think about how each option modifies TCP behavior (e.g., `TCP_NODELAY` for disabling Nagle's algorithm).
* **`tcp_info` struct:** This is a critical structure that provides a wealth of information about the state of a TCP connection. I'd mentally group the members into categories like congestion control, round-trip time, buffer sizes, and packet counts.
* **TCP MD5 Signature and TCP-AO:** These are security features for authenticating TCP connections. I'd note the different structures for setting and retrieving information.
* **TCP Zero-Copy Receive:** This is a performance optimization technique. I'd pay attention to the fields related to memory addresses and lengths.

**4. Connecting to Android Functionality:**

With an understanding of the elements, I'd start connecting them to how they are used in Android:

* **Network Stack:**  The entire file is fundamental to Android's network stack. Any application using TCP sockets indirectly relies on these definitions.
* **`Socket` API:**  Android's Java `Socket` and `ServerSocket` classes, as well as the NDK's socket functions, ultimately interact with the kernel through these definitions.
* **`ConnectivityManager`:** This Android system service manages network connections and would use information related to TCP status.
* **VPN Apps:** VPN applications that create virtual network interfaces would heavily rely on low-level networking concepts defined here.

**5. Dynamic Linker Considerations (Instruction Interpretation):**

The prompt specifically asks about the dynamic linker. While this header file itself doesn't directly *contain* dynamic linking logic, it *is used by* code that *is* dynamically linked. My thinking would be:

* **Where is this header used?** It's included in Bionic's libc, which is a shared library.
* **How does the dynamic linker play a role?** When an Android app (or a native library) uses socket functions (like `connect`, `send`, `recv`), the code for those functions resides in libc.so. The dynamic linker is responsible for loading libc.so into the process's memory space and resolving the symbols.

For the SO layout example, I'd imagine a simplified view of an app's memory:

```
[Memory Region for App Executable]
[Memory Region for libother.so]
[Memory Region for libc.so]  <-- tcp.h is relevant here
   - .text (code for socket functions)
   - .data (global variables)
   - .rodata (constants, including strings used by socket functions)
   - .dynamic (dynamic linking information)
   - .dynsym (symbol table)
   - .rel.dyn (relocations)
```

The linking process involves:

1. **Loading `libc.so`:** The dynamic linker finds `libc.so` based on the app's dependencies.
2. **Symbol Resolution:** When the app calls a socket function (e.g., `connect`), the linker looks up the address of that function within `libc.so`'s symbol table.
3. **Relocation:** If the `connect` function in `libc.so` refers to any global variables or constants (which might be defined using types from `tcp.h`), the linker updates those addresses in the loaded `libc.so` to match the process's memory layout.

**6. Frida Hooking (Instruction Interpretation):**

For Frida, I'd consider which functions that *use* these definitions would be interesting to hook. The core socket system calls are the most relevant.

* **`connect`:** To see when a TCP connection is being established.
* **`send`/`sendto`:** To examine the TCP flags and options being used for outgoing data.
* **`recv`/`recvfrom`:** To observe incoming data and potentially TCP flags.
* **`getsockopt`:** To retrieve TCP information (using `TCP_INFO`).
* **`setsockopt`:** To see how TCP options are being configured.

The Frida examples would target these functions and potentially inspect arguments related to socket options or the `tcp_info` structure.

**7. User/Programming Errors:**

I'd think about common mistakes developers make when working with TCP sockets:

* **Incorrectly setting socket options:**  Setting contradictory options or using inappropriate values.
* **Not handling errors:** Ignoring return values from socket functions.
* **Buffer overflows:** When sending or receiving data.
* **Incorrect byte order:**  Forgetting to use network byte order for multi-byte fields.

**8. Logical Inferences and Assumptions:**

Throughout the analysis, there are assumptions:

* **Endianness:** The code uses `__constant_cpu_to_be32`, indicating awareness of byte order and the need for network byte order (big-endian).
* **Kernel Version Compatibility:**  The `uapi` directory suggests that these definitions are intended to match the kernel's TCP implementation. Incompatibilities could arise if the kernel version doesn't align with the user-space library.

By following these steps, combining general knowledge of networking and system programming with careful examination of the header file's contents, I can arrive at a comprehensive explanation like the example provided in the initial prompt. The iterative process of scanning, categorizing, detailed analysis, and connecting to the broader context is key.
```chinese
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/tcp.h` 这个文件。

**文件功能概览**

这个头文件 (`tcp.h`) 定义了用户空间程序可以用来与 Linux 内核 TCP/IP 协议栈交互的常量、枚举、结构体和宏。 它的主要功能是：

1. **定义 TCP 协议的各种标志位 (Flags):**  例如 SYN, ACK, FIN 等，用于控制 TCP 连接的不同阶段。
2. **定义 TCP Socket 选项 (Options):**  这些选项可以通过 `setsockopt` 和 `getsockopt` 系统调用来配置和获取 TCP 连接的行为，例如 `TCP_NODELAY`，`TCP_KEEPALIVE` 等（尽管这里只列出了一部分与 TCP 直接相关的选项，实际使用中会包含更多）。
3. **定义与 TCP 连接状态和信息相关的结构体:**  例如 `tcp_info` 用于获取连接的详细信息，`tcp_md5sig` 和 `tcp_ao_*` 用于 TCP 认证。
4. **提供与 TCP 修复 (Repair) 和队列管理相关的定义:** 例如用于在连接中断后恢复连接状态的结构体。
5. **定义与 TCP Fast Open 相关的常量:**  用于加速 TCP 连接建立。
6. **定义与 TCP Zero-Copy 接收相关的结构体:**  用于提高接收数据效率。

**与 Android 功能的关系及举例**

这个文件对于 Android 的网络功能至关重要，因为它定义了用户空间程序与内核 TCP 协议栈交互的基础。 几乎所有涉及网络通信的 Android 功能都间接地依赖于这些定义。

**举例说明:**

* **网络请求 (HTTP/HTTPS):** 当 Android 应用发起一个 HTTP 请求时，底层会使用 TCP 协议建立连接。应用不需要直接操作这些底层的 TCP 标志位，但是 Android Framework (例如 `java.net.Socket`, `HttpURLConnection`, `OkHttp`) 或者 NDK 中的 Socket API 会使用这里定义的常量和结构体来配置和管理 TCP 连接。 例如，`TCP_NODELAY` 选项可以用于禁用 Nagle 算法，减少小数据包的延迟，这对于实时性要求高的应用（例如游戏）非常重要。
* **Socket 编程:**  开发者使用 NDK 进行底层网络编程时，会直接使用到这些定义。例如，使用 `setsockopt` 设置 `TCP_KEEPIDLE`，`TCP_KEEPINTVL` 和 `TCP_KEEPCNT` 来配置 TCP Keep-Alive 机制，以检测死连接。
* **VPN 应用:** VPN 应用需要创建和管理网络连接，它们会直接操作 Socket，并可能需要设置各种 TCP 选项来满足特定的需求。

**详细解释 libc 函数的功能实现**

这个头文件本身 **不包含任何 libc 函数的实现**。 它仅仅是定义了一些常量、枚举和结构体，这些定义会被 libc 中的网络相关函数（例如 `socket`, `connect`, `bind`, `listen`, `accept`, `send`, `recv`, `setsockopt`, `getsockopt` 等）使用。

libc 函数的实现通常涉及系统调用 (syscall)。 当一个 libc 函数需要与内核交互时，它会发起一个系统调用，将参数传递给内核，然后内核执行相应的操作。

**举例：`setsockopt` 函数**

`setsockopt` 函数允许用户空间程序设置 socket 的各种选项。 当调用 `setsockopt` 设置一个 TCP 选项时，例如 `TCP_NODELAY`，其内部流程大致如下：

1. **参数校验:** `setsockopt` 函数首先会检查传入的参数是否有效，例如 socket 描述符是否有效，选项名是否是合法的 TCP 选项等。
2. **系统调用:** 如果参数有效，`setsockopt` 会发起一个系统调用 (在 Linux 上通常是 `syscall(__NR_setsockopt, ...)`), 将 socket 描述符、选项级别 (SOL_TCP)、选项名 (例如 `TCP_NODELAY` 的宏定义值) 和选项值传递给内核。
3. **内核处理:**  内核的 TCP 协议栈接收到系统调用后，会根据传入的选项名和值修改对应 socket 的内核数据结构中的相关字段。 例如，设置 `TCP_NODELAY` 会修改一个标志位，使得后续发送数据时不会使用 Nagle 算法。

**涉及 dynamic linker 的功能及处理过程**

这个头文件本身与 dynamic linker 没有直接的功能关联。 但是，使用到这个头文件的 libc 是一个共享库 (`libc.so`)，它的加载和链接是由 dynamic linker 负责的。

**so 布局样本:**

假设一个简单的 Android 应用 `my_app` 使用了网络功能：

```
/system/bin/my_app  (可执行文件)
/system/lib64/libc.so (Bionic C 库)
/system/lib64/libnetd_client.so (Android 网络守护进程客户端库)
/system/lib64/libssl.so (SSL/TLS 库)
...其他库...
```

**链接的处理过程:**

1. **加载可执行文件:** 当 `my_app` 启动时，操作系统首先加载它的可执行文件到内存。
2. **解析依赖:** 可执行文件头包含动态链接信息，指明了它依赖的共享库，例如 `libc.so`。
3. **加载共享库:** Android 的 dynamic linker (`/linker64` 或 `/linker`) 负责加载这些依赖的共享库到进程的地址空间。
4. **符号解析 (Symbol Resolution):** 当 `my_app` 中的代码调用了 `libc.so` 中的函数（例如 `socket`, `connect`），dynamic linker 会负责找到这些函数的实际地址。 这通过查找 `libc.so` 的符号表 (`.dynsym`) 来实现。
5. **重定位 (Relocation):**  共享库中的代码可能包含对其他全局变量或函数的引用。 在加载时，dynamic linker 需要根据库被加载到的实际内存地址，修正这些引用，这个过程称为重定位。

**与 `tcp.h` 的关系:**  `libc.so` 内部的网络相关函数实现中，会包含 `tcp.h` 头文件，使用其中定义的常量和结构体。 因此，虽然 `tcp.h` 本身不参与动态链接过程，但它是被动态链接的库 (`libc.so`) 所使用的。

**逻辑推理，假设输入与输出**

这个头文件主要定义了常量和结构体，更侧重于定义而非逻辑。  没有直接的函数需要推理输入输出。 但是，我们可以想象在使用这些定义的场景下的逻辑。

**假设场景:**  一个应用想要设置 TCP Keep-Alive 选项。

**假设输入:**

* `sockfd`:  一个已创建的 TCP socket 的文件描述符。
* `level`: `SOL_TCP` (表示 TCP 协议层面的选项)。
* `optname`: `TCP_KEEPIDLE`。
* `optval`:  一个整数值，表示空闲多少秒后开始发送 Keep-Alive 探测 (例如 60 秒)。
* `optlen`:  `sizeof(int)`。

**假设输出 (对于 `setsockopt` 系统调用):**

* **成功:** 返回 0。
* **失败:** 返回 -1，并设置 `errno` 指示错误原因（例如 `EBADF` 表示 socket 描述符无效，`EINVAL` 表示选项名无效等）。

**用户或编程常见的使用错误**

1. **使用了错误的选项级别:**  例如，将 TCP 选项传递给 `setsockopt` 时，`level` 参数应该设置为 `SOL_TCP`，而不是 `SOL_SOCKET` 或其他级别。
   ```c
   int keepalive = 1;
   if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
       perror("setsockopt SO_KEEPALIVE failed"); // 正确的，这是 socket 层的 Keep-Alive
   }

   int keepidle = 60;
   if (setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle)) < 0) {
       perror("setsockopt TCP_KEEPIDLE failed"); // 正确的，这是 TCP 层的 Keep-Alive 设置
   }
   ```

2. **传递了错误大小的选项值:**  每个选项都有其预期的数据类型和大小。 例如，`TCP_NODELAY` 的值通常是一个整数 (0 或 1)，如果传递了其他大小的数据，会导致错误。
   ```c
   int nodelay = 1;
   // 错误示例：传递了错误的大小
   // char nodelay_str[] = "1";
   // setsockopt(sockfd, SOL_TCP, TCP_NODELAY, nodelay_str, sizeof(nodelay_str));

   // 正确示例
   setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
   ```

3. **在不合适的时机设置选项:**  某些选项需要在连接建立之前设置，而某些选项可以在连接建立之后设置。  如果在错误的时机设置选项，可能会导致失败或不起作用。

4. **字节序问题:**  虽然这里定义了 `__constant_cpu_to_be32`，表示涉及到字节序转换，但在实际使用 `setsockopt` 和 `getsockopt` 时，对于像整数这样的简单类型，通常不需要手动进行字节序转换。 但是，如果涉及更复杂的结构体，需要注意网络字节序和主机字节序之间的转换。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例**

1. **Android Framework:**
   - 当 Java 代码中使用 `java.net.Socket` 或 `HttpURLConnection` 发起网络请求时，这些 Java 类最终会调用 Android 系统的 native 代码。
   - 这些 native 代码通常在 `libjavacrypto.so`, `libnetd_client.so` 等库中。
   - 这些 native 库会使用 NDK 提供的 socket API（例如 `socket`, `connect`, `setsockopt` 等）。
   - 这些 NDK 函数的实现位于 `libc.so` 中，它们会包含 `bionic/libc/kernel/uapi/linux/tcp.h` 头文件，并使用其中定义的常量和结构体与内核进行交互。

2. **NDK:**
   - 当开发者使用 NDK 进行 socket 编程时，他们会直接调用 `libc.so` 提供的 socket 函数。
   - 这些函数内部同样会包含 `tcp.h`。

**Frida Hook 示例:**

我们可以使用 Frida hook `setsockopt` 系统调用或者 `libc.so` 中的 `setsockopt` 函数来观察 TCP 选项的设置过程。

**Hook `setsockopt` 系统调用:**

```javascript
Interceptor.attach(Module.findExportByName(null, "syscall"), {
  onEnter: function (args) {
    const syscall_number = args[0].toInt32();
    const SYS_SETSOCKOPT = 155; // Linux 上 setsockopt 的系统调用号，可能因架构而异
    if (syscall_number === SYS_SETSOCKOPT) {
      const sockfd = args[1].toInt32();
      const level = args[2].toInt32();
      const optname = args[3].toInt32();
      const optval = args[4];
      const optlen = args[5].toInt32();

      console.log("syscall(SYS_SETSOCKOPT)");
      console.log("  sockfd:", sockfd);
      console.log("  level:", level);
      console.log("  optname:", optname);

      if (level === 6) { // SOL_TCP 的值
        if (optname === 1) { // TCP_NODELAY 的值
          console.log("    TCP_NODELAY:", optval.readInt());
        } else if (optname === 4) { // TCP_KEEPIDLE 的值
          console.log("    TCP_KEEPIDLE:", optval.readInt());
        }
        // 可以根据 optname 的值打印其他 TCP 选项
      }
    }
  },
});
```

**Hook `libc.so` 中的 `setsockopt` 函数:**

```javascript
Interceptor.attach(Module.findExportByName("libc.so", "setsockopt"), {
  onEnter: function (args) {
    const sockfd = args[0].toInt32();
    const level = args[1].toInt32();
    const optname = args[2].toInt32();
    const optval = args[3];
    const optlen = args[4].toInt32();

    console.log("setsockopt");
    console.log("  sockfd:", sockfd);
    console.log("  level:", level);
    console.log("  optname:", optname);

    if (level === 6) { // SOL_TCP 的值
      if (optname === 1) { // TCP_NODELAY 的值
        console.log("    TCP_NODELAY:", optval.readInt());
      } else if (optname === 4) { // TCP_KEEPIDLE 的值
        console.log("    TCP_KEEPIDLE:", optval.readInt());
      }
      // 可以根据 optname 的值打印其他 TCP 选项
    }
  },
});
```

通过这些 Frida hook，我们可以在 Android 应用运行时，观察它如何设置 TCP 选项，从而了解 Android Framework 或 NDK 如何使用这些底层定义。  需要注意的是，系统调用号可能因 Android 版本和架构而异，需要根据具体情况进行调整。  同时，选项名 (`optname`) 的值是宏定义，需要查看 `tcp.h` 文件来确定具体的值。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/tcp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_LINUX_TCP_H
#define _UAPI_LINUX_TCP_H
#include <bits/tcphdr.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>
union tcp_word_hdr {
  struct tcphdr hdr;
  __be32 words[5];
};
#define tcp_flag_word(tp) (((union tcp_word_hdr *) (tp))->words[3])
enum {
  TCP_FLAG_CWR = __constant_cpu_to_be32(0x00800000),
  TCP_FLAG_ECE = __constant_cpu_to_be32(0x00400000),
  TCP_FLAG_URG = __constant_cpu_to_be32(0x00200000),
  TCP_FLAG_ACK = __constant_cpu_to_be32(0x00100000),
  TCP_FLAG_PSH = __constant_cpu_to_be32(0x00080000),
  TCP_FLAG_RST = __constant_cpu_to_be32(0x00040000),
  TCP_FLAG_SYN = __constant_cpu_to_be32(0x00020000),
  TCP_FLAG_FIN = __constant_cpu_to_be32(0x00010000),
  TCP_RESERVED_BITS = __constant_cpu_to_be32(0x0F000000),
  TCP_DATA_OFFSET = __constant_cpu_to_be32(0xF0000000)
};
#define TCP_MSS_DEFAULT 536U
#define TCP_MSS_DESIRED 1220U
#define TCP_NODELAY 1
#define TCP_MAXSEG 2
#define TCP_CORK 3
#define TCP_KEEPIDLE 4
#define TCP_KEEPINTVL 5
#define TCP_KEEPCNT 6
#define TCP_SYNCNT 7
#define TCP_LINGER2 8
#define TCP_DEFER_ACCEPT 9
#define TCP_WINDOW_CLAMP 10
#define TCP_INFO 11
#define TCP_QUICKACK 12
#define TCP_CONGESTION 13
#define TCP_MD5SIG 14
#define TCP_THIN_LINEAR_TIMEOUTS 16
#define TCP_THIN_DUPACK 17
#define TCP_USER_TIMEOUT 18
#define TCP_REPAIR 19
#define TCP_REPAIR_QUEUE 20
#define TCP_QUEUE_SEQ 21
#define TCP_REPAIR_OPTIONS 22
#define TCP_FASTOPEN 23
#define TCP_TIMESTAMP 24
#define TCP_NOTSENT_LOWAT 25
#define TCP_CC_INFO 26
#define TCP_SAVE_SYN 27
#define TCP_SAVED_SYN 28
#define TCP_REPAIR_WINDOW 29
#define TCP_FASTOPEN_CONNECT 30
#define TCP_ULP 31
#define TCP_MD5SIG_EXT 32
#define TCP_FASTOPEN_KEY 33
#define TCP_FASTOPEN_NO_COOKIE 34
#define TCP_ZEROCOPY_RECEIVE 35
#define TCP_INQ 36
#define TCP_CM_INQ TCP_INQ
#define TCP_TX_DELAY 37
#define TCP_AO_ADD_KEY 38
#define TCP_AO_DEL_KEY 39
#define TCP_AO_INFO 40
#define TCP_AO_GET_KEYS 41
#define TCP_AO_REPAIR 42
#define TCP_IS_MPTCP 43
#define TCP_REPAIR_ON 1
#define TCP_REPAIR_OFF 0
#define TCP_REPAIR_OFF_NO_WP - 1
struct tcp_repair_opt {
  __u32 opt_code;
  __u32 opt_val;
};
struct tcp_repair_window {
  __u32 snd_wl1;
  __u32 snd_wnd;
  __u32 max_window;
  __u32 rcv_wnd;
  __u32 rcv_wup;
};
enum {
  TCP_NO_QUEUE,
  TCP_RECV_QUEUE,
  TCP_SEND_QUEUE,
  TCP_QUEUES_NR,
};
enum tcp_fastopen_client_fail {
  TFO_STATUS_UNSPEC,
  TFO_COOKIE_UNAVAILABLE,
  TFO_DATA_NOT_ACKED,
  TFO_SYN_RETRANSMITTED,
};
#define TCPI_OPT_TIMESTAMPS 1
#define TCPI_OPT_SACK 2
#define TCPI_OPT_WSCALE 4
#define TCPI_OPT_ECN 8
#define TCPI_OPT_ECN_SEEN 16
#define TCPI_OPT_SYN_DATA 32
#define TCPI_OPT_USEC_TS 64
enum tcp_ca_state {
  TCP_CA_Open = 0,
#define TCPF_CA_Open (1 << TCP_CA_Open)
  TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1 << TCP_CA_Disorder)
  TCP_CA_CWR = 2,
#define TCPF_CA_CWR (1 << TCP_CA_CWR)
  TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1 << TCP_CA_Recovery)
  TCP_CA_Loss = 4
#define TCPF_CA_Loss (1 << TCP_CA_Loss)
};
struct tcp_info {
  __u8 tcpi_state;
  __u8 tcpi_ca_state;
  __u8 tcpi_retransmits;
  __u8 tcpi_probes;
  __u8 tcpi_backoff;
  __u8 tcpi_options;
  __u8 tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
  __u8 tcpi_delivery_rate_app_limited : 1, tcpi_fastopen_client_fail : 2;
  __u32 tcpi_rto;
  __u32 tcpi_ato;
  __u32 tcpi_snd_mss;
  __u32 tcpi_rcv_mss;
  __u32 tcpi_unacked;
  __u32 tcpi_sacked;
  __u32 tcpi_lost;
  __u32 tcpi_retrans;
  __u32 tcpi_fackets;
  __u32 tcpi_last_data_sent;
  __u32 tcpi_last_ack_sent;
  __u32 tcpi_last_data_recv;
  __u32 tcpi_last_ack_recv;
  __u32 tcpi_pmtu;
  __u32 tcpi_rcv_ssthresh;
  __u32 tcpi_rtt;
  __u32 tcpi_rttvar;
  __u32 tcpi_snd_ssthresh;
  __u32 tcpi_snd_cwnd;
  __u32 tcpi_advmss;
  __u32 tcpi_reordering;
  __u32 tcpi_rcv_rtt;
  __u32 tcpi_rcv_space;
  __u32 tcpi_total_retrans;
  __u64 tcpi_pacing_rate;
  __u64 tcpi_max_pacing_rate;
  __u64 tcpi_bytes_acked;
  __u64 tcpi_bytes_received;
  __u32 tcpi_segs_out;
  __u32 tcpi_segs_in;
  __u32 tcpi_notsent_bytes;
  __u32 tcpi_min_rtt;
  __u32 tcpi_data_segs_in;
  __u32 tcpi_data_segs_out;
  __u64 tcpi_delivery_rate;
  __u64 tcpi_busy_time;
  __u64 tcpi_rwnd_limited;
  __u64 tcpi_sndbuf_limited;
  __u32 tcpi_delivered;
  __u32 tcpi_delivered_ce;
  __u64 tcpi_bytes_sent;
  __u64 tcpi_bytes_retrans;
  __u32 tcpi_dsack_dups;
  __u32 tcpi_reord_seen;
  __u32 tcpi_rcv_ooopack;
  __u32 tcpi_snd_wnd;
  __u32 tcpi_rcv_wnd;
  __u32 tcpi_rehash;
  __u16 tcpi_total_rto;
  __u16 tcpi_total_rto_recoveries;
  __u32 tcpi_total_rto_time;
};
enum {
  TCP_NLA_PAD,
  TCP_NLA_BUSY,
  TCP_NLA_RWND_LIMITED,
  TCP_NLA_SNDBUF_LIMITED,
  TCP_NLA_DATA_SEGS_OUT,
  TCP_NLA_TOTAL_RETRANS,
  TCP_NLA_PACING_RATE,
  TCP_NLA_DELIVERY_RATE,
  TCP_NLA_SND_CWND,
  TCP_NLA_REORDERING,
  TCP_NLA_MIN_RTT,
  TCP_NLA_RECUR_RETRANS,
  TCP_NLA_DELIVERY_RATE_APP_LMT,
  TCP_NLA_SNDQ_SIZE,
  TCP_NLA_CA_STATE,
  TCP_NLA_SND_SSTHRESH,
  TCP_NLA_DELIVERED,
  TCP_NLA_DELIVERED_CE,
  TCP_NLA_BYTES_SENT,
  TCP_NLA_BYTES_RETRANS,
  TCP_NLA_DSACK_DUPS,
  TCP_NLA_REORD_SEEN,
  TCP_NLA_SRTT,
  TCP_NLA_TIMEOUT_REHASH,
  TCP_NLA_BYTES_NOTSENT,
  TCP_NLA_EDT,
  TCP_NLA_TTL,
  TCP_NLA_REHASH,
};
#define TCP_MD5SIG_MAXKEYLEN 80
#define TCP_MD5SIG_FLAG_PREFIX 0x1
#define TCP_MD5SIG_FLAG_IFINDEX 0x2
struct tcp_md5sig {
  struct sockaddr_storage tcpm_addr;
  __u8 tcpm_flags;
  __u8 tcpm_prefixlen;
  __u16 tcpm_keylen;
  int tcpm_ifindex;
  __u8 tcpm_key[TCP_MD5SIG_MAXKEYLEN];
};
struct tcp_diag_md5sig {
  __u8 tcpm_family;
  __u8 tcpm_prefixlen;
  __u16 tcpm_keylen;
  __be32 tcpm_addr[4];
  __u8 tcpm_key[TCP_MD5SIG_MAXKEYLEN];
};
#define TCP_AO_MAXKEYLEN 80
#define TCP_AO_KEYF_IFINDEX (1 << 0)
#define TCP_AO_KEYF_EXCLUDE_OPT (1 << 1)
struct tcp_ao_add {
  struct sockaddr_storage addr;
  char alg_name[64];
  __s32 ifindex;
  __u32 set_current : 1, set_rnext : 1, reserved : 30;
  __u16 reserved2;
  __u8 prefix;
  __u8 sndid;
  __u8 rcvid;
  __u8 maclen;
  __u8 keyflags;
  __u8 keylen;
  __u8 key[TCP_AO_MAXKEYLEN];
} __attribute__((aligned(8)));
struct tcp_ao_del {
  struct sockaddr_storage addr;
  __s32 ifindex;
  __u32 set_current : 1, set_rnext : 1, del_async : 1, reserved : 29;
  __u16 reserved2;
  __u8 prefix;
  __u8 sndid;
  __u8 rcvid;
  __u8 current_key;
  __u8 rnext;
  __u8 keyflags;
} __attribute__((aligned(8)));
struct tcp_ao_info_opt {
  __u32 set_current : 1, set_rnext : 1, ao_required : 1, set_counters : 1, accept_icmps : 1, reserved : 27;
  __u16 reserved2;
  __u8 current_key;
  __u8 rnext;
  __u64 pkt_good;
  __u64 pkt_bad;
  __u64 pkt_key_not_found;
  __u64 pkt_ao_required;
  __u64 pkt_dropped_icmp;
} __attribute__((aligned(8)));
struct tcp_ao_getsockopt {
  struct sockaddr_storage addr;
  char alg_name[64];
  __u8 key[TCP_AO_MAXKEYLEN];
  __u32 nkeys;
  __u16 is_current : 1, is_rnext : 1, get_all : 1, reserved : 13;
  __u8 sndid;
  __u8 rcvid;
  __u8 prefix;
  __u8 maclen;
  __u8 keyflags;
  __u8 keylen;
  __s32 ifindex;
  __u64 pkt_good;
  __u64 pkt_bad;
} __attribute__((aligned(8)));
struct tcp_ao_repair {
  __be32 snt_isn;
  __be32 rcv_isn;
  __u32 snd_sne;
  __u32 rcv_sne;
} __attribute__((aligned(8)));
#define TCP_RECEIVE_ZEROCOPY_FLAG_TLB_CLEAN_HINT 0x1
struct tcp_zerocopy_receive {
  __u64 address;
  __u32 length;
  __u32 recv_skip_hint;
  __u32 inq;
  __s32 err;
  __u64 copybuf_address;
  __s32 copybuf_len;
  __u32 flags;
  __u64 msg_control;
  __u64 msg_controllen;
  __u32 msg_flags;
  __u32 reserved;
};
#endif

"""

```