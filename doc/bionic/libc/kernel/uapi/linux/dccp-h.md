Response:
Let's break down the thought process for answering the request about the `dccp.h` file.

**1. Understanding the Context:**

The first and most crucial step is recognizing the origin and purpose of the file. The prompt clearly states:

* **Path:** `bionic/libc/kernel/uapi/linux/dccp.h`
* **Description:** "bionic is Android's C library, math library, and dynamic linker."
* **Key Insight:** This is a **header file** (`.h`), part of the **Bionic** C library, and located within the **kernel's UAPI** (User-space API) directory for **Linux**. This tells us it defines structures, constants, and enumerations that allow user-space programs (like Android apps and system services) to interact with the Linux kernel's implementation of the DCCP protocol.

**2. Initial Scan and Categorization:**

Next, skim the contents of the file to identify the major categories of definitions. Looking for keywords like `struct`, `enum`, `#define` helps. The file clearly defines:

* **Header Structures:**  `dccp_hdr`, `dccp_hdr_ext`, `dccp_hdr_request`, etc. These represent the layout of DCCP packets.
* **Enumerated Types:** `dccp_pkt_type`, `dccp_reset_codes`, `dccpo_*`, `dccpf_*`, `dccp_cmsg_type`, `dccp_packet_dequeueing_policy`. These define sets of related constants.
* **Macros:** `#define` statements, mainly for socket options (`DCCP_SOCKOPT_*`).

**3. Analyzing Each Category and Identifying Functionality:**

Now, delve into each category to understand its purpose:

* **Header Structures:**  These structures directly mirror the fields within a DCCP packet. They are used for packing and unpacking DCCP data when sending and receiving. The different structures likely represent different types of DCCP packets or extensions.
* **Enumerated Types:**
    * `dccp_pkt_type`: Defines the various types of DCCP packets (request, response, data, etc.). This is fundamental to the protocol's state machine.
    * `dccp_reset_codes`:  Lists reasons for a DCCP connection to be reset. This is important for error handling and diagnostics.
    * `dccpo_*`:  Likely define DCCP options that can be included in packets to negotiate or provide additional information.
    * `dccpf_*`:  Seems to be related to DCCP features or capabilities, potentially used during connection establishment.
    * `dccp_cmsg_type`: Suggests control messages that can be sent alongside DCCP data, possibly for quality of service or other advanced features.
    * `dccp_packet_dequeueing_policy`: Hints at different strategies the kernel can use for managing outgoing DCCP packets.
* **Macros (`#define`):**  These define constants, primarily for setting and getting socket options related to DCCP. This allows applications to configure the DCCP behavior of their sockets.

**4. Connecting to Android Functionality:**

At this point, consider how DCCP might be used in Android. Key areas to think about are:

* **Networking:** DCCP is a transport layer protocol, so it would be used for network communication.
* **Specific Use Cases:** While TCP is more common, DCCP's characteristics (unreliable, message-oriented) might make it suitable for specific scenarios, even if less prevalent on Android. Consider multimedia streaming, online games, or applications where occasional packet loss is acceptable but real-time delivery is important. *Initially, I might think less common, but I should still explore potential (even if niche) use cases.*
* **Android Framework:** The Android framework provides higher-level networking APIs. It's likely that developers wouldn't directly interact with DCCP sockets very often. Instead, the framework might internally use DCCP for certain low-level communication needs, or potentially expose it through more specialized APIs.

**5. Addressing Specific Points in the Request:**

* **Libc Function Implementation:** This header file *defines* structures and constants, but it doesn't *implement* libc functions. The actual DCCP implementation resides in the Linux kernel. The libc functions would involve system calls to interact with the kernel's DCCP module. Focus on the purpose of the definitions within the *header* file.
* **Dynamic Linker:** This file has no direct connection to the dynamic linker. It defines data structures for network communication, not for loading and linking shared libraries. State this clearly.
* **Logical Inference (Input/Output):** Since it's a header file, direct input/output examples are not applicable in the same way as for executable code. Instead, think about *how* these definitions would be used. For example, a program might *input* data to populate a `dccp_hdr` structure before sending it, and *output* data from a received `dccp_hdr`.
* **Common Usage Errors:** Focus on mistakes developers might make when using DCCP sockets if they were to interact with it directly. This could include incorrect socket option settings, misinterpreting packet types, or not handling reset codes properly.
* **Android Framework/NDK Path:** Describe the typical journey from an Android app or NDK code to the underlying kernel functionality. Emphasize the role of system calls.
* **Frida Hook Example:**  Provide a concrete example of how Frida could be used to intercept and inspect DCCP-related system calls. This demonstrates how to observe the interaction between user-space and the kernel.

**6. Structuring the Answer:**

Organize the answer logically, addressing each point in the original request. Use clear headings and bullet points to enhance readability. Provide context and explanations, not just a list of definitions.

**7. Refinement and Review:**

After drafting the initial answer, review it for accuracy, completeness, and clarity. Ensure that the language is precise and avoids jargon where possible. Double-check the connections to Android and the explanation of concepts like system calls and the role of the kernel. For example, initially I might have missed the point about UAPI, but upon review, recognizing its significance in the context of user-space interaction with the kernel is crucial. Also, double-check for any misunderstandings of the request. For example, make sure you're explaining the *definitions* and their purpose, not trying to implement DCCP itself.
这是一个C头文件，定义了Linux内核中数据报拥塞控制协议（DCCP）的用户空间API（UAPI）。它不包含可执行代码，而是定义了数据结构、枚举类型和宏，用于在用户空间程序和Linux内核的DCCP协议实现之间进行交互。

**功能列举：**

该头文件主要定义了以下与DCCP协议相关的功能：

1. **DCCP数据包头结构 (Structures):** 定义了各种DCCP数据包头的结构，包括：
   - `struct dccp_hdr`:  基本DCCP头部，包含源端口、目标端口、数据偏移、校验和、包类型和序列号等关键信息。
   - `struct dccp_hdr_ext`:  扩展DCCP头部，包含低位序列号，用于支持更长的序列号空间。
   - `struct dccp_hdr_request`: 请求包头，包含请求的服务类型。
   - `struct dccp_hdr_ack_bits`: ACK相关字段结构，包含保留字段和确认序列号。
   - `struct dccp_hdr_response`: 响应包头，包含ACK信息和响应服务类型。
   - `struct dccp_hdr_reset`: 重置包头，包含ACK信息、重置码和重置数据。

2. **DCCP包类型枚举 (Enums):**  定义了DCCP协议支持的各种包类型，例如：
   - `enum dccp_pkt_type`:  `DCCP_PKT_REQUEST`, `DCCP_PKT_RESPONSE`, `DCCP_PKT_DATA`, `DCCP_PKT_ACK`, `DCCP_PKT_RESET` 等。

3. **DCCP重置码枚举 (Enums):** 定义了DCCP连接重置的原因代码，例如：
   - `enum dccp_reset_codes`: `DCCP_RESET_CODE_UNSPECIFIED`, `DCCP_RESET_CODE_CLOSED`, `DCCP_RESET_CODE_ABORTED` 等。

4. **DCCP选项枚举 (Enums):** 定义了DCCP协议中可以使用的各种选项，用于协商连接参数或传递额外信息，例如：
   - `enum dccpo`: `DCCPO_PADDING`, `DCCPO_CHANGE_L`, `DCCPO_CONFIRM_L`, `DCCPO_TIMESTAMP` 等。

5. **DCCP能力编号枚举 (Enums):** 定义了DCCP连接可以支持的各种功能，例如：
   - `enum dccp_feature_numbers`: `DCCPF_CCID` (拥塞控制ID), `DCCPF_SHORT_SEQNOS` (短序列号) 等。

6. **DCCP控制消息类型枚举 (Enums):** 定义了与DCCP相关的控制消息类型，例如：
   - `enum dccp_cmsg_type`: `DCCP_SCM_PRIORITY` (优先级)。

7. **DCCP包出队策略枚举 (Enums):** 定义了内核处理DCCP数据包的策略，例如：
   - `enum dccp_packet_dequeueing_policy`: `DCCPQ_POLICY_SIMPLE`, `DCCPQ_POLICY_PRIO` (优先级)。

8. **DCCP套接字选项宏 (Macros):** 定义了用于设置和获取DCCP套接字选项的宏，例如：
   - `#define DCCP_SOCKOPT_PACKET_SIZE`, `#define DCCP_SOCKOPT_SERVICE`, `#define DCCP_SOCKOPT_CCID` 等。

**与 Android 功能的关系及举例：**

虽然 TCP 和 UDP 是 Android 上最常用的传输层协议，但 Android 的 Linux 内核也支持 DCCP。这意味着某些特定的网络应用或底层系统服务可能会使用 DCCP 进行通信。

**举例：**

假设有一个需要进行不可靠但拥塞控制的数据传输的应用场景，例如某些实时性要求较高但不强求可靠性的流媒体应用或在线游戏。在这种情况下，开发者可能会选择使用 DCCP 套接字。

在 Android NDK 中，开发者可以使用标准的 socket API 创建和操作 DCCP 套接字，例如：

```c
#include <sys/socket.h>
#include <linux/dccp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  int sockfd = socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP);
  if (sockfd == -1) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in servaddr;
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(12345);

  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
    perror("bind failed");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  // 可以使用 setsockopt 设置 DCCP 特定的选项
  int ccid = DCCPC_CCID3; // 例如选择 CCID3 拥塞控制算法
  if (setsockopt(sockfd, SOL_DCCP, DCCP_SOCKOPT_CCID, &ccid, sizeof(ccid)) == -1) {
    perror("setsockopt failed");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  // ... 进行 DCCP 通信 ...

  close(sockfd);
  return 0;
}
```

在这个例子中，`socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP)`  创建了一个 DCCP 套接字。  `setsockopt(sockfd, SOL_DCCP, DCCP_SOCKOPT_CCID, ...)`  使用了在 `dccp.h` 中定义的宏 `DCCP_SOCKOPT_CCID` 来设置 DCCP 的拥塞控制算法。

**详细解释 libc 函数的功能是如何实现的：**

该头文件本身不包含 libc 函数的实现。它只是定义了用户空间与内核交互的接口。 真正实现 DCCP 功能的是 Linux 内核。

当用户空间的程序调用像 `socket()`, `bind()`, `sendto()`, `recvfrom()` 这样的套接字相关 libc 函数时，如果指定了 `SOCK_DCCP`，这些 libc 函数会最终通过 **系统调用 (system call)**  进入 Linux 内核。

内核中实现了 DCCP 协议栈，负责处理 DCCP 连接的建立、数据包的发送和接收、拥塞控制、错误处理等。  `dccp.h` 中定义的结构体和常量被内核用来解析和构建 DCCP 数据包。

**涉及 dynamic linker 的功能：**

这个头文件与 dynamic linker 没有直接关系。dynamic linker (在 Android 上是 `linker64` 或 `linker`)  负责在程序运行时加载和链接共享库。 `dccp.h`  定义的是网络协议相关的接口，属于内核 API 的一部分。

因此，无法给出与此头文件相关的 so 布局样本或链接处理过程。

**逻辑推理的假设输入与输出：**

由于这是一个头文件，不涉及具体的逻辑执行，因此没有直接的假设输入和输出。 然而，我们可以考虑当程序使用这些定义时的情况：

**假设输入：**

一个用户空间的程序想要发送一个 DCCP 请求包。程序会填充 `struct dccp_hdr_request` 结构体，设置必要的字段，例如目标端口、服务类型等。

**假设输出：**

内核会根据填充的 `struct dccp_hdr_request`  结构体构建一个 DCCP 请求数据包，并将其发送到网络。接收端收到数据包后，内核会解析数据包头，并将相关信息填充到 `struct dccp_hdr` 或其他相关的结构体中，传递给接收端应用程序。

**涉及用户或者编程常见的使用错误：**

1. **不正确的套接字类型:**  使用 `socket()` 创建套接字时，必须指定 `SOCK_DCCP` 和 `IPPROTO_DCCP`，否则将无法使用 DCCP 协议。

   ```c
   // 错误的用法，使用 TCP 套接字
   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
   ```

2. **未初始化或错误地初始化 DCCP 头结构:** 在发送 DCCP 数据包之前，必须正确地填充相应的头部结构体，例如 `dccp_hdr`。  字段的顺序、大小端问题等都需要考虑。

3. **使用了错误的套接字选项:**  尝试设置不适用于 DCCP 的套接字选项，或者使用了错误的选项值。

4. **没有处理 DCCP 特有的错误码:** DCCP 有一些特定的重置码 (`dccp_reset_codes`)，应用程序应该正确处理这些错误，以便进行适当的错误恢复或提示。

5. **假设 DCCP 的可靠性:**  DCCP 是一个不可靠的协议，应用程序不应假设所有发送的数据包都会被接收到。需要根据应用场景考虑是否需要应用层面的可靠性机制。

**Android framework 或 NDK 是如何一步步的到达这里：**

1. **应用程序/NDK 代码:**  Android 应用程序或 NDK 代码通过 Java 或 C/C++ 代码使用 Socket API。

2. **Java Socket API (Framework):** 对于 Java 代码，会使用 `java.net.Socket` 或 `java.net.DatagramSocket` 等类。当需要使用 DCCP 时，可能需要使用更底层的机制或者自定义的实现（因为 Java 标准库对 DCCP 的支持可能有限）。

3. **Native Socket API (NDK):** 对于 NDK 代码，开发者可以直接使用 POSIX 标准的 Socket API，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()`。

4. **System Calls:** 当 NDK 代码调用 Socket API 函数时，最终会触发 **系统调用 (system call)**，例如 `socket`, `bind`, `sendto`, `recvfrom`。

5. **Linux Kernel:**  系统调用会将控制权转移到 Linux 内核。内核的网络子系统会根据系统调用的参数和指定的协议 (`IPPROTO_DCCP`) 调用相应的 DCCP 协议栈的实现。

6. **DCCP Protocol Stack:**  内核的 DCCP 协议栈会处理 DCCP 连接的管理、数据包的发送和接收、拥塞控制等。在处理过程中，内核会使用 `bionic/libc/kernel/uapi/linux/dccp.h` 中定义的结构体和常量来解释和构建 DCCP 数据包。

**Frida hook 示例调试这些步骤：**

可以使用 Frida hook 系统调用来观察应用程序与内核之间关于 DCCP 的交互。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else device.spawn(['com.example.dccpapp']) # 替换为你的应用包名
    session = device.attach(pid)
except frida.ServerNotStartedError:
    print("Frida server is not running. Please start the Frida server on your device.")
    sys.exit()
except frida.ProcessNotFoundError:
    print(f"Process with PID {pid} not found.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName(null, "socket"), {
    onEnter: function(args) {
        var domain = args[0].toInt32();
        var type = args[1].toInt32();
        var protocol = args[2].toInt32();
        if (type === 3 && protocol === 38) { // SOCK_DCCP (3) and IPPROTO_DCCP (38)
            console.log("[+] socket(domain=" + domain + ", type=SOCK_DCCP, protocol=IPPROTO_DCCP)");
        }
    },
    onLeave: function(retval) {
        if (retval.toInt32() !== -1) {
            console.log("[+] socket() => fd: " + retval);
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "sendto"), {
    onEnter: function(args) {
        var sockfd = args[0].toInt32();
        var buf = args[1];
        var len = args[2].toInt32();
        var flags = args[3].toInt32();
        var dest_addr = ptr(args[4]);
        var addrlen = args[5].toInt32();

        // 可以尝试解析 DCCP 头部
        if (Process.pointerSize === 4 && addrlen >= 8 || Process.pointerSize === 8 && addrlen >= 16) {
            var family = dest_addr.readU16();
            var port = dest_addr.add(Process.pointerSize === 4 ? 2 : 0).readU16();
            if (family === 2) { // AF_INET
                console.log("[+] sendto(sockfd=" + sockfd + ", len=" + len + ", flags=" + flags + ", dest_port=" + port + ")");
                // 可以进一步读取 buf 的内容来分析 DCCP 头部
            }
        }
    }
});

Interceptor.attach(Module.findExportByName(null, "recvfrom"), {
    onEnter: function(args) {
        // ... 类似的 hook recvfrom 来观察接收到的 DCCP 数据包
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**示例说明:**

1. **`Interceptor.attach(Module.findExportByName(null, "socket"), ...)`:**  Hook 了 `socket` 系统调用。当应用程序尝试创建套接字时，Frida 会拦截并检查套接字的类型和协议，如果发现是 DCCP 套接字 (`SOCK_DCCP` 和 `IPPROTO_DCCP`)，则会打印日志。

2. **`Interceptor.attach(Module.findExportByName(null, "sendto"), ...)`:** Hook 了 `sendto` 系统调用。当应用程序尝试发送数据时，Frida 会拦截并打印发送的目标端口，并可以进一步读取发送缓冲区的内容来分析 DCCP 头部信息。

3. **`Interceptor.attach(Module.findExportByName(null, "recvfrom"), ...)`:**  （示例中未完整给出）可以类似地 hook `recvfrom` 系统调用来观察接收到的 DCCP 数据包。

通过运行这个 Frida 脚本，你可以观察到 Android 应用程序何时尝试创建 DCCP 套接字以及发送和接收 DCCP 数据包，从而调试与 DCCP 相关的操作。你需要将 `com.example.dccpapp` 替换为你想要调试的 Android 应用的包名。 如果没有指定 PID，Frida 会尝试启动该应用。 确保你的 Android 设备上运行了 Frida 服务。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/dccp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_DCCP_H
#define _UAPI_LINUX_DCCP_H
#include <linux/types.h>
#include <asm/byteorder.h>
struct dccp_hdr {
  __be16 dccph_sport, dccph_dport;
  __u8 dccph_doff;
#ifdef __LITTLE_ENDIAN_BITFIELD
  __u8 dccph_cscov : 4, dccph_ccval : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u8 dccph_ccval : 4, dccph_cscov : 4;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
  __sum16 dccph_checksum;
#ifdef __LITTLE_ENDIAN_BITFIELD
  __u8 dccph_x : 1, dccph_type : 4, dccph_reserved : 3;
#elif defined(__BIG_ENDIAN_BITFIELD)
  __u8 dccph_reserved : 3, dccph_type : 4, dccph_x : 1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
  __u8 dccph_seq2;
  __be16 dccph_seq;
};
struct dccp_hdr_ext {
  __be32 dccph_seq_low;
};
struct dccp_hdr_request {
  __be32 dccph_req_service;
};
struct dccp_hdr_ack_bits {
  __be16 dccph_reserved1;
  __be16 dccph_ack_nr_high;
  __be32 dccph_ack_nr_low;
};
struct dccp_hdr_response {
  struct dccp_hdr_ack_bits dccph_resp_ack;
  __be32 dccph_resp_service;
};
struct dccp_hdr_reset {
  struct dccp_hdr_ack_bits dccph_reset_ack;
  __u8 dccph_reset_code, dccph_reset_data[3];
};
enum dccp_pkt_type {
  DCCP_PKT_REQUEST = 0,
  DCCP_PKT_RESPONSE,
  DCCP_PKT_DATA,
  DCCP_PKT_ACK,
  DCCP_PKT_DATAACK,
  DCCP_PKT_CLOSEREQ,
  DCCP_PKT_CLOSE,
  DCCP_PKT_RESET,
  DCCP_PKT_SYNC,
  DCCP_PKT_SYNCACK,
  DCCP_PKT_INVALID,
};
#define DCCP_NR_PKT_TYPES DCCP_PKT_INVALID
enum dccp_reset_codes {
  DCCP_RESET_CODE_UNSPECIFIED = 0,
  DCCP_RESET_CODE_CLOSED,
  DCCP_RESET_CODE_ABORTED,
  DCCP_RESET_CODE_NO_CONNECTION,
  DCCP_RESET_CODE_PACKET_ERROR,
  DCCP_RESET_CODE_OPTION_ERROR,
  DCCP_RESET_CODE_MANDATORY_ERROR,
  DCCP_RESET_CODE_CONNECTION_REFUSED,
  DCCP_RESET_CODE_BAD_SERVICE_CODE,
  DCCP_RESET_CODE_TOO_BUSY,
  DCCP_RESET_CODE_BAD_INIT_COOKIE,
  DCCP_RESET_CODE_AGGRESSION_PENALTY,
  DCCP_MAX_RESET_CODES
};
enum {
  DCCPO_PADDING = 0,
  DCCPO_MANDATORY = 1,
  DCCPO_MIN_RESERVED = 3,
  DCCPO_MAX_RESERVED = 31,
  DCCPO_CHANGE_L = 32,
  DCCPO_CONFIRM_L = 33,
  DCCPO_CHANGE_R = 34,
  DCCPO_CONFIRM_R = 35,
  DCCPO_NDP_COUNT = 37,
  DCCPO_ACK_VECTOR_0 = 38,
  DCCPO_ACK_VECTOR_1 = 39,
  DCCPO_TIMESTAMP = 41,
  DCCPO_TIMESTAMP_ECHO = 42,
  DCCPO_ELAPSED_TIME = 43,
  DCCPO_MAX = 45,
  DCCPO_MIN_RX_CCID_SPECIFIC = 128,
  DCCPO_MAX_RX_CCID_SPECIFIC = 191,
  DCCPO_MIN_TX_CCID_SPECIFIC = 192,
  DCCPO_MAX_TX_CCID_SPECIFIC = 255,
};
#define DCCP_SINGLE_OPT_MAXLEN 253
enum {
  DCCPC_CCID2 = 2,
  DCCPC_CCID3 = 3,
};
enum dccp_feature_numbers {
  DCCPF_RESERVED = 0,
  DCCPF_CCID = 1,
  DCCPF_SHORT_SEQNOS = 2,
  DCCPF_SEQUENCE_WINDOW = 3,
  DCCPF_ECN_INCAPABLE = 4,
  DCCPF_ACK_RATIO = 5,
  DCCPF_SEND_ACK_VECTOR = 6,
  DCCPF_SEND_NDP_COUNT = 7,
  DCCPF_MIN_CSUM_COVER = 8,
  DCCPF_DATA_CHECKSUM = 9,
  DCCPF_MIN_CCID_SPECIFIC = 128,
  DCCPF_SEND_LEV_RATE = 192,
  DCCPF_MAX_CCID_SPECIFIC = 255,
};
enum dccp_cmsg_type {
  DCCP_SCM_PRIORITY = 1,
  DCCP_SCM_QPOLICY_MAX = 0xFFFF,
  DCCP_SCM_MAX
};
enum dccp_packet_dequeueing_policy {
  DCCPQ_POLICY_SIMPLE,
  DCCPQ_POLICY_PRIO,
  DCCPQ_POLICY_MAX
};
#define DCCP_SOCKOPT_PACKET_SIZE 1
#define DCCP_SOCKOPT_SERVICE 2
#define DCCP_SOCKOPT_CHANGE_L 3
#define DCCP_SOCKOPT_CHANGE_R 4
#define DCCP_SOCKOPT_GET_CUR_MPS 5
#define DCCP_SOCKOPT_SERVER_TIMEWAIT 6
#define DCCP_SOCKOPT_SEND_CSCOV 10
#define DCCP_SOCKOPT_RECV_CSCOV 11
#define DCCP_SOCKOPT_AVAILABLE_CCIDS 12
#define DCCP_SOCKOPT_CCID 13
#define DCCP_SOCKOPT_TX_CCID 14
#define DCCP_SOCKOPT_RX_CCID 15
#define DCCP_SOCKOPT_QPOLICY_ID 16
#define DCCP_SOCKOPT_QPOLICY_TXQLEN 17
#define DCCP_SOCKOPT_CCID_RX_INFO 128
#define DCCP_SOCKOPT_CCID_TX_INFO 192
#define DCCP_SERVICE_LIST_MAX_LEN 32
#endif

"""

```