Response:
Let's break down the thought process for answering the request about the `netlink.h` header file.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided C header file. Key aspects include:

* **Functionality:** What does this file define?
* **Android Relevance:** How does it relate to Android's operation?
* **libc Function Details:**  Explain the implementation of any libc functions within the file (spoiler: there aren't any directly *implemented* here, but the *types* are used by libc).
* **Dynamic Linker Aspects:** Analyze any features related to dynamic linking (again, this file is about data structures, not dynamic linking itself, but we need to explain why).
* **Logic Inference:**  Provide examples of inputs and outputs (based on the defined structures).
* **Common Usage Errors:** Discuss typical mistakes when working with these definitions.
* **Android Framework/NDK Path:**  Trace how Android components might interact with these definitions.
* **Frida Hook Example:** Provide a practical debugging illustration.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI_CAN_NETLINK_H` and `#define _UAPI_CAN_NETLINK_H`:** Standard header guard to prevent multiple inclusions.
* **`#include <linux/types.h>`:**  Crucially, this indicates that the file relies on basic Linux data types (like `__u32`, `__u16`). This immediately tells us it's part of the Linux kernel's userspace API (UAPI).
* **Structures (`can_bittiming`, `can_bittiming_const`, etc.):** These define data structures related to CAN (Controller Area Network) bus communication parameters. Keywords like "bitrate," "sample_point," "error_warning," etc., strongly suggest a focus on hardware communication.
* **Enums (`can_state`):** Defines a set of possible states for a CAN interface.
* **Macros (`CAN_CTRLMODE_LOOPBACK`, etc.):** Define bit flags for controlling the behavior of a CAN interface.
* **Enums for `IFLA_CAN_*`:**  These look like constants used with netlink, a Linux kernel mechanism for communication between the kernel and userspace. The "IFLA" prefix likely stands for "Interface Layer Attribute."

**3. Connecting to Android:**

* **"bionic is Android's C library..."**: The prompt itself provides the crucial link. While this *specific* header isn't *implemented* in bionic, it's *used* by code that *does* run within Android's userspace (which uses bionic).
* **CAN Bus Usage in Android:**  Think about how Android might use CAN bus. Automotive applications (Android Automotive OS), industrial control, and potentially even some embedded devices. This helps contextualize the relevance.

**4. Addressing Specific Questions:**

* **Functionality:**  Focus on defining data structures and constants for configuring and monitoring CAN interfaces via netlink.
* **Android Relevance (Examples):**  Think about concrete examples. A service controlling a car's braking system, a diagnostic tool communicating with vehicle ECUs, etc.
* **libc Functions:**  Explicitly state that *this file doesn't implement libc functions*. However, note that bionic *uses* these types in its networking-related code (implicitly through the system call interface).
* **Dynamic Linker:** Similarly, explain that this header file itself isn't directly involved in dynamic linking. The *code* that uses these definitions might be, but that's a separate concern. Provide a generic example of a shared library layout for illustrative purposes.
* **Logic Inference:**  Choose a simple structure (e.g., `can_bittiming`) and demonstrate how data would be assigned to its fields.
* **Common Usage Errors:** Think about mistakes developers might make when dealing with hardware interfaces – incorrect configuration values, misinterpreting status codes, not handling errors.
* **Android Framework/NDK Path:**  Start from the application layer and trace down. An app might use the NDK, which calls into bionic, which interacts with the kernel through system calls, potentially using netlink and these structures.
* **Frida Hook:**  Select a relevant function (like `socket` or `sendto`) that would likely be used when interacting with a CAN interface over netlink. Demonstrate how Frida can intercept and inspect the data.

**5. Structuring the Answer:**

Organize the information logically, using headings and bullet points to make it easy to read. Address each part of the original request clearly.

**6. Refining and Adding Detail:**

* **Explain Netlink:**  Briefly describe what netlink is and its role.
* **Clarify UAPI:** Explain the distinction between the kernel's UAPI and userspace libraries like bionic.
* **Provide concrete NDK API examples:** Mention functions from `<linux/can.h>` that NDK developers might use.
* **Make the Frida example practical:** Show how to target a specific process and function.
* **Review and Correct:**  Ensure accuracy and clarity in the explanations.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have thought about directly linking this header file to libc *implementation*. However, a closer look reveals it's defining *types* and *constants*. The connection to bionic is through the *use* of these definitions in system calls and related networking functions provided by bionic. This distinction is crucial for accurate understanding. Similarly, the dynamic linker isn't directly manipulating these structs, but the code that *uses* these structs might reside in dynamically linked libraries.

By following these steps, the detailed and accurate answer provided previously can be constructed. The key is to break down the request, analyze the provided code, connect it to the broader context of Android and Linux, and then structure the information effectively.
这是位于 `bionic/libc/kernel/uapi/linux/can/netlink.h` 的源代码文件，它定义了用于通过 Netlink 套接字与 Linux 内核中的 CAN (Controller Area Network) 子系统进行通信的用户空间 API（UAPI）。`bionic` 是 Android 的 C 库、数学库和动态链接器，这意味着这个头文件定义的内容是 Android 系统与 CAN 总线硬件交互的基础。

**功能列举:**

这个头文件主要定义了以下内容，用于用户空间程序配置和监控 CAN 接口：

1. **数据结构 (Structures):**
   - `can_bittiming`: 定义了 CAN 总线的位定时参数，例如波特率、采样点、时间量子等。
   - `can_bittiming_const`: 定义了 CAN 控制器支持的位定时参数的常量范围。
   - `can_clock`: 定义了 CAN 控制器的时钟频率。
   - `can_berr_counter`: 定义了 CAN 控制器的错误计数器（发送错误和接收错误）。
   - `can_ctrlmode`: 定义了 CAN 控制器的控制模式，例如环回模式、只听模式等。
   - `can_device_stats`: 定义了 CAN 设备的统计信息，例如总线错误、仲裁丢失等。

2. **枚举类型 (Enums):**
   - `can_state`: 定义了 CAN 接口的可能状态，例如错误激活、错误警告、总线关闭等。
   - 匿名枚举类型用于定义 Netlink 属性的 ID，例如 `IFLA_CAN_BITTIMING`、`IFLA_CAN_CTRLMODE` 等，这些 ID 用于在 Netlink 消息中标识不同的 CAN 接口配置参数。

3. **宏定义 (Macros):**
   - `CAN_CTRLMODE_LOOPBACK`, `CAN_CTRLMODE_LISTENONLY` 等：定义了 `can_ctrlmode` 结构体中 `flags` 字段可以使用的位掩码，用于设置 CAN 接口的特定行为。
   - `CAN_TERMINATION_DISABLED`: 定义了禁用 CAN 总线终端的常量。

**与 Android 功能的关系及举例说明:**

这个头文件直接关系到 Android 系统中对 CAN 总线的支持。CAN 总线常用于车辆网络、工业控制等领域。Android 设备如果需要与 CAN 总线设备进行通信，就需要使用这里定义的结构体和常量。

**举例说明:**

* **Android Automotive OS:**  在车载 Android 系统中，CAN 总线是连接各个车载电子控制单元 (ECU) 的重要网络。例如，一个 Android 应用可能需要读取车辆的速度、油耗等信息，这些信息通常通过 CAN 总线传输。该应用会使用到这个头文件中定义的结构体来配置 CAN 接口，例如设置波特率，或者监控 CAN 接口的状态。
* **硬件抽象层 (HAL):**  Android 的 CAN HAL (Hardware Abstraction Layer) 会使用这些定义来与内核中的 CAN 驱动程序进行交互。HAL 层将 Android Framework 的请求转换为内核能够理解的 Netlink 消息，这些消息中会填充这里定义的结构体，例如配置 CAN 控制器的控制模式。
* **诊断工具:**  Android 设备上的诊断工具可能需要通过 CAN 总线与车辆的 ECU 进行通信，以读取故障码或进行其他诊断操作。这些工具也会使用到这个头文件中的定义来构造和解析 Netlink 消息。

**libc 函数的功能实现:**

**这个头文件本身并不实现任何 libc 函数。** 它只是定义了数据结构、枚举和宏，这些是 C 语言的类型定义。这些类型会被 Android 的 C 库 (bionic) 以及使用 bionic 的应用程序所使用。

例如，`socket()` 函数（libc 中的网络编程函数）可以用来创建一个 Netlink 套接字，然后使用 `sendto()` 和 `recvfrom()` 等函数发送和接收与 CAN 相关的 Netlink 消息。这些消息的 payload 部分会包含这里定义的结构体，例如 `can_bittiming` 或 `can_ctrlmode`。

**涉及 dynamic linker 的功能:**

**这个头文件本身与 dynamic linker 没有直接的功能关系。** 动态链接器负责加载和链接共享库。这个头文件定义的是内核接口的数据结构，它会被编译进用户空间的应用程序或共享库。

尽管如此，使用这些定义的代码通常会存在于动态链接的共享库中。例如，一个实现了 CAN HAL 的共享库 (`.so` 文件) 会包含使用这些结构体的代码。

**so 布局样本:**

假设有一个名为 `libcanhal.so` 的共享库，它实现了 CAN HAL：

```
libcanhal.so:
    .init             # 初始化代码段
    .plt              # 程序链接表，用于延迟绑定
    .text             # 代码段，包含 HAL 的实现逻辑，例如配置 CAN 接口的函数
    .rodata           # 只读数据段，可能包含一些常量
    .data             # 可读写数据段，可能包含一些全局变量
    .bss              # 未初始化数据段
    .dynsym           # 动态符号表
    .dynstr           # 动态字符串表
    .rel.dyn          # 动态重定位表
    .rel.plt          # PLT 重定位表
```

**链接的处理过程:**

当一个 Android 应用或服务需要使用 CAN HAL 时，系统会加载 `libcanhal.so`。动态链接器会执行以下步骤：

1. **查找依赖:**  动态链接器会检查 `libcanhal.so` 的依赖项。
2. **加载依赖:**  加载 `libcanhal.so` 依赖的其他共享库。
3. **符号解析:**  解析 `libcanhal.so` 中引用的外部符号，例如 libc 中的函数（`socket`, `sendto` 等）。
4. **重定位:**  调整 `libcanhal.so` 中的代码和数据，使其在内存中的实际地址正确。

在这个过程中，`netlink.h` 中定义的结构体和宏会被编译到 `libcanhal.so` 的 `.text` 或 `.rodata` 段中。当 `libcanhal.so` 中的代码需要配置 CAN 接口时，它会使用这些结构体来构造 Netlink 消息。

**逻辑推理、假设输入与输出:**

假设用户空间程序想要设置 CAN 接口 `can0` 的波特率为 500000 bps。

**假设输入:**

* CAN 接口名称: `can0`
* 波特率: 500000

**逻辑推理:**

1. 程序需要创建一个 Netlink 套接字，并绑定到相应的协议族（`AF_NETLINK`）和协议号（`NETLINK_ROUTE` 或 `NETLINK_GENERIC`，取决于具体的实现）。
2. 程序需要构造一个 Netlink 消息，消息类型通常是 `RTM_SETLINK`，用于设置网络接口的属性。
3. 消息的 payload 部分需要包含一个 `ifinfomsg` 结构体，用于指定要操作的接口（`can0` 的索引）。
4. 消息的属性部分需要包含一个 `IFLA_CAN_BITTIMING` 属性，其值是一个 `can_bittiming` 结构体，其中 `bitrate` 字段设置为 500000。
5. 将构造好的 Netlink 消息发送给内核。

**假设输出:**

* 如果操作成功，内核会返回一个成功的 Netlink 消息。
* 如果操作失败，内核会返回一个包含错误信息的 Netlink 消息，例如指定的接口不存在或参数无效。

**涉及用户或编程常见的使用错误:**

1. **未包含必要的头文件:**  忘记包含 `linux/can/netlink.h` 或其他相关的头文件，导致结构体和宏未定义。
2. **错误的 Netlink 消息构造:**  Netlink 消息的格式有严格的要求，例如消息头、属性的嵌套等，构造错误会导致内核无法解析。
3. **错误的属性 ID:**  使用了错误的 `IFLA_CAN_*` 宏来指定属性，导致内核操作了错误的配置参数。
4. **权限不足:**  配置网络接口通常需要 root 权限。普通用户程序可能无法成功发送 Netlink 配置消息。
5. **CAN 接口不存在:**  尝试配置一个不存在的 CAN 接口。
6. **参数值超出范围:**  设置了超出 CAN 控制器支持范围的参数值，例如波特率。
7. **忽略错误处理:**  发送 Netlink 消息后没有检查内核返回的错误信息，导致程序在错误的情况下继续执行。

**示例:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/can/netlink.h>
#include <net/if.h>
#include <errno.h>

int main() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    int ifindex = if_nametoindex("can0");
    if (ifindex == 0) {
        perror("if_nametoindex");
        close(sock);
        return 1;
    }

    struct {
        struct nlmsghdr nh;
        struct ifinfomsg ifi;
        char attrbuf[1024];
    } req;

    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_type = RTM_SETLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = ifindex;

    struct can_bittiming bittiming;
    memset(&bittiming, 0, sizeof(bittiming));
    bittiming.bitrate = 500000; // 设置波特率为 500000

    struct nlattr *nla = (struct nlattr *)req.attrbuf;
    nla->nla_len = NLA_LENGTH(sizeof(bittiming));
    nla->nla_type = IFLA_CAN_BITTIMING;
    memcpy(NLA_DATA(nla), &bittiming, sizeof(bittiming));
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + NLA_ALIGN(nla->nla_len);

    if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
        perror("send");
        close(sock);
        return 1;
    }

    // ... 接收内核的回复并处理 ...

    close(sock);
    return 0;
}
```

**Android Framework 或 NDK 是如何一步步到达这里的:**

1. **Android 应用 (Java/Kotlin):**  一个需要使用 CAN 总线的 Android 应用，例如车载应用的某个服务。
2. **NDK (Native Development Kit):**  应用开发者可能使用 NDK 来编写 native 代码，以便更底层地控制硬件或利用 C/C++ 库。
3. **CAN HAL (Hardware Abstraction Layer):**  Android 系统中通常会有一个 CAN HAL 模块，负责提供 CAN 总线的抽象接口。这个 HAL 模块通常是一个共享库 (`.so`)，使用 C/C++ 编写。
4. **HAL 实现:**  CAN HAL 的实现代码会使用标准的 Linux socket API 和 Netlink 协议与内核中的 CAN 驱动程序进行通信。
5. **bionic (C 库):**  HAL 的实现代码会链接到 bionic，使用 bionic 提供的系统调用封装，例如 `socket()`, `bind()`, `sendto()` 等。
6. **系统调用:**  bionic 中的网络相关函数最终会调用 Linux 内核的系统调用，例如 `socket`, `bind`, `sendto`。
7. **Netlink 套接字:**  在 HAL 的实现中，会创建一个 `AF_NETLINK` 类型的套接字。
8. **构造 Netlink 消息:**  HAL 代码会根据需要配置的 CAN 参数（例如波特率、控制模式），填充 `netlink.h` 中定义的结构体 (`can_bittiming`, `can_ctrlmode` 等）。
9. **发送 Netlink 消息:**  HAL 代码会将构造好的 Netlink 消息通过 Netlink 套接字发送给内核。
10. **内核 CAN 驱动:**  内核的 CAN 驱动程序接收到 Netlink 消息，解析消息内容，并根据消息中的参数配置 CAN 控制器硬件。

**Frida Hook 示例调试这些步骤:**

可以使用 Frida hook 来观察 Android Framework 或 NDK 代码如何使用这些结构体和函数。以下是一个简单的 Frida Hook 示例，用于拦截 `sendto` 系统调用，查看发送的 Netlink 消息内容：

```javascript
// hook_can_netlink.js

Interceptor.attach(Module.findExportByName(null, "sendto"), {
  onEnter: function (args) {
    const sockfd = args[0].toInt32();
    const buf = args[1];
    const len = args[2].toInt32();
    const destaddr = args[4];

    // 检查是否是 AF_NETLINK 套接字
    const sock_family = Socket.getsockname(sockfd).family;
    if (sock_family === 'af_netlink') {
      console.log("sendto called on NETLINK socket:");
      console.log("  sockfd:", sockfd);
      console.log("  len:", len);

      // 尝试解析 Netlink 消息头
      if (len >= 4) {
        const nlmsghdr = buf.readByteArray(4);
        console.log("  Netlink Header:", hexdump(nlmsghdr));

        // 进一步解析 Netlink 消息内容，例如 RTM_SETLINK 消息
        const nlmsg_type = nlmsghdr[2] | (nlmsghdr[3] << 8);
        if (nlmsg_type === 18) { // RTM_SETLINK 的值
          console.log("  Message Type: RTM_SETLINK");
          // 尝试解析 ifinfomsg
          if (len >= 20) {
            const ifinfomsg = buf.add(16).readByteArray(16);
            console.log("  ifinfomsg:", hexdump(ifinfomsg));

            // 尝试解析 IFLA_CAN_BITTIMING 属性
            let offset = 20;
            while (offset < len) {
              const nla_len = buf.add(offset).readU16();
              const nla_type = buf.add(offset + 2).readU16();
              console.log(`  Attribute Type: ${nla_type}, Length: ${nla_len}`);
              if (nla_type === 2) { // IFLA_CAN_BITTIMING 的值
                if (nla_len >= 8) {
                  const can_bittiming = buf.add(offset + 4).readByteArray(nla_len - 4);
                  console.log("  can_bittiming:", hexdump(can_bittiming));
                }
              }
              offset += nla_len;
              if (nla_len === 0) break;
            }
          }
        }
      }
    }
  },
});
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `hook_can_netlink.js`。
2. 找到目标 Android 进程的 PID，该进程可能是一个负责 CAN 通信的 HAL 进程或应用进程。
3. 使用 Frida 命令运行 Hook 脚本：

   ```bash
   frida -U -f <目标应用包名> -l hook_can_netlink.js --no-pause
   # 或者如果已经运行，则使用 PID
   frida -U <进程PID> -l hook_can_netlink.js
   ```

当目标进程尝试通过 Netlink 发送与 CAN 相关的消息时，Frida 会拦截 `sendto` 调用，并打印出相关的 Netlink 消息头和 `can_bittiming` 结构体的内容，从而帮助调试和分析 CAN 通信过程。

这个详细的解释涵盖了 `bionic/libc/kernel/uapi/linux/can/netlink.h` 文件的功能、与 Android 的关系、动态链接、使用错误、以及如何使用 Frida 进行调试。希望对您有所帮助。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/can/netlink.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_CAN_NETLINK_H
#define _UAPI_CAN_NETLINK_H
#include <linux/types.h>
struct can_bittiming {
  __u32 bitrate;
  __u32 sample_point;
  __u32 tq;
  __u32 prop_seg;
  __u32 phase_seg1;
  __u32 phase_seg2;
  __u32 sjw;
  __u32 brp;
};
struct can_bittiming_const {
  char name[16];
  __u32 tseg1_min;
  __u32 tseg1_max;
  __u32 tseg2_min;
  __u32 tseg2_max;
  __u32 sjw_max;
  __u32 brp_min;
  __u32 brp_max;
  __u32 brp_inc;
};
struct can_clock {
  __u32 freq;
};
enum can_state {
  CAN_STATE_ERROR_ACTIVE = 0,
  CAN_STATE_ERROR_WARNING,
  CAN_STATE_ERROR_PASSIVE,
  CAN_STATE_BUS_OFF,
  CAN_STATE_STOPPED,
  CAN_STATE_SLEEPING,
  CAN_STATE_MAX
};
struct can_berr_counter {
  __u16 txerr;
  __u16 rxerr;
};
struct can_ctrlmode {
  __u32 mask;
  __u32 flags;
};
#define CAN_CTRLMODE_LOOPBACK 0x01
#define CAN_CTRLMODE_LISTENONLY 0x02
#define CAN_CTRLMODE_3_SAMPLES 0x04
#define CAN_CTRLMODE_ONE_SHOT 0x08
#define CAN_CTRLMODE_BERR_REPORTING 0x10
#define CAN_CTRLMODE_FD 0x20
#define CAN_CTRLMODE_PRESUME_ACK 0x40
#define CAN_CTRLMODE_FD_NON_ISO 0x80
#define CAN_CTRLMODE_CC_LEN8_DLC 0x100
#define CAN_CTRLMODE_TDC_AUTO 0x200
#define CAN_CTRLMODE_TDC_MANUAL 0x400
struct can_device_stats {
  __u32 bus_error;
  __u32 error_warning;
  __u32 error_passive;
  __u32 bus_off;
  __u32 arbitration_lost;
  __u32 restarts;
};
enum {
  IFLA_CAN_UNSPEC,
  IFLA_CAN_BITTIMING,
  IFLA_CAN_BITTIMING_CONST,
  IFLA_CAN_CLOCK,
  IFLA_CAN_STATE,
  IFLA_CAN_CTRLMODE,
  IFLA_CAN_RESTART_MS,
  IFLA_CAN_RESTART,
  IFLA_CAN_BERR_COUNTER,
  IFLA_CAN_DATA_BITTIMING,
  IFLA_CAN_DATA_BITTIMING_CONST,
  IFLA_CAN_TERMINATION,
  IFLA_CAN_TERMINATION_CONST,
  IFLA_CAN_BITRATE_CONST,
  IFLA_CAN_DATA_BITRATE_CONST,
  IFLA_CAN_BITRATE_MAX,
  IFLA_CAN_TDC,
  IFLA_CAN_CTRLMODE_EXT,
  __IFLA_CAN_MAX,
  IFLA_CAN_MAX = __IFLA_CAN_MAX - 1
};
enum {
  IFLA_CAN_TDC_UNSPEC,
  IFLA_CAN_TDC_TDCV_MIN,
  IFLA_CAN_TDC_TDCV_MAX,
  IFLA_CAN_TDC_TDCO_MIN,
  IFLA_CAN_TDC_TDCO_MAX,
  IFLA_CAN_TDC_TDCF_MIN,
  IFLA_CAN_TDC_TDCF_MAX,
  IFLA_CAN_TDC_TDCV,
  IFLA_CAN_TDC_TDCO,
  IFLA_CAN_TDC_TDCF,
  __IFLA_CAN_TDC,
  IFLA_CAN_TDC_MAX = __IFLA_CAN_TDC - 1
};
enum {
  IFLA_CAN_CTRLMODE_UNSPEC,
  IFLA_CAN_CTRLMODE_SUPPORTED,
  __IFLA_CAN_CTRLMODE,
  IFLA_CAN_CTRLMODE_MAX = __IFLA_CAN_CTRLMODE - 1
};
#define CAN_TERMINATION_DISABLED 0
#endif
```