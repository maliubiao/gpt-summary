Response:
Let's break down the thought process for analyzing the provided C header file.

**1. Understanding the Context:**

The first and most important step is recognizing the context. The prompt clearly states this is a header file (`.h`) located within the Android Bionic library (`bionic/libc/kernel/uapi/linux/batadv_packet.h`). The path itself gives strong hints: `kernel/uapi` suggests this is an interface between userspace and the Linux kernel. `batadv_packet` strongly implies this relates to the Batmobile Ad-hoc Network (BATMAN) protocol, a mesh networking protocol.

**2. Initial Scan and Identification of Key Elements:**

A quick scan reveals several common C constructs:

* **Header Guards:** `#ifndef _UAPI_LINUX_BATADV_PACKET_H_`, `#define _UAPI_LINUX_BATADV_PACKET_H_`, `#endif` are standard header guards to prevent multiple inclusions.
* **Includes:** `#include <asm/byteorder.h>` and `#include <linux/if_ether.h>` and `#include <linux/types.h>` indicate dependencies on other kernel header files for byte order definitions, Ethernet-related structures (like MAC addresses), and basic type definitions.
* **Macros:** `#define batadv_tp_is_error(n) ...` defines a simple macro.
* **Enums:** `enum batadv_packettype { ... }`, `enum batadv_subtype { ... }`, etc. define sets of named integer constants. These are crucial for understanding the types of packets and sub-types within the BATMAN protocol.
* **Structs:** `struct batadv_bla_claim_dst { ... }`, `struct batadv_ogm_packet { ... }`, etc. define data structures, which likely represent the format of different types of BATMAN packets.
* **`#pragma pack(2)` and `#pragma pack()`:** These directives control structure packing, ensuring specific memory layout.

**3. Deciphering the Enums:**

Enums provide vital information about the protocol's functionality. By examining the enum names and their values, we can infer:

* **`batadv_packettype`:** Defines the high-level type of BATMAN packet (e.g., OGM for Originator Message, BCAST for broadcast, UNICAST for unicast). The numerical ranges (e.g., `BATADV_UNICAST_MIN` and `BATADV_UNICAST_MAX`) provide structure.
* **`batadv_subtype`:**  Specifies subtypes within certain packet types, likely for more specific actions (e.g., DHT get/put requests).
* **`batadv_iv_flags`:**  Flags associated with the IV (routing) information, indicating properties of a route.
* **`batadv_icmp_packettype`:**  Types of ICMP-like messages used within BATMAN.
* **`batadv_mcast_flags`:**  Flags related to multicast functionality.
* **`batadv_tt_data_flags`:** Flags associated with the Translation Table (TT), a key component of BATMAN for layer-2 routing.
* **`batadv_vlan_flags`:** Flags related to VLAN tagging.
* **`batadv_bla_claimframe`:** Types of claim frames used in the Bridge Loop Avoidance (BLA) mechanism.
* **`batadv_tvlv_type`:** Types of Type-Length-Value (TLV) elements, used for extending packet information.

**4. Analyzing the Structs:**

Structs describe the layout of data within packets. Analyzing the members of each struct is critical:

* **Common Fields:** Many structs start with `packet_type` and `version`, suggesting a common header structure.
* **Address Fields:** `orig`, `prev_sender`, `dest`, `src` (with `ETH_ALEN` type) clearly represent MAC addresses.
* **Sequence Numbers:** `seqno` is a common field, used for tracking packet order and potentially detecting duplicates.
* **Timers and Intervals:** `ttl` (Time-To-Live), `elp_interval` suggest mechanisms for managing packet lifetimes and periodic announcements.
* **Flags:** `flags` fields appear in many structs, allowing for boolean-like settings.
* **TLV Lengths:** `tvlv_len` indicates the presence of variable-length data appended to the fixed-size header.
* **Specific Data:**  Structs like `batadv_ogm2_packet` introduce specific fields like `throughput`.

**5. Connecting to Android:**

Since the header resides within Bionic, it's part of Android's system-level libraries. The key connection is the **kernel interface**. This header defines the *structure* of data exchanged between userspace Android processes and the Linux kernel module implementing the BATMAN protocol.

* **NDK Access:**  While direct inclusion might be rare, the structures defined here are fundamental to any NDK application that interacts directly with the BATMAN kernel module (if the device/kernel supports it).
* **Framework Interaction (Indirect):** The Android framework itself might not directly use these structures. However, lower-level network services or HALs (Hardware Abstraction Layers) within Android could potentially interact with the BATMAN kernel module and use these structures indirectly. Imagine a scenario where a custom Wi-Fi Direct implementation leverages BATMAN for ad-hoc connectivity.

**6. Considering libc Functions (and the Lack Thereof):**

This header file primarily *defines data structures and constants*. It doesn't contain *function declarations or implementations* that are typical of libc. Therefore, the prompt's request to explain libc function implementations isn't directly applicable to *this specific file*. The libc functions would come into play when *using* these structures, for example:

* **`socket()` and related system calls:** To open a raw socket for sending and receiving BATMAN packets.
* **Memory manipulation functions (`malloc`, `memcpy`, etc.):** To allocate and manipulate memory for these packet structures.
* **Network byte order functions (`htons`, `ntohs`, etc.):**  To convert between host and network byte order for multi-byte fields.

**7. Dynamic Linker and SO Layout:**

Since this is a header file, it doesn't directly involve dynamic linking in the same way as a shared object (`.so`) file. However, if a userspace application or Android service were to interact with the BATMAN kernel module, and that interaction involved a separate shared library for BATMAN-related functionality, then the typical dynamic linking process would apply:

* **SO Layout:** A `.so` file would contain:
    * `.text`: Executable code.
    * `.data`: Initialized data.
    * `.bss`: Uninitialized data.
    * `.dynsym`: Dynamic symbol table (exported functions and variables).
    * `.plt`, `.got`: Sections for lazy symbol resolution.
* **Linking Process:** The dynamic linker (`/system/bin/linker64` or `/system/bin/linker`) would load the `.so` into memory, resolve symbols (like functions to interact with the kernel), and perform relocations.

**8. User/Programming Errors:**

Common errors related to these structures would involve:

* **Incorrectly packing/unpacking data:**  Forgetting about byte order (`__be16`, `__be32`) or structure packing (`#pragma pack`).
* **Incorrectly setting packet type or version:** Leading to misinterpretation by the receiving end.
* **Buffer overflows:**  Writing beyond the bounds of the defined structures.
* **Incorrectly calculating TLV lengths:**  Causing parsing errors.

**9. Frida Hooking:**

Frida could be used to inspect the creation and processing of these BATMAN packets. You'd likely hook functions within the kernel module or within userspace libraries that interact with the kernel via system calls (e.g., `sendto`, `recvfrom` on a raw socket). The hook would examine the memory containing these structures.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  Focus heavily on libc functions.
* **Correction:** Realized this is a header file defining *data structures*, not implementing libc functions. Shifted focus to *how* these structures would be *used* in conjunction with libc functions.
* **Initial thought:**  Direct NDK usage is common.
* **Refinement:** Acknowledged that direct NDK usage might be less frequent than indirect usage through framework components or lower-level services.
* **Initial thought:** Dynamic linking is directly relevant to *this file*.
* **Correction:** Clarified that dynamic linking applies to *shared libraries that might use these structures*, not the header file itself.

By following this structured approach, breaking down the code into its components, and considering the surrounding context (Android, kernel, networking), we arrive at a comprehensive understanding of the provided header file.
这个C头文件 `bionic/libc/kernel/uapi/linux/batadv_packet.h` 定义了Linux内核中 BATMAN 高级自组织网络（B.A.T.M.A.N. advanced）协议使用的数据包结构和相关的常量。它不是一个源程序文件，而是一个头文件，用于声明数据结构和宏，以便其他C/C++代码可以引用和使用。

**功能列举:**

1. **定义了BATMAN协议的数据包类型 (`enum batadv_packettype`)**:  例如：
    * `BATADV_IV_OGM`:  OGM (Originator Message)，用于路由信息传播。
    * `BATADV_BCAST`: 广播数据包。
    * `BATADV_UNICAST`: 单播数据包。
    * `BATADV_ICMP`:  BATMAN协议内部使用的ICMP类型消息。
2. **定义了数据包的子类型 (`enum batadv_subtype`)**:  用于更细粒度地划分数据包的用途，例如在数据包中进行DHT（分布式哈希表）操作。
3. **定义了IV (路由信息) 相关的标志位 (`enum batadv_iv_flags`)**:  用于标记路由信息的特性，例如是否是最佳下一跳。
4. **定义了BATMAN内部ICMP消息的类型 (`enum batadv_icmp_packettype`)**:  例如：
    * `BATADV_ECHO_REQUEST`: 回显请求。
    * `BATADV_DESTINATION_UNREACHABLE`: 目标不可达。
5. **定义了多播相关的标志位 (`enum batadv_mcast_flags`)**:  用于控制多播行为。
6. **定义了翻译表 (Translation Table, TT) 数据的标志位 (`enum batadv_tt_data_flags`)**:  TT是BATMAN协议用于进行二层转发的关键数据结构。
7. **定义了VLAN相关的标志位 (`enum batadv_vlan_flags`)**:  用于标记VLAN信息。
8. **定义了桥接环路避免 (Bridge Loop Avoidance, BLA) 声明帧的类型 (`enum batadv_bla_claimframe`)**:  用于防止网络环路。
9. **定义了类型-长度-值 (Type-Length-Value, TLV) 元素的类型 (`enum batadv_tvlv_type`)**:  TLV用于在数据包中携带额外的可扩展信息。
10. **定义了各种BATMAN协议数据包的结构体 (`struct batadv_ogm_packet`, `struct batadv_unicast_packet` 等)**:  这些结构体描述了不同类型数据包的字段布局，例如：
    * 包类型、版本、TTL（生存时间）
    * 源MAC地址、目标MAC地址
    * 序列号
    * 标志位
    * TLV数据的长度
    * 特定于包类型的其他数据（例如OGM的跳数、链路质量等）
11. **定义了与TLV元素相关的结构体 (`struct batadv_tvlv_gateway_data`, `struct batadv_tvlv_tt_data` 等)**:  用于定义TLV元素中携带的数据的格式。
12. **定义了一个用于判断是否是错误类型的宏 (`#define batadv_tp_is_error(n)`)**: 简化了错误类型的判断。
13. **定义了兼容性版本号 (`#define BATADV_COMPAT_VERSION`)**: 用于协议版本的管理。

**与Android功能的关联和举例说明:**

这个头文件是Linux内核网络协议栈的一部分，BATMAN协议是一种用于构建无线Mesh网络的协议。虽然Android本身不直接提供用户空间的BATMAN协议实现，但它在以下方面可能存在关联：

* **底层网络驱动/内核模块:** Android设备如果需要支持BATMAN协议，就需要内核中加载相应的BATMAN模块。这个头文件就是定义了这个内核模块所使用的数据结构。
* **定制化的Android ROM或设备:** 某些定制的Android ROM或者特殊用途的Android设备可能会集成或支持BATMAN协议，用于构建自组织网络。例如，在没有基础设施的情况下，多个Android设备可以组成一个Mesh网络进行通信。
* **NDK开发:**  如果开发者使用NDK进行底层网络编程，并且需要与实现了BATMAN协议的内核模块进行交互，那么他们可能会间接地用到这个头文件中定义的结构体。开发者需要构造符合这些结构的数据包，通过Socket等机制发送到内核。

**举例说明:**

假设一个Android设备运行着一个实现了BATMAN协议的内核模块。当该设备需要向Mesh网络中的另一个节点发送数据时，相关的过程可能涉及：

1. **用户空间应用程序 (可能通过NDK) 构造一个BATMAN数据包:**  这需要使用到 `struct batadv_unicast_packet` 或其他相关的结构体。
2. **应用程序设置包类型 (`packet_type`) 为 `BATADV_UNICAST`，目标MAC地址 (`dest`) 为接收方的地址，以及其他必要的字段。**
3. **应用程序可能还会添加TLV元素，例如使用 `struct batadv_tvlv_hdr` 和 `struct batadv_tvlv_dat` 来携带应用层数据。**
4. **应用程序通过Socket (例如 `AF_PACKET`) 将构造好的数据包发送给内核。**
5. **内核中的BATMAN模块接收到数据包，根据数据包头部的字段（例如目标MAC地址），查找路由信息，并将其转发到合适的邻居节点。**

**详细解释每一个libc函数的功能是如何实现的:**

这个头文件本身不包含任何libc函数的实现。它只是声明了数据结构。libc函数会在使用这些数据结构的代码中出现。例如，在构造和解析BATMAN数据包时，可能会用到以下libc函数：

* **`memcpy`**: 用于将数据拷贝到数据包结构体中，或者从结构体中拷贝数据。
* **`malloc` / `free`**:  如果需要在堆上动态分配内存来存储数据包，会使用这些函数。
* **`htons` / `ntohs` (来自 `<arpa/inet.h>` 或 `<netinet/in.h>`)**: 用于将多字节数据（例如序列号）在主机字节序和网络字节序之间进行转换，确保不同架构的系统能够正确解析数据。
* **`socket` / `sendto` / `recvfrom` (来自 `<sys/socket.h>`)**: 用于创建Socket，并通过Socket发送和接收网络数据包。

**对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及dynamic linker。Dynamic linker 主要负责加载共享库 (`.so` 文件) 并解析符号引用。

如果一个用户空间的Android应用程序使用了一个实现了与BATMAN协议交互的共享库，那么这个共享库的布局会包含以下部分：

* **`.text` 段:** 包含可执行的代码。
* **`.data` 段:** 包含已初始化的全局变量和静态变量。
* **`.bss` 段:** 包含未初始化的全局变量和静态变量。
* **`.rodata` 段:** 包含只读数据，例如字符串常量。
* **`.dynsym` 段:** 动态符号表，记录了共享库导出的符号（函数和变量）。
* **`.dynstr` 段:** 动态符号字符串表，存储了符号的名字。
* **`.plt` 段:** 程序链接表 (Procedure Linkage Table)，用于延迟绑定外部函数。
* **`.got` 段:** 全局偏移表 (Global Offset Table)，用于存储外部变量和函数的地址。

**链接的处理过程:**

1. **加载共享库:** 当应用程序启动时，Android的dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会根据应用程序的依赖关系加载所需的共享库。
2. **符号查找:** 当应用程序代码执行到需要调用共享库中函数时，或者访问共享库中的全局变量时，dynamic linker 会查找对应的符号。
3. **重定位:**  由于共享库被加载到内存的哪个地址是运行时决定的，dynamic linker 需要修改代码中的地址引用，使其指向正确的内存位置。这通过修改 `.got` 段中的条目来实现。
4. **延迟绑定 (Lazy Binding):** 为了提高启动速度，对于一些不常用的外部函数，dynamic linker 可能采用延迟绑定的策略。第一次调用该函数时，会跳转到 `.plt` 中的一段代码，该代码会调用 dynamic linker 来解析函数的真实地址并更新 `.got` 表，后续的调用将直接通过 `.got` 表跳转到函数地址。

**如果做了逻辑推理，请给出假设输入与输出:**

由于这个文件是头文件，不包含具体的逻辑。逻辑推理通常发生在实现BATMAN协议的代码中。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **字节序错误:**  BATMAN协议中定义了一些多字节字段（例如序列号 `__be32 seqno`），`__be` 前缀表示大端字节序。如果用户空间的程序在构造数据包时没有注意字节序转换（例如直接使用主机字节序填充），会导致接收方解析错误。

   ```c
   struct batadv_ogm_packet ogm;
   uint32_t seq = 12345;
   // 错误的做法，没有转换为网络字节序
   ogm.seqno = seq;

   // 正确的做法
   ogm.seqno = htonl(seq);
   ```

2. **结构体填充错误:**  错误地估计结构体的大小或字段偏移，导致数据写入到错误的内存位置。

3. **TLV长度计算错误:**  在使用TLV元素时，`tvlv_len` 字段需要正确地指示所有TLV元素的总长度。计算错误会导致接收方无法正确解析TLV数据。

4. **不匹配的协议版本:**  如果发送方和接收方使用的BATMAN协议版本不兼容，可能会导致数据包无法被正确解析。

5. **忘记设置必要的字段:** 例如，发送单播数据包时忘记设置目标MAC地址。

**说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。**

1. **内核模块:** 最底层是Linux内核中实现了BATMAN协议的内核模块 (假设存在)。这个模块会使用 `bionic/libc/kernel/uapi/linux/batadv_packet.h` 中定义的结构体来处理数据包。

2. **系统调用:** 用户空间的Android程序（无论是Java Framework层还是NDK层）需要通过系统调用与内核模块进行交互。对于网络通信，常用的系统调用包括 `socket`、`bind`、`sendto`、`recvfrom` 等。

3. **NDK层:** 如果开发者使用NDK进行开发，他们可以直接调用这些系统调用。为了构造符合BATMAN协议的数据包，开发者需要包含 `bionic/libc/kernel/uapi/linux/batadv_packet.h` 头文件，并使用其中定义的结构体。

4. **Android Framework层:** Android Framework 通常不会直接操作底层的BATMAN协议数据包。Framework层更多地关注于更高级的网络抽象，例如 Wi-Fi、移动数据网络等。但是，在某些特定的场景下，例如定制化的网络配置或服务，可能会涉及到与底层协议的交互。这通常会通过 JNI (Java Native Interface) 调用到 NDK 层的代码来实现。

**Frida Hook 示例:**

假设我们想在内核模块接收到 BATMAN 数据包时进行拦截和查看数据包内容。由于 Frida 主要在用户空间工作，直接 hook 内核函数比较复杂，通常会 hook 用户空间与内核交互的系统调用。

以下是一个使用 Frida hook `recvfrom` 系统调用的示例，用于查看可能包含 BATMAN 数据包的数据：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <process name or PID>".format(__file__))
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "recvfrom"), {
        onEnter: function (args) {
            // args[0] 是 socket 文件描述符
            // args[1] 是接收缓冲区的指针
            // args[2] 是接收缓冲区的大小
            this.buf = args[1];
            this.size = args[2].toInt();
            this.sock_fd = args[0].toInt();
        },
        onLeave: function (retval) {
            if (retval.toInt() > 0) {
                // 成功接收到数据
                var receivedData = Memory.readByteArray(this.buf, retval.toInt());
                console.log("[recvfrom] Socket FD:", this.sock_fd, "Received", retval.toInt(), "bytes:");
                // 在这里可以尝试解析 BATMAN 数据包头部
                if (receivedData.length > 0) {
                    // 假设前几个字节是 packet_type
                    var packetType = receivedData[0];
                    console.log("  Possible BATMAN packet_type:", packetType);
                    // 可以根据 packetType 做更详细的解析
                }
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Hooking recvfrom, press Ctrl+C to stop...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用说明:**

1. 将上述 Python 代码保存为 `frida_hook_recvfrom.py`。
2. 找到你想要监控的进程的名称或 PID（例如，如果某个后台服务可能处理 BATMAN 数据包）。
3. 运行 `python frida_hook_recvfrom.py <进程名称或PID>`。

这个示例会 hook `recvfrom` 系统调用，并在接收到数据时打印接收到的字节数和可能的 BATMAN 数据包类型。你需要根据具体的进程和网络行为来判断是否真的捕获到了 BATMAN 数据包，并进行更深入的解析。

要更精确地 hook 与 BATMAN 相关的操作，可能需要：

* **分析相关的 Android 服务或 Native 库:** 确定哪些组件可能会使用 BATMAN 协议。
* **Hook 相关的 Native 函数:** 如果找到了使用 BATMAN 协议的 Native 库，可以 hook 该库中构造或解析 BATMAN 数据包的函数。
* **Hook 内核函数 (需要 root 权限和更高级的 Frida 用法):**  可以使用内核模块或其他的技术来 hook 内核中处理 BATMAN 数据包的函数，但这通常更复杂。

请记住，直接在 Android 系统上操作网络协议可能需要 root 权限和对系统安全性的充分理解。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/batadv_packet.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_BATADV_PACKET_H_
#define _UAPI_LINUX_BATADV_PACKET_H_
#include <asm/byteorder.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#define batadv_tp_is_error(n) ((__u8) (n) > 127 ? 1 : 0)
enum batadv_packettype {
  BATADV_IV_OGM = 0x00,
  BATADV_BCAST = 0x01,
  BATADV_CODED = 0x02,
  BATADV_ELP = 0x03,
  BATADV_OGM2 = 0x04,
  BATADV_MCAST = 0x05,
#define BATADV_UNICAST_MIN 0x40
  BATADV_UNICAST = 0x40,
  BATADV_UNICAST_FRAG = 0x41,
  BATADV_UNICAST_4ADDR = 0x42,
  BATADV_ICMP = 0x43,
  BATADV_UNICAST_TVLV = 0x44,
#define BATADV_UNICAST_MAX 0x7f
};
enum batadv_subtype {
  BATADV_P_DATA = 0x01,
  BATADV_P_DAT_DHT_GET = 0x02,
  BATADV_P_DAT_DHT_PUT = 0x03,
  BATADV_P_DAT_CACHE_REPLY = 0x04,
};
#define BATADV_COMPAT_VERSION 15
enum batadv_iv_flags {
  BATADV_NOT_BEST_NEXT_HOP = 1UL << 0,
  BATADV_PRIMARIES_FIRST_HOP = 1UL << 1,
  BATADV_DIRECTLINK = 1UL << 2,
};
enum batadv_icmp_packettype {
  BATADV_ECHO_REPLY = 0,
  BATADV_DESTINATION_UNREACHABLE = 3,
  BATADV_ECHO_REQUEST = 8,
  BATADV_TTL_EXCEEDED = 11,
  BATADV_PARAMETER_PROBLEM = 12,
  BATADV_TP = 15,
};
enum batadv_mcast_flags {
  BATADV_MCAST_WANT_ALL_UNSNOOPABLES = 1UL << 0,
  BATADV_MCAST_WANT_ALL_IPV4 = 1UL << 1,
  BATADV_MCAST_WANT_ALL_IPV6 = 1UL << 2,
  BATADV_MCAST_WANT_NO_RTR4 = 1UL << 3,
  BATADV_MCAST_WANT_NO_RTR6 = 1UL << 4,
  BATADV_MCAST_HAVE_MC_PTYPE_CAPA = 1UL << 5,
};
#define BATADV_TT_DATA_TYPE_MASK 0x0F
enum batadv_tt_data_flags {
  BATADV_TT_OGM_DIFF = 1UL << 0,
  BATADV_TT_REQUEST = 1UL << 1,
  BATADV_TT_RESPONSE = 1UL << 2,
  BATADV_TT_FULL_TABLE = 1UL << 4,
};
enum batadv_vlan_flags {
  BATADV_VLAN_HAS_TAG = 1UL << 15,
};
enum batadv_bla_claimframe {
  BATADV_CLAIM_TYPE_CLAIM = 0x00,
  BATADV_CLAIM_TYPE_UNCLAIM = 0x01,
  BATADV_CLAIM_TYPE_ANNOUNCE = 0x02,
  BATADV_CLAIM_TYPE_REQUEST = 0x03,
  BATADV_CLAIM_TYPE_LOOPDETECT = 0x04,
};
enum batadv_tvlv_type {
  BATADV_TVLV_GW = 0x01,
  BATADV_TVLV_DAT = 0x02,
  BATADV_TVLV_NC = 0x03,
  BATADV_TVLV_TT = 0x04,
  BATADV_TVLV_ROAM = 0x05,
  BATADV_TVLV_MCAST = 0x06,
  BATADV_TVLV_MCAST_TRACKER = 0x07,
};
#pragma pack(2)
struct batadv_bla_claim_dst {
  __u8 magic[3];
  __u8 type;
  __be16 group;
};
struct batadv_ogm_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 flags;
  __be32 seqno;
  __u8 orig[ETH_ALEN];
  __u8 prev_sender[ETH_ALEN];
  __u8 reserved;
  __u8 tq;
  __be16 tvlv_len;
};
#define BATADV_OGM_HLEN sizeof(struct batadv_ogm_packet)
struct batadv_ogm2_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 flags;
  __be32 seqno;
  __u8 orig[ETH_ALEN];
  __be16 tvlv_len;
  __be32 throughput;
};
#define BATADV_OGM2_HLEN sizeof(struct batadv_ogm2_packet)
struct batadv_elp_packet {
  __u8 packet_type;
  __u8 version;
  __u8 orig[ETH_ALEN];
  __be32 seqno;
  __be32 elp_interval;
};
#define BATADV_ELP_HLEN sizeof(struct batadv_elp_packet)
struct batadv_icmp_header {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 msg_type;
  __u8 dst[ETH_ALEN];
  __u8 orig[ETH_ALEN];
  __u8 uid;
  __u8 align[3];
};
struct batadv_icmp_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 msg_type;
  __u8 dst[ETH_ALEN];
  __u8 orig[ETH_ALEN];
  __u8 uid;
  __u8 reserved;
  __be16 seqno;
};
struct batadv_icmp_tp_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 msg_type;
  __u8 dst[ETH_ALEN];
  __u8 orig[ETH_ALEN];
  __u8 uid;
  __u8 subtype;
  __u8 session[2];
  __be32 seqno;
  __be32 timestamp;
};
enum batadv_icmp_tp_subtype {
  BATADV_TP_MSG = 0,
  BATADV_TP_ACK,
};
#define BATADV_RR_LEN 16
struct batadv_icmp_packet_rr {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 msg_type;
  __u8 dst[ETH_ALEN];
  __u8 orig[ETH_ALEN];
  __u8 uid;
  __u8 rr_cur;
  __be16 seqno;
  __u8 rr[BATADV_RR_LEN][ETH_ALEN];
};
#define BATADV_ICMP_MAX_PACKET_SIZE sizeof(struct batadv_icmp_packet_rr)
struct batadv_unicast_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 ttvn;
  __u8 dest[ETH_ALEN];
};
struct batadv_unicast_4addr_packet {
  struct batadv_unicast_packet u;
  __u8 src[ETH_ALEN];
  __u8 subtype;
  __u8 reserved;
};
struct batadv_frag_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
#ifdef __BIG_ENDIAN_BITFIELD
  __u8 no : 4;
  __u8 priority : 3;
  __u8 reserved : 1;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
  __u8 reserved : 1;
  __u8 priority : 3;
  __u8 no : 4;
#else
#error "unknown bitfield endianness"
#endif
  __u8 dest[ETH_ALEN];
  __u8 orig[ETH_ALEN];
  __be16 seqno;
  __be16 total_size;
};
struct batadv_bcast_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 reserved;
  __be32 seqno;
  __u8 orig[ETH_ALEN];
};
struct batadv_mcast_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 reserved;
  __be16 tvlv_len;
};
struct batadv_coded_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 first_ttvn;
  __u8 first_source[ETH_ALEN];
  __u8 first_orig_dest[ETH_ALEN];
  __be32 first_crc;
  __u8 second_ttl;
  __u8 second_ttvn;
  __u8 second_dest[ETH_ALEN];
  __u8 second_source[ETH_ALEN];
  __u8 second_orig_dest[ETH_ALEN];
  __be32 second_crc;
  __be16 coded_len;
};
struct batadv_unicast_tvlv_packet {
  __u8 packet_type;
  __u8 version;
  __u8 ttl;
  __u8 reserved;
  __u8 dst[ETH_ALEN];
  __u8 src[ETH_ALEN];
  __be16 tvlv_len;
  __u16 align;
};
struct batadv_tvlv_hdr {
  __u8 type;
  __u8 version;
  __be16 len;
};
struct batadv_tvlv_gateway_data {
  __be32 bandwidth_down;
  __be32 bandwidth_up;
};
struct batadv_tvlv_tt_data {
  __u8 flags;
  __u8 ttvn;
  __be16 num_vlan;
};
struct batadv_tvlv_tt_vlan_data {
  __be32 crc;
  __be16 vid;
  __u16 reserved;
};
struct batadv_tvlv_tt_change {
  __u8 flags;
  __u8 reserved[3];
  __u8 addr[ETH_ALEN];
  __be16 vid;
};
struct batadv_tvlv_roam_adv {
  __u8 client[ETH_ALEN];
  __be16 vid;
};
struct batadv_tvlv_mcast_data {
  __u8 flags;
  __u8 reserved[3];
};
struct batadv_tvlv_mcast_tracker {
  __be16 num_dests;
};
#pragma pack()
#endif

"""

```