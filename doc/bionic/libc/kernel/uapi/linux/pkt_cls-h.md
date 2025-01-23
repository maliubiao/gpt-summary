Response:
Let's break down the thought process for analyzing the provided C header file `pkt_cls.h`.

**1. Initial Understanding - What is this file about?**

The first few lines are crucial:

* `"bionic/libc/kernel/uapi/linux/pkt_cls.h"`: This immediately tells us the file's location within the Android Bionic library, specifically within the kernel's user-space API (uapi). The `linux/` part indicates it's closely tied to the Linux kernel's networking subsystem. The `pkt_cls.h` strongly suggests it deals with packet classification.
* `"bionic is Android's C library, math library, and dynamic linker."`: This provides context about the environment this header file belongs to.

Therefore, the core subject is **Linux kernel packet classification structures and definitions as exposed to user-space applications on Android.**

**2. Identifying Key Sections and Concepts:**

I scanned the code, looking for recurring patterns, keywords, and structures. This leads to the identification of several key areas:

* **`enum` declarations:**  These define sets of named integer constants. I noticed many `enum`s with names starting with `TCA_ACT_`, `TC_ACT_`, `TCA_POLICE_`, `TCA_U32_`, etc. The prefixes `TCA` and `TC` are significant and likely represent different levels or types of traffic control attributes.
* **`#define` macros:** These define symbolic constants. Many of these also start with `TCA_` and `TC_`, reinforcing the idea of traffic control configuration.
* **`struct` declarations:** These define data structures. `tc_police`, `tcf_t`, `tc_cnt`, `tc_u32_key`, `tc_u32_sel`, etc., all seem related to configuring and managing packet classification rules.
* **Comments:** The initial comment about auto-generation is important. It means directly modifying this file is discouraged, and changes should be made upstream in the kernel.

**3. Grouping Functionality and Themes:**

Based on the identified keywords and structures, I began to group related elements:

* **Actions (`TC_ACT_*`, `TCA_ACT_*`):**  These define what happens to a packet after it's classified (e.g., `TC_ACT_OK`, `TC_ACT_RECLASSIFY`, `TC_ACT_SHOT`). I saw the concept of extended actions (`TC_ACT_JUMP`, `TC_ACT_GOTO_CHAIN`).
* **Action Attributes (`TCA_ACT_*` enums):** These specify parameters for actions, such as cookies, flags, and statistics.
* **Policing (`tc_police`, `TCA_POLICE_*`):** This relates to rate limiting and traffic shaping. The `tc_police` struct and associated enums define parameters like `limit`, `burst`, and `rate`.
* **Selectors/Filters (`TC_U32_*`, `TCA_U32_*`, `TCA_FLOWER_*`):**  These define how packets are matched or selected for specific actions. I noticed different types of selectors like `u32`, `flower`, etc., suggesting different matching criteria (e.g., based on IP addresses, ports, VLAN tags). The `tc_u32_sel` and `tc_u32_key` structs seem crucial for `u32` based filtering. The `TCA_FLOWER_*` enums suggest a more flexible "flower" classifier.
* **Matching (`TCA_EMATCH_*`, `tcf_ematch_*`):**  This appears to be a more generic mechanism for matching packets based on various criteria.
* **Counters/Statistics:**  Structures like `tc_cnt`, `tc_basic_pcnt`, `tc_u32_pcnt`, and `tc_matchall_pcnt` indicate the ability to track packet statistics for different classifiers.
* **Flags and Options:** Many `#define` macros represent flags that modify the behavior of classifiers and actions.

**4. Relating to Android:**

Having understood the core Linux traffic control concepts, I considered how they apply to Android:

* **Traffic Shaping/QoS:** Android uses these mechanisms to manage network traffic, prioritize certain applications, and enforce data limits. This is especially relevant for mobile devices with limited bandwidth and data plans.
* **Firewalling/Security:** Packet classification is fundamental for implementing firewalls and network security rules. Android's firewall features likely rely on these underlying kernel capabilities.
* **Network Monitoring/Diagnostics:** Tools and apps that monitor network traffic on Android can use these interfaces to understand packet flows and characteristics.

**5. Considering the Dynamic Linker (as requested):**

While this header file *itself* doesn't contain direct C function implementations that would be handled by the dynamic linker, it defines structures and constants that would be used in *other* code (likely in `netd` or other networking daemons) that *does* get linked. The dynamic linker's role is to resolve the symbols (like structure definitions and constant values) defined in this header file when these other components are loaded.

**6. Thinking about Common Errors:**

I drew on general C programming knowledge and the specific context of network configuration:

* **Incorrectly sized data structures:**  Passing the wrong size when interacting with kernel interfaces is a common error.
* **Invalid flag combinations:** Some flags might be mutually exclusive or have dependencies.
* **Incorrectly formatted data:**  Providing data in the wrong endianness or format.
* **Permissions issues:**  Accessing these network control features often requires elevated privileges.

**7. Sketching a Frida Hook Example:**

To demonstrate interaction, I considered how a Frida script could intercept calls related to traffic control. The key idea is to look for functions or syscalls that would use the definitions in this header file. Since this file defines data structures, the hook would likely target functions that *manipulate* these structures. System calls related to socket options or network interface configuration are good candidates. `setsockopt` with specific traffic control related options would be a plausible target.

**8. Structuring the Output:**

Finally, I organized the information into the requested sections:

* **功能 (Functionality):** A high-level overview of the header file's purpose.
* **与 Android 的关系 (Relationship with Android):** Concrete examples of how these Linux traffic control features are used in Android.
* **libc 函数的实现 (Implementation of libc functions):**  Crucially, I noted that this header *defines* types and constants, but the actual *implementation* of the functions that use these definitions resides elsewhere in the kernel. There are no libc functions *in this file* to explain.
* **Dynamic Linker:** Explained the linker's role in resolving symbols and provided a conceptual SO layout example.
* **逻辑推理 (Logical Inference):**  Presented a simple scenario of using the `TC_ACT_SHOT` action.
* **用户或编程常见的使用错误 (Common user or programming errors):** Listed typical mistakes.
* **Android Framework/NDK 到达这里的步骤 (Steps from Android Framework/NDK):**  Outlined the layers involved in reaching these kernel-level definitions, from high-level Java APIs down to native code and system calls.
* **Frida Hook 示例 (Frida Hook Example):**  Provided a basic Frida script demonstrating how to intercept a relevant system call.

By following this systematic breakdown, I could generate a comprehensive and accurate analysis of the provided header file. The process involves understanding the context, identifying key elements, grouping related concepts, connecting them to the Android environment, and considering practical implications and usage scenarios.
这是一个定义了Linux内核中关于包分类（Packet Classification，pkt_cls）的结构体、枚举和宏定义的文件。它主要用于配置和管理Linux内核的网络流量控制（Traffic Control，tc）子系统中的分类器（classifiers）和动作（actions）。由于Android的底层是Linux内核，这些定义直接影响着Android的网络功能。

**功能列举:**

1. **定义包分类动作 (Traffic Control Actions):**
   - 定义了可以对匹配到的网络包执行的各种动作，例如允许通过 (`TC_ACT_OK`)，重新分类 (`TC_ACT_RECLASSIFY`)，丢弃 (`TC_ACT_SHOT`)，管道传输 (`TC_ACT_PIPE`)，修改 (`TCA_ACT_PEDIT`, `TCA_ACT_SKBEDIT`)，重定向 (`TC_ACT_REDIRECT`) 等。
   - 定义了扩展动作，允许更复杂的控制流，例如跳转到另一个分类器 (`TC_ACT_JUMP`) 或另一个链 (`TC_ACT_GOTO_CHAIN`)。
2. **定义包分类属性 (Traffic Control Attributes):**
   - 使用枚举 `TCA_ACT_UNSPEC` 到 `TCA_ACT_MAX` 定义了与动作相关的各种属性，例如动作的类型 (`TCA_ACT_KIND`)，选项 (`TCA_ACT_OPTIONS`)，索引 (`TCA_ACT_INDEX`)，统计信息 (`TCA_ACT_STATS`)，以及用户自定义的 Cookie (`TCA_ACT_COOKIE`)。
   - 定义了控制硬件加速的标志位，例如 `TCA_ACT_FLAGS_SKIP_HW` 和 `TCA_ACT_FLAGS_SKIP_SW`，用于指示是否跳过硬件或软件统计。
3. **定义包分类器的类型 (Classifier Types):**
   - 通过 `TCA_ACT_GACT`, `TCA_ACT_IPT`, `TCA_ACT_U32`, `TCA_ACT_FLOW`, `TCA_ACT_BPF`, `TCA_ACT_FLOWER` 等宏定义，以及 `tca_id` 枚举，定义了多种不同的包分类器类型。这些分类器使用不同的方法来匹配网络包，例如通用动作 (`GACT`)，基于 `iptables` 规则 (`IPT`)，基于 32 位值的匹配 (`U32`)，基于流的匹配 (`FLOW`)，基于 Berkeley Packet Filter (`BPF`)，以及基于五元组等更细粒度特征的匹配 (`FLOWER`)。
4. **定义策略 (Policing):**
   - 结构体 `tc_police` 定义了流量监管的策略，包括速率限制 (`rate`, `peakrate`)，突发大小 (`burst`)，最大传输单元 (`mtu`) 以及动作 (`action`)。
   - 定义了与策略相关的属性，例如令牌桶过滤器 (`TCA_POLICE_TBF`)，速率 (`TCA_POLICE_RATE`)，峰值速率 (`TCA_POLICE_PEAKRATE`) 等。
5. **定义各种包匹配的规则和结构体:**
   - 例如，`tc_u32_key` 和 `tc_u32_sel` 用于定义基于 32 位值的包匹配规则。
   - `TCA_FLOWER_*` 系列的宏定义用于定义 `flower` 分类器的各种匹配字段，例如以太网 MAC 地址，IP 地址，端口号，VLAN ID 等。
6. **定义统计信息结构体:**
   - 例如 `tc_cnt` 用于存储基本的计数器信息，`tc_u32_pcnt` 用于存储 `u32` 分类器的包计数信息。
7. **定义匹配扩展 (Ematch):**
   - 结构体 `tcf_ematch_tree_hdr` 和 `tcf_ematch_hdr` 定义了更灵活的包匹配方式，允许基于更复杂的规则和模式匹配。

**与 Android 功能的关系及举例说明:**

Android 利用 Linux 内核的流量控制功能来管理网络流量，实现服务质量 (QoS)，计费，以及网络策略等。这个头文件定义的结构体和宏在 Android 的网络栈中被广泛使用。

**举例说明:**

* **网络共享 (Tethering/Hotspot):** Android 可以使用流量控制来限制通过热点连接的设备的带宽，防止单个设备占用过多资源。这可能涉及到设置 `tc` 规则，使用 `tc_police` 结构体来限制速率。
* **VPN 连接:**  Android 可以使用流量控制来管理 VPN 连接的流量，例如对 VPN 连接进行加密或解密操作。这可能涉及到使用 `TCA_ACT_SKBEDIT` 或其他动作来修改数据包。
* **应用的网络优先级:**  Android 允许应用声明其网络优先级。系统可以使用流量控制来确保高优先级的应用获得更多的网络资源。这可能涉及到使用不同的分类器（例如基于应用 UID）和队列规则。
* **防火墙规则:** 虽然这个头文件本身不直接定义防火墙规则，但 `TCA_ACT_IPT` 表明包分类可以与 `iptables` 规则集成，而 Android 的防火墙底层也是基于 `iptables` 或其替代品 (如 `nftables`)。
* **数据使用监控和限制:** Android 系统会监控应用的数据使用情况，并可以设置数据使用限制。这背后可能使用流量控制来强制执行这些限制，例如使用 `tc_police` 来限制应用的带宽。

**libc 函数的实现:**

这个头文件是 Linux 内核的 UAPI (User-space API) 头文件，它定义的是内核数据结构的布局和常量。它本身**不包含任何 libc 函数的实现**。libc (在 Android 中是 Bionic) 中与网络相关的函数，例如 `socket()`, `bind()`, `send()`, `recv()` 等，以及用于配置网络接口的函数 (如 `ioctl` 与网络相关的请求码一起使用)，可能会间接地使用到这里定义的常量和结构体。

例如，Android 的网络配置守护进程 `netd` 或使用 NDK 网络 API 的应用，可能会通过 `ioctl` 系统调用与内核进行交互，传递包含这里定义的结构体的参数，来配置流量控制规则。

**dynamic linker 的功能:**

这个头文件定义的是内核数据结构的布局，它**不涉及动态链接**。动态链接器 (在 Android 中是 `linker64` 或 `linker`) 的作用是加载共享库 (`.so` 文件)，解析符号引用，并将这些库链接到进程的地址空间。

尽管如此，理解动态链接对于理解 Android 如何使用这些内核定义仍然重要。

**SO 布局样本 (假设有使用到这些定义的共享库):**

假设有一个名为 `libandroid_net.so` 的共享库，它封装了与 Android 网络相关的 NDK API，并可能间接使用到 `pkt_cls.h` 中定义的结构体：

```
libandroid_net.so:
    .text          # 包含代码段
        function_a:   # 实现一些网络功能的函数
            ...
            # 可能会调用系统调用，传递使用 pkt_cls.h 中定义的结构体的参数
            mov     r0, #__NR_ioctl  ; 系统调用号
            ldr     r1, [sp, #arg0] ; 指向某个数据结构的指针，该结构体可能包含 pkt_cls.h 中的定义
            mov     r2, #SIOCDEVPRIVATE ; ioctl 请求码，可能与流量控制相关
            svc     #0             ; 发起系统调用
            ...
        function_b:
            ...
    .data          # 包含已初始化数据
        global_var: .word 0         # 全局变量
    .rodata        # 包含只读数据
        string_literal: .asciz "Error message"
    .bss           # 包含未初始化数据
        buffer: .space 1024
    .dynsym        # 动态符号表
        function_a
        global_var
    .dynstr        # 动态字符串表
        "function_a"
        "global_var"
    .rel.dyn       # 动态重定位表
        # 如果 libandroid_net.so 依赖于其他库，这里会记录需要动态链接器处理的重定位信息
```

**链接的处理过程:**

1. **加载共享库:** 当 Android 进程需要使用 `libandroid_net.so` 中的函数时，动态链接器会找到并加载这个库到进程的地址空间。
2. **解析符号:** 动态链接器会查看 `libandroid_net.so` 的动态符号表 (`.dynsym`)，找到需要解析的符号 (例如 `function_a`)。
3. **重定位:** 如果 `libandroid_net.so` 中有对其他共享库的符号引用，动态链接器会根据重定位表 (`.rel.dyn`) 中的信息，修改 `libandroid_net.so` 代码或数据段中的地址，使其指向被依赖库中对应的符号。

**需要注意的是，`pkt_cls.h` 定义的是内核数据结构，用户空间程序通常不会直接链接到包含这些定义的库。而是通过系统调用与内核交互时，传递符合这些结构体布局的数据。**

**逻辑推理 (假设输入与输出):**

假设我们使用 `flower` 分类器来匹配源 IP 地址为 `192.168.1.100` 的所有 TCP 数据包，并对其执行 `TC_ACT_SHOT` (丢弃) 的动作。

**假设输入 (通过某种配置接口，例如 `tc` 命令或 Android 的网络管理 API):**

```
Classifier Type: FLOWER
Match Criteria:
    IP Protocol: TCP
    Source IP Address: 192.168.1.100
Action: TC_ACT_SHOT
```

**逻辑推理:**

当一个源 IP 地址为 `192.168.1.100` 的 TCP 包到达时，内核的网络栈会遍历已配置的流量控制规则。`flower` 分类器会检查该数据包的 IP 头部和 TCP 头部，比对其源 IP 地址和协议类型。如果匹配成功，则执行关联的动作 `TC_ACT_SHOT`，导致该数据包被丢弃，不会继续传递到上层协议栈。

**假设输出 (观察到的网络行为):**

从 `192.168.1.100` 发出的所有 TCP 数据包都无法到达目标，连接会超时或失败。可以通过 `tcpdump` 等工具观察到这些数据包在本地发出后，没有被接收端确认。

**用户或编程常见的使用错误:**

1. **结构体大小不匹配:** 在用户空间程序中构造用于传递给内核的结构体时，如果结构体的大小或成员的布局与内核定义的 `pkt_cls.h` 中的定义不一致，会导致内核解析错误，可能引发崩溃或不可预测的行为。
2. **常量值错误:** 使用了错误的宏定义值，例如错误的动作类型或属性值，会导致配置的流量控制规则无法生效或产生意想不到的结果。
3. **权限问题:** 配置流量控制规则通常需要 root 权限。普通应用无法直接修改这些规则。
4. **不正确的掩码或偏移量:** 在使用例如 `tc_u32_sel` 时，如果掩码 (`mask`) 或偏移量 (`off`) 设置不正确，会导致无法正确匹配目标数据包。
5. **逻辑错误:** 配置了冲突或冗余的流量控制规则，导致实际的网络行为与预期不符。例如，先配置一个规则丢弃所有 TCP 包，然后再配置一个规则允许特定的 TCP 包，此时丢弃规则会生效。
6. **资源泄漏:** 在配置复杂的流量控制规则时，如果没有正确释放相关资源，可能会导致内核资源泄漏。

**Android Framework 或 NDK 如何一步步的到达这里:**

1. **Android Framework (Java 层):**
   - 高级的网络功能，例如设置网络策略、监控数据使用等，通常通过 Android Framework 的 Java API 提供。
   - 例如，`android.net.TrafficStats` 用于获取网络统计信息，`android.app.usage.NetworkStatsManager` 用于查询网络使用情况，`android.net.ConnectivityManager` 用于管理网络连接。
2. **System Services (Native C++ 层):**
   - Framework 的 Java API 通常会调用底层的 System Services，例如 `netd` (Network Daemon)。`netd` 是一个运行在 native 层的守护进程，负责处理网络配置和管理任务。
   - 例如，当应用需要设置网络策略时，Framework 会通过 Binder IPC 调用 `netd` 提供的接口。
3. **NDK API (Native C/C++ 层):**
   - 使用 NDK 开发的应用可以直接调用底层的 C/C++ API 进行网络编程，例如使用 `socket()` 等 POSIX 标准的 socket 函数。
   - 对于更底层的网络控制，可能会使用 `ioctl` 系统调用，并传递与流量控制相关的请求码和数据结构。
4. **System Calls:**
   - `netd` 或使用 NDK 的应用最终会通过系统调用与 Linux 内核进行交互。
   - 与流量控制相关的系统调用可能包括 `ioctl` (例如，使用 `TCA_ACT_*` 等常量来配置分类器和动作) 和 `socket` (创建和操作网络套接字)。
5. **Linux Kernel:**
   - 内核接收到来自用户空间的系统调用后，会根据调用参数执行相应的操作。
   - 对于流量控制相关的操作，内核会使用 `pkt_cls.h` 中定义的结构体和宏来解析用户空间传递的配置信息，并更新内核中的流量控制规则。

**Frida Hook 示例调试步骤:**

假设我们要 hook `netd` 进程中设置 `flower` 分类器的相关代码。由于 `pkt_cls.h` 定义的是内核数据结构，直接 hook 用户空间的函数可能看不到对这些结构的直接操作。更有效的方式是 hook 与流量控制相关的系统调用，例如 `ioctl`。

**Frida Hook 示例:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[*] Error: {message['stack']}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <process name or PID>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.getExportByName(null, "ioctl"), {
        onEnter: function (args) {
            const request = args[1].toInt();
            // 假设与流量控制相关的 ioctl 请求码可能在某个范围内
            // 需要根据实际情况调整
            const TC_SETUP_QDISC_NEW = 0x5470; // 示例请求码，实际值需要查找
            const TC_SETUP_FILTER_NEW = 0x5472;

            if (request === TC_SETUP_QDISC_NEW || request === TC_SETUP_FILTER_NEW) {
                console.log("[*] ioctl called with request:", request);
                // 可以尝试解析 args[2] 指向的数据结构，查看是否包含 pkt_cls.h 中的定义
                // 这部分解析会比较复杂，需要了解内核数据结构的布局
                // 例如，可以读取前几个字节判断数据结构类型
                // const dataPtr = ptr(args[2]);
                // console.log("Data:", hexdump(dataPtr));
            }
        },
        onLeave: function (retval) {
            // console.log("[*] ioctl returned:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print(f"[*] Waiting for ioctl calls in '{target}'...")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**调试步骤:**

1. **确定目标进程:** 通常是 `netd` 进程。
2. **查找相关的 `ioctl` 请求码:** 需要查阅 Linux 内核源代码或相关文档，找到与流量控制操作（例如添加队列规则、分类器、动作）相关的 `ioctl` 请求码。例如，用于设置队列规则、添加过滤器等。
3. **编写 Frida 脚本:** 使用 `Interceptor.attach` hook `ioctl` 系统调用。
4. **在 `onEnter` 中检查 `ioctl` 请求码:** 判断是否是与流量控制相关的操作。
5. **解析 `args[2]` 指向的数据:** 这是 `ioctl` 调用的第三个参数，通常是指向用户空间传递给内核的数据结构的指针。需要根据内核中期望的数据结构布局（部分信息在 `pkt_cls.h` 中定义）来解析这部分数据，以查看是否包含了 `flower` 分类器的配置信息，例如匹配的字段和动作。这部分解析可能需要使用 `Memory.read*` 系列函数，并根据结构体定义进行偏移读取。
6. **分析数据:** 解析出的数据可以帮助我们理解 Android Framework 或 NDK 是如何一步步配置流量控制规则的，例如 `flower` 分类器的各个匹配字段是如何设置的。

**更深入的 Hook:**

如果需要 hook 更高层次的 Android Framework 代码，可以尝试 hook `netd` 进程中处理 Binder IPC 调用的函数，例如与网络策略相关的接口函数。但这通常需要更多的逆向工程知识来确定具体的函数名称和参数。

总结来说，`bionic/libc/kernel/uapi/linux/pkt_cls.handroid` 是一个非常底层的头文件，定义了 Linux 内核网络流量控制的基础结构。理解它的内容对于深入理解 Android 的网络功能至关重要。通过 Frida hook，我们可以观察到用户空间程序如何与内核交互，配置和管理这些底层的流量控制机制。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/pkt_cls.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_PKT_CLS_H
#define __LINUX_PKT_CLS_H
#include <linux/types.h>
#include <linux/pkt_sched.h>
#define TC_COOKIE_MAX_SIZE 16
enum {
  TCA_ACT_UNSPEC,
  TCA_ACT_KIND,
  TCA_ACT_OPTIONS,
  TCA_ACT_INDEX,
  TCA_ACT_STATS,
  TCA_ACT_PAD,
  TCA_ACT_COOKIE,
  TCA_ACT_FLAGS,
  TCA_ACT_HW_STATS,
  TCA_ACT_USED_HW_STATS,
  TCA_ACT_IN_HW_COUNT,
  __TCA_ACT_MAX
};
#define TCA_ACT_FLAGS_NO_PERCPU_STATS (1 << 0)
#define TCA_ACT_FLAGS_SKIP_HW (1 << 1)
#define TCA_ACT_FLAGS_SKIP_SW (1 << 2)
#define TCA_ACT_HW_STATS_IMMEDIATE (1 << 0)
#define TCA_ACT_HW_STATS_DELAYED (1 << 1)
#define TCA_ACT_MAX __TCA_ACT_MAX
#define TCA_OLD_COMPAT (TCA_ACT_MAX + 1)
#define TCA_ACT_MAX_PRIO 32
#define TCA_ACT_BIND 1
#define TCA_ACT_NOBIND 0
#define TCA_ACT_UNBIND 1
#define TCA_ACT_NOUNBIND 0
#define TCA_ACT_REPLACE 1
#define TCA_ACT_NOREPLACE 0
#define TC_ACT_UNSPEC (- 1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7
#define TC_ACT_TRAP 8
#define TC_ACT_VALUE_MAX TC_ACT_TRAP
#define __TC_ACT_EXT_SHIFT 28
#define __TC_ACT_EXT(local) ((local) << __TC_ACT_EXT_SHIFT)
#define TC_ACT_EXT_VAL_MASK ((1 << __TC_ACT_EXT_SHIFT) - 1)
#define TC_ACT_EXT_OPCODE(combined) ((combined) & (~TC_ACT_EXT_VAL_MASK))
#define TC_ACT_EXT_CMP(combined,opcode) (TC_ACT_EXT_OPCODE(combined) == opcode)
#define TC_ACT_JUMP __TC_ACT_EXT(1)
#define TC_ACT_GOTO_CHAIN __TC_ACT_EXT(2)
#define TC_ACT_EXT_OPCODE_MAX TC_ACT_GOTO_CHAIN
#define TCA_ACT_GACT 5
#define TCA_ACT_IPT 6
#define TCA_ACT_PEDIT 7
#define TCA_ACT_MIRRED 8
#define TCA_ACT_NAT 9
#define TCA_ACT_XT 10
#define TCA_ACT_SKBEDIT 11
#define TCA_ACT_VLAN 12
#define TCA_ACT_BPF 13
#define TCA_ACT_CONNMARK 14
#define TCA_ACT_SKBMOD 15
#define TCA_ACT_CSUM 16
#define TCA_ACT_TUNNEL_KEY 17
#define TCA_ACT_SIMP 22
#define TCA_ACT_IFE 25
#define TCA_ACT_SAMPLE 26
enum tca_id {
  TCA_ID_UNSPEC = 0,
  TCA_ID_POLICE = 1,
  TCA_ID_GACT = TCA_ACT_GACT,
  TCA_ID_IPT = TCA_ACT_IPT,
  TCA_ID_PEDIT = TCA_ACT_PEDIT,
  TCA_ID_MIRRED = TCA_ACT_MIRRED,
  TCA_ID_NAT = TCA_ACT_NAT,
  TCA_ID_XT = TCA_ACT_XT,
  TCA_ID_SKBEDIT = TCA_ACT_SKBEDIT,
  TCA_ID_VLAN = TCA_ACT_VLAN,
  TCA_ID_BPF = TCA_ACT_BPF,
  TCA_ID_CONNMARK = TCA_ACT_CONNMARK,
  TCA_ID_SKBMOD = TCA_ACT_SKBMOD,
  TCA_ID_CSUM = TCA_ACT_CSUM,
  TCA_ID_TUNNEL_KEY = TCA_ACT_TUNNEL_KEY,
  TCA_ID_SIMP = TCA_ACT_SIMP,
  TCA_ID_IFE = TCA_ACT_IFE,
  TCA_ID_SAMPLE = TCA_ACT_SAMPLE,
  TCA_ID_CTINFO,
  TCA_ID_MPLS,
  TCA_ID_CT,
  TCA_ID_GATE,
  __TCA_ID_MAX = 255
};
#define TCA_ID_MAX __TCA_ID_MAX
struct tc_police {
  __u32 index;
  int action;
#define TC_POLICE_UNSPEC TC_ACT_UNSPEC
#define TC_POLICE_OK TC_ACT_OK
#define TC_POLICE_RECLASSIFY TC_ACT_RECLASSIFY
#define TC_POLICE_SHOT TC_ACT_SHOT
#define TC_POLICE_PIPE TC_ACT_PIPE
  __u32 limit;
  __u32 burst;
  __u32 mtu;
  struct tc_ratespec rate;
  struct tc_ratespec peakrate;
  int refcnt;
  int bindcnt;
  __u32 capab;
};
struct tcf_t {
  __u64 install;
  __u64 lastuse;
  __u64 expires;
  __u64 firstuse;
};
struct tc_cnt {
  int refcnt;
  int bindcnt;
};
#define tc_gen __u32 index; __u32 capab; int action; int refcnt; int bindcnt
enum {
  TCA_POLICE_UNSPEC,
  TCA_POLICE_TBF,
  TCA_POLICE_RATE,
  TCA_POLICE_PEAKRATE,
  TCA_POLICE_AVRATE,
  TCA_POLICE_RESULT,
  TCA_POLICE_TM,
  TCA_POLICE_PAD,
  TCA_POLICE_RATE64,
  TCA_POLICE_PEAKRATE64,
  TCA_POLICE_PKTRATE64,
  TCA_POLICE_PKTBURST64,
  __TCA_POLICE_MAX
#define TCA_POLICE_RESULT TCA_POLICE_RESULT
};
#define TCA_POLICE_MAX (__TCA_POLICE_MAX - 1)
#define TCA_CLS_FLAGS_SKIP_HW (1 << 0)
#define TCA_CLS_FLAGS_SKIP_SW (1 << 1)
#define TCA_CLS_FLAGS_IN_HW (1 << 2)
#define TCA_CLS_FLAGS_NOT_IN_HW (1 << 3)
#define TCA_CLS_FLAGS_VERBOSE (1 << 4)
#define TC_U32_HTID(h) ((h) & 0xFFF00000)
#define TC_U32_USERHTID(h) (TC_U32_HTID(h) >> 20)
#define TC_U32_HASH(h) (((h) >> 12) & 0xFF)
#define TC_U32_NODE(h) ((h) & 0xFFF)
#define TC_U32_KEY(h) ((h) & 0xFFFFF)
#define TC_U32_UNSPEC 0
#define TC_U32_ROOT (0xFFF00000)
enum {
  TCA_U32_UNSPEC,
  TCA_U32_CLASSID,
  TCA_U32_HASH,
  TCA_U32_LINK,
  TCA_U32_DIVISOR,
  TCA_U32_SEL,
  TCA_U32_POLICE,
  TCA_U32_ACT,
  TCA_U32_INDEV,
  TCA_U32_PCNT,
  TCA_U32_MARK,
  TCA_U32_FLAGS,
  TCA_U32_PAD,
  __TCA_U32_MAX
};
#define TCA_U32_MAX (__TCA_U32_MAX - 1)
struct tc_u32_key {
  __be32 mask;
  __be32 val;
  int off;
  int offmask;
};
struct tc_u32_sel {
  /**
   ** ANDROID FIX: Comment out TAG value to avoid C++ error about using
   ** a type declared in an anonymous union. This is being fixed upstream
   ** and should be corrected by the next kernel import.
   */
  __struct_group(/*tc_u32_sel_hdr*/, hdr,, unsigned char flags;
  unsigned char offshift;
  unsigned char nkeys;
  __be16 offmask;
  __u16 off;
  short offoff;
  short hoff;
  __be32 hmask;
 );
  struct tc_u32_key keys[];
};
struct tc_u32_mark {
  __u32 val;
  __u32 mask;
  __u32 success;
};
struct tc_u32_pcnt {
  __u64 rcnt;
  __u64 rhit;
  __u64 kcnts[];
};
#define TC_U32_TERMINAL 1
#define TC_U32_OFFSET 2
#define TC_U32_VAROFFSET 4
#define TC_U32_EAT 8
#define TC_U32_MAXDEPTH 8
enum {
  TCA_ROUTE4_UNSPEC,
  TCA_ROUTE4_CLASSID,
  TCA_ROUTE4_TO,
  TCA_ROUTE4_FROM,
  TCA_ROUTE4_IIF,
  TCA_ROUTE4_POLICE,
  TCA_ROUTE4_ACT,
  __TCA_ROUTE4_MAX
};
#define TCA_ROUTE4_MAX (__TCA_ROUTE4_MAX - 1)
enum {
  TCA_FW_UNSPEC,
  TCA_FW_CLASSID,
  TCA_FW_POLICE,
  TCA_FW_INDEV,
  TCA_FW_ACT,
  TCA_FW_MASK,
  __TCA_FW_MAX
};
#define TCA_FW_MAX (__TCA_FW_MAX - 1)
enum {
  FLOW_KEY_SRC,
  FLOW_KEY_DST,
  FLOW_KEY_PROTO,
  FLOW_KEY_PROTO_SRC,
  FLOW_KEY_PROTO_DST,
  FLOW_KEY_IIF,
  FLOW_KEY_PRIORITY,
  FLOW_KEY_MARK,
  FLOW_KEY_NFCT,
  FLOW_KEY_NFCT_SRC,
  FLOW_KEY_NFCT_DST,
  FLOW_KEY_NFCT_PROTO_SRC,
  FLOW_KEY_NFCT_PROTO_DST,
  FLOW_KEY_RTCLASSID,
  FLOW_KEY_SKUID,
  FLOW_KEY_SKGID,
  FLOW_KEY_VLAN_TAG,
  FLOW_KEY_RXHASH,
  __FLOW_KEY_MAX,
};
#define FLOW_KEY_MAX (__FLOW_KEY_MAX - 1)
enum {
  FLOW_MODE_MAP,
  FLOW_MODE_HASH,
};
enum {
  TCA_FLOW_UNSPEC,
  TCA_FLOW_KEYS,
  TCA_FLOW_MODE,
  TCA_FLOW_BASECLASS,
  TCA_FLOW_RSHIFT,
  TCA_FLOW_ADDEND,
  TCA_FLOW_MASK,
  TCA_FLOW_XOR,
  TCA_FLOW_DIVISOR,
  TCA_FLOW_ACT,
  TCA_FLOW_POLICE,
  TCA_FLOW_EMATCHES,
  TCA_FLOW_PERTURB,
  __TCA_FLOW_MAX
};
#define TCA_FLOW_MAX (__TCA_FLOW_MAX - 1)
struct tc_basic_pcnt {
  __u64 rcnt;
  __u64 rhit;
};
enum {
  TCA_BASIC_UNSPEC,
  TCA_BASIC_CLASSID,
  TCA_BASIC_EMATCHES,
  TCA_BASIC_ACT,
  TCA_BASIC_POLICE,
  TCA_BASIC_PCNT,
  TCA_BASIC_PAD,
  __TCA_BASIC_MAX
};
#define TCA_BASIC_MAX (__TCA_BASIC_MAX - 1)
enum {
  TCA_CGROUP_UNSPEC,
  TCA_CGROUP_ACT,
  TCA_CGROUP_POLICE,
  TCA_CGROUP_EMATCHES,
  __TCA_CGROUP_MAX,
};
#define TCA_CGROUP_MAX (__TCA_CGROUP_MAX - 1)
#define TCA_BPF_FLAG_ACT_DIRECT (1 << 0)
enum {
  TCA_BPF_UNSPEC,
  TCA_BPF_ACT,
  TCA_BPF_POLICE,
  TCA_BPF_CLASSID,
  TCA_BPF_OPS_LEN,
  TCA_BPF_OPS,
  TCA_BPF_FD,
  TCA_BPF_NAME,
  TCA_BPF_FLAGS,
  TCA_BPF_FLAGS_GEN,
  TCA_BPF_TAG,
  TCA_BPF_ID,
  __TCA_BPF_MAX,
};
#define TCA_BPF_MAX (__TCA_BPF_MAX - 1)
enum {
  TCA_FLOWER_UNSPEC,
  TCA_FLOWER_CLASSID,
  TCA_FLOWER_INDEV,
  TCA_FLOWER_ACT,
  TCA_FLOWER_KEY_ETH_DST,
  TCA_FLOWER_KEY_ETH_DST_MASK,
  TCA_FLOWER_KEY_ETH_SRC,
  TCA_FLOWER_KEY_ETH_SRC_MASK,
  TCA_FLOWER_KEY_ETH_TYPE,
  TCA_FLOWER_KEY_IP_PROTO,
  TCA_FLOWER_KEY_IPV4_SRC,
  TCA_FLOWER_KEY_IPV4_SRC_MASK,
  TCA_FLOWER_KEY_IPV4_DST,
  TCA_FLOWER_KEY_IPV4_DST_MASK,
  TCA_FLOWER_KEY_IPV6_SRC,
  TCA_FLOWER_KEY_IPV6_SRC_MASK,
  TCA_FLOWER_KEY_IPV6_DST,
  TCA_FLOWER_KEY_IPV6_DST_MASK,
  TCA_FLOWER_KEY_TCP_SRC,
  TCA_FLOWER_KEY_TCP_DST,
  TCA_FLOWER_KEY_UDP_SRC,
  TCA_FLOWER_KEY_UDP_DST,
  TCA_FLOWER_FLAGS,
  TCA_FLOWER_KEY_VLAN_ID,
  TCA_FLOWER_KEY_VLAN_PRIO,
  TCA_FLOWER_KEY_VLAN_ETH_TYPE,
  TCA_FLOWER_KEY_ENC_KEY_ID,
  TCA_FLOWER_KEY_ENC_IPV4_SRC,
  TCA_FLOWER_KEY_ENC_IPV4_SRC_MASK,
  TCA_FLOWER_KEY_ENC_IPV4_DST,
  TCA_FLOWER_KEY_ENC_IPV4_DST_MASK,
  TCA_FLOWER_KEY_ENC_IPV6_SRC,
  TCA_FLOWER_KEY_ENC_IPV6_SRC_MASK,
  TCA_FLOWER_KEY_ENC_IPV6_DST,
  TCA_FLOWER_KEY_ENC_IPV6_DST_MASK,
  TCA_FLOWER_KEY_TCP_SRC_MASK,
  TCA_FLOWER_KEY_TCP_DST_MASK,
  TCA_FLOWER_KEY_UDP_SRC_MASK,
  TCA_FLOWER_KEY_UDP_DST_MASK,
  TCA_FLOWER_KEY_SCTP_SRC_MASK,
  TCA_FLOWER_KEY_SCTP_DST_MASK,
  TCA_FLOWER_KEY_SCTP_SRC,
  TCA_FLOWER_KEY_SCTP_DST,
  TCA_FLOWER_KEY_ENC_UDP_SRC_PORT,
  TCA_FLOWER_KEY_ENC_UDP_SRC_PORT_MASK,
  TCA_FLOWER_KEY_ENC_UDP_DST_PORT,
  TCA_FLOWER_KEY_ENC_UDP_DST_PORT_MASK,
  TCA_FLOWER_KEY_FLAGS,
  TCA_FLOWER_KEY_FLAGS_MASK,
  TCA_FLOWER_KEY_ICMPV4_CODE,
  TCA_FLOWER_KEY_ICMPV4_CODE_MASK,
  TCA_FLOWER_KEY_ICMPV4_TYPE,
  TCA_FLOWER_KEY_ICMPV4_TYPE_MASK,
  TCA_FLOWER_KEY_ICMPV6_CODE,
  TCA_FLOWER_KEY_ICMPV6_CODE_MASK,
  TCA_FLOWER_KEY_ICMPV6_TYPE,
  TCA_FLOWER_KEY_ICMPV6_TYPE_MASK,
  TCA_FLOWER_KEY_ARP_SIP,
  TCA_FLOWER_KEY_ARP_SIP_MASK,
  TCA_FLOWER_KEY_ARP_TIP,
  TCA_FLOWER_KEY_ARP_TIP_MASK,
  TCA_FLOWER_KEY_ARP_OP,
  TCA_FLOWER_KEY_ARP_OP_MASK,
  TCA_FLOWER_KEY_ARP_SHA,
  TCA_FLOWER_KEY_ARP_SHA_MASK,
  TCA_FLOWER_KEY_ARP_THA,
  TCA_FLOWER_KEY_ARP_THA_MASK,
  TCA_FLOWER_KEY_MPLS_TTL,
  TCA_FLOWER_KEY_MPLS_BOS,
  TCA_FLOWER_KEY_MPLS_TC,
  TCA_FLOWER_KEY_MPLS_LABEL,
  TCA_FLOWER_KEY_TCP_FLAGS,
  TCA_FLOWER_KEY_TCP_FLAGS_MASK,
  TCA_FLOWER_KEY_IP_TOS,
  TCA_FLOWER_KEY_IP_TOS_MASK,
  TCA_FLOWER_KEY_IP_TTL,
  TCA_FLOWER_KEY_IP_TTL_MASK,
  TCA_FLOWER_KEY_CVLAN_ID,
  TCA_FLOWER_KEY_CVLAN_PRIO,
  TCA_FLOWER_KEY_CVLAN_ETH_TYPE,
  TCA_FLOWER_KEY_ENC_IP_TOS,
  TCA_FLOWER_KEY_ENC_IP_TOS_MASK,
  TCA_FLOWER_KEY_ENC_IP_TTL,
  TCA_FLOWER_KEY_ENC_IP_TTL_MASK,
  TCA_FLOWER_KEY_ENC_OPTS,
  TCA_FLOWER_KEY_ENC_OPTS_MASK,
  TCA_FLOWER_IN_HW_COUNT,
  TCA_FLOWER_KEY_PORT_SRC_MIN,
  TCA_FLOWER_KEY_PORT_SRC_MAX,
  TCA_FLOWER_KEY_PORT_DST_MIN,
  TCA_FLOWER_KEY_PORT_DST_MAX,
  TCA_FLOWER_KEY_CT_STATE,
  TCA_FLOWER_KEY_CT_STATE_MASK,
  TCA_FLOWER_KEY_CT_ZONE,
  TCA_FLOWER_KEY_CT_ZONE_MASK,
  TCA_FLOWER_KEY_CT_MARK,
  TCA_FLOWER_KEY_CT_MARK_MASK,
  TCA_FLOWER_KEY_CT_LABELS,
  TCA_FLOWER_KEY_CT_LABELS_MASK,
  TCA_FLOWER_KEY_MPLS_OPTS,
  TCA_FLOWER_KEY_HASH,
  TCA_FLOWER_KEY_HASH_MASK,
  TCA_FLOWER_KEY_NUM_OF_VLANS,
  TCA_FLOWER_KEY_PPPOE_SID,
  TCA_FLOWER_KEY_PPP_PROTO,
  TCA_FLOWER_KEY_L2TPV3_SID,
  TCA_FLOWER_L2_MISS,
  TCA_FLOWER_KEY_CFM,
  TCA_FLOWER_KEY_SPI,
  TCA_FLOWER_KEY_SPI_MASK,
  TCA_FLOWER_KEY_ENC_FLAGS,
  TCA_FLOWER_KEY_ENC_FLAGS_MASK,
  __TCA_FLOWER_MAX,
};
#define TCA_FLOWER_MAX (__TCA_FLOWER_MAX - 1)
enum {
  TCA_FLOWER_KEY_CT_FLAGS_NEW = 1 << 0,
  TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED = 1 << 1,
  TCA_FLOWER_KEY_CT_FLAGS_RELATED = 1 << 2,
  TCA_FLOWER_KEY_CT_FLAGS_TRACKED = 1 << 3,
  TCA_FLOWER_KEY_CT_FLAGS_INVALID = 1 << 4,
  TCA_FLOWER_KEY_CT_FLAGS_REPLY = 1 << 5,
  __TCA_FLOWER_KEY_CT_FLAGS_MAX,
};
enum {
  TCA_FLOWER_KEY_ENC_OPTS_UNSPEC,
  TCA_FLOWER_KEY_ENC_OPTS_GENEVE,
  TCA_FLOWER_KEY_ENC_OPTS_VXLAN,
  TCA_FLOWER_KEY_ENC_OPTS_ERSPAN,
  TCA_FLOWER_KEY_ENC_OPTS_GTP,
  TCA_FLOWER_KEY_ENC_OPTS_PFCP,
  __TCA_FLOWER_KEY_ENC_OPTS_MAX,
};
#define TCA_FLOWER_KEY_ENC_OPTS_MAX (__TCA_FLOWER_KEY_ENC_OPTS_MAX - 1)
enum {
  TCA_FLOWER_KEY_ENC_OPT_GENEVE_UNSPEC,
  TCA_FLOWER_KEY_ENC_OPT_GENEVE_CLASS,
  TCA_FLOWER_KEY_ENC_OPT_GENEVE_TYPE,
  TCA_FLOWER_KEY_ENC_OPT_GENEVE_DATA,
  __TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX,
};
#define TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX (__TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX - 1)
enum {
  TCA_FLOWER_KEY_ENC_OPT_VXLAN_UNSPEC,
  TCA_FLOWER_KEY_ENC_OPT_VXLAN_GBP,
  __TCA_FLOWER_KEY_ENC_OPT_VXLAN_MAX,
};
#define TCA_FLOWER_KEY_ENC_OPT_VXLAN_MAX (__TCA_FLOWER_KEY_ENC_OPT_VXLAN_MAX - 1)
enum {
  TCA_FLOWER_KEY_ENC_OPT_ERSPAN_UNSPEC,
  TCA_FLOWER_KEY_ENC_OPT_ERSPAN_VER,
  TCA_FLOWER_KEY_ENC_OPT_ERSPAN_INDEX,
  TCA_FLOWER_KEY_ENC_OPT_ERSPAN_DIR,
  TCA_FLOWER_KEY_ENC_OPT_ERSPAN_HWID,
  __TCA_FLOWER_KEY_ENC_OPT_ERSPAN_MAX,
};
#define TCA_FLOWER_KEY_ENC_OPT_ERSPAN_MAX (__TCA_FLOWER_KEY_ENC_OPT_ERSPAN_MAX - 1)
enum {
  TCA_FLOWER_KEY_ENC_OPT_GTP_UNSPEC,
  TCA_FLOWER_KEY_ENC_OPT_GTP_PDU_TYPE,
  TCA_FLOWER_KEY_ENC_OPT_GTP_QFI,
  __TCA_FLOWER_KEY_ENC_OPT_GTP_MAX,
};
#define TCA_FLOWER_KEY_ENC_OPT_GTP_MAX (__TCA_FLOWER_KEY_ENC_OPT_GTP_MAX - 1)
enum {
  TCA_FLOWER_KEY_ENC_OPT_PFCP_UNSPEC,
  TCA_FLOWER_KEY_ENC_OPT_PFCP_TYPE,
  TCA_FLOWER_KEY_ENC_OPT_PFCP_SEID,
  __TCA_FLOWER_KEY_ENC_OPT_PFCP_MAX,
};
#define TCA_FLOWER_KEY_ENC_OPT_PFCP_MAX (__TCA_FLOWER_KEY_ENC_OPT_PFCP_MAX - 1)
enum {
  TCA_FLOWER_KEY_MPLS_OPTS_UNSPEC,
  TCA_FLOWER_KEY_MPLS_OPTS_LSE,
  __TCA_FLOWER_KEY_MPLS_OPTS_MAX,
};
#define TCA_FLOWER_KEY_MPLS_OPTS_MAX (__TCA_FLOWER_KEY_MPLS_OPTS_MAX - 1)
enum {
  TCA_FLOWER_KEY_MPLS_OPT_LSE_UNSPEC,
  TCA_FLOWER_KEY_MPLS_OPT_LSE_DEPTH,
  TCA_FLOWER_KEY_MPLS_OPT_LSE_TTL,
  TCA_FLOWER_KEY_MPLS_OPT_LSE_BOS,
  TCA_FLOWER_KEY_MPLS_OPT_LSE_TC,
  TCA_FLOWER_KEY_MPLS_OPT_LSE_LABEL,
  __TCA_FLOWER_KEY_MPLS_OPT_LSE_MAX,
};
#define TCA_FLOWER_KEY_MPLS_OPT_LSE_MAX (__TCA_FLOWER_KEY_MPLS_OPT_LSE_MAX - 1)
enum {
  TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT = (1 << 0),
  TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST = (1 << 1),
  TCA_FLOWER_KEY_FLAGS_TUNNEL_CSUM = (1 << 2),
  TCA_FLOWER_KEY_FLAGS_TUNNEL_DONT_FRAGMENT = (1 << 3),
  TCA_FLOWER_KEY_FLAGS_TUNNEL_OAM = (1 << 4),
  TCA_FLOWER_KEY_FLAGS_TUNNEL_CRIT_OPT = (1 << 5),
  __TCA_FLOWER_KEY_FLAGS_MAX,
};
#define TCA_FLOWER_KEY_FLAGS_MAX (__TCA_FLOWER_KEY_FLAGS_MAX - 1)
enum {
  TCA_FLOWER_KEY_CFM_OPT_UNSPEC,
  TCA_FLOWER_KEY_CFM_MD_LEVEL,
  TCA_FLOWER_KEY_CFM_OPCODE,
  __TCA_FLOWER_KEY_CFM_OPT_MAX,
};
#define TCA_FLOWER_KEY_CFM_OPT_MAX (__TCA_FLOWER_KEY_CFM_OPT_MAX - 1)
#define TCA_FLOWER_MASK_FLAGS_RANGE (1 << 0)
struct tc_matchall_pcnt {
  __u64 rhit;
};
enum {
  TCA_MATCHALL_UNSPEC,
  TCA_MATCHALL_CLASSID,
  TCA_MATCHALL_ACT,
  TCA_MATCHALL_FLAGS,
  TCA_MATCHALL_PCNT,
  TCA_MATCHALL_PAD,
  __TCA_MATCHALL_MAX,
};
#define TCA_MATCHALL_MAX (__TCA_MATCHALL_MAX - 1)
struct tcf_ematch_tree_hdr {
  __u16 nmatches;
  __u16 progid;
};
enum {
  TCA_EMATCH_TREE_UNSPEC,
  TCA_EMATCH_TREE_HDR,
  TCA_EMATCH_TREE_LIST,
  __TCA_EMATCH_TREE_MAX
};
#define TCA_EMATCH_TREE_MAX (__TCA_EMATCH_TREE_MAX - 1)
struct tcf_ematch_hdr {
  __u16 matchid;
  __u16 kind;
  __u16 flags;
  __u16 pad;
};
#define TCF_EM_REL_END 0
#define TCF_EM_REL_AND (1 << 0)
#define TCF_EM_REL_OR (1 << 1)
#define TCF_EM_INVERT (1 << 2)
#define TCF_EM_SIMPLE (1 << 3)
#define TCF_EM_REL_MASK 3
#define TCF_EM_REL_VALID(v) (((v) & TCF_EM_REL_MASK) != TCF_EM_REL_MASK)
enum {
  TCF_LAYER_LINK,
  TCF_LAYER_NETWORK,
  TCF_LAYER_TRANSPORT,
  __TCF_LAYER_MAX
};
#define TCF_LAYER_MAX (__TCF_LAYER_MAX - 1)
#define TCF_EM_CONTAINER 0
#define TCF_EM_CMP 1
#define TCF_EM_NBYTE 2
#define TCF_EM_U32 3
#define TCF_EM_META 4
#define TCF_EM_TEXT 5
#define TCF_EM_VLAN 6
#define TCF_EM_CANID 7
#define TCF_EM_IPSET 8
#define TCF_EM_IPT 9
#define TCF_EM_MAX 9
enum {
  TCF_EM_PROG_TC
};
enum {
  TCF_EM_OPND_EQ,
  TCF_EM_OPND_GT,
  TCF_EM_OPND_LT
};
#endif
```