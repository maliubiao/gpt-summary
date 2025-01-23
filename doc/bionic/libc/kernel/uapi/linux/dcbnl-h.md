Response:
Let's break down the thought process for analyzing this C header file.

**1. Understanding the Context:**

The first and most crucial step is understanding *what* this file is. The prompt provides key information:

* **Location:** `bionic/libc/kernel/uapi/linux/dcbnl.handroid`
* **Bionic:**  Android's C library, math library, and dynamic linker. This immediately tells us the file is part of the core system on Android.
* **`kernel/uapi`:** This signifies it's a header file defining the *user-space API* for interacting with the kernel. Specifically, it's defining structures and constants used in system calls or ioctl commands related to the kernel.
* **`linux/dcbnl.h`:** The filename itself gives a huge hint. `dcbnl` likely stands for "Data Center Bridging Netlink."  Netlink is a Linux kernel mechanism for communication between the kernel and user-space processes. This strongly suggests the file defines structures for configuring and querying Data Center Bridging (DCB) features within the Linux kernel, as seen from user space.
* **`handroid`:**  This suffix suggests Android-specific modifications or additions to the standard Linux DCB definitions.

**2. High-Level Overview of Functionality (Based on Structure Analysis):**

With the context established, we can scan the file for its primary components:

* **Includes:** `#include <linux/types.h>` indicates the file relies on standard Linux type definitions.
* **Defines (Macros):** A large number of `#define` statements exist. These define constants, often representing limits, states, or selectors. For example, `IEEE_8021QAZ_MAX_TCS` clearly defines the maximum number of Traffic Classes (TCs) supported. Looking at names like `IEEE_8021QAZ_TSA_STRICT`, `DCB_CMD_GSTATE`, and `DCB_ATTR_IFNAME` provides clues about the functionalities being addressed (Traffic Scheduling Algorithm, Get State command, Interface Name attribute).
* **Structures (`struct`):** The file defines several structures like `ieee_ets`, `ieee_qcn`, `ieee_pfc`, etc. These structures likely represent data exchanged between user space and the kernel to configure or retrieve information about DCB features. The names of the structures hint at the specific features they represent (e.g., `ieee_ets` for Enhanced Transmission Selection, `ieee_pfc` for Priority Flow Control).
* **Enums (`enum`):**  Enumerations like `dcbnl_commands`, `dcbnl_attrs`, `ieee_attrs` define sets of named integer constants. These are critical for specifying actions (commands) and the data being operated upon (attributes) within the DCB Netlink communication.

**3. Connecting to Android Functionality:**

Knowing that this is an Android header file, we need to consider how DCB might be relevant:

* **Networking:** DCB is primarily about network Quality of Service (QoS) in data centers. Android devices, while not typical data center nodes, can participate in more complex network environments, especially in enterprise or specialized industrial settings.
* **Peripheral Connectivity:**  While less common for phones, Android devices can act as embedded systems with advanced networking needs. DCB could be used for managing network traffic associated with specific peripherals or applications.
* **Resource Management:**  At a high level, DCB is about managing network resources. Android, in general, needs to manage system resources. Although this specific file deals with *network* DCB, the underlying concept of resource management is relevant.

**4. Addressing Specific Requirements of the Prompt:**

* **Libc Function Explanation:**  This header file *doesn't define libc functions*. It defines *data structures and constants* used by system calls or other kernel interaction mechanisms that *might* be wrapped by libc functions (e.g., `socket`, `ioctl`). Therefore, the answer should clarify this distinction.
* **Dynamic Linker:** This header file is about *kernel interfaces*. It doesn't directly involve the dynamic linker. The answer should explicitly state this. Creating a "so layout sample" and linking process explanation would be incorrect in this context.
* **Logical Reasoning, Assumptions, Input/Output:**  Since this is a header file, direct logical reasoning with input/output isn't applicable at this level. The structures and enums define the *format* of data, not the *logic* of processing it.
* **User/Programming Errors:**  Potential errors would occur when *using* the structures and constants defined here incorrectly in system calls or Netlink messages. Examples include using invalid command/attribute combinations, providing incorrect data types, or not handling kernel responses properly.
* **Android Framework/NDK Path:**  The path likely involves:
    1. **Android Framework:**  Higher-level Android services (e.g., network management services) might need fine-grained control over network QoS.
    2. **System Calls/Netlink:**  These framework services would ultimately interact with the kernel through system calls or the Netlink socket interface.
    3. **Bionic Libc:**  The system calls would be implemented via Bionic's libc wrappers.
    4. **Kernel Interaction:** The kernel would interpret the Netlink messages based on the structures defined in this header file.
* **Frida Hook:** The Frida example should focus on hooking system calls or Netlink interactions related to DCB, demonstrating how to intercept the data being exchanged.

**5. Structuring the Answer:**

A logical structure is crucial for clarity:

1. **Introduction:** Briefly explain the file's purpose and context.
2. **Functionality:** List the core functionalities based on the defined structures, constants, and enums.
3. **Android Relevance:** Explain how these functionalities relate to Android's capabilities, providing concrete examples (even if somewhat hypothetical).
4. **Libc Function Explanation:** Clearly state that this file doesn't define libc functions but defines data used *by* them in kernel interactions.
5. **Dynamic Linker:**  Explicitly state the lack of direct involvement with the dynamic linker.
6. **Logical Reasoning/Input-Output:** Explain why this is not directly applicable at the header file level.
7. **Common Errors:** Provide examples of how developers might misuse the definitions in this file.
8. **Android Framework/NDK Path:** Detail the steps from the framework down to this header file, emphasizing the interaction with the kernel.
9. **Frida Hook Example:**  Provide a concrete example of hooking a relevant system call or Netlink operation.
10. **Conclusion:** Summarize the key takeaways.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps this file directly defines some network configuration functions in libc. **Correction:**  Realize this is a `kernel/uapi` header, meaning it defines the *interface* to the kernel, not the libc implementation itself.
* **Initial thought:** Provide a detailed explanation of how the dynamic linker works. **Correction:** Recognize that this file isn't related to dynamic linking. Keep the answer focused on the file's actual content.
* **Initial thought:**  Try to invent specific Android APIs that directly use these structures. **Refinement:** Focus on the *potential* uses and the general path from framework to kernel, as specific API details would require deeper knowledge of Android's networking stack.

By following this systematic approach, considering the context, analyzing the file's structure, and addressing each part of the prompt, a comprehensive and accurate answer can be constructed.
## 对 bionic/libc/kernel/uapi/linux/dcbnl.handroid 源代码文件的分析

这个C头文件 `bionic/libc/kernel/uapi/linux/dcbnl.handroid` 定义了用于与 Linux 内核中数据中心桥接 (Data Center Bridging, DCB) 子系统进行通信的常量、结构体和枚举。由于它位于 `bionic/libc/kernel/uapi` 目录下，这表明它是 Android Bionic C 库中用于用户空间程序与内核交互的接口定义的一部分。`handroid` 后缀可能表示这是 Android 特有的修改或扩展。

**功能列举:**

这个头文件主要定义了以下功能相关的元素：

1. **数据中心桥接 (DCB) 的配置和状态查询:**  DCB 是一组 IEEE 802.1Q 标准的扩展，旨在提高数据中心网络中融合流量（如以太网存储、局域网和集群互连）的可靠性和效率。此头文件定义了用于配置和查询 DCB 功能的结构体和常量，例如：
    * **优先级流控 (Priority Flow Control, PFC):**  通过 `ieee_pfc` 结构体定义了 PFC 的能力、使能状态、多播抑制、延迟以及请求和指示计数器。
    * **增强传输选择 (Enhanced Transmission Selection, ETS):** 通过 `ieee_ets` 结构体定义了 ETS 的意愿、能力、信用值整型调度器 (CBS) 以及每个流量类别 (TC) 的带宽分配和传输调度算法 (TSA)。
    * **数量拥塞通知 (Quantized Congestion Notification, QCN):** 通过 `ieee_qcn` 和 `ieee_qcn_stats` 结构体定义了 QCN 的参数和统计信息，用于控制网络拥塞。
    * **最大速率:** 通过 `ieee_maxrate` 结构体定义了每个流量类别的最大传输速率。
    * **缓冲区管理:** 通过 `dcbnl_buffer` 结构体定义了优先级到缓冲区的映射和缓冲区大小。
    * **应用优先级:** 通过 `dcb_app` 和 `dcb_peer_app_info` 结构体定义了基于选择器（如以太网类型、协议号等）将应用流量映射到不同优先级的规则。

2. **DCB 控制消息的定义:**  通过 `dcbmsg` 结构体定义了用于 DCB Netlink 通信的基本消息结构，包含协议族、命令和填充字段。

3. **DCB 命令和属性的枚举:**  定义了用于指定要执行的 DCB 操作和要操作的属性的枚举类型，例如：
    * `dcbnl_commands`:  定义了可以执行的命令，如获取/设置状态 (`DCB_CMD_GSTATE`/`DCB_CMD_SSTATE`)、配置 PFC/PG (`DCB_CMD_PFC_GCFG`/`DCB_CMD_PFC_SCFG`，`DCB_CMD_PGTX_GCFG`/`DCB_CMD_PGTX_SCFG`)、获取/设置应用配置 (`DCB_CMD_GAPP`/`DCB_CMD_SAPP`) 等。
    * `dcbnl_attrs`: 定义了可以操作的属性，如接口名 (`DCB_ATTR_IFNAME`)、状态 (`DCB_ATTR_STATE`)、PFC 配置 (`DCB_ATTR_PFC_CFG`)、应用配置 (`DCB_ATTR_APP`) 等。
    * `ieee_attrs`, `cee_attrs`, `dcbnl_pfc_up_attrs`, `dcbnl_pg_attrs`, `dcbnl_tc_attrs`, `dcbnl_cap_attrs`, `dcbnl_numtcs_attrs`, `dcbnl_bcn_attrs`, `dcbnl_app_attrs`, `dcbnl_featcfg_attrs`:  更细粒度地定义了与特定 DCB 功能相关的属性。

4. **特定于 CEE (Converged Enhanced Ethernet) DCBX 的定义:**  包含了一些以 `cee_` 为前缀的结构体，例如 `cee_pg` 和 `cee_pfc`，这些结构体可能与 CEE DCBX (Data Center Bridging Exchange) 协议的配置和信息交换有关。

**与 Android 功能的关系及举例说明:**

DCB 主要用于数据中心环境，在典型的移动 Android 设备上的应用场景可能不多。然而，随着 Android 设备在企业级应用和更复杂的网络环境中的应用增加，DCB 的某些功能可能变得相关。

* **企业级网络 QoS:**  如果 Android 设备需要连接到使用 DCB 来提供服务质量保证的企业网络，那么相关的配置信息可能需要通过 Android 系统进行设置或查询。例如，一个运行在 Android 设备上的应用程序可能需要保证特定的网络带宽和低延迟，这可以通过配置 DCB 的 ETS 功能来实现。

* **USB 网络共享/以太网连接:**  一些 Android 设备可以通过 USB 或以太网连接到主机或网络设备。在这些场景下，如果主机或网络设备支持 DCB，Android 设备可能需要参与 DCB 协商和配置。例如，如果 Android 设备通过 USB 连接到一台服务器并作为网络接口，服务器可能会尝试通过 DCB 配置 Android 设备的 PFC 或 ETS 功能。

* **虚拟化和容器化:**  在 Android 上运行虚拟化或容器化环境时，虚拟机或容器的网络接口可能需要支持 DCB 功能，以便与宿主机或网络中的其他容器进行有效的通信。

**举例说明 (假设场景):**

假设一个 Android 平板电脑被用作企业环境中的控制面板，需要通过以太网连接到支持 DCB 的工业设备。该平板电脑上运行的应用程序需要实时监控设备状态，并对某些操作发出控制指令，这些操作对延迟非常敏感。

在这种情况下，Android 系统或应用程序可能会使用这个头文件中定义的结构体和常量，通过 Netlink 套接字与内核进行交互，配置平板电脑的以太网接口的 DCB 功能，例如：

1. **配置 ETS:**  应用程序可能会设置一个特定的流量类别 (TC) 用于控制指令的传输，并为其分配较高的带宽和严格优先级 (`IEEE_8021QAZ_TSA_STRICT`)，以确保控制指令能够及时发送。这将涉及到填充 `ieee_ets` 结构体并使用 `DCB_CMD_IEEE_SET` 命令和 `DCB_ATTR_IEEE_ETS` 属性。

2. **查询 PFC 状态:**  应用程序可能需要查询网络接口的 PFC 状态，以了解是否存在因拥塞而导致的帧丢失。这将涉及到使用 `DCB_CMD_PFC_GSTATE` 命令和 `DCB_ATTR_PFC_STATE` 属性，内核会返回包含 `ieee_pfc` 结构体的信息。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个头文件本身并没有定义任何 libc 函数。** 它只是定义了数据结构和常量，用于与 Linux 内核的 DCB 子系统进行交互。  实际进行系统调用或 Netlink 通信的 libc 函数可能包括：

* **`socket()`:**  用于创建 Netlink 套接字，以便与内核的 DCB 子系统进行通信。
* **`bind()`:**  将 Netlink 套接字绑定到特定的协议族和组播组（如果需要）。
* **`sendto()`:**  通过 Netlink 套接字向内核发送包含 DCB 配置或查询消息的数据包。消息的格式需要符合这里定义的结构体。
* **`recvfrom()`:**  通过 Netlink 套接字接收来自内核的 DCB 响应消息。接收到的数据需要根据这里定义的结构体进行解析。
* **`ioctl()`:**  在某些情况下，可能使用 `ioctl` 系统调用与网络设备驱动程序进行更底层的 DCB 配置，但这通常发生在驱动程序层面，而不是通过 DCB Netlink 接口。

这些 libc 函数的实现细节非常复杂，涉及操作系统内核的内部机制，超出了这里解释头文件功能的范围。一般来说，它们会：

1. **系统调用入口:**  当用户空间程序调用这些 libc 函数时，会触发一个系统调用，陷入内核态。
2. **内核处理:**  内核接收到系统调用请求后，会根据系统调用号和参数，调用相应的内核函数。
3. **Netlink 通信:**  对于 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等与 Netlink 相关的函数，内核会操作 Netlink 套接字，构建或解析 Netlink 消息，并与相应的 Netlink 协议族（这里是 DCB）的处理程序进行通信。
4. **DCB 子系统交互:**  DCB Netlink 处理程序会解析收到的消息，根据消息中的命令和属性，调用相应的 DCB 内核模块来配置或查询网络设备的状态。
5. **数据返回:**  内核将操作结果或查询到的信息封装成 Netlink 消息，通过 Netlink 套接字返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件与 dynamic linker 没有直接关系。**  Dynamic linker (例如 Android 上的 `linker64` 或 `linker`) 的主要职责是在程序启动时加载和链接共享库 (`.so` 文件)。这个头文件定义的是用于与内核进行网络配置的数据结构，与共享库的加载和链接过程无关。

**如果做了逻辑推理，请给出假设输入与输出:**

以下是一个假设的逻辑推理示例，演示如何使用这些结构体来配置 PFC 功能：

**假设输入:**

* **操作:**  配置网络接口 `eth0` 的 PFC 功能。
* **命令:**  `DCB_CMD_IEEE_SET`
* **属性:**  `DCB_ATTR_IEEE`，其中嵌套了 `DCB_ATTR_IEEE_PFC` 属性。
* **数据:**  一个填充好的 `ieee_pfc` 结构体，例如：
    ```c
    struct ieee_pfc pfc_config;
    memset(&pfc_config, 0, sizeof(pfc_config));
    pfc_config.pfc_cap = 0x01; // 假设支持 PFC
    pfc_config.pfc_en = 0xff;  // 使能所有优先级的 PFC
    pfc_config.mbc = 0;
    pfc_config.delay = 10;
    ```

**逻辑推理:**

1. 用户空间程序创建一个 Netlink 套接字，并绑定到 DCB 协议族。
2. 程序构建一个 Netlink 消息，消息头包含 `DCB_CMD_IEEE_SET` 命令。
3. 消息的 payload 部分包含一个嵌套的属性结构，指示要设置的是 IEEE 802.1Qaz 相关的功能 (`DCB_ATTR_IEEE`)，以及具体的 PFC 配置 (`DCB_ATTR_IEEE_PFC`)。
4. `ieee_pfc` 结构体的数据被添加到 Netlink 消息的 payload 中。
5. 程序使用 `sendto()` 将 Netlink 消息发送到内核。
6. 内核接收到消息后，DCB Netlink 处理程序会解析消息，并调用相应的内核函数来配置 `eth0` 接口的 PFC 功能，根据 `ieee_pfc` 结构体中的数据设置 PFC 的能力、使能状态等。

**假设输出:**

* **成功:**  如果配置成功，内核可能会发送一个 ACK (Acknowledgement) 类型的 Netlink 消息，指示操作成功。
* **失败:**  如果配置失败（例如，网络接口不支持 PFC，或者提供的配置参数无效），内核可能会发送一个包含错误代码的 Netlink 消息。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用错误的命令或属性:**  例如，尝试使用 `DCB_CMD_GSTATE` 命令来设置 PFC 配置，或者使用不适用于 PFC 配置的属性。这会导致内核返回错误，指示命令或属性无效。

2. **填充结构体时数据类型或大小不匹配:**  例如，将一个 `__u32` 类型的值赋给一个 `__u8` 类型的字段，或者填充的结构体大小与预期不符。这可能导致数据解析错误或内核拒绝配置。

3. **忘记设置必要的标志或字段:**  某些 DCB 功能可能依赖于其他功能的先决条件或需要设置特定的标志才能生效。如果用户忘记设置这些必要的标志或字段，配置可能会失败或产生意外的结果。

4. **没有正确处理内核返回的错误:**  用户程序应该检查内核返回的 Netlink 消息，判断操作是否成功。如果没有正确处理错误，可能会导致程序逻辑错误或状态不一致。

5. **在不支持 DCB 的网络接口上尝试配置:**  如果尝试在一个不支持 DCB 功能的网络接口上进行 DCB 配置，内核会返回错误，指示该接口不支持相关的功能。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 DCB 主要在内核层面进行管理，Android Framework 或 NDK 直接使用这个头文件的情况可能不多。更常见的是，Android 系统中负责网络管理的较低层服务或守护进程会与内核的 DCB 子系统进行交互。

**可能的路径:**

1. **Android Framework (Java 层):**  用户可能通过 Android Framework 提供的网络管理 API 进行一些高级的网络配置，例如设置 QoS 策略。

2. **System Services (Native 层):**  Framework 的 API 调用会传递到 native 层的系统服务，例如 `netd` (网络守护进程)。`netd` 负责处理网络配置请求。

3. **Netlink 通信:**  `netd` 或其他相关的 native 服务可能会使用 Netlink 套接字与内核的 DCB 子系统进行通信。这涉及到使用 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等 libc 函数。

4. **Bionic Libc:**  上述 libc 函数的实现位于 Android 的 Bionic C 库中。

5. **Kernel DCB Subsystem:**  内核接收到来自用户空间的 Netlink 消息后，DCB 子系统会根据消息内容进行相应的处理。这个头文件定义的结构体和常量定义了 Netlink 消息的格式。

**Frida Hook 示例:**

可以使用 Frida hook `sendto` 系统调用，并过滤目标地址和协议族，以观察 Android 系统中是否有进程向 DCB Netlink 协议族发送消息。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] sendto() called")
        print(f"[*] PID: {message['pid']}")
        print(f"[*] Destination Address: {message['dest_addr']}")
        print(f"[*] Protocol: {message['protocol']}")
        # 可以进一步解析 data，查看是否是 DCB 相关的消息

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
    Interceptor.attach(Module.findExportByName(null, "sendto"), {
        onEnter: function(args) {
            let sockfd = args[0].toInt32();
            let buf = args[1];
            let len = args[2].toInt32();
            let flags = args[3].toInt32();
            let dest_addr_ptr = args[4];
            let addrlen_ptr = args[5];

            let dest_addr_family = dest_addr_ptr.readU16();

            // 过滤 Netlink 协议族 (AF_NETLINK = 16)
            if (dest_addr_family === 16) {
                let nl_family = dest_addr_ptr.add(2).readU16();
                // 可以进一步过滤 DCB Netlink 协议族 (通常没有固定的值，需要根据具体实现判断)

                let data = Memory.readByteArray(buf, len);

                send({
                    type: 'send',
                    pid: Process.id,
                    dest_addr: hexdump(dest_addr_ptr.readByteArray(16), { ansi: false }),
                    protocol: 'Netlink',
                    data: data
                });
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to exit.")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `frida_hook_dcb.py`。
2. 替换 `<process name or PID>` 为你想要监控的进程名称或 PID，例如 `python frida_hook_dcb.py system_server` 或 `python frida_hook_dcb.py 1000`.
3. 运行 Frida：`frida -U -f <package name>` 或 `frida -U <process name or PID>`。
4. 运行 hook 脚本：`python frida_hook_dcb.py <package name or PID>`。
5. 在 Android 设备上执行可能触发 DCB 相关操作的步骤。
6. 查看 Frida 的输出，看是否有 `sendto()` 调用向 Netlink 协议族发送消息。

**注意:**  DCB 的使用在 Android 上可能比较底层和受限，通常不会有直接的 Framework API 暴露。你可能需要监控底层的网络守护进程或驱动程序才能观察到相关的 Netlink 通信。 找到确切的负责 DCB 配置的进程可能需要一些逆向工程和分析。

希望以上分析能够解答你的问题。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/dcbnl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_DCBNL_H__
#define __LINUX_DCBNL_H__
#include <linux/types.h>
#define IEEE_8021QAZ_MAX_TCS 8
#define IEEE_8021QAZ_TSA_STRICT 0
#define IEEE_8021QAZ_TSA_CB_SHAPER 1
#define IEEE_8021QAZ_TSA_ETS 2
#define IEEE_8021QAZ_TSA_VENDOR 255
struct ieee_ets {
  __u8 willing;
  __u8 ets_cap;
  __u8 cbs;
  __u8 tc_tx_bw[IEEE_8021QAZ_MAX_TCS];
  __u8 tc_rx_bw[IEEE_8021QAZ_MAX_TCS];
  __u8 tc_tsa[IEEE_8021QAZ_MAX_TCS];
  __u8 prio_tc[IEEE_8021QAZ_MAX_TCS];
  __u8 tc_reco_bw[IEEE_8021QAZ_MAX_TCS];
  __u8 tc_reco_tsa[IEEE_8021QAZ_MAX_TCS];
  __u8 reco_prio_tc[IEEE_8021QAZ_MAX_TCS];
};
struct ieee_maxrate {
  __u64 tc_maxrate[IEEE_8021QAZ_MAX_TCS];
};
enum dcbnl_cndd_states {
  DCB_CNDD_RESET = 0,
  DCB_CNDD_EDGE,
  DCB_CNDD_INTERIOR,
  DCB_CNDD_INTERIOR_READY,
};
struct ieee_qcn {
  __u8 rpg_enable[IEEE_8021QAZ_MAX_TCS];
  __u32 rppp_max_rps[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_time_reset[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_byte_reset[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_threshold[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_max_rate[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_ai_rate[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_hai_rate[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_gd[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_min_dec_fac[IEEE_8021QAZ_MAX_TCS];
  __u32 rpg_min_rate[IEEE_8021QAZ_MAX_TCS];
  __u32 cndd_state_machine[IEEE_8021QAZ_MAX_TCS];
};
struct ieee_qcn_stats {
  __u64 rppp_rp_centiseconds[IEEE_8021QAZ_MAX_TCS];
  __u32 rppp_created_rps[IEEE_8021QAZ_MAX_TCS];
};
struct ieee_pfc {
  __u8 pfc_cap;
  __u8 pfc_en;
  __u8 mbc;
  __u16 delay;
  __u64 requests[IEEE_8021QAZ_MAX_TCS];
  __u64 indications[IEEE_8021QAZ_MAX_TCS];
};
#define IEEE_8021Q_MAX_PRIORITIES 8
#define DCBX_MAX_BUFFERS 8
struct dcbnl_buffer {
  __u8 prio2buffer[IEEE_8021Q_MAX_PRIORITIES];
  __u32 buffer_size[DCBX_MAX_BUFFERS];
  __u32 total_size;
};
#define CEE_DCBX_MAX_PGS 8
#define CEE_DCBX_MAX_PRIO 8
struct cee_pg {
  __u8 willing;
  __u8 error;
  __u8 pg_en;
  __u8 tcs_supported;
  __u8 pg_bw[CEE_DCBX_MAX_PGS];
  __u8 prio_pg[CEE_DCBX_MAX_PGS];
};
struct cee_pfc {
  __u8 willing;
  __u8 error;
  __u8 pfc_en;
  __u8 tcs_supported;
};
#define IEEE_8021QAZ_APP_SEL_ETHERTYPE 1
#define IEEE_8021QAZ_APP_SEL_STREAM 2
#define IEEE_8021QAZ_APP_SEL_DGRAM 3
#define IEEE_8021QAZ_APP_SEL_ANY 4
#define IEEE_8021QAZ_APP_SEL_DSCP 5
#define DCB_APP_SEL_PCP 255
struct dcb_app {
  __u8 selector;
  __u8 priority;
  __u16 protocol;
};
#define IEEE_8021QAZ_APP_SEL_MAX 255
struct dcb_peer_app_info {
  __u8 willing;
  __u8 error;
};
struct dcbmsg {
  __u8 dcb_family;
  __u8 cmd;
  __u16 dcb_pad;
};
enum dcbnl_commands {
  DCB_CMD_UNDEFINED,
  DCB_CMD_GSTATE,
  DCB_CMD_SSTATE,
  DCB_CMD_PGTX_GCFG,
  DCB_CMD_PGTX_SCFG,
  DCB_CMD_PGRX_GCFG,
  DCB_CMD_PGRX_SCFG,
  DCB_CMD_PFC_GCFG,
  DCB_CMD_PFC_SCFG,
  DCB_CMD_SET_ALL,
  DCB_CMD_GPERM_HWADDR,
  DCB_CMD_GCAP,
  DCB_CMD_GNUMTCS,
  DCB_CMD_SNUMTCS,
  DCB_CMD_PFC_GSTATE,
  DCB_CMD_PFC_SSTATE,
  DCB_CMD_BCN_GCFG,
  DCB_CMD_BCN_SCFG,
  DCB_CMD_GAPP,
  DCB_CMD_SAPP,
  DCB_CMD_IEEE_SET,
  DCB_CMD_IEEE_GET,
  DCB_CMD_GDCBX,
  DCB_CMD_SDCBX,
  DCB_CMD_GFEATCFG,
  DCB_CMD_SFEATCFG,
  DCB_CMD_CEE_GET,
  DCB_CMD_IEEE_DEL,
  __DCB_CMD_ENUM_MAX,
  DCB_CMD_MAX = __DCB_CMD_ENUM_MAX - 1,
};
enum dcbnl_attrs {
  DCB_ATTR_UNDEFINED,
  DCB_ATTR_IFNAME,
  DCB_ATTR_STATE,
  DCB_ATTR_PFC_STATE,
  DCB_ATTR_PFC_CFG,
  DCB_ATTR_NUM_TC,
  DCB_ATTR_PG_CFG,
  DCB_ATTR_SET_ALL,
  DCB_ATTR_PERM_HWADDR,
  DCB_ATTR_CAP,
  DCB_ATTR_NUMTCS,
  DCB_ATTR_BCN,
  DCB_ATTR_APP,
  DCB_ATTR_IEEE,
  DCB_ATTR_DCBX,
  DCB_ATTR_FEATCFG,
  DCB_ATTR_CEE,
  __DCB_ATTR_ENUM_MAX,
  DCB_ATTR_MAX = __DCB_ATTR_ENUM_MAX - 1,
};
enum ieee_attrs {
  DCB_ATTR_IEEE_UNSPEC,
  DCB_ATTR_IEEE_ETS,
  DCB_ATTR_IEEE_PFC,
  DCB_ATTR_IEEE_APP_TABLE,
  DCB_ATTR_IEEE_PEER_ETS,
  DCB_ATTR_IEEE_PEER_PFC,
  DCB_ATTR_IEEE_PEER_APP,
  DCB_ATTR_IEEE_MAXRATE,
  DCB_ATTR_IEEE_QCN,
  DCB_ATTR_IEEE_QCN_STATS,
  DCB_ATTR_DCB_BUFFER,
  DCB_ATTR_DCB_APP_TRUST_TABLE,
  DCB_ATTR_DCB_REWR_TABLE,
  __DCB_ATTR_IEEE_MAX
};
#define DCB_ATTR_IEEE_MAX (__DCB_ATTR_IEEE_MAX - 1)
enum ieee_attrs_app {
  DCB_ATTR_IEEE_APP_UNSPEC,
  DCB_ATTR_IEEE_APP,
  DCB_ATTR_DCB_APP,
  __DCB_ATTR_IEEE_APP_MAX
};
#define DCB_ATTR_IEEE_APP_MAX (__DCB_ATTR_IEEE_APP_MAX - 1)
enum cee_attrs {
  DCB_ATTR_CEE_UNSPEC,
  DCB_ATTR_CEE_PEER_PG,
  DCB_ATTR_CEE_PEER_PFC,
  DCB_ATTR_CEE_PEER_APP_TABLE,
  DCB_ATTR_CEE_TX_PG,
  DCB_ATTR_CEE_RX_PG,
  DCB_ATTR_CEE_PFC,
  DCB_ATTR_CEE_APP_TABLE,
  DCB_ATTR_CEE_FEAT,
  __DCB_ATTR_CEE_MAX
};
#define DCB_ATTR_CEE_MAX (__DCB_ATTR_CEE_MAX - 1)
enum peer_app_attr {
  DCB_ATTR_CEE_PEER_APP_UNSPEC,
  DCB_ATTR_CEE_PEER_APP_INFO,
  DCB_ATTR_CEE_PEER_APP,
  __DCB_ATTR_CEE_PEER_APP_MAX
};
#define DCB_ATTR_CEE_PEER_APP_MAX (__DCB_ATTR_CEE_PEER_APP_MAX - 1)
enum cee_attrs_app {
  DCB_ATTR_CEE_APP_UNSPEC,
  DCB_ATTR_CEE_APP,
  __DCB_ATTR_CEE_APP_MAX
};
#define DCB_ATTR_CEE_APP_MAX (__DCB_ATTR_CEE_APP_MAX - 1)
enum dcbnl_pfc_up_attrs {
  DCB_PFC_UP_ATTR_UNDEFINED,
  DCB_PFC_UP_ATTR_0,
  DCB_PFC_UP_ATTR_1,
  DCB_PFC_UP_ATTR_2,
  DCB_PFC_UP_ATTR_3,
  DCB_PFC_UP_ATTR_4,
  DCB_PFC_UP_ATTR_5,
  DCB_PFC_UP_ATTR_6,
  DCB_PFC_UP_ATTR_7,
  DCB_PFC_UP_ATTR_ALL,
  __DCB_PFC_UP_ATTR_ENUM_MAX,
  DCB_PFC_UP_ATTR_MAX = __DCB_PFC_UP_ATTR_ENUM_MAX - 1,
};
enum dcbnl_pg_attrs {
  DCB_PG_ATTR_UNDEFINED,
  DCB_PG_ATTR_TC_0,
  DCB_PG_ATTR_TC_1,
  DCB_PG_ATTR_TC_2,
  DCB_PG_ATTR_TC_3,
  DCB_PG_ATTR_TC_4,
  DCB_PG_ATTR_TC_5,
  DCB_PG_ATTR_TC_6,
  DCB_PG_ATTR_TC_7,
  DCB_PG_ATTR_TC_MAX,
  DCB_PG_ATTR_TC_ALL,
  DCB_PG_ATTR_BW_ID_0,
  DCB_PG_ATTR_BW_ID_1,
  DCB_PG_ATTR_BW_ID_2,
  DCB_PG_ATTR_BW_ID_3,
  DCB_PG_ATTR_BW_ID_4,
  DCB_PG_ATTR_BW_ID_5,
  DCB_PG_ATTR_BW_ID_6,
  DCB_PG_ATTR_BW_ID_7,
  DCB_PG_ATTR_BW_ID_MAX,
  DCB_PG_ATTR_BW_ID_ALL,
  __DCB_PG_ATTR_ENUM_MAX,
  DCB_PG_ATTR_MAX = __DCB_PG_ATTR_ENUM_MAX - 1,
};
enum dcbnl_tc_attrs {
  DCB_TC_ATTR_PARAM_UNDEFINED,
  DCB_TC_ATTR_PARAM_PGID,
  DCB_TC_ATTR_PARAM_UP_MAPPING,
  DCB_TC_ATTR_PARAM_STRICT_PRIO,
  DCB_TC_ATTR_PARAM_BW_PCT,
  DCB_TC_ATTR_PARAM_ALL,
  __DCB_TC_ATTR_PARAM_ENUM_MAX,
  DCB_TC_ATTR_PARAM_MAX = __DCB_TC_ATTR_PARAM_ENUM_MAX - 1,
};
enum dcbnl_cap_attrs {
  DCB_CAP_ATTR_UNDEFINED,
  DCB_CAP_ATTR_ALL,
  DCB_CAP_ATTR_PG,
  DCB_CAP_ATTR_PFC,
  DCB_CAP_ATTR_UP2TC,
  DCB_CAP_ATTR_PG_TCS,
  DCB_CAP_ATTR_PFC_TCS,
  DCB_CAP_ATTR_GSP,
  DCB_CAP_ATTR_BCN,
  DCB_CAP_ATTR_DCBX,
  __DCB_CAP_ATTR_ENUM_MAX,
  DCB_CAP_ATTR_MAX = __DCB_CAP_ATTR_ENUM_MAX - 1,
};
#define DCB_CAP_DCBX_HOST 0x01
#define DCB_CAP_DCBX_LLD_MANAGED 0x02
#define DCB_CAP_DCBX_VER_CEE 0x04
#define DCB_CAP_DCBX_VER_IEEE 0x08
#define DCB_CAP_DCBX_STATIC 0x10
enum dcbnl_numtcs_attrs {
  DCB_NUMTCS_ATTR_UNDEFINED,
  DCB_NUMTCS_ATTR_ALL,
  DCB_NUMTCS_ATTR_PG,
  DCB_NUMTCS_ATTR_PFC,
  __DCB_NUMTCS_ATTR_ENUM_MAX,
  DCB_NUMTCS_ATTR_MAX = __DCB_NUMTCS_ATTR_ENUM_MAX - 1,
};
enum dcbnl_bcn_attrs {
  DCB_BCN_ATTR_UNDEFINED = 0,
  DCB_BCN_ATTR_RP_0,
  DCB_BCN_ATTR_RP_1,
  DCB_BCN_ATTR_RP_2,
  DCB_BCN_ATTR_RP_3,
  DCB_BCN_ATTR_RP_4,
  DCB_BCN_ATTR_RP_5,
  DCB_BCN_ATTR_RP_6,
  DCB_BCN_ATTR_RP_7,
  DCB_BCN_ATTR_RP_ALL,
  DCB_BCN_ATTR_BCNA_0,
  DCB_BCN_ATTR_BCNA_1,
  DCB_BCN_ATTR_ALPHA,
  DCB_BCN_ATTR_BETA,
  DCB_BCN_ATTR_GD,
  DCB_BCN_ATTR_GI,
  DCB_BCN_ATTR_TMAX,
  DCB_BCN_ATTR_TD,
  DCB_BCN_ATTR_RMIN,
  DCB_BCN_ATTR_W,
  DCB_BCN_ATTR_RD,
  DCB_BCN_ATTR_RU,
  DCB_BCN_ATTR_WRTT,
  DCB_BCN_ATTR_RI,
  DCB_BCN_ATTR_C,
  DCB_BCN_ATTR_ALL,
  __DCB_BCN_ATTR_ENUM_MAX,
  DCB_BCN_ATTR_MAX = __DCB_BCN_ATTR_ENUM_MAX - 1,
};
enum dcb_general_attr_values {
  DCB_ATTR_VALUE_UNDEFINED = 0xff
};
#define DCB_APP_IDTYPE_ETHTYPE 0x00
#define DCB_APP_IDTYPE_PORTNUM 0x01
enum dcbnl_app_attrs {
  DCB_APP_ATTR_UNDEFINED,
  DCB_APP_ATTR_IDTYPE,
  DCB_APP_ATTR_ID,
  DCB_APP_ATTR_PRIORITY,
  __DCB_APP_ATTR_ENUM_MAX,
  DCB_APP_ATTR_MAX = __DCB_APP_ATTR_ENUM_MAX - 1,
};
#define DCB_FEATCFG_ERROR 0x01
#define DCB_FEATCFG_ENABLE 0x02
#define DCB_FEATCFG_WILLING 0x04
#define DCB_FEATCFG_ADVERTISE 0x08
enum dcbnl_featcfg_attrs {
  DCB_FEATCFG_ATTR_UNDEFINED,
  DCB_FEATCFG_ATTR_ALL,
  DCB_FEATCFG_ATTR_PG,
  DCB_FEATCFG_ATTR_PFC,
  DCB_FEATCFG_ATTR_APP,
  __DCB_FEATCFG_ATTR_ENUM_MAX,
  DCB_FEATCFG_ATTR_MAX = __DCB_FEATCFG_ATTR_ENUM_MAX - 1,
};
#endif
```