Response:
Let's break down the thought process for analyzing this C header file and generating the detailed response.

**1. Initial Understanding of the File's Purpose:**

The first step is to recognize that this is a header file (`.h`) located within the Android Bionic library (`bionic/libc/kernel/uapi/linux/`). The filename `ethtool_netlink.h` combined with the "auto-generated" comment strongly suggests it's related to the `ethtool` utility and network interface configuration, specifically using the Netlink protocol for communication. The `uapi` directory indicates it's an interface between user-space and kernel-space.

**2. High-Level Functionality Identification:**

Scanning the `#define` and `enum` declarations gives a quick overview of the file's content. Key observations include:

* **Message Types (`ETHTOOL_MSG_USER_*`, `ETHTOOL_MSG_KERNEL_*`):** These suggest the file defines the different types of messages exchanged between user-space and the kernel related to `ethtool`.
* **Attribute Enums (`ETHTOOL_A_*`):**  These define the specific data fields or attributes within the Netlink messages. The hierarchical naming (e.g., `ETHTOOL_A_LINKINFO_*`) hints at different categories of information.
* **Constants (`ETHTOOL_FLAG_*`, `#define ETHTOOL_GENL_NAME`, etc.):** These provide specific values and identifiers used in the communication.

Based on these observations, the core functionality is clearly about defining the structure and types of messages used to configure and query network interface settings using `ethtool` and Netlink.

**3. Deeper Dive into Enumerations and Constants:**

Now, the analysis gets more detailed. Examine each `enum` and `#define` to understand its specific role:

* **`ETHTOOL_MSG_USER_*`:**  These are actions initiated by the user-space (like getting link information, setting debug flags, etc.). The names are quite descriptive.
* **`ETHTOOL_MSG_KERNEL_*`:** These are the kernel's responses or notifications corresponding to user requests. The `_REPLY` and `_NTF` suffixes are key.
* **`ethtool_header_flags`:** These are flags that modify the behavior of the Netlink messages (compact bitsets, omitting replies, requesting statistics).
* **`ETHTOOL_A_HEADER_*`:**  These are attributes within the general message header (device index, name, flags).
* **The remaining `ETHTOOL_A_*` enums:** These represent the specific data fields for each type of message (link info, link modes, features, rings, etc.). This is where the bulk of the interface definition resides.

**4. Connecting to Android Functionality:**

The prompt specifically asks about Android relevance. The key connection is the `ethtool` utility itself. Android uses the Linux kernel, and `ethtool` is a standard Linux tool for configuring network interface card (NIC) settings. Therefore, this header file is essential for any Android component that needs to interact with the network hardware at a low level.

* **Examples:**  Think about how Android configures network interfaces (Wi-Fi, Ethernet, etc.). While the high-level framework handles much of this, underlying tools like `ifconfig` (or its modern replacements) and potentially even direct interaction with Netlink sockets (using this header) are involved. Consider scenarios like setting the link speed, duplex mode, enabling/disabling features, or getting detailed statistics.

**5. Addressing Specific Prompt Requirements:**

The prompt has several specific points to address:

* **libc Functions:**  This header file *doesn't directly define libc functions*. It defines constants and enums that *libc functions might use* when interacting with the kernel via Netlink sockets. The core libc function involved would be `socket()`, `bind()`, `sendto()`, `recvfrom()`, and related network socket functions. Explain these functions at a high level.
* **Dynamic Linker:**  This header file is a *static* header file. It doesn't directly involve the dynamic linker. However, if user-space programs use functions that interact with the kernel based on these definitions, then the dynamic linker is involved in loading the necessary libraries. Create a simple example SO layout and illustrate the linking process (finding symbols, resolving addresses).
* **Logic and Assumptions:** When explaining the message flow, make assumptions about the user wanting to get information or set a parameter. Provide example input (a user requesting link info for a specific interface) and the expected output (the kernel's response with the link details).
* **Common Errors:** Think about mistakes a programmer might make when using these definitions (incorrectly constructing messages, misinterpreting return values, using the wrong attribute IDs).
* **Android Framework/NDK Path:** Trace the flow from a high-level Android setting down to the potential use of these definitions. Start with a user interaction (e.g., toggling Wi-Fi), go through the framework services, and explain how it might eventually involve kernel interaction via Netlink and `ethtool`.
* **Frida Hook:**  Provide practical Frida examples showing how to intercept and observe the Netlink messages being sent and received, focusing on the key parts of the message structure as defined in the header file.

**6. Structuring the Response:**

Organize the information logically, using clear headings and subheadings. Address each part of the prompt systematically. Use code blocks for the header file content, SO layout, and Frida scripts. Use bolding and formatting to highlight important terms and concepts.

**7. Review and Refinement:**

After drafting the response, review it carefully for accuracy, clarity, and completeness. Ensure all parts of the prompt have been addressed adequately. Check for any technical errors or inconsistencies. Improve the wording and flow for better readability. For example, ensure the explanation of the dynamic linker's role is accurate (it's indirect).

By following this structured approach, combining initial understanding with detailed analysis, and explicitly addressing each requirement of the prompt, a comprehensive and informative response can be generated. The key is to break down the complex information into manageable chunks and build upon the initial understanding.
```chinese
这是一个定义了用于与 Linux 内核中的 ethtool 功能进行 Netlink 通信的用户空间 API 的 C 头文件。 `ethtool` 是一个 Linux 命令行实用程序，用于查询和控制以太网网络接口卡的驱动程序和硬件设置。 Netlink 是一种用于在内核空间和用户空间进程之间进行通信的套接字。

**功能列表:**

这个头文件定义了以下功能，这些功能描述了用户空间程序如何通过 Netlink 与内核中的 ethtool 功能进行交互：

1. **定义 Netlink 消息类型:**
   - `ETHTOOL_MSG_USER_*`: 定义了用户空间可以发送给内核的请求消息类型，例如获取/设置链路信息、链路模式、状态、调试信息、唤醒方式 (WoL)、特性、私有标志、环形缓冲区大小、通道数量、合并参数、暂停参数、节能以太网 (EEE) 参数、时间戳信息、电缆测试、隧道信息、前向纠错 (FEC) 参数、模块 EEPROM、统计信息、物理时钟 (PHC) 虚拟时钟、模块信息、PSE (Power Sourcing Equipment) 信息、RSS (Receive Side Scaling) 配置、PLCA (Physical Layer Collision Avoidance) 配置和状态、MM (Media Monitoring) 配置和状态、模块固件刷新以及物理层 (PHY) 信息。
   - `ETHTOOL_MSG_KERNEL_*`: 定义了内核响应用户空间请求或发送通知的消息类型。这些消息通常是对应用户空间请求的回复（以 `_REPLY` 结尾）或异步事件的通知（以 `_NTF` 结尾）。

2. **定义 Netlink 消息头部的标志:**
   - `ethtool_header_flags`:  定义了 Netlink 消息头部可以包含的标志，例如 `ETHTOOL_FLAG_COMPACT_BITSETS` (指示使用紧凑的位集表示)、`ETHTOOL_FLAG_OMIT_REPLY` (指示内核不需要回复) 和 `ETHTOOL_FLAG_STATS` (与统计信息相关)。

3. **定义 Netlink 属性 (Attributes):**
   - 大量的 `ETHTOOL_A_*` 枚举定义了 Netlink 消息中可以包含的各种属性 (TLV 结构中的 T 部分)。 这些属性用于携带具体的配置参数、状态信息和请求参数。 例如：
     - `ETHTOOL_A_HEADER_*`: 定义了消息头部的属性，如设备索引、设备名称、标志等。
     - `ETHTOOL_A_LINKINFO_*`: 定义了链路信息的属性，如端口类型、物理地址、MDI-X 设置、收发器类型等。
     - `ETHTOOL_A_LINKMODES_*`: 定义了链路模式的属性，如自动协商、支持的模式、速率、双工模式等。
     - `ETHTOOL_A_FEATURES_*`: 定义了网卡特性的属性，如硬件支持、期望状态、当前激活状态等。
     - ... 以及其他各种与网卡配置和状态相关的属性。

**与 Android 功能的关系及举例说明:**

这个头文件直接关系到 Android 设备中网络接口的管理和配置。 Android 系统底层依赖 Linux 内核，因此 `ethtool` 功能在 Android 中仍然存在并被使用。 虽然 Android 应用程序通常不会直接调用这些底层的 Netlink 接口，但 Android Framework 可能会在后台使用它们来管理网络连接。

**举例说明:**

* **获取网络接口信息:** Android Framework 可以使用这些 Netlink 消息来获取网络接口的链路状态（连接/断开）、速度、双工模式等信息，并在“设置”应用中显示给用户。例如，当你在 Android 手机的“设置”->“WLAN”或“以太网”中查看连接详情时，系统可能在底层使用了 `ETHTOOL_MSG_LINKSTATE_GET` 请求来获取信息。
* **配置网络接口特性:**  某些高级网络配置，例如控制硬件卸载功能 (TSO, GRO)，可能涉及到使用 `ETHTOOL_MSG_FEATURES_GET/SET` 来查询或修改网卡的特性。虽然用户通常不能直接配置这些，但 Android 系统可能会根据网络类型或系统策略进行自动调整。
* **调试网络问题:**  在开发和调试 Android 网络相关问题时，工程师可能会使用 `ethtool` 命令行工具（通过 adb shell）来检查网络接口的配置和状态，这会直接涉及到这里定义的 Netlink 消息和属性。例如，使用 `ethtool eth0` 命令会触发用户空间程序发送相应的 Netlink 请求到内核。

**libc 函数的功能实现:**

这个头文件本身并不定义 libc 函数，它只是定义了常量和数据结构。 然而，用户空间程序需要使用 libc 提供的网络相关的函数来构建和发送/接收 Netlink 消息。 涉及到的 libc 函数主要有：

* **`socket()`:** 创建一个 Netlink 套接字。 使用 `AF_NETLINK` 协议族和 `NETLINK_GENERIC` 或 `NETLINK_ROUTE` 协议类型（取决于具体的 ethtool 实现）。
* **`bind()`:**  将 Netlink 套接字绑定到一个本地地址。 对于用户空间程序，通常将端口 ID 设置为 0 或 `getpid()`。
* **`sendto()`:**  通过 Netlink 套接字向内核发送消息。 消息的内容会根据这里定义的结构和消息类型进行构造。
* **`recvfrom()`:**  通过 Netlink 套接字接收来自内核的回复或通知消息。
* **`nl_socket_alloc()`, `genlmsg_put()`, `nla_put()` (libnl 库):**  更方便地构建和解析 Netlink 消息的函数，很多用户空间工具 (包括 `ethtool` 命令行工具本身) 会使用 `libnl` 库来简化 Netlink 编程。

**详细解释 libc 函数的功能是如何实现的:**

由于这些是标准的 POSIX 网络函数，其实现细节相当复杂，并涉及到操作系统内核的网络协议栈。 简要来说：

* **`socket()` 的实现:**  在内核中创建一个表示套接字的文件描述符，并分配相应的内核数据结构来管理该套接字的状态 (例如，接收和发送缓冲区、协议相关信息等)。 对于 Netlink 套接字，会关联到 Netlink 协议族的处理函数。
* **`bind()` 的实现:**  将套接字与一个本地地址 (对于 Netlink 来说，主要是进程 ID 或端口 ID) 关联起来。 这使得内核可以将发送到特定进程的消息路由到该套接字。
* **`sendto()` 的实现:**  将用户空间传递的数据拷贝到内核空间，并根据指定的协议 (Netlink) 和目标地址 (内核 Netlink 组或进程) 进行封装，然后放入发送队列中。 内核的网络协议栈会处理消息的路由和发送。
* **`recvfrom()` 的实现:**  检查套接字的接收队列是否有数据。 如果有，将数据拷贝到用户空间提供的缓冲区中。 如果没有数据，调用进程可能会被阻塞，直到有数据到达。

**涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身是静态包含的，不涉及动态链接。 然而，如果用户空间程序使用了需要与 ethtool 进行 Netlink 通信的库 (例如 `libnl`), 那么动态链接器就会发挥作用。

**so 布局样本 (假设用户程序 `my_ethtool_app` 使用了 `libnl.so`):**

```
/system/bin/my_ethtool_app  // 可执行文件
/system/lib/libnl.so        // 动态链接库
/system/lib64/libnl.so     // 64位系统的动态链接库
/linker                    // 32位系统的动态链接器
/linker64                   // 64位系统的动态链接器
```

**链接的处理过程:**

1. **加载可执行文件:** 当 Android 系统启动 `my_ethtool_app` 时，内核会加载其代码段和数据段到内存中。
2. **解析依赖:** 动态链接器 ( `/linker` 或 `/linker64` ) 会读取 `my_ethtool_app` 的 ELF 头，找到其依赖的动态链接库列表 (例如 `libnl.so`)。
3. **查找共享库:** 动态链接器会在预定义的路径 (通常在 `/system/lib`, `/vendor/lib` 等) 中查找这些依赖的共享库。
4. **加载共享库:** 找到 `libnl.so` 后，动态链接器会将其加载到内存中。
5. **符号解析 (Symbol Resolution):** 动态链接器会遍历 `my_ethtool_app` 的重定位表，找到所有对外部符号的引用 (例如 `libnl.so` 中提供的函数，如 `nl_socket_alloc`)。 然后，它会在已加载的共享库的符号表中查找这些符号的地址。
6. **重定位 (Relocation):** 找到符号地址后，动态链接器会修改 `my_ethtool_app` 代码段和数据段中的相应位置，将对外部符号的引用替换为实际的内存地址。 这使得 `my_ethtool_app` 可以正确地调用 `libnl.so` 中提供的函数。
7. **执行程序:**  重定位完成后，`my_ethtool_app` 就可以开始执行了。 当它调用 `libnl.so` 中的函数时，程序的执行流程会跳转到 `libnl.so` 的相应代码段。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要获取网络接口 `eth0` 的链路信息。

**假设输入:**

* 程序构造一个 Netlink 消息，消息类型为 `ETHTOOL_MSG_LINKINFO_GET`。
* 消息头部包含目标设备索引，对应于 `eth0`。 设备索引通常可以通过其他方式 (如 `ioctl` 调用) 获取。
* 消息的属性部分可能包含 `ETHTOOL_A_HEADER_DEV_NAME`，值为 "eth0"。

**预期输出 (内核的响应):**

* 内核会回复一个 Netlink 消息，消息类型为 `ETHTOOL_MSG_LINKINFO_GET_REPLY`。
* 消息头部包含与请求消息相同的序列号等信息，用于匹配请求和响应。
* 消息的属性部分会包含以下属性以及对应的值：
    * `ETHTOOL_A_LINKINFO_PORT`:  例如，`PORT_FIBRE` 或 `PORT_TP` (光纤或双绞线)
    * `ETHTOOL_A_LINKINFO_PHYADDR`: 例如，网卡的物理地址 (MAC 地址)。
    * `ETHTOOL_A_LINKINFO_TP_MDIX`: 例如，`MDIX_AUTO`、`MDIX_NORMAL`、`MDIX_CROSSED`。
    * `ETHTOOL_A_LINKINFO_TP_MDIX_CTRL`: 例如，`MDIX_CTRL_AUTO`、`MDIX_CTRL_NORMAL`、`MDIX_CTRL_CROSSED`。
    * `ETHTOOL_A_LINKINFO_TRANSCEIVER`: 例如，`XCVR_INTERNAL`、`XCVR_EXTERNAL`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **消息类型错误:**  用户空间程序发送了错误的 `ETHTOOL_MSG_*` 类型，导致内核无法识别请求或执行错误的操作。 例如，本应该发送 `ETHTOOL_MSG_LINKSTATE_GET` 却发送了 `ETHTOOL_MSG_LINKINFO_GET`。
2. **属性错误或缺失:**  构造 Netlink 消息时，缺少必要的属性或使用了错误的属性 ID。 例如，在设置链路模式时，忘记包含 `ETHTOOL_A_LINKMODES_SPEED` 和 `ETHTOOL_A_LINKMODES_DUPLEX` 属性。
3. **属性值错误:**  提供的属性值超出有效范围或类型不匹配。 例如，尝试将链路速度设置为一个不支持的值。
4. **Netlink 套接字未正确绑定:** 用户空间程序没有正确地绑定 Netlink 套接字，导致内核无法将响应消息路由回程序。
5. **权限不足:**  某些 ethtool 操作需要 root 权限。 非 root 用户尝试执行这些操作会失败。
6. **解析内核响应错误:** 用户空间程序在接收到内核的 Netlink 消息后，未能正确解析消息的结构和属性，导致信息提取错误。
7. **内存管理错误:**  在构造和解析 Netlink 消息时，发生内存泄漏或缓冲区溢出。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android 应用程序不会直接使用这些底层的 `ethtool` Netlink 接口。 更多的是 Android Framework 的系统服务在后台进行操作。

**Android Framework 到达这里的步骤 (示例：获取 Wi-Fi 接口信息):**

1. **用户操作:** 用户在 Android 设置中查看 Wi-Fi 连接详情。
2. **Settings 应用请求:** Settings 应用通过 Binder IPC 调用某个 System Service (例如 `WifiService` 或 `ConnectivityService`) 获取 Wi-Fi 接口的信息。
3. **System Service 处理:**  `WifiService` 或 `ConnectivityService` 可能会：
   -  读取系统属性 (`getprop`)，这些属性可能由更底层的服务设置。
   -  使用 `ioctl` 系统调用与网络驱动程序进行交互 (虽然 `ethtool` 是更常用的方式来获取更详细的硬件信息)。
   -  在某些情况下，为了获取更底层的硬件信息，可能会有守护进程或系统服务使用 Netlink 套接字和 `ethtool` 相关的消息与内核通信。 这通常发生在需要获取更详细的链路状态、统计信息或配置硬件特性时。
4. **内核交互:**  如果使用了 Netlink 和 `ethtool`:
   - 系统服务或守护进程会创建一个 Netlink 套接字。
   - 构造包含 `ETHTOOL_MSG_*` 类型和相关属性的 Netlink 消息。
   - 使用 `sendto()` 将消息发送到内核。
   - 内核中的 ethtool 处理程序接收消息并执行相应的操作。
   - 内核构造包含 `ETHTOOL_MSG_*_REPLY` 或 `ETHTOOL_MSG_*_NTF` 的 Netlink 响应消息。
   - 使用 `recvfrom()` 接收来自内核的响应。
5. **信息返回:** 系统服务将获取到的信息通过 Binder IPC 返回给 Settings 应用。
6. **显示给用户:** Settings 应用将信息展示给用户。

**Frida Hook 示例调试步骤:**

以下 Frida 脚本示例可以 hook `sendto` 系统调用，以便在 Android 系统中查看是否有进程发送了与 `ethtool` 相关的 Netlink 消息。

```javascript
// frida hook 示例

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function getMessageType(data) {
  // 假设 Netlink 消息头部的前 4 个字节是消息长度
  // 紧接着的 2 个字节是消息类型（猜测，实际结构可能更复杂）
  if (data.byteLength >= 6) {
    const dataview = new DataView(data);
    const messageType = dataview.getUint16(4, littleEndian = true); // 假设是小端序
    for (const key in ETHTOOL_MSG_USER) {
      if (ETHTOOL_MSG_USER[key] === messageType) {
        return `ETHTOOL_MSG_USER.${key}`;
      }
    }
    for (const key in ETHTOOL_MSG_KERNEL) {
      if (ETHTOOL_MSG_KERNEL[key] === messageType) {
        return `ETHTOOL_MSG_KERNEL.${key}`;
      }
    }
    return `Unknown message type: ${messageType}`;
  }
  return "Data too short";
}

const ETHTOOL_MSG_USER = {
  ETHTOOL_MSG_USER_NONE: 0,
  ETHTOOL_MSG_STRSET_GET: 1,
  ETHTOOL_MSG_LINKINFO_GET: 2,
  ETHTOOL_MSG_LINKINFO_SET: 3,
  ETHTOOL_MSG_LINKMODES_GET: 4,
  ETHTOOL_MSG_LINKMODES_SET: 5,
  ETHTOOL_MSG_LINKSTATE_GET: 6,
  ETHTOOL_MSG_DEBUG_GET: 7,
  ETHTOOL_MSG_DEBUG_SET: 8,
  ETHTOOL_MSG_WOL_GET: 9,
  ETHTOOL_MSG_WOL_SET: 10,
  ETHTOOL_MSG_FEATURES_GET: 11,
  ETHTOOL_MSG_FEATURES_SET: 12,
  ETHTOOL_MSG_PRIVFLAGS_GET: 13,
  ETHTOOL_MSG_PRIVFLAGS_SET: 14,
  ETHTOOL_MSG_RINGS_GET: 15,
  ETHTOOL_MSG_RINGS_SET: 16,
  ETHTOOL_MSG_CHANNELS_GET: 17,
  ETHTOOL_MSG_CHANNELS_SET: 18,
  ETHTOOL_MSG_COALESCE_GET: 19,
  ETHTOOL_MSG_COALESCE_SET: 20,
  ETHTOOL_MSG_PAUSE_GET: 21,
  ETHTOOL_MSG_PAUSE_SET: 22,
  ETHTOOL_MSG_EEE_GET: 23,
  ETHTOOL_MSG_EEE_SET: 24,
  ETHTOOL_MSG_TSINFO_GET: 25,
  ETHTOOL_MSG_CABLE_TEST_ACT: 26,
  ETHTOOL_MSG_CABLE_TEST_TDR_ACT: 27,
  ETHTOOL_MSG_TUNNEL_INFO_GET: 28,
  ETHTOOL_MSG_FEC_GET: 29,
  ETHTOOL_MSG_FEC_SET: 30,
  ETHTOOL_MSG_MODULE_EEPROM_GET: 31,
  ETHTOOL_MSG_STATS_GET: 32,
  ETHTOOL_MSG_PHC_VCLOCKS_GET: 33,
  ETHTOOL_MSG_MODULE_GET: 34,
  ETHTOOL_MSG_MODULE_SET: 35,
  ETHTOOL_MSG_PSE_GET: 36,
  ETHTOOL_MSG_PSE_SET: 37,
  ETHTOOL_MSG_RSS_GET: 38,
  ETHTOOL_MSG_PLCA_GET_CFG: 39,
  ETHTOOL_MSG_PLCA_SET_CFG: 40,
  ETHTOOL_MSG_PLCA_GET_STATUS: 41,
  ETHTOOL_MSG_MM_GET: 42,
  ETHTOOL_MSG_MM_SET: 43,
  ETHTOOL_MSG_MODULE_FW_FLASH_ACT: 44,
  ETHTOOL_MSG_PHY_GET: 45,
};

const ETHTOOL_MSG_KERNEL = {
  ETHTOOL_MSG_KERNEL_NONE: 0,
  ETHTOOL_MSG_STRSET_GET_REPLY: 1,
  ETHTOOL_MSG_LINKINFO_GET_REPLY: 2,
  ETHTOOL_MSG_LINKINFO_NTF: 3,
  ETHTOOL_MSG_LINKMODES_GET_REPLY: 4,
  ETHTOOL_MSG_LINKMODES_NTF: 5,
  ETHTOOL_MSG_LINKSTATE_GET_REPLY: 6,
  ETHTOOL_MSG_DEBUG_GET_REPLY: 7,
  ETHTOOL_MSG_DEBUG_NTF: 8,
  ETHTOOL_MSG_WOL_GET_REPLY: 9,
  ETHTOOL_MSG_WOL_NTF: 10,
  ETHTOOL_MSG_FEATURES_GET_REPLY: 11,
  ETHTOOL_MSG_FEATURES_SET_REPLY: 12,
  ETHTOOL_MSG_FEATURES_NTF: 13,
  ETHTOOL_MSG_PRIVFLAGS_GET_REPLY: 14,
  ETHTOOL_MSG_PRIVFLAGS_NTF: 15,
  ETHTOOL_MSG_RINGS_GET_REPLY: 16,
  ETHTOOL_MSG_RINGS_NTF: 17,
  ETHTOOL_MSG_CHANNELS_GET_REPLY: 18,
  ETHTOOL_MSG_CHANNELS_NTF: 19,
  ETHTOOL_MSG_COALESCE_GET_REPLY: 20,
  ETHTOOL_MSG_COALESCE_NTF: 21,
  ETHTOOL_MSG_PAUSE_GET_REPLY: 22,
  ETHTOOL_MSG_PAUSE_NTF: 23,
  ETHTOOL_MSG_EEE_GET_REPLY: 24,
  ETHTOOL_MSG_EEE_NTF: 25,
  ETHTOOL_MSG_TSINFO_GET_REPLY: 26,
  ETHTOOL_MSG_CABLE_TEST_NTF: 27,
  ETHTOOL_MSG_CABLE_TEST_TDR_NTF: 28,
  ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY: 29,
  ETHTOOL_MSG_FEC_GET_REPLY: 30,
  ETHTOOL_MSG_FEC_NTF: 31,
  ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY: 32,
  ETHTOOL_MSG_STATS_GET_REPLY: 33,
  ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY: 34,
  ETHTOOL_MSG_MODULE_GET_REPLY: 35,
  ETHTOOL_MSG_MODULE_NTF: 36,
  ETHTOOL_MSG_PSE_GET_REPLY: 37,
  ETHTOOL_MSG_RSS_GET_REPLY: 38,
  ETHTOOL_MSG_PLCA_GET_CFG_REPLY: 39,
  ETHTOOL_MSG_PLCA_GET_STATUS_REPLY: 40,
  ETHTOOL_MSG_PLCA_NTF: 41,
  ETHTOOL_MSG_MM_GET_REPLY: 42,
  ETHTOOL_MSG_MM_NTF: 43,
  ETHTOOL_MSG_MODULE_FW_FLASH_NTF: 44,
  ETHTOOL_MSG_PHY_GET_REPLY: 45,
  ETHTOOL_MSG_PHY_NTF: 46,
};

Interceptor.attach(Module.findExportByName(null, "sendto"), {
  onEnter: function (args) {
    const sockfd = args[0];
    const buf = args[1];
    const len = args[2].toInt();
    const dest_addr = args[3];

    const buffer = Buffer.alloc(len);
    Memory.copy(buffer.unwrap(), buf, len);

    const addressFamily = Memory.readU16(dest_addr);

    if (addressFamily === 16) { // AF_NETLINK 的值为 16
      console.log(`[SendTo] PID: ${Process.id}, FD: ${sockfd}, Length: ${len}`);
      console.log(`[SendTo] Destination Address Family: AF_NETLINK`);

      // 尝试解析 Netlink 消息类型
      console.log(`[SendTo] Netlink Message Type: ${getMessageType(buffer)}`);
      // 可以进一步解析 Netlink 消息的头部和属性
      // ...
    }
  },
});
```

**使用方法:**

1. 将以上 JavaScript 代码保存为 `.js` 文件 (例如 `hook_ethtool.js`).
2. 使用 Frida 连接到你的 Android 设备或模拟器： `frida -U -f <目标进程名或包名> -l hook_ethtool.js --no-pause`  或者先运行目标进程，然后使用 `frida -U <目标进程名或包名> -l hook_ethtool.js`.
3. 当 Android 系统执行网络相关的操作时，如果涉及到发送 `ethtool` 相关的 Netlink 消息，Frida 会拦截 `sendto` 调用并打印相关信息，包括进程 ID、文件描述符、消息长度以及尝试解析出的 Netlink 消息类型。

**注意:**  这个 Frida 示例只是一个起点。 实际解析 Netlink 消息的结构和属性需要更深入的理解 Netlink 协议和 `ethtool` 的消息格式，可能需要使用 `libnl` 库的结构定义来进行解析。 你可能需要 hook 更多的函数 (例如 `recvfrom`) 来查看内核的响应。 此外，找到负责发送这些 Netlink 消息的具体进程可能需要一些逆向工程的技巧。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/ethtool_netlink.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_ETHTOOL_NETLINK_H_
#define _UAPI_LINUX_ETHTOOL_NETLINK_H_
#include <linux/ethtool.h>
enum {
  ETHTOOL_MSG_USER_NONE,
  ETHTOOL_MSG_STRSET_GET,
  ETHTOOL_MSG_LINKINFO_GET,
  ETHTOOL_MSG_LINKINFO_SET,
  ETHTOOL_MSG_LINKMODES_GET,
  ETHTOOL_MSG_LINKMODES_SET,
  ETHTOOL_MSG_LINKSTATE_GET,
  ETHTOOL_MSG_DEBUG_GET,
  ETHTOOL_MSG_DEBUG_SET,
  ETHTOOL_MSG_WOL_GET,
  ETHTOOL_MSG_WOL_SET,
  ETHTOOL_MSG_FEATURES_GET,
  ETHTOOL_MSG_FEATURES_SET,
  ETHTOOL_MSG_PRIVFLAGS_GET,
  ETHTOOL_MSG_PRIVFLAGS_SET,
  ETHTOOL_MSG_RINGS_GET,
  ETHTOOL_MSG_RINGS_SET,
  ETHTOOL_MSG_CHANNELS_GET,
  ETHTOOL_MSG_CHANNELS_SET,
  ETHTOOL_MSG_COALESCE_GET,
  ETHTOOL_MSG_COALESCE_SET,
  ETHTOOL_MSG_PAUSE_GET,
  ETHTOOL_MSG_PAUSE_SET,
  ETHTOOL_MSG_EEE_GET,
  ETHTOOL_MSG_EEE_SET,
  ETHTOOL_MSG_TSINFO_GET,
  ETHTOOL_MSG_CABLE_TEST_ACT,
  ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
  ETHTOOL_MSG_TUNNEL_INFO_GET,
  ETHTOOL_MSG_FEC_GET,
  ETHTOOL_MSG_FEC_SET,
  ETHTOOL_MSG_MODULE_EEPROM_GET,
  ETHTOOL_MSG_STATS_GET,
  ETHTOOL_MSG_PHC_VCLOCKS_GET,
  ETHTOOL_MSG_MODULE_GET,
  ETHTOOL_MSG_MODULE_SET,
  ETHTOOL_MSG_PSE_GET,
  ETHTOOL_MSG_PSE_SET,
  ETHTOOL_MSG_RSS_GET,
  ETHTOOL_MSG_PLCA_GET_CFG,
  ETHTOOL_MSG_PLCA_SET_CFG,
  ETHTOOL_MSG_PLCA_GET_STATUS,
  ETHTOOL_MSG_MM_GET,
  ETHTOOL_MSG_MM_SET,
  ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
  ETHTOOL_MSG_PHY_GET,
  __ETHTOOL_MSG_USER_CNT,
  ETHTOOL_MSG_USER_MAX = __ETHTOOL_MSG_USER_CNT - 1
};
enum {
  ETHTOOL_MSG_KERNEL_NONE,
  ETHTOOL_MSG_STRSET_GET_REPLY,
  ETHTOOL_MSG_LINKINFO_GET_REPLY,
  ETHTOOL_MSG_LINKINFO_NTF,
  ETHTOOL_MSG_LINKMODES_GET_REPLY,
  ETHTOOL_MSG_LINKMODES_NTF,
  ETHTOOL_MSG_LINKSTATE_GET_REPLY,
  ETHTOOL_MSG_DEBUG_GET_REPLY,
  ETHTOOL_MSG_DEBUG_NTF,
  ETHTOOL_MSG_WOL_GET_REPLY,
  ETHTOOL_MSG_WOL_NTF,
  ETHTOOL_MSG_FEATURES_GET_REPLY,
  ETHTOOL_MSG_FEATURES_SET_REPLY,
  ETHTOOL_MSG_FEATURES_NTF,
  ETHTOOL_MSG_PRIVFLAGS_GET_REPLY,
  ETHTOOL_MSG_PRIVFLAGS_NTF,
  ETHTOOL_MSG_RINGS_GET_REPLY,
  ETHTOOL_MSG_RINGS_NTF,
  ETHTOOL_MSG_CHANNELS_GET_REPLY,
  ETHTOOL_MSG_CHANNELS_NTF,
  ETHTOOL_MSG_COALESCE_GET_REPLY,
  ETHTOOL_MSG_COALESCE_NTF,
  ETHTOOL_MSG_PAUSE_GET_REPLY,
  ETHTOOL_MSG_PAUSE_NTF,
  ETHTOOL_MSG_EEE_GET_REPLY,
  ETHTOOL_MSG_EEE_NTF,
  ETHTOOL_MSG_TSINFO_GET_REPLY,
  ETHTOOL_MSG_CABLE_TEST_NTF,
  ETHTOOL_MSG_CABLE_TEST_TDR_NTF,
  ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY,
  ETHTOOL_MSG_FEC_GET_REPLY,
  ETHTOOL_MSG_FEC_NTF,
  ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY,
  ETHTOOL_MSG_STATS_GET_REPLY,
  ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY,
  ETHTOOL_MSG_MODULE_GET_REPLY,
  ETHTOOL_MSG_MODULE_NTF,
  ETHTOOL_MSG_PSE_GET_REPLY,
  ETHTOOL_MSG_RSS_GET_REPLY,
  ETHTOOL_MSG_PLCA_GET_CFG_REPLY,
  ETHTOOL_MSG_PLCA_GET_STATUS_REPLY,
  ETHTOOL_MSG_PLCA_NTF,
  ETHTOOL_MSG_MM_GET_REPLY,
  ETHTOOL_MSG_MM_NTF,
  ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
  ETHTOOL_MSG_PHY_GET_REPLY,
  ETHTOOL_MSG_PHY_NTF,
  __ETHTOOL_MSG_KERNEL_CNT,
  ETHTOOL_MSG_KERNEL_MAX = __ETHTOOL_MSG_KERNEL_CNT - 1
};
enum ethtool_header_flags {
  ETHTOOL_FLAG_COMPACT_BITSETS = 1 << 0,
  ETHTOOL_FLAG_OMIT_REPLY = 1 << 1,
  ETHTOOL_FLAG_STATS = 1 << 2,
};
#define ETHTOOL_FLAG_ALL (ETHTOOL_FLAG_COMPACT_BITSETS | ETHTOOL_FLAG_OMIT_REPLY | ETHTOOL_FLAG_STATS)
enum {
  ETHTOOL_A_HEADER_UNSPEC,
  ETHTOOL_A_HEADER_DEV_INDEX,
  ETHTOOL_A_HEADER_DEV_NAME,
  ETHTOOL_A_HEADER_FLAGS,
  ETHTOOL_A_HEADER_PHY_INDEX,
  __ETHTOOL_A_HEADER_CNT,
  ETHTOOL_A_HEADER_MAX = __ETHTOOL_A_HEADER_CNT - 1
};
enum {
  ETHTOOL_A_BITSET_BIT_UNSPEC,
  ETHTOOL_A_BITSET_BIT_INDEX,
  ETHTOOL_A_BITSET_BIT_NAME,
  ETHTOOL_A_BITSET_BIT_VALUE,
  __ETHTOOL_A_BITSET_BIT_CNT,
  ETHTOOL_A_BITSET_BIT_MAX = __ETHTOOL_A_BITSET_BIT_CNT - 1
};
enum {
  ETHTOOL_A_BITSET_BITS_UNSPEC,
  ETHTOOL_A_BITSET_BITS_BIT,
  __ETHTOOL_A_BITSET_BITS_CNT,
  ETHTOOL_A_BITSET_BITS_MAX = __ETHTOOL_A_BITSET_BITS_CNT - 1
};
enum {
  ETHTOOL_A_BITSET_UNSPEC,
  ETHTOOL_A_BITSET_NOMASK,
  ETHTOOL_A_BITSET_SIZE,
  ETHTOOL_A_BITSET_BITS,
  ETHTOOL_A_BITSET_VALUE,
  ETHTOOL_A_BITSET_MASK,
  __ETHTOOL_A_BITSET_CNT,
  ETHTOOL_A_BITSET_MAX = __ETHTOOL_A_BITSET_CNT - 1
};
enum {
  ETHTOOL_A_STRING_UNSPEC,
  ETHTOOL_A_STRING_INDEX,
  ETHTOOL_A_STRING_VALUE,
  __ETHTOOL_A_STRING_CNT,
  ETHTOOL_A_STRING_MAX = __ETHTOOL_A_STRING_CNT - 1
};
enum {
  ETHTOOL_A_STRINGS_UNSPEC,
  ETHTOOL_A_STRINGS_STRING,
  __ETHTOOL_A_STRINGS_CNT,
  ETHTOOL_A_STRINGS_MAX = __ETHTOOL_A_STRINGS_CNT - 1
};
enum {
  ETHTOOL_A_STRINGSET_UNSPEC,
  ETHTOOL_A_STRINGSET_ID,
  ETHTOOL_A_STRINGSET_COUNT,
  ETHTOOL_A_STRINGSET_STRINGS,
  __ETHTOOL_A_STRINGSET_CNT,
  ETHTOOL_A_STRINGSET_MAX = __ETHTOOL_A_STRINGSET_CNT - 1
};
enum {
  ETHTOOL_A_STRINGSETS_UNSPEC,
  ETHTOOL_A_STRINGSETS_STRINGSET,
  __ETHTOOL_A_STRINGSETS_CNT,
  ETHTOOL_A_STRINGSETS_MAX = __ETHTOOL_A_STRINGSETS_CNT - 1
};
enum {
  ETHTOOL_A_STRSET_UNSPEC,
  ETHTOOL_A_STRSET_HEADER,
  ETHTOOL_A_STRSET_STRINGSETS,
  ETHTOOL_A_STRSET_COUNTS_ONLY,
  __ETHTOOL_A_STRSET_CNT,
  ETHTOOL_A_STRSET_MAX = __ETHTOOL_A_STRSET_CNT - 1
};
enum {
  ETHTOOL_A_LINKINFO_UNSPEC,
  ETHTOOL_A_LINKINFO_HEADER,
  ETHTOOL_A_LINKINFO_PORT,
  ETHTOOL_A_LINKINFO_PHYADDR,
  ETHTOOL_A_LINKINFO_TP_MDIX,
  ETHTOOL_A_LINKINFO_TP_MDIX_CTRL,
  ETHTOOL_A_LINKINFO_TRANSCEIVER,
  __ETHTOOL_A_LINKINFO_CNT,
  ETHTOOL_A_LINKINFO_MAX = __ETHTOOL_A_LINKINFO_CNT - 1
};
enum {
  ETHTOOL_A_LINKMODES_UNSPEC,
  ETHTOOL_A_LINKMODES_HEADER,
  ETHTOOL_A_LINKMODES_AUTONEG,
  ETHTOOL_A_LINKMODES_OURS,
  ETHTOOL_A_LINKMODES_PEER,
  ETHTOOL_A_LINKMODES_SPEED,
  ETHTOOL_A_LINKMODES_DUPLEX,
  ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG,
  ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE,
  ETHTOOL_A_LINKMODES_LANES,
  ETHTOOL_A_LINKMODES_RATE_MATCHING,
  __ETHTOOL_A_LINKMODES_CNT,
  ETHTOOL_A_LINKMODES_MAX = __ETHTOOL_A_LINKMODES_CNT - 1
};
enum {
  ETHTOOL_A_LINKSTATE_UNSPEC,
  ETHTOOL_A_LINKSTATE_HEADER,
  ETHTOOL_A_LINKSTATE_LINK,
  ETHTOOL_A_LINKSTATE_SQI,
  ETHTOOL_A_LINKSTATE_SQI_MAX,
  ETHTOOL_A_LINKSTATE_EXT_STATE,
  ETHTOOL_A_LINKSTATE_EXT_SUBSTATE,
  ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT,
  __ETHTOOL_A_LINKSTATE_CNT,
  ETHTOOL_A_LINKSTATE_MAX = __ETHTOOL_A_LINKSTATE_CNT - 1
};
enum {
  ETHTOOL_A_DEBUG_UNSPEC,
  ETHTOOL_A_DEBUG_HEADER,
  ETHTOOL_A_DEBUG_MSGMASK,
  __ETHTOOL_A_DEBUG_CNT,
  ETHTOOL_A_DEBUG_MAX = __ETHTOOL_A_DEBUG_CNT - 1
};
enum {
  ETHTOOL_A_WOL_UNSPEC,
  ETHTOOL_A_WOL_HEADER,
  ETHTOOL_A_WOL_MODES,
  ETHTOOL_A_WOL_SOPASS,
  __ETHTOOL_A_WOL_CNT,
  ETHTOOL_A_WOL_MAX = __ETHTOOL_A_WOL_CNT - 1
};
enum {
  ETHTOOL_A_FEATURES_UNSPEC,
  ETHTOOL_A_FEATURES_HEADER,
  ETHTOOL_A_FEATURES_HW,
  ETHTOOL_A_FEATURES_WANTED,
  ETHTOOL_A_FEATURES_ACTIVE,
  ETHTOOL_A_FEATURES_NOCHANGE,
  __ETHTOOL_A_FEATURES_CNT,
  ETHTOOL_A_FEATURES_MAX = __ETHTOOL_A_FEATURES_CNT - 1
};
enum {
  ETHTOOL_A_PRIVFLAGS_UNSPEC,
  ETHTOOL_A_PRIVFLAGS_HEADER,
  ETHTOOL_A_PRIVFLAGS_FLAGS,
  __ETHTOOL_A_PRIVFLAGS_CNT,
  ETHTOOL_A_PRIVFLAGS_MAX = __ETHTOOL_A_PRIVFLAGS_CNT - 1
};
enum {
  ETHTOOL_TCP_DATA_SPLIT_UNKNOWN = 0,
  ETHTOOL_TCP_DATA_SPLIT_DISABLED,
  ETHTOOL_TCP_DATA_SPLIT_ENABLED,
};
enum {
  ETHTOOL_A_RINGS_UNSPEC,
  ETHTOOL_A_RINGS_HEADER,
  ETHTOOL_A_RINGS_RX_MAX,
  ETHTOOL_A_RINGS_RX_MINI_MAX,
  ETHTOOL_A_RINGS_RX_JUMBO_MAX,
  ETHTOOL_A_RINGS_TX_MAX,
  ETHTOOL_A_RINGS_RX,
  ETHTOOL_A_RINGS_RX_MINI,
  ETHTOOL_A_RINGS_RX_JUMBO,
  ETHTOOL_A_RINGS_TX,
  ETHTOOL_A_RINGS_RX_BUF_LEN,
  ETHTOOL_A_RINGS_TCP_DATA_SPLIT,
  ETHTOOL_A_RINGS_CQE_SIZE,
  ETHTOOL_A_RINGS_TX_PUSH,
  ETHTOOL_A_RINGS_RX_PUSH,
  ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN,
  ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX,
  __ETHTOOL_A_RINGS_CNT,
  ETHTOOL_A_RINGS_MAX = (__ETHTOOL_A_RINGS_CNT - 1)
};
enum {
  ETHTOOL_A_CHANNELS_UNSPEC,
  ETHTOOL_A_CHANNELS_HEADER,
  ETHTOOL_A_CHANNELS_RX_MAX,
  ETHTOOL_A_CHANNELS_TX_MAX,
  ETHTOOL_A_CHANNELS_OTHER_MAX,
  ETHTOOL_A_CHANNELS_COMBINED_MAX,
  ETHTOOL_A_CHANNELS_RX_COUNT,
  ETHTOOL_A_CHANNELS_TX_COUNT,
  ETHTOOL_A_CHANNELS_OTHER_COUNT,
  ETHTOOL_A_CHANNELS_COMBINED_COUNT,
  __ETHTOOL_A_CHANNELS_CNT,
  ETHTOOL_A_CHANNELS_MAX = (__ETHTOOL_A_CHANNELS_CNT - 1)
};
enum {
  ETHTOOL_A_COALESCE_UNSPEC,
  ETHTOOL_A_COALESCE_HEADER,
  ETHTOOL_A_COALESCE_RX_USECS,
  ETHTOOL_A_COALESCE_RX_MAX_FRAMES,
  ETHTOOL_A_COALESCE_RX_USECS_IRQ,
  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ,
  ETHTOOL_A_COALESCE_TX_USECS,
  ETHTOOL_A_COALESCE_TX_MAX_FRAMES,
  ETHTOOL_A_COALESCE_TX_USECS_IRQ,
  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ,
  ETHTOOL_A_COALESCE_STATS_BLOCK_USECS,
  ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX,
  ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX,
  ETHTOOL_A_COALESCE_PKT_RATE_LOW,
  ETHTOOL_A_COALESCE_RX_USECS_LOW,
  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW,
  ETHTOOL_A_COALESCE_TX_USECS_LOW,
  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW,
  ETHTOOL_A_COALESCE_PKT_RATE_HIGH,
  ETHTOOL_A_COALESCE_RX_USECS_HIGH,
  ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH,
  ETHTOOL_A_COALESCE_TX_USECS_HIGH,
  ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH,
  ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL,
  ETHTOOL_A_COALESCE_USE_CQE_MODE_TX,
  ETHTOOL_A_COALESCE_USE_CQE_MODE_RX,
  ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES,
  ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES,
  ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS,
  ETHTOOL_A_COALESCE_RX_PROFILE,
  ETHTOOL_A_COALESCE_TX_PROFILE,
  __ETHTOOL_A_COALESCE_CNT,
  ETHTOOL_A_COALESCE_MAX = (__ETHTOOL_A_COALESCE_CNT - 1)
};
enum {
  ETHTOOL_A_PROFILE_UNSPEC,
  ETHTOOL_A_PROFILE_IRQ_MODERATION,
  __ETHTOOL_A_PROFILE_CNT,
  ETHTOOL_A_PROFILE_MAX = (__ETHTOOL_A_PROFILE_CNT - 1)
};
enum {
  ETHTOOL_A_IRQ_MODERATION_UNSPEC,
  ETHTOOL_A_IRQ_MODERATION_USEC,
  ETHTOOL_A_IRQ_MODERATION_PKTS,
  ETHTOOL_A_IRQ_MODERATION_COMPS,
  __ETHTOOL_A_IRQ_MODERATION_CNT,
  ETHTOOL_A_IRQ_MODERATION_MAX = (__ETHTOOL_A_IRQ_MODERATION_CNT - 1)
};
enum {
  ETHTOOL_A_PAUSE_UNSPEC,
  ETHTOOL_A_PAUSE_HEADER,
  ETHTOOL_A_PAUSE_AUTONEG,
  ETHTOOL_A_PAUSE_RX,
  ETHTOOL_A_PAUSE_TX,
  ETHTOOL_A_PAUSE_STATS,
  ETHTOOL_A_PAUSE_STATS_SRC,
  __ETHTOOL_A_PAUSE_CNT,
  ETHTOOL_A_PAUSE_MAX = (__ETHTOOL_A_PAUSE_CNT - 1)
};
enum {
  ETHTOOL_A_PAUSE_STAT_UNSPEC,
  ETHTOOL_A_PAUSE_STAT_PAD,
  ETHTOOL_A_PAUSE_STAT_TX_FRAMES,
  ETHTOOL_A_PAUSE_STAT_RX_FRAMES,
  __ETHTOOL_A_PAUSE_STAT_CNT,
  ETHTOOL_A_PAUSE_STAT_MAX = (__ETHTOOL_A_PAUSE_STAT_CNT - 1)
};
enum {
  ETHTOOL_A_EEE_UNSPEC,
  ETHTOOL_A_EEE_HEADER,
  ETHTOOL_A_EEE_MODES_OURS,
  ETHTOOL_A_EEE_MODES_PEER,
  ETHTOOL_A_EEE_ACTIVE,
  ETHTOOL_A_EEE_ENABLED,
  ETHTOOL_A_EEE_TX_LPI_ENABLED,
  ETHTOOL_A_EEE_TX_LPI_TIMER,
  __ETHTOOL_A_EEE_CNT,
  ETHTOOL_A_EEE_MAX = (__ETHTOOL_A_EEE_CNT - 1)
};
enum {
  ETHTOOL_A_TSINFO_UNSPEC,
  ETHTOOL_A_TSINFO_HEADER,
  ETHTOOL_A_TSINFO_TIMESTAMPING,
  ETHTOOL_A_TSINFO_TX_TYPES,
  ETHTOOL_A_TSINFO_RX_FILTERS,
  ETHTOOL_A_TSINFO_PHC_INDEX,
  ETHTOOL_A_TSINFO_STATS,
  __ETHTOOL_A_TSINFO_CNT,
  ETHTOOL_A_TSINFO_MAX = (__ETHTOOL_A_TSINFO_CNT - 1)
};
enum {
  ETHTOOL_A_TS_STAT_UNSPEC,
  ETHTOOL_A_TS_STAT_TX_PKTS,
  ETHTOOL_A_TS_STAT_TX_LOST,
  ETHTOOL_A_TS_STAT_TX_ERR,
  __ETHTOOL_A_TS_STAT_CNT,
  ETHTOOL_A_TS_STAT_MAX = (__ETHTOOL_A_TS_STAT_CNT - 1)
};
enum {
  ETHTOOL_A_PHC_VCLOCKS_UNSPEC,
  ETHTOOL_A_PHC_VCLOCKS_HEADER,
  ETHTOOL_A_PHC_VCLOCKS_NUM,
  ETHTOOL_A_PHC_VCLOCKS_INDEX,
  __ETHTOOL_A_PHC_VCLOCKS_CNT,
  ETHTOOL_A_PHC_VCLOCKS_MAX = (__ETHTOOL_A_PHC_VCLOCKS_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_TEST_UNSPEC,
  ETHTOOL_A_CABLE_TEST_HEADER,
  __ETHTOOL_A_CABLE_TEST_CNT,
  ETHTOOL_A_CABLE_TEST_MAX = __ETHTOOL_A_CABLE_TEST_CNT - 1
};
enum {
  ETHTOOL_A_CABLE_RESULT_CODE_UNSPEC,
  ETHTOOL_A_CABLE_RESULT_CODE_OK,
  ETHTOOL_A_CABLE_RESULT_CODE_OPEN,
  ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT,
  ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT,
  ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH,
  ETHTOOL_A_CABLE_RESULT_CODE_NOISE,
  ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE,
};
enum {
  ETHTOOL_A_CABLE_PAIR_A,
  ETHTOOL_A_CABLE_PAIR_B,
  ETHTOOL_A_CABLE_PAIR_C,
  ETHTOOL_A_CABLE_PAIR_D,
};
enum {
  ETHTOOL_A_CABLE_INF_SRC_UNSPEC,
  ETHTOOL_A_CABLE_INF_SRC_TDR,
  ETHTOOL_A_CABLE_INF_SRC_ALCD,
};
enum {
  ETHTOOL_A_CABLE_RESULT_UNSPEC,
  ETHTOOL_A_CABLE_RESULT_PAIR,
  ETHTOOL_A_CABLE_RESULT_CODE,
  ETHTOOL_A_CABLE_RESULT_SRC,
  __ETHTOOL_A_CABLE_RESULT_CNT,
  ETHTOOL_A_CABLE_RESULT_MAX = (__ETHTOOL_A_CABLE_RESULT_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
  ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,
  ETHTOOL_A_CABLE_FAULT_LENGTH_CM,
  ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,
  __ETHTOOL_A_CABLE_FAULT_LENGTH_CNT,
  ETHTOOL_A_CABLE_FAULT_LENGTH_MAX = (__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_TEST_NTF_STATUS_UNSPEC,
  ETHTOOL_A_CABLE_TEST_NTF_STATUS_STARTED,
  ETHTOOL_A_CABLE_TEST_NTF_STATUS_COMPLETED
};
enum {
  ETHTOOL_A_CABLE_NEST_UNSPEC,
  ETHTOOL_A_CABLE_NEST_RESULT,
  ETHTOOL_A_CABLE_NEST_FAULT_LENGTH,
  __ETHTOOL_A_CABLE_NEST_CNT,
  ETHTOOL_A_CABLE_NEST_MAX = (__ETHTOOL_A_CABLE_NEST_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_TEST_NTF_UNSPEC,
  ETHTOOL_A_CABLE_TEST_NTF_HEADER,
  ETHTOOL_A_CABLE_TEST_NTF_STATUS,
  ETHTOOL_A_CABLE_TEST_NTF_NEST,
  __ETHTOOL_A_CABLE_TEST_NTF_CNT,
  ETHTOOL_A_CABLE_TEST_NTF_MAX = (__ETHTOOL_A_CABLE_TEST_NTF_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_TEST_TDR_CFG_UNSPEC,
  ETHTOOL_A_CABLE_TEST_TDR_CFG_FIRST,
  ETHTOOL_A_CABLE_TEST_TDR_CFG_LAST,
  ETHTOOL_A_CABLE_TEST_TDR_CFG_STEP,
  ETHTOOL_A_CABLE_TEST_TDR_CFG_PAIR,
  __ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT,
  ETHTOOL_A_CABLE_TEST_TDR_CFG_MAX = __ETHTOOL_A_CABLE_TEST_TDR_CFG_CNT - 1
};
enum {
  ETHTOOL_A_CABLE_TEST_TDR_UNSPEC,
  ETHTOOL_A_CABLE_TEST_TDR_HEADER,
  ETHTOOL_A_CABLE_TEST_TDR_CFG,
  __ETHTOOL_A_CABLE_TEST_TDR_CNT,
  ETHTOOL_A_CABLE_TEST_TDR_MAX = __ETHTOOL_A_CABLE_TEST_TDR_CNT - 1
};
enum {
  ETHTOOL_A_CABLE_AMPLITUDE_UNSPEC,
  ETHTOOL_A_CABLE_AMPLITUDE_PAIR,
  ETHTOOL_A_CABLE_AMPLITUDE_mV,
  __ETHTOOL_A_CABLE_AMPLITUDE_CNT,
  ETHTOOL_A_CABLE_AMPLITUDE_MAX = (__ETHTOOL_A_CABLE_AMPLITUDE_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_PULSE_UNSPEC,
  ETHTOOL_A_CABLE_PULSE_mV,
  __ETHTOOL_A_CABLE_PULSE_CNT,
  ETHTOOL_A_CABLE_PULSE_MAX = (__ETHTOOL_A_CABLE_PULSE_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_STEP_UNSPEC,
  ETHTOOL_A_CABLE_STEP_FIRST_DISTANCE,
  ETHTOOL_A_CABLE_STEP_LAST_DISTANCE,
  ETHTOOL_A_CABLE_STEP_STEP_DISTANCE,
  __ETHTOOL_A_CABLE_STEP_CNT,
  ETHTOOL_A_CABLE_STEP_MAX = (__ETHTOOL_A_CABLE_STEP_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_TDR_NEST_UNSPEC,
  ETHTOOL_A_CABLE_TDR_NEST_STEP,
  ETHTOOL_A_CABLE_TDR_NEST_AMPLITUDE,
  ETHTOOL_A_CABLE_TDR_NEST_PULSE,
  __ETHTOOL_A_CABLE_TDR_NEST_CNT,
  ETHTOOL_A_CABLE_TDR_NEST_MAX = (__ETHTOOL_A_CABLE_TDR_NEST_CNT - 1)
};
enum {
  ETHTOOL_A_CABLE_TEST_TDR_NTF_UNSPEC,
  ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER,
  ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS,
  ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST,
  __ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT,
  ETHTOOL_A_CABLE_TEST_TDR_NTF_MAX = __ETHTOOL_A_CABLE_TEST_TDR_NTF_CNT - 1
};
enum {
  ETHTOOL_UDP_TUNNEL_TYPE_VXLAN,
  ETHTOOL_UDP_TUNNEL_TYPE_GENEVE,
  ETHTOOL_UDP_TUNNEL_TYPE_VXLAN_GPE,
  __ETHTOOL_UDP_TUNNEL_TYPE_CNT
};
enum {
  ETHTOOL_A_TUNNEL_UDP_ENTRY_UNSPEC,
  ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT,
  ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE,
  __ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT,
  ETHTOOL_A_TUNNEL_UDP_ENTRY_MAX = (__ETHTOOL_A_TUNNEL_UDP_ENTRY_CNT - 1)
};
enum {
  ETHTOOL_A_TUNNEL_UDP_TABLE_UNSPEC,
  ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE,
  ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES,
  ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY,
  __ETHTOOL_A_TUNNEL_UDP_TABLE_CNT,
  ETHTOOL_A_TUNNEL_UDP_TABLE_MAX = (__ETHTOOL_A_TUNNEL_UDP_TABLE_CNT - 1)
};
enum {
  ETHTOOL_A_TUNNEL_UDP_UNSPEC,
  ETHTOOL_A_TUNNEL_UDP_TABLE,
  __ETHTOOL_A_TUNNEL_UDP_CNT,
  ETHTOOL_A_TUNNEL_UDP_MAX = (__ETHTOOL_A_TUNNEL_UDP_CNT - 1)
};
enum {
  ETHTOOL_A_TUNNEL_INFO_UNSPEC,
  ETHTOOL_A_TUNNEL_INFO_HEADER,
  ETHTOOL_A_TUNNEL_INFO_UDP_PORTS,
  __ETHTOOL_A_TUNNEL_INFO_CNT,
  ETHTOOL_A_TUNNEL_INFO_MAX = (__ETHTOOL_A_TUNNEL_INFO_CNT - 1)
};
enum {
  ETHTOOL_A_FEC_UNSPEC,
  ETHTOOL_A_FEC_HEADER,
  ETHTOOL_A_FEC_MODES,
  ETHTOOL_A_FEC_AUTO,
  ETHTOOL_A_FEC_ACTIVE,
  ETHTOOL_A_FEC_STATS,
  __ETHTOOL_A_FEC_CNT,
  ETHTOOL_A_FEC_MAX = (__ETHTOOL_A_FEC_CNT - 1)
};
enum {
  ETHTOOL_A_FEC_STAT_UNSPEC,
  ETHTOOL_A_FEC_STAT_PAD,
  ETHTOOL_A_FEC_STAT_CORRECTED,
  ETHTOOL_A_FEC_STAT_UNCORR,
  ETHTOOL_A_FEC_STAT_CORR_BITS,
  __ETHTOOL_A_FEC_STAT_CNT,
  ETHTOOL_A_FEC_STAT_MAX = (__ETHTOOL_A_FEC_STAT_CNT - 1)
};
enum {
  ETHTOOL_A_MODULE_EEPROM_UNSPEC,
  ETHTOOL_A_MODULE_EEPROM_HEADER,
  ETHTOOL_A_MODULE_EEPROM_OFFSET,
  ETHTOOL_A_MODULE_EEPROM_LENGTH,
  ETHTOOL_A_MODULE_EEPROM_PAGE,
  ETHTOOL_A_MODULE_EEPROM_BANK,
  ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS,
  ETHTOOL_A_MODULE_EEPROM_DATA,
  __ETHTOOL_A_MODULE_EEPROM_CNT,
  ETHTOOL_A_MODULE_EEPROM_MAX = (__ETHTOOL_A_MODULE_EEPROM_CNT - 1)
};
enum {
  ETHTOOL_A_STATS_UNSPEC,
  ETHTOOL_A_STATS_PAD,
  ETHTOOL_A_STATS_HEADER,
  ETHTOOL_A_STATS_GROUPS,
  ETHTOOL_A_STATS_GRP,
  ETHTOOL_A_STATS_SRC,
  __ETHTOOL_A_STATS_CNT,
  ETHTOOL_A_STATS_MAX = (__ETHTOOL_A_STATS_CNT - 1)
};
enum {
  ETHTOOL_STATS_ETH_PHY,
  ETHTOOL_STATS_ETH_MAC,
  ETHTOOL_STATS_ETH_CTRL,
  ETHTOOL_STATS_RMON,
  __ETHTOOL_STATS_CNT
};
enum {
  ETHTOOL_A_STATS_GRP_UNSPEC,
  ETHTOOL_A_STATS_GRP_PAD,
  ETHTOOL_A_STATS_GRP_ID,
  ETHTOOL_A_STATS_GRP_SS_ID,
  ETHTOOL_A_STATS_GRP_STAT,
  ETHTOOL_A_STATS_GRP_HIST_RX,
  ETHTOOL_A_STATS_GRP_HIST_TX,
  ETHTOOL_A_STATS_GRP_HIST_BKT_LOW,
  ETHTOOL_A_STATS_GRP_HIST_BKT_HI,
  ETHTOOL_A_STATS_GRP_HIST_VAL,
  __ETHTOOL_A_STATS_GRP_CNT,
  ETHTOOL_A_STATS_GRP_MAX = (__ETHTOOL_A_STATS_GRP_CNT - 1)
};
enum {
  ETHTOOL_A_STATS_ETH_PHY_5_SYM_ERR,
  __ETHTOOL_A_STATS_ETH_PHY_CNT,
  ETHTOOL_A_STATS_ETH_PHY_MAX = (__ETHTOOL_A_STATS_ETH_PHY_CNT - 1)
};
enum {
  ETHTOOL_A_STATS_ETH_MAC_2_TX_PKT,
  ETHTOOL_A_STATS_ETH_MAC_3_SINGLE_COL,
  ETHTOOL_A_STATS_ETH_MAC_4_MULTI_COL,
  ETHTOOL_A_STATS_ETH_MAC_5_RX_PKT,
  ETHTOOL_A_STATS_ETH_MAC_6_FCS_ERR,
  ETHTOOL_A_STATS_ETH_MAC_7_ALIGN_ERR,
  ETHTOOL_A_STATS_ETH_MAC_8_TX_BYTES,
  ETHTOOL_A_STATS_ETH_MAC_9_TX_DEFER,
  ETHTOOL_A_STATS_ETH_MAC_10_LATE_COL,
  ETHTOOL_A_STATS_ETH_MAC_11_XS_COL,
  ETHTOOL_A_STATS_ETH_MAC_12_TX_INT_ERR,
  ETHTOOL_A_STATS_ETH_MAC_13_CS_ERR,
  ETHTOOL_A_STATS_ETH_MAC_14_RX_BYTES,
  ETHTOOL_A_STATS_ETH_MAC_15_RX_INT_ERR,
  ETHTOOL_A_STATS_ETH_MAC_18_TX_MCAST,
  ETHTOOL_A_STATS_ETH_MAC_19_TX_BCAST,
  ETHTOOL_A_STATS_ETH_MAC_20_XS_DEFER,
  ETHTOOL_A_STATS_ETH_MAC_21_RX_MCAST,
  ETHTOOL_A_STATS_ETH_MAC_22_RX_BCAST,
  ETHTOOL_A_STATS_ETH_MAC_23_IR_LEN_ERR,
  ETHTOOL_A_STATS_ETH_MAC_24_OOR_LEN,
  ETHTOOL_A_STATS_ETH_MAC_25_TOO_LONG_ERR,
  __ETHTOOL_A_STATS_ETH_MAC_CNT,
  ETHTOOL_A_STATS_ETH_MAC_MAX = (__ETHTOOL_A_STATS_ETH_MAC_CNT - 1)
};
enum {
  ETHTOOL_A_STATS_ETH_CTRL_3_TX,
  ETHTOOL_A_STATS_ETH_CTRL_4_RX,
  ETHTOOL_A_STATS_ETH_CTRL_5_RX_UNSUP,
  __ETHTOOL_A_STATS_ETH_CTRL_CNT,
  ETHTOOL_A_STATS_ETH_CTRL_MAX = (__ETHTOOL_A_STATS_ETH_CTRL_CNT - 1)
};
enum {
  ETHTOOL_A_STATS_RMON_UNDERSIZE,
  ETHTOOL_A_STATS_RMON_OVERSIZE,
  ETHTOOL_A_STATS_RMON_FRAG,
  ETHTOOL_A_STATS_RMON_JABBER,
  __ETHTOOL_A_STATS_RMON_CNT,
  ETHTOOL_A_STATS_RMON_MAX = (__ETHTOOL_A_STATS_RMON_CNT - 1)
};
enum {
  ETHTOOL_A_MODULE_UNSPEC,
  ETHTOOL_A_MODULE_HEADER,
  ETHTOOL_A_MODULE_POWER_MODE_POLICY,
  ETHTOOL_A_MODULE_POWER_MODE,
  __ETHTOOL_A_MODULE_CNT,
  ETHTOOL_A_MODULE_MAX = (__ETHTOOL_A_MODULE_CNT - 1)
};
enum {
  ETHTOOL_A_C33_PSE_PW_LIMIT_UNSPEC,
  ETHTOOL_A_C33_PSE_PW_LIMIT_MIN,
  ETHTOOL_A_C33_PSE_PW_LIMIT_MAX,
};
enum {
  ETHTOOL_A_PSE_UNSPEC,
  ETHTOOL_A_PSE_HEADER,
  ETHTOOL_A_PODL_PSE_ADMIN_STATE,
  ETHTOOL_A_PODL_PSE_ADMIN_CONTROL,
  ETHTOOL_A_PODL_PSE_PW_D_STATUS,
  ETHTOOL_A_C33_PSE_ADMIN_STATE,
  ETHTOOL_A_C33_PSE_ADMIN_CONTROL,
  ETHTOOL_A_C33_PSE_PW_D_STATUS,
  ETHTOOL_A_C33_PSE_PW_CLASS,
  ETHTOOL_A_C33_PSE_ACTUAL_PW,
  ETHTOOL_A_C33_PSE_EXT_STATE,
  ETHTOOL_A_C33_PSE_EXT_SUBSTATE,
  ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,
  ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES,
  __ETHTOOL_A_PSE_CNT,
  ETHTOOL_A_PSE_MAX = (__ETHTOOL_A_PSE_CNT - 1)
};
enum {
  ETHTOOL_A_RSS_UNSPEC,
  ETHTOOL_A_RSS_HEADER,
  ETHTOOL_A_RSS_CONTEXT,
  ETHTOOL_A_RSS_HFUNC,
  ETHTOOL_A_RSS_INDIR,
  ETHTOOL_A_RSS_HKEY,
  ETHTOOL_A_RSS_INPUT_XFRM,
  ETHTOOL_A_RSS_START_CONTEXT,
  __ETHTOOL_A_RSS_CNT,
  ETHTOOL_A_RSS_MAX = (__ETHTOOL_A_RSS_CNT - 1),
};
enum {
  ETHTOOL_A_PLCA_UNSPEC,
  ETHTOOL_A_PLCA_HEADER,
  ETHTOOL_A_PLCA_VERSION,
  ETHTOOL_A_PLCA_ENABLED,
  ETHTOOL_A_PLCA_STATUS,
  ETHTOOL_A_PLCA_NODE_CNT,
  ETHTOOL_A_PLCA_NODE_ID,
  ETHTOOL_A_PLCA_TO_TMR,
  ETHTOOL_A_PLCA_BURST_CNT,
  ETHTOOL_A_PLCA_BURST_TMR,
  __ETHTOOL_A_PLCA_CNT,
  ETHTOOL_A_PLCA_MAX = (__ETHTOOL_A_PLCA_CNT - 1)
};
enum {
  ETHTOOL_A_MM_STAT_UNSPEC,
  ETHTOOL_A_MM_STAT_PAD,
  ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS,
  ETHTOOL_A_MM_STAT_SMD_ERRORS,
  ETHTOOL_A_MM_STAT_REASSEMBLY_OK,
  ETHTOOL_A_MM_STAT_RX_FRAG_COUNT,
  ETHTOOL_A_MM_STAT_TX_FRAG_COUNT,
  ETHTOOL_A_MM_STAT_HOLD_COUNT,
  __ETHTOOL_A_MM_STAT_CNT,
  ETHTOOL_A_MM_STAT_MAX = (__ETHTOOL_A_MM_STAT_CNT - 1)
};
enum {
  ETHTOOL_A_MM_UNSPEC,
  ETHTOOL_A_MM_HEADER,
  ETHTOOL_A_MM_PMAC_ENABLED,
  ETHTOOL_A_MM_TX_ENABLED,
  ETHTOOL_A_MM_TX_ACTIVE,
  ETHTOOL_A_MM_TX_MIN_FRAG_SIZE,
  ETHTOOL_A_MM_RX_MIN_FRAG_SIZE,
  ETHTOOL_A_MM_VERIFY_ENABLED,
  ETHTOOL_A_MM_VERIFY_STATUS,
  ETHTOOL_A_MM_VERIFY_TIME,
  ETHTOOL_A_MM_MAX_VERIFY_TIME,
  ETHTOOL_A_MM_STATS,
  __ETHTOOL_A_MM_CNT,
  ETHTOOL_A_MM_MAX = (__ETHTOOL_A_MM_CNT - 1)
};
enum {
  ETHTOOL_A_MODULE_FW_FLASH_UNSPEC,
  ETHTOOL_A_MODULE_FW_FLASH_HEADER,
  ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,
  ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,
  ETHTOOL_A_MODULE_FW_FLASH_STATUS,
  ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG,
  ETHTOOL_A_MODULE_FW_FLASH_DONE,
  ETHTOOL_A_MODULE_FW_FLASH_TOTAL,
  __ETHTOOL_A_MODULE_FW_FLASH_CNT,
  ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
};
enum {
  ETHTOOL_A_PHY_UNSPEC,
  ETHTOOL_A_PHY_HEADER,
  ETHTOOL_A_PHY_INDEX,
  ETHTOOL_A_PHY_DRVNAME,
  ETHTOOL_A_PHY_NAME,
  ETHTOOL_A_PHY_UPSTREAM_TYPE,
  ETHTOOL_A_PHY_UPSTREAM_INDEX,
  ETHTOOL_A_PHY_UPSTREAM_SFP_NAME,
  ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME,
  __ETHTOOL_A_PHY_CNT,
  ETHTOOL_A_PHY_MAX = (__ETHTOOL_A_PHY_CNT - 1)
};
#define ETHTOOL_GENL_NAME "ethtool"
#define ETHTOOL_GENL_VERSION 1
#define ETHTOOL_MCGRP_MONITOR_NAME "monitor"
#endif

"""

```