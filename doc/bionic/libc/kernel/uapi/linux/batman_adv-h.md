Response:
Let's break down the thought process for analyzing this kernel header file.

**1. Understanding the Context:**

The first and most crucial step is recognizing the context. The prompt explicitly states:

* **Location:** `bionic/libc/kernel/uapi/linux/batman_adv.h`
* **Purpose:**  It's a *kernel* header file intended for *user space* (uapi). This means it defines interfaces and data structures that user-space programs can use to interact with a kernel module.
* **Domain:**  It mentions "batman_adv," which strongly suggests it's related to the BATMAN Advanced routing protocol (a mesh networking protocol).
* **Relationship to Android:**  The path `bionic/libc/kernel/uapi` indicates that this is part of Android's adaptation of the Linux kernel API. `bionic` is Android's C library.

**2. Identifying Key Elements:**

Next, scan the file for the fundamental building blocks of an interface definition:

* **Include Guards:** `#ifndef _UAPI_LINUX_BATMAN_ADV_H_` and `#define _UAPI_LINUX_BATMAN_ADV_H_` are standard include guards to prevent multiple inclusions. This is important but not a functional aspect we need to detail in the summary.
* **Macros:** `#define BATADV_NL_NAME "batadv"` and `#define BATADV_NL_MCAST_GROUP_CONFIG "config"`, etc. These are constants, likely used for identifying the Netlink family and multicast groups associated with the batman-adv module.
* **Enums:**  `enum batadv_tt_client_flags`, `enum batadv_mcast_flags_priv`, `enum batadv_gw_modes`, `enum batadv_nl_attrs`, `enum batadv_nl_commands`, `enum batadv_tp_meter_reason`, `enum batadv_ifla_attrs`. These are the core data structures defining possible values for various attributes and commands. This is where much of the functionality is encoded.

**3. Deciphering the Enums (and Macros):**

Now, go through each enum and try to understand its purpose based on the names of its members:

* **`batadv_tt_client_flags`:**  Likely flags related to clients in the translation table (TT) of the BATMAN-Adv protocol. Keywords like `DEL`, `ROAM`, `WIFI`, `ISOLA` give hints.
* **`batadv_mcast_flags_priv`:**  Flags related to multicast functionality, possibly with a "private" connotation (perhaps internal kernel state). "BRIDGED" and "QUERIER" suggest multicast management.
* **`batadv_gw_modes`:**  Defines the gateway roles a BATMAN-Adv node can take: off, client, server.
* **`batadv_nl_attrs`:**  This is a crucial enum. It lists *attributes* that can be sent and received via Netlink messages to configure or query the batman-adv module. The names are very descriptive: `MESH_IFINDEX`, `ORIG_ADDRESS`, `TQ` (Transmission Quality), `GW_MODE`, etc. This enum essentially defines the schema of the Netlink interface.
* **`batadv_nl_commands`:** This lists the *commands* that can be sent via Netlink. `GET_MESH`, `TP_METER`, `GET_ROUTING_ALGOS`, `SET_MESH`, etc. This indicates the actions a user-space program can request from the kernel module.
* **`batadv_tp_meter_reason`:**  Reasons for the completion or failure of a throughput measurement ("TP Meter") operation.
* **`batadv_ifla_attrs`:** Attributes related to network interface configuration, specifically for BATMAN-Adv.

**4. Connecting to Android:**

Think about how mesh networking and the BATMAN-Adv protocol could be relevant in Android:

* **Tethering/Hotspot:** While not directly BATMAN-Adv, it shares concepts of sharing network connectivity. BATMAN-Adv could be used in more advanced scenarios.
* **Ad-hoc Networks:**  BATMAN-Adv is designed for this. Android devices could theoretically form ad-hoc meshes.
* **Specialized Devices:**  Certain Android-based devices might be used in industrial or IoT settings where mesh networking is beneficial.

**5. Considering libc and Dynamic Linker:**

The prompt mentions `libc` and the dynamic linker.

* **libc:**  While this header file *defines* the interface, the actual *implementation* of sending and receiving Netlink messages would reside in `libc`. Functions like `socket()`, `bind()`, `sendto()`, `recvfrom()`, and Netlink-specific helpers would be used.
* **Dynamic Linker:** The dynamic linker is involved when user-space programs use libraries that interact with the kernel module. However, this specific header file doesn't directly dictate dynamic linking behavior. The *libraries* using this interface would be the ones linked.

**6. Hypothetical Scenarios and Errors:**

Consider how a developer might interact with this interface and potential mistakes:

* **Incorrect Attribute Usage:**  Trying to set a read-only attribute.
* **Invalid Command Sequences:** Sending commands in the wrong order.
* **Incorrect Data Types:**  Providing data in the wrong format for an attribute.

**7. Tracing the Path from Framework/NDK:**

Think about the layers:

* **Framework:** Android's Java/Kotlin framework likely wouldn't directly interact with this low-level kernel interface.
* **NDK:**  NDK developers could use C/C++ code to interact with Netlink sockets and this header file. They would need to construct Netlink messages according to the defined attributes and commands.

**8. Frida Hooking:**

Consider what you'd want to observe:

* **Netlink Socket Calls:** Hooking `sendto()` and `recvfrom()` to see the raw Netlink messages.
* **Specific Functions:** If you knew of a library or service using this interface, you could hook functions within that library.

**9. Structuring the Answer:**

Finally, organize the information logically, addressing each part of the prompt:

* **功能:** Summarize the purpose of the header file and the BATMAN-Adv protocol.
* **与 Android 的关系:** Provide concrete examples.
* **libc 函数:** Explain the general role of `libc` in this interaction, without needing to dive into the exact implementation of every Netlink function (which is complex).
* **Dynamic Linker:** Explain its *indirect* role. Provide a simplified SO layout example.
* **逻辑推理 (假设输入与输出):**  Give a simple example of a Netlink message and its expected effect.
* **用户或编程常见错误:**  Illustrate common mistakes.
* **Android Framework/NDK 到达这里:**  Outline the layers and how an NDK app would interact.
* **Frida Hook 示例:** Provide examples of hooking relevant functions.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file directly defines functions. **Correction:** Realize it's a *header* file, so it primarily defines *data structures* and constants for interacting with a kernel module. The actual implementation is in the kernel.
* **Overly detailed libc explanation:**  Initially, I might have started explaining the intricacies of `socket()`, `bind()`, etc. **Correction:**  Realize that a high-level explanation of `libc`'s role in system calls is sufficient, as the prompt isn't asking for a deep dive into socket programming.
* **Focusing too much on specific Android APIs:**  While connections exist, the focus should remain on the *kernel interface* defined by the header. Android-specific APIs would be higher-level abstractions.

By following these steps,  you can systematically analyze a kernel header file and provide a comprehensive and accurate response.
这个文件 `bionic/libc/kernel/uapi/linux/batman_adv.handroid` 定义了用户空间程序与 Linux 内核中的 `batman-adv` 模块进行交互时所使用的常量、枚举和数据结构。`batman-adv` 是一个用于创建 mesh 网络的内核模块。

**它的功能:**

这个头文件主要定义了以下几个方面的内容，以便用户空间程序能够配置和监控 `batman-adv` 模块的行为：

1. **Netlink 通信的基础定义:**
   - `BATADV_NL_NAME`: 定义了用于与 `batman-adv` 模块通信的 Netlink 协议族的名称（"batadv"）。
   - `BATADV_NL_MCAST_GROUP_CONFIG` 和 `BATADV_NL_MCAST_GROUP_TPMETER`: 定义了用于接收特定类型 multicast 消息的 Netlink multicast 组名。

2. **BATMAN-Adv 协议相关的枚举类型 (Enums):**
   - `batadv_tt_client_flags`: 定义了 translation table (TT) 中客户端条目的标志位，例如删除、漫游、WiFi 客户端、隔离客户端等。
   - `batadv_mcast_flags_priv`: 定义了 multicast 功能的私有标志位，例如是否桥接、是否存在 IPv4/IPv6 查询器等。
   - `batadv_gw_modes`: 定义了网关的工作模式，包括关闭、客户端和服务器。
   - `batadv_nl_attrs`: 定义了通过 Netlink 消息传递的各种属性（attribute）的 ID，例如版本、算法名称、接口索引/名称/地址、邻居地址、链路质量 (TQ)、吞吐量、网关模式等等。这些属性用于配置和获取 `batman-adv` 的状态信息。
   - `batadv_nl_commands`: 定义了通过 Netlink 消息发送的命令 ID，例如获取 mesh 信息、启动/取消吞吐量测量、获取路由算法、获取邻居/网关信息、设置 mesh 参数等等。
   - `batadv_tp_meter_reason`: 定义了吞吐量测量 (throughput meter) 完成或失败的原因。
   - `batadv_ifla_attrs`: 定义了与网络接口属性相关的 `batman-adv` 特有属性。

**与 Android 功能的关系及举例说明:**

虽然 `batman-adv` 不是 Android 核心的网络功能，但它在某些特定的 Android 应用场景中可能被使用，或者其概念与 Android 的某些功能相关：

* **无线 Ad-hoc 网络/ Mesh 网络:**  `batman-adv` 的主要目的是创建无线 mesh 网络，让设备之间能够自动发现和路由数据，而无需中心化的接入点。在某些 Android 设备或定制 ROM 中，可能会使用 `batman-adv` 或类似技术来实现设备间的直接互联，例如用于文件共享、局域网游戏或者在没有基础设施的环境下进行通信。
* **网络共享/热点增强:**  虽然 Android 原生的热点功能通常基于 AP 模式，但 `batman-adv` 提供的 mesh 功能可以更灵活地扩展网络覆盖范围，并允许设备之间进行多跳路由。在一些特定的嵌入式 Android 设备上，例如用于工业控制或物联网网关的设备，可能会用到 `batman-adv` 来构建鲁棒的网络。
* **NDK 开发:**  Android NDK 允许开发者使用 C/C++ 代码与底层系统交互。如果开发者需要在 Android 设备上实现基于 mesh 网络的应用程序，他们可能会使用 Netlink socket API，并参考这个头文件中定义的常量和结构体来与内核中的 `batman-adv` 模块进行通信。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**不包含任何 libc 函数的实现**。它只是一个头文件，定义了常量和数据结构。用户空间的程序需要使用标准的 libc 函数，例如 socket 相关的函数，以及 Netlink 相关的辅助函数（如果存在），才能与内核模块进行交互。

以下是一些可能相关的 libc 函数及其简要说明：

* **`socket()`:**  创建一个 socket 文件描述符。用户空间程序需要创建一个 `AF_NETLINK` 类型的 socket 来与内核的 Netlink 接口通信。
* **`bind()`:**  将 socket 绑定到一个地址。对于 Netlink socket，通常需要绑定到 `NETLINK_GENERIC` 协议族，并指定与 `batman-adv` 模块对应的 Netlink ID (通常可以通过 `genl_ctrl_resolve()` 或类似函数获取)。
* **`sendto()`/`sendmsg()`:**  通过 socket 发送数据。用户空间程序需要构造符合 Netlink 协议格式的消息，包含 `batadv_nl_attrs` 中定义的属性和 `batadv_nl_commands` 中定义的命令，然后通过 `sendto` 或 `sendmsg` 发送给内核。
* **`recvfrom()`/`recvmsg()`:**  通过 socket 接收数据。内核模块处理用户空间的请求后，会通过 Netlink socket 发送响应消息，用户空间程序使用 `recvfrom` 或 `recvmsg` 接收这些消息。
* **Netlink 辅助函数 (例如来自 `libnl`):** 一些库，如 `libnl`，提供了更高级的 API 来简化 Netlink 消息的构造和解析。这些库内部会使用上述基本的 socket 函数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身**不直接涉及 dynamic linker 的功能**。Dynamic linker 的作用是将程序依赖的共享库加载到内存中，并解析符号引用。

如果用户空间程序使用 `batman-adv` 提供的功能，它可能会依赖一些共享库来辅助 Netlink 通信。例如，如果使用了 `libnl`，那么该程序的链接过程会涉及 `libnl.so`。

**SO 布局样本:**

假设一个名为 `my_batman_app` 的应用程序使用了 `libnl` 来与 `batman-adv` 交互，其可能依赖的 SO 布局如下：

```
/system/bin/my_batman_app  # 可执行文件
/system/lib[64]/libnl.so   # libnl 共享库
/system/lib[64]/libc.so    # C 标准库
/system/lib[64]/libm.so    # 数学库 (可能依赖)
/system/lib[64]/libdl.so   # 动态链接器库 (在启动时被内核加载)
...
```

**链接的处理过程:**

1. **编译时链接:** 编译器会将 `my_batman_app` 中对 `libnl` 中函数的调用记录下来，生成重定位信息。
2. **加载时链接 (Dynamic Linker 的工作):**
   - 当系统启动 `my_batman_app` 时，内核会加载程序本身。
   - 程序头部信息指示需要动态链接器 (`/system/bin/linker[64]`)。
   - 动态链接器被加载到进程的地址空间。
   - 动态链接器读取 `my_batman_app` 的动态链接段，获取其依赖的共享库列表 (`libnl.so` 等)。
   - 动态链接器在预定义的路径中搜索这些共享库。
   - 找到共享库后，将其加载到进程的地址空间。
   - 动态链接器解析 `my_batman_app` 中对 `libnl.so` 中函数的符号引用，并将其地址指向加载到内存中的 `libnl.so` 中对应函数的地址。
   - 完成所有依赖库的加载和符号解析后，动态链接器将控制权交给 `my_batman_app` 的入口点。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要获取 `batman-adv` 模块的版本信息。

**假设输入 (通过 Netlink 发送的消息):**

一个构造好的 Netlink 消息，包含以下关键信息：

* **`nlmsghdr`:** Netlink 消息头，包含消息长度、类型等信息。
* **`genlmsghdr`:** Generic Netlink 消息头，包含命令族 ID 和命令 ID。
    * 族 ID:  `BATADV_GENL_FAMILY` (假设已通过 `genl_ctrl_resolve()` 获取)
    * 命令 ID: `BATADV_CMD_GET_MESH_INFO` (或类似的命令，具体取决于内核实现)
* **Netlink Attributes:**
    * 属性类型: `BATADV_ATTR_UNSPEC` (或其他必要的属性，可能为空)

**预期输出 (通过 Netlink 接收的消息):**

一个 Netlink 响应消息，包含以下关键信息：

* **`nlmsghdr`:** Netlink 消息头。
* **`genlmsghdr`:** Generic Netlink 消息头，指示这是一个响应。
* **Netlink Attributes:**
    * 属性类型: `BATADV_ATTR_VERSION`
    * 属性数据:  一个表示 `batman-adv` 模块版本号的值 (例如，一个整数)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的 Netlink 消息构造:**
   - **错误的属性类型或顺序:**  使用了错误的 `batadv_nl_attrs` 枚举值，或者属性的顺序与内核期望的不符。
   - **缺少必要的属性:**  某些命令可能需要特定的属性才能正确执行，如果缺少这些属性，内核可能会返回错误。
   - **属性数据格式错误:**  例如，应该发送一个 IP 地址的二进制数据，却发送了字符串。

   ```c
   // 错误示例：尝试设置一个不存在的属性
   struct nlattr *attr = nla_nest_start(nmsg, BATADV_ATTR_UNSPEC + 100); // 假设这是一个无效的属性 ID
   if (attr == NULL)
       // 处理错误
   ```

2. **使用错误的 Netlink 命令:**
   - 发送了内核不支持的 `batadv_nl_commands` 值。
   - 在不合适的时机发送命令，例如在 `batman-adv` 模块未加载时尝试配置它。

3. **权限问题:**
   - 某些 `batman-adv` 的配置可能需要 root 权限才能执行。如果用户程序没有足够的权限，Netlink 调用可能会失败。

4. **忽略错误处理:**
   - 用户程序没有检查 `sendto` 和 `recvfrom` 的返回值，导致忽略了 Netlink 通信中可能发生的错误。

5. **不正确的 Netlink Socket 配置:**
   - 没有正确绑定 Netlink socket 到 `NETLINK_GENERIC` 族，或者使用了错误的 multicast 组 ID。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android Framework 不会直接与 `batman-adv` 模块交互。这种交互更多发生在具有特定网络需求的应用或服务中，这些应用或服务可能会使用 NDK 来实现。

**步骤：Android NDK 应用访问 `batman-adv`**

1. **NDK 应用开发:** 开发者使用 C/C++ 编写 NDK 应用，需要包含 `<linux/netlink.h>` 和 `<linux/genetlink.h>` 头文件，以及本文件 `bionic/libc/kernel/uapi/linux/batman_adv.h`。
2. **创建 Netlink Socket:** NDK 应用使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)` 创建一个 Netlink socket。
3. **解析 Generic Netlink Family ID:**  应用需要通过 `genl_ctrl_resolve()` 或类似的机制获取 `batman-adv` 的 Generic Netlink 家族 ID。这通常涉及发送一个 `CTRL_CMD_GETFAMILY` 命令到 `NETLINK_GENERIC` 控制接口。
4. **构造 Netlink 消息:**  应用根据需要配置或查询 `batman-adv`，构造包含 `batadv_nl_attrs` 和 `batadv_nl_commands` 的 Netlink 消息。
5. **发送 Netlink 消息:** 使用 `sendto()` 或 `sendmsg()` 将消息发送到内核。
6. **接收 Netlink 响应:** 使用 `recvfrom()` 或 `recvmsg()` 接收内核的响应。
7. **解析 Netlink 消息:** 解析接收到的消息，提取 `batadv_nl_attrs` 中的数据。

**Frida Hook 示例:**

假设我们想观察一个 NDK 应用发送给 `batman-adv` 的 Netlink 消息。我们可以 hook `sendto` 函数。

```javascript
// frida 脚本

function hook_sendto() {
  const sendtoPtr = Module.findExportByName("libc.so", "sendto");
  if (sendtoPtr) {
    Interceptor.attach(sendtoPtr, {
      onEnter: function (args) {
        const sockfd = args[0].toInt32();
        const bufPtr = args[1];
        const len = args[2].toInt32();
        const destAddrPtr = args[3];
        const addrlen = args[4] ? args[4].toInt32() : 0;

        // 检查是否是 AF_NETLINK socket (简化判断)
        const sockaddrFamily = destAddrPtr.readU16();
        if (sockaddrFamily === 16) { // AF_NETLINK
          console.log("sendto called on Netlink socket:");
          console.log("  sockfd:", sockfd);
          console.log("  length:", len);

          // 读取并打印 Netlink 消息头 (简单打印，可能需要更详细的解析)
          const nlmsghdrPtr = bufPtr;
          const nlmsg_len = nlmsghdrPtr.readU32();
          const nlmsg_type = nlmsghdrPtr.readU16();
          const nlmsg_flags = nlmsghdrPtr.readU16();
          const nlmsg_seq = nlmsghdrPtr.readU32();
          const nlmsg_pid = nlmsghdrPtr.readU32();

          console.log("  Netlink Header:");
          console.log("    len:", nlmsg_len);
          console.log("    type:", nlmsg_type);
          console.log("    flags:", nlmsg_flags);
          console.log("    seq:", nlmsg_seq);
          console.log("    pid:", nlmsg_pid);

          // 可以进一步解析 Generic Netlink 头部和属性
          // ...
        }
      },
    });
    console.log("Hooked sendto");
  } else {
    console.log("Failed to find sendto in libc.so");
  }
}

setTimeout(hook_sendto, 0);
```

这个 Frida 脚本会 hook `libc.so` 中的 `sendto` 函数。当 NDK 应用在 Netlink socket 上调用 `sendto` 时，脚本会打印出 socket 文件描述符、发送数据的长度以及 Netlink 消息头的一些基本信息。要解析更详细的 Netlink 消息内容，需要进一步读取和解析消息体中的 Generic Netlink 头部和属性，这需要对 Netlink 协议和 `batman_adv.h` 中定义的结构体有更深入的了解。

要调试接收过程，可以类似地 hook `recvfrom` 函数。还可以 hook 更高层的 Netlink 辅助库函数（如果应用使用了这些库），例如 `libnl` 中的函数。

请注意，直接与 `batman-adv` 交互的应用在普通 Android 设备上可能比较少见，更多可能出现在定制的 Android 系统或嵌入式设备中。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/batman_adv.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_BATMAN_ADV_H_
#define _UAPI_LINUX_BATMAN_ADV_H_
#define BATADV_NL_NAME "batadv"
#define BATADV_NL_MCAST_GROUP_CONFIG "config"
#define BATADV_NL_MCAST_GROUP_TPMETER "tpmeter"
enum batadv_tt_client_flags {
  BATADV_TT_CLIENT_DEL = (1 << 0),
  BATADV_TT_CLIENT_ROAM = (1 << 1),
  BATADV_TT_CLIENT_WIFI = (1 << 4),
  BATADV_TT_CLIENT_ISOLA = (1 << 5),
  BATADV_TT_CLIENT_NOPURGE = (1 << 8),
  BATADV_TT_CLIENT_NEW = (1 << 9),
  BATADV_TT_CLIENT_PENDING = (1 << 10),
  BATADV_TT_CLIENT_TEMP = (1 << 11),
};
enum batadv_mcast_flags_priv {
  BATADV_MCAST_FLAGS_BRIDGED = (1 << 0),
  BATADV_MCAST_FLAGS_QUERIER_IPV4_EXISTS = (1 << 1),
  BATADV_MCAST_FLAGS_QUERIER_IPV6_EXISTS = (1 << 2),
  BATADV_MCAST_FLAGS_QUERIER_IPV4_SHADOWING = (1 << 3),
  BATADV_MCAST_FLAGS_QUERIER_IPV6_SHADOWING = (1 << 4),
};
enum batadv_gw_modes {
  BATADV_GW_MODE_OFF,
  BATADV_GW_MODE_CLIENT,
  BATADV_GW_MODE_SERVER,
};
enum batadv_nl_attrs {
  BATADV_ATTR_UNSPEC,
  BATADV_ATTR_VERSION,
  BATADV_ATTR_ALGO_NAME,
  BATADV_ATTR_MESH_IFINDEX,
  BATADV_ATTR_MESH_IFNAME,
  BATADV_ATTR_MESH_ADDRESS,
  BATADV_ATTR_HARD_IFINDEX,
  BATADV_ATTR_HARD_IFNAME,
  BATADV_ATTR_HARD_ADDRESS,
  BATADV_ATTR_ORIG_ADDRESS,
  BATADV_ATTR_TPMETER_RESULT,
  BATADV_ATTR_TPMETER_TEST_TIME,
  BATADV_ATTR_TPMETER_BYTES,
  BATADV_ATTR_TPMETER_COOKIE,
  BATADV_ATTR_PAD,
  BATADV_ATTR_ACTIVE,
  BATADV_ATTR_TT_ADDRESS,
  BATADV_ATTR_TT_TTVN,
  BATADV_ATTR_TT_LAST_TTVN,
  BATADV_ATTR_TT_CRC32,
  BATADV_ATTR_TT_VID,
  BATADV_ATTR_TT_FLAGS,
  BATADV_ATTR_FLAG_BEST,
  BATADV_ATTR_LAST_SEEN_MSECS,
  BATADV_ATTR_NEIGH_ADDRESS,
  BATADV_ATTR_TQ,
  BATADV_ATTR_THROUGHPUT,
  BATADV_ATTR_BANDWIDTH_UP,
  BATADV_ATTR_BANDWIDTH_DOWN,
  BATADV_ATTR_ROUTER,
  BATADV_ATTR_BLA_OWN,
  BATADV_ATTR_BLA_ADDRESS,
  BATADV_ATTR_BLA_VID,
  BATADV_ATTR_BLA_BACKBONE,
  BATADV_ATTR_BLA_CRC,
  BATADV_ATTR_DAT_CACHE_IP4ADDRESS,
  BATADV_ATTR_DAT_CACHE_HWADDRESS,
  BATADV_ATTR_DAT_CACHE_VID,
  BATADV_ATTR_MCAST_FLAGS,
  BATADV_ATTR_MCAST_FLAGS_PRIV,
  BATADV_ATTR_VLANID,
  BATADV_ATTR_AGGREGATED_OGMS_ENABLED,
  BATADV_ATTR_AP_ISOLATION_ENABLED,
  BATADV_ATTR_ISOLATION_MARK,
  BATADV_ATTR_ISOLATION_MASK,
  BATADV_ATTR_BONDING_ENABLED,
  BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED,
  BATADV_ATTR_DISTRIBUTED_ARP_TABLE_ENABLED,
  BATADV_ATTR_FRAGMENTATION_ENABLED,
  BATADV_ATTR_GW_BANDWIDTH_DOWN,
  BATADV_ATTR_GW_BANDWIDTH_UP,
  BATADV_ATTR_GW_MODE,
  BATADV_ATTR_GW_SEL_CLASS,
  BATADV_ATTR_HOP_PENALTY,
  BATADV_ATTR_LOG_LEVEL,
  BATADV_ATTR_MULTICAST_FORCEFLOOD_ENABLED,
  BATADV_ATTR_NETWORK_CODING_ENABLED,
  BATADV_ATTR_ORIG_INTERVAL,
  BATADV_ATTR_ELP_INTERVAL,
  BATADV_ATTR_THROUGHPUT_OVERRIDE,
  BATADV_ATTR_MULTICAST_FANOUT,
  __BATADV_ATTR_AFTER_LAST,
  NUM_BATADV_ATTR = __BATADV_ATTR_AFTER_LAST,
  BATADV_ATTR_MAX = __BATADV_ATTR_AFTER_LAST - 1
};
enum batadv_nl_commands {
  BATADV_CMD_UNSPEC,
  BATADV_CMD_GET_MESH,
  BATADV_CMD_GET_MESH_INFO = BATADV_CMD_GET_MESH,
  BATADV_CMD_TP_METER,
  BATADV_CMD_TP_METER_CANCEL,
  BATADV_CMD_GET_ROUTING_ALGOS,
  BATADV_CMD_GET_HARDIF,
  BATADV_CMD_GET_HARDIFS = BATADV_CMD_GET_HARDIF,
  BATADV_CMD_GET_TRANSTABLE_LOCAL,
  BATADV_CMD_GET_TRANSTABLE_GLOBAL,
  BATADV_CMD_GET_ORIGINATORS,
  BATADV_CMD_GET_NEIGHBORS,
  BATADV_CMD_GET_GATEWAYS,
  BATADV_CMD_GET_BLA_CLAIM,
  BATADV_CMD_GET_BLA_BACKBONE,
  BATADV_CMD_GET_DAT_CACHE,
  BATADV_CMD_GET_MCAST_FLAGS,
  BATADV_CMD_SET_MESH,
  BATADV_CMD_SET_HARDIF,
  BATADV_CMD_GET_VLAN,
  BATADV_CMD_SET_VLAN,
  __BATADV_CMD_AFTER_LAST,
  BATADV_CMD_MAX = __BATADV_CMD_AFTER_LAST - 1
};
enum batadv_tp_meter_reason {
  BATADV_TP_REASON_COMPLETE = 3,
  BATADV_TP_REASON_CANCEL = 4,
  BATADV_TP_REASON_DST_UNREACHABLE = 128,
  BATADV_TP_REASON_RESEND_LIMIT = 129,
  BATADV_TP_REASON_ALREADY_ONGOING = 130,
  BATADV_TP_REASON_MEMORY_ERROR = 131,
  BATADV_TP_REASON_CANT_SEND = 132,
  BATADV_TP_REASON_TOO_MANY = 133,
};
enum batadv_ifla_attrs {
  IFLA_BATADV_UNSPEC,
  IFLA_BATADV_ALGO_NAME,
  __IFLA_BATADV_MAX,
};
#define IFLA_BATADV_MAX (__IFLA_BATADV_MAX - 1)
#endif
```