Response:
Let's break down the thought process to generate the comprehensive answer.

**1. Understanding the Core Request:**

The central task is to analyze a header file (`ioam6_genl.h`) within Android's Bionic library and explain its purpose, functionalities, relationship to Android, implementation details (even if the header doesn't *contain* the implementation), dynamic linking aspects (if any), potential errors, and how Android frameworks might use it, along with a Frida hooking example.

**2. Initial Interpretation of the Header File:**

The `#ifndef _UAPI_LINUX_IOAM6_GENL_H` suggests this is a UAPI (User API) header, intended for use by user-space applications. The presence of `genl` in the filename strongly indicates it relates to Generic Netlink, a Linux kernel mechanism for communication between the kernel and user-space. The "IOAM6" part likely refers to a specific kernel subsystem or module.

**3. Deconstructing the Header Content:**

* **`#define IOAM6_GENL_NAME "IOAM6"` and `#define IOAM6_GENL_VERSION 0x1`:**  These are straightforward definitions for the Netlink family name and version. This allows user-space to identify and communicate with the correct kernel module.

* **`enum { IOAM6_ATTR_... }`:** This defines attributes that can be exchanged in Netlink messages. The names suggest managing namespaces (like virtual networks or isolated environments) and schemas (data structures or rules). `IOAM6_ATTR_NS_ID`, `IOAM6_ATTR_NS_DATA`, `IOAM6_ATTR_SC_ID`, `IOAM6_ATTR_SC_DATA` are key here. `IOAM6_MAX_SCHEMA_DATA_LEN` provides a size constraint.

* **`enum { IOAM6_CMD_... }`:** This defines the commands that user-space can send to the kernel module. `ADD_NAMESPACE`, `DEL_NAMESPACE`, `DUMP_NAMESPACES`, `ADD_SCHEMA`, `DEL_SCHEMA`, `DUMP_SCHEMAS`, and `NS_SET_SCHEMA` clearly indicate operations related to managing namespaces and schemas.

* **`#define IOAM6_GENL_EV_GRP_NAME "ioam6_events"`:** This defines a multicast group name for events. This allows the kernel to send asynchronous notifications to interested user-space processes.

* **`enum ioam6_event_type { IOAM6_EVENT_UNSPEC, IOAM6_EVENT_TRACE };` and `enum ioam6_event_attr { ... };`:** These define the types of events the kernel can send and the attributes associated with those events. The `IOAM6_EVENT_TRACE` and related attributes (`TRACE_NAMESPACE`, `TRACE_NODELEN`, `TRACE_TYPE`, `TRACE_DATA`) strongly suggest this is used for some kind of tracing or monitoring functionality.

**4. Connecting to Android Functionality:**

Given that this is in `bionic`, which is core to Android, the functionality likely supports some aspect of Android's system management or monitoring. The namespace concept aligns with Android's process isolation and containerization (though this might be a lower-level mechanism). Tracing capabilities are crucial for debugging and performance analysis.

**5. Addressing Specific Requirements:**

* **Functionality Listing:**  Simply summarize the identified enums and defines.

* **Relationship to Android (with examples):** Focus on the namespace and tracing aspects and how they might relate to app isolation, system monitoring, and performance analysis.

* **libc Function Implementation:**  Acknowledge that this is a *header* file and doesn't contain libc *implementation*. Explain the role of header files and the actual system call interaction.

* **Dynamic Linker:**  Explain that *this specific header* isn't directly involved in dynamic linking. However, if user-space code *using* this header were dynamically linked, explain the general dynamic linking process and provide a basic `SO_LAYOUT` example. Emphasize the role of `dlopen`, `dlsym`, and `dlclose`.

* **Logical Reasoning (Assumptions):** Create plausible scenarios for how the commands and attributes could be used. For example, adding a namespace with specific data.

* **Common User Errors:** Think about typical mistakes developers make when interacting with Netlink or similar kernel interfaces, such as incorrect attribute packing, missing error handling, and not properly closing sockets.

* **Android Framework/NDK Path:**  Trace a hypothetical path from a high-level Android API (like `Trace` or network management APIs) down to the system call level and how this `ioam6_genl` interface might be involved. This requires some educated guessing, as the exact implementation is not in the provided code.

* **Frida Hook Example:** Demonstrate how to use Frida to intercept Netlink communication related to `IOAM6`. This involves finding the relevant system calls (like `socket`, `bind`, `sendto`, `recvfrom`) and filtering for the correct Netlink family.

**6. Structuring the Answer:**

Organize the information logically with clear headings and bullet points for readability. Start with a general overview, then delve into specifics, and finally address the more advanced aspects like dynamic linking and Frida hooking.

**7. Language and Tone:**

Use clear, concise, and technical language. Explain concepts thoroughly, but avoid unnecessary jargon. Use code examples where appropriate.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This might directly involve Android app network namespaces."  **Correction:**  While related, it's more likely a lower-level system component used *by* the mechanisms that manage app namespaces.
* **Initial thought:** "Let's explain how `open()` and `read()` work in libc." **Correction:**  This header deals with Netlink, not file I/O. Focus on the relevant system calls for Netlink.
* **Initial thought:** "The Frida example should hook specific functions within the Bionic library." **Correction:**  Since this is a kernel interface, hooking at the system call level is more appropriate and direct.

By following this thought process, systematically analyzing the input, and addressing each part of the request, a comprehensive and accurate answer can be generated.
这个头文件 `bionic/libc/kernel/uapi/linux/ioam6_genl.h` 定义了用于与 Linux 内核中的 `IOAM6` 模块进行交互的通用 Netlink 协议的常量和数据结构。`UAPI` 表示用户空间 API，意味着这些定义用于用户空间程序与内核进行通信。`genl` 表明它使用的是 Generic Netlink 框架。

以下是对其功能的详细解释：

**功能列举:**

这个头文件主要定义了以下内容，用于用户空间程序与内核 `IOAM6` 模块进行通信：

1. **Netlink Family 名称和版本:**
   - `IOAM6_GENL_NAME "IOAM6"`: 定义了用于识别该 Netlink Family 的名称。用户空间程序需要使用这个名称来查找对应的 Netlink ID。
   - `IOAM6_GENL_VERSION 0x1`: 定义了该 Netlink Family 的版本号。

2. **Netlink 属性 (Attributes):**
   - `enum { IOAM6_ATTR_UNSPEC, ... }`: 定义了可以通过 Netlink 消息传递的各种属性的枚举值。这些属性用于传递具体的数据。
     - `IOAM6_ATTR_NS_ID`:  命名空间 ID。
     - `IOAM6_ATTR_NS_DATA`:  命名空间数据。
     - `IOAM6_ATTR_NS_DATA_WIDE`: 宽命名空间数据（可能是指更大的数据块）。
     - `IOAM6_MAX_SCHEMA_DATA_LEN`: 定义了 Schema 数据的最大长度。
     - `IOAM6_ATTR_SC_ID`:  Schema ID。
     - `IOAM6_ATTR_SC_DATA`:  Schema 数据。
     - `IOAM6_ATTR_SC_NONE`:  表示没有 Schema 数据。
     - `IOAM6_ATTR_PAD`:  用于填充，以满足对齐要求。
   - `#define IOAM6_ATTR_MAX (__IOAM6_ATTR_MAX - 1)`:  定义了最大属性值的宏。

3. **Netlink 命令 (Commands):**
   - `enum { IOAM6_CMD_UNSPEC, ... }`: 定义了用户空间可以发送给内核 `IOAM6` 模块的各种命令的枚举值。
     - `IOAM6_CMD_ADD_NAMESPACE`: 添加一个命名空间。
     - `IOAM6_CMD_DEL_NAMESPACE`: 删除一个命名空间。
     - `IOAM6_CMD_DUMP_NAMESPACES`: 获取所有命名空间的列表。
     - `IOAM6_CMD_ADD_SCHEMA`: 添加一个 Schema。
     - `IOAM6_CMD_DEL_SCHEMA`: 删除一个 Schema。
     - `IOAM6_CMD_DUMP_SCHEMAS`: 获取所有 Schema 的列表。
     - `IOAM6_CMD_NS_SET_SCHEMA`: 为一个命名空间设置 Schema。
   - `#define IOAM6_CMD_MAX (__IOAM6_CMD_MAX - 1)`: 定义了最大命令值的宏。

4. **Netlink 事件 (Events):**
   - `#define IOAM6_GENL_EV_GRP_NAME "ioam6_events"`: 定义了用于 `IOAM6` 模块事件的多播组名称。用户空间程序可以订阅这个组来接收相关的事件通知。
   - `enum ioam6_event_type { IOAM6_EVENT_UNSPEC, IOAM6_EVENT_TRACE };`: 定义了事件的类型。目前只有一个 `IOAM6_EVENT_TRACE`，表示跟踪事件。
   - `enum ioam6_event_attr { IOAM6_EVENT_ATTR_UNSPEC, ... };`: 定义了事件属性，用于传递事件的具体信息。
     - `IOAM6_EVENT_ATTR_TRACE_NAMESPACE`: 跟踪事件所属的命名空间。
     - `IOAM6_EVENT_ATTR_TRACE_NODELEN`:  跟踪节点的长度。
     - `IOAM6_EVENT_ATTR_TRACE_TYPE`:  跟踪类型。
     - `IOAM6_EVENT_ATTR_TRACE_DATA`:  跟踪数据。
   - `#define IOAM6_EVENT_ATTR_MAX (__IOAM6_EVENT_ATTR_MAX - 1)`: 定义了最大事件属性值的宏。

**与 Android 功能的关系举例:**

这个头文件定义的 `IOAM6` 模块很可能与 Android 系统中的 **监控、性能分析或网络管理** 相关。从命名上看，`IOAM` 可能代表 "In-situ OAM" (Operation, Administration, and Maintenance)，这是一种网络管理和监控技术。

以下是一些可能的联系：

* **网络监控和调试:**  `IOAM6` 可能用于在网络数据包中嵌入元数据，以便在网络路径上的不同节点进行监控和分析。Android 系统可能利用这个模块来收集网络性能数据，例如延迟、丢包率等，用于诊断网络问题或进行性能优化。
* **资源管理和隔离:** "命名空间" (Namespace) 的概念在 Linux 中常用于资源隔离。 `IOAM6` 中对命名空间的操作可能与 Android 系统中进程或网络命名空间的管理有关。例如，Android 可以使用它来隔离不同应用的网络流量或资源使用情况。
* **系统跟踪和事件:** `IOAM6_EVENT_TRACE` 表明该模块可以产生跟踪事件。Android 框架或底层服务可能使用这些事件来监控系统的行为，进行性能分析或故障排查。

**详细解释 libc 函数的功能实现:**

**重要的理解是：这个头文件本身并没有包含任何 libc 函数的实现代码。** 它只是定义了常量和数据结构，用于与内核模块进行交互。

用户空间程序需要使用标准的 libc 函数，例如 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等，以及一些特定于 Netlink 的辅助函数（通常不是标准 libc 的一部分，可能来自 `libnl` 或自定义库），来构建和发送/接收 Netlink 消息。

以下是一些可能涉及的 libc 函数以及它们在与 `IOAM6` 交互中的作用：

1. **`socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)`:**
   - **功能:** 创建一个 Netlink 套接字。
   - **实现:**  `socket()` 是一个系统调用，它请求内核创建一个新的套接字文件描述符。参数 `AF_NETLINK` 指定了地址族为 Netlink，`SOCK_RAW` 表示原始套接字，`NETLINK_GENERIC` 指定了 Netlink 协议类型为 Generic Netlink。内核会分配必要的资源并返回一个文件描述符。

2. **`bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`:**
   - **功能:** 将套接字绑定到一个地址。对于 Netlink 套接字，这意味着指定要连接的 Netlink Family ID 和进程 ID。
   - **实现:** `bind()` 也是一个系统调用。对于 Netlink，通常需要填充一个 `struct sockaddr_nl` 结构体，包含 `nl_family` (设置为 `AF_NETLINK`)，`nl_pid` (设置为进程 ID，通常为 0 表示内核)，以及 `nl_groups` (用于订阅多播组)。内核会将套接字与指定的地址关联起来。

3. **`sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)`:**
   - **功能:** 通过套接字发送数据报。用于向内核 `IOAM6` 模块发送命令和数据。
   - **实现:** `sendto()` 是一个系统调用。用户空间程序需要构建一个 Netlink 消息，包含消息头、Generic Netlink 头以及包含命令和属性的有效载荷。`dest_addr` 参数需要填充目标内核模块的 Netlink 地址信息。

4. **`recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)`:**
   - **功能:** 从套接字接收数据报。用于接收来自内核 `IOAM6` 模块的响应或事件通知。
   - **实现:** `recvfrom()` 是一个系统调用。内核将数据包放入接收缓冲区，并唤醒等待的进程。接收到的数据需要解析 Netlink 消息头和有效载荷，以提取命令结果或事件信息。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及动态链接。它定义的是内核接口。然而，用户空间中与内核交互的代码可能会被编译成动态链接库 (`.so`)。

**SO 布局样本 (假设一个使用 `IOAM6` 的库):**

```
libioam_client.so:
    .text           # 代码段
        connect_to_ioam6
        send_add_namespace
        receive_namespace_list
        ...
    .data           # 数据段
        ioam6_family_id
        ...
    .bss            # 未初始化数据段
    .dynamic        # 动态链接信息
        NEEDED         libc.so
        SONAME         libioam_client.so
        ...
    .symtab         # 符号表
        connect_to_ioam6 (GLOBAL, FUNC)
        send_add_namespace (GLOBAL, FUNC)
        ...
    .strtab         # 字符串表
        connect_to_ioam6
        send_add_namespace
        ...
```

**链接的处理过程:**

1. **编译时链接:** 当开发者编译使用 `libioam_client.so` 的应用程序时，链接器会将对 `libioam_client.so` 中导出符号的引用记录在应用程序的可执行文件中。

2. **加载时链接 (动态链接):** 当应用程序启动时，Android 的动态链接器 (`linker64` 或 `linker`) 会执行以下步骤：
   - **加载依赖库:**  读取应用程序可执行文件的 `.dynamic` 段，找到依赖的库 (`NEEDED`)，例如 `libc.so` 和 `libioam_client.so`。
   - **加载 SO:** 将这些 `.so` 文件加载到内存中。加载器会根据 `.so` 文件的头部信息确定代码段、数据段等的位置。
   - **符号解析 (Symbol Resolution):**  遍历应用程序中的未定义符号，并在加载的共享库的符号表 (`.symtab`) 中查找匹配的符号。例如，如果应用程序调用了 `libioam_client.so` 中的 `connect_to_ioam6` 函数，链接器会在 `libioam_client.so` 的符号表中找到该符号的地址。
   - **重定位 (Relocation):**  由于共享库加载到内存的地址可能不是编译时的地址，链接器需要修改代码段和数据段中的某些地址，使其指向正确的内存位置。例如，对全局变量的访问需要进行重定位。

**假设输入与输出 (逻辑推理):**

假设用户空间程序想要添加一个名为 "my_network" 的命名空间，并传递一些关联数据。

**假设输入:**

* 命令: `IOAM6_CMD_ADD_NAMESPACE`
* 属性:
    * `IOAM6_ATTR_NS_ID`:  例如，123
    * `IOAM6_ATTR_NS_DATA`:  例如，"network configuration data" (编码为字节流)

**预期输出 (来自内核):**

* 成功响应: 可能是一个没有有效载荷的确认消息，或者包含新创建命名空间的详细信息。
* 失败响应:  可能包含一个错误码，指示添加失败的原因（例如，命名空间 ID 已存在）。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **未正确初始化 Netlink 消息结构:**  忘记设置消息头中的 `nlmsg_len`, `nlmsg_type`, `nlmsg_flags` 等字段，或者 Generic Netlink 头中的 `cmd` 和 `version` 字段。

   ```c
   struct nlmsghdr nlh;
   // 忘记设置 nlh.nlmsg_len 等
   ```

2. **属性编码错误:**  在将属性添加到 Netlink 消息时，使用了错误的类型或长度。例如，将字符串长度计算错误，或者使用了错误的对齐方式。

3. **忘记处理错误:**  `sendto()` 和 `recvfrom()` 可能返回错误。未能检查返回值可能导致程序在出现问题时继续执行，导致不可预测的行为。

   ```c
   if (sendto(...) < 0) {
       perror("sendto failed"); // 缺少错误处理
   }
   ```

4. **Netlink Family ID 错误:**  在连接到 Netlink 套接字时使用了错误的 Family ID。需要先通过 `resolve_genl_family()` 或类似方法获取正确的 ID。

5. **权限问题:**  某些 Netlink 操作可能需要特定的权限。用户空间程序可能因为权限不足而无法执行某些命令。

6. **并发问题:** 如果多个进程同时尝试操作 `IOAM6` 模块，可能会出现竞争条件，导致数据不一致或其他问题。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 `ioam6_genl.h` 定义的是内核接口，Android Framework 或 NDK 通常不会直接使用这个头文件。相反，它们可能会通过以下步骤间接地与之交互：

1. **Android Framework 层:** Android Framework 中的高级服务 (例如，网络管理服务) 可能需要获取或设置与网络相关的低级信息。这些服务可能会调用底层的 Binder 接口与 Native 服务通信。

2. **Native 服务层:**  Native 服务 (通常是用 C++ 编写) 负责处理来自 Framework 的请求。这些服务可能会使用标准的 Linux 系统调用和 Netlink 接口与内核 `IOAM6` 模块进行通信。这些 Native 服务可能会封装与 Netlink 交互的复杂性，并向上层提供更简洁的 API。

3. **NDK 使用 (较少见):** 虽然不常见，但如果开发者需要进行非常底层的网络或系统监控，他们可以使用 NDK 直接编写代码来与 Netlink 接口交互。在这种情况下，开发者会使用 `socket()`, `bind()`, `sendto()`, `recvfrom()` 等系统调用，并参考 `ioam6_genl.h` 中定义的常量和结构体。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截发送给 `IOAM6` 模块的 Netlink 消息的示例：

```javascript
// attach 到目标进程
const processName = "com.example.myapp"; // 替换为目标进程名
const session = frida.attach(processName);

session.then(() => {
    console.log(`Attached to process: ${processName}`);

    // 拦截 sendto 系统调用
    const sendtoPtr = Module.findExportByName(null, "sendto");
    if (sendtoPtr) {
        Interceptor.attach(sendtoPtr, {
            onEnter: function (args) {
                const sockfd = args[0].toInt32();
                const bufPtr = args[1];
                const len = args[2].toInt32();
                const destAddrPtr = args[4];

                // 检查是否是 Netlink 套接字 (这里只是一个简单的检查，更严谨的需要检查地址族)
                try {
                    const destAddr = destAddrPtr.readByteArray(16); // sockaddr_nl 结构体大小
                    const nlFamily = destAddr.readU16();
                    if (nlFamily === 18) { // AF_NETLINK 的值
                        console.log("sendto called for Netlink socket:", sockfd);
                        console.log("Length:", len);

                        // 读取并打印 Netlink 消息内容
                        const nlMsg = bufPtr.readByteArray(len);
                        console.log("Netlink Message:", hexdump(nlMsg, { ansi: true }));

                        // 可以进一步解析 Netlink 消息头和 Generic Netlink 头
                        // 并根据 IOAM6_GENL_NAME 过滤
                    }
                } catch (e) {
                    // 忽略读取地址可能出现的错误
                }
            }
        });
        console.log("Hooked sendto");
    } else {
        console.error("Could not find sendto");
    }
});
```

**示例说明:**

1. **`frida.attach(processName)`:**  将 Frida 连接到目标 Android 进程。
2. **`Module.findExportByName(null, "sendto")`:**  查找 `sendto` 系统调用的地址。`null` 表示在所有已加载的模块中查找。
3. **`Interceptor.attach(sendtoPtr, { ... })`:**  拦截 `sendto` 函数的调用。
4. **`onEnter: function (args)`:**  在 `sendto` 函数执行之前调用。`args` 数组包含了传递给 `sendto` 的参数。
5. **参数解析:** 从 `args` 中获取套接字描述符、数据缓冲区指针、数据长度和目标地址指针。
6. **Netlink 检查:** 检查目标地址的地址族是否为 `AF_NETLINK`，以确定是否是 Netlink 套接字。
7. **消息读取和打印:** 读取 Netlink 消息的内容并使用 `hexdump` 打印出来。
8. **进一步解析:**  在实际调试中，你可以进一步解析 Netlink 消息头和 Generic Netlink 头，以确定是否是与 `IOAM6` 模块的通信。你需要检查 `genl_family` 是否与 `IOAM6_GENL_NAME` 对应。

这个 Frida 示例提供了一个基本的框架，你可以根据需要进行扩展，例如过滤特定的 `IOAM6` 命令或属性，或者修改发送的数据。

总而言之，`bionic/libc/kernel/uapi/linux/ioam6_genl.h` 定义了与 Linux 内核 `IOAM6` 模块交互的接口，它对于理解 Android 系统中可能涉及的网络监控、资源管理或性能分析的底层机制非常重要。虽然开发者通常不会直接使用它，但理解其定义有助于理解 Android 系统更深层次的运作原理。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/ioam6_genl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_IOAM6_GENL_H
#define _UAPI_LINUX_IOAM6_GENL_H
#define IOAM6_GENL_NAME "IOAM6"
#define IOAM6_GENL_VERSION 0x1
enum {
  IOAM6_ATTR_UNSPEC,
  IOAM6_ATTR_NS_ID,
  IOAM6_ATTR_NS_DATA,
  IOAM6_ATTR_NS_DATA_WIDE,
#define IOAM6_MAX_SCHEMA_DATA_LEN (255 * 4)
  IOAM6_ATTR_SC_ID,
  IOAM6_ATTR_SC_DATA,
  IOAM6_ATTR_SC_NONE,
  IOAM6_ATTR_PAD,
  __IOAM6_ATTR_MAX,
};
#define IOAM6_ATTR_MAX (__IOAM6_ATTR_MAX - 1)
enum {
  IOAM6_CMD_UNSPEC,
  IOAM6_CMD_ADD_NAMESPACE,
  IOAM6_CMD_DEL_NAMESPACE,
  IOAM6_CMD_DUMP_NAMESPACES,
  IOAM6_CMD_ADD_SCHEMA,
  IOAM6_CMD_DEL_SCHEMA,
  IOAM6_CMD_DUMP_SCHEMAS,
  IOAM6_CMD_NS_SET_SCHEMA,
  __IOAM6_CMD_MAX,
};
#define IOAM6_CMD_MAX (__IOAM6_CMD_MAX - 1)
#define IOAM6_GENL_EV_GRP_NAME "ioam6_events"
enum ioam6_event_type {
  IOAM6_EVENT_UNSPEC,
  IOAM6_EVENT_TRACE,
};
enum ioam6_event_attr {
  IOAM6_EVENT_ATTR_UNSPEC,
  IOAM6_EVENT_ATTR_TRACE_NAMESPACE,
  IOAM6_EVENT_ATTR_TRACE_NODELEN,
  IOAM6_EVENT_ATTR_TRACE_TYPE,
  IOAM6_EVENT_ATTR_TRACE_DATA,
  __IOAM6_EVENT_ATTR_MAX
};
#define IOAM6_EVENT_ATTR_MAX (__IOAM6_EVENT_ATTR_MAX - 1)
#endif
```