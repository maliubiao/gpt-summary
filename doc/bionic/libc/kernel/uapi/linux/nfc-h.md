Response:
Let's break down the thought process for analyzing this NFC header file.

1. **Identify the Core Purpose:** The first step is to understand what this file *is*. The comment at the top clearly states it's an auto-generated header file for the Linux NFC subsystem, specifically within the Android Bionic library (kernel UAPI). This immediately tells us it defines the interface between user-space (Android framework/NDK) and the kernel's NFC driver.

2. **Dissect the Structure:** Header files define constants, enums, structs, and function prototypes (though this one doesn't have function prototypes). We should systematically go through each of these.

3. **Enumerate Definitions and Their Meanings:**

   * **Includes:** `<linux/types.h>` and `<linux/socket.h>` are fundamental kernel headers. They provide basic type definitions and socket structures. This suggests NFC communication might involve socket-like interactions.

   * **`#define` Constants:**
      * `NFC_GENL_NAME`, `NFC_GENL_VERSION`, `NFC_GENL_MCAST_EVENT_NAME`: These strongly suggest the use of Generic Netlink for communication. Generic Netlink is a standard Linux mechanism for communication between kernel and userspace. The names hint at control and event signaling.
      * `NFC_CMD_MAX`, `NFC_ATTR_MAX`, `NFC_SDP_ATTR_MAX`: These define the upper bounds for the enumerated command and attribute types.
      * Size-related defines (e.g., `NFC_DEVICE_NAME_MAXSIZE`): These impose limits on the size of data fields. Good to note for potential buffer overflow concerns in usage (though the kernel driver should ideally handle this).
      * Protocol masks (e.g., `NFC_PROTO_JEWEL_MASK`):  These are bitmasks to represent which NFC protocols are active.
      * `NFC_SE_*` defines: Relate to Secure Element functionality (UICC, embedded).

   * **`enum` Types:**
      * `nfc_commands`:  A list of commands that can be sent to the NFC driver. Examples: `GET_DEVICE`, `DEV_UP`, `START_POLL`, `ENABLE_SE`, `SE_IO`. These reveal the core functionalities exposed by the NFC subsystem.
      * `nfc_attrs`: Attributes associated with the commands or events. Examples: `DEVICE_INDEX`, `DEVICE_NAME`, `TARGET_NFCID1`, `SE_TYPE`, `VENDOR_DATA`. These are the data payloads carried in the communication.
      * `nfc_sdp_attr`:  Attributes specifically related to Service Discovery Protocol (SDP).
      * Other enums (protocol types, communication modes, RF modes) define various configuration options and states of the NFC controller.

   * **`struct` Types:**
      * `sockaddr_nfc`:  A socket address structure specific to NFC. It includes device and target indices, and the NFC protocol. This confirms the likely use of sockets.
      * `sockaddr_nfc_llcp`: An extension of the NFC socket address for Logical Link Control Protocol (LLCP), including service name and SAPs.

   * **Other Defines:** Socket protocol defines (`NFC_SOCKPROTO_*`), header sizes, direction (RX/TX), raw payload types, LLCP parameters.

4. **Connect to Android Functionality:** Now, think about how these definitions map to what Android NFC does.

   * **`NFC_CMD_GET_DEVICE` and related attributes:**  Android needs to discover NFC controllers.
   * **`NFC_CMD_DEV_UP`/`DOWN`:** Turning the NFC radio on and off.
   * **Polling commands:** The basis for tag detection.
   * **Target commands:** Interacting with discovered NFC tags.
   * **SE commands:**  Accessing secure elements for things like mobile payments.
   * **LLCP:** For peer-to-peer NFC communication (Android Beam).
   * **Events (e.g., `TARGETS_FOUND`, `DEVICE_ADDED`):**  Notifications that Android framework uses to react to NFC events.

5. **Address Specific Questions:** Go back to the prompt and answer each part methodically.

   * **Functionality Listing:**  Summarize the identified commands and attributes in a user-friendly way.
   * **Android Relationship:** Explain the connection between the defined elements and higher-level Android NFC features. Provide concrete examples like tag reading, payment, and peer-to-peer.
   * **libc Functions:** This header file *doesn't* define libc functions. It defines *kernel* structures and constants. This is an important distinction. Emphasize this.
   * **Dynamic Linker:**  This header file itself isn't directly related to dynamic linking. However, the *usage* of the NFC functionality *will* involve dynamic linking of libraries that interact with the kernel. Provide a typical `libnfc.so` example and the linking process conceptually.
   * **Logical Reasoning:**  Give examples of how the commands and attributes might be used together (e.g., getting device info).
   * **Common Errors:**  Think about how developers might misuse these definitions, such as incorrect size assumptions or invalid command sequences.
   * **Android Framework/NDK Path:**  Outline the flow from the Android framework down to the kernel, emphasizing the role of Binder and potentially native libraries.
   * **Frida Hooking:** Provide practical Frida examples that target specific commands or events. This demonstrates how to observe and intercept NFC interactions.

6. **Review and Refine:**  Read through the entire answer to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or areas where more detail might be helpful. For example, initially, I might not have explicitly mentioned Generic Netlink, but seeing the `NFC_GENL_*` definitions should trigger that connection. Also, double-checking the prompt to make sure all questions are addressed is crucial. The distinction between kernel UAPI and libc functions needs to be very clear.
这个文件 `bionic/libc/kernel/uapi/linux/nfc.handroid` 是 Android Bionic 库中关于 Linux NFC (Near Field Communication) 子系统的用户空间 API 头文件。它定义了用户空间程序（例如 Android Framework 或 NDK 应用）与 Linux 内核中的 NFC 驱动程序进行交互所需的常量、枚举和结构体。

**功能列举：**

1. **定义了与 NFC 设备进行通信的命令 (Commands)：**  `enum nfc_commands` 列出了可以发送给 NFC 驱动程序的各种操作指令，例如获取设备信息、启动/停止轮询、激活/停用目标设备、启用/禁用安全元件 (SE) 等。

2. **定义了与 NFC 设备和操作相关的属性 (Attributes)：** `enum nfc_attrs` 列出了与 NFC 设备、目标设备和通信过程相关的各种属性，例如设备索引、设备名称、支持的协议、目标设备的各种标识符 (如 NFCID1)、通信模式、RF 模式、安全元件相关信息等。

3. **定义了与 NFC 服务发现协议 (SDP) 相关的属性 (SDP Attributes)：** `enum nfc_sdp_attr` 列出了用于 NFC 服务发现协议的属性，例如 URI (统一资源标识符) 和 SAP (服务接入点)。

4. **定义了各种常量 (Constants)：**  例如，定义了设备名称、各种 ID、响应数据的最大长度，以及各种 NFC 协议的标识符和掩码。

5. **定义了网络套接字相关的结构体 (Socket Structures)：**  `struct sockaddr_nfc` 和 `struct sockaddr_nfc_llcp` 定义了用于 NFC 通信的套接字地址结构，允许用户空间程序通过套接字接口与 NFC 驱动程序进行交互。  `sockaddr_nfc_llcp` 专门用于 LLCP (Logical Link Control Protocol) 通信。

6. **定义了套接字协议类型 (Socket Protocol Types)：** `NFC_SOCKPROTO_RAW` 和 `NFC_SOCKPROTO_LLCP` 定义了可以用于 NFC 套接字的协议类型，分别对应原始 NFC 帧和 LLCP 协议。

7. **定义了其他与底层通信相关的常量：** 例如，头部大小、数据传输方向、原始负载类型等。

**与 Android 功能的关系及举例说明：**

这个头文件是 Android NFC 功能的基础。Android Framework 或 NDK 通过底层的 C/C++ 库与内核中的 NFC 驱动程序进行交互，而这个头文件就定义了这种交互的接口。

* **NFC 开启/关闭：** Android 系统可以通过发送 `NFC_CMD_DEV_UP` 和 `NFC_CMD_DEV_DOWN` 命令来控制 NFC 芯片的开关。例如，用户在 Android 设置中切换 NFC 开关时，Framework 会调用相应的 Native 方法，最终通过 Netlink 或其他内核接口发送这些命令。

* **NFC 标签扫描：**  当 Android 设备搜索附近的 NFC 标签时，Framework 会发送 `NFC_CMD_START_POLL` 命令，并监听 `NFC_EVENT_TARGETS_FOUND` 事件。接收到该事件后，Framework 可以通过 `NFC_ATTR_TARGET_*` 相关的属性获取标签的信息，例如标签的类型、ID 等。

* **HCE (Host-based Card Emulation) 和 SE (Secure Element) 相关操作：** Android 支付功能会涉及到 HCE 或使用安全元件进行交易。Framework 可以通过 `NFC_CMD_ENABLE_SE` 和 `NFC_CMD_DISABLE_SE` 命令来控制安全元件的启用和禁用。进行 APDU (Application Protocol Data Unit) 通信时，会使用 `NFC_CMD_SE_IO` 命令，并通过 `NFC_ATTR_SE_APDU` 属性传递 APDU 数据。

* **Android Beam (P2P)：** Android Beam 功能使用了 LLCP 协议。Framework 可以使用 `sockaddr_nfc_llcp` 结构体创建套接字，并使用 `NFC_SOCKPROTO_LLCP` 协议类型进行设备间的点对点数据传输。

**libc 函数的功能实现：**

这个头文件本身**并不定义 libc 函数**。它定义的是内核的 API 接口。用户空间的库（例如 Android 的 `libnfc_nci.so` 或其他 NFC HAL 实现）会使用这个头文件中定义的常量、枚举和结构体，通过系统调用（例如 `socket`, `bind`, `sendto`, `recvfrom` 等 libc 函数）与内核中的 NFC 驱动程序进行通信。

例如，`libnfc_nci.so` 可能会使用 `socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)` 创建一个 Netlink 套接字，然后使用 `sendto` 发送包含这个头文件中定义的命令和属性的 Netlink 消息给内核。

**dynamic linker 的功能：**

这个头文件本身与 dynamic linker 没有直接关系。但是，当 Android 系统启动 NFC 功能时，会加载相关的动态链接库，例如 `libnfc_nci.so`。

**so 布局样本：**

```
/system/lib64/libnfc_nci.so  (64位系统)
/system/lib/libnfc_nci.so   (32位系统)

该 so 文件可能依赖于其他的库，例如：
/system/lib64/libc.so
/system/lib64/liblog.so
/system/lib64/libutils.so
... 其他与硬件抽象层 (HAL) 相关的库
```

**链接的处理过程：**

1. **加载器 (loader)：** 当 Android 系统需要使用 NFC 功能时，例如启动一个需要 NFC 的应用或服务时，`/system/bin/app_process` 或 `zygote` 进程会使用 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 来加载 `libnfc_nci.so`。

2. **依赖分析：** Dynamic linker 会解析 `libnfc_nci.so` 的 ELF 文件头，找出其依赖的其他共享库。

3. **加载依赖库：** Dynamic linker 会按照依赖关系，依次加载所需的共享库到内存中。

4. **符号解析与重定位：** Dynamic linker 会解析 `libnfc_nci.so` 中引用的来自其他共享库的符号 (例如函数或全局变量)。它会在已加载的共享库中查找这些符号的地址，并将 `libnfc_nci.so` 中的相应引用地址更新为实际的内存地址，这个过程称为重定位。

5. **执行初始化代码：**  加载和链接完成后，dynamic linker 会执行每个共享库中的初始化代码（通常是 `.init` 和 `.ctors` section 中的代码）。

**假设输入与输出（逻辑推理）：**

假设用户在 Android 设置中点击开启 NFC 开关。

* **假设输入：** Android Framework 接收到用户操作的广播或事件。
* **逻辑推理：**
    1. Framework 调用 NFC 服务相关的 Java 代码。
    2. NFC 服务通过 JNI (Java Native Interface) 调用 Native 代码（可能在 `libnfc_nci.so` 中）。
    3. Native 代码创建一个 Netlink 套接字。
    4. Native 代码构造一个 Netlink 消息，其 payload 中包含 `NFC_CMD_DEV_UP` 命令，以及可能相关的设备索引 `NFC_ATTR_DEVICE_INDEX`。
    5. Native 代码使用 `sendto` 系统调用将该消息发送到内核。
* **假设输出：**
    1. 内核中的 NFC 驱动程序接收到该 Netlink 消息。
    2. 驱动程序解析消息，识别出 `NFC_CMD_DEV_UP` 命令。
    3. 驱动程序执行相应的操作，例如初始化 NFC 控制器，开启射频等。
    4. 驱动程序可能通过 Netlink 发送一个确认消息或事件回用户空间。
    5. Framework 接收到确认消息，更新 UI 状态，表示 NFC 已开启。

**用户或编程常见的使用错误：**

1. **错误的属性值：**  在构造 Netlink 消息时，传递了错误的属性值，例如设备索引不存在，或者协议类型不支持。这会导致内核驱动程序处理错误或忽略该命令。

   ```c++
   // 错误示例：使用了不存在的设备索引
   struct nlmsghdr *nlh = // ... 构建 Netlink 消息头
   struct nfcmessage *nfc_msg = NLMSG_DATA(nlh);
   nfc_msg->cmd = NFC_CMD_GET_DEVICE;
   addattr_l(nlh, MAX_NL_MSG, NFC_ATTR_DEVICE_INDEX, &invalid_device_index, sizeof(invalid_device_index));
   sendto(sockfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
   ```

2. **命令顺序错误：**  例如，在没有启动轮询的情况下尝试获取目标设备信息。这会导致内核返回错误，因为操作的前提条件不满足。

3. **缓冲区溢出：**  在处理从内核接收到的数据时，没有正确检查数据长度，导致写入缓冲区超出边界。虽然内核驱动应该避免发送过大的数据，但用户空间代码也需要进行校验。

4. **忘记处理错误：**  `sendto` 和 `recvfrom` 等系统调用可能会失败，用户空间代码需要检查返回值并进行适当的错误处理，否则可能会导致程序行为异常。

**Android Framework 或 NDK 如何一步步到达这里：**

1. **Android Framework (Java 层)：** 用户与 Android 系统的 NFC 功能交互，例如在设置中切换 NFC 开关，或者使用支持 NFC 的应用。Framework 层的 Java 代码会调用 `android.nfc` 包下的相关类，例如 `NfcAdapter`, `NfcManager` 等。

2. **NFC Service (Java 层)：** Framework 层的 API 调用会委托给 System Server 进程中的 NFC 服务 (`com.android.server.nfc.NfcService`)。

3. **Native 代码 (JNI)：** NFC 服务通过 JNI (Java Native Interface) 调用 Native 代码。这些 Native 代码通常位于 `packages/modules/Nfc/nci/jni/` 或相关的 HAL (Hardware Abstraction Layer) 实现中。

4. **NFC HAL (Hardware Abstraction Layer)：** Native 代码会调用 NFC HAL 接口，这些接口定义了与底层 NFC 芯片交互的标准方法。HAL 的实现通常由设备制造商提供，例如 `vendor/xxx/libnfc_nci.so`。

5. **Netlink 或其他内核接口：**  HAL 的实现（例如 `libnfc_nci.so`）会使用 Linux 的内核接口与 NFC 驱动程序通信。常见的接口是 Netlink 套接字。HAL 代码会创建 Netlink 套接字，并构造包含这个头文件中定义的命令和属性的 Netlink 消息，然后使用 `sendto` 系统调用发送给内核。

6. **Linux Kernel NFC Driver：**  内核中的 NFC 驱动程序（例如 `drivers/nfc/pn544.c` 或类似的驱动）会接收并解析来自用户空间的 Netlink 消息，执行相应的操作，并可能通过 Netlink 发送事件回用户空间。

**Frida Hook 示例调试步骤：**

假设我们要 Hook `libnfc_nci.so` 中发送 `NFC_CMD_DEV_UP` 命令的代码。

```javascript
// Frida 脚本

// 假设你知道 libnfc_nci.so 中发送 Netlink 消息的函数，例如 send_generic_message
// 这里只是一个假设的函数名，实际名称需要根据具体实现查找

const sendGenericMessage = Module.findExportByName("libnfc_nci.so", "_ZN3xxx18send_generic_messageEPKNS_10nfc_message_tE"); // 替换为实际函数签名

if (sendGenericMessage) {
  Interceptor.attach(sendGenericMessage, {
    onEnter: function (args) {
      const nfcMessagePtr = args[0];
      if (nfcMessagePtr) {
        const cmd = Memory.readU32(nfcMessagePtr.add(offset_of_command)); // 替换为 nfc_message_t 结构体中 cmd 字段的偏移

        if (cmd === 1) { // 假设 NFC_CMD_DEV_UP 的值为 1
          console.log("Sending NFC_CMD_DEV_UP command!");
          // 你可以进一步检查消息的其他属性
          // 例如，遍历 Netlink 消息的属性
        }
      }
    }
  });
} else {
  console.log("send_generic_message function not found.");
}

// 查找 sendto 系统调用，可以监控所有发送到内核的消息
const sendtoPtr = Module.findExportByName(null, "sendto");
if (sendtoPtr) {
  Interceptor.attach(sendtoPtr, {
    onEnter: function (args) {
      const sockfd = args[0].toInt32();
      const buf = args[1];
      const len = args[2].toInt32();
      const flags = args[3].toInt32();
      const dest_addr = args[4];
      const addrlen = args[5].toInt32();

      // 可以检查 sockfd 是否是 Netlink 套接字
      // 并解析 buf 中的 Netlink 消息，查看是否包含 NFC 相关的命令

      console.log("sendto called!");
      console.log("  sockfd:", sockfd);
      console.log("  buf:", buf);
      console.log("  len:", len);

      // 尝试解析 Netlink 消息头
      const nlmsg_type = Memory.readU16(buf.add(2)); // nlmsg_type 偏移为 2
      const nlmsg_len = Memory.readU32(buf);      // nlmsg_len 偏移为 0
      console.log("  Netlink Message Type:", nlmsg_type);
      console.log("  Netlink Message Length:", nlmsg_len);

      // 如果是 Generic Netlink 消息，可以进一步解析其 payload
      // 需要知道 Generic Netlink 的头部结构和 NFC 消息的格式
    }
  });
} else {
  console.log("sendto function not found.");
}
```

**调试步骤：**

1. **找到关键函数：** 使用 `frida-ps -U` 找到目标进程，通常是 System Server 或相关的 NFC 进程。
2. **定位 Native 函数：**  分析 Android 源码或使用反编译工具（如 IDA Pro, Ghidra）找到 `libnfc_nci.so` 中负责发送 Netlink 消息的函数。这可能需要一些逆向工程的技巧。
3. **Hook Native 函数或系统调用：** 使用 Frida 的 `Interceptor.attach` API 来 hook 目标函数或 `sendto` 系统调用。
4. **解析数据：** 在 `onEnter` 回调中，读取函数参数或 `sendto` 的缓冲区内容，解析 Netlink 消息头和 payload，提取出 NFC 命令和属性。你需要了解 Netlink 消息的结构以及这个头文件中定义的常量。
5. **触发事件：** 在 Android 设备上执行触发 NFC 命令的操作，例如开启 NFC 开关。
6. **查看 Frida 输出：**  观察 Frida 控制台的输出，查看是否捕获到了目标命令，并分析其参数。

通过这些步骤，你可以深入了解 Android Framework 如何通过 Native 代码和内核接口与 NFC 驱动程序进行交互。这个头文件是理解这些交互的基础。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/nfc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_NFC_H
#define __LINUX_NFC_H
#include <linux/types.h>
#include <linux/socket.h>
#define NFC_GENL_NAME "nfc"
#define NFC_GENL_VERSION 1
#define NFC_GENL_MCAST_EVENT_NAME "events"
enum nfc_commands {
  NFC_CMD_UNSPEC,
  NFC_CMD_GET_DEVICE,
  NFC_CMD_DEV_UP,
  NFC_CMD_DEV_DOWN,
  NFC_CMD_DEP_LINK_UP,
  NFC_CMD_DEP_LINK_DOWN,
  NFC_CMD_START_POLL,
  NFC_CMD_STOP_POLL,
  NFC_CMD_GET_TARGET,
  NFC_EVENT_TARGETS_FOUND,
  NFC_EVENT_DEVICE_ADDED,
  NFC_EVENT_DEVICE_REMOVED,
  NFC_EVENT_TARGET_LOST,
  NFC_EVENT_TM_ACTIVATED,
  NFC_EVENT_TM_DEACTIVATED,
  NFC_CMD_LLC_GET_PARAMS,
  NFC_CMD_LLC_SET_PARAMS,
  NFC_CMD_ENABLE_SE,
  NFC_CMD_DISABLE_SE,
  NFC_CMD_LLC_SDREQ,
  NFC_EVENT_LLC_SDRES,
  NFC_CMD_FW_DOWNLOAD,
  NFC_EVENT_SE_ADDED,
  NFC_EVENT_SE_REMOVED,
  NFC_EVENT_SE_CONNECTIVITY,
  NFC_EVENT_SE_TRANSACTION,
  NFC_CMD_GET_SE,
  NFC_CMD_SE_IO,
  NFC_CMD_ACTIVATE_TARGET,
  NFC_CMD_VENDOR,
  NFC_CMD_DEACTIVATE_TARGET,
  __NFC_CMD_AFTER_LAST
};
#define NFC_CMD_MAX (__NFC_CMD_AFTER_LAST - 1)
enum nfc_attrs {
  NFC_ATTR_UNSPEC,
  NFC_ATTR_DEVICE_INDEX,
  NFC_ATTR_DEVICE_NAME,
  NFC_ATTR_PROTOCOLS,
  NFC_ATTR_TARGET_INDEX,
  NFC_ATTR_TARGET_SENS_RES,
  NFC_ATTR_TARGET_SEL_RES,
  NFC_ATTR_TARGET_NFCID1,
  NFC_ATTR_TARGET_SENSB_RES,
  NFC_ATTR_TARGET_SENSF_RES,
  NFC_ATTR_COMM_MODE,
  NFC_ATTR_RF_MODE,
  NFC_ATTR_DEVICE_POWERED,
  NFC_ATTR_IM_PROTOCOLS,
  NFC_ATTR_TM_PROTOCOLS,
  NFC_ATTR_LLC_PARAM_LTO,
  NFC_ATTR_LLC_PARAM_RW,
  NFC_ATTR_LLC_PARAM_MIUX,
  NFC_ATTR_SE,
  NFC_ATTR_LLC_SDP,
  NFC_ATTR_FIRMWARE_NAME,
  NFC_ATTR_SE_INDEX,
  NFC_ATTR_SE_TYPE,
  NFC_ATTR_SE_AID,
  NFC_ATTR_FIRMWARE_DOWNLOAD_STATUS,
  NFC_ATTR_SE_APDU,
  NFC_ATTR_TARGET_ISO15693_DSFID,
  NFC_ATTR_TARGET_ISO15693_UID,
  NFC_ATTR_SE_PARAMS,
  NFC_ATTR_VENDOR_ID,
  NFC_ATTR_VENDOR_SUBCMD,
  NFC_ATTR_VENDOR_DATA,
  __NFC_ATTR_AFTER_LAST
};
#define NFC_ATTR_MAX (__NFC_ATTR_AFTER_LAST - 1)
enum nfc_sdp_attr {
  NFC_SDP_ATTR_UNSPEC,
  NFC_SDP_ATTR_URI,
  NFC_SDP_ATTR_SAP,
  __NFC_SDP_ATTR_AFTER_LAST
};
#define NFC_SDP_ATTR_MAX (__NFC_SDP_ATTR_AFTER_LAST - 1)
#define NFC_DEVICE_NAME_MAXSIZE 8
#define NFC_NFCID1_MAXSIZE 10
#define NFC_NFCID2_MAXSIZE 8
#define NFC_NFCID3_MAXSIZE 10
#define NFC_SENSB_RES_MAXSIZE 12
#define NFC_SENSF_RES_MAXSIZE 18
#define NFC_ATR_REQ_MAXSIZE 64
#define NFC_ATR_RES_MAXSIZE 64
#define NFC_ATR_REQ_GB_MAXSIZE 48
#define NFC_ATR_RES_GB_MAXSIZE 47
#define NFC_GB_MAXSIZE 48
#define NFC_FIRMWARE_NAME_MAXSIZE 32
#define NFC_ISO15693_UID_MAXSIZE 8
#define NFC_PROTO_JEWEL 1
#define NFC_PROTO_MIFARE 2
#define NFC_PROTO_FELICA 3
#define NFC_PROTO_ISO14443 4
#define NFC_PROTO_NFC_DEP 5
#define NFC_PROTO_ISO14443_B 6
#define NFC_PROTO_ISO15693 7
#define NFC_PROTO_MAX 8
#define NFC_COMM_ACTIVE 0
#define NFC_COMM_PASSIVE 1
#define NFC_RF_INITIATOR 0
#define NFC_RF_TARGET 1
#define NFC_RF_NONE 2
#define NFC_PROTO_JEWEL_MASK (1 << NFC_PROTO_JEWEL)
#define NFC_PROTO_MIFARE_MASK (1 << NFC_PROTO_MIFARE)
#define NFC_PROTO_FELICA_MASK (1 << NFC_PROTO_FELICA)
#define NFC_PROTO_ISO14443_MASK (1 << NFC_PROTO_ISO14443)
#define NFC_PROTO_NFC_DEP_MASK (1 << NFC_PROTO_NFC_DEP)
#define NFC_PROTO_ISO14443_B_MASK (1 << NFC_PROTO_ISO14443_B)
#define NFC_PROTO_ISO15693_MASK (1 << NFC_PROTO_ISO15693)
#define NFC_SE_UICC 0x1
#define NFC_SE_EMBEDDED 0x2
#define NFC_SE_DISABLED 0x0
#define NFC_SE_ENABLED 0x1
struct sockaddr_nfc {
  __kernel_sa_family_t sa_family;
  __u32 dev_idx;
  __u32 target_idx;
  __u32 nfc_protocol;
};
#define NFC_LLCP_MAX_SERVICE_NAME 63
struct sockaddr_nfc_llcp {
  __kernel_sa_family_t sa_family;
  __u32 dev_idx;
  __u32 target_idx;
  __u32 nfc_protocol;
  __u8 dsap;
  __u8 ssap;
  char service_name[NFC_LLCP_MAX_SERVICE_NAME];
;
  __kernel_size_t service_name_len;
};
#define NFC_SOCKPROTO_RAW 0
#define NFC_SOCKPROTO_LLCP 1
#define NFC_SOCKPROTO_MAX 2
#define NFC_HEADER_SIZE 1
#define NFC_RAW_HEADER_SIZE 2
#define NFC_DIRECTION_RX 0x00
#define NFC_DIRECTION_TX 0x01
#define RAW_PAYLOAD_LLCP 0
#define RAW_PAYLOAD_NCI 1
#define RAW_PAYLOAD_HCI 2
#define RAW_PAYLOAD_DIGITAL 3
#define RAW_PAYLOAD_PROPRIETARY 4
#define NFC_LLCP_RW 0
#define NFC_LLCP_MIUX 1
#define NFC_LLCP_REMOTE_MIU 2
#define NFC_LLCP_REMOTE_LTO 3
#define NFC_LLCP_REMOTE_RW 4
#endif
```