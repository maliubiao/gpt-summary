Response:
Let's break down the thought process for analyzing this C header file.

**1. Understanding the Context:**

The first and most crucial step is to understand *what* this file is and *where* it comes from. The prompt clearly states it's `bionic/libc/kernel/uapi/linux/ipmi_msgdefs.h`, part of Android's Bionic library. The "uapi" strongly suggests it's a user-space API header, providing definitions for interacting with the kernel. The "linux" part indicates it's targeting the Linux kernel's IPMI subsystem.

**2. Initial Scan and Identification of Key Elements:**

A quick scan reveals a series of `#define` statements. These define constants. My immediate thought is: "These are likely numeric codes and flags used for communicating with the IPMI driver."

I see prefixes like `IPMI_NETFN_`, `IPMI_GET_`, `IPMI_COLD_RESET_CMD`, `IPMI_CC_`, `IPMI_CHANNEL_PROTOCOL_`, etc. These prefixes provide important clues about the *categories* of definitions:

* `IPMI_NETFN_`: Likely Network Function codes for different IPMI operations.
* `IPMI_GET_`:  Commands to retrieve information.
* `IPMI_..._CMD`: Specific commands to be sent.
* `IPMI_CC_`:  Completion Codes indicating success or failure.
* `IPMI_CHANNEL_PROTOCOL_`, `IPMI_CHANNEL_MEDIUM_`:  Constants related to communication channels.

**3. Grouping and Categorization (Mental or Explicit):**

I mentally group the definitions based on their prefixes and semantic meaning. This helps in understanding the overall structure and purpose of the file. I might even make a mental list or notes like:

* **Request/Response Types:**  `IPMI_NETFN_SENSOR_EVENT_REQUEST`, `IPMI_NETFN_SENSOR_EVENT_RESPONSE`, etc.
* **Commands:** `IPMI_GET_DEVICE_ID_CMD`, `IPMI_COLD_RESET_CMD`, etc.
* **Error Codes:** `IPMI_CC_NO_ERROR`, `IPMI_NODE_BUSY_ERR`, etc.
* **Channel Information:** `IPMI_CHANNEL_PROTOCOL_*`, `IPMI_CHANNEL_MEDIUM_*`.
* **Interrupt Flags:** `IPMI_BMC_RCV_MSG_INTR`, `IPMI_BMC_EVT_MSG_INTR`, etc.
* **Other Constants:** `IPMI_MAX_MSG_LENGTH`, `IPMI_BMC_SLAVE_ADDR`.

**4. Inferring Functionality:**

Based on the identified categories, I can start inferring the overall functionality of the IPMI subsystem. It clearly involves:

* **Sending commands:**  Requests and responses.
* **Getting information:** Device ID, GUID, channel info, message flags.
* **Managing the system:** Resets, enabling/disabling features.
* **Handling events:** Sensor events, message reception.
* **Error reporting:**  Completion codes.
* **Communication protocols and media:** Different ways to connect to the IPMI controller.

**5. Connecting to Android:**

The next step is to relate this to Android. Since it's in Bionic, it's definitely used by Android at some level. The question is *how*?

* **Low-level hardware interaction:** IPMI is typically used for out-of-band management. This suggests Android might use it for hardware monitoring, remote management, or system recovery scenarios. Think of servers or embedded devices running Android.
* **Potential Android System Services:**  There might be system services in Android that interact with the IPMI driver to provide system health information or allow remote control.
* **NDK Usage (Less likely for direct IPMI interaction):** While the NDK allows access to native APIs, direct IPMI interaction is less common in typical Android apps. It's more of a system-level concern.

**6. Explaining `libc` Functions (Important Detail - Misinterpretation):**

The prompt asks for details on `libc` function implementations. *This is a key point of potential misunderstanding.*  This header file *defines constants*, not `libc` functions. It's crucial to recognize this distinction. Therefore, the correct answer is to state that it doesn't contain `libc` function definitions.

**7. Dynamic Linker and SO Layout (Again, Misinterpretation):**

Similar to the `libc` functions, this header file doesn't directly involve the dynamic linker. It defines constants used by code that *might* be linked dynamically, but the header itself isn't a linked library. The correct response is to explain that it's not a shared object and doesn't have a typical SO layout.

**8. Logic and Assumptions:**

While there isn't explicit logic in the header file itself, the design implies certain assumptions:

* **Standard IPMI protocol:** The constants adhere to the IPMI specification.
* **Kernel driver availability:** The presence of the header implies a corresponding IPMI driver in the Linux kernel.
* **User-space applications needing IPMI access:** Android components need a way to interact with the IPMI controller.

**9. Common Errors:**

Thinking about how a developer might use these definitions, I can identify potential errors:

* **Incorrect constant usage:** Using the wrong command code or network function.
* **Invalid parameter values:**  Passing incorrect values when sending IPMI messages.
* **Ignoring error codes:** Not checking the `IPMI_CC_*` values for errors.
* **Incorrect message formatting:**  Constructing IPMI messages with the wrong structure.

**10. Android Framework/NDK and Frida Hooking:**

This requires tracing how Android components might actually use IPMI.

* **Identifying potential entry points:** Look for system services or native daemons that might interact with IPMI. This often involves searching the Android source code.
* **System calls:**  IPMI interaction typically involves `ioctl()` system calls to communicate with the kernel driver.
* **Frida Hooking Strategy:**  Hooking the `ioctl()` system call with appropriate filtering (checking the `fd` and `request` parameters) would be the way to intercept IPMI communication. Hooking higher-level functions in system services that call `ioctl()` is also possible.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This file defines functions for interacting with IPMI."
* **Correction:** "No, it defines *constants* used for interacting with IPMI. The actual interaction happens through system calls or libraries."

* **Initial thought:** "Need to explain how `memcpy` or other `libc` functions are implemented within this file."
* **Correction:** "This file doesn't implement `libc` functions. It's a header file."

By following this structured thought process, focusing on understanding the context, identifying key elements, inferring functionality, and critically evaluating the prompt's questions, I can arrive at a comprehensive and accurate answer. The key is to avoid making assumptions and to differentiate between definitions and implementations.
这个文件 `bionic/libc/kernel/uapi/linux/ipmi_msgdefs.h` 是 Android Bionic 库的一部分，它定义了 Linux 内核中 IPMI（Intelligent Platform Management Interface，智能平台管理接口）子系统的消息定义。 它的主要功能是为用户空间程序提供与 IPMI 驱动程序交互时需要使用的常量定义。

**功能列表:**

1. **定义 IPMI 网络功能代码 (Network Function Codes):** 例如 `IPMI_NETFN_SENSOR_EVENT_REQUEST` 和 `IPMI_NETFN_SENSOR_EVENT_RESPONSE`，这些代码标识了 IPMI 消息所属的功能组，如传感器事件、应用命令、存储操作、固件操作等。
2. **定义 IPMI 命令代码 (Command Codes):**  例如 `IPMI_GET_DEVICE_ID_CMD`、`IPMI_COLD_RESET_CMD`、`IPMI_SEND_MSG_CMD` 等，这些代码指定了要执行的具体 IPMI 操作，如获取设备 ID、执行冷启动、发送消息等。
3. **定义 IPMI 事件接收器命令代码:** 例如 `IPMI_GET_EVENT_RECEIVER_CMD`。
4. **定义 IPMI 消息标志相关的命令代码:** 例如 `IPMI_CLEAR_MSG_FLAGS_CMD` 和 `IPMI_GET_MSG_FLAGS_CMD`。
5. **定义 BMC (Baseboard Management Controller，基板管理控制器) 全局使能相关的命令代码:** 例如 `IPMI_SET_BMC_GLOBAL_ENABLES_CMD` 和 `IPMI_GET_BMC_GLOBAL_ENABLES_CMD`。
6. **定义读取事件消息缓冲区的命令代码:** 例如 `IPMI_READ_EVENT_MSG_BUFFER_CMD`。
7. **定义获取通道信息的命令代码:** 例如 `IPMI_GET_CHANNEL_INFO_CMD`。
8. **定义 BMC 接收消息和事件消息中断的标志位:** 例如 `IPMI_BMC_RCV_MSG_INTR` 和 `IPMI_BMC_EVT_MSG_INTR`。
9. **定义存储操作相关的命令代码:** 例如 `IPMI_ADD_SEL_ENTRY_CMD` (SEL 指 System Event Log，系统事件日志)。
10. **定义 BMC 从机地址:** 例如 `IPMI_BMC_SLAVE_ADDR`。
11. **定义 IPMI 消息的最大长度:** 例如 `IPMI_MAX_MSG_LENGTH`。
12. **定义 IPMI 完成代码 (Completion Codes):** 例如 `IPMI_CC_NO_ERROR`、`IPMI_NODE_BUSY_ERR`、`IPMI_TIMEOUT_ERR` 等，用于表示 IPMI 操作的成功或失败以及失败的原因。
13. **定义 IPMI 通道协议类型:** 例如 `IPMI_CHANNEL_PROTOCOL_IPMB`、`IPMI_CHANNEL_PROTOCOL_SMBUS` 等，表示不同的物理通信协议。
14. **定义 IPMI 通道介质类型:** 例如 `IPMI_CHANNEL_MEDIUM_IPMB`、`IPMI_CHANNEL_MEDIUM_8023LAN` 等，表示不同的物理连接介质。

**与 Android 功能的关系及举例说明:**

IPMI 主要用于服务器和嵌入式系统的带外管理 (out-of-band management)。这意味着即使操作系统没有运行，或者系统处于关机状态，也可以通过 IPMI 对硬件进行监控和管理。在 Android 的上下文中，它通常用于一些特定的场景，例如：

* **服务器或数据中心设备:**  运行 Android 的服务器或数据中心设备可能使用 IPMI 进行远程监控、电源管理、硬件诊断等。例如，一个运行 Android 的服务器可以使用 IPMI 来监控其温度、风扇转速、电源状态，甚至可以远程重启服务器。
* **嵌入式系统:**  某些工业级或企业级 Android 嵌入式设备可能集成了 IPMI 功能，以便进行远程管理和维护。
* **硬件抽象层 (HAL):** Android 的硬件抽象层可能包含与 IPMI 驱动程序交互的模块，以便将底层的硬件管理功能暴露给上层应用或系统服务。

**举例说明:**

假设一个运行 Android 的服务器需要监控其 CPU 温度。

1. **Android 系统服务或 HAL 模块**可能会使用 `IPMI_NETFN_SENSOR_EVENT_REQUEST` 和相关的命令（可能需要查询传感器类型和值）来向 BMC 发送请求。
2. BMC 会响应 `IPMI_NETFN_SENSOR_EVENT_RESPONSE`，其中包含 CPU 温度信息以及可能的完成代码（例如 `IPMI_CC_NO_ERROR` 表示成功）。
3. 如果 BMC 没有响应或返回错误，则完成代码可能是 `IPMI_TIMEOUT_ERR` 或其他错误代码。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个头文件 `ipmi_msgdefs.h` 本身并不包含任何 `libc` 函数的实现。** 它只是定义了一些宏常量。`libc` (Bionic 在 Android 中的实现) 是一个 C 标准库的实现，提供了各种函数，例如内存管理 (`malloc`, `free`)、字符串操作 (`strcpy`, `strlen`)、输入输出 (`printf`, `scanf`) 等。

要使用这里定义的 IPMI 常量，应用程序或系统服务需要使用系统调用（例如 `ioctl`）与 Linux 内核中的 IPMI 驱动程序进行交互。`libc` 提供了 `ioctl` 函数的封装，但 `ioctl` 的具体实现位于内核中。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件 `ipmi_msgdefs.h` 本身不直接涉及 dynamic linker (动态链接器)。** 动态链接器负责在程序启动时将共享库（.so 文件）加载到内存中，并解析符号引用。

包含此头文件的代码（例如 Android 系统服务或 HAL 模块）可能会被编译成可执行文件或共享库。如果这些代码依赖于其他共享库，那么动态链接器会参与链接过程。

**SO 布局样本 (假设一个使用 IPMI 的共享库 `libipmiclient.so`):**

```
libipmiclient.so:
    .text          # 代码段
        function_a:
            ... // 使用了 IPMI_GET_DEVICE_ID_CMD 等常量
            call    ioctl  // 调用了 libc 的 ioctl 函数
            ...
        function_b:
            ...
    .rodata        # 只读数据段
        ipmi_version_string: .string "IPMI Client v1.0"
    .data          # 可读写数据段
        global_variable: ...
    .bss           # 未初始化数据段
        ...
    .dynamic       # 动态链接信息
        NEEDED      libc.so
        SONAME      libipmiclient.so
        ...
    .symtab        # 符号表
        ...
    .strtab        # 字符串表
        ...
```

**链接的处理过程:**

1. **编译时:** 编译器会将 `libipmiclient.c` (假设) 编译成目标文件 `libipmiclient.o`。在这个阶段，对 `IPMI_GET_DEVICE_ID_CMD` 等常量的引用会被直接替换为它们的值。对 `ioctl` 函数的调用会生成一个对外部符号 `ioctl` 的引用。
2. **链接时:** 链接器会将 `libipmiclient.o` 与 `libc.so` 等依赖的共享库链接起来。
3. **动态链接时 (程序启动时):**
    * Android 的 `linker` (动态链接器) 会加载 `libipmiclient.so` 和 `libc.so` 到内存中。
    * `linker` 会解析 `libipmiclient.so` 中对 `ioctl` 函数的引用，并将其指向 `libc.so` 中 `ioctl` 函数的实际地址。
    * `linker` 会处理其他的重定位和符号绑定。

**如果做了逻辑推理，请给出假设输入与输出:**

这个头文件本身不包含逻辑，它只是数据定义。逻辑推理发生在使用了这些定义的代码中。

**假设输入与输出的例子 (基于使用了这些常量的代码):**

**场景:** 一个 Android 服务尝试获取 IPMI 设备的 ID。

**假设输入:**

*  服务代码使用 `IPMI_GET_DEVICE_ID_CMD` 常量构造一个 IPMI 消息。
*  通过 `ioctl` 系统调用将该消息发送到 IPMI 驱动程序。

**假设输出 (成功情况):**

* IPMI 驱动程序收到消息，并与 BMC 通信。
* BMC 返回设备 ID 信息。
* IPMI 驱动程序将设备 ID 信息封装在 IPMI 响应消息中。
* `ioctl` 系统调用返回成功。
* 服务代码解析响应消息，提取设备 ID。

**假设输出 (失败情况):**

*  BMC 没有响应，或返回错误。
*  IPMI 驱动程序返回一个包含错误完成代码（例如 `IPMI_TIMEOUT_ERR`) 的响应消息。
*  `ioctl` 系统调用可能返回一个错误码。
*  服务代码检查完成代码，并处理错误情况。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用了错误的命令代码或网络功能代码:**  例如，错误地使用了获取传感器事件的请求代码去尝试获取设备 ID。这会导致 BMC 返回错误，或者根本无法理解请求。
2. **构造 IPMI 消息时使用了错误的长度或格式:** IPMI 消息有特定的结构。如果开发者没有正确地构造消息，BMC 可能无法解析，或者会返回格式错误的响应。
3. **没有正确处理 IPMI 完成代码:**  即使 `ioctl` 调用成功返回，IPMI 操作本身可能已经失败。开发者需要检查 IPMI 响应中的完成代码（例如 `IPMI_CC_NO_ERROR`），以确保操作成功。
4. **假设特定的硬件行为:**  不同的 BMC 实现可能略有不同。依赖于特定 BMC 的行为而不是遵循 IPMI 标准可能会导致代码在不同的硬件上出现问题。
5. **权限问题:**  与 IPMI 驱动程序交互通常需要 root 权限或特定的设备权限。普通应用可能无法直接访问 IPMI。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常情况下，Android Framework 或 NDK 应用不会直接使用这些底层的 IPMI 定义。IPMI 通常被系统服务或 HAL 模块使用，这些模块运行在更高的权限级别。

**步骤示例 (假设一个系统服务使用 IPMI):**

1. **Android Framework (例如，一个 System Server 组件):**  Framework 可能会调用一个系统服务的方法，该服务负责监控硬件状态。
2. **System Service (Java 层):** 该系统服务可能通过 JNI 调用本地代码。
3. **HAL (Hardware Abstraction Layer, C/C++ 代码):**  本地代码可能位于一个 HAL 模块中，该模块负责与硬件交互。
4. **IPMI Client Library (C/C++ 代码):**  HAL 模块可能会使用一个 IPMI 客户端库，该库封装了与 IPMI 驱动程序交互的细节。
5. **System Calls (ioctl):** IPMI 客户端库最终会使用 `ioctl` 系统调用，并传递包含 IPMI 命令和数据的结构体。这些结构体中会使用 `ipmi_msgdefs.h` 中定义的常量。
6. **Linux Kernel (IPMI Driver):**  内核中的 IPMI 驱动程序接收 `ioctl` 调用，并与 BMC 进行通信。

**Frida Hook 示例:**

假设我们想 hook 一个名为 `com.android.server.IpmiService` 的系统服务中与 IPMI 交互的关键点，并且这个服务调用了一个本地方法 `sendIpmiCommand`，该方法最终会调用 `ioctl`。

```python
import frida
import sys

package_name = "android" # 系统服务通常在 android 进程中运行

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保系统服务正在运行。")
    sys.exit()

script_code = """
// 假设 sendIpmiCommand 是 JNI 方法
Java.perform(function() {
    var IpmiService = Java.use("com.android.server.IpmiService"); // 替换为实际的类名

    if (IpmiService) {
        IpmiService.sendIpmiCommand.implementation = function(command, netfn, lun, data) {
            console.log("[Frida] sendIpmiCommand called:");
            console.log("[Frida]   Command: " + command);
            console.log("[Frida]   NetFn: " + netfn);
            console.log("[Frida]   Lun: " + lun);
            console.log("[Frida]   Data: " + data);

            // 调用原始方法
            var result = this.sendIpmiCommand(command, netfn, lun, data);
            console.log("[Frida] sendIpmiCommand result: " + result);
            return result;
        };
        console.log("[Frida] Hooked com.android.server.IpmiService.sendIpmiCommand");
    } else {
        console.log("[Frida] Class com.android.server.IpmiService not found");
    }

    // Hook ioctl 系统调用 (更底层)
    var libc = Process.getModuleByName("libc.so");
    var ioctlPtr = libc.getExportByName("ioctl");
    if (ioctlPtr) {
        Interceptor.attach(ioctlPtr, {
            onEnter: function(args) {
                var fd = args[0].toInt32();
                var request = args[1].toInt32();
                console.log("[Frida] ioctl called:");
                console.log("[Frida]   fd: " + fd);
                console.log("[Frida]   request: 0x" + request.toString(16));
                // 尝试解码 request (需要知道可能的 ioctl 命令值)
                if (request === 0xdeadbeef) { // 替换为实际的 IPMI ioctl 命令
                    console.log("[Frida]   Potentially an IPMI ioctl command");
                }
            },
            onLeave: function(retval) {
                console.log("[Frida] ioctl returned: " + retval);
            }
        });
        console.log("[Frida] Hooked ioctl");
    } else {
        console.log("[Frida] Symbol ioctl not found in libc.so");
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

1. **Attach 到目标进程:**  代码首先尝试 attach 到 `android` 进程，因为系统服务通常运行在这个进程中。
2. **Hook Java 方法 (sendIpmiCommand):** 使用 `Java.perform` 钩取 `com.android.server.IpmiService` 类的 `sendIpmiCommand` 方法。当该方法被调用时，Frida 会打印出其参数。
3. **Hook ioctl 系统调用:** 获取 `libc.so` 模块，找到 `ioctl` 函数的地址，并使用 `Interceptor.attach` 钩取它。当 `ioctl` 被调用时，Frida 会打印出文件描述符 (`fd`) 和请求码 (`request`)。你需要知道 IPMI 驱动程序可能使用的 `ioctl` 请求码来更精确地识别 IPMI 相关的 `ioctl` 调用。

**注意:**

*  实际的类名和方法名可能需要根据具体的 Android 版本和实现进行调整。
*  IPMI 交互可能发生在更底层的 HAL 代码中，而不是直接在 Java 系统服务中。你需要根据具体情况找到相关的本地代码入口点。
*  Hook `ioctl` 可以捕获所有 `ioctl` 调用，因此需要通过检查 `fd` 或 `request` 参数来过滤出与 IPMI 相关的调用。这需要对 IPMI 驱动程序使用的 `ioctl` 命令有所了解。

通过以上步骤，你可以使用 Frida 动态地观察 Android 系统如何一步步地使用 IPMI 相关的常量和系统调用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/ipmi_msgdefs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __LINUX_IPMI_MSGDEFS_H
#define __LINUX_IPMI_MSGDEFS_H
#define IPMI_NETFN_SENSOR_EVENT_REQUEST 0x04
#define IPMI_NETFN_SENSOR_EVENT_RESPONSE 0x05
#define IPMI_GET_EVENT_RECEIVER_CMD 0x01
#define IPMI_NETFN_APP_REQUEST 0x06
#define IPMI_NETFN_APP_RESPONSE 0x07
#define IPMI_GET_DEVICE_ID_CMD 0x01
#define IPMI_COLD_RESET_CMD 0x02
#define IPMI_WARM_RESET_CMD 0x03
#define IPMI_CLEAR_MSG_FLAGS_CMD 0x30
#define IPMI_GET_DEVICE_GUID_CMD 0x08
#define IPMI_GET_MSG_FLAGS_CMD 0x31
#define IPMI_SEND_MSG_CMD 0x34
#define IPMI_GET_MSG_CMD 0x33
#define IPMI_SET_BMC_GLOBAL_ENABLES_CMD 0x2e
#define IPMI_GET_BMC_GLOBAL_ENABLES_CMD 0x2f
#define IPMI_READ_EVENT_MSG_BUFFER_CMD 0x35
#define IPMI_GET_CHANNEL_INFO_CMD 0x42
#define IPMI_BMC_RCV_MSG_INTR 0x01
#define IPMI_BMC_EVT_MSG_INTR 0x02
#define IPMI_BMC_EVT_MSG_BUFF 0x04
#define IPMI_BMC_SYS_LOG 0x08
#define IPMI_NETFN_STORAGE_REQUEST 0x0a
#define IPMI_NETFN_STORAGE_RESPONSE 0x0b
#define IPMI_ADD_SEL_ENTRY_CMD 0x44
#define IPMI_NETFN_FIRMWARE_REQUEST 0x08
#define IPMI_NETFN_FIRMWARE_RESPONSE 0x09
#define IPMI_BMC_SLAVE_ADDR 0x20
#define IPMI_MAX_MSG_LENGTH 272
#define IPMI_CC_NO_ERROR 0x00
#define IPMI_NODE_BUSY_ERR 0xc0
#define IPMI_INVALID_COMMAND_ERR 0xc1
#define IPMI_TIMEOUT_ERR 0xc3
#define IPMI_ERR_MSG_TRUNCATED 0xc6
#define IPMI_REQ_LEN_INVALID_ERR 0xc7
#define IPMI_REQ_LEN_EXCEEDED_ERR 0xc8
#define IPMI_DEVICE_IN_FW_UPDATE_ERR 0xd1
#define IPMI_DEVICE_IN_INIT_ERR 0xd2
#define IPMI_NOT_IN_MY_STATE_ERR 0xd5
#define IPMI_LOST_ARBITRATION_ERR 0x81
#define IPMI_BUS_ERR 0x82
#define IPMI_NAK_ON_WRITE_ERR 0x83
#define IPMI_ERR_UNSPECIFIED 0xff
#define IPMI_CHANNEL_PROTOCOL_IPMB 1
#define IPMI_CHANNEL_PROTOCOL_ICMB 2
#define IPMI_CHANNEL_PROTOCOL_SMBUS 4
#define IPMI_CHANNEL_PROTOCOL_KCS 5
#define IPMI_CHANNEL_PROTOCOL_SMIC 6
#define IPMI_CHANNEL_PROTOCOL_BT10 7
#define IPMI_CHANNEL_PROTOCOL_BT15 8
#define IPMI_CHANNEL_PROTOCOL_TMODE 9
#define IPMI_CHANNEL_MEDIUM_IPMB 1
#define IPMI_CHANNEL_MEDIUM_ICMB10 2
#define IPMI_CHANNEL_MEDIUM_ICMB09 3
#define IPMI_CHANNEL_MEDIUM_8023LAN 4
#define IPMI_CHANNEL_MEDIUM_ASYNC 5
#define IPMI_CHANNEL_MEDIUM_OTHER_LAN 6
#define IPMI_CHANNEL_MEDIUM_PCI_SMBUS 7
#define IPMI_CHANNEL_MEDIUM_SMBUS1 8
#define IPMI_CHANNEL_MEDIUM_SMBUS2 9
#define IPMI_CHANNEL_MEDIUM_USB1 10
#define IPMI_CHANNEL_MEDIUM_USB2 11
#define IPMI_CHANNEL_MEDIUM_SYSINTF 12
#define IPMI_CHANNEL_MEDIUM_OEM_MIN 0x60
#define IPMI_CHANNEL_MEDIUM_OEM_MAX 0x7f
#endif
```