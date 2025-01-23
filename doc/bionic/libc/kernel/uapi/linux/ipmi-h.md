Response:
Let's break down the thought process to generate the comprehensive answer about `ipmi.h`.

**1. Understanding the Request:**

The request asks for an analysis of the provided C header file (`ipmi.h`) within the context of Android's bionic library. Key points include:

* **Functionality:** What does this code *do*? What concepts does it define?
* **Android Relevance:** How does this relate to Android's operation?  Provide specific examples.
* **libc Function Explanation:**  Deep dive into the purpose and implementation of any libc functions used.
* **Dynamic Linker (if applicable):**  Explain linker interactions with sample SO layout and linking process.
* **Logic Inference:** Provide examples of input and output based on the defined structures.
* **Common Errors:**  Highlight potential pitfalls for users/programmers.
* **Framework/NDK Path:**  Trace how Android code reaches this header.
* **Frida Hooking:** Demonstrate debugging with Frida.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPI__LINUX_IPMI_H` and `#define _UAPI__LINUX_IPMI_H`:**  Include guards to prevent multiple inclusions.
* **`#include <linux/ipmi_msgdefs.h>` and `#include <linux/compiler.h>`:** Includes other kernel headers, suggesting this file is related to kernel-level interaction.
* **Structure Definitions:** The core of the file consists of `struct` definitions like `ipmi_addr`, `ipmi_msg`, `ipmi_req`, `ipmi_recv`, etc. These clearly represent data structures for interacting with the IPMI (Intelligent Platform Management Interface) system.
* **Constants and Macros:**  Definitions like `IPMI_MAX_ADDR_SIZE`, `IPMI_SYSTEM_INTERFACE_ADDR_TYPE`, `IPMI_IOC_MAGIC`, and various `IPMICTL_` macros are present. These define specific values and are likely used for system calls or ioctl operations.
* **`_IOR`, `_IOWR`, `_IOW` Macros:** These macros (from `<asm-generic/ioctl.h>`) are strong indicators of ioctl commands for interacting with a device driver.

**3. Determining the Core Functionality:**

Based on the structure names and constants, the central theme is clearly **IPMI**. IPMI is a standard for out-of-band management of computer systems. This header file provides the data structures and definitions necessary for software to communicate with an IPMI controller.

**4. Connecting to Android:**

The key is to understand *why* Android would need IPMI. Android runs on various hardware, including server-like systems. In such environments, IPMI is used for:

* **Remote Management:** Power control, system monitoring, sensor data retrieval.
* **Hardware Diagnostics:** Checking hardware health independently of the OS.

Therefore, while not used in typical consumer Android devices, IPMI functionality is relevant for Android running on server platforms or embedded systems that require remote management capabilities.

**5. Examining `libc` Functions:**

Looking through the header, there are **no direct calls to standard `libc` functions** like `malloc`, `memcpy`, `printf`, etc. This header primarily defines data structures and constants. The actual *implementation* of IPMI interaction (using these structures) would happen in other parts of the Android system (likely in kernel drivers or HALs), and *those* components would use `libc` functions.

**6. Dynamic Linker Aspects:**

Because this is a header file, it doesn't directly involve dynamic linking. The structures defined here would be used by code that *is* linked, but the header itself is a compile-time artifact. Therefore, a detailed SO layout and linking process for *this specific file* is not applicable. However, it's important to mention that the *code that uses these structures* would be part of shared libraries and would be subject to the dynamic linker's processes.

**7. Logic Inference (Example Use Case):**

To demonstrate how these structures are used, a plausible scenario is sending an IPMI command:

* **Input:**  Populate an `ipmi_req` structure with the target address, message details (netfn, cmd, data).
* **System Call:** Use `ioctl` with `IPMICTL_SEND_COMMAND` and the populated `ipmi_req` structure.
* **Output:** The kernel driver would process the request and potentially return status or response data.

**8. Common Errors:**

Consider common mistakes when working with low-level system interfaces:

* **Incorrect Structure Initialization:**  Forgetting to set required fields, especially address information.
* **Invalid `ioctl` Numbers:**  Using the wrong `IPMICTL_` constant.
* **Buffer Overflows:**  Not allocating enough memory for `data` in `ipmi_msg`.
* **Permissions Issues:**  The user might not have the necessary permissions to access the IPMI device.

**9. Android Framework/NDK Path:**

Trace the path from a high-level Android component to this header:

* **Android Framework (Java/Kotlin):**  A management application might use Android's system services.
* **System Services (C++):** These services interact with Hardware Abstraction Layers (HALs).
* **HALs (C/C++):**  The IPMI HAL would contain the core logic for IPMI communication, using the structures defined in `ipmi.h`.
* **Kernel Driver:** The HAL would ultimately make system calls (like `ioctl`) that interact with an IPMI kernel driver. The driver uses the definitions in this header file.
* **NDK:**  While less common, an NDK application could directly interact with the IPMI device driver using `ioctl` and these structures if it has the necessary permissions.

**10. Frida Hooking:**

Demonstrate how to intercept calls related to IPMI using Frida:

* **Hooking `ioctl`:**  Target calls to the `ioctl` system call.
* **Filtering by `ioctl` Number:** Check if the `ioctl` number matches the `IPMICTL_` constants defined in the header.
* **Examining Arguments:** Inspect the `ipmi_req` or `ipmi_recv` structures passed to `ioctl`.

**11. Structuring the Answer:**

Organize the information logically with clear headings and examples. Use code blocks for clarity. Maintain a conversational and informative tone.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on `libc` functions called within the header.
* **Correction:** Realize that this header primarily *defines* data structures, and the `libc` functions are used in the *implementation* (drivers, HALs) that *uses* these structures. Shift focus accordingly.
* **Initial thought:** Assume widespread use of IPMI in Android.
* **Correction:**  Recognize that IPMI is more specific to server/embedded contexts within the Android ecosystem. Clarify this distinction.
* **Initial thought:**  Provide a generic SO layout.
* **Correction:** Understand that this header file itself isn't an SO. Explain that the *code using* these structures would be in SOs.

By following these steps and incorporating self-correction, a comprehensive and accurate answer can be constructed.
这个C头文件 `ipmi.h` 定义了 Linux 内核中与 **IPMI (Intelligent Platform Management Interface)** 子系统交互的数据结构和常量。IPMI 是一种行业标准，允许系统管理员远程管理和监控计算机硬件，独立于主机操作系统、CPU 和 BIOS。

**功能列表:**

1. **定义 IPMI 地址结构体 (`ipmi_addr`)：** 用于表示 IPMI 消息的目标或来源地址，包含地址类型、通道和具体地址数据。
2. **定义不同类型的 IPMI 地址结构体：** 针对不同的 IPMI 通信方式定义了特定的地址结构，例如：
    * `ipmi_system_interface_addr`: 系统接口地址。
    * `ipmi_ipmb_addr`: IPMB (Intelligent Platform Management Bus) 地址。
    * `ipmi_ipmb_direct_addr`: IPMB 直接寻址。
    * `ipmi_lan_addr`: 基于 LAN 的地址。
3. **定义 IPMI 消息结构体 (`ipmi_msg`, `kernel_ipmi_msg`)：** 用于封装要发送或接收的 IPMI 命令和数据，包括网络功能号 (netfn)、命令码 (cmd)、数据长度 (data_len) 和数据指针 (data)。`kernel_ipmi_msg` 似乎是内核内部使用的消息结构。
4. **定义 IPMI 消息完成代码常量：**  例如 `IPMI_INVALID_CMD_COMPLETION_CODE`、`IPMI_TIMEOUT_COMPLETION_CODE` 等，表示 IPMI 命令执行的结果。
5. **定义 IPMI 接收类型常量：** 例如 `IPMI_RESPONSE_RECV_TYPE`、`IPMI_ASYNC_EVENT_RECV_TYPE` 等，标识接收到的 IPMI 消息类型。
6. **定义维护模式常量：** 例如 `IPMI_MAINTENANCE_MODE_AUTO`、`IPMI_MAINTENANCE_MODE_OFF`、`IPMI_MAINTENANCE_MODE_ON`，用于设置 IPMI 控制器的维护模式。
7. **定义 ioctl 命令和相关结构体：**  使用 `IPMI_IOC_MAGIC` 定义了一系列 ioctl 命令，用于用户空间程序与 IPMI 设备驱动程序进行交互，例如：
    * `IPMICTL_SEND_COMMAND`: 发送 IPMI 命令。
    * `IPMICTL_RECEIVE_MSG`: 接收 IPMI 消息。
    * `IPMICTL_REGISTER_FOR_CMD`: 注册接收特定 IPMI 命令的通知。
    * `IPMICTL_SET_MY_ADDRESS_CMD`: 设置本地 IPMI 地址。
    * `IPMICTL_GET_TIMING_PARMS_CMD`: 获取 IPMI 超时参数。

**与 Android 功能的关系及举例说明:**

虽然 IPMI 主要用于服务器和嵌入式系统管理，但在某些 Android 设备上，特别是那些作为服务器或具有远程管理需求的设备，可能会使用到 IPMI 功能。

**举例说明：**

* **远程电源管理:**  一个运行 Android 的服务器可以通过 IPMI 远程重启、关闭或打开电源。Android 系统中的某个管理服务可能会使用这里定义的结构体，通过 ioctl 系统调用与 IPMI 设备驱动程序通信，发送相应的 IPMI 命令来控制服务器的电源状态。
* **硬件监控:**  Android 系统可以利用 IPMI 获取硬件传感器的信息，例如温度、风扇转速、电压等。一个监控应用可以使用这些数据来了解硬件健康状况。

**详细解释 libc 函数的功能实现:**

**这个头文件本身并没有定义或实现任何 `libc` 函数。** 它主要定义了数据结构和常量，用于与内核中的 IPMI 驱动程序进行交互。  `libc` 函数会在用户空间程序中被使用，用来操作这些结构体或进行系统调用。

例如，在用户空间程序中，可能会使用 `malloc()` 分配内存来存储 `ipmi_req` 结构体，使用 `ioctl()` 系统调用与 IPMI 驱动程序通信。 `ioctl()` 本身是一个 `libc` 函数，其功能是向设备驱动程序发送控制命令。

**对于涉及 dynamic linker 的功能:**

**这个头文件本身不直接涉及 dynamic linker。**  它定义的数据结构会被编译到用户空间的应用程序或共享库中。当这些应用程序或共享库被加载时，dynamic linker 会参与链接过程。

**SO 布局样本 (假设一个使用了 IPMI 功能的共享库 `libipmi_client.so`)：**

```
libipmi_client.so:
  .text         # 包含代码段
    - 函数，例如发送 IPMI 命令的函数
  .rodata       # 包含只读数据
    - 可能包含一些 IPMI 相关的常量字符串
  .data         # 包含已初始化数据
    - 可能包含一些全局变量
  .bss          # 包含未初始化数据
  .dynsym       # 动态符号表
    - 包含导出的和导入的符号
  .dynstr       # 动态字符串表
  .rel.dyn      # 动态重定位表
  .rel.plt      # PLT 重定位表
  ... 其他段 ...
```

**链接的处理过程：**

1. **编译时：** 编译器会将使用了 `ipmi.h` 中定义的结构体的代码编译成目标文件 (`.o`)。这些目标文件中会包含对内核提供的 IPMI 功能的引用（通常通过 `ioctl` 系统调用）。
2. **链接时：** 链接器会将多个目标文件链接成共享库 (`.so`)。对于使用了系统调用的代码，链接器通常会生成一个间接调用，例如通过 PLT (Procedure Linkage Table)。
3. **运行时：** 当应用程序加载 `libipmi_client.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * **加载共享库到内存。**
    * **解析共享库的依赖关系。**
    * **重定位：**  Dynamic linker 会根据重定位表 `.rel.dyn` 和 `.rel.plt` 中的信息，修改代码和数据段中的地址，以确保函数调用和数据访问指向正确的内存位置。对于 `ioctl` 系统调用，PLT 中会有一个条目，指向内核的系统调用入口点。
    * **符号绑定：** Dynamic linker 会解析共享库中引用的外部符号。对于系统调用，这些符号通常由内核提供。

**假设输入与输出 (逻辑推理)：**

假设用户空间程序想要发送一个获取 BMC (Baseboard Management Controller) 状态的 IPMI 命令。

**假设输入：**

* `addr_type`: `IPMI_SYSTEM_INTERFACE_ADDR_TYPE` (0x0c)
* `channel`: `IPMI_BMC_CHANNEL` (0xf)
* `netfn`: 0x06 (Sensor Request)
* `cmd`: 0x01 (Get Device ID)
* `data_len`: 0
* `data`: NULL

**预期输出 (假设命令执行成功)：**

* `ioctl` 系统调用返回 0 表示成功。
* 如果程序接收响应，`IPMICTL_RECEIVE_MSG` 返回的 `ipmi_recv` 结构体中的 `msg` 成员会包含 BMC 的设备 ID 信息。

**涉及用户或者编程常见的使用错误：**

1. **地址结构体初始化错误：**  没有正确设置 `ipmi_addr` 结构体的 `addr_type` 和 `channel`，导致 IPMI 消息发送到错误的目标。
   ```c
   struct ipmi_req req;
   struct ipmi_system_interface_addr addr;
   addr.addr_type = 0; // 错误：应该设置为 IPMI_SYSTEM_INTERFACE_ADDR_TYPE
   addr.channel = IPMI_BMC_CHANNEL;
   req.addr = (unsigned char *)&addr;
   req.addr_len = sizeof(addr);
   // ... 其他初始化 ...
   ioctl(fd, IPMICTL_SEND_COMMAND, &req);
   ```
2. **`ioctl` 命令使用错误：** 使用了错误的 `ioctl` 命令常量，例如想要接收消息却使用了发送命令的常量。
3. **数据长度错误：** `ipmi_msg` 结构体中的 `data_len` 与实际 `data` 指向的数据长度不符，可能导致缓冲区溢出或数据截断。
4. **权限问题：** 用户空间程序可能没有足够的权限访问 IPMI 设备驱动程序，导致 `ioctl` 调用失败。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 IPMI 主要用于底层硬件管理，Android Framework 或 NDK 通常不会直接使用这些定义。然而，某些系统级服务或者硬件抽象层 (HAL) 可能会间接使用到它们。

**假设场景：** 一个 Android 系统服务需要获取硬件温度信息，而底层通过 IPMI 获取。

1. **Android Framework (Java/Kotlin):**  一个系统服务（例如 `HardwareService`）可能会提供一个 API 来获取温度信息。
2. **System Service (C++):** `HardwareService` 的 C++ 实现会调用更底层的接口。
3. **Hardware Abstraction Layer (HAL):** Android 定义了 HAL 来隔离硬件细节。可能会有一个特定的 HAL 模块负责传感器数据获取（例如 `android.hardware.sensors@X.Y::ISensors`）。该 HAL 的实现（通常是 C/C++ 代码）可能会使用 IPMI 与硬件通信。
4. **IPMI Client Library (C/C++):** HAL 可能会使用一个内部的 IPMI 客户端库，该库会包含使用 `ipmi.h` 中定义的结构体的代码。
5. **Kernel Driver:** IPMI 客户端库最终会通过 `ioctl` 系统调用与内核中的 IPMI 设备驱动程序通信。

**Frida Hook 示例：**

假设我们想 hook HAL 中发送 IPMI 命令的 `ioctl` 调用。我们需要找到 HAL 进程，并 hook `ioctl` 系统调用，并过滤与 IPMI 相关的调用。

```python
import frida
import sys

package_name = "com.android.system.hw"  # 假设 HAL 进程的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var buf = args[2];

        // 定义 IPMI 控制命令魔数
        const IPMI_IOC_MAGIC = 'i'.charCodeAt(0);

        // 检查是否是 IPMI 相关的 ioctl 命令
        if ((request >> 8) === IPMI_IOC_MAGIC) {
            console.log("发现 IPMI ioctl 调用:");
            console.log("  文件描述符 (fd): " + fd);
            console.log("  请求码 (request): 0x" + request.toString(16));

            // 根据不同的 ioctl 命令，解析参数结构体
            if (request === 0xc018690d) { // IPMICTL_SEND_COMMAND 的值 (需要根据实际情况调整)
                console.log("  命令: IPMICTL_SEND_COMMAND");
                var ipmi_req_ptr = ptr(buf);
                var addr_ptr = ipmi_req_ptr.readPointer();
                var addr_len = ipmi_req_ptr.add(Process.pointerSize).readU32();
                var msg_ptr = ipmi_req_ptr.add(Process.pointerSize * 2 + 8); // 假设 msg 结构体偏移

                console.log("  地址数据 (addr): " + hexdump(addr_ptr.readByteArray(addr_len)));
                var netfn = msg_ptr.readU8();
                var cmd = msg_ptr.add(1).readU8();
                var data_len = msg_ptr.add(2).readU16();
                var data_ptr = msg_ptr.add(4).readPointer();
                console.log("  IPMI 消息 (netfn: 0x" + netfn.toString(16) + ", cmd: 0x" + cmd.toString(16) + ", data_len: " + data_len + ")");
                if (data_len > 0) {
                    console.log("  数据 (data): " + hexdump(data_ptr.readByteArray(data_len)));
                }
            } else if (request === 0xc020690c) { // IPMICTL_RECEIVE_MSG 的值 (需要根据实际情况调整)
                console.log("  命令: IPMICTL_RECEIVE_MSG");
                // ... 解析接收到的消息结构体 ...
            }
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl 返回值: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 调试步骤：**

1. **找到目标进程：** 确定负责 IPMI 通信的 Android 进程的名称或包名。可以使用 `adb shell ps | grep ipmi` 或类似的命令查找。
2. **编写 Frida 脚本：** 使用 Frida 的 JavaScript API，hook `libc.so` 中的 `ioctl` 函数。
3. **过滤 IPMI 调用：** 在 `onEnter` 函数中，检查 `ioctl` 的第二个参数（请求码）。IPMI 相关的 `ioctl` 命令通常具有特定的模式，例如 `_IO` 或 `_IOWR` 宏生成的值，其中包含 `IPMI_IOC_MAGIC`。
4. **解析参数：** 根据 `ioctl` 命令的类型，解析第三个参数指向的结构体（例如 `ipmi_req` 或 `ipmi_recv`），并打印出关键信息，例如地址、消息内容等。
5. **运行 Frida 脚本：** 使用 `frida` 命令或 Python 脚本运行编写的 Frida 代码，连接到目标进程。
6. **触发 IPMI 操作：** 在 Android 设备上执行会导致 IPMI 通信的操作，例如读取传感器数据。
7. **观察输出：** Frida 会拦截相关的 `ioctl` 调用，并打印出脚本中定义的信息，帮助你理解 Android 系统如何与 IPMI 设备进行交互。

**请注意：**

* 上述 Frida 脚本只是一个示例，实际的 `ioctl` 命令值和结构体布局可能需要根据具体的 Android 版本和 HAL 实现进行调整。
* Hook 系统进程可能需要 root 权限。
* 理解 ARM 架构下的函数调用约定和结构体内存布局对于正确解析参数至关重要。

总而言之，`bionic/libc/kernel/uapi/linux/ipmi.h` 定义了与 Linux 内核 IPMI 子系统交互的基础数据结构，为用户空间程序（包括 Android 系统中的某些底层组件）提供了与硬件管理控制器通信的接口。虽然在典型的消费级 Android 设备中不常见，但在服务器或具有远程管理能力的 Android 系统中发挥着重要作用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/ipmi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_IPMI_H
#define _UAPI__LINUX_IPMI_H
#include <linux/ipmi_msgdefs.h>
#include <linux/compiler.h>
#define IPMI_MAX_ADDR_SIZE 32
struct ipmi_addr {
  int addr_type;
  short channel;
  char data[IPMI_MAX_ADDR_SIZE];
};
#define IPMI_SYSTEM_INTERFACE_ADDR_TYPE 0x0c
struct ipmi_system_interface_addr {
  int addr_type;
  short channel;
  unsigned char lun;
};
#define IPMI_IPMB_ADDR_TYPE 0x01
#define IPMI_IPMB_BROADCAST_ADDR_TYPE 0x41
struct ipmi_ipmb_addr {
  int addr_type;
  short channel;
  unsigned char slave_addr;
  unsigned char lun;
};
#define IPMI_IPMB_DIRECT_ADDR_TYPE 0x81
struct ipmi_ipmb_direct_addr {
  int addr_type;
  short channel;
  unsigned char slave_addr;
  unsigned char rs_lun;
  unsigned char rq_lun;
};
#define IPMI_LAN_ADDR_TYPE 0x04
struct ipmi_lan_addr {
  int addr_type;
  short channel;
  unsigned char privilege;
  unsigned char session_handle;
  unsigned char remote_SWID;
  unsigned char local_SWID;
  unsigned char lun;
};
#define IPMI_BMC_CHANNEL 0xf
#define IPMI_NUM_CHANNELS 0x10
#define IPMI_CHAN_ALL (~0)
struct ipmi_msg {
  unsigned char netfn;
  unsigned char cmd;
  unsigned short data_len;
  unsigned char  * data;
};
struct kernel_ipmi_msg {
  unsigned char netfn;
  unsigned char cmd;
  unsigned short data_len;
  unsigned char * data;
};
#define IPMI_INVALID_CMD_COMPLETION_CODE 0xC1
#define IPMI_TIMEOUT_COMPLETION_CODE 0xC3
#define IPMI_UNKNOWN_ERR_COMPLETION_CODE 0xff
#define IPMI_RESPONSE_RECV_TYPE 1
#define IPMI_ASYNC_EVENT_RECV_TYPE 2
#define IPMI_CMD_RECV_TYPE 3
#define IPMI_RESPONSE_RESPONSE_TYPE 4
#define IPMI_OEM_RECV_TYPE 5
#define IPMI_MAINTENANCE_MODE_AUTO 0
#define IPMI_MAINTENANCE_MODE_OFF 1
#define IPMI_MAINTENANCE_MODE_ON 2
#define IPMI_IOC_MAGIC 'i'
struct ipmi_req {
  unsigned char  * addr;
  unsigned int addr_len;
  long msgid;
  struct ipmi_msg msg;
};
#define IPMICTL_SEND_COMMAND _IOR(IPMI_IOC_MAGIC, 13, struct ipmi_req)
struct ipmi_req_settime {
  struct ipmi_req req;
  int retries;
  unsigned int retry_time_ms;
};
#define IPMICTL_SEND_COMMAND_SETTIME _IOR(IPMI_IOC_MAGIC, 21, struct ipmi_req_settime)
struct ipmi_recv {
  int recv_type;
  unsigned char  * addr;
  unsigned int addr_len;
  long msgid;
  struct ipmi_msg msg;
};
#define IPMICTL_RECEIVE_MSG _IOWR(IPMI_IOC_MAGIC, 12, struct ipmi_recv)
#define IPMICTL_RECEIVE_MSG_TRUNC _IOWR(IPMI_IOC_MAGIC, 11, struct ipmi_recv)
struct ipmi_cmdspec {
  unsigned char netfn;
  unsigned char cmd;
};
#define IPMICTL_REGISTER_FOR_CMD _IOR(IPMI_IOC_MAGIC, 14, struct ipmi_cmdspec)
#define IPMICTL_UNREGISTER_FOR_CMD _IOR(IPMI_IOC_MAGIC, 15, struct ipmi_cmdspec)
struct ipmi_cmdspec_chans {
  unsigned int netfn;
  unsigned int cmd;
  unsigned int chans;
};
#define IPMICTL_REGISTER_FOR_CMD_CHANS _IOR(IPMI_IOC_MAGIC, 28, struct ipmi_cmdspec_chans)
#define IPMICTL_UNREGISTER_FOR_CMD_CHANS _IOR(IPMI_IOC_MAGIC, 29, struct ipmi_cmdspec_chans)
#define IPMICTL_SET_GETS_EVENTS_CMD _IOR(IPMI_IOC_MAGIC, 16, int)
struct ipmi_channel_lun_address_set {
  unsigned short channel;
  unsigned char value;
};
#define IPMICTL_SET_MY_CHANNEL_ADDRESS_CMD _IOR(IPMI_IOC_MAGIC, 24, struct ipmi_channel_lun_address_set)
#define IPMICTL_GET_MY_CHANNEL_ADDRESS_CMD _IOR(IPMI_IOC_MAGIC, 25, struct ipmi_channel_lun_address_set)
#define IPMICTL_SET_MY_CHANNEL_LUN_CMD _IOR(IPMI_IOC_MAGIC, 26, struct ipmi_channel_lun_address_set)
#define IPMICTL_GET_MY_CHANNEL_LUN_CMD _IOR(IPMI_IOC_MAGIC, 27, struct ipmi_channel_lun_address_set)
#define IPMICTL_SET_MY_ADDRESS_CMD _IOR(IPMI_IOC_MAGIC, 17, unsigned int)
#define IPMICTL_GET_MY_ADDRESS_CMD _IOR(IPMI_IOC_MAGIC, 18, unsigned int)
#define IPMICTL_SET_MY_LUN_CMD _IOR(IPMI_IOC_MAGIC, 19, unsigned int)
#define IPMICTL_GET_MY_LUN_CMD _IOR(IPMI_IOC_MAGIC, 20, unsigned int)
struct ipmi_timing_parms {
  int retries;
  unsigned int retry_time_ms;
};
#define IPMICTL_SET_TIMING_PARMS_CMD _IOR(IPMI_IOC_MAGIC, 22, struct ipmi_timing_parms)
#define IPMICTL_GET_TIMING_PARMS_CMD _IOR(IPMI_IOC_MAGIC, 23, struct ipmi_timing_parms)
#define IPMICTL_GET_MAINTENANCE_MODE_CMD _IOR(IPMI_IOC_MAGIC, 30, int)
#define IPMICTL_SET_MAINTENANCE_MODE_CMD _IOW(IPMI_IOC_MAGIC, 31, int)
#endif
```