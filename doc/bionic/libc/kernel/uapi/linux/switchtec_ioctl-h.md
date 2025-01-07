Response:
Let's break down the thought process for analyzing this header file.

1. **Identify the Core Purpose:** The filename `switchtec_ioctl.h` and the comments at the beginning immediately point to this being a header file defining ioctl commands for interacting with a "switchtec" device driver in the Linux kernel. The location in the Android bionic tree confirms this is used within Android.

2. **Recognize the Role of `ioctl`:** Ioctl (Input/Output Control) is a system call mechanism in Unix-like systems for device-specific operations beyond the standard read/write/open/close. This file defines the *commands* and *data structures* used with the `ioctl` system call for the Switchtec driver.

3. **Categorize the Definitions:** Scan through the file and group related definitions. I see several distinct categories:
    * **Partition Definitions:** `SWITCHTEC_IOCTL_PART_*` constants and related structures (`switchtec_ioctl_flash_info`, `switchtec_ioctl_flash_part_info`).
    * **Event Definitions:** `SWITCHTEC_IOCTL_EVENT_*` constants and related structures (`switchtec_ioctl_event_summary`, `switchtec_ioctl_event_ctl`).
    * **PFF (Probably Port Fabric Forwarding) Definitions:** `SWITCHTEC_IOCTL_PFF_*` constants and the `switchtec_ioctl_pff_port` structure.
    * **Generic Constants:** `SWITCHTEC_NUM_PARTITIONS_*`.
    * **IOCTL Command Definitions:** `SWITCHTEC_IOCTL_*` macros using `_IOR` and `_IOWR`.

4. **Analyze Each Category in Detail:**

    * **Partitions:** The `SWITCHTEC_IOCTL_PART_*` constants clearly define different partitions of the Switchtec device's flash memory. The `_flash_info` structure provides overall flash size and partition count. The `_flash_part_info` structure gives details about a specific partition (address, length, active status). The `SWITCHTEC_NUM_PARTITIONS_*` constants hint at different generations of the Switchtec hardware.

    * **Events:** The `SWITCHTEC_IOCTL_EVENT_*` constants define various event types the Switchtec device can report (errors, resets, hotplug, etc.). The `_event_summary` structures (legacy and current) provide a summary of these events. The `_event_ctl` structure allows controlling event reporting (enabling/disabling, clearing flags, etc.). The flags like `_EN_POLL`, `_EN_LOG`, `_EN_CLI`, `_EN_FATAL` suggest different ways these events might be handled (polling, logging, command-line interface, fatal error handling).

    * **PFF:** The `SWITCHTEC_IOCTL_PFF_*` constants and the `_pff_port` structure suggest a way to map a PFF identifier to a physical port and partition. This likely relates to how the switch fabric routes traffic.

    * **IOCTL Commands:**  These macros use the standard `ioctl` encoding scheme (`_IOR` for read, `_IOWR` for read/write). They link the defined structures and operation codes (0x40, 0x41, etc.) to specific ioctl commands. The 'W' likely refers to the "magic number" for this driver family.

5. **Connect to Android:** Think about how such a low-level hardware component might be used in Android. Since it's a "switch," it likely deals with some form of high-speed interconnect, potentially PCIe. Android devices might use such switches for connecting peripherals, accelerators, or other internal components. The existence of this header within the bionic library means that user-space Android code (likely via NDK) can interact with this hardware.

6. **Consider Implementation and Usage:**  Imagine how a C/C++ program would use these definitions. It would need to open the device file (e.g., `/dev/switchtec`), populate the appropriate structures based on the desired operation, and then call the `ioctl` system call with the correct command and structure pointer.

7. **Think about Errors:** What could go wrong? Invalid partition numbers, trying to access non-existent events, incorrect flags, passing incorrect structure sizes, insufficient permissions to access the device.

8. **Address Specific Requirements:**  Go back to the prompt and make sure to address each point:
    * **Functionality:** List the capabilities derived from the analysis above.
    * **Android Relevance:** Provide examples of how this relates to Android (hardware connectivity, NDK interaction).
    * **`libc` Functions:** Explain that *this header file doesn't define `libc` functions*. It defines *constants and structures* used with the `ioctl` system call, which *is* a `libc` function. Focus on how `ioctl` works.
    * **Dynamic Linker:**  This header *doesn't directly involve the dynamic linker*. Explain this and why.
    * **Logical Reasoning/Assumptions:** Explicitly state the assumptions made (e.g., Switchtec is a PCIe switch).
    * **Common Errors:** Provide concrete examples of usage errors.
    * **Android Framework/NDK Path:** Describe how an app might indirectly use this via the NDK and a hardware abstraction layer (HAL).
    * **Frida Hook:** Give an example of how to hook the `ioctl` call to observe the interactions.

9. **Structure the Output:** Organize the information logically with clear headings and explanations for each point in the prompt. Use clear and concise language.

10. **Review and Refine:** Read through the generated response to ensure accuracy, clarity, and completeness. Correct any errors or omissions. For example, initially, I might have incorrectly assumed this file *contained* the Switchtec driver. Re-reading the prompt and the file clarifies it defines the *interface* to the driver. Also, I initially might have focused too much on the details of the Switchtec hardware. It's important to keep the focus on the *interface* defined by the header file.
这个头文件 `switchtec_ioctl.h` 定义了用于与 Linux 内核中的 Switchtec 设备驱动程序进行交互的 ioctl 命令和相关数据结构。Switchtec 通常指 Microchip (前身是 Microsemi) 生产的 PCIe 开关芯片。

**功能列举:**

这个头文件主要定义了以下功能：

1. **Flash 分区管理:**
   - 定义了各种 Flash 分区的标识符，例如 `SWITCHTEC_IOCTL_PART_CFG0`, `SWITCHTEC_IOCTL_PART_IMG0` 等。这些分区通常用于存储配置数据、固件镜像、日志等。
   - 定义了获取 Flash 信息的 ioctl 命令 (`SWITCHTEC_IOCTL_FLASH_INFO`) 和对应的数据结构 `switchtec_ioctl_flash_info`，用于查询 Flash 的总长度和分区数量。
   - 定义了获取和设置特定 Flash 分区信息的 ioctl 命令 (`SWITCHTEC_IOCTL_FLASH_PART_INFO`) 和对应的数据结构 `switchtec_ioctl_flash_part_info`，用于查询或设置分区的地址、长度和激活状态。

2. **事件管理:**
   - 定义了各种 Switchtec 设备可能产生的事件类型，例如 `SWITCHTEC_IOCTL_EVENT_STACK_ERROR`, `SWITCHTEC_IOCTL_EVENT_SYS_RESET`, `SWITCHTEC_IOCTL_EVENT_HOTPLUG` 等。
   - 定义了获取事件概要信息的 ioctl 命令 (`SWITCHTEC_IOCTL_EVENT_SUMMARY`, `SWITCHTEC_IOCTL_EVENT_SUMMARY_LEGACY`) 和对应的数据结构 `switchtec_ioctl_event_summary` 和 `switchtec_ioctl_event_summary_legacy`，用于获取全局事件计数和每个分区的事件计数。
   - 定义了控制事件上报行为的 ioctl 命令 (`SWITCHTEC_IOCTL_EVENT_CTL`) 和对应的数据结构 `switchtec_ioctl_event_ctl`，允许用户启用/禁用特定事件的轮询、日志记录、命令行接口上报和致命错误上报。

3. **端口 Fabric Forwarding (PFF) 管理:**
   - 定义了与端口 Fabric Forwarding 相关的 ioctl 命令 (`SWITCHTEC_IOCTL_PFF_TO_PORT`, `SWITCHTEC_IOCTL_PORT_TO_PFF`) 和对应的数据结构 `switchtec_ioctl_pff_port`。这些功能允许将 PFF 标识符映射到物理端口和分区，或者反之。

**与 Android 功能的关系及举例说明:**

Switchtec 芯片通常用于服务器、工作站等高性能计算设备中，但在某些高端 Android 设备或开发板中也可能存在，用于扩展 PCIe 连接能力。

例如，一个拥有多个高性能 GPU 或其他 PCIe 设备的 Android 设备，可能会使用 Switchtec 芯片来管理这些设备的连接。

* **Flash 分区管理:** Android 系统可能需要与 Switchtec 芯片交互来更新其固件或配置。例如，Android 的一个服务可能需要读取 Switchtec 芯片的配置分区 (`SWITCHTEC_IOCTL_PART_CFG0`) 以获取设备的初始化参数。
* **事件管理:** 当 Switchtec 芯片发生错误（例如 PCIe 链路错误）或硬件事件（例如热插拔）时，内核驱动程序会产生相应的事件。Android 系统可以通过 `SWITCHTEC_IOCTL_EVENT_SUMMARY` 获取这些事件信息，或者通过 `SWITCHTEC_IOCTL_EVENT_CTL` 注册对特定事件的关注。这可以帮助 Android 系统诊断硬件问题或响应硬件状态变化。
* **端口 Fabric Forwarding:** 如果 Android 系统需要配置 Switchtec 芯片的路由规则，以控制不同 PCIe 设备之间的通信，可能会使用 `SWITCHTEC_IOCTL_PFF_TO_PORT` 和 `SWITCHTEC_IOCTL_PORT_TO_PFF` 相关的 ioctl 命令。

**libc 函数的功能实现:**

这个头文件本身不包含任何 `libc` 函数的实现。它只是定义了与内核交互的接口（ioctl 命令和数据结构）。`libc` 库中与此相关的函数是 `ioctl` 系统调用。

`ioctl` 函数的功能是向设备驱动程序发送控制命令。它的原型通常如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

- `fd`:  表示打开的设备文件的文件描述符。
- `request`:  表示要执行的 ioctl 命令，通常由宏定义，例如这里的 `SWITCHTEC_IOCTL_FLASH_INFO`。
- `...`:  可选的参数，通常是指向与 ioctl 命令相关的数据结构的指针。

当用户空间程序调用 `ioctl` 时，内核会根据文件描述符找到对应的设备驱动程序，并将 `request` 和可选的参数传递给驱动程序的 `ioctl` 处理函数。驱动程序会根据 `request` 执行相应的操作，例如读取或写入设备寄存器，并可能通过参数传递数据回用户空间。

**dynamic linker 的功能 (不适用):**

这个头文件与 dynamic linker (动态链接器) 没有直接关系。Dynamic linker 的主要职责是在程序启动时加载共享库，并解析程序中对共享库函数的引用。

**逻辑推理、假设输入与输出:**

假设用户空间程序想要获取 Switchtec 芯片的 Flash 信息，它会执行以下步骤：

1. **打开 Switchtec 设备文件:**
   ```c
   int fd = open("/dev/your_switchtec_device", O_RDWR); // 假设设备文件路径
   if (fd < 0) {
       perror("open");
       // 处理错误
   }
   ```

2. **构造 `switchtec_ioctl_flash_info` 结构体:**
   ```c
   struct switchtec_ioctl_flash_info flash_info;
   ```

3. **调用 `ioctl` 命令:**
   ```c
   if (ioctl(fd, SWITCHTEC_IOCTL_FLASH_INFO, &flash_info) < 0) {
       perror("ioctl");
       // 处理错误
   }
   ```

4. **处理返回的 Flash 信息:**
   ```c
   printf("Flash Length: %llu\n", flash_info.flash_length);
   printf("Number of Partitions: %u\n", flash_info.num_partitions);
   ```

**假设输入:**  `/dev/your_switchtec_device` 是 Switchtec 设备的有效设备文件路径。

**预期输出:**  如果 ioctl 调用成功，`flash_info` 结构体将被驱动程序填充，程序将打印出 Switchtec 芯片的 Flash 总长度和分区数量。

**用户或编程常见的使用错误:**

1. **设备文件路径错误:**  打开了错误的设备文件或设备文件不存在。
   ```c
   int fd = open("/dev/wrong_device", O_RDWR); // 错误的文件路径
   ```

2. **ioctl 命令错误:**  使用了错误的 ioctl 命令常量。
   ```c
   // 假设想要获取 Flash 信息，却使用了获取事件概要信息的命令
   struct switchtec_ioctl_event_summary event_summary;
   if (ioctl(fd, SWITCHTEC_IOCTL_EVENT_SUMMARY, &event_summary) < 0) {
       // 错误，因为期望的数据结构不匹配
   }
   ```

3. **数据结构错误:**  传递给 `ioctl` 的数据结构类型或大小不正确。
   ```c
   struct switchtec_ioctl_flash_info *flash_info_ptr = NULL;
   if (ioctl(fd, SWITCHTEC_IOCTL_FLASH_INFO, flash_info_ptr) < 0) {
       // 错误，传递了 NULL 指针
   }
   ```

4. **权限不足:**  用户没有足够的权限访问 Switchtec 设备文件。

5. **设备驱动未加载:**  Switchtec 设备的内核驱动程序没有正确加载或初始化。

**Android Framework 或 NDK 如何到达这里:**

1. **硬件抽象层 (HAL):** Android Framework 通常不会直接与内核驱动程序交互。它会通过硬件抽象层 (HAL) 来间接访问硬件。对于 Switchtec 这样的硬件，可能会有一个专门的 HAL 模块。

2. **NDK (Native Development Kit):** 如果开发者需要在 Native 代码中直接与 Switchtec 交互，可以使用 NDK。

3. **Native 代码调用 `open` 和 `ioctl`:** NDK 代码可以使用标准的 C 库函数 `open` 打开 Switchtec 的设备文件，然后使用 `ioctl` 系统调用，并传入 `switchtec_ioctl.h` 中定义的 ioctl 命令和数据结构。

**步骤示例:**

1. **Android Framework (Java/Kotlin):**  Framework 层可能调用一个 Java Native Interface (JNI) 方法。

2. **JNI 代码 (C/C++):** JNI 方法会调用 Native 代码。

3. **Native 代码 (C/C++):**
   ```c++
   #include <fcntl.h>
   #include <sys/ioctl.h>
   #include "bionic/libc/kernel/uapi/linux/switchtec_ioctl.handroid" // 包含头文件

   int get_flash_info() {
       int fd = open("/dev/your_switchtec_device", O_RDWR);
       if (fd < 0) {
           perror("open");
           return -1;
       }

       struct switchtec_ioctl_flash_info flash_info;
       if (ioctl(fd, SWITCHTEC_IOCTL_FLASH_INFO, &flash_info) < 0) {
           perror("ioctl");
           close(fd);
           return -1;
       }

       printf("Flash Length: %llu\n", flash_info.flash_length);
       printf("Number of Partitions: %u\n", flash_info.num_partitions);

       close(fd);
       return 0;
   }
   ```

**Frida Hook 示例调试步骤:**

假设你想 hook `ioctl` 系统调用，查看哪些参数被传递给 Switchtec 驱动程序：

```python
import frida
import sys

# 替换为你的 Android 设备上的进程名称或 PID
process_name = "your_android_app_process"

try:
    session = frida.attach(process_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{process_name}' 未找到，请检查进程名称或 PID。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const buf = args[2];

        // 这里假设 Switchtec 设备的设备文件路径包含 "switchtec"
        const path = this.context.readReg('sp').add(Process.pointerSize).readPointer().readCString(); // 获取 open 系统调用的路径 (不完全准确，更可靠的方法需要更复杂的栈回溯)
        if (path && path.includes("switchtec")) {
            console.log("ioctl called with fd:", fd, "request:", request);

            // 打印 request 的十六进制值
            console.log("Request (Hex):", request.toString(16));

            // 可以根据 request 的值来解析 buf 指向的数据结构
            if (request === 0x40085740) { // SWITCHTEC_IOCTL_FLASH_INFO 的值 (需要根据实际情况确定)
                console.log("SWITCHTEC_IOCTL_FLASH_INFO detected");
                // 读取并打印 switchtec_ioctl_flash_info 结构体的内容
                const flash_info = buf.readByteArray(12); // 结构体大小
                console.log("flash_info:", hexdump(flash_info, { ansi: true }));
            } else if (request === 0xc0105741) { // SWITCHTEC_IOCTL_FLASH_PART_INFO 的值
                console.log("SWITCHTEC_IOCTL_FLASH_PART_INFO detected");
                const part_info = buf.readByteArray(16); // 结构体大小
                console.log("part_info:", hexdump(part_info, { ansi: true }));
            }
            // ... 添加其他 ioctl 命令的处理
        }
    }
});
"""

script = session.create_script(script_code)

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[-] Error: {message}")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**说明:**

1. **`frida.attach(process_name)`:** 连接到目标 Android 进程。
2. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:** Hook `ioctl` 系统调用。
3. **`onEnter`:** 在 `ioctl` 函数调用前执行的代码。
4. **`args`:**  `ioctl` 函数的参数。`args[0]` 是文件描述符，`args[1]` 是请求码，`args[2]` 是指向数据结构的指针。
5. **`request.toString(16)`:** 将请求码转换为十六进制字符串。
6. **条件判断 `if (request === 0x...)`:**  根据请求码判断具体的 ioctl 命令，并解析 `buf` 指向的数据。你需要根据 `switchtec_ioctl.h` 中定义的宏来计算实际的请求码值。请求码的计算方式通常是 `_IOR`, `_IOW`, `_IOWR` 宏的展开结果。例如，`_IOR('W', 0x40, struct switchtec_ioctl_flash_info)` 的值需要查阅 `asm/ioctl.h` 中的宏定义。
7. **`buf.readByteArray(size)`:** 读取 `buf` 指向的内存区域的数据。
8. **`hexdump`:**  Frida 提供的函数，用于以十六进制形式打印内存数据。

运行这个 Frida 脚本后，当目标 Android 进程调用 `ioctl` 并与 Switchtec 设备进行交互时，你将能在 Frida 的输出中看到 `ioctl` 的参数和相关的数据结构内容，从而帮助你调试和理解交互过程。

请注意，实际的设备文件路径和 ioctl 请求码的值可能因设备和驱动程序版本而异。你需要根据你的具体环境进行调整。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/switchtec_ioctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_SWITCHTEC_IOCTL_H
#define _UAPI_LINUX_SWITCHTEC_IOCTL_H
#include <linux/types.h>
#define SWITCHTEC_IOCTL_PART_CFG0 0
#define SWITCHTEC_IOCTL_PART_CFG1 1
#define SWITCHTEC_IOCTL_PART_IMG0 2
#define SWITCHTEC_IOCTL_PART_IMG1 3
#define SWITCHTEC_IOCTL_PART_NVLOG 4
#define SWITCHTEC_IOCTL_PART_VENDOR0 5
#define SWITCHTEC_IOCTL_PART_VENDOR1 6
#define SWITCHTEC_IOCTL_PART_VENDOR2 7
#define SWITCHTEC_IOCTL_PART_VENDOR3 8
#define SWITCHTEC_IOCTL_PART_VENDOR4 9
#define SWITCHTEC_IOCTL_PART_VENDOR5 10
#define SWITCHTEC_IOCTL_PART_VENDOR6 11
#define SWITCHTEC_IOCTL_PART_VENDOR7 12
#define SWITCHTEC_IOCTL_PART_BL2_0 13
#define SWITCHTEC_IOCTL_PART_BL2_1 14
#define SWITCHTEC_IOCTL_PART_MAP_0 15
#define SWITCHTEC_IOCTL_PART_MAP_1 16
#define SWITCHTEC_IOCTL_PART_KEY_0 17
#define SWITCHTEC_IOCTL_PART_KEY_1 18
#define SWITCHTEC_NUM_PARTITIONS_GEN3 13
#define SWITCHTEC_NUM_PARTITIONS_GEN4 19
#define SWITCHTEC_IOCTL_NUM_PARTITIONS SWITCHTEC_NUM_PARTITIONS_GEN3
struct switchtec_ioctl_flash_info {
  __u64 flash_length;
  __u32 num_partitions;
  __u32 padding;
};
#define SWITCHTEC_IOCTL_PART_ACTIVE 1
#define SWITCHTEC_IOCTL_PART_RUNNING 2
struct switchtec_ioctl_flash_part_info {
  __u32 flash_partition;
  __u32 address;
  __u32 length;
  __u32 active;
};
struct switchtec_ioctl_event_summary_legacy {
  __u64 global;
  __u64 part_bitmap;
  __u32 local_part;
  __u32 padding;
  __u32 part[48];
  __u32 pff[48];
};
struct switchtec_ioctl_event_summary {
  __u64 global;
  __u64 part_bitmap;
  __u32 local_part;
  __u32 padding;
  __u32 part[48];
  __u32 pff[255];
};
#define SWITCHTEC_IOCTL_EVENT_STACK_ERROR 0
#define SWITCHTEC_IOCTL_EVENT_PPU_ERROR 1
#define SWITCHTEC_IOCTL_EVENT_ISP_ERROR 2
#define SWITCHTEC_IOCTL_EVENT_SYS_RESET 3
#define SWITCHTEC_IOCTL_EVENT_FW_EXC 4
#define SWITCHTEC_IOCTL_EVENT_FW_NMI 5
#define SWITCHTEC_IOCTL_EVENT_FW_NON_FATAL 6
#define SWITCHTEC_IOCTL_EVENT_FW_FATAL 7
#define SWITCHTEC_IOCTL_EVENT_TWI_MRPC_COMP 8
#define SWITCHTEC_IOCTL_EVENT_TWI_MRPC_COMP_ASYNC 9
#define SWITCHTEC_IOCTL_EVENT_CLI_MRPC_COMP 10
#define SWITCHTEC_IOCTL_EVENT_CLI_MRPC_COMP_ASYNC 11
#define SWITCHTEC_IOCTL_EVENT_GPIO_INT 12
#define SWITCHTEC_IOCTL_EVENT_PART_RESET 13
#define SWITCHTEC_IOCTL_EVENT_MRPC_COMP 14
#define SWITCHTEC_IOCTL_EVENT_MRPC_COMP_ASYNC 15
#define SWITCHTEC_IOCTL_EVENT_DYN_PART_BIND_COMP 16
#define SWITCHTEC_IOCTL_EVENT_AER_IN_P2P 17
#define SWITCHTEC_IOCTL_EVENT_AER_IN_VEP 18
#define SWITCHTEC_IOCTL_EVENT_DPC 19
#define SWITCHTEC_IOCTL_EVENT_CTS 20
#define SWITCHTEC_IOCTL_EVENT_HOTPLUG 21
#define SWITCHTEC_IOCTL_EVENT_IER 22
#define SWITCHTEC_IOCTL_EVENT_THRESH 23
#define SWITCHTEC_IOCTL_EVENT_POWER_MGMT 24
#define SWITCHTEC_IOCTL_EVENT_TLP_THROTTLING 25
#define SWITCHTEC_IOCTL_EVENT_FORCE_SPEED 26
#define SWITCHTEC_IOCTL_EVENT_CREDIT_TIMEOUT 27
#define SWITCHTEC_IOCTL_EVENT_LINK_STATE 28
#define SWITCHTEC_IOCTL_EVENT_GFMS 29
#define SWITCHTEC_IOCTL_EVENT_INTERCOMM_REQ_NOTIFY 30
#define SWITCHTEC_IOCTL_EVENT_UEC 31
#define SWITCHTEC_IOCTL_MAX_EVENTS 32
#define SWITCHTEC_IOCTL_EVENT_LOCAL_PART_IDX - 1
#define SWITCHTEC_IOCTL_EVENT_IDX_ALL - 2
#define SWITCHTEC_IOCTL_EVENT_FLAG_CLEAR (1 << 0)
#define SWITCHTEC_IOCTL_EVENT_FLAG_EN_POLL (1 << 1)
#define SWITCHTEC_IOCTL_EVENT_FLAG_EN_LOG (1 << 2)
#define SWITCHTEC_IOCTL_EVENT_FLAG_EN_CLI (1 << 3)
#define SWITCHTEC_IOCTL_EVENT_FLAG_EN_FATAL (1 << 4)
#define SWITCHTEC_IOCTL_EVENT_FLAG_DIS_POLL (1 << 5)
#define SWITCHTEC_IOCTL_EVENT_FLAG_DIS_LOG (1 << 6)
#define SWITCHTEC_IOCTL_EVENT_FLAG_DIS_CLI (1 << 7)
#define SWITCHTEC_IOCTL_EVENT_FLAG_DIS_FATAL (1 << 8)
#define SWITCHTEC_IOCTL_EVENT_FLAG_UNUSED (~0x1ff)
struct switchtec_ioctl_event_ctl {
  __u32 event_id;
  __s32 index;
  __u32 flags;
  __u32 occurred;
  __u32 count;
  __u32 data[5];
};
#define SWITCHTEC_IOCTL_PFF_VEP 100
struct switchtec_ioctl_pff_port {
  __u32 pff;
  __u32 partition;
  __u32 port;
};
#define SWITCHTEC_IOCTL_FLASH_INFO _IOR('W', 0x40, struct switchtec_ioctl_flash_info)
#define SWITCHTEC_IOCTL_FLASH_PART_INFO _IOWR('W', 0x41, struct switchtec_ioctl_flash_part_info)
#define SWITCHTEC_IOCTL_EVENT_SUMMARY _IOR('W', 0x42, struct switchtec_ioctl_event_summary)
#define SWITCHTEC_IOCTL_EVENT_SUMMARY_LEGACY _IOR('W', 0x42, struct switchtec_ioctl_event_summary_legacy)
#define SWITCHTEC_IOCTL_EVENT_CTL _IOWR('W', 0x43, struct switchtec_ioctl_event_ctl)
#define SWITCHTEC_IOCTL_PFF_TO_PORT _IOWR('W', 0x44, struct switchtec_ioctl_pff_port)
#define SWITCHTEC_IOCTL_PORT_TO_PFF _IOWR('W', 0x45, struct switchtec_ioctl_pff_port)
#endif

"""

```