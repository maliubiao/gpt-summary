Response:
Let's break down the thought process for analyzing the provided C header file.

**1. Initial Understanding: What is this file?**

The first line is crucial: "这是目录为bionic/libc/kernel/uapi/rdma/hfi/hfi1_user.handroid bionic的源代码文件". This tells us:

* **Location:** `bionic/libc/kernel/uapi/rdma/hfi/hfi1_user.handroid`  This immediately suggests it's related to the Android Bionic library, interacts with the kernel, specifically through the `uapi` (userspace API) and involves RDMA (Remote Direct Memory Access) and a specific hardware interface (`hfi1`). The `.handroid` extension is likely just a marker for the Android build process.
* **Purpose:**  Since it's under `uapi`, it defines the interface between userspace applications and the kernel for interacting with the `hfi1` RDMA hardware. It's a *header file*, meaning it declares types, constants, and possibly inline functions.

**2. High-Level Functionality Identification (Scanning for Keywords and Patterns):**

I'll scan the code looking for recurring themes and keywords:

* **`#define HFI1_`**:  This prefix is dominant. It suggests constants and definitions specific to the `hfi1` interface. Looking at the values, many are bitmasks (powers of 2). This strongly hints at capabilities and status flags.
* **`RDMA`**:  The path and `rdma_user_ioctl.h` include directly confirm RDMA involvement.
* **`CAP_`**:  Appears frequently after `HFI1_`. This strongly suggests hardware or driver capabilities.
* **`EVENT_`**:  Indicates events that the userspace application can be notified about.
* **`STATUS_`**: Likely reflects the state of the hardware or the connection.
* **`sdma`**:  Appears in `HFI1_CAP_SDMA`, `hfi1_sdma_comp_state`, `hfi1_sdma_comp_entry`, `sdma_req_opcode`, and `sdma_req_info`. This points to a Sub-Direct Memory Access mechanism.
* **`pkt_header`**, `kdeth_header`: Suggests network packet structures.
* **`ureg`**:  Indicates userspace registers or memory regions accessible via this interface.
* **`ioctl`**: While not directly in this file, the inclusion of `rdma_user_ioctl.h` is a strong indicator that this interface is accessed through ioctl system calls.

**3. Categorizing Functionality:**

Based on the keywords, I can start grouping the functionalities:

* **Capabilities:**  `HFI1_CAP_*` definitions. These describe what the `hfi1` hardware/driver supports.
* **Events:** `HFI1_EVENT_*` definitions. These are notifications from the kernel to the user space.
* **Status:** `HFI1_STATUS_*` definitions. Reflect the current state of the hardware.
* **Sub-Direct Memory Access (SDMA):**  Definitions related to `sdma_req_opcode`, `sdma_req_info`, and `hfi1_sdma_comp_entry`. This is a mechanism for offloading memory operations.
* **Packet Handling:** `hfi1_pkt_header` and `hfi1_kdeth_header`. These define the structure of network packets.
* **Userspace Registers:** `enum hfi1_ureg`. Defines accessible memory regions.
* **Versioning:** `HFI1_USER_SWMAJOR` and `HFI1_USER_SWMINOR`.

**4. Connecting to Android:**

Now, how does this relate to Android?

* **Bionic Library:** The file is part of Bionic, Android's C library. This means Android applications *could* potentially use this interface, though it's likely low-level and not directly exposed to typical app developers.
* **RDMA:** RDMA is used for high-performance networking. Android devices themselves rarely directly expose high-performance RDMA hardware. However, it becomes relevant in scenarios like:
    * **Data Centers:** Android devices (or custom Android-based systems) in data centers might use RDMA for inter-node communication.
    * **Specialized Hardware:** Some specialized Android devices might include RDMA capabilities.
    * **Virtualization/Emulation:** Android emulators or virtualized Android environments might use RDMA for communication with the host system or other virtual machines.

**5. Explaining Libc Functions (Not Directly Present):**

The key insight here is that *this header file doesn't *define* libc functions*. It defines *constants and structures* that would be used *in conjunction with* libc functions. The relevant libc function would be `ioctl()`, used to interact with device drivers.

**6. Dynamic Linker (Limited Relevance):**

This header file itself doesn't directly involve the dynamic linker. It's a header file defining an API. However:

* **Usage Context:** If userspace libraries were built to interact with this RDMA interface, those libraries would be linked dynamically.
* **`rdma_user_ioctl.h`:**  The included header *might* indirectly involve concepts relevant to dynamic linking if it defines function pointers or structures used in shared libraries.

**7. Logic Inference (Limited Scope):**

The logic here is mostly about defining constants and data structures. There isn't complex algorithmic logic within this header file itself. Hypothetical inputs and outputs would relate to the values of these constants and how they are used in ioctl calls.

**8. Common Usage Errors:**

Thinking about how a programmer might use this API:

* **Incorrect Bitmask Usage:**  Misunderstanding the meaning of the capability flags or status bits.
* **Incorrect ioctl Codes:** Using the wrong ioctl command to interact with the driver.
* **Memory Management:** Incorrectly allocating or managing memory for the structures defined here.
* **Version Mismatches:**  Trying to use features not supported by the current hardware/driver version.

**9. Android Framework/NDK Access and Frida Hooking:**

This is where the explanation gets more involved:

* **Likely Low-Level:** Direct access from typical Android apps through the NDK is unlikely. This is a very low-level hardware interface.
* **Potential Users:**  System services or HAL (Hardware Abstraction Layer) implementations would be the most likely users.
* **HAL Implementation:** A HAL module responsible for managing the RDMA hardware would use these definitions.
* **Frida Hooking:** To hook calls related to this, you'd need to target the kernel driver or the HAL module interacting with the driver. Hooking `ioctl` calls with the relevant device file descriptor and ioctl command codes would be the primary approach.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Are there any actual function definitions here?"  *Correction:*  No, it's just a header file.
* **Initial thought:** "How does dynamic linking directly apply here?" *Correction:* It's more about the context of *using* this API from shared libraries.
* **Focus shift:**  Move from trying to find explicit libc function calls *within* the header to understanding how the defined constants and structures are *used* in system calls like `ioctl`.

By following these steps, combining code analysis with an understanding of the Android architecture and RDMA concepts, we arrive at a comprehensive explanation of the header file's functionality.
这个文件 `bionic/libc/kernel/uapi/rdma/hfi/hfi1_user.handroid` 是 Android Bionic 库中的一个头文件，它定义了用户空间程序与 InfiniBand HFI1 (Host Fabric Interface 1) 硬件交互所需的常量、数据结构和宏定义。HFI1 是一种高性能网络接口卡，常用于高性能计算和数据中心环境。

由于这是一个 `uapi` (用户空间 API) 目录下的文件，它的主要目的是为用户空间程序提供一个稳定的接口，以便它们可以与内核中的 HFI1 驱动程序进行通信。

**功能列举:**

1. **定义 HFI1 硬件的能力 (Capabilities):**  一系列 `HFI1_CAP_*` 宏定义了 HFI1 硬件支持的各种特性。例如：
    * `HFI1_CAP_DMA_RTAIL`: 支持 DMA 读尾指针。
    * `HFI1_CAP_SDMA`: 支持 Sub-Direct Memory Access (SDMA)。
    * `HFI1_CAP_EXTENDED_PSN`: 支持扩展的包序列号。
    这些能力信息允许用户空间程序在运行时检查硬件是否支持特定的功能。

2. **定义事件 (Events):**  `HFI1_EVENT_*` 宏定义了 HFI1 硬件可能触发的事件，例如：
    * `HFI1_EVENT_FROZEN`: 硬件进入冻结状态。
    * `HFI1_EVENT_LINKDOWN`: 网络链路断开。
    用户空间程序可以使用这些事件来监控硬件的状态变化。

3. **定义状态 (Status):** `HFI1_STATUS_*` 宏定义了 HFI1 硬件的各种状态标志，例如：
    * `HFI1_STATUS_INITTED`: 硬件已初始化。
    * `HFI1_STATUS_IB_READY`: InfiniBand 接口已准备就绪。
    用户空间程序可以读取这些状态来了解硬件的当前运行状况。

4. **定义 SDMA (Sub-Direct Memory Access) 相关结构和枚举:**
    * `enum hfi1_sdma_comp_state`: 定义了 SDMA 操作的完成状态 (例如 `FREE`, `QUEUED`, `COMPLETE`, `ERROR`)。
    * `struct hfi1_sdma_comp_entry`: 定义了 SDMA 完成队列的条目结构，包含状态和错误代码。
    * `enum sdma_req_opcode`: 定义了 SDMA 请求的操作码 (例如 `EXPECTED`, `EAGER`)。
    * `struct sdma_req_info`: 定义了 SDMA 请求的附加信息。
    SDMA 允许硬件直接访问内存，而无需 CPU 的干预，从而提高数据传输效率。

5. **定义包头结构 (Packet Header Structures):**
    * `struct hfi1_kdeth_header`: 定义了扩展数据传输头 (Kernel Data Transport Header) 的结构。
    * `struct hfi1_pkt_header`: 定义了完整的包头结构，包括 PBC (Packet Buffer Control), LRH (Local Route Header), BTH (Base Transport Header) 和 KDETH。

6. **定义用户空间寄存器 (Userspace Registers):** `enum hfi1_ureg` 定义了用户空间可以直接访问的硬件寄存器偏移量。这允许用户空间程序直接读取或写入特定的硬件寄存器。

7. **定义软件版本信息:** `HFI1_USER_SWMAJOR` 和 `HFI1_USER_SWMINOR` 定义了用户空间 API 的主版本号和次版本号。

**与 Android 功能的关系及举例:**

虽然这个文件位于 Android Bionic 库中，但 HFI1 硬件本身并不是 Android 移动设备的标准配置。HFI1 主要用于高性能计算和服务器环境。因此，直接在典型的 Android 手机或平板电脑上使用这些功能是不太可能的。

**可能的使用场景:**

* **Android 在服务器或数据中心的应用:** 如果 Android 被用作服务器操作系统或者在数据中心环境中运行，并且这些服务器配备了 HFI1 网卡，那么这些定义就会被使用。例如，某些高性能数据库或者分布式计算框架可能会利用 RDMA 技术（包括 HFI1）来提高节点之间的通信效率。

* **特定的嵌入式系统或定制 Android 设备:**  一些具有特殊网络需求的高性能嵌入式系统可能会集成 HFI1 硬件，并在其 Android 系统中使用这些接口。

**由于 HFI1 不是 Android 核心功能，很难给出直接与 Android Framework 或 NDK 相关的典型例子。**  这些定义更像是 Linux 内核提供的底层硬件接口，Android 只是将其包含在 Bionic 库中以便在需要时使用。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **没有定义任何 libc 函数**。它只定义了常量、宏和数据结构。libc 函数（例如 `open`, `close`, `ioctl`, `mmap` 等）会使用这些定义来与内核中的 HFI1 驱动程序进行交互。

例如，用户空间程序可能会使用 `ioctl` 系统调用，并传入与 HFI1 相关的命令码（这些命令码可能在 `rdma_user_ioctl.h` 中定义，该文件被此文件包含），以及包含此文件中定义的结构体的参数，来控制 HFI1 硬件或获取其状态。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不直接涉及 dynamic linker 的功能**。它定义的是内核接口。然而，如果用户空间程序或库需要使用这些 HFI1 功能，它们会通过链接到相关的共享库来实现。

**假设有一个名为 `libhfi1user.so` 的共享库，它封装了对 HFI1 接口的访问。**

**`libhfi1user.so` 的布局样本:**

```
libhfi1user.so:
    .text          # 包含代码段
        hfi1_init()
        hfi1_query_capabilities()
        hfi1_send_data()
        ...
    .data          # 包含已初始化的数据
        ...
    .bss           # 包含未初始化的数据
        ...
    .dynsym        # 动态符号表
        hfi1_init
        hfi1_query_capabilities
        ...
    .dynstr        # 动态字符串表
        ...
    .rel.dyn       # 动态重定位表
        ...
    .plt           # 程序链接表 (Procedure Linkage Table)
        ...
    .got.plt       # 全局偏移表 (Global Offset Table)
        ...
```

**链接的处理过程:**

1. **编译时链接:** 当应用程序或另一个共享库需要使用 `libhfi1user.so` 提供的功能时，链接器（例如 `ld`）会在编译时记录对 `libhfi1user.so` 中符号的依赖。

2. **运行时链接:** 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载所有需要的共享库，包括 `libhfi1user.so`。

3. **符号解析:** dynamic linker 会解析应用程序和 `libhfi1user.so` 之间的符号引用。例如，如果应用程序调用了 `hfi1_init()` 函数，dynamic linker 会在 `libhfi1user.so` 的 `.dynsym` 表中查找该符号的地址，并更新应用程序的 `.got.plt` 表，使其指向 `libhfi1user.so` 中 `hfi1_init()` 函数的实际地址。

4. **重定位:** dynamic linker 会根据 `.rel.dyn` 表中的信息，调整 `libhfi1user.so` 中需要重定位的地址，使其在当前进程的地址空间中正确工作。

**逻辑推理，假设输入与输出:**

由于这个文件主要是定义，逻辑推理的应用场景有限。一个可能的例子是基于能力标志进行条件编译或运行时检查：

**假设输入:** 用户空间程序想要确定 HFI1 硬件是否支持 SDMA 功能。

**代码逻辑:**

```c
#include <stdio.h>
#include <bionic/libc/kernel/uapi/rdma/hfi/hfi1_user.handroid>

int main() {
    unsigned long capabilities = /* 从内核获取的硬件能力值 */;

    if (capabilities & HFI1_CAP_SDMA) {
        printf("HFI1 hardware supports SDMA.\n");
        // 执行使用 SDMA 的代码
    } else {
        printf("HFI1 hardware does not support SDMA.\n");
        // 执行不使用 SDMA 的代码
    }

    return 0;
}
```

**输出:**  根据 `capabilities` 变量的值，程序会输出 "HFI1 hardware supports SDMA." 或 "HFI1 hardware does not support SDMA."。

**用户或编程常见的使用错误:**

1. **直接使用宏定义而没有检查硬件能力:**  用户空间程序可能会直接使用需要特定硬件能力的功能，而没有先检查对应的 `HFI1_CAP_*` 标志，导致运行时错误。

   **示例:**  程序假设 SDMA 可用，并直接构建 SDMA 请求，但运行在不支持 SDMA 的硬件上，导致驱动程序返回错误。

2. **错误地解释状态标志:**  误解 `HFI1_STATUS_*` 标志的含义，导致程序做出错误的判断。

   **示例:**  程序认为 `HFI1_STATUS_IB_READY` 表示硬件完全正常，但实际上可能还有其他问题。

3. **不正确的 ioctl 使用:**  向内核驱动程序发送错误的 ioctl 命令码或参数，导致驱动程序出错或返回意外结果。

   **示例:**  在调用 ioctl 设置某些 HFI1 参数时，使用了错误的结构体大小或字段顺序。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**可能性较低：**  由于 HFI1 不是 Android 设备的常见硬件，Android Framework 和 NDK 很少会直接涉及这个文件。更可能的使用场景是在特定的、定制的 Android 系统或服务器应用中。

**假设一个定制的 Android 系统或运行在服务器上的 Android 应用使用了 HFI1。**

1. **NDK 开发 (不太常见):**  开发者可以使用 NDK 编写 C/C++ 代码，直接包含 `bionic/libc/kernel/uapi/rdma/hfi/hfi1_user.handroid` 头文件，并使用相关的系统调用（如 `ioctl`）与 HFI1 驱动程序交互。

2. **HAL (硬件抽象层):**  更常见的情况是，与 HFI1 硬件交互的逻辑会被封装在 HAL 模块中。Android Framework 通过 HAL 与硬件进行通信。一个负责 HFI1 的 HAL 模块的实现可能会包含这个头文件。

3. **系统服务:**  在 Android 系统中运行的某些特权服务可能需要直接与硬件交互，例如网络相关的服务。如果 HFI1 被用作底层网络接口，这些服务可能会使用这些定义。

**Frida Hook 示例:**

假设我们想 hook 一个使用 `ioctl` 系统调用与 HFI1 驱动程序交互的程序。我们需要找到该程序打开的 HFI1 设备文件描述符以及它使用的 ioctl 命令码。

**步骤：**

1. **识别目标进程:** 确定要 hook 的进程的名称或 PID。
2. **查找设备文件:**  HFI1 设备通常位于 `/dev/infiniband/` 目录下，例如 `/dev/infiniband/hfi1_0`。
3. **Hook `ioctl` 系统调用:**  使用 Frida 拦截 `ioctl` 调用，并检查其文件描述符和命令码。

**Frida 脚本示例 (假设目标进程名为 `hfi1_app`):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach("hfi1_app")
except frida.ProcessNotFoundError:
    print("Target process not found.")
    sys.exit()

script_code = """
    const IOCTL_MAGIC = 0xC0; // 假设 HFI1 ioctl 命令的 magic number

    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function (args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 检查文件描述符是否指向 HFI1 设备 (需要根据实际情况判断)
            // 例如，可以检查打开的文件路径
            const path = this.context.rsi.readCString(); // 假设 open 系统调用的路径在 rsi 寄存器中

            if (path && path.startsWith("/dev/infiniband/hfi1")) {
                // 检查 ioctl 命令码是否与 HFI1 相关
                if ((request >> 8) == IOCTL_MAGIC) {
                    console.log("[*] ioctl called on HFI1 device, fd:", fd, "request:", request);
                    // 可以进一步解析 args[2] 指向的结构体
                }
            }
        },
        onLeave: function (retval) {
            // console.log("ioctl returned:", retval);
        }
    });
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释:**

* 这个 Frida 脚本 hook 了 `ioctl` 系统调用。
* 在 `onEnter` 中，它获取了文件描述符和 ioctl 命令码。
* 它尝试根据文件路径（假设通过检查 `open` 系统调用的参数获取）来判断是否是 HFI1 设备。
* 它还检查 ioctl 命令码的 magic number，以进一步确认是否是 HFI1 相关的 ioctl。
* 如果满足条件，它会打印出相关信息。

**请注意:**  实际的 hook 脚本可能需要根据具体的 HFI1 驱动程序和用户空间程序的实现进行调整，例如确定正确的设备文件路径和 ioctl 命令码的格式。还需要解析 `ioctl` 的第三个参数，该参数通常指向与 HFI1 相关的结构体。

总结来说，虽然 `hfi1_user.handroid` 文件是 Android Bionic 的一部分，但它的功能主要服务于高性能计算环境中的 HFI1 硬件，与典型的 Android 移动设备功能关系不大。 理解这个文件的功能需要了解 RDMA 和 InfiniBand 的概念。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/rdma/hfi/hfi1_user.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX__HFI1_USER_H
#define _LINUX__HFI1_USER_H
#include <linux/types.h>
#include <rdma/rdma_user_ioctl.h>
#define HFI1_USER_SWMAJOR 6
#define HFI1_USER_SWMINOR 3
#define HFI1_SWMAJOR_SHIFT 16
#define HFI1_CAP_DMA_RTAIL (1UL << 0)
#define HFI1_CAP_SDMA (1UL << 1)
#define HFI1_CAP_SDMA_AHG (1UL << 2)
#define HFI1_CAP_EXTENDED_PSN (1UL << 3)
#define HFI1_CAP_HDRSUPP (1UL << 4)
#define HFI1_CAP_TID_RDMA (1UL << 5)
#define HFI1_CAP_USE_SDMA_HEAD (1UL << 6)
#define HFI1_CAP_MULTI_PKT_EGR (1UL << 7)
#define HFI1_CAP_NODROP_RHQ_FULL (1UL << 8)
#define HFI1_CAP_NODROP_EGR_FULL (1UL << 9)
#define HFI1_CAP_TID_UNMAP (1UL << 10)
#define HFI1_CAP_PRINT_UNIMPL (1UL << 11)
#define HFI1_CAP_ALLOW_PERM_JKEY (1UL << 12)
#define HFI1_CAP_NO_INTEGRITY (1UL << 13)
#define HFI1_CAP_PKEY_CHECK (1UL << 14)
#define HFI1_CAP_STATIC_RATE_CTRL (1UL << 15)
#define HFI1_CAP_OPFN (1UL << 16)
#define HFI1_CAP_SDMA_HEAD_CHECK (1UL << 17)
#define HFI1_CAP_EARLY_CREDIT_RETURN (1UL << 18)
#define HFI1_CAP_AIP (1UL << 19)
#define HFI1_RCVHDR_ENTSIZE_2 (1UL << 0)
#define HFI1_RCVHDR_ENTSIZE_16 (1UL << 1)
#define HFI1_RCVDHR_ENTSIZE_32 (1UL << 2)
#define _HFI1_EVENT_FROZEN_BIT 0
#define _HFI1_EVENT_LINKDOWN_BIT 1
#define _HFI1_EVENT_LID_CHANGE_BIT 2
#define _HFI1_EVENT_LMC_CHANGE_BIT 3
#define _HFI1_EVENT_SL2VL_CHANGE_BIT 4
#define _HFI1_EVENT_TID_MMU_NOTIFY_BIT 5
#define _HFI1_MAX_EVENT_BIT _HFI1_EVENT_TID_MMU_NOTIFY_BIT
#define HFI1_EVENT_FROZEN (1UL << _HFI1_EVENT_FROZEN_BIT)
#define HFI1_EVENT_LINKDOWN (1UL << _HFI1_EVENT_LINKDOWN_BIT)
#define HFI1_EVENT_LID_CHANGE (1UL << _HFI1_EVENT_LID_CHANGE_BIT)
#define HFI1_EVENT_LMC_CHANGE (1UL << _HFI1_EVENT_LMC_CHANGE_BIT)
#define HFI1_EVENT_SL2VL_CHANGE (1UL << _HFI1_EVENT_SL2VL_CHANGE_BIT)
#define HFI1_EVENT_TID_MMU_NOTIFY (1UL << _HFI1_EVENT_TID_MMU_NOTIFY_BIT)
#define HFI1_STATUS_INITTED 0x1
#define HFI1_STATUS_CHIP_PRESENT 0x20
#define HFI1_STATUS_IB_READY 0x40
#define HFI1_STATUS_IB_CONF 0x80
#define HFI1_STATUS_HWERROR 0x200
#define HFI1_MAX_SHARED_CTXTS 8
#define HFI1_POLL_TYPE_ANYRCV 0x0
#define HFI1_POLL_TYPE_URGENT 0x1
enum hfi1_sdma_comp_state {
  FREE = 0,
  QUEUED,
  COMPLETE,
  ERROR
};
struct hfi1_sdma_comp_entry {
  __u32 status;
  __u32 errcode;
};
struct hfi1_status {
  __aligned_u64 dev;
  __aligned_u64 port;
  char freezemsg[];
};
enum sdma_req_opcode {
  EXPECTED = 0,
  EAGER
};
#define HFI1_SDMA_REQ_VERSION_MASK 0xF
#define HFI1_SDMA_REQ_VERSION_SHIFT 0x0
#define HFI1_SDMA_REQ_OPCODE_MASK 0xF
#define HFI1_SDMA_REQ_OPCODE_SHIFT 0x4
#define HFI1_SDMA_REQ_IOVCNT_MASK 0xFF
#define HFI1_SDMA_REQ_IOVCNT_SHIFT 0x8
struct sdma_req_info {
  __u16 ctrl;
  __u16 npkts;
  __u16 fragsize;
  __u16 comp_idx;
} __attribute__((__packed__));
struct hfi1_kdeth_header {
  __le32 ver_tid_offset;
  __le16 jkey;
  __le16 hcrc;
  __le32 swdata[7];
} __attribute__((__packed__));
struct hfi1_pkt_header {
  __le16 pbc[4];
  __be16 lrh[4];
  __be32 bth[3];
  struct hfi1_kdeth_header kdeth;
} __attribute__((__packed__));
enum hfi1_ureg {
  ur_rcvhdrtail = 0,
  ur_rcvhdrhead = 1,
  ur_rcvegrindextail = 2,
  ur_rcvegrindexhead = 3,
  ur_rcvegroffsettail = 4,
  ur_maxreg,
  ur_rcvtidflowtable = 256
};
#endif

"""

```