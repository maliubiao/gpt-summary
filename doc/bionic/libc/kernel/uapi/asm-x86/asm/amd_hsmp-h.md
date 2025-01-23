Response:
Let's break down the thought process for analyzing this header file.

**1. Initial Scan and Understanding the Context:**

* **File Path:**  `bionic/libc/kernel/uapi/asm-x86/asm/amd_hsmp.h`  This immediately tells us a few key things:
    * `bionic`: This is part of the Android's C library.
    * `libc`: It's related to the core C library functionalities.
    * `kernel`: This indicates it's an interface to the Linux kernel.
    * `uapi`: This signifies "user-space API," meaning it defines how user-space programs interact with the kernel.
    * `asm-x86`: This is specific to the x86 architecture.
    * `amd_hsmp.h`:  The "amd_hsmp" part is the most crucial. It strongly suggests this header file deals with AMD's "Heterogeneous System Management Protocol" (HSMP).

* **Auto-generated Comment:**  The "auto-generated" comment is a strong indicator that manual modification is discouraged. This often implies a more fundamental role or that changes should be made elsewhere (e.g., in kernel source).

* **Includes:**  `#include <linux/types.h>`  This confirms its kernel interface nature, pulling in standard Linux type definitions.

* **`#pragma pack(4)`:** This directive affects how structures are laid out in memory, specifically setting the alignment of structure members to 4 bytes. This is often done for performance or compatibility reasons when interacting with hardware or kernel interfaces.

**2. Identifying Key Data Structures and Enums:**

* **`enum hsmp_message_ids`:** This is a central element. The names clearly indicate various functionalities related to monitoring and controlling hardware aspects, such as power, temperature, frequency, and interconnects (XGMI). The naming convention is quite descriptive (e.g., `HSMP_GET_SOCKET_POWER`).

* **`struct hsmp_message`:** This structure likely represents the data exchanged between user-space and the kernel for HSMP commands. The fields `msg_id`, `num_args`, `response_sz`, `args`, and `sock_ind` suggest a command-response mechanism.

* **`enum hsmp_msg_type`:**  `HSMP_SET` and `HSMP_GET` clearly define the two basic types of operations.

* **`enum hsmp_proto_versions`:**  This indicates versioning of the HSMP protocol, which is common in communication protocols.

* **`struct hsmp_msg_desc`:**  This seems to be a table describing the properties (number of arguments, response size, type) of each message ID defined in `hsmp_message_ids`.

* **`hsmp_msg_desc_table`:** This is the actual table populated with `hsmp_msg_desc` entries, indexed by the `hsmp_message_ids` enum values. The data within this table is critical for understanding the expected format of each command.

* **`struct hsmp_metric_table`:** This is a large structure containing various performance and telemetry data points related to the AMD system. The names of the fields are self-explanatory and provide insight into the information HSMP can provide (e.g., temperatures, power, frequencies, bandwidth).

**3. Understanding Functionality and Relationships:**

* **Core Function:**  Based on the names and structures, the primary function of this header file is to define the interface for interacting with AMD's HSMP. This protocol allows user-space to query and potentially control various hardware aspects of an AMD system.

* **Android Relevance:**  Given it's part of Bionic, it's clear that Android uses HSMP on devices with compatible AMD hardware. This allows the Android system to monitor and manage the hardware for power efficiency, thermal control, and performance optimization.

* **libc Functions (Implied):**  While this header *doesn't* define libc functions, it *enables* them. A libc function (likely involving `ioctl`) would use the structures and constants defined here to communicate with the kernel driver responsible for HSMP.

* **Dynamic Linker (Indirect):** The dynamic linker's role is indirect. If an Android component (like a HAL or a system service) needs to interact with the HSMP functionality, it would likely be implemented in a shared library (`.so`). The dynamic linker would load this library.

**4. Hypothetical Use Case and Error Handling:**

* **Hypothetical Use Case:** An Android system service responsible for thermal management might use HSMP to get temperature readings and adjust power limits.

* **Common Errors:**  Incorrect `msg_id`, wrong number of arguments, or trying to set a value outside the allowed range are potential errors. The kernel driver would likely return error codes.

**5. Tracing the Path (Framework/NDK to Kernel):**

* **Android Framework/NDK:**  An Android framework service or an NDK application would likely use standard Linux system calls, most probably `ioctl()`, to interact with the kernel driver. This involves opening the appropriate device file (likely under `/dev`) and then making `ioctl` calls with the `HSMP_IOCTL_CMD` and the `hsmp_message` structure.

**6. Frida Hooking (Conceptual):**

* The thought process for Frida hooking is to identify the point of interaction. Since `ioctl` is the likely system call, hooking `ioctl` and filtering for calls related to the HSMP device file or the `HSMP_IOCTL_CMD` would be the primary strategy. Then, examining the `hsmp_message` structure passed to `ioctl` would reveal the specific command being sent.

**Self-Correction/Refinement during the thought process:**

* Initially, I might have focused too much on specific libc functions. Realizing this is a *header* file for kernel interaction shifts the focus to system calls like `ioctl`.
* Recognizing the "auto-generated" nature emphasizes that the core logic isn't *in* this file but in the kernel driver it describes.
* Thinking about how user-space actually *uses* these definitions leads to the `ioctl` system call and the need for a device file.

By following this structured approach, starting with the big picture and gradually drilling down into the details of the code, it's possible to effectively analyze the functionality and its role within the Android ecosystem. The key is to leverage the naming conventions, structure definitions, and comments within the code itself to infer the purpose and relationships.
这个头文件 `bionic/libc/kernel/uapi/asm-x86/asm/amd_hsmp.h` 定义了用户空间程序与 Linux 内核中 AMD Heterogeneous System Management Protocol (HSMP) 接口进行交互所需的常量、枚举和数据结构。由于它位于 `uapi` 目录下，这意味着它是用户空间 API 的一部分，用于定义用户程序如何与内核模块通信。

**功能列举:**

这个头文件定义了以下功能，用于用户空间程序与 AMD HSMP 驱动程序进行交互：

1. **消息 ID 定义 (`enum hsmp_message_ids`)**:  定义了各种 HSMP 命令的唯一标识符。这些命令涵盖了监控和控制 AMD 处理器和系统硬件的不同方面，例如：
    * **性能监控**: 获取 CPU 核心利用率、频率限制、温度、功耗等信息。
    * **电源管理**: 设置和获取插槽功耗限制、Boost 限制、电源模式等。
    * **互连管理**:  设置和获取 XGMI 链路宽度、DF P-State 等与处理器内部互连相关的参数。
    * **内存监控**: 获取内存带宽、DIMM 温度和功耗等信息。
    * **系统配置**: 设置 PCI Rate 等。
    * **度量指标**: 获取更详细的硬件性能指标。

2. **消息结构体 (`struct hsmp_message`)**: 定义了用户空间向内核发送 HSMP 命令以及内核返回响应的数据格式。它包含：
    * `msg_id`:  要执行的 HSMP 命令的 ID。
    * `num_args`:  命令参数的数量。
    * `response_sz`:  期望的响应数据大小。
    * `args`:  命令参数数组。
    * `sock_ind`:  插槽索引，用于指定操作的目标处理器插槽。

3. **消息类型枚举 (`enum hsmp_msg_type`)**:  定义了 HSMP 消息的类型，分为 `HSMP_SET` (设置) 和 `HSMP_GET` (获取)。

4. **协议版本枚举 (`enum hsmp_proto_versions`)**: 定义了支持的 HSMP 协议版本。

5. **消息描述表 (`struct hsmp_msg_desc` 和 `hsmp_msg_desc_table`)**:  提供了一个查找表，用于描述每个 HSMP 消息 ID 的属性，例如参数数量、响应大小和消息类型。

6. **度量指标表结构体 (`struct hsmp_metric_table`)**: 定义了一个复杂的数据结构，包含了各种详细的硬件性能和状态指标。

7. **IOCTL 命令定义 (`HSMP_BASE_IOCTL_NR` 和 `HSMP_IOCTL_CMD`)**:  定义了用于与 HSMP 内核驱动程序通信的 ioctl 命令。

**与 Android 功能的关系及举例说明:**

这个头文件定义的接口允许 Android 系统在具有 AMD 处理器的设备上监控和管理硬件资源，从而实现以下功能：

* **性能监控和优化**: Android 系统可以使用这些接口来监控 CPU 核心频率、温度、功耗等信息，并根据这些数据动态调整系统资源，以实现最佳的性能和功耗平衡。例如，`HSMP_GET_C0_PERCENT` 可以用来获取 CPU 核心的空闲时间百分比，从而判断 CPU 的负载情况。

* **电源管理**: Android 的电源管理服务可以使用 `HSMP_SET_SOCKET_POWER_LIMIT` 来限制处理器的最大功耗，以节省电池或防止过热。`HSMP_GET_SOCKET_POWER` 可以用来监控当前的插槽功耗。

* **温度管理**:  通过 `HSMP_GET_PROC_HOT` 可以获取处理器是否过热，从而触发相应的散热措施或降低性能以防止硬件损坏。

* **硬件健康监控**:  可以监控 DIMM 的温度和功耗 (`HSMP_GET_DIMM_TEMP_RANGE`, `HSMP_GET_DIMM_POWER`)，以确保硬件的正常运行。

**libc 函数的功能实现:**

这个头文件本身 **并不定义任何 libc 函数**。它只是定义了与内核通信的数据结构和常量。用户空间的程序（包括 Android 的系统服务或 HAL 组件）通常会使用标准的 libc 函数，例如 `ioctl()`，来与内核驱动程序进行交互。

要使用这些定义，程序需要：

1. **打开设备文件**:  通常是 `/dev` 目录下与 HSMP 驱动程序关联的设备文件。
2. **填充 `hsmp_message` 结构体**:  根据要执行的操作，设置 `msg_id`、参数等。
3. **调用 `ioctl()` 函数**:  使用 `HSMP_IOCTL_CMD` 作为请求参数，并将填充好的 `hsmp_message` 结构体指针传递给 `ioctl()`。
4. **解析响应**:  如果操作是获取信息，内核驱动程序会将结果写回 `hsmp_message` 结构体的 `args` 数组中。

**示例 (伪代码):**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "bionic/libc/kernel/uapi/asm-x86/asm/amd_hsmp.h"

int main() {
    int fd = open("/dev/your_hsmp_device", O_RDWR); // 替换为实际的设备文件路径
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct hsmp_message msg;
    msg.msg_id = HSMP_GET_SOCKET_POWER;
    msg.num_args = 0;
    msg.response_sz = 1; // 假设功率值占用一个 __u32
    msg.sock_ind = 0;    // 假设操作的是第一个插槽

    if (ioctl(fd, HSMP_IOCTL_CMD, &msg) == -1) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    printf("Socket Power: %u\n", msg.args[0]);

    close(fd);
    return 0;
}
```

**dynamic linker 的功能 (间接涉及):**

这个头文件本身与 dynamic linker 没有直接关系。然而，如果 Android 的某个共享库（.so 文件）需要使用 HSMP 功能，那么 dynamic linker 会负责加载这个共享库。

**so 布局样本:**

假设有一个名为 `libhsmp_client.so` 的共享库，它封装了与 HSMP 交互的逻辑。其布局可能如下：

```
libhsmp_client.so:
    .text          # 代码段，包含与 HSMP 交互的函数
    .rodata        # 只读数据段，可能包含 HSMP 相关的常量
    .data          # 可读写数据段
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # 程序链接表
    .got.plt       # 全局偏移量表
    ...
```

**链接的处理过程:**

1. **编译时链接**:  当开发者编译使用了 HSMP 功能的代码时，编译器会将对 `ioctl()` 等 libc 函数的调用记录在可执行文件或共享库的动态符号表中。
2. **加载时链接**: 当 Android 系统加载使用了 `libhsmp_client.so` 的进程时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会执行以下步骤：
    * **加载共享库**:  将 `libhsmp_client.so` 加载到进程的地址空间。
    * **符号解析**:  根据共享库的动态符号表，找到需要的外部符号（例如 `ioctl`）。
    * **重定位**:  修改代码段和数据段中的地址，使其指向 `ioctl` 函数在 libc.so 中的实际地址。这通常通过 .plt 和 .got.plt 完成。

**假设输入与输出 (基于示例代码):**

**假设输入:**

* 运行上述示例代码。
* HSMP 驱动程序正常运行，并且能够获取插槽功耗信息。

**预期输出:**

```
Socket Power: <一个表示当前插槽功耗的数字>
```

实际输出的数字取决于 AMD 处理器的当前功耗状态。

**用户或编程常见的使用错误:**

1. **错误的设备文件路径**:  如果 `open()` 函数打开的设备文件路径不正确，会导致程序无法与 HSMP 驱动程序通信。
2. **错误的 `msg_id`**:  使用了不存在或不支持的 `msg_id` 会导致内核返回错误。
3. **参数数量或大小不匹配**:  如果 `num_args` 或 `response_sz` 与实际需要的参数数量或响应大小不符，可能导致数据错误或内核崩溃。
4. **权限问题**:  用户空间程序可能没有足够的权限访问 HSMP 驱动程序的设备文件。
5. **内核驱动程序未加载**: 如果 HSMP 驱动程序没有被加载到内核中，尝试与它通信将失败。
6. **假设返回值总是有效**:  `ioctl()` 调用可能失败，程序需要检查返回值并处理错误情况。

**Android framework 或 ndk 如何一步步的到达这里:**

假设一个 Android 系统服务需要获取 CPU 功耗信息：

1. **Android Framework (Java 代码)**: 系统服务（例如 PowerManagerService）可能会调用 native 方法，这些 native 方法通过 JNI (Java Native Interface) 与 NDK 代码交互。
2. **NDK 代码 (C/C++)**: NDK 代码会使用标准的 POSIX API，例如 `open()` 和 `ioctl()`，来与内核进行通信。
3. **打开设备文件**: NDK 代码会打开与 HSMP 驱动程序关联的设备文件，通常位于 `/dev` 目录下。这个设备文件的名字可能类似于 `amd_hsmp` 或具有类似的命名规则。
4. **构建 `hsmp_message`**: NDK 代码会创建一个 `hsmp_message` 结构体实例，并设置 `msg_id` 为 `HSMP_GET_SOCKET_POWER`，设置其他必要的参数，例如插槽索引。
5. **调用 `ioctl()`**: NDK 代码会调用 `ioctl(fd, HSMP_IOCTL_CMD, &msg)`，其中 `fd` 是打开的设备文件描述符，`HSMP_IOCTL_CMD` 是定义的 ioctl 命令，`&msg` 是指向构建好的 `hsmp_message` 结构体的指针。
6. **内核处理**: Linux 内核接收到 ioctl 请求后，HSMP 驱动程序会处理该请求，读取硬件寄存器以获取插槽功耗信息，并将结果写回到 `msg.args` 中。
7. **返回结果**: `ioctl()` 调用返回，NDK 代码可以从 `msg.args` 中读取功耗值。
8. **传递回 Framework**: NDK 代码通过 JNI 将获取到的功耗值传递回 Java 代码的 PowerManagerService。
9. **Framework 使用**: PowerManagerService 可以使用这些信息来制定电源管理策略，例如调整 CPU 频率或限制功耗。

**Frida hook 示例调试步骤:**

假设你想 hook `ioctl` 调用来查看 Android 系统如何使用 HSMP 获取插槽功耗。

**Frida hook 脚本 (JavaScript):**

```javascript
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();
    const argp = args[2];

    // 检查是否是与 HSMP 相关的 ioctl 命令
    if (request === 0xf800) { // HSMP_IOCTL_CMD 的值 (需要根据实际定义计算)
      console.log("ioctl called with HSMP_IOCTL_CMD");
      console.log("File Descriptor:", fd);

      // 读取 hsmp_message 结构体
      const hsmp_msg = argp.readByteArray(20); // sizeof(struct hsmp_message)

      // 解析 hsmp_message (需要手动解析结构体字段)
      const msg_id = ArrayBuffer.wrap(hsmp_msg.slice(0, 4)).getInt32(0, true);
      const num_args = ArrayBuffer.wrap(hsmp_msg.slice(4, 6)).getInt16(0, true);
      const response_sz = ArrayBuffer.wrap(hsmp_msg.slice(6, 8)).getInt16(0, true);
      const sock_ind = ArrayBuffer.wrap(hsmp_msg.slice(16, 20)).getInt16(0, true);

      console.log("HSMP Message ID:", msg_id);
      console.log("Number of Arguments:", num_args);
      console.log("Response Size:", response_sz);
      console.log("Socket Index:", sock_ind);

      // 如果是获取插槽功耗的命令
      if (msg_id === 4) { // HSMP_GET_SOCKET_POWER 的值
        console.log("Getting Socket Power...");
      }
    }
  },
  onLeave: function (retval) {
    // 可以检查 ioctl 的返回值
    if (retval.toInt32() === 0) {
      console.log("ioctl call successful");
    } else {
      console.log("ioctl call failed with error:", retval);
    }
  },
});
```

**调试步骤:**

1. **找到目标进程**:  确定你想要监控的进程，例如 PowerManagerService 的进程 ID。
2. **运行 Frida**:  使用 Frida 连接到目标进程：`frida -U -f <目标进程包名或进程名> -l your_script.js --no-pause` 或 `frida -p <进程ID> -l your_script.js`。
3. **观察输出**:  当目标进程调用 `ioctl` 并且 `request` 参数与 `HSMP_IOCTL_CMD` 的值匹配时，Frida 脚本会输出相关信息，包括文件描述符、HSMP 消息 ID 和其他参数。
4. **分析数据**:  通过分析输出的 HSMP 消息 ID，你可以确定哪些 Android 组件正在使用 HSMP 的哪些功能。例如，如果看到 `HSMP Message ID: 4`，则表示正在获取插槽功耗。
5. **进一步分析**:  你可以根据需要修改 Frida 脚本来读取和解析 `hsmp_message` 结构体中的更多字段，例如参数和响应数据。

**注意:**

* 上述 Frida 脚本需要根据实际环境中 `HSMP_IOCTL_CMD` 和 `HSMP_GET_SOCKET_POWER` 的枚举值进行调整。你可以通过查看内核头文件或者反编译相关的共享库来获取这些值。
* Hook 系统调用可能需要 root 权限。
* 解析二进制数据需要仔细处理字节序和数据类型。

通过以上分析，我们可以了解到 `bionic/libc/kernel/uapi/asm-x86/asm/amd_hsmp.h` 头文件在 Android 系统中扮演着连接用户空间和 AMD HSMP 驱动程序的关键角色，为 Android 系统提供了监控和管理 AMD 处理器硬件的能力。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-x86/asm/amd_hsmp.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_ASM_X86_AMD_HSMP_H_
#define _UAPI_ASM_X86_AMD_HSMP_H_
#include <linux/types.h>
#pragma pack(4)
#define HSMP_MAX_MSG_LEN 8
enum hsmp_message_ids {
  HSMP_TEST = 1,
  HSMP_GET_SMU_VER,
  HSMP_GET_PROTO_VER,
  HSMP_GET_SOCKET_POWER,
  HSMP_SET_SOCKET_POWER_LIMIT,
  HSMP_GET_SOCKET_POWER_LIMIT,
  HSMP_GET_SOCKET_POWER_LIMIT_MAX,
  HSMP_SET_BOOST_LIMIT,
  HSMP_SET_BOOST_LIMIT_SOCKET,
  HSMP_GET_BOOST_LIMIT,
  HSMP_GET_PROC_HOT,
  HSMP_SET_XGMI_LINK_WIDTH,
  HSMP_SET_DF_PSTATE,
  HSMP_SET_AUTO_DF_PSTATE,
  HSMP_GET_FCLK_MCLK,
  HSMP_GET_CCLK_THROTTLE_LIMIT,
  HSMP_GET_C0_PERCENT,
  HSMP_SET_NBIO_DPM_LEVEL,
  HSMP_GET_NBIO_DPM_LEVEL,
  HSMP_GET_DDR_BANDWIDTH,
  HSMP_GET_TEMP_MONITOR,
  HSMP_GET_DIMM_TEMP_RANGE,
  HSMP_GET_DIMM_POWER,
  HSMP_GET_DIMM_THERMAL,
  HSMP_GET_SOCKET_FREQ_LIMIT,
  HSMP_GET_CCLK_CORE_LIMIT,
  HSMP_GET_RAILS_SVI,
  HSMP_GET_SOCKET_FMAX_FMIN,
  HSMP_GET_IOLINK_BANDWITH,
  HSMP_GET_XGMI_BANDWITH,
  HSMP_SET_GMI3_WIDTH,
  HSMP_SET_PCI_RATE,
  HSMP_SET_POWER_MODE,
  HSMP_SET_PSTATE_MAX_MIN,
  HSMP_GET_METRIC_TABLE_VER,
  HSMP_GET_METRIC_TABLE,
  HSMP_GET_METRIC_TABLE_DRAM_ADDR,
  HSMP_MSG_ID_MAX,
};
struct hsmp_message {
  __u32 msg_id;
  __u16 num_args;
  __u16 response_sz;
  __u32 args[HSMP_MAX_MSG_LEN];
  __u16 sock_ind;
};
enum hsmp_msg_type {
  HSMP_RSVD = - 1,
  HSMP_SET = 0,
  HSMP_GET = 1,
};
enum hsmp_proto_versions {
  HSMP_PROTO_VER2 = 2,
  HSMP_PROTO_VER3,
  HSMP_PROTO_VER4,
  HSMP_PROTO_VER5,
  HSMP_PROTO_VER6
};
struct hsmp_msg_desc {
  int num_args;
  int response_sz;
  enum hsmp_msg_type type;
};
static const struct hsmp_msg_desc hsmp_msg_desc_table[] = {
 {
    0, 0, HSMP_RSVD
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    0, 0, HSMP_SET
  }
 , {
    0, 2, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    1, 1, HSMP_GET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    1, 1, HSMP_SET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    1, 0, HSMP_SET
  }
 , {
    0, 1, HSMP_GET
  }
 , {
    0, 0, HSMP_GET
  }
 , {
    0, 2, HSMP_GET
  }
 ,
};
struct hsmp_metric_table {
  __u32 accumulation_counter;
  __u32 max_socket_temperature;
  __u32 max_vr_temperature;
  __u32 max_hbm_temperature;
  __u64 max_socket_temperature_acc;
  __u64 max_vr_temperature_acc;
  __u64 max_hbm_temperature_acc;
  __u32 socket_power_limit;
  __u32 max_socket_power_limit;
  __u32 socket_power;
  __u64 timestamp;
  __u64 socket_energy_acc;
  __u64 ccd_energy_acc;
  __u64 xcd_energy_acc;
  __u64 aid_energy_acc;
  __u64 hbm_energy_acc;
  __u32 cclk_frequency_limit;
  __u32 gfxclk_frequency_limit;
  __u32 fclk_frequency;
  __u32 uclk_frequency;
  __u32 socclk_frequency[4];
  __u32 vclk_frequency[4];
  __u32 dclk_frequency[4];
  __u32 lclk_frequency[4];
  __u64 gfxclk_frequency_acc[8];
  __u64 cclk_frequency_acc[96];
  __u32 max_cclk_frequency;
  __u32 min_cclk_frequency;
  __u32 max_gfxclk_frequency;
  __u32 min_gfxclk_frequency;
  __u32 fclk_frequency_table[4];
  __u32 uclk_frequency_table[4];
  __u32 socclk_frequency_table[4];
  __u32 vclk_frequency_table[4];
  __u32 dclk_frequency_table[4];
  __u32 lclk_frequency_table[4];
  __u32 max_lclk_dpm_range;
  __u32 min_lclk_dpm_range;
  __u32 xgmi_width;
  __u32 xgmi_bitrate;
  __u64 xgmi_read_bandwidth_acc[8];
  __u64 xgmi_write_bandwidth_acc[8];
  __u32 socket_c0_residency;
  __u32 socket_gfx_busy;
  __u32 dram_bandwidth_utilization;
  __u64 socket_c0_residency_acc;
  __u64 socket_gfx_busy_acc;
  __u64 dram_bandwidth_acc;
  __u32 max_dram_bandwidth;
  __u64 dram_bandwidth_utilization_acc;
  __u64 pcie_bandwidth_acc[4];
  __u32 prochot_residency_acc;
  __u32 ppt_residency_acc;
  __u32 socket_thm_residency_acc;
  __u32 vr_thm_residency_acc;
  __u32 hbm_thm_residency_acc;
  __u32 spare;
  __u32 gfxclk_frequency[8];
};
#pragma pack()
#define HSMP_BASE_IOCTL_NR 0xF8
#define HSMP_IOCTL_CMD _IOWR(HSMP_BASE_IOCTL_NR, 0, struct hsmp_message)
#endif
```