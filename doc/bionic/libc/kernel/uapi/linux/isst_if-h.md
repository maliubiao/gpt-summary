Response:
Let's break down the thought process for analyzing this header file.

1. **Understanding the Context:** The initial prompt provides crucial context: `bionic/libc/kernel/uapi/linux/isst_if.handroid`. This tells us several things:
    * **Bionic:**  It's part of Android's core C library. This immediately suggests it's a low-level interface, likely interacting directly with the kernel.
    * **`libc/kernel`:**  Confirms the kernel interaction. It's a header file defining structures used to communicate with a kernel module or subsystem.
    * **`uapi`:**  Stands for "userspace API." This signifies that these definitions are meant for use by programs running in user space, not directly within the kernel.
    * **`linux`:**  Specifies the target operating system kernel.
    * **`isst_if.h`:** The filename itself hints at the purpose: "Intel Speed Shift Technology Interface." The "if" likely means "interface."  The `.handroid` suffix is a bionic convention for kernel headers.

2. **High-Level Analysis (First Pass):**  A quick scan of the file reveals a series of `struct` definitions and `#define` macros. This strongly suggests it's defining a set of data structures and commands for interacting with a specific kernel feature. The names of the structures (e.g., `isst_if_platform_info`, `isst_if_cpu_map`, `isst_if_mbox_cmd`) provide initial clues about their purpose.

3. **Categorizing Structures:**  As I read through the structs, I start to mentally group them:
    * **System Information:**  Structures like `isst_if_platform_info` likely hold information about the underlying hardware or driver.
    * **CPU Mapping:** `isst_if_cpu_map` and `isst_if_cpu_maps` clearly deal with relating logical and physical CPUs.
    * **Low-Level Access:** `isst_if_io_reg`, `isst_if_io_regs`, `isst_if_msr_cmd`, `isst_if_msr_cmds` point to direct hardware access (IO ports and Model Specific Registers).
    * **Mailbox Commands:**  `isst_if_mbox_cmd` and `isst_if_mbox_cmds` suggest a command/response mechanism, possibly for controlling the ISST feature.
    * **Power Management/Frequency Control:** A large number of structs (`isst_core_power`, `isst_clos_param`, `isst_if_clos_assoc`, `isst_tpmi_instance_count`, `isst_perf_level_info`, etc.) are clearly related to managing CPU power states, frequencies, and performance levels.
    * **Detailed Performance Data:** Structures like `isst_perf_level_data_info`, `isst_base_freq_info`, and `isst_turbo_freq_info` are for querying detailed information about performance levels and frequencies.

4. **Analyzing the Macros:** The `#define` macros with the `ISST_IF_` prefix are clearly defining ioctl command codes. The structure names within the `_IOR`, `_IOW`, and `_IOWR` macros confirm the purpose of each ioctl and the associated data structure used for communication. The `ISST_IF_MAGIC` value acts as a unique identifier for this specific interface.

5. **Connecting to Android:**  Knowing this is part of Bionic, I start thinking about *how* Android would use this. Power management and performance are critical for mobile devices. Features like dynamic frequency scaling, core parking, and thermal management are essential for battery life and responsiveness. This header likely provides a low-level interface for Android's power management services to interact with the CPU's ISST features.

6. **Considering the "Why":**  Why would Android need direct access like this?  The standard Linux power management framework might not offer the fine-grained control needed for optimal performance and power efficiency on Android devices. ISST provides more specific, hardware-level control.

7. **Hypothesizing Usage Scenarios:** I start imagining how the different structures and ioctls would be used:
    * **Getting Platform Info:** An Android service might call `ioctl` with `ISST_IF_GET_PLATFORM_INFO` to check if the ISST driver is present and what capabilities it offers.
    * **Reading MSRs:**  For debugging or advanced power management, the system might use `ISST_IF_MSR_COMMAND` to read specific Model Specific Registers.
    * **Setting Performance Levels:**  The Android framework could use `ISST_IF_PERF_SET_LEVEL` to adjust the CPU's performance level based on the device's power state or the current application's needs.

8. **Considering Potential Errors:**  What could go wrong?
    * **Incorrect `ioctl` calls:** Passing the wrong size or type of data to `ioctl`.
    * **Invalid parameters:** Sending out-of-range values in the structures.
    * **Driver not loaded:** Trying to use the interface when the ISST kernel module isn't loaded.
    * **Permissions issues:**  Not having the necessary permissions to access the device file associated with the ISST driver.

9. **Thinking about Frida Hooking:** How could we observe this in action? Frida can intercept system calls like `ioctl`. We'd need to identify the device file being used (likely under `/dev`) and then hook the `ioctl` call, filtering for the `ISST_IF_MAGIC` to target the relevant interactions. We'd then need to parse the arguments to understand which specific command is being sent and the data being exchanged.

10. **Structuring the Answer:**  Finally, I organize the information into the requested sections: functionality, relationship to Android, libc function details (acknowledging they're mostly data structures), dynamic linker (not applicable here), assumptions and outputs, common errors, and the Android framework/NDK path with Frida example. I try to provide concrete examples to illustrate the concepts.

This iterative process of reading, categorizing, connecting to the context, hypothesizing, and considering potential issues allows for a comprehensive understanding of the header file's purpose and how it fits into the broader Android ecosystem.
这个C头文件 `isst_if.h` 定义了用户空间程序与Linux内核中 Intel Speed Shift Technology (ISST) 驱动程序通信的接口。它位于 Android 的 Bionic C 库中，说明 Android 系统会利用 ISST 技术。

**功能列举:**

这个头文件定义了一系列数据结构和宏，用于执行以下操作：

1. **获取平台信息:**  获取 ISST 驱动和硬件平台的相关信息，例如 API 版本、驱动版本、每次 ioctl 调用允许的最大命令数、是否支持邮箱 (mailbox) 和内存映射 I/O (MMIO)。
2. **CPU 映射:**  获取逻辑 CPU 和物理 CPU 的对应关系。
3. **I/O 寄存器访问:**  读写 CPU 的 I/O 寄存器。
4. **邮箱命令:**  向 ISST 驱动发送 mailbox 命令并接收响应。
5. **MSR 访问:**  读写 CPU 的 Model Specific Registers (MSR)。
6. **TPMI 实例计数:** 获取每个 Socket 上 TPMI (Telemetry Provider Management Interface) 实例的数量。
7. **核心电源状态控制:** 获取和设置 CPU 核心的电源状态。
8. **CLOS 参数控制:** 获取和设置 CPU 的 CLOS (Cache Allocation Technology/Code and Data Prioritization) 参数，用于控制缓存分配和优先级。
9. **CLOS 关联:**  获取和设置逻辑 CPU 与 CLOS 的关联关系。
10. **性能等级信息:** 获取 CPU 支持的性能等级信息，例如最大等级、特性修订、当前等级、是否锁定和启用等。
11. **性能等级控制:** 设置 CPU 的性能等级。
12. **性能特性控制:**  启用或禁用特定的性能特性。
13. **详细性能等级信息:** 获取更详细的性能等级数据，例如 TDP、频率、温度等。
14. **性能等级 CPU 掩码:** 获取特定性能等级下启用的 CPU 核心掩码。
15. **基本频率信息:** 获取 CPU 的基本频率信息。
16. **Turbo 频率信息:** 获取 CPU 的 Turbo 频率信息。

**与 Android 功能的关系及举例说明:**

ISST (Intel Speed Shift Technology) 是一项 CPU 技术，允许操作系统更精细地控制 CPU 的频率和电压，从而提高性能和能源效率。Android 系统利用这项技术来优化设备的性能和电池寿命。

**举例说明:**

* **动态频率调整 (Dynamic Frequency Scaling, DFS):** Android 框架可以利用这些接口，根据当前的负载动态调整 CPU 的频率。例如，当用户运行高负载的应用或游戏时，Android 可以通过 `ISST_IF_PERF_SET_LEVEL` 接口提高 CPU 的性能等级，以获得更好的响应速度。当设备空闲时，可以降低性能等级以节省电量。
* **电源管理:**  Android 的电源管理服务可以使用 `ISST_IF_CORE_POWER_STATE` 来控制 CPU 核心的电源状态，例如在低功耗模式下关闭部分核心。
* **热管理:**  通过读取详细的性能等级信息 (`ISST_IF_GET_PERF_LEVEL_INFO`)，Android 可以监测 CPU 的温度和功耗，并采取相应的措施，例如降低频率，以防止过热。
* **任务调度和资源分配:**  CLOS 相关的功能 (`ISST_IF_CLOS_PARAM`, `ISST_IF_CLOS_ASSOC`) 可以帮助 Android 更有效地管理缓存资源，例如为前台应用分配更多的缓存，从而提高其性能。

**libc 函数的功能及实现:**

这个头文件本身并没有定义 C 函数的实现。它只是定义了数据结构和宏。这些结构体会被 Android 系统中的其他 C 代码使用，通常是通过 `ioctl` 系统调用与内核驱动程序进行交互。

`ioctl` 函数是 Linux 系统中用于设备特定操作的系统调用。其基本用法如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`:  文件描述符，通常是打开的设备文件的文件描述符。
* `request`:  一个设备特定的请求码，通常使用宏定义，例如这里定义的 `ISST_IF_GET_PLATFORM_INFO` 等。
* `...`:  可选的参数，通常是指向数据结构的指针，用于向内核传递数据或接收内核返回的数据。

例如，要获取平台信息，Android 系统可能会执行以下操作：

1. 打开 ISST 驱动的设备文件，例如 `/dev/isst_driver` (实际路径可能不同)。
2. 定义一个 `isst_if_platform_info` 结构体变量。
3. 调用 `ioctl` 函数，传入设备文件的文件描述符、`ISST_IF_GET_PLATFORM_INFO` 请求码以及 `isst_if_platform_info` 结构体变量的地址。
4. 内核驱动程序会填充 `isst_if_platform_info` 结构体，`ioctl` 调用返回后，用户空间程序就可以读取其中的信息。

**dynamic linker 的功能 (不适用):**

这个头文件主要定义了内核接口，与 dynamic linker (动态链接器) 的功能没有直接关系。Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 负责在程序运行时加载和链接共享库 (.so 文件)。  这个头文件定义的数据结构不是用来在进程之间共享代码或数据的，而是用于与内核驱动通信。

**逻辑推理、假设输入与输出 (基于 `ioctl` 调用):**

假设一个 Android 服务想要获取 ISST 驱动的平台信息。

**假设输入:**

* 打开 ISST 驱动的设备文件 `/dev/isst_driver` 成功，返回文件描述符 `fd`。
* 定义了一个 `isst_if_platform_info` 结构体变量 `platform_info`。

**ioctl 调用:**

```c
int ret = ioctl(fd, ISST_IF_GET_PLATFORM_INFO, &platform_info);
```

**假设输出 (如果调用成功):**

* `ret` 的值为 0，表示调用成功。
* `platform_info` 结构体的成员被内核驱动程序填充，例如：
    * `platform_info.api_version` 可能为 `0x0100` (表示 API 版本 1.0)。
    * `platform_info.driver_version` 可能为 `0x0200` (表示驱动版本 2.0)。
    * `platform_info.max_cmds_per_ioctl` 可能为 `16`。
    * `platform_info.mbox_supported` 可能为 `1` (表示支持 mailbox)。
    * `platform_info.mmio_supported` 可能为 `0` (表示不支持 MMIO)。

**用户或编程常见的使用错误:**

1. **传递错误的结构体大小:**  虽然 `ioctl` 通常会检查一些基本的大小，但如果传递的结构体大小与内核驱动期望的不符，可能会导致数据损坏或程序崩溃。
2. **使用错误的 ioctl 请求码:**  使用错误的请求码会导致内核执行错误的操作或者返回错误的数据。
3. **在错误的上下文调用:**  某些 ioctl 调用可能需要在特定的权限或上下文下才能调用成功。
4. **忘记检查 `ioctl` 的返回值:** `ioctl` 调用失败时会返回 -1，并设置 `errno`。没有正确检查返回值会导致程序在错误的情况下继续执行。
5. **并发访问冲突:** 如果多个进程或线程同时尝试访问 ISST 驱动，可能会导致数据竞争或死锁。需要适当的同步机制。
6. **设备文件未打开或打开失败:** 在调用 `ioctl` 之前必须成功打开设备文件。

**举例说明错误:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/isst_if.h> // 假设头文件路径正确

int main() {
    int fd = open("/dev/isst_driver", O_RDWR);
    if (fd == -1) {
        perror("open /dev/isst_driver failed");
        return 1;
    }

    struct isst_if_platform_info platform_info;

    // 错误示例：使用错误的 ioctl 请求码
    int ret = ioctl(fd, ISST_IF_CORE_POWER_STATE, &platform_info);
    if (ret == -1) {
        perror("ioctl failed"); // 可能会输出 "ioctl failed: Inappropriate ioctl for device"
    }

    close(fd);
    return 0;
}
```

**Android framework 或 NDK 如何到达这里，给出 frida hook 示例调试这些步骤:**

1. **Android Framework 层:** Android 的 power manager 服务或 system server 中的相关模块可能需要获取或设置 CPU 的性能状态。这些服务通常使用 Java 代码，并通过 JNI (Java Native Interface) 调用到底层的 C/C++ 代码。

2. **Native 代码层 (Bionic/NDK):** 在 Bionic 库或 NDK 提供的库中，会有 C/C++ 代码调用 `open` 打开 ISST 驱动的设备文件，然后使用 `ioctl` 系统调用，并传递这个头文件中定义的数据结构和宏。

3. **Kernel 驱动层:** Linux 内核中的 ISST 驱动程序会接收到 `ioctl` 调用，根据请求码执行相应的操作，例如读取硬件寄存器或更新 CPU 的配置。

**Frida Hook 示例:**

假设我们想观察 Android 系统何时以及如何获取 ISST 平台信息。我们可以使用 Frida hook `ioctl` 系统调用，并过滤出与 ISST 相关的调用。

首先，需要找到打开 ISST 驱动设备文件的路径。这可能需要一些逆向或分析。假设设备文件路径是 `/dev/isst_driver`。

**Frida Hook 脚本 (Python):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.android.systemui"]) # 或者你想要监控的进程
    process = device.attach(pid)
    device.resume(pid)

    script_code = """
    const ISST_IF_MAGIC = 0xFE;
    const ISST_IF_GET_PLATFORM_INFO = _IOR(ISST_IF_MAGIC, 0, 0); // 第三个参数是大小，这里可以忽略或使用0

    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();

            // 检查是否是打开 ISST 驱动的文件描述符 (需要找到打开时的路径)
            const pathBuf = Memory.allocUtf8String(256);
            const pathLen = recvSync('get_path', fd).wait().data['path'].length;
            if (pathLen > 0) {
                const path = recvSync('get_path', fd).wait().data['path'];
                if (path.includes("/dev/isst_driver")) {
                    if (request === ISST_IF_GET_PLATFORM_INFO) {
                        send({type: "info", payload: "ioctl called with ISST_IF_GET_PLATFORM_INFO"});
                        // 你可以进一步读取 args[2] 指向的内存，解析 struct isst_if_platform_info
                    }
                }
            }
        }
    });

    // Helper function to get file path from fd (requires additional setup)
    function getFilePathFromFd(fd) {
        try {
            const buf = Memory.allocUtf8String(256);
            const ret = syscall(265, fd, buf, 256); // SYS_readlinkat with /proc/self/fd/
            if (ret > 0) {
                return buf.readUtf8String();
            }
        } catch (e) {
            // Handle errors
        }
        return null;
    }

    // Send message to Python to get the path of the file descriptor
    recv('get_path', function(hooked_fd) {
        const path = getFilePathFromFd(hooked_fd.data);
        send({type: 'path', fd: hooked_fd.data, path: path});
    });
    """

    script = process.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()

except Exception as e:
    print(e)
```

**解释 Frida Hook 脚本:**

1. **`frida.get_usb_device()` 和 `device.spawn()`/`device.attach()`:** 连接到 USB 设备并附加到目标进程 (这里以 `com.android.systemui` 为例，实际需要根据情况调整)。
2. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  Hook `ioctl` 系统调用。
3. **`onEnter: function(args)`:** 在 `ioctl` 调用进入时执行的函数。
4. **`args[0]` 和 `args[1]`:** 分别是文件描述符和请求码。
5. **`ISST_IF_GET_PLATFORM_INFO` 常量:** 定义了 `ISST_IF_GET_PLATFORM_INFO` 的值。
6. **路径检查:**  需要一种方法来判断 `ioctl` 的文件描述符是否对应于 ISST 驱动的设备文件。这通常需要一些辅助方法来获取文件描述符对应的路径。示例代码中提供了一个 `getFilePathFromFd` 函数的框架，但实际实现可能需要根据 Android 系统的具体情况进行调整，例如读取 `/proc/pid/fd/` 目录。
7. **请求码匹配:** 检查 `ioctl` 的请求码是否为 `ISST_IF_GET_PLATFORM_INFO`。
8. **`send()`:**  将信息发送到 Frida 客户端 (Python 脚本)。
9. **解析参数:** 可以进一步读取 `args[2]` 指向的内存，并根据 `isst_if_platform_info` 结构体的定义解析其中的数据。

**请注意:**

* **设备文件路径:** `/dev/isst_driver` 只是一个假设的路径，实际路径可能不同。你需要通过逆向或其他方法找到正确的路径。
* **权限:**  运行 Frida 脚本可能需要 root 权限。
* **目标进程:**  你需要选择正确的 Android 进程进行 hook，这取决于哪个进程会调用 ISST 相关的接口。
* **错误处理:**  Frida 脚本中需要添加适当的错误处理。
* **`_IOR` 宏:**  在 Frida JavaScript 中需要手动计算 `_IOR` 宏的值，或者使用其他方式获取请求码。

通过这个 Frida Hook 示例，你可以动态地观察 Android 系统中哪些进程在调用 ISST 相关的 `ioctl` 命令，以及传递的具体参数，从而深入了解 Android 如何利用 ISST 技术。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/isst_if.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __ISST_IF_H
#define __ISST_IF_H
#include <linux/types.h>
struct isst_if_platform_info {
  __u16 api_version;
  __u16 driver_version;
  __u16 max_cmds_per_ioctl;
  __u8 mbox_supported;
  __u8 mmio_supported;
};
struct isst_if_cpu_map {
  __u32 logical_cpu;
  __u32 physical_cpu;
};
struct isst_if_cpu_maps {
  __u32 cmd_count;
  struct isst_if_cpu_map cpu_map[1];
};
struct isst_if_io_reg {
  __u32 read_write;
  __u32 logical_cpu;
  __u32 reg;
  __u32 value;
};
struct isst_if_io_regs {
  __u32 req_count;
  struct isst_if_io_reg io_reg[1];
};
struct isst_if_mbox_cmd {
  __u32 logical_cpu;
  __u32 parameter;
  __u32 req_data;
  __u32 resp_data;
  __u16 command;
  __u16 sub_command;
  __u32 reserved;
};
struct isst_if_mbox_cmds {
  __u32 cmd_count;
  struct isst_if_mbox_cmd mbox_cmd[1];
};
struct isst_if_msr_cmd {
  __u32 read_write;
  __u32 logical_cpu;
  __u64 msr;
  __u64 data;
};
struct isst_if_msr_cmds {
  __u32 cmd_count;
  struct isst_if_msr_cmd msr_cmd[1];
};
struct isst_core_power {
  __u8 get_set;
  __u8 socket_id;
  __u8 power_domain_id;
  __u8 enable;
  __u8 supported;
  __u8 priority_type;
};
struct isst_clos_param {
  __u8 get_set;
  __u8 socket_id;
  __u8 power_domain_id;
  __u8 clos;
  __u16 min_freq_mhz;
  __u16 max_freq_mhz;
  __u8 prop_prio;
};
struct isst_if_clos_assoc {
  __u8 socket_id;
  __u8 power_domain_id;
  __u16 logical_cpu;
  __u16 clos;
};
struct isst_if_clos_assoc_cmds {
  __u16 cmd_count;
  __u16 get_set;
  __u16 punit_cpu_map;
  struct isst_if_clos_assoc assoc_info[1];
};
struct isst_tpmi_instance_count {
  __u8 socket_id;
  __u8 count;
  __u16 valid_mask;
};
struct isst_perf_level_info {
  __u8 socket_id;
  __u8 power_domain_id;
  __u8 max_level;
  __u8 feature_rev;
  __u8 level_mask;
  __u8 current_level;
  __u8 feature_state;
  __u8 locked;
  __u8 enabled;
  __u8 sst_tf_support;
  __u8 sst_bf_support;
};
struct isst_perf_level_control {
  __u8 socket_id;
  __u8 power_domain_id;
  __u8 level;
};
struct isst_perf_feature_control {
  __u8 socket_id;
  __u8 power_domain_id;
  __u8 feature;
};
#define TRL_MAX_BUCKETS 8
#define TRL_MAX_LEVELS 6
struct isst_perf_level_data_info {
  __u8 socket_id;
  __u8 power_domain_id;
  __u16 level;
  __u16 tdp_ratio;
  __u16 base_freq_mhz;
  __u16 base_freq_avx2_mhz;
  __u16 base_freq_avx512_mhz;
  __u16 base_freq_amx_mhz;
  __u16 thermal_design_power_w;
  __u16 tjunction_max_c;
  __u16 max_memory_freq_mhz;
  __u16 cooling_type;
  __u16 p0_freq_mhz;
  __u16 p1_freq_mhz;
  __u16 pn_freq_mhz;
  __u16 pm_freq_mhz;
  __u16 p0_fabric_freq_mhz;
  __u16 p1_fabric_freq_mhz;
  __u16 pn_fabric_freq_mhz;
  __u16 pm_fabric_freq_mhz;
  __u16 max_buckets;
  __u16 max_trl_levels;
  __u16 bucket_core_counts[TRL_MAX_BUCKETS];
  __u16 trl_freq_mhz[TRL_MAX_LEVELS][TRL_MAX_BUCKETS];
};
struct isst_perf_level_cpu_mask {
  __u8 socket_id;
  __u8 power_domain_id;
  __u8 level;
  __u8 punit_cpu_map;
  __u64 mask;
  __u16 cpu_buffer_size;
  __s8 cpu_buffer[1];
};
struct isst_base_freq_info {
  __u8 socket_id;
  __u8 power_domain_id;
  __u16 level;
  __u16 high_base_freq_mhz;
  __u16 low_base_freq_mhz;
  __u16 tjunction_max_c;
  __u16 thermal_design_power_w;
};
struct isst_turbo_freq_info {
  __u8 socket_id;
  __u8 power_domain_id;
  __u16 level;
  __u16 max_clip_freqs;
  __u16 max_buckets;
  __u16 max_trl_levels;
  __u16 lp_clip_freq_mhz[TRL_MAX_LEVELS];
  __u16 bucket_core_counts[TRL_MAX_BUCKETS];
  __u16 trl_freq_mhz[TRL_MAX_LEVELS][TRL_MAX_BUCKETS];
};
#define ISST_IF_MAGIC 0xFE
#define ISST_IF_GET_PLATFORM_INFO _IOR(ISST_IF_MAGIC, 0, struct isst_if_platform_info *)
#define ISST_IF_GET_PHY_ID _IOWR(ISST_IF_MAGIC, 1, struct isst_if_cpu_map *)
#define ISST_IF_IO_CMD _IOW(ISST_IF_MAGIC, 2, struct isst_if_io_regs *)
#define ISST_IF_MBOX_COMMAND _IOWR(ISST_IF_MAGIC, 3, struct isst_if_mbox_cmds *)
#define ISST_IF_MSR_COMMAND _IOWR(ISST_IF_MAGIC, 4, struct isst_if_msr_cmds *)
#define ISST_IF_COUNT_TPMI_INSTANCES _IOR(ISST_IF_MAGIC, 5, struct isst_tpmi_instance_count *)
#define ISST_IF_CORE_POWER_STATE _IOWR(ISST_IF_MAGIC, 6, struct isst_core_power *)
#define ISST_IF_CLOS_PARAM _IOWR(ISST_IF_MAGIC, 7, struct isst_clos_param *)
#define ISST_IF_CLOS_ASSOC _IOWR(ISST_IF_MAGIC, 8, struct isst_if_clos_assoc_cmds *)
#define ISST_IF_PERF_LEVELS _IOWR(ISST_IF_MAGIC, 9, struct isst_perf_level_info *)
#define ISST_IF_PERF_SET_LEVEL _IOW(ISST_IF_MAGIC, 10, struct isst_perf_level_control *)
#define ISST_IF_PERF_SET_FEATURE _IOW(ISST_IF_MAGIC, 11, struct isst_perf_feature_control *)
#define ISST_IF_GET_PERF_LEVEL_INFO _IOR(ISST_IF_MAGIC, 12, struct isst_perf_level_data_info *)
#define ISST_IF_GET_PERF_LEVEL_CPU_MASK _IOR(ISST_IF_MAGIC, 13, struct isst_perf_level_cpu_mask *)
#define ISST_IF_GET_BASE_FREQ_INFO _IOR(ISST_IF_MAGIC, 14, struct isst_base_freq_info *)
#define ISST_IF_GET_BASE_FREQ_CPU_MASK _IOR(ISST_IF_MAGIC, 15, struct isst_perf_level_cpu_mask *)
#define ISST_IF_GET_TURBO_FREQ_INFO _IOR(ISST_IF_MAGIC, 16, struct isst_turbo_freq_info *)
#endif

"""

```