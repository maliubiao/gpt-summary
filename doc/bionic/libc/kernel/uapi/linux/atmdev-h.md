Response:
Let's break down the thought process for generating the comprehensive answer about the `atmdev.h` file.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `atmdev.h` header file within the context of Android's Bionic library. Key areas of interest are: its purpose, relationship to Android, implementation details (specifically for libc functions), dynamic linker involvement, potential usage errors, and how it's accessed from Android framework/NDK.

**2. Initial Analysis of the Header File:**

* **`#ifndef _UAPILINUX_ATMDEV_H` / `#define _UAPILINUX_ATMDEV_H`:**  This is a standard include guard to prevent multiple inclusions. It doesn't directly represent functionality but is important for code correctness.
* **`#include <linux/atmapi.h>` / `#include <linux/atm.h>` / `#include <linux/atmioc.h>`:** This immediately signals that the file is related to Asynchronous Transfer Mode (ATM) networking. The "uapi" in the path suggests it's a user-space interface to kernel functionality.
* **`#define ESI_LEN 6` and other `#define` constants:** These define symbolic constants. The names (e.g., `ATM_OC3_PCR`, `ATM_25_PCR`) strongly suggest ATM-related parameters like Peak Cell Rate (PCR) for different ATM speeds.
* **`struct atm_aal_stats` and `struct atm_dev_stats`:** These structures define how ATM statistics are organized. `aal` likely refers to ATM Adaptation Layers.
* **`#define ATM_GETLINKRATE _IOW('a', ATMIOC_ITF + 1, struct atmif_sioc)` and similar macros:** This is the most crucial part for understanding functionality. The `_IOW` macro hints at ioctl commands. The names (`ATM_GETLINKRATE`, `ATM_GETNAMES`, etc.) clearly indicate operations related to managing ATM devices. The `ATMIOC_ITF`, `ATMIOC_SARCOM`, `ATMIOC_SPECIAL` likely categorize different groups of ioctl commands. The third argument (`struct atmif_sioc`, `struct atm_iobuf`, `int`, `atm_backend_t`) specifies the data structure used with the ioctl.
* **`#define ATM_BACKEND_RAW 0`, `#define ATM_BACKEND_PPP 1`, etc.:**  These define constants for different backend types, indicating different ways ATM can be used (raw, PPP, etc.).
* **`struct atm_iobuf`:** This structure is used for passing data to/from ioctl calls.
* **`struct atm_cirange`:** This structure likely defines the Cell Identifier (CI) range.
* **`#define ATM_SC_RX 1024`, `#define ATM_SC_TX 2048`, etc.:** These constants likely relate to socket control options.
* **`#define ATM_VS_IDLE 0`, `#define ATM_VS_CONNECTED 1`, etc.:** These define states for ATM virtual circuits.

**3. Deriving Functionality:**

Based on the analysis above, the core functionality is clearly about providing a user-space interface to control and monitor ATM devices. This includes:

* **Getting information:** Link rate, names, type, ESI (likely Equipment Serial Identifier), addresses, CI ranges, statistics, loopback status.
* **Setting configuration:** ESI, CI ranges, loopback, socket control options, backend type.
* **Managing addresses:** Adding, deleting, resetting addresses, LECS addresses.
* **Managing parties (connections):** Adding and dropping parties.

**4. Relating to Android:**

The key realization is that while this header file exists in Bionic, **modern Android devices typically don't directly use ATM networking.**  ATM was more prevalent in older infrastructure. Therefore, the direct relevance to typical Android apps is low. However, it's *part of the kernel API* that Bionic exposes, even if it's not commonly used on mobile devices. The connection is more about Bionic mirroring kernel headers than actively using ATM.

**5. Implementation of libc Functions:**

This is where careful reading is needed. The header file itself **does not contain the *implementation* of libc functions.** It only *declares* constants and structures that would be used by functions that interact with the kernel's ATM driver. The actual implementation of functions like `ioctl()` (which is what the `_IOW` macros ultimately translate to) resides elsewhere in Bionic and the kernel.

**6. Dynamic Linker Aspects:**

This header file has **no direct involvement with the dynamic linker.** It defines constants and structures. Dynamic linking is about loading and resolving symbols of shared libraries (`.so` files). This header would be *included* by code that might eventually be part of a shared library, but it doesn't define any dynamic linking behavior itself. The SO layout and linking process are irrelevant to this specific header file.

**7. Logical Reasoning and Examples:**

Since the functionality is primarily about ioctl commands, the reasoning is based on what these commands likely do. For example, `ATM_GETLINKRATE` *implies* a kernel call to retrieve the link speed. The output would be the link speed.

**8. Common Usage Errors:**

The most common errors would stem from using incorrect ioctl codes, passing invalid data structures, or trying to use these functions on systems where the ATM driver is not present or configured.

**9. Android Framework/NDK Path and Frida Hook:**

The path is indirect. Android Framework/NDK would not directly call functions defined by this header. The interaction would likely be through lower-level system calls. The Frida hook example demonstrates how to intercept the `ioctl` system call and check if the `request` argument matches any of the ATM-related ioctl codes defined in the header.

**10. Structuring the Answer:**

The final step is to organize the information logically, using clear headings and explanations. The goal is to provide a comprehensive yet easy-to-understand answer that addresses all aspects of the user's request. This includes acknowledging the limited relevance of ATM in modern Android but still explaining its presence in Bionic.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/linux/atmdev.handroid` 这个头文件。

**功能列举:**

这个头文件定义了与 Linux ATM (Asynchronous Transfer Mode，异步传输模式) 设备驱动交互所需的常量、数据结构和宏。它主要用于用户空间程序与内核中的 ATM 设备驱动进行通信，完成以下功能：

1. **定义 ATM 相关常量:**
   - `ESI_LEN`:  定义 ESI (Equipment Serial Identifier，设备序列号) 的长度。
   - `ATM_OC3_PCR`, `ATM_25_PCR`, `ATM_OC12_PCR`, `ATM_DS3_PCR`: 定义不同 ATM 接口速率的峰值信元速率 (Peak Cell Rate, PCR)。
   - `ATM_BACKEND_RAW`, `ATM_BACKEND_PPP`, `ATM_BACKEND_BR2684`: 定义 ATM 后端类型。
   - `ATM_ITFTYP_LEN`: 定义接口类型字符串的长度。
   - `ATM_LM_NONE` 等: 定义环路模式相关的常量。
   - `ATM_CI_MAX`: 定义最大连接标识符 (Connection Identifier)。
   - `ATM_SC_RX`, `ATM_SC_TX`: 定义套接字控制选项。
   - `ATM_BACKLOG_DEFAULT`: 定义默认的积压队列长度。
   - `ATM_MF_IMMED` 等: 定义修改标志。
   - `ATM_VS_IDLE` 等: 定义虚拟电路状态。

2. **定义 ATM 相关数据结构:**
   - `struct atm_aal_stats`: 定义 ATM 适配层 (AAL) 的统计信息，包括发送 (tx)、发送错误 (tx_err)、接收 (rx)、接收错误 (rx_err) 和接收丢弃 (rx_drop) 的计数。
   - `struct atm_dev_stats`: 定义 ATM 设备的统计信息，包含 AAL0、AAL34 和 AAL5 三种 AAL 类型的统计数据。
   - `struct atm_iobuf`: 定义用于传递数据缓冲区的结构，包含缓冲区长度和指向缓冲区的指针。
   - `struct atm_cirange`: 定义连接标识符 (CI) 的范围，包括 VPI (Virtual Path Identifier，虚路径标识符) 和 VCI (Virtual Channel Identifier，虚通道标识符) 的位数。

3. **定义与 ATM 设备驱动交互的 ioctl 命令:**
   - `ATM_GETLINKRATE`: 获取链路速率。
   - `ATM_GETNAMES`: 获取设备名称。
   - `ATM_GETTYPE`: 获取设备类型。
   - `ATM_GETESI`: 获取设备序列号 (ESI)。
   - `ATM_GETADDR`: 获取 ATM 地址。
   - `ATM_RSTADDR`: 重置 ATM 地址。
   - `ATM_ADDADDR`: 添加 ATM 地址。
   - `ATM_DELADDR`: 删除 ATM 地址。
   - `ATM_GETCIRANGE`: 获取 CI 范围。
   - `ATM_SETCIRANGE`: 设置 CI 范围。
   - `ATM_SETESI`: 设置 ESI。
   - `ATM_SETESIF`: 设置 ESI 标志。
   - `ATM_ADDLECSADDR`: 添加 LECS (LAN Emulation Configuration Server，局域网仿真配置服务器) 地址。
   - `ATM_DELLECSADDR`: 删除 LECS 地址。
   - `ATM_GETLECSADDR`: 获取 LECS 地址。
   - `ATM_GETSTAT`: 获取统计信息。
   - `ATM_GETSTATZ`: 获取并重置统计信息。
   - `ATM_GETLOOP`: 获取环路状态。
   - `ATM_SETLOOP`: 设置环路状态。
   - `ATM_QUERYLOOP`: 查询环路状态。
   - `ATM_SETSC`: 设置特殊控制。
   - `ATM_SETBACKEND`: 设置后端类型。
   - `ATM_NEWBACKENDIF`: 创建新的后端接口。
   - `ATM_ADDPARTY`: 添加连接参与方。
   - `ATM_DROPPARTY`: 移除连接参与方。

**与 Android 功能的关系及举例说明:**

ATM 是一种早期的网络技术，在现代 Android 设备中并不常见。这个头文件存在于 Android 的 Bionic 库中，主要是因为它来源于 Linux 内核的 API。虽然现代 Android 手机和平板电脑通常不直接使用 ATM 网络，但某些特定类型的 Android 设备或运行在特殊网络环境中的设备可能仍然会涉及到 ATM 技术。

**举例说明:**

假设一个工业级 Android 设备被用于连接到使用 ATM 网络的旧式电信设备。在这种情况下，开发者可能需要使用到这个头文件中定义的接口，通过 ioctl 系统调用与内核中的 ATM 驱动进行交互，以配置和管理 ATM 连接。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有定义任何 libc 函数的实现，它只是定义了一些常量、数据结构和宏，这些内容会被用户空间的程序使用，通过系统调用（如 `ioctl`）来与内核进行交互。

当用户空间的程序需要执行与 ATM 设备相关的操作时，它会调用 libc 提供的 `ioctl` 函数。`ioctl` 函数是一个通用的设备控制接口，它允许用户空间程序向设备驱动发送控制命令并传递数据。

**`ioctl` 函数的实现过程简述:**

1. **系统调用:** 用户空间程序调用 `ioctl` 函数，提供文件描述符 (与 ATM 设备关联)、请求码 (例如 `ATM_GETLINKRATE`) 和可选的参数指针。
2. **陷入内核:** `ioctl` 函数会触发一个系统调用，将控制权转移到内核。
3. **内核处理:** 内核接收到系统调用后，会根据文件描述符找到对应的设备驱动程序。
4. **驱动处理:** ATM 设备驱动程序接收到 `ioctl` 请求，根据请求码执行相应的操作。这可能包括读取或修改设备的状态、发送控制命令到硬件等。
5. **数据传输:** 如果 `ioctl` 调用包含数据传递，内核会在用户空间和内核空间之间复制数据。
6. **返回用户空间:** 设备驱动程序完成操作后，内核将结果返回给用户空间的 `ioctl` 函数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不涉及 dynamic linker 的功能。它定义的是与内核交互的接口，而不是用户空间共享库的接口。Dynamic linker 主要负责在程序运行时加载和链接共享库 (`.so` 文件)。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要获取 ATM 设备的链路速率，它会使用如下代码（简化）：

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/atmdev.h>
#include <linux/atmbr2684.h> // 可能需要包含相关的 ATM 驱动头文件

int main() {
    int fd;
    struct atmif_sioc if_req;

    // 打开 ATM 设备文件，例如 /dev/atm0
    fd = open("/dev/atm0", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // 设置接口名称
    strncpy(if_req. নাম, "atm0", IFNAMSIZ - 1);
    if_req. নাম[IFNAMSIZ - 1] = 0;

    // 调用 ioctl 获取链路速率
    if (ioctl(fd, ATM_GETLINKRATE, &if_req) < 0) {
        perror("ioctl ATM_GETLINKRATE");
        close(fd);
        return 1;
    }

    // 假设链路速率信息存储在 if_req 的某个字段中 (具体字段取决于内核驱动的实现)
    // 这里只是一个假设，实际情况需要查看内核文档
    printf("ATM Link Rate: %lld bps\n", (long long)if_req.link_rate);

    close(fd);
    return 0;
}
```

**假设输入与输出:**

- **假设输入:**  ATM 设备 `/dev/atm0` 存在且已启动，并且支持 `ATM_GETLINKRATE` ioctl 命令。
- **预期输出:**  程序将打印出 ATM 设备的链路速率，例如 "ATM Link Rate: 155520000 bps" (对于 OC-3 接口)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **设备文件不存在或权限不足:** 尝试打开不存在的 ATM 设备文件（例如 `/dev/atm0`）或者没有足够的权限访问该文件。
   ```c
   int fd = open("/dev/atm_nonexistent", O_RDONLY); // 错误：设备文件不存在
   // 或者
   int fd = open("/dev/atm0", O_RDONLY); // 错误：没有足够的读权限
   ```

2. **使用错误的 ioctl 命令码:**  传递了内核不支持的或与当前操作不符的 ioctl 命令码。
   ```c
   ioctl(fd, ATM_SETESI, &if_req); // 错误：可能应该使用 ATM_GETESI 获取 ESI
   ```

3. **传递了错误的数据结构或数据内容:**  `ioctl` 命令需要特定的数据结构作为参数，如果传递了错误类型的结构体或者结构体中的数据不符合预期，会导致错误。
   ```c
   struct some_other_struct wrong_req;
   ioctl(fd, ATM_GETLINKRATE, &wrong_req); // 错误：应该传递 struct atmif_sioc
   ```

4. **没有正确设置 ioctl 命令需要的参数:**  例如，`ATM_GETLINKRATE` 可能需要先设置接口名称，如果没有设置，内核驱动可能无法正确执行操作。
   ```c
   // 忘记设置 if_req.nam
   ioctl(fd, ATM_GETLINKRATE, &if_req); // 可能导致错误
   ```

5. **在不支持 ATM 的系统上运行代码:**  如果 Android 设备的内核没有配置或编译 ATM 驱动，尝试使用这些 ioctl 命令将会失败。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常情况下，Android Framework 或 NDK **不会直接**使用这些底层的 ATM 接口。Android 更倾向于使用现代的网络协议栈，例如 TCP/IP over Ethernet 或 Wi-Fi。

然而，如果某个底层的 Native 代码库（可能由 OEM 或特定硬件厂商提供）需要与 ATM 设备交互，那么它可能会使用到这些头文件中定义的接口。

**模拟 Android Framework/NDK 到达这里的路径（假设场景）：**

1. **应用程序 (Java/Kotlin):**  一个 Android 应用可能调用一个 NDK 提供的 Native 方法。
2. **NDK Native 代码 (.so):** 这个 Native 代码库可能会调用底层的 C/C++ 函数来操作硬件。
3. **系统调用 (libc):**  这个 Native 代码可能会调用 `ioctl` 函数，并使用 `linux/atmdev.h` 中定义的常量和结构体。
4. **内核驱动:**  `ioctl` 系统调用最终会到达内核中的 ATM 设备驱动程序。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida Hook `ioctl` 系统调用，并检查其 `request` 参数是否为 `linux/atmdev.h` 中定义的 ATM 相关 ioctl 命令码。

```python
import frida
import sys

# 要 hook 的进程名称
package_name = "your.target.app"

# 要监控的 ioctl 命令码 (这里列举一些，可以根据需要添加)
atm_ioctl_codes = [
    0x6141,  # ATM_GETLINKRATE 的值，需要根据 _IOW 宏计算
    0x6143,  # ATM_GETNAMES
    # ... 添加其他 ATM 相关的 ioctl 代码
]

# 计算 _IOW 宏的值
def _IOW(type, nr, size):
    return (ord(type) << 8) | nr | (size << 16)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var argp = args[2];

        // 检查是否是 ATM 相关的 ioctl 命令
        var atm_ioctl_codes = %s;
        if (atm_ioctl_codes.includes(request)) {
            console.log("Detected ATM ioctl call!");
            console.log("File Descriptor:", fd);
            console.log("Request Code:", request.toString(16));
            // 可以进一步解析 argp 指向的数据
        }
    }
});
""" % atm_ioctl_codes

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(script_code)
    script.load()
    sys.stdin.read()  # 让脚本保持运行状态

except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
except Exception as e:
    print(f"发生错误: {e}")
```

**使用步骤:**

1. **安装 Frida 和 Python 环境。**
2. **找到目标 Android 应用的进程名称。**
3. **计算 `linux/atmdev.h` 中相关 ioctl 命令码的实际数值。**  例如，`ATM_GETLINKRATE` 定义为 `_IOW('a', ATMIOC_ITF + 1, struct atmif_sioc)`。你需要查看 `linux/atmioc.h` 和 `struct atmif_sioc` 的大小来计算实际的数值。
4. **将计算出的 ioctl 代码添加到 `atm_ioctl_codes` 列表中。**
5. **运行 Frida 脚本。**
6. **在 Android 设备上执行可能会触发 ATM 相关操作的应用功能。**
7. **查看 Frida 的输出，如果检测到匹配的 ioctl 调用，将会打印相关信息。**

**总结:**

`bionic/libc/kernel/uapi/linux/atmdev.h` 定义了与 Linux ATM 设备驱动交互的接口。虽然在现代 Android 设备中不常用，但它作为 Linux 内核 API 的一部分仍然存在于 Bionic 库中。理解这个头文件的功能有助于理解 Android 系统与底层硬件交互的某些方面，尤其是在处理旧式网络设备或特定行业应用时。使用 Frida 可以帮助我们动态地分析系统调用，从而观察这些接口是否被使用以及如何被使用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/atmdev.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPILINUX_ATMDEV_H
#define _UAPILINUX_ATMDEV_H
#include <linux/atmapi.h>
#include <linux/atm.h>
#include <linux/atmioc.h>
#define ESI_LEN 6
#define ATM_OC3_PCR (155520000 / 270 * 260 / 8 / 53)
#define ATM_25_PCR ((25600000 / 8 - 8000) / 54)
#define ATM_OC12_PCR (622080000 / 1080 * 1040 / 8 / 53)
#define ATM_DS3_PCR (8000 * 12)
#define __AAL_STAT_ITEMS __HANDLE_ITEM(tx); __HANDLE_ITEM(tx_err); __HANDLE_ITEM(rx); __HANDLE_ITEM(rx_err); __HANDLE_ITEM(rx_drop);
struct atm_aal_stats {
#define __HANDLE_ITEM(i) int i
  __AAL_STAT_ITEMS
#undef __HANDLE_ITEM
};
struct atm_dev_stats {
  struct atm_aal_stats aal0;
  struct atm_aal_stats aal34;
  struct atm_aal_stats aal5;
} __ATM_API_ALIGN;
#define ATM_GETLINKRATE _IOW('a', ATMIOC_ITF + 1, struct atmif_sioc)
#define ATM_GETNAMES _IOW('a', ATMIOC_ITF + 3, struct atm_iobuf)
#define ATM_GETTYPE _IOW('a', ATMIOC_ITF + 4, struct atmif_sioc)
#define ATM_GETESI _IOW('a', ATMIOC_ITF + 5, struct atmif_sioc)
#define ATM_GETADDR _IOW('a', ATMIOC_ITF + 6, struct atmif_sioc)
#define ATM_RSTADDR _IOW('a', ATMIOC_ITF + 7, struct atmif_sioc)
#define ATM_ADDADDR _IOW('a', ATMIOC_ITF + 8, struct atmif_sioc)
#define ATM_DELADDR _IOW('a', ATMIOC_ITF + 9, struct atmif_sioc)
#define ATM_GETCIRANGE _IOW('a', ATMIOC_ITF + 10, struct atmif_sioc)
#define ATM_SETCIRANGE _IOW('a', ATMIOC_ITF + 11, struct atmif_sioc)
#define ATM_SETESI _IOW('a', ATMIOC_ITF + 12, struct atmif_sioc)
#define ATM_SETESIF _IOW('a', ATMIOC_ITF + 13, struct atmif_sioc)
#define ATM_ADDLECSADDR _IOW('a', ATMIOC_ITF + 14, struct atmif_sioc)
#define ATM_DELLECSADDR _IOW('a', ATMIOC_ITF + 15, struct atmif_sioc)
#define ATM_GETLECSADDR _IOW('a', ATMIOC_ITF + 16, struct atmif_sioc)
#define ATM_GETSTAT _IOW('a', ATMIOC_SARCOM + 0, struct atmif_sioc)
#define ATM_GETSTATZ _IOW('a', ATMIOC_SARCOM + 1, struct atmif_sioc)
#define ATM_GETLOOP _IOW('a', ATMIOC_SARCOM + 2, struct atmif_sioc)
#define ATM_SETLOOP _IOW('a', ATMIOC_SARCOM + 3, struct atmif_sioc)
#define ATM_QUERYLOOP _IOW('a', ATMIOC_SARCOM + 4, struct atmif_sioc)
#define ATM_SETSC _IOW('a', ATMIOC_SPECIAL + 1, int)
#define ATM_SETBACKEND _IOW('a', ATMIOC_SPECIAL + 2, atm_backend_t)
#define ATM_NEWBACKENDIF _IOW('a', ATMIOC_SPECIAL + 3, atm_backend_t)
#define ATM_ADDPARTY _IOW('a', ATMIOC_SPECIAL + 4, struct atm_iobuf)
#define ATM_DROPPARTY _IOW('a', ATMIOC_SPECIAL + 5, int)
#define ATM_BACKEND_RAW 0
#define ATM_BACKEND_PPP 1
#define ATM_BACKEND_BR2684 2
#define ATM_ITFTYP_LEN 8
#define __ATM_LM_NONE 0
#define __ATM_LM_AAL 1
#define __ATM_LM_ATM 2
#define __ATM_LM_PHY 8
#define __ATM_LM_ANALOG 16
#define __ATM_LM_MKLOC(n) ((n))
#define __ATM_LM_MKRMT(n) ((n) << 8)
#define __ATM_LM_XTLOC(n) ((n) & 0xff)
#define __ATM_LM_XTRMT(n) (((n) >> 8) & 0xff)
#define ATM_LM_NONE 0
#define ATM_LM_LOC_AAL __ATM_LM_MKLOC(__ATM_LM_AAL)
#define ATM_LM_LOC_ATM __ATM_LM_MKLOC(__ATM_LM_ATM)
#define ATM_LM_LOC_PHY __ATM_LM_MKLOC(__ATM_LM_PHY)
#define ATM_LM_LOC_ANALOG __ATM_LM_MKLOC(__ATM_LM_ANALOG)
#define ATM_LM_RMT_AAL __ATM_LM_MKRMT(__ATM_LM_AAL)
#define ATM_LM_RMT_ATM __ATM_LM_MKRMT(__ATM_LM_ATM)
#define ATM_LM_RMT_PHY __ATM_LM_MKRMT(__ATM_LM_PHY)
#define ATM_LM_RMT_ANALOG __ATM_LM_MKRMT(__ATM_LM_ANALOG)
struct atm_iobuf {
  int length;
  void  * buffer;
};
#define ATM_CI_MAX - 1
struct atm_cirange {
  signed char vpi_bits;
  signed char vci_bits;
};
#define ATM_SC_RX 1024
#define ATM_SC_TX 2048
#define ATM_BACKLOG_DEFAULT 32
#define ATM_MF_IMMED 1
#define ATM_MF_INC_RSV 2
#define ATM_MF_INC_SHP 4
#define ATM_MF_DEC_RSV 8
#define ATM_MF_DEC_SHP 16
#define ATM_MF_BWD 32
#define ATM_MF_SET (ATM_MF_INC_RSV | ATM_MF_INC_SHP | ATM_MF_DEC_RSV | ATM_MF_DEC_SHP | ATM_MF_BWD)
#define ATM_VS_IDLE 0
#define ATM_VS_CONNECTED 1
#define ATM_VS_CLOSING 2
#define ATM_VS_LISTEN 3
#define ATM_VS_INUSE 4
#define ATM_VS_BOUND 5
#define ATM_VS2TXT_MAP "IDLE", "CONNECTED", "CLOSING", "LISTEN", "INUSE", "BOUND"
#define ATM_VF2TXT_MAP "ADDR", "READY", "PARTIAL", "REGIS", "RELEASED", "HASQOS", "LISTEN", "META", "256", "512", "1024", "2048", "SESSION", "HASSAP", "BOUND", "CLOSE"
#endif
```