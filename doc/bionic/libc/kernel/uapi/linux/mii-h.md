Response:
Let's break down the thought process for analyzing the provided C header file (`mii.h`).

1. **Understanding the Context:** The prompt clearly states this is a kernel UAPI header file from Android's `bionic` library, specifically related to `mii` (Media Independent Interface). This immediately tells us it deals with low-level network hardware interaction, particularly the PHY (Physical Layer) of Ethernet. The "uapi" part signifies it's for user-space programs to interact with the kernel.

2. **Initial Scan and Keyword Identification:**  I quickly scanned the file, looking for keywords and patterns. Key terms that jumped out were:

    * `#define`:  Lots of these, indicating symbolic constants.
    * `MII_`: A very common prefix, suggesting these constants are grouped.
    * `BMCR_`, `BMSR_`, `ADVERTISE_`, `LPA_`, `EXPANSION_`, `ESTATUS_`, `NWAYTEST_`, `CTL1000_`: More prefixes, likely categorizing related constants.
    * `struct mii_ioctl_data`:  A structure definition, indicating data passed between user-space and kernel.
    * `linux/types.h`, `linux/ethtool.h`: Included header files.

3. **Categorization and Functional Grouping (Mental Model):** Based on the prefixes, I started to mentally group the constants:

    * **MII Registers:** `MII_BMCR`, `MII_BMSR`, etc. These likely represent addresses of registers within the PHY chip.
    * **BMCR (Basic Mode Control Register) Bits:** `BMCR_RESET`, `BMCR_SPEED100`, etc. These control the PHY's operational mode.
    * **BMSR (Basic Mode Status Register) Bits:** `BMSR_LSTATUS`, `BMSR_ANEGCOMPLETE`, etc. These reflect the PHY's status.
    * **Negotiation Registers:** `ADVERTISE_`, `LPA_`. These handle auto-negotiation settings.
    * **Advanced Features:**  `EXPANSION_`, `ESTATUS_`, `NWAYTEST_`, `CTL1000_`. These relate to more specific or newer features.

4. **Analyzing Individual Constants (Deeper Dive):**  I started looking at individual constants within each group. For example, in `BMCR_`:

    * `BMCR_RESET`:  Clearly a bit to reset the PHY.
    * `BMCR_SPEED100`, `BMCR_SPEED1000`:  Bits to set the desired speed.
    * `BMCR_FULLDPLX`:  Bit for full-duplex communication.
    * `BMCR_ANENABLE`:  Bit to enable auto-negotiation.

    Similarly, in `BMSR_`:

    * `BMSR_LSTATUS`:  Indicates link status.
    * `BMSR_ANEGCAPABLE`: Shows if the PHY supports auto-negotiation.
    * `BMSR_ANEGCOMPLETE`: Indicates auto-negotiation is finished.

5. **Connecting to Android Functionality:**  I considered how this low-level hardware interaction relates to higher-level Android features. Networking is fundamental. Therefore:

    * **Network Connectivity:** This is the most obvious connection. The MII is essential for establishing an Ethernet connection.
    * **Network Configuration:**  Android allows users and the system to configure network settings (IP address, etc.). Underneath, the system needs to communicate with the PHY to establish the physical link and negotiate parameters.
    * **Wi-Fi Direct/Tethering:** While this file is for *wired* Ethernet, the underlying principles of network device management are similar, and the Android framework handles both wired and wireless connections.

6. **Libc Functions - Not Directly Present:** I realized that this header file *defines constants*, not actual libc *functions*. The *use* of these constants would be in code that interacts with the network driver, which might involve `ioctl` system calls.

7. **Dynamic Linker - Not Directly Relevant:**  This header file doesn't contain executable code or library dependencies, so the dynamic linker isn't directly involved. However, the libraries *using* these definitions would be linked.

8. **User/Programming Errors:**  I thought about common mistakes developers might make when working with network hardware or using these constants:

    * Incorrectly setting control bits.
    * Misinterpreting status bits.
    * Not handling auto-negotiation properly.

9. **Android Framework and NDK:** I considered the path from the Android framework down to this level:

    * **Java Framework (ConnectivityManager, NetworkInterface):**  High-level APIs for network management.
    * **Native Framework (Netd, RIL):**  Native daemons that handle network configuration and control.
    * **Kernel Drivers:**  The actual drivers for the Ethernet hardware.
    * **System Calls (`ioctl`):** The mechanism for user-space to communicate with kernel drivers.

10. **Frida Hooking:** I envisioned how Frida could be used to observe interactions at this low level:

    * Hooking the `ioctl` system call to intercept commands related to Ethernet devices.
    * Filtering for `SIOCGMIIPHY` and `SIOCSMIIREG` (common `ioctl` commands for reading/writing MII registers).
    * Logging the register addresses and values being accessed.

11. **Structuring the Response:** Finally, I organized the information logically, starting with a general overview and then going into more detail for each aspect requested in the prompt. I used clear headings and bullet points for readability. I ensured to explicitly address each part of the initial request. I also made sure to clarify when a particular aspect (like libc functions or the dynamic linker) wasn't directly involved but provided context where appropriate.

This iterative process of scanning, categorizing, analyzing, connecting, and structuring allows for a comprehensive understanding and explanation of the given header file.
这个头文件 `bionic/libc/kernel/uapi/linux/mii.h` 定义了用于与以太网物理层芯片 (PHY) 交互的常量和结构体。它属于 Linux 内核的 UAPI (User API)，供用户空间程序使用，以便与内核中的网络驱动程序进行通信。由于 `bionic` 是 Android 的 C 库，因此这些定义被 Android 系统用于进行底层的网络硬件控制。

**功能列举:**

该文件主要定义了以下内容，这些都与控制和监控以太网 PHY 芯片有关：

1. **MII 寄存器地址:**  定义了各种 MII (Media Independent Interface) 寄存器的地址，例如 `MII_BMCR` (基本模式控制寄存器)、`MII_BMSR` (基本模式状态寄存器) 等。这些寄存器用于配置和读取 PHY 芯片的状态。
2. **BMCR 位掩码:** 定义了 `MII_BMCR` 寄存器中各个位的含义，例如 `BMCR_RESET` (复位 PHY)、`BMCR_SPEED100` (设置速度为 100Mbps)、`BMCR_FULLDPLX` (设置全双工模式) 等。
3. **BMSR 位掩码:** 定义了 `MII_BMSR` 寄存器中各个位的含义，例如 `BMSR_LSTATUS` (链路状态)、`BMSR_ANEGCAPABLE` (是否支持自动协商)、`BMSR_ANEGCOMPLETE` (自动协商是否完成) 等。
4. **自协商寄存器位掩码:**  定义了用于自动协商的寄存器 (`MII_ADVERTISE`, `MII_LPA`) 中各个位的含义，例如支持的速率、双工模式、流控等。
5. **其他控制和状态寄存器位掩码:** 定义了其他 MII 扩展寄存器中各个位的含义，用于更高级的控制和状态查询。
6. **`mii_ioctl_data` 结构体:**  定义了一个结构体，用于在用户空间程序和内核驱动程序之间传递 MII 操作的参数，例如 PHY 地址、寄存器号、输入值和输出值。

**与 Android 功能的关系及举例:**

Android 设备通常通过以太网或 Wi-Fi 进行网络连接。虽然这个文件直接涉及的是有线以太网的 PHY 层交互，但其核心概念和机制也与 Wi-Fi 等其他网络技术有所关联。

**举例说明:**

* **网络连接建立:** 当 Android 设备连接到有线网络时，系统底层的网络驱动程序会使用这里定义的常量来配置和监控以太网 PHY 芯片。例如，驱动程序可能会设置 `MII_BMCR` 寄存器的 `BMCR_ANENABLE` 位来启用自动协商，并读取 `MII_BMSR` 寄存器的 `BMSR_LSTATUS` 位来检查链路是否建立。
* **网络速度和双工模式协商:**  自动协商是 Ethernet 设备确定最佳连接速度和双工模式的过程。Android 系统在建立连接时，底层的驱动程序会读取和设置 `MII_ADVERTISE` 和 `MII_LPA` 寄存器，以确定双方都支持的连接参数。
* **网络状态监控:**  Android 系统会定期检查网络连接的状态。驱动程序会读取 `MII_BMSR` 寄存器来获取链路状态、连接速度等信息，并将这些信息传递给上层，最终反映在 Android 的网络设置界面中。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**并没有定义任何 libc 函数**。它只定义了常量和数据结构。实际操作这些 MII 寄存器的是内核中的网络驱动程序。用户空间程序（例如 Android 的网络服务）会使用 `ioctl` 系统调用与内核驱动程序通信，并使用这里定义的常量来指定要操作的寄存器和位。

例如，Android 的一个网络管理服务可能需要读取 PHY 的状态。它会通过 `ioctl` 系统调用，并使用 `mii_ioctl_data` 结构体来指定要读取的 PHY 地址和寄存器号 (例如 `MII_BMSR`)。内核驱动程序接收到 `ioctl` 请求后，会执行实际的硬件操作，读取 PHY 芯片的相应寄存器，并将结果返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件是内核 UAPI 的一部分，主要用于内核驱动程序和用户空间程序之间的接口定义。**它不直接涉及 dynamic linker 的功能**。Dynamic linker (例如 Android 的 `linker64` 或 `linker`) 负责加载和链接用户空间的共享库 (`.so` 文件)。

虽然这个头文件本身与 dynamic linker 无关，但使用这些定义的代码（例如网络管理相关的共享库）会被 dynamic linker 加载。

**假设一个使用这些定义的共享库 `libnetmgr.so` 的布局样本：**

```
libnetmgr.so:
    .text          # 代码段
        function_a:
            # ... 使用了 MII 相关的常量 ...
            mov  r0, #MII_BMSR  // 使用了 MII_BMSR 常量
            // ... 调用 ioctl ...
    .rodata        # 只读数据段
        mii_constants:
            .word MII_BMCR
            .word MII_BMSR
            // ...
    .data          # 可读写数据段
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息
        NEEDED      libc.so
        SONAME      libnetmgr.so
        // ...
```

**链接处理过程：**

1. 当一个 Android 进程需要使用 `libnetmgr.so` 时，dynamic linker 会根据其依赖关系加载 `libc.so` (因为 `libnetmgr.so` 依赖于它)。
2. Dynamic linker 会解析 `libnetmgr.so` 的 `.dynamic` 段，找到所需的共享库。
3. Dynamic linker 会将 `libnetmgr.so` 加载到内存中的合适位置。
4. 如果 `libnetmgr.so` 中使用了在 `libc.so` 中定义的符号（例如 `ioctl` 函数），dynamic linker 会进行符号解析，将 `libnetmgr.so` 中对这些符号的引用指向 `libc.so` 中相应的实现。
5. **注意：**  `mii.h` 中定义的常量是在编译时直接嵌入到使用它的代码中的，dynamic linker 不需要在运行时解析这些常量。

**如果做了逻辑推理，请给出假设输入与输出:**

由于这个文件定义的是常量和结构体，不存在直接的逻辑推理过程。逻辑推理发生在内核驱动程序中，它会根据读取到的 MII 寄存器的值来判断 PHY 的状态并采取相应的行动。

**假设场景：** 内核驱动程序读取了 `MII_BMSR` 寄存器的值。

**假设输入 (读取到的 `MII_BMSR` 值):** `0x0025` (二进制: `0000 0000 0010 0101`)

**逻辑推理:**

* `BMSR_LSTATUS (0x0004)` 位为 1，表示链路已建立。
* `BMSR_ANEGCOMPLETE (0x0020)` 位为 1，表示自动协商已完成。
* 其他位为 0，表示没有检测到其他特定的状态。

**假设输出 (驱动程序根据读取到的值采取的行动):**  驱动程序确认网络连接已建立且自动协商已完成，可以继续进行数据传输。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的寄存器地址或位掩码:**  直接使用硬编码的数值而不是使用头文件中定义的常量，容易导致错误，例如写错寄存器地址或位掩码，导致 PHY 工作异常甚至损坏。
   ```c
   // 错误示例：使用硬编码的数值
   ioctl_data.reg_num = 0x00; // 应该使用 MII_BMCR
   value |= 0x8000;          // 应该使用 BMCR_RESET
   ```

2. **未正确处理 `ioctl` 的返回值:** `ioctl` 调用可能会失败，例如由于权限问题或设备不存在。没有检查返回值会导致程序行为不可预测。
   ```c
   // 错误示例：未检查 ioctl 的返回值
   if (ioctl(fd, SIOCSMIIREG, &ioctl_data) < 0) {
       // 应该处理错误
       perror("ioctl failed");
   }
   ```

3. **并发访问冲突:**  多个进程或线程同时尝试访问和修改 PHY 的配置可能会导致冲突和不可预测的行为。需要进行适当的同步和互斥控制。

4. **不理解 PHY 的工作原理:** 错误地配置 PHY 的参数，例如禁用自动协商但又没有手动配置正确的速度和双工模式，会导致网络连接失败。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

Android Framework 和 NDK 通常不会直接操作 MII 寄存器。这些操作主要发生在内核驱动程序中。然而，Android Framework 会通过一系列抽象层与内核驱动程序进行交互。

**大致步骤:**

1. **Android Framework (Java层):**  例如，`ConnectivityManager` 或 `NetworkInterface` 类提供了高层次的网络管理 API。
2. **Native Framework (C++层):**  Java Framework 通过 JNI (Java Native Interface) 调用 Native Framework 中的代码，例如 `netd` (网络守护进程)。
3. **System Calls:** `netd` 等 Native 组件会使用底层的系统调用，如 `ioctl`，来与内核驱动程序通信。
4. **内核驱动程序:**  以太网设备驱动程序（例如 `drivers/net/ethernet/...`) 会处理来自用户空间的 `ioctl` 请求，并最终操作硬件（包括 MII 寄存器）。

**Frida Hook 示例:**

我们可以使用 Frida Hook `ioctl` 系统调用，并过滤与 MII 相关的操作。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

session = frida.attach('com.android.systemui') # 替换为你想要监控的进程

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        if (request === 0x8946 || request === 0x8947) { // SIOCGMIIPHY (Get MII PHY address) or SIOCSMIIREG (Set or get MII register)
            console.log("[ioctl] File Descriptor:", fd);
            console.log("[ioctl] Request:", request);

            if (request === 0x8947) {
                const mii_ioctl_data_ptr = ptr(argp);
                const phy_id = mii_ioctl_data_ptr.readU16();
                const reg_num = mii_ioctl_data_ptr.add(2).readU16();
                const val_in = mii_ioctl_data_ptr.add(4).readU16();

                console.log("[ioctl] mii_ioctl_data.phy_id:", phy_id);
                console.log("[ioctl] mii_ioctl_data.reg_num:", reg_num);
                console.log("[ioctl] mii_ioctl_data.val_in:", val_in);
            }
        }
    },
    onLeave: function(retval) {
        // console.log("[ioctl] Return Value:", retval);
    }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
""")

```

**解释 Frida Hook 代码:**

1. **`frida.attach('com.android.systemui')`**:  连接到 `com.android.systemui` 进程（你可以替换为你感兴趣的网络相关进程）。
2. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`**:  Hook `ioctl` 系统调用。
3. **`onEnter` 函数**: 在 `ioctl` 调用进入时执行。
4. **`request === 0x8946 || request === 0x8947`**:  检查 `ioctl` 的请求码是否为 `SIOCGMIIPHY` (获取 MII PHY 地址) 或 `SIOCSMIIREG` (设置/获取 MII 寄存器)。这两个是与 MII 交互相关的常见 `ioctl` 请求。
5. **读取 `mii_ioctl_data` 结构体**: 如果是 `SIOCSMIIREG` 请求，我们尝试读取 `mii_ioctl_data` 结构体中的 `phy_id`、`reg_num` 和 `val_in`，以便了解正在访问哪个 PHY 的哪个寄存器以及要写入的值。
6. **`onLeave` 函数**: 在 `ioctl` 调用返回时执行 (这里被注释掉了，你可以根据需要添加逻辑)。

**如何使用 Frida Hook 调试:**

1. 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. 将上述 Python 代码保存为 `.py` 文件 (例如 `hook_mii.py`)。
3. 在 PC 上运行该 Python 脚本：`python hook_mii.py`。
4. 在 Android 设备上执行一些网络相关的操作，例如连接或断开有线网络，或者查看网络设置。
5. Frida 会拦截与 MII 相关的 `ioctl` 调用，并将相关信息打印到你的终端上，你可以通过这些信息了解 Android 系统是如何与底层的 PHY 芯片进行交互的。

请注意，实际的调用链可能很复杂，涉及多个组件和抽象层。这个 Frida Hook 示例只是一个起点，可以帮助你观察与 MII 交互相关的底层操作。 你可能需要根据你想要调试的具体场景和目标进程进行调整。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/mii.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_MII_H__
#define _UAPI__LINUX_MII_H__
#include <linux/types.h>
#include <linux/ethtool.h>
#define MII_BMCR 0x00
#define MII_BMSR 0x01
#define MII_PHYSID1 0x02
#define MII_PHYSID2 0x03
#define MII_ADVERTISE 0x04
#define MII_LPA 0x05
#define MII_EXPANSION 0x06
#define MII_CTRL1000 0x09
#define MII_STAT1000 0x0a
#define MII_MMD_CTRL 0x0d
#define MII_MMD_DATA 0x0e
#define MII_ESTATUS 0x0f
#define MII_DCOUNTER 0x12
#define MII_FCSCOUNTER 0x13
#define MII_NWAYTEST 0x14
#define MII_RERRCOUNTER 0x15
#define MII_SREVISION 0x16
#define MII_RESV1 0x17
#define MII_LBRERROR 0x18
#define MII_PHYADDR 0x19
#define MII_RESV2 0x1a
#define MII_TPISTATUS 0x1b
#define MII_NCONFIG 0x1c
#define BMCR_RESV 0x003f
#define BMCR_SPEED1000 0x0040
#define BMCR_CTST 0x0080
#define BMCR_FULLDPLX 0x0100
#define BMCR_ANRESTART 0x0200
#define BMCR_ISOLATE 0x0400
#define BMCR_PDOWN 0x0800
#define BMCR_ANENABLE 0x1000
#define BMCR_SPEED100 0x2000
#define BMCR_LOOPBACK 0x4000
#define BMCR_RESET 0x8000
#define BMCR_SPEED10 0x0000
#define BMSR_ERCAP 0x0001
#define BMSR_JCD 0x0002
#define BMSR_LSTATUS 0x0004
#define BMSR_ANEGCAPABLE 0x0008
#define BMSR_RFAULT 0x0010
#define BMSR_ANEGCOMPLETE 0x0020
#define BMSR_RESV 0x00c0
#define BMSR_ESTATEN 0x0100
#define BMSR_100HALF2 0x0200
#define BMSR_100FULL2 0x0400
#define BMSR_10HALF 0x0800
#define BMSR_10FULL 0x1000
#define BMSR_100HALF 0x2000
#define BMSR_100FULL 0x4000
#define BMSR_100BASE4 0x8000
#define ADVERTISE_SLCT 0x001f
#define ADVERTISE_CSMA 0x0001
#define ADVERTISE_10HALF 0x0020
#define ADVERTISE_1000XFULL 0x0020
#define ADVERTISE_10FULL 0x0040
#define ADVERTISE_1000XHALF 0x0040
#define ADVERTISE_100HALF 0x0080
#define ADVERTISE_1000XPAUSE 0x0080
#define ADVERTISE_100FULL 0x0100
#define ADVERTISE_1000XPSE_ASYM 0x0100
#define ADVERTISE_100BASE4 0x0200
#define ADVERTISE_PAUSE_CAP 0x0400
#define ADVERTISE_PAUSE_ASYM 0x0800
#define ADVERTISE_RESV 0x1000
#define ADVERTISE_RFAULT 0x2000
#define ADVERTISE_LPACK 0x4000
#define ADVERTISE_NPAGE 0x8000
#define ADVERTISE_FULL (ADVERTISE_100FULL | ADVERTISE_10FULL | ADVERTISE_CSMA)
#define ADVERTISE_ALL (ADVERTISE_10HALF | ADVERTISE_10FULL | ADVERTISE_100HALF | ADVERTISE_100FULL)
#define LPA_SLCT 0x001f
#define LPA_10HALF 0x0020
#define LPA_1000XFULL 0x0020
#define LPA_10FULL 0x0040
#define LPA_1000XHALF 0x0040
#define LPA_100HALF 0x0080
#define LPA_1000XPAUSE 0x0080
#define LPA_100FULL 0x0100
#define LPA_1000XPAUSE_ASYM 0x0100
#define LPA_100BASE4 0x0200
#define LPA_PAUSE_CAP 0x0400
#define LPA_PAUSE_ASYM 0x0800
#define LPA_RESV 0x1000
#define LPA_RFAULT 0x2000
#define LPA_LPACK 0x4000
#define LPA_NPAGE 0x8000
#define LPA_DUPLEX (LPA_10FULL | LPA_100FULL)
#define LPA_100 (LPA_100FULL | LPA_100HALF | LPA_100BASE4)
#define EXPANSION_NWAY 0x0001
#define EXPANSION_LCWP 0x0002
#define EXPANSION_ENABLENPAGE 0x0004
#define EXPANSION_NPCAPABLE 0x0008
#define EXPANSION_MFAULTS 0x0010
#define EXPANSION_RESV 0xffe0
#define ESTATUS_1000_XFULL 0x8000
#define ESTATUS_1000_XHALF 0x4000
#define ESTATUS_1000_TFULL 0x2000
#define ESTATUS_1000_THALF 0x1000
#define NWAYTEST_RESV1 0x00ff
#define NWAYTEST_LOOPBACK 0x0100
#define NWAYTEST_RESV2 0xfe00
#define ADVERTISE_SGMII 0x0001
#define LPA_SGMII 0x0001
#define LPA_SGMII_SPD_MASK 0x0c00
#define LPA_SGMII_FULL_DUPLEX 0x1000
#define LPA_SGMII_DPX_SPD_MASK 0x1C00
#define LPA_SGMII_10 0x0000
#define LPA_SGMII_10HALF 0x0000
#define LPA_SGMII_10FULL 0x1000
#define LPA_SGMII_100 0x0400
#define LPA_SGMII_100HALF 0x0400
#define LPA_SGMII_100FULL 0x1400
#define LPA_SGMII_1000 0x0800
#define LPA_SGMII_1000HALF 0x0800
#define LPA_SGMII_1000FULL 0x1800
#define LPA_SGMII_LINK 0x8000
#define ADVERTISE_1000FULL 0x0200
#define ADVERTISE_1000HALF 0x0100
#define CTL1000_PREFER_MASTER 0x0400
#define CTL1000_AS_MASTER 0x0800
#define CTL1000_ENABLE_MASTER 0x1000
#define LPA_1000MSFAIL 0x8000
#define LPA_1000MSRES 0x4000
#define LPA_1000LOCALRXOK 0x2000
#define LPA_1000REMRXOK 0x1000
#define LPA_1000FULL 0x0800
#define LPA_1000HALF 0x0400
#define FLOW_CTRL_TX 0x01
#define FLOW_CTRL_RX 0x02
#define MII_MMD_CTRL_DEVAD_MASK 0x1f
#define MII_MMD_CTRL_ADDR 0x0000
#define MII_MMD_CTRL_NOINCR 0x4000
#define MII_MMD_CTRL_INCR_RDWT 0x8000
#define MII_MMD_CTRL_INCR_ON_WT 0xC000
struct mii_ioctl_data {
  __u16 phy_id;
  __u16 reg_num;
  __u16 val_in;
  __u16 val_out;
};
#endif

"""

```