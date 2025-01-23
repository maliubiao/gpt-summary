Response:
Let's break down the thought process for answering this complex request about the `mdio.h` header file.

**1. Understanding the Core Request:**

The fundamental request is to understand the functionality of the `mdio.h` header file within the Android Bionic context. The user wants a comprehensive explanation, including its relation to Android, function implementations (even though it's just a header), dynamic linker aspects (unlikely for a header like this), usage errors, and how Android frameworks reach this code.

**2. Initial Assessment of the File:**

The file starts with a crucial comment: "This file is auto-generated. Modifications will be lost."  This immediately tells us this isn't hand-written, complex C code with intricate logic. It's likely a definition file generated from some other source, probably related to the Linux kernel. The `#ifndef`, `#define`, and `#include` directives confirm it's a header file. The contents are primarily `#define` macros.

**3. Identifying Key Areas for Analysis:**

Based on the request and the file content, I identified the following key areas to address:

* **Functionality:** What does this header *define* and what purpose does it serve?
* **Android Relevance:** How do these definitions relate to Android's hardware and networking?
* **libc Functions:**  While there aren't *implementations* here, I need to explain that this header *supports* libc by providing definitions.
* **Dynamic Linker:** This seems unlikely for a header, but I need to address it and explain why.
* **Logic/Assumptions:**  The definitions are straightforward, so complex logical deduction isn't needed.
* **Usage Errors:**  Focus on the *intent* of the definitions and potential misinterpretations or incorrect usage by developers.
* **Android Framework/NDK:**  Trace the path from high-level Android to this low-level kernel header.
* **Frida Hooking:** Provide examples of how a developer might inspect the values of these definitions.

**4. Detailing Each Area:**

* **Functionality:** The macros define constants related to MDIO (Management Data Input/Output), a serial bus used to manage PHYs (physical layer transceivers) in network devices. I need to explain the purpose of MDIO and PHYs in networking.

* **Android Relevance:** Think about where network hardware interaction happens in Android. The HAL (Hardware Abstraction Layer) is a key point. I need to explain how these definitions might be used by drivers interacting with network chips. Examples of network interfaces (Wi-Fi, Ethernet) are helpful.

* **libc Functions:**  Emphasize that this is a *header file*, not the *implementation*. The `include` directive brings these definitions into C/C++ code. Briefly explain the included headers (`linux/types.h`, `linux/mii.h`).

* **Dynamic Linker:**  Explain that header files aren't directly involved in dynamic linking. The linker works with compiled code (`.so` files). Provide a sample `.so` layout and explain the linking process conceptually, even though it's not directly relevant here, to show understanding of the concept.

* **Logic/Assumptions:**  The definitions are direct mappings of names to numerical values. The primary "logic" is in the consistent naming conventions (e.g., `MDIO_MMD_`, `MDIO_CTRL1_`).

* **Usage Errors:**  Focus on semantic errors. Using the wrong constant, misunderstanding the meaning of a bitmask, or not checking return values from related functions would be common errors. Provide concrete examples.

* **Android Framework/NDK:**  Start from the application level (e.g., `ConnectivityManager`). Trace down through the frameworks, native code, HAL, and finally to kernel drivers where these definitions would be used. This requires a high-level understanding of the Android architecture.

* **Frida Hooking:**  Demonstrate how to use Frida to inspect the values of these constants at runtime within a relevant process (e.g., a network service). Provide a clear, concise example.

**5. Structuring the Response:**

Organize the information logically, following the order of the user's request. Use clear headings and subheadings. Maintain a consistent tone and level of detail. Use code blocks for the Frida examples and the `.so` layout.

**6. Language and Tone:**

Use clear, concise Chinese. Avoid overly technical jargon where possible, or explain technical terms. Maintain a helpful and informative tone.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe I should try to find the exact C code where these macros are used. **Correction:** This is likely unnecessary and time-consuming. Focus on the *purpose* of the definitions.
* **Initial thought:**  Go into deep detail about the MDIO protocol. **Correction:**  Provide a basic explanation of MDIO, but avoid getting bogged down in the specifics of the protocol unless directly relevant to the defined constants.
* **Realization:** The user specifically asked about libc functions' *implementations*. **Correction:**  Clearly state that header files don't contain implementations and focus on the role of the header in providing definitions for code that *will* be implemented elsewhere.
* **Double-check:** Ensure the Frida example is correct and provides practical value to the user.

By following this structured approach, focusing on the key aspects of the request, and making necessary refinements along the way, a comprehensive and accurate answer can be constructed. The key is to understand the context of the file within the larger Android ecosystem.
这个目录下的 `mdio.h` 文件是 Android Bionic 中关于 MDIO（Management Data Input/Output）接口的头文件。MDIO 是一种用于管理以太网 PHY（Physical Layer）芯片的串行总线。这个头文件定义了一系列用于访问和控制 PHY 芯片寄存器的常量和宏。

**功能列举:**

该头文件主要定义了以下功能相关的常量和宏：

1. **MMD (Management Module Descriptor) 地址:** 定义了不同管理模块的地址，例如 `MDIO_MMD_PMAPMD` (物理媒体附件/物理媒体依赖)，`MDIO_MMD_AN` (自协商) 等。这些地址用于访问 PHY 芯片内部的不同功能模块。
2. **基本控制和状态寄存器地址:** 定义了符合 IEEE 802.3 标准的基本控制和状态寄存器地址，例如 `MDIO_CTRL1` (基本控制寄存器 - MII_BMCR)，`MDIO_STAT1` (基本状态寄存器 - MII_BMSR)。
3. **扩展寄存器地址:** 定义了用于访问 PHY 芯片扩展功能的寄存器地址，例如速度配置 (`MDIO_SPEED`)，设备能力 (`MDIO_DEVS1`, `MDIO_DEVS2`) 等。
4. **自协商相关寄存器地址:** 定义了自协商过程中的寄存器地址，例如 `MDIO_AN_ADVERTISE` (自协商通告寄存器)，`MDIO_AN_LPA` (链路伙伴能力寄存器)。
5. **节能以太网 (EEE) 相关寄存器地址:** 定义了与节能以太网功能相关的寄存器地址，例如 `MDIO_PCS_EEE_ABLE` (PCS EEE 能力寄存器)。
6. **高速以太网 (10G/2.5G/5G 等) 相关寄存器地址:** 定义了用于控制和读取高速以太网 PHY 芯片状态的寄存器地址，例如 `MDIO_PCS_10GBRT_STAT1`，`MDIO_AN_10GBT_CTRL`。
7. **单对以太网 (10BASE-T1L) 相关寄存器地址:** 定义了用于控制和读取单对以太网 PHY 芯片状态的寄存器地址，例如 `MDIO_PMA_10T1L_CTRL`，`MDIO_PMA_10T1L_STAT`。
8. **特定厂商寄存器地址:**  预留了特定厂商使用的寄存器地址范围，例如 `MDIO_MMD_VEND1`，`MDIO_MMD_VEND2`。
9. **位掩码和标志位:** 定义了用于操作寄存器中特定位或标志位的掩码和常量，例如 `MDIO_CTRL1_SPEED1000`，`MDIO_STAT1_LSTATUS`。
10. **速度和双工模式定义:** 定义了表示不同速度和双工模式的常量，例如 `MDIO_SPEED_10G`，`MDIO_CTRL1_FULLDPLX`。
11. **设备存在位掩码:** 定义了用于指示特定 MMD 模块是否存在的位掩码，例如 `MDIO_DEVS_PRESENT(devad)`，`MDIO_DEVS_PMAPMD`。

**与 Android 功能的关系及举例说明:**

这个头文件直接关系到 Android 设备中的**网络连接功能**，特别是**以太网连接**。Android 设备（例如一些机顶盒、工控设备或开发板）可能包含以太网接口。

* **硬件抽象层 (HAL) 中的使用:**  Android 的网络 HAL (Hardware Abstraction Layer) 会使用这些定义来与底层的以太网 PHY 芯片进行通信。例如，一个以太网驱动程序可能需要读取 PHY 的链路状态，速度和双工模式。它会使用 `MDIO_STAT1_LSTATUS` 来检查链路是否建立，使用 `MDIO_SPEED` 来获取当前速度。
* **网络驱动程序中的使用:** Linux 内核中的以太网驱动程序（例如 `drivers/net/ethernet` 下的驱动）会包含并使用这个头文件中的定义。这些驱动程序负责控制 PHY 芯片，并向上层网络协议栈报告链路状态和配置信息。
* **示例:** 假设 Android 设备连接到以太网网络，并正在协商链路速度。底层的以太网驱动程序可能会执行以下操作：
    1. 通过 MDIO 接口写入 `MDIO_CTRL1` 寄存器，使用 `MDIO_CTRL1_RESET` 位来复位 PHY 芯片。
    2. 写入 `MDIO_AN_ADVERTISE` 寄存器，设置支持的自协商模式 (例如使用 `MDIO_AN_T1_ADV_M_1000BT1` 表示支持 1000BASE-T1)。
    3. 写入 `MDIO_CTRL1` 寄存器，使用 `MDIO_AN_CTRL1_ENABLE` 位来启动自协商。
    4. 轮询读取 `MDIO_STAT1` 寄存器，检查 `MDIO_AN_STAT1_COMPLETE` 位，判断自协商是否完成。
    5. 读取 `MDIO_SPEED` 寄存器，获取协商后的链路速度。

**详细解释每一个 libc 函数的功能是如何实现的:**

**需要明确的是，这个 `mdio.h` 文件是一个头文件，它只包含宏定义和常量声明，并不包含任何 libc 函数的实现代码。**  libc 函数的实现位于 Bionic 库的其他源文件中（通常是 `.c` 或 `.S` 文件）。

这个头文件提供的定义会被其他 C/C++ 代码使用，这些代码可能会调用 libc 函数来进行实际的操作。例如，读写 MDIO 寄存器的操作通常会涉及到底层的 I/O 操作，这些操作可能会通过系统调用来完成，而系统调用的封装是由 libc 提供的。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个 `mdio.h` 文件本身不直接涉及 dynamic linker 的功能。** 它定义的常量和宏主要用于内核驱动程序或 HAL 中的代码，这些代码通常不以动态链接库 (.so) 的形式存在于用户空间。

然而，如果一个用户空间的库（例如一个通过 NDK 开发的库）需要与底层的网络硬件进行交互，它可能会间接地依赖于使用这些定义的 HAL 模块或驱动程序。

**如果一个使用了这些定义的 HAL 模块是以动态链接库的形式存在，那么其 .so 布局可能如下所示（简化示例）：**

```
lib<network_hal>.so:
    .text          # 代码段
        ... (实现与 PHY 芯片交互的函数，可能使用 mdio.h 中的定义) ...
    .rodata        # 只读数据段
        ... (可能包含 mdio.h 中定义的常量) ...
    .data          # 可读写数据段
        ...
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息
        NEEDED      libc.so
        SONAME      lib<network_hal>.so
        ...
    .dynsym        # 动态符号表
        ... (可能包含导出的函数符号) ...
    .dynstr        # 动态字符串表
        ...
    ...
```

**链接处理过程：**

1. **编译时链接：** 当编译一个依赖于该 HAL 库的程序时，链接器会查找该库提供的符号（例如函数）。`mdio.h` 中的定义在编译时会被替换为具体的数值，因此不会直接参与链接过程。
2. **运行时链接：** 当程序运行时，dynamic linker (例如 Bionic 的 linker) 会加载所有依赖的 .so 文件 (`libc.so`, `lib<network_hal>.so` 等)。
3. **符号解析：** dynamic linker 会解析各个 .so 文件中的符号依赖关系。如果 `lib<network_hal>.so` 依赖于 `libc.so` 中的函数，linker 会找到这些函数的地址，并将 `lib<network_hal>.so` 中对这些函数的调用重定向到正确的地址。
4. **重定位：** dynamic linker 还会执行重定位操作，调整 .so 文件中需要根据加载地址进行修改的部分。

**对于 `mdio.h` 而言，它主要在编译时起作用，为使用 MDIO 接口的代码提供必要的常量定义。**

**如果做了逻辑推理，请给出假设输入与输出:**

由于 `mdio.h` 主要是定义常量，它本身不包含逻辑推理的代码。逻辑推理会发生在使用了这些定义的驱动程序或 HAL 模块中。

**假设输入与输出示例 (在使用了 `mdio.h` 的驱动程序中):**

**场景:** 驱动程序需要判断 PHY 芯片是否支持 1000BASE-T 模式。

**假设输入:**  读取 `MDIO_AN_ADVERTISE` 寄存器的值为 `0x0100` (二进制 `0000 0001 0000 0000`)。

**逻辑推理:**  驱动程序会使用 `MDIO_AN_T1_ADV_M_1000BT1` (值为 `0x0080`，二进制 `0000 0000 1000 0000`) 与读取到的值进行按位与操作。

**输出:**  如果 `(read_value & MDIO_AN_T1_ADV_M_1000BT1)` 的结果非零，则表示 PHY 芯片通告了支持 1000BASE-T 模式。在本例中，`0x0100 & 0x0080` 的结果为 `0x0000`，所以输出为“不支持 1000BASE-T”。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用错误的寄存器地址:**  开发者可能会错误地使用了与预期功能不符的寄存器地址，导致读写操作的目标错误。例如，想读取基本状态寄存器却使用了扩展状态寄存器的地址。
2. **错误的位操作:**  在操作寄存器的特定位时，可能会使用错误的掩码或逻辑运算符，导致无法正确设置或读取标志位。例如，使用按位或 `|` 来检查某个位是否被设置，而不是按位与 `&`。
3. **忽略 PHY 的状态:**  在进行配置后，没有正确读取 PHY 的状态寄存器来验证配置是否生效，导致系统行为异常。
4. **未考虑 PHY 的特定特性:** 不同的 PHY 芯片可能具有不同的寄存器映射和功能。直接使用 `mdio.h` 中的标准定义可能无法覆盖所有 PHY 的特定功能，需要查阅 PHY 芯片的手册。
5. **竞态条件:**  在多线程或中断上下文中访问 MDIO 寄存器时，如果没有进行适当的同步保护，可能会出现竞态条件，导致数据不一致。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

到达 `bionic/libc/kernel/uapi/linux/mdio.h` 的路径通常涉及到 Android 系统与底层硬件的交互：

1. **Android Framework (Java 层):**  应用程序通常通过 Android Framework 提供的 API 进行网络操作，例如 `ConnectivityManager`。
2. **System Services (Java/Native 层):** Framework 的 API 会调用 System Services，例如 `ConnectivityService`，这些服务可能部分由 Java 代码实现，部分通过 JNI 调用 Native 代码。
3. **Native 网络库 (Native 层):**  System Services 的 Native 代码可能会调用更底层的 Native 网络库，例如 `netd` (Network Daemon)。
4. **HAL (Hardware Abstraction Layer) (Native 层):**  `netd` 或其他系统组件最终会通过 HAL 与硬件交互。对于以太网，可能涉及到以太网 HAL 模块。
5. **内核驱动程序 (Kernel 层):**  HAL 模块会调用 Linux 内核中的以太网驱动程序。这些驱动程序会使用 `mdio.h` 中定义的常量来与 PHY 芯片进行通信，例如读写 PHY 的寄存器。

**Frida Hook 示例：**

要 hook 与 MDIO 相关的操作，我们需要找到实际进行 MDIO 读写操作的代码位置。这通常位于内核驱动程序中。由于直接 hook 内核代码比较复杂，更常见的做法是 hook 用户空间的 HAL 模块，观察其如何使用 MDIO 相关的系统调用或 ioctl。

**以下是一个 Hook HAL 模块中可能与 MDIO 交互的函数的示例 (假设 HAL 模块名为 `libethhal.so`，并且有一个名为 `phy_read_register` 的函数用于读取 PHY 寄存器):**

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行，请先启动应用。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libethhal.so", "phy_read_register"), {
    onEnter: function(args) {
        console.log("[*] Calling phy_read_register");
        console.log("    寄存器地址:", args[1].toInt()); // 假设第二个参数是寄存器地址
    },
    onLeave: function(retval) {
        console.log("    返回值 (寄存器值):", retval.toInt());
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**说明:**

1. **找到目标 HAL 模块和函数:**  需要根据具体的 Android 设备和 HAL 实现找到负责以太网 PHY 交互的 HAL 模块 (`libethhal.so` 只是一个假设的名称) 以及相关的函数 (例如 `phy_read_register`, `phy_write_register`)。这可能需要一些逆向分析的工作。
2. **Frida 连接:**  使用 Frida 连接到目标 Android 进程。
3. **Hook `phy_read_register`:**  使用 `Interceptor.attach` hook `phy_read_register` 函数。
4. **`onEnter`:** 在函数调用前打印日志，包括寄存器地址。
5. **`onLeave`:** 在函数返回后打印返回值，即读取到的寄存器值。

**调试步骤:**

1. 确保你的 Android 设备已 root，并且安装了 Frida server。
2. 运行目标 Android 应用。
3. 运行上面的 Frida Python 脚本。
4. 当应用进行以太网相关的操作时，Frida 会拦截对 `phy_read_register` 的调用，并打印相关的寄存器地址和值。你可以根据这些信息，结合 `mdio.h` 中的定义，来理解 HAL 模块是如何与 PHY 芯片交互的。

**请注意:**  实际的 HAL 模块名称、函数名称和参数传递方式可能因设备而异，需要进行具体的分析才能确定。这个示例提供了一个基本的 Hook 思路。

总结来说，`bionic/libc/kernel/uapi/linux/mdio.h` 是一个底层的头文件，定义了用于访问和控制以太网 PHY 芯片的常量。它在 Android 的网络连接功能中扮演着关键角色，被底层的内核驱动程序和 HAL 模块使用。虽然它本身不包含 libc 函数的实现或直接涉及 dynamic linker，但它为这些组件提供了必要的定义，使得它们能够与硬件进行交互。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/mdio.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_MDIO_H__
#define _UAPI__LINUX_MDIO_H__
#include <linux/types.h>
#include <linux/mii.h>
#define MDIO_MMD_PMAPMD 1
#define MDIO_MMD_WIS 2
#define MDIO_MMD_PCS 3
#define MDIO_MMD_PHYXS 4
#define MDIO_MMD_DTEXS 5
#define MDIO_MMD_TC 6
#define MDIO_MMD_AN 7
#define MDIO_MMD_POWER_UNIT 13
#define MDIO_MMD_C22EXT 29
#define MDIO_MMD_VEND1 30
#define MDIO_MMD_VEND2 31
#define MDIO_CTRL1 MII_BMCR
#define MDIO_STAT1 MII_BMSR
#define MDIO_DEVID1 MII_PHYSID1
#define MDIO_DEVID2 MII_PHYSID2
#define MDIO_SPEED 4
#define MDIO_DEVS1 5
#define MDIO_DEVS2 6
#define MDIO_CTRL2 7
#define MDIO_STAT2 8
#define MDIO_PMA_TXDIS 9
#define MDIO_PMA_RXDET 10
#define MDIO_PMA_EXTABLE 11
#define MDIO_PKGID1 14
#define MDIO_PKGID2 15
#define MDIO_AN_ADVERTISE 16
#define MDIO_AN_LPA 19
#define MDIO_PCS_EEE_ABLE 20
#define MDIO_PCS_EEE_ABLE2 21
#define MDIO_PMA_NG_EXTABLE 21
#define MDIO_PCS_EEE_WK_ERR 22
#define MDIO_PHYXS_LNSTAT 24
#define MDIO_AN_EEE_ADV 60
#define MDIO_AN_EEE_LPABLE 61
#define MDIO_AN_EEE_ADV2 62
#define MDIO_AN_EEE_LPABLE2 63
#define MDIO_AN_CTRL2 64
#define MDIO_PMA_10GBT_SWAPPOL 130
#define MDIO_PMA_10GBT_TXPWR 131
#define MDIO_PMA_10GBT_SNR 133
#define MDIO_PMA_10GBR_FSRT_CSR 147
#define MDIO_PMA_10GBR_FECABLE 170
#define MDIO_PCS_10GBX_STAT1 24
#define MDIO_PCS_10GBRT_STAT1 32
#define MDIO_PCS_10GBRT_STAT2 33
#define MDIO_AN_10GBT_CTRL 32
#define MDIO_AN_10GBT_STAT 33
#define MDIO_B10L_PMA_CTRL 2294
#define MDIO_PMA_10T1L_STAT 2295
#define MDIO_PCS_10T1L_CTRL 2278
#define MDIO_PMA_PMD_BT1 18
#define MDIO_AN_T1_CTRL 512
#define MDIO_AN_T1_STAT 513
#define MDIO_AN_T1_ADV_L 514
#define MDIO_AN_T1_ADV_M 515
#define MDIO_AN_T1_ADV_H 516
#define MDIO_AN_T1_LP_L 517
#define MDIO_AN_T1_LP_M 518
#define MDIO_AN_T1_LP_H 519
#define MDIO_AN_10BT1_AN_CTRL 526
#define MDIO_AN_10BT1_AN_STAT 527
#define MDIO_PMA_PMD_BT1_CTRL 2100
#define MDIO_PCS_1000BT1_CTRL 2304
#define MDIO_PCS_1000BT1_STAT 2305
#define MDIO_PMA_LASI_RXCTRL 0x9000
#define MDIO_PMA_LASI_TXCTRL 0x9001
#define MDIO_PMA_LASI_CTRL 0x9002
#define MDIO_PMA_LASI_RXSTAT 0x9003
#define MDIO_PMA_LASI_TXSTAT 0x9004
#define MDIO_PMA_LASI_STAT 0x9005
#define MDIO_CTRL1_SPEEDSELEXT (BMCR_SPEED1000 | BMCR_SPEED100)
#define MDIO_CTRL1_SPEEDSEL (MDIO_CTRL1_SPEEDSELEXT | 0x003c)
#define MDIO_CTRL1_FULLDPLX BMCR_FULLDPLX
#define MDIO_CTRL1_LPOWER BMCR_PDOWN
#define MDIO_CTRL1_RESET BMCR_RESET
#define MDIO_PMA_CTRL1_LOOPBACK 0x0001
#define MDIO_PMA_CTRL1_SPEED1000 BMCR_SPEED1000
#define MDIO_PMA_CTRL1_SPEED100 BMCR_SPEED100
#define MDIO_PCS_CTRL1_LOOPBACK BMCR_LOOPBACK
#define MDIO_PHYXS_CTRL1_LOOPBACK BMCR_LOOPBACK
#define MDIO_AN_CTRL1_RESTART BMCR_ANRESTART
#define MDIO_AN_CTRL1_ENABLE BMCR_ANENABLE
#define MDIO_AN_CTRL1_XNP 0x2000
#define MDIO_PCS_CTRL1_CLKSTOP_EN 0x400
#define MDIO_CTRL1_SPEED10G (MDIO_CTRL1_SPEEDSELEXT | 0x00)
#define MDIO_CTRL1_SPEED10P2B (MDIO_CTRL1_SPEEDSELEXT | 0x04)
#define MDIO_CTRL1_SPEED2_5G (MDIO_CTRL1_SPEEDSELEXT | 0x18)
#define MDIO_CTRL1_SPEED5G (MDIO_CTRL1_SPEEDSELEXT | 0x1c)
#define MDIO_STAT1_LPOWERABLE 0x0002
#define MDIO_STAT1_LSTATUS BMSR_LSTATUS
#define MDIO_STAT1_FAULT 0x0080
#define MDIO_AN_STAT1_LPABLE 0x0001
#define MDIO_AN_STAT1_ABLE BMSR_ANEGCAPABLE
#define MDIO_AN_STAT1_RFAULT BMSR_RFAULT
#define MDIO_AN_STAT1_COMPLETE BMSR_ANEGCOMPLETE
#define MDIO_AN_STAT1_PAGE 0x0040
#define MDIO_AN_STAT1_XNP 0x0080
#define MDIO_SPEED_10G 0x0001
#define MDIO_PMA_SPEED_2B 0x0002
#define MDIO_PMA_SPEED_10P 0x0004
#define MDIO_PMA_SPEED_1000 0x0010
#define MDIO_PMA_SPEED_100 0x0020
#define MDIO_PMA_SPEED_10 0x0040
#define MDIO_PMA_SPEED_2_5G 0x2000
#define MDIO_PMA_SPEED_5G 0x4000
#define MDIO_PCS_SPEED_10P2B 0x0002
#define MDIO_PCS_SPEED_2_5G 0x0040
#define MDIO_PCS_SPEED_5G 0x0080
#define MDIO_DEVS_PRESENT(devad) (1 << (devad))
#define MDIO_DEVS_C22PRESENT MDIO_DEVS_PRESENT(0)
#define MDIO_DEVS_PMAPMD MDIO_DEVS_PRESENT(MDIO_MMD_PMAPMD)
#define MDIO_DEVS_WIS MDIO_DEVS_PRESENT(MDIO_MMD_WIS)
#define MDIO_DEVS_PCS MDIO_DEVS_PRESENT(MDIO_MMD_PCS)
#define MDIO_DEVS_PHYXS MDIO_DEVS_PRESENT(MDIO_MMD_PHYXS)
#define MDIO_DEVS_DTEXS MDIO_DEVS_PRESENT(MDIO_MMD_DTEXS)
#define MDIO_DEVS_TC MDIO_DEVS_PRESENT(MDIO_MMD_TC)
#define MDIO_DEVS_AN MDIO_DEVS_PRESENT(MDIO_MMD_AN)
#define MDIO_DEVS_C22EXT MDIO_DEVS_PRESENT(MDIO_MMD_C22EXT)
#define MDIO_DEVS_VEND1 MDIO_DEVS_PRESENT(MDIO_MMD_VEND1)
#define MDIO_DEVS_VEND2 MDIO_DEVS_PRESENT(MDIO_MMD_VEND2)
#define MDIO_PMA_CTRL2_TYPE 0x000f
#define MDIO_PMA_CTRL2_10GBCX4 0x0000
#define MDIO_PMA_CTRL2_10GBEW 0x0001
#define MDIO_PMA_CTRL2_10GBLW 0x0002
#define MDIO_PMA_CTRL2_10GBSW 0x0003
#define MDIO_PMA_CTRL2_10GBLX4 0x0004
#define MDIO_PMA_CTRL2_10GBER 0x0005
#define MDIO_PMA_CTRL2_10GBLR 0x0006
#define MDIO_PMA_CTRL2_10GBSR 0x0007
#define MDIO_PMA_CTRL2_10GBLRM 0x0008
#define MDIO_PMA_CTRL2_10GBT 0x0009
#define MDIO_PMA_CTRL2_10GBKX4 0x000a
#define MDIO_PMA_CTRL2_10GBKR 0x000b
#define MDIO_PMA_CTRL2_1000BT 0x000c
#define MDIO_PMA_CTRL2_1000BKX 0x000d
#define MDIO_PMA_CTRL2_100BTX 0x000e
#define MDIO_PMA_CTRL2_10BT 0x000f
#define MDIO_PMA_CTRL2_2_5GBT 0x0030
#define MDIO_PMA_CTRL2_5GBT 0x0031
#define MDIO_PMA_CTRL2_BASET1 0x003D
#define MDIO_PCS_CTRL2_TYPE 0x0003
#define MDIO_PCS_CTRL2_10GBR 0x0000
#define MDIO_PCS_CTRL2_10GBX 0x0001
#define MDIO_PCS_CTRL2_10GBW 0x0002
#define MDIO_PCS_CTRL2_10GBT 0x0003
#define MDIO_STAT2_RXFAULT 0x0400
#define MDIO_STAT2_TXFAULT 0x0800
#define MDIO_STAT2_DEVPRST 0xc000
#define MDIO_STAT2_DEVPRST_VAL 0x8000
#define MDIO_PMA_STAT2_LBABLE 0x0001
#define MDIO_PMA_STAT2_10GBEW 0x0002
#define MDIO_PMA_STAT2_10GBLW 0x0004
#define MDIO_PMA_STAT2_10GBSW 0x0008
#define MDIO_PMA_STAT2_10GBLX4 0x0010
#define MDIO_PMA_STAT2_10GBER 0x0020
#define MDIO_PMA_STAT2_10GBLR 0x0040
#define MDIO_PMA_STAT2_10GBSR 0x0080
#define MDIO_PMD_STAT2_TXDISAB 0x0100
#define MDIO_PMA_STAT2_EXTABLE 0x0200
#define MDIO_PMA_STAT2_RXFLTABLE 0x1000
#define MDIO_PMA_STAT2_TXFLTABLE 0x2000
#define MDIO_PCS_STAT2_10GBR 0x0001
#define MDIO_PCS_STAT2_10GBX 0x0002
#define MDIO_PCS_STAT2_10GBW 0x0004
#define MDIO_PCS_STAT2_RXFLTABLE 0x1000
#define MDIO_PCS_STAT2_TXFLTABLE 0x2000
#define MDIO_PMD_TXDIS_GLOBAL 0x0001
#define MDIO_PMD_TXDIS_0 0x0002
#define MDIO_PMD_TXDIS_1 0x0004
#define MDIO_PMD_TXDIS_2 0x0008
#define MDIO_PMD_TXDIS_3 0x0010
#define MDIO_PMD_RXDET_GLOBAL 0x0001
#define MDIO_PMD_RXDET_0 0x0002
#define MDIO_PMD_RXDET_1 0x0004
#define MDIO_PMD_RXDET_2 0x0008
#define MDIO_PMD_RXDET_3 0x0010
#define MDIO_PMA_EXTABLE_10GCX4 0x0001
#define MDIO_PMA_EXTABLE_10GBLRM 0x0002
#define MDIO_PMA_EXTABLE_10GBT 0x0004
#define MDIO_PMA_EXTABLE_10GBKX4 0x0008
#define MDIO_PMA_EXTABLE_10GBKR 0x0010
#define MDIO_PMA_EXTABLE_1000BT 0x0020
#define MDIO_PMA_EXTABLE_1000BKX 0x0040
#define MDIO_PMA_EXTABLE_100BTX 0x0080
#define MDIO_PMA_EXTABLE_10BT 0x0100
#define MDIO_PMA_EXTABLE_BT1 0x0800
#define MDIO_PMA_EXTABLE_NBT 0x4000
#define MDIO_AN_C73_0_S_MASK GENMASK(4, 0)
#define MDIO_AN_C73_0_E_MASK GENMASK(9, 5)
#define MDIO_AN_C73_0_PAUSE BIT(10)
#define MDIO_AN_C73_0_ASM_DIR BIT(11)
#define MDIO_AN_C73_0_C2 BIT(12)
#define MDIO_AN_C73_0_RF BIT(13)
#define MDIO_AN_C73_0_ACK BIT(14)
#define MDIO_AN_C73_0_NP BIT(15)
#define MDIO_AN_C73_1_T_MASK GENMASK(4, 0)
#define MDIO_AN_C73_1_1000BASE_KX BIT(5)
#define MDIO_AN_C73_1_10GBASE_KX4 BIT(6)
#define MDIO_AN_C73_1_10GBASE_KR BIT(7)
#define MDIO_AN_C73_1_40GBASE_KR4 BIT(8)
#define MDIO_AN_C73_1_40GBASE_CR4 BIT(9)
#define MDIO_AN_C73_1_100GBASE_CR10 BIT(10)
#define MDIO_AN_C73_1_100GBASE_KP4 BIT(11)
#define MDIO_AN_C73_1_100GBASE_KR4 BIT(12)
#define MDIO_AN_C73_1_100GBASE_CR4 BIT(13)
#define MDIO_AN_C73_1_25GBASE_R_S BIT(14)
#define MDIO_AN_C73_1_25GBASE_R BIT(15)
#define MDIO_AN_C73_2_2500BASE_KX BIT(0)
#define MDIO_AN_C73_2_5GBASE_KR BIT(1)
#define MDIO_PHYXS_LNSTAT_SYNC0 0x0001
#define MDIO_PHYXS_LNSTAT_SYNC1 0x0002
#define MDIO_PHYXS_LNSTAT_SYNC2 0x0004
#define MDIO_PHYXS_LNSTAT_SYNC3 0x0008
#define MDIO_PHYXS_LNSTAT_ALIGN 0x1000
#define MDIO_PMA_10GBT_SWAPPOL_ABNX 0x0001
#define MDIO_PMA_10GBT_SWAPPOL_CDNX 0x0002
#define MDIO_PMA_10GBT_SWAPPOL_AREV 0x0100
#define MDIO_PMA_10GBT_SWAPPOL_BREV 0x0200
#define MDIO_PMA_10GBT_SWAPPOL_CREV 0x0400
#define MDIO_PMA_10GBT_SWAPPOL_DREV 0x0800
#define MDIO_PMA_10GBT_TXPWR_SHORT 0x0001
#define MDIO_PMA_10GBT_SNR_BIAS 0x8000
#define MDIO_PMA_10GBT_SNR_MAX 127
#define MDIO_PMA_10GBR_FECABLE_ABLE 0x0001
#define MDIO_PMA_10GBR_FECABLE_ERRABLE 0x0002
#define MDIO_PMA_10GBR_FSRT_ENABLE 0x0001
#define MDIO_PCS_10GBRT_STAT1_BLKLK 0x0001
#define MDIO_PCS_10GBRT_STAT2_ERR 0x00ff
#define MDIO_PCS_10GBRT_STAT2_BER 0x3f00
#define MDIO_AN_10GBT_CTRL_ADVFSRT2_5G 0x0020
#define MDIO_AN_10GBT_CTRL_ADV2_5G 0x0080
#define MDIO_AN_10GBT_CTRL_ADV5G 0x0100
#define MDIO_AN_10GBT_CTRL_ADV10G 0x1000
#define MDIO_AN_10GBT_STAT_LP2_5G 0x0020
#define MDIO_AN_10GBT_STAT_LP5G 0x0040
#define MDIO_AN_10GBT_STAT_LPTRR 0x0200
#define MDIO_AN_10GBT_STAT_LPLTABLE 0x0400
#define MDIO_AN_10GBT_STAT_LP10G 0x0800
#define MDIO_AN_10GBT_STAT_REMOK 0x1000
#define MDIO_AN_10GBT_STAT_LOCOK 0x2000
#define MDIO_AN_10GBT_STAT_MS 0x4000
#define MDIO_AN_10GBT_STAT_MSFLT 0x8000
#define MDIO_PMA_10T1L_CTRL_LB_EN 0x0001
#define MDIO_PMA_10T1L_CTRL_EEE_EN 0x0400
#define MDIO_PMA_10T1L_CTRL_LOW_POWER 0x0800
#define MDIO_PMA_10T1L_CTRL_2V4_EN 0x1000
#define MDIO_PMA_10T1L_CTRL_TX_DIS 0x4000
#define MDIO_PMA_10T1L_CTRL_PMA_RST 0x8000
#define MDIO_PMA_10T1L_STAT_LINK 0x0001
#define MDIO_PMA_10T1L_STAT_FAULT 0x0002
#define MDIO_PMA_10T1L_STAT_POLARITY 0x0004
#define MDIO_PMA_10T1L_STAT_RECV_FAULT 0x0200
#define MDIO_PMA_10T1L_STAT_EEE 0x0400
#define MDIO_PMA_10T1L_STAT_LOW_POWER 0x0800
#define MDIO_PMA_10T1L_STAT_2V4_ABLE 0x1000
#define MDIO_PMA_10T1L_STAT_LB_ABLE 0x2000
#define MDIO_PCS_10T1L_CTRL_LB 0x4000
#define MDIO_PCS_10T1L_CTRL_RESET 0x8000
#define MDIO_PMA_PMD_BT1_B100_ABLE 0x0001
#define MDIO_PMA_PMD_BT1_B1000_ABLE 0x0002
#define MDIO_PMA_PMD_BT1_B10L_ABLE 0x0004
#define MDIO_AN_T1_ADV_L_PAUSE_CAP ADVERTISE_PAUSE_CAP
#define MDIO_AN_T1_ADV_L_PAUSE_ASYM ADVERTISE_PAUSE_ASYM
#define MDIO_AN_T1_ADV_L_FORCE_MS 0x1000
#define MDIO_AN_T1_ADV_L_REMOTE_FAULT ADVERTISE_RFAULT
#define MDIO_AN_T1_ADV_L_ACK ADVERTISE_LPACK
#define MDIO_AN_T1_ADV_L_NEXT_PAGE_REQ ADVERTISE_NPAGE
#define MDIO_AN_T1_ADV_M_B10L 0x4000
#define MDIO_AN_T1_ADV_M_1000BT1 0x0080
#define MDIO_AN_T1_ADV_M_100BT1 0x0020
#define MDIO_AN_T1_ADV_M_MST 0x0010
#define MDIO_AN_T1_ADV_H_10L_TX_HI_REQ 0x1000
#define MDIO_AN_T1_ADV_H_10L_TX_HI 0x2000
#define MDIO_AN_T1_LP_L_PAUSE_CAP LPA_PAUSE_CAP
#define MDIO_AN_T1_LP_L_PAUSE_ASYM LPA_PAUSE_ASYM
#define MDIO_AN_T1_LP_L_FORCE_MS 0x1000
#define MDIO_AN_T1_LP_L_REMOTE_FAULT LPA_RFAULT
#define MDIO_AN_T1_LP_L_ACK LPA_LPACK
#define MDIO_AN_T1_LP_L_NEXT_PAGE_REQ LPA_NPAGE
#define MDIO_AN_T1_LP_M_MST 0x0010
#define MDIO_AN_T1_LP_M_B10L 0x4000
#define MDIO_AN_T1_LP_H_10L_TX_HI_REQ 0x1000
#define MDIO_AN_T1_LP_H_10L_TX_HI 0x2000
#define MDIO_AN_10BT1_AN_CTRL_ADV_EEE_T1L 0x4000
#define MDIO_AN_10BT1_AN_STAT_LPA_EEE_T1L 0x4000
#define MDIO_PMA_PMD_BT1_CTRL_STRAP 0x000F
#define MDIO_PMA_PMD_BT1_CTRL_STRAP_B1000 0x0001
#define MDIO_PMA_PMD_BT1_CTRL_CFG_MST 0x4000
#define MDIO_PCS_1000BT1_CTRL_LOW_POWER 0x0800
#define MDIO_PCS_1000BT1_CTRL_DISABLE_TX 0x4000
#define MDIO_PCS_1000BT1_CTRL_RESET 0x8000
#define MDIO_PCS_1000BT1_STAT_LINK 0x0004
#define MDIO_PCS_1000BT1_STAT_FAULT 0x0080
#define MDIO_AN_EEE_ADV_100TX 0x0002
#define MDIO_AN_EEE_ADV_1000T 0x0004
#define MDIO_EEE_100TX MDIO_AN_EEE_ADV_100TX
#define MDIO_EEE_1000T MDIO_AN_EEE_ADV_1000T
#define MDIO_EEE_10GT 0x0008
#define MDIO_EEE_1000KX 0x0010
#define MDIO_EEE_10GKX4 0x0020
#define MDIO_EEE_10GKR 0x0040
#define MDIO_EEE_40GR_FW 0x0100
#define MDIO_EEE_40GR_DS 0x0200
#define MDIO_EEE_100GR_FW 0x1000
#define MDIO_EEE_100GR_DS 0x2000
#define MDIO_EEE_2_5GT 0x0001
#define MDIO_EEE_5GT 0x0002
#define MDIO_AN_THP_BP2_5GT 0x0008
#define MDIO_PMA_NG_EXTABLE_2_5GBT 0x0001
#define MDIO_PMA_NG_EXTABLE_5GBT 0x0002
#define MDIO_PMA_LASI_RX_PHYXSLFLT 0x0001
#define MDIO_PMA_LASI_RX_PCSLFLT 0x0008
#define MDIO_PMA_LASI_RX_PMALFLT 0x0010
#define MDIO_PMA_LASI_RX_OPTICPOWERFLT 0x0020
#define MDIO_PMA_LASI_RX_WISLFLT 0x0200
#define MDIO_PMA_LASI_TX_PHYXSLFLT 0x0001
#define MDIO_PMA_LASI_TX_PCSLFLT 0x0008
#define MDIO_PMA_LASI_TX_PMALFLT 0x0010
#define MDIO_PMA_LASI_TX_LASERPOWERFLT 0x0080
#define MDIO_PMA_LASI_TX_LASERTEMPFLT 0x0100
#define MDIO_PMA_LASI_TX_LASERBICURRFLT 0x0200
#define MDIO_PMA_LASI_LSALARM 0x0001
#define MDIO_PMA_LASI_TXALARM 0x0002
#define MDIO_PMA_LASI_RXALARM 0x0004
#define MDIO_PHY_ID_C45 0x8000
#define MDIO_PHY_ID_PRTAD 0x03e0
#define MDIO_PHY_ID_DEVAD 0x001f
#define MDIO_PHY_ID_C45_MASK (MDIO_PHY_ID_C45 | MDIO_PHY_ID_PRTAD | MDIO_PHY_ID_DEVAD)
#define MDIO_USXGMII_EEE_CLK_STP 0x0080
#define MDIO_USXGMII_EEE 0x0100
#define MDIO_USXGMII_SPD_MASK 0x0e00
#define MDIO_USXGMII_FULL_DUPLEX 0x1000
#define MDIO_USXGMII_DPX_SPD_MASK 0x1e00
#define MDIO_USXGMII_10 0x0000
#define MDIO_USXGMII_10HALF 0x0000
#define MDIO_USXGMII_10FULL 0x1000
#define MDIO_USXGMII_100 0x0200
#define MDIO_USXGMII_100HALF 0x0200
#define MDIO_USXGMII_100FULL 0x1200
#define MDIO_USXGMII_1000 0x0400
#define MDIO_USXGMII_1000HALF 0x0400
#define MDIO_USXGMII_1000FULL 0x1400
#define MDIO_USXGMII_10G 0x0600
#define MDIO_USXGMII_10GHALF 0x0600
#define MDIO_USXGMII_10GFULL 0x1600
#define MDIO_USXGMII_2500 0x0800
#define MDIO_USXGMII_2500HALF 0x0800
#define MDIO_USXGMII_2500FULL 0x1800
#define MDIO_USXGMII_5000 0x0a00
#define MDIO_USXGMII_5000HALF 0x0a00
#define MDIO_USXGMII_5000FULL 0x1a00
#define MDIO_USXGMII_LINK 0x8000
#endif
```