Response:
Let's break down the thought process for analyzing the provided C header file.

**1. Initial Understanding - What is this?**

The first step is recognizing the context. The prompt states this is a header file for the `genwqe` driver in Android's Bionic library. Keywords like "driver," "kernel," and the path `bionic/libc/kernel/uapi/linux/genwqe/` immediately suggest it's a low-level interface for interacting with hardware. The `uapi` part confirms it's meant for user-space programs.

**2. Core Functionality Identification - What does it *do*?**

The filename `genwqe_card.h` hints at controlling a "genwqe" card. Scanning the definitions reveals:

* **Device Identification:** `GENWQE_DEVNAME` ("genwqe") suggests the device name used for opening the driver.
* **Card Types:** `GENWQE_TYPE_ALTERA_*` indicates support for different hardware versions.
* **Memory Mapping:** `GENWQE_UID_OFFS`, `GENWQE_SLU_OFFS`, `GENWQE_HSU_OFFS`, `GENWQE_APP_OFFS` point to memory regions, likely for different functional units within the card.
* **Registers:**  A large number of `IO_*` constants strongly suggest memory-mapped registers for controlling and monitoring the hardware. The prefixes `IO_SLU_`, `IO_HSU_`, `IO_APP_`, `IO_SLC_`, `IO_PF_SLC_` further categorize these registers.
* **Data Structures:** `genwqe_reg_io`, `genwqe_bitstream`, `genwqe_debug_data`, `genwqe_ddcb_cmd`, `genwqe_mem` represent data exchanged with the driver.
* **IOCTLs:** `GENWQE_IOC_CODE` and the `_IOR`, `_IOW`, `_IOWR` macros define ioctl commands for interacting with the driver. These commands have names like `GENWQE_READ_REG64`, `GENWQE_WRITE_REG64`, `GENWQE_EXECUTE_DDCB`, etc.
* **States:** `enum genwqe_card_state` indicates different operational states of the card.
* **Commands:**  Definitions like `SLCMD_ECHO_SYNC`, `SLCMD_MOVE_FLASH` suggest specific commands that can be sent to the hardware.

**3. Connecting to Android - Why is this in Bionic?**

Since Bionic is Android's C library, this header file allows user-space Android processes (including system services and potentially NDK apps) to interact with `genwqe` hardware. The most likely scenario is that this hardware provides some form of acceleration or specialized processing.

**4. Detailed Analysis - Decoding the specifics.**

* **libc Functions:** The header file itself doesn't *implement* libc functions. Instead, it *uses* standard C preprocessor features like `#ifndef`, `#define`, `offsetof`. The `_IOR`, `_IOW`, `_IOWR` macros are related to the `ioctl` system call, a standard POSIX interface.
* **Dynamic Linker:** This header file doesn't directly involve the dynamic linker. It defines structures and constants, which are compile-time information. However, if a library using this header was dynamically linked, the linker would handle its loading.
* **Logic and Assumptions:** The structure names and constants strongly suggest a hierarchical hardware design with units like SLU, HSU, and APP. The `DDCB` structures likely represent Direct Data Command Blocks, a common pattern for hardware interaction. The `IOCTL` commands are clearly designed for reading/writing registers, executing commands, and managing memory.
* **Common Errors:**  Incorrectly using the ioctl commands (wrong size, wrong structure), providing invalid register addresses, or not handling errors returned by `ioctl` are common pitfalls.

**5. Android Framework/NDK Interaction - How does user code reach this?**

The flow likely involves:

1. **NDK App or System Service:** User-space code needs to interact with the `genwqe` device.
2. **Open the Device:** Use the `open()` system call with `/dev/genwqe`.
3. **`ioctl()` Calls:** Use the `ioctl()` system call with the defined `GENWQE_*` commands and associated structures to control the hardware.
4. **Kernel Driver:** The `ioctl()` calls are intercepted by the kernel, which has a driver for the `genwqe` device.
5. **Hardware Interaction:** The kernel driver translates the ioctl commands into low-level hardware operations.

**6. Frida Hooking - Practical Debugging.**

Frida is an excellent tool for intercepting function calls. The key functions to hook are `open()` and `ioctl()`. By hooking these, you can see which process is interacting with the device, what commands are being sent, and what data is being exchanged.

**Self-Correction/Refinement during the process:**

* **Initially, I might have focused too much on the individual register definitions.**  Realizing the overarching purpose (hardware control) and the structures is more important in the initial analysis.
* **The prompt asked for libc function implementation details.**  I corrected myself to point out that the header *uses* libc features but doesn't implement them.
* **The dynamic linker question requires understanding the scope of the header file.** While the header itself isn't about linking, code using it would be subject to the dynamic linker's processes. Providing a hypothetical SO layout demonstrates this connection.

By following these steps, focusing on the context, identifying key components, and then drilling down into the specifics, a comprehensive understanding of the header file can be achieved. The addition of Android-specific connections and practical debugging examples further enhances the analysis.
这个头文件 `bionic/libc/kernel/uapi/linux/genwqe/genwqe_card.h` 定义了 Linux 内核中 `genwqe` 字符设备驱动的用户空间 API。它主要用于用户空间程序与 `genwqe` 硬件加速卡进行交互。由于它位于 Android 的 Bionic 库中，这意味着 Android 系统支持使用这种硬件加速卡。

**功能列表:**

1. **定义 `genwqe` 设备名称:**  `GENWQE_DEVNAME "genwqe"` 定义了用户空间程序打开 `genwqe` 设备的名称，通常是通过 `/dev/genwqe` 访问。
2. **定义 `genwqe` 卡的类型:** `GENWQE_TYPE_ALTERA_230`, `GENWQE_TYPE_ALTERA_530`, `GENWQE_TYPE_ALTERA_A4`, `GENWQE_TYPE_ALTERA_A7` 定义了支持的不同 `genwqe` 硬件卡的类型。
3. **定义内存偏移量:** `GENWQE_UID_OFFS`, `GENWQE_SLU_OFFS`, `GENWQE_HSU_OFFS`, `GENWQE_APP_OFFS` 定义了卡内不同单元 (SLU, HSU, APP) 的内存映射偏移量，用于访问这些单元的寄存器。
4. **定义寄存器地址:**  大量的 `IO_*` 常量定义了 `genwqe` 卡上各种寄存器的地址。这些寄存器用于控制硬件的行为、读取状态和错误信息。例如，`IO_SLU_UNITCFG` 是 SLU 单元的配置寄存器。
5. **定义常量和掩码:**  例如 `TIMEOUT_250MS`, `HEARTBEAT_DISABLE`, `IO_SLU_UNITCFG_TYPE_MASK` 用于配置寄存器或比较寄存器值。
6. **定义数据结构:**  `genwqe_reg_io`, `genwqe_bitstream`, `genwqe_debug_data`, `genwqe_ddcb_cmd`, `genwqe_mem` 等结构体定义了用户空间和内核空间之间传递数据的格式。
7. **定义 IOCTL 命令:**  `GENWQE_IOC_CODE` 以及一系列 `_IOR`, `_IOW`, `_IOWR` 宏定义的 IOCTL 命令，用于执行各种操作，如读写寄存器、获取卡状态、操作内存、执行命令等。 例如 `GENWQE_READ_REG64` 用于读取 64 位寄存器。
8. **定义卡的状态:** `enum genwqe_card_state` 定义了 `genwqe` 卡的不同状态，例如 `GENWQE_CARD_UNUSED`, `GENWQE_CARD_USED`, `GENWQE_CARD_FATAL_ERROR`。
9. **定义 DDCB (Direct Data Command Block) 相关常量:**  定义了用于与硬件交互的命令块结构和相关的选项、返回码等。
10. **定义 SLCMD (SLU Command) 相关常量:** 定义了 Specific Logic Unit (SLU) 可以执行的特定命令。

**与 Android 功能的关系及举例说明:**

`genwqe` 卡很可能是一种硬件加速器，用于执行特定的计算任务。在 Android 中，这种硬件加速可以用于提高某些特定应用或服务的性能，例如：

* **加速机器学习推理:** 如果 `genwqe` 卡擅长矩阵运算或其他机器学习相关的计算，Android 框架或 NDK 应用可以使用它来加速模型推理过程。例如，一个图像识别应用可以使用 `genwqe` 卡来加速卷积神经网络的计算。
* **加速数据加密/解密:** 如果 `genwqe` 卡具有高效的加密/解密能力，Android 系统或应用可以使用它来加速数据保护相关的操作。
* **特定领域的硬件加速:**  `genwqe` 卡可能针对特定的应用领域进行了优化，例如高性能计算、网络处理等。Android 系统中运行的特定应用如果能利用这些特性，可以获得显著的性能提升。

**举例说明:**

假设一个 Android 应用需要进行大量的矩阵乘法运算。该应用可以通过 NDK 调用底层的 C/C++ 代码，然后使用 `open("/dev/genwqe", ...)` 打开 `genwqe` 设备。接着，通过 `ioctl` 系统调用，使用诸如 `GENWQE_WRITE_REG64` 将需要计算的数据地址和参数写入 `genwqe` 卡的特定寄存器，并使用 `GENWQE_EXECUTE_DDCB` 或其他类似的 IOCTL 命令来触发硬件开始计算。计算完成后，应用可以再次通过 `ioctl` 读取结果。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**不包含** libc 函数的实现。它只是定义了一些宏、常量和数据结构，用于用户空间程序与内核驱动进行交互。

用户空间程序会使用标准的 libc 函数，例如 `open()`, `close()`, `ioctl()` 来与 `genwqe` 设备进行交互。

* **`open()`:**  `open()` 函数是 POSIX 标准的系统调用，用于打开文件或设备。在这里，它用于打开 `/dev/genwqe` 设备文件，从而与 `genwqe` 驱动建立连接。`open()` 的实现位于 Bionic 的 `libc/bionic/syscalls.c` 或类似的文件中，最终会陷入内核，由内核的文件系统层处理，并调用 `genwqe` 驱动的 `open` 方法。
* **`close()`:** `close()` 函数用于关闭打开的文件或设备描述符。它的实现方式类似 `open()`，最终会调用 `genwqe` 驱动的 `close` 方法。
* **`ioctl()`:** `ioctl()` 函数是用于设备特定操作的系统调用。用户空间程序通过 `ioctl()` 发送命令和数据到内核驱动。`ioctl()` 的实现位于 Bionic 的 `libc/bionic/syscalls.c` 或类似的文件中，它会陷入内核，内核根据传入的设备描述符找到对应的驱动，并调用该驱动的 `ioctl` 方法。 在 `genwqe` 驱动中，会根据 `ioctl` 命令（例如 `GENWQE_READ_REG64`）执行相应的硬件操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。它定义的是内核接口。然而，如果一个用户空间库（例如一个 `.so` 文件）使用了这个头文件中定义的常量和结构体来与 `genwqe` 设备交互，那么 dynamic linker 会负责加载这个库。

**so 布局样本 (假设一个名为 `libgenwqewrapper.so` 的库使用了这个头文件):**

```
libgenwqewrapper.so:
    .init          # 初始化段
    .plt           # 程序链接表
    .text          # 代码段，包含使用 genwqe_card.h 中定义的常量和结构体的函数
        - genwqe_init()
        - genwqe_read_register()
        - genwqe_execute_command()
        ...
    .rodata        # 只读数据段，可能包含一些常量
    .data          # 数据段，可能包含全局变量
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息
    .symtab        # 符号表
    .strtab        # 字符串表
    ...
```

**链接的处理过程:**

1. **加载:** 当一个依赖 `libgenwqewrapper.so` 的应用启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载这个 `.so` 文件到进程的内存空间。
2. **符号解析:** Dynamic linker 会解析 `libgenwqewrapper.so` 中未定义的符号，并尝试在其他已加载的共享库或主程序中找到这些符号的定义。在这个场景下，`libgenwqewrapper.so` 可能会调用 libc 的 `open()` 和 `ioctl()` 函数，dynamic linker 会将这些调用链接到 Bionic 的 libc.so 中的实现。
3. **重定位:** Dynamic linker 会修改 `libgenwqewrapper.so` 中的一些代码和数据，以确保它们在加载到内存中的实际地址上能够正确工作。例如，对全局变量的访问和函数调用地址需要根据加载地址进行调整。
4. **初始化:** 加载和链接完成后，dynamic linker 会执行 `libgenwqewrapper.so` 的 `.init` 段中的代码，进行一些初始化操作。

**假设输入与输出 (针对 `ioctl` 系统调用):**

假设用户空间程序想读取 `IO_SLU_UNITCFG` 寄存器的值。

**假设输入:**

* **文件描述符:** 通过 `open("/dev/genwqe", ...)` 获取的 `genwqe` 设备的文件描述符 `fd`。
* **`ioctl` 请求:** `GENWQE_READ_REG64`。
* **`argp` (指向 `struct genwqe_reg_io` 的指针):**
  ```c
  struct genwqe_reg_io reg_io;
  reg_io.num = IO_SLU_UNITCFG; // 要读取的寄存器地址
  reg_io.val64 = 0;           // 用于接收读取到的值
  ```

**假设输出:**

如果 `ioctl` 调用成功，返回值通常为 0。`reg_io.val64` 将包含 `IO_SLU_UNITCFG` 寄存器中读取到的 64 位值。如果发生错误，`ioctl` 返回 -1，并设置 `errno` 以指示错误类型。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记打开设备:** 在使用任何 `ioctl` 命令之前，必须先使用 `open()` 函数打开 `/dev/genwqe` 设备。
   ```c
   int fd = open("/dev/genwqe", O_RDWR);
   if (fd < 0) {
       perror("Failed to open /dev/genwqe");
       // ... 错误处理
   }
   // ... 使用 ioctl ...
   close(fd); // 记得关闭设备
   ```
   **错误:**  直接调用 `ioctl` 而没有先 `open` 设备会导致文件描述符无效的错误。

2. **传递错误的 `ioctl` 请求码:** 使用了未定义的或不适用的 `ioctl` 命令码。
   ```c
   struct genwqe_reg_io reg_io;
   reg_io.num = IO_SLU_UNITCFG;
   // 错误：使用了错误的 IOCTL 请求码
   if (ioctl(fd, _IOR(GENWQE_IOC_CODE, 999, struct genwqe_reg_io), &reg_io) < 0) {
       perror("ioctl failed");
       // ... 错误处理
   }
   ```

3. **传递错误大小的参数结构体:**  `ioctl` 命令通常需要传递一个指向特定结构体的指针。如果传递的结构体大小不匹配，会导致数据读取或写入错误。

4. **访问无效的寄存器地址:**  尝试读取或写入未定义的或保留的寄存器地址可能会导致硬件错误或系统崩溃。

5. **权限问题:** 用户空间程序可能没有足够的权限访问 `/dev/genwqe` 设备。这通常需要 root 权限或特定的用户组权限。

6. **竞争条件:** 如果多个进程或线程同时访问 `genwqe` 设备，可能会导致竞争条件和不可预测的行为。驱动程序需要进行适当的同步控制。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK 应用:** 一个使用 `genwqe` 硬件加速的 Android 应用通常会通过 NDK (Native Development Kit) 使用 C/C++ 代码与内核驱动交互。

2. **打开设备:** NDK 代码会使用 `open("/dev/genwqe", O_RDWR)` 打开设备文件。这个 `open` 调用会通过 Bionic 的 libc 转发到内核。

3. **执行 IOCTL:** NDK 代码会使用 `ioctl(fd, request, argp)` 发送命令到驱动。这里的 `request` 就是 `GENWQE_READ_REG64` 等定义的 IOCTL 命令，`argp` 是指向数据结构（如 `struct genwqe_reg_io`）的指针。

4. **内核驱动:** 内核中的 `genwqe` 驱动程序会接收到 `ioctl` 请求，并根据请求码执行相应的硬件操作。

**Frida Hook 示例:**

假设我们要监控一个 NDK 应用与 `genwqe` 驱动的交互，可以 Hook `open` 和 `ioctl` 函数。

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        const pathname = Memory.readCString(args[0]);
        const flags = args[1].toInt();
        this.is_genwqe = pathname.includes("genwqe");
        if (this.is_genwqe) {
            console.log("[*] Calling open('" + pathname + "', " + flags + ")");
        }
    },
    onLeave: function(retval) {
        if (this.is_genwqe) {
            console.log("[*] open returned: " + retval);
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt();
        const request = args[1].toInt();
        const argp = args[2];

        // 这里可以根据 request 的值来判断具体的 IOCTL 命令
        let commandName = "Unknown IOCTL";
        if (request === 0xa500001e) { // 替换为 GENWQE_READ_REG64 的实际值
            commandName = "GENWQE_READ_REG64";
            // 可以进一步解析 argp 指向的数据结构
        } else if (request === 0xa500001f) { // 替换为 GENWQE_WRITE_REG64 的实际值
            commandName = "GENWQE_WRITE_REG64";
            // 可以进一步解析 argp 指向的数据结构
        }
        // ... 添加其他 IOCTL 命令的判断

        console.log("[*] Calling ioctl(fd=" + fd + ", request=" + request + " (" + commandName + "), argp=" + argp + ")");
        this.is_genwqe_ioctl = false;
        try {
            const filename = Kernel.readCStringFromFD(fd);
            if (filename && filename.includes("genwqe")) {
                this.is_genwqe_ioctl = true;
            }
        } catch (e) {
            // ignore
        }
        if (this.is_genwqe_ioctl) {
             // 可以尝试读取和打印 argp 指向的数据
             // 注意：需要根据具体的 IOCTL 命令和数据结构进行解析
             // 例如，对于 GENWQE_READ_REG64：
             // const reg_io = Memory.readByteArray(argp, 16); // 假设 struct genwqe_reg_io 大小为 16 字节
             // console.log("[*] ioctl argp data: " + hexdump(reg_io));
        }
    },
    onLeave: function(retval) {
        if (this.is_genwqe_ioctl) {
            console.log("[*] ioctl returned: " + retval);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **连接到设备和进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到 USB 设备上的目标 Android 应用进程。
3. **定义消息处理函数:** `on_message` 函数用于接收来自 Frida Hook 的消息并打印。
4. **Frida Script 代码:**
   - **Hook `open` 函数:** 拦截 `libc.so` 中的 `open` 函数，记录打开的文件路径和标志，并判断是否打开了包含 "genwqe" 的文件。
   - **Hook `ioctl` 函数:** 拦截 `libc.so` 中的 `ioctl` 函数，记录文件描述符、请求码和 `argp` 指针。
   - **解析 IOCTL 命令:**  根据 `request` 的值判断具体的 IOCTL 命令 (需要查阅相关文档或反汇编来确定具体的请求码)。
   - **读取 `argp` 数据:**  尝试读取 `argp` 指向的数据，并根据具体的 IOCTL 命令和数据结构进行解析和打印。**注意：直接读取和解析内存需要小心，确保偏移量和大小正确。**
5. **创建和加载 Script:** 使用 `session.create_script(script_code)` 创建 Frida Script，并使用 `script.load()` 加载到目标进程。
6. **保持运行:** `sys.stdin.read()` 使脚本保持运行状态，直到手动停止。

通过运行这个 Frida 脚本，你可以在应用与 `genwqe` 驱动交互时，在终端看到 `open` 和 `ioctl` 函数的调用信息，以及传递的参数，从而调试和分析交互过程。你需要替换 `your.app.package.name` 为你要监控的应用的实际包名，并根据实际的 `GENWQE_*` 常量值更新 `ioctl` hook 中的判断条件。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/genwqe/genwqe_card.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __GENWQE_CARD_H__
#define __GENWQE_CARD_H__
#include <linux/types.h>
#include <linux/ioctl.h>
#define GENWQE_DEVNAME "genwqe"
#define GENWQE_TYPE_ALTERA_230 0x00
#define GENWQE_TYPE_ALTERA_530 0x01
#define GENWQE_TYPE_ALTERA_A4 0x02
#define GENWQE_TYPE_ALTERA_A7 0x03
#define GENWQE_UID_OFFS(uid) ((uid) << 24)
#define GENWQE_SLU_OFFS GENWQE_UID_OFFS(0)
#define GENWQE_HSU_OFFS GENWQE_UID_OFFS(1)
#define GENWQE_APP_OFFS GENWQE_UID_OFFS(2)
#define GENWQE_MAX_UNITS 3
#define IO_EXTENDED_ERROR_POINTER 0x00000048
#define IO_ERROR_INJECT_SELECTOR 0x00000060
#define IO_EXTENDED_DIAG_SELECTOR 0x00000070
#define IO_EXTENDED_DIAG_READ_MBX 0x00000078
#define IO_EXTENDED_DIAG_MAP(ring) (0x00000500 | ((ring) << 3))
#define GENWQE_EXTENDED_DIAG_SELECTOR(ring,trace) (((ring) << 8) | (trace))
#define IO_SLU_UNITCFG 0x00000000
#define IO_SLU_UNITCFG_TYPE_MASK 0x000000000ff00000
#define IO_SLU_FIR 0x00000008
#define IO_SLU_FIR_CLR 0x00000010
#define IO_SLU_FEC 0x00000018
#define IO_SLU_ERR_ACT_MASK 0x00000020
#define IO_SLU_ERR_ATTN_MASK 0x00000028
#define IO_SLU_FIRX1_ACT_MASK 0x00000030
#define IO_SLU_FIRX0_ACT_MASK 0x00000038
#define IO_SLU_SEC_LEM_DEBUG_OVR 0x00000040
#define IO_SLU_EXTENDED_ERR_PTR 0x00000048
#define IO_SLU_COMMON_CONFIG 0x00000060
#define IO_SLU_FLASH_FIR 0x00000108
#define IO_SLU_SLC_FIR 0x00000110
#define IO_SLU_RIU_TRAP 0x00000280
#define IO_SLU_FLASH_FEC 0x00000308
#define IO_SLU_SLC_FEC 0x00000310
#define IO_SLC_QUEUE_SEGMENT 0x00010000
#define IO_SLC_VF_QUEUE_SEGMENT 0x00050000
#define IO_SLC_QUEUE_OFFSET 0x00010008
#define IO_SLC_VF_QUEUE_OFFSET 0x00050008
#define IO_SLC_QUEUE_CONFIG 0x00010010
#define IO_SLC_VF_QUEUE_CONFIG 0x00050010
#define IO_SLC_APPJOB_TIMEOUT 0x00010018
#define IO_SLC_VF_APPJOB_TIMEOUT 0x00050018
#define TIMEOUT_250MS 0x0000000f
#define HEARTBEAT_DISABLE 0x0000ff00
#define IO_SLC_QUEUE_INITSQN 0x00010020
#define IO_SLC_VF_QUEUE_INITSQN 0x00050020
#define IO_SLC_QUEUE_WRAP 0x00010028
#define IO_SLC_VF_QUEUE_WRAP 0x00050028
#define IO_SLC_QUEUE_STATUS 0x00010100
#define IO_SLC_VF_QUEUE_STATUS 0x00050100
#define IO_SLC_QUEUE_WTIME 0x00010030
#define IO_SLC_VF_QUEUE_WTIME 0x00050030
#define IO_SLC_QUEUE_ERRCNTS 0x00010038
#define IO_SLC_VF_QUEUE_ERRCNTS 0x00050038
#define IO_SLC_QUEUE_LRW 0x00010040
#define IO_SLC_VF_QUEUE_LRW 0x00050040
#define IO_SLC_FREE_RUNNING_TIMER 0x00010108
#define IO_SLC_VF_FREE_RUNNING_TIMER 0x00050108
#define IO_PF_SLC_VIRTUAL_REGION 0x00050000
#define IO_PF_SLC_VIRTUAL_WINDOW 0x00060000
#define IO_PF_SLC_JOBPEND(n) (0x00061000 + 8 * (n))
#define IO_SLC_JOBPEND(n) IO_PF_SLC_JOBPEND(n)
#define IO_SLU_SLC_PARSE_TRAP(n) (0x00011000 + 8 * (n))
#define IO_SLU_SLC_DISP_TRAP(n) (0x00011200 + 8 * (n))
#define IO_SLC_CFGREG_GFIR 0x00020000
#define GFIR_ERR_TRIGGER 0x0000ffff
#define IO_SLC_CFGREG_SOFTRESET 0x00020018
#define IO_SLC_MISC_DEBUG 0x00020060
#define IO_SLC_MISC_DEBUG_CLR 0x00020068
#define IO_SLC_MISC_DEBUG_SET 0x00020070
#define IO_SLU_TEMPERATURE_SENSOR 0x00030000
#define IO_SLU_TEMPERATURE_CONFIG 0x00030008
#define IO_SLU_VOLTAGE_CONTROL 0x00030080
#define IO_SLU_VOLTAGE_NOMINAL 0x00000000
#define IO_SLU_VOLTAGE_DOWN5 0x00000006
#define IO_SLU_VOLTAGE_UP5 0x00000007
#define IO_SLU_LEDCONTROL 0x00030100
#define IO_SLU_FLASH_DIRECTACCESS 0x00040010
#define IO_SLU_FLASH_DIRECTACCESS2 0x00040020
#define IO_SLU_FLASH_CMDINTF 0x00040030
#define IO_SLU_BITSTREAM 0x00040040
#define IO_HSU_ERR_BEHAVIOR 0x01001010
#define IO_SLC2_SQB_TRAP 0x00062000
#define IO_SLC2_QUEUE_MANAGER_TRAP 0x00062008
#define IO_SLC2_FLS_MASTER_TRAP 0x00062010
#define IO_HSU_UNITCFG 0x01000000
#define IO_HSU_FIR 0x01000008
#define IO_HSU_FIR_CLR 0x01000010
#define IO_HSU_FEC 0x01000018
#define IO_HSU_ERR_ACT_MASK 0x01000020
#define IO_HSU_ERR_ATTN_MASK 0x01000028
#define IO_HSU_FIRX1_ACT_MASK 0x01000030
#define IO_HSU_FIRX0_ACT_MASK 0x01000038
#define IO_HSU_SEC_LEM_DEBUG_OVR 0x01000040
#define IO_HSU_EXTENDED_ERR_PTR 0x01000048
#define IO_HSU_COMMON_CONFIG 0x01000060
#define IO_APP_UNITCFG 0x02000000
#define IO_APP_FIR 0x02000008
#define IO_APP_FIR_CLR 0x02000010
#define IO_APP_FEC 0x02000018
#define IO_APP_ERR_ACT_MASK 0x02000020
#define IO_APP_ERR_ATTN_MASK 0x02000028
#define IO_APP_FIRX1_ACT_MASK 0x02000030
#define IO_APP_FIRX0_ACT_MASK 0x02000038
#define IO_APP_SEC_LEM_DEBUG_OVR 0x02000040
#define IO_APP_EXTENDED_ERR_PTR 0x02000048
#define IO_APP_COMMON_CONFIG 0x02000060
#define IO_APP_DEBUG_REG_01 0x02010000
#define IO_APP_DEBUG_REG_02 0x02010008
#define IO_APP_DEBUG_REG_03 0x02010010
#define IO_APP_DEBUG_REG_04 0x02010018
#define IO_APP_DEBUG_REG_05 0x02010020
#define IO_APP_DEBUG_REG_06 0x02010028
#define IO_APP_DEBUG_REG_07 0x02010030
#define IO_APP_DEBUG_REG_08 0x02010038
#define IO_APP_DEBUG_REG_09 0x02010040
#define IO_APP_DEBUG_REG_10 0x02010048
#define IO_APP_DEBUG_REG_11 0x02010050
#define IO_APP_DEBUG_REG_12 0x02010058
#define IO_APP_DEBUG_REG_13 0x02010060
#define IO_APP_DEBUG_REG_14 0x02010068
#define IO_APP_DEBUG_REG_15 0x02010070
#define IO_APP_DEBUG_REG_16 0x02010078
#define IO_APP_DEBUG_REG_17 0x02010080
#define IO_APP_DEBUG_REG_18 0x02010088
struct genwqe_reg_io {
  __u64 num;
  __u64 val64;
};
#define IO_ILLEGAL_VALUE 0xffffffffffffffffull
#define DDCB_ACFUNC_SLU 0x00
#define DDCB_ACFUNC_APP 0x01
#define DDCB_RETC_IDLE 0x0000
#define DDCB_RETC_PENDING 0x0101
#define DDCB_RETC_COMPLETE 0x0102
#define DDCB_RETC_FAULT 0x0104
#define DDCB_RETC_ERROR 0x0108
#define DDCB_RETC_FORCED_ERROR 0x01ff
#define DDCB_RETC_UNEXEC 0x0110
#define DDCB_RETC_TERM 0x0120
#define DDCB_RETC_RES0 0x0140
#define DDCB_RETC_RES1 0x0180
#define DDCB_OPT_ECHO_FORCE_NO 0x0000
#define DDCB_OPT_ECHO_FORCE_102 0x0001
#define DDCB_OPT_ECHO_FORCE_104 0x0002
#define DDCB_OPT_ECHO_FORCE_108 0x0003
#define DDCB_OPT_ECHO_FORCE_110 0x0004
#define DDCB_OPT_ECHO_FORCE_120 0x0005
#define DDCB_OPT_ECHO_FORCE_140 0x0006
#define DDCB_OPT_ECHO_FORCE_180 0x0007
#define DDCB_OPT_ECHO_COPY_NONE (0 << 5)
#define DDCB_OPT_ECHO_COPY_ALL (1 << 5)
#define SLCMD_ECHO_SYNC 0x00
#define SLCMD_MOVE_FLASH 0x06
#define SLCMD_MOVE_FLASH_FLAGS_MODE 0x03
#define SLCMD_MOVE_FLASH_FLAGS_DLOAD 0
#define SLCMD_MOVE_FLASH_FLAGS_EMUL 1
#define SLCMD_MOVE_FLASH_FLAGS_UPLOAD 2
#define SLCMD_MOVE_FLASH_FLAGS_VERIFY 3
#define SLCMD_MOVE_FLASH_FLAG_NOTAP (1 << 2)
#define SLCMD_MOVE_FLASH_FLAG_POLL (1 << 3)
#define SLCMD_MOVE_FLASH_FLAG_PARTITION (1 << 4)
#define SLCMD_MOVE_FLASH_FLAG_ERASE (1 << 5)
enum genwqe_card_state {
  GENWQE_CARD_UNUSED = 0,
  GENWQE_CARD_USED = 1,
  GENWQE_CARD_FATAL_ERROR = 2,
  GENWQE_CARD_RELOAD_BITSTREAM = 3,
  GENWQE_CARD_STATE_MAX,
};
struct genwqe_bitstream {
  __u64 data_addr;
  __u32 size;
  __u32 crc;
  __u64 target_addr;
  __u32 partition;
  __u32 uid;
  __u64 slu_id;
  __u64 app_id;
  __u16 retc;
  __u16 attn;
  __u32 progress;
};
#define DDCB_LENGTH 256
#define DDCB_ASIV_LENGTH 104
#define DDCB_ASIV_LENGTH_ATS 96
#define DDCB_ASV_LENGTH 64
#define DDCB_FIXUPS 12
struct genwqe_debug_data {
  char driver_version[64];
  __u64 slu_unitcfg;
  __u64 app_unitcfg;
  __u8 ddcb_before[DDCB_LENGTH];
  __u8 ddcb_prev[DDCB_LENGTH];
  __u8 ddcb_finished[DDCB_LENGTH];
};
#define ATS_TYPE_DATA 0x0ull
#define ATS_TYPE_FLAT_RD 0x4ull
#define ATS_TYPE_FLAT_RDWR 0x5ull
#define ATS_TYPE_SGL_RD 0x6ull
#define ATS_TYPE_SGL_RDWR 0x7ull
#define ATS_SET_FLAGS(_struct,_field,_flags) (((_flags) & 0xf) << (44 - (4 * (offsetof(_struct, _field) / 8))))
#define ATS_GET_FLAGS(_ats,_byte_offs) (((_ats) >> (44 - (4 * ((_byte_offs) / 8)))) & 0xf)
struct genwqe_ddcb_cmd {
  __u64 next_addr;
  __u64 flags;
  __u8 acfunc;
  __u8 cmd;
  __u8 asiv_length;
  __u8 asv_length;
  __u16 cmdopts;
  __u16 retc;
  __u16 attn;
  __u16 vcrc;
  __u32 progress;
  __u64 deque_ts;
  __u64 cmplt_ts;
  __u64 disp_ts;
  __u64 ddata_addr;
  __u8 asv[DDCB_ASV_LENGTH];
  union {
    struct {
      __u64 ats;
      __u8 asiv[DDCB_ASIV_LENGTH_ATS];
    };
    __u8 __asiv[DDCB_ASIV_LENGTH];
  };
};
#define GENWQE_IOC_CODE 0xa5
#define GENWQE_READ_REG64 _IOR(GENWQE_IOC_CODE, 30, struct genwqe_reg_io)
#define GENWQE_WRITE_REG64 _IOW(GENWQE_IOC_CODE, 31, struct genwqe_reg_io)
#define GENWQE_READ_REG32 _IOR(GENWQE_IOC_CODE, 32, struct genwqe_reg_io)
#define GENWQE_WRITE_REG32 _IOW(GENWQE_IOC_CODE, 33, struct genwqe_reg_io)
#define GENWQE_READ_REG16 _IOR(GENWQE_IOC_CODE, 34, struct genwqe_reg_io)
#define GENWQE_WRITE_REG16 _IOW(GENWQE_IOC_CODE, 35, struct genwqe_reg_io)
#define GENWQE_GET_CARD_STATE _IOR(GENWQE_IOC_CODE, 36, enum genwqe_card_state)
struct genwqe_mem {
  __u64 addr;
  __u64 size;
  __u64 direction;
  __u64 flags;
};
#define GENWQE_PIN_MEM _IOWR(GENWQE_IOC_CODE, 40, struct genwqe_mem)
#define GENWQE_UNPIN_MEM _IOWR(GENWQE_IOC_CODE, 41, struct genwqe_mem)
#define GENWQE_EXECUTE_DDCB _IOWR(GENWQE_IOC_CODE, 50, struct genwqe_ddcb_cmd)
#define GENWQE_EXECUTE_RAW_DDCB _IOWR(GENWQE_IOC_CODE, 51, struct genwqe_ddcb_cmd)
#define GENWQE_SLU_UPDATE _IOWR(GENWQE_IOC_CODE, 80, struct genwqe_bitstream)
#define GENWQE_SLU_READ _IOWR(GENWQE_IOC_CODE, 81, struct genwqe_bitstream)
#endif
```