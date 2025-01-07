Response:
Let's break down the thought process for answering the user's request about the `i2o-dev.h` header file.

**1. Understanding the Core Request:**

The user wants to know about the functionality of the provided C header file (`i2o-dev.h`), especially in the context of Android. They are asking for a comprehensive analysis, covering:

* **Functionality:** What does this file define and what's its purpose?
* **Android Relevance:** How does this relate to Android's operation?
* **libc Functions:** Explanation of specific libc functions used (though in this case, there aren't many *directly* used).
* **Dynamic Linker:** How does this interact with the dynamic linker (more about header inclusion than direct linking).
* **Logic/Assumptions:** Any assumptions made in understanding the file.
* **Common Errors:** Typical programming mistakes when using such a file.
* **Android Framework/NDK Path:** How does Android code eventually use this?
* **Frida Hooking:** Examples of using Frida for debugging.

**2. Initial Analysis of the Header File:**

* **`#ifndef _I2O_DEV_H` ... `#endif`:**  This is a standard header guard, preventing multiple inclusions.
* **`#define MAX_I2O_CONTROLLERS 32`:**  A constant defining the maximum number of I2O controllers.
* **`#include <linux/ioctl.h>` and `#include <linux/types.h>`:**  This immediately signals that this file is related to Linux kernel interfaces, specifically `ioctl` (input/output control) and basic type definitions. The "uapi" in the path confirms it's a user-space API header for kernel interfaces.
* **`#define I2O_MAGIC_NUMBER 'i'`:** A magic number, likely used for `ioctl` calls to identify the I2O subsystem.
* **`#define I2OGETIOPS ... #define I2ODPT_FLASH_WRITE ...`:**  A series of `#define` statements. These are primarily:
    * **`ioctl` definitions:**  Macros like `_IOR`, `_IOWR`, `_IOW` indicate `ioctl` commands, each with a specific function (read, write, read/write), a magic number, a command number, and a data structure.
    * **Structure definitions:**  `struct i2o_cmd_hrtlct`, `struct i2o_sw_xfer`, etc. These define the data structures exchanged via `ioctl`.
    * **Constants:**  Various `#define` constants for states, events, classes, subclasses, parameters, etc.
* **Data structures:** The structures like `i2o_hrt`, `i2o_lct`, and `i2o_status_block` suggest this file deals with the hardware topology, logical configuration, and status of I2O devices.
* **Comments:** The initial comment stating "This file is auto-generated. Modifications will be lost." is crucial. It tells us this isn't meant for manual editing.

**3. Connecting to I2O (Independent Intelligent I/O):**

The filename and the content clearly indicate this file is related to the **Intelligent Input/Output (I2O)** architecture. This is a significant piece of information for understanding the file's purpose. A quick search about I2O would confirm its role in communication between a host system and intelligent peripheral devices.

**4. Addressing the User's Specific Questions (Iterative Refinement):**

* **Functionality:** Based on the `ioctl` definitions and data structures, the core function is providing an interface for user-space applications to interact with I2O devices through the kernel. This involves getting device information, setting parameters, performing data transfers, and registering for events.

* **Android Relevance:**  This requires some inference. While not directly a central part of the typical Android application development, it *is* part of the kernel interface. Therefore, if Android devices have hardware using the I2O protocol (less common now, but possible for specialized hardware), the kernel drivers for that hardware would expose this interface. Applications needing to interact with such low-level hardware would indirectly use this. The example of a hardware RAID controller is a good illustration.

* **libc Functions:** The header itself *doesn't define* any libc functions. It *uses* types and macros defined in other libc headers (`linux/ioctl.h`, `linux/types.h`). The actual system calls (`ioctl`) are part of libc, but this file just defines the *parameters* for those calls. The explanation should focus on how the *macros* in this file build arguments for the `ioctl` system call.

* **Dynamic Linker:** The dynamic linker is involved in making the `ioctl` *system call* available to user-space programs. The header file itself is statically included. The example SO layout should reflect a typical library that might use these `ioctl` calls. The linking process involves resolving the `ioctl` symbol to the libc implementation.

* **Logic/Assumptions:**  The main assumption is that the user wants to understand the *purpose* and *use* of this header file within the Android ecosystem, even if it's not a widely used API for typical app development.

* **Common Errors:**  Focus on errors related to incorrect `ioctl` usage: wrong command numbers, incorrect data structures, insufficient buffer sizes, permission issues.

* **Android Framework/NDK Path:** This involves tracing how a higher-level Android component might eventually trigger an `ioctl` call that uses these definitions. The path goes from the Android framework (Java/Kotlin) down through the NDK (C/C++), possibly interacting with HAL (Hardware Abstraction Layer) implementations, which could then make `ioctl` calls to the kernel using the definitions from this header.

* **Frida Hooking:**  The Frida examples should target the `ioctl` system call itself, showing how to intercept calls that use the I2O command numbers defined in the header. This helps in debugging and understanding how the I2O interface is being used.

**5. Structuring the Answer:**

Organize the answer logically, addressing each of the user's points in a clear and concise manner. Use headings and bullet points to improve readability. Provide concrete examples to illustrate abstract concepts.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** Maybe focus too much on direct libc function calls.
* **Correction:** Realize the header primarily defines *data structures* and *constants* for `ioctl`, not standalone libc functions. Shift focus accordingly.
* **Initial Thought:**  Overcomplicate the dynamic linker explanation.
* **Correction:** Simplify it to how the `ioctl` system call is made available and how libraries using this header would link against libc.
* **Initial Thought:** Assume everyone knows what I2O is.
* **Correction:** Briefly explain the purpose of I2O for better understanding.
* **Initial Thought:**  Only provide very basic Frida examples.
* **Correction:**  Offer more targeted examples that show how to filter `ioctl` calls based on the I2O magic number and command numbers.

By following this iterative process of understanding the request, analyzing the code, connecting it to relevant concepts, and refining the explanation, a comprehensive and accurate answer can be constructed.
## 源代码文件 bionic/libc/kernel/uapi/linux/i2o-dev.h 功能分析

这个头文件 `i2o-dev.h` 定义了Linux内核中与 **I2O (Intelligent Input/Output)** 设备驱动交互的用户空间接口。它不是 Android 特有的，而是 Linux 内核的一部分，被 bionic (Android 的 C 库) 收录进来是为了提供与底层硬件交互的能力，如果 Android 设备使用了 I2O 架构的硬件。

**功能列举:**

1. **定义 I2O 控制器的最大数量:** `MAX_I2O_CONTROLLERS 32` 定义了系统中最多可以支持的 I2O 控制器数量。
2. **定义 `ioctl` 命令:**  该文件定义了一系列用于与 I2O 设备驱动进行通信的 `ioctl` 命令，例如：
    * `I2OGETIOPS`: 获取系统中所有 I2O 控制器的信息。
    * `I2OHRTGET`: 获取硬件资源表 (HRT)。
    * `I2OLCTGET`: 获取逻辑配置表 (LCT)。
    * `I2OPARMSET`, `I2OPARMGET`: 设置和获取 I2O 设备的参数。
    * `I2OSWDL`, `I2OSWUL`, `I2OSWDEL`: 下载、上传和删除 I2O 设备的固件。
    * `I2OVALIDATE`: 验证 I2O 设备。
    * `I2OHTML`: 获取 I2O 设备的 HTML 信息 (可能用于管理接口)。
    * `I2OEVTREG`, `I2OEVTGET`: 注册和获取 I2O 设备事件。
    * `I2OPASSTHRU`, `I2OPASSTHRU32`: 向 I2O 设备发送原始的 passthrough 命令。
3. **定义 `ioctl` 命令参数结构体:** 每个 `ioctl` 命令都关联着一个或多个结构体，用于传递命令参数和接收返回结果。例如：
    * `struct i2o_cmd_hrtlct`: 用于 `I2OHRTGET` 和 `I2OLCTGET` 命令，包含控制器编号和用于存储结果的缓冲区指针和长度。
    * `struct i2o_cmd_psetget`: 用于 `I2OPARMSET` 和 `I2OPARMGET` 命令，包含控制器编号、目标 ID、操作缓冲区、结果缓冲区等。
    * `struct i2o_sw_xfer`: 用于固件操作相关的命令，包含控制器编号、标志、固件类型、缓冲区指针和长度等。
    * `struct i2o_evt_id`, `struct i2o_evt_info`: 用于事件注册和获取，包含控制器编号、目标 ID、事件掩码和事件数据。
4. **定义 I2O 相关的常量和类型:** 文件中定义了大量的常量，用于表示 I2O 设备的状态、事件类型、总线类型、设备类别、参数类型等。这些常量用于解析和构建与 I2O 设备交互的数据。例如：
    * `I2O_BUS_LOCAL`, `I2O_BUS_ISA`, `I2O_BUS_PCI` 等定义了不同的总线类型。
    * `I2O_EVT_IND_STATE_CHANGE`, `I2O_EVT_IND_GENERAL_WARNING` 等定义了不同的事件指示类型。
    * `I2O_CLASS_EXECUTIVE`, `I2O_CLASS_DDM`, `I2O_CLASS_RANDOM_BLOCK_STORAGE` 等定义了不同的设备类别。
5. **定义 I2O 设备的结构信息:**  定义了描述 I2O 设备硬件资源 (`i2o_hrt_entry`) 和逻辑配置 (`i2o_lct_entry`) 的结构体。这些结构体包含了设备的 ID、状态、总线信息、设备类型、版本、供应商信息等。
6. **定义 I2O 状态块结构:** `struct _i2o_status_block` 定义了用于获取 I2O 控制器状态信息的结构体，包含 IOP ID、状态、版本、能力、内存和 IO 资源信息等。

**与 Android 功能的关系及举例说明:**

`i2o-dev.h` 不是 Android 核心功能直接相关的头文件。它主要用于支持基于 I2O 架构的硬件。在典型的 Android 移动设备中，I2O 架构并不常见。

**举例说明 (可能性较低但存在):**

* **服务器或嵌入式 Android 设备:** 如果某个特定的 Android 设备 (例如，一个运行 Android 的服务器或工业控制设备)  使用了基于 I2O 的硬件控制器 (例如，某些老旧的 RAID 控制器或其他特殊的 I/O 设备)，那么底层的硬件驱动程序会使用这些定义来与硬件交互。
* **硬件抽象层 (HAL):**  Android 的 HAL 可以作为硬件驱动的上层抽象。如果某个 HAL 需要与 I2O 设备通信，它可能会间接地使用这些定义。

**由于 I2O 架构在现代移动设备中并不普及，因此直接使用这些定义的 Android 应用或框架组件非常罕见。**

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**并没有定义任何 libc 函数**。它定义的是 **Linux 内核的接口**，主要通过 `ioctl` 系统调用来使用。

* **`ioctl` 函数:** `ioctl` 是一个通用的设备控制系统调用，允许用户空间程序向设备驱动程序发送控制命令并传递数据。
    * **实现原理:** 当用户空间程序调用 `ioctl` 时，内核会根据文件描述符找到对应的设备驱动程序，并将 `ioctl` 的命令号和参数传递给驱动程序的 `ioctl` 处理函数。驱动程序根据命令号执行相应的操作，并可能将结果返回给用户空间。
    * **在这个文件中，`_IOR`, `_IOWR`, `_IOW` 等宏是用于构建 `ioctl` 命令号的辅助宏:**
        * `_IOR(type, nr, size)`: 构建一个用于**读取**数据的 `ioctl` 命令号。
        * `_IOW(type, nr, size)`: 构建一个用于**写入**数据的 `ioctl` 命令号。
        * `_IOWR(type, nr, size)`: 构建一个用于**读写**数据的 `ioctl` 命令号。
        * 其中 `type` 是幻数 (这里是 `I2O_MAGIC_NUMBER 'i'`)，`nr` 是命令编号，`size` 是传递的数据大小。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件是内核头文件，通常会被静态地包含到 C/C++ 代码中，而不是通过动态链接。但是，如果一个共享库 (SO) 需要使用 I2O 设备，它会包含这个头文件，并使用 `ioctl` 系统调用。

**SO 布局样本 (假设一个名为 `libi2odev.so` 的库使用了 I2O):**

```
libi2odev.so:
    .text         # 代码段，包含使用 ioctl 的函数
    .rodata       # 只读数据段，可能包含一些常量
    .data         # 可读写数据段
    .bss          # 未初始化数据段
    .dynamic      # 动态链接信息
    .symtab       # 符号表
    .strtab       # 字符串表
    ...
```

**链接的处理过程:**

1. **编译时:** 当编译 `libi2odev.so` 的源代码时，编译器会遇到 `#include <linux/i2o-dev.h>`。预处理器会将该头文件的内容直接插入到源文件中。
2. **链接时:** 链接器会将 `libi2odev.so` 与必要的库 (通常是 `libc.so`) 链接。由于 `ioctl` 是 `libc.so` 提供的系统调用封装，链接器会解析对 `ioctl` 的引用，确保程序在运行时能够找到 `ioctl` 函数的实现。
3. **运行时:** 当程序加载 `libi2odev.so` 时，动态链接器会检查其依赖关系，并加载所需的共享库 (例如 `libc.so`)。当 `libi2odev.so` 中的代码调用 `ioctl` 时，它实际上会调用 `libc.so` 中 `ioctl` 的实现，最终陷入内核执行设备驱动程序提供的功能。

**逻辑推理、假设输入与输出:**

假设有一个程序想要获取系统中所有 I2O 控制器的数量。

**假设输入:**

* 程序打开了 `/dev/i2o_ctl` (假设存在这样一个设备节点) 的文件描述符 `fd`。

**代码片段:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2o-dev.h>

int main() {
    int fd = open("/dev/i2o_ctl", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    unsigned char iops[MAX_I2O_CONTROLLERS];
    if (ioctl(fd, I2OGETIOPS, iops) == -1) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    int count = 0;
    for (int i = 0; i < MAX_I2O_CONTROLLERS; ++i) {
        if (iops[i] != 0) { // 假设非零值表示控制器存在
            count++;
        }
    }

    printf("Found %d I2O controllers.\n", count);

    close(fd);
    return 0;
}
```

**假设输出 (取决于实际硬件配置):**

```
Found 2 I2O controllers.
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记包含头文件:** 如果程序中使用了 `I2OGETIOPS` 等宏或 `struct i2o_cmd_hrtlct` 等结构体，但忘记包含 `<linux/i2o-dev.h>`，会导致编译错误。
2. **`ioctl` 命令号错误:** 传递了错误的 `ioctl` 命令号，导致内核无法识别请求，`ioctl` 调用返回 -1，并设置 `errno`。
3. **数据结构不匹配:**  传递给 `ioctl` 的数据结构与内核驱动程序期望的不一致 (例如，大小错误，类型错误)，可能导致内核崩溃或其他不可预测的行为。
4. **缓冲区大小不足:**  在读取数据时 (例如使用 `I2OHRTGET`)，提供的缓冲区大小不足以存储返回的数据，可能导致数据截断或缓冲区溢出。
5. **权限不足:** 访问 I2O 设备可能需要特定的权限。如果用户没有足够的权限，`open` 或 `ioctl` 调用可能会失败。
6. **设备节点不存在:** 如果尝试打开的 I2O 设备节点 (例如 `/dev/i2o_ctl`) 不存在，`open` 调用会失败。
7. **假设控制器总是存在:**  在示例代码中，简单地遍历 `iops` 数组并假设非零值表示控制器存在可能是不准确的，具体的判断逻辑需要参考 I2O 驱动的文档。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**路径说明 (理论可能性):**

1. **Android Framework (Java/Kotlin):**  Android Framework 本身通常不会直接操作底层的 I2O 设备。
2. **NDK (C/C++):**  如果一个使用 NDK 开发的 Native 库需要与 I2O 设备交互，它可以包含 `<linux/i2o-dev.h>` 并使用 `ioctl` 系统调用。
3. **HAL (Hardware Abstraction Layer):** Android 的 HAL 负责连接 Framework 和硬件驱动。如果存在一个针对 I2O 设备的 HAL 实现，那么 HAL 的 C/C++ 代码会使用这些定义。
4. **Kernel Driver:**  最终，HAL 或 Native 库的 `ioctl` 调用会传递到 Linux 内核中对应的 I2O 设备驱动程序。

**Frida Hook 示例:**

以下是一个使用 Frida hook `ioctl` 系统调用的示例，用于监控涉及 I2O 设备的 `ioctl` 调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    device = frida.get_usb_device()
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None

    if pid:
        session = device.attach(pid)
    else:
        print("Please specify a PID.")
        return

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            var fd = args[0].toInt32();
            var request = args[1].toInt32();

            // 检查是否是 I2O 相关的 ioctl 命令 (通过 MAGIC NUMBER)
            if ((request & 0xFF) === 'i'.charCodeAt(0)) {
                console.log("[Ioctl Hook]");
                console.log("  FD:", fd);
                console.log("  Request:", request, " (0x" + request.toString(16) + ")");

                // 可以进一步解析 request 来判断具体的 I2O 命令
                // 例如:
                // if (request === 0x80086969) { // 假设这是 I2OGETIOPS 的值
                //     console.log("  Command: I2OGETIOPS");
                // }

                // 如果需要，可以读取和解析第三个参数 (数据指针)
                // var dataPtr = args[2];
                // if (dataPtr.isNull() === false) {
                //     // ... 读取和解析数据 ...
                // }
            }
        },
        onLeave: function(retval) {
            // console.log("Return value:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded, monitoring ioctl calls...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将以上 Python 代码保存为 `hook_ioctl.py`。
2. 找到目标进程的 PID (例如，一个可能与 I2O 硬件交互的 HAL 进程)。
3. 运行 Frida 脚本: `frida -U -f <package_name> --no-pause -l hook_ioctl.py`  或者 `python hook_ioctl.py <PID>`。

**解释:**

* 该 Frida 脚本 hook 了 `ioctl` 系统调用。
* 在 `onEnter` 函数中，它获取了文件描述符 `fd` 和 `ioctl` 请求号 `request`。
* 它通过检查 `request` 的低 8 位是否与 `I2O_MAGIC_NUMBER 'i'` 的 ASCII 码匹配来初步判断是否是 I2O 相关的 `ioctl` 调用。
* 如果是，它会打印出文件描述符和请求号。
* 可以根据需要进一步解析 `request` 来判断具体的 I2O 命令，并读取和解析第三个参数 (数据指针)。

**注意:**

* 这种 hook 方式会监控所有进程的 `ioctl` 调用，如果目标进程频繁调用 `ioctl`，输出可能会非常多。需要根据实际情况进行过滤。
* 确定准确的 I2O `ioctl` 命令号可能需要参考内核源代码或相关的文档。
*  在没有实际使用 I2O 硬件的 Android 设备上运行此脚本，可能不会捕获到任何相关的 `ioctl` 调用。

总而言之，`bionic/libc/kernel/uapi/linux/i2o-dev.h` 提供了与 Linux 内核中 I2O 设备驱动交互的接口定义。虽然在现代移动 Android 设备中不常见，但在某些特定的服务器或嵌入式 Android 系统中，仍然可能被底层的硬件驱动或 HAL 使用。使用 Frida 可以帮助开发者调试和理解这些底层的交互过程。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/i2o-dev.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _I2O_DEV_H
#define _I2O_DEV_H
#define MAX_I2O_CONTROLLERS 32
#include <linux/ioctl.h>
#include <linux/types.h>
#define I2O_MAGIC_NUMBER 'i'
#define I2OGETIOPS _IOR(I2O_MAGIC_NUMBER, 0, __u8[MAX_I2O_CONTROLLERS])
#define I2OHRTGET _IOWR(I2O_MAGIC_NUMBER, 1, struct i2o_cmd_hrtlct)
#define I2OLCTGET _IOWR(I2O_MAGIC_NUMBER, 2, struct i2o_cmd_hrtlct)
#define I2OPARMSET _IOWR(I2O_MAGIC_NUMBER, 3, struct i2o_cmd_psetget)
#define I2OPARMGET _IOWR(I2O_MAGIC_NUMBER, 4, struct i2o_cmd_psetget)
#define I2OSWDL _IOWR(I2O_MAGIC_NUMBER, 5, struct i2o_sw_xfer)
#define I2OSWUL _IOWR(I2O_MAGIC_NUMBER, 6, struct i2o_sw_xfer)
#define I2OSWDEL _IOWR(I2O_MAGIC_NUMBER, 7, struct i2o_sw_xfer)
#define I2OVALIDATE _IOR(I2O_MAGIC_NUMBER, 8, __u32)
#define I2OHTML _IOWR(I2O_MAGIC_NUMBER, 9, struct i2o_html)
#define I2OEVTREG _IOW(I2O_MAGIC_NUMBER, 10, struct i2o_evt_id)
#define I2OEVTGET _IOR(I2O_MAGIC_NUMBER, 11, struct i2o_evt_info)
#define I2OPASSTHRU _IOR(I2O_MAGIC_NUMBER, 12, struct i2o_cmd_passthru)
#define I2OPASSTHRU32 _IOR(I2O_MAGIC_NUMBER, 12, struct i2o_cmd_passthru32)
struct i2o_cmd_passthru32 {
  unsigned int iop;
  __u32 msg;
};
struct i2o_cmd_passthru {
  unsigned int iop;
  void  * msg;
};
struct i2o_cmd_hrtlct {
  unsigned int iop;
  void  * resbuf;
  unsigned int  * reslen;
};
struct i2o_cmd_psetget {
  unsigned int iop;
  unsigned int tid;
  void  * opbuf;
  unsigned int oplen;
  void  * resbuf;
  unsigned int  * reslen;
};
struct i2o_sw_xfer {
  unsigned int iop;
  unsigned char flags;
  unsigned char sw_type;
  unsigned int sw_id;
  void  * buf;
  unsigned int  * swlen;
  unsigned int  * maxfrag;
  unsigned int  * curfrag;
};
struct i2o_html {
  unsigned int iop;
  unsigned int tid;
  unsigned int page;
  void  * resbuf;
  unsigned int  * reslen;
  void  * qbuf;
  unsigned int qlen;
};
#define I2O_EVT_Q_LEN 32
struct i2o_evt_id {
  unsigned int iop;
  unsigned int tid;
  unsigned int evt_mask;
};
#define I2O_EVT_DATA_SIZE 88
struct i2o_evt_info {
  struct i2o_evt_id id;
  unsigned char evt_data[I2O_EVT_DATA_SIZE];
  unsigned int data_size;
};
struct i2o_evt_get {
  struct i2o_evt_info info;
  int pending;
  int lost;
};
typedef struct i2o_sg_io_hdr {
  unsigned int flags;
} i2o_sg_io_hdr_t;
#define I2O_BUS_LOCAL 0
#define I2O_BUS_ISA 1
#define I2O_BUS_EISA 2
#define I2O_BUS_PCI 4
#define I2O_BUS_PCMCIA 5
#define I2O_BUS_NUBUS 6
#define I2O_BUS_CARDBUS 7
#define I2O_BUS_UNKNOWN 0x80
typedef struct _i2o_pci_bus {
  __u8 PciFunctionNumber;
  __u8 PciDeviceNumber;
  __u8 PciBusNumber;
  __u8 reserved;
  __u16 PciVendorID;
  __u16 PciDeviceID;
} i2o_pci_bus;
typedef struct _i2o_local_bus {
  __u16 LbBaseIOPort;
  __u16 reserved;
  __u32 LbBaseMemoryAddress;
} i2o_local_bus;
typedef struct _i2o_isa_bus {
  __u16 IsaBaseIOPort;
  __u8 CSN;
  __u8 reserved;
  __u32 IsaBaseMemoryAddress;
} i2o_isa_bus;
typedef struct _i2o_eisa_bus_info {
  __u16 EisaBaseIOPort;
  __u8 reserved;
  __u8 EisaSlotNumber;
  __u32 EisaBaseMemoryAddress;
} i2o_eisa_bus;
typedef struct _i2o_mca_bus {
  __u16 McaBaseIOPort;
  __u8 reserved;
  __u8 McaSlotNumber;
  __u32 McaBaseMemoryAddress;
} i2o_mca_bus;
typedef struct _i2o_other_bus {
  __u16 BaseIOPort;
  __u16 reserved;
  __u32 BaseMemoryAddress;
} i2o_other_bus;
typedef struct _i2o_hrt_entry {
  __u32 adapter_id;
  __u32 parent_tid : 12;
  __u32 state : 4;
  __u32 bus_num : 8;
  __u32 bus_type : 8;
  union {
    i2o_pci_bus pci_bus;
    i2o_local_bus local_bus;
    i2o_isa_bus isa_bus;
    i2o_eisa_bus eisa_bus;
    i2o_mca_bus mca_bus;
    i2o_other_bus other_bus;
  } bus;
} i2o_hrt_entry;
typedef struct _i2o_hrt {
  __u16 num_entries;
  __u8 entry_len;
  __u8 hrt_version;
  __u32 change_ind;
  i2o_hrt_entry hrt_entry[1];
} i2o_hrt;
typedef struct _i2o_lct_entry {
  __u32 entry_size : 16;
  __u32 tid : 12;
  __u32 reserved : 4;
  __u32 change_ind;
  __u32 device_flags;
  __u32 class_id : 12;
  __u32 version : 4;
  __u32 vendor_id : 16;
  __u32 sub_class;
  __u32 user_tid : 12;
  __u32 parent_tid : 12;
  __u32 bios_info : 8;
  __u8 identity_tag[8];
  __u32 event_capabilities;
} i2o_lct_entry;
typedef struct _i2o_lct {
  __u32 table_size : 16;
  __u32 boot_tid : 12;
  __u32 lct_ver : 4;
  __u32 iop_flags;
  __u32 change_ind;
  i2o_lct_entry lct_entry[1];
} i2o_lct;
typedef struct _i2o_status_block {
  __u16 org_id;
  __u16 reserved;
  __u16 iop_id : 12;
  __u16 reserved1 : 4;
  __u16 host_unit_id;
  __u16 segment_number : 12;
  __u16 i2o_version : 4;
  __u8 iop_state;
  __u8 msg_type;
  __u16 inbound_frame_size;
  __u8 init_code;
  __u8 reserved2;
  __u32 max_inbound_frames;
  __u32 cur_inbound_frames;
  __u32 max_outbound_frames;
  char product_id[24];
  __u32 expected_lct_size;
  __u32 iop_capabilities;
  __u32 desired_mem_size;
  __u32 current_mem_size;
  __u32 current_mem_base;
  __u32 desired_io_size;
  __u32 current_io_size;
  __u32 current_io_base;
  __u32 reserved3 : 24;
  __u32 cmd_status : 8;
} i2o_status_block;
#define I2O_EVT_IND_STATE_CHANGE 0x80000000
#define I2O_EVT_IND_GENERAL_WARNING 0x40000000
#define I2O_EVT_IND_CONFIGURATION_FLAG 0x20000000
#define I2O_EVT_IND_LOCK_RELEASE 0x10000000
#define I2O_EVT_IND_CAPABILITY_CHANGE 0x08000000
#define I2O_EVT_IND_DEVICE_RESET 0x04000000
#define I2O_EVT_IND_EVT_MASK_MODIFIED 0x02000000
#define I2O_EVT_IND_FIELD_MODIFIED 0x01000000
#define I2O_EVT_IND_VENDOR_EVT 0x00800000
#define I2O_EVT_IND_DEVICE_STATE 0x00400000
#define I2O_EVT_IND_EXEC_RESOURCE_LIMITS 0x00000001
#define I2O_EVT_IND_EXEC_CONNECTION_FAIL 0x00000002
#define I2O_EVT_IND_EXEC_ADAPTER_FAULT 0x00000004
#define I2O_EVT_IND_EXEC_POWER_FAIL 0x00000008
#define I2O_EVT_IND_EXEC_RESET_PENDING 0x00000010
#define I2O_EVT_IND_EXEC_RESET_IMMINENT 0x00000020
#define I2O_EVT_IND_EXEC_HW_FAIL 0x00000040
#define I2O_EVT_IND_EXEC_XCT_CHANGE 0x00000080
#define I2O_EVT_IND_EXEC_NEW_LCT_ENTRY 0x00000100
#define I2O_EVT_IND_EXEC_MODIFIED_LCT 0x00000200
#define I2O_EVT_IND_EXEC_DDM_AVAILABILITY 0x00000400
#define I2O_EVT_IND_BSA_VOLUME_LOAD 0x00000001
#define I2O_EVT_IND_BSA_VOLUME_UNLOAD 0x00000002
#define I2O_EVT_IND_BSA_VOLUME_UNLOAD_REQ 0x00000004
#define I2O_EVT_IND_BSA_CAPACITY_CHANGE 0x00000008
#define I2O_EVT_IND_BSA_SCSI_SMART 0x00000010
#define I2O_EVT_STATE_CHANGE_NORMAL 0x00
#define I2O_EVT_STATE_CHANGE_SUSPENDED 0x01
#define I2O_EVT_STATE_CHANGE_RESTART 0x02
#define I2O_EVT_STATE_CHANGE_NA_RECOVER 0x03
#define I2O_EVT_STATE_CHANGE_NA_NO_RECOVER 0x04
#define I2O_EVT_STATE_CHANGE_QUIESCE_REQUEST 0x05
#define I2O_EVT_STATE_CHANGE_FAILED 0x10
#define I2O_EVT_STATE_CHANGE_FAULTED 0x11
#define I2O_EVT_GEN_WARNING_NORMAL 0x00
#define I2O_EVT_GEN_WARNING_ERROR_THRESHOLD 0x01
#define I2O_EVT_GEN_WARNING_MEDIA_FAULT 0x02
#define I2O_EVT_CAPABILITY_OTHER 0x01
#define I2O_EVT_CAPABILITY_CHANGED 0x02
#define I2O_EVT_SENSOR_STATE_CHANGED 0x01
#define I2O_CLASS_VERSION_10 0x00
#define I2O_CLASS_VERSION_11 0x01
#define I2O_CLASS_EXECUTIVE 0x000
#define I2O_CLASS_DDM 0x001
#define I2O_CLASS_RANDOM_BLOCK_STORAGE 0x010
#define I2O_CLASS_SEQUENTIAL_STORAGE 0x011
#define I2O_CLASS_LAN 0x020
#define I2O_CLASS_WAN 0x030
#define I2O_CLASS_FIBRE_CHANNEL_PORT 0x040
#define I2O_CLASS_FIBRE_CHANNEL_PERIPHERAL 0x041
#define I2O_CLASS_SCSI_PERIPHERAL 0x051
#define I2O_CLASS_ATE_PORT 0x060
#define I2O_CLASS_ATE_PERIPHERAL 0x061
#define I2O_CLASS_FLOPPY_CONTROLLER 0x070
#define I2O_CLASS_FLOPPY_DEVICE 0x071
#define I2O_CLASS_BUS_ADAPTER 0x080
#define I2O_CLASS_PEER_TRANSPORT_AGENT 0x090
#define I2O_CLASS_PEER_TRANSPORT 0x091
#define I2O_CLASS_END 0xfff
#define I2O_CLASS_MATCH_ANYCLASS 0xffffffff
#define I2O_SUBCLASS_i960 0x001
#define I2O_SUBCLASS_HDM 0x020
#define I2O_SUBCLASS_ISM 0x021
#define I2O_PARAMS_FIELD_GET 0x0001
#define I2O_PARAMS_LIST_GET 0x0002
#define I2O_PARAMS_MORE_GET 0x0003
#define I2O_PARAMS_SIZE_GET 0x0004
#define I2O_PARAMS_TABLE_GET 0x0005
#define I2O_PARAMS_FIELD_SET 0x0006
#define I2O_PARAMS_LIST_SET 0x0007
#define I2O_PARAMS_ROW_ADD 0x0008
#define I2O_PARAMS_ROW_DELETE 0x0009
#define I2O_PARAMS_TABLE_CLEAR 0x000A
#define I2O_SNFORMAT_UNKNOWN 0
#define I2O_SNFORMAT_BINARY 1
#define I2O_SNFORMAT_ASCII 2
#define I2O_SNFORMAT_UNICODE 3
#define I2O_SNFORMAT_LAN48_MAC 4
#define I2O_SNFORMAT_WAN 5
#define I2O_SNFORMAT_LAN64_MAC 6
#define I2O_SNFORMAT_DDM 7
#define I2O_SNFORMAT_IEEE_REG64 8
#define I2O_SNFORMAT_IEEE_REG128 9
#define I2O_SNFORMAT_UNKNOWN2 0xff
#define ADAPTER_STATE_INITIALIZING 0x01
#define ADAPTER_STATE_RESET 0x02
#define ADAPTER_STATE_HOLD 0x04
#define ADAPTER_STATE_READY 0x05
#define ADAPTER_STATE_OPERATIONAL 0x08
#define ADAPTER_STATE_FAILED 0x10
#define ADAPTER_STATE_FAULTED 0x11
#define I2O_SOFTWARE_MODULE_IRTOS 0x11
#define I2O_SOFTWARE_MODULE_IOP_PRIVATE 0x22
#define I2O_SOFTWARE_MODULE_IOP_CONFIG 0x23
#define I2O_VENDOR_DPT 0x001b
#define I2O_DPT_SG_FLAG_INTERPRET 0x00010000
#define I2O_DPT_SG_FLAG_PHYSICAL 0x00020000
#define I2O_DPT_FLASH_FRAG_SIZE 0x10000
#define I2O_DPT_FLASH_READ 0x0101
#define I2O_DPT_FLASH_WRITE 0x0102
#endif

"""

```