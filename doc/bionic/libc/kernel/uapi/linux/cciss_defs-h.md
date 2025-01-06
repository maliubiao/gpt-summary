Response:
Let's break down the thought process to answer the request about the `cciss_defs.h` file.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided header file, focusing on its functionality, relationship to Android, implementation details (where applicable), dynamic linking aspects, error handling, usage within the Android framework, and debugging techniques. The key is to extract as much meaningful information as possible from a relatively small header file.

**2. Initial Analysis of the Header File:**

* **Filename and Path:** The filename `cciss_defs.h` and the path `bionic/libc/kernel/uapi/linux/` immediately suggest this file defines constants and data structures related to a specific kernel interface. The "uapi" signifies "user API," meaning these definitions are meant for user-space programs interacting with the kernel.
* **Copyright Notice:** The "auto-generated" comment and the link to the Bionic repository highlight that this isn't manually written but rather derived from the kernel sources. This is crucial information for understanding its origin and purpose.
* **Header Guards:** The `#ifndef CCISS_DEFS_H` and `#define CCISS_DEFS_H` are standard header guards, preventing multiple inclusions and compilation errors.
* **Includes:** The inclusion of `<linux/types.h>` tells us it relies on basic Linux type definitions like `__u8`, `__u16`, and `__u32`.
* **Definitions:** The bulk of the file consists of `#define` directives for constants and `typedef` for structures and unions. This indicates it's primarily defining an interface for communicating with a device driver.
* **`#pragma pack(1)`:** This directive is significant. It instructs the compiler to disable padding within structures, ensuring they have a specific memory layout. This is common in hardware interfaces where data needs to be exchanged in a fixed format.

**3. Identifying the Purpose - "cciss":**

The filename `cciss_defs.h` contains "cciss". A quick search reveals that CCISS stands for "Compaq Command Interface for Storage Subsystems". This is a crucial piece of the puzzle. The file defines how user-space interacts with hardware RAID controllers, originally from Compaq (now HP).

**4. Categorizing the Definitions:**

Based on their names and values, the definitions can be grouped:

* **Command Status Codes (CMD_*):** Indicate the outcome of a command sent to the storage controller.
* **Transfer Directions (XFER_*):**  Specify whether data is being read from or written to the device.
* **Tagging Attributes (ATTR_*):** Related to command queuing and prioritization.
* **Message/Command Types (TYPE_*):** Differentiate between control messages and data commands.
* **Basic Types (BYTE, WORD, HWORD, DWORD):** Aliases for fundamental unsigned integer types.
* **Limits (CISS_MAX_LUN):** Maximum number of logical units.
* **Addressing Structures (`SCSI3Addr_struct`, `PhysDevAddr_struct`, `LogDevAddr_struct`, `LUNAddr_struct`):**  Define how to address physical and logical storage devices. The multiple structures within `LUNAddr_struct` (using a union) indicate different ways to represent a Logical Unit Number (LUN).
* **Request Structure (`RequestBlock_struct`):**  Represents a command to be sent to the controller, including the command itself (CDB - Command Descriptor Block).
* **Error Information Structures (`MoreErrInfo_struct`, `ErrorInfo_struct`):**  Contain details about errors encountered during command processing.

**5. Connecting to Android:**

* **Kernel Interaction:**  The fact that this is in `bionic/libc/kernel/uapi/linux/` directly links it to the Android kernel interface. Android devices might use CCISS-compatible RAID controllers in some configurations (though less common nowadays, especially in mobile).
* **Low-Level I/O:**  Android's storage abstraction layers eventually interact with the kernel through system calls. This header file provides the structures used for those low-level interactions related to these specific controllers.
* **HAL (Hardware Abstraction Layer):** While this specific header might not be directly used by a typical application, HAL implementations dealing with storage could potentially use definitions derived from this (though a more general SCSI interface is more likely).

**6. Addressing Specific Request Points:**

* **Functionality Listing:**  Summarize the categories of definitions (command status, addressing, etc.).
* **Android Relevance:** Explain the kernel interaction and potential (though perhaps not direct) use in HALs. Emphasize that it's a low-level interface.
* **Libc Function Implementation:**  *Crucially*, realize that **this header file *doesn't define libc functions*.** It defines *data structures and constants*. The actual functions that *use* these definitions would be in kernel drivers or potentially in very low-level userspace libraries (not standard libc). Therefore, explain *why* there are no libc function implementations to discuss.
* **Dynamic Linker:**  Similar to libc functions, this header file doesn't directly involve the dynamic linker. Explain that it's a data definition file, not executable code. If a userspace library *were* to use these definitions, the dynamic linker would be involved in loading that library, but this file itself isn't an SO. Provide a basic SO layout example to demonstrate understanding of SO structure even though it's not directly applicable here.
* **Logical Reasoning (Hypothetical Input/Output):**  Since it's mostly definitions, creating hypothetical input/output for *this file itself* is not really meaningful. Instead, provide an example of how the *defined structures* would be used in a hypothetical scenario (e.g., sending a command and interpreting the status).
* **Common Usage Errors:**  Focus on potential mistakes when *using* these definitions, such as incorrect structure packing, interpreting status codes incorrectly, or providing invalid addresses.
* **Android Framework/NDK Path:**  Illustrate the path from a high-level Android API call down to the kernel level, showing where these definitions *could* theoretically be involved (even if indirectly). Emphasize the layers of abstraction.
* **Frida Hook Example:** Provide a Frida example that targets a hypothetical system call or function that *would* use these definitions. Since we don't have the exact function, demonstrate the *technique* of hooking and inspecting arguments/return values.

**7. Refinement and Language:**

* Use clear and concise language.
* Explain technical terms (like "uapi," "CDB," "LUN").
* Structure the answer logically, addressing each part of the request.
* Use formatting (bullet points, code blocks) for readability.
* Emphasize the limitations of the analysis due to the nature of the input file (it's just definitions).

By following this thought process, breaking down the request, analyzing the file, and connecting it to the broader Android context, a comprehensive and accurate answer can be generated, even when the input is primarily a header file defining data structures and constants. The key is to understand *what* the file is and *how* it's intended to be used, rather than trying to force it into categories that don't apply (like libc function implementations).
这是一个定义了与 CCISS (Compaq Command Interface for Storage Subsystems) 设备交互所需的常量、数据结构和类型的文件。CCISS 是一种用于与某些硬件 RAID 控制器进行通信的协议。 由于路径包含 `uapi`，这意味着它是用户空间程序与 Linux 内核中 CCISS 驱动程序交互的接口定义。

**它的功能：**

该文件定义了以下内容，用于用户空间程序与 CCISS 设备驱动程序进行交互：

1. **常量定义 (Macros):**
   - `SENSEINFOBYTES`: 定义了 SCSI Sense 信息的字节数，用于描述设备返回的错误信息。
   - `CMD_*`: 定义了各种命令状态代码，表示设备执行命令的结果（成功、错误等）。例如：
     - `CMD_SUCCESS`: 命令成功。
     - `CMD_TARGET_STATUS`: 目标设备返回状态。
     - `CMD_DATA_UNDERRUN`: 数据不足。
     - `CMD_DATA_OVERRUN`: 数据溢出。
     - 其他 `CMD_*` 常量表示各种错误和状态。
   - `XFER_*`: 定义了数据传输的方向。
     - `XFER_NONE`: 无数据传输。
     - `XFER_WRITE`: 向设备写入数据。
     - `XFER_READ`: 从设备读取数据。
   - `ATTR_*`: 定义了命令标记属性，用于命令队列管理。
     - `ATTR_UNTAGGED`: 未标记。
     - `ATTR_SIMPLE`: 简单标记。
     - `ATTR_HEADOFQUEUE`: 队列头部。
     - `ATTR_ORDERED`: 有序。
     - `ATTR_ACA`: ACA 标记。
   - `TYPE_*`: 定义了消息类型。
     - `TYPE_CMD`: 命令。
     - `TYPE_MSG`: 消息。
   - `CISS_MAX_LUN`: 定义了最大的逻辑单元号 (LUN)。
   - `LEVEL2LUN`, `LEVEL3LUN`: 定义了 LUN 的级别。

2. **基本类型定义 (typedef):**
   - `BYTE`: 定义为无符号 8 位整数 (`__u8`)。
   - `WORD`, `HWORD`: 定义为无符号 16 位整数 (`__u16`)。
   - `DWORD`: 定义为无符号 32 位整数 (`__u32`)。

3. **数据结构定义 (typedef struct/union):**
   - `SCSI3Addr_struct`: 定义了 SCSI-3 设备的地址结构，包含物理设备、逻辑设备和逻辑单元的寻址信息。这是一个联合体，用于以不同的方式解释相同的内存区域。
   - `PhysDevAddr_struct`: 定义了物理设备地址结构，包含目标 ID、总线号和模式。
   - `LogDevAddr_struct`: 定义了逻辑设备地址结构，包含卷 ID 和模式。
   - `LUNAddr_struct`: 定义了逻辑单元号 (LUN) 的地址结构，它是一个联合体，可以包含不同的寻址方式。
   - `RequestBlock_struct`: 定义了请求块结构，用于发送命令到 CCISS 设备，包含 CDB (Command Descriptor Block)、命令类型、属性、方向和超时时间。
   - `MoreErrInfo_struct`: 定义了更多错误信息的结构，用于提供命令执行失败的详细原因。
   - `ErrorInfo_struct`: 定义了错误信息结构，包含了 SCSI 状态、Sense 长度、命令状态、剩余计数以及更详细的错误信息和 Sense 信息。

**它与 Android 的功能关系：**

这个头文件是 Android Bionic 的一部分，Bionic 提供了 Android 系统的 C 库和其他底层支持。虽然不是 Android 核心功能直接暴露给应用开发者的部分，但它在以下方面与 Android 功能相关：

1. **底层硬件支持:**  如果 Android 设备的硬件使用了基于 CCISS 协议的 RAID 控制器，那么 Android 内核就需要与这些硬件进行交互。这个头文件就是定义了这种交互的接口。

2. **内核驱动程序接口:** Android 的内核中可能包含了 CCISS 设备的驱动程序。这个头文件作为用户空间程序与这些驱动程序交互的桥梁。

3. **存储抽象层:** 虽然高级的 Android 存储 API (如 MediaStore, Storage Access Framework) 不会直接使用这些定义，但在底层，当涉及到与硬件存储设备交互时，可能需要用到这些定义。

**举例说明:**

假设 Android 设备内部使用了一个基于 CCISS 的 RAID 控制器来管理存储。当 Android 系统需要读取或写入存储设备时，底层的存储驱动程序可能会使用类似以下步骤：

1. **用户空间请求:**  Android Framework 或 NDK 中的代码发起一个文件读写请求。
2. **系统调用:** 该请求最终会转换为一个系统调用，例如 `read()` 或 `write()`, 传递给 Linux 内核。
3. **VFS 层:** Linux 内核的虚拟文件系统 (VFS) 层会根据文件系统类型将请求路由到相应的驱动程序。
4. **CCISS 驱动程序:** 如果目标设备是 CCISS 设备，那么 CCISS 驱动程序会被调用。
5. **构建请求:** CCISS 驱动程序会根据请求的信息构建一个 `RequestBlock_struct` 结构体，其中包含了要执行的命令 (例如 SCSI 的 READ 或 WRITE 命令) 和相关的参数 (例如 LUN 地址、数据传输方向、数据长度等)。这些参数的类型和结构就由 `cciss_defs.h` 定义。
6. **发送命令:** 驱动程序会使用特定的机制 (例如 IOCTL 系统调用) 将构建好的 `RequestBlock_struct` 发送到 CCISS 控制器硬件。
7. **硬件执行:** CCISS 控制器执行命令。
8. **返回结果:** 控制器将执行结果 (包括状态码和可能的错误信息) 返回给驱动程序。
9. **解析结果:** 驱动程序会解析返回的状态码 (例如 `CMD_SUCCESS`, `CMD_DATA_UNDERRUN`)，这些状态码的定义就在 `cciss_defs.h` 中。
10. **返回用户空间:** 驱动程序最终将操作结果返回给用户空间的应用程序。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件 **没有定义任何 libc 函数**。它只定义了常量、类型和数据结构。这些定义被内核驱动程序和可能的一些用户空间工具使用，但它们本身不是 libc 函数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不涉及 dynamic linker**。它是一个头文件，用于编译到其他 C/C++ 代码中。Dynamic linker (如 Android 的 `linker64` 或 `linker`) 的作用是加载和链接共享库 (`.so` 文件)。

如果一个使用了 `cciss_defs.h` 中定义的结构的 **用户空间程序或共享库** 需要加载，那么 dynamic linker 会发挥作用。

**SO 布局样本 (假设存在一个使用这些定义的 `libcciss_utils.so`):**

```
libcciss_utils.so:
    .dynsym:  // 动态符号表，包含导出的函数和变量
        symbol_a: FUNCTION ...
        symbol_b: VARIABLE ...
    .dynstr:  // 动态字符串表，存储符号名
        "symbol_a"
        "symbol_b"
        ...
    .hash / .gnu.hash: // 符号哈希表，用于快速查找符号
    .plt / .got:      // 程序链接表和全局偏移表，用于延迟绑定
    .text:     // 代码段，包含函数实现 (可能会使用 cciss_defs.h 中的定义)
        // ... 实现使用 RequestBlock_struct 等结构的函数 ...
    .rodata:   // 只读数据段，可能包含一些常量
    .data:     // 可读写数据段，可能包含全局变量
    .bss:      // 未初始化数据段

```

**链接的处理过程:**

1. **加载 SO:** 当一个应用程序需要使用 `libcciss_utils.so` 中的功能时，操作系统会调用 dynamic linker 来加载该共享库。
2. **查找依赖:** Dynamic linker 会检查 `libcciss_utils.so` 的依赖项，并确保这些依赖项也已加载。
3. **符号解析:** Dynamic linker 会解析 `libcciss_utils.so` 中引用的外部符号。如果 `libcciss_utils.so` 中使用了标准 C 库的函数 (如 `malloc`, `memcpy`)，dynamic linker 会将这些引用链接到 Bionic 的 libc.so 中的相应函数。
4. **重定位:** Dynamic linker 会修改 SO 的代码和数据段中的地址，以使其在内存中的实际加载地址上正确运行。例如，全局变量的地址需要根据加载地址进行调整。
5. **延迟绑定 (Lazy Binding):**  通常，为了提高启动速度，符号的解析和重定位是延迟进行的。当程序第一次调用 `libcciss_utils.so` 中的某个函数时，PLT 和 GOT 表会被用来解析该函数的实际地址。

**由于 `cciss_defs.h` 只是头文件，它本身不参与链接过程。 只有当包含它的源文件被编译成目标文件，并最终链接成共享库或可执行文件时，dynamic linker 才会处理包含这些定义的目标文件。**

**如果做了逻辑推理，请给出假设输入与输出:**

由于 `cciss_defs.h` 主要定义数据结构和常量，直接的 "输入" 和 "输出" 的概念不太适用。但是，可以假设一个使用这些定义的场景：

**假设输入:**

一个用户空间程序想要读取 CCISS 设备上的一个扇区。它会构建一个 `RequestBlock_struct` 结构体：

```c
#include <linux/cciss_defs.h>
#include <stdio.h>
#include <string.h>

int main() {
    struct RequestBlock_struct req;
    memset(&req, 0, sizeof(req));

    req.CDBLen = 10; // 假设是 SCSI READ(10) 命令
    req.Type.Direction = XFER_READ;
    req.Timeout = 1000; // 1秒超时

    // 构造 CDB (Command Descriptor Block) - 假设读取 LUN 0，LBA 0，1个扇区
    req.CDB[0] = 0x28; // SCSI READ(10) 命令码
    req.CDB[1] = 0x00;
    req.CDB[2] = 0x00;
    req.CDB[3] = 0x00;
    req.CDB[4] = 0x00; // 高位 LBA
    req.CDB[5] = 0x00;
    req.CDB[6] = 0x00;
    req.CDB[7] = 0x00; // 低位 LBA
    req.CDB[8] = 0x00; // 传输长度 (1 个扇区)
    req.CDB[9] = 0x01;

    // ... 将 req 发送给 CCISS 驱动程序的代码 (通常通过 IOCTL) ...

    return 0;
}
```

**假设输出 (从 CCISS 驱动程序返回):**

如果读取成功，驱动程序可能会返回一个包含以下信息的结构：

```c
struct ErrorInfo_struct err_info;
// ... 接收驱动程序返回的 err_info ...

if (err_info.CommandStatus == CMD_SUCCESS) {
    printf("读取成功！\n");
} else {
    printf("读取失败，错误代码: 0x%04X\n", err_info.CommandStatus);
    // 可以根据 err_info 中的其他字段获取更详细的错误信息
}
```

在这个例子中，`RequestBlock_struct` 是程序的输出（发送给驱动程序的），而 `ErrorInfo_struct` 是驱动程序的输出（返回给程序的）。`CMD_SUCCESS` 常量就是 `cciss_defs.h` 中定义的。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **结构体打包错误:**  `#pragma pack(1)` 指示编译器以紧凑的方式打包结构体，不进行字节对齐。如果用户代码没有意识到这一点，可能会错误地假设结构体成员之间存在填充字节，导致与驱动程序的数据交换出现问题。

   ```c
   // 错误的假设，认为结构体是默认对齐的
   struct RequestBlock_struct req;
   req.Timeout = 0x1234; // 期望 Timeout 占用 2 个字节
   // 但由于 #pragma pack(1)，CDB 紧随其后，可能导致数据错位
   ```

2. **错误的命令码或参数:** 使用了错误的 CDB 命令码或参数，导致 CCISS 控制器无法识别或执行命令。

   ```c
   struct RequestBlock_struct req;
   req.CDB[0] = 0xFF; // 无效的命令码
   // ...
   ```

3. **超时时间设置不合理:**  `Timeout` 字段设置得过短，导致命令还在执行中就被认为超时。

   ```c
   struct RequestBlock_struct req;
   req.Timeout = 1; // 非常短的超时时间，可能导致命令经常超时
   // ...
   ```

4. **忽略错误状态:**  没有检查驱动程序返回的 `ErrorInfo_struct` 中的 `CommandStatus`，导致即使命令失败也认为成功。

   ```c
   // 没有检查错误状态
   // ... 发送请求 ...
   // 假设操作成功，但实际上可能失败了
   ```

5. **LUN 地址错误:**  提供了不存在或无效的逻辑单元号。

6. **数据传输方向错误:**  例如，尝试对只读设备进行写操作，或者在应该读取数据时指定了 `XFER_NONE`。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

要从 Android Framework 或 NDK 到达这里 (涉及到 `cciss_defs.h` 中定义的结构)，需要经过多层抽象。通常情况下，开发者不会直接使用这些定义。

**大致路径:**

1. **Android Framework (Java/Kotlin):**  应用程序发起一个存储操作，例如通过 `FileOutputStream` 写入文件。
2. **System Services (Java/Kotlin):** Framework 将请求传递给系统服务，例如 `StorageManagerService` 或 `MediaProvider`.
3. **Native Code (C/C++):** 系统服务会调用底层的 Native 代码，这些代码可能位于 Android 的各种库中 (例如 `libdiskconfig.so`, `libext4_utils.so`, 或硬件抽象层 HAL)。
4. **HAL (Hardware Abstraction Layer):** 如果涉及特定的硬件设备 (例如 CCISS RAID 控制器)，可能需要通过 HAL 进行交互。HAL 定义了一组标准接口，硬件供应商可以实现这些接口来对接 Android 系统。相关的 HAL 模块可能是存储 HAL (`android.hardware.storaged`).
5. **Kernel Driver:** HAL 的实现会与内核驱动程序进行交互。对于 CCISS 设备，这涉及到 CCISS 驱动程序。
6. **System Calls:** HAL 通过系统调用 (例如 `ioctl`) 与内核驱动程序进行通信。传递给 `ioctl` 的参数可能就包含了基于 `cciss_defs.h` 中定义的结构体。

**Frida Hook 示例:**

由于 `cciss_defs.h` 主要在内核空间和一些非常底层的用户空间代码中使用，直接 hook 一个应用层的 Java/Kotlin 函数来观察到这些结构比较困难。更合适的 hook 点是在 Native 层，特别是可能与驱动程序交互的地方。

假设我们想要观察当一个存储操作发生时，传递给 CCISS 驱动程序的 `ioctl` 调用中 `RequestBlock_struct` 的内容。

```python
import frida
import sys

# 假设我们知道与 CCISS 驱动交互的设备文件路径，例如 "/dev/cciss0"
device_path = "/dev/cciss0"

# Frida 脚本
hook_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt3d();
        var request = args[1].toInt3d();

        // 检查文件描述符是否与目标设备相关
        var fd_path = null;
        try {
            fd_path = readlink("/proc/self/fd/" + fd);
        } catch (e) {
            // Ignore errors reading symlink
        }

        if (fd_path && fd_path.startsWith("%s")) {
            console.log("ioctl called for CCISS device!");
            console.log("File Descriptor:", fd);
            console.log("Request Code:", request.toString(16));

            // 假设与 CCISS 相关的 ioctl 命令码是某个特定的值，例如 0x12345678
            if (request == 0x12345678) {
                var request_block_ptr = args[2];
                if (request_block_ptr) {
                    console.log("RequestBlock_struct:");
                    console.log("  CDBLen:", request_block_ptr.readU8());
                    // ... 读取 RequestBlock_struct 的其他字段 ...
                    var type_field = request_block_ptr.add(1).readU8();
                    console.log("  Type.Direction:", (type_field & 0x03));
                    // ... 继续解析结构体 ...
                }
            }
        }
    }
});
""".replace("%s", device_path)

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach("com.example.myapp") # 替换为目标应用包名
    script = session.create_script(hook_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print("目标进程未找到，请确保应用正在运行。")
except Exception as e:
    print(e)
```

**说明:**

1. **目标函数:**  我们 hook 了 `ioctl` 系统调用，这是用户空间程序与设备驱动程序通信的常见方式。
2. **文件描述符检查:**  我们尝试获取 `ioctl` 的文件描述符对应的路径，并检查是否与 CCISS 设备文件路径匹配。
3. **请求码检查:** 可以根据已知的 CCISS 驱动程序的 `ioctl` 请求码来进一步过滤。
4. **解析结构体:**  如果 `ioctl` 调用看起来是针对 CCISS 设备的，并且请求码匹配，我们尝试读取第三个参数，该参数通常是指向传递给 `ioctl` 的数据结构的指针。我们假设该数据结构是 `RequestBlock_struct`，并尝试解析其成员。

**请注意:**

* 这个 Frida 脚本是一个简化的示例，实际情况可能需要更精细的过滤和结构体解析。
* 你需要知道目标 Android 设备上 CCISS 设备的路径 (通常在 `/dev` 目录下) 以及相关的 `ioctl` 请求码才能编写有效的 hook 脚本。
* Hook 系统调用可能需要 root 权限。
* 这种调试方法需要对 Linux 内核和设备驱动程序的工作原理有一定的了解。

通过这种方式，可以使用 Frida 来动态地观察 Android 系统中与底层硬件交互的过程，并分析传递给驱动程序的数据结构的内容，从而理解 Android Framework 或 NDK 如何一步步地到达像 `cciss_defs.h` 中定义的结构。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/cciss_defs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef CCISS_DEFS_H
#define CCISS_DEFS_H
#include <linux/types.h>
#define SENSEINFOBYTES 32
#define CMD_SUCCESS 0x0000
#define CMD_TARGET_STATUS 0x0001
#define CMD_DATA_UNDERRUN 0x0002
#define CMD_DATA_OVERRUN 0x0003
#define CMD_INVALID 0x0004
#define CMD_PROTOCOL_ERR 0x0005
#define CMD_HARDWARE_ERR 0x0006
#define CMD_CONNECTION_LOST 0x0007
#define CMD_ABORTED 0x0008
#define CMD_ABORT_FAILED 0x0009
#define CMD_UNSOLICITED_ABORT 0x000A
#define CMD_TIMEOUT 0x000B
#define CMD_UNABORTABLE 0x000C
#define XFER_NONE 0x00
#define XFER_WRITE 0x01
#define XFER_READ 0x02
#define XFER_RSVD 0x03
#define ATTR_UNTAGGED 0x00
#define ATTR_SIMPLE 0x04
#define ATTR_HEADOFQUEUE 0x05
#define ATTR_ORDERED 0x06
#define ATTR_ACA 0x07
#define TYPE_CMD 0x00
#define TYPE_MSG 0x01
#define BYTE __u8
#define WORD __u16
#define HWORD __u16
#define DWORD __u32
#define CISS_MAX_LUN 1024
#define LEVEL2LUN 1
#define LEVEL3LUN 0
#pragma pack(1)
typedef union _SCSI3Addr_struct {
  struct {
    BYTE Dev;
    BYTE Bus : 6;
    BYTE Mode : 2;
  } PeripDev;
  struct {
    BYTE DevLSB;
    BYTE DevMSB : 6;
    BYTE Mode : 2;
  } LogDev;
  struct {
    BYTE Dev : 5;
    BYTE Bus : 3;
    BYTE Targ : 6;
    BYTE Mode : 2;
  } LogUnit;
} SCSI3Addr_struct;
typedef struct _PhysDevAddr_struct {
  DWORD TargetId : 24;
  DWORD Bus : 6;
  DWORD Mode : 2;
  SCSI3Addr_struct Target[2];
} PhysDevAddr_struct;
typedef struct _LogDevAddr_struct {
  DWORD VolId : 30;
  DWORD Mode : 2;
  BYTE reserved[4];
} LogDevAddr_struct;
typedef union _LUNAddr_struct {
  BYTE LunAddrBytes[8];
  SCSI3Addr_struct SCSI3Lun[4];
  PhysDevAddr_struct PhysDev;
  LogDevAddr_struct LogDev;
} LUNAddr_struct;
typedef struct _RequestBlock_struct {
  BYTE CDBLen;
  struct {
    BYTE Type : 3;
    BYTE Attribute : 3;
    BYTE Direction : 2;
  } Type;
  HWORD Timeout;
  BYTE CDB[16];
} RequestBlock_struct;
typedef union _MoreErrInfo_struct {
  struct {
    BYTE Reserved[3];
    BYTE Type;
    DWORD ErrorInfo;
  } Common_Info;
  struct {
    BYTE Reserved[2];
    BYTE offense_size;
    BYTE offense_num;
    DWORD offense_value;
  } Invalid_Cmd;
} MoreErrInfo_struct;
typedef struct _ErrorInfo_struct {
  BYTE ScsiStatus;
  BYTE SenseLen;
  HWORD CommandStatus;
  DWORD ResidualCnt;
  MoreErrInfo_struct MoreErrInfo;
  BYTE SenseInfo[SENSEINFOBYTES];
} ErrorInfo_struct;
#pragma pack()
#endif

"""

```