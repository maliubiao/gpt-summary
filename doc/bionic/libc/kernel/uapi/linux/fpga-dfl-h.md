Response:
Let's break down the thought process for answering this complex request.

**1. Understanding the Core Request:**

The request asks for a detailed analysis of a Linux kernel header file (`fpga-dfl.h`) within the Android Bionic context. The key elements are:

* **Functionality:** What does this header file *do*?
* **Android Relevance:** How does this relate to Android's capabilities?
* **libc Function Details:** Explain how specific libc functions are used (though this file primarily defines constants, not functions).
* **Dynamic Linker:** How might this interact with the dynamic linker (more about usage than direct linking)?
* **Logic and Examples:**  Provide illustrative scenarios.
* **Common Errors:** Identify potential pitfalls for developers.
* **Android Framework/NDK Integration:** Trace the path from high-level Android to this low-level file.
* **Frida Hooking:** Demonstrate how to intercept calls related to this.

**2. Initial Analysis of the Header File:**

The first step is to read the header file itself. Key observations:

* **Auto-generated:** This immediately suggests a layer of abstraction and potential kernel module involvement.
* **`#ifndef _UAPI_LINUX_FPGA_DFL_H`:** Standard header guard.
* **Includes `<linux/types.h>` and `<linux/ioctl.h>`:**  Indicates this interacts with the Linux kernel's device driver subsystem, specifically using `ioctl`.
* **`DFL_FPGA_API_VERSION`, `DFL_FPGA_MAGIC`, `DFL_FPGA_BASE`, etc.:** These are constants, likely used to define `ioctl` command numbers and base addresses for hardware interaction.
* **`_IO`, `_IOR`, `_IOW` macros:**  These are standard Linux kernel macros for defining `ioctl` commands, specifying data direction (none, read, write).
* **`struct dfl_fpga_port_info`, `dfl_fpga_port_region_info`, etc.:** These structures define the data exchanged via `ioctl` calls. They represent information about FPGA ports, regions, DMA mappings, and interrupts.
* **Focus on FPGA (Field-Programmable Gate Array):**  The file's name and the defined constants clearly point to FPGA hardware management.

**3. Connecting to Android:**

Now, how does this FPGA stuff fit into Android?  Key considerations:

* **Not Core Android Functionality:** FPGAs aren't in every Android device. This suggests a more specialized use case.
* **Possible Use Cases:**  High-performance computing, hardware acceleration (AI/ML, video processing), custom hardware peripherals.
* **Android's Abstraction Layers:** Android aims to hide direct hardware interaction. Therefore, there must be an abstraction layer on top of these direct `ioctl` calls. This leads to thinking about HALs (Hardware Abstraction Layers).

**4. Addressing Specific Request Points:**

* **Functionality:**  The header defines the interface for interacting with an FPGA driver using `ioctl`. It provides mechanisms to:
    * Get API version.
    * Check extensions.
    * Reset ports.
    * Get port information (regions, UMSGs).
    * Get region information (size, offset, permissions).
    * Map and unmap DMA buffers.
    * Get and set interrupt configurations.
    * Manage port resource allocation within the FPGA fabric.

* **Android Relevance & Examples:**
    * **HAL:**  A HAL implementation would use these definitions to communicate with the FPGA driver. Example: An AI accelerator HAL might use `DFL_FPGA_PORT_DMA_MAP` to share input data with the FPGA.
    * **NDK:** An NDK library could provide a C/C++ interface to these `ioctl` calls. Example: A specialized video processing library might use these to offload tasks to the FPGA.

* **libc Functions:** The header itself *doesn't define* libc functions. It defines *constants* used in system calls. The primary libc function involved is `ioctl()`. The explanation should focus on `ioctl()`'s role in sending these commands and data to the kernel driver.

* **Dynamic Linker:**  This header is unlikely to be *directly* linked. The relevant dynamic linking happens with the HAL or NDK libraries that *use* these definitions. The SO layout and linking process would be for those higher-level libraries.

* **Logic and Examples:**  Choose a simple scenario, like getting port information. Outline the steps and the expected data flow.

* **Common Errors:** Focus on incorrect `ioctl` usage: wrong command numbers, incorrect data structures, permission issues, and driver not loaded.

* **Android Framework/NDK Path:**
    1. **Application:** User-level app needs FPGA functionality.
    2. **Framework/NDK API:**  The app uses a high-level API (e.g., AI APIs, custom hardware APIs).
    3. **HAL:** The framework/NDK implementation calls into a specific HAL implementation for the FPGA.
    4. **`ioctl()` calls:** The HAL uses `ioctl()` with the constants defined in this header to communicate with the FPGA kernel driver.

* **Frida Hooking:** Focus on hooking the `ioctl()` system call. Explain how to filter by the file descriptor (if known) or the `ioctl` command number (`DFL_FPGA_MAGIC` and the specific command).

**5. Structuring the Answer:**

Organize the answer logically, following the points in the request. Use clear headings and bullet points for readability. Provide code snippets and diagrams where helpful.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on libc functions *defined* in the header.
* **Correction:** Realize this header primarily defines constants for `ioctl`. Shift focus to `ioctl()`'s role.
* **Initial thought:** Provide a generic SO layout.
* **Correction:** Recognize that the *direct* interaction isn't through linking to this header. Focus on the dynamic linking of the HAL or NDK library that uses these definitions.
* **Initial thought:** Make the Frida example overly complex.
* **Correction:** Simplify the Frida example to focus on the core `ioctl()` interception.

By following this structured thought process, anticipating potential misunderstandings, and refining the approach along the way, a comprehensive and accurate answer can be constructed.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/linux/fpga-dfl.handroid` 这个头文件。

**功能概述**

这个头文件 `fpga-dfl.h` 定义了用户空间程序与 Linux 内核中 FPGA (Field-Programmable Gate Array) 设备驱动进行交互的接口。具体来说，它定义了一系列常量、结构体和 `ioctl` 命令，用于控制和管理 FPGA 设备的功能，特别是针对 Intel DFL (Dynamic Function eXtension Logic) 架构的 FPGA。

主要功能可以归纳为：

1. **定义 API 版本:**  `DFL_FPGA_API_VERSION` 定义了 FPGA 驱动的 API 版本，用于兼容性检查。
2. **定义魔数和基地址:** `DFL_FPGA_MAGIC` 是一个幻数，用于 `ioctl` 命令的构造，确保命令被发送到正确的设备。`DFL_FPGA_BASE`, `DFL_PORT_BASE`, `DFL_FME_BASE` 定义了不同功能组的基地址，用于区分不同的 `ioctl` 命令。
3. **定义 `ioctl` 命令:**  一系列以 `DFL_FPGA_` 开头的宏定义了各种 `ioctl` 命令，用于执行不同的操作，例如：
    * 获取 API 版本 (`DFL_FPGA_GET_API_VERSION`)
    * 检查扩展支持 (`DFL_FPGA_CHECK_EXTENSION`)
    * 重置 FPGA 端口 (`DFL_FPGA_PORT_RESET`)
    * 获取端口信息 (`DFL_FPGA_PORT_GET_INFO`)
    * 获取端口内存区域信息 (`DFL_FPGA_PORT_GET_REGION_INFO`)
    * 映射和取消映射 DMA 缓冲区 (`DFL_FPGA_PORT_DMA_MAP`, `DFL_FPGA_PORT_DMA_UNMAP`)
    * 获取和设置中断 (`DFL_FPGA_PORT_ERR_GET_IRQ_NUM`, `DFL_FPGA_PORT_ERR_SET_IRQ`, `DFL_FPGA_PORT_UINT_GET_IRQ_NUM`, `DFL_FPGA_PORT_UINT_SET_IRQ`)
    * 进行 FPGA 管理引擎 (FME) 的端口操作，如分配和释放端口资源 (`DFL_FPGA_FME_PORT_PR`, `DFL_FPGA_FME_PORT_RELEASE`, `DFL_FPGA_FME_PORT_ASSIGN`)
4. **定义数据结构:**  定义了用于 `ioctl` 命令的数据结构，用于传递参数和接收结果，例如：
    * `dfl_fpga_port_info`: 包含端口的基本信息，如标志、内存区域数量和用户消息队列数量。
    * `dfl_fpga_port_region_info`: 描述端口的内存区域信息，包括大小、偏移和访问权限。
    * `dfl_fpga_port_dma_map`, `dfl_fpga_port_dma_unmap`:  用于 DMA 映射和取消映射的参数。
    * `dfl_fpga_irq_set`: 用于设置中断的起始索引、数量和文件描述符。
    * `dfl_fpga_fme_port_pr`: 用于 FPGA 管理引擎端口资源配置的参数。

**与 Android 功能的关系及举例**

虽然这个头文件直接属于 Linux 内核的 UAPI (User API)，但它在 Android 系统中扮演着重要的角色，特别是当涉及到使用 FPGA 硬件加速的场景。

**例子：硬件加速**

假设一个 Android 设备搭载了支持 Intel DFL 架构的 FPGA，并且有一个应用程序需要利用 FPGA 进行高性能计算或硬件加速，例如：

* **机器学习加速:**  一个机器学习应用可能需要将某些计算密集型的任务卸载到 FPGA 上进行加速，例如模型推理。
* **视频处理加速:**  视频编解码或图像处理应用可以使用 FPGA 来加速编解码过程或进行实时的图像处理。
* **自定义硬件功能:**  某些特定的 Android 设备可能集成了通过 FPGA 实现的自定义硬件功能。

在这种情况下，Android 框架或 NDK 开发的应用程序可以通过以下步骤与 FPGA 驱动进行交互：

1. **打开设备节点:** 应用程序需要打开 FPGA 设备的字符设备节点，通常位于 `/dev` 目录下，例如 `/dev/fpga0`。
2. **使用 `ioctl` 系统调用:** 应用程序使用 `ioctl` 系统调用，并传递这个头文件中定义的命令和数据结构，来控制 FPGA 设备。

**具体举例说明:**

* **获取端口信息:**  应用程序可能需要调用 `ioctl` 并使用 `DFL_FPGA_PORT_GET_INFO` 命令来获取特定 FPGA 端口的信息，例如该端口有多少个可用的内存区域，以及支持多少个用户消息队列。这有助于应用程序了解如何与该端口进行交互。

   ```c
   #include <sys/ioctl.h>
   #include <fcntl.h>
   #include <linux/fpga-dfl.h>
   #include <stdio.h>
   #include <unistd.h>

   int main() {
       int fd = open("/dev/fpga0.0", O_RDWR); // 假设设备节点是 /dev/fpga0.0
       if (fd < 0) {
           perror("打开设备失败");
           return 1;
       }

       struct dfl_fpga_port_info port_info;
       port_info.argsz = sizeof(port_info);

       if (ioctl(fd, DFL_FPGA_PORT_GET_INFO, &port_info) == -1) {
           perror("ioctl 失败");
           close(fd);
           return 1;
       }

       printf("端口信息:\n");
       printf("  标志: 0x%x\n", port_info.flags);
       printf("  内存区域数量: %u\n", port_info.num_regions);
       printf("  用户消息队列数量: %u\n", port_info.num_umsgs);

       close(fd);
       return 0;
   }
   ```

* **映射 DMA 缓冲区:**  应用程序可能需要将用户空间的内存映射到 FPGA 可以直接访问的地址空间，以便 FPGA 可以直接读取或写入数据。这可以通过调用 `ioctl` 并使用 `DFL_FPGA_PORT_DMA_MAP` 命令来实现。

   ```c
   // 假设 user_buffer 是用户空间的缓冲区，length 是缓冲区大小
   struct dfl_fpga_port_dma_map dma_map;
   dma_map.argsz = sizeof(dma_map);
   dma_map.user_addr = (unsigned long)user_buffer;
   dma_map.length = length;

   if (ioctl(fd, DFL_FPGA_PORT_DMA_MAP, &dma_map) == -1) {
       perror("DMA 映射失败");
       // ... 错误处理
   } else {
       printf("DMA 映射成功，IOVA 地址: 0x%llx\n", dma_map.iova);
       // FPGA 可以使用 dma_map.iova 来访问用户缓冲区
   }
   ```

**详细解释 libc 函数的功能实现**

这个头文件本身并不包含任何 libc 函数的实现。它只是定义了常量和数据结构，用于与内核驱动交互。**关键的 libc 函数是 `ioctl`**。

**`ioctl` 函数的功能和实现:**

`ioctl` (input/output control) 是一个系统调用，允许用户空间的程序向设备驱动程序发送控制命令并传递数据。它的原型通常如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`:  文件描述符，通常是通过 `open` 系统调用打开的设备文件。
* `request`:  一个与设备相关的请求码。这个头文件中定义的 `DFL_FPGA_...` 宏就是用于构建这个请求码。Linux 内核使用特定的宏 (`_IO`, `_IOR`, `_IOW`, `_IOWR`) 来生成 `ioctl` 请求码，这些宏会组合魔数、命令编号和数据传输方向。
* `...`:  可选的参数，通常是指向数据的指针，这些数据会被传递给驱动程序或从驱动程序返回。参数的具体类型和大小取决于 `request`。

**`ioctl` 的实现过程:**

1. **系统调用入口:** 用户空间的程序调用 `ioctl` 函数，这是一个陷入内核态的系统调用。
2. **系统调用处理:** 内核接收到 `ioctl` 系统调用后，会根据文件描述符 `fd` 找到对应的设备驱动程序。
3. **驱动程序处理:**  设备驱动程序会实现一个 `ioctl` 函数 (或类似的函数指针，如 `unlocked_ioctl` 或 `compat_ioctl`)，该函数负责处理接收到的 `ioctl` 命令。
4. **命令解析:** 驱动程序的 `ioctl` 函数会解析 `request` 参数，提取魔数和命令编号，以确定用户空间请求的操作。
5. **数据传输:** 如果 `ioctl` 命令需要传递数据，驱动程序会根据请求码中定义的传输方向 (`_IOR`, `_IOW`, `_IOWR`)，从用户空间读取数据或向用户空间写入数据。
6. **执行操作:** 驱动程序根据解析出的命令执行相应的硬件操作或数据处理。对于 FPGA 驱动来说，这可能包括配置 FPGA 内部逻辑、启动 DMA 传输、管理中断等。
7. **返回结果:**  驱动程序完成操作后，会将结果返回给内核。`ioctl` 系统调用最终返回到用户空间，返回值通常表示操作是否成功（0 表示成功，-1 表示失败）。

**涉及 dynamic linker 的功能**

这个头文件本身不涉及动态链接器的功能。动态链接器 (如 Android 的 `linker64` 或 `linker`) 的主要作用是在程序启动时加载共享库 (`.so` 文件) 并解析符号引用。

然而，如果用户空间程序需要与 FPGA 驱动进行交互，它可能会链接到提供 FPGA 相关功能的共享库。这个共享库内部可能会使用 `ioctl` 系统调用以及这个头文件中定义的常量和结构体。

**so 布局样本 (假设存在一个名为 `libfpga.so` 的共享库):**

```
libfpga.so:
    .text          # 代码段
        fpga_init()
        fpga_get_port_info()
        fpga_dma_map()
        ...
    .rodata        # 只读数据段 (可能包含一些常量)
    .data          # 可读写数据段
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # 程序链接表
    .got           # 全局偏移表
```

**链接的处理过程:**

1. **编译链接:**  应用程序在编译链接时，会指定链接 `libfpga.so`。链接器会记录下对 `libfpga.so` 中符号的引用。
2. **程序启动:** 当应用程序启动时，Android 的动态链接器会：
    * **加载共享库:**  找到 `libfpga.so` 并将其加载到内存中。
    * **符号解析:**  解析应用程序中对 `libfpga.so` 中函数的引用，将这些引用指向 `libfpga.so` 中对应的函数地址。
    * **重定位:**  调整共享库中的一些地址，使其在当前进程的地址空间中正确工作。

**假设输入与输出 (针对 `ioctl` 调用):**

**假设输入:**

* `fd`:  已打开的 FPGA 设备文件描述符 (例如，通过 `open("/dev/fpga0.0", O_RDWR)` 获取)。
* `request`:  `DFL_FPGA_PORT_GET_INFO` (宏展开后的数值)。
* `argp`:  指向 `struct dfl_fpga_port_info` 结构体的指针，其中 `argsz` 成员已设置为 `sizeof(struct dfl_fpga_port_info)`.

**预期输出:**

* `ioctl` 函数返回 0 表示成功。
* `argp` 指向的 `struct dfl_fpga_port_info` 结构体中的其他成员 (如 `flags`, `num_regions`, `num_umsgs`) 会被内核驱动填充，包含 FPGA 端口的实际信息。如果 `ioctl` 失败，则返回 -1，并设置 `errno` 错误码。

**用户或编程常见的使用错误**

1. **错误的设备节点:** 打开了错误的设备节点，或者设备节点不存在。
2. **权限问题:**  用户没有足够的权限访问设备节点。
3. **`ioctl` 命令错误:** 使用了错误的 `ioctl` 命令码，或者命令码与设备驱动不匹配。
4. **数据结构错误:** 传递给 `ioctl` 的数据结构大小不正确，或者成员设置不正确。例如，忘记设置 `argsz` 成员。
5. **驱动未加载:**  FPGA 驱动程序没有正确加载或初始化。
6. **参数错误:**  传递给 `ioctl` 的参数值不合法，例如，DMA 映射的地址或长度无效。
7. **资源冲突:**  尝试访问已被其他进程或设备占用的资源。

**举例说明:**

```c
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/fpga-dfl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main() {
    int fd = open("/dev/wrong_fpga_device", O_RDWR); // 错误的设备节点
    if (fd < 0) {
        perror("打开设备失败");
        return 1;
    }

    struct dfl_fpga_port_info port_info;
    // 忘记设置 argsz，导致数据结构大小信息不正确
    // port_info.argsz = sizeof(port_info);

    if (ioctl(fd, DFL_FPGA_PORT_GET_INFO, &port_info) == -1) {
        perror("ioctl 失败");
        printf("错误码: %d\n", errno);
        close(fd);
        return 1;
    }

    // ... 后续操作

    close(fd);
    return 0;
}
```

在这个例子中，如果打开了错误的设备节点，`open` 调用会失败。如果忘记设置 `port_info.argsz`，`ioctl` 调用可能会失败，因为内核驱动无法正确判断传入的数据结构大小。

**Android framework or ndk 是如何一步步的到达这里**

1. **应用层 (Java/Kotlin):**  Android 应用程序可能需要使用 FPGA 提供的硬件加速功能。
2. **Framework API (Java):** Android Framework 可能会提供一些高级 API，用于访问硬件加速器。例如，Android 的 Neural Networks API (NNAPI) 可以将机器学习任务委托给不同的硬件加速器，包括 FPGA。
3. **NDK (C/C++):**  开发者也可以使用 NDK 直接编写 C/C++ 代码来与硬件交互。他们可能会使用一些辅助库或直接调用系统调用。
4. **Hardware Abstraction Layer (HAL):**  Android 使用 HAL 来抽象底层的硬件细节。针对 FPGA 设备，可能会有一个专门的 HAL 模块 (通常是 `.so` 文件)。这个 HAL 模块会提供 C 接口，供上层 Framework 或 NDK 调用。
5. **HAL 实现:** HAL 的实现代码会打开 FPGA 的设备节点 (`/dev/fpga*`)，并使用 `ioctl` 系统调用以及 `bionic/libc/kernel/uapi/linux/fpga-dfl.h` 中定义的常量和结构体来与 FPGA 驱动程序通信。
6. **Kernel Driver:** Linux 内核中的 FPGA 驱动程序接收到来自用户空间的 `ioctl` 调用后，会解析命令并操作 FPGA 硬件。

**Frida hook 示例调试这些步骤**

可以使用 Frida hook `ioctl` 系统调用，并过滤与 FPGA 设备相关的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device(timeout=10)
pid = device.spawn(["com.example.fpga_app"]) # 替换为你的应用包名
session = device.attach(pid)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 可以根据文件描述符或 ioctl 命令进行过滤
        // 假设 FPGA 设备的路径包含 "fpga"
        const path = this.context.fd ? this.context.fd.path : null;
        if (path && path.includes("fpga")) {
            send({ type: 'send', payload: `ioctl called with fd: ${fd}, request: 0x${request.toString(16)}` });

            // 可以进一步解析 request，判断具体的 ioctl 命令
            // if (request === 0xb600) { // 假设 DFL_FPGA_GET_API_VERSION 的值为 0xb600
            //     send({ type: 'send', payload: "  DFL_FPGA_GET_API_VERSION" });
            // }
        }
    },
    onLeave: function(retval) {
        // 可以查看 ioctl 的返回值
        // if (this.context.fd && this.context.fd.path && this.context.fd.path.includes("fpga")) {
        //     send({ type: 'send', payload: `ioctl returned: ${retval}` });
        // }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
device.resume(pid)
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **连接设备和附加进程:** 代码首先连接到 USB 设备，并启动或附加到目标 Android 应用程序进程。
2. **Hook `ioctl`:** 使用 `Interceptor.attach` 拦截 `ioctl` 系统调用。
3. **`onEnter` 函数:** 当 `ioctl` 被调用时，`onEnter` 函数会被执行。
4. **过滤 `ioctl` 调用:**  代码通过检查文件描述符对应的路径是否包含 "fpga" 来过滤与 FPGA 设备相关的 `ioctl` 调用。你可能需要根据实际情况调整过滤条件。
5. **打印信息:** 打印出 `ioctl` 调用的文件描述符和请求码。
6. **`onLeave` 函数 (可选):**  `onLeave` 函数可以在 `ioctl` 调用返回后执行，可以查看返回值。
7. **加载和运行脚本:**  加载 Frida 脚本并恢复应用程序的执行。

通过运行这个 Frida 脚本，你可以观察到应用程序在与 FPGA 设备驱动交互时调用的 `ioctl` 命令，从而帮助你调试和理解 Android Framework 或 NDK 如何一步步到达这里。你可以根据打印出的请求码，对照 `fpga-dfl.h` 中的定义，来确定具体执行了哪个 FPGA 操作。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/fpga-dfl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_FPGA_DFL_H
#define _UAPI_LINUX_FPGA_DFL_H
#include <linux/types.h>
#include <linux/ioctl.h>
#define DFL_FPGA_API_VERSION 0
#define DFL_FPGA_MAGIC 0xB6
#define DFL_FPGA_BASE 0
#define DFL_PORT_BASE 0x40
#define DFL_FME_BASE 0x80
#define DFL_FPGA_GET_API_VERSION _IO(DFL_FPGA_MAGIC, DFL_FPGA_BASE + 0)
#define DFL_FPGA_CHECK_EXTENSION _IO(DFL_FPGA_MAGIC, DFL_FPGA_BASE + 1)
#define DFL_FPGA_PORT_RESET _IO(DFL_FPGA_MAGIC, DFL_PORT_BASE + 0)
struct dfl_fpga_port_info {
  __u32 argsz;
  __u32 flags;
  __u32 num_regions;
  __u32 num_umsgs;
};
#define DFL_FPGA_PORT_GET_INFO _IO(DFL_FPGA_MAGIC, DFL_PORT_BASE + 1)
struct dfl_fpga_port_region_info {
  __u32 argsz;
  __u32 flags;
#define DFL_PORT_REGION_READ (1 << 0)
#define DFL_PORT_REGION_WRITE (1 << 1)
#define DFL_PORT_REGION_MMAP (1 << 2)
  __u32 index;
#define DFL_PORT_REGION_INDEX_AFU 0
#define DFL_PORT_REGION_INDEX_STP 1
  __u32 padding;
  __u64 size;
  __u64 offset;
};
#define DFL_FPGA_PORT_GET_REGION_INFO _IO(DFL_FPGA_MAGIC, DFL_PORT_BASE + 2)
struct dfl_fpga_port_dma_map {
  __u32 argsz;
  __u32 flags;
  __u64 user_addr;
  __u64 length;
  __u64 iova;
};
#define DFL_FPGA_PORT_DMA_MAP _IO(DFL_FPGA_MAGIC, DFL_PORT_BASE + 3)
struct dfl_fpga_port_dma_unmap {
  __u32 argsz;
  __u32 flags;
  __u64 iova;
};
#define DFL_FPGA_PORT_DMA_UNMAP _IO(DFL_FPGA_MAGIC, DFL_PORT_BASE + 4)
struct dfl_fpga_irq_set {
  __u32 start;
  __u32 count;
  __s32 evtfds[];
};
#define DFL_FPGA_PORT_ERR_GET_IRQ_NUM _IOR(DFL_FPGA_MAGIC, DFL_PORT_BASE + 5, __u32)
#define DFL_FPGA_PORT_ERR_SET_IRQ _IOW(DFL_FPGA_MAGIC, DFL_PORT_BASE + 6, struct dfl_fpga_irq_set)
#define DFL_FPGA_PORT_UINT_GET_IRQ_NUM _IOR(DFL_FPGA_MAGIC, DFL_PORT_BASE + 7, __u32)
#define DFL_FPGA_PORT_UINT_SET_IRQ _IOW(DFL_FPGA_MAGIC, DFL_PORT_BASE + 8, struct dfl_fpga_irq_set)
struct dfl_fpga_fme_port_pr {
  __u32 argsz;
  __u32 flags;
  __u32 port_id;
  __u32 buffer_size;
  __u64 buffer_address;
};
#define DFL_FPGA_FME_PORT_PR _IO(DFL_FPGA_MAGIC, DFL_FME_BASE + 0)
#define DFL_FPGA_FME_PORT_RELEASE _IOW(DFL_FPGA_MAGIC, DFL_FME_BASE + 1, int)
#define DFL_FPGA_FME_PORT_ASSIGN _IOW(DFL_FPGA_MAGIC, DFL_FME_BASE + 2, int)
#define DFL_FPGA_FME_ERR_GET_IRQ_NUM _IOR(DFL_FPGA_MAGIC, DFL_FME_BASE + 3, __u32)
#define DFL_FPGA_FME_ERR_SET_IRQ _IOW(DFL_FPGA_MAGIC, DFL_FME_BASE + 4, struct dfl_fpga_irq_set)
#endif
```