Response:
Let's break down the thought process for analyzing the provided `iommufd.h` header file and generating the comprehensive response.

**1. Understanding the Goal:**

The request asks for a detailed analysis of the C header file, including its functionality, relationship to Android, implementation details (where applicable), dynamic linking aspects, usage errors, and how Android frameworks interact with it. The core subject is the `iommufd` (IOMMU file descriptor) interface.

**2. Initial File Scan and Keyword Recognition:**

The first step is to quickly scan the file and identify key elements:

* **`#ifndef _UAPI_IOMMUFD_H` and `#define _UAPI_IOMMUFD_H`:**  This is a standard include guard, indicating a header file.
* **`#include <linux/ioctl.h>` and `#include <linux/types.h>`:** This points to the usage of Linux kernel interfaces, particularly `ioctl` for device control.
* **`IOMMUFD_TYPE (';')`:** Defines a type character for the `ioctl` commands.
* **`enum { ... }`:** Defines a set of constants, specifically `IOMMUFD_CMD_*`, representing different commands for the `iommufd`.
* **`struct iommu_* { ... }`:** Defines various data structures that are used as arguments to the `ioctl` commands.
* **`#define IOMMU_* _IO(IOMMUFD_TYPE, IOMMUFD_CMD_*)`:**  These macros define the actual `ioctl` command numbers using the `_IO` macro. This is a strong indicator of an interface for interacting with a kernel driver.
* **`enum iommufd_* { ... }`:** Defines enumerations for flags and options related to the commands.

**3. Inferring Core Functionality - The "What":**

Based on the identified elements, especially the commands and data structures, the core functionality becomes apparent: This header defines an interface for managing IOMMU (Input/Output Memory Management Unit) functionality. The commands suggest operations like:

* **Object Management:** Creating (`_ALLOC`), destroying (`_DESTROY`).
* **Address Space Management:** Allocating (`_IOAS_ALLOC`), allowing specific IOVAs (`_IOAS_ALLOW_IOVAS`), copying data between address spaces (`_IOAS_COPY`), querying available ranges (`_IOAS_IOVA_RANGES`), mapping (`_IOAS_MAP`), unmapping (`_IOAS_UNMAP`).
* **Hardware Page Table Management:** Allocating (`_HWPT_ALLOC`), setting dirty tracking (`_HWPT_SET_DIRTY_TRACKING`), getting dirty bitmaps (`_HWPT_GET_DIRTY_BITMAP`), invalidating (`_HWPT_INVALIDATE`).
* **Fault Handling:** Allocating fault queues (`_FAULT_QUEUE_ALLOC`).
* **Configuration/Information:** Setting/getting options (`_OPTION`), getting hardware information (`_GET_HW_INFO`).
* **VFIO Integration:** Related to using IOMMU with VFIO (`_VFIO_IOAS`).

**4. Connecting to Android - The "Why Android Cares":**

The file is located within `bionic`, Android's C library. This immediately suggests its importance for low-level Android functionality. Thinking about where IOMMUs are crucial leads to:

* **Hardware Acceleration:**  GPUs, network cards, and other peripherals use DMA (Direct Memory Access) and thus benefit from IOMMUs for security and memory management.
* **Virtualization:**  Android can run virtual machines or containers, which heavily rely on IOMMUs for securely managing hardware access.
* **Security:** IOMMUs prevent malicious or buggy peripherals from accessing arbitrary system memory.

**5. Deep Dive into Individual Functions (Commands) - The "How":**

For each `ioctl` command (`IOMMU_*`), the associated structure provides details about its parameters. The analysis involves:

* **Identifying the purpose of each field:**  `size`, `flags`, `id`, `user_va`, `length`, `iova`, etc.
* **Understanding the data flow:**  Which fields are input, which are output, and which are both.
* **Inferring the operation performed by the kernel driver upon receiving this command and data.**  This often involves connecting the command name with the structure fields (e.g., `IOMMU_IOAS_MAP` likely maps a user-space virtual address to an IOMMU virtual address).

**6. Addressing Dynamic Linking - The "Where in Memory":**

Since this is a header file within `bionic`, the question of dynamic linking arises.

* **Identifying the relevant components:** The header itself doesn't directly involve dynamic linking, but the *use* of these definitions in other libraries and applications does.
* **Creating a mental model of library dependencies:**  Applications would use functions defined in other shared libraries (`.so` files) which, in turn, might make `ioctl` calls using these structures.
* **Generating a sample SO layout:** This helps visualize how different parts of the system (app, shared library, kernel) interact.
* **Explaining the linking process:**  How the dynamic linker resolves symbols and ensures proper communication.

**7. Anticipating Usage Errors - The "Gotchas":**

Based on the API design, common mistakes can be identified:

* **Incorrect size:** Passing the wrong `size` field in the structures.
* **Invalid flags:** Using undefined or inappropriate flag combinations.
* **Resource management errors:** Failing to `destroy` allocated objects.
* **IOVA conflicts:** Attempting to map to already used IOVAs.
* **Permissions issues:** Trying to map memory with incorrect read/write permissions.

**8. Tracing the Call Path - The "Journey":**

The request asks how Android frameworks reach this code. This involves a top-down approach:

* **Identifying the starting point:**  High-level Android frameworks or NDK APIs related to hardware access (e.g., interacting with graphics, networking).
* **Tracing down through layers:**  Framework APIs call into native libraries, which might then use system calls (like `ioctl`) that utilize the definitions in this header.
* **Illustrating with a concrete example:**  Using GPU memory allocation as a use case.
* **Providing a Frida hook example:**  Demonstrating how to intercept and inspect these interactions at runtime.

**9. Structuring the Response - Clarity and Organization:**

The final step is to organize the information logically and clearly:

* **Start with a summary of the file's purpose.**
* **Detail the functionality by grouping related commands.**
* **Explain the connection to Android with concrete examples.**
* **Address the implementation details (focusing on the `ioctl` mechanism).**
* **Discuss dynamic linking aspects with an SO layout.**
* **Provide examples of common usage errors.**
* **Illustrate the Android framework call path.**
* **Include a Frida hooking example.**

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just a header file, how much detail can I go into about implementation?"  *Correction:* Focus on explaining *what* the structures and commands represent in terms of kernel driver interaction, even without the driver's source code.
* **Realization:**  The request asks for dynamic linking details, but the header file itself isn't linked. *Clarification:* Explain how the *use* of these definitions in other dynamically linked libraries is relevant.
* **Considering the audience:** The response should be comprehensive but also understandable. Avoid overly technical jargon where possible, or explain it clearly.

By following these steps, the detailed and informative response can be generated. The process involves understanding the request, dissecting the code, connecting it to the broader context (Android), and then organizing the findings in a clear and structured manner.
这个头文件 `bionic/libc/kernel/uapi/linux/iommufd.handroid` 定义了用户空间程序与 Linux 内核中的 IOMMU (Input/Output Memory Management Unit) 驱动进行交互的接口。它使用了 `ioctl` 系统调用来发送命令和数据到内核，并定义了相关的命令码和数据结构。由于它位于 `bionic` 目录下的 `kernel/uapi`，这意味着它是 Android 系统中用户空间程序可以用来与内核 IOMMU 功能进行交互的接口定义。

**它的功能:**

这个头文件定义了与 IOMMU 文件描述符 (iommufd) 交互的各种命令和数据结构，允许用户空间程序执行以下操作：

1. **IOMMU 实例管理:**
   - `IOMMU_DESTROY`: 销毁一个 IOMMU 实例。

2. **IO 地址空间 (IOAS) 管理:**
   - `IOMMU_IOAS_ALLOC`: 分配一个 IO 地址空间。
   - `IOMMU_IOAS_ALLOW_IOVAS`: 允许特定的 IO 虚拟地址 (IOVA) 范围在 IOAS 中使用。
   - `IOMMU_IOAS_COPY`: 在不同的 IOAS 之间复制数据。
   - `IOMMU_IOAS_IOVA_RANGES`: 获取 IOAS 中允许的 IOVA 范围信息。
   - `IOMMU_IOAS_MAP`: 将用户空间的虚拟地址映射到 IOAS 中的 IOVA。
   - `IOMMU_IOAS_UNMAP`: 取消用户空间虚拟地址到 IOVA 的映射。

3. **IOMMU 选项配置:**
   - `IOMMU_OPTION`: 设置或获取 IOMMU 相关的选项，例如资源限制模式或是否使用大页。

4. **VFIO 集成:**
   - `IOMMU_VFIO_IOAS`:  用于与 VFIO (Virtual Function I/O) 集成的操作，例如获取、设置或清除与 VFIO 相关的 IOAS。

5. **硬件页表 (HWPT) 管理:**
   - `IOMMU_HWPT_ALLOC`: 分配一个硬件页表。
   - `IOMMU_HWPT_SET_DIRTY_TRACKING`: 启用或禁用硬件页表的脏位跟踪。
   - `IOMMU_HWPT_GET_DIRTY_BITMAP`: 获取硬件页表的脏位图。
   - `IOMMU_HWPT_INVALIDATE`: 使硬件页表中的条目失效。

6. **获取硬件信息:**
   - `IOMMU_GET_HW_INFO`: 获取 IOMMU 硬件的特定信息，例如 Intel VT-d 的能力寄存器。

7. **故障队列管理:**
   - `IOMMU_FAULT_QUEUE_ALLOC`: 分配一个用于接收 IOMMU 故障的队列。

**与 Android 功能的关系和举例说明:**

IOMMU 在 Android 系统中主要用于增强硬件虚拟化和设备隔离的安全性。例如：

* **保障直通设备 (Passthrough Devices) 的安全:** 在 Android 虚拟化场景中，例如运行虚拟机或容器，IOMMU 可以防止虚拟机或容器中的恶意驱动程序通过 DMA 访问宿主机或其他虚拟机的内存，从而提高安全性。
    * **例子:** Android 中的 `VirtualizationService` 可能使用 `iommufd` 接口来配置 IOMMU，以确保分配给虚拟机的硬件设备只能访问分配给它的内存区域。

* **保护系统免受恶意或错误的硬件驱动程序的影响:**  即使在非虚拟化场景下，IOMMU 也可以限制硬件设备的 DMA 访问范围，防止有漏洞或恶意的硬件驱动程序破坏系统内存。
    * **例子:** Android 中的图形驱动程序或者网络驱动程序可能会间接使用 IOMMU，例如在分配 DMA buffer 时，系统可能会使用 IOMMU 来限制这些 buffer 的访问范围。

* **支持硬件加速的安全性:** 某些硬件加速器（例如 GPU）可能使用 DMA 来访问内存。IOMMU 可以确保这些加速器只能访问授权的内存区域，防止安全漏洞。
    * **例子:**  当 Android 应用程序使用 RenderScript 或 Vulkan API 进行图形渲染时，底层的图形驱动程序可能会使用 `iommufd` 来管理 GPU 对内存的访问权限。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身并没有定义任何 C 函数。它定义的是用于 `ioctl` 系统调用的常量和数据结构。用户空间的程序需要使用标准 C 库提供的 `ioctl` 函数，并传入这里定义的命令码和数据结构指针，才能与内核 IOMMU 驱动进行交互。

例如，要分配一个 IO 地址空间，用户空间程序会执行以下步骤：

1. 打开 `/dev/iommu` 设备文件描述符 (fd)。
2. 填充 `struct iommu_ioas_alloc` 结构体，设置 `flags` 等参数。
3. 调用 `ioctl(fd, IOMMU_IOAS_ALLOC, &ioas_alloc_struct)`，其中 `IOMMU_IOAS_ALLOC` 是宏定义的一个 `ioctl` 命令码。

`ioctl` 函数是一个系统调用，它的实现位于 Linux 内核中。当用户空间程序调用 `ioctl` 时，会陷入内核态，内核会根据传入的文件描述符找到对应的设备驱动程序（在这里是 IOMMU 驱动程序），然后调用该驱动程序中与传入的命令码对应的处理函数。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker 的功能。它定义的是内核接口。但是，用户空间的库（例如 Android 的某些 HAL 库或 Framework 中的 native 代码）可能会使用这个头文件中定义的接口。这些库会被动态链接到应用程序进程中。

**SO 布局样本:**

假设有一个名为 `libiommud_client.so` 的共享库，它使用了 `iommufd` 接口：

```
libiommud_client.so:
    .text:  // 代码段，包含使用 ioctl 的函数
        client_allocate_ioas:
            // ... 填充 struct iommu_ioas_alloc
            // ... 调用 ioctl(iommu_fd, IOMMU_IOAS_ALLOC, ...)
            // ...

    .data:  // 数据段，可能包含一些全局变量

    .bss:   // 未初始化数据段

    .dynsym: // 动态符号表，记录导出的和导入的符号
        // 导入的符号：ioctl
    .dynstr: // 动态字符串表，存储符号名称

    .plt:   // 过程链接表，用于延迟绑定
        ioctl@LIBC

    .got.plt: // 全局偏移量表，存储导入符号的地址
        // ioctl 的地址会在运行时被 dynamic linker 填充
```

**链接的处理过程:**

1. **编译时:** 编译器遇到 `ioctl` 函数调用时，会生成一个对 `ioctl@LIBC` 的引用。`LIBC` 表示 `libc.so`。
2. **链接时:** 静态链接器在创建 `libiommud_client.so` 时，会记录下对 `ioctl` 的未解析引用。
3. **加载时:** 当应用程序加载 `libiommud_client.so` 时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责解析这些未解析的引用。
4. **查找依赖:** dynamic linker 会读取 `libiommud_client.so` 的依赖信息，找到 `libc.so`。
5. **符号解析:** dynamic linker 会在 `libc.so` 的动态符号表中查找 `ioctl` 的定义。
6. **重定位:** dynamic linker 会将 `ioctl` 在 `libc.so` 中的实际地址填充到 `libiommud_client.so` 的 `.got.plt` 表中。
7. **延迟绑定 (如果使用):** 通常，为了提高启动速度，会使用延迟绑定。第一次调用 `ioctl` 时，会跳转到 `.plt` 表中的一段代码，该代码会调用 dynamic linker 来解析符号并更新 `.got.plt` 表。后续调用将直接通过 `.got.plt` 跳转到 `ioctl` 的实际地址。

**如果做了逻辑推理，请给出假设输入与输出:**

假设用户空间程序想要分配一个 ID 为 10 的 IO 地址空间：

**假设输入 (对于 `IOMMU_IOAS_ALLOC` 命令):**

* `fd`:  打开 `/dev/iommu` 得到的文件描述符。
* `struct iommu_ioas_alloc`:
    * `size`: `sizeof(struct iommu_ioas_alloc)`
    * `flags`:  0 (或其他定义的标志)
    * `out_ioas_id`:  程序希望内核返回分配的 IOAS 的 ID，但这是一个输出参数，所以输入时通常不设置或设置为 0。

**预期输出:**

* `ioctl` 系统调用成功返回 0。
* `struct iommu_ioas_alloc.out_ioas_id`: 内核分配的 IO 地址空间的 ID，例如 10（如果内核允许）。

**假设输入 (对于 `IOMMU_IOAS_MAP` 命令):**

假设用户空间想要将地址 `0x10000000`，长度为 `4096` 字节的内存映射到 IOAS ID 为 10 的 IOVA `0x20000000`。

* `fd`: 打开 `/dev/iommu` 得到的文件描述符。
* `struct iommu_ioas_map`:
    * `size`: `sizeof(struct iommu_ioas_map)`
    * `flags`: 0 (或其他定义的标志，例如 `IOMMU_IOAS_MAP_FIXED_IOVA`)
    * `ioas_id`: 10
    * `user_va`: `0x10000000`
    * `length`: `4096`
    * `iova`: `0x20000000` (如果 `flags` 包含 `IOMMU_IOAS_MAP_FIXED_IOVA`) 或 0 (让内核分配 IOVA)。

**预期输出:**

* `ioctl` 系统调用成功返回 0。
* 如果没有指定 `IOMMU_IOAS_MAP_FIXED_IOVA`，则内核可能会在 `struct iommu_ioas_map` 的某个输出字段中返回实际分配的 IOVA。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **传递错误的 `size` 值:**  `ioctl` 通常会检查传入结构体的大小，如果 `size` 字段不正确，内核可能会拒绝该请求并返回错误，例如 `EINVAL`。

   ```c
   struct iommu_ioas_alloc alloc;
   alloc.size = 0; // 错误！应该设置为 sizeof(alloc)
   ioctl(fd, IOMMU_IOAS_ALLOC, &alloc); // 可能返回错误
   ```

2. **使用无效的标志:** 传递了未定义的或不支持的标志值，可能导致内核行为异常或返回错误。

   ```c
   struct iommu_ioas_map map;
   map.flags = 0xFFFFFFFF; // 假设这是一个无效的标志组合
   ioctl(fd, IOMMU_IOAS_MAP, &map); // 可能返回错误
   ```

3. **尝试映射已经映射的区域:**  如果用户尝试将同一块用户空间内存或 IOVA 多次映射，可能会导致冲突。

4. **忘记释放资源:** 分配了 IO 地址空间或硬件页表后，忘记调用 `IOMMU_DESTROY` 进行释放，可能导致资源泄漏。

5. **IOVA 冲突:** 在没有指定 `IOMMU_IOAS_MAP_FIXED_IOVA` 的情况下，如果请求的 IOVA 范围与已有的映射冲突，内核会拒绝映射。

6. **权限错误:**  尝试映射没有访问权限的内存区域。

7. **在错误的 IOMMU 实例上操作:** 如果系统中有多个 IOMMU 实例，操作了错误的实例可能会导致不可预测的结果。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android Framework 或 NDK 不会直接调用 `ioctl` 来操作 `iommufd`。这些操作通常发生在更底层的 HAL (Hardware Abstraction Layer) 库或者内核驱动程序中。

**可能的路径:**

1. **Framework 层:** Android Framework 中的某些服务，例如 `VirtualizationService` 或与图形、网络相关的服务，可能需要与 IOMMU 交互。
2. **Native 代码:** 这些 Framework 服务通常会调用底层的 Native 代码 (C/C++)。
3. **HAL 层:** Native 代码可能会调用硬件相关的 HAL 库，这些库负责与内核驱动程序交互。
4. **ioctl 调用:** 在 HAL 库的实现中，会打开 `/dev/iommu` 设备文件，并使用 `ioctl` 系统调用，传入 `iommufd.h` 中定义的命令码和数据结构，来配置 IOMMU。
5. **内核驱动:** 内核接收到 `ioctl` 调用后，IOMMU 驱动程序会处理这些请求，执行相应的 IOMMU 操作。

**Frida Hook 示例:**

假设我们想 hook `libiommud_client.so` 中调用 `ioctl` 的 `client_allocate_ioas` 函数，并查看传递给 `ioctl` 的参数。

```python
import frida
import sys

package_name = "your.android.app"  # 替换为你的应用程序包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到正在运行的进程: {package_name}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libiommud_client.so", "client_allocate_ioas"), {
    onEnter: function(args) {
        console.log("[+] client_allocate_ioas called");
        // 假设 client_allocate_ioas 的第一个参数是 iommu_fd，第二个参数是指向 iommu_ioas_alloc 结构的指针
        var iommu_fd = args[0].toInt32();
        var alloc_ptr = args[1];

        console.log("[+] iommu_fd:", iommu_fd);

        if (alloc_ptr.isNull() === false) {
            var alloc_struct = Memory.readByteArray(alloc_ptr, Process.pageSize); // 读取结构体内容，可以根据实际大小调整
            console.log("[+] iommu_ioas_alloc struct:", hexdump(alloc_struct, { length: 64 })); // 打印结构体内容
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var argp = args[2];

        console.log("[+] ioctl called with fd:", fd, "request:", request);

        if (request === 0xc0043b81) { // 假设 IOMMU_IOAS_ALLOC 的 ioctl 请求码是 0xc0043b81，需要根据实际值替换
            console.log("[+] IOMMU_IOAS_ALLOC command detected");
            if (argp.isNull() === false) {
                var alloc_struct = Memory.readByteArray(argp, Process.pageSize);
                console.log("[+] iommu_ioas_alloc struct:", hexdump(alloc_struct, { length: 64 }));
            }
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

1. **Attach to Process:**  连接到目标 Android 应用程序进程。
2. **Hook `client_allocate_ioas`:** 拦截 `libiommud_client.so` 中的 `client_allocate_ioas` 函数，打印其被调用的信息以及参数（假设是文件描述符和指向 `iommu_ioas_alloc` 结构的指针）。
3. **Hook `ioctl`:** 拦截 `libc.so` 中的 `ioctl` 函数，打印其文件描述符和请求码。
4. **Check for `IOMMU_IOAS_ALLOC`:**  如果 `ioctl` 的请求码与 `IOMMU_IOAS_ALLOC` 宏定义的值匹配（需要根据实际计算或反汇编获取），则打印一条消息，并读取并打印传递给 `ioctl` 的 `iommu_ioas_alloc` 结构体的内容。
5. **启动脚本:** 将 Frida 脚本注入到目标进程。

**使用步骤:**

1. 确保你的 Android 设备已连接并通过 ADB 连接。
2. 安装 Frida 和 Frida-tools (`pip install frida frida-tools`).
3. 替换 `package_name` 为你要调试的应用程序的包名。
4. 替换 `0xc0043b81` 为 `IOMMU_IOAS_ALLOC` 实际的 `ioctl` 请求码。你可以通过查看内核源码或者反汇编相关的 HAL 库来获取。
5. 运行 Frida 脚本 (`python your_frida_script.py`)。
6. 在你的 Android 应用程序中触发与 IOMMU 交互的操作。
7. 查看 Frida 的输出，它会打印出 `client_allocate_ioas` 和 `ioctl` 的调用信息以及相关的数据结构内容。

这个示例展示了如何使用 Frida 来追踪用户空间程序与 IOMMU 驱动的交互过程，帮助你理解 Android Framework 或 NDK 如何最终到达这个底层的内核接口。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/iommufd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_IOMMUFD_H
#define _UAPI_IOMMUFD_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define IOMMUFD_TYPE (';')
enum {
  IOMMUFD_CMD_BASE = 0x80,
  IOMMUFD_CMD_DESTROY = IOMMUFD_CMD_BASE,
  IOMMUFD_CMD_IOAS_ALLOC = 0x81,
  IOMMUFD_CMD_IOAS_ALLOW_IOVAS = 0x82,
  IOMMUFD_CMD_IOAS_COPY = 0x83,
  IOMMUFD_CMD_IOAS_IOVA_RANGES = 0x84,
  IOMMUFD_CMD_IOAS_MAP = 0x85,
  IOMMUFD_CMD_IOAS_UNMAP = 0x86,
  IOMMUFD_CMD_OPTION = 0x87,
  IOMMUFD_CMD_VFIO_IOAS = 0x88,
  IOMMUFD_CMD_HWPT_ALLOC = 0x89,
  IOMMUFD_CMD_GET_HW_INFO = 0x8a,
  IOMMUFD_CMD_HWPT_SET_DIRTY_TRACKING = 0x8b,
  IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP = 0x8c,
  IOMMUFD_CMD_HWPT_INVALIDATE = 0x8d,
  IOMMUFD_CMD_FAULT_QUEUE_ALLOC = 0x8e,
};
struct iommu_destroy {
  __u32 size;
  __u32 id;
};
#define IOMMU_DESTROY _IO(IOMMUFD_TYPE, IOMMUFD_CMD_DESTROY)
struct iommu_ioas_alloc {
  __u32 size;
  __u32 flags;
  __u32 out_ioas_id;
};
#define IOMMU_IOAS_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_ALLOC)
struct iommu_iova_range {
  __aligned_u64 start;
  __aligned_u64 last;
};
struct iommu_ioas_iova_ranges {
  __u32 size;
  __u32 ioas_id;
  __u32 num_iovas;
  __u32 __reserved;
  __aligned_u64 allowed_iovas;
  __aligned_u64 out_iova_alignment;
};
#define IOMMU_IOAS_IOVA_RANGES _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_IOVA_RANGES)
struct iommu_ioas_allow_iovas {
  __u32 size;
  __u32 ioas_id;
  __u32 num_iovas;
  __u32 __reserved;
  __aligned_u64 allowed_iovas;
};
#define IOMMU_IOAS_ALLOW_IOVAS _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_ALLOW_IOVAS)
enum iommufd_ioas_map_flags {
  IOMMU_IOAS_MAP_FIXED_IOVA = 1 << 0,
  IOMMU_IOAS_MAP_WRITEABLE = 1 << 1,
  IOMMU_IOAS_MAP_READABLE = 1 << 2,
};
struct iommu_ioas_map {
  __u32 size;
  __u32 flags;
  __u32 ioas_id;
  __u32 __reserved;
  __aligned_u64 user_va;
  __aligned_u64 length;
  __aligned_u64 iova;
};
#define IOMMU_IOAS_MAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_MAP)
struct iommu_ioas_copy {
  __u32 size;
  __u32 flags;
  __u32 dst_ioas_id;
  __u32 src_ioas_id;
  __aligned_u64 length;
  __aligned_u64 dst_iova;
  __aligned_u64 src_iova;
};
#define IOMMU_IOAS_COPY _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_COPY)
struct iommu_ioas_unmap {
  __u32 size;
  __u32 ioas_id;
  __aligned_u64 iova;
  __aligned_u64 length;
};
#define IOMMU_IOAS_UNMAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_UNMAP)
enum iommufd_option {
  IOMMU_OPTION_RLIMIT_MODE = 0,
  IOMMU_OPTION_HUGE_PAGES = 1,
};
enum iommufd_option_ops {
  IOMMU_OPTION_OP_SET = 0,
  IOMMU_OPTION_OP_GET = 1,
};
struct iommu_option {
  __u32 size;
  __u32 option_id;
  __u16 op;
  __u16 __reserved;
  __u32 object_id;
  __aligned_u64 val64;
};
#define IOMMU_OPTION _IO(IOMMUFD_TYPE, IOMMUFD_CMD_OPTION)
enum iommufd_vfio_ioas_op {
  IOMMU_VFIO_IOAS_GET = 0,
  IOMMU_VFIO_IOAS_SET = 1,
  IOMMU_VFIO_IOAS_CLEAR = 2,
};
struct iommu_vfio_ioas {
  __u32 size;
  __u32 ioas_id;
  __u16 op;
  __u16 __reserved;
};
#define IOMMU_VFIO_IOAS _IO(IOMMUFD_TYPE, IOMMUFD_CMD_VFIO_IOAS)
enum iommufd_hwpt_alloc_flags {
  IOMMU_HWPT_ALLOC_NEST_PARENT = 1 << 0,
  IOMMU_HWPT_ALLOC_DIRTY_TRACKING = 1 << 1,
  IOMMU_HWPT_FAULT_ID_VALID = 1 << 2,
};
enum iommu_hwpt_vtd_s1_flags {
  IOMMU_VTD_S1_SRE = 1 << 0,
  IOMMU_VTD_S1_EAFE = 1 << 1,
  IOMMU_VTD_S1_WPE = 1 << 2,
};
struct iommu_hwpt_vtd_s1 {
  __aligned_u64 flags;
  __aligned_u64 pgtbl_addr;
  __u32 addr_width;
  __u32 __reserved;
};
enum iommu_hwpt_data_type {
  IOMMU_HWPT_DATA_NONE = 0,
  IOMMU_HWPT_DATA_VTD_S1 = 1,
};
struct iommu_hwpt_alloc {
  __u32 size;
  __u32 flags;
  __u32 dev_id;
  __u32 pt_id;
  __u32 out_hwpt_id;
  __u32 __reserved;
  __u32 data_type;
  __u32 data_len;
  __aligned_u64 data_uptr;
  __u32 fault_id;
  __u32 __reserved2;
};
#define IOMMU_HWPT_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_ALLOC)
enum iommu_hw_info_vtd_flags {
  IOMMU_HW_INFO_VTD_ERRATA_772415_SPR17 = 1 << 0,
};
struct iommu_hw_info_vtd {
  __u32 flags;
  __u32 __reserved;
  __aligned_u64 cap_reg;
  __aligned_u64 ecap_reg;
};
enum iommu_hw_info_type {
  IOMMU_HW_INFO_TYPE_NONE = 0,
  IOMMU_HW_INFO_TYPE_INTEL_VTD = 1,
};
enum iommufd_hw_capabilities {
  IOMMU_HW_CAP_DIRTY_TRACKING = 1 << 0,
};
struct iommu_hw_info {
  __u32 size;
  __u32 flags;
  __u32 dev_id;
  __u32 data_len;
  __aligned_u64 data_uptr;
  __u32 out_data_type;
  __u32 __reserved;
  __aligned_u64 out_capabilities;
};
#define IOMMU_GET_HW_INFO _IO(IOMMUFD_TYPE, IOMMUFD_CMD_GET_HW_INFO)
enum iommufd_hwpt_set_dirty_tracking_flags {
  IOMMU_HWPT_DIRTY_TRACKING_ENABLE = 1,
};
struct iommu_hwpt_set_dirty_tracking {
  __u32 size;
  __u32 flags;
  __u32 hwpt_id;
  __u32 __reserved;
};
#define IOMMU_HWPT_SET_DIRTY_TRACKING _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_SET_DIRTY_TRACKING)
enum iommufd_hwpt_get_dirty_bitmap_flags {
  IOMMU_HWPT_GET_DIRTY_BITMAP_NO_CLEAR = 1,
};
struct iommu_hwpt_get_dirty_bitmap {
  __u32 size;
  __u32 hwpt_id;
  __u32 flags;
  __u32 __reserved;
  __aligned_u64 iova;
  __aligned_u64 length;
  __aligned_u64 page_size;
  __aligned_u64 data;
};
#define IOMMU_HWPT_GET_DIRTY_BITMAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP)
enum iommu_hwpt_invalidate_data_type {
  IOMMU_HWPT_INVALIDATE_DATA_VTD_S1 = 0,
};
enum iommu_hwpt_vtd_s1_invalidate_flags {
  IOMMU_VTD_INV_FLAGS_LEAF = 1 << 0,
};
struct iommu_hwpt_vtd_s1_invalidate {
  __aligned_u64 addr;
  __aligned_u64 npages;
  __u32 flags;
  __u32 __reserved;
};
struct iommu_hwpt_invalidate {
  __u32 size;
  __u32 hwpt_id;
  __aligned_u64 data_uptr;
  __u32 data_type;
  __u32 entry_len;
  __u32 entry_num;
  __u32 __reserved;
};
#define IOMMU_HWPT_INVALIDATE _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_INVALIDATE)
enum iommu_hwpt_pgfault_flags {
  IOMMU_PGFAULT_FLAGS_PASID_VALID = (1 << 0),
  IOMMU_PGFAULT_FLAGS_LAST_PAGE = (1 << 1),
};
enum iommu_hwpt_pgfault_perm {
  IOMMU_PGFAULT_PERM_READ = (1 << 0),
  IOMMU_PGFAULT_PERM_WRITE = (1 << 1),
  IOMMU_PGFAULT_PERM_EXEC = (1 << 2),
  IOMMU_PGFAULT_PERM_PRIV = (1 << 3),
};
struct iommu_hwpt_pgfault {
  __u32 flags;
  __u32 dev_id;
  __u32 pasid;
  __u32 grpid;
  __u32 perm;
  __u64 addr;
  __u32 length;
  __u32 cookie;
};
enum iommufd_page_response_code {
  IOMMUFD_PAGE_RESP_SUCCESS = 0,
  IOMMUFD_PAGE_RESP_INVALID = 1,
};
struct iommu_hwpt_page_response {
  __u32 cookie;
  __u32 code;
};
struct iommu_fault_alloc {
  __u32 size;
  __u32 flags;
  __u32 out_fault_id;
  __u32 out_fault_fd;
};
#define IOMMU_FAULT_QUEUE_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_FAULT_QUEUE_ALLOC)
#endif

"""

```