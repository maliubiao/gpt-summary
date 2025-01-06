Response:
Let's break down the thought process for answering this request. The request is quite comprehensive, demanding a detailed analysis of a header file related to RDMA in Android. Here's a possible internal monologue and steps:

1. **Understand the Core Request:** The primary goal is to understand the functionality of the `ib_user_ioctl_cmds.h` file within the context of Android's Bionic library and its relevance to the Android framework and NDK.

2. **Initial Analysis of the Header File:**
    * **Keywords:**  Notice terms like `RDMA`, `ioctl`, `uverbs`, `device`, `PD`, `CQ`, `QP`, etc. This immediately signals that the file is about Remote Direct Memory Access (RDMA) and defines commands for interacting with RDMA hardware/drivers from user space via the `ioctl` system call.
    * **Structure:** Observe the use of `#ifndef`, `#define`, and `enum`. This is a standard C header file defining constants and enumerations. The enumerations clearly define object types (e.g., `UVERBS_OBJECT_DEVICE`) and different methods/operations (e.g., `UVERBS_METHOD_QP_CREATE`).
    * **Naming Conventions:**  The `UVERBS_` prefix suggests "User Verbs," implying this is a user-space API for RDMA verbs.

3. **Identify Key Functional Areas:** Based on the enumerations, categorize the functionalities:
    * **Object Management:** Creating, destroying various RDMA objects (Device, PD, CQ, QP, SRQ, MR, MW, etc.).
    * **Device Information:** Querying device capabilities and context.
    * **Queue Pair (QP) Management:** Creating, destroying QPs, which are fundamental for RDMA communication.
    * **Completion Queue (CQ) Management:** Managing CQs for receiving notifications about completed operations.
    * **Memory Management:** Registering memory regions for RDMA access (MR).
    * **Flow Control:**  Dealing with network traffic management (Flow, Flow Actions).
    * **Direct Memory (DM):** Allocating and freeing direct memory.
    * **Counters:**  Managing performance counters.
    * **Asynchronous Events:** Handling asynchronous notifications.
    * **GID Table:**  Querying Global Identifier (GID) information.

4. **Connect to Android Functionality:**
    * **RDMA in Android:**  Recognize that RDMA is not a core, widely used feature in typical Android application development. Its primary use cases are in high-performance computing, data centers, and potentially for specialized hardware integrations.
    * **Kernel Interaction:**  The use of `ioctl` strongly indicates direct interaction with a kernel driver.
    * **Potential Use Cases:**  Think about scenarios where high-throughput, low-latency communication is crucial. Examples include:
        * Inter-process communication (though likely more niche than standard IPC).
        * Communication with specialized hardware accelerators.
        * Potentially within Android's lower-level infrastructure if performance is paramount in certain subsystems.

5. **Explain `libc` Functions (General Approach):**
    * **Not Direct `libc` Functions:** Realize that this header file *defines constants* used with `ioctl`, a system call. It doesn't define `libc` functions themselves. Clarify this distinction.
    * **Role of `ioctl`:** Explain the purpose of `ioctl` as a generic system call for device-specific control.

6. **Explain Dynamic Linker Functionality:**
    * **Header File's Role:** Recognize that this header file doesn't directly involve the dynamic linker. It defines constants for kernel interaction.
    * **Dynamic Linking in the Context of RDMA:**  Consider where dynamic linking *might* be involved in a real RDMA setup in Android. Likely in user-space libraries that *use* these constants to interact with the RDMA driver.
    * **Hypothetical `so` Layout:**  Provide an example of a potential shared library (`librdma.so`) that might encapsulate RDMA functionality and use these constants.
    * **Linking Process:** Briefly describe the dynamic linking process, even if this specific header isn't directly involved.

7. **Logical Reasoning, Assumptions, and Examples:**
    * **Assumptions:**  Make assumptions about how a developer would use these constants with the `ioctl` system call.
    * **Input/Output:** Provide hypothetical examples of `ioctl` calls, showcasing how the defined constants would be used as command codes.
    * **User Errors:** Think about common mistakes when working with `ioctl` and kernel interfaces, such as incorrect command codes, invalid handles, or permission issues.

8. **Android Framework/NDK Path:**
    * **Framework Involvement:** Acknowledge that direct use from the Android framework is unlikely.
    * **NDK Usage:** Highlight the possibility of using this from native code via the NDK.
    * **System Calls:** Emphasize the transition from NDK code to the `ioctl` system call.
    * **Kernel Driver:**  Explain that the `ioctl` call reaches the RDMA kernel driver.

9. **Frida Hooking:**
    * **Target the `ioctl` System Call:**  Since the interaction happens via `ioctl`, target that system call for hooking.
    * **Hook Points:** Identify key arguments of `ioctl` (file descriptor, request code) that would be relevant for monitoring RDMA interactions.
    * **Hooking Example:** Provide a practical Frida script demonstrating how to hook `ioctl` and filter for RDMA-related commands based on the constants defined in the header file.

10. **Structure and Language:**
    * **Organize the Answer:**  Use clear headings and bullet points to structure the comprehensive information.
    * **Use Clear and Concise Language:** Explain technical terms without being overly verbose.
    * **Maintain Accuracy:** Ensure the technical details are correct.
    * **Address All Parts of the Prompt:**  Double-check that every aspect of the original request is addressed.

**Self-Correction/Refinement during the process:**

* **Initial Thought:**  "Are these `libc` functions directly?"  **Correction:** Realize these are *definitions* used *with* system calls, not `libc` functions themselves.
* **Initial Thought:** "How does dynamic linking fit in?" **Refinement:**  Understand that the header file itself isn't directly linked, but the *user-space libraries* that use these definitions would be.
* **Frida Example:** "What's the best way to demonstrate hooking?" **Refinement:** Focus on hooking the `ioctl` system call and filtering based on the command codes.

By following these steps, the detailed and accurate answer provided can be constructed. The key is to systematically analyze the input, connect it to the broader context of Android and RDMA, and address each part of the complex request methodically.
这是一个定义了用于与 Linux 内核中的 RDMA (Remote Direct Memory Access) 子系统进行交互的 `ioctl` 命令的头文件。RDMA 允许应用程序绕过操作系统内核，直接访问远程机器的内存，从而实现高性能的网络通信。

**它的功能:**

这个头文件定义了一系列常量和枚举，用于构建通过 `ioctl` 系统调用发送给 RDMA 设备驱动程序的命令。这些命令涵盖了 RDMA 子系统中各种对象的创建、销毁、查询和操作。具体来说，它定义了以下内容：

1. **对象类型 (`enum uverbs_default_objects`):**  定义了 RDMA 子系统中可以操作的各种对象类型，例如：
   - `UVERBS_OBJECT_DEVICE`: RDMA 设备本身。
   - `UVERBS_OBJECT_PD`: Protection Domain (保护域)，用于管理内存访问权限。
   - `UVERBS_OBJECT_COMP_CHANNEL`: Completion Channel (完成通道)，用于接收操作完成的通知。
   - `UVERBS_OBJECT_CQ`: Completion Queue (完成队列)，存储完成事件。
   - `UVERBS_OBJECT_QP`: Queue Pair (队列对)，用于发送和接收 RDMA 操作。
   - `UVERBS_OBJECT_SRQ`: Shared Receive Queue (共享接收队列)，多个 QP 可以共享的接收队列。
   - `UVERBS_OBJECT_AH`: Address Handle (地址句柄)，用于指定远程节点的地址信息。
   - `UVERBS_OBJECT_MR`: Memory Region (内存区域)，应用程序注册的可供 RDMA 访问的内存区域。
   - `UVERBS_OBJECT_MW`: Memory Window (内存窗口)，动态映射到远程内存的窗口。
   - `UVERBS_OBJECT_FLOW`: 流控制对象。
   - `UVERBS_OBJECT_XRCD`:  扩展的 RC 连接描述符。
   - `UVERBS_OBJECT_RWQ_IND_TBL`:  可路由的 Work Queue 指示表。
   - `UVERBS_OBJECT_WQ`: Work Queue (工作队列)。
   - `UVERBS_OBJECT_FLOW_ACTION`: 流操作。
   - `UVERBS_OBJECT_DM`: Direct Memory (直接内存)。
   - `UVERBS_OBJECT_COUNTERS`: 性能计数器。
   - `UVERBS_OBJECT_ASYNC_EVENT`: 异步事件。

2. **命名空间 (`enum { ... }`):** 定义了命令的命名空间，用于区分不同的命令类型。`UVERBS_ID_DRIVER_NS` 表明接下来的命令属于驱动程序特定的命名空间。

3. **设备方法 (`enum uverbs_methods_device`):** 定义了可以对 RDMA 设备执行的操作，例如：
   - `UVERBS_METHOD_INVOKE_WRITE`: 调用写操作。
   - `UVERBS_METHOD_INFO_HANDLES`: 获取句柄信息。
   - `UVERBS_METHOD_QUERY_PORT`: 查询端口信息。
   - `UVERBS_METHOD_GET_CONTEXT`: 获取设备上下文。
   - `UVERBS_METHOD_QUERY_CONTEXT`: 查询设备上下文。
   - `UVERBS_METHOD_QUERY_GID_TABLE`: 查询全局 ID 表。
   - `UVERBS_METHOD_QUERY_GID_ENTRY`: 查询全局 ID 表项。

4. **各种属性 ID (`enum uverbs_attrs_*`):**  定义了与不同命令相关的属性 ID，用于在 `ioctl` 调用中传递参数和接收返回值。例如，`UVERBS_ATTR_CREATE_CQ_CQE` 表示创建完成队列时设置队列大小的属性。

5. **其他对象的方法 (`enum uverbs_methods_*`):** 定义了可以对其他 RDMA 对象执行的操作，如创建、销毁等。

**与 Android 功能的关系及举例说明:**

RDMA 在 Android 中并不是一个核心或常用的功能，因为它主要用于高性能计算、数据中心等场景。普通 Android 应用程序通常不会直接使用 RDMA。然而，在以下一些特定场景下，RDMA 可能与 Android 功能存在关联：

1. **高性能网络设备驱动:** 如果 Android 设备集成了支持 RDMA 的网络硬件 (例如 InfiniBand 网卡)，那么 Android 内核中会存在相应的 RDMA 设备驱动程序。这个头文件定义的常量和枚举会被该驱动程序使用，以便用户空间程序 (通常是系统服务或特定的高性能应用) 可以通过 `ioctl` 与驱动程序交互，配置和使用 RDMA 功能。

   **举例:** 假设一个 Android 系统被用作高性能存储设备的控制器，需要与其他存储节点进行高速数据传输。可以使用 RDMA 来加速数据传输。一个 Android 系统服务可能会使用这个头文件中定义的常量来创建 QP、注册内存区域，并通过 `ioctl` 发送 RDMA 操作请求到内核驱动。

2. **虚拟化环境:** 在 Android 虚拟化场景中，虚拟机 guest 操作系统可能会利用 RDMA 进行高效的设备模拟或与宿主机进行通信。

   **举例:** 一个运行在 Android 上的虚拟机可能使用 VFIO (Virtual Function I/O) 技术直接访问宿主机的 RDMA 设备。虚拟机内部的 RDMA 驱动程序会使用类似的 `ioctl` 命令与宿主机的虚拟化层进行交互。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个头文件本身并不包含 `libc` 函数的实现**。它只是定义了一些常量和枚举类型。这些常量会被传递给 `ioctl` 系统调用，而 `ioctl` 是一个 `libc` 函数。

`ioctl` 函数的原型通常如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

- `fd`:  文件描述符，通常是通过 `open()` 打开的设备文件的文件描述符，例如 RDMA 设备的文件路径 `/dev/infiniband/uverbs0`。
- `request`:  一个请求码，用于指定要执行的操作。这个头文件中定义的 `UVERBS_METHOD_*` 和相关的属性 ID 会被组合成这个 `request`。
- `...`: 可变参数，用于传递与特定操作相关的参数结构体。这些结构体通常会包含在这个头文件中定义的各种 `UVERBS_ATTR_*` 属性。

**`ioctl` 的实现过程:**

1. **用户空间调用:** 用户空间程序调用 `ioctl` 函数，传递文件描述符、请求码以及可能的参数。
2. **系统调用:** `ioctl` 是一个系统调用，会陷入内核。
3. **VFS 处理:** 内核的 VFS (Virtual File System) 层根据文件描述符找到对应的设备驱动程序。
4. **驱动程序处理:** 设备驱动程序接收到 `ioctl` 请求。驱动程序会根据 `request` 参数 (也就是通过这个头文件定义的常量组合而成) 来判断需要执行的具体操作。
5. **硬件交互:** 驱动程序可能会与底层的 RDMA 硬件进行交互，例如配置网卡、发送命令等。
6. **返回结果:** 驱动程序将操作结果返回给内核，内核再将结果返回给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件本身不直接涉及 dynamic linker 的功能**。它定义的是内核接口，而不是用户空间的共享库接口。

然而，如果用户空间程序需要使用 RDMA 功能，它可能会链接到一个提供 RDMA 功能封装的共享库。假设存在一个名为 `librdma.so` 的共享库，它封装了使用 `ioctl` 与 RDMA 设备交互的逻辑。

**`librdma.so` 布局样本:**

```
librdma.so:
    .text          # 代码段，包含 RDMA 相关的函数实现
    .rodata        # 只读数据段，可能包含一些常量
    .data          # 可读写数据段
    .bss           # 未初始化数据段
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .rel.dyn       # 动态重定位表
    .rel.plt       # PLT 重定位表
    ...
```

**链接的处理过程:**

1. **编译时链接:**  当用户空间程序 (例如一个 native NDK 应用) 使用 `librdma.so` 时，编译器会在编译时记录下对 `librdma.so` 中导出符号的引用。
2. **动态链接:**  当程序运行时，dynamic linker (例如 Android 的 `linker64` 或 `linker`) 会负责加载 `librdma.so` 到内存中，并解析程序中对 `librdma.so` 中符号的引用，将这些引用指向 `librdma.so` 中相应的函数地址。
3. **符号查找:** dynamic linker 会查找 `librdma.so` 的 `.dynsym` 和 `.dynstr` 段，找到程序引用的符号及其对应的地址。
4. **重定位:** dynamic linker 会根据 `.rel.dyn` 和 `.rel.plt` 段中的信息，修改程序代码中的地址，使其指向正确的 `librdma.so` 中的函数。

**假设输入与输出 (针对 `ioctl` 调用):**

假设我们要创建一个 Completion Queue (CQ)。

**假设输入:**

- `fd`:  RDMA 设备的文件描述符，例如通过 `open("/dev/infiniband/uverbs0", O_RDWR)` 获取。
- `request`:  一个由 `UVERBS_METHOD_CQ_CREATE` 和相关的属性 ID 组合而成的请求码。
- 可变参数: 一个指向包含创建 CQ 所需属性的结构体的指针，例如：
  ```c
  struct uverbs_create_cq {
      __u32 comp_channel; // Completion Channel 的句柄
      __u32 cqe;          // CQ 的大小 (条目数)
      __u32 user_handle;  // 用户定义的句柄
      // ... 其他属性
  };
  ```

**预期输出:**

- 如果创建成功，`ioctl` 返回 0。
- 如果创建失败，`ioctl` 返回 -1，并设置 `errno` 指示错误原因 (例如权限不足、参数错误等)。
- 驱动程序可能会通过传递的结构体返回新创建的 CQ 的句柄或其他信息。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **文件描述符无效:**  在调用 `ioctl` 之前，没有正确地 `open()` RDMA 设备文件，或者文件描述符被意外关闭。

   ```c
   int fd = open("/dev/infiniband/uverbs0", O_RDWR);
   if (fd < 0) {
       perror("open");
       // 错误处理
   }
   // ... 可能的操作
   close(fd);
   // 之后尝试使用已经关闭的 fd 调用 ioctl
   ioctl(fd, UVERBS_METHOD_QP_CREATE, ...); // 错误！
   ```

2. **请求码错误:**  使用了错误的 `request` 值，导致驱动程序无法识别要执行的操作。这可能是因为手动组合请求码时出错，或者使用了不兼容的头文件版本。

3. **参数结构体错误:**  传递给 `ioctl` 的参数结构体中的值不正确，例如：
   - 提供了无效的句柄值。
   - 设置了超出范围的大小。
   - 传递了空指针。

   ```c
   int fd = open("/dev/infiniband/uverbs0", O_RDWR);
   struct uverbs_create_cq create_cq_attr;
   create_cq_attr.cqe = 0; // CQ 大小为 0，通常是无效的
   ioctl(fd, UVERBS_METHOD_CQ_CREATE, &create_cq_attr); // 可能失败
   ```

4. **权限问题:**  用户空间程序没有足够的权限访问 RDMA 设备文件。

5. **资源耗尽:**  尝试创建过多的 RDMA 对象，导致系统资源耗尽。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

由于 RDMA 不是 Android Framework 的核心功能，直接从 Framework 到达这里的路径比较少见。更常见的是通过 NDK 开发的 native 应用来使用 RDMA 功能。

**NDK 到达这里的步骤:**

1. **NDK 应用开发:**  开发者使用 NDK 编写 C/C++ 代码，其中包括使用 `ioctl` 系统调用与 RDMA 设备驱动交互的逻辑。需要包含 `ib_user_ioctl_cmds.h` 头文件。
2. **调用 `ioctl`:**  NDK 应用中会直接调用 `ioctl` 函数，传递 RDMA 设备的文件描述符和通过 `ib_user_ioctl_cmds.h` 中定义的常量构建的请求码和参数。
3. **系统调用:**  `ioctl` 是一个系统调用，当 NDK 应用调用它时，会触发一个从用户空间到内核空间的切换。
4. **内核处理:**  Android 内核接收到 `ioctl` 系统调用，VFS 层会根据文件描述符找到对应的 RDMA 设备驱动程序。
5. **驱动程序处理:**  RDMA 设备驱动程序根据 `ioctl` 的请求码和参数执行相应的操作，与硬件交互，并返回结果。

**Frida Hook 示例:**

可以使用 Frida hook `ioctl` 系统调用来观察 NDK 应用与 RDMA 驱动的交互。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

session = frida.attach('your_app_process_name') # 替换为你的应用进程名

script = session.create_script("""
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();

        // 检查是否是与 RDMA 相关的 ioctl 调用 (可以根据文件路径或 request 值判断)
        if (fd > 0) { // 简单的判断，实际需要更精确的过滤
            console.log("ioctl called");
            console.log("  fd:", fd);
            console.log("  request:", request);
            // 可以进一步解析参数 args[2] 来查看传递的结构体内容
        }
    },
    onLeave: function(retval) {
        console.log("ioctl returned with:", retval.toInt32());
    }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**代码解释:**

1. **`frida.attach('your_app_process_name')`:** 连接到目标 Android 应用的进程。
2. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  Hook `ioctl` 系统调用。`Module.findExportByName(null, "ioctl")`  在所有加载的模块中查找 `ioctl` 函数的地址。
3. **`onEnter`:**  在 `ioctl` 函数被调用之前执行。
   - `args[0]`: 文件描述符。
   - `args[1]`: 请求码。
   - 代码中简单的判断 `fd > 0` 来过滤可能的 RDMA 相关调用。实际应用中需要根据 RDMA 设备的文件路径或者更具体的 `request` 值来进行判断。
   - 可以进一步解析 `args[2]` 指向的内存，来查看传递给 `ioctl` 的参数结构体的内容，但这需要了解结构体的布局。
4. **`onLeave`:** 在 `ioctl` 函数返回之后执行，可以查看返回值。

**使用步骤:**

1. 确保你的 Android 设备已 root，并安装了 Frida 服务端。
2. 找到你的 NDK 应用的进程名。
3. 将上面的 Python 脚本保存为 `hook_ioctl.py`。
4. 运行脚本： `python3 hook_ioctl.py`
5. 运行你的 NDK 应用，进行涉及到 RDMA 的操作。
6. Frida 会打印出 `ioctl` 调用时的文件描述符、请求码以及返回值，帮助你调试 RDMA 相关的操作。

通过这种方式，你可以观察到 NDK 应用是如何调用 `ioctl`，传递哪些参数，以及内核的响应，从而理解 Android 应用与 RDMA 驱动的交互过程。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/rdma/ib_user_ioctl_cmds.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef IB_USER_IOCTL_CMDS_H
#define IB_USER_IOCTL_CMDS_H
#define UVERBS_ID_NS_MASK 0xF000
#define UVERBS_ID_NS_SHIFT 12
enum uverbs_default_objects {
  UVERBS_OBJECT_DEVICE,
  UVERBS_OBJECT_PD,
  UVERBS_OBJECT_COMP_CHANNEL,
  UVERBS_OBJECT_CQ,
  UVERBS_OBJECT_QP,
  UVERBS_OBJECT_SRQ,
  UVERBS_OBJECT_AH,
  UVERBS_OBJECT_MR,
  UVERBS_OBJECT_MW,
  UVERBS_OBJECT_FLOW,
  UVERBS_OBJECT_XRCD,
  UVERBS_OBJECT_RWQ_IND_TBL,
  UVERBS_OBJECT_WQ,
  UVERBS_OBJECT_FLOW_ACTION,
  UVERBS_OBJECT_DM,
  UVERBS_OBJECT_COUNTERS,
  UVERBS_OBJECT_ASYNC_EVENT,
};
enum {
  UVERBS_ID_DRIVER_NS = 1UL << UVERBS_ID_NS_SHIFT,
  UVERBS_ATTR_UHW_IN = UVERBS_ID_DRIVER_NS,
  UVERBS_ATTR_UHW_OUT,
  UVERBS_ID_DRIVER_NS_WITH_UHW,
};
enum uverbs_methods_device {
  UVERBS_METHOD_INVOKE_WRITE,
  UVERBS_METHOD_INFO_HANDLES,
  UVERBS_METHOD_QUERY_PORT,
  UVERBS_METHOD_GET_CONTEXT,
  UVERBS_METHOD_QUERY_CONTEXT,
  UVERBS_METHOD_QUERY_GID_TABLE,
  UVERBS_METHOD_QUERY_GID_ENTRY,
};
enum uverbs_attrs_invoke_write_cmd_attr_ids {
  UVERBS_ATTR_CORE_IN,
  UVERBS_ATTR_CORE_OUT,
  UVERBS_ATTR_WRITE_CMD,
};
enum uverbs_attrs_query_port_cmd_attr_ids {
  UVERBS_ATTR_QUERY_PORT_PORT_NUM,
  UVERBS_ATTR_QUERY_PORT_RESP,
};
enum uverbs_attrs_get_context_attr_ids {
  UVERBS_ATTR_GET_CONTEXT_NUM_COMP_VECTORS,
  UVERBS_ATTR_GET_CONTEXT_CORE_SUPPORT,
};
enum uverbs_attrs_query_context_attr_ids {
  UVERBS_ATTR_QUERY_CONTEXT_NUM_COMP_VECTORS,
  UVERBS_ATTR_QUERY_CONTEXT_CORE_SUPPORT,
};
enum uverbs_attrs_create_cq_cmd_attr_ids {
  UVERBS_ATTR_CREATE_CQ_HANDLE,
  UVERBS_ATTR_CREATE_CQ_CQE,
  UVERBS_ATTR_CREATE_CQ_USER_HANDLE,
  UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL,
  UVERBS_ATTR_CREATE_CQ_COMP_VECTOR,
  UVERBS_ATTR_CREATE_CQ_FLAGS,
  UVERBS_ATTR_CREATE_CQ_RESP_CQE,
  UVERBS_ATTR_CREATE_CQ_EVENT_FD,
};
enum uverbs_attrs_destroy_cq_cmd_attr_ids {
  UVERBS_ATTR_DESTROY_CQ_HANDLE,
  UVERBS_ATTR_DESTROY_CQ_RESP,
};
enum uverbs_attrs_create_flow_action_esp {
  UVERBS_ATTR_CREATE_FLOW_ACTION_ESP_HANDLE,
  UVERBS_ATTR_FLOW_ACTION_ESP_ATTRS,
  UVERBS_ATTR_FLOW_ACTION_ESP_ESN,
  UVERBS_ATTR_FLOW_ACTION_ESP_KEYMAT,
  UVERBS_ATTR_FLOW_ACTION_ESP_REPLAY,
  UVERBS_ATTR_FLOW_ACTION_ESP_ENCAP,
};
enum uverbs_attrs_modify_flow_action_esp {
  UVERBS_ATTR_MODIFY_FLOW_ACTION_ESP_HANDLE = UVERBS_ATTR_CREATE_FLOW_ACTION_ESP_HANDLE,
};
enum uverbs_attrs_destroy_flow_action_esp {
  UVERBS_ATTR_DESTROY_FLOW_ACTION_HANDLE,
};
enum uverbs_attrs_create_qp_cmd_attr_ids {
  UVERBS_ATTR_CREATE_QP_HANDLE,
  UVERBS_ATTR_CREATE_QP_XRCD_HANDLE,
  UVERBS_ATTR_CREATE_QP_PD_HANDLE,
  UVERBS_ATTR_CREATE_QP_SRQ_HANDLE,
  UVERBS_ATTR_CREATE_QP_SEND_CQ_HANDLE,
  UVERBS_ATTR_CREATE_QP_RECV_CQ_HANDLE,
  UVERBS_ATTR_CREATE_QP_IND_TABLE_HANDLE,
  UVERBS_ATTR_CREATE_QP_USER_HANDLE,
  UVERBS_ATTR_CREATE_QP_CAP,
  UVERBS_ATTR_CREATE_QP_TYPE,
  UVERBS_ATTR_CREATE_QP_FLAGS,
  UVERBS_ATTR_CREATE_QP_SOURCE_QPN,
  UVERBS_ATTR_CREATE_QP_EVENT_FD,
  UVERBS_ATTR_CREATE_QP_RESP_CAP,
  UVERBS_ATTR_CREATE_QP_RESP_QP_NUM,
};
enum uverbs_attrs_destroy_qp_cmd_attr_ids {
  UVERBS_ATTR_DESTROY_QP_HANDLE,
  UVERBS_ATTR_DESTROY_QP_RESP,
};
enum uverbs_methods_qp {
  UVERBS_METHOD_QP_CREATE,
  UVERBS_METHOD_QP_DESTROY,
};
enum uverbs_attrs_create_srq_cmd_attr_ids {
  UVERBS_ATTR_CREATE_SRQ_HANDLE,
  UVERBS_ATTR_CREATE_SRQ_PD_HANDLE,
  UVERBS_ATTR_CREATE_SRQ_XRCD_HANDLE,
  UVERBS_ATTR_CREATE_SRQ_CQ_HANDLE,
  UVERBS_ATTR_CREATE_SRQ_USER_HANDLE,
  UVERBS_ATTR_CREATE_SRQ_MAX_WR,
  UVERBS_ATTR_CREATE_SRQ_MAX_SGE,
  UVERBS_ATTR_CREATE_SRQ_LIMIT,
  UVERBS_ATTR_CREATE_SRQ_MAX_NUM_TAGS,
  UVERBS_ATTR_CREATE_SRQ_TYPE,
  UVERBS_ATTR_CREATE_SRQ_EVENT_FD,
  UVERBS_ATTR_CREATE_SRQ_RESP_MAX_WR,
  UVERBS_ATTR_CREATE_SRQ_RESP_MAX_SGE,
  UVERBS_ATTR_CREATE_SRQ_RESP_SRQ_NUM,
};
enum uverbs_attrs_destroy_srq_cmd_attr_ids {
  UVERBS_ATTR_DESTROY_SRQ_HANDLE,
  UVERBS_ATTR_DESTROY_SRQ_RESP,
};
enum uverbs_methods_srq {
  UVERBS_METHOD_SRQ_CREATE,
  UVERBS_METHOD_SRQ_DESTROY,
};
enum uverbs_methods_cq {
  UVERBS_METHOD_CQ_CREATE,
  UVERBS_METHOD_CQ_DESTROY,
};
enum uverbs_attrs_create_wq_cmd_attr_ids {
  UVERBS_ATTR_CREATE_WQ_HANDLE,
  UVERBS_ATTR_CREATE_WQ_PD_HANDLE,
  UVERBS_ATTR_CREATE_WQ_CQ_HANDLE,
  UVERBS_ATTR_CREATE_WQ_USER_HANDLE,
  UVERBS_ATTR_CREATE_WQ_TYPE,
  UVERBS_ATTR_CREATE_WQ_EVENT_FD,
  UVERBS_ATTR_CREATE_WQ_MAX_WR,
  UVERBS_ATTR_CREATE_WQ_MAX_SGE,
  UVERBS_ATTR_CREATE_WQ_FLAGS,
  UVERBS_ATTR_CREATE_WQ_RESP_MAX_WR,
  UVERBS_ATTR_CREATE_WQ_RESP_MAX_SGE,
  UVERBS_ATTR_CREATE_WQ_RESP_WQ_NUM,
};
enum uverbs_attrs_destroy_wq_cmd_attr_ids {
  UVERBS_ATTR_DESTROY_WQ_HANDLE,
  UVERBS_ATTR_DESTROY_WQ_RESP,
};
enum uverbs_methods_wq {
  UVERBS_METHOD_WQ_CREATE,
  UVERBS_METHOD_WQ_DESTROY,
};
enum uverbs_methods_actions_flow_action_ops {
  UVERBS_METHOD_FLOW_ACTION_ESP_CREATE,
  UVERBS_METHOD_FLOW_ACTION_DESTROY,
  UVERBS_METHOD_FLOW_ACTION_ESP_MODIFY,
};
enum uverbs_attrs_alloc_dm_cmd_attr_ids {
  UVERBS_ATTR_ALLOC_DM_HANDLE,
  UVERBS_ATTR_ALLOC_DM_LENGTH,
  UVERBS_ATTR_ALLOC_DM_ALIGNMENT,
};
enum uverbs_attrs_free_dm_cmd_attr_ids {
  UVERBS_ATTR_FREE_DM_HANDLE,
};
enum uverbs_methods_dm {
  UVERBS_METHOD_DM_ALLOC,
  UVERBS_METHOD_DM_FREE,
};
enum uverbs_attrs_reg_dm_mr_cmd_attr_ids {
  UVERBS_ATTR_REG_DM_MR_HANDLE,
  UVERBS_ATTR_REG_DM_MR_OFFSET,
  UVERBS_ATTR_REG_DM_MR_LENGTH,
  UVERBS_ATTR_REG_DM_MR_PD_HANDLE,
  UVERBS_ATTR_REG_DM_MR_ACCESS_FLAGS,
  UVERBS_ATTR_REG_DM_MR_DM_HANDLE,
  UVERBS_ATTR_REG_DM_MR_RESP_LKEY,
  UVERBS_ATTR_REG_DM_MR_RESP_RKEY,
};
enum uverbs_methods_mr {
  UVERBS_METHOD_DM_MR_REG,
  UVERBS_METHOD_MR_DESTROY,
  UVERBS_METHOD_ADVISE_MR,
  UVERBS_METHOD_QUERY_MR,
  UVERBS_METHOD_REG_DMABUF_MR,
};
enum uverbs_attrs_mr_destroy_ids {
  UVERBS_ATTR_DESTROY_MR_HANDLE,
};
enum uverbs_attrs_advise_mr_cmd_attr_ids {
  UVERBS_ATTR_ADVISE_MR_PD_HANDLE,
  UVERBS_ATTR_ADVISE_MR_ADVICE,
  UVERBS_ATTR_ADVISE_MR_FLAGS,
  UVERBS_ATTR_ADVISE_MR_SGE_LIST,
};
enum uverbs_attrs_query_mr_cmd_attr_ids {
  UVERBS_ATTR_QUERY_MR_HANDLE,
  UVERBS_ATTR_QUERY_MR_RESP_LKEY,
  UVERBS_ATTR_QUERY_MR_RESP_RKEY,
  UVERBS_ATTR_QUERY_MR_RESP_LENGTH,
  UVERBS_ATTR_QUERY_MR_RESP_IOVA,
};
enum uverbs_attrs_reg_dmabuf_mr_cmd_attr_ids {
  UVERBS_ATTR_REG_DMABUF_MR_HANDLE,
  UVERBS_ATTR_REG_DMABUF_MR_PD_HANDLE,
  UVERBS_ATTR_REG_DMABUF_MR_OFFSET,
  UVERBS_ATTR_REG_DMABUF_MR_LENGTH,
  UVERBS_ATTR_REG_DMABUF_MR_IOVA,
  UVERBS_ATTR_REG_DMABUF_MR_FD,
  UVERBS_ATTR_REG_DMABUF_MR_ACCESS_FLAGS,
  UVERBS_ATTR_REG_DMABUF_MR_RESP_LKEY,
  UVERBS_ATTR_REG_DMABUF_MR_RESP_RKEY,
};
enum uverbs_attrs_create_counters_cmd_attr_ids {
  UVERBS_ATTR_CREATE_COUNTERS_HANDLE,
};
enum uverbs_attrs_destroy_counters_cmd_attr_ids {
  UVERBS_ATTR_DESTROY_COUNTERS_HANDLE,
};
enum uverbs_attrs_read_counters_cmd_attr_ids {
  UVERBS_ATTR_READ_COUNTERS_HANDLE,
  UVERBS_ATTR_READ_COUNTERS_BUFF,
  UVERBS_ATTR_READ_COUNTERS_FLAGS,
};
enum uverbs_methods_actions_counters_ops {
  UVERBS_METHOD_COUNTERS_CREATE,
  UVERBS_METHOD_COUNTERS_DESTROY,
  UVERBS_METHOD_COUNTERS_READ,
};
enum uverbs_attrs_info_handles_id {
  UVERBS_ATTR_INFO_OBJECT_ID,
  UVERBS_ATTR_INFO_TOTAL_HANDLES,
  UVERBS_ATTR_INFO_HANDLES_LIST,
};
enum uverbs_methods_pd {
  UVERBS_METHOD_PD_DESTROY,
};
enum uverbs_attrs_pd_destroy_ids {
  UVERBS_ATTR_DESTROY_PD_HANDLE,
};
enum uverbs_methods_mw {
  UVERBS_METHOD_MW_DESTROY,
};
enum uverbs_attrs_mw_destroy_ids {
  UVERBS_ATTR_DESTROY_MW_HANDLE,
};
enum uverbs_methods_xrcd {
  UVERBS_METHOD_XRCD_DESTROY,
};
enum uverbs_attrs_xrcd_destroy_ids {
  UVERBS_ATTR_DESTROY_XRCD_HANDLE,
};
enum uverbs_methods_ah {
  UVERBS_METHOD_AH_DESTROY,
};
enum uverbs_attrs_ah_destroy_ids {
  UVERBS_ATTR_DESTROY_AH_HANDLE,
};
enum uverbs_methods_rwq_ind_tbl {
  UVERBS_METHOD_RWQ_IND_TBL_DESTROY,
};
enum uverbs_attrs_rwq_ind_tbl_destroy_ids {
  UVERBS_ATTR_DESTROY_RWQ_IND_TBL_HANDLE,
};
enum uverbs_methods_flow {
  UVERBS_METHOD_FLOW_DESTROY,
};
enum uverbs_attrs_flow_destroy_ids {
  UVERBS_ATTR_DESTROY_FLOW_HANDLE,
};
enum uverbs_method_async_event {
  UVERBS_METHOD_ASYNC_EVENT_ALLOC,
};
enum uverbs_attrs_async_event_create {
  UVERBS_ATTR_ASYNC_EVENT_ALLOC_FD_HANDLE,
};
enum uverbs_attrs_query_gid_table_cmd_attr_ids {
  UVERBS_ATTR_QUERY_GID_TABLE_ENTRY_SIZE,
  UVERBS_ATTR_QUERY_GID_TABLE_FLAGS,
  UVERBS_ATTR_QUERY_GID_TABLE_RESP_ENTRIES,
  UVERBS_ATTR_QUERY_GID_TABLE_RESP_NUM_ENTRIES,
};
enum uverbs_attrs_query_gid_entry_cmd_attr_ids {
  UVERBS_ATTR_QUERY_GID_ENTRY_PORT,
  UVERBS_ATTR_QUERY_GID_ENTRY_GID_INDEX,
  UVERBS_ATTR_QUERY_GID_ENTRY_FLAGS,
  UVERBS_ATTR_QUERY_GID_ENTRY_RESP_ENTRY,
};
#endif

"""

```