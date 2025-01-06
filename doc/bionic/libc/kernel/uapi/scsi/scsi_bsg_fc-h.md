Response:
Let's break down the thought process for answering the request about the `scsi_bsg_fc.h` header file.

**1. Understanding the Core Request:**

The central task is to analyze the provided C header file (`scsi_bsg_fc.h`) within the context of Android's Bionic library and explain its purpose, relation to Android, implementation details, potential issues, and how Android uses it. The decomposed instructions provide specific areas to focus on.

**2. Initial Analysis of the Header File:**

* **`#ifndef SCSI_BSG_FC_H`, `#define SCSI_BSG_FC_H`, `#endif`:**  Standard header guard to prevent multiple inclusions. This is fundamental C practice and not specific to the file's functionality.
* **`#include <linux/types.h>`:**  Indicates this header file is part of the Linux kernel's UAPI (User API). This immediately tells us it deals with low-level hardware interaction, specifically SCSI.
* **Macros (e.g., `FC_DEFAULT_BSG_TIMEOUT`, `FC_BSG_CLS_MASK`):** These define constants, likely for bit manipulation and setting default values related to Fibre Channel SCSI. The names provide hints about their purpose (timeout, class mask, etc.).
* **Structures (e.g., `fc_bsg_host_add_rport`, `fc_bsg_reply`):** These define data structures used for communication related to Fibre Channel SCSI. The structure names are quite descriptive (host add remote port, Fibre Channel block storage generic reply). The `__u8`, `__u32`, `__u64` types indicate unsigned integer values of different sizes, common in kernel-level code.
* **Bitwise ORing in Macro Definitions (e.g., `FC_BSG_HST_MASK | 0x00000001`):**  This suggests the macros are used to create specific command or status codes by combining a base mask with a specific operation identifier.
* **`union` in `fc_bsg_request` and `fc_bsg_reply`:**  This is a key observation. Unions allow different data structures to occupy the same memory location. This is used to represent different types of requests and replies based on the `msgcode`.
* **`__attribute__((packed))`:** This compiler directive minimizes padding in the `fc_bsg_request` structure, important for ensuring the data layout matches the expectations of the underlying hardware or driver.
* **`__DECLARE_FLEX_ARRAY`:** This is a Bionic/kernel-specific macro for defining a flexible array member at the end of a structure. It means `vendor_rsp` can have a variable number of `__u32` elements.

**3. Connecting to Android and SCSI:**

* **`bionic/libc/kernel/uapi/`:** The path strongly suggests this is part of Android's Bionic library and provides the user-space interface to kernel functionality. The "uapi" confirms it's a user-facing API.
* **"scsi":**  Clearly related to the Small Computer System Interface, a standard for connecting storage and other peripherals.
* **"bsg":** Block Storage Generic. This implies a generic way to interact with block storage devices using SCSI commands.
* **"fc":** Fibre Channel, a high-speed network technology often used for storage area networks (SANs).

Therefore, the file provides the user-space definitions for interacting with Fibre Channel SCSI devices on an Android system.

**4. Addressing Specific Instructions:**

* **功能 (Functionality):** Summarize the overall purpose: defining data structures and constants for sending SCSI commands related to Fibre Channel block storage. Mention adding/deleting ports, sending ELS/CT commands, and vendor-specific commands.
* **与 Android 的关系 (Relationship to Android):**  Explain that while not directly used by typical Android apps, it's crucial for devices that *do* use Fibre Channel storage, like specialized enterprise devices. Give a hypothetical example of a high-end Android storage appliance.
* **libc 函数功能 (libc Function Implementation):**  *Crucially*, realize that this header file *doesn't contain libc function implementations*. It's a header file defining data structures. State this clearly and explain the role of header files.
* **dynamic linker 功能 (Dynamic Linker Functionality):**  Similarly, this header file doesn't directly involve the dynamic linker. Explain the dynamic linker's role (loading shared libraries) and why it's not relevant here. Provide a *general* example of SO layout and linking process for broader understanding, but emphasize it's not specific to *this* file.
* **逻辑推理 (Logical Inference):**  Create hypothetical scenarios (e.g., adding a port, sending a CT command) to illustrate how the data structures would be used. Show the input and expected output (in terms of the structure fields being filled).
* **用户/编程常见错误 (Common Usage Errors):** Focus on misuse of the structures, incorrect command codes, buffer overflows (if dealing with variable-length data), and incorrect interpretation of status codes.
* **Android Framework/NDK 到达路径 (Android Framework/NDK Path):** This requires understanding the layers of Android. Start from the application level, go down to the framework (StorageManager), then the NDK (if used), and finally to kernel drivers and this UAPI header. Use a simplified illustration.
* **Frida Hook 示例 (Frida Hook Example):**  Provide a basic example of hooking a system call (e.g., `ioctl`) that would likely be used to interact with the underlying driver using these structures. This demonstrates how to intercept and inspect the data being exchanged.

**5. Language and Tone:**

Use clear and concise Chinese. Explain technical terms when necessary. Acknowledge limitations (e.g., not containing function implementations).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file contains some inline functions. **Correction:**  Careful examination shows it's just data structure definitions and macros.
* **Initial thought:** Focus heavily on the "libc" part of the prompt. **Correction:** Realize the core function is defining the UAPI for a kernel subsystem. Libc's role is primarily providing the system call interface to *use* these definitions, not define them.
* **Initial thought:** Provide very detailed technical information about Fibre Channel protocols. **Correction:** Keep the explanation relevant to the header file itself and the Android context. Avoid getting bogged down in protocol specifics unless absolutely necessary. Focus on how the *structures* are used.

By following this structured thought process, focusing on the key information in the header file, and addressing each part of the request methodically, a comprehensive and accurate answer can be constructed.
这个C头文件 `bionic/libc/kernel/uapi/scsi/scsi_bsg_fc.h` 定义了用户空间程序与 Linux 内核中 Fibre Channel (FC) SCSI Block Storage Generic (BSG) 子系统进行交互所需的数据结构和常量。它属于 Android Bionic 库的一部分，Bionic 库是 Android 系统的 C 标准库、数学库和动态链接器。

下面详细列举它的功能和相关说明：

**1. 功能概述:**

这个头文件定义了用于向 Fibre Channel SCSI 设备发送控制命令和接收响应的请求和回复结构体。它主要涉及以下功能：

* **定义 Fibre Channel BSG 操作码:**  通过宏定义了各种 Fibre Channel BSG 操作码，例如添加/删除远程端口、发送 ELS (交换链路服务) 和 CT (通用传输) 命令等。这些操作码用于 `fc_bsg_request` 结构体中的 `msgcode` 字段，指示要执行的具体操作。
* **定义与主机相关的操作结构体:**  定义了以 `fc_bsg_host_` 开头的结构体，用于执行与 FC 主机总线适配器 (HBA) 相关的操作，例如：
    * `fc_bsg_host_add_rport`: 添加远程端口。
    * `fc_bsg_host_del_rport`: 删除远程端口。
    * `fc_bsg_host_els`: 发送主机发起的 ELS 命令。
    * `fc_bsg_host_ct`: 发送主机发起的 CT 命令。
    * `fc_bsg_host_vendor`: 发送主机相关的厂商自定义命令。
* **定义与远程端口相关的操作结构体:** 定义了以 `fc_bsg_rport_` 开头的结构体，用于执行与远程端口相关的操作，例如：
    * `fc_bsg_rport_els`: 发送远程端口相关的 ELS 命令。
    * `fc_bsg_rport_ct`: 发送远程端口相关的 CT 命令。
* **定义请求和回复结构体:**
    * `fc_bsg_request`:  定义了发送给内核的请求结构体，包含操作码 (`msgcode`) 和一个联合体 (`rqst_data`)，联合体根据操作码的不同包含不同的操作数据结构。
    * `fc_bsg_reply`: 定义了从内核接收的回复结构体，包含操作结果 (`result`)、回复数据的长度 (`reply_payload_rcv_len`) 和一个联合体 (`reply_data`)，联合体根据请求类型的不同包含不同的回复数据结构。
* **定义状态码和常量:**  例如 `FC_DEFAULT_BSG_TIMEOUT` 定义了默认的 BSG 超时时间，`FC_CTELS_STATUS_OK` 等定义了 CT/ELS 命令的回复状态。

**2. 与 Android 功能的关系及举例:**

这个头文件定义的是底层的内核接口，主要用于支持连接到 Android 设备的 Fibre Channel 存储设备。普通 Android 应用程序通常不会直接使用这些接口。它更可能被以下类型的场景使用：

* **企业级存储设备连接:**  如果 Android 设备作为存储客户端连接到 Fibre Channel SAN (存储区域网络)，那么底层的驱动程序和用户空间工具可能会使用这些结构体来管理连接和执行存储操作。
* **特定硬件或模拟器:**  某些特定的 Android 硬件或者用于开发和测试的模拟器可能需要与 Fibre Channel 设备交互。
* **文件系统或存储管理工具:**  Android 系统中一些底层的存储管理工具，如果需要直接操作 Fibre Channel 设备，可能会间接地使用这些接口。

**举例说明:**

假设一个 Android 设备连接到一个 Fibre Channel SAN。一个负责管理存储连接的用户空间守护进程可能需要添加一个新的远程端口。它会构建一个 `fc_bsg_request` 结构体，其中：

* `msgcode` 设置为 `FC_BSG_HST_ADD_RPORT`。
* `rqst_data.h_addrport` 填充要添加的远程端口的 ID 信息。

然后，这个请求会通过一个系统调用（通常是 `ioctl`）发送给内核。内核的 Fibre Channel BSG 驱动程序会解析这个请求，执行相应的操作，并通过 `fc_bsg_reply` 结构体返回操作结果。

**3. 详细解释每一个 libc 函数的功能是如何实现的:**

**重要:** 这个头文件本身**并不包含任何 libc 函数的实现**。它只是定义了数据结构和常量。这些结构体会被传递给内核，内核中的驱动程序会处理这些请求。

libc (Bionic 在 Android 中的实现) 的作用是提供访问内核功能的系统调用接口。  用户空间的程序会使用 libc 提供的系统调用函数（例如 `ioctl`）来与内核进行交互，并将这些结构体作为参数传递给系统调用。

**例如，当用户空间程序需要发送一个 FC BSG 请求时，它会执行以下步骤 (简化)：**

1. **包含头文件:**  `#include <scsi/scsi_bsg_fc.h>`  以获取结构体定义。
2. **填充请求结构体:** 创建并填充 `fc_bsg_request` 结构体的相应字段。
3. **打开设备文件:**  打开与 Fibre Channel 设备关联的设备文件 (例如 `/dev/bsg/hostX/portY/deviceZ`)。
4. **调用 `ioctl` 系统调用:**  使用 `ioctl` 函数，将打开的设备文件描述符、一个表示 BSG 操作的命令码（例如 `SG_IO`，并携带 BSG 请求类型信息），以及指向填充好的 `fc_bsg_request` 结构体的指针作为参数传递给内核。
5. **内核处理:**  内核接收到 `ioctl` 调用后，会根据命令码将请求传递给相应的 Fibre Channel BSG 驱动程序。驱动程序会解析 `fc_bsg_request` 结构体，执行对应的 Fibre Channel 协议操作。
6. **内核返回:**  驱动程序执行完成后，会将结果填充到 `fc_bsg_reply` 结构体中，并通过 `ioctl` 系统调用返回给用户空间程序。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**这个头文件本身与 dynamic linker 没有直接关系。**  Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要职责是在程序启动或运行时加载共享库 (`.so` 文件) 并解析符号引用。

`scsi_bsg_fc.h` 定义的是用户空间与内核交互的数据结构，它会被编译到使用它的用户空间程序中。 这些结构体的定义是静态的，不需要动态链接。

**尽管如此，为了理解 dynamic linker 的一般概念，这里提供一个简化的 SO 布局样本和链接过程：**

**SO 布局样本 (假设一个名为 `libfcsi.so` 的共享库可能使用了这些头文件):**

```
libfcsi.so:
  .text:  // 包含代码段
    function_a:
      // ... 使用了 scsi_bsg_fc.h 中定义的结构体 ...
  .data:  // 包含已初始化的全局变量
    global_var:
      // ...
  .bss:   // 包含未初始化的全局变量
    uninitialized_var:
      // ...
  .dynsym: // 动态符号表，列出库导出的符号
    function_a
  .dynstr: // 动态字符串表，存储符号名称
    function_a
  .plt:    // Procedure Linkage Table，用于延迟绑定
  .got:    // Global Offset Table，存储全局变量的地址
```

**链接的处理过程 (简化):**

1. **编译时链接:** 当编译一个使用 `libfcsi.so` 的程序时，编译器和链接器会记录程序对 `libfcsi.so` 中符号的引用。
2. **加载时链接 (dynamic linker 的工作):**
   * 当程序启动时，内核会加载程序的 ELF 文件。
   * ELF 文件头中包含了对 dynamic linker 的引用。内核会启动 dynamic linker。
   * Dynamic linker 读取程序的 ELF 文件头，找到需要加载的共享库 (`libfcsi.so`)。
   * Dynamic linker 在预定义的路径（或通过 `LD_LIBRARY_PATH` 等环境变量指定）中查找 `libfcsi.so`。
   * 加载 `libfcsi.so` 到内存中的一个地址空间。
   * **符号解析:** Dynamic linker 遍历程序和 `libfcsi.so` 的动态符号表 (`.dynsym`)，解析程序中对 `libfcsi.so` 中符号（例如 `function_a`）的引用。它会更新程序的 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table)，将符号引用指向 `libfcsi.so` 中对应符号的地址。
   * **重定位:** Dynamic linker 可能需要调整库中某些代码或数据的地址，以适应它被加载到的实际内存地址。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

假设我们想使用 `FC_BSG_HST_ADD_RPORT` 操作添加一个远程端口。

**假设输入 (在用户空间程序中填充的 `fc_bsg_request` 结构体):**

```c
struct fc_bsg_request request;
memset(&request, 0, sizeof(request));
request.msgcode = FC_BSG_HST_ADD_RPORT;
request.rqst_data.h_addrport.reserved = 0;
request.rqst_data.h_addrport.port_id[0] = 0xFA;
request.rqst_data.h_addrport.port_id[1] = 0xFB;
request.rqst_data.h_addrport.port_id[2] = 0xFC;
```

**逻辑推理:**

用户空间程序将填充 `fc_bsg_request` 结构体，指定操作码为 `FC_BSG_HST_ADD_RPORT`，并在 `rqst_data.h_addrport` 中设置要添加的远程端口 ID (0xFAFBFC)。然后，这个请求会通过 `ioctl` 系统调用发送到内核。

**假设输出 (内核返回的 `fc_bsg_reply` 结构体):**

* **成功的情况:**

```c
struct fc_bsg_reply reply;
// ... 从 ioctl 获取 reply ...
if (reply.result == 0) { // 假设 0 表示成功
  // 添加远程端口成功
} else {
  // 添加远程端口失败，根据 reply.result 进行错误处理
}
```

* **失败的情况 (例如，端口已存在):**

```c
struct fc_bsg_reply reply;
// ... 从 ioctl 获取 reply ...
if (reply.result != 0) {
  // 添加远程端口失败
  // reply.result 可能包含特定的错误码，例如表示端口已存在
}
```

**注意:**  实际的 `reply.result` 的含义由内核驱动程序定义。

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **错误的 `msgcode`:**  使用了错误的 `msgcode`，导致内核无法正确识别请求的操作。
    ```c
    request.msgcode = 0xFFFFFFFF; // 错误的 msgcode
    ```
* **未正确初始化结构体:**  忘记初始化结构体，导致结构体中包含垃圾数据，传递给内核后可能导致不可预测的行为。
    ```c
    struct fc_bsg_request request; // 未初始化
    request.msgcode = FC_BSG_HST_ADD_RPORT;
    // rqst_data 中的 port_id 未初始化
    ```
* **缓冲区溢出 (虽然此头文件没有直接涉及，但在实际使用中可能发生):** 如果涉及到需要传递数据的操作，例如发送 ELS 或 CT 命令，用户空间程序分配的缓冲区大小不足以容纳数据，可能导致缓冲区溢出。
* **错误地解释 `reply.result`:**  不理解内核返回的 `reply.result` 的含义，导致错误的程序逻辑。
* **在错误的设备文件上调用 `ioctl`:**  尝试在不正确的设备文件上执行 BSG 操作，例如针对一个不属于 Fibre Channel 设备的设备文件。
* **权限问题:**  用户空间程序可能没有足够的权限访问 `/dev/bsg` 下的设备文件。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**典型的 Android 应用或 NDK 开发很少会直接接触到 `scsi_bsg_fc.h` 定义的接口。**  这些接口通常被底层的系统服务或驱动程序使用。

**可能的路径 (非常规或特定场景):**

1. **应用层 (Java/Kotlin):**  应用程序不太可能直接使用这些接口。
2. **Android Framework (Java):**  某些底层的系统服务，例如 StorageManager，可能会间接地与处理存储设备的 Native 代码交互。
3. **Native 代码 (C/C++):**  这些系统服务会调用 Native 代码，这些 Native 代码可能会使用 NDK 提供的接口来与内核交互。
4. **NDK (Native Development Kit):**  NDK 提供了一些系统调用的封装，但通常不直接暴露与 Fibre Channel BSG 相关的接口。更可能的是，底层的 Native 代码会直接使用 `ioctl` 系统调用。
5. **Bionic libc:**  Native 代码会链接到 Bionic libc，使用其提供的 `ioctl` 函数。
6. **内核驱动程序:**  `ioctl` 系统调用最终会到达内核的 Fibre Channel BSG 驱动程序。
7. **`scsi_bsg_fc.h`:**  在 Native 代码中，为了构建发送给内核的请求结构体，会包含 `scsi_bsg_fc.h` 头文件。

**Frida Hook 示例:**

假设我们想 hook 一个可能使用这些接口的 Native 服务，并观察它如何调用 `ioctl` 以及传递的参数。

```python
import frida
import sys

package_name = "com.android.systemui" # 替换为目标进程的包名或进程名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保进程正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 检查文件描述符是否可能与 Fibre Channel 设备相关
        const path = this.syscall(frida.syscall.types.linux.SYS_readlink, ptr(fd), Memory.allocUtf8String(256), 256);
        if (path && path.includes("/dev/bsg/")) {
            console.log("发现 ioctl 调用，文件描述符:", fd, "请求码:", request);

            // 尝试解析 argp 指向的结构体 (需要根据具体的 request 码来确定结构体类型)
            if (request === 0xA4) { // 假设 0xA4 是一个与 FC BSG 相关的 ioctl 命令码
                const bsg_request_ptr = argp;
                const msgcode = bsg_request_ptr.readU32();
                console.log("  msgcode:", msgcode);

                // 根据 msgcode 解析联合体中的数据 (需要根据 scsi_bsg_fc.h 的定义)
                if (msgcode === 0x80000001) { // FC_BSG_HST_ADD_RPORT
                    const port_id_ptr = bsg_request_ptr.add(4 + 1); // 跳过 msgcode 和 reserved 字段
                    const port_id = [port_id_ptr.readU8(), port_id_ptr.add(1).readU8(), port_id_ptr.add(2).readU8()];
                    console.log("  port_id:", port_id);
                }
                // ... 其他 msgcode 的解析 ...
            }
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl 返回值:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例说明:**

1. **Attach 到目标进程:**  使用 Frida attach 到可能使用相关接口的 Android 系统进程。
2. **Hook `ioctl`:**  Hook `libc.so` 中的 `ioctl` 函数，这是用户空间程序与内核交互的常见方式。
3. **检查文件描述符:**  在 `onEnter` 中，尝试读取文件描述符对应的路径，判断是否与 `/dev/bsg/` 相关，从而缩小监控范围。
4. **解析参数:**  如果文件路径符合条件，尝试解析 `ioctl` 的参数 `argp`，该参数通常指向传递给内核的数据结构。 需要根据具体的 `request` 码（`ioctl` 的第二个参数）和 `scsi_bsg_fc.h` 中的结构体定义来解析数据。
5. **输出信息:**  打印捕获到的 `ioctl` 调用信息，包括文件描述符、请求码以及解析出的结构体内容。

**请注意:**  这个 Frida Hook 示例只是一个起点，你需要根据你要调试的具体场景和目标进程来调整代码，包括确定正确的进程名、`ioctl` 命令码以及如何解析结构体。 实际的系统服务可能会使用更复杂的逻辑和多层调用，你需要进行逐步分析和 Hook 才能定位到与 Fibre Channel BSG 相关的调用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/scsi/scsi_bsg_fc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef SCSI_BSG_FC_H
#define SCSI_BSG_FC_H
#include <linux/types.h>
#define FC_DEFAULT_BSG_TIMEOUT (10 * HZ)
#define FC_BSG_CLS_MASK 0xF0000000
#define FC_BSG_HST_MASK 0x80000000
#define FC_BSG_RPT_MASK 0x40000000
#define FC_BSG_HST_ADD_RPORT (FC_BSG_HST_MASK | 0x00000001)
#define FC_BSG_HST_DEL_RPORT (FC_BSG_HST_MASK | 0x00000002)
#define FC_BSG_HST_ELS_NOLOGIN (FC_BSG_HST_MASK | 0x00000003)
#define FC_BSG_HST_CT (FC_BSG_HST_MASK | 0x00000004)
#define FC_BSG_HST_VENDOR (FC_BSG_HST_MASK | 0x000000FF)
#define FC_BSG_RPT_ELS (FC_BSG_RPT_MASK | 0x00000001)
#define FC_BSG_RPT_CT (FC_BSG_RPT_MASK | 0x00000002)
struct fc_bsg_host_add_rport {
  __u8 reserved;
  __u8 port_id[3];
};
struct fc_bsg_host_del_rport {
  __u8 reserved;
  __u8 port_id[3];
};
struct fc_bsg_host_els {
  __u8 command_code;
  __u8 port_id[3];
};
#define FC_CTELS_STATUS_OK 0x00000000
#define FC_CTELS_STATUS_REJECT 0x00000001
#define FC_CTELS_STATUS_P_RJT 0x00000002
#define FC_CTELS_STATUS_F_RJT 0x00000003
#define FC_CTELS_STATUS_P_BSY 0x00000004
#define FC_CTELS_STATUS_F_BSY 0x00000006
struct fc_bsg_ctels_reply {
  __u32 status;
  struct {
    __u8 action;
    __u8 reason_code;
    __u8 reason_explanation;
    __u8 vendor_unique;
  } rjt_data;
};
struct fc_bsg_host_ct {
  __u8 reserved;
  __u8 port_id[3];
  __u32 preamble_word0;
  __u32 preamble_word1;
  __u32 preamble_word2;
};
struct fc_bsg_host_vendor {
  __u64 vendor_id;
  __u32 vendor_cmd[];
};
struct fc_bsg_host_vendor_reply {
  __DECLARE_FLEX_ARRAY(__u32, vendor_rsp);
};
struct fc_bsg_rport_els {
  __u8 els_code;
};
struct fc_bsg_rport_ct {
  __u32 preamble_word0;
  __u32 preamble_word1;
  __u32 preamble_word2;
};
struct fc_bsg_request {
  __u32 msgcode;
  union {
    struct fc_bsg_host_add_rport h_addrport;
    struct fc_bsg_host_del_rport h_delrport;
    struct fc_bsg_host_els h_els;
    struct fc_bsg_host_ct h_ct;
    struct fc_bsg_host_vendor h_vendor;
    struct fc_bsg_rport_els r_els;
    struct fc_bsg_rport_ct r_ct;
  } rqst_data;
} __attribute__((packed));
struct fc_bsg_reply {
  __u32 result;
  __u32 reply_payload_rcv_len;
  union {
    struct fc_bsg_host_vendor_reply vendor_reply;
    struct fc_bsg_ctels_reply ctels_reply;
  } reply_data;
};
#endif

"""

```