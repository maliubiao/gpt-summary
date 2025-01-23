Response:
Let's break down the thought process for analyzing this header file.

1. **Understanding the Context:** The first step is to recognize the context provided: `bionic/libc/kernel/uapi/scsi/scsi_bsg_ufs.handroid bionic`. This immediately tells us:
    * **bionic:**  This is Android's core C library. Anything here is fundamental to the Android operating system.
    * **libc/kernel/uapi:** This indicates a header file that defines the *user-space application programming interface* (UAPI) for interacting with the *kernel*. Specifically, it's within the `scsi` (Small Computer System Interface) subsystem. The `uapi` directory is crucial – it signifies the boundary between kernel and user space. Changes here need careful consideration as they affect application compatibility.
    * **scsi/scsi_bsg_ufs.h:** This pinpoints the specific area: SCSI block generic (bsg) interface for Universal Flash Storage (UFS) devices. The `.h` extension confirms it's a header file defining data structures and constants.
    * **handroid:** This likely refers to Android-specific extensions or customizations within the standard UFS interface.

2. **Initial Scan for Key Structures and Enums:**  The next step is to quickly scan the code for important elements. Enums and structs are the core building blocks of such header files. I'd look for:
    * `enum`: These define sets of named constants, often representing states or command codes. The presence of `ufs_bsg_msg_code` and `ufs_rpmb_op_type` is significant, hinting at message types and RPMB (Replay Protected Memory Block) operations.
    * `struct`: These define data structures used to pass information between user space and the kernel. The presence of `utp_upiu_header`, `utp_upiu_cmd`, `ufs_bsg_request`, `ufs_bsg_reply`, `ufs_rpmb_request`, and `ufs_rpmb_reply` strongly suggests these are the primary data structures for communication.
    * `#define`: These are preprocessor definitions. `UFS_CDB_SIZE` and `UIC_CMD_SIZE` define important size constants.

3. **Analyzing Individual Elements:** Now, dive into the details of each enum and struct:
    * **Enums:** Understand what each enumerated value represents. For example, `UPIU_TRANSACTION_UIC_CMD` suggests a command related to the UFS Interconnect Command (UIC), and the `UFS_RPMB_*` enums clearly relate to secure storage operations.
    * **Structs:** For each struct, examine its members, their data types, and their names. Try to infer the purpose of each field. For instance, `utp_upiu_header` contains fields like `transaction_code`, `flags`, `lun`, `task_tag`, which are common in SCSI-like protocols. The union within this struct is interesting and likely provides different views of the same underlying memory. The endianness handling (`#ifdef __BIG_ENDIAN`...) is also noteworthy.
    * **Endianness:** Recognize the importance of byte order (`__be32`). This indicates that data needs to be converted to network byte order when communicating with the UFS device, which is essential for interoperability.

4. **Inferring Functionality:** Based on the structures and enums, start inferring the high-level functionality:
    * **UFS Communication:** The `utp_upiu_*` structures strongly suggest this file defines the protocol for communicating with UFS devices at a low level.
    * **Block Layer Interaction:** The `scsi_bsg` part indicates interaction with the SCSI block generic interface, a standard way for user space to send SCSI commands to block devices.
    * **RPMB Support:** The `ufs_rpmb_*` structures and enums clearly point to support for RPMB, a secure storage area within UFS devices used for storing sensitive data like cryptographic keys.
    * **UIC Commands:**  The `UPIU_TRANSACTION_UIC_CMD` and `UIC_CMD_SIZE` indicate the ability to send vendor-specific or UFS standard management commands directly to the device.

5. **Connecting to Android:** Now, think about how these functionalities relate to Android:
    * **Storage:** UFS is the primary storage technology in modern Android devices. This header file is fundamental to how Android interacts with its storage.
    * **Security:** RPMB is crucial for Android's security model. It's used for things like Verified Boot, storing DRM keys, and potentially other sensitive data.
    * **HAL Layer:**  The interaction likely occurs through the Hardware Abstraction Layer (HAL). The framework would make requests, the HAL would translate those into the appropriate structures defined here, and then the kernel would send these commands to the UFS device.

6. **Considering `libc` and Dynamic Linking:**
    * **`libc` Functions:** Recognize that this header file *defines data structures*, not the implementation of `libc` functions. The `libc` functions would use these structures to interact with the kernel. Focus on *how* the structures are used rather than *how `libc` functions are implemented*.
    * **Dynamic Linking:** While this header doesn't directly involve dynamic linking, understand that the code *using* these structures would be part of shared libraries (.so files). Provide a basic example of an `so` layout and the linking process to illustrate the concept.

7. **Identifying Potential Issues and Errors:** Think about how developers might misuse these definitions:
    * **Incorrect Structure Usage:**  Passing the wrong data in the structures.
    * **Endianness Issues:**  Forgetting to convert data to network byte order.
    * **Size Mismatches:** Incorrectly calculating the size of data buffers.
    * **Invalid Command Codes:** Using incorrect values for `msgcode` or RPMB operation types.

8. **Frida Hooking:**  Consider how Frida can be used to inspect this interaction:
    * **Function Hooks:**  Hooking functions in the HAL or kernel that use these structures.
    * **Structure Inspection:**  Using Frida to examine the contents of these structures as they are passed between layers.

9. **Structuring the Answer:** Organize the information logically, starting with the basic functionality and then moving to more advanced topics like Android integration, dynamic linking, and debugging. Use clear headings and bullet points for readability. Provide concrete examples where possible.

10. **Refinement and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any logical inconsistencies or areas where more detail might be helpful. For instance, initially, I might focus too much on low-level SCSI details. I need to bring it back to the Android context and its implications. Also, ensure the language is precise and avoids jargon where possible or explains it clearly.

By following this systematic approach, I can dissect the header file and generate a comprehensive and informative answer that addresses all aspects of the prompt.
这是一个描述 Linux 内核 UAPI 中关于 UFS (Universal Flash Storage) 设备的 SCSI Block Generic (BSG) 接口的头文件。它定义了用于用户空间程序与 UFS 设备进行通信的数据结构和常量，特别是关于 RPMB (Replay Protected Memory Block) 安全功能的操作。

**功能列举：**

1. **定义 UFS BSG 消息代码 (`ufs_bsg_msg_code` enum):**  定义了可以通过 BSG 接口发送的不同类型的 UFS 消息。目前定义了两种：
    * `UPIU_TRANSACTION_UIC_CMD`:  用于发送 UFS Interconnect Command (UIC) 命令。UIC 命令允许用户空间直接与 UFS 设备的管理功能进行交互。
    * `UPIU_TRANSACTION_ARPMB_CMD`:  用于发送 RPMB (Replay Protected Memory Block) 命令。RPMB 是一种安全区域，用于存储加密密钥、安全启动数据等敏感信息。

2. **定义 UFS RPMB 操作类型 (`ufs_rpmb_op_type` enum):**  定义了可以执行的各种 RPMB 操作：
    * `UFS_RPMB_WRITE_KEY`: 写入 RPMB 认证密钥。
    * `UFS_RPMB_READ_CNT`: 读取 RPMB 写入计数器，用于防止回放攻击。
    * `UFS_RPMB_WRITE`: 写入 RPMB 数据块。
    * `UFS_RPMB_READ`: 读取 RPMB 数据块。
    * `UFS_RPMB_READ_RESP`: 读取 RPMB 操作的响应。
    * `UFS_RPMB_SEC_CONF_WRITE`: 写入安全配置数据。
    * `UFS_RPMB_SEC_CONF_READ`: 读取安全配置数据。
    * `UFS_RPMB_PURGE_ENABLE`: 启用 RPMB 清除功能。
    * `UFS_RPMB_PURGE_STATUS_READ`: 读取 RPMB 清除状态。

3. **定义 UTP UPIU (UFS Transport Protocol Unit Information Unit) 头部结构体 (`utp_upiu_header`):**  定义了 UFS 传输协议单元的头部信息，包含了事务代码、标志、LUN (Logical Unit Number)、任务标签、命令集类型、实例 ID (IID) 等信息。它还包含一个联合体，用于访问部分头部信息。

4. **定义 UTP UPIU 查询相关结构体 (`utp_upiu_query`, `utp_upiu_query_v4_0`):**  定义了用于发送 UFS 查询命令的结构体，用于获取设备属性和参数。

5. **定义 UTP UPIU 命令结构体 (`utp_upiu_cmd`):**  定义了用于发送标准 SCSI 命令的结构体，包含期望的数据传输长度和 CDB (Command Descriptor Block)。

6. **定义 UTP UPIU 请求结构体 (`utp_upiu_req`):**  定义了 UFS 请求的通用结构体，包含 UPIU 头部和一个联合体，用于存放不同类型的命令内容 (SCSI 命令、查询命令、UIC 命令)。

7. **定义 UFS ARPMB 元数据结构体 (`ufs_arpmb_meta`):**  定义了 RPMB 操作的元数据，包含请求/响应类型、随机数 (nonce)、写入计数器、地址/LUN、块计数和结果。

8. **定义 UFS EHS (Extended Header Segment) 结构体 (`ufs_ehs`):**  定义了扩展头部段，用于包含 RPMB 相关的元数据和 MAC 密钥，用于认证 RPMB 操作。

9. **定义 UFS BSG 请求和回复结构体 (`ufs_bsg_request`, `ufs_bsg_reply`):**  定义了通过 BSG 接口发送的请求和接收的回复的结构体。请求包含消息代码和 UPIU 请求，回复包含结果、接收到的回复载荷长度和 UPIU 响应。

10. **定义 UFS RPMB 请求和回复结构体 (`ufs_rpmb_request`, `ufs_rpmb_reply`):**  定义了专门用于 RPMB 操作的请求和回复结构体，包含了 BSG 请求/回复以及 EHS 信息。

**与 Android 功能的关系及举例：**

这个头文件对于 Android 设备的存储和安全功能至关重要，因为它定义了与 UFS 存储设备进行底层交互的接口。

* **存储访问:** Android 系统需要与 UFS 设备进行数据读写。尽管通常使用更高层的抽象接口 (如文件系统 API)，但在某些底层操作中，例如设备初始化、固件更新等，可能会使用到 BSG 接口发送底层的 SCSI 命令。例如，Android 的 `vold` (Volume Daemon) 组件可能在挂载和管理存储设备时，通过内核调用使用这些结构体。
* **安全启动 (Verified Boot):**  Android 的 Verified Boot 机制依赖于 RPMB 来存储关键的哈希值和计数器，以确保启动过程的完整性。例如，在启动过程中，bootloader 可能使用 `UFS_RPMB_READ` 读取 RPMB 中的数据来验证系统镜像的签名。
* **DRM (Digital Rights Management):**  DRM 框架可能使用 RPMB 来安全地存储设备唯一的密钥和其他敏感信息，以保护受版权保护的内容。例如，当播放受 DRM 保护的视频时，可能会使用 RPMB 来验证许可证。
* **Keymaster / Keystore:** Android 的 Keymaster 和 Keystore 系统可以利用 RPMB 来提供硬件级别的密钥存储，提高密钥的安全性。例如，用户的指纹认证密钥或设备加密密钥可能会存储在 RPMB 中，以防止软件攻击。
* **SELinux (Security-Enhanced Linux):** 虽然 SELinux 本身不直接使用这些结构体，但底层的存储访问和安全机制是 SELinux 策略执行的基础。

**libc 函数功能实现解释：**

这个头文件本身**没有定义任何 libc 函数**。它定义的是内核 UAPI，即用户空间程序可以用来与内核进行交互的数据结构。用户空间程序 (包括 Android Framework 和 NDK 应用) 需要使用 **系统调用 (syscalls)**，例如 `ioctl()`，并配合这些定义的结构体来向内核发送命令，从而间接地与 UFS 设备进行通信。

例如，要发送一个 RPMB 读取请求，用户空间程序需要：

1. 填充 `ufs_rpmb_request` 结构体的相应字段，例如设置 `bsg_request.msgcode` 为 `UPIU_TRANSACTION_ARPMB_CMD`，并设置 `ehs_req` 和 `bsg_request.upiu_req` 中的其他必要参数 (例如 RPMB 操作类型、地址、数据长度等)。
2. 打开一个表示 UFS 设备的设备文件 (例如 `/dev/sgX`)。
3. 调用 `ioctl()` 系统调用，指定相应的 ioctl 命令 (通常是 `SG_IO`)，并将填充好的 `ufs_rpmb_request` 结构体的地址作为参数传递给 `ioctl()`。
4. 内核接收到 `ioctl()` 调用后，会解析 `ufs_rpmb_request` 结构体中的信息，并将其转换为 UFS 设备能够理解的命令，最终发送到 UFS 存储设备。
5. UFS 设备处理完命令后，内核会接收到响应，并将响应信息填充到用户空间传递过来的 `ufs_rpmb_reply` 结构体中。
6. `ioctl()` 调用返回，用户空间程序可以从 `ufs_rpmb_reply` 结构体中读取结果。

**dynamic linker 功能及 SO 布局样本和链接处理过程：**

**动态链接器不直接参与** 对这个头文件中定义的结构体的使用。这些结构体是在用户空间程序和内核之间传递数据的桥梁，而动态链接器负责加载和链接共享库。

但是，**使用这些结构体的代码** 通常会存在于共享库 (`.so`) 中，例如存储相关的 HAL (Hardware Abstraction Layer) 库。

**SO 布局样本：**

假设有一个名为 `libufs_hal.so` 的共享库，它负责与 UFS 设备进行交互：

```
libufs_hal.so:
    .text:  # 代码段
        ufs_rpmb_read_data:  # 实现 RPMB 读取功能的函数
            # ... 使用 ufs_rpmb_request 和 ioctl 进行通信 ...
        ufs_send_uic_command: # 实现发送 UIC 命令的函数
            # ... 使用 ufs_bsg_request 和 ioctl 进行通信 ...
        ... 其他 UFS 相关功能 ...
    .data:  # 数据段
        ... 全局变量 ...
    .rodata: # 只读数据段
        ... 常量数据 ...
    .dynamic: # 动态链接信息
        ... 依赖的库，例如 libc.so ...
    .symtab:  # 符号表
        ... 导出和导入的符号 ...
    .strtab:  # 字符串表
        ... 符号名称 ...
```

**链接处理过程：**

1. 当一个应用程序 (或其他共享库) 需要使用 `libufs_hal.so` 中的函数时，动态链接器 (例如 `linker64` 或 `linker`) 会负责加载 `libufs_hal.so` 到内存中。
2. 动态链接器会解析 `libufs_hal.so` 的 `.dynamic` 段，找到它依赖的其他共享库 (例如 `libc.so`)。
3. 动态链接器也会加载这些依赖的共享库。
4. 动态链接器会解析 `libufs_hal.so` 和其依赖库的符号表 (`.symtab`) 和字符串表 (`.strtab`)。
5. 如果 `libufs_hal.so` 中的函数 (例如 `ufs_rpmb_read_data`) 调用了 `libc.so` 中的函数 (例如 `open`, `ioctl`)，动态链接器会进行符号解析，将 `ufs_rpmb_read_data` 中对 `ioctl` 的调用地址重定向到 `libc.so` 中 `ioctl` 函数的实际地址。这个过程被称为 **重定位 (relocation)**。

**假设输入与输出 (针对 RPMB 读取操作):**

**假设输入 (用户空间程序准备的 `ufs_rpmb_request` 结构体):**

```c
struct ufs_rpmb_request req;
memset(&req, 0, sizeof(req));

req.bsg_request.msgcode = UPIU_TRANSACTION_ARPMB_CMD;
req.ehs_req.length = sizeof(struct ufs_ehs);
req.ehs_req.ehs_type = /* 适当的 EHS 类型 */;
req.ehs_req.ehssub_type = /* 适当的 EHS 子类型 */;
req.ehs_req.meta.req_resp_type = htole16(0x0004); // RPMB read request
// ... 设置 nonce, write_counter, addr_lun, block_count 等 ...

req.bsg_request.upiu_req.header.transaction_code = /* 适当的事务代码 */;
req.bsg_request.upiu_req.header.lun = /* 适当的 LUN */;
// ... 设置 UPIU 头部其他字段 ...
```

**假设输出 (内核返回的 `ufs_rpmb_reply` 结构体):**

```c
struct ufs_rpmb_reply resp;
// ... ioctl 调用返回后 ...

if (resp.bsg_reply.result == 0) {
    // RPMB 读取成功
    // resp.ehs_rsp 中包含读取到的数据和 MAC 等信息
    // ... 处理读取到的数据 ...
} else {
    // RPMB 读取失败
    // resp.bsg_reply.result 中包含错误码
    // ... 处理错误 ...
}
```

**用户或编程常见的使用错误：**

1. **字节序错误 (Endianness):** UFS 协议中很多字段是大端序 (`__be16`, `__be32`)，而用户空间程序可能运行在小端序架构上。忘记使用 `htole16`, `htole32`, `be16toh`, `be32toh` 等函数进行字节序转换会导致数据解析错误。
    * **示例:** 直接将小端序的整数赋值给 `__be16` 字段，导致内核接收到的值与预期不符。
2. **结构体大小错误:**  在 `ioctl` 调用中，传递的结构体大小不正确可能导致内核读取或写入错误的内存区域。
    * **示例:**  计算 `sizeof(struct ufs_rpmb_request)` 时遗漏了某些字段或使用了错误的类型。
3. **命令代码错误:**  使用错误的 `msgcode` 或 RPMB 操作类型会导致内核执行错误的命令。
    * **示例:**  将 RPMB 读取请求的 `msgcode` 设置为 UIC 命令的代码。
4. **权限不足:**  访问 UFS 设备文件 (例如 `/dev/sgX`) 需要特定的权限。普通应用程序可能没有权限直接执行这些操作。
    * **示例:**  未经授权的应用程序尝试打开 `/dev/sg0` 并发送 RPMB 命令，会导致权限被拒绝。
5. **参数错误:**  RPMB 操作需要提供正确的地址、数据长度、密钥等参数。参数错误会导致操作失败或数据损坏。
    * **示例:**  尝试读取超出 RPMB 区域的地址，或者使用错误的认证密钥。
6. **并发访问冲突:**  多个进程或线程同时访问 RPMB 可能会导致冲突和数据不一致。
7. **错误处理不足:**  没有正确检查 `ioctl` 的返回值或回复结构体中的 `result` 字段，导致没有发现错误或以错误的方式处理错误。

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例：**

通常，应用程序不会直接使用这些底层的 UFS BSG 接口。Android Framework 提供更高级别的抽象，例如通过 `StorageManager` 服务与存储设备进行交互。HAL (Hardware Abstraction Layer) 是连接 Android Framework 和硬件的桥梁。

**步骤：**

1. **应用程序 (Java/Kotlin):** 应用程序通过 Android Framework 的 API (例如 `android.os.storage.StorageManager`) 请求执行存储相关的操作，例如读取或写入文件。
2. **Android Framework (Java):** `StorageManager` 服务接收到请求后，会调用底层的 Binder 接口，将请求传递给负责存储管理的系统服务 (例如 `vold`)。
3. **System Service (`vold`, C++):** `vold` 接收到请求后，可能会根据具体的操作类型，调用相应的 HAL 接口。
4. **Storage HAL (C/C++):** Storage HAL 库 (例如实现了 `android.hardware.storaged`) 负责与内核驱动进行交互。在某些情况下，HAL 可能会直接使用 `ioctl` 系统调用，并填充 `ufs_bsg_request` 或 `ufs_rpmb_request` 结构体，来向内核发送 UFS 命令。
5. **内核驱动 (Linux Kernel, C):** 内核中的 UFS 驱动程序接收到来自用户空间的 `ioctl` 调用后，会解析传递的结构体，并与 UFS 存储设备进行通信。

**Frida Hook 示例：**

可以使用 Frida Hook HAL 库中可能调用 `ioctl` 并使用这些结构体的函数。以下是一个 Hook `ioctl` 函数并打印相关信息的示例：

```python
import frida
import sys

# 连接到 Android 设备或模拟器
device = frida.get_usb_device()
pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
process = device.attach(pid)
device.resume(pid)

# Hook ioctl 函数
script = process.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        console.log("ioctl called with fd:", fd, "request:", request);

        // 判断是否是 SG_IO 命令 (与 SCSI 设备交互的常用 ioctl)
        const SG_IO = 0x2285; // 需要根据你的 Android 版本确定实际值
        if (request === SG_IO) {
            console.log("Potential SCSI Generic IOCTL");
            // 读取 sg_io_hdr 结构体 (需要包含 linux/ посылки 的头文件信息)
            const sg_io_hdr_ptr = argp;
            // ... 根据 sg_io_hdr 的定义读取相关字段，例如 cmd_len, dxfer_len, data ...

            // 尝试解析 UFS BSG request (假设 data 指向的是 ufs_bsg_request)
            const ufs_bsg_request_ptr = /* 计算 data 指针 */;
            if (ufs_bsg_request_ptr) {
                console.log("Likely UFS BSG Request");
                const msgcode = Memory.readU32(ufs_bsg_request_ptr);
                console.log("  msgcode:", msgcode);

                // 可以进一步解析 upiu_req 等字段
            }
        }
    },
    onLeave: function (retval) {
        console.log("ioctl returned:", retval);
    }
});
""")

script.load()
sys.stdin.read()
```

**说明:**

* 这个 Frida 脚本 Hook 了 `libc.so` 中的 `ioctl` 函数。
* 在 `onEnter` 中，它打印了 `ioctl` 的文件描述符和请求码。
* 它尝试判断是否是 `SG_IO` 命令，这通常用于与 SCSI 设备进行通信。
* 如果是 `SG_IO`，脚本会尝试读取 `sg_io_hdr` 结构体，并尝试将其解释为 `ufs_bsg_request` 结构体，打印出 `msgcode`。
* 要进行更深入的调试，你需要了解 `sg_io_hdr` 结构体的布局，并根据 `msgcode` 的值，进一步解析 `upiu_req` 或 `ehs_req` 等字段。
* 需要根据具体的 Android 版本和内核源码来确定 `SG_IO` 的值和相关结构体的定义。

通过 Frida Hook，你可以观察 Android Framework 或 NDK 应用在底层是如何使用这些 UFS BSG 接口与存储设备进行交互的，从而更好地理解其工作原理和排查问题。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/scsi/scsi_bsg_ufs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef SCSI_BSG_UFS_H
#define SCSI_BSG_UFS_H
#include <asm/byteorder.h>
#include <linux/types.h>
#define UFS_CDB_SIZE 16
#define UIC_CMD_SIZE (sizeof(__u32) * 4)
enum ufs_bsg_msg_code {
  UPIU_TRANSACTION_UIC_CMD = 0x1F,
  UPIU_TRANSACTION_ARPMB_CMD,
};
enum ufs_rpmb_op_type {
  UFS_RPMB_WRITE_KEY = 0x01,
  UFS_RPMB_READ_CNT = 0x02,
  UFS_RPMB_WRITE = 0x03,
  UFS_RPMB_READ = 0x04,
  UFS_RPMB_READ_RESP = 0x05,
  UFS_RPMB_SEC_CONF_WRITE = 0x06,
  UFS_RPMB_SEC_CONF_READ = 0x07,
  UFS_RPMB_PURGE_ENABLE = 0x08,
  UFS_RPMB_PURGE_STATUS_READ = 0x09,
};
struct utp_upiu_header {
  union {
    struct {
      __be32 dword_0;
      __be32 dword_1;
      __be32 dword_2;
    };
    struct {
      __u8 transaction_code;
      __u8 flags;
      __u8 lun;
      __u8 task_tag;
#ifdef __BIG_ENDIAN
      __u8 iid : 4;
      __u8 command_set_type : 4;
#elif defined(__LITTLE_ENDIAN)
      __u8 command_set_type : 4;
      __u8 iid : 4;
#else
#error 
#endif
      union {
        __u8 tm_function;
        __u8 query_function;
      } __attribute__((packed));
      __u8 response;
      __u8 status;
      __u8 ehs_length;
      __u8 device_information;
      __be16 data_segment_length;
    };
  };
};
struct utp_upiu_query {
  __u8 opcode;
  __u8 idn;
  __u8 index;
  __u8 selector;
  __be16 reserved_osf;
  __be16 length;
  __be32 value;
  __be32 reserved[2];
};
struct utp_upiu_query_v4_0 {
  __u8 opcode;
  __u8 idn;
  __u8 index;
  __u8 selector;
  __u8 osf3;
  __u8 osf4;
  __be16 osf5;
  __be32 osf6;
  __be32 osf7;
  __be32 reserved;
};
struct utp_upiu_cmd {
  __be32 exp_data_transfer_len;
  __u8 cdb[UFS_CDB_SIZE];
};
struct utp_upiu_req {
  struct utp_upiu_header header;
  union {
    struct utp_upiu_cmd sc;
    struct utp_upiu_query qr;
    struct utp_upiu_query uc;
  };
};
struct ufs_arpmb_meta {
  __be16 req_resp_type;
  __u8 nonce[16];
  __be32 write_counter;
  __be16 addr_lun;
  __be16 block_count;
  __be16 result;
} __attribute__((__packed__));
struct ufs_ehs {
  __u8 length;
  __u8 ehs_type;
  __be16 ehssub_type;
  struct ufs_arpmb_meta meta;
  __u8 mac_key[32];
} __attribute__((__packed__));
struct ufs_bsg_request {
  __u32 msgcode;
  struct utp_upiu_req upiu_req;
};
struct ufs_bsg_reply {
  int result;
  __u32 reply_payload_rcv_len;
  struct utp_upiu_req upiu_rsp;
};
struct ufs_rpmb_request {
  struct ufs_bsg_request bsg_request;
  struct ufs_ehs ehs_req;
};
struct ufs_rpmb_reply {
  struct ufs_bsg_reply bsg_reply;
  struct ufs_ehs ehs_rsp;
};
#endif
```