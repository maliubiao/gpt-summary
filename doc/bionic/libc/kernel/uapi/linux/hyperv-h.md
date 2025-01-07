Response:
Let's break down the thought process to generate the detailed explanation of the `hyperv.h` file.

1. **Understand the Goal:** The primary goal is to analyze a C header file (`hyperv.h`) located within the Android Bionic library's kernel interface and explain its functionality, connections to Android, implementation details, dynamic linking aspects, potential errors, and how Android frameworks might reach this code.

2. **Initial Information Extraction:** The first step is to read through the header file and identify key elements:
    * **Include:** `#include <linux/types.h>` - Indicates it uses standard Linux type definitions.
    * **Macros:**  Definitions like `UTIL_FW_MINOR`, `VSS_OP_REGISTER`, `FCOPY_VERSION_0`, `HV_KVP_EXCHANGE_MAX_VALUE_SIZE`, etc. These often represent constants or version information.
    * **Enums:** `hv_vss_op`, `hv_fcopy_op`, `hv_kvp_exchg_op`, `hv_kvp_exchg_pool`. These define sets of related named constants.
    * **Structs:** `hv_vss_hdr`, `hv_vss_check_feature`, `hv_vss_msg`, `hv_fcopy_hdr`, `hv_start_fcopy`, `hv_do_fcopy`, `hv_kvp_ipaddr_value`, `hv_kvp_hdr`, `hv_kvp_exchg_msg_value`, `hv_kvp_msg_enumerate`, `hv_kvp_msg_get`, `hv_kvp_msg_set`, `hv_kvp_msg_delete`, `hv_kvp_register`, `hv_kvp_msg`, `hv_kvp_ip_msg`. These define data structures used for communication.
    * **Packed Attribute:** `__attribute__((packed))` appears frequently, indicating that the compiler should not add padding between struct members, ensuring the binary layout is predictable for inter-process communication or interaction with hardware/kernel.

3. **Categorization and Functional Grouping:**  Organize the extracted information into logical categories based on the prefixes used in the definitions (VSS, FCOPY, KVP). This helps understand the overall structure and purpose of the file:
    * **Volume Shadow Copy Service (VSS):**  Definitions starting with `VSS_`. Likely related to creating snapshots or backups.
    * **File Copy Service (FCOPY):** Definitions starting with `FCOPY_`. Related to transferring files.
    * **Key-Value Pair Exchange (KVP):** Definitions starting with `KVP_`. Used for exchanging configuration or status information.

4. **Inferring Functionality:**  Based on the names of the enums and structs, infer the purpose of each section:
    * **VSS:** Operations like `CREATE`, `DELETE`, `HOT_BACKUP`, `FREEZE`, `THAW` strongly suggest backup/restore capabilities.
    * **FCOPY:** Operations like `START_FILE_COPY`, `WRITE_TO_FILE`, `COMPLETE_FCOPY`, `CANCEL_FCOPY` clearly indicate file transfer functionality.
    * **KVP:** Operations like `GET`, `SET`, `DELETE`, `ENUMERATE` point to a mechanism for retrieving, storing, and managing key-value pairs. The `KVP_POOL` enum suggests different scopes for these key-value pairs.

5. **Connecting to Android:**  Consider how these functionalities relate to Android. Since it's in `bionic/libc/kernel/uapi/linux/`, it's a low-level interface. Hyper-V is a Microsoft virtualization technology, so this file enables Android, running as a guest OS in Hyper-V, to interact with the host. Examples:
    * **VSS:**  Android backups might use this to create consistent snapshots of the guest OS.
    * **FCOPY:**  Could be used for transferring files between the Android guest and the Hyper-V host, though less likely for typical Android user operations. More relevant for system-level tools or virtualization management.
    * **KVP:**  This is the most obvious connection. Virtualization platforms often use KVP to exchange configuration data (like IP addresses, hostnames) between the host and guest. Android might use this to get network information or report status to the host.

6. **Implementation Details (libc Functions):** Since this is a header file, it primarily *defines* data structures and constants. It doesn't contain the *implementation* of libc functions. The implementation would reside in kernel modules or other parts of the Android system that utilize these definitions. Therefore, the explanation focuses on *how these definitions would be used* by libc functions (like `ioctl`) to interact with the Hyper-V hypervisor.

7. **Dynamic Linking:** This header file itself doesn't directly involve dynamic linking. However, the *use* of these structures and constants by Android system services and applications *does*. The explanation focuses on how these structures might be used in system calls and the role of the dynamic linker in resolving dependencies. A sample `.so` layout and the linking process are provided to illustrate the general concept of how different parts of Android interact with kernel interfaces.

8. **Logical Reasoning and Assumptions:** When explaining the functionality, make explicit any assumptions made. For example, assuming that `VSS_OP_FREEZE` and `VSS_OP_THAW` are for pausing and resuming file system operations during a backup.

9. **User/Programming Errors:** Think about common mistakes when working with such low-level interfaces. Incorrectly sized buffers, wrong operation codes, or misunderstanding the packed nature of the structs are potential issues.

10. **Android Framework/NDK Interaction:** Trace the path from a user-level action to the kernel interface. For example, a user initiating a backup through Android settings might trigger framework services, which then use NDK APIs, eventually leading to system calls that utilize these Hyper-V structures.

11. **Frida Hook Examples:** Provide practical Frida code snippets to demonstrate how to intercept and inspect the data being exchanged at this level. Focus on the `ioctl` system call, as that's the typical way user-space interacts with device drivers and kernel modules.

12. **Language and Clarity:** Ensure the explanation is in clear and concise Chinese, using appropriate technical terms. Break down complex concepts into smaller, understandable parts.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe these structs are directly used by libc functions like `read` and `write`."  **Correction:** Realized that while `read` and `write` might be involved at a lower level, the primary interaction for device control is more likely to be `ioctl`.
* **Initial thought:** "Focus on explaining the C syntax of the header." **Correction:** Shifted focus to the *purpose* and *functionality* of the definitions, and their relevance to Android.
* **Realization:**  Dynamic linking is not *directly* in the header file, but it's crucial to understand how the *code that uses this header* is linked. So, include a general explanation and example.
* **Frida Example Refinement:**  Initially considered hooking specific functions within libc, but realized hooking the `ioctl` system call is more direct for observing the interaction with the Hyper-V driver.

By following these steps and iteratively refining the explanation, the comprehensive and informative answer is generated.
这个目录 `bionic/libc/kernel/uapi/linux/hyperv.handroid` 下的 `hyperv.h` 文件是 Android Bionic C 库的一部分，它定义了用户空间程序与 Linux 内核中 Hyper-V 相关的接口。这意味着 Android 系统运行在 Hyper-V 虚拟机上时，可以通过这些定义与底层的 Hyper-V 虚拟机监控器进行交互。

**它的主要功能是定义了一系列用于 Hyper-V 虚拟机特性的数据结构和常量，这些特性包括：**

1. **卷影复制服务 (Volume Shadow Copy Service, VSS):**  允许在虚拟机内部创建一致性的备份快照。
2. **文件复制服务 (File Copy Service, FCOPY):**  允许在虚拟机和宿主机之间进行文件复制操作。
3. **键值对交换服务 (Key-Value Pair Exchange, KVP):**  允许虚拟机和宿主机之间交换配置信息和其他数据。

**与 Android 功能的关系及举例说明：**

当 Android 系统作为 Hyper-V 的客户操作系统运行时，这些定义使得 Android 能够利用 Hyper-V 提供的特定功能。

* **卷影复制服务 (VSS):**  Android 可能会利用 VSS 来实现虚拟机的备份和恢复功能。例如，在 Hyper-V 管理器中对运行 Android 的虚拟机进行备份时，Hyper-V 可能会触发虚拟机内部的 VSS 机制，Android 系统可以使用 `hv_vss_hdr` 和相关的结构体来响应这些操作，例如执行冻结文件系统 (`VSS_OP_FREEZE`) 和解冻文件系统 (`VSS_OP_THAW`) 的操作，以确保备份的一致性。

* **文件复制服务 (FCOPY):**  虽然 Android 用户不太可能直接使用这些接口进行文件复制，但在某些特定的场景下，例如虚拟机管理工具或者一些底层系统服务，可能会使用 FCOPY 在 Android 虚拟机和 Hyper-V 宿主机之间传输文件。例如，虚拟机管理工具可能使用 `hv_start_fcopy` 结构体来启动文件复制，并使用 `hv_do_fcopy` 结构体来传输文件数据。

* **键值对交换服务 (KVP):**  这是与 Android 功能最密切相关的部分。Hyper-V 可以通过 KVP 服务向虚拟机传递一些配置信息，例如网络配置、主机名等。Android 系统可以使用 `hv_kvp_hdr` 和相关的结构体来获取这些信息。
    * **举例：获取 IP 地址信息。** Hyper-V 宿主机可以设置虚拟机的 IP 地址等网络信息，并通过 KVP 服务传递给虚拟机。Android 内部的网络管理服务可能会使用这里的定义，通过系统调用与内核交互，读取 `hv_kvp_ipaddr_value` 结构体中的信息，从而获取到分配给虚拟机的 IP 地址、子网掩码、网关等。

**详细解释每一个 libc 函数的功能是如何实现的:**

**重要提示：** `hyperv.h` 文件本身 **不是** libc 函数的实现，它只是定义了数据结构和常量。真正的实现是在 Linux 内核的 Hyper-V 驱动程序中。用户空间的程序（包括 Android 的系统服务）会使用这些定义构建数据，然后通过 **系统调用 (system call)**  与内核的 Hyper-V 驱动进行通信。

例如，要使用 KVP 服务获取一个键的值，Android 的代码可能会执行以下步骤：

1. **构建 `hv_kvp_msg` 结构体：**  根据要执行的操作（`KVP_OP_GET`）、要查询的键的名称等信息，填充 `hv_kvp_hdr` 和 `hv_kvp_msg_get` 结构体。
2. **执行系统调用：**  调用一个适当的系统调用，例如 `ioctl`，并将构建好的 `hv_kvp_msg` 结构体传递给内核的 Hyper-V 驱动。系统调用的编号和具体的调用方式取决于内核的实现。
3. **内核处理：**  内核的 Hyper-V 驱动程序接收到 `ioctl` 调用后，解析 `hv_kvp_msg` 结构体，执行相应的操作（例如从 Hyper-V 的 KVP 存储中读取值），并将结果写回 `hv_kvp_msg` 结构体。
4. **返回用户空间：**  系统调用返回，用户空间的程序可以从 `hv_kvp_msg` 结构体中读取到结果。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`hyperv.h` 文件本身并不直接涉及到 dynamic linker。它定义的是内核接口，而不是用户空间的动态链接库。然而，使用这些定义的 Android 系统服务或应用程序可能会被编译成动态链接库 (`.so` 文件)。

**`.so` 布局样本：**

```
libhyperv_client.so:
    .text          # 包含可执行代码
        - function_to_use_hyperv_api
    .rodata        # 包含只读数据
        - some_constants
    .data          # 包含可读写数据
        - some_variables
    .bss           # 包含未初始化的数据
    .dynsym        # 动态符号表
        - _sys_ioctl (假设使用了 ioctl 系统调用)
    .dynstr        # 动态字符串表
        - "ioctl"
    .rel.dyn       # 动态重定位表
        - 重定位 _sys_ioctl 的地址
    .plt           # 程序链接表（Procedure Linkage Table）
        - _sys_ioctl 的 PLT 条目
```

**链接的处理过程：**

1. **编译时：** 当 `libhyperv_client.so` 被编译时，如果它调用了需要与内核交互的函数（最终会使用到 `ioctl` 等系统调用），编译器会在其动态符号表中记录对这些外部符号的引用（例如 `_sys_ioctl`）。
2. **加载时：** 当 Android 系统加载 `libhyperv_client.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责解析其依赖关系。
3. **符号查找：** 对于 `libhyperv_client.so` 中引用的外部符号（例如 `_sys_ioctl`），dynamic linker 会在系统提供的共享库 (`.so` 文件) 中查找这些符号的定义。`ioctl` 系统调用通常是通过 `libc.so` 提供的包装函数来访问的。
4. **重定位：**  Dynamic linker 会根据重定位表 `.rel.dyn` 中的信息，修改 `libhyperv_client.so` 中对外部符号的引用，将其指向 `libc.so` 中 `ioctl` 函数的实际地址。
5. **PLT 条目：**  程序链接表 (PLT) 用于延迟绑定。第一次调用 `ioctl` 时，会跳转到 PLT 中的一个桩代码，该桩代码会调用 dynamic linker 来解析符号并更新 GOT (Global Offset Table)。后续调用将直接跳转到 GOT 中已解析的地址。

**假设输入与输出 (针对 KVP 服务)：**

**假设输入：**

* **操作:** `KVP_OP_GET` (获取键值对)
* **池:** `KVP_POOL_GUEST` (访客池)
* **键:** "MyCustomKey" (要查询的键)

**预期输出 (成功情况)：**

* **返回状态:** `HV_S_OK` (0x00000000)
* **值类型:** `REG_SZ` (字符串)
* **值大小:**  例如 10 (字节)
* **值:** "MyValue" (对应的值)

**预期输出 (失败情况，键不存在)：**

* **返回状态:**  可能返回一个错误码，例如 `HV_GUID_NOTFOUND` (0x80041002)
* **错误信息:** (在 `hv_kvp_msg` 结构体的 `error` 字段中)

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **缓冲区溢出：**  在设置或获取键值对时，如果提供的缓冲区大小不足以容纳键或值，可能导致缓冲区溢出。
   ```c
   struct hv_kvp_msg msg;
   memset(&msg, 0, sizeof(msg));
   msg.kvp_hdr.operation = KVP_OP_GET;
   strcpy(msg.body.kvp_get.data.key, "VeryLongKeyNameThatExceedsTheBufferSize"); // 潜在的缓冲区溢出
   // ... 执行 ioctl ...
   ```

2. **错误的操作码：**  使用了错误的 `operation` 值，导致内核执行了非预期的操作。
   ```c
   struct hv_kvp_msg msg;
   msg.kvp_hdr.operation = 999; // 无效的操作码
   // ... 执行 ioctl ...
   ```

3. **未初始化结构体：**  忘记初始化结构体中的某些重要字段，导致传递给内核的数据不完整或不正确。
   ```c
   struct hv_kvp_msg msg;
   // 忘记设置 msg.kvp_hdr.operation
   strcpy(msg.body.kvp_get.data.key, "MyKey");
   // ... 执行 ioctl ...
   ```

4. **大小端问题：**  如果虚拟机和宿主机的大小端序不同，且没有正确处理，可能会导致数据解析错误。虽然这里的结构体使用了 `__u32` 等类型，但在某些跨平台场景下仍然需要注意。

5. **不正确的 `ioctl` 请求码：**  `ioctl` 系统调用需要一个特定的请求码来指定要执行的操作。如果使用了错误的请求码，内核将无法识别要执行的 Hyper-V 操作。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 层：**  用户在 Android 系统中执行某些操作，例如获取网络信息或进行虚拟机相关的设置，可能会触发 Framework 层的代码。例如，`ConnectivityService` 或 `Settings` 应用可能会请求某些信息。

2. **System Services (Java/Kotlin)：** Framework 层的请求通常会传递到 System Services，这些服务通常用 Java 或 Kotlin 编写。例如，`ConnectivityService` 会处理网络相关的请求。

3. **Native Code (C/C++) 通过 JNI：**  System Services 可能需要调用 Native 代码来执行底层操作。这通常通过 Java Native Interface (JNI) 完成。例如，`ConnectivityService` 可能会调用一个 Native 方法来获取底层的网络配置信息。

4. **NDK 接口：**  Native 代码通常使用 NDK 提供的 API 来访问系统功能。为了与 Hyper-V 交互，Native 代码可能会直接使用标准的 Linux 系统调用接口，例如 `ioctl`。

5. **Bionic libc：**  NDK 提供的 C 库（Bionic libc）实现了诸如 `ioctl` 等系统调用的包装函数。Native 代码调用 `ioctl` 函数时，实际上是调用了 Bionic libc 中的实现。

6. **Kernel 系统调用接口：**  Bionic libc 中的 `ioctl` 函数最终会发起一个系统调用，陷入到 Linux 内核。

7. **Hyper-V 驱动程序：**  Linux 内核接收到 `ioctl` 系统调用后，会根据请求码将其路由到相应的设备驱动程序。对于与 Hyper-V 相关的操作，请求会被发送到 Hyper-V 驱动程序。

8. **`hyperv.h` 定义的使用：**  在内核的 Hyper-V 驱动程序中，会使用 `hyperv.h` 中定义的数据结构来解析用户空间传递过来的数据，并执行相应的 Hyper-V 操作。

**Frida Hook 示例：**

以下是一个使用 Frida Hook `ioctl` 系统调用的示例，可以用来观察 Android 系统与 Hyper-V 驱动的交互：

```javascript
// hook ioctl 系统调用
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();
    const argp = args[2];

    console.log("ioctl called");
    console.log("  fd:", fd);
    console.log("  request:", request, " (0x" + request.toString(16) + ")");

    // 可以根据 fd 和 request 的值来判断是否是与 Hyper-V 相关的 ioctl 调用
    // Hyper-V 相关的 request 值需要根据内核驱动的实现来确定

    // 尝试读取 argp 指向的数据，需要知道具体的结构体类型和大小
    // 这里假设是 hv_kvp_msg 结构体
    if (request === /* 假设的 Hyper-V KVP 操作请求码 */ 0xC0184801) {
      const hv_kvp_msg_ptr = argp;
      const operation = hv_kvp_msg_ptr.readU8();
      const pool = hv_kvp_msg_ptr.add(1).readU8();
      console.log("  Hyper-V KVP operation:", operation);
      console.log("  Hyper-V KVP pool:", pool);

      // 进一步解析 hv_kvp_msg 结构体的其他部分
    }
  },
  onLeave: function (retval) {
    console.log("ioctl returned:", retval);
  }
});
```

**解释 Frida Hook 示例：**

1. **`Interceptor.attach(Module.findExportByName(null, "ioctl"), ...)`:**  这行代码使用 Frida 的 `Interceptor` API 来拦截 `ioctl` 系统调用。`Module.findExportByName(null, "ioctl")` 查找名为 "ioctl" 的导出函数，在用户空间，这通常是 Bionic libc 提供的 `ioctl` 包装函数。
2. **`onEnter: function (args)`:**  当 `ioctl` 函数被调用时，`onEnter` 函数会被执行。`args` 参数是一个数组，包含了 `ioctl` 函数的参数：文件描述符 `fd`，请求码 `request`，以及指向参数结构的指针 `argp`。
3. **打印参数：**  代码打印了 `ioctl` 调用的文件描述符和请求码。
4. **判断 Hyper-V 相关调用：**  通过检查 `request` 的值，可以尝试判断是否是与 Hyper-V 相关的 `ioctl` 调用。**注意：这里需要根据实际的内核 Hyper-V 驱动的实现来确定 Hyper-V 相关的 `ioctl` 请求码。**
5. **解析 `hv_kvp_msg`：**  如果判断是 Hyper-V KVP 相关的调用，代码尝试将 `argp` 解释为指向 `hv_kvp_msg` 结构体的指针，并读取其中的 `operation` 和 `pool` 字段。你需要知道 `hv_kvp_msg` 结构体的布局才能正确解析数据。
6. **`onLeave: function (retval)`:**  当 `ioctl` 函数执行完毕返回时，`onLeave` 函数会被执行，这里打印了 `ioctl` 的返回值。

通过运行这个 Frida 脚本，你可以在 Android 设备上观察到 `ioctl` 系统调用的发生，并尝试解码与 Hyper-V 相关的交互数据，从而理解 Android Framework 如何逐步到达这个底层的内核接口。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/hyperv.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_HYPERV_H
#define _UAPI_HYPERV_H
#include <linux/types.h>
#define UTIL_FW_MINOR 0
#define UTIL_WS2K8_FW_MAJOR 1
#define UTIL_WS2K8_FW_VERSION (UTIL_WS2K8_FW_MAJOR << 16 | UTIL_FW_MINOR)
#define UTIL_FW_MAJOR 3
#define UTIL_FW_VERSION (UTIL_FW_MAJOR << 16 | UTIL_FW_MINOR)
#define VSS_OP_REGISTER 128
#define VSS_OP_REGISTER1 129
enum hv_vss_op {
  VSS_OP_CREATE = 0,
  VSS_OP_DELETE,
  VSS_OP_HOT_BACKUP,
  VSS_OP_GET_DM_INFO,
  VSS_OP_BU_COMPLETE,
  VSS_OP_FREEZE,
  VSS_OP_THAW,
  VSS_OP_AUTO_RECOVER,
  VSS_OP_COUNT
};
struct hv_vss_hdr {
  __u8 operation;
  __u8 reserved[7];
} __attribute__((packed));
#define VSS_HBU_NO_AUTO_RECOVERY 0x00000005
struct hv_vss_check_feature {
  __u32 flags;
} __attribute__((packed));
struct hv_vss_check_dm_info {
  __u32 flags;
} __attribute__((packed));
struct hv_vss_msg {
  union {
    struct hv_vss_hdr vss_hdr;
    int error;
  };
  union {
    struct hv_vss_check_feature vss_cf;
    struct hv_vss_check_dm_info dm_info;
  };
} __attribute__((packed));
#define FCOPY_VERSION_0 0
#define FCOPY_VERSION_1 1
#define FCOPY_CURRENT_VERSION FCOPY_VERSION_1
#define W_MAX_PATH 260
enum hv_fcopy_op {
  START_FILE_COPY = 0,
  WRITE_TO_FILE,
  COMPLETE_FCOPY,
  CANCEL_FCOPY,
};
struct hv_fcopy_hdr {
  __u32 operation;
  __u8 service_id0[16];
  __u8 service_id1[16];
} __attribute__((packed));
#define OVER_WRITE 0x1
#define CREATE_PATH 0x2
struct hv_start_fcopy {
  struct hv_fcopy_hdr hdr;
  __u16 file_name[W_MAX_PATH];
  __u16 path_name[W_MAX_PATH];
  __u32 copy_flags;
  __u64 file_size;
} __attribute__((packed));
#define DATA_FRAGMENT (6 * 1024)
struct hv_do_fcopy {
  struct hv_fcopy_hdr hdr;
  __u32 pad;
  __u64 offset;
  __u32 size;
  __u8 data[DATA_FRAGMENT];
} __attribute__((packed));
#define HV_KVP_EXCHANGE_MAX_VALUE_SIZE (2048)
#define HV_KVP_EXCHANGE_MAX_KEY_SIZE (512)
#define REG_SZ 1
#define REG_U32 4
#define REG_U64 8
#define KVP_OP_REGISTER 4
#define KVP_OP_REGISTER1 100
enum hv_kvp_exchg_op {
  KVP_OP_GET = 0,
  KVP_OP_SET,
  KVP_OP_DELETE,
  KVP_OP_ENUMERATE,
  KVP_OP_GET_IP_INFO,
  KVP_OP_SET_IP_INFO,
  KVP_OP_COUNT
};
enum hv_kvp_exchg_pool {
  KVP_POOL_EXTERNAL = 0,
  KVP_POOL_GUEST,
  KVP_POOL_AUTO,
  KVP_POOL_AUTO_EXTERNAL,
  KVP_POOL_AUTO_INTERNAL,
  KVP_POOL_COUNT
};
#define HV_S_OK 0x00000000
#define HV_E_FAIL 0x80004005
#define HV_S_CONT 0x80070103
#define HV_ERROR_NOT_SUPPORTED 0x80070032
#define HV_ERROR_MACHINE_LOCKED 0x800704F7
#define HV_ERROR_DEVICE_NOT_CONNECTED 0x8007048F
#define HV_INVALIDARG 0x80070057
#define HV_GUID_NOTFOUND 0x80041002
#define HV_ERROR_ALREADY_EXISTS 0x80070050
#define HV_ERROR_DISK_FULL 0x80070070
#define ADDR_FAMILY_NONE 0x00
#define ADDR_FAMILY_IPV4 0x01
#define ADDR_FAMILY_IPV6 0x02
#define MAX_ADAPTER_ID_SIZE 128
#define MAX_IP_ADDR_SIZE 1024
#define MAX_GATEWAY_SIZE 512
struct hv_kvp_ipaddr_value {
  __u16 adapter_id[MAX_ADAPTER_ID_SIZE];
  __u8 addr_family;
  __u8 dhcp_enabled;
  __u16 ip_addr[MAX_IP_ADDR_SIZE];
  __u16 sub_net[MAX_IP_ADDR_SIZE];
  __u16 gate_way[MAX_GATEWAY_SIZE];
  __u16 dns_addr[MAX_IP_ADDR_SIZE];
} __attribute__((packed));
struct hv_kvp_hdr {
  __u8 operation;
  __u8 pool;
  __u16 pad;
} __attribute__((packed));
struct hv_kvp_exchg_msg_value {
  __u32 value_type;
  __u32 key_size;
  __u32 value_size;
  __u8 key[HV_KVP_EXCHANGE_MAX_KEY_SIZE];
  union {
    __u8 value[HV_KVP_EXCHANGE_MAX_VALUE_SIZE];
    __u32 value_u32;
    __u64 value_u64;
  };
} __attribute__((packed));
struct hv_kvp_msg_enumerate {
  __u32 index;
  struct hv_kvp_exchg_msg_value data;
} __attribute__((packed));
struct hv_kvp_msg_get {
  struct hv_kvp_exchg_msg_value data;
};
struct hv_kvp_msg_set {
  struct hv_kvp_exchg_msg_value data;
};
struct hv_kvp_msg_delete {
  __u32 key_size;
  __u8 key[HV_KVP_EXCHANGE_MAX_KEY_SIZE];
};
struct hv_kvp_register {
  __u8 version[HV_KVP_EXCHANGE_MAX_KEY_SIZE];
};
struct hv_kvp_msg {
  union {
    struct hv_kvp_hdr kvp_hdr;
    int error;
  };
  union {
    struct hv_kvp_msg_get kvp_get;
    struct hv_kvp_msg_set kvp_set;
    struct hv_kvp_msg_delete kvp_delete;
    struct hv_kvp_msg_enumerate kvp_enum_data;
    struct hv_kvp_ipaddr_value kvp_ip_val;
    struct hv_kvp_register kvp_register;
  } body;
} __attribute__((packed));
struct hv_kvp_ip_msg {
  __u8 operation;
  __u8 pool;
  struct hv_kvp_ipaddr_value kvp_ip_val;
} __attribute__((packed));
#endif

"""

```