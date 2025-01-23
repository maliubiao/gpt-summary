Response:
Let's break down the thought process for analyzing this header file and generating the response.

**1. Initial Understanding of the File:**

* **File Path:** `bionic/libc/kernel/uapi/linux/dm-ioctl.h` immediately tells me this is an auto-generated header file within Android's Bionic library. It interacts with the Linux kernel's Device Mapper subsystem (hence `dm-ioctl`). The `uapi` suggests it's part of the user-kernel interface.
* **Auto-generated:**  The comment at the top is crucial. It warns against manual modification. This means the content directly reflects the kernel's Device Mapper ioctl interface at a specific point in time.
* **Purpose:**  The file defines structures, constants, and macros needed for user-space programs to communicate with the Device Mapper driver in the Linux kernel. This driver is essential for logical volume management.

**2. Deconstructing the Contents (Iterative Process):**

I'll go through the file section by section, understanding the purpose of each element.

* **Includes:** `#include <linux/types.h>`: Standard Linux type definitions (like `__u32`, `__u64`). Not Bionic-specific.
* **Defines:**
    * `DM_DIR`, `DM_CONTROL_NODE`:  These suggest paths within the `/dev` filesystem related to Device Mapper.
    * `DM_MAX_TYPE_NAME`, `DM_NAME_LEN`, `DM_UUID_LEN`: Size limits for strings used by Device Mapper.
* **Structures:** This is the core of the file. I'll analyze each structure:
    * `dm_ioctl`: The main structure for `ioctl` calls. It contains version info, data size/start, target counts, flags, device numbers, names, and a data buffer. I'll note the `data` member's small size – likely just a header or metadata.
    * `dm_target_spec`:  Describes a single target within a mapped device (start sector, length, status, target type).
    * `dm_target_deps`: Represents dependencies of a target (on underlying devices).
    * `dm_name_list`: Used for listing existing Device Mapper devices.
    * `dm_target_versions`:  Information about the versions supported by a target type.
    * `dm_target_msg`:  For sending messages to a target.
* **Enums:** The `enum` defines the different `ioctl` commands that can be sent to the Device Mapper driver. I'll list them and understand their general purpose (create, remove, suspend, etc.).
* **Macros (`#define` for ioctls):** These macros define the specific `ioctl` numbers using the `_IOWR` macro. They link the `DM_IOCTL` magic number and the specific command enum to the `dm_ioctl` structure. This is how user-space programs initiate specific Device Mapper operations.
* **Version Defines:**  `DM_VERSION_MAJOR`, `DM_VERSION_MINOR`, etc., provide version information for the Device Mapper interface.
* **Flag Defines:**  A series of bit flags used within the `dm_ioctl` structure to specify options or indicate status.

**3. Connecting to Android:**

* **Core Functionality:** Device Mapper is fundamental to Android's storage management. Logical volumes, encryption (like File-Based Encryption), and possibly snapshotting rely on it.
* **Examples:** I'll think of concrete examples:
    * Creating an encrypted partition.
    * Resizing a logical volume.
    * How Android might use these commands during boot or when the user interacts with storage settings.

**4. Libc Function Explanation (Not Applicable Here):**

The prompt asked for explanations of libc functions. However, this file *doesn't define or implement* libc functions. It's a header file defining data structures and constants. The *use* of these structures involves libc functions like `open`, `ioctl`, and `close`, but the header itself doesn't implement them. I need to clarify this distinction.

**5. Dynamic Linker (Also Not Directly Applicable):**

Similarly, this header file isn't directly involved in the dynamic linking process. It defines the *interface* to a kernel module, not a shared library. I'll explain why this aspect of the prompt doesn't apply.

**6. Logical Reasoning and Examples:**

While the file itself isn't a program with logic, I can create hypothetical scenarios of how these structures might be used. For instance, creating a simple mapped device with one target.

**7. User Errors:**

I'll consider common mistakes when working with `ioctl` calls, such as incorrect structure sizes, invalid command codes, or insufficient permissions.

**8. Android Framework and NDK Path:**

I'll trace how an Android app might indirectly trigger Device Mapper operations:
    * User interacts with storage settings in the UI.
    * Framework components (like `vold`) make system calls.
    * These system calls involve `ioctl` with the defined structures.
    * NDK developers might use lower-level APIs that eventually lead to these calls.

**9. Frida Hooking:**

I'll provide examples of how to use Frida to intercept `ioctl` calls related to Device Mapper, focusing on the file descriptor and the `ioctl` command.

**10. Structuring the Response:**

Finally, I'll organize the information logically with clear headings and examples, ensuring all aspects of the prompt are addressed, even if it means explaining why certain parts don't directly apply. I'll use Chinese as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is about libc functions."  **Correction:** No, it's a header file for kernel interaction, not defining libc functions themselves.
* **Initial thought:** "How does the dynamic linker fit in?" **Correction:** This header defines the *interface* to the kernel; the dynamic linker deals with shared libraries in user space. They're related in the broader system but not directly in this file.
* **Ensuring Clarity:** Make sure to explicitly state when a part of the prompt doesn't directly apply to the file's content. Don't just ignore it.

By following this structured and iterative approach, I can analyze the header file effectively and generate a comprehensive and accurate response.
这是一个定义 Linux Device Mapper (DM) 子系统的用户空间接口的头文件。Device Mapper 是 Linux 内核中一个灵活的框架，用于创建逻辑块设备。这个头文件定义了用户空间程序与 Device Mapper 驱动程序进行交互所需的结构体、常量和宏。 由于它位于 `bionic/libc/kernel/uapi/linux` 目录下，这意味着它是 Android Bionic C 库的一部分，用于提供与 Linux 内核的兼容性接口。

**它的功能：**

这个头文件定义了与 Linux Device Mapper 交互所需的：

1. **数据结构 (Structures):**
   - `dm_ioctl`:  这是与 Device Mapper 驱动程序进行 ioctl 通信的主要结构体。它包含版本信息、数据大小、命令类型、设备名称、UUID、目标数量以及用于传输数据的缓冲区。
   - `dm_target_spec`: 定义了映射设备中一个目标的信息，包括起始扇区、长度、状态、下一个目标的偏移以及目标类型名称。
   - `dm_target_deps`: 描述了目标的依赖关系，例如它依赖的底层块设备。
   - `dm_name_list`: 用于列出 Device Mapper 设备及其对应的设备号。
   - `dm_target_versions`:  列出特定目标类型支持的版本。
   - `dm_target_msg`: 用于向目标发送消息。

2. **常量 (Defines):**
   - `DM_DIR`:  定义 Device Mapper 设备节点所在的目录（通常是 "mapper"）。
   - `DM_CONTROL_NODE`: 定义 Device Mapper 控制节点的名称（通常是 "control"）。
   - `DM_MAX_TYPE_NAME`, `DM_NAME_LEN`, `DM_UUID_LEN`: 定义了各种字符串的最大长度。
   - 一系列以 `DM_` 开头的枚举值，定义了不同的 Device Mapper ioctl 命令，例如 `DM_VERSION_CMD` (获取版本)、`DM_DEV_CREATE_CMD` (创建设备)、`DM_TABLE_LOAD_CMD` (加载表) 等。
   - 一系列以 `DM_` 开头的宏，定义了用于执行各种 Device Mapper 操作的 ioctl 请求，例如 `DM_VERSION`、`DM_DEV_CREATE` 等。这些宏使用 `_IOWR` 将 `DM_IOCTL` 魔数与具体的命令码和数据结构关联起来。
   - `DM_VERSION_MAJOR`, `DM_VERSION_MINOR`, `DM_VERSION_PATCHLEVEL`, `DM_VERSION_EXTRA`: 定义了 Device Mapper 接口的版本信息。
   - 一系列以 `DM_` 开头的标志位，用于在 `dm_ioctl` 结构体中设置或获取状态，例如 `DM_READONLY_FLAG` (只读)、`DM_SUSPEND_FLAG` (挂起) 等。

**与 Android 功能的关系及举例说明：**

Device Mapper 是 Android 存储管理的核心组件之一。许多 Android 的关键功能都依赖于 Device Mapper，例如：

1. **逻辑卷管理 (LVM):**  虽然 Android 默认不使用传统的 LVM，但 Device Mapper 提供了类似的功能，允许将多个物理分区组合成一个逻辑卷，并进行灵活的管理。例如，`/data` 分区可能就是一个基于 Device Mapper 的逻辑卷。

   **例子:**  在 Android 中，`/data` 分区通常会使用 Device Mapper 来实现文件系统级别的加密 (File-Based Encryption, FBE) 或基于块的加密 (Full-Disk Encryption, FDE)。Device Mapper 的 `crypt` 目标用于执行加密和解密操作。

2. **设备加密 (Encryption):** Android 的文件系统加密机制广泛使用 Device Mapper。`crypt` 目标用于在底层块设备上实现透明的加密和解密。

   **例子:** 当你在 Android 设备上启用屏幕锁并选择加密设备时，Android 会使用 Device Mapper 的 `crypt` 目标来创建一个加密的逻辑设备，并将 `/data` 分区映射到这个加密设备上。

3. **合成文件系统 (Synthetic Filesystem):**  某些 Android 功能可能会使用 Device Mapper 创建临时的、虚拟的块设备。

   **例子:**  Android 的 A/B 系统更新可能会使用 Device Mapper 来创建当前系统和新系统的快照，以便在更新失败时可以回滚到旧系统。

4. **容器化 (Containerization):**  某些 Android 环境下，例如工作资料 (Work Profile)，可能会使用 Device Mapper 来隔离不同的用户空间。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个头文件本身**没有定义或实现任何 libc 函数**。它只是定义了数据结构和常量，用于与 Linux 内核的 Device Mapper 驱动程序进行交互。用户空间的程序需要使用标准的 libc 函数，例如 `open()`, `ioctl()`, `close()` 等，来与 `/dev/mapper/control` 节点进行通信，并使用这里定义的结构体来构造 `ioctl` 请求。

* **`open()`:**  用于打开 `/dev/mapper/control` 设备节点。这是一个字符设备，是与 Device Mapper 驱动程序通信的入口点。
* **`ioctl()`:**  用于向 Device Mapper 驱动程序发送命令。程序会填充 `dm_ioctl` 结构体，指定要执行的操作（通过设置 `version` 和 `data_size` 等字段），并将指向该结构体的指针作为 `ioctl()` 的参数传递给内核。
* **`close()`:**  用于关闭 `/dev/mapper/control` 设备节点。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个头文件与 dynamic linker (动态链接器) **没有直接关系**。Dynamic linker (通常是 `linker64` 或 `linker`) 负责加载和链接共享库 (`.so` 文件)。这个头文件定义的是内核接口，而不是用户空间的共享库接口。

虽然用户空间程序（例如 Android 的 `vold` 守护进程）可能会使用包含这个头文件的代码，并且这些程序本身是被动态链接的，但这个头文件本身不涉及动态链接的过程。

**如果做了逻辑推理，请给出假设输入与输出：**

假设我们想创建一个名为 "my_volume"，大小为 10MB 的线性映射设备，它映射到 `/dev/sdb1` 的起始扇区。

**假设输入 (构造 `dm_ioctl` 结构体):**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/dm-ioctl.h>
#include <errno.h>
#include <string.h>

int main() {
    int fd;
    struct dm_ioctl dio;
    struct dm_target_spec *dts;
    char data_buf[1024]; // 足够大的缓冲区

    // 打开控制节点
    fd = open("/dev/mapper/control", O_RDWR);
    if (fd < 0) {
        perror("open /dev/mapper/control");
        return 1;
    }

    // 初始化 dm_ioctl 结构体，用于创建设备
    memset(&dio, 0, sizeof(dio));
    dio.version[0] = DM_VERSION_MAJOR;
    dio.version[1] = DM_VERSION_MINOR;
    dio.version[2] = DM_VERSION_PATCHLEVEL;
    dio.data_size = sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec) + strlen("linear 0 2048 /dev/sdb1 0") + 1; // 假设扇区大小为 512 字节，10MB = 2048 个扇区
    dio.data_start = sizeof(struct dm_ioctl);
    dio.target_count = 1;
    strcpy(dio.name, "my_volume");

    // 构造 target spec
    dts = (struct dm_target_spec *)(data_buf + sizeof(struct dm_ioctl));
    dts->sector_start = 0;
    dts->length = 2048; // 10MB
    strcpy(dts->target_type, "linear");
    dts->next = 0;

    // 构造 target 参数字符串
    char *params = data_buf + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    strcpy(params, "0 2048 /dev/sdb1 0");

    // 发送 DM_DEV_CREATE 命令
    if (ioctl(fd, DM_DEV_CREATE, &dio)) {
        perror("ioctl DM_DEV_CREATE");
        close(fd);
        return 1;
    }

    printf("Device 'my_volume' created successfully.\n");

    close(fd);
    return 0;
}
```

**假设输出：**

如果操作成功，会在 `/dev/mapper` 目录下创建一个名为 `my_volume` 的设备节点。你可以像访问普通块设备一样访问它。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **`ioctl` 参数错误:**  传递给 `ioctl()` 的 `dm_ioctl` 结构体没有正确初始化，例如 `version` 字段不匹配内核版本，或者 `data_size` 计算错误，导致数据溢出或不足。

   ```c
   // 错误示例：data_size 计算错误
   dio.data_size = sizeof(struct dm_ioctl); // 缺少 target spec 和参数字符串的大小
   if (ioctl(fd, DM_TABLE_LOAD, &dio)) { // 尝试加载表会失败
       perror("ioctl DM_TABLE_LOAD");
   }
   ```

2. **权限不足:**  尝试执行需要 root 权限的 Device Mapper 操作，例如创建或删除设备，但程序没有以 root 用户身份运行。

   ```bash
   ./my_dm_program  # 如果没有 root 权限，可能会失败并提示权限错误
   ```

3. **设备名冲突:**  尝试创建一个已存在的设备名称。

   ```c
   strcpy(dio.name, "my_volume");
   // ... 创建 'my_volume' ...
   // 再次尝试创建同名设备
   if (ioctl(fd, DM_DEV_CREATE, &dio)) {
       perror("ioctl DM_DEV_CREATE"); // 可能会提示设备已存在
   }
   ```

4. **目标参数错误:**  在加载表时，提供的目标类型或参数不正确，导致内核无法解析或执行。

   ```c
   // 错误示例：linear 目标的参数错误，缺少起始扇区
   strcpy(params, "2048 /dev/sdb1");
   if (ioctl(fd, DM_TABLE_LOAD, &dio)) {
       perror("ioctl DM_TABLE_LOAD"); // 内核可能报告参数错误
   }
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android 应用程序不会直接调用 Device Mapper 的 ioctl 接口。相反，Android Framework 会通过底层的 C++ 守护进程（例如 `vold` - Volume Daemon）来管理存储相关的操作。

**Android Framework 到 Device Mapper 的步骤：**

1. **Android Framework (Java/Kotlin):** 用户在设置中或通过应用进行存储相关的操作（例如格式化 SD 卡，启用文件加密）。这些操作会触发 Framework 层的 API 调用。
2. **System Server:** Framework 的请求通常会传递给 System Server 中的组件，例如 `StorageManagerService`。
3. **Native Daemons (C++):** `StorageManagerService` 会通过 Binder IPC 与底层的 C++ 守护进程 `vold` 进行通信。
4. **`vold` (Volume Daemon):** `vold` 负责执行实际的存储管理操作。它会解析 Framework 的请求，并调用相应的 Device Mapper ioctl 接口来创建、删除、修改逻辑卷或管理加密设备。
5. **Kernel Driver (Device Mapper):** `vold` 通过 `open("/dev/mapper/control", ...)` 打开 Device Mapper 控制节点，然后使用 `ioctl()` 系统调用，并传递填充好的 `dm_ioctl` 结构体来与 Device Mapper 驱动程序进行交互。

**NDK 到 Device Mapper 的步骤：**

使用 NDK 开发的应用程序理论上可以直接调用与 Device Mapper 交互的系统调用，但这通常是不推荐的，因为它需要 `CAP_SYS_ADMIN` 权限，并且绕过了 Android Framework 的管理。在极少数需要直接操作的情况下，NDK 代码可以：

1. **直接调用 `open()` 和 `ioctl()`:**  使用 NDK 提供的标准 C 库函数 `open()` 打开 `/dev/mapper/control`，然后使用 `ioctl()` 并填充 `dm_ioctl` 结构体。

**Frida Hook 示例：**

可以使用 Frida 来 hook `ioctl` 系统调用，并检查传递给 Device Mapper 的参数。

```python
import frida
import sys

# 要 hook 的进程名称
package_name = "com.android.vold"  # 或者你想要调试的进程

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the process is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "ioctl"), {
    onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const buf = args[2];

        // 检查是否是与 Device Mapper 相关的 ioctl 调用
        if (fd > 0) {
            const path = readlink("/proc/self/fd/" + fd);
            if (path && path.startsWith("/dev/mapper/control")) {
                console.log("[*] ioctl called on /dev/mapper/control");
                console.log("    fd:", fd);
                console.log("    request:", request, "(0x" + request.toString(16) + ")");

                // 可以进一步解析 buf 指向的 dm_ioctl 结构体
                if (request === 0xfd) { // DM_IOCTL 魔数
                    const dm_ioctl_struct = Memory.readByteArray(buf, 100); // 读取部分结构体
                    console.log("    dm_ioctl struct (partial):", hexdump(dm_ioctl_struct, { length: 100 }));
                    // 可以根据 request 的具体值来解析不同的数据结构
                }
            }
        }
    },
    onLeave: function (retval) {
        // console.log("ioctl returned:", retval);
    }
});

function readlink(path) {
    try {
        const readlinkPtr = Module.findExportByName(null, "readlink");
        const readlinkFunc = new NativeFunction(readlinkPtr, 'int', ['pointer', 'pointer', 'size_t']);
        const buffer = Memory.alloc(256);
        const result = readlinkFunc(Memory.allocUtf8String(path), buffer, 256);
        if (result > 0) {
            return Memory.readUtf8String(buffer, result);
        }
        return null;
    } catch (e) {
        return null;
    }
}
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个 Frida 脚本会 hook `ioctl` 系统调用，并检查文件描述符是否指向 `/dev/mapper/control`。如果是，它会打印出 `ioctl` 的请求码，并尝试读取部分 `dm_ioctl` 结构体的内容。你可以根据输出的信息来调试 Android Framework 是如何与 Device Mapper 交互的。

请注意，调试系统进程（如 `vold`）可能需要 root 权限。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/dm-ioctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_DM_IOCTL_V4_H
#define _LINUX_DM_IOCTL_V4_H
#include <linux/types.h>
#define DM_DIR "mapper"
#define DM_CONTROL_NODE "control"
#define DM_MAX_TYPE_NAME 16
#define DM_NAME_LEN 128
#define DM_UUID_LEN 129
struct dm_ioctl {
  __u32 version[3];
  __u32 data_size;
  __u32 data_start;
  __u32 target_count;
  __s32 open_count;
  __u32 flags;
  __u32 event_nr;
  __u32 padding;
  __u64 dev;
  char name[DM_NAME_LEN];
  char uuid[DM_UUID_LEN];
  char data[7];
};
struct dm_target_spec {
  __u64 sector_start;
  __u64 length;
  __s32 status;
  __u32 next;
  char target_type[DM_MAX_TYPE_NAME];
};
struct dm_target_deps {
  __u32 count;
  __u32 padding;
  __u64 dev[];
};
struct dm_name_list {
  __u64 dev;
  __u32 next;
  char name[];
};
#define DM_NAME_LIST_FLAG_HAS_UUID 1
#define DM_NAME_LIST_FLAG_DOESNT_HAVE_UUID 2
struct dm_target_versions {
  __u32 next;
  __u32 version[3];
  char name[];
};
struct dm_target_msg {
  __u64 sector;
  char message[];
};
enum {
  DM_VERSION_CMD = 0,
  DM_REMOVE_ALL_CMD,
  DM_LIST_DEVICES_CMD,
  DM_DEV_CREATE_CMD,
  DM_DEV_REMOVE_CMD,
  DM_DEV_RENAME_CMD,
  DM_DEV_SUSPEND_CMD,
  DM_DEV_STATUS_CMD,
  DM_DEV_WAIT_CMD,
  DM_TABLE_LOAD_CMD,
  DM_TABLE_CLEAR_CMD,
  DM_TABLE_DEPS_CMD,
  DM_TABLE_STATUS_CMD,
  DM_LIST_VERSIONS_CMD,
  DM_TARGET_MSG_CMD,
  DM_DEV_SET_GEOMETRY_CMD,
  DM_DEV_ARM_POLL_CMD,
  DM_GET_TARGET_VERSION_CMD,
};
#define DM_IOCTL 0xfd
#define DM_VERSION _IOWR(DM_IOCTL, DM_VERSION_CMD, struct dm_ioctl)
#define DM_REMOVE_ALL _IOWR(DM_IOCTL, DM_REMOVE_ALL_CMD, struct dm_ioctl)
#define DM_LIST_DEVICES _IOWR(DM_IOCTL, DM_LIST_DEVICES_CMD, struct dm_ioctl)
#define DM_DEV_CREATE _IOWR(DM_IOCTL, DM_DEV_CREATE_CMD, struct dm_ioctl)
#define DM_DEV_REMOVE _IOWR(DM_IOCTL, DM_DEV_REMOVE_CMD, struct dm_ioctl)
#define DM_DEV_RENAME _IOWR(DM_IOCTL, DM_DEV_RENAME_CMD, struct dm_ioctl)
#define DM_DEV_SUSPEND _IOWR(DM_IOCTL, DM_DEV_SUSPEND_CMD, struct dm_ioctl)
#define DM_DEV_STATUS _IOWR(DM_IOCTL, DM_DEV_STATUS_CMD, struct dm_ioctl)
#define DM_DEV_WAIT _IOWR(DM_IOCTL, DM_DEV_WAIT_CMD, struct dm_ioctl)
#define DM_DEV_ARM_POLL _IOWR(DM_IOCTL, DM_DEV_ARM_POLL_CMD, struct dm_ioctl)
#define DM_TABLE_LOAD _IOWR(DM_IOCTL, DM_TABLE_LOAD_CMD, struct dm_ioctl)
#define DM_TABLE_CLEAR _IOWR(DM_IOCTL, DM_TABLE_CLEAR_CMD, struct dm_ioctl)
#define DM_TABLE_DEPS _IOWR(DM_IOCTL, DM_TABLE_DEPS_CMD, struct dm_ioctl)
#define DM_TABLE_STATUS _IOWR(DM_IOCTL, DM_TABLE_STATUS_CMD, struct dm_ioctl)
#define DM_LIST_VERSIONS _IOWR(DM_IOCTL, DM_LIST_VERSIONS_CMD, struct dm_ioctl)
#define DM_GET_TARGET_VERSION _IOWR(DM_IOCTL, DM_GET_TARGET_VERSION_CMD, struct dm_ioctl)
#define DM_TARGET_MSG _IOWR(DM_IOCTL, DM_TARGET_MSG_CMD, struct dm_ioctl)
#define DM_DEV_SET_GEOMETRY _IOWR(DM_IOCTL, DM_DEV_SET_GEOMETRY_CMD, struct dm_ioctl)
#define DM_VERSION_MAJOR 4
#define DM_VERSION_MINOR 48
#define DM_VERSION_PATCHLEVEL 0
#define DM_VERSION_EXTRA "-ioctl(2023-03-01)"
#define DM_READONLY_FLAG (1 << 0)
#define DM_SUSPEND_FLAG (1 << 1)
#define DM_PERSISTENT_DEV_FLAG (1 << 3)
#define DM_STATUS_TABLE_FLAG (1 << 4)
#define DM_ACTIVE_PRESENT_FLAG (1 << 5)
#define DM_INACTIVE_PRESENT_FLAG (1 << 6)
#define DM_BUFFER_FULL_FLAG (1 << 8)
#define DM_SKIP_BDGET_FLAG (1 << 9)
#define DM_SKIP_LOCKFS_FLAG (1 << 10)
#define DM_NOFLUSH_FLAG (1 << 11)
#define DM_QUERY_INACTIVE_TABLE_FLAG (1 << 12)
#define DM_UEVENT_GENERATED_FLAG (1 << 13)
#define DM_UUID_FLAG (1 << 14)
#define DM_SECURE_DATA_FLAG (1 << 15)
#define DM_DATA_OUT_FLAG (1 << 16)
#define DM_DEFERRED_REMOVE (1 << 17)
#define DM_INTERNAL_SUSPEND_FLAG (1 << 18)
#define DM_IMA_MEASUREMENT_FLAG (1 << 19)
#endif
```