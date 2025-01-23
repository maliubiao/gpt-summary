Response:
Let's break down the thought process for answering this complex request. The initial request is to analyze a kernel header file for the Btrfs filesystem within the Android Bionic library. Here’s a step-by-step approach:

1. **Understand the Nature of the File:** Recognize that this is a *kernel* header file (indicated by `uapi/linux`). This means it defines the interface between *userspace* (like Android apps or system services) and the *kernel* (specifically the Btrfs filesystem driver). The content will primarily be data structures and ioctl definitions used for communication. This immediately tells us we won't find implementation details of libc *functions* within this file itself.

2. **Identify the Core Functionality:** The file defines structures and constants related to interacting with the Btrfs filesystem. The `#define BTRFS_IOCTL_MAGIC 0x94` strongly suggests that the primary mechanism for interaction is through `ioctl` system calls.

3. **Categorize the Functionality:**  Go through the defined structures and `ioctl` macros, grouping related concepts. Common Btrfs features should be recognizable or inferable from the names:
    * **Volume Management:** Creating/deleting subvolumes, snapshots, resizing. (`btrfs_ioctl_vol_args`, `BTRFS_IOC_SUBVOL_CREATE`, `BTRFS_IOC_SNAP_DESTROY`)
    * **Device Management:** Adding/removing devices, replacing devices, getting device info. (`btrfs_ioctl_dev_info_args`, `BTRFS_IOC_ADD_DEV`, `BTRFS_IOC_RM_DEV`, `BTRFS_IOC_DEV_REPLACE`)
    * **Quota Management:** Setting limits, assigning quotas, rescanning. (`btrfs_qgroup_limit`, `BTRFS_IOC_QUOTA_CTL`, `BTRFS_IOC_QGROUP_ASSIGN`)
    * **Data Integrity and Repair:**  Scrubbing, balancing. (`btrfs_ioctl_scrub_args`, `BTRFS_IOC_SCRUB`, `btrfs_ioctl_balance_args`, `BTRFS_IOC_BALANCE`)
    * **Sending and Receiving Subvolumes:**  Snapshot and replication features. (`btrfs_ioctl_send_args`, `BTRFS_IOC_SEND`, `btrfs_ioctl_received_subvol_args`)
    * **File System Information:** Getting overall FS information, features. (`btrfs_ioctl_fs_info_args`, `BTRFS_IOC_FS_INFO`, `btrfs_ioctl_feature_flags`, `BTRFS_IOC_GET_FEATURES`)
    * **Other Operations:**  Defragmentation, cloning, searching, space information. (`BTRFS_IOC_DEFRAG_RANGE`, `BTRFS_IOC_CLONE_RANGE`, `BTRFS_IOC_TREE_SEARCH`, `BTRFS_IOC_SPACE_INFO`)

4. **Relate to Android:** Consider how these Btrfs features might be used in Android.
    * **System Partitions:**  Android uses filesystems like ext4, F2FS, and sometimes Btrfs for system and userdata partitions. Btrfs features like snapshots can be useful for system updates and rollback mechanisms (A/B updates).
    * **Containerization/Virtualization:**  Subvolumes could be used for isolating container or virtual machine data.
    * **Storage Management:** Quotas could be relevant for managing storage usage in multi-user scenarios or for specific app data.
    * **Data Integrity:** Scrubbing helps maintain data integrity on the device.

5. **Address Specific Questions:**

    * **libc Function Implementation:** Explicitly state that this file *doesn't* contain libc function implementations. It defines the *interface* used by libc functions (like `ioctl`). Mention that the actual implementation is in the Linux kernel.

    * **Dynamic Linker:** Recognize that this header file is about kernel interfaces, not dynamic linking. State that there's no direct connection to the dynamic linker within *this specific file*. Acknowledge that libc functions *using* these ioctls will be linked by the dynamic linker, but the header itself doesn't define or use dynamic linking concepts. Therefore, the SO layout and linking process are irrelevant *to the content of this header file*. *Initially, I might have considered if any of the data structures are used in a shared library context, but a closer look reveals they are primarily for `ioctl` communication, which bypasses typical shared library linking.*

    * **Logic Inference/Assumptions:** For each `ioctl`, describe the *intended* behavior based on the struct members. For example, `BTRFS_IOC_SUBVOL_CREATE` takes a `btrfs_ioctl_vol_args` structure, which contains the subvolume name. The *assumption* is that upon successful execution, a new subvolume with that name will be created. Provide example input and expected output at a *conceptual* level (the kernel doesn't return high-level objects, just success/failure).

    * **User/Programming Errors:** Think about common mistakes when using these ioctls. Incorrect flags, invalid file descriptors, incorrect data sizes, and permission issues are common problems. Provide concrete code snippets to illustrate these errors.

    * **Android Framework/NDK to Kernel:** Outline the path. NDK uses standard Linux system calls exposed by libc. Android Framework interacts with system services, which in turn use these system calls. `ioctl` is the key system call involved here. Give a simplified example using Java's `FileDescriptor` and JNI to call `ioctl`.

    * **Frida Hooking:** Provide Frida examples that target the `ioctl` system call, filtering for the specific `BTRFS_IOCTL_MAGIC`. Explain how to examine the arguments being passed to the ioctl.

6. **Structure and Clarity:** Organize the answer logically with clear headings and bullet points. Use code formatting for constants, structures, and example code. Explain technical terms clearly. Maintain a consistent and professional tone.

7. **Review and Refine:** Read through the answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might not have been explicit enough about the difference between the header file defining the interface and the kernel implementing the functionality. Refinement would involve clarifying this crucial distinction.这个头文件 `bionic/libc/kernel/uapi/linux/btrfs.h` 定义了用户空间程序与 Linux 内核中 Btrfs 文件系统进行交互的接口。它并非 Bionic C 库或动态链接器的源代码，而是描述了 Btrfs 特定的数据结构和 ioctl 命令。因此，它不包含任何 libc 函数的实现，也不直接涉及动态链接器的功能。

让我们详细列举一下它的功能，并尽可能与 Android 的功能关联起来：

**主要功能：定义 Btrfs 文件系统的用户空间接口**

这个头文件的核心作用是定义了一系列结构体、常量和宏，用于用户空间程序通过 `ioctl` 系统调用与 Linux 内核中的 Btrfs 文件系统驱动程序进行通信。这些定义使得用户空间的程序能够执行诸如创建/删除子卷、管理快照、管理磁盘空间、进行数据校验等操作。

**具体功能分解：**

1. **魔数定义 (`BTRFS_IOCTL_MAGIC`)**:  定义了用于 Btrfs 特定 `ioctl` 命令的魔数，用于区分不同文件系统的 ioctl 调用。

2. **常量定义 (如 `BTRFS_VOL_NAME_MAX`, `BTRFS_PATH_NAME_MAX` 等)**: 定义了各种 Btrfs 对象名称、路径的最大长度限制。

3. **`btrfs_ioctl_vol_args` 结构体**:  用于多种卷操作的通用参数结构体，例如创建快照、删除子卷等，包含文件描述符和路径名。

4. **子卷管理相关定义 (`BTRFS_SUBVOL_CREATE_ASYNC`, `BTRFS_SUBVOL_RDONLY` 等)**:  定义了创建子卷时的各种标志，例如异步创建、只读属性、继承配额组等。

5. **配额组管理相关定义 (`BTRFS_QGROUP_LIMIT_*`, `btrfs_qgroup_limit`, `btrfs_qgroup_inherit` 等)**:  定义了用于管理 Btrfs 配额组的结构体和标志，允许限制特定子卷或用户的磁盘使用量。

6. **设备管理相关定义 (`BTRFS_DEVICE_PATH_NAME_MAX`, `btrfs_ioctl_dev_replace_args`, `btrfs_ioctl_dev_info_args` 等)**:  定义了用于管理 Btrfs 文件系统中的磁盘设备的结构体和常量，包括添加、删除、替换设备，以及获取设备信息。

7. **数据校验和修复相关定义 (`btrfs_ioctl_scrub_args`, `BTRFS_SCRUB_READONLY` 等)**:  定义了用于执行 Btrfs 数据校验（scrub）操作的结构体和标志，用于检测和修复磁盘错误。

8. **平衡操作相关定义 (`btrfs_ioctl_balance_args`, `BTRFS_BALANCE_DATA`, `BTRFS_BALANCE_METADATA` 等)**:  定义了用于管理 Btrfs 数据布局平衡操作的结构体和标志，例如将数据迁移到不同的磁盘或调整数据冗余级别。

9. **文件查找相关定义 (`btrfs_ioctl_ino_lookup_args`, `btrfs_ioctl_search_args` 等)**:  定义了用于在 Btrfs 文件系统中查找文件 inode 或特定数据结构的结构体。

10. **克隆操作相关定义 (`btrfs_ioctl_clone_range_args`)**: 定义了用于执行 Btrfs 文件克隆（COW，Copy-on-Write）操作的结构体，允许高效地复制文件数据。

11. **碎片整理相关定义 (`btrfs_ioctl_defrag_range_args`)**: 定义了用于执行 Btrfs 文件碎片整理操作的结构体。

12. **空间信息相关定义 (`btrfs_ioctl_space_args`)**: 定义了用于获取 Btrfs 文件系统空间使用信息的结构体。

13. **错误码定义 (`enum btrfs_err_code`)**:  定义了 Btrfs 操作可能返回的特定错误码。

14. **ioctl 命令定义 (`BTRFS_IOC_SNAP_CREATE`, `BTRFS_IOC_ADD_DEV` 等)**:  使用 `_IO`, `_IOR`, `_IOW`, `_IOWR` 宏定义了各种 Btrfs 特定的 `ioctl` 命令，每个命令对应一种 Btrfs 操作。

**与 Android 功能的关系及举例说明：**

虽然这个头文件本身不直接属于 Android 的功能，但它描述的 Btrfs 文件系统功能可以在 Android 系统中使用，尤其是在以下方面：

*   **系统分区**: Android 设备可能会使用 Btrfs 作为系统分区或数据分区的文件系统。例如，某些定制的 Android ROM 或特定的设备可能会选择 Btrfs 以利用其快照、校验和等特性。
*   **容器化和虚拟化**: 如果 Android 系统中使用了容器化技术（如 Docker）或者虚拟化技术，Btrfs 的子卷功能可以用于隔离不同容器或虚拟机的文件系统，提高效率和隔离性。
*   **系统更新和回滚**: Btrfs 的快照功能可以用于实现更可靠的系统更新机制。在更新前创建系统快照，如果更新失败，可以快速回滚到之前的状态。
*   **数据完整性**: Btrfs 的内置校验和功能可以提高数据的完整性，防止因硬件错误导致的数据损坏。Android 可以利用 `BTRFS_IOC_SCRUB` 等 ioctl 命令定期进行数据校验。
*   **存储管理**: Btrfs 的配额功能可以用于限制特定应用或用户的存储空间使用，这在多用户或资源受限的 Android 环境中可能有用。

**举例说明：**

假设一个 Android 系统使用了 Btrfs 作为其数据分区的文件系统。

*   **创建快照进行系统备份**: 一个系统应用可以使用 `BTRFS_IOC_SNAP_CREATE` ioctl 命令创建一个当前系统状态的快照，用于备份目的。
    ```c
    #include <sys/ioctl.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <string.h>
    #include "btrfs.h"

    int main() {
        int fd = open("/data", O_RDONLY); // 假设 /data 是 Btrfs 文件系统
        if (fd < 0) {
            perror("open");
            return 1;
        }

        struct btrfs_ioctl_vol_args args;
        memset(&args, 0, sizeof(args));
        strcpy(args.name, "snapshot_backup"); // 快照名称

        if (ioctl(fd, BTRFS_IOC_SNAP_CREATE, &args) < 0) {
            perror("ioctl BTRFS_IOC_SNAP_CREATE");
            close(fd);
            return 1;
        }

        printf("Snapshot created successfully.\n");
        close(fd);
        return 0;
    }
    ```

*   **执行数据校验 (scrub)**:  一个后台服务可以使用 `BTRFS_IOC_SCRUB` ioctl 命令来启动对文件系统的校验，确保数据完整性。

**详细解释每一个 libc 函数的功能是如何实现的:**

**关键点：这个头文件不包含 libc 函数的实现。** 它定义了与内核交互的 *接口*。实际的 libc 函数（如 `open`, `ioctl`）的实现在 Bionic C 库的其他源文件中。

*   **`ioctl` 函数**:  `ioctl` 是一个通用的设备控制系统调用。当用户空间程序需要与设备驱动程序（包括文件系统驱动程序）进行特定操作时，会使用 `ioctl`。
    *   **实现原理**: `ioctl` 系统调用会将一个命令码（例如 `BTRFS_IOC_SNAP_CREATE`）和一个指向参数结构的指针传递给内核。内核根据命令码找到相应的设备驱动程序，并将参数传递给驱动程序的 `ioctl` 处理函数。对于 Btrfs 相关的 `ioctl` 调用，Linux 内核中的 Btrfs 文件系统驱动程序会解析命令和参数，并执行相应的 Btrfs 操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**关键点：这个头文件不直接涉及 dynamic linker 的功能。**

动态链接器（在 Android 中是 `linker` 或 `linker64`）负责在程序启动时将共享库（`.so` 文件）加载到内存中，并解析库之间的依赖关系，将函数调用地址绑定到正确的实现。

*   **libc 函数与动态链接**:  当用户空间的程序调用 `ioctl` 时，这个函数本身是 Bionic C 库中的一个共享库提供的。动态链接器会在程序启动时加载 libc.so，并将程序中 `ioctl` 函数的调用链接到 libc.so 中 `ioctl` 的实现。
*   **Btrfs ioctl 与动态链接**:  `btrfs.h` 中定义的宏和结构体被用于构建传递给 `ioctl` 系统调用的参数。动态链接器不直接处理这些定义。
*   **SO 布局样本**: `libc.so` 是一个包含 `ioctl` 函数实现的共享库。其布局大致如下（简化）：
    ```
    libc.so:
        .text:
            ioctl:  <ioctl 函数的机器码实现>
            ... 其他 libc 函数 ...
        .data:
            ... 全局变量 ...
        .dynamic:
            ... 动态链接信息 ...
        .symtab:
            ... 符号表，包含 ioctl 等符号 ...
        .strtab:
            ... 字符串表 ...
    ```
*   **链接的处理过程**:
    1. 当编译链接用户空间程序时，链接器会记录程序对 `ioctl` 函数的依赖。
    2. 在程序启动时，动态链接器会加载 `libc.so`。
    3. 动态链接器会查找 `libc.so` 的符号表，找到 `ioctl` 的地址。
    4. 动态链接器会将程序中调用 `ioctl` 的地址重定向到 `libc.so` 中 `ioctl` 的实际地址。

**如果做了逻辑推理，请给出假设输入与输出:**

以 `BTRFS_IOC_SUBVOL_CREATE` 为例：

*   **假设输入**:
    *   文件描述符 `fd` 指向一个已经挂载的 Btrfs 文件系统的根目录。
    *   `args.name` 包含要创建的子卷的名称，例如 "my_new_subvol"。
*   **逻辑推理**: 内核的 Btrfs 驱动程序会检查提供的文件描述符是否有效，是否具有创建子卷的权限，以及子卷名称是否符合规范。如果一切正常，它会在 Btrfs 文件系统中创建一个新的子卷。
*   **假设输出**:
    *   如果创建成功，`ioctl` 系统调用返回 0。
    *   如果创建失败（例如，权限不足，名称已存在），`ioctl` 系统调用返回 -1，并设置 `errno` 以指示错误类型。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误的文件描述符**:  传递给 `ioctl` 的文件描述符不是一个 Btrfs 文件系统的有效挂载点。
    ```c
    int fd = open("/tmp/some_file", O_RDONLY); // 错误的文件描述符
    struct btrfs_ioctl_vol_args args;
    strcpy(args.name, "my_subvol");
    if (ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &args) < 0) {
        perror("ioctl"); // 可能会得到 "Invalid argument" 错误
    }
    close(fd);
    ```

2. **子卷名称冲突**: 尝试创建一个已经存在的子卷名称。
    ```c
    int fd = open("/mnt/btrfs", O_RDONLY); // 假设 /mnt/btrfs 是 Btrfs 挂载点
    struct btrfs_ioctl_vol_args args;
    strcpy(args.name, "existing_subvol"); // 假设 "existing_subvol" 已经存在
    if (ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &args) < 0) {
        perror("ioctl"); // 可能会得到 "File exists" 错误
    }
    close(fd);
    ```

3. **权限不足**: 用户没有在 Btrfs 文件系统上执行特定操作的权限。
    ```c
    int fd = open("/mnt/btrfs", O_RDONLY);
    struct btrfs_ioctl_vol_args args;
    strcpy(args.name, "new_subvol");
    // 如果当前用户没有创建子卷的权限
    if (ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &args) < 0) {
        perror("ioctl"); // 可能会得到 "Permission denied" 错误
    }
    close(fd);
    ```

4. **传递错误的参数结构体**:  例如，没有正确初始化结构体，或者结构体中的某些字段值不合法。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK (Native Development Kit)**:
    *   Android 开发者可以使用 NDK 编写 C/C++ 代码。
    *   在 NDK 代码中，可以直接调用标准的 Linux 系统调用，包括 `ioctl`。
    *   开发者需要包含 `<sys/ioctl.h>` 和 `<linux/btrfs.h>` 头文件。
    *   通过 `open()` 打开 Btrfs 文件系统的挂载点，然后调用 `ioctl()` 并传入相应的 Btrfs ioctl 命令和参数结构体。

    ```c++
    // NDK 代码示例
    #include <jni.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>
    #include <cstring>
    #include <unistd.h>
    #include <linux/btrfs.h>
    #include <android/log.h>

    #define TAG "BtrfsTest"

    extern "C" JNIEXPORT jint JNICALL
    Java_com_example_btrfstest_MainActivity_createBtrfsSubvolume(
        JNIEnv* env,
        jobject /* this */,
        jstring subvolumeName) {

        const char* subvolumeNameStr = env->GetStringUTFChars(subvolumeName, nullptr);
        if (subvolumeNameStr == nullptr) {
            return -1;
        }

        int fd = open("/data", O_RDONLY); // 假设 /data 是 Btrfs
        if (fd < 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open /data");
            env->ReleaseStringUTFChars(subvolumeName, subvolumeNameStr);
            return -1;
        }

        btrfs_ioctl_vol_args vol_args;
        memset(&vol_args, 0, sizeof(vol_args));
        strncpy(vol_args.name, subvolumeNameStr, BTRFS_PATH_NAME_MAX);

        if (ioctl(fd, BTRFS_IOC_SUBVOL_CREATE, &vol_args) < 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "ioctl BTRFS_IOC_SUBVOL_CREATE failed: %s", strerror(errno));
            close(fd);
            env->ReleaseStringUTFChars(subvolumeName, subvolumeNameStr);
            return -1;
        }

        close(fd);
        env->ReleaseStringUTFChars(subvolumeName, subvolumeNameStr);
        return 0;
    }
    ```

2. **Android Framework**:
    *   Android Framework 层通常不会直接调用 Btrfs 特定的 ioctl 命令。
    *   Framework 更倾向于使用抽象的 API，例如 `StorageManager` 等，来管理存储。
    *   这些高级 API 底层可能会调用 VFS（Virtual File System）层提供的通用文件系统操作接口。
    *   如果 Framework 需要执行 Btrfs 特定的操作，可能会通过 JNI 调用到 Native 代码（使用 NDK），然后在 Native 代码中调用 `ioctl`。
    *   或者，某些系统服务可能直接在 Native 代码中与 Btrfs 文件系统交互。

**Frida Hook 示例：**

可以使用 Frida Hook `ioctl` 系统调用，并过滤出 Btrfs 相关的 ioctl 命令。

```javascript
// Frida 脚本示例
Interceptor.attach(Module.getExportByName(null, "ioctl"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const request = args[1].toInt32();

    // 检查是否是 Btrfs ioctl 魔数
    if ((request >> 8) === 0x94) {
      console.log("BTRFS ioctl called!");
      console.log("  File Descriptor:", fd);
      console.log("  Request Code:", request.toString(16));

      // 可以进一步解析参数，根据不同的 ioctl 命令
      if (request === 0xc018940e) { // BTRFS_IOC_SUBVOL_CREATE
        const argp = ptr(args[2]);
        const vol_args = argp.readByteArray(Process.pointerSize + 4088); // 假设结构体大小
        const subvol_name = Memory.readCString(argp.add(Process.pointerSize));
        console.log("  Subvolume Name:", subvol_name);
      }
    }
  },
  onLeave: function (retval) {
    // console.log("ioctl returned:", retval.toInt32());
  }
});
```

**调试步骤：**

1. 将 Frida 脚本保存为 `.js` 文件（例如 `btrfs_hook.js`）。
2. 在连接到 Android 设备的电脑上运行 Frida 服务 (`frida-server` 需要在 Android 设备上运行)。
3. 确定要监控的进程，可以是应用进程或系统服务进程。
4. 使用 Frida 命令运行脚本：
    ```bash
    frida -U -f <包名或进程名> -l btrfs_hook.js --no-pause
    ```
    或者，如果进程已经运行：
    ```bash
    frida -U <包名或进程名> -l btrfs_hook.js
    ```
5. 当目标进程调用 `ioctl` 且请求码匹配 Btrfs 的魔数时，Frida 脚本会在控制台输出相关信息，包括文件描述符、ioctl 命令码以及可能的参数。

通过 Frida Hook，可以动态地观察 Android 系统或应用如何与 Btrfs 文件系统进行交互，验证参数的传递和返回值的状态，从而进行调试和分析。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/btrfs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_BTRFS_H
#define _UAPI_LINUX_BTRFS_H
#ifdef __cplusplus
extern "C" {
#endif
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#define BTRFS_IOCTL_MAGIC 0x94
#define BTRFS_VOL_NAME_MAX 255
#define BTRFS_LABEL_SIZE 256
#define BTRFS_PATH_NAME_MAX 4087
struct btrfs_ioctl_vol_args {
  __s64 fd;
  char name[BTRFS_PATH_NAME_MAX + 1];
};
#define BTRFS_DEVICE_PATH_NAME_MAX 1024
#define BTRFS_SUBVOL_NAME_MAX 4039
#define BTRFS_SUBVOL_CREATE_ASYNC (1ULL << 0)
#define BTRFS_SUBVOL_RDONLY (1ULL << 1)
#define BTRFS_SUBVOL_QGROUP_INHERIT (1ULL << 2)
#define BTRFS_DEVICE_SPEC_BY_ID (1ULL << 3)
#define BTRFS_SUBVOL_SPEC_BY_ID (1ULL << 4)
#define BTRFS_VOL_ARG_V2_FLAGS_SUPPORTED (BTRFS_SUBVOL_RDONLY | BTRFS_SUBVOL_QGROUP_INHERIT | BTRFS_DEVICE_SPEC_BY_ID | BTRFS_SUBVOL_SPEC_BY_ID)
#define BTRFS_FSID_SIZE 16
#define BTRFS_UUID_SIZE 16
#define BTRFS_UUID_UNPARSED_SIZE 37
#define BTRFS_QGROUP_LIMIT_MAX_RFER (1ULL << 0)
#define BTRFS_QGROUP_LIMIT_MAX_EXCL (1ULL << 1)
#define BTRFS_QGROUP_LIMIT_RSV_RFER (1ULL << 2)
#define BTRFS_QGROUP_LIMIT_RSV_EXCL (1ULL << 3)
#define BTRFS_QGROUP_LIMIT_RFER_CMPR (1ULL << 4)
#define BTRFS_QGROUP_LIMIT_EXCL_CMPR (1ULL << 5)
struct btrfs_qgroup_limit {
  __u64 flags;
  __u64 max_rfer;
  __u64 max_excl;
  __u64 rsv_rfer;
  __u64 rsv_excl;
};
#define BTRFS_QGROUP_INHERIT_SET_LIMITS (1ULL << 0)
#define BTRFS_QGROUP_INHERIT_FLAGS_SUPP (BTRFS_QGROUP_INHERIT_SET_LIMITS)
struct btrfs_qgroup_inherit {
  __u64 flags;
  __u64 num_qgroups;
  __u64 num_ref_copies;
  __u64 num_excl_copies;
  struct btrfs_qgroup_limit lim;
  __u64 qgroups[];
};
struct btrfs_ioctl_qgroup_limit_args {
  __u64 qgroupid;
  struct btrfs_qgroup_limit lim;
};
#define BTRFS_DEVICE_REMOVE_ARGS_MASK (BTRFS_DEVICE_SPEC_BY_ID)
#define BTRFS_SUBVOL_CREATE_ARGS_MASK (BTRFS_SUBVOL_RDONLY | BTRFS_SUBVOL_QGROUP_INHERIT)
#define BTRFS_SUBVOL_DELETE_ARGS_MASK (BTRFS_SUBVOL_SPEC_BY_ID)
struct btrfs_ioctl_vol_args_v2 {
  __s64 fd;
  __u64 transid;
  __u64 flags;
  union {
    struct {
      __u64 size;
      struct btrfs_qgroup_inherit  * qgroup_inherit;
    };
    __u64 unused[4];
  };
  union {
    char name[BTRFS_SUBVOL_NAME_MAX + 1];
    __u64 devid;
    __u64 subvolid;
  };
};
struct btrfs_scrub_progress {
  __u64 data_extents_scrubbed;
  __u64 tree_extents_scrubbed;
  __u64 data_bytes_scrubbed;
  __u64 tree_bytes_scrubbed;
  __u64 read_errors;
  __u64 csum_errors;
  __u64 verify_errors;
  __u64 no_csum;
  __u64 csum_discards;
  __u64 super_errors;
  __u64 malloc_errors;
  __u64 uncorrectable_errors;
  __u64 corrected_errors;
  __u64 last_physical;
  __u64 unverified_errors;
};
#define BTRFS_SCRUB_READONLY 1
#define BTRFS_SCRUB_SUPPORTED_FLAGS (BTRFS_SCRUB_READONLY)
struct btrfs_ioctl_scrub_args {
  __u64 devid;
  __u64 start;
  __u64 end;
  __u64 flags;
  struct btrfs_scrub_progress progress;
  __u64 unused[(1024 - 32 - sizeof(struct btrfs_scrub_progress)) / 8];
};
#define BTRFS_IOCTL_DEV_REPLACE_CONT_READING_FROM_SRCDEV_MODE_ALWAYS 0
#define BTRFS_IOCTL_DEV_REPLACE_CONT_READING_FROM_SRCDEV_MODE_AVOID 1
struct btrfs_ioctl_dev_replace_start_params {
  __u64 srcdevid;
  __u64 cont_reading_from_srcdev_mode;
  __u8 srcdev_name[BTRFS_DEVICE_PATH_NAME_MAX + 1];
  __u8 tgtdev_name[BTRFS_DEVICE_PATH_NAME_MAX + 1];
};
#define BTRFS_IOCTL_DEV_REPLACE_STATE_NEVER_STARTED 0
#define BTRFS_IOCTL_DEV_REPLACE_STATE_STARTED 1
#define BTRFS_IOCTL_DEV_REPLACE_STATE_FINISHED 2
#define BTRFS_IOCTL_DEV_REPLACE_STATE_CANCELED 3
#define BTRFS_IOCTL_DEV_REPLACE_STATE_SUSPENDED 4
struct btrfs_ioctl_dev_replace_status_params {
  __u64 replace_state;
  __u64 progress_1000;
  __u64 time_started;
  __u64 time_stopped;
  __u64 num_write_errors;
  __u64 num_uncorrectable_read_errors;
};
#define BTRFS_IOCTL_DEV_REPLACE_CMD_START 0
#define BTRFS_IOCTL_DEV_REPLACE_CMD_STATUS 1
#define BTRFS_IOCTL_DEV_REPLACE_CMD_CANCEL 2
#define BTRFS_IOCTL_DEV_REPLACE_RESULT_NO_ERROR 0
#define BTRFS_IOCTL_DEV_REPLACE_RESULT_NOT_STARTED 1
#define BTRFS_IOCTL_DEV_REPLACE_RESULT_ALREADY_STARTED 2
#define BTRFS_IOCTL_DEV_REPLACE_RESULT_SCRUB_INPROGRESS 3
struct btrfs_ioctl_dev_replace_args {
  __u64 cmd;
  __u64 result;
  union {
    struct btrfs_ioctl_dev_replace_start_params start;
    struct btrfs_ioctl_dev_replace_status_params status;
  };
  __u64 spare[64];
};
struct btrfs_ioctl_dev_info_args {
  __u64 devid;
  __u8 uuid[BTRFS_UUID_SIZE];
  __u64 bytes_used;
  __u64 total_bytes;
  __u8 fsid[BTRFS_UUID_SIZE];
  __u64 unused[377];
  __u8 path[BTRFS_DEVICE_PATH_NAME_MAX];
};
#define BTRFS_FS_INFO_FLAG_CSUM_INFO (1 << 0)
#define BTRFS_FS_INFO_FLAG_GENERATION (1 << 1)
#define BTRFS_FS_INFO_FLAG_METADATA_UUID (1 << 2)
struct btrfs_ioctl_fs_info_args {
  __u64 max_id;
  __u64 num_devices;
  __u8 fsid[BTRFS_FSID_SIZE];
  __u32 nodesize;
  __u32 sectorsize;
  __u32 clone_alignment;
  __u16 csum_type;
  __u16 csum_size;
  __u64 flags;
  __u64 generation;
  __u8 metadata_uuid[BTRFS_FSID_SIZE];
  __u8 reserved[944];
};
#define BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE (1ULL << 0)
#define BTRFS_FEATURE_COMPAT_RO_FREE_SPACE_TREE_VALID (1ULL << 1)
#define BTRFS_FEATURE_COMPAT_RO_VERITY (1ULL << 2)
#define BTRFS_FEATURE_COMPAT_RO_BLOCK_GROUP_TREE (1ULL << 3)
#define BTRFS_FEATURE_INCOMPAT_MIXED_BACKREF (1ULL << 0)
#define BTRFS_FEATURE_INCOMPAT_DEFAULT_SUBVOL (1ULL << 1)
#define BTRFS_FEATURE_INCOMPAT_MIXED_GROUPS (1ULL << 2)
#define BTRFS_FEATURE_INCOMPAT_COMPRESS_LZO (1ULL << 3)
#define BTRFS_FEATURE_INCOMPAT_COMPRESS_ZSTD (1ULL << 4)
#define BTRFS_FEATURE_INCOMPAT_BIG_METADATA (1ULL << 5)
#define BTRFS_FEATURE_INCOMPAT_EXTENDED_IREF (1ULL << 6)
#define BTRFS_FEATURE_INCOMPAT_RAID56 (1ULL << 7)
#define BTRFS_FEATURE_INCOMPAT_SKINNY_METADATA (1ULL << 8)
#define BTRFS_FEATURE_INCOMPAT_NO_HOLES (1ULL << 9)
#define BTRFS_FEATURE_INCOMPAT_METADATA_UUID (1ULL << 10)
#define BTRFS_FEATURE_INCOMPAT_RAID1C34 (1ULL << 11)
#define BTRFS_FEATURE_INCOMPAT_ZONED (1ULL << 12)
#define BTRFS_FEATURE_INCOMPAT_EXTENT_TREE_V2 (1ULL << 13)
#define BTRFS_FEATURE_INCOMPAT_RAID_STRIPE_TREE (1ULL << 14)
#define BTRFS_FEATURE_INCOMPAT_SIMPLE_QUOTA (1ULL << 16)
struct btrfs_ioctl_feature_flags {
  __u64 compat_flags;
  __u64 compat_ro_flags;
  __u64 incompat_flags;
};
#define BTRFS_BALANCE_CTL_PAUSE 1
#define BTRFS_BALANCE_CTL_CANCEL 2
struct btrfs_balance_args {
  __u64 profiles;
  union {
    __u64 usage;
    struct {
      __u32 usage_min;
      __u32 usage_max;
    };
  };
  __u64 devid;
  __u64 pstart;
  __u64 pend;
  __u64 vstart;
  __u64 vend;
  __u64 target;
  __u64 flags;
  union {
    __u64 limit;
    struct {
      __u32 limit_min;
      __u32 limit_max;
    };
  };
  __u32 stripes_min;
  __u32 stripes_max;
  __u64 unused[6];
} __attribute__((__packed__));
struct btrfs_balance_progress {
  __u64 expected;
  __u64 considered;
  __u64 completed;
};
#define BTRFS_BALANCE_DATA (1ULL << 0)
#define BTRFS_BALANCE_SYSTEM (1ULL << 1)
#define BTRFS_BALANCE_METADATA (1ULL << 2)
#define BTRFS_BALANCE_TYPE_MASK (BTRFS_BALANCE_DATA | BTRFS_BALANCE_SYSTEM | BTRFS_BALANCE_METADATA)
#define BTRFS_BALANCE_FORCE (1ULL << 3)
#define BTRFS_BALANCE_RESUME (1ULL << 4)
#define BTRFS_BALANCE_ARGS_PROFILES (1ULL << 0)
#define BTRFS_BALANCE_ARGS_USAGE (1ULL << 1)
#define BTRFS_BALANCE_ARGS_DEVID (1ULL << 2)
#define BTRFS_BALANCE_ARGS_DRANGE (1ULL << 3)
#define BTRFS_BALANCE_ARGS_VRANGE (1ULL << 4)
#define BTRFS_BALANCE_ARGS_LIMIT (1ULL << 5)
#define BTRFS_BALANCE_ARGS_LIMIT_RANGE (1ULL << 6)
#define BTRFS_BALANCE_ARGS_STRIPES_RANGE (1ULL << 7)
#define BTRFS_BALANCE_ARGS_USAGE_RANGE (1ULL << 10)
#define BTRFS_BALANCE_ARGS_MASK (BTRFS_BALANCE_ARGS_PROFILES | BTRFS_BALANCE_ARGS_USAGE | BTRFS_BALANCE_ARGS_DEVID | BTRFS_BALANCE_ARGS_DRANGE | BTRFS_BALANCE_ARGS_VRANGE | BTRFS_BALANCE_ARGS_LIMIT | BTRFS_BALANCE_ARGS_LIMIT_RANGE | BTRFS_BALANCE_ARGS_STRIPES_RANGE | BTRFS_BALANCE_ARGS_USAGE_RANGE)
#define BTRFS_BALANCE_ARGS_CONVERT (1ULL << 8)
#define BTRFS_BALANCE_ARGS_SOFT (1ULL << 9)
#define BTRFS_BALANCE_STATE_RUNNING (1ULL << 0)
#define BTRFS_BALANCE_STATE_PAUSE_REQ (1ULL << 1)
#define BTRFS_BALANCE_STATE_CANCEL_REQ (1ULL << 2)
struct btrfs_ioctl_balance_args {
  __u64 flags;
  __u64 state;
  struct btrfs_balance_args data;
  struct btrfs_balance_args meta;
  struct btrfs_balance_args sys;
  struct btrfs_balance_progress stat;
  __u64 unused[72];
};
#define BTRFS_INO_LOOKUP_PATH_MAX 4080
struct btrfs_ioctl_ino_lookup_args {
  __u64 treeid;
  __u64 objectid;
  char name[BTRFS_INO_LOOKUP_PATH_MAX];
};
#define BTRFS_INO_LOOKUP_USER_PATH_MAX (4080 - BTRFS_VOL_NAME_MAX - 1)
struct btrfs_ioctl_ino_lookup_user_args {
  __u64 dirid;
  __u64 treeid;
  char name[BTRFS_VOL_NAME_MAX + 1];
  char path[BTRFS_INO_LOOKUP_USER_PATH_MAX];
};
struct btrfs_ioctl_search_key {
  __u64 tree_id;
  __u64 min_objectid;
  __u64 max_objectid;
  __u64 min_offset;
  __u64 max_offset;
  __u64 min_transid;
  __u64 max_transid;
  __u32 min_type;
  __u32 max_type;
  __u32 nr_items;
  __u32 unused;
  __u64 unused1;
  __u64 unused2;
  __u64 unused3;
  __u64 unused4;
};
struct btrfs_ioctl_search_header {
  __u64 transid;
  __u64 objectid;
  __u64 offset;
  __u32 type;
  __u32 len;
} __attribute__((__may_alias__));
#define BTRFS_SEARCH_ARGS_BUFSIZE (4096 - sizeof(struct btrfs_ioctl_search_key))
struct btrfs_ioctl_search_args {
  struct btrfs_ioctl_search_key key;
  char buf[BTRFS_SEARCH_ARGS_BUFSIZE];
};
struct btrfs_ioctl_search_args_v2 {
  struct btrfs_ioctl_search_key key;
  __u64 buf_size;
  __u64 buf[];
};
struct btrfs_ioctl_clone_range_args {
  __s64 src_fd;
  __u64 src_offset, src_length;
  __u64 dest_offset;
};
#define BTRFS_DEFRAG_RANGE_COMPRESS 1
#define BTRFS_DEFRAG_RANGE_START_IO 2
#define BTRFS_DEFRAG_RANGE_FLAGS_SUPP (BTRFS_DEFRAG_RANGE_COMPRESS | BTRFS_DEFRAG_RANGE_START_IO)
struct btrfs_ioctl_defrag_range_args {
  __u64 start;
  __u64 len;
  __u64 flags;
  __u32 extent_thresh;
  __u32 compress_type;
  __u32 unused[4];
};
#define BTRFS_SAME_DATA_DIFFERS 1
struct btrfs_ioctl_same_extent_info {
  __s64 fd;
  __u64 logical_offset;
  __u64 bytes_deduped;
  __s32 status;
  __u32 reserved;
};
struct btrfs_ioctl_same_args {
  __u64 logical_offset;
  __u64 length;
  __u16 dest_count;
  __u16 reserved1;
  __u32 reserved2;
  struct btrfs_ioctl_same_extent_info info[];
};
struct btrfs_ioctl_space_info {
  __u64 flags;
  __u64 total_bytes;
  __u64 used_bytes;
};
struct btrfs_ioctl_space_args {
  __u64 space_slots;
  __u64 total_spaces;
  struct btrfs_ioctl_space_info spaces[];
};
struct btrfs_data_container {
  __u32 bytes_left;
  __u32 bytes_missing;
  __u32 elem_cnt;
  __u32 elem_missed;
  __u64 val[];
};
struct btrfs_ioctl_ino_path_args {
  __u64 inum;
  __u64 size;
  __u64 reserved[4];
  __u64 fspath;
};
struct btrfs_ioctl_logical_ino_args {
  __u64 logical;
  __u64 size;
  __u64 reserved[3];
  __u64 flags;
  __u64 inodes;
};
#define BTRFS_LOGICAL_INO_ARGS_IGNORE_OFFSET (1ULL << 0)
enum btrfs_dev_stat_values {
  BTRFS_DEV_STAT_WRITE_ERRS,
  BTRFS_DEV_STAT_READ_ERRS,
  BTRFS_DEV_STAT_FLUSH_ERRS,
  BTRFS_DEV_STAT_CORRUPTION_ERRS,
  BTRFS_DEV_STAT_GENERATION_ERRS,
  BTRFS_DEV_STAT_VALUES_MAX
};
#define BTRFS_DEV_STATS_RESET (1ULL << 0)
struct btrfs_ioctl_get_dev_stats {
  __u64 devid;
  __u64 nr_items;
  __u64 flags;
  __u64 values[BTRFS_DEV_STAT_VALUES_MAX];
  __u64 unused[128 - 2 - BTRFS_DEV_STAT_VALUES_MAX];
};
#define BTRFS_QUOTA_CTL_ENABLE 1
#define BTRFS_QUOTA_CTL_DISABLE 2
#define BTRFS_QUOTA_CTL_RESCAN__NOTUSED 3
#define BTRFS_QUOTA_CTL_ENABLE_SIMPLE_QUOTA 4
struct btrfs_ioctl_quota_ctl_args {
  __u64 cmd;
  __u64 status;
};
struct btrfs_ioctl_quota_rescan_args {
  __u64 flags;
  __u64 progress;
  __u64 reserved[6];
};
struct btrfs_ioctl_qgroup_assign_args {
  __u64 assign;
  __u64 src;
  __u64 dst;
};
struct btrfs_ioctl_qgroup_create_args {
  __u64 create;
  __u64 qgroupid;
};
struct btrfs_ioctl_timespec {
  __u64 sec;
  __u32 nsec;
};
struct btrfs_ioctl_received_subvol_args {
  char uuid[BTRFS_UUID_SIZE];
  __u64 stransid;
  __u64 rtransid;
  struct btrfs_ioctl_timespec stime;
  struct btrfs_ioctl_timespec rtime;
  __u64 flags;
  __u64 reserved[16];
};
#define BTRFS_SEND_FLAG_NO_FILE_DATA 0x1
#define BTRFS_SEND_FLAG_OMIT_STREAM_HEADER 0x2
#define BTRFS_SEND_FLAG_OMIT_END_CMD 0x4
#define BTRFS_SEND_FLAG_VERSION 0x8
#define BTRFS_SEND_FLAG_COMPRESSED 0x10
#define BTRFS_SEND_FLAG_MASK (BTRFS_SEND_FLAG_NO_FILE_DATA | BTRFS_SEND_FLAG_OMIT_STREAM_HEADER | BTRFS_SEND_FLAG_OMIT_END_CMD | BTRFS_SEND_FLAG_VERSION | BTRFS_SEND_FLAG_COMPRESSED)
struct btrfs_ioctl_send_args {
  __s64 send_fd;
  __u64 clone_sources_count;
  __u64  * clone_sources;
  __u64 parent_root;
  __u64 flags;
  __u32 version;
  __u8 reserved[28];
};
struct btrfs_ioctl_get_subvol_info_args {
  __u64 treeid;
  char name[BTRFS_VOL_NAME_MAX + 1];
  __u64 parent_id;
  __u64 dirid;
  __u64 generation;
  __u64 flags;
  __u8 uuid[BTRFS_UUID_SIZE];
  __u8 parent_uuid[BTRFS_UUID_SIZE];
  __u8 received_uuid[BTRFS_UUID_SIZE];
  __u64 ctransid;
  __u64 otransid;
  __u64 stransid;
  __u64 rtransid;
  struct btrfs_ioctl_timespec ctime;
  struct btrfs_ioctl_timespec otime;
  struct btrfs_ioctl_timespec stime;
  struct btrfs_ioctl_timespec rtime;
  __u64 reserved[8];
};
#define BTRFS_MAX_ROOTREF_BUFFER_NUM 255
struct btrfs_ioctl_get_subvol_rootref_args {
  __u64 min_treeid;
  struct {
    __u64 treeid;
    __u64 dirid;
  } rootref[BTRFS_MAX_ROOTREF_BUFFER_NUM];
  __u8 num_items;
  __u8 align[7];
};
struct btrfs_ioctl_encoded_io_args {
  const struct iovec  * iov;
  unsigned long iovcnt;
  __s64 offset;
  __u64 flags;
  __u64 len;
  __u64 unencoded_len;
  __u64 unencoded_offset;
  __u32 compression;
  __u32 encryption;
  __u8 reserved[64];
};
#define BTRFS_ENCODED_IO_COMPRESSION_NONE 0
#define BTRFS_ENCODED_IO_COMPRESSION_ZLIB 1
#define BTRFS_ENCODED_IO_COMPRESSION_ZSTD 2
#define BTRFS_ENCODED_IO_COMPRESSION_LZO_4K 3
#define BTRFS_ENCODED_IO_COMPRESSION_LZO_8K 4
#define BTRFS_ENCODED_IO_COMPRESSION_LZO_16K 5
#define BTRFS_ENCODED_IO_COMPRESSION_LZO_32K 6
#define BTRFS_ENCODED_IO_COMPRESSION_LZO_64K 7
#define BTRFS_ENCODED_IO_COMPRESSION_TYPES 8
#define BTRFS_ENCODED_IO_ENCRYPTION_NONE 0
#define BTRFS_ENCODED_IO_ENCRYPTION_TYPES 1
enum btrfs_err_code {
  BTRFS_ERROR_DEV_RAID1_MIN_NOT_MET = 1,
  BTRFS_ERROR_DEV_RAID10_MIN_NOT_MET,
  BTRFS_ERROR_DEV_RAID5_MIN_NOT_MET,
  BTRFS_ERROR_DEV_RAID6_MIN_NOT_MET,
  BTRFS_ERROR_DEV_TGT_REPLACE,
  BTRFS_ERROR_DEV_MISSING_NOT_FOUND,
  BTRFS_ERROR_DEV_ONLY_WRITABLE,
  BTRFS_ERROR_DEV_EXCL_RUN_IN_PROGRESS,
  BTRFS_ERROR_DEV_RAID1C3_MIN_NOT_MET,
  BTRFS_ERROR_DEV_RAID1C4_MIN_NOT_MET,
};
#define BTRFS_IOC_SNAP_CREATE _IOW(BTRFS_IOCTL_MAGIC, 1, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_DEFRAG _IOW(BTRFS_IOCTL_MAGIC, 2, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_RESIZE _IOW(BTRFS_IOCTL_MAGIC, 3, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_SCAN_DEV _IOW(BTRFS_IOCTL_MAGIC, 4, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_FORGET_DEV _IOW(BTRFS_IOCTL_MAGIC, 5, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_TRANS_START _IO(BTRFS_IOCTL_MAGIC, 6)
#define BTRFS_IOC_TRANS_END _IO(BTRFS_IOCTL_MAGIC, 7)
#define BTRFS_IOC_SYNC _IO(BTRFS_IOCTL_MAGIC, 8)
#define BTRFS_IOC_CLONE _IOW(BTRFS_IOCTL_MAGIC, 9, int)
#define BTRFS_IOC_ADD_DEV _IOW(BTRFS_IOCTL_MAGIC, 10, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_RM_DEV _IOW(BTRFS_IOCTL_MAGIC, 11, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_BALANCE _IOW(BTRFS_IOCTL_MAGIC, 12, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_CLONE_RANGE _IOW(BTRFS_IOCTL_MAGIC, 13, struct btrfs_ioctl_clone_range_args)
#define BTRFS_IOC_SUBVOL_CREATE _IOW(BTRFS_IOCTL_MAGIC, 14, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_SNAP_DESTROY _IOW(BTRFS_IOCTL_MAGIC, 15, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_DEFRAG_RANGE _IOW(BTRFS_IOCTL_MAGIC, 16, struct btrfs_ioctl_defrag_range_args)
#define BTRFS_IOC_TREE_SEARCH _IOWR(BTRFS_IOCTL_MAGIC, 17, struct btrfs_ioctl_search_args)
#define BTRFS_IOC_TREE_SEARCH_V2 _IOWR(BTRFS_IOCTL_MAGIC, 17, struct btrfs_ioctl_search_args_v2)
#define BTRFS_IOC_INO_LOOKUP _IOWR(BTRFS_IOCTL_MAGIC, 18, struct btrfs_ioctl_ino_lookup_args)
#define BTRFS_IOC_DEFAULT_SUBVOL _IOW(BTRFS_IOCTL_MAGIC, 19, __u64)
#define BTRFS_IOC_SPACE_INFO _IOWR(BTRFS_IOCTL_MAGIC, 20, struct btrfs_ioctl_space_args)
#define BTRFS_IOC_START_SYNC _IOR(BTRFS_IOCTL_MAGIC, 24, __u64)
#define BTRFS_IOC_WAIT_SYNC _IOW(BTRFS_IOCTL_MAGIC, 22, __u64)
#define BTRFS_IOC_SNAP_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 23, struct btrfs_ioctl_vol_args_v2)
#define BTRFS_IOC_SUBVOL_CREATE_V2 _IOW(BTRFS_IOCTL_MAGIC, 24, struct btrfs_ioctl_vol_args_v2)
#define BTRFS_IOC_SUBVOL_GETFLAGS _IOR(BTRFS_IOCTL_MAGIC, 25, __u64)
#define BTRFS_IOC_SUBVOL_SETFLAGS _IOW(BTRFS_IOCTL_MAGIC, 26, __u64)
#define BTRFS_IOC_SCRUB _IOWR(BTRFS_IOCTL_MAGIC, 27, struct btrfs_ioctl_scrub_args)
#define BTRFS_IOC_SCRUB_CANCEL _IO(BTRFS_IOCTL_MAGIC, 28)
#define BTRFS_IOC_SCRUB_PROGRESS _IOWR(BTRFS_IOCTL_MAGIC, 29, struct btrfs_ioctl_scrub_args)
#define BTRFS_IOC_DEV_INFO _IOWR(BTRFS_IOCTL_MAGIC, 30, struct btrfs_ioctl_dev_info_args)
#define BTRFS_IOC_FS_INFO _IOR(BTRFS_IOCTL_MAGIC, 31, struct btrfs_ioctl_fs_info_args)
#define BTRFS_IOC_BALANCE_V2 _IOWR(BTRFS_IOCTL_MAGIC, 32, struct btrfs_ioctl_balance_args)
#define BTRFS_IOC_BALANCE_CTL _IOW(BTRFS_IOCTL_MAGIC, 33, int)
#define BTRFS_IOC_BALANCE_PROGRESS _IOR(BTRFS_IOCTL_MAGIC, 34, struct btrfs_ioctl_balance_args)
#define BTRFS_IOC_INO_PATHS _IOWR(BTRFS_IOCTL_MAGIC, 35, struct btrfs_ioctl_ino_path_args)
#define BTRFS_IOC_LOGICAL_INO _IOWR(BTRFS_IOCTL_MAGIC, 36, struct btrfs_ioctl_logical_ino_args)
#define BTRFS_IOC_SET_RECEIVED_SUBVOL _IOWR(BTRFS_IOCTL_MAGIC, 37, struct btrfs_ioctl_received_subvol_args)
#define BTRFS_IOC_SEND _IOW(BTRFS_IOCTL_MAGIC, 38, struct btrfs_ioctl_send_args)
#define BTRFS_IOC_DEVICES_READY _IOR(BTRFS_IOCTL_MAGIC, 39, struct btrfs_ioctl_vol_args)
#define BTRFS_IOC_QUOTA_CTL _IOWR(BTRFS_IOCTL_MAGIC, 40, struct btrfs_ioctl_quota_ctl_args)
#define BTRFS_IOC_QGROUP_ASSIGN _IOW(BTRFS_IOCTL_MAGIC, 41, struct btrfs_ioctl_qgroup_assign_args)
#define BTRFS_IOC_QGROUP_CREATE _IOW(BTRFS_IOCTL_MAGIC, 42, struct btrfs_ioctl_qgroup_create_args)
#define BTRFS_IOC_QGROUP_LIMIT _IOR(BTRFS_IOCTL_MAGIC, 43, struct btrfs_ioctl_qgroup_limit_args)
#define BTRFS_IOC_QUOTA_RESCAN _IOW(BTRFS_IOCTL_MAGIC, 44, struct btrfs_ioctl_quota_rescan_args)
#define BTRFS_IOC_QUOTA_RESCAN_STATUS _IOR(BTRFS_IOCTL_MAGIC, 45, struct btrfs_ioctl_quota_rescan_args)
#define BTRFS_IOC_QUOTA_RESCAN_WAIT _IO(BTRFS_IOCTL_MAGIC, 46)
#define BTRFS_IOC_GET_FSLABEL FS_IOC_GETFSLABEL
#define BTRFS_IOC_SET_FSLABEL FS_IOC_SETFSLABEL
#define BTRFS_IOC_GET_DEV_STATS _IOWR(BTRFS_IOCTL_MAGIC, 52, struct btrfs_ioctl_get_dev_stats)
#define BTRFS_IOC_DEV_REPLACE _IOWR(BTRFS_IOCTL_MAGIC, 53, struct btrfs_ioctl_dev_replace_args)
#define BTRFS_IOC_FILE_EXTENT_SAME _IOWR(BTRFS_IOCTL_MAGIC, 54, struct btrfs_ioctl_same_args)
#define BTRFS_IOC_GET_FEATURES _IOR(BTRFS_IOCTL_MAGIC, 57, struct btrfs_ioctl_feature_flags)
#define BTRFS_IOC_SET_FEATURES _IOW(BTRFS_IOCTL_MAGIC, 57, struct btrfs_ioctl_feature_flags[2])
#define BTRFS_IOC_GET_SUPPORTED_FEATURES _IOR(BTRFS_IOCTL_MAGIC, 57, struct btrfs_ioctl_feature_flags[3])
#define BTRFS_IOC_RM_DEV_V2 _IOW(BTRFS_IOCTL_MAGIC, 58, struct btrfs_ioctl_vol_args_v2)
#define BTRFS_IOC_LOGICAL_INO_V2 _IOWR(BTRFS_IOCTL_MAGIC, 59, struct btrfs_ioctl_logical_ino_args)
#define BTRFS_IOC_GET_SUBVOL_INFO _IOR(BTRFS_IOCTL_MAGIC, 60, struct btrfs_ioctl_get_subvol_info_args)
#define BTRFS_IOC_GET_SUBVOL_ROOTREF _IOWR(BTRFS_IOCTL_MAGIC, 61, struct btrfs_ioctl_get_subvol_rootref_args)
#define BTRFS_IOC_INO_LOOKUP_USER _IOWR(BTRFS_IOCTL_MAGIC, 62, struct btrfs_ioctl_ino_lookup_user_args)
#define BTRFS_IOC_SNAP_DESTROY_V2 _IOW(BTRFS_IOCTL_MAGIC, 63, struct btrfs_ioctl_vol_args_v2)
#define BTRFS_IOC_ENCODED_READ _IOR(BTRFS_IOCTL_MAGIC, 64, struct btrfs_ioctl_encoded_io_args)
#define BTRFS_IOC_ENCODED_WRITE _IOW(BTRFS_IOCTL_MAGIC, 64, struct btrfs_ioctl_encoded_io_args)
#ifdef __cplusplus
}
#endif
#endif
```