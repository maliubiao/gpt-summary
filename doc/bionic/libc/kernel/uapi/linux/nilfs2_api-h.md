Response:
Let's break down the thought process for analyzing this C header file related to the NILFS2 filesystem in Android's Bionic library.

**1. Initial Understanding & Context:**

* **Keywords:** `bionic`, `libc`, `kernel`, `uapi`, `linux`, `nilfs2_api.h`, `Android`. These immediately tell us:
    * This is a system-level header file.
    * It defines interfaces between user space (applications using Bionic) and the Linux kernel (specifically the NILFS2 filesystem).
    * "uapi" stands for User API, further confirming the user-kernel boundary.
    * NILFS2 is a specific filesystem.
* **Auto-generated:**  The comment at the top is crucial. It warns against manual modification. This means the file is likely generated from some internal definition, perhaps in the kernel. This has implications for how closely it might match a standard Linux kernel header.
* **Includes:** `<linux/types.h>` and `<linux/ioctl.h>` are standard Linux kernel headers. `types.h` defines fundamental data types, and `ioctl.h` is essential for device control.

**2. Identifying Data Structures:**

* Scan the file for `struct`. Each `struct` represents a data structure used to exchange information. List them out and try to infer their purpose based on their names and member variables.
    * `nilfs_cpinfo`:  "cp" likely stands for CheckPoint. Members like `ci_cno` (checkpoint number), `ci_create` (creation time), `ci_nblk_inc` (block increment) suggest information *about* a checkpoint.
    * `nilfs_suinfo`: "su" likely stands for Super Unit or Superblock information. `sui_lastmod`, `sui_nblocks`, `sui_flags` point to metadata about the filesystem's state.
    * `nilfs_suinfo_update`:  Clearly for *updating* `nilfs_suinfo`.
    * `nilfs_cpmode`: Relates to checkpoint "mode".
    * `nilfs_argv`: This looks suspiciously like arguments passed to a function or system call. `v_base`, `v_nmembs`, `v_size` suggest it might describe an array or buffer.
    * `nilfs_period`:  A time range with `p_start` and `p_end`.
    * `nilfs_cpstat`: Statistics *about* checkpoints.
    * `nilfs_sustat`: Statistics about the Super Unit.
    * `nilfs_vinfo`: Likely related to volume or virtual block information.
    * `nilfs_vdesc`:  A volume descriptor.
    * `nilfs_bdesc`:  A block descriptor.

**3. Identifying Enums:**

* Look for `enum`. These define sets of named constants.
    * The enums related to `nilfs_cpinfo` and `nilfs_suinfo` clarify the meaning of their flag bits.
    * The `NILFS_SUINFO_UPDATE_*` enum specifies which fields of `nilfs_suinfo` can be updated.
    * `NILFS_CHECKPOINT` and `NILFS_SNAPSHOT` are likely related concepts within NILFS2.

**4. Identifying Macros and Inline Functions:**

* Search for `#define` and `static inline`. These define constants and small, optimized functions.
    * The `NILFS_CPINFO_FNS`, `NILFS_SUINFO_FNS`, and `NILFS_SUINFO_UPDATE_FNS` macros generate inline helper functions to check or manipulate flags within the structures. The naming convention (`nilfs_cpinfo_is_snapshot`, `nilfs_suinfo_set_dirty`, etc.) makes their purpose clear.
    * The `NILFS_IOCTL_*` defines are *critical*. They define the ioctl commands used to interact with the NILFS2 driver. The `_IOW`, `_IOR`, `_IOWR` macros are standard Linux kernel macros for creating ioctl numbers, indicating the direction of data flow (write, read, read/write). The numerical values (0x80, 0x81, etc.) are specific to the NILFS2 driver.

**5. Connecting to Android:**

* **Bionic as the Interface:**  Recognize that this header is part of Bionic, Android's C library. This means Android applications (both native and those using the NDK) will interact with the kernel's NILFS2 implementation *through* the interfaces defined here.
* **Filesystem Context:** Understand that NILFS2 is a filesystem option for Android devices (though perhaps less common than ext4/f2fs). It's used for storing data persistently.
* **ioctl as the Key Mechanism:**  The presence of `NILFS_IOCTL_*` macros signifies that the primary way Android user-space interacts with the NILFS2 kernel driver is via the `ioctl()` system call.

**6. Considering Dynamic Linking (Though Less Relevant Here):**

* Although the prompt asks about the dynamic linker, this *specific* header file doesn't directly involve dynamic linking. It defines data structures and ioctl commands. Dynamic linking is more about how shared libraries (`.so` files) are loaded and their symbols resolved. However, realize that *code* that uses these structures (likely within Bionic or other system libraries) *will* be part of dynamically linked libraries.

**7. Predicting Usage and Errors:**

* **User Space Interaction:** Think about how an application would use these definitions. It would open a file or device associated with a NILFS2 filesystem, then use the `ioctl()` system call with the defined commands and structures to manage the filesystem (e.g., creating snapshots, getting status, resizing).
* **Common Errors:**  Consider common `ioctl()` errors: invalid file descriptor, incorrect `ioctl` command number, passing incorrectly sized or formatted data structures.

**8. Frida Hooking (Conceptual):**

* Focus on the entry points: The `ioctl()` system call. A Frida hook would target this call, filtering for the specific `NILFS_IOCTL_*` command numbers to observe the data being passed between the application and the kernel.

**Self-Correction/Refinement during the Process:**

* **Initial Assumption Checks:**  Double-check initial assumptions. For example, while "su" might initially sound like "super user," in the context of a filesystem, "super unit" or "superblock information" makes more sense.
* **Contextual Understanding:** Continuously refer back to the core context: this is about user-space interaction with a kernel filesystem.
* **Clarity of Explanation:**  Focus on explaining the *why* behind things, not just the *what*. For example, explaining why `ioctl` is used.
* **Addressing All Parts of the Prompt:** Make sure to address each point in the original request (functionality, Android relation, libc implementation, dynamic linker, errors, framework/NDK path, Frida).

By following this systematic approach, breaking down the file into its components, and understanding the context within Android's system architecture, one can effectively analyze and explain the purpose and functionality of this NILFS2 header file.
这个头文件 `bionic/libc/kernel/uapi/linux/nilfs2_api.h` 定义了用户空间程序与 Linux 内核中 NILFS2 文件系统进行交互的接口。NILFS2 (New Implementation of a Log-structured File System) 是一种日志结构的文件系统。 由于它位于 `uapi` 目录下，这意味着它是用户空间可以直接使用的内核 API 定义。

下面我们详细分析一下它的功能：

**1. 功能概述:**

该头文件定义了与 NILFS2 文件系统交互所需的数据结构、枚举和 ioctl 命令。主要功能包括：

* **查询和管理检查点 (Checkpoint):**  允许用户空间程序获取检查点的信息，创建或删除检查点，以及修改检查点的模式。
* **查询和管理超级块信息 (Superblock Information):**  提供获取和更新 NILFS2 文件系统超级块相关信息的能力。
* **获取文件系统状态信息:**  允许获取文件系统的统计信息，例如段的数量、干净段的数量等。
* **管理段清理 (Segment Cleaning):**  可能涉及触发或管理 NILFS2 的段清理过程。
* **文件系统同步 (Sync):**  提供将内存中的文件系统数据刷新到磁盘的功能。
* **调整文件系统大小 (Resize):**  允许调整 NILFS2 文件系统的大小。
* **设置分配范围 (Allocation Range):**  可能用于限制新数据块的分配范围。

**2. 与 Android 功能的关系及举例说明:**

虽然 NILFS2 并非 Android 设备上最常用的文件系统 (通常是 ext4 或 F2FS)，但 Android 系统仍然可能支持它。这个头文件存在于 Bionic 中，意味着理论上 Android 用户空间程序可以通过 Bionic 提供的接口与 NILFS2 文件系统进行交互。

**举例说明:**

假设 Android 设备上的某个分区格式化为 NILFS2，一个具有 root 权限的 Android 应用程序可能使用这里定义的 ioctl 命令来执行以下操作：

* **备份文件系统状态:**  应用程序可以调用 `NILFS_IOCTL_GET_CPINFO` 获取当前检查点的信息，用于后续恢复。
* **创建快照:** 应用程序可能通过某种方式触发内核创建一个 NILFS2 快照 (虽然这个头文件本身没有直接创建快照的 ioctl，但可以通过修改检查点模式或其他机制间接实现)。
* **监控文件系统健康状况:**  应用程序可以使用 `NILFS_IOCTL_GET_SUSTAT` 获取文件系统的段状态，以便监控磁盘空间使用情况和文件系统的健康状况。

**3. libc 函数的功能实现:**

这个头文件本身**不包含任何 libc 函数的实现**。它仅仅是数据结构和常量的定义。 用户空间程序会使用标准的 libc 函数，例如 `open()`, `ioctl()` 等来与内核交互。

* **`ioctl()` 函数:**  这个是与 NILFS2 交互的关键。应用程序会打开一个与 NILFS2 文件系统关联的文件描述符 (例如，挂载点的目录)，然后调用 `ioctl()` 函数，并传入相应的 `NILFS_IOCTL_*` 命令以及数据结构指针。内核中的 NILFS2 文件系统驱动会处理这些 ioctl 命令。

**4. 涉及 dynamic linker 的功能:**

这个头文件本身**不涉及 dynamic linker 的功能**。它定义的是内核接口。Dynamic linker (在 Android 上主要是 `linker64` 或 `linker`) 负责加载和链接共享库 (`.so` 文件)。

**如果使用到这个头文件中定义的常量和结构体的代码位于一个共享库中，那么 dynamic linker 会处理该库的加载和符号解析。**

**so 布局样本 (假设一个使用了 NILFS2 API 的库):**

```
libmynilfs.so:
    .text          # 代码段
        my_nilfs_function:
            # ... 使用了 nilfs2_cpinfo 结构体的代码 ...
            mov     r0, #NILFS_IOCTL_GET_CPINFO
            # ... 调用 ioctl ...
    .rodata        # 只读数据段
        some_constant: .word NILFS_CPINFO_SNAPSHOT
    .data          # 可写数据段
        ...
    .dynamic       # 动态链接信息
        NEEDED      libc.so
        SONAME      libmynilfs.so
        ...
```

**链接的处理过程:**

1. **加载:** Dynamic linker 在程序启动或运行时加载 `libmynilfs.so`。
2. **依赖解析:** Dynamic linker 检查 `libmynilfs.so` 的依赖项，例如 `libc.so`。
3. **符号查找:** 如果 `libmynilfs.so` 中的代码使用了 `ioctl` 函数或者 `nilfs2_cpinfo` 结构体，dynamic linker 会在依赖库 (如 `libc.so`) 中查找这些符号的定义。对于结构体定义，通常是在编译时就确定了布局。
4. **重定位:** Dynamic linker 更新 `libmynilfs.so` 中对外部符号的引用，使其指向正确的内存地址。

**5. 逻辑推理 (假设输入与输出):**

假设用户空间程序想要获取一个特定检查点的信息。

**假设输入:**

* 打开 NILFS2 文件系统挂载点的文件描述符 `fd`。
* 一个 `nilfs_argv` 结构体 `arg`，其中 `arg.v_index` 设置为要查询的检查点编号。

**逻辑推理:**

程序会调用 `ioctl(fd, NILFS_IOCTL_GET_CPINFO, &arg)`。

**预期输出:**

* 如果调用成功，`ioctl` 返回 0。
* `arg.v_base` 指向的内存区域会被填充，包含一个 `nilfs_cpinfo` 结构体，其中包含指定检查点的信息，例如创建时间、块增量等。
* 如果调用失败 (例如，指定的检查点不存在)，`ioctl` 返回 -1，并设置 `errno` 指示错误类型。

**6. 用户或编程常见的使用错误:**

* **文件描述符无效:** 传递给 `ioctl` 的文件描述符没有正确打开与 NILFS2 文件系统相关的对象。
* **ioctl 命令错误:** 使用了错误的 `NILFS_IOCTL_*` 命令常量。
* **数据结构大小或内容错误:** 传递给 `ioctl` 的数据结构的大小不正确，或者成员变量的值不合法。例如，`nilfs_argv.v_size` 应该设置为 `sizeof(struct nilfs_cpinfo)` 以接收检查点信息。
* **权限不足:**  某些 ioctl 操作可能需要 root 权限才能执行。
* **并发问题:**  在多线程程序中，如果没有正确地同步对文件系统状态的访问，可能会导致数据不一致。

**举例说明:**

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/nilfs2_api.h>
#include <errno.h>

int main() {
    int fd = open("/mnt/nilfs2", O_RDONLY); // 假设 /mnt/nilfs2 是 NILFS2 的挂载点
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct nilfs_argv arg = {0};
    arg.v_index = 10; // 查询检查点编号为 10 的信息
    arg.v_size = sizeof(struct nilfs_cpinfo);
    struct nilfs_cpinfo cpinfo;
    arg.v_base = (__u64)&cpinfo;

    if (ioctl(fd, NILFS_IOCTL_GET_CPINFO, &arg) == -1) {
        perror("ioctl NILFS_IOCTL_GET_CPINFO");
        close(fd);
        return 1;
    }

    printf("Checkpoint Number: %llu\n", cpinfo.ci_cno);
    printf("Creation Time: %llu\n", cpinfo.ci_create);

    close(fd);
    return 0;
}
```

**常见错误:**

* **忘记设置 `arg.v_size`:** 如果 `arg.v_size` 设置为 0 或错误的值，`ioctl` 可能无法正确填充 `cpinfo` 结构体。
* **挂载点错误:** 如果 `/mnt/nilfs2` 不是 NILFS2 文件系统的挂载点，`open` 会失败，或者 `ioctl` 会返回错误。
* **检查点不存在:** 如果请求的检查点编号 (例如 10) 不存在，`ioctl` 可能会返回错误。

**7. Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤。**

**Android Framework 或 NDK 到达这里的路径 (理论上):**

1. **应用程序请求:** Android 应用程序 (可能是系统应用或具有 root 权限的第三方应用) 需要执行与 NILFS2 文件系统相关的操作。
2. **NDK 调用 (如果使用 NDK):** 如果是使用 NDK 开发的 native 应用，开发者会直接调用标准的 C 库函数，例如 `open()` 和 `ioctl()`。
3. **Framework 调用 (如果使用 Framework API):**  如果使用 Java Framework API，可能存在一个底层的 native 实现 (通常在 SystemServer 或其他系统服务中) 通过 JNI 调用 Bionic 提供的接口。
4. **Bionic libc:**  无论是 NDK 还是 Framework，最终都会调用 Bionic 提供的 `open()` 和 `ioctl()` 函数。
5. **系统调用:** Bionic 的 `ioctl()` 函数会发起一个 `ioctl` 系统调用，陷入 Linux 内核。
6. **内核处理:** Linux 内核接收到 `ioctl` 系统调用，根据文件描述符找到对应的文件系统驱动 (NILFS2 驱动)，并调用该驱动中处理 `NILFS_IOCTL_*` 命令的函数。
7. **返回结果:** 内核处理完成后，将结果返回给用户空间程序。

**Frida Hook 示例:**

假设我们想要监控对 `NILFS_IOCTL_GET_CPINFO` ioctl 命令的调用。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <process name or PID>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "ioctl"), {
        onEnter: function(args) {
            const fd = args[0].toInt32();
            const request = args[1].toInt32();
            const argp = args[2];

            if (request === 0xc0106e82) { // NILFS_IOCTL_GET_CPINFO 的值
                console.log("[*] ioctl called with NILFS_IOCTL_GET_CPINFO");
                console.log("    File Descriptor:", fd);
                console.log("    Request:", request);

                // 读取 nilfs_argv 结构体
                const v_base = argp.readU64();
                const v_nmembs = argp.add(8).readU32();
                const v_size = argp.add(12).readU16();
                const v_flags = argp.add(14).readU16();
                const v_index = argp.add(16).readU64();

                console.log("    nilfs_argv:");
                console.log("        v_base:", v_base.toString(16));
                console.log("        v_nmembs:", v_nmembs);
                console.log("        v_size:", v_size);
                console.log("        v_flags:", v_flags);
                console.log("        v_index:", v_index);

                if (v_size === 48) { // sizeof(struct nilfs_cpinfo)
                    const cpinfo_ptr = ptr(v_base);
                    const ci_flags = cpinfo_ptr.readU32();
                    const ci_pad = cpinfo_ptr.add(4).readU32();
                    const ci_cno = cpinfo_ptr.add(8).readU64();
                    const ci_create = cpinfo_ptr.add(16).readU64();
                    const ci_nblk_inc = cpinfo_ptr.add(24).readU64();
                    const ci_inodes_count = cpinfo_ptr.add(32).readU64();
                    const ci_blocks_count = cpinfo_ptr.add(40).readU64();

                    console.log("    nilfs_cpinfo:");
                    console.log("        ci_flags:", ci_flags);
                    console.log("        ci_cno:", ci_cno.toString());
                    console.log("        ci_create:", ci_create.toString());
                    console.log("        ci_nblk_inc:", ci_nblk_inc.toString());
                    console.log("        ci_inodes_count:", ci_inodes_count.toString());
                    console.log("        ci_blocks_count:", ci_blocks_count.toString());
                }
            }
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to exit.")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `nilfs_hook.py`。
2. 找到你想要监控的进程名称或 PID (例如，一个可能操作 NILFS2 的系统服务)。
3. 运行 Frida 脚本：`frida -U -f <进程名称> -l nilfs_hook.py` 或 `frida -U <PID> -l nilfs_hook.py`。

**Frida 脚本解释:**

* **`Interceptor.attach`:**  Hook 了 `ioctl` 函数。
* **`onEnter`:**  在 `ioctl` 函数执行之前被调用。
* **`args`:**  包含了 `ioctl` 函数的参数，分别是文件描述符、请求码和参数指针。
* **`request === 0xc0106e82`:**  检查 `ioctl` 请求码是否为 `NILFS_IOCTL_GET_CPINFO`。你需要将 `NILFS_IOCTL_GET_CPINFO` 的宏定义值转换为十六进制。
* **读取参数:**  从参数指针 `argp` 中读取 `nilfs_argv` 结构体的成员。
* **读取 `nilfs_cpinfo`:** 如果 `v_size` 表明传递的是 `nilfs_cpinfo` 结构体，则从 `v_base` 指向的内存地址读取其成员。

这个 Frida 示例可以帮助你观察哪些进程在调用与 NILFS2 相关的 ioctl 命令，以及传递的具体参数和数据。 请注意，直接操作 NILFS2 文件系统通常需要 root 权限，并且可能影响系统的稳定性，因此在实际操作中需要谨慎。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/nilfs2_api.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_NILFS2_API_H
#define _LINUX_NILFS2_API_H
#include <linux/types.h>
#include <linux/ioctl.h>
struct nilfs_cpinfo {
  __u32 ci_flags;
  __u32 ci_pad;
  __u64 ci_cno;
  __u64 ci_create;
  __u64 ci_nblk_inc;
  __u64 ci_inodes_count;
  __u64 ci_blocks_count;
  __u64 ci_next;
};
enum {
  NILFS_CPINFO_SNAPSHOT,
  NILFS_CPINFO_INVALID,
  NILFS_CPINFO_SKETCH,
  NILFS_CPINFO_MINOR,
};
#define NILFS_CPINFO_FNS(flag,name) static inline int nilfs_cpinfo_ ##name(const struct nilfs_cpinfo * cpinfo) \
{ return ! ! (cpinfo->ci_flags & (1UL << NILFS_CPINFO_ ##flag)); \
}
struct nilfs_suinfo {
  __u64 sui_lastmod;
  __u32 sui_nblocks;
  __u32 sui_flags;
};
enum {
  NILFS_SUINFO_ACTIVE,
  NILFS_SUINFO_DIRTY,
  NILFS_SUINFO_ERROR,
};
#define NILFS_SUINFO_FNS(flag,name) static inline int nilfs_suinfo_ ##name(const struct nilfs_suinfo * si) \
{ return si->sui_flags & (1UL << NILFS_SUINFO_ ##flag); \
}
struct nilfs_suinfo_update {
  __u64 sup_segnum;
  __u32 sup_flags;
  __u32 sup_reserved;
  struct nilfs_suinfo sup_sui;
};
enum {
  NILFS_SUINFO_UPDATE_LASTMOD,
  NILFS_SUINFO_UPDATE_NBLOCKS,
  NILFS_SUINFO_UPDATE_FLAGS,
  __NR_NILFS_SUINFO_UPDATE_FIELDS,
};
#define NILFS_SUINFO_UPDATE_FNS(flag,name) static inline void nilfs_suinfo_update_set_ ##name(struct nilfs_suinfo_update * sup) \
{ sup->sup_flags |= 1UL << NILFS_SUINFO_UPDATE_ ##flag; \
} static inline void nilfs_suinfo_update_clear_ ##name(struct nilfs_suinfo_update * sup) \
{ sup->sup_flags &= ~(1UL << NILFS_SUINFO_UPDATE_ ##flag); \
} static inline int nilfs_suinfo_update_ ##name(const struct nilfs_suinfo_update * sup) \
{ return ! ! (sup->sup_flags & (1UL << NILFS_SUINFO_UPDATE_ ##flag)); \
}
enum {
  NILFS_CHECKPOINT,
  NILFS_SNAPSHOT,
};
struct nilfs_cpmode {
  __u64 cm_cno;
  __u32 cm_mode;
  __u32 cm_pad;
};
struct nilfs_argv {
  __u64 v_base;
  __u32 v_nmembs;
  __u16 v_size;
  __u16 v_flags;
  __u64 v_index;
};
struct nilfs_period {
  __u64 p_start;
  __u64 p_end;
};
struct nilfs_cpstat {
  __u64 cs_cno;
  __u64 cs_ncps;
  __u64 cs_nsss;
};
struct nilfs_sustat {
  __u64 ss_nsegs;
  __u64 ss_ncleansegs;
  __u64 ss_ndirtysegs;
  __u64 ss_ctime;
  __u64 ss_nongc_ctime;
  __u64 ss_prot_seq;
};
struct nilfs_vinfo {
  __u64 vi_vblocknr;
  __u64 vi_start;
  __u64 vi_end;
  __u64 vi_blocknr;
};
struct nilfs_vdesc {
  __u64 vd_ino;
  __u64 vd_cno;
  __u64 vd_vblocknr;
  struct nilfs_period vd_period;
  __u64 vd_blocknr;
  __u64 vd_offset;
  __u32 vd_flags;
  __u32 vd_pad;
};
struct nilfs_bdesc {
  __u64 bd_ino;
  __u64 bd_oblocknr;
  __u64 bd_blocknr;
  __u64 bd_offset;
  __u32 bd_level;
  __u32 bd_pad;
};
#define NILFS_IOCTL_IDENT 'n'
#define NILFS_IOCTL_CHANGE_CPMODE _IOW(NILFS_IOCTL_IDENT, 0x80, struct nilfs_cpmode)
#define NILFS_IOCTL_DELETE_CHECKPOINT _IOW(NILFS_IOCTL_IDENT, 0x81, __u64)
#define NILFS_IOCTL_GET_CPINFO _IOR(NILFS_IOCTL_IDENT, 0x82, struct nilfs_argv)
#define NILFS_IOCTL_GET_CPSTAT _IOR(NILFS_IOCTL_IDENT, 0x83, struct nilfs_cpstat)
#define NILFS_IOCTL_GET_SUINFO _IOR(NILFS_IOCTL_IDENT, 0x84, struct nilfs_argv)
#define NILFS_IOCTL_GET_SUSTAT _IOR(NILFS_IOCTL_IDENT, 0x85, struct nilfs_sustat)
#define NILFS_IOCTL_GET_VINFO _IOWR(NILFS_IOCTL_IDENT, 0x86, struct nilfs_argv)
#define NILFS_IOCTL_GET_BDESCS _IOWR(NILFS_IOCTL_IDENT, 0x87, struct nilfs_argv)
#define NILFS_IOCTL_CLEAN_SEGMENTS _IOW(NILFS_IOCTL_IDENT, 0x88, struct nilfs_argv[5])
#define NILFS_IOCTL_SYNC _IOR(NILFS_IOCTL_IDENT, 0x8A, __u64)
#define NILFS_IOCTL_RESIZE _IOW(NILFS_IOCTL_IDENT, 0x8B, __u64)
#define NILFS_IOCTL_SET_ALLOC_RANGE _IOW(NILFS_IOCTL_IDENT, 0x8C, __u64[2])
#define NILFS_IOCTL_SET_SUINFO _IOW(NILFS_IOCTL_IDENT, 0x8D, struct nilfs_argv)
#endif

"""

```