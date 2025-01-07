Response:
Let's break down the thought process for generating the comprehensive answer to the user's request.

**1. Understanding the Request:**

The core request is to analyze the provided C header file (`ext4.h`) located within the Android Bionic library. The user wants to understand its functions, its relationship to Android, implementation details (especially for libc functions), dynamic linking aspects, potential errors, and how it's reached from the Android framework/NDK, along with a Frida hook example.

**2. Initial Analysis of the Header File:**

* **Purpose:** The `#ifndef _UAPI_LINUX_EXT4_H` suggests this is a header file defining the user-space API for interacting with the ext4 filesystem in the Linux kernel. The comment "This file is auto-generated. Modifications will be lost" indicates it's derived from the kernel source.
* **Key Elements:** The file primarily consists of `#define` macros defining constants and especially I/O control commands (`ioctl`). There are also some struct definitions.
* **Lack of Implementation:**  Crucially, this is a *header file*. It declares interfaces but doesn't contain the actual implementation of any functions. This is a fundamental point to address.

**3. Categorizing the Content:**

The header file's contents naturally fall into these categories:

* **ioctl definitions:** These are the primary functions defined, allowing user-space programs to send commands to the kernel's ext4 driver.
* **Constants:**  Various `#define`s represent flags, error codes, or other significant values.
* **Structures:** These define the data structures used to pass information between user-space and the kernel via the ioctl calls.

**4. Addressing Specific Questions:**

Now, let's address each part of the user's query systematically:

* **功能 (Functions):** The core functionality is provided by the `ioctl` commands. List and describe each one. Since it's a header file, emphasize that these aren't *libc functions* in the traditional sense but define *kernel interfaces*.
* **与 Android 的关系 (Relationship to Android):**  Android uses the Linux kernel, and the ext4 filesystem is a common filesystem on Android devices. The `ioctl` commands allow Android to manage the filesystem. Give examples of how Android components (like `vold`, `fsck`, `mkfs`) might use these calls.
* **libc 函数的实现 (Implementation of libc functions):** This is a crucial point to clarify. The *header file* doesn't implement libc functions. Instead, it *defines* the interface for kernel interaction. Explain how libc's `ioctl()` system call is used to invoke these commands. Mention that the *kernel* implements the actual ext4 functionality.
* **dynamic linker 的功能 (Dynamic linker functions):**  This header file doesn't directly involve the dynamic linker. Explain why – it defines kernel interfaces, not shared library functions that would be linked. Mention that the *programs* using these calls (like `vold`) *do* use the dynamic linker to load libc.
* **逻辑推理 (Logical deduction):**  For `ioctl`, the input is often a file descriptor and potentially a structure. The output can be a status code or modified data in the provided structure. Give simple examples.
* **使用错误 (Common usage errors):** Focus on incorrect usage of `ioctl`, like wrong command codes, incorrect structure sizes, or permission issues.
* **Android framework/NDK 到达这里 (Path from Android framework/NDK):**  Describe the chain: Framework/NDK -> system calls (via JNI for Java, directly for native) -> libc's `ioctl()` -> kernel's `ioctl` handler -> ext4 driver.
* **Frida hook 示例 (Frida hook example):**  Provide an example of hooking the `ioctl` function and filtering for the specific `EXT4_IOC_*` commands. This is practical and demonstrates how to observe these interactions.

**5. Structuring the Answer:**

Organize the information logically with clear headings for each part of the user's request. Use bullet points for lists of ioctl commands and other items. Use code blocks for the Frida example.

**6. Emphasizing Key Distinctions:**

Continuously reiterate the difference between the header file's *definitions* and the *implementation* within the kernel. Clarify the role of libc's `ioctl()` as the bridge.

**7. Refining the Language:**

Use clear and concise Chinese. Avoid overly technical jargon where possible, or explain it if necessary.

**Self-Correction/Refinement during the thought process:**

* **Initial Thought:** Maybe I should describe the ext4 filesystem in detail.
* **Correction:** The request focuses on the *header file*. Keep the focus narrow and avoid going too deep into filesystem internals unless directly relevant to the defined ioctl commands.
* **Initial Thought:**  I should show how to implement a function using these ioctl commands.
* **Correction:** The request asks about the *header file*. Providing a full implementation would be excessive. Focus on demonstrating *usage* through the Frida hook and explaining the general flow.
* **Initial Thought:**  The dynamic linker section is tricky.
* **Correction:** The key is to explain *why* this header file *doesn't* directly involve the dynamic linker. The programs that *use* these definitions do, but the header itself is about kernel interfaces.

By following this structured thought process, focusing on the user's specific questions, and making necessary refinements, we can arrive at a comprehensive and accurate answer.
好的，让我们来详细分析一下 `bionic/libc/kernel/uapi/linux/ext4.h` 这个头文件。

**功能概述:**

这个头文件定义了用户空间程序与 Linux 内核中 ext4 文件系统驱动程序进行交互的接口。它主要通过定义一系列的 ioctl (输入/输出控制) 命令来实现这一点。这些 ioctl 命令允许用户空间程序向内核发送指令，以执行与 ext4 文件系统相关的特定操作。

**具体功能列表:**

以下是头文件中定义的各个宏和结构体及其功能的详细解释：

* **`EXT4_IOC_GETVERSION` / `EXT4_IOC_SETVERSION`:**
    * 功能：获取和设置 ext4 文件系统的版本号。这通常用于检查文件系统是否为期望的版本，或者在某些情况下，可能用于升级文件系统（虽然直接通过 ioctl 升级文件系统版本的情况比较少见）。
    * 数据类型：`long`
* **`EXT4_IOC_GETVERSION_OLD` / `EXT4_IOC_SETVERSION_OLD`:**
    * 功能：为了兼容性而保留的旧版本获取和设置文件系统版本号的宏，它们实际上映射到 `FS_IOC_GETVERSION` 和 `FS_IOC_SETVERSION`，这是更通用的文件系统 ioctl。
* **`EXT4_IOC_GETRSVSZ` / `EXT4_IOC_SETRSVSZ`:**
    * 功能：获取和设置文件系统预留空间的大小。预留空间是文件系统为了保证关键操作的顺利进行而保留的一部分磁盘空间，例如防止在写入关键元数据时磁盘空间耗尽。
    * 数据类型：`long`
* **`EXT4_IOC_GROUP_EXTEND`:**
    * 功能：扩展文件系统中的块组。块组是 ext4 文件系统组织磁盘空间的基本单元。扩展块组意味着增加文件系统的容量。
    * 数据类型：`unsigned long` (表示要扩展的块的数量)
* **`EXT4_IOC_GROUP_ADD`:**
    * 功能：向文件系统添加新的块组。这类似于 `EXT4_IOC_GROUP_EXTEND`，但可能涉及更底层的分配和初始化过程。
    * 数据类型：`struct ext4_new_group_input` (包含新块组的起始地址、位图地址等信息)
* **`EXT4_IOC_MIGRATE`:**
    * 功能：迁移文件系统中的数据块。这可能用于优化磁盘布局、碎片整理或将数据移动到性能更好的存储介质上。
* **`EXT4_IOC_ALLOC_DA_BLKS`:**
    * 功能：分配延迟分配（DA）块。延迟分配是一种性能优化技术，允许文件系统推迟实际的磁盘块分配，直到数据真正写入磁盘。
* **`EXT4_IOC_MOVE_EXT`:**
    * 功能：在文件系统内部移动一个文件的 extent (连续的磁盘块)。这通常用于碎片整理或优化文件布局。
    * 数据类型：`struct move_extent` (包含源文件描述符、起始位置、目标起始位置、长度等信息)
* **`EXT4_IOC_RESIZE_FS`:**
    * 功能：调整文件系统的大小。这允许在运行时动态地增加或减少文件系统的容量。
    * 数据类型：`__u64` (表示新的文件系统大小)
* **`EXT4_IOC_SWAP_BOOT`:**
    * 功能：交换启动扇区。这允许在不重新格式化文件系统的情况下更改引导加载程序。
* **`EXT4_IOC_PRECACHE_EXTENTS`:**
    * 功能：预先缓存文件的 extent 信息。这可以提高文件访问性能，特别是对于大文件。
* **`EXT4_IOC_CLEAR_ES_CACHE`:**
    * 功能：清除 extent 状态缓存。extent 状态缓存用于记录文件的 extent 的状态，清除缓存可能用于解决某些一致性问题。
* **`EXT4_IOC_GETSTATE`:**
    * 功能：获取文件系统的状态标志。这些标志指示文件系统的当前状态，例如是否正在进行某些操作。
    * 数据类型：`__u32` (状态标志的位掩码)
* **`EXT4_IOC_GET_ES_CACHE`:**
    * 功能：获取 extent 状态缓存的信息。
    * 数据类型：`struct fiemap` (描述文件 extent 的映射信息)
* **`EXT4_IOC_CHECKPOINT`:**
    * 功能：创建一个文件系统检查点。检查点用于在文件系统出现问题时进行恢复。
    * 数据类型：`__u32` (检查点标志)
* **`EXT4_IOC_GETFSUUID` / `EXT4_IOC_SETFSUUID`:**
    * 功能：获取和设置文件系统的 UUID (通用唯一标识符)。UUID 用于唯一标识文件系统。
    * 数据类型：`struct fsuuid` (包含 UUID 数据)
* **`EXT4_IOC_SHUTDOWN`:**
    * 功能：安全地关闭文件系统。这会确保所有挂起的写入操作都已完成，并释放相关资源。
    * 数据类型：`__u32` (通常用于传递关闭标志)

**结构体:**

* **`struct fsuuid`:**  定义了文件系统 UUID 的结构，包含长度、标志和 UUID 数据。
* **`struct move_extent`:** 定义了 `EXT4_IOC_MOVE_EXT` 命令的参数，描述了要移动的 extent 的源和目标位置。
* **`struct ext4_new_group_input`:** 定义了 `EXT4_IOC_GROUP_ADD` 命令的参数，描述了要添加的新块组的元数据信息。

**与 Android 功能的关系及举例说明:**

这个头文件定义的接口对于 Android 系统的正常运行至关重要，因为 Android 系统广泛使用 ext4 文件系统作为其主要的文件系统。以下是一些示例：

* **`vold` (Volume Daemon):** `vold` 是 Android 中负责管理存储设备的守护进程。它使用这些 ioctl 命令来创建、挂载、卸载和调整存储卷的大小，例如内部存储、SD 卡等。例如，当格式化一个 SD 卡时，`vold` 可能会使用 `EXT4_IOC_RESIZE_FS` 或类似的命令来设置文件系统的大小。
* **`fsck_ext4` (File System Check):** `fsck_ext4` 是 ext4 文件系统的检查工具，用于检测和修复文件系统中的错误。它可能会使用 `EXT4_IOC_GETVERSION` 来验证文件系统的版本，并可能在修复过程中使用其他 ioctl 命令。
* **`mkfs.ext4` (Make File System):**  `mkfs.ext4` 是用于创建 ext4 文件系统的工具。它在创建文件系统时会涉及设置初始的文件系统结构，可能使用底层的 ioctl 命令来分配块组、设置元数据等。
* **OTA (Over-The-Air) 更新:** 在 Android 系统进行 OTA 更新时，可能需要调整分区大小或进行其他文件系统操作，这可能会涉及到这些 ioctl 命令。
* **存储性能优化:** Android 系统可能会在后台使用一些机制来优化存储性能，例如通过 `EXT4_IOC_MOVE_EXT` 移动文件 extent 来减少碎片。

**libc 函数的实现:**

这个头文件本身**不是** libc 函数的实现。它定义的是与内核交互的接口，即 `ioctl` 命令的编号和参数结构。

当用户空间程序想要执行这些操作时，它会调用 libc 提供的 `ioctl()` 函数。`ioctl()` 是一个系统调用，它会将命令和数据传递给内核。内核接收到 `ioctl()` 调用后，会根据命令编号（例如 `EXT4_IOC_RESIZE_FS`）将其分发给相应的设备驱动程序处理，在本例中是 ext4 文件系统驱动程序。

**简而言之，这个头文件定义了接口，而 libc 的 `ioctl()` 函数提供了使用这个接口的方式，内核的 ext4 驱动程序负责接口的具体实现。**

**涉及 dynamic linker 的功能及 so 布局样本和链接处理过程:**

这个头文件本身**不直接涉及** dynamic linker (动态链接器)。Dynamic linker 的作用是在程序运行时加载和链接共享库 (`.so` 文件)。

然而，**使用这个头文件中定义的接口的程序** (例如 `vold`, `fsck_ext4`)  会链接到 libc，并且 libc 本身是一个共享库。

**so 布局样本 (libc):**

```
/system/lib64/libc.so (或 /system/lib/libc.so，取决于架构)

  节 (Section):
    .text          (代码段)
    .rodata        (只读数据段)
    .data          (已初始化数据段)
    .bss           (未初始化数据段)
    .dynsym        (动态符号表)
    .dynstr        (动态字符串表)
    .plt           (过程链接表)
    .got.plt       (全局偏移量表，用于 PLT)
    ... 其他节 ...
```

**链接的处理过程:**

1. **编译时链接:** 当编译 `vold` 或 `fsck_ext4` 等程序时，编译器会知道这些程序需要使用 libc 提供的 `ioctl()` 函数。链接器会将对 `ioctl()` 的调用标记为需要动态链接。
2. **运行时加载:** 当 Android 系统启动这些程序时，`linker64` (或 `linker`) 动态链接器会被调用。
3. **加载共享库:**  `linker` 会根据程序头中的信息，找到并加载 `libc.so` 到内存中。
4. **符号解析:** `linker` 会解析程序中对 `ioctl()` 的调用，并将其与 `libc.so` 中 `ioctl()` 函数的地址关联起来。这通常通过查看 `.dynsym` 和 `.dynstr` 表以及使用 `.plt` 和 `.got.plt` 完成。
5. **重定位:**  由于共享库被加载到内存中的位置可能不固定，`linker` 需要修改程序中的某些地址（例如 `got.plt` 中的地址）以指向 `libc.so` 中正确的函数地址。

**总结：** 虽然 `ext4.h` 不直接涉及 dynamic linker，但它定义的接口通过 libc 的 `ioctl()` 函数被用户空间程序使用，而这些程序会动态链接到 libc。

**逻辑推理及假设输入与输出:**

以 `EXT4_IOC_GETVERSION` 为例：

* **假设输入:**
    * 一个打开的 ext4 文件系统的文件描述符 `fd`。
* **逻辑推理:** 当程序调用 `ioctl(fd, EXT4_IOC_GETVERSION, &version)` 时，内核会接收到这个调用，并识别出是获取 ext4 文件系统版本的请求。内核的 ext4 驱动程序会读取文件系统的超级块（superblock）中的版本信息，并将其存储到用户空间提供的 `version` 变量中。
* **预期输出:**
    * `ioctl()` 函数返回 0 表示成功。
    * `version` 变量被填充为文件系统的版本号（例如，一个整数）。

以 `EXT4_IOC_RESIZE_FS` 为例：

* **假设输入:**
    * 一个打开的 ext4 文件系统的文件描述符 `fd`。
    * 一个表示新的文件系统大小的 `__u64` 类型的变量 `new_size`。
* **逻辑推理:** 当程序调用 `ioctl(fd, EXT4_IOC_RESIZE_FS, new_size)` 时，内核会接收到这个调用，并识别出是调整文件系统大小的请求。内核的 ext4 驱动程序会进行一系列检查，例如是否有足够的可用空间，并执行调整大小的操作。这可能涉及到修改文件系统的元数据。
* **预期输出:**
    * `ioctl()` 函数返回 0 表示成功。
    * 如果调整大小失败（例如，空间不足），`ioctl()` 函数可能返回 -1，并设置 `errno` 以指示错误原因。

**用户或编程常见的使用错误:**

* **使用错误的 ioctl 命令编号:** 如果传递给 `ioctl()` 函数的命令编号与期望的操作不符，内核可能会返回错误。
* **传递不正确的参数结构:**  对于需要传递结构体的 ioctl 命令，如果结构体的定义不正确（例如大小错误、字段顺序错误），内核可能无法正确解析参数，导致错误或未定义的行为。
* **权限不足:**  某些 ioctl 操作可能需要特定的权限。如果调用进程没有足够的权限，`ioctl()` 函数会返回错误（例如 `EPERM`）。
* **在错误的文件描述符上调用:**  `ioctl()` 函数需要一个有效的文件描述符。如果文件描述符无效或者不是一个 ext4 文件系统的文件描述符，调用将会失败。
* **不检查 `ioctl()` 的返回值:**  `ioctl()` 函数会返回一个值来指示操作是否成功。忽略返回值可能导致程序在操作失败的情况下继续执行，从而引发问题。
* **在高并发场景下不进行同步:** 某些 ioctl 操作可能会影响文件系统的状态，在高并发环境下不进行适当的同步可能会导致数据不一致或其他问题。

**Android framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java 代码):**
   * 在 Android Framework 中，与文件系统操作相关的请求通常会通过 `java.io.File` 或 `android.os.storage.StorageManager` 等类进行。
   * 这些类的方法最终会调用底层的 Native 代码 (C/C++)。
   * 例如，`StorageManager.mkdirs()` 方法在底层可能会调用 `mkdir()` 系统调用。

2. **Native 代码 (C/C++ 代码，包括 NDK 代码):**
   * NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的一部分。
   * 在 Native 代码中，可以直接调用 libc 提供的文件系统相关的函数，例如 `open()`, `read()`, `write()`, `ioctl()` 等。
   * 当需要执行 ext4 特定的操作时，Native 代码会调用 `ioctl()` 函数，并传入 `ext4.h` 中定义的 `EXT4_IOC_*` 命令编号和相应的参数。

3. **libc (Bionic):**
   * libc 是 Android 的 C 标准库。
   * 当 Native 代码调用 `ioctl()` 函数时，实际上调用的是 Bionic 库中 `ioctl()` 的实现。
   * Bionic 的 `ioctl()` 函数是一个系统调用包装器，它会将用户空间的请求转换为内核可以理解的格式，并传递给内核。

4. **Linux Kernel:**
   * Android 底层是 Linux 内核。
   * 当内核接收到 `ioctl()` 系统调用时，它会根据文件描述符找到对应的设备驱动程序。
   * 对于 ext4 文件系统的文件描述符，内核会将 `ioctl()` 调用传递给 ext4 文件系统驱动程序。
   * ext4 驱动程序会根据 `ioctl` 命令编号执行相应的操作，并返回结果。

**Frida hook 示例调试这些步骤:**

以下是一个使用 Frida hook `ioctl` 系统调用的示例，用于观察与 ext4 相关的 ioctl 调用：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python frida_ioctl_hook.py <process_name_or_pid>")
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

            const EXT4_IOC_MAGIC = 0x66; // 'f'

            if (((request >> 8) & 0xFF) === EXT4_IOC_MAGIC) {
                let commandName = "UNKNOWN_EXT4_IOC";
                switch (request) {
                    case 0xc0086607: commandName = "EXT4_IOC_GROUP_EXTEND"; break;
                    case 0xc0106608: commandName = "EXT4_IOC_GROUP_ADD"; break;
                    case 0xc0186610: commandName = "EXT4_IOC_RESIZE_FS"; break;
                    // ... 添加其他 EXT4_IOC 命令 ...
                }
                console.log("[IOCTL] fd:", fd, "request:", request.toString(16), "(" + commandName + ")");
                // 可以进一步解析 argp 指向的数据
            }
        },
        onLeave: function(retval) {
            // console.log("ioctl returned:", retval.toInt32());
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Waiting for ioctl calls...")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**使用方法:**

1. 将上述 Python 代码保存为 `frida_ioctl_hook.py`。
2. 找到你想要监控的进程的名称或 PID (例如，`vold` 或你的 NDK 应用的进程名)。
3. 运行命令：`python frida_ioctl_hook.py <process_name_or_pid>`
4. 当目标进程执行与 ext4 相关的 ioctl 调用时，Frida 会拦截这些调用并在控制台上打印相关信息，包括文件描述符和 ioctl 命令编号。你需要根据 `ext4.h` 中的定义将命令编号转换为对应的宏名称。

**注意:**  你需要安装 Frida 和 frida-tools 才能运行此脚本。你可能还需要 root 权限才能 attach 到某些系统进程。

希望这个详细的解释能够帮助你理解 `bionic/libc/kernel/uapi/linux/ext4.h` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/ext4.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_EXT4_H
#define _UAPI_LINUX_EXT4_H
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#define EXT4_IOC_GETVERSION _IOR('f', 3, long)
#define EXT4_IOC_SETVERSION _IOW('f', 4, long)
#define EXT4_IOC_GETVERSION_OLD FS_IOC_GETVERSION
#define EXT4_IOC_SETVERSION_OLD FS_IOC_SETVERSION
#define EXT4_IOC_GETRSVSZ _IOR('f', 5, long)
#define EXT4_IOC_SETRSVSZ _IOW('f', 6, long)
#define EXT4_IOC_GROUP_EXTEND _IOW('f', 7, unsigned long)
#define EXT4_IOC_GROUP_ADD _IOW('f', 8, struct ext4_new_group_input)
#define EXT4_IOC_MIGRATE _IO('f', 9)
#define EXT4_IOC_ALLOC_DA_BLKS _IO('f', 12)
#define EXT4_IOC_MOVE_EXT _IOWR('f', 15, struct move_extent)
#define EXT4_IOC_RESIZE_FS _IOW('f', 16, __u64)
#define EXT4_IOC_SWAP_BOOT _IO('f', 17)
#define EXT4_IOC_PRECACHE_EXTENTS _IO('f', 18)
#define EXT4_IOC_CLEAR_ES_CACHE _IO('f', 40)
#define EXT4_IOC_GETSTATE _IOW('f', 41, __u32)
#define EXT4_IOC_GET_ES_CACHE _IOWR('f', 42, struct fiemap)
#define EXT4_IOC_CHECKPOINT _IOW('f', 43, __u32)
#define EXT4_IOC_GETFSUUID _IOR('f', 44, struct fsuuid)
#define EXT4_IOC_SETFSUUID _IOW('f', 44, struct fsuuid)
#define EXT4_IOC_SHUTDOWN _IOR('X', 125, __u32)
#define EXT4_IOC32_GETVERSION _IOR('f', 3, int)
#define EXT4_IOC32_SETVERSION _IOW('f', 4, int)
#define EXT4_IOC32_GETRSVSZ _IOR('f', 5, int)
#define EXT4_IOC32_SETRSVSZ _IOW('f', 6, int)
#define EXT4_IOC32_GROUP_EXTEND _IOW('f', 7, unsigned int)
#define EXT4_IOC32_GROUP_ADD _IOW('f', 8, struct compat_ext4_new_group_input)
#define EXT4_IOC32_GETVERSION_OLD FS_IOC32_GETVERSION
#define EXT4_IOC32_SETVERSION_OLD FS_IOC32_SETVERSION
#define EXT4_STATE_FLAG_EXT_PRECACHED 0x00000001
#define EXT4_STATE_FLAG_NEW 0x00000002
#define EXT4_STATE_FLAG_NEWENTRY 0x00000004
#define EXT4_STATE_FLAG_DA_ALLOC_CLOSE 0x00000008
#define EXT4_IOC_CHECKPOINT_FLAG_DISCARD 0x1
#define EXT4_IOC_CHECKPOINT_FLAG_ZEROOUT 0x2
#define EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN 0x4
#define EXT4_IOC_CHECKPOINT_FLAG_VALID (EXT4_IOC_CHECKPOINT_FLAG_DISCARD | EXT4_IOC_CHECKPOINT_FLAG_ZEROOUT | EXT4_IOC_CHECKPOINT_FLAG_DRY_RUN)
struct fsuuid {
  __u32 fsu_len;
  __u32 fsu_flags;
  __u8 fsu_uuid[];
};
struct move_extent {
  __u32 reserved;
  __u32 donor_fd;
  __u64 orig_start;
  __u64 donor_start;
  __u64 len;
  __u64 moved_len;
};
#define EXT4_GOING_FLAGS_DEFAULT 0x0
#define EXT4_GOING_FLAGS_LOGFLUSH 0x1
#define EXT4_GOING_FLAGS_NOLOGFLUSH 0x2
struct ext4_new_group_input {
  __u32 group;
  __u64 block_bitmap;
  __u64 inode_bitmap;
  __u64 inode_table;
  __u32 blocks_count;
  __u16 reserved_blocks;
  __u16 unused;
};
#define EXT4_FIEMAP_EXTENT_HOLE 0x08000000
#endif

"""

```