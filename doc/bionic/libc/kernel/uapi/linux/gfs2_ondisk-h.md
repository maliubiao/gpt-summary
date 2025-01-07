Response:
Let's break down the thought process to answer the user's request about the `gfs2_ondisk.h` header file.

**1. Understanding the Request:**

The user wants a comprehensive analysis of the provided C header file, `gfs2_ondisk.h`. Specifically, they're interested in:

* **Functionality:** What does this file define?
* **Android Relevance:** How does it relate to Android?
* **Libc Functions:**  Detailed explanation of *each* libc function.
* **Dynamic Linker:** Information about dynamic linking, including SO layout and linking process.
* **Logic Inference:**  Examples of input/output.
* **Common Errors:** Potential usage mistakes.
* **Android Framework/NDK Interaction:** How Android code reaches this file.
* **Frida Hooking:** Examples for debugging.

**2. Initial Assessment of the Header File:**

The first step is to examine the content of `gfs2_ondisk.h`. Key observations:

* **`auto-generated` and `bionic`:**  This immediately tells us it's part of Android's libc and generated from some other source (likely kernel headers). This means direct manipulation is discouraged, and it reflects the underlying Linux kernel's GFS2 filesystem structure.
* **Includes `linux/types.h`:**  Confirms it's related to the Linux kernel.
* **Defines Constants (`#define`):** A large number of constants related to magic numbers, block sizes, lock types, file formats, metadata types, and various flags.
* **Defines Structures (`struct`):**  Several structures representing on-disk data structures for the GFS2 filesystem (superblock, inodes, directory entries, resource groups, etc.).
* **No Function Declarations:**  Crucially, there are *no* function declarations within this header. This means it defines *data structures* and *constants*, not the implementation of operations on those structures.

**3. Addressing Each Point of the Request:**

Now, let's go through each point of the user's request systematically:

* **Functionality:**  Since there are no functions, the functionality is about *defining the data structures and constants* necessary for interacting with the GFS2 filesystem. This includes the layout of metadata on disk.

* **Android Relevance:**  This is where the understanding of the `bionic` path is vital. This header defines the *interface* for how Android's kernel (which is still Linux-based) interacts with a GFS2 filesystem. If an Android device were formatted with GFS2 (which is rare, ext4 is the norm), the kernel would use these definitions. *Crucially*,  Android's userspace (apps, etc.) doesn't directly interact with these structures. Filesystem operations go through system calls. So, the relevance is at the *kernel driver* level.

* **Libc Functions:**  This is a key point where the initial assessment pays off. Since the file *only defines data structures*, there are *no libc functions implemented in this file*. The confusion might arise from its location within the `bionic/libc` directory. The explanation needs to emphasize this distinction.

* **Dynamic Linker:** Similar to the libc functions, this header file itself doesn't involve dynamic linking. Dynamic linking happens at the userspace level with shared libraries (`.so`). This header is used by the kernel. The answer needs to clarify this and provide a general explanation of dynamic linking in Android, even if this specific file isn't directly involved. Providing a sample `.so` layout and the linking process is helpful for the user's broader understanding.

* **Logic Inference:**  Because this file defines data structures, "logic inference" isn't about the *code* within this file. Instead, it's about understanding how these structures are used. The example provided focuses on the relationship between the `GFS2_BASIC_BLOCK_SHIFT` and `GFS2_BASIC_BLOCK` constants and how they determine the block size.

* **Common Errors:** The most common error isn't in *using* this file directly (since it's a kernel header), but rather in *misunderstanding its purpose*. Developers shouldn't try to directly manipulate these structures in userspace code.

* **Android Framework/NDK Interaction:** This requires tracing the path from high-level Android operations down to the kernel. The example starts with a simple file write operation in Java, goes through the Android framework, native code (possibly using NDK), and ultimately results in a system call. The kernel then uses these `gfs2_ondisk.h` definitions if the underlying filesystem is GFS2.

* **Frida Hooking:**  Since the interaction is primarily at the kernel level, Frida hooking would need to target kernel functions or system calls related to filesystem operations. The example demonstrates hooking the `write` system call and filtering for GFS2-related context.

**4. Structuring the Answer:**

The final step is to organize the information clearly and address each point of the user's request. Using headings and bullet points makes the answer easier to read and understand. It's important to be precise and address any potential misunderstandings (like the role of libc functions).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps I need to find the *implementation* of GFS2 functions within libc.
* **Correction:**  Realization that this is a *header file* defining data structures, not implementing functions. The implementation is in the Linux kernel.
* **Initial thought:** Focus only on GFS2.
* **Refinement:** Explain the broader context of filesystem interaction in Android and the role of the kernel.
* **Initial thought:**  Provide a very specific Frida hook for GFS2 internals.
* **Refinement:** Provide a more general example of hooking a system call relevant to filesystem operations, as directly hooking GFS2 internal kernel functions might be too complex for a general explanation.

By following this thought process, including the self-correction and refinement steps, we arrive at the comprehensive and accurate answer provided earlier.
这个文件 `bionic/libc/kernel/uapi/linux/gfs2_ondisk.h` 是 Android Bionic 库的一部分，它不是一个源代码文件，而是一个 **头文件**。这个头文件定义了 Linux 内核中 GFS2 文件系统的 **磁盘数据结构 (on-disk data structures)** 和相关的 **常量**。

**功能列举：**

该头文件的主要功能是提供 C 语言定义，描述了 GFS2 文件系统在磁盘上的组织方式。它定义了以下内容：

1. **魔数 (Magic Numbers):** 用于标识 GFS2 文件系统及其内部不同数据结构的常量，例如 `GFS2_MAGIC`。
2. **块大小 (Block Size):** 定义了 GFS2 文件系统的基本块大小，例如 `GFS2_BASIC_BLOCK` 和 `GFS2_BASIC_BLOCK_SHIFT`。
3. **锁类型 (Lock Types):** 定义了 GFS2 使用的不同锁类型，例如 `GFS2_MOUNT_LOCK`，`GFS2_LIVE_LOCK` 等。
4. **格式类型 (Format Types):** 定义了 GFS2 磁盘上不同数据块的格式类型，例如 `GFS2_FORMAT_SB` (superblock)，`GFS2_FORMAT_RG` (resource group) 等。
5. **元数据类型 (Metadata Types):** 定义了 GFS2 文件系统中不同元数据的类型，例如 `GFS2_METATYPE_SB`，`GFS2_METATYPE_RG` 等。
6. **数据结构 (Structures):** 定义了 GFS2 文件系统在磁盘上存储的各种数据结构，例如：
    * `gfs2_inum`: inode 的标识信息。
    * `gfs2_meta_header`: 所有 GFS2 元数据块的通用头部。
    * `gfs2_sb`: 超级块 (superblock) 的结构。
    * `gfs2_rindex`: 资源索引的结构。
    * `gfs2_rgrp`: 资源组的结构。
    * `gfs2_dinode`: 磁盘 inode 的结构。
    * `gfs2_dirent`: 目录项的结构。
    * `gfs2_leaf`: 目录叶子节点的结构。
    * `gfs2_ea_header`: 扩展属性的头部结构。
    * `gfs2_log_header`: 日志头部的结构。
    * `gfs2_log_descriptor`: 日志描述符的结构。
    * `gfs2_quota`: 磁盘配额信息的结构。
    * `gfs2_quota_lvb`: 磁盘配额本地值块的结构。
7. **标志位 (Flags):** 定义了用于表示不同状态和属性的标志位，例如文件属性标志 `GFS2_DIF_*`，资源组标志 `GFS2_RGF_*` 等。
8. **常量定义:**  定义了诸如最大元数据高度 `GFS2_MAX_META_HEIGHT`，最大目录深度 `GFS2_DIR_MAX_DEPTH`，文件名最大长度 `GFS2_FNAMESIZE` 等常量。

**与 Android 功能的关系及举例说明：**

这个头文件定义的是 Linux 内核的 GFS2 文件系统结构。GFS2 (Global File System 2) 是一种集群文件系统。虽然 Android 设备通常不使用 GFS2 作为其主要的系统或数据分区文件系统（Android 常用 ext4 或 F2FS），但在某些特定的场景下，例如：

* **共享存储或网络文件系统:**  如果 Android 设备作为集群的一部分，并挂载了使用 GFS2 格式化的共享存储设备或网络文件系统，那么内核就需要理解 GFS2 的磁盘结构才能进行读写操作。
* **开发和测试:**  在 Android 系统开发或文件系统相关的测试中，开发者可能会使用 GFS2 进行特定的功能测试或性能评估。

**举例说明：**

假设一个 Android 设备挂载了一个使用 GFS2 格式化的外部存储设备。当 Android 系统需要读取这个设备上的文件时，内核中的 GFS2 文件系统驱动会根据这个头文件中定义的结构来解析磁盘上的数据，例如：

* **读取超级块 (Superblock):**  内核会读取磁盘上特定位置的超级块，并根据 `struct gfs2_sb` 的定义来解析其中的信息，如块大小 (`sb_bsize`)，根目录 inode 的位置 (`sb_root_dir`)，锁协议信息 (`sb_lockproto`) 等。
* **查找文件:**  当查找某个文件时，内核会读取目录项，并根据 `struct gfs2_dirent` 的定义来获取文件名 (`de_name_len`) 和对应的 inode 号 (`de_inum`)。
* **读取文件内容:**  获取到文件的 inode 号后，内核会读取磁盘上的 inode 数据块，并根据 `struct gfs2_dinode` 的定义来解析文件的大小 (`di_size`)、数据块的位置等信息。

**详细解释每一个 libc 函数的功能是如何实现的：**

**重要提示：**  `gfs2_ondisk.h` **不是** 实现 libc 函数的文件。它是一个 **头文件**，用于定义数据结构。libc 函数的实现代码位于其他的 `.c` 文件中。

这个头文件是被 Linux 内核使用的，而不是直接被 libc 使用。当内核中的 GFS2 文件系统驱动需要操作磁盘上的 GFS2 数据时，它会使用这里定义的结构体来解释磁盘上的二进制数据。

因此，**这里没有 libc 函数的实现** 需要解释。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

**`gfs2_ondisk.h` 不直接涉及 dynamic linker 的功能。** Dynamic linker (例如 Android 的 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库 (`.so` 文件) 并解析符号引用。

`gfs2_ondisk.h` 定义的是内核数据结构，用于文件系统的磁盘布局。内核模块（例如 GFS2 文件系统驱动）通常是静态链接到内核中的，或者作为可加载内核模块 (LKM) 动态加载，但这与用户空间的 dynamic linker 处理 `.so` 文件是不同的概念。

**尽管如此，为了说明 dynamic linker 的工作方式，这里提供一个简化的 `.so` 布局样本和链接过程的概述：**

**`.so` 布局样本 (简化):**

```
ELF Header:
  Magic:   7f 45 4c 46 ... (ELF 文件标识)
  ...
Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSiz              MemSiz              Flags  Align
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000 0x00000001000        0x00000001000        R E    0x1000
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000 0x0000000000000500        0x0000000000000600        RW     0x1000
  DYNAMIC        0x0000000000001500 0x0000000000001500 0x0000000000001500 0x0000000000000100        0x0000000000000100        RW     0x8
Section Headers:
  [Nr] Name              Type             Address             Offset
   ...
  [ .dynsym] .dynsym           SYMTAB           0000000000001600  00001600
  [ .dynstr] .dynstr           STRTAB           0000000000001800  00001800
  [ .rel.dyn] .rel.dyn           REL              0000000000001a00  00001a00
  ...
```

* **ELF Header:**  标识这是一个 ELF 文件。
* **Program Headers:**  描述了如何将文件的不同部分加载到内存中 (LOAD 段)，以及动态链接所需的信息 (DYNAMIC 段)。
* **Section Headers:**  描述了文件的各个节 (section)，例如 `.text` (代码段), `.data` (已初始化数据), `.bss` (未初始化数据), `.dynsym` (动态符号表), `.dynstr` (动态字符串表), `.rel.dyn` (动态重定位表) 等。

**链接的处理过程 (简化):**

1. **加载 `.so` 文件:** Dynamic linker 根据 Program Headers 中的信息将 `.so` 文件的 LOAD 段加载到内存中。
2. **解析 DYNAMIC 段:** Dynamic linker 读取 DYNAMIC 段，获取动态链接所需的信息，例如依赖的共享库列表、符号表的位置、重定位表的位置等。
3. **加载依赖的共享库:** 如果当前 `.so` 依赖其他共享库，dynamic linker 会递归地加载这些依赖库。
4. **符号解析 (Symbol Resolution):**
   * 当程序或共享库引用了外部符号 (例如来自其他 `.so` 的函数或全局变量) 时，这些引用需要在运行时被解析。
   * Dynamic linker 会遍历已加载的共享库的动态符号表 (`.dynsym`)，查找与引用符号名称匹配的定义。
5. **重定位 (Relocation):**
   * 当代码或数据中引用了需要在运行时才能确定的地址时 (例如，被引用符号的实际内存地址)，就需要进行重定位。
   * Dynamic linker 会读取重定位表 (`.rel.dyn`)，根据其中的指示修改代码或数据，将占位符地址替换为实际的运行时地址。

**如果做了逻辑推理，请给出假设输入与输出：**

由于 `gfs2_ondisk.h` 是一个定义数据结构的头文件，它本身不包含任何可执行的逻辑。因此，**无法直接给出假设的输入和输出**。

逻辑推理通常发生在内核的 GFS2 文件系统驱动中，当它需要解释磁盘上的数据时。例如：

**假设输入：**  从磁盘上读取的 512 字节的超级块数据。

**逻辑推理 (内核 GFS2 驱动):**

1. **读取魔数 `mh_magic`:**  读取超级块的头部，检查 `mh_magic` 是否等于 `GFS2_MAGIC` (0x01161970)。如果匹配，则确认为 GFS2 文件系统。
2. **读取格式类型 `mh_format`:** 读取 `mh_format`，例如，如果值为 `GFS2_FORMAT_SB` (100)，则确认这是一个超级块。
3. **读取块大小 `sb_bsize`:**  读取 `sb_bsize`，例如，如果值为 4096，则文件系统的块大小为 4096 字节。
4. **读取根目录 inode 位置 `sb_root_dir`:** 读取 `sb_root_dir` 结构，获取根目录 inode 的块号和偏移量。

**假设输出：**  经过解析后得到的超级块信息，例如：

* 文件系统类型：GFS2
* 块大小：4096
* 根目录 inode 号：{ no_formal_ino: 64, no_addr: 1024 }

**如果涉及用户或者编程常见的使用错误，请举例说明：**

由于 `gfs2_ondisk.h` 主要被内核使用，**普通用户或应用程序开发者通常不会直接操作或包含这个头文件**。因此，直接使用这个头文件导致编程错误的场景较少。

但是，如果开发者错误地理解了这个头文件的作用，可能会导致以下误用：

1. **在用户空间程序中尝试直接解析 GFS2 磁盘结构:**  用户空间程序应该通过系统调用与文件系统交互，而不是直接解析磁盘上的数据结构。尝试直接解析可能会导致程序崩溃、数据损坏或安全漏洞。

   ```c
   // 错误示例 (用户空间代码)
   #include <linux/gfs2_ondisk.h>
   #include <fcntl.h>
   #include <unistd.h>
   #include <stdio.h>

   int main() {
       int fd = open("/dev/sda1", O_RDONLY); // 假设 /dev/sda1 是 GFS2 分区
       if (fd < 0) {
           perror("open");
           return 1;
       }
       struct gfs2_sb sb;
       if (pread(fd, &sb, sizeof(sb), GFS2_SB_ADDR * GFS2_BASIC_BLOCK) != sizeof(sb)) {
           perror("pread");
           close(fd);
           return 1;
       }
       if (sb.sb_header.mh_magic == cpu_to_be32(GFS2_MAGIC)) {
           printf("Found GFS2 filesystem!\n");
       } else {
           printf("Not a GFS2 filesystem.\n");
       }
       close(fd);
       return 0;
   }
   ```

   **正确做法:** 用户空间程序应该使用标准的文件操作函数（如 `open`, `read`, `write`, `stat` 等），内核会处理底层的 GFS2 磁盘结构解析。

2. **在用户空间程序中错误地定义或使用 GFS2 数据结构:**  如果开发者试图在用户空间重新定义或使用与 `gfs2_ondisk.h` 中相同的结构，可能会因为字节序、数据类型大小等问题导致不兼容。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

到达 `gfs2_ondisk.h` 的路径主要发生在 **内核空间**，而不是 Android Framework 或 NDK 的用户空间代码直接访问。

**大致路径:**

1. **Android Framework 或 NDK 发起文件系统操作:** 例如，Java 代码中使用 `FileOutputStream` 写入文件，或者 Native 代码中使用 `open`, `write` 等函数。
2. **系统调用 (System Call):** 这些文件操作最终会转换为系统调用，例如 `openat`, `write` 等。
3. **内核 VFS 层 (Virtual File System):** 内核的 VFS 层接收到系统调用请求，并根据文件路径找到对应的文件系统实例。
4. **GFS2 文件系统驱动:** 如果目标文件位于一个 GFS2 文件系统上，VFS 层会将操作传递给 GFS2 文件系统驱动。
5. **GFS2 驱动使用 `gfs2_ondisk.h`:** GFS2 驱动在执行诸如读取超级块、查找 inode、读写数据块等操作时，会使用 `gfs2_ondisk.h` 中定义的结构体来解释磁盘上的数据。

**Frida Hook 示例 (调试系统调用层面):**

由于 `gfs2_ondisk.h` 主要在内核中使用，直接 hook 到内核函数需要更高级的 Frida 技术，这里提供一个在 **系统调用层面** 使用 Frida 进行 Hook 的示例，以观察与文件操作相关的系统调用：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['name'], message['payload']['args']))
    else:
        print(message)

def main():
    device = frida.get_usb_device()
    pid = device.spawn(['com.example.myapp']) # 替换为你的应用包名
    session = device.attach(pid)
    device.resume(pid)

    script_code = """
    // Hook openat 系统调用
    Interceptor.attach(Module.findExportByName(null, "openat"), {
        onEnter: function(args) {
            var pathname = Memory.readUtf8String(args[1]);
            this.name = "openat";
            this.args = [pathname, args[2].toInt(), args[3].toInt()];
            // 可以添加逻辑判断，如果操作的是 GFS2 分区上的文件，则进行更详细的记录
        },
        onLeave: function(retval) {
            //console.log("openat returned:", retval);
        }
    });

    // Hook write 系统调用
    Interceptor.attach(Module.findExportByName(null, "write"), {
        onEnter: function(args) {
            var fd = args[0].toInt();
            var count = args[2].toInt();
            this.name = "write";
            this.args = [fd, count];
            // 可以添加逻辑判断，根据 fd 判断是否操作的是 GFS2 分区上的文件
        },
        onLeave: function(retval) {
            //console.log("write returned:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**解释：**

1. **Hook 系统调用:**  这个 Frida 脚本 Hook 了 `openat` 和 `write` 这两个与文件操作密切相关的系统调用。
2. **`onEnter` 函数:**  在系统调用执行之前，`onEnter` 函数会被调用，可以访问系统调用的参数。
3. **记录参数:**  脚本记录了 `openat` 调用的文件路径名和 `write` 调用的文件描述符和写入字节数。
4. **进一步分析:**  在实际调试中，你可以根据文件路径或文件描述符来判断操作是否发生在 GFS2 分区上，并进行更详细的分析。

**更深层次的内核 Hook (高级):**

要直接 Hook 到内核中 GFS2 驱动的函数，需要使用更高级的 Frida 技术，例如：

* **内核模块注入:** 将 Frida Agent 注入到内核空间。
* **内核符号解析:** 找到 GFS2 驱动中相关函数的地址。
* **基于地址的 Hook:** 使用找到的地址进行 Hook。

这种方法较为复杂，需要对内核和 Frida 的内部机制有深入的理解。

总结来说，`bionic/libc/kernel/uapi/linux/gfs2_ondisk.h` 是 Android 内核中关于 GFS2 文件系统磁盘结构的定义，主要被内核的 GFS2 驱动使用。用户空间的程序通过系统调用与文件系统交互，并不直接操作这些数据结构。 Frida 可以用于 Hook 系统调用来观察文件操作，但要深入 Hook 内核函数则需要更高级的技术。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/gfs2_ondisk.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __GFS2_ONDISK_DOT_H__
#define __GFS2_ONDISK_DOT_H__
#include <linux/types.h>
#define GFS2_MAGIC 0x01161970
#define GFS2_BASIC_BLOCK 512
#define GFS2_BASIC_BLOCK_SHIFT 9
#define GFS2_MOUNT_LOCK 0
#define GFS2_LIVE_LOCK 1
#define GFS2_FREEZE_LOCK 2
#define GFS2_RENAME_LOCK 3
#define GFS2_CONTROL_LOCK 4
#define GFS2_MOUNTED_LOCK 5
#define GFS2_FORMAT_NONE 0
#define GFS2_FORMAT_SB 100
#define GFS2_FORMAT_RG 200
#define GFS2_FORMAT_RB 300
#define GFS2_FORMAT_DI 400
#define GFS2_FORMAT_IN 500
#define GFS2_FORMAT_LF 600
#define GFS2_FORMAT_JD 700
#define GFS2_FORMAT_LH 800
#define GFS2_FORMAT_LD 900
#define GFS2_FORMAT_LB 1000
#define GFS2_FORMAT_EA 1600
#define GFS2_FORMAT_ED 1700
#define GFS2_FORMAT_QC 1400
#define GFS2_FORMAT_RI 1100
#define GFS2_FORMAT_DE 1200
#define GFS2_FORMAT_QU 1500
#define GFS2_FORMAT_FS 1802
#define GFS2_FORMAT_MULTI 1900
struct gfs2_inum {
  __be64 no_formal_ino;
  __be64 no_addr;
};
#define GFS2_METATYPE_NONE 0
#define GFS2_METATYPE_SB 1
#define GFS2_METATYPE_RG 2
#define GFS2_METATYPE_RB 3
#define GFS2_METATYPE_DI 4
#define GFS2_METATYPE_IN 5
#define GFS2_METATYPE_LF 6
#define GFS2_METATYPE_JD 7
#define GFS2_METATYPE_LH 8
#define GFS2_METATYPE_LD 9
#define GFS2_METATYPE_LB 12
#define GFS2_METATYPE_EA 10
#define GFS2_METATYPE_ED 11
#define GFS2_METATYPE_QC 14
struct gfs2_meta_header {
  __be32 mh_magic;
  __be32 mh_type;
  __be64 __pad0;
  __be32 mh_format;
  union {
    __be32 mh_jid;
    __be32 __pad1;
  };
};
#define GFS2_SB_ADDR 128
#define GFS2_SB_LOCK 0
#define GFS2_LOCKNAME_LEN 64
struct gfs2_sb {
  struct gfs2_meta_header sb_header;
  __be32 sb_fs_format;
  __be32 sb_multihost_format;
  __u32 __pad0;
  __be32 sb_bsize;
  __be32 sb_bsize_shift;
  __u32 __pad1;
  struct gfs2_inum sb_master_dir;
  struct gfs2_inum __pad2;
  struct gfs2_inum sb_root_dir;
  char sb_lockproto[GFS2_LOCKNAME_LEN];
  char sb_locktable[GFS2_LOCKNAME_LEN];
  struct gfs2_inum __pad3;
  struct gfs2_inum __pad4;
#define GFS2_HAS_UUID 1
  __u8 sb_uuid[16];
};
struct gfs2_rindex {
  __be64 ri_addr;
  __be32 ri_length;
  __u32 __pad;
  __be64 ri_data0;
  __be32 ri_data;
  __be32 ri_bitbytes;
  __u8 ri_reserved[64];
};
#define GFS2_NBBY 4
#define GFS2_BIT_SIZE 2
#define GFS2_BIT_MASK 0x00000003
#define GFS2_BLKST_FREE 0
#define GFS2_BLKST_USED 1
#define GFS2_BLKST_UNLINKED 2
#define GFS2_BLKST_DINODE 3
#define GFS2_RGF_JOURNAL 0x00000001
#define GFS2_RGF_METAONLY 0x00000002
#define GFS2_RGF_DATAONLY 0x00000004
#define GFS2_RGF_NOALLOC 0x00000008
#define GFS2_RGF_TRIMMED 0x00000010
struct gfs2_inode_lvb {
  __be32 ri_magic;
  __be32 __pad;
  __be64 ri_generation_deleted;
};
struct gfs2_rgrp_lvb {
  __be32 rl_magic;
  __be32 rl_flags;
  __be32 rl_free;
  __be32 rl_dinodes;
  __be64 rl_igeneration;
  __be32 rl_unlinked;
  __be32 __pad;
};
struct gfs2_rgrp {
  struct gfs2_meta_header rg_header;
  __be32 rg_flags;
  __be32 rg_free;
  __be32 rg_dinodes;
  union {
    __be32 __pad;
    __be32 rg_skip;
  };
  __be64 rg_igeneration;
  __be64 rg_data0;
  __be32 rg_data;
  __be32 rg_bitbytes;
  __be32 rg_crc;
  __u8 rg_reserved[60];
};
struct gfs2_quota {
  __be64 qu_limit;
  __be64 qu_warn;
  __be64 qu_value;
  __u8 qu_reserved[64];
};
#define GFS2_MAX_META_HEIGHT 10
#define GFS2_DIR_MAX_DEPTH 17
#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)
enum {
  gfs2fl_Jdata = 0,
  gfs2fl_ExHash = 1,
  gfs2fl_Unused = 2,
  gfs2fl_EaIndirect = 3,
  gfs2fl_Directio = 4,
  gfs2fl_Immutable = 5,
  gfs2fl_AppendOnly = 6,
  gfs2fl_NoAtime = 7,
  gfs2fl_Sync = 8,
  gfs2fl_System = 9,
  gfs2fl_TopLevel = 10,
  gfs2fl_TruncInProg = 29,
  gfs2fl_InheritDirectio = 30,
  gfs2fl_InheritJdata = 31,
};
#define GFS2_DIF_JDATA 0x00000001
#define GFS2_DIF_EXHASH 0x00000002
#define GFS2_DIF_UNUSED 0x00000004
#define GFS2_DIF_EA_INDIRECT 0x00000008
#define GFS2_DIF_DIRECTIO 0x00000010
#define GFS2_DIF_IMMUTABLE 0x00000020
#define GFS2_DIF_APPENDONLY 0x00000040
#define GFS2_DIF_NOATIME 0x00000080
#define GFS2_DIF_SYNC 0x00000100
#define GFS2_DIF_SYSTEM 0x00000200
#define GFS2_DIF_TOPDIR 0x00000400
#define GFS2_DIF_TRUNC_IN_PROG 0x20000000
#define GFS2_DIF_INHERIT_DIRECTIO 0x40000000
#define GFS2_DIF_INHERIT_JDATA 0x80000000
struct gfs2_dinode {
  struct gfs2_meta_header di_header;
  struct gfs2_inum di_num;
  __be32 di_mode;
  __be32 di_uid;
  __be32 di_gid;
  __be32 di_nlink;
  __be64 di_size;
  __be64 di_blocks;
  __be64 di_atime;
  __be64 di_mtime;
  __be64 di_ctime;
  __be32 di_major;
  __be32 di_minor;
  __be64 di_goal_meta;
  __be64 di_goal_data;
  __be64 di_generation;
  __be32 di_flags;
  __be32 di_payload_format;
  __u16 __pad1;
  __be16 di_height;
  __u32 __pad2;
  __u16 __pad3;
  __be16 di_depth;
  __be32 di_entries;
  struct gfs2_inum __pad4;
  __be64 di_eattr;
  __be32 di_atime_nsec;
  __be32 di_mtime_nsec;
  __be32 di_ctime_nsec;
  __u8 di_reserved[44];
};
#define GFS2_FNAMESIZE 255
#define GFS2_DIRENT_SIZE(name_len) ((sizeof(struct gfs2_dirent) + (name_len) + 7) & ~7)
#define GFS2_MIN_DIRENT_SIZE (GFS2_DIRENT_SIZE(1))
struct gfs2_dirent {
  struct gfs2_inum de_inum;
  __be32 de_hash;
  __be16 de_rec_len;
  __be16 de_name_len;
  __be16 de_type;
  __be16 de_rahead;
  union {
    __u8 __pad[12];
    struct {
      __u32 de_cookie;
      __u8 pad3[8];
    };
  };
};
struct gfs2_leaf {
  struct gfs2_meta_header lf_header;
  __be16 lf_depth;
  __be16 lf_entries;
  __be32 lf_dirent_format;
  __be64 lf_next;
  union {
    __u8 lf_reserved[64];
    struct {
      __be64 lf_inode;
      __be32 lf_dist;
      __be32 lf_nsec;
      __be64 lf_sec;
      __u8 lf_reserved2[40];
    };
  };
};
#define GFS2_EA_MAX_NAME_LEN 255
#define GFS2_EA_MAX_DATA_LEN 65536
#define GFS2_EATYPE_UNUSED 0
#define GFS2_EATYPE_USR 1
#define GFS2_EATYPE_SYS 2
#define GFS2_EATYPE_SECURITY 3
#define GFS2_EATYPE_TRUSTED 4
#define GFS2_EATYPE_LAST 4
#define GFS2_EATYPE_VALID(x) ((x) <= GFS2_EATYPE_LAST)
#define GFS2_EAFLAG_LAST 0x01
struct gfs2_ea_header {
  __be32 ea_rec_len;
  __be32 ea_data_len;
  __u8 ea_name_len;
  __u8 ea_type;
  __u8 ea_flags;
  __u8 ea_num_ptrs;
  __u32 __pad;
};
#define GFS2_LOG_HEAD_UNMOUNT 0x00000001
#define GFS2_LOG_HEAD_FLUSH_NORMAL 0x00000002
#define GFS2_LOG_HEAD_FLUSH_SYNC 0x00000004
#define GFS2_LOG_HEAD_FLUSH_SHUTDOWN 0x00000008
#define GFS2_LOG_HEAD_FLUSH_FREEZE 0x00000010
#define GFS2_LOG_HEAD_RECOVERY 0x00000020
#define GFS2_LOG_HEAD_USERSPACE 0x80000000
#define GFS2_LFC_SHUTDOWN 0x00000100
#define GFS2_LFC_JDATA_WPAGES 0x00000200
#define GFS2_LFC_SET_FLAGS 0x00000400
#define GFS2_LFC_AIL_EMPTY_GL 0x00000800
#define GFS2_LFC_AIL_FLUSH 0x00001000
#define GFS2_LFC_RGRP_GO_SYNC 0x00002000
#define GFS2_LFC_INODE_GO_SYNC 0x00004000
#define GFS2_LFC_INODE_GO_INVAL 0x00008000
#define GFS2_LFC_FREEZE_GO_SYNC 0x00010000
#define GFS2_LFC_KILL_SB 0x00020000
#define GFS2_LFC_DO_SYNC 0x00040000
#define GFS2_LFC_INPLACE_RESERVE 0x00080000
#define GFS2_LFC_WRITE_INODE 0x00100000
#define GFS2_LFC_MAKE_FS_RO 0x00200000
#define GFS2_LFC_SYNC_FS 0x00400000
#define GFS2_LFC_EVICT_INODE 0x00800000
#define GFS2_LFC_TRANS_END 0x01000000
#define GFS2_LFC_LOGD_JFLUSH_REQD 0x02000000
#define GFS2_LFC_LOGD_AIL_FLUSH_REQD 0x04000000
#define LH_V1_SIZE (offsetofend(struct gfs2_log_header, lh_hash))
struct gfs2_log_header {
  struct gfs2_meta_header lh_header;
  __be64 lh_sequence;
  __be32 lh_flags;
  __be32 lh_tail;
  __be32 lh_blkno;
  __be32 lh_hash;
  __be32 lh_crc;
  __be32 lh_nsec;
  __be64 lh_sec;
  __be64 lh_addr;
  __be64 lh_jinode;
  __be64 lh_statfs_addr;
  __be64 lh_quota_addr;
  __be64 lh_local_total;
  __be64 lh_local_free;
  __be64 lh_local_dinodes;
};
#define GFS2_LOG_DESC_METADATA 300
#define GFS2_LOG_DESC_REVOKE 301
#define GFS2_LOG_DESC_JDATA 302
struct gfs2_log_descriptor {
  struct gfs2_meta_header ld_header;
  __be32 ld_type;
  __be32 ld_length;
  __be32 ld_data1;
  __be32 ld_data2;
  __u8 ld_reserved[32];
};
#define GFS2_INUM_QUANTUM 1048576
struct gfs2_inum_range {
  __be64 ir_start;
  __be64 ir_length;
};
struct gfs2_statfs_change {
  __be64 sc_total;
  __be64 sc_free;
  __be64 sc_dinodes;
};
#define GFS2_QCF_USER 0x00000001
struct gfs2_quota_change {
  __be64 qc_change;
  __be32 qc_flags;
  __be32 qc_id;
};
struct gfs2_quota_lvb {
  __be32 qb_magic;
  __u32 __pad;
  __be64 qb_limit;
  __be64 qb_warn;
  __be64 qb_value;
};
#endif

"""

```