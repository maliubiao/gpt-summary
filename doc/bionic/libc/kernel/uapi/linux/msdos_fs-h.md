Response:
Let's break down the thought process for answering the request about the `msdos_fs.h` header file.

**1. Understanding the Core Request:**

The core request is to analyze a specific header file (`msdos_fs.h`) within the Android bionic library and explain its function, its relationship to Android, how libc functions within it are implemented (though this is a header, so the implementation isn't *here* but rather *used* by implementations elsewhere), its connection to the dynamic linker, potential usage errors, and how it's reached from Android frameworks/NDK, including a Frida hook example.

**2. Initial Analysis of the Header File:**

The first step is to scan the header file for key elements:

* **`#ifndef`, `#define`, `#include`:** Standard C header file guards and inclusions. This tells us it's defining constants and possibly structures for use elsewhere.
* **`linux/types.h`, `linux/magic.h`, `asm/byteorder.h`:**  These includes are crucial. They indicate this header is designed to interface with the Linux kernel's understanding of the MS-DOS filesystem. `byteorder.h` strongly suggests handling of data representation across different architectures (endianness).
* **`SECTOR_SIZE`, `MSDOS_DPS`, `MSDOS_LONGNAME`:**  These `#define`s define core constants related to the MS-DOS filesystem structure: sector size, directory entries per sector, and maximum long filename length.
* **`CF_LE_W`, `CF_LE_L`, `CT_LE_W`, `CT_LE_L`:** These macros clearly deal with converting between little-endian and CPU-native endianness for words (16-bit) and longs (32-bit). This is critical for cross-platform compatibility.
* **`ATTR_...`:**  A series of `#define`s defining file attributes (read-only, hidden, system, etc.). This suggests this header is used for manipulating file metadata.
* **`struct __fat_dirent`, `struct fat_boot_sector`, `struct fat_boot_fsinfo`, `struct msdos_dir_entry`, `struct msdos_dir_slot`:** These are the core data structures defining the layout of the MS-DOS filesystem on disk, including directory entries, boot sector information, and long filename slots.
* **`VFAT_IOCTL_READDIR_BOTH`, `FAT_IOCTL_GET_ATTRIBUTES`, etc.:** These are `ioctl` request codes. This is a strong indicator that the header is used for interacting with a kernel driver for the MS-DOS filesystem.

**3. Determining Functionality:**

Based on the elements above, the core functionality becomes clear:

* **Defining Constants:**  Providing essential numerical values related to the MS-DOS filesystem.
* **Data Structures:** Defining the layout of on-disk data structures for the MS-DOS filesystem.
* **Endianness Handling:** Providing macros to handle byte order differences.
* **`ioctl` Interface:** Defining the commands used to interact with the MS-DOS filesystem driver in the kernel.

**4. Connecting to Android:**

The `bionic` prefix is the giveaway. This header is part of Android's C library. Android devices often use SD cards or internal storage formatted with FAT32 (a type of MS-DOS filesystem). Therefore, this header is crucial for:

* **File System Access:**  Allowing Android to read and write files on FAT32 volumes.
* **Mounting and Unmounting:** The kernel uses these structures to understand the filesystem during mount/unmount operations.
* **Tools and Utilities:**  Utilities that interact with FAT32 partitions (like `fsck_msdos`) would use these definitions.

**5. Explaining `libc` Functions (Conceptual):**

It's important to note that this header *doesn't contain the *implementation* of `libc` functions*. It *declares* the structures and constants that `libc` functions (like `open()`, `read()`, `write()`, `readdir()`, `ioctl()`) will *use* when interacting with an MS-DOS filesystem. The explanation focuses on *how* these functions would *use* the definitions within the header.

**6. Dynamic Linker Connection:**

This header file itself doesn't directly interact with the dynamic linker. However, the `libc` that *uses* this header is linked dynamically. The example `so` layout and linking process illustrate the general mechanism of dynamic linking in Android and how `libc.so` (which uses these definitions) is loaded and resolved.

**7. Logical Reasoning (Assumptions and Outputs):**

The example of reading a directory entry illustrates a basic use case. It assumes a function receives a raw directory entry and uses the structures defined in the header to access the filename and attributes.

**8. Common Usage Errors:**

The examples focus on mistakes related to byte order (forgetting to use the endianness conversion macros) and incorrect structure usage, which are common when working with low-level file system structures.

**9. Android Framework/NDK Path:**

This is a multi-step process tracing how an app's request eventually leads to the use of these low-level definitions. It starts with high-level APIs and goes down through the layers:

* **Java Framework:**  `java.io.File`, etc.
* **Native Code (NDK):**  Standard C library functions.
* **`libc` Implementation:** Where the definitions in the header are used.
* **Kernel System Calls:**  Functions like `open()`, `readdir()`, which interact with the kernel.
* **Kernel Filesystem Driver:** The driver that understands the MS-DOS filesystem format using the structures defined in the header.

**10. Frida Hook Example:**

The Frida example targets the `readdir()` system call. This is a relevant point to hook because `readdir()` is a fundamental operation for listing files in a directory, and its implementation for MS-DOS filesystems will rely on the structures defined in this header. The hook intercepts the system call, allows inspection of arguments (like the file descriptor), and the return value (the directory entry).

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Focus too much on the *implementation* of libc functions within this header. **Correction:** Realize it's a header, so it provides *declarations* and constants, not the actual code. Shift focus to how other parts of `libc` and the kernel *use* these definitions.
* **Overcomplicate the dynamic linker part:**  Initially consider trying to pinpoint specific symbols related to this header being resolved. **Correction:** Simplify to show the general dynamic linking process involving `libc.so` as a whole.
* **Frida hook too specific:**  Consider hooking a specific libc function. **Correction:**  Hooking the system call is more illustrative of the point where the kernel interacts with the filesystem driver and uses the structures defined in the header. It's a lower-level interception.

By following these steps and iteratively refining the understanding, a comprehensive and accurate answer can be constructed.
这个目录 `bionic/libc/kernel/uapi/linux/msdos_fs.h` 下的源代码文件 `msdos_fs.h` 是 Android Bionic C 库的一部分，它定义了用户空间程序与 Linux 内核中 MS-DOS 文件系统驱动程序交互时使用的常量、数据结构和宏。该文件属于内核头文件，但被复制到用户空间以便用户空间的库和应用程序可以直接使用这些定义。

**它的功能：**

1. **定义 MS-DOS 文件系统的元数据结构:**  该文件定义了在 MS-DOS 文件系统（包括 FAT12、FAT16 和 FAT32）中用于描述文件和目录的各种数据结构，例如引导扇区（`fat_boot_sector`）、文件系统信息扇区（`fat_boot_fsinfo`）、目录项（`msdos_dir_entry` 和 `msdos_dir_slot`）。
2. **定义常量和宏:**  它定义了与 MS-DOS 文件系统相关的各种常量和宏，例如扇区大小 (`SECTOR_SIZE`)，每簇扇区数，各种文件属性 (`ATTR_RO`, `ATTR_HIDDEN` 等)，特殊 FAT 条目的值 (例如 `EOF_FAT32`, `BAD_FAT16`)，以及字节序转换宏 (`CF_LE_W`, `CT_LE_L`)。
3. **定义 `ioctl` 请求代码:**  它定义了用户空间程序可以通过 `ioctl` 系统调用发送给 MS-DOS 文件系统驱动程序的命令代码，例如 `VFAT_IOCTL_READDIR_BOTH`（读取包含长文件名和短文件名的目录项），`FAT_IOCTL_GET_ATTRIBUTES`（获取文件属性），`FAT_IOCTL_SET_ATTRIBUTES`（设置文件属性）。

**与 Android 功能的关系及举例说明：**

Android 设备经常使用 FAT32 文件系统格式化的 SD 卡或内部存储分区。当 Android 系统需要访问这些分区上的文件时，底层的 Linux 内核就需要理解这种文件系统的结构。`msdos_fs.h` 中定义的结构和常量正是内核驱动程序和用户空间库进行交互的基础。

**举例说明：**

* 当你在 Android 设备上访问 SD 卡上的一个图片文件时，Android 的 Java Framework 会通过 Native 代码调用 C 库函数（位于 Bionic 中）。
* Bionic 的文件操作函数，例如 `open()`, `read()`, `write()`, `readdir()` 等，在处理 FAT32 文件系统上的文件时，会最终通过系统调用与内核中的 MS-DOS 文件系统驱动程序交互。
* 内核驱动程序会使用 `msdos_fs.h` 中定义的结构来解析磁盘上的 FAT32 文件系统结构，例如读取引导扇区来获取文件系统的基本信息，读取目录项来查找文件，以及读取 FAT 表来确定文件的数据块位置。
* 例如，在遍历目录时，`readdir()` 函数会使用 `VFAT_IOCTL_READDIR_BOTH`  `ioctl` 请求码来请求内核返回目录项信息，内核会填充 `__fat_dirent` 结构并返回给用户空间。

**详细解释每一个 libc 函数的功能是如何实现的：**

需要强调的是，`msdos_fs.h` **本身不包含任何 `libc` 函数的实现代码**。它只是定义了数据结构和常量。`libc` 中的文件操作函数（如 `open`, `read`, `write`, `readdir` 等）的实现位于其他的 C 源代码文件中，它们会 *使用* `msdos_fs.h` 中定义的类型和常量来与内核中的 MS-DOS 文件系统驱动程序交互。

例如，`readdir()` 函数的简化逻辑可能是：

1. 用户空间调用 `readdir()`。
2. `readdir()` 函数内部会维护一个目录流的上下文。
3. 在第一次调用或需要读取下一个目录项时，`readdir()` 会调用底层的 `getdents()` 系统调用或直接使用 `ioctl` (如 `VFAT_IOCTL_READDIR_BOTH`) 与内核交互。
4. 内核中的 MS-DOS 文件系统驱动程序收到请求后，会读取磁盘上的目录项数据，并将其转换为用户空间可以理解的格式，例如填充 `__fat_dirent` 结构。
5. 内核将结果返回给用户空间的 `readdir()` 函数。
6. `readdir()` 函数将 `__fat_dirent` 结构中的文件名等信息填充到 `dirent` 结构中，并返回给调用者。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`msdos_fs.h` 本身不直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并解析符号依赖。

但是，使用 `msdos_fs.h` 中定义的结构和常量的 `libc.so` 是一个动态链接库。

**`libc.so` 布局样本（简化）：**

```
libc.so:
    .text          # 包含 C 库函数的代码，例如 open(), read(), readdir() 等
    .data          # 包含已初始化的全局变量
    .bss           # 包含未初始化的全局变量
    .rodata        # 包含只读数据，例如字符串常量
    .plt           # Procedure Linkage Table，用于延迟绑定
    .got           # Global Offset Table，用于存储全局变量和函数地址
    ...其他段...
```

**链接的处理过程（简化）：**

1. **编译时：** 当一个应用程序或共享库需要使用 `libc` 中的函数（例如操作 FAT32 文件系统上的文件）时，编译器会在目标文件中记录对这些函数的未解析符号引用。
2. **链接时：** 静态链接器会将多个目标文件链接成一个可执行文件或共享库。它会记录下对外部共享库的依赖关系，例如对 `libc.so` 的依赖。
3. **运行时：** 当操作系统加载可执行文件时，dynamic linker 会被调用。
4. **加载共享库：** Dynamic linker 会根据可执行文件的依赖关系列表加载所需的共享库，例如 `libc.so`。
5. **符号解析（动态绑定）：**  当程序第一次调用 `libc.so` 中的函数时，会通过 `.plt` 和 `.got` 进行延迟绑定。
    * `.plt` 中的条目会跳转到 dynamic linker。
    * Dynamic linker 会在 `.so` 文件中查找被调用函数的地址。
    * Dynamic linker 将找到的函数地址写入到 `.got` 中对应的条目。
    * 后续对该函数的调用会直接通过 `.got` 跳转到实际的函数地址，避免了重复的解析开销。

在访问 FAT32 文件系统的情况下，当应用程序调用 `open()` 或 `readdir()` 等函数时，这些函数最终会调用内核提供的系统调用，而内核中的 MS-DOS 文件系统驱动程序会使用 `msdos_fs.h` 中定义的结构来处理文件系统的操作。

**如果做了逻辑推理，请给出假设输入与输出：**

假设有一个用户空间程序尝试读取一个 FAT32 文件系统上的目录 `/mnt/sdcard/pictures`。

**假设输入：**

* 系统调用：`getdents` 或 `ioctl` (例如 `VFAT_IOCTL_READDIR_BOTH`)
* 文件描述符：指向已打开的目录 `/mnt/sdcard/pictures` 的文件描述符。
* 缓冲区：用于存储读取到的目录项信息的内存区域。

**逻辑推理（内核 MS-DOS 文件系统驱动程序内部）：**

1. 驱动程序接收到读取目录项的请求。
2. 驱动程序根据文件描述符找到对应的目录在磁盘上的位置（通常是目录项所在的簇号）。
3. 驱动程序读取该簇或多个簇的数据到内存中。
4. 驱动程序解析读取到的原始数据，根据 `msdos_dir_entry` 和 `msdos_dir_slot` 的结构，提取出文件名、文件属性等信息。
5. 如果遇到长文件名 (LFN) 条目，驱动程序会将多个 `msdos_dir_slot` 条目组合成完整的长文件名。
6. 驱动程序将提取出的目录项信息填充到 `__fat_dirent` 结构中。

**假设输出：**

* 如果成功，系统调用返回读取到的目录项数量，缓冲区中包含填充好的 `__fat_dirent` 结构数组，每个结构描述一个目录项（文件名、inode 号等）。
* 如果发生错误（例如目录不存在，权限不足），系统调用返回错误代码（例如 `-ENOENT`, `-EACCES`）。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **字节序问题：** 直接使用从磁盘读取的 `__le16` 或 `__le32` 字段，而不使用 `le16_to_cpu` 或 `le32_to_cpu` 进行转换，会导致在大小端架构的系统上解析错误。例如，读取 `fat_boot_sector` 中的 `sector_size` 字段时，应该使用 `CF_LE_W(boot->sector_size)`。
2. **结构体大小和对齐问题：**  在用户空间和内核空间传递数据时，结构体的大小和内存布局必须一致。如果用户空间程序使用了与内核不兼容的结构体定义，会导致数据解析错误或程序崩溃。但由于 `msdos_fs.h` 是用户空间和内核共享的头文件，这种情况发生的概率较低。
3. **不正确的 `ioctl` 使用：**  使用错误的 `ioctl` 请求码或传递不正确的数据结构给 `ioctl` 系统调用会导致内核返回错误或执行意外操作。例如，尝试使用 `VFAT_IOCTL_READDIR_SHORT` 读取包含长文件名的目录可能会导致信息丢失。
4. **缓冲区溢出：** 在处理长文件名时，如果没有正确分配和管理缓冲区，可能会导致缓冲区溢出。例如，在读取目录项并将长文件名复制到缓冲区时，需要确保缓冲区足够大。
5. **假设文件名编码：**  MS-DOS 文件系统使用的文件名编码可能不是 UTF-8。如果程序假设文件名是 UTF-8 编码并进行不正确的转换，会导致文件名显示乱码。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `msdos_fs.h` 的路径：**

1. **Java Framework 层:** 用户应用程序通过 Java Framework API 进行文件操作，例如使用 `java.io.File` 类及其相关方法（如 `listFiles()`, `FileInputStream`, `FileOutputStream`）。
2. **Native 代码层 (NDK):** Java Framework 的文件操作 API 通常会调用底层的 Native 代码实现，这些 Native 代码位于 Android 的运行时库 (如 `libjavacrypto.so`, `libandroid_runtime.so`) 中。
3. **Bionic C 库:** Native 代码最终会调用 Bionic C 库提供的标准 C 库函数，例如 `open()`, `read()`, `write()`, `readdir()`, `ioctl()` 等。这些函数的实现位于 `libc.so` 中。
4. **系统调用:** Bionic C 库的函数会通过系统调用接口与 Linux 内核进行交互。例如，`open()` 函数会触发 `openat()` 系统调用，`readdir()` 可能会触发 `getdents()` 或使用 `ioctl`。
5. **Linux 内核 VFS 层:** 系统调用进入内核后，首先到达虚拟文件系统 (VFS) 层。VFS 根据文件路径识别出对应的文件系统类型（例如 FAT32）。
6. **MS-DOS 文件系统驱动程序:** VFS 层将请求转发给注册的 MS-DOS 文件系统驱动程序。该驱动程序的代码会使用 `msdos_fs.h` 中定义的结构和常量来解析磁盘上的 FAT32 文件系统结构，并执行相应的操作。

**Frida Hook 示例：**

可以使用 Frida 来 hook Bionic C 库中的函数或系统调用，以观察文件操作过程中涉及到的数据结构和参数。以下是一个 hook `readdir()` 函数的示例：

```javascript
// attach 到目标进程
var processName = "com.example.myapp"; // 替换为你的应用进程名
var session = frida.attach(processName);

session.then(function(api) {
  var libc = Process.getModuleByName("libc.so");
  var readdirPtr = libc.getExportByName("readdir");

  if (readdirPtr) {
    Interceptor.attach(readdirPtr, {
      onEnter: function(args) {
        console.log("[Readdir] Called");
        // args[0] 是 DIR* 指针
        console.log("  DIR* =", args[0]);
      },
      onLeave: function(retval) {
        console.log("  Return value =", retval);
        if (!retval.isNull()) {
          // 读取 dirent 结构体的内容
          var d_ino = retval.readU64();
          var d_off = retval.add(8).readU64();
          var d_reclen = retval.add(16).readU16();
          var d_type = retval.add(18).readU8();
          var d_name = retval.add(19).readUtf8String();
          console.log("  d_ino =", d_ino);
          console.log("  d_off =", d_off);
          console.log("  d_reclen =", d_reclen);
          console.log("  d_type =", d_type);
          console.log("  d_name =", d_name);
        }
      }
    });
    console.log("[*] Hooked readdir");
  } else {
    console.log("[!] readdir not found");
  }
});
```

**更进一步的 Hook 示例 (Hook `ioctl`，查看与 FAT32 相关的命令)：**

```javascript
var processName = "com.example.myapp";
var session = frida.attach(processName);

session.then(function(api) {
  var libc = Process.getModuleByName("libc.so");
  var ioctlPtr = libc.getExportByName("ioctl");

  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();

        console.log("[ioctl] Called");
        console.log("  fd =", fd);
        console.log("  request =", request, " (0x" + request.toString(16) + ")");

        // 可以根据 request 的值来判断是否是与 FAT32 相关的 ioctl 命令
        // 例如 VFAT_IOCTL_READDIR_BOTH 的值
        const VFAT_IOCTL_READDIR_BOTH = 0x40087201; // 假设的值，需要根据实际情况确定

        if (request === VFAT_IOCTL_READDIR_BOTH) {
          console.log("  [+] Potential FAT32 readdir ioctl");
          // 可以进一步检查 args[2] 指向的结构体内容
        }
      },
      onLeave: function(retval) {
        console.log("  Return value =", retval);
      }
    });
    console.log("[*] Hooked ioctl");
  } else {
    console.log("[!] ioctl not found");
  }
});
```

要 hook 更深层次与 `msdos_fs.h` 相关的操作，可能需要 hook 系统调用层面，或者甚至内核函数（需要 root 权限和内核符号信息）。但是，hook `readdir` 或 `ioctl` 已经可以观察到用户空间程序与内核文件系统驱动程序交互的一些关键信息。你需要根据具体的调试目标选择合适的 hook 点。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/msdos_fs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_LINUX_MSDOS_FS_H
#define _UAPI_LINUX_MSDOS_FS_H
#include <linux/types.h>
#include <linux/magic.h>
#include <asm/byteorder.h>
#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif
#define SECTOR_BITS 9
#define MSDOS_DPB (MSDOS_DPS)
#define MSDOS_DPB_BITS 4
#define MSDOS_DPS (SECTOR_SIZE / sizeof(struct msdos_dir_entry))
#define MSDOS_DPS_BITS 4
#define MSDOS_LONGNAME 256
#define CF_LE_W(v) le16_to_cpu(v)
#define CF_LE_L(v) le32_to_cpu(v)
#define CT_LE_W(v) cpu_to_le16(v)
#define CT_LE_L(v) cpu_to_le32(v)
#define MSDOS_ROOT_INO 1
#define MSDOS_FSINFO_INO 2
#define MSDOS_DIR_BITS 5
#define FAT_MAX_DIR_ENTRIES (65536)
#define FAT_MAX_DIR_SIZE (FAT_MAX_DIR_ENTRIES << MSDOS_DIR_BITS)
#define ATTR_NONE 0
#define ATTR_RO 1
#define ATTR_HIDDEN 2
#define ATTR_SYS 4
#define ATTR_VOLUME 8
#define ATTR_DIR 16
#define ATTR_ARCH 32
#define ATTR_UNUSED (ATTR_VOLUME | ATTR_ARCH | ATTR_SYS | ATTR_HIDDEN)
#define ATTR_EXT (ATTR_RO | ATTR_HIDDEN | ATTR_SYS | ATTR_VOLUME)
#define CASE_LOWER_BASE 8
#define CASE_LOWER_EXT 16
#define DELETED_FLAG 0xe5
#define IS_FREE(n) (! * (n) || * (n) == DELETED_FLAG)
#define FAT_LFN_LEN 255
#define MSDOS_NAME 11
#define MSDOS_SLOTS 21
#define MSDOS_DOT ".          "
#define MSDOS_DOTDOT "..         "
#define FAT_START_ENT 2
#define MAX_FAT12 0xFF4
#define MAX_FAT16 0xFFF4
#define MAX_FAT32 0x0FFFFFF6
#define BAD_FAT12 0xFF7
#define BAD_FAT16 0xFFF7
#define BAD_FAT32 0x0FFFFFF7
#define EOF_FAT12 0xFFF
#define EOF_FAT16 0xFFFF
#define EOF_FAT32 0x0FFFFFFF
#define FAT_ENT_FREE (0)
#define FAT_ENT_BAD (BAD_FAT32)
#define FAT_ENT_EOF (EOF_FAT32)
#define FAT_FSINFO_SIG1 0x41615252
#define FAT_FSINFO_SIG2 0x61417272
#define IS_FSINFO(x) (le32_to_cpu((x)->signature1) == FAT_FSINFO_SIG1 && le32_to_cpu((x)->signature2) == FAT_FSINFO_SIG2)
#define FAT_STATE_DIRTY 0x01
struct __fat_dirent {
  long d_ino;
  __kernel_off_t d_off;
  unsigned short d_reclen;
  char d_name[256];
};
#define VFAT_IOCTL_READDIR_BOTH _IOR('r', 1, struct __fat_dirent[2])
#define VFAT_IOCTL_READDIR_SHORT _IOR('r', 2, struct __fat_dirent[2])
#define FAT_IOCTL_GET_ATTRIBUTES _IOR('r', 0x10, __u32)
#define FAT_IOCTL_SET_ATTRIBUTES _IOW('r', 0x11, __u32)
#define FAT_IOCTL_GET_VOLUME_ID _IOR('r', 0x13, __u32)
struct fat_boot_sector {
  __u8 ignored[3];
  __u8 system_id[8];
  __u8 sector_size[2];
  __u8 sec_per_clus;
  __le16 reserved;
  __u8 fats;
  __u8 dir_entries[2];
  __u8 sectors[2];
  __u8 media;
  __le16 fat_length;
  __le16 secs_track;
  __le16 heads;
  __le32 hidden;
  __le32 total_sect;
  union {
    struct {
      __u8 drive_number;
      __u8 state;
      __u8 signature;
      __u8 vol_id[4];
      __u8 vol_label[MSDOS_NAME];
      __u8 fs_type[8];
    } fat16;
    struct {
      __le32 length;
      __le16 flags;
      __u8 version[2];
      __le32 root_cluster;
      __le16 info_sector;
      __le16 backup_boot;
      __le16 reserved2[6];
      __u8 drive_number;
      __u8 state;
      __u8 signature;
      __u8 vol_id[4];
      __u8 vol_label[MSDOS_NAME];
      __u8 fs_type[8];
    } fat32;
  };
};
struct fat_boot_fsinfo {
  __le32 signature1;
  __le32 reserved1[120];
  __le32 signature2;
  __le32 free_clusters;
  __le32 next_cluster;
  __le32 reserved2[4];
};
struct msdos_dir_entry {
  __u8 name[MSDOS_NAME];
  __u8 attr;
  __u8 lcase;
  __u8 ctime_cs;
  __le16 ctime;
  __le16 cdate;
  __le16 adate;
  __le16 starthi;
  __le16 time, date, start;
  __le32 size;
};
struct msdos_dir_slot {
  __u8 id;
  __u8 name0_4[10];
  __u8 attr;
  __u8 reserved;
  __u8 alias_checksum;
  __u8 name5_10[12];
  __le16 start;
  __u8 name11_12[4];
};
#endif
```