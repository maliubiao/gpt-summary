Response:
Let's break down the thought process for answering the user's request about `unistd_64.handroid`.

**1. Understanding the Core Request:**

The user has provided a header file (`unistd_64.handroid`) and wants to understand its purpose, its relationship to Android, how the functions are implemented, how the dynamic linker is involved, potential errors, and how to debug it. The key is recognizing this file defines system call numbers.

**2. Identifying the File's Purpose:**

The initial lines clearly state the file is auto-generated and related to bionic (Android's C library). The `#define __NR_*` lines immediately indicate it's a list of system call numbers. The `uapi` in the path strongly suggests it's a user-space API definition for interacting with the kernel. The "asm-arm64" part specifies the architecture. Therefore, the core function is *mapping symbolic names to numeric system call IDs for 64-bit ARM architecture in Android*.

**3. Explaining the Connection to Android:**

This is crucial. System calls are the fundamental way user-space programs (including Android apps and framework components) interact with the kernel. So, the explanation needs to highlight:

* **Foundation of system interaction:**  All high-level operations eventually boil down to system calls.
* **Abstraction:**  Libc functions (like `open`, `read`, `write`) act as wrappers around these system calls.
* **Android's dependency:**  Android heavily relies on these system calls for basic functionalities like file access, process management, networking, etc.

**4. Providing Concrete Examples:**

Abstract explanations aren't enough. The user needs examples. Good examples include:

* **File I/O:** `open`, `read`, `write` are directly mapped.
* **Process Management:** `fork`, `execve`, `exit` are fundamental.
* **Memory Management:** `mmap`, `munmap` are important for performance.
* **Networking:** `socket`, `bind`, `connect` are essential for network communication.

**5. Addressing Libc Function Implementation:**

The request asks for detailed explanations of *how* libc functions are implemented. The key insight here is that libc functions are *wrappers*. They:

* **Set up arguments:** Prepare the necessary data for the system call.
* **Invoke the system call:** Use inline assembly or a system call instruction to transition to kernel space.
* **Handle return values and errors:** Check the system call's return code and translate it into libc error codes (errno).

It's important *not* to dive into the kernel's implementation details (which is beyond the scope of this file).

**6. Handling the Dynamic Linker Aspect:**

The file itself doesn't directly *implement* dynamic linking. However, *system calls are used by the dynamic linker*. The key system calls are `mmap` (to load shared libraries) and potentially others for setting up memory regions and resolving symbols.

To illustrate, a simple SO layout example is needed, showing the different sections (.text, .data, .bss, .dynamic, .got, .plt). The linking process explanation should cover:

* **Locating dependencies:**  Using `DT_NEEDED` entries in the `.dynamic` section.
* **Loading dependencies:**  Using `mmap`.
* **Symbol resolution:**  Using the Global Offset Table (GOT) and Procedure Linkage Table (PLT) with lazy or immediate binding.

**7. Considering User Errors:**

Common errors relate to incorrect usage of the libc wrappers:

* **Invalid file descriptors:**  Using a closed or non-existent file descriptor.
* **Incorrect permissions:** Trying to access a file without the necessary permissions.
* **Memory errors:**  Passing invalid memory addresses or sizes.
* **Ignoring return values:** Not checking for errors.

**8. Explaining the Path from Android Framework/NDK:**

This requires tracing the execution flow. The high-level explanation should be:

* **NDK/SDK API calls:**  Developers use high-level APIs.
* **Framework Services:** These APIs often call into native services.
* **Native Code:**  Framework services and NDK apps use C/C++.
* **Libc Wrappers:**  Native code uses libc functions.
* **System Calls:**  Libc functions translate to system calls defined in this file.
* **Kernel:** The kernel handles the actual system call execution.

**9. Providing a Frida Hook Example:**

A practical Frida example is essential for debugging. The example should:

* **Hook a libc function:**  Choose a common function like `openat`.
* **Log arguments and return value:** Show how to inspect the input and output of the function.
* **Demonstrate the system call number:**  Access the `__NR_openat` constant.

**10. Structuring the Answer:**

The answer needs to be well-organized and easy to understand. Using headings, bullet points, and clear language is crucial. The structure should follow the user's request:

* Functionality of the file.
* Relationship to Android with examples.
* Explanation of libc function implementation.
* Dynamic linker aspects with examples.
* Common user errors.
* Tracing the path from the framework/NDK.
* Frida hook example.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe I should explain the kernel's system call handling in detail. **Correction:**  No, the focus should be on the *user-space* perspective and how this header file is used. Kernel details are too deep.
* **Initial thought:** Just list the system calls. **Correction:**  That's not enough. The user needs to understand the *purpose* and *context* of these calls within Android.
* **Initial thought:**  Focus only on code. **Correction:**  The user also asked about common errors and debugging, so I need to address those practical aspects.
* **Initial thought:**  The Frida example should be very complex. **Correction:** Keep it simple and focused on demonstrating the basic hooking and logging of system call information.

By following these steps and making necessary refinements, a comprehensive and helpful answer can be generated, addressing all aspects of the user's request.
这个文件 `bionic/libc/kernel/uapi/asm-arm64/asm/unistd_64.handroid` 是 Android Bionic C 库的一部分，它定义了 **64位 ARM 架构** (arm64) 上 Linux 内核提供的 **系统调用号 (syscall numbers)**。

**功能:**

该文件的主要功能是建立用户空间程序（例如，Android 应用程序和系统服务）发起的系统调用请求与 Linux 内核提供的实际系统调用函数之间的映射关系。 简单来说，它是一个 **系统调用号的常量定义表**。

* **定义系统调用号:**  它使用 `#define` 预处理器指令将每个系统调用关联到一个唯一的数字常量，例如 `__NR_read` 定义为 63，表示 `read` 系统调用的编号是 63。
* **为用户空间提供接口:**  这个头文件被 Bionic C 库（`libc`）使用，以便将高级 C 函数调用（如 `open()`, `read()`, `write()` 等）转换为内核能够理解的系统调用请求。

**与 Android 功能的关系及举例说明:**

这个文件是 Android 操作系统运行的基石，因为它定义了用户空间程序与内核交互的方式。Android 的几乎所有功能都直接或间接地依赖于这些系统调用。

**举例说明:**

1. **文件操作:**
   * 当一个 Android 应用程序需要打开一个文件时，它会调用 `libc` 中的 `open()` 函数。
   * `open()` 函数内部会使用 `__NR_openat` 这个系统调用号 (在不同的架构上可能有所不同，但概念相同)。
   * 操作系统内核接收到包含 `__NR_openat` 的请求，知道应用程序想要执行打开文件的操作，并执行相应的内核代码。

2. **进程管理:**
   * 当 Android 系统需要创建一个新的进程时（例如启动一个新的应用），它会调用 `fork()` 或 `execve()` 等函数。
   * 这些函数最终会通过对应的系统调用号 (`__NR_fork`, `__NR_execve`) 来通知内核执行进程创建或替换的操作。

3. **内存管理:**
   * Android 的 Dalvik/ART 虚拟机需要分配和管理内存。它会使用 `mmap()` 和 `munmap()` 等函数。
   * 这些函数会调用相应的系统调用 (`__NR_mmap`, `__NR_munmap`) 来请求内核分配或释放内存。

4. **网络通信:**
   * 当一个 Android 应用需要进行网络通信时，它会使用 `socket()`, `bind()`, `connect()`, `send()`, `recv()` 等函数。
   * 这些函数会映射到诸如 `__NR_socket`, `__NR_bind`, `__NR_connect`, `__NR_sendto`, `__NR_recvfrom` 等系统调用。

**详细解释每一个 libc 函数的功能是如何实现的:**

`unistd_64.handroid` 文件本身 **不包含** libc 函数的实现代码。它仅仅定义了系统调用号。 libc 函数的实现通常包含以下步骤：

1. **参数准备:**  libc 函数会接收用户传递的参数，并进行必要的验证和转换，以符合系统调用的要求。
2. **系统调用号加载:**  libc 函数会使用与特定操作对应的系统调用号（从 `unistd_64.handroid` 中定义）。
3. **陷入内核 (Trap to Kernel):**  libc 函数会使用特定的 CPU 指令（例如 ARM64 架构上的 `svc` 指令）触发一个异常，将执行权转移到内核空间。
4. **系统调用处理:** 内核接收到异常后，会根据系统调用号查找对应的内核函数，并执行该函数。内核函数会执行实际的操作，例如打开文件、创建进程等。
5. **结果返回:** 内核函数执行完毕后，会将结果（包括成功或失败的指示以及可能的返回值）返回给用户空间。
6. **错误处理:** libc 函数会检查内核返回的结果。如果发生错误，libc 函数会将错误码设置到全局变量 `errno` 中，并可能返回一个特定的错误值（例如 -1）。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`unistd_64.handroid` 文件本身 **不直接涉及** dynamic linker 的功能。Dynamic linker (例如 Android 上的 `linker64`) 负责在程序运行时加载共享库 (.so 文件) 并解析符号。

然而，dynamic linker 在执行其任务时，会 **使用一些这里定义的系统调用**。例如：

* **`openat` 或 `open`:** 用于打开共享库文件。
* **`mmap`:** 用于将共享库加载到内存中。
* **`mprotect`:** 用于设置内存区域的保护属性。
* **`close`:** 用于关闭不再需要的文件描述符。

**SO 布局样本:**

一个典型的 64 位 Android .so 文件的布局可能如下：

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          ...
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         ...
  Size of section headers:           64 (bytes)
  Number of section headers:         ...
  Section header string table index: ...

Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSize             MemSize              Flags              Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040 0x0000000000000248 0x0000000000000248 R      0x8
  INTERP         0x0000000000000288 0x0000000000000288 0x0000000000000288 0x000000000000001c 0x000000000000001c R      0x1
      [Requesting program interpreter: /system/bin/linker64]
  LOAD           0x0000000000000000 0x00000000xxxxxxxx 0x00000000xxxxxxxx 0x00000000yyyyyyyy 0x00000000zzzzzzzz R E    0x1000
  LOAD           0x000000000000xxxx 0x00000000xxxxxxxx 0x00000000xxxxxxxx 0x00000000aaaaaaaa 0x00000000bbbbbbbb RW     0x1000
  DYNAMIC        0x000000000000xxxx 0x00000000xxxxxxxx 0x00000000xxxxxxxx 0x00000000cccccccc 0x00000000cccccccc RW     0x8

Section Headers:
  [Nr] Name              Type             Address   Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL             00000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS         xxxxxxxx xxxxxxxx yyyyyyyy 00  AX  0   0 16
  [ 2] .rodata           PROGBITS         xxxxxxxx xxxxxxxx zzzzzzzz 00   A  0   0  8
  [ 3] .data             PROGBITS         xxxxxxxx xxxxxxxx aaaaaaaa 00  WA  0   0  8
  [ 4] .bss              NOBITS           xxxxxxxx xxxxxxxx bbbbbbbb 00  WA  0   0  8
  [ 5] .dynamic          DYNAMIC          xxxxxxxx xxxxxxxx cccccccc 10  WA  6   0  8
  [ 6] .symtab           SYMTAB           xxxxxxxx xxxxxxxx dddddddd 18   A  7  XX  8
  [ 7] .strtab           STRTAB           xxxxxxxx xxxxxxxx eeeeeeee 00   A  0   0  1
  [ 8] .rel.dyn          REL              xxxxxxxx xxxxxxxx ffffffff 08   A  6   X  8
  [ 9] .rel.plt          REL              xxxxxxxx xxxxxxxx gggggggg 08   A  6  XX  8
  [10] .plt              PROGBITS         xxxxxxxx xxxxxxxx hhhhhhhh 04  AX  0   0 16
  ...

Dynamic Section:
  TAG        TYPE              NAME/VALUE
  0x00000001 (NEEDED)           Shared library: [libc.so]
  0x00000001 (NEEDED)           Shared library: [libm.so]
  0x0000000c (INIT)             0xxxxxxxxxxxxx
  0x0000000d (FINI)             0xxxxxxxxxxxxx
  0x00000005 (STRTAB)           0xxxxxxxxxxxxx
  0x00000006 (SYMTAB)           0xxxxxxxxxxxxx
  0x0000000a (STRSZ)            xxxxxxxxx
  0x0000000b (SYMENT)           0x18
  0x00000015 (DEBUG)            0x0
  0x00000003 (PLTGOT)           0xxxxxxxxxxxxx
  0x00000002 (PLTRELSZ)         xxxxxxxxx
  0x00000014 (PLTREL)           REL
  0x00000017 (JMPREL)           0xxxxxxxxxxxxx
  0x00000011 (REL)              0xxxxxxxxxxxxx
  0x00000012 (RELSZ)            xxxxxxxxx
  0x00000013 (RELENT)           0x8
  ...
```

**链接的处理过程:**

1. **加载可执行文件:** 当 Android 启动一个应用程序时，`linker64` 首先加载主可执行文件。
2. **解析依赖:** `linker64` 解析可执行文件的 `DYNAMIC` 段，查找 `NEEDED` 标记，确定其依赖的共享库。
3. **加载共享库:** 对于每个依赖的共享库，`linker64` 会尝试在系统路径中找到它们（例如 `/system/lib64`, `/vendor/lib64` 等），并使用 `openat` 或 `open` 系统调用打开文件。然后使用 `mmap` 将共享库加载到进程的地址空间中。
4. **符号解析 (Symbol Resolution):**  这是链接的核心部分。
   * **全局偏移量表 (GOT - Global Offset Table):**  GOT 是数据段中的一个表，用于存储全局变量的地址。在编译时，GOT 中的条目是未知的。dynamic linker 在加载时会填充这些条目，使其指向正确的全局变量的地址。
   * **过程链接表 (PLT - Procedure Linkage Table):** PLT 是代码段中的一个小代码段，用于间接调用外部函数。
   * **Lazy Binding (延迟绑定):** 默认情况下，Android 使用延迟绑定。当程序第一次调用一个外部函数时，会跳转到 PLT 中的一个桩代码。这个桩代码会调用 dynamic linker，dynamic linker 会解析该函数的地址，更新 GOT 表中的对应条目，并将控制权转移到实际的函数。后续的调用将直接通过 GOT 表跳转到函数，避免重复解析。
   * **Immediate Binding (立即绑定):**  可以通过某些编译选项或环境变量强制使用立即绑定。在这种情况下，dynamic linker 会在加载时解析所有外部函数的地址。
5. **重定位 (Relocation):**  由于共享库被加载到内存中的地址可能与编译时的地址不同，dynamic linker 需要修改代码和数据中的地址引用，使其指向正确的内存位置。这通过解析 `.rel.dyn` 和 `.rel.plt` 等重定位段来完成。

**逻辑推理，假设输入与输出:**

由于此文件是系统调用号的定义，它本身不涉及逻辑推理的输入和输出。 逻辑推理发生在内核处理系统调用时。

**假设输入 (以 `read` 系统调用为例):**

* **系统调用号:** `__NR_read` (63)
* **文件描述符 (fd):** 例如 3 (表示一个已打开的文件)
* **缓冲区地址 (buf):**  一个指向用户空间内存的指针，用于接收读取的数据。
* **读取字节数 (count):** 例如 1024 (表示希望读取 1024 字节)

**假设输出 (基于上述输入):**

* **成功:**
    * 返回值：实际读取的字节数（可能小于等于 `count`，例如 512）。
    * `buf` 指向的内存区域会被填充从文件中读取的数据。
* **失败:**
    * 返回值：-1。
    * `errno` 会被设置为相应的错误码，例如 `EAGAIN` (资源暂时不可用), `EBADF` (无效的文件描述符) 等。

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用了错误的系统调用号:**  直接使用硬编码的数字而不是使用 `unistd_64.handroid` 中定义的常量，会导致代码在不同的架构或 Android 版本上崩溃或行为异常。 **正确做法:** 始终使用 `__NR_xxx` 形式的宏。

2. **没有正确处理系统调用的返回值:**  很多系统调用在出错时会返回 -1，并将错误码设置到 `errno`。如果程序没有检查返回值和 `errno`，就可能在发生错误时继续执行，导致不可预测的行为。 **示例:**

   ```c
   int fd = open("/path/to/file", O_RDONLY);
   // 缺少错误检查
   char buffer[100];
   read(fd, buffer, sizeof(buffer)); // 如果 open 失败，fd 可能是一个无效值，导致 read 崩溃
   ```

3. **传递了无效的参数给系统调用:** 例如，传递一个空指针作为缓冲区地址，或者传递一个负数的字节数。内核会拒绝这些请求，并返回错误。

4. **权限问题:** 尝试执行需要特定权限的系统调用，但应用程序没有相应的权限。例如，尝试修改系统文件但没有 root 权限。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**路径说明:**

1. **Android SDK/NDK API 调用:**  Android 开发者通常使用 Java (Android SDK) 或 C/C++ (Android NDK) 提供的 API。
2. **Android Framework Services:** SDK API 背后通常由 Android Framework 中的各种服务实现。例如，`FileInputStream` 最终会调用到 `frameworks/base/core/java/android/os/ParcelFileDescriptor.java` 等。
3. **Native Libraries (Framework & NDK):** Framework 服务和 NDK 应用程序会使用 C/C++ 编写的本地库。例如，`FileInputStream` 底层会调用到 Bionic C 库中的 `read()` 函数。
4. **Bionic C Library (libc):**  Bionic C 库提供了与 Linux 内核交互的接口。例如，`read()` 函数的实现最终会调用一个汇编指令来触发 `read` 系统调用。
5. **System Call Number Lookup:**  `libc` 使用 `unistd_64.handroid` (或其对应架构的版本) 中定义的宏来获取 `read` 系统调用的编号 (`__NR_read`)。
6. **System Call (Kernel):**  `libc` 将系统调用号和参数传递给内核。内核接收到请求后，根据系统调用号调度相应的内核函数来执行操作。

**Frida Hook 示例:**

以下 Frida 脚本展示了如何 hook `openat` 函数，并打印其参数和系统调用号：

```javascript
if (Process.arch === 'arm64') {
  const openatPtr = Module.findExportByName("libc.so", "openat");
  const NR_openat = Module.findExportByName("libc.so", "__NR_openat");

  if (openatPtr && NR_openat) {
    Interceptor.attach(openatPtr, {
      onEnter: function (args) {
        const dirfd = args[0].toInt32();
        const pathname = args[1].readUtf8String();
        const flags = args[2].toInt32();
        console.log(`[openat Hook]`);
        console.log(`  Syscall Number: ${NR_openat.readU32()}`);
        console.log(`  dirfd: ${dirfd}`);
        console.log(`  pathname: ${pathname}`);
        console.log(`  flags: ${flags}`);
      },
      onLeave: function (retval) {
        console.log(`  Return Value: ${retval}`);
      }
    });
  } else {
    console.error("Failed to find openat or __NR_openat symbols.");
  }
} else {
  console.warn("This script is for arm64 architecture.");
}
```

**使用方法:**

1. 将上述代码保存为 `hook_openat.js`。
2. 确保你的 Android 设备已 root，并且安装了 Frida 服务。
3. 使用 USB 连接你的设备，并通过 `adb` 连接到设备。
4. 运行要调试的 Android 应用程序。
5. 使用 Frida 连接到目标应用程序的进程：
   ```bash
   frida -U -f <包名> -l hook_openat.js --no-pause
   ```
   或者，如果应用程序已经在运行：
   ```bash
   frida -U <包名> -l hook_openat.js
   ```

**预期输出:**

当应用程序调用 `openat` 函数时，Frida 脚本会在控制台中打印类似以下的输出：

```
[#] spawn      
[#] open      com.example.myapp
[Pixel 6::com.example.myapp]-> [openat Hook]
  Syscall Number: 56
  dirfd: -100
  pathname: /data/local/tmp/myfile.txt
  flags: 97664
  Return Value: 3
```

**解释:**

* **`Syscall Number: 56`:**  这表示 `openat` 函数对应的系统调用号是 56，与 `unistd_64.handroid` 中 `__NR_openat 56` 的定义一致。
* **`dirfd`，`pathname`，`flags`:**  这些是 `openat` 函数的参数，显示了应用程序尝试打开的文件路径和打开方式。
* **`Return Value: 3`:**  这是 `openat` 函数的返回值，通常是一个非负的文件描述符，表示文件打开成功。

通过这种方式，你可以使用 Frida 来观察应用程序如何调用 libc 函数，并验证它们最终如何映射到 `unistd_64.handroid` 中定义的系统调用。这对于理解 Android 系统的底层工作原理和调试问题非常有帮助。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-arm64/asm/unistd_64.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_ASM_UNISTD_64_H
#define _UAPI_ASM_UNISTD_64_H
#define __NR_io_setup 0
#define __NR_io_destroy 1
#define __NR_io_submit 2
#define __NR_io_cancel 3
#define __NR_io_getevents 4
#define __NR_setxattr 5
#define __NR_lsetxattr 6
#define __NR_fsetxattr 7
#define __NR_getxattr 8
#define __NR_lgetxattr 9
#define __NR_fgetxattr 10
#define __NR_listxattr 11
#define __NR_llistxattr 12
#define __NR_flistxattr 13
#define __NR_removexattr 14
#define __NR_lremovexattr 15
#define __NR_fremovexattr 16
#define __NR_getcwd 17
#define __NR_lookup_dcookie 18
#define __NR_eventfd2 19
#define __NR_epoll_create1 20
#define __NR_epoll_ctl 21
#define __NR_epoll_pwait 22
#define __NR_dup 23
#define __NR_dup3 24
#define __NR_fcntl 25
#define __NR_inotify_init1 26
#define __NR_inotify_add_watch 27
#define __NR_inotify_rm_watch 28
#define __NR_ioctl 29
#define __NR_ioprio_set 30
#define __NR_ioprio_get 31
#define __NR_flock 32
#define __NR_mknodat 33
#define __NR_mkdirat 34
#define __NR_unlinkat 35
#define __NR_symlinkat 36
#define __NR_linkat 37
#define __NR_renameat 38
#define __NR_umount2 39
#define __NR_mount 40
#define __NR_pivot_root 41
#define __NR_nfsservctl 42
#define __NR_statfs 43
#define __NR_fstatfs 44
#define __NR_truncate 45
#define __NR_ftruncate 46
#define __NR_fallocate 47
#define __NR_faccessat 48
#define __NR_chdir 49
#define __NR_fchdir 50
#define __NR_chroot 51
#define __NR_fchmod 52
#define __NR_fchmodat 53
#define __NR_fchownat 54
#define __NR_fchown 55
#define __NR_openat 56
#define __NR_close 57
#define __NR_vhangup 58
#define __NR_pipe2 59
#define __NR_quotactl 60
#define __NR_getdents64 61
#define __NR_lseek 62
#define __NR_read 63
#define __NR_write 64
#define __NR_readv 65
#define __NR_writev 66
#define __NR_pread64 67
#define __NR_pwrite64 68
#define __NR_preadv 69
#define __NR_pwritev 70
#define __NR_sendfile 71
#define __NR_pselect6 72
#define __NR_ppoll 73
#define __NR_signalfd4 74
#define __NR_vmsplice 75
#define __NR_splice 76
#define __NR_tee 77
#define __NR_readlinkat 78
#define __NR_newfstatat 79
#define __NR_fstat 80
#define __NR_sync 81
#define __NR_fsync 82
#define __NR_fdatasync 83
#define __NR_sync_file_range 84
#define __NR_timerfd_create 85
#define __NR_timerfd_settime 86
#define __NR_timerfd_gettime 87
#define __NR_utimensat 88
#define __NR_acct 89
#define __NR_capget 90
#define __NR_capset 91
#define __NR_personality 92
#define __NR_exit 93
#define __NR_exit_group 94
#define __NR_waitid 95
#define __NR_set_tid_address 96
#define __NR_unshare 97
#define __NR_futex 98
#define __NR_set_robust_list 99
#define __NR_get_robust_list 100
#define __NR_nanosleep 101
#define __NR_getitimer 102
#define __NR_setitimer 103
#define __NR_kexec_load 104
#define __NR_init_module 105
#define __NR_delete_module 106
#define __NR_timer_create 107
#define __NR_timer_gettime 108
#define __NR_timer_getoverrun 109
#define __NR_timer_settime 110
#define __NR_timer_delete 111
#define __NR_clock_settime 112
#define __NR_clock_gettime 113
#define __NR_clock_getres 114
#define __NR_clock_nanosleep 115
#define __NR_syslog 116
#define __NR_ptrace 117
#define __NR_sched_setparam 118
#define __NR_sched_setscheduler 119
#define __NR_sched_getscheduler 120
#define __NR_sched_getparam 121
#define __NR_sched_setaffinity 122
#define __NR_sched_getaffinity 123
#define __NR_sched_yield 124
#define __NR_sched_get_priority_max 125
#define __NR_sched_get_priority_min 126
#define __NR_sched_rr_get_interval 127
#define __NR_restart_syscall 128
#define __NR_kill 129
#define __NR_tkill 130
#define __NR_tgkill 131
#define __NR_sigaltstack 132
#define __NR_rt_sigsuspend 133
#define __NR_rt_sigaction 134
#define __NR_rt_sigprocmask 135
#define __NR_rt_sigpending 136
#define __NR_rt_sigtimedwait 137
#define __NR_rt_sigqueueinfo 138
#define __NR_rt_sigreturn 139
#define __NR_setpriority 140
#define __NR_getpriority 141
#define __NR_reboot 142
#define __NR_setregid 143
#define __NR_setgid 144
#define __NR_setreuid 145
#define __NR_setuid 146
#define __NR_setresuid 147
#define __NR_getresuid 148
#define __NR_setresgid 149
#define __NR_getresgid 150
#define __NR_setfsuid 151
#define __NR_setfsgid 152
#define __NR_times 153
#define __NR_setpgid 154
#define __NR_getpgid 155
#define __NR_getsid 156
#define __NR_setsid 157
#define __NR_getgroups 158
#define __NR_setgroups 159
#define __NR_uname 160
#define __NR_sethostname 161
#define __NR_setdomainname 162
#define __NR_getrlimit 163
#define __NR_setrlimit 164
#define __NR_getrusage 165
#define __NR_umask 166
#define __NR_prctl 167
#define __NR_getcpu 168
#define __NR_gettimeofday 169
#define __NR_settimeofday 170
#define __NR_adjtimex 171
#define __NR_getpid 172
#define __NR_getppid 173
#define __NR_getuid 174
#define __NR_geteuid 175
#define __NR_getgid 176
#define __NR_getegid 177
#define __NR_gettid 178
#define __NR_sysinfo 179
#define __NR_mq_open 180
#define __NR_mq_unlink 181
#define __NR_mq_timedsend 182
#define __NR_mq_timedreceive 183
#define __NR_mq_notify 184
#define __NR_mq_getsetattr 185
#define __NR_msgget 186
#define __NR_msgctl 187
#define __NR_msgrcv 188
#define __NR_msgsnd 189
#define __NR_semget 190
#define __NR_semctl 191
#define __NR_semtimedop 192
#define __NR_semop 193
#define __NR_shmget 194
#define __NR_shmctl 195
#define __NR_shmat 196
#define __NR_shmdt 197
#define __NR_socket 198
#define __NR_socketpair 199
#define __NR_bind 200
#define __NR_listen 201
#define __NR_accept 202
#define __NR_connect 203
#define __NR_getsockname 204
#define __NR_getpeername 205
#define __NR_sendto 206
#define __NR_recvfrom 207
#define __NR_setsockopt 208
#define __NR_getsockopt 209
#define __NR_shutdown 210
#define __NR_sendmsg 211
#define __NR_recvmsg 212
#define __NR_readahead 213
#define __NR_brk 214
#define __NR_munmap 215
#define __NR_mremap 216
#define __NR_add_key 217
#define __NR_request_key 218
#define __NR_keyctl 219
#define __NR_clone 220
#define __NR_execve 221
#define __NR_mmap 222
#define __NR_fadvise64 223
#define __NR_swapon 224
#define __NR_swapoff 225
#define __NR_mprotect 226
#define __NR_msync 227
#define __NR_mlock 228
#define __NR_munlock 229
#define __NR_mlockall 230
#define __NR_munlockall 231
#define __NR_mincore 232
#define __NR_madvise 233
#define __NR_remap_file_pages 234
#define __NR_mbind 235
#define __NR_get_mempolicy 236
#define __NR_set_mempolicy 237
#define __NR_migrate_pages 238
#define __NR_move_pages 239
#define __NR_rt_tgsigqueueinfo 240
#define __NR_perf_event_open 241
#define __NR_accept4 242
#define __NR_recvmmsg 243
#define __NR_wait4 260
#define __NR_prlimit64 261
#define __NR_fanotify_init 262
#define __NR_fanotify_mark 263
#define __NR_name_to_handle_at 264
#define __NR_open_by_handle_at 265
#define __NR_clock_adjtime 266
#define __NR_syncfs 267
#define __NR_setns 268
#define __NR_sendmmsg 269
#define __NR_process_vm_readv 270
#define __NR_process_vm_writev 271
#define __NR_kcmp 272
#define __NR_finit_module 273
#define __NR_sched_setattr 274
#define __NR_sched_getattr 275
#define __NR_renameat2 276
#define __NR_seccomp 277
#define __NR_getrandom 278
#define __NR_memfd_create 279
#define __NR_bpf 280
#define __NR_execveat 281
#define __NR_userfaultfd 282
#define __NR_membarrier 283
#define __NR_mlock2 284
#define __NR_copy_file_range 285
#define __NR_preadv2 286
#define __NR_pwritev2 287
#define __NR_pkey_mprotect 288
#define __NR_pkey_alloc 289
#define __NR_pkey_free 290
#define __NR_statx 291
#define __NR_io_pgetevents 292
#define __NR_rseq 293
#define __NR_kexec_file_load 294
#define __NR_pidfd_send_signal 424
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#define __NR_io_uring_register 427
#define __NR_open_tree 428
#define __NR_move_mount 429
#define __NR_fsopen 430
#define __NR_fsconfig 431
#define __NR_fsmount 432
#define __NR_fspick 433
#define __NR_pidfd_open 434
#define __NR_clone3 435
#define __NR_close_range 436
#define __NR_openat2 437
#define __NR_pidfd_getfd 438
#define __NR_faccessat2 439
#define __NR_process_madvise 440
#define __NR_epoll_pwait2 441
#define __NR_mount_setattr 442
#define __NR_quotactl_fd 443
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#define __NR_memfd_secret 447
#define __NR_process_mrelease 448
#define __NR_futex_waitv 449
#define __NR_set_mempolicy_home_node 450
#define __NR_cachestat 451
#define __NR_fchmodat2 452
#define __NR_map_shadow_stack 453
#define __NR_futex_wake 454
#define __NR_futex_wait 455
#define __NR_futex_requeue 456
#define __NR_statmount 457
#define __NR_listmount 458
#define __NR_lsm_get_self_attr 459
#define __NR_lsm_set_self_attr 460
#define __NR_lsm_list_modules 461
#define __NR_mseal 462
#endif
```