Response:
Let's break down the thought process for analyzing the given `fuse.h` file.

**1. Initial Understanding - What is FUSE?**

The filename `fuse.h` and the comment mentioning it's related to Linux immediately trigger the association with Filesystem in Userspace (FUSE). The path `bionic/libc/kernel/uapi/linux/` reinforces that this is a kernel-userspace API definition within Android's libc.

**2. High-Level Functionality - What does this file define?**

The `#ifndef _LINUX_FUSE_H` and `#define _LINUX_FUSE_H` indicate a header guard, meaning this file defines data structures and constants. Scanning the contents reveals:

* **Version information:** `FUSE_KERNEL_VERSION`, `FUSE_KERNEL_MINOR_VERSION`
* **Data Structures:**  `fuse_attr`, `fuse_statx`, `fuse_kstatfs`, etc. These clearly represent metadata and file system information.
* **Constants/Macros:**  `FATTR_MODE`, `FOPEN_DIRECT_IO`, `FUSE_ASYNC_READ`, `FUSE_LOOKUP`, etc. These are bit flags, options, and operation codes related to FUSE interactions.
* **Enums:** `fuse_ext_type`, `fuse_opcode`, `fuse_notify_code`. These define sets of related values.
* **Input/Output Structures:**  `fuse_entry_out`, `fuse_forget_in`, `fuse_getattr_in`, etc. These define the structure of messages exchanged between user space and the kernel FUSE module.

**3. Connecting to Android Functionality:**

* **Filesystem Abstraction:**  FUSE's core purpose is to allow user-space programs to implement file systems. Android leverages this to support various virtual file systems (e.g., for MTP, SD cards, or even cloud storage).
* **Specific Examples (Initial Thoughts - might refine later):**  Accessing files on an SD card mounted via FUSE, interacting with files served by an MTP device connected to the phone.

**4. Deep Dive into Data Structures and Constants:**

* **`fuse_attr`:**  Standard file attributes (inode, size, timestamps, permissions).
* **`fuse_statx`:**  More detailed file attributes, likely used for newer `statx` system calls.
* **`fuse_kstatfs`:** Filesystem statistics (total/free space, inodes).
* **`FATTR_*`:** Flags indicating which attributes are being set or requested.
* **`FOPEN_*`:** Flags for the `open` operation.
* **`FUSE_*` (Capabilities):**  Features the FUSE implementation supports (async reads, large writes, etc.).
* **`fuse_opcode`:**  The core of the FUSE protocol - the specific operations being requested (lookup, getattr, read, write, etc.).

**5. `libc` Function Implications (The tricky part - the file itself *doesn't* contain `libc` function implementations):**

The key realization here is that this header file *defines* the interface, but the *implementation* resides in the kernel FUSE module. `libc` functions like `open()`, `read()`, `write()`, `getattr()`, etc., will, under certain circumstances (when interacting with a FUSE filesystem), make system calls that eventually lead to these FUSE messages being exchanged.

* **Example:** When a user-space app calls `open("/mnt/sdcard/myfile.txt", O_RDONLY)`, if `/mnt/sdcard` is a FUSE mount point, the `open()` call in `libc` will eventually trigger a FUSE `FUSE_OPEN` request to the kernel. The `fuse_open_in` structure defines the data sent in that request.

**6. Dynamic Linker (SO Layout and Linking):**

This header file is primarily about data structures. While FUSE is used by user-space programs, the dynamic linker isn't directly *processing* this header file in the linking phase. The linker deals with linking against libraries that *use* these definitions.

* **SO Layout (Conceptual):**  A FUSE-based Android app would link against `libc.so`. `libc.so` would contain the implementations of the system calls that interact with the FUSE kernel module.
* **Linking Process:** The app's object files would have references to `libc` functions. The dynamic linker resolves these references at runtime, ensuring the app calls the correct `libc` implementations.

**7. Logic Inference and Assumptions:**

The structures define a clear request-response pattern. For example, a `FUSE_LOOKUP` request (input structure not shown in the provided snippet but exists in the full header) would likely result in a `fuse_entry_out` structure containing information about the looked-up file.

**8. Common User Errors:**

* **Incorrect Permissions:**  Trying to access a file without the necessary permissions (maps to FUSE `FUSE_ACCESS`).
* **Invalid File Paths:** Trying to open a non-existent file (maps to FUSE `FUSE_LOOKUP` failing).
* **Resource Exhaustion:**  Running out of disk space on the FUSE filesystem (maps to FUSE `FUSE_WRITE` failing).

**9. Android Framework/NDK Flow:**

* **Framework:** When an Android app uses `java.io.File` or similar classes to interact with files on a FUSE-mounted filesystem (like SD card), the Java code makes JNI calls to native code in the Android runtime.
* **NDK:**  NDK developers can directly use C/C++ file I/O functions (like `open`, `read`, `write`) which will eventually interact with FUSE if the target path is on a FUSE filesystem.

**10. Frida Hooking (Conceptual):**

You'd need to hook the system calls within `libc` that interact with the kernel FUSE module. Key system calls would be something like `ioctl()` (which is often used for device communication) or potentially the raw syscall interface. Hooking at the `fuse_in_header` and `fuse_out_header` level within the kernel module itself would be more powerful but requires kernel-level hooking.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** This file defines `libc` function implementations. **Correction:** This file defines *data structures* for communication with the kernel. `libc` provides the *glue code* to use these structures via system calls.
* **Initial thought:**  The dynamic linker directly processes this header. **Correction:** The linker resolves symbols in libraries that *use* these definitions.
* **Need to be clear about the levels of abstraction:** User-space app -> `libc` -> system call -> kernel FUSE module -> FUSE filesystem implementation.

By following this structured approach, starting with the big picture and gradually drilling down into details, while constantly connecting the information back to Android's context, we can arrive at a comprehensive understanding of the `fuse.h` file.
这个头文件 `fuse.h` 定义了 Linux FUSE (Filesystem in Userspace) 框架中用户空间和内核空间之间通信所使用的数据结构和常量。由于它位于 `bionic/libc/kernel/uapi/linux/` 目录下，这意味着它是 Android Bionic C 库中关于 FUSE 的用户空间 API 定义。

**功能列举:**

1. **定义 FUSE 协议的数据结构:**  该文件定义了在用户空间 FUSE 客户端和内核 FUSE 模块之间传递消息的各种结构体，例如：
    * `fuse_attr`: 文件属性 (inode, 大小, 时间戳, 权限等)。
    * `fuse_statx`: 更详细的文件属性信息。
    * `fuse_kstatfs`: 文件系统统计信息 (总空间, 可用空间, inode 数量等)。
    * `fuse_file_lock`: 文件锁信息。
    * `fuse_entry_out`: 文件或目录查找结果的信息。
    * `fuse_in_header`, `fuse_out_header`: FUSE 请求和响应的通用头部。
    * 以及各种特定操作的输入/输出结构体，如 `fuse_open_in`, `fuse_read_in`, `fuse_write_out` 等。

2. **定义 FUSE 操作码 (opcodes):**  `enum fuse_opcode` 列举了所有可能的 FUSE 操作，例如：
    * `FUSE_LOOKUP`: 查找文件或目录。
    * `FUSE_GETATTR`: 获取文件或目录属性。
    * `FUSE_READ`, `FUSE_WRITE`: 读写文件。
    * `FUSE_MKDIR`, `FUSE_UNLINK`: 创建和删除目录/文件。
    * `FUSE_OPEN`, `FUSE_RELEASE`: 打开和关闭文件。
    * 以及其他文件系统操作。

3. **定义 FUSE 标志 (flags) 和常量:**  文件中定义了大量的宏常量，用于控制 FUSE 的行为和传递额外的操作信息，例如：
    * `FATTR_*`:  用于指示需要设置或获取哪些文件属性。
    * `FOPEN_*`:  用于 `open` 操作的标志 (如 `FOPEN_DIRECT_IO`, `FOPEN_KEEP_CACHE`)。
    * `FUSE_*`:  表示 FUSE 文件系统支持的特性 (如 `FUSE_ASYNC_READ`, `FUSE_BIG_WRITES`)。
    * `FUSE_IOCTL_*`:  与 ioctl 操作相关的标志。

4. **定义 FUSE 通知码 (notification codes):** `enum fuse_notify_code` 列举了内核向用户空间发送的通知类型。

**与 Android 功能的关系及举例说明:**

FUSE 是 Android 系统中实现某些虚拟文件系统的重要机制。Android 使用 FUSE 来实现以下功能：

* **SD 卡和外部存储挂载:**  当你在 Android 设备上插入 SD 卡或连接外部存储设备时，通常会使用 `sdcardfs` (一个基于 FUSE 的文件系统) 来挂载这些存储设备。这使得用户空间应用程序可以通过标准的文件 I/O 操作访问外部存储。
    * **例子:** 当一个 Android 应用读取 SD 卡上的图片文件时，底层的操作会涉及 FUSE。`java.io.FileInputStream` 或 NDK 中的 `open()` 系统调用最终会触发 FUSE 的 `FUSE_LOOKUP`, `FUSE_OPEN`, `FUSE_READ` 等操作。

* **MTP (Media Transfer Protocol):** 当你的 Android 设备通过 USB 连接到电脑并选择 MTP 模式时，设备上会运行一个 FUSE 服务，将设备上的文件系统暴露给电脑。
    * **例子:** 当你在电脑上通过文件管理器浏览 Android 设备上的照片时，电脑上的 MTP 客户端与 Android 设备上的 FUSE 服务进行通信，而通信的内容就是基于 `fuse.h` 中定义的结构体和操作码。

* **用户定义的文件系统:** Android 允许开发者创建自定义的 FUSE 文件系统，用于特定的应用场景。
    * **例子:**  一个云存储应用可能会使用 FUSE 来创建一个虚拟文件系统，将云端的文件映射到本地的文件路径，使得用户可以直接通过文件管理器访问云端文件。

**详细解释每一个 libc 函数的功能是如何实现的:**

**注意：** 这个 `fuse.h` 文件本身 **没有包含任何 libc 函数的实现**。它只是定义了用于 FUSE 通信的数据结构。

`libc` (Bionic) 中与 FUSE 交互的函数通常是标准的文件 I/O 函数，例如 `open()`, `read()`, `write()`, `getattr()`, `readdir()` 等。当这些函数操作的是一个 FUSE 文件系统上的文件时，Bionic 会将这些操作转换为 FUSE 协议的消息，并发送给内核的 FUSE 模块。

**例如，`open()` 函数的 FUSE 实现过程可能如下：**

1. 用户空间程序调用 `open(pathname, flags, mode)`。
2. Bionic `open()` 函数判断 `pathname` 是否位于一个 FUSE 挂载点上。
3. 如果是，Bionic 会构建一个 `fuse_in_header` 和 `fuse_open_in` 结构体，其中包含操作码 `FUSE_OPEN` 和相关参数 (如 `flags`)。
4. Bionic 使用某种机制 (通常是与 `/dev/fuse` 设备文件的交互) 将这个 FUSE 请求发送给内核。
5. 内核的 FUSE 模块接收到请求，并将其转发给负责该 FUSE 文件系统的用户空间进程。
6. 用户空间 FUSE 进程执行相应的操作 (例如，访问实际的存储设备)，并构建一个 `fuse_out_header` 和可能的其他数据结构作为响应。
7. 响应通过内核 FUSE 模块传递回 Bionic。
8. Bionic `open()` 函数解析响应，并返回文件描述符或错误代码给用户空间程序。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`fuse.h` 本身与 dynamic linker 的直接关系不大。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件) 并解析符号引用。

**SO 布局样本 (针对使用 FUSE 的应用):**

```
Application Process:
  - Executable (APK 的 native library 或独立 native executable)
  - Dependencies:
    - libc.so (Android Bionic C 库，包含文件 I/O 函数的实现)
    - 其他应用依赖的 native 库
    - 可能包含实现特定 FUSE 文件系统的 .so 库 (如果应用自己实现了 FUSE)

libc.so 内部可能包含与 FUSE 交互的代码，但这些代码是通用的文件 I/O 实现，会根据操作的文件路径判断是否需要使用 FUSE。

如果用户空间自己实现了一个 FUSE 文件系统，那么可能会有如下布局：

FUSE File System Process:
  - Executable (用户空间 FUSE 守护进程)
  - Dependencies:
    - libc.so
    - libfuse.so (可选，一些 FUSE 实现会使用 libfuse 库)
    - 自定义的 FUSE 文件系统逻辑的 .so 库
```

**链接的处理过程:**

1. **编译时链接:** 当编译一个使用标准文件 I/O 函数的 Android 应用时，链接器会将应用的 native 代码与 Bionic 的 `libc.so` 链接起来。这意味着应用的代码中对 `open()`, `read()` 等函数的调用会被解析为 `libc.so` 中对应的实现。

2. **运行时链接:** 当应用启动时，dynamic linker 会加载所有依赖的 `.so` 库，包括 `libc.so`。Dynamic linker 会解析应用代码中对 `libc` 函数的引用，并将它们指向 `libc.so` 中实际的函数地址。

**关键点：** `fuse.h` 定义的是内核与用户空间 FUSE 服务之间的通信协议。`libc.so` 提供了使用这个协议的接口 (即标准的文件 I/O 函数)。当这些接口操作 FUSE 文件系统上的文件时，底层的实现会按照 `fuse.h` 中定义的结构发送消息给内核。

**如果做了逻辑推理，请给出假设输入与输出:**

假设一个用户空间程序尝试打开一个位于 FUSE 文件系统上的文件 `/mnt/fuse_mount/myfile.txt` 并读取其内容。

**假设输入 (用户空间程序):**

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
  int fd = open("/mnt/fuse_mount/myfile.txt", O_RDONLY);
  if (fd == -1) {
    perror("open");
    return 1;
  }

  char buffer[1024];
  ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
  if (bytes_read > 0) {
    printf("Read %zd bytes: %.*s\n", bytes_read, (int)bytes_read, buffer);
  } else if (bytes_read == -1) {
    perror("read");
  }

  close(fd);
  return 0;
}
```

**假设输出 (FUSE 交互):**

1. **`open()` 调用:**
   - Bionic 构建一个 `fuse_in_header` 和 `fuse_open_in` 结构体，`opcode` 为 `FUSE_OPEN`，`flags` 包含 `O_RDONLY` 的对应值。
   - 内核 FUSE 模块将此请求发送给负责 `/mnt/fuse_mount` 的 FUSE 用户空间进程。
   - FUSE 用户空间进程执行 `open` 操作，可能访问实际的存储。
   - FUSE 用户空间进程构建一个 `fuse_out_header` 和 `fuse_open_out` 结构体，包含一个文件句柄 `fh`。
   - 内核 FUSE 模块将响应传递回 Bionic。
   - Bionic `open()` 返回文件描述符 `fd`。

2. **`read()` 调用:**
   - Bionic 构建一个 `fuse_in_header` 和 `fuse_read_in` 结构体，`opcode` 为 `FUSE_READ`，包含 `fh` (从 `open()` 获取)，`offset` 为 0，`size` 为 1024。
   - 内核 FUSE 模块将此请求发送给 FUSE 用户空间进程。
   - FUSE 用户空间进程读取文件内容。
   - FUSE 用户空间进程构建一个 `fuse_out_header` 和读取的数据。
   - 内核 FUSE 模块将响应传递回 Bionic。
   - Bionic `read()` 返回读取的字节数 `bytes_read` 和数据。

3. **`close()` 调用:**
   - Bionic 构建一个 `fuse_in_header` 和 `fuse_release_in` 结构体，`opcode` 为 `FUSE_RELEASE`，包含 `fh`。
   - 内核 FUSE 模块将此请求发送给 FUSE 用户空间进程。
   - FUSE 用户空间进程执行清理操作。
   - FUSE 用户空间进程构建一个 `fuse_out_header`。
   - 内核 FUSE 模块将响应传递回 Bionic.

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **权限错误:**  用户尝试访问一个没有权限的文件。
   - **现象:** `open()` 或其他文件操作返回错误，例如 `EACCES` (Permission denied)。
   - **底层 FUSE:** `FUSE_ACCESS` 操作可能会返回错误。

2. **文件不存在:** 用户尝试打开一个不存在的文件。
   - **现象:** `open()` 返回 -1，`errno` 设置为 `ENOENT` (No such file or directory)。
   - **底层 FUSE:** `FUSE_LOOKUP` 操作会找不到对应的 inode。

3. **文件系统只读:** 用户尝试写入一个以只读方式挂载的 FUSE 文件系统。
   - **现象:** `write()` 返回 -1，`errno` 设置为 `EROFS` (Read-only file system)。
   - **底层 FUSE:** `FUSE_WRITE` 操作可能会返回错误。

4. **资源耗尽:**  例如，尝试写入超过文件系统剩余空间的量。
   - **现象:** `write()` 返回的字节数少于请求的字节数，或者返回 -1 并设置 `errno` 为 `ENOSPC` (No space left on device)。
   - **底层 FUSE:** `FUSE_WRITE` 操作可能会返回错误。

5. **忘记 `close()` 文件描述符:**  这会导致 FUSE 文件系统上的资源泄漏，可能导致 FUSE 用户空间进程资源耗尽。
   - **现象:**  长时间运行的程序可能会导致 FUSE 文件系统不稳定。
   - **底层 FUSE:**  对应的 `FUSE_RELEASE` 操作可能不会被触发。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤:**

**Android Framework 到 FUSE 的路径:**

1. **Java 代码:** Android 应用的 Java 代码使用 `java.io.File`, `FileInputStream`, `FileOutputStream` 等类进行文件操作。
2. **JNI 调用:** 这些 Java 文件 I/O 类最终会调用底层的 Native 方法，这些方法位于 Android 运行时 (ART 或 Dalvik) 的 native 库中。
3. **系统调用:** ART 的 native 代码会调用 Linux 系统调用，例如 `open()`, `read()`, `write()`, `getattr()`, `readdir()` 等。
4. **Bionic `libc`:** 这些系统调用会进入 Android 的 Bionic C 库。
5. **FUSE 处理:** 如果操作的文件路径位于一个 FUSE 挂载点，Bionic `libc` 中的文件 I/O 函数会构建相应的 FUSE 请求消息 (基于 `fuse.h` 定义的结构)。
6. **`/dev/fuse` 设备:**  Bionic 使用与 `/dev/fuse` 设备文件的交互来将 FUSE 请求发送给内核。
7. **内核 FUSE 模块:** 内核的 FUSE 模块接收到请求，并根据挂载信息将其转发给负责该 FUSE 文件系统的用户空间进程。
8. **FUSE 用户空间进程:** 用户空间的 FUSE 进程处理请求，并返回响应。
9. **路径反向:** 响应沿着相同的路径返回给应用程序。

**NDK 到 FUSE 的路径:**

1. **NDK 代码:** 使用 Android NDK 开发的应用可以直接使用 C/C++ 的标准文件 I/O 函数 (包含在 `unistd.h` 和 `fcntl.h` 中)，例如 `open()`, `read()`, `write()`.
2. **系统调用:** NDK 代码中的这些函数调用会直接进入 Linux 系统调用。
3. **Bionic `libc` 和后续步骤:**  后面的步骤与 Android Framework 的路径相同，从 Bionic `libc` 处理 FUSE 请求开始。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `open()` 系统调用，并查看其是否与 FUSE 相关的示例：

```javascript
// hook_fuse_open.js

Interceptor.attach(Module.findExportByName(null, "open"), {
  onEnter: function(args) {
    const pathname = Memory.readUtf8String(args[0]);
    const flags = args[1].toInt();
    this.is_fuse = pathname.startsWith("/mnt/"); // 假设 FUSE 挂载点在 /mnt/ 下

    if (this.is_fuse) {
      console.log("Opening FUSE file:", pathname, "flags:", flags);
    }
  },
  onLeave: function(retval) {
    if (this.is_fuse) {
      console.log("open() returned:", retval);
    }
  }
});
```

**使用 Frida 运行 Hook:**

1. 将上述 JavaScript 代码保存为 `hook_fuse_open.js`。
2. 找到目标 Android 进程的 PID。
3. 使用 Frida 连接到目标进程并运行 Hook：

   ```bash
   frida -U -f <package_name> -l hook_fuse_open.js --no-pause
   # 或者连接到已运行的进程
   frida -U <package_name> -l hook_fuse_open.js
   ```

**更深入的 FUSE 调试:**

要调试更底层的 FUSE 交互，你可以尝试 Hook 以下内容：

* **`/dev/fuse` 设备的 `ioctl()` 调用:**  FUSE 用户空间进程通常使用 `ioctl()` 系统调用与内核 FUSE 模块通信。你可以 Hook `ioctl()` 并检查其参数，以查看发送和接收的 FUSE 消息。
* **FUSE 用户空间进程:** 如果你知道负责特定 FUSE 挂载点的用户空间进程，你可以 Hook 该进程中的相关函数，例如处理 FUSE 请求的函数。

**注意:**  Hook 系统调用和设备文件交互可能需要 root 权限。调试 FUSE 涉及内核和用户空间多个组件，可能需要一定的 Linux 系统编程和 FUSE 协议知识。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/fuse.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_FUSE_H
#define _LINUX_FUSE_H
#include <stdint.h>
#define FUSE_KERNEL_VERSION 7
#define FUSE_KERNEL_MINOR_VERSION 41
#define FUSE_ROOT_ID 1
struct fuse_attr {
  uint64_t ino;
  uint64_t size;
  uint64_t blocks;
  uint64_t atime;
  uint64_t mtime;
  uint64_t ctime;
  uint32_t atimensec;
  uint32_t mtimensec;
  uint32_t ctimensec;
  uint32_t mode;
  uint32_t nlink;
  uint32_t uid;
  uint32_t gid;
  uint32_t rdev;
  uint32_t blksize;
  uint32_t flags;
};
struct fuse_sx_time {
  int64_t tv_sec;
  uint32_t tv_nsec;
  int32_t __reserved;
};
struct fuse_statx {
  uint32_t mask;
  uint32_t blksize;
  uint64_t attributes;
  uint32_t nlink;
  uint32_t uid;
  uint32_t gid;
  uint16_t mode;
  uint16_t __spare0[1];
  uint64_t ino;
  uint64_t size;
  uint64_t blocks;
  uint64_t attributes_mask;
  struct fuse_sx_time atime;
  struct fuse_sx_time btime;
  struct fuse_sx_time ctime;
  struct fuse_sx_time mtime;
  uint32_t rdev_major;
  uint32_t rdev_minor;
  uint32_t dev_major;
  uint32_t dev_minor;
  uint64_t __spare2[14];
};
struct fuse_kstatfs {
  uint64_t blocks;
  uint64_t bfree;
  uint64_t bavail;
  uint64_t files;
  uint64_t ffree;
  uint32_t bsize;
  uint32_t namelen;
  uint32_t frsize;
  uint32_t padding;
  uint32_t spare[6];
};
struct fuse_file_lock {
  uint64_t start;
  uint64_t end;
  uint32_t type;
  uint32_t pid;
};
#define FATTR_MODE (1 << 0)
#define FATTR_UID (1 << 1)
#define FATTR_GID (1 << 2)
#define FATTR_SIZE (1 << 3)
#define FATTR_ATIME (1 << 4)
#define FATTR_MTIME (1 << 5)
#define FATTR_FH (1 << 6)
#define FATTR_ATIME_NOW (1 << 7)
#define FATTR_MTIME_NOW (1 << 8)
#define FATTR_LOCKOWNER (1 << 9)
#define FATTR_CTIME (1 << 10)
#define FATTR_KILL_SUIDGID (1 << 11)
#define FOPEN_DIRECT_IO (1 << 0)
#define FOPEN_KEEP_CACHE (1 << 1)
#define FOPEN_NONSEEKABLE (1 << 2)
#define FOPEN_CACHE_DIR (1 << 3)
#define FOPEN_STREAM (1 << 4)
#define FOPEN_NOFLUSH (1 << 5)
#define FOPEN_PARALLEL_DIRECT_WRITES (1 << 6)
#define FOPEN_PASSTHROUGH (1 << 7)
#define FUSE_ASYNC_READ (1 << 0)
#define FUSE_POSIX_LOCKS (1 << 1)
#define FUSE_FILE_OPS (1 << 2)
#define FUSE_ATOMIC_O_TRUNC (1 << 3)
#define FUSE_EXPORT_SUPPORT (1 << 4)
#define FUSE_BIG_WRITES (1 << 5)
#define FUSE_DONT_MASK (1 << 6)
#define FUSE_SPLICE_WRITE (1 << 7)
#define FUSE_SPLICE_MOVE (1 << 8)
#define FUSE_SPLICE_READ (1 << 9)
#define FUSE_FLOCK_LOCKS (1 << 10)
#define FUSE_HAS_IOCTL_DIR (1 << 11)
#define FUSE_AUTO_INVAL_DATA (1 << 12)
#define FUSE_DO_READDIRPLUS (1 << 13)
#define FUSE_READDIRPLUS_AUTO (1 << 14)
#define FUSE_ASYNC_DIO (1 << 15)
#define FUSE_WRITEBACK_CACHE (1 << 16)
#define FUSE_NO_OPEN_SUPPORT (1 << 17)
#define FUSE_PARALLEL_DIROPS (1 << 18)
#define FUSE_HANDLE_KILLPRIV (1 << 19)
#define FUSE_POSIX_ACL (1 << 20)
#define FUSE_ABORT_ERROR (1 << 21)
#define FUSE_MAX_PAGES (1 << 22)
#define FUSE_CACHE_SYMLINKS (1 << 23)
#define FUSE_NO_OPENDIR_SUPPORT (1 << 24)
#define FUSE_EXPLICIT_INVAL_DATA (1 << 25)
#define FUSE_MAP_ALIGNMENT (1 << 26)
#define FUSE_SUBMOUNTS (1 << 27)
#define FUSE_HANDLE_KILLPRIV_V2 (1 << 28)
#define FUSE_SETXATTR_EXT (1 << 29)
#define FUSE_INIT_EXT (1 << 30)
#define FUSE_INIT_RESERVED (1 << 31)
#define FUSE_SECURITY_CTX (1ULL << 32)
#define FUSE_HAS_INODE_DAX (1ULL << 33)
#define FUSE_CREATE_SUPP_GROUP (1ULL << 34)
#define FUSE_HAS_EXPIRE_ONLY (1ULL << 35)
#define FUSE_DIRECT_IO_ALLOW_MMAP (1ULL << 36)
#define FUSE_PASSTHROUGH (1ULL << 37)
#define FUSE_NO_EXPORT_SUPPORT (1ULL << 38)
#define FUSE_HAS_RESEND (1ULL << 39)
#define FUSE_DIRECT_IO_RELAX FUSE_DIRECT_IO_ALLOW_MMAP
#define FUSE_ALLOW_IDMAP (1ULL << 40)
#define CUSE_UNRESTRICTED_IOCTL (1 << 0)
#define FUSE_RELEASE_FLUSH (1 << 0)
#define FUSE_RELEASE_FLOCK_UNLOCK (1 << 1)
#define FUSE_GETATTR_FH (1 << 0)
#define FUSE_LK_FLOCK (1 << 0)
#define FUSE_WRITE_CACHE (1 << 0)
#define FUSE_WRITE_LOCKOWNER (1 << 1)
#define FUSE_WRITE_KILL_SUIDGID (1 << 2)
#define FUSE_WRITE_KILL_PRIV FUSE_WRITE_KILL_SUIDGID
#define FUSE_READ_LOCKOWNER (1 << 1)
#define FUSE_IOCTL_COMPAT (1 << 0)
#define FUSE_IOCTL_UNRESTRICTED (1 << 1)
#define FUSE_IOCTL_RETRY (1 << 2)
#define FUSE_IOCTL_32BIT (1 << 3)
#define FUSE_IOCTL_DIR (1 << 4)
#define FUSE_IOCTL_COMPAT_X32 (1 << 5)
#define FUSE_IOCTL_MAX_IOV 256
#define FUSE_POLL_SCHEDULE_NOTIFY (1 << 0)
#define FUSE_FSYNC_FDATASYNC (1 << 0)
#define FUSE_ATTR_SUBMOUNT (1 << 0)
#define FUSE_ATTR_DAX (1 << 1)
#define FUSE_OPEN_KILL_SUIDGID (1 << 0)
#define FUSE_SETXATTR_ACL_KILL_SGID (1 << 0)
#define FUSE_EXPIRE_ONLY (1 << 0)
enum fuse_ext_type {
  FUSE_MAX_NR_SECCTX = 31,
  FUSE_EXT_GROUPS = 32,
};
enum fuse_opcode {
  FUSE_LOOKUP = 1,
  FUSE_FORGET = 2,
  FUSE_GETATTR = 3,
  FUSE_SETATTR = 4,
  FUSE_READLINK = 5,
  FUSE_SYMLINK = 6,
  FUSE_MKNOD = 8,
  FUSE_MKDIR = 9,
  FUSE_UNLINK = 10,
  FUSE_RMDIR = 11,
  FUSE_RENAME = 12,
  FUSE_LINK = 13,
  FUSE_OPEN = 14,
  FUSE_READ = 15,
  FUSE_WRITE = 16,
  FUSE_STATFS = 17,
  FUSE_RELEASE = 18,
  FUSE_FSYNC = 20,
  FUSE_SETXATTR = 21,
  FUSE_GETXATTR = 22,
  FUSE_LISTXATTR = 23,
  FUSE_REMOVEXATTR = 24,
  FUSE_FLUSH = 25,
  FUSE_INIT = 26,
  FUSE_OPENDIR = 27,
  FUSE_READDIR = 28,
  FUSE_RELEASEDIR = 29,
  FUSE_FSYNCDIR = 30,
  FUSE_GETLK = 31,
  FUSE_SETLK = 32,
  FUSE_SETLKW = 33,
  FUSE_ACCESS = 34,
  FUSE_CREATE = 35,
  FUSE_INTERRUPT = 36,
  FUSE_BMAP = 37,
  FUSE_DESTROY = 38,
  FUSE_IOCTL = 39,
  FUSE_POLL = 40,
  FUSE_NOTIFY_REPLY = 41,
  FUSE_BATCH_FORGET = 42,
  FUSE_FALLOCATE = 43,
  FUSE_READDIRPLUS = 44,
  FUSE_RENAME2 = 45,
  FUSE_LSEEK = 46,
  FUSE_COPY_FILE_RANGE = 47,
  FUSE_SETUPMAPPING = 48,
  FUSE_REMOVEMAPPING = 49,
  FUSE_SYNCFS = 50,
  FUSE_TMPFILE = 51,
  FUSE_STATX = 52,
  FUSE_CANONICAL_PATH = 2016,
  CUSE_INIT = 4096,
  CUSE_INIT_BSWAP_RESERVED = 1048576,
  FUSE_INIT_BSWAP_RESERVED = 436207616,
};
enum fuse_notify_code {
  FUSE_NOTIFY_POLL = 1,
  FUSE_NOTIFY_INVAL_INODE = 2,
  FUSE_NOTIFY_INVAL_ENTRY = 3,
  FUSE_NOTIFY_STORE = 4,
  FUSE_NOTIFY_RETRIEVE = 5,
  FUSE_NOTIFY_DELETE = 6,
  FUSE_NOTIFY_RESEND = 7,
  FUSE_NOTIFY_CODE_MAX,
};
#define FUSE_MIN_READ_BUFFER 8192
#define FUSE_COMPAT_ENTRY_OUT_SIZE 120
struct fuse_entry_out {
  uint64_t nodeid;
  uint64_t generation;
  uint64_t entry_valid;
  uint64_t attr_valid;
  uint32_t entry_valid_nsec;
  uint32_t attr_valid_nsec;
  struct fuse_attr attr;
};
struct fuse_forget_in {
  uint64_t nlookup;
};
struct fuse_forget_one {
  uint64_t nodeid;
  uint64_t nlookup;
};
struct fuse_batch_forget_in {
  uint32_t count;
  uint32_t dummy;
};
struct fuse_getattr_in {
  uint32_t getattr_flags;
  uint32_t dummy;
  uint64_t fh;
};
#define FUSE_COMPAT_ATTR_OUT_SIZE 96
struct fuse_attr_out {
  uint64_t attr_valid;
  uint32_t attr_valid_nsec;
  uint32_t dummy;
  struct fuse_attr attr;
};
struct fuse_statx_in {
  uint32_t getattr_flags;
  uint32_t reserved;
  uint64_t fh;
  uint32_t sx_flags;
  uint32_t sx_mask;
};
struct fuse_statx_out {
  uint64_t attr_valid;
  uint32_t attr_valid_nsec;
  uint32_t flags;
  uint64_t spare[2];
  struct fuse_statx stat;
};
#define FUSE_COMPAT_MKNOD_IN_SIZE 8
struct fuse_mknod_in {
  uint32_t mode;
  uint32_t rdev;
  uint32_t umask;
  uint32_t padding;
};
struct fuse_mkdir_in {
  uint32_t mode;
  uint32_t umask;
};
struct fuse_rename_in {
  uint64_t newdir;
};
struct fuse_rename2_in {
  uint64_t newdir;
  uint32_t flags;
  uint32_t padding;
};
struct fuse_link_in {
  uint64_t oldnodeid;
};
struct fuse_setattr_in {
  uint32_t valid;
  uint32_t padding;
  uint64_t fh;
  uint64_t size;
  uint64_t lock_owner;
  uint64_t atime;
  uint64_t mtime;
  uint64_t ctime;
  uint32_t atimensec;
  uint32_t mtimensec;
  uint32_t ctimensec;
  uint32_t mode;
  uint32_t unused4;
  uint32_t uid;
  uint32_t gid;
  uint32_t unused5;
};
struct fuse_open_in {
  uint32_t flags;
  uint32_t open_flags;
};
struct fuse_create_in {
  uint32_t flags;
  uint32_t mode;
  uint32_t umask;
  uint32_t open_flags;
};
struct fuse_open_out {
  uint64_t fh;
  uint32_t open_flags;
  int32_t backing_id;
};
struct fuse_release_in {
  uint64_t fh;
  uint32_t flags;
  uint32_t release_flags;
  uint64_t lock_owner;
};
struct fuse_flush_in {
  uint64_t fh;
  uint32_t unused;
  uint32_t padding;
  uint64_t lock_owner;
};
struct fuse_read_in {
  uint64_t fh;
  uint64_t offset;
  uint32_t size;
  uint32_t read_flags;
  uint64_t lock_owner;
  uint32_t flags;
  uint32_t padding;
};
#define FUSE_COMPAT_WRITE_IN_SIZE 24
struct fuse_write_in {
  uint64_t fh;
  uint64_t offset;
  uint32_t size;
  uint32_t write_flags;
  uint64_t lock_owner;
  uint32_t flags;
  uint32_t padding;
};
struct fuse_write_out {
  uint32_t size;
  uint32_t padding;
};
#define FUSE_COMPAT_STATFS_SIZE 48
struct fuse_statfs_out {
  struct fuse_kstatfs st;
};
struct fuse_fsync_in {
  uint64_t fh;
  uint32_t fsync_flags;
  uint32_t padding;
};
#define FUSE_COMPAT_SETXATTR_IN_SIZE 8
struct fuse_setxattr_in {
  uint32_t size;
  uint32_t flags;
  uint32_t setxattr_flags;
  uint32_t padding;
};
struct fuse_getxattr_in {
  uint32_t size;
  uint32_t padding;
};
struct fuse_getxattr_out {
  uint32_t size;
  uint32_t padding;
};
struct fuse_lk_in {
  uint64_t fh;
  uint64_t owner;
  struct fuse_file_lock lk;
  uint32_t lk_flags;
  uint32_t padding;
};
struct fuse_lk_out {
  struct fuse_file_lock lk;
};
struct fuse_access_in {
  uint32_t mask;
  uint32_t padding;
};
struct fuse_init_in {
  uint32_t major;
  uint32_t minor;
  uint32_t max_readahead;
  uint32_t flags;
  uint32_t flags2;
  uint32_t unused[11];
};
#define FUSE_COMPAT_INIT_OUT_SIZE 8
#define FUSE_COMPAT_22_INIT_OUT_SIZE 24
struct fuse_init_out {
  uint32_t major;
  uint32_t minor;
  uint32_t max_readahead;
  uint32_t flags;
  uint16_t max_background;
  uint16_t congestion_threshold;
  uint32_t max_write;
  uint32_t time_gran;
  uint16_t max_pages;
  uint16_t map_alignment;
  uint32_t flags2;
  uint32_t max_stack_depth;
  uint32_t unused[6];
};
#define CUSE_INIT_INFO_MAX 4096
struct cuse_init_in {
  uint32_t major;
  uint32_t minor;
  uint32_t unused;
  uint32_t flags;
};
struct cuse_init_out {
  uint32_t major;
  uint32_t minor;
  uint32_t unused;
  uint32_t flags;
  uint32_t max_read;
  uint32_t max_write;
  uint32_t dev_major;
  uint32_t dev_minor;
  uint32_t spare[10];
};
struct fuse_interrupt_in {
  uint64_t unique;
};
struct fuse_bmap_in {
  uint64_t block;
  uint32_t blocksize;
  uint32_t padding;
};
struct fuse_bmap_out {
  uint64_t block;
};
struct fuse_ioctl_in {
  uint64_t fh;
  uint32_t flags;
  uint32_t cmd;
  uint64_t arg;
  uint32_t in_size;
  uint32_t out_size;
};
struct fuse_ioctl_iovec {
  uint64_t base;
  uint64_t len;
};
struct fuse_ioctl_out {
  int32_t result;
  uint32_t flags;
  uint32_t in_iovs;
  uint32_t out_iovs;
};
struct fuse_poll_in {
  uint64_t fh;
  uint64_t kh;
  uint32_t flags;
  uint32_t events;
};
struct fuse_poll_out {
  uint32_t revents;
  uint32_t padding;
};
struct fuse_notify_poll_wakeup_out {
  uint64_t kh;
};
struct fuse_fallocate_in {
  uint64_t fh;
  uint64_t offset;
  uint64_t length;
  uint32_t mode;
  uint32_t padding;
};
#define FUSE_UNIQUE_RESEND (1ULL << 63)
#define FUSE_INVALID_UIDGID ((uint32_t) (- 1))
struct fuse_in_header {
  uint32_t len;
  uint32_t opcode;
  uint64_t unique;
  uint64_t nodeid;
  uint32_t uid;
  uint32_t gid;
  uint32_t pid;
  uint16_t total_extlen;
  uint16_t padding;
};
struct fuse_out_header {
  uint32_t len;
  int32_t error;
  uint64_t unique;
};
struct fuse_dirent {
  uint64_t ino;
  uint64_t off;
  uint32_t namelen;
  uint32_t type;
  char name[];
};
#define FUSE_REC_ALIGN(x) (((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))
#define FUSE_NAME_OFFSET offsetof(struct fuse_dirent, name)
#define FUSE_DIRENT_ALIGN(x) FUSE_REC_ALIGN(x)
#define FUSE_DIRENT_SIZE(d) FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)
struct fuse_direntplus {
  struct fuse_entry_out entry_out;
  struct fuse_dirent dirent;
};
#define FUSE_NAME_OFFSET_DIRENTPLUS offsetof(struct fuse_direntplus, dirent.name)
#define FUSE_DIRENTPLUS_SIZE(d) FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET_DIRENTPLUS + (d)->dirent.namelen)
struct fuse_notify_inval_inode_out {
  uint64_t ino;
  int64_t off;
  int64_t len;
};
struct fuse_notify_inval_entry_out {
  uint64_t parent;
  uint32_t namelen;
  uint32_t flags;
};
struct fuse_notify_delete_out {
  uint64_t parent;
  uint64_t child;
  uint32_t namelen;
  uint32_t padding;
};
struct fuse_notify_store_out {
  uint64_t nodeid;
  uint64_t offset;
  uint32_t size;
  uint32_t padding;
};
struct fuse_notify_retrieve_out {
  uint64_t notify_unique;
  uint64_t nodeid;
  uint64_t offset;
  uint32_t size;
  uint32_t padding;
};
struct fuse_notify_retrieve_in {
  uint64_t dummy1;
  uint64_t offset;
  uint32_t size;
  uint32_t dummy2;
  uint64_t dummy3;
  uint64_t dummy4;
};
struct fuse_backing_map {
  int32_t fd;
  uint32_t flags;
  uint64_t padding;
};
#define FUSE_DEV_IOC_MAGIC 229
#define FUSE_DEV_IOC_CLONE _IOR(FUSE_DEV_IOC_MAGIC, 0, uint32_t)
#define FUSE_DEV_IOC_BACKING_OPEN _IOW(FUSE_DEV_IOC_MAGIC, 1, struct fuse_backing_map)
#define FUSE_DEV_IOC_BACKING_CLOSE _IOW(FUSE_DEV_IOC_MAGIC, 2, uint32_t)
struct fuse_lseek_in {
  uint64_t fh;
  uint64_t offset;
  uint32_t whence;
  uint32_t padding;
};
struct fuse_lseek_out {
  uint64_t offset;
};
struct fuse_copy_file_range_in {
  uint64_t fh_in;
  uint64_t off_in;
  uint64_t nodeid_out;
  uint64_t fh_out;
  uint64_t off_out;
  uint64_t len;
  uint64_t flags;
};
#define FUSE_SETUPMAPPING_FLAG_WRITE (1ull << 0)
#define FUSE_SETUPMAPPING_FLAG_READ (1ull << 1)
struct fuse_setupmapping_in {
  uint64_t fh;
  uint64_t foffset;
  uint64_t len;
  uint64_t flags;
  uint64_t moffset;
};
struct fuse_removemapping_in {
  uint32_t count;
};
struct fuse_removemapping_one {
  uint64_t moffset;
  uint64_t len;
};
#define FUSE_REMOVEMAPPING_MAX_ENTRY (PAGE_SIZE / sizeof(struct fuse_removemapping_one))
struct fuse_syncfs_in {
  uint64_t padding;
};
struct fuse_secctx {
  uint32_t size;
  uint32_t padding;
};
struct fuse_secctx_header {
  uint32_t size;
  uint32_t nr_secctx;
};
struct fuse_ext_header {
  uint32_t size;
  uint32_t type;
};
struct fuse_supp_groups {
  uint32_t nr_groups;
  uint32_t groups[];
};
#endif

"""

```