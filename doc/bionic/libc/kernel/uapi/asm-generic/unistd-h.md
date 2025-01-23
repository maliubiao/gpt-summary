Response:
Let's break down the thought process for answering the user's request about `unistd.handroid`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided C header file (`unistd.handroid`) which defines system call numbers. They are particularly interested in its relationship with Android, how the functions are implemented (especially libc functions and dynamic linker aspects), potential usage errors, and how to trace its usage from Android frameworks/NDK.

**2. Initial Analysis of the File Content:**

The file predominantly consists of `#define` macros. A key observation is the pattern `__NR_... number`. This immediately suggests that these definitions are mapping symbolic names to numerical identifiers for system calls. The presence of `__SYSCALL`, `__SC_3264`, and `__SC_COMP` indicates architecture-specific handling, particularly for 32-bit and 64-bit systems and compatibility layers. The comment at the beginning also confirms it's auto-generated and part of Bionic, Android's C library.

**3. Identifying Key Functional Areas:**

Based on the system call names (e.g., `openat`, `read`, `write`, `mmap`, `execve`), I can categorize the functionalities into:

* **File I/O:** Operations like opening, reading, writing, closing files.
* **Process Management:**  Creating, terminating, and managing processes (e.g., `clone`, `execve`, `exit`).
* **Memory Management:** Allocating, mapping, and managing memory (e.g., `mmap`, `munmap`).
* **Inter-Process Communication (IPC):** Mechanisms for processes to communicate (e.g., `pipe`, `socket`, `mq`).
* **Time and Scheduling:**  Functions related to time and process scheduling (e.g., `nanosleep`, `sched_setaffinity`).
* **Security and Permissions:**  System calls related to security attributes and permissions (e.g., `setxattr`, `capget`).
* **Other System Operations:**  A miscellaneous category for other kernel functionalities (e.g., `reboot`, `uname`).

**4. Addressing Specific User Questions:**

* **Functionality Listing:**  This is straightforward based on the identified categories. I'll list the categories and provide some representative examples.
* **Relationship with Android:**  This is crucial. Android uses these system calls extensively. I need to give concrete examples at the framework, NDK, and even application level. Examples like file access, networking, process creation, and memory allocation are good choices.
* **libc Function Implementation:** This is a tricky one because `unistd.handroid` only *defines* the system call numbers, it doesn't contain the libc *implementations*. The key is to explain that the *actual implementation* resides in the kernel. The libc functions act as wrappers that make the system call. I need to explain this wrapper concept.
* **Dynamic Linker:**  The provided file *doesn't directly involve* the dynamic linker. However, system calls like `execve` (which is present) are the *trigger* for the dynamic linker to load shared libraries. I should explain this indirect relationship and provide a basic example of an SO layout and the linking process.
* **Logic Inference:**  The file doesn't contain complex logic. The "inference" is the mapping of names to numbers. I can create a simple example demonstrating this mapping.
* **Common Usage Errors:**  Focus on errors related to incorrect parameters, permissions, file not found, etc., when using the corresponding libc functions that eventually lead to these system calls.
* **Android Framework/NDK to System Call:** This requires explaining the layers involved: Android framework (Java/Kotlin) -> Native code (NDK) -> Bionic libc -> System call. I need to give a concrete example, like opening a file, and trace it through these layers.
* **Frida Hook Example:**  A Frida example should demonstrate how to intercept a system call. `openat` is a good candidate as it's commonly used. The hook needs to show how to get arguments and potentially modify the behavior.

**5. Structuring the Answer:**

A logical flow is important for clarity. I'll organize the answer as follows:

* **Introduction:** Briefly explain what the file is and its purpose.
* **Functionality Listing:** Categorized list of system calls.
* **Relationship with Android:** Explain the connection and provide examples at different levels.
* **libc Function Implementation:** Explain the wrapper function concept and the kernel's role.
* **Dynamic Linker:** Explain the indirect relationship, provide an SO layout example, and the linking process.
* **Logic Inference Example:** Demonstrate the mapping of names to numbers.
* **Common Usage Errors:**  Give examples of errors related to the system calls.
* **Android Framework/NDK to System Call:** Trace a concrete example.
* **Frida Hook Example:**  Provide a Frida script for intercepting a system call.
* **Conclusion:** Summarize the key takeaways.

**6. Refinement and Details:**

* **Accuracy:** Ensure the system call descriptions are correct and relevant.
* **Clarity:** Use clear and concise language, avoiding jargon where possible.
* **Completeness:** Address all aspects of the user's request.
* **Examples:** Provide practical examples to illustrate the concepts.
* **Formatting:** Use formatting (like code blocks) to improve readability.

**Self-Correction/Refinement during the thought process:**

* Initially, I might have thought of explaining the implementation of *every* libc function. However, realizing that `unistd.handroid` only defines the numbers, I corrected myself to focus on the *wrapper concept* and the kernel's role.
* I considered providing a detailed explanation of the dynamic linking process. But given that the file doesn't directly relate to it, I decided to keep the dynamic linker explanation concise and focus on the trigger (like `execve`).
* For the Frida example, I initially thought of a more complex scenario. However, a simple hook for `openat` is more illustrative for understanding the basic principle.

By following this thought process, I can construct a comprehensive and accurate answer that addresses all the user's questions about the `unistd.handroid` file.
这是一个定义了一系列Linux系统调用号的C头文件，专门用于Android Bionic 库。它并不包含任何实际的函数实现，而是为Bionic libc 提供了与Linux内核进行交互的“号码簿”。

**它的主要功能是：**

1. **定义系统调用号 (System Call Numbers):**  每个`#define __NR_xxx number` 这样的宏定义都将一个系统调用的名称（例如 `__NR_openat`）映射到一个唯一的数字（例如 `56`）。 这个数字是 Bionic libc 通过 `syscall()` 函数向Linux内核发起系统调用时使用的标识符。

2. **提供架构兼容性支持:**  通过 `__BITS_PER_LONG`、`__SYSCALL_COMPAT` 等宏，该文件可以根据不同的处理器架构（32位或64位）以及兼容性需求，定义不同的系统调用号。例如，对于某些系统调用，32位和64位系统可能使用不同的编号，或者在进行32位兼容性调用时需要使用特殊的编号。

3. **作为Bionic libc和Linux内核之间的桥梁:**  Bionic libc 中的许多函数（例如 `open()`, `read()`, `write()` 等）最终会通过 `syscall()` 函数调用到 Linux 内核。 这个头文件提供的系统调用号就是 `syscall()` 函数的关键参数。

**它与 Android 功能的关系以及举例说明：**

这个文件是 Android 系统底层运作的核心组成部分，几乎所有的 Android 功能都直接或间接地依赖于这些系统调用。

* **文件操作:** 当 Android 应用或 Framework 需要打开、读取、写入或删除文件时，最终会调用 Bionic libc 提供的 `open()`, `read()`, `write()`, `unlink()` 等函数。 这些函数内部会使用这里定义的 `__NR_openat`, `__NR_read`, `__NR_write`, `__NR_unlinkat` 等系统调用号来请求内核执行相应的操作。
    * **举例:** 当你在 Android 手机上点击一个文件管理器应用，打开一个图片时，应用会调用 `open()` 函数，Bionic libc 会使用 `__NR_openat` 系统调用号通知内核打开该文件。

* **进程管理:**  Android 系统中创建新进程、结束进程等操作，也依赖于这里的系统调用。例如，`fork()`, `execve()`, `exit()` 等 libc 函数会分别使用 `__NR_clone`, `__NR_execve`, `__NR_exit_group` 等系统调用。
    * **举例:** 当你启动一个新的 Android 应用时，zygote 进程会 `fork()` 出一个新的进程，然后调用 `execve()` 加载应用的代码。这两个操作分别对应 `__NR_clone` 和 `__NR_execve` 系统调用。

* **网络通信:**  Android 的网络功能，例如建立 TCP 连接、发送 UDP 数据包等，也需要使用系统调用。`socket()`, `bind()`, `connect()`, `sendto()`, `recvfrom()` 等 libc 网络函数会使用 `__NR_socket`, `__NR_bind`, `__NR_connect`, `__NR_sendto`, `__NR_recvfrom` 等系统调用。
    * **举例:** 当你的 Android 应用访问一个网站时，它会使用 `socket()` 创建一个套接字，然后 `connect()` 到服务器，这些操作都依赖于相应的系统调用。

* **内存管理:**  Android 系统的内存分配和管理，例如分配内存、释放内存、映射文件到内存等，也离不开系统调用。`mmap()`, `munmap()`, `brk()` 等 libc 函数会使用 `__NR_mmap`, `__NR_munmap`, `__NR_brk` 等系统调用。
    * **举例:** 当 Android 系统加载一个 APK 文件时，它会使用 `mmap()` 将 APK 文件映射到内存中，以便高效地访问其中的代码和资源。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个 `unistd.handroid` 文件本身 **不包含任何 libc 函数的实现**。 它只是定义了系统调用号。

libc 函数的实现位于 Bionic libc 的其他源文件中（通常在 `bionic/libc/` 目录下）。  一个典型的 libc 函数实现会包含以下步骤：

1. **参数处理和验证:** 检查传入的参数是否合法。
2. **设置系统调用参数:** 将 libc 函数的参数转换为系统调用所需的参数格式。
3. **调用 `syscall()` 函数:** 使用 `syscall()` 函数，并将对应的系统调用号（从 `unistd.handroid` 中获取）和准备好的参数传递给内核。
4. **处理系统调用返回值:**  内核执行完系统调用后会返回一个值，libc 函数会根据返回值判断调用是否成功，并设置 `errno` 全局变量（如果发生错误）。
5. **返回结果:** 将系统调用的结果转换为 libc 函数的返回值。

**以 `openat()` 函数为例：**

```c
// 假设的 openat() 函数在 Bionic libc 中的简化实现
#include <fcntl.h>
#include <syscall.h>
#include <errno.h>
#include <unistd.h> // 包含 unistd.h，其中可能会间接包含 unistd.handroid

int openat(int dirfd, const char *pathname, int flags, ...) {
  mode_t mode = 0;
  if (__OPEN_NEEDS_MODE(flags)) {
    va_list arg;
    va_start(arg, flags);
    mode = va_arg(arg, mode_t);
    va_end(arg);
  }
  long ret = syscall(__NR_openat, dirfd, pathname, flags, mode); // 使用 __NR_openat
  if (ret < 0) {
    errno = -ret; // 系统调用返回负数表示错误，取反并赋值给 errno
    return -1;
  }
  return ret;
}
```

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`unistd.handroid` 文件本身 **不直接涉及 dynamic linker 的功能**。 动态链接器 (linker64/linker) 的主要职责是在程序启动时加载所需的共享库 (`.so` 文件）并将它们链接到应用程序的地址空间。

然而，某些系统调用，例如 `execve()`, 是程序启动的关键，会触发动态链接器的运行。

**SO 布局样本：**

假设我们有一个应用程序 `app`，它链接了两个共享库 `liba.so` 和 `libb.so`。

```
/system/bin/app  (主程序)
/system/lib64/liba.so
/system/lib64/libb.so
```

**链接的处理过程 (以 `execve()` 为例)：**

1. **`execve()` 系统调用:** 当 Android 系统需要启动 `app` 时，会调用 `execve()` 系统调用。`execve()` 的参数包括程序路径 `/system/bin/app` 和环境变量等。

2. **内核加载程序:** 内核会加载 `app` 的可执行文件头，并识别出它是一个动态链接的程序。

3. **动态链接器启动:**  内核会启动动态链接器（通常是 `/system/bin/linker64` 或 `/system/bin/linker`），并将控制权交给它。

4. **解析依赖关系:** 动态链接器会读取 `app` 的 ELF 头信息，找到它所依赖的共享库 (`liba.so`, `libb.so`)。

5. **加载共享库:** 动态链接器会根据配置（例如 `LD_LIBRARY_PATH` 环境变量），在文件系统中查找并加载这些共享库到内存中。

6. **符号解析和重定位:**
   * **符号解析:** 动态链接器会查找 `app` 中引用的来自共享库的符号（函数、全局变量等）。
   * **重定位:**  由于共享库被加载到内存中的地址可能不是编译时的地址，动态链接器需要修改 `app` 和共享库中的地址引用，使其指向正确的内存地址。这涉及到修改 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table)。

7. **执行初始化代码:** 动态链接器会执行每个加载的共享库中的初始化函数 (`.init` 和 `.ctors` 段中的代码）。

8. **将控制权交给应用程序:** 链接完成后，动态链接器会将控制权交给应用程序的入口点。

**逻辑推理，假设输入与输出：**

这个文件主要是定义，逻辑推理比较少。一个简单的逻辑推理是基于架构判断使用哪个系统调用号：

**假设输入:**  `__BITS_PER_LONG` 为 64 (表示 64 位架构)

**文件内容:**
```c
#define __NR3264_fcntl 25
#if __BITS_PER_LONG == 64
#define __NR_fcntl __NR3264_fcntl
#endif
```

**输出:**  `__NR_fcntl` 的值会被定义为 `25`。

**假设输入:** `__BITS_PER_LONG` 为 32 (表示 32 位架构)

**文件内容:**  同上

**输出:**  `__NR_fcntl` 的值不会被定义为 `25`，可能会有其他针对 32 位的定义。

**涉及用户或者编程常见的使用错误，请举例说明：**

虽然这个文件本身不涉及直接的用户编程，但它定义的系统调用号是 libc 函数的基础，因此与用户编程错误密切相关。

1. **使用了错误的系统调用号:**  程序员通常不会直接使用系统调用号，而是使用 libc 函数。如果 Bionic libc 的实现有误，使用了错误的系统调用号，会导致程序行为异常甚至崩溃。 这类错误非常罕见，因为 Bionic libc 经过严格测试。

2. **libc 函数参数错误导致调用错误的系统调用:** 例如，传递给 `open()` 函数的文件路径不存在或权限不足，会导致 `open()` 函数调用 `__NR_openat` 系统调用并返回错误。

3. **在不支持的 Android 版本上使用了新的系统调用:**  一些新的系统调用可能会在较新的 Android 版本中引入。如果在旧版本的 Android 上尝试使用相关的 libc 函数，可能会导致程序崩溃或功能不正常。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 System Call 的路径 (以打开文件为例):**

1. **Android Framework (Java/Kotlin):**  Android 应用或 Framework 组件通常使用 Java 或 Kotlin 代码与系统交互。例如，要打开一个文件，可能会使用 `java.io.FileInputStream`.

   ```java
   // Java 代码示例
   FileInputStream fis = new FileInputStream("/sdcard/test.txt");
   ```

2. **Android SDK/Runtime Libraries:** `FileInputStream` 内部会调用 Android SDK 或 Runtime Libraries 中相关的 Native 方法 (JNI)。

3. **NDK (Native Development Kit) (可选):** 如果应用使用了 NDK 进行 Native 开发，可以直接调用 Bionic libc 提供的函数。

   ```c++
   // NDK C++ 代码示例
   #include <fcntl.h>
   int fd = open("/sdcard/test.txt", O_RDONLY);
   ```

4. **Bionic libc:**  `FileInputStream` 的 Native 方法或者 NDK 代码最终会调用 Bionic libc 中的 `open()` 或 `openat()` 函数。

5. **`syscall()` 函数:** Bionic libc 的 `openat()` 函数会使用 `syscall(__NR_openat, ...)` 来发起系统调用，其中 `__NR_openat` 的值就定义在这个 `unistd.handroid` 文件中。

6. **Linux Kernel:** Linux 内核接收到系统调用请求，根据系统调用号 `__NR_openat` 执行相应的内核代码，完成打开文件的操作。

**Frida Hook 示例：**

我们可以使用 Frida Hook Bionic libc 的 `openat()` 函数，来观察它使用的系统调用号。

```python
# Frida Python 脚本

import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "openat"), {
    onEnter: function(args) {
        var pathname = Memory.readUtf8String(args[1]);
        var flags = args[2].toInt();
        this.syscall_num = 257; // __NR_openat 的值 (不同架构可能不同，这里假设是 Android)
        send({
            type: "info",
            content: "openat() called",
            pathname: pathname,
            flags: flags,
            syscall_number: this.syscall_num
        });
    },
    onLeave: function(retval) {
        send({
            type: "info",
            content: "openat() returned",
            retval: retval.toInt()
        });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 说明：**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 设备上的目标应用进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "openat"), ...)`:**  Hook Bionic libc 中的 `openat()` 函数。
3. **`onEnter: function(args)`:** 在 `openat()` 函数被调用前执行。
    * `args[0]`: `dirfd` 参数
    * `args[1]`: `pathname` 参数
    * `args[2]`: `flags` 参数
    * `Memory.readUtf8String(args[1])`: 读取 `pathname` 字符串。
    * `send(...)`:  通过 Frida 发送消息到 Python 脚本。
4. **`onLeave: function(retval)`:** 在 `openat()` 函数返回后执行。
    * `retval`: `openat()` 函数的返回值（文件描述符或错误码）。

**运行 Frida 脚本后，当你操作目标应用，触发打开文件的操作时，Frida 会打印出 `openat()` 函数的调用信息，包括文件名、标志位，以及我们假设的系统调用号。**

**总结:**

`bionic/libc/kernel/uapi/asm-generic/unistd.handroid` 是一个至关重要的头文件，它定义了 Android Bionic libc 用来与 Linux 内核交互的系统调用号。它本身不包含任何函数实现，而是作为 Bionic libc 和内核之间的桥梁。 理解它的作用有助于深入了解 Android 系统的底层运作机制。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-generic/unistd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#include <asm/bitsperlong.h>
#ifndef __SYSCALL
#define __SYSCALL(x,y)
#endif
#if __BITS_PER_LONG == 32 || defined(__SYSCALL_COMPAT)
#define __SC_3264(_nr,_32,_64) __SYSCALL(_nr, _32)
#else
#define __SC_3264(_nr,_32,_64) __SYSCALL(_nr, _64)
#endif
#ifdef __SYSCALL_COMPAT
#define __SC_COMP(_nr,_sys,_comp) __SYSCALL(_nr, _comp)
#define __SC_COMP_3264(_nr,_32,_64,_comp) __SYSCALL(_nr, _comp)
#else
#define __SC_COMP(_nr,_sys,_comp) __SYSCALL(_nr, _sys)
#define __SC_COMP_3264(_nr,_32,_64,_comp) __SC_3264(_nr, _32, _64)
#endif
#define __NR_io_setup 0
#define __NR_io_destroy 1
#define __NR_io_submit 2
#define __NR_io_cancel 3
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_io_getevents 4
#endif
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
#define __NR3264_fcntl 25
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
#ifdef __ARCH_WANT_RENAMEAT
#define __NR_renameat 38
#endif
#define __NR_umount2 39
#define __NR_mount 40
#define __NR_pivot_root 41
#define __NR_nfsservctl 42
#define __NR3264_statfs 43
#define __NR3264_fstatfs 44
#define __NR3264_truncate 45
#define __NR3264_ftruncate 46
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
#define __NR3264_lseek 62
#define __NR_read 63
#define __NR_write 64
#define __NR_readv 65
#define __NR_writev 66
#define __NR_pread64 67
#define __NR_pwrite64 68
#define __NR_preadv 69
#define __NR_pwritev 70
#define __NR3264_sendfile 71
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_pselect6 72
#define __NR_ppoll 73
#endif
#define __NR_signalfd4 74
#define __NR_vmsplice 75
#define __NR_splice 76
#define __NR_tee 77
#define __NR_readlinkat 78
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
#define __NR3264_fstatat 79
#define __NR3264_fstat 80
#endif
#define __NR_sync 81
#define __NR_fsync 82
#define __NR_fdatasync 83
#ifdef __ARCH_WANT_SYNC_FILE_RANGE2
#define __NR_sync_file_range2 84
#else
#define __NR_sync_file_range 84
#endif
#define __NR_timerfd_create 85
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_timerfd_settime 86
#define __NR_timerfd_gettime 87
#endif
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_utimensat 88
#endif
#define __NR_acct 89
#define __NR_capget 90
#define __NR_capset 91
#define __NR_personality 92
#define __NR_exit 93
#define __NR_exit_group 94
#define __NR_waitid 95
#define __NR_set_tid_address 96
#define __NR_unshare 97
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_futex 98
#endif
#define __NR_set_robust_list 99
#define __NR_get_robust_list 100
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_nanosleep 101
#endif
#define __NR_getitimer 102
#define __NR_setitimer 103
#define __NR_kexec_load 104
#define __NR_init_module 105
#define __NR_delete_module 106
#define __NR_timer_create 107
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_timer_gettime 108
#endif
#define __NR_timer_getoverrun 109
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_timer_settime 110
#endif
#define __NR_timer_delete 111
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_clock_settime 112
#define __NR_clock_gettime 113
#define __NR_clock_getres 114
#define __NR_clock_nanosleep 115
#endif
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
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_sched_rr_get_interval 127
#endif
#define __NR_restart_syscall 128
#define __NR_kill 129
#define __NR_tkill 130
#define __NR_tgkill 131
#define __NR_sigaltstack 132
#define __NR_rt_sigsuspend 133
#define __NR_rt_sigaction 134
#define __NR_rt_sigprocmask 135
#define __NR_rt_sigpending 136
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_rt_sigtimedwait 137
#endif
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
#ifdef __ARCH_WANT_SET_GET_RLIMIT
#define __NR_getrlimit 163
#define __NR_setrlimit 164
#endif
#define __NR_getrusage 165
#define __NR_umask 166
#define __NR_prctl 167
#define __NR_getcpu 168
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_gettimeofday 169
#define __NR_settimeofday 170
#define __NR_adjtimex 171
#endif
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
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_mq_timedsend 182
#define __NR_mq_timedreceive 183
#endif
#define __NR_mq_notify 184
#define __NR_mq_getsetattr 185
#define __NR_msgget 186
#define __NR_msgctl 187
#define __NR_msgrcv 188
#define __NR_msgsnd 189
#define __NR_semget 190
#define __NR_semctl 191
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_semtimedop 192
#endif
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
#define __NR3264_mmap 222
#define __NR3264_fadvise64 223
#ifndef __ARCH_NOMMU
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
#endif
#define __NR_rt_tgsigqueueinfo 240
#define __NR_perf_event_open 241
#define __NR_accept4 242
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_recvmmsg 243
#endif
#define __NR_arch_specific_syscall 244
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_wait4 260
#endif
#define __NR_prlimit64 261
#define __NR_fanotify_init 262
#define __NR_fanotify_mark 263
#define __NR_name_to_handle_at 264
#define __NR_open_by_handle_at 265
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_clock_adjtime 266
#endif
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
#if defined(__ARCH_WANT_TIME32_SYSCALLS) || __BITS_PER_LONG != 32
#define __NR_io_pgetevents 292
#endif
#define __NR_rseq 293
#define __NR_kexec_file_load 294
#if defined(__SYSCALL_COMPAT) || __BITS_PER_LONG == 32
#define __NR_clock_gettime64 403
#define __NR_clock_settime64 404
#define __NR_clock_adjtime64 405
#define __NR_clock_getres_time64 406
#define __NR_clock_nanosleep_time64 407
#define __NR_timer_gettime64 408
#define __NR_timer_settime64 409
#define __NR_timerfd_gettime64 410
#define __NR_timerfd_settime64 411
#define __NR_utimensat_time64 412
#define __NR_pselect6_time64 413
#define __NR_ppoll_time64 414
#define __NR_io_pgetevents_time64 416
#define __NR_recvmmsg_time64 417
#define __NR_mq_timedsend_time64 418
#define __NR_mq_timedreceive_time64 419
#define __NR_semtimedop_time64 420
#define __NR_rt_sigtimedwait_time64 421
#define __NR_futex_time64 422
#define __NR_sched_rr_get_interval_time64 423
#endif
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
#ifdef __ARCH_WANT_MEMFD_SECRET
#define __NR_memfd_secret 447
#endif
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
#undef __NR_syscalls
#define __NR_syscalls 463
#if __BITS_PER_LONG == 64 && !defined(__SYSCALL_COMPAT)
#define __NR_fcntl __NR3264_fcntl
#define __NR_statfs __NR3264_statfs
#define __NR_fstatfs __NR3264_fstatfs
#define __NR_truncate __NR3264_truncate
#define __NR_ftruncate __NR3264_ftruncate
#define __NR_lseek __NR3264_lseek
#define __NR_sendfile __NR3264_sendfile
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
#define __NR_newfstatat __NR3264_fstatat
#define __NR_fstat __NR3264_fstat
#endif
#define __NR_mmap __NR3264_mmap
#define __NR_fadvise64 __NR3264_fadvise64
#ifdef __NR3264_stat
#define __NR_stat __NR3264_stat
#define __NR_lstat __NR3264_lstat
#endif
#else
#define __NR_fcntl64 __NR3264_fcntl
#define __NR_statfs64 __NR3264_statfs
#define __NR_fstatfs64 __NR3264_fstatfs
#define __NR_truncate64 __NR3264_truncate
#define __NR_ftruncate64 __NR3264_ftruncate
#define __NR_llseek __NR3264_lseek
#define __NR_sendfile64 __NR3264_sendfile
#if defined(__ARCH_WANT_NEW_STAT) || defined(__ARCH_WANT_STAT64)
#define __NR_fstatat64 __NR3264_fstatat
#define __NR_fstat64 __NR3264_fstat
#endif
#define __NR_mmap2 __NR3264_mmap
#define __NR_fadvise64_64 __NR3264_fadvise64
#ifdef __NR3264_stat
#define __NR_stat64 __NR3264_stat
#define __NR_lstat64 __NR3264_lstat
#endif
#endif
```