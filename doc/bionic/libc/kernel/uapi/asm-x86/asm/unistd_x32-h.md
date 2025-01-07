Response:
Let's break down the thought process to generate the comprehensive answer about `unistd_x32.h`.

**1. Understanding the Core Question:**

The central point is to analyze the provided C header file, `unistd_x32.h`, within the context of Android's bionic library. The file clearly defines system call numbers for the x86 32-bit architecture. The request asks for functionalities, relationships to Android, implementation details (especially for libc functions), dynamic linker aspects, examples, usage errors, and how Android frameworks/NDK reach this level, including a Frida hook example.

**2. Deconstructing the Request into Sub-Tasks:**

To handle the multifaceted request, I mentally broke it down:

* **Identify Functionality:** What does this file *do*?  It's a list of system call numbers.
* **Android Relevance:** How are system calls used in Android?  Through libc wrappers.
* **libc Implementation:**  How do libc functions interact with these system call numbers? (High-level explanation, not diving into kernel code).
* **Dynamic Linker:**  Are there system calls directly related to the dynamic linker?  (Yes, things like `mmap`, `mprotect`). How does the linker use these?
* **Examples:**  Provide concrete code snippets demonstrating the use of these system calls (via libc functions).
* **Common Errors:** What mistakes do programmers often make when using these functions?
* **Android Framework/NDK Path:** How does a high-level Android application end up invoking these low-level system calls?
* **Frida Hook:** Demonstrate how to intercept these calls using Frida.

**3. Addressing Each Sub-Task Systematically:**

* **Functionality:**  The most obvious function is defining system call numbers for the x86 32-bit architecture in Android. This is crucial for the interface between user-space applications and the kernel.

* **Android Relevance:**  This is where the link to libc comes in. The header file itself doesn't implement anything. It's just a definition. Libc provides the wrapper functions that use these numbers to make the actual system calls. Example:  `open()` in libc uses `__NR_open`.

* **libc Implementation:** Focus on the *concept* of a wrapper function. It marshals arguments, triggers the system call (using assembly instructions, though not explicitly detailed in the header), and handles return values and errors. Avoid getting bogged down in the exact assembly, as the header doesn't show that.

* **Dynamic Linker:**  Identify relevant system calls like `mmap`, `mprotect`, `munmap`. Explain how the dynamic linker uses these to load shared libraries into memory and set permissions. Create a simplified SO layout as requested. Describe the linking process (symbol resolution, relocation).

* **Examples:** Choose simple, common system calls like `read`, `write`, `open`. Provide basic C code using the corresponding libc functions.

* **Common Errors:** Think about typical programming mistakes related to file I/O (e.g., forgetting to close files), memory management (e.g., `mmap` issues), and general error handling (ignoring return values).

* **Android Framework/NDK Path:**  Trace the execution flow from a high-level API call (like reading a file) down through Java framework layers, native libraries, and finally libc system call wrappers. Emphasize that the NDK allows direct use of libc functions.

* **Frida Hook:**  Provide a clear and concise Frida script that intercepts a system call (like `open`). Explain the key parts: attaching to the process, finding the symbol, replacing the implementation, and restoring the original. Include example input and output for the hook.

**4. Structuring the Answer:**

Organize the information logically using headings and bullet points. This makes the answer easier to read and understand. Start with the high-level functionality and gradually delve into more specific details.

**5. Language and Tone:**

Use clear and concise Chinese. Explain technical terms without being overly jargon-heavy. Maintain a helpful and informative tone.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Should I go into detail about the assembly instructions for making system calls?  **Correction:** No, the header file doesn't provide that level of detail, and the request focuses on the higher-level concepts. Stick to the role of the header file and how libc uses it.
* **Initial thought:**  Should I list *all* the libc functions corresponding to these system calls? **Correction:**  That would be too exhaustive. Focus on providing representative examples.
* **Initial thought:**  The dynamic linker explanation could be very complex. **Correction:** Keep it focused on the relevant system calls and the core linking process. A full dynamic linker explanation is outside the scope.
* **Frida hook example:** Ensure the Frida script is functional and easy to adapt. Provide clear comments.

By following these steps, breaking the problem down, and making necessary refinements, the comprehensive and informative answer can be generated. The process involves understanding the request, identifying key components, providing relevant details, illustrating with examples, and structuring the information clearly.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/asm-x86/asm/unistd_x32.handroid` 这个头文件。

**功能列举**

这个头文件的主要功能是定义了 **x86 32位架构 (x32 ABI)** 下的 Linux 系统调用号 (syscall numbers)。

* **系统调用号映射:** 它将每个系统调用的名称（例如 `read`, `write`, `open`）与一个唯一的数字常量关联起来，例如 `#define __NR_read (__X32_SYSCALL_BIT + 0)`。
* **ABI 定义:**  这个文件是 Android Bionic libc 的一部分，它定义了在 x32 ABI 下应用程序如何与 Linux 内核进行交互的关键部分。`__X32_SYSCALL_BIT` 是一个用于标识 x32 系统调用的位掩码。

**与 Android 功能的关系及举例说明**

这个文件直接关系到 Android 应用程序与底层 Linux 内核的交互。Android 应用程序（包括 Java 代码和 Native 代码）最终都需要通过系统调用来请求内核执行某些操作，例如：

* **文件操作:**
    * 当 Java 代码使用 `java.io.FileInputStream` 读取文件时，Android Framework 会调用 Native 代码，最终会通过 libc 的 `read()` 函数发起 `__NR_read` 系统调用。
    * 当 Native 代码使用 `open()` 函数打开文件时，会使用 `__NR_open` 系统调用。
* **内存管理:**
    * `malloc()` 函数最终可能会通过 `__NR_brk` 或 `__NR_mmap` 来分配内存。
    * 当使用 `mmap()` 系统调用将文件映射到内存时，会使用 `__NR_mmap`。
* **进程管理:**
    * `fork()` 函数会使用 `__NR_fork` 系统调用创建子进程。
    * `exit()` 函数会使用 `__NR_exit` 系统调用结束进程。
* **网络操作:**
    * 当使用 socket 进行网络通信时，例如 `socket()`, `bind()`, `connect()`, `sendto()`, `recvfrom()` 等函数，会分别对应 `__NR_socket`, `__NR_bind`, `__NR_connect`, `__NR_sendto`, `__NR_recvfrom` 等系统调用。

**libc 函数的功能实现**

libc (Bionic) 中的函数通常是对系统调用的封装。当应用程序调用 libc 函数时，libc 函数会执行以下步骤：

1. **参数准备:** 将应用程序传递的参数按照系统调用要求的格式进行组织和准备。
2. **系统调用触发:**  使用汇编指令（通常是 `syscall` 指令在 x86-64 架构上，对于 x86 32位，可能是 `int 0x80`）触发系统调用，并将系统调用号（例如 `__NR_read`）加载到特定的寄存器中（例如 `EAX` 寄存器在 x86 32位架构上）。
3. **内核处理:** Linux 内核接收到系统调用请求后，根据系统调用号找到对应的内核函数，执行相应的操作。
4. **结果返回:** 内核将操作结果（包括成功或错误代码）返回给用户空间。
5. **错误处理:** libc 函数会检查内核返回的结果。如果发生错误，libc 函数会将错误码设置到全局变量 `errno` 中，并通常返回一个表示错误的值（例如 -1）。

**举例说明 `read()` 函数的实现：**

```c
// (简化的 libc read() 函数实现)
#include <unistd.h>
#include <errno.h>
#include <syscall.h> // Bionic 提供的 syscall 宏

ssize_t read(int fd, void *buf, size_t count) {
  long ret = syscall(__NR_read, fd, buf, count);
  if (ret < 0) {
    errno = -ret; // 内核返回的错误码是负数，需要取反
    return -1;
  }
  return ret;
}
```

* `syscall(__NR_read, fd, buf, count)`:  这个宏会展开成一段汇编代码，将 `__NR_read` 的值加载到系统调用号寄存器，并将 `fd`, `buf`, `count` 作为参数传递给内核。
* 如果系统调用返回的 `ret` 小于 0，表示发生了错误。libc 会将 `-ret` 赋值给 `errno`，并将 `read()` 函数的返回值设置为 -1。

**涉及 dynamic linker 的功能及处理过程**

与 dynamic linker (在 Android 上是 `linker64` 或 `linker`) 相关的系统调用主要集中在内存管理和程序执行方面：

* **`mmap` (`__NR_mmap`):**  dynamic linker 使用 `mmap` 将共享库 (SO 文件) 加载到进程的地址空间。
* **`mprotect` (`__NR_mprotect`):** dynamic linker 使用 `mprotect` 设置加载的共享库内存区域的访问权限（例如，代码段设置为只读和执行）。
* **`munmap` (`__NR_munmap`):**  当卸载共享库或进程结束时，dynamic linker 使用 `munmap` 释放之前通过 `mmap` 分配的内存。
* **`open` (`__NR_open`), `close` (`__NR_close`), `read` (`__NR_read`):** dynamic linker 需要打开、读取共享库文件来加载其内容。
* **`execve` (`__NR_execve`):**  当启动一个新的可执行文件时，内核会调用 `execve`，dynamic linker 会参与到新进程的初始化过程中，加载其依赖的共享库。
* **`brk` (`__NR_brk`):**  虽然 `mmap` 是加载共享库的主要方式，但在某些情况下，dynamic linker 也可能使用 `brk` 来扩展堆空间。

**SO 布局样本和链接处理过程**

假设我们有一个名为 `libfoo.so` 的共享库，它被应用程序 `my_app` 使用。

**`libfoo.so` 的布局样本 (简化)**

```
|-------------------|  基地址（由 dynamic linker 决定）
| .text (代码段)     |  可执行，只读
|-------------------|
| .rodata (只读数据) |  只读
|-------------------|
| .data (已初始化数据) |  可读写
|-------------------|
| .bss (未初始化数据) |  可读写
|-------------------|
| .dynamic (动态链接信息) |  包含符号表、重定位表等信息
|-------------------|
| GOT (全局偏移表)   |  用于间接访问全局变量和函数
|-------------------|
| PLT (过程链接表)   |  用于延迟绑定外部函数
|-------------------|
```

**链接处理过程**

1. **加载:** 当 `my_app` 启动时，内核会加载 `my_app` 的代码段和数据段。`my_app` 的头部信息会指示需要加载 `libfoo.so`。
2. **定位:** dynamic linker (在 `/system/bin/linker64` 或 `/system/bin/linker` ) 会根据预加载列表或 `my_app` 的依赖信息找到 `libfoo.so` 文件。
3. **映射:** dynamic linker 使用 `mmap` 系统调用将 `libfoo.so` 的各个段加载到 `my_app` 的进程地址空间中。
4. **重定位:**
   * dynamic linker 会解析 `libfoo.so` 的 `.dynamic` 段，读取符号表和重定位表。
   * **符号解析:**  查找 `my_app` 中引用但在 `libfoo.so` 中定义的符号，以及 `libfoo.so` 中引用但在其他库或 `my_app` 中定义的符号。
   * **重定位应用:**  修改 `libfoo.so` 的 GOT 和 PLT 表项，使其指向正确的地址。
     * **GOT (全局偏移表):** 用于访问全局变量。dynamic linker 会将全局变量的实际地址写入 GOT 表项。
     * **PLT (过程链接表):** 用于延迟绑定外部函数。最初，PLT 表项会跳转到 dynamic linker 的解析例程。当第一次调用外部函数时，dynamic linker 会解析该函数的地址并更新 PLT 表项，后续调用将直接跳转到目标函数。
5. **依赖处理:** 如果 `libfoo.so` 还有其他依赖的共享库，dynamic linker 会递归地加载和链接这些库。

**假设输入与输出 (逻辑推理)**

假设我们调用了 `open("/sdcard/test.txt", O_RDONLY)` 这个函数。

* **假设输入:**
    * `pathname`: 指向字符串 "/sdcard/test.txt" 的指针。
    * `flags`: `O_RDONLY` 的值 (通常是 0)。
    * （对于 `open` 系统调用，还有 `mode` 参数，这里假设是默认值）
* **输出:**
    * **成功:** 返回一个非负的文件描述符 (例如 3)。
    * **失败:** 返回 -1，并且全局变量 `errno` 会被设置为相应的错误码，例如 `ENOENT` (文件不存在) 或 `EACCES` (权限不足)。

**用户或编程常见的使用错误**

* **忘记检查返回值:** 系统调用（以及 libc 函数）通常会返回表示成功或失败的值。忽略返回值可能导致程序在出现错误时继续执行，产生不可预测的行为。
    ```c
    // 错误示例
    open("myfile.txt", O_RDWR); // 没有检查返回值

    // 正确示例
    int fd = open("myfile.txt", O_RDWR);
    if (fd == -1) {
        perror("open"); // 打印错误信息
        // 处理错误
    } else {
        // 使用文件描述符
        close(fd);
    }
    ```
* **文件描述符泄露:**  打开文件或 socket 后，忘记调用 `close()` 关闭，会导致文件描述符资源耗尽。
* **`mmap` 使用错误:**
    *  `mmap` 的长度不正确。
    *  尝试写入以只读方式映射的内存区域。
    *  进程退出时未 `munmap` 释放映射的内存。
* **权限错误:**  尝试访问没有足够权限的文件或目录。
* **并发问题:**  在多线程或多进程环境下，不正确地使用共享资源（例如文件）可能导致数据竞争和不一致。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 代码):**
   * 例如，`FileInputStream` 的 `read()` 方法最终会调用 Native 方法。
   * 这些 Native 方法通常位于 Android Framework 的 Native 组件中 (例如 `libandroid_runtime.so`).

2. **NDK (Native 代码):**
   * NDK 开发者可以使用标准 C/C++ 库函数，例如 `open()`, `read()`, `write()`, `malloc()`, 等。
   * 这些 NDK 代码直接链接到 Bionic libc。

3. **Bionic libc:**
   * NDK 代码或 Framework 的 Native 组件调用的 libc 函数（例如 `open()`）会根据系统调用号（在 `unistd_x32.h` 中定义）构建系统调用。

4. **系统调用:**
   * libc 函数使用汇编指令触发系统调用，将控制权转移到 Linux 内核。

**Frida Hook 示例调试**

假设我们要 hook `open` 系统调用，查看应用程序尝试打开的文件路径。

```python
import frida
import sys

package_name = "com.example.myapp" # 替换成你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device()
    pid = device.spawn([package_name])
    session = device.attach(pid)
    device.resume(pid)
except frida.ServerNotStartedError:
    print("请确保 Frida 服务已在设备上运行。")
    sys.exit(1)
except frida.ProcessNotFoundError:
    print(f"找不到进程: {package_name}。请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "syscall"), {
    onEnter: function(args) {
        var syscall_number = this.context.eax; // x86 32位架构，系统调用号在 EAX 寄存器
        if (syscall_number == 5) { // __NR_open 的值 (需要根据你的系统确定)
            var filename = Memory.readUtf8String(ptr(this.context.ebx)); // 文件名参数通常在 EBX 寄存器
            console.log("[Frida Hook] 打开文件: " + filename);
        }
    },
    onLeave: function(retval) {
        // console.log("syscall returned with: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 步骤说明:**

1. **导入 Frida 库:** 导入 `frida` 和 `sys` 库。
2. **指定包名:** 设置要 hook 的 Android 应用的包名。
3. **连接设备和附加进程:** 使用 Frida 连接到 USB 设备，启动目标应用并附加到其进程。
4. **Frida Script:**
   * **`Interceptor.attach`:**  hook `syscall` 函数，这是所有系统调用的入口点。
   * **`onEnter`:** 在 `syscall` 函数被调用前执行。
     * `this.context.eax`: 获取 `EAX` 寄存器的值，即系统调用号。
     * `if (syscall_number == 5)`:  检查是否是 `open` 系统调用 (`__NR_open` 的值需要根据你的具体 Android 版本和架构确定，这里假设是 5)。
     * `Memory.readUtf8String(ptr(this.context.ebx))`: 读取 `EBX` 寄存器指向的内存地址中的 UTF-8 字符串，这通常是 `open` 系统调用的 `pathname` 参数。
     * `console.log(...)`: 打印 hook 到的信息。
   * **`onLeave`:** 在 `syscall` 函数返回后执行（这里被注释掉了）。
5. **加载脚本和保持运行:** 创建 Frida 脚本，设置消息回调，加载脚本，并保持脚本运行直到用户手动停止。

**运行 Frida 脚本:**

1. 确保你的 Android 设备已连接并通过 adb 可访问，并且 Frida 服务正在设备上运行。
2. 将上面的 Python 代码保存为 `.py` 文件（例如 `hook_open.py`）。
3. 替换 `package_name` 为你要 hook 的应用的包名。
4. 运行脚本： `python hook_open.py`
5. 启动目标应用，当应用尝试打开文件时，Frida 会拦截到 `open` 系统调用并打印出打开的文件路径。

**注意:**

* 系统调用号可能因 Android 版本和架构而异。你需要根据你的目标环境查找正确的 `__NR_open` 值。你可以在设备的 `/usr/include/asm/unistd_32.h` 或类似路径中找到。
* Frida 需要 root 权限或在可调试的应用程序上运行。

希望这个详细的分析能够帮助你理解 `unistd_x32.handroid` 文件以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-x86/asm/unistd_x32.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_ASM_UNISTD_X32_H
#define _UAPI_ASM_UNISTD_X32_H
#define __NR_read (__X32_SYSCALL_BIT + 0)
#define __NR_write (__X32_SYSCALL_BIT + 1)
#define __NR_open (__X32_SYSCALL_BIT + 2)
#define __NR_close (__X32_SYSCALL_BIT + 3)
#define __NR_stat (__X32_SYSCALL_BIT + 4)
#define __NR_fstat (__X32_SYSCALL_BIT + 5)
#define __NR_lstat (__X32_SYSCALL_BIT + 6)
#define __NR_poll (__X32_SYSCALL_BIT + 7)
#define __NR_lseek (__X32_SYSCALL_BIT + 8)
#define __NR_mmap (__X32_SYSCALL_BIT + 9)
#define __NR_mprotect (__X32_SYSCALL_BIT + 10)
#define __NR_munmap (__X32_SYSCALL_BIT + 11)
#define __NR_brk (__X32_SYSCALL_BIT + 12)
#define __NR_rt_sigprocmask (__X32_SYSCALL_BIT + 14)
#define __NR_pread64 (__X32_SYSCALL_BIT + 17)
#define __NR_pwrite64 (__X32_SYSCALL_BIT + 18)
#define __NR_access (__X32_SYSCALL_BIT + 21)
#define __NR_pipe (__X32_SYSCALL_BIT + 22)
#define __NR_select (__X32_SYSCALL_BIT + 23)
#define __NR_sched_yield (__X32_SYSCALL_BIT + 24)
#define __NR_mremap (__X32_SYSCALL_BIT + 25)
#define __NR_msync (__X32_SYSCALL_BIT + 26)
#define __NR_mincore (__X32_SYSCALL_BIT + 27)
#define __NR_madvise (__X32_SYSCALL_BIT + 28)
#define __NR_shmget (__X32_SYSCALL_BIT + 29)
#define __NR_shmat (__X32_SYSCALL_BIT + 30)
#define __NR_shmctl (__X32_SYSCALL_BIT + 31)
#define __NR_dup (__X32_SYSCALL_BIT + 32)
#define __NR_dup2 (__X32_SYSCALL_BIT + 33)
#define __NR_pause (__X32_SYSCALL_BIT + 34)
#define __NR_nanosleep (__X32_SYSCALL_BIT + 35)
#define __NR_getitimer (__X32_SYSCALL_BIT + 36)
#define __NR_alarm (__X32_SYSCALL_BIT + 37)
#define __NR_setitimer (__X32_SYSCALL_BIT + 38)
#define __NR_getpid (__X32_SYSCALL_BIT + 39)
#define __NR_sendfile (__X32_SYSCALL_BIT + 40)
#define __NR_socket (__X32_SYSCALL_BIT + 41)
#define __NR_connect (__X32_SYSCALL_BIT + 42)
#define __NR_accept (__X32_SYSCALL_BIT + 43)
#define __NR_sendto (__X32_SYSCALL_BIT + 44)
#define __NR_shutdown (__X32_SYSCALL_BIT + 48)
#define __NR_bind (__X32_SYSCALL_BIT + 49)
#define __NR_listen (__X32_SYSCALL_BIT + 50)
#define __NR_getsockname (__X32_SYSCALL_BIT + 51)
#define __NR_getpeername (__X32_SYSCALL_BIT + 52)
#define __NR_socketpair (__X32_SYSCALL_BIT + 53)
#define __NR_clone (__X32_SYSCALL_BIT + 56)
#define __NR_fork (__X32_SYSCALL_BIT + 57)
#define __NR_vfork (__X32_SYSCALL_BIT + 58)
#define __NR_exit (__X32_SYSCALL_BIT + 60)
#define __NR_wait4 (__X32_SYSCALL_BIT + 61)
#define __NR_kill (__X32_SYSCALL_BIT + 62)
#define __NR_uname (__X32_SYSCALL_BIT + 63)
#define __NR_semget (__X32_SYSCALL_BIT + 64)
#define __NR_semop (__X32_SYSCALL_BIT + 65)
#define __NR_semctl (__X32_SYSCALL_BIT + 66)
#define __NR_shmdt (__X32_SYSCALL_BIT + 67)
#define __NR_msgget (__X32_SYSCALL_BIT + 68)
#define __NR_msgsnd (__X32_SYSCALL_BIT + 69)
#define __NR_msgrcv (__X32_SYSCALL_BIT + 70)
#define __NR_msgctl (__X32_SYSCALL_BIT + 71)
#define __NR_fcntl (__X32_SYSCALL_BIT + 72)
#define __NR_flock (__X32_SYSCALL_BIT + 73)
#define __NR_fsync (__X32_SYSCALL_BIT + 74)
#define __NR_fdatasync (__X32_SYSCALL_BIT + 75)
#define __NR_truncate (__X32_SYSCALL_BIT + 76)
#define __NR_ftruncate (__X32_SYSCALL_BIT + 77)
#define __NR_getdents (__X32_SYSCALL_BIT + 78)
#define __NR_getcwd (__X32_SYSCALL_BIT + 79)
#define __NR_chdir (__X32_SYSCALL_BIT + 80)
#define __NR_fchdir (__X32_SYSCALL_BIT + 81)
#define __NR_rename (__X32_SYSCALL_BIT + 82)
#define __NR_mkdir (__X32_SYSCALL_BIT + 83)
#define __NR_rmdir (__X32_SYSCALL_BIT + 84)
#define __NR_creat (__X32_SYSCALL_BIT + 85)
#define __NR_link (__X32_SYSCALL_BIT + 86)
#define __NR_unlink (__X32_SYSCALL_BIT + 87)
#define __NR_symlink (__X32_SYSCALL_BIT + 88)
#define __NR_readlink (__X32_SYSCALL_BIT + 89)
#define __NR_chmod (__X32_SYSCALL_BIT + 90)
#define __NR_fchmod (__X32_SYSCALL_BIT + 91)
#define __NR_chown (__X32_SYSCALL_BIT + 92)
#define __NR_fchown (__X32_SYSCALL_BIT + 93)
#define __NR_lchown (__X32_SYSCALL_BIT + 94)
#define __NR_umask (__X32_SYSCALL_BIT + 95)
#define __NR_gettimeofday (__X32_SYSCALL_BIT + 96)
#define __NR_getrlimit (__X32_SYSCALL_BIT + 97)
#define __NR_getrusage (__X32_SYSCALL_BIT + 98)
#define __NR_sysinfo (__X32_SYSCALL_BIT + 99)
#define __NR_times (__X32_SYSCALL_BIT + 100)
#define __NR_getuid (__X32_SYSCALL_BIT + 102)
#define __NR_syslog (__X32_SYSCALL_BIT + 103)
#define __NR_getgid (__X32_SYSCALL_BIT + 104)
#define __NR_setuid (__X32_SYSCALL_BIT + 105)
#define __NR_setgid (__X32_SYSCALL_BIT + 106)
#define __NR_geteuid (__X32_SYSCALL_BIT + 107)
#define __NR_getegid (__X32_SYSCALL_BIT + 108)
#define __NR_setpgid (__X32_SYSCALL_BIT + 109)
#define __NR_getppid (__X32_SYSCALL_BIT + 110)
#define __NR_getpgrp (__X32_SYSCALL_BIT + 111)
#define __NR_setsid (__X32_SYSCALL_BIT + 112)
#define __NR_setreuid (__X32_SYSCALL_BIT + 113)
#define __NR_setregid (__X32_SYSCALL_BIT + 114)
#define __NR_getgroups (__X32_SYSCALL_BIT + 115)
#define __NR_setgroups (__X32_SYSCALL_BIT + 116)
#define __NR_setresuid (__X32_SYSCALL_BIT + 117)
#define __NR_getresuid (__X32_SYSCALL_BIT + 118)
#define __NR_setresgid (__X32_SYSCALL_BIT + 119)
#define __NR_getresgid (__X32_SYSCALL_BIT + 120)
#define __NR_getpgid (__X32_SYSCALL_BIT + 121)
#define __NR_setfsuid (__X32_SYSCALL_BIT + 122)
#define __NR_setfsgid (__X32_SYSCALL_BIT + 123)
#define __NR_getsid (__X32_SYSCALL_BIT + 124)
#define __NR_capget (__X32_SYSCALL_BIT + 125)
#define __NR_capset (__X32_SYSCALL_BIT + 126)
#define __NR_rt_sigsuspend (__X32_SYSCALL_BIT + 130)
#define __NR_utime (__X32_SYSCALL_BIT + 132)
#define __NR_mknod (__X32_SYSCALL_BIT + 133)
#define __NR_personality (__X32_SYSCALL_BIT + 135)
#define __NR_ustat (__X32_SYSCALL_BIT + 136)
#define __NR_statfs (__X32_SYSCALL_BIT + 137)
#define __NR_fstatfs (__X32_SYSCALL_BIT + 138)
#define __NR_sysfs (__X32_SYSCALL_BIT + 139)
#define __NR_getpriority (__X32_SYSCALL_BIT + 140)
#define __NR_setpriority (__X32_SYSCALL_BIT + 141)
#define __NR_sched_setparam (__X32_SYSCALL_BIT + 142)
#define __NR_sched_getparam (__X32_SYSCALL_BIT + 143)
#define __NR_sched_setscheduler (__X32_SYSCALL_BIT + 144)
#define __NR_sched_getscheduler (__X32_SYSCALL_BIT + 145)
#define __NR_sched_get_priority_max (__X32_SYSCALL_BIT + 146)
#define __NR_sched_get_priority_min (__X32_SYSCALL_BIT + 147)
#define __NR_sched_rr_get_interval (__X32_SYSCALL_BIT + 148)
#define __NR_mlock (__X32_SYSCALL_BIT + 149)
#define __NR_munlock (__X32_SYSCALL_BIT + 150)
#define __NR_mlockall (__X32_SYSCALL_BIT + 151)
#define __NR_munlockall (__X32_SYSCALL_BIT + 152)
#define __NR_vhangup (__X32_SYSCALL_BIT + 153)
#define __NR_modify_ldt (__X32_SYSCALL_BIT + 154)
#define __NR_pivot_root (__X32_SYSCALL_BIT + 155)
#define __NR_prctl (__X32_SYSCALL_BIT + 157)
#define __NR_arch_prctl (__X32_SYSCALL_BIT + 158)
#define __NR_adjtimex (__X32_SYSCALL_BIT + 159)
#define __NR_setrlimit (__X32_SYSCALL_BIT + 160)
#define __NR_chroot (__X32_SYSCALL_BIT + 161)
#define __NR_sync (__X32_SYSCALL_BIT + 162)
#define __NR_acct (__X32_SYSCALL_BIT + 163)
#define __NR_settimeofday (__X32_SYSCALL_BIT + 164)
#define __NR_mount (__X32_SYSCALL_BIT + 165)
#define __NR_umount2 (__X32_SYSCALL_BIT + 166)
#define __NR_swapon (__X32_SYSCALL_BIT + 167)
#define __NR_swapoff (__X32_SYSCALL_BIT + 168)
#define __NR_reboot (__X32_SYSCALL_BIT + 169)
#define __NR_sethostname (__X32_SYSCALL_BIT + 170)
#define __NR_setdomainname (__X32_SYSCALL_BIT + 171)
#define __NR_iopl (__X32_SYSCALL_BIT + 172)
#define __NR_ioperm (__X32_SYSCALL_BIT + 173)
#define __NR_init_module (__X32_SYSCALL_BIT + 175)
#define __NR_delete_module (__X32_SYSCALL_BIT + 176)
#define __NR_quotactl (__X32_SYSCALL_BIT + 179)
#define __NR_getpmsg (__X32_SYSCALL_BIT + 181)
#define __NR_putpmsg (__X32_SYSCALL_BIT + 182)
#define __NR_afs_syscall (__X32_SYSCALL_BIT + 183)
#define __NR_tuxcall (__X32_SYSCALL_BIT + 184)
#define __NR_security (__X32_SYSCALL_BIT + 185)
#define __NR_gettid (__X32_SYSCALL_BIT + 186)
#define __NR_readahead (__X32_SYSCALL_BIT + 187)
#define __NR_setxattr (__X32_SYSCALL_BIT + 188)
#define __NR_lsetxattr (__X32_SYSCALL_BIT + 189)
#define __NR_fsetxattr (__X32_SYSCALL_BIT + 190)
#define __NR_getxattr (__X32_SYSCALL_BIT + 191)
#define __NR_lgetxattr (__X32_SYSCALL_BIT + 192)
#define __NR_fgetxattr (__X32_SYSCALL_BIT + 193)
#define __NR_listxattr (__X32_SYSCALL_BIT + 194)
#define __NR_llistxattr (__X32_SYSCALL_BIT + 195)
#define __NR_flistxattr (__X32_SYSCALL_BIT + 196)
#define __NR_removexattr (__X32_SYSCALL_BIT + 197)
#define __NR_lremovexattr (__X32_SYSCALL_BIT + 198)
#define __NR_fremovexattr (__X32_SYSCALL_BIT + 199)
#define __NR_tkill (__X32_SYSCALL_BIT + 200)
#define __NR_time (__X32_SYSCALL_BIT + 201)
#define __NR_futex (__X32_SYSCALL_BIT + 202)
#define __NR_sched_setaffinity (__X32_SYSCALL_BIT + 203)
#define __NR_sched_getaffinity (__X32_SYSCALL_BIT + 204)
#define __NR_io_destroy (__X32_SYSCALL_BIT + 207)
#define __NR_io_getevents (__X32_SYSCALL_BIT + 208)
#define __NR_io_cancel (__X32_SYSCALL_BIT + 210)
#define __NR_lookup_dcookie (__X32_SYSCALL_BIT + 212)
#define __NR_epoll_create (__X32_SYSCALL_BIT + 213)
#define __NR_remap_file_pages (__X32_SYSCALL_BIT + 216)
#define __NR_getdents64 (__X32_SYSCALL_BIT + 217)
#define __NR_set_tid_address (__X32_SYSCALL_BIT + 218)
#define __NR_restart_syscall (__X32_SYSCALL_BIT + 219)
#define __NR_semtimedop (__X32_SYSCALL_BIT + 220)
#define __NR_fadvise64 (__X32_SYSCALL_BIT + 221)
#define __NR_timer_settime (__X32_SYSCALL_BIT + 223)
#define __NR_timer_gettime (__X32_SYSCALL_BIT + 224)
#define __NR_timer_getoverrun (__X32_SYSCALL_BIT + 225)
#define __NR_timer_delete (__X32_SYSCALL_BIT + 226)
#define __NR_clock_settime (__X32_SYSCALL_BIT + 227)
#define __NR_clock_gettime (__X32_SYSCALL_BIT + 228)
#define __NR_clock_getres (__X32_SYSCALL_BIT + 229)
#define __NR_clock_nanosleep (__X32_SYSCALL_BIT + 230)
#define __NR_exit_group (__X32_SYSCALL_BIT + 231)
#define __NR_epoll_wait (__X32_SYSCALL_BIT + 232)
#define __NR_epoll_ctl (__X32_SYSCALL_BIT + 233)
#define __NR_tgkill (__X32_SYSCALL_BIT + 234)
#define __NR_utimes (__X32_SYSCALL_BIT + 235)
#define __NR_mbind (__X32_SYSCALL_BIT + 237)
#define __NR_set_mempolicy (__X32_SYSCALL_BIT + 238)
#define __NR_get_mempolicy (__X32_SYSCALL_BIT + 239)
#define __NR_mq_open (__X32_SYSCALL_BIT + 240)
#define __NR_mq_unlink (__X32_SYSCALL_BIT + 241)
#define __NR_mq_timedsend (__X32_SYSCALL_BIT + 242)
#define __NR_mq_timedreceive (__X32_SYSCALL_BIT + 243)
#define __NR_mq_getsetattr (__X32_SYSCALL_BIT + 245)
#define __NR_add_key (__X32_SYSCALL_BIT + 248)
#define __NR_request_key (__X32_SYSCALL_BIT + 249)
#define __NR_keyctl (__X32_SYSCALL_BIT + 250)
#define __NR_ioprio_set (__X32_SYSCALL_BIT + 251)
#define __NR_ioprio_get (__X32_SYSCALL_BIT + 252)
#define __NR_inotify_init (__X32_SYSCALL_BIT + 253)
#define __NR_inotify_add_watch (__X32_SYSCALL_BIT + 254)
#define __NR_inotify_rm_watch (__X32_SYSCALL_BIT + 255)
#define __NR_migrate_pages (__X32_SYSCALL_BIT + 256)
#define __NR_openat (__X32_SYSCALL_BIT + 257)
#define __NR_mkdirat (__X32_SYSCALL_BIT + 258)
#define __NR_mknodat (__X32_SYSCALL_BIT + 259)
#define __NR_fchownat (__X32_SYSCALL_BIT + 260)
#define __NR_futimesat (__X32_SYSCALL_BIT + 261)
#define __NR_newfstatat (__X32_SYSCALL_BIT + 262)
#define __NR_unlinkat (__X32_SYSCALL_BIT + 263)
#define __NR_renameat (__X32_SYSCALL_BIT + 264)
#define __NR_linkat (__X32_SYSCALL_BIT + 265)
#define __NR_symlinkat (__X32_SYSCALL_BIT + 266)
#define __NR_readlinkat (__X32_SYSCALL_BIT + 267)
#define __NR_fchmodat (__X32_SYSCALL_BIT + 268)
#define __NR_faccessat (__X32_SYSCALL_BIT + 269)
#define __NR_pselect6 (__X32_SYSCALL_BIT + 270)
#define __NR_ppoll (__X32_SYSCALL_BIT + 271)
#define __NR_unshare (__X32_SYSCALL_BIT + 272)
#define __NR_splice (__X32_SYSCALL_BIT + 275)
#define __NR_tee (__X32_SYSCALL_BIT + 276)
#define __NR_sync_file_range (__X32_SYSCALL_BIT + 277)
#define __NR_utimensat (__X32_SYSCALL_BIT + 280)
#define __NR_epoll_pwait (__X32_SYSCALL_BIT + 281)
#define __NR_signalfd (__X32_SYSCALL_BIT + 282)
#define __NR_timerfd_create (__X32_SYSCALL_BIT + 283)
#define __NR_eventfd (__X32_SYSCALL_BIT + 284)
#define __NR_fallocate (__X32_SYSCALL_BIT + 285)
#define __NR_timerfd_settime (__X32_SYSCALL_BIT + 286)
#define __NR_timerfd_gettime (__X32_SYSCALL_BIT + 287)
#define __NR_accept4 (__X32_SYSCALL_BIT + 288)
#define __NR_signalfd4 (__X32_SYSCALL_BIT + 289)
#define __NR_eventfd2 (__X32_SYSCALL_BIT + 290)
#define __NR_epoll_create1 (__X32_SYSCALL_BIT + 291)
#define __NR_dup3 (__X32_SYSCALL_BIT + 292)
#define __NR_pipe2 (__X32_SYSCALL_BIT + 293)
#define __NR_inotify_init1 (__X32_SYSCALL_BIT + 294)
#define __NR_perf_event_open (__X32_SYSCALL_BIT + 298)
#define __NR_fanotify_init (__X32_SYSCALL_BIT + 300)
#define __NR_fanotify_mark (__X32_SYSCALL_BIT + 301)
#define __NR_prlimit64 (__X32_SYSCALL_BIT + 302)
#define __NR_name_to_handle_at (__X32_SYSCALL_BIT + 303)
#define __NR_open_by_handle_at (__X32_SYSCALL_BIT + 304)
#define __NR_clock_adjtime (__X32_SYSCALL_BIT + 305)
#define __NR_syncfs (__X32_SYSCALL_BIT + 306)
#define __NR_setns (__X32_SYSCALL_BIT + 308)
#define __NR_getcpu (__X32_SYSCALL_BIT + 309)
#define __NR_kcmp (__X32_SYSCALL_BIT + 312)
#define __NR_finit_module (__X32_SYSCALL_BIT + 313)
#define __NR_sched_setattr (__X32_SYSCALL_BIT + 314)
#define __NR_sched_getattr (__X32_SYSCALL_BIT + 315)
#define __NR_renameat2 (__X32_SYSCALL_BIT + 316)
#define __NR_seccomp (__X32_SYSCALL_BIT + 317)
#define __NR_getrandom (__X32_SYSCALL_BIT + 318)
#define __NR_memfd_create (__X32_SYSCALL_BIT + 319)
#define __NR_kexec_file_load (__X32_SYSCALL_BIT + 320)
#define __NR_bpf (__X32_SYSCALL_BIT + 321)
#define __NR_userfaultfd (__X32_SYSCALL_BIT + 323)
#define __NR_membarrier (__X32_SYSCALL_BIT + 324)
#define __NR_mlock2 (__X32_SYSCALL_BIT + 325)
#define __NR_copy_file_range (__X32_SYSCALL_BIT + 326)
#define __NR_pkey_mprotect (__X32_SYSCALL_BIT + 329)
#define __NR_pkey_alloc (__X32_SYSCALL_BIT + 330)
#define __NR_pkey_free (__X32_SYSCALL_BIT + 331)
#define __NR_statx (__X32_SYSCALL_BIT + 332)
#define __NR_io_pgetevents (__X32_SYSCALL_BIT + 333)
#define __NR_rseq (__X32_SYSCALL_BIT + 334)
#define __NR_uretprobe (__X32_SYSCALL_BIT + 335)
#define __NR_pidfd_send_signal (__X32_SYSCALL_BIT + 424)
#define __NR_io_uring_setup (__X32_SYSCALL_BIT + 425)
#define __NR_io_uring_enter (__X32_SYSCALL_BIT + 426)
#define __NR_io_uring_register (__X32_SYSCALL_BIT + 427)
#define __NR_open_tree (__X32_SYSCALL_BIT + 428)
#define __NR_move_mount (__X32_SYSCALL_BIT + 429)
#define __NR_fsopen (__X32_SYSCALL_BIT + 430)
#define __NR_fsconfig (__X32_SYSCALL_BIT + 431)
#define __NR_fsmount (__X32_SYSCALL_BIT + 432)
#define __NR_fspick (__X32_SYSCALL_BIT + 433)
#define __NR_pidfd_open (__X32_SYSCALL_BIT + 434)
#define __NR_clone3 (__X32_SYSCALL_BIT + 435)
#define __NR_close_range (__X32_SYSCALL_BIT + 436)
#define __NR_openat2 (__X32_SYSCALL_BIT + 437)
#define __NR_pidfd_getfd (__X32_SYSCALL_BIT + 438)
#define __NR_faccessat2 (__X32_SYSCALL_BIT + 439)
#define __NR_process_madvise (__X32_SYSCALL_BIT + 440)
#define __NR_epoll_pwait2 (__X32_SYSCALL_BIT + 441)
#define __NR_mount_setattr (__X32_SYSCALL_BIT + 442)
#define __NR_quotactl_fd (__X32_SYSCALL_BIT + 443)
#define __NR_landlock_create_ruleset (__X32_SYSCALL_BIT + 444)
#define __NR_landlock_add_rule (__X32_SYSCALL_BIT + 445)
#define __NR_landlock_restrict_self (__X32_SYSCALL_BIT + 446)
#define __NR_memfd_secret (__X32_SYSCALL_BIT + 447)
#define __NR_process_mrelease (__X32_SYSCALL_BIT + 448)
#define __NR_futex_waitv (__X32_SYSCALL_BIT + 449)
#define __NR_set_mempolicy_home_node (__X32_SYSCALL_BIT + 450)
#define __NR_cachestat (__X32_SYSCALL_BIT + 451)
#define __NR_fchmodat2 (__X32_SYSCALL_BIT + 452)
#define __NR_map_shadow_stack (__X32_SYSCALL_BIT + 453)
#define __NR_futex_wake (__X32_SYSCALL_BIT + 454)
#define __NR_futex_wait (__X32_SYSCALL_BIT + 455)
#define __NR_futex_requeue (__X32_SYSCALL_BIT + 456)
#define __NR_statmount (__X32_SYSCALL_BIT + 457)
#define __NR_listmount (__X32_SYSCALL_BIT + 458)
#define __NR_lsm_get_self_attr (__X32_SYSCALL_BIT + 459)
#define __NR_lsm_set_self_attr (__X32_SYSCALL_BIT + 460)
#define __NR_lsm_list_modules (__X32_SYSCALL_BIT + 461)
#define __NR_mseal (__X32_SYSCALL_BIT + 462)
#define __NR_rt_sigaction (__X32_SYSCALL_BIT + 512)
#define __NR_rt_sigreturn (__X32_SYSCALL_BIT + 513)
#define __NR_ioctl (__X32_SYSCALL_BIT + 514)
#define __NR_readv (__X32_SYSCALL_BIT + 515)
#define __NR_writev (__X32_SYSCALL_BIT + 516)
#define __NR_recvfrom (__X32_SYSCALL_BIT + 517)
#define __NR_sendmsg (__X32_SYSCALL_BIT + 518)
#define __NR_recvmsg (__X32_SYSCALL_BIT + 519)
#define __NR_execve (__X32_SYSCALL_BIT + 520)
#define __NR_ptrace (__X32_SYSCALL_BIT + 521)
#define __NR_rt_sigpending (__X32_SYSCALL_BIT + 522)
#define __NR_rt_sigtimedwait (__X32_SYSCALL_BIT + 523)
#define __NR_rt_sigqueueinfo (__X32_SYSCALL_BIT + 524)
#define __NR_sigaltstack (__X32_SYSCALL_BIT + 525)
#define __NR_timer_create (__X32_SYSCALL_BIT + 526)
#define __NR_mq_notify (__X32_SYSCALL_BIT + 527)
#define __NR_kexec_load (__X32_SYSCALL_BIT + 528)
#define __NR_waitid (__X32_SYSCALL_BIT + 529)
#define __NR_set_robust_list (__X32_SYSCALL_BIT + 530)
#define __NR_get_robust_list (__X32_SYSCALL_BIT + 531)
#define __NR_vmsplice (__X32_SYSCALL_BIT + 532)
#define __NR_move_pages (__X32_SYSCALL_BIT + 533)
#define __NR_preadv (__X32_SYSCALL_BIT + 534)
#define __NR_pwritev (__X32_SYSCALL_BIT + 535)
#define __NR_rt_tgsigqueueinfo (__X32_SYSCALL_BIT + 536)
#define __NR_recvmmsg (__X32_SYSCALL_BIT + 537)
#define __NR_sendmmsg (__X32_SYSCALL_BIT + 538)
#define __NR_process_vm_readv (__X32_SYSCALL_BIT + 539)
#define __NR_process_vm_writev (__X32_SYSCALL_BIT + 540)
#define __NR_setsockopt (__X32_SYSCALL_BIT + 541)
#define __NR_getsockopt (__X32_SYSCALL_BIT + 542)
#define __NR_io_setup (__X32_SYSCALL_BIT + 543)
#define __NR_io_submit (__X32_SYSCALL_BIT + 544)
#define __NR_execveat (__X32_SYSCALL_BIT + 545)
#define __NR_preadv2 (__X32_SYSCALL_BIT + 546)
#define __NR_pwritev2 (__X32_SYSCALL_BIT + 547)
#endif

"""

```