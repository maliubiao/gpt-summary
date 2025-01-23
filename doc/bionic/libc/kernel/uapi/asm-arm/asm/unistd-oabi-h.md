Response:
Let's break down the thought process for answering the user's request about `unistd-oabi.h`.

**1. Understanding the Core Request:**

The user is asking about a specific header file within Android's Bionic library. The core request is to understand the *functionality* of this file and its relationship to Android. The user also asks for details about `libc` functions, dynamic linking, usage errors, and how Android frameworks reach this level.

**2. Initial Analysis of the File Content:**

The file is a header file (`.h`) containing a long list of `#define` macros. Each macro defines a constant starting with `__NR_`, followed by a name, and assigned a value calculated using `__NR_SYSCALL_BASE`. This immediately suggests:

* **System Calls:** The `__NR_` prefix is a strong indicator of system call numbers. These numbers are used by the operating system kernel to identify specific system services.
* **Abstraction Layer:** This header file acts as an abstraction layer, providing symbolic names for the raw system call numbers. This makes code more readable and maintainable.
* **OABI:** The `oabi` in the filename likely stands for "Old ABI" or "Original ABI". This hints at historical compatibility concerns.

**3. Answering the Functionality Question:**

Based on the above analysis, the primary function of the file is to define the system call numbers for the ARM architecture using the "old ABI". It's a mapping between symbolic names and numerical identifiers for interacting with the Linux kernel on Android.

**4. Connecting to Android Functionality:**

Every time an Android application needs to perform an operation that requires kernel intervention (like file I/O, process management, networking), it ultimately makes a system call. This header file is *essential* for this process. Examples should illustrate common user-facing actions that trigger system calls (opening a file, creating a process, etc.).

**5. Addressing `libc` Function Details:**

The header file itself *doesn't implement* `libc` functions. It *defines the interface* between `libc` functions and the kernel. A `libc` function like `open()` will internally use the `__NR_open` constant to issue the correct system call. The explanation should emphasize this indirection and focus on the `libc` function's role in setting up the system call.

**6. Delving into Dynamic Linking:**

This header file doesn't directly handle dynamic linking. However, system calls like `execve` are *fundamental* to the dynamic linking process. When an executable is loaded, the dynamic linker (`linker64` or `linker`) uses system calls to load shared libraries. The explanation needs to cover:

* **SO Layout:** A simple example of how shared libraries are loaded into memory.
* **Linking Process:**  A high-level overview of how the dynamic linker resolves symbols and relocates code.
* **Relevance to the Header:**  Highlighting how `execve` and potentially `mmap` are used by the linker.

**7. Handling Logical Reasoning (Assumptions and Outputs):**

Since the file primarily defines constants, direct logical reasoning with input/output is less applicable. Instead, the focus should be on how these constants are *used*. For example, when `open("myfile.txt", O_RDONLY)` is called, the `libc` `open` function uses `__NR_open` (which has a specific value) when making the system call.

**8. Identifying Common Usage Errors:**

Users don't directly interact with this header file. Errors arise at the `libc` level or during system call usage. Examples should focus on common mistakes made when using functions that *rely* on these system calls (e.g., incorrect file paths for `open`, invalid arguments for `ioctl`).

**9. Explaining the Android Framework/NDK Path:**

This requires tracing the call stack from the application layer down to the system call. The explanation should follow these steps:

* **Framework/NDK:** Start with a high-level action (e.g., Java file I/O, NDK file I/O).
* **JNI (if applicable):** Explain how Java code might use JNI to call native code.
* **`libc` Functions:** Show how the native code uses standard `libc` functions.
* **System Call:** Demonstrate how the `libc` function eventually makes a system call using the constants from this header file.

**10. Providing a Frida Hook Example:**

A Frida hook example should target a `libc` function whose corresponding system call is defined in the header. Hooking `open` is a good choice because it's commonly used. The example should demonstrate how to intercept the call and inspect the arguments, proving that the system call is being made.

**11. Structuring the Response:**

Organize the answer logically, addressing each part of the user's request systematically. Use clear headings and bullet points to improve readability. Provide specific examples and avoid overly technical jargon where possible. Emphasize the key role of `unistd-oabi.h` as the foundation for system interaction on Android (for the ARM OABI).

**Self-Correction/Refinement during the process:**

* **Initial Thought:** Focus heavily on individual system call implementations.
* **Correction:** Realize that the header file *defines* the calls, not their implementation. Shift focus to the role of the header in the overall process.
* **Initial Thought:**  Provide complex dynamic linking scenarios.
* **Correction:**  Simplify the dynamic linking explanation, focusing on the basic principles and how system calls are involved.
* **Initial Thought:**  Provide very low-level Frida hook details.
* **Correction:**  Offer a more user-friendly Frida example that demonstrates the core concept of intercepting the `libc` call before it reaches the kernel.

By following this thought process, which involves understanding the core request, analyzing the content, connecting to relevant concepts, and refining the explanation, a comprehensive and accurate answer can be constructed.
这个文件 `unistd-oabi.handroid` 是 Android Bionic C 库中，针对 **ARM 架构** 并且使用 **OABI (Old ABI)** 的系统调用号定义。它的主要功能是提供了一组宏定义，将系统调用的名称与对应的系统调用号关联起来。

**功能列举:**

1. **定义系统调用号:**  该文件定义了一系列以 `__NR_` 开头的宏，例如 `__NR_read`, `__NR_write`, `__NR_open` 等。这些宏的值是系统调用号，内核通过这些数字来识别用户空间请求的具体操作。
2. **为旧版 ARM ABI 提供兼容性:**  `oabi` 表明这是为旧的 ARM 应用程序二进制接口 (ABI) 准备的。在较新的 Android 版本中，通常使用 EABI (Embedded ABI)。 这个文件是为了兼容那些使用旧 ABI 编译的程序。
3. **作为用户空间与内核交互的桥梁:**  C 库函数 (例如 `read`, `write`, `open`) 在底层会通过这些系统调用号来请求内核执行相应的操作。

**与 Android 功能的关系及举例说明:**

这个文件是 Android 系统运行的基石，几乎所有的 Android 功能都间接地或直接地依赖于这里定义的系统调用。

* **文件操作:**  当你使用 Java 或 Native 代码打开、读取、写入文件时，最终会调用到 `libc` 提供的 `open`, `read`, `write` 等函数。这些函数内部会使用 `__NR_open`, `__NR_read`, `__NR_write` 等宏定义的系统调用号来请求内核执行文件操作。
    * **例如:**  Java 代码中 `FileInputStream` 的创建最终会通过 JNI 调用到 native 层的 `open` 函数，该函数会使用 `__NR_open` 发起系统调用。
    * **NDK 例子:**  在 C++ 代码中使用 `fopen`, `fread`, `fwrite` 等函数进行文件操作时，也会最终调用到对应的系统调用。
* **进程管理:**  `__NR_fork`, `__NR_execve`, `__NR_exit` 等系统调用号用于创建、执行和终止进程。Android 的应用启动、进程管理等都离不开这些系统调用。
    * **例如:** 当 Android 系统启动一个新的应用时，`zygote` 进程会 `fork` 出一个新的进程，然后调用 `execve` 加载应用的代码。
* **内存管理:** `__NR_mmap`, `__NR_munmap`, `__NR_brk` 等系统调用号用于进行内存映射、取消映射和动态内存分配。
    * **例如:**  Android 的 Dalvik/ART 虚拟机使用 `mmap` 将 DEX 文件映射到内存中执行。
* **网络通信:** `__NR_socket`, `__NR_bind`, `__NR_connect`, `__NR_send`, `__NR_recv` 等系统调用号用于进行网络编程。
    * **例如:**  当你的 Android 应用需要连接到服务器发送数据时，会使用 `socket` 创建套接字，然后使用 `connect` 连接服务器，最后使用 `send` 发送数据。这些操作都对应着相应的系统调用。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件本身并不实现 `libc` 函数，它只是定义了系统调用号。`libc` 函数的实现通常包含以下步骤：

1. **参数准备:** `libc` 函数接收用户传入的参数，并将其转换为内核期望的格式。
2. **系统调用号加载:**  `libc` 函数内部会使用这里定义的 `__NR_xxx` 宏来获取对应的系统调用号。
3. **陷入内核 (Trap to Kernel):**  `libc` 函数会使用特定的汇编指令（例如 ARM 架构上的 `SWI` 或 `SVC`）触发一个软中断，将程序执行权交给内核。这个过程也称为 "系统调用"。
4. **内核处理:**  内核接收到中断后，会根据系统调用号查找对应的内核函数，并执行相应的操作。
5. **结果返回:**  内核操作完成后，会将结果写入特定的寄存器，并将程序执行权返回给用户空间。
6. **`libc` 函数处理返回值:**  `libc` 函数接收内核返回的结果，并将其转换为 C 语言的返回值类型 (例如 int，-1 表示错误，其他值表示成功)。

**举例说明 `open` 函数的实现流程：**

1. 用户代码调用 `open("/sdcard/myfile.txt", O_RDONLY);`
2. `libc` 中的 `open` 函数接收文件路径和打开模式。
3. `open` 函数内部会加载 `__NR_open` 宏定义的值（假设是 5）。
4. `open` 函数会将文件路径、打开模式等参数放到特定的寄存器中。
5. `open` 函数执行 `SWI 0x80` (或其他类似的指令) 触发系统调用。
6. 内核接收到系统调用，根据调用号 5 找到对应的内核 `sys_open` 函数。
7. `sys_open` 函数会进行权限检查、文件查找等操作。
8. 如果成功，`sys_open` 会返回一个文件描述符 (一个小的整数)，否则返回错误码。
9. 内核将文件描述符或错误码写入寄存器，并返回用户空间。
10. `libc` 的 `open` 函数接收到返回值，如果是错误码，则设置 `errno` 并返回 -1，否则返回文件描述符。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及 dynamic linker 的具体实现细节，但 `execve` 系统调用是 dynamic linker 启动的关键。当执行一个动态链接的可执行文件时，内核会加载该文件，并注意到它依赖于一些共享库 (shared objects, `.so` 文件)。然后，内核会启动 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 来处理这些依赖。

**SO 布局样本:**

假设一个简单的 App 依赖于 `liblog.so` 和 `libcutils.so`。当 App 启动时，内存布局可能如下（简化表示）：

```
[App Process Memory Space]

Stack:     [ ... Application Stack ... ]
Heap:      [ ... Application Heap ... ]
Mapped Libraries:
    [Base Address App]      [ ... Application Code and Data ... ]
    [Base Address liblog.so]  [ ... liblog.so Code and Data ... ]
    [Base Address libcutils.so] [ ... libcutils.so Code and Data ... ]
    [Base Address libc.so]     [ ... libc.so Code and Data ... ]
    [Base Address libdl.so]    [ ... libdl.so (Dynamic Linker Library) ... ]

```

**链接的处理过程:**

1. **`execve` 系统调用:**  当 App 启动时，系统调用 `execve` 被调用，指定要执行的 App 可执行文件。
2. **加载器识别:** 内核加载 App 的可执行文件，并在其头部信息中找到 `PT_INTERP` 段，该段指向 dynamic linker 的路径 (`/system/bin/linker` 或 `/system/bin/linker64`)。
3. **启动 Dynamic Linker:** 内核不是直接执行 App 的代码，而是启动 dynamic linker。
4. **加载共享库:** Dynamic linker 解析 App 可执行文件的头部信息，找到它依赖的共享库 (例如 `liblog.so`, `libcutils.so`)。然后，dynamic linker 使用 `mmap` 等系统调用将这些共享库加载到 App 的进程地址空间中。
5. **符号解析 (Symbol Resolution):**  App 和各个共享库中会引用一些外部符号 (例如函数名、全局变量名)。Dynamic linker 需要找到这些符号的定义位置。它会遍历已加载的共享库的符号表，找到匹配的符号。
6. **重定位 (Relocation):**  由于共享库被加载到不同的内存地址，原来编译时的绝对地址可能不再有效。Dynamic linker 需要修改代码和数据段中与这些符号相关的地址，使其指向正确的内存位置。
7. **执行 App 代码:**  当所有依赖的共享库都被加载和链接完成后，dynamic linker 会将控制权交给 App 的入口点，开始执行 App 的代码。

**假设输入与输出 (逻辑推理):**

由于这个文件主要是定义常量，直接的 "输入" 和 "输出" 并不适用。但可以考虑间接的场景：

**假设输入:** 用户在 C++ 代码中调用 `open("test.txt", O_RDWR | O_CREAT, 0644);`

**逻辑推理:**

1. `libc` 的 `open` 函数会被调用，接收文件名、标志和权限模式。
2. `open` 函数内部会使用 `__NR_open` 宏获取系统调用号。
3. 参数会被准备好，包括指向 "test.txt" 字符串的指针，以及 `O_RDWR | O_CREAT` 和 `0644` 的值。
4. 系统调用陷入内核。
5. 内核的 `sys_open` 函数接收这些参数。
6. `sys_open` 函数会尝试打开或创建 "test.txt" 文件，并设置相应的权限。

**可能输出:**

* **成功:** 返回一个非负的文件描述符 (例如 3)。
* **失败:** 返回 -1，并设置 `errno` 变量指示错误原因 (例如文件不存在但未指定 `O_CREAT`，或者权限不足)。

**用户或编程常见的使用错误，请举例说明:**

* **系统调用号错误或不匹配:**  虽然通常不会直接使用这里的宏，但在极少数底层编程或内核开发中，如果使用了错误的系统调用号，会导致程序行为异常甚至崩溃。
* **`libc` 函数参数错误:** 这是更常见的错误。例如，调用 `open` 时传入了空指针作为文件名，或者使用了无效的标志位。这会导致 `libc` 函数返回错误，但最终还是通过这里定义的系统调用号与内核交互。
    ```c
    #include <fcntl.h>
    #include <unistd.h>
    #include <stdio.h>
    #include <errno.h>

    int main() {
        int fd = open(NULL, O_RDONLY); // 错误：文件名为空指针
        if (fd == -1) {
            perror("open"); // 输出错误信息
        }
        return 0;
    }
    ```
* **权限问题:**  尝试执行某些需要特权的系统调用 (例如 `mount`, `reboot`) 但当前用户没有足够的权限，会导致系统调用失败。
* **资源耗尽:**  例如，在高并发场景下，尝试创建过多的文件描述符或进程，可能会导致对应的系统调用失败。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤 (以文件读取为例):**

1. **Java Framework:** Android 应用通常通过 Java Framework 进行文件操作，例如 `FileInputStream`.
2. **JNI (Java Native Interface):** `FileInputStream` 底层会通过 JNI 调用到 Native 代码 (通常是 `libopenjdk.so` 或其他相关库)。
3. **Native Libc Wrapper:** Native 代码会调用 `libc` 提供的文件操作函数，例如 `open`, `read`.
4. **系统调用:** `libc` 函数内部会使用 `__NR_read` (或其他相关宏) 定义的系统调用号，通过软中断陷入内核。
5. **Kernel System Call Handler:** Linux 内核接收到中断，根据系统调用号找到对应的内核函数 (例如 `sys_read`) 执行文件读取操作。

**NDK 到达这里的步骤:**

1. **NDK 代码:** 使用 NDK 开发的 Native 代码直接调用 `libc` 函数，例如 `open`, `read`.
2. **系统调用:**  与 Framework 类似，`libc` 函数内部会使用 `__NR_read` 等宏定义的系统调用号，触发系统调用。
3. **Kernel System Call Handler:** 内核处理相应的系统调用。

**Frida Hook 示例:**

以下是一个使用 Frida hook `open` 系统调用的示例，可以观察参数和返回值：

```python
import frida
import sys

package_name = "your.package.name" # 替换成你要调试的 App 包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var pathname = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        var mode = args[2] ? args[2].toInt() : -1; // mode 参数可能不存在

        send({
            type: "open",
            pathname: pathname,
            flags: flags,
            mode: mode
        });
    },
    onLeave: function(retval) {
        send({
            type: "open_return",
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

**Frida Hook 解释:**

1. **导入 Frida 库:** 导入必要的 Frida 模块。
2. **指定包名:**  设置要 hook 的 Android 应用的包名。
3. **连接设备并附加进程:** 使用 Frida 连接 USB 设备，并附加到目标应用的进程。
4. **Frida Script:**
   - `Interceptor.attach`:  使用 Frida 的 `Interceptor` API 来 hook `libc.so` 中的 `open` 函数。
   - `onEnter`: 在 `open` 函数被调用之前执行。
     - `args`:  包含了 `open` 函数的参数。`args[0]` 是文件名指针，`args[1]` 是 flags，`args[2]` 是 mode。
     - `Memory.readUtf8String`: 读取文件名指针指向的字符串。
     - `toInt()`: 将参数转换为整数。
     - `send()`:  使用 Frida 的 `send` 函数将信息发送回 Python 脚本。
   - `onLeave`: 在 `open` 函数执行完成并返回之后执行。
     - `retval`: 包含了 `open` 函数的返回值 (文件描述符或 -1)。
     - `send()`: 发送返回值信息。
5. **加载脚本并保持运行:**  加载 Frida 脚本，并使用 `sys.stdin.read()` 使 Python 脚本保持运行，以便持续监听 hook 的结果。

**运行这个 Frida 脚本后，当你操作目标 App 进行文件打开操作时，Frida 会打印出 `open` 函数的参数 (文件名, flags, mode) 和返回值。这可以帮助你理解 Android Framework 或 NDK 是如何调用到 `libc` 的 `open` 函数，并最终通过系统调用与内核交互的。**

总结来说，`bionic/libc/kernel/uapi/asm-arm/asm/unistd-oabi.handroid` 文件是 Android 系统与内核交互的基础，它定义了旧版 ARM ABI 的系统调用号，使得用户空间的 `libc` 函数能够请求内核执行各种操作。理解这个文件有助于深入理解 Android 系统的底层运作机制。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-arm/asm/unistd-oabi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_ASM_UNISTD_OABI_H
#define _UAPI_ASM_UNISTD_OABI_H
#define __NR_restart_syscall (__NR_SYSCALL_BASE + 0)
#define __NR_exit (__NR_SYSCALL_BASE + 1)
#define __NR_fork (__NR_SYSCALL_BASE + 2)
#define __NR_read (__NR_SYSCALL_BASE + 3)
#define __NR_write (__NR_SYSCALL_BASE + 4)
#define __NR_open (__NR_SYSCALL_BASE + 5)
#define __NR_close (__NR_SYSCALL_BASE + 6)
#define __NR_creat (__NR_SYSCALL_BASE + 8)
#define __NR_link (__NR_SYSCALL_BASE + 9)
#define __NR_unlink (__NR_SYSCALL_BASE + 10)
#define __NR_execve (__NR_SYSCALL_BASE + 11)
#define __NR_chdir (__NR_SYSCALL_BASE + 12)
#define __NR_time (__NR_SYSCALL_BASE + 13)
#define __NR_mknod (__NR_SYSCALL_BASE + 14)
#define __NR_chmod (__NR_SYSCALL_BASE + 15)
#define __NR_lchown (__NR_SYSCALL_BASE + 16)
#define __NR_lseek (__NR_SYSCALL_BASE + 19)
#define __NR_getpid (__NR_SYSCALL_BASE + 20)
#define __NR_mount (__NR_SYSCALL_BASE + 21)
#define __NR_umount (__NR_SYSCALL_BASE + 22)
#define __NR_setuid (__NR_SYSCALL_BASE + 23)
#define __NR_getuid (__NR_SYSCALL_BASE + 24)
#define __NR_stime (__NR_SYSCALL_BASE + 25)
#define __NR_ptrace (__NR_SYSCALL_BASE + 26)
#define __NR_alarm (__NR_SYSCALL_BASE + 27)
#define __NR_pause (__NR_SYSCALL_BASE + 29)
#define __NR_utime (__NR_SYSCALL_BASE + 30)
#define __NR_access (__NR_SYSCALL_BASE + 33)
#define __NR_nice (__NR_SYSCALL_BASE + 34)
#define __NR_sync (__NR_SYSCALL_BASE + 36)
#define __NR_kill (__NR_SYSCALL_BASE + 37)
#define __NR_rename (__NR_SYSCALL_BASE + 38)
#define __NR_mkdir (__NR_SYSCALL_BASE + 39)
#define __NR_rmdir (__NR_SYSCALL_BASE + 40)
#define __NR_dup (__NR_SYSCALL_BASE + 41)
#define __NR_pipe (__NR_SYSCALL_BASE + 42)
#define __NR_times (__NR_SYSCALL_BASE + 43)
#define __NR_brk (__NR_SYSCALL_BASE + 45)
#define __NR_setgid (__NR_SYSCALL_BASE + 46)
#define __NR_getgid (__NR_SYSCALL_BASE + 47)
#define __NR_geteuid (__NR_SYSCALL_BASE + 49)
#define __NR_getegid (__NR_SYSCALL_BASE + 50)
#define __NR_acct (__NR_SYSCALL_BASE + 51)
#define __NR_umount2 (__NR_SYSCALL_BASE + 52)
#define __NR_ioctl (__NR_SYSCALL_BASE + 54)
#define __NR_fcntl (__NR_SYSCALL_BASE + 55)
#define __NR_setpgid (__NR_SYSCALL_BASE + 57)
#define __NR_umask (__NR_SYSCALL_BASE + 60)
#define __NR_chroot (__NR_SYSCALL_BASE + 61)
#define __NR_ustat (__NR_SYSCALL_BASE + 62)
#define __NR_dup2 (__NR_SYSCALL_BASE + 63)
#define __NR_getppid (__NR_SYSCALL_BASE + 64)
#define __NR_getpgrp (__NR_SYSCALL_BASE + 65)
#define __NR_setsid (__NR_SYSCALL_BASE + 66)
#define __NR_sigaction (__NR_SYSCALL_BASE + 67)
#define __NR_setreuid (__NR_SYSCALL_BASE + 70)
#define __NR_setregid (__NR_SYSCALL_BASE + 71)
#define __NR_sigsuspend (__NR_SYSCALL_BASE + 72)
#define __NR_sigpending (__NR_SYSCALL_BASE + 73)
#define __NR_sethostname (__NR_SYSCALL_BASE + 74)
#define __NR_setrlimit (__NR_SYSCALL_BASE + 75)
#define __NR_getrlimit (__NR_SYSCALL_BASE + 76)
#define __NR_getrusage (__NR_SYSCALL_BASE + 77)
#define __NR_gettimeofday (__NR_SYSCALL_BASE + 78)
#define __NR_settimeofday (__NR_SYSCALL_BASE + 79)
#define __NR_getgroups (__NR_SYSCALL_BASE + 80)
#define __NR_setgroups (__NR_SYSCALL_BASE + 81)
#define __NR_select (__NR_SYSCALL_BASE + 82)
#define __NR_symlink (__NR_SYSCALL_BASE + 83)
#define __NR_readlink (__NR_SYSCALL_BASE + 85)
#define __NR_uselib (__NR_SYSCALL_BASE + 86)
#define __NR_swapon (__NR_SYSCALL_BASE + 87)
#define __NR_reboot (__NR_SYSCALL_BASE + 88)
#define __NR_readdir (__NR_SYSCALL_BASE + 89)
#define __NR_mmap (__NR_SYSCALL_BASE + 90)
#define __NR_munmap (__NR_SYSCALL_BASE + 91)
#define __NR_truncate (__NR_SYSCALL_BASE + 92)
#define __NR_ftruncate (__NR_SYSCALL_BASE + 93)
#define __NR_fchmod (__NR_SYSCALL_BASE + 94)
#define __NR_fchown (__NR_SYSCALL_BASE + 95)
#define __NR_getpriority (__NR_SYSCALL_BASE + 96)
#define __NR_setpriority (__NR_SYSCALL_BASE + 97)
#define __NR_statfs (__NR_SYSCALL_BASE + 99)
#define __NR_fstatfs (__NR_SYSCALL_BASE + 100)
#define __NR_socketcall (__NR_SYSCALL_BASE + 102)
#define __NR_syslog (__NR_SYSCALL_BASE + 103)
#define __NR_setitimer (__NR_SYSCALL_BASE + 104)
#define __NR_getitimer (__NR_SYSCALL_BASE + 105)
#define __NR_stat (__NR_SYSCALL_BASE + 106)
#define __NR_lstat (__NR_SYSCALL_BASE + 107)
#define __NR_fstat (__NR_SYSCALL_BASE + 108)
#define __NR_vhangup (__NR_SYSCALL_BASE + 111)
#define __NR_syscall (__NR_SYSCALL_BASE + 113)
#define __NR_wait4 (__NR_SYSCALL_BASE + 114)
#define __NR_swapoff (__NR_SYSCALL_BASE + 115)
#define __NR_sysinfo (__NR_SYSCALL_BASE + 116)
#define __NR_ipc (__NR_SYSCALL_BASE + 117)
#define __NR_fsync (__NR_SYSCALL_BASE + 118)
#define __NR_sigreturn (__NR_SYSCALL_BASE + 119)
#define __NR_clone (__NR_SYSCALL_BASE + 120)
#define __NR_setdomainname (__NR_SYSCALL_BASE + 121)
#define __NR_uname (__NR_SYSCALL_BASE + 122)
#define __NR_adjtimex (__NR_SYSCALL_BASE + 124)
#define __NR_mprotect (__NR_SYSCALL_BASE + 125)
#define __NR_sigprocmask (__NR_SYSCALL_BASE + 126)
#define __NR_init_module (__NR_SYSCALL_BASE + 128)
#define __NR_delete_module (__NR_SYSCALL_BASE + 129)
#define __NR_quotactl (__NR_SYSCALL_BASE + 131)
#define __NR_getpgid (__NR_SYSCALL_BASE + 132)
#define __NR_fchdir (__NR_SYSCALL_BASE + 133)
#define __NR_bdflush (__NR_SYSCALL_BASE + 134)
#define __NR_sysfs (__NR_SYSCALL_BASE + 135)
#define __NR_personality (__NR_SYSCALL_BASE + 136)
#define __NR_setfsuid (__NR_SYSCALL_BASE + 138)
#define __NR_setfsgid (__NR_SYSCALL_BASE + 139)
#define __NR__llseek (__NR_SYSCALL_BASE + 140)
#define __NR_getdents (__NR_SYSCALL_BASE + 141)
#define __NR__newselect (__NR_SYSCALL_BASE + 142)
#define __NR_flock (__NR_SYSCALL_BASE + 143)
#define __NR_msync (__NR_SYSCALL_BASE + 144)
#define __NR_readv (__NR_SYSCALL_BASE + 145)
#define __NR_writev (__NR_SYSCALL_BASE + 146)
#define __NR_getsid (__NR_SYSCALL_BASE + 147)
#define __NR_fdatasync (__NR_SYSCALL_BASE + 148)
#define __NR__sysctl (__NR_SYSCALL_BASE + 149)
#define __NR_mlock (__NR_SYSCALL_BASE + 150)
#define __NR_munlock (__NR_SYSCALL_BASE + 151)
#define __NR_mlockall (__NR_SYSCALL_BASE + 152)
#define __NR_munlockall (__NR_SYSCALL_BASE + 153)
#define __NR_sched_setparam (__NR_SYSCALL_BASE + 154)
#define __NR_sched_getparam (__NR_SYSCALL_BASE + 155)
#define __NR_sched_setscheduler (__NR_SYSCALL_BASE + 156)
#define __NR_sched_getscheduler (__NR_SYSCALL_BASE + 157)
#define __NR_sched_yield (__NR_SYSCALL_BASE + 158)
#define __NR_sched_get_priority_max (__NR_SYSCALL_BASE + 159)
#define __NR_sched_get_priority_min (__NR_SYSCALL_BASE + 160)
#define __NR_sched_rr_get_interval (__NR_SYSCALL_BASE + 161)
#define __NR_nanosleep (__NR_SYSCALL_BASE + 162)
#define __NR_mremap (__NR_SYSCALL_BASE + 163)
#define __NR_setresuid (__NR_SYSCALL_BASE + 164)
#define __NR_getresuid (__NR_SYSCALL_BASE + 165)
#define __NR_poll (__NR_SYSCALL_BASE + 168)
#define __NR_nfsservctl (__NR_SYSCALL_BASE + 169)
#define __NR_setresgid (__NR_SYSCALL_BASE + 170)
#define __NR_getresgid (__NR_SYSCALL_BASE + 171)
#define __NR_prctl (__NR_SYSCALL_BASE + 172)
#define __NR_rt_sigreturn (__NR_SYSCALL_BASE + 173)
#define __NR_rt_sigaction (__NR_SYSCALL_BASE + 174)
#define __NR_rt_sigprocmask (__NR_SYSCALL_BASE + 175)
#define __NR_rt_sigpending (__NR_SYSCALL_BASE + 176)
#define __NR_rt_sigtimedwait (__NR_SYSCALL_BASE + 177)
#define __NR_rt_sigqueueinfo (__NR_SYSCALL_BASE + 178)
#define __NR_rt_sigsuspend (__NR_SYSCALL_BASE + 179)
#define __NR_pread64 (__NR_SYSCALL_BASE + 180)
#define __NR_pwrite64 (__NR_SYSCALL_BASE + 181)
#define __NR_chown (__NR_SYSCALL_BASE + 182)
#define __NR_getcwd (__NR_SYSCALL_BASE + 183)
#define __NR_capget (__NR_SYSCALL_BASE + 184)
#define __NR_capset (__NR_SYSCALL_BASE + 185)
#define __NR_sigaltstack (__NR_SYSCALL_BASE + 186)
#define __NR_sendfile (__NR_SYSCALL_BASE + 187)
#define __NR_vfork (__NR_SYSCALL_BASE + 190)
#define __NR_ugetrlimit (__NR_SYSCALL_BASE + 191)
#define __NR_mmap2 (__NR_SYSCALL_BASE + 192)
#define __NR_truncate64 (__NR_SYSCALL_BASE + 193)
#define __NR_ftruncate64 (__NR_SYSCALL_BASE + 194)
#define __NR_stat64 (__NR_SYSCALL_BASE + 195)
#define __NR_lstat64 (__NR_SYSCALL_BASE + 196)
#define __NR_fstat64 (__NR_SYSCALL_BASE + 197)
#define __NR_lchown32 (__NR_SYSCALL_BASE + 198)
#define __NR_getuid32 (__NR_SYSCALL_BASE + 199)
#define __NR_getgid32 (__NR_SYSCALL_BASE + 200)
#define __NR_geteuid32 (__NR_SYSCALL_BASE + 201)
#define __NR_getegid32 (__NR_SYSCALL_BASE + 202)
#define __NR_setreuid32 (__NR_SYSCALL_BASE + 203)
#define __NR_setregid32 (__NR_SYSCALL_BASE + 204)
#define __NR_getgroups32 (__NR_SYSCALL_BASE + 205)
#define __NR_setgroups32 (__NR_SYSCALL_BASE + 206)
#define __NR_fchown32 (__NR_SYSCALL_BASE + 207)
#define __NR_setresuid32 (__NR_SYSCALL_BASE + 208)
#define __NR_getresuid32 (__NR_SYSCALL_BASE + 209)
#define __NR_setresgid32 (__NR_SYSCALL_BASE + 210)
#define __NR_getresgid32 (__NR_SYSCALL_BASE + 211)
#define __NR_chown32 (__NR_SYSCALL_BASE + 212)
#define __NR_setuid32 (__NR_SYSCALL_BASE + 213)
#define __NR_setgid32 (__NR_SYSCALL_BASE + 214)
#define __NR_setfsuid32 (__NR_SYSCALL_BASE + 215)
#define __NR_setfsgid32 (__NR_SYSCALL_BASE + 216)
#define __NR_getdents64 (__NR_SYSCALL_BASE + 217)
#define __NR_pivot_root (__NR_SYSCALL_BASE + 218)
#define __NR_mincore (__NR_SYSCALL_BASE + 219)
#define __NR_madvise (__NR_SYSCALL_BASE + 220)
#define __NR_fcntl64 (__NR_SYSCALL_BASE + 221)
#define __NR_gettid (__NR_SYSCALL_BASE + 224)
#define __NR_readahead (__NR_SYSCALL_BASE + 225)
#define __NR_setxattr (__NR_SYSCALL_BASE + 226)
#define __NR_lsetxattr (__NR_SYSCALL_BASE + 227)
#define __NR_fsetxattr (__NR_SYSCALL_BASE + 228)
#define __NR_getxattr (__NR_SYSCALL_BASE + 229)
#define __NR_lgetxattr (__NR_SYSCALL_BASE + 230)
#define __NR_fgetxattr (__NR_SYSCALL_BASE + 231)
#define __NR_listxattr (__NR_SYSCALL_BASE + 232)
#define __NR_llistxattr (__NR_SYSCALL_BASE + 233)
#define __NR_flistxattr (__NR_SYSCALL_BASE + 234)
#define __NR_removexattr (__NR_SYSCALL_BASE + 235)
#define __NR_lremovexattr (__NR_SYSCALL_BASE + 236)
#define __NR_fremovexattr (__NR_SYSCALL_BASE + 237)
#define __NR_tkill (__NR_SYSCALL_BASE + 238)
#define __NR_sendfile64 (__NR_SYSCALL_BASE + 239)
#define __NR_futex (__NR_SYSCALL_BASE + 240)
#define __NR_sched_setaffinity (__NR_SYSCALL_BASE + 241)
#define __NR_sched_getaffinity (__NR_SYSCALL_BASE + 242)
#define __NR_io_setup (__NR_SYSCALL_BASE + 243)
#define __NR_io_destroy (__NR_SYSCALL_BASE + 244)
#define __NR_io_getevents (__NR_SYSCALL_BASE + 245)
#define __NR_io_submit (__NR_SYSCALL_BASE + 246)
#define __NR_io_cancel (__NR_SYSCALL_BASE + 247)
#define __NR_exit_group (__NR_SYSCALL_BASE + 248)
#define __NR_lookup_dcookie (__NR_SYSCALL_BASE + 249)
#define __NR_epoll_create (__NR_SYSCALL_BASE + 250)
#define __NR_epoll_ctl (__NR_SYSCALL_BASE + 251)
#define __NR_epoll_wait (__NR_SYSCALL_BASE + 252)
#define __NR_remap_file_pages (__NR_SYSCALL_BASE + 253)
#define __NR_set_tid_address (__NR_SYSCALL_BASE + 256)
#define __NR_timer_create (__NR_SYSCALL_BASE + 257)
#define __NR_timer_settime (__NR_SYSCALL_BASE + 258)
#define __NR_timer_gettime (__NR_SYSCALL_BASE + 259)
#define __NR_timer_getoverrun (__NR_SYSCALL_BASE + 260)
#define __NR_timer_delete (__NR_SYSCALL_BASE + 261)
#define __NR_clock_settime (__NR_SYSCALL_BASE + 262)
#define __NR_clock_gettime (__NR_SYSCALL_BASE + 263)
#define __NR_clock_getres (__NR_SYSCALL_BASE + 264)
#define __NR_clock_nanosleep (__NR_SYSCALL_BASE + 265)
#define __NR_statfs64 (__NR_SYSCALL_BASE + 266)
#define __NR_fstatfs64 (__NR_SYSCALL_BASE + 267)
#define __NR_tgkill (__NR_SYSCALL_BASE + 268)
#define __NR_utimes (__NR_SYSCALL_BASE + 269)
#define __NR_arm_fadvise64_64 (__NR_SYSCALL_BASE + 270)
#define __NR_pciconfig_iobase (__NR_SYSCALL_BASE + 271)
#define __NR_pciconfig_read (__NR_SYSCALL_BASE + 272)
#define __NR_pciconfig_write (__NR_SYSCALL_BASE + 273)
#define __NR_mq_open (__NR_SYSCALL_BASE + 274)
#define __NR_mq_unlink (__NR_SYSCALL_BASE + 275)
#define __NR_mq_timedsend (__NR_SYSCALL_BASE + 276)
#define __NR_mq_timedreceive (__NR_SYSCALL_BASE + 277)
#define __NR_mq_notify (__NR_SYSCALL_BASE + 278)
#define __NR_mq_getsetattr (__NR_SYSCALL_BASE + 279)
#define __NR_waitid (__NR_SYSCALL_BASE + 280)
#define __NR_socket (__NR_SYSCALL_BASE + 281)
#define __NR_bind (__NR_SYSCALL_BASE + 282)
#define __NR_connect (__NR_SYSCALL_BASE + 283)
#define __NR_listen (__NR_SYSCALL_BASE + 284)
#define __NR_accept (__NR_SYSCALL_BASE + 285)
#define __NR_getsockname (__NR_SYSCALL_BASE + 286)
#define __NR_getpeername (__NR_SYSCALL_BASE + 287)
#define __NR_socketpair (__NR_SYSCALL_BASE + 288)
#define __NR_send (__NR_SYSCALL_BASE + 289)
#define __NR_sendto (__NR_SYSCALL_BASE + 290)
#define __NR_recv (__NR_SYSCALL_BASE + 291)
#define __NR_recvfrom (__NR_SYSCALL_BASE + 292)
#define __NR_shutdown (__NR_SYSCALL_BASE + 293)
#define __NR_setsockopt (__NR_SYSCALL_BASE + 294)
#define __NR_getsockopt (__NR_SYSCALL_BASE + 295)
#define __NR_sendmsg (__NR_SYSCALL_BASE + 296)
#define __NR_recvmsg (__NR_SYSCALL_BASE + 297)
#define __NR_semop (__NR_SYSCALL_BASE + 298)
#define __NR_semget (__NR_SYSCALL_BASE + 299)
#define __NR_semctl (__NR_SYSCALL_BASE + 300)
#define __NR_msgsnd (__NR_SYSCALL_BASE + 301)
#define __NR_msgrcv (__NR_SYSCALL_BASE + 302)
#define __NR_msgget (__NR_SYSCALL_BASE + 303)
#define __NR_msgctl (__NR_SYSCALL_BASE + 304)
#define __NR_shmat (__NR_SYSCALL_BASE + 305)
#define __NR_shmdt (__NR_SYSCALL_BASE + 306)
#define __NR_shmget (__NR_SYSCALL_BASE + 307)
#define __NR_shmctl (__NR_SYSCALL_BASE + 308)
#define __NR_add_key (__NR_SYSCALL_BASE + 309)
#define __NR_request_key (__NR_SYSCALL_BASE + 310)
#define __NR_keyctl (__NR_SYSCALL_BASE + 311)
#define __NR_semtimedop (__NR_SYSCALL_BASE + 312)
#define __NR_vserver (__NR_SYSCALL_BASE + 313)
#define __NR_ioprio_set (__NR_SYSCALL_BASE + 314)
#define __NR_ioprio_get (__NR_SYSCALL_BASE + 315)
#define __NR_inotify_init (__NR_SYSCALL_BASE + 316)
#define __NR_inotify_add_watch (__NR_SYSCALL_BASE + 317)
#define __NR_inotify_rm_watch (__NR_SYSCALL_BASE + 318)
#define __NR_mbind (__NR_SYSCALL_BASE + 319)
#define __NR_get_mempolicy (__NR_SYSCALL_BASE + 320)
#define __NR_set_mempolicy (__NR_SYSCALL_BASE + 321)
#define __NR_openat (__NR_SYSCALL_BASE + 322)
#define __NR_mkdirat (__NR_SYSCALL_BASE + 323)
#define __NR_mknodat (__NR_SYSCALL_BASE + 324)
#define __NR_fchownat (__NR_SYSCALL_BASE + 325)
#define __NR_futimesat (__NR_SYSCALL_BASE + 326)
#define __NR_fstatat64 (__NR_SYSCALL_BASE + 327)
#define __NR_unlinkat (__NR_SYSCALL_BASE + 328)
#define __NR_renameat (__NR_SYSCALL_BASE + 329)
#define __NR_linkat (__NR_SYSCALL_BASE + 330)
#define __NR_symlinkat (__NR_SYSCALL_BASE + 331)
#define __NR_readlinkat (__NR_SYSCALL_BASE + 332)
#define __NR_fchmodat (__NR_SYSCALL_BASE + 333)
#define __NR_faccessat (__NR_SYSCALL_BASE + 334)
#define __NR_pselect6 (__NR_SYSCALL_BASE + 335)
#define __NR_ppoll (__NR_SYSCALL_BASE + 336)
#define __NR_unshare (__NR_SYSCALL_BASE + 337)
#define __NR_set_robust_list (__NR_SYSCALL_BASE + 338)
#define __NR_get_robust_list (__NR_SYSCALL_BASE + 339)
#define __NR_splice (__NR_SYSCALL_BASE + 340)
#define __NR_arm_sync_file_range (__NR_SYSCALL_BASE + 341)
#define __NR_tee (__NR_SYSCALL_BASE + 342)
#define __NR_vmsplice (__NR_SYSCALL_BASE + 343)
#define __NR_move_pages (__NR_SYSCALL_BASE + 344)
#define __NR_getcpu (__NR_SYSCALL_BASE + 345)
#define __NR_epoll_pwait (__NR_SYSCALL_BASE + 346)
#define __NR_kexec_load (__NR_SYSCALL_BASE + 347)
#define __NR_utimensat (__NR_SYSCALL_BASE + 348)
#define __NR_signalfd (__NR_SYSCALL_BASE + 349)
#define __NR_timerfd_create (__NR_SYSCALL_BASE + 350)
#define __NR_eventfd (__NR_SYSCALL_BASE + 351)
#define __NR_fallocate (__NR_SYSCALL_BASE + 352)
#define __NR_timerfd_settime (__NR_SYSCALL_BASE + 353)
#define __NR_timerfd_gettime (__NR_SYSCALL_BASE + 354)
#define __NR_signalfd4 (__NR_SYSCALL_BASE + 355)
#define __NR_eventfd2 (__NR_SYSCALL_BASE + 356)
#define __NR_epoll_create1 (__NR_SYSCALL_BASE + 357)
#define __NR_dup3 (__NR_SYSCALL_BASE + 358)
#define __NR_pipe2 (__NR_SYSCALL_BASE + 359)
#define __NR_inotify_init1 (__NR_SYSCALL_BASE + 360)
#define __NR_preadv (__NR_SYSCALL_BASE + 361)
#define __NR_pwritev (__NR_SYSCALL_BASE + 362)
#define __NR_rt_tgsigqueueinfo (__NR_SYSCALL_BASE + 363)
#define __NR_perf_event_open (__NR_SYSCALL_BASE + 364)
#define __NR_recvmmsg (__NR_SYSCALL_BASE + 365)
#define __NR_accept4 (__NR_SYSCALL_BASE + 366)
#define __NR_fanotify_init (__NR_SYSCALL_BASE + 367)
#define __NR_fanotify_mark (__NR_SYSCALL_BASE + 368)
#define __NR_prlimit64 (__NR_SYSCALL_BASE + 369)
#define __NR_name_to_handle_at (__NR_SYSCALL_BASE + 370)
#define __NR_open_by_handle_at (__NR_SYSCALL_BASE + 371)
#define __NR_clock_adjtime (__NR_SYSCALL_BASE + 372)
#define __NR_syncfs (__NR_SYSCALL_BASE + 373)
#define __NR_sendmmsg (__NR_SYSCALL_BASE + 374)
#define __NR_setns (__NR_SYSCALL_BASE + 375)
#define __NR_process_vm_readv (__NR_SYSCALL_BASE + 376)
#define __NR_process_vm_writev (__NR_SYSCALL_BASE + 377)
#define __NR_kcmp (__NR_SYSCALL_BASE + 378)
#define __NR_finit_module (__NR_SYSCALL_BASE + 379)
#define __NR_sched_setattr (__NR_SYSCALL_BASE + 380)
#define __NR_sched_getattr (__NR_SYSCALL_BASE + 381)
#define __NR_renameat2 (__NR_SYSCALL_BASE + 382)
#define __NR_seccomp (__NR_SYSCALL_BASE + 383)
#define __NR_getrandom (__NR_SYSCALL_BASE + 384)
#define __NR_memfd_create (__NR_SYSCALL_BASE + 385)
#define __NR_bpf (__NR_SYSCALL_BASE + 386)
#define __NR_execveat (__NR_SYSCALL_BASE + 387)
#define __NR_userfaultfd (__NR_SYSCALL_BASE + 388)
#define __NR_membarrier (__NR_SYSCALL_BASE + 389)
#define __NR_mlock2 (__NR_SYSCALL_BASE + 390)
#define __NR_copy_file_range (__NR_SYSCALL_BASE + 391)
#define __NR_preadv2 (__NR_SYSCALL_BASE + 392)
#define __NR_pwritev2 (__NR_SYSCALL_BASE + 393)
#define __NR_pkey_mprotect (__NR_SYSCALL_BASE + 394)
#define __NR_pkey_alloc (__NR_SYSCALL_BASE + 395)
#define __NR_pkey_free (__NR_SYSCALL_BASE + 396)
#define __NR_statx (__NR_SYSCALL_BASE + 397)
#define __NR_rseq (__NR_SYSCALL_BASE + 398)
#define __NR_io_pgetevents (__NR_SYSCALL_BASE + 399)
#define __NR_migrate_pages (__NR_SYSCALL_BASE + 400)
#define __NR_kexec_file_load (__NR_SYSCALL_BASE + 401)
#define __NR_clock_gettime64 (__NR_SYSCALL_BASE + 403)
#define __NR_clock_settime64 (__NR_SYSCALL_BASE + 404)
#define __NR_clock_adjtime64 (__NR_SYSCALL_BASE + 405)
#define __NR_clock_getres_time64 (__NR_SYSCALL_BASE + 406)
#define __NR_clock_nanosleep_time64 (__NR_SYSCALL_BASE + 407)
#define __NR_timer_gettime64 (__NR_SYSCALL_BASE + 408)
#define __NR_timer_settime64 (__NR_SYSCALL_BASE + 409)
#define __NR_timerfd_gettime64 (__NR_SYSCALL_BASE + 410)
#define __NR_timerfd_settime64 (__NR_SYSCALL_BASE + 411)
#define __NR_utimensat_time64 (__NR_SYSCALL_BASE + 412)
#define __NR_pselect6_time64 (__NR_SYSCALL_BASE + 413)
#define __NR_ppoll_time64 (__NR_SYSCALL_BASE + 414)
#define __NR_io_pgetevents_time64 (__NR_SYSCALL_BASE + 416)
#define __NR_recvmmsg_time64 (__NR_SYSCALL_BASE + 417)
#define __NR_mq_timedsend_time64 (__NR_SYSCALL_BASE + 418)
#define __NR_mq_timedreceive_time64 (__NR_SYSCALL_BASE + 419)
#define __NR_semtimedop_time64 (__NR_SYSCALL_BASE + 420)
#define __NR_rt_sigtimedwait_time64 (__NR_SYSCALL_BASE + 421)
#define __NR_futex_time64 (__NR_SYSCALL_BASE + 422)
#define __NR_sched_rr_get_interval_time64 (__NR_SYSCALL_BASE + 423)
#define __NR_pidfd_send_signal (__NR_SYSCALL_BASE + 424)
#define __NR_io_uring_setup (__NR_SYSCALL_BASE + 425)
#define __NR_io_uring_enter (__NR_SYSCALL_BASE + 426)
#define __NR_io_uring_register (__NR_SYSCALL_BASE + 427)
#define __NR_open_tree (__NR_SYSCALL_BASE + 428)
#define __NR_move_mount (__NR_SYSCALL_BASE + 429)
#define __NR_fsopen (__NR_SYSCALL_BASE + 430)
#define __NR_fsconfig (__NR_SYSCALL_BASE + 431)
#define __NR_fsmount (__NR_SYSCALL_BASE + 432)
#define __NR_fspick (__NR_SYSCALL_BASE + 433)
#define __NR_pidfd_open (__NR_SYSCALL_BASE + 434)
#define __NR_clone3 (__NR_SYSCALL_BASE + 435)
#define __NR_close_range (__NR_SYSCALL_BASE + 436)
#define __NR_openat2 (__NR_SYSCALL_BASE + 437)
#define __NR_pidfd_getfd (__NR_SYSCALL_BASE + 438)
#define __NR_faccessat2 (__NR_SYSCALL_BASE + 439)
#define __NR_process_madvise (__NR_SYSCALL_BASE + 440)
#define __NR_epoll_pwait2 (__NR_SYSCALL_BASE + 441)
#define __NR_mount_setattr (__NR_SYSCALL_BASE + 442)
#define __NR_quotactl_fd (__NR_SYSCALL_BASE + 443)
#define __NR_landlock_create_ruleset (__NR_SYSCALL_BASE + 444)
#define __NR_landlock_add_rule (__NR_SYSCALL_BASE + 445)
#define __NR_landlock_restrict_self (__NR_SYSCALL_BASE + 446)
#define __NR_process_mrelease (__NR_SYSCALL_BASE + 448)
#define __NR_futex_waitv (__NR_SYSCALL_BASE + 449)
#define __NR_set_mempolicy_home_node (__NR_SYSCALL_BASE + 450)
#define __NR_cachestat (__NR_SYSCALL_BASE + 451)
#define __NR_fchmodat2 (__NR_SYSCALL_BASE + 452)
#define __NR_map_shadow_stack (__NR_SYSCALL_BASE + 453)
#define __NR_futex_wake (__NR_SYSCALL_BASE + 454)
#define __NR_futex_wait (__NR_SYSCALL_BASE + 455)
#define __NR_futex_requeue (__NR_SYSCALL_BASE + 456)
#define __NR_statmount (__NR_SYSCALL_BASE + 457)
#define __NR_listmount (__NR_SYSCALL_BASE + 458)
#define __NR_lsm_get_self_attr (__NR_SYSCALL_BASE + 459)
#define __NR_lsm_set_self_attr (__NR_SYSCALL_BASE + 460)
#define __NR_lsm_list_modules (__NR_SYSCALL_BASE + 461)
#define __NR_mseal (__NR_SYSCALL_BASE + 462)
#endif
```