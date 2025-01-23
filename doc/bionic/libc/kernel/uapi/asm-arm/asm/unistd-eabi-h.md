Response:
Let's break down the thought process for answering the user's request about `unistd-eabi.handroid`.

**1. Understanding the Core Request:**

The user has provided a header file containing a list of macros. The key takeaway is that these macros define syscall numbers for the ARM architecture in an EABI (Embedded Application Binary Interface) environment, specifically for Android. The user wants to understand the *functionality* this file represents and its relation to Android.

**2. Initial Analysis of the File:**

* **`#ifndef _UAPI_ASM_UNISTD_EABI_H` and `#define _UAPI_ASM_UNISTD_EABI_H`:** Standard header guard to prevent multiple inclusions.
* **`#define __NR_restart_syscall (__NR_SYSCALL_BASE + 0)` and similar lines:** This is the crucial part. It's a mapping of symbolic names (like `__NR_restart_syscall`) to numerical values. The `__NR_SYSCALL_BASE` suggests a starting point for the syscall number assignments. The subsequent numbers increment, indicating a sequence of syscalls.

**3. Connecting to Syscalls:**

The term "syscall" is immediately relevant. I know that syscalls are the interface between user-space applications and the kernel. They are how programs request services from the operating system.

**4. Identifying the Functionality:**

Since the file defines syscall numbers, its primary function is to provide a standardized way for user-space code (like the C library) to *invoke* specific kernel operations. It's a dictionary translating human-readable names to machine-understandable numbers.

**5. Relating to Android:**

* **Bionic:** The user explicitly mentions bionic. I know bionic is Android's C library. This connection is vital. The functions in bionic often wrap these raw syscalls.
* **System Calls in General:** All operating systems need a way for applications to interact with the kernel. This file is Android's ARM EABI way of defining those interactions.

**6. Addressing the Specific Questions:**

Now, let's go through each part of the user's request systematically:

* **功能 (Functionality):** This is straightforward now: defining syscall numbers for ARM EABI on Android.

* **与 Android 功能的关系 (Relationship with Android):**  Provide examples. The most common libc functions (`read`, `write`, `open`, `close`, `exit`) are good starting points. Explain how the libc function calls the corresponding syscall.

* **详细解释 libc 函数的实现 (Detailed Explanation of libc Function Implementation):** This requires explaining the wrapping process. A typical libc function:
    1. Takes user-provided arguments.
    2. Performs some validation or setup (optional).
    3. Places the syscall number into a specific register (on ARM, typically `r7`).
    4. Places the arguments into other specific registers.
    5. Executes the `svc` (Supervisor Call) instruction.
    6. The kernel handles the syscall.
    7. The kernel returns a result (often an error code or success).
    8. The libc function checks the return value and translates it into standard C errors (like setting `errno`).

* **涉及 dynamic linker 的功能 (Functions related to the dynamic linker):**  Review the list of syscalls. `execve` is the most prominent one directly related to process execution and thus the dynamic linker.
    * **so 布局样本 (Sample SO layout):**  Create a simplified example of how shared libraries are laid out in memory. Include the GOT and PLT sections, as they are essential for dynamic linking.
    * **链接的处理过程 (Linking process):** Explain how the dynamic linker resolves symbols at runtime using the GOT and PLT. Mention lazy binding.

* **逻辑推理 (Logical Deduction):** For syscalls like `open`, `read`, and `write`, provide simple scenarios with input and output. For example, opening a file and reading from it.

* **用户或者编程常见的使用错误 (Common User/Programming Errors):** Think about common mistakes when using these syscalls indirectly through libc. Examples: forgetting to check return values, incorrect file permissions, buffer overflows when using `read` or `write`.

* **说明 android framework or ndk 是如何一步步的到达这里 (How Android Framework/NDK reaches here):**  Trace the path from a high-level API call down to the syscall.
    1. **Framework:** Example: File I/O using Java APIs.
    2. **NDK:** Example: Direct use of C/C++ standard library functions.
    3. **libc:**  The core of the interaction. Show how the standard library functions map to syscalls.

* **给出 frida hook 示例调试这些步骤 (Frida Hook Example):** Provide code snippets to demonstrate how to intercept syscalls or libc function calls using Frida. Show both syscall hooking and libc function hooking.

**7. Structuring the Answer:**

Organize the answer logically, addressing each part of the user's request clearly. Use headings and bullet points to improve readability.

**8. Refining and Adding Detail:**

* **`__NR_SYSCALL_BASE`:** Briefly explain what this represents (a base value for syscall numbering).
* **EABI:**  Mention its purpose (standardizing the ABI for embedded systems).
* **Error Handling:** Emphasize the importance of checking return values.
* **Security Implications:** Briefly touch upon how these syscalls are fundamental for system security.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe focus only on the direct syscalls.
* **Correction:** Realize the user is likely more interested in how these syscalls are used in practice, so explaining the libc wrapping is crucial.
* **Initial thought:** Provide very complex examples for dynamic linking.
* **Correction:** Simplify the SO layout and linking process explanation for clarity. Focus on the core concepts of GOT and PLT.
* **Initial thought:**  Only provide one Frida example.
* **Correction:**  Provide examples for both hooking syscalls directly and hooking libc functions, as both are relevant.

By following this structured thought process, breaking down the request, and systematically addressing each point, I can generate a comprehensive and informative answer that meets the user's needs.
## 对 bionic/libc/kernel/uapi/asm-arm/asm/unistd-eabi.handroid 的源代码文件的分析

你提供的文件 `unistd-eabi.handroid` 是 Android 系统中 bionic 库的一部分，它定义了一系列 **系统调用号 (syscall numbers)**，用于 ARM 架构上的 EABI (Embedded Application Binary Interface) 环境。 简单来说，它是一个头文件，里面列举了操作系统内核提供的各种服务，并给每个服务分配了一个唯一的数字。

**功能列举:**

该文件的主要功能是：

1. **定义系统调用号常量:**  为每个系统调用定义一个宏常量，例如 `__NR_restart_syscall`，`__NR_exit`，`__NR_read` 等。这些常量代表了内核中特定功能的编号。
2. **为用户空间程序提供访问内核服务的接口:**  用户空间程序（例如应用程序、libc 库）不能直接执行内核代码，而是需要通过系统调用来请求内核执行某些操作，例如读写文件、创建进程等。这个文件提供的系统调用号就是这个桥梁的一部分。
3. **作为 bionic libc 的基础:**  bionic libc 中的许多函数，例如 `open()`, `read()`, `write()` 等，最终会通过这些系统调用号来调用内核的相应功能。
4. **保持 ABI 兼容性:**  通过定义明确的系统调用号，可以保证在不同的 Android 版本和设备上，用户空间程序能够以一致的方式调用内核服务，从而实现 ABI 兼容性。

**与 Android 功能的关系及举例说明:**

该文件直接关联着 Android 系统的核心功能。几乎所有涉及到操作系统底层操作的功能都与此相关。以下是一些例子：

* **文件操作:**
    * `__NR_open`:  `open()` 函数在底层会使用这个系统调用来打开一个文件。例如，当一个应用需要读取一个配置文件的内容时，会调用 `open()`，最终会触发 `__NR_open` 系统调用。
    * `__NR_read`:  `read()` 函数用于从打开的文件中读取数据，底层使用 `__NR_read` 系统调用。例如，图片查看器读取图片文件内容。
    * `__NR_write`: `write()` 函数用于向打开的文件中写入数据，底层使用 `__NR_write` 系统调用。例如，日志记录器将日志信息写入文件。
    * `__NR_close`: `close()` 函数用于关闭打开的文件，底层使用 `__NR_close` 系统调用。

* **进程管理:**
    * `__NR_fork`:  `fork()` 函数用于创建一个新的进程，底层使用 `__NR_fork` 系统调用。例如，启动一个新的后台服务。
    * `__NR_execve`: `execve()` 函数用于执行一个新的程序，替换当前进程的映像，底层使用 `__NR_execve` 系统调用。例如，应用启动时，zygote 进程会 `fork` 并 `execve` 启动应用进程。
    * `__NR_exit`: `exit()` 函数用于终止当前进程，底层使用 `__NR_exit` 系统调用。

* **内存管理:**
    * `__NR_mmap`: `mmap()` 函数用于将文件或设备映射到内存中，底层使用 `__NR_mmap2` (因为是 32 位 ARM) 系统调用。 例如，加载共享库到进程的地址空间。
    * `__NR_munmap`: `munmap()` 函数用于解除内存映射。

* **网络通信:**
    * `__NR_socket`: `socket()` 函数用于创建一个网络套接字，底层使用 `__NR_socket` 系统调用。例如，应用发起网络请求。
    * `__NR_bind`, `__NR_connect`, `__NR_listen`, `__NR_accept`, `__NR_send`, `__NR_recv` 等：用于网络通信的各种操作。

* **设备交互:**
    * `__NR_ioctl`:  `ioctl()` 函数用于执行设备特定的控制操作，底层使用 `__NR_ioctl` 系统调用。例如，控制摄像头、传感器等。

**详细解释每一个 libc 函数的功能是如何实现的:**

这里我们以 `read()` 函数为例来说明：

1. **用户调用 libc 函数:** 应用程序调用 `read(fd, buf, count)`，其中 `fd` 是文件描述符，`buf` 是用于存储读取数据的缓冲区，`count` 是要读取的字节数。
2. **libc 函数封装:**  bionic libc 中的 `read()` 函数（位于 `bionic/libc/unistd/read.cpp` 或类似位置）会做一些参数校验和准备工作。
3. **构建系统调用:** `read()` 函数会将系统调用号 `__NR_read` 以及参数 `fd`, `buf`, `count` 放入特定的寄存器中。在 ARM 架构的 EABI 环境下，系统调用号通常放在寄存器 `r7` 中，参数则会按照一定的约定放在 `r0`, `r1`, `r2` 等寄存器中。
4. **触发软中断:** `read()` 函数会执行一条特殊的指令，例如 `svc #0` (Supervisor Call)，触发一个软中断，将控制权交给操作系统内核。
5. **内核处理系统调用:**
    * 内核接收到软中断后，会根据寄存器 `r7` 中的值（也就是 `__NR_read`）来确定用户请求的是哪个系统调用。
    * 内核会执行 `__NR_read` 对应的内核函数（例如 `sys_read`）。
    * `sys_read` 函数会根据文件描述符 `fd` 找到对应的文件对象，然后从文件中读取 `count` 个字节的数据，并将数据复制到用户提供的缓冲区 `buf` 中。
    * 内核会将读取的字节数或错误码放入寄存器 `r0` 中作为返回值。
6. **返回用户空间:** 内核执行完毕后，会将控制权返回给用户空间程序。
7. **libc 函数处理返回值:** bionic libc 的 `read()` 函数会检查内核返回的值：
    * 如果返回值大于等于 0，表示读取成功，返回值就是实际读取的字节数。
    * 如果返回值是 -1，表示发生错误，`read()` 函数会读取内核设置的全局变量 `errno`，将其设置为对应的错误码，并返回 -1。
8. **应用程序处理返回值:** 应用程序根据 `read()` 函数的返回值判断是否读取成功，并处理可能出现的错误。

其他 libc 函数的实现原理类似，都是通过将系统调用号和参数传递给内核来请求操作系统服务。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`__NR_execve` 系统调用是与 dynamic linker (动态链接器) 关系最密切的系统调用之一。当执行一个新的程序时，内核会加载程序的可执行文件，然后 dynamic linker 负责加载程序依赖的共享库 (Shared Objects, .so 文件)。

**SO 布局样本:**

一个典型的 .so 文件的内存布局可能如下所示（简化版）：

```
  +-------------------+  <-- 加载基址
  |      .text        |  代码段 (函数指令)
  +-------------------+
  |      .rodata      |  只读数据段 (常量字符串等)
  +-------------------+
  |      .data        |  已初始化数据段 (全局变量等)
  +-------------------+
  |      .bss         |  未初始化数据段 (未初始化的全局变量)
  +-------------------+
  |      .plt         |  过程链接表 (Procedure Linkage Table)
  +-------------------+
  |      .got.plt     |  全局偏移量表 (Global Offset Table，用于 PLT)
  +-------------------+
  |      .got         |  全局偏移量表 (Global Offset Table，用于数据)
  +-------------------+
  |      ...         |  其他段 (例如 .dynamic, .symtab, .strtab)
  +-------------------+
```

* **.text:** 存放程序的机器码指令。
* **.rodata:** 存放只读数据，例如字符串常量。
* **.data:** 存放已初始化的全局变量和静态变量。
* **.bss:** 存放未初始化的全局变量和静态变量。
* **.plt (Procedure Linkage Table):**  用于延迟绑定（lazy binding），当程序首次调用一个外部函数时，PLT 中的代码会跳转到 dynamic linker 进行符号解析。
* **.got.plt (Global Offset Table for PLT):**  与 PLT 配合使用，存放外部函数的实际地址。在动态链接完成之前，这里存放的是跳转到 dynamic linker 的地址。
* **.got (Global Offset Table):**  存放全局变量的实际地址。

**链接的处理过程:**

1. **`execve` 系统调用:** 当调用 `execve` 执行一个程序时，内核会加载可执行文件，并启动 dynamic linker。
2. **dynamic linker 加载:**  dynamic linker 本身也是一个共享库，内核会将其加载到新进程的地址空间。
3. **解析依赖:** dynamic linker 会读取可执行文件的头部信息，找到其依赖的共享库列表。
4. **加载共享库:** dynamic linker 会根据依赖列表，逐个加载所需的 .so 文件到进程的地址空间。加载时会处理地址重定位，确保共享库的代码和数据能够正确访问。
5. **符号解析 (Symbol Resolution):**
    * **延迟绑定:** 默认情况下，dynamic linker 使用延迟绑定。这意味着在程序启动时，不会立即解析所有外部函数的地址。
    * **首次调用:** 当程序首次调用一个外部函数时，会跳转到该函数在 PLT 中的入口。
    * **PLT 跳转:** PLT 入口处的代码会通过 GOT.plt 跳转到 dynamic linker。
    * **dynamic linker 解析:** dynamic linker 会查找该函数的实际地址，并将其写入 GOT.plt 中对应的条目。
    * **后续调用:**  下次再调用同一个外部函数时，会直接跳转到 GOT.plt 中已经解析好的地址，而不再需要 dynamic linker 的介入。
6. **跳转到程序入口:**  所有必要的共享库加载和符号解析完成后，dynamic linker 会跳转到程序的入口点 (通常是 `_start` 函数)。

**假设输入与输出 (对于 `execve`):**

**假设输入:**

* `pathname`:  要执行的程序路径，例如 `/system/bin/ls`。
* `argv`:  传递给程序的命令行参数，例如 `["ls", "-l", "/sdcard"]`。
* `envp`:  传递给程序的环境变量。

**输出:**

* **成功:** 如果执行成功，`execve` 系统调用不会返回（因为当前进程的映像被替换了）。新的进程开始执行 `/system/bin/ls`，并带有指定的命令行参数和环境变量。
* **失败:** 如果执行失败（例如文件不存在、权限不足等），`execve` 系统调用会返回 -1，并设置 `errno` 变量指示错误原因。

**用户或者编程常见的使用错误:**

1. **忘记检查返回值:**  很多系统调用会返回 -1 表示错误，并设置 `errno`。 程序员可能会忘记检查返回值，导致程序在发生错误后继续执行，产生不可预测的行为。
   ```c
   int fd = open("nonexistent_file.txt", O_RDONLY);
   // 忘记检查 fd 的值，直接尝试读取
   char buffer[100];
   read(fd, buffer, sizeof(buffer)); // 错误！fd 的值可能是 -1
   ```
2. **文件描述符泄漏:**  打开文件或套接字后，忘记调用 `close()` 关闭，会导致文件描述符泄漏，最终可能耗尽系统资源。
   ```c
   for (int i = 0; i < 10000; ++i) {
       open("temp_file.txt", O_RDWR | O_CREAT); // 忘记 close()
   }
   ```
3. **缓冲区溢出:** 在使用 `read()` 或 `write()` 等函数时，如果提供的缓冲区大小不正确，可能会导致缓冲区溢出，覆盖其他内存区域，造成程序崩溃或安全漏洞。
   ```c
   char buffer[10];
   read(fd, buffer, 100); // 缓冲区太小，可能溢出
   ```
4. **权限问题:**  尝试访问没有权限的文件或目录，会导致系统调用失败。
5. **信号处理不当:**  一些系统调用可能会被信号中断，需要妥善处理中断的情况。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤:**

**Android Framework 到系统调用的路径 (以文件读取为例):**

1. **Java 代码调用 Framework API:** Android 应用的 Java 代码使用 `FileInputStream` 或 `FileReader` 等类来读取文件。
   ```java
   FileInputStream fis = new FileInputStream("/sdcard/myfile.txt");
   int data = fis.read();
   fis.close();
   ```
2. **Framework API 调用 Native 方法:**  `FileInputStream` 的 `read()` 方法最终会调用底层的 Native 方法 (JNI)。
3. **Native 方法调用 bionic libc:** Native 方法会调用 bionic libc 提供的文件操作函数，例如 `read()`。
   ```c++
   // 在 Android framework 的 native 代码中
   ssize_t n = ::read(fd, buffer, count);
   ```
4. **libc 函数调用系统调用:** bionic libc 的 `read()` 函数会将参数传递给内核，并触发 `__NR_read` 系统调用。
5. **内核处理系统调用:** 内核执行文件读取操作。

**NDK 到系统调用的路径:**

1. **NDK 代码直接调用 libc 函数:** 使用 NDK 开发的应用可以直接调用 bionic libc 提供的 C/C++ 标准库函数。
   ```c++
   #include <unistd.h>
   #include <fcntl.h>

   int fd = open("/sdcard/myfile.txt", O_RDONLY);
   char buffer[100];
   read(fd, buffer, sizeof(buffer));
   close(fd);
   ```
2. **libc 函数调用系统调用:**  与 Framework 类似，libc 函数最终会调用相应的系统调用。

**Frida Hook 示例:**

以下是使用 Frida Hook `read` 系统调用和 `open` libc 函数的示例：

**Hook `read` 系统调用:**

```javascript
// hook_read_syscall.js
if (Process.arch === 'arm') {
  const readPtr = Module.findExportByName(null, '__ARM_NR_read'); // 获取 syscall number
  if (readPtr) {
    const readSyscall = new NativeFunction(readPtr, 'int', ['int', 'pointer', 'size_t']);

    Interceptor.attach(readSyscall, {
      onEnter: function (args) {
        console.log("read syscall called");
        console.log("  fd:", args[0]);
        console.log("  buf:", args[1]);
        console.log("  count:", args[2]);
      },
      onLeave: function (retval) {
        console.log("read syscall returned:", retval);
        if (parseInt(retval) > 0) {
          const buffer = this.context.r1; // 获取 buffer 地址
          const bytesRead = parseInt(retval);
          const data = Memory.readByteArray(buffer, bytesRead);
          console.log("  Data read:", hexdump(data, { length: bytesRead }));
        }
      }
    });
  } else {
    console.log("Could not find __ARM_NR_read syscall.");
  }
} else {
  console.log("This script is for ARM architecture.");
}
```

**Hook `open` libc 函数:**

```javascript
// hook_open_libc.js
const openPtr = Module.findExportByName("libc.so", "open");
if (openPtr) {
  const open = new NativeFunction(openPtr, 'int', ['pointer', 'int', 'int']);

  Interceptor.attach(open, {
    onEnter: function (args) {
      console.log("open libc function called");
      console.log("  pathname:", args[0].readCString());
      console.log("  flags:", args[1]);
      console.log("  mode:", args[2]);
    },
    onLeave: function (retval) {
      console.log("open libc function returned:", retval);
    }
  });
} else {
  console.log("Could not find open function in libc.so.");
}
```

**使用 Frida 调试步骤:**

1. **安装 Frida:** 确保你的电脑和 Android 设备上都安装了 Frida 和 frida-server。
2. **运行 frida-server:** 在 Android 设备上运行 frida-server。
3. **运行目标应用:** 运行你想要调试的 Android 应用。
4. **执行 Frida Hook 脚本:** 在你的电脑上使用 Frida 命令执行你编写的 Hook 脚本，例如：
   ```bash
   frida -U -f <package_name> -l hook_read_syscall.js
   frida -U -n <process_name> -l hook_open_libc.js
   ```
   将 `<package_name>` 替换为你的应用包名，`<process_name>` 替换为应用进程名。
5. **观察输出:** 当应用执行到被 Hook 的系统调用或 libc 函数时，Frida 会在控制台输出相关信息，帮助你理解参数、返回值以及执行流程。

通过 Frida Hook，你可以动态地观察应用与操作系统底层的交互，深入理解 Android Framework 和 NDK 如何一步步地调用到这些系统调用。

希望以上分析能够帮助你理解 `unistd-eabi.handroid` 文件的作用以及它在 Android 系统中的重要性。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-arm/asm/unistd-eabi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_ASM_UNISTD_EABI_H
#define _UAPI_ASM_UNISTD_EABI_H
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
#define __NR_mknod (__NR_SYSCALL_BASE + 14)
#define __NR_chmod (__NR_SYSCALL_BASE + 15)
#define __NR_lchown (__NR_SYSCALL_BASE + 16)
#define __NR_lseek (__NR_SYSCALL_BASE + 19)
#define __NR_getpid (__NR_SYSCALL_BASE + 20)
#define __NR_mount (__NR_SYSCALL_BASE + 21)
#define __NR_setuid (__NR_SYSCALL_BASE + 23)
#define __NR_getuid (__NR_SYSCALL_BASE + 24)
#define __NR_ptrace (__NR_SYSCALL_BASE + 26)
#define __NR_pause (__NR_SYSCALL_BASE + 29)
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
#define __NR_getrusage (__NR_SYSCALL_BASE + 77)
#define __NR_gettimeofday (__NR_SYSCALL_BASE + 78)
#define __NR_settimeofday (__NR_SYSCALL_BASE + 79)
#define __NR_getgroups (__NR_SYSCALL_BASE + 80)
#define __NR_setgroups (__NR_SYSCALL_BASE + 81)
#define __NR_symlink (__NR_SYSCALL_BASE + 83)
#define __NR_readlink (__NR_SYSCALL_BASE + 85)
#define __NR_uselib (__NR_SYSCALL_BASE + 86)
#define __NR_swapon (__NR_SYSCALL_BASE + 87)
#define __NR_reboot (__NR_SYSCALL_BASE + 88)
#define __NR_munmap (__NR_SYSCALL_BASE + 91)
#define __NR_truncate (__NR_SYSCALL_BASE + 92)
#define __NR_ftruncate (__NR_SYSCALL_BASE + 93)
#define __NR_fchmod (__NR_SYSCALL_BASE + 94)
#define __NR_fchown (__NR_SYSCALL_BASE + 95)
#define __NR_getpriority (__NR_SYSCALL_BASE + 96)
#define __NR_setpriority (__NR_SYSCALL_BASE + 97)
#define __NR_statfs (__NR_SYSCALL_BASE + 99)
#define __NR_fstatfs (__NR_SYSCALL_BASE + 100)
#define __NR_syslog (__NR_SYSCALL_BASE + 103)
#define __NR_setitimer (__NR_SYSCALL_BASE + 104)
#define __NR_getitimer (__NR_SYSCALL_BASE + 105)
#define __NR_stat (__NR_SYSCALL_BASE + 106)
#define __NR_lstat (__NR_SYSCALL_BASE + 107)
#define __NR_fstat (__NR_SYSCALL_BASE + 108)
#define __NR_vhangup (__NR_SYSCALL_BASE + 111)
#define __NR_wait4 (__NR_SYSCALL_BASE + 114)
#define __NR_swapoff (__NR_SYSCALL_BASE + 115)
#define __NR_sysinfo (__NR_SYSCALL_BASE + 116)
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