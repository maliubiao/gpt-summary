Response:
Let's break down the thought process for analyzing the provided C header file and generating the comprehensive response.

**1. Understanding the Request:**

The request asks for a detailed analysis of the `fcntl.h` header file within the Android Bionic library. Key requirements include identifying its functions, their relation to Android, implementation details (especially for libc functions), dynamic linker aspects, examples of usage errors, and how Android frameworks/NDK reach this code, culminating in a Frida hook example.

**2. Initial Scan and Keyword Recognition:**

My first pass through the code involved identifying keywords and structures:

* **`#define`:**  This immediately signals constant definitions. I noticed prefixes like `O_`, `F_`, `LOCK_`, indicating flags for file operations.
* **`struct`:** The `f_owner_ex` structure stands out, suggesting something related to file ownership.
* **`#ifndef ... #define ... #endif`:** Standard header file inclusion guards.
* **`#include`:** Inclusion of `bits/flock64.h`, `bits/flock.h`, and `linux/types.h` hints at the file's purpose: managing file control operations, particularly locking.

**3. Categorizing the Definitions:**

I started grouping the `#define` statements based on their prefixes:

* **`O_*`:**  These clearly relate to the `open()` system call flags, defining how a file is opened (read-only, write-only, create, etc.).
* **`F_*`:** These relate to the `fcntl()` system call, dealing with file descriptor manipulation (duplicating, getting/setting flags, locks, ownership).
* **`LOCK_*`:** These are related to file locking mechanisms.

**4. Addressing the Specific Requirements (Iterative Process):**

* **功能列举:**  This was relatively straightforward. I simply listed all the defined constants and the structure. I grouped them logically (open flags, fcntl commands, lock types).

* **与 Android 功能的关系及举例:**  This required connecting the low-level definitions to higher-level Android concepts. I considered:
    * **File System Access:**  Apps need to open, read, and write files. The `O_*` flags are directly used in `open()` calls. I provided the example of opening a file for reading and creating it if it doesn't exist.
    * **Inter-Process Communication (IPC):** File locking is a common mechanism for synchronization. I gave the example of a shared preference file.
    * **Security:** `O_NOFOLLOW` is important to prevent symlink attacks.

* **详细解释 libc 函数的实现:**  This was a crucial part but also tricky, as *this header file doesn't define libc functions*. It defines constants used *by* libc functions. My thought process was:
    * **Identify the relevant system calls:** The definitions clearly map to the `open()` and `fcntl()` system calls.
    * **Explain the *purpose* of these system calls:**  `open()` creates or opens files, `fcntl()` manipulates file descriptors.
    * **Explain how the *constants* are used:**  The `#define` constants are passed as arguments to these system calls to specify the desired behavior. I used `open()` with `O_RDWR | O_CREAT` as an example.
    * **Emphasize that this file is *declarative*, not *implementative*:**  The actual implementation resides in the kernel.

* **Dynamic Linker 功能:** This was also about connecting the dots.
    * **Recognize the Context:** This header is part of Bionic, and Bionic *is* Android's C library, including the dynamic linker.
    * **Identify the Indirect Link:** While this specific file doesn't *directly* involve dynamic linking, the libc functions that *use* these constants are linked into processes.
    * **Illustrate with an SO layout:** I described a typical shared library layout and pointed out how libc (`libc.so`) would be linked.
    * **Explain the Linking Process:** Briefly described how the dynamic linker resolves symbols (like `open`) at runtime.

* **逻辑推理 (假设输入与输出):** For the constants, the "input" is a combination of flags, and the "output" is the integer representation used in system calls. I provided examples.

* **用户或编程常见的使用错误:** I focused on common mistakes when using the `open()` and `fcntl()` system calls with these flags, such as incorrect flag combinations or forgetting error handling.

* **Android Framework/NDK 到达这里的步骤:** I outlined the path from an app using Java APIs or NDK functions down to the system calls, emphasizing the role of the Android Runtime (ART) and the system call interface.

* **Frida Hook 示例:**  This required demonstrating how to intercept calls to `open` and `fcntl` and access the flag arguments. I aimed for a simple but illustrative example.

**5. Language and Formatting:**

Throughout the process, I focused on using clear and concise Chinese, with appropriate technical terminology. I used formatting (bullet points, code blocks) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Perhaps describe the kernel implementation of `open()` and `fcntl()`. **Correction:** The request asked about the *libc* function's implementation. While related, focusing on the system call interface is more accurate given the header file's content.
* **Initial thought:**  Provide very detailed explanations of each flag. **Correction:**  Focus on the most commonly used and important flags and provide a general overview. The request didn't ask for an exhaustive explanation of every single flag.
* **Initial thought:** Directly link this header file to specific dynamic linker mechanisms. **Correction:** This header defines constants. The connection to the dynamic linker is through the libc functions that *use* these constants and are subject to dynamic linking. The explanation needed to be more nuanced.

By following this iterative process of understanding the request, identifying key elements, categorizing information, and addressing specific requirements with relevant examples and explanations, I arrived at the comprehensive response provided earlier. The self-correction aspect helped ensure accuracy and focus on the most relevant information.

这是一个定义了文件控制（fcntl）相关的常量和数据结构的C头文件，它属于Android Bionic库的一部分。这个文件并非实现具体的功能，而是为在用户空间（例如应用程序或库）进行文件操作提供标准化的接口定义。

**功能列举:**

这个头文件定义了以下几种主要类型的常量和结构：

1. **文件打开标志 (Open Flags, 以 `O_` 开头):**
   - `O_RDONLY`: 以只读模式打开文件。
   - `O_WRONLY`: 以只写模式打开文件。
   - `O_RDWR`: 以读写模式打开文件。
   - `O_CREAT`: 如果文件不存在则创建文件。
   - `O_EXCL`: 与 `O_CREAT` 一起使用，如果文件已存在则打开失败。
   - `O_NOCTTY`: 如果打开的是一个终端设备，则不会使其成为调用进程的控制终端。
   - `O_TRUNC`: 如果文件已存在并且以写模式或读写模式打开，则将其长度截断为零。
   - `O_APPEND`: 写入操作将追加到文件末尾。
   - `O_NONBLOCK`: 以非阻塞模式打开文件。
   - `O_DSYNC`: 写入操作会等待数据和元数据都写入磁盘。
   - `O_DIRECT`: 尝试绕过页缓存进行 I/O 操作。
   - `O_LARGEFILE`:  在现代系统中通常不需要显式指定，用于支持大文件。
   - `O_DIRECTORY`:  要求打开的路径必须是一个目录。
   - `O_NOFOLLOW`:  如果路径名是一个符号链接，则打开操作失败。
   - `O_NOATIME`:  不更新文件的最后访问时间。
   - `O_CLOEXEC`:  在执行新的程序后自动关闭该文件描述符。
   - `O_SYNC`:  写入操作会等待数据和所有元数据都写入磁盘 (比 `O_DSYNC` 更严格)。
   - `O_PATH`:  获取一个可以用于其他文件系统操作但不允许直接读写的特殊文件描述符。
   - `O_TMPFILE`:  创建一个未命名的临时文件。
   - `O_NDELAY`: 等同于 `O_NONBLOCK`。
   - `O_ACCMODE`:  用于提取打开模式（`O_RDONLY`、`O_WRONLY`、`O_RDWR`）。

2. **`fcntl()` 命令 (以 `F_` 开头):**
   - `F_DUPFD`: 复制一个文件描述符。
   - `F_GETFD`: 获取文件描述符标志（例如 `FD_CLOEXEC`）。
   - `F_SETFD`: 设置文件描述符标志。
   - `F_GETFL`: 获取文件访问模式和状态标志（例如之前 `open()` 时使用的 `O_` 标志）。
   - `F_SETFL`: 设置文件状态标志（一些 `O_` 标志，例如 `O_APPEND`、`O_NONBLOCK`）。
   - `F_GETLK`, `F_SETLK`, `F_SETLKW`: 获取、设置文件锁（非阻塞和阻塞）。
   - `F_SETOWN`, `F_GETOWN`: 设置或获取接收 SIGIO 和 SIGURG 信号的进程 ID 或进程组 ID。
   - `F_SETSIG`, `F_GETSIG`: 设置或获取用于异步 I/O 通知的信号。
   - `F_GETLK64`, `F_SETLK64`, `F_SETLKW64`:  用于 64 位文件偏移量的文件锁操作（在 32 位系统上定义）。
   - `F_SETOWN_EX`, `F_GETOWN_EX`:  扩展的设置/获取文件所有者信息。
   - `F_GETOWNER_UIDS`: 获取文件所有者的 UID 信息。
   - `F_OFD_GETLK`, `F_OFD_SETLK`, `F_OFD_SETLKW`: 基于打开文件描述符的文件锁操作，避免了路径名竞争。

3. **文件所有者类型 (以 `F_OWNER_` 开头):**
   - `F_OWNER_TID`: 文件所有者是线程 ID。
   - `F_OWNER_PID`: 文件所有者是进程 ID。
   - `F_OWNER_PGRP`: 文件所有者是进程组 ID。

4. **文件锁类型 (以 `F_RDLCK`, `F_WRLCK`, `F_UNLCK`, `LOCK_` 开头):**
   - `F_RDLCK` (`LOCK_SH`): 共享锁（多个进程可以拥有）。
   - `F_WRLCK` (`LOCK_EX`): 排他锁（只有一个进程可以拥有）。
   - `F_UNLCK` (`LOCK_UN`): 解锁。
   - `F_EXLCK`: 等同于 `F_WRLCK`。
   - `F_SHLCK`: 等同于 `F_RDLCK`。
   - `LOCK_NB`: 非阻塞地尝试获取锁。
   - `LOCK_MAND`: 启用强制锁（由内核强制执行）。
   - `LOCK_READ`: 获取读锁。
   - `LOCK_WRITE`: 获取写锁。
   - `LOCK_RW`:  读写锁。

5. **文件描述符标志:**
   - `FD_CLOEXEC`:  与 `F_SETFD` 一起使用，设置执行时关闭标志。

6. **结构体:**
   - `struct f_owner_ex`: 用于扩展的文件所有者信息，包含所有者类型和进程/线程 ID。

**与 Android 功能的关系及举例:**

这个头文件中定义的常量和结构是 Android 操作系统进行文件操作的基础。Android 应用程序和系统服务在进行文件读写、创建、删除、权限控制、进程间同步（通过文件锁）等操作时，都会间接地使用到这些定义。

**举例说明:**

* **打开文件:** 当一个 Android 应用需要读取一个文本文件时，它会调用 `open()` 系统调用，并使用 `O_RDONLY` 标志。如果需要创建文件，则会使用 `O_CREAT` 和 `O_WRONLY` 或 `O_RDWR`。
   ```c
   // NDK 代码示例
   #include <fcntl.h>
   #include <unistd.h>

   int fd = open("/sdcard/test.txt", O_RDWR | O_CREAT, 0660);
   if (fd == -1) {
       // 处理错误
   }
   // ... 进行文件操作 ...
   close(fd);
   ```
   在这个例子中，`O_RDWR` 和 `O_CREAT` 就是在这个头文件中定义的常量。

* **文件锁:**  Android 系统内部，例如在多进程访问共享资源时，可能会使用文件锁来保证数据的一致性。例如，`SharedPreferences` 的底层实现可能使用文件锁来防止并发写入导致数据损坏。
   ```c
   // NDK 代码示例
   #include <fcntl.h>
   #include <unistd.h>

   int fd = open("/data/data/com.example.app/shared_prefs/my_prefs.xml", O_RDWR);
   if (fd != -1) {
       struct flock fl;
       fl.l_type = F_WRLCK;
       fl.l_whence = SEEK_SET;
       fl.l_start = 0;
       fl.l_len = 0;
       int result = fcntl(fd, F_SETLKW, &fl); // 尝试获取写锁，阻塞直到获取
       if (result == 0) {
           // 进行写操作
           fl.l_type = F_UNLCK;
           fcntl(fd, F_SETLK, &fl); // 释放锁
       }
       close(fd);
   }
   ```
   这里 `F_WRLCK` 和 `F_SETLKW` 也是在这个头文件中定义的。

* **非阻塞 I/O:**  在网络编程或其他需要高性能 I/O 的场景中，可能会使用 `O_NONBLOCK` 标志来设置非阻塞的文件描述符。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **不包含任何 libc 函数的实现**。它只是定义了与文件控制相关的常量和数据结构。这些常量会被 libc 提供的系统调用包装函数（例如 `open()`, `fcntl()`, `flock()`) 使用，最终由 Linux 内核来实现具体的功能。

例如：

* **`open()` 函数:** libc 中的 `open()` 函数会将用户提供的路径名和标志（例如 `O_RDONLY`, `O_CREAT`）传递给内核的 `open` 系统调用。内核会根据这些标志来创建或打开文件，并返回一个文件描述符。
* **`fcntl()` 函数:** libc 中的 `fcntl()` 函数会将用户提供的文件描述符、命令（例如 `F_GETFL`, `F_SETLK`）和可选的参数传递给内核的 `fcntl` 系统调用。内核会根据命令执行相应的操作，例如获取或设置文件描述符的标志，或者进行文件锁操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker 的功能。但是，它属于 Bionic 库，而 Bionic 库（特别是 `libc.so`）是所有 Android 应用程序和许多系统进程都需要链接的共享库。

**so 布局样本 (libc.so):**

一个典型的 `libc.so` 的布局可能包含以下部分：

```
.init        # 初始化代码段
.plt         # 程序链接表 (Procedure Linkage Table)，用于延迟绑定
.text        # 代码段，包含 open(), fcntl() 等函数的机器码实现
.fini        # 终止代码段
.rodata      # 只读数据段，包含字符串常量等
.data        # 可读写数据段，包含全局变量等
.bss         # 未初始化数据段
.dynamic     # 动态链接信息
.symtab      # 符号表
.strtab      # 字符串表
.rel.dyn     # 动态重定位表
.rel.plt     # PLT 重定位表
...
```

**链接的处理过程:**

1. **编译时链接:** 当编译一个使用 `open()` 或 `fcntl()` 等函数的 Android 应用程序或共享库时，编译器会生成对这些函数的未解析引用。

2. **加载时链接:** 当 Android 系统启动应用程序或加载共享库时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责解析这些未解析的引用。

3. **符号查找:** dynamic linker 会在应用程序依赖的共享库（包括 `libc.so`）的符号表 (`.symtab`) 中查找 `open` 和 `fcntl` 等符号。

4. **重定位:** 找到符号后，dynamic linker 会修改应用程序或共享库的代码段和数据段中的地址，将对这些函数的未解析引用指向 `libc.so` 中对应的函数实现地址。这个过程称为重定位。

5. **延迟绑定 (Lazy Binding):** 为了提高启动速度，Android 使用延迟绑定。这意味着对外部函数的解析和重定位通常不会在程序启动时立即完成，而是在第一次调用该函数时才进行。PLT 和 GOT (Global Offset Table) 用于实现延迟绑定。

**假设输入与输出 (逻辑推理):**

虽然这个文件定义的是常量，我们可以假设在使用这些常量的函数调用中，输入和输出的关系：

**假设输入:**

* **`open()` 调用:**
    * `pathname`:  "/sdcard/my_file.txt"
    * `flags`: `O_RDWR | O_CREAT`
    * `mode`: `0644`

**预期输出:**

* 如果文件 "/sdcard/my_file.txt" 不存在，则创建一个新的文件，并返回一个表示该文件的文件描述符（一个非负整数）。
* 如果文件存在，则以读写模式打开该文件，并返回一个文件描述符。
* 如果发生错误（例如权限不足），则返回 -1，并设置 `errno` 全局变量指示错误类型。

* **`fcntl()` 调用:**
    * `fd`:  一个有效的文件描述符。
    * `cmd`: `F_GETFL`

**预期输出:**

* 返回一个整数，表示该文件描述符当前的状态标志（例如，打开时使用的 `O_` 标志）。

**用户或者编程常见的使用错误:**

1. **`open()` 时标志组合错误:**
   - 同时使用 `O_RDONLY` 和 `O_WRONLY` 是没有意义的。
   - 忘记使用 `O_CREAT` 创建新文件，导致 `open()` 失败。
   - 没有正确设置 `mode` 参数，导致创建的文件权限不正确。

2. **`fcntl()` 使用错误:**
   - 传递了无效的 `cmd` 参数。
   - 尝试设置某些不可修改的标志。
   - 在没有检查返回值的情况下就假设 `fcntl()` 调用成功。

3. **文件锁使用错误:**
   - 死锁：多个进程互相等待对方释放锁。
   - 忘记释放锁，导致其他进程无法访问资源。
   - 没有正确处理 `fcntl()` 返回的错误，例如 `EAGAIN` 或 `EWOULDBLOCK`（在使用非阻塞锁时）。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java 代码):**
   - 当 Android Framework 中的 Java 代码需要进行文件操作时，例如使用 `FileInputStream`, `FileOutputStream`, `RandomAccessFile` 等类。
   - 这些 Java 类的方法最终会调用到 Android Runtime (ART) 提供的 native 方法。

2. **Android Runtime (ART, Native 代码):**
   - ART 中的 native 方法会通过系统调用接口 (syscall interface) 调用 Linux 内核提供的系统调用。
   - 例如，`FileInputStream.open()` 最终会调用到 `__NR_openat` 系统调用。

3. **Bionic (libc.so):**
   - Bionic 库中的 `open()` 函数是系统调用的包装函数。它会将 Java 层传递下来的参数转换为系统调用所需的格式，并执行 `syscall(__NR_openat, ...)`。
   - `open()` 函数的实现会使用这个头文件中定义的 `O_*` 标志。

4. **Linux Kernel:**
   - Linux 内核接收到 `openat` 系统调用后，会根据传递的标志执行实际的文件打开操作。

**NDK (Native 代码):**

- NDK 开发的 C/C++ 代码可以直接调用 Bionic 提供的标准 C 库函数，例如 `open()`, `fcntl()`, `flock()`。
- 这些函数会直接使用这个头文件中定义的常量。

**Frida Hook 示例:**

可以使用 Frida Hook 拦截对 `openat` 系统调用或 Bionic 的 `open` 函数的调用，来观察传递的标志。

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload:", message['payload'])
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未运行，请先启动应用。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var pathname = args[0].readUtf8String();
        var flags = args[1].toInt();
        console.log("[open] Pathname:", pathname);
        console.log("[open] Flags:", flags, "(" + flags.toString(8) + " in octal)");
        // 可以进一步解析 flags 以查看具体的 O_* 标志
        if (flags & 0x0001) console.log("  O_WRONLY");
        if (flags & 0x0002) console.log("  O_RDWR");
        if (flags & 0x0040) console.log("  O_NONBLOCK");
        // ... 其他标志
    },
    onLeave: function(retval) {
        console.log("[open] Returned FD:", retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "fcntl"), {
    onEnter: function(args) {
        var fd = args[0].toInt();
        var cmd = args[1].toInt();
        console.log("[fcntl] FD:", fd);
        console.log("[fcntl] Command:", cmd);
        // 可以进一步解析 cmd 以查看具体的 F_* 命令
        if (cmd == 0) console.log("  F_DUPFD");
        if (cmd == 3) console.log("  F_GETFL");
        if (cmd == 4) console.log("  F_SETFL");
        // ... 其他命令
        if (cmd == 5 || cmd == 12) { // F_GETLK, F_GETLK64
            var flockPtr = ptr(args[2]);
            console.log("[fcntl] flock struct:", flockPtr.readByteArray(24)); // 读取 flock 结构体
        }
    },
    onLeave: function(retval) {
        console.log("[fcntl] Returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例解释:**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 设备上的目标应用进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "open"), ...)`:**  Hook Bionic 库中的 `open` 函数。
   - **`onEnter`:** 在 `open` 函数被调用时执行。
     - `args[0]`：指向路径名的指针。
     - `args[1]`：包含打开标志的整数。
     - 代码打印路径名和标志的八进制和十进制表示，并尝试解析部分 `O_*` 标志。
   - **`onLeave`:** 在 `open` 函数返回时执行，打印返回的文件描述符。
3. **`Interceptor.attach(Module.findExportByName("libc.so", "fcntl"), ...)`:** Hook Bionic 库中的 `fcntl` 函数。
   - **`onEnter`:** 在 `fcntl` 函数被调用时执行。
     - `args[0]`：文件描述符。
     - `args[1]`：`fcntl` 命令。
     - `args[2]`：可选的参数指针（例如，对于文件锁操作）。
     - 代码打印文件描述符、命令，并尝试解析部分 `F_*` 命令，对于文件锁命令，读取 `flock` 结构体的内容。
   - **`onLeave`:** 在 `fcntl` 函数返回时执行，打印返回值。

运行此 Frida 脚本后，当目标应用执行 `open` 或 `fcntl` 系统调用时，你将会在 Frida 的输出中看到相关的参数信息，从而可以调试和理解这些步骤。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/asm-generic/fcntl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _ASM_GENERIC_FCNTL_H
#define _ASM_GENERIC_FCNTL_H
#include <bits/flock64.h>
#include <bits/flock.h>
#include <linux/types.h>
#define O_ACCMODE 00000003
#define O_RDONLY 00000000
#define O_WRONLY 00000001
#define O_RDWR 00000002
#ifndef O_CREAT
#define O_CREAT 00000100
#endif
#ifndef O_EXCL
#define O_EXCL 00000200
#endif
#ifndef O_NOCTTY
#define O_NOCTTY 00000400
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif
#ifndef O_APPEND
#define O_APPEND 00002000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 00004000
#endif
#ifndef O_DSYNC
#define O_DSYNC 00010000
#endif
#ifndef FASYNC
#define FASYNC 00020000
#endif
#ifndef O_DIRECT
#define O_DIRECT 00040000
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE 00100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 00200000
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 00400000
#endif
#ifndef O_NOATIME
#define O_NOATIME 01000000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif
#ifndef O_SYNC
#define __O_SYNC 04000000
#define O_SYNC (__O_SYNC | O_DSYNC)
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef __O_TMPFILE
#define __O_TMPFILE 020000000
#endif
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#ifndef O_NDELAY
#define O_NDELAY O_NONBLOCK
#endif
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#ifndef F_GETLK
#define F_GETLK 5
#define F_SETLK 6
#define F_SETLKW 7
#endif
#ifndef F_SETOWN
#define F_SETOWN 8
#define F_GETOWN 9
#endif
#ifndef F_SETSIG
#define F_SETSIG 10
#define F_GETSIG 11
#endif
#if __BITS_PER_LONG == 32
#ifndef F_GETLK64
#define F_GETLK64 12
#define F_SETLK64 13
#define F_SETLKW64 14
#endif
#endif
#ifndef F_SETOWN_EX
#define F_SETOWN_EX 15
#define F_GETOWN_EX 16
#endif
#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS 17
#endif
#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38
#define F_OWNER_TID 0
#define F_OWNER_PID 1
#define F_OWNER_PGRP 2
struct f_owner_ex {
  int type;
  __kernel_pid_t pid;
};
#define FD_CLOEXEC 1
#ifndef F_RDLCK
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2
#endif
#ifndef F_EXLCK
#define F_EXLCK 4
#define F_SHLCK 8
#endif
#define LOCK_SH 1
#define LOCK_EX 2
#define LOCK_NB 4
#define LOCK_UN 8
#define LOCK_MAND 32
#define LOCK_READ 64
#define LOCK_WRITE 128
#define LOCK_RW 192
#define F_LINUX_SPECIFIC_BASE 1024
#ifndef HAVE_ARCH_STRUCT_FLOCK
#endif
#endif
```