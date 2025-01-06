Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The core request is to analyze the provided `unistd.handroid` header file from Android's Bionic library. This involves identifying its functions, explaining their purpose, linking them to Android, detailing their implementation (where possible from a header file), discussing dynamic linking aspects, noting potential errors, and outlining how Android frameworks reach this code.

2. **Initial Scan and Categorization:** I'll first read through the header file to get a high-level understanding. I'll notice sections defining constants (like `STDIN_FILENO`), function declarations, and conditional compilation directives. I'll start grouping functions by their apparent purpose: process management (fork, exec), process/thread IDs, user/group IDs, file system operations (open, read, write, link), directory operations (chdir, rmdir), inter-process communication (pipe), memory management (brk, sbrk), and other system calls.

3. **Function-by-Function Analysis:** For each function, I'll perform the following:

    * **Identify the Core Functionality:**  Based on the function name and the provided comments (which are very helpful), I'll describe what the function does. I'll also leverage my knowledge of standard Unix/POSIX functions as most of these have counterparts there.
    * **Android Relevance and Examples:**  I'll consider how each function is used within the Android ecosystem. This often involves thinking about how apps interact with the OS, how system services work, and how the Android runtime operates. I'll try to provide concrete examples. For example, `fork` is used to create new processes, which is fundamental to Android's process model. `setuid` is important for permission management. File operations are used by almost every app.
    * **Implementation Details:** Since this is a header file, I won't have the full C code implementation. However, I can infer some aspects. For instance, I can state that most of these functions are likely wrappers around underlying Linux kernel system calls. I'll mention if a function has Android-specific behavior (like the thread-local nature of some UID/GID setting functions).
    * **Dynamic Linker Considerations:** I'll look for functions related to loading and executing programs (`exec*`). I'll explain how the dynamic linker (`linker64` or `linker`) is involved in resolving symbols and loading shared libraries. I'll need to create a hypothetical shared library layout example to illustrate the linking process.
    * **Common Errors:** Based on my experience and the function's nature, I'll identify common mistakes developers might make. Examples include incorrect arguments to `exec`, forgetting to check return values for errors, using thread-unsafe functions like `chdir` in a multithreaded context, and issues with file permissions in file operations.
    * **Logic and Assumptions:** If a function's behavior involves conditional logic or relies on specific system states, I'll try to explain it with hypothetical inputs and outputs. However, for basic system calls, this isn't always necessary.

4. **Dynamic Linking Deep Dive:** This requires a more detailed explanation. I will:

    * **Explain the Role of the Dynamic Linker:** Describe its responsibility in resolving symbols at runtime.
    * **Provide a Sample SO Layout:** Create a simplified example of a shared object (`.so`) file, highlighting key sections like `.text`, `.data`, `.bss`, `.dynsym`, and `.dynstr`.
    * **Detail the Linking Process:** Explain the steps involved when a program loads a shared library: finding the library, mapping it into memory, resolving symbols (using symbol tables), and relocation.

5. **Android Framework/NDK Integration:**  I'll explain how high-level Android components eventually call these low-level libc functions. I'll trace the path from:

    * **Android Framework (Java/Kotlin):**  Explain how Java/Kotlin code uses JNI to call native code.
    * **NDK (C/C++):**  Show how NDK code directly calls functions in Bionic.
    * **Bionic (libc):**  Demonstrate that the functions in this header are part of Bionic and are the actual implementations being called.

6. **Frida Hooking:**  I'll provide examples of how Frida can be used to intercept and monitor calls to these functions. I'll give specific Frida code snippets that demonstrate how to hook a function, log its arguments and return value.

7. **Structure and Language:**  I'll organize the information logically, using headings and bullet points for clarity. I'll write in clear and concise Chinese, as requested. I'll make sure to explain technical terms where necessary.

8. **Review and Refinement:** After drafting the response, I'll review it for accuracy, completeness, and clarity. I'll ensure that all parts of the original request are addressed. I will double-check examples and code snippets for correctness.

**Self-Correction/Refinement Example during the process:**

* **Initial Thought:** "Just list all the functions and their basic descriptions."
* **Correction:** "The request asks for more detail, specifically Android relevance, implementation details, dynamic linking, errors, and the path from Android frameworks. I need to expand on each function and provide context."
* **Further Refinement:** "For implementation, since it's a header file, I can't provide the C code. I should focus on stating that they are mostly syscall wrappers. For dynamic linking, a concrete example of an SO layout will be much clearer than just a textual explanation."
* **Even Further Refinement (for Frida):** "A simple `console.log` won't be as helpful as showing how to access arguments and the return value in the Frida hook."

By following this structured approach and continuously refining my understanding of the request and the provided code, I can generate a comprehensive and accurate answer.
您好！您提供的是 Android Bionic 库中 `unistd.h` 文件的内容，这个文件是定义了许多与 POSIX 标准相关的系统调用和常量的头文件。由于文件名包含 "handroid"，这表明它是 Android 特定的 `unistd.h` 变体，可能包含了一些 Android 特有的扩展或行为调整。

让我们逐一分析这个文件中的功能：

**1. 功能列举：**

这个头文件定义了大量的函数和宏，主要涵盖以下功能领域：

* **进程控制：**
    * `fork`, `_Fork`, `vfork`: 创建新进程。
    * `execv`, `execvp`, `execvpe`, `execve`, `execl`, `execlp`, `execle`, `fexecve`: 执行新的程序。
    * `_exit`: 立即终止进程。
    * `getpid`, `gettid`, `getppid`: 获取进程和线程 ID。
    * `getpgid`, `setpgid`, `getpgrp`, `setpgrp`, `getsid`, `setsid`: 获取和设置进程组和会话 ID。
    * `nice`: 改变进程的调度优先级。
    * `daemon`: 创建守护进程。

* **用户和组 ID 管理：**
    * `setuid`, `seteuid`, `setreuid`, `setresuid`: 设置用户 ID。
    * `setgid`, `setegid`, `setregid`, `setresgid`: 设置组 ID。
    * `getuid`, `geteuid`, `getgid`, `getegid`, `getgroups`, `getresuid`, `getresgid`: 获取用户和组 ID 信息。
    * `getlogin`, `getlogin_r`: 获取用户名。

* **文件系统操作：**
    * `open`, `close`, `read`, `write`: 基本的文件读写操作（尽管 `open` 未在此文件中直接列出，但 `unistd.h` 通常会通过包含其他头文件或定义相关常量来支持文件操作）。
    * `lseek`, `pread`, `pwrite`: 定位和带偏移量的读写操作。
    * `truncate`, `ftruncate`: 截断文件大小。
    * `link`, `linkat`, `unlink`, `unlinkat`: 创建和删除硬链接。
    * `symlink`, `symlinkat`, `readlink`, `readlinkat`: 创建和读取符号链接。
    * `rename`, `renameat`: 重命名文件（尽管 `rename` 未在此文件中直接列出，但通常与文件操作相关）。
    * `access`, `faccessat`: 检查文件的访问权限。
    * `chdir`, `fchdir`: 改变当前工作目录。
    * `getcwd`: 获取当前工作目录。
    * `rmdir`: 删除目录。
    * `chown`, `fchown`, `fchownat`, `lchown`: 改变文件的所有者和组。
    * `pipe`, `pipe2`: 创建管道。
    * `dup`, `dup2`, `dup3`: 复制文件描述符。
    * `fsync`, `fdatasync`, `sync`, `syncfs`: 将文件数据同步到磁盘。
    * `mkfifo`, `mkfifoat`: 创建 FIFO 文件（尽管 `mkfifo` 未在此文件中直接列出，但通常与文件操作相关）。
    * `mknod`, `mknodat`: 创建特殊文件（尽管 `mknod` 未在此文件中直接列出，但通常与文件操作相关）。
    * `truncate64`, `lseek64`, `pread64`, `pwrite64`, `ftruncate64`: 针对大文件的 64 位版本操作。
    * `copy_file_range`: 在文件描述符之间复制数据范围。
    * `close_range`: 对文件描述符范围执行操作（通常是关闭）。

* **系统信息：**
    * `pathconf`, `fpathconf`: 获取文件或目录的配置限制。
    * `sysconf`: 获取系统配置信息（尽管 `sysconf` 的定义通常在 `<unistd.h>` 或 `<sys/types.h>` 中，这里是通过包含 `bits/sysconf.h` 来间接使用的）。
    * `getpagesize`: 获取系统页大小。
    * `gethostname`, `sethostname`, `getdomainname`, `setdomainname`: 获取和设置主机名和域名。

* **终端 I/O：**
    * `isatty`: 检查文件描述符是否连接到终端。
    * `ttyname`, `ttyname_r`: 获取终端设备名。
    * `tcgetpgrp`, `tcsetpgrp`: 获取和设置终端的前台进程组 ID。

* **其他：**
    * `alarm`, `sleep`, `usleep`, `pause`: 暂停进程执行。
    * `brk`, `sbrk`: 调整进程的数据段大小（用于动态内存分配）。
    * `acct`: 启用或禁用进程记账。
    * `syscall`: 直接进行系统调用。
    * `swab`: 交换内存中的字节。
    * `getentropy`: 获取高质量的随机数据。
    * `lockf`: 对文件区域施加排他锁。

* **常量定义：**
    * `STDIN_FILENO`, `STDOUT_FILENO`, `STDERR_FILENO`: 标准输入、输出、错误的文件描述符。
    * `F_OK`, `X_OK`, `W_OK`, `R_OK`: `access` 函数使用的文件访问权限检查常量。
    * `_PC_*`: `pathconf` 和 `fpathconf` 函数使用的路径名变量常量。

**2. 与 Android 功能的关系及举例：**

这个头文件中的函数是构建 Android 系统的基础。许多 Android 的核心功能都依赖于这些系统调用。

* **进程管理：**
    * **`fork` 和 `exec` 系列函数：** Android 的进程模型是基于 Zygote 的，Zygote 进程通过 `fork` 创建新的应用进程，然后通过 `exec` 加载应用的 Dalvik/ART 虚拟机和应用程序代码。例如，当您启动一个新的 Android 应用时，系统内部会使用 `fork` 和 `execve` 来创建应用的进程。
    * **`getpid` 和 `gettid`：** Android 系统服务（如 `ActivityManagerService`）需要获取进程和线程 ID 来跟踪和管理进程。开发者可以使用 NDK 调用这些函数来了解他们的应用运行在哪个进程和线程中。
    * **`setuid` 和 `setgid`：** Android 使用这些函数来改变进程或线程的用户和组 ID，实现权限隔离。例如，当应用需要访问特定的系统资源时，可能会临时提升权限。在 Android 中，这些函数通常影响调用线程而非整个进程。

* **文件系统操作：**
    * **`open`, `read`, `write`, `close`：**  Android 上的所有文件 I/O 操作最终都会调用这些系统调用。例如，当一个应用保存一个图片到存储卡时，或者读取一个网络请求的响应数据时，都会使用这些函数。
    * **`access`：** 应用可以使用 `access` 来检查文件是否存在或是否具有读写权限。例如，在安装应用时，包管理器会检查 APK 文件的权限。
    * **`chdir` 和 `getcwd`：** 虽然在多线程环境下不推荐使用，但某些系统工具或守护进程可能会使用它们来管理工作目录。
    * **`pipe`：**  Android 的进程间通信机制（IPC）中，管道是一种基本的方式。例如，`adb shell` 命令的执行可能涉及到管道的使用。

* **系统信息：**
    * **`getpagesize`：** Android 的内存管理系统会使用页大小信息来管理内存映射。
    * **`gethostname` 和 `sethostname`：**  虽然在移动设备上不常用，但在某些网络相关的场景下可能会用到。

**3. libc 函数的实现解释：**

`unistd.h` 文件本身只是头文件，包含了函数的声明。这些函数的实际实现位于 Bionic 库的 C 源代码文件中（通常在 `bionic/libc/src/unistd` 目录下）。

大多数 `unistd.h` 中声明的函数都是对 Linux 内核系统调用的封装。当程序调用这些函数时，Bionic 库会将参数按照系统调用的约定进行设置，然后通过软中断（例如 ARM 架构上的 `svc` 指令，或 x86 架构上的 `int 0x80` 或 `syscall` 指令）切换到内核态。内核接收到系统调用请求后，会执行相应的内核代码，并将结果返回给用户态的 Bionic 库函数，最后 Bionic 库函数再将结果返回给调用者。

例如，`read` 函数的实现大致流程如下：

1. 用户程序调用 `read(fd, buf, count)`。
2. Bionic 库中的 `read` 函数将文件描述符 `fd`、缓冲区地址 `buf` 和读取字节数 `count` 等参数传递给底层的系统调用接口。
3. Bionic 库执行系统调用指令，陷入内核态。
4. Linux 内核接收到 `read` 系统调用请求。
5. 内核根据文件描述符 `fd` 找到对应的文件对象。
6. 内核从文件中读取最多 `count` 个字节的数据，并将数据拷贝到用户提供的缓冲区 `buf` 中。
7. 内核返回实际读取的字节数（或错误码）。
8. Bionic 库中的 `read` 函数接收到内核的返回值，并将其返回给用户程序。

对于一些不直接对应到单一系统调用的函数，例如 `daemon`，Bionic 库会在用户态实现其逻辑（例如，`fork`、`setsid`、关闭文件描述符等操作的组合）。

**4. 涉及 dynamic linker 的功能：**

这里涉及 dynamic linker 的主要功能是 `exec` 系列函数。`exec` 函数族用于加载并执行新的程序。当调用 `exec` 函数时，操作系统会执行以下步骤：

1. **查找可执行文件：** 根据提供的路径或文件名在文件系统中查找可执行文件。
2. **加载器 (Loader) 的介入：** 内核识别出要执行的是一个动态链接的可执行文件，并将控制权交给动态链接器（在 Android 上通常是 `/system/bin/linker` 或 `/system/bin/linker64`）。
3. **加载共享库：** 动态链接器会解析可执行文件的头部信息，找到其依赖的共享库（`.so` 文件）。然后，它会在预定义路径（如 `/system/lib`, `/vendor/lib`, 应用私有库目录等）中查找这些共享库。
4. **内存映射：** 找到的共享库会被映射到进程的地址空间中。为了节省内存，相同的共享库在多个进程中通常会共享代码段（text segment）。
5. **符号解析和重定位：** 动态链接器会解析可执行文件和共享库中的符号表。当可执行文件或共享库中引用了其他模块的函数或变量时，动态链接器会找到这些符号的实际地址，并更新相应的代码或数据，这个过程称为重定位。例如，如果一个应用调用了 `libc.so` 中的 `malloc` 函数，动态链接器会将 `malloc` 的实际地址填入调用指令中。

**so 布局样本：**

一个典型的共享库 (`.so`) 文件布局大致如下：

```
ELF Header:
  Magic number
  Class (32-bit or 64-bit)
  Endianness
  ...
Program Headers:
  LOAD segment (代码段，可执行指令)
    Offset: ...
    Virtual Address: ...
    Physical Address: ...
    File Size: ...
    Memory Size: ...
    Flags: R-E (Read, Execute)
  LOAD segment (数据段，已初始化数据)
    Offset: ...
    Virtual Address: ...
    Physical Address: ...
    File Size: ...
    Memory Size: ...
    Flags: RW- (Read, Write)
  DYNAMIC segment (动态链接信息)
    Tag: DT_NEEDED, Value: 指向依赖的共享库名称的字符串
    Tag: DT_SYMTAB, Value: 符号表的地址
    Tag: DT_STRTAB, Value: 字符串表的地址
    Tag: DT_PLTREL, Value: PLT 重定位入口类型
    ...
Section Headers:
  .text (代码段)
    Address: ...
    Size: ...
  .rodata (只读数据段)
    Address: ...
    Size: ...
  .data (已初始化数据段)
    Address: ...
    Size: ...
  .bss (未初始化数据段)
    Address: ...
    Size: ...
  .dynsym (动态符号表)
    ...
  .dynstr (动态字符串表)
    ...
  .plt (Procedure Linkage Table, 过程链接表)
    ...
  .got (Global Offset Table, 全局偏移表)
    ...
  ...
```

**链接的处理过程：**

1. **加载时重定位 (Load-time Relocation)：**  在程序启动时，动态链接器会遍历可执行文件和所有加载的共享库的重定位表 (`.rel.dyn` 或 `.rela.dyn`)。对于每个需要重定位的条目，动态链接器会查找引用的符号在哪个共享库中定义，并将其运行时地址写入到相应的内存位置（例如，GOT 条目）。
2. **延迟绑定 (Lazy Binding)：**  为了优化启动性能，Android (以及其他一些系统) 默认使用延迟绑定。这意味着对于一些函数调用，最初并不会立即解析其地址。而是通过 PLT 和 GOT 表的机制，在第一次调用该函数时，才会触发动态链接器去解析并填充 GOT 表项。后续对该函数的调用将直接通过 GOT 表找到目标地址，避免了重复的符号查找和重定位。

**5. 逻辑推理的假设输入与输出：**

大多数 `unistd.h` 中的函数直接对应系统调用，其行为由内核决定，相对确定。但有些函数涉及到一些逻辑处理。

* **`access(path, mode)`：**
    * **假设输入：** `path = "/sdcard/Pictures/my_image.jpg"`, `mode = R_OK | W_OK`
    * **输出：**
        * 如果用户拥有该文件的读写权限，返回 `0`。
        * 如果文件不存在或用户没有读写权限，返回 `-1` 并设置 `errno` 为相应的错误码（如 `ENOENT` 或 `EACCES`）。

* **`pipe(fds)`：**
    * **假设输入：** `int fds[2]; pipe(fds);`
    * **输出：**
        * 成功时，返回 `0`，`fds[0]` 是管道的读端文件描述符，`fds[1]` 是管道的写端文件描述符。
        * 失败时，返回 `-1` 并设置 `errno`。

**6. 用户或编程常见的使用错误：**

* **忘记检查返回值：** 大多数 `unistd.h` 中的函数在出错时会返回 `-1` 并设置全局变量 `errno`。程序员必须检查返回值并根据 `errno` 的值来处理错误。例如，如果 `open` 返回 `-1`，没有检查 `errno` 就直接使用返回的文件描述符会导致程序崩溃或产生未定义行为。
* **在多线程环境中使用线程不安全函数：** 一些函数（如 `chdir`）会影响整个进程的状态，在多线程环境下使用可能导致竞争条件和意外行为。Android 的 Bionic 库对某些函数（如 `setuid` 和 `setgid`）进行了修改，使其仅影响调用线程，但这并不是所有函数都如此。
* **`exec` 函数族的使用不当：**
    * **路径错误：** 提供的可执行文件路径不正确。
    * **参数错误：** 传递给新程序的参数列表格式不正确（例如，`argv` 必须以 `NULL` 结尾）。
    * **权限问题：** 没有执行新程序的权限。
* **文件操作权限不足：** 尝试读取或写入没有相应权限的文件。
* **文件描述符泄漏：** 打开文件后忘记关闭，导致系统资源耗尽。
* **信号处理不当：**  某些系统调用可能会被信号中断（返回 `-1` 并设置 `errno` 为 `EINTR`）。应该使用 `TEMP_FAILURE_RETRY` 宏或类似机制来处理这种情况。

**7. Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤：**

* **Android Framework (Java/Kotlin) -> JNI -> NDK (C/C++) -> Bionic (libc):**

1. **Android Framework 层：**  Java 或 Kotlin 代码通常通过 Android SDK 提供的类和方法进行系统调用。例如，`java.io.File` 类的方法最终会调用底层的本地方法。
2. **JNI (Java Native Interface)：**  当需要执行底层操作时，Framework 代码会通过 JNI 调用 NDK 编写的 C/C++ 代码。例如，`FileInputStream.read()` 方法的实现会调用一个 native 方法。
3. **NDK 层：**  NDK 代码中可以直接调用 Bionic 库提供的函数，包括 `unistd.h` 中声明的函数。例如，一个使用 C++ 编写的音视频解码器可能会调用 `open`, `read`, `write` 等函数来处理文件或网络数据。
4. **Bionic (libc) 层：**  NDK 代码调用的 `unistd.h` 中的函数会直接链接到 Bionic 库的实现。

**Frida Hook 示例：**

假设我们要 hook `open` 函数，查看 Java 代码打开的文件路径。

```python
import frida
import sys

package_name = "your.android.app"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message from script: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        var mode = args[2] ? args[2].toInt() : -1;
        send({
            "type": "open",
            "path": path,
            "flags": flags,
            "mode": mode
        });
        console.log("Opening file:", path, "flags:", flags, "mode:", mode);
    },
    onLeave: function(retval) {
        console.log("open returned:", retval.toInt());
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释：**

1. **`frida.get_usb_device().attach(package_name)`：** 连接到目标 Android 设备上的指定应用进程。
2. **`Module.findExportByName("libc.so", "open")`：** 在 `libc.so` 库中查找 `open` 函数的地址。
3. **`Interceptor.attach(...)`：**  拦截对 `open` 函数的调用。
4. **`onEnter`：** 在 `open` 函数执行之前调用。
    * `args[0]`：指向文件路径字符串的指针。
    * `args[1]`：`open` 函数的 flags 参数。
    * `args[2]`：`open` 函数的 mode 参数（可选）。
    * `Memory.readUtf8String(args[0])`：读取文件路径字符串。
    * `send(...)`：将信息发送回 Frida 主机。
    * `console.log(...)`：在目标进程的控制台输出信息。
5. **`onLeave`：** 在 `open` 函数执行之后调用。
    * `retval`：`open` 函数的返回值（文件描述符或错误码）。

**运行步骤：**

1. 确保你的 Android 设备已连接并通过 `adb` 可访问。
2. 安装 Frida 和 `frida-tools`。
3. 将上述 Python 脚本保存为 `hook_open.py`，并将 `your.android.app` 替换为你要监控的应用的包名。
4. 运行脚本：`python hook_open.py`
5. 在 Android 设备上操作该应用，触发文件打开操作。
6. Frida 会拦截 `open` 函数的调用，并在你的终端上打印出打开的文件路径、flags、mode 以及返回值。

这个示例演示了如何使用 Frida 来 hook Bionic 库中的函数，从而观察 Android Framework 或 NDK 代码如何最终调用到这些底层函数。你可以类似地 hook 其他 `unistd.h` 中的函数来调试不同的系统调用过程。

希望以上详细的解释能够帮助您理解 `bionic/libc/include/unistd.handroid` 文件的功能及其在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/include/unistd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

#include <sys/cdefs.h>

#include <stddef.h>
#include <sys/types.h>
#include <sys/select.h>

#include <bits/fcntl.h>
#include <bits/getentropy.h>
#include <bits/getopt.h>
#include <bits/ioctl.h>
#include <bits/lockf.h>
#include <bits/posix_limits.h>
#include <bits/seek_constants.h>
#include <bits/sysconf.h>

__BEGIN_DECLS

#define STDIN_FILENO	0
#define STDOUT_FILENO	1
#define STDERR_FILENO	2

#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

#define _PC_FILESIZEBITS 0
#define _PC_LINK_MAX 1
#define _PC_MAX_CANON 2
#define _PC_MAX_INPUT 3
#define _PC_NAME_MAX 4
#define _PC_PATH_MAX 5
#define _PC_PIPE_BUF 6
#define _PC_2_SYMLINKS 7
#define _PC_ALLOC_SIZE_MIN 8
#define _PC_REC_INCR_XFER_SIZE 9
#define _PC_REC_MAX_XFER_SIZE 10
#define _PC_REC_MIN_XFER_SIZE 11
#define _PC_REC_XFER_ALIGN 12
#define _PC_SYMLINK_MAX 13
#define _PC_CHOWN_RESTRICTED 14
#define _PC_NO_TRUNC 15
#define _PC_VDISABLE 16
#define _PC_ASYNC_IO 17
#define _PC_PRIO_IO 18
#define _PC_SYNC_IO 19

extern char* _Nullable * _Nullable environ;

__noreturn void _exit(int __status);

/**
 * [fork(2)](https://man7.org/linux/man-pages/man2/fork.2.html) creates a new
 * process. fork() runs any handlers set by pthread_atfork().
 *
 * Returns 0 in the child, the pid of the child in the parent,
 * and returns -1 and sets `errno` on failure.
 */
pid_t fork(void);

/**
 * _Fork() creates a new process. _Fork() differs from fork() in that it does
 * not run any handlers set by pthread_atfork(). In addition to any user-defined
 * ones, bionic uses pthread_atfork() handlers to ensure consistency of its own
 * state, so the child should only call
 * [POSIX async-safe](https://man7.org/linux/man-pages/man7/signal-safety.7.html)
 * functions.
 *
 * Returns 0 in the child, the pid of the child in the parent,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 35.
 */

#if __BIONIC_AVAILABILITY_GUARD(35)
pid_t _Fork(void) __INTRODUCED_IN(35);
#endif /* __BIONIC_AVAILABILITY_GUARD(35) */


/**
 * [vfork(2)](https://man7.org/linux/man-pages/man2/vfork.2.html) creates a new
 * process. vfork() differs from fork() in that it does not run any handlers
 * set by pthread_atfork(), and the parent is suspended until the child calls
 * exec() or exits.
 *
 * Returns 0 in the child, the pid of the child in the parent,
 * and returns -1 and sets `errno` on failure.
 */
pid_t vfork(void) __returns_twice;

/**
 * [getpid(2)](https://man7.org/linux/man-pages/man2/getpid.2.html) returns
 * the caller's process ID.
 *
 * Returns the caller's process ID.
 */
pid_t  getpid(void);

/**
 * [gettid(2)](https://man7.org/linux/man-pages/man2/gettid.2.html) returns
 * the caller's thread ID.
 *
 * Returns the caller's thread ID.
 */
pid_t  gettid(void);

pid_t  getpgid(pid_t __pid);
int    setpgid(pid_t __pid, pid_t __pgid);
pid_t  getppid(void);
pid_t  getpgrp(void);
int    setpgrp(void);
pid_t  getsid(pid_t __pid);
pid_t  setsid(void);

int execv(const char* _Nonnull __path, char* _Nullable const* _Nullable __argv);
int execvp(const char* _Nonnull __file, char* _Nullable const* _Nullable __argv);
int execvpe(const char* _Nonnull __file, char* _Nullable const* _Nullable __argv, char* _Nullable const* _Nullable __envp);
int execve(const char* _Nonnull __file, char* _Nullable const* _Nullable __argv, char* _Nullable const* _Nullable __envp);
int execl(const char* _Nonnull __path, const char* _Nullable __arg0, ...) __attribute__((__sentinel__));
int execlp(const char* _Nonnull __file, const char* _Nullable __arg0, ...) __attribute__((__sentinel__));
int execle(const char* _Nonnull __path, const char* _Nullable __arg0, ... /*,  char* const* __envp */)
    __attribute__((__sentinel__(1)));

#if __BIONIC_AVAILABILITY_GUARD(28)
int fexecve(int __fd, char* _Nullable const* _Nullable __argv, char* _Nullable const* _Nullable __envp) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


int nice(int __incr);

/**
 * [setegid(2)](https://man7.org/linux/man-pages/man2/setegid.2.html) sets
 * the effective group ID.
 *
 * On Android, this function only affects the calling thread, not all threads
 * in the process.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int setegid(gid_t __gid);

/**
 * [seteuid(2)](https://man7.org/linux/man-pages/man2/seteuid.2.html) sets
 * the effective user ID.
 *
 * On Android, this function only affects the calling thread, not all threads
 * in the process.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int seteuid(uid_t __uid);

/**
 * [setgid(2)](https://man7.org/linux/man-pages/man2/setgid.2.html) sets
 * the group ID.
 *
 * On Android, this function only affects the calling thread, not all threads
 * in the process.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int setgid(gid_t __gid);

/**
 * [setregid(2)](https://man7.org/linux/man-pages/man2/setregid.2.html) sets
 * the real and effective group IDs (use -1 to leave an ID unchanged).
 *
 * On Android, this function only affects the calling thread, not all threads
 * in the process.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int setregid(gid_t __rgid, gid_t __egid);

/**
 * [setresgid(2)](https://man7.org/linux/man-pages/man2/setresgid.2.html) sets
 * the real, effective, and saved group IDs (use -1 to leave an ID unchanged).
 *
 * On Android, this function only affects the calling thread, not all threads
 * in the process.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int setresgid(gid_t __rgid, gid_t __egid, gid_t __sgid);

/**
 * [setresuid(2)](https://man7.org/linux/man-pages/man2/setresuid.2.html) sets
 * the real, effective, and saved user IDs (use -1 to leave an ID unchanged).
 *
 * On Android, this function only affects the calling thread, not all threads
 * in the process.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int setresuid(uid_t __ruid, uid_t __euid, uid_t __suid);

/**
 * [setreuid(2)](https://man7.org/linux/man-pages/man2/setreuid.2.html) sets
 * the real and effective group IDs (use -1 to leave an ID unchanged).
 *
 * On Android, this function only affects the calling thread, not all threads
 * in the process.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int setreuid(uid_t __ruid, uid_t __euid);

/**
 * [setuid(2)](https://man7.org/linux/man-pages/man2/setuid.2.html) sets
 * the user ID.
 *
 * On Android, this function only affects the calling thread, not all threads
 * in the process.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int setuid(uid_t __uid);

uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int getgroups(int __size, gid_t* _Nullable __list);
int setgroups(size_t __size, const gid_t* _Nullable __list);
int getresuid(uid_t* _Nonnull __ruid, uid_t* _Nonnull __euid, uid_t* _Nonnull __suid);
int getresgid(gid_t* _Nonnull __rgid, gid_t* _Nonnull __egid, gid_t* _Nonnull __sgid);
char* _Nullable getlogin(void);

#if __BIONIC_AVAILABILITY_GUARD(28)
int getlogin_r(char* _Nonnull __buffer, size_t __buffer_size) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


long fpathconf(int __fd, int __name);
long pathconf(const char* _Nonnull __path, int __name);

int access(const char* _Nonnull __path, int __mode);
int faccessat(int __dirfd, const char* _Nonnull __path, int __mode, int __flags);
int link(const char* _Nonnull __old_path, const char* _Nonnull __new_path);
int linkat(int __old_dir_fd, const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path, int __flags);
int unlink(const char* _Nonnull __path);
int unlinkat(int __dirfd, const char* _Nonnull __path, int __flags);

/**
 * [chdir(2)](https://man7.org/linux/man-pages/man2/chdir.2.html) changes
 * the current working directory to the given path.
 *
 * This function affects all threads in the process, so is generally a bad idea
 * on Android where most code will be running in a multi-threaded context.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int chdir(const char* _Nonnull __path);

/**
 * [fchdir(2)](https://man7.org/linux/man-pages/man2/chdir.2.html) changes
 * the current working directory to the given fd.
 *
 * This function affects all threads in the process, so is generally a bad idea
 * on Android where most code will be running in a multi-threaded context.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int fchdir(int __fd);

int rmdir(const char* _Nonnull __path);
int pipe(int __fds[_Nonnull 2]);
#if defined(__USE_GNU)
int pipe2(int __fds[_Nonnull 2], int __flags);
#endif
int chroot(const char* _Nonnull __path);
int symlink(const char* _Nonnull __old_path, const char* _Nonnull __new_path);
int symlinkat(const char* _Nonnull __old_path, int __new_dir_fd, const char* _Nonnull __new_path);
ssize_t readlink(const char* _Nonnull __path, char* _Nonnull __buf, size_t __buf_size);
ssize_t readlinkat(int __dir_fd, const char* _Nonnull __path, char* _Nonnull __buf, size_t __buf_size);
int chown(const char* _Nonnull __path, uid_t __owner, gid_t __group);
int fchown(int __fd, uid_t __owner, gid_t __group);
int fchownat(int __dir_fd, const char* _Nonnull __path, uid_t __owner, gid_t __group, int __flags);
int lchown(const char* _Nonnull __path, uid_t __owner, gid_t __group);
char* _Nullable getcwd(char* _Nullable __buf, size_t __size);

void sync(void);
#if defined(__USE_GNU)

#if __BIONIC_AVAILABILITY_GUARD(28)
int syncfs(int __fd) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

#endif

int close(int __fd);

/**
 * [read(2)](https://man7.org/linux/man-pages/man2/read.2.html) reads
 * up to `__count` bytes from file descriptor `__fd` into `__buf`.
 *
 * Note: `__buf` is not normally nullable, but may be null in the
 * special case of a zero-length read(), which while not generally
 * useful may be meaningful to some device drivers.
 *
 * Returns the number of bytes read on success, and returns -1 and sets `errno` on failure.
 */
ssize_t read(int __fd, void* __BIONIC_COMPLICATED_NULLNESS __buf, size_t __count);

/**
 * [write(2)](https://man7.org/linux/man-pages/man2/write.2.html) writes
 * up to `__count` bytes to file descriptor `__fd` from `__buf`.
 *
 * Note: `__buf` is not normally nullable, but may be null in the
 * special case of a zero-length write(), which while not generally
 * useful may be meaningful to some device drivers.
 *
 * Returns the number of bytes written on success, and returns -1 and sets `errno` on failure.
 */
ssize_t write(int __fd, const void* __BIONIC_COMPLICATED_NULLNESS __buf, size_t __count);

int dup(int __old_fd);
int dup2(int __old_fd, int __new_fd);
int dup3(int __old_fd, int __new_fd, int __flags);
int fsync(int __fd);
int fdatasync(int __fd);

/* See https://android.googlesource.com/platform/bionic/+/main/docs/32-bit-abi.md */
#if defined(__USE_FILE_OFFSET64)
int truncate(const char* _Nonnull __path, off_t __length) __RENAME(truncate64);
off_t lseek(int __fd, off_t __offset, int __whence) __RENAME(lseek64);
ssize_t pread(int __fd, void* _Nonnull __buf, size_t __count, off_t __offset) __RENAME(pread64);
ssize_t pwrite(int __fd, const void* _Nonnull __buf, size_t __count, off_t __offset) __RENAME(pwrite64);
int ftruncate(int __fd, off_t __length) __RENAME(ftruncate64);
#else
int truncate(const char* _Nonnull __path, off_t __length);
off_t lseek(int __fd, off_t __offset, int __whence);
ssize_t pread(int __fd, void* _Nonnull __buf, size_t __count, off_t __offset);
ssize_t pwrite(int __fd, const void* _Nonnull __buf, size_t __count, off_t __offset);
int ftruncate(int __fd, off_t __length);
#endif

int truncate64(const char* _Nonnull __path, off64_t __length);
off64_t lseek64(int __fd, off64_t __offset, int __whence);
ssize_t pread64(int __fd, void* _Nonnull __buf, size_t __count, off64_t __offset);
ssize_t pwrite64(int __fd, const void* _Nonnull __buf, size_t __count, off64_t __offset);
int ftruncate64(int __fd, off64_t __length);

int pause(void);
unsigned int alarm(unsigned int __seconds);
unsigned int sleep(unsigned int __seconds);
int usleep(useconds_t __microseconds);

int gethostname(char* _Nonnull _buf, size_t __buf_size);

#if __BIONIC_AVAILABILITY_GUARD(23)
int sethostname(const char* _Nonnull __name, size_t __n) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


int brk(void* _Nonnull __addr);
void* _Nullable sbrk(ptrdiff_t __increment);

int isatty(int __fd);
char* _Nullable ttyname(int __fd);
int ttyname_r(int __fd, char* _Nonnull __buf, size_t __buf_size);

int acct(const char* _Nullable __path);

/**
 * [getpagesize(2)](https://man7.org/linux/man-pages/man2/getpagesize.2.html)
 * returns the system's page size. This is slightly faster than going via
 * sysconf(), and avoids the linear search in getauxval().
 *
 * Returns the system's page size in bytes.
 */
int getpagesize(void) __attribute_const__;

long syscall(long __number, ...);

int daemon(int __no_chdir, int __no_close);

#if defined(__arm__)
/**
 * New code should use __builtin___clear_cache() instead, which works on
 * all architectures.
 */
int cacheflush(long __addr, long __nbytes, long __cache);
#endif

pid_t tcgetpgrp(int __fd);
int tcsetpgrp(int __fd, pid_t __pid);

/* Used to retry syscalls that can return EINTR. */
#define TEMP_FAILURE_RETRY(exp) ({         \
    __typeof__(exp) _rc;                   \
    do {                                   \
        _rc = (exp);                       \
    } while (_rc == -1 && errno == EINTR); \
    _rc; })


#if __BIONIC_AVAILABILITY_GUARD(26)
int getdomainname(char* _Nonnull __buf, size_t __buf_size) __INTRODUCED_IN(26);
int setdomainname(const char* _Nonnull __name, size_t __n) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


/**
 * [copy_file_range(2)](https://man7.org/linux/man-pages/man2/copy_file_range.2.html) copies
 * a range of data from one file descriptor to another.
 *
 * Available since API level 34.
 *
 * Returns the number of bytes copied on success, and returns -1 and sets
 * `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(34)
ssize_t copy_file_range(int __fd_in, off64_t* _Nullable __off_in, int __fd_out, off64_t* _Nullable __off_out, size_t __length, unsigned int __flags) __INTRODUCED_IN(34);
#endif /* __BIONIC_AVAILABILITY_GUARD(34) */


#if __ANDROID_API__ >= 28
void swab(const void* _Nonnull __src, void* _Nonnull __dst, ssize_t __byte_count) __INTRODUCED_IN(28);
#endif

/**
 * [close_range(2)](https://man7.org/linux/man-pages/man2/close_range.2.html)
 * performs an action (which depends on value of flags) on an inclusive range
 * of file descriptors.
 *
 * Available since API level 34.
 *
 * Note: there is no emulation on too old kernels, hence this will fail with
 * -1/ENOSYS on pre-5.9 kernels, -1/EINVAL for unsupported flags.  In particular
 * CLOSE_RANGE_CLOEXEC requires 5.11, though support was backported to Android
 * Common Kernel 5.10-T.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */

#if __BIONIC_AVAILABILITY_GUARD(34)
int close_range(unsigned int __min_fd, unsigned int __max_fd, int __flags) __INTRODUCED_IN(34);
#endif /* __BIONIC_AVAILABILITY_GUARD(34) */


#if defined(__BIONIC_INCLUDE_FORTIFY_HEADERS)
#define _UNISTD_H_
#include <bits/fortify/unistd.h>
#undef _UNISTD_H_
#endif

__END_DECLS

#include <android/legacy_unistd_inlines.h>

"""

```