Response:
Let's break down the thought process to generate the comprehensive answer about `bionic/libc/bionic/fcntl.cpp`.

**1. Understanding the Request:**

The core request is to analyze a specific C++ file within Android's Bionic library (`fcntl.cpp`). The user wants to understand its functionality, its relationship to Android, implementation details, dynamic linking aspects, potential errors, and how it's reached from higher levels, along with a debugging example. The request emphasizes a detailed explanation in Chinese.

**2. Initial Analysis of the Code:**

The first step is to carefully read the provided code snippet. Key observations are:

* **Includes:** It includes `stdarg.h`, `fcntl.h`, `private/bionic_fdtrack.h`, and `private/bionic_fortify.h`. These give hints about the file's purpose (handling file control operations, file descriptor tracking, and security/robustness checks).
* **External Declarations:** `extern "C" int __fcntl(int fd, int cmd, ...);` and `extern "C" int __fcntl64(int, int, ...);` indicate that this `fcntl.cpp` is a wrapper around the actual system calls. The presence of both `__fcntl` and `__fcntl64` suggests a distinction between 32-bit and 64-bit systems, especially regarding structure sizes (like `flock`).
* **`fcntl` Function:** This is the main function, which takes a file descriptor (`fd`), a command (`cmd`), and potentially variable arguments.
* **Variable Arguments (`va_list`):**  The use of `va_list` confirms that `fcntl` can take a variable number of arguments, as expected for a function that handles various `fcntl` commands.
* **Platform-Specific Logic (`#ifdef __LP64__`):** The code distinguishes between 64-bit (`__LP64__`) and 32-bit architectures. 64-bit uses `__fcntl` directly, while 32-bit uses `__fcntl64`.
* **`F_SETFD` Check:**  There's a specific check for `F_SETFD` to ensure only `FD_CLOEXEC` is used. This hints at a security or policy enforcement within Android's Bionic.
* **File Descriptor Tracking (`FDTRACK_CREATE_NAME`):**  The code calls `FDTRACK_CREATE_NAME` for `F_DUPFD` and `F_DUPFD_CLOEXEC`, indicating a mechanism to track newly duplicated file descriptors.
* **Fortification (`__fortify_fatal`):** The call to `__fortify_fatal` suggests runtime checks for potentially dangerous usage patterns, enhancing security.

**3. Structuring the Answer:**

Based on the request and the code analysis, a logical structure for the answer emerges:

* **功能列举 (Function Listing):** Directly address the request to list the functionalities.
* **与 Android 功能的关系 (Relationship to Android):** Explain how `fcntl` fits into the Android ecosystem with concrete examples.
* **libc 函数的实现 (Implementation of libc Functions):**  Detail how the `fcntl` function is implemented, focusing on the platform differences and the purpose of the wrapper.
* **Dynamic Linker 功能 (Dynamic Linker Functionality):** Explain the role of the dynamic linker in providing the underlying `__fcntl` and `__fcntl64` system calls. Include an SO layout and the linking process.
* **逻辑推理 (Logical Deduction):** Present an example with input and output to illustrate `fcntl`'s behavior.
* **常见使用错误 (Common Usage Errors):** Provide examples of typical programming mistakes when using `fcntl`.
* **Android Framework/NDK 如何到达这里 (How Android Framework/NDK Reaches Here):**  Explain the call stack from higher levels to the `fcntl` implementation. Include a Frida hook example.

**4. Filling in the Details:**

Now, systematically flesh out each section:

* **功能:**  List the core functionalities based on the code and the general purpose of `fcntl`.
* **与 Android 功能的关系:**  Think about common Android scenarios involving file operations (e.g., opening files, creating processes, network sockets) and how `fcntl` plays a role.
* **libc 函数的实现:** Explain the wrapper nature of the `fcntl` function, the platform-specific calls to `__fcntl` and `__fcntl64`, and the meaning of the `F_SETFD` check and file descriptor tracking.
* **Dynamic Linker 功能:**  Explain that `__fcntl` and `__fcntl64` are system calls provided by the kernel. The dynamic linker's role is to resolve these symbols. Create a simple SO layout and explain the linking process (symbol resolution, relocation).
* **逻辑推理:**  Choose a simple `fcntl` command like `F_GETFD` or `F_DUPFD` and provide a clear input and expected output.
* **常见使用错误:** Focus on common mistakes like incorrect flag usage, forgetting error handling, and issues with `FD_CLOEXEC`.
* **Android Framework/NDK 如何到达这里:** Start with a high-level Android API (e.g., Java `File`, NDK `open`) and trace the call path down to the Bionic `fcntl`. Provide a concrete Frida hook example targeting the `fcntl` function.

**5. Refinement and Language:**

Review the entire answer for clarity, accuracy, and completeness. Ensure the language is clear and easy to understand, especially for a Chinese-speaking audience. Use appropriate technical terms and explain them if necessary. Pay attention to formatting and organization to make the answer readable. For instance, using bullet points, code blocks, and headings helps.

**Self-Correction/Improvements During the Process:**

* **Initial thought:**  Maybe directly jump into the implementation details.
* **Correction:** Realized it's better to start with the high-level functionalities before diving into the specifics.
* **Initial thought:** Focus heavily on the technical details of `__fcntl` and `__fcntl64`.
* **Correction:**  Remembered the user also asked about the *relationship* to Android and practical examples, so added more context.
* **Initial thought:**  Provide a very complex Frida hook.
* **Correction:** Kept the Frida hook simple and focused on demonstrating how to intercept the `fcntl` call.
* **Initial thought:** Just describe the dynamic linker's role abstractly.
* **Correction:**  Added a concrete SO layout and explained the linking steps to make it more tangible.

By following these steps, iteratively refining the answer, and considering the user's request, the comprehensive and informative response can be generated.
好的，让我们详细分析一下 `bionic/libc/bionic/fcntl.cpp` 这个文件。

**文件功能列举:**

这个 `fcntl.cpp` 文件在 Android 的 Bionic 库中，其核心功能是提供标准 C 库函数 `fcntl` 的实现。`fcntl` 函数本身是一个非常底层的系统调用接口，用于对已打开的文件描述符执行各种控制操作。 具体来说，这个文件中的 `fcntl` 函数实现了以下功能：

1. **作为 `fcntl` 系统调用的用户空间封装:** 它接收用户程序传递的参数 (文件描述符 `fd`，命令 `cmd` 以及可选的参数 `arg`)。
2. **处理 32 位和 64 位架构的差异:**  根据编译时定义的宏 `__LP64__`，它会选择调用不同的底层系统调用函数：
   - **64 位架构 (`__LP64__` 定义):** 调用 `__fcntl`。
   - **32 位架构 (非 `__LP64__`):** 调用 `__fcntl64`。 这是因为在 32 位系统中，某些 `fcntl` 命令 (如涉及到 `struct flock`) 需要使用 64 位的结构体，所以需要调用 `__fcntl64` 来传递这些结构体。
3. **`F_SETFD` 命令的安全性检查:**  对于 `F_SETFD` 命令，它会进行额外的安全检查，确保用户只设置了 `FD_CLOEXEC` 标志。如果尝试设置其他标志，将会调用 `__fortify_fatal` 终止程序，这是一种安全加固机制。
4. **文件描述符跟踪 (针对 `F_DUPFD` 和 `F_DUPFD_CLOEXEC`):**  对于复制文件描述符的命令 `F_DUPFD` 和 `F_DUPFD_CLOEXEC`，它会调用 `FDTRACK_CREATE_NAME`。这表明 Bionic 库内部可能有一个机制来跟踪新创建的文件描述符，用于调试或其他目的。

**与 Android 功能的关系及举例:**

`fcntl` 函数是 Android 系统和应用程序中非常基础且重要的一个组成部分。几乎所有涉及到文件操作、进程管理和网络编程的 Android 功能都离不开 `fcntl`。以下是一些例子：

1. **文件操作:**
   - **打开文件:**  `open()` 系统调用会返回一个文件描述符。之后，可以使用 `fcntl` 来设置该文件描述符的属性，例如设置非阻塞模式 (通过 `F_SETFL` 和 `O_NONBLOCK`)。
   ```cpp
   // Java 代码 (通过 JNI 调用) 或 Native 代码
   int fd = open("/sdcard/test.txt", O_RDWR);
   if (fd != -1) {
       int flags = fcntl(fd, F_GETFL); // 获取当前标志
       fcntl(fd, F_SETFL, flags | O_NONBLOCK); // 设置为非阻塞
       // ...进行读写操作
       close(fd);
   }
   ```
   这个例子中，`fcntl` 用于获取和设置文件的打开模式。

2. **进程管理:**
   - **创建子进程和重定向文件描述符:**  `fork()` 创建子进程后，子进程会继承父进程的文件描述符。可以使用 `fcntl` 和 `dup2()` 等函数来重定向子进程的标准输入、输出和错误文件描述符。
   ```cpp
   // Native 代码
   pid_t pid = fork();
   if (pid == 0) { // 子进程
       int fd = open("/sdcard/output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
       if (fd != -1) {
           dup2(fd, STDOUT_FILENO); // 将标准输出重定向到文件
           close(fd);
       }
       // 执行子进程代码
   }
   ```
   虽然这里没有直接使用 `fcntl`，但 `fcntl` 的 `F_DUPFD` 功能与 `dup2` 类似，用于复制文件描述符。

3. **网络编程:**
   - **创建 socket 并设置属性:** `socket()` 系统调用会返回一个 socket 文件描述符。可以使用 `fcntl` 设置 socket 的非阻塞属性，或者设置 `FD_CLOEXEC` 标志，确保在 `exec` 系统调用后关闭该 socket。
   ```cpp
   // Native 代码
   int sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd != -1) {
       int flags = fcntl(sockfd, F_GETFL);
       fcntl(sockfd, F_SETFL, flags | O_NONBLOCK); // 设置为非阻塞
       int flags_fd = fcntl(sockfd, F_GETFD);
       fcntl(sockfd, F_SETFD, flags_fd | FD_CLOEXEC); // 设置 exec 后关闭
       // ...进行网络操作
       close(sockfd);
   }
   ```

**每一个 libc 函数的功能是如何实现的:**

这里主要关注的是 `fcntl` 函数的实现。

1. **`fcntl(int fd, int cmd, ...)` 函数:**
   - 这个函数是 Bionic 库提供的 `fcntl` 的实现。
   - 它首先使用 `va_list` 来处理可变参数。
   - 它提取出可选参数 `arg`。
   - **安全性检查:** 如果 `cmd` 是 `F_SETFD`，它会检查 `arg` 是否只设置了 `FD_CLOEXEC` 标志。如果不是，则调用 `__fortify_fatal` 终止程序。
   - **平台差异处理:**
     - 在 64 位架构下，它直接调用底层的 `__fcntl(fd, cmd, arg)` 系统调用。
     - 在 32 位架构下，它调用 `__fcntl64(fd, cmd, arg)` 系统调用。
   - **文件描述符跟踪:** 如果 `cmd` 是 `F_DUPFD` 或 `F_DUPFD_CLOEXEC`，它会调用 `FDTRACK_CREATE_NAME`，并将系统调用返回的文件描述符 `rc` 作为参数传递进去。这个函数很可能在内部维护一个数据结构来记录这些新创建的文件描述符。
   - 最后，返回底层系统调用的返回值。

2. **`__fcntl(int fd, int cmd, ...)` 和 `__fcntl64(int, int, ...)` 函数:**
   - 这两个函数是 Bionic 库声明的外部函数，但它们的实现并不在这个 `fcntl.cpp` 文件中。
   - 它们的实际实现位于内核空间。当用户空间的程序调用 `fcntl` 时，最终会通过系统调用陷入内核，并执行内核中对应的 `sys_fcntl` 或 `sys_fcntl64` 函数。
   - Bionic 库的作用是提供一个用户空间到内核空间的桥梁，处理参数传递等细节。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

在这个 `fcntl.cpp` 文件中，涉及到 dynamic linker 的关键在于对 `__fcntl` 和 `__fcntl64` 这两个外部函数的声明和使用。这两个函数实际上是系统调用，它们的符号需要在运行时被动态链接器解析。

**SO 布局样本:**

假设我们有一个名为 `libmylib.so` 的共享库，它使用了 `fcntl` 函数。

```
libmylib.so:
    .text           # 代码段
        ...
        call    fcntl   # 调用 fcntl 函数
        ...
    .rodata         # 只读数据段
        ...
    .data           # 数据段
        ...
    .dynamic        # 动态链接信息
        DT_NEEDED   libbionic.so  # 依赖 libbionic.so
        DT_SYMTAB   ...          # 符号表
        DT_STRTAB   ...          # 字符串表
        DT_PLTGOT   ...          # PLT/GOT 表
        ...
    .plt            # Procedure Linkage Table (PLT)
        fcntl@plt:
            jmp *fcntl@GOT
    .got            # Global Offset Table (GOT)
        fcntl@GOT: 0x0  # 初始值为 0
        ...
```

**链接的处理过程:**

1. **编译时:** 当 `libmylib.so` 被编译时，编译器看到对 `fcntl` 函数的调用，但它并不知道 `fcntl` 的具体地址。编译器会在 `.plt` 段生成一个条目 `fcntl@plt`，并在 `.got` 段生成一个对应的条目 `fcntl@GOT`，并将 `fcntl@GOT` 的初始值设置为 0。
2. **加载时:** 当 Android 系统加载 `libmylib.so` 时，动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会解析 `libmylib.so` 的 `.dynamic` 段，发现它依赖 `libbionic.so`。
3. **符号解析:** 动态链接器会加载 `libbionic.so`，并在其导出的符号表中查找 `fcntl` 的符号。在 Bionic 中，`fcntl` 的实现就位于 `libbionic.so` 中。
4. **GOT 表填充:** 动态链接器找到 `fcntl` 的实际地址后，会将这个地址写入 `libmylib.so` 的 `.got` 段中 `fcntl@GOT` 对应的位置。
5. **首次调用:** 当 `libmylib.so` 第一次调用 `fcntl` 时，会跳转到 `.plt` 段的 `fcntl@plt`。 `fcntl@plt` 中的指令 `jmp *fcntl@GOT` 会跳转到 `.got` 段中 `fcntl@GOT` 指向的地址，此时该地址已经被动态链接器填充为 `fcntl` 的实际地址，因此成功调用 `fcntl` 函数。
6. **后续调用:** 后续对 `fcntl` 的调用会直接跳转到 `.got` 表中存储的地址，避免了重复的符号解析过程。

在这个过程中，`__fcntl` 和 `__fcntl64` 实际上是更底层的系统调用接口，它们的符号解析过程类似，但通常是由内核或者一个更底层的库（如 `libc.so` 的进一步分解）提供。Bionic 的 `fcntl` 函数作为用户空间的封装，链接的是 Bionic 库提供的 `fcntl` 实现。

**逻辑推理，假设输入与输出:**

假设我们有以下 C++ 代码片段：

```cpp
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

int main() {
    int fd = open("test.txt", O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        std::cerr << "Error opening file" << std::endl;
        return 1;
    }

    // 获取当前文件描述符标志
    int flags = fcntl(fd, F_GETFD);
    std::cout << "Initial flags: " << flags << std::endl;

    // 设置 FD_CLOEXEC 标志
    if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
        std::cerr << "Error setting FD_CLOEXEC" << std::endl;
        close(fd);
        return 1;
    }

    // 再次获取文件描述符标志
    int new_flags = fcntl(fd, F_GETFD);
    std::cout << "Flags after setting FD_CLOEXEC: " << new_flags << std::endl;

    close(fd);
    return 0;
}
```

**假设输入:** 当前目录下不存在名为 `test.txt` 的文件。

**预期输出:**

```
Initial flags: 0
Flags after setting FD_CLOEXEC: 1
```

**解释:**

- 第一次调用 `fcntl(fd, F_GETFD)` 时，由于我们只是打开了文件，没有设置额外的文件描述符标志，所以返回的标志通常是 0。
- `FD_CLOEXEC` 标志的值通常是 1。
- 第二次调用 `fcntl(fd, F_GETFD)` 时，我们成功设置了 `FD_CLOEXEC` 标志，所以返回的标志值会包含 `FD_CLOEXEC`，即 1。

**常见使用错误:**

1. **不检查返回值:** `fcntl` 函数调用失败时会返回 -1，并设置 `errno`。不检查返回值可能导致程序出现未定义的行为。
   ```cpp
   int fd = open("test.txt", O_RDONLY);
   fcntl(fd, F_SETFL, O_NONBLOCK); // 如果 open 失败，fd 可能是 -1，导致 fcntl 出错
   ```

2. **错误使用 `F_SETFD`:** 如代码所示，Bionic 的 `fcntl` 对 `F_SETFD` 进行了限制，只允许设置 `FD_CLOEXEC`。尝试设置其他标志会导致程序崩溃。
   ```cpp
   int fd = open("test.txt", O_RDONLY);
   // 错误示例：尝试设置其他标志
   fcntl(fd, F_SETFD, 0x123); // 这会导致 __fortify_fatal
   ```

3. **与 `F_GETFL` 和 `F_SETFL` 配合使用时的位操作错误:** 当使用 `F_GETFL` 获取文件状态标志，并使用 `F_SETFL` 设置新的标志时，需要注意位操作。错误的位操作可能导致意外地清除或设置了其他标志。
   ```cpp
   int fd = open("test.txt", O_RDWR);
   int flags = fcntl(fd, F_GETFL);
   // 错误示例：只想添加 O_APPEND，但错误地覆盖了其他标志
   fcntl(fd, F_SETFL, O_APPEND);
   ```
   正确的做法是使用位或 `|` 操作添加标志，使用位与非 `& ~` 操作移除标志。

4. **混淆 `F_GETFD` 和 `F_GETFL`:** `F_GETFD` 操作的是文件描述符标志（如 `FD_CLOEXEC`），而 `F_GETFL` 操作的是文件状态标志（如 `O_RDONLY`, `O_NONBLOCK`）。混淆使用会导致错误。

**Android Framework 或 NDK 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤:**

让我们以一个简单的 NDK 例子来说明：

1. **Java 代码 (Android Framework):**  用户在 Android 应用中执行文件操作，例如使用 `java.io.FileInputStream` 读取文件。

2. **JNI 调用:**  `FileInputStream` 的底层实现会通过 JNI 调用到 Native 代码。

3. **NDK 代码:** Native 代码中，可能会使用标准的 C/C++ 文件操作函数，如 `open()`, `read()`, `write()`, 或者 `fcntl()`。

   ```cpp
   // NDK 代码示例 (假设在某个 .cpp 文件中)
   #include <jni.h>
   #include <fcntl.h>
   #include <unistd.h>

   extern "C" JNIEXPORT jint JNICALL
   Java_com_example_myapp_MainActivity_getFileFlags(JNIEnv *env, jobject /* this */, jstring path) {
       const char *filename = env->GetStringUTFChars(path, 0);
       int fd = open(filename, O_RDONLY);
       env->ReleaseStringUTFChars(path, filename);
       if (fd == -1) {
           return -1;
       }
       int flags = fcntl(fd, F_GETFL);
       close(fd);
       return flags;
   }
   ```

4. **Bionic 库:**  NDK 代码中调用的 `fcntl` 函数，实际上链接到的是 Bionic 库中的 `fcntl` 实现 (`bionic/libc/bionic/fcntl.cpp` 中的代码)。

5. **系统调用:** Bionic 的 `fcntl` 函数会根据架构选择调用 `__fcntl` 或 `__fcntl64` 系统调用，最终陷入内核，执行内核中的文件控制操作。

**Frida Hook 示例:**

我们可以使用 Frida 来 hook Bionic 库中的 `fcntl` 函数，观察其调用过程和参数。

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fcntl"), {
    onEnter: function(args) {
        console.log("[+] fcntl called");
        console.log("    fd: " + args[0]);
        console.log("    cmd: " + args[1]);
        // 可以根据 cmd 的值来解析第三个参数
        if (args[1].toInt() === 1) { // F_GETFL
            console.log("    cmd (F_GETFL)");
        } else if (args[1].toInt() === 2) { // F_SETFL
            console.log("    cmd (F_SETFL)");
            console.log("    flags: " + args[2]);
        } else if (args[1].toInt() === 7) { // F_GETFD
            console.log("    cmd (F_GETFD)");
        } else if (args[1].toInt() === 8) { // F_SETFD
            console.log("    cmd (F_SETFD)");
            console.log("    flags: " + args[2]);
        }
        // ... 添加更多 cmd 的解析
    },
    onLeave: function(retval) {
        console.log("[+] fcntl returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. 确保你的 Android 设备已连接并通过 USB 调试授权。
2. 安装 Frida 和 Python 的 Frida 模块 (`pip install frida-tools`).
3. 将上面的 Python 代码保存为 `hook_fcntl.py`，并将 `package_name` 替换为你要调试的应用的包名。
4. 运行你的 Android 应用。
5. 在终端中运行 `python hook_fcntl.py`。
6. 当应用执行涉及到 `fcntl` 的操作时，Frida 会拦截调用并打印出相关的参数和返回值。

这个 Frida hook 示例会拦截对 `libc.so` 中 `fcntl` 函数的调用，并在 `onEnter` 中打印出文件描述符、命令以及根据命令值解析出的第三个参数。在 `onLeave` 中打印出 `fcntl` 的返回值。通过观察这些信息，你可以了解 Android Framework 或 NDK 代码是如何一步步调用到 Bionic 的 `fcntl` 实现的。

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/fcntl.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/fcntl.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdarg.h>
#include <fcntl.h>

#include "private/bionic_fdtrack.h"
#include "private/bionic_fortify.h"

extern "C" int __fcntl(int fd, int cmd, ...);
extern "C" int __fcntl64(int, int, ...);

int fcntl(int fd, int cmd, ...) {
  va_list args;
  va_start(args, cmd);
  // This is a bit sketchy for LP64, especially because arg can be an int,
  // but all of our supported 64-bit ABIs pass the argument in a register.
  void* arg = va_arg(args, void*);
  va_end(args);

  if (cmd == F_SETFD && (reinterpret_cast<uintptr_t>(arg) & ~FD_CLOEXEC) != 0) {
    __fortify_fatal("fcntl(F_SETFD) only supports FD_CLOEXEC but was passed %p", arg);
  }

#if defined(__LP64__)
  int rc = __fcntl(fd, cmd, arg);
#else
  // For LP32 we use the fcntl64 system call to signal that we're using struct flock64.
  int rc = __fcntl64(fd, cmd, arg);
#endif
  if (cmd == F_DUPFD) {
    return FDTRACK_CREATE_NAME("F_DUPFD", rc);
  } else if (cmd == F_DUPFD_CLOEXEC) {
    return FDTRACK_CREATE_NAME("F_DUPFD_CLOEXEC", rc);
  }
  return rc;
}

"""

```