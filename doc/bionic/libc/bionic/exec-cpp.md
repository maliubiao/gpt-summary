Response:
Let's break down the thought process to answer the user's request about `bionic/libc/bionic/exec.cpp`.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the `exec.cpp` file in Android's bionic libc. They are asking for:

* **Functionality List:** What does this file do?
* **Android Relationship:** How does this relate to the Android OS?
* **Detailed Function Explanation:** What does each C library function in the file do and how is it implemented?
* **Dynamic Linker Aspects:** If dynamic linking is involved, provide examples and explain the process.
* **Logic and Examples:**  Illustrate with assumed inputs and outputs.
* **Common Errors:** What mistakes do users/programmers make when using these functions?
* **Android Framework/NDK Path:** How does code execution reach this file from higher levels?
* **Frida Hooking:** How can we use Frida to debug this?

**2. Initial Analysis of the Code:**

Skimming through the `exec.cpp` code immediately reveals the core functions it defines: `execl`, `execle`, `execlp`, `execv`, `execvp`, `execvpe`, and `fexecve`. These are all standard POSIX functions related to executing new programs. The presence of `__execl` (a template), `__exec_as_script`, and the use of `execve` as a core primitive suggest an implementation that wraps the system call.

**3. Addressing Each Requirement Systematically:**

* **Functionality List:**  The main function of this file is to provide the standard `exec` family of functions. These functions replace the current process with a new one.

* **Android Relationship:** This is a *fundamental* part of Android. Every time an app starts, an activity launches, or a service starts, some form of `exec` is involved. It's how the operating system transitions from one program to another.

* **Detailed Function Explanation:**  This requires explaining each `exec` variant:
    * **`execl`, `execle`, `execlp`:**  These take arguments as a variable list. The 'l' signifies a list of arguments. 'e' indicates that the environment is explicitly passed. 'p' means to search the PATH environment variable. The template `__execl` handles the common argument processing.
    * **`execv`, `execvp`:** These take arguments as an array. 'v' signifies a vector of arguments. 'p' again means to search the PATH.
    * **`execve`:** This is the underlying system call. It takes the executable path, the argument vector, and the environment vector.
    * **`execvpe`:**  Android's extension to search the PATH and handle script execution.
    * **`fexecve`:** Executes a file referenced by a file descriptor.

    The explanation needs to cover how arguments are collected, how the environment is handled, and the core call to `execve`. The script execution logic in `__exec_as_script` is also important.

* **Dynamic Linker Aspects:**  The `exec` functions are the *trigger* for the dynamic linker. When a new executable is loaded, the kernel invokes the dynamic linker (usually `linker64` or `linker`). The linker then loads the necessary shared libraries (.so files).

    * **SO Layout Example:**  A simple example showing the main executable and a few shared libraries with their relative paths is sufficient.
    * **Linking Process:** Explain the steps: loading the executable, parsing the ELF header, finding dependencies, loading shared libraries, resolving symbols (using GOT/PLT).

* **Logic and Examples:**  For each function, provide a simple example of how it might be called and the expected outcome (successful execution or an error). This helps clarify the differences between the `exec` variants. Highlight the behavior of `execvp` searching the PATH and `execvpe` handling scripts.

* **Common Errors:**
    * **Incorrect Argument Termination:**  For `execl` family, forgetting the `NULL` terminator.
    * **Incorrect Argument Array:** For `execv` family, not having a `NULL` pointer at the end of the array.
    * **Path Issues:**  Not providing the full path or the executable not being in the PATH.
    * **Permissions:**  The executable lacking execute permissions.
    * **Shebang Errors:** Errors in the first line (`#!`) of a script.

* **Android Framework/NDK Path:**  Trace a typical execution flow:
    * **App/Framework:**  An app's `Activity.startActivity()` or a framework service launching a process.
    * **Zygote:**  Most Android apps are forked from the Zygote process.
    * **`Process.java` (Android Framework):**  Uses `Runtime.exec()` or `ProcessBuilder`.
    * **Native Code (NDK):**  Directly calling `exec` functions in C/C++.
    * **System Call:**  Eventually, these calls lead to the `execve` system call handled by the kernel. The `exec.cpp` functions are wrappers around this system call.

* **Frida Hooking:** Provide examples of how to hook the `execve` function to intercept process execution, inspect arguments, and even modify behavior. Show basic syntax for hooking functions in Frida.

**4. Structuring the Answer:**

Organize the answer logically, starting with a summary of the file's purpose. Then, address each of the user's points in a clear and structured way, using headings and bullet points for readability. Provide code snippets for examples and Frida hooks.

**5. Refining and Explaining Technical Details:**

* **`va_list`:** Explain how variable argument lists work in C/C++ and how they are used in `execl`, `execle`, and `execlp`.
* **`environ`:**  Explain what the `environ` global variable is and how it stores the environment variables.
* **`strsep`:** Briefly explain how `strsep` works for parsing the PATH environment variable.
* **System Calls:** Emphasize that the `exec` functions are ultimately wrappers around the `execve` system call.
* **Dynamic Linking Concepts:**  Clearly define terms like "ELF," "shared libraries," "GOT," and "PLT."

**Self-Correction/Refinement During the Process:**

* **Initially, I might focus too heavily on the C code itself.**  I need to remember the user's request includes the broader context of Android. Therefore, the explanation of the Android framework/NDK path and the dynamic linker is crucial.
* **Simply listing the function names isn't enough.**  I need to explain the *differences* between them (list vs. vector arguments, environment handling, PATH searching).
* **The dynamic linking explanation needs to be simplified.**  A deep dive into ELF format is not necessary. Focus on the core concepts.
* **Frida examples should be practical and easy to understand.**  Avoid overly complex scripting.

By following this structured thought process and continuously refining the explanation, I can provide a comprehensive and helpful answer to the user's request.
好的，让我们详细分析一下 `bionic/libc/bionic/exec.cpp` 这个文件。

**功能列举:**

`exec.cpp` 文件在 Android Bionic libc 中实现了 POSIX 标准定义的 `exec` 函数族。这些函数的主要功能是**用一个新的进程替换当前进程的映像**。  简单来说，就是启动一个新的程序来运行，而原来的程序会被完全替换掉。

这个文件中实现了以下 `exec` 函数：

* **`execl(const char* pathname, const char* arg, ...)`:** 以列表方式传递命令行参数，直到遇到 NULL。使用 PATH 环境变量查找可执行文件。
* **`execle(const char* pathname, const char* arg, ..., char *const envp[])`:**  与 `execl` 类似，但允许显式传递新的环境变量。
* **`execlp(const char* filename, const char* arg, ...)`:**  以列表方式传递命令行参数，直到遇到 NULL。  仅使用 `filename` 作为可执行文件名，并在 PATH 环境变量指定的目录中搜索。
* **`execv(const char* pathname, char *const argv[])`:** 以数组方式传递命令行参数。使用 PATH 环境变量查找可执行文件。
* **`execvp(const char* filename, char *const argv[])`:** 以数组方式传递命令行参数。 仅使用 `filename` 作为可执行文件名，并在 PATH 环境变量指定的目录中搜索。
* **`execvpe(const char* filename, char *const argv[], char *const envp[])`:**  是 Android 对 POSIX 的扩展，与 `execvp` 类似，但允许显式传递新的环境变量。
* **`fexecve(int fd, char *const argv[], char *const envp[])`:**  使用文件描述符指定要执行的文件，而不是路径名。

**与 Android 功能的关系及举例说明:**

`exec` 函数族是 Android 操作系统中**至关重要**的一部分，几乎所有新进程的创建都依赖于它们。

* **启动应用程序:** 当你点击 Android 桌面上的应用图标时，系统会调用 `exec` 函数来启动该应用的进程。例如，Activity Manager Service (AMS) 会使用 `exec` 来启动一个新的 Activity。
* **执行系统命令:**  在 shell 环境中（如 adb shell），当你输入一个命令并执行时，shell 进程会 fork 一个新的进程，然后调用 `exec` 函数来执行你输入的命令（例如 `ls`, `ps`, `top` 等）。
* **NDK 开发:**  使用 Android NDK 进行原生开发时，你的 C/C++ 代码也可以直接调用这些 `exec` 函数来启动新的进程。
* **进程替换:**  一个正在运行的进程可以通过调用 `exec` 函数来替换自身，这常用于程序更新或执行其他任务。

**示例:**

假设你有一个名为 `my_app` 的可执行文件，你想使用 `execl` 启动它，并传递两个参数 `"arg1"` 和 `"arg2"`。

```c
#include <unistd.h>

int main() {
  // 假设 my_app 可执行文件在 /system/bin 目录下
  execl("/system/bin/my_app", "my_app", "arg1", "arg2", NULL);
  // 如果 exec 失败，会执行以下代码
  perror("exec failed");
  return 1;
}
```

在这个例子中，`execl` 函数会被调用，它会尝试执行 `/system/bin/my_app`。新的进程将会以 `"my_app"` 作为 `argv[0]`， `"arg1"` 作为 `argv[1]`， `"arg2"` 作为 `argv[2]` 来运行。

**libc 函数的实现细节:**

让我们逐个分析 `exec.cpp` 中实现的 libc 函数：

* **`__execl` 模板函数:**  这是一个内部辅助函数，用于处理 `execl`, `execle`, `execlp` 这三个变参函数的共同逻辑。它主要负责：
    1. **计算参数个数:** 使用 `va_list` 遍历变参，直到遇到 NULL，统计参数的数量。
    2. **构建 `argv` 数组:**  动态分配内存，将变参复制到 `argv` 数组中。`argv[0]` 通常设置为要执行的文件名本身。
    3. **获取 `envp`:**  对于 `execl` 和 `execlp`，直接使用全局变量 `environ` 作为环境变量；对于 `execle`，则从变参中获取。
    4. **调用 `execve` 或 `execvp`:** 根据模板参数 `variant` 的不同，最终调用 `execve` 或 `execvp` 来执行程序。

* **`execl`:**  调用 `__execl<ExecL>`，使用全局环境变量 `environ`。

* **`execle`:** 调用 `__execl<ExecLE>`，从变参中获取环境变量。

* **`execlp`:** 调用 `__execl<ExecLP>`，使用 `execvp` 执行，以便在 PATH 中搜索可执行文件。

* **`execv`:**  直接调用 `execve`，使用全局环境变量 `environ`。

* **`execvp`:** 调用 `execvpe`，使用全局环境变量 `environ`。

* **`__exec_as_script`:**  这是一个内部辅助函数，用于处理执行脚本的情况。当 `execve` 尝试执行一个没有执行权限的文件或者以 `#!` 开头的文件时，会返回 `ENOEXEC` 错误。这个函数会被调用，它会构造一个新的 `argv` 数组，将 shell 解释器（通常是 `/system/bin/sh`）作为新的可执行文件，原始脚本的路径作为 shell 脚本的第一个参数，并将原始的命令行参数添加到后面。然后调用 `execve` 来执行 shell 脚本。

* **`execvpe`:**  这是实现 PATH 环境变量搜索的关键函数。
    1. **检查 `name`:** 确保要执行的文件名不为空。
    2. **检查路径是否包含 `/`:** 如果文件名包含 `/`，则认为是一个绝对路径或相对路径，直接调用 `execve` 尝试执行。如果 `execve` 失败，并且错误是 `ENOEXEC`，则调用 `__exec_as_script` 处理脚本。
    3. **搜索 PATH:** 如果文件名不包含 `/`，则需要搜索 PATH 环境变量。
        * 获取 PATH 环境变量的值。如果没有设置 PATH，则使用默认路径 `_PATH_DEFPATH`（通常是 `/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin`）。
        * 复制 PATH 字符串到可写缓冲区。
        * 使用 `strsep` 函数分割 PATH 字符串，遍历每个目录。
        * 对于每个目录，构建完整的文件路径（目录 + "/" + 文件名）。
        * 调用 `execve` 尝试执行该路径下的文件。
        * 根据 `execve` 返回的错误码进行处理：
            * 如果是 `ENOEXEC`，调用 `__exec_as_script`。
            * 如果是其他特定错误（如 `EISDIR`, `ELOOP` 等），则继续搜索下一个目录。
            * 如果是 `EACCES`（权限被拒绝），则记录下来，以便在所有路径都搜索完后返回 `EACCES`。
            * 如果是其他错误，则直接返回该错误。
    4. **返回错误:** 如果所有路径都搜索完毕，仍然没有找到可执行文件或执行失败，则返回相应的错误码。

* **`fexecve`:**  使用文件描述符 `fd` 指定要执行的文件。它实际上是调用 `execve`，并将文件描述符转换为文件路径（通过 `FdPath(fd).c_str()`）。如果 `execve` 返回 `ENOENT`，则将其转换为 `EBADF`，因为使用文件描述符时，文件不存在更准确地说是文件描述符无效。

**涉及 dynamic linker 的功能和处理过程:**

当 `execve` 系统调用成功执行一个新的 ELF 可执行文件时，内核会将控制权交给 dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`)。  Dynamic linker 的主要任务是：

1. **加载共享库 (Shared Objects, .so 文件):**  解析新程序的 ELF 头，找到其依赖的共享库列表。然后，按照一定的顺序加载这些共享库到内存中。共享库的路径通常由程序的 `DT_RUNPATH` 或 `DT_RPATH` 标签指定，或者通过 `LD_LIBRARY_PATH` 环境变量指定。

2. **重定位 (Relocation):**  由于共享库在不同的进程中加载的基地址可能不同，dynamic linker 需要修改代码和数据段中的地址引用，使其指向正确的内存位置。这主要涉及到两种重定位类型：
    * **绝对重定位:** 直接修改绝对地址。
    * **PIC (Position Independent Code) 重定位:** 使用 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table) 来实现与位置无关的代码，从而允许多个进程共享同一份共享库代码。

3. **符号解析 (Symbol Resolution):**  解决程序和其依赖的共享库之间的符号引用关系。例如，如果程序调用了一个定义在共享库中的函数，dynamic linker 需要找到该函数的地址。

**SO 布局样本:**

假设你的应用程序 `my_app` 链接了两个共享库 `libutils.so` 和 `libcrypto.so`。

```
/system/bin/my_app      (主可执行文件)
/system/lib64/libutils.so
/vendor/lib64/libcrypto.so
```

**链接的处理过程:**

1. **`execve("/system/bin/my_app", ...)` 被调用。**
2. **内核加载 `my_app` 到内存。**
3. **内核识别出 `my_app` 是一个动态链接的可执行文件，并将控制权交给 dynamic linker `/system/bin/linker64`。**
4. **Dynamic linker 解析 `my_app` 的 ELF 头，找到 `DT_NEEDED` 标签，列出依赖的共享库：`libutils.so` 和 `libcrypto.so`。**
5. **Dynamic linker 根据预定义的搜索路径（如 `/system/lib64`, `/vendor/lib64` 等）以及可能的 `LD_LIBRARY_PATH` 环境变量，查找并加载 `libutils.so` 和 `libcrypto.so` 到内存中。**
6. **Dynamic linker 执行重定位操作，修改 `my_app` 和其依赖的共享库中的地址引用，使其指向正确的内存地址。**
7. **Dynamic linker 解析符号表，解决 `my_app` 和其依赖的共享库之间的符号引用关系。例如，如果 `my_app` 调用了 `libutils.so` 中的一个函数，dynamic linker 会将该调用指向 `libutils.so` 中该函数的实际地址。**
8. **链接过程完成后，dynamic linker 将控制权交给 `my_app` 的入口点，程序开始执行。**

**假设输入与输出 (逻辑推理):**

假设我们调用 `execvp("ls", {"ls", "-l", "/sdcard"})`。

* **输入:**
    * `name`: "ls"
    * `argv`: {"ls", "-l", "/sdcard", NULL}
    * 当前进程的环境变量（假设 PATH 包含 `/system/bin`）

* **处理过程:**
    1. `execvp` 会在 PATH 环境变量指定的目录中搜索名为 "ls" 的可执行文件，通常会在 `/system/bin/ls` 找到。
    2. `execve("/system/bin/ls", {"ls", "-l", "/sdcard"}, environ)` 被调用。
    3. 内核加载 `/system/bin/ls` 的进程映像。
    4. 如果 `ls` 是动态链接的，则 dynamic linker 会加载其依赖的共享库并进行链接。
    5. `ls` 程序开始执行，并列出 `/sdcard` 目录下的文件和详细信息。

* **输出:**  新的进程会执行 `ls -l /sdcard` 命令，并在终端或输出流中显示 `/sdcard` 目录的内容。原来的进程会被替换掉。

**用户或编程常见的使用错误:**

* **`execl` 系列函数参数列表未以 NULL 结尾:**  这是非常常见的错误，会导致程序崩溃或行为异常。例如：`execl("/bin/ls", "ls", "-l");`  缺少最后的 `NULL`。
* **`execv` 系列函数 `argv` 数组未以 NULL 指针结尾:** 类似于 `execl`，`argv` 数组的最后一个元素必须是 `NULL`。
* **提供的可执行文件路径错误或不存在:**  如果传递给 `exec` 函数的路径名不正确，或者文件不存在，`exec` 函数会失败，并设置 `errno` 为 `ENOENT`。
* **权限问题:** 如果要执行的文件没有执行权限，`exec` 函数会失败，并设置 `errno` 为 `EACCES`。
* **环境变量设置错误:**  在使用 `execle` 或 `execvpe` 时，如果传递的环境变量数组格式不正确，可能会导致程序行为异常。
* **忘记处理 `exec` 失败的情况:**  `exec` 函数如果调用成功，不会返回。如果返回了，则说明调用失败。程序员应该检查返回值（通常是 -1）并处理错误（例如，使用 `perror` 打印错误信息）。
* **在多线程程序中使用 `fork` 后不立即 `exec`:**  在多线程程序中，`fork` 只会复制调用线程的状态，这可能会导致子进程的状态不一致。最佳实践是在 `fork` 之后立即调用 `exec` 来替换子进程的映像。
* **脚本文件首行 Shebang (`#!`) 错误:** 如果要执行的是脚本文件，但其首行的 Shebang 行指定了解释器路径错误或不存在，`exec` 可能会失败。

**Android framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java 代码):**
   * 当一个应用程序需要启动一个新的进程时，例如通过 `Context.startActivity()` 启动一个新的 Activity，或者使用 `Runtime.getRuntime().exec()` 执行一个 shell 命令。
   * `startActivity()` 最终会调用到 Activity Manager Service (AMS)。
   * AMS 会决定创建一个新的进程来运行该 Activity。
   * AMS 会与 Zygote 进程通信，请求 fork 一个新的进程。
   * `Runtime.exec()` 最终会调用到 `ProcessBuilder` 或类似的机制。

2. **Zygote 进程 (C++ 代码):**
   * Zygote 是 Android 系统启动的第一个 Java 进程，它预先加载了许多常用的类和资源。
   * 当收到 AMS 的请求后，Zygote 进程会调用 `fork()` 系统调用创建一个新的子进程。
   * 在子进程中，Zygote 会根据 AMS 的请求，调用 `execve` 或类似的函数来启动目标应用程序的进程。通常，它会执行一个特殊的 "app_process" 可执行文件，该文件负责启动 Dalvik/ART 虚拟机并运行应用程序代码。

3. **NDK (Native 代码):**
   * 使用 NDK 开发的应用程序可以直接调用 `exec` 函数族。
   * 例如，一个 native 的守护进程可能需要启动其他的工具或进程。

**Frida hook 示例调试这些步骤:**

你可以使用 Frida 来 hook `execve` 函数，以观察哪些进程正在尝试执行哪些程序以及它们的参数。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['pid'], message['payload']['command']))
    else:
        print(message)

device = frida.get_usb_device()
pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
session = device.attach(pid) if pid else device.spawn(['com.example.myapp']) # 替换成你的应用包名

script_code = """
Interceptor.attach(Module.findExportByName(null, "execve"), {
    onEnter: function(args) {
        var cmd = Memory.readUtf8String(args[0]);
        var argv = [];
        var i = 0;
        var argp = ptr(args[1]);
        while (true) {
            var arg = Memory.readPointer(argp.add(i * Process.pointerSize));
            if (arg.isNull())
                break;
            argv.push(Memory.readUtf8String(arg));
            i++;
        }
        var pid = Process.id;
        send({'pid': pid, 'command': cmd + ' ' + argv.join(' ')});
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将上面的 Python 代码保存为 `hook_execve.py`。
2. 确保你的设备已连接并通过 ADB 连接。
3. 安装 Frida：`pip install frida frida-tools`。
4. 运行 Frida 服务：确保设备上运行了 `frida-server`。
5. 运行 hook 脚本：
   * **附加到正在运行的进程:** `python hook_execve.py <目标进程的 PID>`
   * **启动并附加到新进程:** `python hook_execve.py` (如果代码中使用了 `device.spawn`)

**输出示例:**

当你运行 hook 脚本并在目标应用或系统上进行操作时，你会看到类似以下的输出：

```
[*] 1234: /system/bin/ls ls -l /data/local/tmp
[*] 5678: /system/bin/ping ping 8.8.8.8
[*] 9012: /system/bin/app_process /system/bin --application --zygote --start-system-server
```

这会显示执行 `execve` 的进程 ID 以及要执行的命令及其参数，帮助你追踪进程的创建过程。

希望这个详细的解释能够帮助你理解 `bionic/libc/bionic/exec.cpp` 的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/exec.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <limits.h>
#include <paths.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "private/FdPath.h"
#include "private/__bionic_get_shell_path.h"

extern "C" char** environ;

enum { ExecL, ExecLE, ExecLP };

template <int variant>
static int __execl(const char* name, const char* argv0, va_list ap) {
  // Count the arguments.
  va_list count_ap;
  va_copy(count_ap, ap);
  size_t n = 1;
  while (va_arg(count_ap, char*) != nullptr) {
    ++n;
  }
  va_end(count_ap);

  // Construct the new argv.
  char* argv[n + 1];
  argv[0] = const_cast<char*>(argv0);
  n = 1;
  while ((argv[n] = va_arg(ap, char*)) != nullptr) {
    ++n;
  }

  // Collect the argp too.
  char** argp = (variant == ExecLE) ? va_arg(ap, char**) : environ;

  va_end(ap);

  return (variant == ExecLP) ? execvp(name, argv) : execve(name, argv, argp);
}

int execl(const char* name, const char* arg, ...) {
  va_list ap;
  va_start(ap, arg);
  int result = __execl<ExecL>(name, arg, ap);
  va_end(ap);
  return result;
}

int execle(const char* name, const char* arg, ...) {
  va_list ap;
  va_start(ap, arg);
  int result = __execl<ExecLE>(name, arg, ap);
  va_end(ap);
  return result;
}

int execlp(const char* name, const char* arg, ...) {
  va_list ap;
  va_start(ap, arg);
  int result = __execl<ExecLP>(name, arg, ap);
  va_end(ap);
  return result;
}

int execv(const char* name, char* const* argv) {
  return execve(name, argv, environ);
}

int execvp(const char* name, char* const* argv) {
  return execvpe(name, argv, environ);
}

static int __exec_as_script(const char* buf, char* const* argv, char* const* envp) {
  size_t arg_count = 1;
  while (argv[arg_count] != nullptr) ++arg_count;

  const char* script_argv[arg_count + 2];
  script_argv[0] = "sh";
  script_argv[1] = buf;
  memcpy(script_argv + 2, argv + 1, arg_count * sizeof(char*));
  return execve(__bionic_get_shell_path(), const_cast<char**>(script_argv), envp);
}

int execvpe(const char* name, char* const* argv, char* const* envp) {
  // Do not allow null name.
  if (name == nullptr || *name == '\0') {
    errno = ENOENT;
    return -1;
  }

  // If it's an absolute or relative path name, it's easy.
  if (strchr(name, '/') && execve(name, argv, envp) == -1) {
    if (errno == ENOEXEC) return __exec_as_script(name, argv, envp);
    return -1;
  }

  // Get the path we're searching.
  const char* path = getenv("PATH");
  if (path == nullptr) path = _PATH_DEFPATH;

  // Make a writable copy.
  size_t len = strlen(path) + 1;
  char writable_path[len];
  memcpy(writable_path, path, len);

  bool saw_EACCES = false;

  // Try each element of $PATH in turn...
  char* strsep_buf = writable_path;
  const char* dir;
  while ((dir = strsep(&strsep_buf, ":"))) {
    // It's a shell path: double, leading and trailing colons
    // mean the current directory.
    if (*dir == '\0') dir = const_cast<char*>(".");

    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);

    char buf[dir_len + 1 + name_len + 1];
    mempcpy(mempcpy(mempcpy(buf, dir, dir_len), "/", 1), name, name_len + 1);

    execve(buf, argv, envp);
    switch (errno) {
    case EISDIR:
    case ELOOP:
    case ENAMETOOLONG:
    case ENOENT:
    case ENOTDIR:
      break;
    case ENOEXEC:
      return __exec_as_script(buf, argv, envp);
    case EACCES:
      saw_EACCES = true;
      break;
    default:
      return -1;
    }
  }
  if (saw_EACCES) errno = EACCES;
  return -1;
}

int fexecve(int fd, char* const* argv, char* const* envp) {
  // execveat with AT_EMPTY_PATH (>= 3.19) seems to offer no advantages.
  execve(FdPath(fd).c_str(), argv, envp);
  if (errno == ENOENT) errno = EBADF;
  return -1;
}
```