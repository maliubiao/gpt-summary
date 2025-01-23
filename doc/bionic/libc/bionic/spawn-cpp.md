Response:
Let's break down the thought process for answering the request about `bionic/libc/bionic/spawn.cpp`.

**1. Understanding the Core Request:**

The central request is to analyze the `spawn.cpp` file within Android's Bionic library. This means understanding its purpose, functionality, how it interacts with Android, and common usage patterns/errors. The prompt specifically asks for explanations of libc functions, dynamic linker involvement, and how it's reached from higher levels (framework/NDK).

**2. Initial Code Scan and High-Level Overview:**

The first step is to quickly read through the code to get a general understanding. Keywords like `spawn`, `fork`, `execve`, file actions (`open`, `close`, `dup2`, `chdir`), attributes (process group, signals, scheduling), and `cloexec` immediately stand out. This suggests the file is about creating and configuring new processes.

**3. Deconstructing the Functionality - Top Down:**

It's helpful to start with the main functions and work down:

* **`posix_spawn` and `posix_spawnp`:** These are the entry points for creating new processes. The `p` version handles path lookup. Recognizing these as the core functions is crucial.

* **`ApplyAttrs`:** This function applies the process attributes defined by `posix_spawnattr_t`. This clearly separates the attribute setting logic from the process creation itself.

* **File Actions (`__posix_spawn_file_actions` and related functions):**  This section deals with modifying the file descriptor table of the child process before execution. The `kOpen`, `kClose`, `kDup2`, `kChdir`, `kFchdir` actions are straightforward.

* **Attributes (`__posix_spawnattr` and related functions):** These functions allow setting various properties of the child process like signal masks, process groups, scheduling policies, etc.

* **Helper Functions:**  `set_cloexec` and `cloexec_except_stdioe` are about setting the close-on-exec flag for file descriptors.

**4. Connecting to Android:**

* **Core System Call Abstraction:**  Bionic's primary role is to provide standard C library functions. `posix_spawn` is a standard POSIX function, so its presence here is expected. The implementation likely uses underlying Linux system calls like `fork`, `execve`, `vfork`, etc.

* **Process Management:**  Android relies heavily on forking and execing to launch applications and services. `posix_spawn` provides a more controlled way to do this compared to directly using `fork` and `execve`.

* **Security and Resource Management:** Features like setting signal masks and scheduling policies are essential for managing resources and security in a multi-process environment like Android.

* **`android/fdsan.h`:**  The inclusion of this header suggests an integration with Android's file descriptor sanitization mechanisms, although it's not directly used in the provided snippet.

**5. Detailed Explanation of libc Functions:**

For each function, the explanation should cover:

* **Purpose:** What does the function do?
* **Mechanism:** How does it achieve its purpose (system calls, internal logic)?
* **Parameters and Return Values:**  Briefly describe the key inputs and outputs.

**6. Dynamic Linker (Absent in this snippet):**

The prompt asks about the dynamic linker. *Crucially, this specific `spawn.cpp` file doesn't directly interact with the dynamic linker*. `execve` (or `execvpe`) is the point where the kernel invokes the dynamic linker of the newly executed program. Therefore, the explanation needs to acknowledge this indirect relationship and explain the role of the dynamic linker at that stage.

* **SO Layout Sample:** Provide a simple example of an executable and its linked library.
* **Linking Process:**  Explain the steps involved when the dynamic linker loads and resolves symbols in the child process.

**7. Logic and Assumptions:**

Since the code is about system calls, the logic is mostly deterministic. The assumptions are about the underlying operating system behavior (how `fork`, `execve`, signals, etc., work). For specific scenarios (like file actions), provide examples of input and the expected outcome in the child process.

**8. Common Usage Errors:**

Think about the typical mistakes developers might make when using `posix_spawn`:

* Incorrect flags.
* Issues with file descriptor management (not closing unnecessary fds).
* Signal handling problems.
* Incorrect path or arguments to the executed program.

**9. Android Framework/NDK Path and Frida Hooking:**

* **Framework:** Trace the execution from a high-level Android component (e.g., `ActivityManagerService` starting a new activity) down to the native level where `posix_spawn` (or a related function) would be used.

* **NDK:** Explain how an NDK application would directly call `posix_spawn` or related functions.

* **Frida Hooking:**  Provide a basic example of how to use Frida to intercept calls to `posix_spawn` and inspect its arguments. Highlighting the key information that can be observed (path, arguments, attributes) is important.

**10. Structuring the Answer:**

Organize the information logically:

* Start with a general overview of the file's purpose.
* Detail the functionality, explaining each group of related functions.
* Discuss the relationship with Android.
* Explain the libc functions.
* Address the dynamic linker aspect (even if indirect).
* Provide examples of usage errors.
* Explain the path from the framework/NDK.
* Include a Frida example.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this file *directly* handles dynamic linking.
* **Correction:**  Realized that `execve` is the handoff point to the kernel, which then invokes the dynamic linker. The `spawn.cpp` file sets up the environment for the *new* process, but the linking happens within that new process's context.

* **Initial thought:** Just list the functions.
* **Refinement:**  Group related functions (file actions, attributes) for better clarity and explanation.

* **Initial thought:**  Focus heavily on the code details.
* **Refinement:** Balance code explanation with the broader context of its role in Android and common usage patterns.

By following this structured thought process, you can generate a comprehensive and accurate answer to the complex request. The key is to break down the problem, understand the individual components, and then piece them back together in a clear and logical way.
好的，我们来详细分析一下 `bionic/libc/bionic/spawn.cpp` 文件的功能及其在 Android 系统中的作用。

**文件功能概述**

`spawn.cpp` 文件实现了 `posix_spawn` 和 `posix_spawnp` 以及相关的辅助函数，这些函数用于创建一个新的进程，并允许在创建过程中对新进程的环境进行细粒度的控制。  `posix_spawn` 相比传统的 `fork` 和 `exec` 组合，提供了一种更为轻量级和可配置的方式来创建进程，尤其是在需要精确控制子进程环境时。

**具体功能分解**

1. **`posix_spawn(pid_t* pid, const char* path, const posix_spawn_file_actions_t* actions, const posix_spawnattr_t* attr, char* const argv[], char* const env[])`**:
   - **功能:** 这是 `posix_spawn` 的核心实现，用于创建一个新的子进程并执行指定路径的程序。
   - **实现:**
     - 首先，它会根据 `attr` 中的标志位决定是否使用 `vfork` 或 `fork` 来创建子进程。`vfork` 在子进程调用 `execve` 或 `_exit` 之前共享父进程的内存空间，效率更高，但使用限制较多。如果 `actions` 为空且 `flags` 为 0，则默认使用 `vfork`。
     - 在父进程中，如果 `pid_ptr` 非空，则将子进程的 PID 写入。
     - 在子进程中：
       - 调用 `ApplyAttrs` 应用通过 `attr` 设置的进程属性（如信号掩码、进程组、调度策略等）。
       - 如果 `actions` 非空，则调用 `(*actions)->Do()` 执行预定义的文件操作。
       - 如果没有设置 `POSIX_SPAWN_SETSIGMASK` 标志，则重置信号屏蔽（通过 `ScopedSignalBlocker` 完成）。
       - 最后，调用传递进来的 `exec_fn` 函数执行新的程序。默认情况下，`exec_fn` 是 `execve`。如果 `posix_spawnp` 调用此函数，则 `exec_fn` 是 `execvpe`。
   - **与 Android 的关系:** Android 系统中，很多进程的创建都是通过 `posix_spawn` 或其变体来实现的，例如启动新的应用进程或系统服务进程。

2. **`posix_spawnp(pid_t* pid, const char* file, const posix_spawn_file_actions_t* actions, const posix_spawnattr_t* attr, char* const argv[], char* const env[])`**:
   - **功能:** 类似于 `posix_spawn`，但它会在环境变量 `PATH` 指定的目录中搜索可执行文件。
   - **实现:**  它简单地调用了 `posix_spawn`，并将执行函数设置为 `execvpe`。
   - **与 Android 的关系:** 当需要启动一个系统命令或者应用，但不知道其完整路径时，可以使用 `posix_spawnp`。

3. **`ApplyAttrs(short flags, const posix_spawnattr_t* attr)`**:
   - **功能:** 应用通过 `posix_spawnattr_t` 结构体设置的子进程属性。
   - **实现:**
     - 根据 `flags` 中的标志位，设置子进程的信号处理方式（默认行为或继承）、进程组 ID、会话 ID、调度策略和参数、用户和组 ID，以及信号掩码。
     - 如果设置了 `POSIX_SPAWN_CLOEXEC_DEFAULT`，则调用 `cloexec_except_stdioe` 关闭除标准输入/输出/错误之外的所有打开的文件描述符的 close-on-exec 标志。
   - **与 Android 的关系:** Android 利用这些属性来配置新进程的运行环境，例如设置特定的信号处理方式以确保进程的稳定性。

4. **文件操作相关函数 (`posix_spawn_file_actions_init`, `posix_spawn_file_actions_destroy`, `posix_spawn_file_actions_addopen`, `posix_spawn_file_actions_addclose`, `posix_spawn_file_actions_adddup2`, `posix_spawn_file_actions_addchdir_np`, `posix_spawn_file_actions_addfchdir_np`)**:
   - **功能:** 这些函数允许用户在子进程启动前，对其文件描述符进行操作，例如打开新文件、关闭文件、复制文件描述符以及改变工作目录。
   - **实现:**  它们维护一个链表 `__posix_spawn_file_actions`，其中每个节点 `__posix_spawn_file_action` 描述一个要执行的文件操作。在子进程创建后，`Do()` 方法会遍历这个链表并执行相应的操作。
     - `kOpen`: 在子进程中打开指定路径的文件。
     - `kClose`: 在子进程中关闭指定的文件描述符。
     - `kDup2`: 在子进程中复制文件描述符。
     - `kChdir`: 在子进程中改变当前工作目录为指定路径。
     - `kFchdir`: 在子进程中改变当前工作目录为指定文件描述符代表的目录。
   - **与 Android 的关系:** Android 可以使用这些操作来重定向子进程的标准输入/输出/错误，或者为子进程提供特定的文件描述符。例如，`adb shell` 命令的实现可能就使用了这些功能来连接到设备上的 shell 进程。

5. **进程属性相关函数 (`posix_spawnattr_init`, `posix_spawnattr_destroy`, `posix_spawnattr_setflags`, `posix_spawnattr_getflags`, `posix_spawnattr_setpgroup`, `posix_spawnattr_getpgroup`, `posix_spawnattr_setsigmask`, `posix_spawnattr_getsigmask`, `posix_spawnattr_setsigdefault`, `posix_spawnattr_getsigdefault`, `posix_spawnattr_setschedparam`, `posix_spawnattr_getschedparam`, `posix_spawnattr_setschedpolicy`, `posix_spawnattr_getschedpolicy`)**:
   - **功能:** 这些函数用于初始化、销毁和设置/获取 `posix_spawnattr_t` 结构体的成员，这些成员控制子进程的各种属性。
   - **实现:**  它们直接操作 `__posix_spawnattr` 结构体的成员。
   - **与 Android 的关系:** Android 允许通过这些函数精细地控制新进程的属性，例如将新进程加入特定的进程组，设置其调度优先级，或设置其信号掩码。

6. **辅助函数 (`set_cloexec`, `cloexec_except_stdioe`)**:
   - **`set_cloexec(int i)`**: 设置指定文件描述符的 close-on-exec 标志。当进程执行 `execve` 时，如果文件描述符设置了这个标志，则该文件描述符会被关闭。
   - **`cloexec_except_stdioe()`**:  尝试使用 `close_range` 系统调用（如果可用）关闭除标准输入/输出/错误之外的所有文件描述符的 close-on-exec 标志。如果 `close_range` 不可用，则会遍历所有可能的文件描述符并逐个设置。
   - **与 Android 的关系:**  在创建新进程时，通常希望子进程只继承必要的文件描述符。设置 close-on-exec 标志是一种常见的做法，可以避免子进程意外地持有父进程的文件资源。

**libc 函数实现细节**

- **`fork()`**:  `fork` 是一个系统调用，用于创建一个新的进程，该进程是调用进程的精确副本（内存空间、寄存器等）。父子进程拥有相同的代码，但数据是独立的（写时复制）。
- **`vfork()`**: 类似于 `fork`，但子进程会共享父进程的内存空间，直到调用 `execve` 或 `_exit`。这使得 `vfork` 更快，但也更危险，因为子进程的任何修改都会影响父进程。
- **`execve(const char *pathname, char *const argv[], char *const envp[])`**:  `execve` 是一个系统调用，用于用新的程序替换当前进程的映像。它加载并执行由 `pathname` 指定的可执行文件，使用 `argv` 作为命令行参数，并使用 `envp` 作为环境变量。
- **`open()`, `close()`, `dup2()`, `chdir()`, `fchdir()`**: 这些都是标准的文件操作相关的系统调用，用于打开文件、关闭文件、复制文件描述符、改变当前工作目录。
- **`setpgid()`, `setsid()`**:  用于设置进程组 ID 和创建新的会话。
- **`sched_setscheduler()`, `sched_setparam()`**:  用于设置进程的调度策略和参数。
- **`seteuid()`, `setegid()`**:  用于设置进程的有效用户 ID 和有效组 ID。
- **`sigprocmask64()`**:  用于设置和检查进程的信号掩码，控制哪些信号会被阻塞。
- **`sigaction64()`**: 用于检查和修改特定信号的处理方式。
- **`getrlimit()`**: 用于获取进程的资源限制。
- **`fcntl()`**:  用于对打开的文件描述符执行各种控制操作，包括获取和设置文件描述符标志（如 FD_CLOEXEC）。
- **`close_range()`**:  一个 Linux 系统调用，用于原子地关闭指定范围内的文件描述符，并可以指定只关闭设置了 close-on-exec 标志的文件描述符。

**涉及 dynamic linker 的功能**

`spawn.cpp` 本身并不直接操作 dynamic linker。Dynamic linker 的介入发生在 `execve` 系统调用被执行时。

**so 布局样本:**

假设我们要执行的程序 `my_app` 依赖于共享库 `libmylib.so`。

```
/system/bin/my_app      (可执行文件)
/system/lib/libmylib.so (共享库)
```

**链接的处理过程:**

1. **`execve` 调用:** 当 `posix_spawn` 最终调用 `execve("/system/bin/my_app", ...)` 时，内核会加载 `my_app` 的可执行文件头。
2. **识别 Interpreter:** 内核在可执行文件头中找到一个特殊的段（`.interp`），其中包含了 dynamic linker 的路径，通常是 `/system/bin/linker64` 或 `/system/bin/linker`。
3. **启动 Dynamic Linker:** 内核启动 dynamic linker，并将控制权交给它。
4. **加载依赖库:** Dynamic linker 读取 `my_app` 的 ELF 文件头中的 `DT_NEEDED` 条目，这些条目列出了 `my_app` 依赖的共享库。
5. **搜索共享库:** Dynamic linker 根据一定的规则（通常查看 `LD_LIBRARY_PATH` 环境变量和系统默认路径）搜索这些共享库，例如 `libmylib.so`。
6. **加载共享库:** Dynamic linker 将找到的共享库加载到内存中。
7. **符号解析和重定位:** Dynamic linker 解析 `my_app` 和其依赖的共享库中的符号表，解决符号引用关系。例如，如果 `my_app` 中调用了 `libmylib.so` 中的函数，dynamic linker 会将这些调用指向 `libmylib.so` 中相应的函数地址。这个过程称为重定位。
8. **执行程序:** 完成所有必要的加载和链接后，dynamic linker 将控制权交给 `my_app` 的入口点。

**逻辑推理（假设输入与输出）**

假设我们使用 `posix_spawn` 创建一个新进程，执行 `/system/bin/ls -l`，并将标准输出重定向到一个文件。

**假设输入:**

- `path`: "/system/bin/ls"
- `argv`: {"ls", "-l", nullptr}
- `env`: (继承父进程的环境变量)
- `actions`: 一个 `posix_spawn_file_actions_t` 结构，其中添加了一个打开文件并将文件描述符 3 (通常是标准输出的副本) dup2 到 1 (标准输出) 的操作。 例如：
  ```c
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_addopen(&actions, 3, "/sdcard/ls_output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0660);
  posix_spawn_file_actions_adddup2(&actions, 3, 1);
  posix_spawn_file_actions_addclose(&actions, 3);
  ```
- `attr`:  可以为空，表示使用默认属性。

**预期输出:**

- 创建一个新的子进程。
- 在子进程中，执行 `/system/bin/ls -l` 命令。
- 子进程的标准输出会被重定向到 `/sdcard/ls_output.txt` 文件。
- 父进程继续执行。

**用户或编程常见的使用错误**

1. **忘记初始化或销毁 `posix_spawn_file_actions_t` 或 `posix_spawnattr_t`**:  如果不调用 `*_init` 进行初始化，结构体可能包含垃圾数据，导致未定义的行为。不调用 `*_destroy` 会导致内存泄漏。
2. **错误的文件描述符管理**:  在 `posix_spawn_file_actions_adddup2` 中使用无效的文件描述符，或者忘记关闭不再需要的文件描述符。
3. **信号处理不当**:  没有正确设置信号掩码可能导致子进程接收到不期望的信号。
4. **路径错误**:  在 `posix_spawn` 或 `posix_spawnp` 中提供了错误的可执行文件路径。
5. **环境变量问题**:  子进程可能依赖于特定的环境变量，如果父进程没有正确设置，可能导致子进程运行失败。
6. **权限问题**:  尝试执行没有执行权限的文件。
7. **资源限制**:  子进程可能因为资源限制（例如，打开的文件数量）而运行失败。

**示例：忘记初始化 `posix_spawn_file_actions_t`**

```c
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    pid_t pid;
    char *argv[] = {"/system/bin/ls", "-l", NULL};

    // 错误：忘记初始化 actions
    posix_spawn_file_actions_t actions;

    int ret = posix_spawn(&pid, "/system/bin/ls", &actions, NULL, argv, NULL);
    if (ret != 0) {
        perror("posix_spawn failed");
        return 1;
    }
    return 0;
}
```

在这个例子中，`actions` 未被初始化，其内容是未定义的，传递给 `posix_spawn` 可能会导致程序崩溃或者产生不可预测的行为。正确的做法是先调用 `posix_spawn_file_actions_init(&actions);`。

**Android Framework 或 NDK 如何到达这里**

**Android Framework:**

1. **应用启动请求:**  例如，当用户点击一个应用图标时，`Launcher` 应用会发起一个启动新 Activity 的请求。
2. **ActivityManagerService (AMS):**  系统服务 `ActivityManagerService` 负责管理应用的生命周期。它接收到启动 Activity 的请求。
3. **Process 启动:** AMS 决定需要创建一个新的进程来运行该 Activity（如果该应用还没有运行）。
4. **Zygote 进程:** AMS 会向 `Zygote` 进程发送一个 fork 请求。`Zygote` 是 Android 系统中所有应用进程的父进程，它预先加载了常用的库和资源，以加速新进程的创建。
5. **`fork()` 系统调用:** `Zygote` 进程调用 `fork()` 创建一个自身的副本。
6. **进程初始化:**  在 `fork` 之后，子进程会进行一些初始化操作，例如设置进程组 ID 等。
7. **`execve()` 或 `posix_spawn()`:**  最终，为了执行应用的入口点，AMS 或 `Zygote` 的子进程会调用 `execve()` 或 `posix_spawn()` 来替换当前进程的映像为应用的代码。在较新的 Android 版本中，更倾向于使用 `posix_spawn` 以获得更精细的控制。具体调用哪个函数取决于具体的实现细节。

**Android NDK:**

1. **NDK 应用调用:**  NDK 应用可以使用标准的 POSIX API，包括 `posix_spawn` 和 `posix_spawnp`。
2. **直接调用:**  NDK 代码可以直接包含 `<spawn.h>` 并调用 `posix_spawn` 或 `posix_spawnp` 函数。
3. **Bionic 库链接:**  NDK 应用在编译时会链接到 Bionic 库，因此对 `posix_spawn` 的调用会直接跳转到 `bionic/libc/bionic/spawn.cpp` 中实现的函数。

**Frida Hook 示例调试步骤**

假设我们想要 hook `posix_spawn` 函数，查看其被调用时的参数。

```python
import frida
import sys

# 要 hook 的目标进程
package_name = "com.example.myapp" # 替换为你的应用包名

# Frida 脚本
js_code = """
Interceptor.attach(Module.findExportByName("libc.so", "posix_spawn"), {
  onEnter: function(args) {
    console.log("posix_spawn called!");
    console.log("  pid_ptr:", args[0]);
    console.log("  path:", Memory.readUtf8String(args[1]));
    console.log("  file_actions:", args[2]);
    console.log("  attr:", args[3]);
    console.log("  argv:", this.arrayToString(args[4]));
    console.log("  env:", this.arrayToString(args[5]));
  },
  onLeave: function(retval) {
    console.log("posix_spawn returned:", retval);
  },
  arrayToString: function(arrayPtr) {
    if (arrayPtr.isNull()) {
      return "NULL";
    }
    var strings = [];
    var i = 0;
    while (true) {
      var element = Memory.readPointer(arrayPtr.add(i * Process.pointerSize));
      if (element.isNull()) {
        break;
      }
      strings.push(Memory.readUtf8String(element));
      i++;
    }
    return "[" + strings.join(", ") + "]";
  }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()  # Keep the script running
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
except Exception as e:
    print(e)
```

**调试步骤:**

1. **安装 Frida:** 确保你的开发机器和 Android 设备上都安装了 Frida。
2. **运行目标应用:** 启动你想要监控的应用。
3. **运行 Frida 脚本:** 执行上面的 Python 脚本。将 `com.example.myapp` 替换为你实际应用的包名。
4. **触发 `posix_spawn` 调用:**  在你的应用中执行会导致调用 `posix_spawn` 的操作，例如启动一个新的进程。
5. **查看 Frida 输出:** Frida 脚本会在 `posix_spawn` 被调用时打印出相关的参数，例如要执行的路径、参数列表和环境变量。

这个 Frida 示例提供了一种动态分析 `posix_spawn` 调用的方法，可以帮助开发者理解 Android 系统中进程创建的细节。

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/spawn.cpp` 文件的功能及其在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/spawn.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <spawn.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <android/fdsan.h>

#include "private/ScopedSignalBlocker.h"

static int set_cloexec(int i) {
  int v = fcntl(i, F_GETFD);
  if (v == -1) return -1;  // almost certainly: errno == EBADF
  return fcntl(i, F_SETFD, v | FD_CLOEXEC);
}

// mark all open fds except stdin/out/err as close-on-exec
static int cloexec_except_stdioe() {
  // requires 5.11+ or ACK 5.10-T kernel, otherwise returns ENOSYS or EINVAL
  if (!close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)) return 0;

  // unfortunately getrlimit can lie:
  // - both soft and hard limits can be lowered to 0, with fds still open, so it can underestimate
  // - in practice it usually is some really large value (like 32K or more)
  //   even though only a handful of small fds are actually open (ie. < 500),
  //   this results in poor performance when trying to act on all possibly open fds
  struct rlimit m;
  int max = getrlimit(RLIMIT_NOFILE, &m) ? 1000000 : m.rlim_max;
  for (int i = 3; i < max; ++i) set_cloexec(i);
  return 0;
}

enum Action {
  kOpen,
  kClose,
  kDup2,
  kChdir,
  kFchdir,
};

struct __posix_spawn_file_action {
  __posix_spawn_file_action* next;

  Action what;
  int fd;
  int new_fd;
  char* path;
  int flags;
  mode_t mode;

  void Do() {
    if (what == kOpen) {
      fd = open(path, flags, mode);
      if (fd == -1) _exit(127);
      // If it didn't land where we wanted it, move it.
      if (fd != new_fd) {
        if (dup2(fd, new_fd) == -1) _exit(127);
        close(fd);
      }
    } else if (what == kClose) {
      // Failure to close is ignored.
      close(fd);
    } else if (what == kChdir) {
      if (chdir(path) == -1) _exit(127);
    } else if (what == kFchdir) {
      if (fchdir(fd) == -1) _exit(127);
    } else {
      // It's a dup2.
      if (fd == new_fd) {
        // dup2(2) is a no-op if fd == new_fd, but POSIX suggests that we should
        // manually remove the O_CLOEXEC flag in that case (because otherwise
        // what use is the dup?).
        // See https://www.austingroupbugs.net/view.php?id=411 for details.
        int flags = fcntl(fd, F_GETFD, 0);
        if (flags == -1 || fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) == -1) _exit(127);
      } else {
        if (dup2(fd, new_fd) == -1) _exit(127);
      }
    }
  }
};

struct __posix_spawn_file_actions {
  __posix_spawn_file_action* head;
  __posix_spawn_file_action* last;

  void Do() {
    for (__posix_spawn_file_action* action = head; action != nullptr; action = action->next) {
      action->Do();
    }
  }
};

struct __posix_spawnattr {
  short flags;
  pid_t pgroup;
  sched_param schedparam;
  int schedpolicy;
  union {
    sigset_t sigset;
    sigset64_t sigset64;
  } sigmask, sigdefault;
};

static void ApplyAttrs(short flags, const posix_spawnattr_t* attr) {
  // POSIX: "If POSIX_SPAWN_SETSIGDEF is set ... signals in sigdefault ...
  // shall be set to their default actions in the child process."
  // POSIX: "Signals set to be caught by the calling process shall be
  // set to the default action in the child process."
  bool use_sigdefault = ((flags & POSIX_SPAWN_SETSIGDEF) != 0);
  const struct sigaction64 default_sa = { .sa_handler = SIG_DFL };
  for (int s = 1; s < _NSIG; ++s) {
    bool reset = false;
    if (use_sigdefault && sigismember64(&(*attr)->sigdefault.sigset64, s)) {
      reset = true;
    } else {
      struct sigaction64 current;
      if (sigaction64(s, nullptr, &current) == -1) _exit(127);
      reset = (current.sa_handler != SIG_IGN && current.sa_handler != SIG_DFL);
    }
    if (reset && sigaction64(s, &default_sa, nullptr) == -1) _exit(127);
  }

  if ((flags & POSIX_SPAWN_SETPGROUP) != 0 && setpgid(0, (*attr)->pgroup) == -1) _exit(127);
  if ((flags & POSIX_SPAWN_SETSID) != 0 && setsid() == -1) _exit(127);

  // POSIX_SPAWN_SETSCHEDULER overrides POSIX_SPAWN_SETSCHEDPARAM, but it is not an error
  // to set both.
  if ((flags & POSIX_SPAWN_SETSCHEDULER) != 0) {
    if (sched_setscheduler(0, (*attr)->schedpolicy, &(*attr)->schedparam) == -1) _exit(127);
  } else if ((flags & POSIX_SPAWN_SETSCHEDPARAM) != 0) {
    if (sched_setparam(0, &(*attr)->schedparam) == -1) _exit(127);
  }

  if ((flags & POSIX_SPAWN_RESETIDS) != 0) {
    if (seteuid(getuid()) == -1 || setegid(getgid()) == -1) _exit(127);
  }

  if ((flags & POSIX_SPAWN_SETSIGMASK) != 0) {
    if (sigprocmask64(SIG_SETMASK, &(*attr)->sigmask.sigset64, nullptr)) _exit(127);
  }

  if ((flags & POSIX_SPAWN_CLOEXEC_DEFAULT) != 0) {
    if (cloexec_except_stdioe()) _exit(127);
  }
}

static int posix_spawn(pid_t* pid_ptr,
                       const char* path,
                       const posix_spawn_file_actions_t* actions,
                       const posix_spawnattr_t* attr,
                       char* const argv[],
                       char* const env[],
                       int exec_fn(const char* path, char* const argv[], char* const env[])) {
  // See https://man7.org/linux/man-pages/man3/posix_spawn.3.html
  // and https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/posix_spawn.html

  ScopedSignalBlocker ssb;

  short flags = attr ? (*attr)->flags : 0;
  bool use_vfork = ((flags & POSIX_SPAWN_USEVFORK) != 0) || (actions == nullptr && flags == 0);

  pid_t pid = use_vfork ? vfork() : fork();
  if (pid == -1) return errno;

  if (pid == 0) {
    // Child.
    ApplyAttrs(flags, attr);
    if (actions) (*actions)->Do();
    if ((flags & POSIX_SPAWN_SETSIGMASK) == 0) ssb.reset();
    exec_fn(path, argv, env ? env : environ);
    _exit(127);
  }

  // Parent.
  if (pid_ptr) *pid_ptr = pid;
  return 0;
}

int posix_spawn(pid_t* pid, const char* path, const posix_spawn_file_actions_t* actions,
                const posix_spawnattr_t* attr, char* const argv[], char* const env[]) {
  return posix_spawn(pid, path, actions, attr, argv, env, execve);
}

int posix_spawnp(pid_t* pid, const char* file, const posix_spawn_file_actions_t* actions,
                 const posix_spawnattr_t* attr, char* const argv[], char* const env[]) {
  return posix_spawn(pid, file, actions, attr, argv, env, execvpe);
}

int posix_spawnattr_init(posix_spawnattr_t* attr) {
  *attr = reinterpret_cast<__posix_spawnattr*>(calloc(1, sizeof(__posix_spawnattr)));
  return (*attr == nullptr) ? errno : 0;
}

int posix_spawnattr_destroy(posix_spawnattr_t* attr) {
  free(*attr);
  *attr = nullptr;
  return 0;
}

int posix_spawnattr_setflags(posix_spawnattr_t* attr, short flags) {
  if ((flags & ~(POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF |
                 POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER |
                 POSIX_SPAWN_USEVFORK | POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT)) != 0) {
    return EINVAL;
  }
  (*attr)->flags = flags;
  return 0;
}

int posix_spawnattr_getflags(const posix_spawnattr_t* attr, short* flags) {
  *flags = (*attr)->flags;
  return 0;
}

int posix_spawnattr_setpgroup(posix_spawnattr_t* attr, pid_t pgroup) {
  (*attr)->pgroup = pgroup;
  return 0;
}

int posix_spawnattr_getpgroup(const posix_spawnattr_t* attr, pid_t* pgroup) {
  *pgroup = (*attr)->pgroup;
  return 0;
}

int posix_spawnattr_setsigmask(posix_spawnattr_t* attr, const sigset_t* mask) {
  (*attr)->sigmask.sigset = *mask;
  return 0;
}

int posix_spawnattr_setsigmask64(posix_spawnattr_t* attr, const sigset64_t* mask) {
  (*attr)->sigmask.sigset64 = *mask;
  return 0;
}

int posix_spawnattr_getsigmask(const posix_spawnattr_t* attr, sigset_t* mask) {
  *mask = (*attr)->sigmask.sigset;
  return 0;
}

int posix_spawnattr_getsigmask64(const posix_spawnattr_t* attr, sigset64_t* mask) {
  *mask = (*attr)->sigmask.sigset64;
  return 0;
}

int posix_spawnattr_setsigdefault(posix_spawnattr_t* attr, const sigset_t* mask) {
  (*attr)->sigdefault.sigset = *mask;
  return 0;
}

int posix_spawnattr_setsigdefault64(posix_spawnattr_t* attr, const sigset64_t* mask) {
  (*attr)->sigdefault.sigset64 = *mask;
  return 0;
}

int posix_spawnattr_getsigdefault(const posix_spawnattr_t* attr, sigset_t* mask) {
  *mask = (*attr)->sigdefault.sigset;
  return 0;
}

int posix_spawnattr_getsigdefault64(const posix_spawnattr_t* attr, sigset64_t* mask) {
  *mask = (*attr)->sigdefault.sigset64;
  return 0;
}

int posix_spawnattr_setschedparam(posix_spawnattr_t* attr, const struct sched_param* param) {
  (*attr)->schedparam = *param;
  return 0;
}

int posix_spawnattr_getschedparam(const posix_spawnattr_t* attr, struct sched_param* param) {
  *param = (*attr)->schedparam;
  return 0;
}

int posix_spawnattr_setschedpolicy(posix_spawnattr_t* attr, int policy) {
  (*attr)->schedpolicy = policy;
  return 0;
}

int posix_spawnattr_getschedpolicy(const posix_spawnattr_t* attr, int* policy) {
  *policy = (*attr)->schedpolicy;
  return 0;
}

int posix_spawn_file_actions_init(posix_spawn_file_actions_t* actions) {
  *actions = reinterpret_cast<__posix_spawn_file_actions*>(calloc(1, sizeof(**actions)));
  return (*actions == nullptr) ? errno : 0;
}

int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t* actions) {
  __posix_spawn_file_action* a = (*actions)->head;
  while (a) {
    __posix_spawn_file_action* last = a;
    a = a->next;
    free(last->path);
    free(last);
  }
  free(*actions);
  *actions = nullptr;
  return 0;
}

static int posix_spawn_add_file_action(posix_spawn_file_actions_t* actions,
                                       Action what,
                                       int fd,
                                       int new_fd,
                                       const char* path,
                                       int flags,
                                       mode_t mode) {
  __posix_spawn_file_action* action =
      reinterpret_cast<__posix_spawn_file_action*>(malloc(sizeof(*action)));
  if (action == nullptr) return errno;

  action->next = nullptr;
  if (what == kOpen || what == kChdir) {
    action->path = strdup(path);
    if (action->path == nullptr) {
      free(action);
      return errno;
    }
  } else {
    action->path = nullptr;
  }
  action->what = what;
  action->fd = fd;
  action->new_fd = new_fd;
  action->flags = flags;
  action->mode = mode;

  if ((*actions)->head == nullptr) {
    (*actions)->head = (*actions)->last = action;
  } else {
    (*actions)->last->next = action;
    (*actions)->last = action;
  }

  return 0;
}

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t* actions,
                                     int fd, const char* path, int flags, mode_t mode) {
  if (fd < 0) return EBADF;
  return posix_spawn_add_file_action(actions, kOpen, -1, fd, path, flags, mode);
}

int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t* actions, int fd) {
  if (fd < 0) return EBADF;
  return posix_spawn_add_file_action(actions, kClose, fd, -1, nullptr, 0, 0);
}

int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t* actions, int fd, int new_fd) {
  if (fd < 0 || new_fd < 0) return EBADF;
  return posix_spawn_add_file_action(actions, kDup2, fd, new_fd, nullptr, 0, 0);
}

int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t* actions, const char* path) {
  return posix_spawn_add_file_action(actions, kChdir, -1, -1, path, 0, 0);
}

int posix_spawn_file_actions_addfchdir_np(posix_spawn_file_actions_t* actions, int fd) {
  if (fd < 0) return EBADF;
  return posix_spawn_add_file_action(actions, kFchdir, fd, -1, nullptr, 0, 0);
}
```