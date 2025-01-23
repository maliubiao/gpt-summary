Response:
Let's break down the thought process for answering the request about `bionic/libc/include/spawn.handroid`.

**1. Understanding the Core Request:**

The fundamental request is to analyze the provided header file (`spawn.handroid`) and explain its functionality within the context of Android's Bionic library. The request also specifies several key areas to address: functionality, Android relevance, detailed function explanations, dynamic linker aspects, logical reasoning (input/output), common errors, and how Android Framework/NDK reaches this point, along with a Frida hook example.

**2. Initial Code Analysis (Scanning for Clues):**

The first step is to quickly scan the code for keywords and patterns. I immediately notice:

* **Copyright:**  Indicates this is official Android code.
* **`#ifndef _SPAWN_H_`:** Standard header guard.
* **Includes:**  `sys/cdefs.h`, `sys/types.h`, `sched.h`, `signal.h` - hints at system-level functionalities related to processes, scheduling, and signals.
* **`POSIX_SPAWN_*` macros:**  These are the most significant clues. They clearly point to the `posix_spawn` family of functions.
* **`typedef struct __posix_spawnattr* posix_spawnattr_t;` and `typedef struct __posix_spawn_file_actions* posix_spawn_file_actions_t;`:** Defines opaque types for attributes and file actions, suggesting a way to customize the spawning process.
* **Function Declarations:**  A series of function declarations starting with `posix_spawn`, `posix_spawnattr_`, and `posix_spawn_file_actions_`. The naming convention clearly indicates their purpose.
* **`__INTRODUCED_IN(28)` and `__INTRODUCED_IN(34)`:**  These are Android-specific availability guards, indicating the API level at which these functions were introduced. This is crucial for understanding Android relevance.
* **`__BEGIN_DECLS` and `__END_DECLS`:**  Standard C idiom for ensuring proper C linkage when used in C++ code.

**3. Identifying Key Functionality:**

Based on the `POSIX_SPAWN_*` macros and function names, the core functionality is clearly related to **process creation**. The "POSIX" prefix indicates adherence to POSIX standards for process spawning. The `attr` and `file_actions` types suggest the ability to configure various aspects of the new process.

**4. Connecting to Android:**

The `__INTRODUCED_IN` macros directly link these functions to specific Android API levels. This immediately establishes their relevance to the Android operating system. The purpose of these functions within Android is to provide a more controlled and efficient way to create new processes compared to the traditional `fork`/`exec` combination. This is particularly important for Android's process model.

**5. Detailed Function Explanation (Mental Model):**

For each function, I mentally outline its purpose and parameters:

* **`posix_spawn` and `posix_spawnp`:** The main functions for creating a new process. The 'p' version searches the `PATH` environment variable. They take arguments for the executable path, arguments, environment, attributes, and file actions.
* **`posix_spawnattr_*` functions:**  Functions to initialize, destroy, set, and get various attributes that control the spawning process (e.g., flags, process group, signal mask, scheduling).
* **`posix_spawn_file_actions_*` functions:**  Functions to initialize, destroy, and add actions related to file descriptors that should be performed in the child process before execution (e.g., opening, closing, duplicating file descriptors, changing directories).

**6. Dynamic Linker Considerations:**

While the header file itself doesn't directly *implement* dynamic linking, the act of spawning a new process *involves* the dynamic linker. The child process needs to load its shared libraries. Therefore, I need to address:

* **SO Layout:** A typical Android app's directory structure with `.so` files in `lib` or `libs` folders.
* **Linking Process:** Briefly explain how the dynamic linker (`/system/bin/linker64` or `/system/bin/linker`) is involved in resolving dependencies and loading shared libraries in the child process.

**7. Logical Reasoning (Input/Output):**

For a simple example, consider `posix_spawn`. I can imagine:

* **Input:**  Path to an executable (`/system/bin/ls`), arguments (`-l`), environment variables (some defaults), empty attributes and file actions.
* **Output:**  A new process running the `ls -l` command. The parent process receives the PID of the child.

**8. Common Usage Errors:**

Think about typical mistakes developers make when dealing with process creation:

* Incorrect path to the executable.
* Missing or incorrect arguments.
* Improperly setting file actions (e.g., forgetting to close unnecessary file descriptors).
* Not handling errors from `posix_spawn`.

**9. Android Framework/NDK and Frida Hooking:**

I need to trace how a request from the Android framework (e.g., starting an Activity) or from native code using the NDK can eventually lead to a call to `posix_spawn`. The general flow involves:

* **Framework:** Activity Manager -> Process creation logic (often using `Runtime.exec` which eventually might use `posix_spawn` internally).
* **NDK:** Direct calls to `posix_spawn` from native C/C++ code.

For Frida, the key is to hook the `posix_spawn` or `posix_spawnp` functions to intercept process creation attempts. The hook should log relevant information like the path and arguments.

**10. Structuring the Answer:**

Finally, I organize the information logically based on the request's components: functionality, Android relevance, function details, dynamic linking, reasoning, errors, and the Android pathway with a Frida example. I use clear headings and bullet points for readability.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the details of each flag or attribute. I need to remember the high-level purpose and avoid getting bogged down in minute specifics unless the request specifically asks for it.
* I need to ensure the explanations are accessible to someone with a general understanding of operating systems and C programming, even if they aren't a Bionic expert.
* I should double-check the API level information provided by the `__INTRODUCED_IN` macros to ensure accuracy.

By following this thought process, I can systematically analyze the provided header file and generate a comprehensive and informative answer that addresses all aspects of the request.
这个C头文件 `bionic/libc/include/spawn.handroid` 定义了与 POSIX 进程生成相关的函数和宏。它是 Android Bionic C 库的一部分，Bionic 库负责提供操作系统接口，包括进程管理、文件操作、网络等。

**功能列举：**

这个头文件主要定义了以下功能，用于创建和管理新的进程：

1. **`posix_spawn` 和 `posix_spawnp` 函数:**
   - 用于创建一个新的子进程，并可以精确控制子进程的属性，例如文件描述符、信号掩码、调度策略等。
   - `posix_spawn` 需要提供要执行的程序的完整路径。
   - `posix_spawnp` 会在 `PATH` 环境变量指定的目录中搜索要执行的程序。

2. **`posix_spawnattr_*` 函数族:**
   - 用于操作 `posix_spawnattr_t` 类型的属性对象，这些对象用于指定 `posix_spawn` 和 `posix_spawnp` 创建的子进程的各种属性。
   - `posix_spawnattr_init`: 初始化一个属性对象。
   - `posix_spawnattr_destroy`: 销毁一个属性对象。
   - `posix_spawnattr_setflags`: 设置属性标志，例如是否重置信号处理、设置进程组等。
   - `posix_spawnattr_getflags`: 获取属性标志。
   - `posix_spawnattr_setpgroup`: 设置子进程的进程组 ID。
   - `posix_spawnattr_getpgroup`: 获取子进程的进程组 ID。
   - `posix_spawnattr_setsigmask` 和 `posix_spawnattr_setsigmask64`: 设置子进程的信号掩码。
   - `posix_spawnattr_getsigmask` 和 `posix_spawnattr_getsigmask64`: 获取子进程的信号掩码。
   - `posix_spawnattr_setsigdefault` 和 `posix_spawnattr_setsigdefault64`: 设置子进程的信号处理为默认行为。
   - `posix_spawnattr_getsigdefault` 和 `posix_spawnattr_getsigdefault64`: 获取子进程的默认信号处理。
   - `posix_spawnattr_setschedparam`: 设置子进程的调度参数（例如优先级）。
   - `posix_spawnattr_getschedparam`: 获取子进程的调度参数。
   - `posix_spawnattr_setschedpolicy`: 设置子进程的调度策略（例如 FIFO, RR, OTHER）。
   - `posix_spawnattr_getschedpolicy`: 获取子进程的调度策略。

3. **`posix_spawn_file_actions_*` 函数族:**
   - 用于操作 `posix_spawn_file_actions_t` 类型的文件操作对象，这些对象用于指定在子进程执行之前要进行的文件操作，例如打开、关闭、复制文件描述符。
   - `posix_spawn_file_actions_init`: 初始化一个文件操作对象。
   - `posix_spawn_file_actions_destroy`: 销毁一个文件操作对象。
   - `posix_spawn_file_actions_addopen`: 在子进程中打开一个文件。
   - `posix_spawn_file_actions_addclose`: 在子进程中关闭一个文件描述符。
   - `posix_spawn_file_actions_adddup2`: 在子进程中复制一个文件描述符。
   - `posix_spawn_file_actions_addchdir_np`: (Android 特有) 在子进程中改变当前工作目录。
   - `posix_spawn_file_actions_addfchdir_np`: (Android 特有) 在子进程中使用文件描述符改变当前工作目录。

4. **宏定义:**
   - `POSIX_SPAWN_RESETIDS`:  在子进程中重置有效用户 ID 和组 ID 为实际用户 ID 和组 ID。
   - `POSIX_SPAWN_SETPGROUP`: 在子进程中设置进程组 ID。
   - `POSIX_SPAWN_SETSIGDEF`: 在子进程中将指定的信号处理设置为默认行为。
   - `POSIX_SPAWN_SETSIGMASK`: 在子进程中设置信号掩码。
   - `POSIX_SPAWN_SETSCHEDPARAM`: 在子进程中设置调度参数。
   - `POSIX_SPAWN_SETSCHEDULER`: 在子进程中设置调度策略。
   - `POSIX_SPAWN_USEVFORK`: (GNU 扩展)  尝试使用 `vfork` 而不是 `fork` (在 Android 中可能没有实际效果或已被优化掉)。
   - `POSIX_SPAWN_SETSID`: (GNU 扩展) 在子进程中创建一个新的会话。
   - `POSIX_SPAWN_CLOEXEC_DEFAULT`: 将除 stdin/stdout/stderr 之外的所有文件描述符设置为 `O_CLOEXEC`，防止子进程继承这些文件描述符。

**与 Android 功能的关系及举例说明：**

这些函数在 Android 中被广泛用于启动新的进程，这对于 Android 的应用模型至关重要。Android 应用程序通常运行在独立的进程中。

* **启动应用组件 (Activity, Service, BroadcastReceiver)：** 当 Android Framework 需要启动一个新的 Activity 或 Service 时，底层的实现可能会使用 `posix_spawn` 或 `posix_spawnp` 来创建新的进程。例如，当用户点击一个应用图标时，`ActivityManagerService` 可能会使用这些函数来启动应用的进程。

* **执行 shell 命令：**  Java 中的 `Runtime.exec()` 和 `ProcessBuilder` 最终可能会通过 JNI 调用到 native 层，并使用 `posix_spawn` 或 `posix_spawnp` 来执行 shell 命令。例如，应用需要执行 `ls -l` 命令来列出目录内容。

* **`app_process` 和 zygote:** Android 的进程创建机制中，`zygote` 进程会 fork 出新的应用进程。虽然 `zygote` 主要使用 `fork` 系统调用，但在某些场景下，或者在更底层的实现细节中，可能会涉及到 `posix_spawn` 的使用。

* **NDK 开发:**  使用 NDK 进行 native 开发的开发者可以直接调用这些函数来创建和管理子进程。例如，一个游戏引擎可能需要在后台创建一个独立的进程来处理某些任务。

**详细解释每一个 libc 函数的功能是如何实现的：**

这些函数的具体实现位于 Bionic 库的源代码中，通常在 `bionic/libc/bionic/` 或 `bionic/libc/src/` 目录下。由于你只提供了头文件，我无法直接看到实现代码，但我可以描述其大致的工作原理：

1. **`posix_spawn` 和 `posix_spawnp`:**
   - **参数处理:** 验证输入参数，例如路径是否有效，`argv` 和 `env` 是否正确。
   - **属性应用:** 根据传入的 `posix_spawnattr_t` 对象，设置子进程的属性，例如信号掩码、进程组、调度策略等。这通常涉及到调用底层的系统调用，如 `setpgid`、`sigprocmask`、`sched_setscheduler` 等。
   - **文件操作:**  根据传入的 `posix_spawn_file_actions_t` 对象，在 fork 之后，exec 之前执行指定的文件操作，例如打开、关闭、复制文件描述符。这通常涉及到调用 `open`、`close`、`dup2` 等系统调用。
   - **`fork`:**  调用 `fork` 系统调用创建一个新的子进程。
   - **子进程执行:** 在子进程中，调用 `execve` (对于 `posix_spawn`) 或执行路径查找后调用 `execve` (对于 `posix_spawnp`) 来加载并执行新的程序。
   - **错误处理:** 在整个过程中进行错误检查，并在出错时返回相应的错误码。

2. **`posix_spawnattr_*` 函数族:**
   - 这些函数主要操作 `posix_spawnattr_t` 结构体中的成员变量。
   - `_init` 函数会分配并初始化结构体内存。
   - `_destroy` 函数会释放结构体内存。
   - `_set*` 函数会将传入的值设置到结构体的相应字段中。
   - `_get*` 函数会从结构体的相应字段中读取值。

3. **`posix_spawn_file_actions_*` 函数族:**
   - 这些函数操作 `posix_spawn_file_actions_t` 结构体，该结构体可能维护一个文件操作列表。
   - `_init` 函数会分配并初始化结构体。
   - `_destroy` 函数会释放结构体。
   - `_add*` 函数会将对应的文件操作添加到列表当中，例如 `_addopen` 会记录需要打开的文件路径、标志和模式。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`posix_spawn` 本身并不直接处理动态链接，但它创建的新进程会涉及到动态链接。当子进程执行 `execve` 时，内核会加载指定的 ELF 文件，并启动动态链接器来解析和加载程序依赖的共享库 (.so 文件)。

**SO 布局样本：**

假设我们要启动一个名为 `my_app` 的可执行文件，它依赖于 `libutils.so` 和 `libcutils.so`。

```
/system/
    bin/
        my_app  // 可执行文件
    lib64/ (或 lib/，取决于架构)
        libutils.so
        libcutils.so
```

**链接的处理过程：**

1. **`execve` 调用:** 当 `posix_spawn` 创建的子进程执行 `execve("/system/bin/my_app", ...)` 时，内核会识别 `my_app` 是一个 ELF 可执行文件。
2. **加载程序头部:** 内核会读取 `my_app` 的程序头部（Program Header），查找 `PT_INTERP` 段，该段指定了动态链接器的路径，通常是 `/system/bin/linker64` (对于 64 位) 或 `/system/bin/linker` (对于 32 位)。
3. **启动动态链接器:** 内核会将控制权交给动态链接器。
4. **加载依赖库:** 动态链接器会读取 `my_app` 的 `.dynamic` 段，其中包含了程序依赖的共享库的信息（例如 `NEEDED` 条目）。
5. **搜索共享库:** 动态链接器会在预定义的路径中搜索这些共享库，这些路径通常包括 `/system/lib64`、`/vendor/lib64`、`/data/app/<package_name>/lib/<abi>` 等。环境变量 `LD_LIBRARY_PATH` 也可以影响搜索路径。
6. **加载和链接:** 找到共享库后，动态链接器会将它们加载到进程的内存空间，并解析符号引用，将 `my_app` 中对共享库函数的调用地址链接到共享库中对应的函数地址。
7. **执行程序:** 动态链接完成后，动态链接器会将控制权交给 `my_app` 的入口点，程序开始执行。

**如果做了逻辑推理，请给出假设输入与输出：**

假设我们调用 `posix_spawn` 来启动 `/system/bin/ls -l /data` 命令。

**假设输入：**

```c
pid_t pid;
const char *path = "/system/bin/ls";
char *const argv[] = {"ls", "-l", "/data", NULL};
char *const envp[] = {NULL}; // 使用默认环境变量
posix_spawnattr_t attr;
posix_spawn_file_actions_t actions;

posix_spawnattr_init(&attr);
posix_spawn_file_actions_init(&actions);

int result = posix_spawn(&pid, path, &actions, &attr, argv, envp);

posix_spawn_file_actions_destroy(&actions);
posix_spawnattr_destroy(&attr);
```

**假设输出：**

- 如果 `posix_spawn` 调用成功，`result` 将为 0，并且 `pid` 将包含新创建的子进程的进程 ID。
- 新创建的子进程将执行 `ls -l /data` 命令，并在其标准输出打印 `/data` 目录下的文件列表。
- 父进程可以继续执行后续代码。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **路径错误：**  `posix_spawn` 或 `posix_spawnp` 指定的程序路径不存在或不可执行。

   ```c
   pid_t pid;
   const char *path = "/path/that/does/not/exist"; // 错误路径
   char *const argv[] = {"some_command", NULL};
   // ...
   int result = posix_spawn(&pid, path, NULL, NULL, argv, NULL);
   if (result != 0) {
       perror("posix_spawn failed"); // 可能会输出 "posix_spawn failed: No such file or directory"
   }
   ```

2. **参数错误：** 传递给 `argv` 的参数不正确或缺失 `NULL` 终止符。

   ```c
   pid_t pid;
   const char *path = "/system/bin/ls";
   char *const argv[] = {"ls", "-l", "/data"}; // 缺少 NULL 终止符
   // ...
   int result = posix_spawn(&pid, path, NULL, NULL, argv, NULL);
   // 这可能会导致未定义的行为
   ```

3. **环境变量错误：**  传递给 `envp` 的环境变量格式不正确或缺少 `NULL` 终止符。

4. **文件描述符泄露：** 在使用 `posix_spawn_file_actions_addopen` 等操作时，没有正确地管理文件描述符，可能导致子进程继承了不应该继承的文件描述符。

5. **忽略返回值：** 没有检查 `posix_spawn` 等函数的返回值，导致错误发生时无法及时处理。

6. **属性或文件操作对象未初始化或未销毁：**

   ```c
   pid_t pid;
   const char *path = "/system/bin/ls";
   char *const argv[] = {"ls", NULL};
   posix_spawnattr_t attr; // 未初始化
   // ...
   int result = posix_spawn(&pid, path, NULL, &attr, argv, NULL); // 可能会导致错误或未定义行为

   posix_spawnattr_t attr;
   posix_spawnattr_init(&attr);
   // ... 使用 attr ...
   // 忘记调用 posix_spawnattr_destroy(&attr); 可能导致内存泄漏
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `posix_spawn` 的路径：**

1. **应用层请求:**  例如，用户点击应用图标启动一个 Activity，或者应用调用 `startService()` 启动一个 Service。
2. **Activity Manager Service (AMS):**  Framework 层的 `ActivityManagerService` 负责管理应用的生命周期和进程。当需要启动一个新的应用组件时，AMS 会决定是否需要创建一个新的进程。
3. **Process 启动流程:** AMS 会调用相关的方法来启动进程，例如 `startProcessLocked()`。
4. **Zygote 进程:** Android 系统通常使用 `zygote` 进程作为孵化器来创建新的应用进程。AMS 会向 `zygote` 进程发送请求，要求 `zygote` `fork` 出一个新的进程。
5. **`fork` 和 `execve` (或可能的 `posix_spawn`):** 虽然 `zygote` 主要使用 `fork` 系统调用，但在某些情况下，或者在更底层的实现中，可能会使用 `posix_spawn` 来更精确地控制新进程的创建。 例如，执行 shell 命令或者启动独立的 native 进程时，可能会使用 `posix_spawn`。
6. **Native 代码:**  AMS 的某些部分，以及 `zygote` 进程本身都是用 C++ 编写的，因此可以直接调用 `posix_spawn` 函数。

**NDK 到 `posix_spawn` 的路径：**

1. **NDK 代码调用:**  使用 NDK 进行 native 开发的开发者可以直接在 C/C++ 代码中包含 `<spawn.h>` 头文件，并调用 `posix_spawn` 或 `posix_spawnp` 函数。

   ```c++
   #include <spawn.h>
   #include <unistd.h>
   #include <sys/wait.h>

   void spawn_process() {
       pid_t pid;
       const char *path = "/system/bin/ls";
       char *const argv[] = {"ls", "-l", NULL};
       char *const envp[] = {NULL};

       int result = posix_spawn(&pid, path, nullptr, nullptr, argv, envp);
       if (result == 0) {
           waitpid(pid, nullptr, 0); // 等待子进程结束
       } else {
           // 处理错误
       }
   }
   ```

**Frida Hook 示例：**

可以使用 Frida 来 hook `posix_spawn` 或 `posix_spawnp` 函数，以观察进程创建的过程。

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 {package_name} 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "posix_spawn"), {
    onEnter: function(args) {
        var path = Memory.readUtf8String(args[1]);
        var argv = [];
        if (args[4] != 0) {
            for (var i = 0; ; i++) {
                var arg = Memory.readPointer(args[4].add(i * Process.pointerSize));
                if (arg == 0)
                    break;
                argv.push(Memory.readUtf8String(arg));
            }
        }
        console.log("[posix_spawn] path: " + path);
        console.log("[posix_spawn] argv: " + argv.join(" "));
    },
    onLeave: function(retval) {
        console.log("[posix_spawn] returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "posix_spawnp"), {
    onEnter: function(args) {
        var file = Memory.readUtf8String(args[1]);
        var argv = [];
        if (args[4] != 0) {
            for (var i = 0; ; i++) {
                var arg = Memory.readPointer(args[4].add(i * Process.pointerSize));
                if (arg == 0)
                    break;
                argv.push(Memory.readUtf8String(arg));
            }
        }
        console.log("[posix_spawnp] file: " + file);
        console.log("[posix_spawnp] argv: " + argv.join(" "));
    },
    onLeave: function(retval) {
        console.log("[posix_spawnp] returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. 将上述 Python 代码保存为 `hook_spawn.py`。
2. 确保已安装 Frida 和 frida-tools (`pip install frida frida-tools`)。
3. 确保你的 Android 设备已连接并通过 adb 连接到电脑。
4. 将 `package_name` 替换为你想要监控的应用的包名。
5. 运行 `python hook_spawn.py`。
6. 在你的 Android 设备上操作目标应用，例如启动新的 Activity 或执行某些操作。
7. Frida 会拦截对 `posix_spawn` 和 `posix_spawnp` 的调用，并打印出被执行的路径和参数。

这个 Frida 脚本会 hook `libc.so` 中的 `posix_spawn` 和 `posix_spawnp` 函数。当这些函数被调用时，`onEnter` 函数会被执行，它会读取并打印出被执行的程序路径和参数。`onLeave` 函数会在函数执行完毕后被调用，并打印返回值。通过这种方式，你可以观察到 Android Framework 或 NDK 在哪些场景下使用了这些函数来创建新的进程。

### 提示词
```
这是目录为bionic/libc/include/spawn.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _SPAWN_H_
#define _SPAWN_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sched.h>
#include <signal.h>

__BEGIN_DECLS

#define POSIX_SPAWN_RESETIDS 1
#define POSIX_SPAWN_SETPGROUP 2
#define POSIX_SPAWN_SETSIGDEF 4
#define POSIX_SPAWN_SETSIGMASK 8
#define POSIX_SPAWN_SETSCHEDPARAM 16
#define POSIX_SPAWN_SETSCHEDULER 32
#if defined(__USE_GNU)
#define POSIX_SPAWN_USEVFORK 64
#define POSIX_SPAWN_SETSID 128
#endif
/**
 * Used with posix_spawnattr_setflags() to mark all fds except
 * stdin/stdout/stderr as O_CLOEXEC prior to executing registered file actions.
 */
#define POSIX_SPAWN_CLOEXEC_DEFAULT 256

typedef struct __posix_spawnattr* posix_spawnattr_t;
typedef struct __posix_spawn_file_actions* posix_spawn_file_actions_t;


#if __BIONIC_AVAILABILITY_GUARD(28)
int posix_spawn(pid_t* _Nullable __pid, const char* _Nonnull __path, const posix_spawn_file_actions_t _Nullable * _Nullable __actions, const posix_spawnattr_t _Nullable * _Nullable __attr, char* const _Nullable __argv[_Nullable], char* const _Nullable __env[_Nullable]) __INTRODUCED_IN(28);
int posix_spawnp(pid_t* _Nullable __pid, const char* _Nonnull __file, const posix_spawn_file_actions_t _Nullable * _Nullable __actions, const posix_spawnattr_t _Nullable * _Nullable __attr, char* const _Nullable __argv[_Nullable], char* const _Nullable __env[_Nullable]) __INTRODUCED_IN(28);

int posix_spawnattr_init(posix_spawnattr_t _Nullable * _Nonnull __attr) __INTRODUCED_IN(28);
int posix_spawnattr_destroy(posix_spawnattr_t _Nonnull * _Nonnull __attr) __INTRODUCED_IN(28);

int posix_spawnattr_setflags(posix_spawnattr_t _Nonnull * _Nonnull __attr, short __flags) __INTRODUCED_IN(28);
int posix_spawnattr_getflags(const posix_spawnattr_t _Nonnull * _Nonnull __attr, short* _Nonnull __flags) __INTRODUCED_IN(28);

int posix_spawnattr_setpgroup(posix_spawnattr_t _Nonnull * _Nonnull __attr, pid_t __pgroup) __INTRODUCED_IN(28);
int posix_spawnattr_getpgroup(const posix_spawnattr_t _Nonnull * _Nonnull __attr, pid_t* _Nonnull __pgroup) __INTRODUCED_IN(28);

int posix_spawnattr_setsigmask(posix_spawnattr_t _Nonnull * _Nonnull __attr, const sigset_t* _Nonnull __mask) __INTRODUCED_IN(28);
int posix_spawnattr_setsigmask64(posix_spawnattr_t _Nonnull * _Nonnull __attr, const sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);
int posix_spawnattr_getsigmask(const posix_spawnattr_t _Nonnull * _Nonnull __attr, sigset_t* _Nonnull __mask) __INTRODUCED_IN(28);
int posix_spawnattr_getsigmask64(const posix_spawnattr_t _Nonnull * _Nonnull __attr, sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);

int posix_spawnattr_setsigdefault(posix_spawnattr_t _Nonnull * _Nonnull __attr, const sigset_t* _Nonnull __mask) __INTRODUCED_IN(28);
int posix_spawnattr_setsigdefault64(posix_spawnattr_t _Nonnull * _Nonnull __attr, const sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);
int posix_spawnattr_getsigdefault(const posix_spawnattr_t _Nonnull * _Nonnull __attr, sigset_t* _Nonnull __mask) __INTRODUCED_IN(28);
int posix_spawnattr_getsigdefault64(const posix_spawnattr_t _Nonnull * _Nonnull __attr, sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);

int posix_spawnattr_setschedparam(posix_spawnattr_t _Nonnull * _Nonnull __attr, const struct sched_param* _Nonnull __param) __INTRODUCED_IN(28);
int posix_spawnattr_getschedparam(const posix_spawnattr_t _Nonnull * _Nonnull __attr, struct sched_param* _Nonnull __param) __INTRODUCED_IN(28);

int posix_spawnattr_setschedpolicy(posix_spawnattr_t _Nonnull * _Nonnull __attr, int __policy) __INTRODUCED_IN(28);
int posix_spawnattr_getschedpolicy(const posix_spawnattr_t _Nonnull * _Nonnull __attr, int* _Nonnull __policy) __INTRODUCED_IN(28);

int posix_spawn_file_actions_init(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions) __INTRODUCED_IN(28);
int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions) __INTRODUCED_IN(28);

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd, const char* _Nonnull __path, int __flags, mode_t __mode) __INTRODUCED_IN(28);
int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd) __INTRODUCED_IN(28);
int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd, int __new_fd) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */



#if __BIONIC_AVAILABILITY_GUARD(34)
int posix_spawn_file_actions_addchdir_np(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, const char* _Nonnull __path) __INTRODUCED_IN(34);
int posix_spawn_file_actions_addfchdir_np(posix_spawn_file_actions_t _Nonnull * _Nonnull __actions, int __fd) __INTRODUCED_IN(34);
#endif /* __BIONIC_AVAILABILITY_GUARD(34) */


__END_DECLS

#endif
```