Response:
Let's break down the thought process for analyzing the `signal-defs.handroid` file.

**1. Initial Understanding of the File and its Context:**

* **File Name and Path:** `bionic/libc/kernel/uapi/asm-generic/signal-defs.handroid`. Keywords here are `bionic`, `libc`, `kernel`, `uapi`, `asm-generic`, and `signal-defs`. This immediately tells us it's related to the low-level C library in Android, interacting with the kernel's signal handling mechanisms. The `uapi` suggests user-space API definitions related to kernel structures. `asm-generic` hints at definitions that are generally applicable across architectures. `handroid` likely signifies Android-specific adaptations or configurations.
* **Content:**  The file contains `#define` macros and `typedef` declarations. This strongly suggests it's defining constants and types related to signal handling.
* **Auto-generated comment:**  The comment "This file is auto-generated. Modifications will be lost." is crucial. It means we shouldn't try to understand the *generation* process in detail (unless specifically asked). Our focus should be on what the *generated output* represents.

**2. Deconstructing the Content:**

* **Signal Action Flags (SA_*):** The majority of the `#define` macros starting with `SA_` are signal action flags. The names themselves are quite descriptive:
    * `SA_NOCLDSTOP`:  "No child stop" - likely prevents signals to a parent when a child stops.
    * `SA_NOCLDWAIT`: "No child wait" - likely prevents automatic reaping of child processes.
    * `SA_SIGINFO`:  "Signal info" - indicates that extended signal information is available in the signal handler.
    * `SA_UNSUPPORTED`, `SA_EXPOSE_TAGBITS`:  Less common, require some speculation. `SA_UNSUPPORTED` is straightforward. `SA_EXPOSE_TAGBITS` might relate to memory tagging or similar low-level features.
    * `SA_ONSTACK`: "On stack" - specifies that the signal handler should execute on an alternate signal stack.
    * `SA_RESTART`: "Restart" - instructs the kernel to restart certain system calls after the signal handler returns.
    * `SA_NODEFER` / `SA_NOMASK`: "No defer" / "No mask" - likely means the signal should not be masked while the handler is executing.
    * `SA_RESETHAND` / `SA_ONESHOT`: "Reset hand" / "One shot" - means the signal handler should be reset to its default after being invoked once.

* **Signal Control Options (SIG_*):**  The `#define` macros starting with `SIG_` define options for manipulating signal masks:
    * `SIG_BLOCK`:  Adds signals to the current signal mask.
    * `SIG_UNBLOCK`: Removes signals from the current signal mask.
    * `SIG_SETMASK`: Sets the signal mask to a specific value.

* **Type Definitions:** The `typedef` statements define type aliases for signal handling functions:
    * `__signalfn_t`: A function that takes an `int` (the signal number) and returns `void`. This is the basic type for a signal handler.
    * `__sighandler_t`: A pointer to a `__signalfn_t`. This is the type used to represent a signal handler.
    * `__restorefn_t`:  A function that takes no arguments and returns `void`. This is for restoring the execution context after a signal (less common in modern systems).
    * `__sigrestore_t`: A pointer to a `__restorefn_t`.

* **Special Signal Handlers:** The `#define` macros for `SIG_DFL`, `SIG_IGN`, and `SIG_ERR` define special signal handler values:
    * `SIG_DFL`:  Default signal handling.
    * `SIG_IGN`: Ignore the signal.
    * `SIG_ERR`:  An error occurred while setting the signal handler (often returned by `signal()`).

**3. Connecting to Android Functionality:**

* **Core Signal Handling:**  This file is fundamental to how Android processes signals. Signals are a key mechanism for inter-process communication and handling asynchronous events (like Ctrl+C, process termination, etc.).
* **NDK Usage:**  NDK developers directly use signal-related functions and constants defined (or influenced by) this file when implementing custom signal handling in their native code.
* **Framework Usage:**  The Android Framework (written in Java/Kotlin) relies on the underlying native layer (including `libc`) for signal delivery and basic handling. While framework developers don't directly interact with these definitions, the behavior they observe (e.g., an app crashing due to SIGSEGV) is ultimately rooted in these low-level mechanisms.

**4. Addressing Specific Request Points:**

* **Function Implementations:** The file *doesn't contain function implementations*. It defines *constants and types*. The *implementation* of signal handling is in the kernel and deeper parts of `libc` (e.g., the `signal()` and `sigaction()` system calls). Therefore, a detailed explanation of `libc` function implementations related to this file would involve discussing the `signal()` and `sigaction()` system calls and their interaction with the kernel.
* **Dynamic Linker:** This file itself has no direct connection to the dynamic linker. The dynamic linker (`linker` or `ld-linux.so`) is responsible for loading shared libraries and resolving symbols. Signal handling might *involve* the dynamic linker if a signal handler is in a shared library, but this file only defines the building blocks for signal handling. A hypothetical SO layout example would show a shared library with signal handlers and how the linker resolves those symbols when the library is loaded.
* **Logic and Examples:** For the signal action flags, examples of their behavior (e.g., what happens when a child process stops with and without `SA_NOCLDSTOP`) can be provided as input/output scenarios.
* **Common Errors:**  Misusing `signal()` (especially with non-portable signal handlers) and improper signal masking are common errors.
* **Framework/NDK to this file:** The path from the Android Framework or NDK down to these definitions involves system calls. A Frida example would demonstrate hooking `sigaction` or `signal` to see how signal handlers are registered and how these flags are used.

**5. Structuring the Output:**

The final step is to organize the information logically, using clear headings and bullet points, and providing concrete examples wherever possible. This involves:

* **Listing functionalities:**  Directly mapping the content of the file to its purpose (defining signal handling constants and types).
* **Android relationship:** Explaining how these definitions are used within the broader Android ecosystem.
* **`libc` function details:**  Focusing on the relevant system calls (`signal`, `sigaction`) and explaining their role in signal management.
* **Dynamic linker (if applicable):**  Explaining the linker's role in resolving signal handlers in shared libraries (with a hypothetical example).
* **Logic and examples:** Providing clear input/output scenarios to illustrate the behavior of different signal flags.
* **Common errors:**  Listing and explaining typical mistakes developers make when working with signals.
* **Framework/NDK path:** Describing the chain of calls leading to the use of these definitions, ending with a Frida hooking example.

By following these steps, the detailed and comprehensive answer provided in the initial prompt can be constructed. The key is to break down the file into its components, understand the purpose of each component, and then connect it to the broader context of the Android operating system and its development tools.
这个文件 `bionic/libc/kernel/uapi/asm-generic/signal-defs.handroid` 定义了与信号处理相关的常量和类型。由于它位于 `bionic/libc/kernel/uapi/` 路径下，表明它是用户空间程序可以通过系统调用与内核交互的接口的一部分。更具体地说，`asm-generic` 表明这些定义是跨架构通用的，而 `handroid` 则暗示了 Android 特定的定制或配置。

**功能列举:**

1. **定义信号动作标志 (Signal Action Flags):**  以 `SA_` 开头的宏定义，用于 `sigaction` 系统调用中，指定信号处理程序的行为方式。例如：
    * `SA_NOCLDSTOP`:  当子进程停止或继续时，不向父进程发送 `SIGCHLD` 信号。
    * `SA_NOCLDWAIT`:  当子进程退出时，父进程不显式调用 `wait` 或 `waitpid` 等待子进程，内核会自动回收子进程资源。
    * `SA_SIGINFO`:  信号处理程序接收扩展的信号信息，可以通过 `siginfo_t` 结构体获取更多关于信号的信息（例如，哪个进程发送的信号，信号的类型等）。
    * `SA_ONSTACK`:  在备用信号栈上执行信号处理程序。
    * `SA_RESTART`:  如果系统调用被信号中断，则在信号处理程序返回后自动重启该系统调用。
    * `SA_NODEFER` (或 `SA_NOMASK`):  在信号处理程序执行期间，允许当前信号发生（即不阻塞当前信号）。
    * `SA_RESETHAND` (或 `SA_ONESHOT`):  在信号处理程序执行一次后，将该信号的处理方式重置为默认。

2. **定义信号控制选项 (Signal Control Options):** 以 `SIG_` 开头的宏定义，用于 `sigprocmask` 系统调用中，用于操作进程的信号屏蔽字。
    * `SIG_BLOCK`:  将指定的信号添加到信号屏蔽字中，阻止这些信号的传递。
    * `SIG_UNBLOCK`:  将指定的信号从信号屏蔽字中移除，允许这些信号的传递。
    * `SIG_SETMASK`:  将进程的信号屏蔽字设置为指定的值。

3. **定义信号处理函数类型:**  定义了用于表示信号处理函数的类型别名。
    * `__signalfn_t`:  一个指向函数的指针，该函数接收一个 `int` 参数（信号编号），返回 `void`。这是传统的 `signal()` 函数使用的信号处理函数类型。
    * `__sighandler_t`:  与 `__signalfn_t` 相同，但作为更通用的信号处理程序类型使用。
    * `__restorefn_t`: 一个指向函数的指针，该函数不接收任何参数，返回 `void`。用于恢复信号处理程序执行前的上下文（在某些架构上使用，现代 Linux 系统中较少直接使用）。
    * `__sigrestore_t`: 与 `__restorefn_t` 相同，作为恢复上下文的函数指针类型使用。

4. **定义特殊的信号处理程序值:**
    * `SIG_DFL`:  表示使用信号的默认处理方式。
    * `SIG_IGN`:  表示忽略该信号。
    * `SIG_ERR`:  通常作为 `signal()` 函数的返回值，表示设置信号处理程序时出错。

**与 Android 功能的关系及举例:**

这个文件直接影响了 Android 系统中进程如何处理信号。信号是进程间通信和处理异步事件的重要机制。

* **Android Framework 的进程管理:** Android Framework 使用信号来管理应用程序进程的生命周期。例如，当用户强制停止一个应用时，ActivityManagerService 可能会向该应用进程发送一个信号（如 `SIGKILL`）来终止它。这个信号的处理机制就涉及到这里定义的常量。

* **NDK 开发中的信号处理:** NDK (Native Development Kit) 允许开发者使用 C/C++ 编写 Android 应用的原生代码。开发者可以使用 `signal()` 或 `sigaction()` 函数来注册自定义的信号处理程序。在注册时，他们会使用到这里定义的 `SA_*` 标志来指定信号处理程序的行为。

    **举例 (NDK):**  一个 NDK 应用可能需要在子进程退出时得到通知，并执行一些清理工作。它可以设置一个 `SIGCHLD` 信号的处理器，并使用 `SA_NOCLDSTOP` 标志来防止在子进程停止时也收到信号。

* **Bionic libc 的实现:**  Bionic libc 提供了 `signal()` 和 `sigaction()` 等函数，它们的实现依赖于这里定义的常量。例如，当 `sigaction()` 函数被调用时，它会将用户提供的 `sa_flags` 参数与这里定义的 `SA_*` 宏进行比较，以确定如何设置信号处理程序。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个文件本身 **不包含 libc 函数的实现代码**，它只是定义了常量和类型。`signal()` 和 `sigaction()` 等函数的实现位于 Bionic libc 的其他源文件中，最终会通过系统调用与 Linux 内核进行交互。

* **`signal(int signum, __sighandler_t handler)`:**  这是一个较早的信号处理函数。它的功能是为一个特定的信号 `signum` 设置处理程序 `handler`。
    * **实现:**  在 Bionic libc 中，`signal()` 函数通常会调用更底层的 `sigaction()` 函数来实现其功能。它会将 `handler` 转换为 `struct sigaction` 结构体，并设置相应的标志。由于 `signal()` 的行为在不同 Unix 系统上有所不同，现代 Android 开发更推荐使用 `sigaction()`。

* **`sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`:**  这是一个更强大且可移植的信号处理函数。它可以更精细地控制信号的处理方式。
    * **实现:**
        1. **参数校验:**  Bionic libc 的 `sigaction()` 实现首先会检查传入的信号编号 `signum` 是否有效。
        2. **获取当前处理方式 (可选):** 如果 `oldact` 不为 NULL，则会获取当前信号的处理方式，并将其存储在 `oldact` 指向的结构体中。这通常涉及到与内核的交互，读取内核中维护的信号处理信息。
        3. **设置新的处理方式 (如果 `act` 不为 NULL):**
            * 将 `act` 指向的 `struct sigaction` 结构体中的信息传递给内核。这个结构体包含了信号处理程序地址 (`sa_sigaction` 或 `sa_handler`) 和信号动作标志 (`sa_flags`)。
            * `sa_flags` 中的值（例如 `SA_RESTART`，`SA_SIGINFO` 等）就是在这里定义的宏。内核会根据这些标志来决定如何处理该信号。例如，如果设置了 `SA_RESTART`，当系统调用被该信号中断时，内核会在信号处理程序返回后尝试重启该系统调用。如果设置了 `SA_SIGINFO`，内核会在调用信号处理程序时传递一个 `siginfo_t` 结构体，其中包含更多关于信号的信息。
        4. **系统调用:**  `sigaction()` 的核心是通过一个系统调用（通常是 `rt_sigaction`）将请求传递给 Linux 内核。内核会更新其内部的数据结构，以反映新的信号处理方式。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个文件本身 **不直接涉及 dynamic linker 的功能**。它定义的是信号处理相关的常量和类型，这些是操作系统内核和 libc 的一部分。动态链接器负责加载共享库和解析符号。

然而，如果信号处理程序位于一个共享库 (.so 文件) 中，那么动态链接器在加载该 .so 文件时会参与到信号处理的流程中。

**SO 布局样本:**

假设有一个名为 `libmysignals.so` 的共享库，其中包含一个自定义的信号处理函数：

```c
// libmysignals.c
#include <signal.h>
#include <stdio.h>

void my_signal_handler(int sig) {
    printf("Custom signal handler for signal %d in libmysignals.so\n", sig);
}

__attribute__((constructor)) void my_init(void) {
    struct sigaction sa;
    sa.sa_handler = my_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    printf("Signal handler registered in libmysignals.so\n");
}
```

编译生成 `libmysignals.so`：

```bash
gcc -shared -fPIC libmysignals.c -o libmysignals.so
```

**SO 布局 (简化):**

```
libmysignals.so:
    .text:  // 代码段
        my_signal_handler: ... (函数代码)
        my_init: ... (构造函数代码)
    .data:  // 数据段
        ...
    .dynamic: // 动态链接信息
        SONAME: libmysignals.so
        NEEDED: libc.so
        SYMTAB: ... (符号表)
        STRTAB: ... (字符串表)
        RELA: ... (重定位表)
```

**链接的处理过程:**

1. **加载 .so 文件:** 当一个应用程序加载 `libmysignals.so` 时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会将该 .so 文件加载到进程的地址空间中。

2. **解析符号:** 动态链接器会解析 `libmysignals.so` 中引用的外部符号，例如 `sigaction`，`sigemptyset` 等。这些符号通常来自 `libc.so`。动态链接器会查找 `libc.so` 的符号表，找到这些符号的地址，并将它们链接到 `libmysignals.so` 的代码中。

3. **执行构造函数:**  `__attribute__((constructor))`  标记的函数 `my_init` 会在 .so 文件加载完成后被动态链接器自动执行。

4. **注册信号处理程序:**  在 `my_init` 函数中，`sigaction(SIGUSR1, &sa, NULL)` 会被调用。这个调用最终会通过系统调用与内核交互，将 `my_signal_handler` 函数注册为 `SIGUSR1` 信号的处理程序。这里的 `SA_RESTART` 就来自于 `signal-defs.handroid` 文件定义的宏。

**假设输入与输出 (逻辑推理):**

假设一个应用程序注册了一个使用 `SA_SIGINFO` 标志的信号处理程序来捕获 `SIGUSR1` 信号。

**输入:**

* 进程收到一个 `SIGUSR1` 信号，可能由另一个进程通过 `kill` 系统调用发送。
* 发送信号的进程的 PID 为 1234。
* 发送信号的用户 ID 为 1000。

**输出 (在信号处理程序中):**

* 信号处理程序被调用，传入的信号编号 `sig` 为 `SIGUSR1`。
* 如果信号处理程序正确地声明了接收 `siginfo_t` 结构体的参数，那么该结构体的内容会包含：
    * `si_signo`:  `SIGUSR1`
    * `si_errno`:  0
    * `si_code`:  `SI_USER` (表示信号由用户发送)
    * `si_pid`:  1234 (发送信号的进程 ID)
    * `si_uid`:  1000 (发送信号的用户的 ID)

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **在信号处理程序中使用非异步信号安全 (async-signal-safe) 的函数:** 信号处理程序可能会在主程序的任意时刻被中断执行。如果信号处理程序中调用的函数不是异步信号安全的（例如 `printf`, `malloc`, `free` 等），可能会导致死锁、数据损坏或其他不可预测的行为。

    **错误示例:**

    ```c
    #include <signal.h>
    #include <stdio.h>
    #include <stdlib.h>

    void handler(int sig) {
        printf("Signal received: %d\n", sig); // printf is NOT async-signal-safe
        exit(1); // exit is NOT async-signal-safe
    }

    int main() {
        signal(SIGINT, handler);
        while (1) {
            sleep(1);
        }
        return 0;
    }
    ```

2. **忽略 `sigaction` 的返回值:**  `sigaction` 函数在出错时会返回 -1，并设置 `errno`。忽略返回值可能导致难以调试的问题。

    **错误示例:**

    ```c
    #include <signal.h>
    #include <stdio.h>

    int main() {
        struct sigaction sa;
        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGUSR1, &sa, NULL); // 忘记检查返回值
        // ...
        return 0;
    }
    ```

3. **错误地使用信号掩码:**  在信号处理程序中，可以通过 `sa_mask` 字段设置在执行该处理程序期间需要阻塞的信号。错误地设置信号掩码可能导致死锁或无法及时处理某些重要的信号。

4. **在 `signal()` 中使用不可移植的处理程序:**  `signal()` 函数的行为在不同 Unix 系统上可能有所不同，特别是对于返回前是否重置信号处理程序为默认行为。为了可移植性，推荐使用 `sigaction()`。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达这里的步骤 (以 Java 层发送信号为例):**

1. **Java 层发起信号发送:** Android Framework 的某些组件（例如 ActivityManagerService）可能会需要向某个进程发送信号。这通常通过 `android.os.Process` 类的静态方法 `sendSignal(int pid, int signal)` 实现。

2. **JNI 调用:** `Process.sendSignal()` 方法是一个 native 方法，它会通过 JNI (Java Native Interface) 调用到 Android 运行时 (ART) 中的 C/C++ 代码。

3. **Runtime 调用:** ART 接收到 JNI 调用后，会调用底层的 Bionic libc 函数，例如 `kill()` 系统调用。

4. **系统调用:** `kill(pid, signal)` 系统调用会将信号发送给指定的进程 `pid`。`signal` 参数的值（例如 `SIGKILL`, `SIGTERM` 等）会被传递给内核。

5. **内核处理:** Linux 内核接收到 `kill` 系统调用后，会查找目标进程，并根据目标进程注册的信号处理方式来处理该信号。这其中就涉及到 `signal-defs.handroid` 中定义的信号常量和标志。

**NDK 到达这里的步骤:**

1. **NDK 代码调用信号相关函数:** NDK 开发者可以直接在 C/C++ 代码中使用 `signal()` 或 `sigaction()` 函数来注册信号处理程序，或者使用 `kill()` 函数发送信号。

2. **Bionic libc:** 这些 NDK 代码会链接到 Bionic libc 提供的实现。

3. **系统调用:** Bionic libc 的信号处理函数最终会通过系统调用与内核交互。

**Frida Hook 示例:**

可以使用 Frida hook Bionic libc 的 `sigaction` 函数来观察信号处理程序的注册过程，或者 hook `kill` 函数来观察信号的发送过程。

**Hook `sigaction`:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
session = device.attach(pid) if pid else device.spawn(['com.example.myapp'])
script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "sigaction"), {
    onEnter: function(args) {
        var signum = args[0].toInt32();
        var act = ptr(args[1]);
        var oldact = ptr(args[2]);

        var handler_ptr = act.readPointer();
        var flags = act.add(Process.pointerSize).readU32();

        send({
            "event": "sigaction",
            "signum": signum,
            "handler": handler_ptr,
            "flags": flags.toString(16)
        });
    }
});
""")
script.on('message', on_message)
script.load()
if not pid:
    device.resume(session.pid)
sys.stdin.read()
```

运行此脚本，并替换 `com.example.myapp` 为目标应用的包名或提供进程 PID。当目标应用调用 `sigaction` 时，Frida 会拦截调用并打印出信号编号、处理程序地址和标志（以十六进制形式显示，可以与 `signal-defs.handroid` 中的宏定义进行比较）。

**Hook `kill`:**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
session = device.attach(pid) if pid else device.spawn(['com.example.myapp'])
script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "kill"), {
    onEnter: function(args) {
        var pid = args[0].toInt32();
        var sig = args[1].toInt32();
        send({
            "event": "kill",
            "pid": pid,
            "signal": sig
        });
    }
});
""")
script.on('message', on_message)
script.load()
if not pid:
    device.resume(session.pid)
sys.stdin.read()
```

这个脚本会 hook `kill` 函数，并在每次调用时打印出目标进程的 PID 和发送的信号编号。

通过 Frida 这样的工具，开发者可以动态地观察 Android 系统中信号的注册和发送过程，从而更好地理解信号处理机制和调试相关问题。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-generic/signal-defs.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __ASM_GENERIC_SIGNAL_DEFS_H
#define __ASM_GENERIC_SIGNAL_DEFS_H
#include <linux/compiler.h>
#ifndef SA_NOCLDSTOP
#define SA_NOCLDSTOP 0x00000001
#endif
#ifndef SA_NOCLDWAIT
#define SA_NOCLDWAIT 0x00000002
#endif
#ifndef SA_SIGINFO
#define SA_SIGINFO 0x00000004
#endif
#define SA_UNSUPPORTED 0x00000400
#define SA_EXPOSE_TAGBITS 0x00000800
#ifndef SA_ONSTACK
#define SA_ONSTACK 0x08000000
#endif
#ifndef SA_RESTART
#define SA_RESTART 0x10000000
#endif
#ifndef SA_NODEFER
#define SA_NODEFER 0x40000000
#endif
#ifndef SA_RESETHAND
#define SA_RESETHAND 0x80000000
#endif
#define SA_NOMASK SA_NODEFER
#define SA_ONESHOT SA_RESETHAND
#ifndef SIG_BLOCK
#define SIG_BLOCK 0
#endif
#ifndef SIG_UNBLOCK
#define SIG_UNBLOCK 1
#endif
#ifndef SIG_SETMASK
#define SIG_SETMASK 2
#endif
#ifndef __ASSEMBLY__
typedef void __signalfn_t(int);
typedef __signalfn_t  * __sighandler_t;
typedef void __restorefn_t(void);
typedef __restorefn_t  * __sigrestore_t;
#define SIG_DFL (( __sighandler_t) 0)
#define SIG_IGN (( __sighandler_t) 1)
#define SIG_ERR (( __sighandler_t) - 1)
#endif
#endif

"""

```