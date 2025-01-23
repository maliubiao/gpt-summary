Response:
Let's break down the thought process for answering the request about `prctl.h`.

**1. Understanding the Core Request:**

The request is about a specific header file (`prctl.h`) within Android's Bionic library. The goal is to understand its functionality, its relationship to Android, and how it's used. The request also includes specific sub-questions about libc functions, dynamic linking, common errors, and how Android Framework/NDK reach this point, including a Frida hook example.

**2. Initial Analysis of `prctl.h`:**

The first step is to recognize what the header file is. The comments at the top clearly state it's auto-generated and relates to the Linux `prctl` system call. The bulk of the file consists of `#define` macros. This immediately tells us:

* **Not a source code file with implemented functions:** It's a header file defining constants.
* **Interface to a system call:**  The prefixes `PR_` and the general names (like `PR_SET_NAME`, `PR_GET_DUMPABLE`) strongly suggest these are parameters for the `prctl()` system call.

**3. Identifying the Purpose of `prctl()`:**

Knowing it's related to the `prctl()` system call is key. A quick mental note or a quick search confirms that `prctl()` is used to control various aspects of a process's behavior at the kernel level. This understanding frames the interpretation of the individual macros.

**4. Categorizing and Explaining the Macros:**

Now, the task is to go through the macros and group them by functionality. Common themes emerge:

* **Process Behavior:**  Name, death signal, dumpable status.
* **Resource Management:** Keep capabilities, timerslack.
* **Security:**  Securebits, SECCOMP, capabilities (ambient, bounding set).
* **Memory Management:**  Setting memory regions, memory merging.
* **Debugging/Tracing:** Ptrace, getting TID address.
* **Performance:** TSC, performance events.
* **CPU Features:** Floating-point emulation, endianness, speculation control, tagged addresses, SVE/SME (ARM extensions), RISC-V Vector extensions.
* **Scheduling:**  Scheduling cores.

For each category, a brief explanation of the general function is provided.

**5. Connecting to Android:**

This is where the "Android-specific" aspect comes in. The thought process here is: "How would these process controls be relevant in the Android context?"

* **Process Management:** Android's process lifecycle management relies on kernel features. `PR_SET_PDEATHSIG` is a prime example of how Android ensures child processes are cleaned up if their parent dies.
* **Security:** Android's security model is heavily reliant on Linux kernel features. SECCOMP sandboxing, capabilities, and `securebits` are crucial for isolating apps and protecting the system.
* **Debugging:**  Debuggers (like those used with the NDK) use `ptrace`, and `PR_SET_PTRACER` is part of that.
* **Performance:** Android developers might be interested in features like timerslack or disabling THP for performance tuning.

For each relevant macro/category, a concrete example of its potential use in Android is given.

**6. Explaining `libc` Functions:**

The prompt asks about `libc` functions. It's important to clarify that `prctl.h` itself *doesn't define* `libc` functions. It defines *constants* used by the `prctl()` *system call*. The `libc` function is `prctl()`, which is a wrapper around the system call. The explanation focuses on how the `libc` `prctl()` function takes the parameters (the constants from `prctl.h`) and makes the system call.

**7. Dynamic Linking:**

The connection to the dynamic linker is subtle. The `prctl()` system call itself isn't directly involved in dynamic linking. However, *applications* that use `prctl()` are linked against `libc.so`, which provides the wrapper function. The example SO layout shows a typical Android app's shared library dependencies. The explanation emphasizes that `libc.so` is a dependency and how the dynamic linker resolves symbols.

**8. Logic Reasoning and Assumptions:**

The "logic reasoning" aspect is mostly about understanding the *implications* of the `prctl()` options. For instance, setting `PR_SET_DUMPABLE` to 0 prevents core dumps, which is useful in production environments. The assumptions are primarily around the user's intent when calling `prctl()`.

**9. Common Usage Errors:**

This involves thinking about what could go wrong when using `prctl()`. Common errors include:

* **Incorrect parameters:**  Using invalid option numbers or values.
* **Insufficient privileges:**  Trying to set process attributes that require higher privileges.
* **Not checking return values:**  Ignoring potential errors from the `prctl()` call.

**10. Android Framework/NDK Integration and Frida Hook:**

This requires knowledge of the Android architecture. The path from the Framework/NDK to the `prctl()` system call goes through:

* **Framework:** Java APIs call into native code (via JNI).
* **NDK:** C/C++ code directly calls `libc` functions.
* **`libc`:** The `prctl()` function in `libc.so` makes the system call.
* **Kernel:** The Linux kernel handles the system call.

The Frida hook example demonstrates how to intercept calls to the `prctl()` function, allowing inspection of the parameters being passed.

**11. Structure and Language:**

Finally, the answer is structured logically, using headings and bullet points for clarity. The language is kept clear and technical, explaining concepts without being overly verbose. The request specified Chinese, so the entire response is in Chinese.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the *individual* macros. I realized it's more effective to group them thematically.
* I had to explicitly clarify that `prctl.h` defines *constants*, not the `libc` function itself. This distinction is important.
* When discussing dynamic linking, I ensured the connection to `libc.so` as a dependency was clear.
* The Frida hook example needed to be specific and actionable.

By following these steps and iteratively refining the answer, a comprehensive and accurate response can be generated.这个文件 `bionic/libc/kernel/uapi/linux/prctl.h` 是 Android Bionic 库中的一个头文件，它定义了与 Linux `prctl` 系统调用相关的常量。`prctl` (process control) 是一个强大的系统调用，允许进程修改自身或其子进程的某些属性和行为。

**它的主要功能是定义了 `prctl` 系统调用可以使用的各种选项（宏定义）。**  这些宏定义作为参数传递给 `prctl` 系统调用，以指示要执行的具体操作。

**与 Android 功能的关系及举例说明：**

`prctl` 系统调用是 Linux 内核提供的功能，而 Android 是基于 Linux 内核构建的，因此 `prctl` 在 Android 中被广泛使用，以支持各种系统功能和安全特性。Bionic 库作为 Android 的 C 库，自然需要提供访问这些底层内核功能的接口。

以下是一些 `prctl` 宏定义及其在 Android 中的潜在应用：

* **`PR_SET_PDEATHSIG` / `PR_GET_PDEATHSIG`:** 设置或获取父进程死亡信号。
    * **Android 举例：** Android 的 `zygote` 进程会 fork 出新的应用进程。当应用进程的父进程（比如 `zygote` 或 `servicemanager`）意外终止时，设置 `PR_SET_PDEATHSIG` 可以确保应用进程收到一个信号 (通常是 `SIGKILL`) 并被终止，防止孤儿进程的产生。

* **`PR_GET_DUMPABLE` / `PR_SET_DUMPABLE`:** 获取或设置进程是否可以生成 core dump。
    * **Android 举例：**  出于安全考虑，默认情况下，Android 应用进程的 `dumpable` 属性通常是关闭的。只有在开发者模式下或者特定场景下，才可能允许生成 core dump 以进行调试。

* **`PR_SET_NAME` / `PR_GET_NAME`:** 设置或获取进程名称。
    * **Android 举例：**  Android 系统服务和应用可以使用 `PR_SET_NAME` 来设置一个易于识别的进程名称，这在 `ps` 命令或其他进程监控工具中非常有用，方便开发者和系统管理员识别不同的进程。

* **`PR_SET_SECCOMP`:** 设置进程的安全计算模式 (SECCOMP)。
    * **Android 举例：** Android 使用 SECCOMP 来限制应用进程可以调用的系统调用，从而提高安全性。例如，应用进程可能只被允许调用一部分系统调用，以防止恶意行为。

* **`PR_CAPBSET_READ` / `PR_CAPBSET_DROP`:** 读取或删除进程的 capability bounding set。
    * **Android 举例：** Android 的权限模型依赖于 Linux capabilities。`prctl` 可以用于在运行时管理进程的 capabilities，例如，在启动时删除某些不需要的 capabilities 以提高安全性。

* **`PR_SET_NO_NEW_PRIVS` / `PR_GET_NO_NEW_PRIVS`:** 设置后，进程无法通过 execve 获取新的权限。
    * **Android 举例：**  这是一个重要的安全特性，用于防止提权攻击。一旦设置，即使执行了 setuid/setgid 的程序，进程也不会获得新的用户或组 ID 权限。

* **`PR_SET_TIMERSLACK` / `PR_GET_TIMERSLACK`:** 设置或获取进程的定时器精度容忍度。
    * **Android 举例：**  可以用于优化电池消耗。允许定时器有一定的延迟可以减少 CPU 的唤醒次数。

**详细解释每一个 libc 函数的功能是如何实现的：**

这里需要明确一点，`bionic/libc/kernel/uapi/linux/prctl.h` **本身不是 libc 函数的实现，而是定义了 `prctl` 系统调用使用的常量。**  实际的 `prctl` 函数是在 Bionic 的 `libc.so` 中实现的，它是一个对 Linux 内核 `prctl` 系统调用的封装。

`libc` 中 `prctl` 函数的功能是：

1. **接收参数：**  接收 `prctl` 操作的选项 (来自 `prctl.h` 的宏) 以及其他相关的参数。
2. **系统调用：**  使用汇编指令 (例如 `syscall`) 将这些参数传递给 Linux 内核的 `prctl` 系统调用入口点。
3. **内核处理：** Linux 内核根据传递的选项执行相应的操作，例如设置进程名称、修改信号处理方式等。
4. **返回结果：** 内核将执行结果返回给 `libc` 的 `prctl` 函数。
5. **错误处理：** `libc` 的 `prctl` 函数会将内核返回的结果转换为 C 标准库的错误码 (如果发生错误，通常返回 -1，并设置 `errno`)。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`prctl` 系统调用本身并不直接涉及 dynamic linker 的核心功能。但是，任何使用 `prctl` 的程序都需要链接到 Bionic 的 `libc.so` 库，因为 `prctl` 函数是在该库中提供的。

**so 布局样本 (一个简单的 Android 应用)：**

```
/system/bin/app_process64  // Android 应用程序进程 (示例)
├── linker64             // Dynamic linker
├── libdl.so             // Dynamic linking 支持库
├── libc.so              // Bionic C 库 (包含 prctl 函数)
├── libm.so              // Math 库
├── liblog.so            // 日志库
├── libutils.so          // Android 基础工具库
└── [应用私有的 .so 文件]
```

**链接的处理过程：**

1. **编译时链接：** 当应用程序被编译时，编译器会标记程序需要使用 `libc.so` 中定义的 `prctl` 函数。
2. **加载时链接：** 当应用程序进程启动时，内核会加载应用程序的可执行文件。`linker64` (dynamic linker) 会被启动来解析程序的依赖关系。
3. **依赖解析：** `linker64` 读取应用程序的 ELF 文件头，找到所需的共享库 (例如 `libc.so`)。
4. **加载共享库：** `linker64` 将 `libc.so` 加载到进程的地址空间。
5. **符号解析：** `linker64` 解析应用程序中对 `prctl` 函数的引用，并在 `libc.so` 中找到该函数的地址。
6. **重定位：** `linker64` 修改应用程序中的指令，将对 `prctl` 函数的引用指向 `libc.so` 中 `prctl` 函数的实际地址。
7. **执行：** 当应用程序执行到调用 `prctl` 函数的代码时，程序会跳转到 `libc.so` 中 `prctl` 函数的实现。

**如果做了逻辑推理，请给出假设输入与输出：**

假设我们想设置当前进程的名称为 "my_app_process"。

**假设输入：**

```c
#include <sys/prctl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main() {
    const char *new_name = "my_app_process";
    if (prctl(PR_SET_NAME, new_name) == -1) {
        perror("prctl PR_SET_NAME failed");
        return 1;
    }
    printf("Successfully set process name to: %s\n", new_name);
    return 0;
}
```

**假设输出：**

在成功执行后，通过 `ps` 命令可以看到该进程的名称已变为 "my_app_process"。程序自身的输出会是：

```
Successfully set process name to: my_app_process
```

如果 `prctl` 调用失败（例如，由于权限问题），则输出可能是：

```
prctl PR_SET_NAME failed: Operation not permitted
```

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **使用错误的 `prctl` 选项数字：**  直接使用数字而不是宏定义，容易出错且可读性差。
   ```c
   // 错误的做法
   if (prctl(15, "my_app") == -1) { // 应该使用 PR_SET_NAME
       perror("prctl failed");
   }
   ```

2. **传递了错误的参数类型或大小：**  某些 `prctl` 选项需要特定的结构体作为参数。
   ```c
   // 假设 PR_SET_MM 需要一个 struct prctl_mm_map *
   int value = 10;
   if (prctl(PR_SET_MM, value) == -1) { // 错误的参数类型
       perror("prctl failed");
   }
   ```

3. **权限不足：** 某些 `prctl` 操作需要特定的权限才能执行。
   ```c
   // 尝试设置其他进程的属性，通常需要 root 权限
   if (prctl(PR_SET_PDEATHSIG, SIGKILL, other_pid) == -1) {
       perror("prctl failed"); // 可能会输出 "Operation not permitted"
   }
   ```

4. **忘记检查返回值：** `prctl` 调用失败时会返回 -1，并设置 `errno`。不检查返回值会导致难以排查问题。
   ```c
   prctl(PR_SET_NAME, "my_app"); // 没有检查返回值
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `prctl` 的路径：**

1. **Java Framework API 调用：** Android Framework 中的 Java 代码可能会调用 Native 方法来实现某些功能。例如，`Process.setThreadName()` 最终会调用到 native 代码。

2. **JNI 调用：** Java Native Interface (JNI) 用于 Java 代码和 Native 代码之间的交互。`Process.setThreadName()` 的 native 实现会调用 Bionic 库中的函数。

3. **Bionic 库函数：**  在 Bionic 库中，可能会有封装好的函数来调用 `prctl`。例如，`pthread_setname_np()` 内部最终会调用 `prctl(PR_SET_NAME, ...)`。

4. **`prctl` 系统调用：** Bionic 库中的 `prctl` 函数会执行系统调用，将请求传递给 Linux 内核。

**NDK 到 `prctl` 的路径：**

1. **NDK C/C++ 代码：** 使用 NDK 开发的应用程序可以直接调用 Bionic 库提供的 C 标准库函数，包括 `prctl`。

2. **`prctl` 系统调用：** NDK 代码中直接调用的 `prctl` 函数会执行系统调用，将请求传递给 Linux 内核。

**Frida Hook 示例：**

以下是一个使用 Frida Hook 拦截 `prctl` 系统调用的示例，可以观察哪些参数被传递：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

# 要附加的进程名称或 PID
package_name = "com.example.myapp"  # 替换为你的应用包名

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "prctl"), {
    onEnter: function(args) {
        var option = args[0].toInt();
        var arg2 = args[1];
        var arg3 = args[2];
        var arg4 = args[3];
        var arg5 = args[4];

        var optionName = "Unknown";
        // 这里可以根据 prctl.h 的定义将数字转换为宏名称
        if (option === 15) {
            optionName = "PR_SET_NAME";
            var processName = Memory.readUtf8String(arg2);
            send({ "type": "prctl", "option": optionName, "processName": processName });
        } else if (option === 1) {
            optionName = "PR_SET_PDEATHSIG";
            send({ "type": "prctl", "option": optionName, "signal": arg2.toInt() });
        } else {
            send({ "type": "prctl", "option": optionName, "arg2": arg2, "arg3": arg3, "arg4": arg4, "arg5": arg5 });
        }
        console.log("[Prctl] Option:", option, "(" + optionName + ")");
        console.log("  Arg2:", arg2);
        console.log("  Arg3:", arg3);
        console.log("  Arg4:", arg4);
        console.log("  Arg5:", arg5);
    },
    onLeave: function(retval) {
        console.log("[Prctl] Return value:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法：**

1. 确保你的 Android 设备或模拟器上安装了 Frida 服务。
2. 将上述 Python 代码保存为 `prctl_hook.py`。
3. 将 `package_name` 替换为你要监控的应用的包名。
4. 运行脚本： `python3 prctl_hook.py`
5. 启动或操作目标应用，Frida 会拦截对 `prctl` 的调用并打印相关信息。

这个 Frida 脚本会拦截对 `libc.so` 中 `prctl` 函数的调用，并在 `onEnter` 中打印出传递给 `prctl` 的参数。你可以根据 `prctl.h` 中的宏定义来解析 `option` 参数，并查看其他参数的值，从而了解 Android Framework 或 NDK 代码是如何使用 `prctl` 系统调用的。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/prctl.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _LINUX_PRCTL_H
#define _LINUX_PRCTL_H
#include <linux/types.h>
#define PR_SET_PDEATHSIG 1
#define PR_GET_PDEATHSIG 2
#define PR_GET_DUMPABLE 3
#define PR_SET_DUMPABLE 4
#define PR_GET_UNALIGN 5
#define PR_SET_UNALIGN 6
#define PR_UNALIGN_NOPRINT 1
#define PR_UNALIGN_SIGBUS 2
#define PR_GET_KEEPCAPS 7
#define PR_SET_KEEPCAPS 8
#define PR_GET_FPEMU 9
#define PR_SET_FPEMU 10
#define PR_FPEMU_NOPRINT 1
#define PR_FPEMU_SIGFPE 2
#define PR_GET_FPEXC 11
#define PR_SET_FPEXC 12
#define PR_FP_EXC_SW_ENABLE 0x80
#define PR_FP_EXC_DIV 0x010000
#define PR_FP_EXC_OVF 0x020000
#define PR_FP_EXC_UND 0x040000
#define PR_FP_EXC_RES 0x080000
#define PR_FP_EXC_INV 0x100000
#define PR_FP_EXC_DISABLED 0
#define PR_FP_EXC_NONRECOV 1
#define PR_FP_EXC_ASYNC 2
#define PR_FP_EXC_PRECISE 3
#define PR_GET_TIMING 13
#define PR_SET_TIMING 14
#define PR_TIMING_STATISTICAL 0
#define PR_TIMING_TIMESTAMP 1
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define PR_GET_ENDIAN 19
#define PR_SET_ENDIAN 20
#define PR_ENDIAN_BIG 0
#define PR_ENDIAN_LITTLE 1
#define PR_ENDIAN_PPC_LITTLE 2
#define PR_GET_SECCOMP 21
#define PR_SET_SECCOMP 22
#define PR_CAPBSET_READ 23
#define PR_CAPBSET_DROP 24
#define PR_GET_TSC 25
#define PR_SET_TSC 26
#define PR_TSC_ENABLE 1
#define PR_TSC_SIGSEGV 2
#define PR_GET_SECUREBITS 27
#define PR_SET_SECUREBITS 28
#define PR_SET_TIMERSLACK 29
#define PR_GET_TIMERSLACK 30
#define PR_TASK_PERF_EVENTS_DISABLE 31
#define PR_TASK_PERF_EVENTS_ENABLE 32
#define PR_MCE_KILL 33
#define PR_MCE_KILL_CLEAR 0
#define PR_MCE_KILL_SET 1
#define PR_MCE_KILL_LATE 0
#define PR_MCE_KILL_EARLY 1
#define PR_MCE_KILL_DEFAULT 2
#define PR_MCE_KILL_GET 34
#define PR_SET_MM 35
#define PR_SET_MM_START_CODE 1
#define PR_SET_MM_END_CODE 2
#define PR_SET_MM_START_DATA 3
#define PR_SET_MM_END_DATA 4
#define PR_SET_MM_START_STACK 5
#define PR_SET_MM_START_BRK 6
#define PR_SET_MM_BRK 7
#define PR_SET_MM_ARG_START 8
#define PR_SET_MM_ARG_END 9
#define PR_SET_MM_ENV_START 10
#define PR_SET_MM_ENV_END 11
#define PR_SET_MM_AUXV 12
#define PR_SET_MM_EXE_FILE 13
#define PR_SET_MM_MAP 14
#define PR_SET_MM_MAP_SIZE 15
struct prctl_mm_map {
  __u64 start_code;
  __u64 end_code;
  __u64 start_data;
  __u64 end_data;
  __u64 start_brk;
  __u64 brk;
  __u64 start_stack;
  __u64 arg_start;
  __u64 arg_end;
  __u64 env_start;
  __u64 env_end;
  __u64 * auxv;
  __u32 auxv_size;
  __u32 exe_fd;
};
#define PR_SET_PTRACER 0x59616d61
#define PR_SET_PTRACER_ANY ((unsigned long) - 1)
#define PR_SET_CHILD_SUBREAPER 36
#define PR_GET_CHILD_SUBREAPER 37
#define PR_SET_NO_NEW_PRIVS 38
#define PR_GET_NO_NEW_PRIVS 39
#define PR_GET_TID_ADDRESS 40
#define PR_SET_THP_DISABLE 41
#define PR_GET_THP_DISABLE 42
#define PR_MPX_ENABLE_MANAGEMENT 43
#define PR_MPX_DISABLE_MANAGEMENT 44
#define PR_SET_FP_MODE 45
#define PR_GET_FP_MODE 46
#define PR_FP_MODE_FR (1 << 0)
#define PR_FP_MODE_FRE (1 << 1)
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_IS_SET 1
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_LOWER 3
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#define PR_SVE_SET_VL 50
#define PR_SVE_SET_VL_ONEXEC (1 << 18)
#define PR_SVE_GET_VL 51
#define PR_SVE_VL_LEN_MASK 0xffff
#define PR_SVE_VL_INHERIT (1 << 17)
#define PR_GET_SPECULATION_CTRL 52
#define PR_SET_SPECULATION_CTRL 53
#define PR_SPEC_STORE_BYPASS 0
#define PR_SPEC_INDIRECT_BRANCH 1
#define PR_SPEC_L1D_FLUSH 2
#define PR_SPEC_NOT_AFFECTED 0
#define PR_SPEC_PRCTL (1UL << 0)
#define PR_SPEC_ENABLE (1UL << 1)
#define PR_SPEC_DISABLE (1UL << 2)
#define PR_SPEC_FORCE_DISABLE (1UL << 3)
#define PR_SPEC_DISABLE_NOEXEC (1UL << 4)
#define PR_PAC_RESET_KEYS 54
#define PR_PAC_APIAKEY (1UL << 0)
#define PR_PAC_APIBKEY (1UL << 1)
#define PR_PAC_APDAKEY (1UL << 2)
#define PR_PAC_APDBKEY (1UL << 3)
#define PR_PAC_APGAKEY (1UL << 4)
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_GET_TAGGED_ADDR_CTRL 56
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#define PR_MTE_TCF_NONE 0UL
#define PR_MTE_TCF_SYNC (1UL << 1)
#define PR_MTE_TCF_ASYNC (1UL << 2)
#define PR_MTE_TCF_MASK (PR_MTE_TCF_SYNC | PR_MTE_TCF_ASYNC)
#define PR_MTE_TAG_SHIFT 3
#define PR_MTE_TAG_MASK (0xffffUL << PR_MTE_TAG_SHIFT)
#define PR_MTE_TCF_SHIFT 1
#define PR_SET_IO_FLUSHER 57
#define PR_GET_IO_FLUSHER 58
#define PR_SET_SYSCALL_USER_DISPATCH 59
#define PR_SYS_DISPATCH_OFF 0
#define PR_SYS_DISPATCH_ON 1
#define SYSCALL_DISPATCH_FILTER_ALLOW 0
#define SYSCALL_DISPATCH_FILTER_BLOCK 1
#define PR_PAC_SET_ENABLED_KEYS 60
#define PR_PAC_GET_ENABLED_KEYS 61
#define PR_SCHED_CORE 62
#define PR_SCHED_CORE_GET 0
#define PR_SCHED_CORE_CREATE 1
#define PR_SCHED_CORE_SHARE_TO 2
#define PR_SCHED_CORE_SHARE_FROM 3
#define PR_SCHED_CORE_MAX 4
#define PR_SCHED_CORE_SCOPE_THREAD 0
#define PR_SCHED_CORE_SCOPE_THREAD_GROUP 1
#define PR_SCHED_CORE_SCOPE_PROCESS_GROUP 2
#define PR_SME_SET_VL 63
#define PR_SME_SET_VL_ONEXEC (1 << 18)
#define PR_SME_GET_VL 64
#define PR_SME_VL_LEN_MASK 0xffff
#define PR_SME_VL_INHERIT (1 << 17)
#define PR_SET_MDWE 65
#define PR_MDWE_REFUSE_EXEC_GAIN (1UL << 0)
#define PR_MDWE_NO_INHERIT (1UL << 1)
#define PR_GET_MDWE 66
#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#define PR_GET_AUXV 0x41555856
#define PR_SET_MEMORY_MERGE 67
#define PR_GET_MEMORY_MERGE 68
#define PR_RISCV_V_SET_CONTROL 69
#define PR_RISCV_V_GET_CONTROL 70
#define PR_RISCV_V_VSTATE_CTRL_DEFAULT 0
#define PR_RISCV_V_VSTATE_CTRL_OFF 1
#define PR_RISCV_V_VSTATE_CTRL_ON 2
#define PR_RISCV_V_VSTATE_CTRL_INHERIT (1 << 4)
#define PR_RISCV_V_VSTATE_CTRL_CUR_MASK 0x3
#define PR_RISCV_V_VSTATE_CTRL_NEXT_MASK 0xc
#define PR_RISCV_V_VSTATE_CTRL_MASK 0x1f
#define PR_RISCV_SET_ICACHE_FLUSH_CTX 71
#define PR_RISCV_CTX_SW_FENCEI_ON 0
#define PR_RISCV_CTX_SW_FENCEI_OFF 1
#define PR_RISCV_SCOPE_PER_PROCESS 0
#define PR_RISCV_SCOPE_PER_THREAD 1
#define PR_PPC_GET_DEXCR 72
#define PR_PPC_SET_DEXCR 73
#define PR_PPC_DEXCR_SBHE 0
#define PR_PPC_DEXCR_IBRTPD 1
#define PR_PPC_DEXCR_SRAPD 2
#define PR_PPC_DEXCR_NPHIE 3
#define PR_PPC_DEXCR_CTRL_EDITABLE 0x1
#define PR_PPC_DEXCR_CTRL_SET 0x2
#define PR_PPC_DEXCR_CTRL_CLEAR 0x4
#define PR_PPC_DEXCR_CTRL_SET_ONEXEC 0x8
#define PR_PPC_DEXCR_CTRL_CLEAR_ONEXEC 0x10
#define PR_PPC_DEXCR_CTRL_MASK 0x1f
#endif
```