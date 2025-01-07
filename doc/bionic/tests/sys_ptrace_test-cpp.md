Response:
Let's break down the thought process for answering the user's request about the `sys_ptrace_test.cpp` file.

**1. Understanding the Core Request:**

The user wants a comprehensive analysis of a C++ source file related to `ptrace` within Android's Bionic library. Key aspects they are interested in include functionality, relationship to Android, implementation details of libc functions, dynamic linking aspects, potential logic, common errors, and how Android Framework/NDK reach this code. Finally, they want a Frida hook example.

**2. Initial File Scan and Keyword Identification:**

First, I'd quickly scan the code for prominent features and keywords. This involves looking for:

* **Includes:**  `sys/ptrace.h`, `unistd.h`, `sys/wait.h`, `gtest/gtest.h`, `android-base/` headers. This immediately signals that the file is a unit test for `ptrace` functionality within the Android environment.
* **Test Macros:** `TEST(sys_ptrace, ...)` confirms it's a Google Test.
* **`ptrace()` calls:**  These are the central focus. I'd note the different `ptrace` commands used (`PTRACE_TRACEME`, `PTRACE_SEIZE`, `PTRACE_INTERRUPT`, `PTRACE_CONT`, `PTRACE_GETREGS`, `PTRACE_SETREGS`, `PTRACE_PEEKUSER`, `PTRACE_POKEUSER`, `PTRACE_GETHBPREGS`, `PTRACE_SETHBPREGS`, `PTRACE_GETREGSET`, `PTRACE_SETREGSET`, `PTRACE_GETSIGINFO`).
* **Hardware Breakpoint/Watchpoint related code:** The `HwFeature` enum, `check_hw_feature_supported`, `set_watchpoint`, `set_breakpoint` functions point to tests for hardware debugging.
* **Forking and Process Management:**  `fork()`, `waitpid()`, `kill()`, `prctl()`. This indicates the tests involve creating and controlling child processes.
* **Signal Handling:** `SIGSTOP`, `SIGKILL`, `SIGTRAP`.
* **Assembly Code:**  Inline assembly snippets provide clues about architecture-specific behavior related to watchpoints.
* **Other libc functions:** `err()`, `perror()`, `sched_setaffinity()`, `raise()`, `exit()`, `read()`.
* **Classes:** `ChildGuard`, `PtraceResumptionTest`. These encapsulate specific test setups and teardowns.

**3. Categorizing and Analyzing Functionality:**

Based on the keywords and structure, I'd categorize the file's functionality:

* **Core `ptrace` testing:** This is the primary purpose. The tests cover basic `ptrace` operations like attaching, detaching, continuing execution, and receiving signals.
* **Hardware Breakpoint and Watchpoint testing:** A significant portion is dedicated to verifying hardware debugging features. This is highly relevant to Android's debugging capabilities.
* **Process Control:** The tests heavily rely on creating and managing child processes to exercise `ptrace` in different scenarios.
* **Error Handling:**  The use of `ASSERT_EQ`, `ASSERT_NE`, `EXPECT_ERRNO` shows a focus on verifying expected outcomes and error conditions.
* **Resumption Testing:** The `PtraceResumptionTest` class focuses on testing scenarios where a tracer attaches and detaches from a tracee, particularly in the context of the Yama security module.

**4. Connecting to Android Functionality:**

Now, I'd explicitly connect the functionalities to Android:

* **Debugging:** `ptrace` is fundamental to debuggers like `gdb` and Android Studio's debugger. The hardware breakpoint/watchpoint tests directly relate to how developers debug native code on Android.
* **System Tracing:**  Tools like `systrace` internally use `ptrace` to gather system-level information.
* **Security:**  The `PtraceResumptionTest` and the mention of Yama highlight the security implications of `ptrace` and how Android handles cross-process tracing.
* **NDK:**  Developers using the NDK interact with native code that can be debugged using `ptrace`-based tools. The tests here ensure the underlying `ptrace` implementation in Bionic works correctly.

**5. Deep Dive into `libc` Functions:**

For each relevant `libc` function, I would explain its purpose and how it's used within the test:

* **`ptrace()`:** The central function – elaborate on its various commands and how they manipulate the tracee.
* **`fork()`:** Explain how it creates a new process for testing.
* **`waitpid()`:** Describe its role in synchronizing the parent and child processes and checking the child's status.
* **`kill()`:** Explain how it's used to terminate child processes cleanly.
* **`prctl()`:** Focus on `PR_SET_PDEATHSIG` (ensuring the child dies if the parent does) and `PR_SET_PTRACER` (allowing non-ancestor processes to trace).
* **`sched_setaffinity()`:** Explain how it's used to pin a process to a specific CPU for testing watchpoint behavior.
* **`raise()`:** Show how it's used to send signals (like `SIGSTOP`) to the child process.
* **`exit()`/`_exit()`:** Explain how the child processes terminate.
* **`read()`:**  Describe its use in inter-process communication via pipes.
* **`err()`/`perror()`:** Explain how they report errors.

**6. Addressing Dynamic Linking:**

While this specific test file doesn't directly *demonstrate* dynamic linking, I'd explain the *relevance*:

* **`ptrace` and Shared Libraries:** When debugging, `ptrace` needs to understand the memory layout of dynamically linked libraries. Breakpoints can be set in shared library code.
* **`dlopen`/`dlsym`:** Briefly mention these as the dynamic linker's functions for loading and resolving symbols in shared libraries.
* **SO Layout Sample:**  Provide a simplified example of how a shared library (`.so`) is laid out in memory (e.g., .text, .data, .bss sections).
* **Linking Process:**  Describe the high-level steps of how the dynamic linker resolves symbols and maps shared libraries into the process's address space.

**7. Logic, Assumptions, and I/O:**

For logic, I'd focus on the test scenarios:

* **Watchpoint Tests:** The assumption is that writing to the watched memory region will trigger a `SIGTRAP`.
* **Breakpoint Tests:** The assumption is that executing the code at the breakpoint address will trigger a `SIGTRAP`.
* **Resumption Tests:** The assumption is that `PTRACE_SEIZE` and related commands allow a tracer to attach and detach without causing issues.
* **Hypothetical Inputs/Outputs:**  Provide simple examples of what might happen in successful and failing test cases (e.g., child stops with `SIGTRAP`, `waitpid` returns the child's PID).

**8. Common User Errors:**

I'd highlight typical mistakes when working with `ptrace`:

* **Permissions:**  Not having sufficient privileges to trace other processes.
* **Incorrect `ptrace` calls:** Using the wrong commands or arguments.
* **Signal handling issues:** Not properly handling signals delivered to the traced process.
* **Race conditions:**  Problems arising from the asynchronous nature of tracing.
* **Yama restrictions:**  Being blocked by Yama if not tracing a direct child.

**9. Android Framework/NDK Integration:**

Explain the path from a high-level action to this code:

* **Developer Debugging:**  Starting a debug session in Android Studio -> communicates with `adb` -> `adb` starts `gdbserver` on the device -> `gdbserver` uses `ptrace` to control the target process.
* **System Tools:** Running `systrace` -> `systrace` uses `adb` to execute `atrace` on the device -> `atrace` internally uses `ptrace`.
* **NDK Code:** Native code compiled with the NDK -> can be debugged using the above mechanisms.

**10. Frida Hook Example:**

Provide a practical Frida script demonstrating how to hook a `ptrace` call and log its arguments.

**11. Language and Formatting:**

Finally, ensure the entire response is in clear, understandable Chinese and well-formatted. Using bullet points, code blocks, and clear headings makes the information easier to digest.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe go into extreme detail about every `ptrace` option.
* **Correction:** Focus on the options *used* in the test file and provide a general overview of `ptrace`.
* **Initial thought:**  Try to reverse-engineer the exact assembly generated for watchpoints.
* **Correction:** Explain the *general mechanism* of how watchpoints are set using the debug registers, as the assembly can be architecture-specific.
* **Initial thought:** Provide very low-level details about dynamic linking.
* **Correction:** Keep the dynamic linking explanation at a high-level overview relevant to how `ptrace` interacts with shared libraries.

By following this structured thought process, combining code analysis with conceptual understanding, and considering the user's various points of interest, I can generate a comprehensive and informative answer.
好的，让我们来详细分析一下 `bionic/tests/sys_ptrace_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/sys_ptrace_test.cpp` 是 Android Bionic 库中用于测试 `ptrace` 系统调用的单元测试文件。它的主要功能是验证 `ptrace` 的各种功能是否按预期工作，包括：

* **基本跟踪功能：** 测试进程能否被父进程跟踪，并接收到相应的信号（如 `SIGSTOP`）。
* **硬件断点功能：** 测试能否在子进程中设置和触发硬件断点。
* **硬件观察点功能：** 测试能否在子进程中设置和触发硬件观察点（当特定内存地址被访问或修改时触发）。
* **`PTRACE_SEIZE` 功能：** 测试 `PTRACE_SEIZE` 命令，允许一个进程在不成为其父进程的情况下附加到另一个进程并进行跟踪。
* **`PTRACE_INTERRUPT` 功能：** 测试使用 `PTRACE_INTERRUPT` 向被跟踪进程发送信号，使其停止。
* **`PTRACE_CONT` 功能：** 测试使用 `PTRACE_CONT` 继续被跟踪进程的执行。
* **在多核 CPU 上的观察点功能：** 通过将进程绑定到不同的 CPU 核心来测试观察点的可靠性。
* **处理不精确观察点事件：** 测试当被观察的内存区域与被执行的指令写入的区域重叠但不完全一致时，内核是否能正确处理。
* **跟踪恢复功能：** 测试在不同的场景下，tracer（跟踪者）附加、中断、继续 tracing 的能力，包括被跟踪进程处于运行中或僵尸状态。

**与 Android 功能的关系及举例说明**

`ptrace` 是一个非常底层的系统调用，在 Android 中有多种用途：

1. **调试器（如 gdb 和 Android Studio 的调试器）：**  调试器利用 `ptrace` 来控制被调试进程的执行，设置断点、观察变量、单步执行等。这个测试文件中的硬件断点和观察点测试就直接验证了调试器底层依赖的功能。例如，当你在 Android Studio 中设置一个断点，调试器内部会使用 `ptrace` 将断点指令写入目标进程的内存。

2. **系统调用跟踪工具（如 strace）：** `strace` 可以显示进程执行期间发出的系统调用。它也是通过 `ptrace` 来实现的，在每次系统调用发生前后拦截进程。

3. **性能分析工具：** 一些性能分析工具可能使用 `ptrace` 来收集进程的执行信息。

4. **安全工具和恶意软件分析：** 安全工具可能使用 `ptrace` 来监控进程的行为，检测恶意活动。恶意软件分析人员也可能使用 `ptrace` 来分析恶意软件的运行方式。

5. **应用沙箱：** 一些应用沙箱技术可能利用 `ptrace` 来限制被监控应用的某些行为。

**例子说明：**

* **调试 NDK 代码:** 当你使用 Android Studio 调试使用 NDK 编写的 C/C++ 代码时，底层的调试器（通常是 `gdbserver`）会使用 `ptrace` 来控制你的 native 进程，让你能够单步执行、查看变量等。`sys_ptrace_test.cpp` 中的硬件断点测试 (`TEST(sys_ptrace, hardware_breakpoint)`) 就模拟了这种场景。

* **使用 `strace` 查看应用行为:**  如果你在 Android 设备上使用 `adb shell strace <package_name>`，`strace` 工具会通过 `ptrace` 附加到目标应用的进程，并拦截它的系统调用，然后显示出来。

**每一个 libc 函数的功能是如何实现的**

这个测试文件主要使用了以下 `libc` 函数：

* **`ptrace()`:**  这是核心的系统调用。它的实现非常复杂，涉及到内核的进程管理和调度。简单来说，`ptrace` 允许一个进程（tracer）控制另一个进程（tracee）的执行，可以读取和修改 tracee 的内存和寄存器，接收 tracee 发出的信号等。具体的实现细节在 Linux 内核中，涉及到进程控制块（PCB）、信号处理、内存管理等。不同的 `ptrace` 命令（如 `PTRACE_TRACEME`, `PTRACE_PEEKUSER`, `PTRACE_POKEUSER`, `PTRACE_CONT` 等）会触发内核中不同的处理逻辑。

* **`fork()`:** 用于创建新的进程。内核会复制当前进程的大部分资源（如内存空间、文件描述符等）给新进程，但新进程有自己的 PID。

* **`waitpid()`:** 用于等待子进程状态的改变。父进程调用 `waitpid` 会进入睡眠状态，直到指定的子进程终止或被信号停止。内核会维护子进程的状态信息，当子进程状态改变时唤醒父进程。

* **`kill()`:** 用于向进程发送信号。内核会将指定的信号传递给目标进程，目标进程会根据信号类型进行处理（如终止、暂停等）。

* **`err()` 和 `perror()`:** 用于输出错误信息。它们会将错误信息输出到标准错误流，`perror()` 还会输出当前 `errno` 对应的错误描述。

* **`fcntl()`:** 虽然 `fcntl.h` 被包含，但代码中没有直接使用 `fcntl` 函数。它通常用于操作文件描述符，如改变文件状态标志。

* **`sched_setaffinity()`:** 用于设置进程的 CPU 亲和性，即指定进程可以在哪些 CPU 核心上运行。内核的调度器会尽量将进程调度到指定的 CPU 核心上。

* **`sys/prctl.h` 中定义的函数（如 `prctl()`）：**  `prctl` 提供了对进程的各种控制功能。例如，`PR_SET_PDEATHSIG` 用于设置父进程死亡信号，当父进程终止时，子进程会收到指定的信号。`PR_SET_PTRACER` 用于允许指定的进程或任何进程来 `ptrace` 当前进程。

* **`sys/uio.h` 中定义的结构体和函数（如 `iovec`）：**  `iovec` 结构体用于描述内存中的缓冲区，常用于进行分散/聚集的 I/O 操作，例如在 `ptrace` 中用于获取或设置寄存器状态。

* **`unistd.h` 中定义的函数（如 `sleep()`，实际代码中使用 `std::this_thread::sleep_for`）：**  提供了一些基本的系统调用，如进程控制、文件操作等。`sleep()` 函数会让当前进程休眠指定的时间。

**涉及 dynamic linker 的功能，so 布局样本，以及链接的处理过程**

这个测试文件本身并没有直接测试 dynamic linker 的功能，它的重点在于 `ptrace` 系统调用。但是，`ptrace` 在调试动态链接的程序时会与 dynamic linker 交互。

**SO 布局样本:**

一个典型的 Android 共享库（.so 文件）的内存布局可能如下：

```
+-------------------+  <-- 加载到内存的起始地址
| ELF Header        |
+-------------------+
| Program Headers   |  <-- 描述内存段的信息
+-------------------+
| .text (代码段)    |  <-- 可执行指令
+-------------------+
| .rodata (只读数据段)|  <-- 只读常量
+-------------------+
| .data (数据段)     |  <-- 初始化过的全局变量和静态变量
+-------------------+
| .bss (未初始化数据段)|  <-- 未初始化或初始化为 0 的全局变量和静态变量
+-------------------+
| .plt (过程链接表)  |  <-- 用于延迟绑定
+-------------------+
| .got (全局偏移表)  |  <-- 存储全局变量和函数的地址
+-------------------+
| ... 其他段 ...    |
+-------------------+
```

**链接的处理过程:**

当一个程序依赖于共享库时，dynamic linker（在 Android 上是 `linker64` 或 `linker`）负责在程序启动或运行时加载这些共享库，并将程序中对共享库函数的调用链接到共享库中的实际函数地址。这个过程主要包括：

1. **加载共享库:** Dynamic linker 根据程序头部中的信息找到需要加载的共享库，并在内存中找到合适的地址空间加载它们。

2. **符号解析:** 程序中调用共享库的函数时，最初使用的是占位符地址（在 `.plt` 中）。Dynamic linker 会查找共享库的符号表，找到对应函数的实际地址，并更新 `.got` 表，将占位符地址替换为实际地址。这就是所谓的**延迟绑定**，只有在函数第一次被调用时才会进行解析。

3. **重定位:** 共享库被加载到内存的哪个地址是不确定的，可能每次加载都不一样。Dynamic linker 需要修改共享库中一些地址相关的代码和数据，以适应当前加载的地址。

4. **依赖关系处理:** 如果加载的共享库还依赖于其他共享库，dynamic linker 需要递归地加载和链接这些依赖库。

**`ptrace` 与 dynamic linker 的交互:**

当使用 `ptrace` 调试动态链接的程序时，调试器需要理解 dynamic linker 的行为，例如：

* **设置断点在共享库代码中:** 调试器需要知道共享库被加载到哪个地址，才能正确设置断点。
* **查看共享库中的变量:** 调试器需要能够解析共享库的符号表，找到变量的地址。
* **处理延迟绑定:** 在函数被第一次调用之前，它的实际地址可能还未确定，调试器需要能够处理这种情况。

**逻辑推理，假设输入与输出**

例如，在 `watchpoint_stress` 测试中：

**假设输入:**

* `cpu`: 一个有效的 CPU 核心编号。
* `data`: 一个类型为 `uint8_t`, `uint16_t`, `uint32_t` 或 `uint64_t` 的变量。

**逻辑推理:**

1. 父进程 `fork()` 创建子进程。
2. 子进程调用 `raise(SIGSTOP)` 暂停自身执行。
3. 父进程通过 `waitpid()` 等待子进程暂停。
4. 父进程调用 `set_watchpoint()` 在子进程的 `data` 变量地址上设置观察点。
5. 父进程调用 `ptrace(PTRACE_CONT)` 让子进程继续执行。
6. 子进程执行 `data = 1;`，这会触发观察点。
7. 子进程因观察点被内核暂停，并收到 `SIGTRAP` 信号。
8. 父进程通过 `waitpid()` 再次等待子进程暂停。
9. 父进程检查子进程的停止状态和信号信息，确认观察点被触发。

**预期输出:**

* 测试成功，没有 `ASSERT` 失败。
* 如果硬件不支持观察点，测试会 `GTEST_SKIP()`。

**涉及用户或者编程常见的使用错误，请举例说明**

1. **权限不足:**  尝试 `ptrace` 一个不属于当前用户且没有设置 `PR_SET_PTRACER` 的进程会导致权限错误 (`EACCES`)。

   ```c++
   // 假设 pid 是另一个用户的进程 ID
   if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
       perror("ptrace attach failed"); // 可能会输出 "ptrace attach failed: Operation not permitted"
   }
   ```

2. **错误的 `ptrace` 命令或参数:** 使用错误的 `ptrace` 命令或提供错误的地址或数据会导致各种错误。

   ```c++
   pid_t child = fork();
   if (child == 0) {
       // ...
   } else {
       wait(nullptr);
       // 尝试读取一个无效的地址
       errno = 0;
       long value = ptrace(PTRACE_PEEKTEXT, child, (void*)0xFFFFFFFFFFFFFFFF, nullptr);
       if (value == -1 && errno != 0) {
           perror("ptrace peektext failed"); // 可能会输出 "ptrace peektext failed: Bad address"
       }
   }
   ```

3. **忘记 `PTRACE_TRACEME`:** 子进程需要调用 `ptrace(PTRACE_TRACEME)` 来允许父进程跟踪它。如果忘记调用，父进程尝试附加会失败。

   ```c++
   pid_t child = fork();
   if (child == 0) {
       // 忘记调用 ptrace(PTRACE_TRACEME)
       raise(SIGSTOP);
       _exit(0);
   } else {
       sleep(1); // 给子进程运行的时间
       if (ptrace(PTRACE_ATTACH, child, nullptr, nullptr) == -1) {
           perror("ptrace attach failed"); // 可能会输出 "ptrace attach failed: Operation not permitted"
       }
   }
   ```

4. **信号处理不当:** 在被跟踪的进程收到信号时，tracer 需要正确处理。如果处理不当，可能导致被跟踪进程行为异常。

5. **竞争条件:** 在多线程或多进程环境下使用 `ptrace` 时，可能会出现竞争条件，导致难以预测的行为。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

从 Android Framework 或 NDK 到达 `ptrace` 的路径通常涉及到以下步骤：

1. **应用层请求调试或系统调用:**  例如，开发者在 Android Studio 中点击 "Debug" 按钮，或者一个应用发起了一个需要跟踪的系统调用。

2. **Android Framework (Java 代码):**  Android Framework 会处理这些请求。例如，当启动调试会话时，ActivityManagerService 会参与进来。

3. **Native 代码 (C/C++):**  Framework 的某些部分是用 C/C++ 编写的，例如 `app_process` 进程负责启动应用。调试相关的操作最终会涉及到 native 代码。

4. **`adb` (Android Debug Bridge):**  在开发者机器上运行的 `adb` 工具与设备上的 `adbd` (adb daemon) 通信。

5. **`adbd`:**  `adbd` 运行在 Android 设备上，负责处理来自 `adb` 的命令，例如启动 `gdbserver`。

6. **`gdbserver` (或类似的调试代理):** 当启动调试会话时，`adbd` 会启动 `gdbserver` 进程，并将其附加到目标应用进程。`gdbserver` 作为一个调试代理，使用 `ptrace` 来控制目标进程。

7. **`ptrace` 系统调用:** `gdbserver` (或其他使用 `ptrace` 的工具) 通过调用 `ptrace` 系统调用来执行各种调试操作，如设置断点、单步执行、读取内存等。

**Frida Hook 示例**

可以使用 Frida Hook 来观察 `ptrace` 系统调用的执行和参数。以下是一个简单的 Frida 脚本示例：

```javascript
// attach 到目标进程，替换为你的应用包名或进程名
Process.attach("com.example.myapp");

// hook ptrace 系统调用
Interceptor.attach(Module.findExportByName(null, "ptrace"), {
  onEnter: function (args) {
    // 打印 ptrace 的第一个参数 (request)
    console.log("ptrace called with request:", args[0]);
    // 可以进一步解析 request 的值
    const request = args[0].toInt();
    if (request === 16) { // PTRACE_ATTACH
      console.log("  PTRACE_ATTACH, pid:", args[1]);
    } else if (request === 11) { // PTRACE_PEEKTEXT
      console.log("  PTRACE_PEEKTEXT, pid:", args[1], "addr:", args[2]);
    }
    // ... 可以添加更多 request 类型的判断
  },
  onLeave: function (retval) {
    console.log("ptrace returned:", retval);
  },
});
```

**使用方法:**

1. 将上述代码保存为 `ptrace_hook.js`。
2. 确保你的 Android 设备已连接并通过 `adb` 可访问。
3. 使用 Frida 命令行工具运行 hook 脚本：

   ```bash
   frida -U -f com.example.myapp -l ptrace_hook.js --no-pause
   ```

   或者，如果目标进程已经在运行：

   ```bash
   frida -U com.example.myapp -l ptrace_hook.js
   ```

**解释:**

* `Process.attach()`:  连接到目标进程。
* `Interceptor.attach()`:  拦截对 `ptrace` 函数的调用。
* `Module.findExportByName(null, "ptrace")`:  查找 `ptrace` 函数的地址。
* `onEnter`:  在 `ptrace` 函数调用之前执行。`args` 数组包含了传递给 `ptrace` 的参数。
* `onLeave`:  在 `ptrace` 函数调用返回之后执行。`retval` 是 `ptrace` 的返回值。

通过这个 Frida 脚本，你可以在目标应用运行时观察到 `ptrace` 系统调用的调用情况，包括调用的请求类型和参数，从而帮助你理解 Android Framework 或 NDK 是如何一步步使用 `ptrace` 的。

希望以上详细的解释能够帮助你理解 `bionic/tests/sys_ptrace_test.cpp` 文件的功能以及 `ptrace` 在 Android 中的应用。

Prompt: 
```
这是目录为bionic/tests/sys_ptrace_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/ptrace.h>

#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include <gtest/gtest.h>

#include <android-base/macros.h>
#include <android-base/unique_fd.h>

#include "utils.h"

using namespace std::chrono_literals;

using android::base::unique_fd;

class ChildGuard {
 public:
  explicit ChildGuard(pid_t pid) : pid(pid) {}

  ~ChildGuard() {
    kill(pid, SIGKILL);
    int status;
    TEMP_FAILURE_RETRY(waitpid(pid, &status, 0));
  }

 private:
  pid_t pid;
};

enum class HwFeature { Watchpoint, Breakpoint };

static void check_hw_feature_supported(pid_t child, HwFeature feature) {
#if defined(__arm__)
  errno = 0;
  long capabilities;
  long result = ptrace(PTRACE_GETHBPREGS, child, 0, &capabilities);
  if (result == -1) {
    EXPECT_ERRNO(EIO);
    GTEST_SKIP() << "Hardware debug support disabled at kernel configuration time";
  }
  uint8_t hb_count = capabilities & 0xff;
  capabilities >>= 8;
  uint8_t wp_count = capabilities & 0xff;
  capabilities >>= 8;
  uint8_t max_wp_size = capabilities & 0xff;
  if (max_wp_size == 0) {
    GTEST_SKIP() << "Kernel reports zero maximum watchpoint size";
  } else if (feature == HwFeature::Watchpoint && wp_count == 0) {
    GTEST_SKIP() << "Kernel reports zero hardware watchpoints";
  } else if (feature == HwFeature::Breakpoint && hb_count == 0) {
    GTEST_SKIP() << "Kernel reports zero hardware breakpoints";
  }
#elif defined(__aarch64__)
  user_hwdebug_state dreg_state;
  iovec iov;
  iov.iov_base = &dreg_state;
  iov.iov_len = sizeof(dreg_state);

  errno = 0;
  long result = ptrace(PTRACE_GETREGSET, child,
                       feature == HwFeature::Watchpoint ? NT_ARM_HW_WATCH : NT_ARM_HW_BREAK, &iov);
  if (result == -1) {
    ASSERT_ERRNO(EINVAL);
    GTEST_SKIP() << "Hardware support missing";
  } else if ((dreg_state.dbg_info & 0xff) == 0) {
    if (feature == HwFeature::Watchpoint) {
      GTEST_SKIP() << "Kernel reports zero hardware watchpoints";
    } else {
      GTEST_SKIP() << "Kernel reports zero hardware breakpoints";
    }
  }
#else
  // We assume watchpoints and breakpoints are always supported on x86.
  UNUSED(child);
  UNUSED(feature);
#endif
}

static void set_watchpoint(pid_t child, uintptr_t address, size_t size) {
  ASSERT_EQ(0u, address & 0x7) << "address: " << address;
#if defined(__arm__) || defined(__aarch64__)
  const unsigned byte_mask = (1 << size) - 1;
  const unsigned type = 2; // Write.
  const unsigned enable = 1;
  const unsigned control = byte_mask << 5 | type << 3 | enable;

#ifdef __arm__
  ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, -1, &address)) << strerror(errno);
  ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, -2, &control)) << strerror(errno);
#else // aarch64
  user_hwdebug_state dreg_state = {};
  dreg_state.dbg_regs[0].addr = address;
  dreg_state.dbg_regs[0].ctrl = control;

  iovec iov;
  iov.iov_base = &dreg_state;
  iov.iov_len = offsetof(user_hwdebug_state, dbg_regs) + sizeof(dreg_state.dbg_regs[0]);

  ASSERT_EQ(0, ptrace(PTRACE_SETREGSET, child, NT_ARM_HW_WATCH, &iov)) << strerror(errno);
#endif
#elif defined(__i386__) || defined(__x86_64__)
  ASSERT_EQ(0, ptrace(PTRACE_POKEUSER, child, offsetof(user, u_debugreg[0]), address)) << strerror(errno);
  errno = 0;
  unsigned data = ptrace(PTRACE_PEEKUSER, child, offsetof(user, u_debugreg[7]), nullptr);
  ASSERT_ERRNO(0);

  const unsigned size_flag = (size == 8) ? 2 : size - 1;
  const unsigned enable = 1;
  const unsigned type = 1; // Write.

  const unsigned mask = 3 << 18 | 3 << 16 | 1;
  const unsigned value = size_flag << 18 | type << 16 | enable;
  data &= mask;
  data |= value;
  ASSERT_EQ(0, ptrace(PTRACE_POKEUSER, child, offsetof(user, u_debugreg[7]), data)) << strerror(errno);
#else
  UNUSED(child);
  UNUSED(address);
  UNUSED(size);
#endif
}

template <typename T>
static void run_watchpoint_test(std::function<void(T&)> child_func, size_t offset, size_t size) {
  alignas(16) T data{};

  pid_t child = fork();
  ASSERT_NE(-1, child) << strerror(errno);
  if (child == 0) {
    // Extra precaution: make sure we go away if anything happens to our parent.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
      perror("prctl(PR_SET_PDEATHSIG)");
      _exit(1);
    }

    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
      perror("ptrace(PTRACE_TRACEME)");
      _exit(2);
    }

    child_func(data);
    _exit(0);
  }

  ChildGuard guard(child);

  int status;
  ASSERT_EQ(child, TEMP_FAILURE_RETRY(waitpid(child, &status, __WALL))) << strerror(errno);
  ASSERT_TRUE(WIFSTOPPED(status)) << "Status was: " << status;
  ASSERT_EQ(SIGSTOP, WSTOPSIG(status)) << "Status was: " << status;

  check_hw_feature_supported(child, HwFeature::Watchpoint);
  if (::testing::Test::IsSkipped()) {
    return;
  }

  set_watchpoint(child, uintptr_t(untag_address(&data)) + offset, size);

  ASSERT_EQ(0, ptrace(PTRACE_CONT, child, nullptr, nullptr)) << strerror(errno);
  ASSERT_EQ(child, TEMP_FAILURE_RETRY(waitpid(child, &status, __WALL))) << strerror(errno);
  ASSERT_TRUE(WIFSTOPPED(status)) << "Status was: " << status;
  ASSERT_EQ(SIGTRAP, WSTOPSIG(status)) << "Status was: " << status;

  siginfo_t siginfo;
  ASSERT_EQ(0, ptrace(PTRACE_GETSIGINFO, child, nullptr, &siginfo)) << strerror(errno);
  ASSERT_EQ(TRAP_HWBKPT, siginfo.si_code);
#if defined(__arm__) || defined(__aarch64__)
  ASSERT_LE(&data, siginfo.si_addr);
  ASSERT_GT((&data) + 1, siginfo.si_addr);
#endif
}

template <typename T>
static void watchpoint_stress_child(unsigned cpu, T& data) {
  cpu_set_t cpus;
  CPU_ZERO(&cpus);
  CPU_SET(cpu, &cpus);
  if (sched_setaffinity(0, sizeof cpus, &cpus) == -1) {
    perror("sched_setaffinity");
    _exit(3);
  }
  raise(SIGSTOP);  // Synchronize with the tracer, let it set the watchpoint.

  data = 1;  // Now trigger the watchpoint.
}

template <typename T>
static void run_watchpoint_stress(size_t cpu) {
  run_watchpoint_test<T>(std::bind(watchpoint_stress_child<T>, cpu, std::placeholders::_1), 0,
                         sizeof(T));
}

// Test watchpoint API. The test is considered successful if our watchpoints get hit OR the
// system reports that watchpoint support is not present. We run the test for different
// watchpoint sizes, while pinning the process to each cpu in turn, for better coverage.
TEST(sys_ptrace, watchpoint_stress) {
  cpu_set_t available_cpus;
  ASSERT_EQ(0, sched_getaffinity(0, sizeof available_cpus, &available_cpus));

  for (size_t cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
    if (!CPU_ISSET(cpu, &available_cpus)) continue;

    run_watchpoint_stress<uint8_t>(cpu);
    if (::testing::Test::IsSkipped()) {
      // Only check first case, since all others would skip for same reason.
      return;
    }
    run_watchpoint_stress<uint16_t>(cpu);
    run_watchpoint_stress<uint32_t>(cpu);
#if defined(__LP64__)
    run_watchpoint_stress<uint64_t>(cpu);
#endif
  }
}

struct Uint128_t {
  uint64_t data[2];
};
static void watchpoint_imprecise_child(Uint128_t& data) {
  raise(SIGSTOP);  // Synchronize with the tracer, let it set the watchpoint.

#if defined(__i386__) || defined(__x86_64__)
  asm volatile("movdqa %%xmm0, %0" : : "m"(data));
#elif defined(__arm__)
  asm volatile("stm %0, { r0, r1, r2, r3 }" : : "r"(&data));
#elif defined(__aarch64__)
  asm volatile("stp x0, x1, %0" : : "m"(data));
#elif defined(__riscv)
  UNUSED(data);
  GTEST_LOG_(INFO) << "missing riscv64 instruction to store > 64 bits in one instruction";
#endif
}

// Test that the kernel is able to handle the case when the instruction writes
// to a larger block of memory than the one we are watching. If you see this
// test fail on arm64, you will likely need to cherry-pick fdfeff0f into your
// kernel.
TEST(sys_ptrace, watchpoint_imprecise) {
  // This test relies on the infrastructure to timeout if the test hangs.
  run_watchpoint_test<Uint128_t>(watchpoint_imprecise_child, 8, sizeof(void*));
}

static void __attribute__((noinline)) breakpoint_func() {
  asm volatile("");
}

static void __attribute__((noreturn)) breakpoint_fork_child() {
  // Extra precaution: make sure we go away if anything happens to our parent.
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_PDEATHSIG)");
    _exit(1);
  }

  if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
    perror("ptrace(PTRACE_TRACEME)");
    _exit(2);
  }

  raise(SIGSTOP);  // Synchronize with the tracer, let it set the breakpoint.

  breakpoint_func();  // Now trigger the breakpoint.

  _exit(0);
}

static void set_breakpoint(pid_t child) {
  uintptr_t address = uintptr_t(breakpoint_func);
#if defined(__arm__) || defined(__aarch64__)
  address &= ~3;
  const unsigned byte_mask = 0xf;
  const unsigned enable = 1;
  const unsigned control = byte_mask << 5 | enable;

#ifdef __arm__
  ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, 1, &address)) << strerror(errno);
  ASSERT_EQ(0, ptrace(PTRACE_SETHBPREGS, child, 2, &control)) << strerror(errno);
#else  // aarch64
  user_hwdebug_state dreg_state = {};
  dreg_state.dbg_regs[0].addr = reinterpret_cast<uintptr_t>(address);
  dreg_state.dbg_regs[0].ctrl = control;

  iovec iov;
  iov.iov_base = &dreg_state;
  iov.iov_len = offsetof(user_hwdebug_state, dbg_regs) + sizeof(dreg_state.dbg_regs[0]);

  ASSERT_EQ(0, ptrace(PTRACE_SETREGSET, child, NT_ARM_HW_BREAK, &iov)) << strerror(errno);
#endif
#elif defined(__i386__) || defined(__x86_64__)
  ASSERT_EQ(0, ptrace(PTRACE_POKEUSER, child, offsetof(user, u_debugreg[0]), address))
      << strerror(errno);
  errno = 0;
  unsigned data = ptrace(PTRACE_PEEKUSER, child, offsetof(user, u_debugreg[7]), nullptr);
  ASSERT_ERRNO(0);

  const unsigned size = 0;
  const unsigned enable = 1;
  const unsigned type = 0;  // Execute

  const unsigned mask = 3 << 18 | 3 << 16 | 1;
  const unsigned value = size << 18 | type << 16 | enable;
  data &= mask;
  data |= value;
  ASSERT_EQ(0, ptrace(PTRACE_POKEUSER, child, offsetof(user, u_debugreg[7]), data))
      << strerror(errno);
#else
  UNUSED(child);
  UNUSED(address);
#endif
}

// Test hardware breakpoint API. The test is considered successful if the breakpoints get hit OR the
// system reports that hardware breakpoint support is not present.
TEST(sys_ptrace, hardware_breakpoint) {
  pid_t child = fork();
  ASSERT_NE(-1, child) << strerror(errno);
  if (child == 0) breakpoint_fork_child();

  ChildGuard guard(child);

  int status;
  ASSERT_EQ(child, TEMP_FAILURE_RETRY(waitpid(child, &status, __WALL))) << strerror(errno);
  ASSERT_TRUE(WIFSTOPPED(status)) << "Status was: " << status;
  ASSERT_EQ(SIGSTOP, WSTOPSIG(status)) << "Status was: " << status;

  check_hw_feature_supported(child, HwFeature::Breakpoint);
  if (::testing::Test::IsSkipped()) {
    return;
  }

  set_breakpoint(child);

  ASSERT_EQ(0, ptrace(PTRACE_CONT, child, nullptr, nullptr)) << strerror(errno);
  ASSERT_EQ(child, TEMP_FAILURE_RETRY(waitpid(child, &status, __WALL))) << strerror(errno);
  ASSERT_TRUE(WIFSTOPPED(status)) << "Status was: " << status;
  ASSERT_EQ(SIGTRAP, WSTOPSIG(status)) << "Status was: " << status;

  siginfo_t siginfo;
  ASSERT_EQ(0, ptrace(PTRACE_GETSIGINFO, child, nullptr, &siginfo)) << strerror(errno);
  ASSERT_EQ(TRAP_HWBKPT, siginfo.si_code);
}

class PtraceResumptionTest : public ::testing::Test {
 public:
  unique_fd worker_pipe_write;

  pid_t worker = -1;
  pid_t tracer = -1;

  PtraceResumptionTest() {
    unique_fd worker_pipe_read;
    if (!android::base::Pipe(&worker_pipe_read, &worker_pipe_write)) {
      err(1, "failed to create pipe");
    }

    // Second pipe to synchronize the Yama ptracer setup.
    unique_fd worker_pipe_setup_read, worker_pipe_setup_write;
    if (!android::base::Pipe(&worker_pipe_setup_read, &worker_pipe_setup_write)) {
      err(1, "failed to create pipe");
    }

    worker = fork();
    if (worker == -1) {
      err(1, "failed to fork worker");
    } else if (worker == 0) {
      char buf;
      // Allow the tracer process, which is not a direct process ancestor, to
      // be able to use ptrace(2) on this process when Yama LSM is active.
      if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) == -1) {
        // if Yama is off prctl(PR_SET_PTRACER) returns EINVAL - don't log in this
        // case since it's expected behaviour.
        if (errno != EINVAL) {
          err(1, "prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) failed for pid %d", getpid());
        }
      }
      worker_pipe_setup_write.reset();

      worker_pipe_write.reset();
      TEMP_FAILURE_RETRY(read(worker_pipe_read.get(), &buf, sizeof(buf)));
      exit(0);
    } else {
      // Wait until the Yama ptracer is setup.
      char buf;
      worker_pipe_setup_write.reset();
      TEMP_FAILURE_RETRY(read(worker_pipe_setup_read.get(), &buf, sizeof(buf)));
    }
  }

  ~PtraceResumptionTest() override {
  }

  void AssertDeath(int signo);

  void StartTracer(std::function<void()> f) {
    tracer = fork();
    ASSERT_NE(-1, tracer);
    if (tracer == 0) {
      f();
      if (HasFatalFailure()) {
        exit(1);
      }
      exit(0);
    }
  }

  bool WaitForTracer() {
    if (tracer == -1) {
      errx(1, "tracer not started");
    }

    int result;
    pid_t rc = TEMP_FAILURE_RETRY(waitpid(tracer, &result, 0));
    if (rc != tracer) {
      printf("waitpid returned %d (%s)\n", rc, strerror(errno));
      return false;
    }

    if (!WIFEXITED(result) && !WIFSIGNALED(result)) {
      printf("!WIFEXITED && !WIFSIGNALED\n");
      return false;
    }

    if (WIFEXITED(result)) {
      if (WEXITSTATUS(result) != 0) {
        printf("tracer failed\n");
        return false;
      }
    }

    return true;
  }

  bool WaitForWorker() {
    if (worker == -1) {
      errx(1, "worker not started");
    }

    int result;
    pid_t rc = TEMP_FAILURE_RETRY(waitpid(worker, &result, WNOHANG));
    if (rc != 0) {
      printf("worker exited prematurely\n");
      return false;
    }

    worker_pipe_write.reset();

    rc = TEMP_FAILURE_RETRY(waitpid(worker, &result, 0));
    if (rc != worker) {
      printf("waitpid for worker returned %d (%s)\n", rc, strerror(errno));
      return false;
    }

    if (!WIFEXITED(result)) {
      printf("worker didn't exit\n");
      return false;
    }

    if (WEXITSTATUS(result) != 0) {
      printf("worker exited with status %d\n", WEXITSTATUS(result));
      return false;
    }

    return true;
  }
};

static void wait_for_ptrace_stop(pid_t pid) {
  while (true) {
    int status;
    pid_t rc = TEMP_FAILURE_RETRY(waitpid(pid, &status, __WALL));
    if (rc != pid) {
      abort();
    }
    if (WIFSTOPPED(status)) {
      return;
    }
  }
}

TEST_F(PtraceResumptionTest, smoke) {
  // Make sure that the worker doesn't exit before the tracer stops tracing.
  StartTracer([this]() {
    ASSERT_EQ(0, ptrace(PTRACE_SEIZE, worker, 0, 0)) << strerror(errno);
    ASSERT_EQ(0, ptrace(PTRACE_INTERRUPT, worker, 0, 0)) << strerror(errno);
    wait_for_ptrace_stop(worker);
    std::this_thread::sleep_for(500ms);
  });

  worker_pipe_write.reset();
  std::this_thread::sleep_for(250ms);

  int result;
  ASSERT_EQ(0, TEMP_FAILURE_RETRY(waitpid(worker, &result, WNOHANG)));
  ASSERT_TRUE(WaitForTracer());
  ASSERT_EQ(worker, TEMP_FAILURE_RETRY(waitpid(worker, &result, 0)));
}

TEST_F(PtraceResumptionTest, seize) {
  StartTracer([this]() { ASSERT_EQ(0, ptrace(PTRACE_SEIZE, worker, 0, 0)) << strerror(errno); });
  ASSERT_TRUE(WaitForTracer());
  ASSERT_TRUE(WaitForWorker());
}

TEST_F(PtraceResumptionTest, seize_interrupt) {
  StartTracer([this]() {
    ASSERT_EQ(0, ptrace(PTRACE_SEIZE, worker, 0, 0)) << strerror(errno);
    ASSERT_EQ(0, ptrace(PTRACE_INTERRUPT, worker, 0, 0)) << strerror(errno);
    wait_for_ptrace_stop(worker);
  });
  ASSERT_TRUE(WaitForTracer());
  ASSERT_TRUE(WaitForWorker());
}

TEST_F(PtraceResumptionTest, seize_interrupt_cont) {
  StartTracer([this]() {
    ASSERT_EQ(0, ptrace(PTRACE_SEIZE, worker, 0, 0)) << strerror(errno);
    ASSERT_EQ(0, ptrace(PTRACE_INTERRUPT, worker, 0, 0)) << strerror(errno);
    wait_for_ptrace_stop(worker);
    ASSERT_EQ(0, ptrace(PTRACE_CONT, worker, 0, 0)) << strerror(errno);
  });
  ASSERT_TRUE(WaitForTracer());
  ASSERT_TRUE(WaitForWorker());
}

TEST_F(PtraceResumptionTest, zombie_seize) {
  StartTracer([this]() { ASSERT_EQ(0, ptrace(PTRACE_SEIZE, worker, 0, 0)) << strerror(errno); });
  ASSERT_TRUE(WaitForWorker());
  ASSERT_TRUE(WaitForTracer());
}

TEST_F(PtraceResumptionTest, zombie_seize_interrupt) {
  StartTracer([this]() {
    ASSERT_EQ(0, ptrace(PTRACE_SEIZE, worker, 0, 0)) << strerror(errno);
    ASSERT_EQ(0, ptrace(PTRACE_INTERRUPT, worker, 0, 0)) << strerror(errno);
    wait_for_ptrace_stop(worker);
  });
  ASSERT_TRUE(WaitForWorker());
  ASSERT_TRUE(WaitForTracer());
}

TEST_F(PtraceResumptionTest, zombie_seize_interrupt_cont) {
  StartTracer([this]() {
    ASSERT_EQ(0, ptrace(PTRACE_SEIZE, worker, 0, 0)) << strerror(errno);
    ASSERT_EQ(0, ptrace(PTRACE_INTERRUPT, worker, 0, 0)) << strerror(errno);
    wait_for_ptrace_stop(worker);
    ASSERT_EQ(0, ptrace(PTRACE_CONT, worker, 0, 0)) << strerror(errno);
  });
  ASSERT_TRUE(WaitForWorker());
  ASSERT_TRUE(WaitForTracer());
}

"""

```