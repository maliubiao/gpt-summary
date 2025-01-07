Response:
Let's break down the thought process for answering the request about `bionic/libc/include/bits/wait.h`.

**1. Understanding the Core Request:**

The primary goal is to understand the *purpose* and *functionality* of the provided C header file. The request also asks for connections to Android, detailed implementation explanations, dynamic linker details (though this file doesn't have any), usage errors, and how Android frameworks access it, including a Frida hook example.

**2. Initial Analysis of the Code:**

The first step is to carefully examine the code. Key observations:

* **Header Guard:** `#pragma once` prevents multiple inclusions.
* **Includes:**  `<sys/cdefs.h>` and `<linux/wait.h>`. This immediately suggests it's providing platform-specific (Linux) wait status information.
* **Macros:** The file consists entirely of preprocessor macros. This means these aren't actual functions; they are text substitutions done at compile time.
* **Naming Conventions:** The `W...` prefix clearly indicates these are related to the `wait()` family of system calls.
* **Bitwise Operations:** The macros heavily use bitwise AND (`&`), OR (`|`), and right shift (`>>`) operations. This strongly implies they are dissecting and constructing status values.
* **Comments:** The comments are helpful, explaining the purpose of each macro.

**3. Identifying the Functionality:**

Based on the macros and comments, the file's primary function is to provide convenient ways to:

* **Extract information from a process's termination status.**  This includes the exit code, the signal that terminated it (if any), and whether it dumped core, was stopped, or continued.
* **Construct process termination status values.**

**4. Connecting to Android:**

Since Bionic is Android's C library, this file is fundamental to how Android processes handle the termination of child processes. Any time an Android process uses `wait()`, `waitpid()`, or similar functions, these macros are used to interpret the returned status. This connection is crucial for understanding the file's significance within the Android ecosystem.

**5. Detailed Explanation of Each Macro:**

For each macro, the thought process is:

* **State its Purpose:** Briefly explain what the macro is intended to do based on its name and comments.
* **Analyze the Implementation:** Explain the bitwise operations involved and how they extract or combine the relevant bits of the status value. Referencing the underlying structure of the `wait()` status is important here (although the file itself doesn't explicitly define this structure, knowledge of how `wait()` works is necessary). For example, recognizing that the lower 7 bits often represent the signal number, and the upper 8 bits the exit code.
* **Provide Examples:** Illustrate the macro's usage with concrete examples. This helps clarify the bit manipulation.

**6. Dynamic Linker (SO Layout and Linking):**

It's important to recognize that this specific header file *does not directly involve the dynamic linker*. While `wait()` calls themselves might indirectly relate to process creation and thus dynamic linking, this file only deals with *interpreting the result* of such operations. Therefore, the answer should explicitly state this and explain *why* it's not relevant here. Avoid making up connections where none exist.

**7. Logical Reasoning (Assumptions and Outputs):**

For each macro, creating hypothetical input (`__status` value) and the corresponding output (true/false or the extracted value) is a good way to demonstrate understanding. This involves mentally running through the bitwise operations.

**8. Common Usage Errors:**

Think about how developers might misuse these macros. The most common error is likely misunderstanding which macro to use in a given situation, especially if they haven't checked `WIFEXITED`, `WIFSIGNALED`, etc., first. Accessing the exit status when the process was signaled, for example, is a classic mistake.

**9. Android Framework/NDK Access:**

The path from the Android Framework to these low-level libc functions is a chain of system calls. The thought process here is to trace back from high-level Android APIs down to the underlying system calls.

* **Start High-Level:**  Think of an Android API that involves process management (e.g., starting an app, a service).
* **Trace Down to Native Code:**  Realize that these high-level APIs often rely on native code (written in C/C++).
* **Identify System Calls:**  Consider what system calls would be used in native code to manage processes (e.g., `fork`, `execve`, `waitpid`).
* **Connect to `wait.h`:**  Understand that the `wait()` family of system calls returns a status value that these macros in `wait.h` are designed to interpret.
* **NDK Connection:** Explain that NDK developers directly use these libc functions and macros.

**10. Frida Hook Example:**

A Frida hook needs to target a function that uses these macros. `waitpid` is a good choice because it's a standard function that returns a status. The hook should demonstrate how to intercept the call, inspect the status, and use the macros to extract the relevant information. The example should be clear and demonstrate the process.

**11. Language and Structure:**

The request specified a Chinese response. Ensure the language is clear, concise, and technically accurate. Structure the answer logically, addressing each part of the request systematically. Use headings and bullet points to improve readability.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe this file has more complex logic.
* **Correction:**  Realize it's purely macro definitions, so the complexity lies in understanding the *meaning* of the bit patterns and how they relate to process status, not in any code execution within this file.
* **Initial thought:**  Focus heavily on the dynamic linker since the request mentioned it.
* **Correction:**  Recognize that *this specific file* has nothing to do with the dynamic linker. Address the request, but don't force a connection where one doesn't exist. Explain *why* it's not relevant.
* **Initial thought:**  Just list the macro definitions.
* **Correction:**  Realize the request asks for *explanation* and *context*. Provide detailed explanations of the bitwise operations, examples, and connections to Android.

By following this detailed thought process, breaking down the problem into smaller pieces, and constantly checking for accuracy and completeness, a comprehensive and accurate answer can be constructed.
好的，让我们详细分析 `bionic/libc/include/bits/wait.h` 这个头文件。

**功能列举:**

这个头文件的主要功能是定义了一系列用于解析和构造进程退出状态的宏。这些宏可以帮助程序员方便地从 `wait()` 或 `waitpid()` 等系统调用返回的状态值中提取有用的信息，或者构造特定的状态值。

具体来说，它定义了以下功能：

* **提取退出状态码:**  从进程正常退出时的状态值中提取退出码。
* **判断是否产生了 core dump:** 判断进程是否因为异常而产生了 core dump 文件。
* **提取终止信号:** 从被信号终止的进程的状态值中提取导致其终止的信号编号。
* **提取停止信号:** 从被信号停止的进程的状态值中提取导致其停止的信号编号。
* **判断是否正常退出:** 判断进程是否通过 `exit()` 或 `_exit()` 等方式正常退出。
* **判断是否被信号停止:** 判断进程是否被信号停止（例如，通过发送 `SIGSTOP`）。
* **判断是否被信号终止:** 判断进程是否被信号终止（例如，通过发送 `SIGKILL` 或 `SIGSEGV`）。
* **判断是否已恢复执行:** 判断进程是否从停止状态恢复执行（例如，通过发送 `SIGCONT`）。
* **构造退出状态值:**  根据给定的退出码和信号编号构造一个状态值。
* **构造停止状态值:** 根据给定的信号编号构造一个表示进程被该信号停止的状态值。

**与 Android 功能的关系及举例说明:**

这些宏在 Android 系统中扮演着至关重要的角色，因为 Android 本质上是一个多进程的操作系统。  Android 系统和应用程序需要能够管理和监控子进程的生命周期，而这些宏正是用来处理进程终止状态的关键工具。

**举例说明:**

1. **Activity/Service 启动和停止:** 当 Android Framework 启动一个新的 Activity 或 Service 时，它可能会 fork 一个新的进程。当这个 Activity 或 Service 结束时，其对应的进程会退出。Framework 需要使用 `waitpid()` 等系统调用来等待子进程的结束，并使用这里的宏来判断进程是正常退出、崩溃还是被信号杀死，从而进行相应的清理和错误处理。

2. **应用进程崩溃:** 当一个应用进程崩溃时（例如，由于空指针异常导致收到 `SIGSEGV` 信号），Android 系统会捕获这个信号，并使用 `waitpid()` 获取进程的退出状态。`WIFSIGNALED()` 会返回 true，而 `WTERMSIG()` 会返回 `SIGSEGV` 的编号，从而帮助系统判断崩溃的原因。

3. **进程管理工具 (如 `adb shell ps`)**:  像 `adb shell ps` 这样的工具需要获取系统中运行的所有进程的状态。当某个进程结束时，系统会记录其退出状态，而这些宏可以用来解析这些状态，从而显示进程是正常退出还是被信号杀死。

4. **Native 开发 (NDK):**  使用 Android NDK 进行原生开发的程序员可以直接使用这些宏来处理他们创建的子进程的退出状态。例如，一个游戏可能 fork 一个独立的进程来处理物理计算，主进程需要监控这个子进程的运行状态和退出情况。

**详细解释每一个 libc 函数的功能是如何实现的:**

实际上，`bits/wait.h` 中定义的并不是函数，而是预处理宏。这些宏在编译时会被简单地替换为相应的表达式。它们直接操作 `wait()` 或 `waitpid()` 等系统调用返回的 `status` 参数。这个 `status` 是一个整数值，其不同的比特位被用来编码进程的退出原因和状态。

* **`WEXITSTATUS(__status)`:**  这个宏通过 `((__status) & 0xff00) >> 8` 实现。`__status & 0xff00`  会屏蔽掉 `__status` 的低 8 位（通常用于存储终止信号），然后 `>> 8` 将高 8 位移动到低 8 位，即提取出退出码。假设退出码为 5，则 `__status` 的高 8 位会是 `00000101`，经过位运算后得到 5。

* **`WCOREDUMP(__status)`:** 这个宏通过 `((__status) & 0x80)` 实现。`0x80` 的二进制表示是 `10000000`。如果进程产生了 core dump，则 `__status` 的第 7 位（从 0 开始计数）会被置为 1。与 `0x80` 进行与运算，如果结果非零（即 0x80），则返回 true，表示产生了 core dump。

* **`WTERMSIG(__status)`:** 这个宏通过 `((__status) & 0x7f)` 实现。`0x7f` 的二进制表示是 `01111111`。这个宏会屏蔽掉 `__status` 的高位，保留低 7 位，即提取出导致进程终止的信号编号。

* **`WSTOPSIG(__status)`:** 这个宏直接调用 `WEXITSTATUS(__status)`。这是因为对于停止的进程，导致其停止的信号编号也会存储在 `status` 的高 8 位中，与退出状态码的位置相同。这是一种历史遗留的设计，在新的 POSIX 标准中，推荐使用 `siginfo_t` 结构体来获取更详细的信号信息。

* **`WIFEXITED(__status)`:** 这个宏通过 `(WTERMSIG(__status) == 0)` 实现。如果 `WTERMSIG(__status)` 返回 0，表示进程没有被信号终止，即正常退出。

* **`WIFSTOPPED(__status)`:** 这个宏通过 `((__status) & 0xff) == 0x7f` 实现。当进程被信号停止时，`status` 的低 8 位会被设置为 `0x7f` (十进制 127)。

* **`WIFSIGNALED(__status)`:** 这个宏通过 `(WTERMSIG((__status)+1) >= 2)` 实现。这是一个略微复杂的判断。当进程被信号终止时，`WTERMSIG(__status)` 会返回信号编号。  加上 1 再判断是否大于等于 2 的原因是，如果进程正常退出，`WTERMSIG` 返回 0，加 1 后为 1，不满足条件。信号编号通常是从 1 开始的。

* **`WIFCONTINUED(__status)`:** 这个宏通过 `((__status) == 0xffff)` 实现。当进程收到 `SIGCONT` 信号恢复执行时，`wait()` 或 `waitpid()` 会返回 `0xffff`。

* **`W_EXITCODE(__exit_code, __signal_number)`:** 这个宏通过 `((__exit_code) << 8 | (__signal_number))` 实现。它将退出码左移 8 位，然后与信号编号进行按位或运算，从而构造一个状态值。

* **`W_STOPCODE(__signal_number)`:** 这个宏通过 `((__signal_number) << 8 | 0x7f)` 实现。它将信号编号左移 8 位，然后与 `0x7f` 进行按位或运算，构造一个表示进程被该信号停止的状态值。

**对于涉及 dynamic linker 的功能:**

`bits/wait.h` 本身并不直接涉及 dynamic linker 的功能。它主要关注进程退出状态的解析和构造。Dynamic linker (在 Android 中是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库，并解析和绑定符号。

然而，`wait()` 和 `waitpid()` 系统调用可以间接地与 dynamic linker 产生关联：

1. **子进程加载共享库:** 当一个进程 `fork()` 出一个子进程后，子进程在 `execve()` 执行新的程序时，dynamic linker 会被调用来加载该程序依赖的共享库。如果加载过程中发生错误（例如，找不到共享库），`execve()` 可能会失败，导致子进程退出，并通过 `wait()` 返回相应的错误状态。虽然 `bits/wait.h` 不处理加载过程，但它可以解析由加载错误导致的进程退出状态。

2. **SO 布局样本和链接处理过程 (理论上的联系):**

   假设我们有一个简单的程序 `app` 依赖于一个共享库 `libfoo.so`。

   **SO 布局样本:**

   ```
   /system/bin/app  (可执行文件)
   /system/lib64/libfoo.so (共享库)
   ```

   **链接处理过程:**

   * 当 `app` 进程启动时，内核会加载 `app` 的代码段。
   * dynamic linker (`/system/bin/linker64`) 会被内核加载并启动。
   * dynamic linker 读取 `app` 的 ELF 头中的动态链接信息，找到其依赖的共享库 `libfoo.so`。
   * dynamic linker 在预定义的路径（例如 `/system/lib64`) 中查找 `libfoo.so`。
   * 如果找到 `libfoo.so`，dynamic linker 会将其加载到内存中的某个地址，并解析其符号表。
   * dynamic linker 解析 `app` 中对 `libfoo.so` 中符号的引用，并将这些引用绑定到 `libfoo.so` 中相应符号的地址。这个过程称为重定位。

   如果 dynamic linker 在加载或链接过程中遇到问题（例如，找不到 `libfoo.so`），`execve()` 系统调用会返回错误，并且不会创建新的进程。在这种情况下，`wait()` 函数不会被调用，因为根本没有子进程被成功执行。

   **如果 `app` 成功启动并随后崩溃:**

   假设 `libfoo.so` 中存在一个 bug 导致了程序崩溃（例如，访问了空指针）。操作系统会发送一个信号给 `app` 进程。父进程使用 `waitpid()` 可以获取到 `app` 进程的退出状态，并使用 `WIFSIGNALED()` 和 `WTERMSIG()` 来判断是哪个信号导致了崩溃。

**逻辑推理 (假设输入与输出):**

假设 `waitpid()` 返回的 `status` 值为 `0x000500` (十六进制)。

* **`WIFEXITED(0x000500)`:**
    * `WTERMSIG(0x000500)`  -> `0x000500 & 0x7f` -> `0`
    * 结果: `true` (进程正常退出)

* **`WEXITSTATUS(0x000500)`:**
    * `(0x000500 & 0xff00) >> 8` -> `0x0500 >> 8` -> `0x05` (十进制 5)
    * 结果: `5` (退出码是 5)

假设 `waitpid()` 返回的 `status` 值为 `0x000b7f` (十六进制)，表示进程被信号 11 (`SIGSEGV`) 终止。

* **`WIFSIGNALED(0x000b7f)`:**
    * `WTERMSIG(0x000b7f + 1)` -> `WTERMSIG(0x000b80)` -> `0x000b80 & 0x7f` -> `0`
    * 结果: `false` (这个例子不太好，应该用构造的方式来理解，实际的 `status` 值会更复杂)

让我们用构造的方式来理解：假设进程被 `SIGSEGV` (信号 11) 终止。根据约定，状态值可能是 `signal_number | 0x80` 的形式。

假设 `status` 为 `11 | 0x80` = `0b00001011 | 0b10000000` = `0b10001011` (十进制 139)。

* **`WIFSIGNALED(139)`:**
    * `WTERMSIG(139 + 1)` -> `WTERMSIG(140)` -> `140 & 0x7f` -> `0b10001100 & 0b01111111` -> `0b00001100` (十进制 12)
    * `12 >= 2` -> `true`

* **`WTERMSIG(139)`:**
    * `139 & 0x7f` -> `0b10001011 & 0b01111111` -> `0b00001011` (十进制 11，即 `SIGSEGV`)

**用户或编程常见的使用错误:**

1. **在调用 `wait()` 或 `waitpid()` 之前就尝试使用这些宏:**  这些宏只能用于解析 `wait()` 或 `waitpid()` 返回的有效状态值。如果在没有调用这些系统调用或者系统调用失败的情况下使用，`status` 的值可能是未定义的，导致错误的解析结果。

2. **没有先检查进程退出的方式就尝试获取退出码或信号:** 应该先使用 `WIFEXITED()`, `WIFSIGNALED()`, `WIFSTOPPED()` 等宏来判断进程是如何结束的，然后再使用相应的宏来提取具体信息。例如，如果进程是被信号杀死的，却尝试使用 `WEXITSTATUS()` 获取退出码，结果是未定义的。

   ```c
   int status;
   pid_t pid = wait(&status);
   if (pid > 0) {
       if (WIFEXITED(status)) {
           printf("进程正常退出，退出码: %d\n", WEXITSTATUS(status));
       } else if (WIFSIGNALED(status)) {
           printf("进程被信号杀死，信号编号: %d\n", WTERMSIG(status));
       } else if (WIFSTOPPED(status)) {
           printf("进程被信号停止，信号编号: %d\n", WSTOPSIG(status));
       }
   }
   ```

3. **对停止的进程使用 `WEXITSTATUS()`:**  `WEXITSTATUS()` 仅对正常退出的进程有效。对停止的进程使用它可能会得到意外的结果（通常是停止信号的编号）。

**说明 Android Framework 或 NDK 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `bits/wait.h` 的路径:**

1. **Android Framework (Java 代码):**  Android Framework 中进行进程管理的相关类，例如 `Process`, `ActivityManagerService`, `Zygote` 等，会涉及到进程的创建和监控。

2. **System Server (Native 代码):** Framework 的某些操作会调用到 System Server 的 native 代码，例如通过 JNI 调用。

3. **Bionic Libc:** System Server 的 native 代码最终会调用到 Bionic libc 提供的系统调用封装函数，例如 `waitpid()`。

4. **Kernel System Call:** `waitpid()` 函数最终会触发内核的 `waitpid` 系统调用。

5. **Kernel 返回状态:** 内核执行 `waitpid` 系统调用后，会返回子进程的退出状态。

6. **Bionic Libc `waitpid()` 返回:** Bionic libc 的 `waitpid()` 封装函数会将内核返回的原始状态值传递给调用者。

7. **Framework 或 NDK 代码使用宏:**  Framework 或 NDK 的 native 代码接收到 `waitpid()` 返回的状态值后，就会使用 `bits/wait.h` 中定义的宏来解析这个状态值，以便了解子进程的退出原因。

**NDK 到 `bits/wait.h` 的路径:**

1. **NDK 开发 (C/C++ 代码):**  NDK 开发者可以直接在他们的 native 代码中调用 `wait()` 或 `waitpid()` 等 Bionic libc 提供的函数。

2. **Bionic Libc:** 这些函数直接是 Bionic libc 的实现。

3. **`bits/wait.h` 宏使用:**  NDK 开发者在调用 `wait()` 或 `waitpid()` 后，会包含 `<sys/wait.h>` (它会包含 `<bits/wait.h>`)，并使用其中的宏来解析返回的状态值。

**Frida Hook 示例:**

以下是一个使用 Frida hook `waitpid` 函数并打印相关信息的示例：

```javascript
if (Process.platform === 'android') {
  const waitpidPtr = Module.findExportByName("libc.so", "waitpid");

  if (waitpidPtr) {
    Interceptor.attach(waitpidPtr, {
      onEnter: function (args) {
        this.pid = parseInt(args[0]);
        this.options = parseInt(args[2]);
        console.log(`[Waitpid Hook] Calling waitpid with pid: ${this.pid}, options: ${this.options}`);
      },
      onLeave: function (retval) {
        const statusPtr = this.context.rsi; // status 参数的地址 (x86_64)
        if (statusPtr.isNull()) {
          console.log("[Waitpid Hook] waitpid returned, but status pointer is NULL.");
          return;
        }
        const status = Memory.readU32(statusPtr);

        console.log(`[Waitpid Hook] waitpid returned pid: ${retval}, status: 0x${status.toString(16)}`);

        if (status !== 0) {
          const WIFEXITED = (status) => ((status & 0xff00) >> 8) === 0; // 简化的 WIFEXITED
          const WEXITSTATUS = (status) => ((status & 0xff00) >> 8);
          const WIFSIGNALED = (status) => ((status & 0x7f) !== 0 && ((status & 0xff) !== 0x7f)); // 简化的 WIFSIGNALED
          const WTERMSIG = (status) => (status & 0x7f);

          if (WIFEXITED(status)) {
            console.log(`[Waitpid Hook]   Process exited normally with status: ${WEXITSTATUS(status)}`);
          } else if (WIFSIGNALED(status)) {
            console.log(`[Waitpid Hook]   Process terminated by signal: ${WTERMSIG(status)}`);
          } else {
            console.log(`[Waitpid Hook]   Process exited with unknown status.`);
          }
        }
      }
    });
    console.log("[Frida] Hooked waitpid in libc.so");
  } else {
    console.error("[Frida] Failed to find waitpid in libc.so");
  }
} else {
  console.warn("[Frida] This script is designed for Android.");
}
```

**代码解释:**

1. **查找 `waitpid` 函数:** 使用 `Module.findExportByName` 在 `libc.so` 中查找 `waitpid` 函数的地址。
2. **附加 Interceptor:** 使用 `Interceptor.attach` 拦截 `waitpid` 函数的调用。
3. **`onEnter`:** 在 `waitpid` 函数调用之前执行，记录传入的参数 (进程 ID 和选项)。
4. **`onLeave`:** 在 `waitpid` 函数返回之后执行。
5. **读取 `status` 参数:** 从寄存器中读取 `status` 参数的地址 (x86_64 架构下，通常在 `rsi` 寄存器中)。
6. **读取状态值:** 使用 `Memory.readU32` 从 `status` 指向的内存地址读取 32 位的状态值。
7. **使用简化的宏:** 在 JavaScript 中实现 `WIFEXITED`, `WEXITSTATUS`, `WIFSIGNALED`, `WTERMSIG` 的简化版本来解析状态值。
8. **打印信息:** 打印 `waitpid` 的返回值和解析后的状态信息。

**运行 Frida Hook 的步骤:**

1. 确保你的 Android 设备已 root，并且安装了 Frida 服务。
2. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_waitpid.js`).
3. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <包名> -l hook_waitpid.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <进程名或进程ID> -l hook_waitpid.js
   ```
4. 当目标进程调用 `waitpid` 时，Frida 会拦截调用并打印相关信息，包括进程 ID、选项以及解析后的退出状态。

通过这个 Frida hook 示例，你可以动态地观察 Android 系统或应用程序中 `waitpid` 的调用情况，并验证 `bits/wait.h` 中定义的宏是如何被用于解析进程退出状态的。

Prompt: 
```
这是目录为bionic/libc/include/bits/wait.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

/**
 * @file bits/wait.h
 * @brief Process exit status macros.
 */

#include <sys/cdefs.h>

#include <linux/wait.h>

/** Returns the exit status from a process for which `WIFEXITED` is true. */
#define WEXITSTATUS(__status) (((__status) & 0xff00) >> 8)

/** Returns true if a process dumped core. */
#define WCOREDUMP(__status) ((__status) & 0x80)

/** Returns the terminating signal from a process, or 0 if it exited normally. */
#define WTERMSIG(__status) ((__status) & 0x7f)

/** Returns the signal that stopped the process, if `WIFSTOPPED` is true. */
#define WSTOPSIG(__status) WEXITSTATUS(__status)

/** Returns true if the process exited normally. */
#define WIFEXITED(__status) (WTERMSIG(__status) == 0)

/** Returns true if the process was stopped by a signal. */
#define WIFSTOPPED(__status) (((__status) & 0xff) == 0x7f)

/** Returns true if the process was terminated by a signal. */
#define WIFSIGNALED(__status) (WTERMSIG((__status)+1) >= 2)

/** Returns true if the process was resumed . */
#define WIFCONTINUED(__status) ((__status) == 0xffff)

/** Constructs a status value from the given exit code and signal number. */
#define W_EXITCODE(__exit_code, __signal_number) ((__exit_code) << 8 | (__signal_number))

/** Constructs a status value for a process stopped by the given signal. */
#define W_STOPCODE(__signal_number) ((__signal_number) << 8 | 0x7f)

"""

```