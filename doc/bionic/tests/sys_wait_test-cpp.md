Response:
Let's break down the thought process for answering the request about `bionic/tests/sys_wait_test.cpp`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C++ test file and explain its functionality within the context of Android's Bionic library. Key aspects to address include:

* **Functionality of the Test File:** What aspects of `sys/wait.h` is it testing?
* **Relationship to Android:** How does this relate to Android's core functionality?
* **Implementation Details of libc Functions:**  Explain how the `waitid` system call (and implicitly, related macros) works.
* **Dynamic Linker Involvement (if any):** This is less direct in this specific test, but important to consider generally for Bionic.
* **Logic Inference and Examples:**  Provide scenarios and expected outcomes.
* **Common Usage Errors:** Highlight potential pitfalls for developers.
* **Android Framework/NDK Path:** Describe how a user-level application interacts with these Bionic components.
* **Frida Hooking:** Demonstrate how to use Frida for dynamic analysis.

**2. Initial Code Analysis:**

* **Headers:** `#include <gtest/gtest.h>` indicates this is a unit test using Google Test. `#include <sys/wait.h>` is the crucial header – it's testing functions related to process waiting.
* **Test Cases:**  There are two test cases: `waitid` and `macros`.
* **`waitid` Test:**
    * `fork()` creates a child process.
    * The child process calls `_exit(66)`.
    * The parent process calls `waitid()` to wait for the child.
    * Assertions verify the expected return values and the information in the `siginfo_t` structure.
* **`macros` Test:** This test checks the behavior of the `WIFEXITED`, `WIFSTOPPED`, and `WIFCONTINUED` macros, with a conditional compilation based on `__GLIBC__`. This suggests differences in how these macros are handled between Bionic (based on musl) and glibc.

**3. Deconstructing the Request - Planning the Answer:**

I mentally created sections for each point of the request, outlining what information I needed to include.

* **功能 (Functionality):**  Focus on testing `waitid` and the process status macros.
* **与 Android 的关系 (Relationship to Android):** Explain how process management is fundamental to Android's architecture. Give examples like app lifecycle management.
* **libc 函数实现 (libc Function Implementation):** This requires delving into the kernel's role in process management and signal handling. I needed to explain the system call interaction.
* **Dynamic Linker (if applicable):**  While `waitid` itself isn't directly a dynamic linker function, the process creation (`fork`) and execution of the child involve the dynamic linker. I needed to touch upon how the dynamic linker sets up the child process. The SO layout example would be a simplified representation of this.
* **逻辑推理 (Logic Inference):** Focus on the `waitid` test case and explain the flow and expected outcomes based on the `fork`, `_exit`, and `waitid` calls.
* **常见错误 (Common Errors):** Think about common mistakes developers make when using `fork` and `wait` family functions, such as not handling zombie processes.
* **Android Framework/NDK Path:**  Trace the execution from a user app to the Bionic library. Mention system calls as the key interface.
* **Frida Hooking:** Provide concrete examples of how to hook `fork`, `_exit`, and `waitid`.

**4. Gathering Specific Information (Internal Knowledge and Assumptions):**

* **`waitid` System Call:** I know this system call is used to wait for changes in a child process's state. It's more flexible than `wait` or `waitpid`.
* **`fork()`:** This is a standard POSIX function that creates a new process.
* **`_exit()`:** This is a low-level function to terminate a process immediately.
* **Process States:** I need to explain exited, stopped, and continued states.
* **Bionic vs. glibc:** The conditional compilation in the `macros` test indicates differences in how Bionic and glibc handle the status macros. I need to point this out.
* **Dynamic Linking:** I understand the basic process of how the dynamic linker loads shared libraries and resolves symbols.
* **Android Architecture:**  I have a general understanding of the Android process model (Zygote, app processes, etc.).

**5. Structuring the Answer:**

I organized the answer to follow the order of the questions in the prompt, using clear headings and subheadings. This makes the information easier to digest.

**6. Writing and Refining:**

* **Clarity and Conciseness:**  I aimed for clear and concise explanations, avoiding overly technical jargon where possible, while still being accurate.
* **Examples:** I used concrete examples (like the SO layout and Frida scripts) to illustrate the concepts.
* **Addressing All Points:** I made sure to address every part of the original request.
* **Language:** I used Chinese as requested.

**Self-Correction/Refinement During the Process:**

* **Initial Thought on Dynamic Linking:**  At first, I might have considered going deeper into dynamic linking details. However, realizing that the specific test doesn't heavily exercise dynamic linking, I decided to keep that section focused on the basic concept of how the child process gets set up.
* **Level of Detail for libc Implementation:** I considered going into the kernel implementation of `waitid`. However, for this explanation, focusing on the system call interface and general behavior seemed more appropriate. I opted for a higher-level explanation.
* **Frida Script Specificity:**  I made sure the Frida scripts were concrete and practical, showing specific function names and how to intercept them.

By following this structured approach, I could break down the complex request into manageable parts and generate a comprehensive and informative answer. The key was to understand the underlying concepts being tested and relate them back to the broader Android ecosystem.
好的，让我们来详细分析一下 `bionic/tests/sys_wait_test.cpp` 这个文件。

**文件功能概览**

这个 C++ 文件是 Android Bionic 库中的一个单元测试文件。它的主要功能是测试 `sys/wait.h` 头文件中定义的与进程等待相关的函数和宏，特别是 `waitid` 函数以及用于解析进程状态的宏（`WIFEXITED`、`WIFSTOPPED`、`WIFCONTINUED`）。

**与 Android 功能的关系及举例**

进程管理是操作系统内核的核心功能之一，而 Android 作为基于 Linux 内核的操作系统，也需要对进程进行管理。`sys/wait.h` 中定义的函数和宏是用户空间程序与操作系统内核进行进程状态交互的重要接口。

* **应用启动和退出:** 当一个 Android 应用启动一个新的进程（例如使用 `Runtime.getRuntime().exec()` 或通过 JNI 调用 `fork`）时，父进程可能需要等待子进程执行完毕或发生特定状态变化。`waitid` 或其他 `wait` 系列函数就用于实现这种等待机制。
    * **例子:**  一个下载应用可能启动一个独立的进程来执行下载任务。主应用进程需要等待下载进程完成，以便更新 UI 或进行后续处理。
* **服务管理:** Android 系统中的许多服务是以独立进程运行的。服务管理器 (servicemanager) 或 init 进程需要监控这些服务进程的状态，例如是否崩溃、是否正常退出等。`wait` 系列函数在此过程中发挥作用。
    * **例子:**  当一个系统服务崩溃时，init 进程会检测到该状态并可能重启该服务。
* **进程间通信 (IPC):** 有些 IPC 机制（例如管道、信号）可能涉及到进程间的同步和等待。虽然 `waitid` 主要用于等待子进程，但在某些复杂的 IPC 场景中，对进程状态的监控仍然是必要的。
* **调试工具:** 像 `strace` 这样的调试工具，在跟踪进程执行时，会使用 `wait` 系列函数来捕获子进程的事件，例如系统调用、信号等。

**libc 函数功能及实现详解**

这个测试文件主要涉及了以下 libc 函数和宏：

1. **`fork()`:**
   * **功能:**  `fork()` 是一个系统调用，用于创建一个新的进程。新创建的进程被称为子进程，而调用 `fork()` 的进程被称为父进程。子进程几乎是父进程的精确副本，包括代码、数据、打开的文件描述符等。它们拥有独立的内存空间。
   * **实现:**
     * 当调用 `fork()` 时，内核会为子进程分配新的进程控制块 (PCB) 和进程 ID (PID)。
     * 内核会复制父进程的地址空间到子进程，但这通常是写时复制 (copy-on-write) 的，即只有当父子进程中的一方尝试修改共享内存页时，才会真正进行复制。
     * 子进程会获得父进程文件描述符的副本。
     * `fork()` 调用会返回两次：一次在父进程中返回子进程的 PID，另一次在子进程中返回 0。如果发生错误，则在父进程中返回 -1。

2. **`_exit(int status)`:**
   * **功能:** `_exit()` 是一个系统调用，用于立即终止当前进程。与 `exit()` 不同，`_exit()` 不会执行任何清理操作，例如刷新缓冲区、调用 `atexit()` 注册的函数等。
   * **实现:**
     * 当调用 `_exit()` 时，内核会释放进程占用的资源，例如内存、打开的文件等。
     * 内核会将退出状态 `status` 传递给父进程（如果存在）。父进程可以通过 `wait` 系列函数获取这个状态。
     * 进程的所有线程都会立即终止。

3. **`waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)`:**
   * **功能:** `waitid()` 是一个系统调用，用于等待指定进程或进程组的状态改变。它比 `wait` 和 `waitpid` 提供了更多的灵活性。
   * **参数:**
     * `idtype`: 指定要等待的目标类型，可以是 `P_PID`（等待特定的进程 ID）、`P_PGID`（等待特定的进程组 ID）、或 `P_ALL`（等待任何子进程）。
     * `id`:  根据 `idtype` 指定的具体 ID。
     * `infop`:  一个指向 `siginfo_t` 结构的指针，用于接收有关进程状态变化的信息。
     * `options`:  一组标志，指定要等待的进程状态变化，例如 `WEXITED`（已退出）、`WSTOPPED`（已停止）、`WCONTINUED`（已继续）。
   * **实现:**
     * 当调用 `waitid()` 时，如果指定的子进程的状态满足 `options` 的要求，内核会立即返回。
     * 如果没有符合条件的子进程，调用进程会被阻塞，直到有子进程状态发生改变。
     * 内核会将子进程的状态信息填充到 `siginfo_t` 结构中，包括：
       * `si_pid`:  导致状态改变的子进程的 PID。
       * `si_status`: 子进程的退出状态（如果进程已退出）或导致进程停止或继续的信号。
       * `si_code`:  一个附加代码，说明状态改变的原因，例如 `CLD_EXITED`（进程已退出）、`CLD_KILLED`（进程被信号杀死）、`CLD_STOPPED`（进程被信号停止）等。
   * **本例中的使用:** `TEST(sys_wait, waitid)` 中，`waitid(P_PID, pid, &si, WEXITED)` 表示父进程等待 PID 为 `pid` 的子进程退出。

4. **`WIFEXITED(status)`、`WIFSTOPPED(status)`、`WIFCONTINUED(status)`:**
   * **功能:** 这些是宏，用于检查通过 `wait` 系列函数获取的进程状态 `status`。
     * `WIFEXITED(status)`:  如果子进程正常退出，则返回非零值。
     * `WIFSTOPPED(status)`: 如果子进程被信号停止，则返回非零值。
     * `WIFCONTINUED(status)`: 如果子进程被信号继续执行，则返回非零值。
   * **实现:** 这些宏通常通过位运算来检查状态值中的特定位。进程退出状态、停止信号等信息被编码在状态值中。
   * **本例中的使用:** `TEST(sys_wait, macros)` 测试了这些宏对于特定状态值的行为，并特别注意了 Bionic 和 glibc 在实现上的差异。Bionic 基于 musl libc，与 glibc 在某些细节上有所不同。

**涉及 Dynamic Linker 的功能**

虽然 `sys_wait_test.cpp` 本身并没有直接测试 dynamic linker 的功能，但当涉及到进程创建 (`fork()`) 和执行新程序时，dynamic linker (在 Android 上通常是 `linker64` 或 `linker`) 就扮演了关键角色。

**so 布局样本 (简化)**

当一个新进程被 `fork()` 创建后，如果子进程需要执行新的程序（例如通过 `execve` 系统调用），dynamic linker 会负责加载程序所需的共享库 (`.so` 文件)。一个简化的 so 布局可能如下所示：

```
[进程地址空间]
----------------------------------------------------
|  ... (其他段) ...                                |
----------------------------------------------------
|  Load Address of Executable (如 /system/bin/app) |
----------------------------------------------------
|  .text (代码段)                                  |
----------------------------------------------------
|  .rodata (只读数据段)                             |
----------------------------------------------------
|  .data (已初始化数据段)                           |
----------------------------------------------------
|  .bss (未初始化数据段)                            |
----------------------------------------------------
|  共享库 1 (.so) 的加载地址 (如 /system/lib64/libc.so) |
----------------------------------------------------
|  共享库 1 的 .text 段                           |
----------------------------------------------------
|  共享库 1 的 .rodata 段                         |
----------------------------------------------------
|  ...                                            |
----------------------------------------------------
|  共享库 2 (.so) 的加载地址 (如 /system/lib64/libm.so) |
----------------------------------------------------
|  共享库 2 的 .text 段                           |
----------------------------------------------------
|  ...                                            |
----------------------------------------------------
|  Stack (栈)                                      |
----------------------------------------------------
|  Heap (堆)                                       |
----------------------------------------------------
```

**链接的处理过程**

1. **程序加载:** 当通过 `execve` 执行一个新程序时，内核会加载程序的可执行文件到内存中。
2. **Dynamic Linker 的启动:** 内核会识别出这是一个动态链接的程序，并将控制权交给 dynamic linker。dynamic linker 的路径通常硬编码在可执行文件中。
3. **依赖项解析:** Dynamic linker 会读取可执行文件的头部信息，找到所需的共享库列表 (DT_NEEDED entries)。
4. **共享库加载:** Dynamic linker 会按照一定的顺序加载这些共享库到进程的地址空间中。这可能涉及到查找库文件、分配内存、将库文件的内容加载到内存中等步骤。
5. **符号解析 (Symbol Resolution):** Dynamic linker 会解析程序和共享库之间的符号引用关系。例如，如果程序调用了 `libc.so` 中的 `printf` 函数，dynamic linker 会找到 `printf` 函数在 `libc.so` 中的地址，并将调用指令的目标地址更新为该地址。
6. **重定位 (Relocation):** 由于共享库被加载到不同的内存地址，dynamic linker 需要调整代码和数据中的一些地址引用，使其指向正确的内存位置。
7. **控制权转移:** 完成所有必要的链接操作后，dynamic linker 将控制权交给程序的入口点。

**逻辑推理、假设输入与输出**

**`TEST(sys_wait, waitid)` 分析:**

* **假设输入:**  无特定的外部输入，依赖于 `fork()` 的成功执行。
* **执行流程:**
    1. `fork()` 创建一个子进程。
    2. 父进程的 `pid` 变量保存子进程的 PID（非 -1）。
    3. 子进程执行 `_exit(66)`，退出状态为 66。
    4. 父进程调用 `waitid` 等待 PID 为 `pid` 的子进程退出。
    5. `waitid` 成功返回 0。
    6. `si.si_pid` 应该等于子进程的 PID。
    7. `si.si_status` 应该等于子进程的退出状态 66。
    8. `si.si_code` 应该等于 `CLD_EXITED`，表示子进程已退出。
* **预期输出:**  所有 `ASSERT_EQ` 断言都应该通过。

**`TEST(sys_wait, macros)` 分析:**

* **假设输入:**  硬编码的十六进制状态值，例如 `0x7f`、`0x80`、`0xffff`。
* **执行流程:**
    1. 根据是否定义了 `__GLIBC__` 宏，执行不同的断言分支。在 Android Bionic 环境下，通常不会定义 `__GLIBC__`，因此会执行 `#else` 分支。
    2. 对于每个状态值，宏 `WIFEXITED`、`WIFSTOPPED`、`WIFCONTINUED` 会根据其内部的位运算逻辑返回 `true` 或 `false`。
* **预期输出:**  所有 `ASSERT_FALSE` 和 `ASSERT_TRUE` 断言都应该通过，验证宏的行为符合预期。

**用户或编程常见的使用错误**

1. **忘记处理 `fork()` 的返回值:**  开发者必须检查 `fork()` 的返回值来区分父进程和子进程，并处理错误情况。
   ```c++
   pid_t pid = fork();
   if (pid == -1) {
       perror("fork"); // 处理 fork 失败的情况
       exit(1);
   } else if (pid == 0) {
       // 子进程代码
       _exit(0);
   } else {
       // 父进程代码
       wait(nullptr); // 等待子进程
   }
   ```

2. **产生僵尸进程 (Zombie Process):** 如果父进程没有调用 `wait` 系列函数来回收已退出的子进程的资源，子进程会变成僵尸进程，占用系统资源。
   ```c++
   pid_t pid = fork();
   if (pid == 0) {
       _exit(0);
   } else {
       // 父进程没有调用 wait，子进程会变成僵尸进程
       sleep(10); // 模拟父进程做其他事情
   }
   ```

3. **错误地使用 `wait` 系列函数:**  例如，使用 `wait` 等待一个不存在的子进程，或者没有正确处理 `wait` 函数的返回值。
   ```c++
   pid_t pid = 12345; // 假设这个 PID 不存在或不是子进程
   int status;
   pid_t result = waitpid(pid, &status, 0);
   if (result == -1) {
       perror("waitpid"); // 可能输出 "No child processes" 或 "Invalid argument"
   }
   ```

4. **混淆 `exit()` 和 `_exit()`:**  应该根据是否需要执行清理操作来选择合适的退出函数。通常在库函数中使用 `_exit`，而在 `main` 函数或需要进行清理的地方使用 `exit`。

5. **对 `wait` 返回的状态码进行错误的解析:**  必须使用 `WIFEXITED`、`WEXITSTATUS` 等宏来正确解析 `wait` 函数返回的状态码。直接使用状态码的数值可能会导致错误，因为状态码的位结构是特定的。

**Android Framework 或 NDK 如何到达这里**

以下是一个简化的步骤说明 Android 应用如何间接使用到 `sys/wait.h` 中的功能：

1. **Java 代码调用:** Android 应用的 Java 代码可能通过 `ProcessBuilder` 类或 `Runtime.getRuntime().exec()` 方法来执行外部命令或启动新的进程。

   ```java
   // Java 代码示例
   Process process = new ProcessBuilder("/system/bin/ls", "-l").start();
   int exitCode = process.waitFor(); // 这里会间接使用 wait 系列函数
   ```

2. **NDK 调用:** 如果应用使用了 NDK (Native Development Kit) 进行本地代码开发，可以直接调用 `fork` 和 `wait` 系列的 C/C++ 函数。

   ```c++
   // NDK C++ 代码示例
   #include <unistd.h>
   #include <sys/wait.h>
   #include <android/log.h>

   extern "C" JNIEXPORT void JNICALL
   Java_com_example_myapp_MainActivity_runNativeProcess(JNIEnv *env, jobject /* this */) {
       pid_t pid = fork();
       if (pid == 0) {
           execlp("ls", "ls", "-l", nullptr);
           _exit(127); // exec 失败
       } else if (pid > 0) {
           int status;
           waitpid(pid, &status, 0);
           if (WIFEXITED(status)) {
               __android_log_print(ANDROID_LOG_INFO, "NativeProcess", "Child exited with status %d", WEXITSTATUS(status));
           }
       } else {
           __android_log_print(ANDROID_LOG_ERROR, "NativeProcess", "fork failed");
       }
   }
   ```

3. **系统调用:** 无论是 Java 的 `ProcessBuilder` 还是 NDK 的直接调用，最终都会通过系统调用 (syscall) 进入 Linux 内核。例如，`process.waitFor()` 会最终调用类似 `wait4` 的系统调用。

4. **Bionic libc:** Android 的 libc (Bionic) 提供了对这些系统调用的封装。`sys/wait.h` 中定义的函数实际上是对内核提供的 `wait` 相关系统调用的用户空间接口。

**Frida Hook 示例调试步骤**

可以使用 Frida 来 hook `fork`, `_exit`, 和 `waitid` 函数，以观察它们的行为和参数。

**Frida Hook 脚本示例 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, "libc.so"); // 获取 libc.so 的基地址

  if (libc) {
    const forkPtr = Module.findExportByName("libc.so", "fork");
    const exitPtr = Module.findExportByName("libc.so", "_exit");
    const waitidPtr = Module.findExportByName("libc.so", "waitid");

    if (forkPtr) {
      Interceptor.attach(forkPtr, {
        onEnter: function (args) {
          console.log("[Fork] Calling fork()");
        },
        onLeave: function (retval) {
          console.log("[Fork] fork() returned:", retval.toInt32());
        }
      });
    }

    if (exitPtr) {
      Interceptor.attach(exitPtr, {
        onEnter: function (args) {
          console.log("[_exit] Calling _exit with status:", args[0].toInt32());
        }
      });
    }

    if (waitidPtr) {
      Interceptor.attach(waitidPtr, {
        onEnter: function (args) {
          const idtype = args[0].toInt32();
          const id = args[1].toInt32();
          const infop = ptr(args[2]);
          const options = args[3].toInt32();

          const idtypeMap = { 0: "P_PID", 1: "P_PGID", 2: "P_ALL" };
          const optionsMap = { 1: "WNOWAIT", 2: "WUNTRACED", 4: "WSTOPPED", 8: "WEXITED", 64: "WCONTINUED", 128: "WNOHANG", 536870912: "__WCLONE" }; // 部分常见选项

          console.log("[waitid] Calling waitid(" + idtypeMap[idtype] + ", " + id + ", " + infop + ", " + options.toString(16) + ")");
        },
        onLeave: function (retval) {
          console.log("[waitid] waitid() returned:", retval.toInt32());
          // 可以进一步读取 infop 指向的内存，查看子进程状态信息
        }
      });
    }
  } else {
    console.log("libc.so not found!");
  }
} else {
  console.log("Not running on Android");
}
```

**调试步骤:**

1. **准备环境:** 确保已安装 Frida 和 Frida-server，并将 Frida-server 部署到 Android 设备上。
2. **运行目标应用:** 运行你想要调试的 Android 应用。
3. **执行 Frida 脚本:** 使用 Frida 命令运行上面的 JavaScript 脚本，指定目标应用的进程名称或 PID。
   ```bash
   frida -U -f <应用包名> -l your_script.js --no-pause
   # 或者
   frida -U <进程名或PID> -l your_script.js
   ```
4. **观察输出:** 当应用执行到 `fork`, `_exit`, 或 `waitid` 函数时，Frida 会拦截这些调用并打印出相关信息，例如参数和返回值。

通过 Frida hook，你可以动态地观察 Android 系统中进程创建、退出和等待的详细过程，这对于理解系统行为、调试问题非常有帮助。

希望以上详细的分析能够帮助你理解 `bionic/tests/sys_wait_test.cpp` 文件及其相关的功能。

Prompt: 
```
这是目录为bionic/tests/sys_wait_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2020 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <sys/wait.h>

TEST(sys_wait, waitid) {
  pid_t pid = fork();
  ASSERT_NE(pid, -1);

  if (pid == 0) _exit(66);

  siginfo_t si = {};
  ASSERT_EQ(0, waitid(P_PID, pid, &si, WEXITED));
  ASSERT_EQ(pid, si.si_pid);
  ASSERT_EQ(66, si.si_status);
  ASSERT_EQ(CLD_EXITED, si.si_code);
}

// https://github.com/android/ndk/issues/1878
TEST(sys_wait, macros) {
#if defined(__GLIBC__)
  // glibc before 2016 requires an lvalue.
#else
  ASSERT_FALSE(WIFEXITED(0x7f));
  ASSERT_TRUE(WIFSTOPPED(0x7f));
  ASSERT_FALSE(WIFCONTINUED(0x7f));

  ASSERT_TRUE(WIFEXITED(0x80));
  ASSERT_FALSE(WIFSTOPPED(0x80));
  ASSERT_FALSE(WIFCONTINUED(0x80));

  ASSERT_FALSE(WIFEXITED(0xffff));
  ASSERT_FALSE(WIFSTOPPED(0xffff));
  ASSERT_TRUE(WIFCONTINUED(0xffff));
#endif
}

"""

```