Response:
Let's break down the thought process for analyzing this C++ code. The request is comprehensive, asking for functionality, Android relevance, libc details, dynamic linker aspects, logical reasoning, common errors, and how Android framework/NDK interacts, along with Frida hooks.

**1. Initial Skim and High-Level Understanding:**

The first step is to quickly read through the code to get a general idea of its purpose. Keywords like `stack_tagging_helper`, `mte_set_tag`, `mte_get_tag`, `vfork`, `longjmp`, `sigaltstack`, `android_mallopt`, and `exception_cleanup` stand out. The `#if defined(__aarch64__)` also immediately tells us this code is specific to the ARM64 architecture. This initial scan suggests the code is focused on testing stack tagging functionality, specifically related to Memory Tagging Extension (MTE) on ARM64.

**2. Deconstructing Functionality - What does it *do*?**

Now, let's analyze each major block of code:

* **MTE Helper Functions (`mte_set_tag`, `mte_get_tag`, `mte_increment_tag`):** These are clearly inline assembly functions for manipulating memory tags. The comments and assembly instructions directly reveal their purpose.
* **`test_vfork` and related functions (`vfork_child`, `vfork_child2`, `vfork_parent`):** This set of functions tests how stack tags are preserved or changed after a `vfork` call. It examines different scenarios like `execve`, `execl`, and `_exit` in the child process.
* **`test_longjmp` and related functions (`settag_and_longjmp`, `check_stack_tags`, `check_longjmp_restores_tags`):** These functions are designed to test whether stack tags are correctly restored after a `longjmp`. The use of `setjmp` and `longjmp` is a clear indicator.
* **`test_longjmp_sigaltstack` and related classes (`SigAltStackScoped`, `SigActionScoped`):** This section focuses on testing `longjmp` behavior when a signal handler is executed on an alternate signal stack. The scoped classes manage the setup and teardown of the alternate stack and signal handler.
* **`test_android_mallopt`:** This function checks the status of the `M_MEMTAG_STACK_IS_ON` option using `android_mallopt`.
* **`test_exception_cleanup` and related functions (`throws`, `maybe_throws`, `skip_frame`, `skip_frame2`, `skip_frame3`):**  This part investigates how stack tags are handled during exception handling. The `@no_sanitize("memtag")` attribute is crucial here, indicating intentional disabling of MTE sanitization in certain frames.
* **`main` function:** This function parses command-line arguments to run specific test cases.

**3. Connecting to Android Functionality:**

The code resides in `bionic`, which is Android's core C library. MTE is a hardware feature that Android leverages for memory safety. The tests are directly related to how Android's memory management interacts with MTE during system calls (`vfork`), non-local jumps (`longjmp`), signal handling, and exception handling. `android_mallopt` is a Bionic-specific function, further solidifying the Android connection.

**4. libc Function Details:**

For each libc function used, a deeper understanding is needed:

* **Standard C Library Functions:**  `errno.h`, `setjmp.h`, `signal.h`, `stdio.h`, `stdlib.h`, `string.h`, `sys/mman.h`, `sys/types.h`, `sys/wait.h`, `unistd.h`. Briefly explain the core purpose of each header and the functions used (e.g., `vfork`, `execve`, `longjmp`, `sigaltstack`, `mmap`, `waitpid`, `exit`).
* **Bionic-Specific Functions:** `bionic/malloc.h` (likely introduces `android_mallopt`). Focus on the specific function used.

**5. Dynamic Linker Aspects:**

The `execve` and `execl` tests are relevant here. The child process will need to be loaded and linked by the dynamic linker (`linker64` on ARM64).

* **SO Layout:**  Describe a typical SO layout (code, data, PLT, GOT).
* **Linking Process:** Briefly explain symbol resolution, relocation, and how the dynamic linker maps shared libraries into the process's address space.

**6. Logical Reasoning (Assumptions and Outputs):**

For each test case, consider:

* **Input:**  The command-line arguments passed to the `main` function.
* **Expected Output:**  Based on the code, predict what the test should achieve and whether it should pass or fail (implicitly, these tests are designed to pass if MTE is working correctly). For example, in `test_vfork`, the parent should observe consistent stack tags. In `test_longjmp`, the tags should be restored.

**7. Common User/Programming Errors:**

Think about how a developer might misuse or misunderstand MTE or the functions being tested. For instance, directly manipulating memory tags without understanding the implications, or assuming `longjmp` preserves all memory state without considering MTE.

**8. Android Framework/NDK Interaction:**

Trace how execution might reach this code:

* **Framework:** An app makes a system call that internally uses Bionic functions.
* **NDK:**  An NDK app directly calls Bionic functions. Provide a simplified example of an NDK function calling a Bionic function.

**9. Frida Hook Examples:**

For key functions (e.g., `mte_set_tag`, `vfork_child`, `longjmp`), create basic Frida script snippets to intercept calls, log arguments, and potentially modify behavior.

**Self-Correction/Refinement During the Process:**

* **Architecture Specificity:**  Continuously remember the ARM64 focus.
* **MTE Focus:** Ensure the explanations are centered around memory tagging.
* **Clarity and Detail:** Provide sufficient detail for each point without being overly verbose.
* **Code Snippets:** Include relevant code snippets to illustrate points.
* **Review and Organize:**  After drafting the initial response, review it for clarity, accuracy, and completeness. Organize the information logically according to the prompt's requirements. For example, group related tests together.

By following these steps, we can systematically analyze the given C++ code and generate a comprehensive and accurate response that addresses all aspects of the request. The key is to break down the problem into smaller, manageable parts and then synthesize the information.
这个`bionic/tests/libs/stack_tagging_helper.cpp` 文件是 Android Bionic 库中的一个测试文件，专门用于测试 **堆栈标记（Stack Tagging）** 相关的功能。堆栈标记是 ARMv8.5 引入的内存标记扩展 (Memory Tagging Extension, MTE) 的一种应用，用于在堆栈上分配的内存区域中引入标记，从而帮助检测内存安全错误，例如堆栈缓冲区溢出。

以下是该文件的详细功能解释：

**1. 功能概述：**

该文件的主要目的是测试 Bionic 库中与堆栈标记相关的机制是否正常工作。它通过一系列的测试用例来验证以下场景：

* **基本堆栈标记操作:**  测试设置、获取和递增堆栈内存区域标记的功能 (`mte_set_tag`, `mte_get_tag`, `mte_increment_tag`)。
* **`vfork` 后的堆栈标记:** 测试在 `vfork` 系统调用后，父子进程的堆栈标记是否保持一致。这对于确保在 `vfork` 创建子进程时，内存安全属性得以继承非常重要。
* **`longjmp` 后的堆栈标记:** 测试在使用 `setjmp` 和 `longjmp` 进行非本地跳转后，堆栈标记是否被正确恢复。这对于异常处理和协程等场景至关重要。
* **信号处理程序中的堆栈标记:** 测试在信号处理程序（特别是使用 `sigaltstack` 设置的备用堆栈）中，堆栈标记是否正常工作。
* **`android_mallopt` 的堆栈标记选项:** 检查 `android_mallopt` 函数是否能够正确报告堆栈标记功能是否开启。
* **异常处理中的堆栈标记清理:** 测试在 C++ 异常抛出和捕获过程中，堆栈标记是否被正确清理，以避免误报。

**2. 与 Android 功能的关系及举例说明：**

这个文件直接关系到 Android 的安全性和稳定性。堆栈标记是一种增强内存安全性的技术，可以帮助开发者更早地发现和修复与堆栈相关的内存错误，例如：

* **堆栈缓冲区溢出 (Stack Buffer Overflow):**  攻击者可以利用堆栈缓冲区溢出覆盖返回地址或其他关键数据，从而控制程序执行流程。堆栈标记可以检测到这种越界访问。
    * **举例:**  假设一个函数在堆栈上分配了一个固定大小的缓冲区，但没有正确检查用户输入的大小，导致输入数据超过缓冲区大小，覆盖了相邻的堆栈帧。开启堆栈标记后，当程序尝试访问被溢出覆盖的带有不同标记的内存时，会触发错误。
* **使用已释放的堆栈内存 (Use-After-Return):**  当一个函数返回后，其局部变量所在的堆栈空间应该被释放。如果程序仍然尝试访问这些已释放的内存，可能会导致崩溃或安全漏洞。堆栈标记可以帮助检测这种访问。
    * **举例:**  一个函数返回指向其局部变量的指针。在函数返回后，主调函数仍然尝试解引用这个指针。由于堆栈帧已经被释放，并且可能被重新分配并带有不同的标记，堆栈标记机制可以检测到这种非法访问。

**3. libc 函数的功能及实现：**

该文件使用了一些标准的 libc 函数，以下解释其功能和大致实现（Bionic 中的实现可能与标准 libc 有细微差别）：

* **`errno.h`:** 定义了错误码，例如 `errno` 变量。
* **`setjmp.h`:**
    * **`setjmp(jmp_buf env)`:**  保存当前程序的执行上下文（包括程序计数器、堆栈指针、寄存器等）到 `jmp_buf` 结构体中。它返回 0 表示直接调用。
    * **`longjmp(jmp_buf env, int val)`:**  恢复之前由 `setjmp` 保存的执行上下文。程序会像从 `setjmp` 返回一样继续执行，但 `setjmp` 的返回值是 `longjmp` 的第二个参数 `val`。
    * **实现:**  `setjmp` 通常通过汇编指令将当前的寄存器状态和堆栈信息保存到 `jmp_buf` 中。`longjmp` 则将 `jmp_buf` 中保存的信息恢复到 CPU 寄存器，并跳转到 `setjmp` 保存的指令地址。
* **`signal.h`:**
    * **`sigaltstack(const stack_t *ss, stack_t *old_ss)`:**  允许程序指定一个备用的堆栈用于处理信号。这对于防止在信号处理程序中发生堆栈溢出非常重要。
        * **实现:**  内核维护着进程的信号堆栈信息。`sigaltstack` 系统调用会更新这些信息。当发生信号时，如果设置了 `SA_ONSTACK` 标志，内核会将信号处理程序的执行切换到指定的备用堆栈。
    * **`sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`:**  用于设置信号处理程序。可以指定信号处理函数、标志（例如 `SA_SIGINFO` 用于传递更详细的信号信息，`SA_ONSTACK` 指定在备用堆栈上执行处理程序）。
        * **实现:**  内核维护着一个信号描述符表，每个信号对应一个条目。`sigaction` 系统调用会修改这个表中指定信号的条目，设置其处理函数和标志。
    * **`raise(int sig)`:**  向当前进程发送一个信号。
        * **实现:**  `raise` 通常会调用 `kill(getpid(), sig)` 系统调用，将信号发送给当前进程。
* **`stdio.h`:**  提供标准输入输出函数，例如 `fprintf`。
* **`stdlib.h`:**
    * **`malloc.h` (被包含):**  提供动态内存分配函数 `malloc`（虽然在这个文件中没有直接使用，但 `bionic/malloc.h` 提供了与内存分配相关的 Bionic 特定功能）。
    * **`exit(int status)`:**  终止当前进程，并将退出状态返回给父进程。
    * **`_exit(int status)`:**  立即终止当前进程，不执行任何清理操作（例如刷新缓冲区、调用 `atexit` 注册的函数）。通常在 `fork` 或 `vfork` 的子进程中使用。
    * **`atoi` 等其他标准库函数（尽管文件中未使用，但属于 `stdlib.h`）。
* **`string.h`:** 提供字符串操作函数，例如 `strcmp`。
* **`sys/mman.h`:**
    * **`mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)`:**  将文件或设备映射到内存中，或者分配一块新的内存区域。
        * **实现:**  `mmap` 是一个系统调用，它请求内核在进程的地址空间中创建一个新的虚拟内存区域，并将其与文件或匿名内存关联起来。
    * **`munmap(void *addr, size_t length)`:**  取消之前由 `mmap` 创建的内存映射。
        * **实现:**  `munmap` 系统调用通知内核释放指定的虚拟内存区域。
    * **`getpagesize()`:**  获取系统的页大小。
* **`sys/types.h`:** 定义了一些基本的数据类型，例如 `pid_t`。
* **`sys/wait.h`:**
    * **`waitpid(pid_t pid, int *wstatus, int options)`:**  等待指定的子进程结束。
        * **实现:**  `waitpid` 是一个系统调用，它让父进程进入睡眠状态，直到指定的子进程状态发生变化（例如退出、被信号终止）。内核会更新 `wstatus` 以指示子进程的退出状态。
    * **`WIFEXITED(int status)`:**  检查 `waitpid` 返回的状态是否表示子进程正常退出。
    * **`WEXITSTATUS(int status)`:**  获取子进程的退出状态码。
    * **`WIFSIGNALED(int status)`:**  检查 `waitpid` 返回的状态是否表示子进程被信号终止。
* **`unistd.h`:**
    * **`vfork()`:**  创建一个子进程。与 `fork` 类似，但子进程会共享父进程的内存空间和执行上下文。在子进程调用 `execve` 或 `_exit` 之前，父进程会被阻塞。
        * **实现:**  `vfork` 是一个系统调用，它创建子进程，但不复制父进程的页表。子进程直接运行在父进程的地址空间中。
    * **`execve(const char *pathname, char *const argv[], char *const envp[])`:**  执行一个新的程序。当前进程的映像会被新的程序替换。
        * **实现:**  `execve` 是一个系统调用，它加载并执行指定路径的可执行文件。内核会创建新的堆栈、数据段等，并从可执行文件的入口点开始执行。
    * **`execl(const char *pathname, const char *arg, ...)`:**  与 `execve` 类似，但参数传递方式不同。
    * **`getpid()`:**  获取当前进程的进程 ID。
* **`<thread>`:** 提供 C++ 标准库的线程支持（用于测试多线程场景下的堆栈标记）。
* **`bionic/malloc.h`:**
    * **`android_mallopt(int option, void *arg, size_t arg_size)`:**  提供 Android 特定的内存分配器选项控制。在这个文件中，它用于查询堆栈标记是否开启 (`M_MEMTAG_STACK_IS_ON`).

**4. 涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程：**

`execve` 和 `execl` 功能涉及到 dynamic linker。当子进程调用 `execve` 或 `execl` 时，内核会加载新的可执行文件，并启动 dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 来加载和链接程序依赖的共享库。

**SO 布局样本：**

一个典型的共享库 (`.so`) 文件布局可能如下：

```
.dynamic 段：包含动态链接器需要的信息，如依赖的库、符号表的位置、重定位表的位置等。
.hash 或 .gnu.hash 段：用于加速符号查找的哈希表。
.plt 段 (Procedure Linkage Table)：用于延迟绑定，当首次调用共享库函数时跳转到 dynamic linker 进行解析。
.got 段 (Global Offset Table)：存放全局变量和函数地址，需要被动态链接器重定位。
.text 段：可执行代码段。
.rodata 段：只读数据段，例如字符串常量。
.data 段：已初始化的全局变量和静态变量。
.bss 段：未初始化的全局变量和静态变量。
```

**链接的处理过程：**

1. **加载器启动:** 当 `execve` 被调用时，内核会加载新的可执行文件，并启动 dynamic linker。
2. **解析依赖:** dynamic linker 读取可执行文件的 `.dynamic` 段，获取其依赖的共享库列表。
3. **加载共享库:** dynamic linker 尝试在预定义路径（例如 `/system/lib64`, `/vendor/lib64` 等）中找到并加载这些共享库到进程的地址空间。
4. **符号解析 (Symbol Resolution):** 当程序调用共享库中的函数时，会先跳转到 PLT 中的一个桩代码。第一次调用时，PLT 中的桩代码会跳转到 dynamic linker。dynamic linker 会在已加载的共享库的符号表中查找被调用函数的地址。
5. **重定位 (Relocation):** 找到符号地址后，dynamic linker 会更新 GOT 中对应条目的值，将其指向找到的函数地址。后续的调用会直接通过 GOT 跳转到函数，避免了重复的符号查找。
6. **执行控制转移:** 链接完成后，dynamic linker 将控制权转移到新加载的程序。

**在该测试文件中的体现：**

在 `test_vfork` 函数中，子进程会调用 `execve("/system/bin/true", ...)` 或 `execl("/system/bin/true", ...)`。 这会触发 dynamic linker 加载并链接 `/system/bin/true` 程序。 虽然这个测试本身并不直接测试 dynamic linker 的细节，但它依赖于 dynamic linker 的正确工作来启动子进程。

**5. 逻辑推理，假设输入与输出：**

以下针对一些关键测试用例进行逻辑推理：

**`test_vfork(ChildAction::Exit)`:**

* **假设输入:** 命令行参数为 `"vfork_exit"`。
* **逻辑推理:**
    1. 父进程 `vfork` 创建子进程。
    2. 子进程执行 `vfork_child(ChildAction::Exit)`。
    3. `vfork_child` 函数在堆栈上分配缓冲区并标记一部分。
    4. 子进程调用 `vfork_child2(ChildAction::Exit, ...)`。
    5. `vfork_child2` 函数执行 `_exit(0)`，子进程退出。
    6. 父进程从 `vfork` 返回，执行 `vfork_parent`。
    7. `vfork_parent` 检查其堆栈上的标记是否与预期一致。由于子进程在 `_exit` 前没有修改父进程的内存空间，父进程的堆栈标记应该保持不变。
    8. 父进程 `waitpid` 等待子进程结束。
    9. 父进程检查子进程的退出状态是否为 0。
* **预期输出:** 测试成功，程序退出状态为 0。父进程的堆栈标记检查应该通过。

**`test_longjmp()`:**

* **假设输入:** 命令行参数为 `"longjmp"`。
* **逻辑推理:**
    1. `check_longjmp_restores_tags` 函数调用 `setjmp` 保存当前堆栈状态。
    2. 如果 `setjmp` 返回 0，则调用 `settag_and_longjmp`。
    3. `settag_and_longjmp` 在堆栈上分配缓冲区并设置标记。
    4. `settag_and_longjmp` 调用 `longjmp`，恢复到之前 `setjmp` 保存的状态，并设置 `setjmp` 的返回值为 42。
    5. `check_longjmp_restores_tags` 再次执行，此时 `setjmp` 返回 42。
    6. 检查返回值是否为 42。
    7. 调用 `check_stack_tags` 检查堆栈标记是否与预期一致（应该是在 `settag_and_longjmp` 中设置的值）。
* **预期输出:** 测试成功，程序退出状态为 0。堆栈标记在 `longjmp` 后应该被正确恢复。

**6. 用户或编程常见的使用错误举例说明：**

* **在启用了堆栈标记的系统上运行未适配的代码:**  如果代码没有考虑到堆栈标记的存在，可能会意外地修改标记，导致程序崩溃或行为异常。例如，直接使用指针算术操作内存，而没有意识到标记的存在。
* **在 `vfork` 后父子进程同时操作共享的堆栈内存:** 虽然 `vfork` 速度很快，但父子进程共享内存的特性也容易导致问题。如果子进程在 `execve` 或 `_exit` 前修改了父进程堆栈上带有标记的内存，可能会导致父进程后续的堆栈标记检查失败。
* **错误地使用 `longjmp`:** 如果 `longjmp` 跳转到的 `setjmp` 调用栈帧已经失效（例如函数已经返回），会导致未定义行为，包括可能的堆栈标记不一致。
* **信号处理程序中的堆栈溢出:**  如果信号处理程序在默认堆栈上执行，并且其局部变量使用的空间超过剩余堆栈空间，可能导致堆栈溢出。使用 `sigaltstack` 可以缓解这个问题，但如果备用堆栈本身太小，仍然可能发生溢出。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

这个测试文件本身不是 Android Framework 或 NDK 直接调用的代码。它是一个用于测试 Bionic 库内部功能的单元测试。 然而，Android Framework 和 NDK 应用最终都会使用到 Bionic 提供的 libc 功能，而这些功能可能涉及到堆栈标记。

**Android Framework 到达这里的路径 (间接):**

1. **Android 应用 (Java/Kotlin):**  应用执行某些操作，例如进行网络请求、文件操作等。
2. **Framework API 调用:**  应用调用 Android Framework 提供的 API (例如 `java.net.Socket`, `java.io.File`)。
3. **Native 代码 (Framework):** Framework 的某些部分使用 Native 代码实现 (C/C++)。Framework API 的调用会最终传递到这些 Native 代码。
4. **Bionic libc 调用:** Framework 的 Native 代码会调用 Bionic 提供的 libc 函数，例如 `socket`, `open`, `read`, `write`, `malloc`, `free` 等。
5. **堆栈标记机制 (内部):** 当 Framework 的 Native 代码执行时，如果涉及到堆栈分配，并且系统启用了堆栈标记，Bionic 的内存分配器和相关函数会自动处理堆栈标记的设置和检查。

**NDK 应用到达这里的路径 (直接):**

1. **NDK 应用 (C/C++):** NDK 应用直接使用 C/C++ 编写。
2. **Bionic libc 调用:** NDK 应用可以直接调用 Bionic 提供的 libc 函数。
3. **堆栈标记机制 (内部):**  类似于 Framework，NDK 应用执行时，如果涉及到堆栈分配，Bionic 会处理堆栈标记。

**Frida Hook 示例调试步骤:**

假设我们想观察 `test_vfork` 中子进程的 `execve` 调用：

**Frida 脚本:**

```javascript
if (Process.arch === 'arm64') {
  const execvePtr = Module.findExportByName(null, 'execve');
  if (execvePtr) {
    Interceptor.attach(execvePtr, {
      onEnter: function (args) {
        console.log('[execve] Called');
        console.log('  pathname:', Memory.readUtf8String(args[0]));
        console.log('  argv:', ptrToStringArray(args[1]));
        console.log('  envp:', ptrToStringArray(args[2]));
      },
      onLeave: function (retval) {
        console.log('[execve] Returned:', retval);
      }
    });
  }

  function ptrToStringArray(ptr) {
    const result = [];
    if (ptr.isNull()) {
      return result;
    }
    let i = 0;
    while (true) {
      const strPtr = Memory.readPointer(ptr.add(i * Process.pointerSize));
      if (strPtr.isNull()) {
        break;
      }
      result.push(Memory.readUtf8String(strPtr));
      i++;
    }
    return result;
  }
} else {
  console.log('Skipping hook, not on arm64');
}
```

**调试步骤:**

1. **编译并运行测试程序:**  将 `stack_tagging_helper.cpp` 编译成可执行文件，并使用 `adb push` 推送到 Android 设备上。
2. **启动 Frida Server:** 在 Android 设备上启动 Frida Server。
3. **运行 Frida 脚本:**  在 PC 上使用 Frida 连接到设备上的测试进程，并加载上述 Frida 脚本：

   ```bash
   frida -U -f <package_name_of_test_executable> -l your_frida_script.js
   # 或者，如果进程已经运行：
   frida -U <process_name_or_pid> -l your_frida_script.js
   ```

4. **执行测试用例:**  通过 `adb shell` 运行测试程序，例如：

   ```bash
   adb shell /data/local/tmp/<test_executable_name> vfork_execve
   ```

5. **查看 Frida 输出:** Frida 脚本会在 `execve` 被调用时打印相关信息，包括执行的路径、参数和环境变量。

**其他 Frida Hook 示例:**

* **Hook `mte_set_tag`:** 可以 hook 这个函数来观察何时以及如何设置堆栈标记。
* **Hook `vfork`:** 观察 `vfork` 的调用时机和返回值。
* **Hook `longjmp`:** 观察 `longjmp` 的跳转目标和恢复的上下文。

通过 Frida，我们可以动态地观察和分析 Bionic 库内部的执行过程，这对于理解堆栈标记的实现和行为非常有帮助。

总而言之，`bionic/tests/libs/stack_tagging_helper.cpp` 是一个关键的测试文件，用于确保 Android Bionic 库中堆栈标记功能的正确性，这直接关系到 Android 平台的内存安全。理解这个文件的内容有助于深入了解 Android 的底层机制和安全特性。

Prompt: 
```
这是目录为bionic/tests/libs/stack_tagging_helper.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2022 The Android Open Source Project
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

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>

#include <bionic/malloc.h>

#include "CHECK.h"

#if defined(__aarch64__)

template <typename T>
static inline void mte_set_tag(T* p) {
  __asm__ __volatile__(
      ".arch_extension memtag\n"
      "stg %[Ptr], [%[Ptr]]\n"
      :
      : [Ptr] "r"(p)
      : "memory");
}

template <typename T>
static inline T* mte_get_tag(T* p) {
  __asm__ __volatile__(
      ".arch_extension memtag\n"
      "ldg %[Ptr], [%[Ptr]]\n"
      : [Ptr] "+r"(p)
      :
      : "memory");
  return p;
}

template <typename T>
static inline T* mte_increment_tag(T* p) {
  T* res;
  __asm__ __volatile__(
      ".arch_extension memtag\n"
      "addg %[Res], %[Ptr], #0, #1\n"
      : [Res] "=r"(res)
      : [Ptr] "r"(p)
      : "memory");
  return res;
}

constexpr size_t kStackAllocationSize = 128 * 1024;

// Prevent optimizations.
volatile void* sink;

enum struct ChildAction { Exit, Execve, Execl };

// Either execve or _exit, transferring control back to parent.
__attribute__((no_sanitize("memtag"), optnone, noinline)) void vfork_child2(ChildAction action,
                                                                            void* fp_parent) {
  // Make sure that the buffer in the caller has not been optimized out.
  void* fp = __builtin_frame_address(0);
  CHECK(reinterpret_cast<uintptr_t>(fp_parent) - reinterpret_cast<uintptr_t>(fp) >=
        kStackAllocationSize);
  if (action == ChildAction::Execve) {
    const char* argv[] = {"/system/bin/true", nullptr};
    const char* envp[] = {nullptr};
    execve("/system/bin/true", const_cast<char**>(argv), const_cast<char**>(envp));
    fprintf(stderr, "execve failed: %m\n");
    _exit(1);
  } else if (action == ChildAction::Execl) {
    execl("/system/bin/true", "/system/bin/true", "unusedA", "unusedB", nullptr);
    fprintf(stderr, "execl failed: %m\n");
    _exit(1);
  } else if (action == ChildAction::Exit) {
    _exit(0);
  }
  CHECK(0);
}

// Place a tagged buffer on the stack. Do not tag the top half so that the parent does not crash too
// early even if things go wrong.
__attribute__((no_sanitize("memtag"), optnone, noinline)) void vfork_child(ChildAction action) {
  alignas(16) char buf[kStackAllocationSize] __attribute__((uninitialized));
  sink = &buf;

  for (char* p = buf; p < buf + sizeof(buf) / 2; p += 16) {
    char* q = mte_increment_tag(p);
    mte_set_tag(q);
    CHECK(mte_get_tag(p) == q);
  }
  vfork_child2(action, __builtin_frame_address(0));
}

// Parent. Check that the stack has correct allocation tags.
__attribute__((no_sanitize("memtag"), optnone, noinline)) void vfork_parent(pid_t pid) {
  alignas(16) char buf[kStackAllocationSize] __attribute__((uninitialized));
  fprintf(stderr, "vfork_parent %p\n", &buf);
  bool success = true;
  for (char* p = buf; p < buf + sizeof(buf); p += 16) {
    char* q = mte_get_tag(p);
    if (p != q) {
      fprintf(stderr, "tag mismatch at offset %zx: %p != %p\n", p - buf, p, q);
      success = false;
      break;
    }
  }

  int wstatus;
  do {
    int res = waitpid(pid, &wstatus, 0);
    CHECK(res == pid);
  } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));

  CHECK(WIFEXITED(wstatus));
  CHECK(WEXITSTATUS(wstatus) == 0);

  if (!success) exit(1);
}

void test_vfork(ChildAction action) {
  pid_t pid = vfork();
  if (pid == 0) {
    vfork_child(action);
  } else {
    vfork_parent(pid);
  }
}

__attribute__((no_sanitize("memtag"), optnone, noinline)) static void settag_and_longjmp(
    jmp_buf cont) {
  alignas(16) char buf[kStackAllocationSize] __attribute__((uninitialized));
  sink = &buf;

  for (char* p = buf; p < buf + sizeof(buf) / 2; p += 16) {
    char* q = mte_increment_tag(p);
    mte_set_tag(q);
    if (mte_get_tag(p) != q) {
      fprintf(stderr, "failed to set allocation tags on stack: %p != %p\n", mte_get_tag(p), q);
      exit(1);
    }
  }
  longjmp(cont, 42);
}

// Check that the stack has correct allocation tags.
__attribute__((no_sanitize("memtag"), optnone, noinline)) static void check_stack_tags() {
  alignas(16) char buf[kStackAllocationSize] __attribute__((uninitialized));
  for (char* p = buf; p < buf + sizeof(buf); p += 16) {
    void* q = mte_get_tag(p);
    if (p != q) {
      fprintf(stderr, "stack tags mismatch: expected %p, got %p", p, q);
      exit(1);
    }
  }
}

void check_longjmp_restores_tags() {
  int value;
  jmp_buf jb;
  if ((value = setjmp(jb)) == 0) {
    settag_and_longjmp(jb);
    exit(2);  // Unreachable.
  } else {
    CHECK(value == 42);
    check_stack_tags();
  }
}

class SigAltStackScoped {
  stack_t old_ss;
  void* altstack_start;
  size_t altstack_size;

 public:
  SigAltStackScoped(size_t sz) : altstack_size(sz) {
    altstack_start = mmap(nullptr, altstack_size, PROT_READ | PROT_WRITE | PROT_MTE,
                          MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (altstack_start == MAP_FAILED) {
      fprintf(stderr, "sigaltstack mmap failed: %m\n");
      exit(1);
    }
    stack_t ss = {};
    ss.ss_sp = altstack_start;
    ss.ss_size = altstack_size;
    int res = sigaltstack(&ss, &old_ss);
    CHECK(res == 0);
  }

  ~SigAltStackScoped() {
    int res = sigaltstack(&old_ss, nullptr);
    CHECK(res == 0);
    munmap(altstack_start, altstack_size);
  }
};

class SigActionScoped {
  int signo;
  struct sigaction oldsa;

 public:
  using handler_t = void (*)(int, siginfo_t* siginfo, void*);

  SigActionScoped(int signo, handler_t handler) : signo(signo) {
    struct sigaction sa = {};
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    int res = sigaction(signo, &sa, &oldsa);
    CHECK(res == 0);
  }

  ~SigActionScoped() {
    int res = sigaction(signo, &oldsa, nullptr);
    CHECK(res == 0);
  }
};

void test_longjmp() {
  check_longjmp_restores_tags();

  std::thread t([]() { check_longjmp_restores_tags(); });
  t.join();
}

void test_longjmp_sigaltstack() {
  const size_t kAltStackSize = kStackAllocationSize + getpagesize() * 16;
  SigAltStackScoped sigAltStackScoped(kAltStackSize);
  SigActionScoped sigActionScoped(
      SIGUSR1, [](int, siginfo_t*, void*) { check_longjmp_restores_tags(); });
  raise(SIGUSR1);

  // same for a secondary thread
  std::thread t([&]() {
    SigAltStackScoped sigAltStackScoped(kAltStackSize);
    raise(SIGUSR1);
  });
  t.join();
}

void test_android_mallopt() {
  bool memtag_stack;
  CHECK(android_mallopt(M_MEMTAG_STACK_IS_ON, &memtag_stack, sizeof(memtag_stack)));
  CHECK(memtag_stack);
}

static uintptr_t GetTag(void* addr) {
  return reinterpret_cast<uintptr_t>(addr) & (0xFULL << 56);
}

static uintptr_t GetTag(volatile void* addr) {
  return GetTag(const_cast<void*>(addr));
}

static volatile char* throw_frame;
static volatile char* skip_frame3_frame;
volatile char *x;

__attribute__((noinline)) void throws() {
  // Prevent optimization.
  if (getpid() == 0) return;
  throw_frame = reinterpret_cast<char*>(__builtin_frame_address(0));
  throw "error";
}

__attribute__((noinline)) void maybe_throws() {
  // These are all unique sizes so in case of a failure, we can see which ones
  // are not untagged from the tag dump.
  volatile char y[5 * 16]= {};
  x = y;
  // Make sure y is tagged.
  CHECK(GetTag(&y) != GetTag(__builtin_frame_address(0)));
  throws();
}

__attribute__((noinline, no_sanitize("memtag"))) void skip_frame() {
  volatile char y[6*16] = {};
  x = y;
  // Make sure y is not tagged.
  CHECK(GetTag(&y) == GetTag(__builtin_frame_address(0)));
  maybe_throws();
}

__attribute__((noinline)) void skip_frame2() {
  volatile char y[7*16] = {};
  x = y;
  // Make sure y is tagged.
  CHECK(GetTag(&y) != GetTag(__builtin_frame_address(0)));
  skip_frame();
}

__attribute__((noinline, no_sanitize("memtag"))) void skip_frame3() {
  volatile char y[8*16] = {};
  x = y;
  skip_frame3_frame = reinterpret_cast<char*>(__builtin_frame_address(0));
  // Make sure y is not tagged.
  CHECK(GetTag(&y) == GetTag(__builtin_frame_address(0)));
  skip_frame2();
}

void test_exception_cleanup() {
  // This is here for debugging purposes, if something goes wrong we can
  // verify that this placeholder did not get untagged.
  volatile char placeholder[16*16] = {};
  x = placeholder;
  try {
    skip_frame3();
  } catch (const char* e) {
  }
  if (throw_frame >= skip_frame3_frame) {
    fprintf(stderr, "invalid throw frame");
    exit(1);
  }
  for (char* b = const_cast<char*>(throw_frame); b < skip_frame3_frame; ++b) {
    if (mte_get_tag(b) != b) {
      fprintf(stderr, "invalid tag at %p", b);
      exit(1);
    }
  }
}

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("nothing to do\n");
    return 1;
  }

  if (strcmp(argv[1], "vfork_execve") == 0) {
    test_vfork(ChildAction::Execve);
    return 0;
  }

  if (strcmp(argv[1], "vfork_execl") == 0) {
    test_vfork(ChildAction::Execl);
    return 0;
  }

  if (strcmp(argv[1], "vfork_exit") == 0) {
    test_vfork(ChildAction::Exit);
    return 0;
  }

  if (strcmp(argv[1], "longjmp") == 0) {
    test_longjmp();
    return 0;
  }

  if (strcmp(argv[1], "longjmp_sigaltstack") == 0) {
    test_longjmp_sigaltstack();
    return 0;
  }

  if (strcmp(argv[1], "android_mallopt") == 0) {
    test_android_mallopt();
    return 0;
  }

  if (strcmp(argv[1], "exception_cleanup") == 0) {
    test_exception_cleanup();
    return 0;
  }

  printf("unrecognized command: %s\n", argv[1]);
  return 1;
}
#else
int main(int, char**) {
  printf("aarch64 only\n");
  return 1;
}
#endif  // defined(__aarch64__)

"""

```