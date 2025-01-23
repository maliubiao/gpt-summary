Response:
Let's break down the thought process for analyzing the `signal_test.cpp` file.

**1. Understanding the Goal:**

The primary request is to analyze the provided C++ code, which is a test suite for signal-related functions in Android's Bionic library. The analysis should cover functionality, relation to Android, implementation details (specifically libc functions), dynamic linking aspects, potential errors, and debugging approaches.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly read through the code, paying attention to key elements:

* **Includes:**  `<signal.h>`, `<unistd.h>`, `<sys/syscall.h>`, `<chrono>`, `<thread>`, `<gtest/gtest.h>`. This immediately tells us it's a test file using Google Test and interacts with signals, system calls, and threading.
* **`TEST(signal, ...)`:**  This confirms it's a Google Test suite specifically for signal functionality.
* **Function Names:**  `sigaddset`, `sigdelset`, `sigemptyset`, `sigfillset`, `sigismember`, `raise`, `sigsuspend`, `sigaction`, `sigprocmask`, `pthread_sigmask`, `sigqueue`, `sigwait`, `sigtimedwait`, `sigignore`, `sighold`, `sigpause`, `sigrelse`, `sigset`, `killpg`, `sig2str`, `str2sig`. These are the main functions being tested. Recognizing these as standard POSIX signal functions is crucial.
* **Macros and Constants:** `SIGALRM`, `SIGSEGV`, `SIGRTMIN`, `SIGRTMAX`, `SA_ONSTACK`, `SA_SIGINFO`, `SIG_BLOCK`, `SIG_SETMASK`, `SIG_UNBLOCK`, `SIG_HOLD`, `SIG_IGN`, `SIG_DFL`. These define the signals and options used in the tests.
* **Helper Functions/Classes:**  `TestSigSet1`, `TestSigSet2`, `ScopedSignalHandler`, `SignalMaskRestorer`, `ClearSignalMask`, `FillSignalMask`, `GetSignalMask`, `TestSignalMaskFiltered`, `TestSignalMaskFunction`, `SigqueueSignalHandler`. These simplify testing common patterns.
* **Conditional Compilation:** `#if defined(__BIONIC__)`, `#if defined(ANDROID_HOST_MUSL)`, etc. This highlights platform-specific considerations.
* **System Calls:** `syscall(__NR_rt_sigprocmask, ...)` and `syscall(SYS_rt_tgsigqueueinfo, ...)`. This indicates direct interaction with the kernel.

**3. Categorizing Functionality:**

Based on the function names, I can categorize the testing areas:

* **Signal Set Manipulation:** `sigaddset`, `sigdelset`, `sigemptyset`, `sigfillset`, `sigismember` (and their `64` counterparts for real-time signals).
* **Signal Generation:** `raise`, `sigqueue`, `pthread_sigqueue`.
* **Signal Blocking/Masking:** `sigprocmask`, `pthread_sigmask`, `sigsuspend`, `sigwait`, `sigtimedwait`, `sighold`, `sigrelse`, `sigset`, `sigignore`.
* **Signal Handling:** `sigaction`.
* **Utility Functions:** `killpg`, `sig2str`, `str2sig`.

**4. Connecting to Android and Providing Examples:**

Now, I think about how these functions relate to Android:

* **Fundamental System Operations:** Signals are a core part of how any Unix-like system, including Android, handles asynchronous events and inter-process communication.
* **Application Crashes:**  `SIGSEGV`, `SIGABRT` are common signals that lead to app crashes. The tests implicitly cover how Bionic handles these.
* **Inter-Process Communication (IPC):** While not explicitly demonstrated in *this* test file, signals can be used for basic IPC.
* **Threading:** `pthread_sigmask` and `pthread_sigqueue` directly relate to how signals are handled within multithreaded Android apps.
* **Real-Time Capabilities:** The tests for `SIGRTMIN` and `SIGRTMAX` and the `64` variants highlight Android's support for real-time signals.

**5. Explaining libc Function Implementations:**

This is where the knowledge of standard C library functions comes in. For each function, I'd consider:

* **Core Purpose:** What does the function fundamentally do?
* **Underlying System Call:**  Most of these libc functions are wrappers around system calls (e.g., `sigaction` -> `sys_sigaction`, `sigprocmask` -> `sys_rt_sigprocmask`). Knowing this is key.
* **Data Structures:**  `sigset_t` and `siginfo_t` are important data structures. How are they used?
* **Error Handling:** What are the common error conditions and how are they indicated (e.g., returning -1 and setting `errno`)?

**6. Dynamic Linker Aspects:**

This requires recognizing which functions might involve the dynamic linker:

* **Signal Handlers:** When a signal handler is invoked, the dynamic linker plays a role in ensuring the correct context and stack are used, especially for dynamically loaded libraries.
* **Shared Libraries:** If a signal handler is defined in a shared library, the dynamic linker needs to resolve its address.

To explain the linking process, I would:

* **Describe the SO Layout:** Explain the typical structure of a shared object (`.so`) file (code, data, GOT, PLT).
* **Illustrate Linking:** Show how the Global Offset Table (GOT) and Procedure Linkage Table (PLT) are used for lazy symbol resolution when a signal handler in a shared library is first called.

**7. Logic Inference, Assumptions, Inputs, and Outputs:**

For the template functions like `TestSigSet1` and `TestSigSet2`, I can make assumptions about the input (e.g., null pointers, invalid signal numbers) and predict the expected output (return value of -1, `errno` set to `EINVAL`).

**8. Common Usage Errors:**

Based on the test cases, I can identify potential programmer errors:

* **Incorrect Signal Numbers:**  Passing invalid signal numbers to functions like `sigaddset`.
* **Signal Masking Issues:**  Forgetting to unblock signals, leading to unexpected behavior.
* **Race Conditions:**  Signal handling can be prone to race conditions if not handled carefully, although this specific test file doesn't focus on concurrency issues in handlers themselves.

**9. Android Framework/NDK Path and Frida Hooking:**

This requires knowledge of the Android architecture:

* **Framework:**  Explain how the Android framework uses signals for various purposes (e.g., process management, handling ANRs - Application Not Responding). Give examples of framework components that might interact with signal handling.
* **NDK:**  Describe how NDK developers can directly use signal functions in their native code.
* **Frida:** Explain how Frida can be used to intercept and monitor signal-related function calls at different levels (libc, kernel). Provide a basic Frida script example.

**10. Structuring the Response:**

Finally, organize the information logically, using clear headings and subheadings. Use code examples where appropriate. Ensure the language is precise and accurate. The decomposed request provides a good structure to follow.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus only on the explicit tests.
* **Correction:** Realize the need to explain the underlying concepts and Android context.
* **Initial thought:** Explain every single line of code.
* **Correction:** Focus on the *functionality* being tested and the purpose of the test cases.
* **Initial thought:**  Overly technical explanation of dynamic linking.
* **Correction:**  Provide a simplified but accurate overview focusing on the key concepts relevant to signal handlers.
* **Initial thought:**  Generic Frida example.
* **Correction:**  Tailor the Frida example to specifically hook signal-related functions.

By following these steps, breaking down the problem into smaller, manageable parts, and continuously refining the understanding, I can generate a comprehensive and accurate analysis of the `signal_test.cpp` file.
好的，让我们详细分析一下 `bionic/tests/signal_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/signal_test.cpp` 是 Android Bionic 库中关于信号处理功能的单元测试文件。它的主要目的是测试 Bionic 提供的与信号相关的 API 的正确性和健壮性。  它使用了 Google Test 框架来组织和执行测试用例。

**与 Android 功能的关系及举例**

信号在 Android 系统中扮演着至关重要的角色，用于进程间通信、错误处理、进程生命周期管理等。`signal_test.cpp` 中测试的函数直接关系到 Android 的稳定性和可靠性。

* **应用程序崩溃处理:** 当 Android 应用发生诸如空指针解引用（导致 `SIGSEGV` 信号）或调用 `abort()` 函数时，系统会发送信号给该进程。Bionic 的信号处理机制负责捕获这些信号并进行相应的处理，例如生成 tombstone 文件以供调试。`signal_test.cpp` 中的一些测试用例（虽然没有直接测试崩溃处理，但测试了 `raise` 函数，这是触发信号的一种方式）间接关联到这个功能。
* **进程生命周期管理:** Android 系统使用信号来管理应用程序的生命周期。例如，当系统需要终止一个后台进程以释放资源时，可能会发送 `SIGKILL` 信号。`signal_test.cpp` 中对 `sigignore` 的测试验证了忽略特定信号的能力，这在某些场景下对于进程管理很重要。
* **实时性需求:** Android 系统也支持实时信号 (`SIGRTMIN` 到 `SIGRTMAX`)，用于对时间敏感的应用。`signal_test.cpp` 中有专门针对实时信号的测试用例，例如 `sigaction64_SIGRTMIN` 和 `sigwait64_SIGRTMIN`，这体现了 Bionic 对 Android 实时特性的支持。
* **线程同步:** 信号可以用于线程间的同步和通信。例如，一个线程可以发送信号通知另一个线程某个事件发生。`signal_test.cpp` 中测试了 `pthread_sigmask` 和 `pthread_sigqueue` 等函数，这些都与多线程环境下的信号处理相关。

**libc 函数功能实现详解**

`signal_test.cpp` 中测试了很多 libc 提供的信号处理函数，下面逐一解释其功能和可能的实现方式：

* **`sigemptyset(sigset_t *set)` 和 `sigemptyset64(sigset64_t *set)`:**
    * **功能:** 初始化信号集 `set`，清除所有信号。
    * **实现:**  `sigset_t` 通常是一个位掩码（bitmask），其中每个位代表一个信号。`sigemptyset` 的实现通常是将 `set` 的所有位都设置为 0。`sigset64_t` 用于表示更多的实时信号，可能使用更大的数据类型（例如 64 位整数）作为位掩码。

* **`sigfillset(sigset_t *set)` 和 `sigfillset64(sigset64_t *set)`:**
    * **功能:** 初始化信号集 `set`，包含所有信号。
    * **实现:** 将 `set` 的所有位都设置为 1。

* **`sigaddset(sigset_t *set, int signum)` 和 `sigaddset64(sigset64_t *set, int signum)`:**
    * **功能:** 将信号 `signum` 添加到信号集 `set` 中。
    * **实现:** 将 `set` 中对应 `signum` 的位设置为 1。

* **`sigdelset(sigset_t *set, int signum)` 和 `sigdelset64(sigset64_t *set, int signum)`:**
    * **功能:** 从信号集 `set` 中移除信号 `signum`。
    * **实现:** 将 `set` 中对应 `signum` 的位设置为 0。

* **`sigismember(const sigset_t *set, int signum)` 和 `sigismember64(const sigset64_t *set, int signum)`:**
    * **功能:** 检查信号 `signum` 是否在信号集 `set` 中。
    * **实现:** 检查 `set` 中对应 `signum` 的位是否为 1。如果为 1，则返回非零值；否则返回 0。

* **`raise(int sig)`:**
    * **功能:** 向当前进程发送信号 `sig`。
    * **实现:**  通常会调用底层的系统调用，例如 Linux 上的 `tgkill` 或 `kill`，将信号发送给当前进程（或线程）。

* **`sigsuspend(const sigset_t *mask)` 和 `sigsuspend64(const sigset64_t *mask)`:**
    * **功能:** 临时替换进程的信号掩码为 `mask`，然后挂起进程，直到接收到一个信号。接收到信号后，恢复原来的信号掩码。
    * **实现:**  这是一个原子操作。它首先将进程的信号掩码设置为 `mask`，然后使进程进入休眠状态。当接收到信号并且该信号没有被阻塞时，信号处理函数会被调用。信号处理函数返回后，`sigsuspend` 返回 `-1` 并设置 `errno` 为 `EINTR`，同时恢复原来的信号掩码。

* **`sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)` 和 `sigaction64(int signum, const struct sigaction64 *act, struct sigaction64 *oldact)`:**
    * **功能:** 设置对特定信号 `signum` 的处理方式。
    * **实现:**  这是一个与内核交互的系统调用。它将用户提供的 `sigaction` 结构体（包含信号处理函数地址、标志位等信息）传递给内核，内核会更新对应信号的处理方式。如果 `oldact` 非空，则会将之前的信号处理方式存储在 `oldact` 中。

* **`sigprocmask(int how, const sigset_t *set, sigset_t *oldset)` 和 `sigprocmask64(int how, const sigset64_t *set, sigset64_t *oldset)`:**
    * **功能:**  检查或修改进程的信号掩码，决定哪些信号被阻塞。
    * **实现:**  这是一个系统调用。`how` 参数指定如何修改信号掩码 (`SIG_BLOCK` 添加阻塞信号, `SIG_UNBLOCK` 移除阻塞信号, `SIG_SETMASK` 设置新的掩码)。如果 `oldset` 非空，则会将之前的信号掩码存储在 `oldset` 中。

* **`pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset)` 和 `pthread_sigmask64(int how, const sigset64_t *set, sigset64_t *oldset)`:**
    * **功能:**  类似于 `sigprocmask`，但作用于单个线程而不是整个进程。
    * **实现:**  也是一个系统调用，但作用域是线程级别的。每个线程都有自己的信号掩码。

* **`sigqueue(pid_t pid, int sig, const union sigval value)`:**
    * **功能:** 向指定进程 `pid` 发送信号 `sig`，并附带额外的数据 `value`。
    * **实现:**  这是一个系统调用，允许发送带有额外信息的信号，接收进程可以通过 `siginfo_t` 结构体获取这些信息。这通常用于更精细的进程间通信。

* **`sigwait(const sigset_t *set, int *sig)` 和 `sigwait64(const sigset64_t *set, int *sig)`:**
    * **功能:**  原子地取消阻塞 `set` 中的信号，并挂起调用线程，直到 `set` 中的一个信号被传递。
    * **实现:**  这是一个阻塞调用。当 `set` 中的一个信号被接收到时，该信号的编号会被写入 `*sig`，并且函数返回。在等待期间，其他信号的处理方式不变。

* **`sigwaitinfo(const sigset_t *set, siginfo_t *info)` 和 `sigwaitinfo64(const sigset64_t *set, siginfo_t *info)`:**
    * **功能:** 类似于 `sigwait`，但可以获取关于接收到的信号的更详细信息，存储在 `info` 结构体中。
    * **实现:**  与 `sigwait` 类似，但会填充 `siginfo_t` 结构体，包含发送信号的进程 ID、用户 ID、信号值等信息。

* **`sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout)` 和 `sigtimedwait64(const sigset64_t *set, siginfo_t *info, const struct timespec *timeout)`:**
    * **功能:**  类似于 `sigwaitinfo`，但可以设置超时时间。如果在超时时间内没有接收到信号，则返回错误。
    * **实现:**  与 `sigwaitinfo` 类似，但内部使用了带超时机制的等待系统调用。

* **`sigignore(int sig)`:**
    * **功能:**  忽略指定的信号 `sig`。
    * **实现:**  通常通过调用 `sigaction`，并将信号处理函数设置为 `SIG_IGN` 来实现。

* **`sighold(int sig)`:**
    * **功能:**  将指定的信号 `sig` 添加到进程的信号掩码中，阻塞该信号。
    * **实现:**  通常通过调用 `sigprocmask` 或 `pthread_sigmask`，使用 `SIG_BLOCK` 操作将信号添加到阻塞集合中。

* **`sigpause(int sig)`:**
    * **功能:**  原子地取消阻塞指定的信号 `sig`，并挂起调用进程，直到接收到除 `sig` 以外的任何信号。**注意：这是一个过时的函数，不推荐使用。推荐使用 `sigsuspend`。**
    * **实现:**  早期的信号处理方式，与 `sigsuspend` 类似，但功能受限。

* **`sigrelse(int sig)`:**
    * **功能:**  从进程的信号掩码中移除指定的信号 `sig`，取消阻塞该信号。
    * **实现:**  通常通过调用 `sigprocmask` 或 `pthread_sigmask`，使用 `SIG_UNBLOCK` 操作将信号从阻塞集合中移除。

* **`sigset(int sig, sighandler_t disp)`:**
    * **功能:**  修改对信号 `sig` 的处理方式。**注意：这是一个过时的函数，不推荐使用。推荐使用 `sigaction`。**
    * **实现:**  早期的信号处理方式，功能类似于 `sigaction`，但参数和功能更简单。

* **`killpg(int pgrp, int sig)`:**
    * **功能:**  向指定的进程组 `pgrp` 中的所有进程发送信号 `sig`。
    * **实现:**  通常会调用底层的系统调用 `kill`，但目标是一整个进程组。

* **`sig2str(int sig, char *str)`:**
    * **功能:**  将信号编号 `sig` 转换为对应的信号名称字符串。
    * **实现:**  Bionic 维护了一个信号编号到名称的映射表（例如 `sys_signame`），该函数会在表中查找并返回对应的字符串。对于实时信号，可能会格式化为 "RTMIN+n" 或 "RTMAX-n" 的形式。

* **`str2sig(const char *str, int *sig)`:**
    * **功能:**  将信号名称字符串转换为对应的信号编号。
    * **实现:**  Bionic 会查找信号名称表（或解析 "RTMIN/MAX +/- n" 格式的字符串）来确定信号编号。

**涉及 dynamic linker 的功能、so 布局样本及链接处理过程**

在 `signal_test.cpp` 中，主要与 dynamic linker 交互的场景是当设置自定义信号处理函数时（通过 `sigaction` 或 `sigset`）。

**SO 布局样本:**

假设我们有一个共享库 `libsignal_handler.so`，其中定义了一个信号处理函数 `my_signal_handler`：

```c++
// libsignal_handler.cpp
#include <signal.h>
#include <stdio.h>

extern "C" void my_signal_handler(int sig) {
  printf("Signal %d received in shared library.\n", sig);
}
```

编译生成 `libsignal_handler.so`：
```bash
g++ -shared -fPIC libsignal_handler.cpp -o libsignal_handler.so
```

该 `.so` 文件的布局大致如下：

```
libsignal_handler.so:
    .text          # 包含 my_signal_handler 函数的代码
    .data          # 全局/静态数据
    .rodata        # 只读数据
    .bss           # 未初始化的全局/静态数据
    .dynsym        # 动态符号表，包含 my_signal_handler
    .dynstr        # 动态字符串表
    .rel.plt       # PLT 重定位表
    .rel.dyn       # 数据段重定位表
    ...
```

**链接的处理过程:**

1. **加载共享库:** 当主程序（测试程序或 Android 应用）使用 `dlopen` 或系统自动加载 `libsignal_handler.so` 时，dynamic linker 会将该共享库加载到进程的地址空间。
2. **符号解析:** 当主程序通过 `sigaction` 设置 `my_signal_handler` 作为信号处理函数时，需要传递该函数的地址。如果 `my_signal_handler` 在共享库中，那么这个地址需要在运行时由 dynamic linker 解析。
3. **GOT 和 PLT:**  为了实现动态链接，共享库的代码通常通过 Procedure Linkage Table (PLT) 调用外部函数，而外部函数的实际地址存储在 Global Offset Table (GOT) 中。
4. **首次调用信号处理函数:** 当信号发生并且 `my_signal_handler` 被调用时，如果这是首次调用，PLT 中的代码会跳转到 dynamic linker，dynamic linker 会查找 `my_signal_handler` 的实际地址并更新 GOT 中的条目。之后，对 `my_signal_handler` 的调用将直接通过 GOT 跳转到实际地址。

**假设输入与输出 (针对特定测试用例)**

以 `TEST(signal, sigaddset_invalid)` 为例：

* **假设输入:**
    * `fn` 指向 `sigaddset` 函数。
    * 第一次调用 `fn(nullptr, SIGSEGV)`。
    * 第二次调用 `fn(&set, 0)`，其中 `set` 是一个已声明的 `sigset_t` 变量。
    * 第三次调用 `fn(&set, SIGNAL_MAX(&set) + 1)`。
    * 第四次和第五次调用 `fn(&set, SIGNAL_MIN())` 和 `fn(&set, SIGNAL_MAX(&set))`。
* **预期输出:**
    * 第一次调用返回 `-1`，`errno` 设置为 `EINVAL`（无效参数）。
    * 第二次调用返回 `-1`，`errno` 设置为 `EINVAL`（无效信号编号）。
    * 第三次调用返回 `-1`，`errno` 设置为 `EINVAL`（无效信号编号）。
    * 第四次和第五次调用返回 `0`，`errno` 设置为 `0`（成功）。

**用户或编程常见的使用错误举例说明**

* **忘记初始化信号集:**  在使用 `sigaddset` 或 `sigdelset` 之前，必须先使用 `sigemptyset` 或 `sigfillset` 初始化信号集。否则，信号集的内容是未定义的，可能导致不可预测的行为。
    ```c++
    sigset_t my_set; // 忘记初始化
    sigaddset(&my_set, SIGINT); // 错误：my_set 的初始状态未知
    ```

* **信号处理函数中执行不安全的操作:** 信号处理函数应该尽可能简单和可重入。避免在信号处理函数中调用可能导致死锁或不可重入的函数（例如 `malloc`, `printf` 等）。
    ```c++
    void handler(int sig) {
      printf("Signal received: %d\n", sig); // printf 可能不是线程安全的
    }
    ```

* **信号掩码管理不当:**  错误地阻塞或取消阻塞信号可能导致程序无法响应某些事件或产生竞争条件。例如，在一个线程中阻塞了某个信号，但期望在另一个线程中能够处理它。

* **使用过时的信号处理函数:**  应该优先使用 `sigaction` 而不是 `signal` 或 `sigset`，因为 `sigaction` 提供了更多的控制选项，并且在多线程环境下更加安全。

**Android Framework 或 NDK 如何到达这里及 Frida Hook 示例**

1. **Android Framework:**
   * **系统服务:** Android Framework 的某些系统服务（例如 `ActivityManagerService`, `WindowManagerService`）在进程管理、窗口管理等方面会涉及到信号处理。例如，当一个应用无响应时，`ActivityManagerService` 可能会发送 `SIGQUIT` 或 `SIGKILL` 信号。
   * **Zygote:**  Zygote 进程在 fork 新的应用进程时，也会设置一些默认的信号处理函数。

2. **NDK:**
   * NDK 开发者可以直接使用 `<signal.h>` 中的信号处理函数。例如，一个 native 库可以注册一个信号处理函数来捕获 `SIGSEGV` 并进行自定义的错误处理或日志记录。

**Frida Hook 示例:**

假设我们要 hook `sigaction` 函数，查看哪些信号被处理以及处理函数是什么：

```javascript
if (Process.platform === 'android') {
  const sigactionPtr = Module.findExportByName(null, 'sigaction');
  if (sigactionPtr) {
    Interceptor.attach(sigactionPtr, {
      onEnter: function (args) {
        const signum = args[0].toInt32();
        const act = ptr(args[1]);
        const oldact = ptr(args[2]);

        let handler = null;
        const sa_handler = act.readPointer();
        if (!sa_handler.isNull()) {
          handler = sa_handler;
        } else {
          const sa_sigaction = act.add(Process.pointerSize).readPointer();
          if (!sa_sigaction.isNull()) {
            handler = sa_sigaction;
          }
        }

        console.log(`[sigaction] Signal: ${signum}, Handler: ${handler}, act: ${act}, oldact: ${oldact}`);
      },
      onLeave: function (retval) {
        console.log(`[sigaction] Returned: ${retval}`);
      }
    });
  } else {
    console.log("Could not find sigaction");
  }
}
```

这个 Frida 脚本会拦截 `sigaction` 函数的调用，并打印出信号编号、处理函数地址以及 `sigaction` 结构体的指针。通过这种方式，我们可以观察 Android Framework 或 NDK 库是如何设置信号处理的。

希望以上详细的分析能够帮助你理解 `bionic/tests/signal_test.cpp` 文件的功能和相关知识。

### 提示词
```
这是目录为bionic/tests/signal_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2012 The Android Open Source Project
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
#include <signal.h>
#include <sys/cdefs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include <android-base/macros.h>
#include <android-base/threads.h>

#include <gtest/gtest.h>

#include "SignalUtils.h"
#include "utils.h"

using namespace std::chrono_literals;

#if defined(ANDROID_HOST_MUSL)
// Musl doesn't export __SIGRTMIN and __SIGRTMAX, #define
// them here.
#define __SIGRTMIN 32
#define __SIGRTMAX 64
#endif

static int SIGNAL_MIN() {
  return 1; // Signals start at 1 (SIGHUP), not 0.
}

template <typename SigSetT>
static int SIGNAL_MAX(SigSetT* set) {
  return sizeof(*set) * 8;
}

template <typename SigSetT>
static void TestSigSet1(int (fn)(SigSetT*)) {
  // nullptr sigset_t*/sigset64_t*.
  SigSetT* set_ptr = nullptr;
  errno = 0;
  ASSERT_EQ(-1, fn(set_ptr));
  ASSERT_ERRNO(EINVAL);

  // Non-nullptr.
  SigSetT set = {};
  errno = 0;
  ASSERT_EQ(0, fn(&set));
  ASSERT_ERRNO(0);
}

template <typename SigSetT>
static void TestSigSet2(int (fn)(SigSetT*, int)) {
  // nullptr sigset_t*/sigset64_t*.
  SigSetT* set_ptr = nullptr;
  errno = 0;
  ASSERT_EQ(-1, fn(set_ptr, SIGSEGV));
  ASSERT_ERRNO(EINVAL);

  SigSetT set = {};

  // Bad signal number: too small.
  errno = 0;
  ASSERT_EQ(-1, fn(&set, 0));
  ASSERT_ERRNO(EINVAL);

  // Bad signal number: too high.
  errno = 0;
  ASSERT_EQ(-1, fn(&set, SIGNAL_MAX(&set) + 1));
  ASSERT_ERRNO(EINVAL);

  // Good signal numbers, low and high ends of range.
  errno = 0;
  ASSERT_EQ(0, fn(&set, SIGNAL_MIN()));
  ASSERT_ERRNO(0);
  ASSERT_EQ(0, fn(&set, SIGNAL_MAX(&set)));
  ASSERT_ERRNO(0);
}

TEST(signal, sigaddset_invalid) {
  TestSigSet2(sigaddset);
}

TEST(signal, sigaddset64_invalid) {
#if defined(__BIONIC__)
  TestSigSet2(sigaddset64);
#endif
}

TEST(signal, sigdelset_invalid) {
  TestSigSet2(sigdelset);
}

TEST(signal, sigdelset64_invalid) {
#if defined(__BIONIC__)
  TestSigSet2(sigdelset64);
#endif
}

TEST(signal, sigemptyset_invalid) {
  TestSigSet1(sigemptyset);
}

TEST(signal, sigemptyset64_invalid) {
#if defined(__BIONIC__)
  TestSigSet1(sigemptyset64);
#endif
}

TEST(signal, sigfillset_invalid) {
  TestSigSet1(sigfillset);
}

TEST(signal, sigfillset64_invalid) {
#if defined(__BIONIC__)
  TestSigSet1(sigfillset64);
#endif
}

TEST(signal, sigismember_invalid) {
  TestSigSet2(sigismember);
}

TEST(signal, sigismember64_invalid) {
#if defined(__BIONIC__)
  TestSigSet2(sigismember64);
#endif
}

TEST(signal, raise_invalid) {
  errno = 0;
  ASSERT_EQ(-1, raise(-1));
  ASSERT_ERRNO(EINVAL);
}

static void raise_in_signal_handler_helper(int signal_number) {
  ASSERT_EQ(SIGALRM, signal_number);
  static int count = 0;
  if (++count == 1) {
    raise(SIGALRM);
  }
}

TEST(signal, raise_in_signal_handler) {
  ScopedSignalHandler ssh(SIGALRM, raise_in_signal_handler_helper);
  raise(SIGALRM);
}

static int g_sigsuspend_signal_handler_call_count = 0;

TEST(signal, sigsuspend_sigpending) {
  SignalMaskRestorer smr;

  // Block SIGALRM.
  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &just_SIGALRM, nullptr));

  ScopedSignalHandler ssh(SIGALRM, [](int) { ++g_sigsuspend_signal_handler_call_count; });

  // There should be no pending signals.
  sigset_t pending;
  sigemptyset(&pending);
  ASSERT_EQ(0, sigpending(&pending));
  for (int i = SIGNAL_MIN(); i <= SIGNAL_MAX(&pending); ++i) {
    EXPECT_FALSE(sigismember(&pending, i)) << i;
  }

  // Raise SIGALRM and check our signal handler wasn't called.
  raise(SIGALRM);
  ASSERT_EQ(0, g_sigsuspend_signal_handler_call_count);

  // We should now have a pending SIGALRM but nothing else.
  sigemptyset(&pending);
  ASSERT_EQ(0, sigpending(&pending));
  for (int i = SIGNAL_MIN(); i <= SIGNAL_MAX(&pending); ++i) {
    EXPECT_EQ((i == SIGALRM), sigismember(&pending, i));
  }

  // Use sigsuspend to block everything except SIGALRM...
  sigset_t not_SIGALRM;
  sigfillset(&not_SIGALRM);
  sigdelset(&not_SIGALRM, SIGALRM);
  ASSERT_EQ(-1, sigsuspend(&not_SIGALRM));
  ASSERT_ERRNO(EINTR);
  // ...and check that we now receive our pending SIGALRM.
  ASSERT_EQ(1, g_sigsuspend_signal_handler_call_count);
}

static int g_sigsuspend64_signal_handler_call_count = 0;

TEST(signal, sigsuspend64_sigpending64) {
  SignalMaskRestorer smr;

  // Block SIGRTMIN.
  sigset64_t just_SIGRTMIN;
  sigemptyset64(&just_SIGRTMIN);
  sigaddset64(&just_SIGRTMIN, SIGRTMIN);
  ASSERT_EQ(0, sigprocmask64(SIG_BLOCK, &just_SIGRTMIN, nullptr));

  ScopedSignalHandler ssh(SIGRTMIN, [](int) { ++g_sigsuspend64_signal_handler_call_count; });

  // There should be no pending signals.
  sigset64_t pending;
  sigemptyset64(&pending);
  ASSERT_EQ(0, sigpending64(&pending));
  for (int i = SIGNAL_MIN(); i <= SIGNAL_MAX(&pending); ++i) {
    EXPECT_FALSE(sigismember64(&pending, i)) << i;
  }

  // Raise SIGRTMIN and check our signal handler wasn't called.
  raise(SIGRTMIN);
  ASSERT_EQ(0, g_sigsuspend64_signal_handler_call_count);

  // We should now have a pending SIGRTMIN but nothing else.
  sigemptyset64(&pending);
  ASSERT_EQ(0, sigpending64(&pending));
  for (int i = SIGNAL_MIN(); i <= SIGNAL_MAX(&pending); ++i) {
    EXPECT_EQ((i == SIGRTMIN), sigismember64(&pending, i));
  }

  // Use sigsuspend64 to block everything except SIGRTMIN...
  sigset64_t not_SIGRTMIN;
  sigfillset64(&not_SIGRTMIN);
  sigdelset64(&not_SIGRTMIN, SIGRTMIN);
  ASSERT_EQ(-1, sigsuspend64(&not_SIGRTMIN));
  ASSERT_ERRNO(EINTR);
  // ...and check that we now receive our pending SIGRTMIN.
  ASSERT_EQ(1, g_sigsuspend64_signal_handler_call_count);
}

template <typename SigActionT, typename SigSetT>
static void TestSigAction(int (sigaction_fn)(int, const SigActionT*, SigActionT*),
                          int (sigaddset_fn)(SigSetT*, int),
                          int sig) {
  // Both bionic and glibc set SA_RESTORER when talking to the kernel on arm,
  // arm64, x86, and x86-64. The version of glibc we're using also doesn't
  // define SA_RESTORER, but luckily it's the same value everywhere.
  static const unsigned sa_restorer = 0x4000000;

  // See what's currently set for this signal.
  SigActionT original_sa = {};
  ASSERT_EQ(0, sigaction_fn(sig, nullptr, &original_sa));
  ASSERT_TRUE(original_sa.sa_handler == nullptr);
  ASSERT_TRUE(original_sa.sa_sigaction == nullptr);
  ASSERT_EQ(0U, original_sa.sa_flags & ~sa_restorer);
#ifdef SA_RESTORER
  ASSERT_EQ(bool(original_sa.sa_flags & sa_restorer), bool(original_sa.sa_restorer));
#endif

  // Set a traditional sa_handler signal handler.
  auto no_op_signal_handler = [](int) {};
  SigActionT sa = {};
  sigaddset_fn(&sa.sa_mask, sig);
  sa.sa_flags = SA_ONSTACK;
  sa.sa_handler = no_op_signal_handler;
  ASSERT_EQ(0, sigaction_fn(sig, &sa, nullptr));

  // Check that we can read it back.
  sa = {};
  ASSERT_EQ(0, sigaction_fn(sig, nullptr, &sa));
  ASSERT_TRUE(sa.sa_handler == no_op_signal_handler);
  ASSERT_TRUE((void*) sa.sa_sigaction == (void*) sa.sa_handler);
  ASSERT_EQ(static_cast<unsigned>(SA_ONSTACK), sa.sa_flags & ~sa_restorer);
#ifdef SA_RESTORER
  ASSERT_EQ(bool(sa.sa_flags & sa_restorer), bool(sa.sa_restorer));
#endif

  // Set a new-style sa_sigaction signal handler.
  auto no_op_sigaction = [](int, siginfo_t*, void*) {};
  sa = {};
  sigaddset_fn(&sa.sa_mask, sig);
  sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
  sa.sa_sigaction = no_op_sigaction;
  ASSERT_EQ(0, sigaction_fn(sig, &sa, nullptr));

  // Check that we can read it back.
  sa = {};
  ASSERT_EQ(0, sigaction_fn(sig, nullptr, &sa));
  ASSERT_TRUE(sa.sa_sigaction == no_op_sigaction);
  ASSERT_TRUE((void*) sa.sa_sigaction == (void*) sa.sa_handler);
  ASSERT_EQ(static_cast<unsigned>(SA_ONSTACK | SA_SIGINFO), sa.sa_flags & ~sa_restorer);
#ifdef SA_RESTORER
  ASSERT_EQ(bool(sa.sa_flags & sa_restorer), bool(sa.sa_restorer));
#endif

  // Put everything back how it was.
  ASSERT_EQ(0, sigaction_fn(sig, &original_sa, nullptr));
}

TEST(signal, sigaction) {
  TestSigAction(sigaction, sigaddset, SIGALRM);
}

TEST(signal, sigaction64_SIGRTMIN) {
  TestSigAction(sigaction64, sigaddset64, SIGRTMIN);
}

static void ClearSignalMask() {
  uint64_t sigset = 0;
  SignalSetAdd(&sigset, __SIGRTMIN);
  if (syscall(__NR_rt_sigprocmask, SIG_SETMASK, &sigset, nullptr, sizeof(sigset)) != 0) {
    abort();
  }
}

static void FillSignalMask() {
  uint64_t sigset = ~0ULL;
  for (int signo = __SIGRTMIN + 1; signo < SIGRTMIN; ++signo) {
    SignalSetDel(&sigset, signo);
  }
  if (syscall(__NR_rt_sigprocmask, SIG_SETMASK, &sigset, nullptr, sizeof(sigset)) != 0) {
    abort();
  }
}

static uint64_t GetSignalMask() {
  uint64_t sigset;
  if (syscall(__NR_rt_sigprocmask, SIG_SETMASK, nullptr, &sigset, sizeof(sigset)) != 0) {
    abort();
  }
  return sigset;
}

static void TestSignalMaskFiltered(uint64_t sigset) {
#if defined(__BIONIC__)
  for (int signo = __SIGRTMIN; signo < SIGRTMIN; ++signo) {
    bool signal_blocked = sigset & (1ULL << (signo - 1));
    if (signo == __SIGRTMIN) {
      // TIMER_SIGNAL must be blocked.
      EXPECT_EQ(true, signal_blocked) << "signal " << signo;
    } else {
      // The other reserved signals must not be blocked.
      EXPECT_EQ(false, signal_blocked) << "signal " << signo;
    }
  }
#else
  UNUSED(sigset);
#endif
}

static void TestSignalMaskFunction(std::function<void()> fn) {
  ClearSignalMask();
  fn();
  TestSignalMaskFiltered(GetSignalMask());
}

TEST(signal, sigaction_filter) {
  ClearSignalMask();
  static uint64_t sigset;
  struct sigaction sa = {};
  sa.sa_handler = [](int) { sigset = GetSignalMask(); };
  sa.sa_flags = SA_ONSTACK | SA_NODEFER;
  sigfillset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, nullptr);
  raise(SIGUSR1);

  // On LP32, struct sigaction::sa_mask is only 32-bits wide.
  unsigned long expected_sigset = ~0UL;

  // SIGKILL and SIGSTOP are always blocked.
  expected_sigset &= ~(1UL << (SIGKILL - 1));
  expected_sigset &= ~(1UL << (SIGSTOP - 1));

  ASSERT_EQ(static_cast<uint64_t>(expected_sigset), sigset);
}

TEST(signal, sigaction64_filter) {
  ClearSignalMask();
  static uint64_t sigset;
  struct sigaction64 sa = {};
  sa.sa_handler = [](int) { sigset = GetSignalMask(); };
  sa.sa_flags = SA_ONSTACK | SA_NODEFER;
  sigfillset64(&sa.sa_mask);
  sigaction64(SIGUSR1, &sa, nullptr);
  raise(SIGUSR1);

  uint64_t expected_sigset = ~0ULL;

  // SIGKILL and SIGSTOP are always blocked.
  expected_sigset &= ~(1ULL << (SIGKILL - 1));
  expected_sigset &= ~(1ULL << (SIGSTOP - 1));

  ASSERT_EQ(expected_sigset, sigset);
}

TEST(signal, sigprocmask_setmask_filter) {
  TestSignalMaskFunction([]() {
    ClearSignalMask();
    sigset_t sigset_libc;
    sigfillset(&sigset_libc);
    ASSERT_EQ(0, sigprocmask(SIG_SETMASK, &sigset_libc, nullptr));
  });
}

TEST(signal, sigprocmask64_setmask_filter) {
  TestSignalMaskFunction([]() {
    ClearSignalMask();
    sigset64_t sigset_libc;
    sigfillset64(&sigset_libc);
    ASSERT_EQ(0, sigprocmask64(SIG_SETMASK, &sigset_libc, nullptr));
  });
}

TEST(signal, pthread_sigmask_setmask_filter) {
  TestSignalMaskFunction([]() {
    ClearSignalMask();
    sigset_t sigset_libc;
    sigfillset(&sigset_libc);
    ASSERT_EQ(0, pthread_sigmask(SIG_SETMASK, &sigset_libc, nullptr));
  });
}

TEST(signal, pthread_sigmask64_setmask_filter) {
  TestSignalMaskFunction([]() {
    ClearSignalMask();
    sigset64_t sigset_libc;
    sigfillset64(&sigset_libc);
    ASSERT_EQ(0, pthread_sigmask64(SIG_SETMASK, &sigset_libc, nullptr));
  });
}

TEST(signal, sigprocmask_block_filter) {
  TestSignalMaskFunction([]() {
    ClearSignalMask();
    sigset_t sigset_libc;
    sigfillset(&sigset_libc);
    ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &sigset_libc, nullptr));
  });
}

TEST(signal, sigprocmask64_block_filter) {
  TestSignalMaskFunction([]() {
    ClearSignalMask();
    sigset64_t sigset_libc;
    sigfillset64(&sigset_libc);
    ASSERT_EQ(0, sigprocmask64(SIG_BLOCK, &sigset_libc, nullptr));
  });
}

TEST(signal, pthread_sigmask_block_filter) {
  TestSignalMaskFunction([]() {
    ClearSignalMask();
    sigset_t sigset_libc;
    sigfillset(&sigset_libc);
    ASSERT_EQ(0, pthread_sigmask(SIG_BLOCK, &sigset_libc, nullptr));
  });
}

TEST(signal, pthread_sigmask64_block_filter) {
  TestSignalMaskFunction([]() {
    ClearSignalMask();
    sigset64_t sigset_libc;
    sigfillset64(&sigset_libc);
    ASSERT_EQ(0, pthread_sigmask64(SIG_BLOCK, &sigset_libc, nullptr));
  });
}

TEST(signal, sigprocmask_unblock_filter) {
  TestSignalMaskFunction([]() {
    FillSignalMask();
    sigset_t sigset_libc;
    sigfillset(&sigset_libc);
    ASSERT_EQ(0, sigprocmask(SIG_UNBLOCK, &sigset_libc, nullptr));
  });
}

TEST(signal, sigprocmask64_unblock_filter) {
  TestSignalMaskFunction([]() {
    FillSignalMask();
    sigset64_t sigset_libc;
    sigfillset64(&sigset_libc);
    ASSERT_EQ(0, sigprocmask64(SIG_UNBLOCK, &sigset_libc, nullptr));
  });
}

TEST(signal, pthread_sigmask_unblock_filter) {
  TestSignalMaskFunction([]() {
    FillSignalMask();
    sigset_t sigset_libc;
    sigfillset(&sigset_libc);
    ASSERT_EQ(0, pthread_sigmask(SIG_UNBLOCK, &sigset_libc, nullptr));
  });
}

TEST(signal, pthread_sigmask64_unblock_filter) {
  TestSignalMaskFunction([]() {
    FillSignalMask();
    sigset64_t sigset_libc;
    sigfillset64(&sigset_libc);
    ASSERT_EQ(0, pthread_sigmask64(SIG_UNBLOCK, &sigset_libc, nullptr));
  });
}

// glibc filters out signals via sigfillset, not the actual underlying functions.
TEST(signal, sigset_filter) {
#if defined(__BIONIC__)
  TestSignalMaskFunction([]() {
    for (int i = 1; i <= 64; ++i) {
      sigset(i, SIG_HOLD);
    }
  });
#endif
}

TEST(signal, sighold_filter) {
#if defined(__BIONIC__)
  TestSignalMaskFunction([]() {
    for (int i = 1; i <= 64; ++i) {
      sighold(i);
    }
  });
#endif
}

#if defined(__BIONIC__) && !defined(__riscv)
// Not exposed via headers, but the symbols are available if you declare them yourself.
extern "C" int sigblock(int);
extern "C" int sigsetmask(int);
#define HAVE_SIGBLOCK_SIGSETMASK
#endif

TEST(signal, sigblock_filter) {
#if defined(HAVE_SIGBLOCK_SIGSETMASK)
  TestSignalMaskFunction([]() {
    sigblock(~0U);
  });
#endif
}

TEST(signal, sigsetmask_filter) {
#if defined(HAVE_SIGBLOCK_SIGSETMASK)
  TestSignalMaskFunction([]() {
    sigsetmask(~0U);
  });
#endif
}

TEST(signal, sys_signame) {
#if defined(__BIONIC__)
  ASSERT_TRUE(sys_signame[0] == nullptr);
  ASSERT_STREQ("HUP", sys_signame[SIGHUP]);
#else
  GTEST_SKIP() << "glibc doesn't have sys_signame";
#endif
}

TEST(signal, sys_siglist) {
#if !defined(ANDROID_HOST_MUSL)
  ASSERT_TRUE(sys_siglist[0] == nullptr);
  ASSERT_STREQ("Hangup", sys_siglist[SIGHUP]);
#else
  GTEST_SKIP() << "musl doesn't have sys_siglist";
#endif
}

TEST(signal, limits) {
  // These come from the kernel.
  ASSERT_EQ(32, __SIGRTMIN);
  ASSERT_EQ(64, __SIGRTMAX);

  // We reserve a non-zero number at the bottom for ourselves.
  ASSERT_GT(SIGRTMIN, __SIGRTMIN);

  // We don't currently reserve any at the top.
  ASSERT_EQ(SIGRTMAX, __SIGRTMAX);
}

static int g_sigqueue_signal_handler_call_count = 0;

static void SigqueueSignalHandler(int signum, siginfo_t* info, void*) {
  ASSERT_EQ(SIGALRM, signum);
  ASSERT_EQ(SIGALRM, info->si_signo);
  ASSERT_EQ(SI_QUEUE, info->si_code);
  ASSERT_EQ(1, info->si_value.sival_int);
  ++g_sigqueue_signal_handler_call_count;
}

TEST(signal, sigqueue) {
  ScopedSignalHandler ssh(SIGALRM, SigqueueSignalHandler, SA_SIGINFO);
  sigval sigval = {.sival_int = 1};
  errno = 0;
  ASSERT_EQ(0, sigqueue(getpid(), SIGALRM, sigval));
  ASSERT_ERRNO(0);
  ASSERT_EQ(1, g_sigqueue_signal_handler_call_count);
}

TEST(signal, pthread_sigqueue_self) {
#if !defined(ANDROID_HOST_MUSL)
  ScopedSignalHandler ssh(SIGALRM, SigqueueSignalHandler, SA_SIGINFO);
  sigval sigval = {.sival_int = 1};
  errno = 0;
  ASSERT_EQ(0, pthread_sigqueue(pthread_self(), SIGALRM, sigval));
  ASSERT_ERRNO(0);
  ASSERT_EQ(1, g_sigqueue_signal_handler_call_count);
#else
  GTEST_SKIP() << "musl doesn't have pthread_sigqueue";
#endif
}

TEST(signal, pthread_sigqueue_other) {
#if !defined(ANDROID_HOST_MUSL)
  ScopedSignalHandler ssh(SIGALRM, SigqueueSignalHandler, SA_SIGINFO);
  sigval sigval = {.sival_int = 1};

  sigset_t mask;
  sigfillset(&mask);
  pthread_sigmask(SIG_SETMASK, &mask, nullptr);
  pthread_t thread;
  int rc = pthread_create(&thread, nullptr,
                          [](void*) -> void* {
                            sigset_t mask;
                            sigemptyset(&mask);
                            sigsuspend(&mask);
                            return nullptr;
                          },
                          nullptr);
  ASSERT_EQ(0, rc);

  errno = 0;
  ASSERT_EQ(0, pthread_sigqueue(thread, SIGALRM, sigval));
  ASSERT_ERRNO(0);
  pthread_join(thread, nullptr);
  ASSERT_EQ(1, g_sigqueue_signal_handler_call_count);
#else
  GTEST_SKIP() << "musl doesn't have pthread_sigqueue";
#endif
}

TEST(signal, sigwait_SIGALRM) {
  SignalMaskRestorer smr;

  // Block SIGALRM.
  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &just_SIGALRM, nullptr));

  // Raise SIGALRM.
  sigval sigval = {.sival_int = 1};
  ASSERT_EQ(0, sigqueue(getpid(), SIGALRM, sigval));

  // Get pending SIGALRM.
  int sig;
  ASSERT_EQ(0, sigwait(&just_SIGALRM, &sig));
  ASSERT_EQ(SIGALRM, sig);
}

TEST(signal, sigwait64_SIGRTMIN) {
  SignalMaskRestorer smr;

  // Block SIGRTMIN.
  sigset64_t just_SIGRTMIN;
  sigemptyset64(&just_SIGRTMIN);
  sigaddset64(&just_SIGRTMIN, SIGRTMIN);
  ASSERT_EQ(0, sigprocmask64(SIG_BLOCK, &just_SIGRTMIN, nullptr));

  // Raise SIGRTMIN.
  sigval sigval = {.sival_int = 1};
  ASSERT_EQ(0, sigqueue(getpid(), SIGRTMIN, sigval));

  // Get pending SIGRTMIN.
  int sig;
  ASSERT_EQ(0, sigwait64(&just_SIGRTMIN, &sig));
  ASSERT_EQ(SIGRTMIN, sig);
}

TEST(signal, sigwaitinfo) {
  SignalMaskRestorer smr;

  // Block SIGALRM.
  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &just_SIGALRM, nullptr));

  // Raise SIGALRM.
  sigval sigval = {.sival_int = 1};
  ASSERT_EQ(0, sigqueue(getpid(), SIGALRM, sigval));

  // Get pending SIGALRM.
  siginfo_t info;
  errno = 0;
  ASSERT_EQ(SIGALRM, sigwaitinfo(&just_SIGALRM, &info));
  ASSERT_ERRNO(0);
  ASSERT_EQ(SIGALRM, info.si_signo);
  ASSERT_EQ(1, info.si_value.sival_int);
}

TEST(signal, sigwaitinfo64_SIGRTMIN) {
  SignalMaskRestorer smr;

  // Block SIGRTMIN.
  sigset64_t just_SIGRTMIN;
  sigemptyset64(&just_SIGRTMIN);
  sigaddset64(&just_SIGRTMIN, SIGRTMIN);
  ASSERT_EQ(0, sigprocmask64(SIG_BLOCK, &just_SIGRTMIN, nullptr));

  // Raise SIGRTMIN.
  sigval sigval = {.sival_int = 1};
  ASSERT_EQ(0, sigqueue(getpid(), SIGRTMIN, sigval));

  // Get pending SIGRTMIN.
  siginfo_t info;
  errno = 0;
  ASSERT_EQ(SIGRTMIN, sigwaitinfo64(&just_SIGRTMIN, &info));
  ASSERT_ERRNO(0);
  ASSERT_EQ(SIGRTMIN, info.si_signo);
  ASSERT_EQ(1, info.si_value.sival_int);
}

TEST(signal, sigtimedwait) {
  SignalMaskRestorer smr;

  // Block SIGALRM.
  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &just_SIGALRM, nullptr));

  // Raise SIGALRM.
  sigval sigval = { .sival_int = 1 };
  ASSERT_EQ(0, sigqueue(getpid(), SIGALRM, sigval));

  // Get pending SIGALRM.
  siginfo_t info;
  timespec timeout = { .tv_sec = 2, .tv_nsec = 0 };
  errno = 0;
  ASSERT_EQ(SIGALRM, sigtimedwait(&just_SIGALRM, &info, &timeout));
  ASSERT_ERRNO(0);
}

TEST(signal, sigtimedwait64_SIGRTMIN) {
  SignalMaskRestorer smr;

  // Block SIGRTMIN.
  sigset64_t just_SIGRTMIN;
  sigemptyset64(&just_SIGRTMIN);
  sigaddset64(&just_SIGRTMIN, SIGRTMIN);
  ASSERT_EQ(0, sigprocmask64(SIG_BLOCK, &just_SIGRTMIN, nullptr));

  // Raise SIGALRM.
  sigval sigval = { .sival_int = 1 };
  ASSERT_EQ(0, sigqueue(getpid(), SIGRTMIN, sigval));

  // Get pending SIGALRM.
  siginfo_t info;
  timespec timeout = { .tv_sec = 2, .tv_nsec = 0 };
  errno = 0;
  ASSERT_EQ(SIGRTMIN, sigtimedwait64(&just_SIGRTMIN, &info, &timeout));
  ASSERT_ERRNO(0);
}

TEST(signal, sigtimedwait_timeout) {
  // Block SIGALRM.
  sigset_t just_SIGALRM;
  sigemptyset(&just_SIGALRM);
  sigaddset(&just_SIGALRM, SIGALRM);
  sigset_t original_set;
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &just_SIGALRM, &original_set));

  // Wait timeout.
  auto t0 = std::chrono::steady_clock::now();
  siginfo_t info;
  timespec timeout = { .tv_sec = 0, .tv_nsec = 1000000 };
  errno = 0;
  ASSERT_EQ(-1, sigtimedwait(&just_SIGALRM, &info, &timeout));
  ASSERT_ERRNO(EAGAIN);
  auto t1 = std::chrono::steady_clock::now();
  ASSERT_GE(t1-t0, 1000000ns);

  ASSERT_EQ(0, sigprocmask(SIG_SETMASK, &original_set, nullptr));
}

#if defined(__BIONIC__)
TEST(signal, rt_tgsigqueueinfo) {
  // Test whether rt_tgsigqueueinfo allows sending arbitrary si_code values to self.
  // If this fails, your kernel needs commit 66dd34a to be backported.
  static constexpr char error_msg[] =
    "\nPlease ensure that the following kernel patch has been applied:\n"
    "* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=66dd34ad31e5963d72a700ec3f2449291d322921\n";
  static siginfo received;

  struct sigaction handler = {};
  handler.sa_sigaction = [](int, siginfo_t* siginfo, void*) { received = *siginfo; };
  handler.sa_flags = SA_SIGINFO;

  ASSERT_EQ(0, sigaction(SIGUSR1, &handler, nullptr));

  siginfo sent = {.si_code = SI_TKILL};
  ASSERT_EQ(0, syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), SIGUSR1, &sent))
    << "rt_tgsigqueueinfo failed: " << strerror(errno) << error_msg;
  ASSERT_EQ(sent.si_code, received.si_code) << "rt_tgsigqueueinfo modified si_code, expected "
                                            << sent.si_code << ", received " << received.si_code
                                            << error_msg;

  sent.si_code = SI_USER;
  ASSERT_EQ(0, syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), SIGUSR1, &sent))
    << "rt_tgsigqueueinfo failed: " << strerror(errno) << error_msg;
  ASSERT_EQ(sent.si_code, received.si_code) << "rt_tgsigqueueinfo modified si_code, expected "
                                            << sent.si_code << ", received " << received.si_code
                                            << error_msg;
}
#endif

TEST(signal, sigset_size) {
  // The setjmp implementations assume that sigset_t can fit in a long.
  // This is true because the 32-bit ABIs have broken rt signal support,
  // but the 64-bit ABIs both have a SIGRTMAX defined as 64.
#if defined(__BIONIC__)
  static_assert(sizeof(sigset_t) <= sizeof(long), "sigset_t doesn't fit in a long");
#endif
  static_assert(sizeof(sigset64_t)*8 >= 64, "sigset64_t too small for real-time signals");
}

TEST(signal, sigignore_EINVAL) {
  errno = 0;
  ASSERT_EQ(-1, sigignore(99999));
  ASSERT_ERRNO(EINVAL);
}

TEST(signal, sigignore) {
  errno = 0;
  EXPECT_EQ(-1, sigignore(SIGKILL));
  EXPECT_ERRNO(EINVAL);

  errno = 0;
  EXPECT_EQ(-1, sigignore(SIGSTOP));
  EXPECT_ERRNO(EINVAL);

  ScopedSignalHandler sigalrm{SIGALRM};
  ASSERT_EQ(0, sigignore(SIGALRM));

  struct sigaction sa;
  ASSERT_EQ(0, sigaction(SIGALRM, nullptr, &sa));
  EXPECT_EQ(SIG_IGN, sa.sa_handler);
}

TEST(signal, sighold_EINVAL) {
  errno = 0;
  ASSERT_EQ(-1, sighold(99999));
  ASSERT_ERRNO(EINVAL);
}

TEST(signal, sigpause_EINVAL) {
  errno = 0;
  ASSERT_EQ(-1, sigpause(99999));
  ASSERT_ERRNO(EINVAL);
}

TEST(signal, sigrelse_EINVAL) {
  errno = 0;
  ASSERT_EQ(-1, sigpause(99999));
  ASSERT_ERRNO(EINVAL);
}

static void TestSigholdSigpauseSigrelse(int sig) {
  static int signal_handler_call_count = 0;
  ScopedSignalHandler ssh{sig, [](int) { signal_handler_call_count++; }};
  SignalMaskRestorer mask_restorer;
  sigset_t set;

  // sighold(SIGALRM/SIGRTMIN) should add SIGALRM/SIGRTMIN to the signal mask ...
  ASSERT_EQ(0, sighold(sig));
  ASSERT_EQ(0, sigprocmask(SIG_SETMASK, nullptr, &set));
  EXPECT_TRUE(sigismember(&set, sig));

  // ... preventing our SIGALRM/SIGRTMIN handler from running ...
  raise(sig);
  ASSERT_EQ(0, signal_handler_call_count);
  // ... until sigpause(SIGALRM/SIGRTMIN) temporarily unblocks it.
  ASSERT_EQ(-1, sigpause(sig));
  ASSERT_ERRNO(EINTR);
  ASSERT_EQ(1, signal_handler_call_count);

  if (sig >= SIGRTMIN && sizeof(void*) == 8) {
    // But sigpause(SIGALRM/SIGRTMIN) shouldn't permanently unblock SIGALRM/SIGRTMIN.
    ASSERT_EQ(0, sigprocmask(SIG_SETMASK, nullptr, &set));
    EXPECT_TRUE(sigismember(&set, sig));

    // Whereas sigrelse(SIGALRM/SIGRTMIN) should.
    ASSERT_EQ(0, sigrelse(sig));
    ASSERT_EQ(0, sigprocmask(SIG_SETMASK, nullptr, &set));
    EXPECT_FALSE(sigismember(&set, sig));
  } else {
    // sigismember won't work for SIGRTMIN on LP32.
  }
}

TEST(signal, sighold_sigpause_sigrelse) {
  TestSigholdSigpauseSigrelse(SIGALRM);
}

TEST(signal, sighold_sigpause_sigrelse_RT) {
  TestSigholdSigpauseSigrelse(SIGRTMIN);
}

TEST(signal, sigset_EINVAL) {
  errno = 0;
  ASSERT_EQ(SIG_ERR, sigset(99999, SIG_DFL));
  ASSERT_ERRNO(EINVAL);
}

TEST(signal, sigset_RT) {
  static int signal_handler_call_count = 0;
  auto signal_handler = [](int) { signal_handler_call_count++; };
  ScopedSignalHandler ssh{SIGRTMIN, signal_handler};
  SignalMaskRestorer mask_restorer;

  ASSERT_EQ(signal_handler, sigset(SIGRTMIN, SIG_HOLD));
#if defined(__LP64__)
  sigset_t set;
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, nullptr, &set));
  ASSERT_TRUE(sigismember(&set, SIGRTMIN));
#endif

  ASSERT_EQ(SIG_HOLD, sigset(SIGRTMIN, signal_handler));
  ASSERT_EQ(signal_handler, sigset(SIGRTMIN, signal_handler));
  ASSERT_EQ(0, signal_handler_call_count);
  raise(SIGRTMIN);
  ASSERT_EQ(1, signal_handler_call_count);
}

TEST(signal, sigset) {
  static int signal_handler_call_count = 0;
  auto signal_handler = [](int) { signal_handler_call_count++; };
  ScopedSignalHandler ssh{SIGALRM, signal_handler};
  SignalMaskRestorer mask_restorer;

  ASSERT_EQ(0, signal_handler_call_count);
  raise(SIGALRM);
  ASSERT_EQ(1, signal_handler_call_count);

  // Block SIGALRM so the next sigset(SIGARLM) call will return SIG_HOLD.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, &set, nullptr));

  sigemptyset(&set);
  ASSERT_EQ(SIG_HOLD, sigset(SIGALRM, signal_handler));
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, nullptr, &set));
  EXPECT_FALSE(sigismember(&set, SIGALRM));

  ASSERT_EQ(signal_handler, sigset(SIGALRM, SIG_IGN));
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, nullptr, &set));
  EXPECT_FALSE(sigismember(&set, SIGALRM));

  ASSERT_EQ(SIG_IGN, sigset(SIGALRM, SIG_DFL));
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, nullptr, &set));
  EXPECT_FALSE(sigismember(&set, SIGALRM));

  ASSERT_EQ(SIG_DFL, sigset(SIGALRM, SIG_HOLD));
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, nullptr, &set));
  EXPECT_TRUE(sigismember(&set, SIGALRM));
}

TEST(signal, killpg_EINVAL) {
  // POSIX leaves pgrp <= 1 undefined, but glibc fails with EINVAL for < 0
  // and passes 0 through to kill(2).
  errno = 0;
  ASSERT_EQ(-1, killpg(-1, SIGKILL));
  ASSERT_ERRNO(EINVAL);
}

TEST(signal, sig2str) {
#if defined(__BIONIC__)
  char str[SIG2STR_MAX];

  // A regular signal.
  ASSERT_EQ(0, sig2str(SIGHUP, str));
  ASSERT_STREQ("HUP", str);

  // A real-time signal.
  ASSERT_EQ(0, sig2str(SIGRTMIN + 4, str));
  ASSERT_STREQ("RTMIN+4", str);
  ASSERT_EQ(0, sig2str(SIGRTMAX - 4, str));
  ASSERT_STREQ("RTMAX-4", str);
  // Special cases.
  ASSERT_EQ(0, sig2str(SIGRTMAX, str));
  ASSERT_STREQ("RTMAX", str);
  ASSERT_EQ(0, sig2str(SIGRTMIN, str));
  ASSERT_STREQ("RTMIN", str);
  // One of the signals the C library keeps to itself.
  ASSERT_EQ(-1, sig2str(32, str));  // __SIGRTMIN

  // Errors.
  ASSERT_EQ(-1, sig2str(-1, str));    // Too small.
  ASSERT_EQ(-1, sig2str(0, str));     // Still too small.
  ASSERT_EQ(-1, sig2str(1234, str));  // Too large.
#else
  GTEST_SKIP() << "our old glibc doesn't have sig2str";
#endif
}

TEST(signal, str2sig) {
#if defined(__BIONIC__)
  int sig;

  // A regular signal, by number.
  sig = -1;
  ASSERT_EQ(0, str2sig("9", &sig));
  ASSERT_EQ(SIGKILL, sig);

  // A regular signal, by name.
  sig = -1;
  ASSERT_EQ(0, str2sig("HUP", &sig));
  ASSERT_EQ(SIGHUP, sig);

  // A real-time signal, by number.
  sig = -1;
  ASSERT_EQ(0, str2sig("64", &sig));
  ASSERT_EQ(SIGRTMAX, sig);

  // A real-time signal, by name and offset.
  sig = -1;
  ASSERT_EQ(0, str2sig("RTMAX-4", &sig));
  ASSERT_EQ(SIGRTMAX - 4, sig);
  sig = -1;
  ASSERT_EQ(0, str2sig("RTMIN+4", &sig));
  ASSERT_EQ(SIGRTMIN + 4, sig);
  // Unspecified by POSIX, but we try to be reasonable.
  sig = -1;
  ASSERT_EQ(0, str2sig("RTMAX-0", &sig));
  ASSERT_EQ(SIGRTMAX, sig);
  sig = -1;
  ASSERT_EQ(0, str2sig("RTMIN+0", &sig));
  ASSERT_EQ(SIGRTMIN, sig);
  // One of the signals the C library keeps to itself, numerically.
  ASSERT_EQ(-1, str2sig("32", &sig));  // __SIGRTMIN

  // Special cases.
  sig = -1;
  ASSERT_EQ(0, str2sig("RTMAX", &sig));
  ASSERT_EQ(SIGRTMAX, sig);
  sig = -1;
  ASSERT_EQ(0, str2sig("RTMIN", &sig));
  ASSERT_EQ(SIGRTMIN, sig);

  // Errors.
  ASSERT_EQ(-1, str2sig("SIGHUP", &sig));     // No "SIG" prefix allowed.
  ASSERT_EQ(-1, str2sig("-1", &sig));         // Too small.
  ASSERT_EQ(-1, str2sig("0", &sig));          // Still too small.
  ASSERT_EQ(-1, str2sig("1234", &sig));       // Too large.
  ASSERT_EQ(-1, str2sig("RTMAX-666", &sig));  // Offset too small.
  ASSERT_EQ(-1, str2sig("RTMIN+666", &sig));  // Offset too large.
  ASSERT_EQ(-1, str2sig("RTMAX-+1", &sig));   // Silly.
  ASSERT_EQ(-1, str2sig("RTMIN+-1", &sig));   // Silly.
  ASSERT_EQ(-1, str2sig("HUPs", &sig));       // Trailing junk.
  ASSERT_EQ(-1, str2sig("2b", &sig));         // Trailing junk.
  ASSERT_EQ(-1, str2sig("RTMIN+2b", &sig));   // Trailing junk.
#else
  GTEST_SKIP() << "our old glibc doesn't have str2sig";
#endif
}
```