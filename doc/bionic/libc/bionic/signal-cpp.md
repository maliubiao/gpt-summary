Response:
Let's break down the thought process for answering the request about `bionic/libc/bionic/signal.cpp`.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the provided C++ code related to signal handling in Android's Bionic library. Key areas of focus are:

* **Functionality:** What does the code *do*?
* **Android Relevance:** How does this relate to the Android OS?
* **Detailed Implementation:**  Explain the inner workings of each libc function.
* **Dynamic Linker Interaction:**  Address any interaction with the dynamic linker (though this file doesn't directly involve dynamic linking in a *major* way).
* **Logic and I/O:**  Describe any logical steps and input/output.
* **Common Errors:** Highlight potential pitfalls for developers.
* **Android Framework/NDK Integration:**  Trace the path from the higher levels of Android down to this code.
* **Frida Hooking:** Provide examples of using Frida to inspect this code.

**2. Initial Code Scan and Categorization:**

The first step is to read through the code and identify the functions being defined. I immediately noticed a pattern: many functions have `pthread_` or no prefix, and many have a `64` suffix. This signals the presence of both POSIX standard signal functions and their 64-bit counterparts. This immediately hints at the need to handle different signal set sizes.

I grouped the functions mentally:

* **Thread-related:** `pthread_sigmask`, `pthread_sigmask64`
* **Set Manipulation:** `sigaddset`, `sigaddset64`, `sigdelset`, `sigdelset64`, `sigemptyset`, `sigemptyset64`, `sigfillset`, `sigfillset64`
* **Signal Blocking/Masking (BSD Compatibility):** `sigblock`, `sigsetmask`
* **Signal Handling:** `sighold`, `sigignore`, `siginterrupt`, `signal`, `sigset`
* **Signal Waiting/Pausing:** `sigpause`, `sigsuspend`, `sigsuspend64`, `sigtimedwait`, `sigtimedwait64`, `sigwait`, `sigwait64`, `sigwaitinfo`, `sigwaitinfo64`
* **Signal Sending:** `sigqueue`
* **Signal Pending:** `sigpending`, `sigpending64`
* **Internal Helpers:** `SigAddSet`, `SigDelSet`, `SigEmptySet`, `SigFillSet`, `SigIsMember`, `_signal`
* **External Syscall Wrappers:**  `__rt_sigpending`, `__rt_sigqueueinfo`, `__rt_sigsuspend`, `__rt_sigtimedwait` (crucially, I recognize these are likely direct system call wrappers)

**3. Analyzing Each Function (Core Logic):**

For each function, I asked:

* **What is its purpose according to standard documentation?** (If it's a standard POSIX function).
* **How does this implementation achieve that purpose?**  Does it directly call a syscall?  Does it manipulate data structures?
* **Are there any Bionic-specific details?**  (Like the `ErrnoRestorer` or `SigSetConverter`).

For example, with `sigaddset`:

* **Purpose:** Add a signal to a signal set.
* **Implementation:** Bit manipulation on the underlying `sigset_t` structure. Handles boundary conditions and error checking.
* **Bionic Specifics:** None obvious in the core logic, but the template structure is a Bionic pattern for type safety.

With `pthread_sigmask`:

* **Purpose:** Get and/or set the signal mask for the current thread.
* **Implementation:** Directly calls the `sigprocmask` system call. The `ErrnoRestorer` is a Bionic utility for ensuring errno is correctly handled across syscall boundaries.
* **Bionic Specifics:** The `ErrnoRestorer`.

With `sigsuspend`:

* **Purpose:** Replace the current signal mask and pause execution until a signal is received.
* **Implementation:** Calls the `__rt_sigsuspend` syscall. The filtering of reserved signals is an important Android-specific aspect.

**4. Identifying Android Relevance:**

I looked for connections between the functions and Android's specific needs:

* **Process Management:** Signal handling is fundamental to process management and inter-process communication (IPC), both crucial in Android.
* **System Calls:** The reliance on `sigprocmask`, `sigaction`, and the `__rt_` prefixed functions clearly links this code to the Linux kernel and Android's system call interface.
* **Thread Management:** The `pthread_` prefixed functions highlight the importance of signal handling in a multithreaded environment like Android.
* **Reserved Signals:** The filtering of reserved signals in `sigsuspend` and `sigtimedwait` is a direct Android-specific customization.

**5. Addressing Dynamic Linker Interaction:**

Initially, I thought this file might heavily involve the dynamic linker. However, upon closer inspection, it primarily deals with the *implementation* of signal handling, which is used by dynamically linked libraries. The direct interaction is minimal. I decided to mention this, explaining that while not directly *in* the dynamic linker, it's a fundamental library *used* by it. I provided a generic example of SO layout and linking, rather than trying to force a specific signal-related dynamic linking scenario.

**6. Logic, Input/Output, and Errors:**

For functions with more complex logic (like the `SigAddSet` template), I considered potential inputs and outputs and how errors might occur (e.g., invalid signal numbers, null pointers). For functions like `sigwait`, the looping behavior to handle `EAGAIN` and `EINTR` is an important logical detail.

Common errors are easier to identify based on standard signal usage patterns (e.g., incorrect signal numbers, forgetting to restore signal handlers).

**7. Tracing Framework/NDK Path:**

This required thinking about how Android applications use signals:

* **Framework:**  Java code might trigger events that eventually lead to signals (e.g., app crashes leading to SIGSEGV). The Activity Manager also uses signals for process lifecycle management.
* **NDK:**  Native code can directly use the signal functions exposed by this library.

I traced a simple example: a native crash leading to the delivery of a signal and the execution of a signal handler defined using `signal` or `sigaction`.

**8. Frida Hooking:**

I focused on demonstrating how to intercept function calls and inspect arguments using Frida. I chose key functions like `signal`, `sigaction`, and `pthread_sigmask` to show different aspects of signal handling.

**9. Structuring the Answer:**

I organized the answer logically, starting with the overall functionality and then diving into details for each aspect of the request. I used clear headings and bullet points to make the information easier to read and understand. I made sure to use Chinese as requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file does more with dynamic linking.
* **Correction:** Realized it's more about *implementing* signal handling, which is *used by* dynamically linked code. Adjusted the explanation accordingly.
* **Initial thought:** Go into extreme detail about every bit manipulation in the `SigAddSet` template.
* **Refinement:**  Explained the general principle of bit manipulation and the purpose of the error checking, avoiding overly granular details unless necessary.
* **Ensuring clarity:** Double-checked that the Chinese explanations were accurate and easy to understand.

By following these steps, I aimed to provide a comprehensive and accurate answer that addresses all parts of the original request.
这个文件 `bionic/libc/bionic/signal.cpp` 是 Android Bionic 库中关于信号处理的核心实现。它提供了 POSIX 标准的信号处理 API，供应用程序和系统库使用。

**主要功能列举:**

1. **信号集操作:**
   - `sigemptyset`, `sigemptyset64`: 初始化一个空的信号集。
   - `sigfillset`, `sigfillset64`: 初始化一个包含所有信号的信号集。
   - `sigaddset`, `sigaddset64`: 向信号集中添加一个信号。
   - `sigdelset`, `sigdelset64`: 从信号集中移除一个信号。
   - `sigismember`, `sigismember64`: 检查信号是否是信号集的成员。

2. **信号屏蔽 (Signal Masking):**
   - `pthread_sigmask`, `pthread_sigmask64`: 获取或设置当前线程的信号屏蔽字。
   - `sigprocmask64`: (底层函数，`pthread_sigmask` 的基础) 修改进程的信号屏蔽字。
   - `sigblock`: (BSD 兼容) 向进程的信号屏蔽字中添加信号。
   - `sigsetmask`: (BSD 兼容) 设置进程的信号屏蔽字。

3. **信号处理句柄 (Signal Handlers):**
   - `signal`: 设置一个信号的处理句柄。
   - `sigaction64`: (底层函数，`signal` 的更强大版本) 检查或修改与特定信号关联的操作。允许更精细的控制，例如指定信号处理程序、设置标志等。
   - `sighold`: 阻塞一个信号 (将其添加到屏蔽字)。
   - `sigignore`: 忽略一个信号。
   - `siginterrupt`: 控制在信号处理程序返回后是否重启被中断的系统调用。
   - `sigset`: (部分兼容) 修改信号关联的操作，类似于 `signal`，但行为上有一些差异，特别是在信号阻塞方面。

4. **挂起和等待信号:**
   - `sigpause`: 原子地取消阻塞给定信号并使调用进程休眠，直到接收到信号。
   - `sigsuspend`, `sigsuspend64`: 临时替换进程的信号屏蔽字并挂起进程执行，直到收到一个未被屏蔽的信号。
   - `sigtimedwait`, `sigtimedwait64`: 阻塞调用线程，直到指定的信号集中的信号到达，或者直到超时。
   - `sigwait`, `sigwait64`: 阻塞调用线程，直到指定的信号集中的信号到达。与 `sigtimedwait` 类似，但没有超时。
   - `sigwaitinfo`, `sigwaitinfo64`: 阻塞调用线程，直到指定的信号集中的信号到达，并返回关于该信号的信息。

5. **发送信号:**
   - `sigqueue`: 向指定的进程发送一个带有附加数据的信号。

6. **检查未决信号:**
   - `sigpending`, `sigpending64`: 获取当前被阻塞且未处理的信号集。

**与 Android 功能的关系及举例说明:**

信号处理在 Android 系统中扮演着至关重要的角色，用于进程间通信、错误处理、进程生命周期管理等。

* **应用崩溃处理:** 当 Android 应用发生崩溃 (例如，空指针解引用)，系统会向该应用进程发送 `SIGSEGV` 信号。`bionic/signal.cpp` 中的代码负责处理这些信号，可能会执行一些清理工作，记录错误信息，并最终终止应用进程。
* **进程间通信 (IPC):**  信号可以作为一种简单的 IPC 机制。例如，一个进程可以使用 `kill()` 系统调用（最终会调用到 `sigqueue` 或类似的底层机制）向另一个进程发送信号，以通知其某个事件发生。例如，`ActivityManagerService` 可能会向应用进程发送信号来触发某些操作。
* **进程生命周期管理:** Android 系统使用信号来管理应用进程的生命周期。例如，当系统需要回收内存时，可能会向后台进程发送 `SIGTERM` 信号，请求其优雅地终止。
* **Native 代码的错误处理:** NDK 开发的应用可以使用 `signal` 或 `sigaction` 设置自定义的信号处理程序，以便在接收到特定信号时执行特定的操作，例如记录错误信息或进行资源清理。
* **系统调用中断:** 当一个系统调用正在执行时，如果收到一个信号，系统调用可能会被中断。`siginterrupt` 函数可以控制在这种情况下是否重启系统调用。

**每个 libc 函数的功能和实现细节:**

这里详细解释一些关键函数的实现方式：

**1. `pthread_sigmask`, `pthread_sigmask64`:**

   - **功能:**  获取或设置当前线程的信号屏蔽字。信号屏蔽字决定了哪些信号会被线程阻塞。
   - **实现:** 这两个函数是对 `sigprocmask` 系统调用的封装。`sigprocmask` 是一个内核提供的系统调用，直接操作进程的信号屏蔽字。`pthread_sigmask` 使用了 `ErrnoRestorer` 类来确保在系统调用前后正确处理 `errno` 的值。

   ```c++
   int pthread_sigmask(int how, const sigset_t* new_set, sigset_t* old_set) {
     ErrnoRestorer errno_restorer;
     return (sigprocmask(how, new_set, old_set) == -1) ? errno : 0;
   }
   ```
   - `how`: 指定如何修改信号屏蔽字 (`SIG_BLOCK`, `SIG_UNBLOCK`, `SIG_SETMASK`)。
   - `new_set`: 指向要设置的新信号集的指针。如果为 `nullptr`，则不修改信号屏蔽字。
   - `old_set`: 指向用于存储原始信号集的指针。如果为 `nullptr`，则不获取原始信号集。
   - 如果 `sigprocmask` 返回 -1，则表示出错，`pthread_sigmask` 返回 `errno` 值；否则返回 0 表示成功。

**2. `sigaddset`, `sigdelset`, `sigemptyset`, `sigfillset`:**

   - **功能:**  用于操作信号集。
   - **实现:** 这些函数直接操作 `sigset_t` 或 `sigset64_t` 结构体的内存。信号集通常使用位图来表示，每一位对应一个信号。
   - `SigAddSet` 模板函数展示了添加信号的实现：

   ```c++
   template <typename SigSetT>
   int SigAddSet(SigSetT* set, int sig) {
     int bit = sig - 1; // 信号编号从 1 开始，但位位置从 0 开始。
     unsigned long* local_set = reinterpret_cast<unsigned long*>(set);
     if (set == nullptr || bit < 0 || bit >= static_cast<int>(8*sizeof(*set))) {
       errno = EINVAL;
       return -1;
     }
     local_set[bit / LONG_BIT] |= 1UL << (bit % LONG_BIT);
     return 0;
   }
   ```
   - 它通过计算信号对应的位在 `unsigned long` 数组中的索引和偏移量，然后使用按位或操作来设置该位。

**3. `signal`:**

   - **功能:**  设置一个信号的处理句柄。
   - **实现:**  `signal` 函数实际上是对 `sigaction64` 函数的封装，并设置了 `SA_RESTART` 标志。`SA_RESTART` 表示在信号处理程序返回后，如果被信号中断的系统调用可以重启，则重启该系统调用。

   ```c++
   sighandler_t signal(int sig, sighandler_t handler) {
     return _signal(sig, handler, SA_RESTART);
   }

   __LIBC_HIDDEN__ sighandler_t _signal(int sig, sighandler_t handler, int flags) {
     struct sigaction64 sa = { .sa_handler = handler, .sa_flags = flags };
     return (sigaction64(sig, &sa, &sa) == -1) ? SIG_ERR : sa.sa_handler;
   }
   ```
   - 它创建了一个 `sigaction64` 结构体，设置了信号处理函数 `handler` 和标志 `flags`，然后调用 `sigaction64` 系统调用。

**4. `sigsuspend`, `sigsuspend64`:**

   - **功能:**  原子地替换进程的信号屏蔽字并挂起进程执行，直到收到一个未被屏蔽的信号。
   - **实现:**  这两个函数调用了 `__rt_sigsuspend`，这很可能是一个直接调用内核 `sigsuspend` 系统调用的包装函数。在调用系统调用之前，`sigsuspend64` 还会过滤掉一些 Android 保留的信号。

   ```c++
   int sigsuspend64(const sigset64_t* set) {
     sigset64_t mutable_set;
     sigset64_t* mutable_set_ptr = nullptr;
     if (set) {
       mutable_set = filter_reserved_signals(*set, SIG_SETMASK);
       mutable_set_ptr = &mutable_set;
     }
     return __rt_sigsuspend(mutable_set_ptr, sizeof(*set));
   }
   ```
   - `filter_reserved_signals` 是一个 Android 特有的函数，用于确保某些系统保留的信号不会被用户态的 `sigsuspend` 屏蔽。

**涉及 dynamic linker 的功能:**

这个 `signal.cpp` 文件本身主要负责信号处理的实现，**不直接涉及 dynamic linker 的核心功能**。Dynamic linker (例如 Android 的 `linker64` 或 `linker`) 负责加载共享库，解析符号依赖，并将库加载到进程的地址空间。

然而，信号处理机制是所有进程的基础设施，包括 dynamic linker 本身。当 dynamic linker 在执行加载或链接过程中遇到错误时，它可以使用信号来通知进程或采取其他措施。例如，如果加载一个库失败，可能会导致进程收到一个信号。

**SO 布局样本和链接的处理过程 (与信号处理的间接关系):**

假设我们有一个简单的动态链接的程序 `app`，它依赖于一个共享库 `libfoo.so`。

**SO 布局样本:**

```
地址空间:
  [内存区域 1] - 可执行文件 app 的代码和数据
  [内存区域 2] - libfoo.so 的代码和数据
  [内存区域 3] - libc.so (包含 signal.cpp 的实现)
  ...
```

**链接的处理过程 (简化):**

1. **加载:** 当 `app` 启动时，操作系统会加载 `app` 的可执行文件到内存中。
2. **动态链接器介入:** 操作系统会启动 dynamic linker，dynamic linker 会读取 `app` 的头部信息，找到其依赖的共享库 (例如 `libfoo.so`)。
3. **加载共享库:** dynamic linker 会将 `libfoo.so` 加载到进程的地址空间中。这可能涉及查找库文件、分配内存、读取文件内容等。
4. **符号解析:** dynamic linker 会解析 `app` 和 `libfoo.so` 之间的符号依赖关系。例如，如果 `app` 调用了 `libfoo.so` 中定义的函数，dynamic linker 需要找到该函数的地址。
5. **重定位:** dynamic linker 会修改代码和数据中的地址，使其指向正确的内存位置。
6. **启动应用程序:** 一旦所有依赖的库都加载并链接完成，dynamic linker 就会将控制权交给 `app` 的入口点。

**与信号处理的联系:**

虽然 `signal.cpp` 不直接执行链接操作，但它提供的信号处理功能会被 dynamic linker 使用。例如：

* **加载错误:** 如果 dynamic linker 在加载 `libfoo.so` 时遇到错误 (例如，找不到文件)，它可能会使用信号机制来通知进程或采取默认的错误处理措施。
* **安全机制:** 某些安全相关的操作可能涉及信号处理。

**假设输入与输出 (逻辑推理):**

**示例 1: `sigaddset`**

* **假设输入:**
    - `set`: 指向一个已分配的 `sigset_t` 变量的指针，假设其初始状态为全零 (空集)。
    - `sig`: 信号编号，例如 `SIGINT` (通常为 2)。
* **输出:**
    - 函数返回 0 (表示成功)。
    - `set` 指向的 `sigset_t` 变量的相应位被设置为 1，表示 `SIGINT` 被添加到信号集中。

**示例 2: `pthread_sigmask`**

* **假设输入:**
    - `how`: `SIG_BLOCK` (阻塞信号)。
    - `new_set`: 指向一个包含 `SIGUSR1` (假设为 10) 的信号集的指针。
    - `old_set`: 指向一个已分配的 `sigset_t` 变量的指针。
* **输出:**
    - 函数返回 0 (表示成功)。
    - 当前线程的信号屏蔽字中添加了 `SIGUSR1`。
    - `old_set` 指向的变量存储了调用 `pthread_sigmask` 之前的线程信号屏蔽字。

**用户或编程常见的使用错误:**

1. **错误的信号编号:** 使用未定义的或超出范围的信号编号会导致错误。
2. **忘记恢复信号处理程序:**  如果修改了信号处理程序，但忘记在不需要时恢复到默认或之前的处理程序，可能会导致意外行为。
3. **在多线程环境中使用 `signal`:**  `signal` 函数在多线程环境中的行为是未定义的，应该使用 `pthread_sigaction` 或 `sigaction`。Bionic 中虽然提供了 `signal`，但在多线程环境下使用仍然不推荐。
4. **信号处理程序中的非线程安全操作:** 信号处理程序可能会在任意时刻被调用，因此在其中执行非线程安全的操作 (例如，修改全局变量而没有适当的同步) 可能会导致竞争条件和数据损坏。
5. **对被阻塞的信号的误解:**  阻塞一个信号并不意味着该信号永远不会被处理。当信号被阻塞时，它会被挂起，直到信号被取消阻塞。如果信号在被阻塞期间发生，它会在取消阻塞后立即被传递。
6. **`sigsuspend` 的错误使用:**  `sigsuspend` 必须原子地执行解除阻塞和挂起操作。如果在解除阻塞和调用 `sigsuspend` 之间存在时间间隔，可能会错过信号。

**Android Framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 层):**
   - 应用程序或系统服务在 Java 代码中可能会发生错误，例如空指针异常。
   - JVM 会捕获这些异常，并在某些情况下将其转换为信号，例如 `SIGSEGV`。
   - 系统进程 (例如 `system_server`) 可能会使用 `Process.sendSignal()` 方法向其他进程发送信号。这个方法最终会调用到 native 代码。

2. **NDK (Native 层):**
   - NDK 开发的应用程序可以直接使用 Bionic 库提供的信号处理 API。
   - 例如，native 代码可以调用 `signal()` 或 `sigaction()` 来注册信号处理程序。
   - 当 native 代码发生错误 (例如，访问无效内存)，系统会向进程发送相应的信号。

**详细步骤示例 (NDK):**

1. **NDK 应用调用 `signal()`:**  Native 代码调用 `signal(SIGUSR1, my_signal_handler)` 来注册一个处理 `SIGUSR1` 的函数 `my_signal_handler`。
2. **Bionic `signal()` 被调用:**  该调用会进入 `bionic/libc/bionic/signal.cpp` 中的 `signal` 函数。
3. **`signal()` 调用 `sigaction64()`:**  `signal()` 内部会构造 `sigaction64` 结构体并调用 `sigaction64()` 系统调用。
4. **内核处理 `sigaction64()`:**  Linux 内核会记录该进程对 `SIGUSR1` 的处理方式。
5. **发送信号:**  另一个进程或当前进程自身使用 `kill()` 系统调用发送 `SIGUSR1` 信号。
6. **内核传递信号:**  内核根据进程的信号屏蔽字和注册的处理程序，决定如何处理该信号。由于 `SIGUSR1` 的处理程序已注册，内核会将控制权转移到 `my_signal_handler` 函数。

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida Hook `signal` 函数的示例：

```javascript
// attach 到目标进程
const processName = "your_app_process_name";
const session = await frida.attach(processName);

// 加载脚本
const script = await session.createScript(`
    Interceptor.attach(Module.findExportByName("libc.so", "signal"), {
        onEnter: function (args) {
            const signum = args[0].toInt32();
            const handler = args[1];
            console.log(\`[signal Hook] Signal number: ${signum}, Handler: ${handler}\`);
            // 你可以在这里修改参数，例如替换信号处理程序
            // args[1] = ...;
        },
        onLeave: function (retval) {
            console.log(\`[signal Hook] Return value: ${retval}\`);
        }
    });
`);

await script.load();
```

**解释:**

1. **`frida.attach(processName)`:** 连接到目标 Android 进程。你需要将 `your_app_process_name` 替换为你的应用程序的进程名称。
2. **`Module.findExportByName("libc.so", "signal")`:**  在 `libc.so` 库中查找 `signal` 函数的地址。
3. **`Interceptor.attach(...)`:** 拦截对 `signal` 函数的调用。
4. **`onEnter`:**  在 `signal` 函数被调用之前执行。
   - `args[0]`：包含信号编号的参数。
   - `args[1]`：包含信号处理程序地址的参数。
   - 代码打印出信号编号和处理程序的地址。
5. **`onLeave`:** 在 `signal` 函数返回之后执行。
   - `retval`：包含 `signal` 函数的返回值。

**调试步骤:**

1. **安装 Frida:** 确保你的开发机器上安装了 Frida 和 Frida-server。
2. **启动 Frida-server:** 在你的 Android 设备上启动 Frida-server。
3. **运行目标应用:** 启动你想要调试的 Android 应用程序。
4. **运行 Frida 脚本:** 在你的开发机器上运行上面的 JavaScript Frida 脚本。
5. **观察输出:** 当应用程序调用 `signal` 函数时，Frida 会拦截调用并在控制台中打印出相关信息。

你可以使用类似的方法 Hook 其他信号处理相关的函数，例如 `sigaction`, `pthread_sigmask` 等，以观察其行为和参数。

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/signal.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/signal.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <platform/bionic/reserved_signals.h>

#include "private/ErrnoRestorer.h"
#include "private/SigSetConverter.h"

extern "C" int __rt_sigpending(const sigset64_t*, size_t);
extern "C" int __rt_sigqueueinfo(pid_t, int, siginfo_t*);
extern "C" int __rt_sigsuspend(const sigset64_t*, size_t);
extern "C" int __rt_sigtimedwait(const sigset64_t*, siginfo_t*, const timespec*, size_t);

int pthread_sigmask(int how, const sigset_t* new_set, sigset_t* old_set) {
  ErrnoRestorer errno_restorer;
  return (sigprocmask(how, new_set, old_set) == -1) ? errno : 0;
}

int pthread_sigmask64(int how, const sigset64_t* new_set, sigset64_t* old_set) {
  ErrnoRestorer errno_restorer;
  return (sigprocmask64(how, new_set, old_set) == -1) ? errno : 0;
}

template <typename SigSetT>
int SigAddSet(SigSetT* set, int sig) {
  int bit = sig - 1; // Signal numbers start at 1, but bit positions start at 0.
  unsigned long* local_set = reinterpret_cast<unsigned long*>(set);
  if (set == nullptr || bit < 0 || bit >= static_cast<int>(8*sizeof(*set))) {
    errno = EINVAL;
    return -1;
  }
  local_set[bit / LONG_BIT] |= 1UL << (bit % LONG_BIT);
  return 0;
}

int sigaddset(sigset_t* set, int sig) {
  return SigAddSet(set, sig);
}

int sigaddset64(sigset64_t* set, int sig) {
  return SigAddSet(set, sig);
}

union BsdSigSet {
  int mask;
  sigset64_t set;
};

// This isn't in our header files, but is exposed on all architectures except riscv64.
extern "C" int sigblock(int mask) {
  BsdSigSet in{.mask = mask}, out;
  if (sigprocmask64(SIG_BLOCK, &in.set, &out.set) == -1) return -1;
  return out.mask;
}

// This isn't in our header files, but is exposed on all architectures except riscv64.
extern "C" int sigsetmask(int mask) {
  BsdSigSet in{.mask = mask}, out;
  if (sigprocmask64(SIG_SETMASK, &in.set, &out.set) == -1) return -1;
  return out.mask;
}

template <typename SigSetT>
int SigDelSet(SigSetT* set, int sig) {
  int bit = sig - 1; // Signal numbers start at 1, but bit positions start at 0.
  unsigned long* local_set = reinterpret_cast<unsigned long*>(set);
  if (set == nullptr || bit < 0 || bit >= static_cast<int>(8*sizeof(*set))) {
    errno = EINVAL;
    return -1;
  }
  local_set[bit / LONG_BIT] &= ~(1UL << (bit % LONG_BIT));
  return 0;
}

int sigdelset(sigset_t* set, int sig) {
  return SigDelSet(set, sig);
}

int sigdelset64(sigset64_t* set, int sig) {
  return SigDelSet(set, sig);
}

template <typename SigSetT>
int SigEmptySet(SigSetT* set) {
  if (set == nullptr) {
    errno = EINVAL;
    return -1;
  }
  memset(set, 0, sizeof(*set));
  return 0;
}

int sigemptyset(sigset_t* set) {
  return SigEmptySet(set);
}

int sigemptyset64(sigset64_t* set) {
  return SigEmptySet(set);
}

template <typename SigSetT>
int SigFillSet(SigSetT* set) {
  if (set == nullptr) {
    errno = EINVAL;
    return -1;
  }
  memset(set, 0xff, sizeof(*set));
  return 0;
}

int sigfillset(sigset_t* set) {
  return SigFillSet(set);
}

int sigfillset64(sigset64_t* set) {
  return SigFillSet(set);
}

int sighold(int sig) {
  sigset64_t set = {};
  if (sigaddset64(&set, sig) == -1) return -1;
  return sigprocmask64(SIG_BLOCK, &set, nullptr);
}

int sigignore(int sig) {
  struct sigaction64 sa = { .sa_handler = SIG_IGN };
  return sigaction64(sig, &sa, nullptr);
}

int siginterrupt(int sig, int flag) {
  struct sigaction64 act;
  sigaction64(sig, nullptr, &act);
  if (flag) {
    act.sa_flags &= ~SA_RESTART;
  } else {
    act.sa_flags |= SA_RESTART;
  }
  return sigaction64(sig, &act, nullptr);
}

template <typename SigSetT>
int SigIsMember(const SigSetT* set, int sig) {
  int bit = sig - 1; // Signal numbers start at 1, but bit positions start at 0.
  const unsigned long* local_set = reinterpret_cast<const unsigned long*>(set);
  if (set == nullptr || bit < 0 || bit >= static_cast<int>(8*sizeof(*set))) {
    errno = EINVAL;
    return -1;
  }
  return static_cast<int>((local_set[bit / LONG_BIT] >> (bit % LONG_BIT)) & 1);
}

int sigismember(const sigset_t* set, int sig) {
  return SigIsMember(set, sig);
}

int sigismember64(const sigset64_t* set, int sig) {
  return SigIsMember(set, sig);
}

__LIBC_HIDDEN__ sighandler_t _signal(int sig, sighandler_t handler, int flags) {
  struct sigaction64 sa = { .sa_handler = handler, .sa_flags = flags };
  return (sigaction64(sig, &sa, &sa) == -1) ? SIG_ERR : sa.sa_handler;
}

sighandler_t signal(int sig, sighandler_t handler) {
  return _signal(sig, handler, SA_RESTART);
}

int sigpause(int sig) {
  sigset64_t set = {};
  if (sigprocmask64(SIG_SETMASK, nullptr, &set) == -1 || sigdelset64(&set, sig) == -1) return -1;
  return sigsuspend64(&set);
}

int sigpending(sigset_t* bionic_set) {
  SigSetConverter set{bionic_set};
  if (__rt_sigpending(set.ptr, sizeof(sigset64_t)) == -1) return -1;
  set.copy_out();
  return 0;
}

int sigpending64(sigset64_t* set) {
  return __rt_sigpending(set, sizeof(*set));
}

int sigqueue(pid_t pid, int sig, const sigval value) {
  siginfo_t info = { .si_code = SI_QUEUE };
  info.si_signo = sig;
  info.si_pid = getpid();
  info.si_uid = getuid();
  info.si_value = value;
  return __rt_sigqueueinfo(pid, sig, &info);
}

int sigrelse(int sig) {
  sigset64_t set = {};
  if (sigaddset64(&set, sig) == -1) return -1;
  return sigprocmask64(SIG_UNBLOCK, &set, nullptr);
}

sighandler_t sigset(int sig, sighandler_t disp) {
  struct sigaction64 new_sa;
  if (disp != SIG_HOLD) new_sa = { .sa_handler = disp };

  struct sigaction64 old_sa;
  if (sigaction64(sig, (disp == SIG_HOLD) ? nullptr : &new_sa, &old_sa) == -1) {
    return SIG_ERR;
  }

  sigset64_t new_mask = {};
  sigaddset64(&new_mask, sig);
  sigset64_t old_mask;
  if (sigprocmask64(disp == SIG_HOLD ? SIG_BLOCK : SIG_UNBLOCK, &new_mask, &old_mask) == -1) {
    return SIG_ERR;
  }

  return sigismember64(&old_mask, sig) ? SIG_HOLD : old_sa.sa_handler;
}

int sigsuspend(const sigset_t* bionic_set) {
  SigSetConverter set{bionic_set};
  return sigsuspend64(set.ptr);
}

int sigsuspend64(const sigset64_t* set) {
  sigset64_t mutable_set;
  sigset64_t* mutable_set_ptr = nullptr;
  if (set) {
    mutable_set = filter_reserved_signals(*set, SIG_SETMASK);
    mutable_set_ptr = &mutable_set;
  }
  return __rt_sigsuspend(mutable_set_ptr, sizeof(*set));
}

int sigtimedwait(const sigset_t* bionic_set, siginfo_t* info, const timespec* timeout) {
  SigSetConverter set{bionic_set};
  return sigtimedwait64(set.ptr, info, timeout);
}

int sigtimedwait64(const sigset64_t* set, siginfo_t* info, const timespec* timeout) {
  sigset64_t mutable_set;
  sigset64_t* mutable_set_ptr = nullptr;
  if (set) {
    mutable_set = filter_reserved_signals(*set, SIG_SETMASK);
    mutable_set_ptr = &mutable_set;
  }
  return __rt_sigtimedwait(mutable_set_ptr, info, timeout, sizeof(*set));
}

int sigwait(const sigset_t* bionic_set, int* sig) {
  SigSetConverter set{bionic_set};
  return sigwait64(set.ptr, sig);
}

int sigwait64(const sigset64_t* set, int* sig) {
  while (true) {
    // __rt_sigtimedwait can return EAGAIN or EINTR, we need to loop
    // around them since sigwait is only allowed to return EINVAL.
    int result = sigtimedwait64(set, nullptr, nullptr);
    if (result >= 0) {
      *sig = result;
      return 0;
    }
    if (errno != EAGAIN && errno != EINTR) return errno;
  }
}

int sigwaitinfo(const sigset_t* set, siginfo_t* info) {
  return sigtimedwait(set, info, nullptr);
}

int sigwaitinfo64(const sigset64_t* set, siginfo_t* info) {
  return sigtimedwait64(set, info, nullptr);
}

"""

```