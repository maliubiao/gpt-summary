Response:
My thought process for answering the request went through these stages:

1. **Understanding the Core Request:** The primary goal is to analyze the provided C++ source code (`threads_test.cpp`) from Android's Bionic library. The analysis needs to cover functionality, relationships to Android, libc function implementations, dynamic linker aspects, potential issues, and how to debug it.

2. **Initial Code Scan and High-Level Overview:** I quickly scanned the code to identify the major components and what it's doing. Keywords like `TEST`, `ASSERT_EQ`, `thrd_`, `mtx_`, `cnd_`, and `#if __has_include(<threads.h>)` stood out. This indicated it's a unit test file for thread-related functionalities defined in `<threads.h>`. The `#ifdef HAVE_THREADS_H` blocks suggested the tests are conditionally compiled based on the availability of the `<threads.h>` header.

3. **Categorizing Functionality:** I started grouping the tests based on the function names they test. This led to categories like:
    * `call_once`: Testing one-time initialization.
    * `cnd_*`: Testing condition variables (`cnd_broadcast`, `cnd_wait`, `cnd_signal`, `cnd_timedwait`).
    * `mtx_*`: Testing mutexes (`mtx_init`, `mtx_destroy`, `mtx_lock`, `mtx_trylock`, `mtx_timedlock`, `mtx_unlock`).
    * `thrd_*`: Testing thread management (`thrd_current`, `thrd_equal`, `thrd_create`, `thrd_detach`, `thrd_exit`, `thrd_join`, `thrd_sleep`, `thrd_yield`).
    * `tss_*`: Testing thread-specific storage (`tss_create`, `tss_delete`, `tss_get`, `tss_set`).

4. **Detailing Functionality:** For each category, I elaborated on what the tested functions are intended to do. I relied on my knowledge of standard C/C++ threading primitives and the `<threads.h>` standard. For example, I knew `cnd_wait` blocks a thread until a condition is signaled, and `mtx_lock` acquires a mutex.

5. **Connecting to Android:**  I considered how these threading primitives are fundamental to any multithreaded application on Android. I gave examples like UI rendering, background tasks, and inter-process communication where threads and synchronization are crucial. I also mentioned the NDK, which allows developers to use these functions directly in native code.

6. **Explaining Libc Functions:** For each libc function mentioned, I provided a brief explanation of its purpose. Since the request specifically asked *how* they are implemented, I noted that these are part of the Bionic library and are usually implemented as system calls or wrappers around system calls. I mentioned the underlying kernel mechanisms like futexes for synchronization. I intentionally kept this part somewhat high-level as a detailed implementation description would be extremely long and complex, requiring deep knowledge of the Bionic source.

7. **Addressing Dynamic Linking:**  I recognized that while the test file itself doesn't directly *use* dynamic linking, the functions it tests (`thrd_create`, `mtx_init`, etc.) are part of `libc.so`, a shared library. I explained the basic dynamic linking process: linking at compile time (references), loading at runtime (mapping into memory), and resolving symbols. I provided a simple hypothetical `libc.so` layout and explained symbol resolution.

8. **Identifying Potential Issues:** Based on my understanding of threading, I listed common pitfalls like deadlocks (caused by improper locking order), race conditions (due to unsynchronized access to shared data), and memory leaks (if `tss_set` overwrites pointers without freeing). I provided simple code examples to illustrate these issues.

9. **Illustrating Android Framework/NDK Path:** I outlined the general flow from an Android app (Java/Kotlin) to native code using JNI, highlighting how framework components eventually rely on Bionic's threading primitives. For NDK, the path is more direct, with native code directly calling Bionic functions.

10. **Providing Frida Hook Examples:** I devised Frida scripts to demonstrate how to intercept calls to key functions like `thrd_create` and `mtx_lock`. The scripts show how to print arguments and return values, allowing for runtime inspection.

11. **Structuring the Response:**  I organized the information into clear sections based on the request's points, using headings and bullet points for readability. I used Chinese throughout the response as requested.

12. **Refinement and Language:** I reviewed my answer for accuracy and clarity. I made sure the Chinese was natural and easy to understand. I avoided overly technical jargon where simpler terms would suffice.

Throughout this process, I focused on providing informative and practical answers to each part of the request. I balanced the need for detail with the risk of becoming too bogged down in implementation specifics (especially for libc and the dynamic linker, where a full explanation would be enormous). I prioritized conveying the essential concepts and their relevance to Android development.
好的，让我们深入分析一下 `bionic/tests/threads_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/threads_test.cpp` 是 Android Bionic 库中的一个测试文件。它的主要功能是**测试 Bionic 库中与线程相关的 API 的正确性**。  更具体地说，它使用 Google Test 框架（gtest）来编写了一系列单元测试，涵盖了 `<threads.h>` 头文件中定义的 C11 标准线程 API，以及一些相关的 POSIX 线程 API。

**与 Android 功能的关系及举例说明**

这个测试文件直接关系到 Android 系统的核心功能，因为 Bionic 库是 Android 的基础 C 库。 线程是现代操作系统中实现并发和并行执行的关键机制。Android 框架和应用程序广泛使用线程来执行各种任务，例如：

* **UI 渲染：** Android 的主线程负责处理用户界面事件和渲染。为了避免阻塞主线程，耗时的操作（如网络请求、文件读写）通常会在后台线程中执行。
* **后台服务：**  Android 系统服务（如蓝牙、Wi-Fi、定位服务）通常使用多个线程来处理不同的任务。
* **并发处理：**  应用程序可能需要同时处理多个请求或事件，这可以通过创建和管理多个线程来实现。
* **NDK 开发：** 使用 Android NDK 进行原生开发的应用程序可以直接使用 Bionic 提供的线程 API。

**举例说明：**

* 当一个 Android 应用发起一个网络请求时，通常会创建一个新的线程来执行网络操作，避免阻塞主线程导致应用无响应 (ANR)。这个新线程的创建和管理就可能涉及到 `thrd_create`、`thrd_join` 等 Bionic 提供的线程 API。
* Android 的 `AsyncTask` 类内部就使用了线程池来管理后台任务，而线程池的实现也离不开底层的线程创建和同步机制。
* 在 NDK 开发中，开发者可以直接调用 `pthread_create` (或者 `<threads.h>` 中的 `thrd_create`) 来创建原生线程。

**libc 函数的功能及实现**

这个测试文件中涉及了多个 `<threads.h>` 中定义的 C11 标准线程 API，它们在 Bionic 库中实现。  这些函数通常是对底层 POSIX 线程 API (pthread) 的封装，提供了更简洁和标准化的接口。

以下是每个涉及的 libc 函数的功能和简要实现说明：

1. **`call_once`**:
   * **功能:** 确保某个函数在多线程环境下只被调用一次。
   * **实现:** 通常使用一个原子标志和一个互斥锁来实现。第一次调用时，尝试获取锁并检查标志。如果标志未设置，则执行目标函数并设置标志。后续调用会直接跳过执行。Bionic 的实现可能利用 futex 等内核同步原语。

2. **`cnd_init` / `cnd_destroy`**:
   * **功能:** 初始化和销毁条件变量。
   * **实现:**  `cnd_init` 通常会分配条件变量所需的内存，并初始化相关的内部数据结构，例如关联的等待队列。 `cnd_destroy` 则释放这些资源。在 Bionic 中，这通常会调用底层的 `pthread_cond_init` 和 `pthread_cond_destroy`。

3. **`cnd_signal` / `cnd_broadcast`**:
   * **功能:**  `cnd_signal` 唤醒等待在条件变量上的一个线程。 `cnd_broadcast` 唤醒所有等待在条件变量上的线程。
   * **实现:**  这两个函数会将等待队列中的线程标记为可运行状态。 `cnd_signal` 通常只唤醒队列中的第一个线程，而 `cnd_broadcast` 则会唤醒所有线程。Bionic 的实现会调用 `pthread_cond_signal` 和 `pthread_cond_broadcast`。

4. **`cnd_wait`**:
   * **功能:**  使当前线程进入休眠状态，直到接收到来自同一个条件变量的信号。调用 `cnd_wait` 时必须先持有与条件变量关联的互斥锁，并在等待期间释放该锁，唤醒后重新获取锁。
   * **实现:**  `cnd_wait` 的实现非常关键。它会原子地释放互斥锁并将当前线程添加到条件变量的等待队列中，然后使线程进入阻塞状态。当收到信号时，线程会被唤醒并尝试重新获取互斥锁。Bionic 通常使用 `pthread_cond_wait` 实现，底层依赖 futex。

5. **`cnd_timedwait`**:
   * **功能:**  与 `cnd_wait` 类似，但允许指定一个超时时间。如果超时时间到达之前没有收到信号，函数将返回一个超时错误。
   * **实现:**  Bionic 的实现会调用 `pthread_cond_timedwait`，底层也使用 futex，但会结合时间信息进行判断。

6. **`mtx_init` / `mtx_destroy`**:
   * **功能:** 初始化和销毁互斥锁。
   * **实现:** `mtx_init` 分配互斥锁所需的内存，并根据传入的标志（如 `mtx_plain`、`mtx_recursive`、`mtx_timed`）初始化其类型和状态。 `mtx_destroy` 释放相关资源。 Bionic 会调用 `pthread_mutex_init` 和 `pthread_mutex_destroy`。

7. **`mtx_lock` / `mtx_trylock`**:
   * **功能:**  `mtx_lock` 阻塞当前线程，直到获取到互斥锁。 `mtx_trylock` 尝试获取互斥锁，如果锁已经被其他线程持有，则立即返回一个错误码，不会阻塞。
   * **实现:**  `mtx_lock` 通常会尝试原子地将互斥锁的状态设置为“已锁定”。如果锁已被持有，则将当前线程放入等待队列并使其休眠。 `mtx_trylock` 的实现类似，但不进行阻塞。 Bionic 使用 `pthread_mutex_lock` 和 `pthread_mutex_trylock`。

8. **`mtx_timedlock`**:
   * **功能:**  尝试在指定时间内获取互斥锁。如果超时时间到达仍未获取到锁，则返回超时错误。
   * **实现:**  Bionic 会调用 `pthread_mutex_timedlock`，底层依赖 futex 和时间信息。

9. **`mtx_unlock`**:
   * **功能:**  释放当前线程持有的互斥锁。
   * **实现:**  `mtx_unlock` 会原子地将互斥锁的状态设置为“未锁定”，并可能唤醒等待队列中的一个或多个线程。Bionic 调用 `pthread_mutex_unlock`。

10. **`thrd_current`**:
    * **功能:** 返回当前线程的标识符。
    * **实现:**  Bionic 会调用 `pthread_self()` 来获取 POSIX 线程 ID。

11. **`thrd_equal`**:
    * **功能:** 比较两个线程标识符是否相等。
    * **实现:**  Bionic 会直接比较两个 `pthread_t` 类型的值。

12. **`thrd_create`**:
    * **功能:** 创建一个新的线程并开始执行指定的函数。
    * **实现:** 这是线程创建的核心函数。Bionic 的 `thrd_create` 内部会调用 `pthread_create`，由内核负责创建新的执行上下文和调度线程。

13. **`thrd_detach`**:
    * **功能:** 将一个线程设置为 detached 状态。 detached 线程在其执行结束后会自动释放资源，无需其他线程显式调用 `thrd_join` 来回收。
    * **实现:** Bionic 调用 `pthread_detach`。

14. **`thrd_exit`**:
    * **功能:** 终止当前线程的执行。
    * **实现:** Bionic 调用 `pthread_exit`。 注意，在主线程调用 `thrd_exit` 会导致程序以 `EXIT_SUCCESS` 退出。

15. **`thrd_join`**:
    * **功能:**  阻塞调用线程，直到指定的线程执行结束。可以获取目标线程的返回值（如果提供了输出参数）。
    * **实现:**  Bionic 调用 `pthread_join`。

16. **`thrd_sleep`**:
    * **功能:** 使当前线程休眠指定的时间。可以选择接收剩余休眠时间。
    * **实现:** Bionic 会调用 `nanosleep`。

17. **`thrd_yield`**:
    * **功能:**  提示操作系统放弃当前线程的剩余时间片，让其他线程有机会运行。
    * **实现:** Bionic 调用 `sched_yield`。

18. **`tss_create` / `tss_delete`**:
    * **功能:**  `tss_create` 创建一个线程特定存储 (Thread-Specific Storage) 的键。 `tss_delete` 删除一个 TSS 键。
    * **实现:** Bionic 会调用 `pthread_key_create` 和 `pthread_key_delete`。

19. **`tss_get` / `tss_set`**:
    * **功能:**  `tss_get` 获取与当前线程和指定 TSS 键关联的值。 `tss_set` 设置与当前线程和指定 TSS 键关联的值。
    * **实现:**  Bionic 调用 `pthread_getspecific` 和 `pthread_setspecific`。

**涉及 dynamic linker 的功能**

这个测试文件本身并没有直接涉及到动态链接器的操作。 然而，它测试的这些线程 API 都是在 `libc.so` 这个共享库中实现的。 因此，当一个 Android 应用程序（包括这个测试程序）运行时，动态链接器负责加载 `libc.so` 并解析这些 API 的符号。

**so 布局样本：**

假设 `libc.so` 的部分布局如下（简化）：

```
LOAD           0x...000    0x...000    r-x      ...
LOAD           0x...800    0x...800    r--      ...
LOAD           0x...C00    0x...C00    rw-      ...

.text (代码段):
  0x...000:  <thrd_create 的机器码>
  0x...0A0:  <mtx_lock 的机器码>
  0x...140:  <cnd_wait 的机器码>
  ...

.rodata (只读数据段):
  0x...800:  <一些常量数据>
  ...

.data / .bss (可读写数据段):
  0x...C00:  <全局变量>
  ...

.dynamic (动态链接信息段):
  ...
  SYMBOL TABLE:
    thrd_create:  address=0x...000
    mtx_lock:     address=0x...0A0
    cnd_wait:     address=0x...140
    ...
  ...
```

**链接的处理过程：**

1. **编译时链接：** 当 `threads_test.cpp` 被编译成可执行文件时，编译器会记录下对 `thrd_create`、`mtx_lock` 等函数的引用。由于这些函数在 `libc.so` 中，链接器会在生成可执行文件时创建一个动态链接表，记录这些外部符号以及它们所在的共享库 (`libc.so`)。

2. **运行时链接：**
   * 当测试程序启动时，Android 的 `linker` (动态链接器，通常是 `/system/bin/linker64` 或 `linker`) 会被操作系统调用。
   * `linker` 首先加载可执行文件本身，并解析其头部信息，包括动态链接表。
   * `linker` 根据动态链接表找到需要的共享库 `libc.so`，并将其加载到内存中。
   * **符号解析 (Symbol Resolution):**  `linker` 遍历可执行文件中的未定义符号（例如 `thrd_create`），并在 `libc.so` 的符号表中查找对应的符号。
   * 一旦找到符号，`linker` 就将可执行文件中对该符号的引用重定向到 `libc.so` 中该符号的实际地址。 例如，对 `thrd_create` 的调用会被修改为跳转到 `libc.so` 中 `thrd_create` 函数的地址 (0x...000)。
   * 这个过程通常使用 **延迟绑定 (Lazy Binding)** 或 **立即绑定 (Immediate Binding)**。 Android 默认使用延迟绑定，这意味着符号解析通常在第一次调用该函数时才进行。

**逻辑推理 (假设输入与输出)**

测试文件中的逻辑主要是断言函数的返回值是否符合预期。例如：

* **假设输入:** `mtx_init(&m, mtx_plain)`
* **预期输出:** `thrd_success` (表示互斥锁初始化成功)

* **假设输入:**  在未持有锁的情况下调用 `mtx_trylock(&m)`，且锁被其他线程持有。
* **预期输出:** `thrd_busy` (表示尝试获取锁但失败)

* **假设输入:** 调用 `thrd_create` 创建一个线程，该线程执行的函数返回整数 `5`。然后调用 `thrd_join` 获取返回值。
* **预期输出:** `thrd_join` 返回 `thrd_success`，并且输出参数接收到值 `5`。

**用户或编程常见的使用错误**

* **死锁 (Deadlock):**  多个线程互相等待对方释放资源，导致所有线程都无法继续执行。
   ```c++
   // 线程 1
   mtx_lock(&mutex_a);
   mtx_lock(&mutex_b); // 如果线程 2 先锁定了 mutex_b，则会发生死锁
   // ...
   mtx_unlock(&mutex_b);
   mtx_unlock(&mutex_a);

   // 线程 2
   mtx_lock(&mutex_b);
   mtx_lock(&mutex_a); // 如果线程 1 先锁定了 mutex_a，则会发生死锁
   // ...
   mtx_unlock(&mutex_a);
   mtx_unlock(&mutex_b);
   ```
* **竞态条件 (Race Condition):** 程序的行为取决于多个线程执行的相对顺序，可能导致不可预测的结果。
   ```c++
   int counter = 0;

   // 线程 1
   void increment() {
     for (int i = 0; i < 100000; ++i) {
       counter++; // 非原子操作，可能发生竞态
     }
   }

   // 线程 2 也调用 increment()
   ```
* **忘记解锁互斥锁:** 导致其他线程永久阻塞。
   ```c++
   mtx_lock(&m);
   // ... 做一些操作，但忘记调用 mtx_unlock(&m);
   ```
* **在未初始化的互斥锁或条件变量上操作:** 导致未定义的行为甚至程序崩溃。
   ```c++
   mtx_t m; // 未初始化
   mtx_lock(&m); // 错误！
   ```
* **错误地使用条件变量:** 例如，在 `cnd_wait` 之前没有持有相关的互斥锁，或者在条件不满足时没有在循环中调用 `cnd_wait`。
* **内存泄漏与 TSS:** 如果 `tss_set` 设置了一个指向动态分配内存的指针，但在线程退出或键被删除时没有释放该内存，则会发生内存泄漏。测试代码中通过 `tss_dtor` 演示了如何使用析构函数来清理 TSS 关联的内存。

**Android Framework 或 NDK 如何到达这里**

**Android Framework 到 Bionic:**

1. **Java/Kotlin 代码:** Android 应用程序的界面和大部分逻辑是用 Java 或 Kotlin 编写的。
2. **Android Runtime (ART):** ART 是 Android 的运行时环境，负责执行 Java/Kotlin 代码。
3. **Native 代码调用 (JNI):**  Android Framework 中许多底层功能，或者需要高性能的操作，会使用 C/C++ 编写并通过 JNI (Java Native Interface) 被 Java/Kotlin 代码调用。例如，图形渲染、音频处理、某些系统服务等。
4. **Framework Native Libraries:**  Framework 中包含一些用 C/C++ 编写的本地库（例如 `libandroid_runtime.so`，`libbinder.so`）。这些库会调用 Bionic 提供的 API。
5. **Bionic 库 (`libc.so`, `libm.so`, `libdl.so` 等):**  这些是 Android 的核心 C 库。Framework 的本地库最终会调用 Bionic 提供的线程、内存管理、IO 等基础功能。

**Android NDK 到 Bionic:**

1. **NDK C/C++ 代码:**  使用 NDK 开发的应用程序可以直接编写 C/C++ 代码。
2. **NDK 标准库:** NDK 提供了一套兼容的 C/C++ 标准库实现，这其中就包括了 Bionic 的 `<threads.h>` 和 POSIX 线程 API。
3. **直接调用 Bionic API:** NDK 代码可以直接调用 Bionic 提供的函数，例如 `thrd_create`、`mtx_lock` 等。
4. **编译链接:** NDK 编译工具链会将 NDK 代码编译成共享库 (`.so` 文件)，并链接到 Bionic 库。

**Frida Hook 示例调试步骤**

以下是一个使用 Frida Hook 调试 `thrd_create` 和 `mtx_lock` 的示例：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found.")
    sys.exit(1)

script_source = """
Interceptor.attach(Module.findExportByName("libc.so", "thrd_create"), {
    onEnter: function(args) {
        console.log("[*] thrd_create called");
        console.log("    Thread function:", args[1]);
        console.log("    Argument:", args[2]);
        this.thread_func = args[1];
    },
    onLeave: function(retval) {
        console.log("[*] thrd_create returned:", retval);
        if (retval == 0) {
            console.log("    Thread creation failed.");
        } else {
            console.log("    New thread ID:", retval);
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "mtx_lock"), {
    onEnter: function(args) {
        console.log("[*] mtx_lock called");
        console.log("    Mutex address:", args[0]);
        // 可以尝试读取 mutex 的状态
    },
    onLeave: function(retval) {
        console.log("[*] mtx_lock returned:", retval);
        if (retval == 0) {
            console.log("    Mutex locked successfully.");
        } else {
            console.log("    Failed to lock mutex.");
        }
    }
});
"""

script = session.create_script(script_source)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤：**

1. **安装 Frida 和 frida-tools:**  确保你的电脑上安装了 Frida 和 `frida-tools`。
2. **找到目标应用包名:**  替换脚本中的 `"你的应用包名"` 为你要调试的 Android 应用的包名。
3. **连接 Android 设备:** 确保你的 Android 设备通过 USB 连接到电脑，并且启用了 USB 调试。
4. **运行 Frida 脚本:** 运行上面的 Python 脚本。
5. **操作目标应用:**  在你的 Android 设备上操作目标应用，触发线程创建和互斥锁操作。
6. **查看 Frida 输出:**  Frida 会拦截对 `thrd_create` 和 `mtx_lock` 的调用，并在终端输出相关信息，例如函数参数、返回值等。

**更进一步的调试:**

* **Hook 其他函数:**  你可以添加更多 `Interceptor.attach` 来 Hook 其他线程相关的函数，例如 `pthread_create`、`pthread_mutex_lock` 等。
* **查看内存:**  在 `onEnter` 中，你可以使用 `Memory.read*` 函数来读取内存中的数据，例如查看互斥锁的状态。
* **修改参数或返回值:**  Frida 允许你在 `onEnter` 或 `onLeave` 中修改函数的参数或返回值，这可以用于测试不同的场景或绕过某些逻辑。
* **使用 Stalker:**  Frida 的 Stalker 模块可以用来跟踪线程的执行路径，帮助你理解代码的执行流程。

希望以上详细的分析能够帮助你理解 `bionic/tests/threads_test.cpp` 文件的功能和它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/threads_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#if __has_include(<threads.h>)

#define HAVE_THREADS_H
#include <threads.h>

static int g_call_once_call_count;

static void increment_call_count() {
  ++g_call_once_call_count;
}

static int g_dtor_call_count;

static void tss_dtor(void* ptr) {
  ++g_dtor_call_count;
  free(ptr);
}

static int return_arg(void* arg) {
  return static_cast<int>(reinterpret_cast<uintptr_t>(arg));
}

static int exit_arg(void* arg) {
  thrd_exit(static_cast<int>(reinterpret_cast<uintptr_t>(arg)));
}

#endif

#include <time.h>

#include <thread>

#include <android-base/silent_death_test.h>

#include "SignalUtils.h"

TEST(threads, call_once) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  once_flag flag = ONCE_FLAG_INIT;
  call_once(&flag, increment_call_count);
  call_once(&flag, increment_call_count);
  std::thread([&flag] {
    call_once(&flag, increment_call_count);
  }).join();
  ASSERT_EQ(1, g_call_once_call_count);
#endif
}

TEST(threads, cnd_broadcast__cnd_wait) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_plain));

  cnd_t c;
  ASSERT_EQ(thrd_success, cnd_init(&c));

  std::atomic_int i = 0;

  auto waiter = [&c, &i, &m] {
    ASSERT_EQ(thrd_success, mtx_lock(&m));
    while (i != 1) ASSERT_EQ(thrd_success, cnd_wait(&c, &m));
    ASSERT_EQ(thrd_success, mtx_unlock(&m));
  };
  std::thread t1(waiter);
  std::thread t2(waiter);
  std::thread t3(waiter);

  ASSERT_EQ(thrd_success, mtx_lock(&m));
  i = 1;
  ASSERT_EQ(thrd_success, mtx_unlock(&m));

  ASSERT_EQ(thrd_success, cnd_broadcast(&c));

  t1.join();
  t2.join();
  t3.join();

  mtx_destroy(&m);
  cnd_destroy(&c);
#endif
}

TEST(threads, cnd_init__cnd_destroy) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  cnd_t c;
  ASSERT_EQ(thrd_success, cnd_init(&c));
  cnd_destroy(&c);
#endif
}

TEST(threads, cnd_signal__cnd_wait) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_plain));
  cnd_t c;
  ASSERT_EQ(thrd_success, cnd_init(&c));

  std::atomic_int count = 0;
  auto waiter = [&c, &m, &count] {
    ASSERT_EQ(thrd_success, mtx_lock(&m));
    ASSERT_EQ(thrd_success, cnd_wait(&c, &m));
    ASSERT_EQ(thrd_success, mtx_unlock(&m));
    ++count;
  };
  std::thread t1(waiter);
  std::thread t2(waiter);
  std::thread t3(waiter);

  // This is inherently racy, but attempts to distinguish between cnd_signal and
  // cnd_broadcast.
  usleep(100000);
  ASSERT_EQ(thrd_success, cnd_signal(&c));
  while (count == 0) {
  }
  usleep(100000);
  ASSERT_EQ(1, count);

  ASSERT_EQ(thrd_success, cnd_signal(&c));
  while (count == 1) {
  }
  usleep(100000);
  ASSERT_EQ(2, count);

  ASSERT_EQ(thrd_success, cnd_signal(&c));
  while (count == 2) {
  }
  usleep(100000);
  ASSERT_EQ(3, count);

  t1.join();
  t2.join();
  t3.join();

  mtx_destroy(&m);
  cnd_destroy(&c);
#endif
}

TEST(threads, cnd_timedwait_timedout) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_timed));
  ASSERT_EQ(thrd_success, mtx_lock(&m));

  cnd_t c;
  ASSERT_EQ(thrd_success, cnd_init(&c));

  timespec ts = {};
  ASSERT_EQ(thrd_timedout, cnd_timedwait(&c, &m, &ts));
#endif
}

TEST(threads, cnd_timedwait) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_timed));

  cnd_t c;
  ASSERT_EQ(thrd_success, cnd_init(&c));

  std::atomic_bool done = false;
  std::thread t([&c, &m, &done] {
    ASSERT_EQ(thrd_success, mtx_lock(&m));

    // cnd_timewait's time is *absolute*.
    timespec ts;
    ASSERT_EQ(TIME_UTC, timespec_get(&ts, TIME_UTC));
    ts.tv_sec += 666;

    ASSERT_EQ(thrd_success, cnd_timedwait(&c, &m, &ts));
    done = true;
    ASSERT_EQ(thrd_success, mtx_unlock(&m));
  });

  while (!done) ASSERT_EQ(thrd_success, cnd_signal(&c));

  t.join();
#endif
}

TEST(threads, mtx_init) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_plain));
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_timed));
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_plain | mtx_recursive));
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_timed | mtx_recursive));
  ASSERT_EQ(thrd_error, mtx_init(&m, 123));
  ASSERT_EQ(thrd_error, mtx_init(&m, mtx_recursive));
#endif
}

TEST(threads, mtx_destroy) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_plain));
  mtx_destroy(&m);
#endif
}

TEST(threads, mtx_lock_plain) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_plain));

  ASSERT_EQ(thrd_success, mtx_lock(&m));
  ASSERT_EQ(thrd_busy, mtx_trylock(&m));
  ASSERT_EQ(thrd_success, mtx_unlock(&m));

  mtx_destroy(&m);
#endif
}

TEST(threads, mtx_lock_recursive) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_plain | mtx_recursive));

  ASSERT_EQ(thrd_success, mtx_lock(&m));
  ASSERT_EQ(thrd_success, mtx_trylock(&m));
  ASSERT_EQ(thrd_success, mtx_unlock(&m));
  ASSERT_EQ(thrd_success, mtx_unlock(&m));

  mtx_destroy(&m);
#endif
}

TEST(threads, mtx_timedlock) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_timed));

  timespec ts = {};
  ASSERT_EQ(thrd_success, mtx_timedlock(&m, &ts));

  std::thread([&m] {
    timespec ts = { .tv_nsec = 500000 };
    ASSERT_EQ(thrd_timedout, mtx_timedlock(&m, &ts));
  }).join();

  ASSERT_EQ(thrd_success, mtx_unlock(&m));
  mtx_destroy(&m);
#endif
}


TEST(threads, mtx_unlock) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  mtx_t m;
  ASSERT_EQ(thrd_success, mtx_init(&m, mtx_plain));
  ASSERT_EQ(thrd_success, mtx_lock(&m));
  std::thread([&m] {
    ASSERT_EQ(thrd_busy, mtx_trylock(&m));
  }).join();
  ASSERT_EQ(thrd_success, mtx_unlock(&m));
  std::thread([&m] {
    ASSERT_EQ(thrd_success, mtx_trylock(&m));
  }).join();
#endif
}

TEST(threads, thrd_current__thrd_equal) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  thrd_t t1 = thrd_current();
  // (As a side-effect, this demonstrates interoperability with std::thread.)
  std::thread([&t1] {
    thrd_t t2 = thrd_current();
    ASSERT_FALSE(thrd_equal(t1, t2));
    thrd_t t2_2 = thrd_current();
    ASSERT_TRUE(thrd_equal(t2, t2_2));
  }).join();
  thrd_t t1_2 = thrd_current();
  ASSERT_TRUE(thrd_equal(t1, t1_2));
#endif
}

TEST(threads, thrd_create__thrd_detach) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  thrd_t t;
  ASSERT_EQ(thrd_success, thrd_create(&t, exit_arg, reinterpret_cast<void*>(1)));
  ASSERT_EQ(thrd_success, thrd_detach(t));
#endif
}

TEST(threads, thrd_create__thrd_exit) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  // Similar to the thrd_join test, but with a function that calls thrd_exit
  // instead.
  thrd_t t;
  int result;
  ASSERT_EQ(thrd_success, thrd_create(&t, exit_arg, reinterpret_cast<void*>(1)));
  ASSERT_EQ(thrd_success, thrd_join(t, &result));
  ASSERT_EQ(1, result);

  ASSERT_EQ(thrd_success, thrd_create(&t, exit_arg, reinterpret_cast<void*>(2)));
  ASSERT_EQ(thrd_success, thrd_join(t, &result));
  ASSERT_EQ(2, result);

  // The `result` argument can be null if you don't care...
  ASSERT_EQ(thrd_success, thrd_create(&t, exit_arg, reinterpret_cast<void*>(3)));
  ASSERT_EQ(thrd_success, thrd_join(t, nullptr));
#endif
}

using threads_DeathTest = SilentDeathTest;

TEST(threads_DeathTest, thrd_exit_main_thread) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  // "The program terminates normally after the last thread has been terminated.
  // The behavior is as if the program called the exit function with the status
  // EXIT_SUCCESS at thread termination time." (ISO/IEC 9899:2018)
  ASSERT_EXIT(thrd_exit(12), ::testing::ExitedWithCode(EXIT_SUCCESS), "");
#endif
}

TEST(threads, thrd_create__thrd_join) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  // Similar to the thrd_exit test, but with a function that calls return
  // instead.
  thrd_t t;
  int result;
  ASSERT_EQ(thrd_success, thrd_create(&t, return_arg, reinterpret_cast<void*>(1)));
  ASSERT_EQ(thrd_success, thrd_join(t, &result));
  ASSERT_EQ(1, result);

  ASSERT_EQ(thrd_success, thrd_create(&t, return_arg, reinterpret_cast<void*>(2)));
  ASSERT_EQ(thrd_success, thrd_join(t, &result));
  ASSERT_EQ(2, result);

  // The `result` argument can be null if you don't care...
  ASSERT_EQ(thrd_success, thrd_create(&t, return_arg, reinterpret_cast<void*>(3)));
  ASSERT_EQ(thrd_success, thrd_join(t, nullptr));
#endif
}

TEST(threads, thrd_sleep_signal) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  ScopedSignalHandler ssh{SIGALRM, [](int) {}};
  std::thread t([] {
    timespec long_time = { .tv_sec = 666 };
    timespec remaining = {};
    ASSERT_EQ(-1, thrd_sleep(&long_time, &remaining));
    uint64_t t = remaining.tv_sec * 1000000000 + remaining.tv_nsec;
    ASSERT_LE(t, 666ULL * 1000000000);
  });
  usleep(100000); // 0.1s
  pthread_kill(t.native_handle(), SIGALRM);
  t.join();
#endif
}

TEST(threads, thrd_sleep_signal_nullptr) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  ScopedSignalHandler ssh{SIGALRM, [](int) {}};
  std::thread t([] {
    timespec long_time = { .tv_sec = 666 };
    ASSERT_EQ(-1, thrd_sleep(&long_time, nullptr));
  });
  usleep(100000); // 0.1s
  pthread_kill(t.native_handle(), SIGALRM);
  t.join();
#endif
}

TEST(threads, thrd_sleep_error) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  timespec invalid = { .tv_sec = -1 };
  ASSERT_EQ(-2, thrd_sleep(&invalid, nullptr));
#endif
}

TEST(threads, thrd_yield) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  thrd_yield();
#endif
}

TEST(threads, TSS_DTOR_ITERATIONS_macro) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  ASSERT_EQ(PTHREAD_DESTRUCTOR_ITERATIONS, TSS_DTOR_ITERATIONS);
#endif
}

TEST(threads, tss_create) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  tss_t key;
  ASSERT_EQ(thrd_success, tss_create(&key, nullptr));
  tss_delete(key);
#endif
}

TEST(threads, tss_create_dtor) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  tss_dtor_t dtor = tss_dtor;
  tss_t key;
  ASSERT_EQ(thrd_success, tss_create(&key, dtor));

  ASSERT_EQ(thrd_success, tss_set(key, strdup("hello")));
  std::thread([&key] {
    ASSERT_EQ(thrd_success, tss_set(key, strdup("world")));
  }).join();
  // Thread exit calls the destructor...
  ASSERT_EQ(1, g_dtor_call_count);

  // "[A call to tss_set] will not invoke the destructor associated with the
  // key on the value being replaced" (ISO/IEC 9899:2018).
  g_dtor_call_count = 0;
  ASSERT_EQ(thrd_success, tss_set(key, strdup("hello")));
  ASSERT_EQ(0, g_dtor_call_count);

  // "Calling tss_delete will not result in the invocation of any
  // destructors" (ISO/IEC 9899:2018).
  // The destructor for "hello" won't be called until *this* thread exits.
  g_dtor_call_count = 0;
  tss_delete(key);
  ASSERT_EQ(0, g_dtor_call_count);
#endif
}

TEST(threads, tss_get__tss_set) {
#if !defined(HAVE_THREADS_H)
  GTEST_SKIP() << "<threads.h> unavailable";
#else
  tss_t key;
  ASSERT_EQ(thrd_success, tss_create(&key, nullptr));

  ASSERT_EQ(thrd_success, tss_set(key, const_cast<char*>("hello")));
  ASSERT_STREQ("hello", reinterpret_cast<char*>(tss_get(key)));
  std::thread([&key] {
      ASSERT_EQ(nullptr, tss_get(key));
      ASSERT_EQ(thrd_success, tss_set(key, const_cast<char*>("world")));
      ASSERT_STREQ("world", reinterpret_cast<char*>(tss_get(key)));
  }).join();
  ASSERT_STREQ("hello", reinterpret_cast<char*>(tss_get(key)));

  tss_delete(key);
#endif
}

"""

```