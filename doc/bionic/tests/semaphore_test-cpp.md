Response:
Let's break down the thought process to generate the detailed response for the `semaphore_test.cpp` file.

**1. Understanding the Request:**

The core request is to analyze a C++ source file (`semaphore_test.cpp`) within the Android Bionic library and explain its functionality, connections to Android, implementation details of libc functions, dynamic linking aspects, usage errors, and debugging methods.

**2. Initial File Scan and Purpose Identification:**

The first step is to quickly read through the code. Keywords like `TEST`, `ASSERT_EQ`, `sem_init`, `sem_wait`, `sem_post`, `sem_trywait`, `sem_timedwait`, `sem_getvalue`, and `#include <semaphore.h>` immediately signal that this is a test suite for semaphore functionality. The inclusion of `gtest/gtest.h` confirms this is a Google Test based unit test.

**3. Categorizing the Tests:**

Next, I mentally (or literally) group the tests by the semaphore function they target:

* `sem_init`: Tests initialization with valid and invalid values.
* `sem_trywait`: Tests the non-blocking decrement operation.
* `sem_wait` and `sem_post`: Tests the basic blocking decrement and increment operations, including inter-thread synchronization.
* `sem_timedwait`, `sem_timedwait_monotonic_np`, `sem_clockwait`: Tests the timed blocking decrement with different clock sources.
* `sem_getvalue`: Tests retrieving the current semaphore value.
* Tests related to signal interruption (`sem_wait_no_EINTR_in_sdk_less_equal_than_23`, `sem_wait_EINTR_in_sdk_greater_than_23`): Tests behavior regarding `EINTR` in `sem_wait` based on the target SDK version.
* Death Test (`sem_timedwait_null_timeout`): Tests how the program reacts to invalid input (null pointer).

**4. Addressing Each Part of the Request:**

Now I go through the request point by point, using my understanding of the code.

* **Functionality:**  This is straightforward. I list the semaphore functions being tested.

* **Relationship to Android:** Semaphores are fundamental synchronization primitives used throughout Android. I need to provide concrete examples. Thinking about Android's architecture leads to examples like managing concurrent access to shared resources (like hardware or data structures), inter-process communication (though semaphores aren't the *primary* IPC mechanism, they can be part of it), and thread pool management.

* **libc Function Implementation:** This requires deeper knowledge of how semaphores are typically implemented in a POSIX-like system. The key idea is that `sem_t` is a structure containing a counter and a waiting queue. `sem_init` initializes this structure. `sem_post` increments the counter and wakes up a waiting thread (if any). `sem_wait` decrements the counter if positive, otherwise, the thread is put to sleep in the waiting queue. `sem_trywait` is non-blocking. `sem_timedwait` adds a timeout. `sem_getvalue` simply reads the counter. I mention the underlying system calls (like `futex`) that are often used for efficiency.

* **Dynamic Linker:**  This requires understanding how libraries are loaded and linked. I need to:
    * Provide a sample SO layout showing where the semaphore functions would reside (typically in `libc.so`).
    * Explain the linking process: the executable needing `libm.so`, the linker resolving symbols, and the PLT/GOT mechanism for lazy binding.

* **Logical Reasoning (Assumptions and Outputs):**  For the signal interruption tests, I need to explain the *why*. Older Android versions masked signals in `sem_wait` to avoid unexpected behavior. Newer versions allow `EINTR`. I explain the assumed input (signal arrival during `sem_wait`) and the expected output (return value and `errno`).

* **Common Usage Errors:**  Based on the tests and general semaphore knowledge, I list common mistakes like incorrect initialization, deadlocks, race conditions, and forgetting to destroy semaphores. Providing simple code examples makes these clearer.

* **Android Framework/NDK Path:** This requires knowing how an Android app (using the NDK) ends up calling these Bionic functions. I trace the path: NDK API usage (e.g., `pthread_mutex_lock`), the NDK shim library, and finally the Bionic implementation.

* **Frida Hooking:**  This is about demonstrating runtime inspection. I provide Frida snippets for hooking `sem_wait` and `sem_post`, showing how to intercept calls, log arguments, and potentially modify behavior.

**5. Structuring and Refining the Response:**

Finally, I organize the information logically, using headings and bullet points for readability. I ensure the language is clear and accurate. I review for any inconsistencies or missing information. I make sure to answer *all* parts of the original request.

Essentially, the process combines code understanding, knowledge of operating system concepts (threading, synchronization, dynamic linking), Android architecture, and debugging techniques. The key is to break down the complex request into smaller, manageable parts and address each one systematically.
好的，让我们详细分析一下 `bionic/tests/semaphore_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/semaphore_test.cpp` 是 Android Bionic 库中用于测试信号量 (semaphore) 功能的单元测试文件。它使用 Google Test 框架来验证 Bionic 提供的信号量相关 API 的正确性。

**详细功能列举**

该文件主要测试了以下信号量相关的函数：

* **`sem_init()`**: 初始化信号量。
* **`sem_destroy()`**: 销毁信号量。
* **`sem_trywait()`**: 尝试获取信号量，如果信号量的值为零，则立即返回错误。
* **`sem_wait()`**: 获取信号量，如果信号量的值为零，则阻塞当前线程直到信号量的值大于零。
* **`sem_post()`**: 释放信号量，将信号量的值加一，并唤醒等待该信号量的线程（如果存在）。
* **`sem_timedwait()`**: 在指定时间内尝试获取信号量，如果超时仍未获取到，则返回错误。
* **`sem_getvalue()`**: 获取当前信号量的值。
* **`sem_clockwait()` (Bionic 特有)**: 类似于 `sem_timedwait()`，但允许指定时钟源。
* **`sem_timedwait_monotonic_np()` (Bionic 特有)**:  使用 `CLOCK_MONOTONIC` 时钟源的 `sem_timedwait()` 版本。

**与 Android 功能的关系及举例说明**

信号量是并发编程中非常重要的同步机制，在 Android 系统中被广泛使用，用于控制对共享资源的访问，避免竞争条件和死锁等问题。以下是一些例子：

* **进程间同步 (Inter-Process Communication - IPC)**: 虽然 Android 主要使用 Binder 进行进程间通信，但在某些低级场景或特定需求下，共享内存结合信号量可以实现进程间的同步。例如，一个服务进程可以使用信号量来控制多个客户端进程对共享内存区域的并发访问，确保数据的一致性。

* **线程同步**:  在单个进程内部，多个线程可能需要访问共享资源。信号量可以用来限制同时访问该资源的线程数量，例如，限制同时访问数据库连接池的线程数量，避免资源耗尽。

* **资源计数**:  信号量可以用来追踪可用资源的数量。例如，一个下载管理器可以使用信号量来限制同时进行的下载任务数量。

* **Framework 层的锁**: Android Framework 的某些部分内部也可能使用基于 POSIX 线程库提供的同步原语（包括信号量）来实现更高级别的锁机制。

**libc 函数的实现解释**

以下是该测试文件中涉及的 libc 函数的功能和可能的实现方式：

* **`sem_init(sem_t *sem, int pshared, unsigned int value)`**:
    * **功能**: 初始化一个信号量。`pshared` 指示信号量是否在进程间共享（0 表示线程间共享，非零表示进程间共享）。`value` 是信号量的初始值，必须是非负数且不大于 `SEM_VALUE_MAX`。
    * **实现**:
        * **线程间共享 (pshared == 0)**:  在 Bionic 中，线程间共享的信号量通常会使用进程内的共享内存区域来存储信号量的状态（计数器和等待队列）。可以使用互斥锁 (mutex) 和条件变量 (condition variable) 来实现 `sem_wait` 和 `sem_post` 的阻塞和唤醒机制。
        * **进程间共享 (pshared != 0)**:  进程间共享的信号量通常会使用内核对象来实现，例如 Linux 中的 `futex` 系统调用。`sem_init` 可能会分配一个内核信号量对象，并将句柄存储在 `sem_t` 中。

* **`sem_destroy(sem_t *sem)`**:
    * **功能**: 销毁一个信号量，释放其占用的资源。
    * **实现**:
        * 如果是线程间共享的信号量，则可能需要释放相关的内存。
        * 如果是进程间共享的信号量，则需要调用相应的内核 API 来释放内核对象。如果还有其他进程正在使用该信号量，`sem_destroy` 可能会失败并返回错误。

* **`sem_trywait(sem_t *sem)`**:
    * **功能**: 尝试原子地将信号量的值减 1。如果减 1 后值大于等于 0，则成功返回 0。如果当前信号量的值为 0，则立即返回 -1 并设置 `errno` 为 `EAGAIN`，不会阻塞。
    * **实现**:  通常使用原子操作（例如 compare-and-swap 或 fetch-and-decrement）来安全地减少信号量的值。如果当前值为 0，则直接返回。

* **`sem_wait(sem_t *sem)`**:
    * **功能**: 原子地将信号量的值减 1。如果减 1 后值大于等于 0，则立即返回 0。如果当前信号量的值为 0，则阻塞当前线程，直到其他线程调用 `sem_post` 增加信号量的值，并唤醒当前线程。
    * **实现**:
        * 使用原子操作尝试减少信号量的值。
        * 如果减值后小于 0，则将当前线程加入到信号量的等待队列中。
        * 线程进入睡眠状态，等待被 `sem_post` 唤醒。
        * 唤醒后，重新尝试获取信号量。

* **`sem_post(sem_t *sem)`**:
    * **功能**: 原子地将信号量的值加 1。如果加 1 后信号量的值变为正数，并且有线程在等待该信号量，则唤醒其中一个等待的线程。
    * **实现**:
        * 使用原子操作增加信号量的值。
        * 如果加值后大于 0 且等待队列不为空，则从等待队列中取出一个线程并唤醒它。

* **`sem_timedwait(sem_t *sem, const struct timespec *abs_timeout)`**:
    * **功能**: 类似于 `sem_wait`，但在指定的时间限制内等待信号量变为可用。`abs_timeout` 指定了绝对超时时间。
    * **实现**:  与 `sem_wait` 类似，但当需要阻塞时，会设置一个定时器。如果在定时器到期之前信号量没有变为可用，则返回 -1 并设置 `errno` 为 `ETIMEDOUT`。

* **`sem_getvalue(sem_t *sem, int *sval)`**:
    * **功能**: 获取信号量的当前值，并将结果存储在 `sval` 指向的内存中。
    * **实现**:  通常只需要读取信号量内部的计数器即可。需要注意的是，由于并发的存在，读取到的值可能在返回后就发生了变化。

* **`sem_clockwait(sem_t *sem, clockid_t clockid, const struct timespec *abs_timeout)` (Bionic 特有)**:
    * **功能**:  类似于 `sem_timedwait`，但允许指定用于计算超时的时钟源，例如 `CLOCK_MONOTONIC` 或 `CLOCK_REALTIME`。
    * **实现**:  与 `sem_timedwait` 类似，但使用指定的时钟源来计算超时时间。

* **`sem_timedwait_monotonic_np(sem_t *sem, const struct timespec *abs_timeout)` (Bionic 特有)**:
    * **功能**:  `sem_clockwait` 的一个特定版本，强制使用 `CLOCK_MONOTONIC` 时钟源。`_np` 后缀通常表示非 POSIX 标准的扩展。
    * **实现**:  内部实现等同于 `sem_clockwait(sem, CLOCK_MONOTONIC, abs_timeout)`。

**涉及 dynamic linker 的功能**

该测试文件本身并没有直接涉及 dynamic linker 的复杂功能，它主要测试的是已经链接到进程中的 `libc.so` 提供的信号量 API。然而，理解这些 API 如何被加载和链接是重要的。

**so 布局样本**

假设我们的应用程序使用了信号量，`libc.so` 中与信号量相关的部分布局可能如下（简化表示）：

```
libc.so:
    ...
    [DATA SECTION]
        ...
    [TEXT SECTION]
        sem_init:           ; 信号量初始化函数的代码
            ...
        sem_destroy:        ; 信号量销毁函数的代码
            ...
        sem_trywait:        ; 尝试获取信号量函数的代码
            ...
        sem_wait:           ; 获取信号量函数的代码
            ...
        sem_post:           ; 释放信号量函数的代码
            ...
        sem_timedwait:      ; 定时获取信号量函数的代码
            ...
        sem_getvalue:       ; 获取信号量值的代码
            ...
        sem_clockwait:      ; (Bionic 特有) 定时获取信号量函数的代码
            ...
        sem_timedwait_monotonic_np: ; (Bionic 特有) 定时获取信号量函数的代码
            ...
    [DYNAMIC SYMBOL TABLE]
        sem_init
        sem_destroy
        sem_trywait
        sem_wait
        sem_post
        sem_timedwait
        sem_getvalue
        sem_clockwait
        sem_timedwait_monotonic_np
        ...
```

**链接的处理过程**

1. **编译阶段**: 当我们编译包含信号量操作的代码时，编译器会识别出对 `sem_init`、`sem_wait` 等函数的调用。

2. **链接阶段**:
   * **静态链接 (通常不用于 libc)**: 如果是静态链接，`libc.a`（`libc.so` 的静态库版本）中的相关代码会被直接复制到最终的可执行文件中。
   * **动态链接 (Android 使用)**:  Android 默认使用动态链接。链接器在链接时，不会将 `libc.so` 的代码复制到我们的可执行文件中，而是在可执行文件中创建一个 **动态链接表 (Dynamic Linking Table)** 和 **全局偏移表 (Global Offset Table - GOT)** 以及 **过程链接表 (Procedure Linkage Table - PLT)**。
   * **PLT 条目**: 对于我们调用的每个外部函数（如 `sem_init`），链接器会在 PLT 中创建一个条目。
   * **GOT 条目**:  每个 PLT 条目都关联着 GOT 中的一个条目。在程序启动时，GOT 条目会被 dynamic linker 初始化为 PLT 条目的地址。
   * **动态链接器 (linker)**: 当程序启动时，操作系统会加载 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。
   * **加载共享库**: dynamic linker 会根据可执行文件中的信息，加载所需的共享库，例如 `libc.so`。
   * **符号解析**: dynamic linker 会解析可执行文件和加载的共享库中的符号。对于我们在代码中调用的 `sem_init`，dynamic linker 会在 `libc.so` 的动态符号表中找到 `sem_init` 的地址，并更新 GOT 中对应 `sem_init` 的条目，使其指向 `libc.so` 中 `sem_init` 函数的实际地址。
   * **延迟绑定 (Lazy Binding)**: 默认情况下，Android 使用延迟绑定。这意味着直到第一次调用某个外部函数时，dynamic linker 才会解析该函数的地址。当我们第一次调用 `sem_init` 时，程序会跳转到 PLT 中 `sem_init` 的条目，PLT 中的代码会调用 dynamic linker 来解析 `sem_init` 的地址，并将解析结果写入 GOT 中。后续对 `sem_init` 的调用会直接通过 GOT 跳转到 `libc.so` 中的实现。

**假设输入与输出（逻辑推理）**

以 `TEST(semaphore, sem_init)` 为例：

* **假设输入**:
    * 调用 `sem_init(&s, 0, 0)`：初始化一个线程间共享的信号量，初始值为 0。
    * 调用 `sem_init(&s, 0, 123)`：初始化一个线程间共享的信号量，初始值为 123。
    * 调用 `sem_init(&s, 0, -1)`：尝试初始化一个信号量，初始值为负数。
    * 调用 `sem_init(&s, 0, static_cast<unsigned>(SEM_VALUE_MAX) + 1)`：尝试初始化一个信号量，初始值超过最大值。

* **预期输出**:
    * `sem_init(&s, 0, 0)` 返回 0（成功）。
    * `sem_init(&s, 0, 123)` 返回 0（成功）。
    * `sem_init(&s, 0, -1)` 返回 -1，`errno` 设置为 `EINVAL`（无效参数）。
    * `sem_init(&s, 0, static_cast<unsigned>(SEM_VALUE_MAX) + 1)` 返回 -1，`errno` 设置为 `EINVAL`（无效参数）。

以 `TEST(semaphore, sem_trywait)` 为例：

* **假设输入**:
    * 初始化信号量 `s` 的值为 3。
    * 多次调用 `sem_trywait(&s)`。

* **预期输出**:
    * 前三次 `sem_trywait(&s)` 调用都返回 0，每次调用后信号量的值分别变为 2, 1, 0。
    * 第四次 `sem_trywait(&s)` 调用返回 -1，`errno` 设置为 `EAGAIN`，信号量的值保持为 0。

**用户或编程常见的使用错误**

* **未初始化或重复初始化**: 在使用信号量之前没有调用 `sem_init` 进行初始化，或者对同一个信号量多次调用 `sem_init` 而没有先调用 `sem_destroy`。
* **忘记销毁**:  分配的信号量在使用完毕后没有调用 `sem_destroy` 进行销毁，可能导致资源泄漏。特别是对于进程间共享的信号量，如果不正确地管理生命周期，可能会导致问题。
* **死锁**: 多个线程互相等待对方释放信号量，导致所有线程都无法继续执行。例如：
    ```c++
    sem_t s1, s2;
    sem_init(&s1, 0, 1);
    sem_init(&s2, 0, 1);

    // 线程 1
    sem_wait(&s1);
    // ... 做一些操作 ...
    sem_wait(&s2);
    // ... 做一些操作 ...
    sem_post(&s2);
    sem_post(&s1);

    // 线程 2
    sem_wait(&s2);
    // ... 做一些操作 ...
    sem_wait(&s1);
    // ... 做一些操作 ...
    sem_post(&s1);
    sem_post(&s2);
    ```
    如果线程 1 获取了 `s1`，线程 2 获取了 `s2`，那么它们会互相等待对方释放信号量，导致死锁。

* **竞态条件**:  在没有正确同步的情况下访问共享资源，导致结果的不确定性。例如，多个线程同时对一个受信号量保护的共享变量进行修改，但信号量的使用方式不当，无法保证操作的原子性。
* **信号量值溢出**:  虽然不太常见，但如果对一个已经达到 `SEM_VALUE_MAX` 的信号量调用 `sem_post`，行为是未定义的。
* **在信号处理程序中使用 `sem_wait`**: 在信号处理程序中调用 `sem_wait` 是不安全的，因为 `sem_wait` 可能不是可重入的，并且可能与信号处理程序的执行上下文产生冲突。

**Android Framework 或 NDK 如何到达这里**

1. **NDK API 使用**: 开发者在 Native 代码 (C/C++) 中使用 NDK 提供的线程和同步相关的 API，例如 `pthread_mutex_t`, `pthread_cond_t`，或者直接使用 `sem_t` 相关的 API（如果直接包含 `<semaphore.h>`）。

2. **NDK 库的封装**:  NDK 提供的 `pthread` 和 `semaphore` 等 API 实际上是对 Bionic 库中相应函数的封装。当你的 Native 代码调用这些 NDK API 时，最终会调用到 Bionic 库中的实现。

3. **Bionic 库**: Bionic 是 Android 的 C 库，它提供了操作系统级别的基本功能，包括线程管理、同步原语、内存管理等。`semaphore_test.cpp` 测试的就是 Bionic 提供的信号量实现。

4. **系统调用**: Bionic 库中的信号量实现（特别是进程间共享的信号量）可能会最终调用 Linux 内核提供的系统调用，例如 `futex`。

**Frida Hook 示例调试步骤**

假设你想观察 `sem_wait` 和 `sem_post` 的调用情况，可以使用 Frida 进行 Hook：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 '{package_name}' 未运行，请先启动应用。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "sem_wait"), {
    onEnter: function(args) {
        var sem_ptr = ptr(args[0]);
        var value = Memory.readU32(sem_ptr); // 假设 sem_t 的结构简单，实际可能更复杂
        send({ type: "sem_wait", semaphore: sem_ptr.toString(), value: value });
    },
    onLeave: function(retval) {
        send({ type: "sem_wait_ret", retval: retval });
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "sem_post"), {
    onEnter: function(args) {
        var sem_ptr = ptr(args[0]);
        var value = Memory.readU32(sem_ptr);
        send({ type: "sem_post", semaphore: sem_ptr.toString(), value: value });
    },
    onLeave: function(retval) {
        send({ type: "sem_post_ret", retval: retval });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤解释:**

1. **导入 Frida 库**:  导入 `frida` 和 `sys` 库。
2. **指定应用包名**: 将 `package_name` 替换为你要调试的 Android 应用的包名。
3. **连接到设备和进程**: 使用 `frida.get_usb_device().attach(package_name)` 连接到 USB 设备上的目标应用进程。
4. **定义消息处理函数**: `on_message` 函数用于处理 Frida 脚本发送的消息。
5. **编写 Frida 脚本**:
   * **`Module.findExportByName("libc.so", "sem_wait")`**:  找到 `libc.so` 中 `sem_wait` 函数的地址。
   * **`Interceptor.attach(...)`**:  拦截对 `sem_wait` 函数的调用。
   * **`onEnter`**: 在 `sem_wait` 函数执行之前执行的代码。这里我们读取了信号量指针和可能的值（简化假设），并通过 `send` 函数发送消息。
   * **`onLeave`**: 在 `sem_wait` 函数执行之后执行的代码。这里我们发送了返回值。
   * 同样的操作用于 Hook `sem_post` 函数。
6. **创建和加载脚本**: 使用 `session.create_script(script_code)` 创建 Frida 脚本，并使用 `script.load()` 加载脚本到目标进程。
7. **监听消息**: `script.on('message', on_message)` 设置消息处理函数。
8. **保持脚本运行**: `sys.stdin.read()` 阻止脚本退出，以便持续监听。

**运行步骤:**

1. 确保你的 Android 设备已连接到电脑，并且 adb 可用。
2. 确保你的 Android 设备上安装了 Frida Server，并且正在运行。
3. 将上面的 Python 代码保存为一个 `.py` 文件（例如 `hook_semaphore.py`）。
4. 启动你要调试的 Android 应用。
5. 在电脑上运行 Python 脚本：`python hook_semaphore.py`。

当你的应用调用 `sem_wait` 和 `sem_post` 时，Frida 脚本会拦截这些调用，并打印出相关信息，例如信号量的地址和值，以及函数的返回值。这可以帮助你理解信号量在应用中的使用情况。

希望以上详细的解释能够帮助你理解 `bionic/tests/semaphore_test.cpp` 文件的功能和相关概念。

### 提示词
```
这是目录为bionic/tests/semaphore_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <semaphore.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include <android-base/silent_death_test.h>
#include <gtest/gtest.h>

#include "SignalUtils.h"
#include "private/bionic_constants.h"

#include "utils.h"

using semaphore_DeathTest = SilentDeathTest;

TEST(semaphore, sem_init) {
  sem_t s;

  // Perfectly fine initial values.
  ASSERT_EQ(0, sem_init(&s, 0, 0));
  ASSERT_EQ(0, sem_init(&s, 0, 1));
  ASSERT_EQ(0, sem_init(&s, 0, 123));

  // Too small an initial value.
  errno = 0;
  ASSERT_EQ(-1, sem_init(&s, 0, -1));
  ASSERT_ERRNO(EINVAL);

  ASSERT_EQ(SEM_VALUE_MAX, sysconf(_SC_SEM_VALUE_MAX));

  // The largest initial value.
  ASSERT_EQ(0, sem_init(&s, 0, SEM_VALUE_MAX));

  // Too large an initial value.
  errno = 0;
  ASSERT_EQ(-1, sem_init(&s, 0, static_cast<unsigned>(SEM_VALUE_MAX) + 1));
  ASSERT_ERRNO(EINVAL);

  ASSERT_EQ(0, sem_destroy(&s));
}

TEST(semaphore, sem_trywait) {
  sem_t s;
  ASSERT_EQ(0, sem_init(&s, 0, 3));
  ASSERT_EQ(0, sem_trywait(&s));
  ASSERT_EQ(0, sem_trywait(&s));
  ASSERT_EQ(0, sem_trywait(&s));
  errno = 0;
  ASSERT_EQ(-1, sem_trywait(&s));
  ASSERT_ERRNO(EAGAIN);
  ASSERT_EQ(0, sem_destroy(&s));
}

static void SemWaitThreadTestFn(sem_t& sem) {
  ASSERT_EQ(0, sem_wait(&sem));
}

static void* SemWaitThreadFn(void* arg) {
  SemWaitThreadTestFn(*reinterpret_cast<sem_t*>(arg));
  return nullptr;
}

TEST(semaphore, sem_wait__sem_post) {
  sem_t s;
  ASSERT_EQ(0, sem_init(&s, 0, 0));

  pthread_t t1, t2, t3;
  ASSERT_EQ(0, pthread_create(&t1, nullptr, SemWaitThreadFn, &s));
  ASSERT_EQ(0, pthread_create(&t2, nullptr, SemWaitThreadFn, &s));
  ASSERT_EQ(0, pthread_create(&t3, nullptr, SemWaitThreadFn, &s));

  ASSERT_EQ(0, sem_post(&s));
  ASSERT_EQ(0, sem_post(&s));
  ASSERT_EQ(0, sem_post(&s));

  void* result;
  ASSERT_EQ(0, pthread_join(t1, &result));
  ASSERT_EQ(0, pthread_join(t2, &result));
  ASSERT_EQ(0, pthread_join(t3, &result));
}

static inline void timespec_add_ms(timespec& ts, size_t ms) {
  ts.tv_sec  += ms / 1000;
  ts.tv_nsec += (ms % 1000) * 1000000;
  if (ts.tv_nsec >= NS_PER_S) {
    ts.tv_sec++;
    ts.tv_nsec -= NS_PER_S;
  }
}

static void sem_timedwait_helper(clockid_t clock,
                                 int (*wait_function)(sem_t* __sem, const timespec* __ts)) {
  sem_t s;
  ASSERT_EQ(0, sem_init(&s, 0, 0));

  timespec ts;
  ASSERT_EQ(0, clock_gettime(clock, &ts));
  timespec_add_ms(ts, 100);

  errno = 0;
  ASSERT_EQ(-1, wait_function(&s, &ts));
  ASSERT_ERRNO(ETIMEDOUT);

  // A negative timeout is an error.
  errno = 0;
  ts.tv_nsec = -1;
  ASSERT_EQ(-1, wait_function(&s, &ts));
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  ts.tv_nsec = NS_PER_S;
  ASSERT_EQ(-1, wait_function(&s, &ts));
  ASSERT_ERRNO(EINVAL);

  errno = 0;
  ts.tv_nsec = NS_PER_S - 1;
  ts.tv_sec = -1;
  ASSERT_EQ(-1, wait_function(&s, &ts));
  ASSERT_ERRNO(ETIMEDOUT);

  ASSERT_EQ(0, sem_destroy(&s));
}

TEST(semaphore, sem_timedwait) {
  sem_timedwait_helper(CLOCK_REALTIME, sem_timedwait);
}

TEST(semaphore, sem_timedwait_monotonic_np) {
#if defined(__BIONIC__)
  sem_timedwait_helper(CLOCK_MONOTONIC, sem_timedwait_monotonic_np);
#else   // __BIONIC__
  GTEST_SKIP() << "sem_timedwait_monotonic_np is only supported on bionic";
#endif  // __BIONIC__
}

TEST(semaphore, sem_clockwait) {
#if defined(__BIONIC__)
  sem_timedwait_helper(CLOCK_MONOTONIC, [](sem_t* __sem, const timespec* __ts) {
    return sem_clockwait(__sem, CLOCK_MONOTONIC, __ts);
  });
  sem_timedwait_helper(CLOCK_REALTIME, [](sem_t* __sem, const timespec* __ts) {
    return sem_clockwait(__sem, CLOCK_REALTIME, __ts);
  });
#else   // __BIONIC__
  GTEST_SKIP() << "sem_clockwait is only supported on bionic";
#endif  // __BIONIC__
}

TEST_F(semaphore_DeathTest, sem_timedwait_null_timeout) {
  sem_t s;
  ASSERT_EQ(0, sem_init(&s, 0, 0));
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  ASSERT_EXIT(sem_timedwait(&s, nullptr), testing::KilledBySignal(SIGSEGV), "");
#pragma clang diagnostic pop
}

TEST(semaphore, sem_getvalue) {
  sem_t s;
  ASSERT_EQ(0, sem_init(&s, 0, 0));

  int i;
  ASSERT_EQ(0, sem_getvalue(&s, &i));
  ASSERT_EQ(0, i);

  ASSERT_EQ(0, sem_post(&s));
  ASSERT_EQ(0, sem_getvalue(&s, &i));
  ASSERT_EQ(1, i);

  ASSERT_EQ(0, sem_post(&s));
  ASSERT_EQ(0, sem_getvalue(&s, &i));
  ASSERT_EQ(2, i);

  ASSERT_EQ(0, sem_wait(&s));
  ASSERT_EQ(0, sem_getvalue(&s, &i));
  ASSERT_EQ(1, i);
}

extern "C" void android_set_application_target_sdk_version(int target);

static void sem_wait_test_signal_handler(int) {
}

static void* SemWaitEINTRThreadFn(void* arg) {
  sem_t* sem = reinterpret_cast<sem_t*>(arg);
  uintptr_t have_eintr = 0;
  uintptr_t have_error = 0;
  while (true) {
    int result = sem_wait(sem);
    if (result == 0) {
      break;
    }
    if (result == -1) {
      if (errno == EINTR) {
        have_eintr = 1;
      } else {
        have_error = 1;
        break;
      }
    }
  }
  return reinterpret_cast<void*>((have_eintr << 1) | have_error);
}

TEST(semaphore, sem_wait_no_EINTR_in_sdk_less_equal_than_23) {
#if defined(__BIONIC__)
  android_set_application_target_sdk_version(23);
  sem_t s;
  ASSERT_EQ(0, sem_init(&s, 0, 0));
  ScopedSignalHandler handler(SIGUSR1, sem_wait_test_signal_handler);
  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr, SemWaitEINTRThreadFn, &s));
  // Give some time for the thread to run sem_wait.
  usleep(500000);
  ASSERT_EQ(0, pthread_kill(thread, SIGUSR1));
  // Give some time for the thread to handle signal.
  usleep(500000);
  ASSERT_EQ(0, sem_post(&s));
  void* result;
  ASSERT_EQ(0, pthread_join(thread, &result));
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(result));
#else
  GTEST_SKIP() << "This test tests sem_wait's compatibility for old sdk versions";
#endif
}

TEST(semaphore, sem_wait_EINTR_in_sdk_greater_than_23) {
#if defined(__BIONIC__)
  android_set_application_target_sdk_version(24U);
#endif
  sem_t s;
  ASSERT_EQ(0, sem_init(&s, 0, 0));
  ScopedSignalHandler handler(SIGUSR1, sem_wait_test_signal_handler);
  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr, SemWaitEINTRThreadFn, &s));
  // Give some time for the thread to run sem_wait.
  usleep(500000);
  ASSERT_EQ(0, pthread_kill(thread, SIGUSR1));
  // Give some time for the thread to handle signal.
  usleep(500000);
  ASSERT_EQ(0, sem_post(&s));
  void* result;
  ASSERT_EQ(0, pthread_join(thread, &result));
  ASSERT_EQ(2U, reinterpret_cast<uintptr_t>(result));
}
```