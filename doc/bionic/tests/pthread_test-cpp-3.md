Response:
The user wants a summary of the functionality of the provided C++ code, which is part of the Android Bionic library and focuses on testing the `pthread` (POSIX threads) API.

Here's a breakdown of how to approach the request:

1. **Identify the Core Purpose:** The code consists of unit tests for various `pthread` functions. The main goal is to verify the correct behavior of these functions in different scenarios.

2. **Group Tests by Functionality:**  Organize the tests based on the `pthread` functions they target. This will make the summary more structured and easier to understand.

3. **Describe Each Test Group:** For each group of tests, explain what aspect of the `pthread` function is being tested. Highlight key behaviors being verified (e.g., successful execution, error handling, interaction with attributes).

4. **Address Specific Requirements:**
    * **Relationship to Android:** Mention that these tests are part of Bionic, Android's C library, and ensure the correct functioning of threading primitives used extensively in the Android framework and NDK.
    * **`libc` Function Implementation:** Since the code *tests* `libc` functions, the explanation should focus on what the tests *verify* about the functions' behavior, not the internal implementation details (which aren't in this test code). Avoid going into the kernel-level implementation.
    * **Dynamic Linker:**  This specific code doesn't directly test dynamic linking. Acknowledge this. *Initially, I might have thought about how `pthread_create` involves the dynamic linker loading libraries for the new thread, but this test code focuses on the `pthread` API itself.*
    * **Logic Inference/Input-Output:**  For each test, the "input" is the setup (e.g., arguments to the `pthread` function), and the "output" is the assertion being made (e.g., the return value, the state of a variable).
    * **Common Usage Errors:** Identify potential mistakes developers might make when using the `pthread` functions based on the negative tests (those that expect errors).
    * **Android Framework/NDK Path:** Explain that the Android framework and NDK rely on these `pthread` primitives for concurrency. Provide a high-level overview of the call stack.
    * **Frida Hooking:**  Give general examples of how Frida could be used to intercept calls to these `pthread` functions.
    * **归纳功能 (Summarize Functionality):**  Provide a concise summary of the overall purpose of the test file.

5. **Structure the Response:** Use clear headings and bullet points to organize the information. Use precise language to describe technical concepts.

**Self-Correction/Refinement during thought process:**

* **Initial thought:** Should I explain the implementation of `pthread_create`?  **Correction:** The request asks for the *function of the test file*, not the underlying implementation. Focus on what the tests are doing.
* **Consideration:**  Should I provide specific Frida hook examples for each function? **Correction:** The request asks for examples, and providing a general example for `pthread_create` and perhaps `pthread_mutex_lock` is sufficient to illustrate the concept. Listing every function would be too verbose for a summary.
* **Clarification:** The request mentions "详细解释每一个libc函数的功能是如何实现的". While the prompt asks for this, the provided code is *testing* these functions, not implementing them. The explanation needs to reflect this. I should explain what aspects of the *behavior* are being tested.

By following these steps and refining the approach as needed, I can generate a comprehensive and accurate summary that addresses all aspects of the user's request.
好的，这是对提供的 `bionic/tests/pthread_test.cpp` 代码片段的归纳总结，作为第 4 部分的结论。

**代码功能归纳总结**

这个代码片段是 Android Bionic 库中 `pthread_test.cpp` 文件的一部分，专门用于测试 Bionic 库中 POSIX 线程 (pthread) 相关功能的单元测试。  它的主要目的是：

1. **验证 pthread API 的正确性：**  通过编写各种测试用例，确保 Bionic 提供的 pthread 函数（例如 `pthread_create`, `pthread_join`, `pthread_mutex_lock`, `pthread_cond_wait` 等）按照 POSIX 标准和 Android 的预期行为工作。

2. **测试不同场景和边界条件：**  测试用例覆盖了 pthread 函数的正常使用情况，以及各种异常情况和边界条件，例如：
    *  初始化和销毁各种 pthread 对象 (互斥锁、条件变量、读写锁、屏障、自旋锁、线程属性)。
    *  设置和获取线程属性 (分离状态、调度策略、继承调度属性、栈大小、guard 大小)。
    *  线程创建和加入的不同方式。
    *  尝试在内存分配失败的情况下创建线程。
    *  设置和获取线程的 CPU affinity。
    *  测试 `pthread_barrier_init` 在计数为零时的行为。
    *  测试 `pthread_spin_trylock` 的非阻塞行为。
    *  测试 `pthread_setschedparam` 和 `pthread_setschedprio` 的错误处理。
    *  测试 `android_run_on_all_threads` 的功能。

3. **确保 Bionic 库的稳定性和可靠性：**  这些单元测试是 Bionic 库开发过程中的重要组成部分，可以帮助开发者及时发现和修复与线程相关的 bug，从而提高 Bionic 库的整体质量。

**与 Android 功能的关系举例**

由于 Bionic 是 Android 的核心 C 库，pthread 功能是 Android 框架和 NDK 中实现并发和多线程的关键基础设施。以下是一些例子说明其关联性：

* **Java 线程的底层实现：** Android 的 Java 层线程 (通过 `java.lang.Thread`) 在底层是通过 Bionic 的 pthread 实现的。当 Java 代码创建一个新的 `Thread` 对象并启动时，Android 运行时 (ART 或 Dalvik) 会调用 Bionic 的 `pthread_create` 来创建一个新的本地线程。

* **NDK 开发中的多线程：**  使用 NDK 开发的原生 C/C++ 代码可以直接调用 Bionic 提供的 pthread 函数来创建和管理线程，实现并行计算、异步操作等功能。例如，一个游戏引擎可能会使用多个线程来处理渲染、物理模拟、音频处理等任务。

* **Android 系统服务：** 许多 Android 系统服务（例如 Activity Manager、Package Manager 等）也使用多线程来处理并发请求，提高系统的响应速度和效率。这些服务底层的线程管理也是依赖于 Bionic 的 pthread 实现。

* **Binder 通信机制：**  Binder 是 Android 系统中重要的进程间通信 (IPC) 机制。 Binder 驱动程序和相关的用户空间库也使用了线程池等技术，这些技术在底层也是基于 pthread 实现的。

**libc 函数的功能实现 (以 `pthread_create` 为例)**

这里我们以 `pthread_create` 为例，简要说明其在 Bionic 中的实现思路（请注意，具体的实现细节非常复杂，且会随着 Android 版本演进）：

1. **参数校验：** `pthread_create` 首先会检查传入的参数是否有效，例如线程属性 `attr`、线程执行函数 `start_routine` 等。

2. **资源分配：**  为新线程分配必要的资源，包括：
    * **栈空间：**  根据线程属性中设置的栈大小或默认大小，分配一块内存作为新线程的栈。
    * **线程控制块 (TCB)：**  分配一个数据结构来存储新线程的状态信息，例如线程 ID、优先级、调度策略等。在 Linux 内核中，这个结构通常是 `task_struct`。
    * **线程局部存储 (TLS)：**  为新线程分配 TLS 区域，用于存储线程私有的数据。

3. **内核调用：**  通过系统调用（例如 `clone` 在 Linux 中）来创建新的进程上下文（轻量级进程）。  `clone` 系统调用允许指定父进程和子进程共享的资源，例如内存空间。对于线程创建，通常会共享大部分资源。

4. **线程启动例程：**  在新线程的上下文中，会执行一个内部的线程启动例程。这个例程会做一些初始化工作，例如设置 TLS、调用用户指定的线程执行函数 `start_routine`。

5. **返回线程 ID：**  如果线程创建成功，`pthread_create` 会将新创建的线程的 ID 写入 `thread` 指向的内存。

**涉及 dynamic linker 的功能 (以 `pthread_create` 可能涉及的动态链接为例)**

虽然这个测试代码片段本身没有直接测试动态链接器的功能，但在实际的 `pthread_create` 调用过程中，动态链接器可能会参与进来。

**so 布局样本 (假设新线程执行的代码在共享库中)**

假设我们要创建的线程执行的函数 `thread_func` 定义在一个名为 `libmylibrary.so` 的共享库中：

```
libmylibrary.so:
    .text           # 代码段
        thread_func:
            ...
    .data           # 数据段
        global_var:
            ...
```

**链接的处理过程**

1. **加载共享库：** 当主线程或其他线程第一次调用 `libmylibrary.so` 中的函数时，动态链接器 (在 Android 中通常是 `linker64` 或 `linker`) 会负责将 `libmylibrary.so` 加载到进程的地址空间。

2. **符号解析：** 动态链接器会解析 `libmylibrary.so` 中引用的外部符号，并将其链接到相应的定义。

3. **重定位：**  由于共享库被加载到内存的地址可能不是编译时确定的地址，动态链接器需要修改代码和数据段中的地址引用，使其指向正确的内存位置。

4. **线程启动：** 当 `pthread_create` 创建新线程，并且新线程要执行 `libmylibrary.so` 中的 `thread_func` 时，动态链接器需要确保 `libmylibrary.so` 已经被加载，并且 `thread_func` 的地址是正确的。  这通常在第一次在新线程中执行 `libmylibrary.so` 中的代码时发生。

**逻辑推理、假设输入与输出 (以 `pthread_mutex_lock` 测试为例)**

假设我们有以下简单的测试场景：

```c++
pthread_mutex_t mutex;
pthread_mutex_init(&mutex, nullptr);

// 线程 1
pthread_mutex_lock(&mutex);
// ... 执行需要互斥保护的代码 ...
pthread_mutex_unlock(&mutex);

// 线程 2
pthread_mutex_lock(&mutex); // 线程 2 将阻塞，直到线程 1 释放锁
// ... 执行需要互斥保护的代码 ...
pthread_mutex_unlock(&mutex);
```

* **假设输入：** 两个线程尝试获取同一个互斥锁 `mutex`。
* **逻辑推理：**  互斥锁的特性是同一时刻只有一个线程可以持有它。 因此，当线程 1 成功获取锁后，线程 2 尝试获取锁时会进入阻塞状态，直到线程 1 调用 `pthread_mutex_unlock` 释放锁。
* **预期输出：**  线程 1 先执行互斥区内的代码，然后线程 2 才能执行互斥区内的代码，保证了对共享资源的互斥访问。

**用户或编程常见的使用错误举例**

* **忘记初始化 pthread 对象：**  直接使用未初始化的互斥锁、条件变量等会导致未定义的行为，通常会导致程序崩溃。

  ```c++
  pthread_mutex_t mutex;
  pthread_mutex_lock(&mutex); // 错误：mutex 未初始化
  ```

* **死锁：**  当多个线程互相等待对方释放资源时，就会发生死锁。

  ```c++
  pthread_mutex_t mutex1, mutex2;
  pthread_mutex_init(&mutex1, nullptr);
  pthread_mutex_init(&mutex2, nullptr);

  // 线程 1
  pthread_mutex_lock(&mutex1);
  // ...
  pthread_mutex_lock(&mutex2); // 线程 1 等待 mutex2
  pthread_mutex_unlock(&mutex2);
  pthread_mutex_unlock(&mutex1);

  // 线程 2
  pthread_mutex_lock(&mutex2);
  // ...
  pthread_mutex_lock(&mutex1); // 线程 2 等待 mutex1
  pthread_mutex_unlock(&mutex1);
  pthread_mutex_unlock(&mutex2);
  ```

* **忘记解锁：**  如果线程获取了互斥锁但忘记释放，会导致其他需要该锁的线程一直阻塞。

  ```c++
  pthread_mutex_t mutex;
  pthread_mutex_init(&mutex, nullptr);
  pthread_mutex_lock(&mutex);
  // ... 执行代码，但忘记调用 pthread_mutex_unlock(&mutex);
  ```

* **条件变量使用不当：**  例如，在没有持有互斥锁的情况下调用 `pthread_cond_wait`，或者信号丢失等问题。

**Android Framework 或 NDK 如何到达这里**

1. **Java 代码调用：** 在 Android Framework 中，例如，创建一个新的 `java.lang.Thread` 对象并调用 `start()` 方法。

2. **ART/Dalvik 虚拟机：**  虚拟机内部会调用 JNI (Java Native Interface) 来执行本地代码。

3. **Bionic 库调用：**  JNI 代码最终会调用 Bionic 库中的 `pthread_create` 函数。

4. **系统调用：**  `pthread_create` 内部会通过系统调用（如 Linux 的 `clone`）来创建新的内核线程。

5. **内核调度：**  Linux 内核的调度器负责管理和调度这些线程的执行。

**Frida Hook 示例调试步骤**

假设我们要 hook `pthread_create` 函数：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['from'], message['payload']['data']))
    else:
        print(message)

session = frida.get_usb_device().attach('com.example.myapp') # 替换为你的应用包名

script = session.create_script("""
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
  onEnter: function(args) {
    console.log("[pthread_create] Thread creating...");
    console.log("  Thread pointer:", args[0]);
    console.log("  Attributes:", args[1]);
    console.log("  Start routine:", args[2]);
    console.log("  Arg:", args[3]);
    // 可以修改参数，例如修改线程属性或执行函数
  },
  onLeave: function(retval) {
    console.log("[pthread_create] Thread created, return value:", retval);
  }
});
""")

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤解释：**

1. **导入 Frida 库。**
2. **定义消息处理函数 `on_message`，用于接收来自 Frida 脚本的消息。**
3. **连接到 USB 设备上的目标应用进程 (需要替换包名)。**
4. **创建 Frida 脚本。**
5. **使用 `Interceptor.attach` hook `libc.so` 中的 `pthread_create` 函数。**
6. **`onEnter` 函数在 `pthread_create` 被调用之前执行，可以打印参数信息。**
7. **`onLeave` 函数在 `pthread_create` 调用返回之后执行，可以打印返回值。**
8. **将脚本加载到目标进程。**
9. **保持脚本运行状态，直到手动停止。**

运行这个 Frida 脚本，当目标应用调用 `pthread_create` 创建新线程时，你将在控制台上看到 hook 到的信息，包括传递给 `pthread_create` 的参数。  你可以根据需要修改 `onEnter` 和 `onLeave` 函数来执行更复杂的操作，例如修改参数、查看堆栈信息等。

希望以上归纳总结能够帮助你理解 `bionic/tests/pthread_test.cpp` 的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/pthread_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ds[i], nullptr));
  }
}

TEST(pthread, pthread_barrier_init_zero_count) {
  pthread_barrier_t barrier;
  ASSERT_EQ(EINVAL, pthread_barrier_init(&barrier, nullptr, 0));
}

TEST(pthread, pthread_spinlock_smoke) {
  pthread_spinlock_t lock;
  ASSERT_EQ(0, pthread_spin_init(&lock, 0));
  ASSERT_EQ(0, pthread_spin_trylock(&lock));
  ASSERT_EQ(0, pthread_spin_unlock(&lock));
  ASSERT_EQ(0, pthread_spin_lock(&lock));
  ASSERT_EQ(EBUSY, pthread_spin_trylock(&lock));
  ASSERT_EQ(0, pthread_spin_unlock(&lock));
  ASSERT_EQ(0, pthread_spin_destroy(&lock));
}

TEST(pthread, pthread_attr_getdetachstate__pthread_attr_setdetachstate) {
  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));

  int state;
  ASSERT_EQ(0, pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED));
  ASSERT_EQ(0, pthread_attr_getdetachstate(&attr, &state));
  ASSERT_EQ(PTHREAD_CREATE_DETACHED, state);

  ASSERT_EQ(0, pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE));
  ASSERT_EQ(0, pthread_attr_getdetachstate(&attr, &state));
  ASSERT_EQ(PTHREAD_CREATE_JOINABLE, state);

  ASSERT_EQ(EINVAL, pthread_attr_setdetachstate(&attr, 123));
  ASSERT_EQ(0, pthread_attr_getdetachstate(&attr, &state));
  ASSERT_EQ(PTHREAD_CREATE_JOINABLE, state);
}

TEST(pthread, pthread_create__mmap_failures) {
  // After thread is successfully created, native_bridge might need more memory to run it.
  SKIP_WITH_NATIVE_BRIDGE;

  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED));

  const auto kPageSize = sysconf(_SC_PAGE_SIZE);

  // Use up all the VMAs. By default this is 64Ki (though some will already be in use).
  std::vector<void*> pages;
  pages.reserve(64 * 1024);
  int prot = PROT_NONE;
  while (true) {
    void* page = mmap(nullptr, kPageSize, prot, MAP_ANON|MAP_PRIVATE, -1, 0);
    if (page == MAP_FAILED) break;
    pages.push_back(page);
    prot = (prot == PROT_NONE) ? PROT_READ : PROT_NONE;
  }

  // Try creating threads, freeing up a page each time we fail.
  size_t EAGAIN_count = 0;
  size_t i = 0;
  for (; i < pages.size(); ++i) {
    pthread_t t;
    int status = pthread_create(&t, &attr, IdFn, nullptr);
    if (status != EAGAIN) break;
    ++EAGAIN_count;
    ASSERT_EQ(0, munmap(pages[i], kPageSize));
  }

  // Creating a thread uses at least three VMAs: the combined stack and TLS, and a guard on each
  // side. So we should have seen at least three failures.
  ASSERT_GE(EAGAIN_count, 3U);

  for (; i < pages.size(); ++i) {
    ASSERT_EQ(0, munmap(pages[i], kPageSize));
  }
}

TEST(pthread, pthread_setschedparam) {
  sched_param p = { .sched_priority = INT_MIN };
  ASSERT_EQ(EINVAL, pthread_setschedparam(pthread_self(), INT_MIN, &p));
}

TEST(pthread, pthread_setschedprio) {
  ASSERT_EQ(EINVAL, pthread_setschedprio(pthread_self(), INT_MIN));
}

TEST(pthread, pthread_attr_getinheritsched__pthread_attr_setinheritsched) {
  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));

  int state;
  ASSERT_EQ(0, pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED));
  ASSERT_EQ(0, pthread_attr_getinheritsched(&attr, &state));
  ASSERT_EQ(PTHREAD_INHERIT_SCHED, state);

  ASSERT_EQ(0, pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED));
  ASSERT_EQ(0, pthread_attr_getinheritsched(&attr, &state));
  ASSERT_EQ(PTHREAD_EXPLICIT_SCHED, state);

  ASSERT_EQ(EINVAL, pthread_attr_setinheritsched(&attr, 123));
  ASSERT_EQ(0, pthread_attr_getinheritsched(&attr, &state));
  ASSERT_EQ(PTHREAD_EXPLICIT_SCHED, state);
}

TEST(pthread, pthread_attr_setinheritsched__PTHREAD_INHERIT_SCHED__PTHREAD_EXPLICIT_SCHED) {
  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));

  // If we set invalid scheduling attributes but choose to inherit, everything's fine...
  sched_param param = { .sched_priority = sched_get_priority_max(SCHED_FIFO) + 1 };
  ASSERT_EQ(0, pthread_attr_setschedparam(&attr, &param));
  ASSERT_EQ(0, pthread_attr_setschedpolicy(&attr, SCHED_FIFO));
  ASSERT_EQ(0, pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED));

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, &attr, IdFn, nullptr));
  ASSERT_EQ(0, pthread_join(t, nullptr));

#if defined(__LP64__)
  // If we ask to use them, though, we'll see a failure...
  ASSERT_EQ(0, pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED));
  ASSERT_EQ(EINVAL, pthread_create(&t, &attr, IdFn, nullptr));
#else
  // For backwards compatibility with broken apps, we just ignore failures
  // to set scheduler attributes on LP32.
#endif
}

TEST(pthread, pthread_attr_setinheritsched_PTHREAD_INHERIT_SCHED_takes_effect) {
  sched_param param = { .sched_priority = sched_get_priority_min(SCHED_FIFO) };
  int rc = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
  if (rc == EPERM) GTEST_SKIP() << "pthread_setschedparam failed with EPERM";
  ASSERT_EQ(0, rc);

  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED));

  SpinFunctionHelper spin_helper;
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, &attr, spin_helper.GetFunction(), nullptr));
  int actual_policy;
  sched_param actual_param;
  ASSERT_EQ(0, pthread_getschedparam(t, &actual_policy, &actual_param));
  ASSERT_EQ(SCHED_FIFO, actual_policy);
  spin_helper.UnSpin();
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

TEST(pthread, pthread_attr_setinheritsched_PTHREAD_EXPLICIT_SCHED_takes_effect) {
  sched_param param = { .sched_priority = sched_get_priority_min(SCHED_FIFO) };
  int rc = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
  if (rc == EPERM) GTEST_SKIP() << "pthread_setschedparam failed with EPERM";
  ASSERT_EQ(0, rc);

  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED));
  ASSERT_EQ(0, pthread_attr_setschedpolicy(&attr, SCHED_OTHER));

  SpinFunctionHelper spin_helper;
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, &attr, spin_helper.GetFunction(), nullptr));
  int actual_policy;
  sched_param actual_param;
  ASSERT_EQ(0, pthread_getschedparam(t, &actual_policy, &actual_param));
  ASSERT_EQ(SCHED_OTHER, actual_policy);
  spin_helper.UnSpin();
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

TEST(pthread, pthread_attr_setinheritsched__takes_effect_despite_SCHED_RESET_ON_FORK) {
  sched_param param = { .sched_priority = sched_get_priority_min(SCHED_FIFO) };
  int rc = pthread_setschedparam(pthread_self(), SCHED_FIFO | SCHED_RESET_ON_FORK, &param);
  if (rc == EPERM) GTEST_SKIP() << "pthread_setschedparam failed with EPERM";
  ASSERT_EQ(0, rc);

  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED));

  SpinFunctionHelper spin_helper;
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, &attr, spin_helper.GetFunction(), nullptr));
  int actual_policy;
  sched_param actual_param;
  ASSERT_EQ(0, pthread_getschedparam(t, &actual_policy, &actual_param));
  ASSERT_EQ(SCHED_FIFO  | SCHED_RESET_ON_FORK, actual_policy);
  spin_helper.UnSpin();
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

extern "C" bool android_run_on_all_threads(bool (*func)(void*), void* arg);

TEST(pthread, run_on_all_threads) {
#if defined(__BIONIC__)
  pthread_t t;
  ASSERT_EQ(
      0, pthread_create(
             &t, nullptr,
             [](void*) -> void* {
               pthread_attr_t detached;
               if (pthread_attr_init(&detached) != 0 ||
                   pthread_attr_setdetachstate(&detached, PTHREAD_CREATE_DETACHED) != 0) {
                 return reinterpret_cast<void*>(errno);
               }

               for (int i = 0; i != 1000; ++i) {
                 pthread_t t1, t2;
                 if (pthread_create(
                         &t1, &detached, [](void*) -> void* { return nullptr; }, nullptr) != 0 ||
                     pthread_create(
                         &t2, nullptr, [](void*) -> void* { return nullptr; }, nullptr) != 0 ||
                     pthread_join(t2, nullptr) != 0) {
                   return reinterpret_cast<void*>(errno);
                 }
               }

               if (pthread_attr_destroy(&detached) != 0) {
                 return reinterpret_cast<void*>(errno);
               }
               return nullptr;
             },
             nullptr));

  for (int i = 0; i != 1000; ++i) {
    ASSERT_TRUE(android_run_on_all_threads([](void* arg) { return arg == nullptr; }, nullptr));
  }

  void *retval;
  ASSERT_EQ(0, pthread_join(t, &retval));
  ASSERT_EQ(nullptr, retval);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(pthread, pthread_getaffinity_np_failure) {
  // Trivial test of the errno-preserving/returning behavior.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  errno = 0;
  ASSERT_EQ(EINVAL, pthread_getaffinity_np(pthread_self(), 0, nullptr));
  ASSERT_ERRNO(0);
#pragma clang diagnostic pop
}

TEST(pthread, pthread_getaffinity) {
  cpu_set_t set;
  CPU_ZERO(&set);
  ASSERT_EQ(0, pthread_getaffinity_np(pthread_self(), sizeof(set), &set));
  ASSERT_GT(CPU_COUNT(&set), 0);
}

TEST(pthread, pthread_setaffinity_np_failure) {
  // Trivial test of the errno-preserving/returning behavior.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  errno = 0;
  ASSERT_EQ(EINVAL, pthread_setaffinity_np(pthread_self(), 0, nullptr));
  ASSERT_ERRNO(0);
#pragma clang diagnostic pop
}

TEST(pthread, pthread_setaffinity) {
  cpu_set_t set;
  CPU_ZERO(&set);
  ASSERT_EQ(0, pthread_getaffinity_np(pthread_self(), sizeof(set), &set));
  // It's hard to make any more general claim than this,
  // but it ought to be safe to ask for the same affinity you already have.
  ASSERT_EQ(0, pthread_setaffinity_np(pthread_self(), sizeof(set), &set));
}
```