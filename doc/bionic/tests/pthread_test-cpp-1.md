Response:
My thought process for summarizing the provided C++ code snippet goes like this:

1. **Understand the Goal:** The request is to summarize the functionality of the provided code, which is a part of `pthread_test.cpp` in Android's Bionic library. This means focusing on what the code *does* rather than *how* it does it internally.

2. **Identify Key Components:**  I scan the code for recurring patterns, function calls, and test names. I immediately notice:
    * `TEST(pthread, ...)`: This indicates the code is a set of unit tests for pthread-related functionalities.
    * `pthread_rwlock_*`:  A significant portion of the tests revolves around read-write locks (`pthread_rwlock_t`).
    * `pthread_cond_*`: Another set of tests deals with condition variables (`pthread_cond_t`).
    * `pthread_once`:  There's a test related to `pthread_once`.
    * `pthread_atfork`:  Tests for `pthread_atfork` are present.
    * `pthread_attr_*`: Tests concerning thread attributes are included.
    * `CLOCK_REALTIME`, `CLOCK_MONOTONIC`: These constants appear frequently, suggesting tests related to time and timeouts.
    * `_np` suffixes (like `pthread_rwlock_timedrdlock_monotonic_np`):  These usually indicate non-portable (typically Linux-specific) extensions.
    * `GTEST_SKIP()`: This shows that certain tests are skipped on platforms other than Bionic or when specific features are not available.

3. **Group Related Tests:** I mentally group the tests based on the pthread functionality they are exercising:
    * **Read-Write Locks:**  Tests for locking, unlocking, timed locking, clock-based locking, and different lock "kinds" (prefer reader, prefer writer). These tests often involve creating helper threads to simulate different locking scenarios.
    * **Condition Variables:** Tests for signaling, broadcasting, timed waiting, and clock-based waiting. Similar to the rwlock tests, these often use helper threads.
    * **`pthread_once`:** Tests to ensure a function is executed only once.
    * **`pthread_atfork`:** Tests to verify handlers are called correctly during `fork` and `vfork`.
    * **Thread Attributes:** Tests to get and set thread attributes, particularly stack-related attributes.

4. **Summarize Each Group:**  For each group, I write a concise summary of the functionality being tested. I use action verbs and focus on the observable behavior. For example:
    * **Read-Write Locks:** Focus on testing locking and unlocking behaviors under different conditions (timed, clock-based, reader/writer preference).
    * **Condition Variables:**  Highlight testing the signaling and waiting mechanisms, including timeouts and different clocks.
    * **`pthread_once`:** Explain it tests the single execution guarantee.
    * **`pthread_atfork`:** Describe the testing of handlers during forking.
    * **Thread Attributes:** Mention testing the retrieval of stack attributes.

5. **Identify Conditional Compilation:** I notice the `#if defined(__BIONIC__)` and `#else` blocks. This is crucial for understanding that some tests are Bionic-specific. I explicitly mention this in the summary.

6. **Note Skipped Tests:** The `GTEST_SKIP()` calls are important. I include in the summary that certain tests are skipped based on platform or feature availability.

7. **Structure the Summary:** I organize the summary logically, grouping related functionalities together. I use bullet points for clarity.

8. **Refine and Clarify:** I reread the summary to ensure it's accurate, concise, and easy to understand. I avoid overly technical jargon where possible and focus on the high-level purpose of the tests. For example, instead of saying "tests the `pthread_rwlock_timedrdlock` function," I might say "tests the timed read locking functionality of read-write locks."

By following these steps, I arrive at a comprehensive yet succinct summary of the code's functionality, as demonstrated in the provided example answer. The key is to move from the specific details of the code to a higher-level understanding of its testing purpose.
这段代码是 `bionic/tests/pthread_test.cpp` 文件的一部分，专门测试 **pthread 读写锁（read-write locks）** 和 **pthread once 初始化** 的功能，以及与 **fork** 相关的 **pthread_atfork** 功能，以及 **pthread 属性** 和 **pthread 条件变量** 的部分功能。

**归纳其功能如下：**

* **读写锁 (pthread_rwlock_t) 的功能测试：**
    * **基本加锁和解锁：** 测试读锁 (`pthread_rwlock_rdlock`) 和写锁 (`pthread_rwlock_wrlock`) 的基本功能。
    * **非阻塞加锁：** 测试尝试获取读锁 (`pthread_rwlock_tryrdlock`) 和写锁 (`pthread_rwlock_trywrlock`) 的功能。
    * **带超时的加锁：** 测试在指定时间内尝试获取读锁 (`pthread_rwlock_timedrdlock`, `pthread_rwlock_clockrdlock`) 和写锁 (`pthread_rwlock_timedwrlock`, `pthread_rwlock_clockwrlock`) 的功能，包括使用 `CLOCK_REALTIME` 和 `CLOCK_MONOTONIC` 等不同时钟。
    * **读写锁唤醒：** 测试当一个线程持有写锁时，能否唤醒等待读锁的线程；以及当一个线程持有读锁时，能否唤醒等待写锁的线程。这部分还包括了带超时的唤醒测试。
    * **读写锁属性 (pthread_rwlockattr_t)：**  测试设置和获取读写锁的属性，特别是 `pthread_rwlockattr_setkind_np`，用于设置读写锁的偏好策略（例如，偏好读者、偏好写者）。
* **pthread_once 的功能测试：**
    * **单次初始化：** 测试 `pthread_once` 确保初始化函数只被调用一次，即使在多个线程中多次调用。
    * **嵌套调用：** 测试在 `pthread_once` 的初始化函数中再次调用 `pthread_once` 的情况，验证是否能正常工作。
* **pthread_atfork 的功能测试：**
    * **fork/vfork 时的回调：** 测试 `pthread_atfork` 注册的 prepare, parent, child 回调函数在 `fork` 和 `vfork` 系统调用时的执行顺序和调用情况。
* **pthread 属性 (pthread_attr_t) 的部分功能测试：**
    * **获取作用域：** 测试 `pthread_attr_getscope` 获取线程作用域的功能。
    * **获取栈信息：** 测试 `pthread_attr_getstack` 和 `pthread_attr_getstacksize` 获取线程栈基址和大小的功能，特别是针对主线程和信号处理函数中的栈信息获取。
* **pthread 条件变量 (pthread_cond_t) 的部分功能测试：**
    * **初始化和属性：** 测试 `pthread_condattr_init`， `pthread_condattr_setclock`， `pthread_condattr_getclock`， `pthread_condattr_getpshared`，以及 `pthread_cond_init`，验证条件变量的属性设置。
    * **信号和广播：** 测试 `pthread_cond_signal` 和 `pthread_cond_broadcast` 唤醒等待线程的功能。
    * **等待：** 测试 `pthread_cond_wait` 的基本等待功能。
    * **带超时的等待：** 测试 `pthread_cond_timedwait` 和 `pthread_cond_clockwait` 在指定时间内等待条件变量的功能，包括使用 `CLOCK_REALTIME` 和 `CLOCK_MONOTONIC` 等不同时钟。

**与 Android 功能的关系举例说明：**

* **读写锁：** Android Framework 中很多地方使用了读写锁来保护共享资源，例如 AMS (Activity Manager Service) 中对 Activity 列表的访问，Zygote 进程的 fork 机制等。这些锁可以允许多个线程同时读取资源，但只允许一个线程写入，提高了并发效率。
* **pthread_once：**  Android 系统启动时，可能需要执行一些全局的初始化操作，`pthread_once` 可以确保这些初始化操作只被执行一次，例如初始化日志系统，创建 Binder 线程池等。
* **pthread_atfork：** 当 Android 应用进程 fork 出新的进程时（例如，通过 Zygote 孵化应用进程），`pthread_atfork` 注册的回调函数可以用来清理或准备父子进程之间的共享资源，避免出现死锁或数据不一致的问题。例如，在 fork 之前可能需要持有某些锁，在 fork 之后需要在父子进程中分别释放或重新获取这些锁。
* **pthread 条件变量：**  在 Android 的 Binder 通信机制中，条件变量被广泛用于线程间的同步和等待。例如，一个线程发送 Binder 请求后，会等待另一个线程处理完请求并发送信号，这时就可以使用条件变量来实现高效的等待和唤醒。

**关于 libc 函数的实现细节：**

由于这段代码是测试代码，它主要关注的是 libc 函数的行为和返回值是否符合预期，而不是 libc 函数的具体实现。libc 函数的实现细节通常比较复杂，涉及到系统调用、内核同步原语等。

**关于 dynamic linker 的功能：**

这段代码本身并没有直接涉及 dynamic linker 的功能。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载共享库 (.so 文件)，解析符号，并进行符号重定位。

**如果做了逻辑推理，请给出假设输入与输出：**

这段代码主要是单元测试，它的“输入”是函数调用及其参数，“输出”是函数的返回值和程序的行为（例如，线程是否被唤醒，回调函数是否被调用）。例如：

* **假设输入：** 调用 `pthread_rwlock_rdlock` 尝试获取一个未被持有的读写锁。
* **预期输出：** 函数返回 0，表示成功获取读锁。

* **假设输入：** 调用 `pthread_rwlock_wrlock` 尝试获取一个已被其他线程持有读锁的读写锁。
* **预期输出：** 调用线程会被阻塞，直到持有读锁的线程释放锁。

* **假设输入：** 多次在不同线程中调用 `pthread_once` 并传入同一个 `pthread_once_t` 变量和一个初始化函数。
* **预期输出：** 初始化函数只会被执行一次。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

* **读写锁：**
    * **死锁：**  例如，一个线程持有读锁，然后尝试获取写锁；另一个线程持有写锁，然后尝试获取读锁，可能导致死锁。
    * **忘记解锁：** 获取了读锁或写锁后，忘记调用 `pthread_rwlock_unlock` 释放锁，会导致其他线程永远无法获取该锁。
    * **在错误的时机使用 try lock：** 在需要独占访问资源的情况下，错误地使用了 `pthread_rwlock_trywrlock` 并且没有处理返回的 `EBUSY` 错误，可能导致数据不一致。
* **pthread_once：**
    * **未初始化 `pthread_once_t` 变量：**  直接使用未初始化的 `pthread_once_t` 变量可能导致未定义的行为。应该使用 `PTHREAD_ONCE_INIT` 进行初始化。
* **pthread_atfork：**
    * **在回调函数中执行不安全的操作：**  在 `fork` 之后，父子进程共享内存空间，在回调函数中操作某些资源时需要特别小心，避免竞争条件或死锁。例如，在子进程中关闭父进程打开的文件描述符可能会导致问题。
* **条件变量：**
    * **虚假唤醒：**  即使条件没有满足，`pthread_cond_wait` 也可能返回（所谓的虚假唤醒）。因此，通常需要在 `pthread_cond_wait` 返回后再次检查条件是否满足。
    * **忘记加互斥锁：**  在使用条件变量之前，必须先获取与该条件变量关联的互斥锁。同样，在调用 `pthread_cond_signal` 或 `pthread_cond_broadcast` 之前，通常也需要持有该互斥锁。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

这段代码是 Android 系统库 bionic 的一部分，属于系统底层。Android Framework 或 NDK 应用不会直接调用这些测试代码。但是，Framework 和 NDK 应用会使用 `pthread` 相关的 API，最终会调用到 bionic 库中对应的实现。

**到达这里的路径：**

1. **NDK 应用调用 pthread API：**  例如，一个 NDK 应用调用 `pthread_create` 创建一个线程，或者使用 `pthread_mutex_lock` 加锁。
2. **系统调用：**  bionic 库中的 `pthread` API 实现会调用底层的 Linux 系统调用，例如 `clone` (用于线程创建)，`futex` (用于锁和条件变量的实现)。
3. **内核调度：** Linux 内核负责线程的调度和同步。

**Frida Hook 示例：**

要调试 bionic 库中的 `pthread` 函数，可以使用 Frida hook 这些函数。以下是一个 hook `pthread_mutex_lock` 的示例：

```javascript
// hook pthread_mutex_lock
Interceptor.attach(Module.findExportByName("libc.so", "pthread_mutex_lock"), {
  onEnter: function (args) {
    console.log("pthread_mutex_lock called with mutex:", args[0]);
    // 可以进一步检查调用栈等信息
    // console.log(Thread.backtrace().map(DebugSymbol.fromAddress).join('\\n'));
  },
  onLeave: function (retval) {
    console.log("pthread_mutex_lock returned:", retval);
  }
});
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_mutex.js`）。
2. 使用 Frida 连接到目标 Android 进程： `frida -U -f <package_name> -l hook_mutex.js --no-pause`  （替换 `<package_name>` 为你的应用包名）。

这个示例会在每次调用 `pthread_mutex_lock` 时打印出互斥锁的地址和返回值。你可以根据需要 hook 其他 `pthread` 函数，例如 `pthread_rwlock_rdlock`, `pthread_cond_wait` 等，来观察它们的行为。

**总结这段代码的功能：**

总而言之，这段代码是 Android bionic 库中关于 `pthread` 读写锁、`pthread_once` 初始化、`pthread_atfork`、部分线程属性和条件变量功能的单元测试。它通过各种测试用例验证了这些 API 的正确性和在不同场景下的行为，确保了 Android 系统中多线程编程的可靠性。 这些测试覆盖了基本操作、超时机制、不同时钟源的使用以及与 `fork` 相关的处理，同时也考虑了非便携的扩展功能。

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
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
rwlock_timedwrlock_monotonic_np not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_rwlock_reader_wakeup_writer_clockwait) {
#if defined(__BIONIC__)
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
  ts.tv_sec += 1;
  test_pthread_rwlock_reader_wakeup_writer([&](pthread_rwlock_t* lock) {
    return pthread_rwlock_clockwrlock(lock, CLOCK_MONOTONIC, &ts);
  });

  ASSERT_EQ(0, clock_gettime(CLOCK_REALTIME, &ts));
  ts.tv_sec += 1;
  test_pthread_rwlock_reader_wakeup_writer([&](pthread_rwlock_t* lock) {
    return pthread_rwlock_clockwrlock(lock, CLOCK_REALTIME, &ts);
  });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_clockwrlock not available";
#endif  // __BIONIC__
}

static void test_pthread_rwlock_writer_wakeup_reader(std::function<int (pthread_rwlock_t*)> lock_function) {
  RwlockWakeupHelperArg wakeup_arg;
  ASSERT_EQ(0, pthread_rwlock_init(&wakeup_arg.lock, nullptr));
  ASSERT_EQ(0, pthread_rwlock_wrlock(&wakeup_arg.lock));
  wakeup_arg.progress = RwlockWakeupHelperArg::LOCK_INITIALIZED;
  wakeup_arg.tid = 0;
  wakeup_arg.trylock_function = &pthread_rwlock_tryrdlock;
  wakeup_arg.lock_function = lock_function;

  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
    reinterpret_cast<void* (*)(void*)>(pthread_rwlock_wakeup_helper), &wakeup_arg));
  WaitUntilThreadSleep(wakeup_arg.tid);
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_WAITING, wakeup_arg.progress);

  wakeup_arg.progress = RwlockWakeupHelperArg::LOCK_RELEASED;
  ASSERT_EQ(0, pthread_rwlock_unlock(&wakeup_arg.lock));

  ASSERT_EQ(0, pthread_join(thread, nullptr));
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_ACCESSED, wakeup_arg.progress);
  ASSERT_EQ(0, pthread_rwlock_destroy(&wakeup_arg.lock));
}

TEST(pthread, pthread_rwlock_writer_wakeup_reader) {
  test_pthread_rwlock_writer_wakeup_reader(pthread_rwlock_rdlock);
}

TEST(pthread, pthread_rwlock_writer_wakeup_reader_timedwait) {
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_REALTIME, &ts));
  ts.tv_sec += 1;
  test_pthread_rwlock_writer_wakeup_reader([&](pthread_rwlock_t* lock) {
    return pthread_rwlock_timedrdlock(lock, &ts);
  });
}

TEST(pthread, pthread_rwlock_writer_wakeup_reader_timedwait_monotonic_np) {
#if defined(__BIONIC__)
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
  ts.tv_sec += 1;
  test_pthread_rwlock_writer_wakeup_reader(
      [&](pthread_rwlock_t* lock) { return pthread_rwlock_timedrdlock_monotonic_np(lock, &ts); });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_timedrdlock_monotonic_np not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_rwlock_writer_wakeup_reader_clockwait) {
#if defined(__BIONIC__)
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
  ts.tv_sec += 1;
  test_pthread_rwlock_writer_wakeup_reader([&](pthread_rwlock_t* lock) {
    return pthread_rwlock_clockrdlock(lock, CLOCK_MONOTONIC, &ts);
  });

  ASSERT_EQ(0, clock_gettime(CLOCK_REALTIME, &ts));
  ts.tv_sec += 1;
  test_pthread_rwlock_writer_wakeup_reader([&](pthread_rwlock_t* lock) {
    return pthread_rwlock_clockrdlock(lock, CLOCK_REALTIME, &ts);
  });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_clockrdlock not available";
#endif  // __BIONIC__
}

static void pthread_rwlock_wakeup_timeout_helper(RwlockWakeupHelperArg* arg) {
  arg->tid = gettid();
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_INITIALIZED, arg->progress);
  arg->progress = RwlockWakeupHelperArg::LOCK_WAITING;

  ASSERT_EQ(EBUSY, arg->trylock_function(&arg->lock));

  timespec ts;
  ASSERT_EQ(0, clock_gettime(arg->clock, &ts));
  ASSERT_EQ(ETIMEDOUT, arg->timed_lock_function(&arg->lock, &ts));
  ts.tv_nsec = -1;
  ASSERT_EQ(EINVAL, arg->timed_lock_function(&arg->lock, &ts));
  ts.tv_nsec = NS_PER_S;
  ASSERT_EQ(EINVAL, arg->timed_lock_function(&arg->lock, &ts));
  ts.tv_nsec = NS_PER_S - 1;
  ts.tv_sec = -1;
  ASSERT_EQ(ETIMEDOUT, arg->timed_lock_function(&arg->lock, &ts));
  ASSERT_EQ(0, clock_gettime(arg->clock, &ts));
  ts.tv_sec += 1;
  ASSERT_EQ(ETIMEDOUT, arg->timed_lock_function(&arg->lock, &ts));
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_WAITING, arg->progress);
  arg->progress = RwlockWakeupHelperArg::LOCK_TIMEDOUT;
}

static void pthread_rwlock_timedrdlock_timeout_helper(
    clockid_t clock, int (*lock_function)(pthread_rwlock_t* __rwlock, const timespec* __timeout)) {
  RwlockWakeupHelperArg wakeup_arg;
  ASSERT_EQ(0, pthread_rwlock_init(&wakeup_arg.lock, nullptr));
  ASSERT_EQ(0, pthread_rwlock_wrlock(&wakeup_arg.lock));
  wakeup_arg.progress = RwlockWakeupHelperArg::LOCK_INITIALIZED;
  wakeup_arg.tid = 0;
  wakeup_arg.trylock_function = &pthread_rwlock_tryrdlock;
  wakeup_arg.timed_lock_function = lock_function;
  wakeup_arg.clock = clock;

  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
      reinterpret_cast<void* (*)(void*)>(pthread_rwlock_wakeup_timeout_helper), &wakeup_arg));
  WaitUntilThreadSleep(wakeup_arg.tid);
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_WAITING, wakeup_arg.progress);

  ASSERT_EQ(0, pthread_join(thread, nullptr));
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_TIMEDOUT, wakeup_arg.progress);
  ASSERT_EQ(0, pthread_rwlock_unlock(&wakeup_arg.lock));
  ASSERT_EQ(0, pthread_rwlock_destroy(&wakeup_arg.lock));
}

TEST(pthread, pthread_rwlock_timedrdlock_timeout) {
  pthread_rwlock_timedrdlock_timeout_helper(CLOCK_REALTIME, pthread_rwlock_timedrdlock);
}

TEST(pthread, pthread_rwlock_timedrdlock_monotonic_np_timeout) {
#if defined(__BIONIC__)
  pthread_rwlock_timedrdlock_timeout_helper(CLOCK_MONOTONIC,
                                            pthread_rwlock_timedrdlock_monotonic_np);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_timedrdlock_monotonic_np not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_rwlock_clockrdlock_monotonic_timeout) {
#if defined(__BIONIC__)
  pthread_rwlock_timedrdlock_timeout_helper(
      CLOCK_MONOTONIC, [](pthread_rwlock_t* __rwlock, const timespec* __timeout) {
        return pthread_rwlock_clockrdlock(__rwlock, CLOCK_MONOTONIC, __timeout);
      });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_clockrdlock not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_rwlock_clockrdlock_realtime_timeout) {
#if defined(__BIONIC__)
  pthread_rwlock_timedrdlock_timeout_helper(
      CLOCK_REALTIME, [](pthread_rwlock_t* __rwlock, const timespec* __timeout) {
        return pthread_rwlock_clockrdlock(__rwlock, CLOCK_REALTIME, __timeout);
      });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_clockrdlock not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_rwlock_clockrdlock_invalid) {
#if defined(__BIONIC__)
  pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
  timespec ts;
  EXPECT_EQ(EINVAL, pthread_rwlock_clockrdlock(&lock, CLOCK_PROCESS_CPUTIME_ID, &ts));
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_clockrdlock not available";
#endif  // __BIONIC__
}

static void pthread_rwlock_timedwrlock_timeout_helper(
    clockid_t clock, int (*lock_function)(pthread_rwlock_t* __rwlock, const timespec* __timeout)) {
  RwlockWakeupHelperArg wakeup_arg;
  ASSERT_EQ(0, pthread_rwlock_init(&wakeup_arg.lock, nullptr));
  ASSERT_EQ(0, pthread_rwlock_rdlock(&wakeup_arg.lock));
  wakeup_arg.progress = RwlockWakeupHelperArg::LOCK_INITIALIZED;
  wakeup_arg.tid = 0;
  wakeup_arg.trylock_function = &pthread_rwlock_trywrlock;
  wakeup_arg.timed_lock_function = lock_function;
  wakeup_arg.clock = clock;

  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
      reinterpret_cast<void* (*)(void*)>(pthread_rwlock_wakeup_timeout_helper), &wakeup_arg));
  WaitUntilThreadSleep(wakeup_arg.tid);
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_WAITING, wakeup_arg.progress);

  ASSERT_EQ(0, pthread_join(thread, nullptr));
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_TIMEDOUT, wakeup_arg.progress);
  ASSERT_EQ(0, pthread_rwlock_unlock(&wakeup_arg.lock));
  ASSERT_EQ(0, pthread_rwlock_destroy(&wakeup_arg.lock));
}

TEST(pthread, pthread_rwlock_timedwrlock_timeout) {
  pthread_rwlock_timedwrlock_timeout_helper(CLOCK_REALTIME, pthread_rwlock_timedwrlock);
}

TEST(pthread, pthread_rwlock_timedwrlock_monotonic_np_timeout) {
#if defined(__BIONIC__)
  pthread_rwlock_timedwrlock_timeout_helper(CLOCK_MONOTONIC,
                                            pthread_rwlock_timedwrlock_monotonic_np);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_timedwrlock_monotonic_np not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_rwlock_clockwrlock_monotonic_timeout) {
#if defined(__BIONIC__)
  pthread_rwlock_timedwrlock_timeout_helper(
      CLOCK_MONOTONIC, [](pthread_rwlock_t* __rwlock, const timespec* __timeout) {
        return pthread_rwlock_clockwrlock(__rwlock, CLOCK_MONOTONIC, __timeout);
      });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_clockwrlock not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_rwlock_clockwrlock_realtime_timeout) {
#if defined(__BIONIC__)
  pthread_rwlock_timedwrlock_timeout_helper(
      CLOCK_REALTIME, [](pthread_rwlock_t* __rwlock, const timespec* __timeout) {
        return pthread_rwlock_clockwrlock(__rwlock, CLOCK_REALTIME, __timeout);
      });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_clockwrlock not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_rwlock_clockwrlock_invalid) {
#if defined(__BIONIC__)
  pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
  timespec ts;
  EXPECT_EQ(EINVAL, pthread_rwlock_clockwrlock(&lock, CLOCK_PROCESS_CPUTIME_ID, &ts));
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_rwlock_clockrwlock not available";
#endif  // __BIONIC__
}

#if !defined(ANDROID_HOST_MUSL)
// musl doesn't have pthread_rwlockattr_setkind_np
class RwlockKindTestHelper {
 private:
  struct ThreadArg {
    RwlockKindTestHelper* helper;
    std::atomic<pid_t>& tid;

    ThreadArg(RwlockKindTestHelper* helper, std::atomic<pid_t>& tid)
      : helper(helper), tid(tid) { }
  };

 public:
  pthread_rwlock_t lock;

 public:
  explicit RwlockKindTestHelper(int kind_type) {
    InitRwlock(kind_type);
  }

  ~RwlockKindTestHelper() {
    DestroyRwlock();
  }

  void CreateWriterThread(pthread_t& thread, std::atomic<pid_t>& tid) {
    tid = 0;
    ThreadArg* arg = new ThreadArg(this, tid);
    ASSERT_EQ(0, pthread_create(&thread, nullptr,
                                reinterpret_cast<void* (*)(void*)>(WriterThreadFn), arg));
  }

  void CreateReaderThread(pthread_t& thread, std::atomic<pid_t>& tid) {
    tid = 0;
    ThreadArg* arg = new ThreadArg(this, tid);
    ASSERT_EQ(0, pthread_create(&thread, nullptr,
                                reinterpret_cast<void* (*)(void*)>(ReaderThreadFn), arg));
  }

 private:
  void InitRwlock(int kind_type) {
    pthread_rwlockattr_t attr;
    ASSERT_EQ(0, pthread_rwlockattr_init(&attr));
    ASSERT_EQ(0, pthread_rwlockattr_setkind_np(&attr, kind_type));
    ASSERT_EQ(0, pthread_rwlock_init(&lock, &attr));
    ASSERT_EQ(0, pthread_rwlockattr_destroy(&attr));
  }

  void DestroyRwlock() {
    ASSERT_EQ(0, pthread_rwlock_destroy(&lock));
  }

  static void WriterThreadFn(ThreadArg* arg) {
    arg->tid = gettid();

    RwlockKindTestHelper* helper = arg->helper;
    ASSERT_EQ(0, pthread_rwlock_wrlock(&helper->lock));
    ASSERT_EQ(0, pthread_rwlock_unlock(&helper->lock));
    delete arg;
  }

  static void ReaderThreadFn(ThreadArg* arg) {
    arg->tid = gettid();

    RwlockKindTestHelper* helper = arg->helper;
    ASSERT_EQ(0, pthread_rwlock_rdlock(&helper->lock));
    ASSERT_EQ(0, pthread_rwlock_unlock(&helper->lock));
    delete arg;
  }
};
#endif

TEST(pthread, pthread_rwlock_kind_PTHREAD_RWLOCK_PREFER_READER_NP) {
#if !defined(ANDROID_HOST_MUSL)
  RwlockKindTestHelper helper(PTHREAD_RWLOCK_PREFER_READER_NP);
  ASSERT_EQ(0, pthread_rwlock_rdlock(&helper.lock));

  pthread_t writer_thread;
  std::atomic<pid_t> writer_tid;
  helper.CreateWriterThread(writer_thread, writer_tid);
  WaitUntilThreadSleep(writer_tid);

  pthread_t reader_thread;
  std::atomic<pid_t> reader_tid;
  helper.CreateReaderThread(reader_thread, reader_tid);
  ASSERT_EQ(0, pthread_join(reader_thread, nullptr));

  ASSERT_EQ(0, pthread_rwlock_unlock(&helper.lock));
  ASSERT_EQ(0, pthread_join(writer_thread, nullptr));
#else
  GTEST_SKIP() << "musl doesn't have pthread_rwlockattr_setkind_np";
#endif
}

TEST(pthread, pthread_rwlock_kind_PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP) {
#if !defined(ANDROID_HOST_MUSL)
  RwlockKindTestHelper helper(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
  ASSERT_EQ(0, pthread_rwlock_rdlock(&helper.lock));

  pthread_t writer_thread;
  std::atomic<pid_t> writer_tid;
  helper.CreateWriterThread(writer_thread, writer_tid);
  WaitUntilThreadSleep(writer_tid);

  pthread_t reader_thread;
  std::atomic<pid_t> reader_tid;
  helper.CreateReaderThread(reader_thread, reader_tid);
  WaitUntilThreadSleep(reader_tid);

  ASSERT_EQ(0, pthread_rwlock_unlock(&helper.lock));
  ASSERT_EQ(0, pthread_join(writer_thread, nullptr));
  ASSERT_EQ(0, pthread_join(reader_thread, nullptr));
#else
  GTEST_SKIP() << "musl doesn't have pthread_rwlockattr_setkind_np";
#endif
}

static int g_once_fn_call_count = 0;
static void OnceFn() {
  ++g_once_fn_call_count;
}

TEST(pthread, pthread_once_smoke) {
  pthread_once_t once_control = PTHREAD_ONCE_INIT;
  ASSERT_EQ(0, pthread_once(&once_control, OnceFn));
  ASSERT_EQ(0, pthread_once(&once_control, OnceFn));
  ASSERT_EQ(1, g_once_fn_call_count);
}

static std::string pthread_once_1934122_result = "";

static void Routine2() {
  pthread_once_1934122_result += "2";
}

static void Routine1() {
  pthread_once_t once_control_2 = PTHREAD_ONCE_INIT;
  pthread_once_1934122_result += "1";
  pthread_once(&once_control_2, &Routine2);
}

TEST(pthread, pthread_once_1934122) {
  // Very old versions of Android couldn't call pthread_once from a
  // pthread_once init routine. http://b/1934122.
  pthread_once_t once_control_1 = PTHREAD_ONCE_INIT;
  ASSERT_EQ(0, pthread_once(&once_control_1, &Routine1));
  ASSERT_EQ("12", pthread_once_1934122_result);
}

static int g_atfork_prepare_calls = 0;
static void AtForkPrepare1() { g_atfork_prepare_calls = (g_atfork_prepare_calls * 10) + 1; }
static void AtForkPrepare2() { g_atfork_prepare_calls = (g_atfork_prepare_calls * 10) + 2; }
static int g_atfork_parent_calls = 0;
static void AtForkParent1() { g_atfork_parent_calls = (g_atfork_parent_calls * 10) + 1; }
static void AtForkParent2() { g_atfork_parent_calls = (g_atfork_parent_calls * 10) + 2; }
static int g_atfork_child_calls = 0;
static void AtForkChild1() { g_atfork_child_calls = (g_atfork_child_calls * 10) + 1; }
static void AtForkChild2() { g_atfork_child_calls = (g_atfork_child_calls * 10) + 2; }

TEST(pthread, pthread_atfork_smoke_fork) {
  ASSERT_EQ(0, pthread_atfork(AtForkPrepare1, AtForkParent1, AtForkChild1));
  ASSERT_EQ(0, pthread_atfork(AtForkPrepare2, AtForkParent2, AtForkChild2));

  g_atfork_prepare_calls = g_atfork_parent_calls = g_atfork_child_calls = 0;
  pid_t pid = fork();
  ASSERT_NE(-1, pid) << strerror(errno);

  // Child and parent calls are made in the order they were registered.
  if (pid == 0) {
    ASSERT_EQ(12, g_atfork_child_calls);
    _exit(0);
  }
  ASSERT_EQ(12, g_atfork_parent_calls);

  // Prepare calls are made in the reverse order.
  ASSERT_EQ(21, g_atfork_prepare_calls);
  AssertChildExited(pid, 0);
}

TEST(pthread, pthread_atfork_smoke_vfork) {
  ASSERT_EQ(0, pthread_atfork(AtForkPrepare1, AtForkParent1, AtForkChild1));
  ASSERT_EQ(0, pthread_atfork(AtForkPrepare2, AtForkParent2, AtForkChild2));

  g_atfork_prepare_calls = g_atfork_parent_calls = g_atfork_child_calls = 0;
  pid_t pid = vfork();
  ASSERT_NE(-1, pid) << strerror(errno);

  // atfork handlers are not called.
  if (pid == 0) {
    ASSERT_EQ(0, g_atfork_child_calls);
    _exit(0);
  }
  ASSERT_EQ(0, g_atfork_parent_calls);
  ASSERT_EQ(0, g_atfork_prepare_calls);
  AssertChildExited(pid, 0);
}

TEST(pthread, pthread_atfork_smoke__Fork) {
#if defined(__BIONIC__)
  ASSERT_EQ(0, pthread_atfork(AtForkPrepare1, AtForkParent1, AtForkChild1));
  ASSERT_EQ(0, pthread_atfork(AtForkPrepare2, AtForkParent2, AtForkChild2));

  g_atfork_prepare_calls = g_atfork_parent_calls = g_atfork_child_calls = 0;
  pid_t pid = _Fork();
  ASSERT_NE(-1, pid) << strerror(errno);

  // atfork handlers are not called.
  if (pid == 0) {
    ASSERT_EQ(0, g_atfork_child_calls);
    _exit(0);
  }
  ASSERT_EQ(0, g_atfork_parent_calls);
  ASSERT_EQ(0, g_atfork_prepare_calls);
  AssertChildExited(pid, 0);
#endif
}

TEST(pthread, pthread_attr_getscope) {
  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));

  int scope;
  ASSERT_EQ(0, pthread_attr_getscope(&attr, &scope));
  ASSERT_EQ(PTHREAD_SCOPE_SYSTEM, scope);
}

TEST(pthread, pthread_condattr_init) {
  pthread_condattr_t attr;
  pthread_condattr_init(&attr);

  clockid_t clock;
  ASSERT_EQ(0, pthread_condattr_getclock(&attr, &clock));
  ASSERT_EQ(CLOCK_REALTIME, clock);

  int pshared;
  ASSERT_EQ(0, pthread_condattr_getpshared(&attr, &pshared));
  ASSERT_EQ(PTHREAD_PROCESS_PRIVATE, pshared);
}

TEST(pthread, pthread_condattr_setclock) {
  pthread_condattr_t attr;
  pthread_condattr_init(&attr);

  ASSERT_EQ(0, pthread_condattr_setclock(&attr, CLOCK_REALTIME));
  clockid_t clock;
  ASSERT_EQ(0, pthread_condattr_getclock(&attr, &clock));
  ASSERT_EQ(CLOCK_REALTIME, clock);

  ASSERT_EQ(0, pthread_condattr_setclock(&attr, CLOCK_MONOTONIC));
  ASSERT_EQ(0, pthread_condattr_getclock(&attr, &clock));
  ASSERT_EQ(CLOCK_MONOTONIC, clock);

  ASSERT_EQ(EINVAL, pthread_condattr_setclock(&attr, CLOCK_PROCESS_CPUTIME_ID));
}

TEST(pthread, pthread_cond_broadcast__preserves_condattr_flags) {
#if defined(__BIONIC__)
  pthread_condattr_t attr;
  pthread_condattr_init(&attr);

  ASSERT_EQ(0, pthread_condattr_setclock(&attr, CLOCK_MONOTONIC));
  ASSERT_EQ(0, pthread_condattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));

  pthread_cond_t cond_var;
  ASSERT_EQ(0, pthread_cond_init(&cond_var, &attr));

  ASSERT_EQ(0, pthread_cond_signal(&cond_var));
  ASSERT_EQ(0, pthread_cond_broadcast(&cond_var));

  attr = static_cast<pthread_condattr_t>(*reinterpret_cast<uint32_t*>(cond_var.__private));
  clockid_t clock;
  ASSERT_EQ(0, pthread_condattr_getclock(&attr, &clock));
  ASSERT_EQ(CLOCK_MONOTONIC, clock);
  int pshared;
  ASSERT_EQ(0, pthread_condattr_getpshared(&attr, &pshared));
  ASSERT_EQ(PTHREAD_PROCESS_SHARED, pshared);
#else  // !defined(__BIONIC__)
  GTEST_SKIP() << "bionic-only test";
#endif  // !defined(__BIONIC__)
}

class pthread_CondWakeupTest : public ::testing::Test {
 protected:
  pthread_mutex_t mutex;
  pthread_cond_t cond;

  enum Progress {
    INITIALIZED,
    WAITING,
    SIGNALED,
    FINISHED,
  };
  std::atomic<Progress> progress;
  pthread_t thread;
  timespec ts;
  std::function<int (pthread_cond_t* cond, pthread_mutex_t* mutex)> wait_function;

 protected:
  void SetUp() override {
    ASSERT_EQ(0, pthread_mutex_init(&mutex, nullptr));
  }

  void InitCond(clockid_t clock=CLOCK_REALTIME) {
    pthread_condattr_t attr;
    ASSERT_EQ(0, pthread_condattr_init(&attr));
    ASSERT_EQ(0, pthread_condattr_setclock(&attr, clock));
    ASSERT_EQ(0, pthread_cond_init(&cond, &attr));
    ASSERT_EQ(0, pthread_condattr_destroy(&attr));
  }

  void StartWaitingThread(
      std::function<int(pthread_cond_t* cond, pthread_mutex_t* mutex)> wait_function) {
    progress = INITIALIZED;
    this->wait_function = wait_function;
    ASSERT_EQ(0, pthread_create(&thread, nullptr, reinterpret_cast<void* (*)(void*)>(WaitThreadFn),
                                this));
    while (progress != WAITING) {
      usleep(5000);
    }
    usleep(5000);
  }

  void RunTimedTest(
      clockid_t clock,
      std::function<int(pthread_cond_t* cond, pthread_mutex_t* mutex, const timespec* timeout)>
          wait_function) {
    ASSERT_EQ(0, clock_gettime(clock, &ts));
    ts.tv_sec += 1;

    StartWaitingThread([&wait_function, this](pthread_cond_t* cond, pthread_mutex_t* mutex) {
      return wait_function(cond, mutex, &ts);
    });

    progress = SIGNALED;
    ASSERT_EQ(0, pthread_cond_signal(&cond));
  }

  void RunTimedTest(clockid_t clock, std::function<int(pthread_cond_t* cond, pthread_mutex_t* mutex,
                                                       clockid_t clock, const timespec* timeout)>
                                         wait_function) {
    RunTimedTest(clock, [clock, &wait_function](pthread_cond_t* cond, pthread_mutex_t* mutex,
                                                const timespec* timeout) {
      return wait_function(cond, mutex, clock, timeout);
    });
  }

  void TearDown() override {
    ASSERT_EQ(0, pthread_join(thread, nullptr));
    ASSERT_EQ(FINISHED, progress);
    ASSERT_EQ(0, pthread_cond_destroy(&cond));
    ASSERT_EQ(0, pthread_mutex_destroy(&mutex));
  }

 private:
  static void WaitThreadFn(pthread_CondWakeupTest* test) {
    ASSERT_EQ(0, pthread_mutex_lock(&test->mutex));
    test->progress = WAITING;
    while (test->progress == WAITING) {
      ASSERT_EQ(0, test->wait_function(&test->cond, &test->mutex));
    }
    ASSERT_EQ(SIGNALED, test->progress);
    test->progress = FINISHED;
    ASSERT_EQ(0, pthread_mutex_unlock(&test->mutex));
  }
};

TEST_F(pthread_CondWakeupTest, signal_wait) {
  InitCond();
  StartWaitingThread([](pthread_cond_t* cond, pthread_mutex_t* mutex) {
    return pthread_cond_wait(cond, mutex);
  });
  progress = SIGNALED;
  ASSERT_EQ(0, pthread_cond_signal(&cond));
}

TEST_F(pthread_CondWakeupTest, broadcast_wait) {
  InitCond();
  StartWaitingThread([](pthread_cond_t* cond, pthread_mutex_t* mutex) {
    return pthread_cond_wait(cond, mutex);
  });
  progress = SIGNALED;
  ASSERT_EQ(0, pthread_cond_broadcast(&cond));
}

TEST_F(pthread_CondWakeupTest, signal_timedwait_CLOCK_REALTIME) {
  InitCond(CLOCK_REALTIME);
  RunTimedTest(CLOCK_REALTIME, pthread_cond_timedwait);
}

TEST_F(pthread_CondWakeupTest, signal_timedwait_CLOCK_MONOTONIC) {
  InitCond(CLOCK_MONOTONIC);
  RunTimedTest(CLOCK_MONOTONIC, pthread_cond_timedwait);
}

TEST_F(pthread_CondWakeupTest, signal_timedwait_CLOCK_MONOTONIC_np) {
#if defined(__BIONIC__)
  InitCond(CLOCK_REALTIME);
  RunTimedTest(CLOCK_MONOTONIC, pthread_cond_timedwait_monotonic_np);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_cond_timedwait_monotonic_np not available";
#endif  // __BIONIC__
}

TEST_F(pthread_CondWakeupTest, signal_clockwait_monotonic_monotonic) {
#if defined(__BIONIC__)
  InitCond(CLOCK_MONOTONIC);
  RunTimedTest(CLOCK_MONOTONIC, pthread_cond_clockwait);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_cond_clockwait not available";
#endif  // __BIONIC__
}

TEST_F(pthread_CondWakeupTest, signal_clockwait_monotonic_realtime) {
#if defined(__BIONIC__)
  InitCond(CLOCK_MONOTONIC);
  RunTimedTest(CLOCK_REALTIME, pthread_cond_clockwait);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_cond_clockwait not available";
#endif  // __BIONIC__
}

TEST_F(pthread_CondWakeupTest, signal_clockwait_realtime_monotonic) {
#if defined(__BIONIC__)
  InitCond(CLOCK_REALTIME);
  RunTimedTest(CLOCK_MONOTONIC, pthread_cond_clockwait);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_cond_clockwait not available";
#endif  // __BIONIC__
}

TEST_F(pthread_CondWakeupTest, signal_clockwait_realtime_realtime) {
#if defined(__BIONIC__)
  InitCond(CLOCK_REALTIME);
  RunTimedTest(CLOCK_REALTIME, pthread_cond_clockwait);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_cond_clockwait not available";
#endif  // __BIONIC__
}

static void pthread_cond_timedwait_timeout_helper(bool init_monotonic, clockid_t clock,
                                                  int (*wait_function)(pthread_cond_t* __cond,
                                                                       pthread_mutex_t* __mutex,
                                                                       const timespec* __timeout)) {
  pthread_mutex_t mutex;
  ASSERT_EQ(0, pthread_mutex_init(&mutex, nullptr));
  pthread_cond_t cond;

  if (init_monotonic) {
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);

    ASSERT_EQ(0, pthread_condattr_setclock(&attr, CLOCK_MONOTONIC));
    clockid_t clock;
    ASSERT_EQ(0, pthread_condattr_getclock(&attr, &clock));
    ASSERT_EQ(CLOCK_MONOTONIC, clock);

    ASSERT_EQ(0, pthread_cond_init(&cond, &attr));
  } else {
    ASSERT_EQ(0, pthread_cond_init(&cond, nullptr));
  }
  ASSERT_EQ(0, pthread_mutex_lock(&mutex));

  timespec ts;
  ASSERT_EQ(0, clock_gettime(clock, &ts));
  ASSERT_EQ(ETIMEDOUT, wait_function(&cond, &mutex, &ts));
  ts.tv_nsec = -1;
  ASSERT_EQ(EINVAL, wait_function(&cond, &mutex, &ts));
  ts.tv_nsec = NS_PER_S;
  ASSERT_EQ(EINVAL, wait_function(&cond, &mutex, &ts));
  ts.tv_nsec = NS_PER_S - 1;
  ts.tv_sec = -1;
  ASSERT_EQ(ETIMEDOUT, wait_function(&cond, &mutex, &ts));
  ASSERT_EQ(0, pthread_mutex_unlock(&mutex));
}

TEST(pthread, pthread_cond_timedwait_timeout) {
  pthread_cond_timedwait_timeout_helper(false, CLOCK_REALTIME, pthread_cond_timedwait);
}

TEST(pthread, pthread_cond_timedwait_monotonic_np_timeout) {
#if defined(__BIONIC__)
  pthread_cond_timedwait_timeout_helper(false, CLOCK_MONOTONIC, pthread_cond_timedwait_monotonic_np);
  pthread_cond_timedwait_timeout_helper(true, CLOCK_MONOTONIC, pthread_cond_timedwait_monotonic_np);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_cond_timedwait_monotonic_np not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_cond_clockwait_timeout) {
#if defined(__BIONIC__)
  pthread_cond_timedwait_timeout_helper(
      false, CLOCK_MONOTONIC,
      [](pthread_cond_t* __cond, pthread_mutex_t* __mutex, const timespec* __timeout) {
        return pthread_cond_clockwait(__cond, __mutex, CLOCK_MONOTONIC, __timeout);
      });
  pthread_cond_timedwait_timeout_helper(
      true, CLOCK_MONOTONIC,
      [](pthread_cond_t* __cond, pthread_mutex_t* __mutex, const timespec* __timeout) {
        return pthread_cond_clockwait(__cond, __mutex, CLOCK_MONOTONIC, __timeout);
      });
  pthread_cond_timedwait_timeout_helper(
      false, CLOCK_REALTIME,
      [](pthread_cond_t* __cond, pthread_mutex_t* __mutex, const timespec* __timeout) {
        return pthread_cond_clockwait(__cond, __mutex, CLOCK_REALTIME, __timeout);
      });
  pthread_cond_timedwait_timeout_helper(
      true, CLOCK_REALTIME,
      [](pthread_cond_t* __cond, pthread_mutex_t* __mutex, const timespec* __timeout) {
        return pthread_cond_clockwait(__cond, __mutex, CLOCK_REALTIME, __timeout);
      });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_cond_clockwait not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_cond_clockwait_invalid) {
#if defined(__BIONIC__)
  pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  timespec ts;
  EXPECT_EQ(EINVAL, pthread_cond_clockwait(&cond, &mutex, CLOCK_PROCESS_CPUTIME_ID, &ts));

#else   // __BIONIC__
  GTEST_SKIP() << "pthread_cond_clockwait not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_attr_getstack__main_thread) {
  // This test is only meaningful for the main thread, so make sure we're running on it!
  ASSERT_EQ(getpid(), syscall(__NR_gettid));

  // Get the main thread's attributes.
  pthread_attr_t attributes;
  ASSERT_EQ(0, pthread_getattr_np(pthread_self(), &attributes));

  // Check that we correctly report that the main thread has no guard page.
  size_t guard_size;
  ASSERT_EQ(0, pthread_attr_getguardsize(&attributes, &guard_size));
  ASSERT_EQ(0U, guard_size); // The main thread has no guard page.

  // Get the stack base and the stack size (both ways).
  void* stack_base;
  size_t stack_size;
  ASSERT_EQ(0, pthread_attr_getstack(&attributes, &stack_base, &stack_size));
  size_t stack_size2;
  ASSERT_EQ(0, pthread_attr_getstacksize(&attributes, &stack_size2));

  // The two methods of asking for the stack size should agree.
  EXPECT_EQ(stack_size, stack_size2);

#if defined(__BIONIC__)
  // Find stack in /proc/self/maps using a pointer to the stack.
  //
  // We do not use "[stack]" label because in native-bridge environment it is not
  // guaranteed to point to the right stack. A native bridge implementation may
  // keep separate stack for the guest code.
  void* maps_stack_hi = nullptr;
  std::vector<map_record> maps;
  ASSERT_TRUE(Maps::parse_maps(&maps));
  uintptr_t stack_address = reinterpret_cast<uintptr_t>(untag_address(&maps_stack_hi));
  for (const auto& map : maps) {
    if (map.addr_start <= stack_address && map.addr_end > stack_address){
      maps_stack_hi = reinterpret_cast<void*>(map.addr_end);
      break;
    }
  }

  // The high address of the /proc/self/maps stack region should equal stack_base + stack_size.
  // Remember that the stack grows down (and is mapped in on demand), so the low address of the
  // region isn't very interesting.
  EXPECT_EQ(maps_stack_hi, reinterpret_cast<uint8_t*>(stack_base) + stack_size);

  // The stack size should correspond to RLIMIT_STACK.
  rlimit rl;
  ASSERT_EQ(0, getrlimit(RLIMIT_STACK, &rl));
  uint64_t original_rlim_cur = rl.rlim_cur;
  if (rl.rlim_cur == RLIM_INFINITY) {
    rl.rlim_cur = 8 * 1024 * 1024; // Bionic reports unlimited stacks as 8MiB.
  }
  EXPECT_EQ(rl.rlim_cur, stack_size);

  auto guard = android::base::make_scope_guard([&rl, original_rlim_cur]() {
    rl.rlim_cur = original_rlim_cur;
    ASSERT_EQ(0, setrlimit(RLIMIT_STACK, &rl));
  });

  //
  // What if RLIMIT_STACK is smaller than the stack's current extent?
  //
  rl.rlim_cur = rl.rlim_max = 1024; // 1KiB. We know the stack must be at least a page already.
  rl.rlim_max = RLIM_INFINITY;
  ASSERT_EQ(0, setrlimit(RLIMIT_STACK, &rl));

  ASSERT_EQ(0, pthread_getattr_np(pthread_self(), &attributes));
  ASSERT_EQ(0, pthread_attr_getstack(&attributes, &stack_base, &stack_size));
  ASSERT_EQ(0, pthread_attr_getstacksize(&attributes, &stack_size2));

  EXPECT_EQ(stack_size, stack_size2);
  ASSERT_EQ(1024U, stack_size);

  //
  // What if RLIMIT_STACK isn't a whole number of pages?
  //
  rl.rlim_cur = rl.rlim_max = 6666; // Not a whole number of pages.
  rl.rlim_max = RLIM_INFINITY;
  ASSERT_EQ(0, setrlimit(RLIMIT_STACK, &rl));

  ASSERT_EQ(0, pthread_getattr_np(pthread_self(), &attributes));
  ASSERT_EQ(0, pthread_attr_getstack(&attributes, &stack_base, &stack_size));
  ASSERT_EQ(0, pthread_attr_getstacksize(&attributes, &stack_size2));

  EXPECT_EQ(stack_size, stack_size2);
  ASSERT_EQ(6666U, stack_size);
#endif
}

struct GetStackSignalHandlerArg {
  volatile bool done;
  void* signal_stack_base;
  size_t signal_stack_size;
  void* main_stack_base;
  size_t main_stack_size;
};

static GetStackSignalHandlerArg getstack_signal_handler_arg;

static void getstack_signal_handler(int sig) {
  ASSERT_EQ(SIGUSR1, sig);
  // Use sleep() to make current thread be switched out by the kernel to provoke the error.
  sleep(1);
  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_getattr_np(pthread_self(), &attr));
  void* stack_base;
  size_t stack_size;
  ASSERT_EQ(0, pthread_attr_getstack(&attr, &stack_base, &stack_size));

  // Verify if the stack used by the signal handler is the alternate stack just registered.
  ASSERT_LE(getstack_signal_handler_arg.signal_stack_base, &attr);
  ASSERT_LT(static_cast<void*>(untag_address(&attr)),
            static_cast<char*>(getstack_signal_handler_arg.signal_stack_base) +
                getstack_signal_handler_arg.signal_stack_size);

  // Verify if the main thread's stack got in the signal handler is correct.
  ASSERT_EQ(getstack_signal_handler_arg.main_stack_base, stack_base);
  ASSERT_LE(getstack_signal_handler_arg.main_stack_size, stack_size);

  getstack_signal_handler_arg.done = true;
}

// The previous code obtained the main thread's stack by reading the entry in
// /proc/self/task/<pid>/maps that was labeled [stack]. Unfortunately, on x86/x86_64, the kernel
// relies on sp0 in task state segment(tss) to label the stack map with [stack]. If the kernel
// switches a process while the main thread is in an alternate stack, then the kernel will label
// the wrong map with [stack]. This test verifies that when the above situation happens, the main
// thread's stack is found correctly.
TEST(pthread, pthread_attr_getstack_in_signal_handler) {
  // This test is only meaningful for the main thread, so make sure we're running on it!
  ASSERT_EQ(getpid(), syscall(__NR_gettid));

  const size_t sig_stack_size = 16 * 1024;
  void* sig_stack = mmap(nullptr, sig_stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);
  ASSERT_NE(MAP_FAILED, sig_stack);
  stack_t ss;
  ss.ss_sp = sig_stack;
  ss.ss_size = sig_stack_size;
  ss.ss_flags = 0;
  stack_t oss;
  ASSERT_EQ(0, sigaltstack(&ss, &oss));

  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_getattr_np(pthread_self(), &attr));
  void
```