Response:
The user has provided a code snippet from `bionic/tests/pthread_test.cpp` and asked for a summary of its functionality as part 3 of a 4-part series.

To summarize, I need to identify the main purpose of the tests within the provided code. The code primarily focuses on testing the functionality of various pthread APIs, especially related to mutexes and barriers.

Here's a breakdown of the tests:
- **`pthread_attr_getstack` tests**: Verify the correct retrieval of thread stack information.
- **`pthread_gettid_np` test**: Checks if the function correctly returns the thread ID.
- **`pthread_cleanup_push__pthread_cleanup_pop` test**: Validates the behavior of thread cleanup handlers.
- **Mutex attribute tests**:  Tests `pthread_mutexattr_gettype` and `pthread_mutexattr_protocol`.
- **Mutex locking tests**: Covers various mutex types (NORMAL, ERRORCHECK, RECURSIVE) and priority inheritance.
- **Mutex initialization tests**: Compares `pthread_mutex_init` with static initializers.
- **Mutex wakeup tests**: Verifies the correct waking of threads waiting on mutexes.
- **Priority inheritance tests**: Checks priority changes due to mutex locking.
- **Mutex owner tid limit test**: Checks platform-specific limits on mutex owner thread IDs.
- **Mutex timed lock tests**: Tests `pthread_mutex_timedlock`, `pthread_mutex_timedlock_monotonic_np`, and `pthread_mutex_clocklock`.
- **Destroyed mutex tests**:  Ensures proper behavior when attempting to use destroyed mutexes.
- **Mutex alignment test**:  Verifies that mutexes can be allocated with 4-byte alignment.
- **Null mutex tests**:  Tests the behavior of lock/unlock functions with null mutexes, distinguishing between 32-bit and 64-bit architectures.
- **Signal stack test**: Checks if the signal stack is large enough for backtracing and logging.
- **Barrier attribute test**: Tests basic barrier attribute operations.
- **Barrier synchronization tests**: Verifies the correct synchronization behavior of pthread barriers.
- **Barrier destruction test**: Checks the behavior of destroying a busy barrier.
- **Barrier ordering test**: Ensures that threads proceed in a synchronized order after a barrier.

Therefore, the main function of this part of the `pthread_test.cpp` file is to rigorously test the implementation of pthread mutexes and barriers in bionic, covering various scenarios and edge cases.
这部分代码主要集中在 **pthread 互斥锁 (mutex) 和 屏障 (barrier) 的功能测试**。它涵盖了互斥锁的各种属性、锁定和解锁行为，以及屏障的同步功能。

具体来说，这部分代码的功能可以归纳为以下几点：

1. **测试线程栈属性获取函数 `pthread_attr_getstack`**:  验证是否能正确获取线程的栈基地址和大小。包括在信号处理函数中使用备用栈的情况。

2. **测试获取线程 ID 函数 `pthread_gettid_np`**: 验证该函数是否能正确返回线程的线程 ID。

3. **测试线程清理处理函数 `pthread_cleanup_push` 和 `pthread_cleanup_pop`**: 验证线程退出时清理函数的执行顺序和机制。

4. **测试互斥锁属性的设置和获取**: 包括互斥锁类型 (`pthread_mutexattr_gettype`, `pthread_mutexattr_settype`) 和协议 (`pthread_mutexattr_getprotocol`, `pthread_mutexattr_setprotocol`)。

5. **测试不同类型互斥锁的锁定和解锁行为**:  包括普通锁 (`PTHREAD_MUTEX_NORMAL`)、错误检查锁 (`PTHREAD_MUTEX_ERRORCHECK`) 和递归锁 (`PTHREAD_MUTEX_RECURSIVE`)，以及在开启优先级继承 (`PTHREAD_PRIO_INHERIT`) 时的行为。

6. **测试互斥锁的初始化方式**: 比较使用 `pthread_mutex_init` 初始化和使用静态初始化宏 (`PTHREAD_MUTEX_INITIALIZER` 等) 的结果是否一致。

7. **测试互斥锁的唤醒机制**: 验证等待互斥锁的线程能否被正确唤醒。

8. **测试优先级继承对线程优先级的影响**: 验证当线程持有优先级继承互斥锁时，其优先级是否会提升。

9. **测试互斥锁所有者线程 ID 的限制**: 针对特定架构（例如 32 位 Bionic），测试互斥锁记录所有者线程 ID 的位数限制。

10. **测试带超时的互斥锁锁定函数**:  包括 `pthread_mutex_timedlock`, `pthread_mutex_timedlock_monotonic_np` 和 `pthread_mutex_clocklock`，验证超时功能是否正常工作，并测试不同的时钟源。

11. **测试对已销毁的互斥锁进行操作的行为**: 使用 `pthread_DeathTest` 验证对已销毁的互斥锁执行锁定、解锁等操作是否会导致程序终止。

12. **测试 pthread 类型允许 4 字节对齐**:  验证 pthread 的数据结构（如互斥锁、条件变量、读写锁）即使在 4 字节对齐的情况下也能正常工作，这主要是为了兼容旧版本。

13. **测试对 NULL 互斥锁进行锁定和解锁操作的行为**:  区分 32 位和 64 位架构，验证对 NULL 互斥锁进行操作时的返回值或是否会触发段错误。

14. **测试信号处理函数的栈大小**: 验证信号处理函数在备用栈上运行时是否有足够的空间进行栈回溯、日志记录和字符串格式化操作。

15. **测试屏障属性的设置和获取**: 包括进程共享属性 (`pthread_barrierattr_getpshared`, `pthread_barrierattr_setpshared`)。

16. **测试屏障的同步功能**: 验证多个线程能否在屏障处正确同步，并只有一个线程能获得 `PTHREAD_BARRIER_SERIAL_THREAD` 返回值。

17. **测试销毁忙碌的屏障**: 验证在有线程等待屏障时尝试销毁屏障会返回 `EBUSY` 错误。

18. **测试屏障的执行顺序**: 验证所有线程在通过屏障后，共享的数据能够保持同步更新的状态。

总而言之，这部分代码是 `bionic/tests/pthread_test.cpp` 中专门用于测试 pthread 库中互斥锁和屏障功能的单元测试，旨在确保这些并发原语在 Android 系统中能够正确可靠地工作。

Prompt: 
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
这是第3部分，共4部分，请归纳一下它的功能

"""
* main_stack_base;
  size_t main_stack_size;
  ASSERT_EQ(0, pthread_attr_getstack(&attr, &main_stack_base, &main_stack_size));

  ScopedSignalHandler handler(SIGUSR1, getstack_signal_handler, SA_ONSTACK);
  getstack_signal_handler_arg.done = false;
  getstack_signal_handler_arg.signal_stack_base = sig_stack;
  getstack_signal_handler_arg.signal_stack_size = sig_stack_size;
  getstack_signal_handler_arg.main_stack_base = main_stack_base;
  getstack_signal_handler_arg.main_stack_size = main_stack_size;
  kill(getpid(), SIGUSR1);
  ASSERT_EQ(true, getstack_signal_handler_arg.done);

  ASSERT_EQ(0, sigaltstack(&oss, nullptr));
  ASSERT_EQ(0, munmap(sig_stack, sig_stack_size));
}

static void pthread_attr_getstack_18908062_helper(void*) {
  char local_variable;
  pthread_attr_t attributes;
  pthread_getattr_np(pthread_self(), &attributes);
  void* stack_base;
  size_t stack_size;
  pthread_attr_getstack(&attributes, &stack_base, &stack_size);

  // Test whether &local_variable is in [stack_base, stack_base + stack_size).
  ASSERT_LE(reinterpret_cast<char*>(stack_base), &local_variable);
  ASSERT_LT(untag_address(&local_variable), reinterpret_cast<char*>(stack_base) + stack_size);
}

// Check whether something on stack is in the range of
// [stack_base, stack_base + stack_size). see b/18908062.
TEST(pthread, pthread_attr_getstack_18908062) {
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr,
            reinterpret_cast<void* (*)(void*)>(pthread_attr_getstack_18908062_helper),
            nullptr));
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

#if defined(__BIONIC__)
static pthread_mutex_t pthread_gettid_np_mutex = PTHREAD_MUTEX_INITIALIZER;

static void* pthread_gettid_np_helper(void* arg) {
  *reinterpret_cast<pid_t*>(arg) = gettid();

  // Wait for our parent to call pthread_gettid_np on us before exiting.
  pthread_mutex_lock(&pthread_gettid_np_mutex);
  pthread_mutex_unlock(&pthread_gettid_np_mutex);
  return nullptr;
}
#endif

TEST(pthread, pthread_gettid_np) {
#if defined(__BIONIC__)
  ASSERT_EQ(gettid(), pthread_gettid_np(pthread_self()));

  // Ensure the other thread doesn't exit until after we've called
  // pthread_gettid_np on it.
  pthread_mutex_lock(&pthread_gettid_np_mutex);

  pid_t t_gettid_result;
  pthread_t t;
  pthread_create(&t, nullptr, pthread_gettid_np_helper, &t_gettid_result);

  pid_t t_pthread_gettid_np_result = pthread_gettid_np(t);

  // Release the other thread and wait for it to exit.
  pthread_mutex_unlock(&pthread_gettid_np_mutex);
  ASSERT_EQ(0, pthread_join(t, nullptr));

  ASSERT_EQ(t_gettid_result, t_pthread_gettid_np_result);
#else
  GTEST_SKIP() << "pthread_gettid_np not available";
#endif
}

static size_t cleanup_counter = 0;

static void AbortCleanupRoutine(void*) {
  abort();
}

static void CountCleanupRoutine(void*) {
  ++cleanup_counter;
}

static void PthreadCleanupTester() {
  pthread_cleanup_push(CountCleanupRoutine, nullptr);
  pthread_cleanup_push(CountCleanupRoutine, nullptr);
  pthread_cleanup_push(AbortCleanupRoutine, nullptr);

  pthread_cleanup_pop(0); // Pop the abort without executing it.
  pthread_cleanup_pop(1); // Pop one count while executing it.
  ASSERT_EQ(1U, cleanup_counter);
  // Exit while the other count is still on the cleanup stack.
  pthread_exit(nullptr);

  // Calls to pthread_cleanup_pop/pthread_cleanup_push must always be balanced.
  pthread_cleanup_pop(0);
}

static void* PthreadCleanupStartRoutine(void*) {
  PthreadCleanupTester();
  return nullptr;
}

TEST(pthread, pthread_cleanup_push__pthread_cleanup_pop) {
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, PthreadCleanupStartRoutine, nullptr));
  ASSERT_EQ(0, pthread_join(t, nullptr));
  ASSERT_EQ(2U, cleanup_counter);
}

TEST(pthread, PTHREAD_MUTEX_DEFAULT_is_PTHREAD_MUTEX_NORMAL) {
  ASSERT_EQ(PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_DEFAULT);
}

TEST(pthread, pthread_mutexattr_gettype) {
  pthread_mutexattr_t attr;
  ASSERT_EQ(0, pthread_mutexattr_init(&attr));

  int attr_type;

  ASSERT_EQ(0, pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL));
  ASSERT_EQ(0, pthread_mutexattr_gettype(&attr, &attr_type));
  ASSERT_EQ(PTHREAD_MUTEX_NORMAL, attr_type);

  ASSERT_EQ(0, pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK));
  ASSERT_EQ(0, pthread_mutexattr_gettype(&attr, &attr_type));
  ASSERT_EQ(PTHREAD_MUTEX_ERRORCHECK, attr_type);

  ASSERT_EQ(0, pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE));
  ASSERT_EQ(0, pthread_mutexattr_gettype(&attr, &attr_type));
  ASSERT_EQ(PTHREAD_MUTEX_RECURSIVE, attr_type);

  ASSERT_EQ(0, pthread_mutexattr_destroy(&attr));
}

TEST(pthread, pthread_mutexattr_protocol) {
  pthread_mutexattr_t attr;
  ASSERT_EQ(0, pthread_mutexattr_init(&attr));

  int protocol;
  ASSERT_EQ(0, pthread_mutexattr_getprotocol(&attr, &protocol));
  ASSERT_EQ(PTHREAD_PRIO_NONE, protocol);
  for (size_t repeat = 0; repeat < 2; ++repeat) {
    for (int set_protocol : {PTHREAD_PRIO_NONE, PTHREAD_PRIO_INHERIT}) {
      ASSERT_EQ(0, pthread_mutexattr_setprotocol(&attr, set_protocol));
      ASSERT_EQ(0, pthread_mutexattr_getprotocol(&attr, &protocol));
      ASSERT_EQ(protocol, set_protocol);
    }
  }
}

struct PthreadMutex {
  pthread_mutex_t lock;

  explicit PthreadMutex(int mutex_type, int protocol = PTHREAD_PRIO_NONE) {
    init(mutex_type, protocol);
  }

  ~PthreadMutex() {
    destroy();
  }

 private:
  void init(int mutex_type, int protocol) {
    pthread_mutexattr_t attr;
    ASSERT_EQ(0, pthread_mutexattr_init(&attr));
    ASSERT_EQ(0, pthread_mutexattr_settype(&attr, mutex_type));
    ASSERT_EQ(0, pthread_mutexattr_setprotocol(&attr, protocol));
    ASSERT_EQ(0, pthread_mutex_init(&lock, &attr));
    ASSERT_EQ(0, pthread_mutexattr_destroy(&attr));
  }

  void destroy() {
    ASSERT_EQ(0, pthread_mutex_destroy(&lock));
  }

  DISALLOW_COPY_AND_ASSIGN(PthreadMutex);
};

static int UnlockFromAnotherThread(pthread_mutex_t* mutex) {
  pthread_t thread;
  pthread_create(&thread, nullptr, [](void* mutex_voidp) -> void* {
    pthread_mutex_t* mutex = static_cast<pthread_mutex_t*>(mutex_voidp);
    intptr_t result = pthread_mutex_unlock(mutex);
    return reinterpret_cast<void*>(result);
  }, mutex);
  void* result;
  EXPECT_EQ(0, pthread_join(thread, &result));
  return reinterpret_cast<intptr_t>(result);
};

static void TestPthreadMutexLockNormal(int protocol) {
  PthreadMutex m(PTHREAD_MUTEX_NORMAL, protocol);

  ASSERT_EQ(0, pthread_mutex_lock(&m.lock));
  if (protocol == PTHREAD_PRIO_INHERIT) {
    ASSERT_EQ(EPERM, UnlockFromAnotherThread(&m.lock));
  }
  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_trylock(&m.lock));
  ASSERT_EQ(EBUSY, pthread_mutex_trylock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
}

static void TestPthreadMutexLockErrorCheck(int protocol) {
  PthreadMutex m(PTHREAD_MUTEX_ERRORCHECK, protocol);

  ASSERT_EQ(0, pthread_mutex_lock(&m.lock));
  ASSERT_EQ(EPERM, UnlockFromAnotherThread(&m.lock));
  ASSERT_EQ(EDEADLK, pthread_mutex_lock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_trylock(&m.lock));
  if (protocol == PTHREAD_PRIO_NONE) {
    ASSERT_EQ(EBUSY, pthread_mutex_trylock(&m.lock));
  } else {
    ASSERT_EQ(EDEADLK, pthread_mutex_trylock(&m.lock));
  }
  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
  ASSERT_EQ(EPERM, pthread_mutex_unlock(&m.lock));
}

static void TestPthreadMutexLockRecursive(int protocol) {
  PthreadMutex m(PTHREAD_MUTEX_RECURSIVE, protocol);

  ASSERT_EQ(0, pthread_mutex_lock(&m.lock));
  ASSERT_EQ(EPERM, UnlockFromAnotherThread(&m.lock));
  ASSERT_EQ(0, pthread_mutex_lock(&m.lock));
  ASSERT_EQ(EPERM, UnlockFromAnotherThread(&m.lock));
  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_trylock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_trylock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
  ASSERT_EQ(EPERM, pthread_mutex_unlock(&m.lock));
}

TEST(pthread, pthread_mutex_lock_NORMAL) {
  TestPthreadMutexLockNormal(PTHREAD_PRIO_NONE);
}

TEST(pthread, pthread_mutex_lock_ERRORCHECK) {
  TestPthreadMutexLockErrorCheck(PTHREAD_PRIO_NONE);
}

TEST(pthread, pthread_mutex_lock_RECURSIVE) {
  TestPthreadMutexLockRecursive(PTHREAD_PRIO_NONE);
}

TEST(pthread, pthread_mutex_lock_pi) {
  TestPthreadMutexLockNormal(PTHREAD_PRIO_INHERIT);
  TestPthreadMutexLockErrorCheck(PTHREAD_PRIO_INHERIT);
  TestPthreadMutexLockRecursive(PTHREAD_PRIO_INHERIT);
}

TEST(pthread, pthread_mutex_pi_count_limit) {
#if defined(__BIONIC__) && !defined(__LP64__)
  // Bionic only supports 65536 pi mutexes in 32-bit programs.
  pthread_mutexattr_t attr;
  ASSERT_EQ(0, pthread_mutexattr_init(&attr));
  ASSERT_EQ(0, pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT));
  std::vector<pthread_mutex_t> mutexes(65536);
  // Test if we can use 65536 pi mutexes at the same time.
  // Run 2 times to check if freed pi mutexes can be recycled.
  for (int repeat = 0; repeat < 2; ++repeat) {
    for (auto& m : mutexes) {
      ASSERT_EQ(0, pthread_mutex_init(&m, &attr));
    }
    pthread_mutex_t m;
    ASSERT_EQ(ENOMEM, pthread_mutex_init(&m, &attr));
    for (auto& m : mutexes) {
      ASSERT_EQ(0, pthread_mutex_lock(&m));
    }
    for (auto& m : mutexes) {
      ASSERT_EQ(0, pthread_mutex_unlock(&m));
    }
    for (auto& m : mutexes) {
      ASSERT_EQ(0, pthread_mutex_destroy(&m));
    }
  }
  ASSERT_EQ(0, pthread_mutexattr_destroy(&attr));
#else
  GTEST_SKIP() << "pi mutex count not limited to 64Ki";
#endif
}

TEST(pthread, pthread_mutex_init_same_as_static_initializers) {
  pthread_mutex_t lock_normal = PTHREAD_MUTEX_INITIALIZER;
  PthreadMutex m1(PTHREAD_MUTEX_NORMAL);
  ASSERT_EQ(0, memcmp(&lock_normal, &m1.lock, sizeof(pthread_mutex_t)));
  pthread_mutex_destroy(&lock_normal);

#if !defined(ANDROID_HOST_MUSL)
  // musl doesn't support PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP or
  // PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP.
  pthread_mutex_t lock_errorcheck = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
  PthreadMutex m2(PTHREAD_MUTEX_ERRORCHECK);
  ASSERT_EQ(0, memcmp(&lock_errorcheck, &m2.lock, sizeof(pthread_mutex_t)));
  pthread_mutex_destroy(&lock_errorcheck);

  pthread_mutex_t lock_recursive = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
  PthreadMutex m3(PTHREAD_MUTEX_RECURSIVE);
  ASSERT_EQ(0, memcmp(&lock_recursive, &m3.lock, sizeof(pthread_mutex_t)));
  ASSERT_EQ(0, pthread_mutex_destroy(&lock_recursive));
#endif
}

class MutexWakeupHelper {
 private:
  PthreadMutex m;
  enum Progress {
    LOCK_INITIALIZED,
    LOCK_WAITING,
    LOCK_RELEASED,
    LOCK_ACCESSED
  };
  std::atomic<Progress> progress;
  std::atomic<pid_t> tid;

  static void thread_fn(MutexWakeupHelper* helper) {
    helper->tid = gettid();
    ASSERT_EQ(LOCK_INITIALIZED, helper->progress);
    helper->progress = LOCK_WAITING;

    ASSERT_EQ(0, pthread_mutex_lock(&helper->m.lock));
    ASSERT_EQ(LOCK_RELEASED, helper->progress);
    ASSERT_EQ(0, pthread_mutex_unlock(&helper->m.lock));

    helper->progress = LOCK_ACCESSED;
  }

 public:
  explicit MutexWakeupHelper(int mutex_type) : m(mutex_type) {
  }

  void test() {
    ASSERT_EQ(0, pthread_mutex_lock(&m.lock));
    progress = LOCK_INITIALIZED;
    tid = 0;

    pthread_t thread;
    ASSERT_EQ(0, pthread_create(&thread, nullptr,
      reinterpret_cast<void* (*)(void*)>(MutexWakeupHelper::thread_fn), this));

    WaitUntilThreadSleep(tid);
    ASSERT_EQ(LOCK_WAITING, progress);

    progress = LOCK_RELEASED;
    ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));

    ASSERT_EQ(0, pthread_join(thread, nullptr));
    ASSERT_EQ(LOCK_ACCESSED, progress);
  }
};

TEST(pthread, pthread_mutex_NORMAL_wakeup) {
  MutexWakeupHelper helper(PTHREAD_MUTEX_NORMAL);
  helper.test();
}

TEST(pthread, pthread_mutex_ERRORCHECK_wakeup) {
  MutexWakeupHelper helper(PTHREAD_MUTEX_ERRORCHECK);
  helper.test();
}

TEST(pthread, pthread_mutex_RECURSIVE_wakeup) {
  MutexWakeupHelper helper(PTHREAD_MUTEX_RECURSIVE);
  helper.test();
}

static int GetThreadPriority(pid_t tid) {
  // sched_getparam() returns the static priority of a thread, which can't reflect a thread's
  // priority after priority inheritance. So read /proc/<pid>/stat to get the dynamic priority.
  std::string filename = android::base::StringPrintf("/proc/%d/stat", tid);
  std::string content;
  int result = INT_MAX;
  if (!android::base::ReadFileToString(filename, &content)) {
    return result;
  }
  std::vector<std::string> strs = android::base::Split(content, " ");
  if (strs.size() < 18) {
    return result;
  }
  if (!android::base::ParseInt(strs[17], &result)) {
    return INT_MAX;
  }
  return result;
}

class PIMutexWakeupHelper {
private:
  PthreadMutex m;
  int protocol;
  enum Progress {
    LOCK_INITIALIZED,
    LOCK_CHILD_READY,
    LOCK_WAITING,
    LOCK_RELEASED,
  };
  std::atomic<Progress> progress;
  std::atomic<pid_t> main_tid;
  std::atomic<pid_t> child_tid;
  PthreadMutex start_thread_m;

  static void thread_fn(PIMutexWakeupHelper* helper) {
    helper->child_tid = gettid();
    ASSERT_EQ(LOCK_INITIALIZED, helper->progress);
    ASSERT_EQ(0, setpriority(PRIO_PROCESS, gettid(), 1));
    ASSERT_EQ(21, GetThreadPriority(gettid()));
    ASSERT_EQ(0, pthread_mutex_lock(&helper->m.lock));
    helper->progress = LOCK_CHILD_READY;
    ASSERT_EQ(0, pthread_mutex_lock(&helper->start_thread_m.lock));

    ASSERT_EQ(0, pthread_mutex_unlock(&helper->start_thread_m.lock));
    WaitUntilThreadSleep(helper->main_tid);
    ASSERT_EQ(LOCK_WAITING, helper->progress);

    if (helper->protocol == PTHREAD_PRIO_INHERIT) {
      ASSERT_EQ(20, GetThreadPriority(gettid()));
    } else {
      ASSERT_EQ(21, GetThreadPriority(gettid()));
    }
    helper->progress = LOCK_RELEASED;
    ASSERT_EQ(0, pthread_mutex_unlock(&helper->m.lock));
  }

public:
  explicit PIMutexWakeupHelper(int mutex_type, int protocol)
      : m(mutex_type, protocol), protocol(protocol), start_thread_m(PTHREAD_MUTEX_NORMAL) {
  }

  void test() {
    ASSERT_EQ(0, pthread_mutex_lock(&start_thread_m.lock));
    main_tid = gettid();
    ASSERT_EQ(20, GetThreadPriority(main_tid));
    progress = LOCK_INITIALIZED;
    child_tid = 0;

    pthread_t thread;
    ASSERT_EQ(0, pthread_create(&thread, nullptr,
              reinterpret_cast<void* (*)(void*)>(PIMutexWakeupHelper::thread_fn), this));

    WaitUntilThreadSleep(child_tid);
    ASSERT_EQ(LOCK_CHILD_READY, progress);
    ASSERT_EQ(0, pthread_mutex_unlock(&start_thread_m.lock));
    progress = LOCK_WAITING;
    ASSERT_EQ(0, pthread_mutex_lock(&m.lock));

    ASSERT_EQ(LOCK_RELEASED, progress);
    ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
    ASSERT_EQ(0, pthread_join(thread, nullptr));
  }
};

TEST(pthread, pthread_mutex_pi_wakeup) {
  for (int type : {PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_RECURSIVE, PTHREAD_MUTEX_ERRORCHECK}) {
    for (int protocol : {PTHREAD_PRIO_INHERIT}) {
      PIMutexWakeupHelper helper(type, protocol);
      helper.test();
    }
  }
}

TEST(pthread, pthread_mutex_owner_tid_limit) {
#if defined(__BIONIC__) && !defined(__LP64__)
  FILE* fp = fopen("/proc/sys/kernel/pid_max", "r");
  ASSERT_TRUE(fp != nullptr);
  long pid_max;
  ASSERT_EQ(1, fscanf(fp, "%ld", &pid_max));
  fclose(fp);
  // Bionic's pthread_mutex implementation on 32-bit devices uses 16 bits to represent owner tid.
  ASSERT_LE(pid_max, 65536);
#else
  GTEST_SKIP() << "pthread_mutex supports 32-bit tid";
#endif
}

static void pthread_mutex_timedlock_helper(clockid_t clock,
                                           int (*lock_function)(pthread_mutex_t* __mutex,
                                                                const timespec* __timeout)) {
  pthread_mutex_t m;
  ASSERT_EQ(0, pthread_mutex_init(&m, nullptr));

  // If the mutex is already locked, pthread_mutex_timedlock should time out.
  ASSERT_EQ(0, pthread_mutex_lock(&m));

  timespec ts;
  ASSERT_EQ(0, clock_gettime(clock, &ts));
  ASSERT_EQ(ETIMEDOUT, lock_function(&m, &ts));
  ts.tv_nsec = -1;
  ASSERT_EQ(EINVAL, lock_function(&m, &ts));
  ts.tv_nsec = NS_PER_S;
  ASSERT_EQ(EINVAL, lock_function(&m, &ts));
  ts.tv_nsec = NS_PER_S - 1;
  ts.tv_sec = -1;
  ASSERT_EQ(ETIMEDOUT, lock_function(&m, &ts));

  // Check we wait long enough for the lock before timing out...

  // What time is it before we start?
  ASSERT_EQ(0, clock_gettime(clock, &ts));
  const int64_t start_ns = to_ns(ts);
  // Add a second to get deadline, and wait until we time out.
  ts.tv_sec += 1;
  ASSERT_EQ(ETIMEDOUT, lock_function(&m, &ts));

  // What time is it now we've timed out?
  timespec ts2;
  clock_gettime(clock, &ts2);
  const int64_t end_ns = to_ns(ts2);

  // The timedlock must have waited at least 1 second before returning.
  ASSERT_GE(end_ns - start_ns, NS_PER_S);

  // If the mutex is unlocked, pthread_mutex_timedlock should succeed.
  ASSERT_EQ(0, pthread_mutex_unlock(&m));
  ASSERT_EQ(0, clock_gettime(clock, &ts));
  ts.tv_sec += 1;
  ASSERT_EQ(0, lock_function(&m, &ts));

  ASSERT_EQ(0, pthread_mutex_unlock(&m));
  ASSERT_EQ(0, pthread_mutex_destroy(&m));
}

TEST(pthread, pthread_mutex_timedlock) {
  pthread_mutex_timedlock_helper(CLOCK_REALTIME, pthread_mutex_timedlock);
}

TEST(pthread, pthread_mutex_timedlock_monotonic_np) {
#if defined(__BIONIC__)
  pthread_mutex_timedlock_helper(CLOCK_MONOTONIC, pthread_mutex_timedlock_monotonic_np);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_mutex_timedlock_monotonic_np not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_mutex_clocklock_MONOTONIC) {
#if defined(__BIONIC__)
  pthread_mutex_timedlock_helper(
      CLOCK_MONOTONIC, [](pthread_mutex_t* __mutex, const timespec* __timeout) {
        return pthread_mutex_clocklock(__mutex, CLOCK_MONOTONIC, __timeout);
      });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_mutex_clocklock not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_mutex_clocklock_REALTIME) {
#if defined(__BIONIC__)
  pthread_mutex_timedlock_helper(
      CLOCK_REALTIME, [](pthread_mutex_t* __mutex, const timespec* __timeout) {
        return pthread_mutex_clocklock(__mutex, CLOCK_REALTIME, __timeout);
      });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_mutex_clocklock not available";
#endif  // __BIONIC__
}

static void pthread_mutex_timedlock_pi_helper(clockid_t clock,
                                              int (*lock_function)(pthread_mutex_t* __mutex,
                                                                   const timespec* __timeout)) {
  PthreadMutex m(PTHREAD_MUTEX_NORMAL, PTHREAD_PRIO_INHERIT);

  timespec ts;
  clock_gettime(clock, &ts);
  const int64_t start_ns = ts.tv_sec * NS_PER_S + ts.tv_nsec;

  // add a second to get deadline.
  ts.tv_sec += 1;

  ASSERT_EQ(0, lock_function(&m.lock, &ts));

  struct ThreadArgs {
    clockid_t clock;
    int (*lock_function)(pthread_mutex_t* __mutex, const timespec* __timeout);
    PthreadMutex& m;
  };

  ThreadArgs thread_args = {
    .clock = clock,
    .lock_function = lock_function,
    .m = m,
  };

  auto ThreadFn = [](void* arg) -> void* {
    auto args = static_cast<ThreadArgs*>(arg);
    timespec ts;
    clock_gettime(args->clock, &ts);
    ts.tv_sec += 1;
    intptr_t result = args->lock_function(&args->m.lock, &ts);
    return reinterpret_cast<void*>(result);
  };

  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr, ThreadFn, &thread_args));
  void* result;
  ASSERT_EQ(0, pthread_join(thread, &result));
  ASSERT_EQ(ETIMEDOUT, reinterpret_cast<intptr_t>(result));

  // The timedlock must have waited at least 1 second before returning.
  clock_gettime(clock, &ts);
  const int64_t end_ns = ts.tv_sec * NS_PER_S + ts.tv_nsec;
  ASSERT_GT(end_ns - start_ns, NS_PER_S);

  ASSERT_EQ(0, pthread_mutex_unlock(&m.lock));
}

TEST(pthread, pthread_mutex_timedlock_pi) {
  pthread_mutex_timedlock_pi_helper(CLOCK_REALTIME, pthread_mutex_timedlock);
}

TEST(pthread, pthread_mutex_timedlock_monotonic_np_pi) {
#if defined(__BIONIC__)
  pthread_mutex_timedlock_pi_helper(CLOCK_MONOTONIC, pthread_mutex_timedlock_monotonic_np);
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_mutex_timedlock_monotonic_np not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_mutex_clocklock_pi) {
#if defined(__BIONIC__)
  pthread_mutex_timedlock_pi_helper(
      CLOCK_MONOTONIC, [](pthread_mutex_t* __mutex, const timespec* __timeout) {
        return pthread_mutex_clocklock(__mutex, CLOCK_MONOTONIC, __timeout);
      });
  pthread_mutex_timedlock_pi_helper(
      CLOCK_REALTIME, [](pthread_mutex_t* __mutex, const timespec* __timeout) {
        return pthread_mutex_clocklock(__mutex, CLOCK_REALTIME, __timeout);
      });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_mutex_clocklock not available";
#endif  // __BIONIC__
}

TEST(pthread, pthread_mutex_clocklock_invalid) {
#if defined(__BIONIC__)
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  timespec ts;
  EXPECT_EQ(EINVAL, pthread_mutex_clocklock(&mutex, CLOCK_PROCESS_CPUTIME_ID, &ts));
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_mutex_clocklock not available";
#endif  // __BIONIC__
}

TEST_F(pthread_DeathTest, pthread_mutex_using_destroyed_mutex) {
#if defined(__BIONIC__)
  pthread_mutex_t m;
  ASSERT_EQ(0, pthread_mutex_init(&m, nullptr));
  ASSERT_EQ(0, pthread_mutex_destroy(&m));
  ASSERT_EXIT(pthread_mutex_lock(&m), ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_lock called on a destroyed mutex");
  ASSERT_EXIT(pthread_mutex_unlock(&m), ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_unlock called on a destroyed mutex");
  ASSERT_EXIT(pthread_mutex_trylock(&m), ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_trylock called on a destroyed mutex");
  timespec ts;
  ASSERT_EXIT(pthread_mutex_timedlock(&m, &ts), ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_timedlock called on a destroyed mutex");
  ASSERT_EXIT(pthread_mutex_timedlock_monotonic_np(&m, &ts), ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_timedlock_monotonic_np called on a destroyed mutex");
  ASSERT_EXIT(pthread_mutex_clocklock(&m, CLOCK_MONOTONIC, &ts), ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_clocklock called on a destroyed mutex");
  ASSERT_EXIT(pthread_mutex_clocklock(&m, CLOCK_REALTIME, &ts), ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_clocklock called on a destroyed mutex");
  ASSERT_EXIT(pthread_mutex_clocklock(&m, CLOCK_PROCESS_CPUTIME_ID, &ts),
              ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_clocklock called on a destroyed mutex");
  ASSERT_EXIT(pthread_mutex_destroy(&m), ::testing::KilledBySignal(SIGABRT),
              "pthread_mutex_destroy called on a destroyed mutex");
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

class StrictAlignmentAllocator {
 public:
  void* allocate(size_t size, size_t alignment) {
    char* p = new char[size + alignment * 2];
    allocated_array.push_back(p);
    while (!is_strict_aligned(p, alignment)) {
      ++p;
    }
    return p;
  }

  ~StrictAlignmentAllocator() {
    for (const auto& p : allocated_array) {
      delete[] p;
    }
  }

 private:
  bool is_strict_aligned(char* p, size_t alignment) {
    return (reinterpret_cast<uintptr_t>(p) % (alignment * 2)) == alignment;
  }

  std::vector<char*> allocated_array;
};

TEST(pthread, pthread_types_allow_four_bytes_alignment) {
#if defined(__BIONIC__)
  // For binary compatibility with old version, we need to allow 4-byte aligned data for pthread types.
  StrictAlignmentAllocator allocator;
  pthread_mutex_t* mutex = reinterpret_cast<pthread_mutex_t*>(
                             allocator.allocate(sizeof(pthread_mutex_t), 4));
  ASSERT_EQ(0, pthread_mutex_init(mutex, nullptr));
  ASSERT_EQ(0, pthread_mutex_lock(mutex));
  ASSERT_EQ(0, pthread_mutex_unlock(mutex));
  ASSERT_EQ(0, pthread_mutex_destroy(mutex));

  pthread_cond_t* cond = reinterpret_cast<pthread_cond_t*>(
                           allocator.allocate(sizeof(pthread_cond_t), 4));
  ASSERT_EQ(0, pthread_cond_init(cond, nullptr));
  ASSERT_EQ(0, pthread_cond_signal(cond));
  ASSERT_EQ(0, pthread_cond_broadcast(cond));
  ASSERT_EQ(0, pthread_cond_destroy(cond));

  pthread_rwlock_t* rwlock = reinterpret_cast<pthread_rwlock_t*>(
                               allocator.allocate(sizeof(pthread_rwlock_t), 4));
  ASSERT_EQ(0, pthread_rwlock_init(rwlock, nullptr));
  ASSERT_EQ(0, pthread_rwlock_rdlock(rwlock));
  ASSERT_EQ(0, pthread_rwlock_unlock(rwlock));
  ASSERT_EQ(0, pthread_rwlock_wrlock(rwlock));
  ASSERT_EQ(0, pthread_rwlock_unlock(rwlock));
  ASSERT_EQ(0, pthread_rwlock_destroy(rwlock));

#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(pthread, pthread_mutex_lock_null_32) {
#if defined(__BIONIC__) && !defined(__LP64__)
  // For LP32, the pthread lock/unlock functions allow a NULL mutex and return
  // EINVAL in that case: http://b/19995172.
  //
  // We decorate the public defintion with _Nonnull so that people recompiling
  // their code with get a warning and might fix their bug, but need to pass
  // NULL here to test that we remain compatible.
  pthread_mutex_t* null_value = nullptr;
  ASSERT_EQ(EINVAL, pthread_mutex_lock(null_value));
#else
  GTEST_SKIP() << "32-bit bionic-only test";
#endif
}

TEST(pthread, pthread_mutex_unlock_null_32) {
#if defined(__BIONIC__) && !defined(__LP64__)
  // For LP32, the pthread lock/unlock functions allow a NULL mutex and return
  // EINVAL in that case: http://b/19995172.
  //
  // We decorate the public defintion with _Nonnull so that people recompiling
  // their code with get a warning and might fix their bug, but need to pass
  // NULL here to test that we remain compatible.
  pthread_mutex_t* null_value = nullptr;
  ASSERT_EQ(EINVAL, pthread_mutex_unlock(null_value));
#else
  GTEST_SKIP() << "32-bit bionic-only test";
#endif
}

TEST_F(pthread_DeathTest, pthread_mutex_lock_null_64) {
#if defined(__BIONIC__) && defined(__LP64__)
  pthread_mutex_t* null_value = nullptr;
  ASSERT_EXIT(pthread_mutex_lock(null_value), testing::KilledBySignal(SIGSEGV), "");
#else
  GTEST_SKIP() << "64-bit bionic-only test";
#endif
}

TEST_F(pthread_DeathTest, pthread_mutex_unlock_null_64) {
#if defined(__BIONIC__) && defined(__LP64__)
  pthread_mutex_t* null_value = nullptr;
  ASSERT_EXIT(pthread_mutex_unlock(null_value), testing::KilledBySignal(SIGSEGV), "");
#else
  GTEST_SKIP() << "64-bit bionic-only test";
#endif
}

extern _Unwind_Reason_Code FrameCounter(_Unwind_Context* ctx, void* arg);

static volatile bool signal_handler_on_altstack_done;

__attribute__((__noinline__))
static void signal_handler_backtrace() {
  // Check if we have enough stack space for unwinding.
  int count = 0;
  _Unwind_Backtrace(FrameCounter, &count);
  ASSERT_GT(count, 0);
}

__attribute__((__noinline__))
static void signal_handler_logging() {
  // Check if we have enough stack space for logging.
  std::string s(2048, '*');
  GTEST_LOG_(INFO) << s;
  signal_handler_on_altstack_done = true;
}

__attribute__((__noinline__))
static void signal_handler_snprintf() {
  // Check if we have enough stack space for snprintf to a PATH_MAX buffer, plus some extra.
  char buf[PATH_MAX + 2048];
  ASSERT_GT(snprintf(buf, sizeof(buf), "/proc/%d/status", getpid()), 0);
}

static void SignalHandlerOnAltStack(int signo, siginfo_t*, void*) {
  ASSERT_EQ(SIGUSR1, signo);
  signal_handler_backtrace();
  signal_handler_logging();
  signal_handler_snprintf();
}

TEST(pthread, big_enough_signal_stack) {
  signal_handler_on_altstack_done = false;
  ScopedSignalHandler handler(SIGUSR1, SignalHandlerOnAltStack, SA_SIGINFO | SA_ONSTACK);
  kill(getpid(), SIGUSR1);
  ASSERT_TRUE(signal_handler_on_altstack_done);
}

TEST(pthread, pthread_barrierattr_smoke) {
  pthread_barrierattr_t attr;
  ASSERT_EQ(0, pthread_barrierattr_init(&attr));
  int pshared;
  ASSERT_EQ(0, pthread_barrierattr_getpshared(&attr, &pshared));
  ASSERT_EQ(PTHREAD_PROCESS_PRIVATE, pshared);
  ASSERT_EQ(0, pthread_barrierattr_setpshared(&attr, PTHREAD_PROCESS_SHARED));
  ASSERT_EQ(0, pthread_barrierattr_getpshared(&attr, &pshared));
  ASSERT_EQ(PTHREAD_PROCESS_SHARED, pshared);
  ASSERT_EQ(0, pthread_barrierattr_destroy(&attr));
}

struct BarrierTestHelperData {
  size_t thread_count;
  pthread_barrier_t barrier;
  std::atomic<int> finished_mask;
  std::atomic<int> serial_thread_count;
  size_t iteration_count;
  std::atomic<size_t> finished_iteration_count;

  BarrierTestHelperData(size_t thread_count, size_t iteration_count)
      : thread_count(thread_count), finished_mask(0), serial_thread_count(0),
        iteration_count(iteration_count), finished_iteration_count(0) {
  }
};

struct BarrierTestHelperArg {
  int id;
  BarrierTestHelperData* data;
};

static void BarrierTestHelper(BarrierTestHelperArg* arg) {
  for (size_t i = 0; i < arg->data->iteration_count; ++i) {
    int result = pthread_barrier_wait(&arg->data->barrier);
    if (result == PTHREAD_BARRIER_SERIAL_THREAD) {
      arg->data->serial_thread_count++;
    } else {
      ASSERT_EQ(0, result);
    }
    int mask = arg->data->finished_mask.fetch_or(1 << arg->id);
    mask |= 1 << arg->id;
    if (mask == ((1 << arg->data->thread_count) - 1)) {
      ASSERT_EQ(1, arg->data->serial_thread_count);
      arg->data->finished_iteration_count++;
      arg->data->finished_mask = 0;
      arg->data->serial_thread_count = 0;
    }
  }
}

TEST(pthread, pthread_barrier_smoke) {
  const size_t BARRIER_ITERATION_COUNT = 10;
  const size_t BARRIER_THREAD_COUNT = 10;
  BarrierTestHelperData data(BARRIER_THREAD_COUNT, BARRIER_ITERATION_COUNT);
  ASSERT_EQ(0, pthread_barrier_init(&data.barrier, nullptr, data.thread_count));
  std::vector<pthread_t> threads(data.thread_count);
  std::vector<BarrierTestHelperArg> args(threads.size());
  for (size_t i = 0; i < threads.size(); ++i) {
    args[i].id = i;
    args[i].data = &data;
    ASSERT_EQ(0, pthread_create(&threads[i], nullptr,
                                reinterpret_cast<void* (*)(void*)>(BarrierTestHelper), &args[i]));
  }
  for (size_t i = 0; i < threads.size(); ++i) {
    ASSERT_EQ(0, pthread_join(threads[i], nullptr));
  }
  ASSERT_EQ(data.iteration_count, data.finished_iteration_count);
  ASSERT_EQ(0, pthread_barrier_destroy(&data.barrier));
}

struct BarrierDestroyTestArg {
  std::atomic<int> tid;
  pthread_barrier_t* barrier;
};

static void BarrierDestroyTestHelper(BarrierDestroyTestArg* arg) {
  arg->tid = gettid();
  ASSERT_EQ(0, pthread_barrier_wait(arg->barrier));
}

TEST(pthread, pthread_barrier_destroy) {
  pthread_barrier_t barrier;
  ASSERT_EQ(0, pthread_barrier_init(&barrier, nullptr, 2));
  pthread_t thread;
  BarrierDestroyTestArg arg;
  arg.tid = 0;
  arg.barrier = &barrier;
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
                              reinterpret_cast<void* (*)(void*)>(BarrierDestroyTestHelper), &arg));
  WaitUntilThreadSleep(arg.tid);
  ASSERT_EQ(EBUSY, pthread_barrier_destroy(&barrier));
  ASSERT_EQ(PTHREAD_BARRIER_SERIAL_THREAD, pthread_barrier_wait(&barrier));
  // Verify if the barrier can be destroyed directly after pthread_barrier_wait().
  ASSERT_EQ(0, pthread_barrier_destroy(&barrier));
  ASSERT_EQ(0, pthread_join(thread, nullptr));
#if defined(__BIONIC__)
  ASSERT_EQ(EINVAL, pthread_barrier_destroy(&barrier));
#endif
}

struct BarrierOrderingTestHelperArg {
  pthread_barrier_t* barrier;
  size_t* array;
  size_t array_length;
  size_t id;
};

void BarrierOrderingTestHelper(BarrierOrderingTestHelperArg* arg) {
  const size_t ITERATION_COUNT = 10000;
  for (size_t i = 1; i <= ITERATION_COUNT; ++i) {
    arg->array[arg->id] = i;
    int result = pthread_barrier_wait(arg->barrier);
    ASSERT_TRUE(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
    for (size_t j = 0; j < arg->array_length; ++j) {
      ASSERT_EQ(i, arg->array[j]);
    }
    result = pthread_barrier_wait(arg->barrier);
    ASSERT_TRUE(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
  }
}

TEST(pthread, pthread_barrier_check_ordering) {
  const size_t THREAD_COUNT = 4;
  pthread_barrier_t barrier;
  ASSERT_EQ(0, pthread_barrier_init(&barrier, nullptr, THREAD_COUNT));
  size_t array[THREAD_COUNT];
  std::vector<pthread_t> threads(THREAD_COUNT);
  std::vector<BarrierOrderingTestHelperArg> args(THREAD_COUNT);
  for (size_t i = 0; i < THREAD_COUNT; ++i) {
    args[i].barrier = &barrier;
    args[i].array = array;
    args[i].array_length = THREAD_COUNT;
    args[i].id = i;
    ASSERT_EQ(0, pthread_create(&threads[i], nullptr,
                                reinterpret_cast<void* (*)(void*)>(BarrierOrderingTestHelper),
                                &args[i]));
  }
  for (size_t i = 0; i < THREAD_COUNT; ++i) {
    ASSERT_EQ(0, pthread_join(threa
"""


```