Response:
The user wants a summary of the functionality of the provided C++ source code file, which is a test file for the `malloc` implementation in Android's Bionic library. I need to identify the main features being tested and explain their purpose.

Here's a plan:
1. **Identify the core focus:** The file tests the `malloc` family of functions and related Bionic extensions (`android_mallopt`).
2. **Categorize the tests:** Group the tests by the specific functionality they are verifying (e.g., alignment, allocation limits, zero-initialization, GWP-ASan, MTE).
3. **Summarize each category:** Briefly explain what each group of tests is designed to check.
4. **Highlight Bionic-specific features:**  Pay special attention to tests related to `android_mallopt` and its various options, as these are Android-specific extensions.
这段代码是 `bionic/tests/malloc_test.cpp` 文件的第二部分，主要包含了对 Android Bionic 库中内存分配相关功能的各种测试用例。 归纳起来，它的主要功能是：

**1. 验证内存分配的正确性及各种特性:**

*   **对齐测试 (`align_check`):** 确保 `malloc` 返回的内存块满足平台要求的对齐方式 (在 64 位系统上，小于等于 8 字节的分配对齐到 8 字节，大于 8 字节的分配对齐到 16 字节；在 32 位系统上，根据大小对齐到 8 或 16 字节)。
*   **fork 后的内存分配 (`DISABLED_alloc_after_fork`):**  测试在 `fork` 系统调用创建子进程后，父子进程都能正常进行内存分配和释放，避免出现内存损坏或冲突。这个测试被标记为 `DISABLED`，可能因为当前的 `jemalloc` 实现不通过这个测试。
*   **`android_mallopt` 的错误处理 (`error_on_unexpected_option`):**  验证当 `android_mallopt` 函数接收到无法识别的选项时，能够正确返回错误并设置 `errno`。
*   **`android_mallopt` 的 Zygote 子进程初始化 (`init_zygote_child_profiling`):** 测试 `M_INIT_ZYGOTE_CHILD_PROFILING` 选项，这个选项用于在 Zygote 创建子进程时初始化性能分析功能。它会根据程序是否是动态链接的可执行文件来验证其行为，静态链接的可执行文件不支持此选项。
*   **设置内存分配限制 (`set_allocation_limit`， `set_allocation_limit_multiple`， `set_allocation_limit_realloc_increase`， `set_allocation_limit_realloc_decrease`， `set_allocation_limit_realloc_free`):** 测试 `android_mallopt` 的 `M_SET_ALLOCATION_LIMIT_BYTES` 选项，验证它可以成功设置内存分配的上限，并且后续的内存分配操作会受到这个限制。同时也测试了 `realloc` 函数在内存限制下的行为，包括增加、减少内存块大小以及释放内存的情况。
*   **多线程设置内存分配限制 (`set_allocation_limit_multiple_threads`):**  通过多线程并发调用 `android_mallopt` 来设置内存分配限制，验证在并发情况下只有一个线程能够成功设置，确保了内存管理的线程安全性。
*   **GWP-ASan 相关测试 (`DISABLED_multiple_enable_gwp_asan`, `multiple_enable_gwp_asan`):** 测试 GWP-ASan (Guard Walls Page - Address Sanitizer) 功能的启用。GWP-ASan 是一种内存安全工具，用于检测堆上的 use-after-free 和 heap-buffer-overflow 错误。
*   **内存标签堆栈是否开启 (`memtag_stack_is_on`):**  检查是否启用了内存标签堆栈 (Memory Tagging Extension for Stack)，这是一种利用 ARMv8.5-A 内存标签功能来提高内存安全性的技术。
*   **零初始化 (`zero_init`):**  测试通过 `mallopt(M_BIONIC_ZERO_INIT, 1)` 启用的内存零初始化功能。验证分配的内存块在分配后是否被清零。这个测试只在 Scudo 分配器上运行，并且排除了 HWASAN (Hardware-assisted AddressSanitizer)。
*   **禁用 MTE (`disable_mte`):** 测试通过 `mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, M_HEAP_TAGGING_LEVEL_NONE)` 禁用内存标签扩展 (MTE) 的功能。它创建了一个线程，并在主线程禁用 MTE 后，验证两个线程的 MTE 控制状态是否一致。
*   **分配 slack (`allocation_slack`):**  测试在旧版本的 Android SDK 下，允许访问超出分配大小末尾少量字节的情况，用于兼容旧的应用。这个测试会根据目标 SDK 版本进行不同的行为。
*   **`realloc` 的 MTE 崩溃修复 (`realloc_mte_crash_b206701345`):**  这是一个回归测试，用于验证一个在使用 MTE 时 `realloc` 函数可能发生的崩溃问题是否已修复。
*   **验证内存分配是否为零 (`zeroed_allocations_small_medium_sizes`, `zeroed_allocations_large_sizes`, `zeroed_allocations_realloc`):**  详细测试了 `malloc`， `memalign`， 和 `posix_memalign` 等函数分配的内存是否被初始化为零。测试了小、中、大尺寸的内存分配，以及 `realloc` 扩展内存时的零初始化行为。这些测试符合 Android CDD (Compatibility Definition Document) 的要求。
*   **获取内存回收延迟启用状态的错误处理 (`get_decay_time_enabled_errors`):** 测试 `android_mallopt` 的 `M_GET_DECAY_TIME_ENABLED` 选项在接收到错误参数时的处理。
*   **获取内存回收延迟启用状态 (`get_decay_time_enabled`):**  测试 `android_mallopt` 的 `M_GET_DECAY_TIME_ENABLED` 选项，用于获取内存回收延迟是否启用。它与 `mallopt(M_DECAY_TIME)` 配合使用来控制 Scudo 分配器将空闲内存返回给操作系统的时间。

**总结:**

总而言之，这部分代码主要负责对 Android Bionic 库中的内存分配器进行全面的功能测试，包括基本的分配、释放、对齐、限制，以及一些 Android 特有的扩展功能，如与 Zygote 进程的集成、内存分配限制、GWP-ASan 和 MTE 的支持，以及零初始化等。这些测试确保了 Android 系统内存管理的稳定性和安全性。

Prompt: 
```
这是目录为bionic/tests/malloc_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能

"""
uirement since clang expects this behavior on Android now.
  for (size_t i = 1; i <= 128; i++) {
#if defined(__LP64__)
    if (i <= 8) {
      AndroidVerifyAlignment(i, 8);
    } else {
      AndroidVerifyAlignment(i, 16);
    }
#else
    size_t rounded = (i + 7) & ~7;
    if ((rounded % 16) == 0) {
      AndroidVerifyAlignment(i, 16);
    } else {
      AndroidVerifyAlignment(i, 8);
    }
#endif
    if (::testing::Test::HasFatalFailure()) {
      return;
    }
  }
#endif
}

TEST(malloc, align_check) {
  AlignCheck();
}

// Jemalloc doesn't pass this test right now, so leave it as disabled.
TEST(malloc, DISABLED_alloc_after_fork) {
  // Both of these need to be a power of 2.
  static constexpr size_t kMinAllocationSize = 8;
  static constexpr size_t kMaxAllocationSize = 2097152;

  static constexpr size_t kNumAllocatingThreads = 5;
  static constexpr size_t kNumForkLoops = 100;

  std::atomic_bool stop;

  // Create threads that simply allocate and free different sizes.
  std::vector<std::thread*> threads;
  for (size_t i = 0; i < kNumAllocatingThreads; i++) {
    std::thread* t = new std::thread([&stop] {
      while (!stop) {
        for (size_t size = kMinAllocationSize; size <= kMaxAllocationSize; size <<= 1) {
          void* ptr;
          DoNotOptimize(ptr = malloc(size));
          free(ptr);
        }
      }
    });
    threads.push_back(t);
  }

  // Create a thread to fork and allocate.
  for (size_t i = 0; i < kNumForkLoops; i++) {
    pid_t pid;
    if ((pid = fork()) == 0) {
      for (size_t size = kMinAllocationSize; size <= kMaxAllocationSize; size <<= 1) {
        void* ptr;
        DoNotOptimize(ptr = malloc(size));
        ASSERT_TRUE(ptr != nullptr);
        // Make sure we can touch all of the allocation.
        memset(ptr, 0x1, size);
        ASSERT_LE(size, malloc_usable_size(ptr));
        free(ptr);
      }
      _exit(10);
    }
    ASSERT_NE(-1, pid);
    AssertChildExited(pid, 10);
  }

  stop = true;
  for (auto thread : threads) {
    thread->join();
    delete thread;
  }
}

TEST(android_mallopt, error_on_unexpected_option) {
#if defined(__BIONIC__)
  const int unrecognized_option = -1;
  errno = 0;
  EXPECT_EQ(false, android_mallopt(unrecognized_option, nullptr, 0));
  EXPECT_ERRNO(ENOTSUP);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

bool IsDynamic() {
#if defined(__LP64__)
  Elf64_Ehdr ehdr;
#else
  Elf32_Ehdr ehdr;
#endif
  std::string path(android::base::GetExecutablePath());

  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    // Assume dynamic on error.
    return true;
  }
  bool read_completed = android::base::ReadFully(fd, &ehdr, sizeof(ehdr));
  close(fd);
  // Assume dynamic in error cases.
  return !read_completed || ehdr.e_type == ET_DYN;
}

TEST(android_mallopt, init_zygote_child_profiling) {
#if defined(__BIONIC__)
  // Successful call.
  errno = 0;
  if (IsDynamic()) {
    EXPECT_EQ(true, android_mallopt(M_INIT_ZYGOTE_CHILD_PROFILING, nullptr, 0));
    EXPECT_ERRNO(0);
  } else {
    // Not supported in static executables.
    EXPECT_EQ(false, android_mallopt(M_INIT_ZYGOTE_CHILD_PROFILING, nullptr, 0));
    EXPECT_ERRNO(ENOTSUP);
  }

  // Unexpected arguments rejected.
  errno = 0;
  char unexpected = 0;
  EXPECT_EQ(false, android_mallopt(M_INIT_ZYGOTE_CHILD_PROFILING, &unexpected, 1));
  if (IsDynamic()) {
    EXPECT_ERRNO(EINVAL);
  } else {
    EXPECT_ERRNO(ENOTSUP);
  }
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

#if defined(__BIONIC__)
template <typename FuncType>
void CheckAllocationFunction(FuncType func) {
  // Assumes that no more than 108MB of memory is allocated before this.
  size_t limit = 128 * 1024 * 1024;
  ASSERT_TRUE(android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, &limit, sizeof(limit)));
  if (!func(20 * 1024 * 1024))
    exit(1);
  if (func(128 * 1024 * 1024))
    exit(1);
  exit(0);
}
#endif

TEST(android_mallopt, set_allocation_limit) {
#if defined(__BIONIC__)
  EXPECT_EXIT(CheckAllocationFunction([](size_t bytes) { return calloc(bytes, 1) != nullptr; }),
              testing::ExitedWithCode(0), "");
  EXPECT_EXIT(CheckAllocationFunction([](size_t bytes) { return calloc(1, bytes) != nullptr; }),
              testing::ExitedWithCode(0), "");
  EXPECT_EXIT(CheckAllocationFunction([](size_t bytes) { return malloc(bytes) != nullptr; }),
              testing::ExitedWithCode(0), "");
  EXPECT_EXIT(CheckAllocationFunction(
                  [](size_t bytes) { return memalign(sizeof(void*), bytes) != nullptr; }),
              testing::ExitedWithCode(0), "");
  EXPECT_EXIT(CheckAllocationFunction([](size_t bytes) {
                void* ptr;
                return posix_memalign(&ptr, sizeof(void *), bytes) == 0;
              }),
              testing::ExitedWithCode(0), "");
  EXPECT_EXIT(CheckAllocationFunction(
                  [](size_t bytes) { return aligned_alloc(sizeof(void*), bytes) != nullptr; }),
              testing::ExitedWithCode(0), "");
  EXPECT_EXIT(CheckAllocationFunction([](size_t bytes) {
                void* p = malloc(1024 * 1024);
                return realloc(p, bytes) != nullptr;
              }),
              testing::ExitedWithCode(0), "");
#if !defined(__LP64__)
  EXPECT_EXIT(CheckAllocationFunction([](size_t bytes) { return pvalloc(bytes) != nullptr; }),
              testing::ExitedWithCode(0), "");
  EXPECT_EXIT(CheckAllocationFunction([](size_t bytes) { return valloc(bytes) != nullptr; }),
              testing::ExitedWithCode(0), "");
#endif
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

TEST(android_mallopt, set_allocation_limit_multiple) {
#if defined(__BIONIC__)
  // Only the first set should work.
  size_t limit = 256 * 1024 * 1024;
  ASSERT_TRUE(android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, &limit, sizeof(limit)));
  limit = 32 * 1024 * 1024;
  ASSERT_FALSE(android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, &limit, sizeof(limit)));
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

#if defined(__BIONIC__)
static constexpr size_t kAllocationSize = 8 * 1024 * 1024;

static size_t GetMaxAllocations() {
  size_t max_pointers = 0;
  void* ptrs[20];
  for (size_t i = 0; i < sizeof(ptrs) / sizeof(void*); i++) {
    ptrs[i] = malloc(kAllocationSize);
    if (ptrs[i] == nullptr) {
      max_pointers = i;
      break;
    }
  }
  for (size_t i = 0; i < max_pointers; i++) {
    free(ptrs[i]);
  }
  return max_pointers;
}

static void VerifyMaxPointers(size_t max_pointers) {
  // Now verify that we can allocate the same number as before.
  void* ptrs[20];
  for (size_t i = 0; i < max_pointers; i++) {
    ptrs[i] = malloc(kAllocationSize);
    ASSERT_TRUE(ptrs[i] != nullptr) << "Failed to allocate on iteration " << i;
  }

  // Make sure the next allocation still fails.
  ASSERT_TRUE(malloc(kAllocationSize) == nullptr);
  for (size_t i = 0; i < max_pointers; i++) {
    free(ptrs[i]);
  }
}
#endif

TEST(android_mallopt, set_allocation_limit_realloc_increase) {
#if defined(__BIONIC__)
  size_t limit = 128 * 1024 * 1024;
  ASSERT_TRUE(android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, &limit, sizeof(limit)));

  size_t max_pointers = GetMaxAllocations();
  ASSERT_TRUE(max_pointers != 0) << "Limit never reached.";

  void* memory = malloc(10 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);

  // Increase size.
  memory = realloc(memory, 20 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);
  memory = realloc(memory, 40 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);
  memory = realloc(memory, 60 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);
  memory = realloc(memory, 80 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);
  // Now push past limit.
  memory = realloc(memory, 130 * 1024 * 1024);
  ASSERT_TRUE(memory == nullptr);

  VerifyMaxPointers(max_pointers);
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

TEST(android_mallopt, set_allocation_limit_realloc_decrease) {
#if defined(__BIONIC__)
  size_t limit = 100 * 1024 * 1024;
  ASSERT_TRUE(android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, &limit, sizeof(limit)));

  size_t max_pointers = GetMaxAllocations();
  ASSERT_TRUE(max_pointers != 0) << "Limit never reached.";

  void* memory = malloc(80 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);

  // Decrease size.
  memory = realloc(memory, 60 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);
  memory = realloc(memory, 40 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);
  memory = realloc(memory, 20 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);
  memory = realloc(memory, 10 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);
  free(memory);

  VerifyMaxPointers(max_pointers);
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

TEST(android_mallopt, set_allocation_limit_realloc_free) {
#if defined(__BIONIC__)
  size_t limit = 100 * 1024 * 1024;
  ASSERT_TRUE(android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, &limit, sizeof(limit)));

  size_t max_pointers = GetMaxAllocations();
  ASSERT_TRUE(max_pointers != 0) << "Limit never reached.";

  void* memory = malloc(60 * 1024 * 1024);
  ASSERT_TRUE(memory != nullptr);

  memory = realloc(memory, 0);
  ASSERT_TRUE(memory == nullptr);

  VerifyMaxPointers(max_pointers);
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

#if defined(__BIONIC__)
static void SetAllocationLimitMultipleThreads() {
  static constexpr size_t kNumThreads = 4;
  std::atomic_bool start_running = false;
  std::atomic<size_t> num_running;
  std::atomic<size_t> num_successful;
  std::unique_ptr<std::thread> threads[kNumThreads];
  for (size_t i = 0; i < kNumThreads; i++) {
    threads[i].reset(new std::thread([&num_running, &start_running, &num_successful] {
      ++num_running;
      while (!start_running) {
      }
      size_t limit = 500 * 1024 * 1024;
      if (android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, &limit, sizeof(limit))) {
        ++num_successful;
      }
    }));
  }

  // Wait until all of the threads have started.
  while (num_running != kNumThreads)
    ;

  // Now start all of the threads setting the mallopt at once.
  start_running = true;

  // Send hardcoded signal (BIONIC_SIGNAL_PROFILER with value 0) to trigger
  // heapprofd handler. This will verify that changing the limit while
  // the allocation handlers are being changed at the same time works,
  // or that the limit handler is changed first and this also works properly.
  union sigval signal_value {};
  ASSERT_EQ(0, sigqueue(getpid(), BIONIC_SIGNAL_PROFILER, signal_value));

  // Wait for all of the threads to finish.
  for (size_t i = 0; i < kNumThreads; i++) {
    threads[i]->join();
  }
  ASSERT_EQ(1U, num_successful) << "Only one thread should be able to set the limit.";
  _exit(0);
}
#endif

TEST(android_mallopt, set_allocation_limit_multiple_threads) {
#if defined(__BIONIC__)
  if (IsDynamic()) {
    ASSERT_TRUE(android_mallopt(M_INIT_ZYGOTE_CHILD_PROFILING, nullptr, 0));
  }

  // Run this a number of times as a stress test.
  for (size_t i = 0; i < 100; i++) {
    // Not using ASSERT_EXIT because errors messages are not displayed.
    pid_t pid;
    if ((pid = fork()) == 0) {
      ASSERT_NO_FATAL_FAILURE(SetAllocationLimitMultipleThreads());
    }
    ASSERT_NE(-1, pid);
    int status;
    ASSERT_EQ(pid, wait(&status));
    ASSERT_EQ(0, WEXITSTATUS(status));
  }
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

#if defined(__BIONIC__)
using Mode = android_mallopt_gwp_asan_options_t::Mode;
TEST(android_mallopt, DISABLED_multiple_enable_gwp_asan) {
  android_mallopt_gwp_asan_options_t options;
  options.program_name = "";  // Don't infer GWP-ASan options from sysprops.
  options.mode = Mode::APP_MANIFEST_NEVER;
  // GWP-ASan should already be enabled. Trying to enable or disable it should
  // always pass.
  ASSERT_TRUE(android_mallopt(M_INITIALIZE_GWP_ASAN, &options, sizeof(options)));
  options.mode = Mode::APP_MANIFEST_DEFAULT;
  ASSERT_TRUE(android_mallopt(M_INITIALIZE_GWP_ASAN, &options, sizeof(options)));
}
#endif  // defined(__BIONIC__)

TEST(android_mallopt, multiple_enable_gwp_asan) {
#if defined(__BIONIC__)
  // Always enable GWP-Asan, with default options.
  RunGwpAsanTest("*.DISABLED_multiple_enable_gwp_asan");
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

TEST(android_mallopt, memtag_stack_is_on) {
#if defined(__BIONIC__)
  bool memtag_stack;
  EXPECT_TRUE(android_mallopt(M_MEMTAG_STACK_IS_ON, &memtag_stack, sizeof(memtag_stack)));
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

void TestHeapZeroing(int num_iterations, int (*get_alloc_size)(int iteration)) {
  std::vector<void*> allocs;
  constexpr int kMaxBytesToCheckZero = 64;
  const char kBlankMemory[kMaxBytesToCheckZero] = {};

  for (int i = 0; i < num_iterations; ++i) {
    int size = get_alloc_size(i);
    allocs.push_back(malloc(size));
    memset(allocs.back(), 'X', std::min(size, kMaxBytesToCheckZero));
  }

  for (void* alloc : allocs) {
    free(alloc);
  }
  allocs.clear();

  for (int i = 0; i < num_iterations; ++i) {
    int size = get_alloc_size(i);
    allocs.push_back(malloc(size));
    ASSERT_EQ(0, memcmp(allocs.back(), kBlankMemory, std::min(size, kMaxBytesToCheckZero)));
  }

  for (void* alloc : allocs) {
    free(alloc);
  }
}

TEST(malloc, zero_init) {
#if defined(__BIONIC__)
  SKIP_WITH_HWASAN << "hwasan does not implement mallopt";
  bool allocator_scudo;
  GetAllocatorVersion(&allocator_scudo);
  if (!allocator_scudo) {
    GTEST_SKIP() << "scudo allocator only test";
  }

  mallopt(M_BIONIC_ZERO_INIT, 1);

  // Test using a block of 4K small (1-32 byte) allocations.
  TestHeapZeroing(/* num_iterations */ 0x1000, [](int iteration) -> int {
    return 1 + iteration % 32;
  });

  // Also test large allocations that land in the scudo secondary, as this is
  // the only part of Scudo that's changed by enabling zero initialization with
  // MTE. Uses 32 allocations, totalling 60MiB memory. Decay time (time to
  // release secondary allocations back to the OS) was modified to 0ms/1ms by
  // mallopt_decay. Ensure that we delay for at least a second before releasing
  // pages to the OS in order to avoid implicit zeroing by the kernel.
  mallopt(M_DECAY_TIME, 1);
  TestHeapZeroing(/* num_iterations */ 32, [](int iteration) -> int {
    return 1 << (19 + iteration % 4);
  });

#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

// Note that MTE is enabled on cc_tests on devices that support MTE.
TEST(malloc, disable_mte) {
#if defined(__BIONIC__)
  if (!mte_supported()) {
    GTEST_SKIP() << "This function can only be tested with MTE";
  }

  sem_t sem;
  ASSERT_EQ(0, sem_init(&sem, 0, 0));

  pthread_t thread;
  ASSERT_EQ(0, pthread_create(
                   &thread, nullptr,
                   [](void* ptr) -> void* {
                     auto* sem = reinterpret_cast<sem_t*>(ptr);
                     sem_wait(sem);
                     return reinterpret_cast<void*>(prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0));
                   },
                   &sem));

  ASSERT_EQ(1, mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, M_HEAP_TAGGING_LEVEL_NONE));
  ASSERT_EQ(0, sem_post(&sem));

  int my_tagged_addr_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
  ASSERT_EQ(static_cast<unsigned long>(PR_MTE_TCF_NONE), my_tagged_addr_ctrl & PR_MTE_TCF_MASK);

  void* retval;
  ASSERT_EQ(0, pthread_join(thread, &retval));
  int thread_tagged_addr_ctrl = reinterpret_cast<uintptr_t>(retval);
  ASSERT_EQ(my_tagged_addr_ctrl, thread_tagged_addr_ctrl);
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

TEST(malloc, allocation_slack) {
#if defined(__BIONIC__)
  SKIP_WITH_NATIVE_BRIDGE;  // http://b/189606147

  bool allocator_scudo;
  GetAllocatorVersion(&allocator_scudo);
  if (!allocator_scudo) {
    GTEST_SKIP() << "scudo allocator only test";
  }

  // Test that older target SDK levels let you access a few bytes off the end of
  // a large allocation.
  android_set_application_target_sdk_version(29);
  auto p = std::make_unique<char[]>(131072);
  volatile char *vp = p.get();
  volatile char oob ATTRIBUTE_UNUSED = vp[131072];
#else
  GTEST_SKIP() << "bionic extension";
#endif
}

// Regression test for b/206701345 -- scudo bug, MTE only.
// Fix: https://reviews.llvm.org/D105261
// Fix: https://android-review.googlesource.com/c/platform/external/scudo/+/1763655
TEST(malloc, realloc_mte_crash_b206701345) {
  // We want to hit in-place realloc at the very end of an mmap-ed region.  Not
  // all size classes allow such placement - mmap size has to be divisible by
  // the block size. At the time of writing this could only be reproduced with
  // 64 byte size class (i.e. 48 byte allocations), but that may change in the
  // future. Try several different classes at the lower end.
  std::vector<void*> ptrs(10000);
  for (int i = 1; i < 32; ++i) {
    size_t sz = 16 * i - 1;
    for (void*& p : ptrs) {
      p = realloc(malloc(sz), sz + 1);
    }

    for (void* p : ptrs) {
      free(p);
    }
  }
}

void VerifyAllocationsAreZero(std::function<void*(size_t)> alloc_func, std::string function_name,
                              std::vector<size_t>& test_sizes, size_t max_allocations) {
  // Vector of zero'd data used for comparisons. Make it twice the largest size.
  std::vector<char> zero(test_sizes.back() * 2, 0);

  SCOPED_TRACE(testing::Message() << function_name << " failed to zero memory");

  for (size_t test_size : test_sizes) {
    std::vector<void*> ptrs(max_allocations);
    for (size_t i = 0; i < ptrs.size(); i++) {
      SCOPED_TRACE(testing::Message() << "size " << test_size << " at iteration " << i);
      ptrs[i] = alloc_func(test_size);
      ASSERT_TRUE(ptrs[i] != nullptr);
      size_t alloc_size = malloc_usable_size(ptrs[i]);
      ASSERT_LE(alloc_size, zero.size());
      ASSERT_EQ(0, memcmp(ptrs[i], zero.data(), alloc_size));

      // Set the memory to non-zero to make sure if the pointer
      // is reused it's still zero.
      memset(ptrs[i], 0xab, alloc_size);
    }
    // Free the pointers.
    for (size_t i = 0; i < ptrs.size(); i++) {
      free(ptrs[i]);
    }
    for (size_t i = 0; i < ptrs.size(); i++) {
      SCOPED_TRACE(testing::Message() << "size " << test_size << " at iteration " << i);
      ptrs[i] = malloc(test_size);
      ASSERT_TRUE(ptrs[i] != nullptr);
      size_t alloc_size = malloc_usable_size(ptrs[i]);
      ASSERT_LE(alloc_size, zero.size());
      ASSERT_EQ(0, memcmp(ptrs[i], zero.data(), alloc_size));
    }
    // Free all of the pointers later to maximize the chance of reusing from
    // the first loop.
    for (size_t i = 0; i < ptrs.size(); i++) {
      free(ptrs[i]);
    }
  }
}

// Verify that small and medium allocations are always zero.
// @CddTest = 9.7/C-4-1
TEST(malloc, zeroed_allocations_small_medium_sizes) {
#if !defined(__BIONIC__)
  GTEST_SKIP() << "Only valid on bionic";
#endif
  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";

  if (IsLowRamDevice()) {
    GTEST_SKIP() << "Skipped on low memory devices.";
  }

  constexpr size_t kMaxAllocations = 1024;
  std::vector<size_t> test_sizes = {16, 48, 128, 1024, 4096, 65536};
  VerifyAllocationsAreZero([](size_t size) -> void* { return malloc(size); }, "malloc", test_sizes,
                           kMaxAllocations);

  VerifyAllocationsAreZero([](size_t size) -> void* { return memalign(64, size); }, "memalign",
                           test_sizes, kMaxAllocations);

  VerifyAllocationsAreZero(
      [](size_t size) -> void* {
        void* ptr;
        if (posix_memalign(&ptr, 64, size) == 0) {
          return ptr;
        }
        return nullptr;
      },
      "posix_memalign", test_sizes, kMaxAllocations);
}

// Verify that large allocations are always zero.
// @CddTest = 9.7/C-4-1
TEST(malloc, zeroed_allocations_large_sizes) {
#if !defined(__BIONIC__)
  GTEST_SKIP() << "Only valid on bionic";
#endif
  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";

  if (IsLowRamDevice()) {
    GTEST_SKIP() << "Skipped on low memory devices.";
  }

  constexpr size_t kMaxAllocations = 20;
  std::vector<size_t> test_sizes = {1000000, 2000000, 3000000, 4000000};
  VerifyAllocationsAreZero([](size_t size) -> void* { return malloc(size); }, "malloc", test_sizes,
                           kMaxAllocations);

  VerifyAllocationsAreZero([](size_t size) -> void* { return memalign(64, size); }, "memalign",
                           test_sizes, kMaxAllocations);

  VerifyAllocationsAreZero(
      [](size_t size) -> void* {
        void* ptr;
        if (posix_memalign(&ptr, 64, size) == 0) {
          return ptr;
        }
        return nullptr;
      },
      "posix_memalign", test_sizes, kMaxAllocations);
}

// Verify that reallocs are zeroed when expanded.
// @CddTest = 9.7/C-4-1
TEST(malloc, zeroed_allocations_realloc) {
#if !defined(__BIONIC__)
  GTEST_SKIP() << "Only valid on bionic";
#endif
  SKIP_WITH_HWASAN << "Only test system allocator, not hwasan allocator.";

  if (IsLowRamDevice()) {
    GTEST_SKIP() << "Skipped on low memory devices.";
  }

  // Vector of zero'd data used for comparisons.
  constexpr size_t kMaxMemorySize = 131072;
  std::vector<char> zero(kMaxMemorySize, 0);

  constexpr size_t kMaxAllocations = 1024;
  std::vector<size_t> test_sizes = {16, 48, 128, 1024, 4096, 65536};
  // Do a number of allocations and set them to non-zero.
  for (size_t test_size : test_sizes) {
    std::vector<void*> ptrs(kMaxAllocations);
    for (size_t i = 0; i < kMaxAllocations; i++) {
      ptrs[i] = malloc(test_size);
      ASSERT_TRUE(ptrs[i] != nullptr);

      // Set the memory to non-zero to make sure if the pointer
      // is reused it's still zero.
      memset(ptrs[i], 0xab, malloc_usable_size(ptrs[i]));
    }
    // Free the pointers.
    for (size_t i = 0; i < kMaxAllocations; i++) {
      free(ptrs[i]);
    }
  }

  // Do the reallocs to a larger size and verify the rest of the allocation
  // is zero.
  constexpr size_t kInitialSize = 8;
  for (size_t test_size : test_sizes) {
    std::vector<void*> ptrs(kMaxAllocations);
    for (size_t i = 0; i < kMaxAllocations; i++) {
      ptrs[i] = malloc(kInitialSize);
      ASSERT_TRUE(ptrs[i] != nullptr);
      size_t orig_alloc_size = malloc_usable_size(ptrs[i]);

      ptrs[i] = realloc(ptrs[i], test_size);
      ASSERT_TRUE(ptrs[i] != nullptr);
      size_t new_alloc_size = malloc_usable_size(ptrs[i]);
      char* ptr = reinterpret_cast<char*>(ptrs[i]);
      ASSERT_EQ(0, memcmp(&ptr[orig_alloc_size], zero.data(), new_alloc_size - orig_alloc_size))
          << "realloc from " << kInitialSize << " to size " << test_size << " at iteration " << i;
    }
    for (size_t i = 0; i < kMaxAllocations; i++) {
      free(ptrs[i]);
    }
  }
}

TEST(android_mallopt, get_decay_time_enabled_errors) {
#if defined(__BIONIC__)
  errno = 0;
  EXPECT_FALSE(android_mallopt(M_GET_DECAY_TIME_ENABLED, nullptr, sizeof(bool)));
  EXPECT_ERRNO(EINVAL);

  errno = 0;
  int value;
  EXPECT_FALSE(android_mallopt(M_GET_DECAY_TIME_ENABLED, &value, sizeof(value)));
  EXPECT_ERRNO(EINVAL);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

TEST(android_mallopt, get_decay_time_enabled) {
#if defined(__BIONIC__)
  SKIP_WITH_HWASAN << "hwasan does not implement mallopt";

  EXPECT_EQ(1, mallopt(M_DECAY_TIME, 0));

  bool value;
  EXPECT_TRUE(android_mallopt(M_GET_DECAY_TIME_ENABLED, &value, sizeof(value)));
  EXPECT_FALSE(value);

  EXPECT_EQ(1, mallopt(M_DECAY_TIME, 1));
  EXPECT_TRUE(android_mallopt(M_GET_DECAY_TIME_ENABLED, &value, sizeof(value)));
  EXPECT_TRUE(value);

  EXPECT_EQ(1, mallopt(M_DECAY_TIME, -1));
  EXPECT_TRUE(android_mallopt(M_GET_DECAY_TIME_ENABLED, &value, sizeof(value)));
  EXPECT_FALSE(value);
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

"""


```