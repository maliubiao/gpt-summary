Response:
Let's break down the thought process for analyzing the provided C++ test file and generating the response.

**1. Understanding the Goal:**

The primary goal is to understand what the `unistd_test.cpp` file does and how it relates to Android's bionic library. The request specifically asks for a summary of its functionality, its relationship to Android, explanations of libc functions, dynamic linker aspects, potential errors, how Android gets here, and Frida hooking examples. This is a multi-faceted request that requires understanding the code's purpose within a larger system.

**2. Initial Code Scan and High-Level Interpretation:**

The first step is to quickly scan the code to get a general idea. Keywords like `TEST`, `#include`, and function names like `brk`, `read`, `getenv`, `fork`, `pthread_create`, etc., immediately suggest that this is a unit test file. It's testing various functions related to the `unistd.h` header, which provides access to POSIX operating system APIs. The presence of `#include <gtest/gtest.h>` confirms it's using the Google Test framework.

**3. Identifying Key Areas of Functionality:**

Based on the included headers and the `TEST` names, I can start grouping the tested functionalities:

* **Memory Management:** `brk`, `sbrk`
* **File System Operations:** `truncate`, `ftruncate`, `read`, `open`, `close`, `fdatasync`, `fsync`, `syncfs`
* **Process Management:** `fork`, `vfork`, `clone`, `_exit`, `getpid`, `gettid`, `getppid`, `pause`, `alarm`, `abort`
* **Environment Variables:** `getenv`, `setenv`, `unsetenv`, `putenv`, `clearenv`
* **System Information:** `gethostname`, `sethostname`, `uname`, `pathconf`, `fpathconf`, `sysconf`, constants related to POSIX standards.
* **Signals:** `pause` (implicitly through signal handling)

**4. Relating Functionality to Android:**

The prompt emphasizes the connection to Android. Since `bionic` *is* Android's C library, every function tested here is a fundamental part of the Android operating system. The key is to provide concrete examples of *how* these functions are used in Android. Think about common Android development tasks:

* **Memory Allocation:** Apps and system services need to allocate memory (`brk`, `sbrk`).
* **File I/O:**  Accessing files for storage, reading configurations, etc. (`open`, `read`, `write`, `truncate`).
* **Process Creation:** Launching new processes for apps or services (`fork`, `clone`).
* **Environment Configuration:** Accessing system properties or app-specific configurations (`getenv`, `setenv`).
* **System Calls:**  Interacting with the kernel for various operations (many of these functions are wrappers around syscalls).

**5. Explaining libc Function Implementations (and Recognizing Limitations):**

The request asks for detailed explanations of *how* each libc function is implemented. This is where some strategic thinking is needed. Providing the *exact* implementation details for every function would be extremely lengthy and require deep diving into the bionic source code. Instead, focus on:

* **General Purpose:** What does the function do conceptually?
* **Underlying System Call (if applicable):** Many libc functions are thin wrappers around system calls. Mentioning the corresponding syscall (e.g., `brk` uses the `brk` syscall) is important.
* **Key Implementation Considerations:** Briefly touch upon aspects like error handling, memory management (for things like environment variables), or process creation mechanisms.
* **Acknowledging Complexity:** Explicitly state that providing the complete implementation is beyond the scope of a concise answer.

**6. Addressing Dynamic Linker Aspects:**

This requires understanding how shared libraries (`.so` files) are loaded and linked in Android.

* **SO Layout Sample:** Create a simple example showing multiple `.so` files and their dependencies. This illustrates the basic structure.
* **Linking Process:** Describe the steps involved: loading, symbol resolution, relocation. Mention the role of the dynamic linker (`linker64` or `linker`).

**7. Providing Examples of Common Errors:**

Think about typical mistakes developers make when using these functions:

* **Memory Management:**  Incorrectly using `brk` or `sbrk`, leading to memory corruption.
* **File I/O:** Forgetting to close files, using invalid file descriptors, incorrect permissions.
* **Environment Variables:** Trying to set invalid variable names.
* **Process Management:** Not handling return values of `fork` correctly, leading to unexpected behavior.

**8. Illustrating Android Framework/NDK Usage:**

Trace the path from a high-level Android component to the tested libc functions:

* **Android Framework:**  Start with a common framework class (e.g., `ProcessBuilder`). Show how it might use `fork` and `execve` (which are related to the tested functions).
* **NDK:** Explain how NDK developers directly call these libc functions from their native code.

**9. Frida Hooking Examples:**

Provide practical Frida snippets that demonstrate how to intercept calls to some of the tested functions. Focus on:

* **Basic Interception:**  Hooking a function and printing its arguments.
* **Modifying Behavior (Optional):**  Show how to change the return value or arguments (use with caution in real debugging).

**10. Summarizing Functionality for Part 1:**

Review the identified key areas of functionality and synthesize a concise summary. Emphasize that the file tests core OS functionalities provided by bionic.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Should I provide the *exact* source code for each libc function?  **Correction:** No, that's too much detail. Focus on the conceptual understanding and key aspects.
* **Initial thought:** Should I list *every single* test case? **Correction:** No, focus on the *categories* of functionality being tested.
* **Ensuring Android Relevance:** Continuously ask: "How is this specific function or test relevant to how Android works?" This helps in providing targeted examples.
* **Clarity and Structure:**  Organize the response logically using headings and bullet points to make it easier to read and understand.

By following these steps and continuously refining the approach, a comprehensive and informative answer can be generated, addressing all aspects of the request.
## 功能归纳：bionic/tests/unistd_test.cpp (第1部分)

`bionic/tests/unistd_test.cpp` 文件是 Android Bionic 库中的一个测试文件，专门用于测试 `unistd.h` 头文件中定义的各种 POSIX 标准的系统调用和库函数。

**其主要功能可以归纳为以下几点：**

1. **测试 `unistd.h` 中定义的系统调用和库函数的正确性：**  该文件包含了大量的单元测试用例（以 `TEST` 宏定义），针对 `unistd.h` 中声明的各种函数进行功能验证。这些测试覆盖了不同场景下的输入、输出和错误处理，确保这些函数在 Bionic 库中的实现符合预期。

2. **验证 Bionic 库对 POSIX 标准的兼容性：**  `unistd.h` 定义了 POSIX 标准中与操作系统交互的关键接口。这个测试文件通过测试这些接口，间接验证了 Bionic 库在多大程度上遵循了 POSIX 标准。

3. **回归测试：**  当 Bionic 库的实现发生更改时，运行这些测试可以快速发现引入的错误或不兼容性，保证代码质量和稳定性。

4. **提供示例用法：**  虽然是测试代码，但这些用例也展示了如何在 C/C++ 代码中使用 `unistd.h` 中的函数。开发者可以参考这些测试用例来理解函数的用法和预期行为。

5. **特定于 Android 的测试：**  部分测试用例可能涉及到 Android 特有的行为或扩展，例如对 `/proc` 文件系统的访问或与 Android 进程管理相关的函数。

**简单来说，这个文件的核心目的是：确保 Android 的 C 库 (Bionic) 中关于 `unistd.h` 的实现是正确的、可靠的，并且尽可能地符合 POSIX 标准。**

在接下来的部分中，我们将详细分析文件中的具体测试用例，了解其测试的具体函数和功能，以及与 Android 的关联。

Prompt: 
```
这是目录为bionic/tests/unistd_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
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

#include <gtest/gtest.h>

#include "DoNotOptimize.h"
#include "SignalUtils.h"
#include "utils.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <sys/capability.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>

#include <android-base/file.h>
#include <android-base/silent_death_test.h>
#include <android-base/strings.h>

#include "private/get_cpu_count_from_string.h"

#if defined(__BIONIC__)
#include "bionic/pthread_internal.h"
#endif

#if defined(NOFORTIFY)
#define UNISTD_TEST unistd_nofortify
#define UNISTD_DEATHTEST unistd_nofortify_DeathTest
#else
#define UNISTD_TEST unistd
#define UNISTD_DEATHTEST unistd_DeathTest
#endif

using UNISTD_DEATHTEST = SilentDeathTest;

using namespace std::chrono_literals;

static void* get_brk() {
  return sbrk(0);
}

static void* page_align(uintptr_t addr) {
  uintptr_t mask = sysconf(_SC_PAGE_SIZE) - 1;
  return reinterpret_cast<void*>((addr + mask) & ~mask);
}

TEST(UNISTD_TEST, brk) {
  void* initial_break = get_brk();

  void* new_break = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(initial_break) + 1);
  int ret = brk(new_break);
  if (ret == -1) {
    ASSERT_ERRNO(ENOMEM);
  } else {
    ASSERT_EQ(0, ret);
    ASSERT_GE(get_brk(), new_break);
  }

  // Expand by a full page to force the mapping to expand
  new_break = page_align(reinterpret_cast<uintptr_t>(initial_break) + sysconf(_SC_PAGE_SIZE));
  ret = brk(new_break);
  if (ret == -1) {
    ASSERT_ERRNO(ENOMEM);
  } else {
    ASSERT_EQ(0, ret);
    ASSERT_EQ(get_brk(), new_break);
  }
}

TEST(UNISTD_TEST, brk_ENOMEM) {
  ASSERT_EQ(-1, brk(reinterpret_cast<void*>(-1)));
  ASSERT_ERRNO(ENOMEM);
}

#if defined(__GLIBC__)
#define SBRK_MIN INTPTR_MIN
#define SBRK_MAX INTPTR_MAX
#else
#define SBRK_MIN PTRDIFF_MIN
#define SBRK_MAX PTRDIFF_MAX
#endif

TEST(UNISTD_TEST, sbrk_ENOMEM) {
#if defined(__BIONIC__) && !defined(__LP64__)
  // There is no way to guarantee that all overflow conditions can be tested
  // without manipulating the underlying values of the current break.
  extern void* __bionic_brk;

  class ScopedBrk {
  public:
    ScopedBrk() : saved_brk_(__bionic_brk) {}
    virtual ~ScopedBrk() { __bionic_brk = saved_brk_; }

  private:
    void* saved_brk_;
  };

  ScopedBrk scope_brk;

  // Set the current break to a point that will cause an overflow.
  __bionic_brk = reinterpret_cast<void*>(static_cast<uintptr_t>(PTRDIFF_MAX) + 2);

  // Can't increase by so much that we'd overflow.
  ASSERT_EQ(reinterpret_cast<void*>(-1), sbrk(PTRDIFF_MAX));
  ASSERT_ERRNO(ENOMEM);

  // Set the current break to a point that will cause an overflow.
  __bionic_brk = reinterpret_cast<void*>(static_cast<uintptr_t>(PTRDIFF_MAX));

  ASSERT_EQ(reinterpret_cast<void*>(-1), sbrk(PTRDIFF_MIN));
  ASSERT_ERRNO(ENOMEM);

  __bionic_brk = reinterpret_cast<void*>(static_cast<uintptr_t>(PTRDIFF_MAX) - 1);

  ASSERT_EQ(reinterpret_cast<void*>(-1), sbrk(PTRDIFF_MIN + 1));
  ASSERT_ERRNO(ENOMEM);
#else
  class ScopedBrk {
  public:
    ScopedBrk() : saved_brk_(get_brk()) {}
    virtual ~ScopedBrk() { brk(saved_brk_); }

  private:
    void* saved_brk_;
  };

  ScopedBrk scope_brk;

  uintptr_t cur_brk = reinterpret_cast<uintptr_t>(get_brk());
  if (cur_brk < static_cast<uintptr_t>(-(SBRK_MIN+1))) {
    // Do the overflow test for a max negative increment.
    ASSERT_EQ(reinterpret_cast<void*>(-1), sbrk(SBRK_MIN));
#if defined(__BIONIC__)
    // GLIBC does not set errno in overflow case.
    ASSERT_ERRNO(ENOMEM);
#endif
  }

  uintptr_t overflow_brk = static_cast<uintptr_t>(SBRK_MAX) + 2;
  if (cur_brk < overflow_brk) {
    // Try and move the value to PTRDIFF_MAX + 2.
    cur_brk = reinterpret_cast<uintptr_t>(sbrk(overflow_brk));
  }
  if (cur_brk >= overflow_brk) {
    ASSERT_EQ(reinterpret_cast<void*>(-1), sbrk(SBRK_MAX));
#if defined(__BIONIC__)
    // GLIBC does not set errno in overflow case.
    ASSERT_ERRNO(ENOMEM);
#endif
  }
#endif
}

TEST(UNISTD_TEST, truncate) {
  TemporaryFile tf;
  ASSERT_EQ(0, close(tf.fd));
  ASSERT_EQ(0, truncate(tf.path, 123));

  struct stat sb;
  ASSERT_EQ(0, stat(tf.path, &sb));
  ASSERT_EQ(123, sb.st_size);
}

TEST(UNISTD_TEST, truncate64_smoke) {
  TemporaryFile tf;
  ASSERT_EQ(0, close(tf.fd));
  ASSERT_EQ(0, truncate64(tf.path, 123));

  struct stat sb;
  ASSERT_EQ(0, stat(tf.path, &sb));
  ASSERT_EQ(123, sb.st_size);
}

TEST(UNISTD_TEST, ftruncate) {
  TemporaryFile tf;
  ASSERT_EQ(0, ftruncate(tf.fd, 123));
  ASSERT_EQ(0, close(tf.fd));

  struct stat sb;
  ASSERT_EQ(0, stat(tf.path, &sb));
  ASSERT_EQ(123, sb.st_size);
}

TEST(UNISTD_TEST, ftruncate64_smoke) {
  TemporaryFile tf;
  ASSERT_EQ(0, ftruncate64(tf.fd, 123));
  ASSERT_EQ(0, close(tf.fd));

  struct stat sb;
  ASSERT_EQ(0, stat(tf.path, &sb));
  ASSERT_EQ(123, sb.st_size);
}

TEST(UNISTD_TEST, ftruncate_negative) {
  TemporaryFile tf;
  errno = 0;
  ASSERT_EQ(-1, ftruncate(tf.fd, -123));
  ASSERT_ERRNO(EINVAL);
}

static bool g_pause_test_flag = false;
static void PauseTestSignalHandler(int) {
  g_pause_test_flag = true;
}

TEST(UNISTD_TEST, pause) {
  ScopedSignalHandler handler(SIGALRM, PauseTestSignalHandler);

  alarm(1);
  ASSERT_FALSE(g_pause_test_flag);
  ASSERT_EQ(-1, pause());
  ASSERT_TRUE(g_pause_test_flag);
}

TEST(UNISTD_TEST, read) {
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);

  char buf[5];
  ASSERT_EQ(5, read(fd, buf, 5));
  ASSERT_EQ(buf[0], 'L');
  ASSERT_EQ(buf[1], 'i');
  ASSERT_EQ(buf[2], 'n');
  ASSERT_EQ(buf[3], 'u');
  ASSERT_EQ(buf[4], 'x');
  close(fd);
}

TEST(UNISTD_TEST, read_EBADF) {
  // read returns ssize_t which is 64-bits on LP64, so it's worth explicitly checking that
  // our syscall stubs correctly return a 64-bit -1.
  char buf[1];
  ASSERT_EQ(-1, read(-1, buf, sizeof(buf)));
  ASSERT_ERRNO(EBADF);
}

TEST(UNISTD_TEST, syscall_long) {
  // Check that syscall(3) correctly returns long results.
  // https://code.google.com/p/android/issues/detail?id=73952
  // We assume that the break is > 4GiB, but this is potentially flaky.
  uintptr_t p = reinterpret_cast<uintptr_t>(sbrk(0));
  ASSERT_EQ(p, static_cast<uintptr_t>(syscall(__NR_brk, 0)));
}

TEST(UNISTD_TEST, alarm) {
  ASSERT_EQ(0U, alarm(0));
}

TEST(UNISTD_TEST, _exit) {
  pid_t pid = fork();
  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    _exit(99);
  }

  AssertChildExited(pid, 99);
}

TEST(UNISTD_TEST, getenv_unsetenv) {
  ASSERT_EQ(0, setenv("test-variable", "hello", 1));
  ASSERT_STREQ("hello", getenv("test-variable"));
  ASSERT_EQ(0, unsetenv("test-variable"));
  ASSERT_TRUE(getenv("test-variable") == nullptr);
}

TEST(UNISTD_TEST, unsetenv_EINVAL) {
  EXPECT_EQ(-1, unsetenv(""));
  EXPECT_ERRNO(EINVAL);
  EXPECT_EQ(-1, unsetenv("a=b"));
  EXPECT_ERRNO(EINVAL);
}

TEST(UNISTD_TEST, setenv_EINVAL) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  EXPECT_EQ(-1, setenv(nullptr, "value", 0));
  EXPECT_ERRNO(EINVAL);
  EXPECT_EQ(-1, setenv(nullptr, "value", 1));
  EXPECT_ERRNO(EINVAL);
#pragma clang diagnostic pop
  EXPECT_EQ(-1, setenv("", "value", 0));
  EXPECT_ERRNO(EINVAL);
  EXPECT_EQ(-1, setenv("", "value", 1));
  EXPECT_ERRNO(EINVAL);
  EXPECT_EQ(-1, setenv("a=b", "value", 0));
  EXPECT_ERRNO(EINVAL);
  EXPECT_EQ(-1, setenv("a=b", "value", 1));
  EXPECT_ERRNO(EINVAL);
}

TEST(UNISTD_TEST, setenv) {
  ASSERT_EQ(0, unsetenv("test-variable"));

  char a[] = "a";
  char b[] = "b";
  char c[] = "c";

  // New value.
  EXPECT_EQ(0, setenv("test-variable", a, 0));
  EXPECT_STREQ(a, getenv("test-variable"));

  // Existing value, no overwrite.
  EXPECT_EQ(0, setenv("test-variable", b, 0));
  EXPECT_STREQ(a, getenv("test-variable"));

  // Existing value, overwrite.
  EXPECT_EQ(0, setenv("test-variable", c, 1));
  EXPECT_STREQ(c, getenv("test-variable"));
  // But the arrays backing the values are unchanged.
  EXPECT_EQ('a', a[0]);
  EXPECT_EQ('b', b[0]);
  EXPECT_EQ('c', c[0]);

  ASSERT_EQ(0, unsetenv("test-variable"));
}

TEST(UNISTD_TEST, putenv) {
  ASSERT_EQ(0, unsetenv("a"));

  char* s1 = strdup("a=b");
  ASSERT_EQ(0, putenv(s1));

  ASSERT_STREQ("b", getenv("a"));
  s1[2] = 'c';
  ASSERT_STREQ("c", getenv("a"));

  char* s2 = strdup("a=b");
  ASSERT_EQ(0, putenv(s2));

  ASSERT_STREQ("b", getenv("a"));
  ASSERT_EQ('c', s1[2]);

  ASSERT_EQ(0, unsetenv("a"));
  free(s1);
  free(s2);
}

TEST(UNISTD_TEST, clearenv) {
  extern char** environ;

  // Guarantee that environ is not initially empty...
  ASSERT_EQ(0, setenv("test-variable", "a", 1));

  // Stash a copy.
  std::vector<char*> old_environ;
  for (size_t i = 0; environ[i] != nullptr; ++i) {
    old_environ.push_back(strdup(environ[i]));
  }

  ASSERT_EQ(0, clearenv());

  EXPECT_TRUE(environ == nullptr || environ[0] == nullptr);
  EXPECT_EQ(nullptr, getenv("test-variable"));
  EXPECT_EQ(0, setenv("test-variable", "post-clear", 1));
  EXPECT_STREQ("post-clear", getenv("test-variable"));

  // Put the old environment back.
  for (size_t i = 0; i < old_environ.size(); ++i) {
    EXPECT_EQ(0, putenv(old_environ[i]));
  }

  // Check it wasn't overwritten.
  EXPECT_STREQ("a", getenv("test-variable"));

  EXPECT_EQ(0, unsetenv("test-variable"));
}

static void TestSyncFunction(int (*fn)(int)) {
  int fd;

  // Can't sync an invalid fd.
  errno = 0;
  EXPECT_EQ(-1, fn(-1));
  EXPECT_ERRNO(EBADF);

  // It doesn't matter whether you've opened a file for write or not.
  TemporaryFile tf;
  ASSERT_NE(-1, tf.fd);

  EXPECT_EQ(0, fn(tf.fd));

  ASSERT_NE(-1, fd = open(tf.path, O_RDONLY));
  EXPECT_EQ(0, fn(fd));
  close(fd);

  ASSERT_NE(-1, fd = open(tf.path, O_RDWR));
  EXPECT_EQ(0, fn(fd));
  close(fd);

  // The fd can even be a directory.
  ASSERT_NE(-1, fd = open("/data/local/tmp", O_RDONLY));
  EXPECT_EQ(0, fn(fd));
  close(fd);
}

static void TestFsyncFunction(int (*fn)(int)) {
  TestSyncFunction(fn);

  // But some file systems are fussy about fsync/fdatasync...
  errno = 0;
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_NE(-1, fd);
  EXPECT_EQ(-1, fn(fd));
  EXPECT_ERRNO(EINVAL);
  close(fd);
}

TEST(UNISTD_TEST, fdatasync) {
  TestFsyncFunction(fdatasync);
}

TEST(UNISTD_TEST, fsync) {
  TestFsyncFunction(fsync);
}

TEST(UNISTD_TEST, syncfs) {
  TestSyncFunction(syncfs);
}

TEST(UNISTD_TEST, _Fork) {
#if defined(__BIONIC__)
  pid_t rc = _Fork();
  ASSERT_NE(-1, rc);
  if (rc == 0) {
    _exit(66);
  }

  int status;
  pid_t wait_result = waitpid(rc, &status, 0);
  ASSERT_EQ(wait_result, rc);
  ASSERT_TRUE(WIFEXITED(status));
  ASSERT_EQ(66, WEXITSTATUS(status));
#endif
}

TEST(UNISTD_TEST, vfork) {
#if defined(__BIONIC__)
  pthread_internal_t* self = __get_thread();

  pid_t cached_pid;
  ASSERT_TRUE(self->get_cached_pid(&cached_pid));
  ASSERT_EQ(syscall(__NR_getpid), cached_pid);
  ASSERT_FALSE(self->is_vforked());

  pid_t rc = vfork();
  ASSERT_NE(-1, rc);
  if (rc == 0) {
    if (self->get_cached_pid(&cached_pid)) {
      const char* error = "__get_thread()->cached_pid_ set after vfork\n";
      write(STDERR_FILENO, error, strlen(error));
      _exit(1);
    }

    if (!self->is_vforked()) {
      const char* error = "__get_thread()->vforked_ not set after vfork\n";
      write(STDERR_FILENO, error, strlen(error));
      _exit(1);
    }

    _exit(0);
  } else {
    ASSERT_TRUE(self->get_cached_pid(&cached_pid));
    ASSERT_EQ(syscall(__NR_getpid), cached_pid);
    ASSERT_FALSE(self->is_vforked());

    int status;
    pid_t wait_result = waitpid(rc, &status, 0);
    ASSERT_EQ(wait_result, rc);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));
  }
#endif
}

static void AssertGetPidCorrect() {
  // The loop is just to make manual testing/debugging with strace easier.
  pid_t getpid_syscall_result = syscall(__NR_getpid);
  for (size_t i = 0; i < 128; ++i) {
    ASSERT_EQ(getpid_syscall_result, getpid());
  }
}

static void TestGetPidCachingWithFork(int (*fork_fn)(), void (*exit_fn)(int)) {
  pid_t parent_pid = getpid();
  ASSERT_EQ(syscall(__NR_getpid), parent_pid);

  pid_t fork_result = fork_fn();
  ASSERT_NE(fork_result, -1);
  if (fork_result == 0) {
    // We're the child.
    ASSERT_NO_FATAL_FAILURE(AssertGetPidCorrect());
    ASSERT_EQ(parent_pid, getppid());
    exit_fn(123);
  } else {
    // We're the parent.
    ASSERT_EQ(parent_pid, getpid());
    AssertChildExited(fork_result, 123);
  }
}

// gettid() is marked as __attribute_const__, which will have the compiler
// optimize out multiple calls to gettid in the same function. This wrapper
// defeats that optimization.
static __attribute__((__noinline__)) pid_t GetTidForTest() {
  __asm__("");
  return gettid();
}

static void AssertGetTidCorrect() {
  // The loop is just to make manual testing/debugging with strace easier.
  pid_t gettid_syscall_result = syscall(__NR_gettid);
  for (size_t i = 0; i < 128; ++i) {
    ASSERT_EQ(gettid_syscall_result, GetTidForTest());
  }
}

static void TestGetTidCachingWithFork(int (*fork_fn)(), void (*exit_fn)(int)) {
  pid_t parent_tid = GetTidForTest();
  ASSERT_EQ(syscall(__NR_gettid), parent_tid);

  pid_t fork_result = fork_fn();
  ASSERT_NE(fork_result, -1);
  if (fork_result == 0) {
    // We're the child.
    EXPECT_EQ(syscall(__NR_getpid), syscall(__NR_gettid));
    EXPECT_EQ(getpid(), GetTidForTest()) << "real tid is " << syscall(__NR_gettid)
                                         << ", pid is " << syscall(__NR_getpid);
    ASSERT_NO_FATAL_FAILURE(AssertGetTidCorrect());
    exit_fn(123);
  } else {
    // We're the parent.
    ASSERT_EQ(parent_tid, GetTidForTest());
    AssertChildExited(fork_result, 123);
  }
}

TEST(UNISTD_TEST, getpid_caching_and_fork) {
  TestGetPidCachingWithFork(fork, exit);
}

TEST(UNISTD_TEST, gettid_caching_and_fork) {
  TestGetTidCachingWithFork(fork, exit);
}

TEST(UNISTD_TEST, getpid_caching_and_vfork) {
  TestGetPidCachingWithFork(vfork, _exit);
}

static int CloneLikeFork() {
  return clone(nullptr, nullptr, SIGCHLD, nullptr);
}

TEST(UNISTD_TEST, getpid_caching_and_clone_process) {
  TestGetPidCachingWithFork(CloneLikeFork, exit);
}

TEST(UNISTD_TEST, gettid_caching_and_clone_process) {
  TestGetTidCachingWithFork(CloneLikeFork, exit);
}

static int CloneAndSetTid() {
  pid_t child_tid = 0;
  pid_t parent_tid = GetTidForTest();

  int rv = clone(nullptr, nullptr, CLONE_CHILD_SETTID | SIGCHLD, nullptr, nullptr, nullptr, &child_tid);
  EXPECT_NE(-1, rv);

  if (rv == 0) {
    // Child.
    EXPECT_EQ(child_tid, GetTidForTest());
    EXPECT_NE(child_tid, parent_tid);
  } else {
    EXPECT_NE(child_tid, GetTidForTest());
    EXPECT_NE(child_tid, parent_tid);
    EXPECT_EQ(GetTidForTest(), parent_tid);
  }

  return rv;
}

TEST(UNISTD_TEST, gettid_caching_and_clone_process_settid) {
  TestGetTidCachingWithFork(CloneAndSetTid, exit);
}

__attribute__((no_sanitize("hwaddress", "memtag")))
static int CloneStartRoutine(int (*start_routine)(void*)) {
  void* child_stack[1024];
  return clone(start_routine, &child_stack[1024], SIGCHLD, nullptr);
}

static int GetPidCachingCloneStartRoutine(void*) {
  AssertGetPidCorrect();
  return 123;
}

TEST(UNISTD_TEST, getpid_caching_and_clone) {
  pid_t parent_pid = getpid();
  ASSERT_EQ(syscall(__NR_getpid), parent_pid);

  int clone_result = CloneStartRoutine(GetPidCachingCloneStartRoutine);
  ASSERT_NE(clone_result, -1);

  ASSERT_EQ(parent_pid, getpid());

  AssertChildExited(clone_result, 123);
}

static int GetTidCachingCloneStartRoutine(void*) {
  AssertGetTidCorrect();
  return 123;
}

TEST(UNISTD_TEST, gettid_caching_and_clone) {
  pid_t parent_tid = GetTidForTest();
  ASSERT_EQ(syscall(__NR_gettid), parent_tid);

  int clone_result = CloneStartRoutine(GetTidCachingCloneStartRoutine);
  ASSERT_NE(clone_result, -1);

  ASSERT_EQ(parent_tid, GetTidForTest());

  AssertChildExited(clone_result, 123);
}

static int CloneChildExit(void*) {
  AssertGetPidCorrect();
  AssertGetTidCorrect();
  exit(33);
}

TEST(UNISTD_TEST, clone_fn_and_exit) {
  int clone_result = CloneStartRoutine(CloneChildExit);
  ASSERT_NE(-1, clone_result);

  AssertGetPidCorrect();
  AssertGetTidCorrect();

  AssertChildExited(clone_result, 33);
}

static void* GetPidCachingPthreadStartRoutine(void*) {
  AssertGetPidCorrect();
  return nullptr;
}

TEST(UNISTD_TEST, getpid_caching_and_pthread_create) {
  pid_t parent_pid = getpid();

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, GetPidCachingPthreadStartRoutine, nullptr));

  ASSERT_EQ(parent_pid, getpid());

  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_EQ(nullptr, result);
}

static void* GetTidCachingPthreadStartRoutine(void*) {
  AssertGetTidCorrect();
  uint64_t tid = GetTidForTest();
  return reinterpret_cast<void*>(tid);
}

TEST(UNISTD_TEST, gettid_caching_and_pthread_create) {
  pid_t parent_tid = GetTidForTest();

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, GetTidCachingPthreadStartRoutine, &parent_tid));

  ASSERT_EQ(parent_tid, GetTidForTest());

  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_NE(static_cast<uint64_t>(parent_tid), reinterpret_cast<uint64_t>(result));
}

__attribute__((noinline)) static void HwasanVforkTestChild() {
  // Allocate a tagged region on stack and leave it there.
  char x[10000];
  DoNotOptimize(x);
  _exit(0);
}

__attribute__((noinline)) static void HwasanReadMemory(const char* p, size_t size) {
  // Read memory byte-by-byte. This will blow up if the pointer tag in p does not match any memory
  // tag in [p, p+size).
  char z;
  for (size_t i = 0; i < size; ++i) {
    DoNotOptimize(z = p[i]);
  }
}

__attribute__((noinline, no_sanitize("hwaddress"))) static void HwasanVforkTestParent() {
  // Allocate a region on stack, but don't tag it (see the function attribute).
  // This depends on unallocated stack space at current function entry being untagged.
  char x[10000];
  DoNotOptimize(x);
  // Verify that contents of x[] are untagged.
  HwasanReadMemory(x, sizeof(x));
}

TEST(UNISTD_TEST, hwasan_vfork) {
  // Test hwasan annotation in vfork. This test is only interesting when built with hwasan, but it
  // is supposed to work correctly either way.
  if (vfork()) {
    HwasanVforkTestParent();
  } else {
    HwasanVforkTestChild();
  }
}

TEST_F(UNISTD_DEATHTEST, abort) {
  ASSERT_EXIT(abort(), testing::KilledBySignal(SIGABRT), "");
}

TEST(UNISTD_TEST, sethostname) {
  // The permissions check happens before the argument check, so this will
  // fail for a different reason if you're running as root than if you're
  // not, but it'll fail either way. Checking that we have the symbol is about
  // all we can do for sethostname(2).
  ASSERT_EQ(-1, sethostname("", -1));
}

TEST(UNISTD_TEST, gethostname) {
  char hostname[HOST_NAME_MAX + 1];
  memset(hostname, 0, sizeof(hostname));

  // Can we get the hostname with a big buffer?
  ASSERT_EQ(0, gethostname(hostname, HOST_NAME_MAX));

  // Can we get the hostname with a right-sized buffer?
  ASSERT_EQ(0, gethostname(hostname, strlen(hostname) + 1));

  // Does uname(2) agree?
  utsname buf;
  ASSERT_EQ(0, uname(&buf));
  ASSERT_EQ(0, strncmp(hostname, buf.nodename, sizeof(buf.nodename)));
  ASSERT_GT(strlen(hostname), 0U);

  // Do we correctly detect truncation?
  errno = 0;
  ASSERT_EQ(-1, gethostname(hostname, strlen(hostname)));
  ASSERT_ERRNO(ENAMETOOLONG);
}

TEST(UNISTD_TEST, pathconf_fpathconf) {
  TemporaryFile tf;
  long l;

  // As a file system's block size is always power of 2, the configure values
  // for ALLOC and XFER should be power of 2 as well.
  l = pathconf(tf.path, _PC_ALLOC_SIZE_MIN);
  ASSERT_TRUE(l > 0 && powerof2(l));
  l = pathconf(tf.path, _PC_REC_MIN_XFER_SIZE);
  ASSERT_TRUE(l > 0 && powerof2(l));
  l = pathconf(tf.path, _PC_REC_XFER_ALIGN);
  ASSERT_TRUE(l > 0 && powerof2(l));

  l = fpathconf(tf.fd, _PC_ALLOC_SIZE_MIN);
  ASSERT_TRUE(l > 0 && powerof2(l));
  l = fpathconf(tf.fd, _PC_REC_MIN_XFER_SIZE);
  ASSERT_TRUE(l > 0 && powerof2(l));
  l = fpathconf(tf.fd, _PC_REC_XFER_ALIGN);
  ASSERT_TRUE(l > 0 && powerof2(l));

  // Check that the "I can't answer that, you'll have to try it and see"
  // cases don't set errno.
  int names[] = {
      _PC_ASYNC_IO, _PC_PRIO_IO, _PC_REC_INCR_XFER_SIZE, _PC_REC_MAX_XFER_SIZE, _PC_SYMLINK_MAX,
      _PC_SYNC_IO,  -1};
  for (size_t i = 0; names[i] != -1; i++) {
    errno = 0;
    ASSERT_EQ(-1, pathconf(tf.path, names[i])) << names[i];
    ASSERT_ERRNO(0) << names[i];
    ASSERT_EQ(-1, fpathconf(tf.fd, names[i])) << names[i];
    ASSERT_ERRNO(0) << names[i];
  }
}

TEST(UNISTD_TEST, _POSIX_constants) {
  // Make a tight verification of _POSIX_* / _POSIX2_* / _XOPEN_* macros, to prevent change by mistake.
  // Verify according to POSIX.1-2008.
  EXPECT_EQ(200809L, _POSIX_VERSION);

  EXPECT_EQ(2, _POSIX_AIO_LISTIO_MAX);
  EXPECT_EQ(1, _POSIX_AIO_MAX);
  EXPECT_EQ(4096, _POSIX_ARG_MAX);
  EXPECT_EQ(25, _POSIX_CHILD_MAX);
  EXPECT_EQ(20000000, _POSIX_CLOCKRES_MIN);
  EXPECT_EQ(32, _POSIX_DELAYTIMER_MAX);
  EXPECT_EQ(255, _POSIX_HOST_NAME_MAX);
  EXPECT_EQ(8, _POSIX_LINK_MAX);
  EXPECT_EQ(9, _POSIX_LOGIN_NAME_MAX);
  EXPECT_EQ(255, _POSIX_MAX_CANON);
  EXPECT_EQ(255, _POSIX_MAX_INPUT);
  EXPECT_EQ(8, _POSIX_MQ_OPEN_MAX);
  EXPECT_EQ(32, _POSIX_MQ_PRIO_MAX);
  EXPECT_EQ(14, _POSIX_NAME_MAX);
  EXPECT_EQ(8, _POSIX_NGROUPS_MAX);
  EXPECT_EQ(20, _POSIX_OPEN_MAX);
  EXPECT_EQ(256, _POSIX_PATH_MAX);
  EXPECT_EQ(512, _POSIX_PIPE_BUF);
  EXPECT_EQ(255, _POSIX_RE_DUP_MAX);
  EXPECT_EQ(8, _POSIX_RTSIG_MAX);
  EXPECT_EQ(256, _POSIX_SEM_NSEMS_MAX);
  EXPECT_EQ(32767, _POSIX_SEM_VALUE_MAX);
  EXPECT_EQ(32, _POSIX_SIGQUEUE_MAX);
  EXPECT_EQ(32767, _POSIX_SSIZE_MAX);
  EXPECT_EQ(8, _POSIX_STREAM_MAX);
#if !defined(__GLIBC__)
  EXPECT_EQ(4, _POSIX_SS_REPL_MAX);
#endif
  EXPECT_EQ(255, _POSIX_SYMLINK_MAX);
  EXPECT_EQ(8, _POSIX_SYMLOOP_MAX);
  EXPECT_EQ(4, _POSIX_THREAD_DESTRUCTOR_ITERATIONS);
  EXPECT_EQ(128, _POSIX_THREAD_KEYS_MAX);
  EXPECT_EQ(64, _POSIX_THREAD_THREADS_MAX);
  EXPECT_EQ(32, _POSIX_TIMER_MAX);
#if !defined(__GLIBC__)
  EXPECT_EQ(30, _POSIX_TRACE_EVENT_NAME_MAX);
  EXPECT_EQ(8, _POSIX_TRACE_NAME_MAX);
  EXPECT_EQ(8, _POSIX_TRACE_SYS_MAX);
  EXPECT_EQ(32, _POSIX_TRACE_USER_EVENT_MAX);
#endif
  EXPECT_EQ(9, _POSIX_TTY_NAME_MAX);
  EXPECT_EQ(6, _POSIX_TZNAME_MAX);
  EXPECT_EQ(99, _POSIX2_BC_BASE_MAX);
  EXPECT_EQ(2048, _POSIX2_BC_DIM_MAX);
  EXPECT_EQ(99, _POSIX2_BC_SCALE_MAX);
  EXPECT_EQ(1000, _POSIX2_BC_STRING_MAX);
  EXPECT_EQ(14, _POSIX2_CHARCLASS_NAME_MAX);
  EXPECT_EQ(2, _POSIX2_COLL_WEIGHTS_MAX);
  EXPECT_EQ(32, _POSIX2_EXPR_NEST_MAX);
  EXPECT_EQ(2048, _POSIX2_LINE_MAX);
  EXPECT_EQ(255, _POSIX2_RE_DUP_MAX);

  EXPECT_EQ(16, _XOPEN_IOV_MAX);
#if !defined(__GLIBC__)
  EXPECT_EQ(255, _XOPEN_NAME_MAX);
  EXPECT_EQ(1024, _XOPEN_PATH_MAX);
#endif
}

TEST(UNISTD_TEST, _POSIX_options) {
  EXPECT_EQ(_POSIX_VERSION, _POSIX_ADVISORY_INFO);
  EXPECT_GT(_POSIX_BARRIERS, 0);
  EXPECT_GT(_POSIX_SPIN_LOCKS, 0);
  EXPECT_NE(_POSIX_CHOWN_RESTRICTED, -1);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_CLOCK_SELECTION);
#if !defined(__GLIBC__) // glibc supports ancient kernels.
  EXPECT_EQ(_POSIX_VERSION, _POSIX_CPUTIME);
#endif
  EXPECT_EQ(_POSIX_VERSION, _POSIX_FSYNC);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_IPV6);
  EXPECT_GT(_POSIX_JOB_CONTROL, 0);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_MAPPED_FILES);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_MEMLOCK);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_MEMLOCK_RANGE);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_MEMORY_PROTECTION);
#if !defined(__GLIBC__) // glibc supports ancient kernels.
  EXPECT_EQ(_POSIX_VERSION, _POSIX_MONOTONIC_CLOCK);
#endif
  EXPECT_GT(_POSIX_NO_TRUNC, 0);
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(_POSIX_VERSION, _POSIX_PRIORITY_SCHEDULING);
#endif
  EXPECT_EQ(_POSIX_VERSION, _POSIX_RAW_SOCKETS);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_READER_WRITER_LOCKS);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_REALTIME_SIGNALS);
  EXPECT_GT(_POSIX_REGEXP, 0);
  EXPECT_GT(_POSIX_SAVED_IDS, 0);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_SEMAPHORES);
  EXPECT_GT(_POSIX_SHELL, 0);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_SPAWN);
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(-1, _POSIX_SPORADIC_SERVER);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_SYNCHRONIZED_IO);
#endif
  EXPECT_EQ(_POSIX_VERSION, _POSIX_THREADS);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_THREAD_ATTR_STACKADDR);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_THREAD_ATTR_STACKSIZE);
#if !defined(__GLIBC__) // glibc supports ancient kernels.
  EXPECT_EQ(_POSIX_VERSION, _POSIX_THREAD_CPUTIME);
#endif
  EXPECT_EQ(_POSIX_VERSION, _POSIX_THREAD_PRIORITY_SCHEDULING);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_THREAD_PROCESS_SHARED);
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(-1, _POSIX_THREAD_ROBUST_PRIO_PROTECT);
#endif
  EXPECT_EQ(_POSIX_VERSION, _POSIX_THREAD_SAFE_FUNCTIONS);
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(-1, _POSIX_THREAD_SPORADIC_SERVER);
#endif
  EXPECT_EQ(_POSIX_VERSION, _POSIX_TIMEOUTS);
  EXPECT_EQ(_POSIX_VERSION, _POSIX_TIMERS);
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(-1, _POSIX_TRACE);
  EXPECT_EQ(-1, _POSIX_TRACE_EVENT_FILTER);
  EXPECT_EQ(-1, _POSIX_TRACE_INHERIT);
  EXPECT_EQ(-1, _POSIX_TRACE_LOG);
  EXPECT_EQ(-1, _POSIX_TYPED_MEMORY_OBJECTS);
#endif
  EXPECT_NE(-1, _POSIX_VDISABLE);

  EXPECT_EQ(_POSIX_VERSION, _POSIX2_VERSION);
  EXPECT_EQ(_POSIX_VERSION, _POSIX2_C_BIND);
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(_POSIX_VERSION, _POSIX2_CHAR_TERM);
#endif

  EXPECT_EQ(700, _XOPEN_VERSION);
  EXPECT_EQ(1, _XOPEN_ENH_I18N);
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(1, _XOPEN_REALTIME);
  EXPECT_EQ(1, _XOPEN_REALTIME_THREADS);
  EXPECT_EQ(1, _XOPEN_SHM);
#endif
  EXPECT_EQ(1, _XOPEN_UNIX);

#if defined(__BIONIC__)
  // These tests only pass on bionic, as bionic and glibc has different support on these macros.
  // Macros like _POSIX_ASYNCHRONOUS_IO are not supported on bionic yet.
  EXPECT_EQ(-1, _POSIX_ASYNCHRONOUS_IO);
  EXPECT_EQ(-1, _POSIX_MESSAGE_PASSING);
  EXPECT_EQ(-1, _POSIX_PRIORITIZED_IO);
  EXPECT_EQ(-1, _POSIX_SHARED_MEMORY_OBJECTS);
  EXPECT_EQ(-1, _POSIX_THREAD_PRIO_INHERIT);
  EXPECT_EQ(-1, _POSIX_THREAD_PRIO_PROTECT);
  EXPECT_EQ(-1, _POSIX_THREAD_ROBUST_PRIO_INHERIT);

  EXPECT_EQ(-1, _POSIX2_C_DEV);
  EXPECT_EQ(-1, _POSIX2_FORT_DEV);
  EXPECT_EQ(-1, _POSIX2_FORT_RUN);
  EXPECT_EQ(-1, _POSIX2_LOCALEDEF);
  EXPECT_EQ(-1, _POSIX2_SW_DEV);
  EXPECT_EQ(-1, _POSIX2_UPE);

  EXPECT_EQ(-1, _XOPEN_CRYPT);
  EXPECT_EQ(-1, _XOPEN_LEGACY);
  EXPECT_EQ(-1, _XOPEN_STREAMS);
#endif // defined(__BIONIC__)
}

#define VERIFY_SYSCONF_UNKNOWN(name) \
  VerifySysconf(name, #name, [](long v){return v == -1 && errno == EINVAL;})

#define VERIFY_SYSCONF_UNSUPPORTED(name) \
  VerifySysconf(name, #name, [](long v){return v == -1 && errno == 0;})

// sysconf() means unlimited when it returns -1 with errno unchanged.
#define VERIFY_SYSCONF_POSITIVE(name) \
  VerifySysconf(name, #name, [](long v){return (v > 0 || v == -1) && errno == 0;})

#define VERIFY_SYSCONF_POSIX_VERSION(name) \
  VerifySysconf(name, #name, [](long v){return v == _POSIX_VERSION && errno == 0;})

static void VerifySysconf(int option, const char *option_name, bool (*verify)(long)) {
  errno = 0;
  long ret = sysconf(option);
  EXPECT_TRUE(verify(ret)) << "name = " << option_name << ", ret = "
      << ret <<", Error Message: " << strerror(errno);
}

TEST(UNISTD_TEST, sysconf) {
  VERIFY_SYSCONF_POSIX_VERSION(_SC_ADVISORY_INFO);
  VERIFY_SYSCONF_POSITIVE(_SC_ARG_MAX);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_BARRIERS);
  VERIFY_SYSCONF_POSITIVE(_SC_BC_BASE_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_BC_DIM_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_BC_SCALE_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_CHILD_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_CLK_TCK);
  VERIFY_SYSCONF_POSITIVE(_SC_COLL_WEIGHTS_MAX);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_CPUTIME);
  VERIFY_SYSCONF_POSITIVE(_SC_EXPR_NEST_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_LINE_MAX);
  VerifySysconf(_SC_NGROUPS_MAX, "_SC_NGROUPS_MAX", [](long v){return v >= 0 && v <= NGROUPS_MAX;});
  VERIFY_SYSCONF_POSITIVE(_SC_OPEN_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_PASS_MAX);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_2_C_BIND);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_FORT_DEV);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_FORT_RUN);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_UPE);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_2_VERSION);
  VERIFY_SYSCONF_POSITIVE(_SC_JOB_CONTROL);
  VERIFY_SYSCONF_POSITIVE(_SC_SAVED_IDS);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_VERSION);
  VERIFY_SYSCONF_POSITIVE(_SC_RE_DUP_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_STREAM_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_TZNAME_MAX);
  VerifySysconf(_SC_XOPEN_VERSION, "_SC_XOPEN_VERSION", [](long v){return v == _XOPEN_VERSION && errno == 0;});
  VERIFY_SYSCONF_POSITIVE(_SC_ATEXIT_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_IOV_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_UIO_MAXIOV);
  EXPECT_EQ(sysconf(_SC_IOV_MAX), sysconf(_SC_UIO_MAXIOV));
  VERIFY_SYSCONF_POSITIVE(_SC_PAGESIZE);
  VERIFY_SYSCONF_POSITIVE(_SC_PAGE_SIZE);
  VerifySysconf(_SC_PAGE_SIZE, "_SC_PAGE_SIZE",
                [](long v){return v == sysconf(_SC_PAGESIZE) && errno == 0 && v == getpagesize();});
  VERIFY_SYSCONF_POSITIVE(_SC_XOPEN_UNIX);
  VERIFY_SYSCONF_POSITIVE(_SC_AIO_LISTIO_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_AIO_MAX);
  VerifySysconf(_SC_AIO_PRIO_DELTA_MAX, "_SC_AIO_PRIO_DELTA_MAX", [](long v){return v >= 0 && errno == 0;});
  VERIFY_SYSCONF_POSITIVE(_SC_DELAYTIMER_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_MQ_OPEN_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_MQ_PRIO_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_RTSIG_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_SEM_NSEMS_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_SEM_VALUE_MAX);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_SPIN_LOCKS);
  VERIFY_SYSCONF_POSITIVE(_SC_TIMER_MAX);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_FSYNC);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_MAPPED_FILES);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_MEMLOCK);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_MEMLOCK_RANGE);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_MEMORY_PROTECTION);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_PRIORITY_SCHEDULING);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_REALTIME_SIGNALS);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_SEMAPHORES);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_SYNCHRONIZED_IO);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_TIMERS);
  VERIFY_SYSCONF_POSITIVE(_SC_GETGR_R_SIZE_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_GETPW_R_SIZE_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_LOGIN_NAME_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_THREAD_DESTRUCTOR_ITERATIONS);
  VERIFY_SYSCONF_POSITIVE(_SC_THREAD_KEYS_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_THREAD_STACK_MIN);
  VERIFY_SYSCONF_POSITIVE(_SC_THREAD_THREADS_MAX);
  VERIFY_SYSCONF_POSITIVE(_SC_TTY_NAME_MAX);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_THREADS);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_THREAD_ATTR_STACKADDR);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_THREAD_ATTR_STACKSIZE);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_THREAD_PRIORITY_SCHEDULING);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_THREAD_PRIO_INHERIT);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_THREAD_PRIO_PROTECT);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_THREAD_SAFE_FUNCTIONS);
  VERIFY_SYSCONF_POSITIVE(_SC_NPROCESSORS_CONF);
  VERIFY_SYSCONF_POSITIVE(_SC_NPROCESSORS_ONLN);
  VERIFY_SYSCONF_POSITIVE(_SC_PHYS_PAGES);
  VERIFY_SYSCONF_POSITIVE(_SC_AVPHYS_PAGES);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_MONOTONIC_CLOCK);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_PBS);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_PBS_ACCOUNTING);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_PBS_CHECKPOINT);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_PBS_LOCATE);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_PBS_MESSAGE);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_PBS_TRACK);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_CLOCK_SELECTION);
  VERIFY_SYSCONF_POSITIVE(_SC_HOST_NAME_MAX);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_IPV6);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_RAW_SOCKETS);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_READER_WRITER_LOCKS);
  VERIFY_SYSCONF_POSITIVE(_SC_REGEXP);
  VERIFY_SYSCONF_POSITIVE(_SC_SHELL);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_SPAWN);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_SPORADIC_SERVER);
  VERIFY_SYSCONF_POSITIVE(_SC_SYMLOOP_MAX);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_THREAD_CPUTIME);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_THREAD_PROCESS_SHARED);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_THREAD_SPORADIC_SERVER);
  VERIFY_SYSCONF_POSIX_VERSION(_SC_TIMEOUT
"""


```