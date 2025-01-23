Response:
Here's a breakdown of the thinking process to answer the user's request:

1. **Understand the Core Request:** The user wants a comprehensive analysis of the provided `unistd_test.cpp` file, focusing on its functionality within the Android Bionic environment. The request is broken down into several specific areas, requiring different levels of detail. This is part 2 of a 2-part request, so the goal is to summarize the functionality.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, identifying key functions being tested (`sysconf`, `get_cpu_count_from_string`, `dup2`, `dup3`, `lockf`, `getdomainname`, `setdomainname`, `execve`, `execl`, `execle`, `execv`, `execlp`, `execvp`, `execvpe`, `fexecve`, `getlogin_r`, `swab`, `usleep`, `sleep`, `close_range`, `copy_file_range`). Note the use of `ASSERT_*` and `EXPECT_*` macros, indicating unit tests.

3. **Categorize Functionality:** Group the identified functions into logical categories. This helps structure the answer. Obvious categories include:
    * System Configuration (`sysconf`, related macros)
    * Process Management (`exec*`, `fork`)
    * File Operations (`dup*`, `lockf`, `close_range`, `copy_file_range`)
    * Time (`usleep`, `sleep`)
    * System Information (`getdomainname`, `setdomainname`, `getlogin_r`)
    * Memory Manipulation (`swab`)

4. **Address Specific Request Points (and plan how to handle missing info):**

    * **List Functionality:**  This is straightforward – list the categories identified above.
    * **Relationship to Android:**  Consider how each category or specific function relates to Android. For example, `sysconf` retrieves system limits and configurations, which is relevant for app compatibility. `exec*` functions are fundamental for process creation in Android. Recognize that some tests (like cache info) might be more about validating underlying kernel behavior.
    * **Libc Function Implementation:** The request asks for *detailed* implementation. Realize that providing actual C code for each libc function within the test file is impossible. The *test* verifies the *behavior* of those functions, not the implementation itself. Adjust the answer to focus on the *expected behavior* as demonstrated by the tests. Mention that the actual implementation is within Bionic's libc source code.
    * **Dynamic Linker:** Look for explicit mentions of the dynamic linker. The provided snippet doesn't directly test dynamic linking. Note this absence and explain why it's not covered here (this test focuses on `unistd.h` functionalities).
    * **Logical Reasoning (Assumptions and Outputs):** The tests use `ASSERT` and `EXPECT` with specific inputs and expected outputs. Summarize these test cases as examples of logical reasoning.
    * **Common Usage Errors:** Think about typical mistakes developers make with the tested functions. For example, incorrect use of file descriptors with `dup2`, or lack of permissions with `setdomainname`.
    * **Android Framework/NDK:**  Trace the path from application to the tested functions. A high-level explanation is sufficient, mentioning system calls. The Frida hook request requires showing a basic example targeting one of the tested functions.
    * **Part 2 Summary:** This requires a concise overview of the file's overall purpose.

5. **Draft the Answer Section by Section:**  Start filling in the details for each request point, using the categorized functions as a guide.

    * **Functionality Summary:** List the main areas.
    * **Android Relationship:** Provide specific examples for key functions like `sysconf` and `exec`.
    * **Libc Implementation:** Explain that the *tests* verify behavior, not the internal implementation. Point to the Bionic source as the source of truth.
    * **Dynamic Linker:** State that it's not directly tested here.
    * **Logical Reasoning:** Summarize a few representative test cases (e.g., `get_cpu_count_from_string`, `sysconf_SC_ARG_MAX`).
    * **Common Errors:**  Give practical examples.
    * **Android Framework/NDK & Frida:** Outline the path and provide a simple Frida example (e.g., hooking `open`).
    * **Part 2 Summary:**  Concisely state that the file tests functionalities defined in `unistd.h`.

6. **Refine and Review:** Read through the entire answer, ensuring clarity, accuracy, and completeness. Check that all parts of the user's request have been addressed. Ensure the language is clear and easy to understand. For example, clarify the difference between testing behavior and showing implementation. Ensure smooth transitions between sections.

By following these steps, the detailed and organized answer can be constructed, effectively addressing all aspects of the user's request. The key is to break down the complex request into manageable parts and to adjust the level of detail provided based on the information available within the provided code snippet.
好的，这是对 `bionic/tests/unistd_test.cpp` 文件功能的归纳总结，基于你提供的第二部分代码和之前的第一部分信息：

**功能归纳总结:**

`bionic/tests/unistd_test.cpp` 文件是 Android Bionic 库中用于测试 `unistd.h` 头文件中定义的一系列 POSIX 标准 Unix 系统调用和实用工具函数的单元测试集合。其主要功能可以归纳为以下几点：

1. **验证 `sysconf()` 函数的正确性:**
   - 测试 `sysconf()` 函数对于各种配置选项（例如，处理器数量、最大参数长度、缓存大小等）的返回值是否符合预期。
   - 验证 Bionic 对于某些不支持的 `sysconf()` 选项是否返回 -1 并设置 `errno` 为 `EINVAL`。
   - 针对 Android Bionic 特有的支持情况进行断言，例如对于 64 位 `off_t` 类型的支持。

2. **测试进程管理相关的系统调用:**
   - 验证 `fork()` 函数创建子进程的功能。
   - 测试 `execve()`、`execl()`、`execle()`、`execv()`、`execlp()`、`execvp()`、`execvpe()` 和 `fexecve()` 等 `exec` 系列函数执行新程序的能力，包括参数传递和环境变量设置。
   - 涵盖 `exec` 函数执行失败的情况，并检查预期的错误码。
   - 特别测试了 `execvpe()` 函数处理 shebang 行（`#!`）的情况，以及在没有 shebang 行时的执行机制。

3. **测试文件和 I/O 相关的系统调用:**
   - 验证 `dup2()` 和 `dup3()` 函数复制文件描述符的功能。
   - 测试 `lockf64()` 函数进行文件锁定的功能，包括排他锁、尝试锁和解锁，以及父子进程之间的锁交互。
   - 测试 `close_range()` 函数批量关闭指定范围的文件描述符的功能（如果系统支持）。
   - 测试 `copy_file_range()` 函数在文件之间复制数据的功能（如果系统支持）。

4. **测试系统信息获取相关的函数:**
   - 验证 `getdomainname()` 和 `setdomainname()` 函数获取和设置域名（需要 root 权限）的功能。
   - 测试 `getlogin_r()` 函数获取登录用户名。

5. **测试其他实用工具函数:**
   - 验证 `swab()` 函数交换字节的功能，包括奇数长度和重叠内存区域的情况。
   - 测试 `usleep()` 和 `sleep()` 函数的睡眠功能，验证其休眠时间是否符合预期。

6. **内部辅助函数的测试:**
   - 测试 `GetCpuCountFromString()` 函数解析 CPU 核心数量字符串的功能。

**与 Android 功能的关系举例:**

- **`sysconf(_SC_NPROCESSORS_ONLN)`:**  Android 系统使用这个调用来确定当前可用的 CPU 核心数量，这对于多线程应用的性能至关重要。例如，Android Runtime (ART) 可以根据这个值来调整垃圾回收线程的数量。
- **`execve()`:** 当 Android 系统需要启动一个新的应用程序进程时，例如点击一个应用图标，Zygote 进程会 `fork()` 出一个子进程，然后调用 `execve()` 来加载并执行目标应用的 APK 中的 Dalvik/ART 虚拟机。
- **`lockf64()`:**  Android 的文件系统服务可能使用文件锁来保证数据的一致性，例如在多个进程同时访问同一个文件时。
- **`getdomainname()`:**  虽然 Android 设备通常不加入传统的网络域，但某些网络相关的应用程序或系统服务可能会使用这个调用。

**Libc 函数功能实现（总结，不包含具体代码）:**

由于这是一个测试文件，它不包含 libc 函数的实际实现。它通过调用这些函数并断言其返回值和副作用来验证其行为是否符合预期。  Libc 函数的实际实现位于 Bionic 的其他源文件中（例如 `bionic/libc/bionic/` 和 `bionic/libc/kernel/` 等目录）。

**Dynamic Linker 功能 (未直接涉及):**

这个测试文件主要关注 `unistd.h` 中定义的函数，并没有直接涉及动态链接器的功能。动态链接器的测试通常位于 Bionic 的 `linker_test` 目录中。因此，无法提供此文件的动态链接器相关信息。

**逻辑推理（假设输入与输出）：**

在测试中，逻辑推理体现在每个 `ASSERT_*` 和 `EXPECT_*` 语句中。例如：

- **假设输入:**  调用 `GetCpuCountFromString("0-39")`
- **预期输出:** 返回 `40`

- **假设输入:**  调用 `sysconf(_SC_ARG_MAX)`，且当前进程的 `RLIMIT_STACK` 为 8MB。
- **预期输出:** 返回 8MB / 4 = 2MB (或转换为字节的数值)。

**用户或编程常见的使用错误举例:**

- **`dup2()`:**  不小心将重要的文件描述符复制到另一个已经打开的文件描述符上，导致原始文件描述符被意外关闭。
  ```c++
  int fd1 = open("file1.txt", O_RDWR);
  int fd2 = open("file2.txt", O_RDWR);
  // 错误：如果 fd2 已经在使用，它的内容会被关闭，并指向 fd1 的文件。
  dup2(fd1, fd2);
  ```
- **`lockf64()`:**  忘记在操作完成后释放文件锁，可能导致其他进程无法访问该文件，造成死锁或性能问题。
  ```c++
  int fd = open("data.txt", O_RDWR);
  lockf64(fd, F_LOCK, 0);
  // ... 进行文件操作 ...
  // 忘记调用 lockf64(fd, F_ULOCK, 0);
  close(fd); // 文件锁会在文件描述符关闭时释放，但最好显式释放。
  ```
- **`execve()`:**  提供的参数列表 `argv` 或环境变量列表 `envp` 未以 `NULL` 结尾，可能导致程序崩溃或行为异常。
  ```c++
  char *args[] = {"ls", "-l"}; // 缺少 NULL 结尾
  execve("/bin/ls", args, environ);
  ```

**Android Framework/NDK 到达这里的步骤和 Frida Hook 示例:**

1. **Android Framework/NDK 发起系统调用:**
   - 应用程序通过 Android Framework 的 API（例如 `java.io.File` 操作，`ProcessBuilder` 启动新进程）或 NDK 提供的 C/C++ 接口来间接或直接地调用底层的系统调用。
   - 例如，Java 中的 `FileOutputStream` 最终会调用 `open()` 系统调用，`ProcessBuilder.start()` 会调用 `fork()` 和 `execve()` 等。

2. **系统调用陷入内核:**
   - 当应用程序调用 libc 函数（例如 `open()`, `execve()`) 时，libc 会将这些调用转换为相应的系统调用指令，触发 CPU 的异常，进入内核态。

3. **内核处理系统调用:**
   - Linux 内核接收到系统调用请求后，会根据系统调用号找到对应的内核函数进行处理。

4. **Bionic Libc 提供系统调用封装:**
   - Bionic 的 libc 提供了对这些系统调用的封装函数，例如 `open()`、`execve()` 等，这些函数负责参数传递、错误处理等。`bionic/tests/unistd_test.cpp` 就是用来测试这些封装函数的行为。

**Frida Hook 示例 (以 `open()` 系统调用为例):**

```javascript
// Frida 脚本 hook open 系统调用

Interceptor.attach(Module.findExportByName("libc.so", "open"), {
  onEnter: function(args) {
    // 打印 open 的路径参数
    console.log("Opening file:", Memory.readUtf8String(args[0]));
    // 可以修改参数，例如阻止打开特定文件
    // if (Memory.readUtf8String(args[0]).indexOf("sensitive_data") !== -1) {
    //   args[1] = 0; // 修改为只读
    // }
  },
  onLeave: function(retval) {
    // 打印 open 的返回值 (文件描述符)
    console.log("File descriptor:", retval);
  }
});
```

这个 Frida 脚本会拦截对 `libc.so` 中 `open` 函数的调用，并在函数执行前后打印相关信息。你可以通过类似的方式 hook `execve`、`lockf` 等你在测试文件中看到的函数，以观察其调用情况和参数。

**总结 `bionic/tests/unistd_test.cpp` 的功能 (Part 2 的角度):**

延续第一部分的总结，第二部分的代码主要集中在以下 `unistd.h` 函数的测试：

- **文件操作:** `dup2`, `dup3`, `lockf64`, `close_range`, `copy_file_range`
- **进程管理:** `execve`, `execl`, `execle`, `execv`, `execlp`, `execvp`, `execvpe`, `fexecve`
- **系统信息:** `getdomainname`, `setdomainname`
- **其他工具:** `swab`, `usleep`, `sleep`

总而言之，`bionic/tests/unistd_test.cpp` 是一个关键的测试文件，用于确保 Android Bionic 库提供的 Unix 标准系统调用和实用工具函数能够正确地工作，这对于保证 Android 系统的稳定性和应用程序的兼容性至关重要。

### 提示词
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
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
S);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TRACE);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TRACE_EVENT_FILTER);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TRACE_EVENT_NAME_MAX);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TRACE_INHERIT);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TRACE_LOG);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TRACE_NAME_MAX);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TRACE_SYS_MAX);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TRACE_USER_EVENT_MAX);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_TYPED_MEMORY_OBJECTS);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_XOPEN_STREAMS);

#if defined(__LP64__)
  VERIFY_SYSCONF_UNSUPPORTED(_SC_V7_ILP32_OFF32);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_V7_ILP32_OFFBIG);
  VERIFY_SYSCONF_POSITIVE(_SC_V7_LP64_OFF64);
  VERIFY_SYSCONF_POSITIVE(_SC_V7_LPBIG_OFFBIG);
#else
  VERIFY_SYSCONF_POSITIVE(_SC_V7_ILP32_OFF32);
#if defined(__BIONIC__)
  // bionic does not support 64 bits off_t type on 32bit machine.
  VERIFY_SYSCONF_UNSUPPORTED(_SC_V7_ILP32_OFFBIG);
#endif
  VERIFY_SYSCONF_UNSUPPORTED(_SC_V7_LP64_OFF64);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_V7_LPBIG_OFFBIG);
#endif

#if defined(__BIONIC__)
  // Tests can only run on bionic, as bionic and glibc have different support for these options.
  // Below options are not supported on bionic yet.
  VERIFY_SYSCONF_UNSUPPORTED(_SC_ASYNCHRONOUS_IO);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_MESSAGE_PASSING);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_PRIORITIZED_IO);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_SHARED_MEMORY_OBJECTS);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_THREAD_ROBUST_PRIO_INHERIT);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_THREAD_ROBUST_PRIO_PROTECT);

  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_C_DEV);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_LOCALEDEF);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_2_SW_DEV);

  VERIFY_SYSCONF_UNSUPPORTED(_SC_XOPEN_CRYPT);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_XOPEN_LEGACY);
  VERIFY_SYSCONF_UNSUPPORTED(_SC_XOPEN_UUCP);
#endif // defined(__BIONIC__)
}

TEST(UNISTD_TEST, get_cpu_count_from_string) {
  ASSERT_EQ(0, GetCpuCountFromString(" "));
  ASSERT_EQ(1, GetCpuCountFromString("0"));
  ASSERT_EQ(40, GetCpuCountFromString("0-39"));
  ASSERT_EQ(4, GetCpuCountFromString("0, 1-2, 4\n"));
}

TEST(UNISTD_TEST, sysconf_SC_NPROCESSORS_make_sense) {
  ASSERT_LE(sysconf(_SC_NPROCESSORS_ONLN), sysconf(_SC_NPROCESSORS_CONF));
}

TEST(UNISTD_TEST, sysconf_SC_NPROCESSORS_ONLN) {
  std::string line;
  ASSERT_TRUE(android::base::ReadFileToString("/sys/devices/system/cpu/online", &line));
  long online_cpus = 0;
  for (const std::string& s : android::base::Split(line, ",")) {
    std::vector<std::string> numbers = android::base::Split(s, "-");
    if (numbers.size() == 1u) {
      online_cpus++;
    } else {
      online_cpus += atoi(numbers[1].c_str()) - atoi(numbers[0].c_str()) + 1;
    }
  }
  ASSERT_EQ(online_cpus, sysconf(_SC_NPROCESSORS_ONLN));
}

TEST(UNISTD_TEST, sysconf_SC_ARG_MAX) {
  // Since Linux 2.6.23, ARG_MAX isn't a constant and depends on RLIMIT_STACK.
  // See setup_arg_pages() in the kernel for the gory details:
  // https://elixir.bootlin.com/linux/v6.6.4/source/fs/exec.c#L749

  // Get our current limit, and set things up so we restore the limit.
  rlimit rl;
  ASSERT_EQ(0, getrlimit(RLIMIT_STACK, &rl));
  uint64_t original_rlim_cur = rl.rlim_cur;
  if (rl.rlim_cur == RLIM_INFINITY) {
    rl.rlim_cur = 8 * 1024 * 1024; // Bionic reports unlimited stacks as 8MiB.
  }
  auto guard = android::base::make_scope_guard([&rl, original_rlim_cur]() {
    rl.rlim_cur = original_rlim_cur;
    ASSERT_EQ(0, setrlimit(RLIMIT_STACK, &rl));
  });

  // _SC_ARG_MAX should be 1/4 the stack size.
  EXPECT_EQ(static_cast<long>(rl.rlim_cur / 4), sysconf(_SC_ARG_MAX));

  // If you have a really small stack, the kernel still guarantees a stack
  // expansion of 128KiB (see setup_arg_pages() in fs/exec.c).
  rl.rlim_cur = 1024;
  rl.rlim_max = RLIM_INFINITY;
  ASSERT_EQ(0, setrlimit(RLIMIT_STACK, &rl));

  // The stack expansion number is defined in fs/exec.c.
  // https://elixir.bootlin.com/linux/v6.6.4/source/fs/exec.c#L845
  constexpr long kernel_stack_expansion = 131072;
  EXPECT_EQ(kernel_stack_expansion, sysconf(_SC_ARG_MAX));

  // If you have a large stack, the kernel will keep the stack
  // expansion to 128KiB (see setup_arg_pages() in fs/exec.c).
  rl.rlim_cur = 524288;
  rl.rlim_max = RLIM_INFINITY;
  ASSERT_EQ(0, setrlimit(RLIMIT_STACK, &rl));

  EXPECT_EQ(kernel_stack_expansion, sysconf(_SC_ARG_MAX));
}

TEST(UNISTD_TEST, sysconf_unknown) {
  VERIFY_SYSCONF_UNKNOWN(-1);
  VERIFY_SYSCONF_UNKNOWN(666);
}

[[maybe_unused]] static void show_cache(const char* name, long size, long assoc, long line_size) {
  printf("%s cache size: %ld bytes, line size %ld bytes, ", name, size, line_size);
  if (assoc == 0) {
    printf("fully");
  } else {
    printf("%ld-way", assoc);
  }
  printf(" associative\n");
}

TEST(UNISTD_TEST, sysconf_cache) {
#if defined(ANDROID_HOST_MUSL)
  GTEST_SKIP() << "musl does not have _SC_LEVEL?_?CACHE_SIZE";
#else
  // It's not obvious we can _test_ any of these, but we can at least
  // show the output for humans to inspect.
  show_cache("L1D", sysconf(_SC_LEVEL1_DCACHE_SIZE), sysconf(_SC_LEVEL1_DCACHE_ASSOC), sysconf(_SC_LEVEL1_DCACHE_LINESIZE));
  show_cache("L1I", sysconf(_SC_LEVEL1_ICACHE_SIZE), sysconf(_SC_LEVEL1_ICACHE_ASSOC), sysconf(_SC_LEVEL1_ICACHE_LINESIZE));
  show_cache("L2", sysconf(_SC_LEVEL2_CACHE_SIZE), sysconf(_SC_LEVEL2_CACHE_ASSOC), sysconf(_SC_LEVEL2_CACHE_LINESIZE));
  show_cache("L3", sysconf(_SC_LEVEL3_CACHE_SIZE), sysconf(_SC_LEVEL3_CACHE_ASSOC), sysconf(_SC_LEVEL3_CACHE_LINESIZE));
  show_cache("L4", sysconf(_SC_LEVEL4_CACHE_SIZE), sysconf(_SC_LEVEL4_CACHE_ASSOC), sysconf(_SC_LEVEL4_CACHE_LINESIZE));
#endif
}

TEST(UNISTD_TEST, dup2_same) {
  // POSIX says of dup2:
  // If fildes2 is already a valid open file descriptor ...
  // [and] fildes is equal to fildes2 ... dup2() shall return
  // fildes2 without closing it.
  // This isn't true of dup3(2), so we need to manually implement that.

  // Equal and valid.
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);
  ASSERT_EQ(fd, dup2(fd, fd));
  ASSERT_EQ(0, close(fd)); // Check that dup2 didn't close fd.

  // Equal, but invalid.
  errno = 0;
  ASSERT_EQ(-1, dup2(fd, fd));
  ASSERT_ERRNO(EBADF);
}

TEST(UNISTD_TEST, dup3) {
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_EQ(666, dup3(fd, 666, 0));
  ASSERT_FALSE(CloseOnExec(666));
  close(666);
  ASSERT_EQ(667, dup3(fd, 667, O_CLOEXEC));
  ASSERT_TRUE(CloseOnExec(667));
  close(667);
  close(fd);
}

TEST(UNISTD_TEST, lockf_smoke) {
  constexpr off64_t file_size = 32*1024LL;

  TemporaryFile tf;
  ASSERT_EQ(0, ftruncate(tf.fd, file_size));

  // Lock everything.
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_LOCK, file_size));

  // Try-lock everything, this should succeed too.
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_TLOCK, file_size));

  // Check status.
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_TEST, file_size));

  // Unlock file.
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_ULOCK, file_size));
}

TEST(UNISTD_TEST, lockf_zero) {
  constexpr off64_t file_size = 32*1024LL;

  TemporaryFile tf;
  ASSERT_EQ(0, ftruncate(tf.fd, file_size));

  // Lock everything by specifying a size of 0 (meaning "to the end, even if it changes").
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_LOCK, 0));

  // Check that it's locked.
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_TEST, file_size));

  // Move the end.
  ASSERT_EQ(0, ftruncate(tf.fd, 2*file_size));

  // Check that the new section is locked too.
  ASSERT_EQ(file_size, lseek64(tf.fd, file_size, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_TEST, 2*file_size));
}

TEST(UNISTD_TEST, lockf_negative) {
  constexpr off64_t file_size = 32*1024LL;

  TemporaryFile tf;
  ASSERT_EQ(0, ftruncate(tf.fd, file_size));

  // Lock everything, but specifying the range in reverse.
  ASSERT_EQ(file_size, lseek64(tf.fd, file_size, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_LOCK, -file_size));

  // Check that it's locked.
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_TEST, file_size));
}

TEST(UNISTD_TEST, lockf_with_child) {
  constexpr off64_t file_size = 32*1024LL;

  TemporaryFile tf;
  ASSERT_EQ(0, ftruncate(tf.fd, file_size));

  // Lock everything.
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_LOCK, file_size));

  // Fork a child process
  pid_t pid = fork();
  ASSERT_NE(-1, pid);
  if (pid == 0) {
    // Check that the child cannot lock the file.
    ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
    ASSERT_EQ(-1, lockf64(tf.fd, F_TLOCK, file_size));
    ASSERT_ERRNO(EAGAIN);
    // Check also that it reports itself as locked.
    ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
    ASSERT_EQ(-1, lockf64(tf.fd, F_TEST, file_size));
    ASSERT_ERRNO(EACCES);
    _exit(0);
  }
  AssertChildExited(pid, 0);
}

TEST(UNISTD_TEST, lockf_partial_with_child) {
  constexpr off64_t file_size = 32*1024LL;

  TemporaryFile tf;
  ASSERT_EQ(0, ftruncate(tf.fd, file_size));

  // Lock the first half of the file.
  ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_LOCK, file_size/2));

  // Fork a child process.
  pid_t pid = fork();
  ASSERT_NE(-1, pid);
  if (pid == 0) {
    // Check that the child can lock the other half.
    ASSERT_EQ(file_size/2, lseek64(tf.fd, file_size/2, SEEK_SET));
    ASSERT_EQ(0, lockf64(tf.fd, F_TLOCK, file_size/2));
    // Check that the child cannot lock the first half.
    ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
    ASSERT_EQ(-1, lockf64(tf.fd, F_TEST, file_size/2));
    ASSERT_ERRNO(EACCES);
    // Check also that it reports itself as locked.
    ASSERT_EQ(0, lseek64(tf.fd, 0, SEEK_SET));
    ASSERT_EQ(-1, lockf64(tf.fd, F_TEST, file_size/2));
    ASSERT_ERRNO(EACCES);
    _exit(0);
  }
  AssertChildExited(pid, 0);

  // The second half was locked by the child, but the lock disappeared
  // when the process exited, so check it can be locked now.
  ASSERT_EQ(file_size/2, lseek64(tf.fd, file_size/2, SEEK_SET));
  ASSERT_EQ(0, lockf64(tf.fd, F_TLOCK, file_size/2));
}

TEST(UNISTD_TEST, getdomainname) {
  struct utsname u;
  ASSERT_EQ(0, uname(&u));

  char buf[sizeof(u.domainname)];
  ASSERT_EQ(0, getdomainname(buf, sizeof(buf)));
  EXPECT_STREQ(u.domainname, buf);

#if defined(__BIONIC__)
  // bionic and glibc have different behaviors when len is too small
  ASSERT_EQ(-1, getdomainname(buf, strlen(u.domainname)));
  EXPECT_ERRNO(EINVAL);
#endif
}

TEST(UNISTD_TEST, setdomainname) {
  __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};

  __user_cap_data_struct old_caps[_LINUX_CAPABILITY_U32S_3];
  ASSERT_EQ(0, capget(&header, &old_caps[0]));

  auto admin_idx = CAP_TO_INDEX(CAP_SYS_ADMIN);
  auto admin_mask = CAP_TO_MASK(CAP_SYS_ADMIN);
  bool has_admin = old_caps[admin_idx].effective & admin_mask;
  if (has_admin) {
    __user_cap_data_struct new_caps[_LINUX_CAPABILITY_U32S_3];
    memcpy(new_caps, old_caps, sizeof(new_caps));
    new_caps[admin_idx].effective &= ~admin_mask;

    ASSERT_EQ(0, capset(&header, &new_caps[0])) << "failed to drop admin privileges";
  }

  const char* name = "newdomainname";
  ASSERT_EQ(-1, setdomainname(name, strlen(name)));
  ASSERT_ERRNO(EPERM);

  if (has_admin) {
    ASSERT_EQ(0, capset(&header, &old_caps[0])) << "failed to restore admin privileges";
  }
}

TEST(UNISTD_TEST, execve_failure) {
  ExecTestHelper eth;
  errno = 0;
  ASSERT_EQ(-1, execve("/", eth.GetArgs(), eth.GetEnv()));
  ASSERT_ERRNO(EACCES);
}

static void append_llvm_cov_env_var(std::string& env_str) {
  if (getenv("LLVM_PROFILE_FILE") != nullptr)
    env_str.append("__LLVM_PROFILE_RT_INIT_ONCE=__LLVM_PROFILE_RT_INIT_ONCE\n");
}

TEST(UNISTD_TEST, execve_args) {
  // int execve(const char* path, char* argv[], char* envp[]);

  // Test basic argument passing.
  ExecTestHelper eth;
  eth.SetArgs({"echo", "hello", "world", nullptr});
  eth.Run([&]() { execve(BIN_DIR "echo", eth.GetArgs(), eth.GetEnv()); }, 0, "hello world\n");

  // Test environment variable setting too.
  eth.SetArgs({"printenv", nullptr});
  eth.SetEnv({"A=B", nullptr});

  std::string expected_output("A=B\n");
  append_llvm_cov_env_var(expected_output);

  eth.Run([&]() { execve(BIN_DIR "printenv", eth.GetArgs(), eth.GetEnv()); }, 0,
          expected_output.c_str());
}

TEST(UNISTD_TEST, execl_failure) {
  errno = 0;
  ASSERT_EQ(-1, execl("/", "/", nullptr));
  ASSERT_ERRNO(EACCES);
}

TEST(UNISTD_TEST, execl) {
  ExecTestHelper eth;
  // int execl(const char* path, const char* arg, ...);
  eth.Run([&]() { execl(BIN_DIR "echo", "echo", "hello", "world", nullptr); }, 0, "hello world\n");
}

TEST(UNISTD_TEST, execle_failure) {
  ExecTestHelper eth;
  errno = 0;
  ASSERT_EQ(-1, execle("/", "/", nullptr, eth.GetEnv()));
  ASSERT_ERRNO(EACCES);
}

TEST(UNISTD_TEST, execle) {
  ExecTestHelper eth;
  eth.SetEnv({"A=B", nullptr});

  std::string expected_output("A=B\n");
  append_llvm_cov_env_var(expected_output);

  // int execle(const char* path, const char* arg, ..., char* envp[]);
  eth.Run([&]() { execle(BIN_DIR "printenv", "printenv", nullptr, eth.GetEnv()); }, 0,
          expected_output.c_str());
}

TEST(UNISTD_TEST, execv_failure) {
  ExecTestHelper eth;
  errno = 0;
  ASSERT_EQ(-1, execv("/", eth.GetArgs()));
  ASSERT_ERRNO(EACCES);
}

TEST(UNISTD_TEST, execv) {
  ExecTestHelper eth;
  eth.SetArgs({"echo", "hello", "world", nullptr});
  // int execv(const char* path, char* argv[]);
  eth.Run([&]() { execv(BIN_DIR "echo", eth.GetArgs()); }, 0, "hello world\n");
}

TEST(UNISTD_TEST, execlp_failure) {
  errno = 0;
  ASSERT_EQ(-1, execlp("/", "/", nullptr));
  ASSERT_ERRNO(EACCES);
}

TEST(UNISTD_TEST, execlp) {
  ExecTestHelper eth;
  // int execlp(const char* file, const char* arg, ...);
  eth.Run([&]() { execlp("echo", "echo", "hello", "world", nullptr); }, 0, "hello world\n");
}

TEST(UNISTD_TEST, execvp_failure) {
  ExecTestHelper eth;
  eth.SetArgs({nullptr});
  errno = 0;
  ASSERT_EQ(-1, execvp("/", eth.GetArgs()));
  ASSERT_ERRNO(EACCES);
}

TEST(UNISTD_TEST, execvp) {
  ExecTestHelper eth;
  eth.SetArgs({"echo", "hello", "world", nullptr});
  // int execvp(const char* file, char* argv[]);
  eth.Run([&]() { execvp("echo", eth.GetArgs()); }, 0, "hello world\n");
}

TEST(UNISTD_TEST, execvpe_failure) {
  ExecTestHelper eth;
  errno = 0;
  ASSERT_EQ(-1, execvpe("this-does-not-exist", eth.GetArgs(), eth.GetEnv()));
  // Running in CTS we might not even be able to search all directories in $PATH.
  ASSERT_TRUE(errno == ENOENT || errno == EACCES) << strerror(errno);
}

TEST(UNISTD_TEST, execvpe) {
  // int execvpe(const char* file, char* argv[], char* envp[]);

  // Test basic argument passing.
  ExecTestHelper eth;
  eth.SetArgs({"echo", "hello", "world", nullptr});
  eth.Run([&]() { execvpe("echo", eth.GetArgs(), eth.GetEnv()); }, 0, "hello world\n");

  // Test environment variable setting too.
  eth.SetArgs({"printenv", nullptr});
  eth.SetEnv({"A=B", nullptr});

  std::string expected_output("A=B\n");
  append_llvm_cov_env_var(expected_output);

  eth.Run([&]() { execvpe("printenv", eth.GetArgs(), eth.GetEnv()); }, 0, expected_output.c_str());
}

TEST(UNISTD_TEST, execvpe_ENOEXEC) {
  // Create a shell script with #!.
  TemporaryFile tf;
  ASSERT_TRUE(android::base::WriteStringToFile("#!" BIN_DIR "sh\necho script\n", tf.path));

  // Set $PATH so we can find it.
  setenv("PATH", dirname(tf.path), 1);

  ExecTestHelper eth;
  eth.SetArgs({basename(tf.path), nullptr});

  // It's not inherently executable.
  errno = 0;
  ASSERT_EQ(-1, execvpe(basename(tf.path), eth.GetArgs(), eth.GetEnv()));
  ASSERT_ERRNO(EACCES);

  // Make it executable (and keep it writable because we're going to rewrite it below).
  ASSERT_EQ(0, chmod(tf.path, 0777));

  // TemporaryFile will have a writable fd, so we can test ETXTBSY while we're here...
  errno = 0;
  ASSERT_EQ(-1, execvpe(basename(tf.path), eth.GetArgs(), eth.GetEnv()));
  ASSERT_ERRNO(ETXTBSY);

  // 1. The simplest test: the kernel should handle this.
  ASSERT_EQ(0, close(tf.fd));
  eth.Run([&]() { execvpe(basename(tf.path), eth.GetArgs(), eth.GetEnv()); }, 0, "script\n");

  // 2. Try again without a #!. We should have to handle this ourselves.
  ASSERT_TRUE(android::base::WriteStringToFile("echo script\n", tf.path));
  eth.Run([&]() { execvpe(basename(tf.path), eth.GetArgs(), eth.GetEnv()); }, 0, "script\n");

  // 3. Again without a #!, but also with a leading '/', since that's a special case in the
  // implementation.
  eth.Run([&]() { execvpe(tf.path, eth.GetArgs(), eth.GetEnv()); }, 0, "script\n");
}

TEST(UNISTD_TEST, execvp_libcore_test_55017) {
  ExecTestHelper eth;
  eth.SetArgs({"/system/bin/does-not-exist", nullptr});

  errno = 0;
  ASSERT_EQ(-1, execvp("/system/bin/does-not-exist", eth.GetArgs()));
  ASSERT_ERRNO(ENOENT);
}

TEST(UNISTD_TEST, exec_argv0_null) {
  // http://b/33276926 and http://b/227498625.
  //
  // With old kernels, bionic will see the null pointer and use "<unknown>" but
  // with new (5.18+) kernels, the kernel will already have substituted the
  // empty string, so we don't make any assertion here about what (if anything)
  // comes before the first ':'.
  //
  // If this ever causes trouble, we could change bionic to replace _either_ the
  // null pointer or the empty string. We could also use the actual name from
  // readlink() on /proc/self/exe if we ever had reason to disallow programs
  // from trying to hide like this.
  char* args[] = {nullptr};
  char* envs[] = {nullptr};
  ASSERT_EXIT(execve("/system/bin/run-as", args, envs), testing::ExitedWithCode(1),
              ": usage: run-as");
}

TEST(UNISTD_TEST, fexecve_failure) {
  ExecTestHelper eth;
  errno = 0;
  int fd = open("/", O_RDONLY);
  ASSERT_NE(-1, fd);
  ASSERT_EQ(-1, fexecve(fd, eth.GetArgs(), eth.GetEnv()));
  ASSERT_ERRNO(EACCES);
  close(fd);
}

TEST(UNISTD_TEST, fexecve_bad_fd) {
  ExecTestHelper eth;
  errno = 0;
  ASSERT_EQ(-1, fexecve(-1, eth.GetArgs(), eth.GetEnv()));
  ASSERT_ERRNO(EBADF);
}

TEST(UNISTD_TEST, fexecve_args) {
  // Test basic argument passing.
  int echo_fd = open(BIN_DIR "echo", O_RDONLY | O_CLOEXEC);
  ASSERT_NE(-1, echo_fd);
  ExecTestHelper eth;
  eth.SetArgs({"echo", "hello", "world", nullptr});
  eth.Run([&]() { fexecve(echo_fd, eth.GetArgs(), eth.GetEnv()); }, 0, "hello world\n");
  close(echo_fd);

  // Test environment variable setting too.
  int printenv_fd = open(BIN_DIR "printenv", O_RDONLY | O_CLOEXEC);
  ASSERT_NE(-1, printenv_fd);
  eth.SetArgs({"printenv", nullptr});
  eth.SetEnv({"A=B", nullptr});

  std::string expected_output("A=B\n");
  append_llvm_cov_env_var(expected_output);

  eth.Run([&]() { fexecve(printenv_fd, eth.GetArgs(), eth.GetEnv()); }, 0, expected_output.c_str());
  close(printenv_fd);
}

TEST(UNISTD_TEST, getlogin_r) {
  char buf[LOGIN_NAME_MAX] = {};
  EXPECT_EQ(ERANGE, getlogin_r(buf, 0));
  EXPECT_EQ(0, getlogin_r(buf, sizeof(buf)));
  EXPECT_STREQ(getlogin(), buf);
}

TEST(UNISTD_TEST, swab) {
  // POSIX: "The swab() function shall copy nbytes bytes, which are pointed to by src,
  // to the object pointed to by dest, exchanging adjacent bytes."
  char buf[BUFSIZ];
  memset(buf, 'x', sizeof(buf));
  swab("ehll oowlr\0d", buf, 12);
  ASSERT_STREQ("hello world", buf);
}

TEST(UNISTD_TEST, swab_odd_byte_count) {
  // POSIX: "If nbytes is odd, swab() copies and exchanges nbytes-1 bytes and the disposition
  // of the last byte is unspecified."
  // ...but it seems unreasonable to not just leave the last byte alone.
  char buf[BUFSIZ];
  memset(buf, 'x', sizeof(buf));
  swab("012345", buf, 3);
  ASSERT_EQ('1', buf[0]);
  ASSERT_EQ('0', buf[1]);
  ASSERT_EQ('x', buf[2]);
}

TEST(UNISTD_TEST, swab_overlap) {
  // POSIX: "If copying takes place between objects that overlap, the behavior is undefined."
  // ...but it seems unreasonable to not just do the right thing.
  char buf[] = "012345";
  swab(buf, buf, 4);
  ASSERT_EQ('1', buf[0]);
  ASSERT_EQ('0', buf[1]);
  ASSERT_EQ('3', buf[2]);
  ASSERT_EQ('2', buf[3]);
  ASSERT_EQ('4', buf[4]);
  ASSERT_EQ('5', buf[5]);
  ASSERT_EQ(0, buf[6]);
}

TEST(UNISTD_TEST, swab_negative_byte_count) {
  // POSIX: "If nbytes is negative, swab() does nothing."
  char buf[BUFSIZ];
  memset(buf, 'x', sizeof(buf));
  swab("hello", buf, -1);
  ASSERT_EQ('x', buf[0]);
}

TEST(UNISTD_TEST, usleep) {
  auto t0 = std::chrono::steady_clock::now();
  ASSERT_EQ(0, usleep(5000));
  auto t1 = std::chrono::steady_clock::now();
  ASSERT_GE(t1-t0, 5000us);
}

TEST(UNISTD_TEST, sleep) {
  auto t0 = std::chrono::steady_clock::now();
  ASSERT_EQ(0U, sleep(1));
  auto t1 = std::chrono::steady_clock::now();
  ASSERT_GE(t1-t0, 1s);
}

TEST(UNISTD_TEST, close_range) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "glibc too old";
#elif defined(ANDROID_HOST_MUSL)
  GTEST_SKIP() << "musl does not have close_range";
#else   // __GLIBC__
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_GE(fd, 0);

  int rc = close_range(fd, fd, 0);
  if (rc == -1 && errno == ENOSYS) GTEST_SKIP() << "no close_range() in this kernel";
  ASSERT_EQ(0, rc) << strerror(errno);

  // Check the fd is actually closed.
  ASSERT_EQ(close(fd), -1);
  ASSERT_ERRNO(EBADF);
#endif  // __GLIBC__
}

TEST(UNISTD_TEST, copy_file_range) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "glibc too old";
#else   // __GLIBC__
  TemporaryFile tf;
  ASSERT_TRUE(android::base::WriteStringToFd("hello world", tf.fd));
  ASSERT_EQ(0, lseek(tf.fd, SEEK_SET, 0));
  TemporaryFile tf2;
  ASSERT_EQ(11, copy_file_range(tf.fd, NULL, tf2.fd, NULL, 11, 0));
  ASSERT_EQ(0, lseek(tf2.fd, SEEK_SET, 0));
  std::string content;
  ASSERT_TRUE(android::base::ReadFdToString(tf2.fd, &content));
  ASSERT_EQ("hello world", content);
#endif  // __GLIBC__
}
```