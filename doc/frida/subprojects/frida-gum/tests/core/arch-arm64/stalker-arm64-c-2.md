Response:
The user wants to understand the functionality of the provided C code, which is part of the Frida dynamic instrumentation tool. I need to analyze the code and explain:
1. **Functionality**: What does this code do?
2. **Relationship to Reverse Engineering**: How can this be used in reverse engineering?
3. **Low-level Details**: Does it interact with the binary level, Linux, or Android kernels/frameworks?
4. **Logical Reasoning**:  Can I infer input and output based on the logic?
5. **Common User Errors**: What mistakes could a user make when using this?
6. **User Journey**: How does a user end up interacting with this code?
7. **Summary**: A concise overview of the functionality.

Let's break down the code section by section:

- **`lapsed` function test**: Measures the execution time of a direct function call versus execution under Frida's Stalker. This is a performance test for the Stalker.
- **`store_range_of_test_runner`**:  A helper function to find the memory range of the test runner module. This is likely used to target specific code regions for instrumentation.
- **`pretend_workload`**: Simulates a workload by compressing data using LZMA. This helps in testing the Stalker under realistic conditions.
- **`prefetch` test case**: This is the core of the section. It tests the Stalker's prefetch functionality.
    - It runs a child process twice.
    - In the first run, it records which code blocks are compiled and executed by the Stalker.
    - It then uses `gum_stalker_prefetch` to hint the Stalker about these blocks.
    - In the second run, it checks if the prefetching mechanism worked by verifying that no new blocks were compiled. This is a key optimization in dynamic instrumentation.
- **`prefetch_on_event`**:  A callback function used with the Stalker to record compiled and executed code blocks.
- **`prefetch_run_child`**:  Forks a child process to run the `pretend_workload` under Stalker's instrumentation. It uses pipes to communicate the compiled and executed blocks back to the parent.
- **`prefetch_activation_target`**: An empty function used as a target for activating the Stalker. This prevents the compiler from optimizing away the activation.
- **`prefetch_write_blocks` and `prefetch_read_blocks`**: Helper functions to write and read block addresses through pipes for inter-process communication.
- **`observer` test case**: Demonstrates the use of a Stalker observer. Observers can be used to monitor the Stalker's behavior without directly modifying the target code.
- **`gum_test_stalker_observer_*` functions**: Implementation of a simple Stalker observer that counts the number of times `increment_total` is called.
- **`run_on_thread_current` and `run_on_thread_current_sync`**: Test cases for running a function in the current thread using the Stalker. The `_sync` version waits for the function to complete.
- **`run_on_thread`**: A simple function executed by the Stalker in a specific thread.
- **`run_on_thread_other` and `run_on_thread_other_sync`**: Test cases for running a function in a different thread.
- **`create_sleeping_dummy_thread_sync` and `sleeping_dummy`**: Helper functions to create and manage a separate sleeping thread for testing cross-thread execution.

Now, let's address each of the user's points:
这是frida动态 instrumentation tool源代码文件的一部分，主要功能是测试 `frida-gum` 库中 Stalker (跟踪器) 的功能，特别是关于代码块预取 (prefetch) 和在指定线程上运行代码 (run on thread) 的能力。

**功能列举:**

1. **测试 Stalker 的性能开销:**  `lapsed` 测试用例比较了直接调用函数和通过 Stalker 跟踪执行的性能差异，通过测量时间来评估 Stalker 的性能影响。
2. **获取测试 runner 的内存范围:** `store_range_of_test_runner` 函数用于枚举当前进程的模块，并找到包含 "gum-tests" 的模块，从而获取测试代码的内存范围。这为后续的 Stalker 操作提供了目标区域。
3. **模拟工作负载:** `pretend_workload` 函数使用 LZMA 压缩算法对指定内存范围的数据进行压缩，模拟实际程序执行时的代码行为，用于测试 Stalker 在实际场景下的表现。
4. **测试 Stalker 的预取功能:** `prefetch` 测试用例是核心功能之一，它验证了 Stalker 的预取能力。
    - 它首先运行被跟踪的程序，并记录 Stalker 编译和执行的代码块。
    - 然后，它使用 `gum_stalker_prefetch` 函数告知 Stalker 预先加载这些代码块。
    - 再次运行被跟踪的程序，并验证 Stalker 是否没有重新编译已经预取的代码块，从而证明预取功能的有效性。
5. **使用 Stalker 观察者 (Observer):** `observer` 测试用例展示了如何使用 Stalker 观察者来监控 Stalker 的行为。观察者可以接收 Stalker 的事件通知，而无需直接修改目标代码。
6. **测试在当前线程上运行代码:** `run_on_thread_current` 和 `run_on_thread_current_sync` 测试用例验证了 Stalker 可以在当前线程上执行指定的函数。`run_on_thread_current_sync` 是同步执行，会等待函数执行完成。
7. **测试在其他线程上运行代码:** `run_on_thread_other` 和 `run_on_thread_other_sync` 测试用例验证了 Stalker 可以在指定的其他线程上执行函数。这对于在多线程程序中进行特定线程的监控和操作非常有用。
8. **创建和管理测试线程:**  `create_sleeping_dummy_thread_sync` 和 `sleeping_dummy` 函数用于创建和管理一个休眠的线程，用于测试在其他线程上运行代码的功能。

**与逆向方法的关系及举例说明:**

* **动态代码跟踪和分析:** Stalker 是 Frida 的核心组件，用于动态地跟踪程序执行流程。逆向工程师可以使用 Stalker 来观察目标程序在运行时的行为，例如函数调用顺序、代码执行路径、关键变量的变化等。
    * **举例:** 逆向工程师可以使用 Stalker 跟踪一个恶意软件样本，观察其在运行时加载了哪些库、调用了哪些系统 API，从而理解其恶意行为。
* **代码覆盖率分析:**  通过 Stalker 记录执行过的代码块，可以进行代码覆盖率分析，帮助逆向工程师了解哪些代码被执行了，哪些代码没有被执行，从而更全面地理解程序的逻辑。
    * **举例:** 在分析一个加壳的程序时，可以使用 Stalker 记录解壳过程执行的代码，从而找到原始的程序入口点。
* **运行时修改代码:** 虽然这个文件主要关注跟踪，但 Frida 的 Stalker 也可以与其他的 Frida 功能结合，在运行时修改代码行为，例如 hook 函数、替换指令等。
* **性能分析和优化:**  `lapsed` 测试用例展示了 Stalker 的性能开销。逆向工程师在进行动态分析时，需要了解工具的性能影响，以便更好地进行分析和调试。

**涉及二进制底层，linux, android内核及框架的知识及举例说明:**

* **二进制指令级别操作:** Stalker 的核心功能是跟踪二进制指令的执行。它需要理解目标架构（这里是 ARM64）的指令集，才能正确地插入 hook 代码并记录执行流程。
* **进程和线程管理:**  `prefetch_run_child` 函数使用了 `fork()` 系统调用来创建子进程，`waitpid()` 来等待子进程结束。`run_on_thread_*` 功能涉及到线程的管理，需要理解操作系统提供的线程 API。
* **内存管理:**  Stalker 需要访问目标进程的内存空间，读取和修改指令。`store_range_of_test_runner` 涉及到枚举进程模块并获取其内存范围。`pretend_workload` 中的 LZMA 压缩操作也涉及到内存的分配和使用。
* **进程间通信 (IPC):** `prefetch` 测试用例使用了 `pipe()` 系统调用创建管道，用于父子进程之间的通信，传递编译和执行的代码块信息。这涉及到 Linux 的 IPC 机制。
* **系统调用:** 虽然代码中没有直接的系统调用，但 Stalker 的底层实现会使用大量的系统调用来完成代码注入、内存访问、线程控制等操作。在 Android 平台上，这些系统调用会与 Android 内核和框架进行交互。
* **Android 特性 (可能涉及):**  虽然这个文件是通用的 ARM64 测试，但在 Android 环境下使用 Frida 时，可能会涉及到与 ART (Android Runtime) 的交互，例如 hook Java 方法、跟踪 Dalvik/ART 指令等。

**逻辑推理，给出假设输入与输出:**

**`prefetch` 测试用例:**

* **假设输入:**  测试 runner 模块的内存范围，以及被 `pretend_workload` 模拟执行的代码。
* **第一次运行的预期输出:**  `compiled_run1` 和 `executed_run1` 这两个哈希表将包含在第一次运行时 Stalker 编译和执行的代码块的地址。输出的日志会显示编译和执行的代码块数量。
* **第二次运行的预期输出:** 在第一次运行后，由于使用了 `gum_stalker_prefetch`，第二次运行的 `compiled_run2` 应该为空（或者接近为空），表示没有新的代码块被编译。`executed_run2` 应该和 `executed_run1` 的大小相同，表示执行了相同的代码块。

**`observer` 测试用例:**

* **假设输入:**  一段包含循环的代码 ( `for (i = 0; i != 10; i++) sum += i;` ) 在 Stalker 的跟踪下执行。
* **预期输出:** `test_observer->total` 的值将大于 0，因为在 Stalker 跟踪执行过程中，观察者的 `increment_total` 方法会被调用。具体的数值取决于 Stalker 内部的实现和事件触发机制。

**涉及用户或者编程常见的使用错误及举例说明:**

* **未正确初始化 Frida 环境:** 用户可能忘记启动 Frida 服务或者未将 Frida 客户端连接到目标进程，导致 Stalker 无法正常工作。
* **Hook 错误的地址或函数:**  虽然此文件侧重于 Stalker 的核心功能，但在实际使用中，如果用户使用 Frida 的其他功能（例如 `Interceptor`）来 hook 函数，可能会因为地址错误或函数签名不匹配而导致程序崩溃或 hook 失败。
* **在高频率执行的代码中过度使用 Stalker:** Stalker 会引入一定的性能开销。如果用户在性能敏感的代码区域无限制地使用 Stalker，可能会导致目标程序运行缓慢甚至卡死。
* **在多线程程序中不当使用 Stalker:** 在多线程程序中使用 Stalker 需要特别注意线程安全问题。例如，在回调函数中访问共享数据时需要加锁，否则可能导致数据竞争。
* **忘记取消 Stalker 的跟踪:** 如果用户在完成分析后忘记调用 `gum_stalker_unfollow_me`，Stalker 可能会继续运行并影响目标程序的性能。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要分析一个 ARM64 架构的程序:**  用户可能正在进行逆向工程、恶意软件分析、漏洞挖掘等任务，目标程序是运行在 ARM64 架构上的。
2. **用户选择使用 Frida 进行动态分析:**  Frida 提供了强大的动态 instrumentation 功能，用户选择了 Frida 作为分析工具。
3. **用户希望跟踪程序的执行流程:**  用户可能需要了解程序在运行时的代码执行路径，以便理解其行为或查找漏洞。
4. **用户使用 Frida 的 Stalker 功能:**  Stalker 是 Frida 中用于跟踪代码执行的核心组件，用户选择了 Stalker 来实现代码跟踪的目标。
5. **用户可能遇到了与 Stalker 预取或多线程执行相关的问题:**  例如，用户可能注意到 Stalker 在某些情况下性能不佳，或者希望在特定的线程上执行某些操作。
6. **用户深入研究 Frida 的源代码以了解其工作原理:**  为了更深入地理解 Stalker 的工作方式，或者为了调试遇到的问题，用户可能会查看 Frida 的源代码，并最终找到 `frida/subprojects/frida-gum/tests/core/arch-arm64/stalker-arm64.c` 这个测试文件，希望通过阅读测试代码来理解 Stalker 的特定功能，例如预取和多线程执行。

**归纳一下它的功能 (第3部分):**

总而言之，这个代码文件是 `frida-gum` 库中关于 ARM64 架构下 Stalker 功能的单元测试集合。它主要测试了 Stalker 的性能开销、代码块预取功能以及在指定线程上执行代码的能力。这些测试用例通过模拟实际场景，验证了 Stalker 在 ARM64 平台上的正确性和有效性，同时也为开发者提供了 Stalker 功能的使用示例。对于用户来说，理解这些测试用例可以帮助他们更好地理解和使用 Frida 的 Stalker 功能，从而更有效地进行动态程序分析和逆向工程。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm64/stalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
lapsed (timer, NULL);

  gum_stalker_unfollow_me (fixture->stalker);

  g_timer_destroy (timer);

  g_print ("<duration_direct=%f duration_stalked=%f ratio=%f> ",
      duration_direct, duration_stalked, duration_stalked / duration_direct);
}

static gboolean
store_range_of_test_runner (const GumModuleDetails * details,
                            gpointer user_data)
{
  GumMemoryRange * runner_range = user_data;

  if (strstr (details->name, "gum-tests") != NULL)
  {
    *runner_range = *details->range;
    return FALSE;
  }

  return TRUE;
}

GUM_NOINLINE static void
pretend_workload (GumMemoryRange * runner_range)
{
  lzma_stream stream = LZMA_STREAM_INIT;
  const uint32_t preset = 9 | LZMA_PRESET_EXTREME;
  lzma_ret ret;
  guint8 * outbuf;
  gsize outbuf_size;
  const gsize outbuf_size_increment = 1024 * 1024;

  ret = lzma_easy_encoder (&stream, preset, LZMA_CHECK_CRC64);
  g_assert_cmpint (ret, ==, LZMA_OK);

  outbuf_size = outbuf_size_increment;
  outbuf = malloc (outbuf_size);

  stream.next_in = GSIZE_TO_POINTER (runner_range->base_address);
  stream.avail_in = MIN (runner_range->size, 65536);
  stream.next_out = outbuf;
  stream.avail_out = outbuf_size;

  while (TRUE)
  {
    ret = lzma_code (&stream, LZMA_FINISH);

    if (stream.avail_out == 0)
    {
      gsize compressed_size;

      compressed_size = outbuf_size;

      outbuf_size += outbuf_size_increment;
      outbuf = realloc (outbuf, outbuf_size);

      stream.next_out = outbuf + compressed_size;
      stream.avail_out = outbuf_size - compressed_size;
    }

    if (ret != LZMA_OK)
    {
      g_assert_cmpint (ret, ==, LZMA_STREAM_END);
      break;
    }
  }

  lzma_end (&stream);

  free (outbuf);
}

#ifdef HAVE_LINUX

TESTCASE (prefetch)
{
  GumMemoryRange runner_range;
  gint trust;
  int compile_pipes[2] = { -1, -1 };
  int execute_pipes[2] = { -1, -1 };
  GumEventSink * sink;
  GHashTable * compiled_run1;
  GHashTable * executed_run1;
  guint compiled_size_run1;
  guint executed_size_run1;
  GHashTableIter iter;
  gpointer iter_key, iter_value;
  GHashTable * compiled_run2;
  GHashTable * executed_run2;
  guint compiled_size_run2;
  guint executed_size_run2;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  /* Initialize workload parameters */
  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_cmpuint (runner_range.base_address, !=, 0);
  g_assert_cmpuint (runner_range.size, !=, 0);

  /* Initialize Stalker */
  gum_stalker_set_trust_threshold (fixture->stalker, 3);
  trust = gum_stalker_get_trust_threshold (fixture->stalker);

  /*
   * Create IPC.
   *
   * The pipes by default are 64 KB in size. At 8-bytes per-block, (the block
   * address) we thus have capacity to communicate up to 8192 blocks back to the
   * parent before the child's write() call blocks and we deadlock in waitpid().
   *
   * We can increase the size of these pipes using fcntl(F_SETPIPE_SZ), but we
   * need to be careful so we don't exceed the limit set in
   * /proc/sys/fs/pipe-max-size.
   *
   * Since our test has approx 1800 blocks, we don't need to worry about this.
   * However, production implementations may need to handle this error.
   */
  g_assert_cmpint (pipe (compile_pipes), ==, 0);
  g_assert_cmpint (pipe (execute_pipes), ==, 0);
  g_assert_true (g_unix_set_fd_nonblocking (compile_pipes[0], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (compile_pipes[1], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (execute_pipes[0], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (execute_pipes[1], TRUE, NULL));

  /* Configure Stalker */
  sink = gum_event_sink_make_from_callback (GUM_COMPILE | GUM_BLOCK,
      prefetch_on_event, NULL, NULL);
  gum_stalker_follow_me (fixture->stalker, NULL, sink);
  gum_stalker_deactivate (fixture->stalker);

  /* Run the child */
  prefetch_run_child (fixture->stalker, &runner_range,
      compile_pipes[STDOUT_FILENO], execute_pipes[STDOUT_FILENO]);

  /* Read the results */
  compiled_run1 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (compile_pipes[STDIN_FILENO], compiled_run1);
  executed_run1 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (execute_pipes[STDIN_FILENO], executed_run1);

  compiled_size_run1 = g_hash_table_size (compiled_run1);
  executed_size_run1 = g_hash_table_size (executed_run1);

  if (g_test_verbose ())
  {
    g_print ("\tcompiled: %d\n", compiled_size_run1);
    g_print ("\texecuted: %d\n", executed_size_run1);
  }

  g_assert_cmpuint (compiled_size_run1, >, 0);
  g_assert_cmpuint (compiled_size_run1, ==, executed_size_run1);

  /* Prefetch the blocks */
  g_hash_table_iter_init (&iter, compiled_run1);
  while (g_hash_table_iter_next (&iter, &iter_key, &iter_value))
  {
    gum_stalker_prefetch (fixture->stalker, iter_key, trust);
  }

  /* Run the child again */
  prefetch_run_child (fixture->stalker, &runner_range,
      compile_pipes[STDOUT_FILENO], execute_pipes[STDOUT_FILENO]);

  /* Read the results */
  compiled_run2 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (compile_pipes[STDIN_FILENO], compiled_run2);
  executed_run2 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (execute_pipes[STDIN_FILENO], executed_run2);

  compiled_size_run2 = g_hash_table_size (compiled_run2);
  executed_size_run2 = g_hash_table_size (executed_run2);

  if (g_test_verbose ())
  {
    g_print ("\tcompiled2: %d\n", compiled_size_run2);
    g_print ("\texecuted2: %d\n", executed_size_run2);
  }

  g_assert_cmpuint (compiled_size_run2, ==, 0);
  g_assert_cmpuint (executed_size_run2, ==, executed_size_run1);

  /* Free resources */
  g_hash_table_unref (compiled_run2);
  g_hash_table_unref (executed_run2);
  g_hash_table_unref (compiled_run1);
  g_hash_table_unref (executed_run1);

  close (execute_pipes[STDIN_FILENO]);
  close (execute_pipes[STDOUT_FILENO]);
  close (compile_pipes[STDIN_FILENO]);
  close (compile_pipes[STDOUT_FILENO]);

  gum_stalker_unfollow_me (fixture->stalker);
  g_object_unref (sink);
}

static void
prefetch_on_event (const GumEvent * event,
                   GumCpuContext * cpu_context,
                   gpointer user_data)
{
  switch (event->type)
  {
    case GUM_COMPILE:
    {
      const GumCompileEvent * compile = &event->compile;

      if (prefetch_compiled != NULL)
        g_hash_table_add (prefetch_compiled, compile->start);

      break;
    }
    case GUM_BLOCK:
    {
      const GumBlockEvent * block = &event->block;

      if (prefetch_executed != NULL)
        g_hash_table_add (prefetch_executed, block->start);

      break;
    }
    default:
      break;
  }
}

static void
prefetch_run_child (GumStalker * stalker,
                    GumMemoryRange * runner_range,
                    int compile_fd,
                    int execute_fd)
{
  pid_t pid;
  int res;
  int status;

  pid = fork ();
  g_assert_cmpint (pid, >=, 0);

  if (pid == 0)
  {
    /* Child */

    prefetch_compiled = g_hash_table_new (NULL, NULL);
    prefetch_executed = g_hash_table_new (NULL, NULL);

    gum_stalker_activate (stalker, prefetch_activation_target);
    prefetch_activation_target ();
    pretend_workload (runner_range);
    gum_stalker_unfollow_me (stalker);

    prefetch_write_blocks (compile_fd, prefetch_compiled);
    prefetch_write_blocks (execute_fd, prefetch_executed);

    exit (0);
  }

  /* Wait for the child */
  res = waitpid (pid, &status, 0);
  g_assert_cmpint (res, ==, pid);
  g_assert_cmpint (WIFEXITED (status), !=, 0);
  g_assert_cmpint (WEXITSTATUS (status), ==, 0);
}

GUM_NOINLINE static void
prefetch_activation_target (void)
{
  /* Avoid calls being optimized out */
  asm ("");
}

static void
prefetch_write_blocks (int fd,
                       GHashTable * table)
{
  GHashTableIter iter;
  gpointer iter_key, iter_value;

  g_hash_table_iter_init (&iter, table);
  while (g_hash_table_iter_next (&iter, &iter_key, &iter_value))
  {
    int res = write (fd, &iter_key, sizeof (gpointer));
    g_assert_cmpint (res, ==, sizeof (gpointer));
  }
}

static void
prefetch_read_blocks (int fd,
                      GHashTable * table)
{
  gpointer block_address;

  while (read (fd, &block_address, sizeof (gpointer)) == sizeof (gpointer))
  {
    g_hash_table_add (table, block_address);
  }
}

TESTCASE (observer)
{
  GumTestStalkerObserver * test_observer;
  GumStalkerObserver * observer;
  guint sum, i;

  test_observer = g_object_new (GUM_TYPE_TEST_STALKER_OBSERVER, NULL);

  observer = GUM_STALKER_OBSERVER (test_observer);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  gum_stalker_deactivate (fixture->stalker);

  gum_stalker_set_observer (fixture->stalker, observer);

  gum_stalker_activate (fixture->stalker, prefetch_activation_target);
  prefetch_activation_target ();

  sum = 0;
  for (i = 0; i != 10; i++)
    sum += i;

  gum_stalker_unfollow_me (fixture->stalker);

  if (g_test_verbose ())
    g_print ("total: %" G_GINT64_MODIFIER "u\n", test_observer->total);

  g_assert_cmpuint (sum, ==, 45);
  g_assert_cmpuint (test_observer->total, !=, 0);
}

static void
gum_test_stalker_observer_iface_init (gpointer g_iface,
                                      gpointer iface_data)
{
  GumStalkerObserverInterface * iface = g_iface;

  iface->increment_total = gum_test_stalker_observer_increment_total;
}

static void
gum_test_stalker_observer_class_init (GumTestStalkerObserverClass * klass)
{
}

static void
gum_test_stalker_observer_init (GumTestStalkerObserver * self)
{
}

static void
gum_test_stalker_observer_increment_total (GumStalkerObserver * observer)
{
  GUM_TEST_STALKER_OBSERVER (observer)->total++;
}

#endif

TESTCASE (run_on_thread_current)
{
  GumThreadId thread_id;
  RunOnThreadCtx ctx;
  gboolean accepted;

  thread_id = gum_process_get_current_thread_id ();
  ctx.caller_id = thread_id;
  ctx.thread_id = G_MAXSIZE;

  accepted = gum_stalker_run_on_thread (fixture->stalker, thread_id,
      run_on_thread, &ctx, NULL);
  g_assert_true (accepted);
  g_assert_cmpuint (ctx.thread_id, ==, thread_id);
}

TESTCASE (run_on_thread_current_sync)
{
  GumThreadId thread_id;
  RunOnThreadCtx ctx;
  gboolean accepted;

  thread_id = gum_process_get_current_thread_id ();
  ctx.caller_id = thread_id;
  ctx.thread_id = G_MAXSIZE;

  accepted = gum_stalker_run_on_thread_sync (fixture->stalker, thread_id,
      run_on_thread, &ctx);
  g_assert_true (accepted);
  g_assert_cmpuint (thread_id, ==, ctx.thread_id);
}

static void
run_on_thread (const GumCpuContext * cpu_context,
               gpointer user_data)
{
  RunOnThreadCtx * ctx = user_data;

  g_usleep (250000);
  ctx->thread_id = gum_process_get_current_thread_id ();

  if (ctx->thread_id == ctx->caller_id)
    g_assert_null (cpu_context);
  else
    g_assert_nonnull (cpu_context);
}

TESTCASE (run_on_thread_other)
{
  GThread * thread;
  gboolean done = FALSE;
  GumThreadId other_id, this_id;
  RunOnThreadCtx ctx;
  gboolean accepted;

  thread = create_sleeping_dummy_thread_sync (&done, &other_id);

  this_id = gum_process_get_current_thread_id ();
  g_assert_cmphex (this_id, !=, other_id);
  ctx.caller_id = this_id;
  ctx.thread_id = G_MAXSIZE;

  accepted = gum_stalker_run_on_thread (fixture->stalker, other_id,
      run_on_thread, &ctx, NULL);
  g_assert_true (accepted);
  done = TRUE;
  g_thread_join (thread);
  g_assert_cmphex (ctx.thread_id, ==, other_id);
}

TESTCASE (run_on_thread_other_sync)
{
  GThread * thread;
  gboolean done = FALSE;
  GumThreadId other_id, this_id;
  RunOnThreadCtx ctx;
  gboolean accepted;

  thread = create_sleeping_dummy_thread_sync (&done, &other_id);

  this_id = gum_process_get_current_thread_id ();
  g_assert_cmphex (this_id, !=, other_id);
  ctx.caller_id = this_id;
  ctx.thread_id = G_MAXSIZE;

  accepted = gum_stalker_run_on_thread_sync (fixture->stalker, other_id,
      run_on_thread, &ctx);
  g_assert_true (accepted);
  done = TRUE;
  g_thread_join (thread);
  g_assert_cmpuint (ctx.thread_id, ==, other_id);
}

static GThread *
create_sleeping_dummy_thread_sync (gboolean * done,
                                   GumThreadId * thread_id)
{
  GThread * thread;
  TestThreadSyncData sync_data;

  g_mutex_init (&sync_data.mutex);
  g_cond_init (&sync_data.cond);
  sync_data.started = FALSE;
  sync_data.thread_id = 0;
  sync_data.done = done;

  g_mutex_lock (&sync_data.mutex);

  thread = g_thread_new ("sleepy", sleeping_dummy, &sync_data);

  while (!sync_data.started)
    g_cond_wait (&sync_data.cond, &sync_data.mutex);

  *thread_id = sync_data.thread_id;

  g_mutex_unlock (&sync_data.mutex);

  g_cond_clear (&sync_data.cond);
  g_mutex_clear (&sync_data.mutex);

  return thread;
}

static gpointer
sleeping_dummy (gpointer data)
{
  TestThreadSyncData * sync_data = data;
  gboolean * done = sync_data->done;

  g_mutex_lock (&sync_data->mutex);
  sync_data->started = TRUE;
  sync_data->thread_id = gum_process_get_current_thread_id ();
  g_cond_signal (&sync_data->cond);
  g_mutex_unlock (&sync_data->mutex);

  while (!(*done))
    g_thread_yield ();

  return NULL;
}
```