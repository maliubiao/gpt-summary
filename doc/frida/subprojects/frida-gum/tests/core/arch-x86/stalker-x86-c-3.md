Response:
Let's break down the thought process for analyzing this C code snippet for Frida's Stalker.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `stalker-x86.c` file, specifically focusing on its relationship to reverse engineering, low-level details (kernel, architecture), logical reasoning, potential user errors, debugging context, and a final summary. Since this is part 4 of 4, the final request is to summarize the *entire* file's functionality, considering the previous parts.

**2. Initial Code Scan and Keyword Recognition:**

I'd start by quickly scanning the code for relevant keywords and function names. This gives a high-level overview:

* **`prefetch_backpatch_tranform`, `prefetch_on_fork`, `prefetch_backpatch_simple_workload`:**  These immediately suggest a focus on code modification ("backpatching") and optimization ("prefetching"), potentially in the context of forking processes.
* **`GumStalker`, `GumInterceptor`, `GumCpuContext`, `GumBackpatch`, `GumStalkerIterator`, `GumStalkerOutput`, `GumMemoryRange`:**  These clearly point to Frida's Stalker API and its components for code tracing and modification.
* **`fork`, `waitpid`, `pipe`, `read`, `write`, `close`, `_exit`:** These are standard system calls related to process creation, inter-process communication, and program termination, indicating interaction with the operating system.
* **`TESTCASE`:**  This signifies a unit test file, providing examples of how the Stalker is used.
* **`observer`, `gum_test_stalker_observer_*`:** Suggests a testing mechanism to observe Stalker behavior, especially around backpatching.
* **`ic_var`:** Might relate to instruction counting or some internal variable.
* **`no_exceptions`, `try_and_catch`, `try_and_dont_catch`, `__cxa_throw`:** Indicates testing of exception handling scenarios, important for understanding how Stalker interacts with program control flow.
* **`run_on_thread_*`:**  Focuses on Stalker's ability to operate on specific threads.
* **`GUM_NOINLINE`:** Hints at preventing compiler optimizations, likely for testing specific code paths.
* **`asm ("nop;")`:**  Explicit assembly instruction, again often used in testing to ensure code execution reaches a certain point.

**3. Analyzing Key Functionalities (Iterative Process):**

Now I'd delve into the details of the more significant functions:

* **`prefetch_fork_and_backpatch`:**  This is the core of the first test case. The name itself is descriptive. I'd analyze the sequence:
    * Set up pipes for communication.
    * Install an interceptor on `fork`.
    * Start Stalker (`gum_stalker_follow_me`).
    * Execute a simple workload (`prefetch_backpatch_simple_workload`).
    * The intercepted `fork` calls `prefetch_on_fork`.
    * `prefetch_on_fork` reads backpatch data from the pipe and applies it using `gum_stalker_prefetch_backpatch`.
    * The `prefetch_backpatch_tranform` callback is where the initial entry point is detected and the first `entry_callout` is inserted.
    * `entry_callout` forks multiple children to test the prefetching logic.

* **`prefetch_on_fork`:**  Focus on how it receives backpatch data from the parent process via pipes and uses `gum_stalker_prefetch_backpatch`. The assertions (`g_assert_cmpint`) are crucial for understanding the expected behavior.

* **`prefetch_backpatch_tranform`:**  The key logic is finding the `pretend_workload` address and inserting a callout. This illustrates how Stalker can modify the code flow.

* **`entry_callout`:** The repeated forking and `waitpid` calls are central to the test. The assertions about `counts` are important for verifying the prefetching mechanism.

* **`observer` test case:** The custom observer (`GumTestStalkerObserver`) and its methods (`increment_total`, `notify_backpatch`) demonstrate how to get notifications about Stalker's actions, particularly backpatching. The pipe communication here is for sending backpatch data from the child process back to the parent for prefetching.

* **Exception Handling Tests (`no_exceptions`, `try_and_catch`, etc.):** Focus on how Stalker behaves when exceptions are thrown and caught (or not). The `__cxa_throw` exclusion is a specific detail to note.

* **Thread-Related Tests (`run_on_thread_*`):**  Analyze how Stalker can execute code on specific threads, both the current thread and other threads.

**4. Identifying Relationships to Reverse Engineering, Low-Level Details, and Logical Reasoning:**

* **Reverse Engineering:** The entire concept of Stalker—tracing code execution, intercepting functions, and modifying code—is fundamental to dynamic reverse engineering. The `prefetch_backpatch` mechanism is an optimization, but the underlying ability to insert code and change program behavior is key.
* **Binary/Low-Level:** The code deals with memory addresses, instruction pointers, and the execution of machine code. The interaction with `fork` and the underlying process model are very low-level. The need for architecture-specific code (implied by the file path) is another indicator.
* **Linux/Android Kernel:** The use of `fork`, `waitpid`, pipes, and `/proc/sys/fs/pipe-max-size` are specific to Linux-like operating systems. The `fork` system call directly interacts with the kernel's process management.
* **Logical Reasoning:**  The assertions throughout the code represent logical deductions about the expected state of the program at different points. For example, the assertions in `entry_callout` about the `counts` array are based on the logic of how prefetching should work.

**5. Considering User/Programming Errors and Debugging:**

* **User Errors:**  Incorrectly setting up the `GumStalkerTransformer` or `GumEventSink`, misunderstanding the timing of Stalker's operations, and failing to handle errors from system calls (though the tests use `g_assert`) are potential user errors.
* **Debugging:**  The code itself is a form of testing and debugging the Stalker. The `g_test_verbose()` checks allow for more detailed output, aiding in debugging. The structure of the tests (setup, action, assertion) is a standard debugging pattern. The pipe communication, while functional, could be a source of errors if not managed correctly.

**6. Formulating Assumptions for Input/Output:**

For the `prefetch_fork_and_backpatch` test, the main assumption is the existence of the `pretend_workload` function. The "input" is the execution of this workload. The "output" is the successful completion of the test, verified by the assertions, demonstrating that backpatches are prefetched correctly across fork calls. For simpler functions, the input and output are more direct (e.g., calling `gum_stalker_run_on_thread` and observing the callback execution).

**7. Structuring the Explanation:**

I'd organize the explanation logically, addressing each part of the request:

* **Functionality:** Describe the main purpose of the file and the core test cases.
* **Reverse Engineering:** Explain how Stalker relates to it, using examples from the code (code injection, interception).
* **Low-Level Details:** Discuss the OS and architecture dependencies, citing relevant system calls and concepts.
* **Logical Reasoning:**  Highlight the assertions and the logic behind the tests.
* **User Errors:** Provide concrete examples of potential mistakes.
* **Debugging:** Explain how the tests themselves act as debugging tools.
* **User Operation to Reach Here:**  Outline the steps to run the tests.
* **Summary (Part 4):**  Synthesize the functionalities described across all parts (if available), emphasizing the core capabilities of Stalker.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This just tests forking."  **Correction:** While forking is central, the *purpose* is to test *prefetching of backpatches* during forking.
* **Initial thought:** "The observer is just for logging." **Correction:** The observer actively participates in the backpatch prefetching process by sending backpatch data through the pipes.
* **Overlooking details:** Initially, I might miss the significance of `GUM_NOINLINE` or the explicit assembly `nop`. Rereading and considering *why* these are used helps to understand the testing methodology.

By following these steps, moving from a broad overview to detailed analysis, and constantly relating the code back to the core concepts of Frida and reverse engineering, a comprehensive explanation can be constructed.
这是frida动态 instrumentation工具的源代码文件 `frida/subprojects/frida-gum/tests/core/arch-x86/stalker-x86.c` 的第四部分，它主要包含以下功能：

**1. `TESTCASE (run_on_thread_current)` 和 `TESTCASE (run_on_thread_current_sync)`:**
   - **功能:** 测试 Stalker 是否能在当前线程上执行回调函数。
   - **逆向关系:** 在逆向分析中，我们可能需要在特定的线程上下文中注入代码或执行操作。这两个测试用例验证了 Stalker 具备这种能力。通过 `gum_stalker_run_on_thread` 和 `gum_stalker_run_on_thread_sync`，Frida 可以在目标进程的特定线程上执行用户提供的代码。
   - **二进制底层知识:**  涉及线程的概念，这是操作系统层面的抽象。`gum_process_get_current_thread_id()` 函数需要访问操作系统提供的 API 来获取当前线程 ID。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 当前线程 ID 被正确获取。
     - **预期输出:** `run_on_thread` 回调函数被执行，并且在该回调函数中获取的线程 ID 与初始获取的线程 ID 相等。`run_on_thread_sync` 版本会同步等待回调执行完成。
   - **用户错误:** 用户可能会传递错误的线程 ID，导致回调函数无法在目标线程上执行。
   - **调试线索:** 用户首先需要获取目标进程的线程 ID，然后调用 `gum_stalker_run_on_thread` 或 `gum_stalker_run_on_thread_sync`。如果回调未执行，需要检查线程 ID 是否正确，以及 Stalker 是否已正确初始化。

**2. `TESTCASE (run_on_thread_other)` 和 `TESTCASE (run_on_thread_other_sync)`:**
   - **功能:** 测试 Stalker 是否能在另一个线程上执行回调函数。
   - **逆向关系:**  在实际逆向场景中，目标代码可能在多个线程中运行。能够在特定线程上注入代码是至关重要的，例如，Hook 特定线程的函数调用。
   - **二进制底层知识:** 涉及多线程编程和线程同步。测试用例中使用了 `GThread` 来创建新的线程。`gum_stalker_run_on_thread` 和 `gum_stalker_run_on_thread_sync` 的实现需要处理跨线程执行代码的问题，可能涉及到信号、锁等机制。
   - **Linux/Android内核及框架:** `GThread` 是 GLib 库提供的线程抽象，底层在 Linux 上通常使用 POSIX 线程 (pthreads)，在 Android 上也类似。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**  成功创建了一个新的睡眠线程，并获取了该线程的 ID。
     - **预期输出:** `run_on_thread` 回调函数在新的线程上执行，并且在该回调函数中获取的线程 ID 与新线程的 ID 相等。`run_on_thread_sync` 版本会同步等待回调执行完成。
   - **用户错误:**  用户可能会尝试在已退出或不存在的线程上执行回调。
   - **调试线索:** 用户需要确保目标线程仍然存活。可以使用 Frida 的 API 或操作系统工具来列出进程的线程。如果回调未执行，需要检查线程 ID 的有效性。

**3. `static void run_on_thread(...)`:**
   - **功能:**  这是一个简单的回调函数，用于在上述的 `run_on_thread_*` 测试用例中执行。它会短暂休眠，然后获取当前线程 ID 并与调用者的线程 ID 进行比较。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**  `user_data` 指向一个 `RunOnThreadCtx` 结构体，其中包含调用者的线程 ID。
     - **预期输出:**  回调函数执行后，`ctx->thread_id` 被设置为当前线程的 ID。如果当前线程与调用者线程是同一个，则 `cpu_context` 应该为 NULL，否则不为 NULL。

**4. `static GThread * create_sleeping_dummy_thread_sync(...)` 和 `static gpointer sleeping_dummy(...)`:**
   - **功能:**  这两个函数用于创建一个新的线程，该线程会进入睡眠状态，等待主线程的信号。这用于模拟在另一个线程上执行代码的场景。
   - **二进制底层知识:**  涉及到线程的创建和同步机制，使用了 GLib 库提供的互斥锁 (`g_mutex_t`) 和条件变量 (`g_cond_t`)。
   - **Linux/Android内核及框架:**  依赖于操作系统提供的线程 API。

**归纳一下 `stalker-x86.c` 文件的功能 (综合所有部分):**

`stalker-x86.c` 是 Frida Gum 库中 Stalker 组件在 x86 架构下的单元测试文件。它测试了 Stalker 的核心功能，包括：

1. **基本追踪和代码转换:**  测试 Stalker 能否追踪代码执行，并通过转换器 (transformer) 修改代码，例如插入回调函数 (callout)。
2. **指令级控制:**  测试 Stalker 是否能处理单步执行、控制代码执行流程。
3. **代码排除:**  测试 Stalker 是否能排除特定内存区域的代码追踪。
4. **代码缓存 (IC):**  测试 Stalker 的指令缓存机制。
5. **重写 (Rewriter):** 测试 Stalker 的代码重写功能，能够修改目标指令。
6. **回填 (Backpatching):** 测试 Stalker 的回填机制，允许在运行时修改已执行过的代码。
7. **回填预取 (Prefetch Backpatching):** 测试 Stalker 在进程 fork 时预取回填的能力，以优化性能。
8. **观察者模式 (Observer):** 测试 Stalker 的观察者模式，允许用户监听 Stalker 的事件，例如回填操作。
9. **在特定线程上运行 (Run on Thread):** 测试 Stalker 是否能在指定的线程上执行回调函数，包括当前线程和其他线程。
10. **异常处理:** 测试 Stalker 如何与 C++ 异常处理机制交互。

总而言之，`stalker-x86.c` 通过一系列全面的测试用例，验证了 Frida Stalker 组件在 x86 架构下的各种核心功能，确保其能够可靠地进行代码追踪、修改和在运行时进行动态 instrumentation。这些功能是 Frida 作为动态逆向工程工具的基础。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-x86/stalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
    prefetch_backpatch_tranform, NULL, NULL);

  fork_addr = GSIZE_TO_POINTER (gum_module_find_export_by_name (NULL, "fork"));
  interceptor = gum_interceptor_obtain ();
  gum_interceptor_begin_transaction (interceptor);
  g_assert_cmpint (gum_interceptor_replace (interceptor, fork_addr,
      prefetch_on_fork, NULL, NULL), ==, GUM_REPLACE_OK);
  gum_interceptor_end_transaction (interceptor);

  gum_stalker_set_trust_threshold (fixture->stalker, 0);

  gum_stalker_follow_me (bp_ctx.stalker, bp_ctx.transformer, NULL);

  gum_stalker_set_observer (bp_ctx.stalker,
      GUM_STALKER_OBSERVER (bp_ctx.observer));

  /*
   * Our maximum pipe size is likely to be fairly modest (without reconfiguring
   * the system). So we use a relatively simple workload so that we don't
   * saturate it.
   */
  prefetch_backpatch_simple_workload (&bp_ctx.runner_range);

  _exit (0);
}

static void
prefetch_backpatch_tranform (GumStalkerIterator * iterator,
                             GumStalkerOutput * output,
                             gpointer user_data)
{
  const cs_insn * instr;

  while (gum_stalker_iterator_next (iterator, &instr))
  {
    if (instr->address == GPOINTER_TO_SIZE (pretend_workload))
    {
      gum_stalker_iterator_put_callout (iterator, entry_callout, NULL, NULL);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
entry_callout (GumCpuContext * cpu_context,
               gpointer user_data)
{
  guint counts[3], i;

  for (i = 0; i != G_N_ELEMENTS (counts); i++)
  {
    pid_t pid;
    int res, status;

    pid = fork ();
    g_assert_cmpint (pid, >=, 0);

    if (pid == 0)
    {
      /* Child */
      bp_ctx.entry_reached = TRUE;
      return;
    }

    /* Parent */
    counts[i] = bp_ctx.count;
    res = waitpid (pid, &status, 0);
    g_assert_cmpint (res, ==, pid);
    g_assert_cmpint (WIFEXITED (status), !=, 0);
    g_assert_cmpint (WEXITSTATUS (status), ==, 0);
  }

  /*
   * When we fork the first child, we shouldn't have any backpatches to
   * prefetch.
   */
  g_assert_cmpuint (counts[0], ==, 0);

  /*
   * Just as we fork the second child, we should prefetch the backpatches from
   * the first time the child ran.
   */
  g_assert_cmpuint (counts[1], >, 0);

  /*
   * Before we fork the third child, we should prefetch the new backpatches from
   * the second run of the child, there should be less since the child should
   * have already inherited the backpatches we applied from the first run.
   */
  g_assert_cmpuint (counts[2], <, counts[1]);

  gum_stalker_unfollow_me (bp_ctx.stalker);

  close (bp_ctx.pipes[STDIN_FILENO]);
  close (bp_ctx.pipes[STDOUT_FILENO]);

  _exit (0);
}

static int
prefetch_on_fork (void)
{
  int n;
  gsize size;
  char buf[PIPE_BUF] = { 0, };

  bp_ctx.count = 0;
  for (n = read (bp_ctx.pipes[STDIN_FILENO], &size, sizeof (size));
       n >= 0;
       n = read (bp_ctx.pipes[STDIN_FILENO], &size, sizeof (size)))
  {
    g_assert_cmpint (read (bp_ctx.pipes[STDIN_FILENO], buf, size), ==, size);
    gum_stalker_prefetch_backpatch (bp_ctx.stalker, (const GumBackpatch *) buf);
    bp_ctx.count++;
  }
  g_assert_cmpint (n, ==, -1);
  g_assert_cmpint (errno, ==, EAGAIN);

  if (g_test_verbose ())
    g_print ("Prefetches (%u)\n", bp_ctx.count);

  return fork ();
}

GUM_NOINLINE static void
prefetch_backpatch_simple_workload (GumMemoryRange * runner_range)
{
  const guint8 * buf;
  gsize limit, i;
  guint8 val;

  buf = GSIZE_TO_POINTER (runner_range->base_address);
  limit = MIN (runner_range->size, 65536);

  val = 0;
  for (i = 0; i != limit; i++)
  {
    val = val ^ buf[i];
  }

  if (g_test_verbose ())
    g_print ("Result: 0x%02x\n", val);
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
  iface->notify_backpatch = gum_test_stalker_observer_notify_backpatch;
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

static void
gum_test_stalker_observer_notify_backpatch (GumStalkerObserver * self,
                                            const GumBackpatch * backpatch,
                                            gsize size)
{
  int written;

  if (!bp_ctx.entry_reached)
    return;

  written = write (bp_ctx.pipes[STDOUT_FILENO], &size, sizeof (size));
  g_assert_cmpint (written, ==, sizeof (size));

  written = write (bp_ctx.pipes[STDOUT_FILENO], backpatch, size);
  g_assert_cmpint (written, ==, size);
}

static gsize
get_max_pipe_size (void)
{
  guint64 val;
  gchar * contents;

  g_assert_true (g_file_get_contents ("/proc/sys/fs/pipe-max-size", &contents,
      NULL, NULL));

  val = g_ascii_strtoull (contents, NULL, 10);
  g_assert_cmpuint (val, <=, G_MAXINT32);

  g_free (contents);

  return (gsize) val;
}

#endif

#ifndef HAVE_WINDOWS

TESTCASE (ic_var)
{
  GumMemoryRange runner_range;
  GumStalker * stalker;

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_cmpuint (runner_range.base_address, !=, 0);
  g_assert_cmpuint (runner_range.size, !=, 0);

  stalker = g_object_new (GUM_TYPE_STALKER,
      "ic-entries", 32,
      NULL);

  gum_stalker_follow_me (stalker, NULL, NULL);
  pretend_workload (&runner_range);
  gum_stalker_unfollow_me (stalker);

  while (gum_stalker_garbage_collect (stalker))
    g_usleep (10000);

  g_object_unref (stalker);
}

#endif

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)

TESTCASE (no_exceptions)
{
  guint32 val = 0;

  fixture->sink->mask = GUM_EXEC;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      callback_at_end, &val, NULL);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  test_check_followed ();
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  if (g_test_verbose ())
    g_print ("val: 0x%08x\n", val);

  test_check_bit (&val, 31);
  g_assert_cmpuint (val, ==, 0);
}

TESTCASE (try_and_catch)
{
  guint32 val = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      callback_at_end, &val, NULL);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  test_try_and_catch (&val);
  test_check_followed ();
  gum_stalker_unfollow_me (fixture->stalker);

  if (g_test_verbose ())
    g_print ("val: 0x%08x\n", val);

  test_check_bit (&val, 0);
  test_check_bit (&val, 2);
  test_check_bit (&val, 3);
  test_check_bit (&val, 31);
  g_assert_cmpuint (val, ==, 0);
}

TESTCASE (try_and_catch_excluded)
{
  guint32 val = 0;
  const GumMemoryRange range = {
    .base_address = GPOINTER_TO_SIZE (__cxa_throw),
    .size = 1
  };

  gum_stalker_exclude (fixture->stalker, &range);

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      callback_at_end, &val, NULL);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  test_try_and_catch (&val);
  test_check_followed ();
  gum_stalker_unfollow_me (fixture->stalker);

  if (g_test_verbose ())
    g_print ("val: 0x%08x\n", val);

  test_check_bit (&val, 0);
  test_check_bit (&val, 2);
  test_check_bit (&val, 3);
  test_check_bit (&val, 31);
  g_assert_cmpuint (val, ==, 0);
}

TESTCASE (try_and_dont_catch)
{
  guint32 val = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      callback_at_end, &val, NULL);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  test_try_and_dont_catch (&val);
  test_check_followed ();
  gum_stalker_unfollow_me (fixture->stalker);

  if (g_test_verbose ())
    g_print ("val: 0x%08x\n", val);

  test_check_bit (&val, 0);
  test_check_bit (&val, 1);
  test_check_bit (&val, 2);
  test_check_bit (&val, 5);
  test_check_bit (&val, 6);
  test_check_bit (&val, 7);
  test_check_bit (&val, 11);
  test_check_bit (&val, 31);
  g_assert_cmpuint (val, ==, 0);
}

TESTCASE (try_and_dont_catch_excluded)
{
  guint32 val = 0;
  const GumMemoryRange range = {
    .base_address = GPOINTER_TO_SIZE (__cxa_throw),
    .size = 1
  };

  gum_stalker_exclude (fixture->stalker, &range);

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      callback_at_end, &val, NULL);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  test_try_and_dont_catch (&val);
  test_check_followed ();
  gum_stalker_unfollow_me (fixture->stalker);

  if (g_test_verbose ())
    g_print ("val: 0x%08x\n", val);

  test_check_bit (&val, 0);
  test_check_bit (&val, 1);
  test_check_bit (&val, 2);
  test_check_bit (&val, 5);
  test_check_bit (&val, 6);
  test_check_bit (&val, 7);
  test_check_bit (&val, 11);
  test_check_bit (&val, 31);
  g_assert_cmpuint (val, ==, 0);
}

static void
callback_at_end (GumStalkerIterator * iterator,
                 GumStalkerOutput * output,
                 gpointer user_data)
{
  guint32 * val = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    gum_stalker_iterator_keep (iterator);

    if (insn->address == GPOINTER_TO_SIZE (test_check_followed))
    {
      gum_stalker_iterator_put_callout (iterator, callout_at_end, val, NULL);
    }
  }
}

static void
callout_at_end (GumCpuContext * cpu_context,
                gpointer user_data)
{
  guint32 * val = user_data;
  *val += 1U << 31;
}

GUM_NOINLINE static void
test_check_followed (void)
{
  /* Avoid calls being optimized out */
  asm ("nop;");
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

"""


```