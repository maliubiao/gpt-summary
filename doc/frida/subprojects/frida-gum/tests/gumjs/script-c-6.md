Response:
Let's break down the thought process for analyzing this code snippet and answering the prompt.

1. **Understand the Context:** The initial prompt clearly states this is part of the Frida dynamic instrumentation tool, specifically within the `frida-gum` subproject, in a file named `script.c`. This immediately tells us we're dealing with testing the JavaScript bridge within Frida's core. The file extension `.c` indicates it's written in C, likely using a testing framework.

2. **Identify the Core Functionality:**  The code is structured as a series of `TESTCASE` blocks. This is a strong indicator of a unit testing framework (likely GLib's `g_test`). Each `TESTCASE` seems to focus on testing a specific aspect of the JavaScript API provided by Frida.

3. **Analyze Individual Test Cases (Iterative Process):** This is the most crucial step and requires careful reading of each `TESTCASE` block. For each test case:

    * **Look for Keywords:**  Keywords like `setTimeout`, `clearTimeout`, `setInterval`, `clearInterval`, `setImmediate`, `Script.nextTick`, `Interceptor.attach`, `Interceptor.replace`, `Interceptor.revert`, `send`, `recv`, `NativeFunction`, `NativeCallback`, `Thread.backtrace`, etc., are strong indicators of the functionality being tested.

    * **Understand the JavaScript Code:** The code within `COMPILE_AND_LOAD_SCRIPT` is JavaScript code that's executed within Frida's environment. Understanding this JavaScript is key to understanding the test's purpose.

    * **Identify the Assertion:**  The `EXPECT_SEND_MESSAGE_WITH`, `EXPECT_NO_MESSAGES`, `EXPECT_ERROR_MESSAGE_WITH`, and `g_assert_cmp*` macros are used for assertions. These tell us what the expected outcome of the JavaScript execution is.

    * **Connect to Frida Concepts:**  Relate the JavaScript code and the assertions to Frida's core concepts:
        * **`send()`/`recv()`:** Inter-process communication between the injected JavaScript and the controlling Frida client.
        * **`setTimeout`/`setInterval`/`setImmediate`/`Script.nextTick`:**  Testing the JavaScript timer and asynchronous execution mechanisms within the Frida environment.
        * **`Interceptor.attach()`:** Hooking into native function calls.
        * **`Interceptor.replace()`:** Replacing native function implementations.
        * **`NativeFunction`:** Calling native functions from JavaScript.
        * **`NativeCallback`:** Defining native function implementations in JavaScript.
        * **`this.context`:** Accessing CPU registers and other context information within interceptors.
        * **`Thread.backtrace()`:** Getting a stack trace.

4. **Group Functionality:**  After analyzing several test cases, start grouping them based on the core functionality they test. For example, there's a group testing timers, another testing interceptors, another testing register access, etc.

5. **Address Specific Prompt Questions:**  Once the individual test cases and grouped functionality are understood, start addressing the specific questions in the prompt:

    * **Functionality Listing:**  Summarize the groups of functionalities identified.
    * **Relation to Reverse Engineering:** Connect the tested functionalities to common reverse engineering tasks (e.g., hooking, function replacement, examining arguments and return values, understanding execution flow).
    * **Binary/Kernel/Framework Knowledge:** Identify tests that directly interact with or expose concepts related to the underlying operating system and architecture (e.g., register access, system error codes, thread management).
    * **Logic Reasoning (Assumptions/Inputs/Outputs):** For simpler tests, explicitly state the assumption being tested and the expected input/output based on the JavaScript code.
    * **User/Programming Errors:** Identify tests that expose potential pitfalls for users when using the Frida API (e.g., forgetting to detach listeners, using invalid pointers).
    * **User Operation to Reach Here:** Describe the general steps a user would take to arrive at needing to understand this code (likely developing or debugging Frida scripts).
    * **Summary of Functionality (Part 7):**  Focus on the specific functionality covered in this snippet (timers and basic interception).

6. **Synthesize and Structure the Answer:** Organize the findings into a clear and structured answer, using headings and bullet points to improve readability. Provide concrete examples from the code to illustrate the explanations.

7. **Refine and Review:** Review the answer for accuracy, completeness, and clarity. Ensure that all aspects of the prompt have been addressed. For instance, make sure to explain *why* a certain test relates to reverse engineering or low-level details.

**Self-Correction/Refinement Example During Analysis:**

Initially, I might just see a bunch of `TESTCASE` blocks and think "it's testing Frida."  But as I go through the tests, I realize the specific focus on JavaScript API elements. I might initially miss the significance of the `GUM_PTR_CONST` macro, but then recognize it's likely a placeholder for the address of the target function. I might also initially not fully grasp the multi-threading test but then realize it's checking for deadlocks in a concurrent environment. This iterative process of examining the code, connecting it to Frida concepts, and refining my understanding is crucial for a comprehensive analysis.
好的，让我们来分析一下 `frida/subprojects/frida-gum/tests/gumjs/script.c` 文件中的这段代码，这是第 7 部分，共 11 部分。根据代码内容，我们可以归纳出以下功能：

**主要功能归纳（基于第 7 部分代码）：**

这部分代码主要测试了 Frida GumJS 脚本中关于定时器（timers）和拦截器（interceptors）的核心功能。具体来说，它验证了：

1. **定时器 (Timers):**
   - `setTimeout` 功能的设置和执行。
   - `setTimeout` 功能的取消 (`clearTimeout`)。
   - `setInterval` 功能的设置和周期性执行。
   - `setInterval` 功能的取消 (`clearInterval`).
   - `setImmediate` 功能的设置和立即执行。
   - 从已调度的回调中调度 `setImmediate` 和 `Script.nextTick`。
   - `setImmediate` 功能的取消 (`clearImmediate`).
   - `Script.nextTick` 功能的设置和在下一个事件循环中执行。
   - 定时器取消 API 的容错性 (传入 `undefined`)。

2. **拦截器 (Interceptors):**
   - **参数的读取和替换:**  能够读取被拦截函数的参数值 (`args[0].toInt32()`)，并且能够替换参数值 (`args[0] = replacementString;`).
   - **返回值的读取和替换:** 能够读取被拦截函数的返回值 (`retval.toInt32()`)，并且能够替换返回值 (`retval.replace(1337)`).
   - **返回地址的读取:** 能够读取当前拦截点的返回地址 (`this.returnAddress`).
   - **通用寄存器的读取和写入:** 能够读取和修改被拦截函数执行时的通用寄存器 (`this.context.GUM_RETURN_VALUE_REGISTER_NAME`).
   - **向量寄存器的读取:**  能够读取向量寄存器的值 (`this.context.q0`).
   - **双精度浮点寄存器的读取:** 能够读取双精度浮点寄存器的值 (`this.context.d0`).
   - **单精度浮点寄存器的读取:** 能够读取单精度浮点寄存器的值 (`this.context.s0`).
   - **状态寄存器的读取:** 能够读取状态寄存器的值 (`this.context.cpsr` 或 `this.context.nzcv`).
   - **系统错误码的读取和替换:** 能够读取 (`this.lastError` 或 `this.errno`) 和替换系统错误码。
   - **调用上下文 (Invocation Context):**
     -  每次调用都绑定到 TLS 对象 (`this.value`).
     -  提供线程 ID (`this.threadId`).
     -  提供调用深度 (`this.depth`).
     -  提供用于生成回溯的上下文 (`this.context`).
     -  上下文可以序列化为 JSON (`JSON.stringify(this.context)`).
   - **监听器的分离 (Detaching Listeners):**
     - 可以单独分离监听器 (`firstListener.detach()`, `secondListener.detach()`).
     - 可以通过在调用过程中销毁脚本来分离监听器。
     - 可以分离所有监听器 (`Interceptor.detachAll()`).
   - **函数的替换 (Function Replacement):**
     - 可以使用 JavaScript 函数替换原生函数 (`Interceptor.replace`).
     - 替换后的函数可以立即被调用。
     - 可以恢复被替换的函数 (`Interceptor.revert`).
     - 替换后的函数应该有调用上下文。
   - **指令探测 (Instruction Probing):**  使用 `Interceptor.attach` 可以用于探测指令执行。
   - **支持 NativePointer 类型的值:** `Interceptor.attach` 和 `Interceptor.replace` 可以接受 `NativePointer` 类型的值作为地址。
   - **处理错误的指针:**  测试了当 `Interceptor.attach` 和 `Interceptor.replace` 尝试操作无效内存地址时的错误处理。
   - **拒绝没有回调函数的 attach:** 测试了 `Interceptor.attach` 在没有提供任何回调函数时的行为。
   - **并发场景下的无死锁:**  测试了在多线程并发地 attach 拦截器时，JavaScript 引擎不会发生死锁 (仅限 Darwin 平台)。
   - **快速函数替换 (Fast Function Replacement):**
     - 提供了更高效的函数替换方法 `Interceptor.replaceFast`.
     - 快速替换后的函数可以立即被调用和恢复。
     - 快速替换支持 `NativePointer` 类型的值。
     - 快速替换也能处理错误的指针。
     - 快速替换可以调用原始函数。
     - 提供了快速替换的性能测试。

**与逆向方法的关系及举例说明：**

Frida 本身就是一个动态 instrumentation 工具，其核心目的就是辅助逆向工程。这段代码测试的功能与逆向方法紧密相关：

* **Hooking (拦截):** `Interceptor.attach` 是 Frida 最核心的功能之一，允许在函数执行前后插入自定义代码，是动态分析的关键技术。例如，测试用例 `TESTCASE (argument_can_be_read)` 演示了如何在目标函数入口处读取参数，这在逆向分析中用于理解函数的输入。
* **Function Replacement (函数替换):** `Interceptor.replace` 允许用自定义的 JavaScript 函数替换原有的 native 函数，可以改变程序的行为，用于破解、功能修改等。例如，`TESTCASE (function_can_be_replaced)` 展示了如何替换一个函数并让其返回固定值。
* **参数和返回值的修改:**  在拦截点修改参数和返回值，可以影响函数的执行结果，模拟不同的运行状态，或者绕过某些检查。例如，`TESTCASE (argument_can_be_replaced)` 和 `TESTCASE (return_value_can_be_replaced)` 就展示了这种能力。
* **代码跟踪和分析:**  通过读取寄存器 (`this.context.*`) 和返回地址 (`this.returnAddress`)，逆向工程师可以更深入地了解程序的执行流程和状态。`TESTCASE (general_purpose_register_can_be_read)` 和 `TESTCASE (return_address_can_be_read)` 演示了这些功能。
* **异常和错误处理分析:**  读取和修改系统错误码 (`this.lastError` / `this.errno`) 可以帮助理解程序在特定情况下产生的错误，以及如何通过修改错误码来影响程序的行为。 `TESTCASE (system_error_can_be_read_from_interceptor_listener)` 和相关的测试用例展示了这一点。
* **控制程序流程:**  通过 `setTimeout`、`setInterval` 和 `setImmediate`，可以在目标进程中安排代码在未来的某个时刻执行，可以用于实现延时执行、周期性任务或者改变事件的执行顺序。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明：**

Frida 的工作原理涉及到对目标进程的内存操作和代码注入，因此与底层知识密切相关：

* **二进制底层:**
    * **内存地址操作:** `GUM_PTR_CONST` 代表目标函数的内存地址，`ptr(0x42)` 直接操作内存地址。理解内存地址、指针的概念是使用 Frida 的基础。
    * **汇编指令:**  `Interceptor.attach` 的本质是在目标函数的入口或出口插入跳转指令，执行 Frida 的 hook 代码。虽然这段代码没有直接操作汇编，但其功能是建立在对汇编指令的理解上的。
    * **寄存器:**  `this.context.*` 允许访问 CPU 寄存器，这是底层执行状态的关键信息。不同的架构（ARM, ARM64, x86 等）有不同的寄存器名称和用途。
* **Linux/Android 内核:**
    * **系统调用:**  `errno` 是 Linux 系统调用的错误码，Frida 能够访问和修改它，说明 Frida 能够感知并影响底层的系统调用行为。
    * **进程和线程:**  Frida 在进程内部运行 JavaScript 代码，并能够获取线程 ID (`this.threadId`)，说明它对进程和线程的概念有深入的理解。
    * **信号处理:**  `TESTCASE (crash_on_thread_holding_js_lock_should_not_deadlock)` 涉及到信号 (`SIGSEGV`) 处理，以及在发生崩溃时如何保证 Frida 的稳定性。
* **框架 (Android):**  虽然这段代码本身没有直接体现 Android 特有的框架知识，但 Frida 广泛应用于 Android 逆向，可以 hook Android Framework 层的 Java 方法，或者 Native 层库的函数。

**逻辑推理、假设输入与输出：**

让我们以 `TESTCASE (timeout_can_be_scheduled)` 为例：

* **假设输入:** Frida 脚本成功加载并执行了包含 `setTimeout(() => { send(1338); });` 的代码。
* **逻辑推理:** JavaScript 引擎会创建一个定时器，在指定的时间 (默认为 0ms，因为没有提供延迟参数) 后执行回调函数 `() => { send(1338); }`。回调函数会调用 `send("1338")`，Frida 会捕获这个消息。
* **预期输出:** 首先不会立即收到消息 (`EXPECT_NO_MESSAGES ()`)，等待一段时间 (`g_usleep (25000)`) 后，应该收到包含 "1338" 的消息 (`EXPECT_SEND_MESSAGE_WITH ("1338")`)。

再以 `TESTCASE (argument_can_be_read)` 为例：

* **假设输入:** Frida 脚本成功加载，并使用 `Interceptor.attach` hook 了 `target_function_int` 函数。`target_function_int` 被调用，并传入参数 `42` 和 `-42`。
* **逻辑推理:** 在 `onEnter` 回调中，`args[0].toInt32()` 会读取到 `target_function_int` 的第一个参数，并通过 `send()` 发送出去。
* **预期输出:** 当 `target_function_int(42)` 被调用时，会收到消息 "42" (`EXPECT_SEND_MESSAGE_WITH ("42")`)。当 `target_function_int(-42)` 被调用时，会收到消息 "-42" (`EXPECT_SEND_MESSAGE_WITH ("-42")`)。

**用户或编程常见的使用错误及举例说明：**

* **忘记 detach 监听器:** 如果用户在多次 hook 后忘记调用 `listener.detach()` 或 `Interceptor.detachAll()`，可能会导致性能问题，甚至意外的行为，因为每次调用都会触发多个监听器。 `TESTCASE (listener_can_be_detached)` 就是为了验证 detach 功能的正确性。
* **操作无效内存地址:**  如果用户尝试 hook 或替换一个不存在或不可访问的内存地址，会导致程序崩溃或 Frida 报错。 `TESTCASE (interceptor_should_handle_bad_pointers)` 模拟了这种情况，并验证了 Frida 的错误处理机制。
* **在不适当的时机修改返回值或参数:**  如果用户在 `onEnter` 中修改返回值，或者在 `onLeave` 之后尝试修改返回值，可能会导致未定义的行为。 `TESTCASE (return_value_can_be_replaced)` 中也测试了在 `onLeave` 之后通过 `recv` 回调尝试修改返回值的情况，并预期会报错。
* **类型错误:**  在 JavaScript 中操作 NativePointer 时，如果类型转换不当（例如，尝试将指针解释为整数但指针指向的是字符串），可能会导致错误。
* **并发问题:**  在多线程环境下使用 Frida，如果对共享资源的操作没有进行适当的同步，可能会导致数据竞争或其他并发问题。 `TESTCASE (interceptor_and_js_should_not_deadlock)` 试图在并发场景下测试 Frida 的稳定性。
* **在回调函数中执行耗时操作:**  如果在 Frida 的回调函数中执行过于耗时的操作，可能会阻塞目标进程的执行。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida JavaScript 脚本，例如，使用 `Interceptor.attach` 监控某个函数的调用，或者使用 `Interceptor.replace` 修改函数的行为。
2. **使用 Frida CLI 或 API 注入脚本:** 用户会使用 Frida 的命令行工具 (`frida`) 或编程接口 (Python, Node.js 等) 将该脚本注入到目标进程中。
3. **目标进程执行相关代码:**  一旦脚本注入，当目标进程执行到被 hook 或替换的函数时，Frida 的 JavaScript 代码就会被执行。
4. **观察输出或行为:** 用户会观察 Frida 脚本的输出 (通过 `send()`) 或者目标进程的行为，来验证脚本是否按预期工作。
5. **遇到问题或需要深入了解:** 如果用户发现脚本没有按预期工作，或者想要深入了解 Frida 的内部机制，可能会查看 Frida 的源代码，例如 `frida/subprojects/frida-gum/tests/gumjs/script.c`，以理解 Frida 功能的实现和测试方法，从而找到调试线索。
6. **分析测试用例:** 用户可以通过分析这些测试用例，了解特定 API 的使用方法、边界情况以及预期的行为，从而帮助他们调试自己的 Frida 脚本。例如，如果用户在使用 `setTimeout` 时遇到问题，可能会查看相关的测试用例，看是否遗漏了某些细节。

**总结第 7 部分的功能：**

总而言之，`frida/subprojects/frida-gum/tests/gumjs/script.c` 的第 7 部分代码主要集中测试了 Frida GumJS 脚本中**定时器**和**拦截器**这两大核心功能。它覆盖了定时器的创建、取消、立即执行和延迟执行，以及拦截器的参数和返回值读写、寄存器访问、系统错误码处理、调用上下文信息获取、监听器的管理和函数的替换等关键特性。这些测试用例旨在验证 Frida 提供的 JavaScript API 的正确性和健壮性，确保开发者能够可靠地使用这些功能进行动态 instrumentation 和逆向工程。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共11部分，请归纳一下它的功能

"""
MESSAGES ();

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1338");

  COMPILE_AND_LOAD_SCRIPT (
      "setTimeout(() => {"
      "  send(1227);"
      "});");
  g_usleep (10000);
  EXPECT_SEND_MESSAGE_WITH ("1227");
}

TESTCASE (timeout_can_be_cancelled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const timeout = setTimeout(() => {"
      "  send(1337);"
      "}, 20);"
      "clearTimeout(timeout);");
  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (interval_can_be_scheduled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setInterval(value => {"
      "  send(value);"
      "}, 20, 1337);");
  EXPECT_NO_MESSAGES ();

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1337");

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1337");
}

TESTCASE (interval_can_be_cancelled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "let count = 1;"
      "const interval = setInterval(() => {"
      "  send(count++);"
      "  if (count === 3)"
      "    clearInterval(interval);"
      "}, 20);");

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("1");

  g_usleep (25000);
  EXPECT_SEND_MESSAGE_WITH ("2");

  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (callback_can_be_scheduled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setImmediate(() => {"
      "  send(1337);"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (callback_can_be_scheduled_from_a_scheduled_callback)
{
  COMPILE_AND_LOAD_SCRIPT (
      "setImmediate(() => {"
      "  send(1337);"
      "  Script.nextTick(() => { send(1338); });"
      "  setImmediate(() => { send(1339); });"
      "});");
  EXPECT_SEND_MESSAGE_WITH ("1337");
  EXPECT_SEND_MESSAGE_WITH ("1338");
  EXPECT_SEND_MESSAGE_WITH ("1339");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (callback_can_be_cancelled)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const id = setImmediate(() => {"
      "  send(1337);"
      "});"
      "clearImmediate(id);");
  g_usleep (25000);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (callback_can_be_scheduled_on_next_tick)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Script.nextTick(send, 1337, [0x13, 0x37, 0x0a]);");
  EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA ("1337", "13 37 0a");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (timer_cancellation_apis_should_be_forgiving)
{
  COMPILE_AND_LOAD_SCRIPT (
      "clearTimeout(undefined);"
      "clearInterval(undefined);"
      "clearImmediate(undefined);");
  EXPECT_NO_MESSAGES ();
}

#ifndef HAVE_WINDOWS

TESTCASE (crash_on_thread_holding_js_lock_should_not_deadlock)
{
  struct sigaction sa;
  GThread * worker1, * worker2;
  GumInvokeTargetContext invoke_ctx;
  GumCrashExceptorContext crash_ctx;
  GumExceptor * exceptor;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  memset (&sa, 0, sizeof (sigaction));
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_NODEFER;
  sa.sa_sigaction = exit_on_sigsegv;
  sigaction (SIGSEGV, &sa, NULL);

  COMPILE_AND_LOAD_SCRIPT (
      "const strcmp = new NativeFunction("
      "    Module.getExportByName(null, 'strcmp'),"
      "    'int', ['pointer', 'pointer'],"
      "    {"
      "      scheduling: 'exclusive',"
      "      exceptions: 'propagate'"
      "    });"

      "Process.setExceptionHandler(() => {"
      "  console.log('never called');"
      "});"

      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    strcmp(ptr(341234213), ptr(3423423422));"
      "  }"
      "});",
      target_function_int);
  EXPECT_NO_MESSAGES ();

  invoke_ctx.script = fixture->script;
  invoke_ctx.repeat_duration = 1.0;
  invoke_ctx.started = 0;
  invoke_ctx.finished = 0;

  crash_ctx.called = FALSE;
  crash_ctx.backend = fixture->backend;

  exceptor = gum_exceptor_obtain ();
  gum_exceptor_add (exceptor, on_exceptor_called, &crash_ctx);

  worker1 = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &invoke_ctx);
  worker2 = g_thread_new ("script-test-worker-thread",
      invoke_target_function_int_worker, &invoke_ctx);

  while (invoke_ctx.started == 0)
    g_usleep (G_USEC_PER_SEC / 200);
  g_usleep (G_USEC_PER_SEC / 10);

  g_assert_true (crash_ctx.called);

  g_thread_join (worker1);
  g_thread_join (worker2);

  gum_exceptor_remove (exceptor, on_exceptor_called, &crash_ctx);
  g_object_unref (exceptor);
}

static void
exit_on_sigsegv (int sig,
                 siginfo_t * info,
                 void * context)
{
  exit (0);
}

static gboolean
on_exceptor_called (GumExceptionDetails * details,
                    gpointer user_data)
{
  GumCrashExceptorContext * ctx = user_data;

  ctx->called = TRUE;

#ifdef HAVE_DARWIN
  {
    GThread * worker = g_thread_new ("fake-crash-handler-thread",
        simulate_crash_handler, ctx);
    g_thread_join (worker);
  }
#endif

  return FALSE;
}

#ifdef HAVE_DARWIN

static gpointer
simulate_crash_handler (gpointer user_data)
{
  GumCrashExceptorContext * ctx = user_data;
  GumScriptBackend * backend = ctx->backend;

  gum_process_enumerate_threads (suspend_all_threads, backend);
  gum_process_enumerate_threads (resume_all_threads, backend);

  return NULL;
}

static gboolean
suspend_all_threads (const GumThreadDetails * details,
                     gpointer user_data)
{
#ifndef HAVE_WATCHOS
  GumScriptBackend * backend = user_data;

  if (details->id != gum_process_get_current_thread_id ())
  {
    gum_script_backend_with_lock_held (backend,
        (GumScriptBackendLockedFunc) thread_suspend,
        GSIZE_TO_POINTER (details->id));
  }
#endif

  return TRUE;
}

static gboolean
resume_all_threads (const GumThreadDetails * details,
                    gpointer user_data)
{
#ifndef HAVE_WATCHOS
  if (details->id != gum_process_get_current_thread_id ())
    thread_resume (details->id);
#endif

  return TRUE;
}

#endif /* HAVE_DARWIN */

#endif /* !HAVE_WINDOWS */

TESTCASE (argument_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send(args[0].toInt32());"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("42");

  target_function_int (-42);
  EXPECT_SEND_MESSAGE_WITH ("-42");
}

TESTCASE (argument_can_be_replaced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const replacementString = Memory.allocUtf8String('Hei');"
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    args[0] = replacementString;"
      "  }"
      "});", target_function_string);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpstr (target_function_string ("Hello"), ==, "Hei");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpstr (target_function_string ("Hello"), ==, "Hei");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (return_value_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave(retval) {"
      "    send(retval.toInt32());"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("315");
}

TESTCASE (return_value_can_be_replaced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave(retval) {"
      "    retval.replace(1337);"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave(retval) {"
      "    retval.replace({ handle: ptr(1338) });"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1338);
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "let savedRetval = null;"
      "Interceptor.attach(" GUM_PTR_CONST  ", {"
      "  onLeave(retval) {"
      "    savedRetval = retval;"
      "  }"
      "});"
      "recv('try-replace', () => {"
      "  savedRetval.replace(1337);"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_NO_MESSAGES ();
  POST_MESSAGE ("{\"type\":\"try-replace\"}");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid operation");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (return_address_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter() {"
      "    send(this.returnAddress instanceof NativePointer);"
      "    this.onEnterReturnAddress = this.returnAddress;"
      "  },"
      "  onLeave() {"
      "    send(this.returnAddress.equals(this.onEnterReturnAddress));"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (general_purpose_register_can_be_read)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave() {"
      "    send(this.context." GUM_RETURN_VALUE_REGISTER_NAME ".toInt32());"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("1890");
}

TESTCASE (general_purpose_register_can_be_written)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onLeave() {"
      "    this.context." GUM_RETURN_VALUE_REGISTER_NAME " = ptr(1337);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (42), ==, 1337);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (vector_register_can_be_read)
{
#if (defined (HAVE_ARM) && defined (__ARM_PCS_VFP)) || defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter() {"
      "    const v = new Float64Array(this.context.q0);"
      "    send(v[0]);"
      "  }"
      "});", target_function_double);

  EXPECT_NO_MESSAGES ();
  target_function_double (42.0);
  EXPECT_SEND_MESSAGE_WITH ("42");
#else
  g_print ("<skipping, missing code for current architecture or ABI> ");
#endif
}

TESTCASE (double_register_can_be_read)
{
#if (defined (HAVE_ARM) && defined (__ARM_PCS_VFP)) || defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter() {"
      "    send(this.context.d0);"
      "  }"
      "});", target_function_double);

  EXPECT_NO_MESSAGES ();
  target_function_double (42.0);
  EXPECT_SEND_MESSAGE_WITH ("42");
#else
  g_print ("<skipping, missing code for current architecture or ABI> ");
#endif
}

TESTCASE (float_register_can_be_read)
{
#if (defined (HAVE_ARM) && defined (__ARM_PCS_VFP)) || defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter() {"
      "    send(this.context.s0);"
      "  }"
      "});", target_function_float);

  EXPECT_NO_MESSAGES ();
  target_function_float (42.0f);
  EXPECT_SEND_MESSAGE_WITH ("42");
#else
  g_print ("<skipping, missing code for current architecture or ABI> ");
#endif
}

TESTCASE (status_register_can_be_read)
{
#if defined (HAVE_ARM)
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter() {"
      "    send(typeof this.context.cpsr);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
#elif defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter() {"
      "    send(typeof this.context.nzcv);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (system_error_can_be_read_from_interceptor_listener)
{
#ifdef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(retval) {"
      "    send(this.lastError);"
      "  }"
      "});", target_function_int);

  SetLastError (13);
  target_function_int (7);
  SetLastError (37);
  target_function_int (7);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(retval) {"
      "    send(this.errno);"
      "  }"
      "});", target_function_int);

  errno = 13;
  target_function_int (7);
  errno = 37;
  target_function_int (7);
#endif
  EXPECT_SEND_MESSAGE_WITH ("13");
  EXPECT_SEND_MESSAGE_WITH ("37");
}

TESTCASE (system_error_can_be_read_from_replacement_function)
{
  GumInterceptor * interceptor;

  interceptor = gum_interceptor_obtain ();

  /* Replacement should be used regardless: */
  gum_interceptor_ignore_current_thread (interceptor);

#ifdef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  send(this.lastError);"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  SetLastError (13);
  target_function_int (7);
  SetLastError (37);
  target_function_int (7);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  send(this.errno);"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  errno = 13;
  target_function_int (7);
  errno = 37;
  target_function_int (7);
#endif
  EXPECT_SEND_MESSAGE_WITH ("13");
  EXPECT_SEND_MESSAGE_WITH ("37");

  gum_interceptor_unignore_current_thread (interceptor);

  g_object_unref (interceptor);
}

TESTCASE (system_error_can_be_replaced_from_interceptor_listener)
{
#ifdef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(retval) {"
      "    this.lastError = 1337;"
      "  }"
      "});", target_function_int);

  SetLastError (42);
  target_function_int (7);
  g_assert_cmpint (GetLastError (), ==, 1337);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(retval) {"
      "    this.errno = 1337;"
      "  }"
      "});", target_function_int);

  errno = 42;
  target_function_int (7);
  g_assert_cmpint (errno, ==, 1337);
#endif
}

TESTCASE (system_error_can_be_replaced_from_replacement_function)
{
#ifdef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  this.lastError = 1337;"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  SetLastError (42);
  target_function_int (7);
  g_assert_cmpint (GetLastError (), ==, 1337);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  this.errno = 1337;"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  errno = 42;
  target_function_int (7);
  g_assert_cmpint (errno, ==, 1337);
#endif
}

TESTCASE (system_error_unaffected_by_replacement_if_set_to_original_value)
{
#ifdef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  this.lastError = 1337;"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  SetLastError (1337);
  target_function_int (7);
  g_assert_cmpint (GetLastError (), ==, 1337);
#else
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  this.errno = 1337;"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

  errno = 1337;
  target_function_int (7);
  g_assert_cmpint (errno, ==, 1337);
#endif
}

TESTCASE (system_error_unaffected_by_replacement_if_untouched)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(function (arg) {"
      "  return 0;"
      "}, 'int', ['int']));", target_function_int);

#ifdef HAVE_WINDOWS
  SetLastError (1337);
  target_function_int (7);
  g_assert_cmpint (GetLastError (), ==, 1337);
#else
  errno = 1337;
  target_function_int (7);
  g_assert_cmpint (errno, ==, 1337);
#endif
}

TESTCASE (invocations_are_bound_on_tls_object)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send(this.value || null);"
      "    this.value = args[0].toInt32();"
      "  },"
      "  onLeave(retval) {"
      "    send(this.value || null);"
      "  }"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("7");
  target_function_int (11);
  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("11");
}

TESTCASE (invocations_provide_thread_id)
{
  guint i;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send(this.threadId);"
      "  },"
      "  onLeave(retval) {"
      "    send(this.threadId);"
      "  }"
      "});",
      target_function_int);
  EXPECT_NO_MESSAGES ();

  target_function_int (7);
  for (i = 0; i != 2; i++)
  {
    TestScriptMessageItem * item;
    gint id;

    item = test_script_fixture_pop_message (fixture);
    id = 0;
    sscanf (item->message, "{\"type\":\"send\",\"payload\":%d}", &id);
    g_assert_cmpuint (id, !=, 0);
    test_script_message_item_free (item);
    g_assert_cmpint (id, ==, gum_process_get_current_thread_id ());
  }
}

TESTCASE (invocations_provide_call_depth)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send('>a' + this.depth);"
      "  },"
      "  onLeave(retval) {"
      "    send('<a' + this.depth);"
      "  }"
      "});"
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send('>b' + this.depth);"
      "  },"
      "  onLeave(retval) {"
      "    send('<b' + this.depth);"
      "  }"
      "});"
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send('>c' + this.depth);"
      "  },"
      "  onLeave(retval) {"
      "    send('<c' + this.depth);"
      "  }"
      "});",
      target_function_nested_a,
      target_function_nested_b,
      target_function_nested_c);

  EXPECT_NO_MESSAGES ();
  target_function_nested_a (7);
  EXPECT_SEND_MESSAGE_WITH ("\">a0\"");
  EXPECT_SEND_MESSAGE_WITH ("\">b1\"");
  EXPECT_SEND_MESSAGE_WITH ("\">c2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"<c2\"");
  EXPECT_SEND_MESSAGE_WITH ("\"<b1\"");
  EXPECT_SEND_MESSAGE_WITH ("\"<a0\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (invocations_provide_context_for_backtrace)
{
  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  COMPILE_AND_LOAD_SCRIPT (
      "const mode = '%s';"
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send(Thread.backtrace(this.context, Backtracer.ACCURATE)"
      "        .length > 0);"
      "  },"
      "  onLeave(retval) {"
      "    if (mode === 'slow')"
      "      send(Thread.backtrace(this.context, Backtracer.FUZZY).length > 0);"
      "  }"
      "});",
      g_test_slow () ? "slow" : "fast",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  if (g_test_slow ())
    EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (invocations_provide_context_serializable_to_json)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send(JSON.stringify(this.context) !== \"{}\");"
      "  },"
      "  onLeave(retval) {"
      "    send(JSON.stringify(this.context) !== \"{}\");"
      "  }"
      "});",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (listener_can_be_detached)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const firstListener = Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send(1);"
      "    firstListener.detach();"
      "  },"
      "  onLeave(retval) {"
      "    send(2);"
      "  }"
      "});"
      ""
      "const secondListener = Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send(3);"
      "  },"
      "  onLeave(retval) {"
      "    send(4);"
      "    secondListener.detach();"
      "  }"
      "});",
      target_function_int, target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("4");
  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (listener_can_be_detached_by_destruction_mid_call)
{
  const guint repeats = 10;
  guint i;
  TestTrigger trigger;

  g_mutex_init (&trigger.mutex);
  g_cond_init (&trigger.cond);

  for (i = 0; i != repeats; i++)
  {
    GThread * invoker_thread;

    g_mutex_lock (&trigger.mutex);
    trigger.ready = FALSE;
    trigger.fired = FALSE;
    g_mutex_unlock (&trigger.mutex);

    COMPILE_AND_LOAD_SCRIPT (
        "Interceptor.attach(" GUM_PTR_CONST ", {"
        "  onEnter(args) {"
        "  },"
        "  onLeave(retval) {"
        "  }"
        "});",
        target_function_trigger);

    invoker_thread = g_thread_new ("script-invoker-thread",
        invoke_target_function_trigger, &trigger);

    g_mutex_lock (&trigger.mutex);
    while (!trigger.ready)
      g_cond_wait (&trigger.cond, &trigger.mutex);
    g_mutex_unlock (&trigger.mutex);

    g_mutex_lock (&trigger.mutex);
    trigger.fired = TRUE;
    g_cond_signal (&trigger.cond);
    g_mutex_unlock (&trigger.mutex);

    UNLOAD_SCRIPT ();

    g_thread_join (invoker_thread);
  }

  g_cond_clear (&trigger.cond);
  g_mutex_clear (&trigger.mutex);
}

static gpointer
invoke_target_function_trigger (gpointer data)
{
  TestTrigger * trigger = (TestTrigger *) data;

  target_function_trigger (trigger);

  return NULL;
}

TESTCASE (all_listeners_can_be_detached)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", {"
      "  onEnter(args) {"
      "    send(args[0].toInt32());"
      "  }"
      "});"
      "Interceptor.detachAll();",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (function_can_be_replaced)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ","
      "    new NativeCallback(arg => {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_NO_MESSAGES ();

  gum_script_unload_sync (fixture->script, NULL);
  target_function_int (1);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (function_can_be_replaced_and_called_immediately)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const address = " GUM_PTR_CONST ";"
      "Interceptor.replace(address,"
      "    new NativeCallback(arg => {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));"
      "const f = new NativeFunction(address, 'int', ['int'],"
      "    { scheduling: 'exclusive' });"
      "f(7);"
      "Interceptor.flush();"
      "f(8);",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (function_can_be_reverted)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback(arg => {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));"
      "Interceptor.revert(" GUM_PTR_CONST ");",
      target_function_int, target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (replaced_function_should_have_invocation_context)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", new NativeCallback(function () {"
      "  send(this.returnAddress instanceof NativePointer &&"
      "      !this.context.pc.isNull());"
      "  return 0;"
      "}, 'int', ['int']));",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (instructions_can_be_probed)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(" GUM_PTR_CONST ", function () {"
      "  send(!!this.context);"
      "});", target_function_int);

  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (interceptor_should_support_native_pointer_values)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const value = { handle: " GUM_PTR_CONST " };"
      "Interceptor.attach(value, {"
      "  onEnter(args) {"
      "    send(args[0].toInt32());"
      "  }"
      "});", target_function_int);
  EXPECT_NO_MESSAGES ();
  target_function_int (42);
  EXPECT_SEND_MESSAGE_WITH ("42");

  COMPILE_AND_LOAD_SCRIPT (
      "const value = { handle: " GUM_PTR_CONST " };"
      "Interceptor.replace(value,"
      "    new NativeCallback(arg => 1337, 'int', ['int']));",
      target_function_int);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (interceptor_should_handle_bad_pointers)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.attach(ptr(0x42), {"
      "  onEnter(args) {"
      "  }"
      "});");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x42");

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(ptr(0x42),"
      "    new NativeCallback(() => {}, 'void', []));");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x42");
}

TESTCASE (interceptor_should_refuse_to_attach_without_any_callbacks)
{
  COMPILE_AND_LOAD_SCRIPT ("Interceptor.attach(" GUM_PTR_CONST ", {});",
      target_function_int);
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: expected at least one callback");
}

#ifdef HAVE_DARWIN

TESTCASE (interceptor_and_js_should_not_deadlock)
{
  GThread * worker_thread;
  int state = 0;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  worker_thread = g_thread_new ("script-test-worker-thread",
      interceptor_attacher_worker, &state);
  while (state == 0)
    g_usleep (G_USEC_PER_SEC / 200);

  COMPILE_AND_LOAD_SCRIPT (
      "const iterations = 100;"
      "send('Start loop');"
      "const threadSuspend = new NativeFunction("
      "  Module.getExportByName(null, 'thread_suspend'),"
      "  'int', ['int'], { scheduling: 'exclusive' }"
      ");"
      "Interceptor.replace(threadSuspend, new NativeCallback((threadId) => {"
      "  return threadSuspend(threadId);"
      "}, 'int', ['int']));"
      "Interceptor.flush();"
      "setTimeout(() => {"
      "  for (let i = 0; i !== iterations; i++)"
      "    Thread.sleep(0.1);"
      "  Interceptor.revert(threadSuspend);"
      "  send('The end');"
      "}, 0);");

  EXPECT_SEND_MESSAGE_WITH ("\"Start loop\"");

  g_usleep (G_USEC_PER_SEC / 25);
  g_thread_join (worker_thread);
  g_assert_cmpint (state, ==, 2);
  EXPECT_SEND_MESSAGE_WITH ("\"The end\"");
  EXPECT_NO_MESSAGES ();
}

static gpointer
interceptor_attacher_worker (gpointer data)
{
  int * state = data;
  guint i;
  GumInterceptor * interceptor;
  GumInvocationListener * listener;
  GumAttachReturn result;

  *state = 1;

  interceptor = gum_interceptor_obtain ();
  listener = gum_make_call_listener (empty_invocation_callback,
      empty_invocation_callback, NULL, NULL);

  for (i = 0; i != 300; i++)
  {
    result = gum_interceptor_attach (interceptor, target_function_int,
        GUM_INVOCATION_LISTENER (listener), NULL);
    if (result == GUM_ATTACH_OK)
    {
      g_usleep (G_USEC_PER_SEC / 25);
      gum_interceptor_detach (interceptor, GUM_INVOCATION_LISTENER (listener));
    }
  }

  g_object_unref (listener);

  *state = 2;

  return NULL;
}

static void
empty_invocation_callback (GumInvocationContext * context,
                           gpointer user_data)
{
}

#endif

TESTCASE (function_can_be_replaced_fast)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replaceFast(" GUM_PTR_CONST ", new NativeCallback(arg => {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));",
      target_function_int);

  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  EXPECT_SEND_MESSAGE_WITH ("7");
  EXPECT_NO_MESSAGES ();

  gum_script_unload_sync (fixture->script, NULL);
  target_function_int (1);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (function_can_be_replaced_fast_and_called_immediately)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const address = " GUM_PTR_CONST ";"
      "Interceptor.replaceFast(address, new NativeCallback(arg => {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));"
      "const f = new NativeFunction(address, 'int', ['int'],"
      "    { scheduling: 'exclusive' });"
      "f(7);"
      "Interceptor.flush();"
      "f(8);",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (function_can_be_reverted_fast)
{
  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replaceFast(" GUM_PTR_CONST ", new NativeCallback(arg => {"
      "  send(arg);"
      "  return 1337;"
      "}, 'int', ['int']));"
      "Interceptor.revert(" GUM_PTR_CONST ");",
      target_function_int,
      target_function_int);
  EXPECT_NO_MESSAGES ();
  target_function_int (7);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (interceptor_should_support_native_pointer_values_fast)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const value = { handle: " GUM_PTR_CONST " };"
      "Interceptor.replaceFast(value,"
      "    new NativeCallback(arg => 1337, 'int', ['int']));",
      target_function_int);
  EXPECT_NO_MESSAGES ();
  g_assert_cmpint (target_function_int (7), ==, 1337);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (interceptor_should_handle_bad_pointers_fast)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replaceFast(ptr(0x42),"
      "    new NativeCallback(() => {}, 'void', []));");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: access violation accessing 0x42");
}

TESTCASE (function_can_be_replaced_and_call_original_fast)
{
  int ret = target_function_int (1);

  COMPILE_AND_LOAD_SCRIPT (
      "let func;"
      "const addr = Interceptor.replaceFast(" GUM_PTR_CONST ","
      "    new NativeCallback(arg => func(arg) + 1, 'int', ['int']));"
      "func = new NativeFunction(addr, 'int', ['int']);",
      target_function_int);
  EXPECT_NO_MESSAGES ();

  g_assert_cmpint (target_function_int (1), ==, ret + 1);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (function_can_be_replaced_fast_performance)
{
  GTimer * timer;
  gdouble duration_default, duration_fast;
  guint i;

  target_function_original = NULL;

  timer = g_timer_new ();

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replace(" GUM_PTR_CONST ", " GUM_PTR_CONST ");",
      target_function_int,
      target_function_int_replacement);

  g_timer_reset (timer);
  for (i = 0; i != 1000000; i++)
    g_assert_cmpint (target_function_int (7), ==, 1337);
  duration_default = g_timer_elapsed (timer, NULL);

  gum_script_unload_sync (fixture->script, NULL);

  COMPILE_AND_LOAD_SCRIPT (
      "Interceptor.replaceFast(" GUM_PTR_CONST ", " GUM_PTR_CONST ");",
      target_function_int,
      target_function_int_replacement);

  g_timer_reset (timer);
  for (i = 0; i != 1000000; i++)
    g_assert_cmpint (target_function_int (7), ==, 1337);
  duration_fast = g_timer_elapsed (timer, NULL);

  g_timer_destroy (timer);

  g_print ("<duration_fast=%f duration_default=%f ratio=%f> ",
      duration_fast,
      duration_default,
      duration_fast / duration_default);
}

TESTCASE (function_can_be_replaced_and_call_original_fast_performance)
{
  GTimer * timer;
  gdouble duration_default, duration_fast;
  guint i;

  target_function_original = NULL;

  timer = g_timer_new ();

  COMPILE_AND_LOAD_SCRIPT (
      "const origPtr = ptr(" GUM_PTR_CONST ");"
      "const orig = ptr(" GUM_PTR_CONST ");"
      "Interceptor.replace(orig, " GUM_PTR_CONST ");"
      "origPtr.writePointer(orig);",
      &target_function_original,
      target_function_int,
      target_function_int_replacement);

  g_timer_reset (timer);
  for (i = 0; i != 1000000; i++)
    g_assert_cmpint (target_function_int (7), ==, 1652);
  duration_default = g_timer_elapsed (timer, NULL);

  gu
"""


```