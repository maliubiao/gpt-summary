Response:
Let's break down the thought process for analyzing the C++ Frida code snippet.

**1. Initial Understanding and Goal:**

The primary goal is to understand the functionality of the provided C++ code, which is part of Frida. The prompt specifically asks about features, relationships to reverse engineering, interaction with the OS/kernel, logic, potential errors, and how a user might reach this code.

**2. High-Level Overview (Skimming the Code):**

* **Includes:**  `gumv8thread.h`, `gumv8macros.h`. This immediately signals interaction with V8 (JavaScript engine) within the Frida framework.
* **Macros:** `GUMJS_MODULE_NAME Thread`, `GUMJS_THREAD_ID`. These suggest this code defines a JavaScript module named "Thread" and provides a way to extract a thread ID.
* **Function Declarations:**  `gumjs_thread_backtrace`, `gumjs_thread_sleep`, `gumjs_thread_set_hardware_breakpoint`, etc. These are likely the core functionalities exposed to JavaScript.
* **Function Tables:** `gumjs_thread_module_functions`, `gumjs_thread_functions`. These seem to map C++ functions to JavaScript names.
* **Initialization (`_gum_v8_thread_init`):**  Looks like it sets up the "Thread" module in the V8 environment.
* **Hardware Breakpoints/Watchpoints:**  Several functions deal with setting and unsetting hardware breakpoints and watchpoints, a strong indicator of debugging/instrumentation capabilities.

**3. Detailed Analysis of Key Sections:**

* **`gumjs_thread_backtrace`:**
    * Takes optional arguments: `cpu_context`, `backtrace_type` (Accurate/Fuzzy), and `limit`.
    * Uses `GumBacktracer` to generate a stack trace.
    * Handles "Accurate" and "Fuzzy" backtrace types, hinting at different levels of detail or reliability.
    * Returns an array of memory addresses.
    * **Reverse Engineering Relevance:** Essential for understanding the execution flow of a program.

* **`gumjs_thread_sleep`:**
    * Takes a `delay` in seconds.
    * Uses `g_usleep` to pause execution.
    * **Reverse Engineering Relevance:** Can be used to introduce delays in a target application's execution for analysis.

* **`gumjs_thread_set_hardware_breakpoint` and `gumjs_thread_unset_hardware_breakpoint`:**
    * Take `thread_id`, `breakpoint_id`, and `address`.
    * Interact with the underlying system to set/unset hardware breakpoints.
    * **Reverse Engineering Relevance:**  Powerful for pausing execution when a specific memory location is accessed or executed. Helps in analyzing specific code paths.

* **`gumjs_thread_set_hardware_watchpoint` and `gumjs_thread_unset_hardware_watchpoint`:**
    * Similar to breakpoints but trigger based on memory access (read/write).
    * Take `thread_id`, `watchpoint_id`, `address`, `size`, and `conditions` ('r' for read, 'w' for write).
    * **Reverse Engineering Relevance:** Crucial for understanding how data is being manipulated in memory.

* **`_gum_v8_thread_new`:**
    * Creates a JavaScript object representing a thread.
    * Populates it with thread information like `id`, `name`, `state`, and `context`.
    * **Reverse Engineering Relevance:** Provides access to thread-specific information for analysis.

**4. Identifying Connections to OS/Kernel Concepts:**

* **Hardware Breakpoints/Watchpoints:** These are inherently low-level features provided by the CPU and managed by the operating system kernel. Frida acts as an intermediary to control them.
* **Thread ID:** A fundamental concept in operating systems for managing concurrent execution.
* **CPU Context:** Represents the state of the CPU (registers, program counter, etc.) at a specific point in time. Accessing this requires interacting with OS-level mechanisms.
* **`g_usleep`:** A standard library function that ultimately makes a system call to the kernel to pause the current thread.

**5. Logic and Assumptions:**

* **Backtrace Types:** The "Accurate" vs. "Fuzzy" distinction suggests different underlying implementation strategies for stack unwinding, potentially trading accuracy for performance or availability on certain platforms.
* **Hardware Breakpoint/Watchpoint Limits:** The code doesn't explicitly show handling limits on the number of hardware breakpoints/watchpoints, but such limits exist at the hardware level, and the underlying `gum` library likely handles these.

**6. User Errors:**

* **Invalid Backtrace Type:** Passing something other than `Backtracer.ACCURATE` or `Backtracer.FUZZY`.
* **Invalid Watchpoint Conditions:**  Using characters other than 'r' or 'w' or providing an empty string.
* **Incorrect Argument Types:** Providing the wrong data types to the functions (e.g., a string instead of a number for `breakpoint_id`).

**7. User Journey/Debugging Clues:**

* A user starts by writing a Frida script in JavaScript.
* They might use the `Thread` module to:
    * Get a stack trace of a specific thread.
    * Pause a thread's execution.
    * Set hardware breakpoints or watchpoints to inspect program behavior at specific locations or memory accesses.
* When these JavaScript functions are called, the Frida engine bridges the call to the corresponding C++ functions in `gumv8thread.cpp`.
* Errors in the C++ code or the underlying `gum` library might lead to exceptions or crashes, providing debugging information.

**8. Structuring the Answer:**

Organize the findings logically based on the prompt's categories: Functionality, Reverse Engineering, OS/Kernel, Logic, Errors, and User Journey. Use clear and concise language, and provide concrete examples where possible.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the V8 aspects. Realizing the core function is system interaction (breakpoints, backtraces) shifts the focus.
* I might need to revisit the `gum` library documentation (if available) to understand the implementation details of the backtracer and hardware breakpoint/watchpoint handling.
* The prompt asks for *examples*. Ensuring each point is illustrated with a relevant example is crucial for a complete answer.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumv8thread.cpp` 这个文件，它是 Frida 动态 instrumentation 工具的一部分。

**功能列举:**

该文件定义了 Frida 中用于操作和检查目标进程线程的 JavaScript API，具体功能包括：

1. **获取线程回溯 (Backtrace):**
   - `gumjs_thread_backtrace`: 允许获取目标进程中指定线程的函数调用堆栈信息。可以选择精确回溯 (`ACCURATE`) 或模糊回溯 (`FUZZY`)。

2. **线程休眠 (Sleep):**
   - `gumjs_thread_sleep`: 允许让当前 Frida Agent 运行的线程休眠指定的时间。

3. **硬件断点 (Hardware Breakpoint) 操作:**
   - `gumjs_thread_set_hardware_breakpoint`: 在目标进程的指定线程上设置硬件断点，当线程执行到特定地址时会暂停。
   - `gumjs_thread_unset_hardware_breakpoint`: 移除目标进程指定线程上已设置的硬件断点。

4. **硬件观察点 (Hardware Watchpoint) 操作:**
   - `gumjs_thread_set_hardware_watchpoint`: 在目标进程的指定线程上设置硬件观察点，当线程访问（读或写）特定内存地址时会暂停。
   - `gumjs_thread_unset_hardware_watchpoint`: 移除目标进程指定线程上已设置的硬件观察点。

5. **线程对象创建和属性设置:**
   - `_gum_v8_thread_init`: 初始化 `Thread` 模块，创建 V8 类模板。
   - `_gum_v8_thread_realize`:  在 V8 上下文中实现 `Backtracer` 枚举值。
   - `_gum_v8_thread_new`:  创建表示目标进程线程的 JavaScript 对象，并设置其属性（如 id, name, state, context）。

**与逆向方法的关系及举例说明:**

该文件提供的功能与逆向工程密切相关，是 Frida 作为动态分析工具的核心能力体现：

1. **代码执行流程分析 (Backtrace):**
   - **例子:** 逆向工程师怀疑某个函数调用导致了崩溃。可以使用 `Thread.backtrace()` 获取崩溃时线程的调用堆栈，从而追踪到问题发生的具体代码路径。
   - **Frida 代码:**
     ```javascript
     // 假设要分析的线程 ID 为 1234
     const threadId = 1234;
     const backtrace = Thread.get(threadId).backtrace();
     console.log(backtrace);
     ```

2. **程序行为监控 (Hardware Breakpoint/Watchpoint):**
   - **例子 (Breakpoint):**  逆向工程师想知道某个关键函数何时被调用。可以在该函数的入口地址设置硬件断点，当程序执行到那里时 Frida 会中断程序，允许工程师检查当时的寄存器状态和内存。
   - **Frida 代码:**
     ```javascript
     const threadId = Process.getCurrentThreadId(); // 获取当前线程 ID
     const targetAddress = ptr("0x12345678"); // 目标函数地址
     Thread.get(threadId).setHardwareBreakpoint(0, targetAddress); // 设置断点，ID 为 0

     // ... (程序会暂停在断点处)

     Thread.get(threadId).unsetHardwareBreakpoint(0); // 移除断点
     ```
   - **例子 (Watchpoint):** 逆向工程师想监控某个全局变量何时被修改。可以在该变量的内存地址设置硬件观察点。
   - **Frida 代码:**
     ```javascript
     const threadId = Process.getCurrentThreadId();
     const targetAddress = ptr("0x98765432"); // 目标变量地址
     const size = 4; // 假设是 4 字节的 int
     Thread.get(threadId).setHardwareWatchpoint(0, targetAddress, size, 'w'); // 监控写入

     // ... (程序在写入该变量时会暂停)

     Thread.get(threadId).unsetHardwareWatchpoint(0);
     ```

3. **动态修改程序行为 (Sleep):**
   - **例子:** 逆向工程师发现程序在快速执行某个关键操作，难以观察中间状态。可以使用 `Thread.sleep()` 在关键操作前后插入短暂的暂停，以便更仔细地分析。
   - **Frida 代码:**
     ```javascript
     console.log("Before critical operation");
     Thread.sleep(1); // 休眠 1 秒
     // ... (执行关键操作的代码)
     console.log("After critical operation");
     ```

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

该文件中的功能深深依赖于底层的操作系统和硬件特性：

1. **硬件断点和观察点:**
   - **二进制底层:** 硬件断点和观察点是 CPU 提供的调试功能，通过设置特定的 CPU 寄存器 (如调试寄存器 DR0-DR7) 实现。Frida 需要与操作系统内核交互来设置这些寄存器。
   - **Linux/Android 内核:**  在 Linux 和 Android 上，内核提供了 `ptrace` 系统调用等机制，允许调试器（如 Frida）控制目标进程的执行，包括设置和管理硬件断点/观察点。Frida 的 `gum` 库会利用这些内核接口。
   - **举例:** `gum_thread_set_hardware_breakpoint` 函数内部会调用 `ptrace` 或类似的平台相关的 API 来设置硬件断点。这涉及到操作底层的寄存器和内存管理。

2. **线程回溯 (Backtrace):**
   - **二进制底层:**  回溯的实现依赖于程序的调用栈结构，通常包括栈帧指针 (frame pointer) 和返回地址。
   - **Linux/Android 内核:**  内核可能提供辅助函数或数据结构来帮助构建回溯信息，尤其是在处理信号或异常时。`gum_backtracer_generate` 函数会利用这些信息。不同的架构（如 ARM, x86）可能有不同的回溯机制。
   - **Android 框架:** 在 Android 上，回溯可能需要考虑 ART (Android Runtime) 的调用栈结构。
   - **举例:**  "精确回溯" 尝试尽可能准确地还原调用栈，可能需要读取目标进程的内存来查找栈帧信息。 "模糊回溯" 可能使用一些启发式方法，速度更快但可能不够精确。

3. **线程 ID 和上下文:**
   - **Linux/Android 内核:** 线程 ID 是操作系统内核分配的，用于标识不同的执行流。线程上下文包含了线程的寄存器状态、栈指针等关键信息。
   - **举例:** `GumThreadId` 类型代表线程 ID，而 `GumCpuContext` 结构体则封装了 CPU 寄存器的状态。Frida 需要通过操作系统 API 获取这些信息。

**逻辑推理、假设输入与输出:**

1. **`gumjs_thread_backtrace` 的逻辑:**
   - **假设输入:**  `threadId` (目标线程 ID), `backtraceType` (可以是 `Backtracer.ACCURATE` 或 `Backtracer.FUZZY`), `limit` (可选，限制回溯的栈帧数量)。
   - **逻辑:**
     - 根据 `backtraceType` 选择使用精确的或模糊的回溯器 (`gum_backtracer_make_accurate` 或 `gum_backtracer_make_fuzzy`)。
     - 调用回溯器的生成函数 (`gum_backtracer_generate_with_limit` 或 `gum_backtracer_generate`)，传入目标线程的 CPU 上下文。
     - 将返回的地址数组转换为 JavaScript 的 `Array` 对象。
   - **假设输出:** 一个 JavaScript 数组，包含返回地址的 `NativePointer` 对象，表示函数调用链。

2. **`gumjs_thread_set_hardware_breakpoint` 的逻辑:**
   - **假设输入:** `threadId` (目标线程 ID), `breakpointId` (断点 ID，用于标识和移除断点), `address` (断点地址)。
   - **逻辑:**
     - 调用底层的 `gum_thread_set_hardware_breakpoint` 函数，将断点信息传递给 Frida 的核心 `gum` 库。
     - `gum` 库会与操作系统交互来设置硬件断点。
   - **假设输出:**  如果设置成功，则无明显输出；如果失败，可能抛出 JavaScript 异常。

**用户或编程常见的使用错误及举例说明:**

1. **`gumjs_thread_backtrace`:**
   - **错误:**  传递了无效的 `backtraceType` 字符串。
   - **例子:** `Thread.get(1234).backtrace("INVALID_TYPE");`  会抛出 "invalid backtracer value" 错误。
   - **错误:**  尝试在不支持精确回溯的平台上使用 `Backtracer.ACCURATE`。
   - **例子:** 在某些嵌入式系统上，可能会抛出 "backtracer not yet available for this platform; please try Thread.backtrace(context, Backtracer.FUZZY)" 错误。

2. **`gumjs_thread_set_hardware_breakpoint` / `gumjs_thread_set_hardware_watchpoint`:**
   - **错误:**  使用了超出硬件限制的断点或观察点数量。大多数 CPU 只有有限数量的硬件调试寄存器。
   - **例子:**  连续设置超过 CPU 支持数量的硬件断点可能会导致设置失败或未定义的行为。
   - **错误:**  传递了无效的内存地址。
   - **例子:**  `Thread.get(1234).setHardwareBreakpoint(0, ptr("0xINVALID"));` 可能导致错误。
   - **错误 (Watchpoint):**  使用了无效的观察条件字符串。
   - **例子:** `Thread.get(1234).setHardwareWatchpoint(0, ptr("0x1000"), 4, "x");` 会抛出 "expected a string specifying watch conditions, e.g. 'rw'" 错误。
   - **错误:**  在没有权限的情况下尝试设置硬件断点/观察点。

3. **`gumjs_thread_sleep`:**
   - **错误:**  传递了负数的休眠时间。虽然代码中进行了检查，但用户可能会误用。
   - **例子:** `Thread.sleep(-1);`  不会抛出错误，但不会产生预期的休眠效果。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:** 用户首先会编写一个 JavaScript 脚本，使用 Frida 提供的 API 来进行动态分析。例如，他们可能会使用 `Thread.list()` 获取进程中的线程列表，然后选择一个线程进行操作。
   ```javascript
   // 获取所有线程
   const threads = Process.enumerateThreads();
   console.log("Threads:");
   threads.forEach(thread => {
     console.log(`  ID: ${thread.id}, State: ${thread.state}`);
   });

   // 选择第一个线程
   if (threads.length > 0) {
     const firstThread = threads[0];
     console.log(`\nAnalyzing thread ${firstThread.id}`);

     // 获取该线程的回溯
     const backtrace = firstThread.backtrace();
     console.log("\nBacktrace:");
     console.log(backtrace.join("\n"));

     // 在该线程上设置硬件断点
     const breakpointAddress = Module.findBaseAddress("libc.so").add(0x1234);
     firstThread.setHardwareBreakpoint(0, breakpointAddress);
     console.log(`\nHardware breakpoint set at ${breakpointAddress}`);
   }
   ```

2. **运行 Frida 脚本:**  用户使用 Frida 命令行工具或 API 将该脚本注入到目标进程中。
   ```bash
   frida -p <进程ID> -l your_script.js
   ```

3. **Frida 引擎处理:**  Frida 引擎 (使用 GumJS) 会解析用户的 JavaScript 代码，并识别对 `Thread` 模块的调用，例如 `Thread.get()`, `thread.backtrace()`, `thread.setHardwareBreakpoint()` 等。

4. **调用 C++ 代码:** 当 JavaScript 代码调用 `Thread` 模块的方法时，Frida 引擎会将这些调用桥接到相应的 C++ 函数，这些函数就定义在 `gumv8thread.cpp` 文件中。例如：
   - `Thread.get(threadId)`  可能会创建一个 JavaScript `Thread` 对象，其内部关联了目标线程的信息。
   - `thread.backtrace()` 会调用 `gumjs_thread_backtrace` 函数。
   - `thread.setHardwareBreakpoint()` 会调用 `gumjs_thread_set_hardware_breakpoint` 函数。

5. **`gum` 库交互:**  `gumv8thread.cpp` 中的 C++ 函数会调用 Frida 的核心库 `gum` 提供的 API (例如 `gum_backtracer_generate`, `gum_thread_set_hardware_breakpoint`) 来执行实际的操作，这些 `gum` 库的函数会与操作系统内核进行交互。

6. **内核交互:**  `gum` 库会使用底层的系统调用 (如 `ptrace` 在 Linux 上) 来读取目标进程的内存，设置硬件断点/观察点等。

7. **结果返回:**  C++ 函数执行完毕后，会将结果转换回 JavaScript 对象，并返回给用户的脚本。例如，`gumjs_thread_backtrace` 会返回一个包含回溯信息的 JavaScript 数组。

**调试线索:**

如果用户在 Frida 脚本中遇到问题，例如无法设置硬件断点或回溯信息不正确，调试线索可能包括：

- **Frida 的错误信息:** Frida 会在控制台输出错误信息，指示问题的类型和位置。
- **目标进程的行为:**  观察目标进程是否按预期暂停在断点处，或者是否出现异常行为。
- **操作系统的日志:**  在某些情况下，操作系统日志可能包含与 Frida 操作相关的错误信息。
- **检查 Frida 版本和目标环境:** 确保 Frida 版本与目标操作系统和架构兼容。
- **逐步调试 Frida 脚本:**  可以使用 `console.log()` 语句在脚本中输出中间变量的值，帮助理解脚本的执行流程。
- **分析 `gumv8thread.cpp` 代码:**  如果错误信息指向 `gumv8thread.cpp` 中的逻辑，开发者可能需要查看源代码来理解具体的实现细节和潜在的错误原因。例如，检查参数解析是否正确，或者 `gum` 库的调用是否返回了错误。

总而言之，`frida/subprojects/frida-gum/bindings/gumjs/gumv8thread.cpp` 文件是 Frida 连接 JavaScript API 和底层线程操作的关键桥梁，它利用了操作系统和硬件提供的调试功能，为逆向工程师提供了强大的动态分析能力。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8thread.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 DaVinci <nstefanclaudel13@gmail.com>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8thread.h"

#include "gumv8macros.h"

#define GUMJS_MODULE_NAME Thread

#define GUMJS_THREAD_ID(o) \
    (o)->GetInternalField (0).As<BigInt> ()->Uint64Value ()

using namespace v8;

GUMJS_DECLARE_FUNCTION (gumjs_thread_backtrace)
GUMJS_DECLARE_FUNCTION (gumjs_thread_sleep)

GUMJS_DECLARE_FUNCTION (gumjs_thread_set_hardware_breakpoint)
GUMJS_DECLARE_FUNCTION (gumjs_thread_unset_hardware_breakpoint)
GUMJS_DECLARE_FUNCTION (gumjs_thread_set_hardware_watchpoint)
GUMJS_DECLARE_FUNCTION (gumjs_thread_unset_hardware_watchpoint)

static const GumV8Function gumjs_thread_module_functions[] =
{
  { "_backtrace", gumjs_thread_backtrace },
  { "sleep", gumjs_thread_sleep },

  { NULL, NULL }
};

static const GumV8Function gumjs_thread_functions[] =
{
  { "setHardwareBreakpoint", gumjs_thread_set_hardware_breakpoint },
  { "unsetHardwareBreakpoint", gumjs_thread_unset_hardware_breakpoint },
  { "setHardwareWatchpoint", gumjs_thread_set_hardware_watchpoint },
  { "unsetHardwareWatchpoint", gumjs_thread_unset_hardware_watchpoint },

  { NULL, NULL }
};

void
_gum_v8_thread_init (GumV8Thread * self,
                     GumV8Core * core,
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto klass = _gum_v8_create_class ("Thread", nullptr, scope, module, isolate);
  _gum_v8_class_add_static (klass, gumjs_thread_module_functions, module,
      isolate);
  _gum_v8_class_add (klass, gumjs_thread_functions, module, isolate);
  self->klass = new Global<FunctionTemplate> (isolate, klass);

  _gum_v8_create_module ("Backtracer", scope, isolate);
}

void
_gum_v8_thread_realize (GumV8Thread * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto backtracer = context->Global ()->Get (context,
      _gum_v8_string_new_ascii (isolate, "Backtracer")).ToLocalChecked ()
      .As<Object> ();

  auto accurate = Symbol::ForApi (isolate,
      _gum_v8_string_new_ascii (isolate, "Backtracer.ACCURATE"));
  backtracer->DefineOwnProperty (context,
      _gum_v8_string_new_ascii (isolate, "ACCURATE"), accurate,
      (PropertyAttribute) (ReadOnly | DontDelete)).ToChecked ();
  self->accurate_enum_value = new Global<Symbol> (isolate, accurate);

  auto fuzzy = Symbol::ForApi (isolate,
      _gum_v8_string_new_ascii (isolate, "Backtracer.FUZZY"));
  backtracer->DefineOwnProperty (context,
      _gum_v8_string_new_ascii (isolate, "FUZZY"), fuzzy,
      (PropertyAttribute) (ReadOnly | DontDelete)).ToChecked ();
  self->fuzzy_enum_value = new Global<Symbol> (isolate, fuzzy);
}

void
_gum_v8_thread_dispose (GumV8Thread * self)
{
  delete self->fuzzy_enum_value;
  self->fuzzy_enum_value = nullptr;

  delete self->accurate_enum_value;
  self->accurate_enum_value = nullptr;

  delete self->klass;
  self->klass = nullptr;
}

void
_gum_v8_thread_finalize (GumV8Thread * self)
{
  g_clear_object (&self->accurate_backtracer);
  g_clear_object (&self->fuzzy_backtracer);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_backtrace)
{
  auto context = isolate->GetCurrentContext ();

  GumCpuContext * cpu_context = NULL;
  Local<Value> raw_type;
  guint limit;
  if (!_gum_v8_args_parse (args, "C?Vu", &cpu_context, &raw_type, &limit))
    return;

  if (!raw_type->IsSymbol ())
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid backtracer value");
    return;
  }
  Local<Symbol> type = raw_type.As<Symbol> ();
  gboolean accurate = TRUE;
  if (type->StrictEquals (
        Local<Symbol>::New (isolate, *module->fuzzy_enum_value)))
  {
    accurate = FALSE;
  }
  else if (!type->StrictEquals (
        Local<Symbol>::New (isolate, *module->accurate_enum_value)))
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid backtracer enum value");
    return;
  }

  GumBacktracer * backtracer;
  if (accurate)
  {
    if (module->accurate_backtracer == NULL)
      module->accurate_backtracer = gum_backtracer_make_accurate ();
    backtracer = module->accurate_backtracer;
  }
  else
  {
    if (module->fuzzy_backtracer == NULL)
      module->fuzzy_backtracer = gum_backtracer_make_fuzzy ();
    backtracer = module->fuzzy_backtracer;
  }
  if (backtracer == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, accurate
            ? "backtracer not yet available for this platform; "
            "please try Thread.backtrace(context, Backtracer.FUZZY)"
            : "backtracer not yet available for this platform; "
            "please try Thread.backtrace(context, Backtracer.ACCURATE)");
    return;
  }

  GumReturnAddressArray ret_addrs;
  if (limit != 0)
  {
    gum_backtracer_generate_with_limit (backtracer, cpu_context, &ret_addrs,
        limit);
  }
  else
  {
    gum_backtracer_generate (backtracer, cpu_context, &ret_addrs);
  }

  auto result = Array::New (isolate, ret_addrs.len);
  for (guint i = 0; i != ret_addrs.len; i++)
  {
    result->Set (context, i,
        _gum_v8_native_pointer_new (ret_addrs.items[i], core)).Check ();
  }
  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_sleep)
{
  gdouble delay;

  if (!_gum_v8_args_parse (args, "n", &delay))
    return;

  if (delay < 0)
    return;

  {
    ScriptUnlocker unlocker (core);

    g_usleep (delay * G_USEC_PER_SEC);
  }
}

Local<Object>
_gum_v8_thread_new (const GumThreadDetails * details,
                    GumV8Thread * module)
{
  auto core = module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto klass = Local<FunctionTemplate>::New (isolate, *module->klass);
  auto thread = klass->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  thread->SetInternalField (0, BigInt::NewFromUnsigned (isolate, details->id));

  _gum_v8_object_set (thread, "id", Number::New (isolate, details->id), core);
  if (details->name != NULL)
    _gum_v8_object_set_utf8 (thread, "name", details->name, core);
  _gum_v8_object_set (thread, "state", _gum_v8_string_new_ascii (isolate,
      _gum_v8_thread_state_to_string (details->state)), core);
  auto cpu_context =
      _gum_v8_cpu_context_new_immutable (&details->cpu_context, core);
  _gum_v8_object_set (thread, "context", cpu_context, core);
  _gum_v8_cpu_context_free_later (new Global<Object> (isolate, cpu_context),
      core);

  return thread;
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_set_hardware_breakpoint)
{
  GumThreadId thread_id = GUMJS_THREAD_ID (info.Holder ());

  guint breakpoint_id;
  gpointer address;
  if (!_gum_v8_args_parse (args, "up", &breakpoint_id, &address))
    return;

  GError * error = NULL;
  gum_thread_set_hardware_breakpoint (thread_id, breakpoint_id,
      GUM_ADDRESS (address), &error);
  _gum_v8_maybe_throw (isolate, &error);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_unset_hardware_breakpoint)
{
  GumThreadId thread_id = GUMJS_THREAD_ID (info.Holder ());

  guint breakpoint_id;
  if (!_gum_v8_args_parse (args, "u", &breakpoint_id))
    return;

  GError * error = NULL;
  gum_thread_unset_hardware_breakpoint (thread_id, breakpoint_id, &error);
  _gum_v8_maybe_throw (isolate, &error);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_set_hardware_watchpoint)
{
  GumThreadId thread_id = GUMJS_THREAD_ID (info.Holder ());

  guint watchpoint_id;
  gpointer address;
  gsize size;
  gchar * conditions_str;
  if (!_gum_v8_args_parse (args, "upZs", &watchpoint_id, &address, &size,
        &conditions_str))
  {
    return;
  }

  auto conditions = (GumWatchConditions) 0;
  bool conditions_valid = true;
  for (const gchar * ch = conditions_str; *ch != '\0'; ch++)
  {
    switch (*ch)
    {
      case 'r':
        conditions = (GumWatchConditions) (conditions | GUM_WATCH_READ);
        break;
      case 'w':
        conditions = (GumWatchConditions) (conditions | GUM_WATCH_WRITE);
        break;
      default:
        conditions_valid = false;
        break;
    }
  }

  g_free (conditions_str);

  if (conditions == 0 || !conditions_valid)
  {
    _gum_v8_throw_ascii_literal (isolate,
        "expected a string specifying watch conditions, e.g. 'rw'");
    return;
  }

  GError * error = NULL;
  gum_thread_set_hardware_watchpoint (thread_id, watchpoint_id,
      GUM_ADDRESS (address), size, conditions, &error);
  _gum_v8_maybe_throw (isolate, &error);
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_unset_hardware_watchpoint)
{
  GumThreadId thread_id = GUMJS_THREAD_ID (info.Holder ());

  guint watchpoint_id;
  if (!_gum_v8_args_parse (args, "u", &watchpoint_id))
    return;

  GError * error = NULL;
  gum_thread_unset_hardware_watchpoint (thread_id, watchpoint_id, &error);
  _gum_v8_maybe_throw (isolate, &error);
}

"""

```