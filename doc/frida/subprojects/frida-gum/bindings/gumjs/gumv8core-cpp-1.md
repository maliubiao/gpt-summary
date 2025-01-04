Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Frida dynamic instrumentation tool. The code specifically deals with CPU context access and interaction with the V8 JavaScript engine.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:**  The most prominent feature is the `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_*` macros. These clearly define how Frida accesses and manipulates CPU registers within the JavaScript environment.

2. **Categorize the Registers:**  Notice the different categories:
    * General Purpose Registers (GPRs): x0-x30, sp, fp, lr (for ARM64) and pc, gp, sp, fp, ra, hi, lo, at, v0, v1, a0-a3, t0-t9, s0-s7, k0, k1 (for MIPS).
    * Vector Registers (SIMD): q0-q31, d0-d31, s0-s31 (for ARM64).
    * Recognize the architecture-specific nature (ARM64 and MIPS).

3. **Connect to Reverse Engineering:**  Accessing CPU registers is fundamental to reverse engineering. Frida uses this to inspect and modify the program's state at runtime. Give concrete examples like reading arguments, return values, and stepping through code.

4. **Relate to Binary/OS Concepts:**  Mention the underlying binary structure (registers), how the OS manages processes (context switching), and potentially kernel interaction if the registers are accessed during system calls.

5. **Look for Logic and Data Structures:** Identify `match_pattern` and `source_map` related code. These suggest features for pattern matching in memory and managing source code information (important for debugging and understanding obfuscated code).

6. **Consider User Interaction and Errors:** Think about how a user would interact with these features. They would likely write JavaScript code using Frida's API to access these registers. Common errors could involve incorrect register names or assumptions about their values.

7. **Trace the "Path" to the Code:**  How does the program execution reach this specific part of the code?  Users would write Frida scripts that hook functions. When those functions are called, Frida intercepts the execution, and the `GumCpuContext` structure (which this code manipulates) becomes relevant.

8. **Focus on the "Part 2" Request:** The prompt explicitly asks to summarize the functionality of *this specific snippet*. Avoid going too broad into the overall Frida functionality.

9. **Structure the Answer:** Organize the information into the requested categories:
    * Core Functionality
    * Relation to Reverse Engineering
    * Binary/OS/Kernel Knowledge
    * Logic and Data Structures
    * User Errors
    * User Operation to Reach Here
    * Summary (as requested in part 2).

10. **Refine and Elaborate:** Add details and explanations to make the answer clear and comprehensive. For instance, explain what GPRs and vector registers are in general terms.

11. **Self-Correction/Review:**  Double-check if all parts of the prompt are addressed. Ensure the examples are relevant and easy to understand. For example, initially, I might have just said "accesses registers," but then I elaborated on the *purpose* of accessing them in reverse engineering. Similarly, just saying "binary level" is vague, so specifying "CPU registers" is better.
这是名为 `gumv8core.cpp` 的 Frida 源代码文件的一部分，主要负责定义和管理与 V8 JavaScript 引擎交互的核心功能。 从提供的代码片段来看，它的主要功能集中在 **访问和操作 CPU 上下文（registers）**。

**它的功能:**

1. **定义 CPU 上下文访问器:**  这段代码使用宏 `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_*` 来为各种 CPU 寄存器创建访问器。 这意味着它提供了一种在 Frida 的 JavaScript 环境中读取和写入目标进程的 CPU 寄存器的机制。

   * `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR(_ALIASED)`:  定义通用寄存器的访问器，例如 `x0` 到 `x28` (ARM64) 和 `pc`, `sp`, `ra` 等 (MIPS)。 `_ALIASED` 版本可能表示该寄存器有别名。
   * `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR`: 定义向量寄存器的访问器，例如 `q0` 到 `q31` (ARM64)。
   * `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE`: 定义双精度浮点寄存器的访问器，例如 `d0` 到 `d31` (ARM64)。
   * `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT`: 定义单精度浮点寄存器的访问器，例如 `s0` 到 `s31` (ARM64)。

2. **架构特定:**  代码中使用了 `#elif defined (HAVE_MIPS)`，表明这些寄存器的定义是架构特定的。这段代码同时支持 ARM64 和 MIPS 架构。

**与逆向的方法的关系及举例说明:**

这段代码与动态逆向分析密切相关，因为它允许在程序运行时检查和修改其 CPU 状态。

* **查看函数参数和返回值:** 在函数被调用时，参数通常会被存储在特定的寄存器中。通过访问这些寄存器，逆向工程师可以动态地获取函数的输入参数。类似地，返回值也通常会存储在特定的寄存器中，例如 `x0` (ARM64)。

   **举例:** 假设你想查看 `malloc` 函数的参数。你可以使用 Frida 脚本 hook `malloc`，并在 hook 函数中读取寄存器 `x0` (假设第一个参数传递在 `x0`) 来获取要分配的内存大小。

   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'malloc'), {
     onEnter: function (args) {
       console.log('malloc size:', this.context.x0);
     }
   });
   ```

* **修改程序行为:** 通过修改寄存器的值，可以改变程序的执行流程或结果。 例如，可以修改条件分支指令所依赖的标志位，强制程序执行特定的分支。

   **举例:**  假设你正在逆向一个校验用户名密码的函数。你可以在关键的比较指令之后修改标志位寄存器，使得比较结果始终为真，从而绕过密码验证。

   ```javascript
   Interceptor.attach(Address("0x12345678"), { // 假设这是比较指令的地址
     onLeave: function (retval) {
       // 强制返回值，但这通常不够底层，更常见的是修改标志位
       // 例如，在 ARM64 上可能需要操作 CPSR 寄存器
       this.context.x0 = 1; // 假设返回值在 x0
     }
   });
   ```

* **理解程序执行流程:** 通过在关键点记录寄存器的值，可以追踪程序的执行轨迹，理解函数调用关系和数据流。

   **举例:**  在函数调用的入口和出口记录程序计数器 (PC) 或链接寄存器 (LR) 的值，可以了解函数的调用者和被调用者。

**涉及二进制底层，linux, android内核及框架的知识及举例说明:**

* **二进制底层:**  这段代码直接操作 CPU 寄存器，这是二进制执行的最底层概念。不同的 CPU 架构有不同的寄存器集和调用约定。Frida 需要理解目标架构的寄存器命名和用途才能正确地访问和修改它们。
* **Linux/Android 内核:**  当目标进程运行在 Linux 或 Android 上时，Frida 需要与操作系统内核进行交互才能获取和修改进程的上下文。 这通常涉及到使用特定的系统调用或内核接口。例如，ptrace 系统调用在 Linux 中常用于进程跟踪和调试。 Frida 底层会利用这些机制来实现对寄存器的访问。
* **Android 框架:** 在 Android 环境中，Frida 可以用于分析 Android Framework 的行为。例如，可以 hook Framework 层的函数，并检查或修改传递给这些函数的参数，这些参数可能存储在特定的寄存器中。

**逻辑推理的假设输入与输出:**

这段代码本身主要是定义访问器，并没有复杂的逻辑推理。 然而，在使用这些访问器的 Frida 脚本中会涉及到逻辑推理。

**假设输入 (Frida 脚本):**

```javascript
Interceptor.attach(Module.findExportByName(null, 'some_function'), {
  onEnter: function (args) {
    if (this.context.x0 === 10) {
      console.log("x0 is 10, setting x1 to 20");
      this.context.x1 = 20;
    }
  }
});
```

**输出:**  当 `some_function` 被调用且进入时，如果寄存器 `x0` 的值是 10，那么脚本会将寄存器 `x1` 的值设置为 20。

**涉及用户或者编程常见的使用错误及举例说明:**

* **错误的寄存器名称:** 用户可能会输入错误的寄存器名称，导致 Frida 无法找到对应的寄存器。 例如，在 ARM64 上输入 `r0` 而不是 `x0`。

   **举例:** `console.log(this.context.r0);`  (这在 ARM64 上会出错)

* **假设寄存器的用途:**  用户可能会错误地假设某个寄存器总是存储特定的值。  不同的编译器、架构和调用约定可能导致寄存器的用途有所不同。

   **举例:** 假设用户认为函数的第一个参数总是存储在 `x0`，但在某些特殊情况下，参数可能通过栈传递。

* **不理解架构差异:**  编写 Frida 脚本时没有考虑到目标进程的 CPU 架构，使用了错误的寄存器名称。

   **举例:**  在 MIPS 架构的进程中尝试访问 `this.context.x0`。

* **在错误的时机访问寄存器:** 在 `onEnter` 中修改返回值寄存器或在 `onLeave` 中修改参数寄存器通常没有意义，并且可能导致程序崩溃或行为异常。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户使用 Frida 的 JavaScript API 编写脚本，目的是 hook 目标进程的函数并检查或修改其状态。
2. **使用 `Interceptor.attach`:**  脚本中通常会使用 `Interceptor.attach` 函数来指定要 hook 的目标函数。
3. **访问 `this.context`:** 在 `onEnter` 或 `onLeave` 回调函数中，用户会访问 `this.context` 对象，该对象提供了对 CPU 上下文的访问。
4. **读取或写入寄存器:** 用户通过 `this.context.寄存器名称` 的方式来读取或写入特定的 CPU 寄存器。例如 `this.context.x0`。
5. **Frida 内部执行:** 当目标进程执行到被 hook 的函数时，Frida 的内部机制会暂停目标进程的执行，并将控制权交给 JavaScript 脚本的 `onEnter` 或 `onLeave` 函数。
6. **`gumv8core.cpp` 的作用:** 在 Frida 的内部实现中，当 JavaScript 代码尝试访问 `this.context.x0` 时，最终会调用到 `gumv8core.cpp` 中定义的 `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR` 宏生成的代码，该代码负责从目标进程的内存中读取或写入相应的寄存器值。

**归纳一下它的功能 (第 2 部分):**

这段 `gumv8core.cpp` 的代码片段的主要功能是 **为 Frida 的 JavaScript 环境提供访问和操作目标进程 CPU 寄存器的能力。** 它定义了一系列与特定 CPU 架构相关的访问器，使得 Frida 脚本能够读取和修改通用寄存器、向量寄存器和浮点寄存器的值，从而实现动态的程序分析和修改。这部分代码是 Frida 进行动态 instrumentation 的核心组成部分，为逆向工程师提供了强大的底层控制能力。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8core.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
SSOR_GPR_ALIASED (x22, x[22]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x23, x[23]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x24, x[24]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x25, x[25]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x26, x[26]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x27, x[27]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x28, x[28]);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (fp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (lr);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q0, v[0].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q1, v[1].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q2, v[2].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q3, v[3].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q4, v[4].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q5, v[5].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q6, v[6].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q7, v[7].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q8, v[8].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q9, v[9].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q10, v[10].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q11, v[11].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q12, v[12].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q13, v[13].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q14, v[14].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q15, v[15].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q16, v[16].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q17, v[17].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q18, v[18].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q19, v[19].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q20, v[20].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q21, v[21].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q22, v[22].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q23, v[23].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q24, v[24].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q25, v[25].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q26, v[26].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q27, v[27].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q28, v[28].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q29, v[29].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q30, v[30].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q31, v[31].q);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d0, v[0].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d1, v[1].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d2, v[2].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d3, v[3].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d4, v[4].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d5, v[5].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d6, v[6].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d7, v[7].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d8, v[8].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d9, v[9].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d10, v[10].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d11, v[11].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d12, v[12].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d13, v[13].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d14, v[14].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d15, v[15].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d16, v[16].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d17, v[17].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d18, v[18].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d19, v[19].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d20, v[20].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d21, v[21].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d22, v[22].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d23, v[23].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d24, v[24].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d25, v[25].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d26, v[26].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d27, v[27].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d28, v[28].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d29, v[29].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d30, v[30].d);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d31, v[31].d);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s0, v[0].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s1, v[1].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s2, v[2].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s3, v[3].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s4, v[4].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s5, v[5].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s6, v[6].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s7, v[7].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s8, v[8].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s9, v[9].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s10, v[10].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s11, v[11].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s12, v[12].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s13, v[13].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s14, v[14].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s15, v[15].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s16, v[16].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s17, v[17].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s18, v[18].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s19, v[19].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s20, v[20].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s21, v[21].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s22, v[22].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s23, v[23].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s24, v[24].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s25, v[25].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s26, v[26].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s27, v[27].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s28, v[28].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s29, v[29].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s30, v[30].s);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s31, v[31].s);
#elif defined (HAVE_MIPS)
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (pc);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (gp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (sp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (fp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (ra);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (hi);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (lo);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (at);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (v0);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (v1);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (a0);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (a1);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (a2);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (a3);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t0);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t1);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t2);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t3);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t4);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t5);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t6);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t7);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t8);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (t9);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (s0);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (s1);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (s2);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (s3);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (s4);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (s5);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (s6);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (s7);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (k0);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (k1);
#endif

  auto match_pattern = _gum_v8_create_class ("MatchPattern",
      gumjs_match_pattern_construct, scope, module, isolate);
  self->match_pattern = new Global<FunctionTemplate> (isolate, match_pattern);

  auto source_map = _gum_v8_create_class ("SourceMap",
      gumjs_source_map_construct, scope, module, isolate);
  _gum_v8_class_add (source_map, gumjs_source_map_functions, module, isolate);
  self->source_map = new Global<FunctionTemplate> (isolate, source_map);

  gum_exceptor_add (self->exceptor, gum_v8_core_handle_crashed_js, self);
}

static gboolean
gum_v8_core_handle_crashed_js (GumExceptionDetails * details,
                               gpointer user_data)
{
  GumV8Core * self = (GumV8Core *) user_data;
  GumThreadId thread_id = details->thread_id;

  if (gum_exceptor_has_scope (self->exceptor, thread_id))
    return FALSE;

  if (self->current_owner == thread_id)
  {
    gum_interceptor_end_transaction (self->script->interceptor.interceptor);
    gum_v8_script_backend_mark_scope_mutex_trapped (self->backend);
  }

  return FALSE;
}

void
_gum_v8_core_realize (GumV8Core * self)
{
  auto isolate = self->isolate;
  auto context = isolate->GetCurrentContext ();

  auto module = External::New (isolate, self);

  auto global = context->Global ();
  global->Set (context, _gum_v8_string_new_ascii (isolate, "global"), global)
      .Check ();

  auto array_buffer = global->Get (context,
      _gum_v8_string_new_ascii (isolate, "ArrayBuffer")).ToLocalChecked ()
      .As<Object> ();
  array_buffer->Set (context, _gum_v8_string_new_ascii (isolate, "wrap"),
      Function::New (context, gumjs_array_buffer_wrap, module)
      .ToLocalChecked ()).Check ();
  auto array_buffer_proto = array_buffer->Get (context,
      _gum_v8_string_new_ascii (isolate, "prototype")).ToLocalChecked ()
      .As<Object> ();
  array_buffer_proto->Set (context,
      _gum_v8_string_new_ascii (isolate, "unwrap"),
      Function::New (context, gumjs_array_buffer_unwrap, module)
      .ToLocalChecked ()).Check ();

  self->native_functions = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_native_function_free);

  self->native_callbacks = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_native_callback_clear);

  self->native_resources = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) _gum_v8_native_resource_free);
  self->kernel_resources = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) _gum_v8_kernel_resource_free);

  self->match_patterns = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_match_pattern_free);

  self->source_maps = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_source_map_free);

  Local<Value> zero = Integer::New (isolate, 0);

  auto int64 = Local<FunctionTemplate>::New (isolate, *self->int64);
  auto int64_value = int64->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 1, &zero).ToLocalChecked ();
  self->int64_value = new Global<Object> (isolate, int64_value);

  auto uint64 = Local<FunctionTemplate>::New (isolate, *self->uint64);
  auto uint64_value = uint64->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 1, &zero).ToLocalChecked ();
  self->uint64_value = new Global<Object> (isolate, uint64_value);

  auto native_pointer = Local<FunctionTemplate>::New (isolate,
      *self->native_pointer);
  auto native_pointer_value = native_pointer->GetFunction (context)
      .ToLocalChecked ()->NewInstance (context, 1, &zero).ToLocalChecked ();
  self->native_pointer_value = new Global<Object> (isolate,
      native_pointer_value);
  self->handle_key = new Global<String> (isolate,
      _gum_v8_string_new_ascii (isolate, "handle"));

  self->abi_key = new Global<String> (isolate,
      _gum_v8_string_new_ascii (isolate, "abi"));
  self->scheduling_key = new Global<String> (isolate,
      _gum_v8_string_new_ascii (isolate, "scheduling"));
  self->exceptions_key = new Global<String> (isolate,
      _gum_v8_string_new_ascii (isolate, "exceptions"));
  self->traps_key = new Global<String> (isolate,
      _gum_v8_string_new_ascii (isolate, "traps"));
  auto value_key = _gum_v8_string_new_ascii (isolate, "value");
  self->value_key = new Global<String> (isolate, value_key);
  auto system_error_key =
      _gum_v8_string_new_ascii (isolate, GUMJS_SYSTEM_ERROR_FIELD);
  self->system_error_key = new Global<String> (isolate, system_error_key);

  auto native_return_value = Object::New (isolate);
  native_return_value->Set (context, value_key, zero).Check ();
  native_return_value->Set (context, system_error_key, zero).Check ();
  self->native_return_value = new Global<Object> (isolate, native_return_value);

  auto callback_context = Local<FunctionTemplate>::New (isolate,
      *self->callback_context);
  auto callback_context_value = callback_context->GetFunction (context)
      .ToLocalChecked ()->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->callback_context_value = new Global<Object> (isolate,
      callback_context_value);

  auto cpu_context = Local<FunctionTemplate>::New (isolate, *self->cpu_context);
  auto cpu_context_value = cpu_context->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context).ToLocalChecked ();
  self->cpu_context_value = new Global<Object> (isolate, cpu_context_value);
}

gboolean
_gum_v8_core_flush (GumV8Core * self,
                    GumV8FlushNotify flush_notify)
{
  gboolean done;

  self->flush_notify = flush_notify;

  g_mutex_lock (&self->event_mutex);
  self->event_source_available = FALSE;
  g_cond_broadcast (&self->event_cond);
  g_mutex_unlock (&self->event_mutex);
  g_main_loop_quit (self->event_loop);

  if (self->usage_count > 1)
    return FALSE;

  do
  {
    GHashTableIter iter;
    GumV8ScheduledCallback * callback;

    g_hash_table_iter_init (&iter, self->scheduled_callbacks);
    while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &callback))
    {
      _gum_v8_core_pin (self);
      g_source_destroy (callback->source);
    }
    g_hash_table_remove_all (self->scheduled_callbacks);

    if (self->usage_count > 1)
      return FALSE;

    gum_v8_core_clear_weak_refs (self);
  }
  while (g_hash_table_size (self->scheduled_callbacks) > 0 ||
      g_hash_table_size (self->weak_refs) > 0);

  done = self->usage_count == 1;
  if (done)
    self->flush_notify = NULL;

  return done;
}

static void
gum_v8_core_clear_weak_refs (GumV8Core * self)
{
  GHashTableIter iter;
  GumV8WeakRef * ref;

  g_hash_table_iter_init (&iter, self->weak_refs);
  while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &ref))
  {
    gum_v8_weak_ref_clear (ref);
  }

  g_hash_table_remove_all (self->weak_refs);

  ScriptScope scope (self->script);
  gum_v8_core_invoke_pending_weak_callbacks (self, &scope);
}

void
_gum_v8_core_notify_flushed (GumV8Core * self,
                             GumV8FlushNotify func)
{
  auto callback = g_slice_new (GumV8FlushCallback);
  callback->func = func;
  callback->script = GUM_V8_SCRIPT (g_object_ref (self->script));

  auto source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) gum_v8_flush_callback_notify,
      callback, (GDestroyNotify) gum_v8_flush_callback_free);
  g_source_attach (source,
      gum_script_scheduler_get_js_context (self->scheduler));
  g_source_unref (source);
}

static void
gum_v8_flush_callback_free (GumV8FlushCallback * self)
{
  g_object_unref (self->script);

  g_slice_free (GumV8FlushCallback, self);
}

static gboolean
gum_v8_flush_callback_notify (GumV8FlushCallback * self)
{
  self->func (self->script);
  return FALSE;
}

void
_gum_v8_core_dispose (GumV8Core * self)
{
  g_hash_table_unref (self->source_maps);
  self->source_maps = NULL;

  g_hash_table_unref (self->match_patterns);
  self->match_patterns = NULL;

  g_hash_table_unref (self->kernel_resources);
  self->kernel_resources = NULL;
  g_hash_table_unref (self->native_resources);
  self->native_resources = NULL;

  g_hash_table_unref (self->native_callbacks);
  self->native_callbacks = NULL;

  g_hash_table_unref (self->native_functions);
  self->native_functions = NULL;

  g_clear_pointer (&self->unhandled_exception_sink, gum_v8_exception_sink_free);

  g_clear_pointer (&self->incoming_message_sink, gum_v8_message_sink_free);

  delete self->on_global_get;
  delete self->global_receiver;
  self->on_global_get = nullptr;
  self->global_receiver = nullptr;

  delete self->int64_value;
  self->int64_value = nullptr;

  delete self->uint64_value;
  self->uint64_value = nullptr;

  delete self->handle_key;
  delete self->native_pointer_value;
  self->handle_key = nullptr;
  self->native_pointer_value = nullptr;

  delete self->abi_key;
  delete self->scheduling_key;
  delete self->exceptions_key;
  delete self->traps_key;
  delete self->value_key;
  delete self->system_error_key;
  self->abi_key = nullptr;
  self->scheduling_key = nullptr;
  self->exceptions_key = nullptr;
  self->traps_key = nullptr;
  self->value_key = nullptr;
  self->system_error_key = nullptr;

  delete self->native_return_value;
  self->native_return_value = nullptr;

  delete self->callback_context_value;
  self->callback_context_value = nullptr;

  delete self->cpu_context_value;
  self->cpu_context_value = nullptr;
}

void
_gum_v8_core_finalize (GumV8Core * self)
{
  g_hash_table_unref (self->scheduled_callbacks);
  self->scheduled_callbacks = NULL;

  g_hash_table_unref (self->weak_refs);
  self->weak_refs = NULL;

  delete self->source_map;
  self->source_map = nullptr;

  delete self->match_pattern;
  self->match_pattern = nullptr;

  delete self->cpu_context;
  self->cpu_context = nullptr;

  delete self->callback_context;
  self->callback_context = nullptr;

  delete self->native_function;
  self->native_function = nullptr;

  delete self->native_pointer;
  self->native_pointer = nullptr;

  delete self->uint64;
  self->uint64 = nullptr;

  delete self->int64;
  self->int64 = nullptr;

  gum_exceptor_remove (self->exceptor, gum_v8_core_handle_crashed_js, self);
  g_object_unref (self->exceptor);
  self->exceptor = NULL;

  g_main_loop_unref (self->event_loop);
  self->event_loop = NULL;
  g_mutex_clear (&self->event_mutex);
  g_cond_clear (&self->event_cond);
}

void
_gum_v8_core_pin (GumV8Core * self)
{
  self->usage_count++;
}

void
_gum_v8_core_unpin (GumV8Core * self)
{
  self->usage_count--;
}

void
_gum_v8_core_on_unhandled_exception (GumV8Core * self,
                                     Local<Value> exception)
{
  if (self->unhandled_exception_sink == NULL)
    return;

  gum_v8_exception_sink_handle_exception (self->unhandled_exception_sink,
      exception);
}

void
_gum_v8_core_post (GumV8Core * self,
                   const gchar * message,
                   GBytes * data)
{
  gboolean delivered = FALSE;

  {
    Locker locker (self->isolate);

    if (self->incoming_message_sink != NULL)
    {
      ScriptScope scope (self->script);
      gum_v8_message_sink_post (self->incoming_message_sink, message, data);
      delivered = TRUE;
    }
  }

  if (delivered)
  {
    g_mutex_lock (&self->event_mutex);
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
    g_mutex_unlock (&self->event_mutex);

    g_main_loop_quit (self->event_loop);
  }
  else
  {
    g_bytes_unref (data);
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_set_timeout)
{
  gum_v8_core_schedule_callback (core, args, FALSE);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_interval)
{
  gum_v8_core_schedule_callback (core, args, TRUE);
}

static void
gum_v8_core_schedule_callback (GumV8Core * self,
                               const GumV8Args * args,
                               gboolean repeat)
{
  Local<Function> func;
  gsize delay;

  if (repeat)
  {
    if (!_gum_v8_args_parse (args, "FZ", &func, &delay))
      return;
  }
  else
  {
    delay = 0;
    if (!_gum_v8_args_parse (args, "F|Z", &func, &delay))
      return;
  }

  auto id = self->next_callback_id++;
  GSource * source;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new ((guint) delay);
  auto callback = gum_v8_scheduled_callback_new (id, repeat, source, self);
  callback->func = new Global<Function> (self->isolate, func);
  g_source_set_callback (source, (GSourceFunc) gum_v8_scheduled_callback_invoke,
      callback, (GDestroyNotify) gum_v8_scheduled_callback_free);

  g_hash_table_insert (self->scheduled_callbacks, GINT_TO_POINTER (id),
      callback);
  self->current_scope->AddScheduledSource (source);

  args->info->GetReturnValue ().Set (id);
}

static GumV8ScheduledCallback *
gum_v8_core_try_steal_scheduled_callback (GumV8Core * self,
                                          gint id)
{
  auto raw_id = GINT_TO_POINTER (id);

  auto callback = (GumV8ScheduledCallback *) g_hash_table_lookup (
      self->scheduled_callbacks, raw_id);
  if (callback == NULL)
    return NULL;

  g_hash_table_remove (self->scheduled_callbacks, raw_id);

  return callback;
}

GUMJS_DEFINE_FUNCTION (gumjs_clear_timer)
{
  if (info.Length () < 1 || !info[0]->IsNumber ())
  {
    info.GetReturnValue ().Set (false);
    return;
  }

  gint id;
  if (!_gum_v8_args_parse (args, "i", &id))
    return;

  auto callback = gum_v8_core_try_steal_scheduled_callback (core, id);
  if (callback != NULL)
  {
    _gum_v8_core_pin (core);
    g_source_destroy (callback->source);
  }

  info.GetReturnValue ().Set (callback != NULL);
}

static GumV8ScheduledCallback *
gum_v8_scheduled_callback_new (guint id,
                               gboolean repeat,
                               GSource * source,
                               GumV8Core * core)
{
  auto callback = g_slice_new (GumV8ScheduledCallback);

  callback->id = id;
  callback->repeat = repeat;
  callback->source = source;

  callback->core = core;

  return callback;
}

static void
gum_v8_scheduled_callback_free (GumV8ScheduledCallback * callback)
{
  auto core = callback->core;

  {
    ScriptScope scope (core->script);

    delete callback->func;

    _gum_v8_core_unpin (core);
  }

  g_slice_free (GumV8ScheduledCallback, callback);
}

static gboolean
gum_v8_scheduled_callback_invoke (GumV8ScheduledCallback * self)
{
  auto core = self->core;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto func = Local<Function>::New (isolate, *self->func);
  auto recv = Undefined (isolate);
  auto result = func->Call (context, recv, 0, nullptr);
  _gum_v8_ignore_result (result);

  if (!self->repeat)
  {
    if (gum_v8_core_try_steal_scheduled_callback (core, self->id) != NULL)
      _gum_v8_core_pin (core);
  }

  return self->repeat;
}

GUMJS_DEFINE_FUNCTION (gumjs_send)
{
  gchar * message;
  GBytes * data;
  if (!_gum_v8_args_parse (args, "sB?", &message, &data))
    return;

  /*
   * Synchronize Interceptor state before sending the message. The application
   * might be waiting for an acknowledgement that APIs have been instrumented.
   *
   * This is very important for the RPC API.
   */
  auto interceptor = core->script->interceptor.interceptor;
  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_begin_transaction (interceptor);

  core->message_emitter (core->script, message, data);

  g_bytes_unref (data);
  g_free (message);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F?", &callback))
    return;

  auto new_sink = !callback.IsEmpty ()
      ? gum_v8_exception_sink_new (callback, isolate)
      : NULL;

  auto old_sink = core->unhandled_exception_sink;
  core->unhandled_exception_sink = new_sink;

  if (old_sink != NULL)
    gum_v8_exception_sink_free (old_sink);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_incoming_message_callback)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F?", &callback))
    return;

  auto new_sink = !callback.IsEmpty ()
      ? gum_v8_message_sink_new (callback, isolate)
      : NULL;

  auto old_sink = core->incoming_message_sink;
  core->incoming_message_sink = new_sink;

  if (old_sink != NULL)
    gum_v8_message_sink_free (old_sink);
}

GUMJS_DEFINE_FUNCTION (gumjs_wait_for_event)
{
  g_mutex_lock (&core->event_mutex);
  auto start_count = core->event_count;
  g_mutex_unlock (&core->event_mutex);

  gboolean event_source_available;

  core->current_scope->PerformPendingIO ();

  {
    ScriptUnlocker unlocker (core);

    auto context = gum_script_scheduler_get_js_context (core->scheduler);
    gboolean called_from_js_thread = g_main_context_is_owner (context);

    g_mutex_lock (&core->event_mutex);

    while (core->event_count == start_count && core->event_source_available)
    {
      if (called_from_js_thread)
      {
        g_mutex_unlock (&core->event_mutex);
        g_main_loop_run (core->event_loop);
        g_mutex_lock (&core->event_mutex);
      }
      else
      {
        g_cond_wait (&core->event_cond, &core->event_mutex);
      }
    }

    event_source_available = core->event_source_available;

    g_mutex_unlock (&core->event_mutex);
  }

  if (!event_source_available)
    _gum_v8_throw_ascii_literal (isolate, "script is unloading");
}

static void
gumjs_global_get (Local<Name> property,
                  const PropertyCallbackInfo<Value> & info)
{
  auto self = (GumV8Core *) info.Data ().As<External> ()->Value ();

  if (self->on_global_get == nullptr)
    return;

  auto isolate = info.GetIsolate ();
  auto context = isolate->GetCurrentContext ();

  auto get (Local<Function>::New (isolate, *self->on_global_get));
  auto recv (Local<Object>::New (isolate, *self->global_receiver));
  Local<Value> argv[] = { property };
  Local<Value> result;
  if (get->Call (context, recv, G_N_ELEMENTS (argv), argv).ToLocal (&result) &&
      !result->IsUndefined ())
  {
    info.GetReturnValue ().Set (result);
  }
}

GUMJS_DEFINE_GETTER (gumjs_frida_get_heap_size)
{
  info.GetReturnValue ().Set (gum_peek_private_memory_usage ());
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_objc_load)
{
  bool loaded = false;

#ifdef HAVE_OBJC_BRIDGE
  auto bundle = gum_v8_bundle_new (isolate, gumjs_objc_modules);
  gum_v8_bundle_run (bundle);
  gum_v8_bundle_free (bundle);

  loaded = true;
#endif

  info.GetReturnValue ().Set (loaded);
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_swift_load)
{
  bool loaded = false;

#ifdef HAVE_SWIFT_BRIDGE
  auto bundle = gum_v8_bundle_new (isolate, gumjs_swift_modules);
  gum_v8_bundle_run (bundle);
  gum_v8_bundle_free (bundle);

  loaded = true;
#endif

  info.GetReturnValue ().Set (loaded);
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_java_load)
{
  bool loaded = false;

#ifdef HAVE_JAVA_BRIDGE
  auto bundle = gum_v8_bundle_new (isolate, gumjs_java_modules);
  gum_v8_bundle_run (bundle);
  gum_v8_bundle_free (bundle);

  loaded = true;
#endif

  info.GetReturnValue ().Set (loaded);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_evaluate)
{
  gchar * name, * source;
  if (!_gum_v8_args_parse (args, "ss", &name, &source))
    return;

  auto context = isolate->GetCurrentContext ();

  auto source_str = String::NewFromUtf8 (isolate, source).ToLocalChecked ();

  auto resource_name = String::NewFromUtf8 (isolate, name).ToLocalChecked ();
  ScriptOrigin origin (isolate, resource_name);

  Local<Script> code;
  gchar * error_description = NULL;
  int line = -1;
  {
    TryCatch trycatch (isolate);
    auto maybe_code = Script::Compile (context, source_str, &origin);
    if (!maybe_code.ToLocal (&code))
    {
      error_description =
          _gum_v8_error_get_message (isolate, trycatch.Exception ());
      line = trycatch.Message ()->GetLineNumber (context).FromMaybe (-1);
    }
  }
  if (error_description != NULL)
  {
    _gum_v8_throw (isolate,
        "could not parse '%s' line %d: %s",
        name,
        line,
        error_description);
    g_free (error_description);
  }

  if (!code.IsEmpty ())
  {
    gchar * source_map = gum_query_script_for_inline_source_map (isolate, code);
    if (source_map != NULL)
    {
      _gum_v8_script_register_source_map (core->script, name,
          (gchar *) g_steal_pointer (&source_map));
    }

    Local<Value> result;
    auto maybe_result = code->Run (context);
    if (maybe_result.ToLocal (&result))
      info.GetReturnValue ().Set (result);
  }

  g_free (source);
  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_load)
{
  gchar * name, * source;
  if (!_gum_v8_args_parse (args, "ss", &name, &source))
    return;

  _gum_v8_script_load_module (core->script, name, source);

  g_free (source);
  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_register_source_map)
{
  gchar * name, * json;
  if (!_gum_v8_args_parse (args, "ss", &name, &json))
    return;

  _gum_v8_script_register_source_map (core->script, name,
      (gchar *) g_steal_pointer (&json));

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_find_source_map)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  const gchar * json = NULL;
  gchar * json_malloc_data = NULL;

  GumESProgram * program = core->script->program;
  if (program->es_assets != NULL)
  {
    gchar * map_name = g_strconcat (name, ".map", NULL);

    auto map_asset =
        (GumESAsset *) g_hash_table_lookup (program->es_assets, map_name);
    if (map_asset != NULL)
    {
      json = (const gchar *) map_asset->data;
    }

    g_free (map_name);
  }

  if (json == NULL)
  {
    if (g_strcmp0 (name, program->global_filename) == 0)
    {
      json_malloc_data = gum_query_script_for_inline_source_map (isolate,
          Local<Script>::New (isolate, *program->global_code));
      json = json_malloc_data;
    }
    else
    {
      if (strcmp (name, "/_frida.js") == 0)
      {
        json = core->runtime_source_map;
      }
#ifdef HAVE_OBJC_BRIDGE
      else if (strcmp (name, "/_objc.js") == 0)
      {
        json = gumjs_objc_source_map;
      }
#endif
#ifdef HAVE_SWIFT_BRIDGE
      else if (strcmp (name, "/_swift.js") == 0)
      {
        json = gumjs_swift_source_map;
      }
#endif
#ifdef HAVE_JAVA_BRIDGE
      else if (strcmp (name, "/_java.js") == 0)
      {
        json = gumjs_java_source_map;
      }
#endif
    }
  }

  if (json != NULL)
  {
    Local<Object> map;
    if (gumjs_source_map_new (json, core).ToLocal (&map))
      info.GetReturnValue ().Set (map);
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }

  g_free (json_malloc_data);
  g_free (name);
}

static gchar *
gum_query_script_for_inline_source_map (Isolate * isolate,
                                        Local<Script> script)
{
  auto url_value = script->GetUnboundScript ()->GetSourceMappingURL ();
  if (!url_value->IsString ())
    return NULL;

  String::Utf8Value url_utf8 (isolate, url_value);
  auto url = *url_utf8;

  if (!g_str_has_prefix (url, "data:application/json;"))
    return NULL;

  auto base64_start = strstr (url, "base64,");
  if (base64_start == NULL)
    return NULL;
  base64_start += 7;

  gchar * result;
  gsize size;
  auto data = (gchar *) g_base64_decode (base64_start, &size);
  if (data != NULL && g_utf8_validate (data, size, NULL))
    result = g_strndup (data, size);
  else
    result = NULL;
  g_free (data);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_next_tick)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F", &callback))
    return;

  core->current_scope->AddTickCallback (callback);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_pin)
{
  _gum_v8_core_pin (core);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_unpin)
{
  _gum_v8_core_unpin (core);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_bind_weak)
{
  Local<Value> target;
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "VF", &target, &callback))
    return;

  if (target->IsNullOrUndefined ())
  {
    _gum_v8_throw_ascii_literal (isolate, "expected a heap value");
    return;
  }

  auto id = ++core->last_weak_ref_id;

  auto ref = gum_v8_weak_ref_new (id, target, callback, core);
  g_hash_table_insert (core->weak_refs, GUINT_TO_POINTER (id), ref);

  info.GetReturnValue ().Set (id);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_unbind_weak)
{
  guint id;
  if (!_gum_v8_args_parse (args, "u", &id))
    return;

  bool removed = !!g_hash_table_remove (core->weak_refs, GUINT_TO_POINTER (id));
  info.GetReturnValue ().Set (removed);
}

static GumV8WeakRef *
gum_v8_weak_ref_new (guint id,
                     Local<Value> target,
                     Local<Function> callback,
                     GumV8Core * core)
{
  auto ref = g_slice_new (GumV8WeakRef);

  ref->id = id;
  ref->target = new Global<Value> (core->isolate, target);
  ref->target->SetWeak (ref, gum_v8_weak_ref_on_weak_notify,
      WeakCallbackType::kParameter);
  ref->callback = new Global<Function> (core->isolate, callback);

  ref->core = core;

  return ref;
}

static void
gum_v8_weak_ref_clear (GumV8WeakRef * ref)
{
  delete ref->target;
  ref->target = nullptr;
}

static void
gum_v8_weak_ref_free (GumV8WeakRef * ref)
{
  auto core = ref->core;

  gboolean in_teardown = ref->target == nullptr;

  gum_v8_weak_ref_clear (ref);

  g_queue_push_tail (&core->pending_weak_callbacks, ref->callback);
  if (!in_teardown && core->pending_weak_source == NULL)
  {
    auto source = g_idle_source_new ();
    g_source_set_callback (source,
        (GSourceFunc) gum_v8_core_invoke_pendi
"""


```