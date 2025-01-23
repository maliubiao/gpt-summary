Response:
The user wants a summary of the functionality of the provided C code file, `gumstalker-arm64.c`, which is part of the Frida dynamic instrumentation tool. The summary should include explanations related to reverse engineering, binary/OS concepts (Linux, Android), logical reasoning, common user errors, and debugging.

Here's a breakdown of the process:

1. **Identify the Core Functionality:** The file is named `gumstalker-arm64.c`, suggesting it implements the "stalker" component for the ARM64 architecture. Stalker is responsible for tracing and modifying code execution.

2. **Analyze Key Functions:** Go through the provided code snippets and identify the purpose of the main functions. Look for keywords and function names that reveal their actions (e.g., `follow`, `unfollow`, `exclude`, `invalidate`, `add_call_probe`, exception handling, memory management).

3. **Connect to Reverse Engineering:** Consider how the identified functionalities are relevant to reverse engineering tasks. For example, tracing execution flow, intercepting function calls, and modifying code are all core reverse engineering techniques.

4. **Identify Low-Level Concepts:** Look for interactions with operating system primitives, memory management functions, and CPU context manipulation. Specifically note any references to Linux or Android concepts.

5. **Infer Logical Reasoning:**  Analyze the control flow and data manipulation within the functions. Try to understand the assumptions and conditions under which certain actions are taken. This helps in understanding the logical "if-then-else" structures implicitly present.

6. **Consider User Errors:** Think about how a user might misuse the API provided by this code. Incorrectly specifying memory ranges, failing to manage resources, or misunderstanding the lifecycle of stalker objects are potential error scenarios.

7. **Trace User Interaction:** Imagine the steps a user would take to engage the stalker functionality, leading to the execution of this code. This helps in understanding the debugging context.

8. **Structure the Summary:** Organize the findings into logical categories as requested by the user.

**Pre-computation/Pre-analysis (Internal Thought Process):**

* **Exception Handling:** The presence of `__cxa_throw`, `__gxx_personality_v0`, `_Unwind_Find_FDE`, and `_Unwind_GetIP` clearly indicates exception handling support. The custom functions `gum_stalker_exception_personality`, `gum_stalker_exception_find_fde`, and `gum_stalker_exception_get_ip` suggest Frida is intercepting and potentially modifying the standard C++ exception handling mechanism.
* **Code Modification:** Functions like `gum_stalker_infect`, `gum_stalker_disinfect`, and the use of `GumArm64Writer` strongly point to dynamic code modification capabilities.
* **Thread Management:** Functions with `thread_id` arguments and the use of `gum_process_modify_thread` indicate the ability to interact with and modify the execution of specific threads.
* **Probing:** The `gum_stalker_add_call_probe` and `gum_stalker_remove_call_probe` functions clearly implement a mechanism for intercepting function calls.
* **Invalidation and Recompilation:** The `gum_stalker_invalidate` and `gum_stalker_recompile` functions suggest mechanisms for dealing with changes in the target process's code.
* **Memory Management:** The code interacts with `GumMemoryRange`, allocates memory (`gum_memory_allocate`), and manages code slabs, indicating a custom memory management system within Frida's stalker.

By focusing on these key areas and their interconnections, a comprehensive summary can be generated.
这是 `frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c` 文件的第二部分，它延续了 Frida 动态插桩工具中用于 ARM64 架构的 `GumStalker` 组件的实现。根据这部分代码，我们可以归纳出以下功能：

**核心功能延续：异常处理的集成**

这部分代码主要关注 `GumStalker` 如何与 C++ 异常处理机制进行集成，以便在被插桩的代码抛出异常时，`Stalker` 能够感知并进行相应的处理。

**具体功能点：**

1. **自定义 Personality 例程 (`gum_stalker_exception_personality`)**:
   - **功能**: 这是一个自定义的 `__gxx_personality_v0` 例程，用于处理 C++ 异常的展开 (unwinding) 过程。当被插桩的代码抛出异常时，标准的异常处理机制会调用 Personality 例程。Frida 提供了自定义的实现，以便在异常展开过程中有机会进行干预。
   - **逆向关系**: 在逆向分析中，理解程序的异常处理流程非常重要。Frida 通过 hook 异常处理的关键点，可以监控异常的抛出和捕获，甚至可以修改异常处理的行为。例如，可以记录异常的类型、抛出位置等信息，帮助分析程序在何种情况下会抛出异常。
   - **底层知识**: 这涉及到对 C++ ABI 中异常处理机制的理解，特别是 `__cxa_throw`、`__gxx_personality_v0` 以及 `_Unwind_` 系列函数的运作方式。在 Linux 和 Android 系统中，异常处理的实现依赖于 libunwind 库或类似的机制。
   - **逻辑推理 (假设输入与输出)**:
     - **假设输入**:  被插桩的代码执行过程中抛出一个 C++ 异常。
     - **输出**: `gum_stalker_exception_personality` 被调用，`context` 参数包含当前异常处理的上下文信息。根据 `actions` 和 `exception_class`，该函数可能会决定是否需要安装新的上下文 (`_URC_INSTALL_CONTEXT`)，并可能调用 `gum_exec_ctx_switch_block` 来切换执行上下文。
   - **用户错误**: 用户可能不理解 Frida 对异常处理的干预，导致在某些复杂的异常场景下出现意想不到的行为。例如，如果用户期望原始的异常处理流程，但 Frida 的 hook 改变了流程，可能会导致程序崩溃或行为异常。
   - **调试线索**: 用户在调试一个抛出异常的程序时，如果使用了 Frida 的 `Stalker`，可能会发现 `gum_stalker_exception_personality` 被调用。这可以作为 Frida 介入异常处理流程的线索。用户可以通过查看调用栈和相关参数来理解 Frida 在异常处理过程中做了什么。

2. **查找帧描述符条目 (`gum_stalker_exception_find_fde`)**:
   - **功能**:  该函数负责查找与给定程序计数器 (PC) 关联的帧描述符条目 (Frame Descriptor Entry, FDE)。FDE 包含了进行栈展开所需的信息。当异常发生时，异常处理机制需要找到当前函数的 FDE。
   - **逆向关系**: FDE 是栈展开的关键数据结构。逆向工程师可以通过分析 FDE 来理解函数的栈帧结构，例如局部变量的布局、返回地址的位置等。Frida 通过自定义的 FDE 查找机制，可以确保在插桩代码的环境中，栈展开能够正确进行。
   - **底层知识**: 这涉及到对 DWARF 调试信息格式以及异常处理表 (Exception Handling Tables, e.g., `.eh_frame`) 的理解。在 ARM64 架构上，异常处理信息的组织方式遵循特定的 ABI 规范。
   - **逻辑推理 (假设输入与输出)**:
     - **假设输入**:  一个程序计数器 `pc`，指向抛出异常的指令的末尾。
     - **输出**: 该函数会尝试在 `Stalker` 的上下文中找到与该 `pc` 关联的 FDE。如果 `Stalker` 正在跟踪该地址，可能会返回一个经过转换的地址的 FDE。如果找不到，则调用默认的 `_Unwind_Find_FDE`。
   - **用户错误**:  如果用户错误地排除了包含异常处理表的内存区域，可能导致 `gum_stalker_exception_find_fde` 无法找到正确的 FDE，从而导致程序崩溃。
   - **调试线索**: 如果在异常处理过程中出现栈展开错误，可以检查 `gum_stalker_exception_find_fde` 的行为，查看它返回的 FDE 是否正确。

3. **获取指令指针 (`gum_stalker_exception_get_ip`)**:
   - **功能**:  该函数用于获取当前异常处理上下文中的指令指针 (IP)。
   - **逆向关系**: IP 是程序执行的关键信息。在异常处理过程中，获取正确的 IP 对于栈展开和恢复程序状态至关重要。
   - **底层知识**: 这涉及到对 `_Unwind_Context` 结构以及如何从该结构中获取 IP 的理解。
   - **逻辑推理 (假设输入与输出)**:
     - **假设输入**:  一个 `_Unwind_Context` 指针。
     - **输出**:  该函数会尝试从 `Stalker` 的上下文中获取与该上下文关联的真实 IP。如果 `Stalker` 正在跟踪，可能会返回一个经过转换的地址。否则，返回默认的 IP。
   - **用户错误**:  用户如果错误地修改了 `Stalker` 的状态，可能会导致该函数返回错误的 IP，影响异常处理流程。
   - **调试线索**: 在调试异常处理相关问题时，可以检查 `gum_stalker_exception_get_ip` 返回的值，确保它与预期的执行位置一致。

**与逆向方法的关联举例说明：**

* **监控异常抛出**: 逆向工程师可以使用 Frida hook `__cxa_throw` 函数，然后在 `gum_stalker_exception_personality` 中记录异常的类型和抛出位置，从而了解程序在哪些条件下会抛出异常。
* **修改异常处理流程**: 可以修改 `gum_stalker_exception_personality` 的行为，例如阻止某些异常的展开，或者在异常发生时执行自定义的代码。这可以用于绕过某些反调试机制或修改程序的错误处理逻辑。
* **分析栈帧结构**: 通过分析 `gum_stalker_exception_find_fde` 如何查找 FDE，可以更深入地理解目标程序的栈帧布局和异常处理表的结构。

**涉及的二进制底层、Linux、Android 内核及框架知识举例说明：**

* **ARM64 异常处理 ABI**: 这部分代码直接操作了 ARM64 架构的异常处理相关的寄存器和数据结构，例如 `_Unwind_Context`。
* **libunwind**: 在 Linux 和 Android 系统中，C++ 异常处理通常依赖于 libunwind 库。`_Unwind_Find_FDE` 和 `_Unwind_GetIP` 等函数是 libunwind 提供的接口。
* **DWARF 调试信息**: FDE 是 DWARF 调试信息的一部分。理解 DWARF 格式对于理解异常处理的底层机制至关重要。
* **Linux 系统调用**: 尽管这段代码没有直接展示系统调用，但异常处理本身可能会涉及到一些底层的系统调用，例如在栈展开过程中可能需要访问内存映射信息。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户使用 Frida 连接到目标进程**: 用户编写 Frida 脚本，使用 `frida.attach()` 或 `frida.spawn()` 连接到目标进程。
2. **用户启用 `Stalker`**:  在 Frida 脚本中，用户创建并启动 `Stalker` 对象，例如 `Stalker.follow(threadId, { transform: ... })`。
3. **目标进程执行代码并抛出 C++ 异常**:  目标进程执行到某处，触发了一个 C++ 异常，调用了 `__cxa_throw`。
4. **异常处理机制启动**:  系统开始进行异常展开流程，并调用 Personality 例程。由于 Frida 的 `Stalker` 已经 hook 了相关的异常处理函数，因此会调用 `gum_stalker_exception_personality`。
5. **`gum_stalker_exception_find_fde` 被调用**: 在异常展开过程中，需要查找当前函数的 FDE，因此会调用 `gum_stalker_exception_find_fde`。
6. **`gum_stalker_exception_get_ip` 被调用**: 在处理异常的过程中，可能需要获取当前的指令指针，这时会调用 `gum_stalker_exception_get_ip`。

因此，当用户在调试一个使用了 Frida 的 `Stalker` 进行插桩，并且抛出了 C++ 异常的程序时，就很有可能进入到这部分代码中。调试器可能会停在这些自定义的异常处理函数中，用户可以通过查看调用栈和相关变量来理解 Frida 在异常处理过程中的干预。

**第 2 部分功能归纳：**

这部分 `gumstalker-arm64.c` 代码实现了 `GumStalker` 对 C++ 异常处理机制的集成，通过提供自定义的 Personality 例程、FDE 查找和 IP 获取函数，使得 Frida 能够在被插桩的 ARM64 程序抛出异常时进行感知和干预，从而支持更复杂的动态分析和修改场景。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
exception_class,
        unwind_exception, context);
  }

  _Unwind_SetIP (context, GPOINTER_TO_SIZE (real_throw_ip));

  reason = __gxx_personality_v0 (version, actions, exception_class,
      unwind_exception, context);
  if (reason == _URC_INSTALL_CONTEXT)
  {
    gpointer real_resume_ip, resume_ip;

    real_resume_ip = GSIZE_TO_POINTER (_Unwind_GetIP (context));

    resume_ip = gum_exec_ctx_switch_block (ctx, NULL, real_resume_ip, NULL);
    _Unwind_SetIP (context, GPOINTER_TO_SIZE (resume_ip));

    ctx->pending_calls--;
  }

  return reason;
}

static const void *
gum_stalker_exception_find_fde (const void * pc,
                                struct dwarf_eh_bases * bases)
{
  GumExecCtx * ctx;
  gpointer real_address;

  /*
   * This function is responsible for finding the Frame Descriptor Entry
   * associated with a given exception. To do this, it is provided with the PC
   * of the entry to find.
   *
   * The PC provided is the address of the last byte of the instruction which
   * called __cxa_throw. Since we store the address of the next instruction in
   * our hashtable, (this is used by the personality function) we need to add 1
   * to the value provided before we perform the lookup and subsequently
   * subtract one from the value retrieved.
   *
   * If an exception is thrown whilst there is a code (rather than real) address
   * in our stack (to allow us to execute excluded ranges), then the translation
   * from code address to real address should have been inserted into the
   * hashtable when the instrumented code was written. The _Unwind_Find_FDE
   * function will be called with a code address (rather than the real address)
   * which would usually fail, when this happends we need to translate the
   * address before the call. If we have no associated entry in our lookup, then
   * we can let the call proceed as normal.
   */

  ctx = gum_stalker_get_exec_ctx ();
  if (ctx == NULL)
    return _Unwind_Find_FDE (pc, bases);

  real_address = gum_metal_hash_table_lookup (ctx->excluded_calls, pc + 1);

  if (real_address == NULL)
  {
    real_address = gum_invocation_stack_translate (
        gum_interceptor_get_current_stack (), (gpointer) pc + 1);
    if (real_address == NULL)
      return _Unwind_Find_FDE (pc, bases);
  }

  return _Unwind_Find_FDE (real_address - 1, bases);
}

static unsigned long
gum_stalker_exception_get_ip (struct _Unwind_Context * context)
{
  GumExecCtx * ctx;
  gpointer ip, real_address;

  ctx = gum_stalker_get_exec_ctx ();
  if (ctx == NULL)
    return _Unwind_GetIP (context);

  ip = GSIZE_TO_POINTER (_Unwind_GetIP (context));

  real_address = gum_metal_hash_table_lookup (ctx->excluded_calls, ip);
  if (real_address == NULL)
  {
    real_address = gum_invocation_stack_translate (
        gum_interceptor_get_current_stack (), ip);
    if (real_address == NULL)
      return GPOINTER_TO_SIZE (ip);
  }

  return GPOINTER_TO_SIZE (real_address);
}

#endif

static void
gum_stalker_dispose (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);

  if (self->exceptor != NULL)
  {
    gum_exceptor_remove (self->exceptor, gum_stalker_on_exception, self);
    g_object_unref (self->exceptor);
    self->exceptor = NULL;
  }

  G_OBJECT_CLASS (gum_stalker_parent_class)->dispose (object);
}

static void
gum_stalker_finalize (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);

  g_hash_table_unref (self->probe_array_by_address);
  g_hash_table_unref (self->probe_target_by_id);

  g_array_free (self->exclusions, TRUE);

  g_assert (self->contexts == NULL);
  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_stalker_parent_class)->finalize (object);
}

static void
gum_stalker_get_property (GObject * object,
                          guint property_id,
                          GValue * value,
                          GParamSpec * pspec)
{
  GumStalker * self = GUM_STALKER (object);

  switch (property_id)
  {
    case PROP_IC_ENTRIES:
      g_value_set_uint (value, self->ic_entries);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_stalker_set_property (GObject * object,
                          guint property_id,
                          const GValue * value,
                          GParamSpec * pspec)
{
  GumStalker * self = GUM_STALKER (object);

  switch (property_id)
  {
    case PROP_IC_ENTRIES:
      self->ic_entries = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumStalker *
gum_stalker_new (void)
{
  return g_object_new (GUM_TYPE_STALKER, NULL);
}

void
gum_stalker_exclude (GumStalker * self,
                     const GumMemoryRange * range)
{
  g_array_append_val (self->exclusions, *range);
}

static gboolean
gum_stalker_is_excluding (GumStalker * self,
                          gconstpointer address)
{
  GArray * exclusions = self->exclusions;
  guint i;

  for (i = 0; i != exclusions->len; i++)
  {
    GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (address)))
      return TRUE;
  }

  return FALSE;
}

gint
gum_stalker_get_trust_threshold (GumStalker * self)
{
  return self->trust_threshold;
}

void
gum_stalker_set_trust_threshold (GumStalker * self,
                                 gint trust_threshold)
{
  self->trust_threshold = trust_threshold;
}

void
gum_stalker_flush (GumStalker * self)
{
  GSList * sinks, * cur;

  GUM_STALKER_LOCK (self);

  sinks = NULL;
  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;

    sinks = g_slist_prepend (sinks, g_object_ref (ctx->sink));
  }

  GUM_STALKER_UNLOCK (self);

  for (cur = sinks; cur != NULL; cur = cur->next)
  {
    GumEventSink * sink = cur->data;

    gum_event_sink_flush (sink);
  }

  g_slist_free_full (sinks, g_object_unref);
}

void
gum_stalker_stop (GumStalker * self)
{
  GSList * cur;

  gum_spinlock_acquire (&self->probe_lock);
  g_hash_table_remove_all (self->probe_target_by_id);
  g_hash_table_remove_all (self->probe_array_by_address);
  self->any_probes_attached = FALSE;
  gum_spinlock_release (&self->probe_lock);

rescan:
  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;

    if (g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_ACTIVE)
    {
      GumThreadId thread_id = ctx->thread_id;

      GUM_STALKER_UNLOCK (self);

      gum_stalker_unfollow (self, thread_id);

      goto rescan;
    }
  }

  GUM_STALKER_UNLOCK (self);

  gum_stalker_garbage_collect (self);
}

gboolean
gum_stalker_garbage_collect (GumStalker * self)
{
  gboolean have_pending_garbage;
  GumThreadId current_thread_id;
  gint64 now;
  GSList * cur;

  current_thread_id = gum_process_get_current_thread_id ();
  now = g_get_monotonic_time ();

rescan:
  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * ctx = cur->data;
    gboolean destroy_pending_and_thread_likely_back_in_original_code;

    destroy_pending_and_thread_likely_back_in_original_code =
        g_atomic_int_get (&ctx->state) == GUM_EXEC_CTX_DESTROY_PENDING &&
        (ctx->thread_id == current_thread_id ||
        now - ctx->destroy_pending_since > 20000);

    if (destroy_pending_and_thread_likely_back_in_original_code ||
        !gum_process_has_thread (ctx->thread_id))
    {
      GUM_STALKER_UNLOCK (self);

      gum_stalker_destroy_exec_ctx (self, ctx);

      goto rescan;
    }
  }

  have_pending_garbage = self->contexts != NULL;

  GUM_STALKER_UNLOCK (self);

  return have_pending_garbage;
}

gpointer
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           gpointer ret_addr)
{
  GumExecCtx * ctx;
  gpointer code_address;

  ctx = gum_stalker_create_exec_ctx (self, gum_process_get_current_thread_id (),
      transformer, sink);
  g_private_set (&gum_stalker_exec_ctx_private, ctx);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, ret_addr,
      &code_address);

  if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return ret_addr;
  }

  gum_event_sink_start (ctx->sink);
  ctx->sink_started = TRUE;

  return (guint8 *) code_address + GUM_RESTORATION_PROLOG_SIZE;
}

void
gum_stalker_unfollow_me (GumStalker * self)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx ();
  if (ctx == NULL)
    return;

  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_UNFOLLOW_PENDING);

  if (!gum_exec_ctx_maybe_unfollow (ctx, NULL))
    return;

  g_assert (ctx->unfollow_called_while_still_following);

  gum_stalker_destroy_exec_ctx (self, ctx);
}

gboolean
gum_stalker_is_following_me (GumStalker * self)
{
  return gum_stalker_get_exec_ctx () != NULL;
}

void
gum_stalker_follow (GumStalker * self,
                    GumThreadId thread_id,
                    GumStalkerTransformer * transformer,
                    GumEventSink * sink)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_follow_me (self, transformer, sink);
  }
  else
  {
    GumInfectContext ctx;

    ctx.stalker = self;
    ctx.transformer = transformer;
    ctx.sink = sink;

    gum_process_modify_thread (thread_id, gum_stalker_infect, &ctx,
        GUM_MODIFY_THREAD_FLAGS_NONE);
  }
}

void
gum_stalker_unfollow (GumStalker * self,
                      GumThreadId thread_id)
{
  if (thread_id == gum_process_get_current_thread_id ())
  {
    gum_stalker_unfollow_me (self);
  }
  else
  {
    GumExecCtx * ctx;

    ctx = gum_stalker_find_exec_ctx_by_thread_id (self, thread_id);
    if (ctx == NULL)
      return;

    if (!g_atomic_int_compare_and_exchange (&ctx->state, GUM_EXEC_CTX_ACTIVE,
        GUM_EXEC_CTX_UNFOLLOW_PENDING))
      return;

    if (!gum_exec_ctx_has_executed (ctx))
    {
      GumDisinfectContext dc;

      dc.exec_ctx = ctx;
      dc.success = FALSE;

      gum_process_modify_thread (thread_id, gum_stalker_disinfect, &dc,
          GUM_MODIFY_THREAD_FLAGS_NONE);

      if (dc.success)
        gum_stalker_destroy_exec_ctx (self, ctx);
    }
  }
}

static void
gum_stalker_infect (GumThreadId thread_id,
                    GumCpuContext * cpu_context,
                    gpointer user_data)
{
  GumInfectContext * infect_context = user_data;
  GumStalker * self = infect_context->stalker;
  GumExecCtx * ctx;
  guint8 * pc;
  gpointer code_address;
  GumArm64Writer * cw;
  const guint potential_svc_size = 4;

  ctx = gum_stalker_create_exec_ctx (self, thread_id,
      infect_context->transformer, infect_context->sink);

  pc = GSIZE_TO_POINTER (gum_strip_code_address (cpu_context->pc));

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, pc, &code_address);

  if (gum_exec_ctx_maybe_unfollow (ctx, NULL))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return;
  }

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (self, ctx->thunks, self->thunks_size);
  cw = &ctx->code_writer;
  gum_arm64_writer_reset (cw, ctx->infect_thunk);

  /*
   * In case the thread is in a Linux system call we should allow it to be
   * restarted by bringing along the SVC instruction.
   */
  gum_arm64_writer_put_bytes (cw, pc - potential_svc_size, potential_svc_size);

  ctx->infect_body = GUM_ADDRESS (gum_arm64_writer_cur (cw));
#ifdef HAVE_PTRAUTH
  ctx->infect_body = GPOINTER_TO_SIZE (ptrauth_sign_unauthenticated (
      GSIZE_TO_POINTER (ctx->infect_body), ptrauth_key_process_independent_code,
      ptrauth_string_discriminator ("pc")));
#endif
  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);
  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (g_private_set), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (&gum_stalker_exec_ctx_private),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_arm64_writer_put_b_imm (cw, GUM_ADDRESS (code_address) +
      GUM_RESTORATION_PROLOG_SIZE);

  gum_arm64_writer_flush (cw);
  gum_stalker_freeze (self, cw->base, gum_arm64_writer_offset (cw));

  gum_spinlock_release (&ctx->code_lock);

  gum_event_sink_start (ctx->sink);
  ctx->sink_started = TRUE;

  cpu_context->pc = ctx->infect_body;
}

static void
gum_stalker_disinfect (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  GumDisinfectContext * disinfect_context = user_data;
  GumExecCtx * ctx = disinfect_context->exec_ctx;
  gboolean infection_not_active_yet;

  infection_not_active_yet = cpu_context->pc == ctx->infect_body;
  if (infection_not_active_yet)
  {
    cpu_context->pc = gum_sign_code_address (
        GPOINTER_TO_SIZE (ctx->current_block->real_start));

    disinfect_context->success = TRUE;
  }
}

gpointer
_gum_stalker_do_activate (GumStalker * self,
                          gconstpointer target,
                          gpointer ret_addr)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx ();
  if (ctx == NULL)
    return ret_addr;

  ctx->unfollow_called_while_still_following = FALSE;
  ctx->activation_target = gum_strip_code_pointer ((gpointer) target);

  if (!gum_exec_ctx_contains (ctx, ret_addr))
  {
    gpointer code_address;

    ctx->current_block =
        gum_exec_ctx_obtain_block_for (ctx, ret_addr, &code_address);

    if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
      return ret_addr;

    return (guint8 *) code_address + GUM_RESTORATION_PROLOG_SIZE;
  }

  return ret_addr;
}

gpointer
_gum_stalker_do_deactivate (GumStalker * self,
                            gpointer ret_addr)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx ();
  if (ctx == NULL)
    return ret_addr;

  ctx->unfollow_called_while_still_following = TRUE;
  ctx->activation_target = NULL;

  if (gum_exec_ctx_contains (ctx, ret_addr))
  {
    ctx->pending_calls--;

    return ctx->pending_return_location;
  }

  return ret_addr;
}

static void
gum_stalker_maybe_deactivate (GumStalker * self,
                              GumActivation * activation)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx ();
  activation->ctx = ctx;

  if (ctx != NULL && ctx->pending_calls == 0)
  {
    activation->pending = TRUE;
    activation->target = ctx->activation_target;

    gum_stalker_deactivate (self);
  }
  else
  {
    activation->pending = FALSE;
    activation->target = NULL;
  }
}

static void
gum_stalker_maybe_reactivate (GumStalker * self,
                              GumActivation * activation)
{
  if (activation->pending)
    gum_stalker_activate (self, activation->target);
}

void
gum_stalker_set_observer (GumStalker * self,
                          GumStalkerObserver * observer)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx ();
  g_assert (ctx != NULL);

  if (observer != NULL)
    g_object_ref (observer);
  if (ctx->observer != NULL)
    g_object_unref (ctx->observer);
  ctx->observer = observer;
}

void
gum_stalker_prefetch (GumStalker * self,
                      gconstpointer address,
                      gint recycle_count)
{
  GumExecCtx * ctx;
  GumExecBlock * block;
  gpointer code_address;

  ctx = gum_stalker_get_exec_ctx ();
  g_assert (ctx != NULL);

  block = gum_exec_ctx_obtain_block_for (ctx, (gpointer) address,
      &code_address);
  block->recycle_count = recycle_count;
}

/*
 * This function is intended to be called in the forkserver parent when fuzzing
 * to apply backpatches which have been learnt by the child process (so that we
 * don't lose and have to regenerate those patches each time a new child is
 * spawned). The child will call a function of the Observer providing the opaque
 * GumBackpatch structure containing the necessary information to allow the
 * patch to be re-created in the parent. The mechanics of how these GumBackpatch
 * structures are communictated from the Observer running in the child back to
 * code running in the parent are left to the integrator.
 */
void
gum_stalker_prefetch_backpatch (GumStalker * self,
                                const GumBackpatch * backpatch)
{
  GumExecCtx * ctx;
  GumExecBlock * block_to, * block_from;
  gpointer code_address_to, code_address_from;
  gpointer from_insn = backpatch->from_insn;

  ctx = gum_stalker_get_exec_ctx ();
  g_assert (ctx != NULL);

  block_to = gum_exec_ctx_obtain_block_for (ctx, backpatch->to,
      &code_address_to);
  block_from = gum_exec_ctx_obtain_block_for (ctx, backpatch->from,
      &code_address_from);

  block_to->recycle_count = self->trust_threshold;
  block_from->recycle_count = self->trust_threshold;

  switch (backpatch->type)
  {
    case GUM_BACKPATCH_CALL:
    {
      const GumBackpatchCall * call = &backpatch->call;
      gum_exec_block_backpatch_call (block_to, block_from, from_insn,
          call->code_offset, call->opened_prolog, call->ret_real_address);
      break;
    }
    case GUM_BACKPATCH_JMP:
    {
      const GumBackpatchJmp * jmp = &backpatch->jmp;
      gum_exec_block_backpatch_jmp (block_to, block_from, from_insn,
          jmp->code_offset, jmp->opened_prolog);
      break;
    }
    case GUM_BACKPATCH_INLINE_CACHE:
    {
      gum_exec_block_backpatch_inline_cache (block_to, block_from, from_insn);
      break;
    }
    case GUM_BACKPATCH_EXCLUDED_CALL:
    {
      /*
       * Note that for excluded calls we don't have a target block as our
       * destination. We don't compile a GumExecBlock for an excluded range, but
       * rather allow the target to execute the original real code instead. Thus
       * the arguments here are little asymmetric to those above.
       */
      gum_exec_block_backpatch_excluded_call (block_from, backpatch->to,
          from_insn);
    }
    default:
      g_assert_not_reached ();
      break;
  }
}

void
gum_stalker_recompile (GumStalker * self,
                       gconstpointer address)
{
  GumExecCtx * ctx;
  GumExecBlock * block;

  ctx = gum_stalker_get_exec_ctx ();
  g_assert (ctx != NULL);

  block = gum_metal_hash_table_lookup (ctx->mappings, address);
  if (block == NULL)
    return;

  gum_exec_ctx_recompile_block (ctx, block);
}

gpointer
gum_stalker_backpatch_get_from (const GumBackpatch * backpatch)
{
  return backpatch->from;
}

gpointer
gum_stalker_backpatch_get_to (const GumBackpatch * backpatch)
{
  return backpatch->to;
}

void
gum_stalker_invalidate (GumStalker * self,
                        gconstpointer address)
{
  GumActivation activation;

  gum_stalker_maybe_deactivate (self, &activation);
  if (activation.ctx == NULL)
    return;

  gum_stalker_do_invalidate (activation.ctx, address, &activation);

  gum_stalker_maybe_reactivate (self, &activation);
}

void
gum_stalker_invalidate_for_thread (GumStalker * self,
                                   GumThreadId thread_id,
                                   gconstpointer address)
{
  GumActivation activation;
  GumExecCtx * ctx;

  gum_stalker_maybe_deactivate (self, &activation);

  ctx = gum_stalker_find_exec_ctx_by_thread_id (self, thread_id);
  if (ctx != NULL)
  {
    while (!gum_stalker_do_invalidate (ctx, address, &activation))
    {
      g_thread_yield ();
    }
  }

  gum_stalker_maybe_reactivate (self, &activation);
}

static void
gum_stalker_invalidate_for_all_threads (GumStalker * self,
                                        gconstpointer address,
                                        GumActivation * activation)
{
  GSList * contexts, * cur;

  GUM_STALKER_LOCK (self);
  contexts = g_slist_copy (self->contexts);
  GUM_STALKER_UNLOCK (self);

  cur = contexts;

  while (cur != NULL)
  {
    GumExecCtx * ctx = cur->data;
    GSList * l;

    if (!gum_stalker_do_invalidate (ctx, address, activation))
    {
      cur = g_slist_append (cur, ctx);
    }

    l = cur;
    cur = cur->next;
    g_slist_free_1 (l);
  }
}

static gboolean
gum_stalker_do_invalidate (GumExecCtx * ctx,
                           gconstpointer address,
                           GumActivation * activation)
{
  GumInvalidateContext ic;

  ic.is_executing_target_block = FALSE;

  gum_spinlock_acquire (&ctx->code_lock);

  if ((ic.block = gum_metal_hash_table_lookup (ctx->mappings, address)) != NULL)
  {
    if (ctx == activation->ctx)
    {
      gum_exec_block_invalidate (ic.block);
    }
    else
    {
      gum_process_modify_thread (ctx->thread_id,
          gum_stalker_try_invalidate_block_owned_by_thread, &ic,
          GUM_MODIFY_THREAD_FLAGS_NONE);
    }
  }

  gum_spinlock_release (&ctx->code_lock);

  return !ic.is_executing_target_block;
}

static void
gum_stalker_try_invalidate_block_owned_by_thread (GumThreadId thread_id,
                                                  GumCpuContext * cpu_context,
                                                  gpointer user_data)
{
  GumInvalidateContext * ic = user_data;
  GumExecBlock * block = ic->block;
  const guint8 * pc = GSIZE_TO_POINTER (cpu_context->pc);

  if (pc >= block->code_start &&
      pc < block->code_start + GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE)
  {
    ic->is_executing_target_block = TRUE;
    return;
  }

  gum_exec_block_invalidate (block);
}

GumProbeId
gum_stalker_add_call_probe (GumStalker * self,
                            gpointer target_address,
                            GumCallProbeCallback callback,
                            gpointer data,
                            GDestroyNotify notify)
{
  GumActivation activation;
  GumCallProbe * probe;
  GPtrArray * probes;
  gboolean is_first_for_target;

  gum_stalker_maybe_deactivate (self, &activation);

  target_address = gum_strip_code_pointer (target_address);
  is_first_for_target = FALSE;

  probe = g_slice_new (GumCallProbe);
  probe->ref_count = 1;
  probe->id = g_atomic_int_add (&self->last_probe_id, 1) + 1;
  probe->callback = callback;
  probe->user_data = data;
  probe->user_notify = notify;

  gum_spinlock_acquire (&self->probe_lock);

  g_hash_table_insert (self->probe_target_by_id, GSIZE_TO_POINTER (probe->id),
      target_address);

  probes = g_hash_table_lookup (self->probe_array_by_address, target_address);
  if (probes == NULL)
  {
    probes =
        g_ptr_array_new_with_free_func ((GDestroyNotify) gum_call_probe_unref);
    g_hash_table_insert (self->probe_array_by_address, target_address, probes);

    is_first_for_target = TRUE;
  }

  g_ptr_array_add (probes, probe);

  self->any_probes_attached = TRUE;

  gum_spinlock_release (&self->probe_lock);

  if (is_first_for_target)
    gum_stalker_invalidate_for_all_threads (self, target_address, &activation);

  gum_stalker_maybe_reactivate (self, &activation);

  return probe->id;
}

void
gum_stalker_remove_call_probe (GumStalker * self,
                               GumProbeId id)
{
  GumActivation activation;
  gpointer target_address;
  gboolean is_last_for_target;

  gum_stalker_maybe_deactivate (self, &activation);

  gum_spinlock_acquire (&self->probe_lock);

  target_address =
      g_hash_table_lookup (self->probe_target_by_id, GSIZE_TO_POINTER (id));
  is_last_for_target = FALSE;

  if (target_address != NULL)
  {
    GPtrArray * probes;
    gint match_index = -1;
    guint i;

    g_hash_table_remove (self->probe_target_by_id, GSIZE_TO_POINTER (id));

    probes = g_hash_table_lookup (self->probe_array_by_address, target_address);
    g_assert (probes != NULL);

    for (i = 0; i != probes->len; i++)
    {
      GumCallProbe * probe = g_ptr_array_index (probes, i);
      if (probe->id == id)
      {
        match_index = i;
        break;
      }
    }
    g_assert (match_index != -1);

    g_ptr_array_remove_index (probes, match_index);

    if (probes->len == 0)
    {
      g_hash_table_remove (self->probe_array_by_address, target_address);

      is_last_for_target = TRUE;
    }

    self->any_probes_attached =
        g_hash_table_size (self->probe_array_by_address) != 0;
  }

  gum_spinlock_release (&self->probe_lock);

  if (is_last_for_target)
    gum_stalker_invalidate_for_all_threads (self, target_address, &activation);

  gum_stalker_maybe_reactivate (self, &activation);
}

static void
gum_call_probe_finalize (GumCallProbe * probe)
{
  if (probe->user_notify != NULL)
    probe->user_notify (probe->user_data);
}

static GumCallProbe *
gum_call_probe_ref (GumCallProbe * probe)
{
  g_atomic_int_inc (&probe->ref_count);

  return probe;
}

static void
gum_call_probe_unref (GumCallProbe * probe)
{
  if (g_atomic_int_dec_and_test (&probe->ref_count))
  {
    gum_call_probe_finalize (probe);
  }
}

void
_gum_stalker_modify_to_run_on_thread (GumStalker * self,
                                      GumThreadId thread_id,
                                      GumCpuContext * cpu_context,
                                      GumStalkerRunOnThreadFunc func,
                                      gpointer data)
{
  GumExecCtx * ctx;
  GumAddress pc;
  GumArm64Writer * cw;
  GumAddress cpu_context_copy;

  ctx = gum_stalker_create_exec_ctx (self, thread_id, NULL, NULL);

  pc = gum_strip_code_address (cpu_context->pc);

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (self, ctx->thunks, self->thunks_size);
  cw = &ctx->code_writer;
  gum_arm64_writer_reset (cw, ctx->infect_thunk);

  cpu_context_copy = GUM_ADDRESS (gum_arm64_writer_cur (cw));
  gum_arm64_writer_put_bytes (cw, (guint8 *) cpu_context,
      sizeof (GumCpuContext));

  ctx->infect_body = GUM_ADDRESS (gum_arm64_writer_cur (cw));

#ifdef HAVE_PTRAUTH
  ctx->infect_body = GPOINTER_TO_SIZE (ptrauth_sign_unauthenticated (
      GSIZE_TO_POINTER (ctx->infect_body),
      ptrauth_key_process_independent_code,
      ptrauth_string_discriminator ("pc")));
#endif
  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (func), 2,
      GUM_ARG_ADDRESS, cpu_context_copy,
      GUM_ARG_ADDRESS, GUM_ADDRESS (data));

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, pc);

  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);

  /*
   * Here we spoil x17 since this is a necessity of the AARCH64 architecture
   * when performing long branches. However, the documentation states...
   *
   * "Registers r16 (IP0) and r17 (IP1) may be used by a linker as a scratch
   *  register between a routine and any subroutine it calls."
   *
   * This same approach is used elsewhere in Stalker for arm64.
   */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X17, pc);
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);

  gum_arm64_writer_flush (cw);
  gum_stalker_freeze (self, cw->base, gum_arm64_writer_offset (cw));

  gum_spinlock_release (&ctx->code_lock);

  cpu_context->pc = ctx->infect_body;
}

static GumExecCtx *
gum_stalker_create_exec_ctx (GumStalker * self,
                             GumThreadId thread_id,
                             GumStalkerTransformer * transformer,
                             GumEventSink * sink)
{
  GumExecCtx * ctx = gum_exec_ctx_new (self, thread_id, transformer, sink);

  GUM_STALKER_LOCK (self);
  self->contexts = g_slist_prepend (self->contexts, ctx);
  GUM_STALKER_UNLOCK (self);

  return ctx;
}

static void
gum_stalker_destroy_exec_ctx (GumStalker * self,
                              GumExecCtx * ctx)
{
  GSList * entry;

  GUM_STALKER_LOCK (self);
  entry = g_slist_find (self->contexts, ctx);
  if (entry != NULL)
    self->contexts = g_slist_delete_link (self->contexts, entry);
  GUM_STALKER_UNLOCK (self);

  /* Racy due to garbage-collection. */
  if (entry == NULL)
    return;

  gum_exec_ctx_dispose (ctx);

  if (ctx->sink_started)
  {
    gum_event_sink_stop (ctx->sink);

    ctx->sink_started = FALSE;
  }

  gum_exec_ctx_free (ctx);
}

static GumExecCtx *
gum_stalker_get_exec_ctx (void)
{
  return g_private_get (&gum_stalker_exec_ctx_private);
}

static GumExecCtx *
gum_stalker_find_exec_ctx_by_thread_id (GumStalker * self,
                                        GumThreadId thread_id)
{
  GumExecCtx * ctx = NULL;
  GSList * cur;

  GUM_STALKER_LOCK (self);

  for (cur = self->contexts; cur != NULL; cur = cur->next)
  {
    GumExecCtx * candidate = cur->data;

    if (candidate->thread_id == thread_id)
    {
      ctx = candidate;
      break;
    }
  }

  GUM_STALKER_UNLOCK (self);

  return ctx;
}

static gsize
gum_stalker_snapshot_space_needed_for (GumStalker * self,
                                       gsize real_size)
{
  return (self->trust_threshold != 0) ? real_size : 0;
}

static gsize
gum_stalker_get_ic_entry_size (GumStalker * self)
{
  return self->ic_entries * sizeof (GumIcEntry);
}

static void
gum_stalker_thaw (GumStalker * self,
                  gpointer code,
                  gsize size)
{
  if (size == 0)
    return;

  if (!self->is_rwx_supported)
    gum_mprotect (code, size, GUM_PAGE_RW);
}

static void
gum_stalker_freeze (GumStalker * self,
                    gpointer code,
                    gsize size)
{
  if (size == 0)
  {
    if (!self->is_rwx_supported)
    {
      guint page_offset = GPOINTER_TO_SIZE (code) & (self->page_size - 1);
      if (page_offset != 0)
      {
        gum_memory_mark_code ((guint8 *) code - page_offset,
            self->page_size - page_offset);
      }
    }

    return;
  }

  if (!self->is_rwx_supported)
    gum_memory_mark_code (code, size);

  gum_clear_cache (code, size);
}

static gboolean
gum_stalker_on_exception (GumExceptionDetails * details,
                          gpointer user_data)
{
  GumStalker * self = user_data;
  GumExecCtx * ctx;

  ctx = gum_stalker_find_exec_ctx_by_thread_id (self, details->thread_id);
  if (ctx == NULL)
    return FALSE;

  return gum_exec_ctx_try_handle_exception (ctx, details);
}

static GumExecCtx *
gum_exec_ctx_new (GumStalker * stalker,
                  GumThreadId thread_id,
                  GumStalkerTransformer * transformer,
                  GumEventSink * sink)
{
  GumExecCtx * ctx;
  guint8 * base;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumDataSlab * data_slab;

  base = gum_memory_allocate (NULL, stalker->ctx_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  ctx = (GumExecCtx *) base;

  ctx->state = GUM_EXEC_CTX_ACTIVE;

  ctx->stalker = g_object_ref (stalker);
  ctx->thread_id = thread_id;

  gum_arm64_writer_init (&ctx->code_writer, NULL);
  gum_arm64_writer_init (&ctx->slow_writer, NULL);
  gum_arm64_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

  if (transformer != NULL)
    ctx->transformer = g_object_ref (transformer);
  else
    ctx->transformer = gum_stalker_transformer_make_default ();
  ctx->transform_block_impl =
      GUM_STALKER_TRANSFORMER_GET_IFACE (ctx->transformer)->transform_block;

  if (sink != NULL)
    ctx->sink = g_object_ref (sink);
  else
    ctx->sink = gum_event_sink_make_default ();

  ctx->sink_mask = gum_event_sink_query_mask (ctx->sink);
  ctx->sink_process_impl = GUM_EVENT_SINK_GET_IFACE (ctx->sink)->process;

  ctx->observer = NULL;

  ctx->thunks = base + stalker->thunks_offset;
  ctx->infect_thunk = ctx->thunks;

  gum_spinlock_init (&ctx->code_lock);

  code_slab = (GumCodeSlab *) (base + stalker->code_slab_offset);
  gum_code_slab_init (code_slab, stalker->code_slab_size_initial, 0,
      stalker->page_size);
  gum_exec_ctx_add_code_slab (ctx, code_slab);

  slow_slab = (GumSlowSlab *) (base + stalker->slow_slab_offset);
  gum_slow_slab_init (slow_slab, stalker->slow_slab_size_initial, 0,
      stalker->page_size);
  gum_exec_ctx_add_slow_slab (ctx, slow_slab);

  data_slab = (GumDataSlab *) (base + stalker->data_slab_offset);
  gum_data_slab_init (data_slab, stalker->data_slab_size_initial, 0);
  gum_exec_ctx_add_data_slab (ctx, data_slab);

  ctx->scratch_slab = (GumCodeSlab *) (base + stalker->scratch_slab_offset);
  gum_scratch_slab_init (ctx->scratch_slab, stalker->scratch_slab_size);

  ctx->mappings = gum_metal_hash_table_new (NULL, NULL);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

  ctx->depth = 0;

#ifdef HAVE_LINUX
  ctx->excluded_calls = gum_metal_hash_table_new (NULL, NULL);
#endif

  return ctx;
}

static void
gum_exec_ctx_free (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumDataSlab * data_slab;
  GumCodeSlab * code_slab;

  gum_metal_hash_table_unref (ctx->mappings);

  data_slab = ctx->data_slab;
  while (data_slab != NULL)
  {
    GumDataSlab * next = (GumDataSlab *) data_slab->slab.next;
    gum_data_slab_free (data_slab);
    data_slab = next;
  }

  code_slab = ctx->code_slab;
  while (code_slab
```