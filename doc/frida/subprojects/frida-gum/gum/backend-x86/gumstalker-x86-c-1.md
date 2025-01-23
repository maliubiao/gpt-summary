Response:
The user wants a summary of the functionalities present in the provided C code snippet from `gumstalker-x86.c`. I need to identify the key actions and their purpose, especially in relation to dynamic instrumentation, reverse engineering, and low-level system interactions.

Here's a breakdown of the thought process to generate the summary:

1. **High-Level Understanding:** The code deals with managing the execution context of threads being "stalked" by Frida. This involves setting up interception points, handling exceptions, managing code blocks, and injecting code.

2. **Identify Key Data Structures and Functions:** Look for prominent variables and function calls that indicate core functionalities. For instance:
    * `GumStalker`: The central object managing the stalking process.
    * `GumExecCtx`: Represents the execution context of a stalked thread.
    * `gum_stalker_follow/unfollow`:  Functions for starting and stopping the stalking of threads.
    * `gum_stalker_infect/disinfect`: Functions for injecting and removing the stalking mechanism.
    * `gum_stalker_activate/deactivate`: Functions likely related to temporary control flow changes.
    * `gum_stalker_invalidate`: Function for invalidating cached code.
    * `gum_stalker_add_call_probe/remove_call_probe`: Functions for intercepting function calls.
    * Exception handling functions (`gum_stalker_exception_personality`, `gum_stalker_exception_find_fde`).

3. **Group Related Functionalities:** Categorize the identified functions based on their purpose. This helps create a structured summary. Possible categories include:
    * Thread Management (following, unfollowing)
    * Code Injection and Management
    * Exception Handling
    * Code Caching and Invalidation
    * Probes/Hooks

4. **Explain the "Why":**  For each identified functionality, briefly explain its role in dynamic instrumentation and reverse engineering. For example, why is exception handling important? Because Frida needs to maintain control even when exceptions occur in the target process.

5. **Connect to Low-Level Concepts:**  Identify areas where the code interacts with operating system primitives, the kernel, or binary code. Examples include:
    * Modifying thread contexts (using platform-specific APIs like `SetThreadContext`).
    * Handling system calls.
    * Working with memory ranges.
    * Dealing with instruction pointers (IP/PC).

6. **Infer Implicit Functionality:** Sometimes, the code suggests functionality even if it's not explicitly named. For example, the code related to `Wow64Transition` implies handling 32-bit code within a 64-bit process on Windows.

7. **Structure the Summary:** Organize the identified functionalities into a clear and concise summary using bullet points or numbered lists.

8. **Review and Refine:** Check the summary for accuracy and completeness. Ensure it addresses the user's request and captures the key aspects of the provided code snippet. For example, make sure to mention how the code uses writers (`GumX86Writer`) for code manipulation.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Focus only on the explicitly called functions.
* **Correction:** Recognize the importance of data structures like `GumExecCtx` and their role in managing the stalking process.
* **Initial thought:** Describe each function in isolation.
* **Correction:** Group related functions and explain the broader purpose of each group.
* **Initial thought:**  Just list the technical terms.
* **Correction:** Explain the significance of these terms in the context of dynamic instrumentation and reverse engineering (e.g., explain *why* modifying thread contexts is important).

By following these steps, and through iterative refinement, a comprehensive and informative summary can be generated. The focus remains on interpreting the code in the context of Frida's purpose and the user's request.
这是 frida 动态插桩工具中 `gumstalker-x86.c` 文件的第二部分代码。在第一部分的基础上，这部分代码继续构建和完善了 Stalker 的核心功能，主要集中在以下几个方面：

**1. 异常处理 (Exception Handling) (Linux only):**

* **功能:**  在 Linux 平台上，这部分代码实现了对 C++ 异常处理机制的 hook 和控制。它拦截了 `__gxx_personality_v0` (C++ 异常分发的核心函数) 和 `_Unwind_Find_FDE` (查找帧描述条目的函数)。
* **与逆向的关系:** 当目标程序抛出异常时，Frida 可以介入，分析异常信息，甚至修改程序的执行流程。例如，可以阻止程序崩溃，或者在特定异常发生时执行自定义代码。
* **二进制底层/Linux 知识:**  这部分代码直接操作了与 Linux 异常处理相关的底层 API，涉及到对堆栈回溯、帧信息（FDE）的理解，以及对 ABI (Application Binary Interface) 的了解，特别是 C++ 异常处理的 ABI 约定。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 目标程序在被 Stalker 跟踪的情况下抛出一个 C++ 异常。
    * **输出:** `gum_stalker_exception_personality` 函数会被调用。该函数会检查当前执行上下文是否被 Stalker 管理，如果是，它可能会在调用原始的 `__gxx_personality_v0` 前后修改程序计数器 (PC)，以确保 Stalker 继续控制程序的执行。`gum_stalker_exception_find_fde` 会在查找帧信息时进行类似的地址转换。
* **用户/编程常见使用错误:**  如果用户错误地反转了 `gum_interceptor_replace` 的操作 (例如，在错误的时机调用 `gum_interceptor_revert`)，可能会导致程序在异常处理过程中崩溃或行为异常。
* **用户操作如何到达这里 (调试线索):**
    1. 用户使用 Frida 连接到目标进程。
    2. 用户调用 `Stalker.follow()` 开始跟踪目标进程的执行。
    3. 目标进程执行过程中抛出一个 C++ 异常。
    4. 系统的异常处理机制会调用 `__gxx_personality_v0`。
    5. 由于 Frida 已经 hook 了该函数，`gum_stalker_exception_personality` 会被优先执行。

**2. Stalker 对象的生命周期管理:**

* **功能:** 实现了 `GumStalker` 对象的销毁 (`dispose`, `finalize`)，包括释放占用的资源，例如哈希表、数组、互斥锁等。
* **二进制底层/Linux/Android 内核及框架:**  涉及到对内存的管理，以及多线程同步原语 (互斥锁) 的使用。
* **用户操作如何到达这里 (调试线索):**
    1. 用户在脚本中创建了一个 `Stalker` 对象。
    2. 当脚本执行结束或者用户显式地释放了该 `Stalker` 对象时，`g_object_unref` 会被调用，最终会触发 `gum_stalker_dispose` 和 `gum_stalker_finalize`。

**3. Stalker 属性的获取和设置:**

* **功能:** 提供了访问和修改 `GumStalker` 对象属性的方法，例如 `ic_entries` 和 `adj_blocks`。这些属性可能控制着 Stalker 内部的优化策略。
* **用户操作如何到达这里 (调试线索):**
    1. 用户在 Frida 脚本中使用类似 `stalker.options = { ic_entries: 1024 }` 的代码来设置 Stalker 的属性。
    2. Frida 内部会调用 `g_object_set_property`，最终会调用到 `gum_stalker_set_property`。
    3. 用户可以使用 `stalker.options.ic_entries` 来获取属性值，Frida 内部会调用 `g_object_get_property`，最终调用到 `gum_stalker_get_property`。

**4. 排除特定内存区域 (Exclusion):**

* **功能:** 允许用户指定某些内存区域不被 Stalker 跟踪。这对于提高性能或者避免跟踪不感兴趣的代码非常有用。
* **与逆向的关系:**  逆向工程师可以使用排除功能来聚焦于目标程序的特定部分，忽略已知或不相关的代码。
* **二进制底层:**  涉及到对内存地址范围的比较和判断。
* **用户操作如何到达这里 (调试线索):**
    1. 用户在 Frida 脚本中使用 `Stalker.exclude(range)` 方法，其中 `range` 是一个 `MemoryRange` 对象，指定了要排除的内存区域。
    2. `gum_stalker_exclude` 函数会被调用，将该内存范围添加到 Stalker 对象的排除列表中。
    3. 在 Stalker 的内部逻辑中，会调用 `gum_stalker_is_excluding` 来判断一个给定的地址是否在排除列表中。

**5. 信任阈值 (Trust Threshold):**

* **功能:**  允许设置 Stalker 对代码块的信任程度。这可能影响 Stalker 何时重新编译或刷新代码块。
* **用户操作如何到达这里 (调试线索):**
    1. 用户在 Frida 脚本中使用 `stalker.trustThreshold = value` 来设置信任阈值。
    2. Frida 内部会调用 `gum_stalker_set_trust_threshold`。
    3. 用户可以使用 `stalker.trustThreshold` 来获取当前的信任阈值，Frida 内部会调用 `gum_stalker_get_trust_threshold`。

**6. 刷新 (Flush) Stalker 的事件队列:**

* **功能:**  强制 Stalker 将其内部缓存的事件发送到事件接收器 (Sink)。
* **用户操作如何到达这里 (调试线索):**
    1. 用户在 Frida 脚本中调用 `Stalker.flush()` 方法。
    2. `gum_stalker_flush` 函数会被调用，遍历当前正在被跟踪的线程的执行上下文，并调用每个上下文关联的事件接收器的 `flush` 方法。

**7. 停止 (Stop) Stalker:**

* **功能:**  停止 Stalker 的跟踪，清理所有相关的状态，包括移除注入的代码和释放资源。
* **与逆向的关系:**  在分析完成或者需要更改跟踪策略时，逆向工程师可以停止 Stalker。
* **二进制底层:**  涉及到对目标进程的内存修改 (移除注入的代码)。
* **用户操作如何到达这里 (调试线索):**
    1. 用户在 Frida 脚本中调用 `Stalker.stop()` 方法。
    2. `gum_stalker_stop` 函数会被调用，它会移除所有的探针 (probes)，并尝试停止跟踪所有当前正在被跟踪的线程。

**8. 垃圾回收 (Garbage Collection):**

* **功能:**  定期清理不再需要的执行上下文对象，释放资源。
* **用户操作如何到达这里 (调试线索):**
    垃圾回收通常是 Stalker 内部自动进行的，不需要用户显式调用。但是，理解其机制有助于理解 Stalker 的资源管理。

**归纳这部分代码的功能:**

这部分 `gumstalker-x86.c` 的代码主要负责以下核心功能：

* **增强了 Stalker 在 Linux 平台上的异常处理能力，使其能够更好地控制和分析目标程序的异常行为。**
* **实现了 Stalker 对象的生命周期管理，确保资源得到正确释放。**
* **提供了访问和修改 Stalker 内部配置的接口。**
* **允许用户排除特定的内存区域不被跟踪，提高效率和聚焦分析。**
* **引入了信任阈值的概念，可能用于优化 Stalker 的代码管理策略。**
* **提供了手动刷新和停止 Stalker 跟踪的功能。**
* **实现了内部的垃圾回收机制，用于管理 Stalker 的资源。**

总而言之，这部分代码进一步完善了 Stalker 的核心基础设施，使其更加健壮和可配置，为后续的线程跟踪、代码注入和插桩操作奠定了基础。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
)
      {
        self->user32_start = mbi.BaseAddress;
        self->user32_end = (guint8 *) mbi.BaseAddress + mbi.RegionSize;

        found_user32_code = TRUE;
      }

      p = (guint8 *) mbi.BaseAddress + mbi.RegionSize;
    }
    g_assert (found_user32_code);

    self->ki_user_callback_dispatcher_impl = GUM_FUNCPTR_TO_POINTER (
        GetProcAddress (ntmod, "KiUserCallbackDispatcher"));
    g_assert (self->ki_user_callback_dispatcher_impl != NULL);

    impls = g_array_sized_new (FALSE, FALSE, sizeof (gpointer), 5);
    self->wow_transition_impls = impls;
    gum_collect_export_by_handle (impls, ntmod, "Wow64Transition");
    gum_collect_export_by_handle (impls, usermod, "Wow64Transition");
    gum_collect_export (impls, _T ("kernel32.dll"), "Wow64Transition");
    gum_collect_export (impls, _T ("kernelbase.dll"), "Wow64Transition");
    gum_collect_export (impls, _T ("win32u.dll"), "Wow64Transition");
  }
# endif
#endif
}

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)

static void
gum_stalker_ensure_unwind_apis_instrumented (void)
{
  static gsize initialized = FALSE;

  if (__gxx_personality_v0 == NULL)
    return;

  if (g_once_init_enter (&initialized))
  {
    GumReplaceReturn res G_GNUC_UNUSED;

    gum_exec_ctx_interceptor = gum_interceptor_obtain ();

    res = gum_interceptor_replace (gum_exec_ctx_interceptor,
        __gxx_personality_v0, gum_stalker_exception_personality, NULL, NULL);
    g_assert (res == GUM_REPLACE_OK);

    res = gum_interceptor_replace (gum_exec_ctx_interceptor,
        _Unwind_Find_FDE, gum_stalker_exception_find_fde, NULL, NULL);
    g_assert (res == GUM_REPLACE_OK);

    _gum_register_early_destructor (
        gum_stalker_deinit_unwind_apis_instrumentation);

    g_once_init_leave (&initialized, TRUE);
  }
}

static void
gum_stalker_deinit_unwind_apis_instrumentation (void)
{
  gum_interceptor_revert (gum_exec_ctx_interceptor, __gxx_personality_v0);
  gum_interceptor_revert (gum_exec_ctx_interceptor, _Unwind_Find_FDE);
  g_clear_object (&gum_exec_ctx_interceptor);
}

static _Unwind_Reason_Code
gum_stalker_exception_personality (int version,
                                   _Unwind_Action actions,
                                   uint64_t exception_class,
                                   _Unwind_Exception * unwind_exception,
                                   _Unwind_Context * context)
{
  _Unwind_Reason_Code reason;
  GumExecCtx * ctx;
  gpointer throw_ip;
  gpointer real_throw_ip;

  /*
   * This function is responsible for the dispatching of exceptions. It is
   * actually called twice, first during the search phase and then subsequently
   * for the cleanup phase. This personality function is provided with a context
   * containing the PC of the exception. In this case, the PC is the address of
   * the instruction immediately after the exception is thrown (collected by
   * libunwind from the callstack). If this is a code address rather than a real
   * address, we will perform some address translation, otherwise we will let
   * the function proceed as normal.
   *
   * We must set the PC to the real address, before we call the original
   * personality function. But we must also modify the PC in the event that the
   * personality function installs a new context. This happens, for example,
   * when the exception dispatcher needs to modify the PC to execute any
   * relevant catch blocks. In this case, we must obtain the instrumented block
   * for the real address we are going to vector to and restore the PC to the
   * instrumented version of the block. Otherwise, we will find that the
   * exception is correctly handled, but afterwards execution continues from the
   * real address and hence the thread is no longer under the control of
   * Stalker.
   */

  ctx = gum_stalker_get_exec_ctx ();
  if (ctx == NULL)
  {
    return __gxx_personality_v0 (version, actions, exception_class,
        unwind_exception, context);
  }

  throw_ip = GSIZE_TO_POINTER (_Unwind_GetIP (context));

  real_throw_ip = gum_metal_hash_table_lookup (ctx->excluded_calls, throw_ip);
  if (real_throw_ip == NULL)
  {
    return __gxx_personality_v0 (version, actions, exception_class,
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
  const void * result;
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
    result = _Unwind_Find_FDE (pc, bases);
  else
    result = _Unwind_Find_FDE (real_address - 1, bases);

  return result;
}

#endif

static void
gum_stalker_dispose (GObject * object)
{
#ifdef HAVE_WINDOWS
  {
    GumStalker * self;
    GumExceptor * exceptor;

    self = GUM_STALKER (object);

    exceptor = g_steal_pointer (&self->exceptor);
    if (exceptor != NULL)
    {
      gum_exceptor_remove (exceptor, gum_stalker_on_exception, self);

      g_object_unref (exceptor);
    }
  }
#endif

  G_OBJECT_CLASS (gum_stalker_parent_class)->dispose (object);
}

static void
gum_stalker_finalize (GObject * object)
{
  GumStalker * self = GUM_STALKER (object);

#if defined (HAVE_WINDOWS) && GLIB_SIZEOF_VOID_P == 4
  g_array_unref (self->wow_transition_impls);
#endif

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
    case PROP_ADJACENT_BLOCKS:
      g_value_set_uint (value, self->adj_blocks);
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
    case PROP_ADJACENT_BLOCKS:
      self->adj_blocks = g_value_get_uint (value);
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

#ifdef _MSC_VER

#define RETURN_ADDRESS_POINTER_FROM_FIRST_ARGUMENT(arg)   \
    ((gpointer *) ((volatile guint8 *) &arg - sizeof (gpointer)))

GUM_NOINLINE void
gum_stalker_follow_me (GumStalker * self,
                       GumStalkerTransformer * transformer,
                       GumEventSink * sink)
{
  gpointer * ret_addr_ptr;

  ret_addr_ptr = RETURN_ADDRESS_POINTER_FROM_FIRST_ARGUMENT (self);

  _gum_stalker_do_follow_me (self, transformer, sink, ret_addr_ptr);
}

#endif

void
_gum_stalker_do_follow_me (GumStalker * self,
                           GumStalkerTransformer * transformer,
                           GumEventSink * sink,
                           gpointer * ret_addr_ptr)
{
  GumExecCtx * ctx;
  gpointer code_address;

  ctx = gum_stalker_create_exec_ctx (self, gum_process_get_current_thread_id (),
      transformer, sink);
  g_private_set (&gum_stalker_exec_ctx_private, ctx);

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, *ret_addr_ptr,
      &code_address);

  if (gum_exec_ctx_maybe_unfollow (ctx, *ret_addr_ptr))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return;
  }

  gum_event_sink_start (ctx->sink);
  ctx->sink_started = TRUE;

  *ret_addr_ptr = code_address;
}

GUM_NOINLINE void
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
  GumInfectContext * infect_context = (GumInfectContext *) user_data;
  GumStalker * self = infect_context->stalker;
  GumExecCtx * ctx;
  guint8 * pc;
  const guint max_syscall_size = 2;
  gpointer code_address;
  GumX86Writer * cw;

  ctx = gum_stalker_create_exec_ctx (self, thread_id,
      infect_context->transformer, infect_context->sink);

  pc = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, pc, &code_address);

  if (gum_exec_ctx_maybe_unfollow (ctx, NULL))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return;
  }

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (self, ctx->thunks, self->thunks_size);
  cw = &ctx->code_writer;
  gum_x86_writer_reset (cw, ctx->infect_thunk);

  /*
   * In case the thread is in a Linux system call we should allow it to be
   * restarted by bringing along the syscall instruction.
   */
  gum_x86_writer_put_bytes (cw, pc - max_syscall_size, max_syscall_size);

  ctx->infect_body = GUM_ADDRESS (gum_x86_writer_cur (cw));
  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (g_private_set), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (&gum_stalker_exec_ctx_private),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (code_address));

  gum_x86_writer_flush (cw);
  gum_stalker_freeze (self, cw->base, gum_x86_writer_offset (cw));

  gum_spinlock_release (&ctx->code_lock);

  gum_event_sink_start (ctx->sink);
  ctx->sink_started = TRUE;

#ifdef HAVE_WINDOWS
  {
    gboolean probably_in_syscall;

    probably_in_syscall =
# if GLIB_SIZEOF_VOID_P == 8
        pc[0] == 0xc3 && pc[-2] == 0x0f && pc[-1] == 0x05;
# else
        (pc[0] == 0xc2 || pc[0] == 0xc3) &&
            pc[-2] == 0xff && (pc[-1] & 0xf8) == 0xd0;
# endif
    if (probably_in_syscall)
    {
      gboolean breakpoint_deployed = FALSE;
      HANDLE thread;

      thread = OpenThread (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
          thread_id);
      if (thread != NULL)
      {
#ifdef _MSC_VER
        __declspec (align (64))
#endif
            CONTEXT tc
#ifndef _MSC_VER
              __attribute__ ((aligned (64)))
#endif
              = { 0, };

        tc.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext (thread, &tc))
        {
          ctx->previous_pc = GPOINTER_TO_SIZE (pc);
          ctx->previous_dr0 = tc.Dr0;
          ctx->previous_dr7 = tc.Dr7;

          tc.Dr0 = GPOINTER_TO_SIZE (pc);
          tc.Dr7 = 0x00000700;
          gum_enable_hardware_breakpoint (&tc.Dr7, 0);

          breakpoint_deployed = SetThreadContext (thread, &tc);
        }

        CloseHandle (thread);
      }

      if (!breakpoint_deployed)
        gum_stalker_destroy_exec_ctx (self, ctx);

      return;
    }
  }
#endif

  GUM_CPU_CONTEXT_XIP (cpu_context) = ctx->infect_body;
}

static void
gum_stalker_disinfect (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  GumDisinfectContext * disinfect_context = user_data;
  GumExecCtx * ctx = disinfect_context->exec_ctx;
  gboolean infection_not_active_yet;

#ifdef HAVE_WINDOWS
  infection_not_active_yet =
      GUM_CPU_CONTEXT_XIP (cpu_context) == ctx->previous_pc;
  if (infection_not_active_yet)
  {
    HANDLE thread;

    thread = OpenThread (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE,
        thread_id);
    if (thread != NULL)
    {
#ifdef _MSC_VER
      __declspec (align (64))
#endif
          CONTEXT tc
#ifndef _MSC_VER
            __attribute__ ((aligned (64)))
#endif
            = { 0, };

      tc.ContextFlags = CONTEXT_DEBUG_REGISTERS;
      if (GetThreadContext (thread, &tc))
      {
        tc.Dr0 = ctx->previous_dr0;
        tc.Dr7 = ctx->previous_dr7;

        ctx->previous_pc = 0;

        disinfect_context->success = SetThreadContext (thread, &tc);
      }

      CloseHandle (thread);
    }
  }
#else
  infection_not_active_yet =
      GUM_CPU_CONTEXT_XIP (cpu_context) == ctx->infect_body;
  if (infection_not_active_yet)
  {
    GUM_CPU_CONTEXT_XIP (cpu_context) =
        GPOINTER_TO_SIZE (ctx->current_block->real_start);

    disinfect_context->success = TRUE;
  }
#endif
}

#ifdef _MSC_VER

GUM_NOINLINE void
gum_stalker_activate (GumStalker * self,
                      gconstpointer target)
{
  gpointer * ret_addr_ptr;

  ret_addr_ptr = RETURN_ADDRESS_POINTER_FROM_FIRST_ARGUMENT (self);

  _gum_stalker_do_activate (self, target, ret_addr_ptr);
}

GUM_NOINLINE void
gum_stalker_deactivate (GumStalker * self)
{
  gpointer * ret_addr_ptr;

  ret_addr_ptr = RETURN_ADDRESS_POINTER_FROM_FIRST_ARGUMENT (self);

  _gum_stalker_do_deactivate (self, ret_addr_ptr);
}

#endif

void
_gum_stalker_do_activate (GumStalker * self,
                          gconstpointer target,
                          gpointer * ret_addr_ptr)
{
  guint8 * ret_addr = *ret_addr_ptr;
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx ();
  if (ctx == NULL)
    return;

  ctx->unfollow_called_while_still_following = FALSE;
  ctx->activation_target = target;

  if (!gum_exec_ctx_contains (ctx, ret_addr))
  {
    gpointer code_address;

    ctx->current_block =
        gum_exec_ctx_obtain_block_for (ctx, ret_addr, &code_address);

    if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
      return;

    *ret_addr_ptr = code_address;
  }
}

void
_gum_stalker_do_deactivate (GumStalker * self,
                            gpointer * ret_addr_ptr)
{
  GumExecCtx * ctx;

  ctx = gum_stalker_get_exec_ctx ();
  if (ctx == NULL)
    return;

  ctx->unfollow_called_while_still_following = TRUE;
  ctx->activation_target = NULL;

  if (gum_exec_ctx_contains (ctx, *ret_addr_ptr))
  {
    ctx->pending_calls--;

    *ret_addr_ptr = ctx->pending_return_location;
  }
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
          call->code_offset, call->opened_prolog, call->ret_real_address,
          call->ret_code_offset);
      break;
    }
    case GUM_BACKPATCH_JMP:
    {
      const GumBackpatchJmp * jmp = &backpatch->jmp;
      gum_exec_block_backpatch_jmp (block_to, block_from, from_insn, jmp->id,
          jmp->code_offset, jmp->opened_prolog);
      break;
    }
    case GUM_BACKPATCH_INLINE_CACHE:
    {
      gum_exec_block_backpatch_inline_cache (block_to, block_from, from_insn);
      break;
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
  const guint8 * pc = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));

  if (pc >= block->code_start &&
      pc < block->code_start + GUM_INVALIDATE_TRAMPOLINE_SIZE)
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
  guint8 * pc;
  GumX86Writer * cw;
  GumAddress cpu_context_copy;

  ctx = gum_stalker_create_exec_ctx (self, thread_id, NULL, NULL);

  pc = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (self, ctx->thunks, self->thunks_size);
  cw = &ctx->code_writer;
  gum_x86_writer_reset (cw, ctx->infect_thunk);

  cpu_context_copy = GUM_ADDRESS (gum_x86_writer_cur (cw));
  gum_x86_writer_put_bytes (cw, (guint8 *) cpu_context, sizeof (GumCpuContext));

#ifdef HAVE_LINUX
  /*
   * In case the thread is in a Linux system call we prefix with a couple of
   * NOPs so that when we restart, we don't re-attempt the syscall. We will
   * drop ourselves back to the syscall once we are done.
   */
  gum_x86_writer_put_nop_padding (cw, MAX (sizeof (gum_int80_code),
      sizeof (gum_syscall_code)));
#endif

  ctx->infect_body = GUM_ADDRESS (gum_x86_writer_cur (cw));
  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (func), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (cpu_context_copy),
      GUM_ARG_ADDRESS, GUM_ADDRESS (data));
  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_exec_ctx_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (pc));
  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);

#ifdef HAVE_LINUX
  if (memcmp (&pc[-sizeof (gum_int80_code)], gum_int80_code,
        sizeof (gum_int80_code)) == 0)
  {
    gum_x86_writer_put_jmp_address (cw,
        GUM_ADDRESS (&pc[-sizeof (gum_int80_code)]));
  }
  else if (memcmp (&pc[-sizeof (gum_syscall_code)], gum_syscall_code,
        sizeof (gum_syscall_code)) == 0)
  {
    gum_x86_writer_put_jmp_address (cw,
        GUM_ADDRESS (&pc[-sizeof (gum_syscall_code)]));
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (pc));
  }
#else
  gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (pc));
#endif

  gum_x86_writer_flush (cw);
  gum_stalker_freeze (self, cw->base, gum_x86_writer_offset (cw));

  gum_spinlock_release (&ctx->code_lock);

  GUM_CPU_CONTEXT_XIP
```