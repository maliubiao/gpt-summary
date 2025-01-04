Response:
Let's break down the thought process to analyze this C code snippet.

1. **Understand the Goal:** The request is to analyze the functionality of `guminterceptor.c`, a part of Frida, focusing on its relationship to reverse engineering, low-level details, logic, potential errors, and user interaction. The fact that it's "part 2 of 2" implies we should summarize the overall functionality after detailing the specifics.

2. **High-Level Overview (Skimming):**  Before diving deep, I'll quickly scan the code for keywords and structures:
    * `GumInterceptor`, `GumFunctionContext`, `GumInvocationListener`:  These suggest the core concepts of interception – managing the interception points, context of intercepted functions, and listeners that react to interceptions.
    * `transaction`, `pending_update_tasks`, `pending_destroy_tasks`:  This hints at a transaction-based approach for managing changes, likely for atomicity and consistency.
    * `trampoline`:  A key concept in dynamic instrumentation, used to redirect execution.
    * `cpu_context`:  Indicates interaction with CPU state, crucial for instrumentation.
    * `_gum_interceptor_backend_*`:  Suggests an abstraction layer for platform-specific implementations.
    * `g_hash_table`, `g_array`, `g_queue`:  Standard GLib data structures used for managing data.
    * `gum_code_segment_*`, `gum_clear_cache`:  Lower-level memory management and cache manipulation, important for code modification.
    * `gum_thread_*`: Thread management, necessary for intercepting in multi-threaded applications.
    * `mach_port_mod_refs`:  Darwin-specific API, indicating cross-platform considerations.

3. **Categorize Functionality (First Pass):** Based on the skimming, I can start categorizing functions:
    * **Interception Management:**  `gum_interceptor_*`, `gum_function_context_*` (creation, destruction, adding/removing listeners).
    * **Transaction Management:** `gum_interceptor_transaction_*` (begin, commit, rollback, schedule updates/destroys).
    * **Invocation Handling:** `_gum_function_context_begin_invocation`, `_gum_function_context_end_invocation`.
    * **Listener Management:** Functions related to `ListenerEntry`.
    * **Thread Context:** `InterceptorThreadContext` and associated functions.
    * **Low-Level Operations:** `gum_code_segment_*`, `gum_clear_cache`.
    * **Utility Functions:** `gum_page_address_from_pointer`, `gum_interceptor_resolve`, `gum_interceptor_has`.

4. **Detailed Analysis (Iterative):** Now, I'll go through the code more carefully, function by function or logical block, focusing on the specific instructions in the prompt:

    * **Functionality Listing:** Describe what each function does in simple terms. For example, `gum_interceptor_transaction_begin` initializes a transaction.

    * **Relationship to Reverse Engineering:** Think about *how* each piece helps in reverse engineering. Interception allows observing function calls, modifying behavior, logging arguments/return values, etc. Trampolines are the mechanism that makes this redirection possible. The `resolve` function handles cases where the target function might already be intercepted or have a redirect in place.

    * **Binary/Kernel/Framework Details:** Identify code that interacts with lower levels. `gum_code_segment_*` is clearly about memory manipulation at a code segment level. `gum_clear_cache` is essential after modifying code. The Darwin-specific code relates to thread handling on macOS/iOS. The use of `GumCpuContext` directly manipulates CPU registers.

    * **Logic and Inference (Hypothetical Input/Output):** For functions like `gum_interceptor_transaction_commit`, imagine a scenario: adding an interceptor to a function. What would the input be (function address, listener), and what would the output be (successful commit, potentially with code modifications)?  Think about the steps involved in committing a transaction: copying code, setting up trampolines, updating data structures.

    * **User/Programming Errors:** Consider how a user might misuse the API. For instance, forgetting to commit a transaction, trying to intercept a non-existent function, adding too many listeners, memory leaks if resources aren't properly managed (though the code has cleanup mechanisms).

    * **User Operation to Code:** Trace the steps a user might take to reach this code. A common scenario is attaching Frida to a process and then using the `Interceptor` API to attach to a function. This would trigger the creation of interceptor objects, function contexts, and transactions.

5. **Synthesize and Organize:**  Group the findings logically under the prompt's headings. Use clear and concise language. Provide concrete examples for each point.

6. **Address "Part 2 of 2" (Summarization):**  Review the detailed analysis and identify the core purpose of the code. It's about dynamically intercepting function calls, allowing inspection and modification of behavior. Mention the key components working together: transactions, function contexts, listeners, and the backend.

7. **Review and Refine:**  Read through the entire analysis to ensure clarity, accuracy, and completeness. Check for any redundancies or areas where more detail or better examples could be provided. For instance, initially, I might have missed the significance of the `gum_interceptor_guard_key` for preventing recursive interception, which is an important detail.

**Self-Correction/Refinement Example During the Process:**

* **Initial thought:** "The code copies memory with `memcpy`."
* **Refinement:** "It copies code segments using `gum_code_segment_copy`, which likely handles architecture-specific details for instruction copying, rather than just raw bytes."  This shows deeper understanding.

* **Initial thought:**  "Listeners are just called."
* **Refinement:** "Listeners are called at specific points (entry/leave) in the function execution, and the `GumInvocationContext` provides a structured way to interact with the intercepted call." This highlights the controlled and contextual nature of the interception.

By following this systematic approach, combining high-level understanding with detailed analysis and iterative refinement, I can effectively dissect and explain the functionality of a complex code snippet like the one provided.
好的，让我们来分析一下 `frida/subprojects/frida-gum/gum/guminterceptor.c` 文件的代码片段。

**功能归纳：**

这段代码是 Frida 中负责**函数拦截（Interception）**的核心部分。它实现了在运行时修改目标进程函数行为的功能，允许用户在函数执行前后插入自定义代码。

**更具体的功能点：**

1. **事务管理 (Transaction Management):**
   - 提供了 `GumInterceptorTransaction` 结构体和相关函数 (`gum_interceptor_transaction_begin`, `gum_interceptor_transaction_commit`, `gum_interceptor_transaction_abort`)，用于原子性地执行一系列拦截操作。
   - 在事务中收集需要更新和销毁的任务 (`pending_update_tasks`, `pending_destroy_tasks`)，然后在提交时批量处理，确保操作的一致性。

2. **函数上下文管理 (Function Context Management):**
   - 使用 `GumFunctionContext` 结构体来表示一个被拦截的函数。
   - 存储了函数的地址 (`function_address`)，拦截类型 (`type`)，以及与该函数关联的监听器 (`listener_entries`)。
   - 负责创建 (`gum_function_context_new`)、销毁 (`gum_function_context_destroy`, `gum_function_context_perform_destroy`) 函数上下文。

3. **监听器管理 (Listener Management):**
   - 允许用户为被拦截的函数添加多个监听器 (`gum_function_context_add_listener`)，这些监听器会在函数执行的入口 (`on_enter`) 和出口 (`on_leave`) 被调用。
   - 使用 `ListenerEntry` 结构体来保存监听器实例和用户数据。
   - 提供了移除监听器 (`gum_function_context_remove_listener`) 和检查是否存在监听器 (`gum_function_context_has_listener`) 的功能。

4. **拦截点的激活与去激活 (Activation and Deactivation of Interception Points):**
   - `gum_interceptor_activate` 和 `gum_interceptor_deactivate` 函数负责实际修改目标进程的代码，插入跳转指令，将执行流导向 Frida 的 trampoline 代码。
   - 使用 `gum_code_segment_*` 系列函数来操作目标进程的代码段，例如复制、映射、释放内存。
   - `gum_clear_cache` 用于清除 CPU 指令缓存，确保修改后的代码立即生效。

5. **调用处理 (Invocation Handling):**
   - `_gum_function_context_begin_invocation` 和 `_gum_function_context_end_invocation` 是拦截发生时执行的关键函数。
   - `_gum_function_context_begin_invocation` 在函数入口处被调用，负责：
     - 检查是否需要调用监听器。
     - 如果需要，将当前调用信息压入调用栈 (`GumInvocationStack`)。
     - 调用已注册的 `on_enter` 监听器。
     - 如果有替换函数 (`replacement_function`)，则将执行流导向替换函数。
   - `_gum_function_context_end_invocation` 在函数出口处被调用，负责：
     - 调用已注册的 `on_leave` 监听器。
     - 从调用栈中弹出当前调用信息。
     - 将执行流导向原始的返回地址。

6. **线程管理 (Thread Management):**
   - 使用 `InterceptorThreadContext` 来存储每个线程的拦截上下文信息，例如调用栈 (`stack`) 和监听器数据 (`listener_data_slots`)。
   - `get_interceptor_thread_context` 获取当前线程的上下文。
   - 提供了挂起线程 (`gum_maybe_suspend_thread`) 的功能，可能用于确保在修改代码时没有其他线程正在执行相关代码。

7. **代码段操作 (Code Segment Operations):**
   - 使用 `gum_code_segment_*` 系列函数来管理目标进程的代码段内存，包括创建、复制、映射和释放。这对于插入 trampoline 代码至关重要。

8. **Trampoline 管理:**
   - Trampoline 是一小段动态生成的代码，用于将执行流从原始函数跳转到 Frida 的处理逻辑，并在处理完成后跳转回原始函数或替换函数。
   - 虽然这段代码没有直接创建 trampoline 的逻辑，但它依赖于 backend 提供的创建和销毁 trampoline 的功能 (`_gum_interceptor_backend_create_trampoline`, `_gum_interceptor_backend_destroy_trampoline`)。

**与逆向方法的关系及举例说明：**

函数拦截是动态逆向分析中最核心的技术之一。通过拦截函数，逆向工程师可以：

* **追踪函数调用：** 观察程序的执行流程，了解函数之间的调用关系。
   - **例子：**  拦截 `open` 系统调用，可以记录程序打开了哪些文件及其路径。
* **修改函数行为：**  改变函数的输入、输出或内部逻辑，以绕过安全检查、修复 bug 或注入恶意代码。
   - **例子：**  拦截网络请求函数，修改请求的 URL 或返回数据，用于模拟服务器行为或进行渗透测试。
* **Hook 函数执行：** 在函数执行前后执行自定义代码，例如打印函数参数、返回值、CPU 寄存器状态等，用于调试和分析。
   - **例子：**  拦截加密函数，在加密前和加密后打印输入和输出数据，用于分析加密算法。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制底层:**
    - **指令覆盖：**  拦截的核心在于修改目标函数的指令，通常是将函数开头的几条指令替换为跳转到 Frida trampoline 的指令。
    - **代码段操作：**  需要了解目标进程的内存布局，特别是代码段的权限和地址。`gum_code_segment_*` 函数就是用来操作这些底层的内存细节。
    - **CPU 缓存一致性：**  修改代码后需要清除 CPU 缓存，否则 CPU 可能会继续执行旧的代码。`gum_clear_cache` 就做了这件事。
* **Linux/Android 内核:**
    - **系统调用拦截：**  Frida 可以拦截系统调用，例如 `open`, `read`, `write`, `connect` 等。这需要了解 Linux 的系统调用机制。
    - **内存管理：**  Frida 需要在目标进程中分配和管理内存来存储 trampoline 和其他数据。
    - **线程管理：**  需要能够挂起和恢复目标进程的线程，以确保代码修改的安全性。
* **Android 框架:**
    - **Art/Dalvik 虚拟机：**  在 Android 上，Frida 可以拦截 Java 方法和 Native 方法。对于 Java 方法，需要理解 Art/Dalvik 的方法调用机制和 JNI 接口。
    - **Binder 通信：**  Frida 可以拦截 Android 系统服务之间的 Binder 调用，用于分析系统行为。

**逻辑推理及假设输入与输出：**

假设我们要拦截一个名为 `target_function` 的函数，并添加一个简单的监听器，在函数入口打印 "Function entered"。

**假设输入：**

1. `interceptor`: 一个 `GumInterceptor` 实例。
2. `target_function_address`: `target_function` 在内存中的地址。
3. 一个实现了 `GumInvocationListener` 接口的监听器对象，其 `on_enter` 方法会打印 "Function entered"。

**执行流程（简化）：**

1. **开始事务:** `gum_interceptor_transaction_begin(interceptor);`
2. **获取或创建函数上下文:** 查找是否已存在 `target_function_address` 的上下文，没有则创建。
3. **添加监听器:** `gum_function_context_add_listener(function_ctx, listener, NULL);`
4. **激活拦截点:** `gum_interceptor_activate(interceptor, target_function_address, ...);`  这会修改 `target_function` 的代码，插入 trampoline。
5. **提交事务:** `gum_interceptor_transaction_commit(interceptor);`

**预期输出：**

当 `target_function` 被调用时，在执行 `target_function` 的原始代码之前，会先执行我们监听器的 `on_enter` 方法，从而在控制台上打印 "Function entered"。

**涉及用户或者编程常见的使用错误及举例说明：**

1. **忘记提交事务：**  如果在调用 `gum_interceptor_transaction_begin` 后，没有调用 `gum_interceptor_transaction_commit`，那么所有的拦截操作都不会生效。
   ```c
   GumInterceptorTransaction *tx = gum_interceptor_transaction_begin(interceptor);
   // ... 添加监听器和激活拦截点的操作 ...
   // 错误：忘记调用 gum_interceptor_transaction_commit(interceptor);
   ```
2. **在错误的线程上操作拦截器：**  Frida 的拦截操作通常需要在附加到目标进程的线程上执行。如果在其他线程上尝试修改拦截器状态，可能会导致错误或未定义的行为。
3. **多次拦截同一个函数但未清理：**  如果多次调用 `gum_interceptor_activate` 拦截同一个函数，而没有先调用 `gum_interceptor_deactivate` 或使用事务进行管理，可能会导致 trampoline 冲突或其他问题。
4. **在已经销毁的函数上下文中操作：**  如果持有一个 `GumFunctionContext` 的指针，但在事务提交后，该上下文可能已经被销毁，此时继续操作该指针会导致崩溃。
5. **内存泄漏：**  如果用户自定义的监听器分配了内存，但忘记在 `on_leave` 或其他地方释放，可能会导致目标进程内存泄漏。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本:**  用户首先会编写一个 JavaScript 或 Python 脚本，使用 Frida 的 API 来进行动态instrumentation。
2. **使用 `Interceptor` API:**  在脚本中，用户会使用 `Interceptor` 模块的函数，例如 `Interceptor.attach(address, callbacks)` 或 `Interceptor.replace(address, replacement)`。
3. **Frida 将用户操作转换为 C 代码调用:**  Frida 的 JavaScript/Python 引擎会将这些高级 API 调用转换为对 Gum 库中相应 C 函数的调用。例如，`Interceptor.attach` 最终会调用到 `gum_interceptor_attach` (虽然这段代码中没有直接展示 `gum_interceptor_attach`，但它是 `guminterceptor.c` 中其他部分提供的功能)。
4. **事务的开始:**  `gum_interceptor_attach` 内部会开始一个事务 (`gum_interceptor_transaction_begin`)。
5. **查找或创建函数上下文:**  根据要拦截的函数地址，查找或创建一个 `GumFunctionContext` 实例。
6. **创建监听器上下文:**  根据用户提供的回调函数，创建或配置 `GumInvocationListener`。
7. **激活拦截点:**  调用 `gum_interceptor_activate` 来修改目标函数的代码，插入 trampoline。 这段代码就是处理 `gum_interceptor_activate` 中关于代码段操作的部分。
8. **提交事务:**  最后，调用 `gum_interceptor_transaction_commit` 来提交所有的修改。

当用户报告 Frida 拦截功能出现问题时，例如拦截没有生效、程序崩溃等，开发者可能会检查这段 `guminterceptor.c` 的代码，分析在事务管理、函数上下文管理、监听器调用、代码段操作等环节是否存在逻辑错误或边界情况未处理。

**归纳一下它的功能 (作为第 2 部分的总结):**

这段代码的核心功能是**实现 Frida 的函数运行时拦截机制**。它通过事务管理确保拦截操作的原子性，使用函数上下文来管理被拦截的函数信息，通过监听器机制允许用户在函数执行前后注入自定义代码，并利用代码段操作和 trampoline 技术来实现代码的动态修改和执行流的重定向。它构建了 Frida 动态 instrumentation 功能的基础，使得用户能够在运行时观察、修改目标进程的行为。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/guminterceptor.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
       update->ctx) - target_page));
        }

        source_page += page_size;
      }

      gum_code_segment_realize (segment);

      source_offset = 0;
      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;

        gum_code_segment_map (segment, source_offset, page_size, target_page);

        gum_clear_cache (target_page, page_size);

        source_offset += page_size;
      }

      gum_code_segment_free (segment);
    }
  }

  g_list_free (addresses);

  {
    GumDestroyTask * task;

    while ((task = g_queue_pop_head (self->pending_destroy_tasks)) != NULL)
    {
      if (task->ctx->trampoline_usage_counter == 0)
      {
        GUM_INTERCEPTOR_UNLOCK (interceptor);
        task->notify (task->data);
        GUM_INTERCEPTOR_LOCK (interceptor);

        g_slice_free (GumDestroyTask, task);
      }
      else
      {
        interceptor->current_transaction.is_dirty = TRUE;
        g_queue_push_tail (
            interceptor->current_transaction.pending_destroy_tasks, task);
      }
    }
  }

  gum_interceptor_transaction_destroy (self);

no_changes:
  gum_interceptor_unignore_current_thread (interceptor);
}

static gboolean
gum_maybe_suspend_thread (const GumThreadDetails * details,
                          gpointer user_data)
{
  GumSuspendOperation * op = user_data;

  if (details->id == op->current_thread_id)
    goto skip;

  if (!gum_thread_suspend (details->id, NULL))
    goto skip;

#ifdef HAVE_DARWIN
  mach_port_mod_refs (mach_task_self (), details->id, MACH_PORT_RIGHT_SEND, 1);
#endif
  g_queue_push_tail (&op->suspended_threads, GSIZE_TO_POINTER (details->id));

skip:
  return TRUE;
}

static void
gum_interceptor_transaction_schedule_destroy (GumInterceptorTransaction * self,
                                              GumFunctionContext * ctx,
                                              GDestroyNotify notify,
                                              gpointer data)
{
  GumDestroyTask * task;

  task = g_slice_new (GumDestroyTask);
  task->ctx = ctx;
  task->notify = notify;
  task->data = data;

  g_queue_push_tail (self->pending_destroy_tasks, task);
}

static void
gum_interceptor_transaction_schedule_update (GumInterceptorTransaction * self,
                                             GumFunctionContext * ctx,
                                             GumUpdateTaskFunc func)
{
  guint8 * function_address;
  gpointer start_page, end_page;
  GArray * pending;
  GumUpdateTask update;

  function_address = _gum_interceptor_backend_get_function_address (ctx);

  start_page = gum_page_address_from_pointer (function_address);
  end_page = gum_page_address_from_pointer (function_address +
      ctx->overwritten_prologue_len - 1);

  pending = g_hash_table_lookup (self->pending_update_tasks, start_page);
  if (pending == NULL)
  {
    pending = g_array_new (FALSE, FALSE, sizeof (GumUpdateTask));
    g_hash_table_insert (self->pending_update_tasks, start_page, pending);
  }

  update.ctx = ctx;
  update.func = func;
  g_array_append_val (pending, update);

  if (end_page != start_page)
  {
    pending = g_hash_table_lookup (self->pending_update_tasks, end_page);
    if (pending == NULL)
    {
      pending = g_array_new (FALSE, FALSE, sizeof (GumUpdateTask));
      g_hash_table_insert (self->pending_update_tasks, end_page, pending);
    }
  }
}

static GumFunctionContext *
gum_function_context_new (GumInterceptor * interceptor,
                          gpointer function_address,
                          GumInterceptorType type)
{
  GumFunctionContext * ctx;

  ctx = g_slice_new0 (GumFunctionContext);
  ctx->function_address = function_address;
  ctx->type = type;
  ctx->listener_entries =
      g_ptr_array_new_full (1, (GDestroyNotify) listener_entry_free);
  ctx->interceptor = interceptor;

  return ctx;
}

static void
gum_function_context_finalize (GumFunctionContext * function_ctx)
{
  g_assert (function_ctx->trampoline_slice == NULL);

  g_ptr_array_unref (
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries));

  g_slice_free (GumFunctionContext, function_ctx);
}

static void
gum_function_context_destroy (GumFunctionContext * function_ctx)
{
  GumInterceptorTransaction * transaction =
      &function_ctx->interceptor->current_transaction;

  g_assert (!function_ctx->destroyed);
  function_ctx->destroyed = TRUE;

  if (function_ctx->activated)
  {
    gum_interceptor_transaction_schedule_update (transaction, function_ctx,
        gum_interceptor_deactivate);
  }

  gum_interceptor_transaction_schedule_destroy (transaction, function_ctx,
      (GDestroyNotify) gum_function_context_perform_destroy, function_ctx);
}

static void
gum_function_context_perform_destroy (GumFunctionContext * function_ctx)
{
  _gum_interceptor_backend_destroy_trampoline (
      function_ctx->interceptor->backend, function_ctx);

  gum_function_context_finalize (function_ctx);
}

static gboolean
gum_function_context_is_empty (GumFunctionContext * function_ctx)
{
  if (function_ctx->replacement_function != NULL)
    return FALSE;

  return gum_function_context_find_taken_listener_slot (function_ctx) == NULL;
}

static void
gum_function_context_add_listener (GumFunctionContext * function_ctx,
                                   GumInvocationListener * listener,
                                   gpointer function_data)
{
  ListenerEntry * entry;
  GPtrArray * old_entries, * new_entries;
  guint i;

  entry = g_slice_new (ListenerEntry);
#ifndef GUM_DIET
  entry->listener_interface = GUM_INVOCATION_LISTENER_GET_IFACE (listener);
#endif
  entry->listener_instance = listener;
  entry->function_data = function_data;

  old_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  new_entries = g_ptr_array_new_full (old_entries->len + 1,
      (GDestroyNotify) listener_entry_free);
  for (i = 0; i != old_entries->len; i++)
  {
    ListenerEntry * old_entry = g_ptr_array_index (old_entries, i);
    if (old_entry != NULL)
      g_ptr_array_add (new_entries, g_slice_dup (ListenerEntry, old_entry));
  }
  g_ptr_array_add (new_entries, entry);

  g_atomic_pointer_set (&function_ctx->listener_entries, new_entries);
  gum_interceptor_transaction_schedule_destroy (
      &function_ctx->interceptor->current_transaction, function_ctx,
      (GDestroyNotify) g_ptr_array_unref, old_entries);

  if (entry->listener_interface->on_leave != NULL)
  {
    function_ctx->has_on_leave_listener = TRUE;
  }
}

static void
listener_entry_free (ListenerEntry * entry)
{
  g_slice_free (ListenerEntry, entry);
}

static void
gum_function_context_remove_listener (GumFunctionContext * function_ctx,
                                      GumInvocationListener * listener)
{
  ListenerEntry ** slot;
  gboolean has_on_leave_listener;
  GPtrArray * listener_entries;
  guint i;

  slot = gum_function_context_find_listener (function_ctx, listener);
  g_assert (slot != NULL);
  listener_entry_free (*slot);
  *slot = NULL;

  has_on_leave_listener = FALSE;
  listener_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry * entry = g_ptr_array_index (listener_entries, i);
    if (entry != NULL && entry->listener_interface->on_leave != NULL)
    {
      has_on_leave_listener = TRUE;
      break;
    }
  }
  function_ctx->has_on_leave_listener = has_on_leave_listener;
}

static gboolean
gum_function_context_has_listener (GumFunctionContext * function_ctx,
                                   GumInvocationListener * listener)
{
  return gum_function_context_find_listener (function_ctx, listener) != NULL;
}

static ListenerEntry **
gum_function_context_find_listener (GumFunctionContext * function_ctx,
                                    GumInvocationListener * listener)
{
  GPtrArray * listener_entries;
  guint i;

  listener_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry ** slot = (ListenerEntry **)
        &g_ptr_array_index (listener_entries, i);
    if (*slot != NULL && (*slot)->listener_instance == listener)
      return slot;
  }

  return NULL;
}

static ListenerEntry **
gum_function_context_find_taken_listener_slot (
    GumFunctionContext * function_ctx)
{
  GPtrArray * listener_entries;
  guint i;

  listener_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry ** slot = (ListenerEntry **)
        &g_ptr_array_index (listener_entries, i);
    if (*slot != NULL)
      return slot;
  }

  return NULL;
}

gboolean
_gum_function_context_begin_invocation (GumFunctionContext * function_ctx,
                                        GumCpuContext * cpu_context,
                                        gpointer * caller_ret_addr,
                                        gpointer * next_hop)
{
  GumInterceptor * interceptor;
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStack * stack;
  GumInvocationStackEntry * stack_entry;
  GumInvocationContext * invocation_ctx = NULL;
  gint system_error;
  gboolean invoke_listeners = TRUE;
  gboolean will_trap_on_leave = FALSE;

  g_atomic_int_inc (&function_ctx->trampoline_usage_counter);

  interceptor = function_ctx->interceptor;

#ifdef HAVE_WINDOWS
  system_error = gum_thread_get_system_error ();
#endif

  if (gum_tls_key_get_value (gum_interceptor_guard_key) == interceptor)
  {
    *next_hop = function_ctx->on_invoke_trampoline;
    goto bypass;
  }
  gum_tls_key_set_value (gum_interceptor_guard_key, interceptor);

  interceptor_ctx = get_interceptor_thread_context ();
  stack = interceptor_ctx->stack;

  stack_entry = gum_invocation_stack_peek_top (stack);
  if (stack_entry != NULL &&
      stack_entry->calling_replacement &&
      gum_strip_code_pointer (GUM_FUNCPTR_TO_POINTER (
          stack_entry->invocation_context.function)) ==
          function_ctx->function_address)
  {
    gum_tls_key_set_value (gum_interceptor_guard_key, NULL);
    *next_hop = function_ctx->on_invoke_trampoline;
    goto bypass;
  }

#ifndef HAVE_WINDOWS
  system_error = gum_thread_get_system_error ();
#endif

  if (interceptor->selected_thread_id != 0)
  {
    invoke_listeners =
        gum_process_get_current_thread_id () == interceptor->selected_thread_id;
  }

  if (invoke_listeners)
  {
    invoke_listeners = (interceptor_ctx->ignore_level <= 0);
  }

  will_trap_on_leave = function_ctx->replacement_function != NULL ||
      (invoke_listeners && function_ctx->has_on_leave_listener);
  if (will_trap_on_leave)
  {
    stack_entry = gum_invocation_stack_push (stack, function_ctx,
        *caller_ret_addr);
    invocation_ctx = &stack_entry->invocation_context;
  }
  else if (invoke_listeners)
  {
    stack_entry = gum_invocation_stack_push (stack, function_ctx,
        function_ctx->function_address);
    invocation_ctx = &stack_entry->invocation_context;
  }

  if (invocation_ctx != NULL)
    invocation_ctx->system_error = system_error;

  gum_function_context_fixup_cpu_context (function_ctx, cpu_context);

  if (invoke_listeners)
  {
    GPtrArray * listener_entries;
    guint i;

    invocation_ctx->cpu_context = cpu_context;
    invocation_ctx->backend = &interceptor_ctx->listener_backend;

    listener_entries =
        (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
    for (i = 0; i != listener_entries->len; i++)
    {
      ListenerEntry * listener_entry;
      ListenerInvocationState state;

      listener_entry = g_ptr_array_index (listener_entries, i);
      if (listener_entry == NULL)
        continue;

      state.point_cut = GUM_POINT_ENTER;
      state.entry = listener_entry;
      state.interceptor_ctx = interceptor_ctx;
      state.invocation_data = stack_entry->listener_invocation_data[i];
      invocation_ctx->backend->data = &state;

#ifndef GUM_DIET
      if (listener_entry->listener_interface->on_enter != NULL)
      {
        listener_entry->listener_interface->on_enter (
            listener_entry->listener_instance, invocation_ctx);
      }
#else
      gum_invocation_listener_on_enter (listener_entry->listener_instance,
          invocation_ctx);
#endif
    }

    system_error = invocation_ctx->system_error;
  }

  if (!will_trap_on_leave && invoke_listeners)
  {
    gum_invocation_stack_pop (interceptor_ctx->stack);
  }

  gum_thread_set_system_error (system_error);

  gum_tls_key_set_value (gum_interceptor_guard_key, NULL);

  if (will_trap_on_leave)
  {
    *caller_ret_addr = function_ctx->on_leave_trampoline;
  }

  if (function_ctx->replacement_function != NULL)
  {
    stack_entry->calling_replacement = TRUE;
    stack_entry->cpu_context = *cpu_context;
    stack_entry->original_system_error = system_error;
    invocation_ctx->cpu_context = &stack_entry->cpu_context;
    invocation_ctx->backend = &interceptor_ctx->replacement_backend;
    invocation_ctx->backend->data = function_ctx->replacement_data;

    *next_hop = function_ctx->replacement_function;
  }
  else
  {
    *next_hop = function_ctx->on_invoke_trampoline;
  }

bypass:
  if (!will_trap_on_leave)
  {
    g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
  }

  return will_trap_on_leave;
}

void
_gum_function_context_end_invocation (GumFunctionContext * function_ctx,
                                      GumCpuContext * cpu_context,
                                      gpointer * next_hop)
{
  gint system_error;
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * stack_entry;
  GumInvocationContext * invocation_ctx;
  GPtrArray * listener_entries;
  guint i;

#ifdef HAVE_WINDOWS
  system_error = gum_thread_get_system_error ();
#endif

  gum_tls_key_set_value (gum_interceptor_guard_key, function_ctx->interceptor);

#ifndef HAVE_WINDOWS
  system_error = gum_thread_get_system_error ();
#endif

  interceptor_ctx = get_interceptor_thread_context ();

  stack_entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  *next_hop = gum_sign_code_pointer (stack_entry->caller_ret_addr);

  invocation_ctx = &stack_entry->invocation_context;
  invocation_ctx->cpu_context = cpu_context;
  if (stack_entry->calling_replacement &&
      invocation_ctx->system_error != stack_entry->original_system_error)
  {
    system_error = invocation_ctx->system_error;
  }
  else
  {
    invocation_ctx->system_error = system_error;
  }
  invocation_ctx->backend = &interceptor_ctx->listener_backend;

  gum_function_context_fixup_cpu_context (function_ctx, cpu_context);

  listener_entries =
      (GPtrArray *) g_atomic_pointer_get (&function_ctx->listener_entries);
  for (i = 0; i != listener_entries->len; i++)
  {
    ListenerEntry * listener_entry;
    ListenerInvocationState state;

    listener_entry = g_ptr_array_index (listener_entries, i);
    if (listener_entry == NULL)
      continue;

    state.point_cut = GUM_POINT_LEAVE;
    state.entry = listener_entry;
    state.interceptor_ctx = interceptor_ctx;
    state.invocation_data = stack_entry->listener_invocation_data[i];
    invocation_ctx->backend->data = &state;

#ifndef GUM_DIET
    if (listener_entry->listener_interface->on_leave != NULL)
    {
      listener_entry->listener_interface->on_leave (
          listener_entry->listener_instance, invocation_ctx);
    }
#else
    gum_invocation_listener_on_leave (listener_entry->listener_instance,
        invocation_ctx);
#endif
  }

  gum_thread_set_system_error (invocation_ctx->system_error);

  gum_invocation_stack_pop (interceptor_ctx->stack);

  gum_tls_key_set_value (gum_interceptor_guard_key, NULL);

  g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
}

static void
gum_function_context_fixup_cpu_context (GumFunctionContext * function_ctx,
                                        GumCpuContext * cpu_context)
{
  gsize pc;

  pc = GPOINTER_TO_SIZE (function_ctx->function_address);
#ifdef HAVE_ARM
  pc &= ~1;
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  cpu_context->eip = pc;
# else
  cpu_context->rip = pc;
# endif
#elif defined (HAVE_ARM)
  cpu_context->pc = pc;
#elif defined (HAVE_ARM64)
  cpu_context->pc = pc;
#elif defined (HAVE_MIPS)
  cpu_context->pc = pc;
#else
# error Unsupported architecture
#endif
}

static InterceptorThreadContext *
get_interceptor_thread_context (void)
{
  InterceptorThreadContext * context;

  context = g_private_get (&gum_interceptor_context_private);
  if (context == NULL)
  {
    context = interceptor_thread_context_new ();

    gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
    g_hash_table_add (gum_interceptor_thread_contexts, context);
    gum_spinlock_release (&gum_interceptor_thread_context_lock);

    g_private_set (&gum_interceptor_context_private, context);
  }

  return context;
}

static void
release_interceptor_thread_context (InterceptorThreadContext * context)
{
  if (gum_interceptor_thread_contexts == NULL)
    return;

  gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
  g_hash_table_remove (gum_interceptor_thread_contexts, context);
  gum_spinlock_release (&gum_interceptor_thread_context_lock);
}

static GumPointCut
gum_interceptor_invocation_get_listener_point_cut (
    GumInvocationContext * context)
{
  return ((ListenerInvocationState *) context->backend->data)->point_cut;
}

static GumPointCut
gum_interceptor_invocation_get_replacement_point_cut (
    GumInvocationContext * context)
{
  return GUM_POINT_ENTER;
}

static GumThreadId
gum_interceptor_invocation_get_thread_id (GumInvocationContext * context)
{
  return gum_process_get_current_thread_id ();
}

static guint
gum_interceptor_invocation_get_depth (GumInvocationContext * context)
{
  InterceptorThreadContext * interceptor_ctx =
      (InterceptorThreadContext *) context->backend->state;

  return interceptor_ctx->stack->len - 1;
}

static gpointer
gum_interceptor_invocation_get_listener_thread_data (
    GumInvocationContext * context,
    gsize required_size)
{
  ListenerInvocationState * data =
      (ListenerInvocationState *) context->backend->data;

  return interceptor_thread_context_get_listener_data (data->interceptor_ctx,
      data->entry->listener_instance, required_size);
}

static gpointer
gum_interceptor_invocation_get_listener_function_data (
    GumInvocationContext * context)
{
  return ((ListenerInvocationState *)
      context->backend->data)->entry->function_data;
}

static gpointer
gum_interceptor_invocation_get_listener_invocation_data (
    GumInvocationContext * context,
    gsize required_size)
{
  ListenerInvocationState * data;

  data = (ListenerInvocationState *) context->backend->data;

  if (required_size > GUM_MAX_LISTENER_DATA)
    return NULL;

  return data->invocation_data;
}

static gpointer
gum_interceptor_invocation_get_replacement_data (GumInvocationContext * context)
{
  return context->backend->data;
}

static const GumInvocationBackend
gum_interceptor_listener_invocation_backend =
{
  gum_interceptor_invocation_get_listener_point_cut,

  gum_interceptor_invocation_get_thread_id,
  gum_interceptor_invocation_get_depth,

  gum_interceptor_invocation_get_listener_thread_data,
  gum_interceptor_invocation_get_listener_function_data,
  gum_interceptor_invocation_get_listener_invocation_data,

  NULL,

  NULL,
  NULL
};

static const GumInvocationBackend
gum_interceptor_replacement_invocation_backend =
{
  gum_interceptor_invocation_get_replacement_point_cut,

  gum_interceptor_invocation_get_thread_id,
  gum_interceptor_invocation_get_depth,

  NULL,
  NULL,
  NULL,

  gum_interceptor_invocation_get_replacement_data,

  NULL,
  NULL
};

static InterceptorThreadContext *
interceptor_thread_context_new (void)
{
  InterceptorThreadContext * context;

  context = g_slice_new0 (InterceptorThreadContext);

  gum_memcpy (&context->listener_backend,
      &gum_interceptor_listener_invocation_backend,
      sizeof (GumInvocationBackend));
  gum_memcpy (&context->replacement_backend,
      &gum_interceptor_replacement_invocation_backend,
      sizeof (GumInvocationBackend));
  context->listener_backend.state = context;
  context->replacement_backend.state = context;

  context->ignore_level = 0;

  context->stack = g_array_sized_new (FALSE, TRUE,
      sizeof (GumInvocationStackEntry), GUM_MAX_CALL_DEPTH);

  context->listener_data_slots = g_array_sized_new (FALSE, TRUE,
      sizeof (ListenerDataSlot), GUM_MAX_LISTENERS_PER_FUNCTION);

  return context;
}

static void
interceptor_thread_context_destroy (InterceptorThreadContext * context)
{
  g_array_free (context->listener_data_slots, TRUE);

  g_array_free (context->stack, TRUE);

  g_slice_free (InterceptorThreadContext, context);
}

static gpointer
interceptor_thread_context_get_listener_data (InterceptorThreadContext * self,
                                              GumInvocationListener * listener,
                                              gsize required_size)
{
  guint i;
  ListenerDataSlot * available_slot = NULL;

  if (required_size > GUM_MAX_LISTENER_DATA)
    return NULL;

  for (i = 0; i != self->listener_data_slots->len; i++)
  {
    ListenerDataSlot * slot;

    slot = &g_array_index (self->listener_data_slots, ListenerDataSlot, i);
    if (slot->owner == listener)
      return slot->data;
    else if (slot->owner == NULL)
      available_slot = slot;
  }

  if (available_slot == NULL)
  {
    g_array_set_size (self->listener_data_slots,
        self->listener_data_slots->len + 1);
    available_slot = &g_array_index (self->listener_data_slots,
        ListenerDataSlot, self->listener_data_slots->len - 1);
  }
  else
  {
    gum_memset (available_slot->data, 0, sizeof (available_slot->data));
  }

  available_slot->owner = listener;

  return available_slot->data;
}

static void
interceptor_thread_context_forget_listener_data (
    InterceptorThreadContext * self,
    GumInvocationListener * listener)
{
  guint i;

  for (i = 0; i != self->listener_data_slots->len; i++)
  {
    ListenerDataSlot * slot;

    slot = &g_array_index (self->listener_data_slots, ListenerDataSlot, i);
    if (slot->owner == listener)
    {
      slot->owner = NULL;
      return;
    }
  }
}

static GumInvocationStackEntry *
gum_invocation_stack_push (GumInvocationStack * stack,
                           GumFunctionContext * function_ctx,
                           gpointer caller_ret_addr)
{
  GumInvocationStackEntry * entry;
  GumInvocationContext * ctx;

  g_array_set_size (stack, stack->len + 1);
  entry = (GumInvocationStackEntry *)
      &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  entry->function_ctx = function_ctx;
  entry->caller_ret_addr = caller_ret_addr;

  ctx = &entry->invocation_context;
  ctx->function = gum_sign_code_pointer (function_ctx->function_address);

  ctx->backend = NULL;

  return entry;
}

static gpointer
gum_invocation_stack_pop (GumInvocationStack * stack)
{
  GumInvocationStackEntry * entry;
  gpointer caller_ret_addr;

  entry = (GumInvocationStackEntry *)
      &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  caller_ret_addr = entry->caller_ret_addr;
  g_array_set_size (stack, stack->len - 1);

  return caller_ret_addr;
}

static GumInvocationStackEntry *
gum_invocation_stack_peek_top (GumInvocationStack * stack)
{
  if (stack->len == 0)
    return NULL;

  return &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
}

static gpointer
gum_interceptor_resolve (GumInterceptor * self,
                         gpointer address)
{
  address = gum_strip_code_pointer (address);

  if (!gum_interceptor_has (self, address))
  {
    const gsize max_redirect_size = 16;
    gpointer target;

    gum_ensure_code_readable (address, max_redirect_size);

    /* Avoid following grafted branches. */
    if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
      return address;

    target = _gum_interceptor_backend_resolve_redirect (self->backend,
        address);
    if (target != NULL)
      return gum_interceptor_resolve (self, target);
  }

  return address;
}

static gboolean
gum_interceptor_has (GumInterceptor * self,
                     gpointer function_address)
{
  return g_hash_table_lookup (self->function_by_address,
      function_address) != NULL;
}

static gpointer
gum_page_address_from_pointer (gpointer ptr)
{
  return GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (ptr) & ~((gsize) gum_query_page_size () - 1));
}

static gint
gum_page_address_compare (gconstpointer a,
                          gconstpointer b)
{
  return GPOINTER_TO_SIZE (a) - GPOINTER_TO_SIZE (b);
}

"""


```