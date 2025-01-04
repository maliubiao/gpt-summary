Response:
The user wants to understand the functionality of the provided C code snippet from `gumstalker-arm.c`. They are particularly interested in:

1. **General Functionality:** What does this code do?
2. **Relationship to Reversing:** How does it relate to reverse engineering techniques?
3. **Low-level Details:** How does it interact with binary, Linux/Android kernel, and framework aspects?
4. **Logical Reasoning:** Can I provide examples of inputs and outputs based on its logic?
5. **Common User Errors:** What are typical mistakes users might make when using this code?
6. **User Operations to Reach This Code:**  How does a user's actions in Frida lead to the execution of this code?
7. **Summary:** A concise summary of the code's purpose.

I need to analyze each function within the provided snippet, focusing on these aspects. The snippet includes functions related to infecting and disinfecting threads, activating and deactivating the stalker, managing call probes, and modifying thread execution.

**Function Breakdown and Analysis Plan:**

*   **`gum_stalker_infect`**: This seems to be the core mechanism for injecting the stalker into a thread. It sets up an execution context and redirects the thread's execution.
    *   **Reversing:** This is fundamental to dynamic instrumentation, a key reversing technique.
    *   **Low-level:** Directly manipulates CPU context, deals with instruction pointers, and uses ARM-specific writers.
    *   **Logic:** Sets up a new execution context and jumps to the infection thunk.
    *   **User Error:** Incorrect `user_data` could lead to issues.
    *   **User Operation:** Calling `Stalker.follow()` would likely lead to this.
*   **`gum_stalker_disinfect`**: This function reverses the effects of `gum_stalker_infect`, restoring the original execution flow.
    *   **Reversing:**  Essential for cleaning up after instrumentation.
    *   **Low-level:** Modifies the CPU's program counter.
    *   **Logic:** Checks if the infection is active and restores the original PC.
    *   **User Error:** Calling `Stalker.unfollow()` incorrectly might cause issues.
    *   **User Operation:** Calling `Stalker.unfollow()` would trigger this.
*   **`_gum_stalker_do_activate`**:  This appears to activate the stalker for a specific target.
    *   **Reversing:** Used when focusing instrumentation on a specific function or code region.
    *   **Low-level:**  Deals with execution contexts and potential code rewriting.
    *   **Logic:** Checks if the return address is within the current context and potentially obtains a new block.
    *   **User Error:**  Providing an invalid `target` address.
    *   **User Operation:** Likely called internally when setting up instrumentation for specific functions.
*   **`_gum_stalker_do_deactivate`**: This deactivates the stalker, potentially returning control to the original code flow.
    *   **Reversing:** Necessary to stop instrumentation at a particular point.
    *   **Low-level:** Manages execution context state.
    *   **Logic:** Decrements pending calls and potentially returns to a stored location.
    *   **User Error:**  Mismatched activation/deactivation calls.
    *   **User Operation:** Called internally when finishing instrumentation on a specific function.
*   **`gum_stalker_maybe_deactivate`**: Conditionally deactivates the stalker based on the number of pending calls.
    *   **Reversing:** Helps manage the stalker's activation state.
    *   **Logic:** Checks `pending_calls` and calls `gum_stalker_deactivate`.
*   **`gum_stalker_maybe_reactivate`**:  Conditionally reactivates the stalker.
    *   **Reversing:**  Restores the stalker's activity.
    *   **Logic:** Checks if deactivation is pending and calls `gum_stalker_activate`.
*   **`gum_stalker_set_observer`**: Allows setting an observer for stalker events.
    *   **Reversing:**  Useful for gaining insights into the stalker's operation.
    *   **Logic:**  Manages a reference to the observer object.
*   **`gum_stalker_prefetch`**: Preloads code blocks into the stalker's cache.
    *   **Reversing:**  Can improve performance by ensuring frequently accessed code is readily available.
    *   **Low-level:**  Interacts with the execution context's block management.
*   **`gum_stalker_prefetch_backpatch`**: Handles backpatching, modifying code to redirect execution.
    *   **Reversing:** A powerful technique for code modification during runtime.
    *   **Low-level:** Deals with ARM/Thumb instruction encoding and block management.
*   **`gum_stalker_recompile`**: Forces recompilation of a code block.
    *   **Reversing:**  Useful when code has been modified externally.
    *   **Low-level:**  Invalidates cached code and triggers recompilation.
*   **`gum_stalker_backpatch_get_from`**, **`gum_stalker_backpatch_get_to`**: Accessors for backpatch information.
*   **`gum_stalker_invalidate`**, **`gum_stalker_invalidate_for_thread`**, **`gum_stalker_invalidate_for_all_threads`**:  Functions to invalidate cached code blocks, ensuring the stalker picks up changes.
    *   **Reversing:** Important for maintaining consistency when the target process modifies its own code.
    *   **Low-level:** Interacts with the execution context's block management and thread states.
*   **`gum_stalker_add_call_probe`**:  Inserts a probe at a specific function call.
    *   **Reversing:**  A fundamental technique for intercepting function calls and inspecting arguments/return values.
    *   **Low-level:**  Modifies code to redirect execution to the probe's callback.
*   **`gum_stalker_remove_call_probe`**: Removes a previously added call probe.
    *   **Reversing:** Cleans up instrumentation.
*   **`_gum_stalker_modify_to_run_on_thread`**:  Modifies a thread's execution to run a specific function.
    *   **Reversing:**  Allows injecting arbitrary code into a running thread.
    *   **Low-level:**  Directly manipulates the CPU context and writes code.
*   **Helper Functions (`gum_stalker_create_exec_ctx`, `gum_stalker_destroy_exec_ctx`, etc.)**: These handle the internal management of execution contexts and resources.

By analyzing each of these functions and considering the user's requests, I can generate a comprehensive answer. The key is to connect the code's actions to higher-level concepts in reverse engineering and provide concrete examples where possible.
这是 frida 动态 instrumentation 工具中 `frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c` 文件的第二部分源代码，它主要负责以下功能：

**核心功能：线程的感染、消毒、激活与去激活**

这部分代码的核心是管理 Frida Stalker 对目标进程线程的控制和介入，具体包括：

1. **感染线程 (`gum_stalker_infect`)**:
    *   **功能**:  将 Stalker 注入到指定的线程中，开始追踪该线程的执行流程。
    *   **逆向关系**: 这是动态 instrumentation 的核心步骤，通过感染线程，Frida 才能监控和修改其行为。例如，在逆向一个函数时，需要先感染包含该函数的线程，才能在函数入口或出口插入 hook 代码。
    *   **二进制底层**:
        *   **CPU 上下文操作 (`cpu_context`)**:  直接修改目标线程的 CPU 寄存器状态，例如程序计数器 (`pc`) 和程序状态寄存器 (`cpsr`)。
        *   **ARM 指令写入 (`GumArmWriter`)**: 使用 `GumArmWriter` 结构体，在目标线程的代码段中写入 ARM 指令，实现代码注入和重定向。
        *   **内存管理 (`gum_stalker_thaw`, `gum_stalker_freeze`)**: 临时解除代码页面的写保护 (`thaw`) 以便写入 hook 代码，完成后再恢复保护 (`freeze`) 并清理 CPU 缓存。
    *   **Linux/Android 内核**: 涉及到进程和线程的管理，例如获取线程 ID，以及可能触发内核的内存管理机制。
    *   **逻辑推理**:
        *   **假设输入**: `thread_id` 为目标线程的 ID，`cpu_context` 为目标线程的 CPU 寄存器状态，`user_data` 包含感染上下文信息。
        *   **预期输出**: 目标线程的 `pc` 指向 Frida 注入的 `infect_thunk` 代码，开始执行 Frida 的控制流程。
    *   **用户/编程常见错误**: 错误的 `user_data` 可能会导致感染失败或程序崩溃。例如，`infect_context->transformer` 或 `infect_context->sink` 为空指针。
    *   **调试线索**: 用户通过 Frida 的 API（例如 `Stalker.follow(threadId)`) 指定要跟踪的线程 ID，Frida 内部会将这个 `threadId` 和当前线程的 CPU 上下文传递到 `gum_stalker_infect` 函数。
    *   **代码逻辑**:
        *   创建一个与目标线程关联的执行上下文 (`GumExecCtx`)。
        *   判断目标线程当前的指令集状态（ARM 或 Thumb 模式）。
        *   为目标线程获取一个代码块 (`gum_exec_ctx_obtain_block_for`)。
        *   如果需要取消跟踪 (`gum_exec_ctx_maybe_unfollow`)，则销毁执行上下文并返回。
        *   清除目标线程 CPU 上下文中的 Thumb 模式标志。
        *   将目标线程的 `pc` 修改为指向 Frida 的感染跳板代码 (`ctx->infect_thunk`)。
        *   获取代码锁，确保代码写入的原子性。
        *   解除代码页面的写保护 (`gum_stalker_thaw`)。
        *   重置 ARM 代码写入器，指向感染跳板代码的起始位置。
        *   写入 ARM 代码序言 (`gum_exec_ctx_write_arm_prolog`)。
        *   调用 `g_private_set` 将当前的执行上下文与线程关联起来。
        *   写入 ARM 代码结尾 (`gum_exec_ctx_write_arm_epilog`)。
        *   将生成的代码写入到可执行内存中 (`gum_exec_block_write_arm_exec_generated_code`)。
        *   刷新 ARM 代码写入器的缓冲区。
        *   恢复代码页面的写保护 (`gum_stalker_freeze`)。
        *   释放代码锁。
        *   启动事件接收器 (`gum_event_sink_start`)。

2. **消毒线程 (`gum_stalker_disinfect`)**:
    *   **功能**:  移除 Stalker 对指定线程的控制，使其恢复到正常的执行流程。
    *   **逆向关系**:  在完成动态分析后，需要对线程进行消毒，避免持续的性能损耗和干扰。
    *   **二进制底层**: 直接修改目标线程的 `pc`，使其跳转回原始的执行地址。
    *   **逻辑推理**:
        *   **假设输入**: `thread_id` 为目标线程的 ID，`cpu_context` 为目标线程的 CPU 寄存器状态，`user_data` 包含消毒上下文信息。
        *   **预期输出**: 目标线程的 `pc` 被恢复为感染前的地址，继续执行原始代码。
    *   **用户/编程常见错误**:  在 Stalker 还在活动时尝试消毒线程可能导致不可预测的结果。
    *   **调试线索**: 用户通过 Frida 的 API（例如 `Stalker.unfollow(threadId)`) 指定要取消跟踪的线程 ID，Frida 内部会将这些信息传递给 `gum_stalker_disinfect`。
    *   **代码逻辑**:
        *   检查目标线程的 `pc` 是否指向感染跳板代码，以此判断感染是否已经激活。
        *   如果感染尚未激活，则获取当前代码块的信息。
        *   将目标线程的 `pc` 修改为代码块的真实起始地址 (`block->real_start`)。
        *   设置消毒上下文的 `success` 标志为 `TRUE`。

3. **激活 Stalker (`_gum_stalker_do_activate`)**:
    *   **功能**:  在特定的代码位置激活 Stalker 的追踪和修改功能。
    *   **逆向关系**: 用于在特定的函数入口或代码区域开始精细的监控。
    *   **逻辑推理**:
        *   **假设输入**: `self` 为 `GumStalker` 实例，`target` 为要激活 Stalker 的目标地址，`ret_addr` 为返回地址。
        *   **预期输出**: 如果返回地址不在当前的执行上下文中，则获取一个新的代码块并返回其地址，否则直接返回返回地址。
    *   **用户操作**:  当用户使用 `Stalker.attach()` 或类似的功能时，可能会触发 Stalker 的激活。
    *   **代码逻辑**:
        *   获取当前的执行上下文。
        *   设置 `unfollow_called_while_still_following` 标志为 `FALSE`。
        *   记录激活的目标地址。
        *   检查返回地址是否在当前的执行上下文中。
        *   如果不在，则为返回地址获取一个代码块。
        *   如果需要取消跟踪，则直接返回返回地址。
        *   否则，返回新获取的代码块地址。

4. **去激活 Stalker (`_gum_stalker_do_deactivate`)**:
    *   **功能**:  暂停 Stalker 的追踪和修改功能。
    *   **逆向关系**: 用于在分析完成后停止监控，或者在特定的代码区域临时关闭 Stalker。
    *   **逻辑推理**:
        *   **假设输入**: `self` 为 `GumStalker` 实例，`ret_addr` 为返回地址。
        *   **预期输出**: 如果返回地址在当前的执行上下文中，则返回挂起的返回位置，否则返回原始的返回地址。
    *   **用户操作**:  当用户使用 `Stalker.detach()` 或类似的功能时，可能会触发 Stalker 的去激活。
    *   **代码逻辑**:
        *   获取当前的执行上下文。
        *   设置 `unfollow_called_while_still_following` 标志为 `TRUE`。
        *   清除激活的目标地址。
        *   检查返回地址是否在当前的执行上下文中。
        *   如果在，则递减挂起的调用计数，并返回挂起的返回位置。
        *   否则，返回原始的返回地址。

5. **可能的激活/去激活 (`gum_stalker_maybe_deactivate`, `gum_stalker_maybe_reactivate`)**:
    *   **功能**:  根据条件判断是否需要激活或去激活 Stalker。
    *   **逻辑推理**: 这两个函数用于管理 Stalker 的状态转换，例如在所有 hook 完成后自动去激活。

**其他功能**

6. **设置观察者 (`gum_stalker_set_observer`)**:
    *   **功能**:  允许设置一个观察者对象，用于接收 Stalker 产生的事件通知。
    *   **逆向关系**:  观察者可以用于记录 Stalker 的行为，例如记录执行的代码块切换。

7. **预取代码块 (`gum_stalker_prefetch`)**:
    *   **功能**:  提前加载指定的代码块到 Stalker 的缓存中，提高执行效率。
    *   **逆向关系**:  在已知需要频繁访问的代码区域进行预取可以优化性能。

8. **预取并回填 (`gum_stalker_prefetch_backpatch`)**:
    *   **功能**:  预取代码块，并进行回填操作，通常用于实现跳转或 hook。
    *   **逆向关系**:  回填是实现动态修改代码的关键技术。
    *   **二进制底层**:  根据 ARM 或 Thumb 指令集，写入相应的分支指令。

9. **重新编译代码块 (`gum_stalker_recompile`)**:
    *   **功能**:  强制 Stalker 重新编译指定的代码块。
    *   **逆向关系**:  当目标进程的代码被修改后，需要重新编译以保持 Stalker 的同步。

10. **获取回填信息 (`gum_stalker_backpatch_get_from`, `gum_stalker_backpatch_get_to`)**:
    *   **功能**:  获取回填操作的源地址和目标地址。

11. **使代码块失效 (`gum_stalker_invalidate`, `gum_stalker_invalidate_for_thread`, `gum_stalker_invalidate_for_all_threads`, `gum_stalker_do_invalidate`, `gum_stalker_try_invalidate_block_owned_by_thread`)**:
    *   **功能**:  使 Stalker 缓存的指定地址的代码块失效，迫使其下次执行时重新获取和编译。
    *   **逆向关系**:  当目标进程修改了自身代码时，需要使 Stalker 的缓存失效以保证分析的准确性。
    *   **逻辑推理**: 这些函数提供了不同粒度的失效操作，可以针对所有线程或特定线程。

12. **添加调用探针 (`gum_stalker_add_call_probe`)**:
    *   **功能**:  在指定的函数调用处插入探针，当程序执行到该调用时会触发回调函数。
    *   **逆向关系**:  这是动态分析中常用的 hook 技术，用于拦截和监控函数调用。
    *   **用户操作**: 用户通过 Frida 的 API (例如 `Interceptor.attach()`) 添加 hook。

13. **移除调用探针 (`gum_stalker_remove_call_probe`)**:
    *   **功能**:  移除之前添加的调用探针。

14. **修改线程以在指定线程上运行 (`_gum_stalker_modify_to_run_on_thread`)**:
    *   **功能**:  修改指定线程的执行流程，使其跳转到指定的函数并执行。
    *   **逆向关系**:  可以用于注入代码到目标线程并执行。
    *   **二进制底层**:  直接修改目标线程的 CPU 上下文，写入跳转指令。
    *   **逻辑推理**:  该函数创建了一个临时的执行上下文，并将目标线程的 `pc` 修改为指向注入的代码，该代码会调用用户指定的函数。

**总结**

这段代码是 Frida Stalker 在 ARM 架构下的核心组成部分，主要负责控制和管理目标进程线程的执行流程，是实现动态 instrumentation 的关键。它通过修改 CPU 上下文、注入代码、管理内存和缓存等底层操作，实现了对目标线程的追踪、监控和修改。这些功能与逆向工程中的动态分析、hook 技术、代码注入等方法紧密相关，为逆向工程师提供了强大的工具。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
context = user_data;
  GumStalker * self = infect_context->stalker;
  GumExecCtx * ctx;
  guint32 pc;
  GumArmWriter * cw;

  ctx = gum_stalker_create_exec_ctx (self, thread_id,
      infect_context->transformer, infect_context->sink);

  if ((cpu_context->cpsr & GUM_PSR_T_BIT) == 0)
    pc = cpu_context->pc;
  else
    pc = cpu_context->pc + 1;

  ctx->current_block = gum_exec_ctx_obtain_block_for (ctx,
      GSIZE_TO_POINTER (pc), &ctx->resume_at);

  if (gum_exec_ctx_maybe_unfollow (ctx, NULL))
  {
    gum_stalker_destroy_exec_ctx (self, ctx);
    return;
  }

  cpu_context->cpsr &= ~GUM_PSR_T_BIT;
  cpu_context->pc = GPOINTER_TO_SIZE (ctx->infect_thunk);

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (self, ctx->thunks, self->thunks_size);
  cw = &ctx->arm_writer;
  gum_arm_writer_reset (cw, ctx->infect_thunk);

  gum_exec_ctx_write_arm_prolog (ctx, cw);
  gum_arm_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (g_private_set), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (&gum_stalker_exec_ctx_private),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx));
  gum_exec_ctx_write_arm_epilog (ctx, cw);

  gum_exec_block_write_arm_exec_generated_code (cw, ctx);

  gum_arm_writer_flush (cw);
  gum_stalker_freeze (self, cw->base, gum_arm_writer_offset (cw));

  gum_spinlock_release (&ctx->code_lock);

  gum_event_sink_start (ctx->sink);
  ctx->sink_started = TRUE;
}

static void
gum_stalker_disinfect (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  GumDisinfectContext * disinfect_context = user_data;
  GumExecCtx * ctx = disinfect_context->exec_ctx;
  gboolean infection_not_active_yet;

  infection_not_active_yet =
      cpu_context->pc == GPOINTER_TO_SIZE (ctx->infect_thunk);
  if (infection_not_active_yet)
  {
    GumExecBlock * block = ctx->current_block;

    cpu_context->pc = GPOINTER_TO_SIZE (
        gum_exec_block_encode_instruction_pointer (block, block->real_start));

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
  ctx->activation_target = target;

  if (!gum_exec_ctx_contains (ctx, ret_addr))
  {
    gpointer code_address;

    ctx->current_block =
        gum_exec_ctx_obtain_block_for (ctx, ret_addr, &code_address);

    if (gum_exec_ctx_maybe_unfollow (ctx, ret_addr))
      return ret_addr;

    return code_address;
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
    case GUM_BACKPATCH_ARM:
    {
      gum_exec_ctx_backpatch_arm_branch_to_current (block_to, block_from,
          from_insn, backpatch->code_offset, backpatch->opened_prolog);
      break;
    }
    case GUM_BACKPATCH_THUMB:
    {
      gum_exec_ctx_backpatch_thumb_branch_to_current (block_to, block_from,
          from_insn, backpatch->code_offset, backpatch->opened_prolog);
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
  const guint8 * pc = GSIZE_TO_POINTER (cpu_context->pc);

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
  guint32 pc;
  GumArmWriter * cw;
  GumAddress cpu_context_copy, infect_body;

  ctx = gum_stalker_create_exec_ctx (self, thread_id, NULL, NULL);

  if ((cpu_context->cpsr & GUM_PSR_T_BIT) == 0)
    pc = cpu_context->pc;
  else
    pc = cpu_context->pc + 1;

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (self, ctx->thunks, self->thunks_size);
  cw = &ctx->arm_writer;
  gum_arm_writer_reset (cw, ctx->infect_thunk);

  cpu_context_copy = GUM_ADDRESS (gum_arm_writer_cur (cw));
  gum_arm_writer_put_bytes (cw, (guint8 *) cpu_context, sizeof (GumCpuContext));

  infect_body = GUM_ADDRESS (gum_arm_writer_cur (cw));

  gum_exec_ctx_write_arm_prolog (ctx, cw);

  gum_arm_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (func), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (cpu_context_copy),
      GUM_ARG_ADDRESS, GUM_ADDRESS (data));

  gum_arm_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (pc));

  gum_exec_ctx_write_arm_epilog (ctx, cw);

  gum_arm_writer_put_push_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R0, pc);
  gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
  gum_arm_writer_put_pop_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);

  gum_arm_writer_flush (cw);
  gum_stalker_freeze (self, cw->base, gum_arm_writer_offset (cw));

  gum_spinlock_release (&ctx->code_lock);

  cpu_context->cpsr &= ~GUM_PSR_T_BIT;
  cpu_context->pc = infect_body;
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

static void
gum_stalker_thaw (GumStalker * self,
                  gpointer code,
                  gsize size)
{
  if (!self->is_rwx_supported)
    gum_mprotect (code, size, GUM_PAGE_RW);
}

static void
gum_stalker_freeze (GumStalker * self,
                    gpointer code,
                    gsize size)
{
  if (!self->is_rwx_supported)
    gum_memory_mark_code (code, size);

  gum_clear_cache (code, size);
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
  GumDataSlab * data_slab;

  base = gum_memory_allocate (NULL, stalker->ctx_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  ctx = (GumExecCtx *) base;

  ctx->state = GUM_EXEC_CTX_ACTIVE;

  ctx->stalker = g_object_ref (stalker);
  ctx->thread_id = thread_id;

  gum_arm_writer_init (&ctx->arm_writer, NULL);
  ctx->arm_writer.cpu_features = gum_query_cpu_features ();
  gum_arm_relocator_init (&ctx->arm_relocator, NULL, &ctx->arm_writer);

  gum_thumb_writer_init (&ctx->thumb_writer, NULL);
  gum_thumb_relocator_init (&ctx->thumb_relocator, NULL, &ctx->thumb_writer);
  gum_thumb_relocator_set_it_branch_type (&ctx->thumb_relocator,
      GUM_IT_BRANCH_LONG);

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

  ctx->frames = (GumExecFrame *) (base + stalker->frames_offset);
  ctx->first_frame =
      ctx->frames + (stalker->frames_size / sizeof (GumExecFrame)) - 1;
  ctx->current_frame = ctx->first_frame;

  ctx->thunks = base + stalker->thunks_offset;
  ctx->infect_thunk = ctx->thunks;

  gum_spinlock_init (&ctx->code_lock);

  code_slab = (GumCodeSlab *) (base + stalker->code_slab_offset);
  gum_code_slab_init (code_slab, stalker->code_slab_size_initial,
      stalker->page_size);
  gum_exec_ctx_add_code_slab (ctx, code_slab);

  data_slab = (GumDataSlab *) (base + stalker->data_slab_offset);
  gum_data_slab_init (data_slab, stalker->data_slab_size_initial);
  gum_exec_ctx_add_data_slab (ctx, data_slab);

  ctx->scratch_slab = (GumCodeSlab *) (base + stalker->scratch_slab_offset);
  gum_scratch_slab_init (ctx->scratch_slab, stalker->scratch_slab_size);

  ctx->mappings = gum_metal_hash_table_new (NULL, NULL);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

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
  while (TRUE)
  {
    GumDataSlab * next = (GumDataSlab *) data_slab->slab.next;
    gboolean is_initial;

    is_initial = next == NULL;
    if (is_initial)
      break;

    gum_data_slab_free (data_slab);

    data_slab = next;
  }

  code_slab = ctx->code_slab;
  while (TRUE)
  {
    GumCodeSlab * next = (GumCodeSlab *) code_slab->slab.next;
    gboolean is_initial;

    is_initial = next == NULL;
    if (is_initial)
      break;

    gum_code_slab_free (code_slab);

    code_slab = next;
  }

  g_object_unref (ctx->sink);
  g_object_unref (ctx->transformer);
  g_clear_object (&ctx->observer);

  gum_thumb_relocator_clear (&ctx->thumb_relocator);
  gum_thumb_writer_clear (&ctx->thumb_writer);

  gum_arm_relocator_clear (&ctx->arm_relocator);
  gum_arm_writer_clear (&ctx->arm_writer);

  g_object_unref (stalker);

  gum_memory_free (ctx, stalker->ctx_size);
}

static void
gum_exec_ctx_dispose (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumSlab * slab;

  for (slab = &ctx->code_slab->slab; slab != NULL; slab = slab->next)
  {
    gum_stalker_thaw (stalker, gum_slab_start (slab), slab->offset);
  }

  for (slab = &ctx->data_slab->slab; slab != NULL; slab = slab->next)
  {
    GumExecBlock * blocks;
    guint num_blocks;
    guint i;

    blocks = gum_slab_start (slab);
    num_blocks = slab->offset / sizeof (GumExecBlock);

    for (i = 0; i != num_blocks; i++)
    {
      GumExecBlock * block = &blocks[i];

      gum_exec_block_clear (block);
    }
  }
}

static GumCodeSlab *
gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
                            GumCodeSlab * code_slab)
{
  code_slab->slab.next = &ctx->code_slab->slab;
  ctx->code_slab = code_slab;
  return code_slab;
}

static GumDataSlab *
gum_exec_ctx_add_data_slab (GumExecCtx * ctx,
                            GumDataSlab * data_slab)
{
  data_slab->slab.next = &ctx->data_slab->slab;
  ctx->data_slab = data_slab;
  return data_slab;
}

static void
gum_exec_ctx_compute_code_address_spec (GumExecCtx * ctx,
                                        gsize slab_size,
                                        GumAddressSpec * spec)
{
  GumStalker * stalker = ctx->stalker;

  /* Code must be able to reference ExecCtx fields using 32-bit offsets. */
  spec->near_address = ctx;
  spec->max_distance = G_MAXINT32 - stalker->ctx_size - slab_size;
}

static void
gum_exec_ctx_compute_data_address_spec (GumExecCtx * ctx,
                                        gsize slab_size,
                                        GumAddressSpec * spec)
{
  GumStalker * stalker = ctx->stalker;

  /* Code must be able to reference ExecBlock fields using 32-bit offsets. */
  spec->near_address = ctx->code_slab;
  spec->max_distance = G_MAXINT32 - stalker->code_slab_size_dynamic - slab_size;
}

static gboolean
gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
                             gpointer resume_at)
{
  if (g_atomic_int_get (&ctx->state) != GUM_EXEC_CTX_UNFOLLOW_PENDING)
    return FALSE;

  if (ctx->pending_calls > 0)
    return FALSE;

  gum_exec_ctx_unfollow (ctx, resume_at);

  return TRUE;
}

static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
  ctx->current_block = NULL;

  ctx->resume_at = resume_at;

  g_private_set (&gum_stalker_exec_ctx_private, NULL);

  ctx->destroy_pending_since = g_get_monotonic_time ();
  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_DESTROY_PENDING);
}

static gboolean
gum_exec_ctx_has_executed (GumExecCtx * ctx)
{
  return ctx->resume_at != NULL;
}

static gboolean
gum_exec_ctx_contains (GumExecCtx * ctx,
                       gconstpointer address)
{
  GumSlab * cur = &ctx->code_slab->slab;

  do {
    if ((const guint8 *) address >= cur->data &&
        (const guint8 *) address < (guint8 *) gum_slab_cursor (cur))
    {
      return TRUE;
    }

    cur = cur->next;
  } while (cur != NULL);

  return FALSE;
}

static gboolean
gum_exec_ctx_may_now_backpatch (GumExecCtx * ctx,
                                GumExecBlock * target_block)
{
  if (g_atomic_int_get (&ctx->state) != GUM_EXEC_CTX_ACTIVE)
    return FALSE;

  if ((target_block->flags & GUM_EXEC_BLOCK_ACTIVATION_TARGET) != 0)
    return FALSE;

  if (target_block->recycle_count < ctx->stalker->trust_threshold)
    return FALSE;

  return TRUE;
}

static gpointer
gum_exec_ctx_switch_block (GumExecCtx * ctx,
                           GumExecBlock * block,
                           gpointer start_address,
                           gpointer from_insn)
{
  if (ctx->observer != NULL)
    gum_stalker_observer_increment_total (ctx->observer);

  if (start_address == gum_stalker_unfollow_me ||
      start_address == gum_stalker_deactivate)
  {
    ctx->unfollow_called_while_still_following = TRUE;
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else if (start_address == NULL || start_address == gum_thread_exit_address)
  {
    gum_exec_ctx_unfollow (ctx, start_address);
  }
  else if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
  {
  }
  else if (gum_exec_ctx_contains (ctx, start_address))
  {
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else
  {
    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, start_address,
        &ctx->resume_at);

    if (start_address == ctx->activation_target)
    {
      ctx->activation_target = NULL;
      ctx->current_block->flags |= GUM_EXEC_BLOCK_ACTIVATION_TARGET;
    }

    gum_exec_ctx_maybe_unfollow (ctx, start_address);
  }

  gum_exec_ctx_query_block_switch_callback (ctx, block, start_address,
      from_insn, &ctx->resume_at);

  return ctx->resume_at;
}

static void
gum_exec_ctx_query_block_switch_callback (GumExecCtx * ctx,
                                          GumExecBlock * block,
                                          gpointer start_address,
                                          gpointer from_insn,
                                          gpointer * target)
{
  gpointer from;

  if (ctx->observer == NULL)
    return;

  from = (block != NULL) ? block->real_start : NULL;

  gum_stalker_observer_switch_callback (ctx->observer, from, start_address,
      from_insn, target);
}

static void
gum_exec_ctx_recompile_and_switch_block (GumExecCtx * ctx,
                                         gpointer trampoline_return_address)
{
  GumExecBlock ** block_ptr, * block;
  gpointer start_address;

  block_ptr = gum_strip_thumb_bit (trampoline_return_address);
  block = *block_ptr;

  start_address =
      gum_exec_block_encode_instruction_pointer (block, block->real_start);

  if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
    return;

  gum_exec_ctx_recompile_block (ctx, block);

  ctx->current_block = block;
  ctx->resume_at =
      gum_exec_block_encode_instruction_pointer (block, block->code_start);

  if (start_address == ctx->activation_target)
  {
    ctx->activation_target = NULL;
    ctx->current_block->flags |= GUM_EXEC_BLOCK_ACTIVATION_TARGET;
  }

  gum_exec_ctx_maybe_unfollow (ctx, start_address);
}

static void
gum_exec_ctx_begin_call (GumExecCtx * ctx,
                         gpointer ret_addr)
{
  ctx->pending_return_location = ret_addr;
  ctx->pending_calls++;
}

static void
gum_exec_ctx_end_call (GumExecCtx * ctx)
{
  ctx->pending_calls--;
}

static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address)
{
  GumExecBlock * block;

  gum_spinlock_acquire (&ctx->code_lock);

  block = gum_metal_hash_table_lookup (ctx->mappings, real_address);
  if (block != NULL)
  {
    const gint trust_threshold = ctx->stalker->trust_threshold;
    gboolean still_up_to_date;

    still_up_to_date =
        (trust_threshold >= 0 && block->recycle_count >= trust_threshold) ||
        memcmp (block->real_start, gum_exec_block_get_snapshot_start (block),
            block->real_size) == 0;

    gum_spinlock_release (&ctx->code_lock);

    if (still_up_to_date)
    {
      if (trust_threshold > 0)
        block->recycle_count++;
    }
    else
    {
      gum_exec_ctx_recompile_block (ctx, block);
    }
  }
  else
  {
    gpointer aligned_address;

    block = gum_exec_block_new (ctx);
    if (gum_is_thumb (real_address))
    {
      block->flags |= GUM_EXEC_BLOCK_THUMB;
      aligned_address = gum_strip_thumb_bit (real_address);
    }
    else
    {
      aligned_address = real_address;
    }
    block->real_start = aligned_address;
    gum_exec_block_maybe_inherit_exclusive_access_state (block, block->next);
    gum_exec_ctx_compile_block (ctx, block, aligned_address, block->code_start,
        GUM_ADDRESS (block->code_start), &block->real_size, &block->code_size);
    gum_exec_block_commit (block);
    gum_exec_block_propagate_exclusive_access_state (block);

    gum_metal_hash_table_insert (ctx->mappings, real_address, block);

    gum_spinlock_release (&ctx->code_lock);

    gum_exec_ctx_maybe_emit_compile_event (ctx, block);
  }

  *code_address =
      gum_exec_block_encode_instruction_pointer (block, block->code_start);

  return block;
}

static void
gum_exec_ctx_recompile_block (GumExecCtx * ctx,
                              GumExecBlock * block)
{
  GumStalker * stalker = ctx->stalker;
  guint8 * internal_code = block->code_start;
  GumCodeSlab * slab;
  guint8 * scratch_base;
  guint input_size, output_size;
  gsize new_snapshot_size, new_block_size;

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (stalker, internal_code, block->capacity);

  if (block->storage_block != NULL)
    gum_exec_block_clear (block->storage_block);
  gum_exec_block_clear (block);

  slab = block->code_slab;
  block->code_slab = ctx->scratch_slab;
  scratch_base = ctx->scratch_slab->slab.data;
  ctx->scratch_slab->arm_invalidator = slab->arm_invalidator;
  ctx->scratch_slab->thumb_invalidator = slab->thumb_invalidator;

  gum_exec_ctx_compile_block (ctx, block, block->real_start, scratch_base,
      GUM_ADDRESS (internal_code), &input_size, &output_size);

  block->code_slab = slab;

  new_snapshot_size =
      gum_stalker_snapshot_space_needed_for (stalker, input_size);

  new_block_size = output_size + new_snapshot_size;

  if (new_block_size <= block->capacity)
  {
    block->real_size = input_size;
    block->code_size = output_size;

    memcpy (internal_code, scratch_base, output_size);
    memcpy (gum_exec_block_get_snapshot_start (block), block->real_start,
        new_snapshot_size);

    gum_stalker_freeze (stalker, internal_code, new_block_size);
  }
  else
  {
    GumExecBlock * storage_block;
    GumAddress external_code_address;

    storage_block = gum_exec_block_new (ctx);
    storage_block->flags = block->flags & 2; /* THUMB flag */
    storage_block->real_start = block->real_start;
    gum_exec_ctx_compile_block (ctx, block, block->real_start,
        storage_block->code_start, GUM_ADDRESS (storage_block->code_start),
        &storage_block->real_size, &storage_block->code_size);
    gum_exec_block_commit (storage_block);

    block->storage_block = storage_block;

    gum_stalker_thaw (stalker, internal_code, block->capacity);

    external_code_address = GUM_ADDRESS (storage_block->code_start);

    if ((block->flags & GUM_EXEC_BLOCK_THUMB) != 0)
    {
      GumThumbWriter * cw = &ctx->thumb_writer;

      gum_thumb_writer_reset (cw, internal_code);
      gum_thumb_writer_put_branch_address (cw, external_code_address);
      gum_thumb_writer_flush (cw);
    }
    else
    {
      GumArmWriter * cw = &ctx->arm_writer;

      gum_arm_writer_reset (cw, internal_code);
      gum_arm_writer_put_branch_address (cw, external_code_address);
      gum_arm_writer_flush (cw);
    }

    gum_stalker_freeze (stalker, internal_code, block->capacity);
  }

  gum_spinlock_release (&ctx->code_lock);

  gum_exec_ctx_maybe_emit_compile_event (ctx, block);
}

static void
gum_exec_ctx_compile_block (GumExecCtx * ctx,
                            GumExecBlock * block,
                            gconstpointer input_code,
                            gpointer output_code,
                            GumAddress output_pc,
                            guint * input_size,
                            guint * output_size)
{
  if ((block->flags & GUM_EXEC_BLOCK_THUMB) != 0)
  {
    gum_exec_ctx_compile_thumb_block (ctx, block, input_code, output_code,
        output_pc, input_size, output_size);
  }
  else
  {
    gum_exec_ctx_compile_arm_block (ctx, block, input_code, output_code,
        output_pc, input_size, output_size);
  }
}

static void
gum_exec_ctx_compile_arm_block (GumExecCtx * ctx,
                                GumExecBlock * block,
                                gconstpointer input_code,
                                gpointer output_code,
                                GumAddress output_pc,
                                guint * input_size,
                                guint * output_size)
{
  GumArmWriter * cw = &ctx->arm_writer;
  GumArmRelocator * rl = &ctx->arm_relocator;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  GumStalkerOutput output;
  gboolean all_labels_resolved;

  gum_arm_writer_reset (cw, output_code);
  cw->pc = output_pc;
  gum_arm_relocator_reset (rl, input_code, cw);

  gum_ensure_code_readable (input_code, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.is_thumb = FALSE;
  gc.arm_relocator = rl;
  gc.arm_writer = cw;
  gc.continuation_real_address = NULL;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instr
"""


```