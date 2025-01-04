Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

**1. Initial Understanding and Context:**

The very first step is to understand the context provided by the prompt. It clearly states:

* **Language:** C
* **Project:** Frida Dynamic Instrumentation Tool
* **Location:** `frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c`
* **Core Concept:** `GumStalker` - This immediately signals that the code is about tracing and instrumenting execution.
* **Part of a Larger Whole:** "This is part 3 of 7" indicates there's a broader system at play.

**2. High-Level Skimming for Key Structures and Functions:**

Next, I quickly skimmed the code looking for recurring patterns and important keywords. This helps to get a general idea of the code's purpose without diving into the details yet. I noticed:

* **Structures:** `GumStalker`, `GumExecCtx`, `GumExecBlock`, `GumCodeSlab`, `GumSlowSlab`, `GumDataSlab`, `GumStalkerTransformer`, `GumEventSink`, `GumCpuContext`. These are likely the core data structures involved.
* **Functions starting with `gum_stalker_`:**  These are likely the primary functions related to the `GumStalker` itself.
* **Functions starting with `gum_exec_ctx_`:**  These probably manage the execution contexts of the stalker.
* **Function prefixes like `gum_code_slab_`, `gum_slow_slab_`, `gum_data_slab_`:** These clearly handle memory management for different types of code and data.
* **Locking mechanisms:** `GUM_STALKER_LOCK`, `GUM_STALKER_UNLOCK`, `gum_spinlock_acquire`, `gum_spinlock_release`. Concurrency is a factor.
* **Memory operations:** `gum_memory_allocate`, `gum_memory_free`, `gum_mprotect`, `gum_memory_mark_code`, `gum_clear_cache`. Dealing with low-level memory.
* **Callbacks and events:**  `GumStalkerTransformer`, `GumEventSink`, functions like `gum_exec_ctx_emit_call_event`, `gum_exec_ctx_emit_ret_event`, etc. Instrumentation and reporting are key.
* **`capstone` integration:** `gum_stalker_iterator_get_capstone`. Disassembly is involved.
* **Assembly writing:** `GumX86Writer`, `gum_x86_writer_put_*`. Generating code dynamically.
* **Relocation:** `GumX86Relocator`. Adjusting code addresses during instrumentation.

**3. Focusing on Specific Function Groups and Their Interactions:**

After the initial skimming, I started to group functions based on their apparent roles. This helps to understand the flow of logic.

* **Stalker Management:** `gum_stalker_new`, `gum_stalker_free`, `gum_stalker_create_exec_ctx`, `gum_stalker_destroy_exec_ctx`, `gum_stalker_find_exec_ctx_by_thread_id`. These manage the overall stalker instance and its execution contexts.
* **Execution Context Management:** `gum_exec_ctx_new`, `gum_exec_ctx_free`, `gum_exec_ctx_dispose`, `gum_exec_ctx_switch_block`, `gum_exec_ctx_obtain_block_for`, `gum_exec_ctx_compile_block`. This is central to how Frida intercepts and modifies execution.
* **Code Block Management:**  `gum_exec_block_new`, `gum_exec_block_clear`, `gum_exec_block_commit`. How instrumented code is structured and managed in memory.
* **Code Generation and Relocation:**  The `gum_x86_writer_*` and `gum_x86_relocator_*` functions.
* **Event Handling:** The `gum_exec_ctx_emit_*_event` functions and the `GumEventSink`.
* **Iteration and Transformation:** `gum_stalker_iterator_next`, `gum_stalker_iterator_keep`, `gum_stalker_iterator_put_callout`. This is the core of the dynamic instrumentation process.

**4. Deep Dive into Key Functions (Simulating Execution):**

For some of the crucial functions, I mentally traced the execution flow. For example, with `gum_exec_ctx_switch_block`:

* **Input:** A target address (`start_address`).
* **Checks:** Is it a special "unfollow" address? Is the context already unfollowing? Is it within the existing instrumented code?
* **Core Logic:** If not already instrumented, `gum_exec_ctx_obtain_block_for` is called.
* **Callbacks:** `gum_exec_ctx_query_block_switch_callback` allows user intervention.
* **Output:** The address where execution should resume (`ctx->resume_at`).

Similarly, for `gum_exec_ctx_obtain_block_for`:

* **Input:** A target address.
* **Lookup:** Check if a block already exists for this address in `ctx->mappings`.
* **Recompilation:** If the existing block is outdated, `gum_exec_ctx_recompile_block` is called.
* **Building a New Block:** If no block exists, `gum_exec_ctx_build_block` is called.
* **Prefetching:**  The loop to fetch adjacent blocks is important for understanding performance optimizations.

**5. Connecting Concepts to Reverse Engineering, Low-Level Details, and Potential Errors:**

With a solid understanding of the code's functionality, I started connecting it to the prompt's specific questions:

* **Reverse Engineering:**  The ability to intercept and modify code flow is a fundamental aspect of dynamic analysis and reverse engineering. Examples include tracing function calls, modifying return values, and injecting custom code.
* **Binary/Kernel/Framework:** The code directly manipulates memory, deals with thread IDs, and has platform-specific logic (e.g., Linux/Android differences). The use of `mprotect` and cache clearing are clear indicators of low-level interaction.
* **Logical Inference:**  The conditional logic in `gum_exec_ctx_switch_block` and `gum_exec_ctx_obtain_block_for` provides opportunities for inferring input/output relationships.
* **User Errors:** Misusing the API, like trying to call `unfollow` multiple times or having transformers with inconsistent behavior when backpatching is enabled, are potential pitfalls.
* **Debugging:** The step-by-step user actions to reach this code involve setting up Frida, attaching to a process, and enabling the stalker.

**6. Structuring the Response:**

Finally, I organized the information into the requested categories:

* **Functionality Summary:** A concise overview of the code's main purpose.
* **Relationship to Reverse Engineering:** Concrete examples of how the code enables reverse engineering tasks.
* **Binary/Kernel/Framework Knowledge:** Specific instances where the code interacts with these low-level aspects.
* **Logical Inference:** Providing example inputs and outputs to illustrate the code's behavior.
* **Common User Errors:** Highlighting potential mistakes users might make.
* **User Operations as Debugging Clues:**  Describing the steps to reach this code, helpful for debugging.
* **Overall Function Summary:** A final concise summary, as requested.

**Iterative Refinement:** Throughout this process, there's often a degree of iteration. I might revisit earlier steps as I gain more understanding, refine my mental model, and correct initial assumptions. For instance, realizing the importance of the prefetching loop might lead me to adjust my description of `gum_exec_ctx_obtain_block_for`.
This section of `gumstalker-x86.c` focuses on the management of `GumExecCtx` objects, which represent the execution context of a stalked thread. It handles the creation, destruction, finding, and basic lifecycle management of these contexts. It also includes functions related to memory management within these contexts and the core logic for switching between different code blocks during stalking.

Here's a breakdown of the functionalities:

**Core Functionalities Related to `GumExecCtx` Management:**

1. **Creating `GumExecCtx`:**
   - `gum_stalker_create_exec_ctx`: Allocates and initializes a new `GumExecCtx` for a given thread.
   - Sets up core components like code writers (`GumX86Writer`), relocator (`GumX86Relocator`), transformer (`GumStalkerTransformer`), and event sink (`GumEventSink`).
   - Allocates memory for code slabs, slow slabs, data slabs, and thunks.
   - Initializes spinlocks for thread safety.
   - Adds the newly created context to the stalker's list of active contexts.

2. **Destroying `GumExecCtx`:**
   - `gum_stalker_destroy_exec_ctx`: Removes a `GumExecCtx` from the stalker's list and frees its associated resources.
   - Stops the event sink if it was started.
   - Disposes of the execution context to thaw any frozen memory regions.

3. **Accessing the Current `GumExecCtx`:**
   - `gum_stalker_get_exec_ctx`: Retrieves the `GumExecCtx` associated with the currently executing thread (using thread-local storage).

4. **Finding `GumExecCtx` by Thread ID:**
   - `gum_stalker_find_exec_ctx_by_thread_id`: Searches the stalker's list of active contexts to find the one belonging to a specific thread.

5. **Snapshotting Memory Needs:**
   - `gum_stalker_snapshot_space_needed_for`: Determines the amount of space needed to store a snapshot of the original code being instrumented (used for backpatching if the trust threshold is set).

6. **Indirect Call Entry Size:**
   - `gum_stalker_get_ic_entry_size`: Calculates the size needed for indirect call entries.

7. **Memory Thawing and Freezing:**
   - `gum_stalker_thaw`: Makes code regions writable (RWX or RW depending on OS support) before modification.
   - `gum_stalker_freeze`: Marks code regions as read-only and executable (or just read-only) after modification, and clears the instruction cache. This ensures the modified code is executed.

8. **Internal `GumExecCtx` Creation:**
   - `gum_exec_ctx_new`: The internal function that performs the detailed allocation and initialization of a `GumExecCtx`. It sets up memory slabs, writers, relocators, transformers, and sinks.

9. **Internal `GumExecCtx` Freeing and Disposing:**
   - `gum_exec_ctx_free`:  Frees all the memory allocated for a `GumExecCtx`, including slabs and other resources.
   - `gum_exec_ctx_dispose`:  Prepares a `GumExecCtx` for disposal by thawing memory regions and clearing execution blocks.

10. **Adding Memory Slabs:**
    - `gum_exec_ctx_add_code_slab`, `gum_exec_ctx_add_slow_slab`, `gum_exec_ctx_add_data_slab`:  Functions to add new memory slabs of different types to the execution context as needed.

11. **Computing Address Specifications:**
    - `gum_exec_ctx_compute_code_address_spec`, `gum_exec_ctx_compute_data_address_spec`: Calculate address ranges and constraints for code and data within the context, ensuring they can be accessed with 32-bit offsets.

12. **Handling Unfollowing (Stopping Stalking):**
    - `gum_exec_ctx_maybe_unfollow`: Checks if the context is pending unfollowing and if it's safe to stop.
    - `gum_exec_ctx_unfollow`:  Sets the state of the context to indicate it should stop stalking and records the resume address.
    - `gum_exec_ctx_has_executed`: Checks if the context has executed any code under the stalker.

13. **Checking if an Address Belongs to the Context:**
    - `gum_exec_ctx_contains`: Determines if a given memory address falls within the code or slow code slabs managed by the execution context.

14. **Backpatching Check:**
    - `gum_exec_ctx_may_now_backpatch`: Determines if a code block is eligible for backpatching based on its recycle count and the stalker's trust threshold.

15. **Entry Gates (Block Switching):**
    - Defines macros (`GUM_ENTRYGATE`, `GUM_DEFINE_ENTRYGATE`) and implements a series of functions like `gum_exec_ctx_replace_current_block_from_call_imm`, `gum_exec_ctx_replace_current_block_from_jmp_imm`, etc. These functions are called when control flow transitions from one code block to another (e.g., due to a call, jump, or return). They update the current block, potentially call observers, and determine the next execution address.

16. **Block Switching Logic:**
    - `gum_exec_ctx_switch_block`:  The core function that handles the transition between code blocks. It determines if the target address is already within the stalked code, obtains a new block if necessary, and invokes the block switch callback for observers.

17. **Block Switch Callback:**
    - `gum_exec_ctx_query_block_switch_callback`: Calls the stalker observer's `switch_callback` to allow users to intercept and potentially modify control flow transitions.

18. **Recompiling and Switching Blocks:**
    - `gum_exec_ctx_recompile_and_switch_block`:  Handles cases where a jump target points to the middle of an existing block that needs to be recompiled.

19. **Obtaining Code Blocks:**
    - `gum_exec_ctx_obtain_block_for`:  Retrieves or creates a `GumExecBlock` for a given real address. It checks if a block already exists, and if so, whether it needs recompilation. It also implements a pre-fetching mechanism for adjacent code blocks to optimize performance.

20. **Building New Code Blocks:**
    - `gum_exec_ctx_build_block`:  Creates a new `GumExecBlock` and compiles the code for it.

21. **Recompiling Existing Code Blocks:**
    - `gum_exec_ctx_recompile_block`:  Recompiles an existing `GumExecBlock`, potentially moving the code to a scratch slab if the new code doesn't fit in the original space.

22. **Compiling Code Blocks:**
    - `gum_exec_ctx_compile_block`: The central function responsible for translating the original code at a given address into instrumented code within a `GumExecBlock`. It uses the `GumX86Writer`, `GumX86Relocator`, and the `GumStalkerTransformer` to perform this process.

23. **Emitting Compile Events:**
    - `gum_exec_ctx_maybe_emit_compile_event`:  If the event sink is configured to receive compile events, this function sends an event indicating that a block has been compiled.

**Relationship to Reverse Engineering:**

This code is fundamental to Frida's dynamic instrumentation capabilities, which are heavily used in reverse engineering:

* **Dynamic Code Analysis:**  The entire purpose of the `GumStalker` and `GumExecCtx` is to intercept and analyze code execution in real-time. This allows reverse engineers to understand the behavior of a program as it runs.
* **Tracing Execution Flow:** The block switching logic (`gum_exec_ctx_switch_block`, entry gates) enables the tracing of control flow, showing which parts of the code are being executed and in what order.
* **Instrumentation:** The ability to inject code through transformers and callouts (`gum_stalker_iterator_put_callout`) allows reverse engineers to modify the program's behavior, log information, and perform other analyses.
* **Hooking and Interception:** By intercepting function calls and returns, reverse engineers can observe function arguments, return values, and internal states. The entry gates for `call`, `ret`, and `jmp` are crucial for this.
* **Code Modification:** The thawing and freezing of memory (`gum_stalker_thaw`, `gum_stalker_freeze`) allow Frida to modify the executable code on the fly, enabling techniques like patching vulnerabilities or changing program logic.
* **Understanding Code Structure:** The concept of `GumExecBlock` and its management helps in understanding how Frida organizes and instruments code at a block level.

**Examples:**

* **Tracing Function Calls:** When a `CALL` instruction is encountered, the `gum_exec_ctx_replace_current_block_from_call_imm` (or similar) function is called. This function could be extended (or an observer used) to log the target address of the call, effectively tracing function calls.
* **Modifying Return Values:**  Using a transformer, a reverse engineer could intercept a `RET` instruction and modify the value being popped from the stack (the return address), thus changing the program's control flow.
* **Injecting Custom Code:**  `gum_stalker_iterator_put_callout` allows injecting arbitrary C functions to be executed during the stalked execution, enabling custom logging, data gathering, or behavior modification.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This code interacts with low-level aspects of the operating system and architecture:

* **x86 Architecture:** The code is specific to the x86 architecture, using x86 instruction mnemonics and register names (e.g., `GUM_X86_XSP`, `X86_INS_CALL`).
* **Memory Management:**
    * `gum_memory_allocate`, `gum_memory_free`: These likely wrap OS-level memory allocation functions (like `malloc` and `free` on Linux/Android).
    * `gum_mprotect`: This function directly interacts with the operating system's memory protection mechanisms (e.g., `mprotect` on Linux) to change the permissions of memory pages (read, write, execute). This is crucial for making code regions writable for modification and then executable.
    * Cache clearing (`gum_clear_cache`): This is necessary to ensure that the CPU fetches the newly modified code from memory rather than using stale instructions from its cache.
* **Thread Management:**
    * `GumThreadId`: Represents a thread identifier, likely mapping to OS-level thread IDs.
    * Thread-local storage (`g_private_get`, `g_private_set`) is used to associate the current `GumExecCtx` with the executing thread.
* **Linux/Android Specifics:**
    * The code includes conditional compilation (`#ifdef HAVE_LINUX`, `#ifndef HAVE_ANDROID`) indicating platform-specific handling, particularly related to handling calls into the PLT/GOT sections of shared libraries.
    * The comment about `.plt.got` and `.plt.sec` sections refers to the Procedure Linkage Table and Global Offset Table, which are fundamental concepts in dynamic linking on Linux and Android.
* **Kernel Interaction (Potentially):** While this specific file might not directly make syscalls, the underlying `gum_memory_*` and `gum_mprotect` functions will eventually interact with the kernel to manage memory and permissions.
* **Framework Knowledge (Indirectly):** By allowing the instrumentation of code within applications, Frida can interact with and analyze application frameworks (like the Android runtime environment).

**Logical Inference (Hypothetical Input & Output):**

**Scenario:** A `CALL` instruction at address `0x1000` is executed, targeting address `0x2000`. The `GumStalker` is active, and a `GumExecCtx` exists for the current thread.

**Input:**
* `block->real_start`: The start address of the current code block (e.g., `0x1000`).
* `start_address`: The target address of the call (`0x2000`).
* `from_insn`: The address of the `CALL` instruction (`0x1000`).

**Output:**

Assuming `0x2000` is not already within an existing `GumExecBlock` of the current context:

1. `gum_exec_ctx_switch_block` will be called.
2. It will determine that a new block needs to be created for `0x2000`.
3. `gum_exec_ctx_obtain_block_for` will be called.
4. `gum_exec_ctx_build_block` will be called to create a new `GumExecBlock` for the code starting at `0x2000`.
5. This new block will be compiled using `gum_exec_ctx_compile_block`.
6. `ctx->resume_at` will be set to the `code_start` of the newly created `GumExecBlock`.
7. The function will return the `code_start` address of the new block, which is where the instrumented code for the target of the call will begin execution.

If an observer is registered, the `gum_exec_ctx_query_block_switch_callback` will be invoked, allowing the observer to potentially modify the `resume_at` address, effectively redirecting the call.

**Common User or Programming Errors:**

1. **Incorrect Transformer Logic:** A poorly written `GumStalkerTransformer` could introduce bugs in the instrumented code, leading to crashes or unexpected behavior. For example, incorrect relocation of instructions or forgetting to handle certain instruction types.
2. **Memory Corruption:** If custom callouts write to memory incorrectly, they could corrupt the stalker's internal data structures or the target process's memory.
3. **Reentrancy Issues:** If a callout performs operations that trigger further stalking within the same thread, it could lead to reentrancy problems and stack overflows if not handled carefully.
4. **Deadlocks:** Incorrect usage of the spinlocks (`gum_spinlock_acquire`, `gum_spinlock_release`) could lead to deadlocks if multiple threads are involved in stalking.
5. **Forgetting to `unfollow`:** If a user starts stalking a thread but never calls the `unfollow` function, the stalker will continue to intercept and instrument code, potentially impacting performance.
6. **Modifying Read-Only Memory:**  While Frida handles thawing and freezing, a user interacting directly with memory without understanding these mechanisms could attempt to write to read-only code, causing crashes.

**User Operations to Reach This Code (Debugging Clues):**

1. **Initialize Frida:** The user would first need to initialize the Frida runtime environment, typically by attaching to a running process or spawning a new process with Frida's agent.
2. **Enable Stalker:** The user would then need to enable the `Stalker` for specific threads. This is usually done through Frida's API, for example, using `Frida.Stalker.follow(threadId)`.
3. **Code Execution:** As the followed thread executes code, the `Stalker` intercepts transitions between code blocks.
4. **Function Calls/Jumps:** When the target thread executes a `CALL`, `JMP`, or other control flow changing instruction, the relevant entry gate function (e.g., `gum_exec_ctx_replace_current_block_from_call_imm`) in this file will be invoked.
5. **Block Creation/Retrieval:** If the target of the call/jump is in a new code region that hasn't been instrumented yet, `gum_exec_ctx_obtain_block_for` and `gum_exec_ctx_build_block` will be called to create and compile a new `GumExecBlock`.
6. **Callbacks:** If the user has registered a transformer or observer, the corresponding callback functions will be invoked at various points within this code, such as during block compilation or when switching between blocks.

Therefore, if a debugger breaks within this file, it indicates that a thread being stalked by Frida has encountered a control flow transition to a new or recompiled code block. The specific function where the breakpoint hits provides more context about the type of transition (call, jump, etc.) and the state of the stalking process.

**Overall Function Summary of This Section:**

This section of `gumstalker-x86.c` is responsible for managing the execution contexts of stalked threads. It handles the creation, destruction, and lifecycle of `GumExecCtx` objects. A key function is managing the transition between different code blocks during the stalking process, ensuring that as the target thread executes, Frida can intercept and instrument the code in a controlled and efficient manner. It also handles low-level memory management for the instrumented code and provides mechanisms for user-defined transformations and observations of the execution flow.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共7部分，请归纳一下它的功能

"""
(cpu_context) = ctx->infect_body;
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
  return self->ic_entries * (2 * sizeof (gpointer));
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
  ctx->mode = GUM_EXEC_CTX_NORMAL;

  ctx->stalker = g_object_ref (stalker);
  ctx->thread_id = thread_id;

  gum_x86_writer_init (&ctx->code_writer, NULL);
  gum_x86_writer_init (&ctx->slow_writer, NULL);
  gum_x86_relocator_init (&ctx->relocator, NULL, &ctx->code_writer);

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
  gum_code_slab_init (code_slab, stalker->code_slab_size_initial,
      stalker->page_size);
  gum_exec_ctx_add_code_slab (ctx, code_slab);

  slow_slab = (GumSlowSlab *) (base + stalker->slow_slab_offset);
  gum_slow_slab_init (slow_slab, stalker->slow_slab_size_initial,
      stalker->page_size);
  gum_exec_ctx_add_slow_slab (ctx, slow_slab);

  data_slab = (GumDataSlab *) (base + stalker->data_slab_offset);
  gum_data_slab_init (data_slab, stalker->data_slab_size_initial);
  gum_exec_ctx_add_data_slab (ctx, data_slab);

  ctx->scratch_slab = (GumCodeSlab *) (base + stalker->scratch_slab_offset);
  gum_scratch_slab_init (ctx->scratch_slab, stalker->scratch_slab_size);

  ctx->mappings = gum_metal_hash_table_new (NULL, NULL);

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

  ctx->depth = 0;

#ifdef HAVE_LINUX
  /*
   * We need to build an array of ranges in which the .plt.got and .plt.sec
   * sections of the loaded modules reside to allow us to treat tail calls into
   * them as excluded calls (even though they use a JMP instruction). However,
   * calling into the dynamic loader or even just allocating data on the heap is
   * dangerous when actually stalking a target since we could cause the target
   * to re-enter a section of code which is not designed to be. We will
   * therefore build up our picture of the memory map when Stalker is first
   * instantiated to avoid this potential problem. Should the memory map change
   * afterwards (e.g. another library is loaded) then we will not notice and
   * tail calls into the .plt.got and .plt.sec will not be optimized. However,
   * the application should continue to function as expected.
   */
  gum_exec_ctx_get_plt_got_ranges ();

# ifndef HAVE_ANDROID
  ctx->excluded_calls = gum_metal_hash_table_new (NULL, NULL);
# endif
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

  gum_x86_relocator_clear (&ctx->relocator);
  gum_x86_writer_clear (&ctx->slow_writer);
  gum_x86_writer_clear (&ctx->code_writer);

  g_object_unref (stalker);

  gum_memory_free (ctx, stalker->ctx_size);
}

static void
gum_exec_ctx_dispose (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumSlab * slab;
  GumExecBlock * block;

  for (slab = &ctx->code_slab->slab; slab != NULL; slab = slab->next)
  {
    gum_stalker_thaw (stalker, gum_slab_start (slab), slab->offset);
  }

  for (slab = &ctx->slow_slab->slab; slab != NULL; slab = slab->next)
  {
    gum_stalker_thaw (stalker, gum_slab_start (slab), slab->offset);
  }

  for (block = ctx->block_list; block != NULL; block = block->next)
  {
    gum_exec_block_clear (block);
  }

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  gum_metal_hash_table_unref (ctx->excluded_calls);
#endif
}

static GumCodeSlab *
gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
                            GumCodeSlab * code_slab)
{
  code_slab->slab.next = &ctx->code_slab->slab;
  ctx->code_slab = code_slab;
  return code_slab;
}

static GumSlowSlab *
gum_exec_ctx_add_slow_slab (GumExecCtx * ctx,
                            GumSlowSlab * slow_slab)
{
  slow_slab->slab.next = &ctx->slow_slab->slab;
  ctx->slow_slab = slow_slab;
  return slow_slab;
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
  GumSlab * code_slab = &ctx->code_slab->slab;
  GumSlab * slow_slab = &ctx->slow_slab->slab;

  do
  {
    if ((const guint8 *) address >= code_slab->data &&
        (const guint8 *) address < (guint8 *) gum_slab_cursor (code_slab))
    {
      return TRUE;
    }

    code_slab = code_slab->next;
  }
  while (code_slab != NULL);

  do
  {
    if ((const guint8 *) address >= slow_slab->data &&
        (const guint8 *) address < (guint8 *) gum_slab_cursor (slow_slab))
    {
      return TRUE;
    }

    slow_slab = slow_slab->next;
  }
  while (slow_slab != NULL);

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

#define GUM_ENTRYGATE(name) \
    gum_exec_ctx_replace_current_block_from_##name
#define GUM_DEFINE_ENTRYGATE(name) \
    static gpointer \
    GUM_ENTRYGATE (name) ( \
        GumExecBlock * block, \
        gpointer start_address, \
        gpointer from_insn) \
    { \
      GumExecCtx * ctx = block->ctx; \
      \
      if (ctx->observer != NULL) \
        gum_stalker_observer_increment_##name (ctx->observer); \
      \
      return gum_exec_ctx_switch_block (ctx, block, start_address, from_insn); \
    }

GUM_DEFINE_ENTRYGATE (call_imm)
GUM_DEFINE_ENTRYGATE (call_reg)
GUM_DEFINE_ENTRYGATE (call_mem)
GUM_DEFINE_ENTRYGATE (excluded_call_imm)
GUM_DEFINE_ENTRYGATE (ret_slow_path)

GUM_DEFINE_ENTRYGATE (jmp_imm)
GUM_DEFINE_ENTRYGATE (jmp_mem)
GUM_DEFINE_ENTRYGATE (jmp_reg)

GUM_DEFINE_ENTRYGATE (jmp_cond_imm)
GUM_DEFINE_ENTRYGATE (jmp_cond_mem)
GUM_DEFINE_ENTRYGATE (jmp_cond_reg)
GUM_DEFINE_ENTRYGATE (jmp_cond_jcxz)

GUM_DEFINE_ENTRYGATE (jmp_continuation)

#if GLIB_SIZEOF_VOID_P == 4 && !defined (HAVE_QNX)
GUM_DEFINE_ENTRYGATE (sysenter_slow_path)
#endif

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
  else if (start_address == _gum_thread_exit_impl)
  {
    gum_exec_ctx_unfollow (ctx, start_address);
  }
  else if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
  {
  }
  else if (gum_exec_ctx_contains (ctx, start_address))
  {
    ctx->resume_at = start_address;
    ctx->current_block = NULL;
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

  /*
   * When we fetch a block to be executed, before we make use of the
   * code_address, we first call-back to the observer to allow the user to make
   * any modifications to it. We also pass the user the instruction which was
   * executed immediately before the transition as well as the real address of
   * the target for the branch which resulted in this transition.
   *
   * The user can observe or modify the code being written to a given
   * instrumented address by making use of a transformer. This callback gives
   * the user the ability to modify control-flow rather than just the
   * instructions being executed.
   *
   * It should be noted that as well as making an instantaneous change to the
   * control flow, in the event that backpatching is enabled, this will result
   * in any backpatches being modified accordingly. It is therefore expected
   * that if the user is making use of backpatching that any callback should
   * provide a consistent result when called multiple times with the same
   * inputs.
   */
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
                                         gint32 * distance_to_data)
{
  GumExecBlock * block;
  gpointer start_address;

  block = (GumExecBlock *) ((guint8 *) distance_to_data + *distance_to_data);
  start_address = block->real_start;

  if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
    return;

  gum_exec_ctx_recompile_block (ctx, block);

  ctx->current_block = block;
  ctx->resume_at = block->code_start;

  if (start_address == ctx->activation_target)
  {
    ctx->activation_target = NULL;
    ctx->current_block->flags |= GUM_EXEC_BLOCK_ACTIVATION_TARGET;
  }

  gum_exec_ctx_maybe_unfollow (ctx, start_address);
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
    GumExecBlock * cur;
    guint i;

    block = gum_exec_ctx_build_block (ctx, real_address);
    cur = block;

    /*
     * Fetch the next `n` blocks which are adjacent in the target application so
     * that they are more likely to also appear adjacently in the code_slab.
     * This allows us to transfer control-flow between adjacent blocks using a
     * NOP slide rather than a branch instruction giving an increase in
     * performance.
     */
    for (i = 0; i != ctx->stalker->adj_blocks; i++)
    {
      /*
       * If we reach the end of input (e.g. a RET instruction or a JMP) we
       * cannot be sure that what follows is actually code (it could just be
       * data, or we might reach the end of mapped memory), we must therefore
       * stop fetching blocks.
       */
      if (gum_x86_relocator_eoi (&ctx->relocator))
        break;

      real_address = cur->real_start + cur->real_size;

      /*
       * Don't prefetch adjacent blocks which are in the excluded range, as
       * their treatment depends on whether we have reached the
       * activation_target as to whether they are actually treated as excluded.
       * We don't know this unless we wait to compile the block until it is
       * actually run. This means we can't speculatively compile it early.
       */
      if (gum_stalker_is_excluding (ctx->stalker, real_address))
        break;

      /* Don't fetch any duplicates */
      /* TODO: Consider whether fetching duplicates will improve performance */
      if (gum_metal_hash_table_lookup (ctx->mappings, real_address) != NULL)
        break;

      cur = gum_exec_ctx_build_block (ctx, real_address);
    }

    gum_spinlock_release (&ctx->code_lock);
  }

  *code_address = block->code_start;

  return block;
}

static GumExecBlock *
gum_exec_ctx_build_block (GumExecCtx * ctx,
                          gpointer real_address)
{
  GumExecBlock * block = gum_exec_block_new (ctx);

  block->real_start = real_address;
  gum_exec_ctx_compile_block (ctx, block, real_address, block->code_start,
      GUM_ADDRESS (block->code_start), &block->real_size, &block->code_size,
      &block->slow_size);
  gum_exec_block_commit (block);

  gum_metal_hash_table_insert (ctx->mappings, real_address, block);

  gum_exec_ctx_maybe_emit_compile_event (ctx, block);

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
  guint input_size, output_size, slow_size;
  gsize new_snapshot_size, new_block_size;

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (stalker, internal_code, block->capacity);

  if (block->storage_block != NULL)
    gum_exec_block_clear (block->storage_block);
  gum_exec_block_clear (block);

  slab = block->code_slab;
  block->code_slab = ctx->scratch_slab;
  block->slow_slab = ctx->slow_slab;
  scratch_base = ctx->scratch_slab->slab.data;
  ctx->scratch_slab->invalidator = slab->invalidator;

  gum_exec_ctx_compile_block (ctx, block, block->real_start, scratch_base,
      GUM_ADDRESS (internal_code), &input_size, &output_size, &slow_size);

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
    GumX86Writer * cw = &ctx->code_writer;

    storage_block = gum_exec_block_new (ctx);
    storage_block->real_start = block->real_start;
    gum_exec_ctx_compile_block (ctx, block, block->real_start,
        storage_block->code_start, GUM_ADDRESS (storage_block->code_start),
        &storage_block->real_size, &storage_block->code_size,
        &storage_block->slow_size);
    gum_exec_block_commit (storage_block);
    block->storage_block = storage_block;

    gum_stalker_thaw (stalker, internal_code, block->capacity);
    gum_x86_writer_reset (cw, internal_code);

    gum_x86_writer_put_jmp_address (cw,
        GUM_ADDRESS (storage_block->code_start));

    gum_x86_writer_flush (cw);
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
                            guint * output_size,
                            guint * slow_size)
{
  GumX86Writer * cw = &ctx->code_writer;
  GumX86Writer * cws = &ctx->slow_writer;
  GumX86Relocator * rl = &ctx->relocator;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  GumStalkerOutput output;
  gboolean all_labels_resolved;
  gboolean all_slow_labels_resolved;

  gum_x86_writer_reset (cw, output_code);
  cw->pc = output_pc;

  gum_x86_writer_reset (cws, block->slow_start);
  cws->pc = GUM_ADDRESS (block->slow_start);

  gum_x86_relocator_reset (rl, input_code, cw);

  gum_ensure_code_readable (input_code, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.relocator = rl;
  gc.code_writer = cw;
  gc.slow_writer = cws;
  gc.continuation_real_address = NULL;
  gc.opened_prolog = GUM_PROLOG_NONE;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instruction.start = NULL;
  iterator.instruction.end = NULL;
  iterator.requirements = GUM_REQUIRE_NOTHING;

  output.writer.x86 = cw;
  output.encoding = GUM_INSTRUCTION_DEFAULT;

  gum_exec_block_maybe_write_call_probe_code (block, &gc);

  ctx->pending_calls++;
  ctx->transform_block_impl (ctx->transformer, &iterator, &output);
  ctx->pending_calls--;

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.is_indirect = FALSE;
    continue_target.absolute_address = gc.continuation_real_address;

    gum_exec_block_write_jmp_transfer_code (block, &continue_target,
        GUM_ENTRYGATE (jmp_continuation), &gc, X86_INS_JMP, GUM_ADDRESS (0));
  }

  gum_x86_writer_put_breakpoint (cw); /* Should never get here */

  all_labels_resolved = gum_x86_writer_flush (cw);
  if (!all_labels_resolved)
    gum_panic ("Failed to resolve labels");

  all_slow_labels_resolved = gum_x86_writer_flush (cws);
  if (!all_slow_labels_resolved)
    gum_panic ("Failed to resolve slow labels");

  *input_size = rl->input_cur - rl->input_start;
  *output_size = gum_x86_writer_offset (cw);
  *slow_size = gum_x86_writer_offset (cws);
}

static void
gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
                                       GumExecBlock * block)
{
  if ((ctx->sink_mask & GUM_COMPILE) != 0)
  {
    GumEvent ev;

    ev.type = GUM_COMPILE;
    ev.compile.start = block->real_start;
    ev.compile.end = block->real_start + block->real_size;

    ctx->sink_process_impl (ctx->sink, &ev, NULL);
  }
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumX86Relocator * rl = gc->relocator;
  GumInstruction * instruction;
  gboolean is_first_instruction;
  guint n_read;

  instruction = self->generator_context->instruction;
  is_first_instruction = instruction == NULL;

  if (instruction != NULL)
  {
    gboolean skip_implicitly_requested;

    skip_implicitly_requested = rl->outpos != rl->inpos;
    if (skip_implicitly_requested)
    {
      gum_x86_relocator_skip_one_no_label (rl);
    }

    if (gum_stalker_iterator_is_out_of_space (self))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

    if (!skip_implicitly_requested && gum_x86_relocator_eob (rl))
      return FALSE;
  }

  instruction = &self->instruction;

  n_read = gum_x86_relocator_read_one (rl, &instruction->ci);
  if (n_read == 0)
    return FALSE;

  instruction->start = GSIZE_TO_POINTER (instruction->ci->address);
  instruction->end = instruction->start + instruction->ci->size;

  self->generator_context->instruction = instruction;

  if (is_first_instruction && (self->exec_context->sink_mask & GUM_BLOCK) != 0)
  {
    gum_exec_block_write_block_event_code (self->exec_block, gc,
        GUM_CODE_INTERRUPTIBLE);
  }

  if (insn != NULL)
    *insn = instruction->ci;

  return TRUE;
}

static gboolean
gum_stalker_iterator_is_out_of_space (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumSlab * slab = &block->code_slab->slab;
  gsize capacity, snapshot_size;

  capacity = (guint8 *) gum_slab_end (slab) -
      (guint8 *) gum_x86_writer_cur (self->generator_context->code_writer);

  snapshot_size = gum_stalker_snapshot_space_needed_for (
      self->exec_context->stalker,
      self->generator_context->instruction->end - block->real_start);

  return capacity < GUM_EXEC_BLOCK_MIN_CAPACITY + snapshot_size +
      gum_stalker_get_ic_entry_size (self->exec_context->stalker);
}

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumX86Relocator * rl = gc->relocator;
  const cs_insn * insn = gc->instruction->ci;
  GumVirtualizationRequirements requirements;

  if ((self->exec_context->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_exec_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);

  switch (insn->id)
  {
    case X86_INS_CALL:
    case X86_INS_JMP:
      requirements = gum_exec_block_virtualize_branch_insn (block, gc);
      break;
    case X86_INS_RET:
      requirements = gum_exec_block_virtualize_ret_insn (block, gc);
      break;
    case X86_INS_SYSENTER:
      requirements = gum_exec_block_virtualize_sysenter_insn (block, gc);
      break;
    case X86_INS_SYSCALL:
      requirements = gum_exec_block_virtualize_syscall_insn (block, gc);
      break;
    case X86_INS_INT:
      requirements = gum_exec_block_virtualize_int_insn (block, gc);
      break;
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
      requirements = gum_exec_block_virtualize_branch_insn (block, gc);
      break;
    default:
      if (gum_x86_reader_insn_is_jcc (insn))
        requirements = gum_exec_block_virtualize_branch_insn (block, gc);
      else
        requirements = GUM_REQUIRE_RELOCATION;
      break;
  }

  gum_exec_block_close_prolog (block, gc, gc->code_writer);

  if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
  {
    gum_x86_relocator_write_one_no_label (rl);
  }
  else if ((requirements & GUM_REQUIRE_SINGLE_STEP) != 0)
  {
    gum_x86_relocator_skip_one_no_label (rl);
    gum_exec_block_write_single_step_transfer_code (block, gc);
  }

  self->requirements = requirements;
}

GumMemoryAccess
gum_stalker_iterator_get_memory_access (GumStalkerIterator * self)
{
  return GUM_MEMORY_ACCESS_OPEN;
}

static void
gum_exec_ctx_emit_call_event (GumExecCtx * ctx,
                              gpointer location,
                              gpointer target,
                              GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumCallEvent * call = &ev.call;

  ev.type = GUM_CALL;

  call->location = location;
  call->target = target;
  call->depth = ctx->depth;

  GUM_CPU_CONTEXT_XIP (cpu_context) = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_ret_event (GumExecCtx * ctx,
                             gpointer location,
                             GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumRetEvent * ret = &ev.ret;

  ev.type = GUM_RET;

  ret->location = location;
  ret->target = *((gpointer *) ctx->app_stack);
  ret->depth = ctx->depth;

  GUM_CPU_CONTEXT_XIP (cpu_context) = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_exec_event (GumExecCtx * ctx,
                              gpointer location,
                              GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumExecEvent * exec = &ev.exec;

  ev.type = GUM_EXEC;

  exec->location = location;

  GUM_CPU_CONTEXT_XIP (cpu_context) = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_block_event (GumExecCtx * ctx,
                               const GumExecBlock * block,
                               GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumBlockEvent * bev = &ev.block;

  ev.type = GUM_BLOCK;

  bev->start = block->real_start;
  bev->end = block->real_start + block->real_size;

  GUM_CPU_CONTEXT_XIP (cpu_context) = GPOINTER_TO_SIZE (block->real_start);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

void
gum_stalker_iterator_put_callout (GumStalkerIterator * self,
                                  GumStalkerCallout callout,
                                  gpointer data,
                                  GDestroyNotify data_destroy)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumX86Writer * cw = gc->code_writer;
  GumCalloutEntry entry;
  GumAddress entry_address;

  entry.callout = callout;
  entry.data = data;
  entry.data_destroy = data_destroy;
  entry.pc = gc->instruction->start;
  entry.exec_context = self->exec_context;
  entry.next = gum_exec_block_get_last_callout_entry (block);
  gum_exec_block_write_inline_data (cw, &entry, sizeof (entry), &entry_address);

  gum_exec_block_set_last_callout_entry (block,
      GSIZE_TO_POINTER (entry_address));

  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);
  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_CAPI, GUM_ADDRESS (gum_stalker_invoke_callout), 2,
      GUM_ARG_ADDRESS, entry_address,
      GUM_ARG_REGISTER, GUM_X86_XBX);
  gum_exec_block_close_prolog (block, gc, gc->code_writer);
}

static void
gum_stalker_invoke_callout (GumCalloutEntry * entry,
                            GumCpuContext * cpu_context)
{
  GumExecCtx * ec = entry->exec_context;

  GUM_CPU_CONTEXT_XIP (cpu_context) = GPOINTER_TO_SIZE (entry->pc);

  ec->pending_calls++;
  entry->callout (cpu_context, entry->data);
  ec->pending_calls--;
}

void
gum_stalker_iterator_put_chaining_return (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;

  if ((block->ctx->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);

  gum_exec_block_write_adjust_depth (block, gc->code_writer, -1);

  gum_exec_block_write_chaining_return_code (block, gc, 0);
}

csh
gum_stalker_iterator_get_capstone (GumStalkerIterator * self)
{
  return self->exec_context->relocator.capstone;
}

static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumX86Writer * cw)
{
  switch (type)
  {
    case GUM_PROLOG_MINIMAL:
    case GUM_PROLOG_FULL:
    {
      gpointer helper;

      helper = (type == GUM_PROLOG_MINIMAL)
          ? ctx->last_prolog_minimal
          : ctx->last_prolog_full;

      gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
          GUM_X86_XSP, -GUM_RED_ZONE_SIZE);
      gum_x86_writer_put_call_address (cw, GUM_ADDRESS (helper));

      break;
    }
    case GUM_PROLOG_IC:
    {
      gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
          GUM_X86_XSP, -GUM_RED_ZONE_SIZE);

      gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);
      gum_x86_writer_put_
"""


```