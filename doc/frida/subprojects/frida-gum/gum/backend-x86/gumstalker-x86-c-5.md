Response:
The user wants a breakdown of the C source code file `gumstalker-x86.c` from the Frida dynamic instrumentation tool. Specifically, they are asking for:

1. **Functionality:** A summary of what the code does.
2. **Relationship to Reverse Engineering:**  Examples of how this code relates to reverse engineering techniques.
3. **Low-Level Details:** Explanation of its interaction with binary, Linux/Android kernel/framework knowledge.
4. **Logic and Reasoning:** Identification of logical steps, along with example inputs and outputs.
5. **Common Usage Errors:** Examples of how a user or programmer might misuse this code or its related APIs.
6. **Debugging Context:** Explanation of how a user might end up at this specific code location during debugging.
7. **Summary of Functionality (Part 6 of 7):** A concluding summary of the code's purpose within the larger Frida system.

**Mental Model:**

This file seems to be a core component of Frida's Stalker on x86 architectures. It's likely responsible for generating the dynamic instrumentation code that gets injected into the target process. It manages code blocks, handles different instruction types (calls, jumps, returns), and interacts with inline caches for performance. The "part 6 of 7" suggests this file focuses on a specific aspect of this process, possibly dealing with the generation of code for control flow transfers and event handling.

**Plan:**

1. **High-Level Functionality:** Start by summarizing the main purpose of the code based on the function names and structure (e.g., `gum_exec_block_write_*_code`). It's about generating code for intercepting and modifying program execution.
2. **Reverse Engineering Connection:**  Focus on how the code enables dynamic analysis. Think about breakpoints, tracing, and the ability to intercept and modify function calls and returns. Provide concrete examples.
3. **Low-Level Details:** Identify interactions with CPU registers, memory management (slabs), and potentially system calls or kernel interactions related to code injection and memory protection.
4. **Logic and Reasoning:**  Analyze specific functions like `gum_exec_block_write_call_transfer_code` or `gum_exec_block_write_ret_transfer_code`. Hypothesize the input (e.g., a `CALL` instruction), and trace the code generation steps to predict the output (the injected code sequence).
5. **Usage Errors:** Consider common mistakes when using Frida's Stalker API. This might involve incorrect filter configurations, issues with callbacks, or misunderstandings of the Stalker's behavior.
6. **Debugging Context:** Describe a typical Frida workflow where a user sets up a Stalker, attaches to a process, and observes execution. Explain how stepping through the Stalker's internal code could lead to this file.
7. **Part 6 Summary:**  Synthesize the information gathered in the previous steps to provide a concise summary of this file's role within the Stalker's instrumentation process, focusing on code generation for control flow and event handling. Emphasize that it's a specific stage of a larger instrumentation pipeline.
```c
;

    gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);
    gum_exec_ctx_get_branch_target_address (block->ctx, target, gc,
        gc->code_writer);

    ic_match = gum_exec_block_write_inline_cache_code (block, gc, cw, cws);
    gum_exec_ctx_write_epilog (block->ctx, GUM_PROLOG_IC, cw);

    /* Push the real return address */
    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
        -(gssize) sizeof (gpointer));
    gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);
    gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
        GUM_ADDRESS (ret_real_address));
    gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XSP,
        sizeof (gpointer), GUM_X86_XAX);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);

    gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (ic_match));
  }
  else
  {
    ret_code_address = cw->pc;
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));

    /*
     * Our backpatch may be larger than the trivial jump to the slow slab above,
     * especially if we have to write a epilogue, leave a little wiggle room.
     */
    gum_x86_writer_put_nop_padding (cw, 50);
  }

  gum_exec_block_close_prolog (block, gc, cws);

  if (target->is_indirect)
  {
    entry_func = GUM_ENTRYGATE (call_mem);
  }
  else if (target->base != X86_REG_INVALID)
  {
    entry_func = GUM_ENTRYGATE (call_reg);
  }
  else
  {
    entry_func = GUM_ENTRYGATE (call_imm);
  }

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);

  /* Generate code for the target */
  gum_exec_ctx_get_branch_target_address (block->ctx, target, gc, cws);

  gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
      GUM_ADDRESS (entry_func), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_XAX,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_XAX,
        GUM_ADDRESS (&block->ctx->current_block));
  }

  if (can_backpatch_statically)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_call), 7,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
        GUM_ARG_ADDRESS, call_code_start - GUM_ADDRESS (block->code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog),
        GUM_ARG_ADDRESS, GUM_ADDRESS (ret_real_address),
        GUM_ARG_ADDRESS, ret_code_address - GUM_ADDRESS (block->code_start));
  }

  if (block->ic_entries != NULL)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  /* Execute the generated code */
  gum_exec_block_close_prolog (block, gc, cws);

  /* Push the real return address */
  gum_x86_writer_put_lea_reg_reg_offset (cws, GUM_X86_XSP, GUM_X86_XSP,
      -(gssize) sizeof (gpointer));
  gum_x86_writer_put_push_reg (cws, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_address (cws, GUM_X86_XAX,
      GUM_ADDRESS (ret_real_address));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cws, GUM_X86_XSP,
      sizeof (gpointer), GUM_X86_XAX);
  gum_x86_writer_put_pop_reg (cws, GUM_X86_XAX);

  gum_x86_writer_put_jmp_near_ptr (cws, GUM_ADDRESS (&block->ctx->resume_at));
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumExecCtxReplaceCurrentBlockFunc func,
                                        GumGeneratorContext * gc,
                                        guint id,
                                        GumAddress jcc_address)
{
  const gint trust_threshold = block->ctx->stalker->trust_threshold;
  GumX86Writer * cw = gc->code_writer;
  const GumAddress code_start = cw->pc;
  GumX86Writer * cws = gc->slow_writer;
  const GumPrologType opened_prolog = gc->opened_prolog;
  gboolean can_backpatch_statically;
  gpointer * ic_match = NULL;

  can_backpatch_statically =
      trust_threshold >= 0 &&
      !target->is_indirect &&
      target->base == X86_REG_INVALID;

  if (trust_threshold >= 0 && !can_backpatch_statically)
  {
    gum_exec_block_close_prolog (block, gc, gc->code_writer);

    gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);
    gum_exec_ctx_get_branch_target_address (block->ctx, target, gc,
        gc->code_writer);
    ic_match = gum_exec_block_write_inline_cache_code (block, gc, cw, cws);

    /* Restore the target context and jump at ic_match */
    gum_exec_ctx_write_epilog (block->ctx, GUM_PROLOG_IC, cw);
    gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (ic_match));
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));

    /*
     * Our backpatch may be larger than the trivial jump to the slow slab above,
     * especially if we have to write a epilogue, leave a little wiggle room.
     */
    if (gc->opened_prolog != GUM_PROLOG_NONE)
      gum_x86_writer_put_nop_padding (cw, 11);
  }

  /* Cache miss, do it the hard way */
  gum_exec_block_close_prolog (block, gc, cws);

  /* Slow path */
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);
  gum_exec_ctx_get_branch_target_address (block->ctx, target, gc, cws);
  gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
      GUM_ADDRESS (func), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_XAX,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_XAX,
        GUM_ADDRESS (&block->ctx->current_block));
  }

  if (can_backpatch_statically)
  {
    switch (id)
    {
      case X86_INS_JMP:
      case X86_INS_CALL:
        gum_x86_writer_put_call_address_with_aligned_arguments (cws,
            GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_block_backpatch_jmp), 6,
            GUM_ARG_REGISTER, GUM_X86_XAX,
            GUM_ARG_ADDRESS, GUM_ADDRESS (block),
            GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
            GUM_ARG_ADDRESS, GUM_ADDRESS (id),
            GUM_ARG_ADDRESS, code_start - GUM_ADDRESS (block->code_start),
            GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog));
        break;
      default:
        gum_x86_writer_put_call_address_with_aligned_arguments (cws,
            GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_block_backpatch_jmp), 6,
            GUM_ARG_REGISTER, GUM_X86_XAX,
            GUM_ARG_ADDRESS, GUM_ADDRESS (block),
            GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
            GUM_ARG_ADDRESS, GUM_ADDRESS (id),
            GUM_ARG_ADDRESS, jcc_address - GUM_ADDRESS (block->code_start),
            GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog));
        break;
    }
  }

  if (block->ic_entries != NULL)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  gum_exec_block_close_prolog (block, gc, cws);

  gum_x86_writer_put_jmp_near_ptr (cws, GUM_ADDRESS (&block->ctx->resume_at));
}

/*
 * Return instructions are handled in a similar way to indirect branches using
 * an inline cache to determine the target. This avoids the overhead associated
 * with maintaining a shadow stack, and since most functions will have a very
 * limited number of call-sites, the inline cache should work very effectively.
 */
static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        GumGeneratorContext * gc)
{
  GumInstruction * insn = gc->instruction;
  cs_x86 * x86 = &insn->ci->detail->x86;
  cs_x86_op * op = &x86->operands[0];
  guint16 npop = 0;

  if (x86->op_count != 0)
  {
    g_assert (x86->op_count == 1);
    g_assert (op->type == X86_OP_IMM);
    g_assert (op->imm <= G_MAXUINT16);
    npop = op->imm;
  }

  gum_exec_block_write_chaining_return_code (block, gc, npop);
}

static void
gum_exec_block_write_chaining_return_code (GumExecBlock * block,
                                           GumGeneratorContext * gc,
                                           guint16 npop)
{
  const gint trust_threshold = block->ctx->stalker->trust_threshold;
  GumX86Writer * cw = gc->code_writer;
  GumX86Writer * cws = gc->slow_writer;
  gpointer * ic_match;
  GumExecCtx * ctx = block->ctx;

  if (trust_threshold >= 0)
  {
    gum_exec_block_close_prolog (block, gc, gc->code_writer);

    gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);

    gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
        GUM_ADDRESS (&ctx->app_stack));
    gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XAX);
    gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XAX);

    ic_match = gum_exec_block_write_inline_cache_code (block, gc, cw, cws);

    /* Restore the target context and jump at ic_match */
    gum_exec_ctx_write_epilog (block->ctx, GUM_PROLOG_IC, cw);
    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
        npop + sizeof (gpointer));
    gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (ic_match));
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));
  }

  /* Cache miss, do it the hard way */
  gum_exec_block_close_prolog (block, gc, cws);

  /* Slow path */
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);

  /*
   * If the user emits a CALL instruction from within their transformer, then
   * this will result in control flow returning back to the code slab when that
   * function returns. The target address for this RET is therefore not an
   * instrumented block (e.g. a real address within the application which has
   * been instrumented), but actually a code address within an instrumented
   * block itself. This therefore needs to be treated as a special case.
   *
   * Also since we cannot guarantee that code addresses between a stalker
   * instance and an observer are identical (hence prefetched backpatches are
   * communicated in terms of their real address), whilst these can be
   * backpatched by adding them to the inline cache, they cannot be prefetched.
   *
   * This block handles the backpatching of the entry into the inline cache, but
   * the block is still fetched by the call to `ret_slow_path` below, but the
   * ctx->current_block is not set and therefore the block is not backpatched by
   * gum_exec_block_backpatch_inline_cache in the traditional way.
   */
  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_address (cws, GUM_X86_XAX,
        GUM_ADDRESS (&ctx->app_stack));
    gum_x86_writer_put_mov_reg_reg_ptr (cws, GUM_X86_XAX, GUM_X86_XAX);
    gum_x86_writer_put_mov_reg_reg_ptr (cws, GUM_X86_THUNK_REG_ARG1,
        GUM_X86_XAX);

    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_slab),
        2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_REGISTER, GUM_X86_THUNK_REG_ARG1);
  }

  gum_x86_writer_put_mov_reg_address (cws, GUM_X86_XAX,
      GUM_ADDRESS (&ctx->app_stack));
  gum_x86_writer_put_mov_reg_reg_ptr (cws, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_reg_ptr (cws, GUM_X86_THUNK_REG_ARG1, GUM_X86_XAX);

  gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
      GUM_ADDRESS (GUM_ENTRYGATE (ret_slow_path)), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_THUNK_REG_ARG1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_XAX,
        GUM_ADDRESS (&block->ctx->current_block));

    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  gum_exec_block_close_prolog (block, gc, cws);
  gum_x86_writer_put_lea_reg_reg_offset (cws, GUM_X86_XSP, GUM_X86_XSP,
      npop + sizeof (gpointer));
  gum_x86_writer_put_jmp_near_ptr (cws, GUM_ADDRESS (&block->ctx->resume_at));
}

static gpointer *
gum_exec_block_write_inline_cache_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        GumX86Writer * cw,
                                        GumX86Writer * cws)
{
  GumSlab * data_slab = &block->ctx->data_slab->slab;
  GumStalker * stalker = block->ctx->stalker;
  guint i;
  const gsize empty_val = GUM_IC_MAGIC_EMPTY;
  const gsize scratch_val = GUM_IC_MAGIC_SCRATCH;
  gpointer * ic_match;
  gconstpointer match = cw->code + 1;

  block->ic_entries = gum_slab_reserve (data_slab,
      gum_stalker_get_ic_entry_size (stalker));

  for (i = 0; i != stalker->ic_entries; i++)
  {
    block->ic_entries[i].real_start = NULL;
    block->ic_entries[i].code_start = GSIZE_TO_POINTER (empty_val);
  }

  /*
   * Write a token which we can replace with our matched ic entry code_start
   * so we can use it as scratch space and retrieve and jump to it once we
   * have restored the target application context.
   */
  ic_match = gum_slab_reserve (data_slab, sizeof (scratch_val));
  *ic_match = GSIZE_TO_POINTER (scratch_val);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX,
      GUM_ADDRESS (block->ic_entries));

  for (i = 0; i != stalker->ic_entries; i++)
  {
    gum_x86_writer_put_cmp_reg_offset_ptr_reg (cw, GUM_X86_XBX,
        G_STRUCT_OFFSET (GumIcEntry, real_start), GUM_X86_XAX);
    gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, match, GUM_NO_HINT);
    gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XBX, sizeof (GumIcEntry));
  }

  gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));

  gum_x86_writer_put_label (cw, match);

  /* We found a match, stash the code_start value in the ic_match */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XAX, GUM_X86_XBX,
      G_STRUCT_OFFSET (GumIcEntry, code_start));
  gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (ic_match),
      GUM_X86_XAX);

  return ic_match;
}

/*
 * This function is responsible for backpatching code_slab addresses into the
 * inline cache. This may be encountered, for example when control flow returns
 * following execution of a CALL instruction emitted by a transformer.
 */
static void
gum_exec_block_backpatch_slab (GumExecBlock * block,
                               gpointer target)
{
  GumExecCtx * ctx = block->ctx;
  GumStalker * stalker = ctx->stalker;
  GumIcEntry * ic_entries = block->ic_entries;
  guint i;

  if (!gum_exec_ctx_contains (ctx, target))
    return;

  for (i = 0; i != stalker->ic_entries; i++)
  {
    if (ic_entries[i].real_start == target)
      return;
  }

  gum_spinlock_acquire (&ctx->code_lock);

  memmove (&ic_entries[1], &ic_entries[0],
      (stalker->ic_entries - 1) * sizeof (GumIcEntry));

  ic_entries[0].real_start = target;
  ic_entries[0].code_start = target;

  gum_spinlock_release (&ctx->code_lock);
}

static void
gum_exec_block_write_single_step_transfer_code (GumExecBlock * block,
                                                GumGeneratorContext * gc)
{
  guint8 code[] = {
    0xc6, 0x05, 0x78, 0x56, 0x34, 0x12,       /* mov byte [X], state */
          GUM_EXEC_CTX_SINGLE_STEPPING_ON_CALL,
    0x9c,                                     /* pushfd              */
    0x81, 0x0c, 0x24, 0x00, 0x01, 0x00, 0x00, /* or [esp], 0x100     */
    0x9d                                      /* popfd               */
  };

  *((GumExecCtxMode **) (code + 2)) = &block->ctx->mode;
  gum_x86_writer_put_bytes (gc->code_writer, code, sizeof (code));
  gum_x86_writer_put_jmp_address (gc->code_writer,
      GUM_ADDRESS (gc->instruction->start));
}

#if GLIB_SIZEOF_VOID_P == 4 && !defined (HAVE_QNX)

static void
gum_exec_block_write_sysenter_continuation_code (GumExecBlock * block,
                                                 GumGeneratorContext * gc,
                                                 gpointer saved_ret_addr)
{
  GumStalker * stalker = block->ctx->stalker;
  const gint trust_threshold = stalker->trust_threshold;
  GumX86Writer * cw = gc->code_writer;
  GumX86Writer * cws = gc->slow_writer;
  gpointer * ic_match;

  if (trust_threshold >= 0)
  {
    if ((block->ctx->sink_mask & GUM_RET) != 0)
    {
      gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_UNINTERRUPTIBLE);
    }

    gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);

    /*
     * But first, check if we've been asked to unfollow, in which case we'll
     * enter the Stalker so the unfollow can be completed...
     */
    gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_EAX,
        GUM_ADDRESS (&block->ctx->state));
    gum_x86_writer_put_cmp_reg_i32 (cw, GUM_X86_EAX,
        GUM_EXEC_CTX_UNFOLLOW_PENDING);
    gum_x86_writer_put_jcc_near (cw, X86_INS_JE, cws->code, GUM_UNLIKELY);

    gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_EAX,
        GUM_ADDRESS (saved_ret_addr));

    ic_match = gum_exec_block_write_inline_cache_code (block, gc, cw, cws);

    /* Restore the target context and jump at ic_match */
    gum_exec_ctx_write_epilog (block->ctx, GUM_PROLOG_IC, cw);
    gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (ic_match));
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));
  }

  /* Cache miss, do it the hard way */
  gum_exec_block_close_prolog (block, gc, cws);

  /*
   * Slow path (resolve dynamically)
   */
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);

  gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_THUNK_REG_ARG1,
      GUM_ADDRESS (saved_ret_addr));
  gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
      GUM_ADDRESS (GUM_ENTRYGATE (sysenter_slow_path)), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_THUNK_REG_ARG1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_XAX,
        GUM_ADDRESS (&block->ctx->current_block));

    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  gum_exec_block_close_prolog (block, gc, cws);
  gum_x86_writer_put_jmp_near_ptr (cws, GUM_ADDRESS (&block->ctx->resume_at));

  gum_x86_relocator_skip_one_no_label (gc->relocator);
}

#endif

static void
gum_exec_block_write_call_event_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  GumX86Writer * cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_exec_ctx_get_branch_target_address (block->ctx, target, gc,
      gc->code_writer);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, GUM_X86_XAX,
      GUM_ARG_REGISTER, GUM_X86_XBX);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
  gum_exec_block_close_prolog (block, gc, gc->code_writer);
}

static void
gum_exec_block_write_ret_event_code (Gum
### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
;

    gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);
    gum_exec_ctx_get_branch_target_address (block->ctx, target, gc,
        gc->code_writer);

    ic_match = gum_exec_block_write_inline_cache_code (block, gc, cw, cws);
    gum_exec_ctx_write_epilog (block->ctx, GUM_PROLOG_IC, cw);

    /* Push the real return address */
    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
        -(gssize) sizeof (gpointer));
    gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);
    gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
        GUM_ADDRESS (ret_real_address));
    gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XSP,
        sizeof (gpointer), GUM_X86_XAX);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);

    gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (ic_match));
  }
  else
  {
    ret_code_address = cw->pc;
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));

    /*
     * Our backpatch may be larger than the trivial jump to the slow slab above,
     * especially if we have to write a epilogue, leave a little wiggle room.
     */
    gum_x86_writer_put_nop_padding (cw, 50);
  }

  gum_exec_block_close_prolog (block, gc, cws);

  if (target->is_indirect)
  {
    entry_func = GUM_ENTRYGATE (call_mem);
  }
  else if (target->base != X86_REG_INVALID)
  {
    entry_func = GUM_ENTRYGATE (call_reg);
  }
  else
  {
    entry_func = GUM_ENTRYGATE (call_imm);
  }

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);

  /* Generate code for the target */
  gum_exec_ctx_get_branch_target_address (block->ctx, target, gc, cws);

  gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
      GUM_ADDRESS (entry_func), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_XAX,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_XAX,
        GUM_ADDRESS (&block->ctx->current_block));
  }

  if (can_backpatch_statically)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_call), 7,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
        GUM_ARG_ADDRESS, call_code_start - GUM_ADDRESS (block->code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog),
        GUM_ARG_ADDRESS, GUM_ADDRESS (ret_real_address),
        GUM_ARG_ADDRESS, ret_code_address - GUM_ADDRESS (block->code_start));
  }

  if (block->ic_entries != NULL)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  /* Execute the generated code */
  gum_exec_block_close_prolog (block, gc, cws);

  /* Push the real return address */
  gum_x86_writer_put_lea_reg_reg_offset (cws, GUM_X86_XSP, GUM_X86_XSP,
      -(gssize) sizeof (gpointer));
  gum_x86_writer_put_push_reg (cws, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_address (cws, GUM_X86_XAX,
      GUM_ADDRESS (ret_real_address));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cws, GUM_X86_XSP,
      sizeof (gpointer), GUM_X86_XAX);
  gum_x86_writer_put_pop_reg (cws, GUM_X86_XAX);

  gum_x86_writer_put_jmp_near_ptr (cws, GUM_ADDRESS (&block->ctx->resume_at));
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumExecCtxReplaceCurrentBlockFunc func,
                                        GumGeneratorContext * gc,
                                        guint id,
                                        GumAddress jcc_address)
{
  const gint trust_threshold = block->ctx->stalker->trust_threshold;
  GumX86Writer * cw = gc->code_writer;
  const GumAddress code_start = cw->pc;
  GumX86Writer * cws = gc->slow_writer;
  const GumPrologType opened_prolog = gc->opened_prolog;
  gboolean can_backpatch_statically;
  gpointer * ic_match = NULL;

  can_backpatch_statically =
      trust_threshold >= 0 &&
      !target->is_indirect &&
      target->base == X86_REG_INVALID;

  if (trust_threshold >= 0 && !can_backpatch_statically)
  {
    gum_exec_block_close_prolog (block, gc, gc->code_writer);

    gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);
    gum_exec_ctx_get_branch_target_address (block->ctx, target, gc,
        gc->code_writer);
    ic_match = gum_exec_block_write_inline_cache_code (block, gc, cw, cws);

    /* Restore the target context and jump at ic_match */
    gum_exec_ctx_write_epilog (block->ctx, GUM_PROLOG_IC, cw);
    gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (ic_match));
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));

    /*
     * Our backpatch may be larger than the trivial jump to the slow slab above,
     * especially if we have to write a epilogue, leave a little wiggle room.
     */
    if (gc->opened_prolog != GUM_PROLOG_NONE)
      gum_x86_writer_put_nop_padding (cw, 11);
  }

  /* Cache miss, do it the hard way */
  gum_exec_block_close_prolog (block, gc, cws);

  /* Slow path */
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);
  gum_exec_ctx_get_branch_target_address (block->ctx, target, gc, cws);
  gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
      GUM_ADDRESS (func), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_XAX,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_XAX,
        GUM_ADDRESS (&block->ctx->current_block));
  }

  if (can_backpatch_statically)
  {
    switch (id)
    {
      case X86_INS_JMP:
      case X86_INS_CALL:
        gum_x86_writer_put_call_address_with_aligned_arguments (cws,
            GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_block_backpatch_jmp), 6,
            GUM_ARG_REGISTER, GUM_X86_XAX,
            GUM_ARG_ADDRESS, GUM_ADDRESS (block),
            GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
            GUM_ARG_ADDRESS, GUM_ADDRESS (id),
            GUM_ARG_ADDRESS, code_start - GUM_ADDRESS (block->code_start),
            GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog));
        break;
      default:
        gum_x86_writer_put_call_address_with_aligned_arguments (cws,
            GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_block_backpatch_jmp), 6,
            GUM_ARG_REGISTER, GUM_X86_XAX,
            GUM_ARG_ADDRESS, GUM_ADDRESS (block),
            GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
            GUM_ARG_ADDRESS, GUM_ADDRESS (id),
            GUM_ARG_ADDRESS, jcc_address - GUM_ADDRESS (block->code_start),
            GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog));
        break;
    }
  }

  if (block->ic_entries != NULL)
  {
    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  gum_exec_block_close_prolog (block, gc, cws);

  gum_x86_writer_put_jmp_near_ptr (cws, GUM_ADDRESS (&block->ctx->resume_at));
}

/*
 * Return instructions are handled in a similar way to indirect branches using
 * an inline cache to determine the target. This avoids the overhead associated
 * with maintaining a shadow stack, and since most functions will have a very
 * limited number of call-sites, the inline cache should work very effectively.
 */
static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        GumGeneratorContext * gc)
{
  GumInstruction * insn = gc->instruction;
  cs_x86 * x86 = &insn->ci->detail->x86;
  cs_x86_op * op = &x86->operands[0];
  guint16 npop = 0;

  if (x86->op_count != 0)
  {
    g_assert (x86->op_count == 1);
    g_assert (op->type == X86_OP_IMM);
    g_assert (op->imm <= G_MAXUINT16);
    npop = op->imm;
  }

  gum_exec_block_write_chaining_return_code (block, gc, npop);
}

static void
gum_exec_block_write_chaining_return_code (GumExecBlock * block,
                                           GumGeneratorContext * gc,
                                           guint16 npop)
{
  const gint trust_threshold = block->ctx->stalker->trust_threshold;
  GumX86Writer * cw = gc->code_writer;
  GumX86Writer * cws = gc->slow_writer;
  gpointer * ic_match;
  GumExecCtx * ctx = block->ctx;

  if (trust_threshold >= 0)
  {
    gum_exec_block_close_prolog (block, gc, gc->code_writer);

    gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);

    gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
        GUM_ADDRESS (&ctx->app_stack));
    gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XAX);
    gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XAX);

    ic_match = gum_exec_block_write_inline_cache_code (block, gc, cw, cws);

    /* Restore the target context and jump at ic_match */
    gum_exec_ctx_write_epilog (block->ctx, GUM_PROLOG_IC, cw);
    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
        npop + sizeof (gpointer));
    gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (ic_match));
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));
  }

  /* Cache miss, do it the hard way */
  gum_exec_block_close_prolog (block, gc, cws);

  /* Slow path */
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);

  /*
   * If the user emits a CALL instruction from within their transformer, then
   * this will result in control flow returning back to the code slab when that
   * function returns. The target address for this RET is therefore not an
   * instrumented block (e.g. a real address within the application which has
   * been instrumented), but actually a code address within an instrumented
   * block itself. This therefore needs to be treated as a special case.
   *
   * Also since we cannot guarantee that code addresses between a stalker
   * instance and an observer are identical (hence prefetched backpatches are
   * communicated in terms of their real address), whilst these can be
   * backpatched by adding them to the inline cache, they cannot be prefetched.
   *
   * This block handles the backpatching of the entry into the inline cache, but
   * the block is still fetched by the call to `ret_slow_path` below, but the
   * ctx->current_block is not set and therefore the block is not backpatched by
   * gum_exec_block_backpatch_inline_cache in the traditional way.
   */
  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_address (cws, GUM_X86_XAX,
        GUM_ADDRESS (&ctx->app_stack));
    gum_x86_writer_put_mov_reg_reg_ptr (cws, GUM_X86_XAX, GUM_X86_XAX);
    gum_x86_writer_put_mov_reg_reg_ptr (cws, GUM_X86_THUNK_REG_ARG1,
        GUM_X86_XAX);

    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_slab),
        2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_REGISTER, GUM_X86_THUNK_REG_ARG1);
  }

  gum_x86_writer_put_mov_reg_address (cws, GUM_X86_XAX,
      GUM_ADDRESS (&ctx->app_stack));
  gum_x86_writer_put_mov_reg_reg_ptr (cws, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_reg_ptr (cws, GUM_X86_THUNK_REG_ARG1, GUM_X86_XAX);

  gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
      GUM_ADDRESS (GUM_ENTRYGATE (ret_slow_path)), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_THUNK_REG_ARG1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_XAX,
        GUM_ADDRESS (&block->ctx->current_block));

    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  gum_exec_block_close_prolog (block, gc, cws);
  gum_x86_writer_put_lea_reg_reg_offset (cws, GUM_X86_XSP, GUM_X86_XSP,
      npop + sizeof (gpointer));
  gum_x86_writer_put_jmp_near_ptr (cws, GUM_ADDRESS (&block->ctx->resume_at));
}

static gpointer *
gum_exec_block_write_inline_cache_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        GumX86Writer * cw,
                                        GumX86Writer * cws)
{
  GumSlab * data_slab = &block->ctx->data_slab->slab;
  GumStalker * stalker = block->ctx->stalker;
  guint i;
  const gsize empty_val = GUM_IC_MAGIC_EMPTY;
  const gsize scratch_val = GUM_IC_MAGIC_SCRATCH;
  gpointer * ic_match;
  gconstpointer match = cw->code + 1;

  block->ic_entries = gum_slab_reserve (data_slab,
      gum_stalker_get_ic_entry_size (stalker));

  for (i = 0; i != stalker->ic_entries; i++)
  {
    block->ic_entries[i].real_start = NULL;
    block->ic_entries[i].code_start = GSIZE_TO_POINTER (empty_val);
  }

  /*
   * Write a token which we can replace with our matched ic entry code_start
   * so we can use it as scratch space and retrieve and jump to it once we
   * have restored the target application context.
   */
  ic_match = gum_slab_reserve (data_slab, sizeof (scratch_val));
  *ic_match = GSIZE_TO_POINTER (scratch_val);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX,
      GUM_ADDRESS (block->ic_entries));

  for (i = 0; i != stalker->ic_entries; i++)
  {
    gum_x86_writer_put_cmp_reg_offset_ptr_reg (cw, GUM_X86_XBX,
        G_STRUCT_OFFSET (GumIcEntry, real_start), GUM_X86_XAX);
    gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, match, GUM_NO_HINT);
    gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XBX, sizeof (GumIcEntry));
  }

  gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));

  gum_x86_writer_put_label (cw, match);

  /* We found a match, stash the code_start value in the ic_match */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XAX, GUM_X86_XBX,
      G_STRUCT_OFFSET (GumIcEntry, code_start));
  gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (ic_match),
      GUM_X86_XAX);

  return ic_match;
}

/*
 * This function is responsible for backpatching code_slab addresses into the
 * inline cache. This may be encountered, for example when control flow returns
 * following execution of a CALL instruction emitted by a transformer.
 */
static void
gum_exec_block_backpatch_slab (GumExecBlock * block,
                               gpointer target)
{
  GumExecCtx * ctx = block->ctx;
  GumStalker * stalker = ctx->stalker;
  GumIcEntry * ic_entries = block->ic_entries;
  guint i;

  if (!gum_exec_ctx_contains (ctx, target))
    return;

  for (i = 0; i != stalker->ic_entries; i++)
  {
    if (ic_entries[i].real_start == target)
      return;
  }

  gum_spinlock_acquire (&ctx->code_lock);

  memmove (&ic_entries[1], &ic_entries[0],
      (stalker->ic_entries - 1) * sizeof (GumIcEntry));

  ic_entries[0].real_start = target;
  ic_entries[0].code_start = target;

  gum_spinlock_release (&ctx->code_lock);
}

static void
gum_exec_block_write_single_step_transfer_code (GumExecBlock * block,
                                                GumGeneratorContext * gc)
{
  guint8 code[] = {
    0xc6, 0x05, 0x78, 0x56, 0x34, 0x12,       /* mov byte [X], state */
          GUM_EXEC_CTX_SINGLE_STEPPING_ON_CALL,
    0x9c,                                     /* pushfd              */
    0x81, 0x0c, 0x24, 0x00, 0x01, 0x00, 0x00, /* or [esp], 0x100     */
    0x9d                                      /* popfd               */
  };

  *((GumExecCtxMode **) (code + 2)) = &block->ctx->mode;
  gum_x86_writer_put_bytes (gc->code_writer, code, sizeof (code));
  gum_x86_writer_put_jmp_address (gc->code_writer,
      GUM_ADDRESS (gc->instruction->start));
}

#if GLIB_SIZEOF_VOID_P == 4 && !defined (HAVE_QNX)

static void
gum_exec_block_write_sysenter_continuation_code (GumExecBlock * block,
                                                 GumGeneratorContext * gc,
                                                 gpointer saved_ret_addr)
{
  GumStalker * stalker = block->ctx->stalker;
  const gint trust_threshold = stalker->trust_threshold;
  GumX86Writer * cw = gc->code_writer;
  GumX86Writer * cws = gc->slow_writer;
  gpointer * ic_match;

  if (trust_threshold >= 0)
  {
    if ((block->ctx->sink_mask & GUM_RET) != 0)
    {
      gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_UNINTERRUPTIBLE);
    }

    gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);

    /*
     * But first, check if we've been asked to unfollow, in which case we'll
     * enter the Stalker so the unfollow can be completed...
     */
    gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_EAX,
        GUM_ADDRESS (&block->ctx->state));
    gum_x86_writer_put_cmp_reg_i32 (cw, GUM_X86_EAX,
        GUM_EXEC_CTX_UNFOLLOW_PENDING);
    gum_x86_writer_put_jcc_near (cw, X86_INS_JE, cws->code, GUM_UNLIKELY);

    gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_EAX,
        GUM_ADDRESS (saved_ret_addr));

    ic_match = gum_exec_block_write_inline_cache_code (block, gc, cw, cws);

    /* Restore the target context and jump at ic_match */
    gum_exec_ctx_write_epilog (block->ctx, GUM_PROLOG_IC, cw);
    gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (ic_match));
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (cws->code));
  }

  /* Cache miss, do it the hard way */
  gum_exec_block_close_prolog (block, gc, cws);

  /*
   * Slow path (resolve dynamically)
   */
  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);

  gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_THUNK_REG_ARG1,
      GUM_ADDRESS (saved_ret_addr));
  gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
      GUM_ADDRESS (GUM_ENTRYGATE (sysenter_slow_path)), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_THUNK_REG_ARG1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cws, GUM_X86_XAX,
        GUM_ADDRESS (&block->ctx->current_block));

    gum_x86_writer_put_call_address_with_aligned_arguments (cws, GUM_CALL_CAPI,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, GUM_X86_XAX,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  gum_exec_block_close_prolog (block, gc, cws);
  gum_x86_writer_put_jmp_near_ptr (cws, GUM_ADDRESS (&block->ctx->resume_at));

  gum_x86_relocator_skip_one_no_label (gc->relocator);
}

#endif

static void
gum_exec_block_write_call_event_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  GumX86Writer * cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_exec_ctx_get_branch_target_address (block->ctx, target, gc,
      gc->code_writer);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, GUM_X86_XAX,
      GUM_ARG_REGISTER, GUM_X86_XBX);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
  gum_exec_block_close_prolog (block, gc, gc->code_writer);
}

static void
gum_exec_block_write_ret_event_code (GumExecBlock * block,
                                     GumGeneratorContext * gc,
                                     GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_x86_writer_put_call_address_with_aligned_arguments (gc->code_writer,
      GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, GUM_X86_XBX);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
  gum_exec_block_close_prolog (block, gc, gc->code_writer);
}

static void
gum_exec_block_write_exec_event_code (GumExecBlock * block,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_x86_writer_put_call_address_with_aligned_arguments (gc->code_writer,
      GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, GUM_X86_XBX);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
  gum_exec_block_close_prolog (block, gc, gc->code_writer);
}

static void
gum_exec_block_write_block_event_code (GumExecBlock * block,
                                       GumGeneratorContext * gc,
                                       GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_x86_writer_put_call_address_with_aligned_arguments (gc->code_writer,
      GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_XBX);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
  gum_exec_block_close_prolog (block, gc, gc->code_writer);
}

static void
gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
                                          GumGeneratorContext * gc,
                                          GumCodeContext cc)
{
  GumExecCtx * ctx = block->ctx;
  GumX86Writer * cw = gc->code_writer;
  gconstpointer beach = cw->code + 1;
  GumPrologType opened_prolog;

  if (cc != GUM_CODE_INTERRUPTIBLE)
    return;

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_exec_ctx_maybe_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_EAX, GUM_X86_EAX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, beach, GUM_LIKELY);

  opened_prolog = gc->opened_prolog;
  gum_exec_block_close_prolog (block, gc, gc->code_writer);
  gc->opened_prolog = opened_prolog;

  gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (&ctx->resume_at));

  gum_x86_writer_put_label (cw, beach);
}

static void
gum_exec_block_maybe_write_call_probe_code (GumExecBlock * block,
                                            GumGeneratorContext * gc)
{
  GumStalker * stalker = block->ctx->stalker;

  if (!stalker->any_probes_attached)
    return;

  gum_spinlock_acquire (&stalker->probe_lock);

  if (g_hash_table_contains (stalker->probe_array_by_address,
          block->real_start))
  {
    gum_exec_block_write_call_probe_code (block, gc);
  }

  gum_spinlock_release (&stalker->probe_lock);
}

static void
gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                      GumGeneratorContext * gc)
{
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_x86_writer_put_call_address_with_aligned_arguments (gc->code_writer,
      GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_block_invoke_call_probes),
      2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, GUM_X86_XBX);
}

static void
gum_exec_block_invoke_call_probes (GumExecBlock * block,
                                   GumCpuContext * cpu_context)
{
  GumStalker * stalker = block->ctx->stalker;
  const gpointer target_address = block->real_start;
  GumCallProbe ** probes_copy;
  guint num_probes, i;
  gpointer * return_address_slot;
  GumCallDetails d;

  probes_copy = NULL;
  num_probes = 0;
  {
    GPtrArray * probes;

    gum_spinlock_acquire (&stalker->probe_lock);

    probes =
        g_hash_table_lookup (stalker->probe_array_by_address, target_address);
    if (probes != NULL)
    {
      num_probes = probes->len;
      probes_copy = g_newa (GumCallProbe *, num_probes);
      for (i = 0; i != num_probes; i++)
      {
        probes_copy[i] = gum_call_probe_ref (g_ptr_array_index (probes, i));
      }
    }

    gum_spinlock_release (&stalker->probe_lock);
  }
  if (num_probes == 0)
    return;

  return_address_slot = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XSP (cpu_context));

  d.target_address = target_address;
  d.return_address = *return_address_slot;
  d.stack_data = return_address_slot;
  d.cpu_context = cpu_context;

  GUM_CPU_CONTEXT_XIP (cpu_context) = GPOINTER_TO_SIZE (target_address);

  for (i = 0; i != num_probes; i++)
  {
    GumCallProbe * probe = probes_copy[i];

    probe->callback (&d, probe->user_data);

    gum_call_probe_unref (probe);
  }
}

static gpointer
gum_exec_block_write_inline_data (GumX86Writer * cw,
                                  gconstpointer data,
                                  gsize size,
                                  GumAddress * address)
{
  gpointer location;
  gconstpointer after_data = cw->code + 1;

  while (gum_x86_writer_offset (cw) < GUM_INVALIDATE_TRAMPOLINE_SIZE)
  {
    gum_x86_writer_put_nop (cw);
  }

  if (GUM_IS_WITHIN_UINT8_RANGE (size))
    gum_x86_writer_put_jmp_short_label (cw, after_data);
  else
    gum_x86_writer_put_jmp_near_label (cw, after_data);

  location = gum_x86_writer_cur (cw);
  if (address != NULL)
    *address = cw->pc;
  gum_x86_writer_put_bytes (cw, data, size);

  gum_x86_writer_put_label (cw, after_data);

  return location;
}

static void
gum_exec_block_open_prolog (GumExecBlock * block,
                            GumPrologType type,
                            GumGeneratorContext * gc,
                            GumX86Writer * cw)
{
  if (gc->opened_prolog >= type)
    return;

  /* We don't want to handle this case for performance reasons */
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);

  gc->opened_prolog = type;

  gum_exec_ctx_write_prolog (block->ctx, type, cw);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc,
                             GumX86Writer * cw)
{
  if (gc->opened_prolog == GUM_PROLOG_NONE)
    return;

  gum_exec_ctx_write_epilog (block->ctx, gc->opened_prolog, cw);

  gc->opened_prolog = GUM_PROLOG_NONE;
}

static GumCodeSlab *
gum_code_slab_new (GumExecCtx * ctx)
{
  GumCodeSlab * slab;
  GumStalker * stalker = ctx->stalker;
  const gsize slab_size = stalker->code_slab_size_dynamic;
  GumAddressSpec spec;

  gum_exec_ctx_compute_code_address_spec (ctx, slab_size, &spec);

  slab = gum_memory_allocate_near (&spec, slab_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  gum_code_slab_init (slab, slab_size, stalker->page_size);

  return slab;
}

static GumSlowSlab *
gum_slow_slab_new (GumExecCtx * ctx)
{
  GumSlowSlab * slab;
  GumStalker * stalker = ctx->stalker;
  const gsize slab_size = stalker->code_slab_size_dynamic;
  GumAddressSpec spec;

  gum_exec_ctx_compute_code_address_spec (ctx, slab_size, &spec);

  slab = gum_memory_allocate_near (&spec, slab_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  gum_slow_slab_init (slab, slab_size, stalker->page_size);

  return slab;
}

static void
gum_code_slab_free (GumCodeSlab * code_slab)
{
  gum_slab_free (&code_slab->slab);
}

static void
gum_code_slab_init (GumCodeSlab * code_slab,
                    gsize slab_size,
                    gsize page_size)
{
  /*
   * We don't want to thaw and freeze the header just to update the offset,
   * so we trade a little memory for speed.
   */
  const gsize header_size = GUM_ALIGN_SIZE (sizeof (GumCodeSlab), page_size);

  gum_slab_init (&code_slab->slab, slab_size, header_size);

  code_slab->invalidator = NULL;
}

static void
gum_slow_slab_init (GumSlowSlab * slow_slab,
                    gsize slab_size,
                    gsize page_size)
{
  /*
   * We don't want to thaw and freeze the header just to update the offset,
   * so we trade a little memory for speed.
   */
  const gsize header_size = GUM_ALIGN_SIZE (sizeof (GumCodeSlab), page_size);

  gum_slab_init (&slow_slab->slab, slab_size, header_size);

  slow_slab->invalidator = NULL;
}

static GumDataSlab *
gum_data_slab_new (GumExecCtx * ctx)
{
  GumDataSlab * slab;
  GumStalker * stalker = ctx->stalker;
  const gsize slab_size = stalker->data_slab_size_dynamic;
  GumAddressSpec spec;

  gum_exec_ctx_compute_data_address_spec (ctx, slab_size, &spec);

  slab = gum_memory_allocate_near (&spec, slab_size, stalker->page_size,
      GUM_PAGE_RW);

  gum_data_slab_init (slab, slab_size);

  return slab;
}

static void
gum_data_slab_free (GumDataSlab * data_slab)
{
  gum_slab_free (&data_slab->slab);
}

static void
gum_data_slab_init (GumDataSlab * data_slab,
                    gsize slab_size)
{
  GumSlab * slab = &data_slab->slab;
  const gsize header_size = sizeof (GumDataSlab);

  gum_slab_init (slab, slab_size, header_size);
}

static void
gum_scratch_slab_init (GumCodeSlab * scratch_slab,
                       gsize slab_size)
{
  const gsize header_size = sizeof (GumCodeSlab);

  gum_slab_init (&scratch_slab->slab, slab_size, header_size);

  scratch_slab->invalidator = NULL;
}

static void
gum_slab_free (GumSlab * slab)
{
  const gsize header_size = slab->data - (guint8 *) slab;

  gum_memory_free (slab, header_size + slab->size);
}

static void
gum_slab_init (GumSlab * slab,
               gsize slab_size,
               gsize header_size)
{
  slab->data = (guint8 *) slab + header_size;
  slab->offset = 0;
  slab->size = slab_size - header_size;
  slab->next = NULL;
}

static gsize
gum_slab_available (GumSlab * self)
{
  return self->size - self->offset;
}

static gpointer
gum_slab_start (GumSlab * self)
{
  return self->data;
}

static gpointer
gum_slab_end (GumSlab * self)
{
  return self->data + self->size;
}

static gpointer
gum_slab_cursor (GumSlab * self)
{
  return self->data + self->offset;
}

static gpointer
gum_slab_reserve (GumSlab * self,
                  gsize size)
{
  gpointer cursor;

  cursor = gum_slab_try_reserve (self, size);
  g_assert (cursor != NULL);

  return cursor;
}

static gpointer
gum_slab_try_reserve (GumSlab * self,
                      gsize size)
{
  gpointer cursor;

  if (gum_slab_available (self) < size)
    return NULL;

  cursor = gum_slab_cursor (self);
  self->offset += size;

  return cursor;
}

static void
gum_write_segment_prefix (uint8_t segment,
                          GumX86Writer * cw)
{
  switch (segment)
  {
    case X86_REG_INVALID: break;

    case X86_REG_CS: gum_x86_writer_put_u8 (cw, 0x2e); break;
    case X86_REG_SS: gum_x86_writer_put_u8 (cw, 0x36); break;
    case X86_REG_DS: gum_x86_writer_put_u8 (cw, 0x3e); break;
    case X86_REG_ES: gum_x86_writer_put_u8 (cw, 0x26); break;
    case X86_REG_FS: gum_x86_writer_put_u8 (cw, 0x64); break;
    case X86_REG_GS: gum_x86_writer_put_u8 (cw, 0x65); break;

    default:
      g_assert_not_reached ();
      break;
  }
}

static GumX86Reg
gum_x86_meta_reg_from_real_reg (GumX86Reg reg)
{
  if (reg >= GUM_X86_EAX && reg <= GUM_X86_EDI)
    return (GumX86Reg) (GUM_X86_XAX + reg - GUM_X86_EAX);
  else if (reg >= GUM_X86_RAX && reg <= GUM_X86_RDI)
    return (GumX86Reg) (GUM_X86_XAX + reg - GUM_X86_RAX);
#if GLIB_SIZEOF_VOID_P == 8
  else if (reg >= GUM_X86_R8D && reg <= GUM_X86_R15D)
    return reg;
  else if (reg >= GUM_X86_R8 && reg <= GUM_X86_R15)
    return reg;
#endif
  else if (reg == GUM_X86_RIP)
    return GUM_X86_XIP;
  else if (reg != GUM_X86_NONE)
    g_assert_not_reached ();

  return GUM_X86_NONE;
}

static GumX86Reg
gum_x86_reg_from_capstone (x86_reg reg)
{
  switch (reg)
  {
    case X86_REG_EAX: return GUM_X86_EAX;
    case X86_REG_ECX: return GUM_X86_ECX;
    case X86_REG_EDX: return GUM_X86_EDX;
    case X86_REG_EBX: return GUM_X86_EBX;
    case X86_REG_ESP: return GUM_X86_ESP;
    case X86_REG_EBP: return GUM_X86_
```