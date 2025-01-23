Response:
The user wants a summary of the functionality of the C code provided, specifically focusing on its role in Frida, a dynamic instrumentation tool. I need to identify the key operations performed by this code, relate them to reverse engineering concepts, explain any interactions with the operating system kernel or frameworks, detail any logical reasoning within the code (including hypothetical inputs and outputs), point out potential user errors, describe how a user might reach this code during debugging, and finally, provide a concise summary of its overall function.

Here's a breakdown of the code's main actions:

1. **Prolog and Epilog Handling:** The code defines functions to generate prologues and epilogues for instrumented code. These prologs and epilogues save and restore the execution context (registers, flags, stack). Different levels of prologs (minimal, full, IC) are supported.
2. **Inline Helper Functions:**  It manages the generation and accessibility of small helper functions for common tasks like saving/restoring CPU state (fxsave/fxrstor), handling system calls (int 0x80, syscall), and invalidating code blocks.
3. **Code Generation:** It uses `GumX86Writer` to emit x86 instructions. The code interacts heavily with this writer to generate the prologues, epilogues, and helper functions.
4. **Code Block Management:**  It deals with the creation, clearing, committing, and invalidating of `GumExecBlock` structures. These blocks represent chunks of dynamically generated and instrumented code.
5. **Backpatching:**  A crucial aspect is backpatching. This involves modifying already generated code to redirect control flow to newly generated blocks. This is essential for the dynamic nature of Frida's instrumentation.
6. **Register Handling:** The code includes functions to load the values of real CPU registers into temporary registers within the instrumented code. It manages different strategies based on the type of prologue used.
7. **Branch Target Resolution:**  It handles the calculation and loading of branch target addresses, considering both direct and indirect jumps.

Now, let's map these functionalities to the specific requirements of the prompt.
```c
lahf (cw);
      gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);

      gum_x86_writer_put_push_reg (cw, GUM_X86_XBX);
      gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XBX, GUM_X86_XSP);

      gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XAX, GUM_X86_XSP,
          3 * sizeof (gpointer) + GUM_RED_ZONE_SIZE);
      gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (&ctx->app_stack),
          GUM_X86_XAX);

      break;
    }
    default:
    {
      g_assert_not_reached ();
      break;
    }
  }
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
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
          ? ctx->last_epilog_minimal
          : ctx->last_epilog_full;

      gum_x86_writer_put_call_address (cw, GUM_ADDRESS (helper));
      gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_XSP,
          GUM_ADDRESS (&ctx->app_stack));

      break;
    }
    case GUM_PROLOG_IC:
    {
      gum_x86_writer_put_pop_reg (cw, GUM_X86_XBX);

      gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);
      gum_x86_writer_put_sahf (cw);
      gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);

      gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_XSP,
          GUM_ADDRESS (&ctx->app_stack));

      break;
    }
    default:
    {
      g_assert_not_reached ();
      break;
    }
  }
}

static void
gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx)
{
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_prolog_minimal,
      gum_exec_ctx_write_minimal_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_epilog_minimal,
      gum_exec_ctx_write_minimal_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_prolog_full,
      gum_exec_ctx_write_full_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_epilog_full,
      gum_exec_ctx_write_full_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_invalidator,
      gum_exec_ctx_write_invalidator);
  ctx->code_slab->invalidator = ctx->last_invalidator;

#ifdef HAVE_LINUX
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_int80,
      gum_exec_ctx_write_int80_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_syscall,
      gum_exec_ctx_write_syscall_helper);
#endif
}

static void
gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
                                          GumX86Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
                                          GumX86Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
                                       GumX86Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
                                       GumX86Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumX86Writer * cw)
{
  guint8 fxsave[] = {
    0x0f, 0xae, 0x04, 0x24 /* fxsave [esp] */
  };
  guint8 upper_ymm_saver[] = {
#if GLIB_SIZEOF_VOID_P == 8
    /* vextracti128 ymm0..ymm15, [rsp+0x0]..[rsp+0xF0], 1 */
    0xc4, 0xe3, 0x7d, 0x39, 0x04, 0x24, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x4c, 0x24, 0x10, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x54, 0x24, 0x20, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x5c, 0x24, 0x30, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x64, 0x24, 0x40, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x6c, 0x24, 0x50, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x74, 0x24, 0x60, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x7c, 0x24, 0x70, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0x8c, 0x24, 0x90, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0x94, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0x9c, 0x24, 0xb0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0xa4, 0x24, 0xc0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0xac, 0x24, 0xd0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0xb4, 0x24, 0xe0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0xbc, 0x24, 0xf0, 0x00, 0x00, 0x00, 0x01
#else
    /* vextracti128 ymm0..ymm7, [esp+0x0]..[esp+0x70], 1 */
    0xc4, 0xc3, 0x7d, 0x39, 0x04, 0x24, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x4c, 0x24, 0x10, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x54, 0x24, 0x20, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x5c, 0x24, 0x30, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x64, 0x24, 0x40, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x6c, 0x24, 0x50, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x74, 0x24, 0x60, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x7c, 0x24, 0x70, 0x01
#endif
  };

  gum_x86_writer_put_pushfx (cw);
  gum_x86_writer_put_cld (cw); /* C ABI mandates this */

  if (type == GUM_PROLOG_MINIMAL)
  {
    gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);

    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XAX, GUM_X86_XSP,
        3 * sizeof (gpointer) + GUM_RED_ZONE_SIZE);
    gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (&ctx->app_stack),
        GUM_X86_XAX);

    gum_x86_writer_put_push_reg (cw, GUM_X86_XCX);
    gum_x86_writer_put_push_reg (cw, GUM_X86_XDX);
    gum_x86_writer_put_push_reg (cw, GUM_X86_XBX);

#if GLIB_SIZEOF_VOID_P == 8
    gum_x86_writer_put_push_reg (cw, GUM_X86_XSI);
    gum_x86_writer_put_push_reg (cw, GUM_X86_XDI);
    gum_x86_writer_put_push_reg (cw, GUM_X86_R8);
    gum_x86_writer_put_push_reg (cw, GUM_X86_R9);
    gum_x86_writer_put_push_reg (cw, GUM_X86_R10);
    gum_x86_writer_put_push_reg (cw, GUM_X86_R11);
#endif
  }
  else /* GUM_PROLOG_FULL */
  {
    gum_x86_writer_put_pushax (cw); /* All of GumCpuContext except for xip */
    /* GumCpuContext.xip gets filled out later */
    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
        -(gssize) sizeof (gpointer));

    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XAX, GUM_X86_XSP,
        sizeof (GumCpuContext) + 2 * sizeof (gpointer) + GUM_RED_ZONE_SIZE);
    gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (&ctx->app_stack),
        GUM_X86_XAX);

    gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
        GUM_X86_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
        GUM_X86_XAX);
  }

  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XBX, GUM_X86_XSP);
  gum_x86_writer_put_and_reg_u32 (cw, GUM_X86_XSP, (guint32) ~(16 - 1));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_XSP, 512);
  gum_x86_writer_put_bytes (cw, fxsave, sizeof (fxsave));

  if ((ctx->stalker->cpu_features & GUM_CPU_AVX2) != 0)
  {
    gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_XSP, 0x100);
    gum_x86_writer_put_bytes (cw, upper_ymm_saver, sizeof (upper_ymm_saver));
  }

  /* Jump to our caller but leave it on the stack */
  gum_x86_writer_put_jmp_reg_offset_ptr (cw,
      GUM_X86_XBX, (type == GUM_PROLOG_MINIMAL)
          ? GUM_MINIMAL_PROLOG_RETURN_OFFSET
          : GUM_FULL_PROLOG_RETURN_OFFSET);
}

static void
gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumX86Writer * cw)
{
  guint8 fxrstor[] = {
    0x0f, 0xae, 0x0c, 0x24 /* fxrstor [esp] */
  };
  guint8 upper_ymm_restorer[] = {
#if GLIB_SIZEOF_VOID_P == 8
    /* vinserti128 ymm0..ymm15, ymm0..ymm15, [rsp+0x0]..[rsp+0xF0], 1 */
    0xc4, 0xe3, 0x7d, 0x38, 0x04, 0x24, 0x01,
    0xc4, 0xe3, 0x75, 0x38, 0x4c, 0x24, 0x10, 0x01,
    0xc4, 0xe3, 0x6d, 0x38, 0x54, 0x24, 0x20, 0x01,
    0xc4, 0xe3, 0x65, 0x38, 0x5c, 0x24, 0x30, 0x01,
    0xc4, 0xe3, 0x5d, 0x38, 0x64, 0x24, 0x40, 0x01,
    0xc4, 0xe3, 0x55, 0x38, 0x6c, 0x24, 0x50, 0x01,
    0xc4, 0xe3, 0x4d, 0x38, 0x74, 0x24, 0x60, 0x01,
    0xc4, 0xe3, 0x45, 0x38, 0x7c, 0x24, 0x70, 0x01,
    0xc4, 0x63, 0x3d, 0x38, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x35, 0x38, 0x8c, 0x24, 0x90, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x2d, 0x38, 0x94, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x25, 0x38, 0x9c, 0x24, 0xb0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x1d, 0x38, 0xa4, 0x24, 0xc0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x15, 0x38, 0xac, 0x24, 0xd0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x0d, 0x38, 0xb4, 0x24, 0xe0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x05, 0x38, 0xbc, 0x24, 0xf0, 0x00, 0x00, 0x00, 0x01
#else
    /* vinserti128 ymm0..ymm7, ymm0..ymm7, [esp+0x0]..[esp+0x70], 1 */
    0xc4, 0xc3, 0x7d, 0x38, 0x04, 0x24, 0x01,
    0xc4, 0xc3, 0x75, 0x38, 0x4c, 0x24, 0x10, 0x01,
    0xc4, 0xc3, 0x6d, 0x38, 0x54, 0x24, 0x20, 0x01,
    0xc4, 0xc3, 0x65, 0x38, 0x5c, 0x24, 
### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```c
lahf (cw);
      gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);

      gum_x86_writer_put_push_reg (cw, GUM_X86_XBX);
      gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XBX, GUM_X86_XSP);

      gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XAX, GUM_X86_XSP,
          3 * sizeof (gpointer) + GUM_RED_ZONE_SIZE);
      gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (&ctx->app_stack),
          GUM_X86_XAX);

      break;
    }
    default:
    {
      g_assert_not_reached ();
      break;
    }
  }
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
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
          ? ctx->last_epilog_minimal
          : ctx->last_epilog_full;

      gum_x86_writer_put_call_address (cw, GUM_ADDRESS (helper));
      gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_XSP,
          GUM_ADDRESS (&ctx->app_stack));

      break;
    }
    case GUM_PROLOG_IC:
    {
      gum_x86_writer_put_pop_reg (cw, GUM_X86_XBX);

      gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);
      gum_x86_writer_put_sahf (cw);
      gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);

      gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_XSP,
          GUM_ADDRESS (&ctx->app_stack));

      break;
    }
    default:
    {
      g_assert_not_reached ();
      break;
    }
  }
}

static void
gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx)
{
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_prolog_minimal,
      gum_exec_ctx_write_minimal_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_epilog_minimal,
      gum_exec_ctx_write_minimal_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_prolog_full,
      gum_exec_ctx_write_full_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_epilog_full,
      gum_exec_ctx_write_full_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_invalidator,
      gum_exec_ctx_write_invalidator);
  ctx->code_slab->invalidator = ctx->last_invalidator;

#ifdef HAVE_LINUX
  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_int80,
      gum_exec_ctx_write_int80_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, &ctx->last_syscall,
      gum_exec_ctx_write_syscall_helper);
#endif
}

static void
gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
                                          GumX86Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
                                          GumX86Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
                                       GumX86Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
                                       GumX86Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumX86Writer * cw)
{
  guint8 fxsave[] = {
    0x0f, 0xae, 0x04, 0x24 /* fxsave [esp] */
  };
  guint8 upper_ymm_saver[] = {
#if GLIB_SIZEOF_VOID_P == 8
    /* vextracti128 ymm0..ymm15, [rsp+0x0]..[rsp+0xF0], 1 */
    0xc4, 0xe3, 0x7d, 0x39, 0x04, 0x24, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x4c, 0x24, 0x10, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x54, 0x24, 0x20, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x5c, 0x24, 0x30, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x64, 0x24, 0x40, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x6c, 0x24, 0x50, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x74, 0x24, 0x60, 0x01,
    0xc4, 0xe3, 0x7d, 0x39, 0x7c, 0x24, 0x70, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0x8c, 0x24, 0x90, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0x94, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0x9c, 0x24, 0xb0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0xa4, 0x24, 0xc0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0xac, 0x24, 0xd0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0xb4, 0x24, 0xe0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x7d, 0x39, 0xbc, 0x24, 0xf0, 0x00, 0x00, 0x00, 0x01
#else
    /* vextracti128 ymm0..ymm7, [esp+0x0]..[esp+0x70], 1 */
    0xc4, 0xc3, 0x7d, 0x39, 0x04, 0x24, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x4c, 0x24, 0x10, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x54, 0x24, 0x20, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x5c, 0x24, 0x30, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x64, 0x24, 0x40, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x6c, 0x24, 0x50, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x74, 0x24, 0x60, 0x01,
    0xc4, 0xc3, 0x7d, 0x39, 0x7c, 0x24, 0x70, 0x01
#endif
  };

  gum_x86_writer_put_pushfx (cw);
  gum_x86_writer_put_cld (cw); /* C ABI mandates this */

  if (type == GUM_PROLOG_MINIMAL)
  {
    gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);

    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XAX, GUM_X86_XSP,
        3 * sizeof (gpointer) + GUM_RED_ZONE_SIZE);
    gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (&ctx->app_stack),
        GUM_X86_XAX);

    gum_x86_writer_put_push_reg (cw, GUM_X86_XCX);
    gum_x86_writer_put_push_reg (cw, GUM_X86_XDX);
    gum_x86_writer_put_push_reg (cw, GUM_X86_XBX);

#if GLIB_SIZEOF_VOID_P == 8
    gum_x86_writer_put_push_reg (cw, GUM_X86_XSI);
    gum_x86_writer_put_push_reg (cw, GUM_X86_XDI);
    gum_x86_writer_put_push_reg (cw, GUM_X86_R8);
    gum_x86_writer_put_push_reg (cw, GUM_X86_R9);
    gum_x86_writer_put_push_reg (cw, GUM_X86_R10);
    gum_x86_writer_put_push_reg (cw, GUM_X86_R11);
#endif
  }
  else /* GUM_PROLOG_FULL */
  {
    gum_x86_writer_put_pushax (cw); /* All of GumCpuContext except for xip */
    /* GumCpuContext.xip gets filled out later */
    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
        -(gssize) sizeof (gpointer));

    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XAX, GUM_X86_XSP,
        sizeof (GumCpuContext) + 2 * sizeof (gpointer) + GUM_RED_ZONE_SIZE);
    gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (&ctx->app_stack),
        GUM_X86_XAX);

    gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
        GUM_X86_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
        GUM_X86_XAX);
  }

  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XBX, GUM_X86_XSP);
  gum_x86_writer_put_and_reg_u32 (cw, GUM_X86_XSP, (guint32) ~(16 - 1));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_XSP, 512);
  gum_x86_writer_put_bytes (cw, fxsave, sizeof (fxsave));

  if ((ctx->stalker->cpu_features & GUM_CPU_AVX2) != 0)
  {
    gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_XSP, 0x100);
    gum_x86_writer_put_bytes (cw, upper_ymm_saver, sizeof (upper_ymm_saver));
  }

  /* Jump to our caller but leave it on the stack */
  gum_x86_writer_put_jmp_reg_offset_ptr (cw,
      GUM_X86_XBX, (type == GUM_PROLOG_MINIMAL)
          ? GUM_MINIMAL_PROLOG_RETURN_OFFSET
          : GUM_FULL_PROLOG_RETURN_OFFSET);
}

static void
gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumX86Writer * cw)
{
  guint8 fxrstor[] = {
    0x0f, 0xae, 0x0c, 0x24 /* fxrstor [esp] */
  };
  guint8 upper_ymm_restorer[] = {
#if GLIB_SIZEOF_VOID_P == 8
    /* vinserti128 ymm0..ymm15, ymm0..ymm15, [rsp+0x0]..[rsp+0xF0], 1 */
    0xc4, 0xe3, 0x7d, 0x38, 0x04, 0x24, 0x01,
    0xc4, 0xe3, 0x75, 0x38, 0x4c, 0x24, 0x10, 0x01,
    0xc4, 0xe3, 0x6d, 0x38, 0x54, 0x24, 0x20, 0x01,
    0xc4, 0xe3, 0x65, 0x38, 0x5c, 0x24, 0x30, 0x01,
    0xc4, 0xe3, 0x5d, 0x38, 0x64, 0x24, 0x40, 0x01,
    0xc4, 0xe3, 0x55, 0x38, 0x6c, 0x24, 0x50, 0x01,
    0xc4, 0xe3, 0x4d, 0x38, 0x74, 0x24, 0x60, 0x01,
    0xc4, 0xe3, 0x45, 0x38, 0x7c, 0x24, 0x70, 0x01,
    0xc4, 0x63, 0x3d, 0x38, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x35, 0x38, 0x8c, 0x24, 0x90, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x2d, 0x38, 0x94, 0x24, 0xa0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x25, 0x38, 0x9c, 0x24, 0xb0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x1d, 0x38, 0xa4, 0x24, 0xc0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x15, 0x38, 0xac, 0x24, 0xd0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x0d, 0x38, 0xb4, 0x24, 0xe0, 0x00, 0x00, 0x00, 0x01,
    0xc4, 0x63, 0x05, 0x38, 0xbc, 0x24, 0xf0, 0x00, 0x00, 0x00, 0x01
#else
    /* vinserti128 ymm0..ymm7, ymm0..ymm7, [esp+0x0]..[esp+0x70], 1 */
    0xc4, 0xc3, 0x7d, 0x38, 0x04, 0x24, 0x01,
    0xc4, 0xc3, 0x75, 0x38, 0x4c, 0x24, 0x10, 0x01,
    0xc4, 0xc3, 0x6d, 0x38, 0x54, 0x24, 0x20, 0x01,
    0xc4, 0xc3, 0x65, 0x38, 0x5c, 0x24, 0x30, 0x01,
    0xc4, 0xc3, 0x5d, 0x38, 0x64, 0x24, 0x40, 0x01,
    0xc4, 0xc3, 0x55, 0x38, 0x6c, 0x24, 0x50, 0x01,
    0xc4, 0xc3, 0x4d, 0x38, 0x74, 0x24, 0x60, 0x01,
    0xc4, 0xc3, 0x45, 0x38, 0x7c, 0x24, 0x70, 0x01
#endif
  };

  /* Store our caller in the return address created by the prolog */
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_X86_XBX, (type == GUM_PROLOG_MINIMAL)
          ? GUM_MINIMAL_PROLOG_RETURN_OFFSET
          : GUM_FULL_PROLOG_RETURN_OFFSET,
      GUM_X86_XAX);

  if ((ctx->stalker->cpu_features & GUM_CPU_AVX2) != 0)
  {
    gum_x86_writer_put_bytes (cw, upper_ymm_restorer,
        sizeof (upper_ymm_restorer));
    gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XSP, 0x100);
  }

  gum_x86_writer_put_bytes (cw, fxrstor, sizeof (fxrstor));
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XSP, GUM_X86_XBX);

  if (type == GUM_PROLOG_MINIMAL)
  {
#if GLIB_SIZEOF_VOID_P == 8
    gum_x86_writer_put_pop_reg (cw, GUM_X86_R11);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_R10);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_R9);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_R8);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_XDI);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_XSI);
#endif

    gum_x86_writer_put_pop_reg (cw, GUM_X86_XBX);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_XDX);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_XCX);
    gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);
  }
  else /* GUM_PROLOG_FULL */
  {
    gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX); /* Discard
                                                     GumCpuContext.xip */
    gum_x86_writer_put_popax (cw);
  }

  gum_x86_writer_put_popfx (cw);
  gum_x86_writer_put_ret (cw);
}

static void
gum_exec_ctx_write_invalidator (GumExecCtx * ctx,
                                GumX86Writer * cw)
{
  /* Swap XDI and the top-of-stack return address */
  gum_x86_writer_put_xchg_reg_reg_ptr (cw, GUM_X86_XDI, GUM_X86_XSP);

  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw,
      GUM_CALL_CAPI, GUM_ADDRESS (gum_exec_ctx_recompile_and_switch_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, GUM_X86_XDI);

  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_x86_writer_put_pop_reg (cw, GUM_X86_XDI);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
      GUM_RED_ZONE_SIZE);

  gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (&ctx->resume_at));
}

static void
gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
                                      gpointer * helper_ptr,
                                      GumExecHelperWriteFunc write)
{
  GumSlab * slab = &ctx->code_slab->slab;
  GumX86Writer * cw = &ctx->code_writer;
  gpointer start;

  if (gum_exec_ctx_is_helper_reachable (ctx, helper_ptr))
    return;

  start = gum_slab_cursor (slab);
  gum_stalker_thaw (ctx->stalker, start, gum_slab_available (slab));
  gum_x86_writer_reset (cw, start);
  *helper_ptr = gum_x86_writer_cur (cw);

  write (ctx, cw);

  gum_x86_writer_flush (cw);
  gum_stalker_freeze (ctx->stalker, cw->base, gum_x86_writer_offset (cw));

  gum_slab_reserve (slab, gum_x86_writer_offset (cw));
}

static gboolean
gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
                                  gpointer * helper_ptr)
{
  GumSlab * slab = &ctx->code_slab->slab;
  GumAddress helper, start, end;

  helper = GUM_ADDRESS (*helper_ptr);
  if (helper == 0)
    return FALSE;

  start = GUM_ADDRESS (gum_slab_start (slab));
  end = GUM_ADDRESS (gum_slab_end (slab));

  if (!gum_x86_writer_can_branch_directly_between (start, helper))
    return FALSE;

  return gum_x86_writer_can_branch_directly_between (end, helper);
}

static void
gum_exec_ctx_get_branch_target_address (GumExecCtx * ctx,
                                        const GumBranchTarget * target,
                                        GumGeneratorContext * gc,
                                        GumX86Writer * cw)
{
  if (!target->is_indirect)
  {
    if (target->base == X86_REG_INVALID)
    {
      gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
          GUM_ADDRESS (target->absolute_address));
    }
    else
    {
      gum_exec_ctx_load_real_register_into (ctx, GUM_X86_XAX,
          gum_x86_reg_from_capstone (target->base), target->origin_ip, gc, cw);
    }
  }
  else if (target->base == X86_REG_INVALID && target->index == X86_REG_INVALID)
  {
    g_assert (target->scale == 1);
    g_assert (target->absolute_address != NULL);
    g_assert (target->relative_offset == 0);

#if GLIB_SIZEOF_VOID_P == 8
    gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
        GUM_ADDRESS (target->absolute_address));
    gum_write_segment_prefix (target->pfx_seg, cw);
    gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_RAX, GUM_X86_RAX);
#else
    gum_write_segment_prefix (target->pfx_seg, cw);
    gum_x86_writer_put_u8 (cw, 0xa1);
    gum_x86_writer_put_bytes (cw, (guint8 *) &target->absolute_address,
        sizeof (target->absolute_address));
#endif
  }
  else
  {
    gum_x86_writer_put_push_reg (cw, GUM_X86_XDX);

    gum_exec_ctx_load_real_register_into (ctx, GUM_X86_XAX,
        gum_x86_reg_from_capstone (target->base), target->origin_ip, gc, cw);
    gum_exec_ctx_load_real_register_into (ctx, GUM_X86_XDX,
        gum_x86_reg_from_capstone (target->index), target->origin_ip, gc, cw);
    gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr (cw, GUM_X86_XAX,
        GUM_X86_XAX, GUM_X86_XDX, target->scale,
        target->relative_offset);

    gum_x86_writer_put_pop_reg (cw, GUM_X86_XDX);
  }
}

static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      GumX86Reg target_register,
                                      GumX86Reg source_register,
                                      gpointer ip,
                                      GumGeneratorContext * gc,
                                      GumX86Writer * cw)
{
  switch (gc->opened_prolog)
  {
    case GUM_PROLOG_MINIMAL:
      gum_exec_ctx_load_real_register_from_minimal_frame_into (ctx,
          target_register, source_register, ip, gc, cw);
      break;
    case GUM_PROLOG_FULL:
      gum_exec_ctx_load_real_register_from_full_frame_into (ctx,
          target_register, source_register, ip, gc, cw);
      break;
    case GUM_PROLOG_IC:
      gum_exec_ctx_load_real_register_from_ic_frame_into (ctx, target_register,
          source_register, ip, gc, cw);
      break;
    default:
      g_assert_not_reached ();
      break;
  }
}

static void
gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx,
    GumX86Reg target_register,
    GumX86Reg source_register,
    gpointer ip,
    GumGeneratorContext * gc,
    GumX86Writer * cw)
{
  GumX86Reg source_meta;

  source_meta = gum_x86_meta_reg_from_real_reg (source_register);

  if (source_meta >= GUM_X86_XAX && source_meta <= GUM_X86_XBX)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, target_register,
        GUM_X86_XBX,
        GUM_STATE_PRESERVE_TOPMOST_REGISTER_INDEX * sizeof (gpointer) -
        ((source_meta - GUM_X86_XAX) * sizeof (gpointer)));
  }
#if GLIB_SIZEOF_VOID_P == 8
  else if (source_meta >= GUM_X86_XSI && source_meta <= GUM_X86_XDI)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, target_register,
        GUM_X86_XBX,
        GUM_STATE_PRESERVE_TOPMOST_REGISTER_INDEX * sizeof (gpointer) -
        ((source_meta - 2 - GUM_X86_XAX) * sizeof (gpointer)));
  }
  else if (source_meta >= GUM_X86_R8 && source_meta <= GUM_X86_R11)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, target_register,
        GUM_X86_XBX,
        GUM_STATE_PRESERVE_TOPMOST_REGISTER_INDEX * sizeof (gpointer) -
        ((source_meta - 2 - GUM_X86_RAX) * sizeof (gpointer)));
  }
#endif
  else if (source_meta == GUM_X86_XSP)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cw, target_register,
        GUM_ADDRESS (&ctx->app_stack));
  }
  else if (source_meta == GUM_X86_XIP)
  {
    gum_x86_writer_put_mov_reg_address (cw, target_register, GUM_ADDRESS (ip));
  }
  else if (source_meta == GUM_X86_NONE)
  {
    gum_x86_writer_put_xor_reg_reg (cw, target_register, target_register);
  }
  else
  {
    gum_x86_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static void
gum_exec_ctx_load_real_register_from_full_frame_into (GumExecCtx * ctx,
                                                      GumX86Reg target_register,
                                                      GumX86Reg source_register,
                                                      gpointer ip,
                                                      GumGeneratorContext * gc,
                                                      GumX86Writer * cw)
{
  GumX86Reg source_meta;

  source_meta = gum_x86_meta_reg_from_real_reg (source_register);

  if (source_meta >= GUM_X86_XAX && source_meta <= GUM_X86_XBX)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, target_register,
        GUM_X86_XBX, sizeof (GumCpuContext) -
        ((source_meta - GUM_X86_XAX + 1) * sizeof (gpointer)));
  }
  else if (source_meta >= GUM_X86_XBP && source_meta <= GUM_X86_XDI)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, target_register,
        GUM_X86_XBX, sizeof (GumCpuContext) -
        ((source_meta - GUM_X86_XAX + 1) * sizeof (gpointer)));
  }
#if GLIB_SIZEOF_VOID_P == 8
  else if (source_meta >= GUM_X86_R8 && source_meta <= GUM_X86_R15)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, target_register,
        GUM_X86_XBX, sizeof (GumCpuContext) -
        ((source_meta - GUM_X86_RAX + 1) * sizeof (gpointer)));
  }
#endif
  else if (source_meta == GUM_X86_XSP)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cw, target_register,
        GUM_ADDRESS (&ctx->app_stack));
  }
  else if (source_meta == GUM_X86_XIP)
  {
    gum_x86_writer_put_mov_reg_address (cw, target_register, GUM_ADDRESS (ip));
  }
  else if (source_meta == GUM_X86_NONE)
  {
    gum_x86_writer_put_xor_reg_reg (cw, target_register, target_register);
  }
  else
  {
    gum_x86_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static void
gum_exec_ctx_load_real_register_from_ic_frame_into (GumExecCtx * ctx,
                                                    GumX86Reg target_register,
                                                    GumX86Reg source_register,
                                                    gpointer ip,
                                                    GumGeneratorContext * gc,
                                                    GumX86Writer * cw)
{
  GumX86Reg source_meta;

  source_meta = gum_x86_meta_reg_from_real_reg (source_register);

  if (source_meta == GUM_X86_XAX)
  {
    gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, target_register, GUM_X86_XBX,
        2 * sizeof (gpointer));
  }
  else if (source_meta == GUM_X86_XBX)
  {
    gum_x86_writer_put_mov_reg_reg_ptr (cw, target_register, GUM_X86_XBX);
  }
  else if (source_meta == GUM_X86_XSP)
  {
    gum_x86_writer_put_mov_reg_near_ptr (cw, target_register,
        GUM_ADDRESS (&ctx->app_stack));
  }
  else if (source_meta == GUM_X86_XIP)
  {
    gum_x86_writer_put_mov_reg_address (cw, target_register, GUM_ADDRESS (ip));
  }
  else if (source_meta == GUM_X86_NONE)
  {
    gum_x86_writer_put_xor_reg_reg (cw, target_register, target_register);
  }
  else
  {
    gum_x86_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  GumExecBlock * block;
  GumStalker * stalker = ctx->stalker;
  GumCodeSlab * code_slab = ctx->code_slab;
  GumSlowSlab * slow_slab = ctx->slow_slab;
  GumDataSlab * data_slab = ctx->data_slab;
  gsize code_available, slow_available, data_available;

  /*
   * Whilst we don't write the inline cache entry into the code slab any more,
   * we do write an unrolled loop which walks the table looking for the right
   * entry, so we need to ensure we have some extra space for that anyway.
   */
  code_available = gum_slab_available (&code_slab->slab);
  if (code_available < GUM_EXEC_BLOCK_MIN_CAPACITY +
      gum_stalker_get_ic_entry_size (ctx->stalker))
  {
    GumAddressSpec data_spec;

    code_slab = gum_exec_ctx_add_code_slab (ctx, gum_code_slab_new (ctx));

    gum_exec_ctx_compute_data_address_spec (ctx, data_slab->slab.size,
        &data_spec);
    if (!gum_address_spec_is_satisfied_by (&data_spec,
            gum_slab_start (&data_slab->slab)))
    {
      data_slab = gum_exec_ctx_add_data_slab (ctx, gum_data_slab_new (ctx));
    }

    gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

    code_available = gum_slab_available (&code_slab->slab);
  }

  slow_available = gum_slab_available (&slow_slab->slab);
  if (slow_available < GUM_EXEC_BLOCK_MIN_CAPACITY)
  {
    GumAddressSpec data_spec;

    slow_slab = gum_exec_ctx_add_slow_slab (ctx, gum_slow_slab_new (ctx));

    gum_exec_ctx_compute_data_address_spec (ctx, data_slab->slab.size,
        &data_spec);
    if (!gum_address_spec_is_satisfied_by (&data_spec,
          gum_slab_start (&data_slab->slab)))
    {
      data_slab = gum_exec_ctx_add_data_slab (ctx, gum_data_slab_new (ctx));
    }

    slow_available = gum_slab_available (&code_slab->slab);
  }

  data_available = gum_slab_available (&data_slab->slab);
  if (data_available < GUM_DATA_BLOCK_MIN_CAPACITY +
      gum_stalker_get_ic_entry_size (ctx->stalker))
  {
    data_slab = gum_exec_ctx_add_data_slab (ctx, gum_data_slab_new (ctx));
  }

  block = gum_slab_reserve (&data_slab->slab, sizeof (GumExecBlock));

  block->next = ctx->block_list;
  ctx->block_list = block;

  block->ctx = ctx;
  block->code_slab = code_slab;
  block->slow_slab = slow_slab;

  block->code_start = gum_slab_cursor (&code_slab->slab);
  block->slow_start = gum_slab_cursor (&slow_slab->slab);

  gum_stalker_thaw (stalker, block->code_start, code_available);
  gum_stalker_thaw (stalker, block->slow_start, slow_available);

  return block;
}

static void
gum_exec_block_clear (GumExecBlock * block)
{
  GumCalloutEntry * entry;

  for (entry = gum_exec_block_get_last_callout_entry (block);
      entry != NULL;
      entry = entry->next)
  {
    if (entry->data_destroy != NULL)
      entry->data_destroy (entry->data);
  }
  block->last_callout_offset = 0;

  block->storage_block = NULL;
}

static void
gum_exec_block_commit (GumExecBlock * block)
{
  GumStalker * stalker = block->ctx->stalker;
  gsize snapshot_size;

  snapshot_size =
      gum_stalker_snapshot_space_needed_for (stalker, block->real_size);
  memcpy (gum_exec_block_get_snapshot_start (block), block->real_start,
      snapshot_size);

  block->capacity = block->code_size + snapshot_size;

  gum_slab_reserve (&block->code_slab->slab, block->capacity);
  gum_stalker_freeze (stalker, block->code_start, block->code_size);

  gum_slab_reserve (&block->slow_slab->slab, block->slow_size);
  gum_stalker_freeze (stalker, block->slow_start, block->slow_size);
}

static void
gum_exec_block_invalidate (GumExecBlock * block)
{
  GumExecCtx * ctx = block->ctx;
  GumStalker * stalker = ctx->stalker;
  GumX86Writer * cw = &ctx->code_writer;
  const gsize max_size = GUM_INVALIDATE_TRAMPOLINE_SIZE;
  gint32 distance_to_data;

  gum_stalker_thaw (stalker, block->code_start, max_size);
  gum_x86_writer_reset (cw, block->code_start);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
      -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_call_address (cw,
      GUM_ADDRESS (block->code_slab->invalidator));
  distance_to_data = (guint8 *) block - (guint8 *) GSIZE_TO_POINTER (cw->pc);
  gum_x86_writer_put_bytes (cw, (const guint8 *) &distance_to_data,
      sizeof (distance_to_data));

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) == GUM_INVALIDATE_TRAMPOLINE_SIZE);
  gum_stalker_freeze (stalker, block->code_start, max_size);
}

static gpointer
gum_exec_block_get_snapshot_start (GumExecBlock * block)
{
  return block->code_start + block->code_size;
}

static GumCalloutEntry *
gum_exec_block_get_last_callout_entry (const GumExecBlock * block)
{
  const guint last_callout_offset = block->last_callout_offset;

  if (last_callout_offset == 0)
    return NULL;

  return (GumCalloutEntry *) (block->code_start + last_callout_offset);
}

static void
gum_exec_block_set_last_callout_entry (GumExecBlock * block,
                                       GumCalloutEntry * entry)
{
  block->last_callout_offset = (guint8 *) entry - block->code_start;
}

static void
gum_exec_block_backpatch_call (GumExecBlock * block,
                               GumExecBlock * from,
                               gpointer from_insn,
                               gsize code_offset,
                               GumPrologType opened_prolog,
                               gpointer ret_real_address,
                               gsize ret_code_offset)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  gpointer target;
  guint8 * code_start = from->code_start + code_offset;
  const gsize code_max_size = from->code_size - code_offset;
  GumX86Writer * cw;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  if (!gum_exec_ctx_may_now_backpatch (ctx, block))
    return;

  target = block->code_start;
  gum_exec_ctx_query_block_switch_callback (ctx, block, block->real_start,
      from_insn, &target);

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (ctx->stalker, code_start, code_max_size);

  cw = &ctx->code_writer;
  gum_x86_writer_reset (cw, code_start);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
      -(gssize) sizeof (gpointer));
  gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
      GUM_ADDRESS (ret_real_address));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XSP, sizeof (gpointer),
      GUM_X86_XAX);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);

  gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (target));

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= code_max_size);
  gum_stalker_freeze (ctx->stalker, code_start, code_max_size);

  gum_spinlock_release (&ctx->code_lock);

  if (ctx->observer != NULL)
  {
    GumBackpatch p;

    p.type = GUM_BACKPATCH_CALL;
    p.to = block->real_start;
    p.from = from->real_start;
    p.from_insn = from_insn;
    p.call.code_offset = code_offset;
    p.call.opened_prolog = opened_prolog;
    p.call.ret_real_address = ret_real_address;
    p.call.ret_code_offset = ret_code_offset;

    gum_stalker_observer_notify_backpatch (ctx->observer, &p, sizeof (p));
  }
}

static void
gum_exec_block_backpatch_jmp (GumExecBlock * block,
                              GumExecBlock * from,
                              gpointer from_insn,
                              guint id,
                              gsize code_offset,
                              GumPrologType opened_prolog)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  gboolean is_eob;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  if (!gum_exec_ctx_may_now_backpatch (ctx, block))
    return;

  is_eob = gum_exec_block_get_eob (from_insn, id);

  switch (id)
  {
    case X86_INS_JMP:
      gum_exec_block_backpatch_unconditional_jmp (block, from, from_insn,
          is_eob, code_offset, opened_prolog);
      break;

    default:
      gum_exec_block_backpatch_conditional_jmp (block, from, from_insn, id,
          code_offset, opened_prolog);
      break;
  }

  if (ctx->observer != NULL)
  {
    GumBackpatch p;

    p.type = GUM_BACKPATCH_JMP;
    p.to = block->real_start;
    p.from = from->real_start;
    p.from_insn = from_insn;
    p.jmp.id = id;
    p.jmp.code_offset = code_offset;
    p.jmp.opened_prolog = opened_prolog;

    gum_stalker_observer_notify_backpatch (ctx->observer, &p, sizeof (p));
  }
}

/*
 * This function uses the instruction which is being virtualized (from_insn) and
 * the instruction being generated in its place (id) to determine whether the
 * backpatch for such a pairing will occur at the end of the instrumented block.
 * (E.g. in the case of emulating a Jcc instruction, the resulting instrumented
 * block will contain two different locations in need of backpatching to
 * re-direct control flow depending on whether or not the branch is taken).
 * If this backpatching is occurring at the end of the block and the target
 * instrumented block is immediately adjacent then a NOP slide may be used in
 * place of a branch instruction.
 */
static gboolean
gum_exec_block_get_eob (gpointer from_insn,
                        guint id)
{
  gboolean eob = FALSE;
  cs_insn * ci = NULL;

  /*
   * If we have no instruction, then this means we are handling a block
   * continuation (e.g. an input block split into two instrumented blocks
   * because of its size), for these the backpatch is at the end of the
   * block.
   */
  if (from_insn == NULL)
  {
    eob = TRUE;
    goto beach;
  }

  /*
   * The backpatch location for non-conditional JMP and CALL instructions is
   * at the end of the block.
   */
  ci = gum_x86_reader_disassemble_instruction_at (from_insn);
  if (ci->id == X86_INS_JMP || ci->id == X86_INS_CALL)
  {
    eob = TRUE;
    goto beach;
  }

  /*
   * If we encounter a Jcc instruction then we emit instrumented code as
   * follows:
   *
   *   Jcc taken
   * not_taken:
   *   ...
   *   code to handle not taken branch
   * taken:
   *   ...
   *   code to handle taken branch
   *
   * If we are backpatching the `code to handle not taken branch` then this is
   * replaced with a JMP instruction (hence the id field won't match). In this
   * case as we can see above, our backpatch target is not at the end of the
   * block and therefore cannot be replaced with NOPs.
   */
  if (ci->id == id)
  {
    eob = TRUE;
    goto beach;
  }

beach:
  if (ci != NULL)
    cs_free (ci, 1);

  return eob;
}

static void
gum_exec_block_backpatch_conditional_jmp (GumExecBlock * block,
                                          GumExecBlock * from,
                                          gpointer from_insn,
                                          guint id,
                                          gsize code_offset,
                                          GumPrologType opened_prolog)
{
  GumExecCtx * ctx = block->ctx;
  guint8 * code_start = from->code_start + code_offset;
  const gsize code_max_size = from->code_size - code_offset;
  GumX86Writer * cw = &ctx->code_writer;
  gpointer target_taken = block->code_start;
  GumExecBlock * next_block;

  /*
   * If we encounter a Jcc instruction then we emit instrumented code as
   * follows:
   *
   *   Jcc taken
   * not_taken:
   *   ...
   *   code to handle not taken branch
   * taken:
   *   ...
   *   code to handle taken branch
   *
   * When we backpatch this code, we want to reduce the number of branches taken
   * to an absolute minimum. When we backpatch the not_taken branch we simply
   * replace the `code to handle not taken branch` with a JMP instruction to the
   * required block. We cannot use a NOP slide even if the target block is
   * adjacent since our backpatch is not at the end of our block and we would
   * end up overwriting the `code to handle taken branch`.
   *
   * If we execute the taken branch of the JMPcc, instead of backpatching
   * `code to handle taken branch`, we instead apply our backpatch to overwrite
   * the original Jcc instruction to take control flow direct to the
   * instrumented block and hence avoid taking two branches in quick succession.
   * This also means that since the `code to handle taken branch` is no longer
```