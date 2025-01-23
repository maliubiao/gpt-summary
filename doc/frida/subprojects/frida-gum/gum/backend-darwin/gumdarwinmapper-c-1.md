Response:
The user wants a summary of the functionality of the provided C code, which is part of the Frida dynamic instrumentation tool. I need to identify the key actions and purpose of the code, relating it to reverse engineering, low-level details, and potential user errors.

**Plan:**

1. **High-Level Overview:** Understand the overall goal of `gumdarwinmapper.c`. It seems to be responsible for mapping and preparing code for execution within a target process on Darwin (macOS/iOS).
2. **Function Breakdown:** Analyze the provided functions:
    *   `darwin_mapper_make_code_address`: Likely handles code signing on Darwin.
    *   `gum_darwin_mapper_alloc_and_emit_runtime`:  The core function, seemingly responsible for allocating memory and emitting runtime code. This involves setting up string vectors, handling chained fixups, symbols, and Thread Local Storage (TLS).
    *   `gum_emit_runtime` (and its architecture-specific variants like `gum_emit_x86_runtime`, `gum_emit_arm_runtime`, `gum_emit_arm64_runtime`):  Generates the actual machine code for constructors, destructors, resolving symbols, and calling initialization/termination routines.
    *   Helper functions like `gum_emit_child_constructor_call`, `gum_emit_child_destructor_call`, `gum_emit_chained_fixup_call`, `gum_emit_resolve_if_needed`, `gum_emit_init_calls`, `gum_emit_term_calls`, and `gum_emit_tlv_init_code`.
3. **Relate to Reverse Engineering:** Identify how these functions facilitate dynamic instrumentation, a key technique in reverse engineering.
4. **Identify Low-Level Details:** Point out the interactions with memory management, CPU architectures (x86, ARM), and OS-specific features (like TLS).
5. **Look for Logic and Assumptions:** Analyze how the code manipulates data and makes assumptions about the target environment.
6. **Consider User Errors:** Think about common mistakes a user might make that could lead to issues in this part of Frida.
7. **Trace User Actions:**  Imagine the steps a user would take to trigger this code.
8. **Summarize Functionality:** Concisely describe the main purpose of the code based on the analysis.
```c
arwin_mapper_make_code_address (GumDarwinMapper * self,
                                     GumAddress value)
{
  GumAddress result = value;

  if (self->resolver->ptrauth_support == GUM_PTRAUTH_SUPPORTED)
    result = gum_sign_code_address (result);

  return result;
}

static void
gum_darwin_mapper_alloc_and_emit_runtime (GumDarwinMapper * self,
                                          GumAddress base_address,
                                          gsize size)
{
  GPtrArray * params = self->apple_parameters;
  gsize header_size = self->runtime_header_size;
  gsize pointer_size = self->module->pointer_size;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  gpointer runtime;
  guint strv_length, strv_size;
  gint * strv_offsets;
  GString * strv_blob;
  guint i;
  gpointer cursor;
  GumAddress pc, alignment_offset;
  gsize code_size;

  runtime = g_malloc0 (self->runtime_file_size);

  strv_length = 1 + params->len;
  strv_size = (strv_length + 1) * pointer_size;
  strv_offsets = g_newa (gint, strv_length);
  strv_blob = g_string_new ("");

  strv_offsets[0] = 0;
  g_string_append_printf (strv_blob,
      "frida_dylib_range=0x%" G_GINT64_MODIFIER "x,0x%" G_GSIZE_MODIFIER "x",
      base_address, size);

  for (i = 0; i != params->len; i++)
  {
    g_string_append_c (strv_blob, '\0');

    strv_offsets[1 + i] = strv_blob->len;
    g_string_append (strv_blob, g_ptr_array_index (params, i));
  }

  cursor = runtime;
  pc = base_address;

#define GUM_ADVANCE_BY(n) \
    G_STMT_START \
    { \
      cursor += n; \
      pc += n; \
    } \
    G_STMT_END

  self->apple_strv = pc;

  for (i = 0; i != strv_length; i++)
  {
    gint offset = strv_offsets[i];
    GumAddress str_address;

    str_address = base_address + strv_size + offset;

    if (pointer_size == 4)
      *((guint32 *) cursor) = str_address;
    else
      *((guint64 *) cursor) = str_address;

    GUM_ADVANCE_BY (pointer_size);
  }

  /* String vector terminator goes here. */
  self->empty_strv = pc;
  GUM_ADVANCE_BY (pointer_size);

  memcpy (cursor, strv_blob->str, strv_blob->len);
  GUM_ADVANCE_BY (strv_blob->len + 1);

  g_string_free (strv_blob, TRUE);

  if (self->chained_fixups_count != 0)
  {
    alignment_offset = pc % 4;
    if (alignment_offset != 0)
      GUM_ADVANCE_BY (4 - alignment_offset);

    self->process_chained_fixups = pc;
    memcpy (cursor, gum_fixup_chain_processor_code,
        sizeof (gum_fixup_chain_processor_code));
    GUM_ADVANCE_BY (sizeof (gum_fixup_chain_processor_code));
  }
  else
  {
    self->process_chained_fixups = 0;
  }

  if (self->chained_symbols != NULL && self->chained_symbols->len != 0)
  {
    alignment_offset = pc % pointer_size;
    if (alignment_offset != 0)
      GUM_ADVANCE_BY (pointer_size - alignment_offset);

    self->chained_symbols_vector = pc;
    memcpy (cursor, self->chained_symbols->data,
        self->chained_symbols->len * pointer_size);
    GUM_ADVANCE_BY (self->chained_symbols->len * pointer_size);
  }
  else
  {
    self->chained_symbols_vector = 0;
  }

  if (tlv->num_descriptors != 0)
  {
    self->pthread_key =
        self->module->base_address + tlv->descriptors_offset + pointer_size;
  }

#undef GUM_ADVANCE_BY

  gum_emit_runtime (self, runtime + header_size,
      self->runtime_address + header_size, &code_size);
  g_assert (header_size + code_size <= self->runtime_file_size);

  g_free (self->runtime);
  self->runtime = runtime;
}

#if defined (HAVE_I386)

typedef struct _GumEmitX86Context GumEmitX86Context;

struct _GumEmitX86Context
{
  GumDarwinMapper * mapper;
  GumX86Writer * cw;
};

static void gum_emit_child_constructor_call (GumDarwinMapper * child,
    GumEmitX86Context * ctx);
static void gum_emit_child_destructor_call (GumDarwinMapper * child,
    GumEmitX86Context * ctx);
static gboolean gum_emit_chained_fixup_call (
    const GumDarwinChainedFixupsDetails * details, GumEmitX86Context * ctx);
static gboolean gum_emit_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitX86Context * ctx);
static gboolean gum_emit_init_calls (
    const GumDarwinInitPointersDetails * details, GumEmitX86Context * ctx);
static gboolean gum_emit_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitX86Context * ctx);
static void gum_emit_tlv_init_code (GumEmitX86Context * ctx);

static void
gum_emit_runtime (GumDarwinMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumDarwinModule * module = self->module;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  GumX86Writer cw;
  GumEmitX86Context ctx;
  GSList * children_reversed;

  gum_x86_writer_init (&cw, output_buffer);
  cw.pc = pc;
  gum_x86_writer_set_target_cpu (&cw, self->module->cpu_type);

  ctx.mapper = self;
  ctx.cw = &cw;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_x86_writer_put_xor_reg_reg (&cw, GUM_X86_XAX, GUM_X86_XAX);
    gum_x86_writer_put_ret (&cw);
  }

  self->constructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_XSP, self->module->pointer_size);

  g_slist_foreach (self->children, (GFunc) gum_emit_child_constructor_call,
      &ctx);
  gum_darwin_module_enumerate_chained_fixups (module,
      (GumFoundDarwinChainedFixupsFunc) gum_emit_chained_fixup_call, &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_resolve_if_needed, &ctx);

  if (tlv->num_descriptors != 0)
    gum_emit_tlv_init_code (&ctx);

  gum_darwin_module_enumerate_init_pointers (module,
      (GumFoundDarwinInitPointersFunc) gum_emit_init_calls, &ctx);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_XSP, self->module->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  self->destructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_XSP, self->module->pointer_size);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumFoundDarwinTermPointersFunc) gum_emit_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed, (GFunc) gum_emit_child_destructor_call,
      &ctx);
  g_slist_free (children_reversed);

  if (tlv->num_descriptors != 0)
  {
    gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_XCX, self->pthread_key);
    gum_x86_writer_put_mov_reg_reg_ptr (&cw, GUM_X86_XAX, GUM_X86_XCX);
    gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
        self->pthread_key_delete, 1,
        GUM_ARG_REGISTER, GUM_X86_XAX);
  }

  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_XSP, self->module->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  *size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);
}

static void
gum_emit_child_constructor_call (GumDarwinMapper * child,
                                 GumEmitX86Context * ctx)
{
  GumX86Writer * cw = ctx->cw;

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX,
      gum_darwin_mapper_constructor (child));
  gum_x86_writer_put_call_reg (cw, GUM_X86_XCX);
}

static void
gum_emit_child_destructor_call (GumDarwinMapper * child,
                                GumEmitX86Context * ctx)
{
  GumX86Writer * cw = ctx->cw;

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX,
      gum_darwin_mapper_destructor (child));
  gum_x86_writer_put_call_reg (cw, GUM_X86_XCX);
}

static gboolean
gum_emit_chained_fixup_call (const GumDarwinChainedFixupsDetails * details,
                             GumEmitX86Context * ctx)
{
  GumDarwinMapper * mapper = ctx->mapper;
  GumDarwinModule * module = mapper->module;

  gum_x86_writer_put_call_address_with_aligned_arguments (ctx->cw,
      GUM_CALL_CAPI, mapper->process_chained_fixups, 4,
      GUM_ARG_ADDRESS, details->vm_address,
      GUM_ARG_ADDRESS, module->base_address,
      GUM_ARG_ADDRESS, module->preferred_address,
      GUM_ARG_ADDRESS, mapper->chained_symbols_vector);

  return TRUE;
}

static gboolean
gum_emit_resolve_if_needed (const GumDarwinBindDetails * details,
                            GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX,
      gum_darwin_mapper_make_code_address (self, value.resolver));
  gum_x86_writer_put_call_reg (cw, GUM_X86_XCX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX, details->addend);
  gum_x86_writer_put_add_reg_reg (cw, GUM_X86_XAX, GUM_X86_XCX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX, entry);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XCX, GUM_X86_XAX);

  return TRUE;
}

static gboolean
gum_emit_init_calls (const GumDarwinInitPointersDetails * details,
                     GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBP, details->address);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX, details->count);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XBP);
  gum_x86_writer_put_call_reg_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_X86_XAX, 5,
      /*   argc */ GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      /*   argv */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv),
      /*   envp */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv),
      /*  apple */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->apple_strv),
      /* result */ GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XBP, self->module->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_X86_XBX);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, next_label, GUM_NO_HINT);

  return TRUE;
}

static gboolean
gum_emit_term_calls (const GumDarwinTermPointersDetails * details,
                     GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBP, details->address +
      ((details->count - 1) * self->module->pointer_size));
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX, details->count);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XBP);
  gum_x86_writer_put_call_reg (cw, GUM_X86_XAX);

  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_XBP, self->module->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_X86_XBX);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, next_label, GUM_NO_HINT);

  return TRUE;
}

static void
gum_emit_tlv_init_code (GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  GumDarwinModule * module = self->module;
  gsize pointer_size = module->pointer_size;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  GumAddress tlv_section = module->base_address + tlv->descriptors_offset;
  gconstpointer next_label = GSIZE_TO_POINTER (cw->code + 1);
  gconstpointer has_key_label = GSIZE_TO_POINTER (cw->code + 2);

  gum_x86_writer_put_call_address_with_arguments (cw, GUM_CALL_CAPI,
      self->pthread_key_create, 2,
      GUM_ARG_ADDRESS, self->pthread_key,
      GUM_ARG_ADDRESS, GUM_ADDRESS (0) /* destructor */);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX, self->pthread_key);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_shl_reg_u8 (cw, GUM_X86_XAX,
      (pointer_size == 8) ? 3 : 2);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX, self->tlv_area);
  gum_x86_writer_put_mov_gs_reg_ptr_reg (cw, GUM_X86_XAX, GUM_X86_XBX);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX, tlv->num_descriptors);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX, tlv_section);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX, self->tlv_get_addr_addr);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XBX, GUM_X86_XAX);

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XBX, pointer_size);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XBX);
  gum_x86_writer_put_cmp_reg_i32 (cw, GUM_X86_XAX, 0);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, has_key_label,
      GUM_NO_HINT);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX, self->pthread_key);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XBX, GUM_X86_XAX);

  gum_x86_writer_put_label (cw, has_key_label);

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XBX, 2 * pointer_size);

  gum_x86_writer_put_dec_reg (cw, GUM_X86_XCX);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, next_label, GUM_NO_HINT);
}

#elif defined (HAVE_ARM) || defined (HAVE_ARM64)

typedef struct _GumEmitArmContext GumEmitArmContext;
typedef struct _GumEmitArm64Context GumEmitArm64Context;

struct _GumEmitArmContext
{
  GumDarwinMapper * mapper;
  GumThumbWriter * tw;
};

struct _GumEmitArm64Context
{
  GumDarwinMapper * mapper;
  GumArm64Writer * aw;
};

static void gum_emit_arm_runtime (GumDarwinMapper * self,
    gpointer output_buffer, GumAddress pc, gsize * size);
static void gum_emit_arm_child_constructor_call (GumDarwinMapper * child,
    GumEmitArmContext * ctx);
static void gum_emit_arm_child_destructor_call (GumDarwinMapper * child,
    GumEmitArmContext * ctx);
static gboolean gum_emit_arm_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitArmContext * ctx);
static gboolean gum_emit_arm_init_calls (
    const GumDarwinInitPointersDetails * details, GumEmitArmContext * ctx);
static gboolean gum_emit_arm_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitArmContext * ctx);

static void gum_emit_arm64_runtime (GumDarwinMapper * self,
    gpointer output_buffer, GumAddress pc, gsize * size);
static void gum_emit_arm64_child_constructor_call (GumDarwinMapper * child,
    GumEmitArm64Context * ctx);
static void gum_emit_arm64_child_destructor_call (GumDarwinMapper * child,
    GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_chained_fixup_call (
    const GumDarwinChainedFixupsDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_init_pointer_calls (
    const GumDarwinInitPointersDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_init_offset_calls (
    const GumDarwinInitOffsetsDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitArm64Context * ctx);
static void gum_emit_arm64_tlv_init_code (GumEmitArm64Context * ctx);

static void
gum_emit_runtime (GumDarwinMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  if (self->module->cpu_type == GUM_CPU_ARM)
    gum_emit_arm_runtime (self, output_buffer, pc, size);
  else
    gum_emit_arm64_runtime (self, output_buffer, pc, size);
}

static void
gum_emit_arm_runtime (GumDarwinMapper * self,
                      gpointer output_buffer,
                      GumAddress pc,
                      gsize * size)
{
  GumDarwinModule * module = self->module;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  GumThumbWriter tw;
  GumEmitArmContext ctx;
  GSList * children_reversed;

  gum_thumb_writer_init (&tw, output_buffer);
  tw.pc = pc;

  ctx.mapper = self;
  ctx.tw = &tw;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_thumb_writer_put_ldr_reg_u32 (&tw, ARM_REG_R0, 0);
    gum_thumb_writer_put_bx_reg (&tw, ARM_REG_LR);
  }

  self->constructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);

  g_slist_foreach (self->children, (GFunc) gum_emit_arm_child_constructor_call,
      &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_init_pointers (module,
      (GumFoundDarwinInitPointersFunc) gum_emit_arm_init_calls, &ctx);

  if (tlv->num_descriptors != 0)
  {
    gum_thumb_writer_put_call_address_with_arguments (&tw,
        self->pthread_key_create, 2,
        GUM_ARG_ADDRESS, self->pthread_key,
        GUM_ARG_ADDRESS, GUM_ADDRESS (0) /* destructor */);
  }

  gum_thumb_writer_put_pop_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);

  self->destructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumFoundDarwinTermPointersFunc) gum_emit_arm_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed,
      (GFunc) gum_emit_arm_child_destructor_call, &ctx);
  g_slist_free (children_reversed);

  if (tlv->num_descriptors != 0)
  {
    gum_thumb_writer_put_ldr_reg_address (&tw, ARM_REG_R4, self->pthread_key);
    gum_thumb_writer_put_ldr_reg_reg (&tw, ARM_REG_R4, ARM_REG_R4);

    gum_thumb_writer_put_call_address_with_arguments (&tw,
        self->pthread_key_delete, 1,
        GUM_ARG_REGISTER, ARM_REG_R4);
  }

  gum_thumb_writer_put_pop_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);

  gum_thumb_writer_flush (&tw);
  *size = gum_thumb_writer_offset (&tw);
  gum_thumb_writer_clear (&tw);
}

static void
gum_emit_arm_child_constructor_call (GumDarwinMapper * child,
                                     GumEmitArmContext * ctx)
{
  GumThumbWriter * tw = ctx->tw;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
      gum_darwin_mapper_constructor (child));
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);
}

static void
gum_emit_arm_child_destructor_call (GumDarwinMapper * child,
                                    GumEmitArmContext * ctx)
{
  GumThumbWriter * tw = ctx->tw;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
      gum_darwin_mapper_destructor (child));
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);
}

static gboolean
gum_emit_arm_resolve_if_needed (const GumDarwinBindDetails * details,
                                GumEmitArmContext * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumThumbWriter * tw = ctx->tw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry =
### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumdarwinmapper.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
arwin_mapper_make_code_address (GumDarwinMapper * self,
                                     GumAddress value)
{
  GumAddress result = value;

  if (self->resolver->ptrauth_support == GUM_PTRAUTH_SUPPORTED)
    result = gum_sign_code_address (result);

  return result;
}

static void
gum_darwin_mapper_alloc_and_emit_runtime (GumDarwinMapper * self,
                                          GumAddress base_address,
                                          gsize size)
{
  GPtrArray * params = self->apple_parameters;
  gsize header_size = self->runtime_header_size;
  gsize pointer_size = self->module->pointer_size;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  gpointer runtime;
  guint strv_length, strv_size;
  gint * strv_offsets;
  GString * strv_blob;
  guint i;
  gpointer cursor;
  GumAddress pc, alignment_offset;
  gsize code_size;

  runtime = g_malloc0 (self->runtime_file_size);

  strv_length = 1 + params->len;
  strv_size = (strv_length + 1) * pointer_size;
  strv_offsets = g_newa (gint, strv_length);
  strv_blob = g_string_new ("");

  strv_offsets[0] = 0;
  g_string_append_printf (strv_blob,
      "frida_dylib_range=0x%" G_GINT64_MODIFIER "x,0x%" G_GSIZE_MODIFIER "x",
      base_address, size);

  for (i = 0; i != params->len; i++)
  {
    g_string_append_c (strv_blob, '\0');

    strv_offsets[1 + i] = strv_blob->len;
    g_string_append (strv_blob, g_ptr_array_index (params, i));
  }

  cursor = runtime;
  pc = base_address;

#define GUM_ADVANCE_BY(n) \
    G_STMT_START \
    { \
      cursor += n; \
      pc += n; \
    } \
    G_STMT_END

  self->apple_strv = pc;

  for (i = 0; i != strv_length; i++)
  {
    gint offset = strv_offsets[i];
    GumAddress str_address;

    str_address = base_address + strv_size + offset;

    if (pointer_size == 4)
      *((guint32 *) cursor) = str_address;
    else
      *((guint64 *) cursor) = str_address;

    GUM_ADVANCE_BY (pointer_size);
  }

  /* String vector terminator goes here. */
  self->empty_strv = pc;
  GUM_ADVANCE_BY (pointer_size);

  memcpy (cursor, strv_blob->str, strv_blob->len);
  GUM_ADVANCE_BY (strv_blob->len + 1);

  g_string_free (strv_blob, TRUE);

  if (self->chained_fixups_count != 0)
  {
    alignment_offset = pc % 4;
    if (alignment_offset != 0)
      GUM_ADVANCE_BY (4 - alignment_offset);

    self->process_chained_fixups = pc;
    memcpy (cursor, gum_fixup_chain_processor_code,
        sizeof (gum_fixup_chain_processor_code));
    GUM_ADVANCE_BY (sizeof (gum_fixup_chain_processor_code));
  }
  else
  {
    self->process_chained_fixups = 0;
  }

  if (self->chained_symbols != NULL && self->chained_symbols->len != 0)
  {
    alignment_offset = pc % pointer_size;
    if (alignment_offset != 0)
      GUM_ADVANCE_BY (pointer_size - alignment_offset);

    self->chained_symbols_vector = pc;
    memcpy (cursor, self->chained_symbols->data,
        self->chained_symbols->len * pointer_size);
    GUM_ADVANCE_BY (self->chained_symbols->len * pointer_size);
  }
  else
  {
    self->chained_symbols_vector = 0;
  }

  if (tlv->num_descriptors != 0)
  {
    self->pthread_key =
        self->module->base_address + tlv->descriptors_offset + pointer_size;
  }

#undef GUM_ADVANCE_BY

  gum_emit_runtime (self, runtime + header_size,
      self->runtime_address + header_size, &code_size);
  g_assert (header_size + code_size <= self->runtime_file_size);

  g_free (self->runtime);
  self->runtime = runtime;
}

#if defined (HAVE_I386)

typedef struct _GumEmitX86Context GumEmitX86Context;

struct _GumEmitX86Context
{
  GumDarwinMapper * mapper;
  GumX86Writer * cw;
};

static void gum_emit_child_constructor_call (GumDarwinMapper * child,
    GumEmitX86Context * ctx);
static void gum_emit_child_destructor_call (GumDarwinMapper * child,
    GumEmitX86Context * ctx);
static gboolean gum_emit_chained_fixup_call (
    const GumDarwinChainedFixupsDetails * details, GumEmitX86Context * ctx);
static gboolean gum_emit_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitX86Context * ctx);
static gboolean gum_emit_init_calls (
    const GumDarwinInitPointersDetails * details, GumEmitX86Context * ctx);
static gboolean gum_emit_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitX86Context * ctx);
static void gum_emit_tlv_init_code (GumEmitX86Context * ctx);

static void
gum_emit_runtime (GumDarwinMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  GumDarwinModule * module = self->module;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  GumX86Writer cw;
  GumEmitX86Context ctx;
  GSList * children_reversed;

  gum_x86_writer_init (&cw, output_buffer);
  cw.pc = pc;
  gum_x86_writer_set_target_cpu (&cw, self->module->cpu_type);

  ctx.mapper = self;
  ctx.cw = &cw;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_x86_writer_put_xor_reg_reg (&cw, GUM_X86_XAX, GUM_X86_XAX);
    gum_x86_writer_put_ret (&cw);
  }

  self->constructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_XSP, self->module->pointer_size);

  g_slist_foreach (self->children, (GFunc) gum_emit_child_constructor_call,
      &ctx);
  gum_darwin_module_enumerate_chained_fixups (module,
      (GumFoundDarwinChainedFixupsFunc) gum_emit_chained_fixup_call, &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_resolve_if_needed, &ctx);

  if (tlv->num_descriptors != 0)
    gum_emit_tlv_init_code (&ctx);

  gum_darwin_module_enumerate_init_pointers (module,
      (GumFoundDarwinInitPointersFunc) gum_emit_init_calls, &ctx);

  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_XSP, self->module->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  self->destructor_offset = gum_x86_writer_offset (&cw);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_XSP, self->module->pointer_size);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumFoundDarwinTermPointersFunc) gum_emit_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed, (GFunc) gum_emit_child_destructor_call,
      &ctx);
  g_slist_free (children_reversed);

  if (tlv->num_descriptors != 0)
  {
    gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_XCX, self->pthread_key);
    gum_x86_writer_put_mov_reg_reg_ptr (&cw, GUM_X86_XAX, GUM_X86_XCX);
    gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
        self->pthread_key_delete, 1,
        GUM_ARG_REGISTER, GUM_X86_XAX);
  }

  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_XSP, self->module->pointer_size);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBP);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  *size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);
}

static void
gum_emit_child_constructor_call (GumDarwinMapper * child,
                                 GumEmitX86Context * ctx)
{
  GumX86Writer * cw = ctx->cw;

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX,
      gum_darwin_mapper_constructor (child));
  gum_x86_writer_put_call_reg (cw, GUM_X86_XCX);
}

static void
gum_emit_child_destructor_call (GumDarwinMapper * child,
                                GumEmitX86Context * ctx)
{
  GumX86Writer * cw = ctx->cw;

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX,
      gum_darwin_mapper_destructor (child));
  gum_x86_writer_put_call_reg (cw, GUM_X86_XCX);
}

static gboolean
gum_emit_chained_fixup_call (const GumDarwinChainedFixupsDetails * details,
                             GumEmitX86Context * ctx)
{
  GumDarwinMapper * mapper = ctx->mapper;
  GumDarwinModule * module = mapper->module;

  gum_x86_writer_put_call_address_with_aligned_arguments (ctx->cw,
      GUM_CALL_CAPI, mapper->process_chained_fixups, 4,
      GUM_ARG_ADDRESS, details->vm_address,
      GUM_ARG_ADDRESS, module->base_address,
      GUM_ARG_ADDRESS, module->preferred_address,
      GUM_ARG_ADDRESS, mapper->chained_symbols_vector);

  return TRUE;
}

static gboolean
gum_emit_resolve_if_needed (const GumDarwinBindDetails * details,
                            GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX,
      gum_darwin_mapper_make_code_address (self, value.resolver));
  gum_x86_writer_put_call_reg (cw, GUM_X86_XCX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX, details->addend);
  gum_x86_writer_put_add_reg_reg (cw, GUM_X86_XAX, GUM_X86_XCX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX, entry);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XCX, GUM_X86_XAX);

  return TRUE;
}

static gboolean
gum_emit_init_calls (const GumDarwinInitPointersDetails * details,
                     GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBP, details->address);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX, details->count);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XBP);
  gum_x86_writer_put_call_reg_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_X86_XAX, 5,
      /*   argc */ GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      /*   argv */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv),
      /*   envp */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv),
      /*  apple */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->apple_strv),
      /* result */ GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XBP, self->module->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_X86_XBX);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, next_label, GUM_NO_HINT);

  return TRUE;
}

static gboolean
gum_emit_term_calls (const GumDarwinTermPointersDetails * details,
                     GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBP, details->address +
      ((details->count - 1) * self->module->pointer_size));
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX, details->count);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XBP);
  gum_x86_writer_put_call_reg (cw, GUM_X86_XAX);

  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_XBP, self->module->pointer_size);
  gum_x86_writer_put_dec_reg (cw, GUM_X86_XBX);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, next_label, GUM_NO_HINT);

  return TRUE;
}

static void
gum_emit_tlv_init_code (GumEmitX86Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumX86Writer * cw = ctx->cw;
  GumDarwinModule * module = self->module;
  gsize pointer_size = module->pointer_size;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  GumAddress tlv_section = module->base_address + tlv->descriptors_offset;
  gconstpointer next_label = GSIZE_TO_POINTER (cw->code + 1);
  gconstpointer has_key_label = GSIZE_TO_POINTER (cw->code + 2);

  gum_x86_writer_put_call_address_with_arguments (cw, GUM_CALL_CAPI,
      self->pthread_key_create, 2,
      GUM_ARG_ADDRESS, self->pthread_key,
      GUM_ARG_ADDRESS, GUM_ADDRESS (0) /* destructor */);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX, self->pthread_key);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_shl_reg_u8 (cw, GUM_X86_XAX,
      (pointer_size == 8) ? 3 : 2);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX, self->tlv_area);
  gum_x86_writer_put_mov_gs_reg_ptr_reg (cw, GUM_X86_XAX, GUM_X86_XBX);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XCX, tlv->num_descriptors);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX, tlv_section);

  gum_x86_writer_put_label (cw, next_label);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX, self->tlv_get_addr_addr);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XBX, GUM_X86_XAX);

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XBX, pointer_size);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XBX);
  gum_x86_writer_put_cmp_reg_i32 (cw, GUM_X86_XAX, 0);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, has_key_label,
      GUM_NO_HINT);

  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX, self->pthread_key);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XBX, GUM_X86_XAX);

  gum_x86_writer_put_label (cw, has_key_label);

  gum_x86_writer_put_add_reg_imm (cw, GUM_X86_XBX, 2 * pointer_size);

  gum_x86_writer_put_dec_reg (cw, GUM_X86_XCX);
  gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, next_label, GUM_NO_HINT);
}

#elif defined (HAVE_ARM) || defined (HAVE_ARM64)

typedef struct _GumEmitArmContext GumEmitArmContext;
typedef struct _GumEmitArm64Context GumEmitArm64Context;

struct _GumEmitArmContext
{
  GumDarwinMapper * mapper;
  GumThumbWriter * tw;
};

struct _GumEmitArm64Context
{
  GumDarwinMapper * mapper;
  GumArm64Writer * aw;
};

static void gum_emit_arm_runtime (GumDarwinMapper * self,
    gpointer output_buffer, GumAddress pc, gsize * size);
static void gum_emit_arm_child_constructor_call (GumDarwinMapper * child,
    GumEmitArmContext * ctx);
static void gum_emit_arm_child_destructor_call (GumDarwinMapper * child,
    GumEmitArmContext * ctx);
static gboolean gum_emit_arm_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitArmContext * ctx);
static gboolean gum_emit_arm_init_calls (
    const GumDarwinInitPointersDetails * details, GumEmitArmContext * ctx);
static gboolean gum_emit_arm_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitArmContext * ctx);

static void gum_emit_arm64_runtime (GumDarwinMapper * self,
    gpointer output_buffer, GumAddress pc, gsize * size);
static void gum_emit_arm64_child_constructor_call (GumDarwinMapper * child,
    GumEmitArm64Context * ctx);
static void gum_emit_arm64_child_destructor_call (GumDarwinMapper * child,
    GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_chained_fixup_call (
    const GumDarwinChainedFixupsDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_resolve_if_needed (
    const GumDarwinBindDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_init_pointer_calls (
    const GumDarwinInitPointersDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_init_offset_calls (
    const GumDarwinInitOffsetsDetails * details, GumEmitArm64Context * ctx);
static gboolean gum_emit_arm64_term_calls (
    const GumDarwinTermPointersDetails * details, GumEmitArm64Context * ctx);
static void gum_emit_arm64_tlv_init_code (GumEmitArm64Context * ctx);

static void
gum_emit_runtime (GumDarwinMapper * self,
                  gpointer output_buffer,
                  GumAddress pc,
                  gsize * size)
{
  if (self->module->cpu_type == GUM_CPU_ARM)
    gum_emit_arm_runtime (self, output_buffer, pc, size);
  else
    gum_emit_arm64_runtime (self, output_buffer, pc, size);
}

static void
gum_emit_arm_runtime (GumDarwinMapper * self,
                      gpointer output_buffer,
                      GumAddress pc,
                      gsize * size)
{
  GumDarwinModule * module = self->module;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  GumThumbWriter tw;
  GumEmitArmContext ctx;
  GSList * children_reversed;

  gum_thumb_writer_init (&tw, output_buffer);
  tw.pc = pc;

  ctx.mapper = self;
  ctx.tw = &tw;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_thumb_writer_put_ldr_reg_u32 (&tw, ARM_REG_R0, 0);
    gum_thumb_writer_put_bx_reg (&tw, ARM_REG_LR);
  }

  self->constructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);

  g_slist_foreach (self->children, (GFunc) gum_emit_arm_child_constructor_call,
      &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_init_pointers (module,
      (GumFoundDarwinInitPointersFunc) gum_emit_arm_init_calls, &ctx);

  if (tlv->num_descriptors != 0)
  {
    gum_thumb_writer_put_call_address_with_arguments (&tw,
        self->pthread_key_create, 2,
        GUM_ARG_ADDRESS, self->pthread_key,
        GUM_ARG_ADDRESS, GUM_ADDRESS (0) /* destructor */);
  }

  gum_thumb_writer_put_pop_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);

  self->destructor_offset = gum_thumb_writer_offset (&tw) + 1;
  gum_thumb_writer_put_push_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_LR);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumFoundDarwinTermPointersFunc) gum_emit_arm_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed,
      (GFunc) gum_emit_arm_child_destructor_call, &ctx);
  g_slist_free (children_reversed);

  if (tlv->num_descriptors != 0)
  {
    gum_thumb_writer_put_ldr_reg_address (&tw, ARM_REG_R4, self->pthread_key);
    gum_thumb_writer_put_ldr_reg_reg (&tw, ARM_REG_R4, ARM_REG_R4);

    gum_thumb_writer_put_call_address_with_arguments (&tw,
        self->pthread_key_delete, 1,
        GUM_ARG_REGISTER, ARM_REG_R4);
  }

  gum_thumb_writer_put_pop_regs (&tw, 5, ARM_REG_R4, ARM_REG_R5, ARM_REG_R6,
      ARM_REG_R7, ARM_REG_PC);

  gum_thumb_writer_flush (&tw);
  *size = gum_thumb_writer_offset (&tw);
  gum_thumb_writer_clear (&tw);
}

static void
gum_emit_arm_child_constructor_call (GumDarwinMapper * child,
                                     GumEmitArmContext * ctx)
{
  GumThumbWriter * tw = ctx->tw;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
      gum_darwin_mapper_constructor (child));
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);
}

static void
gum_emit_arm_child_destructor_call (GumDarwinMapper * child,
                                    GumEmitArmContext * ctx)
{
  GumThumbWriter * tw = ctx->tw;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R0,
      gum_darwin_mapper_destructor (child));
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);
}

static gboolean
gum_emit_arm_resolve_if_needed (const GumDarwinBindDetails * details,
                                GumEmitArmContext * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumThumbWriter * tw = ctx->tw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R1,
      gum_darwin_mapper_make_code_address (self, value.resolver));
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R1);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R1, details->addend);
  gum_thumb_writer_put_add_reg_reg_reg (tw, ARM_REG_R0, ARM_REG_R0, ARM_REG_R1);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R1, entry);
  gum_thumb_writer_put_str_reg_reg_offset (tw, ARM_REG_R0, ARM_REG_R1, 0);

  return TRUE;
}

static gboolean
gum_emit_arm_init_calls (const GumDarwinInitPointersDetails * details,
                         GumEmitArmContext * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumThumbWriter * tw = ctx->tw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R4, details->address);
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R5, details->count);

  gum_thumb_writer_put_label (tw, next_label);

  gum_thumb_writer_put_ldr_reg_reg (tw, ARM_REG_R6, ARM_REG_R4);
  gum_thumb_writer_put_call_reg_with_arguments (tw, ARM_REG_R6, 5,
      /*   argc */ GUM_ARG_ADDRESS, GUM_ADDRESS (0),
      /*   argv */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv),
      /*   envp */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->empty_strv),
      /*  apple */ GUM_ARG_ADDRESS, GUM_ADDRESS (self->apple_strv),
      /* result */ GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  gum_thumb_writer_put_add_reg_reg_imm (tw, ARM_REG_R4, ARM_REG_R4, 4);
  gum_thumb_writer_put_sub_reg_reg_imm (tw, ARM_REG_R5, ARM_REG_R5, 1);
  gum_thumb_writer_put_cmp_reg_imm (tw, ARM_REG_R5, 0);
  gum_thumb_writer_put_bne_label (tw, next_label);

  return TRUE;
}

static gboolean
gum_emit_arm_term_calls (const GumDarwinTermPointersDetails * details,
                         GumEmitArmContext * ctx)
{
  GumThumbWriter * tw = ctx->tw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R4, details->address +
      ((details->count - 1) * 4));
  gum_thumb_writer_put_ldr_reg_address (tw, ARM_REG_R5, details->count);

  gum_thumb_writer_put_label (tw, next_label);

  gum_thumb_writer_put_ldr_reg_reg (tw, ARM_REG_R0, ARM_REG_R4);
  gum_thumb_writer_put_blx_reg (tw, ARM_REG_R0);

  gum_thumb_writer_put_sub_reg_reg_imm (tw, ARM_REG_R4, ARM_REG_R4, 4);
  gum_thumb_writer_put_sub_reg_reg_imm (tw, ARM_REG_R5, ARM_REG_R5, 1);
  gum_thumb_writer_put_cmp_reg_imm (tw, ARM_REG_R5, 0);
  gum_thumb_writer_put_bne_label (tw, next_label);

  return TRUE;
}

static void
gum_emit_arm64_runtime (GumDarwinMapper * self,
                        gpointer output_buffer,
                        GumAddress pc,
                        gsize * size)
{
  GumDarwinModule * module = self->module;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  GumArm64Writer aw;
  GumEmitArm64Context ctx;
  GumAddress process_threaded_items, threaded_symbols, threaded_regions;
  GSList * children_reversed;

  gum_arm64_writer_init (&aw, output_buffer);
  aw.pc = pc;

  ctx.mapper = self;
  ctx.aw = &aw;

  if (self->parent == NULL)
  {
    /* atexit stub */
    gum_arm64_writer_put_ldr_reg_u64 (&aw, ARM64_REG_X0, 0);
    gum_arm64_writer_put_ret (&aw);
  }

  if (self->threaded_regions != NULL)
  {
    process_threaded_items = aw.pc;
    gum_arm64_writer_put_bytes (&aw,
        (const guint8 *) gum_threaded_bind_processor_code,
        sizeof (gum_threaded_bind_processor_code));

    threaded_symbols = aw.pc;
    gum_arm64_writer_put_bytes (&aw,
        (const guint8 *) self->threaded_symbols->data,
        self->threaded_symbols->len * sizeof (GumAddress));

    threaded_regions = aw.pc;
    gum_arm64_writer_put_bytes (&aw,
        (const guint8 *) self->threaded_regions->data,
        self->threaded_regions->len * sizeof (GumAddress));
  }

  self->constructor_offset = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);

  g_slist_foreach (self->children,
      (GFunc) gum_emit_arm64_child_constructor_call, &ctx);
  if (self->threaded_regions != NULL)
  {
    gum_arm64_writer_put_call_address_with_arguments (&aw,
        process_threaded_items,
        6,
        GUM_ARG_ADDRESS, module->preferred_address,
        GUM_ARG_ADDRESS, gum_darwin_module_get_slide (module),
        GUM_ARG_ADDRESS, (GumAddress) self->threaded_symbols->len,
        GUM_ARG_ADDRESS, threaded_symbols,
        GUM_ARG_ADDRESS, (GumAddress) self->threaded_regions->len,
        GUM_ARG_ADDRESS, threaded_regions);
  }
  gum_darwin_module_enumerate_chained_fixups (module,
      (GumFoundDarwinChainedFixupsFunc) gum_emit_arm64_chained_fixup_call,
      &ctx);
  gum_darwin_module_enumerate_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm64_resolve_if_needed, &ctx);
  gum_darwin_module_enumerate_lazy_binds (module,
      (GumFoundDarwinBindFunc) gum_emit_arm64_resolve_if_needed, &ctx);

  if (tlv->num_descriptors != 0)
    gum_emit_arm64_tlv_init_code (&ctx);

  gum_darwin_module_enumerate_init_pointers (module,
      (GumFoundDarwinInitPointersFunc) gum_emit_arm64_init_pointer_calls, &ctx);
  gum_darwin_module_enumerate_init_offsets (module,
      (GumFoundDarwinInitOffsetsFunc) gum_emit_arm64_init_offset_calls, &ctx);

  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&aw);

  self->destructor_offset = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);

  gum_darwin_module_enumerate_term_pointers (module,
      (GumFoundDarwinTermPointersFunc) gum_emit_arm64_term_calls, &ctx);
  children_reversed = g_slist_reverse (g_slist_copy (self->children));
  g_slist_foreach (children_reversed,
      (GFunc) gum_emit_arm64_child_destructor_call, &ctx);
  g_slist_free (children_reversed);

  if (tlv->num_descriptors != 0)
  {
    gum_arm64_writer_put_ldr_reg_address (&aw, ARM64_REG_X21,
        self->pthread_key);
    gum_arm64_writer_put_ldr_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X21);

    gum_arm64_writer_put_call_address_with_arguments (&aw,
        self->pthread_key_delete, 1,
        GUM_ARG_REGISTER, ARM64_REG_X21);
  }

  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X21, ARM64_REG_X22);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&aw);

  gum_arm64_writer_flush (&aw);
  *size = gum_arm64_writer_offset (&aw);
  gum_arm64_writer_clear (&aw);
}

static void
gum_emit_arm64_child_constructor_call (GumDarwinMapper * child,
                                       GumEmitArm64Context * ctx)
{
  GumArm64Writer * aw = ctx->aw;

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X0,
      gum_darwin_mapper_constructor (child));
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X0);
}

static void
gum_emit_arm64_child_destructor_call (GumDarwinMapper * child,
                                      GumEmitArm64Context * ctx)
{
  GumArm64Writer * aw = ctx->aw;

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X0,
      gum_darwin_mapper_destructor (child));
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X0);
}

static gboolean
gum_emit_arm64_chained_fixup_call (
    const GumDarwinChainedFixupsDetails * details,
    GumEmitArm64Context * ctx)
{
  GumDarwinMapper * mapper = ctx->mapper;
  GumDarwinModule * module = mapper->module;

  gum_arm64_writer_put_call_address_with_arguments (ctx->aw,
      mapper->process_chained_fixups, 4,
      GUM_ARG_ADDRESS, details->vm_address,
      GUM_ARG_ADDRESS, module->base_address,
      GUM_ARG_ADDRESS, module->preferred_address,
      GUM_ARG_ADDRESS, mapper->chained_symbols_vector);

  return TRUE;
}

static gboolean
gum_emit_arm64_resolve_if_needed (const GumDarwinBindDetails * details,
                                  GumEmitArm64Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumArm64Writer * aw = ctx->aw;
  GumDarwinMapping * dependency;
  GumDarwinSymbolValue value;
  gboolean success;
  GumAddress entry;

  if (details->type != GUM_DARWIN_BIND_POINTER)
    return TRUE;

  dependency = gum_darwin_mapper_get_dependency_by_ordinal (self,
      details->library_ordinal, NULL);
  if (dependency == NULL)
    return TRUE;
  success = gum_darwin_mapper_resolve_symbol (self, dependency->module,
      details->symbol_name, &value);
  if (!success || value.resolver == 0)
    return TRUE;

  entry = self->module->base_address + details->segment->vm_address +
      details->offset;

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1,
      gum_darwin_mapper_make_code_address (self, value.resolver));
  gum_arm64_writer_put_blr_reg (aw, ARM64_REG_X1);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1, details->addend);
  gum_arm64_writer_put_add_reg_reg_reg (aw, ARM64_REG_X0, ARM64_REG_X0,
      ARM64_REG_X1);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X1, entry);
  gum_arm64_writer_put_str_reg_reg_offset (aw, ARM64_REG_X0, ARM64_REG_X1, 0);

  return TRUE;
}

static gboolean
gum_emit_arm64_init_pointer_calls (const GumDarwinInitPointersDetails * details,
                                   GumEmitArm64Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumArm64Writer * aw = ctx->aw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, details->address);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X20, details->count);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X21, self->empty_strv);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X22, self->apple_strv);

  gum_arm64_writer_put_label (aw, next_label);

  /* init (argc, argv, envp, apple, result) */
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X0, ARM64_REG_XZR);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X21);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X2, ARM64_REG_X21);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X3, ARM64_REG_X22);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X4, ARM64_REG_XZR);
  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_X5, ARM64_REG_X19, 0);
  gum_arm64_writer_put_blr_reg_no_auth (aw, ARM64_REG_X5);

  gum_arm64_writer_put_add_reg_reg_imm (aw, ARM64_REG_X19, ARM64_REG_X19, 8);
  gum_arm64_writer_put_sub_reg_reg_imm (aw, ARM64_REG_X20, ARM64_REG_X20, 1);
  gum_arm64_writer_put_cbnz_reg_label (aw, ARM64_REG_X20, next_label);

  return TRUE;
}

static gboolean
gum_emit_arm64_init_offset_calls (const GumDarwinInitOffsetsDetails * details,
                                  GumEmitArm64Context * ctx)
{
  GumDarwinMapper * self = ctx->mapper;
  GumArm64Writer * aw = ctx->aw;
  gconstpointer next_label = GSIZE_TO_POINTER (details->address);

  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X19, details->address);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X20, details->count);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X21, self->empty_strv);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X22, self->apple_strv);

  gum_arm64_writer_put_label (aw, next_label);

  /* init (argc, argv, envp, apple, result) */
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X0, ARM64_REG_XZR);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X1, ARM64_REG_X21);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X2, ARM64_REG_X21);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X3, ARM64_REG_X22);
  gum_arm64_writer_put_mov_reg_reg (aw, ARM64_REG_X4, ARM64_REG_XZR);
  gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X5,
      self->module->base_address);
  gum_arm64_writer_put_ldr_reg_reg_offset (aw, ARM64_REG_W6, ARM64_REG_X19, 0);
  gum_arm64_writer_put_add_reg_reg_reg (aw, ARM64_REG_X5, ARM64_REG_X5,
      ARM64_REG_X6);
  gum_arm64_writer_put_b
```