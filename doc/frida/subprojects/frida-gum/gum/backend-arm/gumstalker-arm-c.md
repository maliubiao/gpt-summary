Response:
The user wants a summary of the functionality of the C source code file `gumstalker-arm.c`. The summary should also cover several specific aspects: its relation to reverse engineering, its use of low-level binary, Linux/Android kernel/framework knowledge, logical reasoning, common user errors, and debugging.

**Plan:**

1. **High-level Overview:** Understand the main purpose of the `gumstalker-arm.c` file within the Frida context. Keywords like "dynamic instrumentation" and the file path hint at its role in modifying code execution on ARM architectures.
2. **Key Data Structures:** Identify the core structs and enums that define the state and operations within the file. This will reveal the fundamental concepts being managed.
3. **Core Functionality:**  Focus on the main functions and their interactions. Look for actions like following/unfollowing threads, code generation, code patching, and event handling.
4. **Reverse Engineering Connection:**  Consider how the instrumentation capabilities provided by this code are directly used in reverse engineering (e.g., tracing execution, modifying behavior).
5. **Binary/Kernel/Framework Aspects:**  Look for code that directly interacts with memory management, CPU state, system calls, and concepts related to the operating system and its kernel.
6. **Logical Reasoning:** Identify any conditional logic or state management within the code that suggests a form of reasoning or decision-making based on input or internal state.
7. **User Errors:**  Think about how a user might misuse the API provided by this module or make mistakes that could lead to unexpected behavior.
8. **Debugging:**  Consider the steps a user might take to reach this specific code during debugging.
9. **Concise Summary:** Combine the above points into a clear and concise summary of the file's functionality.
```c
/*
 * Copyright (C) 2009-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumstalker.h"

#include "gumarmreg.h"
#include "gumarmreader.h"
#include "gumarmrelocator.h"
#include "gumarmwriter.h"
#include "gummemory.h"
#include "gummetalhash.h"
#include "gumspinlock.h"
#include "gumstalker-priv.h"
#include "gumthumbreader.h"
#include "gumthumbrelocator.h"
#include "gumthumbwriter.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_LINUX
# include <sys/syscall.h>
#endif

#define GUM_CODE_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_CODE_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_DATA_SLAB_SIZE_INITIAL  (GUM_CODE_SLAB_SIZE_INITIAL / 5)
#define GUM_DATA_SLAB_SIZE_DYNAMIC  (GUM_CODE_SLAB_SIZE_DYNAMIC / 5)
#define GUM_SCRATCH_SLAB_SIZE       16384
#define GUM_EXEC_BLOCK_MIN_CAPACITY 1024

#define GUM_INVALIDATE_TRAMPOLINE_SIZE 12
#define GUM_EXCLUSIVE_ACCESS_MAX_DEPTH  8

#define GUM_INSTRUCTION_OFFSET_NONE (-1)

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;
typedef struct _GumActivation GumActivation;
typedef struct _GumInvalidateContext GumInvalidateContext;
typedef struct _GumCallProbe GumCallProbe;

typedef struct _GumExecCtx GumExecCtx;
typedef void (* GumArmHelperWriteFunc) (GumExecCtx * ctx, GumArmWriter * cw);
typedef void (* GumThumbHelperWriteFunc) (GumExecCtx * ctx,
    GumThumbWriter * cw);

typedef struct _GumExecBlock GumExecBlock;

typedef guint GumExecBlockFlags;

typedef struct _GumExecFrame GumExecFrame;

typedef struct _GumCodeSlab GumCodeSlab;
typedef struct _GumDataSlab GumDataSlab;
typedef struct _GumSlab GumSlab;

typedef guint GumPrologState;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef guint GumBranchTargetType;
typedef guint GumArmMode;
typedef struct _GumBranchTarget GumBranchTarget;
typedef struct _GumBranchDirectAddress GumBranchDirectAddress;
typedef struct _GumBranchDirectRegOffset GumBranchDirectRegOffset;
typedef struct _GumBranchDirectRegShift GumBranchDirectRegShift;
typedef struct _GumBranchIndirectRegOffset GumBranchIndirectRegOffset;
typedef struct _GumBranchIndirectRegShift GumBranchIndirectRegShift;
typedef struct _GumBranchIndirectPcrelTable GumBranchIndirectPcrelTable;
typedef struct _GumWriteback GumWriteback;
typedef guint GumBackpatchType;

typedef gboolean (* GumCheckExcludedFunc) (GumExecCtx * ctx,
    gconstpointer address);

struct _GumStalker
{
  GObject parent;

  gsize ctx_size;
  gsize ctx_header_size;

  goffset frames_offset;
  gsize frames_size;

  goffset thunks_offset;
  gsize thunks_size;

  goffset code_slab_offset;
  gsize code_slab_size_initial;
  gsize code_slab_size_dynamic;

  goffset data_slab_offset;
  gsize data_slab_size_initial;
  gsize data_slab_size_dynamic;

  goffset scratch_slab_offset;
  gsize scratch_slab_size;

  gsize page_size;
  GumCpuFeatures cpu_features;
  gboolean is_rwx_supported;

  GMutex mutex;
  GSList * contexts;

  GArray * exclusions;
  gint trust_threshold;
  volatile gboolean any_probes_attached;
  volatile gint last_probe_id;
  GumSpinlock probe_lock;
  GHashTable * probe_target_by_id;
  GHashTable * probe_array_by_address;
};

struct _GumInfectContext
{
  GumStalker * stalker;
  GumStalkerTransformer * transformer;
  GumEventSink * sink;
};

struct _GumDisinfectContext
{
  GumExecCtx * exec_ctx;
  gboolean success;
};

struct _GumActivation
{
  GumExecCtx * ctx;
  gboolean pending;
  gconstpointer target;
};

struct _GumInvalidateContext
{
  GumExecBlock * block;
  gboolean is_executing_target_block;
};

struct _GumCallProbe
{
  gint ref_count;
  GumProbeId id;
  GumCallProbeCallback callback;
  gpointer user_data;
  GDestroyNotify user_notify;
};

struct _GumExecCtx
{
  volatile gint state;
  gint64 destroy_pending_since;

  GumStalker * stalker;
  GumThreadId thread_id;

  GumArmWriter arm_writer;
  GumArmRelocator arm_relocator;

  GumThumbWriter thumb_writer;
  GumThumbRelocator thumb_relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerOutput * output);
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  gpointer last_exec_location;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * event,
      GumCpuContext * cpu_context);
  GumStalkerObserver * observer;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gpointer pending_return_location;
  guint pending_calls;
  GumExecFrame * current_frame;
  GumExecFrame * first_frame;
  GumExecFrame * frames;

  gpointer resume_at;
  gpointer kuh_target;
  gconstpointer activation_target;
  guint32 cpsr;

  gpointer thunks;
  gpointer infect_thunk;

  GumSpinlock code_lock;
  GumCodeSlab * code_slab;
  GumDataSlab * data_slab;
  GumCodeSlab * scratch_slab;
  GumMetalHashTable * mappings;
  gpointer last_arm_invalidator;
  gpointer last_thumb_invalidator;

  GumExecBlock * block_list;
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumExecBlock
{
  GumExecBlock * next;

  GumExecCtx * ctx;
  GumCodeSlab * code_slab;
  GumExecBlock * storage_block;

  guint8 * real_start;
  guint8 * code_start;
  guint real_size;
  guint code_size;
  guint capacity;
  guint last_callout_offset;

  GumExecBlockFlags flags;
  gint recycle_count;
};

enum _GumExecBlockFlags
{
  GUM_EXEC_BLOCK_THUMB                 = 1 << 0,
  GUM_EXEC_BLOCK_ACTIVATION_TARGET     = 1 << 1,
  GUM_EXEC_BLOCK_HAS_EXCLUSIVE_LOAD    = 1 << 2,
  GUM_EXEC_BLOCK_HAS_EXCLUSIVE_STORE   = 1 << 3,
  GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS = 1 << 4,
};

struct _GumExecFrame
{
  gpointer real_address;
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  GumSlab * next;
};

struct _GumCodeSlab
{
  GumSlab slab;

  gpointer arm_invalidator;
  gpointer thumb_invalidator;
};

struct _GumDataSlab
{
  GumSlab slab;
};

enum _GumPrologState
{
  GUM_PROLOG_CLOSED,
  GUM_PROLOG_OPEN
};

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  gboolean is_thumb;

  GumArmRelocator * arm_relocator;
  GumArmWriter * arm_writer;

  GumThumbRelocator * thumb_relocator;
  GumThumbWriter * thumb_writer;

  gpointer continuation_real_address;
};

struct _GumInstruction
{
  const cs_insn * ci;
  guint8 * start;
  guint8 * end;
};

struct _GumStalkerIterator
{
  GumExecCtx * exec_context;
  GumExecBlock * exec_block;
  GumGeneratorContext * generator_context;

  GumInstruction instruction;
};

struct _GumCalloutEntry
{
  GumStalkerCallout callout;
  gpointer data;
  GDestroyNotify data_destroy;

  gpointer pc;

  GumExecCtx * exec_context;

  GumCalloutEntry * next;
};

enum _GumBranchTargetType
{
  GUM_TARGET_DIRECT_ADDRESS,
  GUM_TARGET_DIRECT_REG_OFFSET,
  GUM_TARGET_DIRECT_REG_SHIFT,
  GUM_TARGET_INDIRECT_REG_OFFSET,
  GUM_TARGET_INDIRECT_REG_SHIFT,
  GUM_TARGET_INDIRECT_PCREL_TABLE
};

enum _GumArmMode
{
  GUM_ARM_MODE_AUTO,
  GUM_ARM_MODE_CURRENT
};

struct _GumBranchDirectAddress
{
  gpointer address;
};

struct _GumBranchDirectRegOffset
{
  arm_reg reg;
  gssize offset;
  GumArmMode mode;
};

struct _GumBranchDirectRegShift
{
  arm_reg base;
  arm_reg index;
  arm_shifter shifter;
  guint32 shift_value;
};

struct _GumBranchIndirectRegOffset
{
  arm_reg reg;
  gssize offset;
  gboolean write_back;
};

struct _GumBranchIndirectRegShift
{
  arm_reg base;
  arm_reg index;
  arm_shifter shifter;
  guint32 shift_value;
};

struct _GumBranchIndirectPcrelTable
{
  arm_reg base;
  arm_reg index;
  guint element_size;
};

struct _GumBranchTarget
{
  GumBranchTargetType type;

  union
  {
    GumBranchDirectAddress direct_address;
    GumBranchDirectRegOffset direct_reg_offset;
    GumBranchDirectRegShift direct_reg_shift;
    GumBranchIndirectRegOffset indirect_reg_offset;
    GumBranchIndirectRegShift indirect_reg_shift;
    GumBranchIndirectPcrelTable indirect_pcrel_table;
  } value;
};

struct _GumWriteback
{
  arm_reg target;
  gssize offset;
};

enum _GumBackpatchType
{
  GUM_BACKPATCH_ARM,
  GUM_BACKPATCH_THUMB,
};

struct _GumBackpatch
{
  GumBackpatchType type;
  gpointer to;
  gpointer from;
  gpointer from_insn;
  gsize code_offset;
  GumPrologState opened_prolog;
};

static void gum_stalker_finalize (GObject * object);

G_GNUC_INTERNAL gpointer _gum_stalker_do_follow_me (GumStalker * self,
    GumStalkerTransformer * transformer, GumEventSink * sink,
    gpointer ret_addr);
static void gum_stalker_infect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_stalker_disinfect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
G_GNUC_INTERNAL gpointer _gum_stalker_do_activate (GumStalker * self,
    gconstpointer target, gpointer ret_addr);
G_GNUC_INTERNAL gpointer _gum_stalker_do_deactivate (GumStalker * self,
    gpointer ret_addr);
static gboolean gum_stalker_do_invalidate (GumExecCtx * ctx,
    gconstpointer address, GumActivation * activation);
static void gum_stalker_try_invalidate_block_owned_by_thread (
    GumThreadId thread_id, GumCpuContext * cpu_context, gpointer user_data);

static GumCallProbe * gum_call_probe_ref (GumCallProbe * probe);
static void gum_call_probe_unref (GumCallProbe * probe);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumStalkerTransformer * transformer,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (void);
static GumExecCtx * gum_stalker_find_exec_ctx_by_thread_id (GumStalker * self,
    GumThreadId thread_id);

static gsize gum_stalker_snapshot_space_needed_for (GumStalker * self,
    gsize real_size);

static void gum_stalker_thaw (GumStalker * self, gpointer code, gsize size);
static void gum_stalker_freeze (GumStalker * self, gpointer code, gsize size);

static GumExecCtx * gum_exec_ctx_new (GumStalker * self, GumThreadId thread_id,
    GumStalkerTransformer * transformer, GumEventSink * sink);
static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_dispose (GumExecCtx * ctx);
static GumCodeSlab * gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
    GumCodeSlab * code_slab);
static GumDataSlab * gum_exec_ctx_add_data_slab (GumExecCtx * ctx,
    GumDataSlab * data_slab);
static void gum_exec_ctx_compute_code_address_spec (GumExecCtx * ctx,
    gsize slab_size, GumAddressSpec * spec);
static void gum_exec_ctx_compute_data_address_spec (GumExecCtx * ctx,
    gsize slab_size, GumAddressSpec * spec);
static gboolean gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
    gpointer resume_at);
static void gum_exec_ctx_unfollow (GumExecCtx * ctx, gpointer resume_at);
static gboolean gum_exec_ctx_has_executed (GumExecCtx * ctx);
static gboolean gum_exec_ctx_contains (GumExecCtx * ctx, gconstpointer address);
static gpointer gum_exec_ctx_switch_block (GumExecCtx * ctx,
    GumExecBlock * block, gpointer start_address, gpointer from_insn);
static void gum_exec_ctx_query_block_switch_callback (GumExecCtx * ctx,
    GumExecBlock * block, gpointer start_address, gpointer from_insn,
    gpointer * target);
static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address);
static void gum_exec_ctx_recompile_block (GumExecCtx * ctx,
    GumExecBlock * block);
static void gum_exec_ctx_compile_block (GumExecCtx * ctx, GumExecBlock * block,
    gconstpointer input_code, gpointer output_code, GumAddress output_pc,
    guint * input_size, guint * output_size);
static void gum_exec_ctx_compile_arm_block (GumExecCtx * ctx,
    GumExecBlock * block, gconstpointer input_code, gpointer output_code,
    GumAddress output_pc, guint * input_size, guint * output_size);
static void gum_exec_ctx_compile_thumb_block (GumExecCtx * ctx,
    GumExecBlock * block, gconstpointer input_code, gpointer output_code,
    GumAddress output_pc, guint * input_size, guint * output_size);
static void gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
    GumExecBlock * block);

static void gum_exec_ctx_begin_call (GumExecCtx * ctx, gpointer ret_addr);
static void gum_exec_ctx_end_call (GumExecCtx * ctx);

static gboolean gum_stalker_iterator_arm_next (GumStalkerIterator * self,
    const cs_insn ** insn);
static gboolean gum_stalker_iterator_thumb_next (GumStalkerIterator * self,
    const cs_insn ** insn);
static gboolean gum_stalker_iterator_is_out_of_space (
    GumStalkerIterator * self);
static void gum_stalker_iterator_arm_keep (GumStalkerIterator * self);
static void gum_stalker_iterator_thumb_keep (GumStalkerIterator * self);
static void gum_stalker_iterator_handle_thumb_branch_insn (
    GumStalkerIterator * self, const cs_insn * insn);
static void gum_stalker_iterator_handle_thumb_it_insn (
    GumStalkerIterator * self);

static void gum_stalker_save_cpsr (GumCpuContext * cpu_context,
    GumExecCtx * ctx);
static void gum_stalker_restore_cpsr (GumCpuContext * cpu_context,
    GumExecCtx * ctx);

static void gum_stalker_get_target_address (const cs_insn * insn,
    gboolean thumb, GumBranchTarget * target, guint16 * mask);
static void gum_stalker_get_writeback (const cs_insn * insn,
    GumWriteback * writeback);

static void gum_stalker_invoke_callout (GumCalloutEntry * entry,
    GumCpuContext * cpu_context);

static void gum_exec_ctx_write_arm_prolog (GumExecCtx * ctx, GumArmWriter * cw);
static void gum_exec_ctx_write_arm_epilog (GumExecCtx * ctx, GumArmWriter * cw);

static void gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx);
static void gum_exec_ctx_write_arm_invalidator (GumExecCtx * ctx,
    GumArmWriter * cw);
static void gum_exec_ctx_write_thumb_invalidator (GumExecCtx * ctx,
    GumThumbWriter * cw);
static void gum_exec_ctx_ensure_arm_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr, GumArmHelperWriteFunc write);
static void gum_exec_ctx_ensure_thumb_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr, GumThumbHelperWriteFunc write);
static gboolean gum_exec_ctx_is_arm_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr);
static gboolean gum_exec_ctx_is_thumb_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr);

static void gum_exec_ctx_arm_load_real_register_into (GumExecCtx * ctx,
    arm_reg target_register, arm_reg source_register, GumGeneratorContext * gc);
static void gum_exec_ctx_thumb_load_real_register_into (GumExecCtx * ctx,
    arm_reg target_register, arm_reg source_register, GumGeneratorContext * gc);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_clear (GumExecBlock * block);
static void gum_exec_block_commit (GumExecBlock * block);
static void gum_exec_block_invalidate (GumExecBlock * block);
static gpointer gum_exec_block_encode_instruction_pointer (
    const GumExecBlock * block, gpointer ptr);
static gpointer gum_exec_block_get_snapshot_start (GumExecBlock * block);
static GumCalloutEntry * gum_exec_block_get_last_callout_entry (
    const GumExecBlock * block);
static void gum_exec_block_set_last_callout_entry (GumExecBlock * block,
    GumCalloutEntry * entry);

static void gum_exec_ctx_backpatch_arm_branch_to_current (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, gsize code_offset,
    GumPrologState opened_prolog);
static void gum_exec_ctx_backpatch_thumb_branch_to_current (
    GumExecBlock * block, GumExecBlock * from, gpointer from_insn,
    gsize code_offset, GumPrologState opened_prolog);

static void gum_exec_block_virtualize_arm_branch_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumWriteback * writeback,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_branch_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, arm_reg cc_reg,
    GumWriteback * writeback, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_call_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_call_insn (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_ret_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, gboolean pop, guint16 mask,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_ret_insn (GumExecBlock * block,
    const GumBranchTarget * target, gboolean pop, guint16 mask,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_svc_insn (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_svc_insn (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_handle_kuser_helper (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_kuser_helper (
    GumExecBlock * block, const GumBranchTarget * target,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_call_switch_block (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_call_switch_block (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_dont_virtualize_arm_insn (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_dont_virtualize_thumb_insn (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_handle_excluded (GumExecBlock * block,
    const GumBranchTarget * target, gboolean call, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_excluded (GumExecBlock * block,
    const GumBranchTarget * target, gboolean call, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_not_taken (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_not_taken (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, arm_reg cc_reg,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_continue (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_continue (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_writeback (GumExecBlock * block,
    const GumWriteback * writeback, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_writeback (GumExecBlock * block,
    const GumWriteback * writeback, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_exec_generated_code (GumArmWriter * cw,
    GumExecCtx * ctx);
static void gum_exec_block_write_thumb_exec_generated_code (GumThumbWriter * cw,
    GumExecCtx * ctx);

static void gum_exec_block_write_arm_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_ret_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_ret_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_push_stack_frame (GumExecBlock * block,
    gpointer ret_real_address, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_push_stack_frame (GumExecBlock * block,
    gpointer ret_real_address, GumGeneratorContext * gc);
static void gum_exec_block_push_stack_frame (GumExecCtx * ctx,
    gpointer ret_real_address);
static void gum_exec_block_write_arm_pop_stack_frame (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_pop_stack_frame (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_pop_stack_frame (GumExecCtx * ctx,
    gpointer ret_real_address);

static void gum_exec_block_maybe_write_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_invoke_call_probes (GumExecBlock * block,
    GumCpuContext * cpu_context);

static gpointer gum_exec_block_write_arm_inline_data (GumArmWriter * cw,
    gconstpointer data, gsize size, GumAddress * address);
static gpointer gum_exec_block_write_thumb_inline_data (GumThumbWriter * cw,
    gconstpointer data, gsize size, GumAddress * address);

static void gum_exec_block_arm_open_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_thumb_open_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_arm_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_thumb_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_maybe_inherit_exclusive_access_state (
    GumExecBlock * block, GumExecBlock * reference);
static void gum_exec_block_propagate_exclusive_access_state (
    GumExecBlock * block);

static GumCodeSlab * gum_code_slab_new (GumExecCtx * ctx);
static void gum_code_slab_free (GumCodeSlab * code_slab);
static void gum_code_slab_init (GumCodeSlab * code_slab, gsize slab_size,
    gsize page_size);

static GumDataSlab * gum_data_slab_new (GumExecCtx * ctx);
static void gum_data_slab_free (GumDataSlab * data_slab);
static void gum_data_slab_init (GumDataSlab * data_slab, gsize slab_size);

static void gum_scratch_slab_init (GumCodeSlab * scratch_slab, gsize slab_size);

static void gum_slab_free (GumSlab * slab);
static void gum_slab_init (GumSlab * slab, gsize slab_size, gsize header_size);
static gsize gum_slab_available (GumSlab * self);
static gpointer gum_slab_start (GumSlab * self);
static gpointer gum_slab_end (GumSlab * self);
static gpointer gum_slab_cursor (GumSlab * self);
static gpointer gum_slab_align_cursor (GumSlab * self, guint alignment);
static gpointer gum_slab_reserve (GumSlab * self, gsize size);
static gpointer gum_slab_try_reserve (GumSlab * self, gsize size);

static gpointer gum_find_thread_exit_implementation (void);

static gpointer gum_strip_thumb_bit (gpointer address);
static gboolean gum_is_thumb (gconstpointer address);
static gboolean gum_is_kuser_helper (gconstpointer address);
static gboolean gum_is_exclusive_load_insn (const cs_insn * insn);
static gboolean gum_is_exclusive_store_insn (const cs_insn * insn);

static guint gum_count_bits_set (guint16 value);
static guint gum_count_trailing_zeros (guint16 value);

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)

static GPrivate gum_stalker_exec_ctx_private;

static gpointer gum_thread_exit_address;

gboolean
gum_stalker_is_supported (void)
{
  return TRUE;
}

void
gum_stalker_activate_experimental_unwind_support (void)
{
}

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_stalker_finalize;

  gum_thread_exit_address = gum_find_thread_exit_implementation ();
}

static void
gum_stalker_init (GumStalker * self)
{
  gsize page_size;

  
### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2009-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumstalker.h"

#include "gumarmreg.h"
#include "gumarmreader.h"
#include "gumarmrelocator.h"
#include "gumarmwriter.h"
#include "gummemory.h"
#include "gummetalhash.h"
#include "gumspinlock.h"
#include "gumstalker-priv.h"
#include "gumthumbreader.h"
#include "gumthumbrelocator.h"
#include "gumthumbwriter.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_LINUX
# include <sys/syscall.h>
#endif

#define GUM_CODE_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_CODE_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_DATA_SLAB_SIZE_INITIAL  (GUM_CODE_SLAB_SIZE_INITIAL / 5)
#define GUM_DATA_SLAB_SIZE_DYNAMIC  (GUM_CODE_SLAB_SIZE_DYNAMIC / 5)
#define GUM_SCRATCH_SLAB_SIZE       16384
#define GUM_EXEC_BLOCK_MIN_CAPACITY 1024

#define GUM_INVALIDATE_TRAMPOLINE_SIZE 12
#define GUM_EXCLUSIVE_ACCESS_MAX_DEPTH  8

#define GUM_INSTRUCTION_OFFSET_NONE (-1)

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;
typedef struct _GumActivation GumActivation;
typedef struct _GumInvalidateContext GumInvalidateContext;
typedef struct _GumCallProbe GumCallProbe;

typedef struct _GumExecCtx GumExecCtx;
typedef void (* GumArmHelperWriteFunc) (GumExecCtx * ctx, GumArmWriter * cw);
typedef void (* GumThumbHelperWriteFunc) (GumExecCtx * ctx,
    GumThumbWriter * cw);

typedef struct _GumExecBlock GumExecBlock;

typedef guint GumExecBlockFlags;

typedef struct _GumExecFrame GumExecFrame;

typedef struct _GumCodeSlab GumCodeSlab;
typedef struct _GumDataSlab GumDataSlab;
typedef struct _GumSlab GumSlab;

typedef guint GumPrologState;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef guint GumBranchTargetType;
typedef guint GumArmMode;
typedef struct _GumBranchTarget GumBranchTarget;
typedef struct _GumBranchDirectAddress GumBranchDirectAddress;
typedef struct _GumBranchDirectRegOffset GumBranchDirectRegOffset;
typedef struct _GumBranchDirectRegShift GumBranchDirectRegShift;
typedef struct _GumBranchIndirectRegOffset GumBranchIndirectRegOffset;
typedef struct _GumBranchIndirectRegShift GumBranchIndirectRegShift;
typedef struct _GumBranchIndirectPcrelTable GumBranchIndirectPcrelTable;
typedef struct _GumWriteback GumWriteback;
typedef guint GumBackpatchType;

typedef gboolean (* GumCheckExcludedFunc) (GumExecCtx * ctx,
    gconstpointer address);

struct _GumStalker
{
  GObject parent;

  gsize ctx_size;
  gsize ctx_header_size;

  goffset frames_offset;
  gsize frames_size;

  goffset thunks_offset;
  gsize thunks_size;

  goffset code_slab_offset;
  gsize code_slab_size_initial;
  gsize code_slab_size_dynamic;

  goffset data_slab_offset;
  gsize data_slab_size_initial;
  gsize data_slab_size_dynamic;

  goffset scratch_slab_offset;
  gsize scratch_slab_size;

  gsize page_size;
  GumCpuFeatures cpu_features;
  gboolean is_rwx_supported;

  GMutex mutex;
  GSList * contexts;

  GArray * exclusions;
  gint trust_threshold;
  volatile gboolean any_probes_attached;
  volatile gint last_probe_id;
  GumSpinlock probe_lock;
  GHashTable * probe_target_by_id;
  GHashTable * probe_array_by_address;
};

struct _GumInfectContext
{
  GumStalker * stalker;
  GumStalkerTransformer * transformer;
  GumEventSink * sink;
};

struct _GumDisinfectContext
{
  GumExecCtx * exec_ctx;
  gboolean success;
};

struct _GumActivation
{
  GumExecCtx * ctx;
  gboolean pending;
  gconstpointer target;
};

struct _GumInvalidateContext
{
  GumExecBlock * block;
  gboolean is_executing_target_block;
};

struct _GumCallProbe
{
  gint ref_count;
  GumProbeId id;
  GumCallProbeCallback callback;
  gpointer user_data;
  GDestroyNotify user_notify;
};

struct _GumExecCtx
{
  volatile gint state;
  gint64 destroy_pending_since;

  GumStalker * stalker;
  GumThreadId thread_id;

  GumArmWriter arm_writer;
  GumArmRelocator arm_relocator;

  GumThumbWriter thumb_writer;
  GumThumbRelocator thumb_relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerOutput * output);
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  gpointer last_exec_location;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * event,
      GumCpuContext * cpu_context);
  GumStalkerObserver * observer;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gpointer pending_return_location;
  guint pending_calls;
  GumExecFrame * current_frame;
  GumExecFrame * first_frame;
  GumExecFrame * frames;

  gpointer resume_at;
  gpointer kuh_target;
  gconstpointer activation_target;
  guint32 cpsr;

  gpointer thunks;
  gpointer infect_thunk;

  GumSpinlock code_lock;
  GumCodeSlab * code_slab;
  GumDataSlab * data_slab;
  GumCodeSlab * scratch_slab;
  GumMetalHashTable * mappings;
  gpointer last_arm_invalidator;
  gpointer last_thumb_invalidator;

  GumExecBlock * block_list;
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumExecBlock
{
  GumExecBlock * next;

  GumExecCtx * ctx;
  GumCodeSlab * code_slab;
  GumExecBlock * storage_block;

  guint8 * real_start;
  guint8 * code_start;
  guint real_size;
  guint code_size;
  guint capacity;
  guint last_callout_offset;

  GumExecBlockFlags flags;
  gint recycle_count;
};

enum _GumExecBlockFlags
{
  GUM_EXEC_BLOCK_THUMB                 = 1 << 0,
  GUM_EXEC_BLOCK_ACTIVATION_TARGET     = 1 << 1,
  GUM_EXEC_BLOCK_HAS_EXCLUSIVE_LOAD    = 1 << 2,
  GUM_EXEC_BLOCK_HAS_EXCLUSIVE_STORE   = 1 << 3,
  GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS = 1 << 4,
};

struct _GumExecFrame
{
  gpointer real_address;
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  GumSlab * next;
};

struct _GumCodeSlab
{
  GumSlab slab;

  gpointer arm_invalidator;
  gpointer thumb_invalidator;
};

struct _GumDataSlab
{
  GumSlab slab;
};

enum _GumPrologState
{
  GUM_PROLOG_CLOSED,
  GUM_PROLOG_OPEN
};

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  gboolean is_thumb;

  GumArmRelocator * arm_relocator;
  GumArmWriter * arm_writer;

  GumThumbRelocator * thumb_relocator;
  GumThumbWriter * thumb_writer;

  gpointer continuation_real_address;
};

struct _GumInstruction
{
  const cs_insn * ci;
  guint8 * start;
  guint8 * end;
};

struct _GumStalkerIterator
{
  GumExecCtx * exec_context;
  GumExecBlock * exec_block;
  GumGeneratorContext * generator_context;

  GumInstruction instruction;
};

struct _GumCalloutEntry
{
  GumStalkerCallout callout;
  gpointer data;
  GDestroyNotify data_destroy;

  gpointer pc;

  GumExecCtx * exec_context;

  GumCalloutEntry * next;
};

enum _GumBranchTargetType
{
  GUM_TARGET_DIRECT_ADDRESS,
  GUM_TARGET_DIRECT_REG_OFFSET,
  GUM_TARGET_DIRECT_REG_SHIFT,
  GUM_TARGET_INDIRECT_REG_OFFSET,
  GUM_TARGET_INDIRECT_REG_SHIFT,
  GUM_TARGET_INDIRECT_PCREL_TABLE
};

enum _GumArmMode
{
  GUM_ARM_MODE_AUTO,
  GUM_ARM_MODE_CURRENT
};

struct _GumBranchDirectAddress
{
  gpointer address;
};

struct _GumBranchDirectRegOffset
{
  arm_reg reg;
  gssize offset;
  GumArmMode mode;
};

struct _GumBranchDirectRegShift
{
  arm_reg base;
  arm_reg index;
  arm_shifter shifter;
  guint32 shift_value;
};

struct _GumBranchIndirectRegOffset
{
  arm_reg reg;
  gssize offset;
  gboolean write_back;
};

struct _GumBranchIndirectRegShift
{
  arm_reg base;
  arm_reg index;
  arm_shifter shifter;
  guint32 shift_value;
};

struct _GumBranchIndirectPcrelTable
{
  arm_reg base;
  arm_reg index;
  guint element_size;
};

struct _GumBranchTarget
{
  GumBranchTargetType type;

  union
  {
    GumBranchDirectAddress direct_address;
    GumBranchDirectRegOffset direct_reg_offset;
    GumBranchDirectRegShift direct_reg_shift;
    GumBranchIndirectRegOffset indirect_reg_offset;
    GumBranchIndirectRegShift indirect_reg_shift;
    GumBranchIndirectPcrelTable indirect_pcrel_table;
  } value;
};

struct _GumWriteback
{
  arm_reg target;
  gssize offset;
};

enum _GumBackpatchType
{
  GUM_BACKPATCH_ARM,
  GUM_BACKPATCH_THUMB,
};

struct _GumBackpatch
{
  GumBackpatchType type;
  gpointer to;
  gpointer from;
  gpointer from_insn;
  gsize code_offset;
  GumPrologState opened_prolog;
};

static void gum_stalker_finalize (GObject * object);

G_GNUC_INTERNAL gpointer _gum_stalker_do_follow_me (GumStalker * self,
    GumStalkerTransformer * transformer, GumEventSink * sink,
    gpointer ret_addr);
static void gum_stalker_infect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_stalker_disinfect (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
G_GNUC_INTERNAL gpointer _gum_stalker_do_activate (GumStalker * self,
    gconstpointer target, gpointer ret_addr);
G_GNUC_INTERNAL gpointer _gum_stalker_do_deactivate (GumStalker * self,
    gpointer ret_addr);
static gboolean gum_stalker_do_invalidate (GumExecCtx * ctx,
    gconstpointer address, GumActivation * activation);
static void gum_stalker_try_invalidate_block_owned_by_thread (
    GumThreadId thread_id, GumCpuContext * cpu_context, gpointer user_data);

static GumCallProbe * gum_call_probe_ref (GumCallProbe * probe);
static void gum_call_probe_unref (GumCallProbe * probe);

static GumExecCtx * gum_stalker_create_exec_ctx (GumStalker * self,
    GumThreadId thread_id, GumStalkerTransformer * transformer,
    GumEventSink * sink);
static void gum_stalker_destroy_exec_ctx (GumStalker * self, GumExecCtx * ctx);
static GumExecCtx * gum_stalker_get_exec_ctx (void);
static GumExecCtx * gum_stalker_find_exec_ctx_by_thread_id (GumStalker * self,
    GumThreadId thread_id);

static gsize gum_stalker_snapshot_space_needed_for (GumStalker * self,
    gsize real_size);

static void gum_stalker_thaw (GumStalker * self, gpointer code, gsize size);
static void gum_stalker_freeze (GumStalker * self, gpointer code, gsize size);

static GumExecCtx * gum_exec_ctx_new (GumStalker * self, GumThreadId thread_id,
    GumStalkerTransformer * transformer, GumEventSink * sink);
static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_dispose (GumExecCtx * ctx);
static GumCodeSlab * gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
    GumCodeSlab * code_slab);
static GumDataSlab * gum_exec_ctx_add_data_slab (GumExecCtx * ctx,
    GumDataSlab * data_slab);
static void gum_exec_ctx_compute_code_address_spec (GumExecCtx * ctx,
    gsize slab_size, GumAddressSpec * spec);
static void gum_exec_ctx_compute_data_address_spec (GumExecCtx * ctx,
    gsize slab_size, GumAddressSpec * spec);
static gboolean gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
    gpointer resume_at);
static void gum_exec_ctx_unfollow (GumExecCtx * ctx, gpointer resume_at);
static gboolean gum_exec_ctx_has_executed (GumExecCtx * ctx);
static gboolean gum_exec_ctx_contains (GumExecCtx * ctx, gconstpointer address);
static gpointer gum_exec_ctx_switch_block (GumExecCtx * ctx,
    GumExecBlock * block, gpointer start_address, gpointer from_insn);
static void gum_exec_ctx_query_block_switch_callback (GumExecCtx * ctx,
    GumExecBlock * block, gpointer start_address, gpointer from_insn,
    gpointer * target);
static GumExecBlock * gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
    gpointer real_address, gpointer * code_address);
static void gum_exec_ctx_recompile_block (GumExecCtx * ctx,
    GumExecBlock * block);
static void gum_exec_ctx_compile_block (GumExecCtx * ctx, GumExecBlock * block,
    gconstpointer input_code, gpointer output_code, GumAddress output_pc,
    guint * input_size, guint * output_size);
static void gum_exec_ctx_compile_arm_block (GumExecCtx * ctx,
    GumExecBlock * block, gconstpointer input_code, gpointer output_code,
    GumAddress output_pc, guint * input_size, guint * output_size);
static void gum_exec_ctx_compile_thumb_block (GumExecCtx * ctx,
    GumExecBlock * block, gconstpointer input_code, gpointer output_code,
    GumAddress output_pc, guint * input_size, guint * output_size);
static void gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
    GumExecBlock * block);

static void gum_exec_ctx_begin_call (GumExecCtx * ctx, gpointer ret_addr);
static void gum_exec_ctx_end_call (GumExecCtx * ctx);

static gboolean gum_stalker_iterator_arm_next (GumStalkerIterator * self,
    const cs_insn ** insn);
static gboolean gum_stalker_iterator_thumb_next (GumStalkerIterator * self,
    const cs_insn ** insn);
static gboolean gum_stalker_iterator_is_out_of_space (
    GumStalkerIterator * self);
static void gum_stalker_iterator_arm_keep (GumStalkerIterator * self);
static void gum_stalker_iterator_thumb_keep (GumStalkerIterator * self);
static void gum_stalker_iterator_handle_thumb_branch_insn (
    GumStalkerIterator * self, const cs_insn * insn);
static void gum_stalker_iterator_handle_thumb_it_insn (
    GumStalkerIterator * self);

static void gum_stalker_save_cpsr (GumCpuContext * cpu_context,
    GumExecCtx * ctx);
static void gum_stalker_restore_cpsr (GumCpuContext * cpu_context,
    GumExecCtx * ctx);

static void gum_stalker_get_target_address (const cs_insn * insn,
    gboolean thumb, GumBranchTarget * target, guint16 * mask);
static void gum_stalker_get_writeback (const cs_insn * insn,
    GumWriteback * writeback);

static void gum_stalker_invoke_callout (GumCalloutEntry * entry,
    GumCpuContext * cpu_context);

static void gum_exec_ctx_write_arm_prolog (GumExecCtx * ctx, GumArmWriter * cw);
static void gum_exec_ctx_write_arm_epilog (GumExecCtx * ctx, GumArmWriter * cw);

static void gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx);
static void gum_exec_ctx_write_arm_invalidator (GumExecCtx * ctx,
    GumArmWriter * cw);
static void gum_exec_ctx_write_thumb_invalidator (GumExecCtx * ctx,
    GumThumbWriter * cw);
static void gum_exec_ctx_ensure_arm_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr, GumArmHelperWriteFunc write);
static void gum_exec_ctx_ensure_thumb_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr, GumThumbHelperWriteFunc write);
static gboolean gum_exec_ctx_is_arm_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr);
static gboolean gum_exec_ctx_is_thumb_helper_reachable (GumExecCtx * ctx,
    gpointer * helper_ptr);

static void gum_exec_ctx_arm_load_real_register_into (GumExecCtx * ctx,
    arm_reg target_register, arm_reg source_register, GumGeneratorContext * gc);
static void gum_exec_ctx_thumb_load_real_register_into (GumExecCtx * ctx,
    arm_reg target_register, arm_reg source_register, GumGeneratorContext * gc);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_clear (GumExecBlock * block);
static void gum_exec_block_commit (GumExecBlock * block);
static void gum_exec_block_invalidate (GumExecBlock * block);
static gpointer gum_exec_block_encode_instruction_pointer (
    const GumExecBlock * block, gpointer ptr);
static gpointer gum_exec_block_get_snapshot_start (GumExecBlock * block);
static GumCalloutEntry * gum_exec_block_get_last_callout_entry (
    const GumExecBlock * block);
static void gum_exec_block_set_last_callout_entry (GumExecBlock * block,
    GumCalloutEntry * entry);

static void gum_exec_ctx_backpatch_arm_branch_to_current (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, gsize code_offset,
    GumPrologState opened_prolog);
static void gum_exec_ctx_backpatch_thumb_branch_to_current (
    GumExecBlock * block, GumExecBlock * from, gpointer from_insn,
    gsize code_offset, GumPrologState opened_prolog);

static void gum_exec_block_virtualize_arm_branch_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumWriteback * writeback,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_branch_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, arm_reg cc_reg,
    GumWriteback * writeback, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_call_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_call_insn (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_ret_insn (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, gboolean pop, guint16 mask,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_ret_insn (GumExecBlock * block,
    const GumBranchTarget * target, gboolean pop, guint16 mask,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_arm_svc_insn (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_virtualize_thumb_svc_insn (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_handle_kuser_helper (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_kuser_helper (
    GumExecBlock * block, const GumBranchTarget * target,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_call_switch_block (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_call_switch_block (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);

static void gum_exec_block_dont_virtualize_arm_insn (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_dont_virtualize_thumb_insn (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_handle_excluded (GumExecBlock * block,
    const GumBranchTarget * target, gboolean call, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_excluded (GumExecBlock * block,
    const GumBranchTarget * target, gboolean call, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_not_taken (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_not_taken (GumExecBlock * block,
    const GumBranchTarget * target, arm_cc cc, arm_reg cc_reg,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_continue (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_continue (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_handle_writeback (GumExecBlock * block,
    const GumWriteback * writeback, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_handle_writeback (GumExecBlock * block,
    const GumWriteback * writeback, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_exec_generated_code (GumArmWriter * cw,
    GumExecCtx * ctx);
static void gum_exec_block_write_thumb_exec_generated_code (GumThumbWriter * cw,
    GumExecCtx * ctx);

static void gum_exec_block_write_arm_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_ret_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_ret_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_arm_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_write_arm_push_stack_frame (GumExecBlock * block,
    gpointer ret_real_address, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_push_stack_frame (GumExecBlock * block,
    gpointer ret_real_address, GumGeneratorContext * gc);
static void gum_exec_block_push_stack_frame (GumExecCtx * ctx,
    gpointer ret_real_address);
static void gum_exec_block_write_arm_pop_stack_frame (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_pop_stack_frame (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_block_pop_stack_frame (GumExecCtx * ctx,
    gpointer ret_real_address);

static void gum_exec_block_maybe_write_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_arm_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_thumb_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_invoke_call_probes (GumExecBlock * block,
    GumCpuContext * cpu_context);

static gpointer gum_exec_block_write_arm_inline_data (GumArmWriter * cw,
    gconstpointer data, gsize size, GumAddress * address);
static gpointer gum_exec_block_write_thumb_inline_data (GumThumbWriter * cw,
    gconstpointer data, gsize size, GumAddress * address);

static void gum_exec_block_arm_open_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_thumb_open_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_arm_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_thumb_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc);

static void gum_exec_block_maybe_inherit_exclusive_access_state (
    GumExecBlock * block, GumExecBlock * reference);
static void gum_exec_block_propagate_exclusive_access_state (
    GumExecBlock * block);

static GumCodeSlab * gum_code_slab_new (GumExecCtx * ctx);
static void gum_code_slab_free (GumCodeSlab * code_slab);
static void gum_code_slab_init (GumCodeSlab * code_slab, gsize slab_size,
    gsize page_size);

static GumDataSlab * gum_data_slab_new (GumExecCtx * ctx);
static void gum_data_slab_free (GumDataSlab * data_slab);
static void gum_data_slab_init (GumDataSlab * data_slab, gsize slab_size);

static void gum_scratch_slab_init (GumCodeSlab * scratch_slab, gsize slab_size);

static void gum_slab_free (GumSlab * slab);
static void gum_slab_init (GumSlab * slab, gsize slab_size, gsize header_size);
static gsize gum_slab_available (GumSlab * self);
static gpointer gum_slab_start (GumSlab * self);
static gpointer gum_slab_end (GumSlab * self);
static gpointer gum_slab_cursor (GumSlab * self);
static gpointer gum_slab_align_cursor (GumSlab * self, guint alignment);
static gpointer gum_slab_reserve (GumSlab * self, gsize size);
static gpointer gum_slab_try_reserve (GumSlab * self, gsize size);

static gpointer gum_find_thread_exit_implementation (void);

static gpointer gum_strip_thumb_bit (gpointer address);
static gboolean gum_is_thumb (gconstpointer address);
static gboolean gum_is_kuser_helper (gconstpointer address);
static gboolean gum_is_exclusive_load_insn (const cs_insn * insn);
static gboolean gum_is_exclusive_store_insn (const cs_insn * insn);

static guint gum_count_bits_set (guint16 value);
static guint gum_count_trailing_zeros (guint16 value);

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)

static GPrivate gum_stalker_exec_ctx_private;

static gpointer gum_thread_exit_address;

gboolean
gum_stalker_is_supported (void)
{
  return TRUE;
}

void
gum_stalker_activate_experimental_unwind_support (void)
{
}

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_stalker_finalize;

  gum_thread_exit_address = gum_find_thread_exit_implementation ();
}

static void
gum_stalker_init (GumStalker * self)
{
  gsize page_size;

  self->exclusions = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->trust_threshold = 1;

  gum_spinlock_init (&self->probe_lock);
  self->probe_target_by_id = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  self->probe_array_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) g_ptr_array_unref);

  page_size = gum_query_page_size ();

  self->frames_size = page_size;
  g_assert (self->frames_size % sizeof (GumExecFrame) == 0);
  self->thunks_size = page_size;
  self->code_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_SIZE_INITIAL, page_size);
  self->data_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_DATA_SLAB_SIZE_INITIAL, page_size);
  self->code_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_SIZE_DYNAMIC, page_size);
  self->data_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_DATA_SLAB_SIZE_DYNAMIC, page_size);
  self->scratch_slab_size = GUM_ALIGN_SIZE (GUM_SCRATCH_SLAB_SIZE, page_size);
  self->ctx_header_size = GUM_ALIGN_SIZE (sizeof (GumExecCtx), page_size);
  self->ctx_size =
      self->ctx_header_size +
      self->frames_size +
      self->thunks_size +
      self->code_slab_size_initial +
      self->data_slab_size_initial +
      self->scratch_slab_size +
      0;

  self->frames_offset = self->ctx_header_size;
  self->thunks_offset = self->frames_offset + self->frames_size;
  self->code_slab_offset = self->thunks_offset + self->thunks_size;
  self->data_slab_offset =
      self->code_slab_offset + self->code_slab_size_initial;
  self->scratch_slab_offset =
      self->data_slab_offset + self->data_slab_size_initial;

  self->page_size = page_size;
  self->cpu_features = gum_query_cpu_features ();
  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;

  g_mutex_init (&self->mutex);
  self->contexts = NULL;
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
gum_stalker_is_call_excluding (GumExecCtx * ctx,
                               gconstpointer address)
{
  GArray * exclusions = ctx->stalker->exclusions;
  guint i;

  if (ctx->activation_target != NULL)
    return FALSE;

  if (gum_is_kuser_helper (address))
    return TRUE;

  for (i = 0; i != exclusions->len; i++)
  {
    GumMemoryRange * r = &g_array_index (exclusions, GumMemoryRange, i);

    if (GUM_MEMORY_RANGE_INCLUDES (r, GUM_ADDRESS (address)))
      return TRUE;
  }

  return FALSE;
}

static gboolean
gum_stalker_is_branch_excluding (GumExecCtx * ctx,
                                 gconstpointer address)
{
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

  return code_address;
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
  GumInfectContext * infect_
```