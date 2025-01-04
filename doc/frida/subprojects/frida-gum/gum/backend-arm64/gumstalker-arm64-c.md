Response:
The user wants a summary of the functionalities of the C source code file `gumstalker-arm64.c`. I need to identify the key responsibilities and components of this file based on the provided code. I should also look for connections to reverse engineering, low-level details (binary, OS kernel, etc.), logical reasoning (with input/output examples), common user errors, and debugging hints.

**Breakdown of the request:**

1. **List functionalities:**  This is the core request. I need to go through the code and identify the primary tasks performed by `gumstalker-arm64.c`.
2. **Relation to reverse engineering:**  Frida is a dynamic instrumentation toolkit used extensively in reverse engineering. I need to pinpoint how the functionalities of this specific file contribute to reverse engineering tasks.
3. **Binary/OS/Kernel/Framework knowledge:**  The file name suggests architecture-specific code (`arm64`). I need to identify areas where low-level system concepts are involved.
4. **Logical reasoning (input/output):**  If the code performs any transformations or decision-making, I need to provide hypothetical input and output scenarios to illustrate the logic.
5. **Common user errors:** Based on the code and its purpose, I need to anticipate potential mistakes users might make while interacting with or using the functionalities exposed (even indirectly) by this file.
6. **User operations leading here (debugging):**  I need to describe the steps a user might take within the Frida ecosystem that would ultimately involve this specific source file in the process.
7. **Summarize functionality (Part 1):** Finally, I need to synthesize the identified functionalities into a concise summary, keeping in mind this is part 1 of a larger file.

**High-level code analysis plan:**

* Look for key data structures (`struct`) and their members to understand the data being managed.
* Identify the main functions and their roles. Pay attention to functions starting with `gum_stalker_`, `gum_exec_ctx_`, `gum_exec_block_`, etc.
* Analyze the use of macros and constants (`#define`).
* Check for conditional compilation (`#ifdef`).
* Look for interactions with other Frida components (e.g., `GumArm64Writer`, `GumEventSink`).

**Specific areas to focus on:**

* Memory management (slabs).
* Code generation and manipulation.
* Instruction processing.
* Call interception and redirection.
* Context management.
* Exception handling.
```c
/*
 * Copyright (C) 2014-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 * Copyright (C) 2019 John Coates <john@johncoates.dev>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2024 Alex Soler <asoler@nowsecure.com>
 * Copyright (C) 2024 Sai Cao <1665673333@qq.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumstalker.h"

#include "gumarm64reader.h"
#include "gumarm64relocator.h"
#include "gumarm64writer.h"
#include "gumexceptor.h"
#include "gummemory.h"
#include "gummetalhash.h"
#include "gumspinlock.h"
#include "gumstalker-priv.h"
#ifdef HAVE_LINUX
# include "gum-init.h"
# include "guminterceptor.h"
#endif

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_LINUX
# include <unwind.h>
# include <sys/syscall.h>
#endif

#define GUM_CODE_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_CODE_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_SLOW_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_SLOW_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_DATA_SLAB_SIZE_INITIAL  (GUM_CODE_SLAB_SIZE_INITIAL / 5)
#define GUM_DATA_SLAB_SIZE_DYNAMIC  (GUM_CODE_SLAB_SIZE_DYNAMIC / 5)
#define GUM_SCRATCH_SLAB_SIZE       16384
#define GUM_EXEC_BLOCK_MIN_CAPACITY 2048
#define GUM_DATA_BLOCK_MIN_CAPACITY (sizeof (GumExecBlock) + 1024)

#define GUM_STACK_ALIGNMENT                16
#define GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE 40
#define GUM_RESTORATION_PROLOG_SIZE        4
#define GUM_EXCLUSIVE_ACCESS_MAX_DEPTH     8

#define GUM_IC_MAGIC_EMPTY                 0xbaadd00ddeadface

#define GUM_INSTRUCTION_OFFSET_NONE (-1)

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;
typedef struct _GumActivation GumActivation;
typedef struct _GumInvalidateContext GumInvalidateContext;
typedef struct _GumCallProbe GumCallProbe;

typedef struct _GumExecCtx GumExecCtx;
typedef void (* GumExecHelperWriteFunc) (GumExecCtx * ctx, GumArm64Writer * cw);
typedef struct _GumExecBlock GumExecBlock;
typedef guint GumExecBlockFlags;
typedef gpointer (* GumExecCtxReplaceCurrentBlockFunc) (
    GumExecBlock * block, gpointer start_address, gpointer from_insn);

typedef struct _GumCodeSlab GumCodeSlab;
typedef struct _GumSlowSlab GumSlowSlab;
typedef struct _GumDataSlab GumDataSlab;
typedef struct _GumSlab GumSlab;

typedef guint GumPrologType;
typedef guint GumCodeContext;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;
typedef struct _GumIcEntry GumIcEntry;

typedef guint GumVirtualizationRequirements;
typedef guint GumBackpatchType;

typedef struct _GumBackpatchCall GumBackpatchCall;
typedef struct _GumBackpatchJmp GumBackpatchJmp;
typedef struct _GumBackpatchInlineCache GumBackpatchInlineCache;
typedef struct _GumBackpatchExcludedCall GumBackpatchExcludedCall;

#ifdef HAVE_LINUX
typedef struct _Unwind_Exception _Unwind_Exception;
typedef struct _Unwind_Context _Unwind_Context;
struct dwarf_eh_bases;
#endif

enum
{
  PROP_0,
  PROP_IC_ENTRIES,
};

struct _GumStalker
{
  GObject parent;

  guint ic_entries;

  gsize ctx_size;
  gsize ctx_header_size;

  goffset thunks_offset;
  gsize thunks_size;

  goffset code_slab_offset;
  gsize code_slab_size_initial;
  gsize code_slab_size_dynamic;

  /*
   * The instrumented code which Stalker generates is split into two parts.
   * There is the part which is always run (the fast path) and the part which
   * is run only when attempting to find the next block and call the backpatcher
   * (the slow path). Backpatching is applied to the fast path so that
   * subsequent executions no longer need to transit the slow path.
   *
   * By separating the code in this way, we can improve the locality of the code
   * executing in the fast path. This has a performance benefit as well as
   * making the backpatched code much easier to read when working in the
   * debugger.
   *
   * The slow path makes use of its own slab and its own code writer.
   */
  goffset slow_slab_offset;
  gsize slow_slab_size_initial;
  gsize slow_slab_size_dynamic;

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

  GumExceptor * exceptor;
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

  GumArm64Writer code_writer;
  GumArm64Writer slow_writer;
  GumArm64Relocator relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerOutput * output);
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * event,
      GumCpuContext * cpu_context);
  GumStalkerObserver * observer;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gpointer pending_return_location;
  guint pending_calls;

  gpointer resume_at;
  gpointer return_at;
  gconstpointer activation_target;

  gpointer thunks;
  gpointer infect_thunk;
  GumAddress infect_body;

  GumSpinlock code_lock;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumDataSlab * data_slab;
  GumCodeSlab * scratch_slab;
  GumMetalHashTable * mappings;

  gpointer last_prolog_minimal;
  gpointer last_epilog_minimal;
  gpointer last_prolog_full;
  gpointer last_epilog_full;
  gpointer last_invalidator;

  /*
   * GumExecBlocks are attached to a singly linked list when they are generated,
   * this allows us to store other data in the data slab (rather than relying on
   * them being found in there in sequential order).
   */
  GumExecBlock * block_list;

  /*
   * Stalker for AArch64 no longer makes use of a shadow stack for handling
   * CALL/RET instructions, so we instead keep a count of the depth of the stack
   * here when GUM_CALL or GUM_RET events are enabled.
   */
  gint depth;

#ifdef HAVE_LINUX
  GumMetalHashTable * excluded_calls;
#endif
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumExecBlock
{
  /*
   * GumExecBlock instances are held in a singly linked list to allow them to be
   * disposed. This is necessary since other data may also be stored in the data
   * slab (e.g. inline caches) and hence we cannot simply rely on them being
   * contiguous.
   */
  GumExecBlock * next;

  GumExecCtx * ctx;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumExecBlock * storage_block;

  guint8 * real_start;
  guint8 * code_start;
  guint8 * slow_start;
  guint real_size;
  guint code_size;
  guint slow_size;
  guint capacity;
  guint last_callout_offset;

  GumExecBlockFlags flags;
  gint recycle_count;

  GumIcEntry * ic_entries;
};

enum _GumExecBlockFlags
{
  GUM_EXEC_BLOCK_ACTIVATION_TARGET     = 1 << 0,
  GUM_EXEC_BLOCK_HAS_EXCLUSIVE_LOAD    = 1 << 1,
  GUM_EXEC_BLOCK_HAS_EXCLUSIVE_STORE   = 1 << 2,
  GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS = 1 << 3,
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  guint memory_size;
  GumSlab * next;
};

struct _GumCodeSlab
{
  GumSlab slab;

  gpointer invalidator;
};

struct _GumSlowSlab
{
  GumSlab slab;

  gpointer invalidator;
};

struct _GumDataSlab
{
  GumSlab slab;
};

enum _GumPrologType
{
  GUM_PROLOG_NONE,
  GUM_PROLOG_MINIMAL,
  GUM_PROLOG_FULL
};

enum _GumCodeContext
{
  GUM_CODE_INTERRUPTIBLE,
  GUM_CODE_UNINTERRUPTIBLE
};

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  GumArm64Relocator * relocator;
  GumArm64Writer * code_writer;
  GumArm64Writer * slow_writer;
  gpointer continuation_real_address;
  GumPrologType opened_prolog;
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
  GumVirtualizationRequirements requirements;
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

struct _GumBranchTarget
{
  gpointer origin_ip;

  gpointer absolute_address;
  gssize relative_offset;

  arm64_reg reg;
};

struct _GumIcEntry
{
  gpointer real_start;
  gpointer code_start;
};

enum _GumVirtualizationRequirements
{
  GUM_REQUIRE_NOTHING          = 0,
  GUM_REQUIRE_RELOCATION       = 1 << 0,
};

enum _GumBackpatchType
{
  GUM_BACKPATCH_CALL,
  GUM_BACKPATCH_JMP,
  GUM_BACKPATCH_INLINE_CACHE,
  /*
   * On AArch64, immediate branches have limited range, and therefore indirect
   * branches are common. We therefore need to check dynamically whether these
   * are to excluded ranges to avoid stalking large amounts of code
   * unnecessarily.
   *
   * However, calling gum_stalker_is_excluding() repeatedly whenever an indirect
   * call is encountered would be expensive since it would be necessary to open
   * and close a prolog to preserve the register state. We therefore backpatch
   * any excluded calls into the same inline cache used for translating real
   * addresses into their instrumented blocks. We do this by setting the real
   * and instrumented addresses the same.
   *
   * However, since all instructions in AArch64 are 32-bits in length and 32-bit
   * aligned, we use the low bit of the instrumented address as a marker that
   * the call is to an excluded range, and we can therefore handle it
   * accordingly.
   *
   * Note, however, that unlike when we do something similar to handle returns
   * into the slab, we are dealing with real rather than instrumented addresses
   * for our excluded calls. Since the forkserver and it's child both share the
   * same address space, we can be certain that these real addresses will be the
   * same. Therefore unlike returns into the slab, these can also be prefetched.
   */
  GUM_BACKPATCH_EXCLUDED_CALL,
};

struct _GumBackpatchCall
{
  gsize code_offset;
  GumPrologType opened_prolog;
  gpointer ret_real_address;
};

struct _GumBackpatchJmp
{
  gsize code_offset;
  GumPrologType opened_prolog;
};

struct _GumBackpatchInlineCache
{
  guint8 dummy;
};

struct _GumBackpatchExcludedCall
{
  guint8 dummy;
};

struct _GumBackpatch
{
  GumBackpatchType type;
  gpointer to;
  gpointer from;
  gpointer from_insn;

  union
  {
    GumBackpatchCall call;
    GumBackpatchJmp jmp;
    GumBackpatchInlineCache inline_cache;
    GumBackpatchExcludedCall excluded_call;
  };
};

#ifdef HAVE_LINUX

extern _Unwind_Reason_Code __gxx_personality_v0 (int version,
    _Unwind_Action actions, uint64_t exception_class,
    _Unwind_Exception * unwind_exception, _Unwind_Context * context)
    __attribute__ ((weak));
extern const void * _Unwind_Find_FDE (const void * pc, struct dwarf_eh_bases *);
extern unsigned long _Unwind_GetIP (struct _Unwind_Context *);

static void gum_stalker_ensure_unwind_apis_instrumented (void);
static void gum_stalker_deinit_unwind_apis_instrumentation (void);
static _Unwind_Reason_Code gum_stalker_exception_personality (int version,
    _Unwind_Action actions, uint64_t exception_class,
    _Unwind_Exception * unwind_exception, _Unwind_Context * context);
static const void * gum_stalker_exception_find_fde (const void * pc,
    struct dwarf_eh_bases * bases);
static unsigned long gum_stalker_exception_get_ip (
    struct _Unwind_Context * context);

#endif

static void gum_stalker_dispose (GObject * object);
static void gum_stalker_finalize (GObject * object);
static void gum_stalker_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_stalker_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);

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
static gsize gum_stalker_get_ic_entry_size (GumStalker * self);

static void gum_stalker_thaw (GumStalker * self, gpointer code, gsize size);
static void gum_stalker_freeze (GumStalker * self, gpointer code, gsize size);

static gboolean gum_stalker_on_exception (GumExceptionDetails * details,
    gpointer user_data);

static GumExecCtx * gum_exec_ctx_new (GumStalker * self, GumThreadId thread_id,
    GumStalkerTransformer * transformer, GumEventSink * sink);
static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_dispose (GumExecCtx * ctx);
static GumCodeSlab * gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
    GumCodeSlab * code_slab);
static GumSlowSlab * gum_exec_ctx_add_slow_slab (GumExecCtx * ctx,
    GumSlowSlab * code_slab);
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
static void gum_exec_ctx_write_scratch_slab (GumExecCtx * ctx,
    GumExecBlock * block, guint * input_size, guint * output_size,
    guint * slow_size);
static void gum_exec_ctx_compile_block (GumExecCtx * ctx, GumExecBlock * block,
    gconstpointer input_code, gpointer output_code, GumAddress output_pc,
    guint * input_size, guint * output_size, guint * slow_size);
static void gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
    GumExecBlock * block);

static gboolean gum_stalker_iterator_is_out_of_space (
    GumStalkerIterator * self);

static void gum_stalker_invoke_callout (GumCalloutEntry * entry,
    GumCpuContext * cpu_context);

static void gum_exec_ctx_write_prolog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);

static void gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx);
static void gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
    GumPrologType type, GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
    GumPrologType type, GumArm64Writer * cw);
static void gum_exec_ctx_write_invalidator (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
    GumSlab * code_slab, GumSlab * slow_slab, GumArm64Writer * cw,
    gpointer * helper_ptr, GumExecHelperWriteFunc write);
static gboolean gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
    GumSlab * slab, GumArm64Writer * cw, gpointer * helper_ptr);

static void gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
    const GumBranchTarget * target, GumGeneratorContext * gc,
    GumArm64Writer * cw);
static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
    arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc, GumArm64Writer * cw);
static void gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc, GumArm64Writer * cw);
static void gum_exec_ctx_load_real_register_from_full_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc, GumArm64Writer * cw);

static gboolean gum_exec_ctx_try_handle_exception (GumExecCtx * ctx,
    GumExceptionDetails * details);
static void gum_exec_ctx_handle_stp (GumCpuContext * cpu_context,
    arm64_reg reg1, arm64_reg reg2, gsize offset);
static void gum_exec_ctx_handle_ldp (GumCpuContext * cpu_context,
    arm64_reg reg1, arm64_reg reg2, gsize offset);
static guint64 gum_exec_ctx_read_register (GumCpuContext * cpu_context,
    arm64_reg reg);
static void gum_exec_ctx_write_register (GumCpuContext * cpu_context,
    arm64_reg reg, guint64 value);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_maybe_create_new_code_slabs (GumExecCtx * ctx);
static void gum_exec_block_maybe_create_new_data_slab (GumExecCtx * ctx);
static void gum_exec_block_clear (GumExecBlock * block);
static gconstpointer gum_exec_block_check_address_for_exclusion (
    GumExecBlock * block, gconstpointer address);
static void gum_exec_block_commit (GumExecBlock * block);
static void gum_exec_block_invalidate (GumExecBlock * block);
static gpointer gum_exec_block_get_snapshot_start (GumExecBlock * block);
static GumCalloutEntry * gum_exec_block_get_last_callout_entry (
    const GumExecBlock * block);
static void gum_exec_block_set_last_callout_entry (GumExecBlock * block,
    GumCalloutEntry * entry);

static void gum_exec_block_write_jmp_to_block_start (GumExecBlock * block,
    gpointer block_start);

static void gum_exec_block_backpatch_call (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, gsize code_offset,
    GumPrologType opened_prolog, gpointer ret_real_address);
static void gum_exec_block_backpatch_jmp (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, gsize code_offset,
    GumPrologType opened_prolog);
static void gum_exec_block_backpatch_inline_cache (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn);

static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_sysenter_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
#ifdef HAVE_LINUX
static GumVirtualizationRequirements gum_exec_block_virtualize_linux_sysenter (
    GumExecBlock * block, GumGeneratorContext * gc);
static void gum_exec_block_put_aligned_syscall (GumExecBlock * block,
    GumGeneratorContext * gc, const cs_insn * insn);
#endif

static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_ctx_write_begin_call (GumExecCtx * ctx,
    GumArm64Writer * cw, gpointer ret_addr);
static void gum_exec_ctx_write_end_call (GumExecCtx * ctx, GumArm64Writer * cw);
static void gum_exec_block_backpatch_excluded_call (GumExecBlock * block,
    gpointer target, gpointer from_insn);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    const GumBranchTarget * target, GumExecCtxReplaceCurrentBlockFunc func,
    GumGeneratorContext * gc);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
    GumGeneratorContext * gc, arm64_reg ret_reg);
static void gum_exec_block_write_chaining_return_code (GumExecBlock * block,
    GumGeneratorContext * gc, arm64_reg ret_reg);
static void gum_exec_block_write_slab_transfer_code (GumArm64Writer * from,
    GumArm64Writer * to);
static void gum_exec_block_backpatch_slab (GumExecBlock * block,
    gpointer target);
static void gum_exec_block_maybe_inherit_exclusive_access_state (
    GumExecBlock * block, GumExecBlock * reference);
static void gum_exec_block_propagate_exclusive_access_state (
    GumExecBlock * block);
static void gum_exec_ctx_write_adjust_depth (GumExecCtx * ctx,
    GumArm64Writer * cw, gssize adj);
static arm64_reg gum_exec_block_write_inline_cache_code (
    GumExecBlock * block, arm64_reg target_reg, GumArm64Writer * cw,
    GumArm64Writer * cws);

static void gum_exec_block_write_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc,
    GumCodeContext cc);
static void gum_exec_block_write_ret_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
    GumGeneratorContext *
Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2014-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 * Copyright (C) 2019 John Coates <john@johncoates.dev>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2024 Alex Soler <asoler@nowsecure.com>
 * Copyright (C) 2024 Sai Cao <1665673333@qq.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumstalker.h"

#include "gumarm64reader.h"
#include "gumarm64relocator.h"
#include "gumarm64writer.h"
#include "gumexceptor.h"
#include "gummemory.h"
#include "gummetalhash.h"
#include "gumspinlock.h"
#include "gumstalker-priv.h"
#ifdef HAVE_LINUX
# include "gum-init.h"
# include "guminterceptor.h"
#endif

#include <stdlib.h>
#include <string.h>
#ifdef HAVE_LINUX
# include <unwind.h>
# include <sys/syscall.h>
#endif

#define GUM_CODE_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_CODE_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_SLOW_SLAB_SIZE_INITIAL  (128 * 1024)
#define GUM_SLOW_SLAB_SIZE_DYNAMIC  (4 * 1024 * 1024)
#define GUM_DATA_SLAB_SIZE_INITIAL  (GUM_CODE_SLAB_SIZE_INITIAL / 5)
#define GUM_DATA_SLAB_SIZE_DYNAMIC  (GUM_CODE_SLAB_SIZE_DYNAMIC / 5)
#define GUM_SCRATCH_SLAB_SIZE       16384
#define GUM_EXEC_BLOCK_MIN_CAPACITY 2048
#define GUM_DATA_BLOCK_MIN_CAPACITY (sizeof (GumExecBlock) + 1024)

#define GUM_STACK_ALIGNMENT                16
#define GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE 40
#define GUM_RESTORATION_PROLOG_SIZE        4
#define GUM_EXCLUSIVE_ACCESS_MAX_DEPTH     8

#define GUM_IC_MAGIC_EMPTY                 0xbaadd00ddeadface

#define GUM_INSTRUCTION_OFFSET_NONE (-1)

#define GUM_STALKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_STALKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

typedef struct _GumInfectContext GumInfectContext;
typedef struct _GumDisinfectContext GumDisinfectContext;
typedef struct _GumActivation GumActivation;
typedef struct _GumInvalidateContext GumInvalidateContext;
typedef struct _GumCallProbe GumCallProbe;

typedef struct _GumExecCtx GumExecCtx;
typedef void (* GumExecHelperWriteFunc) (GumExecCtx * ctx, GumArm64Writer * cw);
typedef struct _GumExecBlock GumExecBlock;
typedef guint GumExecBlockFlags;
typedef gpointer (* GumExecCtxReplaceCurrentBlockFunc) (
    GumExecBlock * block, gpointer start_address, gpointer from_insn);

typedef struct _GumCodeSlab GumCodeSlab;
typedef struct _GumSlowSlab GumSlowSlab;
typedef struct _GumDataSlab GumDataSlab;
typedef struct _GumSlab GumSlab;

typedef guint GumPrologType;
typedef guint GumCodeContext;
typedef struct _GumGeneratorContext GumGeneratorContext;
typedef struct _GumCalloutEntry GumCalloutEntry;
typedef struct _GumInstruction GumInstruction;
typedef struct _GumBranchTarget GumBranchTarget;
typedef struct _GumIcEntry GumIcEntry;

typedef guint GumVirtualizationRequirements;
typedef guint GumBackpatchType;

typedef struct _GumBackpatchCall GumBackpatchCall;
typedef struct _GumBackpatchJmp GumBackpatchJmp;
typedef struct _GumBackpatchInlineCache GumBackpatchInlineCache;
typedef struct _GumBackpatchExcludedCall GumBackpatchExcludedCall;

#ifdef HAVE_LINUX
typedef struct _Unwind_Exception _Unwind_Exception;
typedef struct _Unwind_Context _Unwind_Context;
struct dwarf_eh_bases;
#endif

enum
{
  PROP_0,
  PROP_IC_ENTRIES,
};

struct _GumStalker
{
  GObject parent;

  guint ic_entries;

  gsize ctx_size;
  gsize ctx_header_size;

  goffset thunks_offset;
  gsize thunks_size;

  goffset code_slab_offset;
  gsize code_slab_size_initial;
  gsize code_slab_size_dynamic;

  /*
   * The instrumented code which Stalker generates is split into two parts.
   * There is the part which is always run (the fast path) and the part which
   * is run only when attempting to find the next block and call the backpatcher
   * (the slow path). Backpatching is applied to the fast path so that
   * subsequent executions no longer need to transit the slow path.
   *
   * By separating the code in this way, we can improve the locality of the code
   * executing in the fast path. This has a performance benefit as well as
   * making the backpatched code much easier to read when working in the
   * debugger.
   *
   * The slow path makes use of its own slab and its own code writer.
   */
  goffset slow_slab_offset;
  gsize slow_slab_size_initial;
  gsize slow_slab_size_dynamic;

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

  GumExceptor * exceptor;
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

  GumArm64Writer code_writer;
  GumArm64Writer slow_writer;
  GumArm64Relocator relocator;

  GumStalkerTransformer * transformer;
  void (* transform_block_impl) (GumStalkerTransformer * self,
      GumStalkerIterator * iterator, GumStalkerOutput * output);
  GumEventSink * sink;
  gboolean sink_started;
  GumEventType sink_mask;
  void (* sink_process_impl) (GumEventSink * self, const GumEvent * event,
      GumCpuContext * cpu_context);
  GumStalkerObserver * observer;

  gboolean unfollow_called_while_still_following;
  GumExecBlock * current_block;
  gpointer pending_return_location;
  guint pending_calls;

  gpointer resume_at;
  gpointer return_at;
  gconstpointer activation_target;

  gpointer thunks;
  gpointer infect_thunk;
  GumAddress infect_body;

  GumSpinlock code_lock;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumDataSlab * data_slab;
  GumCodeSlab * scratch_slab;
  GumMetalHashTable * mappings;

  gpointer last_prolog_minimal;
  gpointer last_epilog_minimal;
  gpointer last_prolog_full;
  gpointer last_epilog_full;
  gpointer last_invalidator;

  /*
   * GumExecBlocks are attached to a singly linked list when they are generated,
   * this allows us to store other data in the data slab (rather than relying on
   * them being found in there in sequential order).
   */
  GumExecBlock * block_list;

  /*
   * Stalker for AArch64 no longer makes use of a shadow stack for handling
   * CALL/RET instructions, so we instead keep a count of the depth of the stack
   * here when GUM_CALL or GUM_RET events are enabled.
   */
  gint depth;

#ifdef HAVE_LINUX
  GumMetalHashTable * excluded_calls;
#endif
};

enum _GumExecCtxState
{
  GUM_EXEC_CTX_ACTIVE,
  GUM_EXEC_CTX_UNFOLLOW_PENDING,
  GUM_EXEC_CTX_DESTROY_PENDING
};

struct _GumExecBlock
{
  /*
   * GumExecBlock instances are held in a singly linked list to allow them to be
   * disposed. This is necessary since other data may also be stored in the data
   * slab (e.g. inline caches) and hence we cannot simply rely on them being
   * contiguous.
   */
  GumExecBlock * next;

  GumExecCtx * ctx;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumExecBlock * storage_block;

  guint8 * real_start;
  guint8 * code_start;
  guint8 * slow_start;
  guint real_size;
  guint code_size;
  guint slow_size;
  guint capacity;
  guint last_callout_offset;

  GumExecBlockFlags flags;
  gint recycle_count;

  GumIcEntry * ic_entries;
};

enum _GumExecBlockFlags
{
  GUM_EXEC_BLOCK_ACTIVATION_TARGET     = 1 << 0,
  GUM_EXEC_BLOCK_HAS_EXCLUSIVE_LOAD    = 1 << 1,
  GUM_EXEC_BLOCK_HAS_EXCLUSIVE_STORE   = 1 << 2,
  GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS = 1 << 3,
};

struct _GumSlab
{
  guint8 * data;
  guint offset;
  guint size;
  guint memory_size;
  GumSlab * next;
};

struct _GumCodeSlab
{
  GumSlab slab;

  gpointer invalidator;
};

struct _GumSlowSlab
{
  GumSlab slab;

  gpointer invalidator;
};

struct _GumDataSlab
{
  GumSlab slab;
};

enum _GumPrologType
{
  GUM_PROLOG_NONE,
  GUM_PROLOG_MINIMAL,
  GUM_PROLOG_FULL
};

enum _GumCodeContext
{
  GUM_CODE_INTERRUPTIBLE,
  GUM_CODE_UNINTERRUPTIBLE
};

struct _GumGeneratorContext
{
  GumInstruction * instruction;
  GumArm64Relocator * relocator;
  GumArm64Writer * code_writer;
  GumArm64Writer * slow_writer;
  gpointer continuation_real_address;
  GumPrologType opened_prolog;
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
  GumVirtualizationRequirements requirements;
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

struct _GumBranchTarget
{
  gpointer origin_ip;

  gpointer absolute_address;
  gssize relative_offset;

  arm64_reg reg;
};

struct _GumIcEntry
{
  gpointer real_start;
  gpointer code_start;
};

enum _GumVirtualizationRequirements
{
  GUM_REQUIRE_NOTHING          = 0,
  GUM_REQUIRE_RELOCATION       = 1 << 0,
};

enum _GumBackpatchType
{
  GUM_BACKPATCH_CALL,
  GUM_BACKPATCH_JMP,
  GUM_BACKPATCH_INLINE_CACHE,
  /*
   * On AArch64, immediate branches have limited range, and therefore indirect
   * branches are common. We therefore need to check dynamically whether these
   * are to excluded ranges to avoid stalking large amounts of code
   * unnecessarily.
   *
   * However, calling gum_stalker_is_excluding() repeatedly whenever an indirect
   * call is encountered would be expensive since it would be necessary to open
   * and close a prolog to preserve the register state. We therefore backpatch
   * any excluded calls into the same inline cache used for translating real
   * addresses into their instrumented blocks. We do this by setting the real
   * and instrumented addresses the same.
   *
   * However, since all instructions in AArch64 are 32-bits in length and 32-bit
   * aligned, we use the low bit of the instrumented address as a marker that
   * the call is to an excluded range, and we can therefore handle it
   * accordingly.
   *
   * Note, however, that unlike when we do something similar to handle returns
   * into the slab, we are dealing with real rather than instrumented addresses
   * for our excluded calls. Since the forkserver and it's child both share the
   * same address space, we can be certain that these real addresses will be the
   * same. Therefore unlike returns into the slab, these can also be prefetched.
   */
  GUM_BACKPATCH_EXCLUDED_CALL,
};

struct _GumBackpatchCall
{
  gsize code_offset;
  GumPrologType opened_prolog;
  gpointer ret_real_address;
};

struct _GumBackpatchJmp
{
  gsize code_offset;
  GumPrologType opened_prolog;
};

struct _GumBackpatchInlineCache
{
  guint8 dummy;
};

struct _GumBackpatchExcludedCall
{
  guint8 dummy;
};

struct _GumBackpatch
{
  GumBackpatchType type;
  gpointer to;
  gpointer from;
  gpointer from_insn;

  union
  {
    GumBackpatchCall call;
    GumBackpatchJmp jmp;
    GumBackpatchInlineCache inline_cache;
    GumBackpatchExcludedCall excluded_call;
  };
};

#ifdef HAVE_LINUX

extern _Unwind_Reason_Code __gxx_personality_v0 (int version,
    _Unwind_Action actions, uint64_t exception_class,
    _Unwind_Exception * unwind_exception, _Unwind_Context * context)
    __attribute__ ((weak));
extern const void * _Unwind_Find_FDE (const void * pc, struct dwarf_eh_bases *);
extern unsigned long _Unwind_GetIP (struct _Unwind_Context *);

static void gum_stalker_ensure_unwind_apis_instrumented (void);
static void gum_stalker_deinit_unwind_apis_instrumentation (void);
static _Unwind_Reason_Code gum_stalker_exception_personality (int version,
    _Unwind_Action actions, uint64_t exception_class,
    _Unwind_Exception * unwind_exception, _Unwind_Context * context);
static const void * gum_stalker_exception_find_fde (const void * pc,
    struct dwarf_eh_bases * bases);
static unsigned long gum_stalker_exception_get_ip (
    struct _Unwind_Context * context);

#endif

static void gum_stalker_dispose (GObject * object);
static void gum_stalker_finalize (GObject * object);
static void gum_stalker_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_stalker_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);

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
static gsize gum_stalker_get_ic_entry_size (GumStalker * self);

static void gum_stalker_thaw (GumStalker * self, gpointer code, gsize size);
static void gum_stalker_freeze (GumStalker * self, gpointer code, gsize size);

static gboolean gum_stalker_on_exception (GumExceptionDetails * details,
    gpointer user_data);

static GumExecCtx * gum_exec_ctx_new (GumStalker * self, GumThreadId thread_id,
    GumStalkerTransformer * transformer, GumEventSink * sink);
static void gum_exec_ctx_free (GumExecCtx * ctx);
static void gum_exec_ctx_dispose (GumExecCtx * ctx);
static GumCodeSlab * gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
    GumCodeSlab * code_slab);
static GumSlowSlab * gum_exec_ctx_add_slow_slab (GumExecCtx * ctx,
    GumSlowSlab * code_slab);
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
static void gum_exec_ctx_write_scratch_slab (GumExecCtx * ctx,
    GumExecBlock * block, guint * input_size, guint * output_size,
    guint * slow_size);
static void gum_exec_ctx_compile_block (GumExecCtx * ctx, GumExecBlock * block,
    gconstpointer input_code, gpointer output_code, GumAddress output_pc,
    guint * input_size, guint * output_size, guint * slow_size);
static void gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
    GumExecBlock * block);

static gboolean gum_stalker_iterator_is_out_of_space (
    GumStalkerIterator * self);

static void gum_stalker_invoke_callout (GumCalloutEntry * entry,
    GumCpuContext * cpu_context);

static void gum_exec_ctx_write_prolog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog (GumExecCtx * ctx, GumPrologType type,
    GumArm64Writer * cw);

static void gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx);
static void gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
    GumPrologType type, GumArm64Writer * cw);
static void gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
    GumPrologType type, GumArm64Writer * cw);
static void gum_exec_ctx_write_invalidator (GumExecCtx * ctx,
    GumArm64Writer * cw);
static void gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
    GumSlab * code_slab, GumSlab * slow_slab, GumArm64Writer * cw,
    gpointer * helper_ptr, GumExecHelperWriteFunc write);
static gboolean gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
    GumSlab * slab, GumArm64Writer * cw, gpointer * helper_ptr);

static void gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
    const GumBranchTarget * target, GumGeneratorContext * gc,
    GumArm64Writer * cw);
static void gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
    arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc, GumArm64Writer * cw);
static void gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc, GumArm64Writer * cw);
static void gum_exec_ctx_load_real_register_from_full_frame_into (
    GumExecCtx * ctx, arm64_reg target_register, arm64_reg source_register,
    GumGeneratorContext * gc, GumArm64Writer * cw);

static gboolean gum_exec_ctx_try_handle_exception (GumExecCtx * ctx,
    GumExceptionDetails * details);
static void gum_exec_ctx_handle_stp (GumCpuContext * cpu_context,
    arm64_reg reg1, arm64_reg reg2, gsize offset);
static void gum_exec_ctx_handle_ldp (GumCpuContext * cpu_context,
    arm64_reg reg1, arm64_reg reg2, gsize offset);
static guint64 gum_exec_ctx_read_register (GumCpuContext * cpu_context,
    arm64_reg reg);
static void gum_exec_ctx_write_register (GumCpuContext * cpu_context,
    arm64_reg reg, guint64 value);

static GumExecBlock * gum_exec_block_new (GumExecCtx * ctx);
static void gum_exec_block_maybe_create_new_code_slabs (GumExecCtx * ctx);
static void gum_exec_block_maybe_create_new_data_slab (GumExecCtx * ctx);
static void gum_exec_block_clear (GumExecBlock * block);
static gconstpointer gum_exec_block_check_address_for_exclusion (
    GumExecBlock * block, gconstpointer address);
static void gum_exec_block_commit (GumExecBlock * block);
static void gum_exec_block_invalidate (GumExecBlock * block);
static gpointer gum_exec_block_get_snapshot_start (GumExecBlock * block);
static GumCalloutEntry * gum_exec_block_get_last_callout_entry (
    const GumExecBlock * block);
static void gum_exec_block_set_last_callout_entry (GumExecBlock * block,
    GumCalloutEntry * entry);

static void gum_exec_block_write_jmp_to_block_start (GumExecBlock * block,
    gpointer block_start);

static void gum_exec_block_backpatch_call (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, gsize code_offset,
    GumPrologType opened_prolog, gpointer ret_real_address);
static void gum_exec_block_backpatch_jmp (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn, gsize code_offset,
    GumPrologType opened_prolog);
static void gum_exec_block_backpatch_inline_cache (GumExecBlock * block,
    GumExecBlock * from, gpointer from_insn);

static GumVirtualizationRequirements gum_exec_block_virtualize_branch_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_ret_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
static GumVirtualizationRequirements gum_exec_block_virtualize_sysenter_insn (
    GumExecBlock * block, GumGeneratorContext * gc);
#ifdef HAVE_LINUX
static GumVirtualizationRequirements gum_exec_block_virtualize_linux_sysenter (
    GumExecBlock * block, GumGeneratorContext * gc);
static void gum_exec_block_put_aligned_syscall (GumExecBlock * block,
    GumGeneratorContext * gc, const cs_insn * insn);
#endif

static void gum_exec_block_write_call_invoke_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc);
static void gum_exec_ctx_write_begin_call (GumExecCtx * ctx,
    GumArm64Writer * cw, gpointer ret_addr);
static void gum_exec_ctx_write_end_call (GumExecCtx * ctx, GumArm64Writer * cw);
static void gum_exec_block_backpatch_excluded_call (GumExecBlock * block,
    gpointer target, gpointer from_insn);
static void gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
    const GumBranchTarget * target, GumExecCtxReplaceCurrentBlockFunc func,
    GumGeneratorContext * gc);
static void gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
    GumGeneratorContext * gc, arm64_reg ret_reg);
static void gum_exec_block_write_chaining_return_code (GumExecBlock * block,
    GumGeneratorContext * gc, arm64_reg ret_reg);
static void gum_exec_block_write_slab_transfer_code (GumArm64Writer * from,
    GumArm64Writer * to);
static void gum_exec_block_backpatch_slab (GumExecBlock * block,
    gpointer target);
static void gum_exec_block_maybe_inherit_exclusive_access_state (
    GumExecBlock * block, GumExecBlock * reference);
static void gum_exec_block_propagate_exclusive_access_state (
    GumExecBlock * block);
static void gum_exec_ctx_write_adjust_depth (GumExecCtx * ctx,
    GumArm64Writer * cw, gssize adj);
static arm64_reg gum_exec_block_write_inline_cache_code (
    GumExecBlock * block, arm64_reg target_reg, GumArm64Writer * cw,
    GumArm64Writer * cws);

static void gum_exec_block_write_call_event_code (GumExecBlock * block,
    const GumBranchTarget * target, GumGeneratorContext * gc,
    GumCodeContext cc);
static void gum_exec_block_write_ret_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_exec_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_block_event_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);
static void gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
    GumGeneratorContext * gc, GumCodeContext cc);

static void gum_exec_block_maybe_write_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_write_call_probe_code (GumExecBlock * block,
    GumGeneratorContext * gc);
static void gum_exec_block_invoke_call_probes (GumExecBlock * block,
    GumCpuContext * cpu_context);

static void gum_exec_block_write_exec_generated_code (GumArm64Writer * cw,
    GumExecCtx * ctx);

static gpointer gum_exec_block_write_inline_data (GumArm64Writer * cw,
    gconstpointer data, gsize size, GumAddress * address);

static void gum_exec_block_open_prolog (GumExecBlock * block,
    GumPrologType type, GumGeneratorContext * gc, GumArm64Writer * cw);
static void gum_exec_block_close_prolog (GumExecBlock * block,
    GumGeneratorContext * gc, GumArm64Writer * cw);

static GumCodeSlab * gum_code_slab_new (GumExecCtx * ctx);
static void gum_code_slab_free (GumCodeSlab * code_slab);
static void gum_code_slab_init (GumCodeSlab * code_slab, gsize slab_size,
    gsize memory_size, gsize page_size);
static void gum_slow_slab_init (GumSlowSlab * slow_slab, gsize slab_size,
    gsize memory_size, gsize page_size);

static GumDataSlab * gum_data_slab_new (GumExecCtx * ctx);
static void gum_data_slab_free (GumDataSlab * data_slab);
static void gum_data_slab_init (GumDataSlab * data_slab, gsize slab_size,
    gsize memory_size);

static void gum_scratch_slab_init (GumCodeSlab * scratch_slab, gsize slab_size);

static void gum_slab_free (GumSlab * slab);
static void gum_slab_init (GumSlab * slab, gsize slab_size, gsize memory_size,
    gsize header_size);
static gsize gum_slab_available (GumSlab * self);
static gpointer gum_slab_start (GumSlab * self);
static gpointer gum_slab_end (GumSlab * self);
static gpointer gum_slab_cursor (GumSlab * self);
static gpointer gum_slab_reserve (GumSlab * self, gsize size);
static gpointer gum_slab_try_reserve (GumSlab * self, gsize size);

static gpointer gum_find_thread_exit_implementation (void);

static gboolean gum_is_bl_imm (guint32 insn) G_GNUC_UNUSED;

G_DEFINE_TYPE (GumStalker, gum_stalker, G_TYPE_OBJECT)

static GPrivate gum_stalker_exec_ctx_private;

static gpointer gum_unfollow_me_address;
static gpointer gum_deactivate_address;
static gpointer gum_thread_exit_address;

#ifdef HAVE_LINUX
static GumInterceptor * gum_exec_ctx_interceptor = NULL;
#endif

gboolean
gum_stalker_is_supported (void)
{
  return TRUE;
}

void
gum_stalker_activate_experimental_unwind_support (void)
{
#ifdef HAVE_LINUX
  gum_stalker_ensure_unwind_apis_instrumented ();
#endif
}

static void
gum_stalker_class_init (GumStalkerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_stalker_dispose;
  object_class->finalize = gum_stalker_finalize;
  object_class->get_property = gum_stalker_get_property;
  object_class->set_property = gum_stalker_set_property;

  g_object_class_install_property (object_class, PROP_IC_ENTRIES,
      g_param_spec_uint ("ic-entries", "IC Entries", "Inline Cache Entries",
      2, 32, 2, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));

  gum_unfollow_me_address = gum_strip_code_pointer (gum_stalker_unfollow_me);
  gum_deactivate_address = gum_strip_code_pointer (gum_stalker_deactivate);
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

  self->thunks_size = page_size;
  self->code_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_SIZE_INITIAL, page_size);
  self->slow_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_SLOW_SLAB_SIZE_INITIAL, page_size);
  self->data_slab_size_initial =
      GUM_ALIGN_SIZE (GUM_DATA_SLAB_SIZE_INITIAL, page_size);
  self->code_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_CODE_SLAB_SIZE_DYNAMIC, page_size);
  self->slow_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_SLOW_SLAB_SIZE_DYNAMIC, page_size);
  self->data_slab_size_dynamic =
      GUM_ALIGN_SIZE (GUM_DATA_SLAB_SIZE_DYNAMIC, page_size);
  self->scratch_slab_size = GUM_ALIGN_SIZE (GUM_SCRATCH_SLAB_SIZE, page_size);
  self->ctx_header_size = GUM_ALIGN_SIZE (sizeof (GumExecCtx), page_size);
  self->ctx_size =
      self->ctx_header_size +
      self->thunks_size +
      self->code_slab_size_initial +
      self->slow_slab_size_initial +
      self->data_slab_size_initial +
      self->scratch_slab_size +
      0;

  self->thunks_offset = self->ctx_header_size;
  self->code_slab_offset = self->thunks_offset + self->thunks_size;
  self->slow_slab_offset =
      self->code_slab_offset + self->code_slab_size_initial;
  self->data_slab_offset =
      self->slow_slab_offset + self->slow_slab_size_initial;
  self->scratch_slab_offset =
      self->data_slab_offset + self->data_slab_size_initial;

  self->page_size = page_size;
  self->cpu_features = gum_query_cpu_features ();
  self->is_rwx_supported = gum_query_rwx_support () != GUM_RWX_NONE;

  g_mutex_init (&self->mutex);
  self->contexts = NULL;

  self->exceptor = gum_exceptor_obtain ();
  gum_exceptor_add (self->exceptor, gum_stalker_on_exception, self);
}

#ifdef HAVE_LINUX

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

    res = gum_interceptor_replace (gum_exec_ctx_interceptor,
        _Unwind_GetIP, gum_stalker_exception_get_ip, NULL, NULL);
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
  gum_interceptor_revert (gum_exec_ctx_interceptor, _Unwind_GetIP);
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
    return __gxx_personality_v0 (version, actions,
"""


```