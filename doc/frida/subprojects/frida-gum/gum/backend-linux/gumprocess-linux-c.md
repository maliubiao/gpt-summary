Response:
The user wants a functional summary of the provided C source code file, `gumprocess-linux.c`, which is part of the Frida dynamic instrumentation toolkit. The summary should also highlight connections to reverse engineering, low-level Linux/Android knowledge, logical inferences, potential user errors, and debugging context.

**Plan:**

1. **High-level Overview:** Identify the main purpose of the file. Based on the name and includes, it likely deals with process-related operations on Linux.
2. **Key Functionalities:** Scan the code for major functions and their roles. Focus on `gum_process_*` functions and other significant static functions.
3. **Reverse Engineering Relevance:** Look for features that are commonly used in reverse engineering, such as accessing process memory, registers, and modifying execution flow.
4. **Low-Level Details:** Identify interactions with Linux kernel interfaces (syscalls, `/proc` filesystem, `ptrace`), and architecture-specific structures (register structures). Note any Android-specific aspects.
5. **Logical Inferences:**  Point out any conditional logic or assumptions made in the code.
6. **User Errors:** Consider scenarios where incorrect usage of Frida or the underlying OS might lead to problems.
7. **Debugging Context:** Explain how a user might end up interacting with this code through Frida.
8. **Summarize Functionality (Part 1):** Condense the identified functionalities into a concise summary for the first part of the file.
```
这是目录为frida/subprojects/frida-gum/gum/backend-linux/gumprocess-linux.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能,
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023-2024 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "backend-elf/gumprocess-elf.h"
#include "gum-init.h"
#include "gum/gumandroid.h"
#include "gum/gumlinux.h"
#include "gumelfmodule.h"
#include "gumlinux-priv.h"
#include "gummodulemap.h"
#include "valgrind.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_PTHREAD_ATTR_GETSTACK
# include <pthread.h>
#endif
#ifdef HAVE_LINK_H
# include <link.h>
#endif
#ifdef HAVE_ASM_PRCTL_H
# include <asm/prctl.h>
#endif
#include <sys/prctl.h>
#include <sys/ptrace.h>
#ifdef HAVE_ASM_PTRACE_H
# include <asm/ptrace.h>
#endif
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif

#define GUM_PAGE_START(value, page_size) \
    (GUM_ADDRESS (value) & ~GUM_ADDRESS (page_size - 1))

#ifndef O_CLOEXEC
# define O_CLOEXEC 0x80000
#endif

#define GUM_PSR_THUMB 0x20

#if defined (HAVE_I386)
typedef struct user_regs_struct GumGPRegs;
typedef struct _GumX86DebugRegs GumDebugRegs;
#elif defined (HAVE_ARM)
typedef struct pt_regs GumGPRegs;
typedef struct _GumArmDebugRegs GumDebugRegs;
#elif defined (HAVE_ARM64)
typedef struct user_pt_regs GumGPRegs;
typedef struct _GumArm64DebugRegs GumDebugRegs;
#elif defined (HAVE_MIPS)
typedef struct pt_regs GumGPRegs;
typedef struct _GumMipsDebugRegs GumDebugRegs;
#else
# error Unsupported architecture
#endif
typedef guint GumMipsWatchStyle;
typedef struct _GumMips32WatchRegs GumMips32WatchRegs;
typedef struct _GumMips64WatchRegs GumMips64WatchRegs;
typedef union _GumRegs GumRegs;
#ifndef PTRACE_GETREGS
# define PTRACE_GETREGS 12
#endif
#ifndef PTRACE_SETREGS
# define PTRACE_SETREGS 13
#endif
#ifndef PTRACE_GETHBPREGS
# define PTRACE_GETHBPREGS 29
#endif
#ifndef PTRACE_SETHBPREGS
# define PTRACE_SETHBPREGS 30
#endif
#ifndef PTRACE_GET_WATCH_REGS
# define PTRACE_GET_WATCH_REGS 0xd0
#endif
#ifndef PTRACE_SET_WATCH_REGS
# define PTRACE_SET_WATCH_REGS 0xd1
#endif
#ifndef PTRACE_GETREGSET
# define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
# define PTRACE_SETREGSET 0x4205
#endif
#ifndef PR_SET_PTRACER
# define PR_SET_PTRACER 0x59616d61
#endif
#ifndef NT_PRSTATUS
# define NT_PRSTATUS 1
#endif

#define GUM_TEMP_FAILURE_RETRY(expression) \
    ({ \
      gssize __result; \
      \
      do __result = (gssize) (expression); \
      while (__result == -EINTR); \
      \
      __result; \
    })

typedef struct _GumProgramModules GumProgramModules;
typedef guint GumProgramRuntimeLinker;
typedef struct _GumProgramRanges GumProgramRanges;
typedef ElfW(auxv_t) * (* GumReadAuxvFunc) (void);

typedef struct _GumModifyThreadContext GumModifyThreadContext;
typedef void (* GumLinuxModifyThreadFunc) (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
typedef struct _GumLinuxModifyThreadContext GumLinuxModifyThreadContext;
typedef guint GumLinuxRegsType;
typedef guint8 GumModifyThreadAck;

typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;
typedef struct _GumResolveModuleNameContext GumResolveModuleNameContext;

typedef gint (* GumFoundDlPhdrFunc) (struct dl_phdr_info * info,
    gsize size, gpointer data);
typedef void (* GumDlIteratePhdrImpl) (GumFoundDlPhdrFunc func, gpointer data);

typedef struct _GumSetHardwareBreakpointContext GumSetHardwareBreakpointContext;
typedef struct _GumSetHardwareWatchpointContext GumSetHardwareWatchpointContext;

typedef struct _GumUserDesc GumUserDesc;
typedef struct _GumTcbHead GumTcbHead;

typedef gint (* GumCloneFunc) (gpointer arg);

struct _GumProgramModules
{
  GumModuleDetails program;
  GumModuleDetails interpreter;
  GumModuleDetails vdso;
  GumProgramRuntimeLinker rtld;
};

enum _GumProgramRuntimeLinker
{
  GUM_PROGRAM_RTLD_NONE,
  GUM_PROGRAM_RTLD_SHARED,
};

struct _GumProgramRanges
{
  GumMemoryRange program;
  GumMemoryRange interpreter;
  GumMemoryRange vdso;
};

struct _GumModifyThreadContext
{
  GumModifyThreadFunc func;
  gpointer user_data;
};

enum _GumLinuxRegsType
{
  GUM_REGS_GENERAL_PURPOSE,
  GUM_REGS_DEBUG_BREAK,
  GUM_REGS_DEBUG_WATCH,
};

struct _GumX86DebugRegs
{
  gsize dr0;
  gsize dr1;
  gsize dr2;
  gsize dr3;
  gsize dr6;
  gsize dr7;
};

struct _GumArmDebugRegs
{
  guint32 cr[16];
  guint32 vr[16];
};

struct _GumArm64DebugRegs
{
  guint64 cr[16];
  guint64 vr[16];
};

enum _GumMipsWatchStyle
{
  GUM_MIPS_WATCH_MIPS32,
  GUM_MIPS_WATCH_MIPS64,
};

struct _GumMips32WatchRegs
{
  guint32 watch_lo[8];
  guint16 watch_hi[8];
  guint16 watch_masks[8];
  guint32 num_valid;
} __attribute__ ((aligned (8)));

struct _GumMips64WatchRegs
{
  guint64 watch_lo[8];
  guint16 watch_hi[8];
  guint16 watch_masks[8];
  guint32 num_valid;
} __attribute__ ((aligned (8)));

struct _GumMipsDebugRegs
{
  GumMipsWatchStyle style;
  union
  {
    GumMips32WatchRegs mips32;
    GumMips64WatchRegs mips64;
  };
};

union _GumRegs
{
  GumGPRegs gp;
  GumDebugRegs debug;
};

enum _GumModifyThreadAck
{
  GUM_ACK_READY = 1,
  GUM_ACK_READ_REGISTERS,
  GUM_ACK_MODIFIED_REGISTERS,
  GUM_ACK_WROTE_REGISTERS,
  GUM_ACK_FAILED_TO_ATTACH,
  GUM_ACK_FAILED_TO_WAIT,
  GUM_ACK_FAILED_TO_STOP,
  GUM_ACK_FAILED_TO_READ,
  GUM_ACK_FAILED_TO_WRITE,
  GUM_ACK_FAILED_TO_DETACH
};

struct _GumLinuxModifyThreadContext
{
  GumThreadId thread_id;
  GumLinuxRegsType regs_type;
  GumLinuxModifyThreadFunc func;
  gpointer user_data;

  gint fd[2];
  GumRegs regs_data;
};

struct _GumEnumerateModulesContext
{
  GumFoundModuleFunc func;
  gpointer user_data;

  GHashTable * named_ranges;
};

struct _GumEmitExecutableModuleContext
{
  const gchar * executable_path;
  GumFoundModuleFunc func;
  gpointer user_data;

  gboolean carry_on;
};

struct _GumResolveModuleNameContext
{
  const gchar * name;
  GumAddress known_address;
  gchar * path;
  GumAddress base;
};

struct _GumSetHardwareBreakpointContext
{
  guint breakpoint_id;
  GumAddress address;
};

struct _GumSetHardwareWatchpointContext
{
  guint watchpoint_id;
  GumAddress address;
  gsize size;
  GumWatchConditions conditions;
};

struct _GumUserDesc
{
  guint entry_number;
  guint base_addr;
  guint limit;
  guint seg_32bit : 1;
  guint contents : 2;
  guint read_exec_only : 1;
  guint limit_in_pages : 1;
  guint seg_not_present : 1;
  guint useable : 1;
};

struct _GumTcbHead
{
#ifdef HAVE_I386
  gpointer tcb;
  gpointer dtv;
  gpointer self;
#else
  gpointer dtv;
  gpointer priv;
#endif
};

static void gum_deinit_program_modules (void);
static gboolean gum_query_program_ranges (GumReadAuxvFunc read_auxv,
    GumProgramRanges * ranges);
static ElfW(auxv_t) * gum_read_auxv_from_proc (void);
static ElfW(auxv_t) * gum_read_auxv_from_stack (void);
static gboolean gum_query_main_thread_stack_range (GumMemoryRange * range);
static void gum_compute_elf_range_from_ehdr (const ElfW(Ehdr) * ehdr,
    GumMemoryRange * range);
static void gum_compute_elf_range_from_phdrs (const ElfW(Phdr) * phdrs,
    ElfW(Half) phdr_size, ElfW(Half) phdr_count, GumAddress base_address,
    GumMemoryRange * range);

static gchar * gum_try_init_libc_name (void);
static gboolean gum_try_resolve_dynamic_symbol (const gchar * name,
    Dl_info * info);
static void gum_deinit_libc_name (void);

static void gum_do_modify_thread (GumThreadId thread_id, GumRegs * regs,
    gpointer user_data);
static gboolean gum_linux_modify_thread (GumThreadId thread_id,
    GumLinuxRegsType regs_type, GumLinuxModifyThreadFunc func,
    gpointer user_data, GError ** error);
static gpointer gum_linux_handle_modify_thread_comms (gpointer data);
static gint gum_linux_do_modify_thread (gpointer data);
static gboolean gum_await_ack (gint fd, GumModifyThreadAck expected_ack);
static void gum_put_ack (gint fd, GumModifyThreadAck ack);

static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static void gum_do_enumerate_modules (const gchar * libc_name,
    GumFoundModuleFunc func, gpointer user_data);
static void gum_process_enumerate_modules_by_using_libc (
    GumDlIteratePhdrImpl iterate_phdr, GumFoundModuleFunc func,
    gpointer user_data);
static gint gum_emit_module_from_phdr (struct dl_phdr_info * info, gsize size,
    gpointer user_data);

static void gum_linux_named_range_free (GumLinuxNamedRange * range);
static gboolean gum_try_translate_vdso_name (gchar * name);
static void gum_do_set_hardware_breakpoint (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
static void gum_do_unset_hardware_breakpoint (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
static void gum_do_set_hardware_watchpoint (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
static void gum_do_unset_hardware_watchpoint (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
static void * gum_module_get_handle (const gchar * module_name);
static void * gum_module_get_symbol (void * module, const gchar * symbol_name);

static gboolean gum_do_resolve_module_name (const gchar * name,
    const gchar * libc_name, gchar ** path, GumAddress * base);
static gboolean gum_store_module_path_and_base_if_match (
    const GumModuleDetails * details, gpointer user_data);

static void gum_proc_maps_iter_init_for_path (GumProcMapsIter * iter,
    const gchar * path);

static void gum_acquire_dumpability (void);
static void gum_release_dumpability (void);

static gchar * gum_thread_read_name (GumThreadId thread_id);
static gboolean gum_thread_read_state (GumThreadId tid, GumThreadState * state);
static GumThreadState gum_thread_state_from_proc_status_character (gchar c);
static GumPageProtection gum_page_protection_from_proc_perms_string (
    const gchar * perms);

static gssize gum_get_regs (pid_t pid, guint type, gpointer data, gsize * size);
static gssize gum_set_regs (pid_t pid, guint type, gconstpointer data,
    gsize size);

static void gum_parse_gp_regs (const GumGPRegs * regs, GumCpuContext * ctx);
static void gum_unparse_gp_regs (const GumCpuContext * ctx, GumGPRegs * regs);

static gssize gum_libc_clone (GumCloneFunc child_func, gpointer child_stack,
    gint flags, gpointer arg, pid_t * parent_tidptr, GumUserDesc * tls,
    pid_t * child_tidptr);
static gssize gum_libc_read (gint fd, gpointer buf, gsize count);
static gssize gum_libc_write (gint fd, gconstpointer buf, gsize count);
static pid_t gum_libc_waitpid (pid_t pid, int * status, int options);
static gssize gum_libc_ptrace (gsize request, pid_t pid, gpointer address,
    gpointer data);

#define gum_libc_syscall_3(n, a, b, c) gum_libc_syscall_4 (n, a, b, c, 0)
static gssize gum_libc_syscall_4 (gsize n, gsize a, gsize b, gsize c, gsize d);

static GumProgramModules gum_program_modules;
static gchar * gum_libc_name;

static gboolean gum_is_regset_supported = TRUE;

G_LOCK_DEFINE_STATIC (gum_dumpable);
static gint gum_dumpable_refcount = 0;
static gint gum_dumpable_previous = 0;

static const GumProgramModules *
gum_query_program_modules (void)
{
  static gsize modules_value = 0;

  if (g_once_init_enter (&modules_value))
  {
    static GumProgramRanges ranges;
    gboolean got_kern, got_user;
    GumProgramRanges kern, user;
    GumProcMapsIter iter;
    gchar * path;
    const gchar * line;

    got_kern = gum_query_program_ranges (gum_read_auxv_from_proc, &kern);
    got_user = gum_query_program_ranges (gum_read_auxv_from_stack, &user);
    if (got_kern && got_user &&
        user.program.base_address != kern.program.base_address)
    {
      ranges = user;
      ranges.interpreter = kern.program;
    }
    else if (got_kern)
      ranges = kern;
    else
      ranges = user;

    gum_program_modules.program.range = &ranges.program;
    gum_program_modules.interpreter.range = &ranges.interpreter;
    gum_program_modules.vdso.range = &ranges.vdso;
    gum_program_modules.rtld = (ranges.interpreter.base_address == 0)
        ? GUM_PROGRAM_RTLD_NONE
        : GUM_PROGRAM_RTLD_SHARED;

    gum_proc_maps_iter_init_for_self (&iter);
    path = g_malloc (PATH_MAX);

    while (gum_proc_maps_iter_next (&iter, &line))
    {
      GumAddress start;
      GumModuleDetails * m;

      sscanf (line, "%" G_GINT64_MODIFIER "x-", &start);

      if (start == ranges.program.base_address)
        m = &gum_program_modules.program;
      else if (start == ranges.interpreter.base_address)
        m = &gum_program_modules.interpreter;
      else
        continue;

      sscanf (line, "%*x-%*x %*c%*c%*c%*c %*x %*s %*d %[^\n]", path);

      m->path = g_strdup (path);
      m->name = strrchr (m->path, '/');
      if (m->name != NULL)
        m->name++;
      else
        m->name = m->path;
    }

    g_free (path);
    gum_proc_maps_iter_destroy (&iter);

    if (ranges.vdso.base_address != 0)
    {
      GumModuleDetails * m = &gum_program_modules.vdso;
      /* FIXME: Parse soname instead of hardcoding: */
      m->path = g_strdup ("linux-vdso.so.1");
      m->name = m->path;
    }

    _gum_register_destructor (gum_deinit_program_modules);

    g_once_init_leave (&modules_value, GPOINTER_TO_SIZE (&gum_program_modules));
  }

  return GSIZE_TO_POINTER (modules_value);
}

static void
gum_deinit_program_modules (void)
{
  GumProgramModules * m = &gum_program_modules;

  g_free ((gchar *) m->program.path);
  g_free ((gchar *) m->interpreter.path);
  g_free ((gchar *) m->vdso.path);
}

static gboolean
gum_query_program_ranges (GumReadAuxvFunc read_auxv,
                          GumProgramRanges * ranges)
{
  gboolean success = FALSE;
  ElfW(auxv_t) * auxv;
  const ElfW(Phdr) * phdrs;
  ElfW(Half) phdr_size, phdr_count;
  const ElfW(Ehdr) * interpreter, * vdso;
  ElfW(auxv_t) * entry;

  bzero (ranges, sizeof (GumProgramRanges));

  auxv = read_auxv ();
  if (auxv == NULL)
    goto beach;

  phdrs = NULL;
  phdr_size = 0;
  phdr_count = 0;
  interpreter = NULL;
  vdso = NULL;
  for (entry = auxv; entry->a_type != AT_NULL; entry++)
  {
    switch (entry->a_type)
    {
      case AT_PHDR:
        phdrs = (ElfW(Phdr) *) entry->a_un.a_val;
        break;
      case AT_PHENT:
        phdr_size = entry->a_un.a_val;
        break;
      case AT_PHNUM:
        phdr_count = entry->a_un.a_val;
        break;
      case AT_BASE:
        interpreter = (const ElfW(Ehdr) *) entry->a_un.a_val;
        break;
      case AT_SYSINFO_EHDR:
        vdso = (const ElfW(Ehdr) *) entry->a_un.a_val;
        break;
    }
  }
  if (phdrs == NULL || phdr_size == 0 || phdr_count == 0)
    goto beach;

  gum_compute_elf_range_from_phdrs (phdrs, phdr_size, phdr_count, 0,
      &ranges->program);
  gum_compute_elf_range_from_ehdr (interpreter, &ranges->interpreter);
  gum_compute_elf_range_from_ehdr (vdso, &ranges->vdso);

  success = TRUE;

beach:
  g_free (auxv);

  return success;
}

static ElfW(auxv_t) *
gum_read_auxv_from_proc (void)
{
  ElfW(auxv_t) * auxv = NULL;

  gum_acquire_dumpability ();

  g_file_get_contents ("/proc/self/auxv", (gchar **) &auxv, NULL, NULL);

  gum_release_dumpability ();

  return auxv;
}

static ElfW(auxv_t) *
gum_read_auxv_from_stack (void)
{
  GumMemoryRange stack;
  gpointer stack_start, stack_end;
  ElfW(auxv_t) needle;
  const ElfW(auxv_t) * match, * last_match;
  gsize offset;
  const ElfW(auxv_t) * cursor, * auxv_start, * auxv_end;
  gsize page_size;

  if (!gum_query_main_thread_stack_range (&stack))
    return NULL;
  stack_start = GSIZE_TO_POINTER (stack.base_address);
  stack_end = stack_start + stack.size;

  needle.a_type = AT_PHENT;
  needle.a_un.a_val = sizeof (ElfW(Phdr));

  match = NULL;
  last_match = NULL;
  offset = 0;
  while (offset != stack.size)
  {
    match = memmem (GSIZE_TO_POINTER (stack.base_address) + offset,
        stack.size - offset, &needle, sizeof (needle));
    if (match == NULL)
      break;

    last_match = match;
    offset = (GUM_ADDRESS (match) - stack.base_address) + 1;
  }
  if (last_match == NULL)
    return NULL;

  auxv_start = NULL;
  page_size = gum_query_page_size ();
  for (cursor = last_match - 1;
      (gpointer) cursor >= stack_start;
      cursor--)
  {
    gboolean probably_an_invalid_type = cursor->a_type >= page_size;
    if (probably_an_invalid_type)
    {
      auxv_start = cursor + 1;
      break;
    }
  }

  auxv_end = NULL;
  for (cursor = last_match + 1;
      (gpointer) cursor <= stack_end - sizeof (ElfW(auxv_t));
      cursor++)
  {
    if (cursor->a_type == AT_NULL)
    {
      auxv_end = cursor + 1;
      break;
    }
  }
  if (auxv_end == NULL)
    return NULL;

  return g_memdup (auxv_start, (guint8 *) auxv_end - (guint8 *) auxv_start);
}

static gboolean
gum_query_main_thread_stack_range (GumMemoryRange * range)
{
  GumProcMapsIter iter;
  GumAddress stack_bottom, stack_top;
  const gchar * line;

  gum_proc_maps_iter_init_for_self (&iter);

  stack_bottom = 0;
  stack_top = 0;

  while (gum_proc_maps_iter_next (&iter, &line))
  {
    if (g_str_has_suffix (line, " [stack]"))
    {
      sscanf (line,
          "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x ",
          &stack_bottom,
          &stack_top);
      break;
    }
  }

  range->base_address = stack_bottom;
  range->size = stack_top - stack_bottom;

  gum_proc_maps_iter_destroy (&iter);

  return range->size != 0;
}

static void
gum_compute_elf_range_from_ehdr (const ElfW(Ehdr) * ehdr,
                                 GumMemoryRange * range)
{
  if (ehdr == NULL)
  {
    range->base_address = 0;
    range->size = 0;
    return;
  }

  gum_compute_elf_range_from_phdrs ((gconstpointer) ehdr + ehdr->e_phoff,
      ehdr->e_phentsize, ehdr->e_phnum, GUM_ADDRESS (ehdr), range);
}

static void
gum_compute_elf_range_from_phdrs (const ElfW(Phdr) * phdrs,
                                  ElfW(Half) phdr_size,
                                  ElfW(Half) phdr_count,
                                  GumAddress base_address,
                                  GumMemoryRange * range)
{
  GumAddress lowest, highest;
  gsize page_size;
  ElfW(Half) i;
  const ElfW(Phdr) * phdr;

  range->base_address = 0;

  lowest = ~0;
  highest = 0;
  page_size = gum_query_page_size ();

  for (i = 0, phdr = phdrs;
      i != phdr_count;
      i++, phdr = (gconstpointer) phdr + phdr_size)
  {
    if (phdr->p_type == PT_PHDR)
      range->base_address = GPOINTER_TO_SIZE (phdrs) - phdr->p_offset;

    if (phdr->p_type == PT_LOAD && phdr->p_offset == 0)
    {
      if (range->base_address == 0)
        range->base_address = phdr->p_vaddr;
    }

    if (phdr->p_type == PT_LOAD)
    {
      lowest = MIN (GUM_PAGE_START (phdr->p_vaddr, page_size), lowest);
      highest = MAX (phdr->p_vaddr + phdr->p_memsz, highest);
    }
  }

  if (range->base_address == 0)
  {
    range->base_address = (base_address != 0)
        ? base_address
        : GUM_PAGE_START (phdrs, page_size);
  }

  range->size = highest - lowest;
}

const gchar *
gum_process_query_libc_name (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_libc_name, NULL);

  if (once.retval == NULL)
    gum_panic ("Unable to locate the libc; please file a bug");

  return once.retval;
}

static gchar *
gum_try_init_libc_name (void)
{
  Dl_info info;

#ifndef HAVE_ANDROID
  if (!gum_try_resolve_dynamic_symbol ("__libc_start_main", &info))
#endif
  {
    if (!gum_try_resolve_dynamic_symbol ("exit", &info))
      return NULL;
  }

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (g_path_is_absolute (info.dli_fname))
  {
    gum_libc_name = g_strdup (info.dli_fname);
  }
  else
  {
    gum_libc_name = g_build_filename (
        "/system",
        (sizeof (gpointer) == 4) ? "lib" : "lib64",
        info.dli_fname,
        NULL);
  }
#else
  {
    GumAddress base;
    gum_do_resolve_module_name (info.dli_fname, info.dli_fname, &gum_libc_name,
        &base);
  }
#endif

  _gum_register_destructor (gum_deinit_libc_name);

  return gum_libc_name;
}

static gboolean
gum_try_resolve_dynamic_symbol (const gchar * name,
                                Dl_info * info)
{
  gpointer address;

  address = dlsym (RTLD_NEXT, name);
  if (address == NULL)
    address = dlsym (RTLD_DEFAULT, name);
  if (address == NULL)
    return FALSE;

  return dladdr (address, info) != 0;
}

static void
gum_deinit_libc_name (void)
{
  g_free (gum_libc_name);
}

gboolean
gum_process_is_debugger_attached (void)
{
  gboolean result;
  gchar * status, * p;

  status = NULL;
  g_file_get_contents ("/proc/self/status", &status, NULL, NULL);

  p = strstr (status, "TracerPid:");
  g_assert (p != NULL);

  result = atoi (p + 10) != 0;

  g_free (status);

  return result;
}

GumProcessId
gum_process_get_id (void)
{
  return getpid ();
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return syscall (__NR_gettid);
}

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  gchar path[16 + 20 + 1];
  sprintf (path, "/proc/self/task/%" G_GSIZE_MODIFIER "u", thread_id);

  return g_file_test (path, G_FILE_TEST_EXISTS);
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data,

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-linux/gumprocess-linux.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023-2024 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "backend-elf/gumprocess-elf.h"
#include "gum-init.h"
#include "gum/gumandroid.h"
#include "gum/gumlinux.h"
#include "gumelfmodule.h"
#include "gumlinux-priv.h"
#include "gummodulemap.h"
#include "valgrind.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_PTHREAD_ATTR_GETSTACK
# include <pthread.h>
#endif
#ifdef HAVE_LINK_H
# include <link.h>
#endif
#ifdef HAVE_ASM_PRCTL_H
# include <asm/prctl.h>
#endif
#include <sys/prctl.h>
#include <sys/ptrace.h>
#ifdef HAVE_ASM_PTRACE_H
# include <asm/ptrace.h>
#endif
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif

#define GUM_PAGE_START(value, page_size) \
    (GUM_ADDRESS (value) & ~GUM_ADDRESS (page_size - 1))

#ifndef O_CLOEXEC
# define O_CLOEXEC 0x80000
#endif

#define GUM_PSR_THUMB 0x20

#if defined (HAVE_I386)
typedef struct user_regs_struct GumGPRegs;
typedef struct _GumX86DebugRegs GumDebugRegs;
#elif defined (HAVE_ARM)
typedef struct pt_regs GumGPRegs;
typedef struct _GumArmDebugRegs GumDebugRegs;
#elif defined (HAVE_ARM64)
typedef struct user_pt_regs GumGPRegs;
typedef struct _GumArm64DebugRegs GumDebugRegs;
#elif defined (HAVE_MIPS)
typedef struct pt_regs GumGPRegs;
typedef struct _GumMipsDebugRegs GumDebugRegs;
#else
# error Unsupported architecture
#endif
typedef guint GumMipsWatchStyle;
typedef struct _GumMips32WatchRegs GumMips32WatchRegs;
typedef struct _GumMips64WatchRegs GumMips64WatchRegs;
typedef union _GumRegs GumRegs;
#ifndef PTRACE_GETREGS
# define PTRACE_GETREGS 12
#endif
#ifndef PTRACE_SETREGS
# define PTRACE_SETREGS 13
#endif
#ifndef PTRACE_GETHBPREGS
# define PTRACE_GETHBPREGS 29
#endif
#ifndef PTRACE_SETHBPREGS
# define PTRACE_SETHBPREGS 30
#endif
#ifndef PTRACE_GET_WATCH_REGS
# define PTRACE_GET_WATCH_REGS 0xd0
#endif
#ifndef PTRACE_SET_WATCH_REGS
# define PTRACE_SET_WATCH_REGS 0xd1
#endif
#ifndef PTRACE_GETREGSET
# define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
# define PTRACE_SETREGSET 0x4205
#endif
#ifndef PR_SET_PTRACER
# define PR_SET_PTRACER 0x59616d61
#endif
#ifndef NT_PRSTATUS
# define NT_PRSTATUS 1
#endif

#define GUM_TEMP_FAILURE_RETRY(expression) \
    ({ \
      gssize __result; \
      \
      do __result = (gssize) (expression); \
      while (__result == -EINTR); \
      \
      __result; \
    })

typedef struct _GumProgramModules GumProgramModules;
typedef guint GumProgramRuntimeLinker;
typedef struct _GumProgramRanges GumProgramRanges;
typedef ElfW(auxv_t) * (* GumReadAuxvFunc) (void);

typedef struct _GumModifyThreadContext GumModifyThreadContext;
typedef void (* GumLinuxModifyThreadFunc) (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
typedef struct _GumLinuxModifyThreadContext GumLinuxModifyThreadContext;
typedef guint GumLinuxRegsType;
typedef guint8 GumModifyThreadAck;

typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;
typedef struct _GumResolveModuleNameContext GumResolveModuleNameContext;

typedef gint (* GumFoundDlPhdrFunc) (struct dl_phdr_info * info,
    gsize size, gpointer data);
typedef void (* GumDlIteratePhdrImpl) (GumFoundDlPhdrFunc func, gpointer data);

typedef struct _GumSetHardwareBreakpointContext GumSetHardwareBreakpointContext;
typedef struct _GumSetHardwareWatchpointContext GumSetHardwareWatchpointContext;

typedef struct _GumUserDesc GumUserDesc;
typedef struct _GumTcbHead GumTcbHead;

typedef gint (* GumCloneFunc) (gpointer arg);

struct _GumProgramModules
{
  GumModuleDetails program;
  GumModuleDetails interpreter;
  GumModuleDetails vdso;
  GumProgramRuntimeLinker rtld;
};

enum _GumProgramRuntimeLinker
{
  GUM_PROGRAM_RTLD_NONE,
  GUM_PROGRAM_RTLD_SHARED,
};

struct _GumProgramRanges
{
  GumMemoryRange program;
  GumMemoryRange interpreter;
  GumMemoryRange vdso;
};

struct _GumModifyThreadContext
{
  GumModifyThreadFunc func;
  gpointer user_data;
};

enum _GumLinuxRegsType
{
  GUM_REGS_GENERAL_PURPOSE,
  GUM_REGS_DEBUG_BREAK,
  GUM_REGS_DEBUG_WATCH,
};

struct _GumX86DebugRegs
{
  gsize dr0;
  gsize dr1;
  gsize dr2;
  gsize dr3;
  gsize dr6;
  gsize dr7;
};

struct _GumArmDebugRegs
{
  guint32 cr[16];
  guint32 vr[16];
};

struct _GumArm64DebugRegs
{
  guint64 cr[16];
  guint64 vr[16];
};

enum _GumMipsWatchStyle
{
  GUM_MIPS_WATCH_MIPS32,
  GUM_MIPS_WATCH_MIPS64,
};

struct _GumMips32WatchRegs
{
  guint32 watch_lo[8];
  guint16 watch_hi[8];
  guint16 watch_masks[8];
  guint32 num_valid;
} __attribute__ ((aligned (8)));

struct _GumMips64WatchRegs
{
  guint64 watch_lo[8];
  guint16 watch_hi[8];
  guint16 watch_masks[8];
  guint32 num_valid;
} __attribute__ ((aligned (8)));

struct _GumMipsDebugRegs
{
  GumMipsWatchStyle style;
  union
  {
    GumMips32WatchRegs mips32;
    GumMips64WatchRegs mips64;
  };
};

union _GumRegs
{
  GumGPRegs gp;
  GumDebugRegs debug;
};

enum _GumModifyThreadAck
{
  GUM_ACK_READY = 1,
  GUM_ACK_READ_REGISTERS,
  GUM_ACK_MODIFIED_REGISTERS,
  GUM_ACK_WROTE_REGISTERS,
  GUM_ACK_FAILED_TO_ATTACH,
  GUM_ACK_FAILED_TO_WAIT,
  GUM_ACK_FAILED_TO_STOP,
  GUM_ACK_FAILED_TO_READ,
  GUM_ACK_FAILED_TO_WRITE,
  GUM_ACK_FAILED_TO_DETACH
};

struct _GumLinuxModifyThreadContext
{
  GumThreadId thread_id;
  GumLinuxRegsType regs_type;
  GumLinuxModifyThreadFunc func;
  gpointer user_data;

  gint fd[2];
  GumRegs regs_data;
};

struct _GumEnumerateModulesContext
{
  GumFoundModuleFunc func;
  gpointer user_data;

  GHashTable * named_ranges;
};

struct _GumEmitExecutableModuleContext
{
  const gchar * executable_path;
  GumFoundModuleFunc func;
  gpointer user_data;

  gboolean carry_on;
};

struct _GumResolveModuleNameContext
{
  const gchar * name;
  GumAddress known_address;
  gchar * path;
  GumAddress base;
};

struct _GumSetHardwareBreakpointContext
{
  guint breakpoint_id;
  GumAddress address;
};

struct _GumSetHardwareWatchpointContext
{
  guint watchpoint_id;
  GumAddress address;
  gsize size;
  GumWatchConditions conditions;
};

struct _GumUserDesc
{
  guint entry_number;
  guint base_addr;
  guint limit;
  guint seg_32bit : 1;
  guint contents : 2;
  guint read_exec_only : 1;
  guint limit_in_pages : 1;
  guint seg_not_present : 1;
  guint useable : 1;
};

struct _GumTcbHead
{
#ifdef HAVE_I386
  gpointer tcb;
  gpointer dtv;
  gpointer self;
#else
  gpointer dtv;
  gpointer priv;
#endif
};

static void gum_deinit_program_modules (void);
static gboolean gum_query_program_ranges (GumReadAuxvFunc read_auxv,
    GumProgramRanges * ranges);
static ElfW(auxv_t) * gum_read_auxv_from_proc (void);
static ElfW(auxv_t) * gum_read_auxv_from_stack (void);
static gboolean gum_query_main_thread_stack_range (GumMemoryRange * range);
static void gum_compute_elf_range_from_ehdr (const ElfW(Ehdr) * ehdr,
    GumMemoryRange * range);
static void gum_compute_elf_range_from_phdrs (const ElfW(Phdr) * phdrs,
    ElfW(Half) phdr_size, ElfW(Half) phdr_count, GumAddress base_address,
    GumMemoryRange * range);

static gchar * gum_try_init_libc_name (void);
static gboolean gum_try_resolve_dynamic_symbol (const gchar * name,
    Dl_info * info);
static void gum_deinit_libc_name (void);

static void gum_do_modify_thread (GumThreadId thread_id, GumRegs * regs,
    gpointer user_data);
static gboolean gum_linux_modify_thread (GumThreadId thread_id,
    GumLinuxRegsType regs_type, GumLinuxModifyThreadFunc func,
    gpointer user_data, GError ** error);
static gpointer gum_linux_handle_modify_thread_comms (gpointer data);
static gint gum_linux_do_modify_thread (gpointer data);
static gboolean gum_await_ack (gint fd, GumModifyThreadAck expected_ack);
static void gum_put_ack (gint fd, GumModifyThreadAck ack);

static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static void gum_do_enumerate_modules (const gchar * libc_name,
    GumFoundModuleFunc func, gpointer user_data);
static void gum_process_enumerate_modules_by_using_libc (
    GumDlIteratePhdrImpl iterate_phdr, GumFoundModuleFunc func,
    gpointer user_data);
static gint gum_emit_module_from_phdr (struct dl_phdr_info * info, gsize size,
    gpointer user_data);

static void gum_linux_named_range_free (GumLinuxNamedRange * range);
static gboolean gum_try_translate_vdso_name (gchar * name);
static void gum_do_set_hardware_breakpoint (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
static void gum_do_unset_hardware_breakpoint (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
static void gum_do_set_hardware_watchpoint (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
static void gum_do_unset_hardware_watchpoint (GumThreadId thread_id,
    GumRegs * regs, gpointer user_data);
static void * gum_module_get_handle (const gchar * module_name);
static void * gum_module_get_symbol (void * module, const gchar * symbol_name);

static gboolean gum_do_resolve_module_name (const gchar * name,
    const gchar * libc_name, gchar ** path, GumAddress * base);
static gboolean gum_store_module_path_and_base_if_match (
    const GumModuleDetails * details, gpointer user_data);

static void gum_proc_maps_iter_init_for_path (GumProcMapsIter * iter,
    const gchar * path);

static void gum_acquire_dumpability (void);
static void gum_release_dumpability (void);

static gchar * gum_thread_read_name (GumThreadId thread_id);
static gboolean gum_thread_read_state (GumThreadId tid, GumThreadState * state);
static GumThreadState gum_thread_state_from_proc_status_character (gchar c);
static GumPageProtection gum_page_protection_from_proc_perms_string (
    const gchar * perms);

static gssize gum_get_regs (pid_t pid, guint type, gpointer data, gsize * size);
static gssize gum_set_regs (pid_t pid, guint type, gconstpointer data,
    gsize size);

static void gum_parse_gp_regs (const GumGPRegs * regs, GumCpuContext * ctx);
static void gum_unparse_gp_regs (const GumCpuContext * ctx, GumGPRegs * regs);

static gssize gum_libc_clone (GumCloneFunc child_func, gpointer child_stack,
    gint flags, gpointer arg, pid_t * parent_tidptr, GumUserDesc * tls,
    pid_t * child_tidptr);
static gssize gum_libc_read (gint fd, gpointer buf, gsize count);
static gssize gum_libc_write (gint fd, gconstpointer buf, gsize count);
static pid_t gum_libc_waitpid (pid_t pid, int * status, int options);
static gssize gum_libc_ptrace (gsize request, pid_t pid, gpointer address,
    gpointer data);

#define gum_libc_syscall_3(n, a, b, c) gum_libc_syscall_4 (n, a, b, c, 0)
static gssize gum_libc_syscall_4 (gsize n, gsize a, gsize b, gsize c, gsize d);

static GumProgramModules gum_program_modules;
static gchar * gum_libc_name;

static gboolean gum_is_regset_supported = TRUE;

G_LOCK_DEFINE_STATIC (gum_dumpable);
static gint gum_dumpable_refcount = 0;
static gint gum_dumpable_previous = 0;

static const GumProgramModules *
gum_query_program_modules (void)
{
  static gsize modules_value = 0;

  if (g_once_init_enter (&modules_value))
  {
    static GumProgramRanges ranges;
    gboolean got_kern, got_user;
    GumProgramRanges kern, user;
    GumProcMapsIter iter;
    gchar * path;
    const gchar * line;

    got_kern = gum_query_program_ranges (gum_read_auxv_from_proc, &kern);
    got_user = gum_query_program_ranges (gum_read_auxv_from_stack, &user);
    if (got_kern && got_user &&
        user.program.base_address != kern.program.base_address)
    {
      ranges = user;
      ranges.interpreter = kern.program;
    }
    else if (got_kern)
      ranges = kern;
    else
      ranges = user;

    gum_program_modules.program.range = &ranges.program;
    gum_program_modules.interpreter.range = &ranges.interpreter;
    gum_program_modules.vdso.range = &ranges.vdso;
    gum_program_modules.rtld = (ranges.interpreter.base_address == 0)
        ? GUM_PROGRAM_RTLD_NONE
        : GUM_PROGRAM_RTLD_SHARED;

    gum_proc_maps_iter_init_for_self (&iter);
    path = g_malloc (PATH_MAX);

    while (gum_proc_maps_iter_next (&iter, &line))
    {
      GumAddress start;
      GumModuleDetails * m;

      sscanf (line, "%" G_GINT64_MODIFIER "x-", &start);

      if (start == ranges.program.base_address)
        m = &gum_program_modules.program;
      else if (start == ranges.interpreter.base_address)
        m = &gum_program_modules.interpreter;
      else
        continue;

      sscanf (line, "%*x-%*x %*c%*c%*c%*c %*x %*s %*d %[^\n]", path);

      m->path = g_strdup (path);
      m->name = strrchr (m->path, '/');
      if (m->name != NULL)
        m->name++;
      else
        m->name = m->path;
    }

    g_free (path);
    gum_proc_maps_iter_destroy (&iter);

    if (ranges.vdso.base_address != 0)
    {
      GumModuleDetails * m = &gum_program_modules.vdso;
      /* FIXME: Parse soname instead of hardcoding: */
      m->path = g_strdup ("linux-vdso.so.1");
      m->name = m->path;
    }

    _gum_register_destructor (gum_deinit_program_modules);

    g_once_init_leave (&modules_value, GPOINTER_TO_SIZE (&gum_program_modules));
  }

  return GSIZE_TO_POINTER (modules_value);
}

static void
gum_deinit_program_modules (void)
{
  GumProgramModules * m = &gum_program_modules;

  g_free ((gchar *) m->program.path);
  g_free ((gchar *) m->interpreter.path);
  g_free ((gchar *) m->vdso.path);
}

static gboolean
gum_query_program_ranges (GumReadAuxvFunc read_auxv,
                          GumProgramRanges * ranges)
{
  gboolean success = FALSE;
  ElfW(auxv_t) * auxv;
  const ElfW(Phdr) * phdrs;
  ElfW(Half) phdr_size, phdr_count;
  const ElfW(Ehdr) * interpreter, * vdso;
  ElfW(auxv_t) * entry;

  bzero (ranges, sizeof (GumProgramRanges));

  auxv = read_auxv ();
  if (auxv == NULL)
    goto beach;

  phdrs = NULL;
  phdr_size = 0;
  phdr_count = 0;
  interpreter = NULL;
  vdso = NULL;
  for (entry = auxv; entry->a_type != AT_NULL; entry++)
  {
    switch (entry->a_type)
    {
      case AT_PHDR:
        phdrs = (ElfW(Phdr) *) entry->a_un.a_val;
        break;
      case AT_PHENT:
        phdr_size = entry->a_un.a_val;
        break;
      case AT_PHNUM:
        phdr_count = entry->a_un.a_val;
        break;
      case AT_BASE:
        interpreter = (const ElfW(Ehdr) *) entry->a_un.a_val;
        break;
      case AT_SYSINFO_EHDR:
        vdso = (const ElfW(Ehdr) *) entry->a_un.a_val;
        break;
    }
  }
  if (phdrs == NULL || phdr_size == 0 || phdr_count == 0)
    goto beach;

  gum_compute_elf_range_from_phdrs (phdrs, phdr_size, phdr_count, 0,
      &ranges->program);
  gum_compute_elf_range_from_ehdr (interpreter, &ranges->interpreter);
  gum_compute_elf_range_from_ehdr (vdso, &ranges->vdso);

  success = TRUE;

beach:
  g_free (auxv);

  return success;
}

static ElfW(auxv_t) *
gum_read_auxv_from_proc (void)
{
  ElfW(auxv_t) * auxv = NULL;

  gum_acquire_dumpability ();

  g_file_get_contents ("/proc/self/auxv", (gchar **) &auxv, NULL, NULL);

  gum_release_dumpability ();

  return auxv;
}

static ElfW(auxv_t) *
gum_read_auxv_from_stack (void)
{
  GumMemoryRange stack;
  gpointer stack_start, stack_end;
  ElfW(auxv_t) needle;
  const ElfW(auxv_t) * match, * last_match;
  gsize offset;
  const ElfW(auxv_t) * cursor, * auxv_start, * auxv_end;
  gsize page_size;

  if (!gum_query_main_thread_stack_range (&stack))
    return NULL;
  stack_start = GSIZE_TO_POINTER (stack.base_address);
  stack_end = stack_start + stack.size;

  needle.a_type = AT_PHENT;
  needle.a_un.a_val = sizeof (ElfW(Phdr));

  match = NULL;
  last_match = NULL;
  offset = 0;
  while (offset != stack.size)
  {
    match = memmem (GSIZE_TO_POINTER (stack.base_address) + offset,
        stack.size - offset, &needle, sizeof (needle));
    if (match == NULL)
      break;

    last_match = match;
    offset = (GUM_ADDRESS (match) - stack.base_address) + 1;
  }
  if (last_match == NULL)
    return NULL;

  auxv_start = NULL;
  page_size = gum_query_page_size ();
  for (cursor = last_match - 1;
      (gpointer) cursor >= stack_start;
      cursor--)
  {
    gboolean probably_an_invalid_type = cursor->a_type >= page_size;
    if (probably_an_invalid_type)
    {
      auxv_start = cursor + 1;
      break;
    }
  }

  auxv_end = NULL;
  for (cursor = last_match + 1;
      (gpointer) cursor <= stack_end - sizeof (ElfW(auxv_t));
      cursor++)
  {
    if (cursor->a_type == AT_NULL)
    {
      auxv_end = cursor + 1;
      break;
    }
  }
  if (auxv_end == NULL)
    return NULL;

  return g_memdup (auxv_start, (guint8 *) auxv_end - (guint8 *) auxv_start);
}

static gboolean
gum_query_main_thread_stack_range (GumMemoryRange * range)
{
  GumProcMapsIter iter;
  GumAddress stack_bottom, stack_top;
  const gchar * line;

  gum_proc_maps_iter_init_for_self (&iter);

  stack_bottom = 0;
  stack_top = 0;

  while (gum_proc_maps_iter_next (&iter, &line))
  {
    if (g_str_has_suffix (line, " [stack]"))
    {
      sscanf (line,
          "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x ",
          &stack_bottom,
          &stack_top);
      break;
    }
  }

  range->base_address = stack_bottom;
  range->size = stack_top - stack_bottom;

  gum_proc_maps_iter_destroy (&iter);

  return range->size != 0;
}

static void
gum_compute_elf_range_from_ehdr (const ElfW(Ehdr) * ehdr,
                                 GumMemoryRange * range)
{
  if (ehdr == NULL)
  {
    range->base_address = 0;
    range->size = 0;
    return;
  }

  gum_compute_elf_range_from_phdrs ((gconstpointer) ehdr + ehdr->e_phoff,
      ehdr->e_phentsize, ehdr->e_phnum, GUM_ADDRESS (ehdr), range);
}

static void
gum_compute_elf_range_from_phdrs (const ElfW(Phdr) * phdrs,
                                  ElfW(Half) phdr_size,
                                  ElfW(Half) phdr_count,
                                  GumAddress base_address,
                                  GumMemoryRange * range)
{
  GumAddress lowest, highest;
  gsize page_size;
  ElfW(Half) i;
  const ElfW(Phdr) * phdr;

  range->base_address = 0;

  lowest = ~0;
  highest = 0;
  page_size = gum_query_page_size ();

  for (i = 0, phdr = phdrs;
      i != phdr_count;
      i++, phdr = (gconstpointer) phdr + phdr_size)
  {
    if (phdr->p_type == PT_PHDR)
      range->base_address = GPOINTER_TO_SIZE (phdrs) - phdr->p_offset;

    if (phdr->p_type == PT_LOAD && phdr->p_offset == 0)
    {
      if (range->base_address == 0)
        range->base_address = phdr->p_vaddr;
    }

    if (phdr->p_type == PT_LOAD)
    {
      lowest = MIN (GUM_PAGE_START (phdr->p_vaddr, page_size), lowest);
      highest = MAX (phdr->p_vaddr + phdr->p_memsz, highest);
    }
  }

  if (range->base_address == 0)
  {
    range->base_address = (base_address != 0)
        ? base_address
        : GUM_PAGE_START (phdrs, page_size);
  }

  range->size = highest - lowest;
}

const gchar *
gum_process_query_libc_name (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_libc_name, NULL);

  if (once.retval == NULL)
    gum_panic ("Unable to locate the libc; please file a bug");

  return once.retval;
}

static gchar *
gum_try_init_libc_name (void)
{
  Dl_info info;

#ifndef HAVE_ANDROID
  if (!gum_try_resolve_dynamic_symbol ("__libc_start_main", &info))
#endif
  {
    if (!gum_try_resolve_dynamic_symbol ("exit", &info))
      return NULL;
  }

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (g_path_is_absolute (info.dli_fname))
  {
    gum_libc_name = g_strdup (info.dli_fname);
  }
  else
  {
    gum_libc_name = g_build_filename (
        "/system",
        (sizeof (gpointer) == 4) ? "lib" : "lib64",
        info.dli_fname,
        NULL);
  }
#else
  {
    GumAddress base;
    gum_do_resolve_module_name (info.dli_fname, info.dli_fname, &gum_libc_name,
        &base);
  }
#endif

  _gum_register_destructor (gum_deinit_libc_name);

  return gum_libc_name;
}

static gboolean
gum_try_resolve_dynamic_symbol (const gchar * name,
                                Dl_info * info)
{
  gpointer address;

  address = dlsym (RTLD_NEXT, name);
  if (address == NULL)
    address = dlsym (RTLD_DEFAULT, name);
  if (address == NULL)
    return FALSE;

  return dladdr (address, info) != 0;
}

static void
gum_deinit_libc_name (void)
{
  g_free (gum_libc_name);
}

gboolean
gum_process_is_debugger_attached (void)
{
  gboolean result;
  gchar * status, * p;

  status = NULL;
  g_file_get_contents ("/proc/self/status", &status, NULL, NULL);

  p = strstr (status, "TracerPid:");
  g_assert (p != NULL);

  result = atoi (p + 10) != 0;

  g_free (status);

  return result;
}

GumProcessId
gum_process_get_id (void)
{
  return getpid ();
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return syscall (__NR_gettid);
}

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  gchar path[16 + 20 + 1];
  sprintf (path, "/proc/self/task/%" G_GSIZE_MODIFIER "u", thread_id);

  return g_file_test (path, G_FILE_TEST_EXISTS);
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data,
                           GumModifyThreadFlags flags)
{
  GumModifyThreadContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  return gum_linux_modify_thread (thread_id, GUM_REGS_GENERAL_PURPOSE,
      gum_do_modify_thread, &ctx, NULL);
}

static void
gum_do_modify_thread (GumThreadId thread_id,
                      GumRegs * regs,
                      gpointer user_data)
{
  GumGPRegs * gpr = &regs->gp;
  GumModifyThreadContext * ctx = user_data;
  GumCpuContext cpu_context;

  gum_parse_gp_regs (gpr, &cpu_context);

  ctx->func (thread_id, &cpu_context, ctx->user_data);

  gum_unparse_gp_regs (&cpu_context, gpr);
}

static gboolean
gum_linux_modify_thread (GumThreadId thread_id,
                         GumLinuxRegsType regs_type,
                         GumLinuxModifyThreadFunc func,
                         gpointer user_data,
                         GError ** error)
{
  gboolean success = FALSE;
  GumLinuxModifyThreadContext ctx;
  gssize child;
  gpointer stack = NULL;
  gpointer tls = NULL;
  GumUserDesc * desc;

  ctx.thread_id = thread_id;
  ctx.regs_type = regs_type;
  ctx.func = func;
  ctx.user_data = user_data;

  ctx.fd[0] = -1;
  ctx.fd[1] = -1;

  memset (&ctx.regs_data, 0, sizeof (ctx.regs_data));

  if (socketpair (AF_UNIX, SOCK_STREAM, 0, ctx.fd) != 0)
    goto socketpair_failed;

  stack = gum_alloc_n_pages (1, GUM_PAGE_RW);
  tls = gum_alloc_n_pages (1, GUM_PAGE_RW);

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  GumUserDesc segment;
  gint gs;

  asm volatile (
      "movw %%gs, %w0"
      : "=q" (gs)
  );

  segment.entry_number = (gs & 0xffff) >> 3;
  segment.base_addr = GPOINTER_TO_SIZE (tls);
  segment.limit = 0xfffff;
  segment.seg_32bit = 1;
  segment.contents = 0;
  segment.read_exec_only = 0;
  segment.limit_in_pages = 1;
  segment.seg_not_present = 0;
  segment.useable = 1;

  desc = &segment;
#else
  desc = tls;
#endif

#if defined (HAVE_I386)
  {
    GumTcbHead * head = tls;

    head->tcb = tls;
    head->dtv = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (tls) + 1024);
    head->self = tls;
  }
#endif

  /*
   * It seems like the only reliable way to read/write the registers of
   * another thread is to use ptrace(). We used to accomplish this by
   * hi-jacking the target thread by installing a signal handler and sending a
   * real-time signal directed at the target thread, and thus relying on the
   * signal handler getting called in that thread. The signal handler would
   * then provide us with read/write access to its registers. This hack would
   * however not work if a thread was for example blocking in poll(), as the
   * signal would then just get queued and we'd end up waiting indefinitely.
   *
   * It is however not possible to ptrace() another thread when we're in the
   * same process group. This used to be supported in old kernels, but it was
   * buggy and eventually dropped. So in order to use ptrace() we will need to
   * spawn a new thread in a different process group so that it can ptrace()
   * the target thread inside our process group. This is also the solution
   * recommended by Linus:
   *
   * https://lkml.org/lkml/2006/9/1/217
   *
   * Because libc implementations don't expose an API to do this, and the
   * thread setup code is private, where the TLS part is crucial for even just
   * the syscall wrappers - due to them accessing `errno` - we cannot make any
   * libc calls in this thread. And because the libc's clone() syscall wrapper
   * typically writes to the child thread's TLS structures, which we cannot
   * portably set up correctly, we cannot use the libc clone() syscall wrapper
   * either.
   */
  child = gum_libc_clone (
      gum_linux_do_modify_thread,
      stack + gum_query_page_size (),
      CLONE_VM | CLONE_SETTLS,
      &ctx,
      NULL,
      desc,
      NULL);
  if (child == -1)
    goto clone_failed;

  gum_acquire_dumpability ();

  prctl (PR_SET_PTRACER, child);

  if (thread_id == gum_process_get_current_thread_id ())
  {
    success = GPOINTER_TO_UINT (g_thread_join (g_thread_new (
            "gum-modify-thread-worker",
            gum_linux_handle_modify_thread_comms,
            &ctx)));
  }
  else
  {
    success = GPOINTER_TO_UINT (gum_linux_handle_modify_thread_comms (&ctx));
  }

  gum_release_dumpability ();

  waitpid (child, NULL, __WCLONE);

  if (!success)
    goto attach_failed;

  goto beach;

socketpair_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_PERMISSION_DENIED,
        "Unable to create socketpair");
    goto beach;
  }
clone_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_PERMISSION_DENIED,
        "Unable to set up clone");
    goto beach;
  }
attach_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_PERMISSION_DENIED,
        "Unable to PTRACE_ATTACH");
    goto beach;
  }
beach:
  {
    g_clear_pointer (&tls, gum_free_pages);
    g_clear_pointer (&stack, gum_free_pages);

    if (ctx.fd[0] != -1)
      close (ctx.fd[0]);
    if (ctx.fd[1] != -1)
      close (ctx.fd[1]);

    return success;
  }
}

static gpointer
gum_linux_handle_modify_thread_comms (gpointer data)
{
  GumLinuxModifyThreadContext * ctx = data;
  gint fd = ctx->fd[0];
  gboolean success = FALSE;

  gum_put_ack (fd, GUM_ACK_READY);

  if (gum_await_ack (fd, GUM_ACK_READ_REGISTERS))
  {
    ctx->func (ctx->thread_id, &ctx->regs_data, ctx->user_data);
    gum_put_ack (fd, GUM_ACK_MODIFIED_REGISTERS);

    success = gum_await_ack (fd, GUM_ACK_WROTE_REGISTERS);
  }

  return GSIZE_TO_POINTER (success);
}

static gint
gum_linux_do_modify_thread (gpointer data)
{
  GumLinuxModifyThreadContext * ctx = data;
  gint fd;
  gboolean attached = FALSE;
  gssize res;
  pid_t wait_result;
  int status;
#if defined (HAVE_I386)
  const guint x86_debugreg_offsets[] = { 0, 1, 2, 3, 6, 7 };
#elif defined (HAVE_ARM)
  guint debug_regs_count = 0;
#elif defined (HAVE_ARM64)
  struct user_hwdebug_state debug_regs;
  const guint debug_regs_type = (ctx->regs_type == GUM_REGS_DEBUG_BREAK)
      ? NT_ARM_HW_BREAK
      : NT_ARM_HW_WATCH;
  gsize debug_regs_size = sizeof (struct user_hwdebug_state);
  guint debug_regs_count = 0;
#endif
#ifndef HAVE_MIPS
  guint i;
#endif

  fd = ctx->fd[1];

  gum_await_ack (fd, GUM_ACK_READY);

  res = gum_libc_ptrace (PTRACE_ATTACH, ctx->thread_id, NULL, NULL);
  if (res == -1)
    goto failed_to_attach;
  attached = TRUE;

  wait_result = gum_libc_waitpid (ctx->thread_id, &status, __WALL);

  if (wait_result != ctx->thread_id)
    goto failed_to_wait;

  if (!WIFSTOPPED (status))
    goto failed_to_stop;

  /*
   * Although ptrace injects SIGSTOP into our process, it is possible that our
   * target is stopped by another stop signal (e.g. SIGTTIN). The man pages for
   * ptrace mention the possible race condition. For our purposes, however, we
   * only require that the target is stopped so that we can read its registers.
   */
  if (ctx->regs_type == GUM_REGS_GENERAL_PURPOSE)
  {
    gsize regs_size = sizeof (GumGPRegs);

    res = gum_get_regs (ctx->thread_id, NT_PRSTATUS, &ctx->regs_data,
        &regs_size);
    if (res == -1)
      goto failed_to_read;
  }
  else
  {
#if defined (HAVE_I386)
    for (i = 0; i != G_N_ELEMENTS (x86_debugreg_offsets); i++)
    {
      const guint offset = x86_debugreg_offsets[i];

      res = gum_libc_ptrace (PTRACE_PEEKUSER, ctx->thread_id,
          GSIZE_TO_POINTER (
            G_STRUCT_OFFSET (struct user, u_debugreg) +
            (offset * sizeof (gpointer))),
          &ctx->regs_data.debug.dr0 + i);
      if (res == -1)
        goto failed_to_read;
    }
#elif defined (HAVE_ARM)
    guint32 info;
    res = gum_libc_ptrace (PTRACE_GETHBPREGS, ctx->thread_id, 0, &info);
    if (res == -1)
      goto failed_to_read;

    debug_regs_count = (ctx->regs_type == GUM_REGS_DEBUG_BREAK)
        ? info & 0xff
        : (info >> 8) & 0xff;

    long step = (ctx->regs_type == GUM_REGS_DEBUG_WATCH) ? -1 : 1;
    long num = step;
    for (i = 0; i != debug_regs_count; i++)
    {
      res = gum_libc_ptrace (PTRACE_GETHBPREGS, ctx->thread_id,
          GSIZE_TO_POINTER (num), &ctx->regs_data.debug.vr[i]);
      if (res == -1)
        goto failed_to_read;
      num += step;

      res = gum_libc_ptrace (PTRACE_GETHBPREGS, ctx->thread_id,
          GSIZE_TO_POINTER (num), &ctx->regs_data.debug.cr[i]);
      if (res == -1)
        goto failed_to_read;
      num += step;
    }
#elif defined (HAVE_ARM64)
    res = gum_get_regs (ctx->thread_id, debug_regs_type, &debug_regs,
        &debug_regs_size);
    if (res == -1)
      goto failed_to_read;

    debug_regs_count = debug_regs.dbg_info & 0xff;

    for (i = 0; i != G_N_ELEMENTS (debug_regs.dbg_regs); i++)
    {
      ctx->regs_data.debug.cr[i] = debug_regs.dbg_regs[i].ctrl;
      ctx->regs_data.debug.vr[i] = debug_regs.dbg_regs[i].addr;
    }
#elif defined (HAVE_MIPS)
    res = gum_libc_ptrace (PTRACE_GET_WATCH_REGS, ctx->thread_id,
        &ctx->regs_data.debug, NULL);
    if (res == -1)
      goto failed_to_read;
#endif
  }
  gum_put_ack (fd, GUM_ACK_READ_REGISTERS);

  gum_await_ack (fd, GUM_ACK_MODIFIED_REGISTERS);
  if (ctx->regs_type == GUM_REGS_GENERAL_PURPOSE)
  {
    res = gum_set_regs (ctx->thread_id, NT_PRSTATUS, &ctx->regs_data,
        sizeof (GumGPRegs));
    if (res == -1)
      goto failed_to_write;
  }
  else
  {
#if defined (HAVE_I386)
    for (i = 0; i != G_N_ELEMENTS (x86_debugreg_offsets); i++)
    {
      const guint offset = x86_debugreg_offsets[i];
      res = gum_libc_ptrace (PTRACE_POKEUSER, ctx->thread_id,
          GSIZE_TO_POINTER (
            G_STRUCT_OFFSET (struct user, u_debugreg) +
            (offset * sizeof (gpointer))),
          GSIZE_TO_POINTER ((&ctx->regs_data.debug.dr0)[i]));
      if (res == -1)
        goto failed_to_write;
    }
#elif defined (HAVE_ARM)
    long step = (ctx->regs_type == GUM_REGS_DEBUG_WATCH) ? -1 : 1;
    long num = step;
    for (i = 0; i != debug_regs_count; i++)
    {
      res = gum_libc_ptrace (PTRACE_SETHBPREGS, ctx->thread_id,
          GSIZE_TO_POINTER (num), &ctx->regs_data.debug.vr[i]);
      if (res == -1)
        goto failed_to_write;
      num += step;

      res = gum_libc_ptrace (PTRACE_SETHBPREGS, ctx->thread_id,
          GSIZE_TO_POINTER (num), &ctx->regs_data.debug.cr[i]);
      if (res == -1)
        goto failed_to_write;
      num += step;
    }
#elif defined (HAVE_ARM64)
    for (i = 0; i != debug_regs_count; i++)
    {
      debug_regs.dbg_regs[i].ctrl = ctx->regs_data.debug.cr[i];
      debug_regs.dbg_regs[i].addr = ctx->regs_data.debug.vr[i];
    }

    res = gum_set_regs (ctx->thread_id, debug_regs_type, &debug_regs,
        G_STRUCT_OFFSET (struct user_hwdebug_state, dbg_regs) +
        debug_regs_count * 16);
    if (res == -1)
      goto failed_to_write;
#elif defined (HAVE_MIPS)
    res = gum_libc_ptrace (PTRACE_SET_WATCH_REGS, ctx->thread_id,
        &ctx->regs_data.debug, NULL);
    if (res == -1)
      goto failed_to_write;
#endif
  }

  res = gum_libc_ptrace (PTRACE_DETACH, ctx->thread_id, NULL,
      GINT_TO_POINTER (SIGCONT));

  attached = FALSE;
  if (res == -1)
    goto failed_to_detach;

  gum_put_ack (fd, GUM_ACK_WROTE_REGISTERS);

  goto beach;

failed_to_attach:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_ATTACH);
    goto beach;
  }
failed_to_wait:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_WAIT);
    goto beach;
  }
failed_to_stop:
  {
    gum_put_ack (fd
"""


```