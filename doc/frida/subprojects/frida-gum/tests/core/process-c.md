Response:
The user wants a summary of the functionality of the provided C code, which is a test file for Frida's dynamic instrumentation tool, specifically the `frida-gum` component.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The filename `process.c` and the test case names strongly suggest this file tests functionalities related to process introspection and manipulation.

2. **Categorize the test cases:** Group the test cases based on the actions they perform. Look for keywords in the test names like `threads`, `modules`, `ranges`, `exports`, `imports`, etc.

3. **Connect to reverse engineering:**  Consider how each tested functionality is used in reverse engineering. For example, listing modules is essential to understand the loaded libraries in a process.

4. **Relate to low-level concepts:** Identify test cases that interact with operating system primitives or kernel concepts. Examples include thread enumeration, memory ranges, module loading, and access to auxiliary vectors on Linux.

5. **Analyze logical assumptions:**  Note any test cases that involve setting up specific conditions and verifying expected outcomes. The `create_sleeping_dummy_thread_sync` function is a good example of setting up a controlled environment.

6. **Consider user errors:** Think about how a user might misuse the Frida API being tested, leading to unexpected results. This often relates to incorrect parameters or assumptions about the target process.

7. **Trace user actions:**  Imagine the steps a user would take within the Frida framework to trigger the code being tested. This typically involves using Frida's API to inspect a running process.

8. **Synthesize a summary:** Combine the identified functionalities into a concise overview.
```c
/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "valgrind.h"

#ifndef HAVE_WINDOWS
#include <dlfcn.h>
#else
#include <windows.h>
#endif

#include <stdlib.h>
#include <string.h>
#if defined (HAVE_LINUX) && defined (HAVE_SYS_AUXV_H)
# include <sys/auxv.h>
#endif

#if defined (HAVE_LINUX)
# include "gum/gumlinux.h"
#endif

#define TESTCASE(NAME) \
    void test_process_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/Process", test_process, NAME)

TESTLIST_BEGIN (process)
  TESTENTRY (process_threads)
  TESTENTRY (process_threads_exclude_cloaked)
  TESTENTRY (process_threads_should_include_name)
  TESTENTRY (process_modules)
  TESTENTRY (process_ranges)
  TESTENTRY (process_ranges_exclude_cloaked)
  TESTENTRY (thread_ranges_can_be_enumerated)
  TESTENTRY (module_can_be_loaded)
  TESTENTRY (module_imports)
  TESTENTRY (module_import_slot_should_contain_correct_value)
  TESTENTRY (module_exports)
  TESTENTRY (module_symbols)
  TESTENTRY (module_ranges_can_be_enumerated)
  TESTENTRY (module_sections_can_be_enumerated)
  TESTENTRY (module_dependencies_can_be_enumerated)
  TESTENTRY (module_base)
  TESTENTRY (module_export_can_be_found)
#ifndef HAVE_ASAN
  TESTENTRY (module_export_matches_system_lookup)
#endif
#ifdef HAVE_WINDOWS
  TESTENTRY (get_set_system_error)
  TESTENTRY (get_current_thread_id)
#endif
#ifdef HAVE_DARWIN
  TESTENTRY (darwin_enumerate_modules)
  TESTENTRY (darwin_enumerate_modules_should_include_core_foundation)
  TESTENTRY (darwin_enumerate_ranges)
  TESTENTRY (darwin_module_exports)
  TESTENTRY (darwin_module_exports_should_support_dyld)
  TESTENTRY (darwin_libsystem_exports_should_contain_chkstk)
  TESTENTRY (darwin_module_resolver_should_resolve_chkstk)
#endif
#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)
  TESTENTRY (process_malloc_ranges)
#endif
#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  TESTENTRY (linux_process_modules)
#endif
#if defined (HAVE_LINUX) && defined (HAVE_SYS_AUXV_H)
  TESTENTRY (linux_get_cpu_from_auxv_null_32bit)
  TESTENTRY (linux_get_cpu_from_auxv_null_64bit)
  TESTENTRY (linux_get_cpu_from_auxv_representative_32bit)
  TESTENTRY (linux_get_cpu_from_auxv_representative_64bit)
#endif
TESTLIST_END ()

typedef struct _TestForEachContext TestForEachContext;
typedef struct _TestThreadContext TestThreadContext;
typedef struct _TestRangeContext TestRangeContext;
typedef struct _TestThreadSyncData TestThreadSyncData;

struct _TestForEachContext
{
  gboolean value_to_return;
  guint number_of_calls;
};

struct _TestThreadContext
{
  GumThreadId needle;
  gboolean found;
};

struct _TestRangeContext
{
  GumMemoryRange range;
  gboolean found;
  gboolean found_exact;
};

struct _TestThreadSyncData
{
  GMutex mutex;
  GCond cond;
  const gchar * name;
  volatile gboolean started;
  volatile GumThreadId thread_id;
  volatile gboolean * volatile done;
};

#ifdef HAVE_DARWIN

typedef struct _ExportSearch ExportSearch;

struct _ExportSearch
{
  GumExportType type;
  const gchar * name;
  GumAddress result;
};

#endif

static gboolean check_thread_enumeration_testable (void);

static gpointer probe_thread (gpointer data);
static void inspect_thread_ranges (void);

static gboolean store_import_slot_of_malloc_if_available (
    const GumImportDetails * details, gpointer user_data);

#ifndef HAVE_WINDOWS
static gboolean store_export_address_if_tricky_module_export (
    const GumExportDetails * details, gpointer user_data);
#endif

#ifdef HAVE_DARWIN
static gboolean assign_true_if_core_foundation (
    const GumModuleDetails * details, gpointer user_data);
static gboolean process_potential_export_search_result (
    const GumExportDetails * details, gpointer user_data);
#endif

static GThread * create_sleeping_dummy_thread_sync (const gchar * name,
    volatile gboolean * done, GumThreadId * thread_id);
static gpointer sleeping_dummy (gpointer data);
static gboolean thread_found_cb (const GumThreadDetails * details,
    gpointer user_data);
static gboolean thread_check_cb (const GumThreadDetails * details,
    gpointer user_data);
G_GNUC_UNUSED static gboolean thread_collect_if_matching_id (
    const GumThreadDetails * details, gpointer user_data);
static gboolean module_found_cb (const GumModuleDetails * details,
    gpointer user_data);
static gboolean import_found_cb (const GumImportDetails * details,
    gpointer user_data);
static gboolean export_found_cb (const GumExportDetails * details,
    gpointer user_data);
static gboolean symbol_found_cb (const GumSymbolDetails * details,
    gpointer user_data);
static gboolean range_found_cb (const GumRangeDetails * details,
    gpointer user_data);
static gboolean range_check_cb (const GumRangeDetails * details,
    gpointer user_data);
static gboolean store_first_range (const GumRangeDetails * details,
    gpointer user_data);
#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)
static gboolean malloc_range_found_cb (
    const GumMallocRangeDetails * details, gpointer user_data);
static gboolean malloc_range_check_cb (
    const GumMallocRangeDetails * details, gpointer user_data);
#endif
static gboolean section_found_cb (const GumSectionDetails * details,
    gpointer user_data);
static gboolean dep_found_cb (const GumDependencyDetails * details,
    gpointer user_data);

TESTCASE (process_threads)
{
  volatile gboolean done = FALSE;
  GThread * thread_a, * thread_b;
  TestForEachContext ctx;

  if (!check_thread_enumeration_testable ())
    return;

  thread_a = create_sleeping_dummy_thread_sync ("process-test-sleeping-dummy-a",
      &done, NULL);
  thread_b = create_sleeping_dummy_thread_sync ("process-test-sleeping-dummy-b",
      &done, NULL);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >=, 2);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  done = TRUE;
  g_thread_join (thread_b);
  g_thread_join (thread_a);
}

TESTCASE (process_threads_exclude_cloaked)
{
  volatile gboolean done = FALSE;
  GThread * thread;
  TestThreadContext ctx;

  if (!check_thread_enumeration_testable ())
    return;

  thread = create_sleeping_dummy_thread_sync ("process-test-sleeping-dummy",
      &done, &ctx.needle);

  ctx.found = FALSE;
  gum_process_enumerate_threads (thread_check_cb, &ctx);
  g_assert_true (ctx.found);

  gum_cloak_add_thread (ctx.needle);

  ctx.found = FALSE;
  gum_process_enumerate_threads (thread_check_cb, &ctx);
  g_assert_false (ctx.found);

  gum_cloak_remove_thread (ctx.needle);

  done = TRUE;
  g_thread_join (thread);
}

TESTCASE (process_threads_should_include_name)
{
#if defined (HAVE_LINUX) && !defined (HAVE_PTHREAD_SETNAME_NP)
  g_print ("<skipping, libc is too old> ");
#else
  volatile gboolean done = FALSE;
  GThread * thread;
  GumThreadDetails d = { 0, };

  if (!check_thread_enumeration_testable ())
    return;

  thread = create_sleeping_dummy_thread_sync ("named", &done, &d.id);
  gum_process_enumerate_threads (thread_collect_if_matching_id, &d);

  g_assert_cmpstr (d.name, ==, "named");

  done = TRUE;
  g_thread_join (thread);

  g_free ((gpointer) d.name);
#endif
}

static gboolean
check_thread_enumeration_testable (void)
{
#ifdef HAVE_LINUX
  if (gum_process_is_debugger_attached ())
  {
    g_print ("<skipping, debugger is attached> ");
    return FALSE;
  }
#endif

#ifdef HAVE_MIPS
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return FALSE;
  }
#endif

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return FALSE;
  }

  return TRUE;
}

TESTCASE (process_modules)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_process_enumerate_modules (module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_process_enumerate_modules (module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)

typedef struct _ModuleBounds ModuleBounds;

struct _ModuleBounds
{
  const gchar * name;
  GumAddress start;
  GumAddress end;
};

static gboolean find_module_bounds (const GumRangeDetails * details,
    gpointer user_data);
static gboolean verify_module_bounds (const GumModuleDetails * details,
    gpointer user_data);

TESTCASE (linux_process_modules)
{
  void * lib;
  ModuleBounds bounds;

  lib = dlopen (TRICKY_MODULE_NAME, RTLD_NOW | RTLD_GLOBAL);
  g_assert_nonnull (lib);

  bounds.name = TRICKY_MODULE_NAME;
  bounds.start = 0;
  bounds.end = 0;

  gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS, find_module_bounds,
      &bounds);

  g_assert_true (bounds.start != 0);
  g_assert_true (bounds.end != 0);

  gum_process_enumerate_modules (verify_module_bounds, &bounds);

  dlclose (lib);
}

static gboolean
find_module_bounds (const GumRangeDetails * details,
                    gpointer user_data)
{
  ModuleBounds * bounds = user_data;
  const GumMemoryRange * range = details->range;
  const GumFileMapping * file = details->file;
  gchar * name;
  gboolean is_match;

  if (file == NULL)
    return TRUE;

  name = g_path_get_basename (file->path);
  is_match = strcmp (name, bounds->name) == 0;
  g_free (name);

  if (!is_match)
    return TRUE;

  if (bounds->start == 0)
    bounds->start = range->base_address;

  bounds->end = range->base_address + range->size;

  return TRUE;
}

static gboolean
verify_module_bounds (const GumModuleDetails * details,
                      gpointer user_data)
{
  ModuleBounds * bounds = user_data;
  const GumMemoryRange * range = details->range;

  if (strcmp (details->name, bounds->name) != 0)
    return TRUE;

  g_assert_cmphex (range->base_address, ==, bounds->start);
  g_assert_cmphex (range->base_address + range->size, >=, bounds->end);

  return TRUE;
}

#endif

#if defined (HAVE_LINUX) && defined (HAVE_SYS_AUXV_H)

TESTCASE (linux_get_cpu_from_auxv_null_32bit)
{
  const guint32 v[] = { AT_NULL, 0 };
  GumCpuType cpu32;

#if defined (HAVE_I386)
  cpu32 = GUM_CPU_IA32;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu32 = GUM_CPU_ARM;
#elif defined (HAVE_MIPS)
  cpu32 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  g_assert_cmpuint (gum_linux_cpu_type_from_auxv (v, sizeof (v)), ==, cpu32);
}

TESTCASE (linux_get_cpu_from_auxv_null_64bit)
{
  const guint64 v[] = { AT_NULL, 0 };
  GumCpuType cpu64;

#if defined (HAVE_I386)
  cpu64 = GUM_CPU_AMD64;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu64 = GUM_CPU_ARM64;
#elif defined (HAVE_MIPS)
  cpu64 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  g_assert_cmpuint (gum_linux_cpu_type_from_auxv (v, sizeof (v)), ==, cpu64);
}

TESTCASE (linux_get_cpu_from_auxv_representative_32bit)
{
  const guint32 v[] = {
    AT_EXECFN, 0xbaad0001,
    AT_HWCAP, 0xdeadface,
    AT_PAGESZ, 0x1000,
    AT_CLKTCK, 0x64,
    AT_PHDR, 0xbaad0002,
    AT_PHENT, 0x38,
    AT_PHNUM, 0xd,
    AT_BASE, 0xbaad0003,
    AT_FLAGS, 0x0,
    AT_ENTRY, 0xbaad0004,
    AT_UID, 0x3e8,
    AT_EUID, 0x3e8,
    AT_GID, 0x3e8,
    AT_EGID, 0x3e8,
    AT_SECURE, 0x0,
    AT_RANDOM, 0xbaad0005,
    AT_PLATFORM, 0xbaad0006,
    AT_NULL, 0
  };
  GumCpuType cpu32;

#if defined (HAVE_I386)
  cpu32 = GUM_CPU_IA32;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu32 = GUM_CPU_ARM;
#elif defined (HAVE_MIPS)
  cpu32 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  g_assert_cmpuint (gum_linux_cpu_type_from_auxv (v, sizeof (v)), ==, cpu32);
}

TESTCASE (linux_get_cpu_from_auxv_representative_64bit)
{
  const guint64 v[] = {
    AT_EXECFN, 0xcafecafebaad0001,
    AT_HWCAP, 0xdeadface,
    AT_PAGESZ, 0x1000,
    AT_CLKTCK, 0x64,
    AT_PHDR, 0xcafecafebaad0002,
    AT_PHENT, 0x38,
    AT_PHNUM, 0xd,
    AT_BASE, 0xcafecafebaad0003,
    AT_FLAGS, 0x0,
    AT_ENTRY, 0xcafecafebaad0004,
    AT_UID, 0x3e8,
    AT_EUID, 0x3e8,
    AT_GID, 0x3e8,
    AT_EGID, 0x3e8,
    AT_SECURE, 0x0,
    AT_RANDOM, 0xcafecafebaad0005,
    AT_PLATFORM, 0xcafecafebaad0006,
    AT_NULL, 0
  };
  GumCpuType cpu64;

#if defined (HAVE_I386)
  cpu64 = GUM_CPU_AMD64;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu64 = GUM_CPU_ARM64;
#elif defined (HAVE_MIPS)
  cpu64 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  g_assert_cmpuint (gum_linux_cpu_type_from_auxv (v, sizeof (v)), ==, cpu64);
}

#endif

TESTCASE (process_ranges)
{
  {
    TestForEachContext ctx;

    ctx.number_of_calls = 0;
    ctx.value_to_return = TRUE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, >, 1);

    ctx.number_of_calls = 0;
    ctx.value_to_return = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, ==, 1);
  }

  {
    TestRangeContext ctx;
    const gsize malloc_buf_size = 100;
    guint8 * malloc_buf;
    const gsize stack_buf_size = 50;
    guint8 * stack_buf;

    malloc_buf = malloc (malloc_buf_size);
    stack_buf = g_alloca (stack_buf_size);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf);
#if defined (HAVE_ANDROID) && defined (HAVE_ARM64)
    /* https://source.android.com/devices/tech/debug/tagged-pointers */
    ctx.range.base_address &= G_GUINT64_CONSTANT (0x00ffffffffffffff);
#endif
    ctx.range.size = malloc_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert_true (ctx.found);

    ctx.range.base_address++;
    ctx.range.size--;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert_true (ctx.found);

    free (malloc_buf);

    ctx.range.base_address = GUM_ADDRESS (stack_buf);
    ctx.range.size = stack_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert_true (ctx.found);
  }
}

TESTCASE (process_ranges_exclude_cloaked)
{
  GumMemoryRange first = { 0, };
  GumMemoryRange range = { 0, };
  gpointer block;
  TestRangeContext ctx;

  gum_process_enumerate_ranges (GUM_PAGE_RX, store_first_range, &first);

  gum_cloak_add_range (&first);
  gum_process_enumerate_ranges (GUM_PAGE_RX, store_first_range, &range);
  g_assert_cmphex (range.base_address, !=, first.base_address);

  gum_cloak_remove_range (&first);
  gum_process_enumerate_ranges (GUM_PAGE_RX, store_first_range, &range);
  g_assert_cmphex (range.base_address, ==, first.base_address);

  block = gum_malloc (1);
  ctx.range.base_address = GUM_ADDRESS (block);
  ctx.range.size = 1;
  ctx.found = FALSE;
  ctx.found_exact = FALSE;
  gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
  gum_free (block);
  g_assert_false (ctx.found);
}

TESTCASE (thread_ranges_can_be_enumerated)
{
  inspect_thread_ranges ();
  g_thread_join (g_thread_new ("prober-thread", probe_thread, NULL));
}

static gpointer
probe_thread (gpointer data)
{
  inspect_thread_ranges ();
  return NULL;
}

static void
inspect_thread_ranges (void)
{
  GumMemoryRange ranges[2];
  guint n;

  n = gum_thread_try_get_ranges (ranges, G_N_ELEMENTS (ranges));

  if (g_test_verbose ())
  {
    guint i;

    g_print ("\n*** n=%u\n", n);

    for (i = 0; i != n; i++)
    {
      const GumMemoryRange * r = &ranges[i];

      g_print ("\tranges[%u] = 0x%" G_GINT64_MODIFIER "x->0x%"
          G_GINT64_MODIFIER "x (%" G_GSIZE_MODIFIER "u bytes)\n",
          i,
          r->base_address,
          r->base_address + r->size,
          r->size);
    }
  }
}

#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)

#define TEST_STACK_BUFFER_SIZE 50

TESTCASE (process_malloc_ranges)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  {
    TestForEachContext ctx;

    ctx.number_of_calls = 0;
    ctx.value_to_return = TRUE;
    gum_process_enumerate_malloc_ranges (malloc_range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, >, 1);

    ctx.number_of_calls = 0;
    ctx.value_to_return = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, ==, 1);
  }

  {
    TestRangeContext ctx;
    const gsize malloc_buf_size = 100;
    guint8 * malloc_buf;
    guint8 stack_buf[TEST_STACK_BUFFER_SIZE];

    malloc_buf = malloc (malloc_buf_size);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf);
    ctx.range.size = malloc_buf_size;
    ctx.found = FALSE;
    ctx.found_exact =
Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/process.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "valgrind.h"

#ifndef HAVE_WINDOWS
#include <dlfcn.h>
#else
#include <windows.h>
#endif

#include <stdlib.h>
#include <string.h>
#if defined (HAVE_LINUX) && defined (HAVE_SYS_AUXV_H)
# include <sys/auxv.h>
#endif

#if defined (HAVE_LINUX)
# include "gum/gumlinux.h"
#endif

#define TESTCASE(NAME) \
    void test_process_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/Process", test_process, NAME)

TESTLIST_BEGIN (process)
  TESTENTRY (process_threads)
  TESTENTRY (process_threads_exclude_cloaked)
  TESTENTRY (process_threads_should_include_name)
  TESTENTRY (process_modules)
  TESTENTRY (process_ranges)
  TESTENTRY (process_ranges_exclude_cloaked)
  TESTENTRY (thread_ranges_can_be_enumerated)
  TESTENTRY (module_can_be_loaded)
  TESTENTRY (module_imports)
  TESTENTRY (module_import_slot_should_contain_correct_value)
  TESTENTRY (module_exports)
  TESTENTRY (module_symbols)
  TESTENTRY (module_ranges_can_be_enumerated)
  TESTENTRY (module_sections_can_be_enumerated)
  TESTENTRY (module_dependencies_can_be_enumerated)
  TESTENTRY (module_base)
  TESTENTRY (module_export_can_be_found)
#ifndef HAVE_ASAN
  TESTENTRY (module_export_matches_system_lookup)
#endif
#ifdef HAVE_WINDOWS
  TESTENTRY (get_set_system_error)
  TESTENTRY (get_current_thread_id)
#endif
#ifdef HAVE_DARWIN
  TESTENTRY (darwin_enumerate_modules)
  TESTENTRY (darwin_enumerate_modules_should_include_core_foundation)
  TESTENTRY (darwin_enumerate_ranges)
  TESTENTRY (darwin_module_exports)
  TESTENTRY (darwin_module_exports_should_support_dyld)
  TESTENTRY (darwin_libsystem_exports_should_contain_chkstk)
  TESTENTRY (darwin_module_resolver_should_resolve_chkstk)
#endif
#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)
  TESTENTRY (process_malloc_ranges)
#endif
#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  TESTENTRY (linux_process_modules)
#endif
#if defined (HAVE_LINUX) && defined (HAVE_SYS_AUXV_H)
  TESTENTRY (linux_get_cpu_from_auxv_null_32bit)
  TESTENTRY (linux_get_cpu_from_auxv_null_64bit)
  TESTENTRY (linux_get_cpu_from_auxv_representative_32bit)
  TESTENTRY (linux_get_cpu_from_auxv_representative_64bit)
#endif
TESTLIST_END ()

typedef struct _TestForEachContext TestForEachContext;
typedef struct _TestThreadContext TestThreadContext;
typedef struct _TestRangeContext TestRangeContext;
typedef struct _TestThreadSyncData TestThreadSyncData;

struct _TestForEachContext
{
  gboolean value_to_return;
  guint number_of_calls;
};

struct _TestThreadContext
{
  GumThreadId needle;
  gboolean found;
};

struct _TestRangeContext
{
  GumMemoryRange range;
  gboolean found;
  gboolean found_exact;
};

struct _TestThreadSyncData
{
  GMutex mutex;
  GCond cond;
  const gchar * name;
  volatile gboolean started;
  volatile GumThreadId thread_id;
  volatile gboolean * volatile done;
};

#ifdef HAVE_DARWIN

typedef struct _ExportSearch ExportSearch;

struct _ExportSearch
{
  GumExportType type;
  const gchar * name;
  GumAddress result;
};

#endif

static gboolean check_thread_enumeration_testable (void);

static gpointer probe_thread (gpointer data);
static void inspect_thread_ranges (void);

static gboolean store_import_slot_of_malloc_if_available (
    const GumImportDetails * details, gpointer user_data);

#ifndef HAVE_WINDOWS
static gboolean store_export_address_if_tricky_module_export (
    const GumExportDetails * details, gpointer user_data);
#endif

#ifdef HAVE_DARWIN
static gboolean assign_true_if_core_foundation (
    const GumModuleDetails * details, gpointer user_data);
static gboolean process_potential_export_search_result (
    const GumExportDetails * details, gpointer user_data);
#endif

static GThread * create_sleeping_dummy_thread_sync (const gchar * name,
    volatile gboolean * done, GumThreadId * thread_id);
static gpointer sleeping_dummy (gpointer data);
static gboolean thread_found_cb (const GumThreadDetails * details,
    gpointer user_data);
static gboolean thread_check_cb (const GumThreadDetails * details,
    gpointer user_data);
G_GNUC_UNUSED static gboolean thread_collect_if_matching_id (
    const GumThreadDetails * details, gpointer user_data);
static gboolean module_found_cb (const GumModuleDetails * details,
    gpointer user_data);
static gboolean import_found_cb (const GumImportDetails * details,
    gpointer user_data);
static gboolean export_found_cb (const GumExportDetails * details,
    gpointer user_data);
static gboolean symbol_found_cb (const GumSymbolDetails * details,
    gpointer user_data);
static gboolean range_found_cb (const GumRangeDetails * details,
    gpointer user_data);
static gboolean range_check_cb (const GumRangeDetails * details,
    gpointer user_data);
static gboolean store_first_range (const GumRangeDetails * details,
    gpointer user_data);
#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)
static gboolean malloc_range_found_cb (
    const GumMallocRangeDetails * details, gpointer user_data);
static gboolean malloc_range_check_cb (
    const GumMallocRangeDetails * details, gpointer user_data);
#endif
static gboolean section_found_cb (const GumSectionDetails * details,
    gpointer user_data);
static gboolean dep_found_cb (const GumDependencyDetails * details,
    gpointer user_data);

TESTCASE (process_threads)
{
  volatile gboolean done = FALSE;
  GThread * thread_a, * thread_b;
  TestForEachContext ctx;

  if (!check_thread_enumeration_testable ())
    return;

  thread_a = create_sleeping_dummy_thread_sync ("process-test-sleeping-dummy-a",
      &done, NULL);
  thread_b = create_sleeping_dummy_thread_sync ("process-test-sleeping-dummy-b",
      &done, NULL);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >=, 2);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_process_enumerate_threads (thread_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  done = TRUE;
  g_thread_join (thread_b);
  g_thread_join (thread_a);
}

TESTCASE (process_threads_exclude_cloaked)
{
  volatile gboolean done = FALSE;
  GThread * thread;
  TestThreadContext ctx;

  if (!check_thread_enumeration_testable ())
    return;

  thread = create_sleeping_dummy_thread_sync ("process-test-sleeping-dummy",
      &done, &ctx.needle);

  ctx.found = FALSE;
  gum_process_enumerate_threads (thread_check_cb, &ctx);
  g_assert_true (ctx.found);

  gum_cloak_add_thread (ctx.needle);

  ctx.found = FALSE;
  gum_process_enumerate_threads (thread_check_cb, &ctx);
  g_assert_false (ctx.found);

  gum_cloak_remove_thread (ctx.needle);

  done = TRUE;
  g_thread_join (thread);
}

TESTCASE (process_threads_should_include_name)
{
#if defined (HAVE_LINUX) && !defined (HAVE_PTHREAD_SETNAME_NP)
  g_print ("<skipping, libc is too old> ");
#else
  volatile gboolean done = FALSE;
  GThread * thread;
  GumThreadDetails d = { 0, };

  if (!check_thread_enumeration_testable ())
    return;

  thread = create_sleeping_dummy_thread_sync ("named", &done, &d.id);
  gum_process_enumerate_threads (thread_collect_if_matching_id, &d);

  g_assert_cmpstr (d.name, ==, "named");

  done = TRUE;
  g_thread_join (thread);

  g_free ((gpointer) d.name);
#endif
}

static gboolean
check_thread_enumeration_testable (void)
{
#ifdef HAVE_LINUX
  if (gum_process_is_debugger_attached ())
  {
    g_print ("<skipping, debugger is attached> ");
    return FALSE;
  }
#endif

#ifdef HAVE_MIPS
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return FALSE;
  }
#endif

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return FALSE;
  }

  return TRUE;
}

TESTCASE (process_modules)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_process_enumerate_modules (module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_process_enumerate_modules (module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)

typedef struct _ModuleBounds ModuleBounds;

struct _ModuleBounds
{
  const gchar * name;
  GumAddress start;
  GumAddress end;
};

static gboolean find_module_bounds (const GumRangeDetails * details,
    gpointer user_data);
static gboolean verify_module_bounds (const GumModuleDetails * details,
    gpointer user_data);

TESTCASE (linux_process_modules)
{
  void * lib;
  ModuleBounds bounds;

  lib = dlopen (TRICKY_MODULE_NAME, RTLD_NOW | RTLD_GLOBAL);
  g_assert_nonnull (lib);

  bounds.name = TRICKY_MODULE_NAME;
  bounds.start = 0;
  bounds.end = 0;

  gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS, find_module_bounds,
      &bounds);

  g_assert_true (bounds.start != 0);
  g_assert_true (bounds.end != 0);

  gum_process_enumerate_modules (verify_module_bounds, &bounds);

  dlclose (lib);
}

static gboolean
find_module_bounds (const GumRangeDetails * details,
                    gpointer user_data)
{
  ModuleBounds * bounds = user_data;
  const GumMemoryRange * range = details->range;
  const GumFileMapping * file = details->file;
  gchar * name;
  gboolean is_match;

  if (file == NULL)
    return TRUE;

  name = g_path_get_basename (file->path);
  is_match = strcmp (name, bounds->name) == 0;
  g_free (name);

  if (!is_match)
    return TRUE;

  if (bounds->start == 0)
    bounds->start = range->base_address;

  bounds->end = range->base_address + range->size;

  return TRUE;
}

static gboolean
verify_module_bounds (const GumModuleDetails * details,
                      gpointer user_data)
{
  ModuleBounds * bounds = user_data;
  const GumMemoryRange * range = details->range;

  if (strcmp (details->name, bounds->name) != 0)
    return TRUE;

  g_assert_cmphex (range->base_address, ==, bounds->start);
  g_assert_cmphex (range->base_address + range->size, >=, bounds->end);

  return TRUE;
}

#endif

#if defined (HAVE_LINUX) && defined (HAVE_SYS_AUXV_H)

TESTCASE (linux_get_cpu_from_auxv_null_32bit)
{
  const guint32 v[] = { AT_NULL, 0 };
  GumCpuType cpu32;

#if defined (HAVE_I386)
  cpu32 = GUM_CPU_IA32;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu32 = GUM_CPU_ARM;
#elif defined (HAVE_MIPS)
  cpu32 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  g_assert_cmpuint (gum_linux_cpu_type_from_auxv (v, sizeof (v)), ==, cpu32);
}

TESTCASE (linux_get_cpu_from_auxv_null_64bit)
{
  const guint64 v[] = { AT_NULL, 0 };
  GumCpuType cpu64;

#if defined (HAVE_I386)
  cpu64 = GUM_CPU_AMD64;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu64 = GUM_CPU_ARM64;
#elif defined (HAVE_MIPS)
  cpu64 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  g_assert_cmpuint (gum_linux_cpu_type_from_auxv (v, sizeof (v)), ==, cpu64);
}

TESTCASE (linux_get_cpu_from_auxv_representative_32bit)
{
  const guint32 v[] = {
    AT_EXECFN, 0xbaad0001,
    AT_HWCAP, 0xdeadface,
    AT_PAGESZ, 0x1000,
    AT_CLKTCK, 0x64,
    AT_PHDR, 0xbaad0002,
    AT_PHENT, 0x38,
    AT_PHNUM, 0xd,
    AT_BASE, 0xbaad0003,
    AT_FLAGS, 0x0,
    AT_ENTRY, 0xbaad0004,
    AT_UID, 0x3e8,
    AT_EUID, 0x3e8,
    AT_GID, 0x3e8,
    AT_EGID, 0x3e8,
    AT_SECURE, 0x0,
    AT_RANDOM, 0xbaad0005,
    AT_PLATFORM, 0xbaad0006,
    AT_NULL, 0
  };
  GumCpuType cpu32;

#if defined (HAVE_I386)
  cpu32 = GUM_CPU_IA32;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu32 = GUM_CPU_ARM;
#elif defined (HAVE_MIPS)
  cpu32 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  g_assert_cmpuint (gum_linux_cpu_type_from_auxv (v, sizeof (v)), ==, cpu32);
}

TESTCASE (linux_get_cpu_from_auxv_representative_64bit)
{
  const guint64 v[] = {
    AT_EXECFN, 0xcafecafebaad0001,
    AT_HWCAP, 0xdeadface,
    AT_PAGESZ, 0x1000,
    AT_CLKTCK, 0x64,
    AT_PHDR, 0xcafecafebaad0002,
    AT_PHENT, 0x38,
    AT_PHNUM, 0xd,
    AT_BASE, 0xcafecafebaad0003,
    AT_FLAGS, 0x0,
    AT_ENTRY, 0xcafecafebaad0004,
    AT_UID, 0x3e8,
    AT_EUID, 0x3e8,
    AT_GID, 0x3e8,
    AT_EGID, 0x3e8,
    AT_SECURE, 0x0,
    AT_RANDOM, 0xcafecafebaad0005,
    AT_PLATFORM, 0xcafecafebaad0006,
    AT_NULL, 0
  };
  GumCpuType cpu64;

#if defined (HAVE_I386)
  cpu64 = GUM_CPU_AMD64;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu64 = GUM_CPU_ARM64;
#elif defined (HAVE_MIPS)
  cpu64 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  g_assert_cmpuint (gum_linux_cpu_type_from_auxv (v, sizeof (v)), ==, cpu64);
}

#endif

TESTCASE (process_ranges)
{
  {
    TestForEachContext ctx;

    ctx.number_of_calls = 0;
    ctx.value_to_return = TRUE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, >, 1);

    ctx.number_of_calls = 0;
    ctx.value_to_return = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, ==, 1);
  }

  {
    TestRangeContext ctx;
    const gsize malloc_buf_size = 100;
    guint8 * malloc_buf;
    const gsize stack_buf_size = 50;
    guint8 * stack_buf;

    malloc_buf = malloc (malloc_buf_size);
    stack_buf = g_alloca (stack_buf_size);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf);
#if defined (HAVE_ANDROID) && defined (HAVE_ARM64)
    /* https://source.android.com/devices/tech/debug/tagged-pointers */
    ctx.range.base_address &= G_GUINT64_CONSTANT (0x00ffffffffffffff);
#endif
    ctx.range.size = malloc_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert_true (ctx.found);

    ctx.range.base_address++;
    ctx.range.size--;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert_true (ctx.found);

    free (malloc_buf);

    ctx.range.base_address = GUM_ADDRESS (stack_buf);
    ctx.range.size = stack_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
    g_assert_true (ctx.found);
  }
}

TESTCASE (process_ranges_exclude_cloaked)
{
  GumMemoryRange first = { 0, };
  GumMemoryRange range = { 0, };
  gpointer block;
  TestRangeContext ctx;

  gum_process_enumerate_ranges (GUM_PAGE_RX, store_first_range, &first);

  gum_cloak_add_range (&first);
  gum_process_enumerate_ranges (GUM_PAGE_RX, store_first_range, &range);
  g_assert_cmphex (range.base_address, !=, first.base_address);

  gum_cloak_remove_range (&first);
  gum_process_enumerate_ranges (GUM_PAGE_RX, store_first_range, &range);
  g_assert_cmphex (range.base_address, ==, first.base_address);

  block = gum_malloc (1);
  ctx.range.base_address = GUM_ADDRESS (block);
  ctx.range.size = 1;
  ctx.found = FALSE;
  ctx.found_exact = FALSE;
  gum_process_enumerate_ranges (GUM_PAGE_RW, range_check_cb, &ctx);
  gum_free (block);
  g_assert_false (ctx.found);
}

TESTCASE (thread_ranges_can_be_enumerated)
{
  inspect_thread_ranges ();
  g_thread_join (g_thread_new ("prober-thread", probe_thread, NULL));
}

static gpointer
probe_thread (gpointer data)
{
  inspect_thread_ranges ();
  return NULL;
}

static void
inspect_thread_ranges (void)
{
  GumMemoryRange ranges[2];
  guint n;

  n = gum_thread_try_get_ranges (ranges, G_N_ELEMENTS (ranges));

  if (g_test_verbose ())
  {
    guint i;

    g_print ("\n*** n=%u\n", n);

    for (i = 0; i != n; i++)
    {
      const GumMemoryRange * r = &ranges[i];

      g_print ("\tranges[%u] = 0x%" G_GINT64_MODIFIER "x->0x%"
          G_GINT64_MODIFIER "x (%" G_GSIZE_MODIFIER "u bytes)\n",
          i,
          r->base_address,
          r->base_address + r->size,
          r->size);
    }
  }
}

#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)

#define TEST_STACK_BUFFER_SIZE 50

TESTCASE (process_malloc_ranges)
{
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  {
    TestForEachContext ctx;

    ctx.number_of_calls = 0;
    ctx.value_to_return = TRUE;
    gum_process_enumerate_malloc_ranges (malloc_range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, >, 1);

    ctx.number_of_calls = 0;
    ctx.value_to_return = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_found_cb, &ctx);
    g_assert_cmpuint (ctx.number_of_calls, ==, 1);
  }

  {
    TestRangeContext ctx;
    const gsize malloc_buf_size = 100;
    guint8 * malloc_buf;
    guint8 stack_buf[TEST_STACK_BUFFER_SIZE];

    malloc_buf = malloc (malloc_buf_size);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf);
    ctx.range.size = malloc_buf_size;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_check_cb, &ctx);
    g_assert_true (ctx.found);
    g_assert_true (ctx.found_exact);

    ctx.range.base_address = GUM_ADDRESS (malloc_buf) + 1;
    ctx.range.size = malloc_buf_size - 1;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_check_cb, &ctx);
    g_assert_true (ctx.found);
    g_assert_false (ctx.found_exact);

    free (malloc_buf);

    ctx.range.base_address = GUM_ADDRESS (stack_buf);
    ctx.range.size = TEST_STACK_BUFFER_SIZE;
    ctx.found = FALSE;
    ctx.found_exact = FALSE;
    gum_process_enumerate_malloc_ranges (malloc_range_check_cb, &ctx);
    g_assert_false (ctx.found);
    g_assert_false (ctx.found_exact);
  }
}

#endif

TESTCASE (module_can_be_loaded)
{
  GError * error = NULL;
  gchar * invalid_name;

  g_assert_true (gum_module_load (SYSTEM_MODULE_NAME, &error));
  g_assert_no_error (error);

  invalid_name = g_strconcat (SYSTEM_MODULE_NAME, "_nope", NULL);
  g_assert_false (gum_module_load (invalid_name, &error));
  g_assert_nonnull (error);
  g_error_free (error);
  g_free (invalid_name);
}

TESTCASE (module_imports)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_imports (GUM_TESTS_MODULE_NAME, import_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_imports (GUM_TESTS_MODULE_NAME, import_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (module_import_slot_should_contain_correct_value)
{
  gpointer * slot;
  gsize actual_value, expected_value;
  gboolean unsupported_on_this_os;

  slot = NULL;
  gum_module_enumerate_imports (GUM_TESTS_MODULE_NAME,
      store_import_slot_of_malloc_if_available, &slot);

  unsupported_on_this_os = slot == NULL;
  if (unsupported_on_this_os)
  {
    g_print ("<skipping, not yet supported on this OS> ");
    return;
  }

  actual_value = gum_strip_code_address (GPOINTER_TO_SIZE (*slot));
  expected_value = gum_strip_code_address (gum_module_find_export_by_name (
        gum_process_query_libc_name (), "malloc"));

  g_assert_cmphex (actual_value, ==, expected_value);
}

static gboolean
store_import_slot_of_malloc_if_available (const GumImportDetails * details,
                                          gpointer user_data)
{
  gpointer ** result = user_data;

  if (strcmp (details->name, "malloc") != 0)
    return TRUE;

  *result = GSIZE_TO_POINTER (details->slot);
  return FALSE;
}

TESTCASE (module_exports)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_exports (SYSTEM_MODULE_NAME, export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_exports (SYSTEM_MODULE_NAME, export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (module_symbols)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_symbols (GUM_TESTS_MODULE_NAME, symbol_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_symbols (GUM_TESTS_MODULE_NAME, symbol_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (module_ranges_can_be_enumerated)
{
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_ranges (SYSTEM_MODULE_NAME, GUM_PAGE_READ,
      range_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_ranges (SYSTEM_MODULE_NAME, GUM_PAGE_READ,
      range_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (module_sections_can_be_enumerated)
{
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_sections (SYSTEM_MODULE_NAME, section_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_sections (SYSTEM_MODULE_NAME, section_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
#else
  (void) section_found_cb;
#endif
}

TESTCASE (module_dependencies_can_be_enumerated)
{
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
  TestForEachContext ctx;

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_module_enumerate_dependencies (GUM_TESTS_MODULE_NAME, dep_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_module_enumerate_dependencies (GUM_TESTS_MODULE_NAME, dep_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
#else
  (void) dep_found_cb;
#endif
}

TESTCASE (module_base)
{
  g_assert_true (gum_module_find_base_address (SYSTEM_MODULE_NAME) != 0);
}

TESTCASE (module_export_can_be_found)
{
  g_assert_true (gum_module_find_export_by_name (SYSTEM_MODULE_NAME,
      SYSTEM_MODULE_EXPORT) != 0);
}

TESTCASE (module_export_matches_system_lookup)
{
#ifndef HAVE_WINDOWS
  void * lib, * system_address;
  GumAddress enumerate_address, find_by_name_address;

  lib = dlopen (TRICKY_MODULE_NAME, RTLD_NOW | RTLD_GLOBAL);
  g_assert_true (lib != NULL);
  system_address = dlsym (lib, TRICKY_MODULE_EXPORT);

  enumerate_address = 0;
  gum_module_enumerate_exports (TRICKY_MODULE_NAME,
      store_export_address_if_tricky_module_export, &enumerate_address);
  g_assert_true (enumerate_address != 0);

  find_by_name_address =
      gum_module_find_export_by_name (TRICKY_MODULE_NAME, TRICKY_MODULE_EXPORT);

  g_assert_cmphex (enumerate_address, ==, GPOINTER_TO_SIZE (system_address));
  g_assert_cmphex (find_by_name_address, ==, GPOINTER_TO_SIZE (system_address));

  dlclose (lib);
#endif
}

#ifndef HAVE_WINDOWS

static gboolean
store_export_address_if_tricky_module_export (const GumExportDetails * details,
                                              gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION
      && strcmp (details->name, TRICKY_MODULE_EXPORT) == 0)
  {
    *((GumAddress *) user_data) = details->address;
    return FALSE;
  }

  return TRUE;
}

#endif

#ifdef HAVE_WINDOWS

TESTCASE (get_current_thread_id)
{
  g_assert_cmphex (gum_process_get_current_thread_id (), ==,
      GetCurrentThreadId ());
}

TESTCASE (get_set_system_error)
{
  gum_thread_set_system_error (0x12345678);
  g_assert_cmpint (GetLastError (), ==, 0x12345678);
  SetLastError (0x89ABCDEF);
  g_assert_cmpint (gum_thread_get_system_error (), ==, (gint) 0x89ABCDEF);
}

#endif

#ifdef HAVE_DARWIN

#include "gum/gumdarwin.h"
#include <mach/mach.h>

static mach_port_t
gum_test_get_target_task (void)
{
#if 1
  return mach_task_self ();
#else
  mach_port_t task;
  kern_return_t ret;

  ret = task_for_pid (mach_task_self (), 12304, &task);
  g_assert_cmpint (ret, ==, 0);

  return task;
#endif
}

TESTCASE (darwin_enumerate_modules)
{
  mach_port_t task;
  TestForEachContext ctx;

  task = gum_test_get_target_task ();

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_darwin_enumerate_modules (task, module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_darwin_enumerate_modules (task, module_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (darwin_enumerate_modules_should_include_core_foundation)
{
  mach_port_t task;
  gboolean found;

  task = gum_test_get_target_task ();

  found = FALSE;
  gum_darwin_enumerate_modules (task, assign_true_if_core_foundation, &found);
  g_assert_true (found);
}

TESTCASE (darwin_enumerate_ranges)
{
  mach_port_t task;
  TestForEachContext ctx;

  task = gum_test_get_target_task ();

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX, range_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX, range_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (darwin_module_exports)
{
  mach_port_t task;
  TestForEachContext ctx;
  ExportSearch search;
  GumAddress actual_mach_msg_address = 0;
  GumAddress expected_mach_msg_address;
  void * module;

  task = gum_test_get_target_task ();

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_darwin_enumerate_exports (task, SYSTEM_MODULE_NAME,
      export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_darwin_enumerate_exports (task, SYSTEM_MODULE_NAME,
      export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);

  search.type = GUM_EXPORT_FUNCTION;
  search.name = "mach_msg";
  search.result = 0;
  gum_darwin_enumerate_exports (task, SYSTEM_MODULE_NAME,
      process_potential_export_search_result, &search);
  actual_mach_msg_address = search.result;
  g_assert_true (actual_mach_msg_address != 0);

  module = dlopen (SYSTEM_MODULE_NAME, 0);
  expected_mach_msg_address = GUM_ADDRESS (dlsym (module, "mach_msg"));
  g_assert_true (expected_mach_msg_address != 0);
  dlclose (module);

  g_assert_cmphex (actual_mach_msg_address, ==, expected_mach_msg_address);
}

TESTCASE (darwin_module_exports_should_support_dyld)
{
  mach_port_t task;
  TestForEachContext ctx;

  task = gum_test_get_target_task ();

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_darwin_enumerate_exports (task, "/usr/lib/dyld", export_found_cb, &ctx);
  g_assert_cmpuint (ctx.number_of_calls, >=, 1);
}

TESTCASE (darwin_libsystem_exports_should_contain_chkstk)
{
  mach_port_t task;
  ExportSearch search;

  task = gum_test_get_target_task ();

  search.type = GUM_EXPORT_FUNCTION;
  search.name = "___chkstk_darwin";
  search.result = 0;

  gum_darwin_enumerate_exports (task, "/usr/lib/libSystem.B.dylib",
      process_potential_export_search_result, &search);

  g_assert_true (search.result != 0);
}

TESTCASE (darwin_module_resolver_should_resolve_chkstk)
{
  mach_port_t task;
  GumDarwinModuleResolver * resolver;
  GumDarwinModule * libsystem;
  GumExportDetails chkstk;

  task = gum_test_get_target_task ();

  resolver = gum_darwin_module_resolver_new (task, NULL);
  g_assert_nonnull (resolver);

  libsystem = gum_darwin_module_resolver_find_module (resolver,
      "/usr/lib/libSystem.B.dylib");
  g_assert_nonnull (libsystem);

  g_assert_true (gum_darwin_module_resolver_find_export_by_mangled_name (
      resolver, libsystem, "____chkstk_darwin", &chkstk));

  g_object_unref (resolver);
}

static gboolean
assign_true_if_core_foundation (const GumModuleDetails * details,
                                gpointer user_data)
{
  gboolean * found = user_data;

  if (strcmp (details->name, "CoreFoundation") == 0)
  {
    *found = TRUE;
    return FALSE;
  }

  return TRUE;
}

static gboolean
process_potential_export_search_result (const GumExportDetails * details,
                                        gpointer user_data)
{
  ExportSearch * search = user_data;

  if (details->type == search->type &&
      strcmp (details->name, search->name) == 0)
  {
    search->result = details->address;
    return FALSE;
  }

  return TRUE;
}

#endif

static GThread *
create_sleeping_dummy_thread_sync (const gchar * name,
                                   volatile gboolean * done,
                                   GumThreadId * thread_id)
{
  TestThreadSyncData sync_data;
  GThread * thread;

  g_mutex_init (&sync_data.mutex);
  g_cond_init (&sync_data.cond);
  sync_data.started = FALSE;
  sync_data.thread_id = 0;
  sync_data.name = name;
  sync_data.done = done;

  g_mutex_lock (&sync_data.mutex);

  thread = g_thread_new (name, sleeping_dummy, &sync_data);

  while (!sync_data.started)
    g_cond_wait (&sync_data.cond, &sync_data.mutex);

  if (thread_id != NULL)
    *thread_id = sync_data.thread_id;

  g_mutex_unlock (&sync_data.mutex);

  g_cond_clear (&sync_data.cond);
  g_mutex_clear (&sync_data.mutex);

  return thread;
}

static gpointer
sleeping_dummy (gpointer data)
{
  TestThreadSyncData * sync_data = data;
  volatile gboolean * done = sync_data->done;

  /*
   * On Linux g_thread_new() may not actually set the thread name, which is due
   * to GLib potentially having been prebuilt against an old libc. Therefore we
   * set the name manually using pthreads.
   */
#if defined (HAVE_LINUX) && defined (HAVE_PTHREAD_SETNAME_NP)
  pthread_setname_np (pthread_self (), sync_data->name);
#endif

  g_mutex_lock (&sync_data->mutex);
  sync_data->started = TRUE;
  sync_data->thread_id = gum_process_get_current_thread_id ();
  g_cond_signal (&sync_data->cond);
  g_mutex_unlock (&sync_data->mutex);

  while (!(*done))
    g_thread_yield ();

  return NULL;
}

static gboolean
thread_found_cb (const GumThreadDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
thread_check_cb (const GumThreadDetails * details,
                 gpointer user_data)
{
  TestThreadContext * ctx = user_data;

  if (details->id == ctx->needle)
    ctx->found = TRUE;

  return !ctx->found;
}

static gboolean
thread_collect_if_matching_id (const GumThreadDetails * details,
                               gpointer user_data)
{
  GumThreadDetails * ctx = user_data;

  if (details->id != ctx->id)
    return TRUE;

  ctx->name = g_strdup (details->name);
  ctx->state = details->state;
  ctx->cpu_context = details->cpu_context;

  return FALSE;
}

static gboolean
module_found_cb (const GumModuleDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
import_found_cb (const GumImportDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = user_data;

  ctx->number_of_calls++;

  if (strcmp (details->name, "malloc") == 0)
    g_assert_cmpint (details->type, ==, GUM_IMPORT_FUNCTION);

  return ctx->value_to_return;
}

static gboolean
export_found_cb (const GumExportDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = user_data;

  ctx->number_of_calls++;

#ifdef HAVE_DARWIN
  if (strcmp (details->name, "malloc") == 0)
    g_assert_cmpint (details->type, ==, GUM_EXPORT_FUNCTION);
  else if (g_str_has_prefix (details->name, "OBJC_CLASS_"))
    g_assert_cmpint (details->type, ==, GUM_EXPORT_VARIABLE);
  else if (strcmp (details->name, "dispatch_async_f") == 0)
    g_assert_cmpint (details->type, ==, GUM_EXPORT_FUNCTION);
#endif

  return ctx->value_to_return;
}

static gboolean
symbol_found_cb (const GumSymbolDetails * details,
                 gpointer user_data)
{
  TestForEachContext * ctx = user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
range_found_cb (const GumRangeDetails * details,
                gpointer user_data)
{
  TestForEachContext * ctx = user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

static gboolean
range_check_cb (const GumRangeDetails * details,
                gpointer user_data)
{
  TestRangeContext * ctx = user_data;
  GumAddress ctx_start, ctx_end;
  GumAddress details_start, details_end;

  ctx_start = ctx->range.base_address;
  ctx_end = ctx_start + ctx->range.size;

  details_start = details->range->base_address;
  details_end = detai
"""


```