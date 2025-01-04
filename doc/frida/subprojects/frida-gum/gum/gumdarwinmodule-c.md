Response:
My thought process for analyzing the provided C code snippet for `gumdarwinmodule.c` went something like this:

1. **Understand the Goal:** The request asks for a functional summary, highlighting relationships to reverse engineering, low-level concepts (binary, Linux/Android kernel), logical reasoning, potential user errors, debugging context, and finally, a concise function summary for this specific part.

2. **Initial Scan for Keywords and Structures:** I quickly scanned the code for recognizable keywords and data structures relevant to the requested information. I looked for:
    * **Platform-specific defines:** `#ifdef HAVE_DARWIN` immediately signals Darwin/macOS specific functionality.
    * **Data Structures:**  `struct`, `typedef struct`, `enum` reveal how data is organized. Names like `GumDarwinModule`, `GumImportDetails`, `GumExportDetails`, `GumMemoryRange`, `GumMachHeader*`, `GumSegmentCommand*`, `GumSection*`,  `GumNList*` are strong indicators of Mach-O (the executable format on macOS) handling.
    * **Function prefixes:** `gum_darwin_module_*` suggests functions operating on the `GumDarwinModule` structure.
    * **Core reverse engineering concepts:** "symbol", "export", "import", "rebase", "bind", "address", "offset", "segment", "section", "UUID".
    * **Low-level hints:** "CPU type", "pointer size", "task" (referring to Mach tasks).
    * **GObject related functions:**  `g_object_new`, `g_object_unref`, `g_object_class_install_property`, `g_value_set_*`, `g_value_get_*` indicating the use of the GLib object system.
    * **Memory management:** `g_array_new`, `g_array_unref`, `g_free`, `g_bytes_unref`, `g_mapped_file_*`.

3. **Group Functionality by Purpose:**  I started grouping the defined structures and functions based on their apparent purpose:
    * **Module Representation:**  `GumDarwinModule`, its properties, and associated creation functions (`gum_darwin_module_new_from_file`, `gum_darwin_module_new_from_blob`, `gum_darwin_module_new_from_memory`).
    * **Image Loading:**  Functions like `gum_darwin_module_load`, `gum_darwin_module_load_image_from_*`.
    * **Symbol Resolution:** `gum_darwin_module_resolve_symbol_address`, `gum_store_address_if_name_matches`.
    * **Import/Export Handling:** `gum_darwin_module_enumerate_imports`, `gum_darwin_module_enumerate_exports`, `gum_emit_import`, `gum_emit_export_from_symbol`.
    * **Low-Level Mach-O Parsing:** Functions dealing with segments, sections, load commands, and specific Mach-O data structures (`GumMachHeader*`, `GumSegmentCommand*`, etc.).
    * **Rebasing and Binding:** Functions related to rebasing (`gum_darwin_module_enumerate_rebases`) and binding (`gum_darwin_module_enumerate_binds`, `gum_darwin_module_enumerate_lazy_binds`, `gum_darwin_module_enumerate_chained_binds`).
    * **Memory Management:**  Functions for reading from tasks (`gum_darwin_module_read_from_task`).

4. **Connect to Reverse Engineering Concepts:**  As I grouped the functionality, I explicitly considered how each group relates to reverse engineering:
    * **Module Representation:**  Essential for identifying and representing loaded libraries/executables.
    * **Image Loading:** The first step in analyzing a binary.
    * **Symbol Resolution:** Core to understanding function calls and data access.
    * **Import/Export Handling:** Reveals dependencies and the public interface of a module.
    * **Low-Level Mach-O Parsing:** Necessary for understanding the binary structure and metadata.
    * **Rebasing and Binding:** Crucial for understanding how addresses are adjusted at runtime and how dependencies are linked.

5. **Identify Low-Level Interactions:**  I looked for explicit mentions or obvious implications of low-level concepts:
    * **Platform dependence:** `#ifdef HAVE_DARWIN` clearly indicates macOS specific code.
    * **Kernel interaction:** `gum_kernel_get_task()`, `gum_kernel_read()` point to kernel-level operations (likely when Frida is running in kernel mode or interacting with the kernel).
    * **Memory management:** Direct manipulation of memory addresses and sizes.
    * **CPU architecture:** Handling of `cpu_type` and `ptrauth_support`.

6. **Consider Logical Reasoning:** I looked for places where the code makes decisions or transformations:
    * **Symbol lookup:** The `gum_store_address_if_name_matches` function performs a string comparison.
    * **Import resolution:** The logic within `gum_emit_import` to determine the dependency module.
    * **Iterating through Mach-O structures:** Loops and conditional statements used to parse headers, load commands, segments, and sections.

7. **Think About User Errors:** I considered how a user interacting with Frida might cause issues related to this code:
    * **Incorrect paths:** Providing an invalid path to `gum_darwin_module_new_from_file`.
    * **Invalid blobs:**  Providing corrupt or incompatible binary data to `gum_darwin_module_new_from_blob`.
    * **Targeting the wrong process/task:** While not directly in this code, the `task` parameter implies interaction with a specific process.

8. **Establish Debugging Context:** I imagined how a developer using Frida might end up debugging this code:
    * **Inspecting module metadata:** Trying to access properties like name, UUID, base address.
    * **Analyzing imports/exports:** Investigating how Frida resolves dependencies.
    * **Troubleshooting crashes or unexpected behavior:** Stepping through the code to understand Mach-O parsing or rebasing logic.

9. **Synthesize a Summary:**  Finally, I combined the above observations into a concise summary, focusing on the key functionalities and their role in dynamic instrumentation. I aimed for a high-level overview without getting bogged down in excessive detail. For the "Part 1" summary, I focused on the core responsibilities covered in the provided code.

By following these steps, I could break down the relatively complex C code into manageable parts, understand its purpose within the larger Frida framework, and address all the specific points raised in the request.
```c
/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2022 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2023 Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumdarwinmodule.h"

#include "gumdarwinmodule-priv.h"
#ifdef HAVE_DARWIN
# include "gum/gumdarwin.h"
#endif
#include "gumleb.h"
#include "gumkernel.h"

#define GUM_MAX_MACHO_METADATA_SIZE   (64 * 1024)

#define GUM_DARWIN_MODULE_HAS_HEADER_ONLY(self) \
    ((self->flags & GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY) != 0)

typedef struct _GumResolveSymbolContext GumResolveSymbolContext;

typedef struct _GumEmitImportContext GumEmitImportContext;
typedef struct _GumEmitExportFromSymbolContext GumEmitExportFromSymbolContext;
typedef struct _GumQueryTlvParamsContext GumQueryTlvParamsContext;
typedef struct _GumEmitInitPointersContext GumEmitInitPointersContext;
typedef struct _GumEmitInitOffsetsContext GumEmitInitOffsetsContext;
typedef struct _GumEmitTermPointersContext GumEmitTermPointersContext;

typedef struct _GumExportsTrieForeachContext GumExportsTrieForeachContext;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_UUID,
  PROP_TASK,
  PROP_CPU_TYPE,
  PROP_PTRAUTH_SUPPORT,
  PROP_BASE_ADDRESS,
  PROP_SOURCE_PATH,
  PROP_SOURCE_BLOB,
  PROP_FLAGS,
};

struct _GumResolveSymbolContext
{
  const gchar * name;
  GumAddress result;
};

struct _GumEmitImportContext
{
  GumFoundImportFunc func;
  GumResolveExportFunc resolver;
  gpointer user_data;

  GumDarwinModule * module;
  GArray * threaded_binds;
  const guint8 * source_start;
  const guint8 * source_end;
  GMappedFile * source_file;
  gboolean carry_on;
};

struct _GumEmitExportFromSymbolContext
{
  GumFoundDarwinExportFunc func;
  gpointer user_data;
};

struct _GumQueryTlvParamsContext
{
  GumMachHeader32 * header;
  GumDarwinTlvParameters * params;
};

struct _GumEmitInitPointersContext
{
  GumFoundDarwinInitPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumEmitInitOffsetsContext
{
  GumFoundDarwinInitOffsetsFunc func;
  gpointer user_data;
};

struct _GumEmitTermPointersContext
{
  GumFoundDarwinTermPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumExportsTrieForeachContext
{
  GumFoundDarwinExportFunc func;
  gpointer user_data;

  GString * prefix;
  const guint8 * exports;
  const guint8 * exports_end;
};

static void gum_darwin_module_constructed (GObject * object);
static void gum_darwin_module_finalize (GObject * object);
static void gum_darwin_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_store_address_if_name_matches (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_emit_import (const GumDarwinBindDetails * details,
    gpointer user_data);
static gboolean gum_emit_export_from_symbol (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_collect_tlv_params (const GumDarwinSectionDetails * section,
    gpointer user_data);
static gboolean gum_emit_section_init_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_emit_section_init_offsets (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_emit_section_term_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_darwin_module_load_image_from_filesystem (
    GumDarwinModule * self, const gchar * path, GError ** error);
static gboolean gum_darwin_module_load_image_header_from_filesystem (
    GumDarwinModule * self, const gchar * path, GError ** error);
static gboolean gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
    GBytes * blob, GError ** error);
static gboolean gum_darwin_module_load_image_from_memory (
    GumDarwinModule * self, GError ** error);
static gboolean gum_darwin_module_can_load (GumDarwinModule * self,
    GumDarwinCpuType cpu_type, GumDarwinCpuSubtype cpu_subtype);
static gboolean gum_darwin_module_take_image (GumDarwinModule * self,
    GumDarwinModuleImage * image, GError ** error);
static gboolean gum_darwin_module_get_header_offset_size (
    GumDarwinModule * self, gpointer data, gsize data_size, gsize * out_offset,
    gsize * out_size, GError ** error);
static void gum_darwin_module_read_and_assign (GumDarwinModule * self,
    GumAddress address, gsize size, const guint8 ** start, const guint8 ** end,
    gpointer * malloc_data);
static gboolean gum_find_linkedit (const guint8 * module, gsize module_size,
    GumAddress * linkedit);
static gboolean gum_add_text_range_if_text_section (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_section_flags_indicate_text_section (guint32 flags);

static gboolean gum_exports_trie_find (const guint8 * exports,
    const guint8 * exports_end, const gchar * name,
    GumDarwinExportDetails * details);
static gboolean gum_exports_trie_foreach (const guint8 * exports,
    const guint8 * exports_end, GumFoundDarwinExportFunc func,
    gpointer user_data);
static gboolean gum_exports_trie_traverse (const guint8 * p,
    GumExportsTrieForeachContext * ctx);

static void gum_darwin_export_details_init_from_node (
    GumDarwinExportDetails * details, const gchar * name, const guint8 * node,
    const guint8 * exports_end);

static void gum_darwin_module_enumerate_chained_binds (GumDarwinModule * self,
    GumFoundDarwinBindFunc func, gpointer user_data);
static gboolean gum_emit_chained_imports (
    const GumDarwinChainedFixupsDetails * details, GumEmitImportContext * ctx);

static GumCpuType gum_cpu_type_from_darwin (GumDarwinCpuType cpu_type);
static GumPtrauthSupport gum_ptrauth_support_from_darwin (
    GumDarwinCpuType cpu_type, GumDarwinCpuSubtype cpu_subtype);
static guint gum_pointer_size_from_cpu_type (GumDarwinCpuType cpu_type);

G_DEFINE_TYPE (GumDarwinModule, gum_darwin_module, G_TYPE_OBJECT)

G_DEFINE_BOXED_TYPE (GumDarwinModuleImage, gum_darwin_module_image,
                     gum_darwin_module_image_dup, gum_darwin_module_image_free)

static void
gum_darwin_module_class_init (GumDarwinModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_darwin_module_constructed;
  object_class->finalize = gum_darwin_module_finalize;
  object_class->get_property = gum_darwin_module_get_property;
  object_class->set_property = gum_darwin_module_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_UUID,
      g_param_spec_string ("uuid", "UUID", "UUID", NULL,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "Task", "Mach task", 0, G_MAXUINT,
      GUM_DARWIN_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CPU_TYPE,
      g_param_spec_uint ("cpu-type", "CpuType", "CPU type", 0, G_MAXUINT,
      GUM_CPU_INVALID, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PTRAUTH_SUPPORT,
      g_param_spec_uint ("ptrauth-support", "PtrauthSupport",
      "Pointer authentication support", 0, G_MAXUINT, GUM_PTRAUTH_INVALID,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "BaseAddress", "Base address", 0,
      G_MAXUINT64, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_PATH,
      g_param_spec_string ("source-path", "SourcePath", "Source path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_BLOB,
      g_param_spec_boxed ("source-blob", "SourceBlob", "Source blob",
      G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_FLAGS,
      g_param_spec_flags ("flags", "Flags", "Optional flags",
      GUM_TYPE_DARWIN_MODULE_FLAGS, GUM_DARWIN_MODULE_FLAGS_NONE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_module_init (GumDarwinModule * self)
{
  self->segments = g_array_new (FALSE, FALSE, sizeof (GumDarwinSegment));
  self->text_ranges = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->dependencies =
      g_array_new (FALSE, FALSE, sizeof (GumDependencyDetails));
  self->reexports = g_ptr_array_sized_new (5);
}

static void
gum_darwin_module_constructed (GObject * object)
{
#ifdef HAVE_DARWIN
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  if (self->task != GUM_DARWIN_PORT_NULL)
  {
    self->is_local = self->task == mach_task_self ();
    self->is_kernel = self->task == gum_kernel_get_task ();
  }
#endif
}

static void
gum_darwin_module_finalize (GObject * object)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  g_array_unref (self->dependencies);
  g_ptr_array_unref (self->reexports);

  g_free (self->rebases_malloc_data);
  g_free (self->binds_malloc_data);
  g_free (self->lazy_binds_malloc_data);
  g_free (self->exports_malloc_data);

  g_array_unref (self->segments);
  g_array_unref (self->text_ranges);

  if (self->image != NULL)
    gum_darwin_module_image_free (self->image);

  g_free (self->source_path);
  g_bytes_unref (self->source_blob);

  g_free (self->name);
  g_free (self->uuid);

  G_OBJECT_CLASS (gum_darwin_module_parent_class)->finalize (object);
}

static void
gum_darwin_module_get_property (GObject * object,
                                guint property_id,
                                GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_UUID:
      if (self->uuid == NULL)
        gum_darwin_module_ensure_image_loaded (self, NULL);
      g_value_set_string (value, self->uuid);
      break;
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    case PROP_CPU_TYPE:
      g_value_set_uint (value, self->cpu_type);
      break;
    case PROP_PTRAUTH_SUPPORT:
      g_value_set_uint (value, self->ptrauth_support);
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, self->base_address);
      break;
    case PROP_SOURCE_PATH:
      g_value_set_string (value, self->source_path);
      break;
    case PROP_SOURCE_BLOB:
      g_value_set_boxed (value, self->source_blob);
      break;
    case PROP_FLAGS:
      g_value_set_flags (value, self->flags);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_module_set_property (GObject * object,
                                guint property_id,
                                const GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_TASK:
      self->task = g_value_get_uint (value);
      break;
    case PROP_CPU_TYPE:
      self->cpu_type = g_value_get_uint (value);
      break;
    case PROP_PTRAUTH_SUPPORT:
      self->ptrauth_support = g_value_get_uint (value);
      break;
    case PROP_BASE_ADDRESS:
      self->base_address = g_value_get_uint64 (value);
      break;
    case PROP_SOURCE_PATH:
      g_free (self->source_path);
      self->source_path = g_value_dup_string (value);
      break;
    case PROP_SOURCE_BLOB:
      g_clear_pointer (&self->source_blob, g_bytes_unref);
      self->source_blob = g_value_dup_boxed (value);
      break;
    case PROP_FLAGS:
      self->flags = g_value_get_flags (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinModule *
gum_darwin_module_new_from_file (const gchar * path,
                                 GumCpuType cpu_type,
                                 GumPtrauthSupport ptrauth_support,
                                 GumDarwinModuleFlags flags,
                                 GError ** error)
{
  GumDarwinModule * module;

  module = g_object_new (GUM_TYPE_DARWIN_MODULE,
      "cpu-type", cpu_type,
      "ptrauth-support", ptrauth_support,
      "source-path", path,
      "flags", flags,
      NULL);
  if (!gum_darwin_module_load (module, error))
  {
    g_object_unref (module);
    module = NULL;
  }

  return module;
}

GumDarwinModule *
gum_darwin_module_new_from_blob (GBytes * blob,
                                 GumCpuType cpu_type,
                                 GumPtrauthSupport ptrauth_support,
                                 GumDarwinModuleFlags flags,
                                 GError ** error)
{
  GumDarwinModule * module;

  module = g_object_new (GUM_TYPE_DARWIN_MODULE,
      "cpu-type", cpu_type,
      "ptrauth-support", ptrauth_support,
      "source-blob", blob,
      "flags", flags,
      NULL);
  if (!gum_darwin_module_load (module, error))
  {
    g_object_unref (module);
    module = NULL;
  }

  return module;
}

GumDarwinModule *
gum_darwin_module_new_from_memory (const gchar * name,
                                   GumDarwinPort task,
                                   GumAddress base_address,
                                   GumDarwinModuleFlags flags,
                                   GError ** error)
{
  GumDarwinModule * module;

  module = g_object_new (GUM_TYPE_DARWIN_MODULE,
      "name", name,
      "task", task,
      "base-address", base_address,
      "flags", flags,
      NULL);
  if (!gum_darwin_module_load (module, error))
  {
    g_object_unref (module);
    module = NULL;
  }

  return module;
}

gboolean
gum_darwin_module_load (GumDarwinModule * self,
                        GError ** error)
{
  if (self->image != NULL)
    return TRUE;

  if (self->source_path != NULL)
  {
    if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self))
    {
      if (!gum_darwin_module_load_image_header_from_filesystem (self,
          self->source_path, error))
      {
        return FALSE;
      }
    }
    else
    {
      if (!gum_darwin_module_load_image_from_filesystem (self,
          self->source_path, error))
      {
        return FALSE;
      }
    }
  }
  else if (self->source_blob != NULL)
  {
    if (!gum_darwin_module_load_image_from_blob (self, self->source_blob,
        error))
    {
      return FALSE;
    }
  }

  if (self->name == NULL)
    return gum_darwin_module_ensure_image_loaded (self, error);

  return TRUE;
}

static guint8 *
gum_darwin_module_read_from_task (GumDarwinModule * self,
                                  GumAddress address,
                                  gsize len,
                                  gsize * n_bytes_read)
{
#ifdef HAVE_DARWIN
  return self->is_kernel
      ? gum_kernel_read (address, len, n_bytes_read)
      : gum_darwin_read (self->task, address, len, n_bytes_read);
#else
  return NULL;
#endif
}

gboolean
gum_darwin_module_resolve_export (GumDarwinModule * self,
                                  const gchar * name,
                                  GumDarwinExportDetails * details)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  if (self->exports != NULL)
  {
    return gum_exports_trie_find (self->exports, self->exports_end, name,
        details);
  }
  else if (self->filetype == GUM_DARWIN_MODULE_FILETYPE_DYLINKER)
  {
    GumAddress address;

    address = gum_darwin_module_resolve_symbol_address (self, name);
    if (address == 0)
      return FALSE;

    details->name = name;
    details->flags = GUM_DARWIN_EXPORT_ABSOLUTE;
    details->offset = address;

    return TRUE;
  }

  return FALSE;
}

GumAddress
gum_darwin_module_resolve_symbol_address (GumDarwinModule * self,
                                          const gchar * name)
{
  GumResolveSymbolContext ctx;

  ctx.name = name;
  ctx.result = 0;

  gum_darwin_module_enumerate_symbols (self, gum_store_address_if_name_matches,
      &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_name_matches (const GumDarwinSymbolDetails * details,
                                   gpointer user_data)
{
  GumResolveSymbolContext * ctx = user_data;
  gboolean carry_on = TRUE;

  if (strcmp (details->name, ctx->name) == 0)
  {
    ctx->result = details->address;
    carry_on = FALSE;
  }

  return carry_on;
}

gboolean
gum_darwin_module_get_lacks_exports_for_reexports (GumDarwinModule * self)
{
  guint32 flags;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  /*
   * FIXME: There must be a better way to detect this behavioral change
   *        introduced in macOS 10.11 and iOS 9.0, but this will have to
   *        do for now.
   */
  flags = ((GumMachHeader32 *) self->image->data)->flags;

  return (flags & GUM_MH_PREBOUND) == 0;
}

void
gum_darwin_module_enumerate_imports (GumDarwinModule * self,
                                     GumFoundImportFunc func,
                                     GumResolveExportFunc resolver,
                                     gpointer user_data)
{
  GumEmitImportContext ctx;

  ctx.func = func;
  ctx.resolver = resolver;
  ctx.user_data = user_data;

  ctx.module = self;
  ctx.threaded_binds = NULL;
  ctx.source_start = NULL;
  ctx.source_end = NULL;
  ctx.source_file = NULL;
  ctx.carry_on = TRUE;

  gum_darwin_module_enumerate_binds (self, gum_emit_import, &ctx);
  if (ctx.carry_on)
    gum_darwin_module_enumerate_lazy_binds (self, gum_emit_import, &ctx);
  if (ctx.carry_on)
    gum_darwin_module_enumerate_chained_binds (self, gum_emit_import, &ctx);

  g_clear_pointer (&ctx.source_file, g_mapped_file_unref);
  g_clear_pointer (&ctx.threaded_binds, g_array_unref);
}

static gboolean
gum_emit_import (const GumDarwinBindDetails * details,
                 gpointer user_data)
{
  GumEmitImportContext * ctx = user_data;
  GumDarwinModule * self = ctx->module;
  const GumDarwinSegment * segment = details->segment;
  GumAddress vm_base;

  vm_base = segment->vm_address + gum_darwin_module_get_slide (self);

  switch (details->type)
  {
    case GUM_DARWIN_BIND_POINTER:
    {
      GumImportDetails d;

      d.type = GUM_IMPORT_UNKNOWN;
      d.name = details->symbol_name;
      switch (details->library_ordinal)
      {
        case GUM_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
        case GUM_BIND_SPECIAL_DYLIB_SELF:
          return TRUE;
        case GUM_BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
        {
          d.module = NULL;
          break;
        }
        default:
          d.module = gum_darwin_module_get_dependency_by_ordinal (self,
              details->library_ordinal);
          break;
      }
      d.address = 0;
      d.slot = vm_base + details->offset;

      if (ctx->threaded_binds != NULL)
        g_array_append_val (ctx->threaded_binds, d);
      else
        ctx->carry_on = ctx->func (&d, ctx->user_data);

      break;
    }
    case GUM_DARWIN_BIND_THREADED_TABLE:
    {
      g_clear_pointer (&ctx->threaded_binds, g_array_unref);
      ctx->threaded_binds = g_array_sized_new (FALSE, FALSE,
          sizeof (GumImportDetails), details->threaded_table_size);

      break;
    }
    case GUM_DARWIN_BIND_THREADED_ITEMS:
    {
      GArray * threaded_binds = ctx->threaded_binds;
      guint64 cursor;
      GumDarwinThreadedItem item;

      if (threaded_binds == NULL)
        return TRUE;

      if (ctx->source_start == NULL)
      {
        gchar * source_path = NULL;
        GMappedFile * file;

#ifdef HAVE_DARWIN
        if (self->task != GUM_DARWIN_PORT_NULL)
        {
          GumDarwinMappingDetails mapping;
          if (gum_darwin_query_mapped_address (self->task, vm_base, &mapping))
            source_path = g_strdup (mapping.path);
        }
#endif
        if (source_path == NULL)
        {
          source_path = g_strdup (self->name);
          if (source_path == NULL)
            return TRUE;
        }
        file = g_mapped_file_new (source_path, FALSE, NULL);
        g_free (source_path);
        if (file == NULL)
          return TRUE;

        ctx->source_start = (const guint8 *) g_mapped_file_get_contents (file);
        ctx->source_end = ctx->source_start + g_mapped_file_get_length (file);
        ctx->source_file = file;
      }

      cursor = details->offset;

      do
      {
        const guint8 * raw_slot;

        raw_slot = ctx->source_start + segment->file_offset + cursor;
        if (raw_slot < ctx->source_start ||
            raw_slot + sizeof (guint64) > ctx->source_end)
        {
          return FALSE;
        }

        gum_darwin_threaded_item_parse (*((const guint64 *) raw_slot), &item);

        if (item.type == GUM_DARWIN_THREADED_BIND)
        {
          
Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gumdarwinmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2022 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2023 Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumdarwinmodule.h"

#include "gumdarwinmodule-priv.h"
#ifdef HAVE_DARWIN
# include "gum/gumdarwin.h"
#endif
#include "gumleb.h"
#include "gumkernel.h"

#define GUM_MAX_MACHO_METADATA_SIZE   (64 * 1024)

#define GUM_DARWIN_MODULE_HAS_HEADER_ONLY(self) \
    ((self->flags & GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY) != 0)

typedef struct _GumResolveSymbolContext GumResolveSymbolContext;

typedef struct _GumEmitImportContext GumEmitImportContext;
typedef struct _GumEmitExportFromSymbolContext GumEmitExportFromSymbolContext;
typedef struct _GumQueryTlvParamsContext GumQueryTlvParamsContext;
typedef struct _GumEmitInitPointersContext GumEmitInitPointersContext;
typedef struct _GumEmitInitOffsetsContext GumEmitInitOffsetsContext;
typedef struct _GumEmitTermPointersContext GumEmitTermPointersContext;

typedef struct _GumExportsTrieForeachContext GumExportsTrieForeachContext;

enum
{
  PROP_0,
  PROP_NAME,
  PROP_UUID,
  PROP_TASK,
  PROP_CPU_TYPE,
  PROP_PTRAUTH_SUPPORT,
  PROP_BASE_ADDRESS,
  PROP_SOURCE_PATH,
  PROP_SOURCE_BLOB,
  PROP_FLAGS,
};

struct _GumResolveSymbolContext
{
  const gchar * name;
  GumAddress result;
};

struct _GumEmitImportContext
{
  GumFoundImportFunc func;
  GumResolveExportFunc resolver;
  gpointer user_data;

  GumDarwinModule * module;
  GArray * threaded_binds;
  const guint8 * source_start;
  const guint8 * source_end;
  GMappedFile * source_file;
  gboolean carry_on;
};

struct _GumEmitExportFromSymbolContext
{
  GumFoundDarwinExportFunc func;
  gpointer user_data;
};

struct _GumQueryTlvParamsContext
{
  GumMachHeader32 * header;
  GumDarwinTlvParameters * params;
};

struct _GumEmitInitPointersContext
{
  GumFoundDarwinInitPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumEmitInitOffsetsContext
{
  GumFoundDarwinInitOffsetsFunc func;
  gpointer user_data;
};

struct _GumEmitTermPointersContext
{
  GumFoundDarwinTermPointersFunc func;
  gpointer user_data;
  gsize pointer_size;
};

struct _GumExportsTrieForeachContext
{
  GumFoundDarwinExportFunc func;
  gpointer user_data;

  GString * prefix;
  const guint8 * exports;
  const guint8 * exports_end;
};

static void gum_darwin_module_constructed (GObject * object);
static void gum_darwin_module_finalize (GObject * object);
static void gum_darwin_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_store_address_if_name_matches (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_emit_import (const GumDarwinBindDetails * details,
    gpointer user_data);
static gboolean gum_emit_export_from_symbol (
    const GumDarwinSymbolDetails * details, gpointer user_data);
static gboolean gum_collect_tlv_params (const GumDarwinSectionDetails * section,
    gpointer user_data);
static gboolean gum_emit_section_init_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_emit_section_init_offsets (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_emit_section_term_pointers (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_darwin_module_load_image_from_filesystem (
    GumDarwinModule * self, const gchar * path, GError ** error);
static gboolean gum_darwin_module_load_image_header_from_filesystem (
    GumDarwinModule * self, const gchar * path, GError ** error);
static gboolean gum_darwin_module_load_image_from_blob (GumDarwinModule * self,
    GBytes * blob, GError ** error);
static gboolean gum_darwin_module_load_image_from_memory (
    GumDarwinModule * self, GError ** error);
static gboolean gum_darwin_module_can_load (GumDarwinModule * self,
    GumDarwinCpuType cpu_type, GumDarwinCpuSubtype cpu_subtype);
static gboolean gum_darwin_module_take_image (GumDarwinModule * self,
    GumDarwinModuleImage * image, GError ** error);
static gboolean gum_darwin_module_get_header_offset_size (
    GumDarwinModule * self, gpointer data, gsize data_size, gsize * out_offset,
    gsize * out_size, GError ** error);
static void gum_darwin_module_read_and_assign (GumDarwinModule * self,
    GumAddress address, gsize size, const guint8 ** start, const guint8 ** end,
    gpointer * malloc_data);
static gboolean gum_find_linkedit (const guint8 * module, gsize module_size,
    GumAddress * linkedit);
static gboolean gum_add_text_range_if_text_section (
    const GumDarwinSectionDetails * details, gpointer user_data);
static gboolean gum_section_flags_indicate_text_section (guint32 flags);

static gboolean gum_exports_trie_find (const guint8 * exports,
    const guint8 * exports_end, const gchar * name,
    GumDarwinExportDetails * details);
static gboolean gum_exports_trie_foreach (const guint8 * exports,
    const guint8 * exports_end, GumFoundDarwinExportFunc func,
    gpointer user_data);
static gboolean gum_exports_trie_traverse (const guint8 * p,
    GumExportsTrieForeachContext * ctx);

static void gum_darwin_export_details_init_from_node (
    GumDarwinExportDetails * details, const gchar * name, const guint8 * node,
    const guint8 * exports_end);

static void gum_darwin_module_enumerate_chained_binds (GumDarwinModule * self,
    GumFoundDarwinBindFunc func, gpointer user_data);
static gboolean gum_emit_chained_imports (
    const GumDarwinChainedFixupsDetails * details, GumEmitImportContext * ctx);

static GumCpuType gum_cpu_type_from_darwin (GumDarwinCpuType cpu_type);
static GumPtrauthSupport gum_ptrauth_support_from_darwin (
    GumDarwinCpuType cpu_type, GumDarwinCpuSubtype cpu_subtype);
static guint gum_pointer_size_from_cpu_type (GumDarwinCpuType cpu_type);

G_DEFINE_TYPE (GumDarwinModule, gum_darwin_module, G_TYPE_OBJECT)

G_DEFINE_BOXED_TYPE (GumDarwinModuleImage, gum_darwin_module_image,
                     gum_darwin_module_image_dup, gum_darwin_module_image_free)

static void
gum_darwin_module_class_init (GumDarwinModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_darwin_module_constructed;
  object_class->finalize = gum_darwin_module_finalize;
  object_class->get_property = gum_darwin_module_get_property;
  object_class->set_property = gum_darwin_module_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_UUID,
      g_param_spec_string ("uuid", "UUID", "UUID", NULL,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "Task", "Mach task", 0, G_MAXUINT,
      GUM_DARWIN_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CPU_TYPE,
      g_param_spec_uint ("cpu-type", "CpuType", "CPU type", 0, G_MAXUINT,
      GUM_CPU_INVALID, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PTRAUTH_SUPPORT,
      g_param_spec_uint ("ptrauth-support", "PtrauthSupport",
      "Pointer authentication support", 0, G_MAXUINT, GUM_PTRAUTH_INVALID,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "BaseAddress", "Base address", 0,
      G_MAXUINT64, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_PATH,
      g_param_spec_string ("source-path", "SourcePath", "Source path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_BLOB,
      g_param_spec_boxed ("source-blob", "SourceBlob", "Source blob",
      G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_FLAGS,
      g_param_spec_flags ("flags", "Flags", "Optional flags",
      GUM_TYPE_DARWIN_MODULE_FLAGS, GUM_DARWIN_MODULE_FLAGS_NONE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_module_init (GumDarwinModule * self)
{
  self->segments = g_array_new (FALSE, FALSE, sizeof (GumDarwinSegment));
  self->text_ranges = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));
  self->dependencies =
      g_array_new (FALSE, FALSE, sizeof (GumDependencyDetails));
  self->reexports = g_ptr_array_sized_new (5);
}

static void
gum_darwin_module_constructed (GObject * object)
{
#ifdef HAVE_DARWIN
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  if (self->task != GUM_DARWIN_PORT_NULL)
  {
    self->is_local = self->task == mach_task_self ();
    self->is_kernel = self->task == gum_kernel_get_task ();
  }
#endif
}

static void
gum_darwin_module_finalize (GObject * object)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  g_array_unref (self->dependencies);
  g_ptr_array_unref (self->reexports);

  g_free (self->rebases_malloc_data);
  g_free (self->binds_malloc_data);
  g_free (self->lazy_binds_malloc_data);
  g_free (self->exports_malloc_data);

  g_array_unref (self->segments);
  g_array_unref (self->text_ranges);

  if (self->image != NULL)
    gum_darwin_module_image_free (self->image);

  g_free (self->source_path);
  g_bytes_unref (self->source_blob);

  g_free (self->name);
  g_free (self->uuid);

  G_OBJECT_CLASS (gum_darwin_module_parent_class)->finalize (object);
}

static void
gum_darwin_module_get_property (GObject * object,
                                guint property_id,
                                GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_UUID:
      if (self->uuid == NULL)
        gum_darwin_module_ensure_image_loaded (self, NULL);
      g_value_set_string (value, self->uuid);
      break;
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    case PROP_CPU_TYPE:
      g_value_set_uint (value, self->cpu_type);
      break;
    case PROP_PTRAUTH_SUPPORT:
      g_value_set_uint (value, self->ptrauth_support);
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, self->base_address);
      break;
    case PROP_SOURCE_PATH:
      g_value_set_string (value, self->source_path);
      break;
    case PROP_SOURCE_BLOB:
      g_value_set_boxed (value, self->source_blob);
      break;
    case PROP_FLAGS:
      g_value_set_flags (value, self->flags);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_module_set_property (GObject * object,
                                guint property_id,
                                const GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinModule * self = GUM_DARWIN_MODULE (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_TASK:
      self->task = g_value_get_uint (value);
      break;
    case PROP_CPU_TYPE:
      self->cpu_type = g_value_get_uint (value);
      break;
    case PROP_PTRAUTH_SUPPORT:
      self->ptrauth_support = g_value_get_uint (value);
      break;
    case PROP_BASE_ADDRESS:
      self->base_address = g_value_get_uint64 (value);
      break;
    case PROP_SOURCE_PATH:
      g_free (self->source_path);
      self->source_path = g_value_dup_string (value);
      break;
    case PROP_SOURCE_BLOB:
      g_clear_pointer (&self->source_blob, g_bytes_unref);
      self->source_blob = g_value_dup_boxed (value);
      break;
    case PROP_FLAGS:
      self->flags = g_value_get_flags (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinModule *
gum_darwin_module_new_from_file (const gchar * path,
                                 GumCpuType cpu_type,
                                 GumPtrauthSupport ptrauth_support,
                                 GumDarwinModuleFlags flags,
                                 GError ** error)
{
  GumDarwinModule * module;

  module = g_object_new (GUM_TYPE_DARWIN_MODULE,
      "cpu-type", cpu_type,
      "ptrauth-support", ptrauth_support,
      "source-path", path,
      "flags", flags,
      NULL);
  if (!gum_darwin_module_load (module, error))
  {
    g_object_unref (module);
    module = NULL;
  }

  return module;
}

GumDarwinModule *
gum_darwin_module_new_from_blob (GBytes * blob,
                                 GumCpuType cpu_type,
                                 GumPtrauthSupport ptrauth_support,
                                 GumDarwinModuleFlags flags,
                                 GError ** error)
{
  GumDarwinModule * module;

  module = g_object_new (GUM_TYPE_DARWIN_MODULE,
      "cpu-type", cpu_type,
      "ptrauth-support", ptrauth_support,
      "source-blob", blob,
      "flags", flags,
      NULL);
  if (!gum_darwin_module_load (module, error))
  {
    g_object_unref (module);
    module = NULL;
  }

  return module;
}

GumDarwinModule *
gum_darwin_module_new_from_memory (const gchar * name,
                                   GumDarwinPort task,
                                   GumAddress base_address,
                                   GumDarwinModuleFlags flags,
                                   GError ** error)
{
  GumDarwinModule * module;

  module = g_object_new (GUM_TYPE_DARWIN_MODULE,
      "name", name,
      "task", task,
      "base-address", base_address,
      "flags", flags,
      NULL);
  if (!gum_darwin_module_load (module, error))
  {
    g_object_unref (module);
    module = NULL;
  }

  return module;
}

gboolean
gum_darwin_module_load (GumDarwinModule * self,
                        GError ** error)
{
  if (self->image != NULL)
    return TRUE;

  if (self->source_path != NULL)
  {
    if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self))
    {
      if (!gum_darwin_module_load_image_header_from_filesystem (self,
          self->source_path, error))
      {
        return FALSE;
      }
    }
    else
    {
      if (!gum_darwin_module_load_image_from_filesystem (self,
          self->source_path, error))
      {
        return FALSE;
      }
    }
  }
  else if (self->source_blob != NULL)
  {
    if (!gum_darwin_module_load_image_from_blob (self, self->source_blob,
        error))
    {
      return FALSE;
    }
  }

  if (self->name == NULL)
    return gum_darwin_module_ensure_image_loaded (self, error);

  return TRUE;
}

static guint8 *
gum_darwin_module_read_from_task (GumDarwinModule * self,
                                  GumAddress address,
                                  gsize len,
                                  gsize * n_bytes_read)
{
#ifdef HAVE_DARWIN
  return self->is_kernel
      ? gum_kernel_read (address, len, n_bytes_read)
      : gum_darwin_read (self->task, address, len, n_bytes_read);
#else
  return NULL;
#endif
}

gboolean
gum_darwin_module_resolve_export (GumDarwinModule * self,
                                  const gchar * name,
                                  GumDarwinExportDetails * details)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  if (self->exports != NULL)
  {
    return gum_exports_trie_find (self->exports, self->exports_end, name,
        details);
  }
  else if (self->filetype == GUM_DARWIN_MODULE_FILETYPE_DYLINKER)
  {
    GumAddress address;

    address = gum_darwin_module_resolve_symbol_address (self, name);
    if (address == 0)
      return FALSE;

    details->name = name;
    details->flags = GUM_DARWIN_EXPORT_ABSOLUTE;
    details->offset = address;

    return TRUE;
  }

  return FALSE;
}

GumAddress
gum_darwin_module_resolve_symbol_address (GumDarwinModule * self,
                                          const gchar * name)
{
  GumResolveSymbolContext ctx;

  ctx.name = name;
  ctx.result = 0;

  gum_darwin_module_enumerate_symbols (self, gum_store_address_if_name_matches,
      &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_name_matches (const GumDarwinSymbolDetails * details,
                                   gpointer user_data)
{
  GumResolveSymbolContext * ctx = user_data;
  gboolean carry_on = TRUE;

  if (strcmp (details->name, ctx->name) == 0)
  {
    ctx->result = details->address;
    carry_on = FALSE;
  }

  return carry_on;
}

gboolean
gum_darwin_module_get_lacks_exports_for_reexports (GumDarwinModule * self)
{
  guint32 flags;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  /*
   * FIXME: There must be a better way to detect this behavioral change
   *        introduced in macOS 10.11 and iOS 9.0, but this will have to
   *        do for now.
   */
  flags = ((GumMachHeader32 *) self->image->data)->flags;

  return (flags & GUM_MH_PREBOUND) == 0;
}

void
gum_darwin_module_enumerate_imports (GumDarwinModule * self,
                                     GumFoundImportFunc func,
                                     GumResolveExportFunc resolver,
                                     gpointer user_data)
{
  GumEmitImportContext ctx;

  ctx.func = func;
  ctx.resolver = resolver;
  ctx.user_data = user_data;

  ctx.module = self;
  ctx.threaded_binds = NULL;
  ctx.source_start = NULL;
  ctx.source_end = NULL;
  ctx.source_file = NULL;
  ctx.carry_on = TRUE;

  gum_darwin_module_enumerate_binds (self, gum_emit_import, &ctx);
  if (ctx.carry_on)
    gum_darwin_module_enumerate_lazy_binds (self, gum_emit_import, &ctx);
  if (ctx.carry_on)
    gum_darwin_module_enumerate_chained_binds (self, gum_emit_import, &ctx);

  g_clear_pointer (&ctx.source_file, g_mapped_file_unref);
  g_clear_pointer (&ctx.threaded_binds, g_array_unref);
}

static gboolean
gum_emit_import (const GumDarwinBindDetails * details,
                 gpointer user_data)
{
  GumEmitImportContext * ctx = user_data;
  GumDarwinModule * self = ctx->module;
  const GumDarwinSegment * segment = details->segment;
  GumAddress vm_base;

  vm_base = segment->vm_address + gum_darwin_module_get_slide (self);

  switch (details->type)
  {
    case GUM_DARWIN_BIND_POINTER:
    {
      GumImportDetails d;

      d.type = GUM_IMPORT_UNKNOWN;
      d.name = details->symbol_name;
      switch (details->library_ordinal)
      {
        case GUM_BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE:
        case GUM_BIND_SPECIAL_DYLIB_SELF:
          return TRUE;
        case GUM_BIND_SPECIAL_DYLIB_FLAT_LOOKUP:
        {
          d.module = NULL;
          break;
        }
        default:
          d.module = gum_darwin_module_get_dependency_by_ordinal (self,
              details->library_ordinal);
          break;
      }
      d.address = 0;
      d.slot = vm_base + details->offset;

      if (ctx->threaded_binds != NULL)
        g_array_append_val (ctx->threaded_binds, d);
      else
        ctx->carry_on = ctx->func (&d, ctx->user_data);

      break;
    }
    case GUM_DARWIN_BIND_THREADED_TABLE:
    {
      g_clear_pointer (&ctx->threaded_binds, g_array_unref);
      ctx->threaded_binds = g_array_sized_new (FALSE, FALSE,
          sizeof (GumImportDetails), details->threaded_table_size);

      break;
    }
    case GUM_DARWIN_BIND_THREADED_ITEMS:
    {
      GArray * threaded_binds = ctx->threaded_binds;
      guint64 cursor;
      GumDarwinThreadedItem item;

      if (threaded_binds == NULL)
        return TRUE;

      if (ctx->source_start == NULL)
      {
        gchar * source_path = NULL;
        GMappedFile * file;

#ifdef HAVE_DARWIN
        if (self->task != GUM_DARWIN_PORT_NULL)
        {
          GumDarwinMappingDetails mapping;
          if (gum_darwin_query_mapped_address (self->task, vm_base, &mapping))
            source_path = g_strdup (mapping.path);
        }
#endif
        if (source_path == NULL)
        {
          source_path = g_strdup (self->name);
          if (source_path == NULL)
            return TRUE;
        }
        file = g_mapped_file_new (source_path, FALSE, NULL);
        g_free (source_path);
        if (file == NULL)
          return TRUE;

        ctx->source_start = (const guint8 *) g_mapped_file_get_contents (file);
        ctx->source_end = ctx->source_start + g_mapped_file_get_length (file);
        ctx->source_file = file;
      }

      cursor = details->offset;

      do
      {
        const guint8 * raw_slot;

        raw_slot = ctx->source_start + segment->file_offset + cursor;
        if (raw_slot < ctx->source_start ||
            raw_slot + sizeof (guint64) > ctx->source_end)
        {
          return FALSE;
        }

        gum_darwin_threaded_item_parse (*((const guint64 *) raw_slot), &item);

        if (item.type == GUM_DARWIN_THREADED_BIND)
        {
          guint ordinal = item.bind_ordinal;
          GumImportDetails * d;

          if (ordinal >= threaded_binds->len)
            return TRUE;
          d = &g_array_index (threaded_binds, GumImportDetails, ordinal);
          d->slot = vm_base + cursor;

          ctx->carry_on = ctx->func (d, ctx->user_data);
        }

        cursor += item.delta * sizeof (guint64);
      }
      while (item.delta != 0 && ctx->carry_on);

      break;
    }
    default:
      g_assert_not_reached ();
  }

  return ctx->carry_on;
}

void
gum_darwin_module_enumerate_exports (GumDarwinModule * self,
                                     GumFoundDarwinExportFunc func,
                                     gpointer user_data)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  if (self->exports != NULL)
  {
    gum_exports_trie_foreach (self->exports, self->exports_end, func,
        user_data);
  }
  else if (self->filetype == GUM_DARWIN_MODULE_FILETYPE_DYLINKER)
  {
    GumEmitExportFromSymbolContext ctx;

    ctx.func = func;
    ctx.user_data = user_data;

    gum_darwin_module_enumerate_symbols (self, gum_emit_export_from_symbol,
        &ctx);
  }
}

static gboolean
gum_emit_export_from_symbol (const GumDarwinSymbolDetails * details,
                             gpointer user_data)
{
  GumEmitExportFromSymbolContext * ctx = user_data;
  GumDarwinExportDetails d;

  if ((details->type & GUM_N_EXT) == 0)
    return TRUE;

  if ((details->type & GUM_N_TYPE) != GUM_N_SECT)
    return TRUE;

  d.name = details->name;
  d.flags = GUM_DARWIN_EXPORT_ABSOLUTE;
  d.offset = details->address;

  return ctx->func (&d, ctx->user_data);
}

void
gum_darwin_module_enumerate_symbols (GumDarwinModule * self,
                                     GumFoundDarwinSymbolFunc func,
                                     gpointer user_data)
{
  GumDarwinModuleImage * image;
  const GumSymtabCommand * symtab;
  GumAddress slide;
  const guint8 * symbols, * strings;
  gpointer symbols_malloc_data = NULL;
  gpointer strings_malloc_data = NULL;
  gsize symbol_index;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    goto beach;
  }

  image = self->image;

  symtab = self->symtab;
  if (symtab == NULL)
    goto beach;

  slide = gum_darwin_module_get_slide (self);

  if (image->linkedit != NULL)
  {
    symbols = (guint8 *) image->linkedit + symtab->symoff;
    strings = (guint8 *) image->linkedit + symtab->stroff;
  }
  else
  {
    GumAddress linkedit;
    gsize symbol_size;

    if (!gum_find_linkedit (image->data, image->size, &linkedit))
      goto beach;
    linkedit += slide;

    symbol_size = (self->pointer_size == 8)
        ? sizeof (GumNList64)
        : sizeof (GumNList32);

    gum_darwin_module_read_and_assign (self, linkedit + symtab->symoff,
        symtab->nsyms * symbol_size, &symbols, NULL, &symbols_malloc_data);
    gum_darwin_module_read_and_assign (self, linkedit + symtab->stroff,
        symtab->strsize, &strings, NULL, &strings_malloc_data);
    if (symbols == NULL || strings == NULL)
      goto beach;
  }

  for (symbol_index = 0; symbol_index != symtab->nsyms; symbol_index++)
  {
    GumDarwinSymbolDetails details;
    gboolean carry_on;

    if (self->pointer_size == 8)
    {
      const GumNList64 * symbol;

      symbol = (GumNList64 *) (symbols + (symbol_index * sizeof (GumNList64)));

      details.name = (const gchar *) (strings + symbol->n_strx);
      details.address = (symbol->n_value != 0) ? symbol->n_value + slide : 0;

      details.type = symbol->n_type;
      details.section = symbol->n_sect;
      details.description = symbol->n_desc;
    }
    else
    {
      const GumNList32 * symbol;

      symbol = (GumNList32 *) (symbols + (symbol_index * sizeof (GumNList32)));

      details.name = (const gchar *) (strings + symbol->n_strx);
      details.address = (symbol->n_value != 0) ? symbol->n_value + slide : 0;

      details.type = symbol->n_type;
      details.section = symbol->n_sect;
      details.description = symbol->n_desc;
    }

    carry_on = func (&details, user_data);
    if (!carry_on)
      goto beach;
  }

beach:
  g_free (strings_malloc_data);
  g_free (symbols_malloc_data);
}

GumAddress
gum_darwin_module_get_slide (GumDarwinModule * self)
{
  return self->base_address - self->preferred_address;
}

const GumDarwinSegment *
gum_darwin_module_get_nth_segment (GumDarwinModule * self,
                                   gsize index)
{
  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return NULL;

  if (index >= self->segments->len)
    return NULL;

  return &g_array_index (self->segments, GumDarwinSegment, index);
}

void
gum_darwin_module_enumerate_sections (GumDarwinModule * self,
                                      GumFoundDarwinSectionFunc func,
                                      gpointer user_data)
{
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;
  GumAddress slide;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  header = (GumMachHeader32 *) self->image->data;
  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) self->image->data + 1;
  else
    command = (GumMachHeader64 *) self->image->data + 1;
  slide = gum_darwin_module_get_slide (self);
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = command;

    if (lc->cmd == GUM_LC_SEGMENT_32 || lc->cmd == GUM_LC_SEGMENT_64)
    {
      GumDarwinSectionDetails details;
      const guint8 * sections;
      gsize section_count, section_index;

      if (lc->cmd == GUM_LC_SEGMENT_32)
      {
        const GumSegmentCommand32 * sc = command;

        details.protection = sc->initprot;

        sections = (const guint8 *) (sc + 1);
        section_count = sc->nsects;
      }
      else
      {
        const GumSegmentCommand64 * sc = command;

        details.protection = sc->initprot;

        sections = (const guint8 *) (sc + 1);
        section_count = sc->nsects;
      }

      for (section_index = 0; section_index != section_count; section_index++)
      {
        if (lc->cmd == GUM_LC_SEGMENT_32)
        {
          const GumSection32 * s =
              (const GumSection32 *) sections + section_index;

          g_strlcpy (details.segment_name, s->segname,
              sizeof (details.segment_name));
          g_strlcpy (details.section_name, s->sectname,
              sizeof (details.section_name));

          details.vm_address = s->addr + (guint32) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }
        else
        {
          const GumSection64 * s =
              (const GumSection64 *) sections + section_index;

          g_strlcpy (details.segment_name, s->segname,
              sizeof (details.segment_name));
          g_strlcpy (details.section_name, s->sectname,
              sizeof (details.section_name));

          details.vm_address = s->addr + (guint64) slide;
          details.size = s->size;
          details.file_offset = s->offset;
          details.flags = s->flags;
        }

        if (!func (&details, user_data))
          return;
      }
    }

    command = (const guint8 *) command + lc->cmdsize;
  }
}

gboolean
gum_darwin_module_is_address_in_text_section (GumDarwinModule * self,
                                              GumAddress address)
{
  gboolean metadata_is_offline;
  GumAddress normalized_address;
  guint i;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return FALSE;

  metadata_is_offline = self->source_path != NULL || self->source_blob != NULL;

  normalized_address = metadata_is_offline
      ? address - self->base_address
      : address;

  for (i = 0; i != self->text_ranges->len; i++)
  {
    GumMemoryRange * r = &g_array_index (self->text_ranges, GumMemoryRange, i);
    if (GUM_MEMORY_RANGE_INCLUDES (r, normalized_address))
      return TRUE;
  }

  return FALSE;
}

void
gum_darwin_module_enumerate_chained_fixups (
    GumDarwinModule * self,
    GumFoundDarwinChainedFixupsFunc func,
    gpointer user_data)
{
  GumDarwinModuleImage * image;
  const GumMachHeader32 * header;
  gconstpointer command;
  gsize command_index;

  if (!gum_darwin_module_ensure_image_loaded (self, NULL))
    return;

  image = self->image;

  header = image->data;
  if (header->magic == GUM_MH_MAGIC_32)
    command = (GumMachHeader32 *) image->data + 1;
  else
    command = (GumMachHeader64 *) image->data + 1;
  for (command_index = 0; command_index != header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = command;

    if (lc->cmd == GUM_LC_DYLD_CHAINED_FIXUPS)
    {
      const GumLinkeditDataCommand * fixups = command;
      GumAddress linkedit;
      GumDarwinChainedFixupsDetails details;

      if (!gum_find_linkedit (image->data, image->size, &linkedit))
        return;

      linkedit += gum_darwin_module_get_slide (self);

      details.vm_address = linkedit + fixups->dataoff;
      details.file_offset = fixups->dataoff;
      details.size = fixups->datasize;

      if (!func (&details, user_data))
        return;
    }

    command = (const guint8 *) command + lc->cmdsize;
  }
}

void
gum_darwin_module_enumerate_rebases (GumDarwinModule * self,
                                     GumFoundDarwinRebaseFunc func,
                                     gpointer user_data)
{
  const guint8 * start, * end, * p;
  gboolean done;
  GumDarwinRebaseDetails details;

  if (GUM_DARWIN_MODULE_HAS_HEADER_ONLY (self) ||
      !gum_darwin_module_ensure_image_loaded (self, NULL))
  {
    return;
  }

  start = self->rebases;
  end = self->rebases_end;
  p = start;
  done = FALSE;

  details.segment = gum_darwin_module_get_nth_segment (self, 0);
  details.offset = 0;
  details.type = 0;
  details.slide = gum_darwin_module_get_slide (self);

  while (!done && p != end)
  {
    guint8 opcode = *p & GUM_REBASE_OPCODE_MASK;
    guint8 immediate = *p & GUM_REBASE_IMMEDIATE_MASK;

    p++;

    switch (opcode)
    {
      case GUM_REBASE_OPCODE_DONE:
        done = TRUE;
        break;
      case GUM_REBASE_OPCODE_SET_TYPE_IMM:
        details.type = immediate;
        break;
      case GUM_REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
      {
        gint segment_index = immediate;
        details.segment =
            gum_darwin_module_get_nth_segment (self, segment_index);
        if (details.segment == NULL)
          return;
        details.offset = gum_read_uleb128 (&p, end);
        break;
      }
      case GUM_REBASE_OPCODE_ADD_ADDR_ULEB:
        details.offset += gum_read_uleb128 (&p, end);
        break;
      case GUM_REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
        details.offset += immediate * self->pointer_size;
        break;
      case GUM_REBASE_OPCODE_DO_REBASE_IMM_TIMES:
      {
        guint8 i;

        for (i = 0; i != immediate; i++)
        {
          if (!func (&details, user_data))
            return;
          details.offset += self->pointer_size;
        }

        break;
      }
      case GUM_REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
      {
        guint64 count, i;

        count = gum_read_uleb128 (&p, end);
        for (i = 0; i != count; i++)
 
"""


```