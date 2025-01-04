Response:
The user wants a summary of the C code provided, specifically focusing on its functionality within the Frida dynamic instrumentation tool. I need to identify the core purpose of `gumdarwingrafter.c`, explain its relationship to reverse engineering, discuss any low-level details (binary, OS kernels, frameworks), pinpoint logical reasoning based on inputs and outputs, highlight potential user errors, and outline how a user might trigger this code.

**Plan:**

1. **Identify Core Functionality:** Analyze the code for key data structures (like `GumDarwinGrafter`, `GumGraftedLayout`, `GumSegmentPairDescriptor`), functions (like `gum_darwin_grafter_graft`, `gum_darwin_grafter_compute_layout`, `gum_darwin_grafter_transform_load_commands`), and the overall workflow. It seems related to modifying Mach-O binaries on Darwin-based systems.

2. **Reverse Engineering Relevance:** Explain how modifying binary code and load commands is a fundamental aspect of dynamic instrumentation and reverse engineering.

3. **Low-Level Details:**  Note the use of Mach-O structures (`GumMachHeader64`, `GumSegmentCommand64`, etc.), concepts like load commands, segments, binding information, and how these relate to the Darwin operating system (macOS, iOS). Mention the potential interaction with kernel components when the modified binary is loaded.

4. **Logical Reasoning (Input/Output):**  Consider the inputs to the `gum_darwin_grafter_graft` function (the target file path and flags) and the expected output (a modified binary). Analyze the steps involved in `gum_darwin_grafter_compute_layout` (analyzing the original binary) and `gum_darwin_grafter_transform_load_commands` (adjusting the load commands).

5. **User Errors:** Think about common mistakes users might make, such as providing an invalid file path, insufficient permissions, or using incorrect flags.

6. **User Trigger:** Describe the typical Frida workflow that leads to this code being executed. This likely involves attaching to a process, specifying instrumentation points, and triggering the instrumentation.

7. **Structure the Response:** Organize the findings into clear categories as requested by the user.
## frida/subprojects/frida-gum/gum/gumdarwingrafter.c 的功能归纳 (第 1 部分)

该 C 代码文件 `gumdarwingrafter.c` 是 frida 动态 instrumentation 工具的一个核心组件，专门用于 **修改 (grafting)** Darwin (macOS, iOS 等) 操作系统上的 Mach-O 二进制文件。它的主要功能是：

**核心功能:**

1. **在现有的 Mach-O 二进制文件中注入额外的代码和数据段 (Segments):**  通过修改 Mach-O 文件的加载命令 (Load Commands)，`gumdarwingrafter.c` 能够在目标进程的内存空间中预留出新的区域，用于存放 frida 需要注入的 hook 代码、trampoline (跳转指令) 以及相关的数据结构。
2. **调整 Mach-O 文件的结构以容纳注入的内容:** 这包括计算新的段的大小和偏移量，更新 `__LINKEDIT` 段的信息 (用于存储符号表、重定位信息等)，以及处理与动态链接相关的绑定信息 (bind information)。
3. **处理和合并动态链接信息:**  当 `GUM_DARWIN_GRAFTER_FLAGS_TRANSFORM_LAZY_BINDS` 标志被设置时，该代码会尝试合并懒加载绑定 (lazy bindings) 到常规绑定 (binds) 中，这涉及到解析和修改 `LC_DYLD_INFO_ONLY` 加载命令中的信息。
4. **收集需要 hook 的代码偏移量 (Code Offsets) 和导入符号 (Imports):**  根据用户提供的代码偏移量以及可选的标志 ( `GUM_DARWIN_GRAFTER_FLAGS_INGEST_FUNCTION_STARTS`, `GUM_DARWIN_GRAFTER_FLAGS_INGEST_IMPORTS` )，该代码会收集需要在目标二进制文件中进行 hook 的函数入口地址和需要进行拦截的导入符号。
5. **生成用于 hook 和调用的 trampoline 代码:**  该代码定义了用于 hook 函数入口 (`GumGraftedHookTrampoline`) 和拦截导入符号 (`GumGraftedImportTrampoline`) 的 trampoline 的结构。这些 trampoline 是实际执行 hook 逻辑的跳转代码。
6. **将修改后的 Mach-O 数据写入文件:**  最终，`gumdarwingrafter.c` 会将修改后的 Mach-O 文件内容写回磁盘，从而持久化这些更改。

**与逆向方法的关联及举例说明:**

`gumdarwingrafter.c` 的核心功能就是为逆向工程提供基础设施。通过在目标程序中注入代码，逆向工程师可以实现以下目标：

*   **函数 Hook:**  通过收集代码偏移量，frida 可以在目标函数的入口处插入 hook 代码，从而在函数执行前或后执行自定义的逻辑，例如打印函数参数、修改返回值、阻止函数执行等。
    *   **举例:** 逆向工程师可以使用 frida hook 一个加密函数的入口，记录其输入参数，以便分析加密算法。
*   **导入符号拦截 (Import Interception):**  通过收集导入符号，frida 可以拦截对特定动态库函数的调用，从而监控程序的行为，甚至替换原始的函数实现。
    *   **举例:** 逆向工程师可以 hook `malloc` 函数，追踪程序的内存分配情况，检测内存泄漏。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

*   **二进制底层 (Mach-O 格式):**  该代码深度依赖于对 Mach-O 文件格式的理解，包括 Mach-O 头 ( `GumMachHeader64` )、加载命令 ( `GumLoadCommand` , `GumSegmentCommand64` , `GumDyldInfoCommand` , `GumLinkeditDataCommand` )、段 (Segments)、节 (Sections) 等概念。它直接操作这些底层结构来修改二进制文件。
    *   **举例:**  代码中通过查找 `__TEXT` 和 `__LINKEDIT` 段来定位代码和链接信息，并计算新的段偏移量和大小。对 `LC_SEGMENT_64` 加载命令的修改直接影响着操作系统加载器如何加载和映射二进制文件到内存。
*   **Darwin 内核及框架 (涉及):** 虽然代码本身不直接与内核交互，但它修改的 Mach-O 文件是被 Darwin 内核的加载器 (dyld) 解析和加载的。注入的代码最终运行在目标进程的上下文中，可能会调用 Darwin 框架提供的 API。
    *   **举例:**  通过 hook 系统调用，逆向工程师可以了解程序与内核的交互方式。
*   **Linux 和 Android 内核及框架 (间接):**  虽然该代码是针对 Darwin 的，但 frida 作为一个跨平台的工具，其核心思想和一些技术 (例如代码注入、hook) 在 Linux 和 Android 上也有对应的实现。了解这些平台的底层机制有助于理解 frida 的整体架构。

**逻辑推理的假设输入与输出:**

假设用户想要 hook 位于偏移量 `0x1000` 的函数，并拦截对 `libSystem.dylib` 中 `open` 函数的调用。

*   **假设输入:**
    *   目标 Mach-O 文件路径: `/Applications/MyApp.app/Contents/MacOS/MyApp`
    *   代码偏移量: `0x1000` (通过 `gum_darwin_grafter_add` 添加)
    *   `GUM_DARWIN_GRAFTER_FLAGS_INGEST_IMPORTS` 标志被设置
*   **处理过程 (简化):**
    1. `gum_darwin_grafter_compute_layout` 会解析目标 Mach-O 文件，确定各个段的布局。
    2. `gum_darwin_grafter_add` 将 `0x1000` 记录为待 hook 的代码偏移量。
    3. 如果设置了 `GUM_DARWIN_GRAFTER_FLAGS_INGEST_IMPORTS`，代码会解析 `LC_DYLD_CHAINED_FIXUPS` 和绑定信息，识别出对 `libSystem.dylib` 中 `open` 函数的导入。
    4. `gum_darwin_grafter_transform_load_commands` 会创建新的 `__FRIDA_TEXT` 和 `__FRIDA_DATA` 段，并在加载命令中添加相应的条目。
    5. 在新的 `__FRIDA_TEXT` 段中，会生成用于 hook `0x1000` 的 `GumGraftedHookTrampoline` 和用于拦截 `open` 函数的 `GumGraftedImportTrampoline`。
    6. `gum_darwin_grafter_emit_segments` 会将 trampoline 代码和相关数据写入到新添加的段中。
    7. 修改后的 Mach-O 文件会被写回磁盘。
*   **预期输出:**  一个修改后的 Mach-O 文件，当它被加载时，frida 可以在 `0x1000` 处设置 hook，并且可以拦截对 `open` 函数的调用。

**涉及用户或编程常见的使用错误及举例说明:**

*   **提供错误的路径:**  如果用户提供的目标文件路径不存在或不可访问，`gum_darwin_module_new_from_file` 将会失败。
    *   **举例:**  用户输入路径 `/tmp/non_existent_file`。
*   **权限不足:**  如果用户没有修改目标文件的权限，`fopen` 和 `fwrite` 操作将会失败。
    *   **举例:**  用户尝试修改位于系统保护目录下的可执行文件，但没有 root 权限。
*   **重复 graft:**  如果用户尝试对已经 graft 过的文件再次进行 graft，代码会检测到 `__FRIDA_` 前缀的段并报错。
    *   **举例:**  用户连续两次执行 graft 操作，目标文件在第一次操作后已经被修改。
*   **误用 Flags:**  如果用户使用了不合适的 flag，可能会导致意想不到的结果或错误。
    *   **举例:**  用户在不需要处理懒加载绑定的情况下设置了 `GUM_DARWIN_GRAFTER_FLAGS_TRANSFORM_LAZY_BINDS`，可能导致额外的处理开销。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 frida 脚本:**  用户使用 JavaScript 或 Python 编写 frida 脚本，指定要 hook 的函数或要拦截的导入符号。
2. **用户运行 frida 命令或程序:**  用户通过 frida CLI 工具 (例如 `frida -f <应用程序>`) 或者使用 frida 的 API 启动或附加到目标进程。
3. **frida-core 处理请求:**  frida-core 接收到用户的 hook 或拦截请求，并确定需要在目标进程中注入代码。
4. **选择合适的 Grafter:**  frida-core 会根据目标进程的操作系统 (Darwin) 和架构 (ARM64) 选择 `gumdarwingrafter.c` 相关的代码进行处理。
5. **创建 GumDarwinGrafter 对象:**  frida-core 会创建一个 `GumDarwinGrafter` 对象，并设置目标文件的路径和相应的 flags。
6. **添加代码偏移量和导入信息:**  用户在脚本中指定的 hook 点和导入拦截信息会被添加到 `GumDarwinGrafter` 对象中。
7. **调用 `gum_darwin_grafter_graft`:**  frida-core 会调用 `gum_darwin_grafter_graft` 函数，开始修改目标 Mach-O 文件的过程。
8. **执行 `gum_darwin_grafter_compute_layout` 等函数:**  `gum_darwin_grafter_graft` 函数内部会调用 `gum_darwin_grafter_compute_layout`，`gum_darwin_grafter_transform_load_commands`，`gum_darwin_grafter_emit_segments` 等函数来完成 Mach-O 文件的修改。
9. **写入修改后的文件:**  最终，修改后的 Mach-O 文件会被写回磁盘 (如果 frida 配置为持久化修改)。

作为调试线索，如果用户在使用 frida 时遇到问题，例如 hook 没有生效，或者程序崩溃，那么可以关注以下几点：

*   **是否成功到达 `gum_darwin_grafter_graft` 函数:**  可以通过在代码中添加日志输出来确认。
*   **`gum_darwin_grafter_compute_layout` 是否正确计算了布局:**  检查计算出的段偏移量和大小是否合理。
*   **`gum_darwin_grafter_transform_load_commands` 是否正确修改了加载命令:**  检查新添加的段信息是否正确。
*   **`gum_darwin_grafter_emit_segments` 是否成功写入了 trampoline 代码:**  可以使用十六进制编辑器查看修改后的文件内容。

总而言之，`gumdarwingrafter.c` 在 frida 中扮演着至关重要的角色，它负责在 Darwin 系统上修改目标二进制文件，为动态 instrumentation 提供必要的代码注入和 hook 基础设施。理解其内部机制对于调试 frida 脚本和深入理解 frida 的工作原理至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gumdarwingrafter.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2021-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021-2023 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdarwingrafter.h"

#include "gumdarwingrafter-priv.h"
#include "gumdarwinmodule-priv.h"
#include "gumleb.h"

#include <glib/gprintf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define GUM_BIND_STATE_RESET_SIZE 2
#define GUM_MAX_LDR_OFFSET (262143 * 4)

#ifndef GUM_DIET

typedef struct _GumGraftedLayout GumGraftedLayout;
typedef struct _GumSegmentPairDescriptor GumSegmentPairDescriptor;
typedef struct _GumGraftedHookTrampoline GumGraftedHookTrampoline;
typedef struct _GumGraftedImportTrampoline GumGraftedImportTrampoline;
typedef struct _GumGraftedRuntime GumGraftedRuntime;
typedef struct _GumCollectFunctionsOperation GumCollectFunctionsOperation;
typedef struct _GumCollectImportsOperation GumCollectImportsOperation;
typedef struct _GumImport GumImport;
typedef struct _GumBindState GumBindState;

enum
{
  PROP_0,
  PROP_PATH,
  PROP_FLAGS,
};

struct _GumDarwinGrafter
{
  GObject parent;

  gchar * path;
  GumDarwinGrafterFlags flags;
  GArray * code_offsets;
};

struct _GumGraftedLayout
{
  gsize page_size;

  GumAddress text_address;
  GArray * segment_pair_descriptors;
  gsize segments_size;

  GumAddress linkedit_address;
  goffset linkedit_offset_in;
  goffset linkedit_offset_out;
  gsize linkedit_size_in;
  gsize linkedit_size_out;
  gsize linkedit_shift;

  goffset rewritten_binds_offset;
  gsize rewritten_binds_capacity;

  goffset rewritten_binds_split_offset;
  gsize rewritten_binds_shift;
};

struct _GumSegmentPairDescriptor
{
  GumAddress code_address;
  goffset code_offset;
  gsize code_size;

  GumAddress data_address;
  goffset data_offset;
  gsize data_size;

  guint code_offsets_start;
  guint num_code_offsets;

  guint imports_start;
  guint num_imports;
};

#pragma pack (push, 1)

struct _GumGraftedHookTrampoline
{
  guint32 on_enter[5];
  guint32 on_leave[3];
  guint32 not_active[1];
  guint32 on_invoke[2];
};

struct _GumGraftedImportTrampoline
{
  guint32 on_enter[3];
  guint32 on_leave[3];
};

struct _GumGraftedRuntime
{
  guint32 do_begin_invocation[2];
  guint32 do_end_invocation[2];
};

#pragma pack (pop)

struct _GumCollectFunctionsOperation
{
  GArray * functions;
  gconstpointer linkedit;
};

struct _GumCollectImportsOperation
{
  GArray * imports;
  GumAddress text_address;
};

struct _GumImport
{
  guint32 slot_offset;
  GumDarwinPageProtection protection;
};

struct _GumBindState
{
  guint segment_index;
  guint64 offset;
  GumDarwinBindType type;
  GumDarwinBindOrdinal library_ordinal;
  gint64 addend;
  guint16 threaded_table_size;
};

static void gum_darwin_grafter_finalize (GObject * object);
static void gum_darwin_grafter_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_grafter_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static gboolean gum_darwin_grafter_compute_layout (GumDarwinGrafter * self,
    GumDarwinModule * module, GumGraftedLayout * layout, GArray ** code_offsets,
    GArray ** imports, GError ** error);
static void gum_collect_chained_imports (GumDarwinModule * module,
    GumCollectImportsOperation * op);
static const GumDarwinSegment * gum_find_segment_by_offset (
    GumDarwinModule * module, gsize offset);
static gboolean gum_collect_functions (
    const GumDarwinFunctionStartsDetails * details, gpointer user_data);
static gboolean gum_collect_import (const GumDarwinBindDetails * details,
    gpointer user_data);
static void gum_normalize_code_offsets (GArray * code_offsets);
static int gum_compare_code_offsets (const void * element_a,
    const void * element_b);
static GByteArray * gum_darwin_grafter_transform_load_commands (
    gconstpointer commands_in, guint32 size_of_commands_in,
    guint32 num_commands_in, const GumGraftedLayout * layout,
    gconstpointer linkedit, guint32 * num_commands_out,
    GByteArray ** merged_binds);
static gboolean gum_darwin_grafter_emit_segments (gpointer output,
    const GumGraftedLayout * layout, GArray * code_offsets, GArray * imports,
    GError ** error);

static GByteArray * gum_merge_lazy_binds_into_binds (
    const GumDyldInfoCommand * ic, gconstpointer linkedit);
static void gum_replay_bind_state_transitions (const guint8 * start,
    const guint8 * end, GumBindState * state);

G_DEFINE_TYPE (GumDarwinGrafter, gum_darwin_grafter, G_TYPE_OBJECT)

static void
gum_darwin_grafter_class_init (GumDarwinGrafterClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_darwin_grafter_finalize;
  object_class->get_property = gum_darwin_grafter_get_property;
  object_class->set_property = gum_darwin_grafter_set_property;

  g_object_class_install_property (object_class, PROP_PATH,
      g_param_spec_string ("path", "Path", "Path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_FLAGS,
      g_param_spec_flags ("flags", "Flags", "Optional flags",
      GUM_TYPE_DARWIN_GRAFTER_FLAGS, GUM_DARWIN_GRAFTER_FLAGS_NONE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_grafter_init (GumDarwinGrafter * self)
{
  self->code_offsets = g_array_new (FALSE, FALSE, sizeof (guint32));
}

static void
gum_darwin_grafter_finalize (GObject * object)
{
  GumDarwinGrafter * self = GUM_DARWIN_GRAFTER (object);

  g_array_unref (self->code_offsets);
  g_free (self->path);

  G_OBJECT_CLASS (gum_darwin_grafter_parent_class)->finalize (object);
}

static void
gum_darwin_grafter_get_property (GObject * object,
                                 guint property_id,
                                 GValue * value,
                                 GParamSpec * pspec)
{
  GumDarwinGrafter * self = GUM_DARWIN_GRAFTER (object);

  switch (property_id)
  {
    case PROP_PATH:
      g_value_set_string (value, self->path);
      break;
    case PROP_FLAGS:
      g_value_set_flags (value, self->flags);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_grafter_set_property (GObject * object,
                                 guint property_id,
                                 const GValue * value,
                                 GParamSpec * pspec)
{
  GumDarwinGrafter * self = GUM_DARWIN_GRAFTER (object);

  switch (property_id)
  {
    case PROP_PATH:
      g_free (self->path);
      self->path = g_value_dup_string (value);
      break;
    case PROP_FLAGS:
      self->flags = g_value_get_flags (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinGrafter *
gum_darwin_grafter_new_from_file (const gchar * path,
                                  GumDarwinGrafterFlags flags)
{
  return g_object_new (GUM_TYPE_DARWIN_GRAFTER,
      "path", path,
      "flags", flags,
      NULL);
}

void
gum_darwin_grafter_add (GumDarwinGrafter * self,
                        guint32 code_offset)
{
  g_array_append_val (self->code_offsets, code_offset);
}

gboolean
gum_darwin_grafter_graft (GumDarwinGrafter * self,
                          GError ** error)
{
  gboolean success = FALSE;
  GumDarwinModule * module;
  guint i;
  GumGraftedLayout layout;
  GArray * code_offsets = NULL;
  GArray * imports = NULL;
  gconstpointer input;
  GumMachHeader64 mach_header;
  gconstpointer commands_in;
  guint32 size_of_commands_in;
  GByteArray * commands_out = NULL;
  GByteArray * merged_binds = NULL;
  GByteArray * output = NULL;
  gconstpointer end_of_load_commands;
  gsize gap_space_used;
  gconstpointer rest_of_gap;
  FILE * file = NULL;

  layout.segment_pair_descriptors = NULL;

  module = gum_darwin_module_new_from_file (self->path, GUM_CPU_ARM64,
      GUM_PTRAUTH_INVALID, GUM_DARWIN_MODULE_FLAGS_NONE, error);
  if (module == NULL)
    goto beach;

  for (i = 0; i != module->segments->len; i++)
  {
    const GumDarwinSegment * segment =
        &g_array_index (module->segments, GumDarwinSegment, i);

    if (g_str_has_prefix (segment->name, "__FRIDA_"))
      goto already_grafted;
  }

  if (!gum_darwin_grafter_compute_layout (self, module, &layout, &code_offsets,
      &imports, error))
  {
    goto beach;
  }

  if (code_offsets->len + imports->len == 0)
    goto nothing_to_instrument;

  input = module->image->data;

  /* XXX: for now we assume matching endian */
  memcpy (&mach_header, input, sizeof (GumMachHeader64));

  commands_in = (const GumMachHeader64 *) input + 1;
  size_of_commands_in = mach_header.sizeofcmds;

  commands_out = gum_darwin_grafter_transform_load_commands (commands_in,
      size_of_commands_in, mach_header.ncmds, &layout, input,
      &mach_header.ncmds, &merged_binds);
  mach_header.sizeofcmds = commands_out->len;

  output = g_byte_array_sized_new (
      layout.linkedit_offset_out + layout.linkedit_size_out);

  g_byte_array_append (output, (const guint8 *) &mach_header,
      sizeof (mach_header));

  g_byte_array_append (output, commands_out->data, commands_out->len);

  end_of_load_commands = (const guint8 *) commands_in + size_of_commands_in;
  /* TODO: shift __TEXT if there's not enough space for our load commands */
  gap_space_used = commands_out->len - size_of_commands_in;
  rest_of_gap = (const guint8 *) end_of_load_commands + gap_space_used;
  g_byte_array_append (output, rest_of_gap, layout.linkedit_offset_in -
      ((const guint8 *) rest_of_gap - (const guint8 *) input));

  g_byte_array_set_size (output, output->len + layout.segments_size);

  if (layout.rewritten_binds_split_offset == -1)
  {
    g_byte_array_append (output,
        (const guint8 *) input + layout.linkedit_offset_in,
        layout.linkedit_size_in);
  }
  else
  {
    gsize head_size =
        layout.rewritten_binds_split_offset - layout.linkedit_offset_in;

    g_byte_array_append (output,
        (const guint8 *) input + layout.linkedit_offset_in,
        head_size);
    g_byte_array_set_size (output, output->len + layout.rewritten_binds_shift);
    g_byte_array_append (output,
        (const guint8 *) input + layout.rewritten_binds_split_offset,
        layout.linkedit_size_in - head_size);
  }

  if (layout.rewritten_binds_offset != -1)
  {
    guint8 * rewritten_binds_start = output->data +
        layout.rewritten_binds_offset + layout.linkedit_shift;
    memcpy (rewritten_binds_start, merged_binds->data, merged_binds->len);
    if (layout.rewritten_binds_capacity > merged_binds->len)
    {
      memset (rewritten_binds_start + merged_binds->len, 0,
          layout.rewritten_binds_capacity - merged_binds->len);
    }
  }

  if (!gum_darwin_grafter_emit_segments (output->data, &layout,
      code_offsets, imports, error))
  {
    goto beach;
  }

  file = fopen (self->path, "wb");
  if (file == NULL)
    goto io_error;

  if (fwrite (output->data, output->len, 1, file) != 1)
    goto io_error;

  success = TRUE;
  goto beach;

already_grafted:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_EXISTS, "Already grafted");
    goto beach;
  }
nothing_to_instrument:
  {
    success = TRUE;
    goto beach;
  }
io_error:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
        "%s", g_strerror (errno));
  }
beach:
  {
    g_clear_pointer (&file, fclose);
    g_clear_pointer (&output, g_byte_array_unref);
    g_clear_pointer (&merged_binds, g_byte_array_unref);
    g_clear_pointer (&commands_out, g_byte_array_unref);
    g_clear_pointer (&imports, g_array_unref);
    g_clear_pointer (&code_offsets, g_array_unref);
    g_clear_pointer (&layout.segment_pair_descriptors, g_array_unref);
    g_clear_object (&module);

    return success;
  }
}

static gboolean
gum_darwin_grafter_compute_layout (GumDarwinGrafter * self,
                                   GumDarwinModule * module,
                                   GumGraftedLayout * layout,
                                   GArray ** code_offsets,
                                   GArray ** imports,
                                   GError ** error)
{
  gboolean success = FALSE;
  guint i;
  GumAddress address_cursor;
  goffset offset_cursor;
  guint pending_imports, pending_code_offsets;

  *code_offsets = NULL;
  *imports = NULL;

  memset (layout, 0, sizeof (GumGraftedLayout));
  layout->page_size = 16384;
  layout->segments_size = 0;
  layout->linkedit_offset_in = -1;
  for (i = 0; i != module->segments->len; i++)
  {
    const GumDarwinSegment * segment =
        &g_array_index (module->segments, GumDarwinSegment, i);

    if (strcmp (segment->name, "__TEXT") == 0)
    {
      layout->text_address = segment->vm_address;
    }
    else if (strcmp (segment->name, "__LINKEDIT") == 0)
    {
      layout->linkedit_address = segment->vm_address;
      layout->linkedit_offset_in = segment->file_offset;
      layout->linkedit_size_in = segment->file_size;
    }
  }
  if (layout->linkedit_offset_in == -1)
    goto invalid_data;

  layout->linkedit_size_out = layout->linkedit_size_in;
  layout->rewritten_binds_offset = -1;
  layout->rewritten_binds_split_offset = -1;
  if ((self->flags & GUM_DARWIN_GRAFTER_FLAGS_TRANSFORM_LAZY_BINDS) != 0)
  {
    const GumMachHeader64 * mach_header;
    gconstpointer command;

    mach_header = (const GumMachHeader64 *) module->image->data;
    command = mach_header + 1;

    for (i = 0; i != mach_header->ncmds; i++)
    {
      const GumLoadCommand * lc = command;

      if (lc->cmd == GUM_LC_DYLD_INFO_ONLY)
      {
        const GumDyldInfoCommand * ic = command;

        if (ic->lazy_bind_size != 0)
        {
          gboolean lazy_binds_follow_binds;
          gsize addendum;

          lazy_binds_follow_binds =
              ic->lazy_bind_off == ic->bind_off + ic->bind_size;

          layout->rewritten_binds_offset = ic->bind_off;
          layout->rewritten_binds_capacity = GUM_ALIGN_SIZE (ic->bind_size +
              ic->lazy_bind_size + GUM_BIND_STATE_RESET_SIZE, 16);

          if (lazy_binds_follow_binds)
          {
            addendum = GUM_ALIGN_SIZE (layout->rewritten_binds_capacity -
                (ic->bind_size + ic->lazy_bind_size), 16);
            layout->rewritten_binds_capacity =
                ic->bind_size + ic->lazy_bind_size + addendum;
            layout->rewritten_binds_split_offset =
                layout->rewritten_binds_offset + ic->bind_size +
                ic->lazy_bind_size;
          }
          else
          {
            addendum = GUM_ALIGN_SIZE (
                layout->rewritten_binds_capacity - ic->bind_size, 16);
            layout->rewritten_binds_capacity = ic->bind_size + addendum;
            layout->rewritten_binds_split_offset =
                layout->rewritten_binds_offset + ic->bind_size;
          }

          layout->rewritten_binds_shift = addendum;
          layout->linkedit_size_out += addendum;
        }
      }

      command = (const guint8 *) command + lc->cmdsize;
    }
  }

  *code_offsets = g_array_copy (self->code_offsets);
  if ((self->flags & GUM_DARWIN_GRAFTER_FLAGS_INGEST_FUNCTION_STARTS) != 0)
  {
    GumCollectFunctionsOperation op;
    op.functions = *code_offsets;
    op.linkedit = module->image->data;

    gum_darwin_module_enumerate_function_starts (module, gum_collect_functions,
        &op);
  }
  gum_normalize_code_offsets (*code_offsets);

  *imports = g_array_new (FALSE, FALSE, sizeof (GumImport));
  if ((self->flags & GUM_DARWIN_GRAFTER_FLAGS_INGEST_IMPORTS) != 0)
  {
    GumCollectImportsOperation op;
    op.imports = *imports;
    op.text_address = layout->text_address;

    gum_collect_chained_imports (module, &op);
    gum_darwin_module_enumerate_binds (module, gum_collect_import, &op);
    gum_darwin_module_enumerate_lazy_binds (module, gum_collect_import, &op);
  }

  layout->segment_pair_descriptors = g_array_new (FALSE, FALSE,
      sizeof (GumSegmentPairDescriptor));

  pending_imports = (*imports)->len;
  pending_code_offsets = (*code_offsets)->len;

  address_cursor = layout->linkedit_address;
  offset_cursor = layout->linkedit_offset_in;

  while (pending_imports > 0 || pending_code_offsets > 0)
  {
    GumSegmentPairDescriptor descriptor;
    gsize code_size = 0;
    guint used_imports, used_code_offsets;
    const gsize max_code_size = GUM_MAX_LDR_OFFSET -
        sizeof (GumGraftedHeader) -
        sizeof (GumGraftedImport);

    if (pending_code_offsets > 0)
    {
      used_code_offsets =
          MIN (pending_code_offsets * sizeof (GumGraftedHookTrampoline),
              max_code_size - sizeof (GumGraftedRuntime)) /
          sizeof (GumGraftedHookTrampoline);

      if (used_code_offsets == pending_code_offsets)
      {
        used_imports =
            MIN (pending_imports * sizeof (GumGraftedImportTrampoline),
                max_code_size - sizeof (GumGraftedRuntime) -
                used_code_offsets * sizeof (GumGraftedHookTrampoline)) /
            sizeof (GumGraftedImportTrampoline);
      }
      else
      {
        used_imports = 0;
      }
    }
    else if (pending_imports > 0)
    {
      used_imports = MIN (pending_imports * sizeof (GumGraftedImportTrampoline),
          max_code_size - sizeof (GumGraftedRuntime)) /
          sizeof (GumGraftedImportTrampoline);
      used_code_offsets = 0;
    }
    else
    {
      g_assert_not_reached ();
    }

    descriptor.code_address = address_cursor;
    descriptor.code_offset = offset_cursor;
    descriptor.imports_start = (*imports)->len - pending_imports;
    descriptor.code_offsets_start = (*code_offsets)->len - pending_code_offsets;

    while ((code_size = GUM_ALIGN_SIZE (
            used_code_offsets * sizeof (GumGraftedHookTrampoline) +
            used_imports * sizeof (GumGraftedImportTrampoline) +
            sizeof (GumGraftedRuntime),
            layout->page_size)) >= max_code_size)
    {
      if (used_code_offsets > 0)
      {
        if (used_imports > 0)
          used_imports--;
        else
          used_code_offsets--;
      }
      else if (used_imports > 0)
      {
        used_imports--;
      }
    }

    descriptor.code_size = code_size;
    descriptor.num_code_offsets = used_code_offsets;
    descriptor.num_imports = used_imports;

    pending_imports -= descriptor.num_imports;
    pending_code_offsets -= descriptor.num_code_offsets;

    address_cursor += descriptor.code_size;
    offset_cursor += descriptor.code_size;

    descriptor.data_address = address_cursor;
    descriptor.data_offset = offset_cursor;
    descriptor.data_size = GUM_ALIGN_SIZE (
        sizeof (GumGraftedHeader) +
        descriptor.num_code_offsets * sizeof (GumGraftedHook) +
        descriptor.num_imports * sizeof (GumGraftedImport),
        layout->page_size);

    g_array_append_val (layout->segment_pair_descriptors, descriptor);

    layout->segments_size += descriptor.data_size + descriptor.code_size;

    address_cursor += descriptor.data_size;
    offset_cursor += descriptor.data_size;
  }

  layout->linkedit_offset_out = offset_cursor;
  layout->linkedit_shift =
      layout->linkedit_offset_out - layout->linkedit_offset_in;

  success = TRUE;
  goto beach;

invalid_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Invalid Mach-O image");
    goto beach;
  }
beach:
  {
    if (!success)
    {
      g_clear_pointer (imports, g_array_unref);
      g_clear_pointer (code_offsets, g_array_unref);
    }

    return success;
  }
}

static void
gum_collect_chained_imports (GumDarwinModule * module,
                             GumCollectImportsOperation * op)
{
  const GumDarwinSegment * linkedit_segment, * segment;
  gsize i;
  GumDarwinModuleImage * image;
  const GumMachHeader64 * mach_header;
  gconstpointer command;
  gsize command_index;

  if (!gum_darwin_module_ensure_image_loaded (module, NULL))
    return;

  linkedit_segment = NULL;
  i = 0;
  while ((segment = gum_darwin_module_get_nth_segment (module, i++)) != NULL)
  {
    if (strcmp (segment->name, "__LINKEDIT") == 0)
    {
      linkedit_segment = segment;
      break;
    }
  }
  if (linkedit_segment == NULL)
    return;

  image = module->image;
  mach_header = image->data;

  command = mach_header + 1;
  for (command_index = 0; command_index != mach_header->ncmds; command_index++)
  {
    const GumLoadCommand * lc = command;

    if (lc->cmd == GUM_LC_DYLD_CHAINED_FIXUPS)
    {
      const GumLinkeditDataCommand * fixups = command;
      const GumChainedFixupsHeader * fixups_header;
      const GumChainedStartsInImage * image_starts;
      guint seg_index;

      fixups_header = (const GumChainedFixupsHeader *)
          ((const guint8 *) image->linkedit + fixups->dataoff);

      image_starts = (const GumChainedStartsInImage *)
          ((const guint8 *) fixups_header + fixups_header->starts_offset);

      for (seg_index = 0; seg_index != image_starts->seg_count; seg_index++)
      {
        const guint seg_offset = image_starts->seg_info_offset[seg_index];
        const GumChainedStartsInSegment * seg_starts;
        GumChainedPtrFormat format;
        guint16 page_index;

        if (seg_offset == 0)
          continue;

        seg_starts = (const GumChainedStartsInSegment *)
            ((const guint8 *) image_starts + seg_offset);
        format = seg_starts->pointer_format;

        segment = gum_find_segment_by_offset (module,
            seg_starts->segment_offset);
        if (segment == NULL)
          continue;

        for (page_index = 0; page_index != seg_starts->page_count; page_index++)
        {
          guint16 start;
          const guint8 * cursor;

          start = seg_starts->page_start[page_index];
          if (start == GUM_CHAINED_PTR_START_NONE)
            continue;

          cursor = (const guint8 *) mach_header + seg_starts->segment_offset +
              (page_index * seg_starts->page_size) +
              start;

          if (format == GUM_CHAINED_PTR_64 ||
              format == GUM_CHAINED_PTR_64_OFFSET)
          {
            const gsize stride = 4;

            while (TRUE)
            {
              const guint64 * slot = (const guint64 *) cursor;
              gsize delta;

              if ((*slot >> 63) == 0)
              {
                GumChainedPtr64Rebase * item = (GumChainedPtr64Rebase *) cursor;

                delta = item->next;
              }
              else
              {
                GumChainedPtr64Bind * item = (GumChainedPtr64Bind *) cursor;
                GumImport import;

                delta = item->next;

                import.slot_offset = (const guint8 *) slot -
                    (const guint8 *) mach_header;
                import.protection = segment->protection;

                g_array_append_val (op->imports, import);
              }

              if (delta == 0)
                break;

              cursor += delta * stride;
            }
          }
          else
          {
            const gsize stride = 8;

            while (TRUE)
            {
              const guint64 * slot = (const guint64 *) cursor;
              gsize delta;

              switch (*slot >> 62)
              {
                case 0b00:
                {
                  GumChainedPtrArm64eRebase * item =
                      (GumChainedPtrArm64eRebase *) cursor;

                  delta = item->next;

                  break;
                }
                case 0b01:
                {
                  GumChainedPtrArm64eBind * item =
                      (GumChainedPtrArm64eBind *) cursor;
                  GumImport import;

                  delta = item->next;

                  import.slot_offset = (const guint8 *) slot -
                      (const guint8 *) mach_header;
                  import.protection = segment->protection;

                  g_array_append_val (op->imports, import);

                  break;
                }
                case 0b10:
                {
                  GumChainedPtrArm64eAuthRebase * item =
                      (GumChainedPtrArm64eAuthRebase *) cursor;

                  delta = item->next;

                  break;
                }
                case 0b11:
                {
                  GumChainedPtrArm64eAuthBind * item =
                      (GumChainedPtrArm64eAuthBind *) cursor;
                  GumImport import;

                  delta = item->next;

                  import.slot_offset = (const guint8 *) slot -
                      (const guint8 *) mach_header;
                  import.protection = segment->protection;

                  g_array_append_val (op->imports, import);

                  break;
                }
              }

              if (delta == 0)
                break;

              cursor += delta * stride;
            }
          }
        }
      }
    }

    command = (const guint8 *) command + lc->cmdsize;
  }
}

static const GumDarwinSegment *
gum_find_segment_by_offset (GumDarwinModule * module,
                            gsize offset)
{
  const GumDarwinSegment * segment;
  gsize i = 0;

  while ((segment = gum_darwin_module_get_nth_segment (module, i++)) != NULL)
  {
    if (offset >= segment->file_offset &&
        offset < segment->file_offset + segment->file_size)
    {
      return segment;
    }
  }

  return NULL;
}

static gboolean
gum_collect_functions (const GumDarwinFunctionStartsDetails * details,
                       gpointer user_data)
{
  GumCollectFunctionsOperation * op = user_data;
  const guint8 * p, * end;
  guint32 offset;

  p = (const guint8 *) op->linkedit + details->file_offset;
  end = p + details->size;

  offset = 0;
  while (p != end)
  {
    guint64 delta;

    delta = gum_read_uleb128 (&p, end);
    if (delta == 0)
      break;

    offset += delta;

    g_array_append_val (op->functions, offset);
  }

  return TRUE;
}

static gboolean
gum_collect_import (const GumDarwinBindDetails * details,
                    gpointer user_data)
{
  GumCollectImportsOperation * op = user_data;
  const GumDarwinSegment * segment = details->segment;
  GumImport import;

  import.slot_offset = segment->vm_address - op->text_address + details->offset;
  import.protection = segment->protection;

  g_array_append_val (op->imports, import);

  return TRUE;
}

static void
gum_normalize_code_offsets (GArray * code_offsets)
{
  GHashTable * seen_offsets;
  gint i;

  seen_offsets = g_hash_table_new (NULL, NULL);

  for (i = 0; i < code_offsets->len; i++)
  {
    guint32 offset = g_array_index (code_offsets, guint32, i);

    if (g_hash_table_contains (seen_offsets, GSIZE_TO_POINTER (offset)))
    {
      g_array_remove_index_fast (code_offsets, i);
      i--;
    }
    else
    {
      g_hash_table_add (seen_offsets, GSIZE_TO_POINTER (offset));
    }
  }

  g_hash_table_unref (seen_offsets);

  g_array_sort (code_offsets, gum_compare_code_offsets);
}

static int
gum_compare_code_offsets (const void * element_a,
                          const void * element_b)
{
  const guint32 * a = element_a;
  const guint32 * b = element_b;

  return (gssize) *a - (gssize) *b;
}

static GByteArray *
gum_darwin_grafter_transform_load_commands (gconstpointer commands_in,
                                            guint32 size_of_commands_in,
                                            guint32 num_commands_in,
                                            const GumGraftedLayout * layout,
                                            gconstpointer linkedit,
                                            guint32 * num_commands_out,
                                            GByteArray ** merged_binds)
{
  GByteArray * commands_out;
  guint32 n;
  gconstpointer command_in;
  guint32 i;

  *merged_binds = NULL;

  commands_out = g_byte_array_sized_new (size_of_commands_in);
  n = 0;

  command_in = commands_in;
  for (i = 0; i != num_commands_in; i++)
  {
    const GumLoadCommand * lc = command_in;
    gboolean is_linkedit_command = FALSE;
    guint start_offset;
    gpointer command_out;

    if (lc->cmd == GUM_LC_SEGMENT_64)
    {
      const GumSegmentCommand64 * sc = command_in;

      is_linkedit_command = sc->fileoff == layout->linkedit_offset_in;
    }

    if (is_linkedit_command)
    {
      guint j;

      for (j = 0; j != layout->segment_pair_descriptors->len; j++)
      {
        const GumSegmentPairDescriptor * descriptor;
        GumSegmentCommand64 seg;
        GumSection64 sect;

        descriptor = &g_array_index (layout->segment_pair_descriptors,
            GumSegmentPairDescriptor, j);

        seg.cmd = GUM_LC_SEGMENT_64;
        seg.cmdsize = sizeof (seg) + sizeof (sect);
        g_snprintf (seg.segname, sizeof (seg.segname), "__FRIDA_TEXT%u", j);
        seg.vmaddr = descriptor->code_address;
        seg.vmsize = descriptor->code_size;
        seg.fileoff = descriptor->code_offset;
        seg.filesize = descriptor->code_size;
        seg.maxprot = GUM_VM_PROT_READ | GUM_VM_PROT_EXECUTE;
        seg.initprot = GUM_VM_PROT_READ | GUM_VM_PROT_EXECUTE;
        seg.nsects = 1;
        seg.flags = 0;
        g_byte_array_append (commands_out,
            (const guint8 *) &seg, sizeof (seg));

        strcpy (sect.sectname, "__trampolines");
        strcpy (sect.segname, seg.segname);
        sect.addr = seg.vmaddr;
        sect.size = seg.vmsize;
        sect.offset = seg.fileoff;
        sect.align = 2;
        sect.reloff = 0;
        sect.nreloc = 0;
        sect.flags = GUM_S_ATTR_PURE_INSTRUCTIONS |
            GUM_S_ATTR_SOME_INSTRUCTIONS;
        sect.reserved1 = 0;
        sect.reserved2 = 0;
        sect.reserved3 = 0;
        g_byte_array_append (commands_out,
            (const guint8 *) &sect, sizeof (sect));

        seg.cmd = GUM_LC_SEGMENT_64;
        seg.cmdsize = sizeof (seg) + sizeof (sect);
        g_snprintf (seg.segname, sizeof (seg.segname), "__FRIDA_DATA%u", j);
        seg.vmaddr = descriptor->data_address;
        seg.vmsize = descriptor->data_size;
        seg.fileoff = descriptor->data_offset;
        seg.filesize = descriptor->data_size;
        seg.maxprot = GUM_VM_PROT_READ | GUM_VM_PROT_WRITE;
        seg.initprot = GUM_VM_PROT_READ | GUM_VM_PROT_WRITE;
        seg.nsects = 1;
        seg.flags = 0;
        g_byte_array_append (commands_out,
            (const guint8 *) &seg, sizeof (seg));

        strcpy (sect.sectname, "__entries");
        strcpy (sect.segname, seg.segname);
        sect.addr = seg.vmaddr;
        sect.size = seg.vmsize;
        sect.offset = seg.fileoff;
        sect.align = 3;
        sect.reloff = 0;
        sect.nreloc = 0;
        sect.flags = 0;
        sect.reserved1 = 0;
        sect.reserved2 = 0;
        sect.reserved3 = 0;
        g_byte_array_append (commands_out,
            (const guint8 *) &sect, sizeof (sect));

        n += 2;
      }
    }

    start_offset = commands_out->len;
    g_byte_array_append (commands_out, (const guint8 *) lc, lc->cmdsize);
    command_out = commands_out->data + start_offset;
    n++;

#define GUM_SHIFT(field) \
    if (field >= layout->rewritten_binds_split_offset) \
      field += layout->rewritten_binds_shift; \
    field += layout->linkedit_shift

#define GUM_MAYBE_SHIFT(field) \
    if (field != 0 && field >= layout->rewritten_binds_split_offset) \
      field += layout->rewritten_binds_shift; \
    if (field != 0) \
      field += layout->linkedit_shift

    switch (lc->cmd)
    {
      case GUM_LC_SEGMENT_64:
      {
        GumSegmentCommand64 * sc = command_out;

        if (is_linkedit_command)
        {
          guint64 base = sc->vmaddr - sc->fileoff;

          sc->vmsize =
              GUM_ALIGN_SIZE (layout->linkedit_size_out, layout->page_size);

          GUM_SHIFT (sc->fileoff);
          sc->filesize = layout->linkedit_size_out;
          sc->vmaddr = base + sc->fileoff;
        }

        break;
      }
      case GUM_LC_DYLD_INFO_ONLY:
      {
        GumDyldInfoCommand * ic = command_out;

        if (layout->rewritten_binds_offset != -1)
        {
          GByteArray * binds;
          gboolean lazy_binds_follow_binds =
              ic->lazy_bind_off == ic->bind_off + ic->bind_size;

          if (!lazy_binds_follow_binds)
          {
            /*
             * Fill the gap left by merging binds and lazy binds, so that
             * __LINKEDIT has no gaps and codesign is happy. We do this by
             * detecting what is preceding the lazy bindings and extending
             * its size.
             */
            if (ic->rebase_off + ic->rebase_size == ic->lazy_bind_off)
              ic->rebase_size += ic->lazy_bind_size;
            else if (ic->weak_
"""


```