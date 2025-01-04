Response:
The user wants to understand the functionality of the `gumcmodule.c` file, which is part of the Frida dynamic instrumentation toolkit. I need to analyze the provided C code and extract its core responsibilities. The user has also asked for specific connections to reverse engineering, low-level concepts, logical reasoning, common errors, and debugging context. Since this is the second part of the request, I should focus on summarizing the overall functionality of the code, building upon the analysis done in the first part (which I don't have access to, so I'll infer based on the function names and structures).

**Plan:**

1. **Identify Core Structures and Data Types:** Focus on `GumCModule`, `GumGccCModule`, `GumDarwinCModule`, and related structs.
2. **Analyze Key Functions:**  Examine functions like `gum_gcc_cmodule_new`, `gum_darwin_cmodule_new`, `link_pre`, `link_at`, `enumerate_symbols`, `find_symbol_by_name`, `drop_metadata`.
3. **Infer Overall Purpose:** Based on the functions and structures, deduce the main goal of the module.
4. **Address Specific Requests:**  Summarize the functionalities in relation to reverse engineering, low-level concepts, logical reasoning, user errors, and debugging.
这是 `frida/subprojects/frida-gum/bindings/gumjs/gumcmodule.c` 文件的第二部分源代码。结合第一部分（未提供，但可以通过函数名推测），这个文件的主要功能是 **支持在 Frida 中加载和管理由 C 代码编译而成的动态链接库 (C Module)**。 这部分代码主要关注 Darwin (macOS 和 iOS) 平台下的 C Module 的具体实现，并包含了一些通用的辅助函数。

**功能归纳:**

基于提供的第二部分代码，我们可以归纳出以下功能，并结合函数名推测其与第一部分的联系：

1. **Darwin 平台下的 C Module 支持 (`GumDarwinCModule`):**
    *   **创建 C Module (`gum_darwin_cmodule_new`):** 负责编译和加载 C 代码。如果提供了预编译的二进制文件，则直接使用。否则，它会使用 `clang` 编译器将提供的 C 源代码编译成动态库 (`.dylib`)。它还会处理头文件的包含和编译选项的设置。
    *   **添加宏定义和符号 (`gum_darwin_cmodule_add_define`, `gum_darwin_cmodule_add_symbol`):** 允许在编译时定义宏，以及在加载时提供外部符号的地址。这些符号可以被 C Module 内部的代码引用。
    *   **链接 C Module (`gum_darwin_cmodule_link_pre`, `gum_darwin_cmodule_link_at`, `gum_darwin_cmodule_link_post`):**  这个过程涉及内存映射、符号解析和初始化。`link_pre` 阶段会创建模块解析器 (`GumDarwinModuleResolver`) 和内存映射器 (`GumDarwinMapper`)，`link_at` 阶段将模块映射到内存并执行构造函数， `link_post` 阶段可能执行一些清理工作 (虽然目前为空)。
    *   **枚举符号 (`gum_darwin_cmodule_enumerate_symbols`):** 允许遍历 C Module 中导出的符号，并将符号名和地址传递给回调函数。
    *   **按名称查找符号 (`gum_darwin_cmodule_find_symbol_by_name`):**  根据符号名称查找其在 C Module 中的地址。
    *   **解析符号 (`gum_darwin_cmodule_resolve_symbol`):**  用于在动态链接时解析符号的地址。它首先查找用户提供的符号，然后在全局符号表中查找。
    *   **清理元数据 (`gum_darwin_cmodule_drop_metadata`):**  在 C Module 不再使用时，释放相关资源，如编译产生的临时文件、加载的二进制数据等。

2. **通用辅助函数:**
    *   **`gum_store_address_if_name_matches`:**  一个用于比较符号名称并存储地址的回调函数，可能在第一部分的符号查找中使用。
    *   **`gum_populate_include_dir`:** 将 Frida 相关的头文件复制到临时目录中，以便在编译 C Module 时包含这些头文件。
    *   **`gum_rmtree`:**  递归删除目录及其内容，用于清理编译过程中产生的临时文件。
    *   **`gum_call_tool`:**  调用外部工具（如 `clang` 编译器）并获取其输出和退出状态。
    *   **`gum_append_error`:**  用于拼接错误消息。

**与逆向方法的联系及举例:**

*   **动态库加载和符号解析:** 逆向分析常常需要理解目标程序加载了哪些动态库，以及如何解析和使用其中的符号。Frida 的 C Module 功能允许用户编写 C 代码，将其编译成动态库，并在目标进程中加载。通过 `gum_darwin_cmodule_enumerate_symbols` 和 `gum_darwin_cmodule_find_symbol_by_name`，逆向工程师可以动态地获取目标进程中加载的 C Module 的符号信息，而无需静态分析。

    **举例:** 假设你想知道目标进程中一个名为 `calculate_value` 的函数的地址。你可以编写一个 Frida 脚本，加载一个包含以下 C 代码的 C Module：

    ```c
    #include <frida-gum.h>
    #include <stdio.h>

    __attribute__((constructor))
    void on_load() {
        GumAddress addr = gum_module_find_export_by_name(NULL, "calculate_value");
        printf("Address of calculate_value: %p\n", (void *)addr);
    }
    ```

    Frida 会加载这个 C Module，并在 `on_load` 函数中通过 `gum_module_find_export_by_name` 查找目标进程中的 `calculate_value` 函数的地址。虽然这个例子没有直接使用 `gumcmodule.c` 提供的函数，但它展示了 C Module 如何与 Frida 的其他部分协同工作以进行动态分析。 `gumcmodule.c` 提供的符号枚举和查找功能是实现 `gum_module_find_export_by_name` 的基础。

*   **代码注入和执行:** C Module 允许将自定义的 C 代码注入到目标进程中执行。这为逆向工程师提供了强大的能力，可以 hook 函数、修改内存、调用目标进程中的函数等。

    **举例:**  你可以编写一个 C Module 来 hook 目标进程中的某个关键函数，例如认证函数。在 hook 函数中，你可以打印函数的参数、返回值，甚至修改函数的行为。

**涉及的二进制底层、Linux/Android 内核及框架知识 (主要针对 Darwin 平台):**

*   **Mach-O 文件格式 (Darwin):**  `GumDarwinCModule` 涉及到对 Mach-O 文件的加载和解析，这是 macOS 和 iOS 系统上可执行文件和动态库的格式。
*   **动态链接器 (dyld):**  代码中与链接相关的操作模拟了动态链接器的工作，例如符号解析和重定位。
*   **内存管理:**  将 C Module 加载到目标进程的内存空间需要理解操作系统的内存管理机制。
*   **系统调用:** 编译和加载动态库可能涉及到系统调用，例如 `mmap`（内存映射）、`dlopen` (动态库加载，虽然这里可能是模拟实现)。
*   **线程和进程:**  C Module 在目标进程的上下文中运行，需要理解线程和进程的概念。

**逻辑推理及假设输入与输出:**

*   **`gum_darwin_cmodule_new`:**
    *   **假设输入:**
        *   `source`:  一段包含一个名为 `my_function` 的函数的 C 代码字符串。
        *   `binary`: `NULL` (表示需要编译)。
        *   `options`:  可能包含一些编译选项。
    *   **预期输出:**  一个 `GumDarwinCModule` 对象，其中包含了编译后的动态库的二进制数据。在编译过程中，`gum_call_tool` 会被调用，使用 `clang` 将 C 代码编译成 `.dylib` 文件。编译成功后，`.dylib` 文件的内容会被读取到 `cmodule->binary` 中。

*   **`gum_darwin_cmodule_find_symbol_by_name`:**
    *   **假设输入:**
        *   `cm`:  一个已经成功加载的 `GumDarwinCModule` 对象。
        *   `name`:  字符串 "my_function"。
    *   **预期输出:**  指向 `my_function` 函数在内存中地址的指针。这个地址是通过 `gum_darwin_module_resolver_find_export_address` 在已加载的模块中查找得到的。

**涉及用户或编程常见的使用错误及举例:**

*   **编译错误:** 用户提供的 C 代码可能存在语法错误或链接错误。`gum_darwin_cmodule_new` 在编译失败时会设置 `GError`，指示编译失败，并包含编译器的输出。

    **举例:** 如果用户提供的 C 代码中包含拼写错误的函数名或者缺少必要的头文件，`clang` 编译时会报错，Frida 会将错误信息返回给用户。

*   **符号未定义:**  用户在 C 代码中引用了外部符号，但这些符号在目标进程中不存在，或者没有通过 `gum_darwin_cmodule_add_symbol` 提供。在链接阶段 (`gum_darwin_cmodule_link_at`)，会尝试解析这些符号，如果找不到，则会产生错误。

    **举例:**  如果 C 代码尝试调用一个目标进程中不存在的函数，链接时会报错，提示 "undefined reference to..."。

*   **内存访问错误:**  用户编写的 C 代码可能存在内存访问错误，例如访问空指针或越界访问。这些错误可能导致目标进程崩溃。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本，希望加载自定义的 C 代码到目标进程中。** 这通常通过 Frida 的 JavaScript API 完成，例如使用 `Memory.load` 函数。
2. **在 `Memory.load` 中，用户提供 C 源代码或预编译的二进制文件。**
3. **Frida 的 JavaScript 引擎将请求传递给 GumJS 层。**
4. **GumJS 层会调用相应的 C++ 代码，最终调用到 `gumcmodule.c` 中的函数，例如 `gum_darwin_cmodule_new` (在 Darwin 平台下)。**
5. **如果提供的是源代码，`gum_darwin_cmodule_new` 会创建临时目录，复制源代码和必要的头文件，并调用 `gum_call_tool` 运行 `clang` 编译器。**
6. **编译成功后，动态库的二进制数据会被读取并存储在 `GumDarwinCModule` 对象中。**
7. **后续的链接和加载过程会调用 `gum_darwin_cmodule_link_pre` 和 `gum_darwin_cmodule_link_at` 等函数，将动态库加载到目标进程的内存空间。**
8. **用户可以通过 Frida 脚本调用 C Module 中导出的函数，或者在 C Module 的构造函数中执行自定义的逻辑。**

**调试线索:**  如果在加载 C Module 的过程中出现问题，可以关注以下几点：

*   **编译器的输出:** 查看 `gum_call_tool` 的输出，了解编译是否成功，以及是否有编译错误或警告。
*   **链接错误:**  如果出现 "undefined reference to..." 错误，说明 C 代码中引用了未定义的符号。需要检查符号名是否正确，以及目标进程是否导出了该符号。
*   **内存错误:** 使用 Frida 的调试工具（例如 `Interceptor`）来跟踪 C Module 的执行，检查是否存在内存访问错误。
*   **Frida 的日志:** Frida 通常会输出一些调试信息，可以帮助定位问题。

总而言之，`gumcmodule.c` (特别是第二部分) 专注于在 Darwin 平台上实现 Frida 的 C Module 功能，负责编译、加载、链接和管理用户提供的 C 代码，使其能够在目标进程中执行，从而实现更灵活和底层的动态分析和 instrumentation。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumcmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
e_enumerate_symbols (cm, gum_store_address_if_name_matches, &ctx);

  return ctx.address;
}

static void
gum_store_address_if_name_matches (const GumCSymbolDetails * details,
                                   gpointer user_data)
{
  GumCSymbolDetails * ctx = user_data;

  if (strcmp (details->name, ctx->name) == 0)
    ctx->address = details->address;
}

static void
gum_gcc_cmodule_drop_metadata (GumCModule * cm)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);

  g_clear_pointer (&self->symbols, g_array_unref);

  g_clear_pointer (&self->argv, g_ptr_array_unref);

  if (self->workdir != NULL)
  {
    GFile * workdir_file = g_file_new_for_path (self->workdir);

    gum_rmtree (workdir_file);
    g_object_unref (workdir_file);

    g_free (self->workdir);
    self->workdir = NULL;
  }
}

#ifdef HAVE_DARWIN

#define GUM_TYPE_DARWIN_CMODULE (gum_darwin_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumDarwinCModule, gum_darwin_cmodule, GUM, DARWIN_CMODULE,
    GumCModule)

typedef struct _GumEnumerateExportsContext GumEnumerateExportsContext;

struct _GumDarwinCModule
{
  GumCModule parent;

  gchar * name;
  GBytes * binary;
  gchar * workdir;
  GPtrArray * argv;
  GHashTable * symbols;

  GumDarwinModuleResolver * resolver;
  GumDarwinMapper * mapper;
  GumDarwinModule * module;
};

struct _GumEnumerateExportsContext
{
  GumFoundCSymbolFunc func;
  gpointer user_data;

  GumDarwinCModule * self;
};

static void gum_darwin_cmodule_add_define (GumCModule * cm, const gchar * name,
    const gchar * value);
static void gum_darwin_cmodule_add_symbol (GumCModule * cm, const gchar * name,
    gconstpointer value);
static gboolean gum_darwin_cmodule_link_pre (GumCModule * cm, gsize * size,
    GString ** error_messages);
static gboolean gum_darwin_cmodule_link_at (GumCModule * cm, gpointer base,
    GString ** error_messages);
static void gum_darwin_cmodule_link_post (GumCModule * cm);
static void gum_darwin_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gboolean gum_emit_export (const GumDarwinExportDetails * details,
    gpointer user_data);
static gpointer gum_darwin_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static GumAddress gum_darwin_cmodule_resolve_symbol (const gchar * symbol,
    gpointer user_data);
static void gum_darwin_cmodule_drop_metadata (GumCModule * cm);

G_DEFINE_TYPE (GumDarwinCModule, gum_darwin_cmodule, GUM_TYPE_CMODULE)

static void
gum_darwin_cmodule_class_init (GumDarwinCModuleClass * klass)
{
  GumCModuleClass * cmodule_class = GUM_CMODULE_CLASS (klass);

  cmodule_class->add_define = gum_darwin_cmodule_add_define;
  cmodule_class->add_symbol = gum_darwin_cmodule_add_symbol;
  cmodule_class->link_pre = gum_darwin_cmodule_link_pre;
  cmodule_class->link_at = gum_darwin_cmodule_link_at;
  cmodule_class->link_post = gum_darwin_cmodule_link_post;
  cmodule_class->enumerate_symbols = gum_darwin_cmodule_enumerate_symbols;
  cmodule_class->find_symbol_by_name = gum_darwin_cmodule_find_symbol_by_name;
  cmodule_class->drop_metadata = gum_darwin_cmodule_drop_metadata;
}

static void
gum_darwin_cmodule_init (GumDarwinCModule * self)
{
  self->name = g_strdup ("module.dylib");
  self->symbols = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
}

static GumCModule *
gum_darwin_cmodule_new (const gchar * source,
                        GBytes * binary,
                        const GumCModuleOptions * options,
                        GError ** error)
{
  GumCModule * result;
  GumDarwinCModule * cmodule;
  gboolean success = FALSE;
  gchar * source_path = NULL;
  gchar * binary_path = NULL;
  gchar * output = NULL;

  result = g_object_new (GUM_TYPE_DARWIN_CMODULE, NULL);
  cmodule = GUM_DARWIN_CMODULE (result);

  if (binary != NULL)
  {
    cmodule->binary = g_bytes_ref (binary);
  }
  else
  {
    const gchar * arch;
    gint exit_status;
    gpointer data;
    gsize size;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    arch = "x86_64";
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
    arch = "i386";
#elif defined (HAVE_ARM64) && defined (HAVE_PTRAUTH)
    arch = "arm64e";
#elif defined (HAVE_ARM64)
    arch = "arm64";
#elif defined (HAVE_ARM)
    arch = "armv7";
#else
# error Unsupported architecture.
#endif

    cmodule->workdir = g_dir_make_tmp ("cmodule-XXXXXX", error);
    if (cmodule->workdir == NULL)
      goto beach;

    source_path = g_build_filename (cmodule->workdir, "module.c", NULL);
    binary_path = g_build_filename (cmodule->workdir, cmodule->name, NULL);

    if (!g_file_set_contents (source_path, source, -1, error))
      goto beach;

    if (!gum_populate_include_dir (cmodule->workdir, error))
      goto beach;

    cmodule->argv = g_ptr_array_new_with_free_func (g_free);
    g_ptr_array_add (cmodule->argv, g_strdup ("clang"));
    g_ptr_array_add (cmodule->argv, g_strdup ("-arch"));
    g_ptr_array_add (cmodule->argv, g_strdup (arch));
    g_ptr_array_add (cmodule->argv, g_strdup ("-dynamiclib"));
    g_ptr_array_add (cmodule->argv, g_strdup ("-Wall"));
    g_ptr_array_add (cmodule->argv, g_strdup ("-Werror"));
    g_ptr_array_add (cmodule->argv, g_strdup ("-O2"));
    g_ptr_array_add (cmodule->argv, g_strdup ("-isystem"));
    g_ptr_array_add (cmodule->argv, g_strdup ("."));
    g_ptr_array_add (cmodule->argv, g_strdup ("-isystem"));
    g_ptr_array_add (cmodule->argv, g_strdup ("capstone"));
    gum_cmodule_add_standard_defines (result);
    g_ptr_array_add (cmodule->argv, g_strdup ("module.c"));
    g_ptr_array_add (cmodule->argv, g_strdup ("-o"));
    g_ptr_array_add (cmodule->argv, g_strdup (cmodule->name));
    g_ptr_array_add (cmodule->argv, g_strdup ("-Wl,-undefined,dynamic_lookup"));
    g_ptr_array_add (cmodule->argv, NULL);

    if (!gum_call_tool (cmodule->workdir,
        (const gchar * const *) cmodule->argv->pdata, &output, &exit_status,
        error))
    {
      goto beach;
    }

    if (exit_status != 0)
      goto compilation_failed;

    if (!g_file_get_contents (binary_path, (gchar **) &data, &size, error))
      goto beach;

    cmodule->binary = g_bytes_new_take (data, size);
  }

  success = TRUE;
  goto beach;

compilation_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s", output);
    goto beach;
  }
beach:
  {
    g_free (output);
    g_free (binary_path);
    g_free (source_path);
    if (!success)
      g_clear_object (&result);

    return result;
  }
}

static void
gum_darwin_cmodule_add_define (GumCModule * cm,
                               const gchar * name,
                               const gchar * value)
{
  GumDarwinCModule * self = GUM_DARWIN_CMODULE (cm);
  gchar * arg;

  arg = (value == NULL)
      ? g_strconcat ("-D", name, NULL)
      : g_strconcat ("-D", name, "=", value, NULL);

  g_ptr_array_add (self->argv, arg);
}

static void
gum_darwin_cmodule_add_symbol (GumCModule * cm,
                               const gchar * name,
                               gconstpointer value)
{
  GumDarwinCModule * self = GUM_DARWIN_CMODULE (cm);

  g_hash_table_insert (self->symbols, g_strdup (name), (gpointer) value);
}

static gboolean
gum_darwin_cmodule_link_pre (GumCModule * cm,
                             gsize * size,
                             GString ** error_messages)
{
  GumDarwinCModule * self = GUM_DARWIN_CMODULE (cm);
  gboolean success = FALSE;
  GError * error = NULL;

  self->resolver = gum_darwin_module_resolver_new (mach_task_self (), NULL);
  gum_darwin_module_resolver_set_dynamic_lookup_handler (self->resolver,
      gum_darwin_cmodule_resolve_symbol, self, NULL);

  self->mapper = gum_darwin_mapper_new_take_blob (self->name,
      g_steal_pointer (&self->binary), self->resolver, &error);
  if (error != NULL)
    goto propagate_error;

  g_object_get (self->mapper, "module", &self->module, NULL);

  *size = gum_darwin_mapper_size (self->mapper);

  success = TRUE;
  goto beach;

propagate_error:
  {
    gum_append_error (error_messages, error->message);
    g_error_free (error);
    goto beach;
  }
beach:
  {
    return success;
  }
}

static gboolean
gum_darwin_cmodule_link_at (GumCModule * cm,
                            gpointer base,
                            GString ** error_messages)
{
  GumDarwinCModule * self;
  GumCModulePrivate * priv;
  GError * error = NULL;
  GumDarwinMapperConstructor ctor;

  self = GUM_DARWIN_CMODULE (cm);
  priv = gum_cmodule_get_instance_private (cm);

  gum_darwin_mapper_map (self->mapper, GUM_ADDRESS (base), &error);
  if (error != NULL)
    goto propagate_error;

  ctor = GSIZE_TO_POINTER (gum_darwin_mapper_constructor (self->mapper));
  ctor ();

  priv->destruct =
      GSIZE_TO_POINTER (gum_darwin_mapper_destructor (self->mapper));

  return TRUE;

propagate_error:
  {
    if (g_error_matches (error, GUM_ERROR, GUM_ERROR_NOT_FOUND))
    {
      const gchar * name_start, * name_end;
      gchar * name, * message;

      name_start = g_utf8_find_next_char (strstr (error->message, "“"), NULL);
      name_end = strstr (name_start, "”");

      name = g_strndup (name_start, name_end - name_start);

      message = g_strdup_printf ("undefined reference to `%s'", name);

      gum_append_error (error_messages, message);

      g_free (message);
      g_free (name);
    }
    else
    {
      gum_append_error (error_messages, error->message);
    }

    g_error_free (error);

    return FALSE;
  }
}

static void
gum_darwin_cmodule_link_post (GumCModule * cm)
{
}

static void
gum_darwin_cmodule_enumerate_symbols (GumCModule * cm,
                                      GumFoundCSymbolFunc func,
                                      gpointer user_data)
{
  GumDarwinCModule * self = GUM_DARWIN_CMODULE (cm);
  GumEnumerateExportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.self = self;

  gum_darwin_module_enumerate_exports (self->module, gum_emit_export, &ctx);
}

static gboolean
gum_emit_export (const GumDarwinExportDetails * details,
                 gpointer user_data)
{
  GumEnumerateExportsContext * ctx = user_data;
  GumDarwinCModule * self = ctx->self;
  GumExportDetails export;
  GumCSymbolDetails d;

  if (!gum_darwin_module_resolver_resolve_export (self->resolver, self->module,
      details, &export))
  {
    return TRUE;
  }

  d.name = export.name;
  d.address = GSIZE_TO_POINTER (export.address);

  ctx->func (&d, ctx->user_data);

  return TRUE;
}

static gpointer
gum_darwin_cmodule_find_symbol_by_name (GumCModule * cm,
                                        const gchar * name)
{
  GumDarwinCModule * self = GUM_DARWIN_CMODULE (cm);

  return GSIZE_TO_POINTER (gum_darwin_module_resolver_find_export_address (
      self->resolver, self->module, name));
}

static GumAddress
gum_darwin_cmodule_resolve_symbol (const gchar * symbol,
                                   gpointer user_data)
{
  GumDarwinCModule * self = GUM_DARWIN_CMODULE (user_data);
  gpointer address;

  address = g_hash_table_lookup (self->symbols, symbol);
  if (address == NULL)
    address = g_hash_table_lookup (gum_cmodule_get_symbols (), symbol);

  return GUM_ADDRESS (address);
}

static void
gum_darwin_cmodule_drop_metadata (GumCModule * cm)
{
  GumDarwinCModule * self = GUM_DARWIN_CMODULE (cm);

  g_clear_object (&self->module);
  g_clear_object (&self->mapper);
  g_clear_object (&self->resolver);

  g_clear_pointer (&self->symbols, g_hash_table_unref);

  g_clear_pointer (&self->argv, g_ptr_array_unref);

  if (self->workdir != NULL)
  {
    GFile * workdir_file = g_file_new_for_path (self->workdir);

    gum_rmtree (workdir_file);
    g_object_unref (workdir_file);

    g_free (self->workdir);
    self->workdir = NULL;
  }

  g_clear_pointer (&self->binary, g_bytes_unref);

  g_clear_pointer (&self->name, g_free);
}

#endif /* HAVE_DARWIN */

static void
gum_csymbol_details_destroy (GumCSymbolDetails * details)
{
  g_free ((gchar *) details->name);
}

static gboolean
gum_populate_include_dir (const gchar * path,
                          GError ** error)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCHeaderDetails * h = &gum_cmodule_headers[i];
    gchar * filename, * dirname;
    gboolean written;

    if (h->kind != GUM_CHEADER_FRIDA)
      continue;

    filename = g_build_filename (path, h->name, NULL);
    dirname = g_path_get_dirname (filename);

    g_mkdir_with_parents (dirname, 0700);
    written = g_file_set_contents (filename, h->data, h->size, error);

    g_free (dirname);
    g_free (filename);

    if (!written)
      return FALSE;
  }

  return TRUE;
}

static void
gum_rmtree (GFile * file)
{
  GFileEnumerator * enumerator;

  enumerator = g_file_enumerate_children (file, G_FILE_ATTRIBUTE_STANDARD_NAME,
      G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
  if (enumerator != NULL)
  {
    GFileInfo * info;
    GFile * child;

    while (g_file_enumerator_iterate (enumerator, &info, &child, NULL, NULL) &&
        child != NULL)
    {
      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        gum_rmtree (child);
      else
        g_file_delete (child, NULL, NULL);
    }

    g_object_unref (enumerator);
  }

  g_file_delete (file, NULL, NULL);
}

static gboolean
gum_call_tool (const gchar * cwd,
               const gchar * const * argv,
               gchar ** output,
               gint * exit_status,
               GError ** error)
{
  GSubprocessLauncher * launcher;
  GSubprocess * proc;

  launcher = g_subprocess_launcher_new (
      G_SUBPROCESS_FLAGS_STDOUT_PIPE |
      G_SUBPROCESS_FLAGS_STDERR_MERGE);
  g_subprocess_launcher_set_cwd (launcher, cwd);
  proc = g_subprocess_launcher_spawnv (launcher, argv, error);
  g_object_unref (launcher);
  if (proc == NULL)
    goto propagate_error;

  if (!g_subprocess_communicate_utf8 (proc, NULL, NULL, output, NULL, error))
    goto propagate_error;

  *exit_status = g_subprocess_get_exit_status (proc);

  g_object_unref (proc);

  return TRUE;

propagate_error:
  {
    g_clear_object (&proc);

    return FALSE;
  }
}

static void
gum_append_error (GString ** messages,
                  const char * msg)
{
  if (*messages == NULL)
  {
    *messages = g_string_new (msg);
  }
  else
  {
    g_string_append_c (*messages, '\n');
    g_string_append (*messages, msg);
  }
}

"""


```