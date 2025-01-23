Response:
Let's break down the thought process for analyzing this C code for `gumsourcemap.c`.

1. **Understand the Core Purpose:** The filename and the initial copyright notice immediately suggest this file deals with "source maps."  Combined with the "frida-gum" and "bindings/gumjs" path, it strongly indicates a connection between JavaScript and its original source code, likely for debugging purposes.

2. **Identify Key Data Structures:** Scan the code for `struct` definitions. The core structures are `GumSourceMap` and `GumSourceMapping`. Understanding their members is crucial:
    * `GumSourceMap`: Holds arrays of `sources`, `names`, and `mappings`. These likely correspond to the components of a standard source map.
    * `GumSourceMapping`: Represents a single mapping between a generated location (line/column) and its original location (source file, line, column, and optionally a name).

3. **Trace the Core Functionality:** Look for the primary functions, especially those that create and manipulate these structures.
    * `gum_source_map_new`:  This is the constructor. It takes JSON as input, hinting at the format of the source map.
    * `gum_source_map_load`:  Responsible for parsing the JSON. It calls `gum_read_string_array` and `gum_source_map_load_mappings`.
    * `gum_source_map_load_mappings`: This function appears to handle the most complex part – decoding the "mappings" string. The use of VLQ encoding and the iterative processing with `prev_*` variables suggest it's incrementally building the mappings.
    * `gum_source_map_resolve`: This is the key function for *using* the source map. It takes a generated line/column and tries to find the corresponding original location. The use of `gum_bsearch_find_closest` suggests an optimization for searching.

4. **Analyze Helper Functions:** Examine the supporting functions:
    * `gum_read_string_array`:  Parses arrays of strings from the JSON.
    * `gum_parse_segment`:  Decodes a single segment from the "mappings" string.
    * `gum_parse_vlq_value`:  Decodes a Variable Length Quantity (VLQ) value, a common encoding in source maps.
    * `gum_bsearch_find_closest` and `gum_find_closest_in_range`: Implement a binary search with a "closest" match, important for handling inexact mappings.
    * `gum_source_mapping_compare`: Defines how source mappings are compared, crucial for sorting and searching.

5. **Connect to Concepts:**  Now, relate the code elements to broader concepts:
    * **Source Maps:** The entire file is about source maps, explaining how generated code (e.g., minified JavaScript) maps back to the original source.
    * **JSON:** The input format is JSON, a standard for data exchange.
    * **VLQ Encoding:** Recognize this as an efficient way to represent integers with varying lengths, used in source map mappings.
    * **Binary Search:** Understand why binary search is used for efficient lookup in a sorted list of mappings.

6. **Consider the Context:** Remember this is within Frida, a dynamic instrumentation toolkit. This means the source maps are likely being used to improve the debugging experience when instrumenting JavaScript code. Frida intercepts and modifies program behavior at runtime.

7. **Address Specific Questions:**  Go through the prompt's questions systematically:
    * **Functionality:** Summarize the core tasks: loading, parsing, resolving.
    * **Reversing:** Explain how source maps aid reverse engineering by making minified code readable. Provide concrete examples (stack traces, debugging).
    * **Low-Level/Kernel:**  Mention the connection to JavaScript runtimes (like V8), which are often written in C/C++ and interact with the operating system. The file itself *doesn't* directly touch kernel code, but it supports the debugging of code that *does*. Mentioning Android's WebView or Node.js reinforces this.
    * **Logic & I/O:** Create a simple example JSON input and trace how `gum_source_map_resolve` would work with a given generated line/column. Highlight the role of the comparison function.
    * **User Errors:** Focus on incorrect JSON format as the primary user error. Explain how this would lead to `NULL` returns or crashes.
    * **User Journey (Debugging):**  Describe the typical steps a user would take that would lead to this code being used (setting breakpoints in Frida, viewing stack traces).

8. **Refine and Structure:** Organize the findings into a clear and logical structure. Use headings and bullet points for readability. Explain technical terms where necessary.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is directly involved in code injection.
* **Correction:** No, it's focused on *debugging* the injected or target JavaScript, not the injection itself.
* **Initial thought:**  Focus heavily on the C language aspects.
* **Correction:** While the code is C, the primary *domain* is source maps and their role in JavaScript debugging. Balance the technical C details with the higher-level purpose.
* **Initial thought:** Just list the functions.
* **Correction:** Explain the *flow* of data and how the functions interact to achieve the overall goal.

By following these steps, combining code analysis with domain knowledge, and iteratively refining the understanding, a comprehensive and accurate explanation can be generated.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumsourcemap.c` 这个文件的功能和相关知识点。

**文件功能概述**

`gumsourcemap.c` 文件实现了在 Frida 中处理 Source Map 的功能。Source Map 是一种将编译、转换或压缩后的代码（通常是 JavaScript）映射回其原始源代码的技术。这对于调试和理解经过处理的代码至关重要。

具体来说，这个文件的主要功能包括：

1. **加载 Source Map:**  能够解析 JSON 格式的 Source Map 文件或字符串。
2. **存储 Source Map 信息:**  将解析后的 Source Map 信息存储在 `GumSourceMap` 结构体中，包括原始源文件列表、变量名列表和映射关系。
3. **解析映射关系:**  解析 Source Map 中关键的 "mappings" 字段，该字段使用 Base64 VLQ 编码表示了生成代码的位置与原始代码位置之间的映射。
4. **查找原始位置:**  提供 `gum_source_map_resolve` 函数，根据生成代码的行号和列号，查找对应的原始源文件、行号、列号以及变量名（如果存在）。

**与逆向方法的关联及举例说明**

Source Map 在 JavaScript 逆向分析中扮演着重要的角色。当目标应用程序使用打包器（如 Webpack、Rollup）或编译器（如 Babel、TypeScript）处理 JavaScript 代码后，生成的代码通常会被压缩、混淆，可读性极差。Source Map 提供了将这些难以理解的生成代码映射回原始易懂代码的桥梁。

**举例说明：**

假设我们正在逆向一个使用了 Webpack 打包的 Web 应用程序。当我们通过 Frida 附加到进程并尝试设置断点时，我们可能会看到类似这样的堆栈跟踪：

```
at o (/static/js/app.bundle.js:1234:567)
at r (/static/js/app.bundle.js:987:654)
at ...
```

这对于理解代码逻辑非常困难，因为我们只能看到打包后的 `app.bundle.js` 中的行号和列号。

但是，如果应用程序提供了 Source Map 文件（通常命名为 `app.bundle.js.map`），Frida (或者其他支持 Source Map 的调试工具) 就可以利用 `gumsourcemap.c` 中的功能：

1. **加载 Source Map:** Frida 会加载 `app.bundle.js.map` 文件。
2. **解析映射:** `gumsourcemap.c` 会解析 "mappings" 字段，建立生成代码位置和原始代码位置的映射关系。
3. **解析原始位置:** 当我们尝试在打包后的代码的 `1234` 行 `567` 列设置断点时，Frida 会调用 `gum_source_map_resolve`。
4. **输出原始信息:** `gum_source_map_resolve` 会在 `GumSourceMap` 中查找对应的原始信息，例如：原始文件可能是 `src/components/MyComponent.vue`，原始行号是 `50`，原始列号是 `10`。

这样，我们就可以在 Frida 中看到更具意义的断点位置和堆栈跟踪信息：

```
at MyComponent.o (src/components/MyComponent.vue:50:10)
at r (/static/js/app.bundle.js:987:654)  // 可能这部分没有 Source Map
at ...
```

这大大提高了逆向分析的效率，使我们能够理解代码的真实结构和逻辑。

**涉及到的二进制底层、Linux、Android 内核及框架的知识**

`gumsourcemap.c` 本身主要处理的是数据解析和查找逻辑，与直接的二进制底层、Linux/Android 内核交互较少。但是，它为 Frida 提供了处理 Source Map 的能力，而 Frida 本身是一个动态插桩工具，其核心功能涉及到：

* **二进制底层知识:** Frida 需要理解目标进程的内存结构、指令集等，才能进行代码注入和拦截。
* **操作系统 API:** Frida 需要使用操作系统提供的 API 来附加到进程、读取/写入内存、设置断点等。在 Linux 上，这涉及到 `ptrace` 等系统调用；在 Android 上，可能涉及到 Android 特有的 API 或机制。
* **JavaScript 运行时环境:**  Source Map 通常用于 JavaScript 代码。Frida 需要理解 JavaScript 运行时环境（例如 V8、JavaScriptCore）的内部结构，才能有效地进行插桩和调试。
* **Android 框架:**  在 Android 平台上，Frida 经常用于分析 Android 应用，这需要对 Android 的应用程序框架、虚拟机（Dalvik/ART）有一定的了解。

**逻辑推理及假设输入与输出**

`gum_source_map_resolve` 函数是该文件中进行逻辑推理的核心部分。

**假设输入:**

* `GumSourceMap` 对象 `self` 已成功加载并解析了一个 Source Map。
* `line`:  指向一个 `guint` 类型的指针，假设其值为 `1234` (生成代码的行号)。
* `column`: 指向一个 `guint` 类型的指针，假设其值为 `567` (生成代码的列号)。

**逻辑推理过程:**

1. `gum_source_map_resolve` 函数创建一个 `GumSourceMapping` 类型的 `needle` 结构体，其 `generated_line` 设置为 `*line` (1234)，`generated_column` 设置为 `*column` (567)。
2. 调用 `gum_bsearch_find_closest` 函数在 `self->mappings` 数组中查找最接近 `needle` 的映射关系。`gum_source_mapping_compare` 函数用于比较两个 `GumSourceMapping` 结构体，首先比较 `generated_line`，然后比较 `generated_column`。
3. 如果找到匹配的映射关系，且 `mapping->generated_line` 与 `needle.generated_line` 相等，则认为找到了精确匹配。
4. 将匹配到的原始行号 (`mapping->line`)、列号 (`mapping->column`)、源文件 (`mapping->source`) 和变量名 (`mapping->name`) 赋值给 `line`、`column`、`source` 和 `name` 指针指向的内存。

**假设输出 (如果找到匹配):**

* `*line` 的值可能被修改为 `50` (原始代码的行号)。
* `*column` 的值可能被修改为 `10` (原始代码的列号)。
* `*source` 指向的字符串可能是 `"src/components/MyComponent.vue"`。
* `*name` 指向的字符串可能是 `"o"` (如果 Source Map 中包含了变量名信息)。
* 函数返回 `TRUE`。

**假设输出 (如果没有找到匹配):**

* 函数返回 `FALSE`。`line`, `column`, `source`, `name` 指针指向的值不会被修改。

**涉及用户或编程常见的使用错误及举例说明**

1. **错误的 Source Map 文件路径或内容:** 用户可能提供了错误的 Source Map 文件路径，导致 Frida 无法加载 Source Map。或者 Source Map 文件本身内容损坏或格式不正确，导致解析失败。
   * **错误示例:** 用户在 Frida 脚本中指定了一个不存在的 `.map` 文件路径。
   * **后果:** `gum_source_map_new` 函数会返回 `NULL`。

2. **Source Map 版本不兼容:** 不同版本的 Source Map 规范可能存在差异，如果 `gumsourcemap.c` 的实现不支持特定版本的 Source Map，可能会导致解析错误或无法正确映射。
   * **错误示例:** 目标应用程序使用了最新版本的 Source Map 规范的某些特性，而 Frida 的 `gumsourcemap.c` 版本较旧，不支持这些特性。
   * **后果:**  部分或全部映射可能失败，`gum_source_map_resolve` 无法找到正确的原始位置。

3. **在没有 Source Map 的情况下尝试解析:**  如果目标代码没有生成 Source Map，用户仍然尝试使用 `gum_source_map_resolve`，则会返回 `FALSE`。
   * **错误示例:** 用户尝试在一些老旧的 JavaScript 代码上使用 Source Map 功能，但这些代码在构建时没有生成 `.map` 文件。
   * **后果:** `gum_source_map_resolve` 总是返回 `FALSE`。

4. **误解 Source Map 的作用范围:**  Source Map 只能映射回生成代码对应的原始代码。如果生成代码中包含了一些运行时生成的代码或者第三方库的代码，这些部分可能没有对应的 Source Map 信息。
   * **错误示例:** 用户期望能够通过 Source Map 追踪到所有 JavaScript 代码的原始位置，包括浏览器内置的 API 或第三方库的代码。
   * **后果:** 对于没有 Source Map 信息的部分，`gum_source_map_resolve` 将无法解析。

**用户操作如何一步步到达这里，作为调试线索**

1. **用户启动 Frida 并附加到目标进程:** 用户首先会使用 Frida 客户端 (例如 Python 脚本) 连接到目标应用程序的进程。
   ```python
   import frida
   session = frida.attach("target_application")
   ```

2. **用户加载 JavaScript 代码到 Frida 环境:** 用户会将包含 Frida API 调用 (例如 `Interceptor.attach`, `console.log`) 的 JavaScript 代码注入到目标进程。
   ```python
   script = session.create_script("""
       Interceptor.attach(ptr("0x12345678"), {
           onEnter: function(args) {
               console.log("Function called!");
           }
       });
   """)
   script.load()
   ```

3. **Frida 执行 JavaScript 代码，尝试进行插桩:** 当 Frida 执行这段 JavaScript 代码时，`Interceptor.attach` 函数会被调用。如果目标地址 `0x12345678` 对应的是一段打包后的 JavaScript 代码，并且 Frida 尝试解析该地址处的代码信息以提供更详细的调试信息 (例如，显示原始文件名和行号)，那么可能会涉及到 Source Map 的处理。

4. **Frida 尝试加载 Source Map:**  Frida 内部的 GumJS 绑定层 (即 `gumjs`) 会尝试查找与当前执行的 JavaScript 代码相关的 Source Map 文件。这通常会根据一些约定俗成的规则进行查找，例如，如果执行的代码位于 `app.bundle.js`，Frida 可能会尝试查找 `app.bundle.js.map`。

5. **调用 `gum_source_map_new` 加载 Source Map:** 如果找到了疑似 Source Map 的文件，Frida 会调用 `gum_source_map_new` 函数，并将文件内容作为 JSON 字符串传递给它。

6. **调用 `gum_source_map_load` 解析 Source Map:** `gum_source_map_new` 内部会调用 `gum_source_map_load` 来解析 JSON 数据，提取 sources, names 和 mappings 信息。

7. **在需要时调用 `gum_source_map_resolve` 进行映射:** 当 Frida 需要将生成代码的位置映射回原始位置时 (例如，在 `console.log` 输出堆栈跟踪信息，或者在设置断点时)，会调用 `gum_source_map_resolve` 函数，传入生成代码的行号和列号。

**作为调试线索:**

如果用户在 Frida 的输出中看到了原始文件名和行号，那么说明 `gumsourcemap.c` 的功能正在成功运行。如果用户只看到了打包后的文件名和行号，或者遇到了与 Source Map 相关的错误，那么可以沿着这个调用链进行调试：

* **检查 Source Map 文件是否存在且可访问。**
* **检查 Source Map 文件的内容是否符合规范。**
* **确认 Frida 版本是否支持目标 Source Map 的格式。**
* **检查 Frida 的日志输出，看是否有关于 Source Map 加载或解析的错误信息。**

总而言之，`gumsourcemap.c` 是 Frida 中一个关键的组成部分，它使得 Frida 能够理解和利用 JavaScript Source Map，从而为用户提供更强大和便捷的动态分析和调试能力。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumsourcemap.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2016 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsourcemap.h"

#include <json-glib/json-glib.h>

typedef struct _GumSourceMapping GumSourceMapping;

struct _GumSourceMap
{
  GObject parent;

  GPtrArray * sources;
  GPtrArray * names;
  GArray * mappings;
};

struct _GumSourceMapping
{
  guint generated_line;
  guint generated_column;

  const gchar * source;
  guint line;
  guint column;
  const gchar * name;
};

static void gum_source_map_finalize (GObject * object);
static gboolean gum_source_map_load (GumSourceMap * self, const gchar * json);
static gboolean gum_source_map_load_mappings (GumSourceMap * self,
    const gchar * encoded_mappings);

static gconstpointer gum_bsearch_find_closest (gconstpointer needle,
    GArray * haystack, GCompareFunc compare);
static gint gum_find_closest_in_range (gint low, gint high,
    gconstpointer needle, GArray * haystack, GCompareFunc compare);
static gint gum_source_mapping_compare (const GumSourceMapping * a,
    const GumSourceMapping * b);

static gboolean gum_read_string_array (JsonReader * reader,
    const gchar * member_name, GPtrArray * array);

static gboolean gum_parse_segment (const gchar ** cursor, gint * segment,
    guint * segment_length);
static gboolean gum_parse_vlq_value (const gchar ** cursor, gint * value);

G_DEFINE_TYPE (GumSourceMap, gum_source_map, G_TYPE_OBJECT)

static void
gum_source_map_class_init (GumSourceMapClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_source_map_finalize;
}

static void
gum_source_map_init (GumSourceMap * self)
{
  self->sources = g_ptr_array_new_with_free_func (g_free);
  self->names = g_ptr_array_new_with_free_func (g_free);
  self->mappings = g_array_new (FALSE, FALSE, sizeof (GumSourceMapping));
}

static void
gum_source_map_finalize (GObject * object)
{
  GumSourceMap * self = GUM_SOURCE_MAP (object);

  g_array_unref (self->mappings);
  g_ptr_array_unref (self->names);
  g_ptr_array_unref (self->sources);

  G_OBJECT_CLASS (gum_source_map_parent_class)->finalize (object);
}

GumSourceMap *
gum_source_map_new (const gchar * json)
{
  GumSourceMap * map;

  map = g_object_new (GUM_TYPE_SOURCE_MAP, NULL);

  if (!gum_source_map_load (map, json))
  {
    g_object_unref (map);
    return NULL;
  }

  return map;
}

static gboolean
gum_source_map_load (GumSourceMap * self,
                     const gchar * json)
{
  JsonNode * root;
  JsonReader * reader;
  const gchar * mappings;

  root = json_from_string (json, NULL);
  if (root == NULL)
    return FALSE;
  reader = json_reader_new (root);
  json_node_unref (root);

  if (!gum_read_string_array (reader, "sources", self->sources))
    goto error;

  gum_read_string_array (reader, "names", self->names);

  json_reader_read_member (reader, "mappings");
  mappings = json_reader_get_string_value (reader);
  if (mappings == NULL)
    goto error;
  if (!gum_source_map_load_mappings (self, mappings))
    goto error;
  json_reader_end_member (reader);

  g_object_unref (reader);
  return TRUE;

error:
  {
    g_object_unref (reader);
    return FALSE;
  }
}

static gboolean
gum_source_map_load_mappings (GumSourceMap * self,
                              const gchar * encoded_mappings)
{
  GPtrArray * sources = self->sources;
  GPtrArray * names = self->names;
  GArray * mappings = self->mappings;
  const gchar * cursor = encoded_mappings;
  guint generated_line = 1;
  gint prev_generated_column = 0;
  gint prev_source = 0;
  gint prev_line = 0;
  gint prev_column = 0;
  gint prev_name = 0;

  while (*cursor != '\0')
  {
    GumSourceMapping * mapping;
    guint mapping_index;
    gint segment[5];
    guint segment_length;

    if (*cursor == ';')
    {
      generated_line++;
      prev_generated_column = 0;
      cursor++;
      continue;
    }
    else if (*cursor == ',')
    {
      cursor++;
      continue;
    }

    mapping_index = mappings->len;
    g_array_set_size (mappings, mapping_index + 1);
    mapping = &g_array_index (mappings, GumSourceMapping, mapping_index);

    mapping->generated_line = generated_line;

    if (!gum_parse_segment (&cursor, segment, &segment_length))
      return FALSE;

    mapping->generated_column = prev_generated_column + segment[0];
    prev_generated_column = mapping->generated_column;

    if (segment_length > 1)
    {
      gint source_index;

      source_index = prev_source + segment[1];
      if (source_index < 0 || source_index >= (gint) sources->len)
        return FALSE;
      mapping->source = g_ptr_array_index (sources, source_index);
      prev_source = source_index;

      mapping->line = prev_line + segment[2];
      prev_line = mapping->line;
      mapping->line++;

      mapping->column = prev_column + segment[3];
      prev_column = mapping->column;

      if (segment_length > 4)
      {
        gint name_index;

        name_index = prev_name + segment[4];
        if (name_index < 0 || name_index >= (gint) names->len)
          return FALSE;
        mapping->name = g_ptr_array_index (names, name_index);
        prev_name = name_index;
      }
      else
      {
        mapping->name = NULL;
      }
    }
    else
    {
      mapping->source = NULL;
      mapping->line = 0;
      mapping->column = 0;
      mapping->name = NULL;
    }
  }

  g_array_sort (mappings, (GCompareFunc) gum_source_mapping_compare);

  return TRUE;
}

gboolean
gum_source_map_resolve (GumSourceMap * self,
                        guint * line,
                        guint * column,
                        const gchar ** source,
                        const gchar ** name)
{
  GumSourceMapping needle;
  const GumSourceMapping * mapping;

  needle.generated_line = *line;
  needle.generated_column = *column;

  mapping = gum_bsearch_find_closest (&needle, self->mappings,
      (GCompareFunc) gum_source_mapping_compare);
  if (mapping == NULL || mapping->generated_line != needle.generated_line)
    return FALSE;

  *line = mapping->line;
  *column = mapping->column;
  *source = mapping->source;
  *name = mapping->name;

  return TRUE;
}

static gconstpointer
gum_bsearch_find_closest (gconstpointer needle,
                          GArray * haystack,
                          GCompareFunc compare)
{
  gint index;
  guint element_size;

  if (haystack->len == 0)
    return NULL;

  index =
      gum_find_closest_in_range (-1, haystack->len, needle, haystack, compare);
  if (index < 0)
    return NULL;

  element_size = g_array_get_element_size (haystack);

  while (index - 1 >= 0)
  {
    if (compare (haystack->data + (index * element_size),
        haystack->data + ((index - 1) * element_size)) != 0)
      break;
    index--;
  }

  return haystack->data + (index * element_size);
}

static gint
gum_find_closest_in_range (gint low,
                           gint high,
                           gconstpointer needle,
                           GArray * haystack,
                           GCompareFunc compare)
{
  gint mid, comparison;

  mid = ((high - low) / 2) + low;

  comparison = compare (needle,
      haystack->data + (mid * g_array_get_element_size (haystack)));
  if (comparison == 0)
  {
    return mid;
  }
  else if (comparison > 0)
  {
    if (high - mid > 1)
      return gum_find_closest_in_range (mid, high, needle, haystack, compare);
    else
      return mid;
  }
  else
  {
    if (mid - low > 1)
      return gum_find_closest_in_range (low, mid, needle, haystack, compare);
    else
      return low < 0 ? -1 : low;
  }
}

static gint
gum_source_mapping_compare (const GumSourceMapping * a,
                            const GumSourceMapping * b)
{
  gint result;

  result = a->generated_line - b->generated_line;
  if (result != 0)
    return result;

  if (a->generated_column == G_MAXUINT || b->generated_column == G_MAXUINT)
    return 0;

  result = a->generated_column - b->generated_column;

  return result;
}

static gboolean
gum_read_string_array (JsonReader * reader,
                       const gchar * member_name,
                       GPtrArray * array)
{
  gint num_elements, element_index;

  if (!json_reader_read_member (reader, member_name))
    goto member_error;

  num_elements = json_reader_count_elements (reader);
  if (num_elements == -1)
    goto member_error;

  g_ptr_array_set_size (array, num_elements);

  for (element_index = 0; element_index != num_elements; element_index++)
  {
    const gchar * element;

    json_reader_read_element (reader, element_index);

    element = json_reader_get_string_value (reader);
    if (element == NULL)
      goto element_error;

    g_ptr_array_index (array, element_index) = g_strdup (element);

    json_reader_end_element (reader);
  }

  json_reader_end_member (reader);

  return TRUE;

element_error:
  {
    json_reader_end_element (reader);
  }
member_error:
  {
    json_reader_end_member (reader);

    g_ptr_array_set_size (array, 0);

    return FALSE;
  }
}

static gboolean
gum_parse_segment (const gchar ** cursor,
                   gint * segment,
                   guint * segment_length)
{
  if (!gum_parse_vlq_value (cursor, &segment[0]))
    return FALSE;

  if (!gum_parse_vlq_value (cursor, &segment[1]))
  {
    *segment_length = 1;
    return TRUE;
  }

  if (!gum_parse_vlq_value (cursor, &segment[2]))
    return FALSE;

  if (!gum_parse_vlq_value (cursor, &segment[3]))
    return FALSE;

  if (gum_parse_vlq_value (cursor, &segment[4]))
    *segment_length = 5;
  else
    *segment_length = 4;
  return TRUE;
}

static const gint8 gum_vlq_character_to_digit[256] =
{
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
  61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
  14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26,
  27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
  46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1
};

static gboolean
gum_parse_vlq_value (const gchar ** cursor,
                     gint * value)
{
  const gchar * c = *cursor;
  guint result = 0, offset = 0;
  gboolean has_continuation, is_positive;

  do
  {
    gint8 digit;
    guint chunk;

    digit = gum_vlq_character_to_digit[(guint8) *c++];
    if (digit == -1)
      return FALSE;

    chunk = digit & 0x1f;
    result |= (chunk << offset);
    offset += 5;

    has_continuation = (digit & (1 << 5)) != 0;
  }
  while (has_continuation);

  *cursor = c;

  is_positive = (result & 1) == 0;
  if (is_positive)
    *value = result >> 1;
  else
    *value = -((gint) (result >> 1));

  return TRUE;
}
```