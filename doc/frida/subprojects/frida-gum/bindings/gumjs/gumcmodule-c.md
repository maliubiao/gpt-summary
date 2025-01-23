Response:
My thinking process to analyze the C code and generate the response involved several steps:

1. **Understand the Goal:** The request asks for a functional breakdown of `gumcmodule.c`, highlighting its relevance to reverse engineering, low-level aspects (kernel, etc.), logical reasoning, potential user errors, debugging information, and a concise summary of its functions.

2. **High-Level Skim for Structure and Keywords:** I first quickly scanned the code for key elements:
    * **Includes:**  `gum.h`, `gio.h`, `json-glib/json-glib.h`, `libtcc.h` (conditional), implying interactions with Frida's core, file I/O, JSON handling, and a potential internal compiler (TinyCC). The `HAVE_DARWIN` conditional inclusion of `gumdarwinmapper.h` is also important.
    * **`GumCModule` Structure and Methods:** The presence of `GumCModule`, `GumCModulePrivate`, and related functions (`gum_cmodule_new`, `gum_cmodule_link`, etc.) immediately signals this is a core component dealing with loading and managing dynamically compiled C code. The use of GObject suggests a GLib-based object system.
    * **Conditional Compilation:**  `#ifdef HAVE_TINYCC`, `#ifdef HAVE_DARWIN`, etc., indicate platform-specific implementations and different compilation paths. This is crucial for understanding the overall flexibility of the module.
    * **Toolchain Abstraction:** The concept of `GUM_CMODULE_TOOLCHAIN_INTERNAL` and `GUM_CMODULE_TOOLCHAIN_EXTERNAL` points to an abstraction layer for handling different C compilers.
    * **Memory Management:**  Functions like `gum_memory_allocate`, `gum_memory_free`, `gum_cloak_add_range`, `gum_cloak_remove_range` suggest tight integration with Frida's memory management capabilities.
    * **Symbol Handling:** Functions like `gum_cmodule_add_symbol`, `gum_cmodule_find_symbol_by_name`, and enumeration functions indicate the module's ability to manage symbols within the compiled code.
    * **Linking:** Functions like `gum_cmodule_link_pre`, `gum_cmodule_link_at`, `gum_cmodule_link_post` clearly relate to the linking process of the dynamically compiled code.
    * **Error Handling:** The frequent use of `GError ** error` parameters highlights the importance of robust error reporting.

3. **Detailed Analysis of Key Functions and Concepts:** I then focused on understanding the purpose and interactions of the most important functions:
    * **`gum_cmodule_new`:** This is the entry point for creating a `GumCModule`. The logic for selecting the appropriate toolchain (TinyCC or external GCC/Clang) based on availability and provided binary is central.
    * **`gum_cmodule_link`:** This function performs the critical steps of allocating memory, linking the compiled code at the allocated address, and potentially calling initialization and finalization functions within the module.
    * **Toolchain-Specific Implementations (`gum_tcc_cmodule_new`, `gum_gcc_cmodule_new`, `gum_darwin_cmodule_new`):**  These functions encapsulate the logic for compiling C code using different toolchains. The TCC implementation is self-contained, while the GCC implementation involves invoking external tools like `gcc`, `ld`, and `objcopy`.
    * **Symbol Management (`gum_cmodule_add_symbol`, `gum_cmodule_find_symbol_by_name`):**  These functions allow Frida to interact with specific functions or variables defined in the dynamically loaded C code.
    * **Define Handling (`gum_cmodule_add_define`, `gum_cmodule_add_standard_defines`):** This mechanism allows passing preprocessor definitions to the C compiler, controlling the compilation process.
    * **Memory Cloaking (`gum_cloak_add_range`, `gum_cloak_remove_range`):** This is a security feature in Frida to control the visibility and permissions of the dynamically loaded code in memory.

4. **Relate to Reverse Engineering Concepts:** I connected the functionality to common reverse engineering tasks:
    * **Dynamic Instrumentation:** The core purpose of the module aligns directly with dynamic instrumentation.
    * **Code Injection:** Loading and executing custom C code within a running process is a form of code injection.
    * **Hooking:**  While not explicitly in this file, the ability to load custom code opens the door for hooking techniques by replacing or augmenting existing functions.
    * **Understanding Program Behavior:**  By injecting code, reverse engineers can observe and modify the behavior of target applications.

5. **Identify Low-Level Aspects:**  I pinpointed areas that touch upon low-level concepts:
    * **Memory Management:** Direct allocation and manipulation of memory.
    * **Page Permissions:**  Setting memory pages to read-write-execute.
    * **System Calls (Indirect):** The interaction with the operating system for memory allocation and potentially loading.
    * **Architecture-Specific Code:** The conditional compilation for different architectures (x86, ARM, ARM64, MIPS) and the inclusion of ABI helper functions in the TinyCC implementation.
    * **Linking and Loading:** The entire process of compiling, linking, and loading dynamic code.

6. **Consider Logical Reasoning and Input/Output:**  I thought about how different inputs (C code, compiler options) would lead to different outputs (compiled module, errors). The conditional logic for toolchain selection is a good example of where reasoning is applied.

7. **Anticipate User Errors:**  Based on my understanding of the process, I identified common pitfalls:
    * **Compilation Errors:** Incorrect C syntax or missing headers.
    * **Linking Errors:**  Undefined symbols.
    * **Security Issues:**  Writing unsafe code that could crash the target process.
    * **Incorrect Toolchain Selection:**  Forcing a specific toolchain when it's not available.

8. **Trace User Actions to Reach This Code:**  I considered the typical steps a Frida user would take that would eventually involve this code:
    * Writing a Frida script using `frida-compile` or inline JavaScript with backticks.
    * Using `Interceptor.attach` or other Frida APIs that might involve dynamically loading C code for advanced instrumentation.
    * Explicitly using `Memory.allocCode` or similar mechanisms that could leverage this module under the hood.

9. **Summarize Functionality:** Finally, I synthesized the information into a concise summary of the module's main responsibilities.

Throughout this process, I constantly referred back to the code to verify my understanding and ensure accuracy. The conditional compilation and the abstraction over different toolchains were key aspects that required careful attention.
好的，让我们详细分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumcmodule.c` 文件的功能。

**功能归纳**

这个 C 代码文件 `gumcmodule.c` 是 Frida 动态插桩工具中一个核心组件，主要负责**在目标进程中动态编译和加载 C 代码模块**。 它提供了一种机制，允许 Frida 用户将 C 代码片段注入到目标进程中，并在运行时执行，从而实现更复杂、更底层的插桩和修改行为。

更具体地说，其主要功能可以概括为：

1. **C 代码模块的创建和管理:**
   - 提供创建 `GumCModule` 对象的接口，用于表示一个即将被加载的 C 代码模块。
   - 管理 C 代码模块的生命周期，包括初始化、链接、加载、执行和卸载。

2. **支持多种 C 代码编译方式:**
   - **内部编译器 (TinyCC):**  如果编译时启用了 `HAVE_TINYCC` 宏，则使用内置的 Tiny C Compiler (TCC) 来直接在内存中编译 C 代码。
   - **外部编译器 (GCC/Clang):** 如果 `HAVE_TINYCC` 未定义，则会调用外部的 GCC 或 Clang 编译器来编译 C 代码。

3. **C 代码的编译和链接:**
   - 接受 C 代码字符串作为输入。
   - 根据选择的编译器，执行编译过程，生成可执行的机器码。
   - 将编译后的代码链接到目标进程的内存空间中。

4. **符号管理:**
   - 允许向 C 代码模块中添加符号定义（例如，宏定义）。
   - 允许向 C 代码模块中添加符号（函数或变量）及其对应的内存地址。这通常用于将目标进程中的函数或变量暴露给注入的 C 代码。
   - 提供查找已加载 C 代码模块中符号的功能。

5. **内存管理:**
   - 在目标进程中分配内存来加载编译后的 C 代码。
   - 管理已分配内存的权限（例如，设置为可读、可写、可执行）。
   - 提供机制在模块卸载时释放分配的内存。

6. **错误处理:**
   - 提供错误处理机制，用于捕获编译、链接和加载过程中可能出现的错误，并向用户报告。

7. **平台适配:**
   - 通过条件编译 (`#ifdef HAVE_DARWIN`, `#ifdef HAVE_I386` 等) 来处理不同操作系统和 CPU 架构之间的差异。

**与逆向方法的关联及举例说明**

`gumcmodule.c` 文件提供的功能与逆向工程中的多种方法紧密相关：

* **动态代码注入:** 这是最直接的关联。通过 `GumCModule`，逆向工程师可以将自定义的 C 代码注入到目标进程中，并在运行时执行。
    * **举例:**  逆向工程师想要修改目标进程中某个函数的行为，但现有的 Frida JavaScript API 不足以实现。他可以使用 `GumCModule` 加载一段 C 代码，这段代码使用 Gum 的 API (例如 `Interceptor.replace`) 来替换目标函数的实现。

* **底层操作和系统调用拦截:**  C 语言提供了更底层的硬件访问和系统调用接口。通过注入 C 代码，逆向工程师可以执行 JavaScript 无法完成的操作。
    * **举例:**  逆向工程师想要监控目标进程执行的特定系统调用，例如 `open` 或 `read`。他可以使用 `GumCModule` 注入 C 代码，这段代码使用内联汇编或直接的系统调用来拦截这些调用并记录相关信息。

* **绕过高层抽象:**  有时候，目标应用的反调试或安全机制在高层 (例如，JavaScript 层面) 比较容易检测。通过注入 C 代码，逆向工程师可以更接近底层，从而更容易绕过这些检测。
    * **举例:**  目标应用会检测 Frida 的 JavaScript 环境。逆向工程师可以使用 `GumCModule` 注入 C 代码，该代码直接操作内存，绕过 JavaScript 层的检测。

* **性能优化:**  对于性能敏感的插桩任务，使用 C 代码通常比 JavaScript 更高效。
    * **举例:**  逆向工程师需要对目标进程中一个被频繁调用的函数进行插桩，记录其调用次数和参数。使用 C 代码编写的插桩逻辑通常比 JavaScript 更快，对目标进程的性能影响更小。

**涉及的二进制底层、Linux/Android 内核及框架知识**

`gumcmodule.c` 的实现和使用涉及到以下底层知识：

* **二进制文件结构和加载:** 了解可执行文件和动态链接库的结构 (例如，ELF, Mach-O)，以及操作系统如何加载和执行这些文件。
* **内存管理:**  理解进程的内存空间布局（代码段、数据段、堆、栈），以及内存分配和权限管理机制。Frida 使用 `gum_memory_allocate` 和相关的函数来管理注入代码的内存。
* **链接器和加载器:**  理解动态链接的过程，包括符号解析和重定位。`gumcmodule.c` 中 `gum_cmodule_link_pre` 和 `gum_cmodule_link_at` 等函数就与链接过程有关。
* **CPU 架构:**  需要了解目标进程运行的 CPU 架构 (例如，x86, ARM)，因为编译后的 C 代码必须与目标架构兼容。条件编译宏 (`HAVE_I386`, `HAVE_ARM`, etc.) 就是为了处理架构差异。
* **调用约定 (Calling Conventions):**  在将 C 代码中的函数暴露给 JavaScript 或与其他 C 代码交互时，需要理解不同平台和架构的调用约定。
* **系统调用:**  当注入的 C 代码需要执行操作系统级别的操作时，需要了解相关的系统调用接口。
* **Linux/Android 框架 (如果目标是 Android):**
    * **Android Runtime (ART) 或 Dalvik:**  如果目标是 Android 应用程序，可能需要了解 ART 或 Dalvik 虚拟机的内部机制，以便更好地与注入的 C 代码交互。
    * **Binder IPC:**  Android 系统中常用的进程间通信机制。注入的 C 代码可能需要与系统服务或其他进程通信。
    * **Android NDK:**  虽然 `gumcmodule.c` 本身不直接涉及 NDK，但使用它注入的 C 代码很可能会使用 NDK 提供的库。

**逻辑推理及假设输入与输出**

假设用户想要将以下 C 代码注入到目标进程：

```c
#include <gum/gum.h>
#include <stdio.h>

void my_function() {
  printf("Hello from injected C code!\n");
}

void init() {
  GumAddress my_func_addr = GUM_ADDRESS(my_function);
  printf("Address of my_function: %p\n", (void*)my_func_addr);
}
```

**假设输入:**

* `source`: 上述 C 代码字符串。
* `options`:  `GumCModuleOptions` 结构体，可能指定了编译器选项或其他配置。

**逻辑推理过程:**

1. `gum_cmodule_new` 被调用，根据配置选择内部 (TinyCC) 或外部编译器。
2. 如果选择 TinyCC，`gum_tcc_cmodule_new` 被调用：
   - 创建 TCC 状态 (`TCCState`).
   - 设置错误处理、头文件加载和符号解析函数。
   - 添加标准宏定义。
   - 编译 C 代码 (`tcc_compile_string`).
3. 如果选择外部编译器 (例如 GCC)，`gum_gcc_cmodule_new` 被调用：
   - 创建临时工作目录。
   - 将 C 代码写入文件 (`module.c`).
   - 调用 GCC 编译代码，生成目标文件 (`module.o`).
4. `gum_cmodule_link` 被调用：
   - `gum_cmodule_link_pre` (特定于编译器) 计算所需的内存大小。
   - 分配内存 (`gum_memory_allocate`).
   - `gum_cmodule_link_at` (特定于编译器) 将编译后的代码加载到分配的内存中，并进行重定位。
   - 调用注入的 C 代码中的 `init` 函数 (如果存在)。

**预期输出:**

* 如果编译和链接成功，`gum_cmodule_link` 返回 `TRUE`。
* 在目标进程的控制台中，可能会看到以下输出：
  ```
  Hello from injected C code!
  Address of my_function: <内存地址>
  ```
* 如果编译或链接失败，`gum_cmodule_link` 返回 `FALSE`，并通过 `GError` 提供错误信息。

**用户或编程常见的使用错误及举例说明**

1. **C 代码编译错误:**  注入的 C 代码包含语法错误或使用了未定义的函数/变量。
   * **举例:**  忘记包含头文件 `#include <stdio.h>` 就使用了 `printf` 函数。Frida 会报告编译错误。

2. **链接错误:**  注入的 C 代码引用了目标进程中不存在的符号，或者符号的地址没有正确提供给 `gum_cmodule_add_symbol`。
   * **举例:**  C 代码尝试调用目标进程中的 `some_unknown_function`，但该函数实际上不存在或拼写错误。Frida 会报告链接错误。

3. **内存访问错误:**  注入的 C 代码尝试访问无效的内存地址，可能导致目标进程崩溃。
   * **举例:**  C 代码中存在指针错误，例如解引用空指针或越界访问数组。

4. **类型不匹配:**  在使用 `gum_cmodule_add_symbol` 将目标进程中的符号传递给 C 代码时，类型不匹配可能导致未定义的行为。
   * **举例:**  将一个 `int` 类型的变量的地址作为 `char*` 传递给 C 代码。

5. **竞争条件:**  如果注入的 C 代码与目标进程的其他线程共享资源，可能会出现竞争条件，导致程序行为不稳定。

6. **资源泄漏:**  注入的 C 代码分配了内存或其他资源，但在模块卸载时没有正确释放。

**用户操作是如何一步步到达这里的作为调试线索**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本 (通常是 JavaScript)。
2. **使用 `Memory.allocUtf8String`, `Memory.alloc` 等分配内存:**  用户可能使用这些 Frida API 在目标进程中分配内存。
3. **使用反引号 (`) 或 `frida-compile` 嵌入 C 代码:**  用户需要在 Frida 脚本中提供要注入的 C 代码。这可以通过 JavaScript 的反引号语法嵌入多行字符串，或者使用 `frida-compile` 将单独的 C 文件编译成 JavaScript 代码。
4. **调用 `Module.load()` 或 `Memory.load()`:**  Frida 提供了 `Module.load()` 或 `Memory.load()` 函数，这些函数最终会调用到 `gumcmodule.c` 中的相关逻辑。
   - `Module.load()` 用于加载动态链接库文件 (.so, .dll)。
   - `Memory.load()` 可以直接加载一段内存中的机器码，而 `gumcmodule.c` 负责编译 C 代码到内存。
5. **传递 C 代码和选项:**  在调用 `Module.load()` 或 `Memory.load()` 时，用户会将 C 代码字符串和可选的 `GumCModuleOptions` 对象传递给 Frida。
6. **Frida 内部处理:** Frida 接收到这些信息后，会创建 `GumCModule` 对象，并根据配置选择合适的编译器进行编译和链接。
7. **执行注入的 C 代码:**  一旦 C 代码被成功加载和链接，Frida 就可以调用 C 代码中导出的函数或访问其中的全局变量。

当调试与动态加载 C 代码相关的问题时，可以关注以下线索：

* **Frida 脚本中 `Module.load()` 或 `Memory.load()` 的调用:**  检查传递给这些函数的 C 代码和选项是否正确。
* **Frida 的错误信息:**  仔细阅读 Frida 提供的错误信息，这通常会指示编译、链接或运行时错误的原因。
* **目标进程的日志或崩溃信息:**  如果注入的 C 代码导致目标进程崩溃或产生错误日志，这些信息可以帮助定位问题。
* **使用 Frida 的调试功能:**  Frida 提供了一些调试功能，例如 `console.log` 或 `hexdump`，可以在注入的 C 代码中输出信息，帮助理解其执行过程。

**第 1 部分功能归纳**

总结来说，`gumcmodule.c` 的核心功能是**为 Frida 提供了一种动态编译和加载 C 代码到目标进程的能力**。它抽象了不同编译工具链的细节，并提供了管理已加载 C 代码模块的接口，使得 Frida 能够执行更底层、更复杂的插桩任务。这个文件是 Frida 实现强大动态分析能力的关键组成部分。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumcmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2019-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcmodule.h"

#include <stdio.h>
#include <string.h>
#include <gio/gio.h>
#include <gum/gum-init.h>
#include <gum/gum.h>
#include <json-glib/json-glib.h>
#ifdef HAVE_DARWIN
# include <gum/gumdarwinmapper.h>
#endif

#ifdef HAVE_TINYCC
static GumCModule * gum_tcc_cmodule_new (const gchar * source,
    const GumCModuleOptions * options, GError ** error);
#endif
static GumCModule * gum_gcc_cmodule_new (const gchar * source, GBytes * binary,
    const GumCModuleOptions * options, GError ** error) G_GNUC_UNUSED;
#ifdef HAVE_DARWIN
static GumCModule * gum_darwin_cmodule_new (const gchar * source,
    GBytes * binary, const GumCModuleOptions * options, GError ** error);
#endif

typedef struct _GumCModulePrivate GumCModulePrivate;

typedef void (* GumCModuleInitFunc) (void);
typedef void (* GumCModuleFinalizeFunc) (void);
typedef void (* GumCModuleDestructFunc) (void);

struct _GumCModulePrivate
{
  GumMemoryRange range;
  GumCModuleFinalizeFunc finalize;
  GumCModuleDestructFunc destruct;
};

static void gum_cmodule_finalize (GObject * object);
static void gum_emit_standard_define (const GumCDefineDetails * details,
    gpointer user_data);
static void gum_cmodule_add_define (GumCModule * self, const gchar * name,
    const gchar * value);
static gboolean gum_cmodule_link_pre (GumCModule * self, gsize * size,
    GString ** error_messages);
static gboolean gum_cmodule_link_at (GumCModule * self, gpointer base,
    GString ** error_messages);
static void gum_cmodule_link_post (GumCModule * self);
static void gum_emit_builtin_define (const gchar * name, const gchar * value,
    GumFoundCDefineFunc func, gpointer user_data);
static void gum_emit_builtin_define_str (const gchar * name,
    const gchar * value, GumFoundCDefineFunc func, gpointer user_data);

static void gum_csymbol_details_destroy (GumCSymbolDetails * details);

static gboolean gum_populate_include_dir (const gchar * path, GError ** error);
static void gum_rmtree (GFile * file);
static gboolean gum_call_tool (const gchar * cwd, const gchar * const * argv,
    gchar ** output, gint * exit_status, GError ** error);
static void gum_append_error (GString ** messages, const char * msg);

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (GumCModule, gum_cmodule, G_TYPE_OBJECT);

#include "gumcmodule-runtime.h"

static void
gum_cmodule_class_init (GumCModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_cmodule_finalize;
}

static void
gum_cmodule_init (GumCModule * cmodule)
{
}

static void
gum_cmodule_finalize (GObject * object)
{
  GumCModule * self;
  GumCModulePrivate * priv;
  const GumMemoryRange * r;

  self = GUM_CMODULE (object);
  priv = gum_cmodule_get_instance_private (self);
  r = &priv->range;

  if (r->base_address != 0)
  {
    if (priv->finalize != NULL)
      priv->finalize ();

    if (priv->destruct != NULL)
      priv->destruct ();

    gum_cloak_remove_range (r);

    gum_memory_free (GSIZE_TO_POINTER (r->base_address), r->size);
  }

  gum_cmodule_drop_metadata (self);

  G_OBJECT_CLASS (gum_cmodule_parent_class)->finalize (object);
}

GumCModule *
gum_cmodule_new (const gchar * source,
                 GBytes * binary,
                 const GumCModuleOptions * options,
                 GError ** error)
{
  GumCModuleToolchain toolchain = options->toolchain;

  if (toolchain == GUM_CMODULE_TOOLCHAIN_ANY)
  {
#ifdef HAVE_TINYCC
    toolchain = GUM_CMODULE_TOOLCHAIN_INTERNAL;
#else
    toolchain = GUM_CMODULE_TOOLCHAIN_EXTERNAL;
#endif
  }

  if (binary != NULL)
    toolchain = GUM_CMODULE_TOOLCHAIN_EXTERNAL;

  switch (toolchain)
  {
    case GUM_CMODULE_TOOLCHAIN_INTERNAL:
#ifdef HAVE_TINYCC
      return gum_tcc_cmodule_new (source, options, error);
#else
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
          "Internal toolchain is not available in this build configuration");
      return NULL;
#endif
    case GUM_CMODULE_TOOLCHAIN_EXTERNAL:
#ifdef HAVE_DARWIN
      return gum_darwin_cmodule_new (source, binary, options, error);
#else
      return gum_gcc_cmodule_new (source, binary, options, error);
#endif
    default:
      g_assert_not_reached ();
  }
}

const GumMemoryRange *
gum_cmodule_get_range (GumCModule * self)
{
  GumCModulePrivate * priv = gum_cmodule_get_instance_private (self);

  return &priv->range;
}

static void
gum_cmodule_add_standard_defines (GumCModule * self)
{
  gum_cmodule_enumerate_builtin_defines (gum_emit_standard_define, self);
}

static void
gum_emit_standard_define (const GumCDefineDetails * details,
                          gpointer user_data)
{
  GumCModule * self = user_data;

  gum_cmodule_add_define (self, details->name, details->value);
}

static void
gum_cmodule_add_define (GumCModule * self,
                        const gchar * name,
                        const gchar * value)
{
  GUM_CMODULE_GET_CLASS (self)->add_define (self, name, value);
}

void
gum_cmodule_add_symbol (GumCModule * self,
                        const gchar * name,
                        gconstpointer value)
{
  GUM_CMODULE_GET_CLASS (self)->add_symbol (self, name, value);
}

gboolean
gum_cmodule_link (GumCModule * self,
                  GError ** error)
{
  gboolean success = FALSE;
  GumCModulePrivate * priv;
  GString * error_messages;
  gsize size, page_size;
  gpointer base;

  priv = gum_cmodule_get_instance_private (self);

  error_messages = NULL;
  if (!gum_cmodule_link_pre (self, &size, &error_messages))
    goto beach;

  page_size = gum_query_page_size ();
  size = GUM_ALIGN_SIZE (size, page_size);

  base = gum_memory_allocate (NULL, size, page_size, GUM_PAGE_RW);

  if (gum_cmodule_link_at (self, base, &error_messages))
  {
    GumMemoryRange * r = &priv->range;
    GumCModuleInitFunc init;

    r->base_address = GUM_ADDRESS (base);
    r->size = size;

    gum_cloak_add_range (r);

    init = GUM_POINTER_TO_FUNCPTR (GumCModuleInitFunc,
        gum_cmodule_find_symbol_by_name (self, "init"));
    if (init != NULL)
      init ();

    priv->finalize = GUM_POINTER_TO_FUNCPTR (GumCModuleFinalizeFunc,
        gum_cmodule_find_symbol_by_name (self, "finalize"));

    success = TRUE;
  }
  else
  {
    gum_memory_free (base, size);
  }

beach:
  gum_cmodule_link_post (self);

  if (error_messages != NULL)
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Linking failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);
  }

  return success;
}

static gboolean
gum_cmodule_link_pre (GumCModule * self,
                      gsize * size,
                      GString ** error_messages)
{
  return GUM_CMODULE_GET_CLASS (self)->link_pre (self, size, error_messages);
}

static gboolean
gum_cmodule_link_at (GumCModule * self,
                     gpointer base,
                     GString ** error_messages)
{
  return GUM_CMODULE_GET_CLASS (self)->link_at (self, base, error_messages);
}

static void
gum_cmodule_link_post (GumCModule * self)
{
  GUM_CMODULE_GET_CLASS (self)->link_post (self);
}

void
gum_cmodule_enumerate_builtin_defines (GumFoundCDefineFunc func,
                                       gpointer user_data)
{
#if defined (HAVE_I386)
  gum_emit_builtin_define ("HAVE_I386", NULL, func, user_data);
#elif defined (HAVE_ARM)
  gum_emit_builtin_define ("HAVE_ARM", NULL, func, user_data);
#elif defined (HAVE_ARM64)
  gum_emit_builtin_define ("HAVE_ARM64", NULL, func, user_data);
#elif defined (HAVE_MIPS)
  gum_emit_builtin_define ("HAVE_MIPS", NULL, func, user_data);
#endif

  gum_emit_builtin_define_str ("G_GINT16_MODIFIER", G_GINT16_MODIFIER,
      func, user_data);
  gum_emit_builtin_define_str ("G_GINT32_MODIFIER", G_GINT32_MODIFIER,
      func, user_data);
  gum_emit_builtin_define_str ("G_GINT64_MODIFIER", G_GINT64_MODIFIER,
      func, user_data);
  gum_emit_builtin_define_str ("G_GSIZE_MODIFIER", G_GSIZE_MODIFIER,
      func, user_data);
  gum_emit_builtin_define_str ("G_GSSIZE_MODIFIER", G_GSSIZE_MODIFIER,
      func, user_data);

  gum_emit_builtin_define ("GLIB_SIZEOF_VOID_P",
      G_STRINGIFY (GLIB_SIZEOF_VOID_P), func, user_data);
}

static void
gum_emit_builtin_define (const gchar * name,
                         const gchar * value,
                         GumFoundCDefineFunc func,
                         gpointer user_data)
{
  GumCDefineDetails d = { name, value };

  func (&d, user_data);
}

static void
gum_emit_builtin_define_str (const gchar * name,
                             const gchar * value,
                             GumFoundCDefineFunc func,
                             gpointer user_data)
{
  gchar * raw_value;

  raw_value = g_strconcat ("\"", value, "\"", NULL);

  gum_emit_builtin_define (name, raw_value, func, user_data);

  g_free (raw_value);
}

void
gum_cmodule_enumerate_builtin_headers (GumFoundCHeaderFunc func,
                                       gpointer user_data)
{
  guint i;

  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCHeaderDetails * h = &gum_cmodule_headers[i];

    func (h, user_data);
  }
}

void
gum_cmodule_enumerate_symbols (GumCModule * self,
                               GumFoundCSymbolFunc func,
                               gpointer user_data)
{
  GUM_CMODULE_GET_CLASS (self)->enumerate_symbols (self, func, user_data);
}

gpointer
gum_cmodule_find_symbol_by_name (GumCModule * self,
                                 const gchar * name)
{
  return GUM_CMODULE_GET_CLASS (self)->find_symbol_by_name (self, name);
}

void
gum_cmodule_drop_metadata (GumCModule * self)
{
  GUM_CMODULE_GET_CLASS (self)->drop_metadata (self);
}

#ifdef HAVE_TINYCC

#include <libtcc.h>

#define GUM_TYPE_TCC_CMODULE (gum_tcc_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumTccCModule, gum_tcc_cmodule, GUM, TCC_CMODULE,
    GumCModule)

typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;

struct _GumTccCModule
{
  GumCModule parent;

  TCCState * state;
  gsize size;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundCSymbolFunc func;
  gpointer user_data;
};

static void gum_tcc_cmodule_add_define (GumCModule * cm, const gchar * name,
    const gchar * value);
static void gum_tcc_cmodule_add_symbol (GumCModule * cm, const gchar * name,
    gconstpointer value);
static gboolean gum_tcc_cmodule_link_pre (GumCModule * cm, gsize * size,
    GString ** error_messages);
static gboolean gum_tcc_cmodule_link_at (GumCModule * cm, gpointer base,
    GString ** error_messages);
static void gum_tcc_cmodule_link_post (GumCModule * cm);
static void gum_tcc_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gpointer gum_tcc_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static void gum_tcc_cmodule_drop_metadata (GumCModule * cm);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static void gum_append_tcc_error (void * opaque, const char * msg);
static void gum_emit_symbol (void * ctx, const char * name, const void * val);
static const char * gum_tcc_cmodule_load_header (void * opaque,
    const char * path, int * len);
static void * gum_tcc_cmodule_resolve_symbol (void * opaque, const char * name);

static void gum_add_abi_symbols (TCCState * state);
static const gchar * gum_undecorate_name (const gchar * name);

G_DEFINE_TYPE (GumTccCModule, gum_tcc_cmodule, GUM_TYPE_CMODULE)

static void
gum_tcc_cmodule_class_init (GumTccCModuleClass * klass)
{
  GumCModuleClass * cmodule_class = GUM_CMODULE_CLASS (klass);

  cmodule_class->add_define = gum_tcc_cmodule_add_define;
  cmodule_class->add_symbol = gum_tcc_cmodule_add_symbol;
  cmodule_class->link_pre = gum_tcc_cmodule_link_pre;
  cmodule_class->link_at = gum_tcc_cmodule_link_at;
  cmodule_class->link_post = gum_tcc_cmodule_link_post;
  cmodule_class->enumerate_symbols = gum_tcc_cmodule_enumerate_symbols;
  cmodule_class->find_symbol_by_name = gum_tcc_cmodule_find_symbol_by_name;
  cmodule_class->drop_metadata = gum_tcc_cmodule_drop_metadata;
}

static void
gum_tcc_cmodule_init (GumTccCModule * cmodule)
{
}

static GumCModule *
gum_tcc_cmodule_new (const gchar * source,
                     const GumCModuleOptions * options,
                     GError ** error)
{
  GumCModule * result;
  GumTccCModule * cmodule;
  TCCState * state;
  GString * error_messages;
  gchar * combined_source;

  result = g_object_new (GUM_TYPE_TCC_CMODULE, NULL);
  cmodule = GUM_TCC_CMODULE (result);

  state = tcc_new ();
  cmodule->state = state;

  error_messages = NULL;
  tcc_set_error_func (state, &error_messages, gum_append_tcc_error);

  tcc_set_cpp_load_func (state, cmodule, gum_tcc_cmodule_load_header);
  tcc_set_linker_resolve_func (state, cmodule, gum_tcc_cmodule_resolve_symbol);
  tcc_set_options (state,
      "-Wall "
      "-Werror "
      "-isystem /frida "
      "-isystem /frida/capstone "
      "-nostdinc "
      "-nostdlib"
  );

  gum_cmodule_add_standard_defines (result);
#ifdef HAVE_WINDOWS
  gum_cmodule_add_define (result, "extern", "__attribute__ ((dllimport))");
#endif

  tcc_set_output_type (state, TCC_OUTPUT_MEMORY);

  combined_source = g_strconcat ("#line 1 \"module.c\"\n", source, NULL);

  tcc_compile_string (state, combined_source);

  g_free (combined_source);

  tcc_set_error_func (state, NULL, NULL);

  if (error_messages != NULL)
    goto propagate_error;

  gum_add_abi_symbols (state);

  return result;

propagate_error:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s", error_messages->str);
    g_string_free (error_messages, TRUE);

    g_object_unref (result);

    return NULL;
  }
}

static void
gum_tcc_cmodule_add_define (GumCModule * cm,
                            const gchar * name,
                            const gchar * value)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_define_symbol (self->state, name, value);
}

static void
gum_tcc_cmodule_add_symbol (GumCModule * cm,
                            const gchar * name,
                            gconstpointer value)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_add_symbol (self->state, name, value);
}

static gboolean
gum_tcc_cmodule_link_pre (GumCModule * cm,
                          gsize * size,
                          GString ** error_messages)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  TCCState * state = self->state;
  int res;

  tcc_set_error_func (state, error_messages, gum_append_tcc_error);

  res = tcc_relocate (state, NULL);
  if (res == -1)
    return FALSE;

  self->size = res;

  *size = res;
  return TRUE;
}

static gboolean
gum_tcc_cmodule_link_at (GumCModule * cm,
                         gpointer base,
                         GString ** error_messages)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  if (tcc_relocate (self->state, base) == -1)
    return FALSE;

  gum_memory_mark_code (base, self->size);

  return TRUE;
}

static void
gum_tcc_cmodule_link_post (GumCModule * cm)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  tcc_set_error_func (self->state, NULL, NULL);
}

static void
gum_append_tcc_error (void * opaque,
                      const char * msg)
{
  GString ** messages = opaque;

  gum_append_error (messages, msg);
}

static void
gum_tcc_cmodule_enumerate_symbols (GumCModule * cm,
                                   GumFoundCSymbolFunc func,
                                   gpointer user_data)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);
  GumEnumerateSymbolsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  tcc_list_symbols (self->state, &ctx, gum_emit_symbol);
}

static void
gum_emit_symbol (void * ctx,
                 const char * name,
                 const void * val)
{
  GumEnumerateSymbolsContext * sc = ctx;
  GumCSymbolDetails d;

  d.name = gum_undecorate_name (name);
  d.address = (gpointer) val;

  sc->func (&d, sc->user_data);
}

static gpointer
gum_tcc_cmodule_find_symbol_by_name (GumCModule * cm,
                                     const gchar * name)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  return tcc_get_symbol (self->state, name);
}

static void
gum_tcc_cmodule_drop_metadata (GumCModule * cm)
{
  GumTccCModule * self = GUM_TCC_CMODULE (cm);

  g_clear_pointer (&self->state, tcc_delete);
}

static const char *
gum_tcc_cmodule_load_header (void * opaque,
                             const char * path,
                             int * len)
{
  const gchar * name;
  guint i;

  name = path;
  if (g_str_has_prefix (name, "/frida/"))
    name += 7;

  for (i = 0; i != G_N_ELEMENTS (gum_cmodule_headers); i++)
  {
    const GumCHeaderDetails * h = &gum_cmodule_headers[i];
    if (strcmp (h->name, name) == 0)
    {
      *len = h->size;
      return h->data;
    }
  }

  return NULL;
}

static void *
gum_tcc_cmodule_resolve_symbol (void * opaque,
                                const char * name)
{
  return g_hash_table_lookup (gum_cmodule_get_symbols (),
      gum_undecorate_name (name));
}

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4

static long long gum_divdi3 (long long a, long long b);
static long long gum_moddi3 (long long a, long long b);
static long gum_fixdfdi (double value);

static void
gum_add_abi_symbols (TCCState * state)
{
  tcc_add_symbol (state, "__divdi3", GUM_FUNCPTR_TO_POINTER (gum_divdi3));
  tcc_add_symbol (state, "__moddi3", GUM_FUNCPTR_TO_POINTER (gum_moddi3));
  tcc_add_symbol (state, "__fixdfdi", GUM_FUNCPTR_TO_POINTER (gum_fixdfdi));
}

static long long
gum_divdi3 (long long a,
            long long b)
{
  return a / b;
}

static long long
gum_moddi3 (long long a,
            long long b)
{
  return a % b;
}

static long
gum_fixdfdi (double value)
{
  return value;
}

#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8 && \
    !defined (_MSC_VER) && !defined (__MINGW32__)

extern void * __va_arg (void * ap, int arg_type, int size, int align);

static void
gum_add_abi_symbols (TCCState * state)
{
  tcc_add_symbol (state, "__va_arg", __va_arg);
}

#elif defined (HAVE_ARM)

#define GUM_DECLARE_HELPER(name) \
    extern void __aeabi_ ## name (void);
#define GUM_DECLARE_HELPER_FALLBACK(name, ...) \
    static void gum_aeabi_ ## name (__VA_ARGS__);
#define GUM_REGISTER_HELPER(name) \
    tcc_add_symbol (state, G_STRINGIFY (__aeabi_ ## name), __aeabi_ ## name)
#define GUM_REGISTER_HELPER_FALLBACK(name) \
    GUM_REGISTER_HELPER_FALLBACK_ALIASED (name, name)
#define GUM_REGISTER_HELPER_FALLBACK_ALIASED(name, impl) \
    tcc_add_symbol (state, G_STRINGIFY (__aeabi_ ## name), gum_aeabi_ ## impl)

#ifdef HAVE_AEABI_MEMORY_BUILTINS
GUM_DECLARE_HELPER (memmove)
GUM_DECLARE_HELPER (memmove4)
GUM_DECLARE_HELPER (memmove8)
GUM_DECLARE_HELPER (memset)
#else
GUM_DECLARE_HELPER_FALLBACK (memmove, void *, const void *, size_t)
GUM_DECLARE_HELPER_FALLBACK (memset, void *, size_t, int)
#endif
#ifndef HAVE_DARWIN
GUM_DECLARE_HELPER (f2ulz)
GUM_DECLARE_HELPER (f2lz)
GUM_DECLARE_HELPER (d2ulz)
GUM_DECLARE_HELPER (d2lz)
GUM_DECLARE_HELPER (ul2f)
GUM_DECLARE_HELPER (l2f)
GUM_DECLARE_HELPER (ul2d)
GUM_DECLARE_HELPER (l2d)
GUM_DECLARE_HELPER (ldivmod)
GUM_DECLARE_HELPER (uldivmod)
GUM_DECLARE_HELPER (llsl)
GUM_DECLARE_HELPER (llsr)
GUM_DECLARE_HELPER (lasr)
GUM_DECLARE_HELPER (idiv)
GUM_DECLARE_HELPER (uidiv)
GUM_DECLARE_HELPER (idivmod)
GUM_DECLARE_HELPER (uidivmod)
#endif

static void
gum_add_abi_symbols (TCCState * state)
{
#ifdef HAVE_AEABI_MEMORY_BUILTINS
  GUM_REGISTER_HELPER (memmove);
  GUM_REGISTER_HELPER (memmove4);
  GUM_REGISTER_HELPER (memmove8);
  GUM_REGISTER_HELPER (memset);
#else
  GUM_REGISTER_HELPER_FALLBACK (memmove);
  GUM_REGISTER_HELPER_FALLBACK_ALIASED (memmove4, memmove);
  GUM_REGISTER_HELPER_FALLBACK_ALIASED (memmove8, memmove);
  GUM_REGISTER_HELPER_FALLBACK (memset);
#endif
#ifndef HAVE_DARWIN
  GUM_REGISTER_HELPER (f2ulz);
  GUM_REGISTER_HELPER (f2lz);
  GUM_REGISTER_HELPER (d2ulz);
  GUM_REGISTER_HELPER (d2lz);
  GUM_REGISTER_HELPER (ul2f);
  GUM_REGISTER_HELPER (l2f);
  GUM_REGISTER_HELPER (ul2d);
  GUM_REGISTER_HELPER (l2d);
  GUM_REGISTER_HELPER (ldivmod);
  GUM_REGISTER_HELPER (uldivmod);
  GUM_REGISTER_HELPER (llsl);
  GUM_REGISTER_HELPER (llsr);
  GUM_REGISTER_HELPER (lasr);
  GUM_REGISTER_HELPER (idiv);
  GUM_REGISTER_HELPER (uidiv);
  GUM_REGISTER_HELPER (idivmod);
  GUM_REGISTER_HELPER (uidivmod);
#endif
}

#ifndef HAVE_AEABI_MEMORY_BUILTINS

static void
gum_aeabi_memmove (void * dst,
                   const void * src,
                   size_t n)
{
  memmove (dst, src, n);
}

static void
gum_aeabi_memset (void * s,
                  size_t n,
                  int c)
{
  memset (s, c, n);
}

#endif

#else

static void
gum_add_abi_symbols (TCCState * state)
{
}

#endif

static const gchar *
gum_undecorate_name (const gchar * name)
{
#ifdef HAVE_DARWIN
  return name + 1;
#else
  return name;
#endif
}

#endif /* HAVE_TINYCC */

#define GUM_TYPE_GCC_CMODULE (gum_gcc_cmodule_get_type ())
G_DECLARE_FINAL_TYPE (GumGccCModule, gum_gcc_cmodule, GUM, GCC_CMODULE,
    GumCModule)

typedef struct _GumLdsPrinter GumLdsPrinter;

struct _GumGccCModule
{
  GumCModule parent;

  gchar * workdir;
  GPtrArray * argv;
  GArray * symbols;
};

struct _GumLdsPrinter
{
  FILE * file;
  gpointer base;
};

static void gum_gcc_cmodule_add_define (GumCModule * cm, const gchar * name,
    const gchar * value);
static void gum_gcc_cmodule_add_symbol (GumCModule * cm, const gchar * name,
    gconstpointer value);
static gboolean gum_gcc_cmodule_link_pre (GumCModule * cm, gsize * size,
    GString ** error_messages);
static gboolean gum_gcc_cmodule_link_at (GumCModule * cm, gpointer base,
    GString ** error_messages);
static void gum_gcc_cmodule_link_post (GumCModule * cm);
static gboolean gum_gcc_cmodule_do_link (GumCModule * cm, gpointer base,
    gpointer * contents, gsize * size, GString ** error_messages);
static gboolean gum_gcc_cmodule_call_ld (GumGccCModule * self, gpointer base,
    GError ** error);
static gboolean gum_gcc_cmodule_call_objcopy (GumGccCModule * self,
    GError ** error);
static void gum_write_linker_script (FILE * file, gpointer base,
    GHashTable * api_symbols, GArray * user_symbols);
static void gum_print_lds_assignment (gpointer key, gpointer value,
    gpointer user_data);
static void gum_gcc_cmodule_enumerate_symbols (GumCModule * cm,
    GumFoundCSymbolFunc func, gpointer user_data);
static gpointer gum_gcc_cmodule_find_symbol_by_name (GumCModule * cm,
    const gchar * name);
static void gum_store_address_if_name_matches (
    const GumCSymbolDetails * details, gpointer user_data);
static void gum_gcc_cmodule_drop_metadata (GumCModule * cm);

G_DEFINE_TYPE (GumGccCModule, gum_gcc_cmodule, GUM_TYPE_CMODULE)

static void
gum_gcc_cmodule_class_init (GumGccCModuleClass * klass)
{
  GumCModuleClass * cmodule_class = GUM_CMODULE_CLASS (klass);

  cmodule_class->add_define = gum_gcc_cmodule_add_define;
  cmodule_class->add_symbol = gum_gcc_cmodule_add_symbol;
  cmodule_class->link_pre = gum_gcc_cmodule_link_pre;
  cmodule_class->link_at = gum_gcc_cmodule_link_at;
  cmodule_class->link_post = gum_gcc_cmodule_link_post;
  cmodule_class->enumerate_symbols = gum_gcc_cmodule_enumerate_symbols;
  cmodule_class->find_symbol_by_name = gum_gcc_cmodule_find_symbol_by_name;
  cmodule_class->drop_metadata = gum_gcc_cmodule_drop_metadata;
}

static void
gum_gcc_cmodule_init (GumGccCModule * self)
{
  self->argv = g_ptr_array_new_with_free_func (g_free);

  self->symbols = g_array_new (FALSE, FALSE, sizeof (GumCSymbolDetails));
  g_array_set_clear_func (self->symbols,
      (GDestroyNotify) gum_csymbol_details_destroy);
}

static GumCModule *
gum_gcc_cmodule_new (const gchar * source,
                     GBytes * binary,
                     const GumCModuleOptions * options,
                     GError ** error)
{
  GumCModule * result = NULL;
  GumGccCModule * cmodule;
  gboolean success = FALSE;
  gchar * source_path = NULL;
  gchar * output = NULL;
  gint exit_status;

  if (binary != NULL)
    goto binary_loading_unsupported;

  result = g_object_new (GUM_TYPE_GCC_CMODULE, NULL);
  cmodule = GUM_GCC_CMODULE (result);

  cmodule->workdir = g_dir_make_tmp ("cmodule-XXXXXX", error);
  if (cmodule->workdir == NULL)
    goto beach;

  source_path = g_build_filename (cmodule->workdir, "module.c", NULL);

  if (!g_file_set_contents (source_path, source, -1, error))
    goto beach;

  if (!gum_populate_include_dir (cmodule->workdir, error))
    goto beach;

  g_ptr_array_add (cmodule->argv, g_strdup ("gcc"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-c"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-Wall"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-Werror"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-O2"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-fno-pic"));
#ifdef HAVE_I386
  g_ptr_array_add (cmodule->argv, g_strdup ("-mcmodel=large"));
#endif
  g_ptr_array_add (cmodule->argv, g_strdup ("-nostdlib"));
  g_ptr_array_add (cmodule->argv, g_strdup ("-isystem"));
  g_ptr_array_add (cmodule->argv, g_strdup ("."));
  g_ptr_array_add (cmodule->argv, g_strdup ("-isystem"));
  g_ptr_array_add (cmodule->argv, g_strdup ("capstone"));
  gum_cmodule_add_standard_defines (result);
  g_ptr_array_add (cmodule->argv, g_strdup ("module.c"));
  g_ptr_array_add (cmodule->argv, NULL);

  if (!gum_call_tool (cmodule->workdir,
      (const gchar * const *) cmodule->argv->pdata, &output, &exit_status,
      error))
  {
    goto beach;
  }

  if (exit_status != 0)
    goto compilation_failed;

  success = TRUE;
  goto beach;

binary_loading_unsupported:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Binary loading is not yet supported on this platform");
    goto beach;
  }
compilation_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Compilation failed: %s", output);
    goto beach;
  }
beach:
  {
    g_free (output);
    g_free (source_path);
    if (!success)
      g_clear_object (&result);

    return result;
  }
}

static void
gum_gcc_cmodule_add_define (GumCModule * cm,
                            const gchar * name,
                            const gchar * value)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);
  gchar * arg;

  arg = (value == NULL)
      ? g_strconcat ("-D", name, NULL)
      : g_strconcat ("-D", name, "=", value, NULL);

  g_ptr_array_add (self->argv, arg);
}

static void
gum_gcc_cmodule_add_symbol (GumCModule * cm,
                            const gchar * name,
                            gconstpointer value)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);
  GumCSymbolDetails d;

  d.name = g_strdup (name);
  d.address = (gpointer) value;

  g_array_append_val (self->symbols, d);
}

static gboolean
gum_gcc_cmodule_link_pre (GumCModule * cm,
                          gsize * size,
                          GString ** error_messages)
{
  gpointer contents;

  if (!gum_gcc_cmodule_do_link (cm, 0, &contents, size, error_messages))
    return FALSE;

  g_free (contents);

  return TRUE;
}

static gboolean
gum_gcc_cmodule_link_at (GumCModule * cm,
                         gpointer base,
                         GString ** error_messages)
{
  gpointer contents;
  gsize size;

  if (!gum_gcc_cmodule_do_link (cm, base, &contents, &size, error_messages))
    return FALSE;

  memcpy (base, contents, size);
  gum_memory_mark_code (base, size);

  g_free (contents);

  return TRUE;
}

static void
gum_gcc_cmodule_link_post (GumCModule * cm)
{
}

static gboolean
gum_gcc_cmodule_do_link (GumCModule * cm,
                         gpointer base,
                         gpointer * contents,
                         gsize * size,
                         GString ** error_messages)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);
  gboolean success = FALSE;
  GError * error = NULL;
  gchar * module_path = NULL;

  if (!gum_gcc_cmodule_call_ld (self, base, &error))
    goto propagate_error;

  if (!gum_gcc_cmodule_call_objcopy (self, &error))
    goto propagate_error;

  module_path = g_build_filename (self->workdir, "module", NULL);

  if (!g_file_get_contents (module_path, (gchar **) contents, size, &error))
    goto propagate_error;

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
    g_free (module_path);

    return success;
  }
}

static gboolean
gum_gcc_cmodule_call_ld (GumGccCModule * self,
                         gpointer base,
                         GError ** error)
{
  gboolean success = FALSE;
  gchar * linker_script_path;
  FILE * file;
  const gchar * argv[] = {
    "gcc",
    "-nostdlib",
    "-Wl,--build-id=none",
    "-Wl,--script=module.lds",
    "module.o",
    NULL
  };
  gchar * output = NULL;
  gint exit_status;

  linker_script_path = g_build_filename (self->workdir, "module.lds", NULL);

  file = fopen (linker_script_path, "w");
  if (file == NULL)
    goto fopen_failed;
  gum_write_linker_script (file, base, gum_cmodule_get_symbols (),
      self->symbols);
  fclose (file);

  if (!gum_call_tool (self->workdir, argv, &output, &exit_status, error))
    goto beach;

  if (exit_status != 0)
    goto ld_failed;

  success = TRUE;
  goto beach;

fopen_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Failed to create %s", linker_script_path);
    goto beach;
  }
ld_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "ld failed: %s", output);
    goto beach;
  }
beach:
  {
    g_free (output);
    g_free (linker_script_path);

    return success;
  }
}

static gboolean
gum_gcc_cmodule_call_objcopy (GumGccCModule * self,
                              GError ** error)
{
  gboolean success = FALSE;
  const gchar * argv[] = {
    "objcopy",
    "-O", "binary",
    "--only-section=.frida",
    "a.out",
    "module",
    NULL
  };
  gchar * output;
  gint exit_status;

  if (!gum_call_tool (self->workdir, argv, &output, &exit_status, error))
    return FALSE;

  if (exit_status != 0)
    goto objcopy_failed;

  success = TRUE;
  goto beach;

objcopy_failed:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "objcopy failed: %s", output);
    goto beach;
  }
beach:
  {
    g_free (output);

    return success;
  }
}

static void
gum_write_linker_script (FILE * file,
                         gpointer base,
                         GHashTable * api_symbols,
                         GArray * user_symbols)
{
  GumLdsPrinter printer = {
    .file = file,
    .base = base,
  };
  guint i;

  g_hash_table_foreach (api_symbols, gum_print_lds_assignment, &printer);

  for (i = 0; i != user_symbols->len; i++)
  {
    GumCSymbolDetails * d = &g_array_index (user_symbols, GumCSymbolDetails, i);

    gum_print_lds_assignment ((gpointer) d->name, d->address, &printer);
  }

  fprintf (printer.file,
      "SECTIONS {\n"
      "  .frida 0x%zx: {\n"
      "    *(.text*)\n"
      "    *(.data)\n"
      "    *(.bss)\n"
      "    *(COMMON)\n"
      "    *(.rodata*)\n"
      "  }\n"
      "  /DISCARD/ : { *(*) }\n"
      "}\n",
      GPOINTER_TO_SIZE (base));
}

static void
gum_print_lds_assignment (gpointer key,
                          gpointer value,
                          gpointer user_data)
{
  GumLdsPrinter * printer = user_data;

  fprintf (printer->file, "%s = 0x%zx;\n",
      (gchar *) key,
      (printer->base != NULL) ? GPOINTER_TO_SIZE (value) : 0);
}

static void
gum_gcc_cmodule_enumerate_symbols (GumCModule * cm,
                                   GumFoundCSymbolFunc func,
                                   gpointer user_data)
{
  GumGccCModule * self = GUM_GCC_CMODULE (cm);
  const gchar * argv[] = { "nm", "a.out", NULL };
  gchar * output = NULL;
  gint exit_status;
  gchar * line_start;

  if (!gum_call_tool (self->workdir, argv, &output, &exit_status, NULL))
    goto beach;

  if (exit_status != 0)
    goto beach;

  line_start = output;
  while (TRUE)
  {
    gchar * line_end;
    guint64 address;
    gchar * endptr;

    line_end = strchr (line_start, '\n');
    if (line_end == NULL)
      break;
    *line_end = '\0';

    address = g_ascii_strtoull (line_start, &endptr, 16);
    if (endptr != line_start)
    {
      GumCSymbolDetails d;

      d.address = GSIZE_TO_POINTER (address);
      d.name = endptr + 3;

      func (&d, user_data);
    }

    line_start = line_end + 1;
  }

beach:
  g_free (output);
}

static gpointer
gum_gcc_cmodule_find_symbol_by_name (GumCModule * cm,
                                     const gchar * name)
{
  GumCSymbolDetails ctx;

  ctx.name = name;
  ctx.address = NULL;
  gum_cmodul
```