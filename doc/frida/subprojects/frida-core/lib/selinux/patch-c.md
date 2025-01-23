Response:
Let's break down the thought process for analyzing the C code and answering the prompt.

**1. Understanding the Goal:**

The core goal is to understand what this C code does, specifically in the context of Frida and dynamic instrumentation, and relate it to various technical areas like reverse engineering, low-level systems (Linux, Android kernel), and potential user errors.

**2. Initial Code Scan and Keyword Recognition:**

The first step is a quick scan for important keywords and function names:

* **`#include "frida-selinux.h"`:**  Immediately points to SELinux involvement.
* **`<selinux/selinux.h>`, `<sepol/policydb/policydb.h>`:** Confirms SELinux manipulation.
* **`frida_selinux_patch_policy`:** This is the main entry point and the core function we need to analyze.
* **`frida_load_policy`, `frida_save_policy`:** Obvious functions for reading and writing SELinux policies.
* **`frida_ensure_type`, `frida_ensure_rule`, `frida_ensure_permissive`:** Functions suggesting modification of the SELinux policy by adding new types, rules, and making types permissive.
* **`FridaSELinuxRule`:** A structure defining the rules to be added.
* **`open`, `write`:** Low-level file operations, indicating interaction with the file system.
* **`/sys/fs/selinux/policy`, `/sys/fs/selinux/load`:**  Key files for interacting with the SELinux kernel module.

**3. Tracing the `frida_selinux_patch_policy` Function:**

This is the heart of the code. We need to follow its logic step-by-step:

* **Load Existing Policy:**  It first attempts to load the current SELinux policy from `/sys/fs/selinux/policy`. This is crucial – it's modifying the *existing* policy.
* **Add New Types:** It adds two new SELinux types: `frida_file` and `frida_memfd`. It associates these types with attributes like `file_type` and `mlstrustedobject`.
* **Iterate Through Rules:** It loops through the `frida_selinux_rules` array. Each rule defines a source, target, class, and permissions.
* **Process Each Rule:** For each rule:
    * It checks for optional (`?`) source and target types, skipping the rule if the type doesn't exist.
    * It iterates through the defined permissions.
    * It calls `frida_ensure_rule` to add the rule to the policy.
* **Save Modified Policy:** It attempts to save the modified policy to `/sys/fs/selinux/load`.
* **Handle Saving Errors (Emulator Case):** If saving fails and it detects it's likely an emulator (SELinux is enforcing and can be temporarily disabled), it tries a fallback: make the `shell` domain permissive and then save. This is a critical piece of logic for understanding how Frida adapts to restrictive environments.
* **Cleanup:** Destroys policy structures and frees allocated memory.

**4. Analyzing Helper Functions:**

* **`frida_load_policy`:** Reads the binary SELinux policy file into memory.
* **`frida_save_policy`:**  Serializes the in-memory policy back into a binary format and prepares it for writing.
* **`frida_ensure_type`:**  Adds a new type to the policy. It handles cases where the type already exists. The variable argument list (`...`) allows for specifying attributes during type creation.
* **`frida_ensure_rule`:** Adds a new access control rule (allowing a source type to perform certain actions on a target type). It handles the special `$self` target.
* **`frida_ensure_permissive`:** Makes a given type permissive, bypassing SELinux restrictions for that type.
* **`frida_set_file_contents`:**  A utility for writing data to a file, similar to `g_file_set_contents` but without a temporary file.

**5. Connecting to Key Concepts:**

* **SELinux:** The core technology. Understanding SELinux types, classes, permissions, and policy is essential.
* **Dynamic Instrumentation (Frida's Purpose):** The code aims to *relax* SELinux restrictions to allow Frida's instrumentation to work effectively. This is the primary link.
* **Reverse Engineering:**  Relaxing SELinux can be a step in reverse engineering to gain more control and access to system resources.
* **Binary Format:** The policy files are binary, hence the use of `sepol` library functions.
* **Linux/Android Kernel:** SELinux is a kernel security module. The code interacts directly with the kernel's SELinux implementation via the `/sys/fs/selinux` interface.
* **Android Framework:**  Concepts like `zygote`, `system_server`, and `shell` are Android framework components protected by SELinux.

**6. Generating Examples and Explanations:**

Based on the code analysis, create concrete examples for each category:

* **Functionality:** Summarize what the code *does*.
* **Reverse Engineering:** Explain how weakening SELinux aids in reverse engineering.
* **Binary/Kernel/Android:** Detail the interaction with these low-level systems.
* **Logical Reasoning:**  Provide a scenario showing how optional rules are handled.
* **User Errors:**  Illustrate common mistakes when using Frida that could lead to this code being executed.
* **Debugging:**  Describe the user actions that lead to this code being a relevant part of the debugging process.

**7. Structuring the Output:**

Organize the information clearly under the requested headings. Use code snippets or clear explanations to illustrate the points.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this code *replaces* the entire SELinux policy. **Correction:**  The code *loads* the existing policy and *modifies* it, adding new rules and types. This is evident from `frida_load_policy` and `frida_save_policy`.
* **Initial thought:** The emulator handling is a minor detail. **Correction:**  This is a significant part of Frida's design to work in more restricted environments, and it demonstrates a deeper understanding of how SELinux works and how to temporarily bypass it.
* **Focus on Frida's intent:**  Continuously remind yourself *why* this code exists within Frida. It's about enabling instrumentation by overcoming SELinux restrictions.

By following these steps, systematically analyzing the code, and connecting it to the relevant technical domains, we can generate a comprehensive and accurate answer to the prompt.
这是一个 frida 动态插桩工具的源代码文件，名为 `patch.c`，位于 `frida/subprojects/frida-core/lib/selinux/` 目录下。它的主要功能是**在运行时修改 Linux 或 Android 系统的 SELinux 策略，以允许 Frida 执行某些操作**。

下面详细列举其功能，并根据要求进行说明：

**功能列表：**

1. **加载现有的 SELinux 策略:**  通过读取 `/sys/fs/selinux/policy` 文件，将当前系统的 SELinux 策略加载到内存中。
2. **添加自定义的 SELinux 类型 (Type):**  定义并添加了 `frida_file` 和 `frida_memfd` 两种新的 SELinux 类型，并将其标记为 `file_type` 和 `mlstrustedobject` 属性。
3. **添加自定义的 SELinux 规则 (Rule):**  根据预定义的规则列表 `frida_selinux_rules`，向 SELinux 策略中添加新的访问控制规则。这些规则允许特定的源类型 (source) 对特定的目标类型 (target) 和类别 (klass) 执行特定的权限 (permissions)。
4. **处理可选的规则条件:** 规则中可以使用 `?` 前缀表示可选的源或目标类型。如果系统中不存在该类型，则该规则会被跳过。
5. **尝试保存修改后的策略:** 将内存中修改后的 SELinux 策略写入到 `/sys/fs/selinux/load` 文件中，以使修改生效。
6. **处理保存策略失败的情况 (模拟器场景):** 如果保存策略失败，并且系统看起来像一个模拟器 (SELinux 处于 enforcing 模式并且可以被临时禁用)，则会尝试将 `shell` 域设置为 permissive 模式，然后再保存策略。之后会尝试恢复 SELinux 的 enforcing 模式。
7. **提供错误处理机制:**  使用 `GError` 结构体来报告加载、添加或保存 SELinux 策略过程中遇到的错误。
8. **使用底层的 SELinux 库:**  依赖于 `libselinux` 和 `libsepol` 库来操作 SELinux 策略。

**与逆向方法的关系：**

这个文件与逆向方法有着直接的关系，因为它旨在**绕过或放宽目标进程的 SELinux 限制，以便 Frida 能够进行更深入的动态插桩和分析**。

**举例说明:**

* **场景:**  你想使用 Frida hook 一个受 SELinux 保护的 Android 应用中的函数，该应用不允许普通域访问其文件。
* **`patch.c` 的作用:**  `patch.c` 中定义的规则，例如：
    ```c
    { { "domain", NULL }, "frida_file", "file", { "open", "read", "getattr", "execute", "?map", NULL } },
    ```
    这条规则允许所有 `domain` 类型的进程 (通常指应用程序进程) 对标记为 `frida_file` 类型的 *文件* 执行 `open`, `read`, `getattr`, `execute` 和可选的 `map` 权限。通过在 Frida 启动时或之前运行 `frida_selinux_patch_policy` 函数，可以将 `frida_file` 类型应用到 Frida 需要访问的目标应用的文件上，从而绕过原有的 SELinux 限制，使得 Frida 能够读取目标应用的 dex 文件或 so 库进行 hook。
* **逆向中的应用:**  通过放宽 SELinux 的限制，逆向工程师可以：
    * **读取受保护的文件:**  例如，目标应用的私有数据文件。
    * **执行受限的操作:**  例如，在某些受保护的内存区域执行代码。
    * **连接到受限的网络端口:**  如果目标应用的网络通信受到 SELinux 的限制。

**涉及的二进制底层，Linux，Android 内核及框架的知识：**

1. **二进制底层:**
    * **SELinux 策略的二进制格式:**  该代码直接操作 SELinux 策略的二进制表示，需要理解其结构才能进行修改。`libsepol` 库提供了处理这种二进制格式的接口。
    * **文件 I/O 操作:**  使用底层的 `open`, `read`, `write` 等系统调用来读取和写入 SELinux 策略文件。

2. **Linux 内核:**
    * **SELinux 内核模块:**  SELinux 是 Linux 内核的一个安全模块。该代码通过 `/sys/fs/selinux` 文件系统与 SELinux 内核模块进行交互，加载和更新策略。
    * **SELinux 的工作原理:**  需要理解 SELinux 的核心概念，如域 (domain)、类型 (type)、类 (class) 和权限 (permission)，以及策略是如何定义访问控制的。

3. **Android 内核及框架:**
    * **Android 的 SELinux 定制:**  Android 系统大量使用了 SELinux 来增强安全性。了解 Android 中特定的 SELinux 配置和策略至关重要。
    * **Android 进程模型:**  代码中涉及的 `domain`, `zygote`, `system_server` 等都是 Android 系统中的重要进程或概念，它们的 SELinux 类型有特殊的意义。
    * **`/sys/fs/selinux` 文件系统:**  这是 Linux 内核暴露给用户空间用于与 SELinux 交互的接口，在 Android 中也存在。

**逻辑推理及假设输入与输出：**

* **假设输入:**
    * 系统当前 SELinux 策略文件存在于 `/sys/fs/selinux/policy`。
    * 用户尝试运行一个需要访问被 SELinux 保护的资源的 Frida 脚本。
* **逻辑推理:**
    1. `frida_selinux_patch_policy` 函数被调用。
    2. 它会尝试加载 `/sys/fs/selinux/policy`。
    3. 如果加载成功，它会添加 `frida_file` 和 `frida_memfd` 类型。
    4. 然后，它会遍历 `frida_selinux_rules` 数组，并尝试添加这些规则到策略中。
    5. 例如，对于规则 `{ { "domain", NULL }, "frida_file", "file", { "open", "read", "getattr", "execute", "?map", NULL } }`：
        * 它会查找名为 "domain" 和 "frida_file" 的类型。
        * 它会查找名为 "file" 的类。
        * 它会尝试添加允许 "domain" 类型的进程对 "frida_file" 类型的 "file" 对象执行 "open", "read", "getattr", "execute" 权限的规则。
    6. 最后，它会尝试将修改后的策略保存到 `/sys/fs/selinux/load`。
* **假设输出:**
    * 如果一切顺利，SELinux 策略会被成功修改，Frida 脚本能够访问之前被限制的资源。
    * 如果保存策略失败 (例如，在非模拟器环境中)，可能会打印错误信息。
    * 如果规则中的可选类型不存在，则会跳过该规则，不会报错。

**涉及用户或者编程常见的使用错误：**

1. **权限不足:** 用户运行 Frida 的进程可能没有足够的权限读取 `/sys/fs/selinux/policy` 或写入 `/sys/fs/selinux/load`。这会导致加载或保存策略失败。
2. **SELinux 策略格式不兼容:** 如果系统的 SELinux 策略格式与代码预期的不符，`frida_load_policy` 可能会失败，并报 `FRIDA_SELINUX_ERROR_POLICY_FORMAT_NOT_SUPPORTED` 错误。
3. **依赖库缺失:** 如果系统中缺少 `libselinux` 或 `libsepol` 库，编译或运行时会出错。
4. **错误地修改或删除了必要的 SELinux 类型或规则:**  虽然 `patch.c` 的目的是添加规则，但用户可能手动修改了系统的 SELinux 配置，导致 Frida 尝试添加的规则与现有规则冲突，或者依赖的类型不存在。
5. **在不支持运行时修改 SELinux 策略的环境中运行:** 某些高度安全的系统可能不允许在运行时加载新的 SELinux 策略。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户想要使用 Frida 对一个受 SELinux 保护的应用进行动态插桩。**
2. **用户运行 Frida 命令，并尝试 hook 或访问应用中的某些资源。**
3. **Frida 检测到相关的操作被 SELinux 阻止。**
4. **Frida 内部机制 (可能是 Frida Agent 或 Frida Core 的一部分) 尝试调用 `frida_selinux_patch_policy` 函数。** 这通常发生在 Frida 尝试执行需要提升权限或访问受限资源的操作之前。
5. **`frida_selinux_patch_policy` 函数执行其加载、添加规则和保存策略的流程。**
6. **如果在上述任何步骤中出现错误，例如加载策略失败，或者添加规则时发现类型或类不存在，就会打印相应的错误信息。**

**调试线索:**

* **查看 Frida 的输出信息:**  Frida 通常会在控制台或日志中打印与 SELinux 相关的错误信息。例如，如果看到 "Unable to load SELinux policy from the kernel" 或 "Unable to add SELinux rule"，则表明 `patch.c` 的执行遇到了问题。
* **检查 `/sys/fs/selinux/load` 的写入权限:**  确认运行 Frida 的用户是否有权限向该文件写入。
* **检查系统中是否存在 `libselinux` 和 `libsepol` 库。**
* **使用 `getenforce` 命令检查 SELinux 的状态:**  确认 SELinux 是否处于 enforcing 模式。
* **查看内核日志 (dmesg):**  有时内核会记录与 SELinux 相关的事件和错误。
* **手动检查 SELinux 策略:**  可以使用 `sesearch` 等工具来查看当前系统的 SELinux 策略，确认 Frida 尝试添加的规则是否已经存在，或者是否存在冲突。
* **在模拟器环境中尝试:**  `patch.c` 中包含针对模拟器的特殊处理逻辑，如果在模拟器中问题消失，则可能表明问题与真机的 SELinux 配置有关。

总而言之，`frida/subprojects/frida-core/lib/selinux/patch.c` 是 Frida 为了能够在受 SELinux 保护的系统上顺利进行动态插桩而采取的关键步骤之一。它通过在运行时修改 SELinux 策略，放宽了对 Frida 及其目标进程的限制，从而实现了更强大的动态分析能力。

### 提示词
```
这是目录为frida/subprojects/frida-core/lib/selinux/patch.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#include "frida-selinux.h"

#include <fcntl.h>
#include <gio/gio.h>
#include <selinux/selinux.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>

#define FRIDA_SELINUX_ERROR frida_selinux_error_quark ()

typedef struct _FridaSELinuxRule FridaSELinuxRule;
typedef enum _FridaSELinuxErrorEnum FridaSELinuxErrorEnum;

struct _FridaSELinuxRule
{
  const gchar * sources[4];
  const gchar * target;
  const gchar * klass;
  const gchar * permissions[16];
};

enum _FridaSELinuxErrorEnum
{
  FRIDA_SELINUX_ERROR_POLICY_FORMAT_NOT_SUPPORTED,
  FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND,
  FRIDA_SELINUX_ERROR_CLASS_NOT_FOUND,
  FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND
};

static gboolean frida_load_policy (const gchar * filename, policydb_t * db, gchar ** data, GError ** error);
static gboolean frida_save_policy (const gchar * filename, policydb_t * db, GError ** error);
static type_datum_t * frida_ensure_type (policydb_t * db, const gchar * type_name, guint num_attributes, ...);
static void frida_add_type_to_class_constraints_referencing_attribute (policydb_t * db, uint32_t type_id, uint32_t attribute_id);
static gboolean frida_ensure_permissive (policydb_t * db, const gchar * type_name, GError ** error);
static avtab_datum_t * frida_ensure_rule (policydb_t * db, const gchar * s, const gchar * t, const gchar * c, const gchar * p, GError ** error);

static gboolean frida_set_file_contents (const gchar * filename, const gchar * contents, gssize length, GError ** error);

static const FridaSELinuxRule frida_selinux_rules[] =
{
  { { "domain", NULL }, "domain", "process", { "execmem", NULL } },
  { { "domain", NULL }, "frida_file", "dir", { "search", NULL } },
  { { "domain", NULL }, "frida_file", "file", { "open", "read", "getattr", "execute", "?map", NULL } },
  { { "domain", NULL }, "frida_memfd", "file", { "open", "read", "write", "getattr", "execute", "?map", NULL } },
  { { "domain", NULL }, "shell_data_file", "dir", { "search", NULL } },
  { { "domain", NULL }, "zygote_exec", "file", { "execute", NULL } },
  { { "domain", NULL }, "$self", "process", { "sigchld", NULL } },
  { { "domain", NULL }, "$self", "fd", { "use", NULL } },
  { { "domain", NULL }, "$self", "unix_stream_socket", { "connectto", "read", "write", "getattr", "getopt", NULL } },
  { { "domain", NULL }, "$self", "tcp_socket", { "read", "write", "getattr", "getopt", NULL } },
  { { "zygote", NULL }, "zygote", "capability", { "sys_ptrace", NULL } },
  { { "?app_zygote", NULL }, "zygote_exec", "file", { "read", NULL } },
  { { "system_server", NULL, }, "?apex_art_data_file", "file", { "execute", NULL } },
};

G_DEFINE_QUARK (frida-selinux-error-quark, frida_selinux_error)

void
frida_selinux_patch_policy (void)
{
  const gchar * system_policy = "/sys/fs/selinux/policy";
  policydb_t db;
  gchar * db_data;
  sidtab_t sidtab;
  GError * error = NULL;
  int res G_GNUC_UNUSED;
  guint rule_index;

  sepol_set_policydb (&db);
  sepol_set_sidtab (&sidtab);

  if (!g_file_test (system_policy, G_FILE_TEST_EXISTS))
    return;

  if (!frida_load_policy (system_policy, &db, &db_data, &error))
  {
    g_printerr ("Unable to load SELinux policy from the kernel: %s\n", error->message);
    g_error_free (error);
    return;
  }

  res = policydb_load_isids (&db, &sidtab);
  g_assert (res == 0);

  if (frida_ensure_type (&db, "frida_file", 2, "file_type", "mlstrustedobject", &error) == NULL)
  {
    g_printerr ("Unable to add SELinux type: %s\n", error->message);
    g_clear_error (&error);
    goto beach;
  }

  if (frida_ensure_type (&db, "frida_memfd", 2, "file_type", "mlstrustedobject", &error) == NULL)
  {
    g_printerr ("Unable to add SELinux type: %s\n", error->message);
    g_clear_error (&error);
    goto beach;
  }

  for (rule_index = 0; rule_index != G_N_ELEMENTS (frida_selinux_rules); rule_index++)
  {
    const FridaSELinuxRule * rule = &frida_selinux_rules[rule_index];
    const gchar * target = rule->target;
    const gchar * const * source_cursor;
    const gchar * const * perm_entry;

    if (target[0] == '?')
    {
      target++;

      if (hashtab_search (db.p_types.table, (char *) target) == NULL)
        continue;
    }

    for (source_cursor = rule->sources; *source_cursor != NULL; source_cursor++)
    {
      const gchar * source = *source_cursor;

      if (source[0] == '?')
      {
        source++;

        if (hashtab_search (db.p_types.table, (char *) source) == NULL)
          continue;
      }

      for (perm_entry = rule->permissions; *perm_entry != NULL; perm_entry++)
      {
        const gchar * perm = *perm_entry;
        gboolean is_important = TRUE;

        if (perm[0] == '?')
        {
          is_important = FALSE;
          perm++;
        }

        if (frida_ensure_rule (&db, source, target, rule->klass, perm, &error) == NULL)
        {
          if (!g_error_matches (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND) || is_important)
            g_printerr ("Unable to add SELinux rule: %s\n", error->message);
          g_clear_error (&error);
        }
      }
    }
  }

  if (!frida_save_policy ("/sys/fs/selinux/load", &db, &error))
  {
    gboolean success = FALSE, probably_in_emulator;

    probably_in_emulator = security_getenforce () == 1 && security_setenforce (0) == 0;
    if (probably_in_emulator)
    {
      g_clear_error (&error);

      success = frida_ensure_permissive (&db, "shell", &error);
      if (success)
        success = frida_save_policy ("/sys/fs/selinux/load", &db, &error);

      security_setenforce (1);
    }

    if (!success)
    {
      g_printerr ("Unable to save SELinux policy to the kernel: %s\n", error->message);
      g_clear_error (&error);
    }
  }

beach:
  policydb_destroy (&db);
  g_free (db_data);
}

static gboolean
frida_load_policy (const gchar * filename, policydb_t * db, gchar ** data, GError ** error)
{
  policy_file_t file;
  int res;

  policy_file_init (&file);
  file.type = PF_USE_MEMORY;
  if (!g_file_get_contents (filename, &file.data, &file.len, error))
    return FALSE;

  *data = file.data;

  policydb_init (db);

  res = policydb_read (db, &file, FALSE);
  if (res != 0)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_POLICY_FORMAT_NOT_SUPPORTED, "unsupported policy database format");
    policydb_destroy (db);
    g_free (*data);
    return FALSE;
  }

  return TRUE;
}

static gboolean
frida_save_policy (const gchar * filename, policydb_t * db, GError ** error)
{
  void * data;
  size_t size;
  int res G_GNUC_UNUSED;

  res = policydb_to_image (NULL, db, &data, &size);
  g_assert (res == 0);

  return frida_set_file_contents (filename, data, size, error);
}

static type_datum_t *
frida_ensure_type (policydb_t * db, const gchar * type_name, guint n_attributes, ...)
{
  type_datum_t * type;
  uint32_t type_id;
  va_list vl;
  guint i;
  GError * pending_error, ** error;

  type = hashtab_search (db->p_types.table, (char *) type_name);
  if (type == NULL)
  {
    uint32_t i, n;
    gchar * name;

    type_id = ++db->p_types.nprim;
    name = strdup (type_name);

    type = malloc (sizeof (type_datum_t));

    type_datum_init (type);
    type->s.value = type_id;
    type->primary = TRUE;
    type->flavor = TYPE_TYPE;

    hashtab_insert (db->p_types.table, name, type);

    policydb_index_others (NULL, db, FALSE);

    i = type_id - 1;
    n = db->p_types.nprim;
    db->type_attr_map = realloc (db->type_attr_map, n * sizeof (ebitmap_t));
    db->attr_type_map = realloc (db->attr_type_map, n * sizeof (ebitmap_t));
    ebitmap_init (&db->type_attr_map[i]);
    ebitmap_init (&db->attr_type_map[i]);

    /* We also need to add the type itself as the degenerate case. */
    ebitmap_set_bit (&db->type_attr_map[i], i, 1);
  }
  else
  {
    type_id = type->s.value;
  }

  va_start (vl, n_attributes);

  pending_error = NULL;
  for (i = 0; i != n_attributes; i++)
  {
    const gchar * attribute_name;
    type_datum_t * attribute_type;

    attribute_name = va_arg (vl, const gchar *);
    attribute_type = hashtab_search (db->p_types.table, (char *) attribute_name);
    if (attribute_type != NULL)
    {
      uint32_t attribute_id = attribute_type->s.value;
      ebitmap_set_bit (&attribute_type->types, type_id - 1, 1);
      ebitmap_set_bit (&db->type_attr_map[type_id - 1], attribute_id - 1, 1);
      ebitmap_set_bit (&db->attr_type_map[attribute_id - 1], type_id - 1, 1);

      frida_add_type_to_class_constraints_referencing_attribute (db, type_id, attribute_id);
    }
    else if (pending_error == NULL)
    {
      g_set_error (&pending_error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "attribute type “%s” does not exist", attribute_name);
    }
  }

  error = va_arg (vl, GError **);
  if (pending_error != NULL)
    g_propagate_error (error, pending_error);

  va_end (vl);

  return (pending_error == NULL) ? type : NULL;
}

static void
frida_add_type_to_class_constraints_referencing_attribute (policydb_t * db, uint32_t type_id, uint32_t attribute_id)
{
  uint32_t class_index;

  for (class_index = 0; class_index != db->p_classes.nprim; class_index++)
  {
    class_datum_t * klass = db->class_val_to_struct[class_index];
    constraint_node_t * node;

    for (node = klass->constraints; node != NULL; node = node->next)
    {
      constraint_expr_t * expr;

      for (expr = node->expr; expr != NULL; expr = expr->next)
      {
        ebitmap_node_t * tnode;
        guint i;

        ebitmap_for_each_bit (&expr->type_names->types, tnode, i)
        {
          if (ebitmap_node_get_bit (tnode, i) && i == attribute_id - 1)
            ebitmap_set_bit (&expr->names, type_id - 1, 1);
        }
      }
    }
  }
}

static gboolean
frida_ensure_permissive (policydb_t * db, const gchar * type_name, GError ** error)
{
  type_datum_t * type;
  int res G_GNUC_UNUSED;

  type = hashtab_search (db->p_types.table, (char *) type_name);
  if (type == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "type %s does not exist", type_name);
    return FALSE;
  }

  res = ebitmap_set_bit (&db->permissive_map, type->s.value, 1);
  g_assert (res == 0);

  return TRUE;
}

static avtab_datum_t *
frida_ensure_rule (policydb_t * db, const gchar * s, const gchar * t, const gchar * c, const gchar * p, GError ** error)
{
  type_datum_t * source, * target;
  gchar * self_type = NULL;
  class_datum_t * klass;
  perm_datum_t * perm;
  avtab_key_t key;
  avtab_datum_t * av;
  uint32_t perm_bit;

  source = hashtab_search (db->p_types.table, (char *) s);
  if (source == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "source type “%s” does not exist", s);
    return NULL;
  }

  if (strcmp (t, "$self") == 0)
  {
    char * self_context;
    gchar ** tokens;

    getcon (&self_context);

    tokens = g_strsplit (self_context, ":", 4);

    self_type = g_strdup (tokens[2]);
    t = self_type;

    g_strfreev (tokens);

    freecon (self_context);
  }

  target = hashtab_search (db->p_types.table, (char *) t);

  g_free (self_type);

  if (target == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_TYPE_NOT_FOUND, "target type “%s” does not exist", t);
    return NULL;
  }

  klass = hashtab_search (db->p_classes.table, (char *) c);
  if (klass == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_CLASS_NOT_FOUND, "class “%s” does not exist", c);
    return NULL;
  }

  perm = hashtab_search (klass->permissions.table, (char *) p);
  if (perm == NULL && klass->comdatum != NULL)
    perm = hashtab_search (klass->comdatum->permissions.table, (char *) p);
  if (perm == NULL)
  {
    g_set_error (error, FRIDA_SELINUX_ERROR, FRIDA_SELINUX_ERROR_PERMISSION_NOT_FOUND, "perm “%s” does not exist on the “%s” class", p, c);
    return NULL;
  }
  perm_bit = 1U << (perm->s.value - 1);

  key.source_type = source->s.value;
  key.target_type = target->s.value;
  key.target_class = klass->s.value;
  key.specified = AVTAB_ALLOWED;

  av = avtab_search (&db->te_avtab, &key);
  if (av == NULL)
  {
    int res G_GNUC_UNUSED;

    av = malloc (sizeof (avtab_datum_t));
    av->data = perm_bit;
    av->xperms = NULL;

    res = avtab_insert (&db->te_avtab, &key, av);
    g_assert (res == 0);
  }

  av->data |= perm_bit;

  return av;
}

/* Just like g_file_set_contents() except there's no temporary file involved. */

static gboolean
frida_set_file_contents (const gchar * filename, const gchar * contents, gssize length, GError ** error)
{
  int fd, res;
  gsize offset, size;

  fd = open (filename, O_RDWR);
  if (fd == -1)
    goto error;

  offset = 0;
  size = (length == -1) ? strlen (contents) : length;

  while (offset != size)
  {
    res = write (fd, contents + offset, size - offset);
    if (res != -1)
      offset += res;
    else if (errno != EINTR)
      goto error;
  }

  close (fd);

  return TRUE;

error:
  {
    int e;

    e = errno;
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (e), "%s", g_strerror (e));

    if (fd != -1)
      close (fd);

    return FALSE;
  }
}
```