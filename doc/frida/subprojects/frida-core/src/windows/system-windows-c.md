Response:
Let's break down the thought process for analyzing the `system-windows.c` code. The goal is to address all the prompt's requirements systematically.

**1. Initial Understanding and High-Level Overview:**

* **Identify the core purpose:** The filename and the `#include "frida-core.h"` strongly suggest this file provides system-level interaction for Frida on Windows. It's likely responsible for tasks like enumerating processes and getting process information.
* **Scan for key Windows APIs:**  Seeing includes like `<psapi.h>` and `<tlhelp32.h>` confirms this suspicion. These are core Windows APIs for process and system information.
* **Look for major functions:** `frida_system_get_frontmost_application`, `frida_system_enumerate_applications`, `frida_system_enumerate_processes`, and `frida_system_kill` stand out as the primary entry points for interacting with the system.

**2. Deconstructing Function by Function (Focusing on the Most Important Ones):**

* **`frida_system_enumerate_processes`:** This is a crucial function. The logic involves:
    * **Scope:**  Handles different levels of detail (minimal, normal, full).
    * **Enumeration:** Uses `EnumProcesses` to get a list of PIDs.
    * **Iteration:** Calls `frida_collect_process_info` for each PID.
    * **Filtering:**  Can optionally filter by specific PIDs.
    * **Metadata Collection:**  Calls helper functions to gather details like path, user, start time, and icons.
* **`frida_collect_process_info`:** This is the workhorse for gathering process details. Key steps:
    * **Opening a Handle:** `OpenProcess(PROCESS_QUERY_INFORMATION, ...)` is critical for accessing process info.
    * **Getting Filename:** `frida_get_process_filename` handles the conversion from device paths to drive letters.
    * **Metadata:** Calls `frida_add_process_metadata` for additional info.
    * **Icons:**  Calls `_frida_icon_from_process_or_file` (external, but its purpose is clear).
* **`frida_add_process_metadata`:**  Gathers supplementary info:
    * **User:** `frida_get_process_user` uses token information.
    * **PPID:** `frida_build_ppid_table` and table lookup.
    * **Start Time:** `frida_get_process_start_time` uses `GetProcessTimes`.
* **Helper Functions:** The other static functions are important supporting actors. Understanding their purpose helps understand the overall flow. For instance, `frida_get_process_filename`'s logic is a bit involved with drive letter mapping.

**3. Addressing the Prompt's Specific Questions:**

* **Functionality:**  List the main functions and their roles based on the code analysis.
* **Relationship to Reverse Engineering:** Think about how the information gathered by these functions is useful for reverse engineers. Process listing, path, user, start time – all crucial for understanding a system's state and identifying target processes. Hooking into API calls based on process names is a direct application.
* **Binary/Kernel/Android/Linux:**
    * **Binary:**  The code directly interacts with the Windows API, which operates at the binary level. Concepts like process handles and memory addresses are fundamental.
    * **Windows Kernel:**  APIs like `EnumProcesses`, `OpenProcess`, and `GetProcessImageFileNameW` are implemented by the Windows kernel.
    * **Linux/Android:**  Acknowledge the Windows-specific nature of this code and point out that similar functionality exists on other platforms but through different APIs and kernel structures.
* **Logical Reasoning (Input/Output):**
    * **`frida_system_enumerate_processes`:**  Consider the input (`FridaProcessQueryOptions`) and the output (`FridaHostProcessInfo` array). Imagine different options (e.g., specific PIDs, scope).
    * **`frida_collect_process_info`:** Think about the input (a PID) and the output (populating the `FridaHostProcessInfo` struct).
* **User/Programming Errors:** Look for potential pitfalls:
    * **Permissions:**  Failing to open a process handle due to insufficient privileges is a common issue.
    * **Buffer Overflows:** While the code uses `g_realloc`, incorrect sizing or assumptions about buffer sizes could lead to issues (though less likely with GLib).
    * **Resource Leaks:** Forgetting to `CloseHandle` is a classic Windows programming error.
* **User Path to This Code (Debugging):**  Trace the Frida workflow:
    1. User wants to interact with a process.
    2. Frida needs to know *which* process.
    3. This involves listing processes, often triggered by a command or API call.
    4. The Frida core then calls these system-level functions on the target OS.

**4. Structuring the Answer:**

Organize the findings clearly, addressing each point of the prompt systematically. Use bullet points, code snippets (where relevant), and clear explanations.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on every single static function.
* **Correction:** Prioritize the core functions that expose the main functionality. Briefly explain the helper functions but don't get bogged down in excessive detail for each one.
* **Initial thought:**  Just list the Windows APIs.
* **Correction:** Explain *why* those APIs are relevant in the context of Frida and reverse engineering. Connect the API calls to the high-level functionality.
* **Initial thought:** Overlook the "user path" question.
* **Correction:** Realize this is important for understanding the context and how this code fits into the larger Frida ecosystem. Think about the typical user interactions.

By following this structured approach, you can thoroughly analyze the code and address all aspects of the prompt effectively. The key is to understand the core purpose, dissect the logic function by function, and then connect the technical details to the broader context of reverse engineering, operating systems, and potential user issues.
这个C文件 `system-windows.c` 是 Frida 动态 instrumentation工具在 Windows 平台上的一个核心组件，主要负责与底层 Windows 系统进行交互，获取系统信息，例如进程列表、进程详细信息等。

下面我将根据你的要求，详细列举其功能，并结合逆向、二进制底层、Linux/Android 内核/框架知识、逻辑推理、用户错误以及调试线索进行说明。

**1. 功能列举:**

* **枚举进程 (`frida_system_enumerate_processes`):**  获取当前系统正在运行的所有进程的信息。这包括进程ID (PID)、进程名称、进程路径、父进程ID (PPID)、启动时间、用户等。它使用 Windows API `EnumProcesses` 来获取 PID 列表，然后遍历这些 PID 获取详细信息。
* **获取前台应用程序 (`frida_system_get_frontmost_application`):**  尝试获取当前用户正在交互的最前台应用程序的信息。但代码中此功能被标记为 "Not implemented"，说明在当前版本中，Frida for Windows 尚未实现此功能。
* **枚举应用程序 (`frida_system_enumerate_applications`):**  尝试获取系统中已安装的应用程序列表。同样，此功能在代码中返回 NULL，表明尚未实现。
* **终止进程 (`frida_system_kill`):**  根据给定的 PID 终止指定的进程。它使用 Windows API `OpenProcess` 获取进程句柄，然后调用 `TerminateProcess` 来结束进程。
* **获取系统临时目录 (`frida_temporary_directory_get_system_tmp`):**  获取操作系统的临时文件夹路径。它直接调用 glib 库的 `g_get_tmp_dir()` 函数。
* **收集进程信息 (`frida_collect_process_info`):**  这是一个内部辅助函数，用于根据给定的 PID 获取进程的详细信息，例如进程路径、用户、启动时间、图标等。
* **添加进程元数据 (`frida_add_process_metadata`):**  这是一个内部辅助函数，用于向进程信息中添加额外的元数据，例如父进程ID、用户、启动时间。
* **获取进程文件名 (`frida_get_process_filename`):**  根据进程句柄获取进程的可执行文件路径。它处理了从设备路径到驱动器字母的转换。
* **获取进程用户 (`frida_get_process_user`):**  根据进程句柄获取运行该进程的用户信息。它使用了 Windows API `OpenProcessToken` 和 `LookupAccountSidW`。
* **获取进程启动时间 (`frida_get_process_start_time`):**  根据进程句柄获取进程的启动时间。它使用了 Windows API `GetProcessTimes`。
* **构建 PPID 表 (`frida_build_ppid_table`):**  创建一个哈希表，存储进程 PID 和其父进程 PID 的映射关系。它使用了 Windows API `CreateToolhelp32Snapshot` 和 `Process32First/Next`。
* **获取前台进程 PID (`frida_get_frontmost_pid`):**  获取当前前台窗口所属的进程的 PID。它使用了 Windows API `GetForegroundWindow` 和 `GetWindowThreadProcessId`。
* **解析 FILETIME (`frida_parse_filetime`):**  将 Windows 的 `FILETIME` 结构转换为 `GDateTime` 对象。
* **FILETIME 转换为 Unix 时间戳 (`frida_filetime_to_unix`):**  将 Windows 的 `FILETIME` 结构转换为 Unix 时间戳（以微秒为单位）。

**2. 与逆向方法的关系及举例说明:**

该文件提供的功能是逆向分析的基础。逆向工程师经常需要了解目标系统的运行状态，包括正在运行的进程及其属性。

* **枚举进程 (`frida_system_enumerate_processes`):** 逆向工程师可以使用 Frida 连接到目标系统，并列出正在运行的进程，以便找到目标进程进行分析或注入代码。例如，他们可能会查找特定名称的进程，如 "target.exe"。
* **获取进程路径 (`frida_collect_process_info` -> `frida_get_process_filename`):**  了解目标进程的完整路径有助于确认是否为预期的程序，避免分析错误的进程。
* **获取进程用户 (`frida_collect_process_info` -> `frida_get_process_user`):**  在某些场景下，了解进程的运行用户可以帮助判断进程的权限级别以及潜在的安全风险。
* **终止进程 (`frida_system_kill`):**  在逆向调试过程中，可能需要反复启动和停止目标进程，`frida_system_kill` 提供了终止进程的能力。

**举例说明:**

假设逆向工程师想要分析一个名为 "suspicious.exe" 的进程。他们可以使用 Frida 的 Python API 调用 `frida.get_process_list()`，Frida 内部会调用 `frida_system_enumerate_processes` 获取进程列表，然后在列表中查找名称为 "suspicious.exe" 的进程。一旦找到，就可以获取其 PID 并进行后续操作，例如附加到该进程进行动态分析。

**3. 涉及二进制底层、Linux/Android 内核及框架的知识:**

* **二进制底层:** 该文件大量使用了 Windows API，这些 API 是与 Windows 内核进行交互的接口，涉及到操作系统的底层机制，例如进程管理、内存管理、安全机制等。例如，`OpenProcess` 操作的是进程对象在内核中的表示，`TerminateProcess` 直接调用内核函数来结束进程。`FILETIME` 结构是 Windows 用于表示时间的底层结构。
* **Linux/Android 内核及框架:**  虽然这个文件是 Windows 平台的代码，但理解 Linux/Android 的类似概念有助于更好地理解其功能：
    * **进程枚举:** 在 Linux 中，可以通过读取 `/proc` 文件系统来获取进程信息。Android 基于 Linux 内核，也有类似机制，并通过 `/proc` 或 `ProcessList` 等系统服务提供进程信息。
    * **进程终止:** Linux 使用 `kill` 系统调用，Android 中也有类似的机制。
    * **用户和权限:** Windows 和 Linux/Android 都有用户和权限的概念，但实现方式不同。Windows 使用 SID（安全标识符），而 Linux/Android 使用 UID（用户ID）和 GID（组ID）。
    * **进程启动时间:** 在 Linux 中，可以通过读取 `/proc/[pid]/stat` 文件获取进程的启动时间。

**4. 逻辑推理及假设输入与输出:**

* **函数：`frida_system_enumerate_processes`**
    * **假设输入:**  `FridaProcessQueryOptions` 对象，假设没有设置任何过滤条件（例如，不指定特定的 PID）。
    * **预期输出:**  一个 `FridaHostProcessInfo` 数组，包含当前系统中所有正在运行的进程的信息。每个 `FridaHostProcessInfo` 结构体至少包含 `pid` 和 `name` 字段，如果 `scope` 不是 `FRIDA_SCOPE_MINIMAL`，还会包含 `parameters` 哈希表，其中可能包含 "path" 等键值对。
* **函数：`frida_collect_process_info`**
    * **假设输入:**  一个进程的 PID，例如 `1234`，以及一个 `FridaEnumerateProcessesOperation` 结构体。
    * **预期输出:**  如果 PID 对应的进程存在且可以访问，`op->result` 数组中会添加一个 `FridaHostProcessInfo` 结构体，包含该进程的详细信息。
* **函数：`frida_get_process_filename`**
    * **假设输入:**  一个有效进程的句柄 `process`，一个用于存储文件名的 `WCHAR` 数组 `name`，以及数组的容量。
    * **预期输出:**  如果成功获取文件名，`name` 数组会被填充为进程的可执行文件路径，函数返回 `TRUE`。如果获取失败，返回 `FALSE`。

**5. 用户或编程常见的使用错误及举例说明:**

* **权限不足:**  Frida 运行时可能没有足够的权限来枚举所有进程或获取某些进程的详细信息。例如，如果 Frida 运行在普通用户权限下，可能无法获取系统关键进程的信息。这将导致 `OpenProcess` 等 API 调用失败，`handle` 为 `NULL`，从而跳过对该进程信息的收集。
* **错误的 PID:**  在调用 `frida_system_kill` 时，如果传入一个不存在的 PID，`OpenProcess` 会返回 `NULL`，导致终止进程的操作不会执行。虽然不会崩溃，但用户可能会误以为进程已被终止。
* **假设前台应用功能已实现:**  用户可能会尝试使用 Frida 的 API 获取前台应用程序信息，但由于 `frida_system_get_frontmost_application` 尚未实现，会导致错误或返回空结果。

**举例说明:**

用户尝试使用 Frida 连接到系统并列出所有进程：

```python
import frida

try:
    session = frida.attach("explorer.exe") # 尝试附加到 explorer.exe
    processes = frida.enumerate_processes()
    for process in processes:
        print(f"PID: {process.pid}, Name: {process.name}")
except frida.ProcessNotFoundError:
    print("explorer.exe not found.")
except Exception as e:
    print(f"An error occurred: {e}")
```

如果 Frida 运行时权限不足，某些进程可能不会出现在 `processes` 列表中，或者尝试获取某些进程的详细信息时可能会失败。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

当用户使用 Frida 与 Windows 系统进行交互时，其操作会逐步触发调用到 `system-windows.c` 中的函数。以下是一些场景：

1. **列出进程:**
   * 用户在 Frida 客户端（例如 Python 脚本或 Frida CLI）调用 `frida.enumerate_processes()`。
   * Frida 的核心逻辑会判断目标是本地系统，并调用 `frida_system_enumerate_processes()` (在 `frida-core` 库中)。
   * `frida_system_enumerate_processes()` 内部使用 Windows API `EnumProcesses` 获取 PID 列表。
   * 对于每个 PID，会调用 `frida_collect_process_info()` 获取详细信息。
   * `frida_collect_process_info()` 可能会调用 `frida_get_process_filename()`, `frida_add_process_metadata()` 等辅助函数。
   * `frida_add_process_metadata()` 可能会调用 `frida_build_ppid_table()`, `frida_get_process_user()`, `frida_get_process_start_time()`。
   * 这些函数内部又会调用相应的 Windows API，例如 `OpenProcess`, `GetProcessImageFileNameW`, `OpenProcessToken`, `LookupAccountSidW`, `GetProcessTimes` 等。

2. **附加到进程:**
   * 用户调用 `frida.attach(process_name_or_pid)` 或 `frida.get_usb_device().attach(process_name_or_pid)`。
   * Frida 需要验证目标进程是否存在，可能会先调用类似进程枚举的功能来查找目标进程。

3. **终止进程:**
   * 用户调用 Frida 提供的终止进程的 API，例如通过远程会话操作。
   * Frida 的核心逻辑会调用 `frida_system_kill(pid)`。
   * `frida_system_kill()` 内部使用 `OpenProcess(PROCESS_TERMINATE, ...)` 和 `TerminateProcess()`。

**调试线索:**

如果在使用 Frida 的过程中遇到问题，例如无法列出某些进程，或者无法附加到目标进程，可以从以下方面进行调试：

* **Frida 运行权限:** 确保 Frida 进程具有足够的权限来执行所需的操作。以管理员权限运行 Frida 脚本或 CLI。
* **目标进程状态:** 确认目标进程是否正在运行，并且 Frida 可以访问它。
* **反病毒软件干扰:** 某些反病毒软件可能会阻止 Frida 的操作。尝试禁用或配置反病毒软件。
* **Frida 版本兼容性:** 确保 Frida 客户端和 Frida 服务端的版本兼容。
* **查看 Frida 日志:** Frida 通常会输出详细的日志信息，可以帮助诊断问题。
* **逐步调试 Frida 源码:** 如果是 Frida 开发人员或需要深入了解其工作原理，可以逐步调试 `system-windows.c` 中的代码，查看 Windows API 的调用结果和参数，以定位问题所在。

总而言之，`frida/subprojects/frida-core/src/windows/system-windows.c` 是 Frida 在 Windows 平台上实现系统交互的关键模块，为 Frida 的各种功能提供了基础的系统信息获取和进程管理能力，这些能力对于动态 instrumentation 和逆向工程至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-core/src/windows/system-windows.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#include "frida-core.h"

#include "icon-helpers.h"

#include <psapi.h>
#include <tlhelp32.h>

#define DRIVE_STRINGS_MAX_LENGTH     (512)

typedef struct _FridaEnumerateProcessesOperation FridaEnumerateProcessesOperation;

struct _FridaEnumerateProcessesOperation
{
  FridaScope scope;
  GHashTable * ppid_by_pid;
  guint frontmost_pid;

  GArray * result;
};

static void frida_collect_process_info (guint pid, FridaEnumerateProcessesOperation * op);
static gboolean frida_add_process_metadata (GHashTable * parameters, guint pid, HANDLE process, FridaEnumerateProcessesOperation * op);

static gboolean frida_get_process_filename (HANDLE process, WCHAR * name, DWORD name_capacity);
static GVariant * frida_get_process_user (HANDLE process);
static GVariant * frida_get_process_start_time (HANDLE process);

static GHashTable * frida_build_ppid_table (void);
static guint frida_get_frontmost_pid (void);

static GDateTime * frida_parse_filetime (const FILETIME * ft);
static gint64 frida_filetime_to_unix (const FILETIME * ft);

void
frida_system_get_frontmost_application (FridaFrontmostQueryOptions * options, FridaHostApplicationInfo * result, GError ** error)
{
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not implemented");
}

FridaHostApplicationInfo *
frida_system_enumerate_applications (FridaApplicationQueryOptions * options, int * result_length)
{
  *result_length = 0;

  return NULL;
}

FridaHostProcessInfo *
frida_system_enumerate_processes (FridaProcessQueryOptions * options, int * result_length)
{
  FridaEnumerateProcessesOperation op;

  op.scope = frida_process_query_options_get_scope (options);
  op.ppid_by_pid = NULL;
  op.frontmost_pid = (op.scope != FRIDA_SCOPE_MINIMAL) ? frida_get_frontmost_pid () : 0;

  op.result = g_array_new (FALSE, FALSE, sizeof (FridaHostProcessInfo));

  if (frida_process_query_options_has_selected_pids (options))
  {
    frida_process_query_options_enumerate_selected_pids (options, (GFunc) frida_collect_process_info, &op);
  }
  else
  {
    DWORD * pids = NULL;
    DWORD size = 64 * sizeof (DWORD);
    DWORD bytes_returned;
    guint i;

    do
    {
      size *= 2;
      pids = g_realloc (pids, size);
      if (!EnumProcesses (pids, size, &bytes_returned))
        bytes_returned = 0;
    }
    while (bytes_returned == size);

    for (i = 0; i != bytes_returned / sizeof (DWORD); i++)
      frida_collect_process_info (pids[i], &op);

    g_free (pids);
  }

  g_clear_pointer (&op.ppid_by_pid, g_hash_table_unref);

  *result_length = op.result->len;

  return (FridaHostProcessInfo *) g_array_free (op.result, FALSE);
}

static void
frida_collect_process_info (guint pid, FridaEnumerateProcessesOperation * op)
{
  FridaHostProcessInfo info = { 0, };
  gboolean still_alive = TRUE;
  HANDLE handle;
  WCHAR program_path_utf16[MAX_PATH];
  gchar * program_path = NULL;

  handle = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, pid);
  if (handle == NULL)
    return;

  if (!frida_get_process_filename (handle, program_path_utf16, G_N_ELEMENTS (program_path_utf16)))
    goto beach;

  program_path = g_utf16_to_utf8 (program_path_utf16, -1, NULL, NULL, NULL);

  info.pid = pid;
  info.name = g_path_get_basename (program_path);

  info.parameters = frida_make_parameters_dict ();

  if (op->scope != FRIDA_SCOPE_MINIMAL)
  {
    g_hash_table_insert (info.parameters, g_strdup ("path"),
        g_variant_ref_sink (g_variant_new_take_string (g_steal_pointer (&program_path))));

    still_alive = frida_add_process_metadata (info.parameters, pid, handle, op);

    if (pid == op->frontmost_pid)
      g_hash_table_insert (info.parameters, g_strdup ("frontmost"), g_variant_ref_sink (g_variant_new_boolean (TRUE)));
  }

  if (op->scope == FRIDA_SCOPE_FULL)
  {
    GVariantBuilder builder;
    GVariant * small_icon, * large_icon;

    g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

    small_icon = _frida_icon_from_process_or_file (pid, program_path_utf16, FRIDA_ICON_SMALL);
    if (small_icon != NULL)
    {
      g_variant_builder_add_value (&builder, small_icon);
      g_variant_unref (small_icon);
    }

    large_icon = _frida_icon_from_process_or_file (pid, program_path_utf16, FRIDA_ICON_LARGE);
    if (large_icon != NULL)
    {
      g_variant_builder_add_value (&builder, large_icon);
      g_variant_unref (large_icon);
    }

    g_hash_table_insert (info.parameters, g_strdup ("icons"), g_variant_ref_sink (g_variant_builder_end (&builder)));

    still_alive = small_icon != NULL && large_icon != NULL;
  }

  if (still_alive)
    g_array_append_val (op->result, info);
  else
    frida_host_process_info_destroy (&info);

beach:
  g_free (program_path);
  CloseHandle (handle);
}

void
frida_system_kill (guint pid)
{
  HANDLE process;

  process = OpenProcess (PROCESS_TERMINATE, FALSE, pid);
  if (process != NULL)
  {
    TerminateProcess (process, 0xdeadbeef);
    CloseHandle (process);
  }
}

gchar *
frida_temporary_directory_get_system_tmp (void)
{
  return g_strdup (g_get_tmp_dir ());
}

static gboolean
frida_add_process_metadata (GHashTable * parameters, guint pid, HANDLE process, FridaEnumerateProcessesOperation * op)
{
  GVariant * user;
  guint ppid;
  GVariant * started;

  user = frida_get_process_user (process);
  if (user == NULL)
    return FALSE;
  g_hash_table_insert (parameters, g_strdup ("user"), g_variant_ref_sink (user));

  if (op->ppid_by_pid == NULL)
    op->ppid_by_pid = frida_build_ppid_table ();
  ppid = GPOINTER_TO_UINT (g_hash_table_lookup (op->ppid_by_pid, GUINT_TO_POINTER (pid)));
  if (ppid == 0)
    return FALSE;
  g_hash_table_insert (parameters, g_strdup ("ppid"), g_variant_ref_sink (g_variant_new_int64 (ppid)));

  started = frida_get_process_start_time (process);
  if (started == NULL)
    return FALSE;
  g_hash_table_insert (parameters, g_strdup ("started"), g_variant_ref_sink (started));

  return TRUE;
}

static gboolean
frida_get_process_filename (HANDLE process, WCHAR * name, DWORD name_capacity)
{
  gsize name_length;
  WCHAR drive_strings[DRIVE_STRINGS_MAX_LENGTH];
  WCHAR *drive;

  if (GetProcessImageFileNameW (process, name, name_capacity) == 0)
    return FALSE;
  name_length = wcslen (name);

  drive_strings[0] = L'\0';
  drive_strings[DRIVE_STRINGS_MAX_LENGTH - 1] = L'\0';
  GetLogicalDriveStringsW (DRIVE_STRINGS_MAX_LENGTH - 1, drive_strings);
  for (drive = drive_strings; *drive != '\0'; drive += wcslen (drive) + 1)
  {
    WCHAR device_name[3];
    WCHAR mapping_strings[MAX_PATH];
    WCHAR * mapping;
    gsize mapping_length;

    wcsncpy (device_name, drive, 2);
    device_name[2] = L'\0';

    mapping_strings[0] = '\0';
    mapping_strings[MAX_PATH - 1] = '\0';
    QueryDosDeviceW (device_name, mapping_strings, MAX_PATH - 1);
    for (mapping = mapping_strings; *mapping != '\0'; mapping += mapping_length + 1)
    {
      mapping_length = wcslen (mapping);

      if (mapping_length > name_length)
        continue;

      if (wcsncmp (name, mapping, mapping_length) == 0)
      {
        wcsncpy (name, device_name, 2);
        memmove (name + 2, name + mapping_length, (name_length - mapping_length + 1) * sizeof (WCHAR));
        return TRUE;
      }
    }
  }

  return FALSE;
}

static GVariant *
frida_get_process_user (HANDLE process)
{
  GVariant * result = NULL;
  HANDLE token;
  TOKEN_USER * user = NULL;
  DWORD user_size;
  WCHAR * name = NULL;
  DWORD name_length;
  WCHAR * domain_name = NULL;
  DWORD domain_name_length;
  SID_NAME_USE name_use;

  if (!OpenProcessToken (process, TOKEN_QUERY, &token))
    return NULL;

  user_size = 64;
  user = g_malloc (user_size);

  if (!GetTokenInformation (token, TokenUser, user, user_size, &user_size))
  {
    if (GetLastError () != ERROR_INSUFFICIENT_BUFFER)
      goto beach;

    user = g_realloc (user, user_size);

    if (!GetTokenInformation (token, TokenUser, user, user_size, &user_size))
      goto beach;
  }

  name_length = 64;
  name = g_malloc (name_length * sizeof (WCHAR));

  domain_name_length = 64;
  domain_name = g_malloc (domain_name_length * sizeof (WCHAR));

  if (!LookupAccountSidW (NULL, user->User.Sid, name, &name_length, domain_name, &domain_name_length, &name_use))
  {
    if (GetLastError () != ERROR_INSUFFICIENT_BUFFER)
      goto beach;

    name = g_realloc (name, name_length * sizeof (WCHAR));
    domain_name = g_realloc (domain_name, domain_name_length * sizeof (WCHAR));

    if (!LookupAccountSidW (NULL, user->User.Sid, name, &name_length, domain_name, &domain_name_length, &name_use))
      goto beach;
  }

  result = g_variant_new_take_string (g_utf16_to_utf8 (name, -1, NULL, NULL, NULL));

beach:
  g_free (domain_name);
  g_free (name);
  g_free (user);
  CloseHandle (token);

  return result;
}

static GVariant *
frida_get_process_start_time (HANDLE process)
{
  GVariant * result;
  FILETIME creation_time, exit_time, kernel_time, user_time;
  GDateTime * creation_dt;

  if (!GetProcessTimes (process, &creation_time, &exit_time, &kernel_time, &user_time))
    return NULL;

  creation_dt = frida_parse_filetime (&creation_time);
  result = g_variant_new_take_string (g_date_time_format_iso8601 (creation_dt));
  g_date_time_unref (creation_dt);

  return result;
}

static GHashTable *
frida_build_ppid_table (void)
{
  GHashTable * result = NULL;
  HANDLE snapshot;
  PROCESSENTRY32 entry;

  snapshot = CreateToolhelp32Snapshot (TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    goto beach;

  entry.dwSize = sizeof (entry);

  if (!Process32First (snapshot, &entry))
    goto beach;

  result = g_hash_table_new (NULL, NULL);

  do
  {
    g_hash_table_insert (result, GUINT_TO_POINTER (entry.th32ProcessID), GUINT_TO_POINTER (entry.th32ParentProcessID));
  }
  while (Process32Next (snapshot, &entry));

beach:
  if (snapshot != INVALID_HANDLE_VALUE)
    CloseHandle (snapshot);

  return result;
}

static guint
frida_get_frontmost_pid (void)
{
  DWORD pid;
  HWND window;

  window = GetForegroundWindow ();
  if (window == NULL)
    return 0;

  pid = 0;
  GetWindowThreadProcessId (window, &pid);

  return pid;
}

static GDateTime *
frida_parse_filetime (const FILETIME * ft)
{
  GDateTime * result;
  gint64 unix_time, unix_sec, unix_usec;
  GDateTime * dt;

  unix_time = frida_filetime_to_unix (ft);

  unix_sec = unix_time / G_USEC_PER_SEC;
  unix_usec = unix_time % G_USEC_PER_SEC;

  dt = g_date_time_new_from_unix_utc (unix_sec);
  result = g_date_time_add (dt, unix_usec);
  g_date_time_unref (dt);

  return result;
}

static gint64
frida_filetime_to_unix (const FILETIME * ft)
{
  ULARGE_INTEGER u;

  u.LowPart = ft->dwLowDateTime;
  u.HighPart = ft->dwHighDateTime;

  return (u.QuadPart - G_GUINT64_CONSTANT (116444736000000000)) / 10;
}
```