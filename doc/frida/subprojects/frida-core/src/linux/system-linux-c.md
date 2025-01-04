Response:
Let's break down the thought process for analyzing the provided C code. The goal is to extract its functionality, relate it to reverse engineering, identify low-level concepts, analyze logic, and pinpoint potential user errors.

**1. Initial Skim and Keyword Spotting:**

The first step is a quick read-through to get a general idea of the code's purpose. Keywords like `Frida`, `process`, `enumerate`, `system`, `/proc`, `pid`, `kill`, `tmp`, `mount`, and `uid` jump out. This immediately suggests the code is related to system-level operations, particularly process management, likely within the context of Frida.

**2. Function-by-Function Analysis:**

The next step is to examine each function individually.

* **`frida_system_get_frontmost_application`:**  The comment "Not implemented" is a key piece of information. This function is a placeholder.

* **`frida_system_enumerate_applications`:** Similarly, the function returns `NULL` and sets `result_length` to 0. It's unimplemented.

* **`frida_system_enumerate_processes`:** This looks important. It iterates through `/proc`, reads process IDs, and calls `frida_collect_process_info`. The `FridaScope` suggests different levels of detail might be gathered. The conditional check for `frida_process_query_options_has_selected_pids` indicates it can either enumerate all processes or specific ones.

* **`frida_collect_process_info`:**  This function gathers information for a specific process. It reads `/proc/[pid]/exe`, `/proc/[pid]/cmdline`, and then calls `frida_add_process_metadata`. It extracts the process name and potentially other parameters. The `goto beach` pattern handles cleanup.

* **`frida_system_kill`:** This is straightforward: it uses the `kill` system call to terminate a process.

* **`frida_temporary_directory_get_system_tmp`:** This function determines a suitable temporary directory. It checks for Android (and uses a specific path if running as root), then checks the standard temporary directory and whether it's mounted `noexec`. If `noexec`, it falls back to the application directory.

* **`frida_is_directory_noexec`:** This function uses `g_unix_mount_for` to get mount information and checks if the "noexec" option is present.

* **`frida_get_application_directory`:**  This uses `gum_process_get_main_module()` to find the directory where the Frida component is running.

* **`frida_add_process_metadata`:** This function reads `/proc/[pid]/status` and `/proc/[pid]/stat` to gather more detailed process information, like UID, PPID, and start time. It uses `frida_uid_to_name` and `frida_query_boot_time`.

* **`frida_query_boot_time`:**  This reads `/proc/stat` to find the "btime" value, representing the boot time.

* **`frida_uid_to_name`:** This function uses `getpwuid_r` to look up the username associated with a UID.

**3. Relating to Reverse Engineering:**

Think about how a reverse engineer might use these functionalities.

* **Process Enumeration:** Essential for identifying target processes to attach to.
* **Process Information:**  Knowing the path, command line, parent process, and user helps in understanding the target process.
* **Killing Processes:** Useful for terminating processes after analysis or in controlled testing.
* **Temporary Directory:** Frida needs to place its agent library somewhere the target process can load it. Understanding how this location is determined is important for debugging and security analysis.

**4. Identifying Low-Level Concepts:**

Focus on the interactions with the operating system.

* **`/proc` filesystem:** The heavy reliance on `/proc` for process information is a key Linux concept. Explain what `/proc` is and how it works.
* **System Calls:**  Mention `kill`, `sysconf`, and potentially `getpwuid_r` as direct interactions with the kernel.
* **File System Concepts:**  Discuss mount points and the `noexec` option.
* **User IDs (UIDs):** Explain their role in Linux security.
* **Process IDs (PIDs):**  Fundamental to process management.
* **Jiffies and Boot Time:** Explain how the kernel tracks time.

**5. Logical Reasoning and Assumptions:**

Consider the inputs and outputs of functions.

* **`frida_system_enumerate_processes`:** Input is `FridaProcessQueryOptions` (which can specify PIDs or a scope). Output is an array of `FridaHostProcessInfo`. Assume that reading `/proc` might fail if permissions are incorrect, leading to incomplete information.
* **`frida_temporary_directory_get_system_tmp`:** Input is the system state (UID, mount points). Output is a path string. The logic for `noexec` involves a decision based on mount information.

**6. Common User Errors:**

Think about how a programmer using Frida might misuse these functions or encounter issues.

* **Permissions:**  Not having the necessary permissions to read `/proc` or access temporary directories.
* **Incorrect PID:**  Providing an invalid PID to `frida_system_kill`.
* **Assumptions about temporary directory:**  Assuming the temporary directory is always writable and executable.

**7. Tracing User Operations (Debugging Clues):**

Imagine a scenario where a user wants to attach Frida to a process.

1. User starts a Frida client (e.g., Python script).
2. The client calls a Frida API to list processes.
3. This API call might eventually lead to `frida_system_enumerate_processes` being executed on the target system where Frida is running.
4. The code in this file is then responsible for gathering the process information that is sent back to the client.

Or, if the user wants to spawn a process with Frida:

1. Frida needs a place to put its agent library.
2. `frida_temporary_directory_get_system_tmp` is called to determine this location.

**8. Structuring the Answer:**

Finally, organize the information logically using the categories requested in the prompt (functionality, reverse engineering relevance, low-level details, logic, user errors, debugging). Use clear language and provide specific examples. The goal is to demonstrate a thorough understanding of the code's purpose and its context within the Frida framework.
好的，让我们详细分析一下 `frida/subprojects/frida-core/src/linux/system-linux.c` 这个文件。

**文件功能概述:**

这个文件是 Frida 动态 instrumentation 工具在 Linux 平台上实现系统级别操作的核心部分。它提供了一组函数，用于获取和操作系统信息，特别是与进程和应用程序相关的操作。其主要功能包括：

1. **枚举进程:** 获取系统中正在运行的进程列表及其详细信息。
2. **获取前台应用程序 (未实现):**  虽然定义了函数，但目前在 Linux 上未实现获取前台应用程序的功能。
3. **枚举应用程序 (未实现):** 同样，枚举应用程序的功能目前也未实现。
4. **终止进程:**  通过进程 ID 强制终止指定的进程。
5. **获取临时目录:**  获取系统上的临时目录，并考虑 `noexec` 挂载选项，以确保 Frida 代理可以正常加载。
6. **辅助功能:**  提供了一些辅助函数，用于读取 `/proc` 文件系统中的信息，如进程状态、启动时间、用户 ID 映射到用户名等。

**与逆向方法的关系及举例说明:**

Frida 本身就是一个强大的逆向工程工具，而这个文件中的功能直接支持了 Frida 的核心逆向操作：

* **进程枚举是逆向分析的第一步:** 在进行动态分析时，逆向工程师首先需要找到目标进程。`frida_system_enumerate_processes` 提供了这个功能，允许用户列出所有正在运行的进程，并通过进程名或 PID 来定位目标。
    * **举例:** 逆向工程师想要分析一个名为 `target_app` 的进程。他们可以使用 Frida 客户端（如 Python API）调用 `frida.get_process_list()`，Frida 内部会调用到这个文件中的 `frida_system_enumerate_processes` 函数，遍历 `/proc` 目录，最终在返回的进程列表中找到 `target_app` 的信息（包括 PID）。
* **获取进程信息有助于理解目标:**  通过 `frida_collect_process_info` 和 `frida_add_process_metadata`，可以获取进程的路径、命令行参数、父进程 ID、启动时间、所属用户等信息。这些信息对于理解目标进程的运行环境和行为至关重要。
    * **举例:**  逆向工程师发现一个可疑进程，想知道它的启动方式。通过 Frida 获取该进程的详细信息，可以得到它的命令行参数，从而了解它是否带有恶意参数或者是由哪个父进程启动的。
* **终止进程用于实验控制:** 在某些逆向场景下，需要控制目标进程的生命周期。`frida_system_kill` 允许逆向工程师强制终止目标进程，以便重新启动或停止分析。
    * **举例:**  逆向工程师在调试一个崩溃的程序，可能需要在崩溃后立即终止该进程，然后重新以调试模式启动，以便更精确地定位崩溃原因。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明:**

这个文件深入地使用了 Linux 操作系统底层的概念和机制：

* **`/proc` 文件系统:**  代码大量使用了 `/proc` 文件系统来获取进程信息。`/proc` 是 Linux 内核提供的一个虚拟文件系统，它以文件的形式暴露了内核和进程的运行时信息。
    * **举例:**  `frida_collect_process_info` 函数通过读取 `/proc/[pid]/exe` 获取进程的可执行文件路径，读取 `/proc/[pid]/cmdline` 获取进程的命令行参数，读取 `/proc/[pid]/status` 和 `/proc/[pid]/stat` 获取进程的状态信息、父进程 ID 和启动时间等。这些都是直接与 Linux 内核交互的方式。
* **系统调用:** `frida_system_kill` 函数直接调用了 `kill` 系统调用来发送信号终止进程。系统调用是用户空间程序与内核交互的唯一方式。
    * **举例:** 当 Frida 客户端请求终止一个进程时，最终会通过 `frida_system_kill` 函数调用 `kill(pid, SIGKILL)`，这是一个底层的操作系统操作。
* **用户和权限:**  `frida_temporary_directory_get_system_tmp` 函数中使用了 `getuid()` 来获取当前用户的 ID，并根据是否为 root 用户来选择临时目录。这涉及到 Linux 的用户权限管理机制。
    * **举例:** 在 Android 系统中，如果 Frida 作为 root 用户运行，它可能会选择 `/data/local/tmp` 作为临时目录。
* **文件系统挂载选项:** `frida_is_directory_noexec` 函数检查目录是否以 `noexec` 选项挂载。这涉及到 Linux 文件系统的挂载和权限控制。`noexec` 选项禁止在文件系统上执行程序，这会影响 Frida 代理的加载。
    * **举例:** 如果系统的 `/tmp` 目录以 `noexec` 挂载，Frida 就不能直接在 `/tmp` 中创建并执行 agent 库，需要寻找其他可执行的临时目录。
* **时间和启动:** `frida_add_process_metadata` 和 `frida_query_boot_time` 函数涉及获取进程启动时间和系统启动时间，这与 Linux 内核维护的时间信息相关。
    * **举例:**  代码通过读取 `/proc/stat` 中的 `btime` 获取系统启动时间，并结合 `/proc/[pid]/stat` 中的 `starttime` 计算进程的启动时间。
* **用户 ID 映射:** `frida_uid_to_name` 函数使用 `getpwuid_r` 函数将用户 ID 转换为用户名。这是 Linux 系统中用户管理的一部分。
    * **举例:** 在进程信息中，通常会显示进程的 UID，但为了方便用户理解，Frida 会将其转换为用户名。

**逻辑推理及假设输入与输出:**

让我们以 `frida_system_enumerate_processes` 函数为例进行逻辑推理：

**假设输入:**

1. **`options` 参数:** 一个 `FridaProcessQueryOptions` 对象。
    * **情况 1:** `options` 未指定特定的 PID，需要枚举所有进程。
    * **情况 2:** `options` 指定了一个或多个特定的 PID。

**逻辑推理:**

* **情况 1 (枚举所有进程):**
    1. 打开 `/proc` 目录。
    2. 循环读取 `/proc` 目录下的所有条目。
    3. 对于每个条目，尝试将其转换为数字（PID）。
    4. 如果成功转换为 PID，则调用 `frida_collect_process_info` 函数来收集该进程的详细信息。
    5. 将收集到的进程信息添加到结果数组 `op.result` 中。
    6. 关闭 `/proc` 目录。
    7. 返回结果数组。

* **情况 2 (枚举特定 PID):**
    1. 直接遍历 `options` 中指定的 PID 列表。
    2. 对于每个 PID，调用 `frida_collect_process_info` 函数来收集该进程的详细信息。
    3. 将收集到的进程信息添加到结果数组 `op.result` 中。
    4. 返回结果数组。

**假设输出:**

* **情况 1:**  一个包含系统中所有正在运行进程信息的 `FridaHostProcessInfo` 数组。每个元素包含进程的 PID、名称以及其他元数据（取决于 `options` 中指定的 scope）。
* **情况 2:** 一个包含指定 PID 的进程信息的 `FridaHostProcessInfo` 数组。如果某些指定的 PID 对应的进程不存在，则不会包含在输出中。

**`frida_collect_process_info` 函数的假设输入与输出:**

**假设输入:**

1. **`pid`:** 一个有效的进程 ID。
2. **`op`:**  一个 `FridaEnumerateProcessesOperation` 结构体，用于存储结果。

**逻辑推理:**

1. 构建 `/proc/[pid]/exe` 路径，检查文件是否存在，判断是否为用户态进程。
2. 读取 `/proc/[pid]/exe` 的符号链接，获取程序路径。
3. 读取 `/proc/[pid]/cmdline` 获取命令行参数。
4. 根据命令行参数和程序路径推断进程名称。
5. 如果 `op->scope` 不是 `FRIDA_SCOPE_MINIMAL`，则调用 `frida_add_process_metadata` 获取更多信息。
6. 将收集到的进程信息添加到 `op->result` 数组。

**假设输出:**

一个 `FridaHostProcessInfo` 结构体，包含指定 PID 进程的以下信息：

* `pid`: 进程 ID
* `name`: 进程名称
* `parameters`: 一个哈希表，包含进程的其他元数据，例如 "path" (程序路径), "ppid" (父进程 ID), "user" (用户名), "started" (启动时间) 等。

**涉及用户或者编程常见的使用错误及举例说明:**

* **权限不足:** 用户运行 Frida 的进程没有足够的权限读取 `/proc` 下的目标进程信息。
    * **举例:**  如果用户尝试枚举属于其他用户的进程，或者尝试获取 root 进程的详细信息，可能会因为权限不足而失败，导致部分信息缺失或整个操作失败。
* **目标进程不存在:**  用户尝试操作一个不存在的 PID。
    * **举例:**  用户手动输入了一个错误的 PID 给 `frida_system_kill` 函数，导致 `kill` 系统调用失败。
* **临时目录不可用:** 用户环境的临时目录被设置为 `noexec`，导致 Frida 无法加载 agent 库。
    * **举例:**  某些安全加固的 Linux 系统可能会将 `/tmp` 挂载为 `noexec`，如果 Frida 尝试在那里创建 agent 库，将会失败。用户可能会看到类似 "Permission denied" 的错误。
* **假设前台应用程序功能已实现:**  用户可能会错误地认为 `frida_system_get_frontmost_application` 可以正常工作，但实际上在 Linux 上它并未实现。
    * **举例:**  用户编写 Frida 脚本尝试获取前台应用信息，但该函数总是返回一个 "Not implemented" 的错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

以下是一些可能导致代码执行的典型 Frida 用户操作：

1. **列出进程:**
   * 用户在 Frida 客户端（例如 Python）中调用 `frida.get_process_list()` 或 `frida.enumerate_devices()`（后者也会列出进程）。
   * Frida 客户端通过 RPC (Remote Procedure Call) 将请求发送到 Frida 服务端。
   * Frida 服务端接收到请求，并调用 `frida-core` 库中的相应函数，最终会调用到 `frida_system_enumerate_processes`。

2. **附加到指定进程:**
   * 用户在 Frida 客户端中使用 `frida.attach(pid)` 或 `frida.attach(process_name)` 来附加到一个正在运行的进程。
   * 为了验证 PID 或找到进程的 PID，Frida 内部可能会先调用进程枚举功能 (`frida_system_enumerate_processes`)。

3. **Spawn 新进程并注入:**
   * 用户在 Frida 客户端中使用 `frida.spawn(program)` 来启动一个新的进程并注入 Frida。
   * 在 spawn 过程中，Frida 需要确定一个合适的临时目录来存放 agent 库，这会调用 `frida_temporary_directory_get_system_tmp`。

4. **使用 `Process.kill()` API:**
   * 用户在 Frida 客户端中获取到一个 `Process` 对象后，调用其 `kill()` 方法。
   * 这会导致 Frida 客户端向服务端发送终止进程的请求，服务端最终会调用 `frida_system_kill` 函数。

**调试线索:**

如果用户在使用 Frida 时遇到问题，例如无法列出进程、无法附加到进程、或者注入失败，那么可以沿着这些调用链进行调试：

* **检查 Frida 客户端的日志:** 查看客户端是否报错，以及发送了哪些请求。
* **检查 Frida 服务端的日志:**  查看服务端是否接收到请求，以及执行了哪些操作。
* **使用 GDB 等调试器附加到 Frida 服务端进程:**  可以设置断点在 `frida_system_enumerate_processes`、`frida_collect_process_info`、`frida_system_kill`、`frida_temporary_directory_get_system_tmp` 等函数上，查看参数和执行流程，判断问题出在哪里。
* **检查目标系统的 `/proc` 文件系统:**  确认 `/proc` 是否正常工作，以及目标进程的信息是否可以读取。
* **检查文件系统权限:**  确认 Frida 运行的用户是否有权限访问 `/proc` 和临时目录。

总而言之，`system-linux.c` 文件是 Frida 在 Linux 平台上进行系统级操作的关键组件，它直接 взаимодействует with the operating system kernel to provide essential functionalities for dynamic instrumentation and reverse engineering. 深入理解其实现有助于我们更好地使用 Frida 并排查相关问题。

Prompt: 
```
这是目录为frida/subprojects/frida-core/src/linux/system-linux.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "frida-core.h"

#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include <gio/gunixmounts.h>

typedef struct _FridaEnumerateProcessesOperation FridaEnumerateProcessesOperation;

struct _FridaEnumerateProcessesOperation
{
  FridaScope scope;
  GArray * result;
};

static void frida_collect_process_info (guint pid, FridaEnumerateProcessesOperation * op);
static gboolean frida_is_directory_noexec (const gchar * directory);
static gchar * frida_get_application_directory (void);
static gboolean frida_add_process_metadata (GHashTable * parameters, const gchar * proc_entry_name);
static GDateTime * frida_query_boot_time (void);
static GVariant * frida_uid_to_name (uid_t uid);

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
  op.result = g_array_new (FALSE, FALSE, sizeof (FridaHostProcessInfo));

  if (frida_process_query_options_has_selected_pids (options))
  {
    frida_process_query_options_enumerate_selected_pids (options, (GFunc) frida_collect_process_info, &op);
  }
  else
  {
    GDir * proc_dir;
    const gchar * proc_name;

    proc_dir = g_dir_open ("/proc", 0, NULL);

    while ((proc_name = g_dir_read_name (proc_dir)) != NULL)
    {
      guint pid;
      gchar * end;

      pid = strtoul (proc_name, &end, 10);
      if (*end == '\0')
        frida_collect_process_info (pid, &op);
    }

    g_dir_close (proc_dir);
  }

  *result_length = op.result->len;

  return (FridaHostProcessInfo *) g_array_free (op.result, FALSE);
}

static void
frida_collect_process_info (guint pid, FridaEnumerateProcessesOperation * op)
{
  FridaHostProcessInfo info = { 0, };
  gboolean still_alive = TRUE;
  gchar * proc_name = NULL;
  gchar * exe_path = NULL;
  gboolean is_userland;
  gchar * program_path = NULL;
  gchar * cmdline_path = NULL;
  gchar * cmdline_data = NULL;
  gchar * name = NULL;

  proc_name = g_strdup_printf ("%u", pid);

  exe_path = g_build_filename ("/proc", proc_name, "exe", NULL);

  is_userland = g_file_test (exe_path, G_FILE_TEST_EXISTS);
  if (!is_userland)
    goto beach;

  program_path = g_file_read_link (exe_path, NULL);

  cmdline_path = g_build_filename ("/proc", proc_name, "cmdline", NULL);

  g_file_get_contents (cmdline_path, &cmdline_data, NULL, NULL);
  if (cmdline_data == NULL)
    goto beach;

  if (g_str_has_prefix (cmdline_data, "/proc/"))
  {
    name = g_path_get_basename (program_path);
  }
  else
  {
    gchar * space_dash;

    space_dash = strstr (cmdline_data, " -");
    if (space_dash != NULL)
      *space_dash = '\0';

    name = g_path_get_basename (cmdline_data);
  }

  info.pid = pid;
  info.name = g_steal_pointer (&name);

  info.parameters = frida_make_parameters_dict ();

  if (op->scope != FRIDA_SCOPE_MINIMAL)
  {
    g_hash_table_insert (info.parameters, g_strdup ("path"),
        g_variant_ref_sink (g_variant_new_take_string (g_steal_pointer (&program_path))));

    still_alive = frida_add_process_metadata (info.parameters, proc_name);
  }

  if (still_alive)
    g_array_append_val (op->result, info);
  else
    frida_host_process_info_destroy (&info);

beach:
  g_free (name);
  g_free (cmdline_data);
  g_free (cmdline_path);
  g_free (program_path);
  g_free (exe_path);
  g_free (proc_name);
}

void
frida_system_kill (guint pid)
{
  kill (pid, SIGKILL);
}

gchar *
frida_temporary_directory_get_system_tmp (void)
{
  const gchar * tmp_dir;

#ifdef HAVE_ANDROID
  if (getuid () == 0)
    return g_strdup ("/data/local/tmp");
#endif

  tmp_dir = g_get_tmp_dir ();

  /*
   * If the temporary directory resides on a file-system which is marked
   * `noexec`, then we won't be able to write the frida-agent.so there and
   * subsequently dlopen() it inside the target application as it will result in
   * permission denied.
   *
   * The mounting of the temporary file-system as `noexec` is sometimes used as
   * an added security measure on embedded systems where the functionality is
   * fixed and we aren't expecting any interactive user sessions.
   *
   * Since our current process is executing, we know that it must reside on a
   * file-system which is not mounted `noexec`. Whilst it is possible that it is
   * mounted read-only, or there may be some other reason why it isn't suitable,
   * we know that the temporary directory is definitely unusable. If both these
   * locations are found to be unsuitable, then a future implementation may seek
   * to validate an ordered list of potential locations.
   */
  if (frida_is_directory_noexec (tmp_dir))
    return frida_get_application_directory ();
  else
    return g_strdup (tmp_dir);
}

static gboolean
frida_is_directory_noexec (const gchar * directory)
{
  gboolean is_noexec;
  g_autoptr(GUnixMountEntry) entry;
  gchar ** options;

  entry = g_unix_mount_for (directory, NULL);
  if (entry == NULL)
    return FALSE;

  options = g_strsplit (g_unix_mount_get_options (entry), ",", 0);
  is_noexec = g_strv_contains ((const char * const *) options, "noexec");
  g_strfreev (options);

  return is_noexec;
}

static gchar *
frida_get_application_directory (void)
{
  return g_path_get_dirname (gum_process_get_main_module ()->path);
}

static gboolean
frida_add_process_metadata (GHashTable * parameters, const gchar * proc_entry_name)
{
  gboolean success = FALSE;
  gchar * status_path = NULL;
  gchar * status_data = NULL;
  gchar ** status_lines = NULL;
  gchar ** cursor;
  gchar * stat_path = NULL;
  gchar * stat_data = NULL;
  int ppid;
  guint64 start_time_delta_in_jiffies;
  static gsize caches_initialized = 0;
  static GDateTime * boot_time = NULL;
  static long usec_per_jiffy = 0;
  GDateTime * started;

  status_path = g_build_filename ("/proc", proc_entry_name, "status", NULL);
  if (!g_file_get_contents (status_path, &status_data, NULL, NULL))
    goto beach;

  status_lines = g_strsplit (status_data, "\n", 0);
  for (cursor = status_lines; *cursor != NULL; cursor++)
  {
    const gchar * line = *cursor;

    if (g_str_has_prefix (line, "Uid:"))
    {
      uid_t uid;

      sscanf (line + 4, "%*u %u %*u %*u", &uid);

      g_hash_table_insert (parameters, g_strdup ("user"), frida_uid_to_name (uid));

      break;
    }
  }

  stat_path = g_build_filename ("/proc", proc_entry_name, "stat", NULL);
  if (!g_file_get_contents (stat_path, &stat_data, NULL, NULL))
    goto beach;

  sscanf (stat_data,
      "%*d "                       /* ( 1) pid         */
      "(%*[^)]) "                  /* ( 2) comm        */
      "%*c "                       /* ( 3) state       */
      "%d "                        /* ( 4) ppid        */
      "%*d "                       /* ( 5) pgrp        */
      "%*d "                       /* ( 6) session     */
      "%*d "                       /* ( 7) tty_nr      */
      "%*d "                       /* ( 8) tpgid       */
      "%*u "                       /* ( 9) flags       */
      "%*u "                       /* (10) minflt      */
      "%*u "                       /* (11) cminflt     */
      "%*u "                       /* (12) majflt      */
      "%*u "                       /* (13) cmajflt     */
      "%*u "                       /* (14) utime       */
      "%*u "                       /* (15) stime       */
      "%*d "                       /* (16) cutime      */
      "%*d "                       /* (17) cstime      */
      "%*d "                       /* (18) priority    */
      "%*d "                       /* (19) nice        */
      "%*d "                       /* (20) num_threads */
      "%*d "                       /* (21) itrealvalue */
      "%" G_GINT64_MODIFIER "u ",  /* (22) starttime   */
      &ppid,
      &start_time_delta_in_jiffies);

  g_hash_table_insert (parameters, g_strdup ("ppid"), g_variant_ref_sink (g_variant_new_int64 (ppid)));

  if (g_once_init_enter (&caches_initialized))
  {
    boot_time = frida_query_boot_time ();
    usec_per_jiffy = G_USEC_PER_SEC / sysconf (_SC_CLK_TCK);

    g_once_init_leave (&caches_initialized, TRUE);
  }

  started = g_date_time_add (boot_time, start_time_delta_in_jiffies * usec_per_jiffy);
  g_hash_table_insert (parameters, g_strdup ("started"),
      g_variant_ref_sink (g_variant_new_take_string (g_date_time_format_iso8601 (started))));
  g_date_time_unref (started);

  success = TRUE;

beach:
  g_free (stat_data);
  g_free (stat_path);
  g_strfreev (status_lines);
  g_free (status_data);
  g_free (status_path);

  return success;
}

static GDateTime *
frida_query_boot_time (void)
{
  GDateTime * boot_time = NULL;
  gchar * data = NULL;
  gchar ** lines, ** cursor;

  g_file_get_contents ("/proc/stat", &data, NULL, NULL);
  g_assert (data != NULL);

  lines = g_strsplit (data, "\n", 0);

  for (cursor = lines; *cursor != NULL; cursor++)
  {
    const gchar * line = *cursor;

    if (g_str_has_prefix (line, "btime "))
    {
      gint64 unix_utc_time;

      g_ascii_string_to_signed (line + 6, 10, G_MININT64, G_MAXINT64, &unix_utc_time, NULL);

      boot_time = g_date_time_new_from_unix_utc (unix_utc_time);

      break;
    }
  }
  g_assert (boot_time != NULL);

  g_strfreev (lines);
  g_free (data);

  return boot_time;
}

static GVariant *
frida_uid_to_name (uid_t uid)
{
  GVariant * name;
  static size_t buffer_size = 0;
  char * buffer;
  struct passwd pwd, * entry;

  if (buffer_size == 0)
    buffer_size = sysconf (_SC_GETPW_R_SIZE_MAX);

  buffer = g_malloc (buffer_size);

  entry = NULL;
  getpwuid_r (uid, &pwd, buffer, buffer_size, &entry);

  if (entry != NULL)
    name = g_variant_new_string (entry->pw_name);
  else
    name = g_variant_new_take_string (g_strdup_printf ("%u", uid));
  name = g_variant_ref_sink (name);

  g_free (buffer);

  return name;
}

"""

```