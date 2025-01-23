Response:
Let's break down the thought process to analyze this C code for Frida.

**1. Understanding the Goal:**

The request asks for the functionality of the `windows-host-session-glue.c` file within Frida, specifically focusing on its relation to reverse engineering, binary/kernel interactions, logical reasoning, potential user errors, and debugging context.

**2. Initial Code Scan & Keyword Spotting:**

The first step is to quickly scan the code for recognizable patterns and keywords. This helps to identify the main areas of functionality. Keywords like:

* `CreateProcessW`, `DebugActiveProcessStop`, `ResumeThread`: Indicate process creation and control.
* `CreatePipe`, `GetStdHandle`: Suggest interaction with standard input/output/error streams.
* `SHGetDesktopFolder`, `SHGetFileInfoW`: Point to icon extraction functionality.
* `g_utf8_to_utf16`, `frida_argv_to_command_line`, `frida_envp_to_environment_block`:  Deal with string and environment variable manipulation.
* `OpenProcess`, `WaitForSingleObject`: Relate to checking process status.
* `g_child_watch_add_full`:  Indicates monitoring child processes.

**3. Function-by-Function Analysis:**

Next, examine each function individually to understand its purpose and how it contributes to the overall goal.

* **`_frida_windows_host_session_provider_try_extract_icon`**:  The name is self-explanatory. It uses Windows Shell APIs to find and extract the "My Computer" icon. This is likely used for UI representation within Frida.

* **`_frida_windows_host_session_spawn`**: This is a core function. The parameters (`path`, `options`) and the use of `CreateProcessW` immediately suggest it's responsible for spawning new processes on Windows. The logic around `FRIDA_STDIO_INHERIT` and `FRIDA_STDIO_PIPE` handles different ways of managing standard streams. The use of `CREATE_SUSPENDED`, `DEBUG_PROCESS`, and `DEBUG_ONLY_THIS_PROCESS` is a strong indicator of its relevance to dynamic instrumentation.

* **`_frida_windows_host_session_process_is_alive`**:  Uses `OpenProcess` and `WaitForSingleObject` to determine if a process with a given PID is still running. This is essential for Frida to track target processes.

* **`frida_child_process_close`**:  Handles cleanup when a child process is no longer needed, releasing resources like handles.

* **`frida_child_process_resume`**: Resumes the execution of a suspended child process. This is crucial for allowing the target application to run after Frida has attached or spawned it.

* **`frida_child_process_on_death`**: A callback function triggered when a child process terminates. It notifies the parent Frida session.

* **`frida_argv_to_command_line`**:  Converts an array of command-line arguments into a single string suitable for `CreateProcessW`. The complex quoting logic is important for handling arguments with spaces or special characters correctly.

* **`frida_envp_to_environment_block`**:  Formats environment variables into a block of memory required by `CreateProcessW`.

* **`frida_append_n_backslashes`**: A helper function for the command-line quoting logic.

* **`frida_make_pipe`**: Creates anonymous pipes for redirecting standard input/output/error.

* **`frida_ensure_not_inherited`**: Prevents child processes from inheriting handles, which is important for controlling the communication channels.

**4. Connecting to the Request's Specific Points:**

Now, revisit the original request and connect the analyzed functionality to each point:

* **Functionality Listing:** Summarize the purpose of each key function.

* **Relationship to Reverse Engineering:** Focus on functions like `_frida_windows_host_session_spawn` and how its flags (`CREATE_SUSPENDED`, `DEBUG_PROCESS`) are directly related to attaching debuggers and instrumenting code. Give examples like modifying memory after the process is spawned in a suspended state.

* **Binary/Kernel/OS Knowledge:** Highlight Windows-specific APIs like `CreateProcessW`, handle management (`HANDLE`), and the differences between `STDIO_INHERIT` and `STDIO_PIPE`. Mention the interaction with the Windows process model.

* **Logical Reasoning:**  Look for conditional logic and decision points. For example, the quoting logic in `frida_argv_to_command_line` is a good example of a set of rules to follow. Formulate hypothetical inputs and outputs to illustrate the function's behavior.

* **User/Programming Errors:** Consider common mistakes developers make when using process creation APIs, such as incorrect command-line formatting or not handling standard streams properly. Relate these to potential issues when using Frida if these low-level details are not managed correctly by the Frida framework.

* **Debugging Clues/User Journey:**  Trace how a user action (e.g., running `frida.spawn()`) would eventually lead to the execution of functions in this file. Emphasize the role of this code as the low-level interface for interacting with the Windows operating system.

**5. Structuring the Answer:**

Organize the findings into a clear and structured answer, using headings and bullet points to improve readability. Provide concrete examples to illustrate the concepts.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file just spawns processes."
* **Correction:**  "It does more than just spawn. It also handles standard streams, manages process lifecycle (resuming, closing), and extracts icons. The `DEBUG_PROCESS` flag is a key aspect related to Frida's core functionality."

* **Initial thought:**  "The quoting logic is just a detail."
* **Correction:** "The quoting logic is crucial for correctness. Incorrect quoting can lead to the target application receiving incorrect arguments, which is a potential user error when constructing Frida scripts."

By following these steps, combining code analysis with an understanding of the request's specific points, and iteratively refining the understanding, we arrive at a comprehensive and informative answer.
这个 `frida/subprojects/frida-core/src/windows/windows-host-session-glue.c` 文件是 Frida 动态Instrumentation工具在 Windows 平台上的一个核心组成部分，它负责处理与宿主系统（运行 Frida 脚本的机器）会话相关的底层操作，特别是与进程的创建、管理以及标准输入输出重定向相关的任务。

以下是该文件的功能列表，并结合逆向、二进制底层、Linux/Android知识、逻辑推理、用户错误以及调试线索进行详细说明：

**主要功能:**

1. **启动新进程 (`_frida_windows_host_session_spawn`)**:
   - 这是该文件最重要的功能之一。它负责在 Windows 上启动一个新的进程。
   - 允许指定要执行的可执行文件路径 (`path`)。
   - 接收 `FridaHostSpawnOptions` 结构体，该结构体包含启动进程所需的各种选项，例如命令行参数 (`argv`)、环境变量 (`envp` 或 `env`)、当前工作目录 (`cwd`) 以及标准输入输出的处理方式 (`stdio`)。
   - 使用 Windows API `CreateProcessW` 来创建进程。
   - **与逆向的关系**: 这是 Frida 能够动态分析程序的基础。逆向工程师可以使用 Frida 脚本来启动目标程序，并在程序运行时进行监控、修改其行为。
   - **二进制底层知识**:  `CreateProcessW` 是 Windows API 中用于创建进程的关键函数，涉及 PE 文件加载、进程空间分配、线程创建等底层操作。参数如 `CREATE_SUSPENDED`、`DEBUG_PROCESS` 等直接控制了进程创建的底层行为。
   - **Linux/Android知识**:  与 Linux 的 `fork`/`exec` 或 Android 的 `Runtime.exec` 类似，但 Windows 使用不同的 API 和概念。理解这些跨平台差异有助于理解 Frida 如何在不同操作系统上实现类似的功能。
   - **逻辑推理**:  根据 `FridaHostSpawnOptions` 的不同配置，`_frida_windows_host_session_spawn` 会执行不同的代码路径，例如处理不同的标准输入输出模式。
     - **假设输入**:  `path` 为 "C:\\Windows\\System32\\notepad.exe"，`options->stdio` 为 `FRIDA_STDIO_PIPE`。
     - **输出**:  启动 `notepad.exe` 进程，并且创建管道用于重定向其标准输入、输出和错误流。
   - **用户错误**:  常见的用户错误包括提供的 `path` 不存在或不可执行，提供的命令行参数或环境变量格式不正确。
   - **调试线索**: 当 Frida 尝试启动新进程失败时，会调用 `GetLastError()` 获取错误代码，这对于诊断启动失败的原因至关重要。例如，`ERROR_BAD_EXE_FORMAT` 表示可执行文件格式不正确。

2. **提取 "我的电脑" 图标 (`_frida_windows_host_session_provider_try_extract_icon`)**:
   - 此功能尝试从 Windows Shell 中提取 "我的电脑" 图标。
   - 使用 COM 接口 (`IShellFolder`, `IEnumIDList`) 和 Shell API (`SHGetDesktopFolder`, `SHGetFileInfoW`) 来完成。
   - **与逆向的关系**:  这与逆向分析目标程序本身的关系不大，但可能用于 Frida 的 UI 或其他辅助功能，提供更友好的用户体验。例如，在 Frida 的进程列表中显示图标。
   - **二进制底层知识**: 涉及到 Windows Shell 命名空间和 COM 对象的交互，这些都是 Windows 底层架构的一部分。
   - **用户操作如何到达这里**:  Frida 初始化或需要显示连接目标的信息时，可能会调用此函数来获取代表宿主系统的图标。

3. **检查进程是否存活 (`_frida_windows_host_session_process_is_alive`)**:
   - 接收一个进程 ID (`pid`) 作为参数。
   - 使用 `OpenProcess` 尝试打开该进程，并使用 `WaitForSingleObject` 以非阻塞方式检查进程是否仍然运行。
   - **与逆向的关系**: Frida 需要监控目标进程的生命周期，以便在进程退出时进行清理或其他操作。
   - **二进制底层知识**: `OpenProcess` 和 `WaitForSingleObject` 是 Windows 内核对象操作的 API。
   - **逻辑推理**:
     - **假设输入**: 一个正在运行的进程的 PID。
     - **输出**: `TRUE`。
     - **假设输入**: 一个已经退出的进程的 PID。
     - **输出**: `FALSE`。
   - **用户操作如何到达这里**:  Frida 定期检查已附加或创建的进程是否仍在运行。

4. **关闭子进程 (`frida_child_process_close`)**:
   - 清理与子进程相关的资源，例如关闭进程句柄和主线程句柄。
   - **与逆向的关系**:  在 Frida 脚本执行完毕或用户断开连接时，需要清理不再需要的进程资源。
   - **二进制底层知识**:  `CloseHandle` 用于释放操作系统资源。

5. **恢复子进程执行 (`frida_child_process_resume`)**:
   - 接收一个 `FridaChildProcess` 对象作为参数，该对象代表一个被 Frida 创建并可能处于挂起状态的子进程。
   - 调用 `ResumeThread` 来恢复进程主线程的执行。
   - **与逆向的关系**:  通常，Frida 在启动新进程时会将其置于挂起状态 (`CREATE_SUSPENDED`)，以便在目标代码执行之前进行注入或其他操作。`frida_child_process_resume` 用于在完成这些操作后让目标进程继续运行。
   - **二进制底层知识**: `ResumeThread` 是 Windows API 中控制线程执行的函数。
   - **用户错误**:  多次调用 `frida_child_process_resume` 会导致错误，因为线程已经处于运行状态。

6. **处理子进程死亡事件 (`frida_child_process_on_death`)**:
   - 这是一个回调函数，当由 `g_child_watch_add_full` 注册的子进程监视器检测到进程死亡时被调用。
   - 它通知 Frida 宿主会话管理器 (`_frida_windows_host_session_on_child_dead`)。
   - **与逆向的关系**:  允许 Frida 在目标进程退出时执行清理或通知用户。

7. **将命令行参数转换为命令行字符串 (`frida_argv_to_command_line`)**:
   - 接收一个字符串数组形式的命令行参数 (`argv`)。
   - 将其转换为 `CreateProcessW` 函数所需的单个命令行字符串，并处理参数中的引号和反斜杠等特殊字符。
   - **与逆向的关系**:  确保传递给目标进程的命令行参数是正确的。
   - **逻辑推理**:  函数内部包含了复杂的逻辑来处理各种可能的命令行参数组合，特别是包含空格和引号的情况。例如，如果参数包含空格，则需要用引号括起来。如果参数本身包含引号，则需要进行转义。
     - **假设输入**: `argv` 为 `{"notepad", "test file.txt"}`。
     - **输出**: `L"notepad \"test file.txt\""`。
   - **用户错误**:  如果用户在 Frida 脚本中提供的参数格式不正确，可能会导致生成的命令行字符串错误，从而影响目标程序的行为。

8. **将环境变量转换为环境变量块 (`frida_envp_to_environment_block`)**:
   - 接收一个字符串数组形式的环境变量 (`envp`)。
   - 将其转换为 `CreateProcessW` 函数所需的以 NULL 结尾的字符串块。
   - **与逆向的关系**:  允许 Frida 在启动目标进程时设置特定的环境变量。
   - **二进制底层知识**:  Windows 使用特定的格式来存储进程的环境变量。

9. **辅助函数 (`frida_append_n_backslashes`, `frida_make_pipe`, `frida_ensure_not_inherited`)**:
   - `frida_append_n_backslashes`:  用于在构建命令行字符串时添加指定数量的反斜杠，主要用于处理引号转义。
   - `frida_make_pipe`:  创建匿名管道，用于重定向子进程的标准输入、输出和错误流。
   - `frida_ensure_not_inherited`:  确保指定的句柄不会被子进程继承，这对于控制子进程的访问权限很重要。
   - **与逆向的关系**:  管道的创建和句柄继承的控制对于 Frida 与目标进程之间的通信至关重要。Frida 可以通过管道向目标进程发送数据或接收其输出。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在 Frida 脚本中调用 `frida.spawn(target, options=...)`**: 这是启动新进程的最常见方式。
2. **Frida 的 Python 绑定会将此调用传递给 Frida Core**:  Frida Core 是用 C 编写的。
3. **Frida Core 的主机会话管理器接收到 spawn 请求**: 在 Windows 上，这将涉及到 `frida-core/src/windows/windows-host-session.c` 中的代码。
4. **`frida-core/src/windows/windows-host-session.c` 会调用 `_frida_windows_host_session_spawn`**:  这个函数是 `windows-host-session-glue.c` 中定义的。
5. **`_frida_windows_host_session_spawn` 内部**:
   - 根据 `options` 中的 `argv` 和 `envp`，分别调用 `frida_argv_to_command_line` 和 `frida_envp_to_environment_block` 来格式化命令行参数和环境变量。
   - 如果 `options->stdio` 设置为 `FRIDA_STDIO_PIPE`，则会调用 `frida_make_pipe` 创建管道。
   - 调用 Windows API `CreateProcessW` 来创建进程。
   - 如果创建成功，根据 `options->stdio` 的设置，关联相应的管道或继承标准流。
   - 如果设置了 `CREATE_SUSPENDED`，则进程会暂停执行，等待 Frida 的进一步操作（例如注入代码）。
   - 使用 `g_child_watch_add_full` 注册子进程死亡事件的监听器。
   - 返回一个 `FridaChildProcess` 对象，该对象封装了新创建的进程的信息。

**总结**:

`windows-host-session-glue.c` 文件是 Frida 在 Windows 平台上与操作系统进行交互的关键桥梁，特别是负责进程的创建和管理。它深入到 Windows 的底层 API，处理了进程启动的各种细节，包括命令行参数、环境变量和标准输入输出的配置。理解这个文件的功能对于理解 Frida 如何在 Windows 上工作以及如何调试 Frida 脚本与目标进程的交互至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-core/src/windows/windows-host-session-glue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#define COBJMACROS 1

#include "frida-core.h"

#include "icon-helpers.h"

#include <gio/gwin32inputstream.h>
#include <gio/gwin32outputstream.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shobjidl.h>
#include <string.h>
#include <unknwn.h>

#define PARSE_STRING_MAX_LENGTH   (40 + 1)

static void frida_child_process_on_death (GPid pid, gint status, gpointer user_data);

static WCHAR * frida_argv_to_command_line (gchar ** argv, gint argv_length);
static WCHAR * frida_envp_to_environment_block (gchar ** envp, gint envp_length);

static void frida_append_n_backslashes (GString * str, guint n);

static void frida_make_pipe (HANDLE * read, HANDLE * write);
static void frida_ensure_not_inherited (HANDLE handle);

GVariant *
_frida_windows_host_session_provider_try_extract_icon (void)
{
  GVariant * result = NULL;
  OLECHAR my_computer_parse_string[PARSE_STRING_MAX_LENGTH];
  IShellFolder * desktop_folder = NULL;
  IEnumIDList * children = NULL;
  ITEMIDLIST * child;

  wcscpy (my_computer_parse_string, L"::");
  StringFromGUID2 (&CLSID_MyComputer, my_computer_parse_string + 2, PARSE_STRING_MAX_LENGTH - 2);

  if (SHGetDesktopFolder (&desktop_folder) != S_OK)
    goto beach;

  if (IShellFolder_EnumObjects (desktop_folder, NULL, SHCONTF_FOLDERS, &children) != S_OK)
    goto beach;

  while (result == NULL && IEnumIDList_Next (children, 1, &child, NULL) == S_OK)
  {
    STRRET display_name_value;
    WCHAR display_name[MAX_PATH];
    SHFILEINFOW file_info = { 0, };

    if (IShellFolder_GetDisplayNameOf (desktop_folder, child, SHGDN_FORPARSING, &display_name_value) != S_OK)
      goto next_child;
    StrRetToBufW (&display_name_value, child, display_name, MAX_PATH);

    if (_wcsicmp (display_name, my_computer_parse_string) != 0)
      goto next_child;

    if (SHGetFileInfoW ((LPCWSTR) child, 0, &file_info, sizeof (file_info), SHGFI_PIDL | SHGFI_ICON | SHGFI_SMALLICON | SHGFI_ADDOVERLAYS) == 0)
      goto next_child;

    result = _frida_icon_from_native_icon_handle (file_info.hIcon, FRIDA_ICON_SMALL);

    DestroyIcon (file_info.hIcon);

next_child:
    CoTaskMemFree (child);
  }

beach:
  if (children != NULL)
    IUnknown_Release (children);
  if (desktop_folder != NULL)
    IUnknown_Release (desktop_folder);

  return result;
}

FridaChildProcess *
_frida_windows_host_session_spawn (FridaWindowsHostSession * self, const gchar * path, FridaHostSpawnOptions * options, GError ** error)
{
  FridaChildProcess * process = NULL;
  WCHAR * application_name, * command_line, * environment, * current_directory;
  STARTUPINFOW startup_info;
  HANDLE stdin_read = NULL, stdin_write = NULL;
  HANDLE stdout_read = NULL, stdout_write = NULL;
  HANDLE stderr_read = NULL, stderr_write = NULL;
  PROCESS_INFORMATION process_info;
  FridaStdioPipes * pipes;
  guint watch_id;
  GSource * watch;

  application_name = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);

  if (options->has_argv)
    command_line = frida_argv_to_command_line (options->argv, options->argv_length1);
  else
    command_line = NULL;

  if (options->has_envp || options->has_env)
  {
    gchar ** envp;
    gint envp_length;

    envp = frida_host_spawn_options_compute_envp (options, &envp_length);
    environment = frida_envp_to_environment_block (envp, envp_length);
    g_strfreev (envp);
  }
  else
  {
    environment = NULL;
  }

  if (strlen (options->cwd) > 0)
    current_directory = (WCHAR *) g_utf8_to_utf16 (options->cwd, -1, NULL, NULL, NULL);
  else
    current_directory = NULL;

  ZeroMemory (&startup_info, sizeof (startup_info));
  startup_info.cb = sizeof (startup_info);

  switch (options->stdio)
  {
    case FRIDA_STDIO_INHERIT:
      startup_info.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
      startup_info.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
      startup_info.hStdError = GetStdHandle (STD_ERROR_HANDLE);
      startup_info.dwFlags = STARTF_USESTDHANDLES;

      break;

    case FRIDA_STDIO_PIPE:
      frida_make_pipe (&stdin_read, &stdin_write);
      frida_make_pipe (&stdout_read, &stdout_write);
      frida_make_pipe (&stderr_read, &stderr_write);

      frida_ensure_not_inherited (stdin_write);
      frida_ensure_not_inherited (stdout_read);
      frida_ensure_not_inherited (stderr_read);

      startup_info.hStdInput = stdin_read;
      startup_info.hStdOutput = stdout_write;
      startup_info.hStdError = stderr_write;
      startup_info.dwFlags = STARTF_USESTDHANDLES;

      break;

    default:
      g_assert_not_reached ();
  }

  if (!CreateProcessW (
      application_name,
      command_line,
      NULL,
      NULL,
      TRUE,
      CREATE_SUSPENDED |
      CREATE_UNICODE_ENVIRONMENT |
      CREATE_NEW_PROCESS_GROUP |
      DEBUG_PROCESS |
      DEBUG_ONLY_THIS_PROCESS,
      environment,
      current_directory,
      &startup_info,
      &process_info))
  {
    goto create_process_failed;
  }

  DebugActiveProcessStop (process_info.dwProcessId);

  if (options->stdio == FRIDA_STDIO_PIPE)
  {
    CloseHandle (stdin_read);
    CloseHandle (stdout_write);
    CloseHandle (stderr_write);

    pipes = frida_stdio_pipes_new (
        g_win32_output_stream_new (stdin_write, TRUE),
        g_win32_input_stream_new (stdout_read, TRUE),
        g_win32_input_stream_new (stderr_read, TRUE));
  }
  else
  {
    pipes = NULL;
  }

  process = frida_child_process_new (
      G_OBJECT (self),
      process_info.dwProcessId,
      process_info.hProcess,
      process_info.hThread,
      pipes);

  watch_id = g_child_watch_add_full (
      G_PRIORITY_DEFAULT,
      process_info.hProcess,
      frida_child_process_on_death,
      g_object_ref (process),
      g_object_unref);
  watch = g_main_context_find_source_by_id (g_main_context_get_thread_default (), watch_id);
  g_assert (watch != NULL);
  frida_child_process_set_watch (process, watch);

  goto beach;

create_process_failed:
  {
    DWORD last_error;

    last_error = GetLastError ();
    if (last_error == ERROR_BAD_EXE_FORMAT)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED,
          "Unable to spawn executable at '%s': unsupported file format",
          path);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unable to spawn executable at '%s': 0x%08lx",
          path, last_error);
    }

    if (options->stdio == FRIDA_STDIO_PIPE)
    {
      CloseHandle (stdin_read);
      CloseHandle (stdin_write);

      CloseHandle (stdout_read);
      CloseHandle (stdout_write);

      CloseHandle (stderr_read);
      CloseHandle (stderr_write);
    }

    goto beach;
  }
beach:
  {
    g_free (current_directory);
    g_free (environment);
    g_free (command_line);
    g_free (application_name);

    return process;
  }
}

gboolean
_frida_windows_host_session_process_is_alive (guint pid)
{
  HANDLE process;
  DWORD res;

  process = OpenProcess (SYNCHRONIZE, FALSE, pid);
  if (process == NULL)
    return GetLastError () == ERROR_ACCESS_DENIED;

  res = WaitForSingleObject (process, 0);

  CloseHandle (process);

  return res == WAIT_TIMEOUT;
}

void
frida_child_process_close (FridaChildProcess * self)
{
  GSource * watch;

  if (self->closed)
    return;

  watch = frida_child_process_get_watch (self);
  if (watch != NULL)
    g_source_destroy (watch);

  CloseHandle (frida_child_process_get_handle (self));
  CloseHandle (frida_child_process_get_main_thread (self));

  self->closed = TRUE;
}

void
frida_child_process_resume (FridaChildProcess * self, GError ** error)
{
  if (self->resumed)
    goto already_resumed;

  ResumeThread (frida_child_process_get_main_thread (self));

  self->resumed = TRUE;
  return;

already_resumed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_OPERATION,
        "Already resumed");
  }
}

static void
frida_child_process_on_death (GPid pid, gint status, gpointer user_data)
{
  FridaChildProcess * self = user_data;

  (void) pid;

  _frida_windows_host_session_on_child_dead (
      FRIDA_WINDOWS_HOST_SESSION (frida_child_process_get_parent (self)),
      self,
      status);
}

static WCHAR *
frida_argv_to_command_line (gchar ** argv, gint argv_length)
{
  GString * line;
  WCHAR * line_utf16;
  gint i;

  line = g_string_new ("");

  for (i = 0; i != argv_length; i++)
  {
    const gchar * arg = argv[i];
    gboolean no_quotes_needed;

    if (i > 0)
      g_string_append_c (line, ' ');

    no_quotes_needed = arg[0] != '\0' &&
        g_utf8_strchr (arg, -1, ' ') == NULL &&
        g_utf8_strchr (arg, -1, '\t') == NULL &&
        g_utf8_strchr (arg, -1, '\n') == NULL &&
        g_utf8_strchr (arg, -1, '\v') == NULL &&
        g_utf8_strchr (arg, -1, '"') == NULL;
    if (no_quotes_needed)
    {
      g_string_append (line, arg);
    }
    else
    {
      const gchar * c;

      g_string_append_c (line, '"');

      for (c = arg; *c != '\0'; c = g_utf8_next_char (c))
      {
        guint num_backslashes = 0;

        while (*c != '\0' && *c == '\\')
        {
          num_backslashes++;
          c++;
        }

        if (*c == '\0')
        {
          frida_append_n_backslashes (line, num_backslashes * 2);
          break;
        }
        else if (*c == '"')
        {
          frida_append_n_backslashes (line, (num_backslashes * 2) + 1);
          g_string_append_c (line, *c);
        }
        else
        {
          frida_append_n_backslashes (line, num_backslashes);
          g_string_append_unichar (line, g_utf8_get_char (c));
        }
      }

      g_string_append_c (line, '"');
    }
  }

  line_utf16 = (WCHAR *) g_utf8_to_utf16 (line->str, -1, NULL, NULL, NULL);

  g_string_free (line, TRUE);

  return line_utf16;
}

static WCHAR *
frida_envp_to_environment_block (gchar ** envp, gint envp_length)
{
  GString * block;

  block = g_string_new ("");

  if (envp_length > 0)
  {
    gint i;

    for (i = 0; i != envp_length; i++)
    {
      gunichar2 * var;
      glong items_written;

      var = g_utf8_to_utf16 (envp[i], -1, NULL, &items_written, NULL);
      g_string_append_len (block, (gchar *) var, (items_written + 1) * sizeof (gunichar2));
      g_free (var);
    }
  }
  else
  {
    g_string_append_c (block, '\0');
    g_string_append_c (block, '\0');
  }

  g_string_append_c (block, '\0');
  g_string_append_c (block, '\0');

  return (WCHAR *) g_string_free (block, FALSE);
}

static void
frida_append_n_backslashes (GString * str, guint n)
{
  guint i;

  for (i = 0; i != n; i++)
    g_string_append_c (str, '\\');
}

static void
frida_make_pipe (HANDLE * read, HANDLE * write)
{
  SECURITY_ATTRIBUTES attributes;
  DWORD default_buffer_size = 0;
  G_GNUC_UNUSED BOOL pipe_created;

  attributes.nLength = sizeof (attributes);
  attributes.bInheritHandle = TRUE;
  attributes.lpSecurityDescriptor = NULL;

  pipe_created = CreatePipe (read, write, &attributes, default_buffer_size);
  g_assert (pipe_created);
}

static void
frida_ensure_not_inherited (HANDLE handle)
{
  G_GNUC_UNUSED BOOL inherit_flag_updated;

  inherit_flag_updated = SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0);
  g_assert (inherit_flag_updated);
}
```