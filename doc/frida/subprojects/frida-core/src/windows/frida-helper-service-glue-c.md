Response:
Let's break down the thought process to analyze the `frida-helper-service-glue.c` file and answer the prompt's questions.

**1. Initial Understanding - The Big Picture:**

The filename itself gives a strong hint: "frida-helper-service-glue". The "glue" part suggests this code acts as an intermediary or connection point between different components. Combined with "service", it likely manages the lifecycle of helper processes or services. The `frida` prefix indicates it's part of the Frida instrumentation toolkit. The location in `frida/subprojects/frida-core/src/windows/` confirms it's Windows-specific and core to Frida's functionality.

**2. Core Functionality Identification (Reading the Code Top-Down):**

* **Includes:**  `<windows.h>` is a dead giveaway for Windows API usage. The `frida-helper-service-glue.h` suggests a header file with declarations relevant to this source file.
* **Architecture Detection:** The `#if defined ... #endif` block defines `FRIDA_HELPER_SERVICE_ARCH`, clearly indicating it dynamically determines the system's architecture (x86, x86_64, arm64). This is crucial for deploying the correct helper executable.
* **`FridaServiceContext`:** This struct is central. It holds the service basename, the service control manager handle (`scm`), and two queues: `system_services` and `standalone_services`. This strongly implies it manages two types of helper processes.
* **Function Declarations:**  Scanning the function declarations provides a high-level overview of what the code *does*. Keywords like "register", "start", "stop", "unregister", "spawn", "join", "kill" point towards service management. The "standalone" prefix suggests a distinction in how these services are launched and managed.
* **`frida_helper_manager_start_services` and `frida_helper_manager_stop_services`:** These are likely the main entry points for starting and stopping the helper services. The `FridaPrivilegeLevel` parameter in `start_services` hints at different execution contexts.
* **Filename/Servicename Derivation:** Functions like `frida_helper_service_derive_basename`, `derive_filename_for_suffix`, and `derive_svcname_for_self/suffix` suggest the code programmatically constructs the names of helper executables and Windows services.
* **Service Control Manager Interaction:**  Functions using `OpenSCManager`, `CreateServiceW`, `StartService`, `ControlService`, `DeleteService`, `EnumServicesStatusExW`, `QueryServiceConfigW` clearly interact with the Windows Service Control Manager API.
* **Standalone Process Management:** Functions like `frida_spawn_standalone_service`, `join_standalone_service`, `kill_standalone_service` use standard Windows process creation and management functions (`CreateProcessW`, `WaitForSingleObject`, `TerminateProcess`).
* **`frida_managed_helper_service_enter_dispatcher_and_main_loop`, `frida_managed_helper_service_main`, `frida_managed_helper_service_handle_control_code`:** This block implements the main logic for a *managed* Windows service, including handling control codes (like stop).
* **`frida_rmtree`:** This function suggests cleanup by recursively deleting directories, likely used when uninstalling stale services.

**3. Answering the Specific Questions:**

* **Functionality:** Based on the function names and their operations, I can list the core functionalities (registering, starting, stopping, unregistering services; spawning, joining, killing standalone processes; deriving filenames and service names; handling service control events).
* **Relationship to Reverse Engineering:** Frida is a dynamic instrumentation tool used extensively in reverse engineering. This code is responsible for setting up the helper processes that Frida uses to interact with target applications. The ability to inject code and inspect memory relies on these helper services running correctly.
* **Binary/OS/Kernel Knowledge:** The code directly uses Windows API functions for service management and process creation. This demonstrates knowledge of the Windows operating system's service architecture and process model. The architecture detection (`HAVE_ARM64`, `GLIB_SIZEOF_VOID_P`) shows awareness of different CPU architectures and their implications for binary compatibility.
* **Logical Reasoning (Hypothetical Input/Output):**  Consider the `frida_helper_manager_start_services` function. If `service_basename` is "my-frida-helper" and `archs` is ["x86", "x86_64"], and the privilege level is elevated, the function will attempt to register and start two Windows services named "my-frida-helper-x86" and "my-frida-helper-x86_64". If it fails, it will try spawning them as standalone processes.
* **User/Programming Errors:**  A common mistake is incorrect privilege levels. If a user tries to start services requiring elevated privileges without running Frida as administrator, service registration will fail. Another error might be missing or corrupted helper executables in the expected locations.
* **User Operations to Reach This Code (Debugging Context):**  A user wanting to connect Frida to a Windows process will trigger the Frida client to interact with the Frida server on the target machine. The server then needs to spawn the appropriate helper service for the target process's architecture. This code is executed during that helper service setup phase. Debugging scenarios might involve setting breakpoints in these functions to understand service registration or spawning failures.

**4. Refinement and Organization:**

After the initial analysis, I would organize the findings into the structured answer format requested by the prompt, providing clear explanations and examples for each point. I'd ensure the examples are concrete and easy to understand. For instance, for "reverse engineering," I'd explicitly mention code injection and memory inspection. For "binary level," I'd focus on the architecture-specific logic.

This structured approach, starting with a high-level understanding and then diving into the details of the code, helps in comprehensively analyzing the functionality and its relevance to the different aspects mentioned in the prompt.
好的，让我们来分析一下 `frida/subprojects/frida-core/src/windows/frida-helper-service-glue.c` 这个文件，它是 Frida 动态 instrumentation 工具在 Windows 平台上的一个核心组成部分，负责管理 Frida 的辅助服务进程。

**功能列举:**

该文件的主要功能是管理 Frida 在 Windows 系统上运行所需的辅助服务进程。这些辅助服务进程帮助 Frida 与目标进程进行交互和注入代码。具体来说，它负责：

1. **确定辅助服务的基础名称:**  通过 `frida_helper_service_derive_basename` 函数，根据当前 Frida 进程的文件名来生成辅助服务的基础名称（例如，如果 Frida 进程是 `frida-server.exe`，则基础名称可能是 `frida-server-`）。
2. **根据架构注册和启动系统服务:**  使用 Windows 服务控制管理器 (SCM) API，例如 `OpenSCManager`, `CreateServiceW`, `StartService`，来注册和启动不同架构（x86, x86_64, arm64）的 Frida 辅助服务。这些服务以 Windows 服务的形式运行，通常需要管理员权限。
3. **以独立进程的方式启动辅助服务:** 如果无法以系统服务的方式启动（例如，权限不足），则会使用 `CreateProcessW` 函数以独立进程的方式启动辅助服务。
4. **停止和注销系统服务:**  使用 SCM API，例如 `ControlService` 和 `DeleteService`，来停止和注销之前注册的 Frida 辅助服务。
5. **停止和清理独立的辅助服务进程:**  使用 `WaitForSingleObject` 等待独立进程结束，如果超时则使用 `TerminateProcess` 强制结束进程，并使用 `CloseHandle` 清理进程句柄。
6. **清理残留的旧版本辅助服务:**  通过 `frida_unregister_stale_services` 函数，枚举系统中已注册的类似 "frida-" 开头的服务，并尝试注销它们，同时删除相关的临时目录。
7. **管理辅助服务的生命周期:**  提供 `frida_helper_manager_start_services` 和 `frida_helper_manager_stop_services` 函数作为启动和停止辅助服务的统一入口点。
8. **处理托管的辅助服务进程:**  实现了 `frida_managed_helper_service_main` 函数，这是以 Windows 服务方式运行的 Frida 辅助服务的主函数，负责注册控制句柄并进入消息循环。
9. **处理服务控制代码:**  `frida_managed_helper_service_handle_control_code` 函数响应 SCM 发送的控制代码，例如停止服务。
10. **生成辅助服务的文件名和显示名称:**  通过 `frida_helper_service_derive_filename_for_suffix` 和相关函数，根据架构后缀生成辅助服务可执行文件的完整路径和显示名称。

**与逆向方法的关联:**

这个文件是 Frida 工具进行动态 instrumentation 的关键组成部分，与逆向方法紧密相关：

* **代码注入:** Frida 的核心功能之一是将 JavaScript 代码注入到目标进程中。 这些辅助服务进程充当了 Frida 服务器和目标进程之间的桥梁，帮助 Frida 完成代码注入操作。
* **内存访问和修改:**  通过辅助服务，Frida 能够读取和修改目标进程的内存，这是动态分析和逆向工程的重要手段。
* **函数 Hooking:** Frida 可以 hook 目标进程中的函数，拦截函数调用并修改其行为。辅助服务参与了 hook 的植入和管理过程。
* **动态分析:**  Frida 允许逆向工程师在程序运行时观察其行为，这依赖于 Frida 能够与目标进程进行实时的交互，而辅助服务为此提供了基础。

**举例说明:**

假设你要使用 Frida hook 一个 Windows 应用程序的 `MessageBoxW` 函数。

1. Frida 客户端 (例如，你的 Python 脚本) 会连接到目标机器上的 Frida 服务。
2. Frida 服务会根据目标进程的架构（例如，x86_64）调用 `frida_helper_manager_start_services` 来启动对应的辅助服务进程（例如，`frida-helper-64.exe`）。
3. `frida-helper-service-glue.c` 中的代码负责找到或创建这个辅助服务进程。如果需要，它会注册并启动一个新的 Windows 服务，或者以独立进程的方式运行它。
4. 辅助服务进程启动后，Frida 服务会指示它将 hook 代码注入到目标应用程序中。
5. 当目标应用程序调用 `MessageBoxW` 时，hook 代码会被触发，允许 Frida 执行你定义的 JavaScript 代码，例如打印消息框的参数。

**涉及二进制底层、Linux、Android 内核及框架的知识 (需要注意，此文件是 Windows 特有的):**

虽然这个文件是 Windows 平台的代码，但理解其功能也需要一些通用的系统和二进制知识：

* **二进制底层:**
    * **进程和线程:** 代码中涉及进程的创建 (`CreateProcessW`)、终止 (`TerminateProcess`) 和等待 (`WaitForSingleObject`)，这是操作系统进程管理的基础知识。
    * **内存管理:** 虽然此文件本身不直接操作目标进程内存，但它管理的辅助服务是进行内存读写操作的关键。理解进程地址空间的概念对于理解 Frida 的工作原理很重要。
    * **可执行文件格式 (PE):**  了解 Windows PE 文件的结构有助于理解辅助服务是如何被加载和执行的。
    * **调用约定:**  虽然代码中没有直接体现，但 Frida 进行函数 hook 时需要理解不同架构下的调用约定。
* **Windows 内核及框架:**
    * **Windows 服务控制管理器 (SCM):** 代码大量使用了 SCM API，需要理解 Windows 服务的架构、状态转换、注册和启动流程。
    * **Windows API:**  代码广泛使用了 Windows API 函数，例如用于文件操作、进程管理、服务管理等。
    * **Unicode:**  由于 Windows 内核广泛使用 Unicode，代码中使用了 `WCHAR` 和相关的 UTF-8/UTF-16 转换函数 (`g_utf8_to_utf16`, `g_utf16_to_utf8`)。
* **关于 Linux 和 Android 内核及框架 (非直接涉及，但概念有共通之处):**
    * **进程间通信 (IPC):** 尽管此文件主要处理本地服务管理，但 Frida 的整体架构涉及客户端和服务器之间的通信，以及 Frida 服务和目标进程之间的通信。理解 Linux 和 Android 中的 IPC 机制 (如 Socket, Binder) 有助于理解 Frida 的跨平台设计思想。
    * **系统调用:** Frida 在进行 hook 操作时，最终会涉及到系统调用。了解 Linux 和 Android 的系统调用机制有助于理解 hook 的底层原理。
    * **动态链接库 (Shared Libraries):**  Frida 的注入机制类似于在 Linux 和 Android 中将共享库注入到进程。

**逻辑推理 (假设输入与输出):**

假设输入：

* `service_basename`: "my-app-frida-helper"
* `archs`: ["x86", "arm64"]
* Frida 以管理员权限运行。

输出：

* 调用 `frida_register_and_start_services` 将会尝试在 SCM 中注册并启动两个 Windows 服务：
    * 名称: "my-app-frida-helper-x86"
    * 名称: "my-app-frida-helper-arm64"
* 如果注册和启动成功，SCM 中将存在这两个服务，并且它们的状态为 "正在运行"。

假设输入：

* `service_basename`: "my-game-frida-helper"
* `archs`: ["x86_64"]
* Frida 没有管理员权限运行。

输出：

* 调用 `frida_register_and_start_services` 可能会失败，因为没有权限操作 SCM。
* 接着会调用 `frida_spawn_standalone_services`，它会尝试创建两个独立的进程来运行辅助服务：
    * 可执行文件: "my-game-frida-helper-x86_64.exe" (假设该文件存在)
    * 启动参数: `"my-game-frida-helper-x86_64.exe" STANDALONE`

**用户或编程常见的使用错误:**

1. **权限不足:**  用户在没有管理员权限的情况下运行依赖于系统服务的 Frida 操作，会导致服务注册和启动失败。错误信息可能指示无法打开 SCM 或创建服务。
   * **示例:** 用户直接双击运行 Frida 客户端程序，而没有选择 "以管理员身份运行"。
2. **辅助服务文件缺失或损坏:** 如果 Frida 的辅助服务可执行文件（例如，`frida-helper-64.exe`）不存在或被损坏，会导致启动辅助服务失败。错误信息可能指示找不到指定的文件。
   * **示例:**  Frida 安装不完整，或者用户手动删除了某些 Frida 的文件。
3. **防火墙或安全软件阻止连接:**  某些防火墙或安全软件可能会阻止 Frida 客户端与辅助服务之间的通信。
   * **示例:**  Windows 防火墙阻止了 Frida 辅助服务进程的网络连接。
4. **端口冲突:**  如果 Frida 使用的端口被其他程序占用，可能会导致连接问题。
5. **不兼容的 Frida 版本:**  使用与目标环境不兼容的 Frida 版本可能会导致辅助服务无法正常启动或工作。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida 客户端:** 用户运行一个 Frida 客户端程序 (例如，一个 Python 脚本，或者 Frida 的命令行工具 `frida`)，尝试连接到目标进程。
2. **Frida 客户端连接到 Frida 服务端:**  客户端会尝试连接到目标机器上运行的 Frida 服务端进程（例如，`frida-server.exe`）。
3. **Frida 服务端检测到目标进程:**  服务端接收到客户端的请求，并确定需要与哪个目标进程进行交互。
4. **Frida 服务端启动或连接到辅助服务:**
   * **如果目标进程是第一次被 Frida 连接，或者之前的辅助服务已经停止，** Frida 服务端会调用 `frida_helper_manager_start_services` 来启动针对目标进程架构的辅助服务。这时就会执行 `frida-helper-service-glue.c` 中的代码。
   * **如果已经存在运行中的辅助服务，**  服务端可能会尝试连接到该服务，而不是启动新的服务。
5. **`frida_helper_manager_start_services` 的执行流程:**
   * 首先，`frida_service_context_new` 会创建一个上下文结构来管理服务状态。
   * 然后，根据 Frida 的运行权限 (`FRIDA_PRIVILEGE_LEVEL_ELEVATED`)，尝试打开 SCM。
   * 如果权限足够，`frida_unregister_stale_services` 会被调用以清理旧版本的辅助服务。
   * 接着，`frida_register_and_start_services` 会尝试注册并启动系统服务。
   * 如果系统服务启动失败（例如，权限问题），`frida_spawn_standalone_services` 会尝试以独立进程的方式启动辅助服务。
6. **调试线索:**  如果在调试 Frida 连接问题时，你发现程序执行流程进入了 `frida_helper_manager_start_services`，那么可能的调试方向包括：
   * **检查 Frida 的运行权限:** 确保 Frida 客户端或服务端是以管理员身份运行的。
   * **检查 Windows 事件查看器:**  查看系统事件和服务事件日志，看是否有关于 Frida 服务启动失败的错误信息。
   * **检查 Frida 辅助服务文件是否存在:**  确认 `frida-helper-x86.exe`, `frida-helper-x64.exe`, `frida-helper-arm64.exe` 等文件存在于 Frida 的安装目录中。
   * **使用进程监视工具:**  例如 Process Monitor，观察 Frida 服务端在尝试创建或连接辅助服务时，是否发生了权限错误、文件访问错误等。
   * **在 `frida-helper-service-glue.c` 中设置断点:**  如果你有 Frida 的源码，可以在关键函数（例如 `frida_register_service`, `frida_start_service`, `frida_spawn_standalone_service`) 中设置断点，逐步跟踪代码执行，了解辅助服务启动失败的原因。

总而言之，`frida-helper-service-glue.c` 是 Frida 在 Windows 平台上管理辅助服务进程的核心代码，理解其功能对于调试 Frida 连接问题和深入理解 Frida 的工作原理至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-core/src/windows/frida-helper-service-glue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#include "frida-helper-service-glue.h"

#include <windows.h>

#if defined (HAVE_ARM64)
# define FRIDA_HELPER_SERVICE_ARCH "arm64"
#elif GLIB_SIZEOF_VOID_P == 8
# define FRIDA_HELPER_SERVICE_ARCH "x86_64"
#else
# define FRIDA_HELPER_SERVICE_ARCH "x86"
#endif

#define STANDALONE_JOIN_TIMEOUT_MSEC (5 * 1000)

typedef struct _FridaServiceContext FridaServiceContext;

struct _FridaServiceContext
{
  gchar * service_basename;

  SC_HANDLE scm;

  GQueue system_services;
  GQueue standalone_services;
};

static void WINAPI frida_managed_helper_service_main (DWORD argc, WCHAR ** argv);
static DWORD WINAPI frida_managed_helper_service_handle_control_code (DWORD control, DWORD event_type, void * event_data, void * context);
static void frida_managed_helper_service_report_status (DWORD current_state, DWORD exit_code, DWORD wait_hint);

static gboolean frida_register_and_start_services (FridaServiceContext * self, gchar ** archs, gint archs_length);
static void frida_stop_and_unregister_services (FridaServiceContext * self);
static gboolean frida_spawn_standalone_services (FridaServiceContext * self, gchar ** archs, gint archs_length);
static gboolean frida_join_standalone_services (FridaServiceContext * self);
static void frida_kill_standalone_services (FridaServiceContext * self);
static void frida_release_standalone_services (FridaServiceContext * self);

static gboolean frida_register_services (FridaServiceContext * self, gchar ** archs, gint archs_length);
static gboolean frida_unregister_services (FridaServiceContext * self);
static gboolean frida_start_services (FridaServiceContext * self);
static gboolean frida_stop_services (FridaServiceContext * self);

static SC_HANDLE frida_register_service (FridaServiceContext * self, const gchar * suffix);
static gboolean frida_unregister_service (FridaServiceContext * self, SC_HANDLE handle);
static void frida_unregister_stale_services (FridaServiceContext * self);
static gboolean frida_start_service (FridaServiceContext * self, SC_HANDLE handle);
static gboolean frida_stop_service (FridaServiceContext * self, SC_HANDLE handle);

static HANDLE frida_spawn_standalone_service (FridaServiceContext * self, const gchar * suffix);
static gboolean frida_join_standalone_service (FridaServiceContext * self, HANDLE handle);
static void frida_kill_standalone_service (FridaServiceContext * self, HANDLE handle);

static FridaServiceContext * frida_service_context_new (const gchar * service_basename);
static void frida_service_context_free (FridaServiceContext * self);

static void frida_rmtree (GFile * file);

static WCHAR * frida_managed_helper_service_name = NULL;
static SERVICE_STATUS_HANDLE frida_managed_helper_service_status_handle = NULL;

void *
frida_helper_manager_start_services (const char * service_basename, gchar ** archs, gint archs_length, FridaPrivilegeLevel level)
{
  FridaServiceContext * self;

  self = frida_service_context_new (service_basename);

  self->scm = (level == FRIDA_PRIVILEGE_LEVEL_ELEVATED)
      ? OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS)
      : NULL;
  if (self->scm != NULL)
  {
    frida_unregister_stale_services (self);

    if (!frida_register_and_start_services (self, archs, archs_length))
    {
      CloseServiceHandle (self->scm);
      self->scm = NULL;
    }
  }

  if (self->scm == NULL)
  {
    if (!frida_spawn_standalone_services (self, archs, archs_length))
    {
      frida_service_context_free (self);
      self = NULL;
    }
  }

  return self;
}

void
frida_helper_manager_stop_services (void * context)
{
  FridaServiceContext * self = context;

  if (self->scm != NULL)
  {
    frida_stop_and_unregister_services (self);
  }
  else
  {
    if (!frida_join_standalone_services (self))
      frida_kill_standalone_services (self);
  }

  frida_service_context_free (self);
}

char *
frida_helper_service_derive_basename (void)
{
  WCHAR filename_utf16[MAX_PATH + 1] = { 0, };
  gchar * name, * tmp;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);

  name = g_utf16_to_utf8 (filename_utf16, -1, NULL, NULL, NULL);

  tmp = g_path_get_dirname (name);
  g_free (name);
  name = tmp;

  tmp = g_path_get_basename (name);
  g_free (name);
  name = tmp;

  tmp = g_strconcat (name, "-", NULL);
  g_free (name);
  name = tmp;

  return name;
}

char *
frida_helper_service_derive_filename_for_suffix (const char * suffix)
{
  WCHAR filename_utf16[MAX_PATH + 1] = { 0, };
  gchar * name, * tail, * tmp;
  glong len;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);

  name = g_utf16_to_utf8 (filename_utf16, -1, NULL, &len, NULL);
  tail = strrchr (name, '-');
  if (tail != NULL)
  {
    tail[1] = '\0';
    tmp = g_strconcat (name, suffix, ".exe", NULL);
    g_free (name);
    name = tmp;
  }
  else
  {
    g_critical ("Unexpected filename: %s", name);
  }

  return name;
}

char *
frida_helper_service_derive_svcname_for_self (void)
{
  gchar * basename, * name;

  basename = frida_helper_service_derive_basename ();
  name = g_strconcat (basename, FRIDA_HELPER_SERVICE_ARCH, NULL);
  g_free (basename);

  return name;
}

char *
frida_helper_service_derive_svcname_for_suffix (const char * suffix)
{
  gchar * basename, * name;

  basename = frida_helper_service_derive_basename ();
  name = g_strconcat (basename, suffix, NULL);
  g_free (basename);

  return name;
}

void
frida_managed_helper_service_enter_dispatcher_and_main_loop (void)
{
  SERVICE_TABLE_ENTRYW dispatch_table[2] = { 0, };
  gchar * name;

  name = frida_helper_service_derive_svcname_for_self ();
  frida_managed_helper_service_name = g_utf8_to_utf16 (name, -1, NULL, NULL, NULL);
  g_free (name);

  dispatch_table[0].lpServiceName = frida_managed_helper_service_name;
  dispatch_table[0].lpServiceProc = frida_managed_helper_service_main;

  StartServiceCtrlDispatcherW (dispatch_table);

  frida_managed_helper_service_status_handle = NULL;

  g_free (frida_managed_helper_service_name);
  frida_managed_helper_service_name = NULL;
}

static void WINAPI
frida_managed_helper_service_main (DWORD argc, WCHAR ** argv)
{
  GMainLoop * loop;

  (void) argc;
  (void) argv;

  loop = g_main_loop_new (NULL, FALSE);

  frida_managed_helper_service_status_handle = RegisterServiceCtrlHandlerExW (
      frida_managed_helper_service_name,
      frida_managed_helper_service_handle_control_code,
      loop);

  frida_managed_helper_service_report_status (SERVICE_START_PENDING, NO_ERROR, 0);

  frida_managed_helper_service_report_status (SERVICE_RUNNING, NO_ERROR, 0);
  g_main_loop_run (loop);
  frida_managed_helper_service_report_status (SERVICE_STOPPED, NO_ERROR, 0);

  g_main_loop_unref (loop);
}

static gboolean
frida_managed_helper_service_stop (gpointer data)
{
  GMainLoop * loop = data;

  g_main_loop_quit (loop);

  return FALSE;
}

static DWORD WINAPI
frida_managed_helper_service_handle_control_code (DWORD control, DWORD event_type, void * event_data, void * context)
{
  GMainLoop * loop = context;

  (void) event_type;
  (void) event_data;

  switch (control)
  {
    case SERVICE_CONTROL_STOP:
      frida_managed_helper_service_report_status (SERVICE_STOP_PENDING, NO_ERROR, 0);
      g_idle_add (frida_managed_helper_service_stop, loop);
      return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
      return NO_ERROR;

    default:
      return ERROR_CALL_NOT_IMPLEMENTED;
  }
}

static void
frida_managed_helper_service_report_status (DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
  SERVICE_STATUS status;
  static DWORD checkpoint = 1;

  status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.dwCurrentState = current_state;

  if (current_state == SERVICE_START_PENDING)
    status.dwControlsAccepted = 0;
  else
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  status.dwWin32ExitCode = exit_code;
  status.dwServiceSpecificExitCode = 0;

  if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED)
  {
    status.dwCheckPoint = 0;
  }
  else
  {
    status.dwCheckPoint = checkpoint++;
  }

  status.dwWaitHint = wait_hint;

  SetServiceStatus (frida_managed_helper_service_status_handle, &status);
}

static gboolean
frida_register_and_start_services (FridaServiceContext * self, gchar ** archs, gint archs_length)
{
  if (!frida_register_services (self, archs, archs_length))
    return FALSE;

  if (!frida_start_services (self))
  {
    frida_unregister_services (self);
    return FALSE;
  }

  return TRUE;
}

static void
frida_stop_and_unregister_services (FridaServiceContext * self)
{
  frida_stop_services (self);
  frida_unregister_services (self);
}

static gboolean
frida_spawn_standalone_services (FridaServiceContext * self, gchar ** archs, gint archs_length)
{
  gint i;

  for (i = 0; i != archs_length; i++)
  {
    HANDLE service = frida_spawn_standalone_service (self, archs[i]);
    if (service == NULL)
      goto unable_to_spawn;
    g_queue_push_tail (&self->standalone_services, service);
  }

  return TRUE;

unable_to_spawn:
  {
    frida_kill_standalone_services (self);
    return FALSE;
  }
}

static gboolean
frida_join_standalone_services (FridaServiceContext * self)
{
  gboolean success = TRUE;
  GList * cur;

  for (cur = self->standalone_services.head; cur != NULL; cur = cur->next)
    success &= frida_join_standalone_service (self, cur->data);

  if (success)
    frida_release_standalone_services (self);

  return success;
}

static void
frida_kill_standalone_services (FridaServiceContext * self)
{
  GList * cur;

  for (cur = self->standalone_services.head; cur != NULL; cur = cur->next)
    frida_kill_standalone_service (self, cur->data);

  frida_release_standalone_services (self);
}

static void
frida_release_standalone_services (FridaServiceContext * self)
{
  HANDLE service;

  while ((service = g_queue_pop_tail (&self->standalone_services)) != NULL)
    CloseHandle (service);
}

static gboolean
frida_register_services (FridaServiceContext * self, gchar ** archs, gint archs_length)
{
  gint i;

  for (i = 0; i != archs_length; i++)
  {
    SC_HANDLE service = frida_register_service (self, archs[i]);
    if (service == NULL)
      goto unable_to_register;
    g_queue_push_tail (&self->system_services, service);
  }

  return TRUE;

unable_to_register:
  {
    frida_unregister_services (self);
    return FALSE;
  }
}

static gboolean
frida_unregister_services (FridaServiceContext * self)
{
  gboolean success = TRUE;
  SC_HANDLE service;

  while ((service = g_queue_pop_tail (&self->system_services)) != NULL)
  {
    success &= frida_unregister_service (self, service);
    CloseServiceHandle (service);
  }

  return success;
}

static gboolean
frida_start_services (FridaServiceContext * self)
{
  GList * cur;

  for (cur = self->system_services.head; cur != NULL; cur = cur->next)
  {
    if (!frida_start_service (self, cur->data))
      goto unable_to_start;
  }

  return TRUE;

unable_to_start:
  {
    frida_stop_services (self);
    return FALSE;
  }
}

static gboolean
frida_stop_services (FridaServiceContext * self)
{
  gboolean success = TRUE;
  GList * cur;

  for (cur = self->system_services.head; cur != NULL; cur = cur->next)
    success &= frida_stop_service (self, cur->data);

  return success;
}

static SC_HANDLE
frida_register_service (FridaServiceContext * self, const gchar * suffix)
{
  SC_HANDLE handle;
  gchar * servicename_utf8;
  WCHAR * servicename;
  gchar * displayname_utf8;
  WCHAR * displayname;
  gchar * filename_utf8;
  WCHAR * filename;

  servicename_utf8 = g_strconcat (self->service_basename, suffix, NULL);
  servicename = g_utf8_to_utf16 (servicename_utf8, -1, NULL, NULL, NULL);

  displayname_utf8 = g_strdup_printf ("Frida %s helper (%s)", suffix, servicename_utf8);
  displayname = g_utf8_to_utf16 (displayname_utf8, -1, NULL, NULL, NULL);

  filename_utf8 = frida_helper_service_derive_filename_for_suffix (suffix);
  filename = g_utf8_to_utf16 (filename_utf8, -1, NULL, NULL, NULL);

  handle = CreateServiceW (self->scm,
      servicename,
      displayname,
      SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS,
      SERVICE_DEMAND_START,
      SERVICE_ERROR_NORMAL,
      filename,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL);

  g_free (filename);
  g_free (filename_utf8);

  g_free (displayname);
  g_free (displayname_utf8);

  g_free (servicename);
  g_free (servicename_utf8);

  return handle;
}

static gboolean
frida_unregister_service (FridaServiceContext * self, SC_HANDLE handle)
{
  (void) self;

  return DeleteService (handle);
}

static void
frida_unregister_stale_services (FridaServiceContext * self)
{
  BYTE * services_data;
  DWORD services_size, bytes_needed, num_services, resume_handle;
  GQueue stale_services = G_QUEUE_INIT;

  services_size = 16384;
  services_data = g_malloc (services_size);

  resume_handle = 0;

  do
  {
    ENUM_SERVICE_STATUS_PROCESSW * services;
    DWORD i;

    num_services = 0;
    if (!EnumServicesStatusExW (self->scm,
        SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_INACTIVE,
        services_data,
        services_size,
        &bytes_needed,
        &num_services,
        &resume_handle,
        NULL))
    {
      if (GetLastError () == ERROR_MORE_DATA)
      {
        if (num_services == 0)
        {
          services_data = g_realloc (services_data, bytes_needed);
          services_size = bytes_needed;
          continue;
        }
      }
      else
      {
        break;
      }
    }

    services = (ENUM_SERVICE_STATUS_PROCESSW *) services_data;
    for (i = 0; i != num_services; i++)
    {
      ENUM_SERVICE_STATUS_PROCESSW * service = &services[i];

      if (wcsncmp (service->lpServiceName, L"frida-", 6) == 0 && wcslen (service->lpServiceName) == 41)
      {
        SC_HANDLE handle = OpenServiceW (self->scm, service->lpServiceName, SERVICE_QUERY_CONFIG | DELETE);
        if (handle != NULL)
          g_queue_push_tail (&stale_services, handle);
      }
    }
  }
  while (num_services == 0 || resume_handle != 0);

  g_free (services_data);

  if (!g_queue_is_empty (&stale_services))
  {
    GHashTable * stale_dirs;
    QUERY_SERVICE_CONFIGW * config_data;
    DWORD config_size;
    GList * cur;
    GHashTableIter iter;
    gchar * stale_dir;

    stale_dirs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    config_data = NULL;
    config_size = 0;

    for (cur = stale_services.head; cur != NULL; cur = cur->next)
    {
      SC_HANDLE handle = cur->data;

retry:
      if (QueryServiceConfigW (handle, config_data, config_size, &bytes_needed))
      {
        gchar * binary_path, * tempdir_path;

        binary_path = g_utf16_to_utf8 (config_data->lpBinaryPathName, -1, NULL, NULL, NULL);
        tempdir_path = g_path_get_dirname (binary_path);

        g_hash_table_add (stale_dirs, tempdir_path);

        g_free (binary_path);
      }
      else if (GetLastError () == ERROR_INSUFFICIENT_BUFFER)
      {
        config_data = g_realloc (config_data, bytes_needed);
        config_size = bytes_needed;
        goto retry;
      }

      DeleteService (handle);
      CloseServiceHandle (handle);
    }

    g_hash_table_iter_init (&iter, stale_dirs);
    while (g_hash_table_iter_next (&iter, (gpointer *) &stale_dir, NULL))
    {
      GFile * file = g_file_new_for_path (stale_dir);
      frida_rmtree (file);
      g_object_unref (file);
    }

    g_free (config_data);
    g_hash_table_unref (stale_dirs);
  }

  g_queue_clear (&stale_services);
}

static gboolean
frida_start_service (FridaServiceContext * self, SC_HANDLE handle)
{
  (void) self;

  return StartService (handle, 0, NULL);
}

static gboolean
frida_stop_service (FridaServiceContext * self, SC_HANDLE handle)
{
  SERVICE_STATUS status = { 0, };

  (void) self;

  return ControlService (handle, SERVICE_CONTROL_STOP, &status);
}

static HANDLE
frida_spawn_standalone_service (FridaServiceContext * self, const gchar * suffix)
{
  HANDLE handle = NULL;
  gchar * appname_utf8;
  WCHAR * appname;
  gchar * cmdline_utf8;
  WCHAR * cmdline;
  STARTUPINFOW si = { 0, };
  PROCESS_INFORMATION pi = { 0, };

  (void) self;

  appname_utf8 = frida_helper_service_derive_filename_for_suffix (suffix);
  appname = (WCHAR *) g_utf8_to_utf16 (appname_utf8, -1, NULL, NULL, NULL);

  cmdline_utf8 = g_strconcat ("\"", appname_utf8, "\" STANDALONE", NULL);
  cmdline = (WCHAR *) g_utf8_to_utf16 (cmdline_utf8, -1, NULL, NULL, NULL);

  si.cb = sizeof (si);

  if (CreateProcessW (appname, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
  {
    handle = pi.hProcess;
    CloseHandle (pi.hThread);
  }

  g_free (cmdline);
  g_free (cmdline_utf8);

  g_free (appname);
  g_free (appname_utf8);

  return handle;
}

static gboolean
frida_join_standalone_service (FridaServiceContext * self, HANDLE handle)
{
  (void) self;

  return WaitForSingleObject (handle,
      STANDALONE_JOIN_TIMEOUT_MSEC) == WAIT_OBJECT_0;
}

static void
frida_kill_standalone_service (FridaServiceContext * self, HANDLE handle)
{
  (void) self;

  TerminateProcess (handle, 1);
}

static FridaServiceContext *
frida_service_context_new (const gchar * service_basename)
{
  FridaServiceContext * self;

  self = g_slice_new0 (FridaServiceContext);
  self->service_basename = g_strdup (service_basename);
  g_queue_init (&self->standalone_services);

  return self;
}

static void
frida_service_context_free (FridaServiceContext * self)
{
  g_assert (g_queue_is_empty (&self->system_services));
  g_assert (g_queue_is_empty (&self->standalone_services));

  if (self->scm != NULL)
    CloseServiceHandle (self->scm);

  g_free (self->service_basename);

  g_slice_free (FridaServiceContext, self);
}

static void
frida_rmtree (GFile * file)
{
  GFileEnumerator * enumerator =
      g_file_enumerate_children (file, G_FILE_ATTRIBUTE_STANDARD_NAME, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, NULL);
  if (enumerator != NULL)
  {
    GFileInfo * info;
    GFile * child;

    while (g_file_enumerator_iterate (enumerator, &info, &child, NULL, NULL) && child != NULL)
    {
      if (g_file_info_get_file_type (info) == G_FILE_TYPE_DIRECTORY)
        frida_rmtree (child);
      else
        g_file_delete (child, NULL, NULL);
    }

    g_object_unref (enumerator);
  }

  g_file_delete (file, NULL, NULL);
}
```