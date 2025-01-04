Response:
My thinking process to analyze the C code snippet and generate the response above involved several steps:

1. **Understand the Goal:** The request asks for an explanation of a C source file's functionality within the context of the Frida dynamic instrumentation tool. Key aspects to address include reverse engineering relevance, low-level details (Linux, Android, kernel), logical assumptions, potential user errors, debugging clues, and a summary of the file's purpose.

2. **Initial Scan and Keyword Recognition:** I quickly scanned the code for recognizable keywords and patterns related to system programming, process manipulation, and dynamic linking. This included:
    * `#include` directives (stdio, dlfcn, glib, libelf, gio, gum, sys/...) indicating system-level operations.
    * `ptrace` (process tracing and debugging).
    * `fork`, `execve`, `waitpid` (process creation and management).
    * `dlopen`, `dlsym`, `dlclose` (dynamic library loading).
    * `mmap`, `munmap`, `mprotect` (memory management).
    * `pipe`, `mkfifo`, `open`, `close`, `read`, `write` (inter-process communication).
    * `pthread_create`, `pthread_detach`, `pthread_getthreadid_np` (threading).
    * Structures with names like `FridaSpawnInstance`, `FridaInjectInstance`, `FridaRemoteApi` suggesting different phases or components of the injection process.
    * Macros like `CHECK_OS_RESULT` indicating error handling based on system call results.
    * The file name `binjector-glue.c` strongly suggests a role in injecting code into other processes.

3. **Identify Core Functionality (Grouping by Structures and Functions):** I started grouping related code elements based on the defined structures and functions. This helps in understanding the overall flow and responsibilities of different parts of the code:
    * **`FridaSpawnInstance`:** Associated with `_frida_binjector_do_spawn`, `frida_spawn_instance_new`, `frida_spawn_instance_free`, `frida_spawn_instance_resume`. This clearly handles spawning new processes under Frida's control.
    * **`FridaExecInstance`:** Connected to `_frida_binjector_do_prepare_exec_transition`, `frida_exec_instance_prepare_transition`, `frida_exec_instance_try_perform_transition`, `frida_exec_instance_suspend`, `frida_exec_instance_resume`, `frida_exec_instance_free`. This seems to manage the transition of an existing process when it executes a new program (execve).
    * **`FridaInjectInstance`:** Related to a large number of functions, including `_frida_binjector_do_inject`, `frida_inject_instance_new`, `frida_inject_instance_attach`, `frida_inject_instance_detach`, `frida_inject_instance_start_remote_thread`, and functions for managing the FIFO. This is the core of the code injection mechanism.
    * **Helper Functions:**  Functions like `frida_make_pipe`, `frida_wait_for_attach_signal`, `frida_get_regs`, `frida_set_regs`, `frida_remote_api_try_init`, `frida_remote_alloc`, `frida_remote_dealloc`, `frida_remote_read`, `frida_remote_write`, `frida_remote_call`, `frida_remote_exec` provide lower-level utilities for process interaction and memory manipulation.

4. **Analyze Function Interactions:**  I looked at how these structures and their associated functions interact. For example, `_frida_binjector_do_inject` creates a `FridaInjectInstance`, attaches to the target process, allocates memory, transfers a payload, and starts a remote thread.

5. **Connect to Reverse Engineering Concepts:** With a grasp of the core functionality, I could then connect it to reverse engineering techniques:
    * **Code Injection:** The primary goal of this code is to inject code into a running process. This is a fundamental technique in dynamic analysis and instrumentation.
    * **Dynamic Instrumentation:** Frida's purpose is dynamic instrumentation, and this file is a key part of achieving that.
    * **API Hooking:**  While not explicitly shown in this snippet, the ability to inject code enables API hooking by overwriting function pointers or inserting detours.
    * **Memory Analysis:** The functions for remote memory reading and writing (`frida_remote_read`, `frida_remote_write`) are crucial for inspecting and modifying the target process's memory.

6. **Identify Low-Level Dependencies:**  The `#include` directives and the use of system calls like `ptrace`, `fork`, `execve`, `mmap`, etc., clearly indicate reliance on Linux/FreeBSD kernel features. The use of `dlfcn.h` points to the dynamic linking mechanism. The mention of `pthread` highlights the threading model. The file is specifically located under `frida/subprojects/frida-core/src/freebsd/`, explicitly stating its FreeBSD focus. Although the question mentioned Linux and Android, I focused on FreeBSD as per the file path.

7. **Infer Logical Flow and Assumptions:** I made logical inferences about the order of operations and the assumptions made by the code. For example, the injection process likely involves: attaching to the target, allocating memory in the target, writing the payload code and data, setting up the execution environment (stack, registers), and then starting the injected code.

8. **Consider Potential User Errors:** I thought about common mistakes a user might make when using Frida that could lead to this code being executed or issues arising from it. Incorrect PID, wrong paths, permission problems, and issues with the injected code itself are all possibilities.

9. **Trace the Debugging Path:** I considered how a developer debugging Frida might end up examining this file. They might be investigating issues with process spawning, code injection failures, or problems related to the communication channel (FIFO).

10. **Summarize Functionality:** Finally, I synthesized the information gathered into a concise summary of the file's purpose.

11. **Structure the Response:**  I organized the response into clear sections addressing each part of the request (functionality, reverse engineering, low-level details, logical inferences, user errors, debugging, and summary). I used bullet points and code snippets where appropriate to enhance readability.

Throughout this process, I constantly referred back to the code to ensure my explanations were accurate and grounded in the provided source. I also tried to anticipate the "why" behind certain code patterns and how they fit into the larger picture of Frida's operation.
好的，这是对提供的 `frida/subprojects/frida-core/src/freebsd/binjector-glue.c` 文件代码的功能进行分析：

**文件功能归纳：**

`binjector-glue.c` 文件是 Frida 动态插桩工具在 FreeBSD 平台上实现**代码注入**和**进程管理**的核心组件。它提供了一系列函数，用于：

1. **启动新的进程并进行监控 (Spawning):**  允许 Frida 启动一个新的进程，并在其启动时进行拦截和控制，以便在目标进程执行任何代码之前注入 Frida 的 Agent。
2. **管理进程的 `exec` 调用 (Exec Transition):** 监听并处理目标进程执行 `execve` 等系统调用，以便在新的可执行文件开始执行前重新注入 Frida 的 Agent。
3. **将代码注入到现有进程 (Injection):**  允许 Frida 将自定义代码（通常是 Frida 的 Agent）注入到已经运行的目标进程中。
4. **在注入的代码中创建远程线程:** 在目标进程中分配内存，加载必要的库（如 `pthread`），并创建一个新的线程来执行注入的 Agent 代码。
5. **建立与注入代码的通信通道:** 使用命名管道 (FIFO) 在 Frida 主进程和注入到目标进程的代码之间建立双向通信通道。
6. **管理注入实例的生命周期:**  跟踪和管理每个注入实例的状态，包括分配的内存、创建的线程和打开的管道。
7. **处理进程状态变化:** 响应目标进程的状态变化，例如暂停、恢复、退出等。

**与逆向方法的关系及举例说明：**

该文件中的功能与多种逆向方法紧密相关，因为它提供了 Frida 动态插桩的核心能力：

* **动态代码分析:** 通过代码注入，逆向工程师可以将自定义代码注入到目标进程中，以观察其运行时的行为、修改内存数据、hook 函数调用等。
    * **举例:** 逆向工程师可以使用 Frida 注入一段 JavaScript 代码，hook 目标进程的关键 API 函数，记录其参数和返回值，从而理解该函数的用途和行为。例如，可以 hook `open()` 系统调用来监控目标进程打开的文件。
* **运行时修改:** Frida 允许在运行时修改目标进程的内存，这对于绕过安全检查、修改程序逻辑非常有用。
    * **举例:** 可以注入代码来修改目标进程中某个标志位的值，从而绕过身份验证或激活隐藏功能。
* **API Hooking:**  代码注入是实现 API Hooking 的基础。通过替换目标进程中函数的地址或插入跳转指令，可以拦截对特定 API 函数的调用，并在调用前后执行自定义代码。
    * **举例:** 可以 hook 加密算法相关的 API 函数，在加密前或解密后获取原始数据，从而破解加密。
* **进程控制:** Frida 能够暂停、恢复目标进程的执行，这对于单步调试和分析程序流程非常有用。
    * **举例:**  可以在目标进程执行到特定位置时暂停它，然后检查其寄存器和内存状态。

**涉及的二进制底层、Linux/FreeBSD 内核及框架知识及举例说明：**

该文件涉及大量的底层知识：

* **系统调用:** 代码中直接使用 `ptrace`、`fork`、`execve`、`waitpid`、`kill`、`mmap`、`munmap`、`mprotect`、`open`、`close`、`write`、`mkfifo` 等系统调用，这些是操作系统提供给用户空间程序访问内核功能的接口。
    * **举例:** `ptrace (PT_ATTACH, pid, NULL, 0)` 用于附加到目标进程，这是进行代码注入和控制的前提。
* **进程和线程管理:**  涉及到进程的创建 (`fork`)、执行 (`execve`)、信号处理 (`SIGTRAP`, `SIGSTOP`)、线程的创建 (`pthread_create`) 和管理 (`pthread_detach`)。
    * **举例:** `frida_wait_for_child_signal` 函数等待目标子进程发出特定的信号，这是同步 Frida 和目标进程执行的关键机制。
* **内存管理:**  使用 `mmap` 在目标进程中分配内存，`mprotect` 修改内存保护属性。
    * **举例:**  注入的 Agent 代码需要被加载到目标进程的内存空间中执行，`frida_remote_alloc` 函数负责在目标进程中分配相应的内存。
* **动态链接:**  使用 `dlopen`、`dlsym`、`dlclose` 来加载和解析目标进程中的动态链接库，以便获取函数地址。
    * **举例:**  注入的 Agent 通常需要调用目标进程中的一些函数，例如 `pthread_create`，这需要先通过 `dlopen` 加载 `pthread` 库，再通过 `dlsym` 获取 `pthread_create` 的地址。
* **命名管道 (FIFO):**  用于在 Frida 主进程和注入的目标进程之间建立通信通道。
    * **举例:**  Frida 使用 FIFO 将控制命令发送给注入的 Agent，并接收 Agent 返回的结果或数据。
* **FreeBSD 内核 API (及部分 POSIX 标准):** 代码中使用了 `<sys/ptrace.h>`， `<sys/thr.h>` 等 FreeBSD 特定的头文件，以及符合 POSIX 标准的 `<dlfcn.h>`， `<pthread.h>` 等。
    * **举例:** `thr_kill2(pid, tid, signal)` 是 FreeBSD 特有的用于向指定进程的特定线程发送信号的系统调用。
* **Glib 库:**  使用了 Glib 库提供的跨平台抽象，例如 `g_unix_open_pipe` 创建管道， `g_strdup_printf` 格式化字符串。

**逻辑推理、假设输入与输出:**

* **假设输入:**
    * Frida 主进程请求注入代码到 PID 为 `1234` 的进程。
    * 要注入的共享库路径为 `/tmp/my_agent.so`。
    * 注入后要执行的入口函数名为 `agent_main`。
    * 传递给入口函数的数据为 `"hello"`。
* **逻辑推理:**
    1. `_frida_binjector_do_inject` 函数会被调用。
    2. 该函数会创建一个 `FridaInjectInstance` 结构体来管理这次注入。
    3. 使用 `ptrace(PT_ATTACH)` 附加到目标进程 `1234`。
    4. 在目标进程中分配内存区域，用于存放注入的代码和数据。
    5. 构建一个包含加载 `/tmp/my_agent.so`，查找 `agent_main` 函数，并调用它的 payload 代码。
    6. 通过 `frida_remote_write` 将 payload 代码和包含参数（如 `"hello"`）的数据写入到目标进程分配的内存中。
    7. 修改目标进程的寄存器，使其执行注入的 payload 代码。
    8. 注入的 payload 代码会加载 `/tmp/my_agent.so`，找到 `agent_main` 函数，并将 `"hello"` 作为参数传递给它。
    9. 通过 FIFO 建立与注入的 Agent 的通信。
* **预期输出 (不直接体现在此 C 代码中，而是 Frida 的整体行为):**
    * 目标进程 `1234` 中会加载 `/tmp/my_agent.so`。
    * 目标进程会创建一个新的线程来执行 `agent_main` 函数。
    * Frida 主进程可以通过 FIFO 与注入的 Agent 进行通信。

**用户或编程常见的使用错误及举例说明:**

* **权限不足:**  Frida 运行时可能没有足够的权限附加到目标进程或在其内存空间中分配内存。
    * **举例:**  如果用户没有 root 权限，尝试注入到属于其他用户的进程可能会失败，并显示 "Unable to access process with pid %u due to system restrictions; try running Frida as root" 错误信息。
* **目标进程没有 libc:**  某些非常底层的进程可能不依赖于 `libc` 库，Frida 依赖 `dlopen` 等 `libc` 提供的函数进行动态链接，如果目标进程没有 `libc`，注入会失败。
    * **举例:** 尝试注入到一个非常小的、静态链接的程序可能会导致 "Unable to inject library into process without libc" 错误。
* **提供的共享库路径错误:**  如果用户提供的要注入的共享库路径不存在或 Frida 无法访问，注入会失败。
    * **举例:**  如果 `path` 参数指向一个不存在的文件，注入过程会因为无法加载共享库而失败。
* **入口点名称错误:**  如果提供的入口点名称在注入的共享库中不存在，注入后的执行可能会出错。
    * **举例:**  如果 `entrypoint` 参数指定的函数名在 `/tmp/my_agent.so` 中不存在，那么在尝试查找该函数地址时会失败。
* **临时文件路径问题:**  如果提供的临时文件路径不可写，创建 FIFO 可能会失败。
    * **举例:** 如果 `temp_path` 指向一个只读目录，`mkfifo` 调用会失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户通过 Frida 的客户端 API（例如 Python 或 JavaScript）发起注入操作，最终会触发 `binjector-glue.c` 中的代码执行。以下是一个可能的步骤：

1. **用户编写 Frida 脚本:**  用户使用 Frida 的 Python 或 JavaScript API 编写脚本，指定要注入的目标进程 (通过 PID 或进程名) 和要注入的 Agent 代码 (通常是一个 JavaScript 文件或共享库)。
2. **用户运行 Frida 脚本:**  用户在命令行或通过 Frida 的工具运行该脚本。
3. **Frida 客户端与 Frida Server 通信:**  Frida 客户端会将用户的请求发送到 Frida Server (通常运行在目标设备上)。
4. **Frida Server 处理注入请求:**  Frida Server 接收到注入请求后，会根据目标进程的操作系统类型，选择相应的 `Binjector` 实现。在 FreeBSD 上，会使用 `frida-core` 中的 `FridaBinjector`。
5. **调用 `_frida_binjector_do_inject` 或相关函数:**  `FridaBinjector` 会调用 `binjector-glue.c` 中定义的 `_frida_binjector_do_inject` 函数，并传递相关的参数，例如目标进程的 PID、共享库路径、入口点名称等。
6. **`binjector-glue.c` 中的代码执行:**  `_frida_binjector_do_inject` 函数会执行前面描述的步骤，例如附加到目标进程、分配内存、写入 payload、创建远程线程等。

**调试线索:**

如果 Frida 的注入过程出现问题，逆向工程师或 Frida 开发者可能会查看 `binjector-glue.c` 文件作为调试的起点：

* **注入失败:** 如果注入没有成功，可以检查 `_frida_binjector_do_inject` 函数中的步骤，例如 `ptrace` 调用是否成功，内存分配是否成功，payload 是否正确写入等。
* **远程线程启动失败:** 如果注入成功但 Agent 代码没有执行，可以检查 `frida_inject_instance_start_remote_thread` 函数，查看远程线程是否成功创建和启动。
* **通信问题:** 如果 Frida 主进程和注入的 Agent 无法通信，可以检查 FIFO 的创建和打开过程，以及读写操作是否正确。
* **进程状态异常:** 如果目标进程在注入过程中崩溃或进入异常状态，可以检查进程管理相关的函数，例如 `frida_spawn_instance_resume`， `frida_exec_instance_resume`，查看是否因为 Frida 的操作导致了问题。

**总结一下它的功能:**

总而言之，`frida/subprojects/frida-core/src/freebsd/binjector-glue.c` 文件是 Frida 在 FreeBSD 平台上实现核心注入功能的关键模块，负责启动和管理目标进程，并将 Frida 的 Agent 代码注入到目标进程中，并建立通信通道，是 Frida 动态插桩技术的基础。

Prompt: 
```
这是目录为frida/subprojects/frida-core/src/freebsd/binjector-glue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
#include "frida-core.h"

#include <dlfcn.h>
#include <glib-unix.h>
#include <libelf.h>
#include <string.h>
#include <gio/gunixinputstream.h>
#include <gum/gumfreebsd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/thr.h>
#include <sys/types.h>
#include <sys/wait.h>

#define FRIDA_STACK_ALIGNMENT 16
#define FRIDA_RED_ZONE_SIZE 128
#if GLIB_SIZEOF_VOID_P == 8
# define FRIDA_MAP_FAILED G_MAXUINT64
#else
# define FRIDA_MAP_FAILED G_MAXUINT32
#endif

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto os_failure; \
  }

typedef struct reg FridaRegs;

#define FRIDA_REMOTE_DATA_FIELD(n) \
    (remote_address + params->data.offset + G_STRUCT_OFFSET (FridaTrampolineData, n))

#define FRIDA_DUMMY_RETURN_ADDRESS 0x320

typedef struct _FridaSpawnInstance FridaSpawnInstance;
typedef struct _FridaExecInstance FridaExecInstance;
typedef struct _FridaNotifyExecPendingContext FridaNotifyExecPendingContext;
typedef struct _FridaInjectInstance FridaInjectInstance;
typedef struct _FridaInjectParams FridaInjectParams;
typedef struct _FridaInjectRegion FridaInjectRegion;
typedef struct _FridaCodeChunk FridaCodeChunk;
typedef struct _FridaTrampolineData FridaTrampolineData;
typedef struct _FridaRemoteApi FridaRemoteApi;

typedef void (* FridaInjectEmitFunc) (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code);

struct _FridaRemoteApi
{
  GumAddress mmap_impl;
  GumAddress munmap_impl;
  GumAddress mprotect_impl;

  GumAddress open_impl;
  GumAddress close_impl;
  GumAddress write_impl;

  GumAddress dlopen_impl;
  GumAddress dlclose_impl;
  GumAddress dlsym_impl;
};

struct _FridaSpawnInstance
{
  pid_t pid;
  lwpid_t interruptible_thread;

  FridaBinjector * binjector;
};

struct _FridaExecInstance
{
  pid_t pid;
  lwpid_t interruptible_thread;

  FridaBinjector * binjector;
};

struct _FridaNotifyExecPendingContext
{
  pid_t pid;
  gboolean pending;
};

struct _FridaInjectInstance
{
  guint id;

  pid_t pid;
  FridaRemoteApi api;
  gchar * executable_path;
  gboolean already_attached;
  gboolean exec_pending;

  gchar * temp_path;

  gchar * fifo_path;
  gint fifo;
  gint previous_fifo;

  GumAddress remote_payload;
  guint remote_size;
  GumAddress entrypoint;
  GumAddress stack_top;
  GumAddress trampoline_data;

  FridaBinjector * binjector;
};

struct _FridaInjectRegion
{
  guint offset;
  guint size;
};

struct _FridaInjectParams
{
  pid_t pid;

  FridaRemoteApi api;

  const gchar * so_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;

  const gchar * fifo_path;

  FridaInjectRegion code;
  FridaInjectRegion data;
  FridaInjectRegion guard;
  FridaInjectRegion stack;

  GumAddress remote_address;
  guint remote_size;
};

struct _FridaCodeChunk
{
  guint8 * cur;
  gsize size;
};

struct _FridaTrampolineData
{
  gchar pthread_so_string[32];
  gchar pthread_create_string[16];
  gchar pthread_detach_string[16];
  gchar pthread_getthreadid_np_string[32];
  gchar fifo_path[256];
  gchar so_path[256];
  gchar entrypoint_name[256];
  gchar entrypoint_data[256];
  guint8 hello_byte;

  gpointer pthread_so;
  pthread_t worker_thread;
  gpointer module_handle;
};

static gboolean frida_set_matching_inject_instances_exec_pending (GeeMapEntry * entry, FridaNotifyExecPendingContext * ctx);

static FridaSpawnInstance * frida_spawn_instance_new (FridaBinjector * binjector);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static FridaExecInstance * frida_exec_instance_new (FridaBinjector * binjector, pid_t pid);
static void frida_exec_instance_free (FridaExecInstance * instance);
static gboolean frida_exec_instance_prepare_transition (FridaExecInstance * self, GError ** error);
static gboolean frida_exec_instance_try_perform_transition (FridaExecInstance * self, GError ** error);
static void frida_exec_instance_suspend (FridaExecInstance * self);
static void frida_exec_instance_resume (FridaExecInstance * self);

static void frida_make_pipe (int fds[2]);

static FridaInjectInstance * frida_inject_instance_new (FridaBinjector * binjector, guint id, guint pid, const FridaRemoteApi * api,
    const gchar * temp_path);
static void frida_inject_instance_recreate_fifo (FridaInjectInstance * self);
static FridaInjectInstance * frida_inject_instance_clone (const FridaInjectInstance * instance, guint id);
static void frida_inject_instance_init_fifo (FridaInjectInstance * self);
static void frida_inject_instance_close_previous_fifo (FridaInjectInstance * self);
static void frida_inject_instance_free (FridaInjectInstance * instance, FridaUnloadPolicy unload_policy);
static gboolean frida_inject_instance_did_not_exec (FridaInjectInstance * self);
static gboolean frida_inject_instance_attach (FridaInjectInstance * self, FridaRegs * saved_regs, GError ** error);
static gboolean frida_inject_instance_detach (FridaInjectInstance * self, const FridaRegs * saved_regs, GError ** error);
static gboolean frida_inject_instance_start_remote_thread (FridaInjectInstance * self, gboolean * exited, GError ** error);
static gboolean frida_inject_instance_emit_and_transfer_payload (FridaInjectEmitFunc func, const FridaInjectParams * params, GumAddress * entrypoint, GError ** error);
static void frida_inject_instance_emit_payload_code (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code);

static gboolean frida_wait_for_attach_signal (pid_t pid);
static gboolean frida_wait_for_child_signal (pid_t pid, int signal, gboolean * exited);
static gint frida_get_regs (pid_t pid, FridaRegs * regs);
static gint frida_set_regs (pid_t pid, const FridaRegs * regs);

static gboolean frida_run_to_entrypoint (pid_t pid, GError ** error);

static gboolean frida_remote_api_try_init (FridaRemoteApi * api, pid_t pid);
static GumAddress frida_remote_alloc (pid_t pid, size_t size, int prot, const FridaRemoteApi * api, GError ** error);
static gboolean frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, const FridaRemoteApi * api, GError ** error);
static gboolean frida_remote_mprotect (pid_t pid, GumAddress address, size_t size, int prot, const FridaRemoteApi * api, GError ** error);
static gboolean frida_remote_read (pid_t pid, GumAddress remote_address, gpointer data, gsize size, GError ** error);
static gboolean frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval,
    gboolean * exited, GError ** error);
static gboolean frida_remote_exec (pid_t pid, GumAddress remote_address, GumAddress remote_stack, GumAddress * result, gboolean * exited,
    GError ** error);

guint
_frida_binjector_do_spawn (FridaBinjector * self, const gchar * path, FridaHostSpawnOptions * options, FridaStdioPipes ** pipes, GError ** error)
{
  FridaSpawnInstance * instance;
  gchar ** argv, ** envp;
  int stdin_pipe[2], stdout_pipe[2], stderr_pipe[2];
  gchar * old_cwd = NULL;
  gboolean success;
  const gchar * failed_operation;

  instance = frida_spawn_instance_new (self);

  argv = frida_host_spawn_options_compute_argv (options, path, NULL);
  envp = frida_host_spawn_options_compute_envp (options, NULL);

  switch (options->stdio)
  {
    case FRIDA_STDIO_INHERIT:
      *pipes = NULL;
      break;

    case FRIDA_STDIO_PIPE:
      frida_make_pipe (stdin_pipe);
      frida_make_pipe (stdout_pipe);
      frida_make_pipe (stderr_pipe);

      *pipes = frida_stdio_pipes_new (stdin_pipe[1], stdout_pipe[0], stderr_pipe[0]);

      break;

    default:
      g_assert_not_reached ();
  }

  if (strlen (options->cwd) > 0)
  {
    old_cwd = g_get_current_dir ();
    if (chdir (options->cwd) != 0)
      goto chdir_failed;
  }

  instance->pid = fork ();
  if (instance->pid == 0)
  {
    setsid ();

    if (options->stdio == FRIDA_STDIO_PIPE)
    {
      dup2 (stdin_pipe[0], 0);
      dup2 (stdout_pipe[1], 1);
      dup2 (stderr_pipe[1], 2);
    }

    ptrace (PT_TRACE_ME, 0, NULL, 0);
    if (execve (path, argv, envp) == -1)
    {
      g_printerr ("Unexpected error while spawning process (execve failed: %s)\n", strerror (errno));
      _exit (1);
    }
  }

  if (old_cwd != NULL)
  {
    if (chdir (old_cwd) != 0)
      g_warning ("Failed to restore working directory");
  }

  if (options->stdio == FRIDA_STDIO_PIPE)
  {
    close (stdin_pipe[0]);
    close (stdout_pipe[1]);
    close (stderr_pipe[1]);
  }

  success = frida_wait_for_child_signal (instance->pid, SIGTRAP, NULL);
  CHECK_OS_RESULT (success, !=, FALSE, "wait(SIGTRAP)");

  if (!frida_run_to_entrypoint (instance->pid, error))
    goto failure;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->spawn_instances), GUINT_TO_POINTER (instance->pid), instance);

  goto beach;

chdir_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_ARGUMENT,
        "Unable to change directory to '%s'",
        options->cwd);
    goto failure;
  }
os_failure:
  {
    (void) failed_operation;
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to spawn executable at '%s'",
        path);
    goto failure;
  }
failure:
  {
    g_clear_pointer (&instance, frida_spawn_instance_free);
    goto beach;
  }
beach:
  {
    g_free (old_cwd);
    g_strfreev (envp);
    g_strfreev (argv);

    return (instance != NULL) ? instance->pid : 0;
  }
}

void
_frida_binjector_resume_spawn_instance (FridaBinjector * self, void * instance)
{
  frida_spawn_instance_resume (instance);
}

void
_frida_binjector_free_spawn_instance (FridaBinjector * self, void * instance)
{
  frida_spawn_instance_free (instance);
}

void
_frida_binjector_do_prepare_exec_transition (FridaBinjector * self, guint pid, GError ** error)
{
  FridaExecInstance * instance;

  instance = frida_exec_instance_new (self, pid);

  if (!frida_exec_instance_prepare_transition (instance, error))
    goto failure;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->exec_instances), GUINT_TO_POINTER (pid), instance);

  return;

failure:
  {
    frida_exec_instance_free (instance);
    return;
  }
}

void
_frida_binjector_notify_exec_pending (FridaBinjector * self, guint pid, gboolean pending)
{
  FridaNotifyExecPendingContext ctx;

  ctx.pid = pid;
  ctx.pending = pending;

  gee_abstract_map_foreach (GEE_ABSTRACT_MAP (self->inject_instances),
      (GeeForallFunc) frida_set_matching_inject_instances_exec_pending, &ctx);
}

static gboolean
frida_set_matching_inject_instances_exec_pending (GeeMapEntry * entry, FridaNotifyExecPendingContext * ctx)
{
  FridaInjectInstance * instance;

  instance = (FridaInjectInstance *) gee_map_entry_get_value (entry);
  if (instance->pid == ctx->pid)
  {
    instance->exec_pending = ctx->pending;
  }

  return TRUE;
}

gboolean
_frida_binjector_try_transition_exec_instance (FridaBinjector * self, void * instance, GError ** error)
{
  return frida_exec_instance_try_perform_transition (instance, error);
}

void
_frida_binjector_suspend_exec_instance (FridaBinjector * self, void * instance)
{
  frida_exec_instance_suspend (instance);
}

void
_frida_binjector_resume_exec_instance (FridaBinjector * self, void * instance)
{
  frida_exec_instance_resume (instance);
}

void
_frida_binjector_free_exec_instance (FridaBinjector * self, void * instance)
{
  frida_exec_instance_free (instance);
}

void
_frida_binjector_do_inject (FridaBinjector * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data, const gchar * temp_path, guint id, GError ** error)
{
  FridaInjectParams params;
  guint offset, page_size;
  FridaInjectInstance * instance;
  FridaRegs saved_regs;
  gboolean exited;

  params.pid = pid;

  if (kill (pid, 0) != 0 && errno == EPERM)
    goto permission_denied;

  if (!frida_remote_api_try_init (&params.api, pid))
    goto no_libc;

  params.so_path = path;
  params.entrypoint_name = entrypoint;
  params.entrypoint_data = data;

  params.fifo_path = NULL;

  offset = 0;
  page_size = gum_query_page_size ();

  params.code.offset = offset;
  params.code.size = page_size;
  offset += params.code.size;

  params.data.offset = offset;
  params.data.size = page_size;
  offset += params.data.size;

  params.guard.offset = offset;
  params.guard.size = page_size;
  offset += params.guard.size;

  params.stack.offset = offset;
  params.stack.size = 512 * 1024;
  offset += params.stack.size;

  params.remote_address = 0;
  params.remote_size = offset;

  instance = frida_inject_instance_new (self, id, pid, &params.api, temp_path);
  if (instance->executable_path == NULL)
    goto premature_termination;

  if (!frida_inject_instance_attach (instance, &saved_regs, error))
    goto premature_termination;

  params.fifo_path = instance->fifo_path;
  params.remote_address = frida_remote_alloc (pid, params.remote_size, PROT_READ | PROT_WRITE, &params.api, error);
  if (params.remote_address == 0)
    goto premature_termination;
  instance->remote_payload = params.remote_address;
  instance->remote_size = params.remote_size;

  if (!frida_inject_instance_emit_and_transfer_payload (frida_inject_instance_emit_payload_code, &params, &instance->entrypoint, error))
    goto premature_termination;
  instance->stack_top = params.remote_address + params.stack.offset + params.stack.size;
  instance->trampoline_data = params.remote_address + params.data.offset;

  if (!frida_inject_instance_start_remote_thread (instance, &exited, error) && !exited)
    goto premature_termination;

  if (!exited)
    frida_inject_instance_detach (instance, &saved_regs, NULL);
  else
    g_clear_error (error);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instances), GUINT_TO_POINTER (id), instance);

  return;

permission_denied:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to access process with pid %u due to system restrictions;"
        " try running Frida as root",
        pid);
    return;
  }
no_libc:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to inject library into process without libc");
    return;
  }
premature_termination:
  {
    frida_inject_instance_free (instance, FRIDA_UNLOAD_POLICY_IMMEDIATE);
    return;
  }
}

void
_frida_binjector_demonitor (FridaBinjector * self, void * raw_instance)
{
  FridaInjectInstance * instance = raw_instance;

  frida_inject_instance_recreate_fifo (instance);
}

guint
_frida_binjector_demonitor_and_clone_injectee_state (FridaBinjector * self, void * raw_instance, guint clone_id)
{
  FridaInjectInstance * instance = raw_instance;
  FridaInjectInstance * clone;

  frida_inject_instance_recreate_fifo (instance);

  clone = frida_inject_instance_clone (instance, clone_id);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instances), GUINT_TO_POINTER (clone->id), clone);

  return clone->id;
}

void
_frida_binjector_recreate_injectee_thread (FridaBinjector * self, void * raw_instance, guint pid, GError ** error)
{
  FridaInjectInstance * instance = raw_instance;
  gboolean is_uninitialized_clone;
  FridaRegs saved_regs;
  gboolean exited;

  is_uninitialized_clone = instance->pid == 0;

  instance->pid = pid;

  frida_inject_instance_close_previous_fifo (instance);

  if (!frida_inject_instance_attach (instance, &saved_regs, error))
    goto failure;

  if (is_uninitialized_clone)
  {
    if (!frida_remote_write (pid, instance->trampoline_data + G_STRUCT_OFFSET (FridaTrampolineData, fifo_path),
        instance->fifo_path, strlen (instance->fifo_path) + 1, error))
      goto failure;
  }

  if (!frida_inject_instance_start_remote_thread (instance, &exited, error) && !exited)
    goto failure;

  if (!exited)
    frida_inject_instance_detach (instance, &saved_regs, NULL);
  else
    g_clear_error (error);

  return;

failure:
  {
    _frida_binjector_destroy_inject_instance (self, instance->id, FRIDA_UNLOAD_POLICY_IMMEDIATE);
    return;
  }
}

GInputStream *
_frida_binjector_get_fifo_for_inject_instance (FridaBinjector * self, void * instance)
{
  return g_unix_input_stream_new (((FridaInjectInstance *) instance)->fifo, FALSE);
}

void
_frida_binjector_free_inject_instance (FridaBinjector * self, void * instance, FridaUnloadPolicy unload_policy)
{
  frida_inject_instance_free (instance, unload_policy);
}

gboolean
_frida_process_has_thread (guint pid, glong tid)
{
  return thr_kill2 (pid, tid, 0) == 0;
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaBinjector * binjector)
{
  FridaSpawnInstance * instance;

  instance = g_slice_new0 (FridaSpawnInstance);
  instance->binjector = g_object_ref (binjector);

  return instance;
}

static void
frida_spawn_instance_free (FridaSpawnInstance * instance)
{
  g_object_unref (instance->binjector);

  g_slice_free (FridaSpawnInstance, instance);
}

static void
frida_spawn_instance_resume (FridaSpawnInstance * self)
{
  if (self->interruptible_thread != 0)
  {
    thr_kill2 (self->pid, self->interruptible_thread, SIGSTOP);
    frida_wait_for_child_signal (self->pid, SIGSTOP, NULL);
  }

  ptrace (PT_DETACH, self->pid, NULL, 0);
}

static FridaExecInstance *
frida_exec_instance_new (FridaBinjector * binjector, pid_t pid)
{
  FridaExecInstance * instance;

  instance = g_slice_new0 (FridaExecInstance);
  instance->pid = pid;

  instance->binjector = g_object_ref (binjector);

  return instance;
}

static void
frida_exec_instance_free (FridaExecInstance * instance)
{
  g_object_unref (instance->binjector);

  g_slice_free (FridaExecInstance, instance);
}

static gboolean
frida_exec_instance_prepare_transition (FridaExecInstance * self, GError ** error)
{
  int pt_result;
  const gchar * failed_operation;
  int status;
  pid_t wait_result;

  pt_result = ptrace (PT_ATTACH, self->pid, NULL, 0);
  CHECK_OS_RESULT (pt_result, ==, 0, "PT_ATTACH");

  status = 0;
  wait_result = waitpid (self->pid, &status, 0);
  if (wait_result != self->pid || !WIFSTOPPED (status) || WSTOPSIG (status) != SIGSTOP)
    goto wait_failed;

  pt_result = ptrace (PT_CONTINUE, self->pid, GSIZE_TO_POINTER (1), 0);
  CHECK_OS_RESULT (pt_result, ==, 0, "PT_CONTINUE");

  return TRUE;

os_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to prepare for exec transition: %s failed", failed_operation);
    goto failure;
  }
wait_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to prepare for exec transition: waitpid() failed");
    goto failure;
  }
failure:
  {
    return FALSE;
  }
}

static gboolean
frida_exec_instance_try_perform_transition (FridaExecInstance * self, GError ** error)
{
  int status;
  pid_t wait_result;

  status = 0;
  wait_result = waitpid (self->pid, &status, WNOHANG);
  if (wait_result != self->pid)
    return FALSE;
  if (!WIFSTOPPED (status) || WSTOPSIG (status) != SIGTRAP)
    goto wait_failed;

  if (!frida_run_to_entrypoint (self->pid, error))
    goto failure;

  return TRUE;

wait_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to wait for exec transition: waitpid() failed");
    goto failure;
  }
failure:
  {
    return FALSE;
  }
}

static void
frida_exec_instance_suspend (FridaExecInstance * self)
{
  kill (self->pid, SIGSTOP);
  frida_wait_for_child_signal (self->pid, SIGSTOP, NULL);
}

static void
frida_exec_instance_resume (FridaExecInstance * self)
{
  if (self->interruptible_thread != 0)
  {
    thr_kill2 (self->pid, self->interruptible_thread, SIGSTOP);
    frida_wait_for_child_signal (self->pid, SIGSTOP, NULL);
  }

  ptrace (PT_DETACH, self->pid, NULL, 0);
}

static void
frida_make_pipe (int fds[2])
{
  g_unix_open_pipe (fds, FD_CLOEXEC, NULL);
}

static FridaInjectInstance *
frida_inject_instance_new (FridaBinjector * binjector, guint id, guint pid, const FridaRemoteApi * api, const gchar * temp_path)
{
  FridaInjectInstance * instance;

  instance = g_slice_new0 (FridaInjectInstance);
  instance->id = id;

  instance->pid = pid;
  instance->api = *api;
  instance->executable_path = gum_freebsd_query_program_path_for_pid (pid, NULL);
  instance->already_attached = FALSE;
  instance->exec_pending = FALSE;

  instance->temp_path = g_strdup (temp_path);

  frida_inject_instance_init_fifo (instance);
  instance->previous_fifo = -1;

  instance->binjector = g_object_ref (binjector);

  return instance;
}

static void
frida_inject_instance_recreate_fifo (FridaInjectInstance * self)
{
  frida_inject_instance_close_previous_fifo (self);
  self->previous_fifo = self->fifo;
  unlink (self->fifo_path);
  g_free (self->fifo_path);

  frida_inject_instance_init_fifo (self);
}

static FridaInjectInstance *
frida_inject_instance_clone (const FridaInjectInstance * instance, guint id)
{
  FridaInjectInstance * clone;

  clone = g_slice_dup (FridaInjectInstance, instance);
  clone->id = id;

  clone->pid = 0;
  clone->executable_path = g_strdup (instance->executable_path);
  clone->already_attached = FALSE;
  clone->exec_pending = FALSE;

  clone->temp_path = g_strdup (instance->temp_path);

  frida_inject_instance_init_fifo (clone);
  clone->previous_fifo = -1;

  g_object_ref (clone->binjector);

  return clone;
}

static void
frida_inject_instance_init_fifo (FridaInjectInstance * self)
{
  const int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

  self->fifo_path = g_strdup_printf ("%s/binjector-%u", self->temp_path, self->id);

  mkfifo (self->fifo_path, mode);
  chmod (self->fifo_path, mode);

  self->fifo = open (self->fifo_path, O_RDONLY | O_NONBLOCK);
  g_assert (self->fifo != -1);
}

static void
frida_inject_instance_close_previous_fifo (FridaInjectInstance * self)
{
  if (self->previous_fifo != -1)
  {
    close (self->previous_fifo);
    self->previous_fifo = -1;
  }
}

static void
frida_inject_instance_free (FridaInjectInstance * instance, FridaUnloadPolicy unload_policy)
{
  if (instance->pid != 0 && instance->remote_payload != 0 && unload_policy == FRIDA_UNLOAD_POLICY_IMMEDIATE && !instance->exec_pending)
  {
    FridaRegs saved_regs;

    if (frida_inject_instance_did_not_exec (instance) &&
        frida_inject_instance_attach (instance, &saved_regs, NULL))
    {
      frida_remote_dealloc (instance->pid, instance->remote_payload, instance->remote_size, &instance->api, NULL);
      frida_inject_instance_detach (instance, &saved_regs, NULL);
    }
  }

  frida_inject_instance_close_previous_fifo (instance);
  close (instance->fifo);
  unlink (instance->fifo_path);
  g_free (instance->fifo_path);

  g_free (instance->temp_path);

  g_free (instance->executable_path);

  g_object_unref (instance->binjector);

  g_slice_free (FridaInjectInstance, instance);
}

static gboolean
frida_inject_instance_did_not_exec (FridaInjectInstance * self)
{
  gchar * executable_path;
  gboolean probably_did_not_exec;

  executable_path = gum_freebsd_query_program_path_for_pid (self->pid, NULL);
  if (executable_path == NULL)
    return FALSE;

  probably_did_not_exec = strcmp (executable_path, self->executable_path) == 0;

  g_free (executable_path);

  return probably_did_not_exec;
}

static gboolean
frida_inject_instance_attach (FridaInjectInstance * self, FridaRegs * saved_regs, GError ** error)
{
  const pid_t pid = self->pid;
  int ret;
  int attach_errno;
  const gchar * failed_operation;
  gboolean maybe_already_attached, success;

  ret = ptrace (PT_ATTACH, pid, NULL, 0);
  attach_errno = errno;

  maybe_already_attached = (ret != 0 && attach_errno == EBUSY);
  if (maybe_already_attached)
  {
    ret = frida_get_regs (pid, saved_regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

    self->already_attached = TRUE;
  }
  else
  {
    CHECK_OS_RESULT (ret, ==, 0, "PT_ATTACH");

    self->already_attached = FALSE;

    success = frida_wait_for_attach_signal (pid);
    if (!success)
      goto wait_failed;

    ret = frida_get_regs (pid, saved_regs);
    if (ret != 0)
      goto wait_failed;
  }

  return TRUE;

os_failure:
  {
    if (attach_errno == EPERM)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PERMISSION_DENIED,
          "Unable to access process with pid %u due to system restrictions;"
          " try running Frida as root",
          pid);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while attaching to process with pid %u (%s returned '%s')",
          pid, failed_operation, strerror (errno));
    }

    return FALSE;
  }
wait_failed:
  {
    ptrace (PT_DETACH, pid, NULL, 0);

    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while attaching to process with pid %u",
        pid);

    return FALSE;
  }
}

static gboolean
frida_inject_instance_detach (FridaInjectInstance * self, const FridaRegs * saved_regs, GError ** error)
{
  const pid_t pid = self->pid;
  int ret;
  const gchar * failed_operation;

  ret = frida_set_regs (pid, saved_regs);
  CHECK_OS_RESULT (ret, ==, 0, "frida_set_regs");

  if (self->already_attached)
  {
    lwpid_t * interruptible_thread;
    FridaSpawnInstance * spawn;
    struct ptrace_lwpinfo lwp_info;
    lwpid_t main_thread, threads[2], non_main_thread;

    interruptible_thread = NULL;
    spawn = gee_abstract_map_get (GEE_ABSTRACT_MAP (self->binjector->spawn_instances), GUINT_TO_POINTER (pid));
    if (spawn != NULL)
    {
      interruptible_thread = &spawn->interruptible_thread;
    }
    else
    {
      FridaExecInstance * exec = gee_abstract_map_get (GEE_ABSTRACT_MAP (self->binjector->exec_instances), GUINT_TO_POINTER (pid));
      if (exec != NULL)
        interruptible_thread = &exec->interruptible_thread;
    }
    if (interruptible_thread == NULL)
      return TRUE;

    ret = ptrace (PT_LWPINFO, pid, (caddr_t) &lwp_info, sizeof (lwp_info));
    CHECK_OS_RESULT (ret, ==, 0, "PT_LWPINFO");
    main_thread = lwp_info.pl_lwpid;

    ret = ptrace (PT_GETLWPLIST, pid, (caddr_t) threads, G_N_ELEMENTS (threads));
    CHECK_OS_RESULT (ret, ==, G_N_ELEMENTS (threads), "PT_GETLWPLIST");
    non_main_thread = (threads[0] != main_thread) ? threads[0] : threads[1];
    *interruptible_thread = non_main_thread;

    ret = ptrace (PT_SUSPEND, main_thread, NULL, 0);
    CHECK_OS_RESULT (ret, ==, 0, "PT_SUSPEND");

    ret = ptrace (PT_CONTINUE, pid, GSIZE_TO_POINTER (1), 0);
    CHECK_OS_RESULT (ret, ==, 0, "PT_CONTINUE");
  }
  else
  {
    ret = ptrace (PT_DETACH, pid, NULL, 0);
    CHECK_OS_RESULT (ret, ==, 0, "PT_DETACH");
  }

  return TRUE;

os_failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_OPERATION,
        "detach_from_process %s failed: %s",
        failed_operation, g_strerror (errno));
    return FALSE;
  }
}

static gboolean
frida_inject_instance_start_remote_thread (FridaInjectInstance * self, gboolean * exited, GError ** error)
{
  return frida_remote_exec (self->pid, self->entrypoint, self->stack_top, NULL, exited, error);
}

static gboolean
frida_inject_instance_emit_and_transfer_payload (FridaInjectEmitFunc func, const FridaInjectParams * params, GumAddress * entrypoint, GError ** error)
{
  const pid_t pid = params->pid;
  const FridaRemoteApi * api = &params->api;
  gboolean success = FALSE;
  gpointer scratch_buffer;
  FridaCodeChunk code;
  FridaTrampolineData * data;
  gchar * libthr_name;

  scratch_buffer = g_malloc0 (params->remote_size);

  code.cur = scratch_buffer + params->code.offset;
  code.size = 0;

  func (params, params->remote_address, &code);

  data = (FridaTrampolineData *) (scratch_buffer + params->data.offset);
  libthr_name = _frida_detect_libthr_name ();
  strcpy (data->pthread_so_string, libthr_name);
  g_free (libthr_name);
  strcpy (data->pthread_create_string, "pthread_create");
  strcpy (data->pthread_detach_string, "pthread_detach");
  strcpy (data->pthread_getthreadid_np_string, "pthread_getthreadid_np");
  strcpy (data->fifo_path, params->fifo_path);
  strcpy (data->so_path, params->so_path);
  strcpy (data->entrypoint_name, params->entrypoint_name);
  strcpy (data->entrypoint_data, params->entrypoint_data);
  data->hello_byte = FRIDA_PROGRESS_MESSAGE_TYPE_HELLO;

  if (!frida_remote_write (pid, params->remote_address + params->code.offset, scratch_buffer + params->code.offset, code.size, error))
    goto beach;
  if (!frida_remote_write (pid, params->remote_address + params->data.offset, data, sizeof (FridaTrampolineData), error))
    goto beach;

  if (!frida_remote_mprotect (pid, params->remote_address + params->code.offset, params->code.size, PROT_READ | PROT_EXEC, api, error))
    goto beach;
  if (!frida_remote_mprotect (pid, params->remote_address + params->guard.offset, params->guard.size, PROT_NONE, api, error))
    goto beach;

  *entrypoint = (params->remote_address + params->code.offset);

  success = TRUE;

beach:
  g_free (scratch_buffer);

  return success;
}

#define ARG_IMM(value) \
    GUM_ARG_ADDRESS, GUM_ADDRESS (value)

#if defined (HAVE_I386)

#define EMIT_MOVE(dst, src) \
    gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_##dst, GUM_X86_##src)
#define EMIT_LEA(dst, src, offset) \
    gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_X86_##dst, GUM_X86_##src, offset)
#define EMIT_SUB(reg, value) \
    gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_##reg, value)
#define EMIT_PUSH(reg) \
    gum_x86_writer_put_push_reg (&cw, GUM_X86_##reg)
#define EMIT_POP(reg) \
    gum_x86_writer_put_pop_reg (&cw, GUM_X86_##reg)
#define EMIT_LOAD_FIELD(reg, field) \
    gum_x86_writer_put_mov_reg_near_ptr (&cw, GUM_X86_##reg, FRIDA_REMOTE_DATA_FIELD (field))
#define EMIT_STORE_FIELD(field, reg) \
    gum_x86_writer_put_mov_near_ptr_reg (&cw, FRIDA_REMOTE_DATA_FIELD (field), GUM_X86_##reg)
#define EMIT_LOAD_IMM(reg, value) \
    gum_x86_writer_put_mov_reg_address (&cw, GUM_X86_##reg, value)
#define EMIT_LOAD_REG(dst, src, offset) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_##dst, GUM_X86_##src, offset)
#define EMIT_LOAD_REGV(dst, src, offset) \
    gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, dst, GUM_X86_##src, offset)
#define EMIT_STORE_IMM(dst, offset, value) \
    gum_x86_writer_put_mov_reg_offset_ptr_u32 (&cw, GUM_X86_##dst, offset, value)
#define EMIT_STORE_REG(dst, offset, src) \
    gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_X86_##dst, offset, GUM_X86_##src)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_x86_writer_put_call_address_with_aligned_arguments (&cw, GUM_CALL_CAPI, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_x86_writer_put_call_reg_with_aligned_arguments (&cw, GUM_CALL_CAPI, GUM_X86_##reg, n_args, __VA_ARGS__)
#define EMIT_RET() \
    gum_x86_writer_put_ret (&cw)
#define EMIT_LABEL(name) \
    gum_x86_writer_put_label (&cw, name)
#define EMIT_CMP(reg, value) \
    gum_x86_writer_put_cmp_reg_i32 (&cw, GUM_X86_##reg, value)
#define EMIT_JE(label) \
    gum_x86_writer_put_jcc_short_label (&cw, X86_INS_JE, label, GUM_NO_HINT)
#define EMIT_JNE(label) \
    gum_x86_writer_put_jcc_short_label (&cw, X86_INS_JNE, label, GUM_NO_HINT)

#define ARG_REG(reg) \
    GUM_ARG_REGISTER, GUM_X86_##reg
#define ARG_REGV(reg) \
    GUM_ARG_REGISTER, reg

static void
frida_inject_instance_commit_x86_code (GumX86Writer * cw, FridaCodeChunk * code)
{
  gum_x86_writer_flush (cw);
  code->cur = gum_x86_writer_cur (cw);
  code->size += gum_x86_writer_offset (cw);
}

static void
frida_inject_instance_emit_payload_code (const FridaInjectParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  const FridaRemoteApi * api = &params->api;
  GumX86Writer cw;
  const guint worker_offset = 172;
  gssize fd_offset, unload_policy_offset, tid_offset;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";
  GumX86Reg fd_reg;

  gum_x86_writer_init (&cw, code->cur);
  cw.pc = remote_address + params->code.offset + code->size;

  EMIT_CALL_IMM (api->dlopen_impl,
      2,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_so_string)),
      ARG_IMM (RTLD_GLOBAL | RTLD_LAZY));
  EMIT_STORE_FIELD (pthread_so, XAX);

  EMIT_CALL_IMM (api->dlsym_impl,
      2,
      ARG_REG (XAX),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (pthread_create_string)));

  EMIT_CALL_REG (XAX,
      4,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (worker_thread)),
      ARG_IMM (0),
      ARG_IMM (remote_address + worker_offset),
      ARG_IMM (0));

  gum_x86_writer_put_breakpoint (&cw);
  gum_x86_wri
"""


```