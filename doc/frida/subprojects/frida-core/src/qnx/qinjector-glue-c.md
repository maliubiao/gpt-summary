Response:
Let's break down the thought process for analyzing the provided C code.

1. **Understand the Goal:** The request asks for a functional breakdown, connection to reverse engineering, low-level details (binary, OS kernels, frameworks), logical reasoning, error handling examples, and the user journey leading to this code. Essentially, it wants a comprehensive understanding of what this code *does* and *how* it fits into the larger Frida picture.

2. **Initial Scan and Keyword Recognition:**  A quick scan reveals keywords like `frida`, `qinjector`, `QNX`, `gum`, `dlopen`, `dlsym`, `pthread_create`, `mmap`, `munmap`, `/proc/`, `devctl`, `ARM_REG_*`, etc. These immediately hint at dynamic instrumentation, QNX as the target OS, memory manipulation, thread creation, system calls, and ARM architecture specifics.

3. **Core Function Identification (The "What"):**  The filename `qinjector-glue.c` suggests this code acts as a bridge or interface. The presence of `_frida_qinjector_do_inject` strongly indicates the primary function: injecting code into a running process on QNX. Other functions like `frida_remote_alloc`, `frida_remote_dealloc`, `frida_remote_pthread_create`, and `frida_remote_call` further solidify this by describing the individual steps involved in code injection.

4. **Reverse Engineering Connection (The "Why It's Relevant"):** The code explicitly deals with inspecting and modifying the state of a running process. This is the core of dynamic analysis, a fundamental reverse engineering technique. The ability to inject code and execute it within a target process allows for observing behavior, intercepting function calls, modifying data, and more. Think about how a reverse engineer would use these primitives.

5. **Low-Level Details (The "How It Works Under the Hood"):**

    * **Binary Level:** The code uses `gum` which is a library for code generation. The `GumArmWriter` indicates it's generating ARM assembly. The `EMIT_*` macros are assembly instructions. The manipulation of registers like PC, LR, and SP is direct binary-level interaction.
    * **QNX Kernel:** The heavy use of `devctl` with `DCMD_PROC_*` commands directly interacts with the QNX kernel's process debugging interface. Functions like `ChannelCreate_r`, `MsgSendPulse_r`, `ConnectAttach_r`, and `ConnectDetach_r` are specific to QNX inter-process communication. The file operations within `/proc/` are also QNX-specific.
    * **No Android/Linux Kernel or Framework Mention:** Acknowledge the *absence* of these elements. The code is explicitly targeting QNX.

6. **Logical Reasoning (The "If-Then"):** Focus on the control flow within key functions. `_frida_qinjector_do_inject` allocates memory, emits code, and starts a thread. `frida_emit_payload_code` constructs the ARM assembly payload based on the injection parameters. `frida_remote_call` carefully stops the target thread, modifies registers, executes the injected code, and restores the original state. The `if` statements around `dlopen`/`dlclose` and `pthread_detach` demonstrate conditional execution based on the unload policy. Consider what inputs would trigger these different branches.

7. **Error Handling (The "What Could Go Wrong"):** Look for `GError ** error` parameters and the use of `g_set_error`. Identify specific error conditions like failing to allocate memory, open files, or perform `devctl` operations. Think about common programming errors that might lead to these failures (e.g., incorrect file paths, insufficient permissions).

8. **User Journey (The "How Did We Get Here"):**  Trace back the steps a user would take to trigger this code. A user would typically use the Frida API to target a QNX process for injection. This API call would eventually lead to the `_frida_qinjector_do_inject` function in this file. Emphasize the user's high-level intent and how Frida translates that into low-level actions.

9. **Structure and Clarity:** Organize the findings into clear categories based on the prompt's requirements. Use examples to illustrate points. Maintain a consistent level of detail and avoid overly technical jargon where possible.

10. **Review and Refine:**  Read through the analysis to ensure accuracy, completeness, and clarity. Check for any missing points or areas that could be explained better. For instance, initially, I might not have explicitly mentioned the role of `frida_resolve_remote_libc_function` in locating library functions, and a review would catch this.

By following this systematic approach, we can effectively analyze the given C code and provide a comprehensive response that addresses all aspects of the request. The key is to combine code reading with an understanding of the underlying operating system and the goals of dynamic instrumentation.
好的，让我们详细分析一下 `frida/subprojects/frida-core/src/qnx/qinjector-glue.c` 文件的功能。

**文件功能概述**

这个文件是 Frida 动态Instrumentation工具在 QNX 操作系统上的一个核心组件，负责将 Frida 的 Agent 代码注入到目标进程中。  它主要实现了以下功能：

1. **目标进程内存分配:**  在目标进程中分配一块可读、可写、可执行的内存区域，用于存放即将注入的代码和数据。
2. **payload 代码生成:**  生成一段小的汇编代码（称为 payload），这段代码会在目标进程中执行，负责加载 Frida Agent 动态库并启动 Agent。
3. **数据准备:**  准备注入所需的各种数据，例如目标 so 库的路径、入口函数名称、以及传递给入口函数的数据等。
4. **远程写入:**  将生成的 payload 代码和准备好的数据写入到目标进程之前分配的内存区域。
5. **指令缓存失效:**  通知目标进程使指令缓存失效，确保新写入的代码能够被正确执行。
6. **远程线程创建:**  在目标进程中创建一个新的线程来执行注入的 payload 代码。
7. **远程函数调用:**  提供了一种通用的机制，可以在目标进程中调用任意函数，这对于 payload 的执行和控制至关重要。
8. **库函数地址解析:**  能够在目标进程中解析标准 C 库 (`libc`) 和其他共享库中函数的地址，这使得 payload 代码可以调用这些函数。
9. **动态库基址查找:**  可以找到目标进程中已加载动态库的基址。
10. **资源管理:**  管理注入实例，包括创建、跟踪和清理注入相关的资源。

**与逆向方法的关联及举例说明**

这个文件直接服务于动态逆向分析。通过 Frida，逆向工程师可以将自定义的代码注入到目标进程中，从而：

* **Hook 函数:**  拦截目标进程中关键函数的调用，在函数执行前后执行自定义代码，例如打印函数参数、修改返回值、监控函数行为等。
    * **举例:** 假设要逆向一个 QNX 上的网络服务，可以 hook `recv()` 函数来查看接收到的网络数据包内容。注入的 payload 代码会找到 `recv()` 的地址，然后在调用 `recv()` 前后执行自定义的打印逻辑。
* **代码插桩:**  在目标进程的关键代码段插入额外的代码，用于监控程序状态、收集运行信息、甚至修改程序行为。
    * **举例:**  在某个加密算法的关键循环中插入代码，记录每次循环的中间变量值，以便分析加密过程。
* **内存分析:**  通过注入的代码，可以读取和修改目标进程的内存，用于分析数据结构、查找敏感信息、甚至修改程序逻辑。
    * **举例:**  在游戏逆向中，可以注入代码来查找和修改玩家的金币数量。
* **动态调试:**  虽然 Frida 不是传统的调试器，但它提供的代码注入和执行能力可以实现类似动态调试的功能，例如断点模拟、单步执行（通过更复杂的 hook 实现）等。

**涉及到的二进制底层、Linux、Android 内核及框架知识**

* **二进制底层知识:**
    * **ARM 汇编:** 代码中使用了 `gum/arch-arm/gumarmwriter.h` 和 `gum/arch-arm/gumthumbwriter.h`，说明目标架构是 ARM。生成的 payload 代码就是 ARM 汇编指令。
    * **寄存器操作:** 代码中定义了 `GUM_QNX_ARM_REG_*` 等常量，直接操作 ARM 架构的寄存器，例如程序计数器 (PC)、链接寄存器 (LR)、栈指针 (SP) 等。在 `frida_emit_payload_code` 函数中，可以看到如何设置这些寄存器的值，以控制程序的执行流程。
    * **函数调用约定:**  `frida_remote_call` 函数需要了解 ARM 的函数调用约定，如何传递参数、如何获取返回值等。
    * **内存布局:**  代码中定义了 `FRIDA_REMOTE_PAYLOAD_SIZE`、`FRIDA_REMOTE_DATA_OFFSET`、`FRIDA_REMOTE_STACK_OFFSET` 等常量，描述了在目标进程中分配的内存区域的布局，用于存放代码、数据和栈。
* **QNX 内核知识:**
    * **进程管理:**  代码中使用了 `pid_t` 来表示进程 ID，并使用 `/proc/<pid>/as` 文件来访问目标进程的地址空间进行读写操作。
    * **线程管理:**  使用了 `pthread_create` 在目标进程中创建新线程。
    * **进程间通信 (IPC):** 使用了 QNX 特有的 `ChannelCreate_r`、`MsgSendPulse_r`、`ConnectAttach_r`、`ConnectDetach_r` 等函数来实现 Frida Agent 和 Frida 服务之间的通信。
    * **`devctl` 系统调用:**  大量使用了 `devctl` 系统调用，这是 QNX 中用于设备控制的通用接口，在这里用于进行进程调试相关的操作，例如停止/继续进程 (`DCMD_PROC_STOP`/`DCMD_PROC_RUN`)、获取/设置寄存器 (`DCMD_PROC_GETGREG`/`DCMD_PROC_SETGREG`)、获取进程状态 (`DCMD_PROC_TIDSTATUS`)、获取内存映射信息 (`DCMD_PROC_PAGEDATA`/`DCMD_PROC_MAPDEBUG`) 等。
    * **信号:** 使用了信号 (`SIGHUP`, `FLTPAGE`) 来控制目标进程的执行流程。
* **Linux 和 Android 内核/框架知识 (间接相关):**
    * 虽然此文件是 QNX 特有的，但理解 Linux/Android 的进程和线程模型、内存管理机制、动态链接原理等概念，有助于理解其在 QNX 上的对应实现。例如，`dlopen`/`dlsym`/`dlclose` 是 POSIX 标准的动态链接函数，在各个操作系统上的作用是类似的。

**逻辑推理、假设输入与输出**

假设我们调用 Frida 的 API，指示要将一个名为 `my_agent.so` 的库注入到 PID 为 `1234` 的 QNX 进程中，并且要执行该库中的 `my_entrypoint` 函数，并传递字符串数据 `"hello"`。

* **假设输入:**
    * `pid = 1234`
    * `path = "my_agent.so"`
    * `entrypoint = "my_entrypoint"`
    * `data = "hello"`
* **逻辑推理过程:**
    1. `_frida_qinjector_do_inject` 函数被调用，接收到上述参数。
    2. `frida_injection_instance_new` 创建一个新的注入实例，并创建一个 QNX channel 用于通信。
    3. `frida_remote_alloc` 在目标进程 (PID 1234) 中分配一块内存区域，用于存放 payload。
    4. `frida_emit_payload_code` 函数生成 ARM 汇编 payload，这段 payload 的逻辑大致如下：
        * 连接到 Frida 的通信 channel。
        * 发送一个 "hello" 脉冲。
        * 使用 `dlopen` 加载 `my_agent.so` 到目标进程。
        * 使用 `dlsym` 找到 `my_entrypoint` 函数的地址。
        * 调用 `my_entrypoint` 函数，传递数据 `"hello"` 以及一些 Frida 内部的参数。
        * 根据卸载策略，可能调用 `dlclose` 卸载库或 `pthread_detach` 分离线程。
        * 发送一个 "bye" 脉冲。
        * 断开通信 channel。
    5. payload 中的 `strcpy` 将 `my_agent.so`、`my_entrypoint`、`hello` 等信息拷贝到目标进程的内存中。
    6. `frida_remote_write` 将生成的 payload 代码和数据写入到目标进程的内存。
    7. `frida_remote_msync` 使目标进程的指令缓存失效。
    8. `frida_remote_pthread_create` 在目标进程中创建一个新线程，并将 payload 代码的起始地址设置为该线程的入口点，从而启动 payload 的执行。
* **假设输出:**
    * 如果一切顺利，目标进程 (PID 1234) 会加载 `my_agent.so`，并执行 `my_entrypoint` 函数，该函数可以访问到传递的 `"hello"` 数据。
    * Frida 的控制端会收到来自目标进程的 "hello" 和 "bye" 脉冲，表明注入过程已完成。

**用户或编程常见的使用错误及举例说明**

1. **SO 库路径错误:**  用户提供的 `so_path` 不存在或目标进程无法访问。
    * **举例:**  用户将 Agent 库放在 `/tmp/my_agent.so`，但目标进程的权限限制无法访问该路径。
    * **调试线索:**  `frida_remote_alloc` 可能会成功，但 `frida_emit_payload_code` 中生成的 payload 在 `dlopen` 时会失败，导致 Agent 无法加载。在 Frida 的控制台上可能会看到 `dlopen` 相关的错误信息。
2. **入口点名称错误:**  用户提供的 `entrypoint_name` 在目标 SO 库中不存在。
    * **举例:**  用户将入口点名称拼写错误，例如将 `my_entrypoint` 写成 `my_entypoint`。
    * **调试线索:**  Payload 在执行 `dlsym` 时会返回 NULL，导致后续调用该地址时发生错误。Frida 控制台可能会显示找不到符号的错误。
3. **权限不足:**  运行 Frida 的用户没有足够的权限访问目标进程或执行注入操作。
    * **举例:**  目标进程属于 root 用户，但运行 Frida 的用户是普通用户。
    * **调试线索:**  在尝试打开 `/proc/<pid>/as` 文件或调用 `devctl` 时可能会失败，返回 `-1` 并设置 `errno`。Frida 控制台会显示权限相关的错误信息。
4. **目标进程状态异常:**  目标进程处于不稳定的状态，例如正在崩溃或被其他调试器占用。
    * **举例:**  目标进程已经挂起或正在被 gdb 调试。
    * **调试线索:**  `DCMD_PROC_STOP` 或 `DCMD_PROC_WAITSTOP` 可能会失败或超时。
5. **QNX 版本或配置不兼容:**  Frida 版本与目标 QNX 系统的版本或配置不兼容。
    * **举例:**  Frida 依赖的某些 QNX 特性在目标系统上不存在。
    * **调试线索:**  可能会在不同的 `devctl` 调用中遇到未知的错误码。

**用户操作如何一步步到达这里，作为调试线索**

1. **用户编写 Frida 脚本:**  用户编写 JavaScript 或 Python 代码，使用 Frida 的 API 来连接到目标 QNX 进程，并指定要注入的 SO 库路径、入口点等信息。
   ```python
   import frida
   import sys

   def on_message(message, data):
       if message['type'] == 'send':
           print("[*] {}: {}".format(message['payload']))
       else:
           print(message)

   process = frida.attach(sys.argv[1]) # 用户通过命令行参数指定目标进程 PID
   script = process.create_script("""
       // JavaScript 代码，例如 hook 函数
       Interceptor.attach(Module.findExportByName(null, "recv"), {
           onEnter: function(args) {
               send("recv called with arg1: " + args[0]);
           }
       });
   """)
   script.on('message', on_message)
   script.load()
   sys.stdin.read()
   ```
2. **用户运行 Frida 脚本:**  用户通过命令行运行编写的 Frida 脚本，并指定目标进程的 PID。
   ```bash
   python my_frida_script.py 1234
   ```
3. **Frida 控制端处理请求:**  Frida 的 Python 绑定将用户的请求传递给 Frida 的核心组件。
4. **选择合适的注入器:**  Frida 核心会根据目标操作系统 (QNX) 选择合适的注入器，即 `frida-core/src/qnx/qinjector-glue.c` 中的代码。
5. **调用 `_frida_qinjector_do_inject`:**  Frida 核心调用 `_frida_qinjector_do_inject` 函数，并将用户提供的 SO 库路径、入口点等信息作为参数传递进来。
6. **后续的内存分配、payload 生成、远程写入、线程创建等操作:**  如前面所述，`_frida_qinjector_do_inject` 及其调用的其他函数会执行一系列底层操作，将 Agent 代码注入到目标进程中。

**作为调试线索:**

当 Frida 注入失败或出现异常时，理解用户操作的路径可以帮助定位问题：

* **检查用户提供的参数:**  首先检查用户在 Frida 脚本中提供的目标进程 PID、SO 库路径、入口点名称等是否正确。
* **查看 Frida 控制台输出:**  Frida 通常会将错误信息输出到控制台，例如 `dlopen` 失败、找不到符号等。
* **使用 Frida 的调试功能:**  Frida 提供了一些调试选项，可以输出更详细的日志信息，帮助开发者了解注入过程中的具体步骤和状态。
* **分析 `qinjector-glue.c` 中的日志和错误处理:**  虽然此代码片段中没有显式的日志输出，但在实际的 Frida 实现中，可能会有更详细的日志记录。理解代码中的错误处理逻辑，可以根据错误信息判断是哪个环节出了问题，例如是内存分配失败、远程写入失败还是线程创建失败。
* **结合 QNX 系统的调试工具:**  如果问题难以定位，可能需要结合 QNX 系统提供的调试工具，例如 System Information Perspective (SIP) 或 Momentics IDE，来查看目标进程的状态、内存布局等信息。

总而言之，`frida/subprojects/frida-core/src/qnx/qinjector-glue.c` 文件是 Frida 在 QNX 平台上实现动态 Instrumentation 的关键组成部分，它涉及到深入的操作系统底层知识和二进制编程技巧，为逆向工程师提供了强大的代码注入和执行能力。理解其功能和实现细节，对于调试 Frida 的注入问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-core/src/qnx/qinjector-glue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#include "frida-core.h"

#include <gio/gunixinputstream.h>
#include <gum/arch-arm/gumarmwriter.h>
#include <gum/arch-arm/gumthumbwriter.h>
#include <gum/gum.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/debug.h>
#include <sys/mman.h>
#include <sys/netmgr.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/states.h>
#include <sys/types.h>
#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif
#include <sys/wait.h>

enum {
  GUM_QNX_ARM_REG_PC = ARM_REG_PC,
  GUM_QNX_ARM_REG_LR = ARM_REG_LR,
  GUM_QNX_ARM_REG_SP = ARM_REG_SP,
  GUM_QNX_ARM_REG_R0 = ARM_REG_R0
};
#undef ARM_REG_R0
#undef ARM_REG_R1
#undef ARM_REG_R2
#undef ARM_REG_R3
#undef ARM_REG_R4
#undef ARM_REG_R5
#undef ARM_REG_R6
#undef ARM_REG_R7
#undef ARM_REG_R8
#undef ARM_REG_R9
#undef ARM_REG_R10
#undef ARM_REG_R11
#undef ARM_REG_R12
#undef ARM_REG_R13
#undef ARM_REG_R14
#undef ARM_REG_R15
#undef ARM_REG_SPSR
#undef ARM_REG_FP
#undef ARM_REG_IP
#undef ARM_REG_SP
#undef ARM_REG_LR
#undef ARM_REG_PC

#define PSR_T_BIT (1 << 5)

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto os_failure; \
  }

#define FRIDA_REMOTE_PAYLOAD_SIZE (8192)
#define FRIDA_REMOTE_DATA_OFFSET (512)
#define FRIDA_REMOTE_STACK_OFFSET (FRIDA_REMOTE_PAYLOAD_SIZE - 512)
#define FRIDA_REMOTE_DATA_FIELD(n) \
    remote_address + FRIDA_REMOTE_DATA_OFFSET + G_STRUCT_OFFSET (FridaTrampolineData, n)

typedef struct _FridaInjectionInstance FridaInjectionInstance;
typedef struct _FridaInjectionParams FridaInjectionParams;
typedef struct _FridaCodeChunk FridaCodeChunk;
typedef struct _FridaTrampolineData FridaTrampolineData;
typedef struct _FridaFindLandingStripContext FridaFindLandingStripContext;

typedef void (* FridaEmitFunc) (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code);

struct _FridaInjectionInstance
{
  FridaQinjector * qinjector;
  guint id;
  pid_t pid;
  gboolean already_attached;
  int channel_id;
  GumAddress remote_payload;
};

struct _FridaInjectionParams
{
  pid_t pid;
  const gchar * so_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;

  int channel_id;
  GumAddress remote_address;
};

struct _FridaCodeChunk
{
  guint8 * cur;
  gsize size;
  guint8 bytes[2048];
};

struct _FridaTrampolineData
{
  gchar so_path[256];
  gchar entrypoint_name[256];
  gchar entrypoint_data[256];

  pthread_t worker_thread;
  gpointer module_handle;
};

struct _FridaFindLandingStripContext
{
  pid_t pid;
  GumAddress result;
};

static gboolean frida_emit_and_remote_execute (FridaEmitFunc func, const FridaInjectionParams * params, GumAddress * result, GError ** error);

static void frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code);

static GumAddress frida_remote_alloc (pid_t pid, size_t size, int prot, GError ** error);
static int frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, GError ** error);
static int frida_remote_pthread_create (pid_t pid, GumAddress address, GError ** error);
static int frida_remote_msync (pid_t pid, GumAddress remote_address, gint size, gint flags, GError ** error);
static gboolean frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean frida_remote_write_fd (gint fd, GumAddress remote_address, gconstpointer data, gsize size, GError ** error);
static gboolean frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, GError ** error);

static GumAddress frida_resolve_remote_libc_function (int remote_pid, const gchar * function_name);

static GumAddress frida_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name);
static GumAddress frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path);

static FridaInjectionInstance *
frida_injection_instance_new (FridaQinjector * qinjector, guint id, pid_t pid, const char * temp_path)
{
  FridaInjectionInstance * instance;

  instance = g_slice_new0 (FridaInjectionInstance);
  instance->qinjector = g_object_ref (qinjector);
  instance->id = id;
  instance->pid = pid;
  instance->already_attached = FALSE;

  instance->channel_id = ChannelCreate_r (_NTO_CHF_DISCONNECT);

  return instance;
}

static void
frida_injection_instance_free (FridaInjectionInstance * instance, FridaUnloadPolicy unload_policy)
{
  if (instance->remote_payload != 0 && unload_policy == FRIDA_UNLOAD_POLICY_IMMEDIATE)
  {
    GError * error = NULL;

    frida_remote_dealloc (instance->pid, instance->remote_payload, FRIDA_REMOTE_PAYLOAD_SIZE, &error);

    g_clear_error (&error);
  }

  ChannelDestroy_r (instance->channel_id);
  g_object_unref (instance->qinjector);
  g_slice_free (FridaInjectionInstance, instance);
}

void
_frida_remote_thread_session_receive_pulse (void * opaque_instance, FridaQnxPulseCode * code, gint * val, GError ** error)
{
  FridaInjectionInstance * instance = opaque_instance;
  int res;
  struct _pulse pulse;

  res = MsgReceivePulse_r (instance->channel_id, &pulse, sizeof (pulse), NULL);
  if (res != EOK)
    goto failure;

  *code = pulse.code;
  *val = pulse.value.sival_int;

  return;

failure:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_OPERATION,
        "Unable to receive pulse: %s",
        strerror (-res));
    return;
  }
}

gboolean
_frida_remote_thread_session_thread_is_alive (guint pid, guint tid)
{
  gboolean alive = FALSE;
  gchar * path;
  gint fd;
  procfs_status status;

  path = g_strdup_printf ("/proc/%u", pid);

  fd = open (path, O_RDONLY);
  if (fd == -1)
    goto beach;

  status.tid = tid;
  if (devctl (fd, DCMD_PROC_TIDSTATUS, &status, sizeof (status), NULL) != EOK)
    goto beach;

  alive = status.tid == tid;

beach:
  if (fd != -1)
    close (fd);

  g_free (path);

  return alive;
}

void
_frida_qinjector_free_instance (FridaQinjector * self, void * instance, FridaUnloadPolicy unload_policy)
{
  frida_injection_instance_free (instance, unload_policy);
}

guint
_frida_qinjector_do_inject (FridaQinjector * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data,
    const gchar * temp_path, GError ** error)
{
  FridaInjectionInstance * instance;
  FridaInjectionParams params = { pid, path, entrypoint, data };

  instance = frida_injection_instance_new (self, self->next_instance_id++, pid, temp_path);

  params.channel_id = instance->channel_id;
  params.remote_address = frida_remote_alloc (pid, FRIDA_REMOTE_PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, error);
  if (params.remote_address == 0)
    goto beach;
  instance->remote_payload = params.remote_address;

  if (!frida_emit_and_remote_execute (frida_emit_payload_code, &params, NULL, error))
    goto beach;

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instances), GUINT_TO_POINTER (instance->id), instance);

  return instance->id;

beach:
  {
    frida_injection_instance_free (instance, FRIDA_UNLOAD_POLICY_IMMEDIATE);
    return 0;
  }
}

static gboolean
frida_emit_and_remote_execute (FridaEmitFunc func, const FridaInjectionParams * params, GumAddress * result,
    GError ** error)
{
  FridaCodeChunk code;
  FridaTrampolineData * data;

  code.cur = code.bytes;
  code.size = 0;

  func (params, GUM_ADDRESS (params->remote_address), &code);

  data = (FridaTrampolineData *) (code.bytes + FRIDA_REMOTE_DATA_OFFSET);
  strcpy (data->so_path, params->so_path);
  strcpy (data->entrypoint_name, params->entrypoint_name);
  strcpy (data->entrypoint_data, params->entrypoint_data);
  data->worker_thread = 0;
  data->module_handle = NULL;

  if (!frida_remote_write (params->pid, params->remote_address, code.bytes, FRIDA_REMOTE_DATA_OFFSET + sizeof (FridaTrampolineData), error))
    return FALSE;

  /*
   * We need to flush the data cache and invalidate the instruction cache before
   * trying to run the generated code.
   */
  if (frida_remote_msync (params->pid, params->remote_address, FRIDA_REMOTE_PAYLOAD_SIZE, MS_INVALIDATE_ICACHE, error) != 0)
    return FALSE;

  if (frida_remote_pthread_create (params->pid, params->remote_address, error) != 0)
    return FALSE;

  return TRUE;
}

#define EMIT_MOVE(dst, src) \
    gum_arm_writer_put_mov_reg_reg (&cw, ARM_REG_##dst, ARM_REG_##src)
#define EMIT_ADD(dst, src, offset) \
    gum_arm_writer_put_add_reg_reg_imm (&cw, ARM_REG_##dst, ARM_REG_##src, offset)
#define EMIT_LOAD_FIELD(reg, field) \
    gum_arm_writer_put_ldr_reg_address (&cw, ARM_REG_##reg, FRIDA_REMOTE_DATA_FIELD (field)); \
    EMIT_LDR (reg, reg)
#define EMIT_STORE_FIELD(field, reg) \
    gum_arm_writer_put_ldr_reg_address (&cw, ARM_REG_R0, FRIDA_REMOTE_DATA_FIELD (field)); \
    gum_arm_writer_put_str_reg_reg_offset (&cw, ARM_REG_##reg, ARM_REG_R0, 0)
#define EMIT_LDR(dst, src) \
    gum_arm_writer_put_ldr_reg_reg_offset (&cw, ARM_REG_##dst, ARM_REG_##src, 0)
#define EMIT_LDR_U32(reg, value) \
    gum_arm_writer_put_ldr_reg_u32 (&cw, ARM_REG_##reg, value)
#define EMIT_CALL_IMM(func, n_args, ...) \
    gum_arm_writer_put_call_address_with_arguments (&cw, func, n_args, __VA_ARGS__)
#define EMIT_CALL_REG(reg, n_args, ...) \
    gum_arm_writer_put_call_reg_with_arguments (&cw, ARM_REG_##reg, n_args, __VA_ARGS__)
#define EMIT_LABEL(name) \
    gum_arm_writer_put_label (&cw, name)
#define EMIT_CMP(reg, imm) \
    gum_arm_writer_put_cmp_reg_imm (&cw, ARM_REG_##reg, imm)
#define EMIT_B_COND(cond, label) \
    gum_arm_writer_put_b_cond_label (&cw, ARM_CC_##cond, label)

#define ARG_IMM(value) \
    GUM_ARG_ADDRESS, GUM_ADDRESS (value)
#define ARG_REG(reg) \
    GUM_ARG_REGISTER, ARM_REG_##reg

static void
frida_emit_payload_code (const FridaInjectionParams * params, GumAddress remote_address, FridaCodeChunk * code)
{
  GumArmWriter cw;
  const gchar * skip_dlopen = "skip_dlopen";
  const gchar * skip_dlclose = "skip_dlclose";
  const gchar * skip_detach = "skip_detach";

  gum_arm_writer_init (&cw, code->cur);

  gum_arm_writer_put_push_regs (&cw, 4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);

  EMIT_CALL_IMM (frida_resolve_remote_libc_function (params->pid, "ConnectAttach_r"),
      5,
      ARG_IMM (ND_LOCAL_NODE),
      ARG_IMM (getpid ()),
      ARG_IMM (params->channel_id),
      ARG_IMM (_NTO_SIDE_CHANNEL),
      ARG_IMM (_NTO_COF_CLOEXEC));
  EMIT_MOVE (R7, R0);

  gum_arm_writer_put_call_address_with_arguments (&cw, frida_resolve_remote_libc_function (params->pid, "gettid"), 0);
  EMIT_MOVE (R3, R0);

  EMIT_CALL_IMM (frida_resolve_remote_libc_function (params->pid, "MsgSendPulse_r"),
      4,
      ARG_REG (R7),
      ARG_IMM (-1),
      ARG_IMM (FRIDA_QNX_PULSE_CODE_HELLO),
      ARG_REG (R3));

  EMIT_LOAD_FIELD (R6, module_handle);
  EMIT_CMP (R6, 0);
  EMIT_B_COND (NE, skip_dlopen);
  {
    EMIT_CALL_IMM (frida_resolve_remote_libc_function (params->pid, "dlopen"),
        2,
        ARG_IMM (FRIDA_REMOTE_DATA_FIELD (so_path)),
        ARG_IMM (RTLD_LAZY));
    EMIT_MOVE (R6, R0);
    EMIT_STORE_FIELD (module_handle, R6);
  }
  EMIT_LABEL (skip_dlopen);

  EMIT_CALL_IMM (frida_resolve_remote_libc_function (params->pid, "dlsym"),
      2,
      ARG_REG (R6),
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_name)));
  gum_arm_writer_put_mov_reg_reg (&cw, ARM_REG_R5, ARM_REG_R0);

  EMIT_LDR_U32 (R0, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  gum_arm_writer_put_push_regs (&cw, 2, ARM_REG_R0, ARM_REG_R7);
  EMIT_MOVE (R1, SP);
  EMIT_ADD (R2, SP, 4);
  EMIT_CALL_REG (R5,
      3,
      ARG_IMM (FRIDA_REMOTE_DATA_FIELD (entrypoint_data)),
      ARG_REG (R1),
      ARG_REG (R2));

  EMIT_LDR (R0, SP);
  EMIT_CMP (R0, FRIDA_UNLOAD_POLICY_IMMEDIATE);
  EMIT_B_COND (NE, skip_dlclose);
  {
    EMIT_CALL_IMM (frida_resolve_remote_libc_function (params->pid, "dlclose"),
        1,
        ARG_REG (R6));
  }
  EMIT_LABEL (skip_dlclose);

  EMIT_LDR (R0, SP);
  EMIT_CMP (R0, FRIDA_UNLOAD_POLICY_DEFERRED);
  EMIT_B_COND (EQ, skip_detach);
  {
    EMIT_LOAD_FIELD (R0, worker_thread);
    EMIT_CALL_IMM (frida_resolve_remote_libc_function (params->pid, "pthread_detach"),
        1,
        ARG_REG (R0));
  }
  EMIT_LABEL (skip_detach);

  EMIT_LDR (R3, SP);
  EMIT_CALL_IMM (frida_resolve_remote_libc_function (params->pid, "MsgSendPulse_r"),
      4,
      ARG_REG (R7),
      ARG_IMM (-1),
      ARG_IMM (FRIDA_QNX_PULSE_CODE_BYE),
      ARG_REG (R3));

  EMIT_CALL_IMM (frida_resolve_remote_libc_function (params->pid, "ConnectDetach_r"),
      1,
      ARG_REG (R7));

  gum_arm_writer_put_pop_regs (&cw, 2, ARM_REG_R0, ARM_REG_R7);

  gum_arm_writer_put_pop_regs (&cw, 4, ARM_REG_R5, ARM_REG_R6, ARM_REG_R7, ARM_REG_PC);

  gum_arm_writer_flush (&cw);
  code->cur = gum_arm_writer_cur (&cw);
  code->size += gum_arm_writer_offset (&cw);
  gum_arm_writer_clear (&cw);
}

static GumAddress
frida_remote_alloc (pid_t pid, size_t size, int prot, GError ** error)
{
  GumAddress args[] = {
    0,
    size,
    prot,
    MAP_PRIVATE | MAP_ANONYMOUS,
    -1,
    0
  };
  GumAddress retval = 0;
  GumAddress function = frida_resolve_remote_libc_function (pid, "mmap");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_alloc failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!frida_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return 0;

  if (retval == G_GUINT64_CONSTANT (0xffffffffffffffff))
    return 0;

  return retval;
}

static int
frida_remote_dealloc (pid_t pid, GumAddress address, size_t size, GError ** error)
{
  GumAddress args[] = {
    address,
    size
  };
  GumAddress retval;
  GumAddress function = frida_resolve_remote_libc_function (pid, "munmap");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_dealloc failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!frida_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static int
frida_remote_pthread_create (pid_t pid, GumAddress remote_address, GError ** error)
{
  GumAddress args[] = {
    FRIDA_REMOTE_DATA_FIELD (worker_thread),
    0,
    remote_address,
    0
  };
  GumAddress retval;
  GumAddress function = frida_resolve_remote_libc_function (pid, "pthread_create");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_pthread_create failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!frida_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static int
frida_remote_msync (pid_t pid, GumAddress remote_address, gint size, gint flags, GError ** error)
{
  GumAddress args[] = {
    remote_address,
    size,
    flags
  };
  GumAddress retval;
  GumAddress function = frida_resolve_remote_libc_function (pid, "msync");

  if (function == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_msync failed on pid: %d, errno: %d", pid, errno);
    return -1;
  }

  if (!frida_remote_call (pid, function, args, G_N_ELEMENTS (args), &retval, error))
    return -1;

  return retval;
}

static gboolean
frida_remote_write (pid_t pid, GumAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  gint fd;
  gchar as_path[PATH_MAX];
  gboolean result;

  sprintf (as_path, "/proc/%d/as", pid);
  fd = open (as_path, O_RDWR);
  if (fd == -1)
    return FALSE;

  result = frida_remote_write_fd (fd, remote_address, data, size, error);

  close (fd);

  return result;
}

static gboolean
frida_remote_write_fd (gint fd, GumAddress remote_address, gconstpointer data, gsize size, GError ** error)
{
  long ret;
  const gchar * failed_operation;

  ret = lseek (fd, GPOINTER_TO_SIZE (remote_address), SEEK_SET);
  CHECK_OS_RESULT (ret, ==, remote_address, "seek to address");

  ret = write (fd, data, size);
  CHECK_OS_RESULT (ret, ==, size, "write data");

  return TRUE;

os_failure:
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_write %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static gboolean
frida_remote_call (pid_t pid, GumAddress func, const GumAddress * args, gint args_length, GumAddress * retval, GError ** error)
{
  gboolean success = FALSE;
  gint ret;
  const gchar * failed_operation;
  gint fd;
  gint i;
  gchar as_path[PATH_MAX];
  pthread_t tid;
  debug_thread_t thread;
  procfs_greg saved_registers, modified_registers;
  procfs_status status;
  procfs_run run;
  sigset_t * run_fault = (sigset_t *) &run.fault;

  sprintf (as_path, "/proc/%d/as", pid);
  fd = open (as_path, O_RDWR);
  if (fd == -1)
  {
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_call failed to open process %d, errno: %d", pid, errno);
    return FALSE;
  }

  /*
   * Find the first active thread:
   */
  for (tid = 1;; tid++)
  {
    thread.tid = tid;
    if (devctl (fd, DCMD_PROC_TIDSTATUS, &thread, sizeof (thread), 0) == EOK)
      break;
  }

  /*
   * Set current thread and freeze our target thread:
   */
  ret = devctl (fd, DCMD_PROC_CURTHREAD, &tid, sizeof (tid), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_CURTHREAD");

  ret = devctl (fd, DCMD_PROC_STOP, &status, sizeof (status), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_STOP");

  if (status.state == STATE_DEAD)
    goto beach;

  if (status.state != STATE_STOPPED)
  {
    /*
     * If the thread was not in the STOPPED state, it's probably
     * blocked in a NANOSLEEP or some syscall. We'll SIGHUP
     * it to kick it out of the blocker and WAITSTOP until the
     * signal is delivered.
     */
    memset (&run, 0, sizeof (run));
    run.flags |= _DEBUG_RUN_TRACE;
    sigemptyset (&run.trace);
    sigaddset (&run.trace, SIGHUP);
    ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_RUN");

    kill (pid, SIGHUP);

    ret = devctl (fd, DCMD_PROC_WAITSTOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_WAITSTOP");
    if (status.why == _DEBUG_WHY_TERMINATED)
      goto beach;

    /*
     * We need the extra PROC_STOP because status.state is not
     * properly reported by WAITSTOP.
     */
    ret = devctl (fd, DCMD_PROC_STOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_STOP");
  }

  /*
   * Get the thread's registers:
   */
  ret = devctl (fd, DCMD_PROC_GETGREG, &saved_registers, sizeof (saved_registers), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_GETGREG");

  memcpy (&modified_registers, &saved_registers, sizeof (saved_registers));

  /*
   * Set the PC to be the function address and SP to the stack address.
   */
  if ((func & 1) != 0)
  {
    modified_registers.arm.gpr[GUM_QNX_ARM_REG_PC] = (func & ~1);
    modified_registers.arm.spsr |= PSR_T_BIT;
  }
  else
  {
    modified_registers.arm.gpr[GUM_QNX_ARM_REG_PC] = func;
    modified_registers.arm.spsr &= ~PSR_T_BIT;
  }

  for (i = 0; i < args_length && i < 4; i++)
  {
    modified_registers.arm.gpr[i] = args[i];
  }

  for (i = args_length - 1; i >= 4; i--)
  {
    modified_registers.arm.gpr[GUM_QNX_ARM_REG_SP] -= 4;

    if (!frida_remote_write_fd (fd, modified_registers.arm.gpr[GUM_QNX_ARM_REG_SP], &args[i],
        4, error))
      goto beach;
  }

  /*
   * Set the LR to be a dummy address which will trigger a pagefault.
   */
  modified_registers.arm.gpr[GUM_QNX_ARM_REG_LR] = 0xfffffff0;

  ret = devctl (fd, DCMD_PROC_SETGREG, &modified_registers, sizeof (modified_registers), 0);
  CHECK_OS_RESULT (ret, ==, 0, "DCMD_PROC_SETGREG");

  while (modified_registers.arm.gpr[GUM_QNX_ARM_REG_PC] != 0xfffffff0)
  {
    /*
     * Continue the process, watching for FLTPAGE which should trigger when
     * the dummy LR value (0xfffffff0) is reached.
     */
    memset (&run, 0, sizeof (run));
    sigemptyset (run_fault);
    sigaddset (run_fault, FLTPAGE);
    run.flags |= _DEBUG_RUN_FAULT | _DEBUG_RUN_CLRFLT | _DEBUG_RUN_CLRSIG;
    ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
    CHECK_OS_RESULT (ret, ==, 0, "DCMD_PROC_RUN");

    /*
     * Wait for the process to stop at the fault.
     */
    ret = devctl (fd, DCMD_PROC_WAITSTOP, &status, sizeof (status), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_WAITSTOP");

    /*
     * Get the thread's registers:
     */
    ret = devctl (fd, DCMD_PROC_GETGREG, &modified_registers,
        sizeof (modified_registers), 0);
    CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_GETGREG");
  }

  if (retval != NULL)
    *retval = modified_registers.arm.gpr[GUM_QNX_ARM_REG_R0];

  /*
   * Restore the registers and continue the process:
   */
  ret = devctl (fd, DCMD_PROC_SETGREG, &saved_registers, sizeof (saved_registers), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_SETGREG");

  memset (&run, 0, sizeof (run));
  run.flags |= _DEBUG_RUN_CLRFLT | _DEBUG_RUN_CLRSIG;
  ret = devctl (fd, DCMD_PROC_RUN, &run, sizeof (run), 0);
  CHECK_OS_RESULT (ret, ==, EOK, "DCMD_PROC_RUN");

  success = TRUE;

beach:
  close (fd);

  return success;

os_failure:
  {
    if (fd != -1)
      close (fd);
    g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "remote_call %s failed: %d", failed_operation, errno);
    return FALSE;
  }
}

static GumAddress
frida_resolve_remote_libc_function (int remote_pid, const gchar * function_name)
{
  return frida_resolve_remote_library_function (remote_pid, "libc", function_name);
}

static GumAddress
frida_resolve_remote_library_function (int remote_pid, const gchar * library_name, const gchar * function_name)
{
  gchar * local_library_path, * remote_library_path, * canonical_library_name;
  GumAddress local_base, remote_base, remote_address;
  gpointer module, local_address;

  local_base = frida_find_library_base (getpid (), library_name, &local_library_path);
  g_assert (local_base != 0);

  remote_base = frida_find_library_base (remote_pid, library_name, &remote_library_path);
  if (remote_base == 0)
  {
    g_free (local_library_path);
    return 0;
  }

  g_assert (g_strcmp0 (local_library_path, remote_library_path) == 0);

  canonical_library_name = g_path_get_basename (local_library_path);

  module = dlopen (canonical_library_name, RTLD_GLOBAL | RTLD_LAZY);
  g_assert (module != NULL);

  local_address = dlsym (module, function_name);
  g_assert (local_address != NULL);

  remote_address = remote_base + (GUM_ADDRESS (local_address) - local_base);

  dlclose (module);

  g_free (local_library_path);
  g_free (remote_library_path);
  g_free (canonical_library_name);

  return remote_address;
}

static GumAddress
frida_find_library_base (pid_t pid, const gchar * library_name, gchar ** library_path)
{
  GumAddress result = 0;
  gchar * as_path = NULL;
  int fd = -1;
  int res;
  procfs_mapinfo * mapinfos = NULL;
  gint num_mapinfos;
  procfs_debuginfo * debuginfo = NULL;
  gint i;
  gchar * path;

  if (library_path != NULL)
    *library_path = NULL;

  as_path = g_strdup_printf ("/proc/%d/as", pid);

  fd = open (as_path, O_RDONLY);
  if (fd == -1)
    goto beach;

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &num_mapinfos);
  if (res != 0)
    goto beach;

  mapinfos = g_malloc (num_mapinfos * sizeof (procfs_mapinfo));
  debuginfo = g_malloc (sizeof (procfs_debuginfo) + 0x100);

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfos,
      num_mapinfos * sizeof (procfs_mapinfo), &num_mapinfos);
  if (res != 0)
    goto beach;

  for (i = 0; i != num_mapinfos; i++)
  {
    debuginfo->vaddr = mapinfos[i].vaddr;
    res = devctl (fd, DCMD_PROC_MAPDEBUG, debuginfo,
        sizeof (procfs_debuginfo) + 0x100, NULL);
    if (res != 0)
      goto beach;
    path = debuginfo->path;

    if (strcmp (path, library_name) == 0)
    {
      result = mapinfos[i].vaddr;
      if (library_path != NULL)
        *library_path = g_strdup (path);
    }
    else
    {
      gchar * p = strrchr (path, '/');
      if (p != NULL)
      {
        p++;

        gchar * s = strrchr (p, '.');
        gboolean has_numeric_suffix = FALSE;
        if (s != NULL && g_ascii_isdigit (*(s + 1)))
        {
          has_numeric_suffix = TRUE;
          *s = '\0';
        }
        if (g_str_has_prefix (p, library_name) && g_str_has_suffix (p, ".so"))
        {
          gchar next_char = p[strlen (library_name)];
          if (next_char == '-' || next_char == '.')
          {
            result = mapinfos[i].vaddr;
            if (library_path != NULL)
            {
              if (has_numeric_suffix)
                *s = '.';
              *library_path = g_strdup (path);
              break;
            }
          }
        }
      }
    }
  }

beach:
  g_free (debuginfo);
  g_free (mapinfos);

  if (fd != -1)
    close (fd);

  g_free (as_path);

  return result;
}
```