Response:
Let's break down the thought process for analyzing this C code for Frida's Windows pipe implementation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided C code, identify its connection to reverse engineering, and its reliance on low-level details (OS, kernel, etc.). We also need to spot potential user errors and understand the execution flow to reach this code.

**2. Initial Code Scan and Keyword Spotting:**

I'd first scan the code for familiar keywords and patterns. Things that immediately jump out:

* `#include <windows.h>`: This confirms it's Windows-specific code.
* `pipe`:  The filename and frequent use of "pipe" strongly suggest inter-process communication (IPC) using named pipes.
* `CreateNamedPipeW`, `CreateFileW`, `ConnectNamedPipe`, `ReadFile`, `WriteFile`, `CloseHandle`: These are core Windows API functions related to named pipes.
* `OVERLAPPED`:  Indicates asynchronous I/O operations.
* `CreateEvent`, `WaitForMultipleObjects`, `SetEvent`: These are used for synchronization in asynchronous operations.
* `SECURITY_DESCRIPTOR`, `ConvertStringSecurityDescriptorToSecurityDescriptorW`: Security settings for the named pipe.
* `GInputStream`, `GOutputStream`:  These suggest the code integrates with GLib's I/O streaming framework.
* `g_strdup_printf`, `g_slice_new0`, `g_slice_free`, `g_free`:  GLib memory management functions.
* `frida_`, `_frida_`:  Prefixes indicating Frida-specific functions.

**3. Deconstructing the Core Functionality:**

Based on the keywords, I'd deduce the core functionality:

* **Creating Named Pipes:** The code provides mechanisms to create both server and client ends of a named pipe. The server creates the pipe, and the client connects to it.
* **Asynchronous Communication:** The use of `OVERLAPPED` structures and events indicates that read and write operations are performed asynchronously, allowing the program to continue other tasks while waiting for I/O to complete.
* **Data Transfer:** The `frida_windows_pipe_input_stream_read` and `frida_windows_pipe_output_stream_write` functions handle the actual transfer of data through the pipe.
* **Connection Management:** Functions like `frida_windows_pipe_backend_connect` manage the connection establishment between the client and server.
* **Error Handling:** The code uses `GetLastError()` and GLib's error reporting (`g_set_error`) to handle potential failures.
* **Security:**  The code sets security descriptors for the named pipe using SDDL, controlling access to it.

**4. Identifying Connections to Reverse Engineering:**

Now, I'd consider how this functionality relates to reverse engineering, specifically in the context of Frida:

* **Inter-Process Communication:** Frida often needs to communicate with the target process being instrumented. Named pipes are a viable mechanism for this, especially on Windows. The Frida agent (injected into the target process) could use one end of the pipe, and the Frida client (the controlling process) could use the other.
* **Code Injection and Hooking:** While this specific file doesn't *perform* injection or hooking, it provides the *communication channel* that would be essential for sending commands to a hooked process or receiving data back.

**5. Identifying Low-Level Dependencies:**

This part is straightforward given the included headers and API calls:

* **Windows API:**  Direct use of Windows functions for pipe management, events, and security.
* **Operating System Kernels (Implicit):**  Named pipes are an OS-level construct. The Windows kernel is responsible for managing them.
* **Binary Data:**  The `read` and `write` functions operate on raw memory (`void * buffer`, `const void * buffer`), implying the transfer of binary data.

**6. Logical Reasoning and Example Input/Output:**

This requires making assumptions about how Frida uses this code:

* **Assumption:** Frida uses this for communication between its client and agent processes.
* **Server-Side (Agent):** The agent creates a named pipe (server role). Input could be commands from the Frida client (e.g., "hook function X"). Output could be the results of those commands (e.g., the address of function X, or data intercepted by a hook).
* **Client-Side (Frida CLI/Script):** The client connects to the named pipe (client role). Input would be commands, output would be the responses.

**7. Identifying Potential User Errors:**

This involves thinking about how a developer using Frida might misuse the pipe functionality (or how the underlying OS could cause issues):

* **Incorrect Pipe Name:**  If the client tries to connect to a non-existent pipe.
* **Permission Issues:** If the security descriptor prevents the client from connecting.
* **Resource Exhaustion:**  Although less likely in typical Frida usage, creating too many pipes could theoretically lead to resource issues.
* **Deadlocks (Advanced):** While not immediately obvious from *this* code, incorrect synchronization in a larger system using these pipes could lead to deadlocks.

**8. Tracing User Operations:**

This requires understanding Frida's architecture at a high level:

1. **User executes a Frida command or script.** (e.g., `frida -p <pid> -l my_script.js`)
2. **Frida Core initiates the instrumentation process.** This often involves injecting a Frida agent into the target process.
3. **Frida Core needs a communication channel.**  This `pipe-windows.c` code provides that channel using named pipes.
4. **The `_frida_pipe_transport_create_backend` function is likely called** to set up the named pipe, generating the local and remote addresses.
5. **The agent (injected into the target) uses the "client" address** to connect to the pipe.
6. **The Frida controlling process uses the "server" address.**
7. **Data is exchanged** using the input and output streams provided by this code.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This is just basic IPC."  **Correction:**  "While it's *based* on IPC, the asynchronous nature and integration with GLib are important details within the Frida context."
* **Initial thought:** "User errors are just about wrong names." **Correction:** "Security permissions are also a significant factor with named pipes on Windows."
* **Focusing too much on the C code details:** **Correction:** Stepping back to consider how this fits into the larger Frida ecosystem is crucial. The purpose isn't just to understand *how* the pipe works, but *why* Frida uses it and what kind of data flows through it.

By following these steps, combining code analysis with knowledge of the broader Frida architecture and operating system fundamentals, we can arrive at a comprehensive understanding of the `pipe-windows.c` file.
好的，让我们来分析一下 `frida/subprojects/frida-core/lib/pipe/pipe-windows.c` 这个文件。

**功能列举:**

这个 C 代码文件实现了 Frida 在 Windows 平台上使用命名管道 (Named Pipes) 进行进程间通信 (IPC) 的功能。具体来说，它提供了以下功能：

1. **创建和销毁管道后端 (Pipe Backend):**
   - `_frida_windows_pipe_create_backend`:  根据提供的地址字符串（包含 "role=server/client" 和 "name=管道名" 信息）创建命名管道的后端。它可以作为服务端创建管道，也可以作为客户端连接到已存在的管道。
   - `_frida_windows_pipe_destroy_backend`:  释放与管道后端相关的资源，包括关闭管道句柄和事件句柄。

2. **打开命名管道:**
   - `frida_windows_pipe_open_named_pipe`:  核心函数，根据角色 (服务端或客户端) 和管道名称，调用 Windows API `CreateNamedPipeW` (服务端) 或 `CreateFileW` (客户端) 打开或创建命名管道。

3. **连接命名管道 (服务端):**
   - `frida_windows_pipe_backend_connect`:  仅用于服务端角色，调用 `ConnectNamedPipe` 等待客户端连接。它使用异步 I/O 和事件对象来实现非阻塞的等待。

4. **创建输入/输出流:**
   - `_frida_windows_pipe_make_input_stream`:  创建一个用于从管道读取数据的 `GInputStream` 对象。
   - `_frida_windows_pipe_make_output_stream`: 创建一个用于向管道写入数据的 `GOutputStream` 对象。

5. **读取和写入管道:**
   - `frida_windows_pipe_input_stream_read`:  使用 Windows API `ReadFile` 从管道读取数据。它也使用了异步 I/O 和事件对象来实现非阻塞读取。
   - `frida_windows_pipe_output_stream_write`: 使用 Windows API `WriteFile` 向管道写入数据，同样使用了异步 I/O。

6. **关闭管道:**
   - `_frida_windows_pipe_close_backend`:  调用 `CloseHandle` 关闭管道句柄。

7. **生成管道名称:**
   - `frida_pipe_generate_name`:  生成一个唯一的随机管道名称，以避免冲突。

8. **从管道名称获取路径:**
   - `frida_pipe_path_from_name`:  将管道名称转换为 Windows 命名管道的路径格式 (例如 `\\\\.\\pipe\\frida-xxxxxxxxxxxxxxxx`).

9. **异步操作处理:**
   - `frida_windows_pipe_backend_await`:  等待异步操作完成或取消信号。它使用了 `WaitForMultipleObjects` 等待读/写完成事件或取消事件。
   - `frida_windows_pipe_backend_on_cancel`:  当操作被取消时设置取消事件。

10. **设置管道安全描述符:**
    -  虽然代码中调用了 `frida_pipe_get_sddl_string_for_pipe()`, 并使用 `ConvertStringSecurityDescriptorToSecurityDescriptorW` 来设置管道的安全属性，但这部分具体的安全策略实现没有在这个文件中。这表明 Frida 使用 SDDL (Security Descriptor Definition Language) 来控制管道的访问权限。

**与逆向方法的关系及举例:**

Frida 作为动态插桩工具，其核心功能之一就是在运行时修改目标进程的行为。为了实现这一点，Frida 需要在运行 Frida 脚本的进程（通常是你的电脑上运行的 Python 脚本）和目标进程之间建立通信通道。命名管道就是一种常用的 IPC 机制，特别是在 Windows 平台上。

**举例说明:**

1. **Frida Client 发送命令给 Frida Agent:**
   - 你使用 Frida 脚本调用 `Interceptor.attach()` 来 hook 目标进程中的一个函数。
   - 这个 `attach` 的请求会被 Frida Client 序列化成消息，并通过这个 `pipe-windows.c` 实现的输出流 (`frida_windows_pipe_output_stream_write`) 发送到目标进程中的 Frida Agent。

2. **Frida Agent 返回结果给 Frida Client:**
   - Frida Agent 在目标进程中执行了 hook 操作，可能会收集一些信息 (例如函数参数、返回值)。
   - 这些信息会被 Frida Agent 序列化，并通过这个 `pipe-windows.c` 实现的输入流 (`frida_windows_pipe_input_stream_read`) 发送回 Frida Client。

**二进制底层、Linux、Android 内核及框架的知识:**

* **二进制底层:**
    - 代码中直接操作内存 (`void * buffer`, `const void * buffer`) 进行数据的读写，这涉及到二进制数据的处理。
    - 命名管道传输的是原始的字节流，Frida 需要在两端进行数据的序列化和反序列化，将高级数据结构转换为二进制数据进行传输。

* **Windows API:**
    - 代码大量使用了 Windows 特定的 API，例如 `CreateNamedPipeW`, `CreateFileW`, `ReadFile`, `WriteFile`, `ConnectNamedPipe`, `OVERLAPPED`, `CreateEvent`, `WaitForMultipleObjects`, `CloseHandle` 等。这些都是 Windows 操作系统提供的用于处理 IPC 和异步 I/O 的底层接口。

* **Linux 和 Android 内核及框架 (对比):**
    - 在 Linux 和 Android 上，Frida 通常会使用 Unix Domain Sockets 或 Ashmem (Android 共享内存) 等机制进行进程间通信。
    - 这些机制与 Windows 的命名管道在实现细节上有所不同，但目的都是为了在进程间高效地传递数据。例如，Unix Domain Sockets 使用文件系统路径作为地址，而命名管道使用特定的命名空间。
    - Android 的 Binder 机制也是一种重要的 IPC 方式，Frida 可能会在某些场景下使用 Binder 与 Android 系统服务或目标进程通信。

**逻辑推理、假设输入与输出:**

假设 Frida Client 想要让 Frida Agent 读取目标进程中地址 `0x12345678` 的 4 个字节的数据。

**假设输入 (写入管道):**

Frida Client 通过 `frida_windows_pipe_output_stream_write` 向管道写入一个包含以下信息的序列化数据结构：

```
{
  "type": "read_memory",
  "address": 0x12345678,
  "size": 4
}
```

**假设输出 (从管道读取):**

Frida Agent 读取到上述请求后，会读取目标进程的内存，并将结果通过 `frida_windows_pipe_input_stream_read` 发回，例如：

```
{
  "type": "read_memory_response",
  "address": 0x12345678,
  "data": [0xAA, 0xBB, 0xCC, 0xDD]
}
```

这里的 `0xAA, 0xBB, 0xCC, 0xDD` 就是从目标进程地址 `0x12345678` 读取到的 4 个字节的二进制数据。

**用户或编程常见的使用错误及举例:**

1. **管道名称不匹配:**
   - **错误:**  Frida Client 和 Frida Agent 配置了不同的管道名称。
   - **后果:**  客户端无法连接到服务端创建的管道，导致通信失败。
   - **例子:**  在 Frida 脚本中，你可能错误地指定了管道名称：
     ```python
     session = frida.attach("目标进程")
     # 假设 Frida Agent 启动时使用的管道名是 "my_frida_pipe"
     # 但你的脚本中使用了错误的名称
     transport_options = {"pipe": {"name": "wrong_pipe_name"}}
     # ... 后续操作将无法通过管道通信
     ```

2. **权限问题:**
   - **错误:**  运行 Frida 的用户没有足够的权限访问或创建命名管道。
   - **后果:**  服务端无法创建管道，或者客户端无法连接到管道。
   - **例子:**  在某些受限的环境下，操作系统可能会阻止创建或访问特定的命名管道。

3. **管道未创建 (客户端先启动):**
   - **错误:**  Frida Client 尝试连接管道时，服务端（Frida Agent）尚未创建该管道。
   - **后果:**  客户端连接失败。
   - **例子:**  如果 Frida Agent 的启动需要一些时间，而 Frida 脚本立即尝试连接，可能会遇到这种情况。

4. **读取或写入错误的数据大小:**
   - **错误:**  Frida Client 或 Agent 在读取或写入管道时，使用了不正确的数据大小。
   - **后果:**  可能导致数据截断、丢失或程序崩溃。
   - **例子:**  如果 Agent 预期接收 10 个字节的数据，但 Client 只发送了 5 个字节。

5. **异步操作处理不当:**
   - **错误:**  没有正确处理异步 I/O 的完成事件或取消事件。
   - **后果:**  可能导致程序hang住、资源泄漏或数据不一致。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户启动 Frida 脚本或使用 Frida CLI 工具:**
   - 例如，用户运行 `frida -p 1234 -l my_script.js` 来附加到一个进程 (PID 1234) 并执行脚本。

2. **Frida Core 初始化通信机制:**
   - Frida Core 需要与目标进程中的 Frida Agent 建立通信。在 Windows 上，如果选择使用命名管道作为传输方式，就会涉及到这个 `pipe-windows.c` 文件。

3. **创建管道后端:**
   - Frida Core 会调用 `_frida_pipe_transport_create_backend` (虽然这个函数在这个文件中是空的，但它会在其他地方被实现，并最终调用到 `_frida_windows_pipe_create_backend`) 来创建管道的后端。这包括生成管道名称，并根据角色创建服务端或客户端的管道对象。

4. **创建输入/输出流:**
   - Frida Core 会调用 `_frida_windows_pipe_make_input_stream` 和 `_frida_windows_pipe_make_output_stream` 来获取用于读写管道的流对象。

5. **Frida Client 和 Agent 通过管道交换数据:**
   - 当 Frida 脚本执行到需要与目标进程交互的部分 (例如 `Interceptor.attach`, `Memory.readByteArray`, `Memory.writeByteArray` 等) 时，这些操作会被转换为消息，并通过这里实现的管道输出流发送到 Agent。
   - Agent 执行操作后，会将结果通过管道输入流发送回 Client。

**调试线索:**

如果在 Frida 的使用过程中遇到通信问题，可以从以下几个方面入手进行调试：

* **检查管道名称:** 确保 Frida Client 和 Agent 使用了相同的管道名称配置。
* **检查权限:** 确保运行 Frida 的用户具有创建和访问命名管道的权限。
* **查看日志:** Frida 通常会提供详细的日志信息，可以查看是否有关于管道连接或读写错误的提示。
* **使用调试工具:** 可以使用 Windows 的 `Process Explorer` 或 `Handle` 工具来查看系统中存在的命名管道以及它们的访问权限。
* **代码断点:** 如果你有 Frida 的源代码，可以在 `pipe-windows.c` 中的关键函数 (例如 `frida_windows_pipe_open_named_pipe`, `ReadFile`, `WriteFile`) 设置断点，跟踪管道的创建、连接和数据传输过程。

希望以上分析能够帮助你理解 `frida/subprojects/frida-core/lib/pipe/pipe-windows.c` 文件的功能以及它在 Frida 中的作用。

### 提示词
```
这是目录为frida/subprojects/frida-core/lib/pipe/pipe-windows.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#include "pipe-glue.h"

#include "pipe-sddl.h"

#include <sddl.h>
#include <windows.h>

#define PIPE_BUFSIZE (1024 * 1024)

#define CHECK_WINAPI_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto winapi_failed; \
  }

typedef struct _FridaPipeBackend FridaPipeBackend;
typedef guint FridaWindowsPipeRole;

struct _FridaPipeBackend
{
  FridaWindowsPipeRole role;
  HANDLE pipe;
  gboolean connected;
  HANDLE read_complete;
  HANDLE read_cancel;
  HANDLE write_complete;
  HANDLE write_cancel;
};

enum _FridaWindowsPipeRole
{
  FRIDA_WINDOWS_PIPE_SERVER = 1,
  FRIDA_WINDOWS_PIPE_CLIENT
};

struct _FridaWindowsPipeInputStream
{
  GInputStream parent;

  FridaPipeBackend * backend;
};

struct _FridaWindowsPipeOutputStream
{
  GOutputStream parent;

  FridaPipeBackend * backend;
};

static HANDLE frida_windows_pipe_open_named_pipe (const gchar * name, FridaWindowsPipeRole role, GError ** error);

static gssize frida_windows_pipe_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static gboolean frida_windows_pipe_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error);

static gssize frida_windows_pipe_output_stream_write (GOutputStream * base, const void * buffer, gsize count, GCancellable * cancellable, GError ** error);
static gboolean frida_windows_pipe_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error);

static gchar * frida_pipe_generate_name (void);
static WCHAR * frida_pipe_path_from_name (const gchar * name);

static gboolean frida_windows_pipe_backend_await (FridaPipeBackend * self, HANDLE complete, HANDLE cancel, GCancellable * cancellable, GError ** error);
static void frida_windows_pipe_backend_on_cancel (GCancellable * cancellable, gpointer user_data);

G_DEFINE_TYPE (FridaWindowsPipeInputStream, frida_windows_pipe_input_stream, G_TYPE_INPUT_STREAM)
G_DEFINE_TYPE (FridaWindowsPipeOutputStream, frida_windows_pipe_output_stream, G_TYPE_OUTPUT_STREAM)

void
frida_pipe_transport_set_temp_directory (const gchar * path)
{
}

void *
_frida_pipe_transport_create_backend (gchar ** local_address, gchar ** remote_address, GError ** error)
{
  gchar * name;

  name = frida_pipe_generate_name ();

  *local_address = g_strdup_printf ("pipe:role=server,name=%s", name);
  *remote_address = g_strdup_printf ("pipe:role=client,name=%s", name);

  g_free (name);

  return NULL;
}

void
_frida_pipe_transport_destroy_backend (void * backend)
{
}

void *
_frida_windows_pipe_create_backend (const gchar * address, GError ** error)
{
  FridaPipeBackend * backend;
  const gchar * role, * name;

  backend = g_slice_new0 (FridaPipeBackend);

  role = strstr (address, "role=") + 5;
  backend->role = role[0] == 's' ? FRIDA_WINDOWS_PIPE_SERVER : FRIDA_WINDOWS_PIPE_CLIENT;
  name = strstr (address, "name=") + 5;
  backend->pipe = frida_windows_pipe_open_named_pipe (name, backend->role, error);
  if (backend->pipe != INVALID_HANDLE_VALUE)
  {
    backend->read_complete = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->read_cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->write_complete = CreateEvent (NULL, TRUE, FALSE, NULL);
    backend->write_cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
  }
  else
  {
    _frida_windows_pipe_destroy_backend (backend);
    backend = NULL;
  }

  return backend;
}

void
_frida_windows_pipe_destroy_backend (void * opaque_backend)
{
  FridaPipeBackend * backend = opaque_backend;

  if (backend->read_complete != NULL)
    CloseHandle (backend->read_complete);
  if (backend->read_cancel != NULL)
    CloseHandle (backend->read_cancel);
  if (backend->write_complete != NULL)
    CloseHandle (backend->write_complete);
  if (backend->write_cancel != NULL)
    CloseHandle (backend->write_cancel);

  if (backend->pipe != INVALID_HANDLE_VALUE)
    CloseHandle (backend->pipe);

  g_slice_free (FridaPipeBackend, backend);
}

static HANDLE
frida_windows_pipe_open_named_pipe (const gchar * name, FridaWindowsPipeRole role, GError ** error)
{
  HANDLE result = INVALID_HANDLE_VALUE;
  BOOL success;
  const gchar * failed_operation;
  WCHAR * path;
  LPCWSTR sddl;
  PSECURITY_DESCRIPTOR sd = NULL;
  SECURITY_ATTRIBUTES sa;

  path = frida_pipe_path_from_name (name);
  sddl = frida_pipe_get_sddl_string_for_pipe ();
  success = ConvertStringSecurityDescriptorToSecurityDescriptorW (sddl, SDDL_REVISION_1, &sd, NULL);
  CHECK_WINAPI_RESULT (success, !=, FALSE, "ConvertStringSecurityDescriptorToSecurityDescriptor");

  sa.nLength = sizeof (sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;

  if (role == FRIDA_WINDOWS_PIPE_SERVER)
  {
    result = CreateNamedPipeW (path,
        PIPE_ACCESS_DUPLEX |
        FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE |
        PIPE_READMODE_BYTE |
        PIPE_WAIT,
        1,
        PIPE_BUFSIZE,
        PIPE_BUFSIZE,
        0,
        &sa);
    CHECK_WINAPI_RESULT (result, !=, INVALID_HANDLE_VALUE, "CreateNamedPipe");
  }
  else
  {
    result = CreateFileW (path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        &sa,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);
    CHECK_WINAPI_RESULT (result, !=, INVALID_HANDLE_VALUE, "CreateFile");
  }

  goto beach;

winapi_failed:
  {
    DWORD last_error = GetLastError ();
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error opening named pipe (%s returned 0x%08lx)",
        failed_operation, last_error);
    goto beach;
  }

beach:
  {
    if (sd != NULL)
      LocalFree (sd);

    g_free (path);

    return result;
  }
}

static gboolean
frida_windows_pipe_backend_connect (FridaPipeBackend * backend, GCancellable * cancellable, GError ** error)
{
  gboolean success = FALSE;
  HANDLE connect, cancel;
  OVERLAPPED overlapped = { 0, };
  BOOL ret, last_error;
  DWORD bytes_transferred;

  if (backend->connected)
  {
    return TRUE;
  }
  else if (backend->role == FRIDA_WINDOWS_PIPE_CLIENT)
  {
    backend->connected = TRUE;
    return TRUE;
  }

  connect = CreateEvent (NULL, TRUE, FALSE, NULL);
  cancel = CreateEvent (NULL, TRUE, FALSE, NULL);
  overlapped.hEvent = connect;

  ret = ConnectNamedPipe (backend->pipe, &overlapped);
  last_error = GetLastError ();
  if (!ret && last_error != ERROR_IO_PENDING && last_error != ERROR_PIPE_CONNECTED)
    goto failure;

  if (last_error == ERROR_IO_PENDING)
  {
    if (!frida_windows_pipe_backend_await (backend, connect, cancel, cancellable, error))
      goto beach;

    if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
      goto failure;
  }

  backend->connected = TRUE;
  success = TRUE;
  goto beach;

failure:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error opening named pipe");
    goto beach;
  }
beach:
  {
    CloseHandle (connect);
    CloseHandle (cancel);
    return success;
  }
}

static gboolean
frida_windows_pipe_backend_await (FridaPipeBackend * self, HANDLE complete, HANDLE cancel, GCancellable * cancellable, GError ** error)
{
  gulong handler_id = 0;
  HANDLE events[2];

  if (cancellable != NULL)
  {
    handler_id = g_cancellable_connect (cancellable, G_CALLBACK (frida_windows_pipe_backend_on_cancel), cancel, NULL);
  }

  events[0] = complete;
  events[1] = cancel;
  WaitForMultipleObjects (G_N_ELEMENTS (events), events, FALSE, INFINITE);

  if (cancellable != NULL)
  {
    g_cancellable_disconnect (cancellable, handler_id);
    if (g_cancellable_set_error_if_cancelled (cancellable, error))
    {
      CancelIo (self->pipe);
      return FALSE;
    }
  }

  return TRUE;
}

static void
frida_windows_pipe_backend_on_cancel (GCancellable * cancellable, gpointer user_data)
{
  HANDLE cancel = (HANDLE) user_data;

  SetEvent (cancel);
}

gboolean
_frida_windows_pipe_close_backend (void * opaque_backend, GError ** error)
{
  FridaPipeBackend * backend = opaque_backend;

  if (!CloseHandle (backend->pipe))
    goto failure;
  backend->pipe = INVALID_HANDLE_VALUE;
  return TRUE;

failure:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error closing named pipe");
    return FALSE;
  }
}

GInputStream *
_frida_windows_pipe_make_input_stream (void * backend)
{
  FridaWindowsPipeInputStream * stream;

  stream = g_object_new (FRIDA_TYPE_WINDOWS_PIPE_INPUT_STREAM, NULL);
  stream->backend = backend;

  return G_INPUT_STREAM (stream);
}

GOutputStream *
_frida_windows_pipe_make_output_stream (void * backend)
{
  FridaWindowsPipeOutputStream * stream;

  stream = g_object_new (FRIDA_TYPE_WINDOWS_PIPE_OUTPUT_STREAM, NULL);
  stream->backend = backend;

  return G_OUTPUT_STREAM (stream);
}

static void
frida_windows_pipe_input_stream_class_init (FridaWindowsPipeInputStreamClass * klass)
{
  GInputStreamClass * stream_class = G_INPUT_STREAM_CLASS (klass);

  stream_class->read_fn = frida_windows_pipe_input_stream_read;
  stream_class->close_fn = frida_windows_pipe_input_stream_close;
}

static void
frida_windows_pipe_input_stream_init (FridaWindowsPipeInputStream * self)
{
}

static gssize
frida_windows_pipe_input_stream_read (GInputStream * base, void * buffer, gsize count, GCancellable * cancellable, GError ** error)
{
  FridaWindowsPipeInputStream * self = FRIDA_WINDOWS_PIPE_INPUT_STREAM (base);
  FridaPipeBackend * backend = self->backend;
  gssize result = -1;
  OVERLAPPED overlapped = { 0, };
  BOOL ret;
  DWORD bytes_transferred;

  if (!frida_windows_pipe_backend_connect (backend, cancellable, error))
    goto beach;

  overlapped.hEvent = backend->read_complete;
  ret = ReadFile (backend->pipe, buffer, count, NULL, &overlapped);
  if (!ret && GetLastError () != ERROR_IO_PENDING)
    goto failure;

  if (!frida_windows_pipe_backend_await (backend, backend->read_complete, backend->read_cancel, cancellable, error))
    goto beach;

  if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
    goto failure;

  result = bytes_transferred;
  goto beach;

failure:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error reading from named pipe");
    goto beach;
  }
beach:
  {
    return result;
  }
}

static gboolean
frida_windows_pipe_input_stream_close (GInputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
}

static void
frida_windows_pipe_output_stream_class_init (FridaWindowsPipeOutputStreamClass * klass)
{
  GOutputStreamClass * stream_class = G_OUTPUT_STREAM_CLASS (klass);

  stream_class->write_fn = frida_windows_pipe_output_stream_write;
  stream_class->close_fn = frida_windows_pipe_output_stream_close;
}

static void
frida_windows_pipe_output_stream_init (FridaWindowsPipeOutputStream * self)
{
}

static gssize
frida_windows_pipe_output_stream_write (GOutputStream * base, const void * buffer, gsize count, GCancellable * cancellable, GError ** error)
{
  FridaWindowsPipeOutputStream * self = FRIDA_WINDOWS_PIPE_OUTPUT_STREAM (base);
  FridaPipeBackend * backend = self->backend;
  gssize result = -1;
  OVERLAPPED overlapped = { 0, };
  BOOL ret;
  DWORD bytes_transferred;

  if (!frida_windows_pipe_backend_connect (backend, cancellable, error))
    goto beach;

  overlapped.hEvent = backend->write_complete;
  ret = WriteFile (backend->pipe, buffer, count, NULL, &overlapped);
  if (!ret && GetLastError () != ERROR_IO_PENDING)
    goto failure;

  if (!frida_windows_pipe_backend_await (backend, backend->write_complete, backend->write_cancel, cancellable, error))
    goto beach;

  if (!GetOverlappedResult (backend->pipe, &overlapped, &bytes_transferred, FALSE))
    goto failure;

  result = bytes_transferred;
  goto beach;

failure:
  {
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (GetLastError ()),
        "Error writing to named pipe");
    goto beach;
  }
beach:
  {
    return result;
  }
}

static gboolean
frida_windows_pipe_output_stream_close (GOutputStream * base, GCancellable * cancellable, GError ** error)
{
  return TRUE;
}

static gchar *
frida_pipe_generate_name (void)
{
  GString * s;
  guint i;

  s = g_string_new ("frida-");
  for (i = 0; i != 16; i++)
    g_string_append_printf (s, "%02x", g_random_int_range (0, 255));

  return g_string_free (s, FALSE);
}

static WCHAR *
frida_pipe_path_from_name (const gchar * name)
{
  gchar * path_utf8;
  WCHAR * path;

  path_utf8 = g_strconcat ("\\\\.\\pipe\\", name, NULL);
  path = (WCHAR *) g_utf8_to_utf16 (path_utf8, -1, NULL, NULL, NULL);
  g_free (path_utf8);

  return path;
}
```