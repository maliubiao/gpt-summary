Response:
Let's break down the thought process for analyzing the C code and generating the detailed response.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of a C source file within the Frida project. The key is to identify its functionality, its relation to reverse engineering, its low-level interactions, any logical inferences, potential user errors, and the path to reaching this code.

**2. Initial Code Scan and Keyword Spotting:**

The first step is a quick read-through of the code, looking for recognizable keywords and patterns. This helps establish the general purpose. Keywords like:

* `#include`:  `windows.h`, `tlhelp32.h`, `gio/gio.h`, `gum/gum.h` immediately suggest Windows-specific functionality and the use of the Gum library (Frida's core instrumentation engine).
* `typedef struct`: Defines structures, which are crucial for understanding data organization.
* `WINAPI`: Indicates Windows API function calls.
* `OpenProcess`, `CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`, `GetProcAddress`, `LoadLibraryW`, `FreeLibrary`: These are all classic Windows API functions related to process manipulation and DLL injection.
* `RtlCreateUserThread`:  A lower-level alternative to `CreateRemoteThread`.
* `SECURITY_DESCRIPTOR`, `TOKEN_PRIVILEGES`:  Suggest security-related operations.
* `gum_...`: Functions prefixed with `gum_` are part of Frida's Gum library, likely related to code generation and manipulation.
* `MAX_PATH`, `GetLastError`: Standard Windows constants and functions.
* Error handling (`GError ** error`, `goto error_common`, `CHECK_OS_RESULT`, `CHECK_NT_RESULT`): Indicate the code handles potential failures.

**3. Deconstructing the Main Functionalities:**

Based on the keyword spotting, the primary function `_frida_windows_helper_backend_inject_library_file` stands out. Its name strongly suggests its purpose: injecting a DLL into a target process. The parameters confirm this: `pid`, `path` (DLL path), `entrypoint`, `data`.

Following the execution flow within this function reveals the core steps of DLL injection:

* **Privilege Escalation:** `frida_enable_debug_privilege()` is called to gain `SeDebugPrivilege`, necessary for interacting with other processes.
* **Opening the Target Process:** `OpenProcess()` is used to get a handle to the target process.
* **Remote Worker Context:** `frida_remote_worker_context_init()` is called, suggesting a setup phase for executing code in the target.
* **Remote Code Execution:** `CreateRemoteThread` (or `RtlCreateUserThread`) is used to execute code in the target process. The `rwc.entrypoint` and `rwc.argument` are key here.
* **Cleanup:**  `frida_remote_worker_context_destroy()` handles memory deallocation.

The secondary function `_frida_windows_helper_backend_free_inject_instance` appears to be responsible for cleaning up after the injection, potentially allowing the injected library to stay resident or be unloaded.

**4. Analyzing Supporting Functions:**

* `frida_enable_debug_privilege()`:  Clearly handles setting the `SeDebugPrivilege`.
* `frida_remote_worker_context_init()`: This is a crucial function. It allocates memory in the target process (`VirtualAllocEx`), copies code and data (`WriteProcessMemory`), and sets memory permissions (`VirtualProtectEx`). It also resolves addresses of key kernel32.dll functions. The use of `gum_` functions indicates dynamic code generation.
* `frida_remote_worker_context_emit_payload()`: This function uses Gum's assembler (`GumArm64Writer` or `GumX86Writer`) to generate the actual code that will run in the target process. This code loads the specified DLL, calls an entry point within it, and optionally unloads the DLL.
* `frida_remote_worker_context_destroy()`: Frees the allocated memory in the target process.
* `frida_remote_worker_context_has_resolved_all_kernel32_functions()` and `frida_remote_worker_context_collect_kernel32_export()`: These functions work together to dynamically resolve the addresses of functions like `LoadLibraryW`, `GetProcAddress`, etc., within the target process's `kernel32.dll`. This is essential for the injected code to function.
* `frida_propagate_open_process_error()`:  Handles specific errors when opening the target process.
* `frida_file_exists_and_is_readable()`: A simple check for the existence and readability of the DLL.

**5. Connecting to Reverse Engineering Concepts:**

With the functional understanding, linking it to reverse engineering becomes straightforward. DLL injection is a fundamental technique used by reverse engineers for:

* **Code Injection:** Inserting custom code into a running process to observe behavior, intercept function calls, modify data, etc.
* **Instrumentation:** Adding probes or hooks to analyze program execution.
* **Bypassing Protections:**  Injecting code to disable security measures.

The code directly implements the DLL injection process, making the connection obvious.

**6. Identifying Low-Level and OS/Kernel Interactions:**

The use of Windows API functions like `OpenProcess`, `CreateRemoteThread`, memory management functions, and the handling of privileges directly relates to low-level OS interactions. The conditional compilation based on architecture (`#ifdef HAVE_ARM64`) and the use of `ntdll.dll` (for `RtlCreateUserThread`) also point to low-level details.

**7. Logical Inferences (Hypothetical Inputs and Outputs):**

By analyzing the control flow and data structures, one can infer the expected behavior for given inputs. For example:

* **Input:** A valid PID and a valid DLL path.
* **Expected Output:** Successful injection, the DLL is loaded in the target process, and the entry point is executed.

* **Input:** An invalid PID.
* **Expected Output:** An error indicating the process was not found.

* **Input:** An invalid DLL path.
* **Expected Output:** An error indicating the file could not be found.

**8. Identifying User Errors:**

Knowing how the code works reveals potential user errors:

* **Incorrect PID:**  Specifying the wrong process ID will lead to injection failure.
* **Invalid DLL Path:** Providing a non-existent or inaccessible DLL path will fail.
* **Permissions Issues:**  Not having sufficient privileges to open the target process will cause errors.
* **Architecture Mismatch:** Attempting to inject an x86 DLL into an x64 process (or vice-versa) will fail. Although not explicitly handled in *this* code, it's a common DLL injection problem.

**9. Tracing User Actions to Code Execution:**

This requires understanding the broader Frida architecture. The user typically interacts with Frida through:

* **Frida CLI:**  Using commands like `frida -p <pid> -l <script.js>`.
* **Frida Python Bindings:** Writing Python scripts that use the Frida API.

These user actions eventually lead to calls within Frida's core libraries. The `frida-core` component, where this file resides, is responsible for the low-level injection mechanisms. The request specifically mentions `frida/subprojects/frida-core`, making this connection clear. The steps involve:

1. User initiates injection (CLI command or Python script).
2. Frida's core logic determines the target process and the DLL to inject.
3. This specific C code (`frida-helper-backend-glue.c`) is invoked to perform the platform-specific injection on Windows.

**10. Structuring the Response:**

Finally, organize the findings logically using the categories requested in the prompt. Use clear and concise language, providing code snippets or examples where appropriate. The goal is to provide a comprehensive yet understandable explanation of the code's purpose and behavior.

By following these steps, combining code analysis with knowledge of operating systems, reverse engineering techniques, and the Frida framework, one can generate a detailed and accurate explanation like the example provided in the initial prompt.
This C source file, `frida-helper-backend-glue.c`, is a crucial component of Frida on Windows. Its primary function is to facilitate the injection of a dynamic library (DLL) into a target process, enabling Frida's instrumentation capabilities. Let's break down its functionalities and their relevance:

**1. Core Functionality: DLL Injection**

The central purpose of this file is to implement the DLL injection mechanism on Windows. It provides the `_frida_windows_helper_backend_inject_library_file` function, which takes the target process ID (`pid`), the path to the DLL to inject (`path`), an optional entry point function name (`entrypoint`), and optional data to pass to the entry point (`data`).

**How it works (high-level):**

1. **Opens the Target Process:** It uses `OpenProcess` to get a handle to the target process. This requires appropriate permissions (often `SeDebugPrivilege`).
2. **Allocates Memory in the Target:** It allocates memory within the target process using `VirtualAllocEx` to hold the DLL path, the entry point information, and a small piece of code (the "payload").
3. **Writes Data to the Target:** It writes the DLL path, entry point name, and the payload code into the allocated memory in the target process using `WriteProcessMemory`.
4. **Executes the Payload in the Target:** It creates a new thread within the target process using `CreateRemoteThread` (or `RtlCreateUserThread`) and sets the starting address of this new thread to the injected payload code.
5. **Payload Execution:** The payload code, generated by `frida_remote_worker_context_emit_payload`, is responsible for:
    * Loading the specified DLL using `LoadLibraryW`.
    * Getting the address of the specified entry point function using `GetProcAddress`.
    * Calling the entry point function with the provided data.
    * Optionally unloading the DLL using `FreeLibrary` based on a flag.
6. **Manages Injection Instance:** It creates a `FridaInjectInstance` structure to track the injection, including the process handle and allocated memory addresses.

**2. Relationship to Reverse Engineering**

This file is fundamentally related to reverse engineering methods. DLL injection is a cornerstone technique used by reverse engineers for various purposes:

* **Code Injection:**  Reverse engineers inject their own code into a target process to observe its behavior, intercept function calls, modify data in memory, and hook into its execution flow. Frida leverages this to insert its instrumentation logic.
    * **Example:** A reverse engineer could use Frida (which relies on this injection mechanism) to hook the `CreateFileW` function in a target application to monitor which files it accesses, providing valuable insights into the application's functionality.

* **Dynamic Analysis:** By injecting code, reverse engineers can perform dynamic analysis, examining the application's behavior as it runs, rather than just statically analyzing its code.
    * **Example:** A reverse engineer could inject code that logs the arguments and return values of specific functions to understand how data is processed within the target application.

* **Bypassing Security Measures:** In some cases, DLL injection can be used to bypass security measures or anti-debugging techniques implemented by an application.
    * **Example:**  A reverse engineer might inject a DLL to disable checks that prevent debugging or to bypass license verification routines.

**3. Involvement of Binary, Linux/Android Kernel/Framework Knowledge**

While this specific file is Windows-centric, it interacts with binary code and has concepts that relate to other operating systems:

* **Binary Code Manipulation:** The `frida_remote_worker_context_emit_payload` function dynamically generates machine code (either ARM64 or x86) using the Gum library. This involves understanding instruction sets and calling conventions at the binary level.
    * **Example:** The code uses `gum_arm64_writer_put_ldr_reg_reg_offset` to generate ARM64 instructions that load data from memory into registers, which are fundamental binary operations.

* **Process Memory Management:** The code heavily relies on Windows-specific process memory management functions (`VirtualAllocEx`, `WriteProcessMemory`, `VirtualFreeEx`). The underlying concepts of allocating and managing memory within a process address space are similar across operating systems, including Linux and Android. However, the specific system calls and APIs differ.

* **Thread Creation:** The use of `CreateRemoteThread` is a Windows API for creating threads in another process. Linux uses `pthread_create`, and Android relies on its own threading mechanisms, but the core concept of creating and managing concurrent execution units within a process is universal.

* **Dynamic Linking:** The process of loading a DLL using `LoadLibraryW` and resolving function addresses using `GetProcAddress` is a form of dynamic linking. Linux uses shared objects (.so) and functions like `dlopen` and `dlsym` for similar purposes. Android also uses shared libraries and its own linker.

* **Privilege Management:** The `frida_enable_debug_privilege` function deals with Windows's privilege system. Linux and Android have their own mechanisms for managing permissions and privileges (e.g., capabilities in Linux).

**4. Logical Reasoning and Assumptions**

The code makes several logical deductions and assumptions:

* **Assumption:** The target process is running and accessible.
    * **Input:** A valid process ID (`pid`).
    * **Output:** The code attempts to open the process. If successful, it proceeds with injection. If not, it throws an error.
* **Assumption:** The provided DLL path is valid and the file exists.
    * **Input:** A string representing the file path (`path`).
    * **Output:** The `frida_file_exists_and_is_readable` function checks this. If it doesn't exist or is not readable, an error is returned before attempting injection.
* **Assumption:** The target process has `kernel32.dll` loaded (as it's a fundamental Windows DLL).
    * **Reasoning:** The code relies on resolving addresses of functions like `LoadLibraryW` and `GetProcAddress` from `kernel32.dll` within the target process. This is a safe assumption for almost all Windows processes.
* **Reasoning:** The payload code generated by `frida_remote_worker_context_emit_payload` needs to be executed in the target process's context.
    * **Implementation:** The code allocates executable memory in the target process and creates a remote thread starting at that memory location.

**5. User and Programming Errors**

This code has error handling to catch common issues:

* **Invalid Process ID:** If the user provides an invalid PID, `OpenProcess` will fail, and the `frida_propagate_open_process_error` function will generate an appropriate error message (e.g., "Unable to find process with pid X").
    * **Example User Error:**  Typing the wrong PID in a Frida command.
* **File Not Found/Inaccessible:** If the provided DLL path is incorrect or the file cannot be read, `frida_file_exists_and_is_readable` will return `FALSE`, and an error like "Unable to find DLL at 'path'" will be generated.
    * **Example User Error:** Providing a typo in the DLL path.
* **Insufficient Permissions:** If the user running Frida does not have the necessary permissions to open the target process (e.g., lacks `SeDebugPrivilege`), `OpenProcess` will return `NULL` and `GetLastError` will likely be `ERROR_ACCESS_DENIED`. The code handles this and reports a permission denied error.
    * **Example User Error:** Running Frida without administrator privileges when targeting a system process.
* **Memory Allocation Failure:** `VirtualAllocEx` might fail if there isn't enough memory available in the target process. The code checks for this and reports an error.
* **Write Process Memory Failure:** `WriteProcessMemory` could fail due to permissions or memory protection issues. The code includes checks for this.

**6. User Operation Steps to Reach This Code (Debugging Context)**

A user typically doesn't interact with this C code directly. Instead, they use Frida through its command-line interface (CLI), Python bindings, or other language bindings. Here's how the user's actions lead to the execution of this code:

1. **User Initiates Injection:** The user wants to inject a script or interact with a running process using Frida. They might execute a command like:
   ```bash
   frida -p <process_id> -l my_script.js
   ```
   or use Python code like:
   ```python
   import frida
   session = frida.attach(<process_id>)
   # ... load a script ...
   ```

2. **Frida Core Logic:** The Frida client (CLI or Python binding) communicates with the Frida server running on the target machine. The core Frida logic determines the target process and the necessary actions, including injecting a helper library into the target process.

3. **Platform-Specific Handling:** Frida identifies the operating system of the target process (Windows in this case).

4. **`frida-core` Invocation:** The Frida core on the target machine calls the appropriate platform-specific injection function. For Windows, this is `_frida_windows_helper_backend_inject_library_file` within the `frida-helper-backend-glue.c` file (after compilation into a library).

5. **Execution within the Helper Process:**  Frida often injects a small helper process or library into the target to perform the actual instrumentation. This `frida-helper-backend-glue.c` code might be part of that helper component.

6. **DLL Injection Process:** The `_frida_windows_helper_backend_inject_library_file` function then executes the steps described earlier (open process, allocate memory, write data, create remote thread) to inject Frida's instrumentation library (or a user-specified DLL).

**In Summary:**

`frida-helper-backend-glue.c` is a fundamental piece of Frida's Windows implementation, responsible for the core task of injecting code into target processes. It leverages low-level Windows APIs, demonstrates concepts relevant to reverse engineering, and incorporates error handling for common issues. Users indirectly trigger this code through Frida's higher-level interfaces when they want to instrument a Windows application.

Prompt: 
```
这是目录为frida/subprojects/frida-core/src/windows/frida-helper-backend-glue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "frida-helper-backend.h"

#include <gio/gio.h>
#include <gum/gum.h>
#include <gum/arch-arm64/gumarm64writer.h>
#include <gum/arch-x86/gumx86writer.h>

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!((n1) cmp (n2))) \
  { \
    failed_operation = op; \
    goto os_failure; \
  }

#define CHECK_NT_RESULT(n1, cmp, n2, op) \
  if (!((n1) cmp (n2))) \
  { \
    failed_operation = op; \
    goto nt_failure; \
  }

typedef struct _FridaInjectInstance FridaInjectInstance;
typedef struct _FridaInjectionDetails FridaInjectionDetails;
typedef struct _FridaRemoteWorkerContext FridaRemoteWorkerContext;

struct _FridaInjectInstance
{
  HANDLE process_handle;
  gpointer free_address;
  gpointer stay_resident_address;
};

struct _FridaInjectionDetails
{
  HANDLE process_handle;
  const WCHAR * dll_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;
};

struct _FridaRemoteWorkerContext
{
  gboolean stay_resident;

  gpointer load_library_impl;
  gpointer get_proc_address_impl;
  gpointer free_library_impl;
  gpointer virtual_free_impl;
  gpointer get_last_error_impl;

  WCHAR dll_path[MAX_PATH + 1];
  gchar entrypoint_name[256];
  gchar entrypoint_data[MAX_PATH + 1];

  gpointer entrypoint;
  gpointer argument;
};

typedef struct _RtlClientId RtlClientId;

struct _RtlClientId
{
  SIZE_T unique_process;
  SIZE_T unique_thread;
};

typedef NTSTATUS (WINAPI * RtlCreateUserThreadFunc) (HANDLE process, SECURITY_DESCRIPTOR * sec,
    BOOLEAN create_suspended, ULONG stack_zero_bits, SIZE_T * stack_reserved, SIZE_T * stack_commit,
    LPTHREAD_START_ROUTINE start_address, LPVOID parameter, HANDLE * thread_handle, RtlClientId * result);

static void frida_propagate_open_process_error (guint32 pid, DWORD os_error, GError ** error);
static gboolean frida_enable_debug_privilege (void);

static gboolean frida_remote_worker_context_init (FridaRemoteWorkerContext * rwc, FridaInjectionDetails * details, GError ** error);
static gsize frida_remote_worker_context_emit_payload (FridaRemoteWorkerContext * rwc, gpointer code);
static void frida_remote_worker_context_destroy (FridaRemoteWorkerContext * rwc, FridaInjectionDetails * details);

static gboolean frida_remote_worker_context_has_resolved_all_kernel32_functions (const FridaRemoteWorkerContext * rwc);
static gboolean frida_remote_worker_context_collect_kernel32_export (const GumExportDetails * details, gpointer user_data);

static gboolean frida_file_exists_and_is_readable (const WCHAR * filename);

void
_frida_windows_helper_backend_inject_library_file (guint32 pid, const gchar * path, const gchar * entrypoint, const gchar * data,
    void ** inject_instance, void ** waitable_thread_handle, GError ** error)
{
  gboolean success = FALSE;
  const gchar * failed_operation;
  NTSTATUS nt_status;
  FridaInjectionDetails details;
  DWORD desired_access;
  HANDLE thread_handle = NULL;
  gboolean rwc_initialized = FALSE;
  FridaRemoteWorkerContext rwc;
  FridaInjectInstance * instance;

  details.dll_path = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  details.entrypoint_name = entrypoint;
  details.entrypoint_data = data;
  details.process_handle = NULL;

  if (!frida_file_exists_and_is_readable (details.dll_path))
    goto invalid_path;

  frida_enable_debug_privilege ();

  desired_access =
      PROCESS_DUP_HANDLE    | /* duplicatable handle                  */
      PROCESS_VM_OPERATION  | /* for VirtualProtectEx and mem access  */
      PROCESS_VM_READ       | /*   ReadProcessMemory                  */
      PROCESS_VM_WRITE      | /*   WriteProcessMemory                 */
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

  details.process_handle = OpenProcess (desired_access, FALSE, pid);
  CHECK_OS_RESULT (details.process_handle, !=, NULL, "OpenProcess");

  if (!frida_remote_worker_context_init (&rwc, &details, error))
    goto beach;
  rwc_initialized = TRUE;

  thread_handle = CreateRemoteThread (details.process_handle, NULL, 0, GUM_POINTER_TO_FUNCPTR (LPTHREAD_START_ROUTINE, rwc.entrypoint),
      rwc.argument, 0, NULL);
  if (thread_handle == NULL)
  {
    RtlCreateUserThreadFunc rtl_create_user_thread;
    RtlClientId client_id;

    rtl_create_user_thread = (RtlCreateUserThreadFunc) GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "RtlCreateUserThread");
    nt_status = rtl_create_user_thread (details.process_handle, NULL, FALSE, 0, NULL, NULL,
        GUM_POINTER_TO_FUNCPTR (LPTHREAD_START_ROUTINE, rwc.entrypoint), rwc.argument, &thread_handle, &client_id);
    CHECK_NT_RESULT (nt_status, == , 0, "RtlCreateUserThread");
  }

  instance = g_slice_new (FridaInjectInstance);
  instance->process_handle = details.process_handle;
  details.process_handle = NULL;
  instance->free_address = rwc.entrypoint;
  instance->stay_resident_address = (guint8 *) rwc.argument + G_STRUCT_OFFSET (FridaRemoteWorkerContext, stay_resident);
  *inject_instance = instance;

  *waitable_thread_handle = thread_handle;
  thread_handle = NULL;

  success = TRUE;

  goto beach;

  /* ERRORS */
invalid_path:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_ARGUMENT,
        "Unable to find DLL at '%s'",
        path);
    goto beach;
  }
os_failure:
  {
    DWORD os_error;

    os_error = GetLastError ();

    if (details.process_handle == NULL)
    {
      frida_propagate_open_process_error (pid, os_error, error);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          (os_error == ERROR_ACCESS_DENIED) ? FRIDA_ERROR_PERMISSION_DENIED : FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while attaching to process with pid %u (%s returned 0x%08lx)",
          pid, failed_operation, os_error);
    }

    goto beach;
  }
nt_failure:
  {
    gint code;

    if (nt_status == 0xC0000022) /* STATUS_ACCESS_DENIED */
      code = FRIDA_ERROR_PERMISSION_DENIED;
    else
      code = FRIDA_ERROR_NOT_SUPPORTED;

    g_set_error (error,
        FRIDA_ERROR,
        code,
        "Unexpected error while attaching to process with pid %u (%s returned 0x%08lx)",
        pid, failed_operation, nt_status);
    goto beach;
  }

beach:
  {
    if (!success && rwc_initialized)
      frida_remote_worker_context_destroy (&rwc, &details);

    if (thread_handle != NULL)
      CloseHandle (thread_handle);

    if (details.process_handle != NULL)
      CloseHandle (details.process_handle);

    g_free ((gpointer) details.dll_path);
  }
}

void
_frida_windows_helper_backend_free_inject_instance (void * inject_instance, gboolean * is_resident)
{
  FridaInjectInstance * instance = inject_instance;
  gboolean stay_resident;
  SIZE_T n_bytes_read;

  if (ReadProcessMemory (instance->process_handle, instance->stay_resident_address, &stay_resident, sizeof (stay_resident),
      &n_bytes_read) && n_bytes_read == sizeof (stay_resident))
  {
    *is_resident = stay_resident;
  }
  else
  {
    *is_resident = FALSE;
  }

  VirtualFreeEx (instance->process_handle, instance->free_address, 0, MEM_RELEASE);

  CloseHandle (instance->process_handle);

  g_slice_free (FridaInjectInstance, instance);
}

static void
frida_propagate_open_process_error (guint32 pid, DWORD os_error, GError ** error)
{
  if (os_error == ERROR_INVALID_PARAMETER)
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PROCESS_NOT_FOUND,
        "Unable to find process with pid %u",
        pid);
  }
  else if (os_error == ERROR_ACCESS_DENIED)
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to access process with pid %u from the current user account",
        pid);
  }
  else
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to access process with pid %u due to an unexpected error (OpenProcess returned 0x%08lx)",
        pid, os_error);
  }
}

static gboolean
frida_enable_debug_privilege (void)
{
  static gboolean enabled = FALSE;
  gboolean success = FALSE;
  HANDLE token = NULL;
  TOKEN_PRIVILEGES privileges;
  LUID_AND_ATTRIBUTES * p = &privileges.Privileges[0];

  if (enabled)
    return TRUE;

  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
    goto beach;

  privileges.PrivilegeCount = 1;
  if (!LookupPrivilegeValueW (NULL, L"SeDebugPrivilege", &p->Luid))
    goto beach;
  p->Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges (token, FALSE, &privileges, 0, NULL, NULL))
    goto beach;

  if (GetLastError () == ERROR_NOT_ALL_ASSIGNED)
    goto beach;

  enabled = TRUE;
  success = TRUE;

beach:
  if (token != NULL)
    CloseHandle (token);

  return success;
}

static gboolean
frida_remote_worker_context_init (FridaRemoteWorkerContext * rwc, FridaInjectionDetails * details, GError ** error)
{
  gpointer code;
  guint code_size;
  SIZE_T page_size, alloc_size;
  DWORD old_protect;

  gum_init ();

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX); /* Executable so debugger can be used to inspect code */
  code_size = frida_remote_worker_context_emit_payload (rwc, code);

  memset (rwc, 0, sizeof (FridaRemoteWorkerContext));

  gum_module_enumerate_exports ("kernel32.dll", frida_remote_worker_context_collect_kernel32_export, rwc);
  if (!frida_remote_worker_context_has_resolved_all_kernel32_functions (rwc))
    goto failed_to_resolve_kernel32_functions;

  StringCbCopyW (rwc->dll_path, sizeof (rwc->dll_path), details->dll_path);
  StringCbCopyA (rwc->entrypoint_name, sizeof (rwc->entrypoint_name), details->entrypoint_name);
  StringCbCopyA (rwc->entrypoint_data, sizeof (rwc->entrypoint_data), details->entrypoint_data);

  page_size = gum_query_page_size ();
  g_assert (code_size <= page_size);

  alloc_size = page_size + sizeof (FridaRemoteWorkerContext);
  rwc->entrypoint = VirtualAllocEx (details->process_handle, NULL, alloc_size, MEM_COMMIT, PAGE_READWRITE);
  if (rwc->entrypoint == NULL)
    goto virtual_alloc_ex_failed;

  if (!WriteProcessMemory (details->process_handle, rwc->entrypoint, code, code_size, NULL))
    goto write_process_memory_failed;

  rwc->argument = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (rwc->entrypoint) + page_size);
  if (!WriteProcessMemory (details->process_handle, rwc->argument, rwc, sizeof (FridaRemoteWorkerContext), NULL))
    goto write_process_memory_failed;

  if (!VirtualProtectEx (details->process_handle, rwc->entrypoint, page_size, PAGE_EXECUTE_READ, &old_protect))
    goto virtual_protect_ex_failed;

  gum_free_pages (code);
  return TRUE;

  /* ERRORS */
failed_to_resolve_kernel32_functions:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while resolving kernel32 functions");
    goto error_common;
  }
virtual_alloc_ex_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error allocating memory in target process (VirtualAllocEx returned 0x%08lx)",
        GetLastError ());
    goto error_common;
  }
write_process_memory_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error writing to memory in target process (WriteProcessMemory returned 0x%08lx)",
        GetLastError ());
    goto error_common;
  }
virtual_protect_ex_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error changing memory permission in target process (VirtualProtectEx returned 0x%08lx)",
        GetLastError ());
    goto error_common;
  }
error_common:
  {
    frida_remote_worker_context_destroy (rwc, details);
    gum_free_pages (code);
    return FALSE;
  }
}

#define EMIT_ARM64_LOAD(reg, field) \
    gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaRemoteWorkerContext, field))
#define EMIT_ARM64_LOAD_ADDRESS_OF(reg, field) \
    gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_##reg, ARM64_REG_X20, G_STRUCT_OFFSET (FridaRemoteWorkerContext, field))
#define EMIT_ARM64_MOVE(dstreg, srcreg) \
    gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_##dstreg, ARM64_REG_##srcreg)
#define EMIT_ARM64_CALL(reg) \
    gum_arm64_writer_put_blr_reg_no_auth (&cw, ARM64_REG_##reg)

static gsize
frida_remote_worker_context_emit_payload (FridaRemoteWorkerContext * rwc, gpointer code)
{
  gsize code_size;
  const gchar * loadlibrary_failed = "loadlibrary_failed";
  const gchar * skip_unload = "skip_unload";
  const gchar * return_result = "return_result";
#ifdef HAVE_ARM64
  GumArm64Writer cw;

  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_SP);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_X20);

  /* x20 = (FridaRemoteWorkerContext *) lpParameter */
  EMIT_ARM64_MOVE (X20, X0);

  /* x19 = LoadLibrary (x20->dll_path) */
  EMIT_ARM64_LOAD_ADDRESS_OF (X0, dll_path);
  EMIT_ARM64_LOAD (X8, load_library_impl);
  EMIT_ARM64_CALL (X8);
  gum_arm64_writer_put_cbz_reg_label (&cw, ARM64_REG_X0, loadlibrary_failed);
  EMIT_ARM64_MOVE (X19, X0);

  /* x8 = GetProcAddress (x19, x20->entrypoint_name) */
  EMIT_ARM64_MOVE (X0, X19);
  EMIT_ARM64_LOAD_ADDRESS_OF (X1, entrypoint_name);
  EMIT_ARM64_LOAD (X8, get_proc_address_impl);
  EMIT_ARM64_CALL (X8);
  EMIT_ARM64_MOVE (X8, X0);

  /* x8 (x20->entrypoint_data, &x20->stay_resident, NULL) */
  EMIT_ARM64_LOAD_ADDRESS_OF (X0, entrypoint_data);
  EMIT_ARM64_LOAD_ADDRESS_OF (X1, stay_resident);
  EMIT_ARM64_MOVE (X2, XZR);
  EMIT_ARM64_CALL (X8);

  /* if (!x20->stay_resident) { */
  EMIT_ARM64_LOAD (X0, stay_resident);
  gum_arm64_writer_put_cbnz_reg_label (&cw, ARM64_REG_X0, skip_unload);

  /* FreeLibrary (xsi) */
  EMIT_ARM64_MOVE (X0, X19);
  EMIT_ARM64_LOAD (X8, free_library_impl);
  EMIT_ARM64_CALL (X8);

  /* } */
  gum_arm64_writer_put_label (&cw, skip_unload);

  /* result = ERROR_SUCCESS */
  EMIT_ARM64_MOVE (X0, XZR);
  gum_arm64_writer_put_b_label (&cw, return_result);

  gum_arm64_writer_put_label (&cw, loadlibrary_failed);
  /* result = GetLastError() */
  EMIT_ARM64_LOAD (X8, get_last_error_impl);
  EMIT_ARM64_CALL (X8);

  gum_arm64_writer_put_label (&cw, return_result);
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_X20);
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  code_size = gum_arm64_writer_offset (&cw);
  gum_arm64_writer_clear (&cw);
#else
  GumX86Writer cw;

  gum_x86_writer_init (&cw, code);

  /* Will clobber these */
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XSI);
  gum_x86_writer_put_push_reg (&cw, GUM_X86_XDI); /* Alignment padding */

  /* xbx = (FridaRemoteWorkerContext *) lpParameter */
#if GLIB_SIZEOF_VOID_P == 4
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_EBX, GUM_X86_ESP, (3 + 1) * sizeof (gpointer));
#else
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_RBX, GUM_X86_RCX);
#endif

  /* xsi = LoadLibrary (xbx->dll_path) */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_X86_XCX,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, dll_path));
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, load_library_impl),
      1,
      GUM_ARG_REGISTER, GUM_X86_XCX);
  gum_x86_writer_put_test_reg_reg (&cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_jcc_near_label (&cw, X86_INS_JE, loadlibrary_failed, GUM_UNLIKELY);
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_X86_XSI, GUM_X86_XAX);

  /* xax = GetProcAddress (xsi, xbx->entrypoint_name) */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_X86_XDX,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, entrypoint_name));
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, get_proc_address_impl),
      2,
      GUM_ARG_REGISTER, GUM_X86_XSI,
      GUM_ARG_REGISTER, GUM_X86_XDX);

  /* xax (xbx->entrypoint_data, &xbx->stay_resident, NULL) */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_X86_XCX,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, entrypoint_data));
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_X86_XDX,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, stay_resident));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_X86_XAX,
      3,
      GUM_ARG_REGISTER, GUM_X86_XCX,
      GUM_ARG_REGISTER, GUM_X86_XDX,
      GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  /* if (!xbx->stay_resident) { */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_X86_EAX,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, stay_resident));
  gum_x86_writer_put_test_reg_reg (&cw, GUM_X86_EAX, GUM_X86_EAX);
  gum_x86_writer_put_jcc_short_label (&cw, X86_INS_JNE, skip_unload, GUM_NO_HINT);

  /* FreeLibrary (xsi) */
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, free_library_impl),
      1,
      GUM_ARG_REGISTER, GUM_X86_XSI);

  /* } */
  gum_x86_writer_put_label (&cw, skip_unload);

  /* result = ERROR_SUCCESS */
  gum_x86_writer_put_xor_reg_reg (&cw, GUM_X86_EAX, GUM_X86_EAX);
  gum_x86_writer_put_jmp_short_label (&cw, return_result);

  gum_x86_writer_put_label (&cw, loadlibrary_failed);
  /* result = GetLastError() */
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI,
      GUM_X86_XBX, G_STRUCT_OFFSET (FridaRemoteWorkerContext, get_last_error_impl),
      0);

  gum_x86_writer_put_label (&cw, return_result);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XDI);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XSI);
  gum_x86_writer_put_pop_reg (&cw, GUM_X86_XBX);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  code_size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);
#endif

  return code_size;
}

static void
frida_remote_worker_context_destroy (FridaRemoteWorkerContext * rwc, FridaInjectionDetails * details)
{
  if (rwc->entrypoint != NULL)
  {
    VirtualFreeEx (details->process_handle, rwc->entrypoint, 0, MEM_RELEASE);
    rwc->entrypoint = NULL;
  }
}

static gboolean
frida_remote_worker_context_has_resolved_all_kernel32_functions (const FridaRemoteWorkerContext * rwc)
{
  return (rwc->load_library_impl != NULL) && (rwc->get_proc_address_impl != NULL) &&
      (rwc->free_library_impl != NULL) && (rwc->virtual_free_impl != NULL);
}

static gboolean
frida_remote_worker_context_collect_kernel32_export (const GumExportDetails * details, gpointer user_data)
{
  FridaRemoteWorkerContext * rwc = user_data;

  if (details->type != GUM_EXPORT_FUNCTION)
    return TRUE;

  if (strcmp (details->name, "LoadLibraryW") == 0)
    rwc->load_library_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "GetProcAddress") == 0)
    rwc->get_proc_address_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "FreeLibrary") == 0)
    rwc->free_library_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "VirtualFree") == 0)
    rwc->virtual_free_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "GetLastError") == 0)
    rwc->get_last_error_impl = GSIZE_TO_POINTER (details->address);

  return TRUE;
}

static gboolean
frida_file_exists_and_is_readable (const WCHAR * filename)
{
  HANDLE file;

  file = CreateFileW (filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, 0, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return FALSE;
  CloseHandle (file);

  return TRUE;
}

"""

```