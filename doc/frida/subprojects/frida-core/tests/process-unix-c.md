Response:
Let's break down the thought process for analyzing this C code for Frida's `process-unix.c`.

1. **Understand the Goal:** The request asks for the functionality of this specific file, its relation to reverse engineering, underlying technologies, logical reasoning, potential user errors, and how a user might reach this code during debugging.

2. **Identify Key Areas:** Based on the request, the analysis should focus on these aspects:
    * Core functionalities.
    * Relevance to reverse engineering.
    * Low-level interactions (OS, kernel, etc.).
    * Logical flow and assumptions.
    * Common usage errors.
    * Debugging context.

3. **High-Level Overview:**  The filename `process-unix.c` and the `#include "frida-tests.h"` strongly suggest this file is part of Frida's testing infrastructure, specifically dealing with process creation, manipulation, and monitoring on Unix-like systems. The presence of conditional compilation (`#ifdef`) for different operating systems (Darwin, FreeBSD, QNX, Linux, Android) further confirms this.

4. **Function-by-Function Analysis:** Go through each function in the code and determine its purpose:

    * `frida_test_process_backend_filename_of()`:  Obtains the executable's file path. This is crucial for reverse engineering to know *what* is being analyzed.
    * `frida_test_process_backend_self_handle()`: Returns a handle representing the current process. This is a unique identifier.
    * `frida_test_process_backend_self_id()`: Returns the process ID (PID) of the current process. Fundamental for process management.
    * `frida_test_process_backend_create()`:  The heart of process creation. It handles forking and executing new processes, including options for suspension and architecture specification (important for cross-architecture testing). The Android-specific `su` logic is a notable detail.
    * `frida_test_process_backend_join()`: Waits for a process to terminate, with a timeout. Essential for synchronizing tests and getting the exit status.
    * `frida_test_process_backend_resume()`: Resumes a suspended process. Key for dynamic analysis where you might want to inspect a process before it fully runs.
    * `frida_test_process_backend_kill()`: Terminates a process forcefully. Important for cleanup or stopping runaway processes.
    * The `FridaTestWaitContext` struct and related functions (`frida_test_wait_context_new`, `_ref`, `_unref`, and the `_on_wait_ready/timeout` callbacks): These handle asynchronous waiting on process termination, primarily used on Linux and Android where `waitpid` isn't always the most convenient approach.
    * The `FridaTestSuperSUSpawnContext` struct and related functions (`_on_super_su_spawn_ready/_read_line_ready`): This is specific to Android and deals with launching processes with root privileges using `su`.

5. **Connect to Reverse Engineering:**  As each function is analyzed, consider its direct or indirect relevance to reverse engineering:

    * Getting the executable path (`filename_of`) and PID (`self_id`) is fundamental for identifying and targeting processes.
    * `create()` allows Frida to launch processes that will be instrumented. The suspension feature is vital for attaching before the target does anything significant. Architecture control is crucial for testing different binary versions.
    * `join()` allows Frida to monitor when the target process finishes, which is important for observing the outcome of instrumentation.
    * `resume()` is key for letting the target process actually execute after Frida has attached and set up hooks.
    * `kill()` provides a way to stop the target process if needed.

6. **Identify Low-Level Interactions:** Look for direct system calls or library functions that interact with the OS kernel or frameworks:

    * `getpid()`: Standard Unix system call to get the process ID.
    * `posix_spawn()` (Darwin, QNX): Low-level function for creating new processes with fine-grained control (like setting signal masks and suspension).
    * `waitpid()` (Darwin, QNX): System call to wait for a child process to change state.
    * `kill()`: System call to send signals to processes.
    * `/proc/self/exe` (Linux):  A virtual file system entry providing the path to the current executable.
    * `gum_freebsd_query_program_path_for_self()` (FreeBSD) and `gum_qnx_query_program_path_for_self()` (QNX):  OS-specific functions for getting the executable path.
    * `GSubprocess` (Linux, Android): GLib's abstraction for managing child processes.
    * Frida's `FridaSuperSUProcess` (Android): Frida-specific API for launching processes with `su`.

7. **Analyze Logical Reasoning:**  Examine conditional statements and assumptions:

    * The `FRIDA_TARGET_PID` environment variable override allows tests to attach to existing processes instead of creating new ones.
    * The handling of standard output redirection (`FRIDA_STDIO_OUTPUT`) during process creation.
    * The architecture-specific handling on macOS (`posix_spawnattr_setbinpref_np`) and the special handling of ARM64e binaries.
    * The `su` logic on Android to gain root privileges.
    * The timeout mechanisms in `frida_test_process_backend_join()`.

8. **Consider User Errors:** Think about how a user interacting with Frida or its testing framework might cause this code to be executed incorrectly:

    * Providing an invalid path to the executable in `frida_test_process_backend_create()`.
    * Incorrectly setting environment variables or command-line arguments.
    * Not handling potential errors returned by these functions.
    * On Android, not having `su` available or configured correctly.

9. **Trace User Actions (Debugging Context):** Imagine a developer debugging a Frida module or Frida itself:

    * They might be writing a test case that uses `frida_test_process_backend_create()` to launch a sample application.
    * If the test fails, they might step through the execution of `frida_test_process_backend_create()` to see if the process is being spawned correctly.
    * They might be investigating why Frida fails to attach to a specific process, and they might trace through the process creation logic.
    * On Android, they might be debugging why Frida can't spawn a process with root privileges.

10. **Structure the Output:** Organize the findings into the categories requested by the prompt (functionality, reverse engineering, low-level knowledge, logic, errors, debugging). Use clear and concise language, providing specific examples where applicable.

11. **Review and Refine:** Read through the analysis to ensure accuracy, completeness, and clarity. Correct any errors or omissions. For instance, double-check the platform-specific details.

By following this detailed thought process, the comprehensive analysis provided previously can be generated. The key is to break down the code into smaller, manageable parts and then connect those parts to the broader context of Frida and reverse engineering.
这个C源代码文件 `process-unix.c` 是 Frida 动态 instrumentation工具测试套件的一部分，专注于在 Unix-like 系统（包括 macOS, Linux, FreeBSD, QNX 和 Android）上进行进程相关的操作。它的主要功能是为 Frida 的测试提供一个统一的后端接口，用于创建、管理和监控目标进程。

以下是该文件的功能及其与逆向、底层知识、逻辑推理和用户错误的关联说明：

**功能列举:**

1. **获取当前进程信息:**
   - `frida_test_process_backend_filename_of(void *handle)`:  获取指定句柄（通常是自身进程的句柄）对应的可执行文件的完整路径。
   - `frida_test_process_backend_self_handle(void)`: 返回代表当前进程的句柄。
   - `frida_test_process_backend_self_id(void)`: 获取当前进程的进程ID (PID)。

2. **创建新进程:**
   - `frida_test_process_backend_create(const char *path, gchar **argv, int argv_length, gchar **envp, int envp_length, FridaTestArch arch, gboolean suspended, void **handle, guint *id, GError **error)`:  这是核心功能，用于创建一个新的进程。它允许指定：
     - 可执行文件的路径 (`path`)。
     - 命令行参数 (`argv`)。
     - 环境变量 (`envp`)。
     - 目标进程的架构 (`arch`)，这在跨架构测试中非常重要。
     - 是否以暂停状态启动 (`suspended`)，这对于在进程启动之初进行注入非常关键。
     - 返回新进程的句柄 (`handle`) 和 PID (`id`)。

3. **管理和监控进程:**
   - `frida_test_process_backend_join(void *handle, guint timeout_msec, GError **error)`:  等待指定句柄的进程结束，并获取其退出状态。可以设置超时时间。
   - `frida_test_process_backend_resume(void *handle, GError **error)`:  恢复一个被暂停的进程的执行。
   - `frida_test_process_backend_kill(void *handle)`:  强制终止指定句柄的进程。

**与逆向方法的关联及举例说明:**

这个文件是 Frida 测试框架的基础，而 Frida 本身就是一个强大的逆向工程工具。该文件提供的功能直接支持了逆向分析的几个关键步骤：

* **启动目标进程进行分析:** `frida_test_process_backend_create` 允许 Frida 在受控的环境下启动目标程序。通过设置 `suspended` 为 `TRUE`，Frida 可以在目标程序执行任何代码之前将其暂停，从而有时间进行代码注入、hook 等操作。
    * **举例:**  逆向工程师可能需要分析一个恶意软件样本。他们可以使用 Frida 的 API，底层会调用到这里的 `frida_test_process_backend_create`，以暂停状态启动该恶意软件，然后注入代码来监控其行为，例如它访问了哪些文件、连接了哪些网络地址等。

* **控制目标进程的执行:** `frida_test_process_backend_resume` 和 `frida_test_process_backend_kill` 提供了控制目标进程生命周期的能力。在分析过程中，可能需要在特定时机恢复进程执行，或者在分析完成后终止进程。
    * **举例:**  在动态调试一个程序时，逆向工程师可能在某个关键函数入口处设置断点，当程序执行到断点时暂停。然后，他们可以使用 Frida 提供的接口（底层调用 `frida_test_process_backend_resume`）来让程序继续执行，直到下一个断点或者完成特定功能。

* **获取目标进程的信息:** `frida_test_process_backend_filename_of` 和 `frida_test_process_backend_self_id` 可以在测试环境中获取被测试进程的可执行文件路径和 PID，这在逆向分析中是识别和定位目标进程的基础。

**涉及的二进制底层、Linux/Android 内核及框架知识及举例说明:**

该文件深入涉及了操作系统的底层机制和概念：

* **进程创建:**  使用了不同的系统调用或库函数来创建进程，具体取决于操作系统：
    * **macOS (HAVE_DARWIN):** 使用 `posix_spawn` 系列函数，这是一个更底层的进程创建机制，允许更精细的控制，例如设置信号掩码、文件描述符继承等。还涉及到 Mach-O 文件格式中的 `MH_EXECUTE` 常量和 `_dyld_` 系列函数来获取可执行文件信息。
    * **Linux (HAVE_LINUX):**  使用 GLib 库提供的 `GSubprocess` API，这是一个跨平台的进程管理抽象层。底层最终也会调用 `fork` 和 `exec` 系列的系统调用。通过读取 `/proc/self/exe` 伪文件系统来获取自身进程的路径。
    * **FreeBSD (HAVE_FREEBSD):** 使用 `gum_freebsd_query_program_path_for_self` 函数来查询程序路径，这涉及到 FreeBSD 特定的接口。
    * **QNX (HAVE_QNX):**  类似 macOS，使用 `posix_spawn`。
    * **Android (HAVE_ANDROID):**  除了使用 `GSubprocess`，还特别处理了需要 root 权限执行的情况，使用了 Frida 内部的 `FridaSuperSUProcess` 来通过 `su` 命令启动进程。这涉及到 Android 的权限管理机制。

* **进程管理和信号:**
    * 使用 `waitpid` (macOS, QNX) 或者 GLib 的异步等待机制 (`g_subprocess_wait_async`) 来等待子进程结束。
    * 使用 `kill` 系统调用发送信号 (如 `SIGCONT` 用于恢复，`SIGKILL` 用于强制终止) 来控制进程。

* **架构 (Architecture):**
    * 在 macOS 上，使用 `posix_spawnattr_setbinpref_np` 来指定要创建的进程的架构偏好，这对于测试 32 位和 64 位应用程序非常重要。在 ARM64 macOS 上，还考虑了 ARM64e 架构的特殊路径。

* **GLib 库:**  在 Linux 和 Android 上，大量使用了 GLib 库提供的抽象，如 `GSubprocessLauncher`、`GSubprocess`、`GMainLoop`、`GTimer` 等，这体现了 Frida 跨平台的设计理念。

* **Android 特殊处理:**  针对 Android 平台，代码专门处理了使用 `su` 命令来提升权限的情况，这反映了 Android 系统中应用程序权限管理的复杂性。

**逻辑推理及假设输入与输出:**

* **假设输入 (针对 `frida_test_process_backend_create`):**
    * `path`: "/bin/ls"
    * `argv`: {"ls", "-l", NULL}
    * `envp`: {"HOME=/tmp", NULL}
    * `arch`: `FRIDA_TEST_ARCH_CURRENT` (假设当前架构)
    * `suspended`: `FALSE`

* **预期输出:**
    * 新进程成功创建。
    * `handle`: 指向新进程的某种操作系统句柄（例如，在 Linux 上可能是 `GSubprocess` 结构体的指针，在 macOS 上可能是一个表示进程 ID 的整数）。
    * `id`: 新进程的 PID。
    * `error`: 如果创建成功，则为 `NULL`。

* **逻辑推理 (针对 `frida_test_process_backend_join`):**
    * **假设输入:**  `handle` 是一个已结束的进程的句柄，`timeout_msec` 是 1000 (毫秒)。
    * **逻辑:** 代码会调用 `waitpid` (在 macOS/QNX 上) 或 `g_subprocess_wait_async` (在 Linux/Android 上) 来等待进程状态变化。由于进程已经结束，这些调用应该立即返回。
    * **预期输出:** 函数返回已结束进程的退出状态码。

* **超时逻辑:** 在 `frida_test_process_backend_join` 中，如果 `timeout_msec` 时间内进程没有结束，则会设置 `error` 并返回一个表示超时的状态。这部分逻辑使用了定时器 (`GTimer` 或 `g_timeout_add`)。

**涉及用户或编程常见的使用错误及举例说明:**

* **无效的可执行文件路径:**  如果传递给 `frida_test_process_backend_create` 的 `path` 指向一个不存在或者没有执行权限的文件，将会导致进程创建失败。
    * **举例:** `frida_test_process_backend_create("/path/to/nonexistent_program", ... , error)`，`error` 将会被设置，指示找不到文件。

* **错误的参数或环境变量:**  传递给 `argv` 或 `envp` 的参数或环境变量不正确可能会导致目标程序启动失败或行为异常。
    * **举例:**  如果目标程序需要特定的环境变量才能正常运行，但在调用 `frida_test_process_backend_create` 时没有设置这些环境变量，程序可能会崩溃或执行不符合预期。

* **忘记处理错误:**  调用这些函数后，如果没有检查 `error` 参数，可能会忽略进程创建或管理过程中发生的错误，导致程序出现未预期的行为。
    * **举例:**  调用 `frida_test_process_backend_create` 后，如果没有检查 `error` 是否为 `NULL`，就直接使用返回的 `handle`，如果进程创建失败，使用无效的句柄可能会导致崩溃。

* **超时时间设置不当:**  在 `frida_test_process_backend_join` 中，如果 `timeout_msec` 设置得过短，可能会在进程正常结束前就返回超时错误。

* **Android 平台上 `su` 命令不可用或权限不足:**  如果要在 Android 上以 root 权限启动进程，但设备上没有安装 `su` 或者 Frida 进程没有执行 `su` 的权限，则会导致启动失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接调用这个 `process-unix.c` 文件中的函数。这些函数是 Frida 内部测试框架的一部分。用户通常通过以下方式间接触发这些代码的执行：

1. **运行 Frida 的测试套件:** Frida 的开发者或贡献者在开发过程中会运行其测试套件，以确保 Frida 的功能正常。这些测试用例会使用 `frida-tests.h` 中定义的接口，而 `process-unix.c` 提供了这些接口在 Unix 系统上的实现。

2. **使用 Frida 的 API 进行进程操作 (间接):**  当用户使用 Frida 的 Python 或 JavaScript API 来操作进程时，例如：
   - `frida.spawn(target)`:  在 Unix 系统上，Frida 的 spawn 函数最终会调用到 `frida_test_process_backend_create` 来创建目标进程。
   - `session.attach(target)` (在某些情况下可能需要先 spawn 再 attach):  如果目标进程需要先启动，也会间接用到 `frida_test_process_backend_create`。
   - `process.resume()`:  会调用到 `frida_test_process_backend_resume`。
   - `process.kill()`:  会调用到 `frida_test_process_backend_kill`。

3. **调试 Frida 自身:**  如果 Frida 的内部逻辑出现问题，开发者可能会使用 GDB 或其他调试器来单步执行 Frida 的代码，这时就有可能进入到 `process-unix.c` 中的函数，例如在分析进程创建或管理相关的 bug 时。

**作为调试线索:**

如果开发者在调试 Frida 的进程处理功能时遇到了问题，`process-unix.c` 可以提供以下调试线索：

* **进程创建失败:** 如果使用 Frida 的 `spawn` 功能无法启动目标进程，开发者可以在 `frida_test_process_backend_create` 函数中设置断点，查看传入的参数是否正确，例如路径、参数、环境变量等。还可以检查系统调用的返回值 (`posix_spawn` 的返回值或 `GSubprocess` 的错误信息) 来确定失败原因。

* **进程挂起或无法恢复:** 如果使用 `resume` 功能后进程没有继续执行，可以在 `frida_test_process_backend_resume` 中检查信号是否发送成功。

* **进程无法正常退出或超时:**  如果在等待进程结束时出现问题，可以在 `frida_test_process_backend_join` 中检查等待机制是否正常工作，以及超时时间的设置是否合理。

* **Android 平台权限问题:**  如果是在 Android 上遇到进程启动问题，可以重点关注 `frida_test_process_backend_create` 中与 `FridaSuperSUProcess` 相关的逻辑，检查 `su` 命令的执行情况和权限设置。

总而言之，`process-unix.c` 是 Frida 测试框架中一个关键的底层模块，它抽象了 Unix 系统上进程操作的细节，为 Frida 的测试提供了统一的接口，并且其功能与动态逆向工程的许多核心步骤紧密相关。理解这个文件的功能和实现细节有助于深入理解 Frida 的工作原理，并能为调试 Frida 自身或使用 Frida 进行逆向分析时提供有价值的线索。

Prompt: 
```
这是目录为frida/subprojects/frida-core/tests/process-unix.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#include "frida-tests.h"

#include "frida-tvos.h"

#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#ifdef HAVE_DARWIN
# include <fcntl.h>
# include <mach-o/dyld.h>
# include <signal.h>
# include <spawn.h>
# include <sys/types.h>
#endif
#ifdef HAVE_FREEBSD
# include <gum/gumfreebsd.h>
#endif

#ifdef HAVE_QNX
# include <spawn.h>
# include <gum/gumqnx.h>
#endif

#if !(defined (HAVE_DARWIN) || defined (HAVE_QNX))

typedef struct _FridaTestWaitContext FridaTestWaitContext;

struct _FridaTestWaitContext
{
  gint ref_count;
  gpointer process;
  GMainLoop * loop;
  gboolean timed_out;
};

# ifdef HAVE_ANDROID

typedef struct _FridaTestSuperSUSpawnContext FridaTestSuperSUSpawnContext;

struct _FridaTestSuperSUSpawnContext
{
  GMainLoop * loop;
  FridaSuperSUProcess * process;
  GDataInputStream * output;
  guint pid;
  GError ** error;
};

static void frida_test_process_backend_on_super_su_spawn_ready (GObject * source_object, GAsyncResult * res, gpointer user_data);
static void frida_test_process_backend_on_super_su_read_line_ready (GObject * source_object, GAsyncResult * res, gpointer user_data);
# endif

static void frida_test_process_backend_on_wait_ready (GObject * source_object, GAsyncResult * res, gpointer user_data);
static gboolean frida_test_process_backend_on_wait_timeout (gpointer user_data);

static FridaTestWaitContext * frida_test_wait_context_new (gpointer process);
static FridaTestWaitContext * frida_test_wait_context_ref (FridaTestWaitContext * context);
static void frida_test_wait_context_unref (FridaTestWaitContext * context);

#endif

static int frida_magic_self_handle = -1;

char *
frida_test_process_backend_filename_of (void * handle)
{
#if defined (HAVE_DARWIN)
  guint image_count, image_idx;

  g_assert_true (handle == &frida_magic_self_handle);

  image_count = _dyld_image_count ();
  for (image_idx = 0; image_idx != image_count; image_idx++)
  {
    if (_dyld_get_image_header (image_idx)->filetype == MH_EXECUTE)
      return g_strdup (_dyld_get_image_name (image_idx));
  }

  g_assert_not_reached ();
  return NULL;
#elif defined (HAVE_LINUX)
  g_assert_true (handle == &frida_magic_self_handle);

  return g_file_read_link ("/proc/self/exe", NULL);
#elif defined (HAVE_FREEBSD)
  g_assert_true (handle == &frida_magic_self_handle);

  return gum_freebsd_query_program_path_for_self (NULL);
#elif defined (HAVE_QNX)
  return gum_qnx_query_program_path_for_self (NULL);
#endif
}

void *
frida_test_process_backend_self_handle (void)
{
  return &frida_magic_self_handle;
}

guint
frida_test_process_backend_self_id (void)
{
  return getpid ();
}

void
frida_test_process_backend_create (const char * path, gchar ** argv,
    int argv_length, gchar ** envp, int envp_length, FridaTestArch arch,
    gboolean suspended, void ** handle, guint * id, GError ** error)
{
  const gchar * override = g_getenv ("FRIDA_TARGET_PID");
  if (override != NULL)
  {
    *id = atoi (override);
    *handle = GSIZE_TO_POINTER (*id);
  }
  else
  {
#if defined (HAVE_DARWIN)
    posix_spawn_file_actions_t actions;
    const gchar * stdio_output_path;
    posix_spawnattr_t attr;
    sigset_t signal_mask_set;
    int result;
    cpu_type_t pref;
    gchar * special_path;
    size_t ocount;
    pid_t pid;

    posix_spawn_file_actions_init (&actions);
    posix_spawn_file_actions_addinherit_np (&actions, 0);

    stdio_output_path = g_getenv ("FRIDA_STDIO_OUTPUT");
    if (stdio_output_path != NULL)
    {
      posix_spawn_file_actions_addopen (&actions, 1, stdio_output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
      posix_spawn_file_actions_adddup2 (&actions, 1, 2);
    }
    else
    {
      posix_spawn_file_actions_addinherit_np (&actions, 1);
      posix_spawn_file_actions_addinherit_np (&actions, 2);
    }

    posix_spawnattr_init (&attr);
    sigemptyset (&signal_mask_set);
    posix_spawnattr_setsigmask (&attr, &signal_mask_set);
    posix_spawnattr_setflags (&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT |
        (suspended ? POSIX_SPAWN_START_SUSPENDED : 0));

    special_path = NULL;

# if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
    pref = (arch == FRIDA_TEST_ARCH_CURRENT) ? CPU_TYPE_X86 : CPU_TYPE_X86_64;
# elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    pref = (arch == FRIDA_TEST_ARCH_CURRENT) ? CPU_TYPE_X86_64 : CPU_TYPE_X86;
# elif defined (HAVE_ARM)
    pref = (arch == FRIDA_TEST_ARCH_CURRENT) ? CPU_TYPE_ARM : CPU_TYPE_ARM64;
# elif defined (HAVE_ARM64)
    pref = CPU_TYPE_ARM64;
#  if __has_feature (ptrauth_calls)
    if (arch == FRIDA_TEST_ARCH_CURRENT)
#  else
    if (arch == FRIDA_TEST_ARCH_OTHER)
#  endif
    {
      special_path = g_strconcat (path, "-arm64e", NULL);
      path = special_path;
    }
# endif
    posix_spawnattr_setbinpref_np (&attr, 1, &pref, &ocount);

    result = posix_spawn (&pid, path, &actions, &attr, argv, envp);

    posix_spawnattr_destroy (&attr);
    posix_spawn_file_actions_destroy (&actions);

    if (result == 0)
    {
      g_free (special_path);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_INVALID_ARGUMENT,
          "Unable to spawn executable at '%s': %s",
          path, g_strerror (errno));
      g_free (special_path);
      return;
    }

    *handle = GSIZE_TO_POINTER (pid);
    *id = pid;
#elif defined (HAVE_QNX)
    int result;
    pid_t pid;

    result = posix_spawn (&pid, path, NULL, NULL, argv, envp);
    if (result != 0)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_INVALID_ARGUMENT,
          "Unable to spawn executable at '%s': %s",
          path, g_strerror (errno));
      return;
    }

    *handle = GSIZE_TO_POINTER (pid);
    *id = pid;
#else
    GSubprocessLauncher * launcher;
    GSubprocess * subprocess;
    GError * spawn_error = NULL;

    launcher = g_subprocess_launcher_new (G_SUBPROCESS_FLAGS_STDIN_INHERIT);
    g_subprocess_launcher_set_environ (launcher, envp);
    subprocess = g_subprocess_launcher_spawnv (launcher, (const char * const *) argv, &spawn_error);
    g_object_unref (launcher);

    if (subprocess != NULL)
    {
      *handle = subprocess;
      *id = atoi (g_subprocess_get_identifier (subprocess));
    }
    else
    {
# ifdef HAVE_ANDROID
      if (spawn_error->domain == G_SPAWN_ERROR && spawn_error->code == G_SPAWN_ERROR_ACCES)
      {
        FridaTestSuperSUSpawnContext ctx;
        gchar * args, * wrapper_argv[] = { "su", "-c", NULL, NULL };

        args = g_strjoinv (" ", argv);

        wrapper_argv[0] = "su";
        wrapper_argv[1] = "-c";
        wrapper_argv[2] = g_strconcat ("echo $BASHPID; exec ", args, NULL);

        g_free (args);

        ctx.loop = g_main_loop_new (NULL, FALSE);
        ctx.process = NULL;
        ctx.output = NULL;
        ctx.pid = 0;
        ctx.error = error;

        frida_super_su_spawn ("/", wrapper_argv, 3, envp, envp_length, TRUE, NULL, frida_test_process_backend_on_super_su_spawn_ready, &ctx);

        g_free (wrapper_argv[2]);

        g_main_loop_run (ctx.loop);

        *handle = ctx.process;
        *id = ctx.pid;

        if (ctx.output != NULL)
          g_object_unref (ctx.output);
        g_main_loop_unref (ctx.loop);
      }
      else
# endif
      {
        g_set_error_literal (error,
            FRIDA_ERROR,
            FRIDA_ERROR_INVALID_ARGUMENT,
            spawn_error->message);
      }

      g_error_free (spawn_error);
    }
#endif
  }
}

int
frida_test_process_backend_join (void * handle, guint timeout_msec,
    GError ** error)
{
  int status = -1;

#if defined (HAVE_DARWIN) || defined (HAVE_QNX)
  GTimer * timer;

  timer = g_timer_new ();

  while (TRUE)
  {
    int ret;

    ret = waitpid (GPOINTER_TO_SIZE (handle), &status, WNOHANG);
    if (ret > 0)
    {
      if (WIFEXITED (status))
      {
        status = WEXITSTATUS (status);
      }
      else
      {
        g_set_error (error,
            FRIDA_ERROR,
            FRIDA_ERROR_NOT_SUPPORTED,
            "Unexpected error while waiting for process to exit (child process crashed)");
        status = -1;
      }

      break;
    }
    else if (ret < 0 && errno != ETIMEDOUT)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while waiting for process to exit (waitpid returned '%s')",
          g_strerror (errno));
      break;
    }
    else if (g_timer_elapsed (timer, NULL) * 1000.0 >= timeout_msec)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_TIMED_OUT,
          "Timed out while waiting for process to exit");
      break;
    }

    g_usleep (G_USEC_PER_SEC / 50);
  }

  g_timer_destroy (timer);
#else
  FridaTestWaitContext * context;

  context = frida_test_wait_context_new (handle);

# ifdef HAVE_ANDROID
  if (FRIDA_SUPER_SU_IS_PROCESS (handle))
  {
    FridaSuperSUProcess * process = handle;
    guint timeout;

    frida_super_su_process_wait (process, NULL, frida_test_process_backend_on_wait_ready, frida_test_wait_context_ref (context));
    timeout = g_timeout_add (timeout_msec, frida_test_process_backend_on_wait_timeout, frida_test_wait_context_ref (context));

    g_main_loop_run (context->loop);

    if (!context->timed_out)
    {
      g_source_remove (timeout);

      status = frida_super_su_process_get_exit_status (process);
    }
  }
  else
# endif
  {
    GSubprocess * subprocess = handle;
    guint timeout;

    g_subprocess_wait_async (subprocess, NULL, frida_test_process_backend_on_wait_ready, frida_test_wait_context_ref (context));
    timeout = g_timeout_add (timeout_msec, frida_test_process_backend_on_wait_timeout, frida_test_wait_context_ref (context));

    g_main_loop_run (context->loop);

    if (!context->timed_out)
    {
      g_source_remove (timeout);

      if (g_subprocess_get_if_exited (subprocess))
        status = g_subprocess_get_exit_status (subprocess);
    }
  }

  if (context->timed_out)
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_TIMED_OUT,
        "Timed out while waiting for process to exit");
  }

  frida_test_wait_context_unref (context);
#endif

  return status;
}

void
frida_test_process_backend_resume (void * handle, GError ** error)
{
#if defined (HAVE_DARWIN) || defined (HAVE_QNX)
  kill (GPOINTER_TO_SIZE (handle), SIGCONT);
#else
  (void) handle;

  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not implemented on this OS");
#endif
}

void
frida_test_process_backend_kill (void * handle)
{
#if defined (HAVE_DARWIN) || defined (HAVE_QNX)
  kill (GPOINTER_TO_SIZE (handle), SIGKILL);
#else
  g_subprocess_force_exit (handle);
  g_object_unref (handle);
#endif
}

#if !(defined (HAVE_DARWIN) || defined (HAVE_QNX))

# ifdef HAVE_ANDROID

static void
frida_test_process_backend_on_super_su_spawn_ready (GObject * source_object, GAsyncResult * res, gpointer user_data)
{
  FridaTestSuperSUSpawnContext * ctx = user_data;

  ctx->process = frida_super_su_spawn_finish (res, ctx->error);
  if (ctx->process == NULL)
  {
    g_main_loop_quit (ctx->loop);
    return;
  }

  ctx->output = g_data_input_stream_new (frida_super_su_process_get_output (ctx->process));
  g_data_input_stream_read_line_async (ctx->output, G_PRIORITY_DEFAULT, NULL, frida_test_process_backend_on_super_su_read_line_ready, ctx);
}

static void
frida_test_process_backend_on_super_su_read_line_ready (GObject * source_object, GAsyncResult * res, gpointer user_data)
{
  FridaTestSuperSUSpawnContext * ctx = user_data;
  gsize length;
  gchar * line;

  line = g_data_input_stream_read_line_finish_utf8 (ctx->output, res, &length, ctx->error);
  if (line != NULL)
  {
    ctx->pid = atoi (line);
    g_free (line);
  }

  g_main_loop_quit (ctx->loop);
}

# endif

static void
frida_test_process_backend_on_wait_ready (GObject * source_object, GAsyncResult * res, gpointer user_data)
{
  FridaTestWaitContext * ctx = user_data;

  g_main_loop_quit (ctx->loop);

  frida_test_wait_context_unref (ctx);
}

static gboolean
frida_test_process_backend_on_wait_timeout (gpointer user_data)
{
  FridaTestWaitContext * ctx = user_data;

  ctx->timed_out = TRUE;
  g_main_loop_quit (ctx->loop);

  frida_test_wait_context_unref (ctx);

  return FALSE;
}

static FridaTestWaitContext *
frida_test_wait_context_new (gpointer process)
{
  FridaTestWaitContext * context;

  context = g_slice_new (FridaTestWaitContext);
  context->ref_count = 1;
  context->process = process;
  context->loop = g_main_loop_new (NULL, FALSE);
  context->timed_out = FALSE;

  return context;
}

static FridaTestWaitContext *
frida_test_wait_context_ref (FridaTestWaitContext * context)
{
  context->ref_count++;
  return context;
}

static void
frida_test_wait_context_unref (FridaTestWaitContext * context)
{
  if (--context->ref_count == 0)
  {
    g_main_loop_unref (context->loop);
    g_object_unref (context->process);

    g_slice_free (FridaTestWaitContext, context);
  }
}

#endif

"""

```