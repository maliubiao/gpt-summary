Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of the Frida dynamic instrumentation tool. They are particularly interested in:

1. **Core Functionality:** What does this code do?
2. **Relationship to Reversing:** How does this code help in reverse engineering? Provide examples.
3. **Low-Level Details:**  Does it interact with binary code, Linux internals, or the Android kernel/framework?  Give examples.
4. **Logic and Data Flow:** Are there any logical deductions based on inputs? Provide example inputs and outputs.
5. **Common Usage Errors:**  What mistakes might a user or programmer make when using this code?
6. **User Journey:** How does a user's actions lead to this specific code being executed (debugging context)?

Since this is part 2 of a 3-part series, the user specifically asks for a summary of the provided code.

**Plan:**

1. **Analyze the code:** Read through the functions and identify their purpose. Focus on the system calls and data structures used.
2. **Group related functions:**  Identify logical units of functionality (e.g., thread manipulation, module enumeration, memory range enumeration).
3. **Summarize each functional unit:** Briefly describe what each group of functions does.
4. **Connect to reversing concepts:** Explain how each functionality aids in reverse engineering.
5. **Highlight low-level interactions:** Point out the usage of system calls, `/proc` filesystem, ELF structures, etc.
6. **Infer logic and data flow:**  Where possible, describe how inputs are processed and what outputs are produced. Give examples if clear.
7. **Identify potential user errors:**  Think about how a developer using Frida might misuse these APIs.
8. **Construct a user journey:**  Outline a typical Frida use case that would involve this code.
9. **Synthesize the summary:** Combine the findings into a concise summary of the code's functionality.
这是 frida 工具中负责在 Linux 系统上与进程交互的核心代码文件的一部分。从提供的代码片段来看，其主要功能集中在以下几个方面：

**1. 线程操作：**

* **挂起和恢复线程 (`gum_thread_suspend`, `gum_thread_resume`)：**  通过 `tgkill` 系统调用向指定线程发送 `SIGSTOP` 信号来暂停线程执行，发送 `SIGCONT` 信号来恢复线程执行。这在逆向分析中非常关键，允许在特定时刻中断线程，检查其状态。
    * **逆向举例:**  当分析一个多线程程序时，可以使用 `gum_thread_suspend` 暂停某个工作线程，然后检查其寄存器状态、调用栈或内存，以理解其正在执行的任务。
    * **二进制底层/Linux:**  直接使用了 Linux 提供的 `tgkill` 系统调用，这是一个用于向特定线程发送信号的系统调用。
* **获取和设置硬件断点 (`gum_thread_set_hardware_breakpoint`, `gum_thread_unset_hardware_breakpoint`)：**  利用 Linux 的 `ptrace` 机制以及调试寄存器（如 DR0-DR7）来设置和取消硬件断点。硬件断点允许在 CPU 执行到特定地址时触发中断，非常适用于精确的指令级跟踪。
    * **逆向举例:**  想要跟踪某个特定函数的执行流程，可以在该函数的入口地址设置硬件断点。当程序执行到该函数时，会触发断点，逆向分析人员可以检查此时的 CPU 状态。
    * **二进制底层/Linux:** 这部分代码直接操作了 CPU 的调试寄存器，这些寄存器是硬件层面的概念。通过 `ptrace` 系统调用与目标进程交互，修改其寄存器状态。
* **获取和设置硬件观察点 (`gum_thread_set_hardware_watchpoint`, `gum_thread_unset_hardware_watchpoint`)：** 类似于硬件断点，但观察点会在指定内存地址被访问（读取或写入）时触发中断。这对于追踪特定变量的访问非常有用。
    * **逆向举例:**  想要知道哪个代码段修改了某个全局变量的值，可以设置一个针对该变量地址的写观察点。当有代码写入该地址时，程序会被中断。
    * **二进制底层/Linux:** 同样涉及到 CPU 调试寄存器的操作，并通过 `ptrace` 与目标进程通信。
* **枚举线程 (`_gum_process_enumerate_threads`)：**  通过读取 `/proc/self/task` 目录下的子目录来获取当前进程的所有线程 ID，并可以对每个线程执行指定的回调函数。这为批量操作线程提供了基础。
    * **逆向举例:**  可以枚举进程中的所有线程，并暂停它们，以便在安全的环境下检查整个进程的状态。
    * **Linux:**  依赖于 Linux 的 `/proc` 文件系统，这是一个虚拟文件系统，提供了内核数据的接口。

**2. 模块操作：**

* **加载模块 (`gum_module_load`)：** 使用 `dlopen` 函数动态加载指定的共享库。这允许在运行时向目标进程注入代码或利用已加载的库。
    * **逆向举例:**  可以加载自定义的共享库到目标进程中，以执行特定的监控或修改操作。
    * **Linux:**  使用了标准的动态链接器接口 `dlopen`。
* **查找模块导出符号 (`gum_module_find_export_by_name`)：** 使用 `dlsym` 函数在指定的模块中查找导出符号的地址。这是进行 hook 操作的关键步骤。
    * **逆向举例:**  想要 hook 某个库函数，首先需要使用 `gum_module_find_export_by_name` 获取该函数的地址。
    * **Linux:**  使用了动态链接器接口 `dlsym`。
* **枚举模块 (`_gum_process_enumerate_modules`)：**  通过多种方式（如 `dl_iterate_phdr` 或读取 `/proc/self/maps`）获取当前进程加载的所有模块的信息（基址、大小、路径等）。
    * **逆向举例:**  在逆向分析时，了解目标进程加载了哪些库是至关重要的。可以通过枚举模块来确定感兴趣的目标函数所在的库。
    * **Linux:**  涉及到读取 `/proc/self/maps` 文件，以及可能使用 `dl_iterate_phdr` 这样的 glibc 提供的接口。
* **解析模块名称 (`_gum_process_resolve_module_name`)：** 将模块名称（可以是库文件名或完整路径）解析为模块的完整路径和基址。
    * **逆向举例:**  用户可能只知道要 hook 的函数所在的库文件名，但不知道其完整路径，`gum_process_resolve_module_name` 可以帮助找到该库的加载地址。
    * **Linux:**  可能涉及到读取 `/proc/self/maps` 和使用 `dlopen` 尝试加载。

**3. 内存操作：**

* **枚举内存区域 (`_gum_process_enumerate_ranges`)：**  通过读取 `/proc/<pid>/maps` 文件来获取进程的内存区域信息，包括起始地址、结束地址、权限等。
    * **逆向举例:**  可以用来查找具有特定权限（例如，可执行、可写）的内存区域，这对于理解代码或数据在内存中的布局很有帮助。
    * **Linux:**  依赖于 Linux 的 `/proc` 文件系统。

**4. 其他功能：**

* **获取 CPU 类型 (`gum_linux_cpu_type_from_pid`, `gum_linux_cpu_type_from_file`, `gum_linux_cpu_type_from_auxv`)：**  通过读取 `/proc/<pid>/auxv` 或检查 ELF 文件头来确定目标进程或文件的 CPU 架构。这对于处理不同架构的程序至关重要。
    * **Linux:**  涉及到读取 `/proc` 文件系统和解析 ELF 文件格式。
* **操作进程的 dumpable 属性 (`gum_acquire_dumpability`, `gum_release_dumpability`)：**  在某些情况下，为了能够使用 `ptrace` 等功能，需要将目标进程设置为 dumpable。这段代码提供了修改和恢复进程 dumpable 属性的功能。
    * **Linux:**  使用了 `prctl` 系统调用来获取和设置进程的 dumpable 属性。
* **读取 `/proc/maps` 文件 (`gum_proc_maps_iter_init_for_self`, `gum_proc_maps_iter_init_for_pid`, `gum_proc_maps_iter_next`)：** 提供了一种方便的方式来迭代读取 `/proc/<pid>/maps` 文件的内容，这是许多枚举功能的基础。
    * **Linux:**  直接操作 Linux 的 `/proc` 文件系统。
* **处理 `ptrace` 系统调用的辅助函数 (`gum_linux_modify_thread`, `gum_await_ack`, `gum_put_ack`)：**  封装了与目标进程进行 `ptrace` 交互的细节，包括发送命令和接收确认。

**与逆向方法的关系举例：**

* **动态分析:** 通过挂起线程、设置断点和观察点，可以动态地跟踪程序的执行流程和状态，这比静态分析更能揭示程序的运行时行为。
* **Hook 技术:**  通过查找模块导出符号，可以实现对目标函数的 hook，即在目标函数执行前后插入自定义的代码，以监控其行为或修改其返回值。
* **内存分析:** 枚举内存区域可以帮助理解程序的内存布局，找到感兴趣的数据结构或代码段。

**涉及到二进制底层、Linux、Android 内核及框架的知识举例：**

* **二进制底层:**  直接操作 CPU 寄存器（如调试寄存器）和内存地址。
* **Linux:**  大量使用了 Linux 特有的系统调用（如 `ptrace`, `tgkill`, `prctl`）和 `/proc` 文件系统。
* **Android 内核及框架:**  代码中包含对 Android 特定 linker 行为的处理 (`gum_android_get_linker_flavor`)，表明该代码可以应用于 Android 环境下的逆向。

**逻辑推理的假设输入与输出举例：**

假设输入：

* `gum_thread_suspend(1234)`：尝试挂起线程 ID 为 1234 的线程。
* `/proc/1234/status` 文件存在且指示线程正在运行。

预期输出：

* 如果系统调用成功，则线程 1234 进入暂停状态。
* 如果系统调用失败（例如，线程不存在或权限不足），则返回错误信息。

**涉及用户或编程常见的使用错误举例：**

* **错误的线程 ID：**  用户可能传递了一个不存在的线程 ID 给 `gum_thread_suspend` 或其他线程操作函数。
* **权限不足：**  在没有足够权限的情况下尝试操作其他进程的线程或内存。
* **不正确的断点/观察点地址：**  设置的硬件断点或观察点地址可能无效或不在可执行内存区域。
* **忘记释放 dumpability：**  在使用 `gum_acquire_dumpability` 后，忘记调用 `gum_release_dumpability`，可能会影响其他操作或进程。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本：** 用户编写一个 JavaScript 或 Python 脚本，使用 Frida 的 API 来与目标进程交互。例如，他们可能想要 hook 某个函数。
2. **Frida 脚本调用 Gum API：** Frida 的 JavaScript 或 Python 绑定会将用户的请求转换为对 Gum 库（Frida 的核心引擎）的 C 函数调用。
3. **调用 `gumprocess-linux.c` 中的函数：**  例如，用户脚本调用 `Interceptor.attach()` 来 hook 一个函数，最终会调用到 `gum_module_find_export_by_name` 来查找函数地址，或者调用到硬件断点/观察点的设置函数。
4. **系统调用：**  `gumprocess-linux.c` 中的函数会进一步调用 Linux 的系统调用，如 `ptrace` 或 `tgkill`，来完成实际的操作。
5. **内核交互：**  系统调用会陷入 Linux 内核，内核执行相应的操作，并返回结果。
6. **结果返回：**  结果会沿着调用链返回给用户的 Frida 脚本。

作为调试线索，当用户在使用 Frida 遇到问题时，可以检查 Frida 脚本的调用栈，查看是否最终调用到了 `gumprocess-linux.c` 中的相关函数，并检查传递给这些函数的参数是否正确，以及系统调用的返回值来定位问题。

**功能归纳 (第 2 部分)：**

总而言之，提供的代码片段是 Frida 在 Linux 平台上实现动态 instrumentation 的关键组成部分，它提供了对目标进程线程、模块和内存进行底层操作的能力，包括线程的挂起/恢复、硬件断点/观察点的设置、模块的加载/卸载/枚举、以及内存区域的枚举。这些功能是 Frida 实现 hook、代码注入、动态跟踪等核心特性的基础。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-linux/gumprocess-linux.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
, GUM_ACK_FAILED_TO_STOP);
    goto beach;
  }
failed_to_read:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_READ);
    goto beach;
  }
failed_to_write:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_WRITE);
    goto beach;
  }
failed_to_detach:
  {
    gum_put_ack (fd, GUM_ACK_FAILED_TO_DETACH);
    goto beach;
  }
beach:
  {
    if (attached)
    {
      gum_libc_ptrace (PTRACE_DETACH, ctx->thread_id, NULL,
          GINT_TO_POINTER (SIGCONT));
    }

    return 0;
  }
}

static gboolean
gum_await_ack (gint fd,
               GumModifyThreadAck expected_ack)
{
  guint8 value;
  gssize res;

  res = GUM_TEMP_FAILURE_RETRY (gum_libc_read (fd, &value, sizeof (value)));
  if (res == -1)
    return FALSE;

  return value == expected_ack;
}

static void
gum_put_ack (gint fd,
             GumModifyThreadAck ack)
{
  guint8 value;

  value = ack;
  GUM_TEMP_FAILURE_RETRY (gum_libc_write (fd, &value, sizeof (value)));
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  GDir * dir;
  const gchar * name;
  gboolean carry_on = TRUE;

  dir = g_dir_open ("/proc/self/task", 0, NULL);
  g_assert (dir != NULL);

  while (carry_on && (name = g_dir_read_name (dir)) != NULL)
  {
    GumThreadDetails details;
    gchar * thread_name;

    details.id = atoi (name);

    thread_name = gum_thread_read_name (details.id);
    details.name = thread_name;

    if (gum_thread_read_state (details.id, &details.state))
    {
      if (gum_process_modify_thread (details.id, gum_store_cpu_context,
            &details.cpu_context, GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY))
      {
        carry_on = func (&details, user_data);
      }
    }

    g_free (thread_name);
  }

  g_dir_close (dir);
}

static void
gum_store_cpu_context (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  memcpy (user_data, cpu_context, sizeof (GumCpuContext));
}

gboolean
_gum_process_collect_main_module (const GumModuleDetails * details,
                                  gpointer user_data)
{
  GumModuleDetails ** out = user_data;

  *out = gum_module_details_copy (details);

  return FALSE;
}

void
_gum_process_enumerate_modules (GumFoundModuleFunc func,
                                gpointer user_data)
{
  gum_do_enumerate_modules (gum_process_query_libc_name (), func, user_data);
}

static void
gum_do_enumerate_modules (const gchar * libc_name,
                          GumFoundModuleFunc func,
                          gpointer user_data)
{
  const GumProgramModules * pm;
  static gsize iterate_phdr_value = 0;
  GumDlIteratePhdrImpl iterate_phdr;

  pm = gum_query_program_modules ();

  if (pm->rtld == GUM_PROGRAM_RTLD_NONE)
  {
    if (!func (&pm->program, user_data))
      return;

    if (pm->vdso.range->base_address != 0)
      func (&pm->vdso, user_data);

    return;
  }

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
  {
    gum_android_enumerate_modules (func, user_data);
    return;
  }
#endif

  if (g_once_init_enter (&iterate_phdr_value))
  {
    GumAddress impl;

    impl = gum_module_find_export_by_name (libc_name, "dl_iterate_phdr");

    g_once_init_leave (&iterate_phdr_value, impl + 1);
  }

  iterate_phdr = GSIZE_TO_POINTER (iterate_phdr_value - 1);
  if (iterate_phdr != NULL)
  {
    gum_process_enumerate_modules_by_using_libc (iterate_phdr, func, user_data);
  }
  else
  {
    gum_linux_enumerate_modules_using_proc_maps (func, user_data);
  }
}

static void
gum_process_enumerate_modules_by_using_libc (GumDlIteratePhdrImpl iterate_phdr,
                                             GumFoundModuleFunc func,
                                             gpointer user_data)
{
  GumEnumerateModulesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.named_ranges = gum_linux_collect_named_ranges ();

  iterate_phdr (gum_emit_module_from_phdr, &ctx);

  g_hash_table_unref (ctx.named_ranges);
}

static gint
gum_emit_module_from_phdr (struct dl_phdr_info * info,
                           gsize size,
                           gpointer user_data)
{
  GumEnumerateModulesContext * ctx = user_data;
  GumMemoryRange range;
  GumLinuxNamedRange * named_range;
  const gchar * path;
  gchar * name;
  GumModuleDetails details;
  gboolean carry_on;

  gum_compute_elf_range_from_phdrs (info->dlpi_phdr, sizeof (ElfW(Phdr)),
      info->dlpi_phnum, 0, &range);

  named_range = g_hash_table_lookup (ctx->named_ranges,
      GSIZE_TO_POINTER (range.base_address));

  path = (named_range != NULL) ? named_range->name : info->dlpi_name;
  name = g_path_get_basename (path);

  details.name = name;
  details.range = &range;
  details.path = path;

  carry_on = ctx->func (&details, ctx->user_data);

  g_free (name);

  return carry_on ? 0 : 1;
}

void
gum_linux_enumerate_modules_using_proc_maps (GumFoundModuleFunc func,
                                             gpointer user_data)
{
  GumProcMapsIter iter;
  gchar * path, * next_path;
  const gchar * line;
  gboolean carry_on = TRUE;
  gboolean got_line = FALSE;

  gum_proc_maps_iter_init_for_self (&iter);

  path = g_malloc (PATH_MAX);
  next_path = g_malloc (PATH_MAX);

  do
  {
    const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };
    GumModuleDetails details;
    GumMemoryRange range;
    GumAddress end;
    gchar perms[5] = { 0, };
    gint n;
    gboolean is_vdso, readable, shared;
    gchar * name;

    if (!got_line)
    {
      if (!gum_proc_maps_iter_next (&iter, &line))
        break;
    }
    else
    {
      got_line = FALSE;
    }

    n = sscanf (line,
        "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
        "%4c "
        "%*x %*s %*d "
        "%[^\n]",
        &range.base_address, &end,
        perms,
        path);
    if (n == 3)
      continue;
    g_assert (n == 4);

    is_vdso = gum_try_translate_vdso_name (path);

    readable = perms[0] == 'r';
    shared = perms[3] == 's';
    if (!readable || shared)
      continue;
    else if ((path[0] != '/' && !is_vdso) || g_str_has_prefix (path, "/dev/"))
      continue;
    else if (RUNNING_ON_VALGRIND && strstr (path, "/valgrind/") != NULL)
      continue;
    else if (memcmp (GSIZE_TO_POINTER (range.base_address), elf_magic,
        sizeof (elf_magic)) != 0)
      continue;

    name = g_path_get_basename (path);

    range.size = end - range.base_address;

    details.name = name;
    details.range = &range;
    details.path = path;

    while (gum_proc_maps_iter_next (&iter, &line))
    {
      n = sscanf (line,
          "%*x-%" G_GINT64_MODIFIER "x %*c%*c%*c%*c %*x %*s %*d %[^\n]",
          &end,
          next_path);
      if (n == 1)
      {
        continue;
      }
      else if (n == 2 && next_path[0] == '[')
      {
        if (!gum_try_translate_vdso_name (next_path))
          continue;
      }

      if (n == 2 && strcmp (next_path, path) == 0)
      {
        range.size = end - range.base_address;
      }
      else
      {
        got_line = TRUE;
        break;
      }
    }

    carry_on = func (&details, user_data);

    g_free (name);
  }
  while (carry_on);

  g_free (path);
  g_free (next_path);

  gum_proc_maps_iter_destroy (&iter);
}

GHashTable *
gum_linux_collect_named_ranges (void)
{
  GHashTable * result;
  GumProcMapsIter iter;
  gchar * name, * next_name;
  const gchar * line;
  gboolean carry_on = TRUE;
  gboolean got_line = FALSE;

  result = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_linux_named_range_free);

  gum_proc_maps_iter_init_for_self (&iter);

  name = g_malloc (PATH_MAX);
  next_name = g_malloc (PATH_MAX);

  do
  {
    GumAddress start, end;
    gsize size;
    gint n;
    GumLinuxNamedRange * range;

    if (!got_line)
    {
      if (!gum_proc_maps_iter_next (&iter, &line))
        break;
    }
    else
    {
      got_line = FALSE;
    }

    n = sscanf (line,
        "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
        "%*4c "
        "%*x %*s %*d "
        "%[^\n]",
        &start, &end,
        name);
    if (n == 2)
      continue;
    g_assert (n == 3);

    gum_try_translate_vdso_name (name);

    size = end - start;

    while (gum_proc_maps_iter_next (&iter, &line))
    {
      n = sscanf (line,
          "%*x-%" G_GINT64_MODIFIER "x %*c%*c%*c%*c %*x %*s %*d %[^\n]",
          &end,
          next_name);
      if (n == 1)
      {
        continue;
      }
      else if (n == 2 && next_name[0] == '[')
      {
        if (!gum_try_translate_vdso_name (next_name))
          continue;
      }

      if (n == 2 && strcmp (next_name, name) == 0)
      {
        size = end - start;
      }
      else
      {
        got_line = TRUE;
        break;
      }
    }

    range = g_slice_new (GumLinuxNamedRange);

    range->name = g_strdup (name);
    range->base = GSIZE_TO_POINTER (start);
    range->size = size;

    g_hash_table_insert (result, range->base, range);
  }
  while (carry_on);

  g_free (name);
  g_free (next_name);

  gum_proc_maps_iter_destroy (&iter);

  return result;
}

static void
gum_linux_named_range_free (GumLinuxNamedRange * range)
{
  g_free ((gpointer) range->name);

  g_slice_free (GumLinuxNamedRange, range);
}

static gboolean
gum_try_translate_vdso_name (gchar * name)
{
  if (strcmp (name, "[vdso]") == 0)
  {
    strcpy (name, "linux-vdso.so.1");
    return TRUE;
  }

  return FALSE;
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
  gum_linux_enumerate_ranges (getpid (), prot, func, user_data);
}

void
gum_linux_enumerate_ranges (pid_t pid,
                            GumPageProtection prot,
                            GumFoundRangeFunc func,
                            gpointer user_data)
{
  GumProcMapsIter iter;
  gboolean carry_on = TRUE;
  const gchar * line;

  gum_proc_maps_iter_init_for_pid (&iter, pid);

  while (carry_on && gum_proc_maps_iter_next (&iter, &line))
  {
    GumRangeDetails details;
    GumMemoryRange range;
    GumFileMapping file;
    GumAddress end;
    gchar perms[5] = { 0, };
    guint64 inode;
    gint length;

    sscanf (line,
        "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
        "%4c "
        "%" G_GINT64_MODIFIER "x %*s %" G_GINT64_MODIFIER "d"
        "%n",
        &range.base_address, &end,
        perms,
        &file.offset, &inode,
        &length);

    range.size = end - range.base_address;

    details.file = NULL;
    if (inode != 0)
    {
      file.path = strchr (line + length, '/');
      if (file.path != NULL)
      {
        details.file = &file;
        file.size = 0; /* TODO */

        if (RUNNING_ON_VALGRIND && strstr (file.path, "/valgrind/") != NULL)
          continue;
      }
    }

    details.range = &range;
    details.protection = gum_page_protection_from_proc_perms_string (perms);

    if ((details.protection & prot) == prot)
    {
      carry_on = func (&details, user_data);
    }
  }

  gum_proc_maps_iter_destroy (&iter);
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  /* Not implemented */
}

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
#ifdef HAVE_PTHREAD_ATTR_GETSTACK
  guint n = 0;
  pthread_attr_t attr;
  gboolean allocated = FALSE;
  void * stack_addr;
  size_t stack_size;
  GumMemoryRange * range;

  if (pthread_getattr_np (pthread_self (), &attr) != 0)
    goto beach;
  allocated = TRUE;

  if (pthread_attr_getstack (&attr, &stack_addr, &stack_size) != 0)
    goto beach;

  range = &ranges[0];
  range->base_address = GUM_ADDRESS (stack_addr);
  range->size = stack_size;

  n = 1;

beach:
  if (allocated)
    pthread_attr_destroy (&attr);

  return n;
#else
  return 0;
#endif
}

gint
gum_thread_get_system_error (void)
{
  return errno;
}

void
gum_thread_set_system_error (gint value)
{
  errno = value;
}

gboolean
gum_thread_suspend (GumThreadId thread_id,
                    GError ** error)
{
  if (syscall (__NR_tgkill, getpid (), thread_id, SIGSTOP) != 0)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    return FALSE;
  }
}

gboolean
gum_thread_resume (GumThreadId thread_id,
                   GError ** error)
{
  if (syscall (__NR_tgkill, getpid (), thread_id, SIGCONT) != 0)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    return FALSE;
  }
}

gboolean
gum_thread_set_hardware_breakpoint (GumThreadId thread_id,
                                    guint breakpoint_id,
                                    GumAddress address,
                                    GError ** error)
{
  GumSetHardwareBreakpointContext bpc;

  bpc.breakpoint_id = breakpoint_id;
  bpc.address = address;

  gum_linux_modify_thread (thread_id, GUM_REGS_DEBUG_BREAK,
      gum_do_set_hardware_breakpoint, &bpc, error);

  return gum_linux_modify_thread (thread_id, GUM_REGS_DEBUG_BREAK,
      gum_do_set_hardware_breakpoint, &bpc, error);
}

static void
gum_do_set_hardware_breakpoint (GumThreadId thread_id,
                                GumRegs * regs,
                                gpointer user_data)
{
  GumDebugRegs * dr = &regs->debug;
  GumSetHardwareBreakpointContext * bpc = user_data;

#if defined (HAVE_I386)
  _gum_x86_set_breakpoint (&dr->dr7, &dr->dr0, bpc->breakpoint_id,
      bpc->address);
#elif defined (HAVE_ARM)
  _gum_arm_set_breakpoint (dr->cr, dr->vr, bpc->breakpoint_id, bpc->address);
#elif defined (HAVE_ARM64)
  _gum_arm64_set_breakpoint (dr->cr, dr->vr, bpc->breakpoint_id, bpc->address);
#elif defined (HAVE_MIPS) && GLIB_SIZEOF_VOID_P == 4
  g_assert (dr->style == GUM_MIPS_WATCH_MIPS32);
  _gum_mips_set_breakpoint (dr->mips32.watch_lo, dr->mips32.watch_hi,
      bpc->breakpoint_id, bpc->address);
#elif defined (HAVE_MIPS) && GLIB_SIZEOF_VOID_P == 8
  g_assert (dr->style == GUM_MIPS_WATCH_MIPS64);
  _gum_mips_set_breakpoint (dr->mips64.watch_lo, dr->mips64.watch_hi,
      bpc->breakpoint_id, bpc->address);
#endif
}

gboolean
gum_thread_unset_hardware_breakpoint (GumThreadId thread_id,
                                      guint breakpoint_id,
                                      GError ** error)
{
  return gum_linux_modify_thread (thread_id, GUM_REGS_DEBUG_BREAK,
      gum_do_unset_hardware_breakpoint, GUINT_TO_POINTER (breakpoint_id),
      error);
}

static void
gum_do_unset_hardware_breakpoint (GumThreadId thread_id,
                                  GumRegs * regs,
                                  gpointer user_data)
{
  GumDebugRegs * dr = &regs->debug;
  guint breakpoint_id = GPOINTER_TO_UINT (user_data);

#if defined (HAVE_I386)
  _gum_x86_unset_breakpoint (&dr->dr7, &dr->dr0, breakpoint_id);
#elif defined (HAVE_ARM)
  _gum_arm_unset_breakpoint (dr->cr, dr->vr, breakpoint_id);
#elif defined (HAVE_ARM64)
  _gum_arm64_unset_breakpoint (dr->cr, dr->vr, breakpoint_id);
#elif defined (HAVE_MIPS) && GLIB_SIZEOF_VOID_P == 4
  g_assert (dr->style == GUM_MIPS_WATCH_MIPS32);
  _gum_mips_unset_breakpoint (dr->mips32.watch_lo, dr->mips32.watch_hi,
      breakpoint_id);
#elif defined (HAVE_MIPS) && GLIB_SIZEOF_VOID_P == 8
  g_assert (dr->style == GUM_MIPS_WATCH_MIPS64);
  _gum_mips_unset_breakpoint (dr->mips64.watch_lo, dr->mips64.watch_hi,
      breakpoint_id);
#endif
}

gboolean
gum_thread_set_hardware_watchpoint (GumThreadId thread_id,
                                    guint watchpoint_id,
                                    GumAddress address,
                                    gsize size,
                                    GumWatchConditions wc,
                                    GError ** error)
{
  GumSetHardwareWatchpointContext wpc;

  wpc.watchpoint_id = watchpoint_id;
  wpc.address = address;
  wpc.size = size;
  wpc.conditions = wc;

  return gum_linux_modify_thread (thread_id, GUM_REGS_DEBUG_WATCH,
      gum_do_set_hardware_watchpoint, &wpc, error);
}

static void
gum_do_set_hardware_watchpoint (GumThreadId thread_id,
                                GumRegs * regs,
                                gpointer user_data)
{
  GumDebugRegs * dr = &regs->debug;
  GumSetHardwareWatchpointContext * wpc = user_data;

#if defined (HAVE_I386)
  _gum_x86_set_watchpoint (&dr->dr7, &dr->dr0, wpc->watchpoint_id, wpc->address,
      wpc->size, wpc->conditions);
#elif defined (HAVE_ARM)
  _gum_arm_set_watchpoint (dr->cr, dr->vr, wpc->watchpoint_id, wpc->address,
      wpc->size, wpc->conditions);
#elif defined (HAVE_ARM64)
  _gum_arm64_set_watchpoint (dr->cr, dr->vr, wpc->watchpoint_id, wpc->address,
      wpc->size, wpc->conditions);
#elif defined (HAVE_MIPS) && GLIB_SIZEOF_VOID_P == 4
  g_assert (dr->style == GUM_MIPS_WATCH_MIPS32);
  _gum_mips_set_watchpoint (dr->mips32.watch_lo, dr->mips32.watch_hi,
      wpc->watchpoint_id, wpc->address, wpc->size, wpc->conditions);
#elif defined (HAVE_MIPS) && GLIB_SIZEOF_VOID_P == 8
  g_assert (dr->style == GUM_MIPS_WATCH_MIPS64);
  _gum_mips_set_watchpoint (dr->mips64.watch_lo, dr->mips64.watch_hi,
      wpc->watchpoint_id, wpc->address, wpc->size, wpc->conditions);
#endif
}

gboolean
gum_thread_unset_hardware_watchpoint (GumThreadId thread_id,
                                      guint watchpoint_id,
                                      GError ** error)
{
  return gum_linux_modify_thread (thread_id, GUM_REGS_DEBUG_WATCH,
      gum_do_unset_hardware_watchpoint, GUINT_TO_POINTER (watchpoint_id),
      error);
}

static void
gum_do_unset_hardware_watchpoint (GumThreadId thread_id,
                                  GumRegs * regs,
                                  gpointer user_data)
{
  GumDebugRegs * dr = &regs->debug;
  guint watchpoint_id = GPOINTER_TO_UINT (user_data);

#if defined (HAVE_I386)
  _gum_x86_unset_watchpoint (&dr->dr7, &dr->dr0, watchpoint_id);
#elif defined (HAVE_ARM)
  _gum_arm_unset_watchpoint (dr->cr, dr->vr, watchpoint_id);
#elif defined (HAVE_ARM64)
  _gum_arm64_unset_watchpoint (dr->cr, dr->vr, watchpoint_id);
#elif defined (HAVE_MIPS) && GLIB_SIZEOF_VOID_P == 4
  g_assert (dr->style == GUM_MIPS_WATCH_MIPS32);
  _gum_mips_unset_watchpoint (dr->mips32.watch_lo, dr->mips32.watch_hi,
      watchpoint_id);
#elif defined (HAVE_MIPS) && GLIB_SIZEOF_VOID_P == 8
  g_assert (dr->style == GUM_MIPS_WATCH_MIPS64);
  _gum_mips_unset_watchpoint (dr->mips64.watch_lo, dr->mips64.watch_hi,
      watchpoint_id);
#endif
}

gboolean
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  GumGenericDlopenImpl dlopen_impl = dlopen;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_module_get_handle (module_name) != NULL)
    return TRUE;

  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlopen (&dlopen_impl);
#endif

  if (dlopen_impl (module_name, RTLD_LAZY) == NULL)
    goto not_found;

  return TRUE;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

static void *
gum_module_get_handle (const gchar * module_name)
{
#if defined (HAVE_MUSL)
  struct link_map * cur;

  for (cur = dlopen (NULL, 0); cur != NULL; cur = cur->l_next)
  {
    if (gum_linux_module_path_matches (cur->l_name, module_name))
      return cur;
  }

  for (cur = dlopen (NULL, 0); cur != NULL; cur = cur->l_next)
  {
    gchar * target, * parent_dir, * canonical_path;
    gboolean is_match;

    target = g_file_read_link (cur->l_name, NULL);
    if (target == NULL)
      continue;
    parent_dir = g_path_get_dirname (cur->l_name);
    canonical_path = g_canonicalize_filename (target, parent_dir);

    is_match = gum_linux_module_path_matches (canonical_path, module_name);

    g_free (canonical_path);
    g_free (parent_dir);
    g_free (target);

    if (is_match)
      return cur;
  }

  return NULL;
#else
# if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    return gum_android_get_module_handle (module_name);
# endif

  return dlopen (module_name, RTLD_LAZY | RTLD_NOLOAD);
#endif
}

static void *
gum_module_get_symbol (void * module,
                       const gchar * symbol)
{
  GumGenericDlsymImpl dlsym_impl = dlsym;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    gum_android_find_unrestricted_dlsym (&dlsym_impl);
#endif

  return dlsym_impl (module, symbol);
}

gboolean
gum_module_ensure_initialized (const gchar * module_name)
{
  void * module;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE)
    return gum_android_ensure_module_initialized (module_name);
#endif

  module = gum_module_get_handle (module_name);
  if (module == NULL)
    return FALSE;
  dlclose (module);

#ifndef HAVE_MUSL
  module = dlopen (module_name, RTLD_LAZY);
  if (module == NULL)
    return FALSE;
  dlclose (module);
#endif

  return TRUE;
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumAddress result;
  void * module;

#if defined (HAVE_ANDROID) && !defined (GUM_DIET)
  if (gum_android_get_linker_flavor () == GUM_ANDROID_LINKER_NATIVE &&
      gum_android_try_resolve_magic_export (module_name, symbol_name, &result))
    return result;
#endif

  if (module_name != NULL)
  {
    module = gum_module_get_handle (module_name);
    if (module == NULL)
      return 0;
  }
  else
  {
    module = RTLD_DEFAULT;
  }

  result = GUM_ADDRESS (gum_module_get_symbol (module, symbol_name));

  if (module != RTLD_DEFAULT)
    dlclose (module);

  return result;
}

GumCpuType
gum_linux_cpu_type_from_file (const gchar * path,
                              GError ** error)
{
  GumCpuType result = -1;
  FILE * file;
  guint8 ei_data;
  guint16 e_machine;

  file = fopen (path, "rb");
  if (file == NULL)
    goto fopen_failed;

  if (fseek (file, EI_DATA, SEEK_SET) != 0)
    goto unsupported_executable;
  if (fread (&ei_data, sizeof (ei_data), 1, file) != 1)
    goto unsupported_executable;

  if (fseek (file, 0x12, SEEK_SET) != 0)
    goto unsupported_executable;
  if (fread (&e_machine, sizeof (e_machine), 1, file) != 1)
    goto unsupported_executable;

  if (ei_data == ELFDATA2LSB)
    e_machine = GUINT16_FROM_LE (e_machine);
  else if (ei_data == ELFDATA2MSB)
    e_machine = GUINT16_FROM_BE (e_machine);
  else
    goto unsupported_ei_data;

  switch (e_machine)
  {
    case 0x0003:
      result = GUM_CPU_IA32;
      break;
    case 0x003e:
      result = GUM_CPU_AMD64;
      break;
    case 0x0028:
      result = GUM_CPU_ARM;
      break;
    case 0x00b7:
      result = GUM_CPU_ARM64;
      break;
    case 0x0008:
      result = GUM_CPU_MIPS;
      break;
    default:
      goto unsupported_executable;
  }

  goto beach;

fopen_failed:
  {
    if (errno == ENOENT)
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
          "File not found");
    }
    else if (errno == EACCES)
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_PERMISSION_DENIED,
          "Permission denied");
    }
    else
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
          "Unable to open file: %s", g_strerror (errno));
    }
    goto beach;
  }
unsupported_ei_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Unsupported ELF EI_DATA");
    goto beach;
  }
unsupported_executable:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Unsupported executable");
    goto beach;
  }
beach:
  {
    if (file != NULL)
      fclose (file);

    return result;
  }
}

GumCpuType
gum_linux_cpu_type_from_pid (pid_t pid,
                             GError ** error)
{
  GumCpuType result = -1;
  GError * err;
  gchar * auxv_path, * auxv;
  gsize auxv_size;

  auxv_path = g_strdup_printf ("/proc/%d/auxv", pid);

  auxv = NULL;
  err = NULL;
  if (!g_file_get_contents (auxv_path, &auxv, &auxv_size, &err))
    goto read_failed;
  if (auxv_size == 0)
    goto nearly_dead;

  result = gum_linux_cpu_type_from_auxv (auxv, auxv_size);

  goto beach;

read_failed:
  {
    if (g_error_matches (err, G_FILE_ERROR, G_FILE_ERROR_NOENT))
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
          "Process not found");
    }
    else if (g_error_matches (err, G_FILE_ERROR, G_FILE_ERROR_ACCES))
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_PERMISSION_DENIED,
          "Permission denied");
    }
    else
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
          "%s", err->message);
    }

    g_error_free (err);

    goto beach;
  }
nearly_dead:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND,
        "Process not found");
    goto beach;
  }
beach:
  {
    g_free (auxv);
    g_free (auxv_path);

    return result;
  }
}

GumCpuType
gum_linux_cpu_type_from_auxv (gconstpointer auxv,
                              gsize auxv_size)
{
  GumCpuType result = -1;
  GumCpuType cpu32, cpu64;
  gsize i;

#if defined (HAVE_I386)
  cpu32 = GUM_CPU_IA32;
  cpu64 = GUM_CPU_AMD64;
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  cpu32 = GUM_CPU_ARM;
  cpu64 = GUM_CPU_ARM64;
#elif defined (HAVE_MIPS)
  cpu32 = GUM_CPU_MIPS;
  cpu64 = GUM_CPU_MIPS;
#else
# error Unsupported architecture
#endif

  /*
   * The auxilliary structure format is architecture specific. Most notably,
   * type and value are both natively sized. We therefore detect whether a
   * process is 64-bit by examining each entry and confirming that the low bits
   * of the type field are zero. Note that this is itself endian specific.
   *
   * typedef struct
   * {
   *   uint32_t a_type;
   *   union
   *   {
   *     uint32_t a_val;
   *   } a_un;
   * } Elf32_auxv_t;
   *
   * typedef struct
   * {
   *   uint64_t a_type;
   *   union
   *   {
   *     uint64_t a_val;
   *   } a_un;
   * } Elf64_auxv_t;
   *
   * If the auxiliary vector is 32-bits and contains only an AT_NULL entry (note
   * that the documentation states that "The last entry contains two zeros"),
   * this will mean it has no non-zero type codes and could be mistaken for a
   * 64-bit format auxiliary vector. We therefore handle this special case.
   *
   * If the vector is less than 16 bytes it is not large enough to contain two
   * 64-bit zero values. If it is larger, then if it is a 32-bit format vector,
   * then it must contain at least one non-zero type code and hence the test
   * below should work.
   */

  if (auxv_size < 2 * sizeof (guint64))
  {
    result = cpu32;
  }
  else
  {
    result = cpu64;

    for (i = 0; i + sizeof (guint64) <= auxv_size; i += 16)
    {
      const guint64 * auxv_type = auxv + i;

      if ((*auxv_type & G_GUINT64_CONSTANT (0xffffffff00000000)) != 0)
      {
        result = cpu32;
        break;
      }
    }
  }

  return result;
}

gboolean
_gum_process_resolve_module_name (const gchar * name,
                                  gchar ** path,
                                  GumAddress * base)
{
  return gum_do_resolve_module_name (name, gum_process_query_libc_name (), path,
      base);
}

static gboolean
gum_do_resolve_module_name (const gchar * name,
                            const gchar * libc_name,
                            gchar ** path,
                            GumAddress * base)
{
  gboolean success = FALSE;
  GumResolveModuleNameContext ctx;

  if (name[0] == '/' && base == NULL)
  {
    success = TRUE;

    if (path != NULL)
      *path = g_strdup (name);

    goto beach;
  }

  ctx.name = name;
  ctx.known_address = 0;
#if defined (HAVE_GLIBC) || defined (HAVE_MUSL)
  {
    struct link_map * map = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);
    if (map != NULL)
    {
      ctx.known_address = GUM_ADDRESS (map->l_ld);
      dlclose (map);
    }
  }
#endif
  ctx.path = NULL;
  ctx.base = 0;

  if (name == libc_name &&
      gum_query_program_modules ()->rtld == GUM_PROGRAM_RTLD_NONE)
  {
    gum_linux_enumerate_modules_using_proc_maps (
        gum_store_module_path_and_base_if_match, &ctx);
  }
  else
  {
    gum_do_enumerate_modules (libc_name,
        gum_store_module_path_and_base_if_match, &ctx);
  }

  success = ctx.path != NULL;

  if (path != NULL)
    *path = g_steal_pointer (&ctx.path);

  if (base != NULL)
    *base = ctx.base;

  g_free (ctx.path);

beach:
  return success;
}

static gboolean
gum_store_module_path_and_base_if_match (
    const GumModuleDetails * details,
    gpointer user_data)
{
  GumResolveModuleNameContext * ctx = user_data;
  gboolean is_match;

  if (ctx->known_address != 0)
    is_match = GUM_MEMORY_RANGE_INCLUDES (details->range, ctx->known_address);
  else
    is_match = gum_linux_module_path_matches (details->path, ctx->name);
  if (!is_match)
    return TRUE;

  ctx->path = g_strdup (details->path);
  ctx->base = details->range->base_address;
  return FALSE;
}

gboolean
gum_linux_module_path_matches (const gchar * path,
                               const gchar * name_or_path)
{
  const gchar * s;

  if (name_or_path[0] == '/')
    return strcmp (name_or_path, path) == 0;

  if ((s = strrchr (path, '/')) != NULL)
    return strcmp (name_or_path, s + 1) == 0;

  return strcmp (name_or_path, path) == 0;
}

void
gum_proc_maps_iter_init_for_self (GumProcMapsIter * iter)
{
  gum_proc_maps_iter_init_for_path (iter, "/proc/self/maps");
}

void
gum_proc_maps_iter_init_for_pid (GumProcMapsIter * iter,
                                 pid_t pid)
{
  gchar path[31 + 1];

  sprintf (path, "/proc/%u/maps", (guint) pid);

  gum_proc_maps_iter_init_for_path (iter, path);
}

static void
gum_proc_maps_iter_init_for_path (GumProcMapsIter * iter,
                                  const gchar * path)
{
  iter->fd = open (path, O_RDONLY | O_CLOEXEC);
  iter->read_cursor = iter->buffer;
  iter->write_cursor = iter->buffer;
}

void
gum_proc_maps_iter_destroy (GumProcMapsIter * iter)
{
  if (iter->fd != -1)
    close (iter->fd);
}

gboolean
gum_proc_maps_iter_next (GumProcMapsIter * iter,
                         const gchar ** line)
{
  gchar * next_newline;
  guint available;
  gboolean need_refill;

  if (iter->fd == -1)
    return FALSE;

  next_newline = NULL;

  available = iter->write_cursor - iter->read_cursor;
  if (available == 0)
  {
    need_refill = TRUE;
  }
  else
  {
    next_newline = strchr (iter->read_cursor, '\n');
    if (next_newline != NULL)
    {
      need_refill = FALSE;
    }
    else
    {
      need_refill = TRUE;
    }
  }

  if (need_refill)
  {
    guint offset;
    gssize res;

    offset = iter->read_cursor - iter->buffer;
    if (offset > 0)
    {
      memmove (iter->buffer, iter->read_cursor, available);
      iter->read_cursor -= offset;
      iter->write_cursor -= offset;
    }

    res = GUM_TEMP_FAILURE_RETRY (gum_libc_read (iter->fd,
        iter->write_cursor,
        iter->buffer + sizeof (iter->buffer) - 1 - iter->write_cursor));
    if (res <= 0)
      return FALSE;

    iter->write_cursor += res;
    iter->write_cursor[0] = '\0';

    next_newline = strchr (iter->read_cursor, '\n');
  }

  *line = iter->read_cursor;
  *next_newline = '\0';

  iter->read_cursor = next_newline + 1;

  return TRUE;
}

static void
gum_acquire_dumpability (void)
{
  G_LOCK (gum_dumpable);

  if (++gum_dumpable_refcount == 1)
  {
    /*
     * Some systems (notably Android on release applications) spawn processes as
     * not dumpable by default, disabling ptrace() and some other things on that
     * process for anyone other than root.
     */
    gum_dumpable_previous = prctl (PR_GET_DUMPABLE);
    if (gum_dumpable_previous != -1 && gum_dumpable_previous != 1)
      prctl (PR_SET_DUMPABLE, 1);
  }

  G_UNLOCK (gum_dumpable);
}

static void
gum_release_dumpability (void)
{
  G_LOCK (gum_dumpable);

  if (--gum_dumpable_refcount == 0)
  {
    if (gum_dumpable_previous != -1 && gum_dumpable_previous != 1)
      prctl (PR_SET_DUMPABLE, gum_dumpable_previous);
  }

  G_UNLOCK (gum_dumpable);
}

void
gum_linux_parse_ucontext (const ucontext_t * uc,
                          GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  const greg_t * gr = uc->uc_mcontext.gregs;

  ctx->eip = gr[REG_EIP];

  ctx->edi = gr[REG_EDI];
  ctx->esi = gr[REG_ESI];
  ctx->ebp = gr[REG_EBP];
  ctx->esp = gr[REG_ESP];
  ctx->ebx = gr[REG_EBX];
  ctx->edx = gr[REG_EDX];
  ctx->ecx = gr[REG_ECX];
  ctx->eax = gr[REG_EAX];
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  const greg_t * gr = uc->uc_mcontext.gregs;

  ctx->rip = gr[R
```