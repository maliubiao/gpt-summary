Response:
The user wants a detailed analysis of the provided C code snippet from Frida, focusing on its functionalities, relationship with reverse engineering, use of low-level concepts, logical reasoning, potential user errors, and how the execution might reach this code. Finally, it needs a summary of the code's functionality.

Here's a breakdown of the thought process:

1. **Overall Goal:** Understand the purpose and workings of the `gumandroid.c` code.

2. **Initial Scan:** Quickly read through the code to identify key functions and data structures. Notice functions with names like `gum_try_find_*`, `gum_store_*`, and the use of `GumElfModule`, `GumLinkerApi`, `GumSoinfo`, suggesting interaction with the dynamic linker and loaded libraries on Android.

3. **Function-by-Function Analysis:**  Go through each function systematically:
    * **`gum_android_try_init_linker_api`:** This function seems crucial for initializing the `gum_dl_api` structure. It attempts to locate various linker functions and data structures based on Android API levels and through "forensic" scanning. The `GUM_TRY_ASSIGN` macros suggest conditional assignment based on symbol names.
    * **`gum_try_find_dl_mutex_api_level`:**  Specifically tries to locate the `dl_mutex` based on API level.
    * **`gum_try_find_solist_head_api_level` and `gum_try_find_solist_get_somain_api_level`:**  Similarly, these attempt to find functions related to the loaded shared object list (`solist`).
    * **`gum_try_find_dlopen_api245_forensically` and `gum_try_find_dlopen_api26p_forensically`:** These functions perform "forensic" searches (likely pattern-based) within the linker's memory to find `dlopen` and `dlsym`.
    * **`gum_store_dlopen_api_if_found_in_section`:**  Used as a callback during ELF section enumeration to check for specific function signatures.
    * **`gum_try_find_dl_mutex_forensically`:**  Scans memory for a specific byte pattern likely representing the `dl_mutex`.
    * **`gum_store_dl_mutex_pointer_if_found_in_section`:** Callback for finding the mutex pattern within a section.
    * **`gum_try_find_libdl_info_forensically`:** Tries to locate the `libdl_info` structure.
    * **`gum_store_libdl_info_pointer_if_found_in_section`:**  Looks for the string "libdl.so" or a specific `Soinfo` structure pattern.
    * **`gum_try_find_somain_forensically`:** Traverses the loaded library list to find the main executable's `Soinfo`.
    * **`gum_find_function_by_signature`:**  A general function to locate functions based on byte patterns (signatures).
    * **`gum_store_function_signature_match` and `gum_store_first_scan_match`:** Callback functions for memory scanning.
    * **`gum_solist_get_head_fallback` and `gum_solist_get_somain_fallback`:** Provide fallback mechanisms if direct function pointers aren't found.
    * **`gum_soinfo_get_*` functions:** Accessors for different fields within the `Soinfo` structure, handling API level differences.
    * **`gum_android_find_unrestricted_dlopen`, `gum_android_find_unrestricted_dlsym`, `gum_android_find_unrestricted_linker_api`:** Functions to retrieve the `dlopen` and `dlsym` functions for unrestricted usage.
    * **`gum_call_inner_dlopen` and `gum_call_inner_dlsym`:**  Wrappers around the actual `dlopen` and `dlsym` calls.
    * **`gum_libcxx_string_get_data`:** Extracts the string data from a `libcxx_string` structure.
    * **`gum_android_is_vdso_module_name`:** Checks if a module name corresponds to the vDSO.

4. **Identifying Connections to Reverse Engineering:** Recognize that this code is actively involved in inspecting and manipulating the runtime environment of an Android process. This is a core aspect of dynamic instrumentation and reverse engineering. Hooking, function interception, and understanding library loading are key reverse engineering techniques directly related to the code's function.

5. **Identifying Low-Level Concepts:**  Note the direct interaction with memory addresses, ELF structures, linker internals, threading primitives (`pthread_mutex_t`), and Android API level specifics. Keywords like ".text", ".data", ".bss" directly relate to ELF file structure.

6. **Logical Reasoning and Assumptions:**  The code makes assumptions about the structure and naming conventions of the Android linker (`linker`). The "forensic" methods rely on specific byte patterns. Consider how different Android versions might deviate and how the code attempts to handle these variations.

7. **Potential User Errors:**  Think about how a user might interact with Frida and how errors could occur. Incorrectly specifying function names or relying on outdated information about linker internals are possibilities.

8. **Tracing User Interaction:**  Imagine a user wanting to hook a function in a dynamically loaded library. This likely involves Frida attaching to a process, then using Frida's API to find the library and the function. The code being analyzed here is part of the underlying mechanism Frida uses to achieve this.

9. **Synthesizing Functionality:** Based on the detailed analysis, summarize the core purpose: to locate and initialize access points to the Android dynamic linker, allowing Frida to perform actions like loading libraries and resolving symbols within the target process.

10. **Structuring the Output:** Organize the findings into the requested categories (functionality, reverse engineering, low-level concepts, logic, user errors, user path, and summary). Use clear and concise language with illustrative examples.
这是frida动态instrumentation工具的源代码文件 `frida/subprojects/frida-gum/gum/backend-linux/gumandroid.c` 的第二部分，我们继续分析其功能。

**功能列举:**

这部分代码延续了第一部分的核心目标：**在Android系统上，为了实现动态 instrumentation，需要找到并利用Android动态链接器（linker）的内部API和数据结构。** 这部分代码主要关注以下功能：

* **更精确地查找 `dlopen` 和 `dlsym`:**  定义了基于特定API级别（API 24/25和API 26+）的 `dlopen` 和 `dlsym` 函数的签名（字节序列），并通过扫描linker的 `.text` 段来尝试定位这些函数。这是对第一部分基于API level直接假设的补充，提供了更健壮的查找方式。
* **“取证”式查找 `dl_mutex`:**  定义了 `dl_mutex` 的内存布局模式（"00 40 00 00"），并通过扫描linker的 `.data` 段来尝试定位 `dl_mutex` 变量的地址。这是一种更通用的查找方法，不依赖于符号的存在。
* **“取证”式查找 `libdl_info`:**  尝试通过扫描内存来定位代表 `libdl.so` 的 `Soinfo` 结构体。 它会在 `.data` 段查找 "libdl.so" 字符串，或者在 `.bss` 段查找符合特定 `Soinfo` 结构体特征的内存区域。
* **“取证”式查找 `somain`:**  遍历通过 `solist_get_head` 获取的已加载共享库列表，找到标志为可执行文件（EXE）的 `Soinfo` 结构体，这代表主程序。
* **通用的基于签名的函数查找:**  `gum_find_function_by_signature` 函数提供了一种通用的机制，通过给定的字节签名来在指定内存区域查找函数。
* **辅助函数:** 提供了一些辅助函数，如 `gum_store_function_signature_match` 和 `gum_store_first_scan_match`，用于在内存扫描过程中存储匹配的结果。
* **回退机制:**  提供了 `gum_solist_get_head_fallback` 和 `gum_solist_get_somain_fallback`，作为找不到对应符号时的回退方案，直接使用之前找到的 `solist` 和 `somain_node`。
* **`Soinfo` 结构体访问:** 提供了一系列函数（如 `gum_soinfo_get_head`, `gum_soinfo_get_body`, `gum_soinfo_get_parent`, `gum_soinfo_get_realpath` 等）来安全地访问 `Soinfo` 结构体的成员，并根据不同的Android API级别处理结构体的差异。
* **获取不受限制的 `dlopen` 和 `dlsym`:**  `gum_android_find_unrestricted_dlopen` 和 `gum_android_find_unrestricted_dlsym` 尝试获取可以绕过某些安全限制的 `dlopen` 和 `dlsym` 函数指针。
* **内部 `dlopen` 和 `dlsym` 调用:** `gum_call_inner_dlopen` 和 `gum_call_inner_dlsym` 是对实际 `dlopen` 和 `dlsym` 的封装，可能包含了一些额外的处理或参数传递。
* **`libcxx_string` 处理:** `gum_libcxx_string_get_data` 用于从 `libcxx_string` 结构体中提取字符串数据，这是C++标准库中字符串的常见实现。
* **判断是否为 vDSO 模块:** `gum_android_is_vdso_module_name` 用于判断给定的模块名称是否是 vDSO (Virtual Dynamic Shared Object)。

**与逆向方法的关联和举例说明:**

* **动态分析和内存搜索:**  代码中大量使用了内存扫描和模式匹配 (`gum_memory_scan`, `gum_match_pattern_new_from_string`) 来查找特定的函数或数据结构。这与逆向工程中常用的动态分析技术非常相关，逆向工程师也经常需要在运行时检查进程的内存状态。
    * **举例:**  逆向工程师可能不知道目标应用的 `dlopen` 函数地址，但知道其开头的几个字节的指令模式。他们可以使用类似的内存扫描技术，在linker的代码段中搜索这个模式，从而定位到 `dlopen` 函数。
* **符号解析的替代方案:**  当符号信息不可用时（例如被strip过的二进制文件），代码中使用的“取证”式查找方法提供了一种替代方案。逆向工程师在分析没有符号信息的二进制文件时，也需要依赖类似的技巧。
    * **举例:**  在分析一个被混淆的应用时，其linker的符号表可能被移除。Frida可以通过扫描内存中 `dl_mutex` 的特征码来找到它，即使没有相应的符号信息。
* **理解动态链接过程:**  代码的目标是理解和利用Android的动态链接过程，这对于理解应用的加载和执行至关重要。逆向工程师需要理解动态链接的机制才能有效地分析和修改应用的运行时行为。
    * **举例:**  通过理解 `Soinfo` 结构体的布局和 `solist` 的结构，逆向工程师可以跟踪应用的依赖关系，了解哪些库被加载以及加载顺序。
* **API Hooking 的基础:**  Frida 的核心功能是 API Hooking。这段代码是实现 Hooking 的基础，因为它需要先找到目标 API 函数的地址（例如 `dlopen`, `dlsym`）。
    * **举例:**  要 Hook `dlopen` 函数以监控应用加载的库，Frida 首先需要像这段代码所做的那样，找到 `dlopen` 函数在内存中的地址。

**涉及的二进制底层、Linux、Android内核及框架知识的举例说明:**

* **ELF 文件格式:**  代码中提到了 `.text`, `.data`, `.bss` 等段，这些都是 ELF (Executable and Linkable Format) 文件格式的组成部分。理解 ELF 文件格式对于分析二进制文件至关重要。
    * **举例:**  代码扫描 `.text` 段来查找指令序列，扫描 `.data` 段查找全局变量。逆向工程师也需要理解这些段的用途，以便在静态分析或动态调试时定位代码和数据。
* **Linux 动态链接器:**  代码的核心是与 Android 的动态链接器交互。动态链接器负责在程序运行时加载和链接共享库。
    * **举例:**  代码尝试找到 `dlopen` 和 `dlsym` 函数，这两个函数是 Linux 动态链接器的关键组成部分。逆向工程师需要理解动态链接器的加载过程、符号解析机制等。
* **Android 内核和框架:**  代码中使用了 `pthread_mutex_t`，这是 Linux 提供的线程同步原语，也广泛应用于 Android 框架中。代码还针对不同的 Android API 级别进行了适配，这体现了对 Android 系统版本差异的理解。
    * **举例:**  代码根据 API 级别判断 `Soinfo` 结构体的布局，这是因为 Android 系统在不同版本中可能对内部数据结构进行调整。
* **内存布局:**  代码直接操作内存地址，并假设了某些数据结构在内存中的布局。这需要对 Android 进程的内存布局有深刻的理解。
    * **举例:**  代码通过特定的字节模式来查找 `dl_mutex`，这依赖于对 `pthread_mutex_t` 结构体在内存中表示的理解。

**逻辑推理、假设输入与输出:**

* **`gum_try_find_dlopen_api245_forensically` 函数:**
    * **假设输入:**  指向 linker 模块的 `GumElfModule` 指针和一个未初始化的 `GumLinkerApi` 结构体。
    * **逻辑推理:**  代码会遍历 linker 的 `.text` 段，并尝试根据预定义的字节签名匹配 `dlopen` 和 `dlsym` 函数。
    * **预期输出:** 如果找到匹配的签名，`GumLinkerApi` 结构体的 `do_dlopen` 和 `do_dlsym` 字段将被设置为找到的函数地址，函数返回 `TRUE`；否则返回 `FALSE`。
* **`gum_store_dl_mutex_pointer_if_found_in_section` 函数:**
    * **假设输入:**  描述当前 ELF 段信息的 `GumElfSectionDetails` 结构体（假设其 `name` 为 ".data"）和一个 `GumFindDlMutexContext` 结构体。
    * **逻辑推理:** 代码会在 `.data` 段中扫描字节模式 "00 40 00 00"，这很可能是 `pthread_mutex_t` 的一种未加锁状态的表示。
    * **预期输出:** 如果找到该模式，`GumFindDlMutexContext` 中的 `dl_mutex` 指针将被设置为匹配到的内存地址，函数返回 `FALSE`（因为找到了就停止扫描）。

**用户或编程常见的使用错误及举例说明:**

这段代码本身是 Frida 内部实现的一部分，普通用户不会直接编写或修改它。但是，理解其背后的原理可以帮助用户避免一些与 Frida 使用相关的错误：

* **假设所有设备都使用相同的 linker 实现:**  这段代码尝试多种方法来查找 linker 的 API，是因为不同 Android 版本和设备厂商可能对 linker 进行修改。用户在使用 Frida 时，不应该假设所有设备都使用完全相同的 linker 实现，这可能会导致某些脚本在特定设备上失效。
* **依赖硬编码的地址或偏移:**  这段代码虽然尝试使用签名匹配等更灵活的方式，但在某些情况下仍然会依赖特定的符号名或结构体布局。用户在编写 Frida 脚本时，如果硬编码了某些地址或偏移，可能会因为目标应用的更新或系统版本的变化而失效。
    * **举例:**  如果用户假设 `dlopen` 函数的地址在所有 Android 7.0 设备上都是固定的，并直接使用该地址进行 Hook，那么这个脚本在某些 Android 7.0 设备上可能无法工作。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动一个 Frida 脚本:**  用户编写或使用一个 Frida 脚本，该脚本的目标是在 Android 设备上的某个应用中进行 Hook 或内存操作。
2. **Frida Client 发送请求:**  用户运行脚本后，Frida Client (通常是 Python) 会连接到目标 Android 设备上的 Frida Server。
3. **Frida Server 加载 Gum 库:**  Frida Server 接收到请求后，会将 Gum 库注入到目标应用进程中。`gumandroid.c` 文件是 Gum 库的一部分。
4. **初始化 Linker API:**  Gum 库在初始化阶段会调用 `gum_android_try_init_linker_api` 函数（第一部分的代码），该函数会尝试查找和初始化 linker 的内部 API。
5. **执行“取证”式查找:**  如果基于 API level 的查找失败，或者需要更精确的定位，Gum 库会调用这部分代码中的函数，例如 `gum_try_find_dlopen_api245_forensically` 或 `gum_try_find_dl_mutex_forensically`，尝试通过内存扫描来定位关键函数和数据结构。
6. **用于后续的 Hook 或操作:**  一旦找到了 linker 的 API，Frida 就可以利用这些 API 来实现各种动态 instrumentation 的功能，例如 Hook 函数、修改内存、跟踪函数调用等。

**归纳一下它的功能:**

这部分 `gumandroid.c` 代码的核心功能是**通过更精细和更具弹性的方法，在 Android 进程的内存中定位动态链接器（linker）的关键函数（如 `dlopen`, `dlsym`）和数据结构（如 `dl_mutex`, `libdl_info`, `somain`）。** 它使用了基于字节签名的函数查找和基于内存模式的数据结构查找等“取证”式技术，以应对不同 Android 版本和设备厂商可能存在的 linker 实现差异。 这些被找到的linker内部API是Frida实现动态 instrumentation的关键基础设施，使得Frida能够在运行时操作目标应用的加载行为和符号解析过程。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-linux/gumandroid.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
       /*  < 21 */

  GUM_TRY_ASSIGN (solist_get_somain, "__dl__Z17solist_get_somainv"); /* >= 26 */
  GUM_TRY_ASSIGN_OPTIONAL (somain, "__dl__ZL6somain");               /* "any" */

  /*
   * Realpath getter implemented in API level >= 23+ (6.0+), but may have
   * been inlined.
   */
  GUM_TRY_ASSIGN (soinfo_get_path, "__dl__ZNK6soinfo12get_realpathEv");

beach:
  return *pending != 0;
}

#undef GUM_TRY_ASSIGN
#undef GUM_TRY_ASSIGN_OPTIONAL
#undef _GUM_TRY_ASSIGN

static gboolean
gum_try_find_dlopen_api245_forensically (GumElfModule * linker,
                                         GumLinkerApi * api)
{
  GumFindDlopenApiContext ctx;

  ctx.linker = linker;

  ctx.dlopen_signatures = gum_dlopen_signatures_api245;
  ctx.dlopen = NULL;

  ctx.dlsym_signatures = gum_dlsym_signatures_api245;
  ctx.dlsym = NULL;

  gum_elf_module_enumerate_sections (linker,
      (GumFoundElfSectionFunc) gum_store_dlopen_api_if_found_in_section,
      &ctx);

  if (ctx.dlopen == NULL || ctx.dlsym == NULL)
    return FALSE;

  api->do_dlopen = ctx.dlopen;
  api->do_dlsym = ctx.dlsym;

  return TRUE;
}

static gboolean
gum_try_find_dlopen_api26p_forensically (GumElfModule * linker,
                                         GumLinkerApi * api)
{
  GumFindDlopenApiContext ctx;

  ctx.linker = linker;

  ctx.dlopen_signatures = gum_dlopen_signatures_api26p;
  ctx.dlopen = NULL;

  ctx.dlsym_signatures = gum_dlsym_signatures_api26p;
  ctx.dlsym = NULL;

  gum_elf_module_enumerate_sections (linker,
      (GumFoundElfSectionFunc) gum_store_dlopen_api_if_found_in_section,
      &ctx);

  if (ctx.dlopen == NULL || ctx.dlsym == NULL)
    return FALSE;

  api->dlopen = ctx.dlopen;
  api->dlsym = ctx.dlsym;

  return TRUE;
}

static gboolean
gum_store_dlopen_api_if_found_in_section (const GumElfSectionDetails * details,
                                          GumFindDlopenApiContext * ctx)
{
  if (strcmp (details->name, ".text") != 0)
    return TRUE;

  ctx->dlopen = gum_find_function_by_signature (details->address, details->size,
      ctx->dlopen_signatures);

  ctx->dlsym = gum_find_function_by_signature (details->address, details->size,
      ctx->dlsym_signatures);

  return FALSE;
}

static gboolean
gum_try_find_dl_mutex_forensically (GumElfModule * linker,
                                    pthread_mutex_t ** dl_mutex)
{
  GumFindDlMutexContext ctx;

  ctx.linker = linker;
  ctx.dl_mutex = NULL;

  gum_elf_module_enumerate_sections (linker,
      (GumFoundElfSectionFunc) gum_store_dl_mutex_pointer_if_found_in_section,
      &ctx);

  *dl_mutex = ctx.dl_mutex;

  return *dl_mutex != NULL;
}

static gboolean
gum_store_dl_mutex_pointer_if_found_in_section (
    const GumElfSectionDetails * details,
    GumFindDlMutexContext * ctx)
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  gpointer mutex_in_file;

  if (strcmp (details->name, ".data") != 0)
    return TRUE;

  range.base_address = GUM_ADDRESS (
      gum_elf_module_get_file_data (ctx->linker, NULL)) + details->offset;
  range.size = details->size;

  pattern = gum_match_pattern_new_from_string ("00 40 00 00");

  mutex_in_file = NULL;
  gum_memory_scan (&range, pattern, gum_store_first_scan_match, &mutex_in_file);

  if (mutex_in_file != NULL)
  {
    ctx->dl_mutex = GSIZE_TO_POINTER (
        details->address + (GUM_ADDRESS (mutex_in_file) - range.base_address));
  }

  gum_match_pattern_unref (pattern);

  return FALSE;
}

static gboolean
gum_try_find_libdl_info_forensically (GumElfModule * linker,
                                      GumSoinfo ** libdl_info)
{
  *libdl_info = NULL;

  gum_elf_module_enumerate_sections (linker,
      (GumFoundElfSectionFunc) gum_store_libdl_info_pointer_if_found_in_section,
      libdl_info);

  return *libdl_info != NULL;
}

static gboolean
gum_store_libdl_info_pointer_if_found_in_section (
    const GumElfSectionDetails * details,
    GumSoinfo ** libdl_info)
{
  GumMemoryRange range;
  GumMatchPattern * pattern;

  range.base_address = details->address;
  range.size = details->size;

  if (strcmp (details->name, ".data") == 0)
  {
    pattern = gum_match_pattern_new_from_string ("6c 69 62 64 6c 2e 73 6f 00");
    gum_memory_scan (&range, pattern, gum_store_first_scan_match, libdl_info);
    gum_match_pattern_unref (pattern);
  }
  else if (strcmp (details->name, ".bss") == 0)
  {
    guint offset;

    for (offset = 0;
        offset <= details->size - sizeof (GumSoinfo);
        offset += sizeof (gpointer))
    {
      GumSoinfo * si = GSIZE_TO_POINTER (details->address + offset);
      GumSoinfoBody * sb;

      sb = gum_soinfo_get_body (si);

      if ((sb->flags & ~GUM_SOINFO_GNU_HASH) ==
          (GUM_SOINFO_NEW_FORMAT | GUM_SOINFO_LINKED))
      {
        *libdl_info = si;
        break;
      }
    }
  }

  return *libdl_info == NULL;
}

static gboolean
gum_try_find_somain_forensically (GumLinkerApi * api)
{
  GumSoinfo * si, * next;

  if (api->dl_mutex == NULL || api->solist_get_head == NULL)
    return FALSE;

  pthread_mutex_lock (api->dl_mutex);

  next = NULL;
  for (si = api->solist_get_head (); si != NULL; si = next)
  {
    GumSoinfoBody * sb = gum_soinfo_get_body (si);

    if ((sb->flags & GUM_SOINFO_EXE) != 0)
    {
      api->somain_node = si;
      break;
    }

    next = sb->next;
  }

  pthread_mutex_unlock (api->dl_mutex);

  return api->somain_node != NULL;
}

static gpointer
gum_find_function_by_signature (GumAddress address,
                                gsize size,
                                const GumFunctionSignature * signatures)
{
  GumFindFunctionSignatureContext ctx;
  GumMemoryRange range;
  const GumFunctionSignature * s;

  range.base_address = address;
  range.size = size;

  for (s = signatures; s->signature != NULL; s++)
  {
    GumMatchPattern * pattern;

    ctx.match = 0;
    ctx.num_matches = 0;

    pattern = gum_match_pattern_new_from_string (s->signature);

    gum_memory_scan (&range, pattern,
        (GumMemoryScanMatchFunc) gum_store_function_signature_match, &ctx);

    gum_match_pattern_unref (pattern);

    if (ctx.num_matches == 1)
      return GSIZE_TO_POINTER (ctx.match + s->displacement);
  }

  return NULL;
}

static gboolean
gum_store_function_signature_match (GumAddress address,
                                    gsize size,
                                    GumFindFunctionSignatureContext * ctx)
{
  ctx->match = address;
  ctx->num_matches++;

  return TRUE;
}

static gboolean
gum_store_first_scan_match (GumAddress address,
                            gsize size,
                            gpointer user_data)
{
  gpointer * match = user_data;

  *match = GSIZE_TO_POINTER (address);

  return FALSE;
}

static GumSoinfo *
gum_solist_get_head_fallback (void)
{
  return (gum_dl_api.solist != NULL)
      ? *gum_dl_api.solist
      : gum_dl_api.libdl_info;
}

static GumSoinfo *
gum_solist_get_somain_fallback (void)
{
  return (gum_dl_api.somain != NULL)
      ? *gum_dl_api.somain
      : gum_dl_api.somain_node;
}

#ifdef GUM_ANDROID_LEGACY_SOINFO

static GumSoinfoHead *
gum_soinfo_get_head (GumSoinfo * self)
{
  guint api_level = gum_android_get_api_level ();
  if (api_level >= 26)
    return &self->modern.head;
  else if (api_level >= 23)
    return &self->legacy23.head;
  else
    return &self->legacy.legacy23.head;
}

#endif

static GumSoinfoBody *
gum_soinfo_get_body (GumSoinfo * self)
{
  guint api_level = gum_android_get_api_level ();
  if (api_level >= 26)
    return &self->modern.body;
  else if (api_level >= 23)
    return &self->legacy23.body;
  else
    return &self->legacy.legacy23.body;
}

static gboolean
gum_soinfo_is_linker (GumSoinfo * self)
{
  return gum_soinfo_get_body (self)->base == 0;
}

static GumSoinfo *
gum_soinfo_get_parent (GumSoinfo * self)
{
  GumSoinfoBody * sb;
  GumSoinfoListEntry * entry;

  sb = gum_soinfo_get_body (self);

  if (gum_android_is_api33_or_newer ())
  {
    GumSoinfoListHeader * header = sb->extras.post33.parents.header;

    if (header == NULL)
      return NULL;

    entry = header->head;
  }
  else
  {
    entry = sb->extras.pre33.parents.head;
  }

  if (entry == NULL)
    return NULL;

  return entry->element;
}

static guint32
gum_soinfo_get_rtld_flags (GumSoinfo * self)
{
  GumSoinfoBody * sb = gum_soinfo_get_body (self);

  if (gum_android_is_api33_or_newer ())
    return sb->extras.post33.rtld_flags;
  else
    return sb->extras.pre33.rtld_flags;
}

static const gchar *
gum_soinfo_get_realpath (GumSoinfo * self)
{
  GumSoinfoBody * sb;
  GumLibcxxString * str;

  sb = gum_soinfo_get_body (self);

  str = gum_android_is_api33_or_newer ()
      ? &sb->extras.post33.realpath
      : &sb->extras.pre33.realpath;

  return gum_libcxx_string_get_data (str);
}

static const char *
gum_soinfo_get_path_fallback (GumSoinfo * self)
{
#ifdef GUM_ANDROID_LEGACY_SOINFO
  GumSoinfoBody * sb = gum_soinfo_get_body (self);

  if ((sb->flags & GUM_SOINFO_NEW_FORMAT) != 0 && sb->version >= 2)
    return gum_soinfo_get_realpath (self);
  else
    return gum_soinfo_get_head (self)->old_name;
#else
  return gum_soinfo_get_realpath (self);
#endif
}

gboolean
gum_android_find_unrestricted_dlopen (GumGenericDlopenImpl * generic_dlopen)
{
  if (!gum_android_find_unrestricted_linker_api (NULL))
    return FALSE;

  *generic_dlopen = gum_call_inner_dlopen;

  return TRUE;
}

gboolean
gum_android_find_unrestricted_dlsym (GumGenericDlsymImpl * generic_dlsym)
{
  if (!gum_android_find_unrestricted_linker_api (NULL))
    return FALSE;

  *generic_dlsym = gum_call_inner_dlsym;

  return TRUE;
}

gboolean
gum_android_find_unrestricted_linker_api (GumAndroidUnrestrictedLinkerApi * api)
{
  GumLinkerApi * private_api;

  private_api = gum_linker_api_get ();

  if (private_api->dlopen == NULL)
    return FALSE;

  if (api != NULL)
  {
    api->dlopen = private_api->dlopen;
    api->dlsym = private_api->dlsym;
  }

  return TRUE;
}

static void *
gum_call_inner_dlopen (const char * filename,
                       int flags)
{
  return gum_dl_api.dlopen (filename, flags, gum_dl_api.trusted_caller);
}

static void *
gum_call_inner_dlsym (void * handle,
                      const char * symbol)
{
  return gum_dl_api.dlsym (handle, symbol, NULL, gum_dl_api.trusted_caller);
}

static const char *
gum_libcxx_string_get_data (const GumLibcxxString * self)
{
  gboolean is_tiny;

  is_tiny = (self->tiny.size & 1) == 0;

  return is_tiny ? self->tiny.data : self->huge.data;
}

static gboolean
gum_android_is_vdso_module_name (const gchar * name)
{
  return strcmp (name, GUM_ANDROID_VDSO_MODULE_NAME) == 0;
}

"""


```