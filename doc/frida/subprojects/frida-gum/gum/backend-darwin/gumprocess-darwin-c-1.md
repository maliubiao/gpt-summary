Response:
The user is asking for a summary of the functionalities of the provided C code snippet, which is part of Frida, a dynamic instrumentation toolkit.

The code seems to focus on retrieving information about a process running on Darwin (macOS/iOS). It interacts with the operating system at a low level to gather details about:

1. **Loaded Images (Modules/Libraries):**  Retrieving information about the dynamically loaded libraries in a process, including their load addresses, sizes, and paths.
2. **Memory Regions:** Querying details about memory regions, such as their protection (read, write, execute permissions) and whether they are backed by a file.
3. **Shared Cache:** Identifying the range of the shared cache in memory.
4. **Entry Point:**  Finding the entry point of the main executable.
5. **Threads:** Enumerating the threads within a process and getting their state (registers, etc.).
6. **Imports and Exports:**  Listing the imported and exported symbols of a module.
7. **Symbols and Sections:**  Enumerating the symbols and sections within a module.
8. **Dependencies:**  Listing the dependencies of a module.

The code uses Darwin-specific APIs like `task_for_pid`, `mach_vm_region_recurse`, `thread_get_state`, and `__proc_info` to achieve this. It also deals with the Mach-O binary format used on macOS.

**Plan:**

1. Identify the main functions in the provided code.
2. For each function, determine its primary purpose.
3. Categorize the functionalities based on the information being retrieved (modules, memory, threads, etc.).
4. Summarize the overall purpose of this code snippet within the context of Frida.
Based on the provided C code snippet from `gumprocess-darwin.c`, here's a summary of its functionalities:

This code segment of Frida's Gum library focuses on **gathering information about processes running on Darwin-based systems (macOS and iOS)**. It achieves this by interacting with the operating system at a low level, primarily using Mach APIs.

Here's a breakdown of its key functionalities:

*   **Querying Dyld All Image Information:** The `gum_darwin_query_all_image_infos` function retrieves information about all the dynamically loaded images (executables and libraries) in a target process. This includes their load addresses, the count of images, and potentially the base address of the shared cache. It handles both 32-bit and 64-bit architectures.

*   **Querying Mapped Address Details:** The `gum_darwin_query_mapped_address` function determines the file path, offset within that file, and the remaining size of the mapping for a given memory address in a target process.

*   **Querying Memory Protection:** The `gum_darwin_query_protection` function retrieves the memory protection attributes (read, write, execute permissions) for a specific memory address in a target process.

*   **Querying Shared Cache Range:** The `gum_darwin_query_shared_cache_range` function attempts to identify the memory range occupied by the shared cache in the target process.

*   **Finding the Entry Point:** The `gum_darwin_find_entrypoint` function searches for the entry point of the main executable within a process's memory. It iterates through executable memory regions, parses Mach-O headers, and looks for thread state information or the `LC_MAIN` load command.

*   **Modifying Thread State:** The `gum_darwin_modify_thread` function allows for the modification of the state (registers, etc.) of a specific thread within a process. It first suspends the thread, optionally aborts it safely, gets its current state, calls a provided function to modify the state, and then sets the new state before resuming the thread.

*   **Enumerating Threads:** The `gum_darwin_enumerate_threads` function iterates through all the threads within a given process and provides information about each thread, such as its ID, name (if available), state, and CPU context (registers).

*   **Enumerating Modules:** The `gum_darwin_enumerate_modules` function lists all the loaded modules (executables and libraries) in a target process. It retrieves their base addresses, sizes, and file paths. It utilizes the Dyld information when available and falls back to a more forensic approach if necessary.

*   **Forensic Module Enumeration:** The `gum_darwin_enumerate_modules_forensically` function provides an alternative method for enumerating modules, especially when the standard Dyld information is not readily available. It scans through executable memory regions looking for Mach-O headers.

*   **Enumerating Memory Ranges:** The `gum_darwin_enumerate_ranges` function iterates through the memory regions of a process that have a specific memory protection (e.g., read-execute). It can also provide details about whether a region is backed by a file.

*   **Filling File Mapping Information:** The `gum_darwin_fill_file_mapping` function retrieves detailed information about a file mapping for a given memory address, including the file path, offset within the file, and the file size.

*   **Clamping Range Size:** The `gum_darwin_clamp_range_size` function adjusts the size of a memory range to align with the file size it maps to, ensuring it doesn't extend beyond the file's boundaries.

**In summary, this code snippet provides the core functionality for Frida on Darwin to introspect and gather metadata about running processes. It enables Frida to understand the memory layout, loaded libraries, threads, and other essential details of a target application.**

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumprocess-darwin.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
return FALSE;
#endif

  infos->format = info.all_image_info_format;

  inprocess = task == mach_task_self ();

  if (info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_64)
  {
    DyldAllImageInfos64 * all_info;
    gpointer all_info_malloc_data = NULL;

    if (inprocess)
    {
      all_info = (DyldAllImageInfos64 *) info.all_image_info_addr;
    }
    else
    {
      all_info = (DyldAllImageInfos64 *) gum_darwin_read (task,
          info.all_image_info_addr,
          sizeof (DyldAllImageInfos64),
          NULL);
      all_info_malloc_data = all_info;
    }
    if (all_info == NULL)
      return FALSE;

    infos->info_array_address = all_info->info_array;
    infos->info_array_count = all_info->info_array_count;
    infos->info_array_size =
        all_info->info_array_count * DYLD_IMAGE_INFO_64_SIZE;

    infos->notification_address = all_info->notification;

    infos->libsystem_initialized = all_info->libsystem_initialized;

    infos->dyld_image_load_address = all_info->dyld_image_load_address;

    if (all_info->version >= 15)
      infos->shared_cache_base_address = all_info->shared_cache_base_address;

    g_free (all_info_malloc_data);
  }
  else
  {
    DyldAllImageInfos32 * all_info;
    gpointer all_info_malloc_data = NULL;

    if (inprocess)
    {
      all_info = (DyldAllImageInfos32 *) info.all_image_info_addr;
    }
    else
    {
      all_info = (DyldAllImageInfos32 *) gum_darwin_read (task,
          info.all_image_info_addr,
          sizeof (DyldAllImageInfos32),
          NULL);
      all_info_malloc_data = all_info;
    }
    if (all_info == NULL)
      return FALSE;

    infos->info_array_address = all_info->info_array;
    infos->info_array_count = all_info->info_array_count;
    infos->info_array_size =
        all_info->info_array_count * DYLD_IMAGE_INFO_32_SIZE;

    infos->notification_address = all_info->notification;

    infos->libsystem_initialized = all_info->libsystem_initialized;

    infos->dyld_image_load_address = all_info->dyld_image_load_address;

    if (all_info->version >= 15)
      infos->shared_cache_base_address = all_info->shared_cache_base_address;

    g_free (all_info_malloc_data);
  }

  return TRUE;
}

gboolean
gum_darwin_query_mapped_address (mach_port_t task,
                                 GumAddress address,
                                 GumDarwinMappingDetails * details)
{
  int pid;
  kern_return_t kr;
  GumFileMapping file;
  struct proc_regionwithpathinfo region;
  guint64 mapping_offset;

  kr = pid_for_task (task, &pid);
  if (kr != KERN_SUCCESS)
    return FALSE;

  if (!gum_darwin_fill_file_mapping (pid, address, &file, &region))
    return FALSE;

  g_strlcpy (details->path, file.path, sizeof (details->path));

  mapping_offset = address - region.prp_prinfo.pri_address;
  details->offset = mapping_offset;
  details->size = region.prp_prinfo.pri_size - mapping_offset;

  return TRUE;
}

gboolean
gum_darwin_query_protection (mach_port_t task,
                             GumAddress address,
                             GumPageProtection * prot)
{
  kern_return_t kr;
  gint pid, retval;
  struct proc_regioninfo region;

  kr = pid_for_task (task, &pid);
  if (kr != KERN_SUCCESS)
    return FALSE;

  retval = __proc_info (PROC_INFO_CALL_PIDINFO, pid, PROC_PIDREGIONINFO,
      address, &region, sizeof (struct proc_regioninfo));
  if (retval == -1)
    return FALSE;

  *prot = gum_page_protection_from_mach (region.pri_protection);

  return TRUE;
}

gboolean
gum_darwin_query_shared_cache_range (mach_port_t task,
                                     GumMemoryRange * range)
{
  GumDarwinAllImageInfos infos;
  GumAddress start, end;
  mach_vm_address_t address;
  mach_vm_size_t size;
  natural_t depth;
  struct vm_region_submap_info_64 info;
  mach_msg_type_number_t info_count;
  kern_return_t kr;

  if (!gum_darwin_query_all_image_infos (task, &infos))
    return FALSE;

  start = infos.shared_cache_base_address;
  if (start == 0)
    return FALSE;

  address = start;
  depth = 0;
  info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

  kr = mach_vm_region_recurse (task, &address, &size, &depth,
      (vm_region_recurse_info_t) &info, &info_count);
  if (kr != KERN_SUCCESS)
    return FALSE;

  start = address;
  end = address + size;

  do
  {
    gboolean is_contiguous, is_dsc_tag;

    address += size;
    depth = 0;
    info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kr = mach_vm_region_recurse (task, &address, &size, &depth,
        (vm_region_recurse_info_t) &info, &info_count);
    if (kr != KERN_SUCCESS)
      break;

    is_contiguous = address == end;
    if (!is_contiguous)
      break;

    is_dsc_tag = info.user_tag == 0x20 || info.user_tag == 0x23;
    if (!is_dsc_tag)
      break;

    end = address + size;
  }
  while (TRUE);

  range->base_address = start;
  range->size = end - start;

  return TRUE;
}

GumAddress
gum_darwin_find_entrypoint (mach_port_t task)
{
  GumFindEntrypointContext ctx;

  ctx.result = 0;
  ctx.task = task;
  ctx.alignment = 4096;

  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX,
      gum_probe_range_for_entrypoint, &ctx);

  return ctx.result;
}

static gboolean
gum_probe_range_for_entrypoint (const GumRangeDetails * details,
                                gpointer user_data)
{
  const GumMemoryRange * range = details->range;
  GumFindEntrypointContext * ctx = user_data;
  gboolean carry_on = TRUE;
  guint8 * chunk, * page, * p;
  gsize chunk_size;

  chunk = gum_darwin_read (ctx->task, range->base_address, range->size,
      &chunk_size);
  if (chunk == NULL)
    return TRUE;

  g_assert (chunk_size % ctx->alignment == 0);

  for (page = chunk; page != chunk + chunk_size; page += ctx->alignment)
  {
    struct mach_header * header;
    gint64 slide;
    guint cmd_index;
    GumAddress text_base = 0, text_offset = 0;

    header = (struct mach_header *) page;
    if (header->magic != MH_MAGIC && header->magic != MH_MAGIC_64)
      continue;

    if (header->filetype != MH_EXECUTE)
      continue;

    if (!gum_darwin_find_slide (range->base_address + (page - chunk), page,
          chunk_size - (page - chunk), &slide))
    {
      continue;
    }

    carry_on = FALSE;

    if (header->magic == MH_MAGIC)
      p = page + sizeof (struct mach_header);
    else
      p = page + sizeof (struct mach_header_64);
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      switch (lc->cmd)
      {
        case LC_SEGMENT:
        {
          struct segment_command * sc = (struct segment_command *) lc;
          if (strcmp (sc->segname, "__TEXT") == 0)
            text_base = sc->vmaddr + slide;
          break;
        }
        case LC_SEGMENT_64:
        {
          struct segment_command_64 * sc = (struct segment_command_64 *) lc;
          if (strcmp (sc->segname, "__TEXT") == 0)
            text_base = sc->vmaddr + slide;
          break;
        }
#ifdef HAVE_I386
        case LC_UNIXTHREAD:
        {
          guint8 * thread = p + sizeof (struct thread_command);
          while (thread != p + lc->cmdsize)
          {
            thread_state_flavor_t * flavor = (thread_state_flavor_t *) thread;
            mach_msg_type_number_t * count = (mach_msg_type_number_t *)
                (flavor + 1);
            if (header->magic == MH_MAGIC && *flavor == x86_THREAD_STATE32)
            {
              x86_thread_state32_t * ts = (x86_thread_state32_t *) (count + 1);
              ctx->result = ts->__eip + slide;
            }
            else if (header->magic == MH_MAGIC_64 &&
                *flavor == x86_THREAD_STATE64)
            {
              x86_thread_state64_t * ts = (x86_thread_state64_t *) (count + 1);
              ctx->result = ts->__rip + slide;
            }
            thread = ((guint8 *) (count + 1)) + (*count * sizeof (int));
          }
          break;
        }
#endif
        case LC_MAIN:
        {
          struct entry_point_command * ec = (struct entry_point_command *) p;
          text_offset = ec->entryoff;
          break;
        }
      }
      p += lc->cmdsize;
    }

    if (ctx->result == 0)
      ctx->result = text_base + text_offset;

    if (!carry_on)
      break;
  }

  g_free (chunk);
  return carry_on;
}

gboolean
gum_darwin_modify_thread (mach_port_t thread,
                          GumModifyThreadFunc func,
                          gpointer user_data,
                          GumModifyThreadFlags flags)
{
#ifdef HAVE_WATCHOS
  return FALSE;
#else
  kern_return_t kr;
  gboolean is_suspended = FALSE;
  GumDarwinUnifiedThreadState state;
  mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
  thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;
  GumCpuContext cpu_context, original_cpu_context;

  kr = thread_suspend (thread);
  if (kr != KERN_SUCCESS)
    goto beach;

  is_suspended = TRUE;

  if ((flags & GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY) != 0)
  {
    kr = thread_abort_safely (thread);
    if (kr != KERN_SUCCESS)
      goto beach;
  }

  kr = thread_get_state (thread, state_flavor, (thread_state_t) &state,
      &state_count);
  if (kr != KERN_SUCCESS)
    goto beach;

  gum_darwin_parse_unified_thread_state (&state, &cpu_context);
  memcpy (&original_cpu_context, &cpu_context, sizeof (cpu_context));

  func (thread, &cpu_context, user_data);

  if (memcmp (&cpu_context, &original_cpu_context, sizeof (cpu_context)) != 0)
  {
    gum_darwin_unparse_unified_thread_state (&cpu_context, &state);

    kr = thread_set_state (thread, state_flavor, (thread_state_t) &state,
        state_count);
  }

beach:
  if (is_suspended)
  {
    kern_return_t resume_res;

    resume_res = thread_resume (thread);
    if (kr == KERN_SUCCESS)
      kr = resume_res;
  }

  return kr == KERN_SUCCESS;
#endif
}

void
gum_darwin_enumerate_threads (mach_port_t task,
                              GumFoundThreadFunc func,
                              gpointer user_data)
{
  mach_port_t self;
  thread_act_array_t threads;
  mach_msg_type_number_t count;
  kern_return_t kr;

  self = mach_task_self ();

  kr = task_threads (task, &threads, &count);
  if (kr == KERN_SUCCESS)
  {
    guint i;

    for (i = 0; i != count; i++)
    {
      thread_t thread = threads[i];
      GumThreadDetails details;
      thread_basic_info_data_t info;
      mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
      GumDarwinUnifiedThreadState state;
      gchar thread_name[64];

      kr = thread_info (thread, THREAD_BASIC_INFO, (thread_info_t) &info,
          &info_count);
      if (kr != KERN_SUCCESS)
        continue;

#ifdef HAVE_WATCHOS
      bzero (&state, sizeof (state));
#else
      {
        mach_msg_type_number_t state_count = GUM_DARWIN_THREAD_STATE_COUNT;
        thread_state_flavor_t state_flavor = GUM_DARWIN_THREAD_STATE_FLAVOR;

        kr = thread_get_state (thread, state_flavor, (thread_state_t) &state,
            &state_count);
        if (kr != KERN_SUCCESS)
          continue;
      }
#endif

      details.id = (GumThreadId) thread;

      details.name = NULL;
      if (task == self)
      {
        pthread_t th = pthread_from_mach_thread_np (thread);
        if (th != NULL)
        {
          pthread_getname_np (th, thread_name, sizeof (thread_name));
          if (thread_name[0] != '\0')
            details.name = thread_name;
        }
      }

      details.state = gum_thread_state_from_darwin (info.run_state);

      gum_darwin_parse_unified_thread_state (&state, &details.cpu_context);

      if (!func (&details, user_data))
        break;
    }

    for (i = 0; i != count; i++)
      mach_port_deallocate (self, threads[i]);
    vm_deallocate (self, (vm_address_t) threads, count * sizeof (thread_t));
  }
}

void
gum_darwin_enumerate_modules (mach_port_t task,
                              GumFoundModuleFunc func,
                              gpointer user_data)
{
  GumDarwinAllImageInfos infos;
  gboolean inprocess;
  const gchar * sysroot;
  guint sysroot_size;
  gsize i;
  gpointer info_array, info_array_malloc_data = NULL;
  gpointer header_data, header_data_end, header_malloc_data = NULL;
  const guint header_data_initial_size = 4096;
  gchar * file_path, * file_path_malloc_data = NULL;
  gboolean carry_on = TRUE;

  if (!gum_darwin_query_all_image_infos (task, &infos))
    goto beach;

  if (infos.info_array_address == 0)
    goto fallback;

  inprocess = task == mach_task_self ();

  sysroot = inprocess ? gum_darwin_query_sysroot () : NULL;
  sysroot_size = (sysroot != NULL) ? strlen (sysroot) : 0;

  if (inprocess)
  {
    info_array = GSIZE_TO_POINTER (infos.info_array_address);
  }
  else
  {
    info_array = gum_darwin_read (task, infos.info_array_address,
        infos.info_array_size, NULL);
    info_array_malloc_data = info_array;
  }

  for (i = 0; i != infos.info_array_count + 1 && carry_on; i++)
  {
    GumAddress load_address;
    struct mach_header * header;
    gpointer first_command, p;
    guint cmd_index;
    GumMemoryRange dylib_range;
    gchar * name;
    GumModuleDetails details;

    if (i != infos.info_array_count)
    {
      GumAddress file_path_address;

      if (infos.format == TASK_DYLD_ALL_IMAGE_INFO_64)
      {
        DyldImageInfo64 * info = info_array + (i * DYLD_IMAGE_INFO_64_SIZE);
        load_address = info->image_load_address;
        file_path_address = info->image_file_path;
      }
      else
      {
        DyldImageInfo32 * info = info_array + (i * DYLD_IMAGE_INFO_32_SIZE);
        load_address = info->image_load_address;
        file_path_address = info->image_file_path;
      }

      if (inprocess)
      {
        header_data = GSIZE_TO_POINTER (load_address);

        file_path = GSIZE_TO_POINTER (file_path_address);
      }
      else
      {
        header_data = gum_darwin_read (task, load_address,
            header_data_initial_size, NULL);
        header_malloc_data = header_data;

        if (((file_path_address + MAXPATHLEN + 1) & ~((GumAddress) 4095))
            == load_address)
        {
          file_path = header_data + (file_path_address - load_address);
        }
        else
        {
          file_path = (gchar *) gum_darwin_read (task, file_path_address,
              MAXPATHLEN + 1, NULL);
          file_path_malloc_data = file_path;
        }
      }
      if (header_data == NULL || file_path == NULL)
        goto beach;
    }
    else
    {
      load_address = infos.dyld_image_load_address;

      if (inprocess)
      {
        header_data = GSIZE_TO_POINTER (load_address);
      }
      else
      {
        header_data = gum_darwin_read (task, load_address,
            header_data_initial_size, NULL);
        header_malloc_data = header_data;
      }
      if (header_data == NULL)
        goto beach;

      file_path = "/usr/lib/dyld";
    }

    header_data_end = header_data + header_data_initial_size;

    header = (struct mach_header *) header_data;
    if (infos.format == TASK_DYLD_ALL_IMAGE_INFO_64)
      first_command = header_data + sizeof (struct mach_header_64);
    else
      first_command = header_data + sizeof (struct mach_header);

    dylib_range.base_address = load_address;
    dylib_range.size = 4096;

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = p;

      if (!inprocess)
      {
        while (p + sizeof (struct load_command) > header_data_end ||
            p + lc->cmdsize > header_data_end)
        {
          gsize current_offset, new_size;

          if (file_path_malloc_data == NULL)
          {
            file_path_malloc_data = g_strdup (file_path);
            file_path = file_path_malloc_data;
          }

          current_offset = p - header_data;
          new_size = (header_data_end - header_data) + 4096;

          g_free (header_malloc_data);
          header_data = gum_darwin_read (task, load_address, new_size, NULL);
          header_malloc_data = header_data;
          if (header_data == NULL)
            goto beach;
          header_data_end = header_data + new_size;

          header = (struct mach_header *) header_data;

          p = header_data + current_offset;
          lc = (struct load_command *) p;

          first_command = NULL;
        }
      }

      if (lc->cmd == LC_SEGMENT)
      {
        struct segment_command * sc = p;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }
      else if (lc->cmd == LC_SEGMENT_64)
      {
        struct segment_command_64 * sc = p;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }

      p += lc->cmdsize;
    }

    name = g_path_get_basename (file_path);

    details.name = name;
    details.range = &dylib_range;
    details.path = file_path;
    if (sysroot != NULL && g_str_has_prefix (file_path, sysroot))
      details.path += sysroot_size;

    carry_on = func (&details, user_data);

    g_free (name);

    g_free (file_path_malloc_data);
    file_path_malloc_data = NULL;
    g_free (header_malloc_data);
    header_malloc_data = NULL;
  }

  goto beach;

fallback:
  gum_darwin_enumerate_modules_forensically (task, func, user_data);

beach:
  g_free (file_path_malloc_data);
  g_free (header_malloc_data);
  g_free (info_array_malloc_data);

  return;
}

void
gum_darwin_enumerate_modules_forensically (mach_port_t task,
                                           GumFoundModuleFunc func,
                                           gpointer user_data)
{
  GumEnumerateModulesSlowContext ctx;
  guint i;

  ctx.task = task;
  ctx.func = func;
  ctx.user_data = user_data;

  ctx.ranges = g_array_sized_new (FALSE, FALSE, sizeof (GumMemoryRange), 64);
  ctx.alignment = 4096;

  gum_darwin_enumerate_ranges (task, GUM_PAGE_RX,
      gum_store_range_of_potential_modules, &ctx);

  for (i = 0; i != ctx.ranges->len; i++)
  {
    GumMemoryRange * r = &g_array_index (ctx.ranges, GumMemoryRange, i);
    if (!gum_emit_modules_in_range (r, &ctx))
      break;
  }

  g_array_unref (ctx.ranges);
}

static gboolean
gum_store_range_of_potential_modules (const GumRangeDetails * details,
                                      gpointer user_data)
{
  GumEnumerateModulesSlowContext * ctx = user_data;

  g_array_append_val (ctx->ranges, *(details->range));

  return TRUE;
}

static gboolean
gum_emit_modules_in_range (const GumMemoryRange * range,
                           GumEnumerateModulesSlowContext * ctx)
{
  GumAddress address = range->base_address;
  gsize remaining = range->size;
  gboolean carry_on = TRUE;

  do
  {
    struct mach_header * header;
    gboolean is_dylib;
    guint8 * chunk;
    gsize chunk_size;
    guint8 * first_command, * p;
    guint cmd_index;
    GumMemoryRange dylib_range;

    header = (struct mach_header *) gum_darwin_read (ctx->task,
        address, sizeof (struct mach_header), NULL);
    if (header == NULL)
      return TRUE;
    is_dylib = (header->magic == MH_MAGIC || header->magic == MH_MAGIC_64) &&
        header->filetype == MH_DYLIB;
    g_free (header);

    if (!is_dylib)
    {
      address += ctx->alignment;
      remaining -= ctx->alignment;
      continue;
    }

    chunk = gum_darwin_read (ctx->task,
        address, MIN (MAX_MACH_HEADER_SIZE, remaining), &chunk_size);
    if (chunk == NULL)
      return TRUE;

    header = (struct mach_header *) chunk;
    if (header->magic == MH_MAGIC)
      first_command = chunk + sizeof (struct mach_header);
    else
      first_command = chunk + sizeof (struct mach_header_64);

    dylib_range.base_address = address;
    dylib_range.size = ctx->alignment;

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == GUM_LC_SEGMENT)
      {
        gum_segment_command_t * sc = (gum_segment_command_t *) lc;
        if (strcmp (sc->segname, "__TEXT") == 0)
        {
          dylib_range.size = sc->vmsize;
          break;
        }
      }

      p += lc->cmdsize;
    }

    p = first_command;
    for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
    {
      const struct load_command * lc = (struct load_command *) p;

      if (lc->cmd == LC_ID_DYLIB)
      {
        const struct dylib * dl = &((struct dylib_command *) lc)->dylib;
        const gchar * raw_path;
        guint raw_path_len;
        gchar * path, * name;
        GumModuleDetails details;

        raw_path = (gchar *) p + dl->name.offset;
        raw_path_len = lc->cmdsize - sizeof (struct dylib_command);
        path = g_strndup (raw_path, raw_path_len);
        name = g_path_get_basename (path);

        details.name = name;
        details.range = &dylib_range;
        details.path = path;

        carry_on = ctx->func (&details, ctx->user_data);

        g_free (name);
        g_free (path);

        break;
      }

      p += lc->cmdsize;
    }

    g_free (chunk);

    address += dylib_range.size;
    remaining -= dylib_range.size;

    if (!carry_on)
      break;
  }
  while (remaining != 0);

  return carry_on;
}

void
gum_darwin_enumerate_ranges (mach_port_t task,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  int pid;
  kern_return_t kr;
  mach_vm_address_t address = MACH_VM_MIN_ADDRESS;
  mach_vm_size_t size = 0;
  natural_t depth = 0;

  kr = pid_for_task (task, &pid);
  if (kr != KERN_SUCCESS)
    return;

  while (TRUE)
  {
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t info_count;
    GumPageProtection cur_prot;

    while (TRUE)
    {
      info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
      kr = mach_vm_region_recurse (task, &address, &size, &depth,
          (vm_region_recurse_info_t) &info, &info_count);
      if (kr != KERN_SUCCESS)
        break;

      if (info.is_submap)
      {
        depth++;
        continue;
      }
      else
      {
        break;
      }
    }

    if (kr != KERN_SUCCESS)
      break;

    cur_prot = gum_page_protection_from_mach (info.protection);

    if ((cur_prot & prot) == prot)
    {
      GumMemoryRange range;
      GumRangeDetails details;
      GumFileMapping file;
      struct proc_regionwithpathinfo region;

      range.base_address = address;
      range.size = size;

      details.range = &range;
      details.protection = cur_prot;
      details.file = NULL;

      if (pid != 0 && gum_darwin_fill_file_mapping (pid, address, &file,
          &region))
      {
        details.file = &file;
        gum_darwin_clamp_range_size (&range, &file);
      }

      if (!func (&details, user_data))
        return;
    }

    address += size;
    size = 0;
  }
}

static gboolean
gum_darwin_fill_file_mapping (gint pid,
                              mach_vm_address_t address,
                              GumFileMapping * file,
                              struct proc_regionwithpathinfo * region)
{
  gint flavor, retval, len;

  if (gum_darwin_check_xnu_version (2782, 1, 97))
    flavor = PROC_PIDREGIONPATHINFO2;
  else
    flavor = PROC_PIDREGIONPATHINFO;

  retval = __proc_info (PROC_INFO_CALL_PIDINFO, pid, flavor, (uint64_t) address,
      region, sizeof (struct proc_regionwithpathinfo));

  if (retval == -1)
    return FALSE;

  len = strnlen (region->prp_vip.vip_path, MAXPATHLEN - 1);
  region->prp_vip.vip_path[len] = '\0';

  if (len == 0)
    return FALSE;

  file->path = region->prp_vip.vip_path;
  file->offset = region->prp_prinfo.pri_offset;
  file->size = region->prp_vip.vip_vi.vi_stat.vst_size;

  return TRUE;
}

static void
gum_darwin_clamp_range_size (GumMemoryRange * range,
                             const GumFileMapping * file)
{
  const gsize end_of_map = file->offset + range->size;

  if (end_of_map > file->size)
  {
    const gsize delta = end_of_map - file->size;

    range->size = MIN (
        range->size,
        (range->size - delta + (vm_kernel_page_size - 1)) &
            ~(vm_kernel_page_size - 1));
  }
}

void
gum_darwin_enumerate_imports (mach_port_t task,
                              const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  GumEnumerateImportsContext ctx;
  GumDarwinModule * module;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.resolver = gum_darwin_module_resolver_new (task, NULL);
  if (ctx.resolver == NULL)
    return;
  ctx.module_map = NULL;

  module = gum_darwin_module_resolver_find_module (ctx.resolver, module_name);
  if (module != NULL)
  {
    gum_darwin_module_enumerate_imports (module, gum_emit_import,
        gum_resolve_export, &ctx);
  }

  gum_clear_object (&ctx.module_map);
  gum_object_unref (ctx.resolver);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumImportDetails d;

  d.type = GUM_IMPORT_UNKNOWN;
  d.name = gum_symbol_name_from_darwin (details->name);
  d.module = details->module;
  d.address = 0;
  d.slot = details->slot;

  if (d.module == NULL)
  {
    if (details->address != 0)
      d.address = details->address;
    else
      d.address = GUM_ADDRESS (dlsym (RTLD_DEFAULT, d.name));

    if (d.address != 0)
    {
      const GumModuleDetails * module_details;
      Dl_info info;

      if (ctx->module_map == NULL)
        ctx->module_map = gum_module_map_new ();
      module_details = gum_module_map_find (ctx->module_map, d.address);
      if (module_details != NULL)
        d.module = module_details->path;
      else if (dladdr (GSIZE_TO_POINTER (d.address), &info) != 0)
        d.module = info.dli_fname;
    }
  }

  if (d.module != NULL)
  {
    GumDarwinModule * module;
    GumExportDetails exp;

    module = gum_darwin_module_resolver_find_module (ctx->resolver, d.module);
    if (module != NULL)
    {
      if (gum_darwin_module_resolver_find_export_by_mangled_name (ctx->resolver,
          module, details->name, &exp))
      {
        d.type = exp.type;
        d.address = exp.address;
      }
    }
  }

  return ctx->func (&d, ctx->user_data);
}

static GumAddress
gum_resolve_export (const char * module_name,
                    const char * symbol_name,
                    gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumDarwinModule * module;

  if (module_name == NULL)
  {
    const char * name = gum_symbol_name_from_darwin (symbol_name);
    return GUM_ADDRESS (dlsym (RTLD_DEFAULT, name));
  }

  module = gum_darwin_module_resolver_find_module (ctx->resolver, module_name);
  if (module != NULL)
  {
    GumExportDetails exp;

    if (gum_darwin_module_resolver_find_export_by_mangled_name (ctx->resolver,
        module, symbol_name, &exp))
    {
      return exp.address;
    }
  }

  return 0;
}

void
gum_darwin_enumerate_exports (mach_port_t task,
                              const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumEnumerateExportsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.resolver = gum_darwin_module_resolver_new (task, NULL);
  if (ctx.resolver == NULL)
    return;
  ctx.module = gum_darwin_module_resolver_find_module (ctx.resolver,
      module_name);
  ctx.carry_on = TRUE;
  if (ctx.module != NULL)
  {
    gum_darwin_module_enumerate_exports (ctx.module, gum_emit_export, &ctx);

    if (gum_darwin_module_get_lacks_exports_for_reexports (ctx.module))
    {
      GPtrArray * reexports = ctx.module->reexports;
      guint i;

      for (i = 0; ctx.carry_on && i != reexports->len; i++)
      {
        GumDarwinModule * reexport;

        reexport = gum_darwin_module_resolver_find_module (ctx.resolver,
            g_ptr_array_index (reexports, i));
        if (reexport != NULL)
        {
          ctx.module = reexport;
          gum_darwin_module_enumerate_exports (reexport, gum_emit_export, &ctx);
        }
      }
    }
  }

  gum_object_unref (ctx.resolver);
}

static gboolean
gum_emit_export (const GumDarwinExportDetails * details,
                 gpointer user_data)
{
  GumEnumerateExportsContext * ctx = user_data;
  GumExportDetails export;

  if (!gum_darwin_module_resolver_resolve_export (ctx->resolver, ctx->module,
      details, &export))
  {
    return TRUE;
  }

  ctx->carry_on = ctx->func (&export, ctx->user_data);

  return ctx->carry_on;
}

void
gum_darwin_enumerate_symbols (mach_port_t task,
                              const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  GumDarwinModuleResolver * resolver;
  GumDarwinModule * module;

  resolver = gum_darwin_module_resolver_new (task, NULL);
  if (resolver == NULL)
    return;

  module = gum_darwin_module_resolver_find_module (resolver, module_name);
  if (module != NULL)
  {
    GumEnumerateSymbolsContext ctx;

    ctx.func = func;
    ctx.user_data = user_data;

    ctx.sections = g_array_new (FALSE, FALSE, sizeof (GumSymbolSection));
    g_array_set_clear_func (ctx.sections,
        (GDestroyNotify) gum_symbol_section_destroy);

    gum_darwin_module_enumerate_sections (module, gum_append_symbol_section,
        ctx.sections);

    gum_darwin_module_enumerate_symbols (module, gum_emit_symbol, &ctx);

    g_array_free (ctx.sections, TRUE);
  }

  gum_object_unref (resolver);
}

static gboolean
gum_emit_symbol (const GumDarwinSymbolDetails * details,
                 gpointer user_data)
{
  GumEnumerateSymbolsContext * ctx = user_data;
  GumSymbolDetails symbol;

  symbol.is_global = (details->type & N_EXT) != 0;

  switch (details->type & N_TYPE)
  {
    case N_UNDF: symbol.type = GUM_SYMBOL_UNDEFINED;          break;
    case N_ABS:  symbol.type = GUM_SYMBOL_ABSOLUTE;           break;
    case N_SECT: symbol.type = GUM_SYMBOL_SECTION;            break;
    case N_PBUD: symbol.type = GUM_SYMBOL_PREBOUND_UNDEFINED; break;
    case N_INDR: symbol.type = GUM_SYMBOL_INDIRECT;           break;
    default:     symbol.type = GUM_SYMBOL_UNKNOWN;            break;
  }

  if (details->section != NO_SECT && details->section <= ctx->sections->len)
  {
    symbol.section = &g_array_index (ctx->sections, GumSymbolSection,
        details->section - 1);
  }
  else
  {
    symbol.section = NULL;
  }

  symbol.name = gum_symbol_name_from_darwin (details->name);
  symbol.address = details->address;
  symbol.size = -1;

  return ctx->func (&symbol, ctx->user_data);
}

static gboolean
gum_append_symbol_section (const GumDarwinSectionDetails * details,
                           gpointer user_data)
{
  GArray * sections = user_data;
  GumSymbolSection section;

  section.id = g_strdup_printf ("%u.%s.%s", sections->len,
      details->segment_name, details->section_name);
  section.protection = gum_page_protection_from_mach (details->protection);

  g_array_append_val (sections, section);

  return TRUE;
}

static void
gum_symbol_section_destroy (GumSymbolSection * self)
{
  g_free ((gpointer) self->id);
}

void
gum_darwin_enumerate_sections (mach_port_t task,
                               const gchar * module_name,
                               GumFoundSectionFunc func,
                               gpointer user_data)
{
  GumDarwinModuleResolver * resolver;
  GumDarwinModule * module;

  resolver = gum_darwin_module_resolver_new (task, NULL);
  if (resolver == NULL)
    return;

  module = gum_darwin_module_resolver_find_module (resolver, module_name);
  if (module != NULL)
  {
    GumEnumerateSectionsContext ctx;

    ctx.func = func;
    ctx.user_data = user_data;
    ctx.next_section_id = 0;

    gum_darwin_module_enumerate_sections (module, gum_emit_section, &ctx);
  }

  gum_object_unref (resolver);
}

static gboolean
gum_emit_section (const GumDarwinSectionDetails * details,
                  gpointer user_data)
{
  GumEnumerateSectionsContext * ctx = user_data;
  gboolean carry_on;
  GumSectionDetails section;

  section.id = g_strdup_printf ("%u.%s.%s", ctx->next_section_id,
      details->segment_name, details->section_name);
  section.name = details->section_name;
  section.address = details->vm_address;
  section.size = details->size;

  carry_on = ctx->func (&section, ctx->user_data);

  g_free ((gpointer) section.id);

  ctx->next_section_id++;

  return carry_on;
}

void
gum_darwin_enumerate_dependencies (mach_port_t task,
                                   const gchar * module_name,
                                   GumFoundDependencyFunc func
"""


```