Response:
The user wants a summary of the functionality of the provided C++ code snippet from `bionic/linker/linker.cpp`. This code seems to be handling the dynamic linking and unloading of shared libraries in Android.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core function:** The code primarily deals with unloading shared libraries. The functions `soinfo_unload` and `soinfo_unload_impl` are central to this process.

2. **Trace the unloading process:**  Start by examining `soinfo_unload`. It checks if the library is linked. If linked, it retrieves the root of the load group and decrements its reference count. If the reference count becomes zero, it calls `soinfo_unload_impl`. If not linked, it directly calls `soinfo_unload_impl`.

3. **Analyze `soinfo_unload_impl`:** This function performs the actual unloading. It iterates through the library's dependencies (`local_unload_list`) and calls destructors. It then unregisters the library's TLS, calls an unload hook, and frees the `soinfo` structure. It also handles external references, unloading them if the library was linked.

4. **Consider related functions:**  The `increment_dso_handle_reference_counter` and `decrement_dso_handle_reference_counter` functions manage reference counts for library handles, which directly impacts when a library is unloaded. `do_dlclose` is the user-facing API that triggers the unloading process.

5. **Connect to Android functionality:** The code interacts with Android's dynamic linking mechanism, specifically the `dlopen`, `dlclose`, and `dlsym` family of functions. It also manages namespaces for libraries, a feature specific to Android's linker.

6. **Identify key concepts:**  Reference counting, load groups, namespaces, TLS, destructors, and external dependencies are important concepts demonstrated in the code.

7. **Formulate the summary:**  Combine the identified functionalities and key concepts into a concise summary, focusing on the core purpose of the code.
这段代码是 `bionic/linker/linker.cpp` 文件的一部分，主要负责 **卸载 (unloading)** 动态链接库（shared objects, SOs）。

以下是这段代码功能的归纳：

**核心功能：卸载动态链接库**

1. **`soinfo_unload(soinfo* unload_si)`**: 这是卸载动态链接库的入口函数。
    * **确定卸载根节点:**  判断要卸载的 SO 是否已链接 (`is_linked`)。如果已链接，则找到其所属的加载组的根 SO (`get_local_group_root()`)。如果未链接（例如，`dlopen` 失败的情况），则将自身作为根节点。
    * **引用计数管理:**  如果 SO 已链接，则递减根 SO 的引用计数 (`decrement_ref_count()`)。如果引用计数大于 0，则不进行实际卸载，直接返回。
    * **调用卸载实现:**  如果引用计数为 0，则调用 `soinfo_unload_impl(root)` 来执行实际的卸载操作。

2. **`soinfo_unload_impl(soinfo* root)`**: 这是实际执行卸载操作的函数。
    * **调用析构函数:** 遍历根 SO 及其依赖项列表 (`local_unload_list`)，为每个 SO 调用其析构函数。
    * **通知 GDB:** 调用 `notify_gdb_of_unload(si)` 通知调试器库被卸载。
    * **注销 TLS:** 调用 `unregister_soinfo_tls(si)` 注销该 SO 的线程局部存储 (TLS)。
    * **执行卸载钩子:** 如果定义了卸载钩子 (`__libc_shared_globals()->unload_hook`)，则调用该钩子。
    * **CFI 处理:** 调用 `get_cfi_shadow()->BeforeUnload(si)` 执行控制流完整性 (CFI) 相关的卸载前处理。
    * **释放 `soinfo` 结构:** 调用 `soinfo_free(si)` 释放表示该 SO 的 `soinfo` 结构。
    * **处理外部引用:** 如果 SO 已链接，则遍历其外部引用列表 (`external_unload_list`)，调用 `soinfo_unload(si)` 递归卸载这些外部引用的 SO。如果 SO 未链接，则跳过卸载外部引用。

3. **`increment_dso_handle_reference_counter(void* dso_handle)` 和 `decrement_dso_handle_reference_counter(void* dso_handle)`**: 这两个函数用于管理通过 `dlopen` 获取的动态链接库句柄 (`dso_handle`) 的引用计数。
    * **`increment_dso_handle_reference_counter`**: 增加指定句柄的引用计数。如果该句柄是第一次被引用，则找到对应的 `soinfo` 并增加其引用计数。
    * **`decrement_dso_handle_reference_counter`**: 减少指定句柄的引用计数。当引用计数降为 0 时，找到对应的 `soinfo` 并调用 `soinfo_unload` 来卸载该库。

4. **`do_dlclose(void* handle)`**:  这是用户调用 `dlclose` 时最终调用的 linker 函数。它获取与句柄关联的 `soinfo`，并调用 `soinfo_unload` 来执行卸载。

**与 Android 功能的关系：**

* **`dlclose` 系统调用**:  这段代码实现了 `dlclose` 的核心逻辑。Android 应用或 NDK 库调用 `dlclose` 时，最终会到达这里的 `do_dlclose` 函数。
* **动态链接库管理**:  Android 系统使用动态链接器来加载和卸载共享库。这段代码是动态链接器的一部分，负责执行卸载操作。
* **命名空间隔离**:  代码中涉及到 `soinfo` 的加载组 (`get_local_group_root`) 和命名空间的概念，这与 Android 的库隔离机制有关。
* **GDB 集成**: `notify_gdb_of_unload` 表明 linker 会通知 GDB 调试器关于库的卸载事件，方便调试。

**示例说明：**

假设一个应用通过 `dlopen` 加载了一个名为 `libfoo.so` 的库，并持有了该库的句柄 `handle_foo`。

1. **应用调用 `dlclose(handle_foo)`**:  系统调用会进入 linker 的 `do_dlclose` 函数。
2. **`do_dlclose` 调用 `soinfo_unload`**:  `soinfo_unload` 找到与 `handle_foo` 关联的 `soinfo` 结构（假设为 `si_foo`）。
3. **`soinfo_unload` 递减引用计数**:  如果 `libfoo.so` 是一个加载组的根节点，则会递减其引用计数。
4. **如果引用计数为 0，调用 `soinfo_unload_impl`**:
    * **调用 `libfoo.so` 的析构函数**: 如果 `libfoo.so` 定义了全局对象的析构函数，这些函数会被调用。
    * **卸载依赖项**: 如果 `libfoo.so` 依赖于其他库（例如 `libbar.so`），并且没有其他库依赖于 `libbar.so`，则 `libbar.so` 也会被卸载。
    * **释放内存**:  `si_foo` 结构所占用的内存会被释放。

**libc 函数实现细节：**

这段代码本身并没有直接实现 libc 函数，而是动态链接器的一部分，它负责加载和卸载共享库，这些共享库中包含了 libc 函数的实现。  例如，当 `soinfo_free` 被调用时，它会释放 `soinfo` 结构占用的内存，这通常是通过 libc 的内存管理函数（如 `free`）来实现的。

**Dynamic Linker 功能，SO 布局和链接处理过程：**

这段代码主要关注卸载过程，我们结合上下文来推断链接处理过程：

**假设的 SO 布局：**

```
// libmain.so (应用主库)
// |
// +--- libfoo.so (通过 dlopen 加载)
//      |
//      +--- libbar.so (libfoo.so 的依赖)
```

**链接处理过程（简化）：**

1. **`dlopen("libfoo.so")`**:
   * linker 在命名空间中查找 `libfoo.so`。
   * 加载 `libfoo.so` 到内存，并创建 `soinfo` 结构 `si_foo`。
   * 解析 `libfoo.so` 的 `DT_NEEDED` 标签，发现依赖 `libbar.so`。
   * linker 在命名空间中查找 `libbar.so`。
   * 加载 `libbar.so` 到内存，并创建 `soinfo` 结构 `si_bar`。
   * 建立 `si_foo` 和 `si_bar` 的依赖关系。
   * 解析 `libfoo.so` 和 `libbar.so` 的符号表，进行符号解析和重定位。
   * 调用 `libfoo.so` 和 `libbar.so` 的构造函数。
   * 返回 `libfoo.so` 的句柄。

2. **`dlclose(handle_foo)`**:
   * linker 调用 `soinfo_unload(si_foo)`。
   * `si_foo` 的引用计数减 1。
   * 如果没有其他地方引用 `libfoo.so`，则 `si_foo` 的引用计数变为 0。
   * 调用 `soinfo_unload_impl(si_foo)`。
   * 遍历 `si_foo` 的本地卸载列表，可能包含 `si_bar`。
   * 调用 `si_bar` 的析构函数。
   * 卸载 `si_bar`（如果不再被其他库依赖）。
   * 调用 `si_foo` 的析构函数。
   * 释放 `si_foo` 和 `si_bar` 的 `soinfo` 结构。
   * 从内存中卸载 `libfoo.so` 和 `libbar.so`。

**逻辑推理，假设输入与输出：**

假设 `libfoo.so` 和 `libbar.so` 都定义了全局对象的析构函数，并且 `libfoo.so` 依赖于 `libbar.so`。

**输入：**

* 调用 `dlclose` 函数，传入 `libfoo.so` 的句柄。

**输出：**

1. `libfoo.so` 的全局对象的析构函数被调用。
2. `libbar.so` 的全局对象的析构函数被调用。
3. `libfoo.so` 和 `libbar.so` 从进程的内存空间中卸载。
4. linker 内部与 `libfoo.so` 和 `libbar.so` 相关的 `soinfo` 结构被释放。

**用户或编程常见的使用错误：**

* **多次 `dlclose` 同一个句柄**: 这会导致 double-free 或其他内存错误。linker 通常会检查句柄的有效性，但过度依赖这种检查不是好的编程习惯。
* **忘记 `dlclose`**:  会导致内存泄漏，因为加载的 SO 一直占用内存。
* **在 SO 的析构函数中调用 `dlclose` 卸载自身或其他相关的 SO**: 这可能会导致死锁或其他的复杂问题，因为卸载过程可能正在进行中。
* **在多线程环境下不正确地使用 `dlopen` 和 `dlclose`**:  需要注意线程安全，避免竞争条件。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例：**

1. **Android Framework/NDK 调用 `dlopen` 或 `dlclose`**:
   * 例如，Java 代码中使用 `System.loadLibrary()` 加载 NDK 库，最终会调用 `dlopen`。
   * NDK 代码可以直接调用 `dlopen` 和 `dlclose`。
   * Android Framework 内部也会使用 `dlopen` 和 `dlclose` 来加载和卸载各种模块。

2. **系统调用**:  `dlopen` 和 `dlclose` 是系统调用，会陷入内核。

3. **linker 处理系统调用**: 内核将系统调用传递给动态链接器进程 (linker)。

4. **执行 `do_dlopen` 或 `do_dlclose`**: linker 根据系统调用类型执行相应的函数。

**Frida Hook 示例：**

可以使用 Frida Hook `do_dlclose` 函数来观察卸载过程。

```javascript
// Frida 脚本

Interceptor.attach(Module.findExportByName(null, "dlclose"), {
  onEnter: function (args) {
    console.log("dlclose called with handle:", args[0]);
    var handle = ptr(args[0]);
    var soinfo_ptr = Memory.readPointer(handle); // 假设 handle 指向 soinfo
    if (soinfo_ptr) {
      var realpath = Memory.readCString(Memory.readPointer(soinfo_ptr.add(offset_of_realpath))); // 需要确定 realpath 成员的偏移
      console.log("  Realpath:", realpath);
    }
  },
  onLeave: function (retval) {
    console.log("dlclose returned:", retval);
  }
});
```

**注意：** 上面的 Frida 脚本只是一个示例，需要根据实际的 linker 实现和 `soinfo` 结构来确定偏移量。

总而言之，这段代码是 Android 动态链接器的核心组成部分，负责安全有效地卸载不再需要的共享库，释放资源并保持系统的稳定运行。

### 提示词
```
这是目录为bionic/linker/linker.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
e: calling destructors for \"%s\"@%p ... done",
           si->get_realpath(),
           si);
  });

  while ((si = local_unload_list.pop_front()) != nullptr) {
    LD_LOG(kLogDlopen,
           "... dlclose: unloading \"%s\"@%p ...",
           si->get_realpath(),
           si);
    ++g_module_unload_counter;
    notify_gdb_of_unload(si);
    unregister_soinfo_tls(si);
    if (__libc_shared_globals()->unload_hook) {
      __libc_shared_globals()->unload_hook(si->load_bias, si->phdr, si->phnum);
    }
    get_cfi_shadow()->BeforeUnload(si);
    soinfo_free(si);
  }

  if (is_linked) {
    while ((si = external_unload_list.pop_front()) != nullptr) {
      LD_LOG(kLogDlopen,
             "... dlclose: unloading external reference \"%s\"@%p ...",
             si->get_realpath(),
             si);
      soinfo_unload(si);
    }
  } else {
      LD_LOG(kLogDlopen,
             "... dlclose: unload_si was not linked - not unloading external references ...");
  }
}

static void soinfo_unload(soinfo* unload_si) {
  // Note that the library can be loaded but not linked;
  // in which case there is no root but we still need
  // to walk the tree and unload soinfos involved.
  //
  // This happens on unsuccessful dlopen, when one of
  // the DT_NEEDED libraries could not be linked/found.
  bool is_linked = unload_si->is_linked();
  soinfo* root = is_linked ? unload_si->get_local_group_root() : unload_si;

  LD_LOG(kLogDlopen,
         "... dlclose(realpath=\"%s\"@%p) ... load group root is \"%s\"@%p",
         unload_si->get_realpath(),
         unload_si,
         root->get_realpath(),
         root);


  size_t ref_count = is_linked ? root->decrement_ref_count() : 0;
  if (ref_count > 0) {
    LD_LOG(kLogDlopen,
           "... dlclose(root=\"%s\"@%p) ... not unloading - decrementing ref_count to %zd",
           root->get_realpath(),
           root,
           ref_count);
    return;
  }

  soinfo_unload_impl(root);
}

void increment_dso_handle_reference_counter(void* dso_handle) {
  if (dso_handle == nullptr) {
    return;
  }

  auto it = g_dso_handle_counters.find(dso_handle);
  if (it != g_dso_handle_counters.end()) {
    CHECK(++it->second != 0);
  } else {
    soinfo* si = find_containing_library(dso_handle);
    if (si != nullptr) {
      ProtectedDataGuard guard;
      si->increment_ref_count();
    } else {
      async_safe_fatal(
          "increment_dso_handle_reference_counter: Couldn't find soinfo by dso_handle=%p",
          dso_handle);
    }
    g_dso_handle_counters[dso_handle] = 1U;
  }
}

void decrement_dso_handle_reference_counter(void* dso_handle) {
  if (dso_handle == nullptr) {
    return;
  }

  auto it = g_dso_handle_counters.find(dso_handle);
  CHECK(it != g_dso_handle_counters.end());
  CHECK(it->second != 0);

  if (--it->second == 0) {
    soinfo* si = find_containing_library(dso_handle);
    if (si != nullptr) {
      ProtectedDataGuard guard;
      soinfo_unload(si);
    } else {
      async_safe_fatal(
          "decrement_dso_handle_reference_counter: Couldn't find soinfo by dso_handle=%p",
          dso_handle);
    }
    g_dso_handle_counters.erase(it);
  }
}

static std::string symbol_display_name(const char* sym_name, const char* sym_ver) {
  if (sym_ver == nullptr) {
    return sym_name;
  }

  return std::string(sym_name) + ", version " + sym_ver;
}

static android_namespace_t* get_caller_namespace(soinfo* caller) {
  return caller != nullptr ? caller->get_primary_namespace() : g_anonymous_namespace;
}

void do_android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size) {
  // Use basic string manipulation calls to avoid snprintf.
  // snprintf indirectly calls pthread_getspecific to get the size of a buffer.
  // When debug malloc is enabled, this call returns 0. This in turn causes
  // snprintf to do nothing, which causes libraries to fail to load.
  // See b/17302493 for further details.
  // Once the above bug is fixed, this code can be modified to use
  // snprintf again.
  const auto& default_ld_paths = g_default_namespace.get_default_library_paths();

  size_t required_size = 0;
  for (const auto& path : default_ld_paths) {
    required_size += path.size() + 1;
  }

  if (buffer_size < required_size) {
    async_safe_fatal("android_get_LD_LIBRARY_PATH failed, buffer too small: "
                     "buffer len %zu, required len %zu", buffer_size, required_size);
  }

  char* end = buffer;
  for (size_t i = 0; i < default_ld_paths.size(); ++i) {
    if (i > 0) *end++ = ':';
    end = stpcpy(end, default_ld_paths[i].c_str());
  }
}

void do_android_update_LD_LIBRARY_PATH(const char* ld_library_path) {
  parse_LD_LIBRARY_PATH(ld_library_path);
}

static std::string android_dlextinfo_to_string(const android_dlextinfo* info) {
  if (info == nullptr) {
    return "(null)";
  }

  return android::base::StringPrintf("[flags=0x%" PRIx64 ","
                                     " reserved_addr=%p,"
                                     " reserved_size=0x%zx,"
                                     " relro_fd=%d,"
                                     " library_fd=%d,"
                                     " library_fd_offset=0x%" PRIx64 ","
                                     " library_namespace=%s@%p]",
                                     info->flags,
                                     info->reserved_addr,
                                     info->reserved_size,
                                     info->relro_fd,
                                     info->library_fd,
                                     info->library_fd_offset,
                                     (info->flags & ANDROID_DLEXT_USE_NAMESPACE) != 0 ?
                                        (info->library_namespace != nullptr ?
                                          info->library_namespace->get_name() : "(null)") : "(n/a)",
                                     (info->flags & ANDROID_DLEXT_USE_NAMESPACE) != 0 ?
                                        info->library_namespace : nullptr);
}

void* do_dlopen(const char* name, int flags,
                const android_dlextinfo* extinfo,
                const void* caller_addr) {
  std::string trace_prefix = std::string("dlopen: ") + (name == nullptr ? "(nullptr)" : name);
  ScopedTrace trace(trace_prefix.c_str());
  ScopedTrace loading_trace((trace_prefix + " - loading and linking").c_str());
  soinfo* const caller = find_containing_library(caller_addr);
  android_namespace_t* ns = get_caller_namespace(caller);

  LD_LOG(kLogDlopen,
         "dlopen(name=\"%s\", flags=0x%x, extinfo=%s, caller=\"%s\", caller_ns=%s@%p, targetSdkVersion=%i) ...",
         name,
         flags,
         android_dlextinfo_to_string(extinfo).c_str(),
         caller == nullptr ? "(null)" : caller->get_realpath(),
         ns == nullptr ? "(null)" : ns->get_name(),
         ns,
         get_application_target_sdk_version());

  auto purge_guard = android::base::make_scope_guard([&]() { purge_unused_memory(); });

  auto failure_guard = android::base::make_scope_guard(
      [&]() { LD_LOG(kLogDlopen, "... dlopen failed: %s", linker_get_error_buffer()); });

  if ((flags & ~(RTLD_NOW|RTLD_LAZY|RTLD_LOCAL|RTLD_GLOBAL|RTLD_NODELETE|RTLD_NOLOAD)) != 0) {
    DL_OPEN_ERR("invalid flags to dlopen: %x", flags);
    return nullptr;
  }

  if (extinfo != nullptr) {
    if ((extinfo->flags & ~(ANDROID_DLEXT_VALID_FLAG_BITS)) != 0) {
      DL_OPEN_ERR("invalid extended flags to android_dlopen_ext: 0x%" PRIx64, extinfo->flags);
      return nullptr;
    }

    if ((extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD) == 0 &&
        (extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET) != 0) {
      DL_OPEN_ERR("invalid extended flag combination (ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET without "
          "ANDROID_DLEXT_USE_LIBRARY_FD): 0x%" PRIx64, extinfo->flags);
      return nullptr;
    }

    if ((extinfo->flags & ANDROID_DLEXT_USE_NAMESPACE) != 0) {
      if (extinfo->library_namespace == nullptr) {
        DL_OPEN_ERR("ANDROID_DLEXT_USE_NAMESPACE is set but extinfo->library_namespace is null");
        return nullptr;
      }
      ns = extinfo->library_namespace;
    }
  }

  // Workaround for dlopen(/system/lib/<soname>) when .so is in /apex. http://b/121248172
  // The workaround works only when targetSdkVersion < Q.
  std::string name_to_apex;
  if (translateSystemPathToApexPath(name, &name_to_apex)) {
    const char* new_name = name_to_apex.c_str();
    LD_LOG(kLogDlopen, "dlopen considering translation from %s to APEX path %s",
           name,
           new_name);
    // Some APEXs could be optionally disabled. Only translate the path
    // when the old file is absent and the new file exists.
    // TODO(b/124218500): Re-enable it once app compat issue is resolved
    /*
    if (file_exists(name)) {
      LD_LOG(kLogDlopen, "dlopen %s exists, not translating", name);
    } else
    */
    if (!file_exists(new_name)) {
      LD_LOG(kLogDlopen, "dlopen %s does not exist, not translating",
             new_name);
    } else {
      LD_LOG(kLogDlopen, "dlopen translation accepted: using %s", new_name);
      name = new_name;
    }
  }
  // End Workaround for dlopen(/system/lib/<soname>) when .so is in /apex.

  std::string translated_name_holder;

  assert(!g_is_hwasan || !g_is_asan);
  const char* translated_name = name;
  if (g_is_asan && translated_name != nullptr && translated_name[0] == '/') {
    char original_path[PATH_MAX];
    if (realpath(name, original_path) != nullptr) {
      translated_name_holder = std::string(kAsanLibDirPrefix) + original_path;
      if (file_exists(translated_name_holder.c_str())) {
        soinfo* si = nullptr;
        if (find_loaded_library_by_realpath(ns, original_path, true, &si)) {
          DL_WARN("linker_asan dlopen NOT translating \"%s\" -> \"%s\": library already loaded", name,
                  translated_name_holder.c_str());
        } else {
          DL_WARN("linker_asan dlopen translating \"%s\" -> \"%s\"", name, translated_name);
          translated_name = translated_name_holder.c_str();
        }
      }
    }
  } else if (g_is_hwasan && translated_name != nullptr && translated_name[0] == '/') {
    char original_path[PATH_MAX];
    if (realpath(name, original_path) != nullptr) {
      // Keep this the same as CreateHwasanPath in system/linkerconfig/modules/namespace.cc.
      std::string path(original_path);
      auto slash = path.rfind('/');
      if (slash != std::string::npos || slash != path.size() - 1) {
        translated_name_holder = path.substr(0, slash) + "/hwasan" + path.substr(slash);
      }
      if (!translated_name_holder.empty() && file_exists(translated_name_holder.c_str())) {
        soinfo* si = nullptr;
        if (find_loaded_library_by_realpath(ns, original_path, true, &si)) {
          DL_WARN("linker_hwasan dlopen NOT translating \"%s\" -> \"%s\": library already loaded",
                  name, translated_name_holder.c_str());
        } else {
          DL_WARN("linker_hwasan dlopen translating \"%s\" -> \"%s\"", name, translated_name);
          translated_name = translated_name_holder.c_str();
        }
      }
    }
  }
  ProtectedDataGuard guard;
  soinfo* si = find_library(ns, translated_name, flags, extinfo, caller);
  loading_trace.End();

  if (si != nullptr) {
    void* handle = si->to_handle();
    LD_LOG(kLogDlopen,
           "... dlopen calling constructors: realpath=\"%s\", soname=\"%s\", handle=%p",
           si->get_realpath(), si->get_soname(), handle);
    si->call_constructors();
    failure_guard.Disable();
    LD_LOG(kLogDlopen,
           "... dlopen successful: realpath=\"%s\", soname=\"%s\", handle=%p",
           si->get_realpath(), si->get_soname(), handle);
    return handle;
  }

  return nullptr;
}

int do_dladdr(const void* addr, Dl_info* info) {
  // Determine if this address can be found in any library currently mapped.
  soinfo* si = find_containing_library(addr);
  if (si == nullptr) {
    return 0;
  }

  memset(info, 0, sizeof(Dl_info));

  info->dli_fname = si->get_realpath();
  // Address at which the shared object is loaded.
  info->dli_fbase = reinterpret_cast<void*>(si->base);

  // Determine if any symbol in the library contains the specified address.
  ElfW(Sym)* sym = si->find_symbol_by_address(addr);
  if (sym != nullptr) {
    info->dli_sname = si->get_string(sym->st_name);
    info->dli_saddr = reinterpret_cast<void*>(si->resolve_symbol_address(sym));
  }

  return 1;
}

static soinfo* soinfo_from_handle(void* handle) {
  if ((reinterpret_cast<uintptr_t>(handle) & 1) != 0) {
    auto it = g_soinfo_handles_map.find(reinterpret_cast<uintptr_t>(handle));
    if (it == g_soinfo_handles_map.end()) {
      return nullptr;
    } else {
      return it->second;
    }
  }

  return static_cast<soinfo*>(handle);
}

bool do_dlsym(void* handle,
              const char* sym_name,
              const char* sym_ver,
              const void* caller_addr,
              void** symbol) {
  ScopedTrace trace("dlsym");
#if !defined(__LP64__)
  if (handle == nullptr) {
    DL_SYM_ERR("dlsym failed: library handle is null");
    return false;
  }
#endif

  soinfo* found = nullptr;
  const ElfW(Sym)* sym = nullptr;
  soinfo* caller = find_containing_library(caller_addr);
  android_namespace_t* ns = get_caller_namespace(caller);
  soinfo* si = nullptr;
  if (handle != RTLD_DEFAULT && handle != RTLD_NEXT) {
    si = soinfo_from_handle(handle);
  }

  LD_LOG(kLogDlsym,
         "dlsym(handle=%p(\"%s\"), sym_name=\"%s\", sym_ver=\"%s\", caller=\"%s\", caller_ns=%s@%p) ...",
         handle,
         si != nullptr ? si->get_realpath() : "n/a",
         sym_name,
         sym_ver,
         caller == nullptr ? "(null)" : caller->get_realpath(),
         ns == nullptr ? "(null)" : ns->get_name(),
         ns);

  auto failure_guard = android::base::make_scope_guard(
      [&]() { LD_LOG(kLogDlsym, "... dlsym failed: %s", linker_get_error_buffer()); });

  if (sym_name == nullptr) {
    DL_SYM_ERR("dlsym failed: symbol name is null");
    return false;
  }

  version_info vi_instance;
  version_info* vi = nullptr;

  if (sym_ver != nullptr) {
    vi_instance.name = sym_ver;
    vi_instance.elf_hash = calculate_elf_hash(sym_ver);
    vi = &vi_instance;
  }

  if (handle == RTLD_DEFAULT || handle == RTLD_NEXT) {
    sym = dlsym_linear_lookup(ns, sym_name, vi, &found, caller, handle);
  } else {
    if (si == nullptr) {
      DL_SYM_ERR("dlsym failed: invalid handle: %p", handle);
      return false;
    }
    sym = dlsym_handle_lookup(si, &found, sym_name, vi);
  }

  if (sym != nullptr) {
    uint32_t bind = ELF_ST_BIND(sym->st_info);
    uint32_t type = ELF_ST_TYPE(sym->st_info);

    if ((bind == STB_GLOBAL || bind == STB_WEAK) && sym->st_shndx != 0) {
      if (type == STT_TLS) {
        // For a TLS symbol, dlsym returns the address of the current thread's
        // copy of the symbol.
        const soinfo_tls* tls_module = found->get_tls();
        if (tls_module == nullptr) {
          DL_SYM_ERR("TLS symbol \"%s\" in solib \"%s\" with no TLS segment",
                     sym_name, found->get_realpath());
          return false;
        }
        void* tls_block = get_tls_block_for_this_thread(tls_module, /*should_alloc=*/true);
        *symbol = static_cast<char*>(tls_block) + sym->st_value;
      } else {
        *symbol = get_tagged_address(reinterpret_cast<void*>(found->resolve_symbol_address(sym)));
      }
      failure_guard.Disable();
      LD_LOG(kLogDlsym,
             "... dlsym successful: sym_name=\"%s\", sym_ver=\"%s\", found in=\"%s\", address=%p",
             sym_name, sym_ver, found->get_soname(), *symbol);
      return true;
    }

    DL_SYM_ERR("symbol \"%s\" found but not global", symbol_display_name(sym_name, sym_ver).c_str());
    return false;
  }

  DL_SYM_ERR("undefined symbol: %s", symbol_display_name(sym_name, sym_ver).c_str());
  return false;
}

int do_dlclose(void* handle) {
  ScopedTrace trace("dlclose");
  ProtectedDataGuard guard;
  soinfo* si = soinfo_from_handle(handle);
  if (si == nullptr) {
    DL_OPEN_ERR("invalid handle: %p", handle);
    return -1;
  }

  LD_LOG(kLogDlopen,
         "dlclose(handle=%p, realpath=\"%s\"@%p) ...",
         handle,
         si->get_realpath(),
         si);
  soinfo_unload(si);
  LD_LOG(kLogDlopen,
         "dlclose(handle=%p) ... done",
         handle);
  return 0;
}

// Make ns as the anonymous namespace that is a namespace used when
// we fail to determine the caller address (e.g., call from mono-jited code)
// Since there can be multiple anonymous namespace in a process, subsequent
// call to this function causes an error.
static bool set_anonymous_namespace(android_namespace_t* ns) {
  if (!g_anonymous_namespace_set && ns != nullptr) {
    CHECK(ns->is_also_used_as_anonymous());
    g_anonymous_namespace = ns;
    g_anonymous_namespace_set = true;
    return true;
  }
  return false;
}

// TODO(b/130388701) remove this. Currently, this is used only for testing
// where we don't have classloader namespace.
bool init_anonymous_namespace(const char* shared_lib_sonames, const char* library_search_path) {
  ProtectedDataGuard guard;

  // Test-only feature: we need to change the anonymous namespace multiple times
  // while the test is running.
  g_anonymous_namespace_set = false;

  // create anonymous namespace
  // When the caller is nullptr - create_namespace will take global group
  // from the anonymous namespace, which is fine because anonymous namespace
  // is still pointing to the default one.
  android_namespace_t* anon_ns =
      create_namespace(nullptr,
                       "(anonymous)",
                       nullptr,
                       library_search_path,
                       ANDROID_NAMESPACE_TYPE_ISOLATED |
                       ANDROID_NAMESPACE_TYPE_ALSO_USED_AS_ANONYMOUS,
                       nullptr,
                       &g_default_namespace);

  CHECK(anon_ns != nullptr);

  if (!link_namespaces(anon_ns, &g_default_namespace, shared_lib_sonames)) {
    // TODO: delete anon_ns
    return false;
  }

  return true;
}

static void add_soinfos_to_namespace(const soinfo_list_t& soinfos, android_namespace_t* ns) {
  ns->add_soinfos(soinfos);
  for (auto si : soinfos) {
    si->add_secondary_namespace(ns);
  }
}

std::vector<std::string> fix_lib_paths(std::vector<std::string> paths) {
  // For the bootstrap linker, insert /system/${LIB}/bootstrap in front of /system/${LIB} in any
  // namespace search path. The bootstrap linker should prefer to use the bootstrap bionic libraries
  // (e.g. libc.so).
#if !defined(__ANDROID_APEX__)
  for (size_t i = 0; i < paths.size(); ++i) {
    if (paths[i] == kSystemLibDir) {
      paths.insert(paths.begin() + i, std::string(kSystemLibDir) + "/bootstrap");
      ++i;
    }
  }
#endif
  return paths;
}

android_namespace_t* create_namespace(const void* caller_addr,
                                      const char* name,
                                      const char* ld_library_path,
                                      const char* default_library_path,
                                      uint64_t type,
                                      const char* permitted_when_isolated_path,
                                      android_namespace_t* parent_namespace) {
  if (parent_namespace == nullptr) {
    // if parent_namespace is nullptr -> set it to the caller namespace
    soinfo* caller_soinfo = find_containing_library(caller_addr);

    parent_namespace = caller_soinfo != nullptr ?
                       caller_soinfo->get_primary_namespace() :
                       g_anonymous_namespace;
  }

  ProtectedDataGuard guard;
  std::vector<std::string> ld_library_paths;
  std::vector<std::string> default_library_paths;
  std::vector<std::string> permitted_paths;

  parse_path(ld_library_path, ":", &ld_library_paths);
  parse_path(default_library_path, ":", &default_library_paths);
  parse_path(permitted_when_isolated_path, ":", &permitted_paths);

  android_namespace_t* ns = new (g_namespace_allocator.alloc()) android_namespace_t();
  ns->set_name(name);
  ns->set_isolated((type & ANDROID_NAMESPACE_TYPE_ISOLATED) != 0);
  ns->set_exempt_list_enabled((type & ANDROID_NAMESPACE_TYPE_EXEMPT_LIST_ENABLED) != 0);
  ns->set_also_used_as_anonymous((type & ANDROID_NAMESPACE_TYPE_ALSO_USED_AS_ANONYMOUS) != 0);

  if ((type & ANDROID_NAMESPACE_TYPE_SHARED) != 0) {
    // append parent namespace paths.
    std::copy(parent_namespace->get_ld_library_paths().begin(),
              parent_namespace->get_ld_library_paths().end(),
              back_inserter(ld_library_paths));

    std::copy(parent_namespace->get_default_library_paths().begin(),
              parent_namespace->get_default_library_paths().end(),
              back_inserter(default_library_paths));

    std::copy(parent_namespace->get_permitted_paths().begin(),
              parent_namespace->get_permitted_paths().end(),
              back_inserter(permitted_paths));

    // If shared - clone the parent namespace
    add_soinfos_to_namespace(parent_namespace->soinfo_list(), ns);
    // and copy parent namespace links
    for (auto& link : parent_namespace->linked_namespaces()) {
      ns->add_linked_namespace(link.linked_namespace(), link.shared_lib_sonames(),
                               link.allow_all_shared_libs());
    }
  } else {
    // If not shared - copy only the shared group
    add_soinfos_to_namespace(parent_namespace->get_shared_group(), ns);
  }

  ns->set_ld_library_paths(std::move(ld_library_paths));
  ns->set_default_library_paths(std::move(default_library_paths));
  ns->set_permitted_paths(std::move(permitted_paths));

  if (ns->is_also_used_as_anonymous() && !set_anonymous_namespace(ns)) {
    DL_ERR("failed to set namespace: [name=\"%s\", ld_library_path=\"%s\", default_library_paths=\"%s\""
           " permitted_paths=\"%s\"] as the anonymous namespace",
           ns->get_name(),
           android::base::Join(ns->get_ld_library_paths(), ':').c_str(),
           android::base::Join(ns->get_default_library_paths(), ':').c_str(),
           android::base::Join(ns->get_permitted_paths(), ':').c_str());
    return nullptr;
  }

  return ns;
}

bool link_namespaces(android_namespace_t* namespace_from,
                     android_namespace_t* namespace_to,
                     const char* shared_lib_sonames) {
  if (namespace_to == nullptr) {
    namespace_to = &g_default_namespace;
  }

  if (namespace_from == nullptr) {
    DL_ERR("error linking namespaces: namespace_from is null.");
    return false;
  }

  if (shared_lib_sonames == nullptr || shared_lib_sonames[0] == '\0') {
    DL_ERR("error linking namespaces \"%s\"->\"%s\": the list of shared libraries is empty.",
           namespace_from->get_name(), namespace_to->get_name());
    return false;
  }

  std::vector<std::string> sonames = android::base::Split(shared_lib_sonames, ":");
  std::unordered_set<std::string> sonames_set(std::make_move_iterator(sonames.begin()),
                                              std::make_move_iterator(sonames.end()));

  ProtectedDataGuard guard;
  namespace_from->add_linked_namespace(namespace_to, std::move(sonames_set), false);

  return true;
}

bool link_namespaces_all_libs(android_namespace_t* namespace_from,
                              android_namespace_t* namespace_to) {
  if (namespace_from == nullptr) {
    DL_ERR("error linking namespaces: namespace_from is null.");
    return false;
  }

  if (namespace_to == nullptr) {
    DL_ERR("error linking namespaces: namespace_to is null.");
    return false;
  }

  ProtectedDataGuard guard;
  namespace_from->add_linked_namespace(namespace_to, std::unordered_set<std::string>(), true);

  return true;
}

ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr) {
  if (g_is_ldd) return 0;

  ElfW(Addr) ifunc_addr = __bionic_call_ifunc_resolver(resolver_addr);
  LD_DEBUG(calls, "ifunc_resolver@%p returned %p",
           reinterpret_cast<void *>(resolver_addr), reinterpret_cast<void*>(ifunc_addr));

  return ifunc_addr;
}

const version_info* VersionTracker::get_version_info(ElfW(Versym) source_symver) const {
  if (source_symver < 2 ||
      source_symver >= version_infos.size() ||
      version_infos[source_symver].name == nullptr) {
    return nullptr;
  }

  return &version_infos[source_symver];
}

void VersionTracker::add_version_info(size_t source_index,
                                      ElfW(Word) elf_hash,
                                      const char* ver_name,
                                      const soinfo* target_si) {
  if (source_index >= version_infos.size()) {
    version_infos.resize(source_index+1);
  }

  version_infos[source_index].elf_hash = elf_hash;
  version_infos[source_index].name = ver_name;
  version_infos[source_index].target_si = target_si;
}

bool VersionTracker::init_verneed(const soinfo* si_from) {
  uintptr_t verneed_ptr = si_from->get_verneed_ptr();

  if (verneed_ptr == 0) {
    return true;
  }

  size_t verneed_cnt = si_from->get_verneed_cnt();

  for (size_t i = 0, offset = 0; i<verneed_cnt; ++i) {
    const ElfW(Verneed)* verneed = reinterpret_cast<ElfW(Verneed)*>(verneed_ptr + offset);
    size_t vernaux_offset = offset + verneed->vn_aux;
    offset += verneed->vn_next;

    if (verneed->vn_version != 1) {
      DL_ERR("unsupported verneed[%zd] vn_version: %d (expected 1)", i, verneed->vn_version);
      return false;
    }

    const char* target_soname = si_from->get_string(verneed->vn_file);
    // find it in dependencies
    soinfo* target_si = si_from->get_children().find_if(
        [&](const soinfo* si) { return strcmp(si->get_soname(), target_soname) == 0; });

    if (target_si == nullptr) {
      DL_ERR("cannot find \"%s\" from verneed[%zd] in DT_NEEDED list for \"%s\"",
          target_soname, i, si_from->get_realpath());
      return false;
    }

    for (size_t j = 0; j<verneed->vn_cnt; ++j) {
      const ElfW(Vernaux)* vernaux = reinterpret_cast<ElfW(Vernaux)*>(verneed_ptr + vernaux_offset);
      vernaux_offset += vernaux->vna_next;

      const ElfW(Word) elf_hash = vernaux->vna_hash;
      const char* ver_name = si_from->get_string(vernaux->vna_name);
      ElfW(Half) source_index = vernaux->vna_other;

      add_version_info(source_index, elf_hash, ver_name, target_si);
    }
  }

  return true;
}

template <typename F>
static bool for_each_verdef(const soinfo* si, F functor) {
  if (!si->has_min_version(2)) {
    return true;
  }

  uintptr_t verdef_ptr = si->get_verdef_ptr();
  if (verdef_ptr == 0) {
    return true;
  }

  size_t offset = 0;

  size_t verdef_cnt = si->get_verdef_cnt();
  for (size_t i = 0; i<verdef_cnt; ++i) {
    const ElfW(Verdef)* verdef = reinterpret_cast<ElfW(Verdef)*>(verdef_ptr + offset);
    size_t verdaux_offset = offset + verdef->vd_aux;
    offset += verdef->vd_next;

    if (verdef->vd_version != 1) {
      DL_ERR("unsupported verdef[%zd] vd_version: %d (expected 1) library: %s",
          i, verdef->vd_version, si->get_realpath());
      return false;
    }

    if ((verdef->vd_flags & VER_FLG_BASE) != 0) {
      // "this is the version of the file itself.  It must not be used for
      //  matching a symbol. It can be used to match references."
      //
      // http://www.akkadia.org/drepper/symbol-versioning
      continue;
    }

    if (verdef->vd_cnt == 0) {
      DL_ERR("invalid verdef[%zd] vd_cnt == 0 (version without a name)", i);
      return false;
    }

    const ElfW(Verdaux)* verdaux = reinterpret_cast<ElfW(Verdaux)*>(verdef_ptr + verdaux_offset);

    if (functor(i, verdef, verdaux) == true) {
      break;
    }
  }

  return true;
}

ElfW(Versym) find_verdef_version_index(const soinfo* si, const version_info* vi) {
  if (vi == nullptr) {
    return kVersymNotNeeded;
  }

  ElfW(Versym) result = kVersymGlobal;

  if (!for_each_verdef(si,
    [&](size_t, const ElfW(Verdef)* verdef, const ElfW(Verdaux)* verdaux) {
      if (verdef->vd_hash == vi->elf_hash &&
          strcmp(vi->name, si->get_string(verdaux->vda_name)) == 0) {
        result = verdef->vd_ndx;
        return true;
      }

      return false;
    }
  )) {
    // verdef should have already been validated in prelink_image.
    async_safe_fatal("invalid verdef after prelinking: %s, %s",
                     si->get_realpath(), linker_get_error_buffer());
  }

  return result;
}

// Validate the library's verdef section. On error, returns false and invokes DL_ERR.
bool validate_verdef_section(const soinfo* si) {
  return for_each_verdef(si,
    [&](size_t, const ElfW(Verdef)*, const ElfW(Verdaux)*) {
      return false;
    });
}

bool VersionTracker::init_verdef(const soinfo* si_from) {
  return for_each_verdef(si_from,
    [&](size_t, const ElfW(Verdef)* verdef, const ElfW(Verdaux)* verdaux) {
      add_version_info(verdef->vd_ndx, verdef->vd_hash,
          si_from->get_string(verdaux->vda_name), si_from);
      return false;
    }
  );
}

bool VersionTracker::init(const soinfo* si_from) {
  if (!si_from->has_min_version(2)) {
    return true;
  }

  return init_verneed(si_from) && init_verdef(si_from);
}

// TODO (dimitry): Methods below need to be moved out of soinfo
// and in more isolated file in order minimize dependencies on
// unnecessary object in the linker binary. Consider making them
// independent from soinfo (?).
bool soinfo::lookup_version_info(const VersionTracker& version_tracker, ElfW(Word) sym,
                                 const char* sym_name, const version_info** vi) {
  const ElfW(Versym)* sym_ver_ptr = get_versym(sym);
  ElfW(Versym) sym_ver = sym_ver_ptr == nullptr ? 0 : *sym_ver_ptr;

  if (sym_ver != VER_NDX_LOCAL && sym_ver != VER_NDX_GLOBAL) {
    *vi = version_tracker.get_version_info(sym_ver);

    if (*vi == nullptr) {
      DL_ERR("cannot find verneed/verdef for version index=%d "
          "referenced by symbol \"%s\" at \"%s\"", sym_ver, sym_name, get_realpath());
      return false;
    }
  } else {
    // there is no version info
    *vi = nullptr;
  }

  return true;
}

static void apply_relr_reloc(ElfW(Addr) offset, ElfW(Addr) load_bias, bool has_memtag_globals) {
  ElfW(Addr) destination = offset + load_bias;
  if (!has_memtag_globals) {
    *reinterpret_cast<ElfW(Addr)*>(destination) += load_bias;
    return;
  }

  ElfW(Addr)* tagged_destination =
      reinterpret_cast<ElfW(Addr)*>(get_tagged_address(reinterpret_cast<void*>(destination)));
  ElfW(Addr) tagged_value = reinterpret_cast<ElfW(Addr)>(
      get_tagged_address(reinterpret_cast<void*>(*tagged_destination + load_bias)));
  *tagged_destination = tagged_value;
}

// Process relocations in SHT_RELR section (experimental).
// Details of the encoding are described in this post:
//   https://groups.google.com/d/msg/generic-abi/bX460iggiKg/Pi9aSwwABgAJ
bool relocate_relr(const ElfW(Relr) * begin, const ElfW(Relr) * end, ElfW(Addr) load_bias,
                   bool has_memtag_globals) {
  constexpr size_t wordsize = sizeof(ElfW(Addr));

  ElfW(Addr) base = 0;
  for (const ElfW(Relr)* current = begin; current < end; ++current) {
    ElfW(Relr) entry = *current;
    ElfW(Addr) offset;

    if ((entry&1) == 0) {
      // Even entry: encodes the offset for next relocation.
      offset = static_cast<ElfW(Addr)>(entry);
      apply_relr_reloc(offset, load_bias, has_memtag_globals);
      // Set base offset for subsequent bitmap entries.
      base = offset + wordsize;
      continue;
    }

    // Odd entry: encodes bitmap for relocations starting at base.
    offset = base;
    while (entry != 0) {
      entry >>= 1;
      if ((entry&1) != 0) {
        apply_relr_reloc(offset, load_bias, has_memtag_globals);
      }
      offset += wordsize;
    }

    // Advance base offset by 63 words for 64-bit platforms,
    // or 31 words for 32-bit platforms.
    base += (8*wordsize - 1) * wordsize;
  }
  return true;
}

// An empty list of soinfos
static soinfo_list_t g_empty_list;

bool soinfo::prelink_image(bool dlext_use_relro) {
  if (flags_ & FLAG_PRELINKED) return true;
  /* Extract dynamic section */
  ElfW(Word) dynamic_flags = 0;
  phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);

  /* We can't log anything until the linker is relocated */
  bool relocating_linker = (flags_ & FLAG_LINKER) != 0;
  if (!relocating_linker) {
    LD_DEBUG(any, "[ Linking \"%s\" ]", get_realpath());
    LD_DEBUG(any, "si->base = %p si->flags = 0x%08x", reinterpret_cast<void*>(base), flags_);
  }

  if (dynamic == nullptr) {
    if (!relocating_linker) {
      DL_ERR("missing PT_DYNAMIC in \"%s\"", get_realpath());
    }
    return false;
  } else {
    if (!relocating_linker) {
      LD_DEBUG(dynamic, "dynamic section @%p", dynamic);
    }
  }

#if defined(__arm__)
  (void) phdr_t
```