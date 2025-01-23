Response:
The user wants a summary of the functionality of the provided C++ source code file, which is a test suite for the dynamic linker (`dlfcn`) in Android's Bionic library.

Here's a plan to generate the summary:

1. **Identify the core purpose:** The file contains tests for the `dlfcn` API.
2. **Categorize the tests:** Group tests based on the `dlfcn` functions they target (e.g., `dlopen`, `dlsym`, `dladdr`, `dlclose`).
3. **Highlight specific scenarios tested:**  Note any interesting or edge cases the tests cover (e.g., opening executables, libraries with different hash tables, symbol versioning, thread-local storage, error handling).
4. **Mention Bionic-specific tests:**  Point out any tests that are specific to Android's Bionic implementation.
这个文件是 Android Bionic 库中 `dlfcn_test.cpp` 的一部分，它是一个针对动态链接器功能的集成测试套件。  主要功能是 **验证 `dlfcn` API 的各种功能和边界情况是否按预期工作**。

以下是该部分测试的功能归纳：

* **对已加载可执行文件的操作：**
    * 验证使用 `dlopen(nullptr, ...)` 获取的可执行文件句柄与使用可执行文件绝对路径 `dlopen` 获取的句柄是否相同（在 Bionic 上）。
    * 使用 `dladdr` 查找可执行文件内部符号的信息，包括符号名、地址和所在模块的基地址。

* **对共享库的操作：**
    * 使用绝对路径 `dlopen` 系统库 (`libc.so`)，并使用 `dladdr` 验证返回的路径是否是规范路径。
    * 测试打开只包含 GNU 哈希表或只包含 SysV 哈希表的共享库，并验证可以找到其中的符号。
    * 测试 `dlopen` 的错误标志，如传递无效的标志位。

* **使用 `RTLD_DEFAULT` 和 `RTLD_NEXT`：**
    * 验证 `dlsym` 与 `RTLD_DEFAULT` 和 `RTLD_NEXT` 一起使用时，对于已知和未知符号的行为。
    * 测试在已加载的库中使用 `RTLD_NEXT` 查找 `libc` 中的符号。

* **弱符号处理：**
    * 测试 `dlsym` 查找弱定义函数的情况。
    * 测试 `dlopen` 依赖于未定义的弱符号的库的情况。

* **符号链接处理：**
    * 测试使用符号链接路径 `dlopen` 共享库，并验证其行为与直接打开原始库相同。

* **构造函数中的 `dlopen`：**
    * 测试在共享库的构造函数中调用 `dlopen` 的情况 (主要针对 Bionic，因为 glibc 在这种情况下可能会崩溃)。

* **初始化和析构函数的调用顺序：**
    * 测试具有依赖关系的多个共享库的初始化和析构函数的调用顺序。

* **符号版本控制：**
    * 测试使用不同版本符号的共享库的加载。
    * 测试使用 `dlsym` 获取默认版本符号。
    * 测试使用 `dlvsym` 精确查找特定版本的符号 (在非 musl 环境下)。

* **`DT_RUNPATH` 处理：**
    * 测试使用 `DT_RUNPATH` 指定依赖库路径的共享库的加载。
    * 测试使用绝对路径加载具有 `DT_RUNPATH` 的库。

* **线程局部存储 (TLS) 的析构：**
    * 测试在线程局部变量析构函数执行完毕后和执行之前调用 `dlclose` 的行为。
    * 测试多个共享库共享 TLS 变量时 `dlclose` 的行为。

* **宏定义测试：**
    * 简单地检查一些 `RTLD_` 宏是否已定义。

* **Bionic 特有测试 (仅在 `__BIONIC__` 定义时)：**
    * **兼容性测试 (针对 arm 架构)：** 验证某些系统库是否包含兼容的哈希表和重定位表。
    * **非法 ELF 文件测试：** 测试 `dlopen` 对各种非法或格式错误的 ELF 文件的处理，例如：
        * 包含可写且可执行的加载段。
        * 段头表偏移未对齐。
        * 段头大小为零。
        * 段字符串表索引无效或为空。
        * 段头表为空或偏移为零。
        * 动态段头未找到。
        * 包含文本重定位。
        * 包含对本地 TLS 变量的意外引用。
    * **`DF_1_GLOBAL` 标志测试：** 测试使用 `DF_1_GLOBAL` 标志的库的加载。
    * **段间隙测试：** 测试加载具有内存段间隙的共享库，并验证 `dladdr` 和 `dl_unwind_find_exidx` 是否正常工作。

总的来说，这部分测试旨在全面覆盖 `dlfcn` API 的功能，并确保其在各种场景下（包括错误场景和边界情况）的正确性和稳定性，特别是在 Android 的 Bionic 环境中。

### 提示词
```
这是目录为bionic/tests/dlfcn_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
alpath[PATH_MAX];
  ASSERT_TRUE(realpath(info.dli_fname, dli_realpath) != nullptr);
  ASSERT_STREQ(executable_path.c_str(), dli_realpath);

  // The symbol name should be the symbol we looked up.
  ASSERT_STREQ(info.dli_sname, "DlSymTestFunction");

  // The address should be the exact address of the symbol.
  ASSERT_EQ(info.dli_saddr, sym);

  std::vector<map_record> maps;
  ASSERT_TRUE(Maps::parse_maps(&maps));

  void* base_address = nullptr;
  for (const map_record& rec : maps) {
    if (executable_path == rec.pathname) {
      base_address = reinterpret_cast<void*>(rec.addr_start);
      break;
    }
  }

  // The base address should be the address we were loaded at.
  ASSERT_EQ(info.dli_fbase, base_address);

  ASSERT_EQ(0, dlclose(self));
}

TEST(dlfcn, dlopen_executable_by_absolute_path) {
  void* handle1 = dlopen(nullptr, RTLD_NOW);
  ASSERT_TRUE(handle1 != nullptr) << dlerror();

  void* handle2 = dlopen(android::base::GetExecutablePath().c_str(), RTLD_NOW);
  ASSERT_TRUE(handle2 != nullptr) << dlerror();

#if defined(__BIONIC__)
  ASSERT_EQ(handle1, handle2);
#else
  GTEST_SKIP() << "Skipping ASSERT_EQ(handle1, handle2) for glibc: "
                  "it loads a separate copy of the main executable "
                  "on dlopen by absolute path";
#endif
}

#define ALTERNATE_PATH_TO_SYSTEM_LIB "/system/lib64/" ABI_STRING "/"
#if __has_feature(hwaddress_sanitizer)
#define PATH_TO_LIBC PATH_TO_SYSTEM_LIB "hwasan/libc.so"
#define PATH_TO_BOOTSTRAP_LIBC PATH_TO_SYSTEM_LIB "bootstrap/hwasan/libc.so"
#define ALTERNATE_PATH_TO_LIBC ALTERNATE_PATH_TO_SYSTEM_LIB "hwasan/libc.so"
#else
#define PATH_TO_LIBC PATH_TO_SYSTEM_LIB "libc.so"
#define PATH_TO_BOOTSTRAP_LIBC PATH_TO_SYSTEM_LIB "bootstrap/libc.so"
#define ALTERNATE_PATH_TO_LIBC ALTERNATE_PATH_TO_SYSTEM_LIB "libc.so"
#endif

TEST(dlfcn, dladdr_libc) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "glibc returns libc.so's ldconfig path, which is a symlink (not a realpath)";
#endif

  Dl_info info;
  void* addr = reinterpret_cast<void*>(puts);  // An arbitrary libc function.
  ASSERT_TRUE(dladdr(addr, &info) != 0);

  // Check if libc is in canonical path or in alternate path.
  const char* expected_path;
  if (strncmp(ALTERNATE_PATH_TO_SYSTEM_LIB,
              info.dli_fname,
              sizeof(ALTERNATE_PATH_TO_SYSTEM_LIB) - 1) == 0) {
    // Platform with emulated architecture.  Symlink on ARC++.
    expected_path = ALTERNATE_PATH_TO_LIBC;
  } else if (strncmp(PATH_TO_BOOTSTRAP_LIBC, info.dli_fname,
                     sizeof(PATH_TO_BOOTSTRAP_LIBC) - 1) == 0) {
    expected_path = PATH_TO_BOOTSTRAP_LIBC;
  } else {
    // /system/lib is symlink when this test is executed on host.
    expected_path = PATH_TO_LIBC;
  }
  char libc_realpath[PATH_MAX];
  ASSERT_TRUE(realpath(expected_path, libc_realpath) != nullptr) << strerror(errno);

  ASSERT_STREQ(libc_realpath, info.dli_fname);
  // TODO: add check for dfi_fbase
  ASSERT_STREQ("puts", info.dli_sname);
  ASSERT_EQ(addr, info.dli_saddr);
}

TEST(dlfcn, dladdr_invalid) {
  Dl_info info;

  dlerror(); // Clear any pending errors.

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  // No symbol corresponding to NULL.
  ASSERT_EQ(dladdr(nullptr, &info), 0); // Zero on error, non-zero on success.
  ASSERT_TRUE(dlerror() == nullptr); // dladdr(3) doesn't set dlerror(3).
#pragma clang diagnostic pop

  // No symbol corresponding to a stack address.
  ASSERT_EQ(dladdr(&info, &info), 0); // Zero on error, non-zero on success.
  ASSERT_TRUE(dlerror() == nullptr); // dladdr(3) doesn't set dlerror(3).
}

TEST(dlfcn, dlopen_library_with_only_gnu_hash) {
  dlerror(); // Clear any pending errors.
  void* handle = dlopen("libgnu-hash-table-library.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  auto guard = android::base::make_scope_guard([&]() { dlclose(handle); });
  void* sym = dlsym(handle, "getRandomNumber");
  ASSERT_TRUE(sym != nullptr) << dlerror();
  int (*fn)(void);
  fn = reinterpret_cast<int (*)(void)>(sym);
  EXPECT_EQ(4, fn());

  Dl_info dlinfo;
  ASSERT_TRUE(0 != dladdr(reinterpret_cast<void*>(fn), &dlinfo));

  ASSERT_TRUE(fn == dlinfo.dli_saddr);
  ASSERT_STREQ("getRandomNumber", dlinfo.dli_sname);
  ASSERT_SUBSTR("libgnu-hash-table-library.so", dlinfo.dli_fname);
}

TEST(dlfcn, dlopen_library_with_only_sysv_hash) {
  void* handle = dlopen("libsysv-hash-table-library.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  auto guard = android::base::make_scope_guard([&]() { dlclose(handle); });
  void* sym = dlsym(handle, "getRandomNumber");
  ASSERT_TRUE(sym != nullptr) << dlerror();
  int (*fn)(void);
  fn = reinterpret_cast<int (*)(void)>(sym);
  EXPECT_EQ(4, fn());

  Dl_info dlinfo;
  ASSERT_TRUE(0 != dladdr(reinterpret_cast<void*>(fn), &dlinfo));

  ASSERT_TRUE(fn == dlinfo.dli_saddr);
  ASSERT_STREQ("getRandomNumber", dlinfo.dli_sname);
  ASSERT_SUBSTR("libsysv-hash-table-library.so", dlinfo.dli_fname);
}

TEST(dlfcn, dlopen_bad_flags) {
  dlerror(); // Clear any pending errors.
  void* handle;

#if defined(__GLIBC__)
  // glibc was smart enough not to define RTLD_NOW as 0, so it can detect missing flags.
  handle = dlopen(nullptr, 0);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_SUBSTR("invalid", dlerror());
#endif

  handle = dlopen(nullptr, 0xffffffff);
  ASSERT_TRUE(handle == nullptr);
  ASSERT_SUBSTR("invalid", dlerror());

  // glibc actually allows you to choose both RTLD_NOW and RTLD_LAZY at the same time, and so do we.
  handle = dlopen(nullptr, RTLD_NOW|RTLD_LAZY);
  ASSERT_TRUE(handle != nullptr);
  ASSERT_SUBSTR(nullptr, dlerror());
}

TEST(dlfcn, rtld_default_unknown_symbol) {
  void* addr = dlsym(RTLD_DEFAULT, "ANY_UNKNOWN_SYMBOL_NAME");
  ASSERT_TRUE(addr == nullptr);
}

TEST(dlfcn, rtld_default_known_symbol) {
  void* addr = dlsym(RTLD_DEFAULT, "fopen");
  ASSERT_TRUE(addr != nullptr);
}

TEST(dlfcn, rtld_next_unknown_symbol) {
  void* addr = dlsym(RTLD_NEXT, "ANY_UNKNOWN_SYMBOL_NAME");
  ASSERT_TRUE(addr == nullptr);
}

TEST(dlfcn, rtld_next_known_symbol) {
  void* addr = dlsym(RTLD_NEXT, "fopen");
  ASSERT_TRUE(addr != nullptr);
}

// Check that RTLD_NEXT of a libc symbol works in dlopened library
TEST(dlfcn, rtld_next_from_library) {
  void* library_with_fclose = dlopen("libtest_check_rtld_next_from_library.so", RTLD_NOW | RTLD_GLOBAL);
  ASSERT_TRUE(library_with_fclose != nullptr) << dlerror();
  void* expected_addr = dlsym(RTLD_DEFAULT, "fclose");
  ASSERT_TRUE(expected_addr != nullptr) << dlerror();
  typedef void* (*get_libc_fclose_ptr_fn_t)();
  get_libc_fclose_ptr_fn_t get_libc_fclose_ptr =
      reinterpret_cast<get_libc_fclose_ptr_fn_t>(dlsym(library_with_fclose, "get_libc_fclose_ptr"));
  ASSERT_TRUE(get_libc_fclose_ptr != nullptr) << dlerror();
  ASSERT_EQ(expected_addr, get_libc_fclose_ptr());

  dlclose(library_with_fclose);
}


TEST(dlfcn, dlsym_weak_func) {
  dlerror();
  void* handle = dlopen("libtest_dlsym_weak_func.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr);

  int (*weak_func)();
  weak_func = reinterpret_cast<int (*)()>(dlsym(handle, "weak_func"));
  ASSERT_TRUE(weak_func != nullptr) << "dlerror: " << dlerror();
  EXPECT_EQ(42, weak_func());
  dlclose(handle);
}

TEST(dlfcn, dlopen_undefined_weak_func) {
  void* handle = dlopen("libtest_dlopen_weak_undefined_func.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  int (*weak_func)();
  weak_func = reinterpret_cast<int (*)()>(dlsym(handle, "use_weak_undefined_func"));
  ASSERT_TRUE(weak_func != nullptr) << dlerror();
  EXPECT_EQ(6551, weak_func());
  dlclose(handle);
}

TEST(dlfcn, dlopen_symlink) {
  DlfcnSymlink symlink("dlopen_symlink");
  const std::string symlink_name = android::base::Basename(symlink.get_symlink_path());
  void* handle1 = dlopen("libdlext_test.so", RTLD_NOW);
  void* handle2 = dlopen(symlink_name.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle1 != nullptr);
  ASSERT_TRUE(handle2 != nullptr);
  ASSERT_EQ(handle1, handle2);
  dlclose(handle1);
  dlclose(handle2);
}

// libtest_dlopen_from_ctor_main.so depends on
// libtest_dlopen_from_ctor.so which has a constructor
// that calls dlopen(libc...). This is to test the situation
// described in b/7941716.
TEST(dlfcn, dlopen_dlopen_from_ctor) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "glibc segfaults if you try to call dlopen from a constructor";
#endif

  void* handle = dlopen("libtest_dlopen_from_ctor_main.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  dlclose(handle);
}

static std::string g_fini_call_order_str;

static void register_fini_call(const char* s) {
  g_fini_call_order_str += s;
}

static void test_init_fini_call_order_for(const char* libname) {
  g_fini_call_order_str.clear();
  void* handle = dlopen(libname, RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*get_init_order_number_t)();
  get_init_order_number_t get_init_order_number =
          reinterpret_cast<get_init_order_number_t>(dlsym(handle, "get_init_order_number"));
  ASSERT_EQ(321, get_init_order_number());

  typedef void (*set_fini_callback_t)(void (*f)(const char*));
  set_fini_callback_t set_fini_callback =
          reinterpret_cast<set_fini_callback_t>(dlsym(handle, "set_fini_callback"));
  set_fini_callback(register_fini_call);
  dlclose(handle);
  ASSERT_EQ("(root)(child)(grandchild)", g_fini_call_order_str);
}

TEST(dlfcn, init_fini_call_order) {
  test_init_fini_call_order_for("libtest_init_fini_order_root.so");
  test_init_fini_call_order_for("libtest_init_fini_order_root2.so");
}

TEST(dlfcn, symbol_versioning_use_v1) {
  void* handle = dlopen("libtest_versioned_uselibv1.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*fn_t)();
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "get_function_version"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(1, fn());
  dlclose(handle);
}

TEST(dlfcn, symbol_versioning_use_v2) {
  void* handle = dlopen("libtest_versioned_uselibv2.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*fn_t)();
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "get_function_version"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(2, fn());
  dlclose(handle);
}

TEST(dlfcn, symbol_versioning_use_other_v2) {
  void* handle = dlopen("libtest_versioned_uselibv2_other.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*fn_t)();
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "get_function_version"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(20, fn());
  dlclose(handle);
}

TEST(dlfcn, symbol_versioning_use_other_v3) {
  void* handle = dlopen("libtest_versioned_uselibv3_other.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*fn_t)();
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "get_function_version"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(3, fn());
  dlclose(handle);
}

TEST(dlfcn, symbol_versioning_default_via_dlsym) {
  void* handle = dlopen("libtest_versioned_lib.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*fn_t)();
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "versioned_function"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(3, fn()); // the default version is 3
  dlclose(handle);
}

TEST(dlfcn, dlvsym_smoke) {
#if !defined(ANDROID_HOST_MUSL)
  void* handle = dlopen("libtest_versioned_lib.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*fn_t)();

  {
    fn_t fn = reinterpret_cast<fn_t>(dlvsym(handle, "versioned_function", "nonversion"));
    ASSERT_TRUE(fn == nullptr);
    ASSERT_SUBSTR("undefined symbol: versioned_function, version nonversion", dlerror());
  }

  {
    fn_t fn = reinterpret_cast<fn_t>(dlvsym(handle, "versioned_function", "TESTLIB_V2"));
    ASSERT_TRUE(fn != nullptr) << dlerror();
    ASSERT_EQ(2, fn());
  }

  dlclose(handle);
#else
  GTEST_SKIP() << "musl doesn't have dlvsym";
#endif
}

// This preempts the implementation from libtest_versioned_lib.so
extern "C" int version_zero_function() {
  return 0;
}

// This preempts the implementation from libtest_versioned_uselibv*.so
extern "C" int version_zero_function2() {
  return 0;
}

TEST(dlfcn, dt_runpath_smoke) {
  void* handle = dlopen("libtest_dt_runpath_d.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef void *(* dlopen_b_fn)();
  dlopen_b_fn fn = (dlopen_b_fn)dlsym(handle, "dlopen_b");
  ASSERT_TRUE(fn != nullptr) << dlerror();

  void *p = fn();
  ASSERT_TRUE(p != nullptr);

  dlclose(handle);
}

TEST(dlfcn, dt_runpath_absolute_path) {
  std::string libpath = GetTestLibRoot() + "/libtest_dt_runpath_d.so";
  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef void *(* dlopen_b_fn)();
  dlopen_b_fn fn = (dlopen_b_fn)dlsym(handle, "dlopen_b");
  ASSERT_TRUE(fn != nullptr) << dlerror();

  void *p = fn();
  ASSERT_TRUE(p != nullptr);

  dlclose(handle);
}

static void test_dlclose_after_thread_local_dtor(const char* library_name) {
  bool is_dtor_triggered = false;

  auto f = [](void* handle, bool* is_dtor_triggered) {
    typedef void (*fn_t)(bool*);
    fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "init_thread_local_variable"));
    ASSERT_TRUE(fn != nullptr) << dlerror();

    fn(is_dtor_triggered);

    ASSERT_TRUE(!*is_dtor_triggered);
  };

  void* handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);

  handle = dlopen(library_name, RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  std::thread t(f, handle, &is_dtor_triggered);
  t.join();

  ASSERT_TRUE(is_dtor_triggered);
  dlclose(handle);

  handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
}

TEST(dlfcn, dlclose_after_thread_local_dtor) {
  test_dlclose_after_thread_local_dtor("libtest_thread_local_dtor.so");
}

TEST(dlfcn, dlclose_after_thread_local_dtor_indirect) {
  test_dlclose_after_thread_local_dtor("libtest_indirect_thread_local_dtor.so");
}

static void test_dlclose_before_thread_local_dtor(const char* library_name) {
  bool is_dtor_triggered = false;

  auto f = [library_name](bool* is_dtor_triggered) {
    void* handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
    ASSERT_TRUE(handle == nullptr);

    handle = dlopen(library_name, RTLD_NOW);
    ASSERT_TRUE(handle != nullptr) << dlerror();

    typedef void (*fn_t)(bool*);
    fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "init_thread_local_variable"));
    ASSERT_TRUE(fn != nullptr) << dlerror();

    fn(is_dtor_triggered);

    dlclose(handle);

    ASSERT_TRUE(!*is_dtor_triggered);

    // Since we have thread_atexit dtors associated with handle - the library should
    // still be availabe.
    handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
    ASSERT_TRUE(handle != nullptr) << dlerror();
    dlclose(handle);
  };

  void* handle = dlopen(library_name, RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  dlclose(handle);

  handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);

  std::thread t(f, &is_dtor_triggered);
  t.join();
#if defined(__BIONIC__)
  // ld-android.so unloads unreferenced libraries on pthread_exit()
  ASSERT_TRUE(is_dtor_triggered);
  handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
#else
  // GLIBC does not unload libraries with ref_count = 0 on pthread_exit
  ASSERT_TRUE(is_dtor_triggered);
  handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle != nullptr) << dlerror();
#endif
}

TEST(dlfcn, dlclose_before_thread_local_dtor) {
  test_dlclose_before_thread_local_dtor("libtest_thread_local_dtor.so");
}

TEST(dlfcn, dlclose_before_thread_local_dtor_indirect) {
  test_dlclose_before_thread_local_dtor("libtest_indirect_thread_local_dtor.so");
}

TEST(dlfcn, dlclose_before_thread_local_dtor_multiple_dsos) {
  const constexpr char* library_name = "libtest_indirect_thread_local_dtor.so";

  bool is_dtor1_triggered = false;
  bool is_dtor2_triggered = false;

  std::mutex mtx;
  std::condition_variable cv;
  void* library_handle = nullptr;
  bool thread1_dlopen_complete = false;
  bool thread2_thread_local_dtor_initialized = false;
  bool thread1_complete = false;

  auto f1 = [&]() {
    void* handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
    ASSERT_TRUE(handle == nullptr);

    handle = dlopen(library_name, RTLD_NOW);
    ASSERT_TRUE(handle != nullptr) << dlerror();
    std::unique_lock<std::mutex> lock(mtx);
    thread1_dlopen_complete = true;
    library_handle = handle;
    lock.unlock();
    cv.notify_one();

    typedef void (*fn_t)(bool*);
    fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "init_thread_local_variable"));
    ASSERT_TRUE(fn != nullptr) << dlerror();

    fn(&is_dtor1_triggered);

    lock.lock();
    cv.wait(lock, [&] { return thread2_thread_local_dtor_initialized; });
    lock.unlock();

    dlclose(handle);

    ASSERT_TRUE(!is_dtor1_triggered);

    // Since we have thread_atexit dtors associated with handle - the library should
    // still be availabe.
    handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
    ASSERT_TRUE(handle != nullptr) << dlerror();
    dlclose(handle);
  };

  auto f2 = [&]() {
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [&] { return thread1_dlopen_complete; });
    void* handle = library_handle;
    lock.unlock();

    typedef void (*fn_t)(bool*);
    fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "init_thread_local_variable2"));
    ASSERT_TRUE(fn != nullptr) << dlerror();

    fn(&is_dtor2_triggered);

    lock.lock();
    thread2_thread_local_dtor_initialized = true;
    lock.unlock();
    cv.notify_one();

    lock.lock();
    cv.wait(lock, [&] { return thread1_complete; });
    lock.unlock();

    ASSERT_TRUE(!is_dtor2_triggered);
  };

  void* handle = dlopen(library_name, RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  dlclose(handle);

  handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);

  std::thread t1(f1);
  std::thread t2(f2);
  t1.join();
  ASSERT_TRUE(is_dtor1_triggered);
  ASSERT_TRUE(!is_dtor2_triggered);

  handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  dlclose(handle);

  std::unique_lock<std::mutex> lock(mtx);
  thread1_complete = true;
  lock.unlock();
  cv.notify_one();

  t2.join();
  ASSERT_TRUE(is_dtor2_triggered);

#if defined(__BIONIC__)
  // ld-android.so unloads unreferenced libraries on pthread_exit()
  handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
#else
  // GLIBC does not unload libraries with ref_count = 0 on pthread_exit
  handle = dlopen(library_name, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle != nullptr) << dlerror();
#endif
}

TEST(dlfcn, RTLD_macros) {
#if !defined(RTLD_LOCAL)
#error no RTLD_LOCAL
#elif !defined(RTLD_LAZY)
#error no RTLD_LAZY
#elif !defined(RTLD_NOW)
#error no RTLD_NOW
#elif !defined(RTLD_NOLOAD)
#error no RTLD_NOLOAD
#elif !defined(RTLD_GLOBAL)
#error no RTLD_GLOBAL
#elif !defined(RTLD_NODELETE)
#error no RTLD_NODELETE
#endif
}

// Bionic specific tests
#if defined(__BIONIC__)

#if defined(__arm__)

void validate_compatibility_of_native_library(const std::string& soname, const std::string& path) {
  // Grab the dynamic section in text form...
  ExecTestHelper eth;
  eth.SetArgs({"readelf", "-dW", path.c_str(), nullptr});
  eth.Run([&]() { execvpe("readelf", eth.GetArgs(), eth.GetEnv()); }, 0, nullptr);
  std::string output = eth.GetOutput();

  // Check that there *is* a legacy DT_HASH (not just a GNU hash)...
  ASSERT_TRUE(std::regex_search(output, std::regex("\\(HASH\\)"))) << output;
  // Check that there is no DT_ANDROID_REL or DT_ANDROID_RELA...
  ASSERT_FALSE(std::regex_search(output, std::regex("\\(ANDROID_REL\\)"))) << output;
  ASSERT_FALSE(std::regex_search(output, std::regex("\\(ANDROID_RELA\\)"))) << output;

  // Check that we have regular non-packed relocations.
  // libdl.so is simple enough that it doesn't have any relocations.
  ASSERT_TRUE(std::regex_search(output, std::regex("\\(RELA?\\)")) || soname == "libdl.so")
      << output;
}

void validate_compatibility_of_native_library(const std::string& soname) {
  // On the systems with emulation system libraries would be of different
  // architecture.  Try to use alternate paths first.
  std::string path = std::string(ALTERNATE_PATH_TO_SYSTEM_LIB) + soname;
  if (access(path.c_str(), R_OK) != 0) {
    path = std::string(PATH_TO_SYSTEM_LIB) + soname;
    ASSERT_EQ(0, access(path.c_str(), R_OK));
  }
  validate_compatibility_of_native_library(soname, path);
}

// This is a test for app compatibility workaround for arm apps
// affected by http://b/24465209
TEST(dlext, compat_elf_hash_and_relocation_tables) {
  validate_compatibility_of_native_library("libc.so");
  validate_compatibility_of_native_library("liblog.so");
  validate_compatibility_of_native_library("libstdc++.so");
  validate_compatibility_of_native_library("libdl.so");
  validate_compatibility_of_native_library("libm.so");
  validate_compatibility_of_native_library("libz.so");
  validate_compatibility_of_native_library("libjnigraphics.so");
}

#endif //  defined(__arm__)

TEST(dlfcn, dlopen_invalid_rw_load_segment) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-rw_load_segment.so";
  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\": W+E load segments are not allowed";
  ASSERT_STREQ(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_unaligned_shdr_offset) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-unaligned_shdr_offset.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" has invalid shdr offset/size: ";
  ASSERT_SUBSTR(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_zero_shentsize) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-zero_shentsize.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" has unsupported e_shentsize: 0x0 (expected 0x";
  ASSERT_SUBSTR(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_zero_shstrndx) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-zero_shstrndx.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" has invalid e_shstrndx";
  ASSERT_STREQ(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_empty_shdr_table) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-empty_shdr_table.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" has no section headers";
  ASSERT_STREQ(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_zero_shdr_table_offset) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-zero_shdr_table_offset.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" has invalid shdr offset/size: 0/";
  ASSERT_SUBSTR(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_zero_shdr_table_content) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-zero_shdr_table_content.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" .dynamic section header was not found";
  ASSERT_SUBSTR(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_textrels) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-textrels.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" has text relocations";
  ASSERT_SUBSTR(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_textrels2) {
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-textrels2.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  std::string expected_dlerror = std::string("dlopen failed: \"") + libpath + "\" has text relocations";
  ASSERT_SUBSTR(expected_dlerror.c_str(), dlerror());
}

TEST(dlfcn, dlopen_invalid_local_tls) {
#if defined(__riscv)
  // This is a test for bad gold behavior, and gold doesn't support riscv64.
#else
  const std::string libpath = GetPrebuiltElfDir() + "/libtest_invalid-local-tls.so";

  void* handle = dlopen(libpath.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
#if defined(__arm__)
  const char* referent = "local section";
#else
  const char* referent = "local symbol \"tls_var_2\"";
#endif
  std::string expected_dlerror = std::string("dlopen failed: unexpected TLS reference to ") +
                                 referent + " in \"" + libpath + "\"";
  ASSERT_SUBSTR(expected_dlerror.c_str(), dlerror());
#endif
}

TEST(dlfcn, dlopen_df_1_global) {
  void* handle = dlopen("libtest_dlopen_df_1_global.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
}

TEST(dlfcn, segment_gap) {
  void* handle = dlopen("libsegment_gap_outer.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  auto get_inner = reinterpret_cast<void* (*)()>(dlsym(handle, "get_inner"));
  void* inner = get_inner();
  (void)inner;

#if __arm__
  int count;
  _Unwind_Ptr outer_exidx = dl_unwind_find_exidx(reinterpret_cast<_Unwind_Ptr>(get_inner), &count);
  _Unwind_Ptr inner_exidx = dl_unwind_find_exidx(reinterpret_cast<_Unwind_Ptr>(inner), &count);
  EXPECT_NE(0u, outer_exidx);
  EXPECT_NE(0u, inner_exidx);
  EXPECT_NE(inner_exidx, outer_exidx);
#endif

  Dl_info info;
  int rc = dladdr(inner, &info);
  ASSERT_NE(rc, 0);

  EXPECT_NE(nullptr, strstr(info.dli_fname, "libsegment_gap_inner.so"));
}

#endif
```