Response:
My thought process for summarizing the provided C++ code snippet goes like this:

1. **Identify the Core Purpose:** The file path `bionic/tests/dlfcn_test.cpp` and the included header `<dlfcn.h>` immediately tell me this file is a test suite for the `dlfcn` functionality within Android's Bionic library. `dlfcn` is about dynamic linking, so the tests will likely involve loading, finding symbols in, and unloading shared libraries.

2. **Scan for Test Structure:**  The code uses Google Test (`gtest`). I look for `TEST(dlfcn, ...)` macros to quickly identify individual test cases. This gives me a high-level overview of the features being tested.

3. **Group Related Tests:**  I start grouping the tests based on the `dlfcn` functions they seem to be exercising. For example:
    * Tests involving `dlopen`: `ctor_function_call`, `dlsym_in_executable`, `dlsym_from_sofile`, `dlsym_from_sofile_with_preload`, `dlsym_handle_global_sym`, `dlsym_handle_empty_symbol`, `dlsym_with_dependencies`, `dlopen_noload`, `dlopen_by_soname`, `dlopen_vdso`, `dlopen_check_relocation_dt_needed_order`, etc. I notice many variations of `dlopen` tests, focusing on different flags (`RTLD_NOW`, `RTLD_LAZY`, `RTLD_LOCAL`, `RTLD_GLOBAL`, `RTLD_NOLOAD`, `RTLD_NODELETE`), scenarios (with/without preloading, with dependencies, with loops), and expected outcomes (success, failure).
    * Tests involving `dlsym`:  These are often coupled with `dlopen` as you need to load a library before finding symbols in it. I look for `dlsym(...)` calls and what they are trying to achieve (finding symbols in the executable, in SO files, with specific handles, handling empty symbols, interaction with preloading). The "ifunc" tests form a distinct subgroup related to `dlsym`.
    * Tests involving `dlclose`:  These check the unloading behavior and interactions with other flags like `RTLD_NODELETE`.
    * Tests involving `dlerror`: These focus on the error reporting mechanism, including concurrent access scenarios.
    * Tests involving `dladdr`: This is a separate function for getting information about symbols.

4. **Identify Key Concepts Being Tested:** Beyond the specific `dlfcn` functions, I look for recurring themes and concepts:
    * **Symbol visibility and scope:**  The tests with `RTLD_LOCAL` and `RTLD_GLOBAL` are clearly about how symbols are visible across different loaded libraries. The preloading tests also touch upon this.
    * **Lazy vs. Immediate loading:** The `RTLD_LAZY` and `RTLD_NOW` flags are explicitly tested.
    * **Dependency resolution:** Tests involving `DT_NEEDED` libraries and the order of loading/linking are important. The loop dependency test is a specific case here.
    * **IFuncs:**  A set of tests specifically addresses Indirect Functions, a dynamic linking optimization.
    * **Constructor functions:** The `ctor_function_call` test checks that constructors in shared libraries are executed correctly.
    * **Error handling:** The `dlerror` tests are dedicated to this.
    * **Relocations:** Several tests with "reloc" in their names are verifying the correctness of relocation, especially in complex dependency scenarios.
    * **VDSO:** A test specifically covers loading the Virtual Dynamic Shared Object.

5. **Synthesize the Summary:** I then synthesize a summary by combining the identified functions and concepts. I try to structure it logically, starting with the core purpose and then elaborating on the specific areas covered by the tests. I use clear and concise language, avoiding overly technical jargon where possible while still accurately reflecting the code's functionality. I focus on the *what* and *why* of the tests, rather than getting bogged down in the *how* (the specific assertions and test setups).

6. **Refine and Organize:** Finally, I review the summary for clarity, completeness, and organization. I ensure that the key features and functionalities being tested are accurately represented. I might reorder points or rephrase sentences for better flow. I also make sure to explicitly mention the use of Google Test.

By following these steps, I can effectively analyze the C++ test code and produce a comprehensive summary of its functionalities. The key is to start with the high-level purpose and gradually drill down into the specifics while keeping the overall goal of the code (testing `dlfcn`) in mind.
这是对 Android Bionic 库中 `dlfcn_test.cpp` 文件内容的归纳总结。该文件主要包含了一系列使用 Google Test 框架编写的单元测试，用于验证 Bionic 库中动态链接器 (`dlfcn.h`) 的各种功能。

**功能归纳:**

这个测试文件旨在全面测试 Android Bionic 库提供的动态链接功能，主要覆盖以下方面：

1. **`dlopen()` 函数的功能测试:**
    * **加载可执行文件自身:** 测试 `dlopen(nullptr, RTLD_NOW)` 是否能成功获取当前可执行文件的句柄。
    * **加载共享对象 (.so 文件):**  测试 `dlopen()` 加载不同类型的共享库，包括：
        * 通过文件名加载。
        * 通过 `soname` 加载。
        * 使用 `RTLD_LAZY` 和 `RTLD_NOW` 标志进行加载。
        * 使用 `RTLD_LOCAL` 和 `RTLD_GLOBAL` 标志控制符号的可见性。
        * 使用 `RTLD_NOLOAD` 标志检查库是否已经加载。
        * 使用 `RTLD_NODELETE` 标志控制库卸载行为。
        * 加载包含循环依赖的库。
        * 加载 VDSO (Virtual Dynamic Shared Object)。
    * **加载失败场景:** 测试 `dlopen()` 在找不到库文件时的错误处理。

2. **`dlsym()` 函数的功能测试:**
    * **查找符号:** 测试 `dlsym()` 在不同加载场景下查找符号的能力，包括：
        * 在可执行文件中查找符号。
        * 在已加载的共享库中查找符号。
        * 使用 `RTLD_DEFAULT` 和特定的库句柄进行查找。
        * 查找依赖库中的符号。
        * 查找预加载库中的符号。
        * 查找具有 `DF_1_GLOBAL` 标志的符号。
    * **查找失败场景:** 测试 `dlsym()` 在找不到符号或传入空符号名时的错误处理。

3. **`dlclose()` 函数的功能测试:**
    * **卸载库:** 测试 `dlclose()` 是否能正确卸载已加载的共享库。
    * **与 `RTLD_NODELETE` 的交互:** 验证使用 `RTLD_NODELETE` 加载的库在 `dlclose()` 后不会被立即卸载。

4. **`dlerror()` 函数的功能测试:**
    * **获取错误信息:** 测试 `dlerror()` 能否返回最近的动态链接错误信息。
    * **线程安全性:** 测试在多线程环境下并发调用 `dlerror()` 是否能正确返回各自线程的错误信息。

5. **`dladdr()` 函数的功能测试:**
    * **获取符号信息:** 测试 `dladdr()` 能否根据给定的地址返回符号的相关信息，例如符号名、库文件名等。

6. **构造函数 (`constructor`) 的调用测试:**
    * 验证共享库中的 `__attribute__ ((constructor))` 修饰的函数是否在库加载时被调用。

7. **IFunc (Indirect Function) 的功能测试:**
    * **IFunc 解析:** 测试动态链接器能否正确解析 IFunc 符号，并根据环境变量等条件选择正确的实现。
    * **IFunc 和构造函数:** 测试 IFunc 相关的构造函数是否被正确调用，以及加载方式 (RTLD_LAZY, RTLD_NOW) 对其调用的影响。

8. **库加载顺序和依赖关系测试:**
    * **`DT_NEEDED` 顺序:** 测试链接器是否按照 `DT_NEEDED` 段中指定的顺序加载依赖库，并确保符号解析的正确性。
    * **加载顺序对符号解析的影响:** 测试在复杂的依赖关系图中，不同库中同名符号的解析顺序。
    * **预加载库的影响:** 测试预加载库对符号解析的影响。

9. **重定位 (Relocation) 的测试:**
    * **跨库重定位:** 测试共享库之间函数调用的重定位是否正确。
    * **与可执行文件重定位:** 测试共享库调用可执行文件中定义的符号是否正确。
    * **卸载后重定位的影响:** 测试卸载一个库后，依赖它的库是否还能正常工作 (在 `RTLD_NODELETE` 的情况下)。

总而言之，`dlfcn_test.cpp` 是一个详尽的动态链接功能测试套件，它涵盖了 `dlfcn.h` 中核心函数的各种使用场景和边界情况，旨在确保 Android 系统中动态链接机制的稳定性和正确性。它通过各种断言 (`ASSERT_TRUE`, `ASSERT_EQ`, `ASSERT_SUBSTR` 等) 来验证动态链接操作的预期结果。

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
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <dlfcn.h>
#include <elf.h>
#include <limits.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>
#if __has_include(<sys/auxv.h>)
#include <sys/auxv.h>
#endif
#include <sys/user.h>

#include <string>
#include <thread>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/scopeguard.h>

#include "gtest_globals.h"
#include "gtest_utils.h"
#include "dlfcn_symlink_support.h"
#include "utils.h"

#define ASSERT_SUBSTR(needle, haystack) \
    ASSERT_PRED_FORMAT2(::testing::IsSubstring, needle, haystack)


static bool g_called = false;
extern "C" void DlSymTestFunction() {
  g_called = true;
}

static int g_ctor_function_called = 0;
static int g_ctor_argc = 0;
static char** g_ctor_argv = reinterpret_cast<char**>(0xDEADBEEF);
static char** g_ctor_envp = g_ctor_envp;

extern "C" void ctor_function(int argc, char** argv, char** envp) __attribute__ ((constructor));

extern "C" void ctor_function(int argc, char** argv, char** envp) {
  g_ctor_function_called = 17;
  g_ctor_argc = argc;
  g_ctor_argv = argv;
  g_ctor_envp = envp;
}

TEST(dlfcn, ctor_function_call) {
  ASSERT_EQ(17, g_ctor_function_called);
  ASSERT_TRUE(g_ctor_argc = GetArgc());
  ASSERT_TRUE(g_ctor_argv = GetArgv());
  ASSERT_TRUE(g_ctor_envp = GetEnvp());
}

TEST(dlfcn, dlsym_in_executable) {
  dlerror(); // Clear any pending errors.
  void* self = dlopen(nullptr, RTLD_NOW);
  ASSERT_TRUE(self != nullptr);
  ASSERT_TRUE(dlerror() == nullptr);

  void* sym = dlsym(self, "DlSymTestFunction");
  ASSERT_TRUE(sym != nullptr);

  void (*function)() = reinterpret_cast<void(*)()>(sym);

  g_called = false;
  function();
  ASSERT_TRUE(g_called);

  ASSERT_EQ(0, dlclose(self));
}

TEST(dlfcn, dlsym_from_sofile) {
  void* handle = dlopen("libtest_dlsym_from_this.so", RTLD_LAZY | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  // check that we can't find '_test_dlsym_symbol' via dlsym(RTLD_DEFAULT)
  void* symbol = dlsym(RTLD_DEFAULT, "test_dlsym_symbol");
  ASSERT_TRUE(symbol == nullptr);
  ASSERT_SUBSTR("undefined symbol: test_dlsym_symbol", dlerror());

  typedef int* (*fn_t)();
  fn_t lookup_dlsym_symbol_using_RTLD_DEFAULT =
      reinterpret_cast<fn_t>(dlsym(handle, "lookup_dlsym_symbol_using_RTLD_DEFAULT"));
  ASSERT_TRUE(lookup_dlsym_symbol_using_RTLD_DEFAULT != nullptr) << dlerror();

  int* ptr = lookup_dlsym_symbol_using_RTLD_DEFAULT();
  ASSERT_TRUE(ptr != nullptr) << dlerror();
  ASSERT_EQ(42, *ptr);

  fn_t lookup_dlsym_symbol2_using_RTLD_DEFAULT =
      reinterpret_cast<fn_t>(dlsym(handle, "lookup_dlsym_symbol2_using_RTLD_DEFAULT"));
  ASSERT_TRUE(lookup_dlsym_symbol2_using_RTLD_DEFAULT != nullptr) << dlerror();

  ptr = lookup_dlsym_symbol2_using_RTLD_DEFAULT();
  ASSERT_TRUE(ptr != nullptr) << dlerror();
  ASSERT_EQ(44, *ptr);

  fn_t lookup_dlsym_symbol_using_RTLD_NEXT =
      reinterpret_cast<fn_t>(dlsym(handle, "lookup_dlsym_symbol_using_RTLD_NEXT"));
  ASSERT_TRUE(lookup_dlsym_symbol_using_RTLD_NEXT != nullptr) << dlerror();

  ptr = lookup_dlsym_symbol_using_RTLD_NEXT();
  ASSERT_TRUE(ptr != nullptr) << dlerror();
  ASSERT_EQ(43, *ptr);

  dlclose(handle);
}

TEST(dlfcn, dlsym_from_sofile_with_preload) {
  void* preload = dlopen("libtest_dlsym_from_this_grandchild.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(preload != nullptr) << dlerror();

  void* handle = dlopen("libtest_dlsym_from_this.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  // check that we can't find '_test_dlsym_symbol' via dlsym(RTLD_DEFAULT)
  void* symbol = dlsym(RTLD_DEFAULT, "test_dlsym_symbol");
  ASSERT_TRUE(symbol == nullptr);
  ASSERT_SUBSTR("undefined symbol: test_dlsym_symbol", dlerror());

  typedef int* (*fn_t)();
  fn_t lookup_dlsym_symbol_using_RTLD_DEFAULT =
      reinterpret_cast<fn_t>(dlsym(handle, "lookup_dlsym_symbol_using_RTLD_DEFAULT"));
  ASSERT_TRUE(lookup_dlsym_symbol_using_RTLD_DEFAULT != nullptr) << dlerror();

  int* ptr = lookup_dlsym_symbol_using_RTLD_DEFAULT();
  ASSERT_TRUE(ptr != nullptr) << dlerror();
  ASSERT_EQ(42, *ptr);

  fn_t lookup_dlsym_symbol2_using_RTLD_DEFAULT =
      reinterpret_cast<fn_t>(dlsym(handle, "lookup_dlsym_symbol2_using_RTLD_DEFAULT"));
  ASSERT_TRUE(lookup_dlsym_symbol2_using_RTLD_DEFAULT != nullptr) << dlerror();

  ptr = lookup_dlsym_symbol2_using_RTLD_DEFAULT();
  ASSERT_TRUE(ptr != nullptr) << dlerror();
  ASSERT_EQ(44, *ptr);

  fn_t lookup_dlsym_symbol_using_RTLD_NEXT =
      reinterpret_cast<fn_t>(dlsym(handle, "lookup_dlsym_symbol_using_RTLD_NEXT"));
  ASSERT_TRUE(lookup_dlsym_symbol_using_RTLD_NEXT != nullptr) << dlerror();

  ptr = lookup_dlsym_symbol_using_RTLD_NEXT();
  ASSERT_TRUE(ptr != nullptr) << dlerror();
  ASSERT_EQ(43, *ptr);

  dlclose(handle);
  dlclose(preload);
}

TEST(dlfcn, dlsym_handle_global_sym) {
  // check that we do not look into global group
  // when looking up symbol by handle
  void* handle = dlopen("libtest_empty.so", RTLD_NOW);
  dlopen("libtest_with_dependency.so", RTLD_NOW | RTLD_GLOBAL);
  void* sym = dlsym(handle, "getRandomNumber");
  ASSERT_TRUE(sym == nullptr);
  ASSERT_SUBSTR("undefined symbol: getRandomNumber", dlerror());

  sym = dlsym(handle, "DlSymTestFunction");
  ASSERT_TRUE(sym == nullptr);
  ASSERT_SUBSTR("undefined symbol: DlSymTestFunction", dlerror());
  dlclose(handle);
}

TEST(dlfcn, dlsym_handle_empty_symbol) {
  // check that dlsym of an empty symbol fails (see http://b/33530622)
  void* handle = dlopen("libtest_dlsym_from_this.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  void* sym = dlsym(handle, "");
  ASSERT_TRUE(sym == nullptr);
  ASSERT_SUBSTR("undefined symbol: ", dlerror());
  dlclose(handle);
}

TEST(dlfcn, dlsym_with_dependencies) {
  void* handle = dlopen("libtest_with_dependency.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr);
  dlerror();
  // This symbol is in DT_NEEDED library.
  void* sym = dlsym(handle, "getRandomNumber");
  ASSERT_TRUE(sym != nullptr) << dlerror();
  int (*fn)(void);
  fn = reinterpret_cast<int (*)(void)>(sym);
  EXPECT_EQ(4, fn());
  dlclose(handle);
}

TEST(dlfcn, dlopen_noload) {
  void* handle = dlopen("libtest_simple.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
  handle = dlopen("libtest_simple.so", RTLD_NOW);
  void* handle2 = dlopen("libtest_simple.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle != nullptr);
  ASSERT_TRUE(handle2 != nullptr);
  ASSERT_TRUE(handle == handle2);
  ASSERT_EQ(0, dlclose(handle));
  ASSERT_EQ(0, dlclose(handle2));
}

TEST(dlfcn, dlopen_by_soname) {
  static const char* soname = "libdlext_test_soname.so";
  static const char* filename = "libdlext_test_different_soname.so";
  // 1. Make sure there is no library with soname in default search path
  void* handle = dlopen(soname, RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);

  // 2. Load a library using filename
  handle = dlopen(filename, RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  // 3. Find library by soname
  void* handle_soname = dlopen(soname, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle_soname != nullptr) << dlerror();
  ASSERT_EQ(handle, handle_soname);

  // 4. RTLD_NOLOAD should still work with filename
  void* handle_filename = dlopen(filename, RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle_filename != nullptr) << dlerror();
  ASSERT_EQ(handle, handle_filename);

  dlclose(handle_filename);
  dlclose(handle_soname);
  dlclose(handle);
}

TEST(dlfcn, dlopen_vdso) {
#if __has_include(<sys/auxv.h>)
  if (getauxval(AT_SYSINFO_EHDR) == 0) {
    GTEST_SKIP() << "getauxval(AT_SYSINFO_EHDR) == 0, skipping this test";
  }
#endif

  const char* vdso_name = "linux-vdso.so.1";
#if defined(__i386__)
  vdso_name = "linux-gate.so.1";
#endif
  void* handle = dlopen(vdso_name, RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  dlclose(handle);
}

// HWASan uses an ifunc to describe the location of its shadow memory,
// so even though it's an unusual case, Android needs to support
// "ifunc variables".
TEST(dlfcn, ifunc_variable) {
  typedef const char* (*fn_ptr)();

  // ifunc's choice depends on whether IFUNC_CHOICE has a value
  // first check the set case
  setenv("IFUNC_CHOICE", "set", 1);
  // preload libtest_ifunc_variable_impl.so
  void* handle_impl = dlopen("libtest_ifunc_variable_impl.so", RTLD_NOW);
  void* handle = dlopen("libtest_ifunc_variable.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  const char** foo_ptr = reinterpret_cast<const char**>(dlsym(handle, "foo"));
  fn_ptr foo_library_ptr = reinterpret_cast<fn_ptr>(dlsym(handle, "foo_library"));
  ASSERT_TRUE(foo_ptr != nullptr) << dlerror();
  ASSERT_TRUE(foo_library_ptr != nullptr) << dlerror();
  ASSERT_EQ(strncmp("set", *foo_ptr, 3), 0);
  ASSERT_EQ(strncmp("set", foo_library_ptr(), 3), 0);
  dlclose(handle);
  dlclose(handle_impl);

  // then check the unset case
  unsetenv("IFUNC_CHOICE");
  handle_impl = dlopen("libtest_ifunc_variable_impl.so", RTLD_NOW);
  handle = dlopen("libtest_ifunc_variable.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  foo_ptr = reinterpret_cast<const char**>(dlsym(handle, "foo"));
  foo_library_ptr = reinterpret_cast<fn_ptr>(dlsym(handle, "foo_library"));
  ASSERT_TRUE(foo_ptr != nullptr) << dlerror();
  ASSERT_TRUE(foo_library_ptr != nullptr) << dlerror();
  ASSERT_EQ(strncmp("unset", *foo_ptr, 5), 0);
  ASSERT_EQ(strncmp("unset", foo_library_ptr(), 5), 0);
  dlclose(handle);
  dlclose(handle_impl);
}

TEST(dlfcn, ifunc) {
  typedef const char* (*fn_ptr)();

  // ifunc's choice depends on whether IFUNC_CHOICE has a value
  // first check the set case
  setenv("IFUNC_CHOICE", "set", 1);
  void* handle = dlopen("libtest_ifunc.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  fn_ptr foo_ptr = reinterpret_cast<fn_ptr>(dlsym(handle, "foo"));
  fn_ptr foo_library_ptr = reinterpret_cast<fn_ptr>(dlsym(handle, "foo_library"));
  ASSERT_TRUE(foo_ptr != nullptr) << dlerror();
  ASSERT_TRUE(foo_library_ptr != nullptr) << dlerror();
  ASSERT_EQ(strncmp("set", foo_ptr(), 3), 0);
  ASSERT_EQ(strncmp("set", foo_library_ptr(), 3), 0);
  dlclose(handle);

  // then check the unset case
  unsetenv("IFUNC_CHOICE");
  handle = dlopen("libtest_ifunc.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  foo_ptr = reinterpret_cast<fn_ptr>(dlsym(handle, "foo"));
  foo_library_ptr = reinterpret_cast<fn_ptr>(dlsym(handle, "foo_library"));
  ASSERT_TRUE(foo_ptr != nullptr) << dlerror();
  ASSERT_TRUE(foo_library_ptr != nullptr) << dlerror();
  ASSERT_EQ(strncmp("unset", foo_ptr(), 5), 0);
  ASSERT_EQ(strncmp("unset", foo_library_ptr(), 5), 0);
  dlclose(handle);
}

TEST(dlfcn, ifunc_ctor_call) {
  typedef const char* (*fn_ptr)();

  void* handle = dlopen("libtest_ifunc.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  fn_ptr is_ctor_called =  reinterpret_cast<fn_ptr>(dlsym(handle, "is_ctor_called_irelative"));
  ASSERT_TRUE(is_ctor_called != nullptr) << dlerror();
  ASSERT_STREQ("false", is_ctor_called());

  is_ctor_called =  reinterpret_cast<fn_ptr>(dlsym(handle, "is_ctor_called_jump_slot"));
  ASSERT_TRUE(is_ctor_called != nullptr) << dlerror();
  ASSERT_STREQ("true", is_ctor_called());
  dlclose(handle);
}

TEST(dlfcn, ifunc_ctor_call_rtld_lazy) {
  typedef const char* (*fn_ptr)();

  void* handle = dlopen("libtest_ifunc.so", RTLD_LAZY);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  fn_ptr is_ctor_called =  reinterpret_cast<fn_ptr>(dlsym(handle, "is_ctor_called_irelative"));
  ASSERT_TRUE(is_ctor_called != nullptr) << dlerror();
  ASSERT_STREQ("false", is_ctor_called());

  is_ctor_called =  reinterpret_cast<fn_ptr>(dlsym(handle, "is_ctor_called_jump_slot"));
  ASSERT_TRUE(is_ctor_called != nullptr) << dlerror();
  ASSERT_STREQ("true", is_ctor_called());
  dlclose(handle);
}

TEST(dlfcn, dlopen_check_relocation_dt_needed_order) {
  // This is the structure of the test library and
  // its dt_needed libraries
  // libtest_relo_check_dt_needed_order.so
  // |
  // +-> libtest_relo_check_dt_needed_order_1.so
  // |
  // +-> libtest_relo_check_dt_needed_order_2.so
  //
  // The root library references relo_test_get_answer_lib - which is defined
  // in both dt_needed libraries, the correct relocation should
  // use the function defined in libtest_relo_check_dt_needed_order_1.so
  void* handle = nullptr;
  auto guard = android::base::make_scope_guard([&]() { dlclose(handle); });

  handle = dlopen("libtest_relo_check_dt_needed_order.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef int (*fn_t) (void);
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "relo_test_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(1, fn());
}

TEST(dlfcn, dlopen_check_order_dlsym) {
  // Here is how the test library and its dt_needed
  // libraries are arranged
  //
  //  libtest_check_order_children.so
  //  |
  //  +-> ..._1_left.so
  //  |   |
  //  |   +-> ..._a.so
  //  |   |
  //  |   +-> ...r_b.so
  //  |
  //  +-> ..._2_right.so
  //  |   |
  //  |   +-> ..._d.so
  //  |       |
  //  |       +-> ..._b.so
  //  |
  //  +-> ..._3_c.so
  //
  //  load order should be (1, 2, 3, a, b, d)
  //
  // get_answer() is defined in (2, 3, a, b, c)
  // get_answer2() is defined in (b, d)
  void* sym = dlsym(RTLD_DEFAULT, "check_order_dlsym_get_answer");
  ASSERT_TRUE(sym == nullptr);
  void* handle = dlopen("libtest_check_order_dlsym.so", RTLD_NOW | RTLD_GLOBAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  typedef int (*fn_t) (void);
  fn_t fn, fn2;
  fn = reinterpret_cast<fn_t>(dlsym(RTLD_DEFAULT, "check_order_dlsym_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  fn2 = reinterpret_cast<fn_t>(dlsym(RTLD_DEFAULT, "check_order_dlsym_get_answer2"));
  ASSERT_TRUE(fn2 != nullptr) << dlerror();

  ASSERT_EQ(42, fn());
  ASSERT_EQ(43, fn2());
  dlclose(handle);
}

TEST(dlfcn, dlopen_check_order_reloc_siblings) {
  // This is how this one works:
  // we lookup and call get_answer which is defined in '_2.so'
  // and in turn calls external get_answer_impl() defined in _1.so and in '_[a-f].so'
  // the correct _impl() is implemented by '_a.so';
  //
  // Note that this is test for RTLD_LOCAL (TODO: test for GLOBAL?)
  //
  // Here is the picture:
  //
  // libtest_check_order_reloc_siblings.so
  // |
  // +-> ..._1.so <- empty
  // |   |
  // |   +-> ..._a.so <- exports correct answer_impl()
  // |   |
  // |   +-> ..._b.so <- every other letter exporting incorrect one.
  // |
  // +-> ..._2.so <- empty
  // |   |
  // |   +-> ..._c.so
  // |   |
  // |   +-> ..._d.so
  // |
  // +-> ..._3.so <- empty
  //     |
  //     +-> ..._e.so
  //     |
  //     +-> ..._f.so <- exports get_answer() that calls get_anser_impl();
  //                     implements incorrect get_answer_impl()

  void* handle = dlopen("libtest_check_order_reloc_siblings.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
#ifdef __BIONIC__
  // TODO: glibc returns nullptr on dlerror() here. Is it bug?
  ASSERT_STREQ("dlopen failed: library \"libtest_check_order_reloc_siblings.so\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());
#endif

  handle = dlopen("libtest_check_order_reloc_siblings.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef int (*fn_t) (void);
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "check_order_reloc_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(42, fn());

  ASSERT_EQ(0, dlclose(handle));
}

TEST(dlfcn, dlopen_check_order_reloc_siblings_with_preload) {
  // This test uses the same library as dlopen_check_order_reloc_siblings.
  // Unlike dlopen_check_order_reloc_siblings it preloads
  // libtest_check_order_reloc_siblings_1.so (first dependency) prior to
  // dlopen(libtest_check_order_reloc_siblings.so)

  void* handle = dlopen("libtest_check_order_reloc_siblings.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
  handle = dlopen("libtest_check_order_reloc_siblings_1.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);

  void* handle_for_1 = dlopen("libtest_check_order_reloc_siblings_1.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle_for_1 != nullptr) << dlerror();

  handle = dlopen("libtest_check_order_reloc_siblings.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  ASSERT_EQ(0, dlclose(handle_for_1));

  typedef int (*fn_t) (void);
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "check_order_reloc_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(42, fn());

  ASSERT_EQ(0, dlclose(handle));
}

TEST(dlfcn, dlopen_check_order_reloc_grandchild) {
  // This is how this one works:
  // we lookup and call grandchild_get_answer which is defined in '_2.so'
  // and in turn calls external get_answer_impl() defined in '_c_1.so and _c_2.so'
  // the correct _impl() is implemented by '_c_1.so';
  //
  // Here is the picture of subtree:
  //
  // libtest_check_order_reloc_siblings.so
  // |
  // +-> ..._2.so <- grandchild_get_answer()
  //     |
  //     +-> ..._c.so <- empty
  //     |   |
  //     |   +-> _c_1.so <- exports correct answer_impl()
  //     |   |
  //     |   +-> _c_2.so <- exports incorrect answer_impl()
  //     |
  //     +-> ..._d.so <- empty

  void* handle = dlopen("libtest_check_order_reloc_siblings.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
#ifdef __BIONIC__
  // TODO: glibc returns nullptr on dlerror() here. Is it bug?
  ASSERT_STREQ("dlopen failed: library \"libtest_check_order_reloc_siblings.so\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());
#endif

  handle = dlopen("libtest_check_order_reloc_siblings.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef int (*fn_t) (void);
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "check_order_reloc_grandchild_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(42, fn());

  ASSERT_EQ(0, dlclose(handle));
}

TEST(dlfcn, dlopen_check_order_reloc_nephew) {
  // This is how this one works:
  // we lookup and call nephew_get_answer which is defined in '_2.so'
  // and in turn calls external get_answer_impl() defined in '_[a-f].so'
  // the correct _impl() is implemented by '_a.so';
  //
  // Here is the picture:
  //
  // libtest_check_order_reloc_siblings.so
  // |
  // +-> ..._1.so <- empty
  // |   |
  // |   +-> ..._a.so <- exports correct answer_impl()
  // |   |
  // |   +-> ..._b.so <- every other letter exporting incorrect one.
  // |
  // +-> ..._2.so <- empty
  // |   |
  // |   +-> ..._c.so
  // |   |
  // |   +-> ..._d.so
  // |
  // +-> ..._3.so <- nephew_get_answer() that calls get_answer_impl();
  //     |
  //     +-> ..._e.so
  //     |
  //     +-> ..._f.so

  void* handle = dlopen("libtest_check_order_reloc_siblings.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
#ifdef __BIONIC__
  // TODO: glibc returns nullptr on dlerror() here. Is it bug?
  ASSERT_STREQ("dlopen failed: library \"libtest_check_order_reloc_siblings.so\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());
#endif

  handle = dlopen("libtest_check_order_reloc_siblings.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef int (*fn_t) (void);
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "check_order_reloc_nephew_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(42, fn());

  ASSERT_EQ(0, dlclose(handle));
}

TEST(dlfcn, check_unload_after_reloc) {
  // This is how this one works:
  // libtest_two_parents_parent1 <- answer_impl() used by libtest_two_parents_child
  // |
  // +-> libtest_two_parents_child
  //
  // libtest_two_parents_parent2 <- answer_impl() not used by libtest_two_parents_child
  // |
  // +-> libtest_two_parents_child
  //
  // Test dlopens parent1 which loads and relocates libtest_two_parents_child.so
  // as a second step it dlopens parent2 and dlcloses parent1...

  void* handle = dlopen("libtest_two_parents_parent1.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  void* handle2 = dlopen("libtest_two_parents_parent2.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle2 != nullptr) << dlerror();

  typedef int (*fn_t) (void);
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle2, "check_order_reloc_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(42, fn());

  ASSERT_EQ(0, dlclose(handle));

  handle = dlopen("libtest_two_parents_parent1.so", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
  ASSERT_TRUE(handle != nullptr);
  ASSERT_EQ(0, dlclose(handle));

  fn = reinterpret_cast<fn_t>(dlsym(handle2, "check_order_reloc_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(42, fn());

  ASSERT_EQ(0, dlclose(handle2));

  handle = dlopen("libtest_two_parents_parent1.so", RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
}

extern "C" int check_order_reloc_root_get_answer_impl() {
  return 42;
}

TEST(dlfcn, dlopen_check_order_reloc_main_executable) {
  // This is how this one works:
  // we lookup and call get_answer3 which is defined in 'root.so'
  // and in turn calls external root_get_answer_impl() defined in _2.so and
  // above the correct _impl() is one in the executable.
  //
  // libtest_check_order_reloc_root.so
  // |
  // +-> ..._1.so <- empty
  // |
  // +-> ..._2.so <- gives incorrect answer for answer_main_impl()
  //

  void* handle = dlopen("libtest_check_order_reloc_root.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
#ifdef __BIONIC__
  // TODO: glibc returns nullptr on dlerror() here. Is it bug?
  ASSERT_STREQ("dlopen failed: library \"libtest_check_order_reloc_root.so\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());
#endif

  handle = dlopen("libtest_check_order_reloc_root.so", RTLD_NOW | RTLD_LOCAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef int (*fn_t) (void);
  fn_t fn = reinterpret_cast<fn_t>(dlsym(handle, "check_order_reloc_root_get_answer"));
  ASSERT_TRUE(fn != nullptr) << dlerror();
  ASSERT_EQ(42, fn());

  ASSERT_EQ(0, dlclose(handle));
}

TEST(dlfcn, dlopen_check_rtld_local) {
  void* sym = dlsym(RTLD_DEFAULT, "dlopen_testlib_simple_func");
  ASSERT_TRUE(sym == nullptr);

  // implicit RTLD_LOCAL
  void* handle = dlopen("libtest_simple.so", RTLD_NOW);
  sym = dlsym(RTLD_DEFAULT, "dlopen_testlib_simple_func");
  ASSERT_TRUE(sym == nullptr);
  ASSERT_SUBSTR("undefined symbol: dlopen_testlib_simple_func", dlerror());
  sym = dlsym(handle, "dlopen_testlib_simple_func");
  ASSERT_TRUE(sym != nullptr);
  ASSERT_TRUE(reinterpret_cast<bool (*)(void)>(sym)());
  dlclose(handle);

  // explicit RTLD_LOCAL
  handle = dlopen("libtest_simple.so", RTLD_NOW | RTLD_LOCAL);
  sym = dlsym(RTLD_DEFAULT, "dlopen_testlib_simple_func");
  ASSERT_TRUE(sym == nullptr);
  ASSERT_SUBSTR("undefined symbol: dlopen_testlib_simple_func", dlerror());
  sym = dlsym(handle, "dlopen_testlib_simple_func");
  ASSERT_TRUE(sym != nullptr);
  ASSERT_TRUE(reinterpret_cast<bool (*)(void)>(sym)());
  dlclose(handle);
}

TEST(dlfcn, dlopen_check_rtld_global) {
  void* sym = dlsym(RTLD_DEFAULT, "dlopen_testlib_simple_func");
  ASSERT_TRUE(sym == nullptr);

  void* handle = dlopen("libtest_simple.so", RTLD_NOW | RTLD_GLOBAL);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  sym = dlsym(RTLD_DEFAULT, "dlopen_testlib_simple_func");
  ASSERT_TRUE(sym != nullptr) << dlerror();
  ASSERT_TRUE(reinterpret_cast<bool (*)(void)>(sym)());
  dlclose(handle);

  // RTLD_GLOBAL implies RTLD_NODELETE, let's check that
  void* sym_after_dlclose = dlsym(RTLD_DEFAULT, "dlopen_testlib_simple_func");
  ASSERT_EQ(sym, sym_after_dlclose);

  // Check if dlsym() for main program's handle searches RTLD_GLOBAL
  // shared libraries after symbol was not found in the main executable
  // and dependent libraries.
  void* handle_for_main_executable = dlopen(nullptr, RTLD_NOW);
  sym = dlsym(handle_for_main_executable, "dlopen_testlib_simple_func");
  ASSERT_TRUE(sym != nullptr) << dlerror();

  dlclose(handle_for_main_executable);
}

// libtest_with_dependency_loop.so -> libtest_with_dependency_loop_a.so ->
// libtest_with_dependency_loop_b.so -> libtest_with_dependency_loop_c.so ->
// libtest_with_dependency_loop_a.so
TEST(dlfcn, dlopen_check_loop) {
  void* handle = dlopen("libtest_with_dependency_loop.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  void* f = dlsym(handle, "dlopen_test_loopy_function");
  ASSERT_TRUE(f != nullptr) << dlerror();
  EXPECT_TRUE(reinterpret_cast<bool (*)(void)>(f)());
  ASSERT_EQ(0, dlclose(handle));

  // dlopen second time to make sure that the library was unloaded correctly
  handle = dlopen("libtest_with_dependency_loop.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
#ifdef __BIONIC__
  ASSERT_STREQ("dlopen failed: library \"libtest_with_dependency_loop.so\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());
#else
  // TODO: glibc returns nullptr on dlerror() here. Is it bug?
  ASSERT_TRUE(dlerror() == nullptr);
#endif

  handle = dlopen("libtest_with_dependency_a.so", RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle == nullptr);
}

TEST(dlfcn, dlopen_nodelete) {
  static bool is_unloaded = false;

  void* handle = dlopen("libtest_nodelete_1.so", RTLD_NOW | RTLD_NODELETE);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  void (*set_unload_flag_ptr)(bool*);
  set_unload_flag_ptr = reinterpret_cast<void (*)(bool*)>(dlsym(handle, "dlopen_nodelete_1_set_unload_flag_ptr"));
  ASSERT_TRUE(set_unload_flag_ptr != nullptr) << dlerror();
  set_unload_flag_ptr(&is_unloaded);

  uint32_t* taxicab_number = reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_nodelete_1_taxicab_number"));
  ASSERT_TRUE(taxicab_number != nullptr) << dlerror();
  ASSERT_EQ(1729U, *taxicab_number);
  *taxicab_number = 2;

  dlclose(handle);
  ASSERT_TRUE(!is_unloaded);

  uint32_t* taxicab_number_after_dlclose = reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_nodelete_1_taxicab_number"));
  ASSERT_EQ(taxicab_number_after_dlclose, taxicab_number);
  ASSERT_EQ(2U, *taxicab_number_after_dlclose);


  handle = dlopen("libtest_nodelete_1.so", RTLD_NOW);
  uint32_t* taxicab_number2 = reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_nodelete_1_taxicab_number"));
  ASSERT_EQ(taxicab_number2, taxicab_number);

  ASSERT_EQ(2U, *taxicab_number2);

  dlclose(handle);
  ASSERT_TRUE(!is_unloaded);
}

TEST(dlfcn, dlopen_nodelete_on_second_dlopen) {
  static bool is_unloaded = false;

  void* handle = dlopen("libtest_nodelete_2.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  void (*set_unload_flag_ptr)(bool*);
  set_unload_flag_ptr = reinterpret_cast<void (*)(bool*)>(dlsym(handle, "dlopen_nodelete_2_set_unload_flag_ptr"));
  ASSERT_TRUE(set_unload_flag_ptr != nullptr) << dlerror();
  set_unload_flag_ptr(&is_unloaded);

  uint32_t* taxicab_number = reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_nodelete_2_taxicab_number"));
  ASSERT_TRUE(taxicab_number != nullptr) << dlerror();

  ASSERT_EQ(1729U, *taxicab_number);
  *taxicab_number = 2;

  // This RTLD_NODELETE should be ignored
  void* handle1 = dlopen("libtest_nodelete_2.so", RTLD_NOW | RTLD_NODELETE);
  ASSERT_TRUE(handle1 != nullptr) << dlerror();
  ASSERT_EQ(handle, handle1);

  dlclose(handle1);
  dlclose(handle);

  ASSERT_TRUE(is_unloaded);
}

TEST(dlfcn, dlopen_nodelete_dt_flags_1) {
  static bool is_unloaded = false;

  void* handle = dlopen("libtest_nodelete_dt_flags_1.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  void (*set_unload_flag_ptr)(bool*);
  set_unload_flag_ptr = reinterpret_cast<void (*)(bool*)>(dlsym(handle, "dlopen_nodelete_dt_flags_1_set_unload_flag_ptr"));
  ASSERT_TRUE(set_unload_flag_ptr != nullptr) << dlerror();
  set_unload_flag_ptr(&is_unloaded);

  dlclose(handle);
  ASSERT_TRUE(!is_unloaded);
}

TEST(dlfcn, dlsym_df_1_global) {
  void* handle = dlopen("libtest_dlsym_df_1_global.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  int (*get_answer)();
  get_answer = reinterpret_cast<int (*)()>(dlsym(handle, "dl_df_1_global_get_answer"));
  ASSERT_TRUE(get_answer != nullptr) << dlerror();
  ASSERT_EQ(42, get_answer());
  ASSERT_EQ(0, dlclose(handle));
}

TEST(dlfcn, dlopen_failure) {
  void* self = dlopen("/does/not/exist", RTLD_NOW);
  ASSERT_TRUE(self == nullptr);
#if defined(__BIONIC__)
  ASSERT_STREQ("dlopen failed: library \"/does/not/exist\" not found", dlerror());
#else
  ASSERT_STREQ("/does/not/exist: cannot open shared object file: No such file or directory", dlerror());
#endif
}

TEST(dlfcn, dlclose_unload) {
  const size_t kPageSize = getpagesize();

  void* handle = dlopen("libtest_simple.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  uint32_t* taxicab_number = static_cast<uint32_t*>(dlsym(handle, "dlopen_testlib_taxicab_number"));
  ASSERT_TRUE(taxicab_number != nullptr) << dlerror();
  EXPECT_EQ(1729U, *taxicab_number);
  dlclose(handle);
  // Making sure that the library has been unmapped as part of library unload
  // process. Note that mprotect somewhat counter-intuitively returns ENOMEM in
  // this case.
  uintptr_t page_start = reinterpret_cast<uintptr_t>(taxicab_number) & ~(kPageSize - 1);
  ASSERT_TRUE(mprotect(reinterpret_cast<void*>(page_start), kPageSize, PROT_NONE) != 0);
  ASSERT_ERRNO(ENOMEM);
}

static void ConcurrentDlErrorFn(std::string& error) {
  ASSERT_TRUE(dlerror() == nullptr);

  void* handle = dlopen("/child/thread", RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);

  const char* err = dlerror();
  ASSERT_TRUE(err != nullptr);

  error = err;
}

TEST(dlfcn, dlerror_concurrent_buffer) {
  void* handle = dlopen("/main/thread", RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);
  const char* main_thread_error = dlerror();
  ASSERT_TRUE(main_thread_error != nullptr);
  ASSERT_SUBSTR("/main/thread", main_thread_error);

  std::string child_thread_error;
  std::thread t(ConcurrentDlErrorFn, std::ref(child_thread_error));
  t.join();
  ASSERT_SUBSTR("/child/thread", child_thread_error.c_str());

  // Check that main thread local buffer was not modified.
  ASSERT_SUBSTR("/main/thread", main_thread_error);
}

TEST(dlfcn, dlerror_concurrent) {
  void* handle = dlopen("/main/thread", RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);

  std::string child_thread_error;
  std::thread t(ConcurrentDlErrorFn, std::ref(child_thread_error));
  t.join();
  ASSERT_SUBSTR("/child/thread", child_thread_error.c_str());

  const char* main_thread_error = dlerror();
  ASSERT_TRUE(main_thread_error != nullptr);
  ASSERT_SUBSTR("/main/thread", main_thread_error);
}

TEST(dlfcn, dlsym_failures) {
  dlerror(); // Clear any pending errors.
  void* self = dlopen(nullptr, RTLD_NOW);
  ASSERT_TRUE(self != nullptr);
  ASSERT_TRUE(dlerror() == nullptr);

  void* sym;

#if defined(__BIONIC__) && !defined(__LP64__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  // RTLD_DEFAULT in lp32 bionic is not (void*)0
  // so it can be distinguished from the NULL handle.
  sym = dlsym(nullptr, "test");
  ASSERT_TRUE(sym == nullptr);
  ASSERT_STREQ("dlsym failed: library handle is null", dlerror());
#pragma clang diagnostic pop
#endif

  // Symbol that doesn't exist.
  sym = dlsym(self, "ThisSymbolDoesNotExist");
  ASSERT_TRUE(sym == nullptr);
  ASSERT_SUBSTR("undefined symbol: ThisSymbolDoesNotExist", dlerror());

  ASSERT_EQ(0, dlclose(self));
}

TEST(dlfcn, dladdr_executable) {
  dlerror(); // Clear any pending errors.
  void* self = dlopen(nullptr, RTLD_NOW);
  ASSERT_TRUE(self != nullptr);
  ASSERT_TRUE(dlerror() == nullptr);

  void* sym = dlsym(self, "DlSymTestFunction");
  ASSERT_TRUE(sym != nullptr);

  // Deliberately ask dladdr for an address inside a symbol, rather than the symbol base address.
  void* addr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(sym) + 2);

  Dl_info info;
  int rc = dladdr(addr, &info);
  ASSERT_NE(rc, 0); // Zero on error, non-zero on success.

  // Get the name of this executable.
  const std::string executable_path = android::base::GetExecutablePath();

  // The filename should be that of this executable.
  char dli_re
```