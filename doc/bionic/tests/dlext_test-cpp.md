Response:
My thinking process to answer the request involved these steps:

1. **Understanding the Goal:** The request asks for a detailed analysis of the provided C++ test file (`bionic/tests/dlext_test.cpp`). The key is to break down the file's functionality, relate it to Android, explain the underlying mechanisms (especially `libc` and the dynamic linker), identify potential issues, and outline how Android reaches this code. The request specifically mentions being the first part of a three-part analysis and asks for a summary of the file's functionality.

2. **Initial Scan for Core Functionality:** I quickly scanned the `#include` directives and the test names (`TEST_F`, `TEST`). This immediately revealed the file's purpose: testing the `android_dlopen_ext` function and related dynamic linking extensions. The inclusion of `<dlfcn.h>` and `<android/dlext.h>` are strong indicators. The test names like `ExtInfoNull`, `ExtInfoUseFd`, `Reserved`, `ns_smoke` reinforced this.

3. **Categorizing Test Cases:** I started grouping the test cases based on the functionality they were testing. This involved looking at the test names and the core actions within each test:
    * **Basic `android_dlopen_ext` usage:** Tests like `ExtInfoNull`, `ExtInfoNoFlags`.
    * **Using file descriptors:** Tests like `ExtInfoUseFd`, `ExtInfoUseFdWithOffset`, `ExtInfoUseFdWithInvalidOffset`.
    * **Forcing library loading:** Tests like `android_dlopen_ext_force_load_smoke`, `android_dlopen_ext_force_load_soname_exception`.
    * **System path translation (legacy):**  Tests relating to `libicuuc.so`.
    * **Loading from ZIP archives:** Tests like `dlopen_from_zip_absolute_path`, `dlopen_from_zip_with_dt_runpath`, `dlopen_from_zip_ld_library_path`.
    * **Reserving address space:** Tests like `Reserved`, `ReservedTooSmall`, `ReservedRecursive`, `ReservedHint`.
    * **RELRO sharing:** Tests within the `DlExtRelroSharingTest` fixture.
    * **Namespaces:** Tests within the `ns_smoke` test.

4. **Identifying Key Concepts and Functions:** As I categorized the tests, I noted the key concepts and functions being tested:
    * `android_dlopen_ext`: The central function being tested.
    * `android_dlextinfo`: The structure used to pass extended information to `android_dlopen_ext`.
    * `dlopen`, `dlsym`, `dlclose`, `dlerror`: Standard dynamic linking functions.
    * `RTLD_NOW`, `RTLD_NOLOAD`: Flags for `dlopen`.
    * File descriptors (`open`, `close`).
    * Memory mapping (`mmap`).
    * Process management (`fork`, `wait`).
    * ZIP archive handling (`ziparchive`).
    * Namespaces (`android_create_namespace`, `android_link_namespaces`, `android_init_anonymous_namespace`).

5. **Connecting to Android Functionality:**  For each category, I considered how it relates to Android:
    * **`android_dlopen_ext`:** This is a core Android extension, providing more control over library loading.
    * **File descriptors:**  Essential for loading libraries from APKs or other custom locations.
    * **ZIP archives:**  Crucial for loading libraries embedded within APKs.
    * **Reserved address space:**  Optimization and security feature to control where libraries are loaded.
    * **RELRO sharing:**  Security optimization to share read-only parts of libraries across processes.
    * **Namespaces:**  Isolation mechanism for libraries, preventing conflicts and enhancing security.

6. **Considering Implementation Details (High-Level for this part):**  While the request asked for detailed explanations of `libc` functions and the dynamic linker, this first part focuses on summarizing functionality. Therefore, I noted *that* these things were involved, but didn't delve into the "how" for each individual function yet. I made a mental note to address this in subsequent parts.

7. **Identifying Potential Issues (High-Level):** I looked for common patterns that could indicate potential user errors or areas where things could go wrong:
    * Incorrect flags passed to `android_dlopen_ext`.
    * Issues with file descriptors (invalid FDs, incorrect offsets).
    * Problems with reserved memory regions (too small, incorrect addresses).
    * Namespace configuration errors.

8. **Thinking about the Android Framework and NDK Connection (High-Level):** I considered how a typical Android app or NDK developer might end up using these features:
    * Directly using `dlopen` and related functions in native code.
    * Indirectly through the Android framework's class loading mechanisms (which internally use the dynamic linker).
    * When using libraries packaged inside APKs.

9. **Planning for Subsequent Parts:** I mentally outlined how I would address the detailed function explanations, linker behavior, and Frida hooking in the next parts of the response.

10. **Drafting the Summary:** Finally, I synthesized the information gathered into a concise summary of the file's functionality, focusing on the main purpose of testing `android_dlopen_ext` and its various features. I used clear and straightforward language, avoiding overly technical jargon where possible. I highlighted the key areas tested (FD usage, ZIP loading, reserved addresses, RELRO, namespaces).

Essentially, I approached it like reverse-engineering the purpose of the test file. By looking at what it *does*, I inferred *why* it exists and what functionality it validates. The key was breaking down the complex file into smaller, manageable units based on the individual test cases.
这是对 `bionic/tests/dlext_test.cpp` 文件第一部分的分析和功能归纳。

**文件功能总览:**

`bionic/tests/dlext_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试 `android_dlopen_ext` 函数及其相关扩展功能的行为。`android_dlopen_ext` 是 Android 提供的一个扩展动态链接库加载函数，它允许开发者在加载共享库时提供额外的控制信息，例如从指定的文件描述符加载、指定加载地址、使用 RELRO 等。

**具体功能点归纳:**

该测试文件的主要目的是验证 `android_dlopen_ext` 函数在各种不同场景下的正确性和预期行为。以下是根据提供的代码片段归纳出的主要测试功能点：

1. **基本 `android_dlopen_ext` 功能测试:**
   - 验证在不提供额外扩展信息时（`nullptr` 的 `android_dlextinfo`），`android_dlopen_ext` 是否能够正常加载共享库。
   - 验证提供一个空的 `android_dlextinfo` 结构体（`flags` 为 0）时，`android_dlopen_ext` 是否能够正常加载共享库。

2. **使用文件描述符加载共享库 (`ANDROID_DLEXT_USE_LIBRARY_FD`):**
   - 测试通过打开共享库文件并传递其文件描述符给 `android_dlopen_ext` 来加载库的功能。
   - 验证从文件描述符加载的库能够正常执行其中的函数和访问全局变量。

3. **使用文件描述符和偏移量加载 ZIP 包中的共享库 (`ANDROID_DLEXT_USE_LIBRARY_FD` 和 `ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET`):**
   - 测试从 ZIP 压缩包中提取共享库并通过文件描述符和偏移量加载的功能。这模拟了 Android 系统加载 APK 包中 native 库的场景。
   - 验证正确计算和传递 ZIP 包内共享库的偏移量是加载成功的关键。
   - 测试了无效偏移量（未页对齐、超出文件大小、负数）的情况，验证 `android_dlopen_ext` 能正确返回错误并设置 `dlerror`。
   - 验证了在 `dlopen` 失败后调用 `dlsym` 是否仍然能正常工作（保证符号查找机制的健壮性）。

4. **错误使用偏移量标志 (`ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET` 但未设置 `ANDROID_DLEXT_USE_LIBRARY_FD`):**
   - 测试当设置了偏移量标志但没有设置使用文件描述符标志时，`android_dlopen_ext` 是否能正确检测到这种无效的标志组合并返回错误。

5. **强制加载 (`ANDROID_DLEXT_FORCE_LOAD`):**
   - 测试 `ANDROID_DLEXT_FORCE_LOAD` 标志的作用，即即使共享库已经加载，也会强制加载一个新的副本。
   - 验证当使用符号链接加载库并设置 `ANDROID_DLEXT_FORCE_LOAD` 时，会加载新的实例，即使目标 so name 对应的库已经加载。

6. **处理 `dlopen(nullptr)`:**
   - 测试在 Android API level 28 (P) 及以上版本中，调用 `dlopen(nullptr, RTLD_NOW)` 是否会返回非空指针（这是 Android 的一个特定行为）。

7. **系统库路径转换 (兼容性测试):**
   - 测试在旧版本 Android (API level 28) 上，使用系统库的旧路径 (例如 `/system/lib/libicuuc.so`) 是否仍然能够正常加载库，以保持向后兼容性。
   - 验证在新版本 Android 上，这种旧路径将不再有效。

8. **从 ZIP 包加载共享库 (绝对路径):**
   - 测试使用包含 ZIP 包路径和包内 so 文件路径的绝对路径来加载共享库的功能。

9. **从带 `DT_RUNPATH` 的 ZIP 包加载共享库:**
   - 测试加载包含 `DT_RUNPATH` 的 ZIP 包中的共享库，并验证 `DT_RUNPATH` 是否能够正确影响其依赖库的加载。

10. **通过 `LD_LIBRARY_PATH` 从 ZIP 包加载共享库:**
    - 测试通过 `android_update_LD_LIBRARY_PATH` 添加 ZIP 包内的目录，然后通过 so name 加载共享库的功能。

11. **预留地址空间加载 (`ANDROID_DLEXT_RESERVED_ADDRESS`):**
    - 测试指定预留的内存地址和大小，让 `android_dlopen_ext` 将共享库加载到该地址空间的功能。
    - 验证加载的库中的符号地址是否位于预留的地址范围内。
    - 验证 `dlclose` 后预留的地址空间会被释放。
    - 测试预留空间不足以加载共享库的情况。

12. **递归预留地址空间加载 (`ANDROID_DLEXT_RESERVED_ADDRESS` 和 `ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE`):**
    - 测试在加载共享库及其依赖项时，都将它们加载到预留的地址空间的功能。
    - 验证加载的库及其依赖库中的符号地址都位于预留的地址范围内。
    - 测试递归预留空间不足的情况。

13. **预留地址空间提示加载 (`ANDROID_DLEXT_RESERVED_ADDRESS_HINT`):**
    - 测试提供地址空间提示，让加载器尽量将共享库加载到该地址附近的功能。
    - 验证加载器在提示下尝试加载，但不保证一定加载到指定区域。
    - 测试提示空间不足的情况。

**总结:**

总的来说，`bionic/tests/dlext_test.cpp` 的第一部分主要关注于 `android_dlopen_ext` 函数的基本功能和一些关键扩展功能（如使用文件描述符、从 ZIP 包加载、预留地址空间）的测试。这些测试覆盖了 `android_dlopen_ext` 的各种使用场景和潜在的错误情况，确保该函数在不同情况下都能按预期工作，为 Android 平台上动态库的加载提供了稳定性和可靠性。

在接下来的部分，预计会涉及到更多关于 RELRO 共享、命名空间等更高级的动态链接特性测试。

### 提示词
```
这是目录为bionic/tests/dlext_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2014 The Android Open Source Project
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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <android/dlext.h>
#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>

#include <meminfo/procmeminfo.h>
#include <procinfo/process_map.h>
#include <ziparchive/zip_archive.h>

#include "bionic/mte.h"
#include "bionic/page.h"
#include "core_shared_libs.h"
#include "dlext_private_tests.h"
#include "dlfcn_symlink_support.h"
#include "gtest_globals.h"
#include "utils.h"

#define ASSERT_DL_NOTNULL(ptr) \
    ASSERT_TRUE((ptr) != nullptr) << "dlerror: " << dlerror()

#define ASSERT_DL_ZERO(i) \
    ASSERT_EQ(0, i) << "dlerror: " << dlerror()

#define ASSERT_NOERROR(i) \
    ASSERT_NE(-1, i) << "errno: " << strerror(errno)

#define ASSERT_SUBSTR(needle, haystack) \
    ASSERT_PRED_FORMAT2(::testing::IsSubstring, needle, haystack)


typedef int (*fn)(void);
constexpr const char* kLibName = "libdlext_test.so";
constexpr const char* kLibNameRecursive = "libdlext_test_recursive.so";
constexpr const char* kLibNameNoRelro = "libdlext_test_norelro.so";
constexpr const char* kLibZipSimpleZip = "libdir/libatest_simple_zip.so";
constexpr auto kLibSize = 1024 * 1024; // how much address space to reserve for it

class DlExtTest : public ::testing::Test {
protected:
  void SetUp() override {
    handle_ = nullptr;
    // verify that we don't have the library loaded already
    void* h = dlopen(kLibName, RTLD_NOW | RTLD_NOLOAD);
    ASSERT_TRUE(h == nullptr);
    h = dlopen(kLibNameNoRelro, RTLD_NOW | RTLD_NOLOAD);
    ASSERT_TRUE(h == nullptr);
    // call dlerror() to swallow the error, and check it was the one we wanted
    ASSERT_EQ(std::string("dlopen failed: library \"") + kLibNameNoRelro + "\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());
  }

  void TearDown() override {
    if (handle_ != nullptr) {
      ASSERT_DL_ZERO(dlclose(handle_));
    }
  }

  void* handle_;
  const size_t kPageSize = getpagesize();
};

TEST_F(DlExtTest, ExtInfoNull) {
  handle_ = android_dlopen_ext(kLibName, RTLD_NOW, nullptr);
  ASSERT_DL_NOTNULL(handle_);
  fn f = reinterpret_cast<fn>(dlsym(handle_, "getRandomNumber"));
  ASSERT_DL_NOTNULL(f);
  EXPECT_EQ(4, f());
}

TEST_F(DlExtTest, ExtInfoNoFlags) {
  android_dlextinfo extinfo;
  extinfo.flags = 0;
  handle_ = android_dlopen_ext(kLibName, RTLD_NOW, &extinfo);
  ASSERT_DL_NOTNULL(handle_);
  fn f = reinterpret_cast<fn>(dlsym(handle_, "getRandomNumber"));
  ASSERT_DL_NOTNULL(f);
  EXPECT_EQ(4, f());
}

TEST_F(DlExtTest, ExtInfoUseFd) {
  const std::string lib_path = GetTestLibRoot() + "/libdlext_test_fd/libdlext_test_fd.so";

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
  extinfo.library_fd = TEMP_FAILURE_RETRY(open(lib_path.c_str(), O_RDONLY | O_CLOEXEC));
  ASSERT_TRUE(extinfo.library_fd != -1);
  handle_ = android_dlopen_ext(lib_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_DL_NOTNULL(handle_);
  fn f = reinterpret_cast<fn>(dlsym(handle_, "getRandomNumber"));
  ASSERT_DL_NOTNULL(f);
  EXPECT_EQ(4, f());

  uint32_t* taxicab_number = reinterpret_cast<uint32_t*>(dlsym(handle_, "dlopen_testlib_taxicab_number"));
  ASSERT_DL_NOTNULL(taxicab_number);
  EXPECT_EQ(1729U, *taxicab_number);
}

TEST_F(DlExtTest, ExtInfoUseFdWithOffset) {
  const std::string lib_path = GetTestLibRoot() + "/libdlext_test_zip/libdlext_test_zip_zipaligned.zip";

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET;
  extinfo.library_fd = TEMP_FAILURE_RETRY(open(lib_path.c_str(), O_RDONLY | O_CLOEXEC));

  // Find the offset of the shared library in the zip.
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchive(lib_path.c_str(), &handle));
  ZipEntry zip_entry;
  ASSERT_EQ(0, FindEntry(handle, kLibZipSimpleZip, &zip_entry));
  extinfo.library_fd_offset = zip_entry.offset;
  CloseArchive(handle);

  handle_ = android_dlopen_ext(lib_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_DL_NOTNULL(handle_);

  uint32_t* taxicab_number = reinterpret_cast<uint32_t*>(dlsym(handle_, "dlopen_testlib_taxicab_number"));
  ASSERT_DL_NOTNULL(taxicab_number);
  EXPECT_EQ(1729U, *taxicab_number);
}

TEST_F(DlExtTest, ExtInfoUseFdWithInvalidOffset) {
  const std::string lib_path = GetTestLibRoot() + "/libdlext_test_zip/libdlext_test_zip_zipaligned.zip";

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET;
  extinfo.library_fd = TEMP_FAILURE_RETRY(open(lib_path.c_str(), O_RDONLY | O_CLOEXEC));
  extinfo.library_fd_offset = 17;

  handle_ = android_dlopen_ext("libname_placeholder", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle_ == nullptr);
  ASSERT_STREQ("dlopen failed: file offset for the library \"libname_placeholder\" is not page-aligned: 17", dlerror());

  // Test an address above 2^44, for http://b/18178121 .
  extinfo.library_fd_offset = (5LL << 48) + kPageSize;
  handle_ = android_dlopen_ext("libname_placeholder", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle_ == nullptr);
  ASSERT_SUBSTR("dlopen failed: file offset for the library \"libname_placeholder\" >= file size", dlerror());

  extinfo.library_fd_offset = 0LL - kPageSize;
  handle_ = android_dlopen_ext("libname_placeholder", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle_ == nullptr);
  ASSERT_SUBSTR("dlopen failed: file offset for the library \"libname_placeholder\" is negative", dlerror());

  extinfo.library_fd_offset = 0;
  handle_ = android_dlopen_ext("libname_ignored", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle_ == nullptr);
  ASSERT_EQ("dlopen failed: \"" + lib_path + "\" has bad ELF magic: 504b0304", dlerror());

  // Check if dlsym works after unsuccessful dlopen().
  // Supply non-exiting one to make linker visit every soinfo.
  void* sym = dlsym(RTLD_DEFAULT, "this_symbol_does_not_exist___");
  ASSERT_TRUE(sym == nullptr);

  close(extinfo.library_fd);
}

TEST_F(DlExtTest, ExtInfoUseOffsetWithoutFd) {
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET;
  // This offset will not be used, so it doesn't matter.
  extinfo.library_fd_offset = 0;

  handle_ = android_dlopen_ext("/some/lib/that/does_not_exist", RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle_ == nullptr);
  ASSERT_STREQ("dlopen failed: invalid extended flag combination (ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET without ANDROID_DLEXT_USE_LIBRARY_FD): 0x20", dlerror());
}

TEST(dlext, android_dlopen_ext_force_load_smoke) {
  DlfcnSymlink symlink("android_dlopen_ext_force_load_smoke");
  const std::string symlink_name = basename(symlink.get_symlink_path().c_str());
  // 1. Open actual file
  void* handle = dlopen("libdlext_test.so", RTLD_NOW);
  ASSERT_DL_NOTNULL(handle);
  // 2. Open link with force_load flag set
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_FORCE_LOAD;
  void* handle2 = android_dlopen_ext(symlink_name.c_str(), RTLD_NOW, &extinfo);
  ASSERT_DL_NOTNULL(handle2);
  ASSERT_TRUE(handle != handle2);

  dlclose(handle2);
  dlclose(handle);
}

TEST(dlext, android_dlopen_ext_force_load_soname_exception) {
  DlfcnSymlink symlink("android_dlopen_ext_force_load_soname_exception");
  const std::string symlink_name = basename(symlink.get_symlink_path().c_str());
  // Check if soname lookup still returns already loaded library
  // when ANDROID_DLEXT_FORCE_LOAD flag is specified.
  void* handle = dlopen(symlink_name.c_str(), RTLD_NOW);
  ASSERT_DL_NOTNULL(handle);

  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_FORCE_LOAD;

  // Note that 'libdlext_test.so' is dt_soname for the symlink_name
  void* handle2 = android_dlopen_ext("libdlext_test.so", RTLD_NOW, &extinfo);

  ASSERT_DL_NOTNULL(handle2);
  ASSERT_TRUE(handle == handle2);

  dlclose(handle2);
  dlclose(handle);
}

TEST(dlfcn, dlopen_from_nullptr_android_api_level_28) {
  // Regression test for http://b/123972211. Testing dlopen(nullptr) when target sdk is P
  android_set_application_target_sdk_version(28);
  ASSERT_TRUE(dlopen(nullptr, RTLD_NOW) != nullptr);
}

// Test system path translation for backward compatibility. http://b/130219528
TEST(dlfcn, dlopen_system_libicuuc_android_api_level_28) {
  android_set_application_target_sdk_version(28);
  ASSERT_TRUE(dlopen(PATH_TO_SYSTEM_LIB "libicuuc.so", RTLD_NOW) != nullptr);
  ASSERT_TRUE(dlopen(PATH_TO_SYSTEM_LIB "libicui18n.so", RTLD_NOW) != nullptr);
}

TEST(dlfcn, dlopen_system_libicuuc_android_api_level_29) {
  android_set_application_target_sdk_version(29);
  ASSERT_TRUE(dlopen(PATH_TO_SYSTEM_LIB "libicuuc.so", RTLD_NOW) == nullptr);
  ASSERT_TRUE(dlopen(PATH_TO_SYSTEM_LIB "libicui18n.so", RTLD_NOW) == nullptr);
}

TEST(dlfcn, dlopen_system_libicuuc_android_api_level_current) {
  ASSERT_TRUE(dlopen(PATH_TO_SYSTEM_LIB "libicuuc.so", RTLD_NOW) == nullptr);
  ASSERT_TRUE(dlopen(PATH_TO_SYSTEM_LIB "libicui18n.so", RTLD_NOW) == nullptr);
}

TEST(dlfcn, dlopen_from_zip_absolute_path) {
  const std::string lib_zip_path = "/libdlext_test_zip/libdlext_test_zip_zipaligned.zip";
  const std::string lib_path = GetTestLibRoot() + lib_zip_path;

  void* handle = dlopen((lib_path + "!/libdir/libatest_simple_zip.so").c_str(), RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  uint32_t* taxicab_number = reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_testlib_taxicab_number"));
  ASSERT_DL_NOTNULL(taxicab_number);
  EXPECT_EQ(1729U, *taxicab_number);

  dlclose(handle);
}

TEST(dlfcn, dlopen_from_zip_with_dt_runpath) {
  const std::string lib_zip_path = "/libdlext_test_runpath_zip/libdlext_test_runpath_zip_zipaligned.zip";
  const std::string lib_path = GetTestLibRoot() + lib_zip_path;

  void* handle = dlopen((lib_path + "!/libdir/libtest_dt_runpath_d_zip.so").c_str(), RTLD_NOW);

  ASSERT_TRUE(handle != nullptr) << dlerror();

  typedef void *(* dlopen_b_fn)();
  dlopen_b_fn fn = (dlopen_b_fn)dlsym(handle, "dlopen_b");
  ASSERT_TRUE(fn != nullptr) << dlerror();

  void *p = fn();
  ASSERT_TRUE(p != nullptr) << dlerror();

  dlclose(p);
  dlclose(handle);
}

TEST(dlfcn, dlopen_from_zip_ld_library_path) {
  const std::string lib_zip_path = "/libdlext_test_zip/libdlext_test_zip_zipaligned.zip";
  const std::string lib_path = GetTestLibRoot() + lib_zip_path + "!/libdir";

  typedef void (*fn_t)(const char*);
  fn_t android_update_LD_LIBRARY_PATH =
      reinterpret_cast<fn_t>(dlsym(RTLD_DEFAULT, "android_update_LD_LIBRARY_PATH"));

  ASSERT_TRUE(android_update_LD_LIBRARY_PATH != nullptr) << dlerror();

  void* handle = dlopen("libdlext_test_zip.so", RTLD_NOW);
  ASSERT_TRUE(handle == nullptr);

  android_update_LD_LIBRARY_PATH(lib_path.c_str());

  handle = dlopen("libdlext_test_zip.so", RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  int (*fn)(void);
  fn = reinterpret_cast<int (*)(void)>(dlsym(handle, "getRandomNumber"));
  ASSERT_TRUE(fn != nullptr);
  EXPECT_EQ(4, fn());

  uint32_t* taxicab_number =
          reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_testlib_taxicab_number"));
  ASSERT_DL_NOTNULL(taxicab_number);
  EXPECT_EQ(1729U, *taxicab_number);

  dlclose(handle);
}


TEST_F(DlExtTest, Reserved) {
  void* start = mmap(nullptr, kLibSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_TRUE(start != MAP_FAILED);
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_RESERVED_ADDRESS;
  extinfo.reserved_addr = start;
  extinfo.reserved_size = kLibSize;
  handle_ = android_dlopen_ext(kLibName, RTLD_NOW, &extinfo);
  ASSERT_DL_NOTNULL(handle_);
  fn f = reinterpret_cast<fn>(dlsym(handle_, "getRandomNumber"));
  ASSERT_DL_NOTNULL(f);
  EXPECT_GE(reinterpret_cast<void*>(f), start);
  EXPECT_LT(reinterpret_cast<void*>(f),
            reinterpret_cast<char*>(start) + kLibSize);
  EXPECT_EQ(4, f());

  // Check that after dlclose reserved address space is unmapped (and can be reused)
  dlclose(handle_);
  handle_ = nullptr;

  void* new_start = mmap(start, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(start, new_start) << "dlclose unmapped reserved space";
}

TEST_F(DlExtTest, ReservedTooSmall) {
  void* start = mmap(nullptr, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_TRUE(start != MAP_FAILED);
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_RESERVED_ADDRESS;
  extinfo.reserved_addr = start;
  extinfo.reserved_size = kPageSize;
  handle_ = android_dlopen_ext(kLibName, RTLD_NOW, &extinfo);
  EXPECT_EQ(nullptr, handle_);
}

TEST_F(DlExtTest, ReservedRecursive) {
  void* start = mmap(nullptr, kLibSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_TRUE(start != MAP_FAILED);
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_RESERVED_ADDRESS | ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE;
  extinfo.reserved_addr = start;
  extinfo.reserved_size = kLibSize;
  handle_ = android_dlopen_ext(kLibNameRecursive, RTLD_NOW, &extinfo);
  ASSERT_DL_NOTNULL(handle_);

  fn f = reinterpret_cast<fn>(dlsym(handle_, "getRandomNumber"));
  ASSERT_DL_NOTNULL(f);
  EXPECT_GE(reinterpret_cast<void*>(f), start);
  EXPECT_LT(reinterpret_cast<void*>(f),
            reinterpret_cast<char*>(start) + kLibSize);
  EXPECT_EQ(4, f());

  f = reinterpret_cast<fn>(dlsym(handle_, "getBiggerRandomNumber"));
  ASSERT_DL_NOTNULL(f);
  EXPECT_GE(reinterpret_cast<void*>(f), start);
  EXPECT_LT(reinterpret_cast<void*>(f),
            reinterpret_cast<char*>(start) + kLibSize);
  EXPECT_EQ(8, f());

  uint32_t* taxicab_number = reinterpret_cast<uint32_t*>(dlsym(handle_, "dlopen_testlib_taxicab_number"));
  ASSERT_DL_NOTNULL(taxicab_number);
  // Untag the pointer so that it can be compared with start, which will be untagged.
  void* addr = reinterpret_cast<void*>(untag_address(taxicab_number));
  EXPECT_GE(addr, start);
  EXPECT_LT(addr, reinterpret_cast<char*>(start) + kLibSize);
  EXPECT_EQ(1729U, *taxicab_number);
}

TEST_F(DlExtTest, ReservedRecursiveTooSmall) {
  void* start = mmap(nullptr, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_TRUE(start != MAP_FAILED);
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_RESERVED_ADDRESS | ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE;
  extinfo.reserved_addr = start;
  extinfo.reserved_size = kPageSize;
  handle_ = android_dlopen_ext(kLibNameRecursive, RTLD_NOW, &extinfo);
  EXPECT_EQ(nullptr, handle_);
}

TEST_F(DlExtTest, ReservedHint) {
  void* start = mmap(nullptr, kLibSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_TRUE(start != MAP_FAILED);
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_RESERVED_ADDRESS_HINT;
  extinfo.reserved_addr = start;
  extinfo.reserved_size = kLibSize;
  handle_ = android_dlopen_ext(kLibName, RTLD_NOW, &extinfo);
  ASSERT_DL_NOTNULL(handle_);
  fn f = reinterpret_cast<fn>(dlsym(handle_, "getRandomNumber"));
  ASSERT_DL_NOTNULL(f);
  EXPECT_GE(reinterpret_cast<void*>(f), start);
  EXPECT_LT(reinterpret_cast<void*>(f),
            reinterpret_cast<char*>(start) + kLibSize);
  EXPECT_EQ(4, f());
}

TEST_F(DlExtTest, ReservedHintTooSmall) {
  void* start = mmap(nullptr, kPageSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_TRUE(start != MAP_FAILED);
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_RESERVED_ADDRESS_HINT;
  extinfo.reserved_addr = start;
  extinfo.reserved_size = kPageSize;
  handle_ = android_dlopen_ext(kLibName, RTLD_NOW, &extinfo);
  ASSERT_DL_NOTNULL(handle_);
  fn f = reinterpret_cast<fn>(dlsym(handle_, "getRandomNumber"));
  ASSERT_DL_NOTNULL(f);
  EXPECT_TRUE(reinterpret_cast<void*>(f) < start ||
              (reinterpret_cast<void*>(f) >= reinterpret_cast<char*>(start) + kPageSize));
  EXPECT_EQ(4, f());
}

class DlExtRelroSharingTest : public DlExtTest {
protected:
  void SetUp() override {
    DlExtTest::SetUp();
    void* start = mmap(nullptr, kLibSize, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_TRUE(start != MAP_FAILED);
    extinfo_.flags = ANDROID_DLEXT_RESERVED_ADDRESS;
    extinfo_.reserved_addr = start;
    extinfo_.reserved_size = kLibSize;
    extinfo_.relro_fd = -1;
  }

  void TearDown() override {
    DlExtTest::TearDown();
  }

  void CreateRelroFile(const char* lib, const char* relro_file, bool recursive) {
    int relro_fd = open(relro_file, O_RDWR | O_TRUNC | O_CLOEXEC);
    ASSERT_NOERROR(relro_fd);

    if (recursive) {
      extinfo_.flags |= ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE;
    }

    pid_t pid = fork();
    if (pid == 0) {
      // child process
      extinfo_.flags |= ANDROID_DLEXT_WRITE_RELRO;
      extinfo_.relro_fd = relro_fd;
      void* handle = android_dlopen_ext(lib, RTLD_NOW, &extinfo_);
      if (handle == nullptr) {
        fprintf(stderr, "in child: %s\n", dlerror());
        exit(1);
      }
      fn f = reinterpret_cast<fn>(dlsym(handle, "getRandomNumber"));
      ASSERT_DL_NOTNULL(f);
      EXPECT_EQ(4, f());

      if (recursive) {
        fn f = reinterpret_cast<fn>(dlsym(handle, "getBiggerRandomNumber"));
        ASSERT_DL_NOTNULL(f);
        EXPECT_EQ(8, f());
      }

      uint32_t* taxicab_number =
              reinterpret_cast<uint32_t*>(dlsym(handle, "dlopen_testlib_taxicab_number"));
      ASSERT_DL_NOTNULL(taxicab_number);
      EXPECT_EQ(1729U, *taxicab_number);
      exit(testing::Test::HasFailure());
    }

    // continuing in parent
    ASSERT_NOERROR(close(relro_fd));
    ASSERT_NOERROR(pid);
    AssertChildExited(pid, 0);

    // reopen file for reading so it can be used
    relro_fd = open(relro_file, O_RDONLY | O_CLOEXEC);
    ASSERT_NOERROR(relro_fd);
    extinfo_.flags |= ANDROID_DLEXT_USE_RELRO;
    extinfo_.relro_fd = relro_fd;
  }

  void TryUsingRelro(const char* lib, bool recursive) {
    handle_ = android_dlopen_ext(lib, RTLD_NOW, &extinfo_);
    ASSERT_DL_NOTNULL(handle_);
    fn f = reinterpret_cast<fn>(dlsym(handle_, "getRandomNumber"));
    ASSERT_DL_NOTNULL(f);
    EXPECT_EQ(4, f());

    if (recursive) {
      fn f = reinterpret_cast<fn>(dlsym(handle_, "getBiggerRandomNumber"));
      ASSERT_DL_NOTNULL(f);
      EXPECT_EQ(8, f());
    }

    uint32_t* taxicab_number =
            reinterpret_cast<uint32_t*>(dlsym(handle_, "dlopen_testlib_taxicab_number"));
    ASSERT_DL_NOTNULL(taxicab_number);
    EXPECT_EQ(1729U, *taxicab_number);
  }

  void SpawnChildrenAndMeasurePss(const char* lib, const char* relro_file, bool share_relro,
                                  size_t* pss_out);

  std::string FindMappingName(void* ptr);

  android_dlextinfo extinfo_;
};

TEST_F(DlExtRelroSharingTest, ChildWritesGoodData) {
  TemporaryFile tf; // Use tf to get an unique filename.
  ASSERT_NOERROR(close(tf.fd));

  ASSERT_NO_FATAL_FAILURE(CreateRelroFile(kLibName, tf.path, false));
  ASSERT_NO_FATAL_FAILURE(TryUsingRelro(kLibName, false));
  void* relro_data = dlsym(handle_, "lots_of_relro");
  ASSERT_DL_NOTNULL(relro_data);
  EXPECT_EQ(tf.path, FindMappingName(relro_data));

  // Use destructor of tf to close and unlink the file.
  tf.fd = extinfo_.relro_fd;
}

TEST_F(DlExtRelroSharingTest, ChildWritesGoodDataRecursive) {
  TemporaryFile tf; // Use tf to get an unique filename.
  ASSERT_NOERROR(close(tf.fd));

  ASSERT_NO_FATAL_FAILURE(CreateRelroFile(kLibNameRecursive, tf.path, true));
  ASSERT_NO_FATAL_FAILURE(TryUsingRelro(kLibNameRecursive, true));
  void* relro_data = dlsym(handle_, "lots_of_relro");
  ASSERT_DL_NOTNULL(relro_data);
  EXPECT_EQ(tf.path, FindMappingName(relro_data));
  void* recursive_relro_data = dlsym(handle_, "lots_more_relro");
  ASSERT_DL_NOTNULL(recursive_relro_data);
  EXPECT_EQ(tf.path, FindMappingName(recursive_relro_data));


  // Use destructor of tf to close and unlink the file.
  tf.fd = extinfo_.relro_fd;
}

TEST_F(DlExtRelroSharingTest, CheckRelroSizes) {
  TemporaryFile tf1, tf2;
  ASSERT_NOERROR(close(tf1.fd));
  ASSERT_NOERROR(close(tf2.fd));

  ASSERT_NO_FATAL_FAILURE(CreateRelroFile(kLibNameRecursive, tf1.path, false));
  struct stat no_recursive;
  ASSERT_NOERROR(fstat(extinfo_.relro_fd, &no_recursive));
  tf1.fd = extinfo_.relro_fd;

  ASSERT_NO_FATAL_FAILURE(CreateRelroFile(kLibNameRecursive, tf2.path, true));
  struct stat with_recursive;
  ASSERT_NOERROR(fstat(extinfo_.relro_fd, &with_recursive));
  tf2.fd = extinfo_.relro_fd;

  // RELRO file should end up bigger when we use the recursive flag, since it
  // includes data for more than one library.
  ASSERT_GT(with_recursive.st_size, no_recursive.st_size);
}

TEST_F(DlExtRelroSharingTest, ChildWritesNoRelro) {
  TemporaryFile tf; // // Use tf to get an unique filename.
  ASSERT_NOERROR(close(tf.fd));

  ASSERT_NO_FATAL_FAILURE(CreateRelroFile(kLibNameNoRelro, tf.path, false));
  ASSERT_NO_FATAL_FAILURE(TryUsingRelro(kLibNameNoRelro, false));

  // Use destructor of tf to close and unlink the file.
  tf.fd = extinfo_.relro_fd;
}

TEST_F(DlExtRelroSharingTest, RelroFileEmpty) {
  ASSERT_NO_FATAL_FAILURE(TryUsingRelro(kLibName, false));
}

TEST_F(DlExtRelroSharingTest, VerifyMemorySaving) {
  if (geteuid() != 0) GTEST_SKIP() << "This test must be run as root";

  TemporaryFile tf; // Use tf to get an unique filename.
  ASSERT_NOERROR(close(tf.fd));

  ASSERT_NO_FATAL_FAILURE(CreateRelroFile(kLibName, tf.path, false));

  int pipefd[2];
  ASSERT_NOERROR(pipe(pipefd));

  size_t without_sharing, with_sharing;
  ASSERT_NO_FATAL_FAILURE(SpawnChildrenAndMeasurePss(kLibName, tf.path, false, &without_sharing));
  ASSERT_NO_FATAL_FAILURE(SpawnChildrenAndMeasurePss(kLibName, tf.path, true, &with_sharing));
  ASSERT_LT(with_sharing, without_sharing);

  // We expect the sharing to save at least 50% of the library's total PSS.
  // In practice it saves 80%+ for this library in the test.
  size_t pss_saved = without_sharing - with_sharing;
  size_t expected_min_saved = without_sharing / 2;

  EXPECT_LT(expected_min_saved, pss_saved);

  // Use destructor of tf to close and unlink the file.
  tf.fd = extinfo_.relro_fd;
}

void GetPss(bool shared_relro, const char* lib, const char* relro_file, pid_t pid,
            size_t* total_pss) {
  android::meminfo::ProcMemInfo proc_mem(pid);
  const std::vector<android::meminfo::Vma>& maps = proc_mem.MapsWithoutUsageStats();
  ASSERT_GT(maps.size(), 0UL);

  // Calculate total PSS of the library.
  *total_pss = 0;
  bool saw_relro_file = false;
  for (auto& vma : maps) {
    if (android::base::EndsWith(vma.name, lib) || (vma.name == relro_file)) {
      if (vma.name == relro_file) {
          saw_relro_file = true;
      }

      android::meminfo::Vma update_vma(vma);
      ASSERT_TRUE(proc_mem.FillInVmaStats(update_vma));
      *total_pss += update_vma.usage.pss;
    }
  }

  if (shared_relro) ASSERT_TRUE(saw_relro_file);
}

void DlExtRelroSharingTest::SpawnChildrenAndMeasurePss(const char* lib, const char* relro_file,
                                                       bool share_relro, size_t* pss_out) {
  const int CHILDREN = 20;

  // Create children
  pid_t child_pids[CHILDREN];
  int childpipe[CHILDREN];
  for (int i=0; i<CHILDREN; ++i) {
    char read_buf;
    int child_done_pipe[2], parent_done_pipe[2];
    ASSERT_NOERROR(pipe(child_done_pipe));
    ASSERT_NOERROR(pipe(parent_done_pipe));

    pid_t child = fork();
    if (child == 0) {
      // close the 'wrong' ends of the pipes in the child
      close(child_done_pipe[0]);
      close(parent_done_pipe[1]);

      // open the library
      void* handle;
      if (share_relro) {
        handle = android_dlopen_ext(lib, RTLD_NOW, &extinfo_);
      } else {
        handle = dlopen(lib, RTLD_NOW);
      }
      if (handle == nullptr) {
        fprintf(stderr, "in child: %s\n", dlerror());
        exit(1);
      }

      // close write end of child_done_pipe to signal the parent that we're done.
      close(child_done_pipe[1]);

      // wait for the parent to close parent_done_pipe, then exit
      read(parent_done_pipe[0], &read_buf, 1);
      exit(0);
    }

    ASSERT_NOERROR(child);

    // close the 'wrong' ends of the pipes in the parent
    close(child_done_pipe[1]);
    close(parent_done_pipe[0]);

    // wait for the child to be done
    read(child_done_pipe[0], &read_buf, 1);
    close(child_done_pipe[0]);

    // save the child's pid and the parent_done_pipe
    child_pids[i] = child;
    childpipe[i] = parent_done_pipe[1];
  }

  // Sum the PSS of tested library of all the children
  size_t total_pss = 0;
  for (int i=0; i<CHILDREN; ++i) {
    size_t child_pss;
    ASSERT_NO_FATAL_FAILURE(GetPss(share_relro, lib, relro_file, child_pids[i], &child_pss));
    total_pss += child_pss;
  }
  *pss_out = total_pss;

  // Close pipes and wait for children to exit
  for (int i=0; i<CHILDREN; ++i) {
    ASSERT_NOERROR(close(childpipe[i]));
  }
  for (int i = 0; i < CHILDREN; ++i) {
    AssertChildExited(child_pids[i], 0);
  }
}

std::string DlExtRelroSharingTest::FindMappingName(void* ptr) {
  uint64_t addr = reinterpret_cast<uint64_t>(untag_address(ptr));
  std::string found_name = "<not found>";

  EXPECT_TRUE(android::procinfo::ReadMapFile("/proc/self/maps",
                                             [&](const android::procinfo::MapInfo& mapinfo) {
                                               if (addr >= mapinfo.start && addr < mapinfo.end) {
                                                 found_name = mapinfo.name;
                                               }
                                             }));

  return found_name;
}

// Testing namespaces
static const char* g_public_lib = "libnstest_public.so";

// These are libs shared with default namespace
static const std::string g_core_shared_libs = kCoreSharedLibs;

TEST(dlext, ns_smoke) {
  static const char* root_lib = "libnstest_root.so";
  std::string shared_libs = g_core_shared_libs + ":" + g_public_lib;

  ASSERT_FALSE(android_init_anonymous_namespace("", nullptr));
  ASSERT_STREQ("android_init_anonymous_namespace failed: error linking namespaces"
               " \"(anonymous)\"->\"(default)\": the list of shared libraries is empty.",
               dlerror());

  const std::string lib_public_path = GetTestLibRoot() + "/public_namespace_libs/" + g_public_lib;
  void* handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle_public != nullptr) << dlerror();

  ASSERT_TRUE(android_init_anonymous_namespace(shared_libs.c_str(), nullptr)) << dlerror();

  // Check that libraries added to public namespace are not NODELETE
  dlclose(handle_public);
  handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle_public == nullptr);
  ASSERT_EQ(std::string("dlopen failed: library \"") + lib_public_path +
               "\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());

  handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW);

  // create "public namespace", share limited set of public libraries with

  android_namespace_t* ns1 =
          android_create_namespace("private",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_REGULAR,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns1 != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns1, nullptr, shared_libs.c_str())) << dlerror();

  android_namespace_t* ns2 =
          android_create_namespace("private_isolated",
                                   nullptr,
                                   (GetTestLibRoot() + "/private_namespace_libs").c_str(),
                                   ANDROID_NAMESPACE_TYPE_ISOLATED,
                                   nullptr,
                                   nullptr);
  ASSERT_TRUE(ns2 != nullptr) << dlerror();
  ASSERT_TRUE(android_link_namespaces(ns2, nullptr, shared_libs.c_str())) << dlerror();

  // This should not have affect search path for default namespace:
  ASSERT_TRUE(dlopen(root_lib, RTLD_NOW) == nullptr);
  void* handle = dlopen(g_public_lib, RTLD_NOW);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  dlclose(handle);

  // dlopen for a public library using an absolute path should work
  // 1. For isolated namespaces
  android_dlextinfo extinfo;
  extinfo.flags = ANDROID_DLEXT_USE_NAMESPACE;
  extinfo.library_namespace = ns2;
  handle = android_dlopen_ext(lib_public_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  ASSERT_TRUE(handle == handle_public);

  dlclose(handle);

  // 1.1 even if it wasn't loaded before
  dlclose(handle_public);

  handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle_public == nullptr);
  ASSERT_EQ(std::string("dlopen failed: library \"") + lib_public_path +
               "\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());

  handle = android_dlopen_ext(lib_public_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW);
  ASSERT_TRUE(handle == handle_public);

  dlclose(handle);

  // 2. And for regular namespaces (make sure it does not load second copy of the library)
  extinfo.library_namespace = ns1;
  handle = android_dlopen_ext(lib_public_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();
  ASSERT_TRUE(handle == handle_public);

  dlclose(handle);

  // 2.1 Unless it was not loaded before - in which case it will load a duplicate.
  // TODO(dimitry): This is broken. Maybe we need to deprecate non-isolated namespaces?
  dlclose(handle_public);

  handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW | RTLD_NOLOAD);
  ASSERT_TRUE(handle_public == nullptr);
  ASSERT_EQ(std::string("dlopen failed: library \"") + lib_public_path +
               "\" wasn't loaded and RTLD_NOLOAD prevented it", dlerror());

  handle = android_dlopen_ext(lib_public_path.c_str(), RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle != nullptr) << dlerror();

  handle_public = dlopen(lib_public_path.c_str(), RTLD_NOW);

  ASSERT_TRUE(handle != handle_public);

  dlclose(handle);

  extinfo.library_namespace = ns1;

  void* handle1 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle1 != nullptr) << dlerror();

  extinfo.library_namespace = ns2;
  void* handle2 = android_dlopen_ext(root_lib, RTLD_NOW, &extinfo);
  ASSERT_TRUE(handle2 != nullptr) << dlerror();

  ASSERT_TRUE(handle1 != handle2);

  typedef const char* (*fn_t)();

  fn_t ns_get_local_string1 = reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_local_string"));
  ASSERT_TRUE(ns_get_local_string1 != nullptr) << dlerror();
  fn_t ns_get_local_string2 = reinterpret_cast<fn_t>(dlsym(handle2, "ns_get_local_string"));
  ASSERT_TRUE(ns_get_local_string2 != nullptr) << dlerror();

  EXPECT_STREQ("This string is local to root library", ns_get_local_string1());
  EXPECT_STREQ("This string is local to root library", ns_get_local_string2());

  ASSERT_TRUE(ns_get_local_string1() != ns_get_local_string2());

  fn_t ns_get_private_extern_string1 =
          reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_private_extern_string"));
  ASSERT_TRUE(ns_get_private_extern_string1 != nullptr) << dlerror();
  fn_t ns_get_private_extern_string2 =
          reinterpret_cast<fn_t>(dlsym(handle2, "ns_get_private_extern_string"));
  ASSERT_TRUE(ns_get_private_extern_string2 != nullptr) << dlerror();

  EXPECT_STREQ("This string is from private namespace", ns_get_private_extern_string1());
  EXPECT_STREQ("This string is from private namespace", ns_get_private_extern_string2());

  ASSERT_TRUE(ns_get_private_extern_string1() != ns_get_private_extern_string2());

  fn_t ns_get_public_extern_string1 =
          reinterpret_cast<fn_t>(dlsym(handle1, "ns_get_public_extern_string"));
  ASSERT_TRUE(ns_get_public_extern_string1 != nullptr) << dlerror();
  fn_t ns_get_public_extern_string2 =
          reinterpret_cast<fn_t>(dlsym(handle2, "ns_get_public_extern_string"));
  ASSERT_TRUE(ns_get_public_extern_string2 != nullptr) << dlerror();

  EXPECT_STREQ("This string is from pub
```