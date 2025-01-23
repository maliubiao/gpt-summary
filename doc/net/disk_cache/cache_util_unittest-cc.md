Response:
Let's break down the thought process for analyzing this C++ test file and generating the detailed explanation.

1. **Understand the Goal:** The request asks for the functionality of the C++ test file `cache_util_unittest.cc`, its relation to JavaScript (if any), logical deductions with examples, common usage errors, and debugging information.

2. **Initial Scan for Key Information:**
   - Look at the `#include` directives. They tell us what the code interacts with: file system operations (`base/files/...`), threading (`base/threading/...`), string manipulation (`base/strings/...`), testing frameworks (`testing/gtest/...`, `testing/platform_test.h`), and the target functionality `net/disk_cache/cache_util.h`. The inclusion of `cache_util.h` is crucial, as it defines the functions being tested.
   - Examine the namespace: `namespace disk_cache`. This confirms the tested code is within the disk cache module.
   - Identify the test fixture: `class CacheUtilTest : public PlatformTest`. This indicates the tests are grouped under this class.
   - Look for `TEST_F` macros. These are the individual test cases.

3. **Analyze Each Test Case:**  Go through each `TEST_F` and understand its purpose:

   - `MoveCache`: Tests moving the cache directory. Key assertions: destination directory exists, files are moved, source directory is deleted (or remains on ChromeOS).
   - `DeleteCache`: Tests deleting cache *contents* but keeping the directory. Key assertions: directory exists, files/subdirectories are gone.
   - `DeleteCacheAndDir`: Tests deleting the cache directory itself. Key assertions: directory is gone, files/subdirectories are gone.
   - `CleanupDirectory`: Tests asynchronous cleanup of old cache directories. This involves creating temporary directories and checking if the cleanup function removes them correctly. The asynchronous nature means using `base::RunLoop`. The check involves iterating through the temporary directory to find expected and unexpected files/directories.
   - `CleanupDirectoryFailsWhenParentDirectoryIsInaccessible` (POSIX only): Tests error handling when the *parent* directory of the cache is not accessible (simulated by changing permissions).
   - `CleanupDirectorySucceedsWhenTargetDirectoryIsInaccessible` (POSIX only): Tests that cleanup can still proceed if the *target* cache directory itself is inaccessible (simulated by changing permissions). This highlights a specific behavior or error condition the developers considered.
   - `PreferredCacheSize`: Tests the logic for determining the recommended cache size based on available disk space and potentially feature flags. This is the most complex test case, involving various scenarios and edge cases. Pay close attention to the test data (`kTestCases`) and the logic for applying feature flags.

4. **Identify Core Functionality:** Based on the test cases, the file is primarily testing the following functions from `cache_util.h`:
   - `MoveCache`
   - `DeleteCache`
   - `CleanupDirectory`
   - `PreferredCacheSize`

5. **Analyze JavaScript Relevance:** Carefully consider if any of the tested functionalities have a direct connection to JavaScript. The disk cache is a backend component. JavaScript running in a browser can *trigger* disk cache operations (by fetching resources), but it doesn't directly interact with the functions being tested here. Therefore, the relationship is indirect. Focus on how a JavaScript action *leads* to the execution of these C++ functions.

6. **Logical Deductions (Input/Output):** For each test case, think about a simple scenario and what the expected outcome would be. The `PreferredCacheSize` test already provides explicit input and expected output. For others, create simple examples involving file paths and directory structures.

7. **Common Usage Errors:** Consider how a *developer* using the `cache_util.h` functions might make mistakes. Incorrect file paths, permission issues, and misunderstandings about the difference between `DeleteCache` and `DeleteCacheAndDir` are potential errors.

8. **Debugging Information (User Steps):**  Think about the user actions in a browser that would eventually lead to these cache utility functions being called. Focus on the chain of events: user requests a resource, browser checks cache, cache functions are used for storage/retrieval/maintenance.

9. **Structure the Explanation:** Organize the information logically:
   - Start with a high-level overview of the file's purpose.
   - Detail the functionality of each test case.
   - Address the JavaScript relationship.
   - Provide input/output examples for logical deductions.
   - Discuss common usage errors.
   - Explain the user steps leading to the code.

10. **Refine and Elaborate:** Review the generated explanation for clarity, accuracy, and completeness. Add more details and context where necessary. For example, when discussing `PreferredCacheSize`, explain the different factors influencing the calculation (available space, default size, feature flags).

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Does `PreferredCacheSize` directly impact JavaScript performance?"  **Correction:** While cache size *indirectly* affects performance, the function itself is C++ logic. The direct interaction is through the browser's resource loading mechanism, not direct JavaScript calls.
* **Initial thought:** "Just list the `TEST_F` names." **Refinement:**  Explain the *purpose* of each test case and what it verifies.
* **Initial thought:** "The user never interacts with this directly." **Refinement:** Think about the *indirect* user interaction through browser actions and how those actions trigger the underlying caching mechanisms.

By following this structured approach, systematically analyzing the code, and considering the different aspects of the request, a comprehensive and accurate explanation can be generated.
这个C++文件 `cache_util_unittest.cc` 是 Chromium 网络栈中 `net/disk_cache/cache_util.h` 文件的单元测试文件。它的主要功能是测试 `cache_util.h` 中定义的与磁盘缓存操作相关的实用工具函数。

以下是该文件测试的主要功能点：

**1. 缓存目录的移动 (MoveCache):**

   - **功能:** 测试将整个缓存目录从一个位置移动到另一个位置的功能。
   - **测试场景:**
     - 创建一个包含文件和子目录的缓存目录。
     - 调用 `disk_cache::MoveCache` 函数将缓存目录移动到新的目标位置。
     - 验证目标位置是否存在，并且包含所有原有的文件和子目录。
     - 验证原始缓存目录是否被删除（在非 ChromeOS 平台上）。
   - **假设输入与输出:**
     - **假设输入:**
       - `cache_dir_`:  "/tmp/test_cache/Cache" (包含 file01, .file02, dir01/file03)
       - `dest_dir_`: "/tmp/test_cache/old_Cache_001"
     - **预期输出:**
       - `disk_cache::MoveCache` 返回 `true` (移动成功)。
       - "/tmp/test_cache/old_Cache_001" 目录存在。
       - "/tmp/test_cache/old_Cache_001/file01" 文件存在。
       - "/tmp/test_cache/old_Cache_001/.file02" 文件存在。
       - "/tmp/test_cache/old_Cache_001/dir01" 目录存在。
       - "/tmp/test_cache/old_Cache_001/dir01/file03" 文件存在。
       - 在非 ChromeOS 平台上，"/tmp/test_cache/Cache" 目录不存在。

**2. 缓存内容的删除 (DeleteCache):**

   - **功能:** 测试删除缓存目录中的所有内容，但保留缓存目录本身的功能。
   - **测试场景:**
     - 创建一个包含文件和子目录的缓存目录。
     - 调用 `disk_cache::DeleteCache` 函数，并设置 `delete_於是_dir` 参数为 `false`。
     - 验证缓存目录仍然存在。
     - 验证缓存目录中的文件和子目录都被删除。
   - **假设输入与输出:**
     - **假设输入:**
       - `cache_dir_`: "/tmp/test_cache/Cache" (包含 file01, .file02, dir01/file03)
     - **预期输出:**
       - `disk_cache::DeleteCache` 执行后。
       - "/tmp/test_cache/Cache" 目录存在。
       - "/tmp/test_cache/Cache/dir01" 目录不存在。
       - "/tmp/test_cache/Cache/file01" 文件不存在。
       - "/tmp/test_cache/Cache/.file02" 文件不存在。
       - "/tmp/test_cache/Cache/file03" 文件不存在。

**3. 缓存目录及其内容的删除 (DeleteCacheAndDir):**

   - **功能:** 测试删除整个缓存目录及其所有内容的功能。
   - **测试场景:**
     - 创建一个包含文件和子目录的缓存目录。
     - 调用 `disk_cache::DeleteCache` 函数，并设置 `delete_於是_dir` 参数为 `true`。
     - 验证缓存目录不再存在。
     - 验证缓存目录中的文件和子目录也都被删除。
   - **假设输入与输出:**
     - **假设输入:**
       - `cache_dir_`: "/tmp/test_cache/Cache" (包含 file01, .file02, dir01/file03)
     - **预期输出:**
       - `disk_cache::DeleteCache` 执行后。
       - "/tmp/test_cache/Cache" 目录不存在。
       - "/tmp/test_cache/Cache/dir01" 目录不存在。
       - "/tmp/test_cache/Cache/file01" 文件不存在。
       - "/tmp/test_cache/Cache/.file02" 文件不存在。
       - "/tmp/test_cache/Cache/file03" 文件不存在。

**4. 清理旧的缓存目录 (CleanupDirectory):**

   - **功能:** 测试异步清理旧的缓存目录的功能。这通常用于在缓存移动后清理旧的缓存目录。
   - **测试场景:**
     - 创建一个缓存目录。
     - 调用 `disk_cache::CleanupDirectory` 函数。
     - 异步地验证旧的缓存目录（例如 "old_Cache_000"）最终被删除。
   - **逻辑推理和假设输入与输出:**
     - **假设输入:**
       - `cache_dir_`: "/tmp/test_cache/Cache"
       - 假设在清理过程中，可能存在一个旧的缓存目录 "/tmp/test_cache/old_Cache_000"。
     - **预期输出:**
       - `disk_cache::CleanupDirectory` 最终会删除 "/tmp/test_cache/old_Cache_000" 目录。
       - 测试代码通过轮询检查临时目录的内容来验证这一点。如果发现 "old_Cache_000"，则继续等待，直到它消失。

**5. 处理父目录不可访问的情况 (CleanupDirectoryFailsWhenParentDirectoryIsInaccessible - POSIX):**

   - **功能:** 测试当缓存目录的父目录没有执行权限时，`CleanupDirectory` 函数是否能正确处理并返回失败。
   - **测试场景:**
     - 创建一个缓存目录。
     - 使用 `base::SetPosixFilePermissions` 移除父目录的执行权限。
     - 调用 `disk_cache::CleanupDirectory`。
     - 验证清理操作失败。
   - **假设输入与输出:**
     - **假设输入:**
       - `tmp_dir_.GetPath()` 的权限被设置为 0 (无执行权限)。
       - `cache_dir_`:  "/tmp/test_cache/Cache"
     - **预期输出:**
       - `disk_cache::CleanupDirectory` 完成后，回调函数接收到的 `result` 参数为 `false`。

**6. 处理目标目录不可访问的情况 (CleanupDirectorySucceedsWhenTargetDirectoryIsInaccessible - POSIX):**

   - **功能:** 测试当目标缓存目录本身没有权限时，`CleanupDirectory` 函数是否仍然能成功执行（可能只是无法删除目录内的文件）。
   - **测试场景:**
     - 创建一个缓存目录。
     - 使用 `base::SetPosixFilePermissions` 移除目标缓存目录的权限。
     - 调用 `disk_cache::CleanupDirectory`。
     - 验证清理操作成功（尽管可能无法删除目录内的文件，但清理过程本身没有崩溃）。
   - **假设输入与输出:**
     - **假设输入:**
       - `cache_dir_` 的权限被设置为 0 (无权限)。
     - **预期输出:**
       - `disk_cache::CleanupDirectory` 完成后，回调函数接收到的 `result` 参数为 `true`。

**7. 计算首选缓存大小 (PreferredCacheSize):**

   - **功能:** 测试根据可用磁盘空间和实验配置计算首选缓存大小的功能。
   - **测试场景:**
     - 使用不同的可用磁盘空间值调用 `disk_cache::PreferredCacheSize`。
     - 验证返回的缓存大小是否符合预期，考虑到默认值、百分比以及实验配置。
     - 验证针对特定类型的缓存（例如 WebUI 代码缓存，本地代码缓存）的特殊处理。
   - **逻辑推理和假设输入与输出:**
     - 代码中定义了一个 `kTestCases` 结构体数组，包含了不同的 `available` (可用空间) 输入以及对应的 `expected` (预期缓存大小) 输出。
     - 例如，如果 `available` 是 100 * 1024 * 1024 (100MB)，则在没有实验配置的情况下，预期的缓存大小是 80 * 1024 * 1024 (80MB)。
     - 测试还涵盖了在启用不同的实验配置（例如，将缓存大小调整为可用空间的 200%、250%、300%）时的预期输出。

**与 JavaScript 的关系:**

这个测试文件本身是用 C++ 编写的，用于测试底层的缓存管理功能。JavaScript 代码运行在浏览器中，会触发网络请求，这些请求可能会使用到磁盘缓存。

**举例说明:**

1. **JavaScript 发起网络请求:** 当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个网络请求时，浏览器会先检查磁盘缓存中是否已经存在对应的资源。
2. **C++ 磁盘缓存模块介入:** 如果缓存未命中或需要验证缓存，Chromium 的网络栈中的 C++ 磁盘缓存模块（包括 `cache_util.h` 中定义的函数）会被调用来执行查找、读取或写入缓存的操作。
3. **`MoveCache` 的应用场景:**  例如，在浏览器更新或用户清除浏览器数据时，可能需要将缓存移动到新的位置。虽然 JavaScript 不会直接调用 `MoveCache`，但用户的操作（例如点击“清除缓存”）会触发浏览器内部的逻辑，最终调用这个 C++ 函数。
4. **`DeleteCache` 的应用场景:** 用户清除浏览历史记录或缓存时，浏览器会调用 `DeleteCache` 或 `DeleteCacheAndDir` 来清理磁盘缓存。
5. **`PreferredCacheSize` 的应用场景:** 浏览器启动时，会根据用户的磁盘空间和配置计算一个合适的缓存大小，这会调用 `PreferredCacheSize` 函数。

**用户或编程常见的使用错误:**

由于这是一个单元测试文件，它主要关注的是 `cache_util.h` 中函数的正确性。对于用户或开发者而言，常见的错误可能发生在更高层级的缓存使用或配置上：

1. **错误地配置缓存目录:** 用户可能在配置文件中指定了一个不存在或没有权限的目录作为缓存目录。这会导致缓存功能异常。
2. **手动删除缓存文件导致不一致:** 用户或程序可能会直接删除缓存目录中的文件，而不是通过 Chromium 提供的 API 进行清理。这可能导致缓存索引和实际文件之间的不一致，引发错误。
3. **不理解缓存策略:** 开发者可能没有正确理解浏览器的缓存策略，导致资源被意外地缓存或没有被缓存，从而影响网页性能。
4. **权限问题:** 运行浏览器的用户可能没有足够的权限在指定的缓存目录中创建或修改文件。

**用户操作如何一步步的到达这里 (调试线索):**

虽然用户不会直接“到达”这个 C++ 单元测试代码，但是理解用户操作如何触发相关的缓存操作是调试问题的关键：

1. **用户在浏览器中访问一个网页:**  这是最常见的触发缓存操作的方式。浏览器会检查该网页的资源（HTML, CSS, JavaScript, 图片等）是否已缓存。
2. **用户点击链接或提交表单:** 这会导致新的网络请求，同样会触发缓存检查。
3. **用户清除浏览数据:** 用户在浏览器设置中选择清除浏览历史记录、缓存、Cookie 等，会直接触发 `DeleteCache` 或 `DeleteCacheAndDir` 等函数。
4. **浏览器自动的缓存维护任务:** Chromium 会定期执行一些缓存维护任务，例如清理过期的缓存项或旧的缓存目录，这可能会调用 `CleanupDirectory`.
5. **浏览器更新:**  在浏览器更新时，可能需要移动或迁移缓存数据，这可能会触发 `MoveCache`。
6. **开发者工具的使用:**  开发者可以使用浏览器的开发者工具来禁用缓存、强制刷新缓存等，这些操作会影响缓存的行为。

**总结:**

`cache_util_unittest.cc` 是一个关键的测试文件，用于保证 Chromium 磁盘缓存模块的核心工具函数的正确性和稳定性。它涵盖了缓存的移动、删除、清理以及大小计算等重要功能。虽然 JavaScript 代码不直接调用这些函数，但用户的浏览器操作会间接地触发这些底层 C++ 代码的执行，从而实现高效的资源缓存和管理。

### 提示词
```
这是目录为net/disk_cache/cache_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2011 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>

#include <map>

#include "base/files/file_enumerator.h"
#include "base/files/file_util.h"
#include "base/files/safe_base_name.h"
#include "base/files/scoped_temp_dir.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/threading/platform_thread.h"
#include "build/chromeos_buildflags.h"
#include "net/disk_cache/cache_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

namespace disk_cache {

class CacheUtilTest : public PlatformTest {
 public:
  void SetUp() override {
    PlatformTest::SetUp();
    ASSERT_TRUE(tmp_dir_.CreateUniqueTempDir());
    cache_dir_ = tmp_dir_.GetPath().Append(FILE_PATH_LITERAL("Cache"));
    file1_ = base::FilePath(cache_dir_.Append(FILE_PATH_LITERAL("file01")));
    file2_ = base::FilePath(cache_dir_.Append(FILE_PATH_LITERAL(".file02")));
    dir1_ = base::FilePath(cache_dir_.Append(FILE_PATH_LITERAL("dir01")));
    file3_ = base::FilePath(dir1_.Append(FILE_PATH_LITERAL("file03")));
    ASSERT_TRUE(base::CreateDirectory(cache_dir_));
    FILE *fp = base::OpenFile(file1_, "w");
    ASSERT_TRUE(fp != nullptr);
    base::CloseFile(fp);
    fp = base::OpenFile(file2_, "w");
    ASSERT_TRUE(fp != nullptr);
    base::CloseFile(fp);
    ASSERT_TRUE(base::CreateDirectory(dir1_));
    fp = base::OpenFile(file3_, "w");
    ASSERT_TRUE(fp != nullptr);
    base::CloseFile(fp);
    dest_dir_ = tmp_dir_.GetPath().Append(FILE_PATH_LITERAL("old_Cache_001"));
    dest_file1_ = base::FilePath(dest_dir_.Append(FILE_PATH_LITERAL("file01")));
    dest_file2_ =
        base::FilePath(dest_dir_.Append(FILE_PATH_LITERAL(".file02")));
    dest_dir1_ = base::FilePath(dest_dir_.Append(FILE_PATH_LITERAL("dir01")));
  }

 protected:
  base::ScopedTempDir tmp_dir_;
  base::FilePath cache_dir_;
  base::FilePath file1_;
  base::FilePath file2_;
  base::FilePath dir1_;
  base::FilePath file3_;
  base::FilePath dest_dir_;
  base::FilePath dest_file1_;
  base::FilePath dest_file2_;
  base::FilePath dest_dir1_;

  base::test::TaskEnvironment task_environment_;
};

TEST_F(CacheUtilTest, MoveCache) {
  EXPECT_TRUE(disk_cache::MoveCache(cache_dir_, dest_dir_));
  EXPECT_TRUE(base::PathExists(dest_dir_));
  EXPECT_TRUE(base::PathExists(dest_file1_));
  EXPECT_TRUE(base::PathExists(dest_file2_));
  EXPECT_TRUE(base::PathExists(dest_dir1_));
#if BUILDFLAG(IS_CHROMEOS_ASH)
  EXPECT_TRUE(base::PathExists(cache_dir_)); // old cache dir stays
#else
  EXPECT_FALSE(base::PathExists(cache_dir_)); // old cache is gone
#endif
  EXPECT_FALSE(base::PathExists(file1_));
  EXPECT_FALSE(base::PathExists(file2_));
  EXPECT_FALSE(base::PathExists(dir1_));
}

TEST_F(CacheUtilTest, DeleteCache) {
  disk_cache::DeleteCache(cache_dir_, false);
  EXPECT_TRUE(base::PathExists(cache_dir_)); // cache dir stays
  EXPECT_FALSE(base::PathExists(dir1_));
  EXPECT_FALSE(base::PathExists(file1_));
  EXPECT_FALSE(base::PathExists(file2_));
  EXPECT_FALSE(base::PathExists(file3_));
}

TEST_F(CacheUtilTest, DeleteCacheAndDir) {
  disk_cache::DeleteCache(cache_dir_, true);
  EXPECT_FALSE(base::PathExists(cache_dir_)); // cache dir is gone
  EXPECT_FALSE(base::PathExists(dir1_));
  EXPECT_FALSE(base::PathExists(file1_));
  EXPECT_FALSE(base::PathExists(file2_));
  EXPECT_FALSE(base::PathExists(file3_));
}

TEST_F(CacheUtilTest, CleanupDirectory) {
  base::RunLoop run_loop;
  disk_cache::CleanupDirectory(cache_dir_,
                               base::BindLambdaForTesting([&](bool result) {
                                 EXPECT_TRUE(result);
                                 run_loop.Quit();
                               }));
  run_loop.Run();

  while (true) {
    base::FileEnumerator enumerator(tmp_dir_.GetPath(), /*recursive=*/false,
                                    /*file_type=*/base::FileEnumerator::FILES |
                                        base::FileEnumerator::DIRECTORIES);
    bool found = false;
    while (true) {
      base::FilePath path = enumerator.Next();
      if (path.empty()) {
        break;
      }
      // We're not sure if we see an entry in the directory because it depends
      // on timing, but if we do, it must be "old_Cache_000".
      // Caveat: On ChromeOS, we leave the top-level directory ("Cache") so
      // it must be "Cache" or "old_Cache_000".
      const base::FilePath dirname = path.DirName();
      std::optional<base::SafeBaseName> basename =
          base::SafeBaseName::Create(path);
      ASSERT_EQ(dirname, tmp_dir_.GetPath());
      ASSERT_TRUE(basename.has_value());
#if BUILDFLAG(IS_CHROMEOS_ASH)
      if (basename->path().value() == FILE_PATH_LITERAL("Cache")) {
        // See the comment above.
        ASSERT_TRUE(base::IsDirectoryEmpty(dirname.Append(*basename)));
        continue;
      }
#endif
      ASSERT_EQ(basename->path().value(), FILE_PATH_LITERAL("old_Cache_000"));
      found = true;
    }
    if (!found) {
      break;
    }

    base::PlatformThread::Sleep(base::Milliseconds(10));
  }
}

#if BUILDFLAG(IS_POSIX)
TEST_F(CacheUtilTest, CleanupDirectoryFailsWhenParentDirectoryIsInaccessible) {
  base::RunLoop run_loop;

  ASSERT_TRUE(base::SetPosixFilePermissions(tmp_dir_.GetPath(), /*mode=*/0));
  disk_cache::CleanupDirectory(cache_dir_,
                               base::BindLambdaForTesting([&](bool result) {
                                 EXPECT_FALSE(result);
                                 run_loop.Quit();
                               }));
  run_loop.Run();
}

TEST_F(CacheUtilTest,
       CleanupDirectorySucceedsWhenTargetDirectoryIsInaccessible) {
  base::RunLoop run_loop;

  ASSERT_TRUE(base::SetPosixFilePermissions(cache_dir_, /*mode=*/0));
  disk_cache::CleanupDirectory(cache_dir_,
                               base::BindLambdaForTesting([&](bool result) {
                                 EXPECT_TRUE(result);
                                 run_loop.Quit();
                               }));
  run_loop.Run();
}
#endif

TEST_F(CacheUtilTest, PreferredCacheSize) {
  const struct TestCase {
    int64_t available;
    int expected_without_trial;
    int expected_with_200_trial;
    int expected_with_250_trial;
    int expected_with_300_trial;
  } kTestCases[] = {
      // Weird negative value for available --- return the "default"
      {-1000LL, 80 * 1024 * 1024, 160 * 1024 * 1024, 200 * 1024 * 1024,
       240 * 1024 * 1024},
      {-1LL, 80 * 1024 * 1024, 160 * 1024 * 1024, 200 * 1024 * 1024,
       240 * 1024 * 1024},

      // 0 produces 0.
      {0LL, 0, 0, 0, 0},

      // Cache is 80% of available space, when default cache size is larger than
      // 80% of available space..
      {50 * 1024 * 1024LL, 40 * 1024 * 1024, 40 * 1024 * 1024, 40 * 1024 * 1024,
       40 * 1024 * 1024},
      // Cache is default size, when default size is 10% to 80% of available
      // space.
      {100 * 1024 * 1024LL, 80 * 1024 * 1024, 80 * 1024 * 1024,
       80 * 1024 * 1024, 80 * 1024 * 1024},
      {200 * 1024 * 1024LL, 80 * 1024 * 1024, 80 * 1024 * 1024,
       80 * 1024 * 1024, 80 * 1024 * 1024},
      // Cache is 10% of available space if 2.5 * default size is more than 10%
      // of available space.
      {1000 * 1024 * 1024LL, 100 * 1024 * 1024, 200 * 1024 * 1024,
       200 * 1024 * 1024, 200 * 1024 * 1024},
      {2000 * 1024 * 1024LL, 200 * 1024 * 1024, 400 * 1024 * 1024,
       400 * 1024 * 1024, 400 * 1024 * 1024},
      // Cache is 2.5 * kDefaultCacheSize if 2.5 * kDefaultCacheSize uses from
      // 1% to 10% of available space.
      {10000 * 1024 * 1024LL, 200 * 1024 * 1024, 400 * 1024 * 1024,
       500 * 1024 * 1024, 600 * 1024 * 1024},
      // Otherwise, cache is 1% of available space.
      {20000 * 1024 * 1024LL, 200 * 1024 * 1024, 400 * 1024 * 1024,
       500 * 1024 * 1024, 600 * 1024 * 1024},
      // Until it runs into the cache size cap.
      {32000 * 1024 * 1024LL, 320 * 1024 * 1024, 640 * 1024 * 1024,
       800 * 1024 * 1024, 960 * 1024 * 1024},
      {50000 * 1024 * 1024LL, 320 * 1024 * 1024, 640 * 1024 * 1024,
       800 * 1024 * 1024, 960 * 1024 * 1024},
  };

  for (const auto& test_case : kTestCases) {
    EXPECT_EQ(test_case.expected_without_trial,
              PreferredCacheSize(test_case.available))
        << test_case.available;

    // Preferred size for WebUI code cache matches expected_without_trial but
    // should never be more than 5 MB.
    int expected_webui_code_cache_size =
        std::min(5 * 1024 * 1024, test_case.expected_without_trial);
    EXPECT_EQ(expected_webui_code_cache_size,
              PreferredCacheSize(test_case.available,
                                 net::GENERATED_WEBUI_BYTE_CODE_CACHE))
        << test_case.available;
  }

  // Check that the cache size cap is 50% higher for native code caches.
  EXPECT_EQ(((320 * 1024 * 1024) / 2) * 3,
            PreferredCacheSize(50000 * 1024 * 1024LL,
                               net::GENERATED_NATIVE_CODE_CACHE));

  for (int cache_size_exeriment : {100, 200, 250, 300}) {
    base::test::ScopedFeatureList scoped_feature_list;
    std::map<std::string, std::string> field_trial_params;
    field_trial_params["percent_relative_size"] =
        base::NumberToString(cache_size_exeriment);
    scoped_feature_list.InitAndEnableFeatureWithParameters(
        disk_cache::kChangeDiskCacheSizeExperiment, field_trial_params);

    for (const auto& test_case : kTestCases) {
      int expected = 0;
      switch (cache_size_exeriment) {
        case 100:
          expected = test_case.expected_without_trial;
          break;
        case 200:
          expected = test_case.expected_with_200_trial;
          break;
        case 250:
          expected = test_case.expected_with_250_trial;
          break;
        case 300:
          expected = test_case.expected_with_300_trial;
          break;
      }

      EXPECT_EQ(expected, PreferredCacheSize(test_case.available));

      // For caches other than disk cache, the size is not scaled.
      EXPECT_EQ(test_case.expected_without_trial,
                PreferredCacheSize(test_case.available,
                                   net::GENERATED_BYTE_CODE_CACHE));

      // Preferred size for WebUI code cache is not scaled by the trial, and
      // should never be more than 5 MB.
      int expected_webui_code_cache_size =
          std::min(5 * 1024 * 1024, test_case.expected_without_trial);
      EXPECT_EQ(expected_webui_code_cache_size,
                PreferredCacheSize(test_case.available,
                                   net::GENERATED_WEBUI_BYTE_CODE_CACHE))
          << test_case.available;
    }

    // Check that the cache size cap is 50% higher for native code caches but is
    // not scaled for the experiment.
    EXPECT_EQ(((320 * 1024 * 1024) / 2) * 3,
              PreferredCacheSize(50000 * 1024 * 1024LL,
                                 net::GENERATED_NATIVE_CODE_CACHE));
  }

  // Check no "percent_relative_size" matches default behavior.
  {
    base::test::ScopedFeatureList scoped_feature_list;
    scoped_feature_list.InitAndEnableFeature(
        disk_cache::kChangeDiskCacheSizeExperiment);
    for (const auto& test_case : kTestCases) {
      EXPECT_EQ(test_case.expected_without_trial,
                PreferredCacheSize(test_case.available));
    }
    // Check that the cache size cap is 50% higher for native code caches.
    EXPECT_EQ(((320 * 1024 * 1024) / 2) * 3,
              PreferredCacheSize(50000 * 1024 * 1024LL,
                                 net::GENERATED_NATIVE_CODE_CACHE));
  }
}

}  // namespace disk_cache
```