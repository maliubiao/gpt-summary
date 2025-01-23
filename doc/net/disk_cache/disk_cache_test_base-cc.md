Response:
Let's break down the request and the provided C++ code to generate a comprehensive response.

**1. Understanding the Goal:**

The request asks for an analysis of the C++ source file `net/disk_cache/disk_cache_test_base.cc`. Specifically, it wants to know:

* **Functionality:** What does this file do?
* **JavaScript Relationship:** Does it interact with JavaScript, and how?
* **Logical Reasoning (Example):**  Provide hypothetical inputs and outputs.
* **Common Usage Errors:** What mistakes do developers often make when using it?
* **User Journey (Debugging):** How does a user action lead to this code being executed?

**2. Initial Code Scan and Keyword Identification:**

I'll quickly scan the code for key terms and structures:

* `#include`: Indicates header files, revealing dependencies and core functionalities (e.g., `base/files/file_util.h`, `net/disk_cache/disk_cache.h`, `testing/gtest/include/gtest/gtest.h`).
* `class DiskCacheTest`:  Suggests this is a base class for testing disk cache functionality.
* `class DiskCacheTestWithCache`:  Likely a derived test class that provides a cache instance.
* `InitCache`, `InitMemoryCache`, `InitDiskCache`, `CreateBackend`:  Initialization routines.
* `OpenOrCreateEntry`, `OpenEntry`, `CreateEntry`, `DoomEntry`: Cache entry operations.
* `ReadData`, `WriteData`, `ReadSparseData`, `WriteSparseData`: Data manipulation within cache entries.
* `CreateIterator`:  Iterating over cache entries.
* `SimulateCrash`:  Testing cache robustness under crash scenarios.
* `SetMaxSize`: Configuring cache size.
* `FlushQueueForTest`, `RunTaskForTest`, `TrimForTest`:  Internal testing utilities.
* `CheckCacheIntegrity`:  Verification of cache data integrity.
* `memory_only_`, `simple_cache_mode_`:  Flags indicating different cache implementations being tested.
* `ASSERT_TRUE`, `ASSERT_EQ`, `EXPECT_TRUE`, `EXPECT_THAT`:  GTest assertions, confirming this is definitely a test file.

**3. Formulating the Core Functionality:**

Based on the keywords, the primary function is clear: **This file provides base classes (`DiskCacheTest` and `DiskCacheTestWithCache`) for writing unit tests for Chromium's disk cache.**  It sets up test environments, provides helper functions to interact with the cache, and includes methods for simulating various scenarios (like crashes).

**4. Addressing the JavaScript Relationship:**

A key point is whether this code interacts with JavaScript. After examining the includes and the methods, there's **no direct evidence of JavaScript interaction** within this specific file. It operates at a lower level, dealing with file system operations and cache management. However, the *purpose* of the disk cache is to store web resources, which *are* used by JavaScript in web pages. This is an indirect relationship.

**5. Constructing Logical Reasoning Examples:**

To demonstrate the functionality, I need to create hypothetical test scenarios using the provided methods. I'll pick some common cache operations: creating, writing to, and reading from an entry.

* **Input:** Call `OpenOrCreateEntry` with a key. Write data using `WriteData`. Read data using `ReadData`.
* **Output:**  The `OpenOrCreateEntry` call should return `net::OK` and a valid entry. `WriteData` should return the number of bytes written. `ReadData` should return the same number of bytes read, and the buffer should contain the written data.

**6. Identifying Common Usage Errors:**

As this is a testing base class, the errors are more likely to be related to incorrect usage of the testing framework or misunderstandings about cache behavior. Examples include:

* Not initializing the cache before use.
* Forgetting to release cache entries.
* Making assumptions about cache size or eviction policies without proper setup.

**7. Tracing the User Journey (Debugging):**

This requires thinking about how a user action in Chrome could involve the disk cache. A simple example is loading a webpage:

* **User Action:** User types a URL in the address bar or clicks a link.
* **Browser Request:** Chrome's networking stack initiates a request for the resource.
* **Cache Check:** The networking stack checks the disk cache (`net/disk_cache`) to see if the resource is already present.
* **`OpenEntry` (Potential Call):**  If the cache is checked, methods like `OpenEntry` within the disk cache implementation (which this test file helps verify) might be called.
* **Resource Retrieval:** If the resource is in the cache, it's retrieved from disk. Otherwise, a network request is made, and the response might be stored in the cache using methods tested by this file.

**8. Structuring the Response:**

I'll organize the response according to the prompt's questions, providing clear explanations and examples for each point. I'll use bullet points for clarity.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  The file directly manipulates data seen by JavaScript.
* **Correction:**  While the *purpose* is to cache data used by the web (and thus JavaScript), this C++ file deals with the underlying storage mechanism, not the JavaScript API. The connection is indirect.
* **Initial thought:** Focus only on the `DiskCacheTestWithCache` class.
* **Refinement:**  Recognize that `DiskCacheTest` is a foundational class, and both are important for understanding the file's overall role.
* **Initial thought:**  Provide very technical code examples for usage errors.
* **Refinement:** Focus on higher-level conceptual errors that developers might make when writing tests using these base classes.

By following these steps, iterating through the code, and considering the broader context of Chromium's networking stack, I can construct a detailed and accurate response to the request.
好的，让我们来分析一下 `net/disk_cache/disk_cache_test_base.cc` 这个文件。

**功能列举:**

这个文件定义了两个主要的 C++ 测试基类，用于测试 Chromium 网络栈中的磁盘缓存功能：

1. **`DiskCacheTest`**:
   - 提供基本的测试环境设置和清理，例如创建和删除临时目录作为缓存路径。
   - 提供了复制预先准备好的测试缓存数据的功能 (`CopyTestCache`)。
   - 提供了清理缓存目录的功能 (`CleanupCacheDir`)。

2. **`DiskCacheTestWithCache`**:
   - 继承自 `DiskCacheTest`，并在此基础上提供了更高级的功能，用于与实际的磁盘缓存后端进行交互。
   - 提供了初始化不同类型的缓存后端的能力（内存缓存和磁盘缓存，包括简单的磁盘缓存）。
   - 提供了多种操作缓存条目的方法，例如：
     - `OpenOrCreateEntry`: 打开或创建一个缓存条目。
     - `OpenEntry`: 打开一个已存在的缓存条目。
     - `CreateEntry`: 创建一个新的缓存条目。
     - `DoomEntry`: 删除一个缓存条目。
     - `DoomAllEntries`: 删除所有缓存条目。
     - `DoomEntriesBetween`, `DoomEntriesSince`: 根据时间范围删除缓存条目。
     - `CalculateSizeOfAllEntries`, `CalculateSizeOfEntriesBetween`: 计算缓存条目的大小。
   - 提供了读写缓存条目数据和稀疏数据的方法：
     - `ReadData`, `WriteData`: 读写普通的数据块。
     - `ReadSparseData`, `WriteSparseData`: 读写稀疏数据。
     - `GetAvailableRange`: 获取缓存条目中可用的数据范围。
   - 提供了迭代缓存条目的功能 (`CreateIterator`)。
   - 提供了模拟缓存崩溃的功能 (`SimulateCrash`)。
   - 提供了设置测试模式 (`SetTestMode`) 和最大缓存大小 (`SetMaxSize`) 的功能。
   - 提供了刷新缓存队列 (`FlushQueueForTest`) 和执行特定任务 (`RunTaskForTest`) 的功能，主要用于测试目的。
   - 提供了触发缓存清理 (`TrimForTest`, `TrimDeletedListForTest`) 的功能。
   - 提供了人为增加时间延迟的功能 (`AddDelay`)，这在测试涉及时间相关的缓存行为时很有用。
   - 提供了通知缓存外部命中事件的功能 (`OnExternalCacheHit`)。
   - 提供了获取并释放缓存后端所有权的功能 (`TakeCache`)。
   - 提供了在测试结束时检查缓存完整性的功能 (`CheckCacheIntegrity`)。

**与 JavaScript 的功能关系：**

`net/disk_cache/disk_cache_test_base.cc` 本身是用 C++ 编写的测试代码，**它不直接与 JavaScript 代码交互**。然而，它测试的磁盘缓存功能是浏览器网络栈的核心组成部分，而浏览器网络栈负责加载网页资源，包括 JavaScript 文件。

**举例说明：**

假设一个网页请求了一个 JavaScript 文件 `script.js`。

1. **用户操作：** 用户在浏览器地址栏输入 URL 并回车，或者点击了一个链接。
2. **网络请求：** 浏览器网络栈发起对 `script.js` 的 HTTP 请求。
3. **缓存查找：** 在发起网络请求之前，网络栈会检查磁盘缓存中是否已经存在 `script.js` 的副本。这会涉及到调用磁盘缓存模块提供的接口，而这些接口的正确性就是通过像 `DiskCacheTestWithCache` 这样的测试基类来验证的。
4. **缓存命中：** 如果缓存中存在 `script.js`，磁盘缓存模块会返回缓存的副本，浏览器可以直接使用，无需再次下载。
5. **缓存未命中：** 如果缓存中不存在 `script.js`，浏览器会发起网络请求下载该文件。下载完成后，网络栈可能会将 `script.js` 的内容存储到磁盘缓存中，以便下次使用。存储操作也会通过磁盘缓存模块的接口进行，并由测试代码验证其正确性。
6. **JavaScript 执行：** 最终，浏览器引擎会解析并执行 `script.js` 中的 JavaScript 代码。

**因此，虽然此文件不直接包含 JavaScript 代码，但它测试的磁盘缓存功能对于高效加载包含 JavaScript 的网页至关重要。**  磁盘缓存可以显著减少 JavaScript 文件的加载时间，提升用户体验。

**逻辑推理，假设输入与输出：**

假设我们使用 `DiskCacheTestWithCache` 创建了一个磁盘缓存并进行以下操作：

**假设输入：**

1. 调用 `OpenOrCreateEntry("my_key")` 创建一个名为 "my_key" 的缓存条目。
2. 获取到返回的 `disk_cache::Entry` 指针 `entry`。
3. 创建一个包含 "Hello World" 字符串的 `net::IOBuffer` `write_buffer`，长度为 11。
4. 调用 `WriteData(entry, 0, 0, write_buffer.get(), 11, true)` 将数据写入条目的数据区 0。
5. 调用 `ReadData(entry, 0, 0, read_buffer.get(), 11)` 从条目的数据区 0 读取数据到 `read_buffer`。

**预期输出：**

1. `OpenOrCreateEntry` 返回的 `disk_cache::EntryResult` 的 `net_error()` 应该为 `net::OK`，并且返回的 `Entry` 指针不为空。
2. `WriteData` 的返回值应该为 11，表示成功写入了 11 个字节。
3. `ReadData` 的返回值应该为 11，表示成功读取了 11 个字节。
4. `read_buffer` 的内容应该与 `write_buffer` 的内容相同，即 "Hello World"。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **未初始化缓存：** 在使用 `DiskCacheTestWithCache` 创建的测试环境时，忘记调用 `InitCache()` 初始化缓存后端。这将导致后续的缓存操作失败。

   ```c++
   TEST_F(MyCacheTest, TestWriteWithoutInit) {
     // 忘记调用 InitCache()
     disk_cache::Entry* entry = nullptr;
     int rv = CreateEntry("some_key", &entry);
     EXPECT_NE(net::OK, rv); // 预期创建条目会失败
   }
   ```

2. **忘记释放缓存条目：** 在使用完 `OpenOrCreateEntry`、`OpenEntry` 或 `CreateEntry` 获取到的 `disk_cache::Entry` 指针后，忘记调用 `Release()` 释放条目。这可能导致资源泄漏或死锁，尤其是在长时间运行的测试中。

   ```c++
   TEST_F(MyCacheTest, TestEntryLeak) {
     disk_cache::EntryResult result = OpenOrCreateEntry("another_key");
     ASSERT_TRUE(result.net_error() == net::OK);
     // 忘记调用 result.ReleaseEntry() 或 delete entry
   }
   ```

3. **在错误的线程访问缓存：** 磁盘缓存后端通常有线程模型限制。如果在创建缓存时指定了特定的任务运行器，则必须在该任务运行器关联的线程上执行缓存操作。在其他线程上访问缓存可能导致崩溃或未定义的行为。

4. **假设缓存行为而未进行验证：** 测试代码可能会错误地假设缓存的大小限制或淘汰策略，而没有实际检查这些行为。例如，假设缓存会立即淘汰最旧的条目，但实际上可能存在延迟或其他因素影响淘汰。

5. **不正确地使用完成回调：** 许多缓存操作是异步的，依赖于完成回调来通知操作结果。错误地使用或忽略完成回调可能导致测试失败或hang住。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者在 Chromium 的网络栈中发现了一个关于磁盘缓存的问题，例如某些资源没有被正确缓存，或者缓存的大小增长超出了预期。以下是可能的调试路径：

1. **用户报告问题：** 用户可能会报告网页加载缓慢，或者浏览器使用了大量的磁盘空间。
2. **开发者调查：** 网络栈的开发者开始调查问题，怀疑可能与磁盘缓存有关。
3. **代码审查：** 开发者会查看与磁盘缓存相关的代码，例如 `net/disk_cache` 目录下的文件。
4. **单元测试：** 为了验证磁盘缓存的特定行为，开发者可能会运行现有的单元测试，或者编写新的单元测试来复现问题。`net/disk_cache/disk_cache_test_base.cc` 中定义的基类就是编写这些单元测试的基础。
5. **设置测试环境：** 开发者会使用 `DiskCacheTestWithCache` 创建一个模拟的磁盘缓存环境，并配置相关的参数，例如缓存大小。
6. **模拟用户行为：** 开发者会编写测试代码来模拟用户的操作，例如请求特定的资源，并检查缓存的行为。这可能涉及到调用 `OpenOrCreateEntry`、`WriteData`、`ReadData` 等方法。
7. **断点调试：** 如果单元测试失败，开发者可能会在 `net/disk_cache` 相关的代码中设置断点，例如在 `BackendImpl::OpenOrCreateEntryImpl` 或 `BlockFile::Read` 等函数中，来跟踪代码的执行流程，查看缓存的状态和数据。
8. **日志分析：** 磁盘缓存模块通常会输出日志信息。开发者可以分析这些日志，了解缓存的操作过程，例如哪些条目被创建、删除，以及缓存的大小变化。
9. **问题定位：** 通过单元测试、断点调试和日志分析，开发者可以逐步定位问题的原因，例如是缓存的淘汰策略有问题，还是某些缓存条目没有被正确创建或读取。
10. **修复代码：** 找到问题原因后，开发者会修改相应的 C++ 代码来修复 bug。
11. **验证修复：** 修复代码后，开发者会再次运行单元测试，确保问题得到解决，并且没有引入新的问题。

因此，`net/disk_cache/disk_cache_test_base.cc` 虽然本身不是用户直接交互的代码，但它是保证磁盘缓存功能正确性的重要组成部分，是开发者进行调试和验证的关键工具。当用户遇到与缓存相关的网络问题时，开发者很可能会通过运行或编写基于这个文件的单元测试来诊断和解决问题。

### 提示词
```
这是目录为net/disk_cache/disk_cache_test_base.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/disk_cache_test_base.h"

#include <memory>
#include <utility>

#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/platform_thread.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/memory/mem_backend_impl.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_file_tracker.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsOk;

DiskCacheTest::DiskCacheTest() {
  CHECK(temp_dir_.CreateUniqueTempDir());
  // Put the cache into a subdir of |temp_dir_|, to permit tests to safely
  // remove the cache directory without risking collisions with other tests.
  cache_path_ = temp_dir_.GetPath().AppendASCII("cache");
  CHECK(base::CreateDirectory(cache_path_));
}

DiskCacheTest::~DiskCacheTest() = default;

bool DiskCacheTest::CopyTestCache(const std::string& name) {
  base::FilePath path;
  base::PathService::Get(base::DIR_SRC_TEST_DATA_ROOT, &path);
  path = path.AppendASCII("net");
  path = path.AppendASCII("data");
  path = path.AppendASCII("cache_tests");
  path = path.AppendASCII(name);

  if (!CleanupCacheDir())
    return false;
  return base::CopyDirectory(path, cache_path_, false);
}

bool DiskCacheTest::CleanupCacheDir() {
  return DeleteCache(cache_path_);
}

void DiskCacheTest::TearDown() {
  RunUntilIdle();
}

DiskCacheTestWithCache::TestIterator::TestIterator(
    std::unique_ptr<disk_cache::Backend::Iterator> iterator)
    : iterator_(std::move(iterator)) {}

DiskCacheTestWithCache::TestIterator::~TestIterator() = default;

int DiskCacheTestWithCache::TestIterator::OpenNextEntry(
    disk_cache::Entry** next_entry) {
  TestEntryResultCompletionCallback cb;
  disk_cache::EntryResult result =
      cb.GetResult(iterator_->OpenNextEntry(cb.callback()));
  int rv = result.net_error();
  *next_entry = result.ReleaseEntry();
  return rv;
}

DiskCacheTestWithCache::DiskCacheTestWithCache() = default;

DiskCacheTestWithCache::~DiskCacheTestWithCache() = default;

void DiskCacheTestWithCache::InitCache() {
  if (memory_only_)
    InitMemoryCache();
  else
    InitDiskCache();

  ASSERT_TRUE(nullptr != cache_);
  if (first_cleanup_)
    ASSERT_EQ(0, cache_->GetEntryCount());
}

// We are expected to leak memory when simulating crashes.
void DiskCacheTestWithCache::SimulateCrash() {
  ASSERT_TRUE(!memory_only_);
  net::TestCompletionCallback cb;
  int rv = cache_impl_->FlushQueueForTest(cb.callback());
  ASSERT_THAT(cb.GetResult(rv), IsOk());
  cache_impl_->ClearRefCountForTest();

  ResetCaches();
  EXPECT_TRUE(CheckCacheIntegrity(cache_path_, new_eviction_, size_, mask_));

  CreateBackend(disk_cache::kNoRandom);
}

void DiskCacheTestWithCache::SetTestMode() {
  ASSERT_TRUE(!memory_only_);
  cache_impl_->SetUnitTestMode();
}

void DiskCacheTestWithCache::SetMaxSize(int64_t size) {
  size_ = size;
  // Cache size should not generally be changed dynamically; it takes
  // backend-specific knowledge to make it even semi-reasonable to do.
  DCHECK(!cache_);
}

disk_cache::EntryResult DiskCacheTestWithCache::OpenOrCreateEntry(
    const std::string& key) {
  return OpenOrCreateEntryWithPriority(key, net::HIGHEST);
}

disk_cache::EntryResult DiskCacheTestWithCache::OpenOrCreateEntryWithPriority(
    const std::string& key,
    net::RequestPriority request_priority) {
  TestEntryResultCompletionCallback cb;
  disk_cache::EntryResult result =
      cache_->OpenOrCreateEntry(key, request_priority, cb.callback());
  return cb.GetResult(std::move(result));
}

int DiskCacheTestWithCache::OpenEntry(const std::string& key,
                                      disk_cache::Entry** entry) {
  return OpenEntryWithPriority(key, net::HIGHEST, entry);
}

int DiskCacheTestWithCache::OpenEntryWithPriority(
    const std::string& key,
    net::RequestPriority request_priority,
    disk_cache::Entry** entry) {
  TestEntryResultCompletionCallback cb;
  disk_cache::EntryResult result =
      cb.GetResult(cache_->OpenEntry(key, request_priority, cb.callback()));
  int rv = result.net_error();
  *entry = result.ReleaseEntry();
  return rv;
}

int DiskCacheTestWithCache::CreateEntry(const std::string& key,
                                        disk_cache::Entry** entry) {
  return CreateEntryWithPriority(key, net::HIGHEST, entry);
}

int DiskCacheTestWithCache::CreateEntryWithPriority(
    const std::string& key,
    net::RequestPriority request_priority,
    disk_cache::Entry** entry) {
  TestEntryResultCompletionCallback cb;
  disk_cache::EntryResult result =
      cb.GetResult(cache_->CreateEntry(key, request_priority, cb.callback()));
  int rv = result.net_error();
  *entry = result.ReleaseEntry();
  return rv;
}

int DiskCacheTestWithCache::DoomEntry(const std::string& key) {
  net::TestCompletionCallback cb;
  int rv = cache_->DoomEntry(key, net::HIGHEST, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::DoomAllEntries() {
  net::TestCompletionCallback cb;
  int rv = cache_->DoomAllEntries(cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::DoomEntriesBetween(const base::Time initial_time,
                                               const base::Time end_time) {
  net::TestCompletionCallback cb;
  int rv = cache_->DoomEntriesBetween(initial_time, end_time, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::DoomEntriesSince(const base::Time initial_time) {
  net::TestCompletionCallback cb;
  int rv = cache_->DoomEntriesSince(initial_time, cb.callback());
  return cb.GetResult(rv);
}

int64_t DiskCacheTestWithCache::CalculateSizeOfAllEntries() {
  net::TestInt64CompletionCallback cb;
  int64_t rv = cache_->CalculateSizeOfAllEntries(cb.callback());
  return cb.GetResult(rv);
}

int64_t DiskCacheTestWithCache::CalculateSizeOfEntriesBetween(
    const base::Time initial_time,
    const base::Time end_time) {
  net::TestInt64CompletionCallback cb;
  int64_t rv = cache_->CalculateSizeOfEntriesBetween(initial_time, end_time,
                                                     cb.callback());
  return cb.GetResult(rv);
}

std::unique_ptr<DiskCacheTestWithCache::TestIterator>
DiskCacheTestWithCache::CreateIterator() {
  return std::make_unique<TestIterator>(cache_->CreateIterator());
}

void DiskCacheTestWithCache::FlushQueueForTest() {
  if (memory_only_)
    return;

  if (simple_cache_impl_) {
    disk_cache::FlushCacheThreadForTesting();
    return;
  }

  DCHECK(cache_impl_);
  net::TestCompletionCallback cb;
  int rv = cache_impl_->FlushQueueForTest(cb.callback());
  EXPECT_THAT(cb.GetResult(rv), IsOk());
}

void DiskCacheTestWithCache::RunTaskForTest(base::OnceClosure closure) {
  if (memory_only_ || !cache_impl_) {
    std::move(closure).Run();
    return;
  }

  net::TestCompletionCallback cb;
  int rv = cache_impl_->RunTaskForTest(std::move(closure), cb.callback());
  EXPECT_THAT(cb.GetResult(rv), IsOk());
}

int DiskCacheTestWithCache::ReadData(disk_cache::Entry* entry,
                                     int index,
                                     int offset,
                                     net::IOBuffer* buf,
                                     int len) {
  net::TestCompletionCallback cb;
  int rv = entry->ReadData(index, offset, buf, len, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::WriteData(disk_cache::Entry* entry,
                                      int index,
                                      int offset,
                                      net::IOBuffer* buf,
                                      int len,
                                      bool truncate) {
  net::TestCompletionCallback cb;
  int rv = entry->WriteData(index, offset, buf, len, cb.callback(), truncate);
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::ReadSparseData(disk_cache::Entry* entry,
                                           int64_t offset,
                                           net::IOBuffer* buf,
                                           int len) {
  net::TestCompletionCallback cb;
  int rv = entry->ReadSparseData(offset, buf, len, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::WriteSparseData(disk_cache::Entry* entry,
                                            int64_t offset,
                                            net::IOBuffer* buf,
                                            int len) {
  net::TestCompletionCallback cb;
  int rv = entry->WriteSparseData(offset, buf, len, cb.callback());
  return cb.GetResult(rv);
}

int DiskCacheTestWithCache::GetAvailableRange(disk_cache::Entry* entry,
                                              int64_t offset,
                                              int len,
                                              int64_t* start) {
  TestRangeResultCompletionCallback cb;
  disk_cache::RangeResult result =
      cb.GetResult(entry->GetAvailableRange(offset, len, cb.callback()));

  if (result.net_error == net::OK) {
    *start = result.start;
    return result.available_len;
  }
  return result.net_error;
}

void DiskCacheTestWithCache::TrimForTest(bool empty) {
  if (memory_only_ || !cache_impl_)
    return;

  RunTaskForTest(base::BindOnce(&disk_cache::BackendImpl::TrimForTest,
                                base::Unretained(cache_impl_), empty));
}

void DiskCacheTestWithCache::TrimDeletedListForTest(bool empty) {
  if (memory_only_ || !cache_impl_)
    return;

  RunTaskForTest(
      base::BindOnce(&disk_cache::BackendImpl::TrimDeletedListForTest,
                     base::Unretained(cache_impl_), empty));
}

void DiskCacheTestWithCache::AddDelay() {
  if (simple_cache_mode_) {
    // The simple cache uses second resolution for many timeouts, so it's safest
    // to advance by at least whole seconds before falling back into the normal
    // disk cache epsilon advance.
    const base::Time initial_time = base::Time::Now();
    do {
      base::PlatformThread::YieldCurrentThread();
    } while (base::Time::Now() - initial_time < base::Seconds(1));
  }

  base::Time initial = base::Time::Now();
  while (base::Time::Now() <= initial) {
    base::PlatformThread::Sleep(base::Milliseconds(1));
  };
}

void DiskCacheTestWithCache::OnExternalCacheHit(const std::string& key) {
  cache_->OnExternalCacheHit(key);
}

std::unique_ptr<disk_cache::Backend> DiskCacheTestWithCache::TakeCache() {
  mem_cache_ = nullptr;
  simple_cache_impl_ = nullptr;
  cache_impl_ = nullptr;
  return std::move(cache_);
}

void DiskCacheTestWithCache::TearDown() {
  RunUntilIdle();
  ResetCaches();
  if (!memory_only_ && !simple_cache_mode_ && integrity_) {
    EXPECT_TRUE(CheckCacheIntegrity(cache_path_, new_eviction_, size_, mask_));
  }
  RunUntilIdle();
  if (simple_cache_mode_ && simple_file_tracker_) {
    EXPECT_TRUE(simple_file_tracker_->IsEmptyForTesting());
  }
  DiskCacheTest::TearDown();
}

void DiskCacheTestWithCache::ResetCaches() {
  // Deletion occurs by `cache` going out of scope.
  std::unique_ptr<disk_cache::Backend> cache = TakeCache();
}

void DiskCacheTestWithCache::InitMemoryCache() {
  auto cache =
      disk_cache::MemBackendImpl::CreateBackend(size_, /*net_log=*/nullptr);
  mem_cache_ = cache.get();
  cache_ = std::move(cache);
  ASSERT_TRUE(cache_);
}

void DiskCacheTestWithCache::InitDiskCache() {
  if (first_cleanup_)
    ASSERT_TRUE(CleanupCacheDir());

  CreateBackend(disk_cache::kNoRandom);
}

void DiskCacheTestWithCache::CreateBackend(uint32_t flags) {
  scoped_refptr<base::SingleThreadTaskRunner> runner;
  if (use_current_thread_)
    runner = base::SingleThreadTaskRunner::GetCurrentDefault();
  else
    runner = nullptr;  // let the backend sort it out.

  if (simple_cache_mode_) {
    DCHECK(!use_current_thread_)
        << "Using current thread unsupported by SimpleCache";
    net::TestCompletionCallback cb;
    // We limit ourselves to 64 fds since OS X by default gives us 256.
    // (Chrome raises the number on startup, but the test fixture doesn't).
    if (!simple_file_tracker_)
      simple_file_tracker_ =
          std::make_unique<disk_cache::SimpleFileTracker>(64);
    std::unique_ptr<disk_cache::SimpleBackendImpl> simple_backend =
        std::make_unique<disk_cache::SimpleBackendImpl>(
            /*file_operations=*/nullptr, cache_path_,
            /* cleanup_tracker = */ nullptr, simple_file_tracker_.get(), size_,
            type_, /*net_log = */ nullptr);
    simple_backend->Init(cb.callback());
    ASSERT_THAT(cb.WaitForResult(), IsOk());
    simple_cache_impl_ = simple_backend.get();
    cache_ = std::move(simple_backend);
    if (simple_cache_wait_for_index_) {
      net::TestCompletionCallback wait_for_index_cb;
      simple_cache_impl_->index()->ExecuteWhenReady(
          wait_for_index_cb.callback());
      int rv = wait_for_index_cb.WaitForResult();
      ASSERT_THAT(rv, IsOk());
    }
    return;
  }

  std::unique_ptr<disk_cache::BackendImpl> cache;
  if (mask_) {
    cache = std::make_unique<disk_cache::BackendImpl>(
        cache_path_, mask_,
        /* cleanup_tracker = */ nullptr, runner, type_,
        /* net_log = */ nullptr);
  } else {
    cache = std::make_unique<disk_cache::BackendImpl>(
        cache_path_, /* cleanup_tracker = */ nullptr, runner, type_,
        /* net_log = */ nullptr);
  }
  cache_impl_ = cache.get();
  cache_ = std::move(cache);
  ASSERT_TRUE(cache_);
  if (size_)
    EXPECT_TRUE(cache_impl_->SetMaxSize(size_));
  if (new_eviction_)
    cache_impl_->SetNewEviction();
  cache_impl_->SetFlags(flags);
  net::TestCompletionCallback cb;
  cache_impl_->Init(cb.callback());
  ASSERT_THAT(cb.WaitForResult(), IsOk());
}
```