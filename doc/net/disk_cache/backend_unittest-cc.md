Response:
The user wants to understand the functionality of the `net/disk_cache/backend_unittest.cc` file in Chromium's network stack. I need to:

1. **Summarize the file's purpose:**  It's a unit test suite for the disk cache backend.
2. **Identify connections to JavaScript:** Determine if any of the tested functionalities directly relate to how JavaScript interacts with the cache.
3. **Provide examples of logical reasoning:**  Illustrate how the tests verify specific behaviors with hypothetical inputs and expected outputs.
4. **Point out common usage errors:**  Explain mistakes developers might make when using the disk cache based on the test cases.
5. **Describe user actions leading to this code:** Trace back how a user's interaction with a browser could involve the disk cache and trigger these tests.
6. **Focus on the provided code snippet:**  Only analyze the functionality present in the first part of the file.
这是 `net/disk_cache/backend_unittest.cc` 文件的第一部分，它是一个针对 Chromium 网络栈中磁盘缓存后端功能的**单元测试文件**。

**主要功能归纳:**

* **测试磁盘缓存后端的基本操作:**  例如创建、打开、删除缓存条目（entries），以及查询缓存条目的数量。
* **测试缓存键（key）的处理:**  验证缓存后端对不同大小写、包含特殊字符（例如空字符）的键的处理方式。
* **测试缓存后端的创建和初始化:**  包括在不同缓存类型（例如 DISK_CACHE, MEMORY_CACHE, APP_CACHE, SHADER_CACHE）下的创建行为，以及处理创建失败的情况（例如文件丢失）。
* **测试缓存后端的关闭和清理:**  特别是当存在未完成的 I/O 操作时，测试缓存后端如何安全地关闭。
* **测试缓存大小限制和内存压力管理:**  验证内存缓存如何在达到容量限制时进行条目淘汰，以及如何响应系统内存压力。
* **测试外部文件的处理:**  验证缓存后端在存在外部文件时是否能正常工作。
* **测试缓存的枚举功能:**  验证如何遍历缓存中的条目。
* **测试缓存的恢复机制:**  例如，在索引文件损坏的情况下，应用程序缓存的恢复行为。

**与 JavaScript 的关系 (举例说明):**

虽然这个文件本身是 C++ 代码，用于测试底层的缓存实现，但它所测试的功能直接影响着 JavaScript 在浏览器中的行为。例如：

* **假设输入:**  一个 JavaScript 应用程序尝试通过 `fetch` API 加载一个资源，这个资源之前已经被缓存。
* **对应测试功能:**  `BackendBasics()` 或 `BackendKeying()` 这样的测试用例会验证缓存后端是否能正确地根据请求的 URL（作为缓存键）找到并返回缓存的资源。
* **JavaScript 的功能:**  `fetch` API 会利用网络栈的缓存机制，如果缓存中有对应的条目，浏览器可以直接从缓存中读取数据，而无需再次从网络下载，从而提升页面加载速度。

* **假设输入:**  JavaScript 应用程序尝试加载一个非常大的图片，浏览器决定将这个图片缓存到磁盘以供后续使用。
* **对应测试功能:** `BackendSetSize()` 会测试缓存后端设置最大容量的功能，确保磁盘缓存不会无限增长。
* **JavaScript 的功能:**  如果磁盘缓存已满，后端会根据一定的淘汰策略（例如 LRU - 最近最少使用）删除旧的缓存条目，为新的图片腾出空间。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  调用 `CreateEntry("test_key", ...)` 创建一个缓存条目。
* **逻辑推理:**  `BackendBasics()` 中的相关测试会验证：
    * **输出:**  `GetEntryCount()` 的返回值会增加 1。
    * **输出:**  可以成功调用 `OpenEntry("test_key", ...)` 打开刚刚创建的条目。
    * **输出:**  如果再次调用 `CreateEntry("test_key", ...)` 会返回错误，因为该键的条目已经存在。

* **假设输入:**  调用 `DoomEntry("another_key")` 删除一个缓存条目。
* **逻辑推理:**  `BackendBasics()` 中的相关测试会验证：
    * **输出:**  `GetEntryCount()` 的返回值会减少 1。
    * **输出:**  调用 `OpenEntry("another_key", ...)` 将返回错误，因为该条目已被删除。

**用户或编程常见的使用错误 (举例说明):**

* **错误:**  开发者在不确定缓存是否已经初始化完成的情况下就尝试进行缓存操作。
* **对应测试:**  `CreateBackendDoubleOpenEntry` 测试了在创建第二个缓存实例时，前一个实例可能正在进行操作（例如打开条目），确保后一个实例的创建会等待前一个实例完成。
* **说明:**  如果在缓存初始化完成前进行操作，可能会导致程序崩溃或数据不一致。正确的做法是确保缓存初始化完成的回调被调用后再进行后续操作。

* **错误:**  在多线程环境下，多个线程同时访问和修改同一个缓存条目，没有进行适当的同步。
* **潜在测试 (虽然当前代码段中未直接体现，但在后续部分可能存在):**  可能会有测试用例模拟并发访问，验证缓存后端的线程安全性。
* **说明:**  并发访问可能导致数据竞争和损坏。正确的做法是使用锁或其他同步机制来保护共享的缓存数据。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个网页或资源。**
2. **浏览器发起网络请求。**
3. **网络栈检查本地缓存是否有对应的资源。**
4. **如果缓存中没有，则从网络下载资源，并决定是否将资源缓存起来。**  这个决定可能取决于资源的缓存策略（Cache-Control 头部等）。
5. **如果需要缓存，网络栈会调用磁盘缓存后端的接口 (在这个 `backend_unittest.cc` 文件中测试的功能) 来创建或打开一个缓存条目，并将资源数据写入。**
6. **如果用户之后再次访问相同的网页或资源，网络栈会再次检查缓存。**
7. **如果缓存命中，网络栈会调用磁盘缓存后端的接口来读取缓存的数据，并返回给浏览器，最终显示给用户。**
8. **用户在浏览器设置中清空缓存。** 这会触发网络栈调用磁盘缓存后端的接口来删除缓存条目。

**总结第一部分的功能:**

总而言之，`net/disk_cache/backend_unittest.cc` 的第一部分主要关注于测试磁盘缓存后端最基本的核心功能，包括条目的创建、打开、删除、查询，以及缓存后端的初始化和关闭流程。这些测试确保了底层的缓存机制能够稳定可靠地工作，为浏览器高效地缓存网络资源提供了基础。

### 提示词
```
这是目录为net/disk_cache/backend_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <stdint.h>

#include <memory>
#include <optional>
#include <string_view>

#include "base/containers/queue.h"
#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/memory_pressure_listener.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/field_trial.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_clock.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/process_memory_dump.h"
#include "build/build_config.h"
#include "net/base/cache_type.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/base/tracing.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/blockfile/experiments.h"
#include "net/disk_cache/blockfile/mapped_file.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/disk_cache_test_base.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/memory/mem_backend_impl.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_entry_format.h"
#include "net/disk_cache/simple/simple_histogram_enums.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/disk_cache/simple/simple_synchronous_entry.h"
#include "net/disk_cache/simple/simple_test_util.h"
#include "net/disk_cache/simple/simple_util.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/base/dynamic_annotations.h"

using disk_cache::EntryResult;
using net::test::IsError;
using net::test::IsOk;
using testing::ByRef;
using testing::Contains;
using testing::Eq;
using testing::Field;

#if BUILDFLAG(IS_WIN)
#include <windows.h>

#include "base/win/scoped_handle.h"
#endif

// TODO(crbug.com/41451310): Fix memory leaks in tests and re-enable on LSAN.
#ifdef LEAK_SANITIZER
#define MAYBE_BlockFileOpenOrCreateEntry DISABLED_BlockFileOpenOrCreateEntry
#define MAYBE_NonEmptyCorruptSimpleCacheDoesNotRecover \
  DISABLED_NonEmptyCorruptSimpleCacheDoesNotRecover
#define MAYBE_SimpleOpenOrCreateEntry DISABLED_SimpleOpenOrCreateEntry
#else
#define MAYBE_BlockFileOpenOrCreateEntry BlockFileOpenOrCreateEntry
#define MAYBE_NonEmptyCorruptSimpleCacheDoesNotRecover \
  NonEmptyCorruptSimpleCacheDoesNotRecover
#define MAYBE_SimpleOpenOrCreateEntry SimpleOpenOrCreateEntry
#endif

using base::Time;

namespace {

#if BUILDFLAG(IS_FUCHSIA)
// Load tests with large numbers of file descriptors perform poorly on
// virtualized test execution environments.
// TODO(crbug.com/40560856): Remove this workaround when virtualized test
// performance improves.
const int kLargeNumEntries = 100;
#else
const int kLargeNumEntries = 512;
#endif

}  // namespace

// Tests that can run with different types of caches.
class DiskCacheBackendTest : public DiskCacheTestWithCache {
 protected:
  // Some utility methods:

  // Perform IO operations on the cache until there is pending IO.
  int GeneratePendingIO(net::TestCompletionCallback* cb);

  // Adds 5 sparse entries. |doomed_start| and |doomed_end| if not NULL,
  // will be filled with times, used by DoomEntriesSince and DoomEntriesBetween.
  // There are 4 entries after doomed_start and 2 after doomed_end.
  void InitSparseCache(base::Time* doomed_start, base::Time* doomed_end);

  bool CreateSetOfRandomEntries(std::set<std::string>* key_pool);
  bool EnumerateAndMatchKeys(int max_to_open,
                             TestIterator* iter,
                             std::set<std::string>* keys_to_match,
                             size_t* count);

  // Computes the expected size of entry metadata, i.e. the total size without
  // the actual data stored. This depends only on the entry's |key| size.
  int GetEntryMetadataSize(std::string key);

  // The Simple Backend only tracks the approximate sizes of entries. This
  // rounds the exact size appropriately.
  int GetRoundedSize(int exact_size);

  // Create a default key with the name provided, populate it with
  // CacheTestFillBuffer, and ensure this was done correctly.
  void CreateKeyAndCheck(disk_cache::Backend* cache, std::string key);

  // For the simple cache, wait until indexing has occurred and make sure
  // completes successfully.
  void WaitForSimpleCacheIndexAndCheck(disk_cache::Backend* cache);

  // Run all of the task runners untile idle, covers cache worker pools.
  void RunUntilIdle();

  // Actual tests:
  void BackendBasics();
  void BackendKeying();
  void BackendShutdownWithPendingFileIO(bool fast);
  void BackendShutdownWithPendingIO(bool fast);
  void BackendShutdownWithPendingCreate(bool fast);
  void BackendShutdownWithPendingDoom();
  void BackendSetSize();
  void BackendLoad();
  void BackendChain();
  void BackendValidEntry();
  void BackendInvalidEntry();
  void BackendInvalidEntryRead();
  void BackendInvalidEntryWithLoad();
  void BackendTrimInvalidEntry();
  void BackendTrimInvalidEntry2();
  void BackendEnumerations();
  void BackendEnumerations2();
  void BackendDoomMidEnumeration();
  void BackendInvalidEntryEnumeration();
  void BackendFixEnumerators();
  void BackendDoomRecent();
  void BackendDoomBetween();
  void BackendCalculateSizeOfAllEntries();
  void BackendCalculateSizeOfEntriesBetween(
      bool expect_access_time_range_comparisons);
  void BackendTransaction(const std::string& name, int num_entries, bool load);
  void BackendRecoverInsert();
  void BackendRecoverRemove();
  void BackendRecoverWithEviction();
  void BackendInvalidEntry2();
  void BackendInvalidEntry3();
  void BackendInvalidEntry7();
  void BackendInvalidEntry8();
  void BackendInvalidEntry9(bool eviction);
  void BackendInvalidEntry10(bool eviction);
  void BackendInvalidEntry11(bool eviction);
  void BackendTrimInvalidEntry12();
  void BackendDoomAll();
  void BackendDoomAll2();
  void BackendInvalidRankings();
  void BackendInvalidRankings2();
  void BackendDisable();
  void BackendDisable2();
  void BackendDisable3();
  void BackendDisable4();
  void BackendDisabledAPI();
  void BackendEviction();
  void BackendOpenOrCreateEntry();
  void BackendDeadOpenNextEntry();
  void BackendIteratorConcurrentDoom();
  void BackendValidateMigrated();

  void Test2GiBLimit(net::CacheType type,
                     net::BackendType backend_type,
                     bool expect_limit);
};

void DiskCacheBackendTest::CreateKeyAndCheck(disk_cache::Backend* cache,
                                             std::string key) {
  const int kBufSize = 4 * 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufSize);
  CacheTestFillBuffer(buffer->data(), kBufSize, true);
  TestEntryResultCompletionCallback cb_entry;
  disk_cache::EntryResult result =
      cache->CreateEntry(key, net::HIGHEST, cb_entry.callback());
  result = cb_entry.GetResult(std::move(result));
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  EXPECT_EQ(kBufSize, WriteData(entry, 0, 0, buffer.get(), kBufSize, false));
  entry->Close();
  RunUntilIdle();
}

void DiskCacheBackendTest::WaitForSimpleCacheIndexAndCheck(
    disk_cache::Backend* cache) {
  net::TestCompletionCallback wait_for_index_cb;
  static_cast<disk_cache::SimpleBackendImpl*>(cache)->index()->ExecuteWhenReady(
      wait_for_index_cb.callback());
  int rv = wait_for_index_cb.WaitForResult();
  ASSERT_THAT(rv, IsOk());
  RunUntilIdle();
}

void DiskCacheBackendTest::RunUntilIdle() {
  DiskCacheTestWithCache::RunUntilIdle();
  base::RunLoop().RunUntilIdle();
  disk_cache::FlushCacheThreadForTesting();
}

int DiskCacheBackendTest::GeneratePendingIO(net::TestCompletionCallback* cb) {
  if (!use_current_thread_ && !simple_cache_mode_) {
    ADD_FAILURE();
    return net::ERR_FAILED;
  }

  TestEntryResultCompletionCallback create_cb;
  EntryResult entry_result;
  entry_result =
      cache_->CreateEntry("some key", net::HIGHEST, create_cb.callback());
  entry_result = create_cb.GetResult(std::move(entry_result));
  if (entry_result.net_error() != net::OK)
    return net::ERR_CACHE_CREATE_FAILURE;
  disk_cache::Entry* entry = entry_result.ReleaseEntry();

  const int kSize = 25000;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  int rv = net::OK;
  for (int i = 0; i < 10 * 1024 * 1024; i += 64 * 1024) {
    // We are using the current thread as the cache thread because we want to
    // be able to call directly this method to make sure that the OS (instead
    // of us switching thread) is returning IO pending.
    if (!simple_cache_mode_) {
      rv = static_cast<disk_cache::EntryImpl*>(entry)->WriteDataImpl(
          0, i, buffer.get(), kSize, cb->callback(), false);
    } else {
      rv = entry->WriteData(0, i, buffer.get(), kSize, cb->callback(), false);
    }

    if (rv == net::ERR_IO_PENDING)
      break;
    if (rv != kSize)
      rv = net::ERR_FAILED;
  }

  // Don't call Close() to avoid going through the queue or we'll deadlock
  // waiting for the operation to finish.
  if (!simple_cache_mode_)
    static_cast<disk_cache::EntryImpl*>(entry)->Release();
  else
    entry->Close();

  return rv;
}

void DiskCacheBackendTest::InitSparseCache(base::Time* doomed_start,
                                           base::Time* doomed_end) {
  InitCache();

  const int kSize = 50;
  // This must be greater than MemEntryImpl::kMaxSparseEntrySize.
  const int kOffset = 10 + 1024 * 1024;

  disk_cache::Entry* entry0 = nullptr;
  disk_cache::Entry* entry1 = nullptr;
  disk_cache::Entry* entry2 = nullptr;

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  ASSERT_THAT(CreateEntry("zeroth", &entry0), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry0, 0, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry0, kOffset + kSize, buffer.get(), kSize));
  entry0->Close();

  FlushQueueForTest();
  AddDelay();
  if (doomed_start)
    *doomed_start = base::Time::Now();

  // Order in rankings list:
  // first_part1, first_part2, second_part1, second_part2
  ASSERT_THAT(CreateEntry("first", &entry1), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry1, 0, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry1, kOffset + kSize, buffer.get(), kSize));
  entry1->Close();

  ASSERT_THAT(CreateEntry("second", &entry2), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry2, 0, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry2, kOffset + kSize, buffer.get(), kSize));
  entry2->Close();

  FlushQueueForTest();
  AddDelay();
  if (doomed_end)
    *doomed_end = base::Time::Now();

  // Order in rankings list:
  // third_part1, fourth_part1, third_part2, fourth_part2
  disk_cache::Entry* entry3 = nullptr;
  disk_cache::Entry* entry4 = nullptr;
  ASSERT_THAT(CreateEntry("third", &entry3), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry3, 0, buffer.get(), kSize));
  ASSERT_THAT(CreateEntry("fourth", &entry4), IsOk());
  ASSERT_EQ(kSize, WriteSparseData(entry4, 0, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry3, kOffset + kSize, buffer.get(), kSize));
  ASSERT_EQ(kSize,
            WriteSparseData(entry4, kOffset + kSize, buffer.get(), kSize));
  entry3->Close();
  entry4->Close();

  FlushQueueForTest();
  AddDelay();
}

// Creates entries based on random keys. Stores these keys in |key_pool|.
bool DiskCacheBackendTest::CreateSetOfRandomEntries(
    std::set<std::string>* key_pool) {
  const int kNumEntries = 10;
  const int initial_entry_count = cache_->GetEntryCount();

  for (int i = 0; i < kNumEntries; ++i) {
    std::string key = GenerateKey(true);
    disk_cache::Entry* entry;
    if (CreateEntry(key, &entry) != net::OK) {
      return false;
    }
    key_pool->insert(key);
    entry->Close();
  }
  return key_pool->size() ==
         static_cast<size_t>(cache_->GetEntryCount() - initial_entry_count);
}

// Performs iteration over the backend and checks that the keys of entries
// opened are in |keys_to_match|, then erases them. Up to |max_to_open| entries
// will be opened, if it is positive. Otherwise, iteration will continue until
// OpenNextEntry stops returning net::OK.
bool DiskCacheBackendTest::EnumerateAndMatchKeys(
    int max_to_open,
    TestIterator* iter,
    std::set<std::string>* keys_to_match,
    size_t* count) {
  disk_cache::Entry* entry;

  if (!iter)
    return false;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    if (!entry)
      return false;
    EXPECT_EQ(1U, keys_to_match->erase(entry->GetKey()));
    entry->Close();
    ++(*count);
    if (max_to_open >= 0 && static_cast<int>(*count) >= max_to_open)
      break;
  };

  return true;
}

int DiskCacheBackendTest::GetEntryMetadataSize(std::string key) {
  // For blockfile and memory backends, it is just the key size.
  if (!simple_cache_mode_)
    return key.size();

  // For the simple cache, we must add the file header and EOF, and that for
  // every stream.
  return disk_cache::kSimpleEntryStreamCount *
         (sizeof(disk_cache::SimpleFileHeader) +
          sizeof(disk_cache::SimpleFileEOF) + key.size());
}

int DiskCacheBackendTest::GetRoundedSize(int exact_size) {
  if (!simple_cache_mode_)
    return exact_size;

  return (exact_size + 255) & 0xFFFFFF00;
}

void DiskCacheBackendTest::BackendBasics() {
  InitCache();
  disk_cache::Entry *entry1 = nullptr, *entry2 = nullptr;
  EXPECT_NE(net::OK, OpenEntry("the first key", &entry1));
  ASSERT_THAT(CreateEntry("the first key", &entry1), IsOk());
  ASSERT_TRUE(nullptr != entry1);
  entry1->Close();
  entry1 = nullptr;

  ASSERT_THAT(OpenEntry("the first key", &entry1), IsOk());
  ASSERT_TRUE(nullptr != entry1);
  entry1->Close();
  entry1 = nullptr;

  EXPECT_NE(net::OK, CreateEntry("the first key", &entry1));
  ASSERT_THAT(OpenEntry("the first key", &entry1), IsOk());
  EXPECT_NE(net::OK, OpenEntry("some other key", &entry2));
  ASSERT_THAT(CreateEntry("some other key", &entry2), IsOk());
  ASSERT_TRUE(nullptr != entry1);
  ASSERT_TRUE(nullptr != entry2);
  EXPECT_EQ(2, cache_->GetEntryCount());

  disk_cache::Entry* entry3 = nullptr;
  ASSERT_THAT(OpenEntry("some other key", &entry3), IsOk());
  ASSERT_TRUE(nullptr != entry3);
  EXPECT_TRUE(entry2 == entry3);

  EXPECT_THAT(DoomEntry("some other key"), IsOk());
  EXPECT_EQ(1, cache_->GetEntryCount());
  entry1->Close();
  entry2->Close();
  entry3->Close();

  EXPECT_THAT(DoomEntry("the first key"), IsOk());
  EXPECT_EQ(0, cache_->GetEntryCount());

  ASSERT_THAT(CreateEntry("the first key", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("some other key", &entry2), IsOk());
  entry1->Doom();
  entry1->Close();
  EXPECT_THAT(DoomEntry("some other key"), IsOk());
  EXPECT_EQ(0, cache_->GetEntryCount());
  entry2->Close();
}

TEST_F(DiskCacheBackendTest, Basics) {
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, NewEvictionBasics) {
  SetNewEviction();
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyBasics) {
  SetMemoryOnlyMode();
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, AppCacheBasics) {
  SetCacheType(net::APP_CACHE);
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, ShaderCacheBasics) {
  SetCacheType(net::SHADER_CACHE);
  BackendBasics();
}

void DiskCacheBackendTest::BackendKeying() {
  InitCache();
  const char kName1[] = "the first key";
  const char kName2[] = "the first Key";
  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry(kName1, &entry1), IsOk());

  ASSERT_THAT(CreateEntry(kName2, &entry2), IsOk());
  EXPECT_TRUE(entry1 != entry2) << "Case sensitive";
  entry2->Close();

  char buffer[30];
  base::strlcpy(buffer, kName1, std::size(buffer));
  ASSERT_THAT(OpenEntry(buffer, &entry2), IsOk());
  EXPECT_TRUE(entry1 == entry2);
  entry2->Close();

  base::strlcpy(buffer + 1, kName1, std::size(buffer) - 1);
  ASSERT_THAT(OpenEntry(buffer + 1, &entry2), IsOk());
  EXPECT_TRUE(entry1 == entry2);
  entry2->Close();

  base::strlcpy(buffer + 3, kName1, std::size(buffer) - 3);
  ASSERT_THAT(OpenEntry(buffer + 3, &entry2), IsOk());
  EXPECT_TRUE(entry1 == entry2);
  entry2->Close();

  // Now verify long keys.
  char buffer2[20000];
  memset(buffer2, 's', sizeof(buffer2));
  buffer2[1023] = '\0';
  ASSERT_EQ(net::OK, CreateEntry(buffer2, &entry2)) << "key on block file";
  entry2->Close();

  buffer2[1023] = 'g';
  buffer2[19999] = '\0';
  ASSERT_EQ(net::OK, CreateEntry(buffer2, &entry2)) << "key on external file";
  entry2->Close();
  entry1->Close();

  // Create entries with null terminator(s), and check equality. Note we create
  // the strings via the ctor instead of using literals because literals are
  // implicitly C strings which will stop at the first null terminator.
  std::string key1(4, '\0');
  key1[1] = 's';
  std::string key2(3, '\0');
  key2[1] = 's';
  ASSERT_THAT(CreateEntry(key1, &entry1), IsOk());
  ASSERT_THAT(CreateEntry(key2, &entry2), IsOk());
  EXPECT_TRUE(entry1 != entry2) << "Different lengths";
  EXPECT_EQ(entry1->GetKey(), key1);
  EXPECT_EQ(entry2->GetKey(), key2);
  entry1->Close();
  entry2->Close();
}

TEST_F(DiskCacheBackendTest, Keying) {
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, NewEvictionKeying) {
  SetNewEviction();
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyKeying) {
  SetMemoryOnlyMode();
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, AppCacheKeying) {
  SetCacheType(net::APP_CACHE);
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, ShaderCacheKeying) {
  SetCacheType(net::SHADER_CACHE);
  BackendKeying();
}

TEST_F(DiskCacheTest, CreateBackend) {
  TestBackendResultCompletionCallback cb;

  {
    ASSERT_TRUE(CleanupCacheDir());

    // Test the private factory method(s).
    std::unique_ptr<disk_cache::Backend> cache;
    cache = disk_cache::MemBackendImpl::CreateBackend(0, nullptr);
    ASSERT_TRUE(cache.get());
    cache.reset();

    // Now test the public API.

    disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
        net::DISK_CACHE, net::CACHE_BACKEND_DEFAULT,
        /*file_operations=*/nullptr, cache_path_, 0,
        disk_cache::ResetHandling::kNeverReset, nullptr, cb.callback());
    rv = cb.GetResult(std::move(rv));
    ASSERT_THAT(rv.net_error, IsOk());
    ASSERT_TRUE(rv.backend);
    rv.backend.reset();

    rv = disk_cache::CreateCacheBackend(
        net::MEMORY_CACHE, net::CACHE_BACKEND_DEFAULT,
        /*file_operations=*/nullptr, base::FilePath(), 0,
        disk_cache::ResetHandling::kNeverReset, nullptr, cb.callback());
    rv = cb.GetResult(std::move(rv));
    ASSERT_THAT(rv.net_error, IsOk());
    ASSERT_TRUE(rv.backend);
    rv.backend.reset();
  }

  base::RunLoop().RunUntilIdle();
}

TEST_F(DiskCacheTest, MemBackendPostCleanupCallback) {
  TestBackendResultCompletionCallback cb;

  net::TestClosure on_cleanup;

  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::MEMORY_CACHE, net::CACHE_BACKEND_DEFAULT,
      /*file_operations=*/nullptr, base::FilePath(), 0,
      disk_cache::ResetHandling::kNeverReset, nullptr, on_cleanup.closure(),
      cb.callback());
  rv = cb.GetResult(std::move(rv));
  ASSERT_THAT(rv.net_error, IsOk());
  ASSERT_TRUE(rv.backend);
  // The callback should be posted after backend is destroyed.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(on_cleanup.have_result());

  rv.backend.reset();

  EXPECT_FALSE(on_cleanup.have_result());
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(on_cleanup.have_result());
}

TEST_F(DiskCacheTest, CreateBackendDouble) {
  // Make sure that creation for the second backend for same path happens
  // after the first one completes.
  TestBackendResultCompletionCallback cb, cb2;

  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::APP_CACHE, net::CACHE_BACKEND_DEFAULT, /*file_operations=*/nullptr,
      cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, cb.callback());

  disk_cache::BackendResult rv2 = disk_cache::CreateCacheBackend(
      net::APP_CACHE, net::CACHE_BACKEND_DEFAULT, /*file_operations=*/nullptr,
      cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, cb2.callback());

  rv = cb.GetResult(std::move(rv));
  EXPECT_THAT(rv.net_error, IsOk());
  EXPECT_TRUE(rv.backend);
  disk_cache::FlushCacheThreadForTesting();

  // No rv2.backend yet.
  EXPECT_EQ(net::ERR_IO_PENDING, rv2.net_error);
  EXPECT_FALSE(rv2.backend);
  EXPECT_FALSE(cb2.have_result());

  rv.backend.reset();

  // Now rv2.backend should exist.
  rv2 = cb2.GetResult(std::move(rv2));
  EXPECT_THAT(rv2.net_error, IsOk());
  EXPECT_TRUE(rv2.backend);
}

TEST_F(DiskCacheBackendTest, CreateBackendDoubleOpenEntry) {
  // Demonstrate the creation sequencing with an open entry. This is done
  // with SimpleCache since the block-file cache cancels most of I/O on
  // destruction and blocks for what it can't cancel.

  // Don't try to sanity-check things as a blockfile cache
  SetSimpleCacheMode();

  // Make sure that creation for the second backend for same path happens
  // after the first one completes, and all of its ops complete.
  TestBackendResultCompletionCallback cb, cb2;

  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
      cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, cb.callback());

  disk_cache::BackendResult rv2 = disk_cache::CreateCacheBackend(
      net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
      cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, cb2.callback());

  rv = cb.GetResult(std::move(rv));
  EXPECT_THAT(rv.net_error, IsOk());
  ASSERT_TRUE(rv.backend);
  disk_cache::FlushCacheThreadForTesting();

  // No cache 2 yet.
  EXPECT_EQ(net::ERR_IO_PENDING, rv2.net_error);
  EXPECT_FALSE(rv2.backend);
  EXPECT_FALSE(cb2.have_result());

  TestEntryResultCompletionCallback cb3;
  EntryResult entry_result =
      rv.backend->CreateEntry("key", net::HIGHEST, cb3.callback());
  entry_result = cb3.GetResult(std::move(entry_result));
  ASSERT_EQ(net::OK, entry_result.net_error());

  rv.backend.reset();

  // Still doesn't exist.
  EXPECT_FALSE(cb2.have_result());

  entry_result.ReleaseEntry()->Close();

  // Now should exist.
  rv2 = cb2.GetResult(std::move(rv2));
  EXPECT_THAT(rv2.net_error, IsOk());
  EXPECT_TRUE(rv2.backend);
}

TEST_F(DiskCacheBackendTest, CreateBackendPostCleanup) {
  // Test for the explicit PostCleanupCallback parameter to CreateCacheBackend.

  // Extravagant size payload to make reproducing races easier.
  const int kBufSize = 256 * 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufSize);
  CacheTestFillBuffer(buffer->data(), kBufSize, true);

  SetSimpleCacheMode();
  CleanupCacheDir();

  base::RunLoop run_loop;
  TestBackendResultCompletionCallback cb;

  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
      cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, run_loop.QuitClosure(), cb.callback());
  rv = cb.GetResult(std::move(rv));
  EXPECT_THAT(rv.net_error, IsOk());
  ASSERT_TRUE(rv.backend);

  TestEntryResultCompletionCallback cb2;
  EntryResult result =
      rv.backend->CreateEntry("key", net::HIGHEST, cb2.callback());
  result = cb2.GetResult(std::move(result));
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  EXPECT_EQ(kBufSize, WriteData(entry, 0, 0, buffer.get(), kBufSize, false));
  entry->Close();

  rv.backend.reset();

  // Wait till the post-cleanup callback.
  run_loop.Run();

  // All of the payload should be on disk, despite stream 0 being written
  // back in the async Close()
  base::FilePath entry_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex("key", 0));
  std::optional<int64_t> size = base::GetFileSize(entry_path);
  ASSERT_TRUE(size.has_value());
  EXPECT_GT(size.value(), kBufSize);
}

TEST_F(DiskCacheBackendTest, SimpleCreateBackendRecoveryAppCache) {
  // Tests index recovery in APP_CACHE mode. (This is harder to test for
  // DISK_CACHE since post-cleanup callbacks aren't permitted there).
  const int kBufSize = 4 * 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufSize);
  CacheTestFillBuffer(buffer->data(), kBufSize, true);

  SetSimpleCacheMode();
  SetCacheType(net::APP_CACHE);
  DisableFirstCleanup();
  CleanupCacheDir();

  base::RunLoop run_loop;
  TestBackendResultCompletionCallback cb;

  // Create a backend with post-cleanup callback specified, in order to know
  // when the index has been written back (so it can be deleted race-free).
  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
      cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, run_loop.QuitClosure(), cb.callback());
  rv = cb.GetResult(std::move(rv));
  EXPECT_THAT(rv.net_error, IsOk());
  ASSERT_TRUE(rv.backend);

  // Create an entry.
  TestEntryResultCompletionCallback cb2;
  disk_cache::EntryResult result =
      rv.backend->CreateEntry("key", net::HIGHEST, cb2.callback());
  result = cb2.GetResult(std::move(result));
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  EXPECT_EQ(kBufSize, WriteData(entry, 0, 0, buffer.get(), kBufSize, false));
  entry->Close();

  rv.backend.reset();

  // Wait till the post-cleanup callback.
  run_loop.Run();

  // Delete the index.
  base::DeleteFile(
      cache_path_.AppendASCII("index-dir").AppendASCII("the-real-index"));

  // Open the cache again. The fixture will also waits for index init.
  InitCache();

  // Entry should not have a trailer size, since can't tell what it should be
  // when doing recovery (and definitely shouldn't interpret last use time as
  // such).
  EXPECT_EQ(0, simple_cache_impl_->index()->GetTrailerPrefetchSize(
                   disk_cache::simple_util::GetEntryHashKey("key")));
}

// Tests that |BackendImpl| fails to initialize with a missing file.
TEST_F(DiskCacheBackendTest, CreateBackend_MissingFile) {
  ASSERT_TRUE(CopyTestCache("bad_entry"));
  base::FilePath filename = cache_path_.AppendASCII("data_1");
  base::DeleteFile(filename);
  net::TestCompletionCallback cb;

  // Blocking shouldn't be needed to create the cache.
  std::optional<base::ScopedDisallowBlocking> disallow_blocking(std::in_place);
  std::unique_ptr<disk_cache::BackendImpl> cache(
      std::make_unique<disk_cache::BackendImpl>(cache_path_, nullptr, nullptr,
                                                net::DISK_CACHE, nullptr));
  cache->Init(cb.callback());
  EXPECT_THAT(cb.WaitForResult(), IsError(net::ERR_FAILED));
  disallow_blocking.reset();

  cache.reset();
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, MemoryListensToMemoryPressure) {
  const int kLimit = 16 * 1024;
  const int kEntrySize = 256;
  SetMaxSize(kLimit);
  SetMemoryOnlyMode();
  InitCache();

  // Fill in to about 80-90% full.
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kEntrySize);
  CacheTestFillBuffer(buffer->data(), kEntrySize, false);

  for (int i = 0; i < 0.9 * (kLimit / kEntrySize); ++i) {
    disk_cache::Entry* entry = nullptr;
    ASSERT_EQ(net::OK, CreateEntry(base::NumberToString(i), &entry));
    EXPECT_EQ(kEntrySize,
              WriteData(entry, 0, 0, buffer.get(), kEntrySize, true));
    entry->Close();
  }

  EXPECT_GT(CalculateSizeOfAllEntries(), 0.8 * kLimit);

  // Signal low-memory of various sorts, and see how small it gets.
  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE);
  base::RunLoop().RunUntilIdle();
  EXPECT_LT(CalculateSizeOfAllEntries(), 0.5 * kLimit);

  base::MemoryPressureListener::NotifyMemoryPressure(
      base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
  base::RunLoop().RunUntilIdle();
  EXPECT_LT(CalculateSizeOfAllEntries(), 0.1 * kLimit);
}

TEST_F(DiskCacheBackendTest, ExternalFiles) {
  InitCache();
  // First, let's create a file on the folder.
  base::FilePath filename = cache_path_.AppendASCII("f_000001");

  const int kSize = 50;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  ASSERT_TRUE(base::WriteFile(
      filename, std::string_view(buffer1->data(), static_cast<size_t>(kSize))));

  // Now let's create a file with the cache.
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  ASSERT_EQ(0, WriteData(entry, 0, 20000, buffer1.get(), 0, false));
  entry->Close();

  // And verify that the first file is still there.
  auto buffer2(base::MakeRefCounted<net::IOBufferWithSize>(kSize));
  ASSERT_EQ(kSize, base::ReadFile(filename, buffer2->data(), kSize));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer2->data(), kSize));
}

// Tests that we deal with file-level pending operations at destruction time.
void DiskCacheBackendTest::BackendShutdownWithPendingFileIO(bool fast) {
  ASSERT_TRUE(CleanupCacheDir());
  uint32_t flags = disk_cache::kNoBuffering;
  if (!fast)
    flags |= disk_cache::kNoRandom;

  if (!simple_cache_mode_)
    UseCurrentThread();
  CreateBackend(flags);

  net::TestCompletionCallback cb;
  int rv = GeneratePendingIO(&cb);

  // The cache destructor will see one pending operation here.
  ResetCaches();

  if (rv == net::ERR_IO_PENDING) {
    if (fast || simple_cache_mode_)
      EXPECT_FALSE(cb.have_result());
    else
      EXPECT_TRUE(cb.have_result());
  }

  base::RunLoop().RunUntilIdle();

#if !BUILDFLAG(IS_IOS)
  // Wait for the actual operation to complete, or we'll keep a file handle that
  // may cause issues later. Note that on iOS systems even though this test
  // uses a single thread, the actual IO is posted to a worker thread and the
  // cache destructor breaks the link to reach cb when the operation completes.
  rv = cb.GetResult(rv);
#endif
}

TEST_F(DiskCacheBackendTest, ShutdownWithPendingFileIO) {
  BackendShutdownWithPendingFileIO(false);
}

// Here and below, tests that simulate crashes are not compiled in LeakSanitizer
// builds because they contain a lot of intentional memory leaks.
#if !defined(LEAK_SANITIZER)
// We'll be leaking from this test.
TEST_F(DiskCacheBackendTest, ShutdownWithPendingFileIO_Fast) {
  // The integrity test sets kNoRandom so there's a version mismatch if we don't
  // force new eviction.
  SetNewEviction();
  BackendShutdownWithPendingFileIO(true);
}
#endif

// See crbug.com/330074
#if !BUILDFLAG(IS_IOS)
// Tests that one cache instance is not affected by another one going away.
TEST_F(DiskCacheBackendTest, MultipleInstancesWithPendingFileIO) {
  base::ScopedTempDir store;
  ASSERT_TRUE(store.CreateUniqueTempDir());

  net::TestCompletionCallback cb;
  TestBackendResultCompletionCallback create_cb;
  disk_cache::BackendResult backend_rv = disk_cache::CreateCacheBackend(
      net::DISK_CACHE, net::CACHE_BACKEND_DEFAULT, /*file_operations=*/nullptr,
      store.GetPath(), 0, disk_cache::ResetHandling::kNeverReset,
      /* net_log = */ nullptr, create_cb.callback());
  backend_rv = create_cb.GetResult(std::move(backend_rv));
  ASSERT_THAT(backend_rv.net_error, IsOk());
  ASSERT_TRUE(backend_rv.backend);

  AS
```