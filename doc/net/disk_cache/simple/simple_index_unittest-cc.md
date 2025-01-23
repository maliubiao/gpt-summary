Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Subject:** The filename `simple_index_unittest.cc` and the `#include "net/disk_cache/simple/simple_index.h"` immediately tell us that this file tests the `SimpleIndex` class. This is the central piece of information.

2. **Understand the Purpose of Unittests:**  Unittests are designed to isolate and verify the functionality of a specific unit of code (in this case, the `SimpleIndex` class). They achieve this by setting up controlled scenarios, executing specific methods of the unit under test, and asserting that the outcomes match the expected behavior.

3. **Scan for Key Classes and Methods Being Tested:**  Look for the class name being tested in the test fixture names (e.g., `SimpleIndexTest`, `SimpleIndexAppCacheTest`). Also, scan for calls to the methods of the `SimpleIndex` class. Examples here include `Insert`, `Remove`, `Has`, `UseIfExists`, `UpdateEntrySize`, `GetEntryCount`, `SetMaxSize`, `GetLastUsedTime`, `MergeInitializingSet`.

4. **Analyze Individual Tests:**  Go through each `TEST_F` function. For each test, try to understand:
    * **Setup:** What state is being established before the core action? This often involves inserting data or setting specific configurations.
    * **Action:** What method of the `SimpleIndex` class is being called?
    * **Assertions:** What `EXPECT_*` macros are used to verify the outcome? What specific conditions are being checked?  This is crucial for understanding the tested functionality.

5. **Look for Mocking:** The presence of `MockSimpleIndexFile` is a strong indicator of how the `SimpleIndex` interacts with its dependencies (in this case, the underlying file storage). Analyze how the mock is used to control the behavior of the file system during the tests. This is important for understanding how the `SimpleIndex` handles loading and saving data.

6. **Identify Relationships to JavaScript (If Any):** Consider the broader context of Chromium's network stack. The disk cache is used to store web resources. JavaScript running in a browser relies on these cached resources to improve performance. Think about how JavaScript's actions might lead to interactions with the disk cache. Specifically, fetching resources (images, scripts, stylesheets) can trigger cache operations.

7. **Infer Logical Reasoning and Assumptions:** Based on the test names and assertions, infer the logical paths being tested. For example, tests like `BasicInsertRemove`, `BasicInit`, and `BasicEviction` test fundamental operations. Tests with "BeforeInit" suffix explore how the `SimpleIndex` handles operations before the initial loading from disk. Consider the assumptions made by the tests (e.g., the behavior of the mock file system).

8. **Consider User/Programming Errors:** Think about common mistakes developers might make when using a disk cache. Examples include incorrect size limits, unexpected cache behavior, or data corruption. See if the tests implicitly cover such scenarios.

9. **Trace User Operations to the Code:**  Imagine a user interacting with a web page. How might those interactions lead to the execution of the `SimpleIndex` code?  Focus on actions that involve fetching or storing resources (loading a page, clicking a link, downloading a file).

10. **Structure the Output:** Organize the findings into clear categories (Functionality, JavaScript Relationship, Logical Reasoning, Usage Errors, Debugging). Use bullet points and examples to make the information easy to understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This just tests the disk cache."  **Correction:**  "It specifically tests the *index* part of the simple disk cache, which manages metadata about cached entries."
* **Initial thought:** "How does JavaScript relate?" **Refinement:** "JavaScript fetches resources; the cache stores them. Therefore, fetching resources *causes* the cache to be accessed and modified, triggering the `SimpleIndex` code."
* **Overly detailed analysis:**  Spending too much time on every single line of code. **Correction:** Focus on the overall purpose of each test and the key assertions.
* **Forgetting the mock:** Initially focusing too much on the real file system. **Correction:**  Recognize the crucial role of `MockSimpleIndexFile` in isolating the tests.

By following this structured approach and continuously refining understanding, it becomes possible to effectively analyze and explain the functionality of a complex C++ unittest file like this one.
这个文件 `net/disk_cache/simple/simple_index_unittest.cc` 是 Chromium 网络栈中关于 `SimpleIndex` 类的单元测试。`SimpleIndex` 是一个负责管理简单磁盘缓存索引的组件。

**功能列表:**

这个单元测试文件旨在验证 `SimpleIndex` 类的各种功能，包括但不限于：

1. **条目元数据管理 (`EntryMetadata`):**
   - 测试 `EntryMetadata` 类的创建、设置、序列化和反序列化。
   - 验证条目最后使用时间、大小和内存数据的存储和检索。
   - 验证处理过大或过小的最后使用时间时的行为 (饱和处理)。

2. **索引条目的插入和删除:**
   - 测试向索引中插入新的条目。
   - 测试从索引中删除条目。
   - 验证插入和删除操作后索引状态的正确性。

3. **索引条目的查找 (`Has`, `UseIfExists`):**
   - 测试检查索引中是否存在特定条目的功能 (`Has`)。
   - 测试检查条目是否存在并更新其最后使用时间的功能 (`UseIfExists`)。
   - 验证在索引加载完成前后这些功能的行为。

4. **更新条目大小 (`UpdateEntrySize`):**
   - 测试更新索引中现有条目大小的功能。
   - 验证更新后条目大小的正确性。

5. **获取条目数量 (`GetEntryCount`):**
   - 测试获取索引中当前条目数量的功能。
   - 验证插入和删除操作后条目数量的更新。

6. **初始化 (`BasicInit`):**
   - 测试从磁盘加载索引条目的功能。
   - 验证加载的条目信息（最后使用时间、大小）的正确性。
   - 测试在初始化过程中处理已删除或已插入条目的情况。

7. **驱逐 (Eviction):**
   - 测试基于缓存大小限制的条目驱逐机制。
   - 验证驱逐操作触发的时机和被驱逐的条目。
   - 针对不同缓存类型 (例如，代码缓存) 测试不同的驱逐策略。

8. **磁盘写入 (Disk Write):**
   - 测试索引修改后将数据写回磁盘的功能。
   - 验证磁盘写入操作是否被正确地排队和执行。
   - 测试磁盘写入操作的推迟机制。
   - 针对不同缓存类型测试磁盘写入的触发时机。

9. **合并初始化集合 (`MergeInitializingSet`):**
   - 测试在初始化过程中合并从磁盘加载的条目集合。
   - 验证合并后索引大小的正确性。

**与 JavaScript 的关系:**

`SimpleIndex` 本身是一个 C++ 组件，直接与 JavaScript 没有代码层面的交互。然而，它所管理的磁盘缓存是浏览器用来存储网络资源的，这些资源包括 JavaScript 文件、图片、CSS 等。

**举例说明:**

当 JavaScript 代码通过 `fetch` API 或加载网页时请求一个资源时，浏览器会首先检查磁盘缓存中是否存在该资源。`SimpleIndex` 负责快速查找缓存索引，判断资源是否在缓存中，并提供资源的元数据信息（如大小、最后使用时间）。

例如：

1. **JavaScript 发起请求:**
   ```javascript
   fetch('https://example.com/script.js');
   ```
2. **浏览器缓存查找:** 浏览器网络栈会调用 `SimpleIndex` 的相关方法，根据资源的 URL 生成的 Key 来查找缓存索引。
3. **`SimpleIndex` 的作用:**
   - `Has(key)`:  `SimpleIndex` 会检查索引中是否存在与 `script.js` 对应的条目。
   - `UseIfExists(key)`: 如果存在，`SimpleIndex` 可能会更新该条目的最后使用时间。
4. **缓存命中/未命中:** 根据 `SimpleIndex` 的结果，浏览器决定是从缓存加载资源还是重新从网络下载。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 索引当前为空。
* 缓存最大大小设置为 1000 字节。
* 插入三个条目，大小分别为 200 字节 (最后使用时间 T1)，300 字节 (最后使用时间 T2)，和 600 字节 (最后使用时间 T3)，其中 T1 < T2 < T3。

**预期输出 (基于 LRU 驱逐策略):**

* 当插入大小为 600 字节的条目时，缓存大小将超过限制。
* `SimpleIndex` 会触发驱逐操作。
* 由于是 LRU 策略，最后使用时间最早的条目 (200 字节的那个) 和其次最早的条目 (300 字节的那个) 会被标记为驱逐。
* 最终索引中只剩下大小为 600 字节的条目。
* `doom_entries_calls_` 计数器会增加 1。
* `last_doom_entry_hashes()` 会包含被驱逐条目的哈希值。

**用户或编程常见的使用错误:**

1. **缓存大小设置不合理:** 将缓存大小设置得过小会导致频繁的驱逐，降低缓存效率。
   - **例子:** 用户在程序启动时将缓存大小设置为 1MB，但应用程序需要缓存大量的图片和视频资源。这会导致很多资源被频繁地从缓存中删除和重新加载。

2. **错误地估计条目大小:** 在更新条目大小时提供不准确的大小信息可能导致驱逐策略失效。
   - **例子:** 程序员在更新缓存条目大小时，错误地将一个 500KB 的文件报告为 5KB，导致缓存认为有足够的空间，而实际上空间不足，可能导致后续缓存操作失败或性能问题。

3. **在多线程环境下不正确地使用 `SimpleIndex`:**  虽然 `SimpleIndex` 本身可能采取了一些同步机制，但如果在没有适当的锁保护下并发访问和修改索引，可能会导致数据不一致或崩溃。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在 Chrome 浏览器中访问了一个包含大量图片的网页：

1. **用户在地址栏输入网址或点击链接。**
2. **浏览器发起 HTTP 请求获取网页的 HTML 内容。**
3. **浏览器解析 HTML，发现需要加载多个图片资源。**
4. **对于每个图片资源，浏览器检查磁盘缓存。**
5. **检查缓存的过程涉及 `SimpleIndex`:**
   - 浏览器会根据图片资源的 URL 计算一个 Key。
   - 调用 `SimpleIndex->Has(key)` 检查缓存索引中是否存在该 Key。
   - 如果存在，调用 `SimpleIndex->UseIfExists(key)` 更新最后使用时间。
   - 如果不存在，浏览器会发起网络请求下载图片。
6. **下载完成后，图片数据会被写入磁盘缓存。**
7. **写入缓存涉及 `SimpleIndex`:**
   - 调用 `SimpleIndex->Insert(key)` 将新的条目添加到索引。
   - 调用 `SimpleIndex->UpdateEntrySize(key, size)` 更新条目的大小。
8. **如果缓存空间不足，`SimpleIndex` 会触发驱逐。**
   - `SimpleIndex` 内部会根据 LRU 或其他策略选择要驱逐的条目。
   - 调用 `DoomEntries` 回调通知缓存后端删除磁盘上的文件。
9. **定期地或在特定事件触发时，`SimpleIndex` 会将内存中的索引数据写回磁盘。**
   - 调用 `WriteToDisk` 将索引数据写入文件。

**调试线索:**

如果在调试网络缓存相关的问题时，例如：

* **资源应该被缓存但却没有被缓存。**
* **缓存的资源过期时间不正确。**
* **缓存大小异常增长或缩小。**

可以关注 `SimpleIndex` 的行为：

* **检查 `SimpleIndex::Has` 的返回值:**  确认缓存查找是否按预期工作。
* **观察 `SimpleIndex::UseIfExists` 的调用:**  确认访问时间的更新是否正确。
* **监控 `SimpleIndex::Insert` 和 `SimpleIndex::Remove` 的调用:**  确认条目的添加和删除是否符合预期。
* **分析 `SimpleIndex::UpdateEntrySize` 的参数:**  确认条目大小的记录是否正确。
* **查看 `DoomEntries` 的调用:**  了解哪些条目被驱逐以及驱逐的原因。
* **检查磁盘索引文件的内容:**  确认持久化的索引数据是否正确。

通过这些步骤，可以深入了解 `SimpleIndex` 的工作方式，并帮助定位网络缓存相关的错误。

### 提示词
```
这是目录为net/disk_cache/simple/simple_index_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/simple/simple_index.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <utility>

#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/hash/hash.h"
#include "base/memory/raw_ptr.h"
#include "base/pickle.h"
#include "base/strings/stringprintf.h"
#include "base/task/task_runner.h"
#include "base/test/mock_entropy_provider.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "net/base/cache_type.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/disk_cache.h"
#include "net/disk_cache/simple/simple_index_delegate.h"
#include "net/disk_cache/simple/simple_index_file.h"
#include "net/disk_cache/simple/simple_test_util.h"
#include "net/disk_cache/simple/simple_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace disk_cache {
namespace {

const base::Time kTestLastUsedTime = base::Time::UnixEpoch() + base::Days(20);
const uint32_t kTestEntrySize = 789;
const uint8_t kTestEntryMemoryData = 123;

uint32_t RoundSize(uint32_t in) {
  return (in + 0xFFu) & 0xFFFFFF00u;
}

}  // namespace

class EntryMetadataTest : public testing::Test {
 public:
  EntryMetadata NewEntryMetadataWithValues() {
    EntryMetadata entry(kTestLastUsedTime, kTestEntrySize);
    entry.SetInMemoryData(kTestEntryMemoryData);
    return entry;
  }

  void CheckEntryMetadataValues(const EntryMetadata& entry_metadata) {
    EXPECT_LT(kTestLastUsedTime - base::Seconds(2),
              entry_metadata.GetLastUsedTime());
    EXPECT_GT(kTestLastUsedTime + base::Seconds(2),
              entry_metadata.GetLastUsedTime());
    EXPECT_EQ(RoundSize(kTestEntrySize), entry_metadata.GetEntrySize());
    EXPECT_EQ(kTestEntryMemoryData, entry_metadata.GetInMemoryData());
  }
};

class MockSimpleIndexFile final : public SimpleIndexFile {
 public:
  explicit MockSimpleIndexFile(net::CacheType cache_type)
      : SimpleIndexFile(nullptr,
                        base::MakeRefCounted<TrivialFileOperationsFactory>(),
                        cache_type,
                        base::FilePath()) {}

  void LoadIndexEntries(base::Time cache_last_modified,
                        base::OnceClosure callback,
                        SimpleIndexLoadResult* out_load_result) override {
    load_callback_ = std::move(callback);
    load_result_ = out_load_result;
    ++load_index_entries_calls_;
  }

  void WriteToDisk(net::CacheType cache_type,
                   SimpleIndex::IndexWriteToDiskReason reason,
                   const SimpleIndex::EntrySet& entry_set,
                   uint64_t cache_size,
                   base::OnceClosure callback) override {
    disk_writes_++;
    disk_write_entry_set_ = entry_set;
  }

  void GetAndResetDiskWriteEntrySet(SimpleIndex::EntrySet* entry_set) {
    entry_set->swap(disk_write_entry_set_);
  }

  void RunLoadCallback() {
    // Clear dangling reference since callback may destroy `load_result_`.
    load_result_ = nullptr;
    std::move(load_callback_).Run();
  }
  SimpleIndexLoadResult* load_result() const { return load_result_; }
  int load_index_entries_calls() const { return load_index_entries_calls_; }
  int disk_writes() const { return disk_writes_; }

  base::WeakPtr<MockSimpleIndexFile> AsWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  base::OnceClosure load_callback_;
  raw_ptr<SimpleIndexLoadResult> load_result_ = nullptr;
  int load_index_entries_calls_ = 0;
  int disk_writes_ = 0;
  SimpleIndex::EntrySet disk_write_entry_set_;
  base::WeakPtrFactory<MockSimpleIndexFile> weak_ptr_factory_{this};
};

class SimpleIndexTest : public net::TestWithTaskEnvironment,
                        public SimpleIndexDelegate {
 protected:
  SimpleIndexTest() : hashes_(base::BindRepeating(&HashesInitializer)) {}

  static uint64_t HashesInitializer(size_t hash_index) {
    return disk_cache::simple_util::GetEntryHashKey(
        base::StringPrintf("key%d", static_cast<int>(hash_index)));
  }

  void SetUp() override {
    auto index_file = std::make_unique<MockSimpleIndexFile>(CacheType());
    index_file_ = index_file->AsWeakPtr();
    index_ =
        std::make_unique<SimpleIndex>(/* io_thread = */ nullptr,
                                      /* cleanup_tracker = */ nullptr, this,
                                      CacheType(), std::move(index_file));

    index_->Initialize(base::Time());
  }

  void WaitForTimeChange() {
    const base::Time initial_time = base::Time::Now();
    do {
      base::PlatformThread::YieldCurrentThread();
    } while (base::Time::Now() - initial_time < base::Seconds(1));
  }

  // From SimpleIndexDelegate:
  void DoomEntries(std::vector<uint64_t>* entry_hashes,
                   net::CompletionOnceCallback callback) override {
    for (const uint64_t& entry_hash : *entry_hashes)
      index_->Remove(entry_hash);
    last_doom_entry_hashes_ = *entry_hashes;
    ++doom_entries_calls_;
  }

  // Redirect to allow single "friend" declaration in base class.
  bool GetEntryForTesting(uint64_t key, EntryMetadata* metadata) {
    auto it = index_->entries_set_.find(key);
    if (index_->entries_set_.end() == it)
      return false;
    *metadata = it->second;
    return true;
  }

  void InsertIntoIndexFileReturn(uint64_t hash_key,
                                 base::Time last_used_time,
                                 int entry_size) {
    index_file_->load_result()->entries.emplace(
        hash_key, EntryMetadata(last_used_time,
                                base::checked_cast<uint32_t>(entry_size)));
  }

  void ReturnIndexFile() {
    index_file_->load_result()->did_load = true;
    index_file_->RunLoadCallback();
  }

  // Non-const for timer manipulation.
  SimpleIndex* index() { return index_.get(); }
  const MockSimpleIndexFile* index_file() const { return index_file_.get(); }

  const std::vector<uint64_t>& last_doom_entry_hashes() const {
    return last_doom_entry_hashes_;
  }
  int doom_entries_calls() const { return doom_entries_calls_; }

  virtual net::CacheType CacheType() const { return net::DISK_CACHE; }

  const simple_util::ImmutableArray<uint64_t, 16> hashes_;
  std::unique_ptr<SimpleIndex> index_;
  base::WeakPtr<MockSimpleIndexFile> index_file_;

  std::vector<uint64_t> last_doom_entry_hashes_;
  int doom_entries_calls_ = 0;
};

class SimpleIndexAppCacheTest : public SimpleIndexTest {
 protected:
  net::CacheType CacheType() const override { return net::APP_CACHE; }
};

class SimpleIndexCodeCacheTest : public SimpleIndexTest {
 protected:
  net::CacheType CacheType() const override {
    return net::GENERATED_BYTE_CODE_CACHE;
  }
};

TEST_F(EntryMetadataTest, Basics) {
  EntryMetadata entry_metadata;
  EXPECT_EQ(base::Time(), entry_metadata.GetLastUsedTime());
  EXPECT_EQ(0u, entry_metadata.GetEntrySize());
  EXPECT_EQ(0u, entry_metadata.GetInMemoryData());

  entry_metadata = NewEntryMetadataWithValues();
  CheckEntryMetadataValues(entry_metadata);

  const base::Time new_time = base::Time::Now();
  entry_metadata.SetLastUsedTime(new_time);

  EXPECT_LT(new_time - base::Seconds(2), entry_metadata.GetLastUsedTime());
  EXPECT_GT(new_time + base::Seconds(2), entry_metadata.GetLastUsedTime());
}

// Tests that setting an unusually small/large last used time results in
// truncation (rather than crashing).
TEST_F(EntryMetadataTest, SaturatedLastUsedTime) {
  EntryMetadata entry_metadata;

  // Set a time that is too large to be represented internally as 32-bit unix
  // timestamp. Will saturate to a large timestamp (in year 2106).
  entry_metadata.SetLastUsedTime(base::Time::Max());
  EXPECT_EQ(INT64_C(15939440895000000),
            entry_metadata.GetLastUsedTime().ToInternalValue());

  // Set a time that is too small to be represented by a unix timestamp (before
  // 1970).
  entry_metadata.SetLastUsedTime(
      base::Time::FromInternalValue(7u));  // This is a date in 1601.
  EXPECT_EQ(base::Time::UnixEpoch() + base::Seconds(1),
            entry_metadata.GetLastUsedTime());
}

TEST_F(EntryMetadataTest, Serialize) {
  EntryMetadata entry_metadata = NewEntryMetadataWithValues();

  base::Pickle pickle;
  entry_metadata.Serialize(net::DISK_CACHE, &pickle);

  base::PickleIterator it(pickle);
  EntryMetadata new_entry_metadata;
  new_entry_metadata.Deserialize(net::DISK_CACHE, &it, true, true);
  CheckEntryMetadataValues(new_entry_metadata);

  // Test reading of old format --- the modern serialization of above entry
  // corresponds, in older format, to an entry with size =
  //   RoundSize(kTestEntrySize) | kTestEntryMemoryData, which then gets
  // rounded again when stored by EntryMetadata.
  base::PickleIterator it2(pickle);
  EntryMetadata new_entry_metadata2;
  new_entry_metadata2.Deserialize(net::DISK_CACHE, &it2, false, false);
  EXPECT_EQ(RoundSize(RoundSize(kTestEntrySize) | kTestEntryMemoryData),
            new_entry_metadata2.GetEntrySize());
  EXPECT_EQ(0, new_entry_metadata2.GetInMemoryData());
}

TEST_F(SimpleIndexTest, IndexSizeCorrectOnMerge) {
  const unsigned int kSizeResolution = 256u;
  index()->SetMaxSize(100 * kSizeResolution);
  index()->Insert(hashes_.at<2>());
  index()->UpdateEntrySize(hashes_.at<2>(), 2u * kSizeResolution);
  index()->Insert(hashes_.at<3>());
  index()->UpdateEntrySize(hashes_.at<3>(), 3u * kSizeResolution);
  index()->Insert(hashes_.at<4>());
  index()->UpdateEntrySize(hashes_.at<4>(), 4u * kSizeResolution);
  EXPECT_EQ(9u * kSizeResolution, index()->cache_size_);
  {
    auto result = std::make_unique<SimpleIndexLoadResult>();
    result->did_load = true;
    index()->MergeInitializingSet(std::move(result));
  }
  EXPECT_EQ(9u * kSizeResolution, index()->cache_size_);
  {
    auto result = std::make_unique<SimpleIndexLoadResult>();
    result->did_load = true;
    const uint64_t new_hash_key = hashes_.at<11>();
    result->entries.emplace(
        new_hash_key, EntryMetadata(base::Time::Now(), 11u * kSizeResolution));
    const uint64_t redundant_hash_key = hashes_.at<4>();
    result->entries.emplace(
        redundant_hash_key,
        EntryMetadata(base::Time::Now(), 4u * kSizeResolution));
    index()->MergeInitializingSet(std::move(result));
  }
  EXPECT_EQ((2u + 3u + 4u + 11u) * kSizeResolution, index()->cache_size_);
}

// State of index changes as expected with an insert and a remove.
TEST_F(SimpleIndexTest, BasicInsertRemove) {
  // Confirm blank state.
  EntryMetadata metadata;
  EXPECT_EQ(base::Time(), metadata.GetLastUsedTime());
  EXPECT_EQ(0U, metadata.GetEntrySize());

  // Confirm state after insert.
  index()->Insert(hashes_.at<1>());
  ASSERT_TRUE(GetEntryForTesting(hashes_.at<1>(), &metadata));
  base::Time now(base::Time::Now());
  EXPECT_LT(now - base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_GT(now + base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_EQ(0U, metadata.GetEntrySize());

  // Confirm state after remove.
  metadata = EntryMetadata();
  index()->Remove(hashes_.at<1>());
  EXPECT_FALSE(GetEntryForTesting(hashes_.at<1>(), &metadata));
  EXPECT_EQ(base::Time(), metadata.GetLastUsedTime());
  EXPECT_EQ(0U, metadata.GetEntrySize());
}

TEST_F(SimpleIndexTest, Has) {
  // Confirm the base index has dispatched the request for index entries.
  EXPECT_TRUE(index_file_.get());
  EXPECT_EQ(1, index_file_->load_index_entries_calls());

  // Confirm "Has()" always returns true before the callback is called.
  const uint64_t kHash1 = hashes_.at<1>();
  EXPECT_TRUE(index()->Has(kHash1));
  index()->Insert(kHash1);
  EXPECT_TRUE(index()->Has(kHash1));
  index()->Remove(kHash1);
  // TODO(morlovich): Maybe return false on explicitly removed entries?
  EXPECT_TRUE(index()->Has(kHash1));

  ReturnIndexFile();

  // Confirm "Has() returns conditionally now.
  EXPECT_FALSE(index()->Has(kHash1));
  index()->Insert(kHash1);
  EXPECT_TRUE(index()->Has(kHash1));
  index()->Remove(kHash1);
}

TEST_F(SimpleIndexTest, UseIfExists) {
  // Confirm the base index has dispatched the request for index entries.
  EXPECT_TRUE(index_file_.get());
  EXPECT_EQ(1, index_file_->load_index_entries_calls());

  // Confirm "UseIfExists()" always returns true before the callback is called
  // and updates mod time if the entry was really there.
  const uint64_t kHash1 = hashes_.at<1>();
  EntryMetadata metadata1, metadata2;
  EXPECT_TRUE(index()->UseIfExists(kHash1));
  EXPECT_FALSE(GetEntryForTesting(kHash1, &metadata1));
  index()->Insert(kHash1);
  EXPECT_TRUE(index()->UseIfExists(kHash1));
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata1));
  WaitForTimeChange();
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata2));
  EXPECT_EQ(metadata1.GetLastUsedTime(), metadata2.GetLastUsedTime());
  EXPECT_TRUE(index()->UseIfExists(kHash1));
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata2));
  EXPECT_LT(metadata1.GetLastUsedTime(), metadata2.GetLastUsedTime());
  index()->Remove(kHash1);
  EXPECT_TRUE(index()->UseIfExists(kHash1));

  ReturnIndexFile();

  // Confirm "UseIfExists() returns conditionally now
  EXPECT_FALSE(index()->UseIfExists(kHash1));
  EXPECT_FALSE(GetEntryForTesting(kHash1, &metadata1));
  index()->Insert(kHash1);
  EXPECT_TRUE(index()->UseIfExists(kHash1));
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata1));
  WaitForTimeChange();
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata2));
  EXPECT_EQ(metadata1.GetLastUsedTime(), metadata2.GetLastUsedTime());
  EXPECT_TRUE(index()->UseIfExists(kHash1));
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata2));
  EXPECT_LT(metadata1.GetLastUsedTime(), metadata2.GetLastUsedTime());
  index()->Remove(kHash1);
  EXPECT_FALSE(index()->UseIfExists(kHash1));
}

TEST_F(SimpleIndexTest, UpdateEntrySize) {
  base::Time now(base::Time::Now());

  index()->SetMaxSize(1000);

  const uint64_t kHash1 = hashes_.at<1>();
  InsertIntoIndexFileReturn(kHash1, now - base::Days(2), 475);
  ReturnIndexFile();

  EntryMetadata metadata;
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata));
  EXPECT_LT(now - base::Days(2) - base::Seconds(1), metadata.GetLastUsedTime());
  EXPECT_GT(now - base::Days(2) + base::Seconds(1), metadata.GetLastUsedTime());
  EXPECT_EQ(RoundSize(475u), metadata.GetEntrySize());

  index()->UpdateEntrySize(kHash1, 600u);
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata));
  EXPECT_EQ(RoundSize(600u), metadata.GetEntrySize());
  EXPECT_EQ(1, index()->GetEntryCount());
}

TEST_F(SimpleIndexTest, GetEntryCount) {
  EXPECT_EQ(0, index()->GetEntryCount());
  index()->Insert(hashes_.at<1>());
  EXPECT_EQ(1, index()->GetEntryCount());
  index()->Insert(hashes_.at<2>());
  EXPECT_EQ(2, index()->GetEntryCount());
  index()->Insert(hashes_.at<3>());
  EXPECT_EQ(3, index()->GetEntryCount());
  index()->Insert(hashes_.at<3>());
  EXPECT_EQ(3, index()->GetEntryCount());
  index()->Remove(hashes_.at<2>());
  EXPECT_EQ(2, index()->GetEntryCount());
  index()->Insert(hashes_.at<4>());
  EXPECT_EQ(3, index()->GetEntryCount());
  index()->Remove(hashes_.at<3>());
  EXPECT_EQ(2, index()->GetEntryCount());
  index()->Remove(hashes_.at<3>());
  EXPECT_EQ(2, index()->GetEntryCount());
  index()->Remove(hashes_.at<1>());
  EXPECT_EQ(1, index()->GetEntryCount());
  index()->Remove(hashes_.at<4>());
  EXPECT_EQ(0, index()->GetEntryCount());
}

// Confirm that we get the results we expect from a simple init.
TEST_F(SimpleIndexTest, BasicInit) {
  base::Time now(base::Time::Now());

  InsertIntoIndexFileReturn(hashes_.at<1>(), now - base::Days(2), 10u);
  InsertIntoIndexFileReturn(hashes_.at<2>(), now - base::Days(3), 1000u);

  ReturnIndexFile();

  EntryMetadata metadata;
  EXPECT_TRUE(GetEntryForTesting(hashes_.at<1>(), &metadata));
  EXPECT_EQ(metadata.GetLastUsedTime(),
            index()->GetLastUsedTime(hashes_.at<1>()));
  EXPECT_LT(now - base::Days(2) - base::Seconds(1), metadata.GetLastUsedTime());
  EXPECT_GT(now - base::Days(2) + base::Seconds(1), metadata.GetLastUsedTime());
  EXPECT_EQ(RoundSize(10u), metadata.GetEntrySize());
  EXPECT_TRUE(GetEntryForTesting(hashes_.at<2>(), &metadata));
  EXPECT_EQ(metadata.GetLastUsedTime(),
            index()->GetLastUsedTime(hashes_.at<2>()));
  EXPECT_LT(now - base::Days(3) - base::Seconds(1), metadata.GetLastUsedTime());
  EXPECT_GT(now - base::Days(3) + base::Seconds(1), metadata.GetLastUsedTime());
  EXPECT_EQ(RoundSize(1000u), metadata.GetEntrySize());
  EXPECT_EQ(base::Time(), index()->GetLastUsedTime(hashes_.at<3>()));
}

// Remove something that's going to come in from the loaded index.
TEST_F(SimpleIndexTest, RemoveBeforeInit) {
  const uint64_t kHash1 = hashes_.at<1>();
  index()->Remove(kHash1);

  InsertIntoIndexFileReturn(kHash1, base::Time::Now() - base::Days(2), 10u);
  ReturnIndexFile();

  EXPECT_FALSE(index()->Has(kHash1));
}

// Insert something that's going to come in from the loaded index; correct
// result?
TEST_F(SimpleIndexTest, InsertBeforeInit) {
  const uint64_t kHash1 = hashes_.at<1>();
  index()->Insert(kHash1);

  InsertIntoIndexFileReturn(kHash1, base::Time::Now() - base::Days(2), 10u);
  ReturnIndexFile();

  EntryMetadata metadata;
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata));
  base::Time now(base::Time::Now());
  EXPECT_LT(now - base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_GT(now + base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_EQ(0U, metadata.GetEntrySize());
}

// Insert and Remove something that's going to come in from the loaded index.
TEST_F(SimpleIndexTest, InsertRemoveBeforeInit) {
  const uint64_t kHash1 = hashes_.at<1>();
  index()->Insert(kHash1);
  index()->Remove(kHash1);

  InsertIntoIndexFileReturn(kHash1, base::Time::Now() - base::Days(2), 10u);
  ReturnIndexFile();

  EXPECT_FALSE(index()->Has(kHash1));
}

// Insert and Remove something that's going to come in from the loaded index.
TEST_F(SimpleIndexTest, RemoveInsertBeforeInit) {
  const uint64_t kHash1 = hashes_.at<1>();
  index()->Remove(kHash1);
  index()->Insert(kHash1);

  InsertIntoIndexFileReturn(kHash1, base::Time::Now() - base::Days(2), 10u);
  ReturnIndexFile();

  EntryMetadata metadata;
  EXPECT_TRUE(GetEntryForTesting(kHash1, &metadata));
  base::Time now(base::Time::Now());
  EXPECT_LT(now - base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_GT(now + base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_EQ(0U, metadata.GetEntrySize());
}

// Do all above tests at once + a non-conflict to test for cross-key
// interactions.
TEST_F(SimpleIndexTest, AllInitConflicts) {
  base::Time now(base::Time::Now());

  index()->Remove(hashes_.at<1>());
  InsertIntoIndexFileReturn(hashes_.at<1>(), now - base::Days(2), 10u);
  index()->Insert(hashes_.at<2>());
  InsertIntoIndexFileReturn(hashes_.at<2>(), now - base::Days(3), 100u);
  index()->Insert(hashes_.at<3>());
  index()->Remove(hashes_.at<3>());
  InsertIntoIndexFileReturn(hashes_.at<3>(), now - base::Days(4), 1000u);
  index()->Remove(hashes_.at<4>());
  index()->Insert(hashes_.at<4>());
  InsertIntoIndexFileReturn(hashes_.at<4>(), now - base::Days(5), 10000u);
  InsertIntoIndexFileReturn(hashes_.at<5>(), now - base::Days(6), 100000u);

  ReturnIndexFile();

  EXPECT_FALSE(index()->Has(hashes_.at<1>()));

  EntryMetadata metadata;
  EXPECT_TRUE(GetEntryForTesting(hashes_.at<2>(), &metadata));
  EXPECT_LT(now - base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_GT(now + base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_EQ(0U, metadata.GetEntrySize());

  EXPECT_FALSE(index()->Has(hashes_.at<3>()));

  EXPECT_TRUE(GetEntryForTesting(hashes_.at<4>(), &metadata));
  EXPECT_LT(now - base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_GT(now + base::Minutes(1), metadata.GetLastUsedTime());
  EXPECT_EQ(0U, metadata.GetEntrySize());

  EXPECT_TRUE(GetEntryForTesting(hashes_.at<5>(), &metadata));

  EXPECT_GT(now - base::Days(6) + base::Seconds(1), metadata.GetLastUsedTime());
  EXPECT_LT(now - base::Days(6) - base::Seconds(1), metadata.GetLastUsedTime());

  EXPECT_EQ(RoundSize(100000u), metadata.GetEntrySize());
}

TEST_F(SimpleIndexTest, BasicEviction) {
  base::Time now(base::Time::Now());
  index()->SetMaxSize(1000);
  InsertIntoIndexFileReturn(hashes_.at<1>(), now - base::Days(2), 475u);
  index()->Insert(hashes_.at<2>());
  index()->UpdateEntrySize(hashes_.at<2>(), 475u);
  ReturnIndexFile();

  WaitForTimeChange();

  index()->Insert(hashes_.at<3>());
  // Confirm index is as expected: No eviction, everything there.
  EXPECT_EQ(3, index()->GetEntryCount());
  EXPECT_EQ(0, doom_entries_calls());
  EXPECT_TRUE(index()->Has(hashes_.at<1>()));
  EXPECT_TRUE(index()->Has(hashes_.at<2>()));
  EXPECT_TRUE(index()->Has(hashes_.at<3>()));

  // Trigger an eviction, and make sure the right things are tossed.
  // TODO(morlovich): This is dependent on the innards of the implementation
  // as to at exactly what point we trigger eviction. Not sure how to fix
  // that.
  index()->UpdateEntrySize(hashes_.at<3>(), 475u);
  EXPECT_EQ(1, doom_entries_calls());
  EXPECT_EQ(1, index()->GetEntryCount());
  EXPECT_FALSE(index()->Has(hashes_.at<1>()));
  EXPECT_FALSE(index()->Has(hashes_.at<2>()));
  EXPECT_TRUE(index()->Has(hashes_.at<3>()));
  ASSERT_EQ(2u, last_doom_entry_hashes().size());
}

TEST_F(SimpleIndexTest, EvictBySize) {
  base::Time now(base::Time::Now());
  index()->SetMaxSize(50000);
  InsertIntoIndexFileReturn(hashes_.at<1>(), now - base::Days(2), 475u);
  InsertIntoIndexFileReturn(hashes_.at<2>(), now - base::Days(1), 40000u);
  ReturnIndexFile();
  WaitForTimeChange();

  index()->Insert(hashes_.at<3>());
  // Confirm index is as expected: No eviction, everything there.
  EXPECT_EQ(3, index()->GetEntryCount());
  EXPECT_EQ(0, doom_entries_calls());
  EXPECT_TRUE(index()->Has(hashes_.at<1>()));
  EXPECT_TRUE(index()->Has(hashes_.at<2>()));
  EXPECT_TRUE(index()->Has(hashes_.at<3>()));

  // Trigger an eviction, and make sure the right things are tossed.
  // TODO(morlovich): This is dependent on the innards of the implementation
  // as to at exactly what point we trigger eviction. Not sure how to fix
  // that.
  index()->UpdateEntrySize(hashes_.at<3>(), 40000u);
  EXPECT_EQ(1, doom_entries_calls());
  EXPECT_EQ(2, index()->GetEntryCount());
  EXPECT_TRUE(index()->Has(hashes_.at<1>()));
  EXPECT_FALSE(index()->Has(hashes_.at<2>()));
  EXPECT_TRUE(index()->Has(hashes_.at<3>()));
  ASSERT_EQ(1u, last_doom_entry_hashes().size());
}

TEST_F(SimpleIndexCodeCacheTest, DisableEvictBySize) {
  base::Time now(base::Time::Now());
  index()->SetMaxSize(50000);
  InsertIntoIndexFileReturn(hashes_.at<1>(), now - base::Days(2), 475u);
  InsertIntoIndexFileReturn(hashes_.at<2>(), now - base::Days(1), 40000u);
  ReturnIndexFile();
  WaitForTimeChange();

  index()->Insert(hashes_.at<3>());
  // Confirm index is as expected: No eviction, everything there.
  EXPECT_EQ(3, index()->GetEntryCount());
  EXPECT_EQ(0, doom_entries_calls());
  EXPECT_TRUE(index()->Has(hashes_.at<1>()));
  EXPECT_TRUE(index()->Has(hashes_.at<2>()));
  EXPECT_TRUE(index()->Has(hashes_.at<3>()));

  // Trigger an eviction, and make sure the right things are tossed.
  // Since evict by size is supposed to be disabled, it evicts in LRU order,
  // so entries 1 and 2 are both kicked out.
  index()->UpdateEntrySize(hashes_.at<3>(), 40000u);
  EXPECT_EQ(1, doom_entries_calls());
  EXPECT_EQ(1, index()->GetEntryCount());
  EXPECT_FALSE(index()->Has(hashes_.at<1>()));
  EXPECT_FALSE(index()->Has(hashes_.at<2>()));
  EXPECT_TRUE(index()->Has(hashes_.at<3>()));
  ASSERT_EQ(2u, last_doom_entry_hashes().size());
}

// Same as test above, but using much older entries to make sure that small
// things eventually get evictied.
TEST_F(SimpleIndexTest, EvictBySize2) {
  base::Time now(base::Time::Now());
  index()->SetMaxSize(50000);
  InsertIntoIndexFileReturn(hashes_.at<1>(), now - base::Days(200), 475u);
  InsertIntoIndexFileReturn(hashes_.at<2>(), now - base::Days(1), 40000u);
  ReturnIndexFile();
  WaitForTimeChange();

  index()->Insert(hashes_.at<3>());
  // Confirm index is as expected: No eviction, everything there.
  EXPECT_EQ(3, index()->GetEntryCount());
  EXPECT_EQ(0, doom_entries_calls());
  EXPECT_TRUE(index()->Has(hashes_.at<1>()));
  EXPECT_TRUE(index()->Has(hashes_.at<2>()));
  EXPECT_TRUE(index()->Has(hashes_.at<3>()));

  // Trigger an eviction, and make sure the right things are tossed.
  // TODO(morlovich): This is dependent on the innards of the implementation
  // as to at exactly what point we trigger eviction. Not sure how to fix
  // that.
  index()->UpdateEntrySize(hashes_.at<3>(), 40000u);
  EXPECT_EQ(1, doom_entries_calls());
  EXPECT_EQ(1, index()->GetEntryCount());
  EXPECT_FALSE(index()->Has(hashes_.at<1>()));
  EXPECT_FALSE(index()->Has(hashes_.at<2>()));
  EXPECT_TRUE(index()->Has(hashes_.at<3>()));
  ASSERT_EQ(2u, last_doom_entry_hashes().size());
}

// Confirm all the operations queue a disk write at some point in the
// future.
TEST_F(SimpleIndexTest, DiskWriteQueued) {
  index()->SetMaxSize(1000);
  ReturnIndexFile();

  EXPECT_FALSE(index()->HasPendingWrite());

  const uint64_t kHash1 = hashes_.at<1>();
  index()->Insert(kHash1);
  EXPECT_TRUE(index()->HasPendingWrite());
  index()->write_to_disk_timer_.Stop();
  EXPECT_FALSE(index()->HasPendingWrite());

  // Attempting to insert a hash that already exists should not queue the
  // write timer.
  index()->Insert(kHash1);
  EXPECT_FALSE(index()->HasPendingWrite());

  index()->UseIfExists(kHash1);
  EXPECT_TRUE(index()->HasPendingWrite());
  index()->write_to_disk_timer_.Stop();

  index()->UpdateEntrySize(kHash1, 20u);
  EXPECT_TRUE(index()->HasPendingWrite());
  index()->write_to_disk_timer_.Stop();

  // Updating to the same size should not queue the write timer.
  index()->UpdateEntrySize(kHash1, 20u);
  EXPECT_FALSE(index()->HasPendingWrite());

  index()->Remove(kHash1);
  EXPECT_TRUE(index()->HasPendingWrite());
  index()->write_to_disk_timer_.Stop();

  // Removing a non-existent hash should not queue the write timer.
  index()->Remove(kHash1);
  EXPECT_FALSE(index()->HasPendingWrite());
}

TEST_F(SimpleIndexTest, DiskWriteExecuted) {
  index()->SetMaxSize(1000);
  ReturnIndexFile();

  EXPECT_FALSE(index()->HasPendingWrite());

  const uint64_t kHash1 = hashes_.at<1>();
  index()->Insert(kHash1);
  index()->UpdateEntrySize(kHash1, 20u);
  EXPECT_TRUE(index()->HasPendingWrite());

  EXPECT_EQ(0, index_file_->disk_writes());
  index()->write_to_disk_timer_.FireNow();
  EXPECT_EQ(1, index_file_->disk_writes());
  SimpleIndex::EntrySet entry_set;
  index_file_->GetAndResetDiskWriteEntrySet(&entry_set);

  uint64_t hash_key = kHash1;
  base::Time now(base::Time::Now());
  ASSERT_EQ(1u, entry_set.size());
  EXPECT_EQ(hash_key, entry_set.begin()->first);
  const EntryMetadata& entry1(entry_set.begin()->second);
  EXPECT_LT(now - base::Minutes(1), entry1.GetLastUsedTime());
  EXPECT_GT(now + base::Minutes(1), entry1.GetLastUsedTime());
  EXPECT_EQ(RoundSize(20u), entry1.GetEntrySize());
}

TEST_F(SimpleIndexTest, DiskWritePostponed) {
  index()->SetMaxSize(1000);
  ReturnIndexFile();

  EXPECT_FALSE(index()->HasPendingWrite());

  index()->Insert(hashes_.at<1>());
  index()->UpdateEntrySize(hashes_.at<1>(), 20u);
  EXPECT_TRUE(index()->HasPendingWrite());
  base::TimeTicks expected_trigger(
      index()->write_to_disk_timer_.desired_run_time());

  WaitForTimeChange();
  EXPECT_EQ(expected_trigger, index()->write_to_disk_timer_.desired_run_time());
  index()->Insert(hashes_.at<2>());
  index()->UpdateEntrySize(hashes_.at<2>(), 40u);
  EXPECT_TRUE(index()->HasPendingWrite());
  EXPECT_LT(expected_trigger, index()->write_to_disk_timer_.desired_run_time());
  index()->write_to_disk_timer_.Stop();
}

// net::APP_CACHE mode should not need to queue disk writes in as many places
// as the default net::DISK_CACHE mode.
TEST_F(SimpleIndexAppCacheTest, DiskWriteQueued) {
  index()->SetMaxSize(1000);
  ReturnIndexFile();

  EXPECT_FALSE(index()->HasPendingWrite());

  const uint64_t kHash1 = hashes_.at<1>();
  index()->Insert(kHash1);
  EXPECT_TRUE(index()->HasPendingWrite());
  index()->write_to_disk_timer_.Stop();
  EXPECT_FALSE(index()->HasPendingWrite());

  // Attempting to insert a hash that already exists should not queue the
  // write timer.
  index()->Insert(kHash1);
  EXPECT_FALSE(index()->HasPendingWrite());

  // Since net::APP_CACHE does not evict or track access times using an
  // entry should not queue the write timer.
  index()->UseIfExists(kHash1);
  EXPECT_FALSE(index()->HasPendingWrite());

  index()->UpdateEntrySize(kHash1, 20u);
  EXPECT_TRUE(index()->HasPendingWrite());
  index()->write_to_disk_timer_.Stop();

  // Updating to the same size should not queue the write timer.
  index()->UpdateEntrySize(kHash1, 20u);
  EXPECT_FALSE(index()->HasPendingWrite());

  index()->Remove(kHash1);
  EXPECT_TRUE(index()->HasPendingWrite());
  index()->write_to_disk_timer_.Stop();

  // Removing a non-existent hash should not queue the write timer.
  index()->Remove(kHash1);
  EXPECT_FALSE(index()->HasPendingWrite());
}

}  // namespace disk_cache
```