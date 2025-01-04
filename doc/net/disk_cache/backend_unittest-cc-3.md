Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/disk_cache/backend_unittest.cc`. The snippet contains several test cases for the Chromium network stack's disk cache backend. I need to analyze what each test case does and group them by function. I also need to identify if any of these tests are related to JavaScript, provide examples, explain any logical reasoning with input/output, point out common user/programming errors, and suggest debugging steps.

Here's a breakdown of the test cases:

*   `DisableSuccess3`, `NewEvictionDisableSuccess3`: Tests disabling the cache after initialization with different configurations.
*   `BackendDisable4`, `DisableSuccess4`, `NewEvictionDisableSuccess4`: Tests disabling the cache while entries are open and verifies that existing entries can still be accessed to some extent.
*   `BackendDisabledAPI`, `DisabledAPI`, `NewEvictionDisabledAPI`: Tests the API behavior when the cache is disabled, ensuring attempts to create, open, or delete entries fail.
*   `BackendEviction` (multiple instances), `MemoryOnlyBackendEviction`: Tests the cache eviction mechanism to ensure the cache doesn't exceed its maximum size. Includes a memory-only mode.
*   `MemoryOnlyUseAfterFree`: A regression test to prevent a use-after-free issue in memory-only mode when writing sparse data during eviction.
*   `MemoryCapsWritesToMaxSize`: Tests that the memory cache respects the max size limit even with multiple open entries writing data.
*   `Backend_UsageStatsTimer`: Tests the timer for usage statistics.
*   `TimerNotCreated`: Tests that the usage stats timer is not created when cache initialization fails.
*   `Backend_UsageStats`: Tests that cache usage statistics are recorded and persist across cache restarts.
*   `BackendDoomAll` (multiple instances with different configurations): Tests the functionality of deleting all entries in the cache.
*   `BackendDoomAll2`, `DoomAll2`, `NewEvictionDoomAll2`: Tests deleting all entries when the index size changes during the process.
*   `MultipleInstances`: Tests creating entries in multiple simultaneous cache instances.
*   `AutomaticMaxSize`: Tests the logic for automatically determining the maximum cache size based on available disk space.
*   `TotalBuffersSize1`, `TotalBuffersSize2`: Tests the management of internal buffer sizes within the cache.
*   `FileSharing`: Tests the sharing of external files used by the cache.
*   `UpdateRankForExternalCacheHit`, `ShaderCacheUpdateRankForExternalCacheHit`: Tests updating the ranking of cache entries when an external cache hit occurs.
*   `SimpleCacheShutdownWithPendingCreate`, `SimpleCacheShutdownWithPendingDoom`, `SimpleCacheShutdownWithPendingFileIO`: Tests cache shutdown behavior when there are pending operations.
*   `SimpleCacheBasics`, `SimpleCacheAppCacheBasics`, `SimpleCacheKeying`, `SimpleCacheAppCacheKeying`, `SimpleCacheLoad`, `SimpleCacheAppCacheLoad`, `SimpleDoomRecent`, `DISABLED_SimpleDoomBetween`, `SimpleCacheDoomAll`, `SimpleCacheAppCacheOnlyDoomAll`: Basic functional tests for the SimpleCache implementation.
*   `SimpleCacheOpenMissingFile`, `SimpleCacheOpenBadFile`: Tests the behavior of the SimpleCache when encountering missing or corrupted files.
*   `SimpleCacheOverBlockfileCache`, `BlockfileCacheOverSimpleCache`: Tests that the different cache backend implementations don't try to initialize over each other's data.
*   `SimpleCacheFixEnumerators`, `SimpleCacheEnumerationBasics`, `SimpleCacheEnumerationWhileDoomed`, `SimpleCacheEnumerationCorruption`, `SimpleCacheEnumerationDestruction`: Tests the enumeration API for the SimpleCache.
*   `DISABLED_SimpleCachePrioritizedEntryOrder`: Tests prioritized task execution in the SimpleCache.

The main focus of this code is testing the disk cache backend, including its disabling, eviction, deletion, and interactions with external files. It also includes tests specifically for the "SimpleCache" implementation.

Now, let's organize the summary.
这个代码片段是 Chromium 网络栈中 `net/disk_cache/backend_unittest.cc` 文件的第四部分，主要功能是 **测试磁盘缓存后端在禁用、驱逐条目和删除条目方面的行为，并涵盖了对 SimpleCache 特定实现的测试。**  它延续了前几部分测试的基础功能，并深入测试了更复杂的操作和场景。

**以下是代码片段功能的详细归纳：**

1. **测试禁用缓存 (Cache Disabling):**
    *   **功能:**  测试在不同状态下禁用磁盘缓存的行为，包括在有已打开条目的情况下禁用。
    *   **测试用例:** `DisableSuccess3`, `NewEvictionDisableSuccess3`, `BackendDisable4`, `DisableSuccess4`, `NewEvictionDisableSuccess4`, `BackendDisabledAPI`, `DisabledAPI`, `NewEvictionDisabledAPI`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 磁盘缓存已初始化，可能包含一些条目。执行禁用缓存操作。
        *   **预期输出:**
            *   `BackendDisable4` 中，已打开的条目在禁用后仍然可以读取和写入数据，但无法创建新条目。
            *   `BackendDisabledAPI` 系列测试中，禁用后所有与缓存操作相关的 API 调用（如 `OpenEntry`, `CreateEntry`, `DoomEntry` 等）都应返回错误 (通常是 `net::ERR_FAILED` 或其他非 `net::OK` 的值)。
    *   **用户或编程常见的使用错误:**
        *   在禁用缓存后尝试创建或访问缓存条目，可能会导致程序崩溃或出现未定义的行为（尽管测试用例会检查这种情况）。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户在浏览器设置中禁用了缓存功能。
        2. 浏览器内部的网络栈接收到禁用缓存的指令。
        3. `disk_cache::BackendImpl` 对象接收到禁用通知。
        4. 相关的禁用逻辑被触发，这些测试用例模拟了这个过程并验证了其正确性。

2. **测试缓存驱逐 (Cache Eviction):**
    *   **功能:** 测试磁盘缓存的驱逐机制，确保在容量达到上限时，能够移除旧的或不常用的条目。同时测试了内存模式下的驱逐。
    *   **测试用例:** `BackendEviction` (多次出现), `MemoryOnlyBackendEviction`, `MemoryOnlyUseAfterFree`, `MemoryCapsWritesToMaxSize`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  设置了最大缓存大小，并不断创建新的缓存条目直到超出容量。
        *   **预期输出:**  较旧的或较少使用的条目将被移除，使得缓存总大小不超过预设的最大值。 `MemoryCapsWritesToMaxSize` 特别测试了在接近容量上限时，新的写入操作会被阻止。
    *   **用户或编程常见的使用错误:**
        *   错误地估计缓存大小需求，导致频繁的驱逐，影响性能。
        *   在内存受限的环境中不恰当地配置缓存大小，可能导致内存不足。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户持续访问大量网页或资源，导致缓存数据增多。
        2. 当缓存容量达到预设上限时，驱逐策略被触发。
        3. 这些测试用例模拟了高负载下的缓存行为，并验证了驱逐逻辑的正确性。

3. **测试禁用状态下的 API 行为 (Disabled API Behavior):**
    *   **功能:** 验证当缓存被禁用时，各种缓存 API 的返回值和行为。
    *   **测试用例:** `BackendDisabledAPI`, `DisabledAPI`, `NewEvictionDisabledAPI` (与第一点重复，强调了 API 层面)。
    *   **逻辑推理 (假设输入与输出):** 见第一点。

4. **测试缓存统计信息 (Cache Statistics):**
    *   **功能:** 测试缓存的统计信息功能，确保能够正确记录缓存的命中率、条目数量等信息。
    *   **测试用例:** `Backend_UsageStatsTimer`, `TimerNotCreated`, `Backend_UsageStats`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  创建、打开、关闭缓存条目。
        *   **预期输出:**  相应的统计信息（例如 "Create hit" 的计数）会增加。重启缓存后，统计信息仍然存在。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 浏览器在运行时会收集缓存的使用情况统计信息。
        2. 这些统计信息可能用于性能分析、调试或优化缓存策略。
        3. 测试用例验证了统计信息收集的正确性和持久性。

5. **测试删除所有条目 (Doom All Entries):**
    *   **功能:** 测试 `DoomAllEntries()` 方法，确保能够正确删除缓存中的所有条目。
    *   **测试用例:** `BackendDoomAll` (多次出现), `BackendDoomAll2`, `DoomAll2`, `NewEvictionDoomAll2`, `MemoryOnlyDoomAll`, `AppCacheOnlyDoomAll`, `ShaderCacheOnlyDoomAll`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  缓存中存在若干条目。调用 `DoomAllEntries()`。
        *   **预期输出:**  缓存中的条目数量变为 0。之后尝试打开或创建相同 key 的条目应该成功。
    *   **用户操作到达此处的步骤 (调试线索):**
        1. 用户在浏览器设置中清除了缓存。
        2. 浏览器内部的网络栈接收到清除缓存的指令。
        3. `disk_cache::BackendImpl` 对象调用 `DoomAllEntries()` 来执行清除操作。

6. **测试多实例缓存 (Multiple Cache Instances):**
    *   **功能:** 测试在多个独立的缓存实例中同时创建相同 key 的条目是否可行。
    *   **测试用例:** `MultipleInstances`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  创建两个独立的缓存实例，并尝试在它们中同时创建相同 key 的条目。
        *   **预期输出:**  创建操作应该成功。

7. **测试自动最大缓存大小计算 (Automatic Max Size Calculation):**
    *   **功能:** 测试根据可用磁盘空间自动计算最大缓存大小的逻辑。
    *   **测试用例:** `AutomaticMaxSize`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  不同的可用磁盘空间大小。
        *   **预期输出:**  `PreferredCacheSize()` 函数应该根据预定义的规则返回合适的缓存大小。

8. **测试内部缓冲区大小管理 (Internal Buffer Size Management):**
    *   **功能:** 测试缓存后端如何管理内部缓冲区的大小，避免过度占用内存。
    *   **测试用例:** `TotalBuffersSize1`, `TotalBuffersSize2`。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  持续地写入数据到缓存条目，并观察内部缓冲区大小的变化。
        *   **预期输出:**  内部缓冲区的大小应该在可控的范围内，不会无限增长。

9. **测试文件共享 (File Sharing):**
    *   **功能:** 测试缓存后端对外部文件的共享机制，确保在多个进程或线程之间可以安全地访问和删除外部文件。
    *   **测试用例:** `FileSharing`。

10. **测试外部缓存命中更新排名 (Update Rank for External Cache Hit):**
    *   **功能:** 测试当发生外部缓存命中时，如何更新缓存条目的排名，以影响后续的驱逐策略。
    *   **测试用例:** `UpdateRankForExternalCacheHit`, `ShaderCacheUpdateRankForExternalCacheHit`。

11. **SimpleCache 特定测试:**
    *   **功能:**  测试 `SimpleCache` 实现的特定行为，包括在有待处理操作时的关闭行为、基本功能、Key 生成、加载、删除和枚举等。
    *   **测试用例:** `SimpleCacheShutdownWithPendingCreate`, `SimpleCacheShutdownWithPendingDoom`, `SimpleCacheShutdownWithPendingFileIO`, `SimpleCacheBasics`, `SimpleCacheAppCacheBasics`, `SimpleCacheKeying`, `SimpleCacheAppCacheKeying`, `SimpleCacheLoad`, `SimpleCacheAppCacheLoad`, `SimpleDoomRecent`, `DISABLED_SimpleDoomBetween`, `SimpleCacheDoomAll`, `SimpleCacheAppCacheOnlyDoomAll`, `SimpleCacheOpenMissingFile`, `SimpleCacheOpenBadFile`, `SimpleCacheOverBlockfileCache`, `BlockfileCacheOverSimpleCache`, `SimpleCacheFixEnumerators`, `SimpleCacheEnumerationBasics`, `SimpleCacheEnumerationWhileDoomed`, `SimpleCacheEnumerationCorruption`, `SimpleCacheEnumerationDestruction`, `DISABLED_SimpleCachePrioritizedEntryOrder`。
    *   **与 JavaScript 的关系:**  `SimpleCache` 可以被用于存储来自 JavaScript 的数据，例如 Service Worker 缓存或者其他通过 Web APIs 访问的缓存。
    *   **JavaScript 举例说明:**
        *   **假设 JavaScript 代码:**
            ```javascript
            navigator.serviceWorker.register('sw.js');

            navigator.serviceWorker.ready.then(registration => {
              caches.open('my-cache').then(cache => {
                cache.put('/api/data', new Response('{"data": "example"}'));
              });
            });
            ```
        *   **用户操作到达此处的步骤 (调试线索):**
            1. 用户访问一个注册了 Service Worker 的网页。
            2. Service Worker 中的 JavaScript 代码使用 `caches.open()` 和 `cache.put()` 将数据存储到缓存中。
            3. 如果浏览器使用 `SimpleCache` 作为其缓存后端，那么这些测试用例会验证 `SimpleCache` 在处理这些操作时的正确性，例如 `SimpleCacheKeying` 测试会验证如何从 URL `/api/data` 生成缓存的 Key。`SimpleCacheLoad` 测试会验证如何从磁盘加载这些缓存的条目。
    *   **逻辑推理 (假设输入与输出):**  这些测试用例会模拟 `SimpleCache` 的各种操作，例如创建条目、写入数据、读取数据、删除条目、枚举条目等，并验证其行为是否符合预期。例如，`SimpleCacheOpenMissingFile` 测试会模拟当缓存文件丢失时 `SimpleCache` 的处理方式。
    *   **用户或编程常见的使用错误:**
        *   在 JavaScript 中使用了错误的缓存 Key，导致无法找到或更新缓存的条目。
        *   在 Service Worker 的生命周期管理中，没有正确地删除不再需要的缓存条目，导致缓存占用过多空间。

**总结来说，这部分代码着重于测试 `disk_cache::BackendImpl` (以及 `SimpleBackendImpl`) 在处理禁用、驱逐和删除缓存条目时的内部逻辑和 API 行为，并特别关注了 `SimpleCache` 的功能和与 JavaScript 缓存 API 的潜在关联。** 这些测试用例确保了缓存的稳定性和可靠性，防止了常见的错误和崩溃情况。

Prompt: 
```
这是目录为net/disk_cache/backend_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
r = CreateIterator();
  EXPECT_EQ(2, cache_->GetEntryCount());
  ASSERT_THAT(iter->OpenNextEntry(&entry1), IsOk());
  entry1->Close();

  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry2));
  FlushQueueForTest();

  ASSERT_THAT(CreateEntry("Something new", &entry2), IsOk());
  entry2->Close();

  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DisableSuccess3) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetMaxSize(20 * 1024 * 1024);
  InitCache();
  BackendDisable3();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableSuccess3) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetMaxSize(20 * 1024 * 1024);
  SetNewEviction();
  InitCache();
  BackendDisable3();
}

// If we disable the cache, already open entries should work as far as possible.
void DiskCacheBackendTest::BackendDisable4() {
  disk_cache::Entry *entry1, *entry2, *entry3, *entry4;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry1), IsOk());

  char key2[2000];
  char key3[20000];
  CacheTestFillBuffer(key2, sizeof(key2), true);
  CacheTestFillBuffer(key3, sizeof(key3), true);
  key2[sizeof(key2) - 1] = '\0';
  key3[sizeof(key3) - 1] = '\0';
  ASSERT_THAT(CreateEntry(key2, &entry2), IsOk());
  ASSERT_THAT(CreateEntry(key3, &entry3), IsOk());

  const int kBufSize = 20000;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kBufSize);
  memset(buf->data(), 0, kBufSize);
  EXPECT_EQ(100, WriteData(entry2, 0, 0, buf.get(), 100, false));
  EXPECT_EQ(kBufSize, WriteData(entry3, 0, 0, buf.get(), kBufSize, false));

  // This line should disable the cache but not delete it.
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry4));
  EXPECT_EQ(0, cache_->GetEntryCount());

  EXPECT_NE(net::OK, CreateEntry("cache is disabled", &entry4));

  EXPECT_EQ(100, ReadData(entry2, 0, 0, buf.get(), 100));
  EXPECT_EQ(100, WriteData(entry2, 0, 0, buf.get(), 100, false));
  EXPECT_EQ(100, WriteData(entry2, 1, 0, buf.get(), 100, false));

  EXPECT_EQ(kBufSize, ReadData(entry3, 0, 0, buf.get(), kBufSize));
  EXPECT_EQ(kBufSize, WriteData(entry3, 0, 0, buf.get(), kBufSize, false));
  EXPECT_EQ(kBufSize, WriteData(entry3, 1, 0, buf.get(), kBufSize, false));

  std::string key = entry2->GetKey();
  EXPECT_EQ(sizeof(key2) - 1, key.size());
  key = entry3->GetKey();
  EXPECT_EQ(sizeof(key3) - 1, key.size());

  entry1->Close();
  entry2->Close();
  entry3->Close();
  FlushQueueForTest();  // Flushing the Close posts a task to restart the cache.
  FlushQueueForTest();  // This one actually allows that task to complete.

  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DisableSuccess4) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  BackendDisable4();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableSuccess4) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendDisable4();
}

// Tests the exposed API with a disabled cache.
void DiskCacheBackendTest::BackendDisabledAPI() {
  cache_impl_->SetUnitTestMode();  // Simulate failure restarting the cache.

  disk_cache::Entry *entry1, *entry2;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  EXPECT_EQ(2, cache_->GetEntryCount());
  ASSERT_THAT(iter->OpenNextEntry(&entry1), IsOk());
  entry1->Close();
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry2));
  FlushQueueForTest();
  // The cache should be disabled.

  EXPECT_EQ(net::DISK_CACHE, cache_->GetCacheType());
  EXPECT_EQ(0, cache_->GetEntryCount());
  EXPECT_NE(net::OK, OpenEntry("First", &entry2));
  EXPECT_NE(net::OK, CreateEntry("Something new", &entry2));
  EXPECT_NE(net::OK, DoomEntry("First"));
  EXPECT_NE(net::OK, DoomAllEntries());
  EXPECT_NE(net::OK, DoomEntriesBetween(Time(), Time::Now()));
  EXPECT_NE(net::OK, DoomEntriesSince(Time()));
  iter = CreateIterator();
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry2));

  base::StringPairs stats;
  cache_->GetStats(&stats);
  EXPECT_TRUE(stats.empty());
  OnExternalCacheHit("First");
}

TEST_F(DiskCacheBackendTest, DisabledAPI) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  InitCache();
  BackendDisabledAPI();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisabledAPI) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendDisabledAPI();
}

// Test that some eviction of some kind happens.
void DiskCacheBackendTest::BackendEviction() {
  const int kMaxSize = 200 * 1024;
  const int kMaxEntryCount = 20;
  const int kWriteSize = kMaxSize / kMaxEntryCount;

  const int kWriteEntryCount = kMaxEntryCount * 2;

  static_assert(kWriteEntryCount * kWriteSize > kMaxSize,
                "must write more than MaxSize");

  SetMaxSize(kMaxSize);
  InitSparseCache(nullptr, nullptr);

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kWriteSize);
  CacheTestFillBuffer(buffer->data(), kWriteSize, false);

  std::string key_prefix("prefix");
  for (int i = 0; i < kWriteEntryCount; ++i) {
    AddDelay();
    disk_cache::Entry* entry = nullptr;
    ASSERT_THAT(CreateEntry(key_prefix + base::NumberToString(i), &entry),
                IsOk());
    disk_cache::ScopedEntryPtr entry_closer(entry);
    EXPECT_EQ(kWriteSize,
              WriteData(entry, 1, 0, buffer.get(), kWriteSize, false));
  }

  int size = CalculateSizeOfAllEntries();
  EXPECT_GT(kMaxSize, size);
}

TEST_F(DiskCacheBackendTest, BackendEviction) {
  BackendEviction();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyBackendEviction) {
  SetMemoryOnlyMode();
  BackendEviction();
}

// TODO(morlovich): Enable BackendEviction test for simple cache after
// performance problems are addressed. See crbug.com/588184 for more
// information.

// This overly specific looking test is a regression test aimed at
// crbug.com/589186.
TEST_F(DiskCacheBackendTest, MemoryOnlyUseAfterFree) {
  SetMemoryOnlyMode();

  const int kMaxSize = 200 * 1024;
  const int kMaxEntryCount = 20;
  const int kWriteSize = kMaxSize / kMaxEntryCount;

  SetMaxSize(kMaxSize);
  InitCache();

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kWriteSize);
  CacheTestFillBuffer(buffer->data(), kWriteSize, false);

  // Create an entry to be our sparse entry that gets written later.
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("first parent", &entry), IsOk());
  disk_cache::ScopedEntryPtr first_parent(entry);

  // Create a ton of entries, and keep them open, to put the cache well above
  // its eviction threshhold.
  const int kTooManyEntriesCount = kMaxEntryCount * 2;
  std::list<disk_cache::ScopedEntryPtr> open_entries;
  std::string key_prefix("prefix");
  for (int i = 0; i < kTooManyEntriesCount; ++i) {
    ASSERT_THAT(CreateEntry(key_prefix + base::NumberToString(i), &entry),
                IsOk());
    // Not checking the result because it will start to fail once the max size
    // is reached.
    WriteData(entry, 1, 0, buffer.get(), kWriteSize, false);
    open_entries.push_back(disk_cache::ScopedEntryPtr(entry));
  }

  // Writing this sparse data should not crash. Ignoring the result because
  // we're only concerned with not crashing in this particular test.
  first_parent->WriteSparseData(32768, buffer.get(), 1024,
                                net::CompletionOnceCallback());
}

TEST_F(DiskCacheBackendTest, MemoryCapsWritesToMaxSize) {
  // Verify that the memory backend won't grow beyond its max size if lots of
  // open entries (each smaller than the max entry size) are trying to write
  // beyond the max size.
  SetMemoryOnlyMode();

  const int kMaxSize = 100 * 1024;       // 100KB cache
  const int kNumEntries = 20;            // 20 entries to write
  const int kWriteSize = kMaxSize / 10;  // Each entry writes 1/10th the max

  SetMaxSize(kMaxSize);
  InitCache();

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kWriteSize);
  CacheTestFillBuffer(buffer->data(), kWriteSize, false);

  // Create an entry to be the final entry that gets written later.
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("final", &entry), IsOk());
  disk_cache::ScopedEntryPtr final_entry(entry);

  // Create a ton of entries, write to the cache, and keep the entries open.
  // They should start failing writes once the cache fills.
  std::list<disk_cache::ScopedEntryPtr> open_entries;
  std::string key_prefix("prefix");
  for (int i = 0; i < kNumEntries; ++i) {
    ASSERT_THAT(CreateEntry(key_prefix + base::NumberToString(i), &entry),
                IsOk());
    WriteData(entry, 1, 0, buffer.get(), kWriteSize, false);
    open_entries.push_back(disk_cache::ScopedEntryPtr(entry));
  }
  EXPECT_GE(kMaxSize, CalculateSizeOfAllEntries());

  // Any more writing at this point should cause an error.
  EXPECT_THAT(
      WriteData(final_entry.get(), 1, 0, buffer.get(), kWriteSize, false),
      IsError(net::ERR_INSUFFICIENT_RESOURCES));
}

TEST_F(DiskCacheTest, Backend_UsageStatsTimer) {
  MessageLoopHelper helper;

  ASSERT_TRUE(CleanupCacheDir());
  // Want to use our thread since we call SyncInit ourselves.
  std::unique_ptr<disk_cache::BackendImpl> cache(
      std::make_unique<disk_cache::BackendImpl>(
          cache_path_, nullptr,
          base::SingleThreadTaskRunner::GetCurrentDefault(), net::DISK_CACHE,
          nullptr));
  ASSERT_TRUE(nullptr != cache.get());
  cache->SetUnitTestMode();
  ASSERT_THAT(cache->SyncInit(), IsOk());

  // Wait for a callback that never comes... about 2 secs :). The message loop
  // has to run to allow invocation of the usage timer.
  helper.WaitUntilCacheIoFinished(1);
}

TEST_F(DiskCacheBackendTest, TimerNotCreated) {
  ASSERT_TRUE(CopyTestCache("wrong_version"));

  // Want to use our thread since we call SyncInit ourselves.
  std::unique_ptr<disk_cache::BackendImpl> cache(
      std::make_unique<disk_cache::BackendImpl>(
          cache_path_, nullptr,
          base::SingleThreadTaskRunner::GetCurrentDefault(), net::DISK_CACHE,
          nullptr));
  ASSERT_TRUE(nullptr != cache.get());
  cache->SetUnitTestMode();
  ASSERT_NE(net::OK, cache->SyncInit());

  ASSERT_TRUE(nullptr == cache->GetTimerForTest());

  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, Backend_UsageStats) {
  InitCache();
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  disk_cache::StatsItems stats;
  cache_->GetStats(&stats);
  EXPECT_FALSE(stats.empty());

  disk_cache::StatsItems::value_type hits("Create hit", "0x1");
  EXPECT_EQ(1, base::ranges::count(stats, hits));

  ResetCaches();

  // Now open the cache and verify that the stats are still there.
  DisableFirstCleanup();
  InitCache();
  EXPECT_EQ(1, cache_->GetEntryCount());

  stats.clear();
  cache_->GetStats(&stats);
  EXPECT_FALSE(stats.empty());

  EXPECT_EQ(1, base::ranges::count(stats, hits));
}

void DiskCacheBackendTest::BackendDoomAll() {
  InitCache();

  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry("first", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("second", &entry2), IsOk());
  entry1->Close();
  entry2->Close();

  ASSERT_THAT(CreateEntry("third", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("fourth", &entry2), IsOk());

  ASSERT_EQ(4, cache_->GetEntryCount());
  EXPECT_THAT(DoomAllEntries(), IsOk());
  ASSERT_EQ(0, cache_->GetEntryCount());

  // We should stop posting tasks at some point (if we post any).
  base::RunLoop().RunUntilIdle();

  disk_cache::Entry *entry3, *entry4;
  EXPECT_NE(net::OK, OpenEntry("third", &entry3));
  ASSERT_THAT(CreateEntry("third", &entry3), IsOk());
  ASSERT_THAT(CreateEntry("fourth", &entry4), IsOk());

  EXPECT_THAT(DoomAllEntries(), IsOk());
  ASSERT_EQ(0, cache_->GetEntryCount());

  entry1->Close();
  entry2->Close();
  entry3->Doom();  // The entry should be already doomed, but this must work.
  entry3->Close();
  entry4->Close();

  // Now try with all references released.
  ASSERT_THAT(CreateEntry("third", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("fourth", &entry2), IsOk());
  entry1->Close();
  entry2->Close();

  ASSERT_EQ(2, cache_->GetEntryCount());
  EXPECT_THAT(DoomAllEntries(), IsOk());
  ASSERT_EQ(0, cache_->GetEntryCount());

  EXPECT_THAT(DoomAllEntries(), IsOk());
}

TEST_F(DiskCacheBackendTest, DoomAll) {
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomAll) {
  SetNewEviction();
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomAll) {
  SetMemoryOnlyMode();
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, AppCacheOnlyDoomAll) {
  SetCacheType(net::APP_CACHE);
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, ShaderCacheOnlyDoomAll) {
  SetCacheType(net::SHADER_CACHE);
  BackendDoomAll();
}

// If the index size changes when we doom the cache, we should not crash.
void DiskCacheBackendTest::BackendDoomAll2() {
  EXPECT_EQ(2, cache_->GetEntryCount());
  EXPECT_THAT(DoomAllEntries(), IsOk());

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("Something new", &entry), IsOk());
  entry->Close();

  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DoomAll2) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetMaxSize(20 * 1024 * 1024);
  InitCache();
  BackendDoomAll2();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomAll2) {
  ASSERT_TRUE(CopyTestCache("bad_rankings2"));
  DisableFirstCleanup();
  SetMaxSize(20 * 1024 * 1024);
  SetNewEviction();
  InitCache();
  BackendDoomAll2();
}

// We should be able to create the same entry on multiple simultaneous instances
// of the cache.
TEST_F(DiskCacheTest, MultipleInstances) {
  base::ScopedTempDir store1, store2;
  ASSERT_TRUE(store1.CreateUniqueTempDir());
  ASSERT_TRUE(store2.CreateUniqueTempDir());

  TestBackendResultCompletionCallback cb;

  const int kNumberOfCaches = 2;
  std::unique_ptr<disk_cache::Backend> caches[kNumberOfCaches];

  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::DISK_CACHE, net::CACHE_BACKEND_DEFAULT, /*file_operations=*/nullptr,
      store1.GetPath(), 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, cb.callback());
  rv = cb.GetResult(std::move(rv));
  ASSERT_THAT(rv.net_error, IsOk());
  caches[0] = std::move(rv.backend);
  rv = disk_cache::CreateCacheBackend(
      net::GENERATED_BYTE_CODE_CACHE, net::CACHE_BACKEND_DEFAULT,
      /*file_operations=*/nullptr, store2.GetPath(), 0,
      disk_cache::ResetHandling::kNeverReset, /*net_log=*/nullptr,
      cb.callback());
  rv = cb.GetResult(std::move(rv));
  ASSERT_THAT(rv.net_error, IsOk());
  caches[1] = std::move(rv.backend);

  ASSERT_TRUE(caches[0].get() != nullptr && caches[1].get() != nullptr);

  std::string key("the first key");
  for (auto& cache : caches) {
    TestEntryResultCompletionCallback cb2;
    EntryResult result = cache->CreateEntry(key, net::HIGHEST, cb2.callback());
    result = cb2.GetResult(std::move(result));
    ASSERT_THAT(result.net_error(), IsOk());
    result.ReleaseEntry()->Close();
  }
}

// Test the six regions of the curve that determines the max cache size.
TEST_F(DiskCacheTest, AutomaticMaxSize) {
  using disk_cache::kDefaultCacheSize;
  int64_t large_size = kDefaultCacheSize;

  // Region 1: expected = available * 0.8
  EXPECT_EQ((kDefaultCacheSize - 1) * 8 / 10,
            disk_cache::PreferredCacheSize(large_size - 1));
  EXPECT_EQ(kDefaultCacheSize * 8 / 10,
            disk_cache::PreferredCacheSize(large_size));
  EXPECT_EQ(kDefaultCacheSize - 1,
            disk_cache::PreferredCacheSize(large_size * 10 / 8 - 1));

  // Region 2: expected = default_size
  EXPECT_EQ(kDefaultCacheSize,
            disk_cache::PreferredCacheSize(large_size * 10 / 8));
  EXPECT_EQ(kDefaultCacheSize,
            disk_cache::PreferredCacheSize(large_size * 10 - 1));

  // Region 3: expected = available * 0.1
  EXPECT_EQ(kDefaultCacheSize, disk_cache::PreferredCacheSize(large_size * 10));
  EXPECT_EQ((kDefaultCacheSize * 25 - 1) / 10,
            disk_cache::PreferredCacheSize(large_size * 25 - 1));

  // Region 4: expected = default_size * 2.5
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 25));
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 100 - 1));
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 100));
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 250 - 1));

  // Region 5: expected = available * 0.1
  int64_t largest_size = kDefaultCacheSize * 4;
  EXPECT_EQ(kDefaultCacheSize * 25 / 10,
            disk_cache::PreferredCacheSize(large_size * 250));
  EXPECT_EQ(largest_size - 1,
            disk_cache::PreferredCacheSize(largest_size * 100 - 1));

  // Region 6: expected = largest possible size
  EXPECT_EQ(largest_size, disk_cache::PreferredCacheSize(largest_size * 100));
  EXPECT_EQ(largest_size, disk_cache::PreferredCacheSize(largest_size * 10000));
}

// Make sure that we keep the total memory used by the internal buffers under
// control.
TEST_F(DiskCacheBackendTest, TotalBuffersSize1) {
  InitCache();
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 200;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, true);

  for (int i = 0; i < 10; i++) {
    SCOPED_TRACE(i);
    // Allocate 2MB for this entry.
    EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, true));
    EXPECT_EQ(kSize, WriteData(entry, 1, 0, buffer.get(), kSize, true));
    EXPECT_EQ(kSize,
              WriteData(entry, 0, 1024 * 1024, buffer.get(), kSize, false));
    EXPECT_EQ(kSize,
              WriteData(entry, 1, 1024 * 1024, buffer.get(), kSize, false));

    // Delete one of the buffers and truncate the other.
    EXPECT_EQ(0, WriteData(entry, 0, 0, buffer.get(), 0, true));
    EXPECT_EQ(0, WriteData(entry, 1, 10, buffer.get(), 0, true));

    // Delete the second buffer, writing 10 bytes to disk.
    entry->Close();
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  }

  entry->Close();
  EXPECT_EQ(0, cache_impl_->GetTotalBuffersSize());
}

// This test assumes at least 150MB of system memory.
TEST_F(DiskCacheBackendTest, TotalBuffersSize2) {
  InitCache();

  const int kOneMB = 1024 * 1024;
  EXPECT_TRUE(cache_impl_->IsAllocAllowed(0, kOneMB));
  EXPECT_EQ(kOneMB, cache_impl_->GetTotalBuffersSize());

  EXPECT_TRUE(cache_impl_->IsAllocAllowed(0, kOneMB));
  EXPECT_EQ(kOneMB * 2, cache_impl_->GetTotalBuffersSize());

  EXPECT_TRUE(cache_impl_->IsAllocAllowed(0, kOneMB));
  EXPECT_EQ(kOneMB * 3, cache_impl_->GetTotalBuffersSize());

  cache_impl_->BufferDeleted(kOneMB);
  EXPECT_EQ(kOneMB * 2, cache_impl_->GetTotalBuffersSize());

  // Check the upper limit.
  EXPECT_FALSE(cache_impl_->IsAllocAllowed(0, 30 * kOneMB));

  for (int i = 0; i < 30; i++)
    cache_impl_->IsAllocAllowed(0, kOneMB);  // Ignore the result.

  EXPECT_FALSE(cache_impl_->IsAllocAllowed(0, kOneMB));
}

// Tests that sharing of external files works and we are able to delete the
// files when we need to.
TEST_F(DiskCacheBackendTest, FileSharing) {
  InitCache();

  disk_cache::Addr address(0x80000001);
  ASSERT_TRUE(cache_impl_->CreateExternalFile(&address));
  base::FilePath name = cache_impl_->GetFileName(address);

  {
    auto file = base::MakeRefCounted<disk_cache::File>(false);
    file->Init(name);

#if BUILDFLAG(IS_WIN)
    DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE;
    DWORD access = GENERIC_READ | GENERIC_WRITE;
    base::win::ScopedHandle file2(CreateFile(name.value().c_str(), access,
                                             sharing, nullptr, OPEN_EXISTING, 0,
                                             nullptr));
    EXPECT_FALSE(file2.IsValid());

    sharing |= FILE_SHARE_DELETE;
    file2.Set(CreateFile(name.value().c_str(), access, sharing, nullptr,
                         OPEN_EXISTING, 0, nullptr));
    EXPECT_TRUE(file2.IsValid());
#endif

    EXPECT_TRUE(base::DeleteFile(name));

    // We should be able to use the file.
    const int kSize = 200;
    char buffer1[kSize];
    char buffer2[kSize];
    memset(buffer1, 't', kSize);
    memset(buffer2, 0, kSize);
    EXPECT_TRUE(file->Write(buffer1, kSize, 0));
    EXPECT_TRUE(file->Read(buffer2, kSize, 0));
    EXPECT_EQ(0, memcmp(buffer1, buffer2, kSize));
  }

  base::File file(name, base::File::FLAG_OPEN | base::File::FLAG_READ);
  EXPECT_FALSE(file.IsValid());
  EXPECT_EQ(file.error_details(), base::File::FILE_ERROR_NOT_FOUND);
}

TEST_F(DiskCacheBackendTest, UpdateRankForExternalCacheHit) {
  InitCache();

  disk_cache::Entry* entry;

  for (int i = 0; i < 2; ++i) {
    std::string key = base::StringPrintf("key%d", i);
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }

  // Ping the oldest entry.
  OnExternalCacheHit("key0");

  TrimForTest(false);

  // Make sure the older key remains.
  EXPECT_EQ(1, cache_->GetEntryCount());
  ASSERT_THAT(OpenEntry("key0", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, ShaderCacheUpdateRankForExternalCacheHit) {
  SetCacheType(net::SHADER_CACHE);
  InitCache();

  disk_cache::Entry* entry;

  for (int i = 0; i < 2; ++i) {
    std::string key = base::StringPrintf("key%d", i);
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }

  // Ping the oldest entry.
  OnExternalCacheHit("key0");

  TrimForTest(false);

  // Make sure the older key remains.
  EXPECT_EQ(1, cache_->GetEntryCount());
  ASSERT_THAT(OpenEntry("key0", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, SimpleCacheShutdownWithPendingCreate) {
  // Use net::APP_CACHE to make size estimations deterministic via
  // non-optimistic writes.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendShutdownWithPendingCreate(false);
}

TEST_F(DiskCacheBackendTest, SimpleCacheShutdownWithPendingDoom) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendShutdownWithPendingDoom();
}

TEST_F(DiskCacheBackendTest, SimpleCacheShutdownWithPendingFileIO) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendShutdownWithPendingFileIO(false);
}

TEST_F(DiskCacheBackendTest, SimpleCacheBasics) {
  SetSimpleCacheMode();
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, SimpleCacheAppCacheBasics) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendBasics();
}

TEST_F(DiskCacheBackendTest, SimpleCacheKeying) {
  SetSimpleCacheMode();
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, SimpleCacheAppCacheKeying) {
  SetSimpleCacheMode();
  SetCacheType(net::APP_CACHE);
  BackendKeying();
}

TEST_F(DiskCacheBackendTest, SimpleCacheLoad) {
  SetMaxSize(0x100000);
  SetSimpleCacheMode();
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, SimpleCacheAppCacheLoad) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  SetMaxSize(0x100000);
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, SimpleDoomRecent) {
  SetSimpleCacheMode();
  BackendDoomRecent();
}

// crbug.com/330926, crbug.com/370677
TEST_F(DiskCacheBackendTest, DISABLED_SimpleDoomBetween) {
  SetSimpleCacheMode();
  BackendDoomBetween();
}

TEST_F(DiskCacheBackendTest, SimpleCacheDoomAll) {
  SetSimpleCacheMode();
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, SimpleCacheAppCacheOnlyDoomAll) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendDoomAll();
}

TEST_F(DiskCacheBackendTest, SimpleCacheOpenMissingFile) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  disk_cache::Entry* entry = nullptr;

  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  ASSERT_TRUE(entry != nullptr);
  entry->Close();
  entry = nullptr;

  // To make sure the file creation completed we need to call open again so that
  // we block until it actually created the files.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ASSERT_TRUE(entry != nullptr);
  entry->Close();
  entry = nullptr;

  // Delete one of the files in the entry.
  base::FilePath to_delete_file = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));
  EXPECT_TRUE(base::PathExists(to_delete_file));
  EXPECT_TRUE(base::DeleteFile(to_delete_file));

  // Failing to open the entry should delete the rest of these files.
  ASSERT_THAT(OpenEntry(key, &entry), IsError(net::ERR_FAILED));

  // Confirm the rest of the files are gone.
  for (int i = 1; i < disk_cache::kSimpleEntryNormalFileCount; ++i) {
    base::FilePath should_be_gone_file(cache_path_.AppendASCII(
        disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, i)));
    EXPECT_FALSE(base::PathExists(should_be_gone_file));
  }
}

TEST_F(DiskCacheBackendTest, SimpleCacheOpenBadFile) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  disk_cache::Entry* entry = nullptr;

  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  disk_cache::Entry* null = nullptr;
  ASSERT_NE(null, entry);
  entry->Close();
  entry = nullptr;

  // To make sure the file creation completed we need to call open again so that
  // we block until it actually created the files.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ASSERT_NE(null, entry);
  entry->Close();
  entry = nullptr;

  // The entry is being closed on the Simple Cache worker pool
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  // Write an invalid header for stream 0 and stream 1.
  base::FilePath entry_file1_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));

  disk_cache::SimpleFileHeader header;
  header.initial_magic_number = UINT64_C(0xbadf00d);
  EXPECT_TRUE(
      base::WriteFile(entry_file1_path, base::byte_span_from_ref(header)));
  ASSERT_THAT(OpenEntry(key, &entry), IsError(net::ERR_FAILED));
}

// Tests that the Simple Cache Backend fails to initialize with non-matching
// file structure on disk.
TEST_F(DiskCacheBackendTest, SimpleCacheOverBlockfileCache) {
  // Create a cache structure with the |BackendImpl|.
  InitCache();
  disk_cache::Entry* entry;
  const int kSize = 50;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  ASSERT_EQ(0, WriteData(entry, 0, 0, buffer.get(), 0, false));
  entry->Close();
  ResetCaches();

  // Check that the |SimpleBackendImpl| does not favor this structure.
  auto simple_cache = std::make_unique<disk_cache::SimpleBackendImpl>(
      /*file_operations_factory=*/nullptr, cache_path_, nullptr, nullptr, 0,
      net::DISK_CACHE, nullptr);
  net::TestCompletionCallback cb;
  simple_cache->Init(cb.callback());
  EXPECT_NE(net::OK, cb.WaitForResult());
  simple_cache.reset();
  DisableIntegrityCheck();
}

// Tests that the |BackendImpl| refuses to initialize on top of the files
// generated by the Simple Cache Backend.
TEST_F(DiskCacheBackendTest, BlockfileCacheOverSimpleCache) {
  // Create a cache structure with the |SimpleBackendImpl|.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry;
  const int kSize = 50;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  ASSERT_EQ(0, WriteData(entry, 0, 0, buffer.get(), 0, false));
  entry->Close();
  ResetCaches();

  // Check that the |BackendImpl| does not favor this structure.
  auto cache = std::make_unique<disk_cache::BackendImpl>(
      cache_path_, nullptr, nullptr, net::DISK_CACHE, nullptr);
  cache->SetUnitTestMode();
  net::TestCompletionCallback cb;
  cache->Init(cb.callback());
  EXPECT_NE(net::OK, cb.WaitForResult());
  cache.reset();
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, SimpleCacheFixEnumerators) {
  SetSimpleCacheMode();
  BackendFixEnumerators();
}

// Tests basic functionality of the SimpleBackend implementation of the
// enumeration API.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationBasics) {
  SetSimpleCacheMode();
  InitCache();
  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  // Check that enumeration returns all entries.
  std::set<std::string> keys_to_match(key_pool);
  std::unique_ptr<TestIterator> iter = CreateIterator();
  size_t count = 0;
  ASSERT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &keys_to_match, &count));
  iter.reset();
  EXPECT_EQ(key_pool.size(), count);
  EXPECT_TRUE(keys_to_match.empty());

  // Check that opening entries does not affect enumeration.
  keys_to_match = key_pool;
  iter = CreateIterator();
  count = 0;
  disk_cache::Entry* entry_opened_before;
  ASSERT_THAT(OpenEntry(*(key_pool.begin()), &entry_opened_before), IsOk());
  ASSERT_TRUE(EnumerateAndMatchKeys(key_pool.size() / 2, iter.get(),
                                    &keys_to_match, &count));

  disk_cache::Entry* entry_opened_middle;
  ASSERT_EQ(net::OK, OpenEntry(*(keys_to_match.begin()), &entry_opened_middle));
  ASSERT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &keys_to_match, &count));
  iter.reset();
  entry_opened_before->Close();
  entry_opened_middle->Close();

  EXPECT_EQ(key_pool.size(), count);
  EXPECT_TRUE(keys_to_match.empty());
}

// Tests that the enumerations are not affected by dooming an entry in the
// middle.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationWhileDoomed) {
  SetSimpleCacheMode();
  InitCache();
  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  // Check that enumeration returns all entries but the doomed one.
  std::set<std::string> keys_to_match(key_pool);
  std::unique_ptr<TestIterator> iter = CreateIterator();
  size_t count = 0;
  ASSERT_TRUE(EnumerateAndMatchKeys(key_pool.size() / 2, iter.get(),
                                    &keys_to_match, &count));

  std::string key_to_delete = *(keys_to_match.begin());
  DoomEntry(key_to_delete);
  keys_to_match.erase(key_to_delete);
  key_pool.erase(key_to_delete);
  ASSERT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &keys_to_match, &count));
  iter.reset();

  EXPECT_EQ(key_pool.size(), count);
  EXPECT_TRUE(keys_to_match.empty());
}

// Tests that enumerations are not affected by corrupt files.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationCorruption) {
  SetSimpleCacheMode();
  InitCache();
  // Create a corrupt entry.
  const std::string key = "the key";
  disk_cache::Entry* corrupted_entry;

  ASSERT_THAT(CreateEntry(key, &corrupted_entry), IsOk());
  ASSERT_TRUE(corrupted_entry);
  const int kSize = 50;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);
  ASSERT_EQ(kSize,
            WriteData(corrupted_entry, 0, 0, buffer.get(), kSize, false));
  ASSERT_EQ(kSize, ReadData(corrupted_entry, 0, 0, buffer.get(), kSize));
  corrupted_entry->Close();
  // Let all I/O finish so it doesn't race with corrupting the file below.
  RunUntilIdle();

  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  EXPECT_TRUE(
      disk_cache::simple_util::CreateCorruptFileForTests(key, cache_path_));
  EXPECT_EQ(key_pool.size() + 1, static_cast<size_t>(cache_->GetEntryCount()));

  // Check that enumeration returns all entries but the corrupt one.
  std::set<std::string> keys_to_match(key_pool);
  std::unique_ptr<TestIterator> iter = CreateIterator();
  size_t count = 0;
  ASSERT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &keys_to_match, &count));
  iter.reset();

  EXPECT_EQ(key_pool.size(), count);
  EXPECT_TRUE(keys_to_match.empty());
}

// Tests that enumerations don't leak memory when the backend is destructed
// mid-enumeration.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationDestruction) {
  SetSimpleCacheMode();
  InitCache();
  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  std::unique_ptr<TestIterator> iter = CreateIterator();
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
  EXPECT_TRUE(entry);
  disk_cache::ScopedEntryPtr entry_closer(entry);

  ResetCaches();
  // This test passes if we don't leak memory.
}

// Verify that tasks run in priority order when the experiment is enabled.
// Test has races, disabling until fixed: https://crbug.com/853283
TEST_F(DiskCacheBackendTest, DISABLED_SimpleCachePrioritizedEntryOrder) {
  base::test::ScopedFeatureList scoped_feature_list;
  SetSimpleCacheMode();
  InitCache();

  // Set the SimpleCache's worker pool to a sequenced type for testing
  // priority order.
  disk
"""


```