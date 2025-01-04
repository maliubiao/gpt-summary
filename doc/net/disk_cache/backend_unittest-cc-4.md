Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `net/disk_cache/backend_unittest.cc` file. They are looking for:

1. **General Functionality:** What does this code do?
2. **Relationship to JavaScript:** Does it interact with JavaScript, and how?
3. **Logic and Input/Output:** Are there logical steps, and what are example inputs and outputs?
4. **Common User/Programming Errors:** What mistakes can users or programmers make related to this code?
5. **User Path to this Code (Debugging):** How does a user action lead to this code being executed?
6. **Summary of Functionality:** A concise recap of what the code does.

Given that this is part 5 of 6, the request specifically asks to **summarize** the functionality of *this particular snippet*.

Let's analyze the code block by block:

* **Prioritization Test:** The first test (`TEST_F(DiskCacheBackendTest, SimpleCacheReprioritizeOnRead)`) demonstrates the re-prioritization of cache entries when they are read. It creates three entries with different initial priorities, writes data to them, and then reads them in a specific order. The test verifies that the entries are reordered based on the read access, with the most recently read entry getting higher priority.

* **Long Key Enumeration:** The next test (`TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationLongKeys)`) checks if the cache enumeration includes entries with long keys. It creates a set of random entries and one entry with a very long key, then verifies that enumerating the cache includes this long-keyed entry.

* **Quick Deletion Test:**  `TEST_F(DiskCacheBackendTest, SimpleCacheDeleteQuickly)` appears to be a stability test, checking that the cache doesn't crash when files are deleted immediately after being closed. This is marked as potentially flaky, suggesting it tests a specific race condition or timing issue.

* **Late Doom Scenario:** `TEST_F(DiskCacheBackendTest, SimpleCacheLateDoom)` investigates a scenario where an entry is marked for deletion ("doomed") after the cache index has been written to disk. It ensures that dooming the entry doesn't inadvertently invalidate the index by modifying the cache directory's modification time.

* **Negative Max Size Test:** `TEST_F(DiskCacheBackendTest, SimpleCacheNegMaxSize)` verifies how the cache handles a negative maximum size configuration. It expects the cache to fall back to a reasonable default size and also checks how experimental size scaling affects the maximum size.

* **Last Modified Time Test:** `TEST_F(DiskCacheBackendTest, SimpleLastModified)` addresses a historical bug where the "Last Modified" timestamp of a cache entry was incorrectly based on the cache directory's timestamp. This test specifically creates a situation to trigger this bug and confirms the fix.

* **File Descriptor Limit Test:** `TEST_F(DiskCacheBackendTest, SimpleFdLimit)` simulates a scenario with a large number of cache entries, testing how the cache handles file descriptor limits. It verifies the correct closing and reopening of files to stay within the limit and tracks these actions using histograms.

* **Sparse Eviction Test:** `TEST_F(DiskCacheBackendTest, SparseEvict)` tests cache eviction behavior when dealing with sparse data (data with gaps). It creates entries, writes sparse data that exceeds the cache's maximum size, and checks if the eviction process works correctly.

* **In-Memory Sparse Doom Test:** `TEST_F(DiskCacheBackendTest, InMemorySparseDoom)` focuses on the in-memory cache and how it handles dooming (marking for deletion) entries containing sparse data.

* **Maximum Size Limit Tests (2GiB):** The `Test2GiBLimit` function and the subsequent tests (`BlockFileMaxSizeLimit`, `InMemoryMaxSizeLimit`, `SimpleMaxSizeLimit`) verify the cache's behavior when configured with sizes close to or exceeding the 2GiB limit, testing different backend types.

* **OpenOrCreateEntry Tests:** The `BackendOpenOrCreateEntry` function and its specializations (`InMemoryOnlyOpenOrCreateEntry`, `MAYBE_BlockFileOpenOrCreateEntry`, `MAYBE_SimpleOpenOrCreateEntry`) test the `OpenOrCreateEntry` API, ensuring it correctly creates new entries or opens existing ones, and handles cases with doomed entries. It also covers cancellation of pending operations.

* **Dead Iterator Tests:** The `BackendDeadOpenNextEntry` function and its specializations test the behavior of an iterator when the cache backend has been destroyed.

* **Concurrent Doom and Iterator Tests:** The `BackendIteratorConcurrentDoom` function and its specializations verify how iterators behave when `DoomAllEntries` (deleting all entries) is called concurrently.

* **Corrupted Cache Recovery Tests:** The `EmptyCorruptSimpleCacheRecovery` and `MAYBE_NonEmptyCorruptSimpleCacheDoesNotRecover` tests examine how the simple cache attempts to recover from a corrupted index file, both when the cache is empty and when it contains data.

* **Ownership Transfer and Destruction Race Test:** `TEST_F(DiskCacheBackendTest, SimpleOwnershipTransferBackendDestroyRace)` checks for a specific race condition that could occur during entry creation and backend destruction in the simple cache.

* **Soft and Hard Reset Tests:** `TEST_F(DiskCacheBackendTest, SimpleCacheSoftResetKeepsValues)` and `TEST_F(DiskCacheBackendTest, SimpleCacheHardResetDropsValues)` test the different reset behaviors of the simple cache. Soft reset (kNeverReset) preserves existing entries, while hard reset (kReset) clears the cache.

* **Cancellation of Operation After Doom:** `TEST_F(DiskCacheBackendTest, SimpleCancelOpPendingDoom)` tests that operations queued after a pending doom operation are correctly canceled when the backend is destroyed.

* ** предотвращение утечек при создании после удаления (Don't Leak Post-Doom Create):** The final test (`TEST_F(DiskCacheBackendTest, SimpleDontLeakPostDoomCreate)`) ensures that an entry created optimistically after an entry with the same key has been marked for deletion doesn't lead to memory leaks if the backend is destroyed before the deletion is complete.

**Summarizing the functionality of this specific snippet:**

This section of `backend_unittest.cc` primarily focuses on **testing the functionality and robustness of the `SimpleCacheBackendImpl`**. It includes tests for:

* **Entry Prioritization:** Verifying that reading an entry increases its priority.
* **Handling Long Keys:** Ensuring enumeration works correctly with long cache keys.
* **Resilience to Quick Deletion:** Checking for crashes when entries are deleted immediately after closing.
* **Correct Handling of "Late" Dooming:**  Making sure dooming after index write doesn't corrupt the cache.
* **Handling Invalid Maximum Size:** Testing fallback behavior for negative max size values.
* **Correct Timestamping:** Verifying that entry timestamps are accurate and not based on directory modification times.
* **File Descriptor Management:**  Testing how the cache handles limits on open file descriptors.
* **Sparse Data Handling:** Checking eviction and dooming of entries with sparse data.
* **Maximum Size Limits:**  Verifying behavior when approaching or exceeding 2GiB limits.
* **`OpenOrCreateEntry` API:** Testing creation and opening of entries, including handling of doomed entries and operation cancellation.
* **Iterator Behavior After Backend Death:** Ensuring iterators fail gracefully after the cache is destroyed.
* **Concurrent Doom and Iteration:** Testing iterator behavior when entries are being deleted concurrently.
* **Corrupted Cache Recovery:**  Verifying the simple cache's ability (or inability) to recover from a corrupted index.
* **Race Conditions During Backend Destruction:**  Testing for potential issues during entry creation/opening when the backend is being destroyed.
* **Cache Reset Mechanisms:** Testing the difference between soft and hard resets.
* **Cancellation of Operations:** Ensuring that operations queued after a doom operation are correctly cancelled upon backend destruction.
* **Preventing Leaks in Post-Doom Creation:** Making sure entries created after a doom operation don't leak memory.
这是 `net/disk_cache/backend_unittest.cc` 文件的一部分，主要的功能是 **针对 `SimpleCacheBackendImpl` 这个特定的磁盘缓存后端进行单元测试**。

让我们逐个分析这些测试用例，并尝试回答你的问题：

**功能归纳:**

这部分代码主要集中在测试 `SimpleCacheBackendImpl` 的以下几个核心功能和特性：

1. **条目优先级管理 (Entry Reprioritization):**  测试了当读取一个缓存条目时，该条目的优先级会被提升。这对于优化缓存访问模式非常重要，经常访问的条目应该有更高的优先级，不容易被清理。
2. **长键支持 (Long Keys):** 验证了 `SimpleCacheBackendImpl` 可以正确处理和枚举具有较长键值的缓存条目。
3. **快速删除的鲁棒性 (Delete Quickly):**  测试了在高并发场景下，当缓存条目被快速创建和删除时，`SimpleCacheBackendImpl` 是否能够稳定运行，避免崩溃。这是一个压力测试。
4. **延迟删除 (Late Doom):** 测试了在某些特定时序下（例如，在缓存索引写入磁盘后删除条目），缓存的索引和实际数据是否能保持一致性，避免数据丢失或索引失效。
5. **负的最大缓存大小处理 (Neg MaxSize):** 验证了当设置一个负的最大缓存大小时，`SimpleCacheBackendImpl` 会采取合理的默认行为，而不是出现异常。同时，也测试了通过实验性配置调整缓存大小的功能。
6. **Last-Modified 时间戳 (LastModified):** 测试了缓存条目的 `Last-Modified` 时间戳是否正确地反映了条目本身的修改时间，而不是缓存目录的修改时间，避免时间戳信息的错误。
7. **文件描述符限制 (Fd Limit):**  测试了在文件描述符受限的环境下，`SimpleCacheBackendImpl` 如何通过关闭和重新打开文件来有效地管理文件描述符，避免因超出限制而导致错误。
8. **稀疏数据处理 (Sparse Evict, InMemorySparseDoom):**  测试了对于包含稀疏数据（数据中存在空洞）的缓存条目，缓存的清理和删除机制是否能够正确工作。`InMemorySparseDoom` 专门针对内存缓存进行测试。
9. **最大缓存大小限制 (2GiB Limit):**  针对不同的缓存类型 (`BlockFile`, `InMemory`, `Simple`)，测试了当尝试创建超过 2GiB 的缓存时，系统是否会进行限制，避免潜在的整数溢出或资源耗尽问题。
10. **OpenOrCreateEntry 操作 (BackendOpenOrCreateEntry):**  测试了 `OpenOrCreateEntry` 这个核心 API，验证其能够正确地打开已存在的条目或者创建新的条目，并处理并发操作和取消操作的情况。
11. **迭代器失效处理 (BackendDeadOpenNextEntry):**  测试了当缓存后端已经被销毁后，尝试使用迭代器访问缓存条目时，是否会返回预期的错误。
12. **并发删除与迭代器 (BackendIteratorConcurrentDoom):** 测试了在迭代器正在遍历缓存时，如果同时执行 `DoomAllEntries` (删除所有条目) 操作，迭代器是否能够正确处理，避免崩溃或数据访问错误。
13. **缓存损坏恢复 (EmptyCorruptSimpleCacheRecovery, MAYBE_NonEmptyCorruptSimpleCacheDoesNotRecover):**  测试了 `SimpleCacheBackendImpl` 在遇到损坏的索引文件时，是否能够进行恢复。当缓存为空时，可能会尝试重建索引；当缓存不为空时，通常会选择报错。
14. **所有权转移和后端销毁竞争 (SimpleOwnershipTransferBackendDestroyRace):**  测试了一个特定的竞争条件，即当一个条目即将返回给调用者，但缓存后端在此之前被销毁，是否会导致潜在的问题。
15. **软重置和硬重置 (SimpleCacheSoftResetKeepsValues, SimpleCacheHardResetDropsValues):**  测试了 `SimpleCacheBackendImpl` 的两种重置模式：软重置（保留现有条目）和硬重置（清除所有条目）。
16. **取消挂起的删除操作 (SimpleCancelOpPendingDoom):** 测试了在有挂起的删除操作时，如果尝试创建同名条目，并且缓存后端被销毁，是否能正确取消创建操作。
17. **防止创建后删除造成的内存泄漏 (SimpleDontLeakPostDoomCreate):** 测试了在一个条目被标记为删除后，如果又尝试创建一个同名的条目，并且后端在删除完成前被销毁，是否会造成内存泄漏。

**与 JavaScript 的关系:**

这个 C++ 代码是 Chromium 网络栈的一部分，负责底层的缓存管理。虽然它本身不直接与 JavaScript 代码交互，但它 **间接地影响着 JavaScript 的功能**，因为浏览器中的网络请求和资源缓存都依赖于这个缓存系统。

**举例说明:**

* 当 JavaScript 发起一个网络请求 (例如，通过 `fetch` API 或加载图片、CSS 文件) 时，Chromium 的网络栈会检查缓存中是否已存在对应的资源。
* 如果缓存后端是 `SimpleCacheBackendImpl`，那么这里的测试代码所覆盖的逻辑（例如，条目的优先级、是否能找到长键、缓存大小限制等）都会影响到缓存的查找、读取和写入操作。
* 如果一个 JavaScript 频繁访问的资源被正确地标记为高优先级（通过 `SimpleCacheReprioritizeOnRead` 测试保证），那么下次 JavaScript 请求这个资源时，就能更快地从缓存中获取，提升页面加载速度。
* 如果因为文件描述符限制导致缓存无法正常工作（`SimpleFdLimit` 测试覆盖），那么 JavaScript 发起的网络请求可能会失败或性能下降。

**逻辑推理、假设输入与输出:**

以 `TEST_F(DiskCacheBackendTest, SimpleCacheReprioritizeOnRead)` 为例：

**假设输入:**

* 缓存中存在三个条目，键分别为 "first", "second", "third"。
* "third" 条目被创建时具有最高的请求优先级 (`net::HIGHEST`)。
* 按照创建顺序，"first" 最先，"second" 次之。
* 数据被写入这三个条目的 stream 2。
* 之后按照 "second", "third", "first" 的顺序读取这三个条目的 stream 2 的数据。

**逻辑推理:**

* 由于 "third" 具有最高的请求优先级，它在创建时应该被排在较高的位置。
* 当读取条目时，被读取的条目会被提升优先级。
* 因此，读取顺序 "second", "third", "first" 会导致优先级顺序变为：先是 "third"（因为初始优先级高），然后是 "first"（因为在 "second" 之前创建），最后是 "second"。

**预期输出:**

* `finished_read_order` 向量最终的内容应该是 `{3, 1, 2}`，表示 "third" (3) 最先完成读取，然后是 "first" (1)，最后是 "second" (2)。这验证了读取操作会影响条目的优先级顺序。

**用户或编程常见的使用错误:**

* **配置不当的最大缓存大小:** 用户或开发者可能会设置过小或过大的最大缓存大小，导致缓存效率低下或占用过多磁盘空间。例如，将最大缓存大小设置为负数（虽然测试中会处理，但在实际配置中应该避免）。
* **错误地假设缓存行为:** 开发者可能会错误地假设缓存的清理策略或条目的过期机制，导致某些资源被意外地清理或保留。例如，没有考虑到读取操作会提升条目的优先级，导致一些他们认为应该被清理的条目仍然存在。
* **在高并发场景下不当使用缓存 API:**  例如，在短时间内大量创建和删除缓存条目，可能会触发 `SimpleCacheDeleteQuickly` 测试所覆盖的场景，如果代码没有处理好并发，可能会导致崩溃。
* **依赖错误的 Last-Modified 时间戳:**  在修复 `SimpleLastModified` 测试覆盖的 bug 之前，如果开发者依赖缓存条目的 `Last-Modified` 时间戳来判断资源是否更新，可能会得到错误的结果。

**用户操作到达这里的调试线索:**

假设用户报告了一个与缓存相关的 bug，例如：

1. **页面加载缓慢:** 用户抱怨某个网页加载速度很慢，即使之前已经访问过。这可能涉及到缓存的命中率不高，或者缓存的读取速度有问题。调试时，开发者可能会查看缓存的配置、条目的状态、以及缓存的清理策略。
2. **缓存未按预期工作:** 用户发现某些资源应该被缓存却没有被缓存，或者缓存的内容不是最新的。这可能涉及到缓存策略的配置错误，或者缓存的更新机制存在问题。调试时，开发者可能会检查缓存条目的元数据（例如，`Last-Modified` 时间戳、过期时间）以及缓存的索引信息。
3. **浏览器内存或磁盘占用过高:** 用户发现浏览器的缓存占用了大量的内存或磁盘空间。这可能涉及到缓存的最大大小配置不合理，或者缓存的清理策略没有生效。调试时，开发者可能会查看缓存的统计信息、缓存的大小限制以及缓存的清理过程。
4. **开发者工具中的缓存行为异常:**  开发者在使用浏览器开发者工具的网络面板时，发现缓存的行为与预期不符，例如，某些资源本应从缓存加载却没有，或者缓存的状态显示不正确。

当开发者开始调查这些问题时，他们可能会深入 Chromium 的网络栈代码，包括 `net/disk_cache` 目录下的代码。`backend_unittest.cc` 文件中的测试用例可以帮助他们理解不同缓存后端的行为和特性，并验证相关的修复是否有效。他们可能会：

* **阅读相关的测试用例:**  查找与用户报告的 bug 相似的测试用例，例如，如果用户遇到缓存未按预期清理的问题，开发者可能会查看与缓存清理策略相关的测试用例。
* **运行特定的测试用例:**  为了复现或验证某个特定的缓存行为，开发者可能会运行 `backend_unittest` 中的特定测试用例。
* **在调试器中单步执行缓存代码:**  为了更深入地理解缓存的工作原理，开发者可能会在调试器中设置断点，单步执行缓存的创建、读取、写入和清理等操作。

**总结其功能:**

总而言之，这部分 `net/disk_cache/backend_unittest.cc` 代码的主要功能是 **全面测试 `SimpleCacheBackendImpl` 的各项功能和鲁棒性**，确保其在各种场景下都能按照预期工作，并且能够有效地管理缓存数据，提升网络性能。这些测试覆盖了缓存的核心操作、错误处理、并发控制以及资源管理等方面，是保证 `SimpleCacheBackendImpl` 质量的关键。

Prompt: 
```
这是目录为net/disk_cache/backend_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
_cache::SimpleBackendImpl* simple_cache =
      static_cast<disk_cache::SimpleBackendImpl*>(cache_.get());
  auto task_runner = base::ThreadPool::CreateSequencedTaskRunner(
      {base::TaskPriority::USER_VISIBLE, base::MayBlock()});
  simple_cache->SetTaskRunnerForTesting(task_runner);

  // Create three entries. Priority order is 3, 1, 2 because 3 has the highest
  // request priority and 1 is created before 2.
  disk_cache::Entry* entry1 = nullptr;
  disk_cache::Entry* entry2 = nullptr;
  disk_cache::Entry* entry3 = nullptr;
  ASSERT_THAT(CreateEntryWithPriority("first", net::LOWEST, &entry1), IsOk());
  ASSERT_THAT(CreateEntryWithPriority("second", net::LOWEST, &entry2), IsOk());
  ASSERT_THAT(CreateEntryWithPriority("third", net::HIGHEST, &entry3), IsOk());

  // Write some data to the entries.
  const int kSize = 10;
  auto buf1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf1->data(), kSize, false);
  CacheTestFillBuffer(buf2->data(), kSize, false);
  CacheTestFillBuffer(buf3->data(), kSize, false);

  // Write to stream 2 because it's the only stream that can't be read from
  // synchronously.
  EXPECT_EQ(kSize, WriteData(entry1, 2, 0, buf1.get(), kSize, true));
  EXPECT_EQ(kSize, WriteData(entry2, 2, 0, buf1.get(), kSize, true));
  EXPECT_EQ(kSize, WriteData(entry3, 2, 0, buf1.get(), kSize, true));

  // Wait until the task_runner's queue is empty (WriteData might have
  // optimistically returned synchronously but still had some tasks to run in
  // the worker pool.
  base::RunLoop run_loop;
  task_runner->PostTaskAndReply(FROM_HERE, base::DoNothing(),
                                run_loop.QuitClosure());
  run_loop.Run();

  std::vector<int> finished_read_order;
  auto finished_callback = [](std::vector<int>* finished_read_order,
                              int entry_number, base::OnceClosure quit_closure,
                              int rv) {
    finished_read_order->push_back(entry_number);
    if (quit_closure)
      std::move(quit_closure).Run();
  };

  auto read_buf1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto read_buf2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto read_buf3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);

  // Read from the entries in order 2, 3, 1. They should be reprioritized to
  // 3, 1, 2.
  base::RunLoop read_run_loop;

  entry2->ReadData(2, 0, read_buf2.get(), kSize,
                   base::BindOnce(finished_callback, &finished_read_order, 2,
                                  read_run_loop.QuitClosure()));
  entry3->ReadData(2, 0, read_buf3.get(), kSize,
                   base::BindOnce(finished_callback, &finished_read_order, 3,
                                  base::OnceClosure()));
  entry1->ReadData(2, 0, read_buf1.get(), kSize,
                   base::BindOnce(finished_callback, &finished_read_order, 1,
                                  base::OnceClosure()));
  EXPECT_EQ(0u, finished_read_order.size());

  read_run_loop.Run();
  EXPECT_EQ((std::vector<int>{3, 1, 2}), finished_read_order);
  entry1->Close();
  entry2->Close();
  entry3->Close();
}

// Tests that enumerations include entries with long keys.
TEST_F(DiskCacheBackendTest, SimpleCacheEnumerationLongKeys) {
  SetSimpleCacheMode();
  InitCache();
  std::set<std::string> key_pool;
  ASSERT_TRUE(CreateSetOfRandomEntries(&key_pool));

  const size_t long_key_length =
      disk_cache::SimpleSynchronousEntry::kInitialHeaderRead + 10;
  std::string long_key(long_key_length, 'X');
  key_pool.insert(long_key);
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(long_key.c_str(), &entry), IsOk());
  entry->Close();

  std::unique_ptr<TestIterator> iter = CreateIterator();
  size_t count = 0;
  EXPECT_TRUE(EnumerateAndMatchKeys(-1, iter.get(), &key_pool, &count));
  EXPECT_TRUE(key_pool.empty());
}

// Tests that a SimpleCache doesn't crash when files are deleted very quickly
// after closing.
// NOTE: IF THIS TEST IS FLAKY THEN IT IS FAILING. See https://crbug.com/416940
TEST_F(DiskCacheBackendTest, SimpleCacheDeleteQuickly) {
  SetSimpleCacheMode();
  for (int i = 0; i < 100; ++i) {
    InitCache();
    ResetCaches();
    EXPECT_TRUE(CleanupCacheDir());
  }
}

TEST_F(DiskCacheBackendTest, SimpleCacheLateDoom) {
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry("first", &entry1), IsOk());
  ASSERT_THAT(CreateEntry("second", &entry2), IsOk());
  entry1->Close();

  // Ensure that the directory mtime is flushed to disk before serializing the
  // index.
  disk_cache::FlushCacheThreadForTesting();
#if BUILDFLAG(IS_POSIX)
  base::File cache_dir(cache_path_,
                       base::File::FLAG_OPEN | base::File::FLAG_READ);
  EXPECT_TRUE(cache_dir.Flush());
#endif  // BUILDFLAG(IS_POSIX)
  ResetCaches();
  disk_cache::FlushCacheThreadForTesting();

  // The index is now written. Dooming the last entry can't delete a file,
  // because that would advance the cache directory mtime and invalidate the
  // index.
  entry2->Doom();
  entry2->Close();

  DisableFirstCleanup();
  InitCache();
  EXPECT_EQ(disk_cache::SimpleIndex::INITIALIZE_METHOD_LOADED,
            simple_cache_impl_->index()->init_method());
}

TEST_F(DiskCacheBackendTest, SimpleCacheNegMaxSize) {
  SetMaxSize(-1);
  SetSimpleCacheMode();
  InitCache();
  // We don't know what it will pick, but it's limited to what
  // disk_cache::PreferredCacheSize would return, scaled by the size experiment,
  // which only goes as much as 4x. It definitely should not be MAX_UINT64.
  EXPECT_NE(simple_cache_impl_->index()->max_size(),
            std::numeric_limits<uint64_t>::max());

  int max_default_size =
      2 * disk_cache::PreferredCacheSize(std::numeric_limits<int32_t>::max());

  ASSERT_GE(max_default_size, 0);
  EXPECT_LT(simple_cache_impl_->index()->max_size(),
            static_cast<unsigned>(max_default_size));

  uint64_t max_size_without_scaling = simple_cache_impl_->index()->max_size();

  // Scale to 200%. The size should be twice of |max_size_without_scaling| but
  // since that's capped on 20% of available size, checking for the size to be
  // between max_size_without_scaling and max_size_without_scaling*2.
  {
    base::test::ScopedFeatureList scoped_feature_list;
    std::map<std::string, std::string> field_trial_params;
    field_trial_params["percent_relative_size"] = "200";
    scoped_feature_list.InitAndEnableFeatureWithParameters(
        disk_cache::kChangeDiskCacheSizeExperiment, field_trial_params);

    InitCache();

    uint64_t max_size_scaled = simple_cache_impl_->index()->max_size();

    EXPECT_GE(max_size_scaled, max_size_without_scaling);
    EXPECT_LE(max_size_scaled, 2 * max_size_without_scaling);
  }
}

TEST_F(DiskCacheBackendTest, SimpleLastModified) {
  // Simple cache used to incorrectly set LastModified on entries based on
  // timestamp of the cache directory, and not the entries' file
  // (https://crbug.com/714143). So this test arranges for a situation
  // where this would occur by doing:
  // 1) Write entry 1
  // 2) Delay
  // 3) Write entry 2. This sets directory time stamp to be different from
  //    timestamp of entry 1 (due to the delay)
  // It then checks whether the entry 1 got the proper timestamp or not.

  SetSimpleCacheMode();
  InitCache();
  std::string key1 = GenerateKey(true);
  std::string key2 = GenerateKey(true);

  disk_cache::Entry* entry1;
  ASSERT_THAT(CreateEntry(key1, &entry1), IsOk());

  // Make the Create complete --- SimpleCache can handle it optimistically,
  // and if we let it go fully async then trying to flush the Close might just
  // flush the Create.
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  entry1->Close();

  // Make the ::Close actually complete, since it is asynchronous.
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  Time entry1_timestamp = Time::NowFromSystemTime();

  // Don't want AddDelay since it sleep 1s(!) for SimpleCache, and we don't
  // care about reduced precision in index here.
  while (base::Time::NowFromSystemTime() <=
         (entry1_timestamp + base::Milliseconds(10))) {
    base::PlatformThread::Sleep(base::Milliseconds(1));
  }

  disk_cache::Entry* entry2;
  ASSERT_THAT(CreateEntry(key2, &entry2), IsOk());
  entry2->Close();
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  disk_cache::Entry* reopen_entry1;
  ASSERT_THAT(OpenEntry(key1, &reopen_entry1), IsOk());

  // This shouldn't pick up entry2's write time incorrectly.
  EXPECT_LE(reopen_entry1->GetLastModified(), entry1_timestamp);
  reopen_entry1->Close();
}

TEST_F(DiskCacheBackendTest, SimpleFdLimit) {
  base::HistogramTester histogram_tester;
  SetSimpleCacheMode();
  // Make things blocking so CreateEntry actually waits for file to be
  // created.
  SetCacheType(net::APP_CACHE);
  InitCache();

  disk_cache::Entry* entries[kLargeNumEntries];
  std::string keys[kLargeNumEntries];
  for (int i = 0; i < kLargeNumEntries; ++i) {
    keys[i] = GenerateKey(true);
    ASSERT_THAT(CreateEntry(keys[i], &entries[i]), IsOk());
  }

  // Note the fixture sets the file limit to 64.
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_CLOSE_FILE,
                                     kLargeNumEntries - 64);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_REOPEN_FILE, 0);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_FAIL_REOPEN_FILE, 0);

  const int kSize = 25000;
  auto buf1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf1->data(), kSize, false);

  auto buf2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf2->data(), kSize, false);

  // Doom an entry and create a new one with same name, to test that both
  // re-open properly.
  EXPECT_EQ(net::OK, DoomEntry(keys[0]));
  disk_cache::Entry* alt_entry;
  ASSERT_THAT(CreateEntry(keys[0], &alt_entry), IsOk());

  // One more file closure here to accommodate for alt_entry.
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_CLOSE_FILE,
                                     kLargeNumEntries - 64 + 1);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_REOPEN_FILE, 0);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_FAIL_REOPEN_FILE, 0);

  // Do some writes in [1...kLargeNumEntries) range, both testing bring those in
  // and kicking out [0] and [alt_entry]. These have to be to stream != 0 to
  // actually need files.
  for (int i = 1; i < kLargeNumEntries; ++i) {
    EXPECT_EQ(kSize, WriteData(entries[i], 1, 0, buf1.get(), kSize, true));
    auto read_buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
    ASSERT_EQ(kSize, ReadData(entries[i], 1, 0, read_buf.get(), kSize));
    EXPECT_EQ(0, memcmp(read_buf->data(), buf1->data(), kSize));
  }

  histogram_tester.ExpectBucketCount(
      "SimpleCache.FileDescriptorLimiterAction",
      disk_cache::FD_LIMIT_CLOSE_FILE,
      kLargeNumEntries - 64 + 1 + kLargeNumEntries - 1);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_REOPEN_FILE,
                                     kLargeNumEntries - 1);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_FAIL_REOPEN_FILE, 0);
  EXPECT_EQ(kSize, WriteData(entries[0], 1, 0, buf1.get(), kSize, true));
  EXPECT_EQ(kSize, WriteData(alt_entry, 1, 0, buf2.get(), kSize, true));

  auto read_buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  ASSERT_EQ(kSize, ReadData(entries[0], 1, 0, read_buf.get(), kSize));
  EXPECT_EQ(0, memcmp(read_buf->data(), buf1->data(), kSize));

  auto read_buf2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  ASSERT_EQ(kSize, ReadData(alt_entry, 1, 0, read_buf2.get(), kSize));
  EXPECT_EQ(0, memcmp(read_buf2->data(), buf2->data(), kSize));

  // Two more things than last time --- entries[0] and |alt_entry|
  histogram_tester.ExpectBucketCount(
      "SimpleCache.FileDescriptorLimiterAction",
      disk_cache::FD_LIMIT_CLOSE_FILE,
      kLargeNumEntries - 64 + 1 + kLargeNumEntries - 1 + 2);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_REOPEN_FILE,
                                     kLargeNumEntries + 1);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_FAIL_REOPEN_FILE, 0);

  for (auto* entry : entries) {
    entry->Close();
    RunUntilIdle();
  }
  alt_entry->Close();
  RunUntilIdle();

  // Closes have to pull things in to write out the footer, but they also
  // free up FDs.
  histogram_tester.ExpectBucketCount(
      "SimpleCache.FileDescriptorLimiterAction",
      disk_cache::FD_LIMIT_CLOSE_FILE,
      kLargeNumEntries - 64 + 1 + kLargeNumEntries - 1 + 2);
  histogram_tester.ExpectBucketCount(
      "SimpleCache.FileDescriptorLimiterAction",
      disk_cache::FD_LIMIT_REOPEN_FILE,
      kLargeNumEntries - 64 + 1 + kLargeNumEntries - 1 + 2);
  histogram_tester.ExpectBucketCount("SimpleCache.FileDescriptorLimiterAction",
                                     disk_cache::FD_LIMIT_FAIL_REOPEN_FILE, 0);
}

TEST_F(DiskCacheBackendTest, SparseEvict) {
  const int kMaxSize = 512;

  SetMaxSize(kMaxSize);
  InitCache();

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(64);
  CacheTestFillBuffer(buffer->data(), 64, false);

  disk_cache::Entry* entry0 = nullptr;
  ASSERT_THAT(CreateEntry("http://www.0.com/", &entry0), IsOk());

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry("http://www.1.com/", &entry1), IsOk());

  disk_cache::Entry* entry2 = nullptr;
  // This strange looking domain name affects cache trim order
  // due to hashing
  ASSERT_THAT(CreateEntry("http://www.15360.com/", &entry2), IsOk());

  // Write sparse data to put us over the eviction threshold
  ASSERT_EQ(64, WriteSparseData(entry0, 0, buffer.get(), 64));
  ASSERT_EQ(1, WriteSparseData(entry0, 67108923, buffer.get(), 1));
  ASSERT_EQ(1, WriteSparseData(entry1, 53, buffer.get(), 1));
  ASSERT_EQ(1, WriteSparseData(entry2, 0, buffer.get(), 1));

  // Closing these in a special order should not lead to buggy reentrant
  // eviction.
  entry1->Close();
  entry2->Close();
  entry0->Close();
}

TEST_F(DiskCacheBackendTest, InMemorySparseDoom) {
  const int kMaxSize = 512;

  SetMaxSize(kMaxSize);
  SetMemoryOnlyMode();
  InitCache();

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(64);
  CacheTestFillBuffer(buffer->data(), 64, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("http://www.0.com/", &entry), IsOk());

  ASSERT_EQ(net::ERR_FAILED, WriteSparseData(entry, 4337, buffer.get(), 64));
  entry->Close();

  // Dooming all entries at this point should properly iterate over
  // the parent and its children
  DoomAllEntries();
}

void DiskCacheBackendTest::Test2GiBLimit(net::CacheType type,
                                         net::BackendType backend_type,
                                         bool expect_limit) {
  TestBackendResultCompletionCallback cb;
  ASSERT_TRUE(CleanupCacheDir());
  // We'll either create something of a different backend or have failed
  // creation.
  DisableIntegrityCheck();

  int64_t size = std::numeric_limits<int32_t>::max();

  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      type, backend_type,
      /*file_operations=*/nullptr, cache_path_, size,
      disk_cache::ResetHandling::kNeverReset, nullptr, cb.callback());
  rv = cb.GetResult(std::move(rv));
  ASSERT_THAT(rv.net_error, IsOk());
  EXPECT_TRUE(rv.backend);
  rv.backend.reset();

  size += 1;
  rv = disk_cache::CreateCacheBackend(
      type, backend_type,
      /*file_operations=*/nullptr, cache_path_, size,
      disk_cache::ResetHandling::kNeverReset, nullptr, cb.callback());
  rv = cb.GetResult(std::move(rv));
  if (expect_limit) {
    EXPECT_NE(rv.net_error, net::OK);
    EXPECT_FALSE(rv.backend);
  } else {
    ASSERT_THAT(rv.net_error, IsOk());
    EXPECT_TRUE(rv.backend);
    rv.backend.reset();
  }
}

// Disabled on android since this test requires cache creator to create
// blockfile caches.
#if !BUILDFLAG(IS_ANDROID)
TEST_F(DiskCacheBackendTest, BlockFileMaxSizeLimit) {
  // Note: blockfile actually has trouble before 2GiB as well.
  Test2GiBLimit(net::DISK_CACHE, net::CACHE_BACKEND_BLOCKFILE,
                /*expect_limit=*/true);
}
#endif

TEST_F(DiskCacheBackendTest, InMemoryMaxSizeLimit) {
  Test2GiBLimit(net::MEMORY_CACHE, net::CACHE_BACKEND_DEFAULT,
                /*expect_limit=*/true);
}

TEST_F(DiskCacheBackendTest, SimpleMaxSizeLimit) {
  Test2GiBLimit(net::DISK_CACHE, net::CACHE_BACKEND_SIMPLE,
                /*expect_limit=*/false);
}

void DiskCacheBackendTest::BackendOpenOrCreateEntry() {
  // Avoid the weird kNoRandom flag on blockfile, since this needs to
  // test cleanup behavior actually used in production.
  if (memory_only_) {
    InitCache();
  } else {
    CleanupCacheDir();
    // Since we're not forcing a clean shutdown, integrity check may fail.
    DisableIntegrityCheck();
    CreateBackend(disk_cache::kNone);
  }

  // Test that new key is created.
  disk_cache::EntryResult es1 = OpenOrCreateEntry("first");
  ASSERT_THAT(es1.net_error(), IsOk());
  ASSERT_FALSE(es1.opened());
  disk_cache::Entry* e1 = es1.ReleaseEntry();
  ASSERT_TRUE(nullptr != e1);

  // Test that existing key is opened and its entry matches.
  disk_cache::EntryResult es2 = OpenOrCreateEntry("first");
  ASSERT_THAT(es2.net_error(), IsOk());
  ASSERT_TRUE(es2.opened());
  disk_cache::Entry* e2 = es2.ReleaseEntry();
  ASSERT_TRUE(nullptr != e2);
  ASSERT_EQ(e1, e2);

  // Test that different keys' entries are not the same.
  disk_cache::EntryResult es3 = OpenOrCreateEntry("second");
  ASSERT_THAT(es3.net_error(), IsOk());
  ASSERT_FALSE(es3.opened());
  disk_cache::Entry* e3 = es3.ReleaseEntry();
  ASSERT_TRUE(nullptr != e3);
  ASSERT_NE(e3, e1);

  // Test that a new entry can be created with the same key as a doomed entry.
  e3->Doom();
  disk_cache::EntryResult es4 = OpenOrCreateEntry("second");
  ASSERT_THAT(es4.net_error(), IsOk());
  ASSERT_FALSE(es4.opened());
  disk_cache::Entry* e4 = es4.ReleaseEntry();
  ASSERT_TRUE(nullptr != e4);
  ASSERT_NE(e4, e3);

  // Verify the expected number of entries
  ASSERT_EQ(2, cache_->GetEntryCount());

  e1->Close();
  e2->Close();
  e3->Close();
  e4->Close();

  // Test proper cancellation of callback. In-memory cache
  // is always synchronous, so this isn't' meaningful for it.
  if (!memory_only_) {
    TestEntryResultCompletionCallback callback;

    // Using "first" here:
    // 1) It's an existing entry, so SimpleCache can't cheat with an optimistic
    //    create.
    // 2) "second"'s creation is a cheated post-doom create one, which also
    //    makes testing trickier.
    EntryResult result =
        cache_->OpenOrCreateEntry("first", net::HIGHEST, callback.callback());
    ASSERT_EQ(net::ERR_IO_PENDING, result.net_error());
    ResetCaches();

    // Callback is supposed to be cancelled, so have to flush everything
    // to check for any trouble.
    disk_cache::FlushCacheThreadForTesting();
    RunUntilIdle();
    EXPECT_FALSE(callback.have_result());
  }
}

TEST_F(DiskCacheBackendTest, InMemoryOnlyOpenOrCreateEntry) {
  SetMemoryOnlyMode();
  BackendOpenOrCreateEntry();
}

TEST_F(DiskCacheBackendTest, MAYBE_BlockFileOpenOrCreateEntry) {
  BackendOpenOrCreateEntry();
}

TEST_F(DiskCacheBackendTest, MAYBE_SimpleOpenOrCreateEntry) {
  SetSimpleCacheMode();
  BackendOpenOrCreateEntry();
}

void DiskCacheBackendTest::BackendDeadOpenNextEntry() {
  InitCache();
  std::unique_ptr<disk_cache::Backend::Iterator> iter =
      cache_->CreateIterator();
  ResetCaches();
  EntryResult result = iter->OpenNextEntry(base::DoNothing());
  ASSERT_EQ(net::ERR_FAILED, result.net_error());
}

TEST_F(DiskCacheBackendTest, BlockFileBackendDeadOpenNextEntry) {
  BackendDeadOpenNextEntry();
}

TEST_F(DiskCacheBackendTest, SimpleBackendDeadOpenNextEntry) {
  SetSimpleCacheMode();
  BackendDeadOpenNextEntry();
}

TEST_F(DiskCacheBackendTest, InMemorySimpleBackendDeadOpenNextEntry) {
  SetMemoryOnlyMode();
  BackendDeadOpenNextEntry();
}

void DiskCacheBackendTest::BackendIteratorConcurrentDoom() {
  disk_cache::Entry* entry1 = nullptr;
  disk_cache::Entry* entry2 = nullptr;
  EXPECT_EQ(net::OK, CreateEntry("Key0", &entry1));
  EXPECT_EQ(net::OK, CreateEntry("Key1", &entry2));

  std::unique_ptr<disk_cache::Backend::Iterator> iter =
      cache_->CreateIterator();

  disk_cache::Entry* entry3 = nullptr;
  EXPECT_EQ(net::OK, OpenEntry("Key0", &entry3));

  TestEntryResultCompletionCallback cb;
  EntryResult result_iter = iter->OpenNextEntry(cb.callback());
  result_iter = cb.GetResult(std::move(result_iter));
  EXPECT_EQ(net::OK, result_iter.net_error());

  net::TestCompletionCallback cb_doom;
  int rv_doom = cache_->DoomAllEntries(cb_doom.callback());
  EXPECT_EQ(net::OK, cb_doom.GetResult(rv_doom));

  TestEntryResultCompletionCallback cb2;
  EntryResult result_iter2 = iter->OpenNextEntry(cb2.callback());
  result_iter2 = cb2.GetResult(std::move(result_iter2));

  EXPECT_TRUE(result_iter2.net_error() == net::ERR_FAILED ||
              result_iter2.net_error() == net::OK);

  entry1->Close();
  entry2->Close();
  entry3->Close();
}

TEST_F(DiskCacheBackendTest, BlockFileIteratorConcurrentDoom) {
  // Init in normal mode, bug not reproducible with kNoRandom. Still need to
  // let the test fixture know the new eviction algorithm will be on.
  CleanupCacheDir();
  SetNewEviction();
  CreateBackend(disk_cache::kNone);
  BackendIteratorConcurrentDoom();
}

TEST_F(DiskCacheBackendTest, SimpleIteratorConcurrentDoom) {
  SetSimpleCacheMode();
  InitCache();
  BackendIteratorConcurrentDoom();
}

TEST_F(DiskCacheBackendTest, InMemoryConcurrentDoom) {
  SetMemoryOnlyMode();
  InitCache();
  BackendIteratorConcurrentDoom();
}

TEST_F(DiskCacheBackendTest, EmptyCorruptSimpleCacheRecovery) {
  SetSimpleCacheMode();

  const std::string kCorruptData("corrupted");

  // Create a corrupt fake index in an otherwise empty simple cache.
  ASSERT_TRUE(base::PathExists(cache_path_));
  const base::FilePath index = cache_path_.AppendASCII("index");
  ASSERT_TRUE(base::WriteFile(index, kCorruptData));

  TestBackendResultCompletionCallback cb;

  // Simple cache should be able to recover.
  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
      cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, cb.callback());
  rv = cb.GetResult(std::move(rv));
  EXPECT_THAT(rv.net_error, IsOk());
}

TEST_F(DiskCacheBackendTest, MAYBE_NonEmptyCorruptSimpleCacheDoesNotRecover) {
  SetSimpleCacheMode();
  BackendOpenOrCreateEntry();

  const std::string kCorruptData("corrupted");

  // Corrupt the fake index file for the populated simple cache.
  ASSERT_TRUE(base::PathExists(cache_path_));
  const base::FilePath index = cache_path_.AppendASCII("index");
  ASSERT_TRUE(base::WriteFile(index, kCorruptData));

  TestBackendResultCompletionCallback cb;

  // Simple cache should not be able to recover when there are entry files.
  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
      cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
      /*net_log=*/nullptr, cb.callback());
  rv = cb.GetResult(std::move(rv));
  EXPECT_THAT(rv.net_error, IsError(net::ERR_FAILED));
}

TEST_F(DiskCacheBackendTest, SimpleOwnershipTransferBackendDestroyRace) {
  struct CleanupContext {
    explicit CleanupContext(bool* ran_ptr) : ran_ptr(ran_ptr) {}
    ~CleanupContext() {
      *ran_ptr = true;
    }

    raw_ptr<bool> ran_ptr;
  };

  const char kKey[] = "skeleton";

  // This test was for a fix for see https://crbug.com/946349, but the mechanics
  // of that failure became impossible after a follow up API refactor. Still,
  // the timing is strange, and warrant coverage; in particular this tests what
  // happen if the SimpleBackendImpl is destroyed after SimpleEntryImpl
  // decides to return an entry to the caller, but before the callback is run.
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());
  // Make sure create actually succeeds, not just optimistically.
  RunUntilIdle();

  bool cleanup_context_ran = false;
  auto cleanup_context = std::make_unique<CleanupContext>(&cleanup_context_ran);

  // The OpenEntry code below will find a pre-existing entry in a READY state,
  // so it will immediately post a task to return a result. Destroying the
  // backend before running the event loop again will run that callback in the
  // dead-backend state, while OpenEntry completion was still with it alive.

  EntryResult result = cache_->OpenEntry(
      kKey, net::HIGHEST,
      base::BindOnce(
          [](std::unique_ptr<CleanupContext>, EntryResult result) {
            // The callback is here for ownership of CleanupContext,
            // and it shouldn't get invoked in this test. Normal
            // one would transfer result.entry to CleanupContext.
            ADD_FAILURE() << "This should not actually run";

            // ... but if it ran, it also shouldn't see the pointer.
            EXPECT_EQ(nullptr, result.ReleaseEntry());
          },
          std::move(cleanup_context)));
  EXPECT_EQ(net::ERR_IO_PENDING, result.net_error());
  ResetCaches();

  // Give CleanupContext a chance to do its thing.
  RunUntilIdle();
  EXPECT_TRUE(cleanup_context_ran);

  entry->Close();
}

// Verify that reloading the cache will preserve indices in kNeverReset mode.
TEST_F(DiskCacheBackendTest, SimpleCacheSoftResetKeepsValues) {
  SetSimpleCacheMode();
  SetCacheType(net::APP_CACHE);
  DisableFirstCleanup();
  CleanupCacheDir();

  {  // Do the initial cache creation then delete the values.
    TestBackendResultCompletionCallback cb;

    // Create an initial back-end and wait for indexing
    disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
        net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
        cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
        /*net_log=*/nullptr, cb.callback());
    rv = cb.GetResult(std::move(rv));
    EXPECT_THAT(rv.net_error, IsOk());
    std::unique_ptr<disk_cache::Backend> cache = std::move(rv.backend);
    ASSERT_TRUE(cache.get());
    WaitForSimpleCacheIndexAndCheck(cache.get());

    // Create an entry in the cache
    CreateKeyAndCheck(cache.get(), "key");
  }

  RunUntilIdle();

  {  // Do the second cache creation with no reset flag, preserving entries.
    TestBackendResultCompletionCallback cb;

    disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
        net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
        cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
        /*net_log=*/nullptr, cb.callback());
    rv = cb.GetResult(std::move(rv));
    EXPECT_THAT(rv.net_error, IsOk());
    std::unique_ptr<disk_cache::Backend> cache = std::move(rv.backend);
    ASSERT_TRUE(cache.get());
    WaitForSimpleCacheIndexAndCheck(cache.get());

    // The entry should be present, as a forced reset was not called for.
    EXPECT_TRUE(static_cast<disk_cache::SimpleBackendImpl*>(cache.get())
                    ->index()
                    ->Has(disk_cache::simple_util::GetEntryHashKey("key")));
  }
}

// Verify that reloading the cache will not preserve indices in Reset mode.
TEST_F(DiskCacheBackendTest, SimpleCacheHardResetDropsValues) {
  SetSimpleCacheMode();
  SetCacheType(net::APP_CACHE);
  DisableFirstCleanup();
  CleanupCacheDir();

  {  // Create the initial back-end.
    TestBackendResultCompletionCallback cb;

    disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
        net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
        cache_path_, 0, disk_cache::ResetHandling::kNeverReset,
        /*net_log=*/nullptr, cb.callback());
    rv = cb.GetResult(std::move(rv));
    EXPECT_THAT(rv.net_error, IsOk());
    std::unique_ptr<disk_cache::Backend> cache = std::move(rv.backend);
    ASSERT_TRUE(cache.get());
    WaitForSimpleCacheIndexAndCheck(cache.get());

    // Create an entry in the cache.
    CreateKeyAndCheck(cache.get(), "key");
  }

  RunUntilIdle();

  {  // Re-load cache with a reset flag, which should ignore existing entries.
    TestBackendResultCompletionCallback cb;

    disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
        net::APP_CACHE, net::CACHE_BACKEND_SIMPLE, /*file_operations=*/nullptr,
        cache_path_, 0, disk_cache::ResetHandling::kReset, /*net_log=*/nullptr,
        cb.callback());
    rv = cb.GetResult(std::move(rv));
    EXPECT_THAT(rv.net_error, IsOk());
    std::unique_ptr<disk_cache::Backend> cache = std::move(rv.backend);
    ASSERT_TRUE(cache.get());
    WaitForSimpleCacheIndexAndCheck(cache.get());

    // The entry shouldn't be present, as a forced reset was called for.
    EXPECT_FALSE(static_cast<disk_cache::SimpleBackendImpl*>(cache.get())
                     ->index()
                     ->Has(disk_cache::simple_util::GetEntryHashKey("key")));

    // Add the entry back in the cache, then make sure it's present.
    CreateKeyAndCheck(cache.get(), "key");

    EXPECT_TRUE(static_cast<disk_cache::SimpleBackendImpl*>(cache.get())
                    ->index()
                    ->Has(disk_cache::simple_util::GetEntryHashKey("key")));
  }
}

// Test to make sure cancelation of backend operation that got queued after
// a pending doom on backend destruction happens properly.
TEST_F(DiskCacheBackendTest, SimpleCancelOpPendingDoom) {
  struct CleanupContext {
    explicit CleanupContext(bool* ran_ptr) : ran_ptr(ran_ptr) {}
    ~CleanupContext() { *ran_ptr = true; }

    raw_ptr<bool> ran_ptr;
  };

  const char kKey[] = "skeleton";

  // Disable optimistic ops.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());
  entry->Close();

  // Queue doom.
  cache_->DoomEntry(kKey, net::LOWEST, base::DoNothing());

  // Queue create after it.
  bool cleanup_context_ran = false;
  auto cleanup_context = std::make_unique<CleanupContext>(&cleanup_context_ran);

  EntryResult entry_result = cache_->CreateEntry(
      kKey, net::HIGHEST,
      base::BindOnce(
          [](std::unique_ptr<CleanupContext>, EntryResult result) {
            ADD_FAILURE() << "This should not actually run";
          },
          std::move(cleanup_context)));

  EXPECT_EQ(net::ERR_IO_PENDING, entry_result.net_error());
  ResetCaches();

  RunUntilIdle();
  EXPECT_TRUE(cleanup_context_ran);
}

TEST_F(DiskCacheBackendTest, SimpleDontLeakPostDoomCreate) {
  // If an entry has been optimistically created after a pending doom, and the
  // backend destroyed before the doom completed, the entry would get wedged,
  // with no operations on it workable and entry leaked.
  // (See https://crbug.com/1015774).
  const char kKey[] = "for_lock";
  const int kBufSize = 2 * 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufSize);
  CacheTestFillBuffer(buffer->data(), kBufSize, true);

  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());
  entry->Close();

  // Make sure create actually succeeds, not just optimistically.
  RunUntilIdle();

  // Queue doom.
  int rv = cache_->DoomEntry(kKey, net::LOWEST, base::DoNothing());
  ASSERT_EQ(net::ERR_IO_PENDING, rv);

  // And then do a create. This actually succeeds optimistically.
  EntryResult result =
      cache_->CreateEntry(kKey, net::LOWEST, base::DoNothing());
  ASSERT_EQ(net::OK, result.net_error());
  entry = result.Rel
"""


```