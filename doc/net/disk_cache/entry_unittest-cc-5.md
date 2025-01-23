Response:
The user wants a summary of the provided C++ code snippet from a Chromium network stack file. They are specifically interested in its functionality, potential relationship with JavaScript, logical reasoning with hypothetical inputs/outputs, common usage errors, and debugging information related to user actions.

The code is a series of C++ unit tests for the `disk_cache::Entry` class, specifically focusing on its behavior within the "SimpleCache" implementation.

Here's a breakdown of how to approach the request:

1. **Identify the core functionality:** The tests primarily examine creating, opening, writing to, reading from, and deleting cache entries in the SimpleCache. They cover various scenarios like sparse files, data corruption, concurrent access, and error handling.

2. **Analyze the JavaScript relationship:**  Disk cache functionality is usually transparent to JavaScript. JavaScript interacts with network resources through APIs like `fetch` or `XMLHttpRequest`, and the browser's network stack (including the disk cache) handles caching automatically. Therefore, the relationship is indirect. JavaScript *might* trigger caching behavior, but doesn't directly interact with the `disk_cache::Entry` class.

3. **Deduce logical reasoning and hypothetical inputs/outputs:** Each test function represents a specific scenario. For instance, `SimpleCachePreserveActiveEntries` tests that deleting a "doomed" entry doesn't affect an active entry with the same key. The input is creating two entries with the same key, dooming one, and then deleting it. The expected output is that the second entry remains accessible.

4. **Identify potential user/programming errors:** The tests often implicitly highlight potential error scenarios. For example, the tests dealing with data corruption demonstrate what happens if cache files are tampered with. A common programming error would be not properly handling `net::ERR_CACHE_READ_FAILURE` or similar errors returned by cache operations.

5. **Trace user actions leading to the code:**  User actions that result in network requests are the starting point. For example, navigating to a website, downloading a file, or an AJAX request can trigger caching. The debugging path leads from the network request processing down to the disk cache layer.

6. **Synthesize a summary:** Combine the findings from the above steps into a concise summary of the code snippet's functionality.

**Mental Sandbox:**

*   **JavaScript example:**  Consider a user navigating to an image-heavy website. The browser's JavaScript might trigger multiple image requests. These requests go through the network stack, and the `disk_cache::Entry` code would be involved in storing or retrieving the image data from the cache.
*   **Input/Output example (SimpleCacheBasicSparseIO):** Input: Create a sparse entry, write data at an offset, read data from the same offset. Output: The read data should match the written data.
*   **User Error example:** A programmer might assume a cached resource is always available and doesn't handle the case where the cache entry is corrupted or has been evicted, leading to unexpected failures.
*   **Debugging path:** A developer might be investigating why a specific resource isn't being cached. They would start by examining the network requests in the browser's developer tools and then potentially dive into the Chromium source code, potentially ending up in files like `entry_unittest.cc` to understand how the cache is supposed to behave.
这个C++ 源代码文件 `entry_unittest.cc` 是 Chromium 网络栈中 `net/disk_cache` 目录下的一个单元测试文件。它的主要功能是**测试 `disk_cache::Entry` 类的各种操作和行为**。`disk_cache::Entry` 类代表了磁盘缓存中的一个条目（entry），用于存储网络资源的数据。

以下是该代码片段中涵盖的一些具体功能：

*   **基本条目操作:**
    *   **创建条目 (`CreateEntry`)**: 测试创建新的缓存条目。
    *   **打开条目 (`OpenEntry`)**: 测试打开已存在的缓存条目。
    *   **关闭条目 (`Close`)**: 测试关闭缓存条目。
    *   **删除所有条目 (`DoomAllEntries`)**: 测试删除所有缓存条目。
    *   **删除条目 (`Doom`)**: 测试删除特定的缓存条目。
*   **数据读写:**
    *   **写入数据 (`WriteData`)**: 测试向缓存条目的不同数据流（header, body, side data）写入数据。包括乐观写入和非乐观写入的场景。
    *   **读取数据 (`ReadData`)**: 测试从缓存条目的不同数据流读取数据。
*   **Sparse 文件支持:**
    *   **基本 Sparse IO (`BasicSparseIO`)**: 测试对 sparse 文件的基本读写操作。
    *   **大型 Sparse IO (`HugeSparseIO`)**: 测试对大型 sparse 文件的读写操作。
    *   **获取可用范围 (`GetAvailableRangeTest`)**: 测试获取 sparse 文件中已写入数据的范围。
    *   **更新 Sparse 条目 (`UpdateSparseEntry`)**: 测试更新 sparse 文件中的数据。
    *   **删除 Sparse 条目 (`DoomSparseEntry`)**: 测试删除 sparse 类型的缓存条目。
    *   **部分 Sparse 条目 (`PartialSparseEntry`)**: 测试部分写入 sparse 数据的情况。
    *   **截断大型 Sparse 文件 (`TruncateLargeSparseFile`)**: 测试截断大型 sparse 文件。
*   **错误处理和完整性检查:**
    *   **校验 EOF 标志 (`SimpleCacheNoBodyEOF`, `SimpleCacheNoSideDataEOF`)**: 测试当缓存文件缺少 EOF 标志时的行为。
    *   **缺少 Key SHA256 (`SimpleCacheReadWithoutKeySHA256`, `SimpleCacheDoubleOpenWithoutKeySHA256`)**: 测试当缓存条目缺少 Key SHA256 时的读取和打开行为。
    *   **Key SHA256 损坏 (`SimpleCacheReadCorruptKeySHA256`)**: 测试当缓存条目的 Key SHA256 损坏时的行为。
    *   **长度信息损坏 (`SimpleCacheReadCorruptLength`)**: 测试当缓存条目的长度信息损坏时的行为。
    *   **Sparse 文件错误处理 (`SimpleCacheSparseErrorHandling`)**: 测试当 sparse 文件发生损坏时的行为，包括错误返回和文件删除。
*   **并发和状态管理:**
    *   **保留活动条目 (`SimpleCachePreserveActiveEntries`)**: 测试在删除已标记为 doom 的条目时，是否会影响到相同 key 的活动条目。
    *   **创建冲突 (`SimpleCacheCreateCollision`)**: 测试当两个 key 发生哈希冲突时的创建行为。
    *   **后端销毁后的使用 (`SimpleUseAfterBackendDestruction`, `MemoryOnlyUseAfterBackendDestruction`, `SimpleCloseSparseAfterBackendDestruction`, `MemoryOnlyCloseSparseAfterBackendDestruction`)**: 测试在缓存后端销毁后，对缓存条目的操作是否安全。
    *   **关闭后复活 (`SimpleCacheCloseResurrection`)**: 测试在写入操作还在 pending 的情况下关闭条目，然后尝试打开相同 key 的条目是否会发生问题。
*   **元数据持久化:**
    *   **Last Used Time 的持久化 (`LastUsedTimePersists`, `SimpleLastUsedTimePersists`, `MemoryOnlyLastUsedTimePersists`)**: 测试条目的最后使用时间是否能够正确持久化和恢复。
*   **特殊写入场景:**
    *   **向后截断 (`TruncateBackwards`, `SimpleTruncateBackwards`, `MemoryOnlyTruncateBackwards`)**: 测试向后截断缓存文件的行为。
    *   **零字节写入 (`ZeroWriteBackwards`, `SimpleZeroWriteBackwards`, `MemoryOnlyZeroWriteBackwards`)**: 测试向后进行零字节写入的行为。
*   **Sparse 文件 Offset 处理:**
    *   **64 位 Offset (`SparseOffset64Bit`, `SimpleSparseOffset64Bit`, `MemoryOnlySparseOffset64Bit`)**: 测试 sparse 文件操作是否能正确处理 64 位的 offset。
*   **与其他组件的交互:**
    *   **从 rmdir 恢复 (`SimpleCacheCreateRecoverFromRmdir`)**: 测试当缓存目录被删除后，创建缓存条目是否能够恢复。
    *   **Stream 2 的延迟创建失败 (`SimpleCacheLazyStream2CreateFailure`)**: 测试 stream 2 文件延迟创建失败的情况。
    *   **校验和计算问题 (`SimpleCacheChecksumpScrewUp`)**: 测试在校验和计算过程中可能出现的错误。
*   **预取功能 (`DiskCacheSimplePrefetchTest`)**: 虽然不在提供的代码片段中，但上下文暗示了可能存在针对 SimpleCache 预取功能的测试。

**与 Javascript 的关系：**

该文件中的代码是 C++ 代码，直接与 Javascript 没有交互。然而，磁盘缓存是浏览器网络栈的重要组成部分，它会影响到 Javascript 发起的网络请求的行为。

**举例说明：**

1. **缓存 HTTP 响应:** 当 Javascript 使用 `fetch` API 或 `XMLHttpRequest` 发起一个网络请求时，浏览器会检查该资源的缓存。如果缓存中存在有效的条目，并且满足缓存策略，浏览器可以直接从缓存中读取数据，而无需再次向服务器请求。`disk_cache::Entry` 类的实例就代表了这些被缓存的资源。
2. **Service Worker 缓存:** Service Workers 可以使用 Cache Storage API 来管理缓存。虽然 Cache Storage API 的底层实现可能与 `disk_cache` 有所不同，但其概念是类似的，都涉及到缓存条目的创建、读取和写入。

**逻辑推理和假设输入/输出：**

以 `TEST_F(DiskCacheEntryTest, SimpleCachePreserveActiveEntries)` 为例：

*   **假设输入:**
    1. 创建一个 key 为 "this is a key" 的缓存条目 `entry1`。
    2. 将 `entry1` 标记为 doomed。
    3. 创建另一个 key 相同的缓存条目 `entry2`。
    4. 关闭并重新打开 `entry2`。
    5. 关闭 `entry1`。
    6. 尝试打开另一个 key 相同的缓存条目 `entry3`。
    7. 对 `entry2` 和 `entry3` 执行 `Doom()` 操作。
*   **预期输出:** 在整个过程中，`entry2` 应该始终保持可用状态，即使 `entry1` 被 doomed 和关闭。最后对 `entry2` 和 `entry3` 的 `Doom()` 操作不应该导致程序崩溃，因为它们代表了不同的缓存条目。

**用户或编程常见的使用错误：**

*   **假设缓存总是存在:** 程序员可能会假设通过 URL 获取的资源总是会被缓存，并且下次请求时会立即返回缓存内容。但缓存可能会因为空间限制、过期策略或其他原因被删除。因此，在网络请求失败时，需要考虑缓存不存在的情况。
*   **不处理缓存错误:**  在 C++ 代码中操作缓存时，可能会遇到各种错误，例如 `net::ERR_CACHE_READ_FAILURE` 或 `net::ERR_CACHE_WRITE_FAILURE`。开发者如果没有正确处理这些错误，可能会导致程序行为异常。
*   **错误地假设缓存一致性:**  在多进程或多线程环境下，可能会出现多个组件同时访问缓存的情况。如果没有适当的同步机制，可能会导致缓存数据不一致。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器中输入 URL 或点击链接:** 这会触发一个网络请求。
2. **浏览器网络栈处理请求:** 网络栈会检查该资源是否可以从缓存中获取。
3. **缓存查找:** 如果需要查找缓存，`disk_cache` 组件会被调用。
4. **打开或创建缓存条目:** 如果找到了匹配的缓存条目，会调用 `OpenEntry`；如果没有找到，可能会调用 `CreateEntry` 来创建一个新的条目。
5. **读取或写入数据:** 如果是从缓存读取数据，会调用 `ReadData`；如果是下载新的资源并缓存，会调用 `WriteData`。
6. **关闭缓存条目:** 完成操作后，会调用 `Close` 关闭缓存条目。
7. **出现问题（例如缓存读取失败）：** 如果在上述步骤中出现问题，开发者可能会查看相关的日志或使用调试器。`entry_unittest.cc` 中的测试用例可以帮助开发者理解在特定情况下缓存组件的行为，从而定位问题。例如，如果用户报告某个缓存的图片无法加载，开发者可能会查看缓存读取相关的代码和测试用例，例如测试 EOF 标志或校验和的测试。

**总结该代码片段的功能：**

这个代码片段是 `net/disk_cache/entry_unittest.cc` 文件的一部分，主要功能是**全面地测试 `disk_cache::Entry` 类的各种功能和边缘情况，特别是针对 SimpleCache 这种缓存实现**。它涵盖了条目的创建、打开、读写、删除，以及对 sparse 文件、错误处理、并发、元数据持久化等方面的测试。这些测试用例旨在确保缓存组件的稳定性和可靠性，防止各种潜在的 bug 和错误。

### 提示词
```
这是目录为net/disk_cache/entry_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
llEntries(), IsOk());
    disk_cache::Entry* entry = nullptr;

    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    EXPECT_NE(null, entry);
    entry->Close();
    entry = nullptr;

    ASSERT_THAT(DoomAllEntries(), IsOk());
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    EXPECT_NE(null, entry);

    int offset = 0;
    int buf_len = kSize;
    // This write should not be optimistic (since create is).
    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer1.get(), buf_len, false));

    offset = kSize;
    // This write should be optimistic.
    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer2.get(), buf_len, false));
    entry->Close();

    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    EXPECT_NE(null, entry);

    entry->Close();
    entry = nullptr;
  }
}

// Tests for a regression in crbug.com/317138 , in which deleting an already
// doomed entry was removing the active entry from the index.
TEST_F(DiskCacheEntryTest, SimpleCachePreserveActiveEntries) {
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* null = nullptr;

  const char key[] = "this is a key";

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());
  ScopedEntryPtr entry1_closer(entry1);
  EXPECT_NE(null, entry1);
  entry1->Doom();

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_NE(null, entry2);
  entry2_closer.reset();

  // Closing then reopening entry2 insures that entry2 is serialized, and so
  // it can be opened from files without error.
  entry2 = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry2), IsOk());
  EXPECT_NE(null, entry2);
  entry2_closer.reset(entry2);

  scoped_refptr<disk_cache::SimpleEntryImpl>
      entry1_refptr = static_cast<disk_cache::SimpleEntryImpl*>(entry1);

  // If crbug.com/317138 has regressed, this will remove |entry2| from
  // the backend's |active_entries_| while |entry2| is still alive and its
  // files are still on disk.
  entry1_closer.reset();
  entry1 = nullptr;

  // Close does not have a callback. However, we need to be sure the close is
  // finished before we continue the test. We can take advantage of how the ref
  // counting of a SimpleEntryImpl works to fake out a callback: When the
  // last Close() call is made to an entry, an IO operation is sent to the
  // synchronous entry to close the platform files. This IO operation holds a
  // ref pointer to the entry, which expires when the operation is done. So,
  // we take a refpointer, and watch the SimpleEntry object until it has only
  // one ref; this indicates the IO operation is complete.
  while (!entry1_refptr->HasOneRef()) {
    base::PlatformThread::YieldCurrentThread();
    base::RunLoop().RunUntilIdle();
  }
  entry1_refptr = nullptr;

  // In the bug case, this new entry ends up being a duplicate object pointing
  // at the same underlying files.
  disk_cache::Entry* entry3 = nullptr;
  EXPECT_THAT(OpenEntry(key, &entry3), IsOk());
  ScopedEntryPtr entry3_closer(entry3);
  EXPECT_NE(null, entry3);

  // The test passes if these two dooms do not crash.
  entry2->Doom();
  entry3->Doom();
}

TEST_F(DiskCacheEntryTest, SimpleCacheBasicSparseIO) {
  SetSimpleCacheMode();
  InitCache();
  BasicSparseIO();
}

TEST_F(DiskCacheEntryTest, SimpleCacheHugeSparseIO) {
  SetSimpleCacheMode();
  InitCache();
  HugeSparseIO();
}

TEST_F(DiskCacheEntryTest, SimpleCacheGetAvailableRange) {
  SetSimpleCacheMode();
  InitCache();
  GetAvailableRangeTest();
}

TEST_F(DiskCacheEntryTest, SimpleCacheUpdateSparseEntry) {
  SetSimpleCacheMode();
  InitCache();
  UpdateSparseEntry();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomSparseEntry) {
  SetSimpleCacheMode();
  InitCache();
  DoomSparseEntry();
}

TEST_F(DiskCacheEntryTest, SimpleCachePartialSparseEntry) {
  SetSimpleCacheMode();
  InitCache();
  PartialSparseEntry();
}

TEST_F(DiskCacheEntryTest, SimpleCacheTruncateLargeSparseFile) {
  const int kSize = 1024;

  SetSimpleCacheMode();
  // An entry is allowed sparse data 1/10 the size of the cache, so this size
  // allows for one |kSize|-sized range plus overhead, but not two ranges.
  SetMaxSize(kSize * 15);
  InitCache();

  const char key[] = "key";
  disk_cache::Entry* null = nullptr;
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_NE(null, entry);

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);
  net::TestCompletionCallback callback;
  int ret;

  // Verify initial conditions.
  ret = entry->ReadSparseData(0, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(0, callback.GetResult(ret));

  ret = entry->ReadSparseData(kSize, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(0, callback.GetResult(ret));

  // Write a range and make sure it reads back.
  ret = entry->WriteSparseData(0, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(kSize, callback.GetResult(ret));

  ret = entry->ReadSparseData(0, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(kSize, callback.GetResult(ret));

  // Write another range and make sure it reads back.
  ret = entry->WriteSparseData(kSize, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(kSize, callback.GetResult(ret));

  ret = entry->ReadSparseData(kSize, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(kSize, callback.GetResult(ret));

  // Make sure the first range was removed when the second was written.
  ret = entry->ReadSparseData(0, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(0, callback.GetResult(ret));

  // Close and reopen the entry and make sure the first entry is still absent
  // and the second entry is still present.
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  ret = entry->ReadSparseData(0, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(0, callback.GetResult(ret));

  ret = entry->ReadSparseData(kSize, buffer.get(), kSize, callback.callback());
  EXPECT_EQ(kSize, callback.GetResult(ret));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheNoBodyEOF) {
  SetSimpleCacheMode();
  InitCache();

  const std::string key("the first key");
  const int kSize = 1024;
  CreateEntryWithHeaderBodyAndSideData(key, kSize);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  entry->Close();

  TruncateFileFromEnd(0 /*header and body file index*/, key, kSize,
                      static_cast<int>(sizeof(disk_cache::SimpleFileEOF)));
  EXPECT_THAT(OpenEntry(key, &entry), IsError(net::ERR_FAILED));
}

TEST_F(DiskCacheEntryTest, SimpleCacheNoSideDataEOF) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  const int kSize = 1024;
  CreateEntryWithHeaderBodyAndSideData(key, kSize);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  entry->Close();

  TruncateFileFromEnd(1 /*side data file_index*/, key, kSize,
                      static_cast<int>(sizeof(disk_cache::SimpleFileEOF)));
  EXPECT_THAT(OpenEntry(key, &entry), IsOk());
  // The corrupted stream should have been deleted.
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));
  // _0 should still exist.
  base::FilePath path_0 = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));
  EXPECT_TRUE(base::PathExists(path_0));

  auto check_stream_data = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, check_stream_data.get(), kSize));
  EXPECT_EQ(kSize, ReadData(entry, 1, 0, check_stream_data.get(), kSize));
  EXPECT_EQ(0, entry->GetDataSize(2));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheReadWithoutKeySHA256) {
  // This test runs as APP_CACHE to make operations more synchronous.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry;
  std::string key("a key");
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const std::string stream_0_data = "data for stream zero";
  auto stream_0_iobuffer =
      base::MakeRefCounted<net::StringIOBuffer>(stream_0_data);
  EXPECT_EQ(static_cast<int>(stream_0_data.size()),
            WriteData(entry, 0, 0, stream_0_iobuffer.get(),
                      stream_0_data.size(), false));
  const std::string stream_1_data = "FOR STREAM ONE, QUITE DIFFERENT THINGS";
  auto stream_1_iobuffer =
      base::MakeRefCounted<net::StringIOBuffer>(stream_1_data);
  EXPECT_EQ(static_cast<int>(stream_1_data.size()),
            WriteData(entry, 1, 0, stream_1_iobuffer.get(),
                      stream_1_data.size(), false));
  entry->Close();

  base::RunLoop().RunUntilIdle();
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(
      disk_cache::simple_util::RemoveKeySHA256FromEntry(key, cache_path_));
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ScopedEntryPtr entry_closer(entry);

  EXPECT_EQ(static_cast<int>(stream_0_data.size()), entry->GetDataSize(0));
  auto check_stream_0_data =
      base::MakeRefCounted<net::IOBufferWithSize>(stream_0_data.size());
  EXPECT_EQ(
      static_cast<int>(stream_0_data.size()),
      ReadData(entry, 0, 0, check_stream_0_data.get(), stream_0_data.size()));
  EXPECT_EQ(0, stream_0_data.compare(0, std::string::npos,
                                     check_stream_0_data->data(),
                                     stream_0_data.size()));

  EXPECT_EQ(static_cast<int>(stream_1_data.size()), entry->GetDataSize(1));
  auto check_stream_1_data =
      base::MakeRefCounted<net::IOBufferWithSize>(stream_1_data.size());
  EXPECT_EQ(
      static_cast<int>(stream_1_data.size()),
      ReadData(entry, 1, 0, check_stream_1_data.get(), stream_1_data.size()));
  EXPECT_EQ(0, stream_1_data.compare(0, std::string::npos,
                                     check_stream_1_data->data(),
                                     stream_1_data.size()));
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoubleOpenWithoutKeySHA256) {
  // This test runs as APP_CACHE to make operations more synchronous.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry;
  std::string key("a key");
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Close();

  base::RunLoop().RunUntilIdle();
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(
      disk_cache::simple_util::RemoveKeySHA256FromEntry(key, cache_path_));
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  entry->Close();

  base::RunLoop().RunUntilIdle();
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheReadCorruptKeySHA256) {
  // This test runs as APP_CACHE to make operations more synchronous.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry;
  std::string key("a key");
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Close();

  base::RunLoop().RunUntilIdle();
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(
      disk_cache::simple_util::CorruptKeySHA256FromEntry(key, cache_path_));
  EXPECT_NE(net::OK, OpenEntry(key, &entry));
}

TEST_F(DiskCacheEntryTest, SimpleCacheReadCorruptLength) {
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry;
  std::string key("a key");
  ASSERT_EQ(net::OK, CreateEntry(key, &entry));
  entry->Close();

  base::RunLoop().RunUntilIdle();
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(
      disk_cache::simple_util::CorruptStream0LengthFromEntry(key, cache_path_));
  EXPECT_NE(net::OK, OpenEntry(key, &entry));
}

TEST_F(DiskCacheEntryTest, SimpleCacheCreateRecoverFromRmdir) {
  // This test runs as APP_CACHE to make operations more synchronous.
  // (in particular we want to see if create succeeded or not, so we don't
  //  want an optimistic one).
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();

  // Pretend someone deleted the cache dir. This shouldn't be too scary in
  // the test since cache_path_ is set as:
  //   CHECK(temp_dir_.CreateUniqueTempDir());
  //   cache_path_ = temp_dir_.GetPath().AppendASCII("cache");
  disk_cache::DeleteCache(cache_path_,
                          true /* delete the dir, what we really want*/);

  disk_cache::Entry* entry;
  std::string key("a key");
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheSparseErrorHandling) {
  // If there is corruption in sparse file, we should delete all the files
  // before returning the failure. Further additional sparse operations in
  // failure state should fail gracefully.
  SetSimpleCacheMode();
  InitCache();

  std::string key("a key");

  disk_cache::SimpleFileTracker::EntryFileKey num_key(
      disk_cache::simple_util::GetEntryHashKey(key));
  base::FilePath path_0 = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromEntryFileKeyAndFileIndex(num_key,
                                                                       0));
  base::FilePath path_s = cache_path_.AppendASCII(
      disk_cache::simple_util::GetSparseFilenameFromEntryFileKey(num_key));

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  EXPECT_EQ(kSize, WriteSparseData(entry, 0, buffer.get(), kSize));
  entry->Close();

  disk_cache::FlushCacheThreadForTesting();
  EXPECT_TRUE(base::PathExists(path_0));
  EXPECT_TRUE(base::PathExists(path_s));

  // Now corrupt the _s file in a way that makes it look OK on open, but not on
  // read.
  base::File file_s(path_s, base::File::FLAG_OPEN | base::File::FLAG_READ |
                                base::File::FLAG_WRITE);
  ASSERT_TRUE(file_s.IsValid());
  file_s.SetLength(sizeof(disk_cache::SimpleFileHeader) +
                   sizeof(disk_cache::SimpleFileSparseRangeHeader) +
                   key.size());
  file_s.Close();

  // Re-open, it should still be fine.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  // Read should fail though.
  EXPECT_EQ(net::ERR_CACHE_READ_FAILURE,
            ReadSparseData(entry, 0, buffer.get(), kSize));

  // At the point read returns to us, the files should already been gone.
  EXPECT_FALSE(base::PathExists(path_0));
  EXPECT_FALSE(base::PathExists(path_s));

  // Re-trying should still fail. Not DCHECK-fail.
  EXPECT_EQ(net::ERR_FAILED, ReadSparseData(entry, 0, buffer.get(), kSize));

  // Similarly for other ops.
  EXPECT_EQ(net::ERR_FAILED, WriteSparseData(entry, 0, buffer.get(), kSize));
  net::TestCompletionCallback cb;

  TestRangeResultCompletionCallback range_cb;
  RangeResult result = range_cb.GetResult(
      entry->GetAvailableRange(0, 1024, range_cb.callback()));
  EXPECT_EQ(net::ERR_FAILED, result.net_error);

  entry->Close();
  disk_cache::FlushCacheThreadForTesting();

  // Closing shouldn't resurrect files, either.
  EXPECT_FALSE(base::PathExists(path_0));
  EXPECT_FALSE(base::PathExists(path_s));
}

TEST_F(DiskCacheEntryTest, SimpleCacheCreateCollision) {
  // These two keys collide; this test is that we properly handled creation
  // of both.
  const char kCollKey1[] =
      "\xfb\x4e\x9c\x1d\x66\x71\xf7\x54\xa3\x11\xa0\x7e\x16\xa5\x68\xf6";
  const char kCollKey2[] =
      "\xbc\x60\x64\x92\xbc\xa0\x5c\x15\x17\x93\x29\x2d\xe4\x21\xbd\x03";

  const int kSize = 256;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto read_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  CacheTestFillBuffer(buffer2->data(), kSize, false);

  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* entry1;
  ASSERT_THAT(CreateEntry(kCollKey1, &entry1), IsOk());

  disk_cache::Entry* entry2;
  ASSERT_THAT(CreateEntry(kCollKey2, &entry2), IsOk());

  // Make sure that entry was actually created and we didn't just succeed
  // optimistically. (Oddly I can't seem to hit the sequence of events required
  // for the bug that used to be here if I just set this to APP_CACHE).
  EXPECT_EQ(kSize, WriteData(entry2, 0, 0, buffer2.get(), kSize, false));

  // entry1 is still usable, though, and distinct (we just won't be able to
  // re-open it).
  EXPECT_EQ(kSize, WriteData(entry1, 0, 0, buffer1.get(), kSize, false));
  EXPECT_EQ(kSize, ReadData(entry1, 0, 0, read_buffer.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer1->data(), read_buffer->data(), kSize));

  EXPECT_EQ(kSize, ReadData(entry2, 0, 0, read_buffer.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer2->data(), read_buffer->data(), kSize));

  entry1->Close();
  entry2->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheConvertToSparseStream2LeftOver) {
  // Testcase for what happens when we have a sparse stream and a left over
  // empty stream 2 file.
  const int kSize = 10;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry;
  std::string key("a key");
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  // Create an empty stream 2. To do that, we first make a non-empty one, then
  // truncate it (since otherwise the write would just get ignored).
  EXPECT_EQ(kSize, WriteData(entry, /* stream = */ 2, /* offset = */ 0,
                             buffer.get(), kSize, false));
  EXPECT_EQ(0, WriteData(entry, /* stream = */ 2, /* offset = */ 0,
                         buffer.get(), 0, true));

  EXPECT_EQ(kSize, WriteSparseData(entry, 5, buffer.get(), kSize));
  entry->Close();

  // Reopen, and try to get the sparse data back.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  EXPECT_EQ(kSize, ReadSparseData(entry, 5, buffer2.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer2->data(), kSize));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheLazyStream2CreateFailure) {
  // Testcase for what happens when lazy-creation of stream 2 fails.
  const int kSize = 10;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  // Synchronous ops, for ease of disk state;
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();

  const char kKey[] = "a key";
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());

  // Create _1 file for stream 2; this should inject a failure when the cache
  // tries to create it itself.
  base::FilePath entry_file1_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(kKey, 1));
  base::File entry_file1(entry_file1_path,
                         base::File::FLAG_WRITE | base::File::FLAG_CREATE);
  ASSERT_TRUE(entry_file1.IsValid());
  entry_file1.Close();

  EXPECT_EQ(net::ERR_CACHE_WRITE_FAILURE,
            WriteData(entry, /* index = */ 2, /* offset = */ 0, buffer.get(),
                      kSize, /* truncate = */ false));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheChecksumpScrewUp) {
  // Test for a bug that occurred during development of  movement of CRC
  // computation off I/O thread.
  const int kSize = 10;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  const int kDoubleSize = kSize * 2;
  auto big_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kDoubleSize);
  CacheTestFillBuffer(big_buffer->data(), kDoubleSize, false);

  SetSimpleCacheMode();
  InitCache();

  const char kKey[] = "a key";
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());

  // Write out big_buffer for the double range. Checksum will be set to this.
  ASSERT_EQ(kDoubleSize,
            WriteData(entry, 1, 0, big_buffer.get(), kDoubleSize, false));

  // Reset remembered position to 0 by writing at an earlier non-zero offset.
  ASSERT_EQ(1, WriteData(entry, /* stream = */ 1, /* offset = */ 1,
                         big_buffer.get(), /* len = */ 1, false));

  // Now write out the half-range twice. An intermediate revision would
  // incorrectly compute checksum as if payload was buffer followed by buffer
  // rather than buffer followed by end of big_buffer.
  ASSERT_EQ(kSize, WriteData(entry, 1, 0, buffer.get(), kSize, false));
  ASSERT_EQ(kSize, WriteData(entry, 1, 0, buffer.get(), kSize, false));
  entry->Close();

  ASSERT_THAT(OpenEntry(kKey, &entry), IsOk());
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  EXPECT_EQ(kSize, ReadData(entry, 1, 0, buffer2.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer2->data(), kSize));
  EXPECT_EQ(kSize, ReadData(entry, 1, kSize, buffer2.get(), kSize));
  EXPECT_EQ(0, memcmp(big_buffer->data() + kSize, buffer2->data(), kSize));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SimpleUseAfterBackendDestruction) {
  SetSimpleCacheMode();
  InitCache();
  UseAfterBackendDestruction();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyUseAfterBackendDestruction) {
  // https://crbug.com/741620
  SetMemoryOnlyMode();
  InitCache();
  UseAfterBackendDestruction();
}

TEST_F(DiskCacheEntryTest, SimpleCloseSparseAfterBackendDestruction) {
  SetSimpleCacheMode();
  InitCache();
  CloseSparseAfterBackendDestruction();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyCloseSparseAfterBackendDestruction) {
  // https://crbug.com/946434
  SetMemoryOnlyMode();
  InitCache();
  CloseSparseAfterBackendDestruction();
}

void DiskCacheEntryTest::LastUsedTimePersists() {
  // Make sure that SetLastUsedTimeForTest persists. When used with SimpleCache,
  // this also checks that Entry::GetLastUsed is based on information in index,
  // when available, not atime on disk, which can be inaccurate.
  const char kKey[] = "a key";
  InitCache();

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry1), IsOk());
  ASSERT_TRUE(nullptr != entry1);
  base::Time modified_last_used = entry1->GetLastUsed() - base::Minutes(5);
  entry1->SetLastUsedTimeForTest(modified_last_used);
  entry1->Close();

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(OpenEntry(kKey, &entry2), IsOk());
  ASSERT_TRUE(nullptr != entry2);

  base::TimeDelta diff = modified_last_used - entry2->GetLastUsed();
  EXPECT_LT(diff, base::Seconds(2));
  EXPECT_GT(diff, -base::Seconds(2));
  entry2->Close();
}

TEST_F(DiskCacheEntryTest, LastUsedTimePersists) {
  LastUsedTimePersists();
}

TEST_F(DiskCacheEntryTest, SimpleLastUsedTimePersists) {
  SetSimpleCacheMode();
  LastUsedTimePersists();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyLastUsedTimePersists) {
  SetMemoryOnlyMode();
  LastUsedTimePersists();
}

void DiskCacheEntryTest::TruncateBackwards() {
  const char kKey[] = "a key";

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());
  ASSERT_TRUE(entry != nullptr);

  const int kBigSize = 40 * 1024;
  const int kSmallSize = 9727;

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBigSize);
  CacheTestFillBuffer(buffer->data(), kBigSize, false);
  auto read_buf = base::MakeRefCounted<net::IOBufferWithSize>(kBigSize);

  ASSERT_EQ(kSmallSize, WriteData(entry, /* index = */ 0,
                                  /* offset = */ kBigSize, buffer.get(),
                                  /* size = */ kSmallSize,
                                  /* truncate = */ false));
  memset(read_buf->data(), 0, kBigSize);
  ASSERT_EQ(kSmallSize, ReadData(entry, /* index = */ 0,
                                 /* offset = */ kBigSize, read_buf.get(),
                                 /* size = */ kSmallSize));
  EXPECT_EQ(0, memcmp(read_buf->data(), buffer->data(), kSmallSize));

  // A partly overlapping truncate before the previous write.
  ASSERT_EQ(kBigSize,
            WriteData(entry, /* index = */ 0,
                      /* offset = */ 3, buffer.get(), /* size = */ kBigSize,
                      /* truncate = */ true));
  memset(read_buf->data(), 0, kBigSize);
  ASSERT_EQ(kBigSize,
            ReadData(entry, /* index = */ 0,
                     /* offset = */ 3, read_buf.get(), /* size = */ kBigSize));
  EXPECT_EQ(0, memcmp(read_buf->data(), buffer->data(), kBigSize));
  EXPECT_EQ(kBigSize + 3, entry->GetDataSize(0));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, TruncateBackwards) {
  // https://crbug.com/946539/
  InitCache();
  TruncateBackwards();
}

TEST_F(DiskCacheEntryTest, SimpleTruncateBackwards) {
  SetSimpleCacheMode();
  InitCache();
  TruncateBackwards();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyTruncateBackwards) {
  SetMemoryOnlyMode();
  InitCache();
  TruncateBackwards();
}

void DiskCacheEntryTest::ZeroWriteBackwards() {
  const char kKey[] = "a key";

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());
  ASSERT_TRUE(entry != nullptr);

  const int kSize = 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  // Offset here needs to be > blockfile's kMaxBlockSize to hit
  // https://crbug.com/946538, as writes close to beginning are handled
  // specially.
  EXPECT_EQ(0, WriteData(entry, /* index = */ 0,
                         /* offset = */ 17000, buffer.get(),
                         /* size = */ 0, /* truncate = */ true));

  EXPECT_EQ(0, WriteData(entry, /* index = */ 0,
                         /* offset = */ 0, buffer.get(),
                         /* size = */ 0, /* truncate = */ false));

  EXPECT_EQ(kSize, ReadData(entry, /* index = */ 0,
                            /* offset = */ 0, buffer.get(),
                            /* size = */ kSize));
  for (int i = 0; i < kSize; ++i) {
    EXPECT_EQ(0, buffer->data()[i]) << i;
  }
  entry->Close();
}

TEST_F(DiskCacheEntryTest, ZeroWriteBackwards) {
  // https://crbug.com/946538/
  InitCache();
  ZeroWriteBackwards();
}

TEST_F(DiskCacheEntryTest, SimpleZeroWriteBackwards) {
  SetSimpleCacheMode();
  InitCache();
  ZeroWriteBackwards();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyZeroWriteBackwards) {
  SetMemoryOnlyMode();
  InitCache();
  ZeroWriteBackwards();
}

void DiskCacheEntryTest::SparseOffset64Bit() {
  // Offsets to sparse ops are 64-bit, make sure we keep track of all of them.
  // (Or, as at least in case of blockfile, fail things cleanly, as it has a
  //  cap on max offset that's much lower).
  bool blockfile = !memory_only_ && !simple_cache_mode_;
  InitCache();

  const char kKey[] = "a key";

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());
  ASSERT_TRUE(entry != nullptr);

  const int kSize = 1024;
  // One bit set very high, so intermediate truncations to 32-bit would drop it
  // even if they happen after a bunch of shifting right.
  const int64_t kOffset = (1ll << 61);

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  EXPECT_EQ(blockfile ? net::ERR_CACHE_OPERATION_NOT_SUPPORTED : kSize,
            WriteSparseData(entry, kOffset, buffer.get(), kSize));

  int64_t start_out = -1;
  EXPECT_EQ(0, GetAvailableRange(entry, /* offset = */ 0, kSize, &start_out));

  start_out = -1;
  EXPECT_EQ(blockfile ? 0 : kSize,
            GetAvailableRange(entry, kOffset, kSize, &start_out));
  EXPECT_EQ(kOffset, start_out);

  entry->Close();
}

TEST_F(DiskCacheEntryTest, SparseOffset64Bit) {
  InitCache();
  SparseOffset64Bit();
}

TEST_F(DiskCacheEntryTest, SimpleSparseOffset64Bit) {
  SetSimpleCacheMode();
  InitCache();
  SparseOffset64Bit();
}

TEST_F(DiskCacheEntryTest, MemoryOnlySparseOffset64Bit) {
  // https://crbug.com/946436
  SetMemoryOnlyMode();
  InitCache();
  SparseOffset64Bit();
}

TEST_F(DiskCacheEntryTest, SimpleCacheCloseResurrection) {
  const int kSize = 10;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  const char kKey[] = "key";
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry), IsOk());
  ASSERT_TRUE(entry != nullptr);

  // Let optimistic create finish.
  base::RunLoop().RunUntilIdle();
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  int rv = entry->WriteData(1, 0, buffer.get(), kSize,
                            net::CompletionOnceCallback(), false);

  // Write should be optimistic.
  ASSERT_EQ(kSize, rv);

  // Since the write is still pending, the open will get queued...
  TestEntryResultCompletionCallback cb_open;
  EntryResult result2 =
      cache_->OpenEntry(kKey, net::HIGHEST, cb_open.callback());
  EXPECT_EQ(net::ERR_IO_PENDING, result2.net_error());

  // ... as the open is queued, this Close will temporarily reduce the number
  // of external references to 0.  This should not break things.
  entry->Close();

  // Wait till open finishes.
  result2 = cb_open.GetResult(std::move(result2));
  ASSERT_EQ(net::OK, result2.net_error());
  disk_cache::Entry* entry2 = result2.ReleaseEntry();
  ASSERT_TRUE(entry2 != nullptr);

  // Get first close a chance to finish.
  base::RunLoop().RunUntilIdle();
  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  // Make sure |entry2| is still usable.
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buffer2->data(), 0, kSize);
  EXPECT_EQ(kSize, ReadData(entry2, 1, 0, buffer2.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer2->data(), kSize));
  entry2->Close();
}

TEST_F(DiskCacheEntryTest, BlockFileSparsePendingAfterDtor) {
  // Test of behavior of ~EntryImpl for sparse entry that runs after backend
  // destruction.
  //
  // Hand-creating the backend for realistic shutdown behavior.
  CleanupCacheDir();
  CreateBackend(disk_cache::kNone);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("key", &entry), IsOk());
  ASSERT_TRUE(entry != nullptr);

  const int kSize = 61184;

  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  // The write pattern here avoids the second write being handled by the
  // buffering layer, making SparseControl have to deal with its asynchrony.
  EXPECT_EQ(1, WriteSparseData(entry, 65535, buf.get(), 1));
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->WriteSparseData(2560, buf.get(), kSize, base::DoNothing()));
  entry->Close();
  ResetCaches();

  // Create a new instance as a way of flushing the thread.
  InitCache();
  FlushQueueForTest();
}

class DiskCacheSimplePrefetchTest : public DiskCacheEntryTest {
 public:
  DiskCacheSimplePrefetchTest() = default;

  enum { kEntrySize = 1024 };

  void SetUp() override {
    payload_ = base::MakeRefCounted<net::IOBufferWithSize>(kEntrySize);
    CacheTestFillBuffer(payload_->data(), kEntrySize, false);
    DiskCacheEntryTest::SetUp();
  }

  void SetupFullAndTrailerPrefetch(int full_size,
                                   int trailer_speculative_size) {
    std::map<std::string, std::string> params;
    params[disk_cache::kSimpleCacheFullPrefetchBytesParam] =
        base::NumberToString(full_size);
    params[disk_cache::kSimpleCacheTrailerPrefetchSpeculativeBytesParam] =
        base::NumberToString(trailer_speculative_size);
    scoped_feature_list_.InitAndEnableFeatureWithParameters(
        disk_cache::kSimpleCachePrefetchExperiment, params);
  }

  void SetupFullPrefetch(int size) { SetupFullAndTrailerPrefetch(size, 0); }

  void InitCacheAndCreateEntry(const std::string& key) {
    SetSimpleCacheMode();
    SetCacheType(SimpleCacheType());
    InitCache();

    disk_cache::Entry* entry;
    ASSERT_EQ(net::OK, CreateEntry(key, &entry));
    // Use stream 1 since that's what new prefetch stuff is about.
    ASSERT_EQ(kEntrySize,
              WriteData(entry, 1, 0, payload_.get(), kEntrySize, false));
    entry->Close();
  }

  virtual net::CacheType SimpleCacheType() const { return net::DISK_CACHE; }

  void InitCacheAndCreateEntryWithNoCrc(const std::string& key) {
    const int kHalfSize = kEntrySize / 2;
    const int kRemSize = kEntrySize - kHalfSize;

    SetSimpleCacheMode();
    InitCache();

    disk_cache::Entry* entry;
    ASSERT_EQ(net::OK, CreateEntry(key, &entry));
    // Use stream 1 since that's what new prefetch stuff is about.
    ASSERT_EQ(kEntr
```