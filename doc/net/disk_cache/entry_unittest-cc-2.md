Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `net/disk_cache/entry_unittest.cc`. This snippet contains a series of unit tests for the disk cache entry functionality in Chromium's network stack.

Here's a breakdown of how to approach this:

1. **Identify the Class Under Test:** The tests are within a class named `DiskCacheEntryTest`, which strongly suggests the tests are focused on the `disk_cache::Entry` class (or its implementations).

2. **Analyze Individual Test Cases:**  Go through each `TEST_F` function and understand its purpose. Keywords in the test names are helpful. For example:
    * `SparseWriteBasic`: Deals with basic sparse write operations.
    * `SparseWriteTracking`: Focuses on how the cache tracks sparse writes.
    * `SparseWriteDropped`: Tests scenarios where sparse write data is dropped due to alignment.
    * `SparseSquentialWriteNotDropped`: Verifies that sequential small writes are not dropped.
    * `CouldBeSparse`: Checks the `CouldBeSparse()` method, likely related to determining if an entry utilizes sparse storage.
    * `MemoryOnlyMisalignedSparseIO`: Tests sparse I/O in memory-only mode with misaligned offsets.
    * `MemoryOnlyMisalignedGetAvailableRange`: Checks `GetAvailableRange` in memory-only mode with misaligned scenarios.
    * `UpdateSparseEntry`: Verifies updating existing sparse entries.
    * `DoomSparseEntry`: Tests the deletion (dooming) of sparse entries.
    * `DoomSparseEntry2`:  Specifically tests deletion while a sparse entry operation is pending.
    * `PartialSparseEntry`: Deals with writes and reads that might not align with sparse block boundaries.
    * `SparseInvalidArg`: Tests how the entry handles invalid arguments to sparse I/O operations.
    * `SparseClipEnd`: Checks how the entry handles writes and reads near the maximum allowed offset for sparse data.
    * `CleanupSparseEntry`: Verifies the cleanup of corrupted sparse child entries.
    * `CancelSparseIO`: Tests the ability to cancel pending sparse I/O operations.
    * `KeySanityCheck`:  Focuses on the robustness of the entry against corrupted key data.

3. **Identify Core Functionality Being Tested:** Group related tests together to infer the underlying features. The tests repeatedly use methods like `WriteSparseData`, `ReadSparseData`, `GetAvailableRange`, `CreateEntry`, `OpenEntry`, `DoomEntry`, and `Close`. These are key operations for managing cache entries, especially sparse entries.

4. **Consider JavaScript Relevance:** Think about how browser caching relates to JavaScript. JavaScript interacts with the network, and the cache is a fundamental part of how the browser stores and retrieves resources fetched over the network. While this specific code doesn't *directly* involve JavaScript, the caching behavior it tests has a direct impact on web performance and how JavaScript applications load resources.

5. **Logical Inference (Assumptions and Outputs):** For some tests, especially those involving `GetAvailableRange`, it's possible to infer the expected output given certain write operations.

6. **Common Usage Errors:**  Think about how a developer might misuse the cache API, leading to issues the tests are designed to catch (e.g., misaligned writes with sparse data).

7. **User Journey to This Code:**  Consider the steps a user takes in a browser that might trigger the cache operations being tested.

8. **Synthesize a Summary:** Based on the above analysis, create a concise summary of the file's purpose. Highlight the key features being tested and the types of scenarios covered.

**Applying the process to the given snippet:**

* **Focus on Sparse Entries:**  The repeated use of "Sparse" in the test names indicates a major focus on testing sparse cache entries, a mechanism for efficiently storing large files with potentially many gaps.

* **Key Operations:**  The tests exercise the core API for interacting with sparse entries: writing data (`WriteSparseData`), reading data (`ReadSparseData`), and querying available data ranges (`GetAvailableRange`).

* **Error Handling and Edge Cases:**  Several tests focus on error conditions (invalid arguments, cancellation) and edge cases (misaligned writes, maximum offsets, corrupted entries).

* **Memory-Only Mode:**  The "MemoryOnly" tests show that the code also covers scenarios where the cache operates purely in memory.

* **Relationship to JavaScript:** While not directly manipulating JavaScript, the caching mechanisms being tested are crucial for how web resources are loaded and managed, ultimately affecting JavaScript execution and web page performance.

* **Inference Examples:**
    * *Assumption:*  Writing a small amount of data to a sparse entry.
    * *Expected Output of `GetAvailableRange`:*  The test verifies the correct start offset and length of the available data.

* **Common Errors:**  The tests highlight potential issues like writing to non-aligned offsets in sparse mode, which could lead to data loss.

* **User Journey:** A user browsing a website that uses caching will trigger these underlying cache operations. For example, downloading a large image or video might involve sparse storage.

By systematically analyzing the test cases, the overall functionality of the `entry_unittest.cc` file becomes clear.
这是chromium网络栈的源代码文件`net/disk_cache/entry_unittest.cc`的第3部分，主要侧重于**磁盘缓存条目的稀疏（sparse）数据写入、读取和管理**的单元测试。

**功能归纳:**

这部分代码主要测试了`disk_cache::Entry`类中关于稀疏数据操作的相关功能，包括：

1. **基本的稀疏数据写入和读取:**  测试了`WriteSparseData`和`ReadSparseData`方法的基本功能，验证了数据写入和读取的正确性。
2. **稀疏数据追踪:**  测试了缓存如何追踪稀疏写入的数据块，包括使用位图和记录最后写入的子KB数据块。验证了`GetAvailableRange`方法能够正确返回可用的数据范围。
3. **非对齐稀疏写入:**  重点测试了非1024字节对齐的稀疏写入行为，验证了在非对齐写入时，部分数据会被丢弃的机制。
4. **顺序稀疏写入:**  验证了小块的顺序稀疏写入不会导致数据丢失。
5. **`CouldBeSparse()` 方法:** 测试了`CouldBeSparse()`方法，用于判断一个缓存条目是否可能存储稀疏数据。
6. **内存模式下的稀疏数据操作:**  针对内存模式（`SetMemoryOnlyMode()`）下的稀疏数据读写和`GetAvailableRange`方法进行了测试，验证了在内存模式下稀疏数据操作的正确性，包括处理非对齐的I/O。
7. **更新稀疏条目:** 测试了更新已存在的稀疏缓存条目的功能。
8. **删除稀疏条目:** 测试了删除（dooming）稀疏缓存条目的功能，包括在删除过程中backend被删除的情况。
9. **部分稀疏条目:**  测试了处理未完全对齐到稀疏块大小的I/O操作，验证了在写入和读取大范围数据时，不会留下空洞。
10. **稀疏操作的无效参数处理:** 测试了`WriteSparseData`、`ReadSparseData`和`GetAvailableRange`方法在接收到无效参数时的处理行为，例如负的偏移量或大小。
11. **稀疏写入的末尾裁剪:**  测试了当稀疏写入操作超出允许的最大索引时的行为，以及读取操作如何被裁剪到有效范围内。
12. **清理损坏的稀疏子条目:** 测试了当稀疏条目的子条目损坏时，系统能够自动清理这些损坏的条目。
13. **取消稀疏I/O:** 测试了取消正在进行的稀疏I/O操作的功能。
14. **缓存条目Key的健全性检查:** 测试了缓存条目Key的健全性检查机制，防止读取超出分配缓冲区的数据。

**与JavaScript的功能关系：**

虽然这段C++代码本身不直接涉及JavaScript代码，但它测试的磁盘缓存功能是浏览器加载和管理网络资源（包括JavaScript文件）的关键部分。

**举例说明:**

假设一个JavaScript应用程序需要加载一个大型的图片资源。浏览器可能会将这个图片资源存储在磁盘缓存中，并使用稀疏存储来优化存储空间。

* 当JavaScript发起对该图片的请求时，网络栈会检查缓存。
* 如果缓存中存在该图片，但可能只有部分数据被下载或存储，浏览器可能会使用类似`GetAvailableRange`的功能来确定哪些部分的数据是可用的。
* 如果需要下载新的数据块，则会调用类似`WriteSparseData`的功能将数据写入缓存。
* 当JavaScript需要使用该图片时，浏览器会调用类似`ReadSparseData`的功能从缓存中读取数据。

**逻辑推理（假设输入与输出）:**

**示例1：`SparseWriteTracking` 测试**

* **假设输入:**
    * 向缓存条目的偏移量1024写入1024字节数据。
    * 向偏移量3072写入612字节数据。
    * 查询偏移量2048开始的2048字节的可用范围。
* **预期输出:**
    * 第一次写入成功。
    * 第二次写入成功。
    * `GetAvailableRange` 返回 `net::OK`, `available_len = 1636`, `start = 2048` (因为[2048, 3072)和[3072, 3684)的数据都可用)。

**示例2：`SparseWriteDropped` 测试**

* **假设输入:**
    * 连续多次向接近1024字节边界的偏移量写入180字节的数据，例如偏移量为 1024-500, 1024-400, ...
    * 每次写入后查询写入位置附近的可用范围。
* **预期输出:**
    * 在跨越1024字节边界之前，`GetAvailableRange` 返回 `available_len = 0`，表示数据被丢弃。
    * 当写入跨越边界后，`GetAvailableRange` 会返回跨越边界后的那部分数据的长度。

**用户或编程常见的使用错误：**

1. **非对齐的稀疏写入:**  开发者可能错误地认为可以向任意偏移量进行稀疏写入，而没有考虑到非对齐写入会导致数据丢失。例如，尝试向偏移量1025写入小于1024字节的数据，部分数据可能不会被缓存。
2. **假设所有数据立即可用:**  开发者可能在数据完全写入缓存之前就尝试读取稀疏数据，导致读取到空数据或不完整的数据。
3. **错误地计算可用范围:** 开发者可能错误地使用`GetAvailableRange`，例如传入错误的起始偏移量或长度，导致获取到错误的可用数据信息。

**用户操作如何一步步的到达这里（调试线索）：**

1. **用户在浏览器中发起一个网络请求:** 例如访问一个包含大型图片或视频的网页。
2. **网络栈接收到请求:**  浏览器会首先检查本地缓存是否已经存在该资源。
3. **如果缓存未命中或需要更新:**  浏览器会下载资源数据。
4. **磁盘缓存模块被调用:** 当需要将下载的资源数据存储到磁盘时，磁盘缓存模块会被调用。
5. **如果资源较大且适合稀疏存储:** 磁盘缓存可能会选择使用稀疏存储来管理该资源。
6. **`WriteSparseData` 被调用:** 当有新的数据块需要写入缓存时，`WriteSparseData` 方法会被调用。
7. **如果需要读取缓存的数据:**  例如，当用户再次访问相同的网页或JavaScript代码尝试使用缓存的资源时，`ReadSparseData` 方法会被调用。
8. **`GetAvailableRange` 可能被调用:**  在读取数据之前，或者在决定下载哪些数据块时，可能会调用 `GetAvailableRange` 来查询缓存中已有的数据范围。

**总结一下它的功能:**

这部分单元测试代码的核心功能是**全面测试 Chromium 磁盘缓存中稀疏数据条目的读、写、查询和管理功能**。它涵盖了正常情况下的操作，以及各种边界情况和错误情况，确保了稀疏缓存机制的稳定性和可靠性。这对于优化大型网络资源的缓存效率至关重要，并最终影响用户的浏览体验和JavaScript应用程序的性能。

### 提示词
```
这是目录为net/disk_cache/entry_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
nuous small write, this one at [3072, 3684).
  // This means the cache tracks [1024, 3072) via bitmaps and [3072, 3684)
  // as the last write.
  EXPECT_EQ(kSmallSize, WriteSparseData(entry, /* offset = */ 3072,
                                        buf_small.get(), kSmallSize));

  // Query [2048, 4096). Should get [2048, 3684)
  result = cb.GetResult(entry->GetAvailableRange(2048, 2048, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(1636, result.available_len);
  EXPECT_EQ(2048, result.start);

  // Now write at [4096, 4708). Since only one sub-kb thing is tracked, this
  // now tracks  [1024, 3072) via bitmaps and [4096, 4708) as the last write.
  EXPECT_EQ(kSmallSize, WriteSparseData(entry, /* offset = */ 4096,
                                        buf_small.get(), kSmallSize));

  // Query [2048, 4096). Should get [2048, 3072)
  result = cb.GetResult(entry->GetAvailableRange(2048, 2048, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(1024, result.available_len);
  EXPECT_EQ(2048, result.start);

  // Query 2K more after that: [3072, 5120). Should get [4096, 4708)
  result = cb.GetResult(entry->GetAvailableRange(3072, 2048, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(612, result.available_len);
  EXPECT_EQ(4096, result.start);

  // Also double-check that offsets within later children are correctly
  // computed.
  EXPECT_EQ(kSmallSize, WriteSparseData(entry, /* offset = */ 0x200400,
                                        buf_small.get(), kSmallSize));
  result =
      cb.GetResult(entry->GetAvailableRange(0x100000, 0x200000, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(kSmallSize, result.available_len);
  EXPECT_EQ(0x200400, result.start);

  entry->Close();
}

// Tests that non-sequential writes that are not aligned with the minimum sparse
// data granularity (1024 bytes) do in fact result in dropped data.
TEST_F(DiskCacheEntryTest, SparseWriteDropped) {
  InitCache();
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 180;
  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf_2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf_1->data(), kSize, false);

  // Do small writes (180 bytes) that get increasingly close to a 1024-byte
  // boundary. All data should be dropped until a boundary is crossed, at which
  // point the data after the boundary is saved (at least for a while).
  int offset = 1024 - 500;
  int rv = 0;
  net::TestCompletionCallback cb;
  TestRangeResultCompletionCallback range_cb;
  RangeResult result;
  for (int i = 0; i < 5; i++) {
    // Check result of last GetAvailableRange.
    EXPECT_EQ(0, result.available_len);

    rv = entry->WriteSparseData(offset, buf_1.get(), kSize, cb.callback());
    EXPECT_EQ(kSize, cb.GetResult(rv));

    result = range_cb.GetResult(
        entry->GetAvailableRange(offset - 100, kSize, range_cb.callback()));
    EXPECT_EQ(net::OK, result.net_error);
    EXPECT_EQ(0, result.available_len);

    result = range_cb.GetResult(
        entry->GetAvailableRange(offset, kSize, range_cb.callback()));
    if (!result.available_len) {
      rv = entry->ReadSparseData(offset, buf_2.get(), kSize, cb.callback());
      EXPECT_EQ(0, cb.GetResult(rv));
    }
    offset += 1024 * i + 100;
  }

  // The last write started 100 bytes below a bundary, so there should be 80
  // bytes after the boundary.
  EXPECT_EQ(80, result.available_len);
  EXPECT_EQ(1024 * 7, result.start);
  rv = entry->ReadSparseData(result.start, buf_2.get(), kSize, cb.callback());
  EXPECT_EQ(80, cb.GetResult(rv));
  EXPECT_EQ(0, memcmp(buf_1.get()->data() + 100, buf_2.get()->data(), 80));

  // And even that part is dropped when another write changes the offset.
  offset = result.start;
  rv = entry->WriteSparseData(0, buf_1.get(), kSize, cb.callback());
  EXPECT_EQ(kSize, cb.GetResult(rv));

  result = range_cb.GetResult(
      entry->GetAvailableRange(offset, kSize, range_cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);
  entry->Close();
}

// Tests that small sequential writes are not dropped.
TEST_F(DiskCacheEntryTest, SparseSquentialWriteNotDropped) {
  InitCache();
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 180;
  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf_2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf_1->data(), kSize, false);

  // Any starting offset is fine as long as it is 1024-bytes aligned.
  int rv = 0;
  RangeResult result;
  net::TestCompletionCallback cb;
  TestRangeResultCompletionCallback range_cb;
  int64_t offset = 1024 * 11;
  for (; offset < 20000; offset += kSize) {
    rv = entry->WriteSparseData(offset, buf_1.get(), kSize, cb.callback());
    EXPECT_EQ(kSize, cb.GetResult(rv));

    result = range_cb.GetResult(
        entry->GetAvailableRange(offset, kSize, range_cb.callback()));
    EXPECT_EQ(net::OK, result.net_error);
    EXPECT_EQ(kSize, result.available_len);
    EXPECT_EQ(offset, result.start);

    rv = entry->ReadSparseData(offset, buf_2.get(), kSize, cb.callback());
    EXPECT_EQ(kSize, cb.GetResult(rv));
    EXPECT_EQ(0, memcmp(buf_1.get()->data(), buf_2.get()->data(), kSize));
  }

  entry->Close();
  FlushQueueForTest();

  // Verify again the last write made.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  offset -= kSize;
  result = range_cb.GetResult(
      entry->GetAvailableRange(offset, kSize, range_cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(kSize, result.available_len);
  EXPECT_EQ(offset, result.start);

  rv = entry->ReadSparseData(offset, buf_2.get(), kSize, cb.callback());
  EXPECT_EQ(kSize, cb.GetResult(rv));
  EXPECT_EQ(0, memcmp(buf_1.get()->data(), buf_2.get()->data(), kSize));

  entry->Close();
}

void DiskCacheEntryTest::CouldBeSparse() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 16 * 1024;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  // Write at offset 0x20F0000 (33 MB - 64 KB).
  EXPECT_EQ(kSize, WriteSparseData(entry, 0x20F0000, buf.get(), kSize));

  EXPECT_TRUE(entry->CouldBeSparse());
  entry->Close();

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_TRUE(entry->CouldBeSparse());
  entry->Close();

  // Now verify a regular entry.
  key.assign("another key");
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_FALSE(entry->CouldBeSparse());

  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buf.get(), kSize, false));
  EXPECT_EQ(kSize, WriteData(entry, 1, 0, buf.get(), kSize, false));
  EXPECT_EQ(kSize, WriteData(entry, 2, 0, buf.get(), kSize, false));

  EXPECT_FALSE(entry->CouldBeSparse());
  entry->Close();

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_FALSE(entry->CouldBeSparse());
  entry->Close();
}

TEST_F(DiskCacheEntryTest, CouldBeSparse) {
  InitCache();
  CouldBeSparse();
}

TEST_F(DiskCacheEntryTest, MemoryCouldBeSparse) {
  SetMemoryOnlyMode();
  InitCache();
  CouldBeSparse();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyMisalignedSparseIO) {
  SetMemoryOnlyMode();
  InitCache();

  static constexpr size_t kSize = 8192;
  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf_2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf_1->data(), kSize, false);

  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  // This loop writes back to back starting from offset 0 and 9000.
  for (size_t i = 0; i < kSize; i += 1024) {
    auto buf_3 =
        base::MakeRefCounted<net::WrappedIOBuffer>(buf_1->span().subspan(i));
    VerifySparseIO(entry, i, buf_3.get(), 1024, buf_2.get());
    VerifySparseIO(entry, 9000 + i, buf_3.get(), 1024, buf_2.get());
  }

  // Make sure we have data written.
  VerifyContentSparseIO(entry, 0, buf_1->data(), kSize);
  VerifyContentSparseIO(entry, 9000, buf_1->data(), kSize);

  // This tests a large write that spans 3 entries from a misaligned offset.
  VerifySparseIO(entry, 20481, buf_1.get(), 8192, buf_2.get());

  entry->Close();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyMisalignedGetAvailableRange) {
  SetMemoryOnlyMode();
  InitCache();

  const int kSize = 8192;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  disk_cache::Entry* entry;
  std::string key("the first key");
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  // Writes in the middle of an entry.
  EXPECT_EQ(1024, entry->WriteSparseData(0, buf.get(), 1024,
                                         net::CompletionOnceCallback()));
  EXPECT_EQ(1024, entry->WriteSparseData(5120, buf.get(), 1024,
                                         net::CompletionOnceCallback()));
  EXPECT_EQ(1024, entry->WriteSparseData(10000, buf.get(), 1024,
                                         net::CompletionOnceCallback()));

  // Writes in the middle of an entry and spans 2 child entries.
  EXPECT_EQ(8192, entry->WriteSparseData(50000, buf.get(), 8192,
                                         net::CompletionOnceCallback()));

  TestRangeResultCompletionCallback cb;
  // Test that we stop at a discontinuous child at the second block.
  RangeResult result =
      cb.GetResult(entry->GetAvailableRange(0, 10000, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(1024, result.available_len);
  EXPECT_EQ(0, result.start);

  // Test that number of bytes is reported correctly when we start from the
  // middle of a filled region.
  result = cb.GetResult(entry->GetAvailableRange(512, 10000, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(512, result.available_len);
  EXPECT_EQ(512, result.start);

  // Test that we found bytes in the child of next block.
  result = cb.GetResult(entry->GetAvailableRange(1024, 10000, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(1024, result.available_len);
  EXPECT_EQ(5120, result.start);

  // Test that the desired length is respected. It starts within a filled
  // region.
  result = cb.GetResult(entry->GetAvailableRange(5500, 512, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(512, result.available_len);
  EXPECT_EQ(5500, result.start);

  // Test that the desired length is respected. It starts before a filled
  // region.
  result = cb.GetResult(entry->GetAvailableRange(5000, 620, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(500, result.available_len);
  EXPECT_EQ(5120, result.start);

  // Test that multiple blocks are scanned.
  result = cb.GetResult(entry->GetAvailableRange(40000, 20000, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(8192, result.available_len);
  EXPECT_EQ(50000, result.start);

  entry->Close();
}

void DiskCacheEntryTest::UpdateSparseEntry() {
  std::string key("the first key");
  disk_cache::Entry* entry1;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());

  const int kSize = 2048;
  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf_2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf_1->data(), kSize, false);

  // Write at offset 0.
  VerifySparseIO(entry1, 0, buf_1.get(), kSize, buf_2.get());
  entry1->Close();

  // Write at offset 2048.
  ASSERT_THAT(OpenEntry(key, &entry1), IsOk());
  VerifySparseIO(entry1, 2048, buf_1.get(), kSize, buf_2.get());

  disk_cache::Entry* entry2;
  ASSERT_THAT(CreateEntry("the second key", &entry2), IsOk());

  entry1->Close();
  entry2->Close();
  FlushQueueForTest();
  if (memory_only_ || simple_cache_mode_)
    EXPECT_EQ(2, cache_->GetEntryCount());
  else
    EXPECT_EQ(3, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, UpdateSparseEntry) {
  InitCache();
  UpdateSparseEntry();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyUpdateSparseEntry) {
  SetMemoryOnlyMode();
  InitCache();
  UpdateSparseEntry();
}

void DiskCacheEntryTest::DoomSparseEntry() {
  std::string key1("the first key");
  std::string key2("the second key");
  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry(key1, &entry1), IsOk());
  ASSERT_THAT(CreateEntry(key2, &entry2), IsOk());

  const int kSize = 4 * 1024;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  int64_t offset = 1024;
  // Write to a bunch of ranges.
  for (int i = 0; i < 12; i++) {
    EXPECT_EQ(kSize, WriteSparseData(entry1, offset, buf.get(), kSize));
    // Keep the second map under the default size.
    if (i < 9)
      EXPECT_EQ(kSize, WriteSparseData(entry2, offset, buf.get(), kSize));

    offset *= 4;
  }

  if (memory_only_ || simple_cache_mode_)
    EXPECT_EQ(2, cache_->GetEntryCount());
  else
    EXPECT_EQ(15, cache_->GetEntryCount());

  // Doom the first entry while it's still open.
  entry1->Doom();
  entry1->Close();
  entry2->Close();

  // Doom the second entry after it's fully saved.
  EXPECT_THAT(DoomEntry(key2), IsOk());

  // Make sure we do all needed work. This may fail for entry2 if between Close
  // and DoomEntry the system decides to remove all traces of the file from the
  // system cache so we don't see that there is pending IO.
  base::RunLoop().RunUntilIdle();

  if (memory_only_) {
    EXPECT_EQ(0, cache_->GetEntryCount());
  } else {
    if (5 == cache_->GetEntryCount()) {
      // Most likely we are waiting for the result of reading the sparse info
      // (it's always async on Posix so it is easy to miss). Unfortunately we
      // don't have any signal to watch for so we can only wait.
      base::PlatformThread::Sleep(base::Milliseconds(500));
      base::RunLoop().RunUntilIdle();
    }
    EXPECT_EQ(0, cache_->GetEntryCount());
  }
}

TEST_F(DiskCacheEntryTest, DoomSparseEntry) {
  UseCurrentThread();
  InitCache();
  DoomSparseEntry();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyDoomSparseEntry) {
  SetMemoryOnlyMode();
  InitCache();
  DoomSparseEntry();
}

// A TestCompletionCallback wrapper that deletes the cache from within the
// callback.  The way TestCompletionCallback works means that all tasks (even
// new ones) are executed by the message loop before returning to the caller so
// the only way to simulate a race is to execute what we want on the callback.
class SparseTestCompletionCallback: public net::TestCompletionCallback {
 public:
  explicit SparseTestCompletionCallback(
      std::unique_ptr<disk_cache::Backend> cache)
      : cache_(std::move(cache)) {}

  SparseTestCompletionCallback(const SparseTestCompletionCallback&) = delete;
  SparseTestCompletionCallback& operator=(const SparseTestCompletionCallback&) =
      delete;

 private:
  void SetResult(int result) override {
    cache_.reset();
    TestCompletionCallback::SetResult(result);
  }

  std::unique_ptr<disk_cache::Backend> cache_;
};

// Tests that we don't crash when the backend is deleted while we are working
// deleting the sub-entries of a sparse entry.
TEST_F(DiskCacheEntryTest, DoomSparseEntry2) {
  UseCurrentThread();
  InitCache();
  std::string key("the key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 4 * 1024;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  int64_t offset = 1024;
  // Write to a bunch of ranges.
  for (int i = 0; i < 12; i++) {
    EXPECT_EQ(kSize, entry->WriteSparseData(offset, buf.get(), kSize,
                                            net::CompletionOnceCallback()));
    offset *= 4;
  }
  EXPECT_EQ(9, cache_->GetEntryCount());

  entry->Close();
  disk_cache::Backend* cache = cache_.get();
  SparseTestCompletionCallback cb(TakeCache());
  int rv = cache->DoomEntry(key, net::HIGHEST, cb.callback());
  EXPECT_THAT(rv, IsError(net::ERR_IO_PENDING));
  EXPECT_THAT(cb.WaitForResult(), IsOk());
}

void DiskCacheEntryTest::PartialSparseEntry() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  // We should be able to deal with IO that is not aligned to the block size
  // of a sparse entry, at least to write a big range without leaving holes.
  const int kSize = 4 * 1024;
  const int kSmallSize = 128;
  auto buf1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf1->data(), kSize, false);

  // The first write is just to extend the entry. The third write occupies
  // a 1KB block partially, it may not be written internally depending on the
  // implementation.
  EXPECT_EQ(kSize, WriteSparseData(entry, 20000, buf1.get(), kSize));
  EXPECT_EQ(kSize, WriteSparseData(entry, 500, buf1.get(), kSize));
  EXPECT_EQ(kSmallSize,
            WriteSparseData(entry, 1080321, buf1.get(), kSmallSize));
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  auto buf2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buf2->data(), 0, kSize);
  EXPECT_EQ(0, ReadSparseData(entry, 8000, buf2.get(), kSize));

  EXPECT_EQ(500, ReadSparseData(entry, kSize, buf2.get(), kSize));
  EXPECT_EQ(0, memcmp(buf2->data(), buf1->data() + kSize - 500, 500));
  EXPECT_EQ(0, ReadSparseData(entry, 0, buf2.get(), kSize));

  // This read should not change anything.
  if (memory_only_ || simple_cache_mode_)
    EXPECT_EQ(96, ReadSparseData(entry, 24000, buf2.get(), kSize));
  else
    EXPECT_EQ(0, ReadSparseData(entry, 24000, buf2.get(), kSize));

  EXPECT_EQ(500, ReadSparseData(entry, kSize, buf2.get(), kSize));
  EXPECT_EQ(0, ReadSparseData(entry, 99, buf2.get(), kSize));

  TestRangeResultCompletionCallback cb;
  RangeResult result;
  if (memory_only_ || simple_cache_mode_) {
    result = cb.GetResult(entry->GetAvailableRange(0, 600, cb.callback()));
    EXPECT_EQ(net::OK, result.net_error);
    EXPECT_EQ(100, result.available_len);
    EXPECT_EQ(500, result.start);
  } else {
    result = cb.GetResult(entry->GetAvailableRange(0, 2048, cb.callback()));
    EXPECT_EQ(net::OK, result.net_error);
    EXPECT_EQ(1024, result.available_len);
    EXPECT_EQ(1024, result.start);
  }
  result = cb.GetResult(entry->GetAvailableRange(kSize, kSize, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(500, result.available_len);
  EXPECT_EQ(kSize, result.start);
  result =
      cb.GetResult(entry->GetAvailableRange(20 * 1024, 10000, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  if (memory_only_ || simple_cache_mode_)
    EXPECT_EQ(3616, result.available_len);
  else
    EXPECT_EQ(3072, result.available_len);

  EXPECT_EQ(20 * 1024, result.start);

  // 1. Query before a filled 1KB block.
  // 2. Query within a filled 1KB block.
  // 3. Query beyond a filled 1KB block.
  if (memory_only_ || simple_cache_mode_) {
    result =
        cb.GetResult(entry->GetAvailableRange(19400, kSize, cb.callback()));
    EXPECT_EQ(net::OK, result.net_error);
    EXPECT_EQ(3496, result.available_len);
    EXPECT_EQ(20000, result.start);
  } else {
    result =
        cb.GetResult(entry->GetAvailableRange(19400, kSize, cb.callback()));
    EXPECT_EQ(net::OK, result.net_error);
    EXPECT_EQ(3016, result.available_len);
    EXPECT_EQ(20480, result.start);
  }
  result = cb.GetResult(entry->GetAvailableRange(3073, kSize, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(1523, result.available_len);
  EXPECT_EQ(3073, result.start);
  result = cb.GetResult(entry->GetAvailableRange(4600, kSize, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);
  EXPECT_EQ(4600, result.start);

  // Now make another write and verify that there is no hole in between.
  EXPECT_EQ(kSize, WriteSparseData(entry, 500 + kSize, buf1.get(), kSize));
  result = cb.GetResult(entry->GetAvailableRange(1024, 10000, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(7 * 1024 + 500, result.available_len);
  EXPECT_EQ(1024, result.start);
  EXPECT_EQ(kSize, ReadSparseData(entry, kSize, buf2.get(), kSize));
  EXPECT_EQ(0, memcmp(buf2->data(), buf1->data() + kSize - 500, 500));
  EXPECT_EQ(0, memcmp(buf2->data() + 500, buf1->data(), kSize - 500));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, PartialSparseEntry) {
  InitCache();
  PartialSparseEntry();
}

TEST_F(DiskCacheEntryTest, MemoryPartialSparseEntry) {
  SetMemoryOnlyMode();
  InitCache();
  PartialSparseEntry();
}

void DiskCacheEntryTest::SparseInvalidArg() {
  std::string key("key");
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 2048;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  EXPECT_EQ(net::ERR_INVALID_ARGUMENT,
            WriteSparseData(entry, -1, buf.get(), kSize));
  EXPECT_EQ(net::ERR_INVALID_ARGUMENT,
            WriteSparseData(entry, 0, buf.get(), -1));

  EXPECT_EQ(net::ERR_INVALID_ARGUMENT,
            ReadSparseData(entry, -1, buf.get(), kSize));
  EXPECT_EQ(net::ERR_INVALID_ARGUMENT, ReadSparseData(entry, 0, buf.get(), -1));

  int64_t start_out;
  EXPECT_EQ(net::ERR_INVALID_ARGUMENT,
            GetAvailableRange(entry, -1, kSize, &start_out));
  EXPECT_EQ(net::ERR_INVALID_ARGUMENT,
            GetAvailableRange(entry, 0, -1, &start_out));

  int rv = WriteSparseData(
      entry, std::numeric_limits<int64_t>::max() - kSize + 1, buf.get(), kSize);
  // Blockfile rejects anything over 64GiB with
  // net::ERR_CACHE_OPERATION_NOT_SUPPORTED, which is also OK here, as it's not
  // an overflow or something else nonsensical.
  EXPECT_TRUE(rv == net::ERR_INVALID_ARGUMENT ||
              rv == net::ERR_CACHE_OPERATION_NOT_SUPPORTED);

  entry->Close();
}

TEST_F(DiskCacheEntryTest, SparseInvalidArg) {
  InitCache();
  SparseInvalidArg();
}

TEST_F(DiskCacheEntryTest, MemoryOnlySparseInvalidArg) {
  SetMemoryOnlyMode();
  InitCache();
  SparseInvalidArg();
}

TEST_F(DiskCacheEntryTest, SimpleSparseInvalidArg) {
  SetSimpleCacheMode();
  InitCache();
  SparseInvalidArg();
}

void DiskCacheEntryTest::SparseClipEnd(int64_t max_index,
                                       bool expect_unsupported) {
  std::string key("key");
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 1024;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  auto read_buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize * 2);
  CacheTestFillBuffer(read_buf->data(), kSize * 2, false);

  const int64_t kOffset = max_index - kSize;
  int rv = WriteSparseData(entry, kOffset, buf.get(), kSize);
  EXPECT_EQ(
      rv, expect_unsupported ? net::ERR_CACHE_OPERATION_NOT_SUPPORTED : kSize);

  // Try to read further than offset range, should get clipped (if supported).
  rv = ReadSparseData(entry, kOffset, read_buf.get(), kSize * 2);
  if (expect_unsupported) {
    EXPECT_EQ(rv, net::ERR_CACHE_OPERATION_NOT_SUPPORTED);
  } else {
    EXPECT_EQ(kSize, rv);
    EXPECT_EQ(0, memcmp(buf->data(), read_buf->data(), kSize));
  }

  TestRangeResultCompletionCallback cb;
  RangeResult result = cb.GetResult(
      entry->GetAvailableRange(kOffset - kSize, kSize * 3, cb.callback()));
  if (expect_unsupported) {
    // GetAvailableRange just returns nothing found, not an error.
    EXPECT_EQ(net::OK, result.net_error);
    EXPECT_EQ(result.available_len, 0);
  } else {
    EXPECT_EQ(net::OK, result.net_error);
    EXPECT_EQ(kSize, result.available_len);
    EXPECT_EQ(kOffset, result.start);
  }

  entry->Close();
}

TEST_F(DiskCacheEntryTest, SparseClipEnd) {
  InitCache();

  // Blockfile refuses to deal with sparse indices over 64GiB.
  SparseClipEnd(std::numeric_limits<int64_t>::max(),
                /*expected_unsupported=*/true);
}

TEST_F(DiskCacheEntryTest, SparseClipEnd2) {
  InitCache();

  const int64_t kLimit = 64ll * 1024 * 1024 * 1024;
  // Separate test for blockfile for indices right at the edge of its address
  // space limit. kLimit must match kMaxEndOffset in sparse_control.cc
  SparseClipEnd(kLimit, /*expected_unsupported=*/false);

  // Test with things after kLimit, too, which isn't an issue for backends
  // supporting the entire 64-bit offset range.
  std::string key("key2");
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 1024;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  // Try to write after --- fails.
  int rv = WriteSparseData(entry, kLimit, buf.get(), kSize);
  EXPECT_EQ(net::ERR_CACHE_OPERATION_NOT_SUPPORTED, rv);

  // Similarly for read.
  rv = ReadSparseData(entry, kLimit, buf.get(), kSize);
  EXPECT_EQ(net::ERR_CACHE_OPERATION_NOT_SUPPORTED, rv);

  // GetAvailableRange just returns nothing.
  TestRangeResultCompletionCallback cb;
  RangeResult result =
      cb.GetResult(entry->GetAvailableRange(kLimit, kSize * 3, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);
  entry->Close();
}

TEST_F(DiskCacheEntryTest, MemoryOnlySparseClipEnd) {
  SetMemoryOnlyMode();
  InitCache();
  SparseClipEnd(std::numeric_limits<int64_t>::max(),
                /* expected_unsupported = */ false);
}

TEST_F(DiskCacheEntryTest, SimpleSparseClipEnd) {
  SetSimpleCacheMode();
  InitCache();
  SparseClipEnd(std::numeric_limits<int64_t>::max(),
                /* expected_unsupported = */ false);
}

// Tests that corrupt sparse children are removed automatically.
TEST_F(DiskCacheEntryTest, CleanupSparseEntry) {
  InitCache();
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 4 * 1024;
  auto buf1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf1->data(), kSize, false);

  const int k1Meg = 1024 * 1024;
  EXPECT_EQ(kSize, WriteSparseData(entry, 8192, buf1.get(), kSize));
  EXPECT_EQ(kSize, WriteSparseData(entry, k1Meg + 8192, buf1.get(), kSize));
  EXPECT_EQ(kSize, WriteSparseData(entry, 2 * k1Meg + 8192, buf1.get(), kSize));
  entry->Close();
  EXPECT_EQ(4, cache_->GetEntryCount());

  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  std::string child_keys[2];
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(entry != nullptr);
    // Writing to an entry will alter the LRU list and invalidate the iterator.
    if (entry->GetKey() != key && count < 2)
      child_keys[count++] = entry->GetKey();
    entry->Close();
  }
  for (const auto& child_key : child_keys) {
    ASSERT_THAT(OpenEntry(child_key, &entry), IsOk());
    // Overwrite the header's magic and signature.
    EXPECT_EQ(12, WriteData(entry, 2, 0, buf1.get(), 12, false));
    entry->Close();
  }

  EXPECT_EQ(4, cache_->GetEntryCount());
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  // Two children should be gone. One while reading and one while writing.
  EXPECT_EQ(0, ReadSparseData(entry, 2 * k1Meg + 8192, buf1.get(), kSize));
  EXPECT_EQ(kSize, WriteSparseData(entry, k1Meg + 16384, buf1.get(), kSize));
  EXPECT_EQ(0, ReadSparseData(entry, k1Meg + 8192, buf1.get(), kSize));

  // We never touched this one.
  EXPECT_EQ(kSize, ReadSparseData(entry, 8192, buf1.get(), kSize));
  entry->Close();

  // We re-created one of the corrupt children.
  EXPECT_EQ(3, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, CancelSparseIO) {
  UseCurrentThread();
  InitCache();
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 40 * 1024;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  // This will open and write two "real" entries.
  net::TestCompletionCallback cb1, cb2, cb3, cb4;
  int rv = entry->WriteSparseData(
      1024 * 1024 - 4096, buf.get(), kSize, cb1.callback());
  EXPECT_THAT(rv, IsError(net::ERR_IO_PENDING));

  TestRangeResultCompletionCallback cb5;
  RangeResult result =
      cb5.GetResult(entry->GetAvailableRange(0, kSize, cb5.callback()));
  if (!cb1.have_result()) {
    // We may or may not have finished writing to the entry. If we have not,
    // we cannot start another operation at this time.
    EXPECT_THAT(rv, IsError(net::ERR_CACHE_OPERATION_NOT_SUPPORTED));
  }

  // We cancel the pending operation, and register multiple notifications.
  entry->CancelSparseIO();
  EXPECT_THAT(entry->ReadyForSparseIO(cb2.callback()),
              IsError(net::ERR_IO_PENDING));
  EXPECT_THAT(entry->ReadyForSparseIO(cb3.callback()),
              IsError(net::ERR_IO_PENDING));
  entry->CancelSparseIO();  // Should be a no op at this point.
  EXPECT_THAT(entry->ReadyForSparseIO(cb4.callback()),
              IsError(net::ERR_IO_PENDING));

  if (!cb1.have_result()) {
    EXPECT_EQ(net::ERR_CACHE_OPERATION_NOT_SUPPORTED,
              entry->ReadSparseData(result.start, buf.get(), kSize,
                                    net::CompletionOnceCallback()));
    EXPECT_EQ(net::ERR_CACHE_OPERATION_NOT_SUPPORTED,
              entry->WriteSparseData(result.start, buf.get(), kSize,
                                     net::CompletionOnceCallback()));
  }

  // Now see if we receive all notifications. Note that we should not be able
  // to write everything (unless the timing of the system is really weird).
  rv = cb1.WaitForResult();
  EXPECT_TRUE(rv == 4096 || rv == kSize);
  EXPECT_THAT(cb2.WaitForResult(), IsOk());
  EXPECT_THAT(cb3.WaitForResult(), IsOk());
  EXPECT_THAT(cb4.WaitForResult(), IsOk());

  result = cb5.GetResult(
      entry->GetAvailableRange(result.start, kSize, cb5.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);
  entry->Close();
}

// Tests that we perform sanity checks on an entry's key. Note that there are
// other tests that exercise sanity checks by using saved corrupt files.
TEST_F(DiskCacheEntryTest, KeySanityCheck) {
  UseCurrentThread();
  InitCache();
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);
  disk_cache::EntryStore* store = entry_impl->entry()->Data();

  // We have reserved space for a short key (one block), let's say that the key
  // takes more than one block, and remove the NULLs after the actual key.
  store->key_len = 800;
  memset(store->key + key.size(), 'k', sizeof(store->key) - key.size());
  entry_impl->entry()->set_modified();
  entry->Close();

  // We have a corrupt entry. Now reload it. We should NOT read beyond the
  // allocated buffer here.
  ASSERT_NE(net::OK, OpenEntry(key, &entry));
  DisableIntegrityCheck();
}

TEST_F(DiskCacheEntryTest, KeySanityCheck2) {
  UseCurrentThread();
  InitCache();
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);
  disk_cache::EntryStore* store = entry_impl->entry()->Data();

  // Fill in the rest of inline key store with non-nulls. Unlike in
  // KeySanityCheck, this does not change the length to identify it as
  // stored under |long_key|.
  memset(store->key + key.size(), 'k', sizeof(store->key) - key.size());
  entry_impl->entry()->set_modified();
  entry->Close();

  // We have a corrupt entry. Now reload it. We should NOT read beyond the
  // allocated buffer here.
  ASSERT_NE(net::OK, OpenEntry(key, &entry));
  DisableIntegrityCheck();
}

TEST_F(DiskCacheEntryTest, KeySanityCheck3) {
  const size_t kVeryLong = 40 * 1024;
  UseCurrentThread();
  InitCache();
  std::string key(kVeryLong, 'a');
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);
  disk_cache::EntryStore* store = entry_impl->entry()->Data();

  // Test meaningful when using long keys; and also want this to be
  // an external file to avoid needing to duplicate offset math here.
  disk_cache::Addr key_addr(store->long_key);
  ASSERT_TRUE(key_addr.is_initialized());
  ASSERT_TRUE(key_addr.is_separate_file());

  // Close the entry before messing up its files.
  entry->Close();

  // Mess up the terminating null in the external key file.
  auto key_file =
      base::MakeRefCounted<dis
```