Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/disk_cache/entry_unittest.cc` in the Chromium project. The focus should be on:

1. **Functionality:** What does this specific part of the test file do?
2. **JavaScript Relevance:** Is there any connection to JavaScript?
3. **Logical Inference (Input/Output):**  If there's test logic, what are the assumed inputs and expected outputs?
4. **Common Usage Errors:** What mistakes might users or programmers make when interacting with this code or the system it tests?
5. **User Journey:** How does a user's action lead to this code being executed? (Debugging perspective)
6. **Summarization:**  Provide a concise summary of the functionality of this code block.

Let's break down the code section by section:

* **`TEST_F(DiskCacheEntryTest, SimpleCacheBadKeyFile)`:** Tests how the cache handles a corrupted key file.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheInternalAsyncIO)`:** Tests asynchronous I/O operations for internally stored data in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheExternalAsyncIO)`:** Tests asynchronous I/O operations for externally stored data in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheReleaseBuffer)`:** Tests releasing buffers associated with cache entries in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheStreamAccess)`:** Tests accessing different data streams of a cache entry in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheGetKey)`:** Tests retrieving the key of a cache entry in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheGetTimes)`:** Tests retrieving the timestamps of a cache entry in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheGrowData)`:** Tests increasing the size of data streams in a cache entry in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheTruncateData)`:** Tests decreasing the size of data streams in a cache entry in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheZeroLengthIO)`:** Tests performing I/O operations with zero-length data in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheSizeAtCreate)`:** Tests the size of a cache entry immediately after creation in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheReuseExternalEntry)`:** Tests reusing cache entries for externally stored data in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheReuseInternalEntry)`:** Tests reusing cache entries for internally stored data in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheGiantEntry)`:** Tests the ability to handle very large cache entries in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheSizeChanges)`:** Tests how the reported size of a cache entry changes after modifications in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheInvalidData)`:** Tests how the cache handles invalid data during I/O operations in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheReadWriteDestroyBuffer)`:** Tests reading and writing data and then destroying the associated buffer (with optimistic operations disabled for most streams).
* **`TEST_F(DiskCacheEntryTest, SimpleCacheDoomEntry)`:** Tests deleting (dooming) a normal cache entry in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheDoomEntryNextToOpenEntry)`:** Tests dooming an entry when another entry is open nearby in the cache structure.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheDoomedEntry)`:** Tests interacting with an already doomed cache entry in SimpleCache mode.
* **`SimpleCacheMakeBadChecksumEntry` function:** A helper function to create a cache entry with a corrupted checksum in SimpleCache mode.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheBadChecksum)`:** Tests the cache's behavior when encountering an entry with a corrupted checksum.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheErrorThenDoom)`:** Tests dooming an entry after an I/O error has occurred.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheCreateAfterDiskLayerDoom)`:** Tests creating an entry after a previous creation attempt failed due to a disk error.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheQueuedOpenOnDoomedEntry)`:** Tests opening an entry that is doomed while the open operation is still queued.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheDoomErrorRace)`:** Tests a race condition where a manual doom operation occurs simultaneously with an error-induced doom.
* **`TruncatePath` function:** A helper function to truncate a file to a specific length.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheNoEOF)`:** Tests the cache's behavior when an entry file is truncated such that it doesn't contain the end-of-file marker.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheNonOptimisticOperationsBasic)`:** Tests basic read/write operations when optimistic operations are disabled.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheNonOptimisticOperationsDontBlock)`:** Tests that non-optimistic operations don't block the main thread.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheNonOptimisticOperationsBasicsWithoutWaiting)`:** Tests basic read/write operations with non-optimistic operations without explicitly waiting for completion.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic)`:** Tests a sequence of create, write, read operations when optimistic operations are enabled.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic2)`:** Tests a sequence of create, open, close operations with optimistic operations.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic3)`:** Tests a sequence of create, close, open, close operations with optimistic operations.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic4)`:** Tests a more complex sequence of operations to verify optimistic operation behavior, including handling writes to closed entries.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic5)`:** Tests a sequence of create, doom, write, read, close operations with optimistic operations.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic6)`:** Tests a sequence of create, write, multiple dooms, read, doom, close operations with optimistic operations.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheOptimisticWriteReleases)`:** Tests that IO buffers are released after an optimistic write operation completes.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheCreateDoomRace)`:** Tests a race condition between creating and dooming an entry.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheDoomCreateRace)`:** Tests a race condition between dooming and creating an entry.
* **`TEST_F(DiskCacheEntryTest, SimpleCacheDoomCreateOptimistic)`:** Tests optimized handling of the doom followed by create sequence when optimistic operations are enabled.

Now, let's put it all together.
这是 Chromium 网络栈中 `net/disk_cache/entry_unittest.cc` 文件的第四部分，主要功能是 **详细测试 `SimpleCache` 模式下 `disk_cache::Entry` 的各种操作和边界情况，特别是针对数据完整性、并发操作、以及错误处理的场景**。

以下是更详细的功能列表：

**针对数据完整性和错误处理的测试：**

* **`SimpleCacheBadKeyFile`**: 测试当缓存条目的 key 文件损坏时，缓存的恢复能力。
* **`SimpleCacheBadChecksum`**: 测试缓存检测到数据校验和错误时的处理方式。
* **`SimpleCacheErrorThenDoom`**: 测试在发生 I/O 错误后，能否成功删除（Doom）缓存条目。
* **`SimpleCacheNoEOF`**: 测试当缓存条目文件被截断，缺少末尾标记时，缓存的反应。

**针对并发操作和生命周期的测试：**

* **`SimpleCacheCreateAfterDiskLayerDoom`**: 测试在后台磁盘操作失败后，尝试创建相同 key 的缓存条目会发生什么。
* **`SimpleCacheQueuedOpenOnDoomedEntry`**: 测试当 Open 操作在队列中等待时，如果条目被删除（Doom），Open 操作会如何处理。
* **`SimpleCacheDoomErrorRace`**: 测试当一个条目因为错误被删除，同时又有显式的删除操作发生时的竞争情况。
* **`SimpleCacheCreateDoomRace`**: 测试创建操作和删除操作同时发生时的竞争情况。
* **`SimpleCacheDoomCreateRace`**: 测试删除操作和创建操作同时发生时的竞争情况。
* **`SimpleCacheDoomCreateOptimistic`**: 测试在启用乐观操作的情况下，删除后立即创建同一个 key 的条目是否能被优化处理。

**针对非乐观操作的测试 (使用 `APP_CACHE` 类型禁用乐观操作):**

* **`SimpleCacheNonOptimisticOperationsBasic`**: 测试在禁用乐观操作时，基本的创建、写入、读取和关闭操作。
* **`SimpleCacheNonOptimisticOperationsDontBlock`**: 测试在禁用乐观操作时，写入操作不会阻塞主线程。
* **`SimpleCacheNonOptimisticOperationsBasicsWithoutWaiting`**:  测试在禁用乐观操作时，不等待操作完成的情况下的基本读写操作。

**针对乐观操作的更深入测试 (默认 `SimpleCache` 模式启用乐观操作):**

* **`SimpleCacheOptimistic`**: 测试乐观的创建和写入操作，以及非乐观的读取操作的交互。
* **`SimpleCacheOptimistic2`**: 测试乐观的创建，然后打开同一个条目的情况。
* **`SimpleCacheOptimistic3`**: 测试创建后关闭，再打开同一个条目的情况。
* **`SimpleCacheOptimistic4`**: 测试更复杂的乐观操作序列，包括写入已关闭的条目以及多次打开。
* **`SimpleCacheOptimistic5`**: 测试创建后立即删除（Doom），然后尝试写入和读取的情况。
* **`SimpleCacheOptimistic6`**: 测试创建，写入后多次删除（Doom），然后再读取的情况。
* **`SimpleCacheOptimisticWriteReleases`**: 测试乐观写入操作完成后，是否正确释放了 I/O 缓冲区。

**辅助功能：**

* **`SimpleCacheMakeBadChecksumEntry`**:  一个辅助函数，用于创建一个指定 key 和大小的缓存条目，并故意损坏其校验和。
* **`TruncatePath`**: 一个辅助函数，用于截断指定路径的文件到指定的长度。

**与 Javascript 的关系：**

这段 C++ 代码主要测试的是 Chromium 浏览器底层的网络缓存机制。虽然直接的 Javascript 代码不会直接调用这些 C++ 函数，但是当浏览器加载网页资源（例如图片、CSS、JS 文件）时，网络栈会负责从网络下载或者从缓存中读取这些资源。

**举例说明：**

假设一个网页请求一个 Javascript 文件，并且该文件之前已经被缓存过 (使用 `SimpleCache` 模式)。

1. **用户操作:** 用户在浏览器地址栏输入网址并回车，或者点击一个包含该 Javascript 文件链接的网页。
2. **网络请求:** 浏览器发起对该 Javascript 文件的网络请求。
3. **缓存查找:** 网络栈会首先检查缓存中是否存在该文件的副本。这会涉及到对缓存索引的查找，并可能调用到类似本测试中涉及的 `OpenEntry` 操作。
4. **缓存命中 (如果存在):** 如果缓存命中，网络栈会尝试从缓存中读取该文件的数据。这可能涉及到 `ReadData` 操作。
5. **数据校验 (针对 `SimpleCacheBadChecksum`):**  如果缓存系统检测到缓存文件的校验和错误 (就像 `SimpleCacheMakeBadChecksumEntry` 创建的那样)，网络栈可能会拒绝使用该缓存，并重新从网络下载。
6. **乐观操作 (针对 `SimpleCacheOptimistic` 等测试):** 在 `SimpleCache` 模式下，为了提高性能，缓存的写入和读取操作可能是乐观的。例如，当 Javascript 文件被写入缓存时，写入操作可能不会立即等待磁盘完成，而是先标记为完成，后续再异步刷新到磁盘。

**逻辑推理 (假设输入与输出):**

以 `TEST_F(DiskCacheEntryTest, SimpleCacheBadKeyFile)` 为例：

* **假设输入:**
    * 缓存中存在一个 key 为 "the first key" 的条目。
    * 该条目的 key 文件被损坏（例如，内容被修改）。
* **预期输出:**
    * `OpenEntry("the first key", &entry)` 操作会失败。
    * 缓存能够优雅地恢复，不会崩溃。

以 `TEST_F(DiskCacheEntryTest, SimpleCacheBadChecksum)` 为例：

* **假设输入:**
    * 缓存中存在一个 key 为 "the first key" 的条目。
    * 该条目的数据文件被故意修改，导致校验和不匹配（通过 `SimpleCacheMakeBadChecksumEntry` 创建）。
    * 尝试打开该条目并读取数据。
* **预期输出:**
    * `OpenEntry("the first key", &entry)` 操作成功。
    * `ReadData(entry, 1, 0, read_buffer.get(), kLargeSize)` 操作会返回 `net::ERR_CACHE_CHECKSUM_MISMATCH` 错误。

**用户或编程常见的使用错误：**

* **手动修改缓存文件:** 用户或恶意程序直接修改缓存目录中的文件，可能导致校验和错误，就像 `SimpleCacheBadChecksum` 测试的那样，导致浏览器无法使用缓存。
* **不正确的并发控制:**  在多线程环境下操作缓存时，如果没有适当的锁机制，可能导致数据损坏或竞争条件，这些正是像 `SimpleCacheCreateDoomRace` 和 `SimpleCacheDoomCreateRace` 这样的测试所要覆盖的场景。
* **假设缓存操作总是同步完成:** 开发者如果假设缓存的写入或读取操作是立即完成的，而没有考虑异步操作的可能性，可能会导致程序出现意外行为，尤其是在非乐观模式下，缓存操作可能是异步的。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户访问网页:** 用户在浏览器中输入一个网址或者点击一个链接。
2. **浏览器发起网络请求:** 浏览器解析网页资源，并向服务器发起网络请求，例如请求图片、CSS 或 Javascript 文件。
3. **缓存检查:** Chromium 的网络栈在收到网络请求后，会首先检查本地缓存 (`SimpleCache` 是其中一种缓存实现)。
4. **`OpenEntry` 调用:**  为了判断缓存中是否存在对应的资源，缓存系统可能会调用类似 `OpenEntry` 的函数，尝试打开对应 key 的缓存条目。
5. **文件系统交互:** `OpenEntry` 内部会涉及到文件系统的操作，例如读取索引文件或数据文件。
6. **校验和检查 (`SimpleCacheBadChecksum`):** 如果打开了缓存条目，在读取数据时，缓存系统可能会进行校验和检查，确保缓存数据的完整性。如果校验和不匹配，就会触发类似 `SimpleCacheBadChecksum` 测试中模拟的场景。
7. **错误处理 (`SimpleCacheErrorThenDoom`):**  如果在读取或写入缓存的过程中发生磁盘 I/O 错误，缓存系统需要能够妥善处理这些错误，并可能需要删除（Doom）损坏的缓存条目，就像 `SimpleCacheErrorThenDoom` 测试所验证的那样。

**功能归纳：**

这部分代码主要专注于 `SimpleCache` 模式下 `disk_cache::Entry` 的 **健壮性和可靠性测试**。它涵盖了各种异常情况，例如缓存文件损坏、校验和错误、并发操作以及不同操作模式（乐观与非乐观）下的行为。这些测试旨在确保在各种复杂和异常场景下，缓存系统能够正确运行，保证数据的完整性，并能从错误中恢复。

Prompt: 
```
这是目录为net/disk_cache/entry_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共7部分，请归纳一下它的功能

"""
k_cache::File>(true /* want sync ops*/);
  ASSERT_TRUE(key_file->Init(cache_impl_->GetFileName(key_addr)));

  ASSERT_TRUE(key_file->Write("b", 1u, kVeryLong));
  key_file = nullptr;

  // This case gets graceful recovery.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  // Make sure the key object isn't messed up.
  EXPECT_EQ(kVeryLong, strlen(entry->GetKey().data()));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheInternalAsyncIO) {
  SetSimpleCacheMode();
  InitCache();
  InternalAsyncIO();
}

TEST_F(DiskCacheEntryTest, SimpleCacheExternalAsyncIO) {
  SetSimpleCacheMode();
  InitCache();
  ExternalAsyncIO();
}

TEST_F(DiskCacheEntryTest, SimpleCacheReleaseBuffer) {
  SetSimpleCacheMode();
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    ReleaseBuffer(i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheStreamAccess) {
  SetSimpleCacheMode();
  InitCache();
  StreamAccess();
}

TEST_F(DiskCacheEntryTest, SimpleCacheGetKey) {
  SetSimpleCacheMode();
  InitCache();
  GetKey();
}

TEST_F(DiskCacheEntryTest, SimpleCacheGetTimes) {
  SetSimpleCacheMode();
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    GetTimes(i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheGrowData) {
  SetSimpleCacheMode();
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    GrowData(i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheTruncateData) {
  SetSimpleCacheMode();
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    TruncateData(i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheZeroLengthIO) {
  SetSimpleCacheMode();
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    ZeroLengthIO(i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheSizeAtCreate) {
  SetSimpleCacheMode();
  InitCache();
  SizeAtCreate();
}

TEST_F(DiskCacheEntryTest, SimpleCacheReuseExternalEntry) {
  SetSimpleCacheMode();
  SetMaxSize(200 * 1024);
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    ReuseEntry(20 * 1024, i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheReuseInternalEntry) {
  SetSimpleCacheMode();
  SetMaxSize(100 * 1024);
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    ReuseEntry(10 * 1024, i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheGiantEntry) {
  const int kBufSize = 32 * 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufSize);
  CacheTestFillBuffer(buffer->data(), kBufSize, false);

  // Make sure SimpleCache can write up to 5MiB entry even with a 20MiB cache
  // size that Android WebView uses at the time of this test's writing.
  SetSimpleCacheMode();
  SetMaxSize(20 * 1024 * 1024);
  InitCache();

  {
    std::string key1("the first key");
    disk_cache::Entry* entry1 = nullptr;
    ASSERT_THAT(CreateEntry(key1, &entry1), IsOk());

    const int kSize1 = 5 * 1024 * 1024;
    EXPECT_EQ(kBufSize, WriteData(entry1, 1 /* stream */, kSize1 - kBufSize,
                                  buffer.get(), kBufSize, true /* truncate */));
    entry1->Close();
  }

  // ... but not bigger than that.
  {
    std::string key2("the second key");
    disk_cache::Entry* entry2 = nullptr;
    ASSERT_THAT(CreateEntry(key2, &entry2), IsOk());

    const int kSize2 = 5 * 1024 * 1024 + 1;
    EXPECT_EQ(net::ERR_FAILED,
              WriteData(entry2, 1 /* stream */, kSize2 - kBufSize, buffer.get(),
                        kBufSize, true /* truncate */));
    entry2->Close();
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheSizeChanges) {
  SetSimpleCacheMode();
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    SizeChanges(i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheInvalidData) {
  SetSimpleCacheMode();
  InitCache();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    InvalidData(i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheReadWriteDestroyBuffer) {
  // Proving that the test works well with optimistic operations enabled is
  // subtle, instead run only in APP_CACHE mode to disable optimistic
  // operations. Stream 0 always uses optimistic operations, so the test is not
  // run on stream 0.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();
  for (int i = 1; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    ReadWriteDestroyBuffer(i);
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomEntry) {
  SetSimpleCacheMode();
  InitCache();
  DoomNormalEntry();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomEntryNextToOpenEntry) {
  SetSimpleCacheMode();
  InitCache();
  DoomEntryNextToOpenEntry();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomedEntry) {
  SetSimpleCacheMode();
  InitCache();
  // Stream 2 is excluded because the implementation does not support writing to
  // it on a doomed entry, if it was previously lazily omitted.
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount - 1; ++i) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
    DoomedEntry(i);
  }
}

// Creates an entry with corrupted last byte in stream 0.
// Requires SimpleCacheMode.
bool DiskCacheEntryTest::SimpleCacheMakeBadChecksumEntry(const std::string& key,
                                                         int data_size) {
  disk_cache::Entry* entry = nullptr;

  if (CreateEntry(key, &entry) != net::OK || !entry) {
    LOG(ERROR) << "Could not create entry";
    return false;
  }

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(data_size);
  memset(buffer->data(), 'A', data_size);

  EXPECT_EQ(data_size, WriteData(entry, 1, 0, buffer.get(), data_size, false));
  entry->Close();
  entry = nullptr;

  // Corrupt the last byte of the data.
  base::FilePath entry_file0_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));
  base::File entry_file0(entry_file0_path,
                         base::File::FLAG_WRITE | base::File::FLAG_OPEN);
  if (!entry_file0.IsValid())
    return false;

  int64_t file_offset =
      sizeof(disk_cache::SimpleFileHeader) + key.size() + data_size - 2;
  EXPECT_EQ(1, entry_file0.Write(file_offset, "X", 1));
  return true;
}

TEST_F(DiskCacheEntryTest, SimpleCacheBadChecksum) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  const int kLargeSize = 50000;
  ASSERT_TRUE(SimpleCacheMakeBadChecksumEntry(key, kLargeSize));

  disk_cache::Entry* entry = nullptr;

  // Open the entry. Can't spot the checksum that quickly with it so
  // huge.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ScopedEntryPtr entry_closer(entry);

  EXPECT_GE(kLargeSize, entry->GetDataSize(1));
  auto read_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kLargeSize);
  EXPECT_EQ(net::ERR_CACHE_CHECKSUM_MISMATCH,
            ReadData(entry, 1, 0, read_buffer.get(), kLargeSize));
}

// Tests that an entry that has had an IO error occur can still be Doomed().
TEST_F(DiskCacheEntryTest, SimpleCacheErrorThenDoom) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  const int kLargeSize = 50000;
  ASSERT_TRUE(SimpleCacheMakeBadChecksumEntry(key, kLargeSize));

  disk_cache::Entry* entry = nullptr;

  // Open the entry, forcing an IO error.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ScopedEntryPtr entry_closer(entry);

  EXPECT_GE(kLargeSize, entry->GetDataSize(1));
  auto read_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kLargeSize);
  EXPECT_EQ(net::ERR_CACHE_CHECKSUM_MISMATCH,
            ReadData(entry, 1, 0, read_buffer.get(), kLargeSize));
  entry->Doom();  // Should not crash.
}

TEST_F(DiskCacheEntryTest, SimpleCacheCreateAfterDiskLayerDoom) {
  // Code coverage for what happens when a queued create runs after failure
  // was noticed at SimpleSynchronousEntry layer.
  SetSimpleCacheMode();
  // Disable optimistic ops so we can block on CreateEntry and start
  // WriteData off with an empty op queue.
  SetCacheType(net::APP_CACHE);
  InitCache();

  const char key[] = "the key";
  const int kSize1 = 10;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_EQ(net::OK, CreateEntry(key, &entry));
  ASSERT_TRUE(entry != nullptr);

  // Make an empty _1 file, to cause a stream 2 write to fail.
  base::FilePath entry_file1_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 1));
  base::File entry_file1(entry_file1_path,
                         base::File::FLAG_WRITE | base::File::FLAG_CREATE);
  ASSERT_TRUE(entry_file1.IsValid());

  entry->WriteData(2, 0, buffer1.get(), kSize1, net::CompletionOnceCallback(),
                   /* truncate= */ true);
  entry->Close();

  // At this point we have put WriteData & Close on the queue, and WriteData
  // started, but we haven't given the event loop control so the failure
  // hasn't been reported and handled here, so the entry is still active
  // for the key. Queue up another create for same key, and run through the
  // events.
  disk_cache::Entry* entry2 = nullptr;
  ASSERT_EQ(net::ERR_FAILED, CreateEntry(key, &entry2));
  ASSERT_TRUE(entry2 == nullptr);

  EXPECT_EQ(0, cache_->GetEntryCount());

  // Should be able to create properly next time, though.
  disk_cache::Entry* entry3 = nullptr;
  ASSERT_EQ(net::OK, CreateEntry(key, &entry3));
  ASSERT_TRUE(entry3 != nullptr);
  entry3->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheQueuedOpenOnDoomedEntry) {
  // This tests the following sequence of ops:
  // A = Create(K);
  // Close(A);
  // B = Open(K);
  // Doom(K);
  // Close(B);
  //
  // ... where the execution of the Open sits on the queue all the way till
  // Doom. This now succeeds, as the doom is merely queued at time of Open,
  // rather than completed.

  SetSimpleCacheMode();
  // Disable optimistic ops so we can block on CreateEntry and start
  // WriteData off with an empty op queue.
  SetCacheType(net::APP_CACHE);
  InitCache();

  const char key[] = "the key";

  disk_cache::Entry* entry = nullptr;
  ASSERT_EQ(net::OK, CreateEntry(key, &entry));  // event loop!
  ASSERT_TRUE(entry != nullptr);

  entry->Close();

  // Done via cache_ -> no event loop.
  TestEntryResultCompletionCallback cb;
  EntryResult result = cache_->OpenEntry(key, net::HIGHEST, cb.callback());
  ASSERT_EQ(net::ERR_IO_PENDING, result.net_error());

  net::TestCompletionCallback cb2;
  cache_->DoomEntry(key, net::HIGHEST, cb2.callback());
  // Now event loop.
  result = cb.WaitForResult();
  EXPECT_EQ(net::OK, result.net_error());
  result.ReleaseEntry()->Close();

  EXPECT_EQ(net::OK, cb2.WaitForResult());
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomErrorRace) {
  // Code coverage for a doom racing with a doom induced by a failure.
  SetSimpleCacheMode();
  // Disable optimistic ops so we can block on CreateEntry and start
  // WriteData off with an empty op queue.
  SetCacheType(net::APP_CACHE);
  InitCache();

  const char kKey[] = "the first key";
  const int kSize1 = 10;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_EQ(net::OK, CreateEntry(kKey, &entry));
  ASSERT_TRUE(entry != nullptr);

  // Now an empty _1 file, to cause a stream 2 write to fail.
  base::FilePath entry_file1_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(kKey, 1));
  base::File entry_file1(entry_file1_path,
                         base::File::FLAG_WRITE | base::File::FLAG_CREATE);
  ASSERT_TRUE(entry_file1.IsValid());

  entry->WriteData(2, 0, buffer1.get(), kSize1, net::CompletionOnceCallback(),
                   /* truncate= */ true);

  net::TestCompletionCallback cb;
  cache_->DoomEntry(kKey, net::HIGHEST, cb.callback());
  entry->Close();
  EXPECT_EQ(0, cb.WaitForResult());
}

bool TruncatePath(const base::FilePath& file_path, int64_t length) {
  base::File file(file_path, base::File::FLAG_WRITE | base::File::FLAG_OPEN);
  if (!file.IsValid())
    return false;
  return file.SetLength(length);
}

TEST_F(DiskCacheEntryTest, SimpleCacheNoEOF) {
  SetSimpleCacheMode();
  InitCache();

  const std::string key("the first key");

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  disk_cache::Entry* null = nullptr;
  EXPECT_NE(null, entry);
  entry->Close();
  entry = nullptr;

  // Force the entry to flush to disk, so subsequent platform file operations
  // succed.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  entry->Close();
  entry = nullptr;

  // Truncate the file such that the length isn't sufficient to have an EOF
  // record.
  int kTruncationBytes = -static_cast<int>(sizeof(disk_cache::SimpleFileEOF));
  const base::FilePath entry_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));
  const int64_t invalid_size = disk_cache::simple_util::GetFileSizeFromDataSize(
      key.size(), kTruncationBytes);
  EXPECT_TRUE(TruncatePath(entry_path, invalid_size));
  EXPECT_THAT(OpenEntry(key, &entry), IsError(net::ERR_FAILED));
  DisableIntegrityCheck();
}

TEST_F(DiskCacheEntryTest, SimpleCacheNonOptimisticOperationsBasic) {
  // Test sequence:
  // Create, Write, Read, Close.
  SetCacheType(net::APP_CACHE);  // APP_CACHE doesn't use optimistic operations.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* const null_entry = nullptr;

  disk_cache::Entry* entry = nullptr;
  EXPECT_THAT(CreateEntry("my key", &entry), IsOk());
  ASSERT_NE(null_entry, entry);
  ScopedEntryPtr entry_closer(entry);

  const int kBufferSize = 10;
  scoped_refptr<net::IOBufferWithSize> write_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CacheTestFillBuffer(write_buffer->data(), write_buffer->size(), false);
  EXPECT_EQ(
      write_buffer->size(),
      WriteData(entry, 1, 0, write_buffer.get(), write_buffer->size(), false));

  scoped_refptr<net::IOBufferWithSize> read_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  EXPECT_EQ(read_buffer->size(),
            ReadData(entry, 1, 0, read_buffer.get(), read_buffer->size()));
}

TEST_F(DiskCacheEntryTest, SimpleCacheNonOptimisticOperationsDontBlock) {
  // Test sequence:
  // Create, Write, Close.
  SetCacheType(net::APP_CACHE);  // APP_CACHE doesn't use optimistic operations.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* const null_entry = nullptr;

  MessageLoopHelper helper;
  CallbackTest create_callback(&helper, false);

  int expected_callback_runs = 0;
  const int kBufferSize = 10;
  scoped_refptr<net::IOBufferWithSize> write_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);

  disk_cache::Entry* entry = nullptr;
  EXPECT_THAT(CreateEntry("my key", &entry), IsOk());
  ASSERT_NE(null_entry, entry);
  ScopedEntryPtr entry_closer(entry);

  CacheTestFillBuffer(write_buffer->data(), write_buffer->size(), false);
  CallbackTest write_callback(&helper, false);
  int ret = entry->WriteData(
      1, 0, write_buffer.get(), write_buffer->size(),
      base::BindOnce(&CallbackTest::Run, base::Unretained(&write_callback)),
      false);
  ASSERT_THAT(ret, IsError(net::ERR_IO_PENDING));
  helper.WaitUntilCacheIoFinished(++expected_callback_runs);
}

TEST_F(DiskCacheEntryTest,
       SimpleCacheNonOptimisticOperationsBasicsWithoutWaiting) {
  // Test sequence:
  // Create, Write, Read, Close.
  SetCacheType(net::APP_CACHE);  // APP_CACHE doesn't use optimistic operations.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* const null_entry = nullptr;
  MessageLoopHelper helper;

  disk_cache::Entry* entry = nullptr;
  // Note that |entry| is only set once CreateEntry() completed which is why we
  // have to wait (i.e. use the helper CreateEntry() function).
  EXPECT_THAT(CreateEntry("my key", &entry), IsOk());
  ASSERT_NE(null_entry, entry);
  ScopedEntryPtr entry_closer(entry);

  const int kBufferSize = 10;
  scoped_refptr<net::IOBufferWithSize> write_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CacheTestFillBuffer(write_buffer->data(), write_buffer->size(), false);
  CallbackTest write_callback(&helper, false);
  int ret = entry->WriteData(
      1, 0, write_buffer.get(), write_buffer->size(),
      base::BindOnce(&CallbackTest::Run, base::Unretained(&write_callback)),
      false);
  EXPECT_THAT(ret, IsError(net::ERR_IO_PENDING));
  int expected_callback_runs = 1;

  scoped_refptr<net::IOBufferWithSize> read_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CallbackTest read_callback(&helper, false);
  ret = entry->ReadData(
      1, 0, read_buffer.get(), read_buffer->size(),
      base::BindOnce(&CallbackTest::Run, base::Unretained(&read_callback)));
  EXPECT_THAT(ret, IsError(net::ERR_IO_PENDING));
  ++expected_callback_runs;

  helper.WaitUntilCacheIoFinished(expected_callback_runs);
  ASSERT_EQ(read_buffer->size(), write_buffer->size());
  EXPECT_EQ(
      0,
      memcmp(read_buffer->data(), write_buffer->data(), read_buffer->size()));
}

TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic) {
  // Test sequence:
  // Create, Write, Read, Write, Read, Close.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;
  const char key[] = "the first key";

  MessageLoopHelper helper;
  CallbackTest callback1(&helper, false);
  CallbackTest callback2(&helper, false);
  CallbackTest callback3(&helper, false);
  CallbackTest callback4(&helper, false);
  CallbackTest callback5(&helper, false);

  int expected = 0;
  const int kSize1 = 10;
  const int kSize2 = 20;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer1_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer2_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);

  // Create is optimistic, must return OK.
  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST,
                          base::BindOnce(&CallbackTest::RunWithEntry,
                                         base::Unretained(&callback1)));
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  ASSERT_NE(null, entry);
  ScopedEntryPtr entry_closer(entry);

  // This write may or may not be optimistic (it depends if the previous
  // optimistic create already finished by the time we call the write here).
  int ret = entry->WriteData(
      1, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback2)), false);
  EXPECT_TRUE(kSize1 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  // This Read must not be optimistic, since we don't support that yet.
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->ReadData(1, 0, buffer1_read.get(), kSize1,
                            base::BindOnce(&CallbackTest::Run,
                                           base::Unretained(&callback3))));
  expected++;
  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer1_read->data(), kSize1));

  // At this point after waiting, the pending operations queue on the entry
  // should be empty, so the next Write operation must run as optimistic.
  EXPECT_EQ(kSize2,
            entry->WriteData(1, 0, buffer2.get(), kSize2,
                             base::BindOnce(&CallbackTest::Run,
                                            base::Unretained(&callback4)),
                             false));

  // Lets do another read so we block until both the write and the read
  // operation finishes and we can then test for HasOneRef() below.
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->ReadData(1, 0, buffer2_read.get(), kSize2,
                            base::BindOnce(&CallbackTest::Run,
                                           base::Unretained(&callback5))));
  expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(0, memcmp(buffer2->data(), buffer2_read->data(), kSize2));

  // Check that we are not leaking.
  EXPECT_NE(entry, null);
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());
}

TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic2) {
  // Test sequence:
  // Create, Open, Close, Close.
  SetSimpleCacheMode();
  InitCache();
  const char key[] = "the first key";

  MessageLoopHelper helper;
  CallbackTest callback1(&helper, false);
  CallbackTest callback2(&helper, false);

  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST,
                          base::BindOnce(&CallbackTest::RunWithEntry,
                                         base::Unretained(&callback1)));
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  ASSERT_NE(nullptr, entry);
  ScopedEntryPtr entry_closer(entry);

  EntryResult result2 =
      cache_->OpenEntry(key, net::HIGHEST,
                        base::BindOnce(&CallbackTest::RunWithEntry,
                                       base::Unretained(&callback2)));
  ASSERT_EQ(net::ERR_IO_PENDING, result2.net_error());
  ASSERT_TRUE(helper.WaitUntilCacheIoFinished(1));
  result2 = callback2.ReleaseLastEntryResult();
  EXPECT_EQ(net::OK, result2.net_error());
  disk_cache::Entry* entry2 = result2.ReleaseEntry();
  EXPECT_NE(nullptr, entry2);
  EXPECT_EQ(entry, entry2);

  // We have to call close twice, since we called create and open above.
  // (the other closes is from |entry_closer|).
  entry->Close();

  // Check that we are not leaking.
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());
}

TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic3) {
  // Test sequence:
  // Create, Close, Open, Close.
  SetSimpleCacheMode();
  InitCache();
  const char key[] = "the first key";

  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  ASSERT_NE(nullptr, entry);
  entry->Close();

  TestEntryResultCompletionCallback cb;
  EntryResult result2 = cache_->OpenEntry(key, net::HIGHEST, cb.callback());
  ASSERT_EQ(net::ERR_IO_PENDING, result2.net_error());
  result2 = cb.WaitForResult();
  ASSERT_THAT(result2.net_error(), IsOk());
  disk_cache::Entry* entry2 = result2.ReleaseEntry();
  ScopedEntryPtr entry_closer(entry2);

  EXPECT_NE(nullptr, entry2);
  EXPECT_EQ(entry, entry2);

  // Check that we are not leaking.
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry2)->HasOneRef());
}

TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic4) {
  // Test sequence:
  // Create, Close, Write, Open, Open, Close, Write, Read, Close.
  SetSimpleCacheMode();
  InitCache();
  const char key[] = "the first key";

  net::TestCompletionCallback cb;
  const int kSize1 = 10;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);

  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  ASSERT_NE(nullptr, entry);
  entry->Close();

  // Lets do a Write so we block until both the Close and the Write
  // operation finishes. Write must fail since we are writing in a closed entry.
  EXPECT_EQ(
      net::ERR_IO_PENDING,
      entry->WriteData(1, 0, buffer1.get(), kSize1, cb.callback(), false));
  EXPECT_THAT(cb.GetResult(net::ERR_IO_PENDING), IsError(net::ERR_FAILED));

  // Finish running the pending tasks so that we fully complete the close
  // operation and destroy the entry object.
  base::RunLoop().RunUntilIdle();

  // At this point the |entry| must have been destroyed, and called
  // RemoveSelfFromBackend().
  TestEntryResultCompletionCallback cb2;
  EntryResult result2 = cache_->OpenEntry(key, net::HIGHEST, cb2.callback());
  ASSERT_EQ(net::ERR_IO_PENDING, result2.net_error());
  result2 = cb2.WaitForResult();
  ASSERT_THAT(result2.net_error(), IsOk());
  disk_cache::Entry* entry2 = result2.ReleaseEntry();
  EXPECT_NE(nullptr, entry2);

  EntryResult result3 = cache_->OpenEntry(key, net::HIGHEST, cb2.callback());
  ASSERT_EQ(net::ERR_IO_PENDING, result3.net_error());
  result3 = cb2.WaitForResult();
  ASSERT_THAT(result3.net_error(), IsOk());
  disk_cache::Entry* entry3 = result3.ReleaseEntry();
  EXPECT_NE(nullptr, entry3);
  EXPECT_EQ(entry2, entry3);
  entry3->Close();

  // The previous Close doesn't actually closes the entry since we opened it
  // twice, so the next Write operation must succeed and it must be able to
  // perform it optimistically, since there is no operation running on this
  // entry.
  EXPECT_EQ(kSize1, entry2->WriteData(1, 0, buffer1.get(), kSize1,
                                      net::CompletionOnceCallback(), false));

  // Lets do another read so we block until both the write and the read
  // operation finishes and we can then test for HasOneRef() below.
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry2->ReadData(1, 0, buffer1.get(), kSize1, cb.callback()));
  EXPECT_EQ(kSize1, cb.GetResult(net::ERR_IO_PENDING));

  // Check that we are not leaking.
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry2)->HasOneRef());
  entry2->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic5) {
  // Test sequence:
  // Create, Doom, Write, Read, Close.
  SetSimpleCacheMode();
  InitCache();
  const char key[] = "the first key";

  net::TestCompletionCallback cb;
  const int kSize1 = 10;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);

  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  ASSERT_NE(nullptr, entry);
  ScopedEntryPtr entry_closer(entry);
  entry->Doom();

  EXPECT_EQ(
      net::ERR_IO_PENDING,
      entry->WriteData(1, 0, buffer1.get(), kSize1, cb.callback(), false));
  EXPECT_EQ(kSize1, cb.GetResult(net::ERR_IO_PENDING));

  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->ReadData(1, 0, buffer1.get(), kSize1, cb.callback()));
  EXPECT_EQ(kSize1, cb.GetResult(net::ERR_IO_PENDING));

  // Check that we are not leaking.
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());
}

TEST_F(DiskCacheEntryTest, SimpleCacheOptimistic6) {
  // Test sequence:
  // Create, Write, Doom, Doom, Read, Doom, Close.
  SetSimpleCacheMode();
  InitCache();
  const char key[] = "the first key";

  net::TestCompletionCallback cb;
  const int kSize1 = 10;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer1_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);

  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  EXPECT_NE(nullptr, entry);
  ScopedEntryPtr entry_closer(entry);

  EXPECT_EQ(
      net::ERR_IO_PENDING,
      entry->WriteData(1, 0, buffer1.get(), kSize1, cb.callback(), false));
  EXPECT_EQ(kSize1, cb.GetResult(net::ERR_IO_PENDING));

  entry->Doom();
  entry->Doom();

  // This Read must not be optimistic, since we don't support that yet.
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->ReadData(1, 0, buffer1_read.get(), kSize1, cb.callback()));
  EXPECT_EQ(kSize1, cb.GetResult(net::ERR_IO_PENDING));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer1_read->data(), kSize1));

  entry->Doom();
}

// Confirm that IO buffers are not referenced by the Simple Cache after a write
// completes.
TEST_F(DiskCacheEntryTest, SimpleCacheOptimisticWriteReleases) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";

  // First, an optimistic create.
  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  ASSERT_TRUE(entry);
  ScopedEntryPtr entry_closer(entry);

  const int kWriteSize = 512;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kWriteSize);
  EXPECT_TRUE(buffer1->HasOneRef());
  CacheTestFillBuffer(buffer1->data(), kWriteSize, false);

  // An optimistic write happens only when there is an empty queue of pending
  // operations. To ensure the queue is empty, we issue a write and wait until
  // it completes.
  EXPECT_EQ(kWriteSize,
            WriteData(entry, 1, 0, buffer1.get(), kWriteSize, false));
  EXPECT_TRUE(buffer1->HasOneRef());

  // Finally, we should perform an optimistic write and confirm that all
  // references to the IO buffer have been released.
  EXPECT_EQ(kWriteSize, entry->WriteData(1, 0, buffer1.get(), kWriteSize,
                                         net::CompletionOnceCallback(), false));
  EXPECT_TRUE(buffer1->HasOneRef());
}

TEST_F(DiskCacheEntryTest, SimpleCacheCreateDoomRace) {
  // Test sequence:
  // Create, Doom, Write, Close, Check files are not on disk anymore.
  SetSimpleCacheMode();
  InitCache();
  const char key[] = "the first key";

  net::TestCompletionCallback cb;
  const int kSize1 = 10;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);

  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  EXPECT_NE(nullptr, entry);

  EXPECT_THAT(cache_->DoomEntry(key, net::HIGHEST, cb.callback()),
              IsError(net::ERR_IO_PENDING));
  EXPECT_THAT(cb.GetResult(net::ERR_IO_PENDING), IsOk());

  EXPECT_EQ(
      kSize1,
      entry->WriteData(0, 0, buffer1.get(), kSize1, cb.callback(), false));

  entry->Close();

  // Finish running the pending tasks so that we fully complete the close
  // operation and destroy the entry object.
  base::RunLoop().RunUntilIdle();

  for (int i = 0; i < disk_cache::kSimpleEntryNormalFileCount; ++i) {
    base::FilePath entry_file_path = cache_path_.AppendASCII(
        disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, i));
    base::File::Info info;
    EXPECT_FALSE(base::GetFileInfo(entry_file_path, &info));
  }
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomCreateRace) {
  // This test runs as APP_CACHE to make operations more synchronous. Test
  // sequence:
  // Create, Doom, Create.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  InitCache();
  const char key[] = "the first key";

  TestEntryResultCompletionCallback create_callback;

  EntryResult result1 = create_callback.GetResult(
      cache_->CreateEntry(key, net::HIGHEST, create_callback.callback()));
  ASSERT_EQ(net::OK, result1.net_error());
  disk_cache::Entry* entry1 = result1.ReleaseEntry();
  ScopedEntryPtr entry1_closer(entry1);
  EXPECT_NE(nullptr, entry1);

  net::TestCompletionCallback doom_callback;
  EXPECT_EQ(net::ERR_IO_PENDING,
            cache_->DoomEntry(key, net::HIGHEST, doom_callback.callback()));

  EntryResult result2 = create_callback.GetResult(
      cache_->CreateEntry(key, net::HIGHEST, create_callback.callback()));
  ASSERT_EQ(net::OK, result2.net_error());
  disk_cache::Entry* entry2 = result2.ReleaseEntry();
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_THAT(doom_callback.GetResult(net::ERR_IO_PENDING), IsOk());
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomCreateOptimistic) {
  // Test that we optimize the doom -> create sequence when optimistic ops
  // are on.
  SetSimpleCacheMode();
  InitCache();
  const char kKey[] = "the key";

  // Create entry and initiate its Doom.
  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry1), IsOk());
  ASSERT_TRUE(entry1 != nullptr);

  net::TestCompletionCallback doom_callback;
  cache_->DoomEntry(kKey, net::HIGHEST, doo
"""


```