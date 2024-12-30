Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/disk_cache/backend_unittest.cc`. This is part 2 of a 6-part request.

I need to:
1. **Identify the core functionalities** demonstrated in the code. These appear to be tests related to the disk cache backend.
2. **Check for JavaScript relevance**. Given the nature of disk caching in a browser, there might be indirect links, but I need to be specific.
3. **Identify logical inferences** within the tests and provide examples with inputs and outputs.
4. **Spot common user or programming errors** that the tests might be guarding against.
5. **Explain how a user action could lead to this code being executed** for debugging purposes.
6. **Summarize the overall function** of this specific code segment.

Looking at the code, the primary focus seems to be testing various aspects of the `DiskCacheBackend`. Specifically, it covers scenarios like:

- Handling pending I/O operations during shutdown.
- Handling pending create operations during shutdown.
- Handling pending doom (deletion) operations during shutdown.
- Dealing with truncated index files.
- Setting and enforcing cache size limits.
- Loading and accessing a large number of cache entries.
- Chaining of cache entries.
- Trimming the cache based on eviction policies.
- Handling valid and invalid cache entries (simulating crashes).
- Enumerating cache entries.
- Handling cache entry deletion during enumeration.
- Testing `DoomEntriesSince`.
- Testing `DoomAllEntries`.
- Testing eviction in in-memory sparse caches.

It's important to note that this is *test* code, so its function is to *verify* the behavior of the actual disk cache implementation.
这是 `net/disk_cache/backend_unittest.cc` 文件的一部分，主要功能是 **测试磁盘缓存后端 (DiskCacheBackend) 在各种场景下的行为和功能**。 这部分代码侧重于测试以下几个方面：

**核心功能测试点：**

* **后端关闭时的待处理 I/O 操作 (BackendShutdownWithPendingIO):** 测试在缓存后端关闭时，如果还有未完成的读写操作，后端是否能正确处理，避免崩溃或数据丢失。
* **后端关闭时的待处理创建操作 (BackendShutdownWithPendingCreate):** 测试在缓存后端关闭时，如果还有正在创建但未完成的缓存条目，后端是否能正确处理。
* **后端关闭时的待处理删除操作 (BackendShutdownWithPendingDoom):** 测试在缓存后端关闭时，如果还有正在删除但未完成的缓存条目，后端是否能正确处理。
* **处理截断的索引文件 (TruncatedIndex):** 测试当磁盘缓存的索引文件损坏或截断时，后端是否能检测到并做出合适的处理（通常是创建新的缓存）。
* **设置缓存大小 (BackendSetSize):** 测试设置缓存最大容量的功能是否正常工作，以及当写入的数据超过限制时，缓存的行为是否符合预期。
* **加载大量缓存条目 (BackendLoad):** 测试后端加载大量缓存条目的性能和稳定性。
* **缓存条目的链接 (BackendChain):** 测试缓存内部如何链接不同的缓存条目。
* **新的驱逐策略下的缓存修剪 (NewEvictionTrim):** 测试新的缓存驱逐算法在空间不足时如何选择要删除的缓存条目。
* **处理有效的缓存条目 (BackendValidEntry):** 测试在正常写入数据并重启后，缓存后端是否能正确读取之前写入的有效数据。
* **处理无效的缓存条目 (BackendInvalidEntry, BackendInvalidEntryRead, BackendInvalidEntryWithLoad, BackendTrimInvalidEntry, BackendTrimInvalidEntry2):** 通过模拟崩溃等情况，测试缓存后端如何处理损坏或不完整的缓存条目，例如在写入过程中崩溃或读取后崩溃。
* **缓存条目的枚举 (BackendEnumerations, BackendEnumerations2):** 测试缓存后端提供的迭代器功能，用于遍历缓存中的所有条目。
* **在枚举过程中删除缓存条目 (BackendDoomMidEnumeration):** 测试在正在遍历缓存条目时删除其中一个条目，迭代器是否能正常工作，避免崩溃。
* **根据时间删除缓存条目 (BackendDoomRecent):** 测试根据时间戳删除一定时间后的缓存条目的功能。
* **处理稀疏缓存 (MemoryOnlyDoomEntriesSinceSparse, DoomEntriesSinceSparse, MemoryOnlyDoomAllSparse, DoomAllSparse, InMemorySparseEvict):** 测试针对稀疏缓存（可能只存储部分数据）的特定操作，例如删除操作。
* **修复枚举器 (BackendFixEnumerators):** 测试在迭代器存在的情况下，如果缓存条目被修改或删除，迭代器是否能保持稳定，避免崩溃。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript 代码，但它所测试的磁盘缓存功能是浏览器核心功能的一部分，对 JavaScript 的执行和性能有重要影响。

* **资源缓存:** JavaScript 代码在执行过程中可能会请求网络资源（例如图片、CSS、JS 文件）。这些资源会被缓存到磁盘，下次加载时可以从缓存中直接读取，加快页面加载速度。这段代码测试的正是这个缓存功能的健壮性。
* **Service Worker:**  Service Worker 是一种可以在后台运行的 JavaScript 脚本，它可以拦截网络请求并提供缓存的响应。Service Worker 通常会使用浏览器提供的 Cache API，而 Cache API 的底层实现可能就依赖于类似的磁盘缓存机制。这段代码测试的磁盘缓存功能的稳定性直接影响 Service Worker 的可靠性。

**举例说明（假设输入与输出）：**

**场景：`BackendShutdownWithPendingIO(false)` 测试**

* **假设输入：**
    1. 启动浏览器，访问一个需要从网络加载资源的网页。
    2. 浏览器开始将资源写入磁盘缓存。
    3. 在写入操作尚未完成时，用户关闭浏览器。
* **预期输出：**
    1. 浏览器能够安全地关闭，不会因为未完成的缓存写入操作而崩溃。
    2. 下次启动浏览器并访问相同的网页时，之前未完成的写入操作会被妥善处理（可能被丢弃或稍后重试），不会导致缓存损坏。

**场景：`BackendSetSize()` 测试**

* **假设输入：**
    1. 设置磁盘缓存的最大容量为 64KB。
    2. 尝试缓存一个 7KB 的文件。
    3. 尝试缓存一个 14KB 的文件。
* **预期输出：**
    1. 第一个 7KB 的文件能够成功缓存。
    2. 第二个 14KB 的文件由于超过剩余容量而无法完全缓存（可能写入失败或部分写入）。

**用户或编程常见的使用错误：**

* **程序意外崩溃导致缓存文件损坏：**  例如，在写入缓存文件的过程中，程序突然崩溃，可能导致缓存索引文件或数据文件不完整，这段代码中的 `BackendInvalidEntry` 等测试就是在模拟这种情况。
* **磁盘空间不足导致缓存写入失败：**  用户磁盘空间不足时，尝试缓存新内容可能会失败，这段代码中的 `BackendSetSize` 测试了缓存容量限制相关的逻辑。
* **并发访问缓存导致数据竞争：**  在多线程或多进程环境下，如果同时读写同一个缓存文件，可能导致数据不一致，虽然这段代码主要是单元测试，但其测试的逻辑也间接保证了在并发情况下的稳定性。

**用户操作如何一步步的到达这里（作为调试线索）：**

当开发者在 Chromium 网络栈中发现磁盘缓存相关的 bug 或需要调试磁盘缓存的行为时，可能会运行这些单元测试。

1. **开发者修改了磁盘缓存相关的代码。**
2. **为了验证修改的正确性或者排查潜在的问题，开发者会运行相关的单元测试。**  通常会运行整个 `backend_unittest.cc` 文件，或者针对特定的测试用例运行。
3. **运行测试的过程中，如果某个测试用例失败，开发者会查看失败的日志和断言信息，定位到具体的代码行。**
4. **开发者可能会使用调试器（例如 gdb 或 lldb）来单步执行测试代码和被测试的缓存后端代码，查看变量的值和程序执行流程，从而理解问题发生的原因。**
5. **例如，如果 `BackendShutdownWithPendingIO` 测试失败，可能意味着在缓存后端关闭时，没有正确处理未完成的 I/O 操作，开发者会深入研究 `DiskCacheBackend` 的析构函数和相关的 I/O 管理逻辑。**

**功能归纳 (第2部分):**

这段代码主要功能是 **针对 Chromium 磁盘缓存后端的各种核心功能和异常情况进行全面的单元测试**，包括后端生命周期管理（启动、关闭）、缓存容量限制、数据读写、数据完整性、缓存条目管理（创建、删除、枚举）以及在高并发或异常情况下的鲁棒性。 通过这些测试，可以确保磁盘缓存后端在各种场景下都能正确、稳定地运行，从而保障浏览器的性能和用户体验。

Prompt: 
```
这是目录为net/disk_cache/backend_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
SERT_TRUE(CleanupCacheDir());
  SetNewEviction();  // Match the expected behavior for integrity verification.
  UseCurrentThread();

  CreateBackend(disk_cache::kNoBuffering);
  int rv = GeneratePendingIO(&cb);

  // cache_ has a pending operation, and backend_rv.backend will go away.
  backend_rv.backend.reset();

  if (rv == net::ERR_IO_PENDING)
    EXPECT_FALSE(cb.have_result());

  disk_cache::FlushCacheThreadForTesting();
  base::RunLoop().RunUntilIdle();

  // Wait for the actual operation to complete, or we'll keep a file handle that
  // may cause issues later.
  rv = cb.GetResult(rv);
}
#endif

// Tests that we deal with background-thread pending operations.
void DiskCacheBackendTest::BackendShutdownWithPendingIO(bool fast) {
  TestEntryResultCompletionCallback cb;

  {
    ASSERT_TRUE(CleanupCacheDir());

    uint32_t flags = disk_cache::kNoBuffering;
    if (!fast)
      flags |= disk_cache::kNoRandom;

    CreateBackend(flags);

    EntryResult result =
        cache_->CreateEntry("some key", net::HIGHEST, cb.callback());
    result = cb.GetResult(std::move(result));
    ASSERT_THAT(result.net_error(), IsOk());

    result.ReleaseEntry()->Close();

    // The cache destructor will see one pending operation here.
    ResetCaches();
  }

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(cb.have_result());
}

TEST_F(DiskCacheBackendTest, ShutdownWithPendingIO) {
  BackendShutdownWithPendingIO(false);
}

#if !defined(LEAK_SANITIZER)
// We'll be leaking from this test.
TEST_F(DiskCacheBackendTest, ShutdownWithPendingIO_Fast) {
  // The integrity test sets kNoRandom so there's a version mismatch if we don't
  // force new eviction.
  SetNewEviction();
  BackendShutdownWithPendingIO(true);
}
#endif

// Tests that we deal with create-type pending operations.
void DiskCacheBackendTest::BackendShutdownWithPendingCreate(bool fast) {
  TestEntryResultCompletionCallback cb;

  {
    ASSERT_TRUE(CleanupCacheDir());

    disk_cache::BackendFlags flags =
        fast ? disk_cache::kNone : disk_cache::kNoRandom;
    CreateBackend(flags);

    EntryResult result =
        cache_->CreateEntry("some key", net::HIGHEST, cb.callback());
    ASSERT_THAT(result.net_error(), IsError(net::ERR_IO_PENDING));

    ResetCaches();
    EXPECT_FALSE(cb.have_result());
  }

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(cb.have_result());
}

TEST_F(DiskCacheBackendTest, ShutdownWithPendingCreate) {
  BackendShutdownWithPendingCreate(false);
}

#if !defined(LEAK_SANITIZER)
// We'll be leaking an entry from this test.
TEST_F(DiskCacheBackendTest, ShutdownWithPendingCreate_Fast) {
  // The integrity test sets kNoRandom so there's a version mismatch if we don't
  // force new eviction.
  SetNewEviction();
  BackendShutdownWithPendingCreate(true);
}
#endif

void DiskCacheBackendTest::BackendShutdownWithPendingDoom() {
  net::TestCompletionCallback cb;
  {
    ASSERT_TRUE(CleanupCacheDir());

    disk_cache::BackendFlags flags = disk_cache::kNoRandom;
    CreateBackend(flags);

    TestEntryResultCompletionCallback cb2;
    EntryResult result =
        cache_->CreateEntry("some key", net::HIGHEST, cb2.callback());
    result = cb2.GetResult(std::move(result));
    ASSERT_THAT(result.net_error(), IsOk());
    result.ReleaseEntry()->Close();

    int rv = cache_->DoomEntry("some key", net::HIGHEST, cb.callback());
    ASSERT_THAT(rv, IsError(net::ERR_IO_PENDING));

    ResetCaches();
    EXPECT_FALSE(cb.have_result());
  }

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(cb.have_result());
}

TEST_F(DiskCacheBackendTest, ShutdownWithPendingDoom) {
  BackendShutdownWithPendingDoom();
}

// Disabled on android since this test requires cache creator to create
// blockfile caches.
#if !BUILDFLAG(IS_ANDROID)
TEST_F(DiskCacheTest, TruncatedIndex) {
  ASSERT_TRUE(CleanupCacheDir());
  base::FilePath index = cache_path_.AppendASCII("index");
  ASSERT_TRUE(base::WriteFile(index, "hello"));

  TestBackendResultCompletionCallback cb;

  disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
      net::DISK_CACHE, net::CACHE_BACKEND_BLOCKFILE,
      /*file_operations=*/nullptr, cache_path_, 0,
      disk_cache::ResetHandling::kNeverReset, /*net_log=*/nullptr,
      cb.callback());
  rv = cb.GetResult(std::move(rv));
  ASSERT_NE(net::OK, rv.net_error);
  ASSERT_FALSE(rv.backend);
}
#endif

void DiskCacheBackendTest::BackendSetSize() {
  const int cache_size = 0x10000;  // 64 kB
  SetMaxSize(cache_size);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(cache_size);
  memset(buffer->data(), 0, cache_size);
  EXPECT_EQ(cache_size / 10,
            WriteData(entry, 0, 0, buffer.get(), cache_size / 10, false))
      << "normal file";

  EXPECT_EQ(net::ERR_FAILED,
            WriteData(entry, 1, 0, buffer.get(), cache_size / 5, false))
      << "file size above the limit";
  entry->Close();

  // By doubling the total size, we make this file cacheable.
  ResetCaches();
  SetMaxSize(cache_size * 2);
  InitCache();
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  EXPECT_EQ(cache_size / 5,
            WriteData(entry, 1, 0, buffer.get(), cache_size / 5, false));
  entry->Close();

  // Let's fill up the cache to about 95%, in 5% chunks.
  ResetCaches();
  SetMaxSize(cache_size);
  InitCache();

  for (int i = 0; i < (95 / 5); ++i) {
    ASSERT_THAT(CreateEntry(base::NumberToString(i), &entry), IsOk());

    EXPECT_EQ(cache_size / 20,
              WriteData(entry, 0, 0, buffer.get(), cache_size / 20, false));
    entry->Close();
  }

  ASSERT_THAT(CreateEntry(second, &entry), IsOk());
  EXPECT_EQ(cache_size / 10,
            WriteData(entry, 0, 0, buffer.get(), cache_size / 10, false));

  disk_cache::Entry* entry2;
  ASSERT_THAT(CreateEntry("an extra key", &entry2), IsOk());
  EXPECT_EQ(cache_size / 10,
            WriteData(entry2, 0, 0, buffer.get(), cache_size / 10, false));
  entry2->Close();  // This will trigger the cache trim.

  // Entry "0" is old and should have been evicted.
  EXPECT_NE(net::OK, OpenEntry("0", &entry2));

  FlushQueueForTest();  // Make sure that we are done trimming the cache.
  FlushQueueForTest();  // We may have posted two tasks to evict stuff.

  // "second" is fairly new so should still be around.
  entry->Close();
  ASSERT_THAT(OpenEntry(second, &entry), IsOk());
  EXPECT_EQ(cache_size / 10, entry->GetDataSize(0));
  entry->Close();
}

TEST_F(DiskCacheBackendTest, SetSize) {
  BackendSetSize();
}

TEST_F(DiskCacheBackendTest, NewEvictionSetSize) {
  SetNewEviction();
  BackendSetSize();
}

TEST_F(DiskCacheBackendTest, MemoryOnlySetSize) {
  SetMemoryOnlyMode();
  BackendSetSize();
}

void DiskCacheBackendTest::BackendLoad() {
  InitCache();
  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  disk_cache::Entry* entries[kLargeNumEntries];
  for (auto*& entry : entries) {
    std::string key = GenerateKey(true);
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  }
  EXPECT_EQ(kLargeNumEntries, cache_->GetEntryCount());

  for (int i = 0; i < kLargeNumEntries; i++) {
    int source1 = rand() % kLargeNumEntries;
    int source2 = rand() % kLargeNumEntries;
    disk_cache::Entry* temp = entries[source1];
    entries[source1] = entries[source2];
    entries[source2] = temp;
  }

  for (auto* entry : entries) {
    disk_cache::Entry* new_entry;
    ASSERT_THAT(OpenEntry(entry->GetKey(), &new_entry), IsOk());
    EXPECT_TRUE(new_entry == entry);
    new_entry->Close();
    entry->Doom();
    entry->Close();
  }
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, Load) {
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, NewEvictionLoad) {
  SetNewEviction();
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyLoad) {
  SetMaxSize(0x100000);
  SetMemoryOnlyMode();
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, AppCacheLoad) {
  SetCacheType(net::APP_CACHE);
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  BackendLoad();
}

TEST_F(DiskCacheBackendTest, ShaderCacheLoad) {
  SetCacheType(net::SHADER_CACHE);
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  BackendLoad();
}

// Tests the chaining of an entry to the current head.
void DiskCacheBackendTest::BackendChain() {
  SetMask(0x1);        // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  InitCache();

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("The first key", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("The Second key", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, Chain) {
  BackendChain();
}

TEST_F(DiskCacheBackendTest, NewEvictionChain) {
  SetNewEviction();
  BackendChain();
}

TEST_F(DiskCacheBackendTest, AppCacheChain) {
  SetCacheType(net::APP_CACHE);
  BackendChain();
}

TEST_F(DiskCacheBackendTest, ShaderCacheChain) {
  SetCacheType(net::SHADER_CACHE);
  BackendChain();
}

TEST_F(DiskCacheBackendTest, NewEvictionTrim) {
  SetNewEviction();
  InitCache();

  disk_cache::Entry* entry;
  for (int i = 0; i < 100; i++) {
    std::string name(base::StringPrintf("Key %d", i));
    ASSERT_THAT(CreateEntry(name, &entry), IsOk());
    entry->Close();
    if (i < 90) {
      // Entries 0 to 89 are in list 1; 90 to 99 are in list 0.
      ASSERT_THAT(OpenEntry(name, &entry), IsOk());
      entry->Close();
    }
  }

  // The first eviction must come from list 1 (10% limit), the second must come
  // from list 0.
  TrimForTest(false);
  EXPECT_NE(net::OK, OpenEntry("Key 0", &entry));
  TrimForTest(false);
  EXPECT_NE(net::OK, OpenEntry("Key 90", &entry));

  // Double check that we still have the list tails.
  ASSERT_THAT(OpenEntry("Key 1", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry("Key 91", &entry), IsOk());
  entry->Close();
}

// Before looking for invalid entries, let's check a valid entry.
void DiskCacheBackendTest::BackendValidEntry() {
  InitCache();

  std::string key("Some key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 50;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buffer1->data(), 0, kSize);
  base::strlcpy(buffer1->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer1.get(), kSize, false));
  entry->Close();
  SimulateCrash();

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buffer2->data(), 0, kSize);
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer2.get(), kSize));
  entry->Close();
  EXPECT_STREQ(buffer1->data(), buffer2->data());
}

TEST_F(DiskCacheBackendTest, ValidEntry) {
  BackendValidEntry();
}

TEST_F(DiskCacheBackendTest, NewEvictionValidEntry) {
  SetNewEviction();
  BackendValidEntry();
}

// The same logic of the previous test (ValidEntry), but this time force the
// entry to be invalid, simulating a crash in the middle.
// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendInvalidEntry() {
  InitCache();

  std::string key("Some key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 50;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buffer->data(), 0, kSize);
  base::strlcpy(buffer->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  SimulateCrash();

  EXPECT_NE(net::OK, OpenEntry(key, &entry));
  EXPECT_EQ(0, cache_->GetEntryCount());
}

#if !defined(LEAK_SANITIZER)
// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, InvalidEntry) {
  BackendInvalidEntry();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry) {
  SetNewEviction();
  BackendInvalidEntry();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, AppCacheInvalidEntry) {
  SetCacheType(net::APP_CACHE);
  BackendInvalidEntry();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, ShaderCacheInvalidEntry) {
  SetCacheType(net::SHADER_CACHE);
  BackendInvalidEntry();
}

// Almost the same test, but this time crash the cache after reading an entry.
// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendInvalidEntryRead() {
  InitCache();

  std::string key("Some key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 50;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buffer->data(), 0, kSize);
  base::strlcpy(buffer->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer.get(), kSize));

  SimulateCrash();

  if (type_ == net::APP_CACHE) {
    // Reading an entry and crashing should not make it dirty.
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    EXPECT_EQ(1, cache_->GetEntryCount());
    entry->Close();
  } else {
    EXPECT_NE(net::OK, OpenEntry(key, &entry));
    EXPECT_EQ(0, cache_->GetEntryCount());
  }
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, InvalidEntryRead) {
  BackendInvalidEntryRead();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntryRead) {
  SetNewEviction();
  BackendInvalidEntryRead();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, AppCacheInvalidEntryRead) {
  SetCacheType(net::APP_CACHE);
  BackendInvalidEntryRead();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, ShaderCacheInvalidEntryRead) {
  SetCacheType(net::SHADER_CACHE);
  BackendInvalidEntryRead();
}

// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendInvalidEntryWithLoad() {
  // Work with a tiny index table (16 entries)
  SetMask(0xf);
  SetMaxSize(0x100000);
  InitCache();

  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  const int kNumEntries = 100;
  disk_cache::Entry* entries[kNumEntries];
  for (auto*& entry : entries) {
    std::string key = GenerateKey(true);
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  }
  EXPECT_EQ(kNumEntries, cache_->GetEntryCount());

  for (int i = 0; i < kNumEntries; i++) {
    int source1 = rand() % kNumEntries;
    int source2 = rand() % kNumEntries;
    disk_cache::Entry* temp = entries[source1];
    entries[source1] = entries[source2];
    entries[source2] = temp;
  }

  std::string keys[kNumEntries];
  for (int i = 0; i < kNumEntries; i++) {
    keys[i] = entries[i]->GetKey();
    if (i < kNumEntries / 2)
      entries[i]->Close();
  }

  SimulateCrash();

  for (int i = kNumEntries / 2; i < kNumEntries; i++) {
    disk_cache::Entry* entry;
    EXPECT_NE(net::OK, OpenEntry(keys[i], &entry));
  }

  for (int i = 0; i < kNumEntries / 2; i++) {
    disk_cache::Entry* entry;
    ASSERT_THAT(OpenEntry(keys[i], &entry), IsOk());
    entry->Close();
  }

  EXPECT_EQ(kNumEntries / 2, cache_->GetEntryCount());
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, InvalidEntryWithLoad) {
  BackendInvalidEntryWithLoad();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntryWithLoad) {
  SetNewEviction();
  BackendInvalidEntryWithLoad();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, AppCacheInvalidEntryWithLoad) {
  SetCacheType(net::APP_CACHE);
  BackendInvalidEntryWithLoad();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, ShaderCacheInvalidEntryWithLoad) {
  SetCacheType(net::SHADER_CACHE);
  BackendInvalidEntryWithLoad();
}

// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendTrimInvalidEntry() {
  const int kSize = 0x3000;  // 12 kB
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buffer->data(), 0, kSize);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));

  // Simulate a crash.
  SimulateCrash();

  ASSERT_THAT(CreateEntry(second, &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));

  EXPECT_EQ(2, cache_->GetEntryCount());
  cache_impl_->SetMaxSize(kSize);
  entry->Close();  // Trim the cache.
  FlushQueueForTest();

  // If we evicted the entry in less than 20mS, we have one entry in the cache;
  // if it took more than that, we posted a task and we'll delete the second
  // entry too.
  base::RunLoop().RunUntilIdle();

  // This may be not thread-safe in general, but for now it's OK so add some
  // ThreadSanitizer annotations to ignore data races on cache_.
  // See http://crbug.com/55970
  ABSL_ANNOTATE_IGNORE_READS_BEGIN();
  EXPECT_GE(1, cache_->GetEntryCount());
  ABSL_ANNOTATE_IGNORE_READS_END();

  EXPECT_NE(net::OK, OpenEntry(first, &entry));
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, TrimInvalidEntry) {
  BackendTrimInvalidEntry();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionTrimInvalidEntry) {
  SetNewEviction();
  BackendTrimInvalidEntry();
}

// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendTrimInvalidEntry2() {
  SetMask(0xf);  // 16-entry table.

  const int kSize = 0x3000;  // 12 kB
  SetMaxSize(kSize * 40);
  InitCache();

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buffer->data(), 0, kSize);
  disk_cache::Entry* entry;

  // Writing 32 entries to this cache chains most of them.
  for (int i = 0; i < 32; i++) {
    std::string key(base::StringPrintf("some key %d", i));
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
    entry->Close();
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    // Note that we are not closing the entries.
  }

  // Simulate a crash.
  SimulateCrash();

  ASSERT_THAT(CreateEntry("Something else", &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));

  FlushQueueForTest();
  EXPECT_EQ(33, cache_->GetEntryCount());
  cache_impl_->SetMaxSize(kSize);

  // For the new eviction code, all corrupt entries are on the second list so
  // they are not going away that easy.
  if (new_eviction_) {
    EXPECT_THAT(DoomAllEntries(), IsOk());
  }

  entry->Close();  // Trim the cache.
  FlushQueueForTest();

  // We may abort the eviction before cleaning up everything.
  base::RunLoop().RunUntilIdle();
  FlushQueueForTest();
  // If it's not clear enough: we may still have eviction tasks running at this
  // time, so the number of entries is changing while we read it.
  ABSL_ANNOTATE_IGNORE_READS_AND_WRITES_BEGIN();
  EXPECT_GE(30, cache_->GetEntryCount());
  ABSL_ANNOTATE_IGNORE_READS_AND_WRITES_END();

  // For extra messiness, the integrity check for the cache can actually cause
  // evictions if it's over-capacity, which would race with above. So change the
  // size we pass to CheckCacheIntegrity (but don't mess with existing backend's
  // state.
  size_ = 0;
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, TrimInvalidEntry2) {
  BackendTrimInvalidEntry2();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionTrimInvalidEntry2) {
  SetNewEviction();
  BackendTrimInvalidEntry2();
}
#endif  // !defined(LEAK_SANITIZER)

void DiskCacheBackendTest::BackendEnumerations() {
  InitCache();
  Time initial = Time::Now();

  const int kNumEntries = 100;
  for (int i = 0; i < kNumEntries; i++) {
    std::string key = GenerateKey(true);
    disk_cache::Entry* entry;
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }
  EXPECT_EQ(kNumEntries, cache_->GetEntryCount());
  Time final = Time::Now();

  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  Time last_modified[kNumEntries];
  Time last_used[kNumEntries];
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(nullptr != entry);
    if (count < kNumEntries) {
      last_modified[count] = entry->GetLastModified();
      last_used[count] = entry->GetLastUsed();
      EXPECT_TRUE(initial <= last_modified[count]);
      EXPECT_TRUE(final >= last_modified[count]);
    }

    entry->Close();
    count++;
  };
  EXPECT_EQ(kNumEntries, count);

  iter = CreateIterator();
  count = 0;
  // The previous enumeration should not have changed the timestamps.
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(nullptr != entry);
    if (count < kNumEntries) {
      EXPECT_TRUE(last_modified[count] == entry->GetLastModified());
      EXPECT_TRUE(last_used[count] == entry->GetLastUsed());
    }
    entry->Close();
    count++;
  };
  EXPECT_EQ(kNumEntries, count);
}

TEST_F(DiskCacheBackendTest, Enumerations) {
  BackendEnumerations();
}

TEST_F(DiskCacheBackendTest, NewEvictionEnumerations) {
  SetNewEviction();
  BackendEnumerations();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyEnumerations) {
  SetMemoryOnlyMode();
  BackendEnumerations();
}

TEST_F(DiskCacheBackendTest, ShaderCacheEnumerations) {
  SetCacheType(net::SHADER_CACHE);
  BackendEnumerations();
}

TEST_F(DiskCacheBackendTest, AppCacheEnumerations) {
  SetCacheType(net::APP_CACHE);
  BackendEnumerations();
}

// Verifies enumerations while entries are open.
void DiskCacheBackendTest::BackendEnumerations2() {
  InitCache();
  const std::string first("first");
  const std::string second("second");
  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(CreateEntry(first, &entry1), IsOk());
  entry1->Close();
  ASSERT_THAT(CreateEntry(second, &entry2), IsOk());
  entry2->Close();
  FlushQueueForTest();

  // Make sure that the timestamp is not the same.
  AddDelay();
  ASSERT_THAT(OpenEntry(second, &entry1), IsOk());
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry2), IsOk());
  EXPECT_EQ(entry2->GetKey(), second);

  // Two entries and the iterator pointing at "first".
  entry1->Close();
  entry2->Close();

  // The iterator should still be valid, so we should not crash.
  ASSERT_THAT(iter->OpenNextEntry(&entry2), IsOk());
  EXPECT_EQ(entry2->GetKey(), first);
  entry2->Close();
  iter = CreateIterator();

  // Modify the oldest entry and get the newest element.
  ASSERT_THAT(OpenEntry(first, &entry1), IsOk());
  EXPECT_EQ(0, WriteData(entry1, 0, 200, nullptr, 0, false));
  ASSERT_THAT(iter->OpenNextEntry(&entry2), IsOk());
  if (type_ == net::APP_CACHE) {
    // The list is not updated.
    EXPECT_EQ(entry2->GetKey(), second);
  } else {
    EXPECT_EQ(entry2->GetKey(), first);
  }

  entry1->Close();
  entry2->Close();
}

TEST_F(DiskCacheBackendTest, Enumerations2) {
  BackendEnumerations2();
}

TEST_F(DiskCacheBackendTest, NewEvictionEnumerations2) {
  SetNewEviction();
  BackendEnumerations2();
}

TEST_F(DiskCacheBackendTest, AppCacheEnumerations2) {
  SetCacheType(net::APP_CACHE);
  BackendEnumerations2();
}

TEST_F(DiskCacheBackendTest, ShaderCacheEnumerations2) {
  SetCacheType(net::SHADER_CACHE);
  BackendEnumerations2();
}

void DiskCacheBackendTest::BackendDoomMidEnumeration() {
  InitCache();

  const int kNumEntries = 100;
  std::set<std::string> keys;
  for (int i = 0; i < kNumEntries; i++) {
    std::string key = GenerateKey(true);
    keys.insert(key);
    disk_cache::Entry* entry;
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }

  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    if (count == 0) {
      // Delete a random entry from the cache while in the midst of iteration.
      auto key_to_doom = keys.begin();
      while (*key_to_doom == entry->GetKey())
        key_to_doom++;
      ASSERT_THAT(DoomEntry(*key_to_doom), IsOk());
      ASSERT_EQ(1u, keys.erase(*key_to_doom));
    }
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(1u, keys.erase(entry->GetKey()));
    entry->Close();
    count++;
  };

  EXPECT_EQ(kNumEntries - 1, cache_->GetEntryCount());
  EXPECT_EQ(0u, keys.size());
}

TEST_F(DiskCacheBackendTest, DoomEnumerations) {
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomEnumerations) {
  SetNewEviction();
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomEnumerations) {
  SetMemoryOnlyMode();
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, ShaderCacheDoomEnumerations) {
  SetCacheType(net::SHADER_CACHE);
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, AppCacheDoomEnumerations) {
  SetCacheType(net::APP_CACHE);
  BackendDoomMidEnumeration();
}

TEST_F(DiskCacheBackendTest, SimpleDoomEnumerations) {
  SetSimpleCacheMode();
  BackendDoomMidEnumeration();
}

// Verify that ReadData calls do not update the LRU cache
// when using the SHADER_CACHE type.
TEST_F(DiskCacheBackendTest, ShaderCacheEnumerationReadData) {
  SetCacheType(net::SHADER_CACHE);
  InitCache();
  const std::string first("first");
  const std::string second("second");
  disk_cache::Entry *entry1, *entry2;
  const int kSize = 50;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);

  ASSERT_THAT(CreateEntry(first, &entry1), IsOk());
  memset(buffer1->data(), 0, kSize);
  base::strlcpy(buffer1->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry1, 0, 0, buffer1.get(), kSize, false));

  ASSERT_THAT(CreateEntry(second, &entry2), IsOk());
  entry2->Close();

  FlushQueueForTest();

  // Make sure that the timestamp is not the same.
  AddDelay();

  // Read from the last item in the LRU.
  EXPECT_EQ(kSize, ReadData(entry1, 0, 0, buffer1.get(), kSize));
  entry1->Close();

  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry2), IsOk());
  EXPECT_EQ(entry2->GetKey(), second);
  entry2->Close();
}

#if !defined(LEAK_SANITIZER)
// Verify handling of invalid entries while doing enumerations.
// We'll be leaking memory from this test.
void DiskCacheBackendTest::BackendInvalidEntryEnumeration() {
  InitCache();

  std::string key("Some key");
  disk_cache::Entry *entry, *entry1, *entry2;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());

  const int kSize = 50;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  memset(buffer1->data(), 0, kSize);
  base::strlcpy(buffer1->data(), "And the data to save", kSize);
  EXPECT_EQ(kSize, WriteData(entry1, 0, 0, buffer1.get(), kSize, false));
  entry1->Close();
  ASSERT_THAT(OpenEntry(key, &entry1), IsOk());
  EXPECT_EQ(kSize, ReadData(entry1, 0, 0, buffer1.get(), kSize));

  std::string key2("Another key");
  ASSERT_THAT(CreateEntry(key2, &entry2), IsOk());
  entry2->Close();
  ASSERT_EQ(2, cache_->GetEntryCount());

  SimulateCrash();

  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(nullptr != entry);
    EXPECT_EQ(key2, entry->GetKey());
    entry->Close();
    count++;
  };
  EXPECT_EQ(1, count);
  EXPECT_EQ(1, cache_->GetEntryCount());
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, InvalidEntryEnumeration) {
  BackendInvalidEntryEnumeration();
}

// We'll be leaking memory from this test.
TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntryEnumeration) {
  SetNewEviction();
  BackendInvalidEntryEnumeration();
}
#endif  // !defined(LEAK_SANITIZER)

// Tests that if for some reason entries are modified close to existing cache
// iterators, we don't generate fatal errors or reset the cache.
void DiskCacheBackendTest::BackendFixEnumerators() {
  InitCache();

  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);

  const int kNumEntries = 10;
  for (int i = 0; i < kNumEntries; i++) {
    std::string key = GenerateKey(true);
    disk_cache::Entry* entry;
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    entry->Close();
  }
  EXPECT_EQ(kNumEntries, cache_->GetEntryCount());

  disk_cache::Entry *entry1, *entry2;
  std::unique_ptr<TestIterator> iter1 = CreateIterator(),
                                iter2 = CreateIterator();
  ASSERT_THAT(iter1->OpenNextEntry(&entry1), IsOk());
  ASSERT_TRUE(nullptr != entry1);
  entry1->Close();
  entry1 = nullptr;

  // Let's go to the middle of the list.
  for (int i = 0; i < kNumEntries / 2; i++) {
    if (entry1)
      entry1->Close();
    ASSERT_THAT(iter1->OpenNextEntry(&entry1), IsOk());
    ASSERT_TRUE(nullptr != entry1);

    ASSERT_THAT(iter2->OpenNextEntry(&entry2), IsOk());
    ASSERT_TRUE(nullptr != entry2);
    entry2->Close();
  }

  // Messing up with entry1 will modify entry2->next.
  entry1->Doom();
  ASSERT_THAT(iter2->OpenNextEntry(&entry2), IsOk());
  ASSERT_TRUE(nullptr != entry2);

  // The link entry2->entry1 should be broken.
  EXPECT_NE(entry2->GetKey(), entry1->GetKey());
  entry1->Close();
  entry2->Close();

  // And the second iterator should keep working.
  ASSERT_THAT(iter2->OpenNextEntry(&entry2), IsOk());
  ASSERT_TRUE(nullptr != entry2);
  entry2->Close();
}

TEST_F(DiskCacheBackendTest, FixEnumerators) {
  BackendFixEnumerators();
}

TEST_F(DiskCacheBackendTest, NewEvictionFixEnumerators) {
  SetNewEviction();
  BackendFixEnumerators();
}

void DiskCacheBackendTest::BackendDoomRecent() {
  InitCache();

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("first", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("second", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time middle = Time::Now();

  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("fourth", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time final = Time::Now();

  ASSERT_EQ(4, cache_->GetEntryCount());
  EXPECT_THAT(DoomEntriesSince(final), IsOk());
  ASSERT_EQ(4, cache_->GetEntryCount());

  EXPECT_THAT(DoomEntriesSince(middle), IsOk());
  ASSERT_EQ(2, cache_->GetEntryCount());

  ASSERT_THAT(OpenEntry("second", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, DoomRecent) {
  BackendDoomRecent();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomRecent) {
  SetNewEviction();
  BackendDoomRecent();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomRecent) {
  SetMemoryOnlyMode();
  BackendDoomRecent();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomEntriesSinceSparse) {
  SetMemoryOnlyMode();
  base::Time start;
  InitSparseCache(&start, nullptr);
  DoomEntriesSince(start);
  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DoomEntriesSinceSparse) {
  base::Time start;
  InitSparseCache(&start, nullptr);
  DoomEntriesSince(start);
  // NOTE: BackendImpl counts child entries in its GetEntryCount(), while
  // MemBackendImpl does not. Thats why expected value differs here from
  // MemoryOnlyDoomEntriesSinceSparse.
  EXPECT_EQ(3, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomAllSparse) {
  SetMemoryOnlyMode();
  InitSparseCache(nullptr, nullptr);
  EXPECT_THAT(DoomAllEntries(), IsOk());
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DoomAllSparse) {
  InitSparseCache(nullptr, nullptr);
  EXPECT_THAT(DoomAllEntries(), IsOk());
  EXPECT_EQ(0, cache_->GetEntryCount());
}

// This test is for https://crbug.com/827492.
TEST_F(DiskCacheBackendTest, InMemorySparseEvict) {
  const int kMaxSize = 512;

  SetMaxSize(kMaxSize);
  SetMemoryOnlyMode();
  InitCache();

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(64);
  CacheTestFillBuffer(buffer->data(), 64, false /* no_nulls */);

  std::vector<disk_cache::ScopedEntryPtr> entries;

  disk_cache::Entry* entry = nullptr;
  // Create a bunch of entries
  for (size_t i = 0; i < 14; i++) {
    std::string name = "http://www." + base::NumberToString(i) + ".com/";
    ASSERT_THAT(CreateEntry(name, &entry), IsOk());
    entries.push_back(disk_cache::ScopedEntryPtr(entry));
  }

  // Create several sparse entries and fill with enough data to
  // pass eviction threshold
  ASSERT_EQ(64, WriteSparseData(entries[0].get(), 0, buffer.get(), 64))
"""


```