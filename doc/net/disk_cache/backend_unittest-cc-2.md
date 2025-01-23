Response:
The user wants to understand the functionality of the provided C++ code snippet from `net/disk_cache/backend_unittest.cc`.

Here's a breakdown of the thought process to address the request:

1. **Identify the core purpose:** The file name `backend_unittest.cc` immediately suggests this code contains unit tests for the disk cache backend. The code consists of several `TEST_F` definitions, which are the standard way to define tests using Google Test.

2. **Analyze individual test cases:**  Go through each `TEST_F` and its associated `Backend...` method to understand the specific functionality being tested. Look for keywords and function names that indicate the action being performed (e.g., `Doom`, `CalculateSize`, `Recover`, `InvalidEntry`, `Disable`).

3. **Group related tests:** Notice patterns and group tests that cover similar functionalities. For example, multiple tests might deal with "Doom" operations or "CalculateSize" operations. This helps in summarizing the overall functionality.

4. **Look for variations within test groups:** Observe if tests have variations (e.g., with `NewEviction`, `MemoryOnly`, `SimpleCache`). These variations indicate different configurations or scenarios being tested.

5. **Identify assertions and expectations:** Pay close attention to `ASSERT_THAT`, `ASSERT_EQ`, `EXPECT_EQ`, etc. These statements define the expected behavior of the code under test. This helps in understanding what the test is verifying.

6. **Infer functionality from test names and actions:** Even without knowing the exact implementation of the disk cache, test names like `DoomBetween`, `CalculateSizeOfAllEntries`, `RecoverInsert`, and `InvalidEntry2` provide strong hints about the underlying functionalities being tested.

7. **Address specific request points:**
    * **Functionality:**  List the identified functionalities based on the test cases.
    * **Relationship with JavaScript:**  Consider if any tested functionality has a direct or indirect relationship with how a browser (which uses JavaScript) might interact with a disk cache. Think about caching web resources.
    * **Logical Reasoning (Input/Output):**  For some tests, especially those involving writing and reading data (though this snippet doesn't have many clear examples of that),  try to deduce the expected input and output based on the assertions. In this snippet, many tests focus on state transitions (e.g., number of entries) rather than data content.
    * **User/Programming Errors:**  Identify tests that seem to be designed to handle error conditions or corrupted cache states. These often indicate potential user or programming errors that the cache needs to gracefully handle.
    * **User Operation to Reach:** Consider how a user's actions in a browser might lead to these disk cache operations. Think about browsing history, opening multiple tabs, encountering network issues, etc.
    * **Part Summary:** Combine the identified functionalities into a concise summary for this specific part of the file.

8. **Handle the "Part 3 of 6" instruction:**  Keep in mind this is a part of a larger file. The summary should reflect the functionalities covered in this specific segment.

**Self-Correction/Refinement during the process:**

* Initially, one might focus too much on the low-level details of each line of code. The goal is to understand the *functionality being tested*, not necessarily the exact implementation within each test.
* When considering JavaScript interaction, avoid overthinking. Focus on the basic principles of web caching. JavaScript doesn't directly manipulate the disk cache backend, but it triggers requests that the browser's networking stack handles, potentially involving the cache.
*  For input/output, if the test primarily checks state changes (like entry counts), the "input" is the series of cache operations performed in the test, and the "output" is the asserted final state.

By following these steps, and continuously refining the understanding through analyzing the test cases and their assertions, we can arrive at a comprehensive and accurate summary of the code's functionality.
这是一个C++ Chromium网络栈中 `net/disk_cache/backend_unittest.cc` 文件的代码片段，它主要包含了一系列用于测试磁盘缓存后端功能的单元测试。这个代码片段集中在以下几个方面的测试：

**核心功能归纳：**

1. **稀疏数据写入测试 (Sparse Data Writing):** 测试向缓存条目中写入稀疏数据的能力，包括写入成功和失败的情况。
2. **条目删除测试 (Doom Between):** 测试在特定时间范围内删除缓存条目的功能，包括普通模式和内存模式下的测试。
3. **缓存大小计算测试 (Calculate Size):** 测试计算缓存中所有条目大小的功能，包括计算指定时间范围内的条目大小。涵盖了普通模式、内存模式和简单缓存模式。
4. **事务恢复测试 (Transaction Recovery):** 测试在缓存操作过程中发生异常后，缓存的恢复能力，包括插入和删除操作的恢复。
5. **异常条目处理测试 (Invalid Entry Handling):** 测试缓存后端处理各种损坏或不一致的缓存条目的能力，包括：
    * 遇到错误的版本信息。
    * 遇到损坏的条目数据或元数据。
    * 遇到循环引用的哈希冲突链。
    * 在枚举条目时检测到损坏的条目。
    * 在删除条目时遇到损坏的情况。
6. **缓存禁用测试 (Cache Disabling):** 测试在检测到严重错误（如LRU列表损坏）时禁用缓存的能力。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不包含 JavaScript 代码，但它测试的磁盘缓存功能是浏览器网络栈的核心组成部分，而浏览器需要缓存网页资源（如 HTML、CSS、JavaScript 文件、图片等）来提高加载速度和减少网络请求。

* **举例说明:** 当一个网页中的 JavaScript 代码发起一个网络请求去获取一个资源时（例如，使用 `fetch` API 或 `XMLHttpRequest`），浏览器会首先检查磁盘缓存中是否存在该资源的有效副本。如果存在，浏览器可以直接从缓存中读取，而无需再次从服务器下载。这段代码测试的正是磁盘缓存后端如何存储、检索和管理这些缓存的资源。

**逻辑推理 (假设输入与输出):**

由于这段代码主要是单元测试，我们关注的是每个测试用例的输入和预期输出。

* **`WriteSparseData` 测试:**
    * **假设输入:** 已经创建的缓存条目对象 (`entries[0]`, `entries[1]` 等), 写入偏移量 (例如 `10000`, `0`), 待写入的数据缓冲区 (`buffer.get()`), 写入数据长度 (例如 `4`, `63`, `64`)。
    * **预期输出:** 返回实际写入的字节数。如果写入失败，则返回错误码 (`net::ERR_FAILED`)。例如，向超出条目大小的位置写入会失败。

* **`DoomEntriesBetween` 测试:**
    * **假设输入:** 缓存初始化后的状态，以及两个时间点 `middle_start` 和 `middle_end`。
    * **预期输出:** 在 `middle_start` 和 `middle_end` 之间创建的条目会被删除，缓存条目数量会减少。

* **`CalculateSizeOfAllEntries` 测试:**
    * **假设输入:** 缓存中存在多个不同大小的条目。
    * **预期输出:** 返回缓存中所有条目（包括元数据）大小的总和。

* **`RecoverInsert` 测试:**
    * **假设输入:** 一个包含部分完成插入操作的缓存数据文件。
    * **预期输出:** 缓存能够成功加载并完成未完成的插入操作，达到预期的条目数量。

* **`InvalidEntry2` 测试:**
    * **假设输入:** 一个包含损坏条目的缓存数据文件。
    * **预期输出:** 尝试打开损坏的条目会失败，但不会导致程序崩溃。

**用户或编程常见的使用错误 (举例说明):**

这些测试实际上是在验证缓存后端如何处理各种可能出现的错误情况，这些错误可能是由编程错误或文件系统问题引起的，而不是直接由用户操作触发。

* **编程错误:**  一个编写缓存代码的开发者可能会错误地计算条目的大小，或者在写入数据时发生偏移量错误。`WriteSparseData` 的测试用例就覆盖了尝试写入超出条目大小的情况，这可能就是一个编程错误导致的。
* **文件系统问题:**  文件系统可能在缓存操作过程中损坏，导致缓存文件出现不一致。`InvalidEntry` 系列的测试就是在模拟这种情况，例如，缓存文件中的状态位被错误地设置。

**用户操作如何一步步到达这里 (作为调试线索):**

虽然用户不会直接与这些底层的缓存后端代码交互，但用户的操作会间接地触发这些代码的执行。以下是一些可能的步骤：

1. **用户在浏览器中输入 URL 并访问一个网站。**
2. **浏览器发起对网页资源（HTML、CSS、JavaScript、图片等）的 HTTP 请求。**
3. **网络栈检查磁盘缓存中是否已存在这些资源的有效副本。**
4. **如果缓存中没有，或者缓存已过期，浏览器会从服务器下载资源。**
5. **下载的资源会被写入到磁盘缓存中。这就是这段代码中测试的 `WriteSparseData` 和相关写入操作发挥作用的地方。**
6. **如果缓存空间不足，或者需要清理旧的缓存条目，就会触发删除操作，即 `DoomEntriesBetween` 测试所覆盖的功能。**
7. **当浏览器需要使用缓存的资源时，会从磁盘缓存中读取，涉及到缓存条目的检索。**
8. **如果缓存文件因为某些原因损坏，当浏览器尝试访问或管理这些损坏的条目时，就会触发 `InvalidEntry` 系列的测试场景。**

在调试过程中，如果用户遇到与缓存相关的错误（例如，网页资源无法加载，或者加载的是旧版本的资源），开发者可能会查看缓存的状态，并可能需要运行类似的单元测试来验证缓存后端的功能是否正常。

**本部分功能归纳 (第 3 部分):**

这段代码片段主要集中测试了磁盘缓存后端的 **数据写入、条目删除、大小计算以及在遇到各种异常情况下的处理能力**。它特别关注了 **稀疏数据的写入**，以及 **在特定时间范围内批量删除条目** 的功能。此外，还测试了 **缓存大小的精确计算**，这对缓存管理和资源回收至关重要。最后，这部分开始涉及 **缓存事务的恢复** 和 **对损坏或不一致的缓存条目的处理和容错机制**。

### 提示词
```
这是目录为net/disk_cache/backend_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
;
  ASSERT_EQ(net::ERR_FAILED,
            WriteSparseData(entries[0].get(), 10000, buffer.get(), 4));
  ASSERT_EQ(63, WriteSparseData(entries[1].get(), 0, buffer.get(), 63));
  ASSERT_EQ(64, WriteSparseData(entries[2].get(), 0, buffer.get(), 64));
  ASSERT_EQ(64, WriteSparseData(entries[3].get(), 0, buffer.get(), 64));

  // Close all the entries, leaving a populated LRU list
  // with all entries having refcount 0 (doom implies deletion)
  entries.clear();

  // Create a new entry, triggering buggy eviction
  ASSERT_THAT(CreateEntry("http://www.14.com/", &entry), IsOk());
  entry->Close();
}

void DiskCacheBackendTest::BackendDoomBetween() {
  InitCache();

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("first", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time middle_start = Time::Now();

  ASSERT_THAT(CreateEntry("second", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time middle_end = Time::Now();

  ASSERT_THAT(CreateEntry("fourth", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry("fourth", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();

  AddDelay();
  Time final = Time::Now();

  ASSERT_EQ(4, cache_->GetEntryCount());
  EXPECT_THAT(DoomEntriesBetween(middle_start, middle_end), IsOk());
  ASSERT_EQ(2, cache_->GetEntryCount());

  ASSERT_THAT(OpenEntry("fourth", &entry), IsOk());
  entry->Close();

  EXPECT_THAT(DoomEntriesBetween(middle_start, final), IsOk());
  ASSERT_EQ(1, cache_->GetEntryCount());

  ASSERT_THAT(OpenEntry("first", &entry), IsOk());
  entry->Close();
}

TEST_F(DiskCacheBackendTest, DoomBetween) {
  BackendDoomBetween();
}

TEST_F(DiskCacheBackendTest, NewEvictionDoomBetween) {
  SetNewEviction();
  BackendDoomBetween();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomBetween) {
  SetMemoryOnlyMode();
  BackendDoomBetween();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyDoomEntriesBetweenSparse) {
  SetMemoryOnlyMode();
  base::Time start, end;
  InitSparseCache(&start, &end);
  DoomEntriesBetween(start, end);
  EXPECT_EQ(3, cache_->GetEntryCount());

  start = end;
  end = base::Time::Now();
  DoomEntriesBetween(start, end);
  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DoomEntriesBetweenSparse) {
  base::Time start, end;
  InitSparseCache(&start, &end);
  DoomEntriesBetween(start, end);
  EXPECT_EQ(9, cache_->GetEntryCount());

  start = end;
  end = base::Time::Now();
  DoomEntriesBetween(start, end);
  EXPECT_EQ(3, cache_->GetEntryCount());
}

void DiskCacheBackendTest::BackendCalculateSizeOfAllEntries() {
  InitCache();

  // The cache is initially empty.
  EXPECT_EQ(0, CalculateSizeOfAllEntries());

  // Generate random entries and populate them with data of respective
  // sizes 0, 1, ..., count - 1 bytes.
  std::set<std::string> key_pool;
  CreateSetOfRandomEntries(&key_pool);

  int count = 0;
  int total_size = 0;
  for (std::string key : key_pool) {
    std::string data(count, ' ');
    scoped_refptr<net::StringIOBuffer> buffer =
        base::MakeRefCounted<net::StringIOBuffer>(data);

    // Alternate between writing to first two streams to test that we do not
    // take only one stream into account.
    disk_cache::Entry* entry;
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    ASSERT_EQ(count, WriteData(entry, count % 2, 0, buffer.get(), count, true));
    entry->Close();

    total_size += GetRoundedSize(count + GetEntryMetadataSize(key));
    ++count;
  }

  int result = CalculateSizeOfAllEntries();
  EXPECT_EQ(total_size, result);

  // Add another entry and test if the size is updated. Then remove it and test
  // if the size is back to original value.
  {
    const int last_entry_size = 47;
    std::string data(last_entry_size, ' ');
    scoped_refptr<net::StringIOBuffer> buffer =
        base::MakeRefCounted<net::StringIOBuffer>(data);

    disk_cache::Entry* entry;
    std::string key = GenerateKey(true);
    ASSERT_THAT(CreateEntry(key, &entry), IsOk());
    ASSERT_EQ(last_entry_size,
              WriteData(entry, 0, 0, buffer.get(), last_entry_size, true));
    entry->Close();

    int new_result = CalculateSizeOfAllEntries();
    EXPECT_EQ(
        result + GetRoundedSize(last_entry_size + GetEntryMetadataSize(key)),
        new_result);

    DoomEntry(key);
    new_result = CalculateSizeOfAllEntries();
    EXPECT_EQ(result, new_result);
  }

  // After dooming the entries, the size should be back to zero.
  ASSERT_THAT(DoomAllEntries(), IsOk());
  EXPECT_EQ(0, CalculateSizeOfAllEntries());
}

TEST_F(DiskCacheBackendTest, CalculateSizeOfAllEntries) {
  BackendCalculateSizeOfAllEntries();
}

TEST_F(DiskCacheBackendTest, MemoryOnlyCalculateSizeOfAllEntries) {
  SetMemoryOnlyMode();
  BackendCalculateSizeOfAllEntries();
}

TEST_F(DiskCacheBackendTest, SimpleCacheCalculateSizeOfAllEntries) {
  // Use net::APP_CACHE to make size estimations deterministic via
  // non-optimistic writes.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendCalculateSizeOfAllEntries();
}

void DiskCacheBackendTest::BackendCalculateSizeOfEntriesBetween(
    bool expect_access_time_comparisons) {
  InitCache();

  EXPECT_EQ(0, CalculateSizeOfEntriesBetween(base::Time(), base::Time::Max()));

  Time start = Time::Now();

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("first", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();
  base::RunLoop().RunUntilIdle();

  AddDelay();
  Time middle = Time::Now();
  AddDelay();

  ASSERT_THAT(CreateEntry("second", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("third_entry", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();
  base::RunLoop().RunUntilIdle();

  AddDelay();
  Time end = Time::Now();

  int size_1 = GetRoundedSize(GetEntryMetadataSize("first"));
  int size_2 = GetRoundedSize(GetEntryMetadataSize("second"));
  int size_3 = GetRoundedSize(GetEntryMetadataSize("third_entry"));

  ASSERT_EQ(3, cache_->GetEntryCount());
  ASSERT_EQ(CalculateSizeOfAllEntries(),
            CalculateSizeOfEntriesBetween(base::Time(), base::Time::Max()));

  if (expect_access_time_comparisons) {
    int start_end = CalculateSizeOfEntriesBetween(start, end);
    ASSERT_EQ(CalculateSizeOfAllEntries(), start_end);
    ASSERT_EQ(size_1 + size_2 + size_3, start_end);

    ASSERT_EQ(size_1, CalculateSizeOfEntriesBetween(start, middle));
    ASSERT_EQ(size_2 + size_3, CalculateSizeOfEntriesBetween(middle, end));
  }

  // After dooming the entries, the size should be back to zero.
  ASSERT_THAT(DoomAllEntries(), IsOk());
  EXPECT_EQ(0, CalculateSizeOfEntriesBetween(base::Time(), base::Time::Max()));
}

TEST_F(DiskCacheBackendTest, CalculateSizeOfEntriesBetween) {
  InitCache();
  ASSERT_EQ(net::ERR_NOT_IMPLEMENTED,
            CalculateSizeOfEntriesBetween(base::Time(), base::Time::Max()));
}

TEST_F(DiskCacheBackendTest, MemoryOnlyCalculateSizeOfEntriesBetween) {
  SetMemoryOnlyMode();
  BackendCalculateSizeOfEntriesBetween(true);
}

TEST_F(DiskCacheBackendTest, SimpleCacheCalculateSizeOfEntriesBetween) {
  // Test normal mode in where access time range comparisons are supported.
  SetSimpleCacheMode();
  BackendCalculateSizeOfEntriesBetween(true);
}

TEST_F(DiskCacheBackendTest, SimpleCacheAppCacheCalculateSizeOfEntriesBetween) {
  // Test SimpleCache in APP_CACHE mode separately since it does not support
  // access time range comparisons.
  SetCacheType(net::APP_CACHE);
  SetSimpleCacheMode();
  BackendCalculateSizeOfEntriesBetween(false);
}

void DiskCacheBackendTest::BackendTransaction(const std::string& name,
                                              int num_entries,
                                              bool load) {
  success_ = false;
  ASSERT_TRUE(CopyTestCache(name));
  DisableFirstCleanup();

  uint32_t mask;
  if (load) {
    mask = 0xf;
    SetMaxSize(0x100000);
  } else {
    // Clear the settings from the previous run.
    mask = 0;
    SetMaxSize(0);
  }
  SetMask(mask);

  InitCache();
  ASSERT_EQ(num_entries + 1, cache_->GetEntryCount());

  std::string key("the first key");
  disk_cache::Entry* entry1;
  ASSERT_NE(net::OK, OpenEntry(key, &entry1));

  int actual = cache_->GetEntryCount();
  if (num_entries != actual) {
    ASSERT_TRUE(load);
    // If there is a heavy load, inserting an entry will make another entry
    // dirty (on the hash bucket) so two entries are removed.
    ASSERT_EQ(num_entries - 1, actual);
  }

  ResetCaches();

  ASSERT_TRUE(CheckCacheIntegrity(cache_path_, new_eviction_, MaxSize(), mask));
  success_ = true;
}

void DiskCacheBackendTest::BackendRecoverInsert() {
  // Tests with an empty cache.
  BackendTransaction("insert_empty1", 0, false);
  ASSERT_TRUE(success_) << "insert_empty1";
  BackendTransaction("insert_empty2", 0, false);
  ASSERT_TRUE(success_) << "insert_empty2";
  BackendTransaction("insert_empty3", 0, false);
  ASSERT_TRUE(success_) << "insert_empty3";

  // Tests with one entry on the cache.
  BackendTransaction("insert_one1", 1, false);
  ASSERT_TRUE(success_) << "insert_one1";
  BackendTransaction("insert_one2", 1, false);
  ASSERT_TRUE(success_) << "insert_one2";
  BackendTransaction("insert_one3", 1, false);
  ASSERT_TRUE(success_) << "insert_one3";

  // Tests with one hundred entries on the cache, tiny index.
  BackendTransaction("insert_load1", 100, true);
  ASSERT_TRUE(success_) << "insert_load1";
  BackendTransaction("insert_load2", 100, true);
  ASSERT_TRUE(success_) << "insert_load2";
}

TEST_F(DiskCacheBackendTest, RecoverInsert) {
  BackendRecoverInsert();
}

TEST_F(DiskCacheBackendTest, NewEvictionRecoverInsert) {
  SetNewEviction();
  BackendRecoverInsert();
}

void DiskCacheBackendTest::BackendRecoverRemove() {
  // Removing the only element.
  BackendTransaction("remove_one1", 0, false);
  ASSERT_TRUE(success_) << "remove_one1";
  BackendTransaction("remove_one2", 0, false);
  ASSERT_TRUE(success_) << "remove_one2";
  BackendTransaction("remove_one3", 0, false);
  ASSERT_TRUE(success_) << "remove_one3";

  // Removing the head.
  BackendTransaction("remove_head1", 1, false);
  ASSERT_TRUE(success_) << "remove_head1";
  BackendTransaction("remove_head2", 1, false);
  ASSERT_TRUE(success_) << "remove_head2";
  BackendTransaction("remove_head3", 1, false);
  ASSERT_TRUE(success_) << "remove_head3";

  // Removing the tail.
  BackendTransaction("remove_tail1", 1, false);
  ASSERT_TRUE(success_) << "remove_tail1";
  BackendTransaction("remove_tail2", 1, false);
  ASSERT_TRUE(success_) << "remove_tail2";
  BackendTransaction("remove_tail3", 1, false);
  ASSERT_TRUE(success_) << "remove_tail3";

  // Removing with one hundred entries on the cache, tiny index.
  BackendTransaction("remove_load1", 100, true);
  ASSERT_TRUE(success_) << "remove_load1";
  BackendTransaction("remove_load2", 100, true);
  ASSERT_TRUE(success_) << "remove_load2";
  BackendTransaction("remove_load3", 100, true);
  ASSERT_TRUE(success_) << "remove_load3";

  // This case cannot be reverted.
  BackendTransaction("remove_one4", 0, false);
  ASSERT_TRUE(success_) << "remove_one4";
  BackendTransaction("remove_head4", 1, false);
  ASSERT_TRUE(success_) << "remove_head4";
}

#if BUILDFLAG(IS_WIN)
// http://crbug.com/396392
#define MAYBE_RecoverRemove DISABLED_RecoverRemove
#else
#define MAYBE_RecoverRemove RecoverRemove
#endif
TEST_F(DiskCacheBackendTest, MAYBE_RecoverRemove) {
  BackendRecoverRemove();
}

#if BUILDFLAG(IS_WIN)
// http://crbug.com/396392
#define MAYBE_NewEvictionRecoverRemove DISABLED_NewEvictionRecoverRemove
#else
#define MAYBE_NewEvictionRecoverRemove NewEvictionRecoverRemove
#endif
TEST_F(DiskCacheBackendTest, MAYBE_NewEvictionRecoverRemove) {
  SetNewEviction();
  BackendRecoverRemove();
}

void DiskCacheBackendTest::BackendRecoverWithEviction() {
  success_ = false;
  ASSERT_TRUE(CopyTestCache("insert_load1"));
  DisableFirstCleanup();

  SetMask(0xf);
  SetMaxSize(0x1000);

  // We should not crash here.
  InitCache();
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, RecoverWithEviction) {
  BackendRecoverWithEviction();
}

TEST_F(DiskCacheBackendTest, NewEvictionRecoverWithEviction) {
  SetNewEviction();
  BackendRecoverWithEviction();
}

// Tests that the |BackendImpl| fails to start with the wrong cache version.
TEST_F(DiskCacheTest, WrongVersion) {
  ASSERT_TRUE(CopyTestCache("wrong_version"));
  net::TestCompletionCallback cb;

  std::unique_ptr<disk_cache::BackendImpl> cache(
      std::make_unique<disk_cache::BackendImpl>(cache_path_, nullptr, nullptr,
                                                net::DISK_CACHE, nullptr));
  cache->Init(cb.callback());
  ASSERT_THAT(cb.WaitForResult(), IsError(net::ERR_FAILED));
}

// Tests that the cache is properly restarted on recovery error.
// Disabled on android since this test requires cache creator to create
// blockfile caches.
#if !BUILDFLAG(IS_ANDROID)
TEST_F(DiskCacheBackendTest, DeleteOld) {
  ASSERT_TRUE(CopyTestCache("wrong_version"));
  SetNewEviction();

  TestBackendResultCompletionCallback cb;
  {
    base::ScopedDisallowBlocking disallow_blocking;
    base::FilePath path(cache_path_);
    disk_cache::BackendResult rv = disk_cache::CreateCacheBackend(
        net::DISK_CACHE, net::CACHE_BACKEND_BLOCKFILE,
        /*file_operations=*/nullptr, path, 0,
        disk_cache::ResetHandling::kResetOnError, /*net_log=*/nullptr,
        cb.callback());
    path.clear();  // Make sure path was captured by the previous call.
    rv = cb.GetResult(std::move(rv));
    ASSERT_THAT(rv.net_error, IsOk());
  }
  EXPECT_TRUE(CheckCacheIntegrity(cache_path_, new_eviction_, /*max_size = */ 0,
                                  mask_));
}
#endif

// We want to be able to deal with messed up entries on disk.
void DiskCacheBackendTest::BackendInvalidEntry2() {
  ASSERT_TRUE(CopyTestCache("bad_entry"));
  DisableFirstCleanup();
  InitCache();

  disk_cache::Entry *entry1, *entry2;
  ASSERT_THAT(OpenEntry("the first key", &entry1), IsOk());
  EXPECT_NE(net::OK, OpenEntry("some other key", &entry2));
  entry1->Close();

  // CheckCacheIntegrity will fail at this point.
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidEntry2) {
  BackendInvalidEntry2();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry2) {
  SetNewEviction();
  BackendInvalidEntry2();
}

// Tests that we don't crash or hang when enumerating this cache.
void DiskCacheBackendTest::BackendInvalidEntry3() {
  SetMask(0x1);        // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  while (iter->OpenNextEntry(&entry) == net::OK) {
    entry->Close();
  }
}

TEST_F(DiskCacheBackendTest, InvalidEntry3) {
  ASSERT_TRUE(CopyTestCache("dirty_entry3"));
  BackendInvalidEntry3();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry3) {
  ASSERT_TRUE(CopyTestCache("dirty_entry4"));
  SetNewEviction();
  BackendInvalidEntry3();
  DisableIntegrityCheck();
}

// Test that we handle a dirty entry on the LRU list, already replaced with
// the same key, and with hash collisions.
TEST_F(DiskCacheBackendTest, InvalidEntry4) {
  ASSERT_TRUE(CopyTestCache("dirty_entry3"));
  SetMask(0x1);        // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  TrimForTest(false);
}

// Test that we handle a dirty entry on the deleted list, already replaced with
// the same key, and with hash collisions.
TEST_F(DiskCacheBackendTest, InvalidEntry5) {
  ASSERT_TRUE(CopyTestCache("dirty_entry4"));
  SetNewEviction();
  SetMask(0x1);        // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  TrimDeletedListForTest(false);
}

TEST_F(DiskCacheBackendTest, InvalidEntry6) {
  ASSERT_TRUE(CopyTestCache("dirty_entry5"));
  SetMask(0x1);        // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  // There is a dirty entry (but marked as clean) at the end, pointing to a
  // deleted entry through the hash collision list. We should not re-insert the
  // deleted entry into the index table.

  TrimForTest(false);
  // The cache should be clean (as detected by CheckCacheIntegrity).
}

// Tests that we don't hang when there is a loop on the hash collision list.
// The test cache could be a result of bug 69135.
TEST_F(DiskCacheBackendTest, BadNextEntry1) {
  ASSERT_TRUE(CopyTestCache("list_loop2"));
  SetMask(0x1);        // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  // The second entry points at itselft, and the first entry is not accessible
  // though the index, but it is at the head of the LRU.

  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("The first key", &entry), IsOk());
  entry->Close();

  TrimForTest(false);
  TrimForTest(false);
  ASSERT_THAT(OpenEntry("The first key", &entry), IsOk());
  entry->Close();
  EXPECT_EQ(1, cache_->GetEntryCount());
}

// Tests that we don't hang when there is a loop on the hash collision list.
// The test cache could be a result of bug 69135.
TEST_F(DiskCacheBackendTest, BadNextEntry2) {
  ASSERT_TRUE(CopyTestCache("list_loop3"));
  SetMask(0x1);        // 2-entry table.
  SetMaxSize(0x3000);  // 12 kB.
  DisableFirstCleanup();
  InitCache();

  // There is a wide loop of 5 entries.

  disk_cache::Entry* entry;
  ASSERT_NE(net::OK, OpenEntry("Not present key", &entry));
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry6) {
  ASSERT_TRUE(CopyTestCache("bad_rankings3"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();

  // The second entry is dirty, but removing it should not corrupt the list.
  disk_cache::Entry* entry;
  ASSERT_NE(net::OK, OpenEntry("the second key", &entry));
  ASSERT_THAT(OpenEntry("the first key", &entry), IsOk());

  // This should not delete the cache.
  entry->Doom();
  FlushQueueForTest();
  entry->Close();

  ASSERT_THAT(OpenEntry("some other key", &entry), IsOk());
  entry->Close();
}

// Tests handling of corrupt entries by keeping the rankings node around, with
// a fatal failure.
void DiskCacheBackendTest::BackendInvalidEntry7() {
  const int kSize = 0x3000;  // 12 kB.
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->rankings()->Data()->next = 0;
  entry_impl->rankings()->Store();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(2, cache_->GetEntryCount());

  // This should detect the bad entry.
  EXPECT_NE(net::OK, OpenEntry(second, &entry));
  EXPECT_EQ(1, cache_->GetEntryCount());

  // We should delete the cache. The list still has a corrupt node.
  std::unique_ptr<TestIterator> iter = CreateIterator();
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, InvalidEntry7) {
  BackendInvalidEntry7();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry7) {
  SetNewEviction();
  BackendInvalidEntry7();
}

// Tests handling of corrupt entries by keeping the rankings node around, with
// a non fatal failure.
void DiskCacheBackendTest::BackendInvalidEntry8() {
  const int kSize = 0x3000;  // 12 kB
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->rankings()->Data()->contents = 0;
  entry_impl->rankings()->Store();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(2, cache_->GetEntryCount());

  // This should detect the bad entry.
  EXPECT_NE(net::OK, OpenEntry(second, &entry));
  EXPECT_EQ(1, cache_->GetEntryCount());

  // We should not delete the cache.
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
  entry->Close();
  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  EXPECT_EQ(1, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, InvalidEntry8) {
  BackendInvalidEntry8();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry8) {
  SetNewEviction();
  BackendInvalidEntry8();
}

// Tests handling of corrupt entries detected by enumerations. Note that these
// tests (xx9 to xx11) are basically just going though slightly different
// codepaths so they are tighlty coupled with the code, but that is better than
// not testing error handling code.
void DiskCacheBackendTest::BackendInvalidEntry9(bool eviction) {
  const int kSize = 0x3000;  // 12 kB.
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->entry()->Data()->state = 0xbad;
  entry_impl->entry()->Store();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(2, cache_->GetEntryCount());

  if (eviction) {
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
  } else {
    // We should detect the problem through the list, but we should not delete
    // the entry, just fail the iteration.
    std::unique_ptr<TestIterator> iter = CreateIterator();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));

    // Now a full iteration will work, and return one entry.
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));

    // This should detect what's left of the bad entry.
    EXPECT_NE(net::OK, OpenEntry(second, &entry));
    EXPECT_EQ(2, cache_->GetEntryCount());
  }
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidEntry9) {
  BackendInvalidEntry9(false);
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidEntry9) {
  SetNewEviction();
  BackendInvalidEntry9(false);
}

TEST_F(DiskCacheBackendTest, TrimInvalidEntry9) {
  BackendInvalidEntry9(true);
}

TEST_F(DiskCacheBackendTest, NewEvictionTrimInvalidEntry9) {
  SetNewEviction();
  BackendInvalidEntry9(true);
}

// Tests handling of corrupt entries detected by enumerations.
void DiskCacheBackendTest::BackendInvalidEntry10(bool eviction) {
  const int kSize = 0x3000;  // 12 kB.
  SetMaxSize(kSize * 10);
  SetNewEviction();
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry(first, &entry), IsOk());
  EXPECT_EQ(0, WriteData(entry, 0, 200, nullptr, 0, false));
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->entry()->Data()->state = 0xbad;
  entry_impl->entry()->Store();
  entry->Close();
  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  EXPECT_EQ(3, cache_->GetEntryCount());

  // We have:
  // List 0: third -> second (bad).
  // List 1: first.

  if (eviction) {
    // Detection order: second -> first -> third.
    TrimForTest(false);
    EXPECT_EQ(3, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(2, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
  } else {
    // Detection order: third -> second -> first.
    // We should detect the problem through the list, but we should not delete
    // the entry.
    std::unique_ptr<TestIterator> iter = CreateIterator();
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    EXPECT_EQ(first, entry->GetKey());
    entry->Close();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  }
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidEntry10) {
  BackendInvalidEntry10(false);
}

TEST_F(DiskCacheBackendTest, TrimInvalidEntry10) {
  BackendInvalidEntry10(true);
}

// Tests handling of corrupt entries detected by enumerations.
void DiskCacheBackendTest::BackendInvalidEntry11(bool eviction) {
  const int kSize = 0x3000;  // 12 kB.
  SetMaxSize(kSize * 10);
  SetNewEviction();
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry(first, &entry), IsOk());
  EXPECT_EQ(0, WriteData(entry, 0, 200, nullptr, 0, false));
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(OpenEntry(second, &entry), IsOk());
  EXPECT_EQ(0, WriteData(entry, 0, 200, nullptr, 0, false));

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->entry()->Data()->state = 0xbad;
  entry_impl->entry()->Store();
  entry->Close();
  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(3, cache_->GetEntryCount());

  // We have:
  // List 0: third.
  // List 1: second (bad) -> first.

  if (eviction) {
    // Detection order: third -> first -> second.
    TrimForTest(false);
    EXPECT_EQ(2, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
    TrimForTest(false);
    EXPECT_EQ(1, cache_->GetEntryCount());
  } else {
    // Detection order: third -> second.
    // We should detect the problem through the list, but we should not delete
    // the entry, just fail the iteration.
    std::unique_ptr<TestIterator> iter = CreateIterator();
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));

    // Now a full iteration will work, and return two entries.
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
    entry->Close();
    EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  }
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidEntry11) {
  BackendInvalidEntry11(false);
}

TEST_F(DiskCacheBackendTest, TrimInvalidEntry11) {
  BackendInvalidEntry11(true);
}

// Tests handling of corrupt entries in the middle of a long eviction run.
void DiskCacheBackendTest::BackendTrimInvalidEntry12() {
  const int kSize = 0x3000;  // 12 kB
  SetMaxSize(kSize * 10);
  InitCache();

  std::string first("some key");
  std::string second("something else");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(first, &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry(second, &entry), IsOk());

  // Corrupt this entry.
  disk_cache::EntryImpl* entry_impl =
      static_cast<disk_cache::EntryImpl*>(entry);

  entry_impl->entry()->Data()->state = 0xbad;
  entry_impl->entry()->Store();
  entry->Close();
  ASSERT_THAT(CreateEntry("third", &entry), IsOk());
  entry->Close();
  ASSERT_THAT(CreateEntry("fourth", &entry), IsOk());
  TrimForTest(true);
  EXPECT_EQ(1, cache_->GetEntryCount());
  entry->Close();
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, TrimInvalidEntry12) {
  BackendTrimInvalidEntry12();
}

TEST_F(DiskCacheBackendTest, NewEvictionTrimInvalidEntry12) {
  SetNewEviction();
  BackendTrimInvalidEntry12();
}

// We want to be able to deal with messed up entries on disk.
void DiskCacheBackendTest::BackendInvalidRankings2() {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();

  disk_cache::Entry *entry1, *entry2;
  EXPECT_NE(net::OK, OpenEntry("the first key", &entry1));
  ASSERT_THAT(OpenEntry("some other key", &entry2), IsOk());
  entry2->Close();

  // CheckCacheIntegrity will fail at this point.
  DisableIntegrityCheck();
}

TEST_F(DiskCacheBackendTest, InvalidRankings2) {
  BackendInvalidRankings2();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidRankings2) {
  SetNewEviction();
  BackendInvalidRankings2();
}

// If the LRU is corrupt, we delete the cache.
void DiskCacheBackendTest::BackendInvalidRankings() {
  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry), IsOk());
  entry->Close();
  EXPECT_EQ(2, cache_->GetEntryCount());

  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry));
  FlushQueueForTest();  // Allow the restart to finish.
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, InvalidRankingsSuccess) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  BackendInvalidRankings();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidRankingsSuccess) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendInvalidRankings();
}

TEST_F(DiskCacheBackendTest, InvalidRankingsFailure) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendInvalidRankings();
}

TEST_F(DiskCacheBackendTest, NewEvictionInvalidRankingsFailure) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendInvalidRankings();
}

// If the LRU is corrupt and we have open entries, we disable the cache.
void DiskCacheBackendTest::BackendDisable() {
  disk_cache::Entry *entry1, *entry2;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  ASSERT_THAT(iter->OpenNextEntry(&entry1), IsOk());

  EXPECT_NE(net::OK, iter->OpenNextEntry(&entry2));
  EXPECT_EQ(0, cache_->GetEntryCount());
  EXPECT_NE(net::OK, CreateEntry("Something new", &entry2));

  entry1->Close();
  FlushQueueForTest();  // Flushing the Close posts a task to restart the cache.
  FlushQueueForTest();  // This one actually allows that task to complete.

  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DisableSuccess) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  BackendDisable();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableSuccess) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendDisable();
}

TEST_F(DiskCacheBackendTest, DisableFailure) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendDisable();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableFailure) {
  ASSERT_TRUE(CopyTestCache("bad_rankings"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendDisable();
}

// This is another type of corruption on the LRU; disable the cache.
void DiskCacheBackendTest::BackendDisable2() {
  EXPECT_EQ(8, cache_->GetEntryCount());

  disk_cache::Entry* entry;
  std::unique_ptr<TestIterator> iter = CreateIterator();
  int count = 0;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(nullptr != entry);
    entry->Close();
    count++;
    ASSERT_LT(count, 9);
  };

  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheBackendTest, DisableSuccess2) {
  ASSERT_TRUE(CopyTestCache("list_loop"));
  DisableFirstCleanup();
  InitCache();
  BackendDisable2();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableSuccess2) {
  ASSERT_TRUE(CopyTestCache("list_loop"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  BackendDisable2();
}

TEST_F(DiskCacheBackendTest, DisableFailure2) {
  ASSERT_TRUE(CopyTestCache("list_loop"));
  DisableFirstCleanup();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendDisable2();
}

TEST_F(DiskCacheBackendTest, NewEvictionDisableFailure2) {
  ASSERT_TRUE(CopyTestCache("list_loop"));
  DisableFirstCleanup();
  SetNewEviction();
  InitCache();
  SetTestMode();  // Fail cache reinitialization.
  BackendDisable2();
}

// If the index size changes when we disable the cache, we should not crash.
void DiskCacheBackendTest::BackendDisable3() {
  disk_cache::Entry *entry1, *entry2;
  std::unique_ptr<TestIterator> ite
```