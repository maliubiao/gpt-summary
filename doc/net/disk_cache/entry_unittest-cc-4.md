Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/disk_cache/entry_unittest.cc`. The code appears to be a series of unit tests for the disk cache entry functionality in Chromium's network stack.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Subject:** The file name `entry_unittest.cc` and the repeated use of `TEST_F(DiskCacheEntryTest, ...)` clearly indicate these are unit tests specifically for the `DiskCacheEntry` class (or related entry management).

2. **Scan Test Names for Clues:**  The names of the test functions are highly descriptive and provide the best insight into the tested features. Keywords like "Doom", "Create", "Open", "Write", "Read", "Evict", "Truncate", "CRC", "Sparse", "Optimistic", "Race", and "ThirdStream" suggest the core functionalities being tested.

3. **Group Tests by Functionality:**  Organize the tests into logical categories based on their names. This makes the summary more structured and easier to understand. Examples:
    * Tests related to entry lifecycle: Create, Open, Close, Doom.
    * Tests related to data operations: Write, Read, Truncate.
    * Tests related to error handling or specific scenarios: CRC checks, race conditions, sparse data, third stream behavior.
    * Tests related to cache management: Eviction.

4. **Look for Common Setup:** Notice the `SetSimpleCacheMode()` and `InitCache()` calls at the beginning of many tests. This indicates a focus on the "Simple Cache" backend and the initialization of the cache for testing.

5. **Identify Specific Test Scenarios:**  For each group, pinpoint the specific scenarios being tested. For instance, under "Doom" related tests, notice variations like "DoomCreate", "DoomOpenOptimistic", "MassDoom", which highlight different sequences of operations. Similarly, "InFlightTruncate" and "InFlightRead" focus on concurrent operations.

6. **Note Error Handling and Edge Cases:**  Tests mentioning "Optimistic", "Race", "NoIndex", and "CheckCRC" point to testing error handling, concurrency issues, and data integrity checks.

7. **Recognize the "Simple Cache" Focus:** The repeated use of `SetSimpleCacheMode()` strongly suggests these tests are specifically for the "Simple Cache" implementation.

8. **Infer Assumptions and Inputs/Outputs (Based on Test Structure):** Although the user requested specific input/output examples,  unit tests generally *assert* expected outputs for given actions. The "input" is the sequence of cache operations within each test, and the "output" is verified using `ASSERT_EQ`, `EXPECT_EQ`, `ASSERT_THAT`, etc. It's difficult to provide a single "input and output" for the entire file, but the *structure* of the tests themselves demonstrates this pattern.

9. **Consider User Errors:** Tests that involve sequences of operations like Create, Doom, then another Create implicitly test scenarios where a user (or the system) might try to interact with the cache in unexpected ways. For example, trying to open a doomed entry is a potential user error the tests are validating.

10. **Relate to User Actions (Debugging Context):** Think about how a user's interaction with a browser might lead to these cache operations. Loading a webpage, navigating, downloading files – all these could involve creating, reading from, and potentially dooming cache entries.

11. **Address the JavaScript Question:**  While this C++ code is not directly JavaScript,  the network stack it tests is fundamental to how JavaScript in a browser interacts with the web. When a JavaScript application fetches data (e.g., using `fetch`), the browser's network stack (including this disk cache) is involved.

12. **Review and Refine:**  Read through the generated summary, ensuring clarity, accuracy, and completeness based on the code snippet. Make sure to address all parts of the user's request.

By following these steps, we can analyze the code snippet and generate a comprehensive summary of its functionality, including its relation to JavaScript, potential user errors, and how a user's actions might lead to the execution of this code.
```cpp
m_callback.callback());

  TestEntryResultCompletionCallback create_callback;
  // Open entry2, with same key. With optimistic ops, this should succeed
  // immediately, hence us using cache_->CreateEntry directly rather than using
  // the DiskCacheTestWithCache::CreateEntry wrapper which blocks when needed.
  EntryResult result2 =
      cache_->CreateEntry(kKey, net::HIGHEST, create_callback.callback());
  ASSERT_EQ(net::OK, result2.net_error());
  disk_cache::Entry* entry2 = result2.ReleaseEntry();
  ASSERT_NE(nullptr, entry2);

  // Do some I/O to make sure it's alive.
  const int kSize = 2048;
  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf_2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf_1->data(), kSize, false);

  EXPECT_EQ(kSize, WriteData(entry2, /* index = */ 1, /* offset = */ 0,
                             buf_1.get(), kSize, /* truncate = */ false));
  EXPECT_EQ(kSize, ReadData(entry2, /* index = */ 1, /* offset = */ 0,
                            buf_2.get(), kSize));

  doom_callback.WaitForResult();

  entry1->Close();
  entry2->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomCreateOptimisticMassDoom) {
  // Test that shows that a certain DCHECK in mass doom code had to be removed
  // once optimistic doom -> create was added.
  SetSimpleCacheMode();
  InitCache();
  const char kKey[] = "the key";

  // Create entry and initiate its Doom.
  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry1), IsOk());
  ASSERT_TRUE(entry1 != nullptr);

  net::TestCompletionCallback doom_callback;
  cache_->DoomEntry(kKey, net::HIGHEST, doom_callback.callback());

  TestEntryResultCompletionCallback create_callback;
  // Open entry2, with same key. With optimistic ops, this should succeed
  // immediately, hence us using cache_->CreateEntry directly rather than using
  // the DiskCacheTestWithCache::CreateEntry wrapper which blocks when needed.
  EntryResult result =
      cache_->CreateEntry(kKey, net::HIGHEST, create_callback.callback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry2 = result.ReleaseEntry();
  ASSERT_NE(nullptr, entry2);

  net::TestCompletionCallback doomall_callback;

  // This is what had code that had a no-longer valid DCHECK.
  cache_->DoomAllEntries(doomall_callback.callback());

  doom_callback.WaitForResult();
  doomall_callback.WaitForResult();

  entry1->Close();
  entry2->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomOpenOptimistic) {
  // Test that we optimize the doom -> optimize sequence when optimistic ops
  // are on.
  SetSimpleCacheMode();
  InitCache();
  const char kKey[] = "the key";

  // Create entry and initiate its Doom.
  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry1), IsOk());
  ASSERT_TRUE(entry1 != nullptr);
  entry1->Close();

  net::TestCompletionCallback doom_callback;
  cache_->DoomEntry(kKey, net::HIGHEST, doom_callback.callback());

  // Try to open entry. This should detect a miss immediately, since it's
  // the only thing after a doom.

  EntryResult result2 =
      cache_->OpenEntry(kKey, net::HIGHEST, EntryResultCallback());
  EXPECT_EQ(net::ERR_FAILED, result2.net_error());
  EXPECT_EQ(nullptr, result2.ReleaseEntry());
  doom_callback.WaitForResult();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomDoom) {
  // Test sequence:
  // Create, Doom, Create, Doom (1st entry), Open.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;

  const char key[] = "the first key";

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());
  ScopedEntryPtr entry1_closer(entry1);
  EXPECT_NE(null, entry1);

  EXPECT_THAT(DoomEntry(key), IsOk());

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_NE(null, entry2);

  // Redundantly dooming entry1 should not delete entry2.
  disk_cache::SimpleEntryImpl* simple_entry1 =
      static_cast<disk_cache::SimpleEntryImpl*>(entry1);
  net::TestCompletionCallback cb;
  EXPECT_EQ(net::OK,
            cb.GetResult(simple_entry1->DoomEntry(cb.callback())));

  disk_cache::Entry* entry3 = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry3), IsOk());
  ScopedEntryPtr entry3_closer(entry3);
  EXPECT_NE(null, entry3);
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomCreateDoom) {
  // Test sequence:
  // Create, Doom, Create, Doom.
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* null = nullptr;

  const char key[] = "the first key";

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());
  ScopedEntryPtr entry1_closer(entry1);
  EXPECT_NE(null, entry1);

  entry1->Doom();

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_NE(null, entry2);

  entry2->Doom();

  // This test passes if it doesn't crash.
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomCloseCreateCloseOpen) {
  // Test sequence: Create, Doom, Close, Create, Close, Open.
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* null = nullptr;

  const char key[] = "this is a key";

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());
  ScopedEntryPtr entry1_closer(entry1);
  EXPECT_NE(null, entry1);

  entry1->Doom();
  entry1_closer.reset();
  entry1 = nullptr;

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_NE(null, entry2);

  entry2_closer.reset();
  entry2 = nullptr;

  disk_cache::Entry* entry3 = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry3), IsOk());
  ScopedEntryPtr entry3_closer(entry3);
  EXPECT_NE(null, entry3);
}

// Checks that an optimistic Create would fail later on a racing Open.
TEST_F(DiskCacheEntryTest, SimpleCacheOptimisticCreateFailsOnOpen) {
  SetSimpleCacheMode();
  InitCache();

  // Create a corrupt file in place of a future entry. Optimistic create should
  // initially succeed, but realize later that creation failed.
  const std::string key = "the key";
  disk_cache::Entry* entry = nullptr;
  disk_cache::Entry* entry2 = nullptr;

  EXPECT_TRUE(disk_cache::simple_util::CreateCorruptFileForTests(
      key, cache_path_));
  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  EXPECT_THAT(result.net_error(), IsOk());
  entry = result.ReleaseEntry();
  ASSERT_TRUE(entry);
  ScopedEntryPtr entry_closer(entry);
  ASSERT_NE(net::OK, OpenEntry(key, &entry2));

  // Check that we are not leaking.
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());

  DisableIntegrityCheck();
}

// Tests that old entries are evicted while new entries remain in the index.
// This test relies on non-mandatory properties of the simple Cache Backend:
// LRU eviction, specific values of high-watermark and low-watermark etc.
// When changing the eviction algorithm, the test will have to be re-engineered.
TEST_F(DiskCacheEntryTest, SimpleCacheEvictOldEntries) {
  const int kMaxSize = 200 * 1024;
  const int kWriteSize = kMaxSize / 10;
  const int kNumExtraEntries = 12;
  SetSimpleCacheMode();
  SetMaxSize(kMaxSize);
  InitCache();

  std::string key1("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key1, &entry), IsOk());
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kWriteSize);
  CacheTestFillBuffer(buffer->data(), kWriteSize, false);
  EXPECT_EQ(kWriteSize,
            WriteData(entry, 1, 0, buffer.get(), kWriteSize, false));
  entry->Close();
  AddDelay();

  std::string key2("the key prefix");
  for (int i = 0; i < kNumExtraEntries; i++) {
    if (i == kNumExtraEntries - 2) {
      // Create a distinct timestamp for the last two entries. These entries
      // will be checked for outliving the eviction.
      AddDelay();
    }
    ASSERT_THAT(CreateEntry(key2 + base::NumberToString(i), &entry), IsOk());
    ScopedEntryPtr entry_closer(entry);
    EXPECT_EQ(kWriteSize,
              WriteData(entry, 1, 0, buffer.get(), kWriteSize, false));
  }

  // TODO(pasko): Find a way to wait for the eviction task(s) to finish by using
  // the internal knowledge about |SimpleBackendImpl|.
  ASSERT_NE(net::OK, OpenEntry(key1, &entry))
      << "Should have evicted the old entry";
  for (int i = 0; i < 2; i++) {
    int entry_no = kNumExtraEntries - i - 1;
    // Generally there is no guarantee that at this point the backround eviction
    // is finished. We are testing the positive case, i.e. when the eviction
    // never reaches this entry, should be non-flaky.
    ASSERT_EQ(net::OK, OpenEntry(key2 + base::NumberToString(entry_no), &entry))
        << "Should not have evicted fresh entry " << entry_no;
    entry->Close();
  }
}

// Tests that if a read and a following in-flight truncate are both in progress
// simultaniously that they both can occur successfully. See
// http://crbug.com/239223
TEST_F(DiskCacheEntryTest, SimpleCacheInFlightTruncate)  {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";

  // We use a very large entry size here to make sure this doesn't hit
  // the prefetch path for any concievable setting. Hitting prefetch would
  // make us serve the read below from memory entirely on I/O thread, missing
  // the point of the test which coverred two concurrent disk ops, with
  // portions of work happening on the workpool.
  const int kBufferSize = 50000;
  auto write_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CacheTestFillBuffer(write_buffer->data(), kBufferSize, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  EXPECT_EQ(kBufferSize,
            WriteData(entry, 1, 0, write_buffer.get(), kBufferSize, false));
  entry->Close();
  entry = nullptr;

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ScopedEntryPtr entry_closer(entry);

  MessageLoopHelper helper;
  int expected = 0;

  // Make a short read.
  const int kReadBufferSize = 512;
  auto read_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kReadBufferSize);
  CallbackTest read_callback(&helper, false);
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->ReadData(1, 0, read_buffer.get(), kReadBufferSize,
                            base::BindOnce(&CallbackTest::Run,
                                           base::Unretained(&read_callback))));
  ++expected;

  // Truncate the entry to the length of that read.
  auto truncate_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kReadBufferSize);
  CacheTestFillBuffer(truncate_buffer->data(), kReadBufferSize, false);
  CallbackTest truncate_callback(&helper, false);
  EXPECT_EQ(
      net::ERR_IO_PENDING,
      entry->WriteData(1, 0, truncate_buffer.get(), kReadBufferSize,
                       base::BindOnce(&CallbackTest::Run,
                                      base::Unretained(&truncate_callback)),
                       true));
  ++expected;

  // Wait for both the read and truncation to finish, and confirm that both
  // succeeded.
  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(kReadBufferSize, read_callback.last_result());
  EXPECT_EQ(kReadBufferSize, truncate_callback.last_result());
  EXPECT_EQ(0,
            memcmp(write_buffer->data(), read_buffer->data(), kReadBufferSize));
}

// Tests that if a write and a read dependant on it are both in flight
// simultaneiously that they both can complete successfully without erroneous
// early returns. See http://crbug.com/239223
TEST_F(DiskCacheEntryTest, SimpleCacheInFlightRead) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  ScopedEntryPtr entry_closer(entry);

  const int kBufferSize = 1024;
  auto write_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CacheTestFillBuffer(write_buffer->data(), kBufferSize, false);

  MessageLoopHelper helper;
  int expected = 0;

  CallbackTest write_callback(&helper, false);
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->WriteData(1, 0, write_buffer.get(), kBufferSize,
                             base::BindOnce(&CallbackTest::Run,
                                            base::Unretained(&write_callback)),
                             true));
  ++expected;

  auto read_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CallbackTest read_callback(&helper, false);
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->ReadData(1, 0, read_buffer.get(), kBufferSize,
                            base::BindOnce(&CallbackTest::Run,
                                           base::Unretained(&read_callback))));
  ++expected;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(kBufferSize, write_callback.last_result());
  EXPECT_EQ(kBufferSize, read_callback.last_result());
  EXPECT_EQ(0, memcmp(write_buffer->data(), read_buffer->data(), kBufferSize));
}

TEST_F(DiskCacheEntryTest, SimpleCacheOpenCreateRaceWithNoIndex) {
  SetSimpleCacheMode();
  DisableSimpleCacheWaitForIndex();
  DisableIntegrityCheck();
  InitCache();

  // Assume the index is not initialized, which is likely, since we are blocking
  // the IO thread from executing the index finalization step.
  TestEntryResultCompletionCallback cb1;
  TestEntryResultCompletionCallback cb2;
  EntryResult rv1 = cache_->OpenEntry("key", net::HIGHEST, cb1.callback());
  EntryResult rv2 = cache_->CreateEntry("key", net::HIGHEST, cb2.callback());

  rv1 = cb1.GetResult(std::move(rv1));
  EXPECT_THAT(rv1.net_error(), IsError(net::ERR_FAILED));
  rv2 = cb2.GetResult(std::move(rv2));
  ASSERT_THAT(rv2.net_error(), IsOk());
  disk_cache::Entry* entry2 = rv2.ReleaseEntry();

  // Try to get an alias for entry2. Open should succeed, and return the same
  // pointer.
  disk_cache::Entry* entry3 = nullptr;
  ASSERT_EQ(net::OK, OpenEntry("key", &entry3));
  EXPECT_EQ(entry3, entry2);

  entry2->Close();
  entry3->Close();
}

// Checking one more scenario of overlapped reading of a bad entry.
// Differs from the |SimpleCacheMultipleReadersCheckCRC| only by the order of
// last two reads.
TEST_F(DiskCacheEntryTest, SimpleCacheMultipleReadersCheckCRC2) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "key";
  int size = 50000;
  ASSERT_TRUE(SimpleCacheMakeBadChecksumEntry(key, size));

  auto read_buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(size);
  auto read_buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(size);

  // Advance the first reader a little.
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ScopedEntryPtr entry_closer(entry);
  EXPECT_EQ(1, ReadData(entry, 1, 0, read_buffer1.get(), 1));

  // Advance the 2nd reader by the same amount.
  disk_cache::Entry* entry2 = nullptr;
  EXPECT_THAT(OpenEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_EQ(1, ReadData(entry2, 1, 0, read_buffer2.get(), 1));

  // Continue reading 1st.
  EXPECT_GT(0, ReadData(entry, 1, 1, read_buffer1.get(), size));

  // This read should fail as well because we have previous read failures.
  EXPECT_GT(0, ReadData(entry2, 1, 1, read_buffer2.get(), 1));
  DisableIntegrityCheck();
}

// Test if we can sequentially read each subset of the data until all the data
// is read, then the CRC is calculated correctly and the reads are successful.
TEST_F(DiskCacheEntryTest, SimpleCacheReadCombineCRC) {
  // Test sequence:
  // Create, Write, Read (first half of data), Read (second half of data),
  // Close.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;
  const char key[] = "the first key";

  const int kHalfSize = 200;
  const int kSize = 2 * kHalfSize;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  disk_cache::Entry* entry = nullptr;

  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_NE(null, entry);

  EXPECT_EQ(kSize, WriteData(entry, 1, 0, buffer1.get(), kSize, false));
  entry->Close();

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry2), IsOk());
  EXPECT_EQ(entry, entry2);

  // Read the first half of the data.
  int offset = 0;
  int buf_len = kHalfSize;
  auto buffer1_read1 = base::MakeRefCounted<net::IOBufferWithSize>(buf_len);
  EXPECT_EQ(buf_len, ReadData(entry2, 1, offset, buffer1_read1.get(), buf_len));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer1_read1->data(), buf_len));

  // Read the second half of the data.
  offset = buf_len;
  buf_len = kHalfSize;
  auto buffer1_read2 = base::MakeRefCounted<net::IOBufferWithSize>(buf_len);
  EXPECT_EQ(buf_len, ReadData(entry2, 1, offset, buffer1_read2.get(), buf_len));
  char* buffer1_data = buffer1->data() + offset;
  EXPECT_EQ(0, memcmp(buffer1_data, buffer1_read2->data(), buf_len));

  // Check that we are not leaking.
  EXPECT_NE(entry, null);
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());
  entry->Close();
  entry = nullptr;
}

// Test if we can write the data not in sequence and read correctly. In
// this case the CRC will not be present.
TEST_F(DiskCacheEntryTest, SimpleCacheNonSequentialWrite) {
  // Test sequence:
  // Create, Write (second half of data), Write (first half of data), Read,
  // Close.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;
  const char key[] = "the first key";

  const int kHalfSize = 200;
  const int kSize = 2 * kHalfSize;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  char* buffer1_data = buffer1->data() + kHalfSize;
  memcpy(buffer2->data(), buffer1_data, kHalfSize);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Close();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    EXPECT_NE(null, entry);

    int offset = kHalfSize;
    int buf_len = kHalfSize;

    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer2.get(), buf_len, false));
    offset = 0;
    buf_len = kHalfSize;
    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer1.get(), buf_len, false));
    entry->Close();

    ASSERT_THAT(OpenEntry(key, &entry), IsOk());

    auto buffer1_read1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
    EXPECT_EQ(kSize, ReadData(entry, i, 0, buffer1_read1.get(), kSize));
    EXPECT_EQ(0, memcmp(buffer1->data(), buffer1_read1->data(), kSize));
    // Check that we are not leaking.
    ASSERT_NE(entry, null);
    EXPECT_TRUE(static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());
    entry->Close();
  }
}

// Test that changing stream1 size does not affect stream0 (stream0 and stream1
// are stored in the same file in Simple Cache).
TEST_F(DiskCacheEntryTest, SimpleCacheStream1SizeChanges) {
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry = nullptr;
  const std::string key("the key");
  const int kSize = 100;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_TRUE(entry);

  // Write something into stream0.
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer_read.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer_read->data(), kSize));
  entry->Close();

  // Extend stream1.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  int stream1_size = 100;
  EXPECT_EQ(0, WriteData(entry, 1, stream1_size, buffer.get(), 0, false));
  EXPECT_EQ(stream1_size, entry->GetDataSize(1));
  entry->Close();

  // Check that stream0 data has not been modified and that the EOF record for
  // stream 0 contains a crc.
  // The entry needs to be reopened before checking the crc: Open will perform
  // the synchronization with the previous Close. This ensures the EOF records
  // have been written to disk before we attempt to read them independently.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  base::FilePath entry_file0_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));
  base::File entry_file0(entry_file0_path,
                         base::File::FLAG_READ | base::File::FLAG_OPEN);
  ASSERT_TRUE(entry_file0.IsValid());

  int data_size[disk_cache::kSimpleEntryStreamCount] = {kSize, stream1_size, 0};
  int sparse_data_size = 0;
  disk_cache::SimpleEntryStat entry_stat(
      base::Time::Now(), base::Time::Now(), data_size, sparse_data_size);
  int eof_offset = entry_stat.GetEOFOffsetInFile(key.size(), 0);
  disk_cache::SimpleFileEOF eof_record;
  ASSERT_EQ(static_cast<int>(sizeof(eof_record)),
            entry_file0.Read(eof_offset, reinterpret_cast<char*>(&eof_record),
                             sizeof(eof_record)));
  EXPECT_EQ(disk_cache::kSimpleFinalMagicNumber, eof_record.final_magic_number);
  EXPECT_TRUE((eof_record.flags & disk_cache::SimpleFileEOF::FLAG_HAS_CRC32) ==
              disk_cache::SimpleFileEOF::FLAG_HAS_CRC32);

  buffer_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer_read.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer_read->data(), kSize));

  // Shrink stream1.
  stream1_size = 50;
  EXPECT_EQ(0, WriteData(entry, 1, stream1_size, buffer.get(), 0, true));
  EXPECT_EQ(stream1_size, entry->GetDataSize(1));
  entry->Close();

  // Check that stream0 data has not been modified.
  buffer_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer_read.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer_read->data(), kSize));
  entry->Close();
  entry = nullptr;
}

// Test that writing within the range for which the crc has already been
// computed will properly invalidate the computed crc.
TEST_F(DiskCacheEntryTest, SimpleCacheCRCRewrite) {
  // Test sequence:
  // Create, Write (big data), Write (small data in the middle), Close.
  // Open, Read (all), Close.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;
  const char key[] = "the first key";

  const int kHalfSize = 200;
  const int kSize = 2 * kHalfSize;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kHalfSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  CacheTestFillBuffer(buffer2->data(), kHalfSize, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_NE(null, entry);
  entry->Close();

  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    int offset = 0;
    int buf_len = kSize;

    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer1.get(), buf_len
### 提示词
```
这是目录为net/disk_cache/entry_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
m_callback.callback());

  TestEntryResultCompletionCallback create_callback;
  // Open entry2, with same key. With optimistic ops, this should succeed
  // immediately, hence us using cache_->CreateEntry directly rather than using
  // the DiskCacheTestWithCache::CreateEntry wrapper which blocks when needed.
  EntryResult result2 =
      cache_->CreateEntry(kKey, net::HIGHEST, create_callback.callback());
  ASSERT_EQ(net::OK, result2.net_error());
  disk_cache::Entry* entry2 = result2.ReleaseEntry();
  ASSERT_NE(nullptr, entry2);

  // Do some I/O to make sure it's alive.
  const int kSize = 2048;
  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf_2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf_1->data(), kSize, false);

  EXPECT_EQ(kSize, WriteData(entry2, /* index = */ 1, /* offset = */ 0,
                             buf_1.get(), kSize, /* truncate = */ false));
  EXPECT_EQ(kSize, ReadData(entry2, /* index = */ 1, /* offset = */ 0,
                            buf_2.get(), kSize));

  doom_callback.WaitForResult();

  entry1->Close();
  entry2->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomCreateOptimisticMassDoom) {
  // Test that shows that a certain DCHECK in mass doom code had to be removed
  // once optimistic doom -> create was added.
  SetSimpleCacheMode();
  InitCache();
  const char kKey[] = "the key";

  // Create entry and initiate its Doom.
  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry1), IsOk());
  ASSERT_TRUE(entry1 != nullptr);

  net::TestCompletionCallback doom_callback;
  cache_->DoomEntry(kKey, net::HIGHEST, doom_callback.callback());

  TestEntryResultCompletionCallback create_callback;
  // Open entry2, with same key. With optimistic ops, this should succeed
  // immediately, hence us using cache_->CreateEntry directly rather than using
  // the DiskCacheTestWithCache::CreateEntry wrapper which blocks when needed.
  EntryResult result =
      cache_->CreateEntry(kKey, net::HIGHEST, create_callback.callback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry2 = result.ReleaseEntry();
  ASSERT_NE(nullptr, entry2);

  net::TestCompletionCallback doomall_callback;

  // This is what had code that had a no-longer valid DCHECK.
  cache_->DoomAllEntries(doomall_callback.callback());

  doom_callback.WaitForResult();
  doomall_callback.WaitForResult();

  entry1->Close();
  entry2->Close();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomOpenOptimistic) {
  // Test that we optimize the doom -> optimize sequence when optimistic ops
  // are on.
  SetSimpleCacheMode();
  InitCache();
  const char kKey[] = "the key";

  // Create entry and initiate its Doom.
  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(kKey, &entry1), IsOk());
  ASSERT_TRUE(entry1 != nullptr);
  entry1->Close();

  net::TestCompletionCallback doom_callback;
  cache_->DoomEntry(kKey, net::HIGHEST, doom_callback.callback());

  // Try to open entry. This should detect a miss immediately, since it's
  // the only thing after a doom.

  EntryResult result2 =
      cache_->OpenEntry(kKey, net::HIGHEST, EntryResultCallback());
  EXPECT_EQ(net::ERR_FAILED, result2.net_error());
  EXPECT_EQ(nullptr, result2.ReleaseEntry());
  doom_callback.WaitForResult();
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomDoom) {
  // Test sequence:
  // Create, Doom, Create, Doom (1st entry), Open.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;

  const char key[] = "the first key";

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());
  ScopedEntryPtr entry1_closer(entry1);
  EXPECT_NE(null, entry1);

  EXPECT_THAT(DoomEntry(key), IsOk());

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_NE(null, entry2);

  // Redundantly dooming entry1 should not delete entry2.
  disk_cache::SimpleEntryImpl* simple_entry1 =
      static_cast<disk_cache::SimpleEntryImpl*>(entry1);
  net::TestCompletionCallback cb;
  EXPECT_EQ(net::OK,
            cb.GetResult(simple_entry1->DoomEntry(cb.callback())));

  disk_cache::Entry* entry3 = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry3), IsOk());
  ScopedEntryPtr entry3_closer(entry3);
  EXPECT_NE(null, entry3);
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomCreateDoom) {
  // Test sequence:
  // Create, Doom, Create, Doom.
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* null = nullptr;

  const char key[] = "the first key";

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());
  ScopedEntryPtr entry1_closer(entry1);
  EXPECT_NE(null, entry1);

  entry1->Doom();

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_NE(null, entry2);

  entry2->Doom();

  // This test passes if it doesn't crash.
}

TEST_F(DiskCacheEntryTest, SimpleCacheDoomCloseCreateCloseOpen) {
  // Test sequence: Create, Doom, Close, Create, Close, Open.
  SetSimpleCacheMode();
  InitCache();

  disk_cache::Entry* null = nullptr;

  const char key[] = "this is a key";

  disk_cache::Entry* entry1 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry1), IsOk());
  ScopedEntryPtr entry1_closer(entry1);
  EXPECT_NE(null, entry1);

  entry1->Doom();
  entry1_closer.reset();
  entry1 = nullptr;

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_NE(null, entry2);

  entry2_closer.reset();
  entry2 = nullptr;

  disk_cache::Entry* entry3 = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry3), IsOk());
  ScopedEntryPtr entry3_closer(entry3);
  EXPECT_NE(null, entry3);
}

// Checks that an optimistic Create would fail later on a racing Open.
TEST_F(DiskCacheEntryTest, SimpleCacheOptimisticCreateFailsOnOpen) {
  SetSimpleCacheMode();
  InitCache();

  // Create a corrupt file in place of a future entry. Optimistic create should
  // initially succeed, but realize later that creation failed.
  const std::string key = "the key";
  disk_cache::Entry* entry = nullptr;
  disk_cache::Entry* entry2 = nullptr;

  EXPECT_TRUE(disk_cache::simple_util::CreateCorruptFileForTests(
      key, cache_path_));
  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  EXPECT_THAT(result.net_error(), IsOk());
  entry = result.ReleaseEntry();
  ASSERT_TRUE(entry);
  ScopedEntryPtr entry_closer(entry);
  ASSERT_NE(net::OK, OpenEntry(key, &entry2));

  // Check that we are not leaking.
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());

  DisableIntegrityCheck();
}

// Tests that old entries are evicted while new entries remain in the index.
// This test relies on non-mandatory properties of the simple Cache Backend:
// LRU eviction, specific values of high-watermark and low-watermark etc.
// When changing the eviction algorithm, the test will have to be re-engineered.
TEST_F(DiskCacheEntryTest, SimpleCacheEvictOldEntries) {
  const int kMaxSize = 200 * 1024;
  const int kWriteSize = kMaxSize / 10;
  const int kNumExtraEntries = 12;
  SetSimpleCacheMode();
  SetMaxSize(kMaxSize);
  InitCache();

  std::string key1("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key1, &entry), IsOk());
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kWriteSize);
  CacheTestFillBuffer(buffer->data(), kWriteSize, false);
  EXPECT_EQ(kWriteSize,
            WriteData(entry, 1, 0, buffer.get(), kWriteSize, false));
  entry->Close();
  AddDelay();

  std::string key2("the key prefix");
  for (int i = 0; i < kNumExtraEntries; i++) {
    if (i == kNumExtraEntries - 2) {
      // Create a distinct timestamp for the last two entries. These entries
      // will be checked for outliving the eviction.
      AddDelay();
    }
    ASSERT_THAT(CreateEntry(key2 + base::NumberToString(i), &entry), IsOk());
    ScopedEntryPtr entry_closer(entry);
    EXPECT_EQ(kWriteSize,
              WriteData(entry, 1, 0, buffer.get(), kWriteSize, false));
  }

  // TODO(pasko): Find a way to wait for the eviction task(s) to finish by using
  // the internal knowledge about |SimpleBackendImpl|.
  ASSERT_NE(net::OK, OpenEntry(key1, &entry))
      << "Should have evicted the old entry";
  for (int i = 0; i < 2; i++) {
    int entry_no = kNumExtraEntries - i - 1;
    // Generally there is no guarantee that at this point the backround eviction
    // is finished. We are testing the positive case, i.e. when the eviction
    // never reaches this entry, should be non-flaky.
    ASSERT_EQ(net::OK, OpenEntry(key2 + base::NumberToString(entry_no), &entry))
        << "Should not have evicted fresh entry " << entry_no;
    entry->Close();
  }
}

// Tests that if a read and a following in-flight truncate are both in progress
// simultaniously that they both can occur successfully. See
// http://crbug.com/239223
TEST_F(DiskCacheEntryTest, SimpleCacheInFlightTruncate)  {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";

  // We use a very large entry size here to make sure this doesn't hit
  // the prefetch path for any concievable setting. Hitting prefetch would
  // make us serve the read below from memory entirely on I/O thread, missing
  // the point of the test which coverred two concurrent disk ops, with
  // portions of work happening on the workpool.
  const int kBufferSize = 50000;
  auto write_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CacheTestFillBuffer(write_buffer->data(), kBufferSize, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  EXPECT_EQ(kBufferSize,
            WriteData(entry, 1, 0, write_buffer.get(), kBufferSize, false));
  entry->Close();
  entry = nullptr;

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ScopedEntryPtr entry_closer(entry);

  MessageLoopHelper helper;
  int expected = 0;

  // Make a short read.
  const int kReadBufferSize = 512;
  auto read_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kReadBufferSize);
  CallbackTest read_callback(&helper, false);
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->ReadData(1, 0, read_buffer.get(), kReadBufferSize,
                            base::BindOnce(&CallbackTest::Run,
                                           base::Unretained(&read_callback))));
  ++expected;

  // Truncate the entry to the length of that read.
  auto truncate_buffer =
      base::MakeRefCounted<net::IOBufferWithSize>(kReadBufferSize);
  CacheTestFillBuffer(truncate_buffer->data(), kReadBufferSize, false);
  CallbackTest truncate_callback(&helper, false);
  EXPECT_EQ(
      net::ERR_IO_PENDING,
      entry->WriteData(1, 0, truncate_buffer.get(), kReadBufferSize,
                       base::BindOnce(&CallbackTest::Run,
                                      base::Unretained(&truncate_callback)),
                       true));
  ++expected;

  // Wait for both the read and truncation to finish, and confirm that both
  // succeeded.
  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(kReadBufferSize, read_callback.last_result());
  EXPECT_EQ(kReadBufferSize, truncate_callback.last_result());
  EXPECT_EQ(0,
            memcmp(write_buffer->data(), read_buffer->data(), kReadBufferSize));
}

// Tests that if a write and a read dependant on it are both in flight
// simultaneiously that they both can complete successfully without erroneous
// early returns. See http://crbug.com/239223
TEST_F(DiskCacheEntryTest, SimpleCacheInFlightRead) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "the first key";
  EntryResult result =
      cache_->CreateEntry(key, net::HIGHEST, EntryResultCallback());
  ASSERT_EQ(net::OK, result.net_error());
  disk_cache::Entry* entry = result.ReleaseEntry();
  ScopedEntryPtr entry_closer(entry);

  const int kBufferSize = 1024;
  auto write_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CacheTestFillBuffer(write_buffer->data(), kBufferSize, false);

  MessageLoopHelper helper;
  int expected = 0;

  CallbackTest write_callback(&helper, false);
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->WriteData(1, 0, write_buffer.get(), kBufferSize,
                             base::BindOnce(&CallbackTest::Run,
                                            base::Unretained(&write_callback)),
                             true));
  ++expected;

  auto read_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CallbackTest read_callback(&helper, false);
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->ReadData(1, 0, read_buffer.get(), kBufferSize,
                            base::BindOnce(&CallbackTest::Run,
                                           base::Unretained(&read_callback))));
  ++expected;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(kBufferSize, write_callback.last_result());
  EXPECT_EQ(kBufferSize, read_callback.last_result());
  EXPECT_EQ(0, memcmp(write_buffer->data(), read_buffer->data(), kBufferSize));
}

TEST_F(DiskCacheEntryTest, SimpleCacheOpenCreateRaceWithNoIndex) {
  SetSimpleCacheMode();
  DisableSimpleCacheWaitForIndex();
  DisableIntegrityCheck();
  InitCache();

  // Assume the index is not initialized, which is likely, since we are blocking
  // the IO thread from executing the index finalization step.
  TestEntryResultCompletionCallback cb1;
  TestEntryResultCompletionCallback cb2;
  EntryResult rv1 = cache_->OpenEntry("key", net::HIGHEST, cb1.callback());
  EntryResult rv2 = cache_->CreateEntry("key", net::HIGHEST, cb2.callback());

  rv1 = cb1.GetResult(std::move(rv1));
  EXPECT_THAT(rv1.net_error(), IsError(net::ERR_FAILED));
  rv2 = cb2.GetResult(std::move(rv2));
  ASSERT_THAT(rv2.net_error(), IsOk());
  disk_cache::Entry* entry2 = rv2.ReleaseEntry();

  // Try to get an alias for entry2. Open should succeed, and return the same
  // pointer.
  disk_cache::Entry* entry3 = nullptr;
  ASSERT_EQ(net::OK, OpenEntry("key", &entry3));
  EXPECT_EQ(entry3, entry2);

  entry2->Close();
  entry3->Close();
}

// Checking one more scenario of overlapped reading of a bad entry.
// Differs from the |SimpleCacheMultipleReadersCheckCRC| only by the order of
// last two reads.
TEST_F(DiskCacheEntryTest, SimpleCacheMultipleReadersCheckCRC2) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "key";
  int size = 50000;
  ASSERT_TRUE(SimpleCacheMakeBadChecksumEntry(key, size));

  auto read_buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(size);
  auto read_buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(size);

  // Advance the first reader a little.
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  ScopedEntryPtr entry_closer(entry);
  EXPECT_EQ(1, ReadData(entry, 1, 0, read_buffer1.get(), 1));

  // Advance the 2nd reader by the same amount.
  disk_cache::Entry* entry2 = nullptr;
  EXPECT_THAT(OpenEntry(key, &entry2), IsOk());
  ScopedEntryPtr entry2_closer(entry2);
  EXPECT_EQ(1, ReadData(entry2, 1, 0, read_buffer2.get(), 1));

  // Continue reading 1st.
  EXPECT_GT(0, ReadData(entry, 1, 1, read_buffer1.get(), size));

  // This read should fail as well because we have previous read failures.
  EXPECT_GT(0, ReadData(entry2, 1, 1, read_buffer2.get(), 1));
  DisableIntegrityCheck();
}

// Test if we can sequentially read each subset of the data until all the data
// is read, then the CRC is calculated correctly and the reads are successful.
TEST_F(DiskCacheEntryTest, SimpleCacheReadCombineCRC) {
  // Test sequence:
  // Create, Write, Read (first half of data), Read (second half of data),
  // Close.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;
  const char key[] = "the first key";

  const int kHalfSize = 200;
  const int kSize = 2 * kHalfSize;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  disk_cache::Entry* entry = nullptr;

  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_NE(null, entry);

  EXPECT_EQ(kSize, WriteData(entry, 1, 0, buffer1.get(), kSize, false));
  entry->Close();

  disk_cache::Entry* entry2 = nullptr;
  ASSERT_THAT(OpenEntry(key, &entry2), IsOk());
  EXPECT_EQ(entry, entry2);

  // Read the first half of the data.
  int offset = 0;
  int buf_len = kHalfSize;
  auto buffer1_read1 = base::MakeRefCounted<net::IOBufferWithSize>(buf_len);
  EXPECT_EQ(buf_len, ReadData(entry2, 1, offset, buffer1_read1.get(), buf_len));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer1_read1->data(), buf_len));

  // Read the second half of the data.
  offset = buf_len;
  buf_len = kHalfSize;
  auto buffer1_read2 = base::MakeRefCounted<net::IOBufferWithSize>(buf_len);
  EXPECT_EQ(buf_len, ReadData(entry2, 1, offset, buffer1_read2.get(), buf_len));
  char* buffer1_data = buffer1->data() + offset;
  EXPECT_EQ(0, memcmp(buffer1_data, buffer1_read2->data(), buf_len));

  // Check that we are not leaking.
  EXPECT_NE(entry, null);
  EXPECT_TRUE(
      static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());
  entry->Close();
  entry = nullptr;
}

// Test if we can write the data not in sequence and read correctly. In
// this case the CRC will not be present.
TEST_F(DiskCacheEntryTest, SimpleCacheNonSequentialWrite) {
  // Test sequence:
  // Create, Write (second half of data), Write (first half of data), Read,
  // Close.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;
  const char key[] = "the first key";

  const int kHalfSize = 200;
  const int kSize = 2 * kHalfSize;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  char* buffer1_data = buffer1->data() + kHalfSize;
  memcpy(buffer2->data(), buffer1_data, kHalfSize);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Close();
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    EXPECT_NE(null, entry);

    int offset = kHalfSize;
    int buf_len = kHalfSize;

    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer2.get(), buf_len, false));
    offset = 0;
    buf_len = kHalfSize;
    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer1.get(), buf_len, false));
    entry->Close();

    ASSERT_THAT(OpenEntry(key, &entry), IsOk());

    auto buffer1_read1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
    EXPECT_EQ(kSize, ReadData(entry, i, 0, buffer1_read1.get(), kSize));
    EXPECT_EQ(0, memcmp(buffer1->data(), buffer1_read1->data(), kSize));
    // Check that we are not leaking.
    ASSERT_NE(entry, null);
    EXPECT_TRUE(static_cast<disk_cache::SimpleEntryImpl*>(entry)->HasOneRef());
    entry->Close();
  }
}

// Test that changing stream1 size does not affect stream0 (stream0 and stream1
// are stored in the same file in Simple Cache).
TEST_F(DiskCacheEntryTest, SimpleCacheStream1SizeChanges) {
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* entry = nullptr;
  const std::string key("the key");
  const int kSize = 100;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_TRUE(entry);

  // Write something into stream0.
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer_read.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer_read->data(), kSize));
  entry->Close();

  // Extend stream1.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  int stream1_size = 100;
  EXPECT_EQ(0, WriteData(entry, 1, stream1_size, buffer.get(), 0, false));
  EXPECT_EQ(stream1_size, entry->GetDataSize(1));
  entry->Close();

  // Check that stream0 data has not been modified and that the EOF record for
  // stream 0 contains a crc.
  // The entry needs to be reopened before checking the crc: Open will perform
  // the synchronization with the previous Close. This ensures the EOF records
  // have been written to disk before we attempt to read them independently.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  base::FilePath entry_file0_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, 0));
  base::File entry_file0(entry_file0_path,
                         base::File::FLAG_READ | base::File::FLAG_OPEN);
  ASSERT_TRUE(entry_file0.IsValid());

  int data_size[disk_cache::kSimpleEntryStreamCount] = {kSize, stream1_size, 0};
  int sparse_data_size = 0;
  disk_cache::SimpleEntryStat entry_stat(
      base::Time::Now(), base::Time::Now(), data_size, sparse_data_size);
  int eof_offset = entry_stat.GetEOFOffsetInFile(key.size(), 0);
  disk_cache::SimpleFileEOF eof_record;
  ASSERT_EQ(static_cast<int>(sizeof(eof_record)),
            entry_file0.Read(eof_offset, reinterpret_cast<char*>(&eof_record),
                             sizeof(eof_record)));
  EXPECT_EQ(disk_cache::kSimpleFinalMagicNumber, eof_record.final_magic_number);
  EXPECT_TRUE((eof_record.flags & disk_cache::SimpleFileEOF::FLAG_HAS_CRC32) ==
              disk_cache::SimpleFileEOF::FLAG_HAS_CRC32);

  buffer_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer_read.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer_read->data(), kSize));

  // Shrink stream1.
  stream1_size = 50;
  EXPECT_EQ(0, WriteData(entry, 1, stream1_size, buffer.get(), 0, true));
  EXPECT_EQ(stream1_size, entry->GetDataSize(1));
  entry->Close();

  // Check that stream0 data has not been modified.
  buffer_read = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, ReadData(entry, 0, 0, buffer_read.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer->data(), buffer_read->data(), kSize));
  entry->Close();
  entry = nullptr;
}

// Test that writing within the range for which the crc has already been
// computed will properly invalidate the computed crc.
TEST_F(DiskCacheEntryTest, SimpleCacheCRCRewrite) {
  // Test sequence:
  // Create, Write (big data), Write (small data in the middle), Close.
  // Open, Read (all), Close.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;
  const char key[] = "the first key";

  const int kHalfSize = 200;
  const int kSize = 2 * kHalfSize;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kHalfSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  CacheTestFillBuffer(buffer2->data(), kHalfSize, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_NE(null, entry);
  entry->Close();

  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    ASSERT_THAT(OpenEntry(key, &entry), IsOk());
    int offset = 0;
    int buf_len = kSize;

    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer1.get(), buf_len, false));
    offset = kHalfSize;
    buf_len = kHalfSize;
    EXPECT_EQ(buf_len,
              WriteData(entry, i, offset, buffer2.get(), buf_len, false));
    entry->Close();

    ASSERT_THAT(OpenEntry(key, &entry), IsOk());

    auto buffer1_read1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
    EXPECT_EQ(kSize, ReadData(entry, i, 0, buffer1_read1.get(), kSize));
    EXPECT_EQ(0, memcmp(buffer1->data(), buffer1_read1->data(), kHalfSize));
    EXPECT_EQ(
        0,
        memcmp(buffer2->data(), buffer1_read1->data() + kHalfSize, kHalfSize));

    entry->Close();
  }
}

bool DiskCacheEntryTest::SimpleCacheThirdStreamFileExists(const char* key) {
  int third_stream_file_index =
      disk_cache::simple_util::GetFileIndexFromStreamIndex(2);
  base::FilePath third_stream_file_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(
          key, third_stream_file_index));
  return PathExists(third_stream_file_path);
}

void DiskCacheEntryTest::SyncDoomEntry(const char* key) {
  net::TestCompletionCallback callback;
  cache_->DoomEntry(key, net::HIGHEST, callback.callback());
  callback.WaitForResult();
}

void DiskCacheEntryTest::CreateEntryWithHeaderBodyAndSideData(
    const std::string& key,
    int data_size) {
  // Use one buffer for simplicity.
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(data_size);
  CacheTestFillBuffer(buffer->data(), data_size, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    EXPECT_EQ(data_size, WriteData(entry, i, /* offset */ 0, buffer.get(),
                                   data_size, false));
  }
  entry->Close();
}

void DiskCacheEntryTest::TruncateFileFromEnd(int file_index,
                                             const std::string& key,
                                             int data_size,
                                             int truncate_size) {
  // Remove last eof bytes from cache file.
  ASSERT_GT(data_size, truncate_size);
  const int64_t new_size =
      disk_cache::simple_util::GetFileSizeFromDataSize(key.size(), data_size) -
      truncate_size;
  const base::FilePath entry_path = cache_path_.AppendASCII(
      disk_cache::simple_util::GetFilenameFromKeyAndFileIndex(key, file_index));
  EXPECT_TRUE(TruncatePath(entry_path, new_size));
}

void DiskCacheEntryTest::UseAfterBackendDestruction() {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ResetCaches();

  const int kSize = 100;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  // Do some writes and reads, but don't change the result. We're OK
  // with them failing, just not them crashing.
  WriteData(entry, 1, 0, buffer.get(), kSize, false);
  ReadData(entry, 1, 0, buffer.get(), kSize);
  WriteSparseData(entry, 20000, buffer.get(), kSize);

  entry->Close();
}

void DiskCacheEntryTest::CloseSparseAfterBackendDestruction() {
  const int kSize = 100;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  WriteSparseData(entry, 20000, buffer.get(), kSize);

  ResetCaches();

  // This call shouldn't DCHECK or crash.
  entry->Close();
}

// Check that a newly-created entry with no third-stream writes omits the
// third stream file.
TEST_F(DiskCacheEntryTest, SimpleCacheOmittedThirdStream1) {
  SetSimpleCacheMode();
  InitCache();

  const char key[] = "key";

  disk_cache::Entry* entry;

  // Create entry and close without writing: third stream file should be
  // omitted, since the stream is empty.
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Close();
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));

  SyncDoomEntry(key);
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));
}

// Check that a newly-created entry with only a single zero-offset, zero-length
// write omits the third stream file.
TEST_F(DiskCacheEntryTest, SimpleCacheOmittedThirdStream2) {
  SetSimpleCacheMode();
  InitCache();

  const int kHalfSize = 8;
  const int kSize = kHalfSize * 2;
  const char key[] = "key";
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kHalfSize, false);

  disk_cache::Entry* entry;

  // Create entry, write empty buffer to third stream, and close: third stream
  // should still be omitted, since the entry ignores writes that don't modify
  // data or change the length.
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_EQ(0, WriteData(entry, 2, 0, buffer.get(), 0, true));
  entry->Close();
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));

  SyncDoomEntry(key);
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));
}

// Check that we can read back data written to the third stream.
TEST_F(DiskCacheEntryTest, SimpleCacheOmittedThirdStream3) {
  SetSimpleCacheMode();
  InitCache();

  const int kHalfSize = 8;
  const int kSize = kHalfSize * 2;
  const char key[] = "key";
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kHalfSize, false);

  disk_cache::Entry* entry;

  // Create entry, write data to third stream, and close: third stream should
  // not be omitted, since it contains data.  Re-open entry and ensure there
  // are that many bytes in the third stream.
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_EQ(kHalfSize, WriteData(entry, 2, 0, buffer1.get(), kHalfSize, true));
  entry->Close();
  EXPECT_TRUE(SimpleCacheThirdStreamFileExists(key));

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kHalfSize, ReadData(entry, 2, 0, buffer2.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer2->data(), kHalfSize));
  entry->Close();
  EXPECT_TRUE(SimpleCacheThirdStreamFileExists(key));

  SyncDoomEntry(key);
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));
}

// Check that we remove the third stream file upon opening an entry and finding
// the third stream empty.  (This is the upgrade path for entries written
// before the third stream was optional.)
TEST_F(DiskCacheEntryTest, SimpleCacheOmittedThirdStream4) {
  SetSimpleCacheMode();
  InitCache();

  const int kHalfSize = 8;
  const int kSize = kHalfSize * 2;
  const char key[] = "key";
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kHalfSize, false);

  disk_cache::Entry* entry;

  // Create entry, write data to third stream, truncate third stream back to
  // empty, and close: third stream will not initially be omitted, since entry
  // creates the file when the first significant write comes in, and only
  // removes it on open if it is empty.  Reopen, ensure that the file is
  // deleted, and that there's no data in the third stream.
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_EQ(kHalfSize, WriteData(entry, 2, 0, buffer1.get(), kHalfSize, true));
  EXPECT_EQ(0, WriteData(entry, 2, 0, buffer1.get(), 0, true));
  entry->Close();
  EXPECT_TRUE(SimpleCacheThirdStreamFileExists(key));

  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));
  EXPECT_EQ(0, ReadData(entry, 2, 0, buffer2.get(), kSize));
  entry->Close();
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));

  SyncDoomEntry(key);
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));
}

// Check that we don't accidentally create the third stream file once the entry
// has been doomed.
TEST_F(DiskCacheEntryTest, SimpleCacheOmittedThirdStream5) {
  SetSimpleCacheMode();
  InitCache();

  const int kHalfSize = 8;
  const int kSize = kHalfSize * 2;
  const char key[] = "key";
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kHalfSize, false);

  disk_cache::Entry* entry;

  // Create entry, doom entry, write data to third stream, and close: third
  // stream should not exist.  (Note: We don't care if the write fails, just
  // that it doesn't cause the file to be created on disk.)
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Doom();
  WriteData(entry, 2, 0, buffer.get(), kHalfSize, true);
  entry->Close();
  EXPECT_FALSE(SimpleCacheThirdStreamFileExists(key));
}

// There could be a race between Doom and an optimistic write.
TEST_F(DiskCacheEntryTest, SimpleCacheDoomOptimisticWritesRace) {
  // Test sequence:
  // Create, first Write, second Write, Close.
  // Open, Close.
  SetSimpleCacheMode();
  InitCache();
  disk_cache::Entry* null = nullptr;
  const char key[] = "the first key";

  const int kSize = 200;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  CacheTestFillBuffer(buffer2->data(), kSize, false);

  // The race only happens on stream 1 and stream 2.
  for (int i = 0; i < disk_cache::kSimpleEntryStreamCount; ++i) {
    ASSERT_THAT(DoomA
```