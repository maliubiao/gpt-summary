Response:
The user wants me to analyze a C++ source code file (`entry_unittest.cc`) from Chromium's network stack, focusing on its functionalities related to disk caching. I need to break down its purpose, identify any connections to JavaScript (unlikely given the file name and context), explain logical inferences with hypothetical inputs/outputs, point out common user/programming errors, and trace the user's journey to this code for debugging. Since this is part 2 of a 7-part series, I need to summarize the functionality covered in this specific segment.

Here’s a plan:

1. **Identify the Core Functionality:** Scan the test cases and helper functions to understand what aspects of `disk_cache::Entry` are being tested. Keywords like `WriteData`, `ReadData`, `TruncateData`, `ZeroLengthIO`, `Buffering`, `SizeChanges`, `ReuseEntry`, `InvalidData`, `DoomEntry`, and `SparseIO` are crucial.

2. **JavaScript Relevance:**  Given that this is low-level cache management, direct JavaScript interaction is improbable. I need to explain why and potentially mention indirect connections (e.g., JavaScript triggering network requests that utilize the cache).

3. **Logical Inferences (Hypothetical Inputs/Outputs):** For some key functions like `WriteData` and `ReadData`, I'll create simple scenarios demonstrating how data is written and read, including expected sizes and potential edge cases.

4. **Common Errors:** Think about typical mistakes when using a cache, like writing beyond allocated space, reading from unwritten regions, or incorrect offset/size calculations.

5. **User Journey (Debugging):**  Outline a scenario where a developer might end up investigating this code, such as debugging cache corruption or unexpected data retrieval.

6. **Part 2 Summary:** Condense the functionalities covered in this specific code snippet. This involves listing the tested scenarios and highlighting the main aspects of `disk_cache::Entry` being verified.
```cpp
20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(18000,
            WriteData(entry, stream_index, 0, buffer1.get(), 18000, true));
  EXPECT_EQ(18000, entry->GetDataSize(stream_index));
  EXPECT_EQ(0, WriteData(entry, stream_index, 17500, buffer1.get(), 0, true));
  EXPECT_EQ(17500, entry->GetDataSize(stream_index));

  // And back to an internal block.
  EXPECT_EQ(600,
            WriteData(entry, stream_index, 1000, buffer1.get(), 600, true));
  EXPECT_EQ(1600, entry->GetDataSize(stream_index));
  EXPECT_EQ(600, ReadData(entry, stream_index, 1000, buffer2.get(), 600));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), 600));
  EXPECT_EQ(1000, ReadData(entry, stream_index, 0, buffer2.get(), 1000));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), 1000))
      << "Preserves previous data";

  // Go from external file to zero length.
  EXPECT_EQ(20000,
            WriteData(entry, stream_index, 0, buffer1.get(), 20000, true));
  EXPECT_EQ(20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(0, WriteData(entry, stream_index, 0, buffer1.get(), 0, true));
  EXPECT_EQ(0, entry->GetDataSize(stream_index));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, TruncateData) {
  InitCache();
  TruncateData(0);
}

TEST_F(DiskCacheEntryTest, TruncateDataNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  TruncateData(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyTruncateData) {
  SetMemoryOnlyMode();
  InitCache();
  TruncateData(0);
}

void DiskCacheEntryTest::ZeroLengthIO(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  EXPECT_EQ(0, ReadData(entry, stream_index, 0, nullptr, 0));
  EXPECT_EQ(0, WriteData(entry, stream_index, 0, nullptr, 0, false));

  // This write should extend the entry.
  EXPECT_EQ(0, WriteData(entry, stream_index, 1000, nullptr, 0, false));
  EXPECT_EQ(0, ReadData(entry, stream_index, 500, nullptr, 0));
  EXPECT_EQ(0, ReadData(entry, stream_index, 2000, nullptr, 0));
  EXPECT_EQ(1000, entry->GetDataSize(stream_index));

  EXPECT_EQ(0, WriteData(entry, stream_index, 100000, nullptr, 0, true));
  EXPECT_EQ(0, ReadData(entry, stream_index, 50000, nullptr, 0));
  EXPECT_EQ(100000, entry->GetDataSize(stream_index));

  // Let's verify the actual content.
  const int kSize = 20;
  const char zeros[kSize] = {};
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);

  CacheTestFillBuffer(buffer->data(), kSize, false);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 500, buffer.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer->data(), zeros, kSize));

  CacheTestFillBuffer(buffer->data(), kSize, false);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 5000, buffer.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer->data(), zeros, kSize));

  CacheTestFillBuffer(buffer->data(), kSize, false);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 50000, buffer.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer->data(), zeros, kSize));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, ZeroLengthIO) {
  InitCache();
  ZeroLengthIO(0);
}

TEST_F(DiskCacheEntryTest, ZeroLengthIONoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  ZeroLengthIO(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyZeroLengthIO) {
  SetMemoryOnlyMode();
  InitCache();
  ZeroLengthIO(0);
}

// Tests that we handle the content correctly when buffering, a feature of the
// standard cache that permits fast responses to certain reads.
void DiskCacheEntryTest::Buffering() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 200;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, true);
  CacheTestFillBuffer(buffer2->data(), kSize, true);

  EXPECT_EQ(kSize, WriteData(entry, 1, 0, buffer1.get(), kSize, false));
  entry->Close();

  // Write a little more and read what we wrote before.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 1, 5000, buffer1.get(), kSize, false));
  EXPECT_EQ(kSize, ReadData(entry, 1, 0, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));

  // Now go to an external file.
  EXPECT_EQ(kSize, WriteData(entry, 1, 18000, buffer1.get(), kSize, false));
  entry->Close();

  // Write something else and verify old data.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 1, 10000, buffer1.get(), kSize, false));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 5000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 0, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 18000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));

  // Extend the file some more.
  EXPECT_EQ(kSize, WriteData(entry, 1, 23000, buffer1.get(), kSize, false));
  entry->Close();

  // And now make sure that we can deal with data in both places (ram/disk).
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 1, 17000, buffer1.get(), kSize, false));

  // We should not overwrite the data at 18000 with this.
  EXPECT_EQ(kSize, WriteData(entry, 1, 19000, buffer1.get(), kSize, false));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 18000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 17000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));

  EXPECT_EQ(kSize, WriteData(entry, 1, 22900, buffer1.get(), kSize, false));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(100, ReadData(entry, 1, 23000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data() + 100, 100));

  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(100, ReadData(entry, 1, 23100, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data() + 100, 100));

  // Extend the file again and read before without closing the entry.
  EXPECT_EQ(kSize, WriteData(entry, 1, 25000, buffer1.get(), kSize, false));
  EXPECT_EQ(kSize, WriteData(entry, 1, 45000, buffer1.get(), kSize, false));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 25000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 45000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, Buffering) {
  InitCache();
  Buffering();
}

TEST_F(DiskCacheEntryTest, BufferingNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  Buffering();
}

// Checks that entries are zero length when created.
void DiskCacheEntryTest::SizeAtCreate() {
  const char key[]  = "the first key";
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kNumStreams = 3;
  for (int i = 0; i < kNumStreams; ++i)
    EXPECT_EQ(0, entry->GetDataSize(i));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SizeAtCreate) {
  InitCache();
  SizeAtCreate();
}

TEST_F(DiskCacheEntryTest, MemoryOnlySizeAtCreate) {
  SetMemoryOnlyMode();
  InitCache();
  SizeAtCreate();
}

// Some extra tests to make sure that buffering works properly when changing
// the entry size.
void DiskCacheEntryTest::SizeChanges(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 200;
  const char zeros[kSize] = {};
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, true);
  CacheTestFillBuffer(buffer2->data(), kSize, true);

  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 0, buffer1.get(), kSize, true));
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 17000, buffer1.get(), kSize, true));
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 23000, buffer1.get(), kSize, true));
  entry->Close();

  // Extend the file and read between the old size and the new write.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(23000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 25000, buffer1.get(), kSize, true));
  EXPECT_EQ(25000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 24000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, kSize));

  // Read at the end of the old file size.
  EXPECT_EQ(
      kSize,
      ReadData(entry, stream_index, 23000 + kSize - 35, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data() + kSize - 35, 35));

  // Read slightly before the last write.
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 24900, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, 100));
  EXPECT_TRUE(!memcmp(buffer2->data() + 100, buffer1->data(), kSize - 100));

  // Extend the entry a little more.
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 26000, buffer1.get(), kSize, true));
  EXPECT_EQ(26000 + kSize, entry->GetDataSize(stream_index));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 25900, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, 100));
  EXPECT_TRUE(!memcmp(buffer2->data() + 100, buffer1->data(), kSize - 100));

  // And now reduce the size.
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 25000, buffer1.get(), kSize, true));
  EXPECT_EQ(25000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(
      28,
      ReadData(entry, stream_index, 25000 + kSize - 28, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data() + kSize - 28, 28));

  // Reduce the size with a buffer that is not extending the size.
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 24000, buffer1.get(), kSize, false));
  EXPECT_EQ(25000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 24500, buffer1.get(), kSize, true));
  EXPECT_EQ(24500 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 23900, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, 100));
  EXPECT_TRUE(!memcmp(buffer2->data() + 100, buffer1->data(), kSize - 100));

  // And now reduce the size below the old size.
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 19000, buffer1.get(), kSize, true));
  EXPECT_EQ(19000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 18900, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, 100));
  EXPECT_TRUE(!memcmp(buffer2->data() + 100, buffer1->data(), kSize - 100));

  // Verify that the actual file is truncated.
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(19000 + kSize, entry->GetDataSize(stream_index));

  // Extend the newly opened file with a zero length write, expect zero fill.
  EXPECT_EQ(
      0,
      WriteData(entry, stream_index, 20000 + kSize, buffer1.get(), 0, false));
  EXPECT_EQ(kSize,
            ReadData(entry, stream_index, 19000 + kSize, buffer1.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer1->data(), zeros, kSize));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, SizeChanges) {
  InitCache();
  SizeChanges(1);
}

TEST_F(DiskCacheEntryTest, SizeChangesNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  SizeChanges(1);
}

// Write more than the total cache capacity but to a single entry. |size| is the
// amount of bytes to write each time.
void DiskCacheEntryTest::ReuseEntry(int size, int stream_index) {
  std::string key1("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key1, &entry), IsOk());

  entry->Close();
  std::string key2("the second key");
  ASSERT_THAT(CreateEntry(key2, &entry), IsOk());

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(size);
  CacheTestFillBuffer(buffer->data(), size, false);

  for (int i = 0; i < 15; i++) {
    EXPECT_EQ(0, WriteData(entry, stream_index, 0, buffer.get(), 0, true));
    EXPECT_EQ(size,
              WriteData(entry, stream_index, 0, buffer.get(), size, false));
    entry->Close();
    ASSERT_THAT(OpenEntry(key2, &entry), IsOk());
  }

  entry->Close();
  ASSERT_EQ(net::OK, OpenEntry(key1, &entry)) << "have not evicted this entry";
  entry->Close();
}

TEST_F(DiskCacheEntryTest, ReuseExternalEntry) {
  SetMaxSize(200 * 1024);
  InitCache();
  ReuseEntry(20 * 1024, 0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyReuseExternalEntry) {
  SetMemoryOnlyMode();
  SetMaxSize(200 * 1024);
  InitCache();
  ReuseEntry(20 * 1024, 0);
}

TEST_F(DiskCacheEntryTest, ReuseInternalEntry) {
  SetMaxSize(100 * 1024);
  InitCache();
  ReuseEntry(10 * 1024, 0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyReuseInternalEntry) {
  SetMemoryOnlyMode();
  SetMaxSize(100 * 1024);
  InitCache();
  ReuseEntry(10 * 1024, 0);
}

// Reading somewhere that was not written should return zeros.
void DiskCacheEntryTest::InvalidData(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize1 = 20000;
  const int kSize2 = 20000;
  const int kSize3 = 20000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize3);

  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  memset(buffer2->data(), 0, kSize2);

  // Simple data grow:
  EXPECT_EQ(200,
            WriteData(entry, stream_index, 400, buffer1.get(), 200, false));
  EXPECT_EQ(600, entry->GetDataSize(stream_index));
  EXPECT_EQ(100, ReadData(entry, stream_index, 300, buffer3.get(), 100));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 100));
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  // The entry is now on disk. Load it and extend it.
  EXPECT_EQ(200,
            WriteData(entry, stream_index, 800, buffer1.get(), 200, false));
  EXPECT_EQ(1000, entry->GetDataSize(stream_index));
  EXPECT_EQ(100, ReadData(entry, stream_index, 700, buffer3.get(), 100));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 100));
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  // This time using truncate.
  EXPECT_EQ(200,
            WriteData(entry, stream_index, 1800, buffer1.get(), 200, true));
  EXPECT_EQ(2000, entry->GetDataSize(stream_index));
  EXPECT_EQ(100, ReadData(entry, stream_index, 1500, buffer3.get(), 100));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 100));

  // Go to an external file.
  EXPECT_EQ(200,
            WriteData(entry, stream_index, 19800, buffer1.get(), 200, false));
  EXPECT_EQ(20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(4000, ReadData(entry, stream_index, 14000, buffer3.get(), 4000));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 4000));

  // And back to an internal block.
  EXPECT_EQ(600,
            WriteData(entry, stream_index, 1000, buffer1.get(), 600, true));
  EXPECT_EQ(1600, entry->GetDataSize(stream_index));
  EXPECT_EQ(600, ReadData(entry, stream_index, 1000, buffer3.get(), 600));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer1->data(), 600));

  // Extend it again.
  EXPECT_EQ(600,
            WriteData(entry, stream_index, 2000, buffer1.get(), 600, false));
  EXPECT_EQ(2600, entry->GetDataSize(stream_index));
  EXPECT_EQ(200, ReadData(entry, stream_index, 1800, buffer3.get(), 200));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 200));

  // And again (with truncation flag).
  EXPECT_EQ(600,
            WriteData(entry, stream_index, 3000, buffer1.get(), 600, true));
  EXPECT_EQ(3600, entry->GetDataSize(stream_index));
  EXPECT_EQ(200, ReadData(entry, stream_index, 2800, buffer3.get(), 200));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 200));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, InvalidData) {
  InitCache();
  InvalidData(0);
}

TEST_F(DiskCacheEntryTest, InvalidDataNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  InvalidData(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyInvalidData) {
  SetMemoryOnlyMode();
  InitCache();
  InvalidData(0);
}

// Tests that the cache preserves the buffer of an IO operation.
void DiskCacheEntryTest::ReadWriteDestroyBuffer(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 200;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  net::TestCompletionCallback cb;
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->WriteData(
                stream_index, 0, buffer.get(), kSize, cb.callback(), false));

  // Release our reference to the buffer.
  buffer = nullptr;
  EXPECT_EQ(kSize, cb.WaitForResult());

  // And now test with a Read().
  buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  EXPECT_EQ(
      net::ERR_IO_PENDING,
      entry->ReadData(stream_index, 0, buffer.get(), kSize, cb.callback()));
  buffer = nullptr;
  EXPECT_EQ(kSize, cb.WaitForResult());

  entry->Close();
}

TEST_F(DiskCacheEntryTest, ReadWriteDestroyBuffer) {
  InitCache();
  ReadWriteDestroyBuffer(0);
}

void DiskCacheEntryTest::DoomNormalEntry() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Doom();
  entry->Close();

  const int kSize = 20000;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, true);
  buffer->data()[19999] = '\0';

  key = buffer->data();
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_EQ(20000, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  EXPECT_EQ(20000, WriteData(entry, 1, 0, buffer.get(), kSize, false));
  entry->Doom();
  entry->Close();

  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, DoomEntry) {
  InitCache();
  DoomNormalEntry();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyDoomEntry) {
  SetMemoryOnlyMode();
  InitCache();
  DoomNormalEntry();
}

// Tests dooming an entry that's linked to an open entry.
void DiskCacheEntryTest::DoomEntryNextToOpenEntry() {
  disk_cache::Entry* entry1;
  disk_cache::Entry* entry2;
  ASSERT_THAT(CreateEntry("fixed", &entry1), IsOk());
  entry1->Close();
  ASSERT_THAT(CreateEntry("foo", &entry1), IsOk());
  entry1->Close();
  ASSERT_THAT(CreateEntry("bar", &entry1), IsOk());
  entry1->Close();

  ASSERT_THAT(OpenEntry("foo", &entry1), IsOk());
  ASSERT_THAT(OpenEntry("bar", &entry2), IsOk());
  entry2->Doom();
  entry2->Close();

  ASSERT_THAT(OpenEntry("foo", &entry2), IsOk());
  entry2->Doom();
  entry2->Close();
  entry1->Close();

  ASSERT_THAT(OpenEntry("fixed", &entry1), IsOk());
  entry1->Close();
}

TEST_F(DiskCacheEntryTest, DoomEntryNextToOpenEntry) {
  InitCache();
  DoomEntryNextToOpenEntry();
}

TEST_F(DiskCacheEntryTest, NewEvictionDoomEntryNextToOpenEntry) {
  SetNewEviction();
  InitCache();
  DoomEntryNextToOpenEntry();
}

TEST_F(DiskCacheEntryTest, AppCacheDoomEntryNextToOpenEntry) {
  SetCacheType(net::APP_CACHE);
  InitCache();
  DoomEntryNextToOpenEntry();
}

// Verify that basic operations work as expected with doomed entries.
void DiskCacheEntryTest::DoomedEntry(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Doom();

  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
  Time initial = Time::Now();
  AddDelay();

  const int kSize1 = 2000;
  const int kSize2 = 2000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  memset(buffer2->data(), 0, kSize2);

  EXPECT_EQ(2000,
            WriteData(entry, stream_index, 0, buffer1.get(), 2000, false));
  EXPECT_EQ(2000, ReadData(entry, stream_index, 0, buffer2.get(), 2000));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer2->data(), kSize1));
  EXPECT_EQ(key, entry->GetKey());
  EXPECT_TRUE(initial < entry->GetLastModified());
  EXPECT_TRUE(initial < entry->GetLastUsed());

  entry->Close();
}

TEST_F(DiskCacheEntryTest, DoomedEntry) {
  InitCache();
  DoomedEntry(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyDoomedEntry) {
  SetMemoryOnlyMode();

### 提示词
```
这是目录为net/disk_cache/entry_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(18000,
            WriteData(entry, stream_index, 0, buffer1.get(), 18000, true));
  EXPECT_EQ(18000, entry->GetDataSize(stream_index));
  EXPECT_EQ(0, WriteData(entry, stream_index, 17500, buffer1.get(), 0, true));
  EXPECT_EQ(17500, entry->GetDataSize(stream_index));

  // And back to an internal block.
  EXPECT_EQ(600,
            WriteData(entry, stream_index, 1000, buffer1.get(), 600, true));
  EXPECT_EQ(1600, entry->GetDataSize(stream_index));
  EXPECT_EQ(600, ReadData(entry, stream_index, 1000, buffer2.get(), 600));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), 600));
  EXPECT_EQ(1000, ReadData(entry, stream_index, 0, buffer2.get(), 1000));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), 1000))
      << "Preserves previous data";

  // Go from external file to zero length.
  EXPECT_EQ(20000,
            WriteData(entry, stream_index, 0, buffer1.get(), 20000, true));
  EXPECT_EQ(20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(0, WriteData(entry, stream_index, 0, buffer1.get(), 0, true));
  EXPECT_EQ(0, entry->GetDataSize(stream_index));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, TruncateData) {
  InitCache();
  TruncateData(0);
}

TEST_F(DiskCacheEntryTest, TruncateDataNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  TruncateData(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyTruncateData) {
  SetMemoryOnlyMode();
  InitCache();
  TruncateData(0);
}

void DiskCacheEntryTest::ZeroLengthIO(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  EXPECT_EQ(0, ReadData(entry, stream_index, 0, nullptr, 0));
  EXPECT_EQ(0, WriteData(entry, stream_index, 0, nullptr, 0, false));

  // This write should extend the entry.
  EXPECT_EQ(0, WriteData(entry, stream_index, 1000, nullptr, 0, false));
  EXPECT_EQ(0, ReadData(entry, stream_index, 500, nullptr, 0));
  EXPECT_EQ(0, ReadData(entry, stream_index, 2000, nullptr, 0));
  EXPECT_EQ(1000, entry->GetDataSize(stream_index));

  EXPECT_EQ(0, WriteData(entry, stream_index, 100000, nullptr, 0, true));
  EXPECT_EQ(0, ReadData(entry, stream_index, 50000, nullptr, 0));
  EXPECT_EQ(100000, entry->GetDataSize(stream_index));

  // Let's verify the actual content.
  const int kSize = 20;
  const char zeros[kSize] = {};
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);

  CacheTestFillBuffer(buffer->data(), kSize, false);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 500, buffer.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer->data(), zeros, kSize));

  CacheTestFillBuffer(buffer->data(), kSize, false);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 5000, buffer.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer->data(), zeros, kSize));

  CacheTestFillBuffer(buffer->data(), kSize, false);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 50000, buffer.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer->data(), zeros, kSize));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, ZeroLengthIO) {
  InitCache();
  ZeroLengthIO(0);
}

TEST_F(DiskCacheEntryTest, ZeroLengthIONoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  ZeroLengthIO(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyZeroLengthIO) {
  SetMemoryOnlyMode();
  InitCache();
  ZeroLengthIO(0);
}

// Tests that we handle the content correctly when buffering, a feature of the
// standard cache that permits fast responses to certain reads.
void DiskCacheEntryTest::Buffering() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 200;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, true);
  CacheTestFillBuffer(buffer2->data(), kSize, true);

  EXPECT_EQ(kSize, WriteData(entry, 1, 0, buffer1.get(), kSize, false));
  entry->Close();

  // Write a little more and read what we wrote before.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 1, 5000, buffer1.get(), kSize, false));
  EXPECT_EQ(kSize, ReadData(entry, 1, 0, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));

  // Now go to an external file.
  EXPECT_EQ(kSize, WriteData(entry, 1, 18000, buffer1.get(), kSize, false));
  entry->Close();

  // Write something else and verify old data.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 1, 10000, buffer1.get(), kSize, false));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 5000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 0, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 18000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));

  // Extend the file some more.
  EXPECT_EQ(kSize, WriteData(entry, 1, 23000, buffer1.get(), kSize, false));
  entry->Close();

  // And now make sure that we can deal with data in both places (ram/disk).
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(kSize, WriteData(entry, 1, 17000, buffer1.get(), kSize, false));

  // We should not overwrite the data at 18000 with this.
  EXPECT_EQ(kSize, WriteData(entry, 1, 19000, buffer1.get(), kSize, false));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 18000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 17000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));

  EXPECT_EQ(kSize, WriteData(entry, 1, 22900, buffer1.get(), kSize, false));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(100, ReadData(entry, 1, 23000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data() + 100, 100));

  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(100, ReadData(entry, 1, 23100, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data() + 100, 100));

  // Extend the file again and read before without closing the entry.
  EXPECT_EQ(kSize, WriteData(entry, 1, 25000, buffer1.get(), kSize, false));
  EXPECT_EQ(kSize, WriteData(entry, 1, 45000, buffer1.get(), kSize, false));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 25000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, 1, 45000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data(), kSize));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, Buffering) {
  InitCache();
  Buffering();
}

TEST_F(DiskCacheEntryTest, BufferingNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  Buffering();
}

// Checks that entries are zero length when created.
void DiskCacheEntryTest::SizeAtCreate() {
  const char key[]  = "the first key";
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kNumStreams = 3;
  for (int i = 0; i < kNumStreams; ++i)
    EXPECT_EQ(0, entry->GetDataSize(i));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, SizeAtCreate) {
  InitCache();
  SizeAtCreate();
}

TEST_F(DiskCacheEntryTest, MemoryOnlySizeAtCreate) {
  SetMemoryOnlyMode();
  InitCache();
  SizeAtCreate();
}

// Some extra tests to make sure that buffering works properly when changing
// the entry size.
void DiskCacheEntryTest::SizeChanges(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 200;
  const char zeros[kSize] = {};
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, true);
  CacheTestFillBuffer(buffer2->data(), kSize, true);

  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 0, buffer1.get(), kSize, true));
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 17000, buffer1.get(), kSize, true));
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 23000, buffer1.get(), kSize, true));
  entry->Close();

  // Extend the file and read between the old size and the new write.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(23000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 25000, buffer1.get(), kSize, true));
  EXPECT_EQ(25000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 24000, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, kSize));

  // Read at the end of the old file size.
  EXPECT_EQ(
      kSize,
      ReadData(entry, stream_index, 23000 + kSize - 35, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data() + kSize - 35, 35));

  // Read slightly before the last write.
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 24900, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, 100));
  EXPECT_TRUE(!memcmp(buffer2->data() + 100, buffer1->data(), kSize - 100));

  // Extend the entry a little more.
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 26000, buffer1.get(), kSize, true));
  EXPECT_EQ(26000 + kSize, entry->GetDataSize(stream_index));
  CacheTestFillBuffer(buffer2->data(), kSize, true);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 25900, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, 100));
  EXPECT_TRUE(!memcmp(buffer2->data() + 100, buffer1->data(), kSize - 100));

  // And now reduce the size.
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 25000, buffer1.get(), kSize, true));
  EXPECT_EQ(25000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(
      28,
      ReadData(entry, stream_index, 25000 + kSize - 28, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), buffer1->data() + kSize - 28, 28));

  // Reduce the size with a buffer that is not extending the size.
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 24000, buffer1.get(), kSize, false));
  EXPECT_EQ(25000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 24500, buffer1.get(), kSize, true));
  EXPECT_EQ(24500 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 23900, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, 100));
  EXPECT_TRUE(!memcmp(buffer2->data() + 100, buffer1->data(), kSize - 100));

  // And now reduce the size below the old size.
  EXPECT_EQ(kSize,
            WriteData(entry, stream_index, 19000, buffer1.get(), kSize, true));
  EXPECT_EQ(19000 + kSize, entry->GetDataSize(stream_index));
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 18900, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer2->data(), zeros, 100));
  EXPECT_TRUE(!memcmp(buffer2->data() + 100, buffer1->data(), kSize - 100));

  // Verify that the actual file is truncated.
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(19000 + kSize, entry->GetDataSize(stream_index));

  // Extend the newly opened file with a zero length write, expect zero fill.
  EXPECT_EQ(
      0,
      WriteData(entry, stream_index, 20000 + kSize, buffer1.get(), 0, false));
  EXPECT_EQ(kSize,
            ReadData(entry, stream_index, 19000 + kSize, buffer1.get(), kSize));
  EXPECT_EQ(0, memcmp(buffer1->data(), zeros, kSize));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, SizeChanges) {
  InitCache();
  SizeChanges(1);
}

TEST_F(DiskCacheEntryTest, SizeChangesNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  SizeChanges(1);
}

// Write more than the total cache capacity but to a single entry. |size| is the
// amount of bytes to write each time.
void DiskCacheEntryTest::ReuseEntry(int size, int stream_index) {
  std::string key1("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key1, &entry), IsOk());

  entry->Close();
  std::string key2("the second key");
  ASSERT_THAT(CreateEntry(key2, &entry), IsOk());

  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(size);
  CacheTestFillBuffer(buffer->data(), size, false);

  for (int i = 0; i < 15; i++) {
    EXPECT_EQ(0, WriteData(entry, stream_index, 0, buffer.get(), 0, true));
    EXPECT_EQ(size,
              WriteData(entry, stream_index, 0, buffer.get(), size, false));
    entry->Close();
    ASSERT_THAT(OpenEntry(key2, &entry), IsOk());
  }

  entry->Close();
  ASSERT_EQ(net::OK, OpenEntry(key1, &entry)) << "have not evicted this entry";
  entry->Close();
}

TEST_F(DiskCacheEntryTest, ReuseExternalEntry) {
  SetMaxSize(200 * 1024);
  InitCache();
  ReuseEntry(20 * 1024, 0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyReuseExternalEntry) {
  SetMemoryOnlyMode();
  SetMaxSize(200 * 1024);
  InitCache();
  ReuseEntry(20 * 1024, 0);
}

TEST_F(DiskCacheEntryTest, ReuseInternalEntry) {
  SetMaxSize(100 * 1024);
  InitCache();
  ReuseEntry(10 * 1024, 0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyReuseInternalEntry) {
  SetMemoryOnlyMode();
  SetMaxSize(100 * 1024);
  InitCache();
  ReuseEntry(10 * 1024, 0);
}

// Reading somewhere that was not written should return zeros.
void DiskCacheEntryTest::InvalidData(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize1 = 20000;
  const int kSize2 = 20000;
  const int kSize3 = 20000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize3);

  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  memset(buffer2->data(), 0, kSize2);

  // Simple data grow:
  EXPECT_EQ(200,
            WriteData(entry, stream_index, 400, buffer1.get(), 200, false));
  EXPECT_EQ(600, entry->GetDataSize(stream_index));
  EXPECT_EQ(100, ReadData(entry, stream_index, 300, buffer3.get(), 100));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 100));
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  // The entry is now on disk. Load it and extend it.
  EXPECT_EQ(200,
            WriteData(entry, stream_index, 800, buffer1.get(), 200, false));
  EXPECT_EQ(1000, entry->GetDataSize(stream_index));
  EXPECT_EQ(100, ReadData(entry, stream_index, 700, buffer3.get(), 100));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 100));
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  // This time using truncate.
  EXPECT_EQ(200,
            WriteData(entry, stream_index, 1800, buffer1.get(), 200, true));
  EXPECT_EQ(2000, entry->GetDataSize(stream_index));
  EXPECT_EQ(100, ReadData(entry, stream_index, 1500, buffer3.get(), 100));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 100));

  // Go to an external file.
  EXPECT_EQ(200,
            WriteData(entry, stream_index, 19800, buffer1.get(), 200, false));
  EXPECT_EQ(20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(4000, ReadData(entry, stream_index, 14000, buffer3.get(), 4000));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 4000));

  // And back to an internal block.
  EXPECT_EQ(600,
            WriteData(entry, stream_index, 1000, buffer1.get(), 600, true));
  EXPECT_EQ(1600, entry->GetDataSize(stream_index));
  EXPECT_EQ(600, ReadData(entry, stream_index, 1000, buffer3.get(), 600));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer1->data(), 600));

  // Extend it again.
  EXPECT_EQ(600,
            WriteData(entry, stream_index, 2000, buffer1.get(), 600, false));
  EXPECT_EQ(2600, entry->GetDataSize(stream_index));
  EXPECT_EQ(200, ReadData(entry, stream_index, 1800, buffer3.get(), 200));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 200));

  // And again (with truncation flag).
  EXPECT_EQ(600,
            WriteData(entry, stream_index, 3000, buffer1.get(), 600, true));
  EXPECT_EQ(3600, entry->GetDataSize(stream_index));
  EXPECT_EQ(200, ReadData(entry, stream_index, 2800, buffer3.get(), 200));
  EXPECT_TRUE(!memcmp(buffer3->data(), buffer2->data(), 200));

  entry->Close();
}

TEST_F(DiskCacheEntryTest, InvalidData) {
  InitCache();
  InvalidData(0);
}

TEST_F(DiskCacheEntryTest, InvalidDataNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  InvalidData(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyInvalidData) {
  SetMemoryOnlyMode();
  InitCache();
  InvalidData(0);
}

// Tests that the cache preserves the buffer of an IO operation.
void DiskCacheEntryTest::ReadWriteDestroyBuffer(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 200;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  net::TestCompletionCallback cb;
  EXPECT_EQ(net::ERR_IO_PENDING,
            entry->WriteData(
                stream_index, 0, buffer.get(), kSize, cb.callback(), false));

  // Release our reference to the buffer.
  buffer = nullptr;
  EXPECT_EQ(kSize, cb.WaitForResult());

  // And now test with a Read().
  buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);

  EXPECT_EQ(
      net::ERR_IO_PENDING,
      entry->ReadData(stream_index, 0, buffer.get(), kSize, cb.callback()));
  buffer = nullptr;
  EXPECT_EQ(kSize, cb.WaitForResult());

  entry->Close();
}

TEST_F(DiskCacheEntryTest, ReadWriteDestroyBuffer) {
  InitCache();
  ReadWriteDestroyBuffer(0);
}

void DiskCacheEntryTest::DoomNormalEntry() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Doom();
  entry->Close();

  const int kSize = 20000;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, true);
  buffer->data()[19999] = '\0';

  key = buffer->data();
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_EQ(20000, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  EXPECT_EQ(20000, WriteData(entry, 1, 0, buffer.get(), kSize, false));
  entry->Doom();
  entry->Close();

  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, DoomEntry) {
  InitCache();
  DoomNormalEntry();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyDoomEntry) {
  SetMemoryOnlyMode();
  InitCache();
  DoomNormalEntry();
}

// Tests dooming an entry that's linked to an open entry.
void DiskCacheEntryTest::DoomEntryNextToOpenEntry() {
  disk_cache::Entry* entry1;
  disk_cache::Entry* entry2;
  ASSERT_THAT(CreateEntry("fixed", &entry1), IsOk());
  entry1->Close();
  ASSERT_THAT(CreateEntry("foo", &entry1), IsOk());
  entry1->Close();
  ASSERT_THAT(CreateEntry("bar", &entry1), IsOk());
  entry1->Close();

  ASSERT_THAT(OpenEntry("foo", &entry1), IsOk());
  ASSERT_THAT(OpenEntry("bar", &entry2), IsOk());
  entry2->Doom();
  entry2->Close();

  ASSERT_THAT(OpenEntry("foo", &entry2), IsOk());
  entry2->Doom();
  entry2->Close();
  entry1->Close();

  ASSERT_THAT(OpenEntry("fixed", &entry1), IsOk());
  entry1->Close();
}

TEST_F(DiskCacheEntryTest, DoomEntryNextToOpenEntry) {
  InitCache();
  DoomEntryNextToOpenEntry();
}

TEST_F(DiskCacheEntryTest, NewEvictionDoomEntryNextToOpenEntry) {
  SetNewEviction();
  InitCache();
  DoomEntryNextToOpenEntry();
}

TEST_F(DiskCacheEntryTest, AppCacheDoomEntryNextToOpenEntry) {
  SetCacheType(net::APP_CACHE);
  InitCache();
  DoomEntryNextToOpenEntry();
}

// Verify that basic operations work as expected with doomed entries.
void DiskCacheEntryTest::DoomedEntry(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  entry->Doom();

  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
  Time initial = Time::Now();
  AddDelay();

  const int kSize1 = 2000;
  const int kSize2 = 2000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  memset(buffer2->data(), 0, kSize2);

  EXPECT_EQ(2000,
            WriteData(entry, stream_index, 0, buffer1.get(), 2000, false));
  EXPECT_EQ(2000, ReadData(entry, stream_index, 0, buffer2.get(), 2000));
  EXPECT_EQ(0, memcmp(buffer1->data(), buffer2->data(), kSize1));
  EXPECT_EQ(key, entry->GetKey());
  EXPECT_TRUE(initial < entry->GetLastModified());
  EXPECT_TRUE(initial < entry->GetLastUsed());

  entry->Close();
}

TEST_F(DiskCacheEntryTest, DoomedEntry) {
  InitCache();
  DoomedEntry(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyDoomedEntry) {
  SetMemoryOnlyMode();
  InitCache();
  DoomedEntry(0);
}

// Tests that we discard entries if the data is missing.
TEST_F(DiskCacheEntryTest, MissingData) {
  InitCache();

  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  // Write to an external file.
  const int kSize = 20000;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer->data(), kSize, false);
  EXPECT_EQ(kSize, WriteData(entry, 0, 0, buffer.get(), kSize, false));
  entry->Close();
  FlushQueueForTest();

  disk_cache::Addr address(0x80000001);
  base::FilePath name = cache_impl_->GetFileName(address);
  EXPECT_TRUE(base::DeleteFile(name));

  // Attempt to read the data.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  EXPECT_EQ(net::ERR_FILE_NOT_FOUND,
            ReadData(entry, 0, 0, buffer.get(), kSize));
  entry->Close();

  // The entry should be gone.
  ASSERT_NE(net::OK, OpenEntry(key, &entry));
}

// Test that child entries in a memory cache backend are not visible from
// enumerations.
TEST_F(DiskCacheEntryTest, MemoryOnlyEnumerationWithSparseEntries) {
  SetMemoryOnlyMode();
  InitCache();

  const int kSize = 4096;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  std::string key("the first key");
  disk_cache::Entry* parent_entry;
  ASSERT_THAT(CreateEntry(key, &parent_entry), IsOk());

  // Writes to the parent entry.
  EXPECT_EQ(kSize, parent_entry->WriteSparseData(
                       0, buf.get(), kSize, net::CompletionOnceCallback()));

  // This write creates a child entry and writes to it.
  EXPECT_EQ(kSize, parent_entry->WriteSparseData(
                       8192, buf.get(), kSize, net::CompletionOnceCallback()));

  parent_entry->Close();

  // Perform the enumerations.
  std::unique_ptr<TestIterator> iter = CreateIterator();
  disk_cache::Entry* entry = nullptr;
  int count = 0;
  while (iter->OpenNextEntry(&entry) == net::OK) {
    ASSERT_TRUE(entry != nullptr);
    ++count;
    disk_cache::MemEntryImpl* mem_entry =
        reinterpret_cast<disk_cache::MemEntryImpl*>(entry);
    EXPECT_EQ(disk_cache::MemEntryImpl::EntryType::kParent, mem_entry->type());
    mem_entry->Close();
  }
  EXPECT_EQ(1, count);
}

// Writes |buf_1| to offset and reads it back as |buf_2|.
void VerifySparseIO(disk_cache::Entry* entry,
                    int64_t offset,
                    net::IOBuffer* buf_1,
                    size_t size,
                    net::IOBuffer* buf_2) {
  net::TestCompletionCallback cb;

  memset(buf_2->data(), 0, size);
  const auto size_i = base::checked_cast<int>(size);
  int ret = entry->ReadSparseData(offset, buf_2, size_i, cb.callback());
  EXPECT_EQ(0, cb.GetResult(ret));

  ret = entry->WriteSparseData(offset, buf_1, size_i, cb.callback());
  EXPECT_EQ(size_i, cb.GetResult(ret));

  ret = entry->ReadSparseData(offset, buf_2, size_i, cb.callback());
  EXPECT_EQ(size_i, cb.GetResult(ret));

  EXPECT_EQ(0, memcmp(buf_1->data(), buf_2->data(), size));
}

// Reads |size| bytes from |entry| at |offset| and verifies that they are the
// same as the content of the provided |buffer|.
void VerifyContentSparseIO(disk_cache::Entry* entry,
                           int64_t offset,
                           char* buffer,
                           size_t size) {
  net::TestCompletionCallback cb;

  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(size);
  memset(buf_1->data(), 0, size);
  const auto size_i = base::checked_cast<int>(size);
  int ret = entry->ReadSparseData(offset, buf_1.get(), size_i, cb.callback());
  EXPECT_EQ(size_i, cb.GetResult(ret));
  EXPECT_EQ(0, memcmp(buf_1->data(), buffer, size));
}

void DiskCacheEntryTest::BasicSparseIO() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  static constexpr size_t kSize = 2048;
  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf_2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf_1->data(), kSize, false);

  // Write at offset 0.
  VerifySparseIO(entry, 0, buf_1.get(), kSize, buf_2.get());

  // Write at offset 0x400000 (4 MB).
  VerifySparseIO(entry, 0x400000, buf_1.get(), kSize, buf_2.get());

  // Write at offset 0x800000000 (32 GB).
  VerifySparseIO(entry, 0x800000000ULL, buf_1.get(), kSize, buf_2.get());

  entry->Close();

  // Check everything again.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  VerifyContentSparseIO(entry, 0, buf_1->data(), kSize);
  VerifyContentSparseIO(entry, 0x400000, buf_1->data(), kSize);
  VerifyContentSparseIO(entry, 0x800000000ULL, buf_1->data(), kSize);
  entry->Close();
}

TEST_F(DiskCacheEntryTest, BasicSparseIO) {
  InitCache();
  BasicSparseIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyBasicSparseIO) {
  SetMemoryOnlyMode();
  InitCache();
  BasicSparseIO();
}

void DiskCacheEntryTest::HugeSparseIO() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  // Write 1.2 MB so that we cover multiple entries.
  static constexpr size_t kSize = 1200 * 1024;
  auto buf_1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buf_2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf_1->data(), kSize, false);

  // Write at offset 0x20F0000 (33 MB - 64 KB).
  VerifySparseIO(entry, 0x20F0000, buf_1.get(), kSize, buf_2.get());
  entry->Close();

  // Check it again.
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());
  VerifyContentSparseIO(entry, 0x20F0000, buf_1->data(), kSize);
  entry->Close();
}

TEST_F(DiskCacheEntryTest, HugeSparseIO) {
  InitCache();
  HugeSparseIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyHugeSparseIO) {
  SetMemoryOnlyMode();
  InitCache();
  HugeSparseIO();
}

void DiskCacheEntryTest::GetAvailableRangeTest() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize = 16 * 1024;
  auto buf = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buf->data(), kSize, false);

  // Write at offset 0x20F0000 (33 MB - 64 KB), and 0x20F4400 (33 MB - 47 KB).
  EXPECT_EQ(kSize, WriteSparseData(entry, 0x20F0000, buf.get(), kSize));
  EXPECT_EQ(kSize, WriteSparseData(entry, 0x20F4400, buf.get(), kSize));

  // We stop at the first empty block.
  TestRangeResultCompletionCallback cb;
  RangeResult result = cb.GetResult(
      entry->GetAvailableRange(0x20F0000, kSize * 2, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(kSize, result.available_len);
  EXPECT_EQ(0x20F0000, result.start);

  result = cb.GetResult(entry->GetAvailableRange(0, kSize, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);

  result = cb.GetResult(
      entry->GetAvailableRange(0x20F0000 - kSize, kSize, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);

  result = cb.GetResult(entry->GetAvailableRange(0, 0x2100000, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(kSize, result.available_len);
  EXPECT_EQ(0x20F0000, result.start);

  // We should be able to Read based on the results of GetAvailableRange.
  net::TestCompletionCallback read_cb;
  result =
      cb.GetResult(entry->GetAvailableRange(0x2100000, kSize, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);
  int rv =
      entry->ReadSparseData(result.start, buf.get(), kSize, read_cb.callback());
  EXPECT_EQ(0, read_cb.GetResult(rv));

  result =
      cb.GetResult(entry->GetAvailableRange(0x20F2000, kSize, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0x2000, result.available_len);
  EXPECT_EQ(0x20F2000, result.start);
  EXPECT_EQ(0x2000, ReadSparseData(entry, result.start, buf.get(), kSize));

  // Make sure that we respect the |len| argument.
  result = cb.GetResult(
      entry->GetAvailableRange(0x20F0001 - kSize, kSize, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(1, result.available_len);
  EXPECT_EQ(0x20F0000, result.start);

  // Use very small ranges. Write at offset 50.
  const int kTinyLen = 10;
  EXPECT_EQ(kTinyLen, WriteSparseData(entry, 50, buf.get(), kTinyLen));

  result = cb.GetResult(
      entry->GetAvailableRange(kTinyLen * 2, kTinyLen, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);
  EXPECT_EQ(kTinyLen * 2, result.start);

  // Get a huge range with maximum boundary
  result = cb.GetResult(entry->GetAvailableRange(
      0x2100000, std::numeric_limits<int32_t>::max(), cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(0, result.available_len);

  entry->Close();
}

TEST_F(DiskCacheEntryTest, GetAvailableRange) {
  InitCache();
  GetAvailableRangeTest();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyGetAvailableRange) {
  SetMemoryOnlyMode();
  InitCache();
  GetAvailableRangeTest();
}

TEST_F(DiskCacheEntryTest, GetAvailableRangeBlockFileDiscontinuous) {
  // crbug.com/791056 --- blockfile problem when there is a sub-KiB write before
  // a bunch of full 1KiB blocks, and a GetAvailableRange is issued to which
  // both are a potentially relevant.
  InitCache();

  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  auto buf_2k = base::MakeRefCounted<net::IOBufferWithSize>(2 * 1024);
  CacheTestFillBuffer(buf_2k->data(), 2 * 1024, false);

  const int kSmallSize = 612;  // sub-1k
  auto buf_small = base::MakeRefCounted<net::IOBufferWithSize>(kSmallSize);
  CacheTestFillBuffer(buf_small->data(), kSmallSize, false);

  // Sets some bits for blocks representing 1K ranges [1024, 3072),
  // which will be relevant for the next GetAvailableRange call.
  EXPECT_EQ(2 * 1024, WriteSparseData(entry, /* offset = */ 1024, buf_2k.get(),
                                      /* size = */ 2 * 1024));

  // Now record a partial write from start of the first kb.
  EXPECT_EQ(kSmallSize, WriteSparseData(entry, /* offset = */ 0,
                                        buf_small.get(), kSmallSize));

  // Try to query a range starting from that block 0.
  // The cache tracks: [0, 612) [1024, 3072).
  // The request is for: [812, 2059) so response should be [1024, 2059), which
  // has length = 1035. Previously this return a negative number for rv.
  TestRangeResultCompletionCallback cb;
  RangeResult result =
      cb.GetResult(entry->GetAvailableRange(812, 1247, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(1035, result.available_len);
  EXPECT_EQ(1024, result.start);

  // Now query [512, 1536). This matches both [512, 612) and [1024, 1536),
  // so this should return [512, 612).
  result = cb.GetResult(entry->GetAvailableRange(512, 1024, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(100, result.available_len);
  EXPECT_EQ(512, result.start);

  // Now query next portion, [612, 1636). This now just should produce
  // [1024, 1636)
  result = cb.GetResult(entry->GetAvailableRange(612, 1024, cb.callback()));
  EXPECT_EQ(net::OK, result.net_error);
  EXPECT_EQ(612, result.available_len);
  EXPECT_EQ(1024, result.start);

  // Do a conti
```