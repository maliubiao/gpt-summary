Response:
The user wants to understand the functionality of the `net/disk_cache/entry_unittest.cc` file in the Chromium network stack. I need to analyze the provided code snippet and address the following points:

1. **Functionality:**  Summarize what the code does.
2. **Relationship with JavaScript:** Explain if and how this code relates to JavaScript.
3. **Logic and Assumptions:** Identify any logical deductions and their underlying assumptions (inputs and expected outputs).
4. **Common User/Programming Errors:**  Point out potential mistakes users or programmers could make related to this code.
5. **User Path to this Code:** Describe how user actions can lead to this code being executed during debugging.
6. **Summary of Functionality (Part 1):**  Condense the findings from the first part of the analysis.

Based on the code, it seems like this file is primarily focused on testing the functionality of the disk cache entry. It includes tests for:

- **Synchronous and Asynchronous I/O:** Reading and writing data to cache entries.
- **Internal and External Buffering:** How data is handled in memory and on disk.
- **Stream Access:** Reading and writing to different data streams within an entry.
- **Key Handling:** Creating and retrieving entries based on keys.
- **Time Management:** Testing the recording of last modified and last used times.
- **Data Growth and Truncation:**  Verifying how entry sizes change.
- **Entry Dooming:** Testing the deletion of cache entries.
- **Sparse I/O:** Handling non-contiguous data in entries.
- **Error Handling:**  Testing scenarios with invalid arguments and checksums.

Regarding JavaScript, this code is part of the browser's internal implementation and doesn't directly interact with JavaScript code in the same process. However, the disk cache is used to store resources fetched by the browser, including those initiated by JavaScript (e.g., images, scripts, stylesheets). So, indirectly, JavaScript's network requests rely on the proper functioning of this disk cache.

Let's start drafting the response based on these observations.
```
这是目录为net/disk_cache/entry_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <utility>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_param_associator.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/disk_cache_test_base.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/memory/mem_entry_impl.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_entry_format.h"
#include "net/disk_cache/simple/simple_entry_impl.h"
#include "net/disk_cache/simple/simple_histogram_enums.h"
#include "net/disk_cache/simple/simple_synchronous_entry.h"
#include "net/disk_cache/simple/simple_test_util.h"
#include "net/disk_cache/simple/simple_util.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

using base::Time;
using disk_cache::EntryResult;
using disk_cache::EntryResultCallback;
using disk_cache::RangeResult;
using disk_cache::ScopedEntryPtr;

// Tests that can run with different types of caches.
class DiskCacheEntryTest : public DiskCacheTestWithCache {
 public:
  void InternalSyncIOBackground(disk_cache::Entry* entry);
  void ExternalSyncIOBackground(disk_cache::Entry* entry);

 protected:
  void InternalSyncIO();
  void InternalAsyncIO();
  void ExternalSyncIO();
  void ExternalAsyncIO();
  void ReleaseBuffer(int stream_index);
  void StreamAccess();
  void GetKey();
  void GetTimes(int stream_index);
  void GrowData(int stream_index);
  void TruncateData(int stream_index);
  void ZeroLengthIO(int stream_index);
  void Buffering();
  void SizeAtCreate();
  void SizeChanges(int stream_index);
  void ReuseEntry(int size, int stream_index);
  void InvalidData(int stream_index);
  void ReadWriteDestroyBuffer(int stream_index);
  void DoomNormalEntry();
  void DoomEntryNextToOpenEntry();
  void DoomedEntry(int stream_index);
  void BasicSparseIO();
  void HugeSparseIO();
  void GetAvailableRangeTest();
  void CouldBeSparse();
  void UpdateSparseEntry();
  void DoomSparseEntry();
  void PartialSparseEntry();
  void SparseInvalidArg();
  void SparseClipEnd(int64_t max_index, bool expected_unsupported);
  bool SimpleCacheMakeBadChecksumEntry(const std::string& key, int data_size);
  bool SimpleCacheThirdStreamFileExists(const char* key);
  void SyncDoomEntry(const char* key);
  void CreateEntryWithHeaderBodyAndSideData(const std::string& key,
                                            int data_size);
  void TruncateFileFromEnd(int file_index,
                           const std::string& key,
                           int data_size,
                           int truncate_size);
  void UseAfterBackendDestruction();
  void CloseSparseAfterBackendDestruction();
  void LastUsedTimePersists();
  void TruncateBackwards();
  void ZeroWriteBackwards();
  void SparseOffset64Bit();
};

// This part of the test runs on the background thread.
void DiskCacheEntryTest::InternalSyncIOBackground(disk_cache::Entry* entry) {
  const int kSize1 = 10;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  EXPECT_EQ(0, entry->ReadData(0, 0, buffer1.get(), kSize1,
                               net::CompletionOnceCallback()));
  base::strlcpy(buffer1->data(), "the data", kSize1);
  EXPECT_EQ(10, entry->WriteData(0, 0, buffer1.get(), kSize1,
                                 net::CompletionOnceCallback(), false));
  memset(buffer1->data(), 0, kSize1);
  EXPECT_EQ(10, entry->ReadData(0, 0, buffer1.get(), kSize1,
                                net::CompletionOnceCallback()));
  EXPECT_STREQ("the data", buffer1->data());

  const int kSize2 = 5000;
  const int kSize3 = 10000;
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize3);
  memset(buffer3->data(), 0, kSize3);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);
  base::strlcpy(buffer2->data(), "The really big data goes here", kSize2);
  EXPECT_EQ(5000, entry->WriteData(1, 1500, buffer2.get(), kSize2,
                                   net::CompletionOnceCallback(), false));
  memset(buffer2->data(), 0, kSize2);
  EXPECT_EQ(4989, entry->ReadData(1, 1511, buffer2.get(), kSize2,
                                  net::CompletionOnceCallback()));
  EXPECT_STREQ("big data goes here", buffer2->data());
  EXPECT_EQ(5000, entry->ReadData(1, 0, buffer2.get(), kSize2,
                                  net::CompletionOnceCallback()));
  EXPECT_EQ(0, memcmp(buffer2->data(), buffer3->data(), 1500));
  EXPECT_EQ(1500, entry->ReadData(1, 5000, buffer2.get(), kSize2,
                                  net::CompletionOnceCallback()));

  EXPECT_EQ(0, entry->ReadData(1, 6500, buffer2.get(), kSize2,
                               net::CompletionOnceCallback()));
  EXPECT_EQ(6500, entry->ReadData(1, 0, buffer3.get(), kSize3,
                                  net::CompletionOnceCallback()));
  EXPECT_EQ(8192, entry->WriteData(1, 0, buffer3.get(), 8192,
                                   net::CompletionOnceCallback(), false));
  EXPECT_EQ(8192, entry->ReadData(1, 0, buffer3.get(), kSize3,
                                  net::CompletionOnceCallback()));
  EXPECT_EQ(8192, entry->GetDataSize(1));

  // We need to delete the memory buffer on this thread.
  EXPECT_EQ(0, entry->WriteData(0, 0, nullptr, 0, net::CompletionOnceCallback(),
                                true));
  EXPECT_EQ(0, entry->WriteData(1, 0, nullptr, 0, net::CompletionOnceCallback(),
                                true));
}

// We need to support synchronous IO even though it is not a supported operation
// from the point of view of the disk cache's public interface, because we use
// it internally, not just by a few tests, but as part of the implementation
// (see sparse_control.cc, for example).
void DiskCacheEntryTest::InternalSyncIO() {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);

  // The bulk of the test runs from within the callback, on the cache thread.
  RunTaskForTest(base::BindOnce(&DiskCacheEntryTest::InternalSyncIOBackground,
                                base::Unretained(this), entry));

  entry->Doom();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, InternalSyncIO) {
  InitCache();
  InternalSyncIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyInternalSyncIO) {
  SetMemoryOnlyMode();
  InitCache();
  InternalSyncIO();
}

void DiskCacheEntryTest::InternalAsyncIO() {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);

  // Avoid using internal buffers for the test. We have to write something to
  // the entry and close it so that we flush the internal buffer to disk. After
  // that, IO operations will be really hitting the disk. We don't care about
  // the content, so just extending the entry is enough (all extensions zero-
  // fill any holes).
  EXPECT_EQ(0, WriteData(entry, 0, 15 * 1024, nullptr, 0, false));
  EXPECT_EQ(0, WriteData(entry, 1, 15 * 1024, nullptr, 0, false));
  entry->Close();
  ASSERT_THAT(OpenEntry("the first key", &entry), IsOk());

  MessageLoopHelper helper;
  // Let's verify that each IO goes to the right callback object.
  CallbackTest callback1(&helper, false);
  CallbackTest callback2(&helper, false);
  CallbackTest callback3(&helper, false);
  CallbackTest callback4(&helper, false);
  CallbackTest callback5(&helper, false);
  CallbackTest callback6(&helper, false);
  CallbackTest callback7(&helper, false);
  CallbackTest callback8(&helper, false);
  CallbackTest callback9(&helper, false);
  CallbackTest callback10(&helper, false);
  CallbackTest callback11(&helper, false);
  CallbackTest callback12(&helper, false);
  CallbackTest callback13(&helper, false);

  const int kSize1 = 10;
  const int kSize2 = 5000;
  const int kSize3 = 10000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize3);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);
  CacheTestFillBuffer(buffer3->data(), kSize3, false);

  EXPECT_EQ(0, entry->ReadData(0, 15 * 1024, buffer1.get(), kSize1,
                               base::BindOnce(&CallbackTest::Run,
                                              base::Unretained(&callback1))));
  base::strlcpy(buffer1->data(), "the data", kSize1);
  int expected = 0;
  int ret = entry->WriteData(
      0, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback2)), false);
  EXPECT_TRUE(10 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  memset(buffer2->data(), 0, kSize2);
  ret = entry->ReadData(
      0, 0, buffer2.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback3)));
  EXPECT_TRUE(10 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_STREQ("the data", buffer2->data());

  base::strlcpy(buffer2->data(), "The really big data goes here", kSize2);
  ret = entry->WriteData(
      1, 1500, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback4)), true);
  EXPECT_TRUE(5000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  memset(buffer3->data(), 0, kSize3);
  ret = entry->ReadData(
      1, 1511, buffer3.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback5)));
  EXPECT_TRUE(4989 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_STREQ("big data goes here", buffer3->data());
  ret = entry->ReadData(
      1, 0, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback6)));
  EXPECT_TRUE(5000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  memset(buffer3->data(), 0, kSize3);

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(0, memcmp(buffer2->data(), buffer3->data(), 1500));
  ret = entry->ReadData(
      1, 5000, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback7)));
  EXPECT_TRUE(1500 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->ReadData(
      1, 0, buffer3.get(), kSize3,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback9)));
  EXPECT_TRUE(6500 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->WriteData(
      1, 0, buffer3.get(), 8192,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback10)), true);
  EXPECT_TRUE(8192 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  ret = entry->ReadData(
      1, 0, buffer3.get(), kSize3,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback11)));
  EXPECT_TRUE(8192 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_EQ(8192, entry->GetDataSize(1));

  ret = entry->ReadData(
      0, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback12)));
  EXPECT_TRUE(10 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->ReadData(
      1, 0, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback13)));
  EXPECT_TRUE(5000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));

  EXPECT_FALSE(helper.callback_reused_error());

  entry->Doom();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, InternalAsyncIO) {
  InitCache();
  InternalAsyncIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyInternalAsyncIO) {
  SetMemoryOnlyMode();
  InitCache();
  InternalAsyncIO();
}

// This part of the test runs on the background thread.
void DiskCacheEntryTest::ExternalSyncIOBackground(disk_cache::Entry* entry) {
  const int kSize1 = 17000;
  const int kSize2 = 25000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);
  base::strlcpy(buffer1->data(), "the data", kSize1);
  EXPECT_EQ(17000, entry->WriteData(0, 0, buffer1.get(), kSize1,
                                    net::CompletionOnceCallback(), false));
  memset(buffer1->data(), 0, kSize1);
  EXPECT_EQ(17000, entry->ReadData(0, 0, buffer1.get(), kSize1,
                                   net::CompletionOnceCallback()));
  EXPECT_STREQ("the data", buffer1->data());

  base::strlcpy(buffer2->data(), "The really big data goes here", kSize2);
  EXPECT_EQ(25000, entry->WriteData(1, 10000, buffer2.get(), kSize2,
                                    net::CompletionOnceCallback(), false));
  memset(buffer2->data(), 0, kSize2);
  EXPECT_EQ(24989, entry->ReadData(1, 10011, buffer2.get(), kSize2,
                                   net::CompletionOnceCallback()));
  EXPECT_STREQ("big data goes here", buffer2->data());
  EXPECT_EQ(25000, entry->ReadData(1, 0, buffer2.get(), kSize2,
                                   net::CompletionOnceCallback()));
  EXPECT_EQ(5000, entry->ReadData(1, 30000, buffer2.get(), kSize2,
                                  net::CompletionOnceCallback()));

  EXPECT_EQ(0, entry->ReadData(1, 35000, buffer2.get(), kSize2,
                               net::CompletionOnceCallback()));
  EXPECT_EQ(17000, entry->ReadData(1, 0, buffer1.get(), kSize1,
                                   net::CompletionOnceCallback()));
  EXPECT_EQ(17000, entry->WriteData(1, 20000, buffer1.get(), kSize1,
                                    net::CompletionOnceCallback(), false));
  EXPECT_EQ(37000, entry->GetDataSize(1));

  // We need to delete the memory buffer on this thread.
  EXPECT_EQ(0, entry->WriteData(0, 0, nullptr, 0, net::CompletionOnceCallback(),
                                true));
  EXPECT_EQ(0, entry->WriteData(1, 0, nullptr, 0, net::CompletionOnceCallback(),
                                true));
}

void DiskCacheEntryTest::ExternalSyncIO() {
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());

  // The bulk of the test runs from within the callback, on the cache thread.
  RunTaskForTest(base::BindOnce(&DiskCacheEntryTest::ExternalSyncIOBackground,
                                base::Unretained(this), entry));

  entry->Doom();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, ExternalSyncIO) {
  InitCache();
  ExternalSyncIO();
}

TEST_F(DiskCacheEntryTest, ExternalSyncIONoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  ExternalSyncIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyExternalSyncIO) {
  SetMemoryOnlyMode();
  InitCache();
  ExternalSyncIO();
}

void DiskCacheEntryTest::ExternalAsyncIO() {
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());

  int expected = 0;

  MessageLoopHelper helper;
  // Let's verify that each IO goes to the right callback object.
  CallbackTest callback1(&helper, false);
  CallbackTest callback2(&helper, false);
  CallbackTest callback3(&helper, false);
  CallbackTest callback4(&helper, false);
  CallbackTest callback5(&helper, false);
  CallbackTest callback6(&helper, false);
  CallbackTest callback7(&helper, false);
  CallbackTest callback8(&helper, false);
  CallbackTest callback9(&helper, false);

  const int kSize1 = 17000;
  const int kSize2 = 25000;
  const int kSize3 = 25000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize3);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);
  CacheTestFillBuffer(buffer3->data(), kSize3, false);
  base::strlcpy(buffer1->data(), "the data", kSize1);
  int ret = entry->WriteData(
      0, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback1)), false);
  EXPECT_TRUE(17000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));

  memset(buffer2->data(), 0, kSize1);
  ret = entry->ReadData(
      0, 0, buffer2.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback2)));
  EXPECT_TRUE(17000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_STREQ("the data", buffer2->data());

  base::strlcpy(buffer2->data(), "The really big data goes here", kSize2);
  ret = entry->WriteData(
      1, 10000, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback3)), false);
  EXPECT_TRUE(25000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));

  memset(buffer3->data(), 0, kSize3);
  ret = entry->ReadData(
      1, 10011, buffer3.get(), kSize3,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback4)));
  EXPECT_TRUE(24989 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_STREQ("big data goes here", buffer3->data());
  ret = entry->ReadData(
      1, 0, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback5)));
  EXPECT_TRUE(25000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  memset(buffer3->data(), 0, kSize3);
  EXPECT_EQ(0, memcmp(buffer2->data(), buffer3->data(), 10000));
  ret = entry->ReadData(
      1, 30000, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback6)));
  EXPECT_TRUE(5000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->ReadData(
      1, 35000, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback7)));
  EXPECT_TRUE(0 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->ReadData(
      1, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback8)));
  EXPECT_TRUE(17000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;
  ret = entry->WriteData(
      1, 20000, buffer3.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback9)), false);
  EXPECT_TRUE(17000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(37000, entry->GetDataSize(1));

  EXPECT_FALSE(helper.callback_reused_error());

  entry->Doom();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, ExternalAsyncIO) {
  InitCache();
  ExternalAsyncIO();
}

// TODO(http://crbug.com/497101): This test is flaky.
#if BUILDFLAG(IS_IOS)
#define MAYBE_ExternalAsyncIONoBuffer DISABLED_ExternalAsyncIONoBuffer
#else
#define MAYBE_ExternalAsyncIONoBuffer ExternalAsyncIONoBuffer
#endif
TEST_F(DiskCacheEntryTest, MAYBE_ExternalAsyncIONoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  ExternalAsyncIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyExternalAsyncIO) {
  SetMemoryOnlyMode();
  InitCache();
  ExternalAsyncIO();
}

// Tests that IOBuffers are not referenced after IO completes.
void DiskCacheEntryTest::ReleaseBuffer(int stream_index) {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);

  const int kBufferSize = 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CacheTestFillBuffer(buffer->data(), kBufferSize, false);

  net::ReleaseBufferCompletionCallback cb(buffer.get());
  int rv = entry->WriteData(
      stream_index, 0, buffer.get(), kBufferSize, cb.callback(), false);
  EXPECT_EQ(kBufferSize, cb.GetResult(rv));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, ReleaseBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  ReleaseBuffer(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyReleaseBuffer) {
  SetMemoryOnlyMode();
  InitCache();
  ReleaseBuffer(0);
}

void DiskCacheEntryTest::StreamAccess() {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);

  const int kBufferSize = 1024;
  const int kNumStreams = 3;
  scoped_refptr<net::IOBuffer> reference_buffers[kNumStreams];
  for (auto& reference_buffer : reference_buffers) {
    reference_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
    CacheTestFillBuffer(reference_buffer->data(), kBufferSize, false);
  }
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  for (int i = 0; i < kNumStreams; i++) {
    EXPECT_EQ(
        kBufferSize,
        WriteData(entry, i, 0, reference_buffers[i].get(), kBufferSize, false));
    memset(buffer1->data(), 0, kBufferSize);
    EXPECT_EQ(kBufferSize, ReadData(entry, i, 0, buffer1.get(), kBufferSize));
    EXPECT_EQ(
        0, memcmp(reference_buffers[i]->data(), buffer1->data(), kBufferSize));
  }
  EXPECT_EQ(net::ERR_INVALID_ARG
Prompt: 
```
这是目录为net/disk_cache/entry_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include <utility>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_param_associator.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/disk_cache_test_base.h"
#include "net/disk_cache/disk_cache_test_util.h"
#include "net/disk_cache/memory/mem_entry_impl.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_entry_format.h"
#include "net/disk_cache/simple/simple_entry_impl.h"
#include "net/disk_cache/simple/simple_histogram_enums.h"
#include "net/disk_cache/simple/simple_synchronous_entry.h"
#include "net/disk_cache/simple/simple_test_util.h"
#include "net/disk_cache/simple/simple_util.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

using base::Time;
using disk_cache::EntryResult;
using disk_cache::EntryResultCallback;
using disk_cache::RangeResult;
using disk_cache::ScopedEntryPtr;

// Tests that can run with different types of caches.
class DiskCacheEntryTest : public DiskCacheTestWithCache {
 public:
  void InternalSyncIOBackground(disk_cache::Entry* entry);
  void ExternalSyncIOBackground(disk_cache::Entry* entry);

 protected:
  void InternalSyncIO();
  void InternalAsyncIO();
  void ExternalSyncIO();
  void ExternalAsyncIO();
  void ReleaseBuffer(int stream_index);
  void StreamAccess();
  void GetKey();
  void GetTimes(int stream_index);
  void GrowData(int stream_index);
  void TruncateData(int stream_index);
  void ZeroLengthIO(int stream_index);
  void Buffering();
  void SizeAtCreate();
  void SizeChanges(int stream_index);
  void ReuseEntry(int size, int stream_index);
  void InvalidData(int stream_index);
  void ReadWriteDestroyBuffer(int stream_index);
  void DoomNormalEntry();
  void DoomEntryNextToOpenEntry();
  void DoomedEntry(int stream_index);
  void BasicSparseIO();
  void HugeSparseIO();
  void GetAvailableRangeTest();
  void CouldBeSparse();
  void UpdateSparseEntry();
  void DoomSparseEntry();
  void PartialSparseEntry();
  void SparseInvalidArg();
  void SparseClipEnd(int64_t max_index, bool expected_unsupported);
  bool SimpleCacheMakeBadChecksumEntry(const std::string& key, int data_size);
  bool SimpleCacheThirdStreamFileExists(const char* key);
  void SyncDoomEntry(const char* key);
  void CreateEntryWithHeaderBodyAndSideData(const std::string& key,
                                            int data_size);
  void TruncateFileFromEnd(int file_index,
                           const std::string& key,
                           int data_size,
                           int truncate_size);
  void UseAfterBackendDestruction();
  void CloseSparseAfterBackendDestruction();
  void LastUsedTimePersists();
  void TruncateBackwards();
  void ZeroWriteBackwards();
  void SparseOffset64Bit();
};

// This part of the test runs on the background thread.
void DiskCacheEntryTest::InternalSyncIOBackground(disk_cache::Entry* entry) {
  const int kSize1 = 10;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  EXPECT_EQ(0, entry->ReadData(0, 0, buffer1.get(), kSize1,
                               net::CompletionOnceCallback()));
  base::strlcpy(buffer1->data(), "the data", kSize1);
  EXPECT_EQ(10, entry->WriteData(0, 0, buffer1.get(), kSize1,
                                 net::CompletionOnceCallback(), false));
  memset(buffer1->data(), 0, kSize1);
  EXPECT_EQ(10, entry->ReadData(0, 0, buffer1.get(), kSize1,
                                net::CompletionOnceCallback()));
  EXPECT_STREQ("the data", buffer1->data());

  const int kSize2 = 5000;
  const int kSize3 = 10000;
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize3);
  memset(buffer3->data(), 0, kSize3);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);
  base::strlcpy(buffer2->data(), "The really big data goes here", kSize2);
  EXPECT_EQ(5000, entry->WriteData(1, 1500, buffer2.get(), kSize2,
                                   net::CompletionOnceCallback(), false));
  memset(buffer2->data(), 0, kSize2);
  EXPECT_EQ(4989, entry->ReadData(1, 1511, buffer2.get(), kSize2,
                                  net::CompletionOnceCallback()));
  EXPECT_STREQ("big data goes here", buffer2->data());
  EXPECT_EQ(5000, entry->ReadData(1, 0, buffer2.get(), kSize2,
                                  net::CompletionOnceCallback()));
  EXPECT_EQ(0, memcmp(buffer2->data(), buffer3->data(), 1500));
  EXPECT_EQ(1500, entry->ReadData(1, 5000, buffer2.get(), kSize2,
                                  net::CompletionOnceCallback()));

  EXPECT_EQ(0, entry->ReadData(1, 6500, buffer2.get(), kSize2,
                               net::CompletionOnceCallback()));
  EXPECT_EQ(6500, entry->ReadData(1, 0, buffer3.get(), kSize3,
                                  net::CompletionOnceCallback()));
  EXPECT_EQ(8192, entry->WriteData(1, 0, buffer3.get(), 8192,
                                   net::CompletionOnceCallback(), false));
  EXPECT_EQ(8192, entry->ReadData(1, 0, buffer3.get(), kSize3,
                                  net::CompletionOnceCallback()));
  EXPECT_EQ(8192, entry->GetDataSize(1));

  // We need to delete the memory buffer on this thread.
  EXPECT_EQ(0, entry->WriteData(0, 0, nullptr, 0, net::CompletionOnceCallback(),
                                true));
  EXPECT_EQ(0, entry->WriteData(1, 0, nullptr, 0, net::CompletionOnceCallback(),
                                true));
}

// We need to support synchronous IO even though it is not a supported operation
// from the point of view of the disk cache's public interface, because we use
// it internally, not just by a few tests, but as part of the implementation
// (see sparse_control.cc, for example).
void DiskCacheEntryTest::InternalSyncIO() {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);

  // The bulk of the test runs from within the callback, on the cache thread.
  RunTaskForTest(base::BindOnce(&DiskCacheEntryTest::InternalSyncIOBackground,
                                base::Unretained(this), entry));

  entry->Doom();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, InternalSyncIO) {
  InitCache();
  InternalSyncIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyInternalSyncIO) {
  SetMemoryOnlyMode();
  InitCache();
  InternalSyncIO();
}

void DiskCacheEntryTest::InternalAsyncIO() {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);

  // Avoid using internal buffers for the test. We have to write something to
  // the entry and close it so that we flush the internal buffer to disk. After
  // that, IO operations will be really hitting the disk. We don't care about
  // the content, so just extending the entry is enough (all extensions zero-
  // fill any holes).
  EXPECT_EQ(0, WriteData(entry, 0, 15 * 1024, nullptr, 0, false));
  EXPECT_EQ(0, WriteData(entry, 1, 15 * 1024, nullptr, 0, false));
  entry->Close();
  ASSERT_THAT(OpenEntry("the first key", &entry), IsOk());

  MessageLoopHelper helper;
  // Let's verify that each IO goes to the right callback object.
  CallbackTest callback1(&helper, false);
  CallbackTest callback2(&helper, false);
  CallbackTest callback3(&helper, false);
  CallbackTest callback4(&helper, false);
  CallbackTest callback5(&helper, false);
  CallbackTest callback6(&helper, false);
  CallbackTest callback7(&helper, false);
  CallbackTest callback8(&helper, false);
  CallbackTest callback9(&helper, false);
  CallbackTest callback10(&helper, false);
  CallbackTest callback11(&helper, false);
  CallbackTest callback12(&helper, false);
  CallbackTest callback13(&helper, false);

  const int kSize1 = 10;
  const int kSize2 = 5000;
  const int kSize3 = 10000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize3);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);
  CacheTestFillBuffer(buffer3->data(), kSize3, false);

  EXPECT_EQ(0, entry->ReadData(0, 15 * 1024, buffer1.get(), kSize1,
                               base::BindOnce(&CallbackTest::Run,
                                              base::Unretained(&callback1))));
  base::strlcpy(buffer1->data(), "the data", kSize1);
  int expected = 0;
  int ret = entry->WriteData(
      0, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback2)), false);
  EXPECT_TRUE(10 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  memset(buffer2->data(), 0, kSize2);
  ret = entry->ReadData(
      0, 0, buffer2.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback3)));
  EXPECT_TRUE(10 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_STREQ("the data", buffer2->data());

  base::strlcpy(buffer2->data(), "The really big data goes here", kSize2);
  ret = entry->WriteData(
      1, 1500, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback4)), true);
  EXPECT_TRUE(5000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  memset(buffer3->data(), 0, kSize3);
  ret = entry->ReadData(
      1, 1511, buffer3.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback5)));
  EXPECT_TRUE(4989 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_STREQ("big data goes here", buffer3->data());
  ret = entry->ReadData(
      1, 0, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback6)));
  EXPECT_TRUE(5000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  memset(buffer3->data(), 0, kSize3);

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(0, memcmp(buffer2->data(), buffer3->data(), 1500));
  ret = entry->ReadData(
      1, 5000, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback7)));
  EXPECT_TRUE(1500 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->ReadData(
      1, 0, buffer3.get(), kSize3,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback9)));
  EXPECT_TRUE(6500 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->WriteData(
      1, 0, buffer3.get(), 8192,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback10)), true);
  EXPECT_TRUE(8192 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  ret = entry->ReadData(
      1, 0, buffer3.get(), kSize3,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback11)));
  EXPECT_TRUE(8192 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_EQ(8192, entry->GetDataSize(1));

  ret = entry->ReadData(
      0, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback12)));
  EXPECT_TRUE(10 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->ReadData(
      1, 0, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback13)));
  EXPECT_TRUE(5000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));

  EXPECT_FALSE(helper.callback_reused_error());

  entry->Doom();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, InternalAsyncIO) {
  InitCache();
  InternalAsyncIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyInternalAsyncIO) {
  SetMemoryOnlyMode();
  InitCache();
  InternalAsyncIO();
}

// This part of the test runs on the background thread.
void DiskCacheEntryTest::ExternalSyncIOBackground(disk_cache::Entry* entry) {
  const int kSize1 = 17000;
  const int kSize2 = 25000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);
  base::strlcpy(buffer1->data(), "the data", kSize1);
  EXPECT_EQ(17000, entry->WriteData(0, 0, buffer1.get(), kSize1,
                                    net::CompletionOnceCallback(), false));
  memset(buffer1->data(), 0, kSize1);
  EXPECT_EQ(17000, entry->ReadData(0, 0, buffer1.get(), kSize1,
                                   net::CompletionOnceCallback()));
  EXPECT_STREQ("the data", buffer1->data());

  base::strlcpy(buffer2->data(), "The really big data goes here", kSize2);
  EXPECT_EQ(25000, entry->WriteData(1, 10000, buffer2.get(), kSize2,
                                    net::CompletionOnceCallback(), false));
  memset(buffer2->data(), 0, kSize2);
  EXPECT_EQ(24989, entry->ReadData(1, 10011, buffer2.get(), kSize2,
                                   net::CompletionOnceCallback()));
  EXPECT_STREQ("big data goes here", buffer2->data());
  EXPECT_EQ(25000, entry->ReadData(1, 0, buffer2.get(), kSize2,
                                   net::CompletionOnceCallback()));
  EXPECT_EQ(5000, entry->ReadData(1, 30000, buffer2.get(), kSize2,
                                  net::CompletionOnceCallback()));

  EXPECT_EQ(0, entry->ReadData(1, 35000, buffer2.get(), kSize2,
                               net::CompletionOnceCallback()));
  EXPECT_EQ(17000, entry->ReadData(1, 0, buffer1.get(), kSize1,
                                   net::CompletionOnceCallback()));
  EXPECT_EQ(17000, entry->WriteData(1, 20000, buffer1.get(), kSize1,
                                    net::CompletionOnceCallback(), false));
  EXPECT_EQ(37000, entry->GetDataSize(1));

  // We need to delete the memory buffer on this thread.
  EXPECT_EQ(0, entry->WriteData(0, 0, nullptr, 0, net::CompletionOnceCallback(),
                                true));
  EXPECT_EQ(0, entry->WriteData(1, 0, nullptr, 0, net::CompletionOnceCallback(),
                                true));
}

void DiskCacheEntryTest::ExternalSyncIO() {
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());

  // The bulk of the test runs from within the callback, on the cache thread.
  RunTaskForTest(base::BindOnce(&DiskCacheEntryTest::ExternalSyncIOBackground,
                                base::Unretained(this), entry));

  entry->Doom();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, ExternalSyncIO) {
  InitCache();
  ExternalSyncIO();
}

TEST_F(DiskCacheEntryTest, ExternalSyncIONoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  ExternalSyncIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyExternalSyncIO) {
  SetMemoryOnlyMode();
  InitCache();
  ExternalSyncIO();
}

void DiskCacheEntryTest::ExternalAsyncIO() {
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());

  int expected = 0;

  MessageLoopHelper helper;
  // Let's verify that each IO goes to the right callback object.
  CallbackTest callback1(&helper, false);
  CallbackTest callback2(&helper, false);
  CallbackTest callback3(&helper, false);
  CallbackTest callback4(&helper, false);
  CallbackTest callback5(&helper, false);
  CallbackTest callback6(&helper, false);
  CallbackTest callback7(&helper, false);
  CallbackTest callback8(&helper, false);
  CallbackTest callback9(&helper, false);

  const int kSize1 = 17000;
  const int kSize2 = 25000;
  const int kSize3 = 25000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);
  auto buffer3 = base::MakeRefCounted<net::IOBufferWithSize>(kSize3);
  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  CacheTestFillBuffer(buffer2->data(), kSize2, false);
  CacheTestFillBuffer(buffer3->data(), kSize3, false);
  base::strlcpy(buffer1->data(), "the data", kSize1);
  int ret = entry->WriteData(
      0, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback1)), false);
  EXPECT_TRUE(17000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));

  memset(buffer2->data(), 0, kSize1);
  ret = entry->ReadData(
      0, 0, buffer2.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback2)));
  EXPECT_TRUE(17000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_STREQ("the data", buffer2->data());

  base::strlcpy(buffer2->data(), "The really big data goes here", kSize2);
  ret = entry->WriteData(
      1, 10000, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback3)), false);
  EXPECT_TRUE(25000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));

  memset(buffer3->data(), 0, kSize3);
  ret = entry->ReadData(
      1, 10011, buffer3.get(), kSize3,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback4)));
  EXPECT_TRUE(24989 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_STREQ("big data goes here", buffer3->data());
  ret = entry->ReadData(
      1, 0, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback5)));
  EXPECT_TRUE(25000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  memset(buffer3->data(), 0, kSize3);
  EXPECT_EQ(0, memcmp(buffer2->data(), buffer3->data(), 10000));
  ret = entry->ReadData(
      1, 30000, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback6)));
  EXPECT_TRUE(5000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->ReadData(
      1, 35000, buffer2.get(), kSize2,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback7)));
  EXPECT_TRUE(0 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  ret = entry->ReadData(
      1, 0, buffer1.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback8)));
  EXPECT_TRUE(17000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;
  ret = entry->WriteData(
      1, 20000, buffer3.get(), kSize1,
      base::BindOnce(&CallbackTest::Run, base::Unretained(&callback9)), false);
  EXPECT_TRUE(17000 == ret || net::ERR_IO_PENDING == ret);
  if (net::ERR_IO_PENDING == ret)
    expected++;

  EXPECT_TRUE(helper.WaitUntilCacheIoFinished(expected));
  EXPECT_EQ(37000, entry->GetDataSize(1));

  EXPECT_FALSE(helper.callback_reused_error());

  entry->Doom();
  entry->Close();
  FlushQueueForTest();
  EXPECT_EQ(0, cache_->GetEntryCount());
}

TEST_F(DiskCacheEntryTest, ExternalAsyncIO) {
  InitCache();
  ExternalAsyncIO();
}

// TODO(http://crbug.com/497101): This test is flaky.
#if BUILDFLAG(IS_IOS)
#define MAYBE_ExternalAsyncIONoBuffer DISABLED_ExternalAsyncIONoBuffer
#else
#define MAYBE_ExternalAsyncIONoBuffer ExternalAsyncIONoBuffer
#endif
TEST_F(DiskCacheEntryTest, MAYBE_ExternalAsyncIONoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  ExternalAsyncIO();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyExternalAsyncIO) {
  SetMemoryOnlyMode();
  InitCache();
  ExternalAsyncIO();
}

// Tests that IOBuffers are not referenced after IO completes.
void DiskCacheEntryTest::ReleaseBuffer(int stream_index) {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);

  const int kBufferSize = 1024;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  CacheTestFillBuffer(buffer->data(), kBufferSize, false);

  net::ReleaseBufferCompletionCallback cb(buffer.get());
  int rv = entry->WriteData(
      stream_index, 0, buffer.get(), kBufferSize, cb.callback(), false);
  EXPECT_EQ(kBufferSize, cb.GetResult(rv));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, ReleaseBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  ReleaseBuffer(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyReleaseBuffer) {
  SetMemoryOnlyMode();
  InitCache();
  ReleaseBuffer(0);
}

void DiskCacheEntryTest::StreamAccess() {
  disk_cache::Entry* entry = nullptr;
  ASSERT_THAT(CreateEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);

  const int kBufferSize = 1024;
  const int kNumStreams = 3;
  scoped_refptr<net::IOBuffer> reference_buffers[kNumStreams];
  for (auto& reference_buffer : reference_buffers) {
    reference_buffer = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
    CacheTestFillBuffer(reference_buffer->data(), kBufferSize, false);
  }
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kBufferSize);
  for (int i = 0; i < kNumStreams; i++) {
    EXPECT_EQ(
        kBufferSize,
        WriteData(entry, i, 0, reference_buffers[i].get(), kBufferSize, false));
    memset(buffer1->data(), 0, kBufferSize);
    EXPECT_EQ(kBufferSize, ReadData(entry, i, 0, buffer1.get(), kBufferSize));
    EXPECT_EQ(
        0, memcmp(reference_buffers[i]->data(), buffer1->data(), kBufferSize));
  }
  EXPECT_EQ(net::ERR_INVALID_ARGUMENT,
            ReadData(entry, kNumStreams, 0, buffer1.get(), kBufferSize));
  entry->Close();

  // Open the entry and read it in chunks, including a read past the end.
  ASSERT_THAT(OpenEntry("the first key", &entry), IsOk());
  ASSERT_TRUE(nullptr != entry);
  const int kReadBufferSize = 600;
  const int kFinalReadSize = kBufferSize - kReadBufferSize;
  static_assert(kFinalReadSize < kReadBufferSize,
                "should be exactly two reads");
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kReadBufferSize);
  for (int i = 0; i < kNumStreams; i++) {
    memset(buffer2->data(), 0, kReadBufferSize);
    EXPECT_EQ(kReadBufferSize,
              ReadData(entry, i, 0, buffer2.get(), kReadBufferSize));
    EXPECT_EQ(
        0,
        memcmp(reference_buffers[i]->data(), buffer2->data(), kReadBufferSize));

    memset(buffer2->data(), 0, kReadBufferSize);
    EXPECT_EQ(
        kFinalReadSize,
        ReadData(entry, i, kReadBufferSize, buffer2.get(), kReadBufferSize));
    EXPECT_EQ(0,
              memcmp(reference_buffers[i]->data() + kReadBufferSize,
                     buffer2->data(),
                     kFinalReadSize));
  }

  entry->Close();
}

TEST_F(DiskCacheEntryTest, StreamAccess) {
  InitCache();
  StreamAccess();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyStreamAccess) {
  SetMemoryOnlyMode();
  InitCache();
  StreamAccess();
}

void DiskCacheEntryTest::GetKey() {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_EQ(key, entry->GetKey()) << "short key";
  entry->Close();

  int seed = static_cast<int>(Time::Now().ToInternalValue());
  srand(seed);
  char key_buffer[20000];

  CacheTestFillBuffer(key_buffer, 3000, true);
  key_buffer[1000] = '\0';

  key = key_buffer;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_TRUE(key == entry->GetKey()) << "1000 bytes key";
  entry->Close();

  key_buffer[1000] = 'p';
  key_buffer[3000] = '\0';
  key = key_buffer;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_TRUE(key == entry->GetKey()) << "medium size key";
  entry->Close();

  CacheTestFillBuffer(key_buffer, sizeof(key_buffer), true);
  key_buffer[19999] = '\0';

  key = key_buffer;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_TRUE(key == entry->GetKey()) << "long key";
  entry->Close();

  CacheTestFillBuffer(key_buffer, 0x4000, true);
  key_buffer[0x4000] = '\0';

  key = key_buffer;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_TRUE(key == entry->GetKey()) << "16KB key";
  entry->Close();
}

TEST_F(DiskCacheEntryTest, GetKey) {
  InitCache();
  GetKey();
}

TEST_F(DiskCacheEntryTest, MemoryOnlyGetKey) {
  SetMemoryOnlyMode();
  InitCache();
  GetKey();
}

void DiskCacheEntryTest::GetTimes(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;

  Time t1 = Time::Now();
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());
  EXPECT_TRUE(entry->GetLastModified() >= t1);
  EXPECT_TRUE(entry->GetLastModified() == entry->GetLastUsed());

  AddDelay();
  Time t2 = Time::Now();
  EXPECT_TRUE(t2 > t1);
  EXPECT_EQ(0, WriteData(entry, stream_index, 200, nullptr, 0, false));
  if (type_ == net::APP_CACHE) {
    EXPECT_TRUE(entry->GetLastModified() < t2);
  } else {
    EXPECT_TRUE(entry->GetLastModified() >= t2);
  }
  EXPECT_TRUE(entry->GetLastModified() == entry->GetLastUsed());

  AddDelay();
  Time t3 = Time::Now();
  EXPECT_TRUE(t3 > t2);
  const int kSize = 200;
  auto buffer = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  EXPECT_EQ(kSize, ReadData(entry, stream_index, 0, buffer.get(), kSize));
  if (type_ == net::APP_CACHE) {
    EXPECT_TRUE(entry->GetLastUsed() < t2);
    EXPECT_TRUE(entry->GetLastModified() < t2);
  } else if (type_ == net::SHADER_CACHE) {
    EXPECT_TRUE(entry->GetLastUsed() < t3);
    EXPECT_TRUE(entry->GetLastModified() < t3);
  } else {
    EXPECT_TRUE(entry->GetLastUsed() >= t3);
    EXPECT_TRUE(entry->GetLastModified() < t3);
  }
  entry->Close();
}

TEST_F(DiskCacheEntryTest, GetTimes) {
  InitCache();
  GetTimes(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyGetTimes) {
  SetMemoryOnlyMode();
  InitCache();
  GetTimes(0);
}

TEST_F(DiskCacheEntryTest, AppCacheGetTimes) {
  SetCacheType(net::APP_CACHE);
  InitCache();
  GetTimes(0);
}

TEST_F(DiskCacheEntryTest, ShaderCacheGetTimes) {
  SetCacheType(net::SHADER_CACHE);
  InitCache();
  GetTimes(0);
}

void DiskCacheEntryTest::GrowData(int stream_index) {
  std::string key1("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key1, &entry), IsOk());

  const int kSize = 20000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize);
  CacheTestFillBuffer(buffer1->data(), kSize, false);
  memset(buffer2->data(), 0, kSize);

  base::strlcpy(buffer1->data(), "the data", kSize);
  EXPECT_EQ(10, WriteData(entry, stream_index, 0, buffer1.get(), 10, false));
  EXPECT_EQ(10, ReadData(entry, stream_index, 0, buffer2.get(), 10));
  EXPECT_STREQ("the data", buffer2->data());
  EXPECT_EQ(10, entry->GetDataSize(stream_index));

  EXPECT_EQ(2000,
            WriteData(entry, stream_index, 0, buffer1.get(), 2000, false));
  EXPECT_EQ(2000, entry->GetDataSize(stream_index));
  EXPECT_EQ(2000, ReadData(entry, stream_index, 0, buffer2.get(), 2000));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), 2000));

  EXPECT_EQ(20000,
            WriteData(entry, stream_index, 0, buffer1.get(), kSize, false));
  EXPECT_EQ(20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(20000, ReadData(entry, stream_index, 0, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), kSize));
  entry->Close();

  memset(buffer2->data(), 0, kSize);
  std::string key2("Second key");
  ASSERT_THAT(CreateEntry(key2, &entry), IsOk());
  EXPECT_EQ(10, WriteData(entry, stream_index, 0, buffer1.get(), 10, false));
  EXPECT_EQ(10, entry->GetDataSize(stream_index));
  entry->Close();

  // Go from an internal address to a bigger block size.
  ASSERT_THAT(OpenEntry(key2, &entry), IsOk());
  EXPECT_EQ(2000,
            WriteData(entry, stream_index, 0, buffer1.get(), 2000, false));
  EXPECT_EQ(2000, entry->GetDataSize(stream_index));
  EXPECT_EQ(2000, ReadData(entry, stream_index, 0, buffer2.get(), 2000));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), 2000));
  entry->Close();
  memset(buffer2->data(), 0, kSize);

  // Go from an internal address to an external one.
  ASSERT_THAT(OpenEntry(key2, &entry), IsOk());
  EXPECT_EQ(20000,
            WriteData(entry, stream_index, 0, buffer1.get(), kSize, false));
  EXPECT_EQ(20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(20000, ReadData(entry, stream_index, 0, buffer2.get(), kSize));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), kSize));
  entry->Close();

  // Double check the size from disk.
  ASSERT_THAT(OpenEntry(key2, &entry), IsOk());
  EXPECT_EQ(20000, entry->GetDataSize(stream_index));

  // Now extend the entry without actual data.
  EXPECT_EQ(0, WriteData(entry, stream_index, 45500, buffer1.get(), 0, false));
  entry->Close();

  // And check again from disk.
  ASSERT_THAT(OpenEntry(key2, &entry), IsOk());
  EXPECT_EQ(45500, entry->GetDataSize(stream_index));
  entry->Close();
}

TEST_F(DiskCacheEntryTest, GrowData) {
  InitCache();
  GrowData(0);
}

TEST_F(DiskCacheEntryTest, GrowDataNoBuffer) {
  InitCache();
  cache_impl_->SetFlags(disk_cache::kNoBuffering);
  GrowData(0);
}

TEST_F(DiskCacheEntryTest, MemoryOnlyGrowData) {
  SetMemoryOnlyMode();
  InitCache();
  GrowData(0);
}

void DiskCacheEntryTest::TruncateData(int stream_index) {
  std::string key("the first key");
  disk_cache::Entry* entry;
  ASSERT_THAT(CreateEntry(key, &entry), IsOk());

  const int kSize1 = 20000;
  const int kSize2 = 20000;
  auto buffer1 = base::MakeRefCounted<net::IOBufferWithSize>(kSize1);
  auto buffer2 = base::MakeRefCounted<net::IOBufferWithSize>(kSize2);

  CacheTestFillBuffer(buffer1->data(), kSize1, false);
  memset(buffer2->data(), 0, kSize2);

  // Simple truncation:
  EXPECT_EQ(200, WriteData(entry, stream_index, 0, buffer1.get(), 200, false));
  EXPECT_EQ(200, entry->GetDataSize(stream_index));
  EXPECT_EQ(100, WriteData(entry, stream_index, 0, buffer1.get(), 100, false));
  EXPECT_EQ(200, entry->GetDataSize(stream_index));
  EXPECT_EQ(100, WriteData(entry, stream_index, 0, buffer1.get(), 100, true));
  EXPECT_EQ(100, entry->GetDataSize(stream_index));
  EXPECT_EQ(0, WriteData(entry, stream_index, 50, buffer1.get(), 0, true));
  EXPECT_EQ(50, entry->GetDataSize(stream_index));
  EXPECT_EQ(0, WriteData(entry, stream_index, 0, buffer1.get(), 0, true));
  EXPECT_EQ(0, entry->GetDataSize(stream_index));
  entry->Close();
  ASSERT_THAT(OpenEntry(key, &entry), IsOk());

  // Go to an external file.
  EXPECT_EQ(20000,
            WriteData(entry, stream_index, 0, buffer1.get(), 20000, true));
  EXPECT_EQ(20000, entry->GetDataSize(stream_index));
  EXPECT_EQ(20000, ReadData(entry, stream_index, 0, buffer2.get(), 20000));
  EXPECT_TRUE(!memcmp(buffer1->data(), buffer2->data(), 20000));
  memset(buffer2->data(), 0, kSize2);

  // External file truncation
  EXPECT_EQ(18000,
            WriteData(entry, stream_index, 0, buffer1.get(), 18000, false));
  EXPECT_EQ(
"""


```