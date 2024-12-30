Response:
The user wants to understand the functionality of the `simple_synchronous_entry.cc` file in the Chromium network stack. They're interested in its relationship to JavaScript, examples of logical reasoning with input/output, common user/programming errors, debugging steps, and a general summary of its function.

**Plan:**

1. **High-level Functionality:**  Identify the primary purpose of this file. It seems to manage synchronous operations on cache entries at the file system level.
2. **Relationship to JavaScript:** Analyze the code for any direct interaction with JavaScript. Given this is a low-level caching mechanism, direct interaction is unlikely, but I need to consider indirect connections (e.g., caching resources requested by JavaScript).
3. **Logical Reasoning:** Examine specific functions for their logic and provide hypothetical inputs and outputs. Focus on functions related to reading and writing data.
4. **Common Errors:**  Look for error handling patterns and potential pitfalls for developers or users.
5. **Debugging Steps:** Infer how a user action might lead to this code being executed.
6. **Summary:** Condense the findings into a concise description of the file's function.
This C++ code file `simple_synchronous_entry.cc` within Chromium's network stack is responsible for managing synchronous (blocking) operations on individual entries within the simple disk cache. It handles the low-level details of reading and writing data to the cache files on disk.

**Functionality:**

Here's a breakdown of the key functionalities of this file:

* **Entry Management:**
    * **Opening Entries:**  `OpenEntry` attempts to open an existing cache entry on disk. It retrieves metadata and potentially prefetches data.
    * **Creating Entries:** `CreateEntry` creates a new cache entry on disk, allocating necessary files and writing initial metadata.
    * **Opening or Creating Entries:** `OpenOrCreateEntry` tries to open an existing entry and creates it if it doesn't exist. This function handles potential race conditions and index inconsistencies.
    * **Deleting Entries:** `DeleteEntryFiles` and `DeleteEntrySetFiles` handle the deletion of the physical files associated with one or more cache entries.
    * **Dooming Entries:** `Doom` marks an entry as invalid. This typically involves renaming the files to prevent further access and allows for eventual cleanup.
    * **Truncating Entries:** `TruncateEntryFiles` reduces the size of the files associated with an entry.

* **Data Operations:**
    * **Reading Data:** `ReadData` reads data from a specific stream within a cache entry's file. It can also verify checksums (CRCs).
    * **Writing Data:** `WriteData` writes data to a specific stream within a cache entry's file. It handles extending files, truncating data, and updating checksums.
    * **Reading Sparse Data:** `ReadSparseData` reads data from sparse regions of a cache entry (if supported).
    * **Writing Sparse Data:** `WriteSparseData` writes data to sparse regions of a cache entry.

* **Prefetching:**
    * Implements logic for prefetching data from cache files when an entry is opened, potentially based on heuristics or hints.

* **Metadata Handling:**
    * Manages the `SimpleEntryStat` structure, which holds metadata like last used time, last modified time, and data sizes of the streams.
    * Writes and reads headers containing metadata and a key hash for integrity checks.

* **File System Interaction:**
    * Uses the `BackendFileOperations` interface to interact with the file system (opening, reading, writing, deleting, renaming files). This provides an abstraction layer for different file system implementations.

* **Checksum (CRC) Handling:**
    *  Calculates and verifies CRC32 checksums of data streams to ensure data integrity.

* **SHA-256 Key Hashing:**
    * Calculates the SHA-256 hash of the cache entry's key for integrity verification.

**Relationship to JavaScript:**

This C++ code doesn't directly interact with JavaScript code. However, it plays a crucial role in how web resources (which are often requested and used by JavaScript) are cached by the browser.

**Example:**

1. When a JavaScript application running in a web page makes an HTTP request for an image:
2. The browser's network stack checks the disk cache for this resource.
3. If the resource is found in the simple disk cache, the `OpenEntry` function (or `OpenOrCreateEntry`) in this file might be called to access the cached data.
4. Subsequently, `ReadData` would be used to read the image data from the cache files on disk.
5. This cached data is then provided back to the browser to render the image in the web page, which was originally triggered by the JavaScript request.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider the `ReadData` function:

**Hypothetical Input:**

* `in_entry_op`:
    * `index`: 1 (representing the main response body stream)
    * `offset`: 1024 (read starting from the 1024th byte of the stream)
    * `buf_len`: 512 (read 512 bytes)
    * `previous_crc32`: 0 (assuming this is the first read, or the CRC from a previous read)
    * `request_update_crc`: true (calculate and return the CRC of the read data)
    * `request_verify_crc`: false (don't verify against the EOF CRC in this call)
* `entry_stat`: A `SimpleEntryStat` object containing the current metadata of the cache entry, including the size of stream 1.
* `out_buf`: An `IOBuffer` with a size of at least 512 bytes.

**Hypothetical Output:**

* `out_result`:
    * `result`: 512 (the number of bytes successfully read)
    * `updated_crc32`: The CRC32 checksum calculated for the 512 bytes read from the file.
    * `crc_updated`: true

**Assumptions:**

* The cache entry exists and is valid.
* The offset and length are within the bounds of the data stream.
* The underlying file read operation is successful.

**Common User or Programming Errors:**

* **Cache Corruption:** If the underlying file system has errors or if the caching logic has bugs, the cache files can become corrupted. This could lead to `ReadData` or `WriteData` failing with errors like `net::ERR_CACHE_READ_FAILURE` or `net::ERR_CACHE_WRITE_FAILURE`.
* **Incorrect Offset or Length:** Providing an invalid offset or length to `ReadData` or `WriteData` (e.g., reading beyond the end of the stream) can lead to errors or unexpected behavior. While the code has checks, developers using the cache API need to be careful.
* **Concurrent Access Issues (though this file aims for synchronous operations):** While this file handles synchronous operations, higher-level code using the cache might introduce concurrency issues if not managed properly. This could lead to data corruption or unexpected states.
* **Disk Space Exhaustion:** If the disk is full, writing to the cache will fail. The code handles these errors, but the user experience might be negatively impacted.
* **Permissions Issues:** If the browser process doesn't have the necessary permissions to access the cache directory, operations will fail.

**User Operations Leading to This Code (Debugging Clues):**

Let's say a user is browsing a website and views an image:

1. **User Types URL or Clicks a Link:** The browser initiates a network request for the web page and its resources, including the image.
2. **Browser Checks Cache:** Before making a network request, the browser's network stack checks the disk cache (the "simple cache" in this case) to see if the image is already present.
3. **Cache Lookup:** The browser calculates a key for the image URL and looks it up in the cache index.
4. **Cache Hit:** If the image is found in the index, the browser knows the location of the cached data on disk.
5. **`OpenEntry` or `OpenOrCreateEntry` is Called:** The browser calls `SimpleSynchronousEntry::OpenEntry` (or `OpenOrCreateEntry` if it's unsure) to access the cache entry for the image. This function uses the entry's hash to locate the corresponding files.
6. **`ReadData` is Called:** Once the entry is opened, the browser calls `SimpleSynchronousEntry::ReadData` to read the image data from the cache files.
7. **Image Rendering:** The retrieved image data is then used to render the image on the user's screen.

If the image was not in the cache initially:

1. **Network Request:** The browser makes a network request to the server.
2. **Response Received:** The server sends the image data.
3. **`CreateEntry` is Called:** The browser calls `SimpleSynchronousEntry::CreateEntry` to create a new cache entry for the image.
4. **`WriteData` is Called:** The browser calls `SimpleSynchronousEntry::WriteData` repeatedly to write the received image data into the cache files.

**Summary of Functionality (Part 1):**

The `simple_synchronous_entry.cc` file provides the core logic for performing synchronous read, write, open, create, delete, and doom operations on individual entries within Chromium's simple disk cache. It directly interacts with the file system through the `BackendFileOperations` interface and handles metadata management, checksum calculations, and prefetching. This file is a fundamental building block for the browser's caching mechanism, enabling efficient retrieval of web resources.

Prompt: 
```
这是目录为net/disk_cache/simple/simple_synchronous_entry.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/disk_cache/simple/simple_synchronous_entry.h"

#include <cstring>
#include <functional>
#include <limits>
#include <optional>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/files/file_util.h"
#include "base/hash/hash.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/histogram_macros_local.h"
#include "base/numerics/checked_math.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/task/sequenced_task_runner.h"
#include "base/timer/elapsed_timer.h"
#include "crypto/secure_hash.h"
#include "net/base/hash_value.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/simple/simple_backend_version.h"
#include "net/disk_cache/simple/simple_histogram_enums.h"
#include "net/disk_cache/simple/simple_histogram_macros.h"
#include "net/disk_cache/simple/simple_util.h"
#include "third_party/abseil-cpp/absl/container/inlined_vector.h"
#include "third_party/zlib/zlib.h"

using base::FilePath;
using base::Time;

namespace disk_cache {

namespace {

void RecordSyncOpenResult(net::CacheType cache_type, OpenEntryResult result) {
  DCHECK_LT(result, OPEN_ENTRY_MAX);
  SIMPLE_CACHE_LOCAL(ENUMERATION, "SyncOpenResult", cache_type, result,
                     OPEN_ENTRY_MAX);
}

void RecordWriteResult(net::CacheType cache_type, SyncWriteResult result) {
  SIMPLE_CACHE_LOCAL(ENUMERATION, "SyncWriteResult", cache_type, result,
                     SYNC_WRITE_RESULT_MAX);
}

void RecordCheckEOFResult(net::CacheType cache_type, CheckEOFResult result) {
  SIMPLE_CACHE_LOCAL(ENUMERATION, "SyncCheckEOFResult", cache_type, result,
                     CHECK_EOF_RESULT_MAX);
}

void RecordCloseResult(net::CacheType cache_type, CloseResult result) {
  SIMPLE_CACHE_LOCAL(ENUMERATION, "SyncCloseResult", cache_type, result,
                     CLOSE_RESULT_MAX);
}

void RecordOpenPrefetchMode(net::CacheType cache_type, OpenPrefetchMode mode) {
  SIMPLE_CACHE_UMA(ENUMERATION, "SyncOpenPrefetchMode", cache_type, mode,
                   OPEN_PREFETCH_MAX);
}

void RecordDiskCreateLatency(net::CacheType cache_type, base::TimeDelta delay) {
  SIMPLE_CACHE_LOCAL(TIMES, "DiskCreateLatency", cache_type, delay);
}

bool CanOmitEmptyFile(int file_index) {
  DCHECK_GE(file_index, 0);
  DCHECK_LT(file_index, kSimpleEntryNormalFileCount);
  return file_index == simple_util::GetFileIndexFromStreamIndex(2);
}

bool TruncatePath(const FilePath& filename_to_truncate,
                  BackendFileOperations* file_operations) {
  int flags = base::File::FLAG_OPEN | base::File::FLAG_READ |
              base::File::FLAG_WRITE | base::File::FLAG_WIN_SHARE_DELETE;
  base::File file_to_truncate =
      file_operations->OpenFile(filename_to_truncate, flags);
  if (!file_to_truncate.IsValid())
    return false;
  if (!file_to_truncate.SetLength(0))
    return false;
  return true;
}

void CalculateSHA256OfKey(const std::string& key,
                          net::SHA256HashValue* out_hash_value) {
  std::unique_ptr<crypto::SecureHash> hash(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));
  hash->Update(key.data(), key.size());
  hash->Finish(out_hash_value, sizeof(*out_hash_value));
}

SimpleFileTracker::SubFile SubFileForFileIndex(int file_index) {
  DCHECK_GT(kSimpleEntryNormalFileCount, file_index);
  return file_index == 0 ? SimpleFileTracker::SubFile::FILE_0
                         : SimpleFileTracker::SubFile::FILE_1;
}

int FileIndexForSubFile(SimpleFileTracker::SubFile sub_file) {
  DCHECK_NE(SimpleFileTracker::SubFile::FILE_SPARSE, sub_file);
  return sub_file == SimpleFileTracker::SubFile::FILE_0 ? 0 : 1;
}

}  // namespace

// Helper class to track a range of data prefetched from a file.
class SimpleSynchronousEntry::PrefetchData final {
 public:
  explicit PrefetchData(size_t file_size)
      : file_size_(file_size), earliest_requested_offset_(file_size) {}

  // Returns true if the specified range within the file has been completely
  // prefetched.  Returns false if any part of the range has not been
  // prefetched.
  bool HasData(size_t offset, size_t length) {
    size_t end = 0;
    if (!base::CheckAdd(offset, length).AssignIfValid(&end))
      return false;
    UpdateEarliestOffset(offset);
    return offset >= offset_in_file_ &&
           end <= (offset_in_file_ + buffer_.size());
  }

  // Read the given range out of the prefetch buffer into the target
  // destination buffer.  If the range is not wholely contained within
  // the prefetch buffer than no data will be written to the target
  // buffer.  Returns true if the range has been copied.
  bool ReadData(size_t offset, size_t length, char* dest) {
    DCHECK(dest);
    if (!length)
      return true;
    if (!HasData(offset, length))
      return false;
    DCHECK(offset >= offset_in_file_);
    size_t buffer_offset = offset - offset_in_file_;
    memcpy(dest, buffer_.data() + buffer_offset, length);
    return true;
  }

  // Populate the prefetch buffer from the given file and range.  Returns
  // true if the data is successfully read.
  bool PrefetchFromFile(SimpleFileTracker::FileHandle* file,
                        size_t offset,
                        size_t length) {
    DCHECK(file);
    if (!buffer_.empty()) {
      return false;
    }
    buffer_.resize(length);
    if (file->get()->Read(offset, buffer_.data(), length) !=
        static_cast<int>(length)) {
      buffer_.resize(0);
      return false;
    }
    offset_in_file_ = offset;
    return true;
  }

  // Return how much trailing data has been requested via HasData() or
  // ReadData().  The intent is that this value can be used to tune
  // future prefetching behavior.
  size_t GetDesiredTrailerPrefetchSize() const {
    return file_size_ - earliest_requested_offset_;
  }

 private:
  // Track the earliest offset requested in order to return an optimal trailer
  // prefetch amount in GetDesiredTrailerPrefetchSize().
  void UpdateEarliestOffset(size_t offset) {
    DCHECK_LE(earliest_requested_offset_, file_size_);
    earliest_requested_offset_ = std::min(earliest_requested_offset_, offset);
  }

  const size_t file_size_;

  // Prefer to read the prefetch data into a stack buffer to minimize
  // memory pressure on the OS disk cache.
  absl::InlinedVector<char, 1024> buffer_;
  size_t offset_in_file_ = 0;

  size_t earliest_requested_offset_;
};

class SimpleSynchronousEntry::ScopedFileOperationsBinding final {
 public:
  ScopedFileOperationsBinding(SimpleSynchronousEntry* owner,
                              BackendFileOperations** file_operations)
      : owner_(owner),
        file_operations_(owner->unbound_file_operations_->Bind(
            base::SequencedTaskRunner::GetCurrentDefault())) {
    *file_operations = file_operations_.get();
  }
  ~ScopedFileOperationsBinding() {
    owner_->unbound_file_operations_ = file_operations_->Unbind();
  }

 private:
  const raw_ptr<SimpleSynchronousEntry> owner_;
  std::unique_ptr<BackendFileOperations> file_operations_;
};

using simple_util::GetEntryHashKey;
using simple_util::GetFilenameFromEntryFileKeyAndFileIndex;
using simple_util::GetSparseFilenameFromEntryFileKey;
using simple_util::GetHeaderSize;
using simple_util::GetDataSizeFromFileSize;
using simple_util::GetFileSizeFromDataSize;
using simple_util::GetFileIndexFromStreamIndex;

BASE_FEATURE(kSimpleCachePrefetchExperiment,
             "SimpleCachePrefetchExperiment2",
             base::FEATURE_DISABLED_BY_DEFAULT);

const char kSimpleCacheFullPrefetchBytesParam[] = "FullPrefetchBytes";
constexpr base::FeatureParam<int> kSimpleCacheFullPrefetchSize{
    &kSimpleCachePrefetchExperiment, kSimpleCacheFullPrefetchBytesParam, 0};

const char kSimpleCacheTrailerPrefetchSpeculativeBytesParam[] =
    "TrailerPrefetchSpeculativeBytes";
constexpr base::FeatureParam<int> kSimpleCacheTrailerPrefetchSpeculativeBytes{
    &kSimpleCachePrefetchExperiment,
    kSimpleCacheTrailerPrefetchSpeculativeBytesParam, 0};

int GetSimpleCacheFullPrefetchSize() {
  return kSimpleCacheFullPrefetchSize.Get();
}

int GetSimpleCacheTrailerPrefetchSize(int hint_size) {
  if (hint_size > 0)
    return hint_size;
  return kSimpleCacheTrailerPrefetchSpeculativeBytes.Get();
}

SimpleEntryStat::SimpleEntryStat(base::Time last_used,
                                 base::Time last_modified,
                                 const int32_t data_size[],
                                 const int32_t sparse_data_size)
    : last_used_(last_used),
      last_modified_(last_modified),
      sparse_data_size_(sparse_data_size) {
  memcpy(data_size_, data_size, sizeof(data_size_));
}

// These size methods all assume the presence of the SHA256 on stream zero,
// since this version of the cache always writes it. In the read case, it may
// not be present and these methods can't be relied upon.

int SimpleEntryStat::GetOffsetInFile(size_t key_length,
                                     int offset,
                                     int stream_index) const {
  const size_t headers_size = sizeof(SimpleFileHeader) + key_length;
  const size_t additional_offset =
      stream_index == 0 ? data_size_[1] + sizeof(SimpleFileEOF) : 0;
  return headers_size + offset + additional_offset;
}

int SimpleEntryStat::GetEOFOffsetInFile(size_t key_length,
                                        int stream_index) const {
  size_t additional_offset;
  if (stream_index != 0)
    additional_offset = 0;
  else
    additional_offset = sizeof(net::SHA256HashValue);
  return additional_offset +
         GetOffsetInFile(key_length, data_size_[stream_index], stream_index);
}

int SimpleEntryStat::GetLastEOFOffsetInFile(size_t key_length,
                                            int stream_index) const {
  if (stream_index == 1)
    return GetEOFOffsetInFile(key_length, 0);
  return GetEOFOffsetInFile(key_length, stream_index);
}

int64_t SimpleEntryStat::GetFileSize(size_t key_length, int file_index) const {
  int32_t total_data_size;
  if (file_index == 0) {
    total_data_size = data_size_[0] + data_size_[1] +
                      sizeof(net::SHA256HashValue) + sizeof(SimpleFileEOF);
  } else {
    total_data_size = data_size_[2];
  }
  return GetFileSizeFromDataSize(key_length, total_data_size);
}

SimpleStreamPrefetchData::SimpleStreamPrefetchData()
    : stream_crc32(crc32(0, Z_NULL, 0)) {}

SimpleStreamPrefetchData::~SimpleStreamPrefetchData() = default;

SimpleEntryCreationResults::SimpleEntryCreationResults(
    SimpleEntryStat entry_stat)
    : sync_entry(nullptr), entry_stat(entry_stat) {}

SimpleEntryCreationResults::~SimpleEntryCreationResults() = default;

SimpleSynchronousEntry::CRCRecord::CRCRecord() : index(-1),
                                                 has_crc32(false),
                                                 data_crc32(0) {
}

SimpleSynchronousEntry::CRCRecord::CRCRecord(int index_p,
                                             bool has_crc32_p,
                                             uint32_t data_crc32_p)
    : index(index_p), has_crc32(has_crc32_p), data_crc32(data_crc32_p) {}

SimpleSynchronousEntry::ReadRequest::ReadRequest(int index_p,
                                                 int offset_p,
                                                 int buf_len_p)
    : index(index_p), offset(offset_p), buf_len(buf_len_p) {}

SimpleSynchronousEntry::WriteRequest::WriteRequest(int index_p,
                                                   int offset_p,
                                                   int buf_len_p,
                                                   uint32_t previous_crc32_p,
                                                   bool truncate_p,
                                                   bool doomed_p,
                                                   bool request_update_crc_p)
    : index(index_p),
      offset(offset_p),
      buf_len(buf_len_p),
      previous_crc32(previous_crc32_p),
      truncate(truncate_p),
      doomed(doomed_p),
      request_update_crc(request_update_crc_p) {}

SimpleSynchronousEntry::SparseRequest::SparseRequest(int64_t sparse_offset_p,
                                                     int buf_len_p)
    : sparse_offset(sparse_offset_p), buf_len(buf_len_p) {}

// static
void SimpleSynchronousEntry::OpenEntry(
    net::CacheType cache_type,
    const FilePath& path,
    const std::optional<std::string>& key,
    const uint64_t entry_hash,
    SimpleFileTracker* file_tracker,
    std::unique_ptr<UnboundBackendFileOperations> file_operations,
    int32_t trailer_prefetch_size,
    SimpleEntryCreationResults* out_results) {
  base::TimeTicks start_sync_open_entry = base::TimeTicks::Now();

  auto sync_entry = std::make_unique<SimpleSynchronousEntry>(
      cache_type, path, key, entry_hash, file_tracker,
      std::move(file_operations), trailer_prefetch_size);
  {
    BackendFileOperations* bound_file_operations = nullptr;
    ScopedFileOperationsBinding binding(sync_entry.get(),
                                        &bound_file_operations);
    out_results->result = sync_entry->InitializeForOpen(
        bound_file_operations, &out_results->entry_stat,
        out_results->stream_prefetch_data);
  }
  if (out_results->result != net::OK) {
    sync_entry->Doom();
    sync_entry->CloseFiles();
    out_results->sync_entry = nullptr;
    out_results->unbound_file_operations =
        std::move(sync_entry->unbound_file_operations_);
    out_results->stream_prefetch_data[0].data = nullptr;
    out_results->stream_prefetch_data[1].data = nullptr;
    return;
  }
  SIMPLE_CACHE_UMA(TIMES, "DiskOpenLatency", cache_type,
                   base::TimeTicks::Now() - start_sync_open_entry);
  out_results->sync_entry = sync_entry.release();
  out_results->computed_trailer_prefetch_size =
      out_results->sync_entry->computed_trailer_prefetch_size();
}

// static
void SimpleSynchronousEntry::CreateEntry(
    net::CacheType cache_type,
    const FilePath& path,
    const std::string& key,
    const uint64_t entry_hash,
    SimpleFileTracker* file_tracker,
    std::unique_ptr<UnboundBackendFileOperations> file_operations,
    SimpleEntryCreationResults* out_results) {
  DCHECK_EQ(entry_hash, GetEntryHashKey(key));
  base::TimeTicks start_sync_create_entry = base::TimeTicks::Now();

  auto sync_entry = std::make_unique<SimpleSynchronousEntry>(
      cache_type, path, key, entry_hash, file_tracker,
      std::move(file_operations), -1);
  {
    BackendFileOperations* bound_file_operations = nullptr;
    ScopedFileOperationsBinding binding(sync_entry.get(),
                                        &bound_file_operations);
    out_results->result = sync_entry->InitializeForCreate(
        bound_file_operations, &out_results->entry_stat);
  }
  if (out_results->result != net::OK) {
    if (out_results->result != net::ERR_FILE_EXISTS)
      sync_entry->Doom();
    sync_entry->CloseFiles();
    out_results->unbound_file_operations =
        std::move(sync_entry->unbound_file_operations_);
    out_results->sync_entry = nullptr;
    return;
  }
  out_results->sync_entry = sync_entry.release();
  out_results->created = true;
  RecordDiskCreateLatency(cache_type,
                          base::TimeTicks::Now() - start_sync_create_entry);
}

// static
void SimpleSynchronousEntry::OpenOrCreateEntry(
    net::CacheType cache_type,
    const FilePath& path,
    const std::string& key,
    const uint64_t entry_hash,
    OpenEntryIndexEnum index_state,
    bool optimistic_create,
    SimpleFileTracker* file_tracker,
    std::unique_ptr<UnboundBackendFileOperations> file_operations,
    int32_t trailer_prefetch_size,
    SimpleEntryCreationResults* out_results) {
  base::TimeTicks start = base::TimeTicks::Now();
  if (index_state == INDEX_MISS) {
    // Try to just create.
    auto sync_entry = std::make_unique<SimpleSynchronousEntry>(
        cache_type, path, key, entry_hash, file_tracker,
        std::move(file_operations), trailer_prefetch_size);
    {
      BackendFileOperations* bound_file_operations = nullptr;
      ScopedFileOperationsBinding binding(sync_entry.get(),
                                          &bound_file_operations);
      out_results->result = sync_entry->InitializeForCreate(
          bound_file_operations, &out_results->entry_stat);
    }
    switch (out_results->result) {
      case net::OK:
        out_results->sync_entry = sync_entry.release();
        out_results->created = true;
        RecordDiskCreateLatency(cache_type, base::TimeTicks::Now() - start);
        return;
      case net::ERR_FILE_EXISTS:
        // Our index was messed up.
        if (optimistic_create) {
          // In this case, ::OpenOrCreateEntry already returned claiming it made
          // a new entry. Try extra-hard to make that the actual case.
          sync_entry->Doom();
          sync_entry->CloseFiles();
          file_operations = std::move(sync_entry->unbound_file_operations_);
          sync_entry = nullptr;
          CreateEntry(cache_type, path, key, entry_hash, file_tracker,
                      std::move(file_operations), out_results);
          return;
        }
        // Otherwise can just try opening.
        break;
      default:
        // Trouble. Fail this time.
        sync_entry->Doom();
        sync_entry->CloseFiles();
        out_results->unbound_file_operations =
            std::move(sync_entry->unbound_file_operations_);
        return;
    }
    file_operations = std::move(sync_entry->unbound_file_operations_);
  }

  DCHECK(file_operations);
  // Try open, then if that fails create.
  OpenEntry(cache_type, path, key, entry_hash, file_tracker,
            std::move(file_operations), trailer_prefetch_size, out_results);
  if (out_results->sync_entry)
    return;
  file_operations = std::move(out_results->unbound_file_operations);
  DCHECK(file_operations);
  CreateEntry(cache_type, path, key, entry_hash, file_tracker,
              std::move(file_operations), out_results);
}

// static
int SimpleSynchronousEntry::DeleteEntryFiles(
    const FilePath& path,
    net::CacheType cache_type,
    uint64_t entry_hash,
    std::unique_ptr<UnboundBackendFileOperations> unbound_file_operations) {
  auto file_operations = unbound_file_operations->Bind(
      base::SequencedTaskRunner::GetCurrentDefault());
  return DeleteEntryFilesInternal(path, cache_type, entry_hash,
                                  file_operations.get());
}

// static
int SimpleSynchronousEntry::DeleteEntryFilesInternal(
    const FilePath& path,
    net::CacheType cache_type,
    uint64_t entry_hash,
    BackendFileOperations* file_operations) {
  base::TimeTicks start = base::TimeTicks::Now();
  const bool deleted_well =
      DeleteFilesForEntryHash(path, entry_hash, file_operations);
  SIMPLE_CACHE_UMA(TIMES, "DiskDoomLatency", cache_type,
                   base::TimeTicks::Now() - start);
  return deleted_well ? net::OK : net::ERR_FAILED;
}

int SimpleSynchronousEntry::Doom() {
  BackendFileOperations* file_operations = nullptr;
  ScopedFileOperationsBinding binding(this, &file_operations);
  return DoomInternal(file_operations);
}

int SimpleSynchronousEntry::DoomInternal(
    BackendFileOperations* file_operations) {
  if (entry_file_key_.doom_generation != 0u) {
    // Already doomed.
    return true;
  }

  if (have_open_files_) {
    base::TimeTicks start = base::TimeTicks::Now();
    bool ok = true;
    SimpleFileTracker::EntryFileKey orig_key = entry_file_key_;
    file_tracker_->Doom(this, &entry_file_key_);

    for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
      if (!empty_file_omitted_[i]) {
        base::File::Error out_error;
        FilePath old_name = path_.AppendASCII(
            GetFilenameFromEntryFileKeyAndFileIndex(orig_key, i));
        FilePath new_name = path_.AppendASCII(
            GetFilenameFromEntryFileKeyAndFileIndex(entry_file_key_, i));
        ok = file_operations->ReplaceFile(old_name, new_name, &out_error) && ok;
      }
    }

    if (sparse_file_open()) {
      base::File::Error out_error;
      FilePath old_name =
          path_.AppendASCII(GetSparseFilenameFromEntryFileKey(orig_key));
      FilePath new_name =
          path_.AppendASCII(GetSparseFilenameFromEntryFileKey(entry_file_key_));
      ok = file_operations->ReplaceFile(old_name, new_name, &out_error) && ok;
    }

    SIMPLE_CACHE_UMA(TIMES, "DiskDoomLatency", cache_type_,
                     base::TimeTicks::Now() - start);

    return ok ? net::OK : net::ERR_FAILED;
  } else {
    // No one has ever called Create or Open on us, so we don't have to worry
    // about being accessible to other ops after doom.
    return DeleteEntryFilesInternal(
        path_, cache_type_, entry_file_key_.entry_hash, file_operations);
  }
}

// static
int SimpleSynchronousEntry::TruncateEntryFiles(
    const base::FilePath& path,
    uint64_t entry_hash,
    std::unique_ptr<UnboundBackendFileOperations> unbound_file_operations) {
  auto file_operations = unbound_file_operations->Bind(
      base::SequencedTaskRunner::GetCurrentDefault());
  const bool deleted_well =
      TruncateFilesForEntryHash(path, entry_hash, file_operations.get());
  return deleted_well ? net::OK : net::ERR_FAILED;
}

// static
int SimpleSynchronousEntry::DeleteEntrySetFiles(
    const std::vector<uint64_t>* key_hashes,
    const FilePath& path,
    std::unique_ptr<UnboundBackendFileOperations> unbound_file_operations) {
  auto file_operations = unbound_file_operations->Bind(
      base::SequencedTaskRunner::GetCurrentDefault());
  const size_t did_delete_count = base::ranges::count_if(
      *key_hashes, [&path, &file_operations](const uint64_t& key_hash) {
        return SimpleSynchronousEntry::DeleteFilesForEntryHash(
            path, key_hash, file_operations.get());
      });
  return (did_delete_count == key_hashes->size()) ? net::OK : net::ERR_FAILED;
}

void SimpleSynchronousEntry::ReadData(const ReadRequest& in_entry_op,
                                      SimpleEntryStat* entry_stat,
                                      net::IOBuffer* out_buf,
                                      ReadResult* out_result) {
  DCHECK(initialized_);
  DCHECK_NE(0, in_entry_op.index);
  BackendFileOperations* file_operations = nullptr;
  ScopedFileOperationsBinding binding(this, &file_operations);
  int file_index = GetFileIndexFromStreamIndex(in_entry_op.index);
  SimpleFileTracker::FileHandle file = file_tracker_->Acquire(
      file_operations, this, SubFileForFileIndex(file_index));

  out_result->crc_updated = false;
  if (!file.IsOK() || (header_and_key_check_needed_[file_index] &&
                       !CheckHeaderAndKey(file.get(), file_index))) {
    out_result->result = net::ERR_FAILED;
    DoomInternal(file_operations);
    return;
  }
  const int64_t file_offset = entry_stat->GetOffsetInFile(
      key_->size(), in_entry_op.offset, in_entry_op.index);
  // Zero-length reads and reads to the empty streams of omitted files should
  // be handled in the SimpleEntryImpl.
  DCHECK_GT(in_entry_op.buf_len, 0);
  DCHECK(!empty_file_omitted_[file_index]);
  int bytes_read =
      file->Read(file_offset, out_buf->data(), in_entry_op.buf_len);
  if (bytes_read > 0) {
    entry_stat->set_last_used(Time::Now());
    if (in_entry_op.request_update_crc) {
      out_result->updated_crc32 = simple_util::IncrementalCrc32(
          in_entry_op.previous_crc32, out_buf->data(), bytes_read);
      out_result->crc_updated = true;
      // Verify checksum after last read, if we've been asked to.
      if (in_entry_op.request_verify_crc &&
          in_entry_op.offset + bytes_read ==
              entry_stat->data_size(in_entry_op.index)) {
        int checksum_result =
            CheckEOFRecord(file_operations, file.get(), in_entry_op.index,
                           *entry_stat, out_result->updated_crc32);
        if (checksum_result < 0) {
          out_result->result = checksum_result;
          return;
        }
      }
    }
  }
  if (bytes_read >= 0) {
    out_result->result = bytes_read;
  } else {
    out_result->result = net::ERR_CACHE_READ_FAILURE;
    DoomInternal(file_operations);
  }
}

void SimpleSynchronousEntry::WriteData(const WriteRequest& in_entry_op,
                                       net::IOBuffer* in_buf,
                                       SimpleEntryStat* out_entry_stat,
                                       WriteResult* out_write_result) {
  BackendFileOperations* file_operations = nullptr;
  ScopedFileOperationsBinding binding(this, &file_operations);
  base::ElapsedTimer write_time;
  DCHECK(initialized_);
  DCHECK_NE(0, in_entry_op.index);
  int index = in_entry_op.index;
  int file_index = GetFileIndexFromStreamIndex(index);
  if (header_and_key_check_needed_[file_index] &&
      !empty_file_omitted_[file_index]) {
    SimpleFileTracker::FileHandle file = file_tracker_->Acquire(
        file_operations, this, SubFileForFileIndex(file_index));
    if (!file.IsOK() || !CheckHeaderAndKey(file.get(), file_index)) {
      out_write_result->result = net::ERR_FAILED;
      DoomInternal(file_operations);
      return;
    }
  }
  int offset = in_entry_op.offset;
  int buf_len = in_entry_op.buf_len;
  bool truncate = in_entry_op.truncate;
  bool doomed = in_entry_op.doomed;
  size_t key_size = key_->size();
  const int64_t file_offset = out_entry_stat->GetOffsetInFile(
      key_size, in_entry_op.offset, in_entry_op.index);
  bool extending_by_write = offset + buf_len > out_entry_stat->data_size(index);

  if (empty_file_omitted_[file_index]) {
    // Don't create a new file if the entry has been doomed, to avoid it being
    // mixed up with a newly-created entry with the same key.
    if (doomed) {
      DLOG(WARNING) << "Rejecting write to lazily omitted stream "
                    << in_entry_op.index << " of doomed cache entry.";
      RecordWriteResult(cache_type_,
                        SYNC_WRITE_RESULT_LAZY_STREAM_ENTRY_DOOMED);
      out_write_result->result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
    base::File::Error error;
    if (!MaybeCreateFile(file_operations, file_index, FILE_REQUIRED, &error)) {
      RecordWriteResult(cache_type_, SYNC_WRITE_RESULT_LAZY_CREATE_FAILURE);
      DoomInternal(file_operations);
      out_write_result->result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
    if (!InitializeCreatedFile(file_operations, file_index)) {
      RecordWriteResult(cache_type_, SYNC_WRITE_RESULT_LAZY_INITIALIZE_FAILURE);
      DoomInternal(file_operations);
      out_write_result->result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
  }
  DCHECK(!empty_file_omitted_[file_index]);

  // This needs to be grabbed after the above block, since that's what may
  // create the file (for stream 2/file 1).
  SimpleFileTracker::FileHandle file = file_tracker_->Acquire(
      file_operations, this, SubFileForFileIndex(file_index));
  if (!file.IsOK()) {
    out_write_result->result = net::ERR_FAILED;
    DoomInternal(file_operations);
    return;
  }

  if (extending_by_write) {
    // The EOF record and the eventual stream afterward need to be zeroed out.
    const int64_t file_eof_offset =
        out_entry_stat->GetEOFOffsetInFile(key_size, index);
    if (!file->SetLength(file_eof_offset)) {
      RecordWriteResult(cache_type_, SYNC_WRITE_RESULT_PRETRUNCATE_FAILURE);
      DoomInternal(file_operations);
      out_write_result->result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
  }
  if (buf_len > 0) {
    if (file->Write(file_offset, in_buf->data(), buf_len) != buf_len) {
      RecordWriteResult(cache_type_, SYNC_WRITE_RESULT_WRITE_FAILURE);
      DoomInternal(file_operations);
      out_write_result->result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
  }
  if (!truncate && (buf_len > 0 || !extending_by_write)) {
    out_entry_stat->set_data_size(
        index, std::max(out_entry_stat->data_size(index), offset + buf_len));
  } else {
    out_entry_stat->set_data_size(index, offset + buf_len);
    int file_eof_offset =
        out_entry_stat->GetLastEOFOffsetInFile(key_size, index);
    if (!file->SetLength(file_eof_offset)) {
      RecordWriteResult(cache_type_, SYNC_WRITE_RESULT_TRUNCATE_FAILURE);
      DoomInternal(file_operations);
      out_write_result->result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
  }

  if (in_entry_op.request_update_crc && buf_len > 0) {
    out_write_result->updated_crc32 = simple_util::IncrementalCrc32(
        in_entry_op.previous_crc32, in_buf->data(), buf_len);
    out_write_result->crc_updated = true;
  }

  SIMPLE_CACHE_UMA(TIMES, "DiskWriteLatency", cache_type_,
                   write_time.Elapsed());
  RecordWriteResult(cache_type_, SYNC_WRITE_RESULT_SUCCESS);
  base::Time modification_time = Time::Now();
  out_entry_stat->set_last_used(modification_time);
  out_entry_stat->set_last_modified(modification_time);
  out_write_result->result = buf_len;
}

void SimpleSynchronousEntry::ReadSparseData(const SparseRequest& in_entry_op,
                                            net::IOBuffer* out_buf,
                                            base::Time* out_last_used,
                                            int* out_result) {
  DCHECK(initialized_);
  BackendFileOperations* file_operations = nullptr;
  ScopedFileOperationsBinding binding(this, &file_operations);
  int64_t offset = in_entry_op.sparse_offset;
  int buf_len = in_entry_op.buf_len;

  char* buf = out_buf->data();
  int read_so_far = 0;

  if (!sparse_file_open()) {
    *out_result = 0;
    return;
  }

  SimpleFileTracker::FileHandle sparse_file = file_tracker_->Acquire(
      file_operations, this, SimpleFileTracker::SubFile::FILE_SPARSE);
  if (!sparse_file.IsOK()) {
    DoomInternal(file_operations);
    *out_result = net::ERR_CACHE_READ_FAILURE;
    return;
  }

  // Find the first sparse range at or after the requested offset.
  auto it = sparse_ranges_.lower_bound(offset);

  if (it != sparse_ranges_.begin()) {
    // Hop back one range and read the one overlapping with the start.
    --it;
    SparseRange* found_range = &it->second;
    DCHECK_EQ(it->first, found_range->offset);
    if (found_range->offset + found_range->length > offset) {
      DCHECK_GE(found_range->length, 0);
      DCHECK_LE(found_range->length, std::numeric_limits<int32_t>::max());
      DCHECK_GE(offset - found_range->offset, 0);
      DCHECK_LE(offset - found_range->offset,
                std::numeric_limits<int32_t>::max());
      int net_offset = static_cast<int>(offset - found_range->offset);
      int range_len_after_offset =
          static_cast<int>(found_range->length - net_offset);
      DCHECK_GE(range_len_after_offset, 0);

      int len_to_read = std::min(buf_len, range_len_after_offset);
      if (!ReadSparseRange(sparse_file.get(), found_range, net_offset,
                           len_to_read, buf)) {
        DoomInternal(file_operations);
        *out_result = net::ERR_CACHE_READ_FAILURE;
        return;
      }
      read_so_far += len_to_read;
    }
    ++it;
  }

  // Keep reading until the buffer is full or there is not another contiguous
  // range.
  while (read_so_far < buf_len &&
         it != sparse_ranges_.end() &&
         it->second.offset == offset + read_so_far) {
    SparseRange* found_range = &it->second;
    DCHECK_EQ(it->first, found_range->offset);
    int range_len = base::saturated_cast<int>(found_range->length);
    int len_to_read = std::min(buf_len - read_so_far, range_len);
    if (!ReadSparseRange(sparse_file.get(), found_range, 0, len_to_read,
                         buf + read_so_far)) {
      DoomInternal(file_operations);
      *out_result = net::ERR_CACHE_READ_FAILURE;
      return;
    }
    read_so_far += len_to_read;
    ++it;
  }

  *out_result = read_so_far;
}

void SimpleSynchronousEntry::WriteSparseData(const SparseRequest& in_entry_op,
                                             net::IOBuffer* in_buf,
                                             uint64_t max_sparse_data_size,
                                             SimpleEntryStat* out_entry_stat,
                                             int* out_result) {
  DCHECK(initialized_);
  BackendFileOperations* file_operations = nullptr;
  ScopedFileOperationsBinding binding(this, &
"""


```