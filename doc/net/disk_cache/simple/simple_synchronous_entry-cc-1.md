Response:
The user wants to understand the functionality of the provided C++ code snippet from `simple_synchronous_entry.cc`.

Here's a plan to address the request:

1. **Identify the main purpose of the code:** This section seems to handle sparse file operations within the cache entry.
2. **Break down the functionality:**  Analyze the `WriteSparseData` and `GetAvailableRange` methods.
3. **Check for JavaScript relation:** Determine if these operations have any direct connection to JavaScript execution in the browser.
4. **Provide examples for logical reasoning:** Demonstrate the behavior of `WriteSparseData` and `GetAvailableRange` with hypothetical inputs and outputs.
5. **Illustrate common usage errors:** Identify potential issues users or developers might encounter while interacting with this code.
6. **Explain user operation leading to this code:** Describe how user actions in the browser can trigger these cache operations.
7. **Summarize the functionality:** Concisely describe the overall purpose of this code snippet within the context of the larger file.
这是 `net/disk_cache/simple/simple_synchronous_entry.cc` 文件的第二部分，主要涉及**稀疏数据（sparse data）的处理**。

以下是该部分代码的功能归纳：

**主要功能：稀疏文件操作**

这段代码主要负责对缓存条目中的稀疏数据进行读写和管理。稀疏文件允许在文件中存在“空洞”，这些空洞不会占用实际的磁盘空间，直到被写入数据。这对于存储只需要部分数据的大文件非常有用。

**具体功能点：**

1. **写入稀疏数据 (`WriteSparseData`):**
   - 接收写入请求，包括偏移量 (`offset`)、数据长度 (`buf_len`) 和数据缓冲区 (`buf`).
   - 检查稀疏文件是否已打开，如果未打开则尝试创建。
   - 获取稀疏文件的句柄。
   - 检查写入后的稀疏数据大小是否超过最大允许大小，如果超过则截断稀疏文件。
   - 查找与写入偏移量相关的现有稀疏数据范围 (`sparse_ranges_`)。
   - **覆盖现有范围：** 如果写入偏移量与现有范围重叠，则更新现有范围的数据。
   - **追加新范围：** 如果写入偏移量不在现有范围内，则将数据作为新的稀疏范围追加到文件中。
   - 更新条目的最后使用时间和修改时间。
   - 更新条目的稀疏数据大小 (`sparse_data_size`)。

2. **获取可用范围 (`GetAvailableRange`):**
   - 接收请求，包括起始偏移量 (`offset`) 和期望的长度 (`len`).
   - 在稀疏数据范围集合 (`sparse_ranges_`) 中查找包含或临近指定偏移量的范围。
   - 返回从指定偏移量开始的可用（已写入）数据的实际范围，包括起始偏移量和长度。

**与 JavaScript 的关系：**

直接来说，这段 C++ 代码本身不直接执行 JavaScript 代码。然而，它的功能是为浏览器缓存提供支持，而浏览器缓存存储了各种资源，其中可能包括由 JavaScript 代码生成或使用的内容。

**举例说明：**

假设一个 JavaScript 应用需要下载一个非常大的文件，但只需要文件的部分内容。浏览器可以使用 HTTP Range 请求来下载所需的部分。当这些部分数据被缓存时，`WriteSparseData` 可能会被调用来将这些片段写入到缓存条目的稀疏文件中。

**假设输入与输出（`WriteSparseData`）：**

**假设输入：**

* `in_entry_op.sparse_offset`: 1024 (从文件偏移 1024 处开始写入)
* `in_entry_op.buf_len`: 512 (写入 512 字节的数据)
* `in_buf`: 包含 512 字节数据的内存缓冲区
* `out_entry_stat->sparse_data_size()`: 2048 (当前稀疏数据大小)
* `sparse_ranges_`:  包含一个范围，例如 {offset: 512, length: 1024}

**可能的输出：**

* 如果写入操作成功，`*out_result` 将设置为 512 (写入的字节数)。
* `out_entry_stat->sparse_data_size()` 可能会增加，具体取决于是否覆盖了现有范围或追加了新范围。在这个例子中，由于写入起始于 1024，并且现有范围结束于 1536，因此部分覆盖了现有范围。
* `sparse_ranges_` 可能会被更新，例如，如果写入完全覆盖了现有范围，则该范围可能被修改。
* 如果发生错误（例如磁盘空间不足），`*out_result` 将设置为 `net::ERR_CACHE_WRITE_FAILURE`。

**假设输入与输出（`GetAvailableRange`）：**

**假设输入：**

* `in_entry_op.sparse_offset`: 768
* `in_entry_op.buf_len`: 512
* `sparse_ranges_`: 包含一个范围，例如 {offset: 512, length: 1024}

**可能的输出：**

* `*out_result`: `RangeResult(512, 512)`。这意味着从偏移 512 开始有 512 字节的可用数据，这是请求的范围与现有稀疏范围的交集。

**用户或编程常见的使用错误：**

1. **写入越界：** 尝试写入超过 `max_sparse_data_size` 的数据会导致数据被截断，这可能会导致数据不完整。
   - **示例：**  如果 `max_sparse_data_size` 为 1MB，而用户尝试写入 1.5MB 的稀疏数据。
2. **并发写入冲突：**  如果多个线程或进程同时尝试写入同一个稀疏文件的重叠区域，可能会导致数据损坏。 Chromium 的缓存机制应该会处理并发，但如果外部代码直接操作缓存文件，可能会出现问题。
3. **磁盘空间不足：**  如果磁盘空间不足，写入操作会失败，导致 `net::ERR_CACHE_WRITE_FAILURE`。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个需要下载大量资源的网页。**
2. **浏览器尝试缓存这些资源，为了节省空间，可能会使用稀疏文件来存储部分下载的资源。**
3. **如果使用了 HTTP Range 请求下载资源片段，或者资源本身支持分块加载，那么在缓存这些片段时，就会调用 `WriteSparseData`。**
4. **当 JavaScript 代码尝试读取这些缓存的资源时，如果资源是稀疏存储的，`GetAvailableRange` 可能会被调用来确定哪些部分的数据是可用的。**

**作为调试线索：**

* 如果在网络请求或缓存操作中出现数据不完整或写入失败的问题，可以检查 `WriteSparseData` 的执行情况，例如传入的偏移量、长度和当前稀疏范围。
* 如果在读取缓存资源时遇到问题，可以检查 `GetAvailableRange` 的输出，确认是否找到了预期的可用数据范围。
* 可以通过 Chrome 的内部页面 `chrome://disk-cache/` 或开发者工具的网络面板查看缓存状态和相关信息。

**功能归纳：**

总而言之，这段代码是 Chromium 缓存系统中处理稀疏文件的关键部分。它允许高效地存储和检索大型资源的片段，优化磁盘空间的使用，并支持例如 HTTP Range 请求等功能。通过 `WriteSparseData` 写入稀疏数据，并通过 `GetAvailableRange` 查询可用的数据范围，这段代码为浏览器缓存提供了灵活的存储机制。

### 提示词
```
这是目录为net/disk_cache/simple/simple_synchronous_entry.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
file_operations);
  int64_t offset = in_entry_op.sparse_offset;
  int buf_len = in_entry_op.buf_len;

  const char* buf = in_buf->data();
  int written_so_far = 0;
  int appended_so_far = 0;

  if (!sparse_file_open() && !CreateSparseFile(file_operations)) {
    DoomInternal(file_operations);
    *out_result = net::ERR_CACHE_WRITE_FAILURE;
    return;
  }
  SimpleFileTracker::FileHandle sparse_file = file_tracker_->Acquire(
      file_operations, this, SimpleFileTracker::SubFile::FILE_SPARSE);
  if (!sparse_file.IsOK()) {
    DoomInternal(file_operations);
    *out_result = net::ERR_CACHE_WRITE_FAILURE;
    return;
  }

  int32_t sparse_data_size = out_entry_stat->sparse_data_size();
  int32_t future_sparse_data_size;
  if (!base::CheckAdd(sparse_data_size, buf_len)
           .AssignIfValid(&future_sparse_data_size) ||
      future_sparse_data_size < 0) {
    DoomInternal(file_operations);
    *out_result = net::ERR_CACHE_WRITE_FAILURE;
    return;
  }
  // This is a pessimistic estimate; it assumes the entire buffer is going to
  // be appended as a new range, not written over existing ranges.
  if (static_cast<uint64_t>(future_sparse_data_size) > max_sparse_data_size) {
    DVLOG(1) << "Truncating sparse data file (" << sparse_data_size << " + "
             << buf_len << " > " << max_sparse_data_size << ")";
    TruncateSparseFile(sparse_file.get());
    out_entry_stat->set_sparse_data_size(0);
  }

  auto it = sparse_ranges_.lower_bound(offset);

  if (it != sparse_ranges_.begin()) {
    --it;
    SparseRange* found_range = &it->second;
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

      int len_to_write = std::min(buf_len, range_len_after_offset);
      if (!WriteSparseRange(sparse_file.get(), found_range, net_offset,
                            len_to_write, buf)) {
        DoomInternal(file_operations);
        *out_result = net::ERR_CACHE_WRITE_FAILURE;
        return;
      }
      written_so_far += len_to_write;
    }
    ++it;
  }

  while (written_so_far < buf_len &&
         it != sparse_ranges_.end() &&
         it->second.offset < offset + buf_len) {
    SparseRange* found_range = &it->second;
    if (offset + written_so_far < found_range->offset) {
      int len_to_append =
          static_cast<int>(found_range->offset - (offset + written_so_far));
      if (!AppendSparseRange(sparse_file.get(), offset + written_so_far,
                             len_to_append, buf + written_so_far)) {
        DoomInternal(file_operations);
        *out_result = net::ERR_CACHE_WRITE_FAILURE;
        return;
      }
      written_so_far += len_to_append;
      appended_so_far += len_to_append;
    }
    int range_len = base::saturated_cast<int>(found_range->length);
    int len_to_write = std::min(buf_len - written_so_far, range_len);
    if (!WriteSparseRange(sparse_file.get(), found_range, 0, len_to_write,
                          buf + written_so_far)) {
      DoomInternal(file_operations);
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
    written_so_far += len_to_write;
    ++it;
  }

  if (written_so_far < buf_len) {
    int len_to_append = buf_len - written_so_far;
    if (!AppendSparseRange(sparse_file.get(), offset + written_so_far,
                           len_to_append, buf + written_so_far)) {
      DoomInternal(file_operations);
      *out_result = net::ERR_CACHE_WRITE_FAILURE;
      return;
    }
    written_so_far += len_to_append;
    appended_so_far += len_to_append;
  }

  DCHECK_EQ(buf_len, written_so_far);

  base::Time modification_time = Time::Now();
  out_entry_stat->set_last_used(modification_time);
  out_entry_stat->set_last_modified(modification_time);
  int32_t old_sparse_data_size = out_entry_stat->sparse_data_size();
  out_entry_stat->set_sparse_data_size(old_sparse_data_size + appended_so_far);
  *out_result = written_so_far;
}

void SimpleSynchronousEntry::GetAvailableRange(const SparseRequest& in_entry_op,
                                               RangeResult* out_result) {
  DCHECK(initialized_);
  int64_t offset = in_entry_op.sparse_offset;
  int len = in_entry_op.buf_len;

  auto it = sparse_ranges_.lower_bound(offset);

  int64_t start = offset;
  int64_t avail_so_far = 0;

  if (it != sparse_ranges_.end() && it->second.offset < offset + len)
    start = it->second.offset;

  if ((it == sparse_ranges_.end() || it->second.offset > offset) &&
      it != sparse_ranges_.begin()) {
    --it;
    if (it->second.offset + it->second.length > offset) {
      start = offset;
      avail_so_far = (it->second.offset + it->second.length) - offset;
    }
    ++it;
  }

  while (start + avail_so_far < offset + len &&
         it != sparse_ranges_.end() &&
         it->second.offset == start + avail_so_far) {
    avail_so_far += it->second.length;
    ++it;
  }

  int64_t len_from_start = len - (start - offset);
  *out_result = RangeResult(
      start, static_cast<int>(std::min(avail_so_far, len_from_start)));
}

int SimpleSynchronousEntry::CheckEOFRecord(
    BackendFileOperations* file_operations,
    base::File* file,
    int stream_index,
    const SimpleEntryStat& entry_stat,
    uint32_t expected_crc32) {
  DCHECK(initialized_);
  SimpleFileEOF eof_record;
  int file_offset = entry_stat.GetEOFOffsetInFile(key_->size(), stream_index);
  int file_index = GetFileIndexFromStreamIndex(stream_index);
  int rv =
      GetEOFRecordData(file, nullptr, file_index, file_offset, &eof_record);

  if (rv != net::OK) {
    DoomInternal(file_operations);
    return rv;
  }
  if ((eof_record.flags & SimpleFileEOF::FLAG_HAS_CRC32) &&
      eof_record.data_crc32 != expected_crc32) {
    DVLOG(1) << "EOF record had bad crc.";
    RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_CRC_MISMATCH);
    DoomInternal(file_operations);
    return net::ERR_CACHE_CHECKSUM_MISMATCH;
  }
  RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_SUCCESS);
  return net::OK;
}

int SimpleSynchronousEntry::PreReadStreamPayload(
    base::File* file,
    PrefetchData* prefetch_data,
    int stream_index,
    int extra_size,
    const SimpleEntryStat& entry_stat,
    const SimpleFileEOF& eof_record,
    SimpleStreamPrefetchData* out) {
  DCHECK(stream_index == 0 || stream_index == 1);

  int stream_size = entry_stat.data_size(stream_index);
  int read_size = stream_size + extra_size;
  out->data = base::MakeRefCounted<net::GrowableIOBuffer>();
  out->data->SetCapacity(read_size);
  int file_offset = entry_stat.GetOffsetInFile(key_->size(), 0, stream_index);
  if (!ReadFromFileOrPrefetched(file, prefetch_data, 0, file_offset, read_size,
                                out->data->data()))
    return net::ERR_FAILED;

  // Check the CRC32.
  uint32_t expected_crc32 = simple_util::Crc32(out->data->data(), stream_size);
  if ((eof_record.flags & SimpleFileEOF::FLAG_HAS_CRC32) &&
      eof_record.data_crc32 != expected_crc32) {
    DVLOG(1) << "EOF record had bad crc.";
    RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_CRC_MISMATCH);
    return net::ERR_CACHE_CHECKSUM_MISMATCH;
  }
  out->stream_crc32 = expected_crc32;
  RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_SUCCESS);
  return net::OK;
}

void SimpleSynchronousEntry::Close(
    const SimpleEntryStat& entry_stat,
    std::unique_ptr<std::vector<CRCRecord>> crc32s_to_write,
    net::GrowableIOBuffer* stream_0_data,
    SimpleEntryCloseResults* out_results) {
  // As we delete `this`, we cannot use ScopedFileOperationsBinding here.
  std::unique_ptr<BackendFileOperations> file_operations =
      unbound_file_operations_->Bind(
          base::SequencedTaskRunner::GetCurrentDefault());
  unbound_file_operations_ = nullptr;
  base::ElapsedTimer close_time;
  DCHECK(stream_0_data);
  const std::string& key = *key_;

  for (auto& crc_record : *crc32s_to_write) {
    const int stream_index = crc_record.index;
    const int file_index = GetFileIndexFromStreamIndex(stream_index);
    if (empty_file_omitted_[file_index])
      continue;

    SimpleFileTracker::FileHandle file = file_tracker_->Acquire(
        file_operations.get(), this, SubFileForFileIndex(file_index));
    if (!file.IsOK()) {
      RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
      DoomInternal(file_operations.get());
      break;
    }

    if (stream_index == 0) {
      // Write stream 0 data.
      int stream_0_offset = entry_stat.GetOffsetInFile(key.size(), 0, 0);
      if (file->Write(stream_0_offset, stream_0_data->data(),
                      entry_stat.data_size(0)) != entry_stat.data_size(0)) {
        RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
        DVLOG(1) << "Could not write stream 0 data.";
        DoomInternal(file_operations.get());
      }
      net::SHA256HashValue hash_value;
      CalculateSHA256OfKey(key, &hash_value);
      if (file->Write(stream_0_offset + entry_stat.data_size(0),
                      reinterpret_cast<char*>(hash_value.data),
                      sizeof(hash_value)) != sizeof(hash_value)) {
        RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
        DVLOG(1) << "Could not write stream 0 data.";
        DoomInternal(file_operations.get());
      }

      // Re-compute stream 0 CRC if the data got changed (we may be here even
      // if it didn't change if stream 0's position on disk got changed due to
      // stream 1 write).
      if (!crc_record.has_crc32) {
        crc_record.data_crc32 =
            simple_util::Crc32(stream_0_data->data(), entry_stat.data_size(0));
        crc_record.has_crc32 = true;
      }

      out_results->estimated_trailer_prefetch_size =
          entry_stat.data_size(0) + sizeof(hash_value) + sizeof(SimpleFileEOF);
    }

    SimpleFileEOF eof_record;
    eof_record.stream_size = entry_stat.data_size(stream_index);
    eof_record.final_magic_number = kSimpleFinalMagicNumber;
    eof_record.flags = 0;
    if (crc_record.has_crc32)
      eof_record.flags |= SimpleFileEOF::FLAG_HAS_CRC32;
    if (stream_index == 0)
      eof_record.flags |= SimpleFileEOF::FLAG_HAS_KEY_SHA256;
    eof_record.data_crc32 = crc_record.data_crc32;
    int eof_offset = entry_stat.GetEOFOffsetInFile(key.size(), stream_index);
    // If stream 0 changed size, the file needs to be resized, otherwise the
    // next open will yield wrong stream sizes. On stream 1 and stream 2 proper
    // resizing of the file is handled in SimpleSynchronousEntry::WriteData().
    if (stream_index == 0 && !file->SetLength(eof_offset)) {
      RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
      DVLOG(1) << "Could not truncate stream 0 file.";
      DoomInternal(file_operations.get());
      break;
    }
    if (file->Write(eof_offset, reinterpret_cast<const char*>(&eof_record),
                    sizeof(eof_record)) != sizeof(eof_record)) {
      RecordCloseResult(cache_type_, CLOSE_RESULT_WRITE_FAILURE);
      DVLOG(1) << "Could not write eof record.";
      DoomInternal(file_operations.get());
      break;
    }
  }
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
    if (empty_file_omitted_[i])
      continue;

    if (header_and_key_check_needed_[i]) {
      SimpleFileTracker::FileHandle file = file_tracker_->Acquire(
          file_operations.get(), this, SubFileForFileIndex(i));
      if (!file.IsOK() || !CheckHeaderAndKey(file.get(), i))
        DoomInternal(file_operations.get());
    }
    CloseFile(file_operations.get(), i);
  }

  if (sparse_file_open()) {
    CloseSparseFile(file_operations.get());
  }

  SIMPLE_CACHE_UMA(TIMES, "DiskCloseLatency", cache_type_,
                   close_time.Elapsed());
  RecordCloseResult(cache_type_, CLOSE_RESULT_SUCCESS);
  have_open_files_ = false;
  delete this;
}

SimpleSynchronousEntry::SimpleSynchronousEntry(
    net::CacheType cache_type,
    const FilePath& path,
    const std::optional<std::string>& key,
    const uint64_t entry_hash,
    SimpleFileTracker* file_tracker,
    std::unique_ptr<UnboundBackendFileOperations> unbound_file_operations,
    int32_t trailer_prefetch_size)
    : cache_type_(cache_type),
      path_(path),
      entry_file_key_(entry_hash),
      key_(key),
      file_tracker_(file_tracker),
      unbound_file_operations_(std::move(unbound_file_operations)),
      trailer_prefetch_size_(trailer_prefetch_size) {
  for (bool& empty_file_omitted : empty_file_omitted_) {
    empty_file_omitted = false;
  }
}

SimpleSynchronousEntry::~SimpleSynchronousEntry() {
  DCHECK(!have_open_files_);
}

bool SimpleSynchronousEntry::MaybeOpenFile(
    BackendFileOperations* file_operations,
    int file_index,
    base::File::Error* out_error) {
  DCHECK(out_error);

  FilePath filename = GetFilenameFromFileIndex(file_index);
  int flags = base::File::FLAG_OPEN | base::File::FLAG_READ |
              base::File::FLAG_WRITE | base::File::FLAG_WIN_SHARE_DELETE;
  auto file = std::make_unique<base::File>();
  *file = file_operations->OpenFile(filename, flags);
  *out_error = file->error_details();

  if (CanOmitEmptyFile(file_index) && !file->IsValid() &&
      *out_error == base::File::FILE_ERROR_NOT_FOUND) {
    empty_file_omitted_[file_index] = true;
    return true;
  }

  if (file->IsValid()) {
    file_tracker_->Register(this, SubFileForFileIndex(file_index),
                            std::move(file));
    return true;
  }
  return false;
}

bool SimpleSynchronousEntry::MaybeCreateFile(
    BackendFileOperations* file_operations,
    int file_index,
    FileRequired file_required,
    base::File::Error* out_error) {
  DCHECK(out_error);

  if (CanOmitEmptyFile(file_index) && file_required == FILE_NOT_REQUIRED) {
    empty_file_omitted_[file_index] = true;
    return true;
  }

  FilePath filename = GetFilenameFromFileIndex(file_index);
  int flags = base::File::FLAG_CREATE | base::File::FLAG_READ |
              base::File::FLAG_WRITE | base::File::FLAG_WIN_SHARE_DELETE;
  auto file =
      std::make_unique<base::File>(file_operations->OpenFile(filename, flags));

  // It's possible that the creation failed because someone deleted the
  // directory (e.g. because someone pressed "clear cache" on Android).
  // If so, we would keep failing for a while until periodic index snapshot
  // re-creates the cache dir, so try to recover from it quickly here.
  //
  // This previously also checked whether the directory was missing, but that
  // races against other entry creations attempting the same recovery.
  if (!file->IsValid() &&
      file->error_details() == base::File::FILE_ERROR_NOT_FOUND) {
    file_operations->CreateDirectory(path_);
    *file = file_operations->OpenFile(filename, flags);
  }

  *out_error = file->error_details();
  if (file->IsValid()) {
    file_tracker_->Register(this, SubFileForFileIndex(file_index),
                            std::move(file));
    empty_file_omitted_[file_index] = false;
    return true;
  }
  return false;
}

bool SimpleSynchronousEntry::OpenFiles(BackendFileOperations* file_operations,
                                       SimpleEntryStat* out_entry_stat) {
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
    base::File::Error error;

    if (!MaybeOpenFile(file_operations, i, &error)) {
      RecordSyncOpenResult(cache_type_, OPEN_ENTRY_PLATFORM_FILE_ERROR);
      SIMPLE_CACHE_LOCAL(ENUMERATION, "SyncOpenPlatformFileError", cache_type_,
                         -error, -base::File::FILE_ERROR_MAX);
      while (--i >= 0)
        CloseFile(file_operations, i);
      return false;
    }
  }

  have_open_files_ = true;

  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
    if (empty_file_omitted_[i]) {
      out_entry_stat->set_data_size(i + 1, 0);
      continue;
    }

    base::File::Info file_info;
    SimpleFileTracker::FileHandle file =
        file_tracker_->Acquire(file_operations, this, SubFileForFileIndex(i));
    bool success = file.IsOK() && file->GetInfo(&file_info);
    if (!success) {
      DLOG(WARNING) << "Could not get platform file info.";
      continue;
    }
    out_entry_stat->set_last_used(file_info.last_accessed);
    out_entry_stat->set_last_modified(file_info.last_modified);

    // Two things prevent from knowing the right values for |data_size|:
    // 1) The key might not be known, hence its length might be unknown.
    // 2) Stream 0 and stream 1 are in the same file, and the exact size for
    // each will only be known when reading the EOF record for stream 0.
    //
    // The size for file 0 and 1 is temporarily kept in
    // |data_size(1)| and |data_size(2)| respectively. Reading the key in
    // InitializeForOpen yields the data size for each file. In the case of
    // file hash_1, this is the total size of stream 2, and is assigned to
    // data_size(2). In the case of file 0, it is the combined size of stream
    // 0, stream 1 and one EOF record. The exact distribution of sizes between
    // stream 1 and stream 0 is only determined after reading the EOF record
    // for stream 0 in ReadAndValidateStream0AndMaybe1.
    if (!base::IsValueInRangeForNumericType<int>(file_info.size)) {
      RecordSyncOpenResult(cache_type_, OPEN_ENTRY_INVALID_FILE_LENGTH);
      return false;
    }
    out_entry_stat->set_data_size(i + 1, static_cast<int>(file_info.size));
  }

  return true;
}

bool SimpleSynchronousEntry::CreateFiles(BackendFileOperations* file_operations,
                                         SimpleEntryStat* out_entry_stat) {
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
    base::File::Error error;
    if (!MaybeCreateFile(file_operations, i, FILE_NOT_REQUIRED, &error)) {
      SIMPLE_CACHE_LOCAL(ENUMERATION, "SyncCreatePlatformFileError",
                         cache_type_, -error, -base::File::FILE_ERROR_MAX);
      while (--i >= 0)
        CloseFile(file_operations, i);
      return false;
    }
  }

  have_open_files_ = true;

  base::Time creation_time = Time::Now();
  out_entry_stat->set_last_modified(creation_time);
  out_entry_stat->set_last_used(creation_time);
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i)
    out_entry_stat->set_data_size(i, 0);

  return true;
}

void SimpleSynchronousEntry::CloseFile(BackendFileOperations* file_operations,
                                       int index) {
  if (empty_file_omitted_[index]) {
    empty_file_omitted_[index] = false;
  } else {
    // We want to delete files that were renamed for doom here; and we should do
    // this before calling SimpleFileTracker::Close, since that would make the
    // name available to other threads.
    if (entry_file_key_.doom_generation != 0u) {
      file_operations->DeleteFile(path_.AppendASCII(
          GetFilenameFromEntryFileKeyAndFileIndex(entry_file_key_, index)));
    }
    file_tracker_->Close(this, SubFileForFileIndex(index));
  }
}

void SimpleSynchronousEntry::CloseFiles() {
  if (!have_open_files_) {
    return;
  }
  BackendFileOperations* file_operations = nullptr;
  ScopedFileOperationsBinding binding(this, &file_operations);
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i)
    CloseFile(file_operations, i);
  if (sparse_file_open())
    CloseSparseFile(file_operations);
  have_open_files_ = false;
}

bool SimpleSynchronousEntry::CheckHeaderAndKey(base::File* file,
                                               int file_index) {
  std::vector<char> header_data(
      !key_.has_value() ? kInitialHeaderRead : GetHeaderSize(key_->size()));
  int bytes_read = file->Read(0, header_data.data(), header_data.size());
  const SimpleFileHeader* header =
      reinterpret_cast<const SimpleFileHeader*>(header_data.data());

  if (bytes_read == -1 || static_cast<size_t>(bytes_read) < sizeof(*header)) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_CANT_READ_HEADER);
    return false;
  }
  // This resize will not invalidate iterators since it does not enlarge the
  // header_data.
  DCHECK_LE(static_cast<size_t>(bytes_read), header_data.size());
  header_data.resize(bytes_read);

  if (header->initial_magic_number != kSimpleInitialMagicNumber) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_BAD_MAGIC_NUMBER);
    return false;
  }

  if (header->version != kSimpleEntryVersionOnDisk) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_BAD_VERSION);
    return false;
  }

  size_t expected_header_size = GetHeaderSize(header->key_length);
  if (header_data.size() < expected_header_size) {
    size_t old_size = header_data.size();
    int bytes_to_read = expected_header_size - old_size;
    // This resize will invalidate iterators, since it is enlarging header_data.
    header_data.resize(expected_header_size);
    int read_result =
        file->Read(old_size, header_data.data() + old_size, bytes_to_read);
    if (read_result != bytes_to_read) {
      RecordSyncOpenResult(cache_type_, OPEN_ENTRY_CANT_READ_KEY);
      return false;
    }
    header = reinterpret_cast<const SimpleFileHeader*>(header_data.data());
  }

  const char* key_data = header_data.data() + sizeof(*header);
  base::span<const char> key_span =
      base::make_span(key_data, header->key_length);
  if (base::PersistentHash(base::as_bytes(key_span)) != header->key_hash) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_KEY_HASH_MISMATCH);
    return false;
  }

  std::string key_from_header(key_data, header->key_length);
  if (!key_.has_value()) {
    key_.emplace(std::move(key_from_header));
  } else {
    if (*key_ != key_from_header) {
      RecordSyncOpenResult(cache_type_, OPEN_ENTRY_KEY_MISMATCH);
      return false;
    }
  }

  header_and_key_check_needed_[file_index] = false;
  return true;
}

int SimpleSynchronousEntry::InitializeForOpen(
    BackendFileOperations* file_operations,
    SimpleEntryStat* out_entry_stat,
    SimpleStreamPrefetchData stream_prefetch_data[2]) {
  DCHECK(!initialized_);
  if (!OpenFiles(file_operations, out_entry_stat)) {
    DLOG(WARNING) << "Could not open platform files for entry.";
    return net::ERR_FAILED;
  }
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
    if (empty_file_omitted_[i])
      continue;

    if (!key_.has_value()) {
      SimpleFileTracker::FileHandle file =
          file_tracker_->Acquire(file_operations, this, SubFileForFileIndex(i));
      // If |key_| is empty, we were opened via the iterator interface, without
      // knowing what our key is. We must therefore read the header immediately
      // to discover it, so SimpleEntryImpl can make it available to
      // disk_cache::Entry::GetKey().
      if (!file.IsOK() || !CheckHeaderAndKey(file.get(), i))
        return net::ERR_FAILED;
    } else {
      // If we do know which key were are looking for, we still need to
      // check that the file actually has it (rather than just being a hash
      // collision or some sort of file system accident), but that can be put
      // off until opportune time: either the read of the footer, or when we
      // start reading in the data, depending on stream # and format revision.
      header_and_key_check_needed_[i] = true;
    }
    size_t key_size = key_->size();

    if (i == 0) {
      // File size for stream 0 has been stored temporarily in data_size[1].
      int ret_value_stream_0 = ReadAndValidateStream0AndMaybe1(
          file_operations, out_entry_stat->data_size(1), out_entry_stat,
          stream_prefetch_data);
      if (ret_value_stream_0 != net::OK)
        return ret_value_stream_0;
    } else {
      out_entry_stat->set_data_size(
          2, GetDataSizeFromFileSize(key_size, out_entry_stat->data_size(2)));
      const int32_t data_size_2 = out_entry_stat->data_size(2);
      int ret_value_stream_2 = net::OK;
      if (data_size_2 < 0) {
        DLOG(WARNING) << "Stream 2 file is too small.";
        ret_value_stream_2 = net::ERR_FAILED;
      } else if (data_size_2 > 0) {
        // Validate non empty stream 2.
        SimpleFileEOF eof_record;
        SimpleFileTracker::FileHandle file = file_tracker_->Acquire(
            file_operations, this, SubFileForFileIndex(i));
        int file_offset =
            out_entry_stat->GetEOFOffsetInFile(key_size, 2 /*stream index*/);
        ret_value_stream_2 =
            GetEOFRecordData(file.get(), nullptr, i, file_offset, &eof_record);
      }

      if (ret_value_stream_2 != net::OK) {
        DCHECK_EQ(i, GetFileIndexFromStreamIndex(2));
        DCHECK(CanOmitEmptyFile(GetFileIndexFromStreamIndex(2)));
        // Stream 2 is broken, set its size to zero to have it automatically
        // deleted further down in this function. For V8 this preserves the
        // cached source when only the code cache was corrupted.
        out_entry_stat->set_data_size(2, 0);
      }
    }
  }

  int32_t sparse_data_size = 0;
  if (!OpenSparseFileIfExists(file_operations, &sparse_data_size)) {
    RecordSyncOpenResult(cache_type_, OPEN_ENTRY_SPARSE_OPEN_FAILED);
    return net::ERR_FAILED;
  }
  out_entry_stat->set_sparse_data_size(sparse_data_size);

  const int stream2_file_index = GetFileIndexFromStreamIndex(2);
  DCHECK(CanOmitEmptyFile(stream2_file_index));
  if (!empty_file_omitted_[stream2_file_index] &&
      out_entry_stat->data_size(2) == 0) {
    CloseFile(file_operations, stream2_file_index);
    DeleteFileForEntryHash(path_, entry_file_key_.entry_hash,
                           stream2_file_index, file_operations);
    empty_file_omitted_[stream2_file_index] = true;
  }

  RecordSyncOpenResult(cache_type_, OPEN_ENTRY_SUCCESS);
  initialized_ = true;
  return net::OK;
}

bool SimpleSynchronousEntry::InitializeCreatedFile(
    BackendFileOperations* file_operations,
    int file_index) {
  SimpleFileTracker::FileHandle file = file_tracker_->Acquire(
      file_operations, this, SubFileForFileIndex(file_index));
  if (!file.IsOK())
    return false;
  const std::string& key = *key_;

  SimpleFileHeader header;
  header.initial_magic_number = kSimpleInitialMagicNumber;
  header.version = kSimpleEntryVersionOnDisk;

  header.key_length = key.size();
  header.key_hash = base::PersistentHash(key);

  int bytes_written =
      file->Write(0, reinterpret_cast<char*>(&header), sizeof(header));
  if (bytes_written != sizeof(header))
    return false;

  bytes_written = file->Write(sizeof(header), key.data(), key.size());
  if (bytes_written != base::checked_cast<int>(key.size())) {
    return false;
  }

  return true;
}

int SimpleSynchronousEntry::InitializeForCreate(
    BackendFileOperations* file_operations,
    SimpleEntryStat* out_entry_stat) {
  DCHECK(!initialized_);
  if (!CreateFiles(file_operations, out_entry_stat)) {
    DLOG(WARNING) << "Could not create platform files.";
    return net::ERR_FILE_EXISTS;
  }
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
    if (empty_file_omitted_[i])
      continue;

    if (!InitializeCreatedFile(file_operations, i))
      return net::ERR_FAILED;
  }
  initialized_ = true;
  return net::OK;
}

int SimpleSynchronousEntry::ReadAndValidateStream0AndMaybe1(
    BackendFileOperations* file_operations,
    int file_size,
    SimpleEntryStat* out_entry_stat,
    SimpleStreamPrefetchData stream_prefetch_data[2]) {
  SimpleFileTracker::FileHandle file =
      file_tracker_->Acquire(file_operations, this, SubFileForFileIndex(0));
  if (!file.IsOK())
    return net::ERR_FAILED;

  // We may prefetch data from file in a couple cases:
  //  1) If the file is small enough we may prefetch it entirely.
  //  2) We may also prefetch a block of trailer bytes from the end of
  //     the file.
  // In these cases the PrefetchData object is used to store the
  // bytes read from the file.  The PrefetchData object also keeps track
  // of what range within the file has been prefetched.  It will only
  // allow reads wholely within this range to be accessed via its
  // ReadData() method.
  PrefetchData prefetch_data(file_size);

  // Determine a threshold for fully prefetching the entire entry file.  If
  // the entry file is less than or equal to this number of bytes it will
  // be fully prefetched.
  int full_prefetch_size = GetSimpleCacheFullPrefetchSize();

  // Determine how much trailer data to prefetch.  If the full file prefetch
  // does not trigger then this is the number of bytes to read from the end
  // of the file in a single file operation.  Ideally the trailer prefetch
  // will contain at least stream 0 and its EOF record.
  int trailer_prefetch_size =
      GetSimpleCacheTrailerPrefetchSize(trailer_prefetch_size_);

  OpenPrefetchMode prefetch_mode = OPEN_PREFETCH_NONE;
  if (file_size <= full_prefetch_size || file_size <= trailer_prefetch_size) {
    // Prefetch the entire file.
    prefetch_mode = OPEN_PREFETCH_FULL;
    RecordOpenPrefetchMode(cache_type_, prefetch_mode);
    if (!prefetch_data.PrefetchFromFile(&file, 0, file_size))
      return net::ERR_FAILED;
  } else if (trailer_prefetch_size > 0) {
    // Prefetch trailer data from the end of the file.
    prefetch_mode = OPEN_PREFETCH_TRAILER;
    RecordOpenPrefetchMode(cache_type_, prefetch_mode);
    size_t length = std::min(trailer_prefetch_size, file_size);
    size_t offset = file_size - length;
    if (!prefetch_data.PrefetchFromFile(&file, offset, length))
      return net::ERR_FAILED;
  } else {
    // Do no prefetching.
    RecordOpenPrefetchMode(cache_type_, prefetch_mode);
  }

  // Read stream 0 footer first --- it has size/feature info required to figure
  // out file 0's layout.
  SimpleFileEOF stream_0_eof;
  int rv = GetEOFRecordData(
      file.get(), &prefetch_data, /* file_index = */ 0,
      /* file_offset = */ file_size - sizeof(SimpleFileEOF), &stream_0_eof);
  if (rv != net::OK)
    return rv;

  int32_t stream_0_size = stream_0_eof.stream_size;
  if (stream_0_size < 0 || stream_0_size > file_size)
    return net::ERR_FAILED;
  out_entry_stat->set_data_size(0, stream_0_size);

  // Calculate size for stream 1, now we know stream 0's.
  // See comments in simple_entry_format.h for background.
  bool has_key_sha256 =
      (stream_0_eof.flags & SimpleFileEOF::FLAG_HAS_KEY_SHA256) ==
      SimpleFileEOF::FLAG_HAS_KEY_SHA256;
  int extra_post_stream_0_read = 0;
  if (has_key_sha256)
    extra_post_stream_0_read += sizeof(net::SHA256HashValue);

  const std::string& key = *key_;
  int32_t stream1_size = file_size - 2 * sizeof(SimpleFileEOF) - stream_0_size -
                         sizeof(SimpleFileHeader) - key.size() -
                         extra_post_stream_0_read;
  if (stream1_size < 0 || stream1_size > file_size)
    return net::ERR_FAILED;

  out_entry_stat->set_data_size(1, stream1_size);

  // Put stream 0 data in memory --- plus maybe the sha256(key) footer.
  rv = PreReadStreamPayload(file.get(), &prefetch_data, /* stream_index = */ 0,
                            extra_post_stream_0_read, *out_entry_stat,
                            stream_0_eof, &stream_prefetch_data[0]);
  if (rv != net::OK)
    return rv;

  // Note the exact range needed in order to read the EOF record and stream 0.
  // In APP_CACHE mode this will be stored directly in the index so we can
  // know exactly how much to read next time.
  computed_trailer_prefetch_size_ =
      prefetch_data.GetDesiredTrailerPrefetchSize();

  // If prefetch buffer is available, and we have sha256(key) (so we don't need
  // to look at the header), extract out stream 1 info as well.
  int stream_1_offset = out_entry_stat->GetOffsetInFile(
      key.size(), /* offset= */ 0, /* stream_index = */ 1);
  int stream_1_read_size =
      sizeof(SimpleFileEOF) + out_entry_stat->data_size(/* stream_index = */ 1);
  if (has_key_sha256 &&
      prefetch_data.HasData(stream_1_offset, stream_1_read_size)) {
    SimpleFileEOF stream_1_eof;
    int stream_1_eof_offset =
        out_entry_stat->GetEOFOffsetInFile(key.size(), /* stream_index = */ 1);
    rv = GetEOFRecordData(file.get(), &prefetch_data, /* file_index = */ 0,
                          stream_1_eof_offset, &stream_1_eof);
    if (rv != net::OK)
      return rv;

    rv = PreReadStreamPayload(file.get(), &prefetch_data,
                              /* stream_index = */ 1,
                              /* extra_size = */ 0, *out_entry_stat,
                              stream_1_eof, &stream_prefetch_data[1]);
    if (rv != net::OK)
      return rv;
  }

  // If present, check the key SHA256.
  if (has_key_sha256) {
    net::SHA256HashValue hash_value;
    CalculateSHA256O
```