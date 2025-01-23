Response:
The user wants a summary of the functionality of the provided C++ code snippet from `simple_entry_impl.cc`. I need to identify the key operations performed within this code and explain what it does in the context of a network disk cache.

Here's a breakdown of the code's actions:

1. **`CreateEntryInternal`**:  Handles the creation of a new cache entry.
2. **`OpenOrCreateEntryInternal`**: Deals with opening an existing entry or creating it if it doesn't exist.
3. **`CloseInternal`**: Manages the closing of a cache entry, including writing CRC checksums and updating metadata.
4. **`ReadDataInternal`**: Implements reading data from a specific stream within the cache entry.
5. **`WriteDataInternal`**:  Handles writing data to a specific stream in the cache entry.
6. **`ReadSparseDataInternal`**:  Reads data from a sparse section of the cache entry.
7. **`WriteSparseDataInternal`**: Writes data to a sparse section of the cache entry.
8. **`GetAvailableRangeInternal`**:  Retrieves the available range within the sparse data.
9. **`DoomEntryInternal`**: Marks an entry for deletion or truncation.
10. **`CreationOperationComplete`**:  Handles the completion of a create or open operation.
11. **`UpdateStateAfterOperationComplete`**: Updates the entry's state after an operation completes.
12. **`EntryOperationComplete`**:  A common completion handler for various entry operations.
13. **`ReadOperationComplete`**:  Handles the completion of a read operation.
14. **`WriteOperationComplete`**: Handles the completion of a write operation.
15. **`ReadSparseOperationComplete`**: Handles the completion of a sparse read operation.
16. **`WriteSparseOperationComplete`**: Handles the completion of a sparse write operation.
17. **`GetAvailableRangeOperationComplete`**: Handles the completion of getting the available range.
18. **`DoomOperationComplete`**: Handles the completion of a doom operation.
19. **`CloseOperationComplete`**:  Handles the completion of a close operation.
20. **`UpdateDataFromEntryStat`**: Updates the entry's metadata from a `SimpleEntryStat` object.
21. **`GetDiskUsage`**: Calculates the disk space used by the entry.

In essence, this code manages the lifecycle and data access of individual cache entries within the Chromium network stack's simple disk cache. It handles creating, opening, reading, writing, closing, and deleting entries. It also deals with sparse data and maintains metadata like last used time and data size.
这段代码是 `net/disk_cache/simple/simple_entry_impl.cc` 文件的第二部分，主要负责实现 `SimpleEntryImpl` 类的核心功能，涉及缓存条目的创建、打开、关闭、读写以及删除等操作。

**功能归纳:**

这段代码定义了 `SimpleEntryImpl` 类的多个方法，这些方法共同实现了对磁盘缓存条目的管理和数据访问。其核心功能可以归纳为以下几点：

1. **创建和打开缓存条目:**
   - `CreateEntryInternal`:  在磁盘上创建新的缓存条目文件，并初始化相关的元数据。
   - `OpenOrCreateEntryInternal`: 尝试打开已存在的缓存条目，如果不存在则创建新的。这个方法还会处理乐观创建的情况。

2. **关闭缓存条目:**
   - `CloseInternal`:  负责关闭缓存条目，在关闭时会计算并写入数据的 CRC 校验和，并更新缓存条目的元数据。

3. **读写缓存数据:**
   - `ReadDataInternal`:  从缓存条目的指定数据流中读取数据。针对小数据（stream 0）有内存缓存优化。
   - `WriteDataInternal`:  向缓存条目的指定数据流中写入数据，并支持截断操作。

4. **读写稀疏数据:**
   - `ReadSparseDataInternal`:  从缓存条目的稀疏数据区域读取数据。
   - `WriteSparseDataInternal`:  向缓存条目的稀疏数据区域写入数据。

5. **获取稀疏数据可用范围:**
   - `GetAvailableRangeInternal`: 查询缓存条目稀疏数据中可用的数据范围。

6. **删除缓存条目 (Doom):**
   - `DoomEntryInternal`: 将缓存条目标记为待删除状态。具体删除操作可能延迟执行。

7. **处理异步操作完成:**
   - 提供了多个 `...OperationComplete` 方法，用于处理异步文件操作完成后的回调，例如创建、打开、读写和删除操作完成后的处理。这些方法会更新 `SimpleEntryImpl` 的内部状态，并执行用户提供的回调。

8. **状态管理:**
   - 代码中维护了缓存条目的状态（`state_`），例如 `STATE_UNINITIALIZED`、`STATE_IO_PENDING`、`STATE_READY`、`STATE_FAILURE`，用于控制操作的执行和处理错误情况。

9. **CRC 校验:**
   - 在读写操作中，会计算和校验数据的 CRC 校验和，以保证数据的完整性。

**与 JavaScript 的关系 (间接):**

这段 C++ 代码是 Chromium 网络栈的一部分，负责底层的磁盘缓存管理。虽然 JavaScript 代码本身不能直接调用这些 C++ 方法，但当浏览器执行网络请求时，底层的网络栈会使用这些缓存机制来存储和读取资源。

**举例说明:**

假设一个 JavaScript 应用程序请求一个图片资源 `https://example.com/image.png`。

1. **用户操作:**  用户在浏览器中访问一个包含该图片的网页。
2. **网络请求:** 浏览器发起对 `https://example.com/image.png` 的网络请求。
3. **缓存查找:** Chromium 网络栈的缓存模块会尝试在磁盘缓存中查找该资源。
4. **`OpenOrCreateEntryInternal` (可能被调用):** 如果缓存中不存在该条目，则会调用 `OpenOrCreateEntryInternal` 尝试创建新的缓存条目来存储该图片。
5. **数据写入:** 当网络请求返回图片数据后，`WriteDataInternal` 会被调用，将图片数据写入到缓存条目的数据流中。
6. **后续访问:** 如果用户再次访问该网页，缓存模块找到该缓存条目。
7. **`ReadDataInternal` (被调用):**  `ReadDataInternal` 会被调用，从缓存条目中读取图片数据，并返回给渲染进程，从而更快地显示图片。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- 调用 `ReadDataInternal`，参数如下：
    - `stream_index = 0`
    - `offset = 100`
    - `buf_len = 50`
    - 假设 `stream_0_data_` 缓存了前 200 字节的数据。

**输出:**

- 由于 `stream_index` 为 0，数据会直接从内存中的 `stream_0_data_` 读取。
- `buf` 中会填充 `stream_0_data_` 中偏移量 100 开始的 50 字节数据。
- 回调函数 `callback` 会被调用，返回读取的字节数 50。

**用户或编程常见的使用错误:**

1. **在未关闭条目的情况下尝试再次打开或创建:**  这段代码内部有检查机制，但如果外部逻辑不当，可能会尝试对同一个缓存条目并发进行创建或打开操作，可能导致状态混乱或数据损坏。

2. **读写越界:**  如果提供的 `offset` 和 `buf_len` 超出了缓存条目的数据范围，`ReadDataInternal` 和 `WriteDataInternal` 会进行处理，避免访问越界，但可能会导致读取或写入的数据不完整。例如，尝试读取超出 `GetDataSize(stream_index)` 的数据会返回 0。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中发起网络请求:**  例如，访问一个网页，点击一个链接，或者浏览器自动加载资源（如图片、CSS、JavaScript 文件）。
2. **网络栈处理请求:** Chromium 的网络栈接收到请求。
3. **缓存模块介入:** 网络栈的缓存模块会根据请求的 URL 和缓存策略，决定是否使用缓存。
4. **查找或创建缓存条目:**
   - 如果需要读取缓存，可能会调用 `OpenOrCreateEntryInternal` 尝试打开已有的缓存条目。
   - 如果需要存储新的资源，可能会调用 `CreateEntryInternal` 创建新的缓存条目。
5. **读写数据:**
   - 如果是从缓存读取数据，会调用 `ReadDataInternal` 或 `ReadSparseDataInternal`。
   - 如果是向缓存写入数据，会调用 `WriteDataInternal` 或 `WriteSparseDataInternal`。
6. **关闭缓存条目:**  请求完成后，可能会调用 `CloseInternal` 关闭缓存条目。
7. **用户关闭标签页或浏览器:**  在某些情况下，可能会触发缓存条目的清理或删除，调用 `DoomEntryInternal`。

**调试线索:**

- **NetLog:** Chromium 提供了 `chrome://net-export/` 工具，可以记录网络事件，包括缓存相关的操作。通过分析 NetLog，可以追踪到何时以及为什么会调用这些 `SimpleEntryImpl` 的方法。
- **断点调试:**  在 `simple_entry_impl.cc` 中设置断点，可以单步执行代码，查看调用堆栈和变量的值，从而理解代码的执行流程。
- **日志输出:**  在关键路径上添加日志输出（例如使用 `DVLOG` 或 `LOG`），可以帮助了解代码的执行情况。

总之，这段代码是 Chromium 磁盘缓存实现的核心部分，负责管理缓存条目的生命周期和数据访问，是理解 Chromium 缓存机制的关键。

### 提示词
```
这是目录为net/disk_cache/simple/simple_entry_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
s approximation.
  last_used_ = last_modified_ = base::Time::Now();

  const base::TimeTicks start_time = base::TimeTicks::Now();
  auto results = std::make_unique<SimpleEntryCreationResults>(SimpleEntryStat(
      last_used_, last_modified_, data_size_, sparse_data_size_));

  OnceClosure task =
      base::BindOnce(&SimpleSynchronousEntry::CreateEntry, cache_type_, path_,
                     *key_, entry_hash_, file_tracker_,
                     file_operations_factory_->CreateUnbound(), results.get());
  OnceClosure reply = base::BindOnce(
      &SimpleEntryImpl::CreationOperationComplete, this, result_state,
      std::move(callback), start_time, base::Time(), std::move(results),
      net::NetLogEventType::SIMPLE_CACHE_ENTRY_CREATE_END);
  prioritized_task_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                             std::move(reply), entry_priority_);
}

void SimpleEntryImpl::OpenOrCreateEntryInternal(
    OpenEntryIndexEnum index_state,
    SimpleEntryOperation::EntryResultState result_state,
    EntryResultCallback callback) {
  ScopedOperationRunner operation_runner(this);

  net_log_.AddEvent(
      net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_OR_CREATE_BEGIN);

  // result_state may be ENTRY_ALREADY_RETURNED only if an optimistic create is
  // being performed, which must be in STATE_UNINITIALIZED.
  bool optimistic_create =
      (result_state == SimpleEntryOperation::ENTRY_ALREADY_RETURNED);
  DCHECK(!optimistic_create || state_ == STATE_UNINITIALIZED);

  if (state_ == STATE_READY) {
    ReturnEntryToCallerAsync(/* is_open = */ true, std::move(callback));
    NetLogSimpleEntryCreation(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_OR_CREATE_END,
        net::NetLogEventPhase::NONE, this, net::OK);
    return;
  }
  if (state_ == STATE_FAILURE) {
    PostClientCallback(std::move(callback),
                       EntryResult::MakeError(net::ERR_FAILED));
    NetLogSimpleEntryCreation(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_OR_CREATE_END,
        net::NetLogEventPhase::NONE, this, net::ERR_FAILED);
    return;
  }

  DCHECK_EQ(STATE_UNINITIALIZED, state_);
  DCHECK(!synchronous_entry_);
  state_ = STATE_IO_PENDING;
  const base::TimeTicks start_time = base::TimeTicks::Now();
  auto results = std::make_unique<SimpleEntryCreationResults>(SimpleEntryStat(
      last_used_, last_modified_, data_size_, sparse_data_size_));

  int32_t trailer_prefetch_size = -1;
  base::Time last_used_time;
  if (SimpleBackendImpl* backend = backend_.get()) {
    if (cache_type_ == net::APP_CACHE) {
      trailer_prefetch_size =
          backend->index()->GetTrailerPrefetchSize(entry_hash_);
    } else {
      last_used_time = backend->index()->GetLastUsedTime(entry_hash_);
    }
  }

  base::OnceClosure task =
      base::BindOnce(&SimpleSynchronousEntry::OpenOrCreateEntry, cache_type_,
                     path_, *key_, entry_hash_, index_state, optimistic_create,
                     file_tracker_, file_operations_factory_->CreateUnbound(),
                     trailer_prefetch_size, results.get());

  base::OnceClosure reply = base::BindOnce(
      &SimpleEntryImpl::CreationOperationComplete, this, result_state,
      std::move(callback), start_time, last_used_time, std::move(results),
      net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_OR_CREATE_END);

  prioritized_task_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                             std::move(reply), entry_priority_);
}

void SimpleEntryImpl::CloseInternal() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (open_count_ != 0) {
    // Entry got resurrected in between Close and CloseInternal, nothing to do
    // for now.
    return;
  }

  typedef SimpleSynchronousEntry::CRCRecord CRCRecord;
  auto crc32s_to_write = std::make_unique<std::vector<CRCRecord>>();

  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_CLOSE_BEGIN);

  if (state_ == STATE_READY) {
    DCHECK(synchronous_entry_);
    state_ = STATE_IO_PENDING;
    for (int i = 0; i < kSimpleEntryStreamCount; ++i) {
      if (have_written_[i]) {
        if (GetDataSize(i) == crc32s_end_offset_[i]) {
          int32_t crc = GetDataSize(i) == 0 ? crc32(0, Z_NULL, 0) : crc32s_[i];
          crc32s_to_write->push_back(CRCRecord(i, true, crc));
        } else {
          crc32s_to_write->push_back(CRCRecord(i, false, 0));
        }
      }
    }
  } else {
    DCHECK(STATE_UNINITIALIZED == state_ || STATE_FAILURE == state_);
  }

  auto results = std::make_unique<SimpleEntryCloseResults>();
  if (synchronous_entry_) {
    OnceClosure task = base::BindOnce(
        &SimpleSynchronousEntry::Close, base::Unretained(synchronous_entry_),
        SimpleEntryStat(last_used_, last_modified_, data_size_,
                        sparse_data_size_),
        std::move(crc32s_to_write), base::RetainedRef(stream_0_data_),
        results.get());
    OnceClosure reply = base::BindOnce(&SimpleEntryImpl::CloseOperationComplete,
                                       this, std::move(results));
    synchronous_entry_ = nullptr;
    prioritized_task_runner_->PostTaskAndReply(
        FROM_HERE, std::move(task), std::move(reply), entry_priority_);
  } else {
    CloseOperationComplete(std::move(results));
  }
}

int SimpleEntryImpl::ReadDataInternal(bool sync_possible,
                                      int stream_index,
                                      int offset,
                                      net::IOBuffer* buf,
                                      int buf_len,
                                      net::CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ScopedOperationRunner operation_runner(this);

  if (net_log_.IsCapturing()) {
    NetLogReadWriteData(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_BEGIN,
        net::NetLogEventPhase::NONE, stream_index, offset, buf_len, false);
  }

  if (state_ == STATE_FAILURE || state_ == STATE_UNINITIALIZED) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(net_log_,
                              net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_END,
                              net::NetLogEventPhase::NONE, net::ERR_FAILED);
    }
    // Note that the API states that client-provided callbacks for entry-level
    // (i.e. non-backend) operations (e.g. read, write) are invoked even if
    // the backend was already destroyed.
    return PostToCallbackIfNeeded(sync_possible, std::move(callback),
                                  net::ERR_FAILED);
  }
  DCHECK_EQ(STATE_READY, state_);
  if (offset >= GetDataSize(stream_index) || offset < 0 || !buf_len) {
    // If there is nothing to read, we bail out before setting state_ to
    // STATE_IO_PENDING (so ScopedOperationRunner might start us on next op
    // here).
    return PostToCallbackIfNeeded(sync_possible, std::move(callback), 0);
  }

  // Truncate read to not go past end of stream.
  buf_len = std::min(buf_len, GetDataSize(stream_index) - offset);

  // Since stream 0 data is kept in memory, it is read immediately.
  if (stream_index == 0) {
    state_ = STATE_IO_PENDING;
    ReadFromBuffer(stream_0_data_.get(), offset, buf_len, buf);
    state_ = STATE_READY;
    return PostToCallbackIfNeeded(sync_possible, std::move(callback), buf_len);
  }

  // Sometimes we can read in-ram prefetched stream 1 data immediately, too.
  if (stream_index == 1) {
    if (stream_1_prefetch_data_) {
      state_ = STATE_IO_PENDING;
      ReadFromBuffer(stream_1_prefetch_data_.get(), offset, buf_len, buf);
      state_ = STATE_READY;
      return PostToCallbackIfNeeded(sync_possible, std::move(callback),
                                    buf_len);
    }
  }

  state_ = STATE_IO_PENDING;
  if (doom_state_ == DOOM_NONE && backend_.get())
    backend_->index()->UseIfExists(entry_hash_);

  SimpleSynchronousEntry::ReadRequest read_req(stream_index, offset, buf_len);
  // Figure out if we should be computing the checksum for this read,
  // and whether we should be verifying it, too.
  if (crc32s_end_offset_[stream_index] == offset) {
    read_req.request_update_crc = true;
    read_req.previous_crc32 =
        offset == 0 ? crc32(0, Z_NULL, 0) : crc32s_[stream_index];

    // We can't verify the checksum if we already overwrote part of the file.
    // (It may still make sense to compute it if the overwritten area and the
    //  about-to-read-in area are adjoint).
    read_req.request_verify_crc = !have_written_[stream_index];
  }

  auto result = std::make_unique<SimpleSynchronousEntry::ReadResult>();
  auto entry_stat = std::make_unique<SimpleEntryStat>(
      last_used_, last_modified_, data_size_, sparse_data_size_);
  OnceClosure task = base::BindOnce(
      &SimpleSynchronousEntry::ReadData, base::Unretained(synchronous_entry_),
      read_req, entry_stat.get(), base::RetainedRef(buf), result.get());
  OnceClosure reply = base::BindOnce(
      &SimpleEntryImpl::ReadOperationComplete, this, stream_index, offset,
      std::move(callback), std::move(entry_stat), std::move(result));
  prioritized_task_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                             std::move(reply), entry_priority_);
  return net::ERR_IO_PENDING;
}

void SimpleEntryImpl::WriteDataInternal(int stream_index,
                                        int offset,
                                        net::IOBuffer* buf,
                                        int buf_len,
                                        net::CompletionOnceCallback callback,
                                        bool truncate) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ScopedOperationRunner operation_runner(this);

  if (net_log_.IsCapturing()) {
    NetLogReadWriteData(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_BEGIN,
        net::NetLogEventPhase::NONE, stream_index, offset, buf_len, truncate);
  }

  if (state_ == STATE_FAILURE || state_ == STATE_UNINITIALIZED) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_END,
          net::NetLogEventPhase::NONE, net::ERR_FAILED);
    }
    if (!callback.is_null()) {
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(callback), net::ERR_FAILED));
    }
    // |this| may be destroyed after return here.
    return;
  }

  DCHECK_EQ(STATE_READY, state_);

  // Since stream 0 data is kept in memory, it will be written immediatly.
  if (stream_index == 0) {
    state_ = STATE_IO_PENDING;
    SetStream0Data(buf, offset, buf_len, truncate);
    state_ = STATE_READY;
    if (!callback.is_null()) {
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(callback), buf_len));
    }
    return;
  }

  // Ignore zero-length writes that do not change the file size.
  if (buf_len == 0) {
    int32_t data_size = data_size_[stream_index];
    if (truncate ? (offset == data_size) : (offset <= data_size)) {
      if (!callback.is_null()) {
        base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
            FROM_HERE, base::BindOnce(std::move(callback), 0));
      }
      return;
    }
  }
  state_ = STATE_IO_PENDING;
  if (doom_state_ == DOOM_NONE && backend_.get())
    backend_->index()->UseIfExists(entry_hash_);

  // Any stream 1 write invalidates the prefetched data.
  if (stream_index == 1)
    stream_1_prefetch_data_ = nullptr;

  bool request_update_crc = false;
  uint32_t initial_crc = 0;

  if (offset < crc32s_end_offset_[stream_index]) {
    // If a range for which the crc32 was already computed is rewritten, the
    // computation of the crc32 need to start from 0 again.
    crc32s_end_offset_[stream_index] = 0;
  }

  if (crc32s_end_offset_[stream_index] == offset) {
    request_update_crc = true;
    initial_crc = (offset != 0) ? crc32s_[stream_index] : crc32(0, Z_NULL, 0);
  }

  // |entry_stat| needs to be initialized before modifying |data_size_|.
  auto entry_stat = std::make_unique<SimpleEntryStat>(
      last_used_, last_modified_, data_size_, sparse_data_size_);
  if (truncate) {
    data_size_[stream_index] = offset + buf_len;
  } else {
    data_size_[stream_index] = std::max(offset + buf_len,
                                        GetDataSize(stream_index));
  }

  auto write_result = std::make_unique<SimpleSynchronousEntry::WriteResult>();

  // Since we don't know the correct values for |last_used_| and
  // |last_modified_| yet, we make this approximation.
  last_used_ = last_modified_ = base::Time::Now();

  have_written_[stream_index] = true;
  // Writing on stream 1 affects the placement of stream 0 in the file, the EOF
  // record will have to be rewritten.
  if (stream_index == 1)
    have_written_[0] = true;

  // Retain a reference to |buf| in |reply| instead of |task|, so that we can
  // reduce cross thread malloc/free pairs. The cross thread malloc/free pair
  // increases the apparent memory usage due to the thread cached free list.
  // TODO(morlovich): Remove the doom_state_ argument to WriteData, since with
  // renaming rather than delete, creating a new stream 2 of doomed entry will
  // just work.
  OnceClosure task = base::BindOnce(
      &SimpleSynchronousEntry::WriteData, base::Unretained(synchronous_entry_),
      SimpleSynchronousEntry::WriteRequest(
          stream_index, offset, buf_len, initial_crc, truncate,
          doom_state_ != DOOM_NONE, request_update_crc),
      base::Unretained(buf), entry_stat.get(), write_result.get());
  OnceClosure reply =
      base::BindOnce(&SimpleEntryImpl::WriteOperationComplete, this,
                     stream_index, std::move(callback), std::move(entry_stat),
                     std::move(write_result), base::RetainedRef(buf));
  prioritized_task_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                             std::move(reply), entry_priority_);
}

void SimpleEntryImpl::ReadSparseDataInternal(
    int64_t sparse_offset,
    net::IOBuffer* buf,
    int buf_len,
    net::CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ScopedOperationRunner operation_runner(this);

  if (net_log_.IsCapturing()) {
    NetLogSparseOperation(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_SPARSE_BEGIN,
        net::NetLogEventPhase::NONE, sparse_offset, buf_len);
  }

  if (state_ == STATE_FAILURE || state_ == STATE_UNINITIALIZED) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_SPARSE_END,
          net::NetLogEventPhase::NONE, net::ERR_FAILED);
    }
    if (!callback.is_null()) {
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(callback), net::ERR_FAILED));
    }
    // |this| may be destroyed after return here.
    return;
  }

  DCHECK_EQ(STATE_READY, state_);
  state_ = STATE_IO_PENDING;

  auto result = std::make_unique<int>();
  auto last_used = std::make_unique<base::Time>();
  OnceClosure task = base::BindOnce(
      &SimpleSynchronousEntry::ReadSparseData,
      base::Unretained(synchronous_entry_),
      SimpleSynchronousEntry::SparseRequest(sparse_offset, buf_len),
      base::RetainedRef(buf), last_used.get(), result.get());
  OnceClosure reply = base::BindOnce(
      &SimpleEntryImpl::ReadSparseOperationComplete, this, std::move(callback),
      std::move(last_used), std::move(result));
  prioritized_task_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                             std::move(reply), entry_priority_);
}

void SimpleEntryImpl::WriteSparseDataInternal(
    int64_t sparse_offset,
    net::IOBuffer* buf,
    int buf_len,
    net::CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ScopedOperationRunner operation_runner(this);

  if (net_log_.IsCapturing()) {
    NetLogSparseOperation(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_SPARSE_BEGIN,
        net::NetLogEventPhase::NONE, sparse_offset, buf_len);
  }

  if (state_ == STATE_FAILURE || state_ == STATE_UNINITIALIZED) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_SPARSE_END,
          net::NetLogEventPhase::NONE, net::ERR_FAILED);
    }
    if (!callback.is_null()) {
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(std::move(callback), net::ERR_FAILED));
    }
    // |this| may be destroyed after return here.
    return;
  }

  DCHECK_EQ(STATE_READY, state_);
  state_ = STATE_IO_PENDING;

  uint64_t max_sparse_data_size = std::numeric_limits<int64_t>::max();
  if (backend_.get()) {
    uint64_t max_cache_size = backend_->index()->max_size();
    max_sparse_data_size = max_cache_size / kMaxSparseDataSizeDivisor;
  }

  auto entry_stat = std::make_unique<SimpleEntryStat>(
      last_used_, last_modified_, data_size_, sparse_data_size_);

  last_used_ = last_modified_ = base::Time::Now();

  auto result = std::make_unique<int>();
  OnceClosure task = base::BindOnce(
      &SimpleSynchronousEntry::WriteSparseData,
      base::Unretained(synchronous_entry_),
      SimpleSynchronousEntry::SparseRequest(sparse_offset, buf_len),
      base::RetainedRef(buf), max_sparse_data_size, entry_stat.get(),
      result.get());
  OnceClosure reply = base::BindOnce(
      &SimpleEntryImpl::WriteSparseOperationComplete, this, std::move(callback),
      std::move(entry_stat), std::move(result));
  prioritized_task_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                             std::move(reply), entry_priority_);
}

void SimpleEntryImpl::GetAvailableRangeInternal(int64_t sparse_offset,
                                                int len,
                                                RangeResultCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ScopedOperationRunner operation_runner(this);

  if (state_ == STATE_FAILURE || state_ == STATE_UNINITIALIZED) {
    if (!callback.is_null()) {
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(std::move(callback), RangeResult(net::ERR_FAILED)));
    }
    // |this| may be destroyed after return here.
    return;
  }

  DCHECK_EQ(STATE_READY, state_);
  state_ = STATE_IO_PENDING;

  auto result = std::make_unique<RangeResult>();
  OnceClosure task = base::BindOnce(
      &SimpleSynchronousEntry::GetAvailableRange,
      base::Unretained(synchronous_entry_),
      SimpleSynchronousEntry::SparseRequest(sparse_offset, len), result.get());
  OnceClosure reply =
      base::BindOnce(&SimpleEntryImpl::GetAvailableRangeOperationComplete, this,
                     std::move(callback), std::move(result));
  prioritized_task_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                             std::move(reply), entry_priority_);
}

void SimpleEntryImpl::DoomEntryInternal(net::CompletionOnceCallback callback) {
  if (doom_state_ == DOOM_COMPLETED) {
    // During the time we were sitting on a queue, some operation failed
    // and cleaned our files up, so we don't have to do anything.
    DoomOperationComplete(std::move(callback), state_, net::OK);
    return;
  }

  if (!backend_) {
    // If there's no backend, we want to truncate the files rather than delete
    // or rename them. Either op will update the entry directory's mtime, which
    // will likely force a full index rebuild on the next startup; this is
    // clearly an undesirable cost. Instead, the lesser evil is to set the entry
    // files to length zero, leaving the invalid entry in the index. On the next
    // attempt to open the entry, it will fail asynchronously (since the magic
    // numbers will not be found), and the files will actually be removed.
    // Since there is no backend, new entries to conflict with us also can't be
    // created.
    prioritized_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(&SimpleSynchronousEntry::TruncateEntryFiles, path_,
                       entry_hash_, file_operations_factory_->CreateUnbound()),
        base::BindOnce(&SimpleEntryImpl::DoomOperationComplete, this,
                       std::move(callback),
                       // Return to STATE_FAILURE after dooming, since no
                       // operation can succeed on the truncated entry files.
                       STATE_FAILURE),
        entry_priority_);
    state_ = STATE_IO_PENDING;
    return;
  }

  if (synchronous_entry_) {
    // If there is a backing object, we have to go through its instance methods,
    // so that it can rename itself and keep track of the altenative name.
    prioritized_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(&SimpleSynchronousEntry::Doom,
                       base::Unretained(synchronous_entry_)),
        base::BindOnce(&SimpleEntryImpl::DoomOperationComplete, this,
                       std::move(callback), state_),
        entry_priority_);
  } else {
    DCHECK_EQ(STATE_UNINITIALIZED, state_);
    // If nothing is open, we can just delete the files. We know they have the
    // base names, since if we ever renamed them our doom_state_ would be
    // DOOM_COMPLETED, and we would exit at function entry.
    prioritized_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(&SimpleSynchronousEntry::DeleteEntryFiles, path_,
                       cache_type_, entry_hash_,
                       file_operations_factory_->CreateUnbound()),
        base::BindOnce(&SimpleEntryImpl::DoomOperationComplete, this,
                       std::move(callback), state_),
        entry_priority_);
  }
  state_ = STATE_IO_PENDING;
}

void SimpleEntryImpl::CreationOperationComplete(
    SimpleEntryOperation::EntryResultState result_state,
    EntryResultCallback completion_callback,
    const base::TimeTicks& start_time,
    const base::Time index_last_used_time,
    std::unique_ptr<SimpleEntryCreationResults> in_results,
    net::NetLogEventType end_event_type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(state_, STATE_IO_PENDING);
  DCHECK(in_results);
  ScopedOperationRunner operation_runner(this);
  if (in_results->result != net::OK) {
    if (in_results->result != net::ERR_FILE_EXISTS) {
      // Here we keep index up-to-date, but don't remove ourselves from active
      // entries since we may have queued operations, and it would be
      // problematic to run further Creates, Opens, or Dooms if we are not
      // the active entry.  We can only do this because OpenEntryInternal
      // and CreateEntryInternal have to start from STATE_UNINITIALIZED, so
      // nothing else is going on which may be confused.
      if (backend_)
        backend_->index()->Remove(entry_hash_);
    }

    net_log_.AddEventWithNetErrorCode(end_event_type, net::ERR_FAILED);
    PostClientCallback(std::move(completion_callback),
                       EntryResult::MakeError(net::ERR_FAILED));
    ResetEntry();
    return;
  }

  // If this is a successful creation (rather than open), mark all streams to be
  // saved on close.
  if (in_results->created) {
    for (bool& have_written : have_written_)
      have_written = true;
  }

  // Make sure to keep the index up-to-date. We likely already did this when
  // CreateEntry was called, but it's possible we were sitting on a queue
  // after an op that removed us.
  if (backend_ && doom_state_ == DOOM_NONE)
    backend_->index()->Insert(entry_hash_);

  synchronous_entry_ = in_results->sync_entry;

  // Copy over any pre-fetched data and its CRCs.
  for (int stream = 0; stream < 2; ++stream) {
    const SimpleStreamPrefetchData& prefetched =
        in_results->stream_prefetch_data[stream];
    if (prefetched.data.get()) {
      if (stream == 0)
        stream_0_data_ = prefetched.data;
      else
        stream_1_prefetch_data_ = prefetched.data;

      // The crc was read in SimpleSynchronousEntry.
      crc32s_[stream] = prefetched.stream_crc32;
      crc32s_end_offset_[stream] = in_results->entry_stat.data_size(stream);
    }
  }

  // If this entry was opened by hash, key_ could still be empty. If so, update
  // it with the key read from the synchronous entry.
  if (!key_.has_value()) {
    SetKey(*synchronous_entry_->key());
  } else {
    // This should only be triggered when creating an entry. In the open case
    // the key is either copied from the arguments to open, or checked
    // in the synchronous entry.
    DCHECK_EQ(*key_, *synchronous_entry_->key());
  }

  // Prefer index last used time to disk's, since that may be pretty inaccurate.
  if (!index_last_used_time.is_null())
    in_results->entry_stat.set_last_used(index_last_used_time);

  UpdateDataFromEntryStat(in_results->entry_stat);
  if (cache_type_ == net::APP_CACHE && backend_.get() && backend_->index()) {
    backend_->index()->SetTrailerPrefetchSize(
        entry_hash_, in_results->computed_trailer_prefetch_size);
  }
  SIMPLE_CACHE_UMA(TIMES,
                   "EntryCreationTime", cache_type_,
                   (base::TimeTicks::Now() - start_time));

  net_log_.AddEvent(end_event_type);

  const bool created = in_results->created;

  // We need to release `in_results` before going out of scope, because
  // `operation_runner` destruction might call a close operation, that will
  // ultimately release `in_results->sync_entry`, and thus leading to having a
  // dangling pointer here.
  in_results = nullptr;

  state_ = STATE_READY;
  if (result_state == SimpleEntryOperation::ENTRY_NEEDS_CALLBACK) {
    ReturnEntryToCallerAsync(!created, std::move(completion_callback));
  }
}

void SimpleEntryImpl::UpdateStateAfterOperationComplete(
    const SimpleEntryStat& entry_stat,
    int result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(synchronous_entry_);
  DCHECK_EQ(STATE_IO_PENDING, state_);
  if (result < 0) {
    state_ = STATE_FAILURE;
    MarkAsDoomed(DOOM_COMPLETED);
  } else {
    UpdateDataFromEntryStat(entry_stat);
    state_ = STATE_READY;
  }
}

void SimpleEntryImpl::EntryOperationComplete(
    net::CompletionOnceCallback completion_callback,
    const SimpleEntryStat& entry_stat,
    int result) {
  UpdateStateAfterOperationComplete(entry_stat, result);
  if (!completion_callback.is_null()) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(completion_callback), result));
  }
  RunNextOperationIfNeeded();
}

void SimpleEntryImpl::ReadOperationComplete(
    int stream_index,
    int offset,
    net::CompletionOnceCallback completion_callback,
    std::unique_ptr<SimpleEntryStat> entry_stat,
    std::unique_ptr<SimpleSynchronousEntry::ReadResult> read_result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(synchronous_entry_);
  DCHECK_EQ(STATE_IO_PENDING, state_);
  DCHECK(read_result);
  int result = read_result->result;

  if (read_result->crc_updated) {
    if (result > 0) {
      DCHECK_EQ(crc32s_end_offset_[stream_index], offset);
      crc32s_end_offset_[stream_index] += result;
      crc32s_[stream_index] = read_result->updated_crc32;
    }
  }

  if (result < 0) {
    crc32s_end_offset_[stream_index] = 0;
  }

  if (net_log_.IsCapturing()) {
    NetLogReadWriteComplete(net_log_,
                            net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_END,
                            net::NetLogEventPhase::NONE, result);
  }

  EntryOperationComplete(std::move(completion_callback), *entry_stat, result);
}

void SimpleEntryImpl::WriteOperationComplete(
    int stream_index,
    net::CompletionOnceCallback completion_callback,
    std::unique_ptr<SimpleEntryStat> entry_stat,
    std::unique_ptr<SimpleSynchronousEntry::WriteResult> write_result,
    net::IOBuffer* buf) {
  int result = write_result->result;
  if (net_log_.IsCapturing()) {
    NetLogReadWriteComplete(net_log_,
                            net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_END,
                            net::NetLogEventPhase::NONE, result);
  }

  if (result < 0)
    crc32s_end_offset_[stream_index] = 0;

  if (result > 0 && write_result->crc_updated) {
    crc32s_end_offset_[stream_index] += result;
    crc32s_[stream_index] = write_result->updated_crc32;
  }

  EntryOperationComplete(std::move(completion_callback), *entry_stat, result);
}

void SimpleEntryImpl::ReadSparseOperationComplete(
    net::CompletionOnceCallback completion_callback,
    std::unique_ptr<base::Time> last_used,
    std::unique_ptr<int> result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(synchronous_entry_);
  DCHECK(result);

  if (net_log_.IsCapturing()) {
    NetLogReadWriteComplete(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_SPARSE_END,
        net::NetLogEventPhase::NONE, *result);
  }

  SimpleEntryStat entry_stat(*last_used, last_modified_, data_size_,
                             sparse_data_size_);
  EntryOperationComplete(std::move(completion_callback), entry_stat, *result);
}

void SimpleEntryImpl::WriteSparseOperationComplete(
    net::CompletionOnceCallback completion_callback,
    std::unique_ptr<SimpleEntryStat> entry_stat,
    std::unique_ptr<int> result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(synchronous_entry_);
  DCHECK(result);

  if (net_log_.IsCapturing()) {
    NetLogReadWriteComplete(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_SPARSE_END,
        net::NetLogEventPhase::NONE, *result);
  }

  EntryOperationComplete(std::move(completion_callback), *entry_stat, *result);
}

void SimpleEntryImpl::GetAvailableRangeOperationComplete(
    RangeResultCallback completion_callback,
    std::unique_ptr<RangeResult> result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(synchronous_entry_);
  DCHECK(result);

  SimpleEntryStat entry_stat(last_used_, last_modified_, data_size_,
                             sparse_data_size_);
  UpdateStateAfterOperationComplete(entry_stat, result->net_error);
  if (!completion_callback.is_null()) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(completion_callback), *result));
  }
  RunNextOperationIfNeeded();
}

void SimpleEntryImpl::DoomOperationComplete(
    net::CompletionOnceCallback callback,
    State state_to_restore,
    int result) {
  state_ = state_to_restore;
  doom_state_ = DOOM_COMPLETED;
  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_DOOM_END);
  PostClientCallback(std::move(callback), result);
  RunNextOperationIfNeeded();
  if (post_doom_waiting_) {
    post_doom_waiting_->OnOperationComplete(entry_hash_);
    post_doom_waiting_ = nullptr;
  }
}

void SimpleEntryImpl::CloseOperationComplete(
    std::unique_ptr<SimpleEntryCloseResults> in_results) {
  DCHECK(!synchronous_entry_);
  DCHECK_EQ(0, open_count_);
  DCHECK(STATE_IO_PENDING == state_ || STATE_FAILURE == state_ ||
         STATE_UNINITIALIZED == state_);
  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_CLOSE_END);
  if (cache_type_ == net::APP_CACHE &&
      in_results->estimated_trailer_prefetch_size > 0 && backend_.get() &&
      backend_->index()) {
    backend_->index()->SetTrailerPrefetchSize(
        entry_hash_, in_results->estimated_trailer_prefetch_size);
  }
  ResetEntry();
  RunNextOperationIfNeeded();
}

void SimpleEntryImpl::UpdateDataFromEntryStat(
    const SimpleEntryStat& entry_stat) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(synchronous_entry_);
  // We want to only be called in STATE_IO_PENDING so that if call to
  // SimpleIndex::UpdateEntrySize() ends up triggering eviction and queuing
  // Dooms it doesn't also run any queued operations.
  CHECK_EQ(state_, STATE_IO_PENDING);

  last_used_ = entry_stat.last_used();
  last_modified_ = entry_stat.last_modified();
  for (int i = 0; i < kSimpleEntryStreamCount; ++i) {
    data_size_[i] = entry_stat.data_size(i);
  }
  sparse_data_size_ = entry_stat.sparse_data_size();

  SimpleBackendImpl* backend_ptr = backend_.get();
  if (doom_state_ == DOOM_NONE && backend_ptr) {
    backend_ptr->index()->UpdateEntrySize(
        entry_hash_, base::checked_cast<uint32_t>(GetDiskUsage()));
  }
}

int64_t SimpleEntryImpl::GetDiskUsage() const {
  int64_t file_size = 0;
  for (int data_size : data_size_) {
    file_size += simple_util::GetFileSizeFromDataSize(key
```