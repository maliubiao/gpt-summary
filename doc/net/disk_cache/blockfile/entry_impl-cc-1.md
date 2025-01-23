Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of Chromium's network stack and deals with disk caching.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename "entry_impl.cc" and the context of disk caching immediately suggest that this code manages individual cache entries. It's likely responsible for reading, writing, and managing the data associated with these entries.

2. **Scan for Key Methods and Data Structures:** Look for prominent function names and member variables that hint at the class's responsibilities. Keywords like `WriteData`, `ReadData`, `CreateDataBlock`, `DeleteData`, `UpdateSize`, `Flush`, `PrepareTarget`, and member variables like `entry_`, `backend_`, `user_buffers_`, `files_`, `sparse_` are crucial.

3. **Group Related Functionality:** Organize the identified elements into logical groups. For example:
    * **Data I/O:** `WriteData`, `ReadData`, `Flush`, `PrepareTarget`.
    * **Data Management:** `CreateDataBlock`, `DeleteData`, `UpdateSize`, `HandleTruncation`, `CopyToLocalBuffer`, `MoveToLocalBuffer`, `ImportSeparateFile`.
    * **Entry Metadata:** `UpdateRank`, `SetEntryFlags`, `GetEntryFlags`.
    * **Sparse Data:** `InitSparseData`.
    * **File Handling:** `GetBackingFile`, `GetExternalFile`.

4. **Analyze the Interactions:**  Notice the interaction with `backend_`. This suggests that `EntryImpl` is a component that relies on a lower-level `backend_` for actual file system operations and storage management. The `UserBuffer` suggests in-memory buffering.

5. **Consider JavaScript Relevance (and Lack Thereof):**  Think about how disk caching interacts with web browsers and JavaScript. While the *results* of caching (faster loading) are relevant to JavaScript, the *internal mechanisms* of the cache are generally opaque to it. Therefore, direct connections are unlikely.

6. **Identify Potential User Errors:**  Consider common mistakes developers or users might make related to caching or data handling. For instance, expecting data to persist indefinitely without considering cache eviction policies, or misinterpreting cache behavior. The code itself also hints at potential issues like "TooMuchStorageRequested."

7. **Infer User Actions Leading to This Code:**  Trace back the steps a user might take in a browser that would trigger cache operations. Loading a webpage, downloading a resource, or even navigating through previously visited pages could lead to interaction with the cache.

8. **Address the "Part 2" Instruction:**  Recognize that the prompt explicitly requests a summary based *only* on the provided snippet. Avoid making assumptions about the functionality in "Part 1".

9. **Formulate the Summary:**  Combine the gathered information into a concise description of the code's purpose and key functionalities. Use clear and understandable language.

10. **Refine and Organize:** Structure the summary logically, using headings or bullet points for clarity. Ensure that all aspects of the prompt are addressed, including JavaScript relevance, logical inference, user errors, and debugging hints.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe `EntryImpl` directly handles file I/O.
* **Correction:**  The presence of `backend_` strongly suggests delegation of file system operations.

* **Initial thought:**  There might be direct JavaScript APIs to manipulate the cache.
* **Correction:**  Cache interaction from JavaScript is usually through higher-level browser APIs (like `fetch` with caching directives) and the internal cache mechanisms are hidden.

* **Initial thought:** Focus only on the individual methods.
* **Refinement:**  Group related methods to create a more coherent understanding of the overall functionality.

By following these steps, the generated response effectively summarizes the provided C++ code snippet and addresses all aspects of the user's request.
这是 `net/disk_cache/blockfile/entry_impl.cc` 文件的第二部分代码，延续了第一部分对缓存条目（Entry）的具体实现。 从提供的代码片段来看，它主要关注以下功能：

**核心功能延续：缓存条目的数据写入、管理和持久化**

* **`WriteData(int index, int offset, IOBuffer* buf, int buf_len, net::CompletionOnceCallback callback, bool truncate)` (延续)：** 这是写入数据到缓存条目的核心方法。 这部分代码处理以下逻辑：
    * **数据大小校验:** 确保写入后的偏移量不会超过允许的最大文件大小。
    * **准备写入目标 (`PrepareTarget`):**  调用 `PrepareTarget` 来确保写入操作的目标区域已准备好，包括可能的内存缓冲或磁盘文件。
    * **大小更新 (`UpdateSize`):** 如果写入操作导致数据大小改变（扩展或截断），则更新条目的数据大小。
    * **访问时间更新 (`UpdateRank`):** 更新条目的访问时间，以便进行缓存淘汰等管理。
    * **内存缓冲写入:** 如果数据可以写入到内存缓冲 (`user_buffers_`)，则直接写入。
    * **磁盘文件写入:** 如果需要写入磁盘，则获取或创建相应的磁盘文件 (`GetBackingFile`) 并执行写入操作。
    * **异步IO处理:**  如果写入操作是异步的，则创建回调 (`SyncCallback`) 来处理写入完成事件。
    * **截断处理 (`truncate`):**  如果设置了 `truncate`，会根据需要截断文件。

* **`CreateDataBlock(int index, int size)`:**  为指定索引的数据创建一个数据块（可能在磁盘上）。它调用 `CreateBlock` 来实际创建。

* **`CreateBlock(int size, Addr* address)`:**  根据所需的大小和文件类型，在磁盘上创建一个数据块或外部文件，并将分配的地址存储在 `address` 中。

* **`DeleteData(Addr address, int index)`:**  根据提供的地址删除缓存数据。 如果是独立的文件，则删除该文件；如果是块文件，则通知后端删除该块。

* **`UpdateRank(bool modified)`:** 更新缓存条目的排序信息，通常基于访问时间和修改时间。 如果条目被标记为 `doomed_` (即将被删除)，则直接更新时间戳，否则交由后端进行处理。

* **`GetBackingFile(Addr address, int index)`:**  根据地址获取支持缓存数据的磁盘文件对象。 如果是独立的文件，则调用 `GetExternalFile`。

* **`GetExternalFile(Addr address, int index)`:**  获取或创建外部文件对象（用于存储不适合放在块文件中的数据）。  对于 Key 文件，它使用混合模式 IO。

* **`PrepareTarget(int index, int offset, int buf_len, bool truncate)`:**  准备写入数据的目标位置，这可能涉及使用内存缓冲 (`user_buffers_`) 或直接操作磁盘文件。  它处理截断、内存缓冲的创建和管理。

* **`HandleTruncation(int index, int offset, int buf_len)`:**  处理缓存数据的截断操作，包括当数据在内存缓冲中和在磁盘文件上的情况。

* **`CopyToLocalBuffer(int index)`:**  将指定索引的缓存数据从磁盘复制到内存缓冲中。

* **`MoveToLocalBuffer(int index)`:**  将指定索引的缓存数据移动到内存缓冲中，并将磁盘上的数据删除。

* **`ImportSeparateFile(int index, int new_size)`:**  将一个独立的文件导入到内存缓冲中，通常用于截断操作。

* **`PrepareBuffer(int index, int offset, int buf_len)`:**  准备用于写入的内存缓冲，确保缓冲区的空间足够，并在必要时刷新缓冲区。

* **`Flush(int index, int min_len)`:**  将内存缓冲中的数据刷新到磁盘。

* **`UpdateSize(int index, int old_size, int new_size)`:**  更新缓存条目的数据大小。

* **`InitSparseData()`:**  初始化稀疏数据控制对象 (`SparseControl`)，用于处理稀疏缓存数据。

* **`SetEntryFlags(uint32_t flags)`:**  设置缓存条目的标志位。

* **`GetEntryFlags()`:**  获取缓存条目的标志位。

* **`GetData(int index, std::unique_ptr<char[]>* buffer, Addr* address)`:**  获取缓存数据。如果数据在内存缓冲中，则复制到 `buffer` 中；否则，返回数据在磁盘上的地址。

**与 JavaScript 的关系：**

这个 C++ 代码直接运行在浏览器进程中，负责底层缓存的实现。JavaScript 代码无法直接访问或操作这些底层的缓存机制。然而，JavaScript 的某些行为会间接地触发这些代码的执行：

* **示例：** 当 JavaScript 代码通过 `fetch` API 请求一个资源时，浏览器会先检查缓存。如果缓存中存在该资源且未过期，浏览器可能会从缓存中读取数据，而无需向服务器发送请求。这个读取操作最终会涉及到 `EntryImpl::ReadData` (虽然这个代码片段没有包含 `ReadData`，但它是缓存条目操作的必要部分)。反之，如果需要将响应数据写入缓存，则会涉及到 `EntryImpl::WriteData`。

**逻辑推理：**

* **假设输入：**  `WriteData` 被调用，`index` 为 0，`offset` 为 1024，`buf_len` 为 512，`truncate` 为 `false`。 假设该索引的缓存数据当前大小为 1280 字节，并且数据在磁盘上。
* **输出：**  `PrepareTarget` 会检查是否需要分配新的磁盘空间。 由于 `offset + buf_len` (1536) 大于当前大小 (1280)，`UpdateSize` 会被调用来更新数据大小。 随后，数据从 `buf` 被写入到磁盘文件的偏移量 1024 处，写入 512 字节。 `UpdateRank` 会被调用以更新条目的访问时间。

**用户或编程常见的使用错误：**

* **错误示例：**  开发者错误地估计了缓存空间的需求，导致缓存频繁淘汰重要数据。 这会导致性能下降，因为需要频繁地从服务器重新获取数据。  在 `WriteData` 中，如果 `end_offset > max_file_size`，则会调用 `backend_->TooMuchStorageRequested(size)`，这表明尝试写入超出限制的数据是一个编程错误。

* **错误示例：**  应用程序在短时间内频繁写入大量小块数据到同一个缓存条目，可能会导致频繁的磁盘操作，降低性能。 这里的代码尝试使用内存缓冲来优化这种情况，但如果写入模式不当，仍然可能导致问题。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器中访问一个网页或资源 (例如图片、CSS、JavaScript 文件)。**
2. **浏览器发起网络请求。**
3. **网络栈在接收到响应后，决定是否需要将该资源缓存起来。**  这取决于 HTTP 响应头中的缓存控制指令 (例如 `Cache-Control`, `Expires`)。
4. **如果决定缓存，网络栈会创建一个或找到一个现有的缓存条目来存储该资源。** 这可能涉及到与 `EntryImpl` 相关的创建逻辑（在第一部分中可能）。
5. **`EntryImpl::WriteData` 被调用，将响应数据写入到缓存条目的指定索引 (通常是数据流索引)。** 写入的数据会被写入到内存缓冲或直接写入磁盘文件，如代码所示。

**归纳功能 (第2部分)：**

这部分代码继续深入 `EntryImpl` 的实现细节，主要负责：

* **实现缓存条目的数据写入操作，包括内存缓冲管理和磁盘文件操作。**
* **处理缓存数据的截断、扩展和删除。**
* **提供创建和管理数据块和外部文件的机制。**
* **更新缓存条目的元数据，如大小和访问时间。**
* **为稀疏缓存数据提供支持。**

总的来说，这部分代码是缓存条目数据持久化的核心逻辑所在，它确保了数据能够有效地存储在磁盘上，并能在需要时被检索。 它通过内存缓冲和直接磁盘操作的结合，以及对不同类型存储方式的支持，实现了高效且灵活的缓存管理。

### 提示词
```
这是目录为net/disk_cache/blockfile/entry_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
end_offset > max_file_size) {
    int size = base::CheckAdd(offset, buf_len)
                   .ValueOrDefault(std::numeric_limits<int32_t>::max());
    backend_->TooMuchStorageRequested(size);
    return net::ERR_FAILED;
  }

  // Read the size at this point (it may change inside prepare).
  int entry_size = entry_.Data()->data_size[index];
  bool extending = entry_size < offset + buf_len;
  truncate = truncate && entry_size > offset + buf_len;
  if (!PrepareTarget(index, offset, buf_len, truncate))
    return net::ERR_FAILED;

  if (extending || truncate)
    UpdateSize(index, entry_size, offset + buf_len);

  UpdateRank(true);

  backend_->OnEvent(Stats::WRITE_DATA);
  backend_->OnWrite(buf_len);

  if (user_buffers_[index].get()) {
    // Complete the operation locally.
    user_buffers_[index]->Write(offset, buf, buf_len);
    return buf_len;
  }

  Addr address(entry_.Data()->data_addr[index]);
  if (offset + buf_len == 0) {
    if (truncate) {
      DCHECK(!address.is_initialized());
    }
    return 0;
  }

  File* file = GetBackingFile(address, index);
  if (!file)
    return net::ERR_FILE_NOT_FOUND;

  size_t file_offset = offset;
  if (address.is_block_file()) {
    DCHECK_LE(offset + buf_len, kMaxBlockSize);
    file_offset += address.start_block() * address.BlockSize() +
                   kBlockHeaderSize;
  } else if (truncate || (extending && !buf_len)) {
    if (!file->SetLength(offset + buf_len))
      return net::ERR_FAILED;
  }

  if (!buf_len)
    return 0;

  SyncCallback* io_callback = nullptr;
  bool null_callback = callback.is_null();
  if (!null_callback) {
    io_callback = new SyncCallback(this, buf, std::move(callback),
                                   net::NetLogEventType::ENTRY_WRITE_DATA);
  }

  bool completed;
  if (!file->Write(buf->data(), buf_len, file_offset, io_callback,
                   &completed)) {
    if (io_callback)
      io_callback->Discard();
    return net::ERR_CACHE_WRITE_FAILURE;
  }

  if (io_callback && completed)
    io_callback->Discard();

  return (completed || null_callback) ? buf_len : net::ERR_IO_PENDING;
}

// ------------------------------------------------------------------------

bool EntryImpl::CreateDataBlock(int index, int size) {
  DCHECK(index >= 0 && index < kNumStreams);

  Addr address(entry_.Data()->data_addr[index]);
  if (!CreateBlock(size, &address))
    return false;

  entry_.Data()->data_addr[index] = address.value();
  entry_.Store();
  return true;
}

bool EntryImpl::CreateBlock(int size, Addr* address) {
  DCHECK(!address->is_initialized());
  if (!backend_.get())
    return false;

  FileType file_type = Addr::RequiredFileType(size);
  if (EXTERNAL == file_type) {
    if (size > backend_->MaxFileSize())
      return false;
    if (!backend_->CreateExternalFile(address))
      return false;
  } else {
    int num_blocks = Addr::RequiredBlocks(size, file_type);

    if (!backend_->CreateBlock(file_type, num_blocks, address))
      return false;
  }
  return true;
}

// Note that this method may end up modifying a block file so upon return the
// involved block will be free, and could be reused for something else. If there
// is a crash after that point (and maybe before returning to the caller), the
// entry will be left dirty... and at some point it will be discarded; it is
// important that the entry doesn't keep a reference to this address, or we'll
// end up deleting the contents of |address| once again.
void EntryImpl::DeleteData(Addr address, int index) {
  DCHECK(backend_.get());
  if (!address.is_initialized())
    return;
  if (address.is_separate_file()) {
    int failure = !base::DeleteFile(backend_->GetFileName(address));
    if (failure) {
      LOG(ERROR) << "Failed to delete " <<
          backend_->GetFileName(address).value() << " from the cache.";
    }
    if (files_[index].get())
      files_[index] = nullptr;  // Releases the object.
  } else {
    backend_->DeleteBlock(address, true);
  }
}

void EntryImpl::UpdateRank(bool modified) {
  if (!backend_.get())
    return;

  if (!doomed_) {
    // Everything is handled by the backend.
    backend_->UpdateRank(this, modified);
    return;
  }

  Time current = Time::Now();
  node_.Data()->last_used = current.ToInternalValue();

  if (modified)
    node_.Data()->last_modified = current.ToInternalValue();
}

File* EntryImpl::GetBackingFile(Addr address, int index) {
  if (!backend_.get())
    return nullptr;

  File* file;
  if (address.is_separate_file())
    file = GetExternalFile(address, index);
  else
    file = backend_->File(address);
  return file;
}

File* EntryImpl::GetExternalFile(Addr address, int index) {
  DCHECK(index >= 0 && index <= kKeyFileIndex);
  if (!files_[index].get()) {
    // For a key file, use mixed mode IO.
    auto file = base::MakeRefCounted<File>(kKeyFileIndex == index);
    if (file->Init(backend_->GetFileName(address)))
      files_[index].swap(file);
  }
  return files_[index].get();
}

// We keep a memory buffer for everything that ends up stored on a block file
// (because we don't know yet the final data size), and for some of the data
// that end up on external files. This function will initialize that memory
// buffer and / or the files needed to store the data.
//
// In general, a buffer may overlap data already stored on disk, and in that
// case, the contents of the buffer are the most accurate. It may also extend
// the file, but we don't want to read from disk just to keep the buffer up to
// date. This means that as soon as there is a chance to get confused about what
// is the most recent version of some part of a file, we'll flush the buffer and
// reuse it for the new data. Keep in mind that the normal use pattern is quite
// simple (write sequentially from the beginning), so we optimize for handling
// that case.
bool EntryImpl::PrepareTarget(int index, int offset, int buf_len,
                              bool truncate) {
  if (truncate)
    return HandleTruncation(index, offset, buf_len);

  if (!offset && !buf_len)
    return true;

  Addr address(entry_.Data()->data_addr[index]);
  if (address.is_initialized()) {
    if (address.is_block_file() && !MoveToLocalBuffer(index))
      return false;

    if (!user_buffers_[index].get() && offset < kMaxBlockSize) {
      // We are about to create a buffer for the first 16KB, make sure that we
      // preserve existing data.
      if (!CopyToLocalBuffer(index))
        return false;
    }
  }

  if (!user_buffers_[index].get())
    user_buffers_[index] = std::make_unique<UserBuffer>(backend_.get());

  return PrepareBuffer(index, offset, buf_len);
}

// We get to this function with some data already stored. If there is a
// truncation that results on data stored internally, we'll explicitly
// handle the case here.
bool EntryImpl::HandleTruncation(int index, int offset, int buf_len) {
  Addr address(entry_.Data()->data_addr[index]);

  int current_size = entry_.Data()->data_size[index];
  int new_size = offset + buf_len;

  // This is only called when actually truncating the file, not simply when
  // truncate = true is passed to WriteData(), which could be growing the file.
  DCHECK_LT(new_size, current_size);

  if (new_size == 0) {
    // This is by far the most common scenario.
    backend_->ModifyStorageSize(current_size - unreported_size_[index], 0);
    entry_.Data()->data_addr[index] = 0;
    entry_.Data()->data_size[index] = 0;
    unreported_size_[index] = 0;
    entry_.Store();
    DeleteData(address, index);

    user_buffers_[index].reset();
    return true;
  }

  // We never postpone truncating a file, if there is one, but we may postpone
  // telling the backend about the size reduction.
  if (user_buffers_[index].get()) {
    DCHECK_GE(current_size, user_buffers_[index]->Start());
    if (!address.is_initialized()) {
      // There is no overlap between the buffer and disk.
      if (new_size > user_buffers_[index]->Start()) {
        // Truncate our buffer.
        DCHECK_LT(new_size, user_buffers_[index]->End());
        user_buffers_[index]->Truncate(new_size);

        if (offset < user_buffers_[index]->Start()) {
          // Request to write before the current buffer's start, so flush it to
          // disk and re-init.
          UpdateSize(index, current_size, new_size);
          if (!Flush(index, 0))
            return false;
          return PrepareBuffer(index, offset, buf_len);
        } else {
          // Can just stick to using the memory buffer.
          return true;
        }
      }

      // Truncated to before the current buffer, so can just discard it.
      user_buffers_[index]->Reset();
      return PrepareBuffer(index, offset, buf_len);
    }

    // There is some overlap or we need to extend the file before the
    // truncation.
    if (offset > user_buffers_[index]->Start())
      user_buffers_[index]->Truncate(new_size);
    UpdateSize(index, current_size, new_size);
    if (!Flush(index, 0))
      return false;
    user_buffers_[index].reset();
  }

  // We have data somewhere, and it is not in a buffer.
  DCHECK(!user_buffers_[index].get());
  DCHECK(address.is_initialized());

  if (new_size > kMaxBlockSize)
    return true;  // Let the operation go directly to disk.

  return ImportSeparateFile(index, offset + buf_len);
}

bool EntryImpl::CopyToLocalBuffer(int index) {
  Addr address(entry_.Data()->data_addr[index]);
  DCHECK(!user_buffers_[index].get());
  DCHECK(address.is_initialized());

  int len = std::min(entry_.Data()->data_size[index], kMaxBlockSize);
  user_buffers_[index] = std::make_unique<UserBuffer>(backend_.get());
  user_buffers_[index]->Write(len, nullptr, 0);

  File* file = GetBackingFile(address, index);
  int offset = 0;

  if (address.is_block_file())
    offset = address.start_block() * address.BlockSize() + kBlockHeaderSize;

  if (!file || !file->Read(user_buffers_[index]->Data(), len, offset, nullptr,
                           nullptr)) {
    user_buffers_[index].reset();
    return false;
  }
  return true;
}

bool EntryImpl::MoveToLocalBuffer(int index) {
  if (!CopyToLocalBuffer(index))
    return false;

  Addr address(entry_.Data()->data_addr[index]);
  entry_.Data()->data_addr[index] = 0;
  entry_.Store();
  DeleteData(address, index);

  // If we lose this entry we'll see it as zero sized.
  int len = entry_.Data()->data_size[index];
  backend_->ModifyStorageSize(len - unreported_size_[index], 0);
  unreported_size_[index] = len;
  return true;
}

bool EntryImpl::ImportSeparateFile(int index, int new_size) {
  if (entry_.Data()->data_size[index] > new_size)
    UpdateSize(index, entry_.Data()->data_size[index], new_size);

  return MoveToLocalBuffer(index);
}

bool EntryImpl::PrepareBuffer(int index, int offset, int buf_len) {
  DCHECK(user_buffers_[index].get());
  if ((user_buffers_[index]->End() && offset > user_buffers_[index]->End()) ||
      offset > entry_.Data()->data_size[index]) {
    // We are about to extend the buffer or the file (with zeros), so make sure
    // that we are not overwriting anything.
    Addr address(entry_.Data()->data_addr[index]);
    if (address.is_initialized() && address.is_separate_file()) {
      if (!Flush(index, 0))
        return false;
      // There is an actual file already, and we don't want to keep track of
      // its length so we let this operation go straight to disk.
      // The only case when a buffer is allowed to extend the file (as in fill
      // with zeros before the start) is when there is no file yet to extend.
      user_buffers_[index].reset();
      return true;
    }
  }

  if (!user_buffers_[index]->PreWrite(offset, buf_len)) {
    if (!Flush(index, offset + buf_len))
      return false;

    // Lets try again.
    if (offset > user_buffers_[index]->End() ||
        !user_buffers_[index]->PreWrite(offset, buf_len)) {
      // We cannot complete the operation with a buffer.
      DCHECK(!user_buffers_[index]->Size());
      DCHECK(!user_buffers_[index]->Start());
      user_buffers_[index].reset();
    }
  }
  return true;
}

bool EntryImpl::Flush(int index, int min_len) {
  Addr address(entry_.Data()->data_addr[index]);
  DCHECK(user_buffers_[index].get());
  DCHECK(!address.is_initialized() || address.is_separate_file());
  DVLOG(3) << "Flush";

  int size = std::max(entry_.Data()->data_size[index], min_len);
  if (size && !address.is_initialized() && !CreateDataBlock(index, size))
    return false;

  if (!entry_.Data()->data_size[index]) {
    DCHECK(!user_buffers_[index]->Size());
    return true;
  }

  address.set_value(entry_.Data()->data_addr[index]);

  int len = user_buffers_[index]->Size();
  int offset = user_buffers_[index]->Start();
  if (!len && !offset)
    return true;

  if (address.is_block_file()) {
    DCHECK_EQ(len, entry_.Data()->data_size[index]);
    DCHECK(!offset);
    offset = address.start_block() * address.BlockSize() + kBlockHeaderSize;
  }

  File* file = GetBackingFile(address, index);
  if (!file)
    return false;

  if (!file->Write(user_buffers_[index]->Data(), len, offset, nullptr, nullptr))
    return false;
  user_buffers_[index]->Reset();

  return true;
}

void EntryImpl::UpdateSize(int index, int old_size, int new_size) {
  if (entry_.Data()->data_size[index] == new_size)
    return;

  unreported_size_[index] += new_size - old_size;
  entry_.Data()->data_size[index] = new_size;
  entry_.set_modified();
}

int EntryImpl::InitSparseData() {
  if (sparse_.get())
    return net::OK;

  // Use a local variable so that sparse_ never goes from 'valid' to NULL.
  auto sparse = std::make_unique<SparseControl>(this);
  int result = sparse->Init();
  if (net::OK == result)
    sparse_.swap(sparse);

  return result;
}

void EntryImpl::SetEntryFlags(uint32_t flags) {
  entry_.Data()->flags |= flags;
  entry_.set_modified();
}

uint32_t EntryImpl::GetEntryFlags() {
  return entry_.Data()->flags;
}

void EntryImpl::GetData(int index,
                        std::unique_ptr<char[]>* buffer,
                        Addr* address) {
  DCHECK(backend_.get());
  if (user_buffers_[index].get() && user_buffers_[index]->Size() &&
      !user_buffers_[index]->Start()) {
    // The data is already in memory, just copy it and we're done.
    int data_len = entry_.Data()->data_size[index];
    if (data_len <= user_buffers_[index]->Size()) {
      DCHECK(!user_buffers_[index]->Start());
      *buffer = std::make_unique<char[]>(data_len);
      memcpy(buffer->get(), user_buffers_[index]->Data(), data_len);
      return;
    }
  }

  // Bad news: we'd have to read the info from disk so instead we'll just tell
  // the caller where to read from.
  *buffer = nullptr;
  address->set_value(entry_.Data()->data_addr[index]);
  if (address->is_initialized()) {
    // Prevent us from deleting the block from the backing store.
    backend_->ModifyStorageSize(entry_.Data()->data_size[index] -
                                    unreported_size_[index], 0);
    entry_.Data()->data_addr[index] = 0;
    entry_.Data()->data_size[index] = 0;
  }
}

}  // namespace disk_cache
```