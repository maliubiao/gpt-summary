Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Request:**

The request asks for several things about the provided C++ code:

* **Functionality:** What does this code do?
* **JavaScript Relation:**  Does it interact with JavaScript, and how?
* **Logical Reasoning (Input/Output):**  Can we analyze specific functions with hypothetical inputs and outputs?
* **User/Programming Errors:** What mistakes can developers or users make related to this code?
* **User Operation to Reach Here:** What user actions lead to this code being executed (debugging perspective)?
* **Overall Functionality (Part 3 Summary):** Summarize the specific contributions of *this* snippet.

**2. Initial Code Scan and Keyword Spotting:**

I quickly scan the code for relevant keywords and patterns:

* **File Operations:** `base::File`, `OpenFile`, `Read`, `Write`, `DeleteFile`, `TruncatePath`, `SetLength`. This strongly suggests file system interaction.
* **Cache Specifics:** `disk_cache`, `SimpleSynchronousEntry`, `SimpleFileHeader`, `SimpleFileEOF`, `SparseRange`. This points to a disk cache implementation.
* **Hashing/Checksums:** `hash_value`, `sha256`, `Crc32`. Data integrity and identification seem important.
* **Prefetching:** `PrefetchData`. Optimization for faster data retrieval.
* **Sparse Files:**  Multiple functions dealing with "sparse files" suggest a specific storage optimization.
* **Error Handling:** `net::ERR_FAILED`, `net::OK`, logging (`DLOG`, `DVLOG`).
* **Magic Numbers:** `kSimpleInitialMagicNumber`, `kSimpleFinalMagicNumber`, `kSimpleSparseRangeMagicNumber`. Used for file format validation.

**3. Segmenting the Code by Functionality:**

I start to mentally (or physically, if it's a large file) group related functions:

* **File Validation/Verification:** `VerifyStreamPrefetch`, `CheckHeaderAndKey`, `GetEOFRecordData`.
* **Data Reading:** `ReadFromFileOrPrefetched`.
* **File Deletion/Truncation:** `DeleteFileForEntryHash`, `DeleteFilesForEntryHash`, `TruncateFilesForEntryHash`.
* **Filename Management:** `GetFilenameFromFileIndex`, `GetFilenameForSubfile`.
* **Sparse File Management:** `OpenSparseFileIfExists`, `CreateSparseFile`, `CloseSparseFile`, `TruncateSparseFile`, `InitializeSparseFile`, `ScanSparseFile`, `ReadSparseRange`, `WriteSparseRange`, `AppendSparseRange`.

**4. Addressing Each Request Point:**

* **Functionality:** Based on the grouping, I can describe the core functionalities: verifying cache entry integrity, reading data (potentially from prefetch), managing the lifecycle of cache files (creation, deletion, truncation), and specifically managing sparse files for potentially large, infrequently accessed data.

* **JavaScript Relation:**  This requires thinking about where the network stack interacts with the browser. JavaScript makes network requests. The browser's network stack (including the cache) handles these requests. So, when JavaScript fetches a resource, this cache code *might* be involved in retrieving that resource from disk. The key is to connect the "network request initiated by JavaScript" to the "disk cache potentially serving that request."  Examples: fetching an image, a stylesheet, or a script.

* **Logical Reasoning (Input/Output):** I select a function like `ReadFromFileOrPrefetched` and consider different scenarios:
    * **Valid Input:**  What happens with correct file, offset, and size?
    * **Prefetch Hit:** How does the prefetch path work?
    * **Disk Read:** What happens if prefetch misses?
    * **Error Conditions:**  What if the offset or size is invalid?

* **User/Programming Errors:** I think about common mistakes developers might make when interacting with a cache or file system: incorrect file paths, incorrect sizes, failing to check return values, assuming data is always present.

* **User Operation to Reach Here:**  I trace back from the cache. A user action triggers a network request. The network stack checks the cache. If the data is present and valid, this code could be involved in reading it. Examples: loading a webpage, clicking a link, refreshing a page.

* **Overall Functionality (Part 3 Summary):** I focus on the *specific* functions in this snippet. The emphasis here is on *validation*, *sparse file management*, and *file lifecycle operations* (deletion/truncation). The prefetching aspect is also present.

**5. Refining and Structuring the Answer:**

I organize my thoughts into a clear and structured answer, using headings and bullet points for readability. I try to use precise language and avoid jargon where possible, or explain it when necessary. I provide concrete examples to illustrate the concepts.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:** "Maybe this code directly interacts with the DOM."  **Correction:**  It's more likely a lower-level component, and the interaction with the DOM is indirect via the network stack and rendering engine.
* **Initial Thought:** "Sparse files are just for saving space." **Refinement:** While true,  the code also shows structures for managing ranges within the sparse file and checksums for integrity, suggesting a more sophisticated usage pattern.
* **Overly Technical Language:**  I might initially use terms like "inode" or "block allocation." **Refinement:**  For a general explanation, I'd use more accessible terms like "file" and "disk space."

By following this process of understanding the request, scanning the code, segmenting functionality, addressing each point systematically, and refining the answer, I can arrive at a comprehensive and accurate explanation of the provided code snippet.
这是目录为 `net/disk_cache/simple/simple_synchronous_entry.cc` 的 Chromium 网络栈源代码文件的第 3 部分，总共 3 部分。基于你提供的代码片段，我们可以归纳一下这部分代码的主要功能：

**主要功能归纳：**

这部分代码主要负责 `SimpleSynchronousEntry` 类中关于**数据读取验证、文件级别的删除和截断操作，以及稀疏文件（Sparse File）的管理**。具体来说包括：

1. **读取前的校验和密钥验证:**  在从文件或预取数据中读取数据之前，进行哈希值比对，以及在必要时进行头部和密钥的完整性检查，确保读取数据的正确性。

2. **从文件或预取数据中读取数据:** 提供了一个通用的 `ReadFromFileOrPrefetched` 方法，可以从普通文件或者预先加载的 `PrefetchData` 中读取指定偏移量和大小的数据。

3. **读取文件结尾记录 (EOF Record):**  提供 `GetEOFRecordData` 方法来读取并校验文件结尾的魔数和流大小，用于判断文件是否完整以及获取流的大小信息。

4. **文件删除操作:** 提供了静态方法 `DeleteFileForEntryHash` 和 `DeleteFilesForEntryHash`，用于根据条目的哈希值删除单个或多个与该条目相关的文件，包括普通的流文件和稀疏文件。

5. **文件截断操作:** 提供了静态方法 `TruncateFilesForEntryHash`，用于根据条目的哈希值截断与该条目相关的普通流文件和稀疏文件。

6. **文件名管理:**  提供方法 `GetFilenameFromFileIndex` 和 `GetFilenameForSubfile`，用于根据文件索引或子文件类型获取对应的文件名。

7. **稀疏文件管理:**  提供了一系列方法来管理稀疏文件，包括：
    * `OpenSparseFileIfExists`: 打开已存在的稀疏文件。
    * `CreateSparseFile`: 创建新的稀疏文件。
    * `CloseSparseFile`: 关闭稀疏文件，并在必要时删除。
    * `TruncateSparseFile`: 截断稀疏文件。
    * `InitializeSparseFile`: 初始化稀疏文件的头部和密钥信息。
    * `ScanSparseFile`: 扫描稀疏文件，读取已存在的稀疏数据范围信息。
    * `ReadSparseRange`: 读取稀疏文件中的指定数据范围。
    * `WriteSparseRange`: 写入或更新稀疏文件中的指定数据范围。
    * `AppendSparseRange`: 向稀疏文件追加新的数据范围。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 代码交互，但它作为 Chromium 浏览器网络栈的一部分，其功能最终会影响到 JavaScript 的执行和行为。当 JavaScript 发起网络请求并需要从缓存中获取资源时，这段代码可能会被调用来读取缓存的数据。

**举例说明：**

假设一个 JavaScript 脚本尝试加载一个大型的图片资源：

1. **JavaScript 发起请求:**  `const image = new Image(); image.src = 'https://example.com/large_image.jpg';`
2. **浏览器网络栈处理:** 浏览器网络栈会检查本地缓存是否已存在该资源。
3. **Simple Cache 查找:** 如果使用 Simple Cache，系统可能会调用 `SimpleSynchronousEntry` 来查找对应的缓存条目。
4. **数据读取:** 如果找到了缓存条目，并且资源可能存储在稀疏文件中，那么 `ReadSparseRange` 方法会被调用来读取图片数据的一部分或全部。读取的数据最终会返回给网络栈。
5. **数据传递给渲染引擎:** 网络栈将数据传递给渲染引擎，最终 JavaScript 可以操作加载的图片。

**逻辑推理（假设输入与输出）：**

**假设输入 (对于 `ReadFromFileOrPrefetched` 方法):**

* `file`: 指向一个已打开的缓存文件 `base::File` 对象的指针。
* `prefetch_data`:  `nullptr` (假设没有预取数据)。
* `file_index`: 0 (假设读取的是第一个文件)。
* `offset`: 1024 (从文件的 1024 字节偏移处开始读取)。
* `size`: 2048 (读取 2048 字节的数据)。
* `dest`: 指向一个大小至少为 2048 字节的字符数组的指针。

**预期输出:**

* 如果文件存在且可以成功读取，`ReadFromFileOrPrefetched` 将返回 `true`，并且 `dest` 数组中会包含从文件中读取的 2048 字节的数据。
* 如果文件读取失败（例如，文件不存在或读取超出文件末尾），`ReadFromFileOrPrefetched` 将返回 `false`。

**涉及用户或编程常见的使用错误：**

1. **不正确的偏移量或大小:** 程序员在调用读取方法时，可能传入了负数的偏移量或大小，或者偏移量加上大小超出了文件实际大小。代码中已经有对这些情况的检查 (`offset < 0 || size < 0`)，但如果计算不当仍然可能导致错误。
   ```c++
   // 错误示例：假设文件大小为 1000 字节
   int offset = 900;
   int size = 200; // offset + size = 1100，超出文件大小
   char buffer[200];
   // ... 调用 ReadFromFileOrPrefetched ...
   ```
   这可能导致读取失败或读取到不完整的数据。

2. **缓冲区大小不足:**  程序员提供的 `dest` 缓冲区可能小于要读取的 `size`，导致缓冲区溢出。
   ```c++
   int size = 2048;
   char buffer[1024]; // 缓冲区太小
   // ... 调用 ReadFromFileOrPrefetched ...
   ```
   虽然 `ReadFromFileOrPrefetched` 本身不会直接导致内存错误，但在后续使用 `buffer` 时可能会出现问题。

3. **文件未打开或已关闭:**  在调用读取方法之前，`base::File` 对象可能没有被正确打开，或者已经被关闭，导致读取操作失败。

**用户操作如何一步步的到达这里（作为调试线索）：**

1. **用户在浏览器中输入网址并访问一个网页。**
2. **浏览器解析网页内容，发现需要加载一些资源，例如图片、CSS 文件、JavaScript 文件等。**
3. **浏览器网络栈发起对这些资源的请求。**
4. **网络栈检查缓存系统 (Simple Cache)。**
5. **如果资源存在于缓存中，缓存系统会查找对应的 `SimpleSynchronousEntry`。**
6. **为了验证缓存数据的有效性或读取数据，可能会调用 `VerifyStreamPrefetch`，`CheckHeaderAndKey`，`GetEOFRecordData` 等方法。**
7. **最终，如果需要从磁盘读取数据，`ReadFromFileOrPrefetched` 或 `ReadSparseRange` 等方法会被调用，读取缓存文件中的内容。**

**总结这部分代码的功能：**

总而言之，这部分 `SimpleSynchronousEntry.cc` 的代码专注于**确保从磁盘缓存中读取数据的完整性和正确性，管理缓存文件的生命周期（删除和截断），并提供了一种高效管理大型、不连续数据的机制，即稀疏文件**。它在 Chromium 浏览器的缓存系统中扮演着至关重要的角色，保证了缓存数据的可靠访问，从而提升网页加载速度和用户体验。

### 提示词
```
这是目录为net/disk_cache/simple/simple_synchronous_entry.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
fKey(key, &hash_value);
    bool matched =
        std::memcmp(&hash_value,
                    stream_prefetch_data[0].data->data() + stream_0_size,
                    sizeof(hash_value)) == 0;
    if (!matched)
      return net::ERR_FAILED;

    // Elide header check if we verified sha256(key) via footer.
    header_and_key_check_needed_[0] = false;
  }

  // Ensure the key is validated before completion.
  if (!has_key_sha256 && header_and_key_check_needed_[0])
    CheckHeaderAndKey(file.get(), 0);

  return net::OK;
}

bool SimpleSynchronousEntry::ReadFromFileOrPrefetched(
    base::File* file,
    PrefetchData* prefetch_data,
    int file_index,
    int offset,
    int size,
    char* dest) {
  if (offset < 0 || size < 0)
    return false;
  if (size == 0)
    return true;

  base::CheckedNumeric<size_t> start(offset);
  size_t start_numeric;
  if (!start.AssignIfValid(&start_numeric))
    return false;

  base::CheckedNumeric<size_t> length(size);
  size_t length_numeric;
  if (!length.AssignIfValid(&length_numeric))
    return false;

  // First try to extract the desired range from the PrefetchData.
  if (file_index == 0 && prefetch_data &&
      prefetch_data->ReadData(start_numeric, length_numeric, dest)) {
    return true;
  }

  // If we have not prefetched the range then we must read it from disk.
  return file->Read(start_numeric, dest, length_numeric) == size;
}

int SimpleSynchronousEntry::GetEOFRecordData(base::File* file,
                                             PrefetchData* prefetch_data,
                                             int file_index,
                                             int file_offset,
                                             SimpleFileEOF* eof_record) {
  if (!ReadFromFileOrPrefetched(file, prefetch_data, file_index, file_offset,
                                sizeof(SimpleFileEOF),
                                reinterpret_cast<char*>(eof_record))) {
    RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_READ_FAILURE);
    return net::ERR_CACHE_CHECKSUM_READ_FAILURE;
  }

  if (eof_record->final_magic_number != kSimpleFinalMagicNumber) {
    RecordCheckEOFResult(cache_type_, CHECK_EOF_RESULT_MAGIC_NUMBER_MISMATCH);
    DVLOG(1) << "EOF record had bad magic number.";
    return net::ERR_CACHE_CHECKSUM_READ_FAILURE;
  }

  if (!base::IsValueInRangeForNumericType<int32_t>(eof_record->stream_size))
    return net::ERR_FAILED;
  return net::OK;
}

// static
bool SimpleSynchronousEntry::DeleteFileForEntryHash(
    const FilePath& path,
    const uint64_t entry_hash,
    const int file_index,
    BackendFileOperations* file_operations) {
  FilePath to_delete = path.AppendASCII(GetFilenameFromEntryFileKeyAndFileIndex(
      SimpleFileTracker::EntryFileKey(entry_hash), file_index));
  return file_operations->DeleteFile(to_delete);
}

// static
bool SimpleSynchronousEntry::DeleteFilesForEntryHash(
    const FilePath& path,
    const uint64_t entry_hash,
    BackendFileOperations* file_operations) {
  bool result = true;
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
    if (!DeleteFileForEntryHash(path, entry_hash, i, file_operations) &&
        !CanOmitEmptyFile(i)) {
      result = false;
    }
  }
  FilePath to_delete = path.AppendASCII(GetSparseFilenameFromEntryFileKey(
      SimpleFileTracker::EntryFileKey(entry_hash)));
  file_operations->DeleteFile(
      to_delete,
      BackendFileOperations::DeleteFileMode::kEnsureImmediateAvailability);
  return result;
}

// static
bool SimpleSynchronousEntry::TruncateFilesForEntryHash(
    const FilePath& path,
    const uint64_t entry_hash,
    BackendFileOperations* file_operations) {
  SimpleFileTracker::EntryFileKey file_key(entry_hash);
  bool result = true;
  for (int i = 0; i < kSimpleEntryNormalFileCount; ++i) {
    FilePath filename_to_truncate =
        path.AppendASCII(GetFilenameFromEntryFileKeyAndFileIndex(file_key, i));
    if (!TruncatePath(filename_to_truncate, file_operations))
      result = false;
  }
  FilePath to_delete =
      path.AppendASCII(GetSparseFilenameFromEntryFileKey(file_key));
  TruncatePath(to_delete, file_operations);
  return result;
}

FilePath SimpleSynchronousEntry::GetFilenameFromFileIndex(
    int file_index) const {
  return path_.AppendASCII(
      GetFilenameFromEntryFileKeyAndFileIndex(entry_file_key_, file_index));
}

base::FilePath SimpleSynchronousEntry::GetFilenameForSubfile(
    SimpleFileTracker::SubFile sub_file) const {
  if (sub_file == SimpleFileTracker::SubFile::FILE_SPARSE)
    return path_.AppendASCII(
        GetSparseFilenameFromEntryFileKey(entry_file_key_));
  else
    return GetFilenameFromFileIndex(FileIndexForSubFile(sub_file));
}

bool SimpleSynchronousEntry::OpenSparseFileIfExists(
    BackendFileOperations* file_operations,
    int32_t* out_sparse_data_size) {
  DCHECK(!sparse_file_open());

  FilePath filename =
      path_.AppendASCII(GetSparseFilenameFromEntryFileKey(entry_file_key_));
  int flags = base::File::FLAG_OPEN | base::File::FLAG_READ |
              base::File::FLAG_WRITE | base::File::FLAG_WIN_SHARE_DELETE;
  auto sparse_file =
      std::make_unique<base::File>(file_operations->OpenFile(filename, flags));
  if (!sparse_file->IsValid()) {
    // No file -> OK, file open error -> 'trouble.
    return sparse_file->error_details() == base::File::FILE_ERROR_NOT_FOUND;
  }

  if (!ScanSparseFile(sparse_file.get(), out_sparse_data_size))
    return false;

  file_tracker_->Register(this, SimpleFileTracker::SubFile::FILE_SPARSE,
                          std::move(sparse_file));
  sparse_file_open_ = true;
  return true;
}

bool SimpleSynchronousEntry::CreateSparseFile(
    BackendFileOperations* file_operations) {
  DCHECK(!sparse_file_open());

  FilePath filename =
      path_.AppendASCII(GetSparseFilenameFromEntryFileKey(entry_file_key_));
  int flags = base::File::FLAG_CREATE | base::File::FLAG_READ |
              base::File::FLAG_WRITE | base::File::FLAG_WIN_SHARE_DELETE;
  std::unique_ptr<base::File> sparse_file =
      std::make_unique<base::File>(file_operations->OpenFile(filename, flags));
  if (!sparse_file->IsValid())
    return false;
  if (!InitializeSparseFile(sparse_file.get()))
    return false;
  file_tracker_->Register(this, SimpleFileTracker::SubFile::FILE_SPARSE,
                          std::move(sparse_file));
  sparse_file_open_ = true;
  return true;
}

void SimpleSynchronousEntry::CloseSparseFile(
    BackendFileOperations* file_operations) {
  DCHECK(sparse_file_open());
  if (entry_file_key_.doom_generation != 0u) {
    file_operations->DeleteFile(
        path_.AppendASCII(GetSparseFilenameFromEntryFileKey(entry_file_key_)));
  }
  file_tracker_->Close(this, SimpleFileTracker::SubFile::FILE_SPARSE);
  sparse_file_open_ = false;
}

bool SimpleSynchronousEntry::TruncateSparseFile(base::File* sparse_file) {
  DCHECK(sparse_file_open());

  int64_t header_and_key_length = sizeof(SimpleFileHeader) + key_->size();
  if (!sparse_file->SetLength(header_and_key_length)) {
    DLOG(WARNING) << "Could not truncate sparse file";
    return false;
  }

  sparse_ranges_.clear();
  sparse_tail_offset_ = header_and_key_length;

  return true;
}

bool SimpleSynchronousEntry::InitializeSparseFile(base::File* sparse_file) {
  SimpleFileHeader header;
  header.initial_magic_number = kSimpleInitialMagicNumber;
  header.version = kSimpleVersion;
  const std::string& key = *key_;
  header.key_length = key.size();
  header.key_hash = base::PersistentHash(key);

  int header_write_result =
      sparse_file->Write(0, reinterpret_cast<char*>(&header), sizeof(header));
  if (header_write_result != sizeof(header)) {
    DLOG(WARNING) << "Could not write sparse file header";
    return false;
  }

  int key_write_result =
      sparse_file->Write(sizeof(header), key.data(), key.size());
  if (key_write_result != base::checked_cast<int>(key.size())) {
    DLOG(WARNING) << "Could not write sparse file key";
    return false;
  }

  sparse_ranges_.clear();
  sparse_tail_offset_ = sizeof(header) + key.size();

  return true;
}

bool SimpleSynchronousEntry::ScanSparseFile(base::File* sparse_file,
                                            int32_t* out_sparse_data_size) {
  int64_t sparse_data_size = 0;

  SimpleFileHeader header;
  int header_read_result =
      sparse_file->Read(0, reinterpret_cast<char*>(&header), sizeof(header));
  if (header_read_result != sizeof(header)) {
    DLOG(WARNING) << "Could not read header from sparse file.";
    return false;
  }

  if (header.initial_magic_number != kSimpleInitialMagicNumber) {
    DLOG(WARNING) << "Sparse file magic number did not match.";
    return false;
  }

  if (header.version < kLastCompatSparseVersion ||
      header.version > kSimpleVersion) {
    DLOG(WARNING) << "Sparse file unreadable version.";
    return false;
  }

  sparse_ranges_.clear();

  int64_t range_header_offset = sizeof(header) + key_->size();
  while (true) {
    SimpleFileSparseRangeHeader range_header;
    int range_header_read_result = sparse_file->Read(
        range_header_offset, reinterpret_cast<char*>(&range_header),
        sizeof(range_header));
    if (range_header_read_result == 0)
      break;
    if (range_header_read_result != sizeof(range_header)) {
      DLOG(WARNING) << "Could not read sparse range header.";
      return false;
    }

    if (range_header.sparse_range_magic_number !=
        kSimpleSparseRangeMagicNumber) {
      DLOG(WARNING) << "Invalid sparse range header magic number.";
      return false;
    }

    SparseRange range;
    range.offset = range_header.offset;
    range.length = range_header.length;
    range.data_crc32 = range_header.data_crc32;
    range.file_offset = range_header_offset + sizeof(range_header);
    sparse_ranges_.emplace(range.offset, range);

    range_header_offset += sizeof(range_header) + range.length;

    DCHECK_GE(sparse_data_size + range.length, sparse_data_size);
    sparse_data_size += range.length;
  }

  *out_sparse_data_size = static_cast<int32_t>(sparse_data_size);
  sparse_tail_offset_ = range_header_offset;

  return true;
}

bool SimpleSynchronousEntry::ReadSparseRange(base::File* sparse_file,
                                             const SparseRange* range,
                                             int offset,
                                             int len,
                                             char* buf) {
  DCHECK(range);
  DCHECK(buf);
  DCHECK_LE(offset, range->length);
  DCHECK_LE(offset + len, range->length);

  int bytes_read = sparse_file->Read(range->file_offset + offset, buf, len);
  if (bytes_read < len) {
    DLOG(WARNING) << "Could not read sparse range.";
    return false;
  }

  // If we read the whole range and we have a crc32, check it.
  if (offset == 0 && len == range->length && range->data_crc32 != 0) {
    if (simple_util::Crc32(buf, len) != range->data_crc32) {
      DLOG(WARNING) << "Sparse range crc32 mismatch.";
      return false;
    }
  }
  // TODO(morlovich): Incremental crc32 calculation?

  return true;
}

bool SimpleSynchronousEntry::WriteSparseRange(base::File* sparse_file,
                                              SparseRange* range,
                                              int offset,
                                              int len,
                                              const char* buf) {
  DCHECK(range);
  DCHECK(buf);
  DCHECK_LE(offset, range->length);
  DCHECK_LE(offset + len, range->length);

  uint32_t new_crc32 = 0;
  if (offset == 0 && len == range->length) {
    new_crc32 = simple_util::Crc32(buf, len);
  }

  if (new_crc32 != range->data_crc32) {
    range->data_crc32 = new_crc32;

    SimpleFileSparseRangeHeader header;
    header.sparse_range_magic_number = kSimpleSparseRangeMagicNumber;
    header.offset = range->offset;
    header.length = range->length;
    header.data_crc32 = range->data_crc32;

    int bytes_written =
        sparse_file->Write(range->file_offset - sizeof(header),
                           reinterpret_cast<char*>(&header), sizeof(header));
    if (bytes_written != base::checked_cast<int>(sizeof(header))) {
      DLOG(WARNING) << "Could not rewrite sparse range header.";
      return false;
    }
  }

  int bytes_written = sparse_file->Write(range->file_offset + offset, buf, len);
  if (bytes_written < len) {
    DLOG(WARNING) << "Could not write sparse range.";
    return false;
  }

  return true;
}

bool SimpleSynchronousEntry::AppendSparseRange(base::File* sparse_file,
                                               int64_t offset,
                                               int len,
                                               const char* buf) {
  DCHECK_GE(offset, 0);
  DCHECK_GT(len, 0);
  DCHECK(buf);

  uint32_t data_crc32 = simple_util::Crc32(buf, len);

  SimpleFileSparseRangeHeader header;
  header.sparse_range_magic_number = kSimpleSparseRangeMagicNumber;
  header.offset = offset;
  header.length = len;
  header.data_crc32 = data_crc32;

  int bytes_written = sparse_file->Write(
      sparse_tail_offset_, reinterpret_cast<char*>(&header), sizeof(header));
  if (bytes_written != base::checked_cast<int>(sizeof(header))) {
    DLOG(WARNING) << "Could not append sparse range header.";
    return false;
  }
  sparse_tail_offset_ += bytes_written;

  bytes_written = sparse_file->Write(sparse_tail_offset_, buf, len);
  if (bytes_written < len) {
    DLOG(WARNING) << "Could not append sparse range data.";
    return false;
  }
  int64_t data_file_offset = sparse_tail_offset_;
  sparse_tail_offset_ += bytes_written;

  SparseRange range;
  range.offset = offset;
  range.length = len;
  range.data_crc32 = data_crc32;
  range.file_offset = data_file_offset;
  sparse_ranges_.emplace(offset, range);

  return true;
}

}  // namespace disk_cache
```