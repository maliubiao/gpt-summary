Response:
Let's break down the thought process to analyze the `simple_index_file.cc` code and answer the prompt's questions.

**1. Understanding the Core Functionality:**

The filename `simple_index_file.cc` immediately suggests that this file deals with managing an index for the disk cache. Reading the initial comments confirms this. It's responsible for saving and loading the cache's index to/from disk.

**2. Identifying Key Classes and Structures:**

*   `SimpleIndexFile`: The primary class, containing logic for loading, saving, and related operations.
*   `IndexMetadata`: A nested struct within `SimpleIndexFile` that holds metadata about the index (entry count, cache size, write reason, etc.).
*   `SimpleIndexLoadResult`:  A struct to encapsulate the results of loading the index.
*   `SimpleIndexPickle`: A custom `base::Pickle` subclass, likely for adding a CRC checksum.
*   `EntryMetadata`:  (Referenced in the code but defined elsewhere)  Holds metadata about individual cache entries.

**3. Analyzing Function by Function (or Logical Block):**

*   **`CalculatePickleCRC`:** Straightforward, calculates a CRC checksum for a `base::Pickle`.
*   **`UmaRecord...` functions:** These are for recording UMA (User Metrics Analysis) data, providing insights into the index's state and loading processes. These don't directly affect core functionality but are important for monitoring.
*   **`WritePickleFile`:**  Writes a `base::Pickle` to a file, handling file creation and error checks.
*   **`ProcessEntryFile`:**  This is crucial. It's called when scanning the cache directory. It parses filenames, extracts hash keys, and updates the in-memory index (`entries`). It also handles potentially corrupt file sizes.
*   **`SimpleIndexLoadResult` methods:**  Simple constructors, destructors, and a `Reset` method.
*   **`SimpleIndexFile` constructors and destructor:** Standard C++ stuff.
*   **`LoadIndexEntries`:**  Asynchronous loading of the index, using a worker thread.
*   **`WriteToDisk`:** Asynchronous saving of the index to disk, also using the cache runner.
*   **`SyncWriteToDisk`:**  The *synchronous* implementation of saving the index. It creates a temporary file and then atomically replaces the old index file. This is a common pattern for ensuring data integrity.
*   **`IndexMetadata` methods (`Serialize`, `Deserialize`, `CheckIndexMetadata`):** These handle the serialization and deserialization of the index metadata, including versioning and integrity checks.
*   **`SyncLoadIndexEntries`:**  The core logic for loading or restoring the index. It first tries to load from the index file. If that fails or the index is stale, it scans the directory to rebuild the index.
*   **`SyncLoadFromDisk`:**  The synchronous implementation of loading the index from the index file.
*   **`Serialize`:**  Serializes the index metadata and all the entries into a `base::Pickle`.
*   **`Deserialize`:** Deserializes the index from a `base::Pickle`.
*   **`SyncRestoreFromDisk`:**  Scans the cache directory to reconstruct the index when the index file is corrupt or missing.
*   **`LegacyIsIndexFileStale`:**  A simple check to see if the index file's modification time is older than the cache directory's modification time.

**4. Answering the Specific Questions:**

*   **Functionality:** Summarize the purpose of each major component and how they interact.
*   **Relationship to JavaScript:**  This requires connecting the network stack to web browser behavior. JavaScript makes network requests, which are handled by the network stack. The disk cache is used to store responses to these requests, improving performance. The index file is vital for quickly finding cached resources. Provide a concrete example like fetching an image.
*   **Logical Reasoning (Hypothetical Input/Output):**  Choose a key function like `ProcessEntryFile` or `Deserialize` and illustrate its behavior with a simple example.
*   **User/Programming Errors:** Think about common mistakes related to file systems, data corruption, or assumptions about the cache.
*   **User Operations Leading to This Code:** Trace the user's actions from a high level (opening a webpage) down to the point where the index file might be accessed (cache lookup, cache initialization).
*   **Debugging Clues:**  Consider what information in this file would be helpful when diagnosing cache-related issues. Look for logging statements, UMA recording, and error handling.

**5. Refining and Organizing the Answer:**

Structure the answer clearly, using headings and bullet points. Provide specific examples and avoid vague statements. Review the code again to ensure all relevant aspects are covered. For instance, notice the handling of "todelete_" files, the maximum index size, and the different index states tracked by UMA.

**Self-Correction/Refinement During the Process:**

*   Initially, I might focus too much on the low-level file operations. I need to step back and explain the *why* – why is the index needed?  How does it fit into the broader caching mechanism?
*   When considering JavaScript, I need to be explicit about the connection. Simply saying "it's part of the network stack" isn't enough. I need to show how a user action (like clicking a link) leads to this code being executed.
*   For the hypothetical input/output, I should choose a simple case to illustrate the logic clearly, rather than getting bogged down in complex scenarios.
*   Regarding errors, think about the *consequences* of those errors. What happens if the index is corrupt? How does the system recover?
*   For debugging, consider the practicalities. What log messages would be most helpful?  What UMA metrics could indicate a problem?

By following these steps, combining code analysis with a broader understanding of the caching system and user interaction,  a comprehensive and accurate answer can be constructed.
这个文件 `net/disk_cache/simple/simple_index_file.cc` 是 Chromium 网络栈中简单缓存（Simple Cache）的一部分，其主要功能是**管理和持久化缓存的索引信息**。 索引是缓存的关键组成部分，它记录了缓存条目的元数据，使得缓存系统能够快速定位和访问存储在磁盘上的缓存数据。

以下是该文件的主要功能分解：

**1. 加载和保存缓存索引:**

*   **`LoadIndexEntries`:**  负责异步地从磁盘加载缓存索引。它会尝试读取之前保存的索引文件，如果加载失败（例如，文件不存在或损坏），则会通过扫描缓存目录来重建索引。
*   **`SyncLoadIndexEntries`:**  `LoadIndexEntries` 的同步版本，实际执行加载或重建索引的逻辑。它会判断现有的索引文件是否新鲜，如果过时或者不存在，则会触发 `SyncRestoreFromDisk`。
*   **`SyncLoadFromDisk`:**  负责同步地从指定的索引文件中读取索引数据。它会进行一些完整性检查，例如文件大小和 CRC 校验。
*   **`WriteToDisk`:** 负责异步地将当前内存中的缓存索引写入磁盘。它会将索引数据序列化到一个 `base::Pickle` 对象中，并使用临时文件进行原子写入操作，以确保数据一致性。
*   **`SyncWriteToDisk`:** `WriteToDisk` 的同步版本，实际执行将索引数据写入磁盘的操作。它会先写入到一个临时文件，然后原子地替换旧的索引文件。

**2. 索引数据的序列化和反序列化:**

*   **`Serialize`:** 将内存中的索引数据（包括元数据和所有缓存条目的信息）序列化成一个 `base::Pickle` 对象，以便写入磁盘。
*   **`Deserialize`:** 从磁盘读取的字节流中反序列化出缓存索引数据，包括索引的元数据和所有缓存条目的信息。

**3. 索引的重建:**

*   **`SyncRestoreFromDisk`:**  当无法加载或判断索引文件已过时时，会扫描整个缓存目录，并根据找到的缓存条目文件重建内存中的索引。它会解析文件名，提取哈希键，并读取文件的元数据。
*   **`ProcessEntryFile`:** 在 `SyncRestoreFromDisk` 过程中，对缓存目录中的每个文件调用此函数。它会判断是否是有效的缓存条目文件，解析文件名获取哈希键，并更新内存中的索引。

**4. 索引元数据的管理:**

*   **`IndexMetadata` 结构体:** 定义了索引文件的元数据结构，包括魔数、版本号、条目数量、缓存大小以及写入原因等信息。
*   **`Serialize` (针对 `IndexMetadata`) 和 `Deserialize` (针对 `IndexMetadata`)**:  负责序列化和反序列化索引的元数据部分。
*   **`CheckIndexMetadata`:**  对加载的索引元数据进行校验，例如检查魔数和版本号是否正确。

**5. 错误处理和日志记录:**

*   文件中包含大量的 `LOG(WARNING)` 和 `LOG(ERROR)` 语句，用于记录加载、保存和重建索引过程中遇到的错误，例如文件损坏、CRC 校验失败等。
*   使用 UMA (User Metrics Analysis) 宏记录索引加载的状态和性能指标，用于监控缓存的健康状况。

**与 JavaScript 的关系:**

`simple_index_file.cc` 本身不直接包含 JavaScript 代码，它属于 Chromium 的 C++ 网络栈部分。然而，它的功能对于浏览器加载网页和执行 JavaScript 代码至关重要。

**举例说明:**

1. **JavaScript 发起网络请求:** 当网页中的 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个网络请求时，Chromium 的网络栈会处理这个请求。
2. **缓存查找:** 在发起实际的网络请求之前，网络栈会检查磁盘缓存中是否已经存在该资源的缓存副本。
3. **索引查找:**  `simple_index_file.cc` 中加载的索引数据会被用来快速查找是否存在与当前请求相匹配的缓存条目。  例如，会根据请求的 URL 哈希查找对应的索引条目。
4. **缓存命中:** 如果索引中找到了匹配的条目，缓存系统就可以直接从磁盘读取缓存的数据，而无需再次从网络下载。这大大提高了页面加载速度，并减少了网络流量。
5. **缓存未命中:** 如果索引中没有找到匹配的条目，网络栈会发起实际的网络请求，并在收到响应后，将响应数据存储到磁盘缓存中，并更新索引文件。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器解析 URL，并构建网络请求。**
3. **网络栈接收到请求，首先会检查磁盘缓存。** 这时会涉及到 `SimpleCacheBackendImpl::GetEntry()` 或类似的方法。
4. **缓存后端会查找内存中的索引 (`SimpleIndex`)。**
5. **如果索引尚未加载或需要刷新，可能会调用 `SimpleIndexFile::LoadIndexEntries()`。**  这会触发从磁盘加载索引或重建索引的操作。
6. **在加载索引的过程中，`SyncLoadFromDisk` 或 `SyncRestoreFromDisk` 会被调用，从而执行 `simple_index_file.cc` 中的代码。**
7. **如果用户操作导致新的资源被缓存，或者现有缓存条目被更新，那么 `SimpleIndexFile::WriteToDisk()` 可能会被调用。**

**逻辑推理 (假设输入与输出):**

假设缓存目录中存在以下文件：

*   `index-dir/the-real-index`:  一个合法的索引文件。
*   `0123456789abcdef00`:  一个有效的缓存条目文件。
*   `todelete_somefile`:  一个待删除的临时文件。
*   `invalid_file`:  一个不符合缓存条目文件命名规则的文件。

**假设 `SyncRestoreFromDisk` 被调用:**

*   **输入:**  缓存目录的路径。
*   **输出:**  内存中的 `SimpleIndex::EntrySet` 会包含从 `0123456789abcdef00` 文件中解析出的缓存条目信息（哈希键和元数据）。
*   **中间步骤:**
    *   `ProcessEntryFile` 会被调用多次，分别处理缓存目录中的每个文件。
    *   对于 `todelete_somefile`，它会被直接删除。
    *   对于 `invalid_file`，`ProcessEntryFile` 会忽略它。
    *   对于 `0123456789abcdef00`，`ProcessEntryFile` 会解析文件名，提取哈希键，并读取文件的修改时间等元数据，然后将其添加到 `entries` 中。

**假设输入为一个合法的序列化后的索引数据（`base::Pickle` 对象），并且 `Deserialize` 被调用:**

*   **输入:**  指向序列化数据的指针 `data`，数据长度 `data_len`。
*   **输出:**  `out_result->entries` 会包含反序列化出的缓存条目信息。`out_cache_last_modified` 会被设置为索引中记录的最后缓存修改时间。`out_result->did_load` 会被设置为 `true`。
*   **中间步骤:**
    *   `Deserialize` 会首先检查 Pickle 头的有效性和 CRC 校验。
    *   然后，它会反序列化索引的元数据信息。
    *   接下来，它会循环读取每个缓存条目的哈希键和元数据，并添加到 `out_result->entries` 中。
    *   最后，它会读取缓存的最后修改时间。

**用户或编程常见的使用错误:**

1. **手动修改缓存目录中的文件:** 用户或程序直接修改或删除缓存目录中的文件，可能导致索引文件与实际文件状态不一致，造成数据损坏或缓存失效。`SyncRestoreFromDisk` 可以部分解决这个问题，但仍然可能导致数据丢失。
2. **磁盘空间不足:** 当磁盘空间不足时，缓存系统可能无法正常写入索引文件或缓存数据，导致数据丢失或程序崩溃。虽然代码中有检查文件大小的逻辑，但磁盘空间不足是更底层的问题。
3. **文件系统错误:** 底层文件系统出现错误可能导致索引文件损坏，`Deserialize` 可能会因为 CRC 校验失败或无法读取文件而失败。
4. **并发访问冲突 (理论上，由于使用了临时文件进行原子写入，这种情况应该被避免):**  如果多个进程或线程同时尝试修改缓存索引文件，可能会导致数据不一致。 Chromium 的缓存系统通常会使用锁机制来避免这种情况。
5. **不正确的缓存配置:**  错误的缓存大小或路径配置可能导致缓存无法正常工作。

**调试线索:**

*   **日志输出:**  查看 Chromium 的日志输出 (chrome://net-export/)，可以找到与缓存加载、保存和重建相关的警告和错误信息。
*   **UMA 指标:**  通过 `chrome://histograms` 可以查看与缓存相关的 UMA 指标，例如 `IndexFileStateOnLoad` 可以指示索引文件的加载状态，`IndexRestoreTime` 可以显示重建索引所花费的时间。
*   **文件内容:**  在开发环境中，可以检查索引文件的内容（尽管它是二进制格式）。了解索引文件的结构可以帮助理解序列化和反序列化的过程。
*   **断点调试:**  在 `simple_index_file.cc` 中设置断点，可以逐步跟踪索引加载、保存和重建的流程，查看变量的值，理解代码的执行逻辑。
*   **缓存统计信息:**  通过 `chrome://cache/` 可以查看当前缓存的统计信息，例如条目数量、占用空间等，这可以帮助判断索引是否与实际缓存数据一致。

总而言之，`simple_index_file.cc` 是 Chromium 简单缓存中负责管理和持久化索引的关键文件，它对于缓存的快速查找和高效运行至关重要。理解其功能和工作原理对于理解 Chromium 的缓存机制以及排查缓存相关问题非常有帮助。

### 提示词
```
这是目录为net/disk_cache/simple/simple_index_file.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/341324165): Fix and remove.
#pragma allow_unsafe_buffers
#endif

#include "net/disk_cache/simple/simple_index_file.h"

#include <utility>
#include <vector>

#include "base/files/file.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "base/strings/string_util.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_entry_format.h"
#include "net/disk_cache/simple/simple_file_enumerator.h"
#include "net/disk_cache/simple/simple_histogram_macros.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/disk_cache/simple/simple_synchronous_entry.h"
#include "net/disk_cache/simple/simple_util.h"

namespace disk_cache {
namespace {

const int kEntryFilesHashLength = 16;
const int kEntryFilesSuffixLength = 2;

// Limit on how big a file we are willing to work with, to avoid crashes
// when its corrupt.
const int kMaxEntriesInIndex = 1000000;

// Here 8 comes from the key size.
const int64_t kMaxIndexFileSizeBytes =
    kMaxEntriesInIndex * (8 + EntryMetadata::kOnDiskSizeBytes);

uint32_t CalculatePickleCRC(const base::Pickle& pickle) {
  return simple_util::Crc32(pickle.payload_bytes());
}

// Used in histograms. Please only add new values at the end.
enum IndexFileState {
  INDEX_STATE_CORRUPT = 0,
  INDEX_STATE_STALE = 1,
  INDEX_STATE_FRESH = 2,
  INDEX_STATE_FRESH_CONCURRENT_UPDATES = 3,
  INDEX_STATE_MAX = 4,
};

enum StaleIndexQuality {
  STALE_INDEX_OK = 0,
  STALE_INDEX_MISSED_ENTRIES = 1,
  STALE_INDEX_EXTRA_ENTRIES = 2,
  STALE_INDEX_BOTH_MISSED_AND_EXTRA_ENTRIES = 3,
  STALE_INDEX_MAX = 4,
};

void UmaRecordIndexFileState(IndexFileState state, net::CacheType cache_type) {
  SIMPLE_CACHE_UMA(ENUMERATION,
                   "IndexFileStateOnLoad", cache_type, state, INDEX_STATE_MAX);
}

void UmaRecordIndexInitMethod(SimpleIndex::IndexInitMethod method,
                              net::CacheType cache_type) {
  SIMPLE_CACHE_UMA(ENUMERATION, "IndexInitializeMethod", cache_type, method,
                   SimpleIndex::INITIALIZE_METHOD_MAX);
}

void UmaRecordStaleIndexQuality(int missed_entry_count,
                                int extra_entry_count,
                                net::CacheType cache_type) {
  SIMPLE_CACHE_UMA(CUSTOM_COUNTS, "StaleIndexMissedEntryCount", cache_type,
                   missed_entry_count, 1, 100, 5);
  SIMPLE_CACHE_UMA(CUSTOM_COUNTS, "StaleIndexExtraEntryCount", cache_type,
                   extra_entry_count, 1, 100, 5);

  StaleIndexQuality quality;
  if (missed_entry_count > 0 && extra_entry_count > 0)
    quality = STALE_INDEX_BOTH_MISSED_AND_EXTRA_ENTRIES;
  else if (missed_entry_count > 0)
    quality = STALE_INDEX_MISSED_ENTRIES;
  else if (extra_entry_count > 0)
    quality = STALE_INDEX_EXTRA_ENTRIES;
  else
    quality = STALE_INDEX_OK;
  SIMPLE_CACHE_UMA(ENUMERATION, "StaleIndexQuality", cache_type, quality,
                   STALE_INDEX_MAX);
}

struct PickleHeader : public base::Pickle::Header {
  uint32_t crc;
};

class SimpleIndexPickle : public base::Pickle {
 public:
  SimpleIndexPickle() : base::Pickle(sizeof(PickleHeader)) {}
  explicit SimpleIndexPickle(base::span<const uint8_t> data)
      : base::Pickle(base::Pickle::kUnownedData, data) {}

  bool HeaderValid() const { return header_size() == sizeof(PickleHeader); }
};

bool WritePickleFile(BackendFileOperations* file_operations,
                     base::Pickle* pickle,
                     const base::FilePath& file_name) {
  base::File file = file_operations->OpenFile(
      file_name, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE |
                     base::File::FLAG_WIN_SHARE_DELETE);
  if (!file.IsValid())
    return false;

  int bytes_written = file.Write(0, pickle->data_as_char(), pickle->size());
  if (bytes_written != base::checked_cast<int>(pickle->size())) {
    file_operations->DeleteFile(
        file_name,
        BackendFileOperations::DeleteFileMode::kEnsureImmediateAvailability);
    return false;
  }
  return true;
}

// Called for each cache directory traversal iteration.
void ProcessEntryFile(BackendFileOperations* file_operations,
                      net::CacheType cache_type,
                      SimpleIndex::EntrySet* entries,
                      const base::FilePath& file_path,
                      base::Time last_accessed,
                      base::Time last_modified,
                      int64_t size) {
  static const size_t kEntryFilesLength =
      kEntryFilesHashLength + kEntryFilesSuffixLength;
  // Converting to std::string is OK since we never use UTF8 wide chars in our
  // file names.
  const base::FilePath::StringType base_name = file_path.BaseName().value();
  const std::string file_name(base_name.begin(), base_name.end());

  // Cleanup any left over doomed entries.
  if (file_name.starts_with("todelete_")) {
    file_operations->DeleteFile(file_path);
    return;
  }

  if (file_name.size() != kEntryFilesLength)
    return;
  const auto hash_string = base::MakeStringPiece(
      file_name.begin(), file_name.begin() + kEntryFilesHashLength);
  uint64_t hash_key = 0;
  if (!simple_util::GetEntryHashKeyFromHexString(hash_string, &hash_key)) {
    LOG(WARNING) << "Invalid entry hash key filename while restoring index from"
                 << " disk: " << file_name;
    return;
  }

  base::Time last_used_time;
#if BUILDFLAG(IS_POSIX)
  // For POSIX systems, a last access time is available. However, it's not
  // guaranteed to be more accurate than mtime. It is no worse though.
  last_used_time = last_accessed;
#endif
  if (last_used_time.is_null())
    last_used_time = last_modified;

  auto it = entries->find(hash_key);
  base::CheckedNumeric<uint32_t> total_entry_size = size;

  // Sometimes we see entry sizes here which are nonsense. We can't use them
  // as-is, as they simply won't fit the type. The options that come to mind
  // are:
  // 1) Ignore the file.
  // 2) Make something up.
  // 3) Delete the files for the hash.
  // ("crash the browser" isn't considered a serious alternative).
  //
  // The problem with doing (1) is that we are recovering the index here, so if
  // we don't include the info on the file here, we may completely lose track of
  // the entry and never clean the file up.
  //
  // (2) is actually mostly fine: we may trigger eviction too soon or too late,
  // but we can't really do better since we can't trust the size. If the entry
  // is never opened, it will eventually get evicted. If it is opened, we will
  // re-check the file size, and if it's nonsense delete it there, and if it's
  // fine we will fix up the index via a UpdateDataFromEntryStat to have the
  // correct size.
  //
  // (3) does the best thing except when the wrong size is some weird interim
  // thing just on directory listing (in which case it may evict an entry
  // prematurely). It's a little harder to think about since it involves
  // mutating the disk while there are other mutations going on, however,
  // while (2) is single-threaded.
  //
  // Hence this picks (2).

  const int kPlaceHolderSizeWhenInvalid = 32768;
  if (!total_entry_size.IsValid()) {
    LOG(WARNING) << "Invalid file size while restoring index from disk: "
                 << size << " on file:" << file_name;
  }

  if (it == entries->end()) {
    uint32_t size_to_use =
        total_entry_size.ValueOrDefault(kPlaceHolderSizeWhenInvalid);
    if (cache_type == net::APP_CACHE) {
      SimpleIndex::InsertInEntrySet(
          hash_key, EntryMetadata(0 /* trailer_prefetch_size */, size_to_use),
          entries);
    } else {
      SimpleIndex::InsertInEntrySet(
          hash_key, EntryMetadata(last_used_time, size_to_use), entries);
    }
  } else {
    // Summing up the total size of the entry through all the *_[0-1] files
    total_entry_size += it->second.GetEntrySize();
    it->second.SetEntrySize(
        total_entry_size.ValueOrDefault(kPlaceHolderSizeWhenInvalid));
  }
}

}  // namespace

SimpleIndexLoadResult::SimpleIndexLoadResult() = default;

SimpleIndexLoadResult::~SimpleIndexLoadResult() = default;

void SimpleIndexLoadResult::Reset() {
  did_load = false;
  index_write_reason = SimpleIndex::INDEX_WRITE_REASON_MAX;
  flush_required = false;
  entries.clear();
}

// static
const char SimpleIndexFile::kIndexFileName[] = "the-real-index";
// static
const char SimpleIndexFile::kIndexDirectory[] = "index-dir";
// static
const char SimpleIndexFile::kTempIndexFileName[] = "temp-index";

SimpleIndexFile::IndexMetadata::IndexMetadata()
    : reason_(SimpleIndex::INDEX_WRITE_REASON_MAX),
      entry_count_(0),
      cache_size_(0) {}

SimpleIndexFile::IndexMetadata::IndexMetadata(
    SimpleIndex::IndexWriteToDiskReason reason,
    uint64_t entry_count,
    uint64_t cache_size)
    : reason_(reason), entry_count_(entry_count), cache_size_(cache_size) {}

void SimpleIndexFile::IndexMetadata::Serialize(base::Pickle* pickle) const {
  DCHECK(pickle);
  pickle->WriteUInt64(magic_number_);
  pickle->WriteUInt32(version_);
  pickle->WriteUInt64(entry_count_);
  pickle->WriteUInt64(cache_size_);
  pickle->WriteUInt32(static_cast<uint32_t>(reason_));
}

// static
void SimpleIndexFile::SerializeFinalData(base::Time cache_modified,
                                         base::Pickle* pickle) {
  pickle->WriteInt64(cache_modified.ToInternalValue());
  PickleHeader* header_p = pickle->headerT<PickleHeader>();
  header_p->crc = CalculatePickleCRC(*pickle);
}

bool SimpleIndexFile::IndexMetadata::Deserialize(base::PickleIterator* it) {
  DCHECK(it);

  bool v6_format_index_read_results =
      it->ReadUInt64(&magic_number_) && it->ReadUInt32(&version_) &&
      it->ReadUInt64(&entry_count_) && it->ReadUInt64(&cache_size_);
  if (!v6_format_index_read_results)
    return false;
  if (version_ >= 7) {
    uint32_t tmp_reason;
    if (!it->ReadUInt32(&tmp_reason))
      return false;
    reason_ = static_cast<SimpleIndex::IndexWriteToDiskReason>(tmp_reason);
  }
  return true;
}

void SimpleIndexFile::SyncWriteToDisk(
    std::unique_ptr<BackendFileOperations> file_operations,
    net::CacheType cache_type,
    const base::FilePath& cache_directory,
    const base::FilePath& index_filename,
    const base::FilePath& temp_index_filename,
    std::unique_ptr<base::Pickle> pickle) {
  DCHECK_EQ(index_filename.DirName().value(),
            temp_index_filename.DirName().value());
  base::FilePath index_file_directory = temp_index_filename.DirName();
  if (!file_operations->DirectoryExists(index_file_directory) &&
      !file_operations->CreateDirectory(index_file_directory)) {
    LOG(ERROR) << "Could not create a directory to hold the index file";
    return;
  }

  // There is a chance that the index containing all the necessary data about
  // newly created entries will appear to be stale. This can happen if on-disk
  // part of a Create operation does not fit into the time budget for the index
  // flush delay. This simple approach will be reconsidered if it does not allow
  // for maintaining freshness.
  base::Time cache_dir_mtime;
  std::optional<base::File::Info> file_info =
      file_operations->GetFileInfo(cache_directory);
  if (!file_info) {
    LOG(ERROR) << "Could not obtain information about cache age";
    return;
  }
  cache_dir_mtime = file_info->last_modified;
  SerializeFinalData(cache_dir_mtime, pickle.get());
  if (!WritePickleFile(file_operations.get(), pickle.get(),
                       temp_index_filename)) {
    LOG(ERROR) << "Failed to write the temporary index file";
    return;
  }

  // Atomically rename the temporary index file to become the real one.
  if (!file_operations->ReplaceFile(temp_index_filename, index_filename,
                                    nullptr)) {
    return;
  }
}

bool SimpleIndexFile::IndexMetadata::CheckIndexMetadata() {
  if (entry_count_ > kMaxEntriesInIndex ||
      magic_number_ != kSimpleIndexMagicNumber) {
    return false;
  }

  static_assert(kSimpleVersion == 9, "index metadata reader out of date");
  // No |reason_| is saved in the version 6 file format.
  if (version_ == 6)
    return reason_ == SimpleIndex::INDEX_WRITE_REASON_MAX;
  return (version_ == 7 || version_ == 8 || version_ == 9) &&
         reason_ < SimpleIndex::INDEX_WRITE_REASON_MAX;
}

SimpleIndexFile::SimpleIndexFile(
    scoped_refptr<base::SequencedTaskRunner> cache_runner,
    scoped_refptr<BackendFileOperationsFactory> file_operations_factory,
    net::CacheType cache_type,
    const base::FilePath& cache_directory)
    : cache_runner_(std::move(cache_runner)),
      file_operations_factory_(std::move(file_operations_factory)),
      cache_type_(cache_type),
      cache_directory_(cache_directory),
      index_file_(cache_directory_.AppendASCII(kIndexDirectory)
                      .AppendASCII(kIndexFileName)),
      temp_index_file_(cache_directory_.AppendASCII(kIndexDirectory)
                           .AppendASCII(kTempIndexFileName)) {}

SimpleIndexFile::~SimpleIndexFile() = default;

void SimpleIndexFile::LoadIndexEntries(base::Time cache_last_modified,
                                       base::OnceClosure callback,
                                       SimpleIndexLoadResult* out_result) {
  auto task_runner = base::ThreadPool::CreateSequencedTaskRunner(
      SimpleBackendImpl::kWorkerPoolTaskTraits);
  base::OnceClosure task = base::BindOnce(
      &SimpleIndexFile::SyncLoadIndexEntries,
      file_operations_factory_->Create(task_runner), cache_type_,
      cache_last_modified, cache_directory_, index_file_, out_result);
  task_runner->PostTaskAndReply(FROM_HERE, std::move(task),
                                std::move(callback));
}

void SimpleIndexFile::WriteToDisk(net::CacheType cache_type,
                                  SimpleIndex::IndexWriteToDiskReason reason,
                                  const SimpleIndex::EntrySet& entry_set,
                                  uint64_t cache_size,
                                  base::OnceClosure callback) {
  IndexMetadata index_metadata(reason, entry_set.size(), cache_size);
  std::unique_ptr<base::Pickle> pickle =
      Serialize(cache_type, index_metadata, entry_set);
  auto file_operations = file_operations_factory_->Create(cache_runner_);
  base::OnceClosure task =
      base::BindOnce(&SimpleIndexFile::SyncWriteToDisk,
                     std::move(file_operations), cache_type_, cache_directory_,
                     index_file_, temp_index_file_, std::move(pickle));
  if (callback.is_null())
    cache_runner_->PostTask(FROM_HERE, std::move(task));
  else
    cache_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                    std::move(callback));
}

// static
void SimpleIndexFile::SyncLoadIndexEntries(
    std::unique_ptr<BackendFileOperations> file_operations,
    net::CacheType cache_type,
    base::Time cache_last_modified,
    const base::FilePath& cache_directory,
    const base::FilePath& index_file_path,
    SimpleIndexLoadResult* out_result) {
  // Load the index and find its age.
  base::Time last_cache_seen_by_index;
  SyncLoadFromDisk(file_operations.get(), cache_type, index_file_path,
                   &last_cache_seen_by_index, out_result);

  // Consider the index loaded if it is fresh.
  const bool index_file_existed = file_operations->PathExists(index_file_path);
  if (!out_result->did_load) {
    if (index_file_existed)
      UmaRecordIndexFileState(INDEX_STATE_CORRUPT, cache_type);
  } else {
    if (cache_last_modified <= last_cache_seen_by_index) {
      base::Time latest_dir_mtime;
      if (auto info = file_operations->GetFileInfo(cache_directory)) {
        latest_dir_mtime = info->last_modified;
      }
      if (LegacyIsIndexFileStale(file_operations.get(), latest_dir_mtime,
                                 index_file_path)) {
        UmaRecordIndexFileState(INDEX_STATE_FRESH_CONCURRENT_UPDATES,
                                cache_type);
      } else {
        UmaRecordIndexFileState(INDEX_STATE_FRESH, cache_type);
      }
      out_result->init_method = SimpleIndex::INITIALIZE_METHOD_LOADED;
      UmaRecordIndexInitMethod(out_result->init_method, cache_type);
      return;
    }
    UmaRecordIndexFileState(INDEX_STATE_STALE, cache_type);
  }

  // Reconstruct the index by scanning the disk for entries.
  SimpleIndex::EntrySet entries_from_stale_index;
  entries_from_stale_index.swap(out_result->entries);
  const base::TimeTicks start = base::TimeTicks::Now();
  SyncRestoreFromDisk(file_operations.get(), cache_type, cache_directory,
                      index_file_path, out_result);
  DEPRECATED_SIMPLE_CACHE_UMA_MEDIUM_TIMES("IndexRestoreTime", cache_type,
                                           base::TimeTicks::Now() - start);
  if (index_file_existed) {
    out_result->init_method = SimpleIndex::INITIALIZE_METHOD_RECOVERED;

    int missed_entry_count = 0;
    for (const auto& i : out_result->entries) {
      if (entries_from_stale_index.count(i.first) == 0)
        ++missed_entry_count;
    }
    int extra_entry_count = 0;
    for (const auto& i : entries_from_stale_index) {
      if (out_result->entries.count(i.first) == 0)
        ++extra_entry_count;
    }
    UmaRecordStaleIndexQuality(missed_entry_count, extra_entry_count,
                               cache_type);
  } else {
    out_result->init_method = SimpleIndex::INITIALIZE_METHOD_NEWCACHE;
    SIMPLE_CACHE_UMA(COUNTS_1M,
                     "IndexCreatedEntryCount", cache_type,
                     out_result->entries.size());
  }
  UmaRecordIndexInitMethod(out_result->init_method, cache_type);
}

// static
void SimpleIndexFile::SyncLoadFromDisk(BackendFileOperations* file_operations,
                                       net::CacheType cache_type,
                                       const base::FilePath& index_filename,
                                       base::Time* out_last_cache_seen_by_index,
                                       SimpleIndexLoadResult* out_result) {
  out_result->Reset();

  base::File file = file_operations->OpenFile(
      index_filename, base::File::FLAG_OPEN | base::File::FLAG_READ |
                          base::File::FLAG_WIN_SHARE_DELETE |
                          base::File::FLAG_WIN_SEQUENTIAL_SCAN);
  if (!file.IsValid())
    return;

  // Sanity-check the length. We don't want to crash trying to read some corrupt
  // 10GiB file or such.
  int64_t file_length = file.GetLength();
  if (file_length < 0 || file_length > kMaxIndexFileSizeBytes) {
    file_operations->DeleteFile(
        index_filename,
        BackendFileOperations::DeleteFileMode::kEnsureImmediateAvailability);
    return;
  }

  // Make sure to preallocate in one chunk, so we don't induce fragmentation
  // reallocating a growing buffer.
  auto buffer = std::make_unique<char[]>(file_length);

  int read = file.Read(0, buffer.get(), file_length);
  if (read < file_length) {
    file_operations->DeleteFile(
        index_filename,
        BackendFileOperations::DeleteFileMode::kEnsureImmediateAvailability);
    return;
  }

  SimpleIndexFile::Deserialize(cache_type, buffer.get(), read,
                               out_last_cache_seen_by_index, out_result);

  if (!out_result->did_load) {
    file_operations->DeleteFile(
        index_filename,
        BackendFileOperations::DeleteFileMode::kEnsureImmediateAvailability);
  }
}

// static
std::unique_ptr<base::Pickle> SimpleIndexFile::Serialize(
    net::CacheType cache_type,
    const SimpleIndexFile::IndexMetadata& index_metadata,
    const SimpleIndex::EntrySet& entries) {
  std::unique_ptr<base::Pickle> pickle = std::make_unique<SimpleIndexPickle>();

  index_metadata.Serialize(pickle.get());
  for (const auto& entry : entries) {
    pickle->WriteUInt64(entry.first);
    entry.second.Serialize(cache_type, pickle.get());
  }
  return pickle;
}

// static
void SimpleIndexFile::Deserialize(net::CacheType cache_type,
                                  const char* data,
                                  int data_len,
                                  base::Time* out_cache_last_modified,
                                  SimpleIndexLoadResult* out_result) {
  DCHECK(data);

  out_result->Reset();
  SimpleIndex::EntrySet* entries = &out_result->entries;

  SimpleIndexPickle pickle(
      base::as_bytes(base::span(data, base::checked_cast<size_t>(data_len))));
  if (!pickle.data() || !pickle.HeaderValid()) {
    LOG(WARNING) << "Corrupt Simple Index File.";
    return;
  }

  base::PickleIterator pickle_it(pickle);
  PickleHeader* header_p = pickle.headerT<PickleHeader>();
  const uint32_t crc_read = header_p->crc;
  const uint32_t crc_calculated = CalculatePickleCRC(pickle);

  if (crc_read != crc_calculated) {
    LOG(WARNING) << "Invalid CRC in Simple Index file.";
    return;
  }

  SimpleIndexFile::IndexMetadata index_metadata;
  if (!index_metadata.Deserialize(&pickle_it)) {
    LOG(ERROR) << "Invalid index_metadata on Simple Cache Index.";
    return;
  }

  if (!index_metadata.CheckIndexMetadata()) {
    LOG(ERROR) << "Invalid index_metadata on Simple Cache Index.";
    return;
  }

  entries->reserve(index_metadata.entry_count() + kExtraSizeForMerge);
  while (entries->size() < index_metadata.entry_count()) {
    uint64_t hash_key;
    EntryMetadata entry_metadata;
    if (!pickle_it.ReadUInt64(&hash_key) ||
        !entry_metadata.Deserialize(
            cache_type, &pickle_it, index_metadata.has_entry_in_memory_data(),
            index_metadata.app_cache_has_trailer_prefetch_size())) {
      LOG(WARNING) << "Invalid EntryMetadata in Simple Index file.";
      entries->clear();
      return;
    }
    SimpleIndex::InsertInEntrySet(hash_key, entry_metadata, entries);
  }

  int64_t cache_last_modified;
  if (!pickle_it.ReadInt64(&cache_last_modified)) {
    entries->clear();
    return;
  }
  DCHECK(out_cache_last_modified);
  *out_cache_last_modified = base::Time::FromInternalValue(cache_last_modified);

  out_result->index_write_reason = index_metadata.reason();
  out_result->did_load = true;
}

// static
void SimpleIndexFile::SyncRestoreFromDisk(
    BackendFileOperations* file_operations,
    net::CacheType cache_type,
    const base::FilePath& cache_directory,
    const base::FilePath& index_file_path,
    SimpleIndexLoadResult* out_result) {
  VLOG(1) << "Simple Cache Index is being restored from disk.";
  file_operations->DeleteFile(
      index_file_path,
      BackendFileOperations::DeleteFileMode::kEnsureImmediateAvailability);
  out_result->Reset();
  SimpleIndex::EntrySet* entries = &out_result->entries;

  auto enumerator = file_operations->EnumerateFiles(cache_directory);
  while (std::optional<SimpleFileEnumerator::Entry> entry =
             enumerator->Next()) {
    ProcessEntryFile(file_operations, cache_type, entries, entry->path,
                     entry->last_accessed, entry->last_modified, entry->size);
  }
  if (enumerator->HasError()) {
    LOG(ERROR) << "Could not reconstruct index from disk";
    return;
  }
  out_result->did_load = true;
  // When we restore from disk we write the merged index file to disk right
  // away, this might save us from having to restore again next time.
  out_result->flush_required = true;
}

// static
bool SimpleIndexFile::LegacyIsIndexFileStale(
    BackendFileOperations* file_operations,
    base::Time cache_last_modified,
    const base::FilePath& index_file_path) {
  if (auto info = file_operations->GetFileInfo(index_file_path)) {
    return info->last_modified < cache_last_modified;
  }
  return true;
}

}  // namespace disk_cache
```