Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's network stack. I need to analyze the methods in this part of the `BackendImpl` class and describe what they do. I also need to check for any JavaScript related aspects, provide input/output examples for logical reasoning, highlight common user or programming errors, explain how a user action might lead to this code being executed, and finally summarize the overall functionality of this code block.

**Functionality Breakdown:**

*   **`GetEntryCount()`**: Returns the number of non-deleted entries.
*   **`OpenOrCreateEntry()`**: Initiates opening or creating a cache entry.
*   **`OpenEntry()`**: Initiates opening an existing cache entry.
*   **`CreateEntry()`**: Initiates creating a new cache entry.
*   **`DoomEntry()`**: Initiates marking an entry for deletion.
*   **`DoomAllEntries()`**: Initiates marking all entries for deletion.
*   **`DoomEntriesBetween()`**: Initiates marking entries within a time range for deletion.
*   **`DoomEntriesSince()`**: Initiates marking entries since a specific time for deletion.
*   **`CalculateSizeOfAllEntries()`**: Initiates calculating the total size of all entries.
*   **`IteratorImpl` (inner class)**: Implements an iterator for traversing cache entries.
*   **`CreateIterator()`**: Creates an iterator object.
*   **`GetStats()`**: Collects and provides cache statistics.
*   **`OnExternalCacheHit()`**: Handles events when an external cache is hit.
*   **`CreateBackingStore()`**: Creates the underlying file structure for the cache.
*   **`InitBackingStore()`**: Initializes the backing store (file).
*   **`AdjustMaxCacheSize()`**: Determines and adjusts the maximum cache size.
*   **`InitStats()`**: Initializes statistics tracking.
*   **`StoreStats()`**: Saves the current statistics.
*   **`RestartCache()`**: Restarts the cache, potentially after an error.
*   **`PrepareForRestart()`**: Prepares the cache for a restart.
*   **`NewEntry()`**: Loads an entry into memory or returns an existing one.
*   **`MatchEntry()`**: Finds a cache entry matching a given key.
*   **`OpenFollowingEntryFromList()`**: Retrieves the next entry from a ranking list.
*   **`GetEnumeratedEntry()`**: Retrieves a specific entry during enumeration.
*   **`ResurrectEntry()`**: Handles the case where a creation request finds a deleted entry.
*   **`DestroyInvalidEntry()`**: Handles destroying an entry that is found to be invalid.
*   **`AddStorageSize()`**: Increases the recorded cache storage size.
*   **`SubstractStorageSize()`**: Decreases the recorded cache storage size.
*   **`IncreaseNumRefs()`**: Increments the reference count for the backend.
*   **`DecreaseNumRefs()`**: Decrements the reference count for the backend.
*   **`IncreaseNumEntries()`**: Increments the number of entries.
*   **`DecreaseNumEntries()`**: Decrements the number of entries.
*   **`LogStats()`**: Logs cache statistics.
*   **`UpdateStats()`**: Updates internal cache statistics.
*   **`UpgradeTo2_1()`**: Upgrades the cache format to version 2.1.
*   **`UpgradeTo3_0()`**: Upgrades the cache format to version 3.0.
*   **`CheckIndex()`**: Validates the integrity of the index file.
*   **`CheckAllEntries()`**: Checks the integrity of all cache entries.
*   **`CheckEntry()`**: Checks the integrity of a single cache entry.
*   **`MaxBuffersSize()`**: Returns the maximum size for buffer usage.
*   **`FlushForTesting()`**: Synchronously flushes data for testing.
*   **`FlushAsynchronouslyForTesting()`**: Asynchronously flushes data for testing.

**JavaScript Relationship:** The code manages the disk cache, which stores resources fetched by the browser. JavaScript running in a web page might trigger network requests for resources (like images, scripts, etc.). These requests can lead to the cache being accessed or modified by this C++ code.

**Logical Reasoning Examples:** Consider the `GetEntryCount()` function.

*   **Hypothetical Input:** `data_->header.num_entries = 5`, `data_->header.lru.sizes[Rankings::DELETED] = 2`
*   **Output:** `5 - 2 = 3` (There are 3 non-deleted entries)

*   **Hypothetical Input:** `data_->header.num_entries = 10`, `data_->header.lru.sizes[Rankings::DELETED] = 0`
*   **Output:** `10 - 0 = 10` (All entries are non-deleted)

**User/Programming Errors:**

*   **Cache Corruption:** A program might crash while writing to the cache, leading to inconsistencies between the index and data files. The `CheckIndex()` and `CheckAllEntries()` methods are designed to detect such issues.
*   **Insufficient Disk Space:** If the disk is full, writing to the cache will fail. The `CreateBackingStore()` method attempts to pre-allocate space to avoid runtime failures, but it's still possible.
*   **Incorrect Cache Size Configuration:** If the maximum cache size is set too low, it can lead to frequent cache evictions and potentially impact performance.

**User Actions Leading to Execution:**

1. **User visits a webpage:** The browser might need to fetch resources (HTML, CSS, JavaScript, images) from the network.
2. **Resource Fetch:** The network stack checks the cache for these resources.
3. **Cache Miss/Hit:**
    *   **Cache Miss:** `OpenOrCreateEntry()` or `CreateEntry()` might be called to create a new entry for the fetched resource.
    *   **Cache Hit:** `OpenEntry()` might be called to retrieve the resource from the cache.
4. **Cache Full:** If the cache is full, `DoomEntry()`, `DoomAllEntries()`, `DoomEntriesBetween()`, or `DoomEntriesSince()` might be called as part of the eviction process to make space for new entries.
5. **Browser Closure:** When the browser closes, the cache might be flushed, and statistics might be stored using `StoreStats()`.

**Overall Functionality (Part 2):** This part of the `BackendImpl` class focuses on the core logic of managing cache entries: creating, opening, deleting, and iterating over them. It includes methods for handling cache initialization, size management, statistics tracking, and ensuring data integrity. It orchestrates interactions with the underlying file system and the cache indexing mechanisms to provide a functional disk cache.
这是 `net/disk_cache/blockfile/backend_impl.cc` 文件的第二部分，延续了第一部分的功能，主要负责实现磁盘缓存的后端逻辑，处理缓存条目的创建、打开、删除、遍历以及统计等操作。

**功能归纳:**

这部分代码主要实现了以下功能：

1. **获取缓存条目数量:** `GetEntryCount()` 方法用于获取当前缓存中有效条目的数量，排除了已标记为删除的条目。
2. **异步操作入口:**  `OpenOrCreateEntry`, `OpenEntry`, `CreateEntry`, `DoomEntry`, `DoomAllEntries`, `DoomEntriesBetween`, `DoomEntriesSince`, `CalculateSizeOfAllEntries` 等方法都是异步操作的入口。它们将实际的 I/O 操作委托给后台队列 (`background_queue_`) 处理，并立即返回 `net::ERR_IO_PENDING`，表示操作正在进行中。这保证了主线程的响应性。
3. **缓存条目迭代器:** `IteratorImpl` 类实现了 `Backend::Iterator` 接口，用于遍历缓存中的条目。`CreateIterator()` 方法创建并返回一个迭代器对象。
4. **获取缓存统计信息:** `GetStats()` 方法收集并返回缓存的各种统计信息，如条目数量、待处理的 I/O 操作数、最大缓存大小、当前缓存大小和缓存类型等。
5. **处理外部缓存命中:** `OnExternalCacheHit()` 方法用于处理外部缓存命中事件，同样将其转发到后台队列处理。
6. **创建和初始化缓存存储:** `CreateBackingStore()` 方法用于创建缓存的底层存储文件，包括写入头部信息和分配哈希表空间。`InitBackingStore()` 方法用于初始化缓存的底层存储，包括创建目录、打开或创建索引文件，并映射到内存。
7. **调整最大缓存大小:** `AdjustMaxCacheSize()` 方法根据可用磁盘空间和配置来调整缓存的最大大小。
8. **初始化和存储统计信息:** `InitStats()` 方法用于初始化缓存的统计信息，如果统计信息块不存在则创建。`StoreStats()` 方法将当前的统计信息写回存储。
9. **重启缓存:** `RestartCache()` 方法用于重启缓存，可能在遇到错误后进行清理并重新初始化。`PrepareForRestart()` 方法用于在重启前进行准备工作，例如重置标志、刷新索引等。
10. **操作缓存条目:**
    *   `NewEntry()`:  根据地址加载一个缓存条目到内存中，如果已存在则直接返回。
    *   `MatchEntry()`:  根据键值和哈希值在哈希表中查找匹配的缓存条目。
    *   `OpenFollowingEntryFromList()`: 从指定的排名列表中打开下一个缓存条目。
    *   `GetEnumeratedEntry()`: 获取枚举过程中的特定缓存条目。
    *   `ResurrectEntry()`:  尝试复活一个已删除的缓存条目。
    *   `DestroyInvalidEntry()`:  销毁一个被标记为无效的缓存条目。
11. **更新缓存大小和引用计数:** `AddStorageSize()`, `SubstractStorageSize()`, `IncreaseNumRefs()`, `DecreaseNumRefs()`, `IncreaseNumEntries()`, `DecreaseNumEntries()` 等方法用于维护缓存的大小、引用计数和条目数量等元数据。
12. **日志和统计更新:** `LogStats()` 方法用于记录缓存的统计信息到日志。`UpdateStats()` 方法用于定期更新缓存的内部统计信息。
13. **缓存版本升级:** `UpgradeTo2_1()` 和 `UpgradeTo3_0()` 方法用于将旧版本的缓存格式升级到新版本。
14. **检查缓存完整性:** `CheckIndex()` 方法用于检查索引文件的完整性。`CheckAllEntries()` 方法用于检查所有缓存条目的完整性。`CheckEntry()` 方法用于检查单个缓存条目的完整性。
15. **获取最大缓冲区大小:** `MaxBuffersSize()` 方法用于计算并返回最大缓冲区大小，该大小基于系统内存。
16. **测试相关的刷新操作:** `FlushForTesting()` 和 `FlushAsynchronouslyForTesting()` 方法提供了用于测试的同步和异步刷新缓存数据的接口。

**与 JavaScript 的关系:**

这段代码直接服务于 Chromium 的网络栈，负责管理浏览器在磁盘上缓存的资源。当 JavaScript 代码发起网络请求时，网络栈会尝试从磁盘缓存中查找对应的资源。如果缓存中存在有效的资源，这段代码会被调用来打开并读取缓存条目，从而避免重新从网络下载资源，提升网页加载速度。

**举例说明:**

假设 JavaScript 代码请求一个图片资源 `https://example.com/image.png`。

1. 网络栈会计算该 URL 的哈希值。
2. `BackendImpl::OpenEntry("https://example.com/image.png", ...)` 或 `BackendImpl::OpenOrCreateEntry("https://example.com/image.png", ...)`  可能会被调用。
3. `MatchEntry()` 方法会被调用来在哈希表中查找对应的缓存条目。
4. 如果找到匹配的条目，`NewEntry()` 方法会被调用加载该条目到内存。
5. 如果缓存条目有效，其数据会被读取并返回给网络栈，最终提供给 JavaScript 代码。
6. 如果在查找过程中发现缓存条目损坏，`DestroyInvalidEntry()` 可能会被调用。
7. 如果缓存已满，为了缓存新的图片资源，可能会触发缓存淘汰机制，调用 `DoomEntry()` 等方法删除一些旧的缓存条目。

**逻辑推理的假设输入与输出:**

以 `GetEntryCount()` 方法为例：

*   **假设输入:** `data_->header.num_entries = 10`, `data_->header.lru.sizes[Rankings::DELETED] = 3`
*   **输出:** `10 - 3 = 7` (表示当前有 7 个有效的缓存条目)

以 `AdjustMaxCacheSize()` 方法为例：

*   **假设输入:**  当前可用磁盘空间较大，`max_size_` 为 0 (尚未设置)。
*   **输出:**  `max_size_` 会被设置为一个基于可用磁盘空间的合理值，例如 `kDefaultCacheSize` 的几倍。

**用户或编程常见的使用错误:**

1. **缓存目录权限问题:** 用户可能没有对缓存目录的读写权限，导致缓存初始化失败。
2. **磁盘空间不足:** 当磁盘空间不足时，尝试创建新的缓存条目可能会失败。
3. **程序异常崩溃:**  如果在写入缓存数据的过程中程序崩溃，可能会导致缓存文件损坏，下次启动时需要进行缓存恢复或清理。 这部分代码中的检查机制 (`CheckIndex()`, `CheckAllEntries()`) 就是为了应对这种情况。
4. **不正确的缓存配置:**  开发者可能会设置不合理的缓存大小，导致缓存效率低下。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入网址并访问:** 这会触发网络请求。
2. **浏览器网络栈处理请求:** 网络栈会检查是否可以从缓存中获取资源。
3. **进入 `disk_cache` 模块:** 如果需要访问磁盘缓存，请求会进入 `disk_cache` 模块。
4. **调用 `BackendImpl` 的方法:** 根据具体操作 (打开、创建、删除等)，会调用 `BackendImpl` 相应的公共方法，例如 `OpenEntry()` 或 `CreateEntry()`。
5. **异步操作进入后台队列:** 这些公共方法会将操作放入 `background_queue_` 中异步执行。
6. **后台线程执行具体操作:** 后台线程会调用这部分代码中的私有方法，例如 `MatchEntry()`, `NewEntry()`, `DoomEntryImpl()` (在第一部分) 等，来完成实际的缓存操作。

例如，当用户访问一个之前访问过的网页时，浏览器会尝试从缓存中加载资源：

1. 用户访问网页 `https://example.com/index.html`。
2. 浏览器网络栈发起对 `index.html` 的请求。
3. 网络栈调用 `disk_cache::Backend::OpenEntry("https://example.com/index.html", ...)`。
4. 这会调用 `BackendImpl::OpenEntry()`，将任务放入后台队列。
5. 后台线程执行 `InFlightBackendIO::OpenEntry()` (在第一部分)。
6. `InFlightBackendIO::OpenEntry()` 会调用 `BackendImpl::MatchEntry()` 来查找缓存条目。
7. 如果找到条目，会调用 `BackendImpl::NewEntry()` 加载条目。

总而言之，这部分代码是 Chromium 磁盘缓存后端的核心实现，负责管理缓存条目的生命周期和维护缓存的完整性，是浏览器高效加载网页的关键组成部分。它通过异步处理 I/O 操作，避免阻塞主线程，保证用户界面的流畅性。

Prompt: 
```
这是目录为net/disk_cache/blockfile/backend_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ount() const {
  if (!index_.get() || disabled_)
    return 0;
  // num_entries includes entries already evicted.
  int32_t not_deleted =
      data_->header.num_entries - data_->header.lru.sizes[Rankings::DELETED];

  if (not_deleted < 0) {
    DUMP_WILL_BE_NOTREACHED();
    not_deleted = 0;
  }

  return not_deleted;
}

EntryResult BackendImpl::OpenOrCreateEntry(
    const std::string& key,
    net::RequestPriority request_priority,
    EntryResultCallback callback) {
  DCHECK(!callback.is_null());
  background_queue_.OpenOrCreateEntry(key, std::move(callback));
  return EntryResult::MakeError(net::ERR_IO_PENDING);
}

EntryResult BackendImpl::OpenEntry(const std::string& key,
                                   net::RequestPriority request_priority,
                                   EntryResultCallback callback) {
  DCHECK(!callback.is_null());
  background_queue_.OpenEntry(key, std::move(callback));
  return EntryResult::MakeError(net::ERR_IO_PENDING);
}

EntryResult BackendImpl::CreateEntry(const std::string& key,
                                     net::RequestPriority request_priority,
                                     EntryResultCallback callback) {
  DCHECK(!callback.is_null());
  background_queue_.CreateEntry(key, std::move(callback));
  return EntryResult::MakeError(net::ERR_IO_PENDING);
}

net::Error BackendImpl::DoomEntry(const std::string& key,
                                  net::RequestPriority priority,
                                  CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());
  background_queue_.DoomEntry(key, std::move(callback));
  return net::ERR_IO_PENDING;
}

net::Error BackendImpl::DoomAllEntries(CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());
  background_queue_.DoomAllEntries(std::move(callback));
  return net::ERR_IO_PENDING;
}

net::Error BackendImpl::DoomEntriesBetween(const base::Time initial_time,
                                           const base::Time end_time,
                                           CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());
  background_queue_.DoomEntriesBetween(initial_time, end_time,
                                       std::move(callback));
  return net::ERR_IO_PENDING;
}

net::Error BackendImpl::DoomEntriesSince(const base::Time initial_time,
                                         CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());
  background_queue_.DoomEntriesSince(initial_time, std::move(callback));
  return net::ERR_IO_PENDING;
}

int64_t BackendImpl::CalculateSizeOfAllEntries(
    Int64CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());
  background_queue_.CalculateSizeOfAllEntries(BindOnce(
      [](Int64CompletionOnceCallback callback, int result) {
        std::move(callback).Run(static_cast<int64_t>(result));
      },
      std::move(callback)));
  return net::ERR_IO_PENDING;
}

class BackendImpl::IteratorImpl : public Backend::Iterator {
 public:
  explicit IteratorImpl(base::WeakPtr<InFlightBackendIO> background_queue)
      : background_queue_(background_queue),
        iterator_(std::make_unique<Rankings::Iterator>()) {}

  ~IteratorImpl() override {
    if (background_queue_)
      background_queue_->EndEnumeration(std::move(iterator_));
  }

  EntryResult OpenNextEntry(EntryResultCallback callback) override {
    if (!background_queue_)
      return EntryResult::MakeError(net::ERR_FAILED);
    background_queue_->OpenNextEntry(iterator_.get(), std::move(callback));
    return EntryResult::MakeError(net::ERR_IO_PENDING);
  }

 private:
  const base::WeakPtr<InFlightBackendIO> background_queue_;
  std::unique_ptr<Rankings::Iterator> iterator_;
};

std::unique_ptr<Backend::Iterator> BackendImpl::CreateIterator() {
  return std::make_unique<IteratorImpl>(GetBackgroundQueue());
}

void BackendImpl::GetStats(StatsItems* stats) {
  if (disabled_)
    return;

  std::pair<std::string, std::string> item;

  item.first = "Entries";
  item.second = base::NumberToString(data_->header.num_entries);
  stats->push_back(item);

  item.first = "Pending IO";
  item.second = base::NumberToString(num_pending_io_);
  stats->push_back(item);

  item.first = "Max size";
  item.second = base::NumberToString(max_size_);
  stats->push_back(item);

  item.first = "Current size";
  item.second = base::NumberToString(data_->header.num_bytes);
  stats->push_back(item);

  item.first = "Cache type";
  item.second = "Blockfile Cache";
  stats->push_back(item);

  stats_.GetItems(stats);
}

void BackendImpl::OnExternalCacheHit(const std::string& key) {
  background_queue_.OnExternalCacheHit(key);
}

// ------------------------------------------------------------------------

// We just created a new file so we're going to write the header and set the
// file length to include the hash table (zero filled).
bool BackendImpl::CreateBackingStore(disk_cache::File* file) {
  AdjustMaxCacheSize(0);

  IndexHeader header;
  header.table_len = DesiredIndexTableLen(max_size_);
  header.create_time = Time::Now().ToInternalValue();

  if (!file->Write(&header, sizeof(header), 0))
    return false;

  size_t size = GetIndexSize(header.table_len);
  if (!file->SetLength(size))
    return false;

  // The call to SetLength() above is supposed to have already expanded the file
  // to |size| and zero-filled it, but on some systems the actual storage may
  // not get allocated until the pages are actually touched... resulting in a
  // SIGBUS trying to search through the index if the system is out of disk
  // space. So actually write out the zeroes (for pages after the one with the
  // header), to force allocation now and fail cleanly if there is no space.
  //
  // See https://crbug.com/1097518
  const int kPageSize = 4096;
  static_assert(sizeof(disk_cache::IndexHeader) < kPageSize,
                "Code below assumes it wouldn't overwrite header by starting "
                "at kPageSize");
  auto page = std::make_unique<char[]>(kPageSize);
  memset(page.get(), 0, kPageSize);

  for (size_t offset = kPageSize; offset < size; offset += kPageSize) {
    size_t end = std::min(offset + kPageSize, size);
    if (!file->Write(page.get(), end - offset, offset))
      return false;
  }
  return true;
}

bool BackendImpl::InitBackingStore(bool* file_created) {
  if (!base::CreateDirectory(path_))
    return false;

  base::FilePath index_name = path_.AppendASCII(kIndexName);

  int flags = base::File::FLAG_READ | base::File::FLAG_WRITE |
              base::File::FLAG_OPEN_ALWAYS |
              base::File::FLAG_WIN_EXCLUSIVE_WRITE;
  base::File base_file(index_name, flags);
  if (!base_file.IsValid())
    return false;

  bool ret = true;
  *file_created = base_file.created();

  auto file = base::MakeRefCounted<disk_cache::File>(std::move(base_file));
  if (*file_created)
    ret = CreateBackingStore(file.get());

  file = nullptr;
  if (!ret)
    return false;

  index_ = base::MakeRefCounted<MappedFile>();
  data_ = static_cast<Index*>(index_->Init(index_name, 0));
  if (!data_) {
    LOG(ERROR) << "Unable to map Index file";
    return false;
  }

  if (index_->GetLength() < sizeof(Index)) {
    // We verify this again on CheckIndex() but it's easier to make sure now
    // that the header is there.
    LOG(ERROR) << "Corrupt Index file";
    return false;
  }

  return true;
}

// The maximum cache size will be either set explicitly by the caller, or
// calculated by this code.
void BackendImpl::AdjustMaxCacheSize(int table_len) {
  if (max_size_)
    return;

  // If table_len is provided, the index file exists.
  DCHECK(!table_len || data_->header.magic);

  // The user is not setting the size, let's figure it out.
  int64_t available = base::SysInfo::AmountOfFreeDiskSpace(path_);
  if (available < 0) {
    max_size_ = kDefaultCacheSize;
    return;
  }

  if (table_len)
    available += data_->header.num_bytes;

  max_size_ = PreferredCacheSize(available, GetCacheType());

  if (!table_len)
    return;

  // If we already have a table, adjust the size to it.
  max_size_ = std::min(max_size_, MaxStorageSizeForTable(table_len));
}

bool BackendImpl::InitStats() {
  Addr address(data_->header.stats);
  int size = stats_.StorageSize();

  if (!address.is_initialized()) {
    FileType file_type = Addr::RequiredFileType(size);
    DCHECK_NE(file_type, EXTERNAL);
    int num_blocks = Addr::RequiredBlocks(size, file_type);

    if (!CreateBlock(file_type, num_blocks, &address))
      return false;

    data_->header.stats = address.value();
    return stats_.Init(nullptr, 0, address);
  }

  if (!address.is_block_file()) {
    NOTREACHED();
  }

  // Load the required data.
  size = address.num_blocks() * address.BlockSize();
  MappedFile* file = File(address);
  if (!file)
    return false;

  auto data = std::make_unique<char[]>(size);
  size_t offset = address.start_block() * address.BlockSize() +
                  kBlockHeaderSize;
  if (!file->Read(data.get(), size, offset))
    return false;

  if (!stats_.Init(data.get(), size, address))
    return false;
  if (GetCacheType() == net::DISK_CACHE && ShouldUpdateStats()) {
    stats_.InitSizeHistogram();
  }
  return true;
}

void BackendImpl::StoreStats() {
  int size = stats_.StorageSize();
  auto data = std::make_unique<char[]>(size);
  Addr address;
  size = stats_.SerializeStats(data.get(), size, &address);
  DCHECK(size);
  if (!address.is_initialized())
    return;

  MappedFile* file = File(address);
  if (!file)
    return;

  size_t offset = address.start_block() * address.BlockSize() +
                  kBlockHeaderSize;
  file->Write(data.get(), size, offset);  // ignore result.
}

void BackendImpl::RestartCache(bool failure) {
  TRACE_EVENT0("disk_cache", "BackendImpl::RestartCache");

  int64_t errors = stats_.GetCounter(Stats::FATAL_ERROR);
  int64_t full_dooms = stats_.GetCounter(Stats::DOOM_CACHE);
  int64_t partial_dooms = stats_.GetCounter(Stats::DOOM_RECENT);
  int64_t last_report = stats_.GetCounter(Stats::LAST_REPORT);

  PrepareForRestart();
  if (failure) {
    DCHECK(!num_refs_);
    DCHECK(open_entries_.empty());
    CleanupDirectorySync(path_);
  } else {
    DeleteCache(path_, false);
  }

  // Don't call Init() if directed by the unit test: we are simulating a failure
  // trying to re-enable the cache.
  if (unit_test_) {
    init_ = true;  // Let the destructor do proper cleanup.
  } else if (SyncInit() == net::OK) {
    stats_.SetCounter(Stats::FATAL_ERROR, errors);
    stats_.SetCounter(Stats::DOOM_CACHE, full_dooms);
    stats_.SetCounter(Stats::DOOM_RECENT, partial_dooms);
    stats_.SetCounter(Stats::LAST_REPORT, last_report);
  }
}

void BackendImpl::PrepareForRestart() {
  // Reset the mask_ if it was not given by the user.
  if (!(user_flags_ & kMask))
    mask_ = 0;

  if (!(user_flags_ & kNewEviction))
    new_eviction_ = false;

  disabled_ = true;
  data_->header.crash = 0;
  index_->Flush();
  index_ = nullptr;
  data_ = nullptr;
  block_files_.CloseFiles();
  rankings_.Reset();
  init_ = false;
  restarted_ = true;
}

int BackendImpl::NewEntry(Addr address, scoped_refptr<EntryImpl>* entry) {
  auto it = open_entries_.find(address.value());
  if (it != open_entries_.end()) {
    // Easy job. This entry is already in memory.
    *entry = base::WrapRefCounted(it->second);
    return 0;
  }

  STRESS_DCHECK(block_files_.IsValid(address));

  if (!address.SanityCheckForEntry()) {
    LOG(WARNING) << "Wrong entry address.";
    STRESS_NOTREACHED();
    return ERR_INVALID_ADDRESS;
  }

  auto cache_entry = base::MakeRefCounted<EntryImpl>(this, address, read_only_);
  IncreaseNumRefs();
  *entry = nullptr;

  if (!cache_entry->entry()->Load())
    return ERR_READ_FAILURE;

  if (!cache_entry->SanityCheck()) {
    LOG(WARNING) << "Messed up entry found.";
    STRESS_NOTREACHED();
    return ERR_INVALID_ENTRY;
  }

  STRESS_DCHECK(block_files_.IsValid(
                    Addr(cache_entry->entry()->Data()->rankings_node)));

  if (!cache_entry->LoadNodeAddress())
    return ERR_READ_FAILURE;

  if (!rankings_.SanityCheck(cache_entry->rankings(), false)) {
    STRESS_NOTREACHED();
    cache_entry->SetDirtyFlag(0);
    // Don't remove this from the list (it is not linked properly). Instead,
    // break the link back to the entry because it is going away, and leave the
    // rankings node to be deleted if we find it through a list.
    rankings_.SetContents(cache_entry->rankings(), 0);
  } else if (!rankings_.DataSanityCheck(cache_entry->rankings(), false)) {
    STRESS_NOTREACHED();
    cache_entry->SetDirtyFlag(0);
    rankings_.SetContents(cache_entry->rankings(), address.value());
  }

  if (!cache_entry->DataSanityCheck()) {
    LOG(WARNING) << "Messed up entry found.";
    cache_entry->SetDirtyFlag(0);
    cache_entry->FixForDelete();
  }

  // Prevent overwriting the dirty flag on the destructor.
  cache_entry->SetDirtyFlag(GetCurrentEntryId());

  open_entries_[address.value()] = cache_entry.get();

  cache_entry->BeginLogging(net_log_, false);
  *entry = std::move(cache_entry);
  return 0;
}

scoped_refptr<EntryImpl> BackendImpl::MatchEntry(const std::string& key,
                                                 uint32_t hash,
                                                 bool find_parent,
                                                 Addr entry_addr,
                                                 bool* match_error) {
  TRACE_EVENT0("disk_cache", "BackendImpl::MatchEntry");

  Addr address(data_->table[hash & mask_]);
  scoped_refptr<EntryImpl> cache_entry, parent_entry;
  bool found = false;
  std::set<CacheAddr> visited;
  *match_error = false;

  for (;;) {
    if (disabled_)
      break;

    if (visited.find(address.value()) != visited.end()) {
      // It's possible for a buggy version of the code to write a loop. Just
      // break it.
      address.set_value(0);
      parent_entry->SetNextAddress(address);
    }
    visited.insert(address.value());

    if (!address.is_initialized()) {
      if (find_parent)
        found = true;
      break;
    }

    int error = NewEntry(address, &cache_entry);
    if (error || cache_entry->dirty()) {
      // This entry is dirty on disk (it was not properly closed): we cannot
      // trust it.
      Addr child(0);
      if (!error)
        child.set_value(cache_entry->GetNextAddress());

      if (parent_entry.get()) {
        parent_entry->SetNextAddress(child);
        parent_entry = nullptr;
      } else {
        data_->table[hash & mask_] = child.value();
      }

      if (!error) {
        // It is important to call DestroyInvalidEntry after removing this
        // entry from the table.
        DestroyInvalidEntry(cache_entry.get());
        cache_entry = nullptr;
      }

      // Restart the search.
      address.set_value(data_->table[hash & mask_]);
      visited.clear();
      continue;
    }

    DCHECK_EQ(hash & mask_, cache_entry->entry()->Data()->hash & mask_);
    if (cache_entry->IsSameEntry(key, hash)) {
      if (!cache_entry->Update())
        cache_entry = nullptr;
      found = true;
      if (find_parent && entry_addr.value() != address.value()) {
        *match_error = true;
        parent_entry = nullptr;
      }
      break;
    }
    if (!cache_entry->Update())
      cache_entry = nullptr;
    parent_entry = cache_entry;
    cache_entry = nullptr;
    if (!parent_entry.get())
      break;

    address.set_value(parent_entry->GetNextAddress());
  }

  if (parent_entry.get() && (!find_parent || !found))
    parent_entry = nullptr;

  if (find_parent && entry_addr.is_initialized() && !cache_entry.get()) {
    *match_error = true;
    parent_entry = nullptr;
  }

  if (cache_entry.get() && (find_parent || !found))
    cache_entry = nullptr;

  FlushIndex();

  return find_parent ? std::move(parent_entry) : std::move(cache_entry);
}

bool BackendImpl::OpenFollowingEntryFromList(
    Rankings::List list,
    CacheRankingsBlock** from_entry,
    scoped_refptr<EntryImpl>* next_entry) {
  if (disabled_)
    return false;

  if (!new_eviction_ && Rankings::NO_USE != list)
    return false;

  Rankings::ScopedRankingsBlock rankings(&rankings_, *from_entry);
  CacheRankingsBlock* next_block = rankings_.GetNext(rankings.get(), list);
  Rankings::ScopedRankingsBlock next(&rankings_, next_block);
  *from_entry = nullptr;

  *next_entry = GetEnumeratedEntry(next.get(), list);
  if (!*next_entry)
    return false;

  *from_entry = next.release();
  return true;
}

scoped_refptr<EntryImpl> BackendImpl::GetEnumeratedEntry(
    CacheRankingsBlock* next,
    Rankings::List list) {
  if (!next || disabled_)
    return nullptr;

  scoped_refptr<EntryImpl> entry;
  int rv = NewEntry(Addr(next->Data()->contents), &entry);
  if (rv) {
    STRESS_NOTREACHED();
    rankings_.Remove(next, list, false);
    if (rv == ERR_INVALID_ADDRESS) {
      // There is nothing linked from the index. Delete the rankings node.
      DeleteBlock(next->address(), true);
    }
    return nullptr;
  }

  if (entry->dirty()) {
    // We cannot trust this entry.
    InternalDoomEntry(entry.get());
    return nullptr;
  }

  if (!entry->Update()) {
    STRESS_NOTREACHED();
    return nullptr;
  }

  // Note that it is unfortunate (but possible) for this entry to be clean, but
  // not actually the real entry. In other words, we could have lost this entry
  // from the index, and it could have been replaced with a newer one. It's not
  // worth checking that this entry is "the real one", so we just return it and
  // let the enumeration continue; this entry will be evicted at some point, and
  // the regular path will work with the real entry. With time, this problem
  // will disasappear because this scenario is just a bug.

  // Make sure that we save the key for later.
  entry->GetKey();

  return entry;
}

scoped_refptr<EntryImpl> BackendImpl::ResurrectEntry(
    scoped_refptr<EntryImpl> deleted_entry) {
  if (ENTRY_NORMAL == deleted_entry->entry()->Data()->state) {
    deleted_entry = nullptr;
    stats_.OnEvent(Stats::CREATE_MISS);
    return nullptr;
  }

  // We are attempting to create an entry and found out that the entry was
  // previously deleted.

  eviction_.OnCreateEntry(deleted_entry.get());
  entry_count_++;

  stats_.OnEvent(Stats::RESURRECT_HIT);
  return deleted_entry;
}

void BackendImpl::DestroyInvalidEntry(EntryImpl* entry) {
  LOG(WARNING) << "Destroying invalid entry.";

  entry->SetPointerForInvalidEntry(GetCurrentEntryId());

  eviction_.OnDoomEntry(entry);
  entry->InternalDoom();

  if (!new_eviction_)
    DecreaseNumEntries();
  stats_.OnEvent(Stats::INVALID_ENTRY);
}

void BackendImpl::AddStorageSize(int32_t bytes) {
  data_->header.num_bytes += bytes;
  DCHECK_GE(data_->header.num_bytes, 0);
}

void BackendImpl::SubstractStorageSize(int32_t bytes) {
  data_->header.num_bytes -= bytes;
  DCHECK_GE(data_->header.num_bytes, 0);
}

void BackendImpl::IncreaseNumRefs() {
  num_refs_++;
  if (max_refs_ < num_refs_)
    max_refs_ = num_refs_;
}

void BackendImpl::DecreaseNumRefs() {
  DCHECK(num_refs_);
  num_refs_--;

  if (!num_refs_ && disabled_)
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&BackendImpl::RestartCache, GetWeakPtr(), true));
}

void BackendImpl::IncreaseNumEntries() {
  data_->header.num_entries++;
  DCHECK_GT(data_->header.num_entries, 0);
}

void BackendImpl::DecreaseNumEntries() {
  data_->header.num_entries--;
  if (data_->header.num_entries < 0) {
    STRESS_NOTREACHED();
    data_->header.num_entries = 0;
  }
}

void BackendImpl::LogStats() {
  StatsItems stats;
  GetStats(&stats);

  for (const auto& stat : stats)
    VLOG(1) << stat.first << ": " << stat.second;
}

void BackendImpl::UpdateStats() {
  // Previously this function was used to periodically emit histograms, however
  // now it just performs some regular maintenance on the cache statistics.
  stats_.SetCounter(Stats::MAX_ENTRIES, 0);
  stats_.SetCounter(Stats::FATAL_ERROR, 0);
  stats_.SetCounter(Stats::DOOM_CACHE, 0);
  stats_.SetCounter(Stats::DOOM_RECENT, 0);

  int64_t total_hours = stats_.GetCounter(Stats::TIMER) / 120;
  if (!data_->header.create_time || !data_->header.lru.filled) {
    return;
  }

  int64_t use_hours = stats_.GetCounter(Stats::LAST_REPORT_TIMER) / 120;
  stats_.SetCounter(Stats::LAST_REPORT_TIMER, stats_.GetCounter(Stats::TIMER));

  // We may see users with no use_hours at this point if this is the first time
  // we are running this code.
  if (use_hours)
    use_hours = total_hours - use_hours;

  if (!use_hours || !GetEntryCount() || !data_->header.num_bytes)
    return;

  stats_.ResetRatios();
  stats_.SetCounter(Stats::TRIM_ENTRY, 0);
}

void BackendImpl::UpgradeTo2_1() {
  // 2.1 is basically the same as 2.0, except that new fields are actually
  // updated by the new eviction algorithm.
  DCHECK_EQ(kVersion2_0, data_->header.version);
  data_->header.version = kVersion2_1;
  data_->header.lru.sizes[Rankings::NO_USE] = data_->header.num_entries;
}

void BackendImpl::UpgradeTo3_0() {
  // 3.0 uses a 64-bit size field.
  DCHECK(kVersion2_0 == data_->header.version ||
         kVersion2_1 == data_->header.version);
  data_->header.version = kVersion3_0;
  data_->header.num_bytes = data_->header.old_v2_num_bytes;
}

bool BackendImpl::CheckIndex() {
  DCHECK(data_);

  size_t current_size = index_->GetLength();
  if (current_size < sizeof(Index)) {
    LOG(ERROR) << "Corrupt Index file";
    return false;
  }

  if (data_->header.magic != kIndexMagic) {
    LOG(ERROR) << "Invalid file magic";
    return false;
  }

  // 2.0 + new_eviction needs conversion to 2.1.
  if (data_->header.version == kVersion2_0 && new_eviction_) {
    UpgradeTo2_1();
  }

  // 2.0 or 2.1 can be upgraded to 3.0
  if (data_->header.version == kVersion2_0 ||
      data_->header.version == kVersion2_1) {
    UpgradeTo3_0();
  }

  if (kCurrentVersion != data_->header.version) {
    LOG(ERROR) << "Invalid file version";
    return false;
  }

  if (!data_->header.table_len) {
    LOG(ERROR) << "Invalid table size";
    return false;
  }

  if (current_size < GetIndexSize(data_->header.table_len) ||
      data_->header.table_len & (kBaseTableLen - 1)) {
    LOG(ERROR) << "Corrupt Index file";
    return false;
  }

  AdjustMaxCacheSize(data_->header.table_len);

#if !defined(NET_BUILD_STRESS_CACHE)
  if (data_->header.num_bytes < 0 ||
      (max_size_ < std::numeric_limits<int32_t>::max() - kDefaultCacheSize &&
       data_->header.num_bytes > max_size_ + kDefaultCacheSize)) {
    LOG(ERROR) << "Invalid cache (current) size";
    return false;
  }
#endif

  if (data_->header.num_entries < 0) {
    LOG(ERROR) << "Invalid number of entries";
    return false;
  }

  if (!mask_)
    mask_ = data_->header.table_len - 1;

  // Load the table into memory.
  return index_->Preload();
}

int BackendImpl::CheckAllEntries() {
  int num_dirty = 0;
  int num_entries = 0;
  DCHECK(mask_ < std::numeric_limits<uint32_t>::max());
  for (unsigned int i = 0; i <= mask_; i++) {
    Addr address(data_->table[i]);
    if (!address.is_initialized())
      continue;
    for (;;) {
      scoped_refptr<EntryImpl> cache_entry;
      int ret = NewEntry(address, &cache_entry);
      if (ret) {
        STRESS_NOTREACHED();
        return ret;
      }

      if (cache_entry->dirty())
        num_dirty++;
      else if (CheckEntry(cache_entry.get()))
        num_entries++;
      else
        return ERR_INVALID_ENTRY;

      DCHECK_EQ(i, cache_entry->entry()->Data()->hash & mask_);
      address.set_value(cache_entry->GetNextAddress());
      if (!address.is_initialized())
        break;
    }
  }

  if (num_entries + num_dirty != data_->header.num_entries) {
    LOG(ERROR) << "Number of entries " << num_entries << " " << num_dirty <<
                  " " << data_->header.num_entries;
    DCHECK_LT(num_entries, data_->header.num_entries);
    return ERR_NUM_ENTRIES_MISMATCH;
  }

  return num_dirty;
}

bool BackendImpl::CheckEntry(EntryImpl* cache_entry) {
  bool ok = block_files_.IsValid(cache_entry->entry()->address());
  ok = ok && block_files_.IsValid(cache_entry->rankings()->address());
  EntryStore* data = cache_entry->entry()->Data();
  for (size_t i = 0; i < std::size(data->data_addr); i++) {
    if (data->data_addr[i]) {
      Addr address(data->data_addr[i]);
      if (address.is_block_file())
        ok = ok && block_files_.IsValid(address);
    }
  }

  return ok && cache_entry->rankings()->VerifyHash();
}

// static
int BackendImpl::MaxBuffersSize() {
  // Calculate based on total memory the first time this function is called,
  // then cache the result.
  static const int max_buffers_size = ([]() {
    constexpr uint64_t kMaxMaxBuffersSize = 30 * 1024 * 1024;
    const uint64_t total_memory = base::SysInfo::AmountOfPhysicalMemory();
    if (total_memory == 0u) {
      return int{kMaxMaxBuffersSize};
    }
    const uint64_t two_percent = total_memory * 2 / 100;
    return static_cast<int>(std::min(two_percent, kMaxMaxBuffersSize));
  })();

  return max_buffers_size;
}

void BackendImpl::FlushForTesting() {
  if (!g_internal_cache_thread.IsCreated()) {
    return;
  }

  g_internal_cache_thread.Get().FlushForTesting();
}

void BackendImpl::FlushAsynchronouslyForTesting(base::OnceClosure callback) {
  if (!g_internal_cache_thread.IsCreated()) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(callback));
    return;
  }

  InternalCacheThread()->PostTaskAndReply(FROM_HERE, base::BindOnce([]() {}),
                                          std::move(callback));
}

}  // namespace disk_cache

"""


```