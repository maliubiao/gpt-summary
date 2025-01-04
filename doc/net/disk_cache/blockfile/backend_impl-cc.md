Response:
The user wants a summary of the functionality of the C++ source code file `net/disk_cache/blockfile/backend_impl.cc` from the Chromium project. The request also has several specific constraints:

1. **List the functionalities:** Provide a high-level overview of what the code does.
2. **Relation to JavaScript:** Explain if and how this code interacts with JavaScript functionality.
3. **Logical Reasoning (Input/Output):** If the code performs logical operations, provide examples with hypothetical inputs and outputs.
4. **Common User/Programming Errors:**  Highlight typical mistakes made by users or developers when interacting with this code.
5. **User Operation Trace (Debugging):** Describe how a user action might lead to this code being executed, serving as a debugging hint.
6. **Overall Functionality Summary:**  Provide a concise summary of the file's purpose.

Let's break down the file's content to address these points:

**1. Functionalities:**

The code seems to implement the core logic for a disk cache backend. Key functionalities apparent from the included headers and the class methods are:

* **Cache Initialization and Management:**  Creating, initializing, and cleaning up the cache on disk. This involves managing index files and data block files.
* **Entry Management:** Creating, opening, deleting (dooming), and enumerating cache entries.
* **Data Storage:** Allocating and deallocating disk blocks for storing cached data.
* **Eviction Policy:** Implementing a mechanism for removing old or less frequently used entries to make space for new ones.
* **Statistics Tracking:** Maintaining various metrics about the cache's performance and usage.
* **Error Handling:** Detecting and reporting errors encountered during cache operations.
* **Concurrency Control:** Using a background thread for I/O operations.
* **Experimentation:**  Potentially supporting A/B testing or feature flags related to the cache.

**2. Relation to JavaScript:**

The crucial link between this C++ code and JavaScript in a browser environment is through the network stack. JavaScript code (e.g., in a web page) makes network requests. The browser's network stack, which includes this disk cache component, can intercept these requests and potentially retrieve the resource from the cache instead of making a new network request.

* **Example:** When a JavaScript application fetches an image using `<img>` or `fetch()`, the browser's networking layer checks the disk cache managed by `BackendImpl`. If the image is present and valid, the cached version is returned, improving performance and reducing network traffic.

**3. Logical Reasoning (Input/Output):**

Consider the `SyncOpenEntry` function:

* **Hypothetical Input:** A JavaScript request for a resource with the key "my_resource_key".
* **Logical Operation:** `SyncOpenEntry` searches the cache index for an entry with this key.
* **Possible Outputs:**
    * **Cache Hit:** If the entry exists and is valid, the function returns `net::OK`, and a `scoped_refptr<EntryImpl>` pointing to the entry is returned.
    * **Cache Miss:** If the entry doesn't exist or has been evicted, the function returns `net::ERR_FAILED`, and the `entry` pointer is null.

Consider the `SyncCreateEntry` function:

* **Hypothetical Input:** A JavaScript request resulting in a new resource that needs to be cached with the key "new_resource_key".
* **Logical Operation:** `SyncCreateEntry` allocates space on disk, creates a new entry, and links it into the cache structure.
* **Possible Outputs:**
    * **Success:** If creation is successful, the function returns `net::OK`, and a `scoped_refptr<EntryImpl>` to the newly created entry is returned.
    * **Failure:** If there's not enough disk space or another error occurs, the function returns `net::ERR_FAILED`, and the `entry` pointer is null.

**4. Common User/Programming Errors:**

While users don't directly interact with this C++ code, developers working on Chromium or related projects could make mistakes:

* **Incorrect Cache Size Configuration:** Setting a very small maximum cache size might lead to frequent evictions and reduced cache effectiveness. The code includes logic (`DesiredIndexTableLen`) to determine an appropriate index size based on storage size, implying that a mismatch could cause performance issues.
* **File System Permissions:** If the cache directory doesn't have the correct read/write permissions, the initialization might fail, leading to `net::ERR_FAILED`.
* **Corruption of Cache Files:** Manually modifying or deleting files within the cache directory can lead to inconsistencies and errors detected by the `CheckIndex()` function, potentially resulting in cache invalidation or crashes.

**5. User Operation Trace (Debugging):**

Let's trace a scenario where a user browses a website:

1. **User Types URL:** The user enters a URL in the browser's address bar or clicks a link.
2. **Network Request:** The browser's networking stack initiates a request for the resources needed to display the webpage (HTML, CSS, JavaScript, images).
3. **Cache Check (BackendImpl):** For each resource, the network stack consults the disk cache (`BackendImpl`). Functions like `SyncOpenEntry` are called to check if the resource is already cached.
4. **Cache Miss/Hit:**
   * **Miss:** If the resource is not in the cache, a full network request is made, and upon receiving the response, `SyncCreateEntry` might be called to store the resource in the cache.
   * **Hit:** If the resource is found in the cache, the cached version is retrieved, and functions like `UpdateRank` might be called to update the entry's usage time for eviction purposes.
5. **Resource Loading:** The browser uses the retrieved resource (either from the network or the cache) to render the webpage.
6. **Eviction (Background Thread):** Periodically, the background thread managed by `background_queue_` will execute the eviction logic (`eviction_.TrimCache`) to manage disk space. This is triggered by the timer (`BackendImpl::OnStatsTimer`).

**6. Overall Functionality Summary:**

`net/disk_cache/blockfile/backend_impl.cc` implements the core logic for a blockfile-based disk cache in Chromium's network stack. It handles the creation, management, and access of cached data, including entry creation, retrieval, deletion, and an eviction policy to manage disk space. It acts as an intermediary between network requests and persistent storage, improving browsing performance by serving resources from the local disk when available.

This detailed breakdown should cover the requested aspects of the file's functionality.
这是 `net/disk_cache/blockfile/backend_impl.cc` 文件的第 1 部分，它主要负责实现基于块文件的磁盘缓存的后端逻辑。以下是其功能的归纳：

**主要功能归纳:**

1. **缓存初始化和管理:**
   - 负责缓存的创建、初始化（包括读取和创建索引文件、数据文件等）。
   - 提供了同步初始化 `SyncInit()` 方法。
   - 实现了缓存的清理和关闭 `CleanupCache()`。
   - 涉及到缓存重启 `RestartCache()` 的逻辑。

2. **缓存条目 (Entry) 的管理:**
   - 提供了打开现有缓存条目的功能 `SyncOpenEntry()` 和 `OpenEntryImpl()`。
   - 提供了创建新的缓存条目的功能 `SyncCreateEntry()` 和 `CreateEntryImpl()`。
   - 实现了删除（标记删除）缓存条目的功能 `SyncDoomEntry()` 和 `InternalDoomEntry()`。
   - 提供了遍历缓存条目的功能 `SyncOpenNextEntry()` 和 `OpenNextEntryImpl()`。
   - 提供了结束缓存条目枚举的功能 `SyncEndEnumeration()`。

3. **缓存大小和空间管理:**
   - 允许设置最大缓存大小 `SetMaxSize()`。
   - 跟踪缓存的已用大小和条目数量。
   - 涉及缓存的清理（trimming）逻辑，根据缓存大小和使用情况进行清理。

4. **缓存文件的操作:**
   - 管理索引文件的加载、刷新 `FlushIndex()`。
   - 管理数据块文件的创建、删除 `CreateBlock()` 和 `DeleteBlock()`。
   - 涉及到外部文件的创建和管理 `CreateExternalFile()`。

5. **缓存状态和统计:**
   - 维护缓存的统计信息（例如，命中率、创建次数、删除次数等）。
   - 定期通过定时器 `OnStatsTimer()` 更新统计信息。
   - 记录缓存错误 `ReportError()`。

6. **并发管理:**
   - 使用后台线程 `CacheThread` 和 `background_queue_` 处理 I/O 操作，以避免阻塞主线程。

7. **实验性功能:**
   - 包含一些实验性代码的初始化逻辑 `InitExperiment()`。

8. **自检和调试:**
   - 提供了自检功能 `SelfCheck()`，用于验证缓存的完整性。
   - 提供了一些用于单元测试的方法，例如 `FlushQueueForTest()`，`TrimForTest()` 等。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接包含 JavaScript 代码，但它是 Chromium 浏览器网络栈的一部分，负责管理本地磁盘缓存。当 JavaScript 代码（例如，在网页中运行的脚本）发起网络请求时，浏览器会先检查磁盘缓存。`BackendImpl` 的功能，如 `SyncOpenEntry` 和 `SyncCreateEntry`，会在这个过程中被调用：

* **举例说明:**
    1. **JavaScript 发起请求:** 网页上的 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起一个 GET 请求获取一个图片资源。
    2. **缓存查找:** Chromium 的网络栈会调用 `BackendImpl::SyncOpenEntry()`，尝试在磁盘缓存中查找与该请求 URL 对应的缓存条目。
    3. **缓存命中/未命中:**
        * **命中:** 如果缓存中存在有效的条目，`SyncOpenEntry()` 将返回该条目的信息，浏览器可以直接从缓存加载图片，无需再次从网络下载。
        * **未命中:** 如果缓存中不存在或条目已过期，`SyncOpenEntry()` 将返回失败，浏览器会发起实际的网络请求。当收到图片数据后，可能会调用 `BackendImpl::SyncCreateEntry()` 将图片数据存储到缓存中。

**逻辑推理 (假设输入与输出):**

假设调用 `SyncOpenEntry("https://example.com/image.png", &entry)`：

* **假设输入:**
    * `key`: "https://example.com/image.png" (要打开的缓存条目的键)
    * `entry`: 一个指向 `scoped_refptr<EntryImpl>` 的指针（用于接收打开的条目）。

* **逻辑推理:**
    1. 计算 `key` 的哈希值。
    2. 在索引表中查找与该哈希值对应的位置。
    3. 遍历哈希冲突链表，查找具有相同 `key` 的缓存条目。

* **可能的输出:**
    * **缓存命中:** 如果找到对应的条目，`SyncOpenEntry()` 返回 `net::OK`，并且 `entry` 指向一个有效的 `EntryImpl` 对象，表示该缓存条目被成功打开。
    * **缓存未命中:** 如果未找到对应的条目，`SyncOpenEntry()` 返回 `net::ERR_FAILED`，并且 `entry` 为空。

**用户或编程常见的使用错误:**

由于 `BackendImpl` 是 Chromium 内部的实现细节，普通用户不会直接与其交互。常见的编程错误可能发生在 Chromium 的开发者进行相关修改时：

* **未正确处理缓存初始化失败:** 如果文件系统权限不足或磁盘空间不足，缓存初始化可能会失败。开发者需要妥善处理 `SyncInit()` 返回的错误码。
* **并发访问冲突:**  多个线程同时访问缓存数据可能会导致数据损坏。`BackendImpl` 使用后台线程来管理 I/O，但开发者在其他地方与缓存交互时需要注意线程安全。
* **缓存大小配置不当:** 将缓存大小设置得过小可能导致频繁的缓存清理，降低缓存效率。反之，设置过大可能会占用过多磁盘空间。
* **泄漏缓存条目引用:** 如果 `EntryImpl` 对象在不再使用时没有正确释放，可能会导致内存泄漏。
* **在错误的时间调用缓存操作:** 例如，在缓存尚未初始化完成时就尝试访问缓存条目。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 或点击链接。**
2. **浏览器发起网络请求，请求该 URL 对应的资源。**
3. **Chromium 网络栈的资源加载器（Resource Loader）接收到请求。**
4. **资源加载器会检查是否可以从缓存中加载资源。** 这会涉及到调用 `net::Cache` 接口。
5. **`net::Cache` 会根据配置选择合适的后端，对于基于块文件的缓存，会使用 `BlockfileBackend`。**
6. **`BlockfileBackend` 内部会调用 `BackendImpl` 的方法，例如 `SyncOpenEntry()` 来尝试打开缓存条目。**
7. **如果缓存中不存在该资源，后续的网络请求会将数据下载下来。**
8. **下载完成后，可能会调用 `BackendImpl::SyncCreateEntry()` 将资源存储到缓存中。**

**作为调试线索，如果你怀疑缓存出现了问题，你可以：**

* **检查浏览器的网络面板:** 查看资源是否从缓存加载 (状态码通常为 304 或 `(from disk cache)` 或 `(from memory cache)`，后者可能在 `BackendImpl` 之前)。
* **清除浏览器缓存:**  如果问题消失，可能说明缓存中存在损坏的数据。
* **使用 Chromium 提供的内部 URL (例如 `chrome://net-internals/#cache`)** 查看缓存的状态和条目信息。
* **如果需要深入调试，可能需要修改 Chromium 源码，添加日志输出到 `BackendImpl` 的关键方法中。**

**总结:**

`net/disk_cache/blockfile/backend_impl.cc` 的第 1 部分定义了磁盘缓存后端的核心结构和功能，负责缓存的生命周期管理、条目操作、空间管理以及与底层文件系统的交互。它是 Chromium 网络栈中实现高效资源缓存的关键组成部分，直接影响着网页加载速度和用户体验。

Prompt: 
```
这是目录为net/disk_cache/blockfile/backend_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/disk_cache/blockfile/backend_impl.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/hash/hash.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/message_loop/message_pump_type.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/waitable_event.h"
#include "base/system/sys_info.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/net_errors.h"
#include "net/base/tracing.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/blockfile/disk_format.h"
#include "net/disk_cache/blockfile/entry_impl.h"
#include "net/disk_cache/blockfile/errors.h"
#include "net/disk_cache/blockfile/experiments.h"
#include "net/disk_cache/blockfile/file.h"
#include "net/disk_cache/cache_util.h"

using base::Time;
using base::TimeTicks;

namespace {

const char kIndexName[] = "index";

// Seems like ~240 MB correspond to less than 50k entries for 99% of the people.
// Note that the actual target is to keep the index table load factor under 55%
// for most users.
const int k64kEntriesStore = 240 * 1000 * 1000;
const int kBaseTableLen = 64 * 1024;

// Avoid trimming the cache for the first 5 minutes (10 timer ticks).
const int kTrimDelay = 10;

int DesiredIndexTableLen(int32_t storage_size) {
  if (storage_size <= k64kEntriesStore)
    return kBaseTableLen;
  if (storage_size <= k64kEntriesStore * 2)
    return kBaseTableLen * 2;
  if (storage_size <= k64kEntriesStore * 4)
    return kBaseTableLen * 4;
  if (storage_size <= k64kEntriesStore * 8)
    return kBaseTableLen * 8;

  // The biggest storage_size for int32_t requires a 4 MB table.
  return kBaseTableLen * 16;
}

int MaxStorageSizeForTable(int table_len) {
  return std::min(int64_t{std::numeric_limits<int32_t>::max()},
                  int64_t{table_len} * (k64kEntriesStore / kBaseTableLen));
}

size_t GetIndexSize(int table_len) {
  size_t table_size = sizeof(disk_cache::CacheAddr) * table_len;
  return sizeof(disk_cache::IndexHeader) + table_size;
}

// ------------------------------------------------------------------------

// Sets group for the current experiment. Returns false if the files should be
// discarded.
bool InitExperiment(disk_cache::IndexHeader* header, bool cache_created) {
  if (header->experiment == disk_cache::EXPERIMENT_OLD_FILE1 ||
      header->experiment == disk_cache::EXPERIMENT_OLD_FILE2) {
    // Discard current cache.
    return false;
  }

  header->experiment = disk_cache::NO_EXPERIMENT;
  return true;
}

// A callback to perform final cleanup on the background thread.
void FinalCleanupCallback(disk_cache::BackendImpl* backend,
                          base::WaitableEvent* done) {
  backend->CleanupCache();
  done->Signal();
}

class CacheThread : public base::Thread {
 public:
  CacheThread() : base::Thread("CacheThread_BlockFile") {
    CHECK(
        StartWithOptions(base::Thread::Options(base::MessagePumpType::IO, 0)));
  }

  ~CacheThread() override {
    // We don't expect to be deleted, but call Stop() in dtor 'cause docs
    // say we should.
    Stop();
  }
};

static base::LazyInstance<CacheThread>::Leaky g_internal_cache_thread =
    LAZY_INSTANCE_INITIALIZER;

scoped_refptr<base::SingleThreadTaskRunner> InternalCacheThread() {
  return g_internal_cache_thread.Get().task_runner();
}

scoped_refptr<base::SingleThreadTaskRunner> FallbackToInternalIfNull(
    const scoped_refptr<base::SingleThreadTaskRunner>& cache_thread) {
  return cache_thread ? cache_thread : InternalCacheThread();
}

}  // namespace

// ------------------------------------------------------------------------

namespace disk_cache {

BackendImpl::BackendImpl(
    const base::FilePath& path,
    scoped_refptr<BackendCleanupTracker> cleanup_tracker,
    const scoped_refptr<base::SingleThreadTaskRunner>& cache_thread,
    net::CacheType cache_type,
    net::NetLog* net_log)
    : Backend(cache_type),
      cleanup_tracker_(std::move(cleanup_tracker)),
      background_queue_(this, FallbackToInternalIfNull(cache_thread)),
      path_(path),
      block_files_(path),
      user_flags_(0),
      net_log_(net_log) {
  TRACE_EVENT0("disk_cache", "BackendImpl::BackendImpl");
}

BackendImpl::BackendImpl(
    const base::FilePath& path,
    uint32_t mask,
    scoped_refptr<BackendCleanupTracker> cleanup_tracker,
    const scoped_refptr<base::SingleThreadTaskRunner>& cache_thread,
    net::CacheType cache_type,
    net::NetLog* net_log)
    : Backend(cache_type),
      cleanup_tracker_(std::move(cleanup_tracker)),
      background_queue_(this, FallbackToInternalIfNull(cache_thread)),
      path_(path),
      block_files_(path),
      mask_(mask),
      user_flags_(kMask),
      net_log_(net_log) {
  TRACE_EVENT0("disk_cache", "BackendImpl::BackendImpl");
}

BackendImpl::~BackendImpl() {
  TRACE_EVENT0("disk_cache", "BackendImpl::~BackendImpl");
  if (user_flags_ & kNoRandom) {
    // This is a unit test, so we want to be strict about not leaking entries
    // and completing all the work.
    background_queue_.WaitForPendingIO();
  } else {
    // This is most likely not a test, so we want to do as little work as
    // possible at this time, at the price of leaving dirty entries behind.
    background_queue_.DropPendingIO();
  }

  if (background_queue_.BackgroundIsCurrentSequence()) {
    // Unit tests may use the same sequence for everything.
    CleanupCache();
  } else {
    // Signals the end of background work.
    base::WaitableEvent done;

    background_queue_.background_thread()->PostTask(
        FROM_HERE, base::BindOnce(&FinalCleanupCallback, base::Unretained(this),
                                  base::Unretained(&done)));
    // http://crbug.com/74623
    base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
    done.Wait();
  }
}

void BackendImpl::Init(CompletionOnceCallback callback) {
  background_queue_.Init(std::move(callback));
}

int BackendImpl::SyncInit() {
  TRACE_EVENT0("disk_cache", "BackendImpl::SyncInit");

#if defined(NET_BUILD_STRESS_CACHE)
  // Start evictions right away.
  up_ticks_ = kTrimDelay * 2;
#endif
  DCHECK(!init_);
  if (init_)
    return net::ERR_FAILED;

  bool create_files = false;
  if (!InitBackingStore(&create_files)) {
    ReportError(ERR_STORAGE_ERROR);
    return net::ERR_FAILED;
  }

  num_refs_ = num_pending_io_ = max_refs_ = 0;
  entry_count_ = byte_count_ = 0;

  bool should_create_timer = false;
  if (!restarted_) {
    buffer_bytes_ = 0;
    should_create_timer = true;
  }

  init_ = true;

  if (data_->header.experiment != NO_EXPERIMENT &&
      GetCacheType() != net::DISK_CACHE) {
    // No experiment for other caches.
    return net::ERR_FAILED;
  }

  if (!(user_flags_ & kNoRandom)) {
    // The unit test controls directly what to test.
    new_eviction_ = (GetCacheType() == net::DISK_CACHE);
  }

  if (!CheckIndex()) {
    ReportError(ERR_INIT_FAILED);
    return net::ERR_FAILED;
  }

  if (!restarted_ && (create_files || !data_->header.num_entries))
    ReportError(ERR_CACHE_CREATED);

  if (!(user_flags_ & kNoRandom) && GetCacheType() == net::DISK_CACHE &&
      !InitExperiment(&data_->header, create_files)) {
    return net::ERR_FAILED;
  }

  // We don't care if the value overflows. The only thing we care about is that
  // the id cannot be zero, because that value is used as "not dirty".
  // Increasing the value once per second gives us many years before we start
  // having collisions.
  data_->header.this_id++;
  if (!data_->header.this_id)
    data_->header.this_id++;

  bool previous_crash = (data_->header.crash != 0);
  data_->header.crash = 1;

  if (!block_files_.Init(create_files))
    return net::ERR_FAILED;

  // We want to minimize the changes to cache for an AppCache.
  if (GetCacheType() == net::APP_CACHE) {
    DCHECK(!new_eviction_);
    read_only_ = true;
  } else if (GetCacheType() == net::SHADER_CACHE) {
    DCHECK(!new_eviction_);
  }

  eviction_.Init(this);

  // stats_ and rankings_ may end up calling back to us so we better be enabled.
  disabled_ = false;
  if (!InitStats())
    return net::ERR_FAILED;

  disabled_ = !rankings_.Init(this, new_eviction_);

#if defined(STRESS_CACHE_EXTENDED_VALIDATION)
  trace_object_->EnableTracing(false);
  int sc = SelfCheck();
  if (sc < 0 && sc != ERR_NUM_ENTRIES_MISMATCH)
    NOTREACHED();
  trace_object_->EnableTracing(true);
#endif

  if (previous_crash) {
    ReportError(ERR_PREVIOUS_CRASH);
  } else if (!restarted_) {
    ReportError(ERR_NO_ERROR);
  }

  FlushIndex();

  if (!disabled_ && should_create_timer) {
    // Create a recurrent timer of 30 secs.
    DCHECK(background_queue_.BackgroundIsCurrentSequence());
    int timer_delay = unit_test_ ? 1000 : 30000;
    timer_ = std::make_unique<base::RepeatingTimer>();
    timer_->Start(FROM_HERE, base::Milliseconds(timer_delay), this,
                  &BackendImpl::OnStatsTimer);
  }

  return disabled_ ? net::ERR_FAILED : net::OK;
}

void BackendImpl::CleanupCache() {
  DCHECK(background_queue_.BackgroundIsCurrentSequence());
  TRACE_EVENT0("disk_cache", "BackendImpl::CleanupCache");

  eviction_.Stop();
  timer_.reset();

  if (init_) {
    StoreStats();
    if (data_)
      data_->header.crash = 0;

    if (user_flags_ & kNoRandom) {
      // This is a net_unittest, verify that we are not 'leaking' entries.
      // TODO(crbug.com/40171748): Refactor this and eliminate the
      //    WaitForPendingIOForTesting API.
      File::WaitForPendingIOForTesting(&num_pending_io_);
      DCHECK(!num_refs_);
    } else {
      File::DropPendingIO();
    }
  }
  block_files_.CloseFiles();
  FlushIndex();
  index_ = nullptr;
  ptr_factory_.InvalidateWeakPtrs();
}

// ------------------------------------------------------------------------

int BackendImpl::SyncOpenEntry(const std::string& key,
                               scoped_refptr<EntryImpl>* entry) {
  DCHECK(entry);
  *entry = OpenEntryImpl(key);
  return (*entry) ? net::OK : net::ERR_FAILED;
}

int BackendImpl::SyncCreateEntry(const std::string& key,
                                 scoped_refptr<EntryImpl>* entry) {
  DCHECK(entry);
  *entry = CreateEntryImpl(key);
  return (*entry) ? net::OK : net::ERR_FAILED;
}

int BackendImpl::SyncDoomEntry(const std::string& key) {
  if (disabled_)
    return net::ERR_FAILED;

  scoped_refptr<EntryImpl> entry = OpenEntryImpl(key);
  if (!entry)
    return net::ERR_FAILED;

  entry->DoomImpl();
  return net::OK;
}

int BackendImpl::SyncDoomAllEntries() {
  if (disabled_)
    return net::ERR_FAILED;

  // This is not really an error, but it is an interesting condition.
  ReportError(ERR_CACHE_DOOMED);
  stats_.OnEvent(Stats::DOOM_CACHE);
  if (!num_refs_) {
    RestartCache(false);
    return disabled_ ? net::ERR_FAILED : net::OK;
  } else {
    if (disabled_)
      return net::ERR_FAILED;

    eviction_.TrimCache(true);
    return net::OK;
  }
}

int BackendImpl::SyncDoomEntriesBetween(const base::Time initial_time,
                                        const base::Time end_time) {
  TRACE_EVENT0("disk_cache", "BackendImpl::SyncDoomEntriesBetween");

  DCHECK_NE(net::APP_CACHE, GetCacheType());
  if (end_time.is_null())
    return SyncDoomEntriesSince(initial_time);

  DCHECK(end_time >= initial_time);

  if (disabled_)
    return net::ERR_FAILED;

  scoped_refptr<EntryImpl> node;
  auto iterator = std::make_unique<Rankings::Iterator>();
  scoped_refptr<EntryImpl> next = OpenNextEntryImpl(iterator.get());
  if (!next)
    return net::OK;

  while (next) {
    node = std::move(next);
    next = OpenNextEntryImpl(iterator.get());

    if (node->GetLastUsed() >= initial_time &&
        node->GetLastUsed() < end_time) {
      node->DoomImpl();
    } else if (node->GetLastUsed() < initial_time) {
      next = nullptr;
      SyncEndEnumeration(std::move(iterator));
    }
  }

  return net::OK;
}

int BackendImpl::SyncCalculateSizeOfAllEntries() {
  TRACE_EVENT0("disk_cache", "BackendImpl::SyncCalculateSizeOfAllEntries");

  DCHECK_NE(net::APP_CACHE, GetCacheType());
  if (disabled_)
    return net::ERR_FAILED;

  return data_->header.num_bytes;
}

// We use OpenNextEntryImpl to retrieve elements from the cache, until we get
// entries that are too old.
int BackendImpl::SyncDoomEntriesSince(const base::Time initial_time) {
  TRACE_EVENT0("disk_cache", "BackendImpl::SyncDoomEntriesSince");

  DCHECK_NE(net::APP_CACHE, GetCacheType());
  if (disabled_)
    return net::ERR_FAILED;

  stats_.OnEvent(Stats::DOOM_RECENT);
  for (;;) {
    auto iterator = std::make_unique<Rankings::Iterator>();
    scoped_refptr<EntryImpl> entry = OpenNextEntryImpl(iterator.get());
    if (!entry)
      return net::OK;

    if (initial_time > entry->GetLastUsed()) {
      entry = nullptr;
      SyncEndEnumeration(std::move(iterator));
      return net::OK;
    }

    entry->DoomImpl();
    entry = nullptr;
    SyncEndEnumeration(
        std::move(iterator));  // The doom invalidated the iterator.
  }
}

int BackendImpl::SyncOpenNextEntry(Rankings::Iterator* iterator,
                                   scoped_refptr<EntryImpl>* next_entry) {
  TRACE_EVENT0("disk_cache", "BackendImpl::SyncOpenNextEntry");

  *next_entry = OpenNextEntryImpl(iterator);
  return (*next_entry) ? net::OK : net::ERR_FAILED;
}

void BackendImpl::SyncEndEnumeration(
    std::unique_ptr<Rankings::Iterator> iterator) {
  iterator->Reset();
}

void BackendImpl::SyncOnExternalCacheHit(const std::string& key) {
  if (disabled_)
    return;

  uint32_t hash = base::PersistentHash(key);
  bool error;
  scoped_refptr<EntryImpl> cache_entry =
      MatchEntry(key, hash, false, Addr(), &error);
  if (cache_entry && ENTRY_NORMAL == cache_entry->entry()->Data()->state)
    UpdateRank(cache_entry.get(), GetCacheType() == net::SHADER_CACHE);
}

scoped_refptr<EntryImpl> BackendImpl::OpenEntryImpl(const std::string& key) {
  TRACE_EVENT0("disk_cache", "BackendImpl::OpenEntryImpl");

  if (disabled_)
    return nullptr;

  uint32_t hash = base::PersistentHash(key);

  bool error;
  scoped_refptr<EntryImpl> cache_entry =
      MatchEntry(key, hash, false, Addr(), &error);
  if (cache_entry && ENTRY_NORMAL != cache_entry->entry()->Data()->state) {
    // The entry was already evicted.
    cache_entry = nullptr;
  }

  if (!cache_entry) {
    stats_.OnEvent(Stats::OPEN_MISS);
    return nullptr;
  }

  eviction_.OnOpenEntry(cache_entry.get());
  entry_count_++;

  stats_.OnEvent(Stats::OPEN_HIT);
  return cache_entry;
}

scoped_refptr<EntryImpl> BackendImpl::CreateEntryImpl(const std::string& key) {
  TRACE_EVENT0("disk_cache", "BackendImpl::CreateEntryImpl");

  if (disabled_ || key.empty())
    return nullptr;

  uint32_t hash = base::PersistentHash(key);

  scoped_refptr<EntryImpl> parent;
  Addr entry_address(data_->table[hash & mask_]);
  if (entry_address.is_initialized()) {
    // We have an entry already. It could be the one we are looking for, or just
    // a hash conflict.
    bool error;
    scoped_refptr<EntryImpl> old_entry =
        MatchEntry(key, hash, false, Addr(), &error);
    if (old_entry)
      return ResurrectEntry(std::move(old_entry));

    parent = MatchEntry(key, hash, true, Addr(), &error);
    DCHECK(!error);
    if (!parent && data_->table[hash & mask_]) {
      // We should have corrected the problem.
      DUMP_WILL_BE_NOTREACHED();
      return nullptr;
    }
  }

  // The general flow is to allocate disk space and initialize the entry data,
  // followed by saving that to disk, then linking the entry though the index
  // and finally through the lists. If there is a crash in this process, we may
  // end up with:
  // a. Used, unreferenced empty blocks on disk (basically just garbage).
  // b. Used, unreferenced but meaningful data on disk (more garbage).
  // c. A fully formed entry, reachable only through the index.
  // d. A fully formed entry, also reachable through the lists, but still dirty.
  //
  // Anything after (b) can be automatically cleaned up. We may consider saving
  // the current operation (as we do while manipulating the lists) so that we
  // can detect and cleanup (a) and (b).

  int num_blocks = EntryImpl::NumBlocksForEntry(key.size());
  if (!block_files_.CreateBlock(BLOCK_256, num_blocks, &entry_address)) {
    LOG(ERROR) << "Create entry failed " << key.c_str();
    stats_.OnEvent(Stats::CREATE_ERROR);
    return nullptr;
  }

  Addr node_address(0);
  if (!block_files_.CreateBlock(RANKINGS, 1, &node_address)) {
    block_files_.DeleteBlock(entry_address, false);
    LOG(ERROR) << "Create entry failed " << key.c_str();
    stats_.OnEvent(Stats::CREATE_ERROR);
    return nullptr;
  }

  auto cache_entry =
      base::MakeRefCounted<EntryImpl>(this, entry_address, false);
  IncreaseNumRefs();

  if (!cache_entry->CreateEntry(node_address, key, hash)) {
    block_files_.DeleteBlock(entry_address, false);
    block_files_.DeleteBlock(node_address, false);
    LOG(ERROR) << "Create entry failed " << key.c_str();
    stats_.OnEvent(Stats::CREATE_ERROR);
    return nullptr;
  }

  cache_entry->BeginLogging(net_log_, true);

  // We are not failing the operation; let's add this to the map.
  open_entries_[entry_address.value()] = cache_entry.get();

  // Save the entry.
  cache_entry->entry()->Store();
  cache_entry->rankings()->Store();
  IncreaseNumEntries();
  entry_count_++;

  // Link this entry through the index.
  if (parent.get()) {
    parent->SetNextAddress(entry_address);
  } else {
    data_->table[hash & mask_] = entry_address.value();
  }

  // Link this entry through the lists.
  eviction_.OnCreateEntry(cache_entry.get());

  stats_.OnEvent(Stats::CREATE_HIT);
  FlushIndex();
  return cache_entry;
}

scoped_refptr<EntryImpl> BackendImpl::OpenNextEntryImpl(
    Rankings::Iterator* iterator) {
  if (disabled_)
    return nullptr;

  const int kListsToSearch = 3;
  scoped_refptr<EntryImpl> entries[kListsToSearch];
  if (!iterator->my_rankings) {
    iterator->my_rankings = &rankings_;
    bool ret = false;

    // Get an entry from each list.
    for (int i = 0; i < kListsToSearch; i++) {
      ret |= OpenFollowingEntryFromList(static_cast<Rankings::List>(i),
                                        &iterator->nodes[i], &entries[i]);
    }
    if (!ret) {
      iterator->Reset();
      return nullptr;
    }
  } else {
    // Get the next entry from the last list, and the actual entries for the
    // elements on the other lists.
    for (int i = 0; i < kListsToSearch; i++) {
      if (iterator->list == i) {
        OpenFollowingEntryFromList(iterator->list, &iterator->nodes[i],
                                   &entries[i]);
      } else {
        entries[i] = GetEnumeratedEntry(iterator->nodes[i],
                                        static_cast<Rankings::List>(i));
      }
    }
  }

  int newest = -1;
  int oldest = -1;
  Time access_times[kListsToSearch];
  for (int i = 0; i < kListsToSearch; i++) {
    if (entries[i].get()) {
      access_times[i] = entries[i]->GetLastUsed();
      if (newest < 0) {
        DCHECK_LT(oldest, 0);
        newest = oldest = i;
        continue;
      }
      if (access_times[i] > access_times[newest])
        newest = i;
      if (access_times[i] < access_times[oldest])
        oldest = i;
    }
  }

  if (newest < 0 || oldest < 0) {
    iterator->Reset();
    return nullptr;
  }

  scoped_refptr<EntryImpl> next_entry = entries[newest];
  iterator->list = static_cast<Rankings::List>(newest);
  return next_entry;
}

bool BackendImpl::SetMaxSize(int64_t max_bytes) {
  if (max_bytes < 0 || max_bytes > std::numeric_limits<int>::max())
    return false;

  // Zero size means use the default.
  if (!max_bytes)
    return true;

  // Avoid a DCHECK later on.
  if (max_bytes >= std::numeric_limits<int32_t>::max() -
                       std::numeric_limits<int32_t>::max() / 10) {
    max_bytes = std::numeric_limits<int32_t>::max() -
                std::numeric_limits<int32_t>::max() / 10 - 1;
  }

  user_flags_ |= kMaxSize;
  max_size_ = max_bytes;
  return true;
}

base::FilePath BackendImpl::GetFileName(Addr address) const {
  if (!address.is_separate_file() || !address.is_initialized()) {
    DUMP_WILL_BE_NOTREACHED();
    return base::FilePath();
  }

  std::string tmp = base::StringPrintf("f_%06x", address.FileNumber());
  return path_.AppendASCII(tmp);
}

MappedFile* BackendImpl::File(Addr address) {
  if (disabled_)
    return nullptr;
  return block_files_.GetFile(address);
}

base::WeakPtr<InFlightBackendIO> BackendImpl::GetBackgroundQueue() {
  return background_queue_.GetWeakPtr();
}

bool BackendImpl::CreateExternalFile(Addr* address) {
  TRACE_EVENT0("disk_cache", "BackendImpl::CreateExternalFile");
  int file_number = data_->header.last_file + 1;
  Addr file_address(0);
  bool success = false;
  for (int i = 0; i < 0x0fffffff; i++, file_number++) {
    if (!file_address.SetFileNumber(file_number)) {
      file_number = 1;
      continue;
    }
    base::FilePath name = GetFileName(file_address);
    int flags = base::File::FLAG_READ | base::File::FLAG_WRITE |
                base::File::FLAG_CREATE | base::File::FLAG_WIN_EXCLUSIVE_WRITE;
    base::File file(name, flags);
    if (!file.IsValid()) {
      base::File::Error error = file.error_details();
      if (error != base::File::FILE_ERROR_EXISTS) {
        LOG(ERROR) << "Unable to create file: " << error;
        return false;
      }
      continue;
    }

    success = true;
    break;
  }

  DCHECK(success);
  if (!success)
    return false;

  data_->header.last_file = file_number;
  address->set_value(file_address.value());
  return true;
}

bool BackendImpl::CreateBlock(FileType block_type, int block_count,
                             Addr* block_address) {
  return block_files_.CreateBlock(block_type, block_count, block_address);
}

void BackendImpl::DeleteBlock(Addr block_address, bool deep) {
  block_files_.DeleteBlock(block_address, deep);
}

LruData* BackendImpl::GetLruData() {
  return &data_->header.lru;
}

void BackendImpl::UpdateRank(EntryImpl* entry, bool modified) {
  if (read_only_ || (!modified && GetCacheType() == net::SHADER_CACHE))
    return;
  eviction_.UpdateRank(entry, modified);
}

void BackendImpl::RecoveredEntry(CacheRankingsBlock* rankings) {
  Addr address(rankings->Data()->contents);
  scoped_refptr<EntryImpl> cache_entry;
  if (NewEntry(address, &cache_entry)) {
    STRESS_NOTREACHED();
    return;
  }

  uint32_t hash = cache_entry->GetHash();
  cache_entry = nullptr;

  // Anything on the table means that this entry is there.
  if (data_->table[hash & mask_])
    return;

  data_->table[hash & mask_] = address.value();
  FlushIndex();
}

void BackendImpl::InternalDoomEntry(EntryImpl* entry) {
  uint32_t hash = entry->GetHash();
  std::string key = entry->GetKey();
  Addr entry_addr = entry->entry()->address();
  bool error;
  scoped_refptr<EntryImpl> parent_entry =
      MatchEntry(key, hash, true, entry_addr, &error);
  CacheAddr child(entry->GetNextAddress());

  if (!entry->doomed()) {
    // We may have doomed this entry from within MatchEntry.
    eviction_.OnDoomEntry(entry);
    entry->InternalDoom();
    if (!new_eviction_) {
      DecreaseNumEntries();
    }
    stats_.OnEvent(Stats::DOOM_ENTRY);
  }

  if (parent_entry) {
    parent_entry->SetNextAddress(Addr(child));
    parent_entry = nullptr;
  } else if (!error) {
    data_->table[hash & mask_] = child;
  }

  FlushIndex();
}

#if defined(NET_BUILD_STRESS_CACHE)

CacheAddr BackendImpl::GetNextAddr(Addr address) {
  EntriesMap::iterator it = open_entries_.find(address.value());
  if (it != open_entries_.end()) {
    EntryImpl* this_entry = it->second;
    return this_entry->GetNextAddress();
  }
  DCHECK(block_files_.IsValid(address));
  DCHECK(!address.is_separate_file() && address.file_type() == BLOCK_256);

  CacheEntryBlock entry(File(address), address);
  CHECK(entry.Load());
  return entry.Data()->next;
}

void BackendImpl::NotLinked(EntryImpl* entry) {
  Addr entry_addr = entry->entry()->address();
  uint32_t i = entry->GetHash() & mask_;
  Addr address(data_->table[i]);
  if (!address.is_initialized())
    return;

  for (;;) {
    DCHECK(entry_addr.value() != address.value());
    address.set_value(GetNextAddr(address));
    if (!address.is_initialized())
      break;
  }
}
#endif  // NET_BUILD_STRESS_CACHE

// An entry may be linked on the DELETED list for a while after being doomed.
// This function is called when we want to remove it.
void BackendImpl::RemoveEntry(EntryImpl* entry) {
#if defined(NET_BUILD_STRESS_CACHE)
  NotLinked(entry);
#endif
  if (!new_eviction_)
    return;

  DCHECK_NE(ENTRY_NORMAL, entry->entry()->Data()->state);

  eviction_.OnDestroyEntry(entry);
  DecreaseNumEntries();
}

void BackendImpl::OnEntryDestroyBegin(Addr address) {
  auto it = open_entries_.find(address.value());
  if (it != open_entries_.end())
    open_entries_.erase(it);
}

void BackendImpl::OnEntryDestroyEnd() {
  DecreaseNumRefs();
  consider_evicting_at_op_end_ = true;
}

void BackendImpl::OnSyncBackendOpComplete() {
  if (consider_evicting_at_op_end_) {
    if (data_->header.num_bytes > max_size_ && !read_only_ &&
        (up_ticks_ > kTrimDelay || user_flags_ & kNoRandom))
      eviction_.TrimCache(false);
    consider_evicting_at_op_end_ = false;
  }
}

EntryImpl* BackendImpl::GetOpenEntry(CacheRankingsBlock* rankings) const {
  DCHECK(rankings->HasData());
  auto it = open_entries_.find(rankings->Data()->contents);
  if (it != open_entries_.end()) {
    // We have this entry in memory.
    return it->second;
  }

  return nullptr;
}

int32_t BackendImpl::GetCurrentEntryId() const {
  return data_->header.this_id;
}

int64_t BackendImpl::MaxFileSize() const {
  return GetCacheType() == net::PNACL_CACHE ? max_size_ : max_size_ / 8;
}

void BackendImpl::ModifyStorageSize(int32_t old_size, int32_t new_size) {
  if (disabled_ || old_size == new_size)
    return;
  if (old_size > new_size)
    SubstractStorageSize(old_size - new_size);
  else
    AddStorageSize(new_size - old_size);

  FlushIndex();

  // Update the usage statistics.
  stats_.ModifyStorageStats(old_size, new_size);
}

void BackendImpl::TooMuchStorageRequested(int32_t size) {
  stats_.ModifyStorageStats(0, size);
}

bool BackendImpl::IsAllocAllowed(int current_size, int new_size) {
  DCHECK_GT(new_size, current_size);
  if (user_flags_ & kNoBuffering)
    return false;

  int to_add = new_size - current_size;
  if (buffer_bytes_ + to_add > MaxBuffersSize())
    return false;

  buffer_bytes_ += to_add;
  return true;
}

void BackendImpl::BufferDeleted(int size) {
  buffer_bytes_ -= size;
  DCHECK_GE(size, 0);
}

bool BackendImpl::IsLoaded() const {
  if (user_flags_ & kNoLoadProtection)
    return false;

  return (num_pending_io_ > 5 || user_load_);
}

base::WeakPtr<BackendImpl> BackendImpl::GetWeakPtr() {
  return ptr_factory_.GetWeakPtr();
}

// Previously this method was used to determine when to report histograms, so
// the logic is surprisingly convoluted.
bool BackendImpl::ShouldUpdateStats() {
  if (should_update_) {
    return should_update_ == 2;
  }

  should_update_++;
  int64_t last_report = stats_.GetCounter(Stats::LAST_REPORT);
  Time last_time = Time::FromInternalValue(last_report);
  if (!last_report || (Time::Now() - last_time).InDays() >= 7) {
    stats_.SetCounter(Stats::LAST_REPORT, Time::Now().ToInternalValue());
    should_update_++;
    return true;
  }
  return false;
}

void BackendImpl::FirstEviction() {
  DCHECK(data_->header.create_time);
  if (!GetEntryCount())
    return;  // This is just for unit tests.

  stats_.ResetRatios();
}

void BackendImpl::CriticalError(int error) {
  STRESS_NOTREACHED();
  LOG(ERROR) << "Critical error found " << error;
  if (disabled_)
    return;

  stats_.OnEvent(Stats::FATAL_ERROR);
  LogStats();
  ReportError(error);

  // Setting the index table length to an invalid value will force re-creation
  // of the cache files.
  data_->header.table_len = 1;
  disabled_ = true;

  if (!num_refs_)
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&BackendImpl::RestartCache, GetWeakPtr(), true));
}

void BackendImpl::ReportError(int error) {
  STRESS_DCHECK(!error || error == ERR_PREVIOUS_CRASH ||
                error == ERR_CACHE_CREATED);

  // We transmit positive numbers, instead of direct error codes.
  DCHECK_LE(error, 0);
  if (GetCacheType() == net::DISK_CACHE) {
    base::UmaHistogramExactLinear("DiskCache.0.Error", error * -1, 50);
  }
}

void BackendImpl::OnEvent(Stats::Counters an_event) {
  stats_.OnEvent(an_event);
}

void BackendImpl::OnRead(int32_t bytes) {
  DCHECK_GE(bytes, 0);
  byte_count_ += bytes;
  if (byte_count_ < 0)
    byte_count_ = std::numeric_limits<int32_t>::max();
}

void BackendImpl::OnWrite(int32_t bytes) {
  // We use the same implementation as OnRead... just log the number of bytes.
  OnRead(bytes);
}

void BackendImpl::OnStatsTimer() {
  if (disabled_)
    return;

  stats_.OnEvent(Stats::TIMER);
  int64_t time = stats_.GetCounter(Stats::TIMER);
  int64_t current = stats_.GetCounter(Stats::OPEN_ENTRIES);

  // OPEN_ENTRIES is a sampled average of the number of open entries, avoiding
  // the bias towards 0.
  if (num_refs_ && (current != num_refs_)) {
    int64_t diff = (num_refs_ - current) / 50;
    if (!diff)
      diff = num_refs_ > current ? 1 : -1;
    current = current + diff;
    stats_.SetCounter(Stats::OPEN_ENTRIES, current);
    stats_.SetCounter(Stats::MAX_ENTRIES, max_refs_);
  }

  // These values cover about 99.5% of the population (Oct 2011).
  user_load_ = (entry_count_ > 300 || byte_count_ > 7 * 1024 * 1024);
  entry_count_ = 0;
  byte_count_ = 0;
  up_ticks_++;

  if (!data_)
    first_timer_ = false;
  if (first_timer_) {
    first_timer_ = false;
    if (ShouldUpdateStats()) {
      UpdateStats();
    }
  }

  // Save stats to disk at 5 min intervals.
  if (time % 10 == 0)
    StoreStats();
}

void BackendImpl::IncrementIoCount() {
  num_pending_io_++;
}

void BackendImpl::DecrementIoCount() {
  num_pending_io_--;
}

void BackendImpl::SetUnitTestMode() {
  user_flags_ |= kUnitTestMode;
  unit_test_ = true;
}

void BackendImpl::SetUpgradeMode() {
  user_flags_ |= kUpgradeMode;
  read_only_ = true;
}

void BackendImpl::SetNewEviction() {
  user_flags_ |= kNewEviction;
  new_eviction_ = true;
}

void BackendImpl::SetFlags(uint32_t flags) {
  user_flags_ |= flags;
}

void BackendImpl::ClearRefCountForTest() {
  num_refs_ = 0;
}

int BackendImpl::FlushQueueForTest(CompletionOnceCallback callback) {
  background_queue_.FlushQueue(std::move(callback));
  return net::ERR_IO_PENDING;
}

int BackendImpl::RunTaskForTest(base::OnceClosure task,
                                CompletionOnceCallback callback) {
  background_queue_.RunTask(std::move(task), std::move(callback));
  return net::ERR_IO_PENDING;
}

void BackendImpl::TrimForTest(bool empty) {
  eviction_.SetTestMode();
  eviction_.TrimCache(empty);
}

void BackendImpl::TrimDeletedListForTest(bool empty) {
  eviction_.SetTestMode();
  eviction_.TrimDeletedList(empty);
}

base::RepeatingTimer* BackendImpl::GetTimerForTest() {
  return timer_.get();
}

int BackendImpl::SelfCheck() {
  if (!init_) {
    LOG(ERROR) << "Init failed";
    return ERR_INIT_FAILED;
  }

  int num_entries = rankings_.SelfCheck();
  if (num_entries < 0) {
    LOG(ERROR) << "Invalid rankings list, error " << num_entries;
#if !defined(NET_BUILD_STRESS_CACHE)
    return num_entries;
#endif
  }

  if (num_entries != data_->header.num_entries) {
    LOG(ERROR) << "Number of entries mismatch";
#if !defined(NET_BUILD_STRESS_CACHE)
    return ERR_NUM_ENTRIES_MISMATCH;
#endif
  }

  return CheckAllEntries();
}

void BackendImpl::FlushIndex() {
  if (index_.get() && !disabled_)
    index_->Flush();
}

// ------------------------------------------------------------------------

int32_t BackendImpl::GetEntryC
"""


```