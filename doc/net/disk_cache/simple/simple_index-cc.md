Response:
Let's break down the thought process for analyzing the `simple_index.cc` file.

1. **Understand the Core Purpose:** The file name `simple_index.cc` and the namespace `disk_cache` strongly suggest that this component is responsible for managing an index of cached items on disk. The word "simple" might indicate a specific implementation approach within the broader disk cache system.

2. **Identify Key Data Structures:**  Scan the code for prominent data structures. The `EntrySet` (a `std::map`) storing `entry_hash` and `EntryMetadata` is central. This immediately tells you that the index maps a unique identifier (hash) to metadata about the cached entry.

3. **Analyze `EntryMetadata`:** This structure is crucial. What information does it hold?  `last_used_time_seconds_since_epoch_`, `entry_size_256b_chunks_`, `trailer_prefetch_size_`, and `in_memory_data_`. These fields point to core functionalities: tracking usage for eviction, knowing the size of cached items, and potentially some form of prefetching. Note the `Serialize` and `Deserialize` methods – they are key for saving and loading the metadata.

4. **Examine the `SimpleIndex` Class:**  This is the main class. List its member variables and methods. This provides a high-level overview of its responsibilities.

    * **Member Variables:** `entries_set_`, `cache_size_`, `max_size_`, `write_to_disk_timer_`, etc. These reveal the state managed by the index.
    * **Methods:** `Initialize`, `Insert`, `Remove`, `UseIfExists`, `UpdateEntrySize`, `StartEvictionIfNeeded`, `WriteToDisk`, etc. These represent the actions the index can perform.

5. **Trace Key Operations:**  Follow the flow of critical operations like adding, removing, and accessing cache entries.

    * **Insertion (`Insert`):** Creates a new entry in `entries_set_`. Notice it initially doesn't know the size.
    * **Removal (`Remove`):** Deletes an entry from `entries_set_` and updates `cache_size_`.
    * **Usage (`UseIfExists`):** Updates the last used time (important for eviction).
    * **Size Update (`UpdateEntrySize`):** Modifies the size of an entry and triggers eviction if necessary.
    * **Eviction (`StartEvictionIfNeeded`):**  This is a complex process involving sorting entries by last used time and size. It interacts with the `delegate_` to actually delete the files.
    * **Writing to Disk (`WriteToDisk`):**  Saves the index state to disk. The timer mechanism is important for understanding how frequently this happens.
    * **Initialization (`Initialize`, `MergeInitializingSet`):**  Loads the index from disk and merges any pending changes.

6. **Look for Interactions with Other Components:** The `delegate_` member is significant. It represents an interface to external functionality, particularly for the actual deletion of cache entries during eviction. The `SimpleIndexFile` handles the low-level disk I/O. The `BackendCleanupTracker` suggests coordination with a cleanup process.

7. **Identify Potential Links to JavaScript:** Think about how a browser cache works. JavaScript running in a web page triggers network requests. Responses to these requests are often cached. Consider scenarios where JavaScript interacts with the cache:

    * **Fetching Resources:** When JavaScript makes a `fetch` request or loads an image, the browser checks the cache.
    * **Service Workers:** Service workers can intercept network requests and serve cached responses.
    * **Cache API:**  JavaScript has a Cache API that allows explicit management of the browser cache.

    While `simple_index.cc` doesn't *directly* execute JavaScript, it's a crucial part of the infrastructure that supports caching initiated by JavaScript.

8. **Reason about Logic and Edge Cases:**  Go through the code and consider different scenarios and potential issues:

    * **Eviction Logic:** How does the eviction algorithm prioritize entries? What happens when the cache is full?
    * **Concurrency:**  Are there any explicit locking mechanisms? (In this code snippet, it relies on a single sequence runner).
    * **Error Handling:**  Are there checks for file I/O errors?
    * **Initialization:** What happens if the index file is corrupted?

9. **Consider User and Programmer Errors:**  Think about how mistakes might occur:

    * **Incorrect Cache Size Configuration:** Setting the `max_size_` to a very small value could lead to frequent evictions.
    * **File System Issues:** Disk full errors or permissions problems can affect cache operations.
    * **Logic Errors in Delegate:** A faulty `SimpleIndexDelegate` could lead to incorrect eviction behavior.

10. **Trace User Actions to the Code:**  Imagine a user browsing a website. How does their interaction lead to the `SimpleIndex` being involved?

    * **Visiting a webpage:**  Fetches resources, potentially triggering cache writes (insertions).
    * **Navigating to a previously visited page:**  Might retrieve resources from the cache (using `UseIfExists`).
    * **Clearing browsing data:**  Could involve deleting entries managed by the index.

11. **Structure the Output:** Organize the findings into logical sections as requested by the prompt: Functionality, JavaScript relation, logical reasoning (with input/output), common errors, and debugging. Use clear and concise language.

12. **Refine and Review:** Read through the analysis. Are there any inaccuracies or missing points?  Could anything be explained more clearly?  For instance, initially, I might focus too much on the internal mechanics. Reviewing would prompt me to strengthen the connections to the user experience and JavaScript interaction.

This structured approach allows for a comprehensive understanding of the code's role and its interactions within the larger system.
This C++ source file, `simple_index.cc`, is a core component of the Chromium network stack's **simple disk cache**. It manages the **index** of the cache, which is a list of all the cached resources and their associated metadata. Think of it like the table of contents for the disk cache.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Maintaining a List of Cached Entries:**
   - It stores the hash of each cached entry and its metadata in an in-memory data structure (`entries_set_`, a `std::map`).
   - This allows for quick lookups of whether a resource is cached.

2. **Tracking Entry Metadata:**
   - For each entry, it stores metadata like:
     - `last_used_time`:  The last time the entry was accessed (important for eviction).
     - `entry_size`: The size of the cached resource.
     - `trailer_prefetch_size`: (Specifically for AppCache)  Indicates the size of data to prefetch.
     - `in_memory_data`:  A small amount of in-memory data associated with the entry.

3. **Loading and Saving the Index to Disk:**
   - It uses `SimpleIndexFile` to load the index from disk when the cache is initialized and to save the updated index back to disk.
   - It uses a timer (`write_to_disk_timer_`) to batch writes to disk, improving performance. Writes can be triggered after a delay since the last cache operation or when the application goes into the background.

4. **Cache Eviction:**
   - When the cache reaches its maximum size, it implements an eviction strategy to remove older or less frequently used entries.
   - It sorts entries based on their last used time (and optionally size) and asks a `SimpleIndexDelegate` to actually delete the corresponding files.
   - It maintains `high_watermark_` and `low_watermark_` to trigger eviction when the cache size exceeds the high watermark and stop when it falls below the low watermark.

5. **Entry Insertion and Removal:**
   - Provides methods (`Insert`, `Remove`) to add new entries to the index and remove existing ones.

6. **Updating Entry Information:**
   - Allows updating the last used time (`UseIfExists`) and size (`UpdateEntrySize`) of cached entries.

7. **Synchronization and Initialization:**
   - Manages the initialization process, loading the index from disk.
   - Uses a callback mechanism (`to_run_when_initialized_`) to execute tasks only after the index is fully loaded.

8. **AppCache Specific Handling:**
   - Includes logic specifically for the AppCache, such as tracking `trailer_prefetch_size`.

**Relationship with JavaScript Functionality:**

While `simple_index.cc` is a C++ file and doesn't directly execute JavaScript, it's a fundamental part of the browser's caching mechanism, which **directly impacts JavaScript's ability to load resources efficiently**.

Here are examples:

* **Fetching Resources (e.g., `fetch()` API, `XMLHttpRequest`):** When JavaScript in a web page tries to fetch a resource (like an image, script, or stylesheet), the browser's network stack will consult the disk cache. `SimpleIndex` is used to quickly check if the resource is already cached. If it is, the resource can be retrieved from disk much faster than downloading it again.
    * **Example:** A JavaScript application makes a `fetch('/images/logo.png')` request. The browser checks `SimpleIndex` for the hash of `/images/logo.png`. If found, the cached image data is retrieved.

* **Service Workers:** Service workers, written in JavaScript, can intercept network requests and serve responses from the cache. The service worker uses the Cache API, and the underlying implementation utilizes components like `SimpleIndex` to manage the cached data.
    * **Example:** A service worker's `fetch` event handler checks if a requested resource is in its cache. This check indirectly involves `SimpleIndex` to see if the resource exists in the underlying disk cache.

* **Browser Cache API:** JavaScript can directly interact with the browser's cache through the Cache API. Operations like adding resources to the cache or checking for their existence ultimately interact with the disk cache and its index managed by `SimpleIndex`.
    * **Example:**  JavaScript uses `caches.open('my-cache').then(cache => cache.add('/style.css'))`. This operation would eventually involve `SimpleIndex` to record the new entry in the cache index.

**Logical Reasoning with Assumptions, Inputs, and Outputs:**

Let's consider the `UseIfExists` function:

**Scenario:** JavaScript triggers a request for a resource that might be in the cache.

**Assumptions:**
* The `SimpleIndex` has been initialized.
* The `entry_hash` for the requested resource is known.

**Input:** `entry_hash` of the requested resource.

**Logic:**
1. The `UseIfExists` function is called with the `entry_hash`.
2. It searches for the `entry_hash` in the `entries_set_`.
3. If found:
   - For non-AppCache types, it updates the `last_used_time` of the entry to the current time.
   - It triggers `PostponeWritingToDisk` to save the updated index later.
   - It returns `true`.
4. If not found:
   - If the index is not yet initialized, it returns `true` (forcing a disk check).
   - Otherwise, it returns `false`.

**Output:** `true` if the entry exists (or the index isn't initialized), `false` otherwise. Side effect: potentially updates the `last_used_time` in the in-memory index and schedules a disk write.

**User or Programming Common Usage Errors:**

1. **Incorrect Cache Size Configuration:**
   - **Error:** A developer might accidentally set the maximum cache size to a very small value or zero.
   - **Consequence:** This could lead to very frequent cache evictions, making the cache ineffective and potentially causing performance issues as resources need to be re-downloaded repeatedly.
   - **How it reaches here:** The `SetMaxSize` method is called during cache initialization, likely based on command-line flags or configuration settings. An incorrect value passed to this function will directly affect the `max_size_` member.

2. **File System Permissions Issues:**
   - **Error:** The user might not have the necessary permissions to read or write to the cache directory.
   - **Consequence:** The `SimpleIndexFile` might fail to load the index during initialization or fail to save the updated index. This can lead to data loss, corruption, or the cache not functioning correctly.
   - **How it reaches here:** During `Initialize`, `index_file_->LoadIndexEntries` attempts to read the index file. If permissions are incorrect, this operation will fail, potentially leading to errors propagated through the initialization process. Similarly, `WriteToDisk` can fail if write permissions are missing.

3. **Disk Full Errors:**
   - **Error:** The disk where the cache is located might run out of space.
   - **Consequence:** Attempts to write the index or new cache entries might fail, leading to incomplete or corrupted cache data.
   - **How it reaches here:**  When `WriteToDisk` is called, the underlying file system operations might fail due to lack of disk space. This would result in an error returned by the file I/O functions within `SimpleIndexFile`.

**User Operations Leading to This Code (Debugging Clues):**

Here's how user actions can lead to this code being executed, providing debugging clues:

1. **First Visit to a Website:**
   - **User Action:** The user enters a URL in the address bar or clicks a link to a new website.
   - **Flow:**
     - The browser makes network requests for the website's resources (HTML, CSS, JavaScript, images).
     - For each resource, the network stack checks the cache.
     - If the resource is not in the cache, it's downloaded.
     - Upon successful download, the `Insert` method in `SimpleIndex` is likely called to add the resource to the cache index. The `UpdateEntrySize` method will be called later when the size is known.

2. **Subsequent Visit to the Same Website:**
   - **User Action:** The user revisits a website they've been to before.
   - **Flow:**
     - The browser makes network requests for the website's resources again.
     - The network stack consults the cache using the `Has` method in `SimpleIndex`.
     - If the resource is found in the index, the `UseIfExists` method is called to update the last used time. The resource is likely retrieved from the disk cache instead of being downloaded again.

3. **Cache Eviction in the Background:**
   - **User Action:** The user continues browsing, and the cache starts to fill up.
   - **Flow:**
     - Periodically or when the cache size exceeds the `high_watermark_`, the `StartEvictionIfNeeded` method is called.
     - This method sorts the cached entries based on their last used time and size.
     - It then calls methods on the `delegate_` to actually delete the files for the selected entries. The `Remove` method in `SimpleIndex` is called to update the index.

4. **Closing and Reopening the Browser:**
   - **User Action:** The user closes and then reopens the browser.
   - **Flow:**
     - When the browser starts up, the disk cache is initialized.
     - The `Initialize` method in `SimpleIndex` is called.
     - This method uses `SimpleIndexFile` to load the index from disk.

5. **Clearing Browsing Data (Cache):**
   - **User Action:** The user goes into the browser settings and clears their browsing data, specifically the cached images and files.
   - **Flow:**
     - This action triggers a process that iterates through the cache and removes entries.
     - The `Remove` method in `SimpleIndex` is called for each entry being deleted from the cache.

By understanding these user actions and how they interact with the `SimpleIndex`, developers can better diagnose caching-related issues and understand the flow of execution within the Chromium network stack. Debugging would involve looking at the calls to `SimpleIndex` methods, the values of its member variables, and the interactions with `SimpleIndexFile` and the `delegate_`.

### 提示词
```
这是目录为net/disk_cache/simple/simple_index.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/disk_cache/simple/simple_index.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

#include "base/check_op.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_tokenizer.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/simple/simple_entry_format.h"
#include "net/disk_cache/simple/simple_histogram_macros.h"
#include "net/disk_cache/simple/simple_index_delegate.h"
#include "net/disk_cache/simple/simple_index_file.h"
#include "net/disk_cache/simple/simple_synchronous_entry.h"
#include "net/disk_cache/simple/simple_util.h"

#if BUILDFLAG(IS_POSIX)
#include <sys/stat.h>
#include <sys/time.h>
#endif

namespace {

// How many milliseconds we delay writing the index to disk since the last cache
// operation has happened.
const int kWriteToDiskDelayMSecs = 20000;
const int kWriteToDiskOnBackgroundDelayMSecs = 100;

// Divides the cache space into this amount of parts to evict when only one part
// is left.
const uint32_t kEvictionMarginDivisor = 20;

const uint32_t kBytesInKb = 1024;

// This is added to the size of each entry before using the size
// to determine which entries to evict first. It's basically an
// estimate of the filesystem overhead, but it also serves to flatten
// the curve so that 1-byte entries and 2-byte entries are basically
// treated the same.
static const int kEstimatedEntryOverhead = 512;

}  // namespace

namespace disk_cache {

EntryMetadata::EntryMetadata()
    : last_used_time_seconds_since_epoch_(0),
      entry_size_256b_chunks_(0),
      in_memory_data_(0) {}

EntryMetadata::EntryMetadata(base::Time last_used_time,
                             base::StrictNumeric<uint32_t> entry_size)
    : last_used_time_seconds_since_epoch_(0),
      entry_size_256b_chunks_(0),
      in_memory_data_(0) {
  SetEntrySize(entry_size);  // to round/pack properly.
  SetLastUsedTime(last_used_time);
}

EntryMetadata::EntryMetadata(int32_t trailer_prefetch_size,
                             base::StrictNumeric<uint32_t> entry_size)
    : trailer_prefetch_size_(0),
      entry_size_256b_chunks_(0),
      in_memory_data_(0) {
  SetEntrySize(entry_size);  // to round/pack properly
  SetTrailerPrefetchSize(trailer_prefetch_size);
}

base::Time EntryMetadata::GetLastUsedTime() const {
  // Preserve nullity.
  if (last_used_time_seconds_since_epoch_ == 0)
    return base::Time();

  return base::Time::UnixEpoch() +
         base::Seconds(last_used_time_seconds_since_epoch_);
}

void EntryMetadata::SetLastUsedTime(const base::Time& last_used_time) {
  // Preserve nullity.
  if (last_used_time.is_null()) {
    last_used_time_seconds_since_epoch_ = 0;
    return;
  }

  last_used_time_seconds_since_epoch_ = base::saturated_cast<uint32_t>(
      (last_used_time - base::Time::UnixEpoch()).InSeconds());
  // Avoid accidental nullity.
  if (last_used_time_seconds_since_epoch_ == 0)
    last_used_time_seconds_since_epoch_ = 1;
}

int32_t EntryMetadata::GetTrailerPrefetchSize() const {
  return trailer_prefetch_size_;
}

void EntryMetadata::SetTrailerPrefetchSize(int32_t size) {
  if (size <= 0)
    return;
  trailer_prefetch_size_ = size;
}

uint32_t EntryMetadata::GetEntrySize() const {
  return entry_size_256b_chunks_ << 8;
}

void EntryMetadata::SetEntrySize(base::StrictNumeric<uint32_t> entry_size) {
  // This should not overflow since we limit entries to 1/8th of the cache.
  entry_size_256b_chunks_ = (static_cast<uint32_t>(entry_size) + 255) >> 8;
}

void EntryMetadata::Serialize(net::CacheType cache_type,
                              base::Pickle* pickle) const {
  DCHECK(pickle);
  // If you modify the size of the size of the pickle, be sure to update
  // kOnDiskSizeBytes.
  uint32_t packed_entry_info = (entry_size_256b_chunks_ << 8) | in_memory_data_;
  if (cache_type == net::APP_CACHE) {
    pickle->WriteInt64(trailer_prefetch_size_);
  } else {
    int64_t internal_last_used_time = GetLastUsedTime().ToInternalValue();
    pickle->WriteInt64(internal_last_used_time);
  }
  pickle->WriteUInt64(packed_entry_info);
}

bool EntryMetadata::Deserialize(net::CacheType cache_type,
                                base::PickleIterator* it,
                                bool has_entry_in_memory_data,
                                bool app_cache_has_trailer_prefetch_size) {
  DCHECK(it);
  int64_t tmp_time_or_prefetch_size;
  uint64_t tmp_entry_size;
  if (!it->ReadInt64(&tmp_time_or_prefetch_size) ||
      !it->ReadUInt64(&tmp_entry_size) ||
      tmp_entry_size > std::numeric_limits<uint32_t>::max())
    return false;
  if (cache_type == net::APP_CACHE) {
    if (app_cache_has_trailer_prefetch_size) {
      int32_t trailer_prefetch_size = 0;
      base::CheckedNumeric<int32_t> numeric_size(tmp_time_or_prefetch_size);
      if (numeric_size.AssignIfValid(&trailer_prefetch_size)) {
        SetTrailerPrefetchSize(trailer_prefetch_size);
      }
    }
  } else {
    SetLastUsedTime(base::Time::FromInternalValue(tmp_time_or_prefetch_size));
  }
  if (has_entry_in_memory_data) {
    // tmp_entry_size actually packs entry_size_256b_chunks_ and
    // in_memory_data_.
    SetEntrySize(static_cast<uint32_t>(tmp_entry_size & 0xFFFFFF00));
    SetInMemoryData(static_cast<uint8_t>(tmp_entry_size & 0xFF));
  } else {
    SetEntrySize(static_cast<uint32_t>(tmp_entry_size));
    SetInMemoryData(0);
  }
  return true;
}

SimpleIndex::SimpleIndex(
    const scoped_refptr<base::SequencedTaskRunner>& task_runner,
    scoped_refptr<BackendCleanupTracker> cleanup_tracker,
    SimpleIndexDelegate* delegate,
    net::CacheType cache_type,
    std::unique_ptr<SimpleIndexFile> index_file)
    : cleanup_tracker_(std::move(cleanup_tracker)),
      delegate_(delegate),
      cache_type_(cache_type),
      index_file_(std::move(index_file)),
      task_runner_(task_runner) {
  // Creating the callback once so it is reused every time
  // write_to_disk_timer_.Start() is called.
  write_to_disk_cb_ = base::BindRepeating(&SimpleIndex::WriteToDisk,
                                          weak_ptr_factory_.GetWeakPtr(),
                                          INDEX_WRITE_REASON_IDLE);
}

SimpleIndex::~SimpleIndex() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Fail all callbacks waiting for the index to come up.
  for (auto& callback : to_run_when_initialized_) {
    std::move(callback).Run(net::ERR_ABORTED);
  }
}

void SimpleIndex::Initialize(base::Time cache_mtime) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

#if BUILDFLAG(IS_ANDROID)
  if (app_status_listener_getter_) {
    base::android::ApplicationStatusListener* listener =
        app_status_listener_getter_.Run();
    if (listener) {
      listener->SetCallback(
          base::BindRepeating(&SimpleIndex::OnApplicationStateChange,
                              weak_ptr_factory_.GetWeakPtr()));
    }
    // Not using the fallback on purpose here --- if the getter is set, we may
    // be in a process where the base::android::ApplicationStatusListener::New
    // impl is unavailable.
    // (See https://crbug.com/881572)
  } else if (base::android::IsVMInitialized()) {
    owned_app_status_listener_ = base::android::ApplicationStatusListener::New(
        base::BindRepeating(&SimpleIndex::OnApplicationStateChange,
                            weak_ptr_factory_.GetWeakPtr()));
  }
#endif

  auto load_result = std::make_unique<SimpleIndexLoadResult>();
  auto* load_result_ptr = load_result.get();
  index_file_->LoadIndexEntries(
      cache_mtime,
      base::BindOnce(&SimpleIndex::MergeInitializingSet,
                     weak_ptr_factory_.GetWeakPtr(), std::move(load_result)),
      load_result_ptr);
}

void SimpleIndex::SetMaxSize(uint64_t max_bytes) {
  // Zero size means use the default.
  if (max_bytes) {
    max_size_ = max_bytes;
    high_watermark_ = max_size_ - max_size_ / kEvictionMarginDivisor;
    low_watermark_ = max_size_ - 2 * (max_size_ / kEvictionMarginDivisor);
  }
}

void SimpleIndex::ExecuteWhenReady(net::CompletionOnceCallback task) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (initialized_)
    task_runner_->PostTask(FROM_HERE, base::BindOnce(std::move(task), net::OK));
  else
    to_run_when_initialized_.push_back(std::move(task));
}

std::unique_ptr<SimpleIndex::HashList> SimpleIndex::GetEntriesBetween(
    base::Time initial_time,
    base::Time end_time) {
  DCHECK_EQ(true, initialized_);

  // The net::APP_CACHE mode does not track access times.  Assert that external
  // consumers are not relying on access time ranges.
  DCHECK(cache_type_ != net::APP_CACHE ||
         (initial_time.is_null() && end_time.is_null()));

  if (!initial_time.is_null())
    initial_time -= EntryMetadata::GetLowerEpsilonForTimeComparisons();
  if (end_time.is_null())
    end_time = base::Time::Max();
  else
    end_time += EntryMetadata::GetUpperEpsilonForTimeComparisons();
  DCHECK(end_time >= initial_time);

  auto ret_hashes = std::make_unique<HashList>();
  for (const auto& entry : entries_set_) {
    const EntryMetadata& metadata = entry.second;
    base::Time entry_time = metadata.GetLastUsedTime();
    if (initial_time <= entry_time && entry_time < end_time)
      ret_hashes->push_back(entry.first);
  }
  return ret_hashes;
}

std::unique_ptr<SimpleIndex::HashList> SimpleIndex::GetAllHashes() {
  return GetEntriesBetween(base::Time(), base::Time());
}

int32_t SimpleIndex::GetEntryCount() const {
  // TODO(pasko): return a meaningful initial estimate before initialized.
  return entries_set_.size();
}

uint64_t SimpleIndex::GetCacheSize() const {
  DCHECK(initialized_);
  return cache_size_;
}

uint64_t SimpleIndex::GetCacheSizeBetween(base::Time initial_time,
                                          base::Time end_time) const {
  DCHECK_EQ(true, initialized_);

  if (!initial_time.is_null())
    initial_time -= EntryMetadata::GetLowerEpsilonForTimeComparisons();
  if (end_time.is_null())
    end_time = base::Time::Max();
  else
    end_time += EntryMetadata::GetUpperEpsilonForTimeComparisons();

  DCHECK(end_time >= initial_time);
  uint64_t size = 0;
  for (const auto& entry : entries_set_) {
    const EntryMetadata& metadata = entry.second;
    base::Time entry_time = metadata.GetLastUsedTime();
    if (initial_time <= entry_time && entry_time < end_time)
      size += metadata.GetEntrySize();
  }
  return size;
}

base::Time SimpleIndex::GetLastUsedTime(uint64_t entry_hash) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_NE(cache_type_, net::APP_CACHE);
  auto it = entries_set_.find(entry_hash);
  if (it == entries_set_.end())
    return base::Time();
  return it->second.GetLastUsedTime();
}

void SimpleIndex::SetLastUsedTimeForTest(uint64_t entry_hash,
                                         const base::Time last_used) {
  auto it = entries_set_.find(entry_hash);
  CHECK(it != entries_set_.end(), base::NotFatalUntil::M130);
  it->second.SetLastUsedTime(last_used);
}

bool SimpleIndex::HasPendingWrite() const {
  return write_to_disk_timer_.IsRunning();
}

void SimpleIndex::Insert(uint64_t entry_hash) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Upon insert we don't know yet the size of the entry.
  // It will be updated later when the SimpleEntryImpl finishes opening or
  // creating the new entry, and then UpdateEntrySize will be called.
  bool inserted = false;
  if (cache_type_ == net::APP_CACHE) {
    inserted =
        InsertInEntrySet(entry_hash, EntryMetadata(-1, 0u), &entries_set_);
  } else {
    inserted = InsertInEntrySet(
        entry_hash, EntryMetadata(base::Time::Now(), 0u), &entries_set_);
  }
  if (!initialized_)
    removed_entries_.erase(entry_hash);
  if (inserted)
    PostponeWritingToDisk();
}

void SimpleIndex::Remove(uint64_t entry_hash) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  bool need_write = false;
  auto it = entries_set_.find(entry_hash);
  if (it != entries_set_.end()) {
    UpdateEntryIteratorSize(&it, 0u);
    entries_set_.erase(it);
    need_write = true;
  }

  if (!initialized_)
    removed_entries_.insert(entry_hash);

  if (need_write)
    PostponeWritingToDisk();
}

bool SimpleIndex::Has(uint64_t hash) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // If not initialized, always return true, forcing it to go to the disk.
  return !initialized_ || entries_set_.count(hash) > 0;
}

uint8_t SimpleIndex::GetEntryInMemoryData(uint64_t entry_hash) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto it = entries_set_.find(entry_hash);
  if (it == entries_set_.end())
    return 0;
  return it->second.GetInMemoryData();
}

void SimpleIndex::SetEntryInMemoryData(uint64_t entry_hash, uint8_t value) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto it = entries_set_.find(entry_hash);
  if (it == entries_set_.end())
    return;
  return it->second.SetInMemoryData(value);
}

bool SimpleIndex::UseIfExists(uint64_t entry_hash) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Always update the last used time, even if it is during initialization.
  // It will be merged later.
  auto it = entries_set_.find(entry_hash);
  if (it == entries_set_.end())
    // If not initialized, always return true, forcing it to go to the disk.
    return !initialized_;
  // We do not need to track access times in APP_CACHE mode.
  if (cache_type_ == net::APP_CACHE)
    return true;
  it->second.SetLastUsedTime(base::Time::Now());
  PostponeWritingToDisk();
  return true;
}

void SimpleIndex::StartEvictionIfNeeded() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (eviction_in_progress_ || cache_size_ <= high_watermark_)
    return;
  // Take all live key hashes from the index and sort them by time.
  eviction_in_progress_ = true;
  eviction_start_time_ = base::TimeTicks::Now();

  bool use_size_heuristic =
      (cache_type_ != net::GENERATED_BYTE_CODE_CACHE &&
       cache_type_ != net::GENERATED_WEBUI_BYTE_CODE_CACHE);

  // Flatten for sorting.
  std::vector<std::pair<uint64_t, const EntrySet::value_type*>> entries;
  entries.reserve(entries_set_.size());
  uint32_t now = (base::Time::Now() - base::Time::UnixEpoch()).InSeconds();
  for (EntrySet::const_iterator i = entries_set_.begin();
       i != entries_set_.end(); ++i) {
    uint64_t sort_value = now - i->second.RawTimeForSorting();
    // See crbug.com/736437 for context.
    //
    // Will not overflow since we're multiplying two 32-bit values and storing
    // them in a 64-bit variable.
    if (use_size_heuristic)
      sort_value *= i->second.GetEntrySize() + kEstimatedEntryOverhead;
    // Subtract so we don't need a custom comparator.
    entries.emplace_back(std::numeric_limits<uint64_t>::max() - sort_value,
                         &*i);
  }

  uint64_t evicted_so_far_size = 0;
  const uint64_t amount_to_evict = cache_size_ - low_watermark_;
  std::vector<uint64_t> entry_hashes;
  std::sort(entries.begin(), entries.end());
  for (const auto& score_metadata_pair : entries) {
    if (evicted_so_far_size >= amount_to_evict)
      break;
    evicted_so_far_size += score_metadata_pair.second->second.GetEntrySize();
    entry_hashes.push_back(score_metadata_pair.second->first);
  }

  SIMPLE_CACHE_UMA(COUNTS_1M,
                   "Eviction.EntryCount", cache_type_, entry_hashes.size());
  SIMPLE_CACHE_UMA(TIMES,
                   "Eviction.TimeToSelectEntries", cache_type_,
                   base::TimeTicks::Now() - eviction_start_time_);

  delegate_->DoomEntries(&entry_hashes,
                         base::BindOnce(&SimpleIndex::EvictionDone,
                                        weak_ptr_factory_.GetWeakPtr()));
}

int32_t SimpleIndex::GetTrailerPrefetchSize(uint64_t entry_hash) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(cache_type_, net::APP_CACHE);
  auto it = entries_set_.find(entry_hash);
  if (it == entries_set_.end())
    return -1;
  return it->second.GetTrailerPrefetchSize();
}

void SimpleIndex::SetTrailerPrefetchSize(uint64_t entry_hash, int32_t size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(cache_type_, net::APP_CACHE);
  auto it = entries_set_.find(entry_hash);
  if (it == entries_set_.end())
    return;
  int32_t original_size = it->second.GetTrailerPrefetchSize();
  it->second.SetTrailerPrefetchSize(size);
  if (original_size != it->second.GetTrailerPrefetchSize())
    PostponeWritingToDisk();
}

bool SimpleIndex::UpdateEntrySize(uint64_t entry_hash,
                                  base::StrictNumeric<uint32_t> entry_size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto it = entries_set_.find(entry_hash);
  if (it == entries_set_.end())
    return false;

  // Update the entry size.  If there was no change, then there is nothing
  // else to do here.
  if (!UpdateEntryIteratorSize(&it, entry_size))
    return true;

  PostponeWritingToDisk();
  StartEvictionIfNeeded();
  return true;
}

void SimpleIndex::EvictionDone(int result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Ignore the result of eviction. We did our best.
  eviction_in_progress_ = false;
  SIMPLE_CACHE_UMA(TIMES,
                   "Eviction.TimeToDone", cache_type_,
                   base::TimeTicks::Now() - eviction_start_time_);
}

// static
bool SimpleIndex::InsertInEntrySet(
    uint64_t entry_hash,
    const disk_cache::EntryMetadata& entry_metadata,
    EntrySet* entry_set) {
  DCHECK(entry_set);
  auto result = entry_set->emplace(entry_hash, entry_metadata);
  return result.second;
}

void SimpleIndex::InsertEntryForTesting(uint64_t entry_hash,
                                        const EntryMetadata& entry_metadata) {
  DCHECK(entries_set_.find(entry_hash) == entries_set_.end());
  if (InsertInEntrySet(entry_hash, entry_metadata, &entries_set_))
    cache_size_ += entry_metadata.GetEntrySize();
}

void SimpleIndex::PostponeWritingToDisk() {
  if (!initialized_)
    return;
  const int delay = app_on_background_ ? kWriteToDiskOnBackgroundDelayMSecs
                                       : kWriteToDiskDelayMSecs;
  // If the timer is already active, Start() will just Reset it, postponing it.
  write_to_disk_timer_.Start(FROM_HERE, base::Milliseconds(delay),
                             write_to_disk_cb_);
}

bool SimpleIndex::UpdateEntryIteratorSize(
    EntrySet::iterator* it,
    base::StrictNumeric<uint32_t> entry_size) {
  // Update the total cache size with the new entry size.
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_GE(cache_size_, (*it)->second.GetEntrySize());
  uint32_t original_size = (*it)->second.GetEntrySize();
  cache_size_ -= (*it)->second.GetEntrySize();
  (*it)->second.SetEntrySize(entry_size);
  // We use GetEntrySize to get consistent rounding.
  cache_size_ += (*it)->second.GetEntrySize();
  // Return true if the size of the entry actually changed.  Make sure to
  // compare the rounded values provided by GetEntrySize().
  return original_size != (*it)->second.GetEntrySize();
}

void SimpleIndex::MergeInitializingSet(
    std::unique_ptr<SimpleIndexLoadResult> load_result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  EntrySet* index_file_entries = &load_result->entries;

  for (uint64_t removed_entry : removed_entries_) {
    index_file_entries->erase(removed_entry);
  }
  removed_entries_.clear();

  for (const auto& it : entries_set_) {
    const uint64_t entry_hash = it.first;
    std::pair<EntrySet::iterator, bool> insert_result =
        index_file_entries->insert(EntrySet::value_type(entry_hash,
                                                        EntryMetadata()));
    EntrySet::iterator& possibly_inserted_entry = insert_result.first;
    possibly_inserted_entry->second = it.second;
  }

  uint64_t merged_cache_size = 0;
  for (const auto& index_file_entry : *index_file_entries) {
    merged_cache_size += index_file_entry.second.GetEntrySize();
  }

  entries_set_.swap(*index_file_entries);
  cache_size_ = merged_cache_size;
  initialized_ = true;
  init_method_ = load_result->init_method;

  // The actual IO is asynchronous, so calling WriteToDisk() shouldn't slow the
  // merge down much.
  if (load_result->flush_required)
    WriteToDisk(INDEX_WRITE_REASON_STARTUP_MERGE);

  SIMPLE_CACHE_UMA(CUSTOM_COUNTS, "IndexNumEntriesOnInit", cache_type_,
                   entries_set_.size(), 0, 100000, 50);
  SIMPLE_CACHE_UMA(
      MEMORY_KB, "CacheSizeOnInit", cache_type_,
      static_cast<base::HistogramBase::Sample>(cache_size_ / kBytesInKb));
  SIMPLE_CACHE_UMA(
      MEMORY_KB, "MaxCacheSizeOnInit", cache_type_,
      static_cast<base::HistogramBase::Sample>(max_size_ / kBytesInKb));

  // Run all callbacks waiting for the index to come up.
  for (auto& callback : to_run_when_initialized_) {
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(std::move(callback), net::OK));
  }
  to_run_when_initialized_.clear();
}

#if BUILDFLAG(IS_ANDROID)
void SimpleIndex::OnApplicationStateChange(
    base::android::ApplicationState state) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // For more info about android activities, see:
  // developer.android.com/training/basics/activity-lifecycle/pausing.html
  if (state == base::android::APPLICATION_STATE_HAS_RUNNING_ACTIVITIES) {
    app_on_background_ = false;
  } else if (state ==
      base::android::APPLICATION_STATE_HAS_STOPPED_ACTIVITIES) {
    app_on_background_ = true;
    WriteToDisk(INDEX_WRITE_REASON_ANDROID_STOPPED);
  }
}
#endif

void SimpleIndex::WriteToDisk(IndexWriteToDiskReason reason) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!initialized_)
    return;

  // Cancel any pending writes since we are about to write to disk now.
  write_to_disk_timer_.Stop();

  base::OnceClosure after_write;
  if (cleanup_tracker_) {
    // Make anyone synchronizing with our cleanup wait for the index to be
    // written back.
    after_write = base::DoNothingWithBoundArgs(cleanup_tracker_);
  }

  index_file_->WriteToDisk(cache_type_, reason, entries_set_, cache_size_,
                           std::move(after_write));
}

}  // namespace disk_cache
```