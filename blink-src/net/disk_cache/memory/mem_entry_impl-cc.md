Response:
Let's break down the thought process to analyze the `mem_entry_impl.cc` file and address the prompt's requirements.

**1. Understanding the Core Purpose:**

The filename `mem_entry_impl.cc` and the `#include "net/disk_cache/memory/mem_entry_impl.h"` immediately suggest this file implements the in-memory cache entry. The `disk_cache` namespace confirms this. The initial comments reinforce this: "in-memory cache entry".

**2. Identifying Key Classes and Methods:**

The primary class is `MemEntryImpl`. Skimming through the code, I look for constructors, destructors, and public methods. This helps identify the core functionalities. I notice methods like `ReadData`, `WriteData`, `ReadSparseData`, `WriteSparseData`, `GetAvailableRange`, `Doom`, and `Close`. These strongly indicate data manipulation, lifecycle management, and sparse data handling.

**3. Analyzing Functionality by Grouping Methods:**

I mentally group related methods:

* **Lifecycle:** `MemEntryImpl` (constructors), `~MemEntryImpl` (destructor), `Open`, `Close`, `Doom`, `InUse`.
* **Data I/O (Regular):** `ReadData`, `WriteData`, `GetDataSize`.
* **Data I/O (Sparse):** `ReadSparseData`, `WriteSparseData`, `GetAvailableRange`, `ReadyForSparseIO`, `CouldBeSparse`, `InitSparseInfo`, `GetChild`, `ChildInterval`.
* **Metadata:** `GetKey`, `GetLastUsed`, `GetLastModified`, `UpdateStateOnUse`, `SetLastUsedTimeForTest`.
* **Internal Helpers:**  `InternalReadData`, `InternalWriteData`, `InternalReadSparseData`, `InternalWriteSparseData`, `InternalGetAvailableRange`, `Compact`.

**4. Describing Functionality in Natural Language:**

Based on the grouped methods, I describe the core responsibilities:

* **Representing Cache Entries:**  Holding data and metadata.
* **Managing Entry Lifecycle:**  Creation, opening, closing, destruction, and marking as doomed.
* **Reading and Writing Data:**  Supporting both regular (contiguous) and sparse data access.
* **Sparse Data Management:**  Breaking down large sparse data into smaller "child" entries.
* **Tracking Metadata:**  Key, last access times, etc.
* **Integration with Backend:**  Interacting with `MemBackendImpl` for storage management and notifications.
* **Logging:** Using `net::NetLog` for debugging and tracking.

**5. Identifying Connections to JavaScript (and the lack thereof):**

I consider how a web browser uses the cache. JavaScript running in a web page doesn't directly interact with these C++ cache entry objects. The browser's network stack (written in C++) handles cache interactions transparently. The connection is *indirect*. When JavaScript fetches a resource (e.g., using `fetch()` or `XMLHttpRequest`), the browser's networking code will potentially use the cache, and this C++ code might be involved.

**Example Construction:** I think of a concrete scenario: a JavaScript `fetch()` call retrieves an image. The browser will check the cache. If the image is cacheable and present, this `MemEntryImpl` (or its associated data) might be used to serve the image data. This demonstrates the indirect link.

**6. Logical Reasoning and Hypothetical Inputs/Outputs (Focusing on Sparse Data):**

Sparse data handling offers good opportunities for logical reasoning. I consider:

* **Input:** A write to a sparse entry at a non-contiguous offset.
* **Internal Logic:** The code will need to create "child" entries to store these non-contiguous blocks. The `GetChild(offset, true)` call and the logic within `InternalWriteSparseData` are key here.
* **Output:**  Multiple child entries are created, each holding a portion of the data. A subsequent read to that range would then involve reading from these individual child entries.

**Hypothetical Example:**

* **Input:** `WriteSparseData(5000, buffer, 1000)` where `kMaxChildEntrySize` is 4096.
* **Reasoning:** The write spans across two potential child entries. One child for the range around offset 4096, and another for the range around 8192.
* **Output:**  Potentially two child entries are created (or used if they already exist), and the data is written to the appropriate offsets within those child entries.

**7. Common User/Programming Errors:**

I think about how developers might misuse the cache API (even if they don't directly interact with this low-level code):

* **Incorrect Offset/Length:**  Providing negative or out-of-bounds values to read/write operations. The code explicitly checks for these.
* **Writing Beyond Max Size:**  Attempting to write more data than the cache or entry allows. The code checks for `max_file_size`.
* **Using Sparse Operations on Non-Sparse Entries:** Trying to call `ReadSparseData` or `WriteSparseData` before the entry is initialized for sparse data. The `InitSparseInfo()` check addresses this.
* **Resource Exhaustion:**  The cache running out of memory. The `backend_->HasExceededStorageSize()` check handles this.

**Example Construction:**  I create specific examples of these errors, such as calling `ReadData` with a negative offset.

**8. Tracing User Actions to Code (Debugging Clues):**

I think about the typical flow of a web request that might involve the cache:

1. **User Action:**  The user types a URL or clicks a link.
2. **Browser Request:** The browser's networking stack initiates a request.
3. **Cache Lookup:** The network stack checks the cache for the resource.
4. **Cache Hit/Miss:**
    * **Hit:**  The cached data is retrieved (involving `MemEntryImpl` for in-memory cache). `ReadData` or `ReadSparseData` might be called.
    * **Miss:** The resource is fetched from the network.
5. **Cache Insertion (on Miss):** If the resource is cacheable, a new `MemEntryImpl` is created, and `WriteData` or `WriteSparseData` is used to store the downloaded data.
6. **Subsequent Requests:** If the resource is requested again, the cached version is served.

**Debugging Scenario:**  I consider a scenario where a cached image is not loading correctly. A debugger could be used to step through the code, starting from the cache lookup, potentially reaching `ReadData` or `ReadSparseData` within `MemEntryImpl` to inspect the retrieved data. Logging with `net::NetLog` would also be invaluable.

**9. Review and Refinement:**

Finally, I review my answers to ensure they are clear, accurate, and address all aspects of the prompt. I check for consistency and clarity in the examples. I make sure the explanations of the JavaScript connection and the debugging clues are well-articulated.
This C++ source file, `mem_entry_impl.cc`, is a core component of Chromium's network stack, specifically dealing with the **in-memory representation of cache entries**. It defines the `MemEntryImpl` class, which manages the data and metadata associated with a cached resource held in memory.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **In-Memory Cache Entry Management:**
   - **Stores Data:** Holds the actual cached data for a resource in memory using `std::vector<char>` for different data streams (main data, metadata, etc.).
   - **Manages Metadata:**  Keeps track of information like the cache key, last used time, last modified time, and whether the entry is "doomed" (marked for deletion).
   - **Reference Counting:** Implements reference counting (`ref_count_`) to manage the lifecycle of the entry. An entry is deleted when its reference count drops to zero and it's marked as doomed.
   - **Doom and Close:** Provides methods to mark an entry for deletion (`Doom`) and to release a reference to the entry (`Close`).

2. **Data Read and Write Operations:**
   - **`ReadData` and `InternalReadData`:** Allows reading data from the entry's data streams at a specified offset and length.
   - **`WriteData` and `InternalWriteData`:** Enables writing data to the entry's data streams at a given offset, potentially truncating existing data.

3. **Sparse Data Support:**
   - **`ReadSparseData` and `InternalReadSparseData`:**  Handles reading data from potentially non-contiguous regions within a large cached resource. It divides the large data into smaller "child" entries.
   - **`WriteSparseData` and `InternalWriteSparseData`:**  Allows writing data to non-contiguous regions, creating child entries as needed.
   - **`GetAvailableRange` and `InternalGetAvailableRange`:**  Determines the ranges of data currently available within a sparse entry.
   - **Child Entry Management:** Manages the creation and retrieval of child entries for sparse data, using a `std::map` (`children_`).

4. **Integration with MemBackendImpl:**
   - **Communication:** Interacts with the `MemBackendImpl` (the in-memory cache backend) to notify it of entry creation, updates, and doom events.
   - **Storage Size Tracking:**  Updates the backend about the size of the entry to manage memory usage.

5. **Logging:**
   - Uses `net::NetLog` to record events related to the entry's lifecycle and data access, aiding in debugging and performance analysis.

**Relationship with JavaScript Functionality:**

While JavaScript itself doesn't directly interact with this C++ code, `MemEntryImpl` plays a crucial role in caching resources fetched by JavaScript. Here's how they relate:

* **Indirect Interaction:** When JavaScript code in a web page makes a network request (e.g., using `fetch()` or `XMLHttpRequest`), the browser's network stack (written in C++) handles the request.
* **Cache Lookup:** The network stack checks the cache for the requested resource. If found in the in-memory cache, a `MemEntryImpl` object would represent that cached resource.
* **Serving Cached Data:** The data stored within the `MemEntryImpl` (accessed via methods like `ReadData`) is used to fulfill the JavaScript's request, avoiding a network round trip.

**Example:**

Imagine a JavaScript application requests an image file (`image.png`).

1. **JavaScript `fetch('image.png')` is executed.**
2. **Chromium's network stack intercepts the request.**
3. **The network stack checks the in-memory cache managed by `MemBackendImpl`.**
4. **If `image.png` is cached, a `MemEntryImpl` object for `image.png` is retrieved.**
5. **The `ReadData` method of this `MemEntryImpl` is called to retrieve the image data.**
6. **The retrieved data is passed back up the network stack and eventually provided as the response to the `fetch()` promise in JavaScript.**

**Logical Reasoning and Hypothetical Inputs/Outputs (Sparse Data Example):**

Let's consider a scenario involving writing sparse data:

**Assumption:** `kMaxChildEntrySize` is 4096 bytes.

**Hypothetical Input:**

```
// Parent MemEntryImpl exists with key "my_large_file".
IOBuffer* buffer = ...; // Contains 1000 bytes of data.
int offset = 8192;
int buf_len = 1000;
```

**Logical Reasoning:**

1. **`WriteSparseData(offset, buffer, buf_len)` is called on the parent entry.**
2. **`InternalWriteSparseData` is invoked.**
3. **`GetChild(offset, true)` is called.** Since `offset` is 8192, and `kMaxChildEntrySize` is 4096, `ToChildIndex(8192)` would be 2. A new `MemEntryImpl` (child entry) with `child_id_` 2 is created (because `create` is true).
4. **`ToChildOffset(offset)` is calculated:** `8192 & (4096 - 1)` which is `0`.
5. **`child->WriteData(kSparseData, 0, buffer, 1000, ...)` is called on the newly created child entry.** The 1000 bytes from `buffer` are written to the beginning of this child entry.

**Hypothetical Output:**

- A new child `MemEntryImpl` object associated with the parent entry exists.
- This child entry holds the 1000 bytes of data written starting at its offset 0.
- The parent entry's `children_` map now contains an entry with key 2 pointing to the new child entry.

**User or Programming Common Usage Errors and Examples:**

1. **Incorrect Offset or Length in Read/Write:**
   - **Error:** Calling `ReadData` or `WriteData` with a negative offset or a length that extends beyond the bounds of the data.
   - **Example:** `entry->ReadData(0, -10, buffer, 100, ...)` would likely result in `net::ERR_INVALID_ARGUMENT`.

2. **Writing Beyond Maximum File Size:**
   - **Error:** Attempting to write data that would exceed the maximum allowed size for a cached file (defined by `backend_->MaxFileSize()`).
   - **Example:** If `backend_->MaxFileSize()` is 1MB, and you try to write 500KB to an entry that already has 600KB of data, `InternalWriteData` would return `net::ERR_FAILED` or `net::ERR_INSUFFICIENT_RESOURCES`.

3. **Using Sparse Operations on a Non-Sparse Entry (Initially):**
   - **Error:** Trying to call `ReadSparseData` or `WriteSparseData` on an entry before it has been initialized for sparse data (by calling `InitSparseInfo`).
   - **Example:** If you create a regular `MemEntryImpl` and directly call `WriteSparseData`, it will likely return `net::ERR_CACHE_OPERATION_NOT_SUPPORTED`.

4. **Resource Exhaustion:**
   - **Error:** The in-memory cache running out of space while trying to write data.
   - **Example:** If the memory cache is near its capacity, and `InternalWriteData` needs to allocate more memory, `backend_->HasExceededStorageSize()` might return true, leading to `net::ERR_INSUFFICIENT_RESOURCES`.

**User Operation Steps to Reach `mem_entry_impl.cc` (as a Debugging Clue):**

Let's say a user is experiencing a problem where a large image on a website is not loading correctly or is taking a long time to load. As a developer debugging this, here's how you might trace the path to `mem_entry_impl.cc`:

1. **User Action:** The user navigates to a webpage containing the large image (`<img src="large_image.jpg">`).

2. **Browser Request:** The browser initiates a network request for `large_image.jpg`.

3. **Cache Check (MemBackendImpl):** The network stack first checks the in-memory cache (managed by `MemBackendImpl`).

4. **Cache Hit (Potentially):** If the image is present in the in-memory cache, `MemBackendImpl` will retrieve the corresponding `MemEntryImpl` object.

5. **Reading Cached Data (`MemEntryImpl`):**
   - **For regular images:** `MemEntryImpl::ReadData` might be called to retrieve the image data.
   - **For large or segmented images:**  If the image was stored as sparse data, `MemEntryImpl::ReadSparseData` would be invoked. This would involve fetching data from multiple child `MemEntryImpl` objects.

6. **Potential Issues and Debugging Points:**
   - **Incorrect Data:** If the image is corrupted in the cache, `ReadData` or `ReadSparseData` might be returning incorrect data. Stepping through these functions would reveal the issue.
   - **Performance Bottleneck:** If the image is loading slowly, you might investigate the time spent in `ReadSparseData` if it's a sparse entry, checking the efficiency of accessing child entries.
   - **Cache Miss (Unexpected):** If the image is expected to be cached but isn't, you'd investigate why the `MemEntryImpl` wasn't created or was evicted prematurely.

7. **Debugging Tools:**
   - **Chromium's `net-internals` (chrome://net-internals/#cache):**  Provides insights into the cache's state, including entries, their sizes, and hit/miss ratios.
   - **Debugger (e.g., gdb):** Setting breakpoints in `MemEntryImpl::ReadData` or `MemEntryImpl::ReadSparseData` would allow you to inspect the state of the entry, the data being read, and any potential errors.
   - **Network Logging (`net::NetLog`):** The logging within `MemEntryImpl` can provide valuable information about entry creation, data access, and errors.

By understanding the role of `mem_entry_impl.cc` and using debugging tools, developers can effectively diagnose and resolve issues related to in-memory caching in Chromium.

Prompt: 
```
这是目录为net/disk_cache/memory/mem_entry_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/disk_cache/memory/mem_entry_impl.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/check_op.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_math.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "net/base/interval.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/memory/mem_backend_impl.h"
#include "net/disk_cache/net_log_parameters.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"

using base::Time;

namespace disk_cache {

namespace {

const int kSparseData = 1;

// Maximum size of a child of sparse entry is 2 to the power of this number.
const int kMaxChildEntryBits = 12;

// Sparse entry children have maximum size of 4KB.
const int kMaxChildEntrySize = 1 << kMaxChildEntryBits;

// Convert global offset to child index.
int64_t ToChildIndex(int64_t offset) {
  return offset >> kMaxChildEntryBits;
}

// Convert global offset to offset in child entry.
int ToChildOffset(int64_t offset) {
  return static_cast<int>(offset & (kMaxChildEntrySize - 1));
}

// Returns a name for a child entry given the base_name of the parent and the
// child_id.  This name is only used for logging purposes.
// If the entry is called entry_name, child entries will be named something
// like Range_entry_name:YYY where YYY is the number of the particular child.
std::string GenerateChildName(const std::string& base_name, int64_t child_id) {
  return base::StringPrintf("Range_%s:%" PRId64, base_name.c_str(), child_id);
}

// Returns NetLog parameters for the creation of a MemEntryImpl. A separate
// function is needed because child entries don't store their key().
base::Value::Dict NetLogEntryCreationParams(const MemEntryImpl* entry) {
  base::Value::Dict dict;
  std::string key;
  switch (entry->type()) {
    case MemEntryImpl::EntryType::kParent:
      key = entry->key();
      break;
    case MemEntryImpl::EntryType::kChild:
      key = GenerateChildName(entry->parent()->key(), entry->child_id());
      break;
  }
  dict.Set("key", key);
  dict.Set("created", true);
  return dict;
}

}  // namespace

MemEntryImpl::MemEntryImpl(base::WeakPtr<MemBackendImpl> backend,
                           const std::string& key,
                           net::NetLog* net_log)
    : MemEntryImpl(backend,
                   key,
                   0,        // child_id
                   nullptr,  // parent
                   net_log) {
  Open();
  // Just creating the entry (without any data) could cause the storage to
  // grow beyond capacity, but we allow such infractions.
  backend_->ModifyStorageSize(GetStorageSize());
}

MemEntryImpl::MemEntryImpl(base::WeakPtr<MemBackendImpl> backend,
                           int64_t child_id,
                           MemEntryImpl* parent,
                           net::NetLog* net_log)
    : MemEntryImpl(backend,
                   std::string(),  // key
                   child_id,
                   parent,
                   net_log) {
  (*parent_->children_)[child_id] = this;
}

void MemEntryImpl::Open() {
  // Only a parent entry can be opened.
  DCHECK_EQ(EntryType::kParent, type());
  CHECK_NE(ref_count_, std::numeric_limits<uint32_t>::max());
  ++ref_count_;
  DCHECK(!doomed_);
}

bool MemEntryImpl::InUse() const {
  if (type() == EntryType::kChild)
    return parent_->InUse();

  return ref_count_ > 0;
}

int MemEntryImpl::GetStorageSize() const {
  int storage_size = static_cast<int32_t>(key_.size());
  for (const auto& i : data_)
    storage_size += i.size();
  return storage_size;
}

void MemEntryImpl::UpdateStateOnUse(EntryModified modified_enum) {
  if (!doomed_ && backend_)
    backend_->OnEntryUpdated(this);

  last_used_ = MemBackendImpl::Now(backend_);
  if (modified_enum == ENTRY_WAS_MODIFIED)
    last_modified_ = last_used_;
}

void MemEntryImpl::Doom() {
  if (!doomed_) {
    doomed_ = true;
    if (backend_)
      backend_->OnEntryDoomed(this);
    net_log_.AddEvent(net::NetLogEventType::ENTRY_DOOM);
  }
  if (!ref_count_)
    delete this;
}

void MemEntryImpl::Close() {
  DCHECK_EQ(EntryType::kParent, type());
  CHECK_GT(ref_count_, 0u);
  --ref_count_;
  if (ref_count_ == 0 && !doomed_) {
    // At this point the user is clearly done writing, so make sure there isn't
    // wastage due to exponential growth of vector for main data stream.
    Compact();
    if (children_) {
      for (const auto& child_info : *children_) {
        if (child_info.second != this)
          child_info.second->Compact();
      }
    }
  }
  if (!ref_count_ && doomed_)
    delete this;
}

std::string MemEntryImpl::GetKey() const {
  // A child entry doesn't have key so this method should not be called.
  DCHECK_EQ(EntryType::kParent, type());
  return key_;
}

Time MemEntryImpl::GetLastUsed() const {
  return last_used_;
}

Time MemEntryImpl::GetLastModified() const {
  return last_modified_;
}

int32_t MemEntryImpl::GetDataSize(int index) const {
  if (index < 0 || index >= kNumStreams)
    return 0;
  return data_[index].size();
}

int MemEntryImpl::ReadData(int index,
                           int offset,
                           IOBuffer* buf,
                           int buf_len,
                           CompletionOnceCallback callback) {
  if (net_log_.IsCapturing()) {
    NetLogReadWriteData(net_log_, net::NetLogEventType::ENTRY_READ_DATA,
                        net::NetLogEventPhase::BEGIN, index, offset, buf_len,
                        false);
  }

  int result = InternalReadData(index, offset, buf, buf_len);

  if (net_log_.IsCapturing()) {
    NetLogReadWriteComplete(net_log_, net::NetLogEventType::ENTRY_READ_DATA,
                            net::NetLogEventPhase::END, result);
  }
  return result;
}

int MemEntryImpl::WriteData(int index,
                            int offset,
                            IOBuffer* buf,
                            int buf_len,
                            CompletionOnceCallback callback,
                            bool truncate) {
  if (net_log_.IsCapturing()) {
    NetLogReadWriteData(net_log_, net::NetLogEventType::ENTRY_WRITE_DATA,
                        net::NetLogEventPhase::BEGIN, index, offset, buf_len,
                        truncate);
  }

  int result = InternalWriteData(index, offset, buf, buf_len, truncate);

  if (net_log_.IsCapturing()) {
    NetLogReadWriteComplete(net_log_, net::NetLogEventType::ENTRY_WRITE_DATA,
                            net::NetLogEventPhase::END, result);
  }

  return result;
}

int MemEntryImpl::ReadSparseData(int64_t offset,
                                 IOBuffer* buf,
                                 int buf_len,
                                 CompletionOnceCallback callback) {
  if (net_log_.IsCapturing()) {
    NetLogSparseOperation(net_log_, net::NetLogEventType::SPARSE_READ,
                          net::NetLogEventPhase::BEGIN, offset, buf_len);
  }
  int result = InternalReadSparseData(offset, buf, buf_len);
  if (net_log_.IsCapturing())
    net_log_.EndEvent(net::NetLogEventType::SPARSE_READ);
  return result;
}

int MemEntryImpl::WriteSparseData(int64_t offset,
                                  IOBuffer* buf,
                                  int buf_len,
                                  CompletionOnceCallback callback) {
  if (net_log_.IsCapturing()) {
    NetLogSparseOperation(net_log_, net::NetLogEventType::SPARSE_WRITE,
                          net::NetLogEventPhase::BEGIN, offset, buf_len);
  }
  int result = InternalWriteSparseData(offset, buf, buf_len);
  if (net_log_.IsCapturing())
    net_log_.EndEvent(net::NetLogEventType::SPARSE_WRITE);
  return result;
}

RangeResult MemEntryImpl::GetAvailableRange(int64_t offset,
                                            int len,
                                            RangeResultCallback callback) {
  if (net_log_.IsCapturing()) {
    NetLogSparseOperation(net_log_, net::NetLogEventType::SPARSE_GET_RANGE,
                          net::NetLogEventPhase::BEGIN, offset, len);
  }
  RangeResult result = InternalGetAvailableRange(offset, len);
  if (net_log_.IsCapturing()) {
    net_log_.EndEvent(net::NetLogEventType::SPARSE_GET_RANGE, [&] {
      return CreateNetLogGetAvailableRangeResultParams(result);
    });
  }
  return result;
}

bool MemEntryImpl::CouldBeSparse() const {
  DCHECK_EQ(EntryType::kParent, type());
  return (children_.get() != nullptr);
}

net::Error MemEntryImpl::ReadyForSparseIO(CompletionOnceCallback callback) {
  return net::OK;
}

void MemEntryImpl::SetLastUsedTimeForTest(base::Time time) {
  last_used_ = time;
}

// ------------------------------------------------------------------------

MemEntryImpl::MemEntryImpl(base::WeakPtr<MemBackendImpl> backend,
                           const ::std::string& key,
                           int64_t child_id,
                           MemEntryImpl* parent,
                           net::NetLog* net_log)
    : key_(key),
      child_id_(child_id),
      parent_(parent),
      last_modified_(MemBackendImpl::Now(backend)),
      last_used_(last_modified_),
      backend_(backend) {
  backend_->OnEntryInserted(this);
  net_log_ = net::NetLogWithSource::Make(
      net_log, net::NetLogSourceType::MEMORY_CACHE_ENTRY);
  net_log_.BeginEvent(net::NetLogEventType::DISK_CACHE_MEM_ENTRY_IMPL,
                      [&] { return NetLogEntryCreationParams(this); });
}

MemEntryImpl::~MemEntryImpl() {
  if (backend_)
    backend_->ModifyStorageSize(-GetStorageSize());

  if (type() == EntryType::kParent) {
    if (children_) {
      EntryMap children;
      children_->swap(children);

      for (auto& it : children) {
        // Since |this| is stored in the map, it should be guarded against
        // double dooming, which will result in double destruction.
        if (it.second != this)
          it.second->Doom();
      }
    }
  } else {
    parent_->children_->erase(child_id_);
  }
  net_log_.EndEvent(net::NetLogEventType::DISK_CACHE_MEM_ENTRY_IMPL);
}

int MemEntryImpl::InternalReadData(int index, int offset, IOBuffer* buf,
                                   int buf_len) {
  DCHECK(type() == EntryType::kParent || index == kSparseData);

  if (index < 0 || index >= kNumStreams || buf_len < 0)
    return net::ERR_INVALID_ARGUMENT;

  int entry_size = data_[index].size();
  if (offset >= entry_size || offset < 0 || !buf_len)
    return 0;

  int end_offset;
  if (!base::CheckAdd(offset, buf_len).AssignIfValid(&end_offset) ||
      end_offset > entry_size)
    buf_len = entry_size - offset;

  UpdateStateOnUse(ENTRY_WAS_NOT_MODIFIED);
  std::copy(data_[index].begin() + offset,
            data_[index].begin() + offset + buf_len, buf->data());
  return buf_len;
}

int MemEntryImpl::InternalWriteData(int index, int offset, IOBuffer* buf,
                                    int buf_len, bool truncate) {
  DCHECK(type() == EntryType::kParent || index == kSparseData);
  if (!backend_)
    return net::ERR_INSUFFICIENT_RESOURCES;

  if (index < 0 || index >= kNumStreams)
    return net::ERR_INVALID_ARGUMENT;

  if (offset < 0 || buf_len < 0)
    return net::ERR_INVALID_ARGUMENT;

  const int max_file_size = backend_->MaxFileSize();

  int end_offset;
  if (offset > max_file_size || buf_len > max_file_size ||
      !base::CheckAdd(offset, buf_len).AssignIfValid(&end_offset) ||
      end_offset > max_file_size) {
    return net::ERR_FAILED;
  }

  std::vector<char>& data = data_[index];
  const int old_data_size = base::checked_cast<int>(data.size());

  // Overwrite any data that fits inside the existing file.
  if (offset < old_data_size && buf_len > 0) {
    const int bytes_to_copy = std::min(old_data_size - offset, buf_len);
    std::copy(buf->data(), buf->data() + bytes_to_copy, data.begin() + offset);
  }

  const int delta = end_offset - old_data_size;
  if (truncate && delta < 0) {
    // We permit reducing the size even if the storage size has been exceeded,
    // since it can only improve the situation. See https://crbug.com/331839344.
    backend_->ModifyStorageSize(delta);
    data.resize(end_offset);
  } else if (delta > 0) {
    backend_->ModifyStorageSize(delta);
    if (backend_->HasExceededStorageSize()) {
      backend_->ModifyStorageSize(-delta);
      return net::ERR_INSUFFICIENT_RESOURCES;
    }

    // Zero fill any hole.
    int current_size = old_data_size;
    if (current_size < offset) {
      data.resize(offset);
      current_size = offset;
    }
    // Append any data after the old end of the file.
    if (end_offset > current_size) {
      data.insert(data.end(), buf->data() + current_size - offset,
                  buf->data() + buf_len);
    }
  }

  UpdateStateOnUse(ENTRY_WAS_MODIFIED);

  return buf_len;
}

int MemEntryImpl::InternalReadSparseData(int64_t offset,
                                         IOBuffer* buf,
                                         int buf_len) {
  DCHECK_EQ(EntryType::kParent, type());

  if (!InitSparseInfo())
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  if (offset < 0 || buf_len < 0)
    return net::ERR_INVALID_ARGUMENT;

  // Ensure that offset + buf_len does not overflow. This ensures that
  // offset + io_buf->BytesConsumed() never overflows below.
  // The result of std::min is guaranteed to fit into int since buf_len did.
  buf_len = std::min(static_cast<int64_t>(buf_len),
                     std::numeric_limits<int64_t>::max() - offset);

  // We will keep using this buffer and adjust the offset in this buffer.
  scoped_refptr<net::DrainableIOBuffer> io_buf =
      base::MakeRefCounted<net::DrainableIOBuffer>(buf, buf_len);

  // Iterate until we have read enough.
  while (io_buf->BytesRemaining()) {
    MemEntryImpl* child = GetChild(offset + io_buf->BytesConsumed(), false);

    // No child present for that offset.
    if (!child)
      break;

    // We then need to prepare the child offset and len.
    int child_offset = ToChildOffset(offset + io_buf->BytesConsumed());

    // If we are trying to read from a position that the child entry has no data
    // we should stop.
    if (child_offset < child->child_first_pos_)
      break;
    if (net_log_.IsCapturing()) {
      NetLogSparseReadWrite(net_log_,
                            net::NetLogEventType::SPARSE_READ_CHILD_DATA,
                            net::NetLogEventPhase::BEGIN,
                            child->net_log_.source(), io_buf->BytesRemaining());
    }
    int ret =
        child->ReadData(kSparseData, child_offset, io_buf.get(),
                        io_buf->BytesRemaining(), CompletionOnceCallback());
    if (net_log_.IsCapturing()) {
      net_log_.EndEventWithNetErrorCode(
          net::NetLogEventType::SPARSE_READ_CHILD_DATA, ret);
    }

    // If we encounter an error in one entry, return immediately.
    if (ret < 0)
      return ret;
    else if (ret == 0)
      break;

    // Increment the counter by number of bytes read in the child entry.
    io_buf->DidConsume(ret);
  }

  UpdateStateOnUse(ENTRY_WAS_NOT_MODIFIED);
  return io_buf->BytesConsumed();
}

int MemEntryImpl::InternalWriteSparseData(int64_t offset,
                                          IOBuffer* buf,
                                          int buf_len) {
  DCHECK_EQ(EntryType::kParent, type());

  if (!InitSparseInfo())
    return net::ERR_CACHE_OPERATION_NOT_SUPPORTED;

  // We can't generally do this without the backend since we need it to create
  // child entries.
  if (!backend_)
    return net::ERR_FAILED;

  // Check that offset + buf_len does not overflow. This ensures that
  // offset + io_buf->BytesConsumed() never overflows below.
  if (offset < 0 || buf_len < 0 || !base::CheckAdd(offset, buf_len).IsValid())
    return net::ERR_INVALID_ARGUMENT;

  scoped_refptr<net::DrainableIOBuffer> io_buf =
      base::MakeRefCounted<net::DrainableIOBuffer>(buf, buf_len);

  // This loop walks through child entries continuously starting from |offset|
  // and writes blocks of data (of maximum size kMaxChildEntrySize) into each
  // child entry until all |buf_len| bytes are written. The write operation can
  // start in the middle of an entry.
  while (io_buf->BytesRemaining()) {
    MemEntryImpl* child = GetChild(offset + io_buf->BytesConsumed(), true);
    int child_offset = ToChildOffset(offset + io_buf->BytesConsumed());

    // Find the right amount to write, this evaluates the remaining bytes to
    // write and remaining capacity of this child entry.
    int write_len =
        std::min(io_buf->BytesRemaining(), kMaxChildEntrySize - child_offset);

    // Keep a record of the last byte position (exclusive) in the child.
    int data_size = child->GetDataSize(kSparseData);

    if (net_log_.IsCapturing()) {
      NetLogSparseReadWrite(
          net_log_, net::NetLogEventType::SPARSE_WRITE_CHILD_DATA,
          net::NetLogEventPhase::BEGIN, child->net_log_.source(), write_len);
    }

    // Always writes to the child entry. This operation may overwrite data
    // previously written.
    // TODO(hclam): if there is data in the entry and this write is not
    // continuous we may want to discard this write.
    int ret = child->WriteData(kSparseData, child_offset, io_buf.get(),
                               write_len, CompletionOnceCallback(), true);
    if (net_log_.IsCapturing()) {
      net_log_.EndEventWithNetErrorCode(
          net::NetLogEventType::SPARSE_WRITE_CHILD_DATA, ret);
    }
    if (ret < 0)
      return ret;
    else if (ret == 0)
      break;

    // Keep a record of the first byte position in the child if the write was
    // not aligned nor continuous. This is to enable witting to the middle
    // of an entry and still keep track of data off the aligned edge.
    if (data_size != child_offset)
      child->child_first_pos_ = child_offset;

    // Adjust the offset in the IO buffer.
    io_buf->DidConsume(ret);
  }

  UpdateStateOnUse(ENTRY_WAS_MODIFIED);
  return io_buf->BytesConsumed();
}

RangeResult MemEntryImpl::InternalGetAvailableRange(int64_t offset, int len) {
  DCHECK_EQ(EntryType::kParent, type());

  if (!InitSparseInfo())
    return RangeResult(net::ERR_CACHE_OPERATION_NOT_SUPPORTED);

  if (offset < 0 || len < 0)
    return RangeResult(net::ERR_INVALID_ARGUMENT);

  // Truncate |len| to make sure that |offset + len| does not overflow.
  // This is OK since one can't write that far anyway.
  // The result of std::min is guaranteed to fit into int since |len| did.
  len = std::min(static_cast<int64_t>(len),
                 std::numeric_limits<int64_t>::max() - offset);

  net::Interval<int64_t> requested(offset, offset + len);

  // Find the first relevant child, if any --- may have to skip over
  // one entry as it may be before the range (consider, for example,
  // if the request is for [2048, 10000), while [0, 1024) is a valid range
  // for the entry).
  EntryMap::const_iterator i = children_->lower_bound(ToChildIndex(offset));
  if (i != children_->cend() && !ChildInterval(i).Intersects(requested))
    ++i;
  net::Interval<int64_t> found;
  if (i != children_->cend() &&
      requested.Intersects(ChildInterval(i), &found)) {
    // Found something relevant; now just need to expand this out if next
    // children are contiguous and relevant to the request.
    while (true) {
      ++i;
      net::Interval<int64_t> relevant_in_next_child;
      if (i == children_->cend() ||
          !requested.Intersects(ChildInterval(i), &relevant_in_next_child) ||
          relevant_in_next_child.min() != found.max()) {
        break;
      }

      found.SpanningUnion(relevant_in_next_child);
    }

    return RangeResult(found.min(), found.Length());
  }

  return RangeResult(offset, 0);
}

bool MemEntryImpl::InitSparseInfo() {
  DCHECK_EQ(EntryType::kParent, type());

  if (!children_) {
    // If we already have some data in sparse stream but we are being
    // initialized as a sparse entry, we should fail.
    if (GetDataSize(kSparseData))
      return false;
    children_ = std::make_unique<EntryMap>();

    // The parent entry stores data for the first block, so save this object to
    // index 0.
    (*children_)[0] = this;
  }
  return true;
}

MemEntryImpl* MemEntryImpl::GetChild(int64_t offset, bool create) {
  DCHECK_EQ(EntryType::kParent, type());
  int64_t index = ToChildIndex(offset);
  auto i = children_->find(index);
  if (i != children_->end())
    return i->second;
  if (create)
    return new MemEntryImpl(backend_, index, this, net_log_.net_log());
  return nullptr;
}

net::Interval<int64_t> MemEntryImpl::ChildInterval(
    MemEntryImpl::EntryMap::const_iterator i) {
  DCHECK(i != children_->cend());
  const MemEntryImpl* child = i->second;
  // The valid range in child is [child_first_pos_, DataSize), since the child
  // entry ops just use standard disk_cache::Entry API, so DataSize is
  // not aware of any hole in the beginning.
  int64_t child_responsibility_start = (i->first) * kMaxChildEntrySize;
  return net::Interval<int64_t>(
      child_responsibility_start + child->child_first_pos_,
      child_responsibility_start + child->GetDataSize(kSparseData));
}

void MemEntryImpl::Compact() {
  // Stream 0 should already be fine since it's written out in a single WriteData().
  data_[1].shrink_to_fit();
  data_[2].shrink_to_fit();
}

}  // namespace disk_cache

"""

```