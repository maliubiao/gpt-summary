Response:
My thought process to answer the request for the `SimpleEntryImpl.cc` functionality breakdown goes like this:

1. **Understand the Goal:** The request asks for a description of the file's functionalities, its relationship to JavaScript (if any), logical reasoning examples, common user/programming errors, debugging tips, and a summary of its functions. It explicitly marks this as Part 1 of 3.

2. **Initial Scan for Key Terms and Concepts:** I first quickly scanned the code for recurring keywords and concepts. These jumped out:
    * `disk_cache`
    * `entry` (and related terms like `OpenEntry`, `CreateEntry`, `DoomEntry`, `Close`)
    * `stream` (implying data storage and retrieval)
    * `sparse data`
    * `IOBuffer` (Chromium's buffer management)
    * `callback` (asynchronous operations)
    * `pending_operations_` (a queue)
    * `STATE_` (enum for entry states)
    * `net::Error`
    * `net::NetLog` (for debugging/tracing)
    * `SimpleBackendImpl`, `SimpleSynchronousEntry`, `SimpleFileTracker`, `SimpleIndex` (other components of the simple cache)
    * `optimistic_operations_`

3. **Identify Core Responsibilities:** Based on the key terms, I deduced the primary responsibility of `SimpleEntryImpl.cc`:  **managing the lifecycle and I/O operations for a single cache entry in the Chromium network stack's simple disk cache.**

4. **Break Down Functionality by Public Methods:** I then went through the public methods, as these represent the external interface of the class and clearly define its capabilities:
    * **Lifecycle Management:** `OpenEntry`, `CreateEntry`, `OpenOrCreateEntry`, `DoomEntry`, `Close`. These clearly handle the creation, retrieval, deletion, and closing of cache entries.
    * **Data Access:** `ReadData`, `WriteData`, `ReadSparseData`, `WriteSparseData`, `GetAvailableRange`, `GetDataSize`. These are responsible for reading and writing data to the cache entry. The "sparse" versions suggest support for potentially large files with gaps.
    * **Metadata:** `GetKey`, `GetLastUsed`, `GetLastModified`. These provide access to metadata associated with the entry.
    * **Control:** `CancelSparseIO`, `ReadyForSparseIO`, `SetPriority`, `SetLastUsedTimeForTest`. These are less common operations, likely for specific scenarios or testing.

5. **Relate to Asynchronous Operations:** The presence of `CompletionOnceCallback` everywhere strongly indicates asynchronous operations. The `pending_operations_` queue reinforces this, suggesting a mechanism to serialize and manage these operations.

6. **Address Specific Questions in the Prompt:**  With a solid understanding of the core functionality, I addressed the specific points in the request:

    * **Functionality Summary:**  I combined the breakdown of public methods into a concise summary.
    * **Relationship to JavaScript:** I considered the role of the network stack. JavaScript interacts with the network through browser APIs (like `fetch` or `XMLHttpRequest`). The cache helps optimize these requests. I focused on how JavaScript-initiated network requests might lead to cache operations managed by this code.
    * **Logical Reasoning:** I picked a simple scenario (writing data) and walked through the assumed inputs and outputs, highlighting the asynchronous nature and the role of the callback.
    * **User/Programming Errors:** I thought about common mistakes when interacting with a cache, such as incorrect offsets, buffer sizes, or attempting to access a closed entry.
    * **User Operation to Code Path:** I outlined a typical browser action (loading a webpage) and traced how it might involve the disk cache and eventually reach this code.
    * **Part 1 Summary:** I reiterated the core responsibility of the file.

7. **Consider "Optimistic Operations":** The presence of `use_optimistic_operations_` and the associated logic caught my attention. This suggests a potential optimization where the cache might respond quickly (optimistically) before the actual disk I/O is complete. I made sure to mention this.

8. **Pay Attention to Details:** I noted things like the `crc32` checksums (for data integrity), the `doom_state_` (for marking entries for deletion), and the different `STATE_` values (representing the entry's current status).

9. **Structure and Clarity:** I organized the information logically, using headings and bullet points for better readability. I tried to use clear and concise language.

10. **Review and Refine:** Finally, I reviewed my answer to ensure accuracy, completeness, and clarity. I checked if I had addressed all parts of the prompt.

By following these steps, I could systematically analyze the provided code snippet and generate a comprehensive and informative response that addresses all aspects of the user's request. The iterative process of scanning, identifying key concepts, breaking down functionality, and then addressing specific questions is crucial for understanding complex code like this.好的，让我们来分析一下 `net/disk_cache/simple/simple_entry_impl.cc` 这个文件的功能。

**文件功能归纳**

`simple_entry_impl.cc` 文件实现了 Chromium 网络栈中简单磁盘缓存的单个缓存条目 (`SimpleEntryImpl`) 的核心逻辑。它负责管理缓存条目的生命周期、数据读写、状态维护以及与后端存储的交互。

**具体功能点：**

1. **缓存条目生命周期管理:**
   - **创建 (CreateEntry, OpenOrCreateEntry):**  负责创建新的缓存条目，包括在索引中注册和在磁盘上分配空间。它支持乐观创建模式 (`use_optimistic_operations_`)，允许在实际磁盘操作完成前先返回条目。
   - **打开 (OpenEntry):** 负责打开已存在的缓存条目，检查索引状态，并加载必要的元数据。
   - **关闭 (Close):** 负责关闭缓存条目，释放资源，并可能触发后端的一些清理操作。
   - **删除/标记删除 (DoomEntry):**  负责将缓存条目标记为删除，并通知后端进行清理。它支持在创建过程中进行删除（`optimistic_create_pending_doom_state_`）。

2. **数据读写操作:**
   - **写入数据流 (WriteData):** 允许向缓存条目的指定数据流写入数据。支持截断写入。对于流 0，数据会先保存在内存中。支持乐观写入模式。
   - **读取数据流 (ReadData):** 允许从缓存条目的指定数据流读取数据。
   - **写入稀疏数据 (WriteSparseData):** 允许向缓存条目写入稀疏数据，即可以写入不连续的数据块。
   - **读取稀疏数据 (ReadSparseData):** 允许从缓存条目读取稀疏数据。
   - **获取可用范围 (GetAvailableRange):**  用于查询指定偏移量开始的可用数据范围。

3. **状态管理和同步:**
   - **状态跟踪 (state_):**  维护缓存条目的当前状态（例如：未初始化、准备就绪、IO等待等）。
   - **操作队列 (pending_operations_):**  使用队列来管理待处理的异步操作，确保操作的顺序执行。
   - **同步机制:** 使用 `ScopedOperationRunner` 确保在函数退出时运行下一个待处理的操作。

4. **元数据管理:**
   - **键 (key_):** 存储缓存条目的键。
   - **最后使用时间 (last_used_):** 记录缓存条目最后一次被访问的时间。
   - **最后修改时间 (last_modified_):** 记录缓存条目最后一次被修改的时间。
   - **数据大小 (data_size_):** 记录每个数据流的大小。
   - **稀疏数据大小 (sparse_data_size_):** 记录稀疏数据的大小。

5. **与后端和其他组件交互:**
   - **SimpleBackendImpl:** 与后端缓存实现进行交互，例如在条目被删除时通知后端，或者获取最大文件大小等信息。
   - **SimpleSynchronousEntry:**  负责实际的磁盘文件操作，例如创建、打开、读取和写入文件。
   - **SimpleIndex:** 与缓存索引进行交互，例如在创建和删除条目时更新索引。
   - **SimpleFileTracker:**  跟踪缓存使用的文件。
   - **BackendCleanupTracker:** 参与缓存清理过程。
   - **NetLog:**  用于记录缓存操作的日志，方便调试。

6. **错误处理:**  通过返回 `net::Error` 代码来指示操作的成功或失败。

**与 JavaScript 的关系 (及举例说明):**

`simple_entry_impl.cc` 本身不直接包含任何 JavaScript 代码或直接执行 JavaScript。然而，它在 Chromium 网络栈中扮演着关键角色，而网络栈是浏览器与服务器进行通信的基础。当 JavaScript 代码发起网络请求时（例如，通过 `fetch` API 或加载网页资源），这些请求可能会导致数据被缓存到磁盘。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 请求一个图片资源：

```javascript
fetch('https://example.com/image.png')
  .then(response => response.blob())
  .then(blob => {
    // 处理图片数据
  });
```

当浏览器处理这个请求时，如果启用了磁盘缓存，网络栈可能会将下载的图片数据存储到缓存中。`SimpleEntryImpl` 负责管理这个缓存条目的生命周期和数据存储：

1. 如果这是第一次请求该图片，`CreateEntry` 或 `OpenOrCreateEntry` 可能会被调用来创建一个新的缓存条目。
2. `WriteData` 会被调用来将图片数据写入到缓存条目的数据流中。
3. 后续对同一图片的请求，`OpenEntry` 会被调用来打开已存在的缓存条目。
4. `ReadData` 会被调用来从缓存条目中读取图片数据，而无需再次从服务器下载。

**逻辑推理 (假设输入与输出):**

**场景:**  尝试打开一个不存在的缓存条目。

**假设输入:**
- `entry_hash_`:  一个代表要打开的缓存条目的哈希值。
- 缓存后端 (`backend_`) 的索引 (`index()`) 中不包含 `entry_hash_` 对应的条目。

**逻辑推理过程:**

1. `OpenEntry` 函数被调用。
2. `ComputeIndexState` 函数检查后端索引，发现 `entry_hash_` 不存在 (`INDEX_MISS`)。
3. `RecordOpenEntryIndexState` 记录索引状态。
4. 由于条目不在索引中，`OpenEntry` 直接返回一个错误结果 `EntryResult::MakeError(net::ERR_FAILED)`。
5. `net_log_` 记录打开操作失败。

**预期输出:**
- `OpenEntry` 函数返回 `EntryResult` 对象，其中 `net_error()` 为 `net::ERR_FAILED`。
- 没有进一步的磁盘 I/O 操作会被触发。
- 回调函数会收到一个表示失败的结果。

**用户或编程常见的使用错误 (举例说明):**

1. **尝试在条目关闭后进行读写操作:**
   - **错误场景:**  用户获取了一个 `SimpleEntryImpl` 对象，调用 `Close()` 关闭了它，然后尝试调用 `ReadData()` 或 `WriteData()`。
   - **可能结果:**  由于 `Close()` 可能会释放与条目相关的资源，后续的读写操作可能会失败，或者导致程序崩溃。开发人员应该确保在条目关闭后不再使用该条目对象。

2. **使用错误的偏移量或长度进行读写操作:**
   - **错误场景:**  调用 `ReadData()` 或 `WriteData()` 时，提供的 `offset` 或 `buf_len` 超出了数据流的实际大小或导致越界访问。
   - **可能结果:**  读操作可能会读取到无效数据，写操作可能会导致数据损坏或程序崩溃。`SimpleEntryImpl` 内部会进行一些检查，返回 `net::ERR_INVALID_ARGUMENT`，但开发者应该在调用前确保参数的有效性。

3. **在异步操作未完成时就释放条目对象:**
   - **错误场景:**  发起了一个异步的读写操作，但没有等待回调完成就释放了 `SimpleEntryImpl` 对象。
   - **可能结果:**  可能会导致回调函数无法执行，或者在回调函数执行时访问了无效的内存，导致程序崩溃。应该保持 `SimpleEntryImpl` 对象在异步操作完成前有效。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一个典型的用户操作流程，可能会涉及到 `simple_entry_impl.cc`:

1. **用户在浏览器中输入网址或点击链接:**  例如，访问 `https://www.example.com/index.html`。
2. **浏览器发起网络请求:**  网络栈开始处理该请求。
3. **检查缓存:** 网络栈的缓存模块（例如 `SimpleCache`) 会检查本地磁盘缓存中是否已经存在该 URL 对应的资源。
4. **计算缓存键:**  根据 URL 和其他请求信息计算出缓存条目的键 (`key_`) 和哈希值 (`entry_hash_`)。
5. **尝试打开缓存条目:** `SimpleCache` 可能会调用 `SimpleEntryImpl::OpenEntry` 或 `SimpleEntryImpl::OpenOrCreateEntry`，传入计算出的 `entry_hash_`。
6. **索引查找:** `SimpleEntryImpl` 内部会查询 `SimpleIndex`，检查该 `entry_hash_` 是否存在。
7. **磁盘操作:**
   - **如果缓存命中:** `SimpleSynchronousEntry::OpenEntry` 被调用，从磁盘加载缓存条目的数据和元数据。`ReadData` 被调用来读取数据。
   - **如果缓存未命中:** `SimpleSynchronousEntry::CreateEntry` 被调用，在磁盘上创建新的缓存文件。当服务器返回响应时，`WriteData` 被调用来写入数据。
8. **数据返回:**  读取到的缓存数据或新写入的数据被传递回网络栈的其他部分，最终传递给渲染引擎，用于显示网页。

**调试线索:**

当调试网络缓存相关问题时，可以关注以下线索：

- **NetLog:**  Chromium 的 NetLog (通过 `chrome://net-export/`) 记录了详细的网络事件，包括缓存操作。可以查看与 `SIMPLE_CACHE_ENTRY` 相关的事件，了解缓存条目的创建、打开、读写等操作是否按预期进行。
- **断点调试:** 在 `simple_entry_impl.cc` 的关键函数（如 `OpenEntry`, `CreateEntry`, `ReadData`, `WriteData`) 设置断点，可以跟踪代码的执行流程，查看缓存条目的状态和数据。
- **缓存索引:**  检查缓存索引 (`SimpleIndex`) 的状态，确认缓存条目是否被正确地添加到索引中，以及索引中的元数据是否正确。
- **磁盘文件:**  检查磁盘上缓存文件的内容和元数据，确认数据是否被正确写入。

**这是第1部分，共3部分，请归纳一下它的功能:**

总而言之，`net/disk_cache/simple/simple_entry_impl.cc` 的主要功能是**实现简单磁盘缓存中单个缓存条目的管理，包括其生命周期控制、数据读写操作、状态维护以及与后端存储和索引的交互。** 它为 Chromium 网络栈提供了高效的缓存机制，优化了网络资源的加载速度。

### 提示词
```
这是目录为net/disk_cache/simple/simple_entry_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/disk_cache/simple/simple_entry_impl.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/prioritized_task_runner.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/net_log_parameters.h"
#include "net/disk_cache/simple/simple_backend_impl.h"
#include "net/disk_cache/simple/simple_histogram_enums.h"
#include "net/disk_cache/simple/simple_histogram_macros.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/disk_cache/simple/simple_net_log_parameters.h"
#include "net/disk_cache/simple/simple_synchronous_entry.h"
#include "net/disk_cache/simple/simple_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_source_type.h"
#include "third_party/zlib/zlib.h"

namespace disk_cache {
namespace {

// An entry can store sparse data taking up to 1 / kMaxSparseDataSizeDivisor of
// the cache.
const int64_t kMaxSparseDataSizeDivisor = 10;

OpenEntryIndexEnum ComputeIndexState(SimpleBackendImpl* backend,
                                     uint64_t entry_hash) {
  if (!backend->index()->initialized())
    return INDEX_NOEXIST;
  if (backend->index()->Has(entry_hash))
    return INDEX_HIT;
  return INDEX_MISS;
}

void RecordOpenEntryIndexState(net::CacheType cache_type,
                               OpenEntryIndexEnum state) {
  SIMPLE_CACHE_UMA(ENUMERATION, "OpenEntryIndexState", cache_type, state,
                   INDEX_MAX);
}

void RecordHeaderSize(net::CacheType cache_type, int size) {
  SIMPLE_CACHE_UMA(COUNTS_10000, "HeaderSize", cache_type, size);
}

void InvokeCallbackIfBackendIsAlive(
    const base::WeakPtr<SimpleBackendImpl>& backend,
    net::CompletionOnceCallback completion_callback,
    int result) {
  DCHECK(!completion_callback.is_null());
  if (!backend.get())
    return;
  std::move(completion_callback).Run(result);
}

void InvokeEntryResultCallbackIfBackendIsAlive(
    const base::WeakPtr<SimpleBackendImpl>& backend,
    EntryResultCallback completion_callback,
    EntryResult result) {
  DCHECK(!completion_callback.is_null());
  if (!backend.get())
    return;
  std::move(completion_callback).Run(std::move(result));
}

// If |sync_possible| is false, and callback is available, posts rv to it and
// return net::ERR_IO_PENDING; otherwise just passes through rv.
int PostToCallbackIfNeeded(bool sync_possible,
                           net::CompletionOnceCallback callback,
                           int rv) {
  if (!sync_possible && !callback.is_null()) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(callback), rv));
    return net::ERR_IO_PENDING;
  } else {
    return rv;
  }
}

}  // namespace

using base::OnceClosure;
using base::FilePath;
using base::Time;
using base::TaskRunner;

// A helper class to insure that RunNextOperationIfNeeded() is called when
// exiting the current stack frame.
class SimpleEntryImpl::ScopedOperationRunner {
 public:
  explicit ScopedOperationRunner(SimpleEntryImpl* entry) : entry_(entry) {
  }

  ~ScopedOperationRunner() {
    entry_->RunNextOperationIfNeeded();
  }

 private:
  const raw_ptr<SimpleEntryImpl> entry_;
};

SimpleEntryImpl::ActiveEntryProxy::~ActiveEntryProxy() = default;

SimpleEntryImpl::SimpleEntryImpl(
    net::CacheType cache_type,
    const FilePath& path,
    scoped_refptr<BackendCleanupTracker> cleanup_tracker,
    const uint64_t entry_hash,
    OperationsMode operations_mode,
    SimpleBackendImpl* backend,
    SimpleFileTracker* file_tracker,
    scoped_refptr<BackendFileOperationsFactory> file_operations_factory,
    net::NetLog* net_log,
    uint32_t entry_priority)
    : cleanup_tracker_(std::move(cleanup_tracker)),
      backend_(backend->AsWeakPtr()),
      file_tracker_(file_tracker),
      file_operations_factory_(std::move(file_operations_factory)),
      cache_type_(cache_type),
      path_(path),
      entry_hash_(entry_hash),
      use_optimistic_operations_(operations_mode == OPTIMISTIC_OPERATIONS),
      last_used_(Time::Now()),
      last_modified_(last_used_),
      prioritized_task_runner_(backend_->prioritized_task_runner()),
      net_log_(
          net::NetLogWithSource::Make(net_log,
                                      net::NetLogSourceType::DISK_CACHE_ENTRY)),
      stream_0_data_(base::MakeRefCounted<net::GrowableIOBuffer>()),
      entry_priority_(entry_priority) {
  static_assert(std::extent<decltype(data_size_)>() ==
                    std::extent<decltype(crc32s_end_offset_)>(),
                "arrays should be the same size");
  static_assert(
      std::extent<decltype(data_size_)>() == std::extent<decltype(crc32s_)>(),
      "arrays should be the same size");
  static_assert(std::extent<decltype(data_size_)>() ==
                    std::extent<decltype(have_written_)>(),
                "arrays should be the same size");
  ResetEntry();
  NetLogSimpleEntryConstruction(net_log_,
                                net::NetLogEventType::SIMPLE_CACHE_ENTRY,
                                net::NetLogEventPhase::BEGIN, this);
}

void SimpleEntryImpl::SetActiveEntryProxy(
    std::unique_ptr<ActiveEntryProxy> active_entry_proxy) {
  DCHECK(!active_entry_proxy_);
  active_entry_proxy_ = std::move(active_entry_proxy);
}

EntryResult SimpleEntryImpl::OpenEntry(EntryResultCallback callback) {
  DCHECK(backend_.get());

  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_CALL);

  OpenEntryIndexEnum index_state =
      ComputeIndexState(backend_.get(), entry_hash_);
  RecordOpenEntryIndexState(cache_type_, index_state);

  // If entry is not known to the index, initiate fast failover to the network.
  if (index_state == INDEX_MISS) {
    net_log_.AddEventWithNetErrorCode(
        net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_END, net::ERR_FAILED);
    return EntryResult::MakeError(net::ERR_FAILED);
  }

  pending_operations_.push(SimpleEntryOperation::OpenOperation(
      this, SimpleEntryOperation::ENTRY_NEEDS_CALLBACK, std::move(callback)));
  RunNextOperationIfNeeded();
  return EntryResult::MakeError(net::ERR_IO_PENDING);
}

EntryResult SimpleEntryImpl::CreateEntry(EntryResultCallback callback) {
  DCHECK(backend_.get());
  DCHECK_EQ(entry_hash_, simple_util::GetEntryHashKey(*key_));

  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_CREATE_CALL);

  EntryResult result = EntryResult::MakeError(net::ERR_IO_PENDING);
  if (use_optimistic_operations_ &&
      state_ == STATE_UNINITIALIZED && pending_operations_.size() == 0) {
    net_log_.AddEvent(
        net::NetLogEventType::SIMPLE_CACHE_ENTRY_CREATE_OPTIMISTIC);

    ReturnEntryToCaller();
    result = EntryResult::MakeCreated(this);
    pending_operations_.push(SimpleEntryOperation::CreateOperation(
        this, SimpleEntryOperation::ENTRY_ALREADY_RETURNED,
        EntryResultCallback()));

    // If we are optimistically returning before a preceeding doom, we need to
    // wait for that IO, about which we will be notified externally.
    if (optimistic_create_pending_doom_state_ != CREATE_NORMAL) {
      CHECK_EQ(CREATE_OPTIMISTIC_PENDING_DOOM,
               optimistic_create_pending_doom_state_);
      state_ = STATE_IO_PENDING;
    }
  } else {
    pending_operations_.push(SimpleEntryOperation::CreateOperation(
        this, SimpleEntryOperation::ENTRY_NEEDS_CALLBACK, std::move(callback)));
  }

  // We insert the entry in the index before creating the entry files in the
  // SimpleSynchronousEntry, because this way the worst scenario is when we
  // have the entry in the index but we don't have the created files yet, this
  // way we never leak files. CreationOperationComplete will remove the entry
  // from the index if the creation fails.
  backend_->index()->Insert(entry_hash_);

  RunNextOperationIfNeeded();
  return result;
}

EntryResult SimpleEntryImpl::OpenOrCreateEntry(EntryResultCallback callback) {
  DCHECK(backend_.get());
  DCHECK_EQ(entry_hash_, simple_util::GetEntryHashKey(*key_));

  net_log_.AddEvent(
      net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_OR_CREATE_CALL);

  OpenEntryIndexEnum index_state =
      ComputeIndexState(backend_.get(), entry_hash_);
  RecordOpenEntryIndexState(cache_type_, index_state);

  EntryResult result = EntryResult::MakeError(net::ERR_IO_PENDING);
  if (index_state == INDEX_MISS && use_optimistic_operations_ &&
      state_ == STATE_UNINITIALIZED && pending_operations_.size() == 0) {
    net_log_.AddEvent(
        net::NetLogEventType::SIMPLE_CACHE_ENTRY_CREATE_OPTIMISTIC);

    ReturnEntryToCaller();
    result = EntryResult::MakeCreated(this);
    pending_operations_.push(SimpleEntryOperation::OpenOrCreateOperation(
        this, index_state, SimpleEntryOperation::ENTRY_ALREADY_RETURNED,
        EntryResultCallback()));

    // The post-doom stuff should go through CreateEntry, not here.
    CHECK_EQ(CREATE_NORMAL, optimistic_create_pending_doom_state_);
  } else {
    pending_operations_.push(SimpleEntryOperation::OpenOrCreateOperation(
        this, index_state, SimpleEntryOperation::ENTRY_NEEDS_CALLBACK,
        std::move(callback)));
  }

  // We insert the entry in the index before creating the entry files in the
  // SimpleSynchronousEntry, because this way the worst scenario is when we
  // have the entry in the index but we don't have the created files yet, this
  // way we never leak files. CreationOperationComplete will remove the entry
  // from the index if the creation fails.
  backend_->index()->Insert(entry_hash_);

  RunNextOperationIfNeeded();
  return result;
}

net::Error SimpleEntryImpl::DoomEntry(net::CompletionOnceCallback callback) {
  if (doom_state_ != DOOM_NONE)
    return net::OK;
  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_DOOM_CALL);
  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_DOOM_BEGIN);

  MarkAsDoomed(DOOM_QUEUED);
  if (backend_.get()) {
    if (optimistic_create_pending_doom_state_ == CREATE_NORMAL) {
      post_doom_waiting_ = backend_->OnDoomStart(entry_hash_);
    } else {
      CHECK_EQ(STATE_IO_PENDING, state_);
      CHECK_EQ(CREATE_OPTIMISTIC_PENDING_DOOM,
               optimistic_create_pending_doom_state_);
      // If we are in this state, we went ahead with making the entry even
      // though the backend was already keeping track of a doom, so it can't
      // keep track of ours. So we delay notifying it until
      // NotifyDoomBeforeCreateComplete is called.  Since this path is invoked
      // only when the queue of post-doom callbacks was previously empty, while
      // the CompletionOnceCallback for the op is posted,
      // NotifyDoomBeforeCreateComplete() will be the first thing running after
      // the previous doom completes, so at that point we can immediately grab
      // a spot in entries_pending_doom_.
      optimistic_create_pending_doom_state_ =
          CREATE_OPTIMISTIC_PENDING_DOOM_FOLLOWED_BY_DOOM;
    }
  }
  pending_operations_.push(
      SimpleEntryOperation::DoomOperation(this, std::move(callback)));
  RunNextOperationIfNeeded();
  return net::ERR_IO_PENDING;
}

void SimpleEntryImpl::SetCreatePendingDoom() {
  CHECK_EQ(CREATE_NORMAL, optimistic_create_pending_doom_state_);
  optimistic_create_pending_doom_state_ = CREATE_OPTIMISTIC_PENDING_DOOM;
}

void SimpleEntryImpl::NotifyDoomBeforeCreateComplete() {
  CHECK_EQ(STATE_IO_PENDING, state_);
  CHECK_NE(CREATE_NORMAL, optimistic_create_pending_doom_state_);
  if (backend_.get() && optimistic_create_pending_doom_state_ ==
                            CREATE_OPTIMISTIC_PENDING_DOOM_FOLLOWED_BY_DOOM)
    post_doom_waiting_ = backend_->OnDoomStart(entry_hash_);

  state_ = STATE_UNINITIALIZED;
  optimistic_create_pending_doom_state_ = CREATE_NORMAL;
  RunNextOperationIfNeeded();
}

void SimpleEntryImpl::SetKey(const std::string& key) {
  key_ = key;
  net_log_.AddEventWithStringParams(
      net::NetLogEventType::SIMPLE_CACHE_ENTRY_SET_KEY, "key", key);
}

void SimpleEntryImpl::Doom() {
  DoomEntry(CompletionOnceCallback());
}

void SimpleEntryImpl::Close() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_LT(0, open_count_);

  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_CLOSE_CALL);

  if (--open_count_ > 0) {
    DCHECK(!HasOneRef());
    Release();  // Balanced in ReturnEntryToCaller().
    return;
  }

  pending_operations_.push(SimpleEntryOperation::CloseOperation(this));
  DCHECK(!HasOneRef());
  Release();  // Balanced in ReturnEntryToCaller().
  RunNextOperationIfNeeded();
}

std::string SimpleEntryImpl::GetKey() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return *key_;
}

Time SimpleEntryImpl::GetLastUsed() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(cache_type_ != net::APP_CACHE);
  return last_used_;
}

Time SimpleEntryImpl::GetLastModified() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return last_modified_;
}

int32_t SimpleEntryImpl::GetDataSize(int stream_index) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_LE(0, data_size_[stream_index]);
  return data_size_[stream_index];
}

int SimpleEntryImpl::ReadData(int stream_index,
                              int offset,
                              net::IOBuffer* buf,
                              int buf_len,
                              CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (net_log_.IsCapturing()) {
    NetLogReadWriteData(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_CALL,
        net::NetLogEventPhase::NONE, stream_index, offset, buf_len, false);
  }

  if (stream_index < 0 || stream_index >= kSimpleEntryStreamCount ||
      buf_len < 0) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_END,
          net::NetLogEventPhase::NONE, net::ERR_INVALID_ARGUMENT);
    }

    return net::ERR_INVALID_ARGUMENT;
  }

  // If this is the only operation, bypass the queue, and also see if there is
  // in-memory data to handle it synchronously. In principle, multiple reads can
  // be parallelized, but past studies have shown that parallelizable ones
  // happen <1% of the time, so it's probably not worth the effort.
  bool alone_in_queue =
      pending_operations_.size() == 0 && state_ == STATE_READY;

  if (alone_in_queue) {
    return ReadDataInternal(/*sync_possible = */ true, stream_index, offset,
                            buf, buf_len, std::move(callback));
  }

  pending_operations_.push(SimpleEntryOperation::ReadOperation(
      this, stream_index, offset, buf_len, buf, std::move(callback)));
  RunNextOperationIfNeeded();
  return net::ERR_IO_PENDING;
}

int SimpleEntryImpl::WriteData(int stream_index,
                               int offset,
                               net::IOBuffer* buf,
                               int buf_len,
                               CompletionOnceCallback callback,
                               bool truncate) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (net_log_.IsCapturing()) {
    NetLogReadWriteData(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_CALL,
        net::NetLogEventPhase::NONE, stream_index, offset, buf_len, truncate);
  }

  if (stream_index < 0 || stream_index >= kSimpleEntryStreamCount ||
      offset < 0 || buf_len < 0) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_END,
          net::NetLogEventPhase::NONE, net::ERR_INVALID_ARGUMENT);
    }
    return net::ERR_INVALID_ARGUMENT;
  }
  int end_offset;
  if (!base::CheckAdd(offset, buf_len).AssignIfValid(&end_offset) ||
      (backend_.get() && end_offset > backend_->MaxFileSize())) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_END,
          net::NetLogEventPhase::NONE, net::ERR_FAILED);
    }
    return net::ERR_FAILED;
  }
  ScopedOperationRunner operation_runner(this);

  // Stream 0 data is kept in memory, so can be written immediatly if there are
  // no IO operations pending.
  if (stream_index == 0 && state_ == STATE_READY &&
      pending_operations_.size() == 0) {
    state_ = STATE_IO_PENDING;
    SetStream0Data(buf, offset, buf_len, truncate);
    state_ = STATE_READY;
    return buf_len;
  }

  // We can only do optimistic Write if there is no pending operations, so
  // that we are sure that the next call to RunNextOperationIfNeeded will
  // actually run the write operation that sets the stream size. It also
  // prevents from previous possibly-conflicting writes that could be stacked
  // in the |pending_operations_|. We could optimize this for when we have
  // only read operations enqueued, but past studies have shown that that such
  // parallelizable cases are very rare.
  const bool optimistic =
      (use_optimistic_operations_ && state_ == STATE_READY &&
       pending_operations_.size() == 0);
  CompletionOnceCallback op_callback;
  scoped_refptr<net::IOBuffer> op_buf;
  int ret_value = net::ERR_FAILED;
  if (!optimistic) {
    op_buf = buf;
    op_callback = std::move(callback);
    ret_value = net::ERR_IO_PENDING;
  } else {
    // TODO(morlovich,pasko): For performance, don't use a copy of an IOBuffer
    // here to avoid paying the price of the RefCountedThreadSafe atomic
    // operations.
    if (buf) {
      op_buf = base::MakeRefCounted<net::IOBufferWithSize>(buf_len);
      std::copy(buf->data(), buf->data() + buf_len, op_buf->data());
    }
    op_callback = CompletionOnceCallback();
    ret_value = buf_len;
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_OPTIMISTIC,
          net::NetLogEventPhase::NONE, buf_len);
    }
  }

  pending_operations_.push(SimpleEntryOperation::WriteOperation(
      this, stream_index, offset, buf_len, op_buf.get(), truncate, optimistic,
      std::move(op_callback)));
  return ret_value;
}

int SimpleEntryImpl::ReadSparseData(int64_t offset,
                                    net::IOBuffer* buf,
                                    int buf_len,
                                    CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (net_log_.IsCapturing()) {
    NetLogSparseOperation(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_SPARSE_CALL,
        net::NetLogEventPhase::NONE, offset, buf_len);
  }

  if (offset < 0 || buf_len < 0) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_READ_SPARSE_END,
          net::NetLogEventPhase::NONE, net::ERR_INVALID_ARGUMENT);
    }
    return net::ERR_INVALID_ARGUMENT;
  }

  // Truncate |buf_len| to make sure that |offset + buf_len| does not overflow.
  // This is OK since one can't write that far anyway.
  // The result of std::min is guaranteed to fit into int since |buf_len| did.
  buf_len = std::min(static_cast<int64_t>(buf_len),
                     std::numeric_limits<int64_t>::max() - offset);

  ScopedOperationRunner operation_runner(this);
  pending_operations_.push(SimpleEntryOperation::ReadSparseOperation(
      this, offset, buf_len, buf, std::move(callback)));
  return net::ERR_IO_PENDING;
}

int SimpleEntryImpl::WriteSparseData(int64_t offset,
                                     net::IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (net_log_.IsCapturing()) {
    NetLogSparseOperation(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_SPARSE_CALL,
        net::NetLogEventPhase::NONE, offset, buf_len);
  }

  if (offset < 0 || buf_len < 0 || !base::CheckAdd(offset, buf_len).IsValid()) {
    if (net_log_.IsCapturing()) {
      NetLogReadWriteComplete(
          net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_WRITE_SPARSE_END,
          net::NetLogEventPhase::NONE, net::ERR_INVALID_ARGUMENT);
    }
    return net::ERR_INVALID_ARGUMENT;
  }

  ScopedOperationRunner operation_runner(this);
  pending_operations_.push(SimpleEntryOperation::WriteSparseOperation(
      this, offset, buf_len, buf, std::move(callback)));
  return net::ERR_IO_PENDING;
}

RangeResult SimpleEntryImpl::GetAvailableRange(int64_t offset,
                                               int len,
                                               RangeResultCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (offset < 0 || len < 0)
    return RangeResult(net::ERR_INVALID_ARGUMENT);

  // Truncate |len| to make sure that |offset + len| does not overflow.
  // This is OK since one can't write that far anyway.
  // The result of std::min is guaranteed to fit into int since |len| did.
  len = std::min(static_cast<int64_t>(len),
                 std::numeric_limits<int64_t>::max() - offset);

  ScopedOperationRunner operation_runner(this);
  pending_operations_.push(SimpleEntryOperation::GetAvailableRangeOperation(
      this, offset, len, std::move(callback)));
  return RangeResult(net::ERR_IO_PENDING);
}

bool SimpleEntryImpl::CouldBeSparse() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // TODO(morlovich): Actually check.
  return true;
}

void SimpleEntryImpl::CancelSparseIO() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // The Simple Cache does not return distinct objects for the same non-doomed
  // entry, so there's no need to coordinate which object is performing sparse
  // I/O.  Therefore, CancelSparseIO and ReadyForSparseIO succeed instantly.
}

net::Error SimpleEntryImpl::ReadyForSparseIO(CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // The simple Cache does not return distinct objects for the same non-doomed
  // entry, so there's no need to coordinate which object is performing sparse
  // I/O.  Therefore, CancelSparseIO and ReadyForSparseIO succeed instantly.
  return net::OK;
}

void SimpleEntryImpl::SetLastUsedTimeForTest(base::Time time) {
  last_used_ = time;
  backend_->index()->SetLastUsedTimeForTest(entry_hash_, time);
}

void SimpleEntryImpl::SetPriority(uint32_t entry_priority) {
  entry_priority_ = entry_priority;
}

SimpleEntryImpl::~SimpleEntryImpl() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(0U, pending_operations_.size());

  // This used to DCHECK on `state_`, but it turns out that destruction
  // happening on thread shutdown, when closures holding `this` get deleted
  // can happen in circumstances not possible during normal use, such as when
  // I/O for Close operation is keeping the entry alive in STATE_IO_PENDING, or
  // an entry that's STATE_READY has callbacks pending to hand it over to the
  // user right as the thread is shutdown (this would also have a non-null
  // `synchronous_entry_`).
  net_log_.EndEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY);
}

void SimpleEntryImpl::PostClientCallback(net::CompletionOnceCallback callback,
                                         int result) {
  if (callback.is_null())
    return;
  // Note that the callback is posted rather than directly invoked to avoid
  // reentrancy issues.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&InvokeCallbackIfBackendIsAlive, backend_,
                                std::move(callback), result));
}

void SimpleEntryImpl::PostClientCallback(EntryResultCallback callback,
                                         EntryResult result) {
  if (callback.is_null())
    return;
  // Note that the callback is posted rather than directly invoked to avoid
  // reentrancy issues.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&InvokeEntryResultCallbackIfBackendIsAlive, backend_,
                     std::move(callback), std::move(result)));
}

void SimpleEntryImpl::ResetEntry() {
  // If we're doomed, we can't really do anything else with the entry, since
  // we no longer own the name and are disconnected from the active entry table.
  // We preserve doom_state_ accross this entry for this same reason.
  state_ = doom_state_ == DOOM_COMPLETED ? STATE_FAILURE : STATE_UNINITIALIZED;
  std::memset(crc32s_end_offset_, 0, sizeof(crc32s_end_offset_));
  std::memset(crc32s_, 0, sizeof(crc32s_));
  std::memset(have_written_, 0, sizeof(have_written_));
  std::memset(data_size_, 0, sizeof(data_size_));
}

void SimpleEntryImpl::ReturnEntryToCaller() {
  DCHECK(backend_);
  ++open_count_;
  AddRef();  // Balanced in Close()
}

void SimpleEntryImpl::ReturnEntryToCallerAsync(bool is_open,
                                               EntryResultCallback callback) {
  DCHECK(!callback.is_null());

  // |open_count_| must be incremented immediately, so that a Close on an alias
  // doesn't try to wrap things up.
  ++open_count_;

  // Note that the callback is posted rather than directly invoked to avoid
  // reentrancy issues.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&SimpleEntryImpl::FinishReturnEntryToCallerAsync, this,
                     is_open, std::move(callback)));
}

void SimpleEntryImpl::FinishReturnEntryToCallerAsync(
    bool is_open,
    EntryResultCallback callback) {
  AddRef();  // Balanced in Close()
  if (!backend_.get()) {
    // With backend dead, Open/Create operations are responsible for cleaning up
    // the entry --- the ownership is never transferred to the caller, and their
    // callback isn't invoked.
    Close();
    return;
  }

  std::move(callback).Run(is_open ? EntryResult::MakeOpened(this)
                                  : EntryResult::MakeCreated(this));
}

void SimpleEntryImpl::MarkAsDoomed(DoomState new_state) {
  DCHECK_NE(DOOM_NONE, new_state);
  doom_state_ = new_state;
  if (!backend_.get())
    return;
  backend_->index()->Remove(entry_hash_);
  active_entry_proxy_.reset();
}

void SimpleEntryImpl::RunNextOperationIfNeeded() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!pending_operations_.empty() && state_ != STATE_IO_PENDING) {
    SimpleEntryOperation operation = std::move(pending_operations_.front());
    pending_operations_.pop();
    switch (operation.type()) {
      case SimpleEntryOperation::TYPE_OPEN:
        OpenEntryInternal(operation.entry_result_state(),
                          operation.ReleaseEntryResultCallback());
        break;
      case SimpleEntryOperation::TYPE_CREATE:
        CreateEntryInternal(operation.entry_result_state(),
                            operation.ReleaseEntryResultCallback());
        break;
      case SimpleEntryOperation::TYPE_OPEN_OR_CREATE:
        OpenOrCreateEntryInternal(operation.index_state(),
                                  operation.entry_result_state(),
                                  operation.ReleaseEntryResultCallback());
        break;
      case SimpleEntryOperation::TYPE_CLOSE:
        CloseInternal();
        break;
      case SimpleEntryOperation::TYPE_READ:
        ReadDataInternal(/* sync_possible= */ false, operation.index(),
                         operation.offset(), operation.buf(),
                         operation.length(), operation.ReleaseCallback());
        break;
      case SimpleEntryOperation::TYPE_WRITE:
        WriteDataInternal(operation.index(), operation.offset(),
                          operation.buf(), operation.length(),
                          operation.ReleaseCallback(), operation.truncate());
        break;
      case SimpleEntryOperation::TYPE_READ_SPARSE:
        ReadSparseDataInternal(operation.sparse_offset(), operation.buf(),
                               operation.length(), operation.ReleaseCallback());
        break;
      case SimpleEntryOperation::TYPE_WRITE_SPARSE:
        WriteSparseDataInternal(operation.sparse_offset(), operation.buf(),
                                operation.length(),
                                operation.ReleaseCallback());
        break;
      case SimpleEntryOperation::TYPE_GET_AVAILABLE_RANGE:
        GetAvailableRangeInternal(operation.sparse_offset(), operation.length(),
                                  operation.ReleaseRangeResultCalback());
        break;
      case SimpleEntryOperation::TYPE_DOOM:
        DoomEntryInternal(operation.ReleaseCallback());
        break;
      default:
        NOTREACHED();
    }
    // |this| may have been deleted.
  }
}

void SimpleEntryImpl::OpenEntryInternal(
    SimpleEntryOperation::EntryResultState result_state,
    EntryResultCallback callback) {
  ScopedOperationRunner operation_runner(this);

  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_BEGIN);

  // No optimistic sync return possible on open.
  DCHECK_EQ(SimpleEntryOperation::ENTRY_NEEDS_CALLBACK, result_state);

  if (state_ == STATE_READY) {
    ReturnEntryToCallerAsync(/* is_open = */ true, std::move(callback));
    NetLogSimpleEntryCreation(net_log_,
                              net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_END,
                              net::NetLogEventPhase::NONE, this, net::OK);
    return;
  }
  if (state_ == STATE_FAILURE) {
    PostClientCallback(std::move(callback),
                       EntryResult::MakeError(net::ERR_FAILED));
    NetLogSimpleEntryCreation(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_END,
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

  base::OnceClosure task = base::BindOnce(
      &SimpleSynchronousEntry::OpenEntry, cache_type_, path_, key_, entry_hash_,
      file_tracker_, file_operations_factory_->CreateUnbound(),
      trailer_prefetch_size, results.get());

  base::OnceClosure reply = base::BindOnce(
      &SimpleEntryImpl::CreationOperationComplete, this, result_state,
      std::move(callback), start_time, last_used_time, std::move(results),
      net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_END);

  prioritized_task_runner_->PostTaskAndReply(FROM_HERE, std::move(task),
                                             std::move(reply), entry_priority_);
}

void SimpleEntryImpl::CreateEntryInternal(
    SimpleEntryOperation::EntryResultState result_state,
    EntryResultCallback callback) {
  ScopedOperationRunner operation_runner(this);

  net_log_.AddEvent(net::NetLogEventType::SIMPLE_CACHE_ENTRY_CREATE_BEGIN);

  if (state_ != STATE_UNINITIALIZED) {
    // There is already an active normal entry.
    NetLogSimpleEntryCreation(
        net_log_, net::NetLogEventType::SIMPLE_CACHE_ENTRY_CREATE_END,
        net::NetLogEventPhase::NONE, this, net::ERR_FAILED);
    // If we have optimistically returned an entry, we would be the first entry
    // in queue with state_ == STATE_UNINITIALIZED.
    DCHECK_EQ(SimpleEntryOperation::ENTRY_NEEDS_CALLBACK, result_state);
    PostClientCallback(std::move(callback),
                       EntryResult::MakeError(net::ERR_FAILED));
    return;
  }
  DCHECK_EQ(STATE_UNINITIALIZED, state_);
  DCHECK(!synchronous_entry_);

  state_ = STATE_IO_PENDING;

  // Since we don't know the correct values for |last_used_| and
  // |last_modified_| yet, we make thi
```