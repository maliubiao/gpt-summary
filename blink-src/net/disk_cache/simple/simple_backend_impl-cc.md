Response:
The user wants a summary of the functionality of the `simple_backend_impl.cc` file, focusing on potential JavaScript interaction, logical inferences, common user errors, and debugging tips.

**Plan:**

1. **Functionality Summary:**  Analyze the code to identify its core responsibilities within the Chromium network stack's disk cache. Keywords like "backend," "entry," "index," "file operations," and "doom" suggest key areas.
2. **JavaScript Relationship:** Consider how a disk cache might interact with JavaScript. This likely involves caching resources fetched by JavaScript (e.g., scripts, images, data). Look for code elements related to HTTP requests or resource loading.
3. **Logical Inference (Hypothetical Input/Output):**  Choose a key function (e.g., `OpenEntry`) and imagine a scenario with input parameters and the expected output (success, failure, entry data).
4. **User/Programming Errors:** Think about common mistakes developers or users might make that would lead to interactions with this code (e.g., cache corruption, incorrect settings, exceeding limits).
5. **User Operation to Code Path:**  Outline a typical user action in a browser and trace how it might lead to execution within `simple_backend_impl.cc`.
6. **Concise Summary (for Part 1):**  Synthesize the identified functionalities into a brief overview.
这是 Chromium 网络栈中简单缓存后端的实现文件 `simple_backend_impl.cc` 的第一部分。根据提供的代码，我们可以归纳出以下功能：

**核心功能：简单磁盘缓存的后端实现**

* **缓存条目的管理：**
    * **创建、打开、删除缓存条目 (Entries):**  实现了 `OpenEntry`、`CreateEntry`、`OpenOrCreateEntry` 和 `DoomEntry` 等方法来管理缓存中的条目。
    * **查找缓存条目:** 通过键 (key) 的哈希值来查找和管理缓存条目。
    * **活跃条目跟踪:**  维护一个 `active_entries_` 映射表，跟踪当前正在被使用的缓存条目，以避免并发操作冲突。
    * **待删除条目队列:**  使用 `post_doom_waiting_` 跟踪待删除的条目，确保在删除操作完成前不会被新的请求干扰。
    * **乐观创建:**  在某些情况下 (例如，条目正在被删除但还没有完成)，允许乐观地创建新条目。
* **缓存索引的管理:**
    * **使用 `SimpleIndex`:**  依赖 `SimpleIndex` 组件来管理缓存的索引，包括条目的创建、查找、删除以及过期等。
    * **索引持久化:**  通过 `SimpleIndexFile` 将索引信息持久化到磁盘。
    * **索引加载和初始化:**  在 `Init` 方法中加载和初始化缓存索引。
    * **索引一致性检查:**  在启动时检查缓存目录的结构一致性，并尝试修复或重新创建索引。
* **磁盘空间管理:**
    * **设置最大缓存大小:**  根据配置或可用磁盘空间设置缓存的最大大小。
    * **计算条目大小:**  提供方法 `CalculateSizeOfAllEntries` 和 `CalculateSizeOfEntriesBetween` 来计算缓存中条目的大小。
    * **限制单个文件大小:**  定义了 `kMaxFileRatio` 和 `kMinFileSizeLimit` 来限制单个缓存条目占用的最大空间。
* **缓存条目的删除 (Dooming):**
    * **根据键删除:**  `DoomEntry` 方法根据键来删除特定的缓存条目。
    * **批量删除:**  `DoomEntries` 方法可以批量删除指定的缓存条目。
    * **根据时间范围删除:**  `DoomEntriesBetween` 和 `DoomEntriesSince` 方法允许根据条目的创建或修改时间来删除缓存。
* **缓存迭代器:**
    * **提供 `CreateIterator`:**  允许遍历缓存中的所有条目。
* **统计信息:**
    * **`GetStats`:** 提供方法来获取缓存的统计信息。
* **文件操作抽象:**
    * **使用 `BackendFileOperations`:**  抽象了底层的磁盘文件操作，方便进行测试和不同平台的支持。
    * **全局文件跟踪:**  使用 `SimpleFileTracker` 跟踪打开的文件，以避免超过文件描述符限制。
* **后台清理:**
    * **`BackendCleanupTracker`:**  集成后台清理机制。

**与 JavaScript 的关系：**

这个 C++ 代码直接处理的是磁盘缓存的底层实现，JavaScript 本身无法直接操作这个层面的缓存。然而，当浏览器加载网页资源时（例如，通过 `<script>` 标签加载 JavaScript 文件，或者通过 `fetch` API 请求数据），网络栈会检查磁盘缓存中是否存在这些资源。

**举例说明:**

1. **JavaScript 发起网络请求:**  一个 JavaScript 脚本使用 `fetch('https://example.com/data.json')` 发起一个网络请求。
2. **缓存查找:**  Chromium 的网络栈会首先检查磁盘缓存（这里就是 `simple_backend_impl.cc` 管理的缓存）中是否存在 `https://example.com/data.json` 对应的缓存条目。
3. **缓存命中:**  如果缓存命中，`simple_backend_impl.cc` 中的相关代码会找到对应的缓存条目，读取数据，并返回给网络栈。
4. **数据返回给 JavaScript:**  网络栈将缓存中的数据返回给 JavaScript 的 `fetch` API 的 Promise。

**逻辑推理 (假设输入与输出):**

假设我们调用 `OpenEntry("my_resource", ...)`：

* **假设输入:**
    * `key`: "my_resource"
    * 缓存中存在键为 "my_resource" 的有效条目。
* **预期输出:**
    * `OpenEntry` 方法成功返回，并通过回调函数提供一个可以访问缓存条目的对象 (例如，`SimpleEntryImpl`)。

假设我们调用 `CreateEntry("new_resource", ...)`：

* **假设输入:**
    * `key`: "new_resource"
    * 缓存中不存在键为 "new_resource" 的条目。
* **预期输出:**
    * `CreateEntry` 方法成功返回，并通过回调函数提供一个新创建的缓存条目对象。

**用户或编程常见的使用错误：**

1. **缓存目录权限问题:** 用户或程序可能没有足够的权限访问或修改缓存目录，导致缓存初始化或操作失败。
   * **例子:**  在 Linux 系统中，如果缓存目录的权限被设置为只有 root 用户可写，普通用户运行 Chromium 时可能无法创建或修改缓存文件。
2. **磁盘空间不足:**  当磁盘空间不足时，缓存可能无法创建新的条目或扩展现有条目，导致请求失败或性能下降。
   * **例子:** 用户硬盘空间几乎耗尽，浏览器尝试缓存一个大型文件时可能会失败。
3. **缓存大小设置不合理:**  管理员或用户可能设置了过小的缓存大小，导致频繁的缓存淘汰，降低缓存命中率。
   * **例子:**  企业管理员为了节省服务器磁盘空间，将浏览器缓存大小设置得非常小。
4. **并发操作不当:**  虽然代码中已经有机制来处理并发，但在测试或某些极端情况下，仍然可能出现并发访问同一缓存条目的情况，如果处理不当可能导致数据损坏。
   * **例子:**  多个浏览器窗口同时请求相同的资源，并且缓存策略允许并发写入。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入网址或点击链接:** 这会触发一个网络请求。
2. **网络栈发起资源请求:** Chromium 的网络栈开始处理请求，首先会检查内存缓存。
3. **内存缓存未命中，检查磁盘缓存:** 如果内存缓存没有找到请求的资源，网络栈会查找磁盘缓存。
4. **调用 `SimpleCacheBackend::OpenEntry` 或类似方法:**  根据请求的资源和缓存策略，网络栈会调用 `simple_backend_impl.cc` 中的 `OpenEntry` 方法来查找或创建缓存条目。
5. **文件系统操作:** `simple_backend_impl.cc` 中的代码会通过 `BackendFileOperations` 与文件系统进行交互，查找或创建对应的缓存文件。
6. **数据返回或写入:** 如果缓存命中，数据会被读取并返回给网络栈。如果缓存未命中或需要更新，数据会被写入到缓存文件中。

**功能归纳 (针对第 1 部分):**

`simple_backend_impl.cc` 的第一部分主要负责**简单磁盘缓存后端的初始化、条目的查找和创建，以及初步的删除管理**。它定义了缓存的基本结构和管理接口，并与索引管理组件 (`SimpleIndex`) 和底层文件操作抽象层 (`BackendFileOperations`) 进行了集成。  这部分代码的核心目标是提供一个可靠和高效的机制来存储和检索网络资源到磁盘，从而提升浏览器的性能。

Prompt: 
```
这是目录为net/disk_cache/simple/simple_backend_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/simple/simple_backend_impl.h"

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <limits>

#include "base/functional/callback_helpers.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/thread_pool.h"
#include "build/build_config.h"

#if BUILDFLAG(IS_POSIX)
#include <sys/resource.h>
#endif

#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/system/sys_info.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/base/prioritized_task_runner.h"
#include "net/disk_cache/backend_cleanup_tracker.h"
#include "net/disk_cache/cache_util.h"
#include "net/disk_cache/simple/simple_entry_format.h"
#include "net/disk_cache/simple/simple_entry_impl.h"
#include "net/disk_cache/simple/simple_file_tracker.h"
#include "net/disk_cache/simple/simple_histogram_macros.h"
#include "net/disk_cache/simple/simple_index.h"
#include "net/disk_cache/simple/simple_index_file.h"
#include "net/disk_cache/simple/simple_synchronous_entry.h"
#include "net/disk_cache/simple/simple_util.h"
#include "net/disk_cache/simple/simple_version_upgrade.h"

using base::FilePath;
using base::Time;

namespace disk_cache {

namespace {

// Maximum fraction of the cache that one entry can consume.
const int kMaxFileRatio = 8;

// Native code entries can be large. Rather than increasing the overall cache
// size, allow an individual entry to occupy up to half of the cache.
const int kMaxNativeCodeFileRatio = 2;

// Overrides the above.
const int64_t kMinFileSizeLimit = 5 * 1024 * 1024;

// Global context of all the files we have open --- this permits some to be
// closed on demand if too many FDs are being used, to avoid running out.
base::LazyInstance<SimpleFileTracker>::Leaky g_simple_file_tracker =
    LAZY_INSTANCE_INITIALIZER;

// Detects if the files in the cache directory match the current disk cache
// backend type and version. If the directory contains no cache, occupies it
// with the fresh structure.
SimpleCacheConsistencyResult FileStructureConsistent(
    BackendFileOperations* file_operations,
    const base::FilePath& path) {
  if (!file_operations->PathExists(path) &&
      !file_operations->CreateDirectory(path)) {
    LOG(ERROR) << "Failed to create directory: " << path.LossyDisplayName();
    return SimpleCacheConsistencyResult::kCreateDirectoryFailed;
  }
  return disk_cache::UpgradeSimpleCacheOnDisk(file_operations, path);
}

// A context used by a BarrierCompletionCallback to track state.
struct BarrierContext {
  explicit BarrierContext(net::CompletionOnceCallback final_callback,
                          int expected)
      : final_callback_(std::move(final_callback)), expected(expected) {}

  net::CompletionOnceCallback final_callback_;
  const int expected;
  int count = 0;
  bool had_error = false;
};

void BarrierCompletionCallbackImpl(
    BarrierContext* context,
    int result) {
  DCHECK_GT(context->expected, context->count);
  if (context->had_error)
    return;
  if (result != net::OK) {
    context->had_error = true;
    std::move(context->final_callback_).Run(result);
    return;
  }
  ++context->count;
  if (context->count == context->expected)
    std::move(context->final_callback_).Run(net::OK);
}

// A barrier completion callback is a repeatable callback that waits for
// |count| successful results before invoking |final_callback|. In the case of
// an error, the first error is passed to |final_callback| and all others
// are ignored.
base::RepeatingCallback<void(int)> MakeBarrierCompletionCallback(
    int count,
    net::CompletionOnceCallback final_callback) {
  BarrierContext* context =
      new BarrierContext(std::move(final_callback), count);
  return base::BindRepeating(&BarrierCompletionCallbackImpl,
                             base::Owned(context));
}

// A short bindable thunk that ensures a completion callback is always called
// after running an operation asynchronously. Checks for backend liveness first.
void RunOperationAndCallback(
    base::WeakPtr<SimpleBackendImpl> backend,
    base::OnceCallback<net::Error(net::CompletionOnceCallback)> operation,
    net::CompletionOnceCallback operation_callback) {
  if (!backend)
    return;

  auto split_callback = base::SplitOnceCallback(std::move(operation_callback));
  const int operation_result =
      std::move(operation).Run(std::move(split_callback.first));
  if (operation_result != net::ERR_IO_PENDING && split_callback.second)
    std::move(split_callback.second).Run(operation_result);
}

// Same but for things that work with EntryResult.
void RunEntryResultOperationAndCallback(
    base::WeakPtr<SimpleBackendImpl> backend,
    base::OnceCallback<EntryResult(EntryResultCallback)> operation,
    EntryResultCallback operation_callback) {
  if (!backend)
    return;

  auto split_callback = base::SplitOnceCallback(std::move(operation_callback));
  EntryResult operation_result =
      std::move(operation).Run(std::move(split_callback.first));
  if (operation_result.net_error() != net::ERR_IO_PENDING &&
      split_callback.second) {
    std::move(split_callback.second).Run(std::move(operation_result));
  }
}

void RecordIndexLoad(net::CacheType cache_type,
                     base::TimeTicks constructed_since,
                     int result) {
  const base::TimeDelta creation_to_index = base::TimeTicks::Now() -
                                            constructed_since;
  if (result == net::OK) {
    SIMPLE_CACHE_UMA(TIMES, "CreationToIndex", cache_type, creation_to_index);
  } else {
    SIMPLE_CACHE_UMA(TIMES,
                     "CreationToIndexFail", cache_type, creation_to_index);
  }
}

SimpleEntryImpl::OperationsMode CacheTypeToOperationsMode(net::CacheType type) {
  return (type == net::DISK_CACHE || type == net::GENERATED_BYTE_CODE_CACHE ||
          type == net::GENERATED_NATIVE_CODE_CACHE ||
          type == net::GENERATED_WEBUI_BYTE_CODE_CACHE)
             ? SimpleEntryImpl::OPTIMISTIC_OPERATIONS
             : SimpleEntryImpl::NON_OPTIMISTIC_OPERATIONS;
}

}  // namespace

class SimpleBackendImpl::ActiveEntryProxy
    : public SimpleEntryImpl::ActiveEntryProxy {
 public:
  ~ActiveEntryProxy() override {
    if (backend_) {
      DCHECK_EQ(1U, backend_->active_entries_.count(entry_hash_));
      backend_->active_entries_.erase(entry_hash_);
    }
  }

  static std::unique_ptr<SimpleEntryImpl::ActiveEntryProxy> Create(
      int64_t entry_hash,
      base::WeakPtr<SimpleBackendImpl> backend) {
    return base::WrapUnique(
        new ActiveEntryProxy(entry_hash, std::move(backend)));
  }

 private:
  ActiveEntryProxy(uint64_t entry_hash,
                   base::WeakPtr<SimpleBackendImpl> backend)
      : entry_hash_(entry_hash), backend_(std::move(backend)) {}

  uint64_t entry_hash_;
  base::WeakPtr<SimpleBackendImpl> backend_;
};

SimpleBackendImpl::SimpleBackendImpl(
    scoped_refptr<BackendFileOperationsFactory> file_operations_factory,
    const FilePath& path,
    scoped_refptr<BackendCleanupTracker> cleanup_tracker,
    SimpleFileTracker* file_tracker,
    int64_t max_bytes,
    net::CacheType cache_type,
    net::NetLog* net_log)
    : Backend(cache_type),
      file_operations_factory_(
          file_operations_factory
              ? std::move(file_operations_factory)
              : base::MakeRefCounted<TrivialFileOperationsFactory>()),
      cleanup_tracker_(std::move(cleanup_tracker)),
      file_tracker_(file_tracker ? file_tracker
                                 : g_simple_file_tracker.Pointer()),
      path_(path),
      orig_max_size_(max_bytes),
      entry_operations_mode_(CacheTypeToOperationsMode(cache_type)),
      post_doom_waiting_(
          base::MakeRefCounted<SimplePostOperationWaiterTable>()),
      post_open_by_hash_waiting_(
          base::MakeRefCounted<SimplePostOperationWaiterTable>()),
      net_log_(net_log) {
  // Treat negative passed-in sizes same as in other backends, as default.
  if (orig_max_size_ < 0)
    orig_max_size_ = 0;
}

SimpleBackendImpl::~SimpleBackendImpl() {
  // Write the index out if there is a pending write from a
  // previous operation.
  if (index_->HasPendingWrite())
    index_->WriteToDisk(SimpleIndex::INDEX_WRITE_REASON_SHUTDOWN);
}

void SimpleBackendImpl::SetTaskRunnerForTesting(
    scoped_refptr<base::SequencedTaskRunner> task_runner) {
  prioritized_task_runner_ =
      base::MakeRefCounted<net::PrioritizedTaskRunner>(kWorkerPoolTaskTraits);
  prioritized_task_runner_->SetTaskRunnerForTesting(  // IN-TEST
      std::move(task_runner));
}

void SimpleBackendImpl::Init(CompletionOnceCallback completion_callback) {
  auto index_task_runner = base::ThreadPool::CreateSequencedTaskRunner(
      {base::MayBlock(), base::WithBaseSyncPrimitives(),
       base::TaskPriority::USER_BLOCKING,
       base::TaskShutdownBehavior::BLOCK_SHUTDOWN});

  prioritized_task_runner_ =
      base::MakeRefCounted<net::PrioritizedTaskRunner>(kWorkerPoolTaskTraits);

  index_ = std::make_unique<SimpleIndex>(
      base::SequencedTaskRunner::GetCurrentDefault(), cleanup_tracker_.get(),
      this, GetCacheType(),
      std::make_unique<SimpleIndexFile>(
          index_task_runner, file_operations_factory_, GetCacheType(), path_));
  index_->ExecuteWhenReady(
      base::BindOnce(&RecordIndexLoad, GetCacheType(), base::TimeTicks::Now()));

  auto file_operations = file_operations_factory_->Create(index_task_runner);
  index_task_runner->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(&SimpleBackendImpl::InitCacheStructureOnDisk,
                     std::move(file_operations), path_, orig_max_size_,
                     GetCacheType()),
      base::BindOnce(&SimpleBackendImpl::InitializeIndex,
                     weak_ptr_factory_.GetWeakPtr(),
                     std::move(completion_callback)));
}

int64_t SimpleBackendImpl::MaxFileSize() const {
  uint64_t file_size_ratio = GetCacheType() == net::GENERATED_NATIVE_CODE_CACHE
                                 ? kMaxNativeCodeFileRatio
                                 : kMaxFileRatio;
  return std::max(
      base::saturated_cast<int64_t>(index_->max_size() / file_size_ratio),
      kMinFileSizeLimit);
}

scoped_refptr<SimplePostOperationWaiterTable> SimpleBackendImpl::OnDoomStart(
    uint64_t entry_hash) {
  post_doom_waiting_->OnOperationStart(entry_hash);
  return post_doom_waiting_;
}

void SimpleBackendImpl::DoomEntries(std::vector<uint64_t>* entry_hashes,
                                    net::CompletionOnceCallback callback) {
  auto mass_doom_entry_hashes = std::make_unique<std::vector<uint64_t>>();
  mass_doom_entry_hashes->swap(*entry_hashes);

  std::vector<uint64_t> to_doom_individually_hashes;

  // For each of the entry hashes, there are two cases:
  // 1. There are corresponding entries in active set, pending doom, or both
  //    sets, and so the hash should be doomed individually to avoid flakes.
  // 2. The hash is not in active use at all, so we can call
  //    SimpleSynchronousEntry::DeleteEntrySetFiles and delete the files en
  //    masse.
  for (int i = mass_doom_entry_hashes->size() - 1; i >= 0; --i) {
    const uint64_t entry_hash = (*mass_doom_entry_hashes)[i];
    if (!active_entries_.count(entry_hash) &&
        !post_doom_waiting_->Has(entry_hash)) {
      continue;
    }

    to_doom_individually_hashes.push_back(entry_hash);

    (*mass_doom_entry_hashes)[i] = mass_doom_entry_hashes->back();
    mass_doom_entry_hashes->resize(mass_doom_entry_hashes->size() - 1);
  }

  base::RepeatingCallback<void(int)> barrier_callback =
      MakeBarrierCompletionCallback(to_doom_individually_hashes.size() + 1,
                                    std::move(callback));
  for (std::vector<uint64_t>::const_iterator
           it = to_doom_individually_hashes.begin(),
           end = to_doom_individually_hashes.end();
       it != end; ++it) {
    const int doom_result = DoomEntryFromHash(*it, barrier_callback);
    DCHECK_EQ(net::ERR_IO_PENDING, doom_result);
    index_->Remove(*it);
  }

  for (std::vector<uint64_t>::const_iterator
           it = mass_doom_entry_hashes->begin(),
           end = mass_doom_entry_hashes->end();
       it != end; ++it) {
    index_->Remove(*it);
    OnDoomStart(*it);
  }

  // Taking this pointer here avoids undefined behaviour from calling
  // std::move() before mass_doom_entry_hashes.get().
  std::vector<uint64_t>* mass_doom_entry_hashes_ptr =
      mass_doom_entry_hashes.get();

  // We don't use priorities (i.e., `prioritized_task_runner_`) here because
  // we don't actually have them here (since this is for eviction based on
  // index).
  auto task_runner =
      base::ThreadPool::CreateSequencedTaskRunner(kWorkerPoolTaskTraits);
  task_runner->PostTaskAndReplyWithResult(
      FROM_HERE,
      base::BindOnce(&SimpleSynchronousEntry::DeleteEntrySetFiles,
                     mass_doom_entry_hashes_ptr, path_,
                     file_operations_factory_->CreateUnbound()),
      base::BindOnce(&SimpleBackendImpl::DoomEntriesComplete,
                     weak_ptr_factory_.GetWeakPtr(),
                     std::move(mass_doom_entry_hashes), barrier_callback));
}

int32_t SimpleBackendImpl::GetEntryCount() const {
  // TODO(pasko): Use directory file count when index is not ready.
  return index_->GetEntryCount();
}

EntryResult SimpleBackendImpl::OpenEntry(const std::string& key,
                                         net::RequestPriority request_priority,
                                         EntryResultCallback callback) {
  const uint64_t entry_hash = simple_util::GetEntryHashKey(key);

  std::vector<base::OnceClosure>* post_operation = nullptr;
  PostOperationQueue post_operation_queue = PostOperationQueue::kNone;
  scoped_refptr<SimpleEntryImpl> simple_entry = CreateOrFindActiveOrDoomedEntry(
      entry_hash, key, request_priority, post_operation, post_operation_queue);
  if (!simple_entry) {
    if (post_operation_queue == PostOperationQueue::kPostDoom &&
        post_operation->empty() &&
        entry_operations_mode_ == SimpleEntryImpl::OPTIMISTIC_OPERATIONS) {
      // The entry is doomed, and no other backend operations are queued for the
      // entry, thus the open must fail and it's safe to return synchronously.
      net::NetLogWithSource log_for_entry(net::NetLogWithSource::Make(
          net_log_, net::NetLogSourceType::DISK_CACHE_ENTRY));
      log_for_entry.AddEvent(
          net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_CALL);
      log_for_entry.AddEventWithNetErrorCode(
          net::NetLogEventType::SIMPLE_CACHE_ENTRY_OPEN_END, net::ERR_FAILED);
      return EntryResult::MakeError(net::ERR_FAILED);
    }

    base::OnceCallback<EntryResult(EntryResultCallback)> operation =
        base::BindOnce(&SimpleBackendImpl::OpenEntry, base::Unretained(this),
                       key, request_priority);
    post_operation->emplace_back(base::BindOnce(
        &RunEntryResultOperationAndCallback, weak_ptr_factory_.GetWeakPtr(),
        std::move(operation), std::move(callback)));
    return EntryResult::MakeError(net::ERR_IO_PENDING);
  }
  return simple_entry->OpenEntry(std::move(callback));
}

EntryResult SimpleBackendImpl::CreateEntry(
    const std::string& key,
    net::RequestPriority request_priority,
    EntryResultCallback callback) {
  DCHECK_LT(0u, key.size());
  const uint64_t entry_hash = simple_util::GetEntryHashKey(key);

  std::vector<base::OnceClosure>* post_operation = nullptr;
  PostOperationQueue post_operation_queue = PostOperationQueue::kNone;
  scoped_refptr<SimpleEntryImpl> simple_entry = CreateOrFindActiveOrDoomedEntry(
      entry_hash, key, request_priority, post_operation, post_operation_queue);

  // If couldn't grab an entry object due to pending doom, see if circumstances
  // are right for an optimistic create.
  if (!simple_entry && post_operation_queue == PostOperationQueue::kPostDoom) {
    simple_entry = MaybeOptimisticCreateForPostDoom(
        entry_hash, key, request_priority, post_operation);
  }

  // If that doesn't work either, retry this once doom / open by hash is done.
  if (!simple_entry) {
    base::OnceCallback<EntryResult(EntryResultCallback)> operation =
        base::BindOnce(&SimpleBackendImpl::CreateEntry, base::Unretained(this),
                       key, request_priority);
    post_operation->emplace_back(base::BindOnce(
        &RunEntryResultOperationAndCallback, weak_ptr_factory_.GetWeakPtr(),
        std::move(operation), std::move(callback)));
    return EntryResult::MakeError(net::ERR_IO_PENDING);
  }

  return simple_entry->CreateEntry(std::move(callback));
}

EntryResult SimpleBackendImpl::OpenOrCreateEntry(
    const std::string& key,
    net::RequestPriority request_priority,
    EntryResultCallback callback) {
  DCHECK_LT(0u, key.size());
  const uint64_t entry_hash = simple_util::GetEntryHashKey(key);

  std::vector<base::OnceClosure>* post_operation = nullptr;
  PostOperationQueue post_operation_queue = PostOperationQueue::kNone;
  scoped_refptr<SimpleEntryImpl> simple_entry = CreateOrFindActiveOrDoomedEntry(
      entry_hash, key, request_priority, post_operation, post_operation_queue);

  // If couldn't grab an entry object due to pending doom, see if circumstances
  // are right for an optimistic create.
  if (!simple_entry) {
    if (post_operation_queue == PostOperationQueue::kPostDoom) {
      simple_entry = MaybeOptimisticCreateForPostDoom(
          entry_hash, key, request_priority, post_operation);
    }
    if (simple_entry) {
      return simple_entry->CreateEntry(std::move(callback));
    } else {
      // If that doesn't work either, retry this once doom / open by hash is
      // done.
      base::OnceCallback<EntryResult(EntryResultCallback)> operation =
          base::BindOnce(&SimpleBackendImpl::OpenOrCreateEntry,
                         base::Unretained(this), key, request_priority);
      post_operation->emplace_back(base::BindOnce(
          &RunEntryResultOperationAndCallback, weak_ptr_factory_.GetWeakPtr(),
          std::move(operation), std::move(callback)));
      return EntryResult::MakeError(net::ERR_IO_PENDING);
    }
  }

  return simple_entry->OpenOrCreateEntry(std::move(callback));
}

scoped_refptr<SimpleEntryImpl>
SimpleBackendImpl::MaybeOptimisticCreateForPostDoom(
    uint64_t entry_hash,
    const std::string& key,
    net::RequestPriority request_priority,
    std::vector<base::OnceClosure>* post_doom) {
  scoped_refptr<SimpleEntryImpl> simple_entry;
  // We would like to optimistically have create go ahead, for benefit of
  // HTTP cache use. This can only be sanely done if we are the only op
  // serialized after doom's completion.
  if (post_doom->empty() &&
      entry_operations_mode_ == SimpleEntryImpl::OPTIMISTIC_OPERATIONS) {
    simple_entry = base::MakeRefCounted<SimpleEntryImpl>(
        GetCacheType(), path_, cleanup_tracker_.get(), entry_hash,
        entry_operations_mode_, this, file_tracker_, file_operations_factory_,
        net_log_, GetNewEntryPriority(request_priority));
    simple_entry->SetKey(key);
    simple_entry->SetActiveEntryProxy(
        ActiveEntryProxy::Create(entry_hash, weak_ptr_factory_.GetWeakPtr()));
    simple_entry->SetCreatePendingDoom();
    std::pair<EntryMap::iterator, bool> insert_result = active_entries_.insert(
        EntryMap::value_type(entry_hash, simple_entry.get()));
    post_doom->emplace_back(base::BindOnce(
        &SimpleEntryImpl::NotifyDoomBeforeCreateComplete, simple_entry));
    DCHECK(insert_result.second);
  }

  return simple_entry;
}

net::Error SimpleBackendImpl::DoomEntry(const std::string& key,
                                        net::RequestPriority priority,
                                        CompletionOnceCallback callback) {
  const uint64_t entry_hash = simple_util::GetEntryHashKey(key);

  std::vector<base::OnceClosure>* post_operation = nullptr;
  PostOperationQueue post_operation_queue = PostOperationQueue::kNone;
  scoped_refptr<SimpleEntryImpl> simple_entry = CreateOrFindActiveOrDoomedEntry(
      entry_hash, key, priority, post_operation, post_operation_queue);
  if (!simple_entry) {
    // At first glance, it appears exceedingly silly to queue up a doom when we
    // get here with `post_operation_queue == PostOperationQueue::kPostDoom`,
    // e.g. a doom already pending; but it's possible that the sequence of
    // operations is Doom/Create/Doom, in which case the second Doom is not
    // at all redundant.
    base::OnceCallback<net::Error(CompletionOnceCallback)> operation =
        base::BindOnce(&SimpleBackendImpl::DoomEntry, base::Unretained(this),
                       key, priority);
    post_operation->emplace_back(
        base::BindOnce(&RunOperationAndCallback, weak_ptr_factory_.GetWeakPtr(),
                       std::move(operation), std::move(callback)));
    return net::ERR_IO_PENDING;
  }

  return simple_entry->DoomEntry(std::move(callback));
}

net::Error SimpleBackendImpl::DoomAllEntries(CompletionOnceCallback callback) {
  return DoomEntriesBetween(Time(), Time(), std::move(callback));
}

net::Error SimpleBackendImpl::DoomEntriesBetween(
    const Time initial_time,
    const Time end_time,
    CompletionOnceCallback callback) {
  index_->ExecuteWhenReady(base::BindOnce(
      &SimpleBackendImpl::IndexReadyForDoom, weak_ptr_factory_.GetWeakPtr(),
      initial_time, end_time, std::move(callback)));
  return net::ERR_IO_PENDING;
}

net::Error SimpleBackendImpl::DoomEntriesSince(
    const Time initial_time,
    CompletionOnceCallback callback) {
  return DoomEntriesBetween(initial_time, Time(), std::move(callback));
}

int64_t SimpleBackendImpl::CalculateSizeOfAllEntries(
    Int64CompletionOnceCallback callback) {
  index_->ExecuteWhenReady(
      base::BindOnce(&SimpleBackendImpl::IndexReadyForSizeCalculation,
                     weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
  return net::ERR_IO_PENDING;
}

int64_t SimpleBackendImpl::CalculateSizeOfEntriesBetween(
    base::Time initial_time,
    base::Time end_time,
    Int64CompletionOnceCallback callback) {
  index_->ExecuteWhenReady(
      base::BindOnce(&SimpleBackendImpl::IndexReadyForSizeBetweenCalculation,
                     weak_ptr_factory_.GetWeakPtr(), initial_time, end_time,
                     std::move(callback)));
  return net::ERR_IO_PENDING;
}

class SimpleBackendImpl::SimpleIterator final : public Iterator {
 public:
  explicit SimpleIterator(base::WeakPtr<SimpleBackendImpl> backend)
      : backend_(backend) {}

  // From Backend::Iterator:
  EntryResult OpenNextEntry(EntryResultCallback callback) override {
    if (!backend_)
      return EntryResult::MakeError(net::ERR_FAILED);
    CompletionOnceCallback open_next_entry_impl =
        base::BindOnce(&SimpleIterator::OpenNextEntryImpl,
                       weak_factory_.GetWeakPtr(), std::move(callback));
    backend_->index_->ExecuteWhenReady(std::move(open_next_entry_impl));
    return EntryResult::MakeError(net::ERR_IO_PENDING);
  }

  void OpenNextEntryImpl(EntryResultCallback callback,
                         int index_initialization_error_code) {
    if (!backend_) {
      std::move(callback).Run(EntryResult::MakeError(net::ERR_FAILED));
      return;
    }
    if (index_initialization_error_code != net::OK) {
      std::move(callback).Run(EntryResult::MakeError(
          static_cast<net::Error>(index_initialization_error_code)));
      return;
    }
    if (!hashes_to_enumerate_)
      hashes_to_enumerate_ = backend_->index()->GetAllHashes();

    while (!hashes_to_enumerate_->empty()) {
      uint64_t entry_hash = hashes_to_enumerate_->back();
      hashes_to_enumerate_->pop_back();
      if (backend_->index()->Has(entry_hash)) {
        auto split_callback = base::SplitOnceCallback(std::move(callback));
        callback = std::move(split_callback.first);
        EntryResultCallback continue_iteration = base::BindOnce(
            &SimpleIterator::CheckIterationReturnValue,
            weak_factory_.GetWeakPtr(), std::move(split_callback.second));
        EntryResult open_result = backend_->OpenEntryFromHash(
            entry_hash, std::move(continue_iteration));
        if (open_result.net_error() == net::ERR_IO_PENDING)
          return;
        if (open_result.net_error() != net::ERR_FAILED) {
          std::move(callback).Run(std::move(open_result));
          return;
        }
      }
    }
    std::move(callback).Run(EntryResult::MakeError(net::ERR_FAILED));
  }

  void CheckIterationReturnValue(EntryResultCallback callback,
                                 EntryResult result) {
    if (result.net_error() == net::ERR_FAILED) {
      OpenNextEntry(std::move(callback));
      return;
    }
    std::move(callback).Run(std::move(result));
  }

 private:
  base::WeakPtr<SimpleBackendImpl> backend_;
  std::unique_ptr<std::vector<uint64_t>> hashes_to_enumerate_;
  base::WeakPtrFactory<SimpleIterator> weak_factory_{this};
};

std::unique_ptr<Backend::Iterator> SimpleBackendImpl::CreateIterator() {
  return std::make_unique<SimpleIterator>(weak_ptr_factory_.GetWeakPtr());
}

void SimpleBackendImpl::GetStats(base::StringPairs* stats) {
  std::pair<std::string, std::string> item;
  item.first = "Cache type";
  item.second = "Simple Cache";
  stats->push_back(item);
}

void SimpleBackendImpl::OnExternalCacheHit(const std::string& key) {
  index_->UseIfExists(simple_util::GetEntryHashKey(key));
}

uint8_t SimpleBackendImpl::GetEntryInMemoryData(const std::string& key) {
  const uint64_t entry_hash = simple_util::GetEntryHashKey(key);
  return index_->GetEntryInMemoryData(entry_hash);
}

void SimpleBackendImpl::SetEntryInMemoryData(const std::string& key,
                                             uint8_t data) {
  const uint64_t entry_hash = simple_util::GetEntryHashKey(key);
  index_->SetEntryInMemoryData(entry_hash, data);
}

void SimpleBackendImpl::InitializeIndex(CompletionOnceCallback callback,
                                        const DiskStatResult& result) {
  if (result.net_error == net::OK) {
    index_->SetMaxSize(result.max_size);
#if BUILDFLAG(IS_ANDROID)
    if (app_status_listener_getter_) {
      index_->set_app_status_listener_getter(
          std::move(app_status_listener_getter_));
    }
#endif
    index_->Initialize(result.cache_dir_mtime);
  }
  std::move(callback).Run(result.net_error);
}

void SimpleBackendImpl::IndexReadyForDoom(Time initial_time,
                                          Time end_time,
                                          CompletionOnceCallback callback,
                                          int result) {
  if (result != net::OK) {
    std::move(callback).Run(result);
    return;
  }
  std::unique_ptr<std::vector<uint64_t>> removed_key_hashes(
      index_->GetEntriesBetween(initial_time, end_time).release());
  DoomEntries(removed_key_hashes.get(), std::move(callback));
}

void SimpleBackendImpl::IndexReadyForSizeCalculation(
    Int64CompletionOnceCallback callback,
    int result) {
  int64_t rv = result == net::OK ? index_->GetCacheSize() : result;
  std::move(callback).Run(rv);
}

void SimpleBackendImpl::IndexReadyForSizeBetweenCalculation(
    base::Time initial_time,
    base::Time end_time,
    Int64CompletionOnceCallback callback,
    int result) {
  int64_t rv = result == net::OK
                   ? index_->GetCacheSizeBetween(initial_time, end_time)
                   : result;
  std::move(callback).Run(rv);
}

// static
SimpleBackendImpl::DiskStatResult SimpleBackendImpl::InitCacheStructureOnDisk(
    std::unique_ptr<BackendFileOperations> file_operations,
    const base::FilePath& path,
    uint64_t suggested_max_size,
    net::CacheType cache_type) {
  DiskStatResult result;
  result.max_size = suggested_max_size;
  result.net_error = net::OK;
  SimpleCacheConsistencyResult consistency =
      FileStructureConsistent(file_operations.get(), path);
  SIMPLE_CACHE_UMA(ENUMERATION, "ConsistencyResult", cache_type, consistency);

  // If the cache structure is inconsistent make a single attempt at
  // recovering it.  Previously there were bugs that could cause a partially
  // written fake index file to be left in an otherwise empty cache.  In
  // that case we can delete the index files and start over.  Also, some
  // consistency failures may leave an empty directory directly and we can
  // retry those cases as well.
  if (consistency != SimpleCacheConsistencyResult::kOK) {
    bool deleted_files = disk_cache::DeleteIndexFilesIfCacheIsEmpty(path);
    SIMPLE_CACHE_UMA(BOOLEAN, "DidDeleteIndexFilesAfterFailedConsistency",
                     cache_type, deleted_files);
    if (base::IsDirectoryEmpty(path)) {
      SimpleCacheConsistencyResult orig_consistency = consistency;
      consistency = FileStructureConsistent(file_operations.get(), path);
      SIMPLE_CACHE_UMA(ENUMERATION, "RetryConsistencyResult", cache_type,
                       consistency);
      if (consistency == SimpleCacheConsistencyResult::kOK) {
        SIMPLE_CACHE_UMA(ENUMERATION,
                         "OriginalConsistencyResultBeforeSuccessfulRetry",
                         cache_type, orig_consistency);
      }
    }
    if (deleted_files) {
      SIMPLE_CACHE_UMA(ENUMERATION, "ConsistencyResultAfterIndexFilesDeleted",
                       cache_type, consistency);
    }
  }

  if (consistency != SimpleCacheConsistencyResult::kOK) {
    LOG(ERROR) << "Simple Cache Backend: wrong file structure on disk: "
               << static_cast<int>(consistency)
               << " path: " << path.LossyDisplayName();
    result.net_error = net::ERR_FAILED;
  } else {
    std::optional<base::File::Info> file_info =
        file_operations->GetFileInfo(path);
    if (!file_info.has_value()) {
      // Something deleted the directory between when we set it up and the
      // mstat; this is not uncommon on some test fixtures which erase their
      // tempdir while some worker threads may still be running.
      LOG(ERROR) << "Simple Cache Backend: cache directory inaccessible right "
                    "after creation; path: "
                 << path.LossyDisplayName();
      result.net_error = net::ERR_FAILED;
    } else {
      result.cache_dir_mtime = file_info->last_modified;
      if (!result.max_size) {
        int64_t available = base::SysInfo::AmountOfFreeDiskSpace(path);
        result.max_size = disk_cache::PreferredCacheSize(available, cache_type);
        DCHECK(result.max_size);
      }
    }
  }
  return result;
}

scoped_refptr<SimpleEntryImpl>
SimpleBackendImpl::CreateOrFindActiveOrDoomedEntry(
    const uint64_t entry_hash,
    const std::string& key,
    net::RequestPriority request_priority,
    std::vector<base::OnceClosure>*& post_operation,
    PostOperationQueue& post_operation_queue) {
  DCHECK_EQ(entry_hash, simple_util::GetEntryHashKey(key));

  // If there is a doom pending, we would want to serialize after it.
  std::vector<base::OnceClosure>* post_doom =
      post_doom_waiting_->Find(entry_hash);
  if (post_doom) {
    post_operation = post_doom;
    post_operation_queue = PostOperationQueue::kPostDoom;
    return nullptr;
  }

  std::pair<EntryMap::iterator, bool> insert_result =
      active_entries_.insert(EntryMap::value_type(entry_hash, nullptr));
  EntryMap::iterator& it = insert_result.first;
  const bool did_insert = insert_result.second;
  if (did_insert) {
    SimpleEntryImpl* entry = it->second = new SimpleEntryImpl(
        GetCacheType(), path_, cleanup_tracker_.get(), entry_hash,
        entry_operations_mode_, this, file_tracker_, file_operations_factory_,
        net_log_, GetNewEntryPriority(request_priority));
    entry->SetKey(key);
    entry->SetActiveEntryProxy(
        ActiveEntryProxy::Create(entry_hash, weak_ptr_factory_.GetWeakPtr()));
  }
  // TODO(jkarlin): In case of recycling a half-closed entry, we might want to
  // update its priority.
  DCHECK(it->second);
  // It's possible, but unlikely, that we have an entry hash collision with a
  // currently active entry, or we may not know the key of active entry yet,
  // since it's being opened by hash.
  if (key != it->second->key()) {
    DCHECK(!did_insert);
    if (it->second->key().has_value()) {
      // Collision case.
  
"""


```