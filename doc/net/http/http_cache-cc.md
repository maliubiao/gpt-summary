Response:
My thinking process to answer the request about `net/http/http_cache.cc` went through these stages:

1. **Understanding the Core Request:** The request asks for a functional summary of the provided C++ code, its relation to JavaScript, logical reasoning with examples, common user/programming errors, debugging tips, and finally, a high-level summary. It's crucial to recognize this is part 1 of 2, implying the need for a focused summary on the given code snippet.

2. **Initial Code Scan and Keyword Identification:** I first scanned the code for key terms and structures related to caching, HTTP, and network operations. Words like "cache," "http," "network," "entry," "backend," "transaction," "disk," "memory," "url," "request," "response," "load_flags," "NetworkIsolationKey," and "JavaScript" (although absent, the request prompts consideration). Preprocessor directives like `#ifdef` and pragmas were noted but considered less crucial for the functional summary.

3. **Identifying Key Classes and Structures:** I then focused on the major classes and structs defined in the code: `HttpCache`, `DefaultBackend`, `ActiveEntry`, `PendingOp`, and `WorkItem`. Understanding the purpose of each is essential.

    * **`HttpCache`:** The central class, managing the overall caching mechanism.
    * **`DefaultBackend`:** Represents different storage backends (in-memory or disk).
    * **`ActiveEntry`:**  Manages currently active cache entries and their associated transactions.
    * **`PendingOp`:** Tracks ongoing asynchronous operations related to the cache.
    * **`WorkItem`:** Encapsulates a single cache operation request.

4. **Inferring Functionality from Class Interactions:** I examined how these classes interact. For example, `HttpCache` uses `BackendFactory` to create `disk_cache::Backend`. `ActiveEntry` holds a `disk_cache::Entry` and manages `Transaction` objects. `WorkItem` structures are used to perform actions on the cache.

5. **Mapping Code to High-Level Concepts:**  I translated the code elements into broader caching concepts. For instance, the `DefaultBackend` and its `CreateBackend` method clearly relate to cache initialization and storage management. `ActiveEntry` deals with concurrency control and managing access to cached data. The `GenerateCacheKey` functions are about how URLs and request parameters are transformed into unique cache identifiers.

6. **Addressing Specific Questions:**  With a good understanding of the code, I addressed each part of the request:

    * **Functionality:**  I listed the core functions observed.
    * **JavaScript Relationship:**  I considered how caching, even though implemented in C++, affects JavaScript by influencing the browser's behavior when fetching resources. The browser uses the cache, and JavaScript doesn't directly interact with the C++ implementation but benefits from its performance.
    * **Logical Reasoning:** I chose a simple scenario (fetching a resource) to illustrate the cache interaction, including assumptions about cache state and HTTP headers.
    * **User/Programming Errors:**  I focused on common mistakes related to cache configuration or assumptions about caching behavior, particularly in development scenarios.
    * **User Operation to Code Path:** I described a typical browsing scenario leading to cache operations.
    * **Part 1 Summary:**  I condensed the identified functionalities into a concise summary specifically for the provided code segment.

7. **Focusing on the Provided Snippet (Part 1 Constraint):**  It's crucial to limit the summary and analysis to the code given in "part 1."  Avoid discussing concepts or code that might appear in "part 2" (even though it's not provided). For instance, I didn't delve into the details of `HttpCache::Transaction` or specific cache eviction policies, as those might be elaborated upon later.

8. **Refinement and Clarity:** I reviewed my answers to ensure they were clear, concise, and accurate, using terminology appropriate for the domain. I aimed for a balance between technical detail and high-level understanding.

By following this structured approach, I could effectively analyze the C++ code snippet and address all the specific points raised in the request, while adhering to the constraint of focusing on "part 1."
这是 Chromium 网络栈中 `net/http/http_cache.cc` 文件的第一部分。根据提供的代码，我们可以归纳出以下功能：

**核心功能：HTTP 缓存管理**

这个文件实现了 Chromium 中 HTTP 缓存的核心逻辑，负责存储和检索 HTTP 响应，以提高网页加载速度和减少网络请求。

**具体功能点：**

1. **缓存后端抽象和管理:**
   - 定义了 `HttpCache::BackendFactory` 接口，用于创建不同类型的缓存后端（例如内存缓存、磁盘缓存）。
   - 提供了 `HttpCache::DefaultBackend` 作为默认的后端工厂实现，允许配置缓存类型（`MEMORY_CACHE`, `DISK_CACHE`）、存储路径、最大大小等。
   - 提供了创建内存缓存后端的静态方法 `InMemory()`.
   - 使用 `disk_cache::Backend` 与底层的磁盘缓存进行交互。

2. **活动缓存条目管理 (`HttpCache::ActiveEntry`):**
   - 跟踪当前正在被使用的缓存条目，防止并发修改和提供一致性。
   - 使用 `active_entries_` 映射表来存储活动的缓存条目，键是缓存条目的键值。
   - 提供了添加、移除、查找活动条目的方法。
   - 支持对活动条目进行加锁和解锁，以控制对缓存数据的并发访问。
   - 管理与活动条目关联的读写事务 (`readers_`, `writers_`).
   - 提供了标记条目为 "doomed" 的机制，表示该条目将被删除。
   - 实现了请求重定向到 headers 阶段的逻辑 (`RestartHeadersPhaseTransactions`, `RestartHeadersTransaction`).

3. **待处理操作管理 (`HttpCache::PendingOp`):**
   - 管理当前正在进行的异步缓存操作，例如创建或打开缓存条目，以及创建缓存后端。
   - 使用 `pending_ops_` 映射表存储待处理的操作，键是缓存条目的键值。
   - 维护一个工作项队列 (`pending_queue`)，用于串行化对同一缓存条目的操作。

4. **工作项处理 (`HttpCache::WorkItem`):**
   - 封装了对缓存后端的单个请求，包含操作类型、关联的事务和回调函数。
   - 定义了 `WorkItemOperation` 枚举，表示不同的缓存操作类型（例如打开条目、创建条目、删除条目）。
   - 提供了通知事务操作结果的方法 (`NotifyTransaction`).

5. **缓存事务创建 (`CreateTransaction`):**
   - 负责创建新的 `HttpCache::Transaction` 对象，用于执行缓存相关的操作。
   - 在创建事务时，会进行缓存后端的懒加载初始化。

6. **缓存键生成 (`GenerateCacheKey`, `GenerateCacheKeyForRequest`):**
   - 定义了生成缓存键的逻辑，用于唯一标识一个缓存条目。
   - 考虑了请求的 URL、加载标志（是否允许保存 cookies）、网络隔离键 (`NetworkIsolationKey`)、上传数据标识符等因素。
   - 实现了 split cache 的逻辑，根据网络隔离键对缓存进行分区。
   - 提供了从缓存键中提取原始 URL 的方法 (`GetResourceURLFromHttpCacheKey`).

7. **外部缓存命中通知 (`OnExternalCacheHit`):**
   - 允许外部组件（例如 Service Worker）通知 HTTP 缓存发生了缓存命中。

8. **连接管理 (`CloseAllConnections`, `CloseIdleConnections`):**
   - 提供了关闭所有连接和关闭空闲连接的方法，委托给底层的 `HttpNetworkSession`。

9. **静态配置和全局状态:**
   - 使用全局变量 `g_init_cache` 和 `g_enable_split_cache` 跟踪缓存的初始化状态和 split cache 的启用状态。
   - 提供了静态方法 `SplitCacheFeatureEnableByDefault()` 用于在默认情况下启用 split cache。
   - 提供了静态方法 `IsSplitCacheEnabled()` 用于查询 split cache 是否启用。
   - 提供了静态方法 `ClearGlobalsForTesting()` 用于在测试后清理全局状态。

**与 JavaScript 的关系:**

虽然 `http_cache.cc` 是 C++ 代码，但它直接影响着 JavaScript 在浏览器中的网络行为。当 JavaScript 发起网络请求时（例如通过 `fetch` API 或加载图片、脚本等资源），浏览器会首先检查 HTTP 缓存。

* **缓存命中:** 如果缓存中存在与请求匹配的条目，浏览器会直接从缓存中读取数据，而无需发送网络请求。这显著提高了页面加载速度，用户可以看到更快的渲染。JavaScript 代码无需感知缓存的存在，但会受益于其带来的性能提升。
* **缓存未命中:** 如果缓存中没有匹配的条目，浏览器会发起网络请求。请求返回后，`http_cache.cc` 中的逻辑可能会将响应存储到缓存中，以便下次使用。
* **缓存策略:** HTTP 响应头中的缓存控制指令（例如 `Cache-Control`, `Expires`）会影响 `http_cache.cc` 如何存储和验证缓存条目。JavaScript 可以通过设置这些响应头来影响缓存行为。

**举例说明:**

假设 JavaScript 代码发起一个获取图片的请求：

```javascript
fetch('https://example.com/image.png');
```

1. **首次请求 (假设缓存为空):**
   - 浏览器会调用 Chromium 网络栈的代码，最终会到达 `http_cache.cc`。
   - `HttpCache` 检查缓存中是否存在 `https://example.com/image.png` 的条目，发现不存在。
   - `HttpCache` 将创建一个新的 `HttpCache::Transaction`，并指示网络层发送请求。
   - 请求成功后，`http_cache.cc` 会根据响应头中的缓存控制指令，将图片数据存储到缓存中，并创建一个 `ActiveEntry`。

2. **后续请求:**
   - JavaScript 再次发起相同的请求。
   - `HttpCache` 检查缓存，这次会找到匹配的 `ActiveEntry`。
   - 如果缓存条目仍然有效（未过期），`HttpCache` 会直接从缓存中读取图片数据，并将其返回给浏览器。
   - JavaScript 的 `fetch` API 会接收到缓存中的数据，而无需实际的网络请求。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 用户在浏览器中访问 `https://example.com/page.html`，该 HTML 页面引用了一个 CSS 文件 `https://example.com/style.css`。
* 缓存初始状态为空。
* 服务器对 `style.css` 的响应头包含 `Cache-Control: max-age=3600`。

**输出:**

1. 当浏览器首次请求 `style.css` 时，`HttpCache` 会创建一个新的缓存条目，并将 CSS 文件的内容存储到缓存中，有效期为 3600 秒。
2. 在接下来的 3600 秒内，如果用户再次访问包含相同 `style.css` 引用的页面，`HttpCache` 会直接从缓存中读取 CSS 文件，而不会发送网络请求。

**用户或编程常见的使用错误:**

1. **错误地配置缓存策略:** 服务器端配置了不恰当的 `Cache-Control` 头，导致资源无法被缓存或被缓存的时间过短，降低缓存效率。例如，设置了 `Cache-Control: no-store` 或 `Cache-Control: max-age=0`。
2. **开发者在开发阶段频繁修改静态资源，但浏览器仍然使用旧的缓存版本。** 这可以通过强制刷新（Ctrl+Shift+R 或 Cmd+Shift+R）或清除浏览器缓存来解决。
3. **使用不一致的缓存键:** 在 split cache 启用时，如果请求的某些属性（例如 `NetworkIsolationKey`）发生变化，即使 URL 相同，也可能导致缓存未命中。开发者需要理解 split cache 的工作原理，并确保在需要共享缓存的情况下，请求的这些属性保持一致。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在地址栏输入 URL 并按下回车键，或者点击了一个链接。**
2. **浏览器解析 URL，确定需要加载的资源。**
3. **对于 HTTP(S) 资源，浏览器会调用网络栈的代码。**
4. **网络栈首先会检查 HTTP 缓存 (`HttpCache`)。**
5. **`HttpCache` 根据请求的 URL、方法、加载标志等信息生成缓存键。**
6. **`HttpCache` 查找是否存在与该缓存键匹配的 `ActiveEntry`。**
7. **如果找到匹配的 `ActiveEntry`，且缓存条目有效，则直接从缓存中读取数据。**
8. **如果没有找到匹配的 `ActiveEntry` 或缓存条目已过期，则 `HttpCache` 会创建一个新的 `HttpCache::Transaction`，并指示网络层发起实际的网络请求。**
9. **网络请求完成后，`HttpCache` 会根据响应头中的缓存控制指令，决定是否将响应存储到缓存中。**

**总结 (针对第 1 部分):**

`net/http/http_cache.cc` 的第一部分主要定义了 HTTP 缓存的核心架构和基本组件，包括缓存后端的抽象和管理、活动缓存条目的管理、待处理操作的管理、工作项的处理以及缓存键的生成逻辑。它为实现 Chromium 的 HTTP 缓存功能奠定了基础，并直接影响着浏览器在处理网络请求时的行为和性能。该部分还包含了与 split cache 相关的配置和逻辑。

### 提示词
```
这是目录为net/http/http_cache.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/341324165): Fix and remove.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_cache.h"

#include <optional>
#include <string_view>
#include <utility>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/feature_list.h"
#include "base/files/file_util.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/hash/sha1.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/histogram_macros_local.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "base/pickle.h"
#include "base/ranges/algorithm.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_clock.h"
#include "build/build_config.h"
#include "http_request_info.h"
#include "net/base/cache_type.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_isolation_key.h"
#include "net/base/upload_data_stream.h"
#include "net/disk_cache/disk_cache.h"
#include "net/http/http_cache_transaction.h"
#include "net/http/http_cache_writers.h"
#include "net/http/http_network_layer.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_util.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/quic_server_info.h"
#include "url/origin.h"

#if BUILDFLAG(IS_POSIX)
#include <unistd.h>
#endif

namespace net {

namespace {
// True if any HTTP cache has been initialized.
bool g_init_cache = false;

// True if split cache is enabled by default. Must be set before any HTTP cache
// has been initialized.
bool g_enable_split_cache = false;

}  // namespace

const char HttpCache::kDoubleKeyPrefix[] = "_dk_";
const char HttpCache::kDoubleKeySeparator[] = " ";
const char HttpCache::kSubframeDocumentResourcePrefix[] = "s_";

HttpCache::DefaultBackend::DefaultBackend(
    CacheType type,
    BackendType backend_type,
    scoped_refptr<disk_cache::BackendFileOperationsFactory>
        file_operations_factory,
    const base::FilePath& path,
    int max_bytes,
    bool hard_reset)
    : type_(type),
      backend_type_(backend_type),
      file_operations_factory_(std::move(file_operations_factory)),
      path_(path),
      max_bytes_(max_bytes),
      hard_reset_(hard_reset) {}

HttpCache::DefaultBackend::~DefaultBackend() = default;

// static
std::unique_ptr<HttpCache::BackendFactory> HttpCache::DefaultBackend::InMemory(
    int max_bytes) {
  return std::make_unique<DefaultBackend>(MEMORY_CACHE, CACHE_BACKEND_DEFAULT,
                                          /*file_operations_factory=*/nullptr,
                                          base::FilePath(), max_bytes, false);
}

disk_cache::BackendResult HttpCache::DefaultBackend::CreateBackend(
    NetLog* net_log,
    base::OnceCallback<void(disk_cache::BackendResult)> callback) {
  DCHECK_GE(max_bytes_, 0);
  disk_cache::ResetHandling reset_handling =
      hard_reset_ ? disk_cache::ResetHandling::kReset
                  : disk_cache::ResetHandling::kResetOnError;
  LOCAL_HISTOGRAM_BOOLEAN("HttpCache.HardReset", hard_reset_);
#if BUILDFLAG(IS_ANDROID)
  if (app_status_listener_getter_) {
    return disk_cache::CreateCacheBackend(
        type_, backend_type_, file_operations_factory_, path_, max_bytes_,
        reset_handling, net_log, std::move(callback),
        app_status_listener_getter_);
  }
#endif
  return disk_cache::CreateCacheBackend(
      type_, backend_type_, file_operations_factory_, path_, max_bytes_,
      reset_handling, net_log, std::move(callback));
}

#if BUILDFLAG(IS_ANDROID)
void HttpCache::DefaultBackend::SetAppStatusListenerGetter(
    disk_cache::ApplicationStatusListenerGetter app_status_listener_getter) {
  app_status_listener_getter_ = std::move(app_status_listener_getter);
}
#endif

//-----------------------------------------------------------------------------

HttpCache::ActiveEntry::ActiveEntry(base::WeakPtr<HttpCache> cache,
                                    disk_cache::Entry* entry,
                                    bool opened_in)
    : cache_(std::move(cache)), disk_entry_(entry), opened_(opened_in) {
  CHECK(disk_entry_);
  cache_->active_entries_.emplace(disk_entry_->GetKey(),
                                  base::raw_ref<ActiveEntry>::from_ptr(this));
}

HttpCache::ActiveEntry::~ActiveEntry() {
  if (cache_) {
    if (doomed_) {
      FinalizeDoomed();
    } else {
      Deactivate();
    }
  }
}

void HttpCache::ActiveEntry::FinalizeDoomed() {
  CHECK(doomed_);

  auto it =
      cache_->doomed_entries_.find(base::raw_ref<ActiveEntry>::from_ptr(this));
  CHECK(it != cache_->doomed_entries_.end());

  cache_->doomed_entries_.erase(it);
}

void HttpCache::ActiveEntry::Deactivate() {
  CHECK(!doomed_);

  std::string key = disk_entry_->GetKey();
  if (key.empty()) {
    SlowDeactivate();
    return;
  }

  auto it = cache_->active_entries_.find(key);
  CHECK(it != cache_->active_entries_.end());
  CHECK(&it->second.get() == this);

  cache_->active_entries_.erase(it);
}

// TODO(ricea): Add unit test for this method.
void HttpCache::ActiveEntry::SlowDeactivate() {
  CHECK(cache_);
  // We don't know this entry's key so we have to find it without it.
  for (auto it = cache_->active_entries_.begin();
       it != cache_->active_entries_.end(); ++it) {
    if (&it->second.get() == this) {
      cache_->active_entries_.erase(it);
      return;
    }
  }
}

bool HttpCache::ActiveEntry::TransactionInReaders(
    Transaction* transaction) const {
  return readers_.count(transaction) > 0;
}

void HttpCache::ActiveEntry::ReleaseWriters() {
  // May destroy `this`.
  writers_.reset();
}

void HttpCache::ActiveEntry::AddTransactionToWriters(
    Transaction* transaction,
    ParallelWritingPattern parallel_writing_pattern) {
  CHECK(cache_);
  if (!writers_) {
    writers_ =
        std::make_unique<Writers>(cache_.get(), base::WrapRefCounted(this));
  } else {
    ParallelWritingPattern writers_pattern;
    DCHECK(writers_->CanAddWriters(&writers_pattern));
    DCHECK_EQ(PARALLEL_WRITING_JOIN, writers_pattern);
  }

  Writers::TransactionInfo info(transaction->partial(),
                                transaction->is_truncated(),
                                *(transaction->GetResponseInfo()));

  writers_->AddTransaction(transaction, parallel_writing_pattern,
                           transaction->priority(), info);
}

void HttpCache::ActiveEntry::Doom() {
  doomed_ = true;
  disk_entry_->Doom();
}

void HttpCache::ActiveEntry::RestartHeadersPhaseTransactions() {
  if (headers_transaction_) {
    RestartHeadersTransaction();
  }

  auto it = done_headers_queue_.begin();
  while (it != done_headers_queue_.end()) {
    Transaction* done_headers_transaction = *it;
    it = done_headers_queue_.erase(it);
    done_headers_transaction->cache_io_callback().Run(ERR_CACHE_RACE);
  }
}

void HttpCache::ActiveEntry::RestartHeadersTransaction() {
  Transaction* headers_transaction = headers_transaction_;
  headers_transaction_ = nullptr;
  // May destroy `this`.
  headers_transaction->SetValidatingCannotProceed();
}

void HttpCache::ActiveEntry::ProcessAddToEntryQueue() {
  DCHECK(!add_to_entry_queue_.empty());

  // Note `this` may be new or may already have a response body written to it.
  // In both cases, a transaction needs to wait since only one transaction can
  // be in the headers phase at a time.
  if (headers_transaction_) {
    return;
  }
  Transaction* transaction = add_to_entry_queue_.front();
  add_to_entry_queue_.erase(add_to_entry_queue_.begin());
  headers_transaction_ = transaction;

  transaction->cache_io_callback().Run(OK);
}

bool HttpCache::ActiveEntry::RemovePendingTransaction(
    Transaction* transaction) {
  auto j =
      find(add_to_entry_queue_.begin(), add_to_entry_queue_.end(), transaction);
  if (j == add_to_entry_queue_.end()) {
    return false;
  }

  add_to_entry_queue_.erase(j);
  return true;
}

HttpCache::TransactionList HttpCache::ActiveEntry::TakeAllQueuedTransactions() {
  // Process done_headers_queue before add_to_entry_queue to maintain FIFO
  // order.
  TransactionList list = std::move(done_headers_queue_);
  done_headers_queue_.clear();
  list.splice(list.end(), add_to_entry_queue_);
  add_to_entry_queue_.clear();
  return list;
}

bool HttpCache::ActiveEntry::CanTransactionWriteResponseHeaders(
    Transaction* transaction,
    bool is_partial,
    bool is_match) const {
  // If |transaction| is the current writer, do nothing. This can happen for
  // range requests since they can go back to headers phase after starting to
  // write.
  if (writers_ && writers_->HasTransaction(transaction)) {
    CHECK(is_partial);
    return true;
  }

  if (transaction != headers_transaction_) {
    return false;
  }

  if (!(transaction->mode() & Transaction::WRITE)) {
    return false;
  }

  // If its not a match then check if it is the transaction responsible for
  // writing the response body.
  if (!is_match) {
    return (!writers_ || writers_->IsEmpty()) && done_headers_queue_.empty() &&
           readers_.empty();
  }

  return true;
}

//-----------------------------------------------------------------------------

// This structure keeps track of work items that are attempting to create or
// open cache entries or the backend itself.
struct HttpCache::PendingOp {
  PendingOp() = default;
  ~PendingOp() = default;

  raw_ptr<disk_cache::Entry, AcrossTasksDanglingUntriaged> entry = nullptr;
  bool entry_opened = false;  // rather than created.

  std::unique_ptr<disk_cache::Backend> backend;
  std::unique_ptr<WorkItem> writer;
  // True if there is a posted OnPendingOpComplete() task that might delete
  // |this| without removing it from |pending_ops_|.  Note that since
  // OnPendingOpComplete() is static, it will not get cancelled when HttpCache
  // is destroyed.
  bool callback_will_delete = false;
  WorkItemList pending_queue;
};

//-----------------------------------------------------------------------------

// A work item encapsulates a single request to the backend with all the
// information needed to complete that request.
class HttpCache::WorkItem {
 public:
  WorkItem(WorkItemOperation operation,
           Transaction* transaction,
           scoped_refptr<ActiveEntry>* entry)
      : operation_(operation), transaction_(transaction), entry_(entry) {}
  WorkItem(WorkItemOperation operation,
           Transaction* transaction,
           CompletionOnceCallback callback)
      : operation_(operation),
        transaction_(transaction),
        entry_(nullptr),
        callback_(std::move(callback)) {}
  ~WorkItem() = default;

  // Calls back the transaction with the result of the operation.
  void NotifyTransaction(int result, scoped_refptr<ActiveEntry> entry) {
    if (entry_) {
      *entry_ = std::move(entry);
    }
    if (transaction_) {
      transaction_->cache_io_callback().Run(result);
    }
  }

  // Notifies the caller about the operation completion. Returns true if the
  // callback was invoked.
  bool DoCallback(int result) {
    if (!callback_.is_null()) {
      std::move(callback_).Run(result);
      return true;
    }
    return false;
  }

  WorkItemOperation operation() { return operation_; }
  void ClearTransaction() { transaction_ = nullptr; }
  void ClearEntry() { entry_ = nullptr; }
  void ClearCallback() { callback_.Reset(); }
  bool Matches(Transaction* transaction) const {
    return transaction == transaction_;
  }
  bool IsValid() const {
    return transaction_ || entry_ || !callback_.is_null();
  }

 private:
  WorkItemOperation operation_;
  raw_ptr<Transaction, DanglingUntriaged> transaction_;
  raw_ptr<scoped_refptr<ActiveEntry>, DanglingUntriaged> entry_;
  CompletionOnceCallback callback_;  // User callback.
};

//-----------------------------------------------------------------------------

HttpCache::HttpCache(std::unique_ptr<HttpTransactionFactory> network_layer,
                     std::unique_ptr<BackendFactory> backend_factory)
    : net_log_(nullptr),
      backend_factory_(std::move(backend_factory)),

      network_layer_(std::move(network_layer)),
      clock_(base::DefaultClock::GetInstance()),
      keys_marked_no_store_(
          features::kAvoidEntryCreationForNoStoreCacheSize.Get()) {
  g_init_cache = true;
  HttpNetworkSession* session = network_layer_->GetSession();
  // Session may be NULL in unittests.
  // TODO(mmenke): Seems like tests could be changed to provide a session,
  // rather than having logic only used in unit tests here.
  if (!session) {
    return;
  }

  net_log_ = session->net_log();
}

HttpCache::~HttpCache() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // Transactions should see an invalid cache after this point; otherwise they
  // could see an inconsistent object (half destroyed).
  weak_factory_.InvalidateWeakPtrs();

  active_entries_.clear();
  doomed_entries_.clear();

  // Before deleting pending_ops_, we have to make sure that the disk cache is
  // done with said operations, or it will attempt to use deleted data.
  disk_cache_.reset();

  for (auto& pending_it : pending_ops_) {
    // We are not notifying the transactions about the cache going away, even
    // though they are waiting for a callback that will never fire.
    PendingOp* pending_op = pending_it.second;
    pending_op->writer.reset();
    bool delete_pending_op = true;
    if (building_backend_ && pending_op->callback_will_delete) {
      // If we don't have a backend, when its construction finishes it will
      // deliver the callbacks.
      delete_pending_op = false;
    }

    pending_op->pending_queue.clear();
    if (delete_pending_op) {
      delete pending_op;
    }
  }
}

HttpCache::GetBackendResult HttpCache::GetBackend(GetBackendCallback callback) {
  DCHECK(!callback.is_null());

  if (disk_cache_.get()) {
    return {OK, disk_cache_.get()};
  }

  int rv = CreateBackend(base::BindOnce(&HttpCache::ReportGetBackendResult,
                                        GetWeakPtr(), std::move(callback)));
  if (rv != ERR_IO_PENDING) {
    return {rv, disk_cache_.get()};
  }
  return {ERR_IO_PENDING, nullptr};
}

void HttpCache::ReportGetBackendResult(GetBackendCallback callback,
                                       int net_error) {
  std::move(callback).Run(std::pair(net_error, disk_cache_.get()));
}

disk_cache::Backend* HttpCache::GetCurrentBackend() const {
  return disk_cache_.get();
}

// static
bool HttpCache::ParseResponseInfo(base::span<const uint8_t> data,
                                  HttpResponseInfo* response_info,
                                  bool* response_truncated) {
  base::Pickle pickle = base::Pickle::WithUnownedBuffer(data);
  return response_info->InitFromPickle(pickle, response_truncated);
}

void HttpCache::CloseAllConnections(int net_error,
                                    const char* net_log_reason_utf8) {
  HttpNetworkSession* session = GetSession();
  if (session) {
    session->CloseAllConnections(net_error, net_log_reason_utf8);
  }
}

void HttpCache::CloseIdleConnections(const char* net_log_reason_utf8) {
  HttpNetworkSession* session = GetSession();
  if (session) {
    session->CloseIdleConnections(net_log_reason_utf8);
  }
}

void HttpCache::OnExternalCacheHit(
    const GURL& url,
    const std::string& http_method,
    const NetworkIsolationKey& network_isolation_key,
    bool used_credentials) {
  if (!disk_cache_.get() || mode_ == DISABLE) {
    return;
  }

  HttpRequestInfo request_info;
  request_info.url = url;
  request_info.method = http_method;
  request_info.network_isolation_key = network_isolation_key;
  request_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateFromNetworkIsolationKey(
          network_isolation_key);
  // This method is only called for cache hits on subresources, so mark this
  // request as not being a main frame or subframe navigation.
  request_info.is_subframe_document_resource = false;
  request_info.is_main_frame_navigation = false;
  request_info.initiator = std::nullopt;
  if (base::FeatureList::IsEnabled(features::kSplitCacheByIncludeCredentials)) {
    if (!used_credentials) {
      request_info.load_flags &= LOAD_DO_NOT_SAVE_COOKIES;
    } else {
      request_info.load_flags |= ~LOAD_DO_NOT_SAVE_COOKIES;
    }
  }

  std::optional<std::string> key = GenerateCacheKeyForRequest(&request_info);
  if (!key) {
    return;
  }
  disk_cache_->OnExternalCacheHit(*key);
}

int HttpCache::CreateTransaction(
    RequestPriority priority,
    std::unique_ptr<HttpTransaction>* transaction) {
  // Do lazy initialization of disk cache if needed.
  if (!disk_cache_.get()) {
    // We don't care about the result.
    CreateBackend(CompletionOnceCallback());
  }

  auto new_transaction =
      std::make_unique<HttpCache::Transaction>(priority, this);
  if (bypass_lock_for_test_) {
    new_transaction->BypassLockForTest();
  }
  if (bypass_lock_after_headers_for_test_) {
    new_transaction->BypassLockAfterHeadersForTest();
  }
  if (fail_conditionalization_for_test_) {
    new_transaction->FailConditionalizationForTest();
  }

  *transaction = std::move(new_transaction);
  return OK;
}

HttpCache* HttpCache::GetCache() {
  return this;
}

HttpNetworkSession* HttpCache::GetSession() {
  return network_layer_->GetSession();
}

std::unique_ptr<HttpTransactionFactory>
HttpCache::SetHttpNetworkTransactionFactoryForTesting(
    std::unique_ptr<HttpTransactionFactory> new_network_layer) {
  std::unique_ptr<HttpTransactionFactory> old_network_layer(
      std::move(network_layer_));
  network_layer_ = std::move(new_network_layer);
  return old_network_layer;
}

// static
std::string HttpCache::GetResourceURLFromHttpCacheKey(const std::string& key) {
  // The key format is:
  // credential_key/post_key/[isolation_key]url

  std::string::size_type pos = 0;
  pos = key.find('/', pos) + 1;  // Consume credential_key/
  pos = key.find('/', pos) + 1;  // Consume post_key/

  // It is a good idea to make this function tolerate invalid input. This can
  // happen because of disk corruption.
  if (pos == std::string::npos) {
    return "";
  }

  // Consume [isolation_key].
  // Search the key to see whether it begins with |kDoubleKeyPrefix|. If so,
  // then the entry was double-keyed.
  if (pos == key.find(kDoubleKeyPrefix, pos)) {
    // Find the rightmost occurrence of |kDoubleKeySeparator|, as when both
    // the top-frame origin and the initiator are added to the key, there will
    // be two occurrences of |kDoubleKeySeparator|.  When the cache entry is
    // originally written to disk, GenerateCacheKey method calls
    // HttpUtil::SpecForRequest method, which has a DCHECK to ensure that
    // the original resource url is valid, and hence will not contain the
    // unescaped whitespace of |kDoubleKeySeparator|.
    pos = key.rfind(kDoubleKeySeparator);
    DCHECK_NE(pos, std::string::npos);
    pos += strlen(kDoubleKeySeparator);
    DCHECK_LE(pos, key.size() - 1);
  }
  return key.substr(pos);
}

// static
bool HttpCache::CanGenerateCacheKeyForRequest(const HttpRequestInfo* request) {
  if (IsSplitCacheEnabled()) {
    if (request->network_isolation_key.IsTransient()) {
      return false;
    }
    // If the initiator is opaque, it would serialize to 'null' if used, which
    // would mean that navigations initiated from all opaque origins would share
    // a cache partition. To avoid this, we won't cache navigations where the
    // initiator is an opaque origin if the initiator would be used as part of
    // the cache key.
    if (request->initiator.has_value() && request->initiator->opaque()) {
      switch (HttpCache::GetExperimentMode()) {
        case HttpCache::ExperimentMode::kStandard:
        case HttpCache::ExperimentMode::kCrossSiteInitiatorBoolean:
          break;
        case HttpCache::ExperimentMode::kMainFrameNavigationInitiator:
          if (request->is_main_frame_navigation) {
            return false;
          }
          break;
        case HttpCache::ExperimentMode::kNavigationInitiator:
          if (request->is_main_frame_navigation ||
              request->is_subframe_document_resource) {
            return false;
          }
          break;
      }
    }
  }
  return true;
}

// static
// Generate a key that can be used inside the cache.
std::string HttpCache::GenerateCacheKey(
    const GURL& url,
    int load_flags,
    const NetworkIsolationKey& network_isolation_key,
    int64_t upload_data_identifier,
    bool is_subframe_document_resource,
    bool is_mainframe_navigation,
    std::optional<url::Origin> initiator) {
  // The first character of the key may vary depending on whether or not sending
  // credentials is permitted for this request. This only happens if the
  // SplitCacheByIncludeCredentials feature is enabled.
  const char credential_key = (base::FeatureList::IsEnabled(
                                   features::kSplitCacheByIncludeCredentials) &&
                               (load_flags & LOAD_DO_NOT_SAVE_COOKIES))
                                  ? '0'
                                  : '1';

  std::string isolation_key;
  if (IsSplitCacheEnabled()) {
    // Prepend the key with |kDoubleKeyPrefix| = "_dk_" to mark it as
    // double-keyed (and makes it an invalid url so that it doesn't get
    // confused with a single-keyed entry). Separate the origin and url
    // with invalid whitespace character |kDoubleKeySeparator|.
    CHECK(!network_isolation_key.IsTransient());

    const ExperimentMode experiment_mode = HttpCache::GetExperimentMode();
    std::string_view subframe_document_resource_prefix;
    if (is_subframe_document_resource) {
      switch (experiment_mode) {
        case HttpCache::ExperimentMode::kStandard:
        case HttpCache::ExperimentMode::kCrossSiteInitiatorBoolean:
        case HttpCache::ExperimentMode::kMainFrameNavigationInitiator:
          subframe_document_resource_prefix = kSubframeDocumentResourcePrefix;
          break;
        case HttpCache::ExperimentMode::kNavigationInitiator:
          // No need to set `subframe_document_resource_prefix` if we are
          // keying all cross-site navigations on initiator below.
          break;
      }
    }

    std::string navigation_experiment_prefix;
    if (initiator.has_value() &&
        (is_mainframe_navigation || is_subframe_document_resource)) {
      const auto initiator_site = net::SchemefulSite(*initiator);
      const bool is_initiator_cross_site =
          initiator_site != net::SchemefulSite(url);

      if (is_initiator_cross_site) {
        switch (experiment_mode) {
          case HttpCache::ExperimentMode::kStandard:
            break;
          case HttpCache::ExperimentMode::kCrossSiteInitiatorBoolean:
            if (is_mainframe_navigation) {
              navigation_experiment_prefix = "csnb_ ";
            }
            break;
          case HttpCache::ExperimentMode::kMainFrameNavigationInitiator:
            if (is_mainframe_navigation) {
              CHECK(!initiator_site.opaque());
              navigation_experiment_prefix =
                  base::StrCat({"mfni_", initiator_site.Serialize(), " "});
            }
            break;
          case HttpCache::ExperimentMode::kNavigationInitiator:
            if (is_mainframe_navigation || is_subframe_document_resource) {
              CHECK(!initiator_site.opaque());
              navigation_experiment_prefix =
                  base::StrCat({"ni_", initiator_site.Serialize(), " "});
            }
            break;
        }
      }
    }
    isolation_key = base::StrCat(
        {kDoubleKeyPrefix, subframe_document_resource_prefix,
         navigation_experiment_prefix,
         *network_isolation_key.ToCacheKeyString(), kDoubleKeySeparator});
  }

  // The key format is:
  // credential_key/upload_data_identifier/[isolation_key]url

  // Strip out the reference, username, and password sections of the URL and
  // concatenate with the credential_key, the post_key, and the network
  // isolation key if we are splitting the cache.
  return base::StringPrintf("%c/%" PRId64 "/%s%s", credential_key,
                            upload_data_identifier, isolation_key.c_str(),
                            HttpUtil::SpecForRequest(url).c_str());
}

// static
HttpCache::ExperimentMode HttpCache::GetExperimentMode() {
  bool cross_site_main_frame_navigation_boolean_enabled =
      base::FeatureList::IsEnabled(
          net::features::kSplitCacheByCrossSiteMainFrameNavigationBoolean);
  bool main_frame_navigation_initiator_enabled = base::FeatureList::IsEnabled(
      net::features::kSplitCacheByMainFrameNavigationInitiator);
  bool navigation_initiator_enabled = base::FeatureList::IsEnabled(
      net::features::kSplitCacheByNavigationInitiator);

  if (cross_site_main_frame_navigation_boolean_enabled) {
    if (main_frame_navigation_initiator_enabled ||
        navigation_initiator_enabled) {
      return ExperimentMode::kStandard;
    }
    return ExperimentMode::kCrossSiteInitiatorBoolean;
  } else if (main_frame_navigation_initiator_enabled) {
    if (navigation_initiator_enabled) {
      return ExperimentMode::kStandard;
    }
    return ExperimentMode::kMainFrameNavigationInitiator;
  } else if (navigation_initiator_enabled) {
    return ExperimentMode::kNavigationInitiator;
  }
  return ExperimentMode::kStandard;
}

// static
std::optional<std::string> HttpCache::GenerateCacheKeyForRequest(
    const HttpRequestInfo* request) {
  CHECK(request);

  if (!CanGenerateCacheKeyForRequest(request)) {
    return std::nullopt;
  }

  const int64_t upload_data_identifier =
      request->upload_data_stream ? request->upload_data_stream->identifier()
                                  : int64_t(0);
  return GenerateCacheKey(
      request->url, request->load_flags, request->network_isolation_key,
      upload_data_identifier, request->is_subframe_document_resource,
      request->is_main_frame_navigation, request->initiator);
}

// static
void HttpCache::SplitCacheFeatureEnableByDefault() {
  CHECK(!g_enable_split_cache && !g_init_cache);
  if (!base::FeatureList::GetInstance()->IsFeatureOverridden(
          "SplitCacheByNetworkIsolationKey")) {
    g_enable_split_cache = true;
  }
}

// static
bool HttpCache::IsSplitCacheEnabled() {
  return base::FeatureList::IsEnabled(
             features::kSplitCacheByNetworkIsolationKey) ||
         g_enable_split_cache;
}

// static
void HttpCache::ClearGlobalsForTesting() {
  // Reset these so that unit tests can work.
  g_init_cache = false;
  g_enable_split_cache = false;
}

//-----------------------------------------------------------------------------

Error HttpCache::CreateAndSetWorkItem(scoped_refptr<ActiveEntry>* entry,
                                      Transaction* transaction,
                                      WorkItemOperation operation,
                                      PendingOp* pending_op) {
  auto item = std::make_unique<WorkItem>(operation, transaction, entry);

  if (pending_op->writer) {
    pending_op->pending_queue.push_back(std::move(item));
    return ERR_IO_PENDING;
  }

  DCHECK(pending_op->pending_queue.empty());

  pending_op->writer = std::move(item);
  return OK;
}

int HttpCache::CreateBackend(CompletionOnceCallback callback) {
  DCHECK(!disk_cache_);

  if (!backend_factory_.get()) {
    return ERR_FAILED;
  }

  building_backend_ = true;

  const bool callback_is_null = callback.is_null();
  std::unique_ptr<WorkItem> item = std::make_unique<WorkItem>(
      WI_CREATE_BACKEND, nullptr, std::move(callback));

  // This is the only operation that we can do that is not related to any given
  // entry, so we use an empty key for it.
  PendingOp* pending_op = GetPendingOp(std::string());
  if (pending_op->writer) {
    if (!callback_is_null) {
      pending_op->pending_queue.push_back(std::move(item));
    }
    return ERR_IO_PENDING;
  }

  DCHECK(pending_op->pending_queue.empty());

  pending_op->writer = std::move(item);

  disk_cache::BackendResult result = backend_factory_->CreateBackend(
      net_log_, base::BindOnce(&HttpCache::OnPendingBackendCreationOpComplete,
                               GetWeakPtr(), pending_op));
  if (result.net_error == ERR_IO_PENDING) {
    pending_op->callback_will_delete = true;
    return result.net_error;
  }

  pending_op->writer->ClearCallback();
  int rv = result.net_error;
  OnPendingBackendCreationOpComplete(GetWeakPtr(), pending_op,
                                     std::move(result));
  return rv;
}

int HttpCache::GetBackendForTransaction(Transaction* transaction) {
  if (disk_cache_.get()) {
    return OK;
  }

  if (!building_backend_) {
    return ERR_FAILED;
  }

  std::unique_ptr<WorkItem> item = std::make_unique<WorkItem>(
      WI_CREATE_BACKEND, transaction, CompletionOnceCallback());
  PendingOp* pending_op = GetPendingOp(std::string());
  DCHECK(pending_op->writer);
  pending_op->pending_queue.push_back(std::move(item));
  return ERR_IO_PENDING;
}

void HttpCache::DoomActiveEntry(const std::string& key) {
  auto it = active_entries_.find(key);
  if (it == active_entries_.end()) {
    return;
  }

  // This is not a performance critical operation, this is handling an error
  // condition so it is OK to look up the entry again.
  int rv = DoomEntry(key, nullptr);
  DCHECK_EQ(OK, rv);
}

int HttpCache::DoomEntry(const std::string& key, Transaction* transaction) {
  // Need to abandon the ActiveEntry, but any transaction attached to the entry
  // should not be impacted.  Dooming an entry only means that it will no longer
  // be returned by GetActiveEntry (and it will also be destroyed once all
  // consumers are finished with the entry).
  auto it = active_entries_.find(key);
  if (it == active_entries_.end()) {
    DCHECK(transaction);
    return AsyncDoomEntry(key, transaction);
  }

  raw_ref<ActiveEntry> entry_ref = std::move(it->second);
  active_entries_.erase(it);

  // We keep track of doomed entries so that we can ensure that they are
  // cleaned up properly when the cache is destroyed.
  ActiveEntry& entry = entry_ref.get();
  DCHECK_EQ(0u, doomed_entries_.count(entry_ref));
  doomed_entries_.insert(std::move(entry_ref));

  entry.Doom();

  return OK;
}

int HttpCache::AsyncDoomEntry(const std::string& key,
                              Transaction* transaction) {
  PendingOp* pending_op = GetPendingOp(key);
  int rv =
      CreateAndSetWorkItem(nullptr, transaction, WI_DOOM_ENTRY, pending_op);
  if (rv != OK) {
    return rv;
  }

  RequestPriority priority = transaction ? transaction->priority() : LOWEST;
  rv = disk_cache_->DoomEntry(key, priority,
                              base::BindOnce(&HttpCache::OnPendingOpComplete,
                                             GetWeakPtr(), pending_op));
  if (rv == ERR_IO_PENDING) {
    pending_op->callback_will_delete = true;
    return rv;
  }

  pending_op->writer->ClearTransaction();
  OnPendingOpComplete(GetWeakPtr(), pending_op, rv);
  return rv;
}

void HttpCache::DoomMainEntryForUrl(
    const GURL& url,
    const NetworkIsolationKey& isolation_key,
    bool is_subframe_document_resource,
    bool is_main_frame_navigation,
    const std::optional<url::Origin>& initiator) {
  if (!disk_cache_) {
    return;
  }

  HttpRequestInfo temp_info;
  temp_info.url = url;
  temp_info.method = "GET";
  temp_info.network_isolation_key = isolation_key;
  temp_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateFromNetworkIsolationKey(isolation_key);
  temp_info.is_subframe_document_resource = is_subframe_document_resource;
  temp_info.is_main_frame_navigation = is_main_frame_navigation;
  temp_info.initiator = initiator;

  std::optional<std::string> key = GenerateCacheKeyForRequest(&temp_info);
  if (!key) {
    return;
  }

  // Defer to DoomEntry if there is an active entry, otherwise call
  // AsyncDoomEntry without triggering a callback.
  if (active_entries_.count(*key)) {
    D
```