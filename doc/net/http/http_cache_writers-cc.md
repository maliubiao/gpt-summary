Response:
Let's break down the thought process for analyzing this C++ code.

**1. Understanding the Request:**

The initial request asks for:

* **Functionality:** What does this code *do*?
* **JavaScript Relationship:**  Is there any interaction with JavaScript?
* **Logic & I/O:** Can we trace a simple input/output scenario?
* **Common Errors:** What mistakes do users or developers make related to this?
* **User Journey:** How does a user's action lead to this code being executed (debugging context)?

**2. Initial Code Scan and High-Level Purpose:**

The filename `http_cache_writers.cc` and the namespace `net` immediately suggest this code is part of the networking stack in Chromium and deals with writing data to the HTTP cache. Keywords like `Writers`, `Transaction`, `Entry`, `Read`, `WriteData`, `StopCaching`, `TruncateEntry` reinforce this idea. The copyright notice confirms it's Chromium code.

**3. Identifying Key Classes and Structures:**

* `HttpCache::Writers`: The central class. It manages multiple `Transaction` objects that want to write to the same cache entry.
* `HttpCache::Writers::TransactionInfo`:  Holds information about a specific writing transaction.
* `HttpCache::Transaction`: Represents a single HTTP transaction (request/response). We see methods like `priority()`, `WriterAboutToBeRemovedFromEntry()`, `AddDiskCacheWriteTime()`. This suggests it interacts with other parts of the networking stack.
* `HttpCache::ActiveEntry`: Represents an entry in the HTTP cache. Methods like `GetEntry()` and `WriteData()` indicate its role.
* `HttpTransaction`: Represents the actual network transaction. Methods like `Read()`, `GetResponseInfo()`, `CloseConnectionOnDestruction()`, `SetPriority()` confirm this.
* `IOBuffer`:  A common Chromium class for holding byte buffers.
* `CompletionOnceCallback`:  A function object for asynchronous operations.
* `PartialData`:  Handles partial content scenarios (like byte-range requests).

**4. Deciphering the Core Functionality - Writing to the Cache:**

The code seems to orchestrate concurrent writes to the HTTP cache. Several key aspects emerge:

* **Managing Concurrent Writes:** The `all_writers_` map stores active write transactions. The `parallel_writing_pattern_` and `is_exclusive_` variables control how concurrent writes are handled.
* **Network Reading and Cache Writing:** The `Read()` method fetches data from the network (via `HttpTransaction`) and then writes it to the cache (via `disk_cache::Entry::WriteData()`).
* **Handling Partial Content:** The `PartialData` class and related logic (like checking `info.partial`) handle situations where only parts of a resource are being cached.
* **Truncation:** The `TruncateEntry()` method and related checks determine when and how to mark a cache entry as incomplete if the download is interrupted.
* **Error Handling:**  The `ProcessFailure()` method and various error checks ensure that failures are handled gracefully and waiting transactions are notified.
* **Prioritization:**  The `priority_` member and calls to `network_transaction_->SetPriority()` indicate that the code considers request priorities.

**5. Identifying JavaScript Relationship (or lack thereof):**

Careful examination reveals no direct interaction with JavaScript APIs. The code operates within the networking stack, which is implemented in C++. However, it *indirectly* affects JavaScript by controlling how cached resources are served to web pages. This is a crucial distinction. The *example* focuses on how a JavaScript fetch might *trigger* the cache writing process.

**6. Logic and I/O Example:**

A simple scenario is chosen: a successful GET request. The steps are traced from the `Read()` call to the successful cache write and notification of waiting transactions. The input is the `IOBuffer` and its size, and the output is the number of bytes written.

**7. Common User/Programming Errors:**

The focus here is on *developer* errors in the Chromium codebase itself, as this is internal networking code. Examples include incorrect usage of `StopCaching()` and mishandling of partial content.

**8. User Journey and Debugging:**

The explanation starts with a high-level user action (clicking a link) and drills down through the networking layers until it reaches the `HttpCache::Writers::Read()` method. This provides a clear debugging context. Key components like the `ResourceRequest`, `HttpNetworkTransaction`, and `HttpCache` are mentioned.

**9. Refinement and Language:**

Throughout the analysis, clear and concise language is used. Technical terms are explained where necessary. The formatting of the code snippets and the output examples is important for readability. The "Assumptions" section adds clarity to the logic example.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe there's a direct JavaScript API call. **Correction:**  No direct calls, but indirect impact.
* **Initial thought:** Focus only on successful scenarios. **Correction:** Need to include error handling and truncation logic.
* **Initial thought:**  Describe every single method in detail. **Correction:** Focus on the key functionalities and how the methods contribute to them.
* **Initial thought:**  Assume the reader has deep knowledge of Chromium internals. **Correction:** Provide some context and explanations of key components.

By following these steps, a comprehensive and accurate analysis of the given C++ code can be achieved, addressing all aspects of the original request.
好的，让我们来详细分析一下 `net/http/http_cache_writers.cc` 这个 Chromium 网络栈的源代码文件。

**功能概览**

`http_cache_writers.cc` 文件的核心功能是**管理向 HTTP 缓存写入数据的操作**。 它负责协调多个可能同时发生的“写入者”（writers），确保数据被正确地写入缓存，并处理各种并发和错误情况。

更具体地说，它实现了 `HttpCache::Writers` 类，该类：

1. **管理多个事务 (Transactions) 对同一个缓存条目的写入操作。**  在 Chromium 中，一个 HTTP 请求/响应过程通常对应一个 `HttpTransaction`。当需要将响应数据缓存时，会创建一个或多个“写入者”来将数据写入缓存。
2. **处理并发写入。**  多个请求可能尝试写入相同的缓存条目（例如，范围请求）。`HttpCache::Writers` 负责协调这些写入操作，可能采用串行或并行的方式。
3. **从网络读取数据并写入缓存。**  它使用 `HttpTransaction` 从网络读取响应数据，并使用 `disk_cache::Entry` 将数据写入磁盘缓存。
4. **处理写入过程中的错误。**  例如，网络连接中断、磁盘写入失败等。
5. **支持部分内容写入（Partial Content）。**  处理针对资源特定范围的请求和缓存。
6. **管理缓存条目的生命周期。**  决定何时可以完成缓存条目的写入，以及在发生错误时是否需要截断（truncate）缓存条目。
7. **跟踪写入者的状态和优先级。**  根据优先级来调度网络读取操作。

**与 JavaScript 的关系**

`http_cache_writers.cc` 本身是用 C++ 编写的，**不直接包含 JavaScript 代码或直接调用 JavaScript API**。 然而，它在幕后支撑着浏览器中与 HTTP 缓存相关的 JavaScript 功能，例如：

* **`fetch()` API:**  当 JavaScript 使用 `fetch()` 发起 HTTP 请求时，浏览器会检查缓存。如果响应可以缓存，`http_cache_writers.cc` 中的代码将负责将响应数据写入缓存。
* **Service Workers:**  Service Workers 可以拦截网络请求，并提供来自缓存的响应。`http_cache_writers.cc` 参与了 Service Worker 对缓存的操作。
* **浏览器缓存策略:**  `http_cache_writers.cc` 的行为受到 HTTP 缓存头（如 `Cache-Control`）的影响，这些头部是在服务器响应中设置的，并由浏览器（包括 JavaScript）解析和遵守。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch()` 请求一个图片文件：

```javascript
fetch('https://example.com/image.png')
  .then(response => response.blob())
  .then(imageBlob => {
    // 使用 imageBlob
  });
```

在这个过程中，如果浏览器决定缓存 `image.png` 的响应，那么：

1. **网络请求:**  浏览器会发起对 `https://example.com/image.png` 的网络请求。
2. **响应接收:**  当服务器返回响应数据时，网络栈会接收这些数据。
3. **缓存写入 (C++):**  `http_cache_writers.cc` 中的代码会被调用，创建一个 `HttpCache::Writers` 对象来管理这次缓存写入。
4. **数据读取和写入:**  `HttpCache::Writers` 使用 `HttpTransaction` 读取响应体，并使用 `disk_cache::Entry` 将数据写入磁盘缓存。
5. **后续请求:**  如果 JavaScript 再次请求 `https://example.com/image.png`，浏览器可能会直接从缓存中读取，而不会再次发起网络请求，这得益于之前 `http_cache_writers.cc` 的工作。

**逻辑推理、假设输入与输出**

**假设输入:**

* 存在一个 `HttpCache::ActiveEntry` 对象，代表一个待写入的缓存条目。
* 创建一个 `HttpCache::Writers` 对象来管理对该条目的写入。
* 多个 `HttpCache::Transaction` 对象尝试向该条目写入数据。
* 从网络读取的数据块（`IOBuffer`）。

**逻辑推理 (以 `Read` 方法为例):**

1. **检查并发读取:** 如果当前有其他事务正在进行网络读取 (`next_state_ != State::NONE`)，则新的事务会被加入等待队列 (`waiting_for_read_`)。
2. **开始读取:** 如果没有并发读取，则当前事务被设置为活动事务 (`active_transaction_`)，并将状态设置为 `NETWORK_READ`。
3. **调用网络读取:**  调用 `DoLoop` 进入状态机，最终调用 `DoNetworkRead`，它会调用 `network_transaction_->Read` 从网络读取数据到提供的缓冲区 (`read_buf_`)。
4. **网络读取完成:** 当网络读取完成时（成功或失败），会调用 `OnIOComplete`，并将结果传递给 `DoLoop`，状态转移到 `NETWORK_READ_COMPLETE`。
5. **处理网络读取结果:**
   * **失败:** 如果网络读取失败 (`result < 0`)，则调用 `OnNetworkReadFailure` 处理错误，并可能截断缓存条目。
   * **成功:** 如果网络读取成功，则状态转移到 `CACHE_WRITE_DATA`。
6. **写入缓存:** 调用 `DoCacheWriteData`，它会使用 `entry_->GetEntry()->WriteData` 将从网络读取的数据写入磁盘缓存。
7. **缓存写入完成:** 当缓存写入完成时，调用 `OnIOComplete`，并将结果传递给 `DoLoop`，状态转移到 `CACHE_WRITE_DATA_COMPLETE`。
8. **处理缓存写入结果:**
   * **失败:** 如果缓存写入失败，则调用 `OnCacheWriteFailure` 处理错误。
   * **成功:** 如果缓存写入成功，则调用 `OnDataReceived` 通知等待的事务。

**假设输出 (针对成功的 `Read` 操作):**

* 返回 `OK` 表示成功读取并写入缓存。
* `active_transaction_` 指向的事务成功接收到从网络读取的数据。
* 数据被成功写入到 `HttpCache::ActiveEntry` 对应的磁盘缓存中。
* 等待队列中的其他事务可能会被唤醒并接收到相同的数据（取决于并行写入模式）。

**用户或编程常见的使用错误**

由于 `http_cache_writers.cc` 是 Chromium 内部网络栈的一部分，普通用户不会直接与之交互。常见的错误更多是**编程错误**，通常发生在 Chromium 的开发者在实现或修改网络缓存功能时：

1. **不正确的并发控制:**  例如，在处理并发写入时出现竞态条件，导致数据损坏或写入不一致。
2. **错误的错误处理:**  例如，在网络读取或磁盘写入失败时没有正确处理，导致缓存状态异常。
3. **资源泄漏:**  例如，在事务完成后没有正确释放相关资源（如 `IOBuffer`）。
4. **违反缓存策略:**  例如，在不应该缓存响应时尝试缓存，或者在应该更新缓存时没有更新。
5. **部分内容处理不当:**  在处理范围请求时，可能出现边界条件错误，导致缓存的数据不完整或不正确。

**用户操作如何一步步到达这里 (调试线索)**

要调试与 `http_cache_writers.cc` 相关的问题，可以跟踪以下用户操作和 Chromium 内部流程：

1. **用户在浏览器中发起 HTTP 请求:** 例如，在地址栏输入 URL，点击链接，或 JavaScript 代码发起 `fetch()` 请求。
2. **Chromium 网络栈处理请求:**  Chromium 的网络栈会解析请求，并根据缓存策略决定是否需要从缓存中加载或发起新的网络请求。
3. **未命中缓存或需要更新:** 如果缓存中没有对应的资源，或者缓存的资源已过期需要更新，则会发起网络请求。
4. **`HttpNetworkTransaction` 创建:**  Chromium 会创建一个 `HttpNetworkTransaction` 对象来处理网络通信。
5. **接收到响应数据:** 当服务器返回响应数据时，`HttpNetworkTransaction` 会接收这些数据。
6. **缓存写入决策:**  根据响应头中的缓存控制指令（如 `Cache-Control`），Chromium 决定是否需要缓存该响应。
7. **`HttpCache::Writers` 创建:** 如果需要缓存，`HttpCache` 会创建一个 `HttpCache::Writers` 对象，关联到对应的 `HttpCache::ActiveEntry`。
8. **`HttpCache::Writers::AddTransaction`:**  与当前请求关联的 `HttpTransaction` 会被添加到 `HttpCache::Writers` 中，成为一个写入者。
9. **`HttpCache::Writers::Read`:**  `HttpCache::Writers` 开始从 `HttpNetworkTransaction` 读取响应数据。用户操作的后续影响（例如，继续浏览页面，导致更多数据被下载）可能会触发多次 `Read` 调用。
10. **`disk_cache::Entry::WriteData`:**  读取到的数据会被传递给磁盘缓存系统进行写入。

**调试线索:**

* **网络日志 (net-internals):**  使用 `chrome://net-internals/#events` 可以查看详细的网络事件，包括缓存相关的操作。搜索与特定 URL 或缓存条目相关的事件，可以追踪缓存写入的过程。
* **断点调试:**  在 `http_cache_writers.cc` 的关键方法（如 `Read`、`DoNetworkReadComplete`、`DoCacheWriteDataComplete`）设置断点，可以单步执行代码，查看变量的值和状态变化。
* **日志输出:**  Chromium 的日志系统可以输出与缓存相关的调试信息。启用详细的网络日志可以帮助诊断问题。
* **检查缓存状态:**  使用 `chrome://cache/` 可以查看当前缓存中的条目，以及它们的元数据。

希望以上分析能够帮助你理解 `net/http/http_cache_writers.cc` 的功能和作用。这是一个网络栈中非常核心且复杂的模块，涉及到多个组件的协作。

Prompt: 
```
这是目录为net/http/http_cache_writers.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_cache_writers.h"

#include <algorithm>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/not_fatal_until.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/disk_cache.h"
#include "net/http/http_cache_transaction.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/http/partial_data.h"

namespace net {

namespace {

bool IsValidResponseForWriter(bool is_partial,
                              const HttpResponseInfo* response_info) {
  if (!response_info->headers.get()) {
    return false;
  }

  // Return false if the response code sent by the server is garbled.
  // Both 200 and 304 are valid since concurrent writing is supported.
  if (!is_partial &&
      (response_info->headers->response_code() != HTTP_OK &&
       response_info->headers->response_code() != HTTP_NOT_MODIFIED)) {
    return false;
  }

  return true;
}

}  // namespace

HttpCache::Writers::TransactionInfo::TransactionInfo(PartialData* partial_data,
                                                     const bool is_truncated,
                                                     HttpResponseInfo info)
    : partial(partial_data), truncated(is_truncated), response_info(info) {}

HttpCache::Writers::TransactionInfo::~TransactionInfo() = default;

HttpCache::Writers::TransactionInfo::TransactionInfo(const TransactionInfo&) =
    default;

HttpCache::Writers::Writers(HttpCache* cache,
                            scoped_refptr<HttpCache::ActiveEntry> entry)
    : cache_(cache), entry_(entry) {
  DCHECK(cache_);
  DCHECK(entry_);
}

HttpCache::Writers::~Writers() = default;

int HttpCache::Writers::Read(scoped_refptr<IOBuffer> buf,
                             int buf_len,
                             CompletionOnceCallback callback,
                             Transaction* transaction) {
  DCHECK(buf);
  DCHECK_GT(buf_len, 0);
  DCHECK(!callback.is_null());
  DCHECK(transaction);

  // If another transaction invoked a Read which is currently ongoing, then
  // this transaction waits for the read to complete and gets its buffer filled
  // with the data returned from that read.
  if (next_state_ != State::NONE) {
    WaitingForRead read_info(buf, buf_len, std::move(callback));
    waiting_for_read_.emplace(transaction, std::move(read_info));
    return ERR_IO_PENDING;
  }

  DCHECK_EQ(next_state_, State::NONE);
  DCHECK(callback_.is_null());
  DCHECK_EQ(nullptr, active_transaction_);
  DCHECK(HasTransaction(transaction));
  active_transaction_ = transaction;

  read_buf_ = std::move(buf);
  io_buf_len_ = buf_len;
  next_state_ = State::NETWORK_READ;

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    callback_ = std::move(callback);
  }

  return rv;
}

bool HttpCache::Writers::StopCaching(bool keep_entry) {
  // If this is the only transaction in Writers, then stopping will be
  // successful. If not, then we will not stop caching since there are
  // other consumers waiting to read from the cache.
  if (all_writers_.size() != 1) {
    return false;
  }

  network_read_only_ = true;
  if (!keep_entry) {
    should_keep_entry_ = false;
    cache_->WritersDoomEntryRestartTransactions(entry_.get());
  }

  return true;
}

void HttpCache::Writers::AddTransaction(
    Transaction* transaction,
    ParallelWritingPattern initial_writing_pattern,
    RequestPriority priority,
    const TransactionInfo& info) {
  DCHECK(transaction);
  ParallelWritingPattern writers_pattern;
  DCHECK(CanAddWriters(&writers_pattern));

  DCHECK_EQ(0u, all_writers_.count(transaction));

  // Set truncation related information.
  response_info_truncation_ = info.response_info;
  should_keep_entry_ =
      IsValidResponseForWriter(info.partial != nullptr, &(info.response_info));

  if (all_writers_.empty()) {
    DCHECK_EQ(PARALLEL_WRITING_NONE, parallel_writing_pattern_);
    parallel_writing_pattern_ = initial_writing_pattern;
    if (parallel_writing_pattern_ != PARALLEL_WRITING_JOIN) {
      is_exclusive_ = true;
    }
  } else {
    DCHECK_EQ(PARALLEL_WRITING_JOIN, parallel_writing_pattern_);
  }

  if (info.partial && !info.truncated) {
    DCHECK(!partial_do_not_truncate_);
    partial_do_not_truncate_ = true;
  }

  std::pair<Transaction*, TransactionInfo> writer(transaction, info);
  all_writers_.insert(writer);

  priority_ = std::max(priority, priority_);
  if (network_transaction_) {
    network_transaction_->SetPriority(priority_);
  }
}

void HttpCache::Writers::SetNetworkTransaction(
    Transaction* transaction,
    std::unique_ptr<HttpTransaction> network_transaction) {
  DCHECK_EQ(1u, all_writers_.count(transaction));
  DCHECK(network_transaction);
  DCHECK(!network_transaction_);
  network_transaction_ = std::move(network_transaction);
  network_transaction_->SetPriority(priority_);
}

void HttpCache::Writers::ResetNetworkTransaction() {
  DCHECK(is_exclusive_);
  DCHECK_EQ(1u, all_writers_.size());
  DCHECK(all_writers_.begin()->second.partial);
  network_transaction_.reset();
}

void HttpCache::Writers::RemoveTransaction(Transaction* transaction,
                                           bool success) {
  EraseTransaction(transaction, OK);

  if (!all_writers_.empty()) {
    return;
  }

  if (!success && ShouldTruncate()) {
    TruncateEntry();
  }

  // Destroys `this`.
  cache_->WritersDoneWritingToEntry(entry_, success, should_keep_entry_,
                                    TransactionSet());
}

void HttpCache::Writers::EraseTransaction(Transaction* transaction,
                                          int result) {
  // The transaction should be part of all_writers.
  auto it = all_writers_.find(transaction);
  CHECK(it != all_writers_.end(), base::NotFatalUntil::M130);
  EraseTransaction(it, result);
}

HttpCache::Writers::TransactionMap::iterator
HttpCache::Writers::EraseTransaction(TransactionMap::iterator it, int result) {
  Transaction* transaction = it->first;
  transaction->WriterAboutToBeRemovedFromEntry(result);

  auto return_it = all_writers_.erase(it);

  if (all_writers_.empty() && next_state_ == State::NONE) {
    // This needs to be called to handle the edge case where even before Read is
    // invoked all transactions are removed. In that case the
    // network_transaction_ will still have a valid request info and so it
    // should be destroyed before its consumer is destroyed (request info
    // is a raw pointer owned by its consumer).
    network_transaction_.reset();
  } else {
    UpdatePriority();
  }

  if (active_transaction_ == transaction) {
    active_transaction_ = nullptr;
  } else {
    // If waiting for read, remove it from the map.
    waiting_for_read_.erase(transaction);
  }
  return return_it;
}

void HttpCache::Writers::UpdatePriority() {
  // Get the current highest priority.
  RequestPriority current_highest = MINIMUM_PRIORITY;
  for (auto& writer : all_writers_) {
    Transaction* transaction = writer.first;
    current_highest = std::max(transaction->priority(), current_highest);
  }

  if (priority_ != current_highest) {
    if (network_transaction_) {
      network_transaction_->SetPriority(current_highest);
    }
    priority_ = current_highest;
  }
}

void HttpCache::Writers::CloseConnectionOnDestruction() {
  if (network_transaction_) {
    network_transaction_->CloseConnectionOnDestruction();
  }
}

bool HttpCache::Writers::ContainsOnlyIdleWriters() const {
  return waiting_for_read_.empty() && !active_transaction_;
}

bool HttpCache::Writers::CanAddWriters(ParallelWritingPattern* reason) {
  *reason = parallel_writing_pattern_;

  if (all_writers_.empty()) {
    return true;
  }

  return !is_exclusive_ && !network_read_only_;
}

void HttpCache::Writers::ProcessFailure(int error) {
  // Notify waiting_for_read_ of the failure. Tasks will be posted for all the
  // transactions.
  CompleteWaitingForReadTransactions(error);

  // Idle readers should fail when Read is invoked on them.
  RemoveIdleWriters(error);
}

void HttpCache::Writers::TruncateEntry() {
  DCHECK(ShouldTruncate());
  auto data = base::MakeRefCounted<PickledIOBuffer>();
  response_info_truncation_.Persist(data->pickle(),
                                    true /* skip_transient_headers*/,
                                    true /* response_truncated */);
  data->Done();
  io_buf_len_ = data->pickle()->size();
  entry_->GetEntry()->WriteData(kResponseInfoIndex, 0, data.get(), io_buf_len_,
                                base::DoNothing(), true);
}

bool HttpCache::Writers::ShouldTruncate() {
  // Don't set the flag for sparse entries or for entries that cannot be
  // resumed.
  if (!should_keep_entry_ || partial_do_not_truncate_) {
    return false;
  }

  // Check the response headers for strong validators.
  // Note that if this is a 206, content-length was already fixed after calling
  // PartialData::ResponseHeadersOK().
  if (response_info_truncation_.headers->GetContentLength() <= 0 ||
      response_info_truncation_.headers->HasHeaderValue("Accept-Ranges",
                                                        "none") ||
      !response_info_truncation_.headers->HasStrongValidators()) {
    should_keep_entry_ = false;
    return false;
  }

  // Double check that there is something worth keeping.
  int current_size = entry_->GetEntry()->GetDataSize(kResponseContentIndex);
  if (!current_size) {
    should_keep_entry_ = false;
    return false;
  }

  if (response_info_truncation_.headers->HasHeader("Content-Encoding")) {
    should_keep_entry_ = false;
    return false;
  }

  int64_t content_length =
      response_info_truncation_.headers->GetContentLength();
  if (content_length >= 0 && content_length <= current_size) {
    return false;
  }

  return true;
}

LoadState HttpCache::Writers::GetLoadState() const {
  if (network_transaction_) {
    return network_transaction_->GetLoadState();
  }
  return LOAD_STATE_IDLE;
}

HttpCache::Writers::WaitingForRead::WaitingForRead(
    scoped_refptr<IOBuffer> buf,
    int len,
    CompletionOnceCallback consumer_callback)
    : read_buf(std::move(buf)),
      read_buf_len(len),
      callback(std::move(consumer_callback)) {
  DCHECK(read_buf);
  DCHECK_GT(len, 0);
  DCHECK(!callback.is_null());
}

HttpCache::Writers::WaitingForRead::~WaitingForRead() = default;
HttpCache::Writers::WaitingForRead::WaitingForRead(WaitingForRead&&) = default;

int HttpCache::Writers::DoLoop(int result) {
  DCHECK_NE(State::UNSET, next_state_);
  DCHECK_NE(State::NONE, next_state_);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = State::UNSET;
    switch (state) {
      case State::NETWORK_READ:
        DCHECK_EQ(OK, rv);
        rv = DoNetworkRead();
        break;
      case State::NETWORK_READ_COMPLETE:
        rv = DoNetworkReadComplete(rv);
        break;
      case State::CACHE_WRITE_DATA:
        rv = DoCacheWriteData(rv);
        break;
      case State::CACHE_WRITE_DATA_COMPLETE:
        rv = DoCacheWriteDataComplete(rv);
        break;
      case State::UNSET:
        NOTREACHED() << "bad state";
      case State::NONE:
        // Do Nothing.
        break;
    }
  } while (next_state_ != State::NONE && rv != ERR_IO_PENDING);

  if (next_state_ != State::NONE) {
    if (rv != ERR_IO_PENDING && !callback_.is_null()) {
      std::move(callback_).Run(rv);
    }
    return rv;
  }

  // Save the callback as |this| may be destroyed when |cache_callback_| is run.
  // Note that |callback_| is intentionally reset even if it is not run.
  CompletionOnceCallback callback = std::move(callback_);
  read_buf_ = nullptr;
  DCHECK(!all_writers_.empty() || cache_callback_);
  if (cache_callback_) {
    std::move(cache_callback_).Run();
  }
  // |this| may have been destroyed in the |cache_callback_|.
  if (rv != ERR_IO_PENDING && !callback.is_null()) {
    std::move(callback).Run(rv);
  }
  return rv;
}

int HttpCache::Writers::DoNetworkRead() {
  DCHECK(network_transaction_);
  next_state_ = State::NETWORK_READ_COMPLETE;

  // TODO(crbug.com/40089413): This is a partial mitigation. When
  // reading from the network, a valid HttpNetworkTransaction must be always
  // available.
  if (!network_transaction_) {
    return ERR_FAILED;
  }

  CompletionOnceCallback io_callback = base::BindOnce(
      &HttpCache::Writers::OnIOComplete, weak_factory_.GetWeakPtr());
  return network_transaction_->Read(read_buf_.get(), io_buf_len_,
                                    std::move(io_callback));
}

int HttpCache::Writers::DoNetworkReadComplete(int result) {
  if (result < 0) {
    next_state_ = State::NONE;
    OnNetworkReadFailure(result);
    return result;
  }

  next_state_ = State::CACHE_WRITE_DATA;
  return result;
}

void HttpCache::Writers::OnNetworkReadFailure(int result) {
  ProcessFailure(result);

  if (active_transaction_) {
    EraseTransaction(active_transaction_, result);
  }
  active_transaction_ = nullptr;

  if (ShouldTruncate()) {
    TruncateEntry();
  }

  SetCacheCallback(false, TransactionSet());
}

int HttpCache::Writers::DoCacheWriteData(int num_bytes) {
  next_state_ = State::CACHE_WRITE_DATA_COMPLETE;
  write_len_ = num_bytes;
  if (!num_bytes || network_read_only_) {
    return num_bytes;
  }

  int current_size = entry_->GetEntry()->GetDataSize(kResponseContentIndex);
  CompletionOnceCallback io_callback = base::BindOnce(
      &HttpCache::Writers::OnIOComplete, weak_factory_.GetWeakPtr());

  int rv = 0;

  PartialData* partial = nullptr;
  // The active transaction must be alive if this is a partial request, as
  // partial requests are exclusive and hence will always be the active
  // transaction.
  // TODO(shivanisha): When partial requests support parallel writing, this
  // assumption will not be true.
  if (active_transaction_) {
    partial = all_writers_.find(active_transaction_)->second.partial;
  }

  if (!partial) {
    last_disk_cache_access_start_time_ = base::TimeTicks::Now();
    rv = entry_->GetEntry()->WriteData(kResponseContentIndex, current_size,
                                       read_buf_.get(), num_bytes,
                                       std::move(io_callback), true);
  } else {
    rv = partial->CacheWrite(entry_->GetEntry(), read_buf_.get(), num_bytes,
                             std::move(io_callback));
  }
  return rv;
}

int HttpCache::Writers::DoCacheWriteDataComplete(int result) {
  DCHECK(!all_writers_.empty());
  DCHECK_GE(write_len_, 0);

  if (result != write_len_) {
    next_state_ = State::NONE;

    // Note that it is possible for cache write to fail if the size of the file
    // exceeds the per-file limit.
    OnCacheWriteFailure();

    // |active_transaction_| can continue reading from the network.
    return write_len_;
  }

  if (!last_disk_cache_access_start_time_.is_null() && active_transaction_ &&
      !all_writers_.find(active_transaction_)->second.partial) {
    active_transaction_->AddDiskCacheWriteTime(
        base::TimeTicks::Now() - last_disk_cache_access_start_time_);
    last_disk_cache_access_start_time_ = base::TimeTicks();
  }

  next_state_ = State::NONE;
  OnDataReceived(write_len_);

  return write_len_;
}

void HttpCache::Writers::OnDataReceived(int result) {
  DCHECK(!all_writers_.empty());

  auto it = all_writers_.find(active_transaction_);
  bool is_partial =
      active_transaction_ != nullptr && it->second.partial != nullptr;

  // Partial transaction will process the result, return from here.
  // This is done because partial requests handling require an awareness of both
  // headers and body state machines as they might have to go to the headers
  // phase for the next range, so it cannot be completely handled here.
  if (is_partial) {
    active_transaction_ = nullptr;
    return;
  }

  if (result == 0) {
    // Check if the response is actually completed or if not, attempt to mark
    // the entry as truncated in OnNetworkReadFailure.
    int current_size = entry_->GetEntry()->GetDataSize(kResponseContentIndex);
    DCHECK(network_transaction_);
    const HttpResponseInfo* response_info =
        network_transaction_->GetResponseInfo();
    int64_t content_length = response_info->headers->GetContentLength();
    if (content_length >= 0 && content_length > current_size) {
      OnNetworkReadFailure(result);
      return;
    }

    if (active_transaction_) {
      EraseTransaction(active_transaction_, result);
    }
    active_transaction_ = nullptr;
    CompleteWaitingForReadTransactions(write_len_);

    // Invoke entry processing.
    DCHECK(ContainsOnlyIdleWriters());
    TransactionSet make_readers;
    for (auto& writer : all_writers_) {
      make_readers.insert(writer.first);
    }
    all_writers_.clear();
    SetCacheCallback(true, make_readers);
    // We assume the set callback will be called immediately.
    DCHECK_EQ(next_state_, State::NONE);
    return;
  }

  // Notify waiting_for_read_. Tasks will be posted for all the
  // transactions.
  CompleteWaitingForReadTransactions(write_len_);

  active_transaction_ = nullptr;
}

void HttpCache::Writers::OnCacheWriteFailure() {
  DLOG(ERROR) << "failed to write response data to cache";

  ProcessFailure(ERR_CACHE_WRITE_FAILURE);

  // Now writers will only be reading from the network.
  network_read_only_ = true;

  active_transaction_ = nullptr;

  should_keep_entry_ = false;
  if (all_writers_.empty()) {
    SetCacheCallback(false, TransactionSet());
  } else {
    cache_->WritersDoomEntryRestartTransactions(entry_.get());
  }
}

void HttpCache::Writers::CompleteWaitingForReadTransactions(int result) {
  for (auto it = waiting_for_read_.begin(); it != waiting_for_read_.end();) {
    Transaction* transaction = it->first;
    int callback_result = result;

    if (result >= 0) {  // success
      // Save the data in the waiting transaction's read buffer.
      it->second.write_len = std::min(it->second.read_buf_len, result);
      memcpy(it->second.read_buf->data(), read_buf_->data(),
             it->second.write_len);
      callback_result = it->second.write_len;
    }

    // Post task to notify transaction.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(it->second.callback), callback_result));

    it = waiting_for_read_.erase(it);

    // If its response completion or failure, this transaction needs to be
    // removed from writers.
    if (result <= 0) {
      EraseTransaction(transaction, result);
    }
  }
}

void HttpCache::Writers::RemoveIdleWriters(int result) {
  // Since this is only for idle transactions, waiting_for_read_
  // should be empty.
  DCHECK(waiting_for_read_.empty());
  for (auto it = all_writers_.begin(); it != all_writers_.end();) {
    Transaction* transaction = it->first;
    if (transaction == active_transaction_) {
      it++;
      continue;
    }
    it = EraseTransaction(it, result);
  }
}

void HttpCache::Writers::SetCacheCallback(bool success,
                                          const TransactionSet& make_readers) {
  DCHECK(!cache_callback_);
  cache_callback_ = base::BindOnce(&HttpCache::WritersDoneWritingToEntry,
                                   cache_->GetWeakPtr(), entry_, success,
                                   should_keep_entry_, make_readers);
}

void HttpCache::Writers::OnIOComplete(int result) {
  DoLoop(result);
}

}  // namespace net

"""

```