Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Core Functionality:**

The first step is to understand the high-level purpose of the `in_flight_backend_io.cc` file. Keywords like `disk_cache`, `BackendIO`, `InFlightBackendIO`, `EntryImpl`, and the presence of asynchronous operations (`CompletionOnceCallback`) strongly suggest this file deals with managing I/O operations to a disk cache backend. The "in-flight" part suggests it handles operations that are currently being processed.

**2. Deconstructing the Classes:**

*   **`BackendIO`:** This class seems to represent a single, specific I/O operation. It holds the operation type (`operation_`), data related to the operation (key, buffers, offsets), and callbacks for when the operation completes. The various constructors indicate different types of operations (simple completion, entry results, range results). Methods like `ExecuteOperation`, `OnIOComplete`, and `OnDone` are typical for asynchronous operations.

*   **`InFlightBackendIO`:** This class acts as a controller or manager for `BackendIO` objects. It likely holds the queue of pending operations and interacts with the `BackendImpl` (the actual disk cache implementation). The methods here (e.g., `OpenOrCreateEntry`, `ReadData`) seem to be the API through which higher-level code requests cache operations. The `PostOperation` method signifies the dispatching of operations to a background thread.

**3. Identifying Key Operations:**

Scan through the `BackendIO` class and list out the different `operation_` types. This gives a good overview of what the cache can do: `INIT`, `OPEN_OR_CREATE`, `OPEN`, `CREATE`, `DOOM` (delete), `DOOM_ALL`, `DOOM_BETWEEN`, `DOOM_SINCE`, `SIZE_ALL`, `OPEN_NEXT` (for iteration), `END_ENUMERATION`, `ON_EXTERNAL_CACHE_HIT`, `CLOSE_ENTRY`, `DOOM_ENTRY`, `FLUSH_QUEUE`, `RUN_TASK`, `READ_DATA`, `WRITE_DATA`, `READ_SPARSE`, `WRITE_SPARSE`, `GET_RANGE`, `CANCEL_IO`, `IS_READY`.

**4. Determining Relationships to JavaScript (and Web Browsers):**

This is where some domain knowledge of web browsers and caching comes in handy. While this C++ code doesn't directly interact with JavaScript *within this file*, it's a fundamental part of the Chromium networking stack, which *does* interact with JavaScript.

*   **HTTP Caching:**  The most direct link is HTTP caching. When a web page is loaded, the browser's networking stack uses a disk cache to store resources (HTML, CSS, JavaScript, images, etc.). This C++ code is involved in the low-level management of that disk cache.
*   **Cache API:**  The browser's Cache API allows JavaScript to directly interact with the browser's HTTP cache. Operations in this C++ file are the underlying implementation for the actions initiated by the Cache API.
*   **Service Workers:** Service Workers can intercept network requests and use the Cache API. Therefore, actions within a Service Worker related to caching will eventually lead to the execution of code in files like this.

**5. Logical Reasoning (Hypothetical Input/Output):**

For this section, pick a few representative operations and think about the inputs and expected outputs.

*   **`OpenOrCreateEntry`:** Input: a cache key (string). Output: A `scoped_refptr<EntryImpl>` representing the cache entry (or an error if it fails).
*   **`ReadData`:** Input: An `EntryImpl`, an index, an offset, a buffer, and a length. Output: The buffer filled with data from the cache (or an error).
*   **`DoomEntry`:** Input: A cache key. Output: A success or failure code indicating if the entry was deleted.

**6. Identifying User/Programming Errors:**

Think about common mistakes developers might make when interacting with a cache or when the cache implementation itself might have issues.

*   **Incorrect Key Usage:** Providing the wrong key will result in cache misses or errors.
*   **Out-of-Bounds Access:** Trying to read or write beyond the valid data range of a cache entry.
*   **Concurrency Issues (Although less direct in this file):**  While `InFlightBackendIO` helps manage concurrency, incorrect higher-level usage could lead to race conditions.
*   **Resource Exhaustion:**  Filling the cache to its limit can cause write failures.

**7. Tracing User Actions (Debugging):**

Consider a simple user action and how it might lead to this code:

1. **User Types URL and Hits Enter:**  This initiates a network request.
2. **Browser Checks Cache:** The networking stack checks if the resource is in the cache.
3. **Cache Miss (or Force Refresh):** If the resource isn't found (or the user forces a refresh), a request is made to the server.
4. **Response Received:** The server sends the resource.
5. **Cache Storage:** The browser decides to cache the resource. This involves calling functions that eventually lead to `InFlightBackendIO::OpenOrCreateEntry` and `InFlightBackendIO::WriteData`.

**8. Structuring the Answer:**

Organize the information clearly using headings and bullet points as done in the example answer. This makes it easier to read and understand.

**Self-Correction/Refinement during the process:**

*   Initially, I might have focused too narrowly on the C++ code itself. I needed to broaden my perspective to include how it fits into the larger browser architecture and how JavaScript interacts with caching.
*   I made sure to explicitly mention that the *direct* interaction with JavaScript isn't present in *this specific file*, but the functionality it provides is essential for JavaScript-driven web caching.
*   I tried to provide concrete examples for the hypothetical input/output and user errors, rather than just abstract descriptions.
*   For the debugging section, I started with a high-level user action and worked my way down to the relevant code, which is the typical approach for debugging.
这个文件 `net/disk_cache/blockfile/in_flight_backend_io.cc` 是 Chromium 网络栈中磁盘缓存（disk_cache）模块的一部分，具体来说是 `blockfile` 后端的一个关键组件。它的主要功能是**管理和执行后台的 I/O 操作**，确保这些操作在后台线程安全地执行，并且将结果回调到主线程。

以下是该文件的详细功能列表：

**核心功能：管理和执行后台磁盘缓存 I/O 操作**

1. **异步操作调度:**  `InFlightBackendIO` 类负责接收来自主线程的磁盘缓存操作请求，并将这些操作调度到后台线程执行。
2. **操作封装:** `BackendIO` 类封装了一个具体的磁盘缓存操作，例如打开/创建/删除缓存条目、读取/写入数据等。它包含了执行操作所需的所有信息，例如操作类型、缓存条目的引用、数据缓冲区、偏移量等。
3. **后台线程执行:**  `BackendIO::ExecuteOperation()` 方法在后台线程中被调用，实际执行磁盘缓存的操作，例如调用 `BackendImpl` 或 `EntryImpl` 的同步方法。对于异步的读写操作，它会调用相应的异步方法并设置回调。
4. **结果回调:**  当后台操作完成后，`BackendIO::OnDone()` 方法在主线程中被调用，负责处理操作结果，并执行用户提供的回调函数 (`callback_`, `entry_result_callback_`, `range_result_callback_`)。
5. **并发控制:**  `InFlightBackendIO` 可以管理多个并发的后台 I/O 操作，确保这些操作的执行不会互相干扰，并且在合适的时机通知完成。
6. **性能监控:**  对于读写操作，`BackendIO::OnDone()` 会记录操作的耗时，用于性能分析 (`base::UmaHistogramCustomTimes`)。
7. **Entry 生命周期管理:**  `LeakEntryImpl` 函数用于向用户泄漏 `EntryImpl` 的强引用，以便用户可以继续操作缓存条目。`BackendIO` 的析构函数会处理 `EntryImpl` 的引用计数，确保在没有其他引用时释放资源。

**与 JavaScript 功能的关系**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所提供的磁盘缓存功能是 Web 浏览器运行 JavaScript 代码的重要基础设施。以下是一些关系示例：

*   **HTTP 缓存:**  当 JavaScript 代码发起网络请求（例如使用 `fetch` API 或 `XMLHttpRequest`）时，浏览器会使用磁盘缓存来存储响应资源（HTML、CSS、JavaScript 文件、图片等）。`InFlightBackendIO` 和相关的类负责处理这些资源的缓存和读取。
    *   **举例:**  当一个 Service Worker 拦截到一个 `fetch` 请求并决定从缓存中读取响应时，它会调用浏览器提供的 API，最终触发 `InFlightBackendIO::OpenEntry` 或 `InFlightBackendIO::OpenOrCreateEntry` 来查找或打开相应的缓存条目。然后，`InFlightBackendIO::ReadData` 会被调用来读取缓存的数据并返回给 Service Worker。
*   **Cache API:**  现代浏览器提供了 Cache API，允许 JavaScript 代码直接与浏览器的 HTTP 缓存进行交互。这个 API 的底层实现会使用到 `disk_cache` 模块，包括 `InFlightBackendIO`。
    *   **举例:**  JavaScript 代码可以使用 `caches.open('my-cache').then(cache => cache.put(request, response))` 来将一个响应存储到名为 "my-cache" 的缓存中。这个操作最终会调用到 `InFlightBackendIO::OpenOrCreateEntry` 和 `InFlightBackendIO::WriteData`。
*   **IndexedDB 和其他存储 API:**  虽然 `InFlightBackendIO` 主要用于 HTTP 缓存，但 Chromium 的其他存储机制（例如 IndexedDB）也可能使用类似的后台 I/O 机制，其设计思想与 `InFlightBackendIO` 类似。

**逻辑推理 (假设输入与输出)**

考虑 `InFlightBackendIO::OpenOrCreateEntry` 操作：

*   **假设输入:**
    *   `key`:  一个表示缓存条目的字符串键值，例如 "https://example.com/image.png"。
    *   `EntryResultCallback`: 一个在操作完成后被调用的回调函数，接收 `EntryResult` 对象。
*   **逻辑处理:**
    1. `InFlightBackendIO` 创建一个 `BackendIO` 对象，设置操作类型为 `OP_OPEN_OR_CREATE`，并将 `key` 存储在其中。
    2. `BackendIO` 对象被调度到后台线程执行。
    3. 在后台线程中，`BackendIO::ExecuteBackendOperation()` 被调用。
    4. `backend_->SyncOpenEntry(key_, &entry)` 尝试同步打开已存在的缓存条目。
    5. **情况 1：缓存条目存在:** `SyncOpenEntry` 返回 `net::OK`，并将 `EntryImpl` 对象赋值给 `entry`。`BackendIO` 将 `entry` 泄漏给用户 (`LeakEntryImpl`) 并标记为已打开。
    6. **情况 2：缓存条目不存在:** `SyncOpenEntry` 返回错误。`BackendIO` 尝试同步创建新的缓存条目 `backend_->SyncCreateEntry(key_, &entry)`。`BackendIO` 将新创建的 `entry` 泄漏给用户并标记为未打开。
    7. 后台操作完成，`BackendIO::NotifyController()` 通知 `InFlightBackendIO`。
    8. 在主线程中，`InFlightBackendIO::OnOperationComplete()` 被调用。
    9. `BackendIO::OnDone()` 被调用，根据 `result_` 和 `out_entry_opened_` 创建 `EntryResult` 对象。
    10. `BackendIO::RunEntryResultCallback()` 调用用户提供的回调函数，并将 `EntryResult` 对象传递给它。
*   **假设输出:**
    *   **如果缓存条目存在:** `EntryResult` 对象表示成功打开，包含指向已存在 `EntryImpl` 的指针。
    *   **如果缓存条目不存在:** `EntryResult` 对象表示成功创建，包含指向新创建 `EntryImpl` 的指针。
    *   **如果发生错误 (例如磁盘空间不足):** `EntryResult` 对象表示错误，包含相应的 `net::Error` 代码。

**用户或编程常见的使用错误**

1. **在错误的线程上操作 `EntryImpl`:** `EntryImpl` 对象通常只能在创建它的后台线程上安全地访问。如果用户在主线程或其他非法的线程上直接调用 `EntryImpl` 的方法，可能会导致数据竞争和崩溃。`InFlightBackendIO` 的设计正是为了避免这个问题，强制所有操作都通过后台线程进行。
2. **忘记关闭 `EntryImpl`:**  通过 `LeakEntryImpl` 泄漏的 `EntryImpl` 需要在使用完毕后通过调用 `Close()` 方法来释放资源。忘记关闭会导致资源泄漏。虽然 `BackendIO` 的析构函数会尝试处理这种情况，但这是一种不推荐的做法，应该显式关闭。
3. **在回调函数返回后继续使用 `EntryImpl`:**  一旦与某个 `BackendIO` 操作相关的回调函数返回，就应该停止使用该操作中涉及的 `EntryImpl` 对象，除非文档明确说明可以继续使用。这是因为在回调返回后，`EntryImpl` 的状态可能已经发生变化，例如被其他操作修改或删除。
4. **传递无效的参数给 `BackendIO` 操作:**  例如，传递负数的偏移量或长度给 `ReadData` 或 `WriteData` 操作，可能会导致断言失败或未定义的行为。
5. **没有处理错误回调:**  磁盘缓存操作可能会失败（例如磁盘空间不足，I/O 错误）。用户提供的回调函数应该检查操作结果，并适当地处理错误情况。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户在 Chrome 浏览器中访问了一个网页 `https://example.com/index.html`，并且浏览器需要从磁盘缓存中读取这个网页：

1. **用户在地址栏输入 URL 并回车:** 浏览器开始解析 URL 并启动导航过程。
2. **网络栈发起请求:**  网络栈的更上层组件（例如 ResourceLoader）会创建一个请求，请求获取 `https://example.com/index.html`。
3. **缓存查找:**  在发起网络请求之前，网络栈会检查本地缓存是否已经存在该资源。这通常涉及到查询缓存索引。
4. **缓存命中:** 如果缓存索引指示该资源存在于磁盘缓存中，网络栈会尝试从缓存中读取。
5. **调用 `disk_cache` 模块:**  网络栈会调用 `disk_cache` 模块的接口，请求打开或创建一个与该 URL 相关的缓存条目。这可能最终会调用到 `InFlightBackendIO::OpenEntry`。
6. **`InFlightBackendIO` 调度操作:**  `InFlightBackendIO` 创建一个 `BackendIO` 对象，并将打开缓存条目的操作调度到后台线程。
7. **后台线程执行 `OpenEntry`:**  后台线程执行 `BackendIO::ExecuteOperation()`，调用 `backend_->SyncOpenEntry()` 尝试打开缓存条目。
8. **获取 `EntryImpl`:**  如果缓存条目成功打开，会返回一个 `EntryImpl` 对象。
9. **读取数据:**  网络栈接着会调用 `disk_cache` 模块的接口来读取缓存条目的数据。这会调用到 `InFlightBackendIO::ReadData`。
10. **`InFlightBackendIO` 调度读取操作:** `InFlightBackendIO` 创建另一个 `BackendIO` 对象，并将读取数据的操作调度到后台线程。
11. **后台线程执行 `ReadData`:** 后台线程执行 `BackendIO::ExecuteOperation()`，调用 `entry_->ReadDataImpl()` 从磁盘读取数据。
12. **数据返回:** 读取的数据通过回调函数返回到网络栈。
13. **网页渲染:**  网络栈将读取到的 HTML 数据传递给渲染引擎，渲染引擎开始解析和渲染网页。

**调试线索:**

*   如果在调试过程中发现程序停留在 `InFlightBackendIO` 的某个方法中，例如 `PostOperation`，可能是由于后台线程繁忙或阻塞。
*   如果回调函数没有被按预期调用，可能是由于后台操作失败或 `InFlightBackendIO` 的逻辑错误。
*   可以使用断点和日志输出，跟踪 `BackendIO` 对象的创建、调度和执行过程，查看操作类型、键值、数据缓冲区等信息。
*   可以检查磁盘缓存的日志或状态，了解缓存的健康状况和操作历史。
*   使用 Chromium 的 tracing 工具 (chrome://tracing) 可以更详细地分析后台线程的活动和 I/O 操作。

总而言之，`net/disk_cache/blockfile/in_flight_backend_io.cc` 是 Chromium 磁盘缓存模块中负责后台 I/O 操作的核心组件，它确保了缓存操作的效率、安全性和异步性，是支撑浏览器快速加载网页和提供离线体验的关键基础设施。

Prompt: 
```
这是目录为net/disk_cache/blockfile/in_flight_backend_io.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/disk_cache/blockfile/in_flight_backend_io.h"

#include <utility>

#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/metrics/histogram_functions.h"
#include "base/notreached.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/net_errors.h"
#include "net/disk_cache/blockfile/backend_impl.h"
#include "net/disk_cache/blockfile/entry_impl.h"

namespace disk_cache {

namespace {

// Used to leak a strong reference to an EntryImpl to the user of disk_cache.
EntryImpl* LeakEntryImpl(scoped_refptr<EntryImpl> entry) {
  // Balanced on OP_CLOSE_ENTRY handling in BackendIO::ExecuteBackendOperation.
  if (entry)
    entry->AddRef();
  return entry.get();
}

}  // namespace

BackendIO::BackendIO(InFlightBackendIO* controller,
                     BackendImpl* backend,
                     net::CompletionOnceCallback callback)
    : BackendIO(controller, backend) {
  callback_ = std::move(callback);
}

BackendIO::BackendIO(InFlightBackendIO* controller,
                     BackendImpl* backend,
                     EntryResultCallback callback)
    : BackendIO(controller, backend) {
  entry_result_callback_ = std::move(callback);
}

BackendIO::BackendIO(InFlightBackendIO* controller,
                     BackendImpl* backend,
                     RangeResultCallback callback)
    : BackendIO(controller, backend) {
  range_result_callback_ = std::move(callback);
}

BackendIO::BackendIO(InFlightBackendIO* controller, BackendImpl* backend)
    : BackgroundIO(controller),
      backend_(backend),
      background_task_runner_(controller->background_thread()) {
  DCHECK(background_task_runner_);
  start_time_ = base::TimeTicks::Now();
}

// Runs on the background thread.
void BackendIO::ExecuteOperation() {
  if (IsEntryOperation()) {
    ExecuteEntryOperation();
  } else {
    ExecuteBackendOperation();
  }
  // Clear our pointer to entry we operated on.  We don't need it any more, and
  // it's possible by the time ~BackendIO gets destroyed on the main thread the
  // entry will have been closed and freed on the cache/background thread.
  entry_ = nullptr;
}

// Runs on the background thread.
void BackendIO::OnIOComplete(int result) {
  DCHECK(IsEntryOperation());
  DCHECK_NE(result, net::ERR_IO_PENDING);
  result_ = result;
  NotifyController();
}

// Runs on the primary thread.
void BackendIO::OnDone(bool cancel) {
  if (IsEntryOperation() && backend_->GetCacheType() == net::DISK_CACHE) {
    switch (operation_) {
      case OP_READ:
        base::UmaHistogramCustomTimes("DiskCache.0.TotalIOTimeRead",
                                      ElapsedTime(), base::Milliseconds(1),
                                      base::Seconds(10), 50);
        break;

      case OP_WRITE:
        base::UmaHistogramCustomTimes("DiskCache.0.TotalIOTimeWrite",
                                      ElapsedTime(), base::Milliseconds(1),
                                      base::Seconds(10), 50);
        break;

      default:
        // Other operations are not recorded.
        break;
    }
  }

  if (ReturnsEntry() && result_ == net::OK) {
    static_cast<EntryImpl*>(out_entry_)->OnEntryCreated(backend_);
    if (cancel)
      out_entry_.ExtractAsDangling()->Close();
  }
  ClearController();
}

bool BackendIO::IsEntryOperation() {
  return operation_ > OP_MAX_BACKEND;
}

void BackendIO::RunCallback(int result) {
  std::move(callback_).Run(result);
}

void BackendIO::RunEntryResultCallback() {
  EntryResult entry_result;
  if (result_ != net::OK) {
    entry_result = EntryResult::MakeError(static_cast<net::Error>(result()));
  } else if (out_entry_opened_) {
    entry_result = EntryResult::MakeOpened(out_entry_.ExtractAsDangling());
  } else {
    entry_result = EntryResult::MakeCreated(out_entry_.ExtractAsDangling());
  }
  std::move(entry_result_callback_).Run(std::move(entry_result));
}

void BackendIO::RunRangeResultCallback() {
  std::move(range_result_callback_).Run(range_result_);
}

void BackendIO::Init() {
  operation_ = OP_INIT;
}

void BackendIO::OpenOrCreateEntry(const std::string& key) {
  operation_ = OP_OPEN_OR_CREATE;
  key_ = key;
}

void BackendIO::OpenEntry(const std::string& key) {
  operation_ = OP_OPEN;
  key_ = key;
}

void BackendIO::CreateEntry(const std::string& key) {
  operation_ = OP_CREATE;
  key_ = key;
}

void BackendIO::DoomEntry(const std::string& key) {
  operation_ = OP_DOOM;
  key_ = key;
}

void BackendIO::DoomAllEntries() {
  operation_ = OP_DOOM_ALL;
}

void BackendIO::DoomEntriesBetween(const base::Time initial_time,
                                   const base::Time end_time) {
  operation_ = OP_DOOM_BETWEEN;
  initial_time_ = initial_time;
  end_time_ = end_time;
}

void BackendIO::DoomEntriesSince(const base::Time initial_time) {
  operation_ = OP_DOOM_SINCE;
  initial_time_ = initial_time;
}

void BackendIO::CalculateSizeOfAllEntries() {
  operation_ = OP_SIZE_ALL;
}

void BackendIO::OpenNextEntry(Rankings::Iterator* iterator) {
  operation_ = OP_OPEN_NEXT;
  iterator_ = iterator;
}

void BackendIO::EndEnumeration(std::unique_ptr<Rankings::Iterator> iterator) {
  operation_ = OP_END_ENUMERATION;
  scoped_iterator_ = std::move(iterator);
}

void BackendIO::OnExternalCacheHit(const std::string& key) {
  operation_ = OP_ON_EXTERNAL_CACHE_HIT;
  key_ = key;
}

void BackendIO::CloseEntryImpl(EntryImpl* entry) {
  operation_ = OP_CLOSE_ENTRY;
  entry_ = entry;
}

void BackendIO::DoomEntryImpl(EntryImpl* entry) {
  operation_ = OP_DOOM_ENTRY;
  entry_ = entry;
}

void BackendIO::FlushQueue() {
  operation_ = OP_FLUSH_QUEUE;
}

void BackendIO::RunTask(base::OnceClosure task) {
  operation_ = OP_RUN_TASK;
  task_ = std::move(task);
}

void BackendIO::ReadData(EntryImpl* entry, int index, int offset,
                         net::IOBuffer* buf, int buf_len) {
  operation_ = OP_READ;
  entry_ = entry;
  index_ = index;
  offset_ = offset;
  buf_ = buf;
  buf_len_ = buf_len;
}

void BackendIO::WriteData(EntryImpl* entry, int index, int offset,
                          net::IOBuffer* buf, int buf_len, bool truncate) {
  operation_ = OP_WRITE;
  entry_ = entry;
  index_ = index;
  offset_ = offset;
  buf_ = buf;
  buf_len_ = buf_len;
  truncate_ = truncate;
}

void BackendIO::ReadSparseData(EntryImpl* entry,
                               int64_t offset,
                               net::IOBuffer* buf,
                               int buf_len) {
  operation_ = OP_READ_SPARSE;
  entry_ = entry;
  offset64_ = offset;
  buf_ = buf;
  buf_len_ = buf_len;
}

void BackendIO::WriteSparseData(EntryImpl* entry,
                                int64_t offset,
                                net::IOBuffer* buf,
                                int buf_len) {
  operation_ = OP_WRITE_SPARSE;
  entry_ = entry;
  offset64_ = offset;
  buf_ = buf;
  buf_len_ = buf_len;
}

void BackendIO::GetAvailableRange(EntryImpl* entry, int64_t offset, int len) {
  operation_ = OP_GET_RANGE;
  entry_ = entry;
  offset64_ = offset;
  buf_len_ = len;
}

void BackendIO::CancelSparseIO(EntryImpl* entry) {
  operation_ = OP_CANCEL_IO;
  entry_ = entry;
}

void BackendIO::ReadyForSparseIO(EntryImpl* entry) {
  operation_ = OP_IS_READY;
  entry_ = entry;
}

BackendIO::~BackendIO() {
  if (!did_notify_controller_io_signalled() && out_entry_) {
    // At this point it's very likely the Entry does not have a
    // `background_queue_` so that Close() would do nothing. Post a task to the
    // background task runner to drop the reference, which should effectively
    // destroy if there are no more references. Destruction has to happen
    // on the background task runner.
    background_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&EntryImpl::Release,
                       base::Unretained(out_entry_.ExtractAsDangling())));
  }
}

bool BackendIO::ReturnsEntry() {
  return operation_ == OP_OPEN || operation_ == OP_CREATE ||
         operation_ == OP_OPEN_NEXT || operation_ == OP_OPEN_OR_CREATE;
}

base::TimeDelta BackendIO::ElapsedTime() const {
  return base::TimeTicks::Now() - start_time_;
}

// Runs on the background thread.
void BackendIO::ExecuteBackendOperation() {
  switch (operation_) {
    case OP_INIT:
      result_ = backend_->SyncInit();
      break;
    case OP_OPEN_OR_CREATE: {
      scoped_refptr<EntryImpl> entry;
      result_ = backend_->SyncOpenEntry(key_, &entry);

      if (result_ == net::OK) {
        out_entry_ = LeakEntryImpl(std::move(entry));
        out_entry_opened_ = true;
        break;
      }

      // Opening failed, create an entry instead.
      result_ = backend_->SyncCreateEntry(key_, &entry);
      out_entry_ = LeakEntryImpl(std::move(entry));
      out_entry_opened_ = false;
      break;
    }
    case OP_OPEN: {
      scoped_refptr<EntryImpl> entry;
      result_ = backend_->SyncOpenEntry(key_, &entry);
      out_entry_ = LeakEntryImpl(std::move(entry));
      out_entry_opened_ = true;
      break;
    }
    case OP_CREATE: {
      scoped_refptr<EntryImpl> entry;
      result_ = backend_->SyncCreateEntry(key_, &entry);
      out_entry_ = LeakEntryImpl(std::move(entry));
      out_entry_opened_ = false;
      break;
    }
    case OP_DOOM:
      result_ = backend_->SyncDoomEntry(key_);
      break;
    case OP_DOOM_ALL:
      result_ = backend_->SyncDoomAllEntries();
      break;
    case OP_DOOM_BETWEEN:
      result_ = backend_->SyncDoomEntriesBetween(initial_time_, end_time_);
      break;
    case OP_DOOM_SINCE:
      result_ = backend_->SyncDoomEntriesSince(initial_time_);
      break;
    case OP_SIZE_ALL:
      result_ = backend_->SyncCalculateSizeOfAllEntries();
      break;
    case OP_OPEN_NEXT: {
      scoped_refptr<EntryImpl> entry;
      result_ = backend_->SyncOpenNextEntry(iterator_, &entry);
      out_entry_ = LeakEntryImpl(std::move(entry));
      out_entry_opened_ = true;
      // `iterator_` is a proxied argument and not needed beyond this point. Set
      // it to nullptr so as to not leave a dangling pointer around.
      iterator_ = nullptr;
      break;
    }
    case OP_END_ENUMERATION:
      backend_->SyncEndEnumeration(std::move(scoped_iterator_));
      result_ = net::OK;
      break;
    case OP_ON_EXTERNAL_CACHE_HIT:
      backend_->SyncOnExternalCacheHit(key_);
      result_ = net::OK;
      break;
    case OP_CLOSE_ENTRY:
      // Collect the reference to |entry_| to balance with the AddRef() in
      // LeakEntryImpl.
      entry_.ExtractAsDangling()->Release();
      result_ = net::OK;
      break;
    case OP_DOOM_ENTRY:
      entry_->DoomImpl();
      result_ = net::OK;
      break;
    case OP_FLUSH_QUEUE:
      result_ = net::OK;
      break;
    case OP_RUN_TASK:
      std::move(task_).Run();
      result_ = net::OK;
      break;
    default:
      NOTREACHED() << "Invalid Operation";
  }
  DCHECK_NE(net::ERR_IO_PENDING, result_);
  NotifyController();
  backend_->OnSyncBackendOpComplete();
}

// Runs on the background thread.
void BackendIO::ExecuteEntryOperation() {
  switch (operation_) {
    case OP_READ:
      result_ =
          entry_->ReadDataImpl(index_, offset_, buf_.get(), buf_len_,
                               base::BindOnce(&BackendIO::OnIOComplete, this));
      break;
    case OP_WRITE:
      result_ = entry_->WriteDataImpl(
          index_, offset_, buf_.get(), buf_len_,
          base::BindOnce(&BackendIO::OnIOComplete, this), truncate_);
      break;
    case OP_READ_SPARSE:
      result_ = entry_->ReadSparseDataImpl(
          offset64_, buf_.get(), buf_len_,
          base::BindOnce(&BackendIO::OnIOComplete, this));
      break;
    case OP_WRITE_SPARSE:
      result_ = entry_->WriteSparseDataImpl(
          offset64_, buf_.get(), buf_len_,
          base::BindOnce(&BackendIO::OnIOComplete, this));
      break;
    case OP_GET_RANGE:
      range_result_ = entry_->GetAvailableRangeImpl(offset64_, buf_len_);
      result_ = range_result_.net_error;
      break;
    case OP_CANCEL_IO:
      entry_->CancelSparseIOImpl();
      result_ = net::OK;
      break;
    case OP_IS_READY:
      result_ = entry_->ReadyForSparseIOImpl(
          base::BindOnce(&BackendIO::OnIOComplete, this));
      break;
    default:
      NOTREACHED() << "Invalid Operation";
  }
  buf_ = nullptr;
  if (result_ != net::ERR_IO_PENDING)
    NotifyController();
}

InFlightBackendIO::InFlightBackendIO(
    BackendImpl* backend,
    const scoped_refptr<base::SingleThreadTaskRunner>& background_thread)
    : backend_(backend), background_thread_(background_thread) {}

InFlightBackendIO::~InFlightBackendIO() = default;

void InFlightBackendIO::Init(net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->Init();
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::OpenOrCreateEntry(const std::string& key,
                                          EntryResultCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->OpenOrCreateEntry(key);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::OpenEntry(const std::string& key,
                                  EntryResultCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->OpenEntry(key);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::CreateEntry(const std::string& key,
                                    EntryResultCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->CreateEntry(key);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomEntry(const std::string& key,
                                  net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->DoomEntry(key);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomAllEntries(net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->DoomAllEntries();
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomEntriesBetween(
    const base::Time initial_time,
    const base::Time end_time,
    net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->DoomEntriesBetween(initial_time, end_time);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::CalculateSizeOfAllEntries(
    net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->CalculateSizeOfAllEntries();
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomEntriesSince(const base::Time initial_time,
                                         net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->DoomEntriesSince(initial_time);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::OpenNextEntry(Rankings::Iterator* iterator,
                                      EntryResultCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->OpenNextEntry(iterator);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::EndEnumeration(
    std::unique_ptr<Rankings::Iterator> iterator) {
  auto operation = base::MakeRefCounted<BackendIO>(
      this, backend_, net::CompletionOnceCallback());
  operation->EndEnumeration(std::move(iterator));
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::OnExternalCacheHit(const std::string& key) {
  auto operation = base::MakeRefCounted<BackendIO>(
      this, backend_, net::CompletionOnceCallback());
  operation->OnExternalCacheHit(key);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::CloseEntryImpl(EntryImpl* entry) {
  auto operation = base::MakeRefCounted<BackendIO>(
      this, backend_, net::CompletionOnceCallback());
  operation->CloseEntryImpl(entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::DoomEntryImpl(EntryImpl* entry) {
  auto operation = base::MakeRefCounted<BackendIO>(
      this, backend_, net::CompletionOnceCallback());
  operation->DoomEntryImpl(entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::FlushQueue(net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->FlushQueue();
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::RunTask(base::OnceClosure task,
                                net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->RunTask(std::move(task));
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::ReadData(EntryImpl* entry,
                                 int index,
                                 int offset,
                                 net::IOBuffer* buf,
                                 int buf_len,
                                 net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->ReadData(entry, index, offset, buf, buf_len);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::WriteData(EntryImpl* entry,
                                  int index,
                                  int offset,
                                  net::IOBuffer* buf,
                                  int buf_len,
                                  bool truncate,
                                  net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->WriteData(entry, index, offset, buf, buf_len, truncate);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::ReadSparseData(EntryImpl* entry,
                                       int64_t offset,
                                       net::IOBuffer* buf,
                                       int buf_len,
                                       net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->ReadSparseData(entry, offset, buf, buf_len);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::WriteSparseData(EntryImpl* entry,
                                        int64_t offset,
                                        net::IOBuffer* buf,
                                        int buf_len,
                                        net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->WriteSparseData(entry, offset, buf, buf_len);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::GetAvailableRange(EntryImpl* entry,
                                          int64_t offset,
                                          int len,
                                          RangeResultCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->GetAvailableRange(entry, offset, len);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::CancelSparseIO(EntryImpl* entry) {
  auto operation = base::MakeRefCounted<BackendIO>(
      this, backend_, net::CompletionOnceCallback());
  operation->CancelSparseIO(entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::ReadyForSparseIO(EntryImpl* entry,
                                         net::CompletionOnceCallback callback) {
  auto operation =
      base::MakeRefCounted<BackendIO>(this, backend_, std::move(callback));
  operation->ReadyForSparseIO(entry);
  PostOperation(FROM_HERE, operation.get());
}

void InFlightBackendIO::WaitForPendingIO() {
  InFlightIO::WaitForPendingIO();
}

void InFlightBackendIO::OnOperationComplete(BackgroundIO* operation,
                                            bool cancel) {
  BackendIO* op = static_cast<BackendIO*>(operation);
  op->OnDone(cancel);

  if (op->has_callback() && (!cancel || op->IsEntryOperation()))
    op->RunCallback(op->result());

  if (op->has_range_result_callback()) {
    DCHECK(op->IsEntryOperation());
    op->RunRangeResultCallback();
  }

  if (op->has_entry_result_callback() && !cancel) {
    DCHECK(!op->IsEntryOperation());
    op->RunEntryResultCallback();
  }
}

void InFlightBackendIO::PostOperation(const base::Location& from_here,
                                      BackendIO* operation) {
  background_thread_->PostTask(
      from_here, base::BindOnce(&BackendIO::ExecuteOperation, operation));
  OnOperationPosted(operation);
}

base::WeakPtr<InFlightBackendIO> InFlightBackendIO::GetWeakPtr() {
  return ptr_factory_.GetWeakPtr();
}

}  // namespace disk_cache

"""

```