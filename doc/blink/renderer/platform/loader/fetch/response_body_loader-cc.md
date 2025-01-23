Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

**1. Initial Skim and Keyword Recognition:**

The first step is to quickly read through the code, looking for familiar keywords and patterns related to web technologies and networking. I'd be looking for:

* **`blink` namespace:**  Confirms it's part of the Blink rendering engine.
* **`loader`:**  Indicates involvement in resource loading.
* **`fetch`:**  Points to the Fetch API.
* **`response`:**  Suggests handling server responses.
* **`body`:**  Clearly deals with the content of the response.
* **`BytesConsumer`:**  An interface for reading byte streams, a fundamental part of network communication.
* **`DataPipe`:**  A Chromium mechanism for asynchronous data transfer.
* **`BlobDataHandle`, `EncodedFormData`:** Data structures related to web content.
* **`JavaScript`, `HTML`, `CSS`:** While not directly present in the code, these are the *outputs* of the loading process, so the functionality should be related.
* **`BackForwardCache`:**  A performance optimization, interesting to note its involvement.
* **`Suspend`, `Resume`, `Abort`:**  Lifecycle management related to loading.
* **`DidReceiveData`, `DidFinishLoadingBody`, `DidFailLoadingBody`, `DidCancelLoadingBody`:** Callback methods, revealing the purpose of the class.

**2. Identifying the Core Functionality:**

Based on the keywords and the overall structure, it becomes clear that `ResponseBodyLoader` is responsible for:

* **Reading the response body:**  Interacting with a `BytesConsumer` to get the raw bytes.
* **Delivering the data:**  Notifying a `ResponseBodyLoaderClient` about received data.
* **Handling different consumption methods:** Allowing the body to be consumed as a data pipe or a `BytesConsumer`.
* **Managing the loading lifecycle:** Starting, aborting, suspending, and resuming the loading process.
* **Integrating with the Back/Forward Cache:**  Special handling for cached pages.

**3. Deconstructing Key Components:**

* **`BytesConsumer` and `DelegatingBytesConsumer`:** Recognize the `BytesConsumer` as the primary interface for reading the data. The `DelegatingBytesConsumer` acts as a wrapper, adding features like lookahead and handling suspension. This is important for understanding the data flow.
* **`ResponseBodyLoaderClient`:** Identify this as the interface for receiving notifications about the loading progress.
* **`Buffer`:**  See this as a temporary storage mechanism, particularly for data received while the loader is suspended (especially for the back/forward cache).
* **Methods like `DrainAsDataPipe`, `DrainAsBytesConsumer`:** Understand these are for "handing off" the responsibility of consuming the data.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This requires thinking about the *purpose* of loading a response body. The content loaded by this class is ultimately what JavaScript, HTML, and CSS parsers and engines work with.

* **HTML:** The raw bytes might be the HTML document itself.
* **CSS:** The raw bytes could be the CSS stylesheet.
* **JavaScript:** The raw bytes could be the JavaScript code.

The `ResponseBodyLoader` doesn't *interpret* this content, but it ensures the raw data is available for those interpreters.

**5. Considering Logical Reasoning and Assumptions:**

Think about the different states the loader can be in and how data flows.

* **Assumption:** The `BytesConsumer` provides a stream of bytes.
* **Scenario:** If the loader is suspended, data is buffered. When resumed, the buffered data is dispatched.
* **Scenario:**  If `DrainAsDataPipe` is called, the underlying `BytesConsumer`'s data pipe is used, and the loader becomes a simple relay for completion/error signals.

**6. Identifying Potential User/Programming Errors:**

Focus on how the loader's API might be misused.

* **Calling methods in the wrong order:**  e.g., calling `Start` after draining.
* **Not handling errors:** The client needs to check for loading failures.
* **Misunderstanding the implications of `DrainAsDataPipe`:**  The original client loses direct data access.

**7. Structuring the Response:**

Organize the findings logically, using headings and bullet points for clarity. Start with a high-level summary of the functionality, then go into more detail about specific aspects, relating them to the prompt's questions about JavaScript, HTML, CSS, logic, and errors.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this class directly parses HTML/CSS/JS. **Correction:**  The code focuses on *reading* and *delivering* the bytes, not parsing. Parsing happens later in the pipeline.
* **Initial thought:** The `Buffer` is just for general temporary storage. **Refinement:** The code specifically links the `Buffer` to handling suspension, especially for the back/forward cache.
* **Ensure examples are clear and concise:**  Instead of just saying "handles HTML," give a brief scenario like downloading an HTML page.

By following these steps, combining code analysis with knowledge of web technologies, and applying some logical reasoning, it's possible to generate a comprehensive and accurate explanation of the `ResponseBodyLoader`'s functionality.
这个 `ResponseBodyLoader.cc` 文件是 Chromium Blink 引擎中负责加载 HTTP 响应体（response body）的关键组件。 它的主要功能是从网络或者缓存中读取响应的数据，并将这些数据传递给客户端进行处理。

以下是该文件的主要功能和相关说明：

**核心功能:**

1. **从 `BytesConsumer` 读取数据:**  `ResponseBodyLoader` 依赖于一个 `BytesConsumer` 接口的实例来实际获取响应体的数据。`BytesConsumer` 可以是网络堆栈提供的，也可以是来自缓存或其他来源。
2. **数据传递给客户端:**  它通过 `ResponseBodyLoaderClient` 接口向调用者（通常是资源加载器或渲染管线中的其他部分）传递接收到的数据块。
3. **处理加载完成、失败和取消:**  当响应体加载完成、失败或被取消时，它会通知 `ResponseBodyLoaderClient`。
4. **支持 Back/Forward Cache (BFCache):**  该类对 BFCache 提供了特殊的支持。当页面进入 BFCache 时，它可以暂停数据加载并缓存已接收的数据。当页面从 BFCache 恢复时，可以继续加载或直接使用缓存的数据。
5. **数据缓冲 (用于 BFCache):**  在页面进入 BFCache 后，接收到的数据会被临时存储在一个缓冲区 (`Buffer`) 中，直到页面被恢复。
6. **支持将响应体作为 DataPipe 或 BytesConsumer 传递:**  允许将底层的 `BytesConsumer` 或其数据管道的所有权转移给其他组件。
7. **处理加载的暂停和恢复:**  可以根据需要暂停和恢复响应体的加载。

**与 JavaScript, HTML, CSS 的关系举例:**

`ResponseBodyLoader` 负责下载构成网页的各种资源，包括 HTML 文档、CSS 样式表和 JavaScript 代码。

* **HTML:** 当浏览器请求一个 HTML 页面时，服务器返回的 HTML 内容会通过 `ResponseBodyLoader` 读取，然后传递给 HTML 解析器进行解析，最终构建 DOM 树。
    * **假设输入:**  `BytesConsumer` 提供了 HTML 文本 "<html><head><title>Example</title></head><body>Hello</body></html>"。
    * **输出:** `ResponseBodyLoader` 会将这段 HTML 文本分成若干块，并通过 `DidReceiveData` 方法传递给 HTML 解析器。
* **CSS:**  当浏览器加载一个 `<link rel="stylesheet" href="style.css">` 标签指定的 CSS 文件时，`ResponseBodyLoader` 会下载 `style.css` 的内容，并将其传递给 CSS 解析器，用于构建 CSSOM 树。
    * **假设输入:** `BytesConsumer` 提供了 CSS 文本 "body { background-color: red; }"。
    * **输出:** `ResponseBodyLoader` 会将这段 CSS 文本传递给 CSS 解析器。
* **JavaScript:**  当浏览器执行 `<script src="script.js"></script>` 标签时，`ResponseBodyLoader` 会下载 `script.js` 的代码，并将其传递给 JavaScript 引擎进行解析和执行。
    * **假设输入:** `BytesConsumer` 提供了 JavaScript 代码 "console.log('Hello from script.js');"。
    * **输出:** `ResponseBodyLoader` 会将这段 JavaScript 代码传递给 JavaScript 引擎。

**逻辑推理示例:**

* **假设输入:**  `ResponseBodyLoader` 正在加载一个大型图片，并且用户触发了浏览器的后退按钮，导致页面需要进入 BFCache。
* **逻辑推理:**
    1. `ResponseBodyLoader` 会收到暂停加载的指令 (`Suspend` 方法被调用)。
    2. 之后接收到的图片数据不会立即通过 `DidReceiveData` 传递给客户端。
    3. 这些数据会被添加到内部的 `body_buffer_` 中。
    4. 当用户点击前进按钮，页面从 BFCache 恢复 (`Resume` 方法被调用) 时，`ResponseBodyLoader` 会将 `body_buffer_` 中的数据通过 `DidReceiveData` 重新发送给客户端，然后继续从 `BytesConsumer` 读取剩余的数据。
* **假设输入:**  `ResponseBodyLoader` 正在加载一个资源，但 `BytesConsumer` 返回了一个错误 (例如，网络连接中断)。
* **逻辑推理:**
    1. `BytesConsumer` 的 `BeginRead` 或 `EndRead` 方法会返回一个错误状态 (`Result::kError`).
    2. `ResponseBodyLoader` 会调用 `DidFailLoadingBody` 通知 `ResponseBodyLoaderClient` 加载失败。
    3. 如果加载尚未完成，`ResponseBodyLoader` 可能会调用 `Abort` 来清理资源。

**用户或编程常见的使用错误举例:**

1. **过早地调用 `DrainAsDataPipe` 或 `DrainAsBytesConsumer`:**  这些方法用于转移响应体数据的所有权。如果在调用 `Start()` 之前或在加载过程中意外调用这些方法，可能会导致数据丢失或状态错误。
    * **错误示例:** 在 `ResourceLoader` 创建 `ResponseBodyLoader` 后立即调用 `DrainAsDataPipe`，而没有先 `Start()` 加载过程。这会导致 `*client` 指针为空，后续操作可能出错。
2. **未处理加载失败的情况:**  客户端代码必须实现 `ResponseBodyLoaderClient` 接口，并正确处理 `DidFailLoadingBody` 回调。忽略此回调可能导致程序在资源加载失败时出现未预期的行为。
    * **错误示例:**  一个图像加载器没有检查 `DidFailLoadingBody`，假设所有图像都会成功加载，导致在网络错误时显示空白图片或崩溃。
3. **在 BFCache 场景下错误地假设数据立即可用:**  在页面从 BFCache 恢复后，可能需要一些时间才能将缓存的数据重新传递给客户端。客户端代码不应假设数据在 `Resume` 调用后立即可用。
4. **在已 Abort 的 `ResponseBodyLoader` 上继续操作:**  一旦 `Abort` 被调用，`ResponseBodyLoader` 不应再用于加载数据。尝试这样做可能会导致未定义的行为。
    * **错误示例:** 在接收到 `DidCancelLoadingBody` 回调后，仍然尝试从 `ResponseBodyLoader` 消耗数据。

**总结:**

`ResponseBodyLoader` 是 Blink 渲染引擎中一个核心的低级别组件，负责从各种来源获取 HTTP 响应体的数据，并将其安全有效地传递给上层模块进行处理。它与网页的呈现息息相关，因为所有构成网页的资源（HTML, CSS, JavaScript, 图片等）都需要通过它来加载。理解其功能和生命周期对于理解 Blink 的资源加载机制至关重要。

### 提示词
```
这是目录为blink/renderer/platform/loader/fetch/response_body_loader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/fetch/response_body_loader.h"

#include <algorithm>
#include <utility>

#include "base/auto_reset.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "services/network/public/cpp/features.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/navigation/renderer_eviction_reason.mojom-blink.h"
#include "third_party/blink/renderer/platform/back_forward_cache_buffer_limit_tracker.h"
#include "third_party/blink/renderer/platform/back_forward_cache_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/back_forward_cache_loader_helper.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_context.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_loader.h"
#include "third_party/blink/renderer/platform/loader/fetch/url_loader/navigation_body_loader.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

class ResponseBodyLoader::DelegatingBytesConsumer final
    : public BytesConsumer,
      public BytesConsumer::Client {
 public:
  DelegatingBytesConsumer(
      BytesConsumer& bytes_consumer,
      ResponseBodyLoader& loader,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : bytes_consumer_(bytes_consumer),
        loader_(loader),
        task_runner_(std::move(task_runner)) {}

  Result BeginRead(base::span<const char>& buffer) override {
    buffer = {};
    if (loader_->IsAborted()) {
      return Result::kError;
    }
    // When the loader is suspended for non back/forward cache reason, return
    // with kShouldWait.
    if (IsSuspendedButNotForBackForwardCache()) {
      return Result::kShouldWait;
    }
    if (state_ == State::kCancelled) {
      return Result::kDone;
    }
    auto result = bytes_consumer_->BeginRead(buffer);
    if (result == Result::kOk) {
      buffer = buffer.first(std::min(buffer.size(), lookahead_bytes_));
      if (buffer.empty()) {
        result = bytes_consumer_->EndRead(0);
        buffer = {};
        if (result == Result::kOk) {
          result = Result::kShouldWait;
          if (in_on_state_change_) {
            waiting_for_lookahead_bytes_ = true;
          } else {
            task_runner_->PostTask(
                FROM_HERE,
                base::BindOnce(&DelegatingBytesConsumer::OnStateChange,
                               WrapPersistent(this)));
          }
        }
      }
    }
    HandleResult(result);
    return result;
  }
  Result EndRead(size_t read_size) override {
    DCHECK_LE(read_size, lookahead_bytes_);
    lookahead_bytes_ -= read_size;
    auto result = bytes_consumer_->EndRead(read_size);
    if (loader_->IsAborted()) {
      return Result::kError;
    }
    HandleResult(result);
    return result;
  }
  scoped_refptr<BlobDataHandle> DrainAsBlobDataHandle(
      BlobSizePolicy policy) override {
    if (loader_->IsAborted()) {
      return nullptr;
    }
    auto handle = bytes_consumer_->DrainAsBlobDataHandle(policy);
    if (handle) {
      HandleResult(Result::kDone);
    }
    return handle;
  }
  scoped_refptr<EncodedFormData> DrainAsFormData() override {
    if (loader_->IsAborted()) {
      return nullptr;
    }
    auto form_data = bytes_consumer_->DrainAsFormData();
    if (form_data) {
      HandleResult(Result::kDone);
    }
    return form_data;
  }
  mojo::ScopedDataPipeConsumerHandle DrainAsDataPipe() override {
    if (loader_->IsAborted()) {
      return {};
    }
    auto handle = bytes_consumer_->DrainAsDataPipe();
    if (handle && bytes_consumer_->GetPublicState() == PublicState::kClosed) {
      HandleResult(Result::kDone);
    }
    return handle;
  }
  void SetClient(BytesConsumer::Client* client) override {
    DCHECK(!bytes_consumer_client_);
    DCHECK(client);
    if (state_ != State::kLoading) {
      return;
    }
    bytes_consumer_client_ = client;
  }
  void ClearClient() override { bytes_consumer_client_ = nullptr; }
  void Cancel() override {
    if (state_ != State::kLoading) {
      return;
    }

    state_ = State::kCancelled;

    if (in_on_state_change_) {
      has_pending_state_change_signal_ = true;
      return;
    }
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(&DelegatingBytesConsumer::CancelSync,
                                          WrapWeakPersistent(this)));
  }
  PublicState GetPublicState() const override {
    if (loader_->IsAborted())
      return PublicState::kErrored;
    return bytes_consumer_->GetPublicState();
  }
  Error GetError() const override {
    if (bytes_consumer_->GetPublicState() == PublicState::kErrored) {
      return bytes_consumer_->GetError();
    }
    DCHECK(loader_->IsAborted());
    return Error{"Response body loading was aborted"};
  }
  String DebugName() const override {
    StringBuilder builder;
    builder.Append("DelegatingBytesConsumer(");
    builder.Append(bytes_consumer_->DebugName());
    builder.Append(")");
    return builder.ToString();
  }

  void Abort() {
    if (state_ != State::kLoading) {
      return;
    }
    if (bytes_consumer_client_) {
      bytes_consumer_client_->OnStateChange();
    }
  }

  void OnStateChange() override {
    DCHECK(!in_on_state_change_);
    DCHECK(!has_pending_state_change_signal_);
    DCHECK(!waiting_for_lookahead_bytes_);
    base::AutoReset<bool> auto_reset_for_in_on_state_change(
        &in_on_state_change_, true);
    base::AutoReset<bool> auto_reset_for_has_pending_state_change_signal(
        &has_pending_state_change_signal_, false);
    base::AutoReset<bool> auto_reset_for_waiting_for_lookahead_bytes(
        &waiting_for_lookahead_bytes_, false);

    // Do not proceed to read the data if loader is aborted, suspended for non
    // back/forward cache reason, or the state is cancelled.
    if (loader_->IsAborted() || IsSuspendedButNotForBackForwardCache() ||
        state_ == State::kCancelled) {
      return;
    }

    // Proceed to read the data, even if in back/forward cache.
    while (state_ == State::kLoading) {
      // Peek available bytes from |bytes_consumer_| and report them to
      // |loader_|.
      base::span<const char> buffer;
      // Possible state change caused by BeginRead will be realized by the
      // following logic, so we don't need to worry about it here.
      auto result = bytes_consumer_->BeginRead(buffer);
      if (result == Result::kOk) {
        if (lookahead_bytes_ < buffer.size()) {
          loader_->DidReceiveData(buffer.subspan(lookahead_bytes_));
          lookahead_bytes_ = buffer.size();
        }
        // Possible state change caused by EndRead will be realized by the
        // following logic, so we don't need to worry about it here.
        result = bytes_consumer_->EndRead(0);
      }
      waiting_for_lookahead_bytes_ = false;
      if ((result == Result::kOk || result == Result::kShouldWait) &&
          lookahead_bytes_ == 0) {
        // We have no information to notify the client.
        break;
      }
      if (bytes_consumer_client_) {
        bytes_consumer_client_->OnStateChange();
      }
      if (!waiting_for_lookahead_bytes_) {
        break;
      }
    }

    switch (GetPublicState()) {
      case PublicState::kReadableOrWaiting:
        break;
      case PublicState::kClosed:
        HandleResult(Result::kDone);
        break;
      case PublicState::kErrored:
        HandleResult(Result::kError);
        break;
    }

    if (has_pending_state_change_signal_) {
      switch (state_) {
        case State::kLoading:
          NOTREACHED();
        case State::kDone:
          loader_->DidFinishLoadingBody();
          break;
        case State::kErrored:
          loader_->DidFailLoadingBody();
          break;
        case State::kCancelled:
          CancelSync();
          break;
      }
    }
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(bytes_consumer_);
    visitor->Trace(loader_);
    visitor->Trace(bytes_consumer_client_);
    BytesConsumer::Trace(visitor);
  }

 private:
  enum class State {
    kLoading,
    kDone,
    kErrored,
    kCancelled,
  };

  void CancelSync() {
    bytes_consumer_->Cancel();
    loader_->DidCancelLoadingBody();
  }

  void HandleResult(Result result) {
    if (state_ != State::kLoading) {
      return;
    }

    if (result == Result::kDone) {
      state_ = State::kDone;
      if (in_on_state_change_) {
        has_pending_state_change_signal_ = true;
      } else {
        task_runner_->PostTask(
            FROM_HERE, base::BindOnce(&ResponseBodyLoader::DidFinishLoadingBody,
                                      WrapWeakPersistent(loader_.Get())));
      }
    }

    if (result == Result::kError) {
      state_ = State::kErrored;
      if (in_on_state_change_) {
        has_pending_state_change_signal_ = true;
      } else {
        task_runner_->PostTask(
            FROM_HERE, base::BindOnce(&ResponseBodyLoader::DidFailLoadingBody,
                                      WrapWeakPersistent(loader_.Get())));
      }
    }
  }

  bool IsSuspendedButNotForBackForwardCache() {
    return loader_->IsSuspended() && !loader_->IsSuspendedForBackForwardCache();
  }

  const Member<BytesConsumer> bytes_consumer_;
  const Member<ResponseBodyLoader> loader_;
  Member<BytesConsumer::Client> bytes_consumer_client_;
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  // The size of body which has been reported to |loader_|.
  size_t lookahead_bytes_ = 0;
  State state_ = State::kLoading;
  bool in_on_state_change_ = false;
  // Set when |state_| changes in OnStateChange.
  bool has_pending_state_change_signal_ = false;
  // Set when BeginRead returns kShouldWait due to |lookahead_bytes_| in
  // OnStateChange.
  bool waiting_for_lookahead_bytes_ = false;
};

class ResponseBodyLoader::Buffer final
    : public GarbageCollected<ResponseBodyLoader::Buffer> {
 public:
  explicit Buffer(ResponseBodyLoader* owner) : owner_(owner) {}

  bool IsEmpty() const { return buffered_data_.empty(); }

  // Add |buffer| to |buffered_data_|.
  void AddChunk(const char* buffer, size_t available) {
    TRACE_EVENT2("loading", "ResponseBodyLoader::Buffer::AddChunk",
                 "total_bytes_read", static_cast<int>(total_bytes_read_),
                 "added_bytes", static_cast<int>(available));
    Vector<char> new_chunk;
    new_chunk.Append(buffer, base::checked_cast<wtf_size_t>(available));
    buffered_data_.emplace_back(std::move(new_chunk));
  }

  // Dispatches the frontmost chunk in |buffered_data_|. Returns the size of
  // the data that got dispatched.
  size_t DispatchChunk(size_t max_chunk_size) {
    // Dispatch the chunk at the front of the queue.
    const Vector<char>& current_chunk = buffered_data_.front();
    DCHECK_LT(offset_in_current_chunk_, current_chunk.size());
    // Send as much of the chunk as possible without exceeding |max_chunk_size|.
    base::span<const char> span(current_chunk);
    span = span.subspan(offset_in_current_chunk_);
    span = span.first(std::min(span.size(), max_chunk_size));
    owner_->DidReceiveData(span);

    size_t sent_size = span.size();
    offset_in_current_chunk_ += sent_size;
    if (offset_in_current_chunk_ == current_chunk.size()) {
      // We've finished sending the chunk at the front of the queue, pop it so
      // that we'll send the next chunk next time.
      offset_in_current_chunk_ = 0;
      buffered_data_.pop_front();
    }

    return sent_size;
  }

  void Trace(Visitor* visitor) const { visitor->Trace(owner_); }

 private:
  const Member<ResponseBodyLoader> owner_;
  // We save the response body read when suspended as a queue of chunks so that
  // we can free memory as soon as we finish sending a chunk completely.
  Deque<Vector<char>> buffered_data_;
  size_t offset_in_current_chunk_ = 0;
  size_t total_bytes_read_ = 0;
};

ResponseBodyLoader::ResponseBodyLoader(
    BytesConsumer& bytes_consumer,
    ResponseBodyLoaderClient& client,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    BackForwardCacheLoaderHelper* back_forward_cache_loader_helper)
    : task_runner_(std::move(task_runner)),
      bytes_consumer_(bytes_consumer),
      client_(client),
      back_forward_cache_loader_helper_(back_forward_cache_loader_helper) {
  bytes_consumer_->SetClient(this);
  body_buffer_ = MakeGarbageCollected<Buffer>(this);
}

mojo::ScopedDataPipeConsumerHandle ResponseBodyLoader::DrainAsDataPipe(
    ResponseBodyLoaderClient** client) {
  DCHECK(!started_);
  DCHECK(!drained_as_datapipe_);
  DCHECK(!drained_as_bytes_consumer_);
  DCHECK(!aborted_);

  *client = nullptr;
  DCHECK(bytes_consumer_);
  auto data_pipe = bytes_consumer_->DrainAsDataPipe();
  if (!data_pipe) {
    return data_pipe;
  }

  drained_as_datapipe_ = true;
  bytes_consumer_ = nullptr;
  *client = this;
  return data_pipe;
}

BytesConsumer& ResponseBodyLoader::DrainAsBytesConsumer() {
  DCHECK(!started_);
  DCHECK(!drained_as_datapipe_);
  DCHECK(!drained_as_bytes_consumer_);
  DCHECK(!aborted_);
  DCHECK(bytes_consumer_);
  DCHECK(!delegating_bytes_consumer_);

  delegating_bytes_consumer_ = MakeGarbageCollected<DelegatingBytesConsumer>(
      *bytes_consumer_, *this, task_runner_);
  bytes_consumer_->ClearClient();
  bytes_consumer_->SetClient(delegating_bytes_consumer_);
  bytes_consumer_ = nullptr;
  drained_as_bytes_consumer_ = true;
  return *delegating_bytes_consumer_;
}

void ResponseBodyLoader::DidReceiveData(base::span<const char> data) {
  if (aborted_)
    return;

  if (IsSuspendedForBackForwardCache()) {
    // Track the data size for both total per-process bytes and per-request
    // bytes.
    DidBufferLoadWhileInBackForwardCache(data.size());
    if (!BackForwardCacheBufferLimitTracker::Get()
             .IsUnderPerProcessBufferLimit()) {
      EvictFromBackForwardCache(
          mojom::blink::RendererEvictionReason::kNetworkExceedsBufferLimit);
    }
  }

  client_->DidReceiveData(data);
}

void ResponseBodyLoader::DidReceiveDecodedData(
    const String& data,
    std::unique_ptr<ParkableStringImpl::SecureDigest> digest) {
  if (aborted_)
    return;

  client_->DidReceiveDecodedData(data, std::move(digest));
}

void ResponseBodyLoader::DidFinishLoadingBody() {
  if (aborted_) {
    return;
  }

  TRACE_EVENT0("blink", "ResponseBodyLoader::DidFinishLoadingBody");

  if (IsSuspended()) {
    finish_signal_is_pending_ = true;
    return;
  }

  finish_signal_is_pending_ = false;
  client_->DidFinishLoadingBody();
}

void ResponseBodyLoader::DidFailLoadingBody() {
  if (aborted_) {
    return;
  }

  TRACE_EVENT0("blink", "ResponseBodyLoader::DidFailLoadingBody");

  if (IsSuspended()) {
    fail_signal_is_pending_ = true;
    return;
  }

  fail_signal_is_pending_ = false;
  client_->DidFailLoadingBody();
}

void ResponseBodyLoader::DidCancelLoadingBody() {
  if (aborted_) {
    return;
  }

  TRACE_EVENT0("blink", "ResponseBodyLoader::DidCancelLoadingBody");

  if (IsSuspended()) {
    cancel_signal_is_pending_ = true;
    return;
  }

  cancel_signal_is_pending_ = false;
  client_->DidCancelLoadingBody();
}

void ResponseBodyLoader::EvictFromBackForwardCache(
    mojom::blink::RendererEvictionReason reason) {
  if (!back_forward_cache_loader_helper_)
    return;
  DCHECK(IsSuspendedForBackForwardCache());
  back_forward_cache_loader_helper_->EvictFromBackForwardCache(reason);
}

void ResponseBodyLoader::DidBufferLoadWhileInBackForwardCache(
    size_t num_bytes) {
  if (!back_forward_cache_loader_helper_)
    return;
  back_forward_cache_loader_helper_->DidBufferLoadWhileInBackForwardCache(
      /*update_process_wide_count=*/true, num_bytes);
}

void ResponseBodyLoader::Start() {
  DCHECK(!started_);
  DCHECK(!drained_as_datapipe_);
  DCHECK(!drained_as_bytes_consumer_);

  started_ = true;
  OnStateChange();
}

void ResponseBodyLoader::Abort() {
  if (aborted_)
    return;

  aborted_ = true;

  if (bytes_consumer_ && !in_two_phase_read_) {
    bytes_consumer_->Cancel();
  }

  if (delegating_bytes_consumer_) {
    delegating_bytes_consumer_->Abort();
  }
}

void ResponseBodyLoader::Suspend(LoaderFreezeMode mode) {
  if (aborted_)
    return;

  bool was_suspended = (suspended_state_ == LoaderFreezeMode::kStrict);

  suspended_state_ = mode;
  if (IsSuspendedForBackForwardCache()) {
    DCHECK(IsInflightNetworkRequestBackForwardCacheSupportEnabled());
    // If we're already suspended (but not for back-forward cache), we might've
    // ignored some OnStateChange calls.
    if (was_suspended) {
      task_runner_->PostTask(FROM_HERE,
                             base::BindOnce(&ResponseBodyLoader::OnStateChange,
                                            WrapPersistent(this)));
    }
  }
}

void ResponseBodyLoader::EvictFromBackForwardCacheIfDrainedAsBytesConsumer() {
  if (drained_as_bytes_consumer_) {
    if (!base::FeatureList::IsEnabled(
            features::kAllowDatapipeDrainedAsBytesConsumerInBFCache)) {
      EvictFromBackForwardCache(
          mojom::blink::RendererEvictionReason::
              kNetworkRequestDatapipeDrainedAsBytesConsumer);
    }
  }
}

void ResponseBodyLoader::Resume() {
  if (aborted_)
    return;

  DCHECK(IsSuspended());
  suspended_state_ = LoaderFreezeMode::kNone;

  if (finish_signal_is_pending_) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&ResponseBodyLoader::DidFinishLoadingBody,
                                  WrapPersistent(this)));
  } else if (fail_signal_is_pending_) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&ResponseBodyLoader::DidFailLoadingBody,
                                  WrapPersistent(this)));
  } else if (cancel_signal_is_pending_) {
    task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&ResponseBodyLoader::DidCancelLoadingBody,
                                  WrapPersistent(this)));
  } else {
    task_runner_->PostTask(FROM_HERE,
                           base::BindOnce(&ResponseBodyLoader::OnStateChange,
                                          WrapPersistent(this)));
  }
}

void ResponseBodyLoader::OnStateChange() {
  if (!started_)
    return;

  TRACE_EVENT0("blink", "ResponseBodyLoader::OnStateChange");

  size_t num_bytes_consumed = 0;
  while (!aborted_ && (!IsSuspended() || IsSuspendedForBackForwardCache())) {
    const size_t chunk_size = network::features::kMaxNumConsumedBytesInTask;
    if (chunk_size == num_bytes_consumed) {
      // We've already consumed many bytes in this task. Defer the remaining
      // to the next task.
      task_runner_->PostTask(FROM_HERE,
                             base::BindOnce(&ResponseBodyLoader::OnStateChange,
                                            WrapPersistent(this)));
      return;
    }

    if (!IsSuspended() && body_buffer_ && !body_buffer_->IsEmpty()) {
      // We need to empty |body_buffer_| first before reading more from
      // |bytes_consumer_|.
      num_bytes_consumed +=
          body_buffer_->DispatchChunk(chunk_size - num_bytes_consumed);
      continue;
    }

    base::span<const char> buffer;
    auto result = bytes_consumer_->BeginRead(buffer);
    if (result == BytesConsumer::Result::kShouldWait)
      return;
    if (result == BytesConsumer::Result::kOk) {
      TRACE_EVENT1("blink", "ResponseBodyLoader::OnStateChange", "available",
                   buffer.size());

      base::AutoReset<bool> auto_reset_for_in_two_phase_read(
          &in_two_phase_read_, true);
      buffer = buffer.first(
          std::min(buffer.size(), chunk_size - num_bytes_consumed));
      if (IsSuspendedForBackForwardCache()) {
        // Save the read data into |body_buffer_| instead.
        DidBufferLoadWhileInBackForwardCache(buffer.size());
        body_buffer_->AddChunk(buffer.data(), buffer.size());
        if (!BackForwardCacheBufferLimitTracker::Get()
                 .IsUnderPerProcessBufferLimit()) {
          // We've read too much data while suspended for back-forward cache.
          // Evict the page from the back-forward cache.
          result = bytes_consumer_->EndRead(buffer.size());
          EvictFromBackForwardCache(
              mojom::blink::RendererEvictionReason::kNetworkExceedsBufferLimit);
          return;
        }
      } else {
        DCHECK(!IsSuspended());
        DidReceiveData(buffer);
      }
      result = bytes_consumer_->EndRead(buffer.size());
      num_bytes_consumed += buffer.size();

      if (aborted_) {
        // As we cannot call Cancel in two-phase read, we need to call it here.
        bytes_consumer_->Cancel();
      }
    }
    DCHECK_NE(result, BytesConsumer::Result::kShouldWait);
    if (IsSuspendedForBackForwardCache() &&
        result != BytesConsumer::Result::kOk) {
      // Don't dispatch finish/failure messages when suspended. We'll dispatch
      // them later when we call OnStateChange again after resuming.
      return;
    }
    if (result == BytesConsumer::Result::kDone) {
      DidFinishLoadingBody();
      return;
    }
    if (result != BytesConsumer::Result::kOk) {
      DidFailLoadingBody();
      Abort();
      return;
    }
  }
}

void ResponseBodyLoader::Trace(Visitor* visitor) const {
  visitor->Trace(bytes_consumer_);
  visitor->Trace(delegating_bytes_consumer_);
  visitor->Trace(client_);
  visitor->Trace(body_buffer_);
  visitor->Trace(back_forward_cache_loader_helper_);
  ResponseBodyLoaderDrainableInterface::Trace(visitor);
  ResponseBodyLoaderClient::Trace(visitor);
  BytesConsumer::Client::Trace(visitor);
}

}  // namespace blink
```